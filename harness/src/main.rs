//! Runs kzp.wasm exactly as a host would, in a pure-Rust interpreter:
//! - checks the module imports nothing (pure function, no WASI, no host calls);
//! - runs every conformance and Web Bot Auth vector through the ABI;
//! - drives a full issue → present → verify round trip through the issuance exports;
//! - runs every signing and key-directory vector (`sign.json`) and demands the same bytes;
//! - reports deterministic fuel (≈ executed instructions) per vector;
//! - runs a long loop over every export and asserts linear memory stops growing.
//!
//! The full `kzp.wasm` (verification and issuance) gets all of the above:
//!
//!     cargo rustc --lib --crate-type cdylib --profile wasm --target wasm32-unknown-unknown --features issue
//!     cargo run --release -- ../target/wasm32-unknown-unknown/wasm/kzp.wasm ../vectors
//!
//! The signing-only `kzp.wasm` must export exactly `kzp_alloc`, `kzp_free`,
//! `kzp_sign_request` and `kzp_directory` (plus `memory`), and gets the signing vectors
//! and the memory check:
//!
//!     cargo rustc --lib --crate-type cdylib --profile wasm --target wasm32-unknown-unknown \
//!         --no-default-features --features sign --target-dir target/sign
//!     cargo run --release -- ../target/sign/wasm32-unknown-unknown/wasm/kzp.wasm ../vectors

use std::collections::BTreeMap;

use serde_json::{json, Value};
use wasmi::{Config, Engine, Instance, Linker, Memory, Module, Store, TypedFunc};

type Export = TypedFunc<(i32, i32, i32), ()>;

struct Kzp {
    store: Store<()>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    free: TypedFunc<(i32, i32), ()>,
    exports: BTreeMap<String, Export>,
}

impl Kzp {
    fn new(bytes: &[u8]) -> Self {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, bytes).expect("valid module");
        let imports: Vec<_> = module.imports().map(|i| format!("{}::{}", i.module(), i.name())).collect();
        assert!(imports.is_empty(), "kzp.wasm must import nothing, found {imports:?}");
        let names: Vec<String> = module
            .exports()
            .map(|e| e.name().to_owned())
            .filter(|n| n.starts_with("kzp_") && n != "kzp_alloc" && n != "kzp_free")
            .collect();
        let mut store = Store::new(&engine, ());
        store.set_fuel(u64::MAX).unwrap();
        let instance: Instance = Linker::<()>::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .expect("instantiate");
        let memory = instance.get_memory(&store, "memory").expect("memory export");
        let exports = names
            .into_iter()
            .map(|n| {
                let f = instance.get_typed_func(&store, &n).unwrap();
                (n, f)
            })
            .collect();
        Kzp {
            alloc: instance.get_typed_func(&store, "kzp_alloc").unwrap(),
            free: instance.get_typed_func(&store, "kzp_free").unwrap(),
            store,
            memory,
            exports,
        }
    }

    /// One host call: alloc request and ret, call, read response, free all three.
    fn call(&mut self, export: &str, req: &Value) -> (Value, u64) {
        let req = serde_json::to_vec(req).unwrap();
        let f = self.exports.get(export).unwrap_or_else(|| panic!("no export {export}")).clone();
        let before = self.store.get_fuel().unwrap();
        let len = i32::try_from(req.len()).unwrap();
        let p = self.alloc.call(&mut self.store, len).unwrap();
        let ret = self.alloc.call(&mut self.store, 8).unwrap();
        self.memory.write(&mut self.store, p as usize, &req).unwrap();
        f.call(&mut self.store, (p, len, ret)).unwrap();
        let mut words = [0u8; 8];
        self.memory.read(&self.store, ret as usize, &mut words).unwrap();
        let out = u32::from_le_bytes(words[..4].try_into().unwrap());
        let out_len = u32::from_le_bytes(words[4..].try_into().unwrap());
        let mut body = vec![0u8; out_len as usize];
        self.memory.read(&self.store, out as usize, &mut body).unwrap();
        self.free.call(&mut self.store, (p, len)).unwrap();
        // kzp_free must have zeroed the request (it may hold a seed). The allocator then
        // writes its own free-list words into the block, so check that no 8-byte run of
        // the original request survives rather than that every byte is zero.
        let mut freed = vec![0u8; req.len()];
        self.memory.read(&self.store, p as usize, &mut freed).unwrap();
        let survives = req.windows(8).zip(freed.windows(8)).any(|(a, b)| a == b && a.iter().any(|x| *x != 0));
        assert!(!survives, "request bytes survived kzp_free");
        self.free.call(&mut self.store, (ret, 8)).unwrap();
        self.free.call(&mut self.store, (out as i32, out_len as i32)).unwrap();
        let fuel = before - self.store.get_fuel().unwrap();
        (serde_json::from_slice(&body).expect("response is JSON"), fuel)
    }

    /// Steady-state fuel: the first call pays allocator growth; later ones must agree.
    /// The verification exports agree exactly. The Web Bot Auth ones, and signing, build
    /// structured fields in sfv's hash-seeded dictionaries, so their cost may move by a
    /// few instructions in ten thousand (never their result); they must agree within 0.1%.
    fn steady(&mut self, export: &str, req: &Value) -> (Value, u64) {
        let (got, _) = self.call(export, req);
        let (again, a) = self.call(export, req);
        let (_, b) = self.call(export, req);
        assert_eq!(got, again, "{export}: result must be deterministic");
        if export.contains("agent") || export.contains("sign") {
            assert!(a.abs_diff(b) * 1000 <= a, "{export}: fuel {a} vs {b}");
        } else {
            assert_eq!(a, b, "{export}: fuel must be deterministic");
        }
        (got, a)
    }

    fn pages(&self) -> u64 {
        u64::from(self.memory.size(&self.store))
    }
}

fn ok(v: &Value) -> &Value {
    v.get("ok").unwrap_or_else(|| panic!("expected ok, got {v}"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut k = Kzp::new(&std::fs::read(&args[1]).expect("kzp.wasm"));
    let dir = std::path::Path::new(&args[2]);
    let load = |f: &str| -> Value { serde_json::from_str(&std::fs::read_to_string(dir.join(f)).unwrap()).unwrap() };
    let sign = load("sign.json");

    let mut failed = Vec::new();
    let mut loop_calls: Vec<(String, Value)> = Vec::new();

    // Signing vectors: every build that signs must produce these bytes.
    for (export, cases) in [("kzp_sign_request", &sign["sign"]), ("kzp_directory", &sign["directory"])] {
        for c in cases.as_array().unwrap() {
            let (got, fuel) = k.steady(export, &c["request"]);
            let good = match (got.get("ok"), c["expect"].get("ok"), c["expect"].get("error")) {
                (Some(g), Some(w), _) => g == w,
                (None, _, Some(code)) => got["error"]["code"] == *code,
                _ => false,
            };
            if !good {
                failed.push(format!("{export} {}: {got}", c["name"]));
            }
            println!("{:28} fuel {fuel:>10}", format!("{export}:{}", c["name"].as_str().unwrap()));
            loop_calls.push((export.into(), c["request"].clone()));
        }
    }
    assert!(failed.is_empty(), "wasm disagrees with signing vectors: {failed:#?}");
    println!("{} signing and directory vectors agree byte for byte", loop_calls.len());

    if !k.exports.contains_key("kzp_verify") {
        let names: Vec<&str> = k.exports.keys().map(String::as_str).collect();
        assert_eq!(names, ["kzp_directory", "kzp_sign_request"], "a signing-only build exports exactly these");
        leak_check(&mut k, &loop_calls);
        return;
    }
    let v1 = load("v1.json");
    let agent = load("agent.json");

    // Conformance vectors.
    for c in v1["cases"].as_array().unwrap() {
        let Some(p) = c.get("presentation") else { continue };
        let req = json!({"offer": c["offer"], "jwks": v1["platform_jwks"], "iss": v1["platform"], "now": c["now"],
                         "operator": c["operator"], "presentation": p, "trust": v1["trust"]});
        let (got, fuel) = k.steady("kzp_verify", &req);
        let w = &c["expect"];
        let good = match (got.get("ok"), w.get("ok"), w.get("error")) {
            (Some(g), Some(w), _) => g["act"] == w["act"] && g["amount"] == w["amount"] && g["jti"] == w["jti"],
            (None, _, Some(code)) => got["error"]["code"] == *code,
            _ => false,
        };
        if !good {
            failed.push(format!("{}: {got}", c["name"]));
        }
        println!("{:28} fuel {fuel:>10}", c["name"].as_str().unwrap());
        loop_calls.push(("kzp_verify".into(), req));
    }

    // Web Bot Auth vectors.
    for c in agent["cases"].as_array().unwrap() {
        let mut req = json!({"message": c["message"], "directory": c["directory"],
                         "directory_url": c["directory_url"], "now": c["now"]});
        if let Some(tag) = c.get("tag") {
            req["tag"] = tag.clone();
        }
        let (got, fuel) = k.steady("kzp_verify_agent", &req);
        let w = &c["expect"];
        let good = match (got.get("ok"), w.get("ok"), w.get("error")) {
            (Some(g), Some(w), _) => g["operator"] == w["operator"],
            (None, _, Some(code)) => got["error"]["code"] == *code,
            _ => false,
        };
        if !good {
            failed.push(format!("{}: {got}", c["name"]));
        }
        println!("{:28} fuel {fuel:>10}", c["name"].as_str().unwrap());
        loop_calls.push(("kzp_verify_agent".into(), req));
    }
    assert!(failed.is_empty(), "wasm disagrees with vectors: {failed:#?}");

    // Full round trip through the issuance exports: what a platform and an agent do.
    let seed = |n: u8| base64_url(&[n; 32]);
    let now = 1_792_300_000_i64;
    let shop = "https://api.ryo.example";
    let op = "https://agent.example";
    let platform_jwk = ok(&k.call("kzp_jwk", &json!({"seed": seed(11), "kid": "p1"})).0).clone();
    let issuer_jwk = ok(&k.call("kzp_jwk", &json!({"seed": seed(12), "kid": "i1"})).0).clone();
    let agent_jwk = ok(&k.call("kzp_jwk", &json!({"seed": seed(13), "kid": "a1"})).0).clone();
    let offer = json!({"iss": shop, "iat": now - 5, "exp": now + 200, "nonce": base64_url(&[9; 16]),
        "resource": format!("{shop}/v1/agent/payments"),
        "terms": [{"act": "order:create", "mandate": {"hp": false}, "amount": {"value": 1850, "currency": "USD"}}]});
    let token = ok(&k.call("kzp_issue_offer", &json!({"offer": offer, "kid": "p1", "seed": seed(11)})).0).clone();
    let mut agent_pub = agent_jwk.clone();
    agent_pub.as_object_mut().unwrap().remove("kid");
    let claims = json!({"iss": "https://ryo.example/authority", "sub": "auth_1", "iat": now - 60, "exp": now + 86_400,
        "jti": "mdt_rt", "vct": "kaze.mandate.1", "cnf": {"jwk": agent_pub}});
    let prefix = ok(&k.call("kzp_issue_mandate", &json!({"claims": claims, "kid": "i1", "seed": seed(12),
        "disclosures": [["c2FsdC1yb3VuZHRyaXA", "act", [{"act": "order:*", "on": [shop], "max": {"value": 5000, "currency": "USD"}}]]]})).0).clone();
    let binding = json!({"iat": now - 1, "aud": shop, "op": op, "nonce": base64_url(&[9; 16]), "sd_hash": "",
        "act": "order:create", "amt": {"value": 1850, "currency": "USD"}});
    let pres = ok(&k.call("kzp_present", &json!({"prefix": prefix, "binding": binding, "seed": seed(13)})).0).clone();
    let verify = json!({"offer": token, "jwks": [platform_jwk], "iss": shop, "now": now, "operator": op,
        "presentation": pres, "trust": {"issuers": {"https://ryo.example/authority": [issuer_jwk]}, "providers": {}}});
    let (grant, _) = k.steady("kzp_verify", &verify);
    assert_eq!(ok(&grant)["amount"]["value"], 1850, "round trip grant: {grant}");

    let msg = json!({"method": "POST", "scheme": "https", "authority": "api.ryo.example", "path": "/v1/agent/payments", "headers": []});
    let signed = ok(&k.call("kzp_sign_request", &json!({"message": msg, "label": "sig", "agent_url": op,
        "created": now - 1, "expires": now + 600, "seed": seed(13)})).0).clone();
    let (sa, _) = k.steady("kzp_signature_agent", &json!({"message": signed}));
    let dir_url = ok(&sa)["directory_url"].clone();
    let (who, _) = k.steady("kzp_verify_agent", &json!({"message": signed, "directory": [agent_jwk],
        "directory_url": dir_url, "now": now}));
    assert_eq!(ok(&who)["operator"], op, "round trip agent: {who}");
    let payer = ok(&k.call("kzp_sign_request", &json!({"message": msg, "label": "sig", "agent_url": op,
        "created": now - 1, "expires": now + 600, "tag": "agent-payer-auth", "seed": seed(13)})).0).clone();
    let (who, _) = k.steady("kzp_verify_agent", &json!({"message": payer, "directory": [agent_jwk],
        "directory_url": dir_url, "now": now, "tag": "agent-payer-auth"}));
    assert_eq!(ok(&who)["operator"], op, "round trip tagged agent: {who}");
    println!("round trip: issue offer + mandate, present, sign request, verify agent + grant: ok");
    loop_calls.push(("kzp_verify".into(), verify));

    let presentations = v1["cases"].as_array().unwrap().iter().filter(|c| c.get("presentation").is_some()).count();
    println!(
        "{} conformance + {} agent vectors agree with the native verifier",
        presentations,
        agent["cases"].as_array().unwrap().len()
    );

    leak_check(&mut k, &loop_calls);
}

/// Leak check at the WebAssembly level: after warm-up, linear memory must not grow.
fn leak_check(k: &mut Kzp, loop_calls: &[(String, Value)]) {
    for (e, r) in loop_calls {
        k.call(e, r);
    }
    let warm = k.pages();
    let rounds = 1_000;
    for _ in 0..rounds {
        for (e, r) in loop_calls {
            k.call(e, r);
        }
    }
    let after = k.pages();
    println!("memory: {warm} pages after warm-up, {after} after {} more calls", rounds * loop_calls.len());
    assert_eq!(warm, after, "linear memory grew: leak in the ABI path");
}

fn base64_url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}
