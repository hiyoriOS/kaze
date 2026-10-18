//! Runs every conformance vector through kzp.wasm exactly as a host would, then:
//! - checks the module imports nothing (pure function, no WASI, no host calls);
//! - reports deterministic fuel (≈ executed instructions) per vector;
//! - runs a long alloc/verify/free loop and asserts linear memory stops growing.
//!
//!     cargo rustc --lib --crate-type cdylib --profile wasm --target wasm32-unknown-unknown   (in ../)
//!     cargo run --release -- ../target/wasm32-unknown-unknown/wasm/kzp.wasm ../vectors/v1.json

use serde_json::{json, Value};
use wasmi::{Config, Engine, Instance, Linker, Memory, Module, Store, TypedFunc};

struct Kaze {
    store: Store<()>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    free: TypedFunc<(i32, i32), ()>,
    verify: TypedFunc<(i32, i32, i32), ()>,
}

impl Kaze {
    fn new(bytes: &[u8]) -> Self {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, bytes).expect("valid module");
        let imports: Vec<_> = module.imports().map(|i| format!("{}::{}", i.module(), i.name())).collect();
        assert!(imports.is_empty(), "kzp.wasm must import nothing, found {imports:?}");
        let mut store = Store::new(&engine, ());
        store.set_fuel(u64::MAX).unwrap();
        let instance: Instance = Linker::<()>::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .expect("instantiate");
        let memory = instance.get_memory(&store, "memory").expect("memory export");
        Kaze {
            alloc: instance.get_typed_func(&store, "kzp_alloc").unwrap(),
            free: instance.get_typed_func(&store, "kzp_free").unwrap(),
            verify: instance.get_typed_func(&store, "kzp_verify").unwrap(),
            store,
            memory,
        }
    }

    /// One host call: alloc request and ret, verify, read response, free all three.
    /// Returns (response JSON, fuel consumed).
    fn call(&mut self, req: &[u8]) -> (Value, u64) {
        let before = self.store.get_fuel().unwrap();
        let len = i32::try_from(req.len()).unwrap();
        let p = self.alloc.call(&mut self.store, len).unwrap();
        let ret = self.alloc.call(&mut self.store, 8).unwrap();
        self.memory.write(&mut self.store, p as usize, req).unwrap();
        self.verify.call(&mut self.store, (p, len, ret)).unwrap();
        let mut words = [0u8; 8];
        self.memory.read(&self.store, ret as usize, &mut words).unwrap();
        let out = u32::from_le_bytes(words[..4].try_into().unwrap());
        let out_len = u32::from_le_bytes(words[4..].try_into().unwrap());
        let mut body = vec![0u8; out_len as usize];
        self.memory.read(&self.store, out as usize, &mut body).unwrap();
        self.free.call(&mut self.store, (p, len)).unwrap();
        self.free.call(&mut self.store, (ret, 8)).unwrap();
        self.free.call(&mut self.store, (out as i32, out_len as i32)).unwrap();
        let fuel = before - self.store.get_fuel().unwrap();
        (serde_json::from_slice(&body).expect("response is JSON"), fuel)
    }

    fn pages(&self) -> u64 {
        u64::from(self.memory.size(&self.store))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let wasm = std::fs::read(&args[1]).expect("kzp.wasm");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();
    let mut k = Kaze::new(&wasm);

    let mut failed = Vec::new();
    let mut rows = Vec::new();
    let mut reqs = Vec::new();
    for c in file["cases"].as_array().unwrap() {
        let Some(p) = c.get("presentation") else { continue };
        let req = serde_json::to_vec(&json!({
            "offer": c["offer"], "jwks": file["platform_jwks"], "iss": file["platform"], "now": c["now"],
            "operator": c["operator"], "presentation": p, "trust": file["trust"],
        }))
        .unwrap();
        // The first call pays one-time allocator growth; steady state must be exact.
        let (got, _) = k.call(&req);
        let (_, fuel) = k.call(&req);
        let (_, again) = k.call(&req);
        assert_eq!(fuel, again, "{}: fuel must be deterministic", c["name"]);
        let name = c["name"].as_str().unwrap();
        let want = &c["expect"];
        let ok = match (got.get("ok"), want.get("ok"), want.get("error")) {
            (Some(g), Some(w), _) => g["act"] == w["act"] && g["amount"] == w["amount"] && g["jti"] == w["jti"],
            (None, _, Some(code)) => got["error"]["code"] == *code,
            _ => false,
        };
        if !ok {
            failed.push(format!("{name}: {got}"));
        }
        rows.push((name.to_owned(), fuel));
        reqs.push(req);
    }
    for (name, fuel) in &rows {
        println!("{name:24} fuel {fuel:>10}");
    }
    assert!(failed.is_empty(), "wasm disagrees with vectors: {failed:#?}");
    println!("{} presentation vectors agree with the native verifier's expectations", rows.len());

    // Leak check at the WebAssembly level: after warm-up, linear memory must not grow.
    for r in &reqs {
        k.call(r);
    }
    let warm = k.pages();
    let rounds = 2_000;
    for _ in 0..rounds {
        for r in &reqs {
            k.call(r);
        }
    }
    let after = k.pages();
    println!("memory: {warm} pages after warm-up, {after} after {} more calls", rounds * reqs.len());
    assert_eq!(warm, after, "linear memory grew: leak in the ABI path");
}
