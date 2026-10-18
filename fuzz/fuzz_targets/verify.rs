//! Arbitrary presentation bytes against a real offer and trust set: must never panic.
//! Seeds come from the conformance vectors (`fuzz/corpus/verify`).
#![no_main]

use std::sync::OnceLock;

use kaze::{verify, verify_offer, Context, Jwk, Trust, Verified};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

struct Fixture {
    offer: Verified,
    trust: Trust,
    now: i64,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let file: Value =
            serde_json::from_str(include_str!("../../vectors/v1.json")).expect("vectors");
        let jwks: Vec<Jwk> = serde_json::from_value(file["platform_jwks"].clone()).expect("jwks");
        let ok = file["cases"].as_array().expect("cases").iter().find(|c| c["name"] == "ok_order").expect("ok_order");
        let now = ok["now"].as_i64().expect("now");
        Fixture {
            offer: verify_offer(ok["offer"].as_str().expect("offer"), &jwks, file["platform"].as_str().expect("platform"), now).expect("offer verifies"),
            trust: serde_json::from_value(file["trust"].clone()).expect("trust"),
            now,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    if let Ok(p) = std::str::from_utf8(data) {
        let ctx = Context { now: f.now, operator: "https://agent.example", offer: &f.offer };
        let _ = verify(p, &ctx, &f.trust);
    }
});
