//! Wall-clock benchmarks over the conformance vectors. The deterministic numbers
//! (allocations, WebAssembly fuel) come from `tests/alloc.rs` and `harness/`.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools,
    clippy::struct_excessive_bools,
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::needless_pass_by_value,
    clippy::map_unwrap_or,
    clippy::semicolon_if_nothing_returned,
    clippy::doc_markdown,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kzp::{verify, verify_offer, Context, Jwk, Trust};
use serde_json::{json, Value};

fn load() -> Value {
    serde_json::from_str(include_str!("../vectors/v1.json")).unwrap()
}

fn case<'a>(file: &'a Value, name: &str) -> &'a Value {
    file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
}

fn bench(c: &mut Criterion) {
    let file = load();
    let jwks: Vec<Jwk> = serde_json::from_value(file["platform_jwks"].clone()).unwrap();
    let trust: Trust = serde_json::from_value(file["trust"].clone()).unwrap();
    let platform = file["platform"].as_str().unwrap();

    for name in ["ok_order", "ok_read", "issuer_signature", "liab_cover"] {
        let k = case(&file, name);
        let now = k["now"].as_i64().unwrap();
        let offer = verify_offer(k["offer"].as_str().unwrap(), &jwks, platform, now).unwrap();
        let ctx = Context {
            now,
            operator: k["operator"].as_str().unwrap(),
            offer: &offer,
        };
        let p = k["presentation"].as_str().unwrap();
        c.bench_function(&format!("verify/{name}"), |b| {
            b.iter(|| verify(black_box(p), black_box(&ctx), black_box(&trust)))
        });
    }

    let k = case(&file, "ok_order");
    let now = k["now"].as_i64().unwrap();
    let token = k["offer"].as_str().unwrap();
    c.bench_function("verify_offer", |b| {
        b.iter(|| verify_offer(black_box(token), &jwks, platform, now))
    });

    let req = serde_json::to_vec(&json!({
        "offer": k["offer"], "jwks": file["platform_jwks"], "iss": file["platform"], "now": now,
        "operator": k["operator"], "presentation": k["presentation"], "trust": file["trust"],
    }))
    .unwrap();
    c.bench_function("abi/verify_json", |b| {
        b.iter(|| kzp::abi::verify_json(black_box(&req)))
    });
}

fn agent(c: &mut Criterion) {
    let file: Value = serde_json::from_str(include_str!("../vectors/agent.json")).unwrap();
    let k = file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ok_agent")
        .unwrap();
    let m: kzp::Message = serde_json::from_value(k["message"].clone()).unwrap();
    let d: Vec<Jwk> = serde_json::from_value(k["directory"].clone()).unwrap();
    let u = k["directory_url"].as_str().unwrap();
    let now = k["now"].as_i64().unwrap();
    c.bench_function("verify_agent", |b| {
        b.iter(|| kzp::verify_agent(black_box(&m), &d, u, now))
    });
}

criterion_group!(benches, bench, agent);
criterion_main!(benches);
