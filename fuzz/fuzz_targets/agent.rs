//! Arbitrary Web Bot Auth headers against a real directory: must never panic.
#![no_main]

use kzp::{verify_agent, Jwk, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let mut parts = s.splitn(3, '\n');
    let (a, i, g) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let m = Message {
        method: "POST".into(),
        scheme: "https".into(),
        authority: "api.ryo.example".into(),
        path: "/v1/agent/payments".into(),
        query: None,
        headers: vec![
            ("Signature-Agent".into(), a.into()),
            ("Signature-Input".into(), i.into()),
            ("Signature".into(), g.into()),
        ],
    };
    let d = [Jwk { kty: "OKP".into(), crv: "Ed25519".into(), x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(), kid: None }];
    let _ = kzp::signature_agent(&m);
    let _ = verify_agent(&m, &d, "https://agent.example/.well-known/http-message-signatures-directory", 1_792_300_000);
});
