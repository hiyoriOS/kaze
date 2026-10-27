//! Signing: arbitrary bytes into both signing entry points must never panic and must
//! answer in JSON; and whatever tag and components the signer accepts, the verifier
//! accepts the result for that tag.
#![no_main]

use kzp::agent::verify_agent_with_tag;
use kzp::sign::{self, RequestSignature};
use kzp::Message;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const NOW: i64 = 1_792_300_000;
const AGENT_DIR: &str = "https://agent.example/.well-known/http-message-signatures-directory";

fuzz_target!(|data: &[u8]| {
    for out in [kzp::abi::sign_request_json(data), kzp::abi::directory_json(data)] {
        let v: Value = serde_json::from_slice(&out).expect("response is JSON");
        assert!(v.get("ok").is_some() || v["error"]["code"].is_string(), "{v}");
    }

    // Split the input into a tag and up to four components.
    let Ok(s) = std::str::from_utf8(data) else { return };
    let mut parts = s.split('\n');
    let tag = parts.next().unwrap_or("");
    let components: Vec<&str> = parts.take(4).collect();
    let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
    let mut m = Message {
        method: "POST".into(),
        scheme: "https".into(),
        authority: "api.ryo.example".into(),
        path: "/v1/agent/payments".into(),
        query: None,
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Digest".into(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".into()),
        ],
    };
    let before = m.clone();
    let sig = RequestSignature {
        label: "sig",
        agent_url: "https://agent.example",
        created: NOW - 10,
        expires: NOW + 300,
        nonce: Some("bm9uY2Uta3pw"),
        tag,
        components: &components,
    };
    match sign::sign_request(&mut m, &sig, &key) {
        Ok(()) => {
            let dir = sign::directory(&[key.verifying_key()]).unwrap().keys;
            verify_agent_with_tag(&m, &dir, AGENT_DIR, NOW, tag)
                .expect("a request the signer signed verifies for its tag");
        }
        Err(_) => assert_eq!(m, before, "a failed signature must not touch the message"),
    }
});
