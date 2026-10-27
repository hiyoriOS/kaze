//! Regenerates `vectors/sign.json`: known answers for signing a request and for
//! publishing the key directory, written as the JSON a host sends through the ABI
//! (`kzp_sign_request`, `kzp_directory`). Keys come from fixed seeds and Ed25519 is
//! deterministic, so the output is reproducible.
//!
//!     cargo run --example sign --features sign > vectors/sign.json

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

use kzp::abi::{directory_json, sign_request_json};
use kzp::jws::b64;
use serde_json::{json, Value};

const NOW: i64 = 1_792_300_000;
const AGENT: &str = "https://agent.example";
const DIGEST: &str = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";

fn seed(n: u8) -> String {
    b64(&[n; 32])
}

fn message() -> Value {
    json!({
        "method": "POST",
        "scheme": "https",
        "authority": "api.ryo.example",
        "path": "/v1/agent/payments",
        "headers": [["Content-Type", "application/json"]],
    })
}

fn with_digest() -> Value {
    let mut m = message();
    m["headers"]
        .as_array_mut()
        .unwrap()
        .push(json!(["Content-Digest", DIGEST]));
    m
}

/// A request that signs `message` as agent 5, with `extra` fields merged in.
fn request(message: Value, extra: Value) -> Value {
    let mut r = json!({
        "message": message, "label": "sig", "agent_url": AGENT,
        "created": NOW - 10, "expires": NOW + 3600, "nonce": "bm9uY2Uta3pw", "seed": seed(5),
    });
    for (k, v) in extra.as_object().unwrap() {
        if v.is_null() {
            r.as_object_mut().unwrap().remove(k);
        } else {
            r[k] = v.clone();
        }
    }
    r
}

fn run(f: fn(&[u8]) -> Vec<u8>, request: &Value) -> Value {
    serde_json::from_slice(&f(&serde_json::to_vec(request).unwrap())).unwrap()
}

fn main() {
    let mut sign = Vec::new();
    let mut ok = |name: &str, why: &str, req: Value| {
        let got = run(sign_request_json, &req);
        assert!(got.get("ok").is_some(), "{name}: {got}");
        sign.push(json!({"name": name, "why": why, "request": req, "expect": got}));
    };
    ok(
        "ok_default",
        "no tag and no components: the Web Bot Auth tag and the method, authority and path, exactly as before the tag was a parameter",
        request(message(), json!({})),
    );
    ok(
        "ok_tag",
        "a caller-chosen tag",
        request(message(), json!({"tag": "agent-payer-auth"})),
    );
    ok(
        "ok_components",
        "chosen components bind the body's digest and its type",
        request(
            with_digest(),
            json!({"tag": "web-bot-auth", "components": ["@method", "@authority", "@path", "content-type", "content-digest"]}),
        ),
    );
    ok(
        "ok_target_uri",
        "@target-uri in place of the separate components",
        request(message(), json!({"components": ["@target-uri"]})),
    );
    ok(
        "ok_no_nonce",
        "a nonce is optional",
        request(message(), json!({"nonce": null})),
    );

    let mut errors = Vec::new();
    let mut err = |name: &str, why: &str, req: Value, code: &str| {
        let got = run(sign_request_json, &req);
        assert_eq!(got["error"]["code"], code, "{name}: {got}");
        errors.push(json!({"name": name, "why": why, "request": req, "expect": {"error": code}}));
    };
    err(
        "no_authority",
        "neither @authority nor @target-uri is covered: no verifier could tie the signature to a host",
        request(message(), json!({"components": ["@method", "@path"]})),
        "agent_components",
    );
    err(
        "empty_components",
        "an empty list is not the default",
        request(message(), json!({"components": []})),
        "agent_components",
    );
    err(
        "lists_signature_agent",
        "signature-agent is always covered, keyed by the label; it is not a caller's component",
        request(
            message(),
            json!({"components": ["@authority", "signature-agent"]}),
        ),
        "agent_components",
    );
    err(
        "duplicate_component",
        "a component is covered once",
        request(
            message(),
            json!({"components": ["@authority", "@authority"]}),
        ),
        "agent_components",
    );
    err(
        "missing_header",
        "a covered header the request does not carry",
        request(
            message(),
            json!({"components": ["@authority", "content-digest"]}),
        ),
        "agent_components",
    );
    err(
        "unsupported_component",
        "a component this signer cannot rebuild fails closed",
        request(
            message(),
            json!({"components": ["@authority", "@query-param"]}),
        ),
        "agent_components",
    );
    err(
        "uppercase_header",
        "header names are lowercase in a signature base",
        request(
            message(),
            json!({"components": ["@authority", "Content-Type"]}),
        ),
        "agent_components",
    );
    err(
        "empty_tag",
        "a signature without a tag cannot be found by the verifier",
        request(message(), json!({"tag": ""})),
        "malformed",
    );
    err(
        "tag_not_printable",
        "a tag is a structured-field string: printable ASCII only",
        request(message(), json!({"tag": "agent\npayer"})),
        "malformed",
    );
    err(
        "bad_label",
        "a label is a structured-field key: lowercase",
        request(message(), json!({"label": "Sig"})),
        "malformed",
    );
    err(
        "bad_seed",
        "a seed is 32 bytes",
        request(message(), json!({"seed": b64(&[5u8; 31])})),
        "malformed",
    );
    err(
        "unknown_field",
        "unknown request fields are refused",
        request(message(), json!({"alg": "rsa-pss-sha512"})),
        "malformed",
    );

    let mut directory = Vec::new();
    let mut dir_ok = |name: &str, why: &str, req: Value| {
        let got = run(directory_json, &req);
        assert!(got.get("ok").is_some(), "{name}: {got}");
        directory.push(json!({"name": name, "why": why, "request": req, "expect": got}));
    };
    dir_ok(
        "ok_one",
        "one key; its kid is the thumbprint a signature's keyid carries",
        json!({"seeds": [seed(5)]}),
    );
    dir_ok(
        "ok_rotation",
        "during a rotation the directory lists the old and the new key",
        json!({"seeds": [seed(5), seed(7)]}),
    );
    for (name, why, req) in [
        (
            "no_seeds",
            "an empty directory publishes nothing",
            json!({"seeds": []}),
        ),
        (
            "bad_seed",
            "a seed is 32 bytes",
            json!({"seeds": [b64(&[5u8; 33])]}),
        ),
        (
            "unknown_field",
            "unknown request fields are refused",
            json!({"seeds": [seed(5)], "kid": "agent-1"}),
        ),
    ] {
        let got = run(directory_json, &req);
        assert_eq!(got["error"]["code"], "malformed", "{name}: {got}");
        directory.push(
            json!({"name": name, "why": why, "request": req, "expect": {"error": "malformed"}}),
        );
    }

    let out = json!({
        "version": "kzp-sign-vectors/1",
        "note": "Seeds are test-only: seed(n) is 32 bytes of n, base64url. Signing is Ed25519, which is deterministic, so a host must reproduce `expect` byte for byte.",
        "sign": sign.into_iter().chain(errors).collect::<Vec<_>>(),
        "directory": directory,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
