//! Regenerates `vectors/agent.json`: Web Bot Auth cases for `verify_agent`. Keys come
//! from fixed seeds and Ed25519 is deterministic, so the output is reproducible.
//!
//!     cargo run --example agent --features issue > vectors/agent.json

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines
)]

use ed25519_dalek::SigningKey;
use kzp::{agent, issue, Jwk, Message};
use serde_json::{json, Value};

const NOW: i64 = 1_792_300_000;
const AGENT: &str = "https://agent.example";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn request() -> Message {
    Message {
        method: "POST".into(),
        scheme: "https".into(),
        authority: "api.ryo.example".into(),
        path: "/v1/agent/payments".into(),
        query: None,
        headers: vec![("Content-Type".into(), "application/json".into())],
    }
}

fn signed(url: &str, created: i64, expires: i64, k: &SigningKey) -> Message {
    let mut m = request();
    issue::sign_request(
        &mut m,
        "sig",
        url,
        created,
        expires,
        Some("bm9uY2Uta3pw"),
        k,
    )
    .unwrap();
    m
}

fn header(m: &mut Message, name: &str, f: impl Fn(&str) -> String) {
    for (n, v) in &mut m.headers {
        if n.eq_ignore_ascii_case(name) {
            *v = f(v);
        }
    }
}

fn main() {
    let agent_key = key(5);
    let other = key(6);
    let directory = vec![Jwk::new(&agent_key.verifying_key(), Some("agent-1"))];
    let dir_url = agent::directory_url(AGENT).unwrap();
    let ok = signed(AGENT, NOW - 10, NOW + 3600, &agent_key);
    let mut cases = Vec::new();
    let mut add =
        |name: &str, why: &str, m: &Message, d: &[Jwk], u: &str, now: i64, expect: Value| {
            cases.push(
                json!({"name": name, "why": why, "message": m, "directory": d,
                          "directory_url": u, "now": now, "expect": expect}),
            );
        };
    let err = |c: &str| json!({ "error": c });

    add(
        "ok_agent",
        "signed request, key in the agent's directory",
        &ok,
        &directory,
        &dir_url,
        NOW,
        json!({"ok": {"operator": AGENT, "label": "sig"}}),
    );
    let mut m = ok.clone();
    m.authority = "API.ryo.example:443".into();
    add(
        "ok_authority_normalized",
        "@authority is lowercased and drops the default port",
        &m,
        &directory,
        &dir_url,
        NOW,
        json!({"ok": {"operator": AGENT, "label": "sig"}}),
    );
    let mut m = signed(
        "https://agent.example/bots/hana",
        NOW - 10,
        NOW + 3600,
        &agent_key,
    );
    m.headers.retain(|_| true);
    add(
        "ok_agent_path",
        "an agent URL with a path; the operator is its origin",
        &m,
        &directory,
        &dir_url,
        NOW,
        json!({"ok": {"operator": AGENT, "label": "sig"}}),
    );

    let mut m = request();
    add(
        "agent_header",
        "no Web Bot Auth headers at all",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("agent_header"),
    );
    m = ok.clone();
    header(&mut m, "signature-input", |v| {
        v.replace("tag=\"web-bot-auth\"", "tag=\"other\"")
    });
    add(
        "agent_tag",
        "the only signature is not tagged web-bot-auth",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("agent_header"),
    );
    m = ok.clone();
    header(&mut m, "signature-input", |v| {
        format!("{v}, sig2={}", v.split_once('=').unwrap().1)
    });
    add(
        "agent_two",
        "two web-bot-auth signatures: which one speaks is ambiguous",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("agent_header"),
    );
    m = ok.clone();
    header(&mut m, "signature-input", |v| {
        v.replace("\"@authority\" ", "")
    });
    add(
        "agent_no_authority",
        "neither @authority nor @target-uri is covered",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("agent_components"),
    );
    m = ok.clone();
    header(&mut m, "signature-input", |v| {
        v.replace(" \"signature-agent\";key=\"sig\"", "")
    });
    add(
        "agent_no_agent",
        "the signature-agent member is not covered",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("agent_components"),
    );
    m = ok.clone();
    header(&mut m, "signature-input", |v| {
        v.replace("(\"@method\"", "(\"@query-param\";name=\"x\" \"@method\"")
    });
    add(
        "agent_unsupported",
        "a component this verifier cannot rebuild fails closed",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("agent_components"),
    );
    m = ok.clone();
    header(&mut m, "signature-input", |v| {
        v.replace("alg=\"ed25519\"", "alg=\"rsa-pss-sha512\"")
    });
    add(
        "agent_alg",
        "alg other than ed25519",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("alg"),
    );
    add(
        "agent_expired",
        "past expires",
        &ok,
        &directory,
        &dir_url,
        NOW + 3600,
        err("agent_expired"),
    );
    add(
        "agent_future",
        "created more than a minute ahead",
        &signed(AGENT, NOW + 120, NOW + 3600, &agent_key),
        &directory,
        &dir_url,
        NOW,
        err("agent_expired"),
    );
    add(
        "agent_too_long",
        "valid for more than 24 hours",
        &signed(AGENT, NOW - 10, NOW + 90_000, &agent_key),
        &directory,
        &dir_url,
        NOW,
        err("agent_expired"),
    );
    add(
        "agent_key_unknown",
        "no directory key has this keyid",
        &signed(AGENT, NOW - 10, NOW + 3600, &other),
        &directory,
        &dir_url,
        NOW,
        err("agent_key"),
    );
    add(
        "agent_key_directory",
        "the directory supplied belongs to another agent",
        &ok,
        &directory,
        &agent::directory_url("https://other.example").unwrap(),
        NOW,
        err("agent_key"),
    );
    add(
        "agent_key_http",
        "the agent URL is not https",
        &signed("http://agent.example", NOW - 10, NOW + 3600, &agent_key),
        &directory,
        &dir_url,
        NOW,
        err("agent_key"),
    );
    m = ok.clone();
    header(&mut m, "signature", |v| {
        // Flip spare trailing bits in the last base64 character before "==".
        let i = v.len() - 4;
        let pos = B64.iter().position(|c| *c == v.as_bytes()[i]).unwrap();
        let alt = B64[pos ^ 1] as char; // the lowest of the 4 spare bits
        format!("{}{alt}{}", &v[..i], &v[i + 1..])
    });
    add(
        "agent_noncanonical",
        "a non-canonical base64 signature for the same bytes",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("agent_header"),
    );
    m = ok.clone();
    m.path = "/v1/agent/refunds".into();
    add(
        "agent_signature_path",
        "request path changed after signing",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("agent_signature"),
    );
    m = ok.clone();
    m.authority = "evil.example".into();
    add(
        "agent_signature_authority",
        "a signature replayed against another host",
        &m,
        &directory,
        &dir_url,
        NOW,
        err("agent_signature"),
    );
    m = ok.clone();
    header(&mut m, "signature-agent", |_| {
        "sig=\"https://other.example\"".into()
    });
    add(
        "agent_signature_swapped",
        "Signature-Agent swapped to another operator",
        &m,
        &directory,
        &agent::directory_url("https://other.example").unwrap(),
        NOW,
        err("agent_signature"),
    );

    let out = json!({
        "version": "kzp-agent-vectors/1",
        "note": "Seeds are test-only: key(n) = Ed25519 from 32 bytes of n. agent=5 other=6.",
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
