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
use kzp::sign::{self, RequestSignature};
use kzp::{agent, Jwk, Message};
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
    signed_with(
        request(),
        url,
        created,
        expires,
        k,
        agent::TAG,
        &sign::DEFAULT_COMPONENTS,
    )
}

fn signed_with(
    mut m: Message,
    url: &str,
    created: i64,
    expires: i64,
    k: &SigningKey,
    tag: &str,
    components: &[&str],
) -> Message {
    sign::sign_request(
        &mut m,
        &RequestSignature {
            label: "sig",
            agent_url: url,
            created,
            expires,
            nonce: Some("bm9uY2Uta3pw"),
            tag,
            components,
        },
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

    // The cases below choose the tag and the covered components. They come last, and
    // only they carry a `tag`, so every case above is unchanged.
    let payer = "agent-payer-auth";
    let mut add_tagged = |name: &str, why: &str, tag: &str, m: &Message, expect: Value| {
        cases.push(
            json!({"name": name, "why": why, "message": m, "directory": directory,
                      "directory_url": dir_url, "now": NOW, "tag": tag, "expect": expect}),
        );
    };
    let tagged = signed_with(
        request(),
        AGENT,
        NOW - 10,
        NOW + 300,
        &agent_key,
        payer,
        &sign::DEFAULT_COMPONENTS,
    );
    add_tagged(
        "ok_tag",
        "a caller-chosen tag, verified against that tag",
        payer,
        &tagged,
        json!({"ok": {"operator": AGENT, "label": "sig"}}),
    );
    add_tagged(
        "tag_mismatch",
        "signed with one tag, verified for another",
        "agent-browser-auth",
        &tagged,
        err("agent_header"),
    );
    add_tagged(
        "tag_not_default",
        "a signature with another tag is not a web-bot-auth signature",
        agent::TAG,
        &tagged,
        err("agent_header"),
    );
    let mut m = ok.clone();
    header(&mut m, "signature-input", |v| {
        v.replace("tag=\"web-bot-auth\"", "tag=\"agent-payer-auth\"")
    });
    add_tagged(
        "tag_edited",
        "the tag was changed after signing, so the signature no longer matches",
        payer,
        &m,
        err("agent_signature"),
    );
    let mut with_body = request();
    with_body.headers.push((
        "Content-Digest".into(),
        "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".into(),
    ));
    let bound = signed_with(
        with_body,
        AGENT,
        NOW - 10,
        NOW + 300,
        &agent_key,
        agent::TAG,
        &[
            "@method",
            "@authority",
            "@path",
            "content-type",
            "content-digest",
        ],
    );
    add_tagged(
        "ok_components",
        "the signature also covers the body's Content-Digest and the Content-Type",
        agent::TAG,
        &bound,
        json!({"ok": {"operator": AGENT, "label": "sig"}}),
    );
    let mut m = bound.clone();
    header(&mut m, "content-digest", |_| {
        "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".into()
    });
    add_tagged(
        "components_digest_edited",
        "the body digest changed after signing: the covered Content-Digest binds the body",
        agent::TAG,
        &m,
        err("agent_signature"),
    );
    let target = signed_with(
        request(),
        AGENT,
        NOW - 10,
        NOW + 300,
        &agent_key,
        agent::TAG,
        &["@target-uri"],
    );
    add_tagged(
        "ok_target_uri",
        "@target-uri alone is enough to bind the request to its host",
        agent::TAG,
        &target,
        json!({"ok": {"operator": AGENT, "label": "sig"}}),
    );

    let out = json!({
        "version": "kzp-agent-vectors/1",
        "note": "Seeds are test-only: key(n) = Ed25519 from 32 bytes of n. agent=5 other=6.",
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
