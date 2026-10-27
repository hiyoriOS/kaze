//! Request signing and the key directory: known answers from `vectors/sign.json`, and
//! an independent check that what `sign_request` emits is an RFC 9421 Ed25519
//! signature of the shape Web Bot Auth verifiers expect.
//!
//! The independent check parses the headers with `sfv` and rebuilds the signature base
//! from RFC 9421 §2.5 on its own: it shares no code with `agent::base`, which both
//! `sign_request` and `verify_agent` use.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::format_push_string,
    clippy::type_complexity
)]

use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use kzp::agent::{self, verify_agent_with_tag};
use kzp::sign::{self, RequestSignature};
use kzp::{Error, Jwk, Message};
use serde_json::{json, Value};
use sfv::{BareItem, Dictionary, ListEntry, Parser};
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/sign.json")).unwrap()
}

fn seed_of(request: &Value) -> SigningKey {
    let bytes: [u8; 32] = kzp::jws::unb64(request["seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    SigningKey::from_bytes(&bytes)
}

fn run(f: fn(&[u8]) -> Vec<u8>, request: &Value) -> Value {
    serde_json::from_slice(&f(&serde_json::to_vec(request).unwrap())).unwrap()
}

/// Every known answer, through the same JSON entry points the WebAssembly host uses.
#[test]
fn sign_vectors() {
    let file = vectors();
    let mut failed = Vec::new();
    for c in file["sign"].as_array().unwrap() {
        let got = run(kzp::abi::sign_request_json, &c["request"]);
        let got = got.get("ok").map_or_else(
            || json!({"error": got["error"]["code"]}),
            |m| json!({"ok": m}),
        );
        if got != c["expect"] {
            failed.push(format!("{}: {got}", c["name"]));
        }
    }
    for c in file["directory"].as_array().unwrap() {
        let got = run(kzp::abi::directory_json, &c["request"]);
        let got = got.get("ok").map_or_else(
            || json!({"error": got["error"]["code"]}),
            |m| json!({"ok": m}),
        );
        if got != c["expect"] {
            failed.push(format!("directory {}: {got}", c["name"]));
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
}

/// A host that sends no `tag` and no `components` gets what it got before they
/// existed: the signature in the 0.3 Web Bot Auth vector, byte for byte.
#[test]
fn default_request_is_unchanged() {
    let sign = vectors();
    let agent: Value = serde_json::from_str(include_str!("../vectors/agent.json")).unwrap();
    let old = agent["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ok_agent")
        .unwrap();
    let new = sign["sign"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ok_default")
        .unwrap();
    assert!(new["request"].get("tag").is_none() && new["request"].get("components").is_none());
    assert_eq!(new["expect"]["ok"], old["message"]);
}

/// Everything `sign_request` produces verifies with `verify_agent_with_tag`, for the
/// tag it was given and no other.
#[test]
fn signed_requests_verify_for_their_tag_only() {
    for c in vectors()["sign"].as_array().unwrap() {
        let Some(signed) = c["expect"].get("ok") else {
            continue;
        };
        let message: Message = serde_json::from_value(signed.clone()).unwrap();
        let key = seed_of(&c["request"]);
        let directory = sign::directory(&[key.verifying_key()]).unwrap().keys;
        let url = agent::directory_url(c["request"]["agent_url"].as_str().unwrap()).unwrap();
        let tag = c["request"]["tag"].as_str().unwrap_or(agent::TAG);
        let now = c["request"]["created"].as_i64().unwrap() + 10;
        let who = verify_agent_with_tag(&message, &directory, &url, now, tag)
            .unwrap_or_else(|e| panic!("{}: {e}", c["name"]));
        assert_eq!(who.operator, "https://agent.example");
        assert_eq!(who.keyid, directory[0].kid.clone().unwrap());
        assert_eq!(
            verify_agent_with_tag(&message, &directory, &url, now, "not-this-tag").unwrap_err(),
            Error::AgentHeader,
            "{}",
            c["name"]
        );
    }
}

/// RFC 7638 thumbprint of an Ed25519 key, computed here from its definition.
fn thumbprint(key: &VerifyingKey) -> String {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_bytes());
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonical))
}

fn header<'a>(m: &'a Message, name: &str) -> &'a str {
    let mut all = m
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name));
    let (_, value) = all.next().unwrap_or_else(|| panic!("no {name} header"));
    assert!(all.next().is_none(), "{name} sent twice");
    value
}

/// RFC 9421 §2.1 and §2.2 for the components these requests use.
fn component_value(m: &Message, name: &str) -> String {
    match name {
        "@method" => m.method.clone(),
        "@authority" => m.authority.to_ascii_lowercase(),
        "@path" => m.path.clone(),
        "@scheme" => m.scheme.clone(),
        "@target-uri" => format!(
            "{}://{}{}",
            m.scheme,
            m.authority.to_ascii_lowercase(),
            m.path
        ),
        _ => header(m, name).trim().to_owned(),
    }
}

/// Verifies the `label` signature on `m` as RFC 9421 and the Web Bot Auth profile say,
/// returning the covered component names.
fn verify_rfc9421(m: &Message, key: &VerifyingKey, tag: &str) -> Vec<String> {
    let inputs: Dictionary = Parser::new(header(m, "signature-input")).parse().unwrap();
    let signatures: Dictionary = Parser::new(header(m, "signature")).parse().unwrap();
    assert_eq!(inputs.len(), 1);
    let (label, ListEntry::InnerList(covered)) = inputs.iter().next().unwrap() else {
        panic!("Signature-Input member is not an inner list");
    };
    let label = label.as_str();

    // Signature: one member, a 64-byte byte sequence, in canonical `:base64:` form.
    let Some((_, ListEntry::Item(sig))) = signatures.iter().find(|(k, _)| k.as_str() == label)
    else {
        panic!("no signature for {label}");
    };
    let BareItem::ByteSequence(sig) = &sig.bare_item else {
        panic!("signature is not a byte sequence");
    };
    assert_eq!(sig.len(), 64);
    assert_eq!(
        header(m, "signature"),
        format!(
            "{label}=:{}:",
            base64::engine::general_purpose::STANDARD.encode(sig)
        )
    );

    // Signature-Agent: a dictionary whose member for the label is the agent URL.
    let agents: Dictionary = Parser::new(header(m, "signature-agent")).parse().unwrap();
    let Some((_, ListEntry::Item(url))) = agents.iter().find(|(k, _)| k.as_str() == label) else {
        panic!("Signature-Agent has no member {label}");
    };
    assert!(url
        .bare_item
        .as_string()
        .unwrap()
        .as_str()
        .starts_with("https://"));

    // The signature base (§2.5): one line per covered component, then the params.
    let mut base = String::new();
    let mut names = Vec::new();
    for item in &covered.items {
        let name = item.bare_item.as_string().unwrap().as_str();
        let value = if name == "signature-agent" {
            // Web Bot Auth covers the agent's own dictionary member (§2.1.2).
            assert_eq!(item.params.len(), 1);
            assert_eq!(
                item.params
                    .iter()
                    .next()
                    .unwrap()
                    .1
                    .as_string()
                    .unwrap()
                    .as_str(),
                label
            );
            let (_, ListEntry::Item(member)) =
                agents.iter().find(|(k, _)| k.as_str() == label).unwrap()
            else {
                unreachable!()
            };
            // A string member serializes as itself in quotes (RFC 9651 §4.1.6).
            format!("\"{}\"", member.bare_item.as_string().unwrap().as_str())
        } else {
            assert!(item.params.is_empty(), "{name} carries parameters");
            component_value(m, name)
        };
        let line_name = if name == "signature-agent" {
            format!("\"{name}\";key=\"{label}\"")
        } else {
            format!("\"{name}\"")
        };
        base.push_str(&format!("{line_name}: {value}\n"));
        names.push(name.to_owned());
    }
    // The signature parameters are exactly the Signature-Input member's own text.
    let raw = header(m, "signature-input");
    let params = raw.strip_prefix(&format!("{label}=")).unwrap();
    base.push_str(&format!("\"@signature-params\": {params}"));
    key.verify_strict(base.as_bytes(), &Signature::from_slice(sig).unwrap())
        .unwrap_or_else(|e| panic!("signature does not verify over\n{base}\n{e}"));

    // Web Bot Auth profile: required components and parameters.
    assert!(names
        .iter()
        .any(|n| n == "@authority" || n == "@target-uri"));
    assert_eq!(names.last().unwrap(), "signature-agent");
    let p = &covered.params;
    let get = |k: &str| p.iter().find(|(n, _)| n.as_str() == k).map(|(_, v)| v);
    let string = |k: &str| {
        get(k)
            .and_then(BareItem::as_string)
            .map(|s| s.as_str().to_owned())
    };
    let int = |k: &str| get(k).and_then(BareItem::as_integer).map(i64::from);
    assert_eq!(string("tag").as_deref(), Some(tag));
    assert_eq!(string("alg").as_deref(), Some("ed25519"));
    assert_eq!(string("keyid").unwrap(), thumbprint(key));
    assert!(int("created").unwrap() < int("expires").unwrap());
    assert!(
        p.iter().all(
            |(k, _)| ["created", "expires", "keyid", "alg", "nonce", "tag"].contains(&k.as_str())
        ),
        "unexpected signature parameter in {raw}"
    );
    names
}

#[test]
fn output_is_rfc9421_ed25519_web_bot_auth() {
    let mut checked = 0;
    for c in vectors()["sign"].as_array().unwrap() {
        let Some(signed) = c["expect"].get("ok") else {
            continue;
        };
        let m: Message = serde_json::from_value(signed.clone()).unwrap();
        let key = seed_of(&c["request"]).verifying_key();
        let tag = c["request"]["tag"].as_str().unwrap_or("web-bot-auth");
        let names = verify_rfc9421(&m, &key, tag);
        match c["request"].get("components") {
            Some(want) => {
                let mut want: Vec<&str> = want
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect();
                want.push("signature-agent");
                assert_eq!(names, want, "{}", c["name"]);
            }
            None => assert_eq!(
                names,
                ["@method", "@authority", "@path", "signature-agent"],
                "{}",
                c["name"]
            ),
        }
        let nonce = c["request"].get("nonce").is_some();
        assert_eq!(header(&m, "signature-input").contains(";nonce="), nonce);
        checked += 1;
    }
    assert_eq!(checked, 5);
}

/// The one thing an Ed25519 signature check cannot show: that editing any covered part
/// of the request after signing is caught, and an uncovered part is not.
#[test]
fn covered_components_bind_the_request() {
    let c = vectors()["sign"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ok_components")
        .unwrap()
        .clone();
    let key = seed_of(&c["request"]).verifying_key();
    let signed: Message = serde_json::from_value(c["expect"]["ok"].clone()).unwrap();
    let directory = sign::directory(&[key]).unwrap().keys;
    let url = agent::directory_url("https://agent.example").unwrap();
    let now = c["request"]["created"].as_i64().unwrap() + 10;
    let check = |m: &Message| verify_agent_with_tag(m, &directory, &url, now, agent::TAG);
    assert!(check(&signed).is_ok());

    let edits: [(&str, fn(&mut Message)); 5] = [
        ("method", |m| m.method = "PUT".into()),
        ("authority", |m| m.authority = "evil.example".into()),
        ("path", |m| m.path = "/v1/agent/refunds".into()),
        ("content-type", |m| m.headers[0].1 = "text/plain".into()),
        ("content-digest", |m| {
            let h = m
                .headers
                .iter_mut()
                .find(|(n, _)| n == "Content-Digest")
                .unwrap();
            h.1 = "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".into();
        }),
    ];
    for (what, edit) in edits {
        let mut m = signed.clone();
        edit(&mut m);
        assert_eq!(check(&m).unwrap_err(), Error::AgentSignature, "{what}");
    }
    // The query is not covered by these components, so it is not bound.
    let mut m = signed;
    m.query = Some("x=1".into());
    assert!(check(&m).is_ok());
}

#[test]
fn a_failed_signature_leaves_the_message_alone() {
    let key = SigningKey::from_bytes(&[5; 32]);
    let mut m = Message {
        method: "GET".into(),
        scheme: "https".into(),
        authority: "api.ryo.example".into(),
        path: "/".into(),
        query: None,
        headers: vec![("Accept".into(), "*/*".into())],
    };
    let before = m.clone();
    let sig = RequestSignature {
        label: "sig",
        agent_url: "https://agent.example",
        created: 1,
        expires: 2,
        nonce: None,
        tag: "web-bot-auth",
        components: &["@method", "@path"],
    };
    assert_eq!(
        sign::sign_request(&mut m, &sig, &key),
        Err(Error::AgentComponents)
    );
    assert_eq!(m, before);
    let sig = RequestSignature {
        components: &["@authority"],
        tag: "",
        ..sig
    };
    assert!(matches!(
        sign::sign_request(&mut m, &sig, &key),
        Err(Error::Malformed("tag"))
    ));
    assert_eq!(m, before);
}

#[test]
fn directory_publishes_the_thumbprint_as_kid() {
    let keys: Vec<VerifyingKey> = [5u8, 7]
        .iter()
        .map(|n| SigningKey::from_bytes(&[*n; 32]).verifying_key())
        .collect();
    let dir = sign::directory(&keys).unwrap();
    assert_eq!(dir.keys.len(), 2);
    for (jwk, key) in dir.keys.iter().zip(&keys) {
        assert_eq!(jwk.kid.as_deref(), Some(thumbprint(key).as_str()));
        assert_eq!(jwk.key().unwrap(), *key);
    }
    // The wire form is the RFC 7517 JWK Set shape with a `keys` array.
    let wire = serde_json::to_value(&dir).unwrap();
    assert_eq!(wire["keys"][0]["kty"], "OKP");
    assert_eq!(wire["keys"][0]["crv"], "Ed25519");
    assert_eq!(wire.as_object().unwrap().len(), 1);
    // And it round-trips into what `verify_agent` consumes.
    let back: Vec<Jwk> = serde_json::from_value(wire["keys"].clone()).unwrap();
    assert_eq!(back, dir.keys);
}
