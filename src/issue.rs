//! Producing offers, attestations, mandates and presentations (feature `issue`).
//!
//! Platforms, issuers and agents use these; verifiers don't need them.

use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::{json, Value};

use crate::mandate::{KB_TYP, LIAB_TYP, MANDATE_TYP};
use crate::offer::OFFER_TYP;
use crate::{jws, Attestation, Binding, Offer};

fn value<T: Serialize>(v: &T) -> Value {
    // These types hold only strings, integers and options: serializing cannot fail.
    serde_json::to_value(v).unwrap_or(Value::Null)
}

/// Signs an offer.
#[must_use]
pub fn offer(o: &Offer, kid: &str, key: &SigningKey) -> String {
    let header = json!({"alg": "EdDSA", "typ": OFFER_TYP, "kid": kid});
    jws::sign(&header, &value(o), key)
}

/// Signs a liability attestation.
#[must_use]
pub fn attestation(a: &Attestation, kid: &str, key: &SigningKey) -> String {
    let header = json!({"alg": "EdDSA", "typ": LIAB_TYP, "kid": kid});
    jws::sign(&header, &value(a), key)
}

/// One disclosure, `[salt, name, value]`, base64url. `salt` should carry at least 128
/// bits of randomness; it is a parameter so test vectors stay deterministic.
#[must_use]
pub fn disclosure(salt: &str, name: &str, value: &Value) -> String {
    let arr = json!([salt, name, value]);
    jws::b64(serde_json::to_string(&arr).unwrap_or_default().as_bytes())
}

/// Signs an issuer JWT whose `_sd` holds the sorted digests of `disclosures`. `plain`
/// must be a JSON object of the always-visible claims; anything else is wrapped as
/// `{}`.
#[must_use]
pub fn mandate(plain: Value, disclosures: &[String], kid: &str, key: &SigningKey) -> String {
    let mut obj = match plain {
        Value::Object(o) => o,
        _ => serde_json::Map::new(),
    };
    let mut digests: Vec<String> = disclosures.iter().map(|d| jws::digest(d)).collect();
    digests.sort();
    obj.insert("_sd".into(), json!(digests));
    obj.insert("_sd_alg".into(), json!("sha-256"));
    let header = json!({"alg": "EdDSA", "typ": MANDATE_TYP, "kid": kid});
    jws::sign(&header, &Value::Object(obj), key)
}

/// `<issuer>~<d1>~...~`: the part `sd_hash` covers.
#[must_use]
pub fn prefix(issuer: &str, disclosures: &[String]) -> String {
    let mut s = String::from(issuer);
    s.push('~');
    for d in disclosures {
        s.push_str(d);
        s.push('~');
    }
    s
}

/// Signs the key binding over `prefix`, filling in `sd_hash`, and returns the full
/// presentation.
#[must_use]
pub fn present(prefix: &str, mut binding: Binding, agent: &SigningKey) -> String {
    binding.sd_hash = jws::digest(prefix);
    let header = json!({"alg": "EdDSA", "typ": KB_TYP});
    let kb = jws::sign(&header, &value(&binding), agent);
    format!("{prefix}{kb}")
}
