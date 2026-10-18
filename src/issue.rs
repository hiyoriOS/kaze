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

/// Signs `msg` for Web Bot Auth, adding `Signature-Agent`, `Signature-Input` and
/// `Signature` (draft-ietf-webbotauth-httpsig-protocol). Covers `@method`,
/// `@authority`, `@path` and the request's own `signature-agent` member.
pub fn sign_request(
    msg: &mut crate::Message,
    label: &str,
    agent_url: &str,
    created: i64,
    expires: i64,
    nonce: Option<&str>,
    key: &SigningKey,
) -> Result<(), crate::Error> {
    use sfv::{BareItem, Dictionary, FieldType, InnerList, Item, Key, ListEntry, Parameters};
    let bad = |_| crate::Error::Malformed("signature input");
    let key_of = |k: &str| Key::from_string(k.to_owned()).map_err(|(e, _)| bad(e));
    let string = |s: &str| {
        sfv::String::from_string(s.to_owned())
            .map(BareItem::String)
            .map_err(|(e, _)| bad(e))
    };
    let int = |i: i64| {
        sfv::Integer::try_from(i)
            .map(BareItem::Integer)
            .map_err(bad)
    };

    let mut agent = Dictionary::new();
    agent.insert(
        key_of(label)?,
        ListEntry::Item(Item::new(string(agent_url)?)),
    );
    msg.headers.push((
        "Signature-Agent".into(),
        agent
            .serialize()
            .ok_or(crate::Error::Malformed("signature agent"))?,
    ));

    let mut items: Vec<Item> = ["@method", "@authority", "@path"]
        .iter()
        .map(|c| string(c).map(Item::new))
        .collect::<Result<_, _>>()?;
    let mut keyed = Parameters::new();
    keyed.insert(key_of("key")?, string(label)?);
    items.push(Item::with_params(string("signature-agent")?, keyed));

    let jwk = crate::Jwk::new(&key.verifying_key(), None);
    let mut params = Parameters::new();
    params.insert(key_of("created")?, int(created)?);
    params.insert(key_of("expires")?, int(expires)?);
    params.insert(key_of("keyid")?, string(&crate::agent::thumbprint(&jwk)?)?);
    params.insert(key_of("alg")?, string("ed25519")?);
    if let Some(n) = nonce {
        params.insert(key_of("nonce")?, string(n)?);
    }
    params.insert(key_of("tag")?, string(crate::agent::TAG)?);
    let components = InnerList::with_params(items, params);

    let base = crate::agent::base(msg, &components)?;
    let sig = ed25519_dalek::Signer::sign(key, base.as_bytes());

    let mut input = Dictionary::new();
    input.insert(key_of(label)?, ListEntry::InnerList(components));
    let mut signature = Dictionary::new();
    signature.insert(
        key_of(label)?,
        ListEntry::Item(Item::new(BareItem::ByteSequence(sig.to_bytes().to_vec()))),
    );
    for (name, dict) in [("Signature-Input", input), ("Signature", signature)] {
        let value = dict
            .serialize()
            .ok_or(crate::Error::Malformed("signature"))?;
        msg.headers.push((name.into(), value));
    }
    Ok(())
}
