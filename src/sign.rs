//! Signing an agent's HTTP requests, and publishing the keys that verify them
//! (feature `sign`).
//!
//! Nothing here needs an Offer, a mandate or any other Kaze object. An agent that
//! orders at a business that never issues Offers still has to prove who it is, and
//! that is all this module does: it adds the three Web Bot Auth headers
//! (`Signature-Agent`, `Signature-Input` and `Signature`; RFC 9421 with the profile in
//! `draft-ietf-webbotauth-httpsig-protocol`) to a [`Message`], and builds the key
//! directory the `Signature-Agent` URL points at.
//!
//! Like the rest of the crate these are pure functions: the caller supplies the key,
//! the clock readings and any nonce.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use sfv::{BareItem, Dictionary, FieldType, InnerList, Item, Key, ListEntry, Parameters};

use crate::{agent, Error, Jwk, Message};

/// The components covered when a caller doesn't choose: the method, the host and the
/// path. The agent's own `Signature-Agent` member is always covered in addition.
pub const DEFAULT_COMPONENTS: [&str; 3] = ["@method", "@authority", "@path"];

/// The media type of a key directory response.
pub const DIRECTORY_MEDIA_TYPE: &str = "application/http-message-signatures-directory+json";

/// What [`sign_request`] needs to know besides the message and the key.
#[derive(Clone, Copy, Debug)]
pub struct RequestSignature<'a> {
    /// The signature's label in `Signature` and `Signature-Input`, such as `sig`.
    pub label: &'a str,
    /// The `Signature-Agent` URL: the `https` origin that serves the key directory.
    pub agent_url: &'a str,
    /// `created`, in seconds.
    pub created: i64,
    /// `expires`, in seconds.
    pub expires: i64,
    /// `nonce`, if the verifier wants one. The caller owns its randomness.
    pub nonce: Option<&'a str>,
    /// The `tag` parameter. [`agent::TAG`] (`web-bot-auth`) for Web Bot Auth proper;
    /// a verifier that checks another profile names its own.
    pub tag: &'a str,
    /// The components to cover, in order: derived (`@authority`) or lowercase header
    /// names. At least one of `@authority` and `@target-uri` is required, and a
    /// header listed here must already be on the message. `signature-agent` is added
    /// after them and must not be listed. [`DEFAULT_COMPONENTS`] is the usual choice.
    pub components: &'a [&'a str],
}

/// Signs `msg`, adding `Signature-Agent`, `Signature-Input` and `Signature`.
///
/// The signature is Ed25519 (`alg="ed25519"`), and `keyid` is the key's JWK
/// thumbprint, the same id [`directory`] publishes. A request that already carries
/// these headers must not be signed again; `msg` is untouched if this fails.
pub fn sign_request(
    msg: &mut Message,
    sig: &RequestSignature<'_>,
    key: &SigningKey,
) -> Result<(), Error> {
    let bad = |_| Error::Malformed("signature input");
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
    if sig.tag.is_empty() {
        return Err(Error::Malformed("tag"));
    }
    let names = sig.components;
    if !names
        .iter()
        .any(|c| matches!(*c, "@authority" | "@target-uri"))
        || names
            .iter()
            .any(|c| c.eq_ignore_ascii_case("signature-agent"))
    {
        return Err(Error::AgentComponents);
    }

    let mut agent_header = Dictionary::new();
    agent_header.insert(
        key_of(sig.label)?,
        ListEntry::Item(Item::new(string(sig.agent_url)?)),
    );

    let mut items: Vec<Item> = names
        .iter()
        .map(|c| string(c).map(Item::new))
        .collect::<Result<_, _>>()?;
    let mut keyed = Parameters::new();
    keyed.insert(key_of("key")?, string(sig.label)?);
    items.push(Item::with_params(string("signature-agent")?, keyed));

    let jwk = Jwk::new(&key.verifying_key(), None);
    let mut params = Parameters::new();
    params.insert(key_of("created")?, int(sig.created)?);
    params.insert(key_of("expires")?, int(sig.expires)?);
    params.insert(key_of("keyid")?, string(&agent::thumbprint(&jwk)?)?);
    params.insert(key_of("alg")?, string("ed25519")?);
    if let Some(n) = sig.nonce {
        params.insert(key_of("nonce")?, string(n)?);
    }
    params.insert(key_of("tag")?, string(sig.tag)?);
    let components = InnerList::with_params(items, params);

    // The signed base reads the headers as they will be sent, so add `Signature-Agent`
    // to a copy of the message and only keep the result if everything succeeds.
    let agent_header = agent_header
        .serialize()
        .ok_or(Error::Malformed("signature agent"))?;
    let mut signed = msg.clone();
    signed
        .headers
        .push(("Signature-Agent".into(), agent_header));
    let base = agent::base(&signed, &components)?;
    let signature = ed25519_dalek::Signer::sign(key, base.as_bytes());

    let mut input = Dictionary::new();
    input.insert(key_of(sig.label)?, ListEntry::InnerList(components));
    let mut signature_header = Dictionary::new();
    signature_header.insert(
        key_of(sig.label)?,
        ListEntry::Item(Item::new(BareItem::ByteSequence(
            signature.to_bytes().to_vec(),
        ))),
    );
    for (name, dict) in [("Signature-Input", input), ("Signature", signature_header)] {
        let value = dict.serialize().ok_or(Error::Malformed("signature"))?;
        signed.headers.push((name.into(), value));
    }
    *msg = signed;
    Ok(())
}

/// The body served at `/.well-known/http-message-signatures-directory`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Directory {
    /// The agent's public keys, each with its JWK thumbprint as `kid`.
    pub keys: Vec<Jwk>,
}

/// The key directory for `keys`: list the current key and, while rotating, the next
/// (or the previous) one too. Each key's `kid` is its RFC 7638 thumbprint, which is
/// the `keyid` that [`sign_request`] puts in the signature.
pub fn directory(keys: &[VerifyingKey]) -> Result<Directory, Error> {
    let keys = keys
        .iter()
        .map(|k| {
            let jwk = Jwk::new(k, None);
            let kid = agent::thumbprint(&jwk)?;
            Ok(Jwk {
                kid: Some(kid),
                ..jwk
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(Directory { keys })
}
