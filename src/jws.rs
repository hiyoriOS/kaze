//! JWS Compact with `EdDSA` (Ed25519), the only algorithm draft 0 allows.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{json, Error};

/// base64url without padding. Decoding rejects padding and non-canonical trailing bits.
#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Inverse of [`b64`].
pub fn unb64(s: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::Malformed("base64url"))
}

/// base64url(SHA-256(ascii)): the digest SD-JWT uses for disclosures and `sd_hash`.
#[must_use]
pub fn digest(ascii: &str) -> String {
    b64(&Sha256::digest(ascii.as_bytes()))
}

/// An Ed25519 public key as a JWK (RFC 8037).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Always `OKP`.
    pub kty: String,
    /// Always `Ed25519`.
    pub crv: String,
    /// The 32-byte public key, base64url.
    pub x: String,
    /// Key id; required where a key is chosen by `kid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl Jwk {
    /// Wraps a public key.
    #[must_use]
    pub fn new(key: &VerifyingKey, kid: Option<&str>) -> Self {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: b64(key.as_bytes()),
            kid: kid.map(Into::into),
        }
    }

    /// The public key, if this is a well-formed Ed25519 JWK.
    pub fn key(&self) -> Result<VerifyingKey, Error> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(Error::Alg);
        }
        let bytes: [u8; 32] = unb64(&self.x)?
            .try_into()
            .map_err(|_| Error::Malformed("jwk x"))?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Malformed("jwk x"))
    }
}

/// A decoded but not yet verified JWS.
#[derive(Debug, Clone)]
pub(crate) struct Token<'a> {
    pub(crate) header: Value,
    pub(crate) payload: Value,
    input: &'a str,
    sig: Vec<u8>,
}

impl Token<'_> {
    pub(crate) fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(Value::as_str)
    }

    /// Checks `alg` (and that no `crit` is present), then `typ`, then the signature.
    /// `sig_err` names the stage that failed.
    pub(crate) fn verify(
        &self,
        key: &VerifyingKey,
        typ: &str,
        sig_err: Error,
    ) -> Result<(), Error> {
        if self.header.get("alg").and_then(Value::as_str) != Some("EdDSA")
            || self.header.get("crit").is_some()
        {
            return Err(Error::Alg);
        }
        // RFC 7515 §4.1.9: compare as a media type, case-insensitively, with an
        // optional "application/" prefix.
        let got = self
            .header
            .get("typ")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !media(got).eq_ignore_ascii_case(typ) {
            return Err(Error::Typ);
        }
        let sig = Signature::from_slice(&self.sig).map_err(|_| sig_err.clone())?;
        key.verify_strict(self.input.as_bytes(), &sig)
            .map_err(|_| sig_err)
    }
}

/// Strips an optional, case-insensitive `application/` prefix.
fn media(typ: &str) -> &str {
    match (typ.get(..12), typ.get(12..)) {
        (Some(p), Some(rest)) if p.eq_ignore_ascii_case("application/") => rest,
        _ => typ,
    }
}

pub(crate) fn decode(token: &str) -> Result<Token<'_>, Error> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed("jws parts"));
    };
    let header = json::parse(&unb64(h)?)?;
    if !header.is_object() {
        return Err(Error::Malformed("jws header"));
    }
    let input_len = h.len().saturating_add(1).saturating_add(p.len());
    Ok(Token {
        header,
        payload: json::parse(&unb64(p)?)?,
        input: token
            .get(..input_len)
            .ok_or(Error::Malformed("jws parts"))?,
        sig: unb64(s)?,
    })
}

#[cfg(feature = "issue")]
pub(crate) fn sign(header: &Value, payload: &Value, key: &ed25519_dalek::SigningKey) -> String {
    use ed25519_dalek::Signer;
    // Serializing a Value cannot fail: keys are strings and numbers are finite.
    let enc = |v: &Value| b64(serde_json::to_string(v).unwrap_or_default().as_bytes());
    let input = format!("{}.{}", enc(header), enc(payload));
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
}
