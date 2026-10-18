//! The mandate: an SD-JWT with key binding, carrying `act` and `liab` (spec §5).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::offer::is_act;
use crate::{json, jws, Error, Jwk, Money};

/// The `typ` header of the issuer JWT.
pub const MANDATE_TYP: &str = "kaze-mandate+sd-jwt";
/// The `typ` header of the key-binding JWT.
pub const KB_TYP: &str = "kb+jwt";
/// The `typ` header of a liability attestation.
pub const LIAB_TYP: &str = "kaze-liab+jwt";
/// The `vct` of a draft-0 mandate.
pub const VCT: &str = "kaze.mandate.1";

/// Mandate claims after disclosure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Mandate {
    /// The issuer.
    pub iss: String,
    /// The principal; may be a pseudonym.
    pub sub: String,
    /// Issued at.
    pub iat: i64,
    /// Expiry.
    pub exp: i64,
    /// Mandate id; cumulative limits are tracked against it.
    pub jti: String,
    /// Always [`VCT`].
    pub vct: String,
    /// The agent key.
    pub cnf: Cnf,
    /// Delegated actions.
    pub act: Vec<Act>,
    /// The accountable operator, if named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liab: Option<Liab>,
    /// Any other disclosed or plain claims.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Confirmation key (RFC 7800).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    /// The agent's public key.
    pub jwk: Jwk,
}

/// One delegated action.
///
/// Unknown fields are rejected: a restriction an old verifier ignored would widen what
/// the agent may do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Act {
    /// An action id, or `<domain>:*`.
    pub act: String,
    /// Platform origins, or `*`.
    pub on: Vec<String>,
    /// Per-action ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<Money>,
    /// Approved by the principal for this specific action (spec §5.3).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hp: bool,
}

impl Act {
    /// Whether this entry covers `act` on `platform`: an exact id or `<domain>:*`, and
    /// `platform` or `*` in `on`. Every covering entry applies (spec §7 step 15).
    #[must_use]
    pub fn covers(&self, act: &str, platform: &str) -> bool {
        let id = match self.act.strip_suffix(":*") {
            Some(domain) => act.split_once(':').is_some_and(|(d, _)| d == domain),
            None => self.act == act,
        };
        id && self.on.iter().any(|o| o == "*" || o == platform)
    }

    /// Whether `on` names `platform` itself rather than only `*`.
    #[must_use]
    pub fn names(&self, platform: &str) -> bool {
        self.on.iter().any(|o| o == platform)
    }
}

/// The accountable operator and its provider's attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Liab {
    /// The operator origin.
    pub op: String,
    /// JWS Compact by the recourse provider, `typ` [`LIAB_TYP`].
    pub att: String,
}

/// The recourse provider's attestation inside `liab.att`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// The provider.
    pub iss: String,
    /// The operator it covers.
    pub sub: String,
    /// The cover.
    pub cover: Money,
    /// Issued at.
    pub iat: i64,
    /// Expiry.
    pub exp: i64,
}

/// The key-binding JWT: the closed, per-action mandate (spec §5.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// Issued at.
    pub iat: i64,
    /// The offer's `iss`.
    pub aud: String,
    /// The operator the agent acts for: the origin its Web Bot Auth key belongs to.
    pub op: String,
    /// The offer's `nonce`.
    pub nonce: String,
    /// base64url(SHA-256) of everything before the key binding.
    pub sd_hash: String,
    /// The single action requested.
    pub act: String,
    /// The term's `amount`, repeated; absent when the term has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amt: Option<Money>,
}

/// `<issuer-jwt>~<disclosure>~...~<kb-jwt>` split into its parts.
#[derive(Debug)]
pub(crate) struct Presentation<'a> {
    pub(crate) issuer: &'a str,
    pub(crate) disclosures: Vec<&'a str>,
    pub(crate) kb: &'a str,
    /// Everything up to and including the last `~`: what `sd_hash` covers.
    pub(crate) hashed: &'a str,
}

pub(crate) fn split(presentation: &str) -> Result<Presentation<'_>, Error> {
    let (body, kb) = presentation
        .rsplit_once('~')
        .ok_or(Error::Malformed("presentation"))?;
    let hashed = presentation
        .get(..body.len().saturating_add(1))
        .ok_or(Error::Malformed("presentation"))?;
    let mut parts = body.split('~');
    let issuer = parts.next().unwrap_or_default();
    let disclosures: Vec<&str> = parts.collect();
    if issuer.is_empty() || kb.is_empty() || disclosures.iter().any(|d| d.is_empty()) {
        return Err(Error::Malformed("presentation"));
    }
    Ok(Presentation {
        issuer,
        disclosures,
        kb,
        hashed,
    })
}

/// Folds top-level disclosures into the issuer payload (spec §7 step 5).
pub(crate) fn disclose(mut payload: Value, disclosures: &[&str]) -> Result<Value, Error> {
    let obj = payload
        .as_object_mut()
        .ok_or(Error::Malformed("issuer payload"))?;
    match obj.remove("_sd_alg") {
        None => {}
        Some(Value::String(a)) if a == "sha-256" => {}
        Some(_) => return Err(Error::Alg),
    }
    let mut digests = BTreeSet::new();
    match obj.remove("_sd") {
        None => {}
        Some(Value::Array(a)) => {
            for d in a {
                let Value::String(d) = d else {
                    return Err(Error::Malformed("_sd"));
                };
                if !digests.insert(d) {
                    return Err(Error::Malformed("_sd"));
                }
            }
        }
        Some(_) => return Err(Error::Malformed("_sd")),
    }
    for d in disclosures {
        // `remove` makes a repeated disclosure fail the second time.
        if !digests.remove(&jws::digest(d)) {
            return Err(Error::Disclosure);
        }
        let Value::Array(parts) = jws::unb64(d)
            .and_then(|raw| json::parse(&raw))
            .map_err(|_| Error::Disclosure)?
        else {
            return Err(Error::Disclosure);
        };
        let [Value::String(_salt), Value::String(name), value] =
            <[Value; 3]>::try_from(parts).map_err(|_| Error::Disclosure)?
        else {
            return Err(Error::Disclosure);
        };
        if name == "_sd" || name == "_sd_alg" || name == "..." || obj.contains_key(&name) {
            return Err(Error::Disclosure);
        }
        obj.insert(name, value);
    }
    Ok(payload)
}

impl Mandate {
    pub(crate) fn check(&self) -> Result<(), Error> {
        crate::time(self.iat)?;
        crate::time(self.exp)?;
        if self.act.is_empty() {
            return Err(Error::Malformed("act"));
        }
        for a in &self.act {
            if !is_act(&a.act, true) || a.on.is_empty() {
                return Err(Error::Malformed("act"));
            }
            if let Some(m) = &a.max {
                m.check()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::{disclose, split};
    use crate::Error;

    #[test]
    fn split_rejects_empty_parts() {
        assert!(split("a~b~c").is_ok());
        assert!(split("a~kb").is_ok());
        for bad in ["", "a", "~kb", "a~", "a~~kb", "a~b~~kb"] {
            assert_eq!(
                split(bad).err(),
                Some(Error::Malformed("presentation")),
                "{bad}"
            );
        }
    }

    #[test]
    fn split_hashes_through_last_tilde() {
        let p = split("iss~d1~d2~kb").ok();
        assert_eq!(p.as_ref().map(|p| p.hashed), Some("iss~d1~d2~"));
        assert_eq!(p.map(|p| p.disclosures), Some(vec!["d1", "d2"]));
    }

    #[test]
    fn duplicate_sd_digests_are_rejected() {
        let payload = serde_json::json!({"_sd": ["x", "x"]});
        assert_eq!(disclose(payload, &[]).err(), Some(Error::Malformed("_sd")));
    }
}
