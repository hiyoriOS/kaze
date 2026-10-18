//! The Offer: a platform's signed admission terms (spec §4).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{jws, Error, Jwk, MAX_INT, SHORT, SKEW};

/// The `typ` header of an Offer.
pub const OFFER_TYP: &str = "kaze-offer+jwt";

/// Integer minor units plus an ISO 4217 code; never floating point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Money {
    /// Minor units, at most 2^53 - 1 so every JSON parser reads it exactly.
    pub value: u64,
    /// Three uppercase ASCII letters.
    pub currency: String,
}

impl Money {
    pub(crate) fn check(&self) -> Result<(), Error> {
        let code = self.currency.as_bytes();
        if self.value > MAX_INT || code.len() != 3 || !code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Malformed("money"));
        }
        Ok(())
    }
}

/// The decoded Offer payload.
///
/// Unknown fields are ignored (forward compatible): an Offer only ever restricts the
/// platform that signed it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Offer {
    /// The platform origin; the key binding's `aud`.
    pub iss: String,
    /// Issued at.
    pub iat: i64,
    /// Expiry; `exp - iat` is at most [`SHORT`].
    pub exp: i64,
    /// Single-use, at least 16 random bytes, base64url.
    pub nonce: String,
    /// The resource the terms apply to.
    pub resource: String,
    /// One entry per action; `act` values are unique.
    pub terms: Vec<Term>,
}

/// Terms for one action.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Term {
    /// The action id, `<domain>:<verb>`.
    pub act: String,
    /// Identity required; draft 0 knows only `signed` (Web Bot Auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Present when a mandate is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate: Option<MandateNeed>,
    /// Present when an accountable operator is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liab: Option<LiabNeed>,
    /// The exact amount this action charges or commits. The key binding must repeat
    /// it, and every covering `act` entry's `max` must allow it. Required with `price`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<Money>,
    /// x402 `PaymentRequirements` or an MPP challenge, carried verbatim. Kaze does not
    /// read it; `amount` is what the verifier checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<Value>,
    /// Requests per operator per window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quota>,
    /// The sanctioned path for this action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Who runs checkout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkout: Option<Checkout>,
}

/// What a term demands of the mandate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateNeed {
    /// Human present (spec §5.3).
    #[serde(default)]
    pub hp: bool,
}

/// What a term demands of the operator's cover.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiabNeed {
    /// The minimum cover.
    pub cover: Money,
    /// Recourse providers the platform accepts, by `iss`.
    pub providers: Vec<String>,
}

/// Requests allowed per operator in each window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// Window length in seconds.
    pub window: u32,
    /// Requests allowed in the window.
    pub max: u32,
}

/// Who completes checkout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Checkout {
    /// The agent hands the user to the platform's checkout.
    Platform,
    /// The agent may complete checkout.
    Agent,
}

impl Offer {
    /// The term for `act`, if offered.
    #[must_use]
    pub fn term(&self, act: &str) -> Option<&Term> {
        self.terms.iter().find(|t| t.act == act)
    }

    fn check(&self) -> Result<(), Error> {
        let (iat, exp) = (crate::time(self.iat)?, crate::time(self.exp)?);
        if exp < iat || exp.saturating_sub(iat) > SHORT {
            return Err(Error::Malformed("offer lifetime"));
        }
        if jws::unb64(&self.nonce)?.len() < 16 {
            return Err(Error::Malformed("nonce"));
        }
        if self.terms.is_empty() {
            return Err(Error::Malformed("terms"));
        }
        let mut seen = BTreeSet::new();
        for t in &self.terms {
            if !is_act(&t.act, false) || !seen.insert(t.act.as_str()) {
                return Err(Error::Malformed("term act"));
            }
            if let Some(a) = &t.amount {
                a.check()?;
            } else if t.price.is_some() {
                return Err(Error::Malformed("price without amount"));
            }
            if let Some(l) = &t.liab {
                l.cover.check()?;
                if l.providers.is_empty() {
                    return Err(Error::Malformed("liab providers"));
                }
            }
        }
        Ok(())
    }
}

/// `<domain>:<verb>` over `[a-z0-9_.-]`; with `pattern`, the verb may be `*`.
pub(crate) fn is_act(s: &str, pattern: bool) -> bool {
    let part = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
    };
    match s.split_once(':') {
        Some((d, "*")) => pattern && part(d),
        Some((d, v)) => part(d) && part(v),
        None => false,
    }
}

/// An [`Offer`] that passed [`verify_offer`]. Only `verify_offer` constructs one, so a
/// [`Context`](crate::Context) can never carry an unchecked offer.
#[derive(Clone, Debug, PartialEq)]
pub struct Verified(Offer);

impl std::ops::Deref for Verified {
    type Target = Offer;
    fn deref(&self) -> &Offer {
        &self.0
    }
}

impl Verified {
    /// The verified offer.
    #[must_use]
    pub fn into_inner(self) -> Offer {
        self.0
    }
}

/// Verifies an offer (spec §7 steps 1-2): its signature against `jwks`, that it was
/// issued by `iss` (the origin the JWKS was fetched from), and that it is current.
///
/// Agents run this before acting on an offer; a platform runs it on the offer it issued.
pub fn verify_offer(token: &str, jwks: &[Jwk], iss: &str, now: i64) -> Result<Verified, Error> {
    let now = crate::time(now)?;
    let t = jws::decode(token)?;
    let kid = t.kid().ok_or(Error::OfferSignature)?;
    let jwk = jwks
        .iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .ok_or(Error::OfferSignature)?;
    t.verify(&jwk.key()?, OFFER_TYP, Error::OfferSignature)?;
    let offer: Offer = serde_json::from_value(t.payload).map_err(|_| Error::Malformed("offer"))?;
    offer.check()?;
    if offer.iss != iss {
        return Err(Error::OfferIssuer);
    }
    if offer.exp <= now || offer.iat > now.saturating_add(SKEW) {
        return Err(Error::OfferExpired);
    }
    Ok(Verified(offer))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::is_act;

    #[test]
    fn action_ids() {
        assert!(is_act("order:create", false));
        assert!(is_act("order:*", true));
        assert!(!is_act("order:*", false));
        assert!(!is_act("*", true));
        assert!(!is_act(":*", true));
        assert!(!is_act("Order:create", false));
        assert!(!is_act("order:create:x", false));
        assert!(!is_act("order:", false));
    }
}
