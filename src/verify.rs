//! Platform-side verification: spec §7 steps 3-21, in order. Steps 1-2, the offer
//! itself, are [`verify_offer`](crate::verify_offer).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::mandate::{self, Attestation, Binding, Mandate, KB_TYP, LIAB_TYP, MANDATE_TYP, VCT};
use crate::offer::Verified;
use crate::{jws, Error, Jwk, Money, SHORT, SKEW};

/// Keys the platform trusts, grouped by who holds them.
///
/// Issuers and providers are keyed by their `iss`; each has its own keys, chosen by
/// `kid`. A mandate's `iss` must match the issuer whose key signed it, so `principal`
/// and `jti` in a [`Grant`] are always scoped to one issuer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    /// Mandate issuer keys by issuer `iss`.
    pub issuers: BTreeMap<String, Vec<Jwk>>,
    /// Recourse provider keys by provider `iss`.
    pub providers: BTreeMap<String, Vec<Jwk>>,
}

fn pick<'a>(keys: Option<&'a Vec<Jwk>>, kid: Option<&str>) -> Option<&'a Jwk> {
    let kid = kid?;
    keys?.iter().find(|k| k.kid.as_deref() == Some(kid))
}

/// What the platform knows when it verifies.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// Seconds since the epoch.
    pub now: i64,
    /// The operator origin the platform's Web Bot Auth check established.
    pub operator: &'a str,
    /// The offer this presentation answers.
    pub offer: &'a Verified,
}

/// What the caller acts on.
///
/// The caller must still record `nonce` as used, enforce quota and cumulative limits by
/// (`issuer`, `jti`), and settle `price` for exactly `amount` (spec §7).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    /// The admitted action.
    pub act: String,
    /// The term's amount, confirmed by the agent and within every covering `max`.
    pub amount: Option<Money>,
    /// The mandate issuer.
    pub issuer: String,
    /// The mandate id, unique per issuer.
    pub jti: String,
    /// The offer nonce to mark used.
    pub nonce: String,
    /// The principal (`sub`), scoped to `issuer`.
    pub principal: String,
    /// The operator the action is attributed to.
    pub operator: String,
    /// The term's price, to settle through x402 or MPP.
    pub price: Option<Value>,
}

/// Verifies a mandate presentation against an offer (spec §7 steps 3-21).
#[allow(clippy::too_many_lines)] // one function per spec section reads in spec order
pub fn verify(presentation: &str, ctx: &Context<'_>, trust: &Trust) -> Result<Grant, Error> {
    let offer = ctx.offer;
    // Every time below is in [0, MAX_INT]; saturating arithmetic is belt and braces.
    let now = crate::time(ctx.now)?;
    if offer.exp <= now {
        return Err(Error::OfferExpired);
    }

    // 3-4. issuer: its `iss` picks the key set, its `kid` the key.
    let p = mandate::split(presentation)?;
    let issuer = jws::decode(p.issuer)?;
    let iss = issuer
        .payload
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let key = pick(trust.issuers.get(iss), issuer.kid()).ok_or(Error::UnknownKey)?;
    issuer.verify(&key.key()?, MANDATE_TYP, Error::IssuerSignature)?;

    // 5-7. disclosures, vct, validity
    let claims = mandate::disclose(issuer.payload, &p.disclosures)?;
    if claims.get("vct").and_then(Value::as_str) != Some(VCT) {
        return Err(Error::Vct);
    }
    let m: Mandate =
        serde_json::from_value(claims).map_err(|_| Error::Malformed("mandate claims"))?;
    m.check()?;
    if m.iat > now.saturating_add(SKEW) || m.exp <= now || m.exp < m.iat {
        return Err(Error::MandateExpired);
    }

    // 8-13. key binding
    let agent = m.cnf.jwk.key().map_err(|_| Error::Malformed("cnf"))?;
    let kb = jws::decode(p.kb)?;
    kb.verify(&agent, KB_TYP, Error::KbSignature)?;
    let b: Binding =
        serde_json::from_value(kb.payload).map_err(|_| Error::Malformed("key binding"))?;
    let kb_iat = crate::time(b.iat)?;
    if let Some(amt) = &b.amt {
        amt.check()?;
    }
    if b.aud != offer.iss {
        return Err(Error::Audience);
    }
    if b.op != ctx.operator {
        return Err(Error::Operator);
    }
    if b.nonce != offer.nonce {
        return Err(Error::Nonce);
    }
    if kb_iat > now.saturating_add(SKEW) || now.saturating_sub(kb_iat) > SHORT {
        return Err(Error::KbStale);
    }
    if b.sd_hash != jws::digest(p.hashed) {
        return Err(Error::SdHash);
    }

    // 14-18. action. Every covering entry applies, so array order never matters and
    // the most restrictive limit always wins.
    let term = offer.term(&b.act).ok_or(Error::NotOffered)?;
    let covering: Vec<_> = m
        .act
        .iter()
        .filter(|a| a.covers(&b.act, &offer.iss))
        .collect();
    if covering.is_empty() {
        return Err(Error::Scope);
    }
    if term.mandate.as_ref().is_some_and(|n| n.hp) {
        let approved = covering.iter().any(|a| a.hp && a.names(&offer.iss));
        if !approved || m.exp.saturating_sub(m.iat) > SHORT {
            return Err(Error::HumanPresence);
        }
    }
    if b.amt != term.amount {
        return Err(Error::Amount);
    }
    for max in covering.iter().filter_map(|a| a.max.as_ref()) {
        // A capped entry with no amount to cap: the term must state one.
        let amt = term.amount.as_ref().ok_or(Error::Amount)?;
        if amt.currency != max.currency {
            return Err(Error::Currency);
        }
        if amt.value > max.value {
            return Err(Error::OverLimit);
        }
    }

    // 19-21. liability. A named operator binds whenever it is named.
    if let Some(liab) = &m.liab {
        if liab.op != ctx.operator {
            return Err(Error::LiabOperator);
        }
    }
    if let Some(need) = &term.liab {
        let liab = m.liab.as_ref().ok_or(Error::LiabMissing)?;
        let att = jws::decode(&liab.att)?;
        let provider = att
            .payload
            .get("iss")
            .and_then(Value::as_str)
            .filter(|i| need.providers.iter().any(|p| p == i))
            .ok_or(Error::LiabProvider)?;
        let key = pick(trust.providers.get(provider), att.kid()).ok_or(Error::LiabProvider)?;
        att.verify(&key.key()?, LIAB_TYP, Error::LiabSignature)?;
        let a: Attestation =
            serde_json::from_value(att.payload).map_err(|_| Error::Malformed("attestation"))?;
        let (a_iat, a_exp) = (crate::time(a.iat)?, crate::time(a.exp)?);
        a.cover.check()?;
        if a.sub != liab.op {
            return Err(Error::LiabOperator);
        }
        if a_exp <= now || a_iat > now.saturating_add(SKEW) {
            return Err(Error::LiabExpired);
        }
        if a.cover.currency != need.cover.currency || a.cover.value < need.cover.value {
            return Err(Error::LiabCover);
        }
    }

    Ok(Grant {
        act: b.act,
        amount: b.amt,
        issuer: m.iss,
        jti: m.jti,
        nonce: b.nonce,
        principal: m.sub,
        operator: b.op,
        price: term.price.clone(),
    })
}
