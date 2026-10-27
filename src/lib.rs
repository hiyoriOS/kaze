//! Reference verifier for Kaze draft 0: platform-signed **Offers** of admission terms,
//! and SD-JWT **mandates** whose `act` and `liab` claims say what an agent may do and
//! who answers for it. The protocol is in `spec/kaze.md`.
//!
//! The verifier is a pure function. It never reads the clock, generates randomness, or
//! does I/O: the caller passes `now`, the operator identity its Web Bot Auth check
//! established, and the trusted keys. Single use of nonces, quotas, cumulative limits,
//! and payment settlement need state, so they stay with the caller (spec §7).
//!
//! ```no_run
//! # fn main() -> Result<(), kzp::Error> {
//! # let (token, jwks, presentation, trust) = ("", vec![], "", kzp::Trust::default());
//! let now = 1_792_300_000;
//! let offer = kzp::verify_offer(token, &jwks, "https://shop.example", now)?;
//! let ctx = kzp::Context { now, operator: "https://agent.example", offer: &offer };
//! let grant = kzp::verify(presentation, &ctx, &trust)?;
//! // record grant.nonce, apply quota to grant.jti, settle grant.price
//! # Ok(()) }
//! ```
//!
//! On `wasm32` the crate also exports a small C ABI (see [`abi`]), so one `kzp.wasm`
//! serves every host that can run WebAssembly.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod abi;
pub mod agent;
mod error;
#[cfg(feature = "issue")]
pub mod issue;
mod json;
pub mod jws;
pub mod mandate;
pub mod offer;
#[cfg(feature = "sign")]
pub mod sign;
mod verify;

pub use agent::{signature_agent, verify_agent, Agent, Message};
pub use error::Error;
pub use jws::Jwk;
pub use mandate::{Act, Attestation, Binding, Liab, Mandate};
pub use offer::{verify_offer, Money, Offer, Term, Verified};
pub use verify::{verify, Context, Grant, Trust};

/// Clock skew a verifier tolerates, in seconds (spec §2).
pub const SKEW: i64 = 60;
/// Longest lifetime of an offer, a key binding, or a human-present mandate (spec §4.2,
/// §5.3, §5.5).
pub const SHORT: i64 = 300;
/// Largest integer every JSON parser reads exactly (2^53 - 1). Times and money values
/// above it are malformed, which also keeps all time arithmetic far from overflow.
pub const MAX_INT: u64 = (1 << 53) - 1;

/// Accepts a `NumericDate` in `[0, MAX_INT]`.
pub(crate) fn time(t: i64) -> Result<i64, Error> {
    match u64::try_from(t) {
        Ok(u) if u <= MAX_INT => Ok(t),
        _ => Err(Error::Malformed("time")),
    }
}
