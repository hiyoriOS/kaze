/// Why a verification failed.
///
/// [`Error::code`] is the stable string from spec §7 that the conformance vectors and
/// every host compare against; the `Display` text is for humans and may change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Input is not well-formed: bad encoding, duplicate JSON keys, a missing or
    /// out-of-range field. The payload names the field.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// `alg` is missing, not `EdDSA`, or a `crit` header is present.
    #[error("unsupported or missing alg, or crit present")]
    Alg,
    /// `typ` is not the one this position requires.
    #[error("wrong typ")]
    Typ,
    /// The offer's `kid` is not in the platform JWKS, or its signature fails.
    #[error("offer signature does not verify")]
    OfferSignature,
    /// The offer's `iss` is not the origin its JWKS came from.
    #[error("offer issuer is not the expected origin")]
    OfferIssuer,
    /// The offer is past `exp`, or issued in the future.
    #[error("offer expired")]
    OfferExpired,
    /// The mandate issuer's `kid` is not trusted.
    #[error("issuer key is not trusted")]
    UnknownKey,
    /// The mandate issuer's signature fails.
    #[error("issuer signature does not verify")]
    IssuerSignature,
    /// A disclosure is unknown, repeated, or would overwrite a claim.
    #[error("disclosure does not match an issuer digest")]
    Disclosure,
    /// `vct` is not `kaze.mandate.1`.
    #[error("wrong vct")]
    Vct,
    /// The mandate is expired or not yet valid.
    #[error("mandate expired or not yet valid")]
    MandateExpired,
    /// The key binding is not signed by `cnf.jwk`.
    #[error("key binding signature does not verify")]
    KbSignature,
    /// The key binding's `aud` is not the offer's `iss`.
    #[error("key binding audience is not the offer issuer")]
    Audience,
    /// The key binding's `op` is not the operator Web Bot Auth established.
    #[error("key binding operator is not the request's operator")]
    Operator,
    /// The key binding's `nonce` is not the offer's `nonce`.
    #[error("key binding nonce is not the offer nonce")]
    Nonce,
    /// The key binding is too old or from the future.
    #[error("key binding is stale")]
    KbStale,
    /// The key binding's `sd_hash` does not cover this presentation.
    #[error("key binding sd_hash does not match the presentation")]
    SdHash,
    /// The requested action is not one of the offer's terms.
    #[error("action is not offered")]
    NotOffered,
    /// No `act` entry covers the action on this platform.
    #[error("action is outside the mandate scope")]
    Scope,
    /// The term needs a human-present mandate and this one is not.
    #[error("term needs a human-present mandate")]
    HumanPresence,
    /// The amount's currency differs from the mandate limit's.
    #[error("amount currency differs from the mandate limit")]
    Currency,
    /// The key binding's `amt` differs from the term's `amount` (or one is missing).
    #[error("key binding amount differs from the offer")]
    Amount,
    /// The amount exceeds the mandate limit.
    #[error("amount is over the mandate limit")]
    OverLimit,
    /// The term needs `liab` and the mandate has none.
    #[error("term needs a liability claim")]
    LiabMissing,
    /// The attestation's provider is not accepted by the term or not trusted.
    #[error("liability provider is not accepted")]
    LiabProvider,
    /// The attestation's signature fails.
    #[error("liability attestation signature does not verify")]
    LiabSignature,
    /// `liab.op`, the attestation's `sub`, and the Web Bot Auth operator disagree.
    #[error("liability operator does not match")]
    LiabOperator,
    /// The attestation is expired or issued in the future.
    #[error("liability attestation expired")]
    LiabExpired,
    /// A Web Bot Auth header is missing or malformed, there is not exactly one
    /// `web-bot-auth` signature, or `created`, `expires` or `keyid` is missing.
    #[error("missing or malformed Web Bot Auth headers")]
    AgentHeader,
    /// The signature does not cover `@authority` (or `@target-uri`) and its own
    /// `signature-agent` member, or covers a component this verifier can't rebuild.
    #[error("Web Bot Auth signature covers the wrong components")]
    AgentComponents,
    /// The signature is not yet valid, expired, or lives longer than 24 hours.
    #[error("Web Bot Auth signature expired")]
    AgentExpired,
    /// The agent URL is not https, its directory is not the one supplied, or no
    /// directory key has the signature's `keyid`.
    #[error("Web Bot Auth key not found")]
    AgentKey,
    /// The Web Bot Auth signature does not verify.
    #[error("Web Bot Auth signature does not verify")]
    AgentSignature,
    /// The attested cover is below the term's floor or in another currency.
    #[error("liability cover is below the floor")]
    LiabCover,
}

impl Error {
    /// The stable code from spec §7.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Error::Malformed(_) => "malformed",
            Error::Alg => "alg",
            Error::Typ => "typ",
            Error::OfferSignature => "offer_signature",
            Error::OfferIssuer => "offer_issuer",
            Error::OfferExpired => "offer_expired",
            Error::UnknownKey => "unknown_key",
            Error::IssuerSignature => "issuer_signature",
            Error::Disclosure => "disclosure",
            Error::Vct => "vct",
            Error::MandateExpired => "mandate_expired",
            Error::KbSignature => "kb_signature",
            Error::Audience => "audience",
            Error::Operator => "operator",
            Error::Nonce => "nonce",
            Error::KbStale => "kb_stale",
            Error::SdHash => "sd_hash",
            Error::NotOffered => "not_offered",
            Error::Scope => "scope",
            Error::HumanPresence => "human_presence",
            Error::Currency => "currency",
            Error::Amount => "amount",
            Error::OverLimit => "over_limit",
            Error::LiabMissing => "liab_missing",
            Error::LiabProvider => "liab_provider",
            Error::LiabSignature => "liab_signature",
            Error::LiabOperator => "liab_operator",
            Error::LiabExpired => "liab_expired",
            Error::LiabCover => "liab_cover",
            Error::AgentHeader => "agent_header",
            Error::AgentComponents => "agent_components",
            Error::AgentExpired => "agent_expired",
            Error::AgentKey => "agent_key",
            Error::AgentSignature => "agent_signature",
        }
    }
}
