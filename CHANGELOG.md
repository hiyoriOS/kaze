# Changelog

## 0.1.0 (unreleased)

Draft 0, revision 2 of the protocol (`spec/kaze.md`).

- Verifier for Offers and SD-JWT mandates with `act` and `liab` claims; `issue` feature for producing them.
- `kaze.wasm`: a zero-import WebAssembly build with a JSON-in/JSON-out ABI (`src/abi.rs`).
- Hardening from an adversarial review, each pinned by a conformance vector:
  - The Offer's `amount` is what `max` caps, and the key binding must repeat it. Before this, `max` capped only an amount the agent declared, not the price charged.
  - Every covering `act` entry applies, so the most restrictive limit wins whatever the array order.
  - The key binding names its operator (`op`), and a mandate's `liab.op` always binds.
  - `verify_offer` takes the expected origin (`offer_issuer`) and returns `Verified`, the only type `Context` accepts.
  - Issuer keys are scoped per `iss`, and `Grant` carries `issuer`.
  - Times and money are bounded to 2^53 − 1. Before this, a release build accepted `iat = i64::MIN` through wrapping arithmetic.
  - Duplicate JSON keys, `crit` headers, empty or repeated disclosures, and duplicate `_sd` digests are rejected. A signed disclosure that isn't base64url fails as `disclosure`.
  - `human_presence` must name the platform. `typ` compares as a media type. `kaze_alloc` refuses lengths over `MAX_INPUT`.
