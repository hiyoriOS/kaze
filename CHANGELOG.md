# Changelog

## Unreleased

## 0.3.0 (2026-10-26)

No API changes. This release is the license change and the project documents around it; the code is the same as 0.2.0.

- **License:** the repository is now `Apache-2.0` only (decision 0002). Versions 0.1.0 and 0.2.0 stay under `MIT OR Apache-2.0`, as published.
- **Patents:** the specification (`spec/kaze.md` and `spec/schema/`) is available under the Open Web Foundation Final Specification Agreement (OWFa 1.0), in `PATENTS.md`. It covers independent implementations too.
- **Contributions:** `CONTRIBUTING.md` requires a `Signed-off-by` on every commit (Developer Certificate of Origin 1.1). A new `dco` workflow checks every PR, Markdown-only ones included.
- **Release process:** `RELEASING.md` lists the release steps. `about.toml` and `about.hbs` generate a `THIRD-PARTY-NOTICES` file for each `kzp.wasm` release.

## 0.2.0 (2026-10-18)

- **Web Bot Auth:** `verify_agent`, `signature_agent` and `agent::directory_url` establish the operator from RFC 9421 HTTP Message Signatures (`draft-ietf-webbotauth-httpsig-protocol`). New error codes: `agent_header`, `agent_components`, `agent_expired`, `agent_key`, `agent_signature`.
- **Signing requests:** `issue::sign_request` signs a request the way an agent does.
- **New WASM exports:** `kzp_signature_agent` and `kzp_verify_agent`. A build with `issue` also exports `kzp_jwk`, `kzp_issue_offer`, `kzp_issue_mandate`, `kzp_present` and `kzp_sign_request`, so a host can issue and sign without its own crypto.
- **Canonical signatures:** a `Signature` must use canonical base64, so one signature has exactly one header text. Property tests caught this.
- **Freed memory:** `kzp_free` zeroes every buffer, so seeds never outlive a call.
- **Tests:** `vectors/agent.json` adds 20 cases. The signature base and Ed25519 output match RFC 9421 §B.2.6 byte for byte, and the key thumbprint matches RFC 8037 §A.3.
- **Dependency:** `sfv` 0.14 for RFC 9651 structured fields.

## 0.1.0 (2026-10-18)

First release, published as `kzp` (the name `kaze` is taken on crates.io).

Draft 0, revision 2 of the protocol (`spec/kaze.md`).

- Verifier for Offers and SD-JWT mandates with `act` and `liab` claims; `issue` feature for producing them.
- `kzp.wasm`: a zero-import WebAssembly build with a JSON-in/JSON-out ABI (`src/abi.rs`).
- Hardening from an adversarial review, each pinned by a conformance vector:
  - The Offer's `amount` is what `max` caps, and the key binding must repeat it. Before this, `max` capped only an amount the agent declared, not the price charged.
  - Every covering `act` entry applies, so the most restrictive limit wins whatever the array order.
  - The key binding names its operator (`op`), and a mandate's `liab.op` always binds.
  - `verify_offer` takes the expected origin (`offer_issuer`) and returns `Verified`, the only type `Context` accepts.
  - Issuer keys are scoped per `iss`, and `Grant` carries `issuer`.
  - Times and money are bounded to 2^53 − 1. Before this, a release build accepted `iat = i64::MIN` through wrapping arithmetic.
  - Duplicate JSON keys, `crit` headers, empty or repeated disclosures, and duplicate `_sd` digests are rejected. A signed disclosure that isn't base64url fails as `disclosure`.
  - `human_presence` must name the platform. `typ` compares as a media type. `kzp_alloc` refuses lengths over `MAX_INPUT`.
