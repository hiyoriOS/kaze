# 0003: Kaze for outbound agent orders: two jobs, one profile on AP2 and UCP

Status: accepted
Date: 2026-10-26

## Decision

For an AI checkout agent that buys from small businesses on its owner's behalf, Kaze does two jobs, and the 0.4.0 work of `kzp` follows from that:

1. **Sign the agent's HTTP requests** with Web Bot Auth, so a Cloudflare-style verifier can recognize the agent.
2. **Sign a short-lived mandate for each order**, issued by the payments service after its own authority has decided to allow the order.

Offer issuance and the verifier inside the payments service are deferred. They matter only when other agents buy from that service's businesses, which is a later product.

Kaze becomes **one profile on top of AP2 and UCP**, not a protocol next to them. It does not own the payment format, the checkout flow or the mandate container.

## Context

Hana is an AI checkout agent. Ryo is its owner's payments service. Ryo embeds `kzp.wasm` in Go and has no Rust. On 2026-10-26 the owner decided:

- Ryo's Go rewrite is Ryo's base.
- Payments use Visa and Mastercard agent tokens issued through Stripe.
- Google's Universal Commerce Protocol (UCP) is the path to businesses that are not on Ryo.
- There is no scripted (browser) checkout.

A business that is not on Ryo will never issue a Kaze Offer. So for Hana's outbound orders the Offer has no counterparty, and only the two jobs above remain.

## What stays as it is

| Piece | Why it stays |
|---|---|
| `issue::sign_request`: Web Bot Auth signing | Job 1 |
| `issue::mandate` and `present`: mandate issuance | Job 2 |
| The pure verifier and its WASM build | Ryo embeds it the way its `internal/kaze` already does. No Rust in Ryo. |

## Changes planned for 0.4.0

| Change | Why | Size |
|---|---|---|
| Make the signature `tag` a parameter in `sign_request` and `verify_agent`. It is the constant `TAG` (`web-bot-auth`) in `src/agent.rs`. | Visa's Trusted Agent Protocol uses RFC 9421 with its own tags, so one key could serve both Cloudflare and Visa. See the research below for what else differs. | About a day, more if both tags go on one request (see below) |
| Add ES256 (spec open question 1) | UCP verifiers must support ES256 and need not support Ed25519. AP2 forbids deterministic checkout signatures. `kzp` signs and verifies Ed25519 only. Needs a P-256 dependency, an `alg` check, new vectors and fuzz targets. | About a week |
| Carry `act` and `liab` inside AP2 mandates, not in a separate `Kaze-Mandate` header | Kaze's mandate container is already AP2's (SD-JWT with key binding), so a UCP seller receives Kaze data through a flow it already supports. Answers open question 4. | A few days, mostly spec and vectors |
| Spec: a UCP transport binding, next to HTTP 402 and MCP `_meta` | UCP is the main path to businesses not on Ryo. | Spec only |
| Spec: any payment format in `price`, with a `kind` field (`x402`, `mpp`, `ucp`, `acp`, `card`) | Stripe's tokens and card agent tokens are neither x402 nor MPP. The verifier never reads `price`, so there is no code change. | Spec only |
| Answer open question 3 (revocation) with short expiries | One mandate per order, expiring in minutes, paired with a single-use token. Revoking the authority in Ryo stops the next mandate from being issued, so no status list is needed. | Spec only |

## Parked

- **`liab` for payments.** Card network rules (chargebacks) already give recourse, and Visa and Mastercard will not sign Kaze attestations. `liab` stays for non-payment actions such as bookings and cancellations.
- **Offer issuance, and the verifier running inside Ryo.**

## Open questions answered

| Spec §9 question | Answer |
|---|---|
| 1. ES256 | Add ES256 alongside Ed25519 in 0.4.0. Draft 0 stays Ed25519-only until then. |
| 3. Revocation | Short expiries, no status list. |
| 4. Where to standardise | Kaze is one profile on top of AP2 and UCP. |

Questions 2 (disclosure granularity) and 5 (action registry) stay open.

## Checked before starting

Read on 2026-10-26. "Unconfirmed" marks what the sources do not say.

### Visa Trusted Agent Protocol (TAP)

Sources:
- Visa, [Trusted Agent Protocol specifications](https://developer.visa.com/docs/trusted-agent-protocol/trusted-agent-protocol-specifications) and the [capability overview](https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications), read through a page-fetch tool, so re-read the exact strings before coding.
- Visa's sample code, [`visa/trusted-agent-protocol`](https://github.com/visa/trusted-agent-protocol), commit `16d59bd` (2025-10-28). The sample is not a normative spec.
- Cloudflare, [Securing agentic commerce](https://blog.cloudflare.com/secure-agentic-commerce/).
- IETF, [`draft-ietf-webbotauth-httpsig-protocol-00`](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) (updated 2026-09-01).

| Question | Finding |
|---|---|
| `tag` values | `agent-browser-auth` for browsing and `agent-payer-auth` for checkout. Stated in Visa's docs, used in its sample agent, and repeated by Cloudflare. The sample proxy's own comment says `agent-payment-auth`, which no other source uses. Web Bot Auth requires `web-bot-auth` (draft §5.2). Cloudflare's sample request also shows `web-bot-auth`, and its text says Visa and Mastercard add a new tag. |
| Algorithms | Visa's docs give no allowlist for HTTP message signatures. Examples use `alg="Ed25519"`. The sample agent also signs `rsa-pss-sha256`. `PS256` appears only for the JWT-style container objects in the request body. The Web Bot Auth draft limits `alg` to the IANA registry and does not fix a list. |
| Required components | `@authority` and `@path` at minimum. Agents "may optionally define additional fields". Required parameters are `created`, `expires`, `nonce`, `keyid`, `alg` and `tag`. `created` must be past and `expires` future, at most 8 minutes apart. Headers are `Signature-Input` and `Signature`. |
| Relation to Web Bot Auth | Visa says only that its signature is based on RFC 9421 "[and aligned with web-bot-auth]". Cloudflare says Visa and Mastercard build on Web Bot Auth, adding the new tag and requiring a nonce. |
| Keys | The agent registers its key with Visa, and the merchant looks it up by `keyid` through a Visa-hosted registry. Cloudflare says Visa and Mastercard each host their own directory. TAP's example carries no `Signature-Agent` header. |

**Unconfirmed:**
- Which HTTP signature algorithms Visa's production verifiers accept.
- Whether they accept the lowercase `ed25519` that RFC 9421 registers and `kzp` emits, since Visa's docs write `Ed25519`.
- Whether they accept extra covered components. `kzp` also covers `@method` and `signature-agent;key="<label>"`. Visa's sample verifier handles only `@authority`, `@path`, `content-type` and `host`, so it would fail on `kzp`'s signature base. That is a sample, not Visa's production verifier.
- How a key is registered with Visa and Cloudflare, and whether one registration can cover both.

### UCP

Sources, all at commit [`69895b8`](https://github.com/Universal-Commerce-Protocol/ucp/tree/69895b84b451925a92ac0c9122353eab310e1a23) of `Universal-Commerce-Protocol/ucp` (2026-10-26):
- [`docs/specification/overview/index.md`](https://github.com/Universal-Commerce-Protocol/ucp/blob/69895b84b451925a92ac0c9122353eab310e1a23/docs/specification/overview/index.md), "Namespace Governance".
- [`docs/specification/payment/extensions/ap2-mandates.md`](https://github.com/Universal-Commerce-Protocol/ucp/blob/69895b84b451925a92ac0c9122353eab310e1a23/docs/specification/payment/extensions/ap2-mandates.md).
- [`docs/specification/signatures.md`](https://github.com/Universal-Commerce-Protocol/ucp/blob/69895b84b451925a92ac0c9122353eab310e1a23/docs/specification/signatures.md).
- [`source/schemas/common/payment_ap2_mandate.json`](https://github.com/Universal-Commerce-Protocol/ucp/blob/69895b84b451925a92ac0c9122353eab310e1a23/source/schemas/common/payment_ap2_mandate.json).

And in AP2, commit `e1ea56d` (2026-04-29) of [`google-agentic-commerce/AP2`](https://github.com/google-agentic-commerce/AP2): [`docs/ap2/specification.md`](https://github.com/google-agentic-commerce/AP2/blob/e1ea56db72a6385bce3e5c1112b3a56ce60acb43/docs/ap2/specification.md), `payment_mandate.md`, and [issue #268](https://github.com/google-agentic-commerce/AP2/issues/268).

| Question | Finding |
|---|---|
| Namespacing | Reverse-domain names: `{reverse-domain}.{service}.{capability}`. `dev.ucp.*` is reserved for capabilities the UCP governing body sanctions. Vendors "MUST use their own reverse-domain namespace" (`com.example.payments.installments`). The schema URL's origin must match the namespace. Extension signal keys use reverse-domain names too. |
| AP2 extension | The capability `dev.ucp.common.payment.ap2_mandate` extends `dev.ucp.shopping.checkout`. A business advertises it in `/.well-known/ucp`. All its fields sit in an `ap2` object. When negotiated, the session is "Security Locked" with no fallback to plain checkout. |
| How mandates travel | The business puts `ap2.merchant_authorization` (a detached JWS over the checkout, `ES256`/`ES384`/`ES512`) in every checkout response. The platform sends `ap2.checkout_mandate` (an SD-JWT with key binding) on `complete`. The payment mandate rides in `payment.instruments[*].credential.token`. UCP leaves mandate verification to the AP2 specification. |
| Algorithms | UCP verifiers MUST support `ES256`. `ES384` and `EdDSA` are optional. A UCP signer should pick an algorithm every counterparty accepts, and UCP's default is `ES256`. UCP's own request signing is optional for a business: API keys, OAuth and mTLS are alternatives. |
| UCP and Web Bot Auth | UCP defines a "WBA interop" mode, where one RFC 9421 signature carries `tag="web-bot-auth"` and a `Signature-Agent` header. It must still cover UCP's required components (`@method`, `@authority`, `@path`, plus `ucp-agent`, `idempotency-key`, `content-digest` and `content-type` when present). UCP says `alg` is not included in `Signature-Input`. |
| AP2 algorithm rule | AP2 says the checkout JWT "MUST be signed using a digital signature scheme (e.g., ECDSA) and not a deterministic signature". UCP calls this inconsistent with AP2's own security section. [AP2 #268](https://github.com/google-agentic-commerce/AP2/issues/268) (open, 2026-05-26, with PR #278) proposes allowing any algorithm if the payload has a high-entropy claim. |
| AP2 extension points | A new mandate constraint needs a unique `type`, a schema (including which fields are selectively disclosable) and an evaluation algorithm. AP2 already defines constraints such as `payment.amount_range` and `payment.allowed_payees`. AP2 calls UCP's own extension points the recommended way to support new commerce journeys. |

**Unconfirmed:**
- AP2's document was read for extension points only. Not read: whether a verifier ignores or rejects a constraint `type` it does not know.
- Whether a business needs a UCP-sanctioned name or can negotiate a Kaze capability under its own reverse-domain name (not decided: which domain Kaze would use).

### What this changes in the plan

The plan stands, with these corrections:

1. **The `tag` parameter is not enough to share a key with Visa.** Visa also requires a `nonce` and a lifetime of at most 8 minutes. `sign_request` takes both from the caller, so this is a calling rule, not code. The key must be registered with Visa separately. One signature carries one tag, so serving Cloudflare and Visa on one request means two signatures under two labels. `sign_request` appends new header lines rather than merging into existing ones, so the 0.4.0 work must handle a second call. The "about a day" holds only for the `tag` parameter itself.
2. **`verify_agent` takes a tag, but still rejects Visa-shaped signatures.** It requires `signature-agent` to be covered. TAP's example has no such header. Verifying TAP signatures is not a goal: Ryo is not a TAP merchant. The tag parameter exists so the same code can verify other tags that do cover `signature-agent`.
3. **The ES256 reason is narrower than the plan stated.** "AP2 and UCP require ES256" is not accurate. UCP requires its verifiers to support ES256 and treats Ed25519 as optional. AP2 requires a non-deterministic signature, and it is moving toward allowing any algorithm (#268). ES256 is still needed, because a UCP business may support nothing else, but the WBA key can stay Ed25519.
4. **Signing UCP requests needs more than `sign_request` does today.** `sign_request` covers a fixed set (`@method`, `@authority`, `@path`, `signature-agent`) and always emits `alg="ed25519"`. UCP-bound requests with a body also need `content-digest`, `content-type`, `idempotency-key` and `ucp-agent`, and UCP says to omit `alg`. Whether Hana signs UCP requests with `kzp` or in its own stack is not decided here. UCP does not require signatures from a business's point of view, but a business that asks for them is the case to design for. If `kzp` does it, `sign_request` needs a covered-components parameter and a way to omit `alg`. That work is not in the table above and is unsized.
5. **`act` and `liab` should be defined as AP2 mandate constraint types, not as free claims.** AP2's extension point asks for a unique `type`, a schema and an evaluation algorithm. This is spec work and fits the "few days" estimate. It also needs a check against the constraints AP2 already defines for payments (`payment.amount_range`, `payment.allowed_payees`), which cover part of what `act` does. This supports parking `liab` for payments.
6. **A UCP binding should use a reverse-domain capability name** under a domain the Kaze project controls, not `dev.ucp.*`.

Nothing found argues against the decision itself.

## Not done, and why

- **No code, `Cargo.toml`, `CHANGELOG.md` or `README.md` changes.** This record changes no behavior. 0.4.0 does.
- **No normative spec change.** `spec/kaze.md` §9 points here. §§1 to 8 change with 0.4.0.
- **Mastercard Agent Pay.** Not read from a primary source. Cloudflare says it builds on Web Bot Auth like TAP, which is unconfirmed here.
