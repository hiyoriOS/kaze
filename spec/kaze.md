# Kaze: admission terms and accountable mandates for agents

Status: draft 0, revision 2 (2026-10-18), after an adversarial review. Not yet submitted anywhere.

## 1. Purpose

Platforms block agents for seven reasons: they can't identify the agent, can't prove who authorised it, see shared passwords, lose the customer, get scraped for free, get overloaded, and face unclear law. An analysis of 29 incidents (`../../kaze-analysis/access.md`) found that existing standards already cover identity, payment and receipts. Two pieces are missing:

1. A way for a platform to state **its own terms** for an agent action: which proofs it requires, what liability floor, what price, what quota, which sanctioned path, and who runs checkout. That is the **Offer** (§4).
2. A way for a principal's mandate to cover **any action, not just payments**, and to name **who is accountable** when the agent gets it wrong. Those are the **`act` and `liab` claims** (§5).

Kaze specifies only these two pieces and reuses everything else:

| Need | Reused standard |
|---|---|
| Agent identity on each request | Web Bot Auth (HTTP Message Signatures, RFC 9421) |
| Mandate container | SD-JWT with key binding, as AP2 mandates use |
| Payment | x402 or MPP payment requirements, embedded verbatim |
| Receipt | x402 `PAYMENT-RESPONSE`, MPP `Payment-Receipt`, AP2 receipts |

## 2. Conventions

The key words MUST, SHOULD and MAY are used as in RFC 2119 and RFC 8174.

- **Money** is an object `{ "value": <non-negative integer, minor units>, "currency": <ISO 4217 code> }`. `currency` is three uppercase ASCII letters. Floating point MUST NOT be used.
- **Times** are NumericDate (seconds since the epoch).
- **Integers** (times and money values) MUST lie in `[0, 2^53 − 1]` so every JSON parser reads them exactly. Anything outside that range is `malformed`. This also rules out overflow in time arithmetic.
- **JSON** MUST NOT repeat an object key anywhere, even through escapes (`"exp"` and `"\u0065xp"` are the same key). A verifier MUST reject such input as `malformed` rather than take the first or last value.
- **Skew:** verifiers MUST allow at most 60 s of clock skew.
- **Signatures:** all signed objects are JWS Compact. Draft 0 requires `alg: "EdDSA"` with Ed25519, verified strictly (no malleable signatures, no small-order keys). A later draft adds `ES256`. `alg: "none"` MUST be rejected, and so MUST any header with `crit`.
- **`typ`** is compared as a media type: case-insensitive, with an optional `application/` prefix.
- **Origins** (`iss`, `aud`, `on`, `op`) are compared as exact strings. Senders MUST serialize them as `scheme://host[:port]` with no path or trailing slash.

**Roles:**

| Role | Does |
|---|---|
| **Platform** | Serves the resource; issues Offers; verifies presentations. |
| **Principal** | The human or business the agent acts for. |
| **Issuer** | Signs mandates for the principal: a wallet, credential provider, or a Ryo-style authority service. |
| **Operator** | Runs the agent and signs its requests with Web Bot Auth. |
| **Provider** | A recourse provider that attests an operator's cover: a card network, insurer or bonding service. |

## 3. Flow

```
agent ──(1) request, Web Bot Auth signature───────────────────────────▶ platform
agent ◀─(2) 402 + Kaze-Offer: <offer JWS>──────────────────────────────  platform
agent ──(3) retry: Web Bot Auth signature
              + Kaze-Mandate: <issuer-jwt>~<disclosures>~<kb-jwt>
              + x402/MPP payment payload, if the term has a price ──────▶ platform
agent ◀─(4) result + receipt (x402/MPP/AP2), Kaze-Grant: <jti>──────────  platform
```

Over MCP, the same values travel in `_meta` as `kaze/offer` and `kaze/mandate`.

## 4. The Offer

### 4.1 Transport

The platform answers with `402 Payment Required`, or `401` or `403` when no price applies. It carries the Offer in a `Kaze-Offer` header. It MAY also send the Offer as a body with media type `application/kaze-offer+jwt`.

An unsigned agent that has no mandate MUST still receive the Offer. The point of the Offer is to tell the agent how it could be admitted.

### 4.2 Token

- **JOSE header:** `{"alg":"EdDSA","typ":"kaze-offer+jwt","kid":<key id>}`.
- **Keys:** the platform's keys are published at `<iss>/.well-known/kaze/jwks.json`.

| Claim | Type | Req | Meaning |
|---|---|---|---|
| `iss` | URL origin | yes | The platform. It becomes the `aud` of the key-binding JWT. It MUST be the origin the JWKS was fetched from; an agent MUST reject an Offer whose `iss` differs (`offer_issuer`), or one platform could relay another's terms. |
| `iat`, `exp` | NumericDate | yes | `exp - iat` MUST be ≤ 300. |
| `nonce` | base64url, at least 16 bytes | yes | Single use; the platform records it once it is used. |
| `resource` | URL | yes | The resource the terms apply to. |
| `terms` | array of Term | yes | One entry per action. Every `act` value MUST be unique. |

**Term:**

| Field | Type | Req | Meaning |
|---|---|---|---|
| `act` | action id (§6) | yes | The action these terms admit. |
| `id` | `"signed"` | no | Requires a verified Web Bot Auth signature. Default `"signed"`. |
| `mandate` | `{ "hp": bool }` | no | Present means a mandate is required. `hp: true` means human present (§5.3). |
| `liab` | `{ "cover": Money, "providers": [URL] }` | no | Liability floor, and the recourse providers the platform accepts. |
| `amount` | Money | with `price` | The exact amount this action charges or commits. The key-binding JWT repeats it, and every covering Act's `max` must allow it. This is the only amount the verifier checks. |
| `price` | object | no | x402 `PaymentRequirements` or an MPP challenge, embedded verbatim. Kaze does not read it. The platform MUST settle exactly `amount`. |
| `quota` | `{ "window": seconds, "max": int }` | no | Requests allowed per operator in each window. |
| `path` | URL | no | The sanctioned path for this action, such as an API or MCP endpoint. Agents SHOULD use it rather than driving the DOM. |
| `checkout` | `"platform"` \| `"agent"` | no | `platform` means the agent hands the user to the platform's checkout rather than completing it. |

Unknown Offer and Term fields are ignored. An Offer only ever constrains the platform that signed it, so ignoring a field can't widen anyone else's authority.

The Offer is how a platform keeps control of its relationship with the customer. It decides which actions agents may take, where they take them, what they cost, and whether checkout stays on the platform.

## 5. The mandate

### 5.1 Container

The mandate is an SD-JWT with key binding:

```
<issuer-jwt>~<disclosure>~...~<kb-jwt>
```

- **Issuer JWT header:** `{"alg":"EdDSA","typ":"kaze-mandate+sd-jwt","kid":<issuer key id>}`.
- **Issuer keys:** a verifier trusts keys per issuer `iss`. It chooses the key set by the plain (never disclosed) `iss` claim, then the key by `kid`. A key therefore signs only for its own issuer, and (`iss`, `sub`) and (`iss`, `jti`) are the identities of a principal and a mandate.
- **Disclosures and digests:** `_sd_alg`, if present, MUST be `sha-256` (otherwise `alg`). If absent it means `sha-256`, as in SD-JWT. Digests are base64url(SHA-256(ASCII of the disclosure)). Draft 0 permits only top-level disclosures of the form `[salt, name, value]` with a string salt. A disclosure whose digest matches but that is not valid base64url JSON fails as `disclosure`. `_sd` MUST NOT repeat a digest; a presentation MUST NOT repeat a disclosure or contain an empty one.

| Claim | Req | Meaning |
|---|---|---|
| `iss`, `sub`, `iat`, `exp`, `jti` | yes | Issuer, principal (MAY be a pseudonym), validity, mandate id. |
| `vct` | yes | `"kaze.mandate.1"`. |
| `cnf.jwk` | yes | The agent's key. Only that key can produce the key-binding JWT. |
| `act` | yes | Array of Act (§5.2). SHOULD be selectively disclosable. |
| `liab` | no | The Liab object (§5.4). |
| other | no | MAY be selectively disclosable, for example contact details. |

### 5.2 The `act` claim

| Field | Req | Meaning |
|---|---|---|
| `act` | yes | An action id or a pattern (§6). |
| `on` | yes | Platform origins this entry covers. `"*"` means any platform. |
| `max` | no | Per-action ceiling, as Money. A term covered by an Act with `max` MUST state `amount`. |
| `hp` | no | `true` only if the issuer obtained the principal's approval for this specific action, on a platform named in `on`, in a trusted non-agentic surface (§5.3). |

Unknown Act fields MUST be rejected (`malformed`): a restriction an old verifier ignored would widen what the agent may do.

**Every covering entry applies.** When several Acts cover the requested action on this platform, each one's `max` MUST allow the amount. The most restrictive limit always wins, and the order of the array never changes the outcome.

Cumulative limits, such as a total spend or a daily count, need state. They stay with the issuer and the platform, which track usage by `jti`. They are not part of the stateless check.

### 5.3 Human present

A term with `mandate.hp: true` needs a covering Act with `hp: true` whose `on` names the platform itself (not only `*`), and a mandate whose `exp - iat` is ≤ 300. Issuers MUST NOT set `hp` on long-lived mandates. This is how AP2's "closed, human-present" mandate maps onto Kaze.

### 5.4 The `liab` claim

```json
{ "op": "<operator origin>", "att": "<attestation JWS>" }
```

`att` is signed by a recourse provider:

- **Header:** `{"alg":"EdDSA","typ":"kaze-liab+jwt","kid":...}`.
- **Payload:** `{ "iss": <provider>, "sub": <operator>, "cover": Money, "iat", "exp" }`.

By putting `liab` inside the mandate, the principal names the operator it accepts as accountable. The provider attests that this operator is covered. Whenever a mandate carries `liab`, even for a term that doesn't require it, `op` MUST equal the operator identity verified by Web Bot Auth, so the principal's choice of operator always binds. When the term requires `liab`, `att.sub` MUST also equal `op`.

Kaze carries the claim but does not define recourse itself, such as how a claim is filed or paid. That is a contract between the provider and the platform.

### 5.5 The key-binding JWT (the closed mandate)

- **Header:** `{"alg":"EdDSA","typ":"kb+jwt"}`, signed with the key in `cnf.jwk`.
- **Payload:**

| Claim | Req | Meaning |
|---|---|---|
| `iat` | yes | Within 300 s of the verifier's clock. |
| `aud` | yes | The Offer's `iss`, as a single string. An array, which RFC 7519 otherwise allows, is `malformed`. |
| `op` | yes | The operator origin whose Web Bot Auth key signs this request. It ties the presentation to one operator, so a captured `Kaze-Mandate` header is useless to anyone else. |
| `nonce` | yes | The Offer's `nonce`. |
| `sd_hash` | yes | base64url(SHA-256(`<issuer-jwt>~<disclosures>~`)). |
| `act` | yes | The single action requested. It MUST be one of the Offer's terms. |
| `amt` | exactly when the term has `amount` | The term's `amount`, repeated. The agent confirms the exact amount it is committing to, as AP2's closed mandate does. |

## 6. Action ids

`<domain>:<verb>`, for example `order:create`, `menu:read`, `flight:book` or `account:trade`. The characters are `[a-z0-9_.-]`, plus one `:`.

- A mandate pattern can be an exact id or `<domain>:*`.
- An Offer `act` is always an exact id.
- A registry of common domains is future work. Until then, platforms SHOULD document their own ids at `path`.

## 7. Verification

The inputs are:
- the Offer token, the platform's JWKS, and the expected platform origin
- the presentation
- the operator identity Web Bot Auth established
- `now`
- the trusted issuer keys and provider keys, each grouped by `iss`

The verifier MUST run these steps in order and stop at the first failure, returning its code. Codes are stable and are what the test vectors use. Any input that is not well-formed (bad encoding, duplicate keys, out-of-range integers, a missing field) returns `malformed` at the step that reads it.

| # | Check | Code |
|---|---|---|
| 1 | Offer: `kid` in the JWKS, `alg`, `typ`, signature; well-formed (lifetime ≤ 300, nonce ≥ 16 bytes, unique `act`, `amount` with every `price`); `iss` is the expected origin | `offer_signature`, `alg`, `typ`, `malformed`, `offer_issuer` |
| 2 | `offer.exp > now` and `offer.iat ≤ now + skew` | `offer_expired` |
| 3 | The plain `iss` claim names a trusted issuer that has the header's `kid` | `unknown_key` |
| 4 | Issuer JWT: `alg` (and no `crit`), `typ`, signature | `alg`, `typ`, `issuer_signature` |
| 5 | Disclosures (§5.1) | `disclosure`, `alg`, `malformed` |
| 6 | `vct` | `vct` |
| 7 | `iat ≤ now + skew`, `exp > now`, `exp ≥ iat`; the Acts are well-formed | `mandate_expired`, `malformed` |
| 8 | `cnf.jwk` is an Ed25519 key; the key-binding JWT has `alg` `EdDSA` (no `crit`), `typ` `kb+jwt`, and is signed by `cnf.jwk` | `malformed`, `alg`, `typ`, `kb_signature` |
| 9 | `kb.aud == offer.iss` | `audience` |
| 10 | `kb.op == operator` | `operator` |
| 11 | `kb.nonce == offer.nonce` | `nonce` |
| 12 | `kb.iat ≤ now + skew` and `now − kb.iat ≤ 300` | `kb_stale` |
| 13 | `kb.sd_hash` matches the presented bytes | `sd_hash` |
| 14 | `kb.act` is one of the Offer's terms | `not_offered` |
| 15 | At least one Act covers `kb.act` on `offer.iss` | `scope` |
| 16 | If the term requires `hp`, §5.3 holds | `human_presence` |
| 17 | `kb.amt` equals the term's `amount` (both absent, or both equal) | `amount` |
| 18 | For every covering Act with `max`: the term states `amount` in `max`'s currency, and `amount ≤ max` | `amount`, `currency`, `over_limit` |
| 19 | If the mandate has `liab`: `liab.op == operator` | `liab_operator` |
| 20 | If the term has `liab`: the mandate has `liab`; `att.iss` is in `term.liab.providers` and is a trusted provider with the header's `kid` | `liab_missing`, `liab_provider` |
| 21 | `att`: `alg`, `typ`, signature; `att.sub == liab.op`; `att.iat ≤ now + skew` and `att.exp > now`; cover in the floor's currency and ≥ it | `liab_signature`, `liab_operator`, `liab_expired`, `liab_cover` |

On success, the verifier returns a **Grant** `{ act, amount, issuer, jti, nonce, principal, operator, price }`.

The caller then:
- records `nonce` as used, and rejects any reuse
- applies the quota and cumulative limits by operator and by (`issuer`, `jti`)
- settles `price` for exactly `amount` through x402 or MPP
- returns the receipt

These steps need state, so they are deliberately outside the stateless verifier.

### 7.1 The reference verifier's API

The reference verifier makes step 1 a separate call, `verify_offer(token, jwks, iss, now)`. Its result is the only value accepted as `Context.offer`, so an unchecked or agent-supplied Offer can never reach steps 2–21.

## 8. Security and privacy considerations

- **Replay:** the Offer nonce is single use. The key-binding JWT is bound to that nonce, to `aud`, and to the exact disclosures (`sd_hash`).
- **Credential sharing:** the agent never holds the principal's password. The mandate is scoped, has an expiry, and is bound to the agent's key.
- **Selective disclosure:** an agent discloses only the `act` entries a platform needs. Other platforms and contact details stay hidden. In draft 0, `act` is a single disclosure, so a platform sees every Act. Disclosing individual array elements is planned for draft 1.
- **Liability without identity:** `liab` names the operator, not the principal. A platform can hold someone accountable without learning who the user is.
- **What Kaze cannot fix:** a platform that wants no agents at all, for example to keep ad revenue, will not be persuaded by a protocol. The Offer gives it control and a price. It does not create the incentive to use them.

## 9. Open questions

1. **ES256.** AP2 requires non-deterministic signatures on checkout JWTs. Should Kaze require ES256 for `hp` mandates?
2. **Disclosure granularity.** Should each `act` element be its own disclosure (draft 1)?
3. **Revocation.** For long-lived mandates, should Kaze use a status list (IETF Token Status List) or rely on short expiries?
4. **Where to standardise.** Should the Offer go to the IETF (next to webbotauth and the HTTP `Payment` auth scheme) and `act`/`liab` to the FIDO Payments working group alongside AP2? Or should both be a single profile?
5. **Action registry.** Should there be a shared registry of action ids?
