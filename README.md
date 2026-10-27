# kzp

The reference implementation of **Kaze**, a protocol that lets platforms admit AI agents on their own terms.

- A platform answers an agent with an **Offer**: signed terms for one action, such as its exact amount.
- The agent replies with a **mandate** from the person it acts for: what it may do, where, up to how much, and which operator answers for it.
- **Web Bot Auth** (RFC 9421) identifies that operator.

Identity, payment and receipts reuse existing standards. The full protocol is in [`spec/kaze.md`](spec/kaze.md).

## Install

```toml
[dependencies]
kzp = "0.3"
```

## Verify an agent's request

```rust
// 1. Who is calling: the operator behind the request's Web Bot Auth signature.
let url = kzp::signature_agent(&request)?;                  // request: kzp::Message
let directory = kzp::agent::directory_url(&url)?;
let keys = fetch_keys(&directory)?;                          // your HTTPS client
let agent = kzp::verify_agent(&request, &keys, &directory, now)?;

// 2. What they may do: the presentation, against the Offer you issued.
let offer = kzp::verify_offer(&offer_token, &platform_keys, "https://shop.example", now)?;
let ctx = kzp::Context { now, operator: &agent.operator, offer: &offer };
let grant = kzp::verify(&presentation, &ctx, &trusted_issuers)?;

// 3. Your side: mark grant.nonce used, apply quotas to grant.jti,
//    and charge exactly grant.amount.
```

Every call is a pure function: no clock, no randomness, no I/O. You pass in `now`, the keys and the directory.

## Features

| Feature | Adds |
|---|---|
| *(default)* | Verification only |
| `issue` | Creating Offers, mandates and presentations, and signing requests |

## WebAssembly

Each [release](https://github.com/hiyoriOS/kaze/releases) ships `kzp.wasm` and its SHA-256. It is the same crate built with `issue`, it has no imports, and it exchanges JSON over a small ABI documented in [`src/abi.rs`](src/abi.rs). To build it yourself:

```bash
cargo rustc --lib --crate-type cdylib --profile wasm --target wasm32-unknown-unknown --features issue
```

## Repository

| Path | Contents |
|---|---|
| [`src/`](src/) | The crate |
| [`spec/`](spec/) | The protocol and its JSON Schemas |
| [`vectors/`](vectors/) | Conformance cases every implementation must pass |
| [`docs/decisions/`](docs/decisions/) | Decision records |
| [`TESTING.md`](TESTING.md) | How it's tested, and performance budgets |
| [`CHANGELOG.md`](CHANGELOG.md) | Changes by version |

```bash
cargo test --all-features
```

## Status

Draft 0: not yet submitted to a standards body, and the API may change. The minimum supported Rust version is 1.84.

## License

[Apache-2.0](LICENSE)

Patents: the specification is available under OWFa 1.0 ([PATENTS.md](PATENTS.md)).
