# kzp

The Kaze protocol (KZP) in Rust: platform-signed admission terms for AI agents, and mandates that say what an agent may do and who answers for it.

Kaze adds two pieces on top of existing standards:

- **Offer:** a platform answers an agent with signed terms for each action: the exact amount, the liability floor, the price and the sanctioned path.
- **Mandate:** the agent replies with an SD-JWT mandate from its principal. Its `act` and `liab` claims say what the agent may do, where, up to how much, and which operator is accountable.

Identity (Web Bot Auth), payment (x402, MPP) and receipts are reused, not reinvented. The protocol is specified in [`spec/kaze.md`](spec/kaze.md).

## Example

```toml
[dependencies]
kzp = "0.1"
```

```rust
let offer = kzp::verify_offer(token, &jwks, "https://shop.example", now)?;
let ctx = kzp::Context { now, operator, offer: &offer };
let grant = kzp::verify(presentation, &ctx, &trust)?;
```

The verifier is a pure function: it never reads the clock, generates randomness, or does I/O. The caller keeps the state. It marks `grant.nonce` as used, applies quotas by `(grant.issuer, grant.jti)`, and settles `grant.price` for exactly `grant.amount`.

## WebAssembly

The same crate builds `kzp.wasm`. The module imports nothing, and its ABI is four functions that take and return JSON, documented in [`src/abi.rs`](src/abi.rs).

```bash
cargo rustc --lib --crate-type cdylib --profile wasm --target wasm32-unknown-unknown
```

## Features

- `issue`: produce Offers, attestations, mandates and presentations. Verifiers don't need it.

## Testing

[`vectors/v1.json`](vectors/v1.json) holds the conformance cases that every implementation must pass. [TESTING.md](TESTING.md) covers the other checks: Miri, fuzzing, leak and allocation budgets, the WebAssembly harness, and performance.

## Supported Rust versions

The minimum supported Rust version is 1.84.

## Status

Draft 0 of the protocol. It is not yet submitted to a standards body, and the API may change. Only EdDSA (Ed25519) signatures and top-level disclosures are supported; see [`CHANGELOG.md`](CHANGELOG.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
