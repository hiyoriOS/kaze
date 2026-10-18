# kaze

A verifier for Kaze, a draft protocol that lets a platform state its own terms for admitting an AI agent and lets a principal's mandate say what the agent may do and who answers for it. Kaze adds two pieces to existing standards:

| Piece | What it is |
|---|---|
| **Offer** | A platform-signed set of admission terms, one per action: the exact `amount`, the liability floor, required proofs, price, quota, sanctioned path, and who runs checkout. |
| **`act` / `liab`** | Claims on an SD-JWT mandate (AP2-style): which actions are delegated, on which platforms and up to what amount, and which operator is accountable, backed by a recourse provider's attestation. |

Everything else is reused: Web Bot Auth for identity, x402 or MPP for payment, and x402/MPP/AP2 receipts. The protocol is [`spec/kaze.md`](spec/kaze.md), and the reasoning behind it is in `../kaze-analysis/access.md`.

## Use

```rust
let offer = kaze::verify_offer(token, &jwks, "https://shop.example", now)?;
let ctx = kaze::Context { now, operator: wba_operator, offer: &offer };
let grant = kaze::verify(presentation, &ctx, &trust)?;
// The caller then: marks grant.nonce used, applies quota by (grant.issuer, grant.jti),
// and settles grant.price for exactly grant.amount.
```

The verifier is a pure function: no clock, no randomness, no I/O. The same crate compiles to `kaze.wasm`, which has **zero imports** and a four-function ABI (`kaze_alloc`, `kaze_free`, `kaze_verify`, `kaze_verify_offer`, JSON in and out; see `src/abi.rs`). Any host that runs WebAssembly can use it.

## Layout

The layout follows single-crate conventions from tokio, serde_json and rustls.

```
src/          lib, error, json (strict), jws, offer, mandate, verify, issue (feature), abi
tests/        vectors (conformance), alloc (leaks and allocation budget), props (proptest)
benches/      criterion
examples/     vectors: regenerates vectors/v1.json byte-for-byte
fuzz/         cargo-fuzz targets: verify, abi
harness/      dev-only: runs kaze.wasm in wasmi (fuel, imports, memory growth)
spec/         the protocol and JSON Schemas
vectors/      55 deterministic conformance cases, one or more per error code
deny.toml     cargo-deny policy
.github/      CI that mirrors the checks below
```

## Verified (2026-10-18, Rust 1.95 / nightly 1.101, aarch64-apple-darwin)

| Check | Result |
|---|---|
| Conformance vectors (native) | 55/55 |
| Same vectors through `kaze.wasm` (wasmi) | 52/52 presentation cases agree; the other 3 test offers only |
| Miri: unit tests including every ABI export | 11/11; no UB, leaks or double frees |
| Miri: all 55 vectors with real Ed25519 | pass (870 s) |
| Leaks (counting allocator, 51 runs per vector) | 0 bytes retained, allocation count identical every run |
| Leaks (wasm linear memory, 102,000 calls) | 18 pages before and after |
| Property tests (proptest, 4,096 cases each) | every edit to a valid presentation rejected; no panic on arbitrary input |
| Fuzzing (libFuzzer, 180 s per target) | `verify` 7.6M runs, `abi` 2.9M runs, 0 crashes |
| `clippy::pedantic` plus restriction lints | 0 warnings |
| `rustdoc -D warnings`, `rustfmt` | clean |
| MSRV 1.84 (lib) | builds |
| cargo-deny | advisories, licenses, bans, sources ok |

## Performance

Deterministic numbers are the budget; wall-clock numbers are for orientation.

| Path | Allocations | Peak heap | wasm fuel | Native time |
|---|---|---|---|---|
| Full success (3 signatures, liability) | 317 | 18 KB | 12.4M | 143 µs |
| Read action (2 signatures) | 275 | 18 KB | 9.7M | 100 µs |
| Fails at issuer signature | 213 | 18 KB | 6.4M | 47 µs |
| `verify_offer` | | | | 50 µs |
| ABI round trip, offer + presentation + JSON | | | | 200 µs |

- **Allocations and peak heap** are pinned by `tests/alloc.rs`, which fails if the worst case goes over 400 allocations or 32 KB.
- **Fuel** is wasmi's instruction metering. It is identical on every run once the first call has warmed up.
- **`kaze.wasm`** is 308 KB raw and 107 KB gzipped (`opt-level = "s"`, LTO). `opt-level = "z"` saves only 2.4% (301 KB) and costs 6% more fuel, so the profile stays at `"s"`.
- **Cost in context:** Ryo's executor round trip is about 4.3 ms, so one verification adds under 5%.

## Commands

```bash
cargo test --all-features
```

```bash
cargo run -q --example vectors --features issue | cmp - vectors/v1.json
```

```bash
cargo +nightly miri test --all-features --lib
```

```bash
cargo build --profile wasm --target wasm32-unknown-unknown --lib
```

```bash
cd harness && cargo run --release -- ../target/wasm32-unknown-unknown/wasm/kaze.wasm ../vectors/v1.json
```

```bash
cargo +nightly fuzz run verify fuzz/corpus/verify -- -max_total_time=60
```

## Not done

- **License:** not chosen; `publish = false` until it is.
- **ES256:** only EdDSA is supported (spec §9.1).
- **Disclosures:** only top-level ones. Per-element `act` disclosure is planned for draft 1.
- **Web Bot Auth:** the caller verifies the request signature and passes in the operator.
- **State the caller keeps:** nonce single use, quotas, and cumulative limits.
