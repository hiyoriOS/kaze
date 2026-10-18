# Testing

Every check below also runs in CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Results last recorded 2026-10-18 on Rust 1.94.0 and nightly 1.101 (aarch64-apple-darwin).

## Checks

| Check | Command | Result |
|---|---|---|
| Conformance vectors | `cargo test --all-features` | 55/55 mandate, 20/20 Web Bot Auth |
| RFC known answers | `cargo test --lib agent` | RFC 9421 §B.2.6 signature base and Ed25519 bytes; RFC 8037 §A.3 thumbprint |
| Vectors are reproducible | `cargo run -q --example vectors --features issue \| cmp - vectors/v1.json` (and `--example agent`) | identical |
| Miri: unit tests and every ABI export | `cargo +nightly miri test --lib --all-features` | 11/11; no UB, leaks or double frees |
| Miri: all vectors with real Ed25519 | `cargo +nightly miri test --all-features --test vectors` | pass (883 s) |
| Leaks: counting allocator | `cargo test --release --all-features --test alloc` | 0 bytes retained over 51 runs per mandate vector and 20 per agent vector |
| Property tests | `cargo test --release --all-features --test props` | every edit to a valid presentation or a signed request is rejected; no panic on arbitrary input |
| Fuzzing | `cargo +nightly fuzz run verify fuzz/corpus/verify -- -max_total_time=180` (and `abi`, `agent`) | 7.6M, 2.9M and 1.6M runs, 0 crashes |
| WebAssembly | see below | 52 mandate and 20 agent cases agree; issuance round trip; memory flat over 72,000 calls; freed requests zeroed |
| Lints | `cargo clippy --all-features --all-targets` | pedantic and restriction lints, 0 warnings |
| Docs | `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps` | clean |
| MSRV | `cargo +1.84 check --lib --all-features` | builds |
| Dependencies | `cargo deny check` | advisories, licenses, bans and sources ok |

## WebAssembly harness

`harness/` is a dev-only crate. It loads `kzp.wasm` in wasmi, a pure-Rust interpreter, and then:

1. checks the module has no imports;
2. runs every vector through the ABI exactly as a host would, then a full round trip through the issuance exports (offer, mandate, presentation, signed request);
3. records fuel (wasmi's instruction count). It is identical on every run for verification. Web Bot Auth's cost varies by under 0.1% because `sfv` uses hash-seeded maps; its results never vary;
4. asserts linear memory stops growing after warm-up, and that no request bytes survive `kzp_free`.

```bash
cargo rustc --lib --crate-type cdylib --profile wasm --target wasm32-unknown-unknown --features issue
cd harness && cargo run --release -- ../target/wasm32-unknown-unknown/wasm/kzp.wasm ../vectors
```

## Performance

The deterministic numbers are budgets. The wall-clock times are only for orientation.

| Path | Allocations | Peak heap | Wasm fuel | Native time |
|---|---|---|---|---|
| Full success (3 signatures, liability) | 317 | 18 KB | 12.4M | 143 µs |
| Read action (2 signatures) | 275 | 18 KB | 9.7M | 100 µs |
| Fails at the issuer signature | 213 | 18 KB | 6.4M | 47 µs |
| `verify_offer` | | | | 50 µs |
| `verify_agent` (Web Bot Auth) | | | 3.6M | 71 µs |
| ABI round trip (offer, presentation, JSON) | | | | 200 µs |

- `tests/alloc.rs` fails if the worst case exceeds 400 allocations or 32 KB.
- `kzp.wasm` with `issue` is 414 KB raw (308 KB without it) at `opt-level = "s"`. `"z"` saves only 2.4% but costs 6% more fuel.
- Wall-clock times come from `cargo bench`.
