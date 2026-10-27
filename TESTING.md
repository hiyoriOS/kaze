# Testing

Every check below also runs in CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)); Miri over all vectors and fuzzing run on `main` and nightly rather than on every PR push. Results last recorded 2026-10-18 on Rust 1.94.0 and nightly 1.101 (aarch64-apple-darwin). The rows for signing were recorded on 2026-10-27 on Rust 1.99.1 and the same nightly.

## Checks

| Check | Command | Result |
|---|---|---|
| Conformance vectors | `cargo test --all-features` | 55/55 mandate, 27/27 Web Bot Auth, 17 signing and 5 directory cases |
| RFC known answers | `cargo test --lib agent` | RFC 9421 §B.2.6 signature base and Ed25519 bytes; RFC 8037 §A.3 thumbprint |
| Vectors are reproducible | `cargo run -q --example vectors --features issue \| cmp - vectors/v1.json` (and `--example agent --features issue`, `--example sign --features sign`) | identical |
| Signing is Web Bot Auth | `cargo test --all-features --test sign` | every signed output parses and verifies as RFC 9421 Ed25519 with a hand-built signature base, independent of the crate's own; the default call still produces the 0.3 bytes; each covered component binds the request |
| Signing-only build | `cargo test --no-default-features --features sign` | unit, agent, signing and mandate-vector tests pass without the `verify` exports |
| Miri: unit tests and every ABI export | `cargo +nightly miri test --lib --all-features` | 16/16 (2026-10-27, adds `kzp_sign_request` and `kzp_directory` across the boundary); no UB, leaks or double frees |
| Miri: all vectors with real Ed25519 | `cargo +nightly miri test --all-features --test vectors` | pass (883 s) |
| Leaks: counting allocator | `cargo test --release --all-features --test alloc` | 0 bytes retained over 51 runs per mandate vector and 20 per agent vector |
| Property tests | `cargo test --release --all-features --test props` | every edit to a valid presentation or a signed request is rejected; no panic on arbitrary input |
| Fuzzing | `cargo +nightly fuzz run verify fuzz/corpus/verify -- -max_total_time=180` (and `abi`, `agent`, `sign`) | 7.6M, 2.9M and 1.6M runs, 0 crashes; `sign` 2.2M runs in 181 s, 0 crashes. It also asserts that whatever tag and components the signer accepts, `verify_agent_with_tag` accepts the result |
| WebAssembly | see below | 52 mandate and 27 agent cases agree; 17 signing and 5 directory cases agree byte for byte; issuance round trip; memory flat over 102,000 calls; freed requests zeroed |
| Signing-only `kzp.wasm` | see below | 217,596 bytes, no imports, exactly `kzp_alloc`, `kzp_free`, `kzp_sign_request`, `kzp_directory`; the same SHA-256 from two builds, from another checkout path and from another target directory; memory flat over 22,000 calls |
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

The signing-only build (`--no-default-features --features sign`) goes through the same harness. It must export exactly the four functions above, reproduce `vectors/sign.json`, and keep memory flat. CI builds it twice into separate target directories and fails unless the files are identical:

```bash
cargo rustc --locked --lib --crate-type cdylib --profile wasm --target wasm32-unknown-unknown \
  --no-default-features --features sign --target-dir target/sign
cd harness && cargo run --release -- ../target/sign/wasm32-unknown-unknown/wasm/kzp.wasm ../vectors
```

With Rust 1.99.1 its SHA-256 is `3d10dd2fc766c763f4e0a06ac8340854b6b0310ff91a29ac550cfa5eb425b27d`. A different toolchain can give a different hash.

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
- The signing-only `kzp.wasm` is 218 KB (217,596 bytes). One signature costs 2.6M to 2.8M fuel in wasmi.
- Wall-clock times come from `cargo bench`.
