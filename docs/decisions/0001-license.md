# 0001: One license, `MIT OR Apache-2.0`, for the whole repository

Status: accepted (code, spec, schemas, vectors). Two follow-ups await the owner: a patent pledge for the protocol, and the contribution sign-off.
Date: 2026-10-18

## Decision

Everything in this repository is licensed under the SPDX expression **`MIT OR Apache-2.0`**. That covers the `kzp` crate, the `kzp.wasm` release asset, `spec/kaze.md`, `spec/schema/`, and `vectors/`. The licensee picks either license.

This is not a new choice. `kzp` 0.1.0 and 0.2.0 are already on crates.io under this expression, and a published version keeps its license. This record writes down why we keep it, and it widens the README statement from "this crate" to the whole repository. The spec, schemas and vectors are not in the crate package (`Cargo.toml` `include`), so "this crate" left them without a stated license.

## Who adopts it

| Adopter | What they do with Kaze | What they need from the license |
|---|---|---|
| Agents and agent SDKs | Embed `kzp` or `kzp.wasm` in Rust, TypeScript, Python or Go clients, often closed source | No copyleft. Shipping a binary needs only the notices below. |
| Platforms and merchants | Verify Offers and mandates in proprietary servers. Ryo (unlicensed, proprietary) embeds `kzp.wasm`. | Server-side use triggers no obligations under either license. |
| Payment processors and issuers | Implement or embed the verifier and issue mandates. Their legal teams review the license and patents first. | An express patent grant they can elect: Apache-2.0 §3. |
| Other implementers | Write their own verifier in another language and copy `vectors/` into their test suites | Permission to copy the vectors and quote the spec. Both licenses give it. |

`MIT OR Apache-2.0` is the Rust ecosystem default. Most corporate open-source offices have pre-approved it, so it is the fastest license to get through review.

## Patent grant

Apache-2.0 §3 grants a patent license from each contributor. It ends for a licensee who sues over patents in the Work. MIT has no express patent grant.

Under the dual license, every contributor grants under both licenses, so the Apache-2.0 patent grant always exists. Any adopter who wants it elects Apache-2.0. The cost is that an adopter can elect MIT instead, sue over patents, and still keep its copyright license. Apache-2.0's termination clause would not apply to it.

We accept that cost. Two reasons:

1. **Licensing only under Apache-2.0 would gain little and lose compatibility.** Apache-2.0 alone is incompatible with GPL-2.0-only projects, and it breaks the Rust-standard expression that offices pre-approve. The termination clause protects a small reference implementation that has no patents behind it.
2. **The patent risk that matters is in the protocol, and no code license covers it.** Apache-2.0 §3 covers "the Work", meaning this code. A processor that writes its own Kaze verifier in Java uses none of this code, so it gets no grant from Apache-2.0. Interoperable implementations need a royalty-free patent commitment on the specification itself. See the first follow-up.

## Dependencies

Checked with `cargo metadata` and `cargo deny check` (licenses ok) on 2026-10-18.

**Shipped in the crate and in `kzp.wasm`** (`cargo tree -e normal --all-features --target wasm32-unknown-unknown`):

| License | Crates | Obligation when redistributed as a binary |
|---|---|---|
| BSD-3-Clause | `curve25519-dalek`, `ed25519-dalek`, `subtle` | Reproduce the copyright notice and license text |
| MIT | `generic-array`, `zmij` | Include the notice |
| MIT OR Apache-2.0 (or a superset) | the rest: `serde`, `serde_json`, `sha2`, `digest`, `base64`, `sfv`, `thiserror`, `zeroize`, `indexmap`, `hashbrown`, `memchr`, `itoa`, `typenum`, … | Include a notice for the license elected |
| (MIT OR Apache-2.0) AND Unicode-3.0 | `unicode-ident` (build time only, via proc macros) | None: not in the binary |

All of these are permissive and compatible with `MIT OR Apache-2.0`. None is copyleft. `r-efi` offers LGPL-2.1-or-later only as one choice among MIT and Apache-2.0, and it is not in the wasm build.

**Dev, test and tooling only, never distributed:** `ciborium` (Apache-2.0, via `criterion`), `foldhash` (Zlib, harness), `libfuzzer-sys` ((MIT OR Apache-2.0) AND NCSA, fuzz), `wasmi` (MIT/Apache-2.0, harness). They have no effect on adopters.

**Gap:** the GitHub release asset `kzp.wasm` ships without the BSD-3-Clause and MIT notices of the code compiled into it. Each release should attach a `THIRD-PARTY-NOTICES` file, generated with `cargo about` from the same lockfile. Hosts that redistribute `kzp.wasm` inside their own binaries carry the same obligation.

## Contribution terms

Inbound terms equal outbound terms: a contribution is licensed under `MIT OR Apache-2.0`, per Apache-2.0 §5 and the README. There is no CLA. Today git history has one human author, so the owner can still relicense alone. The first outside contribution ends that.

## Not done, and why

- **SPDX headers in source files.** `Cargo.toml` `license` is the machine-readable source that crates.io, docs.rs and `cargo deny` read. Per-file headers would add noise and nothing else.
- **Licensing the spec under CC-BY-4.0.** The spec text is short, and code-style licenses let implementers copy normative text into their own code comments and tests. A standards body (IETF, FIDO) receives its own grant on submission, alongside this license.

## Follow-ups (owner decision)

1. **A patent pledge for the protocol.** Add a royalty-free commitment covering implementations of `spec/kaze.md`, such as the Open Web Foundation Final Specification Agreement (OWFa 1.0) or a short non-assert in `PATENTS.md`. This matters most to payment processors, and it is the one change that adds protection rather than restating it.
2. **Contribution sign-off.** Choose before the first outside contribution. The recommendation is the DCO (`Signed-off-by`), checked in CI, with no CLA. A CLA is needed only if the owner wants to keep the option of relicensing or selling a commercial license later.
3. **Third-party notices** on each `kzp.wasm` release, as described above.
