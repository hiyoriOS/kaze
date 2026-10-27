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

## Sign an agent's request

An agent that orders at a business with no Offers still signs its requests. This needs no Offer and no mandate:

```rust
use kzp::sign::{self, RequestSignature};

let mut request = kzp::Message { /* method, scheme, authority, path, headers */ };
sign::sign_request(
    &mut request,
    &RequestSignature {
        label: "sig",
        agent_url: "https://agent.example",       // serves the key directory
        created: now,
        expires: now + 300,
        nonce: Some(&nonce),
        tag: kzp::agent::TAG,                       // or the tag your verifier looks for
        components: &sign::DEFAULT_COMPONENTS,      // add "content-digest" to bind the body
    },
    &signing_key,
)?;                                                 // adds Signature-Agent, Signature-Input, Signature

// Serve this at https://agent.example/.well-known/http-message-signatures-directory
let directory = sign::directory(&[signing_key.verifying_key()])?;
```

## Features

| Feature | Adds |
|---|---|
| `verify` *(default)* | The verification exports of the WebAssembly ABI. The verifier itself is always built. |
| `sign` | Signing requests and the key directory, and their ABI exports |
| `issue` | Creating Offers, mandates and presentations. Includes `sign`. |

## WebAssembly

Each [release](https://github.com/hiyoriOS/kaze/releases) ships `kzp.wasm` and its SHA-256. It is the same crate built with `issue`, it has no imports, and it exchanges JSON over a small ABI documented in [`src/abi.rs`](src/abi.rs). To build it yourself:

```bash
cargo rustc --lib --crate-type cdylib --profile wasm --target wasm32-unknown-unknown --features issue
```

### Signing-only `kzp.wasm`

A host that only signs its own requests, such as a Go service, embeds a smaller build: 217,596 bytes, no imports, and four functions plus `memory`.

| Export | Request | Response `ok` |
|---|---|---|
| `kzp_alloc`, `kzp_free` | | |
| `kzp_sign_request` | `{"message","label","agent_url","created","expires","nonce"?,"tag"?,"components"?,"seed"}` | `message` with `Signature-Agent`, `Signature-Input` and `Signature` added |
| `kzp_directory` | `{"seeds": ["<base64url>", ...]}` | `{"keys": [JWK, ...]}`, the body for the key-directory endpoint; each `kid` is the JWK thumbprint, which is the signature's `keyid` |

`seed` is a 32-byte Ed25519 seed, base64url without padding; the host owns it. `tag` defaults to `web-bot-auth`, `components` to `["@method","@authority","@path"]`, and `signature-agent` is always covered after them. Calling convention, errors and memory rules are in [`src/abi.rs`](src/abi.rs); known answers are in [`vectors/sign.json`](vectors/sign.json).

To build it, from a clean checkout of a tag, with the toolchain recorded in the release notes:

```bash
cargo rustc --locked --lib --crate-type cdylib --profile wasm --target wasm32-unknown-unknown \
  --no-default-features --features sign --target-dir target/sign
shasum -a 256 target/sign/wasm32-unknown-unknown/wasm/kzp.wasm
```

The same toolchain and lockfile give the same bytes whatever the checkout path or target directory. Use a `--target-dir` of its own: the output is also named `kzp.wasm`, and the full build writes the same name under `target/`.

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
