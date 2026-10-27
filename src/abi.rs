//! JSON-in, JSON-out entry points for hosts that load `kzp.wasm`.
//!
//! The safe functions here are plain Rust and run on every target. The `extern "C"`
//! exports exist only on `wasm32` (and in this crate's own tests). The protocol for a
//! host is:
//!
//! 1. `ptr = kzp_alloc(len)`, then copy the request JSON into `[ptr, ptr + len)`.
//! 2. `kzp_<op>(ptr, len, ret)`, where `ret` points to two
//!    writable `usize`s (8 bytes on wasm32). `ptr` is left untouched.
//! 3. The response is `ret[1]` bytes at `ret[0]`.
//! 4. `kzp_free(ptr, len)` and `kzp_free(ret[0], ret[1])`. Each pointer is freed
//!    exactly once, with the length it came with.
//!
//! The response is `{"ok": ...}` or `{"error": {"code": ..., "message": ...}}`.
//!
//! Which exports a build has depends on its features:
//!
//! | Feature | Exports |
//! |---|---|
//! | *(always)* | `kzp_alloc`, `kzp_free` |
//! | `verify` (default) | `kzp_verify_offer`, `kzp_verify`, `kzp_signature_agent`, `kzp_verify_agent` |
//! | `sign` | `kzp_sign_request`, `kzp_directory` |
//! | `issue` (includes `sign`) | also `kzp_jwk`, `kzp_issue_offer`, `kzp_issue_mandate`, `kzp_present` |
//!
//! The exports that sign take a 32-byte Ed25519 seed (base64url) from the host, which
//! owns key storage and randomness. `kzp_free` zeroes every buffer before releasing
//! it, so a seed never outlives its call in linear memory.
//!
//! A build that only signs (`--no-default-features --features sign`) is the one a
//! Go host embeds to sign its agent's requests; see `README.md` for the recipe. It
//! exports `kzp_alloc`, `kzp_free`, `kzp_sign_request` and `kzp_directory`, and
//! imports nothing. Its two operations:
//!
//! - `kzp_sign_request`: [`sign_request_json`]. The response's `ok` is the request
//!   `message` with `Signature-Agent`, `Signature-Input` and `Signature` appended
//!   in that order. Send them as headers, exactly as returned. Errors are
//!   `agent_components` (the components cannot be covered: no `@authority` or
//!   `@target-uri`, a header the message lacks, an unsupported or repeated component)
//!   and `malformed` (the request itself, the seed, the label or the tag).
//! - `kzp_directory`: [`directory_json`]. The response's `ok` is the body of
//!   `/.well-known/http-message-signatures-directory`; serve its bytes as they are
//!   with `Content-Type: application/http-message-signatures-directory+json`.
//!
//! Both are pure: the host passes the clock readings (`created`, `expires`), the
//! nonce and the seed. `vectors/sign.json` holds requests and the exact responses.

#[cfg(any(feature = "verify", feature = "sign"))]
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "verify", feature = "sign"))]
use crate::{json, Error};
#[cfg(feature = "verify")]
use crate::{verify, verify_offer, Context, Jwk, Message, Trust};

/// Requests larger than this are refused before parsing.
pub const MAX_INPUT: usize = 256 * 1024;

#[cfg(feature = "verify")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferRequest {
    offer: String,
    jwks: Vec<Jwk>,
    iss: String,
    now: i64,
}

#[cfg(feature = "verify")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    offer: String,
    jwks: Vec<Jwk>,
    iss: String,
    now: i64,
    operator: String,
    presentation: String,
    trust: Trust,
}

#[cfg(any(feature = "verify", feature = "sign"))]
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Response<T> {
    Ok(T),
    Error { code: &'static str, message: String },
}

#[cfg(any(feature = "verify", feature = "sign"))]
fn respond<T: Serialize>(r: Result<T, Error>) -> Vec<u8> {
    let body = match r {
        Ok(v) => Response::Ok(v),
        Err(e) => Response::Error {
            code: e.code(),
            message: e.to_string(),
        },
    };
    // Grants and offers hold only strings, integers and JSON values: this cannot fail.
    serde_json::to_vec(&body).unwrap_or_default()
}

#[cfg(any(feature = "verify", feature = "sign"))]
fn request<T: for<'de> Deserialize<'de>>(input: &[u8]) -> Result<T, Error> {
    if input.len() > MAX_INPUT {
        return Err(Error::Malformed("request too large"));
    }
    serde_json::from_value(json::parse(input)?).map_err(|_| Error::Malformed("request"))
}

/// `{"offer","jwks","iss","now"}` to `{"ok": Offer}`.
#[cfg(feature = "verify")]
#[must_use]
pub fn verify_offer_json(input: &[u8]) -> Vec<u8> {
    respond(
        request::<OfferRequest>(input)
            .and_then(|r| verify_offer(&r.offer, &r.jwks, &r.iss, r.now))
            .map(crate::offer::Verified::into_inner),
    )
}

/// `{"offer","jwks","iss","now","operator","presentation","trust"}` to `{"ok": Grant}`.
#[cfg(feature = "verify")]
#[must_use]
pub fn verify_json(input: &[u8]) -> Vec<u8> {
    respond(request::<VerifyRequest>(input).and_then(|r| {
        let offer = verify_offer(&r.offer, &r.jwks, &r.iss, r.now)?;
        let ctx = Context {
            now: r.now,
            operator: &r.operator,
            offer: &offer,
        };
        verify(&r.presentation, &ctx, &r.trust)
    }))
}

#[cfg(feature = "verify")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRequest {
    message: Message,
    #[serde(default)]
    directory: Vec<Jwk>,
    #[serde(default)]
    directory_url: String,
    #[serde(default)]
    now: i64,
    /// The signature's `tag`; Web Bot Auth's when absent.
    #[serde(default)]
    tag: Option<String>,
}

#[cfg(feature = "verify")]
impl AgentRequest {
    fn tag(&self) -> &str {
        self.tag.as_deref().unwrap_or(crate::agent::TAG)
    }
}

/// `{"message","tag"}` to `{"ok": {"url", "directory_url"}}`: which directory to fetch.
/// `tag` is optional and defaults to `web-bot-auth`.
#[cfg(feature = "verify")]
#[must_use]
pub fn signature_agent_json(input: &[u8]) -> Vec<u8> {
    respond(request::<AgentRequest>(input).and_then(|r| {
        let url = crate::agent::signature_agent_with_tag(&r.message, r.tag())?;
        let directory_url = crate::agent::directory_url(&url)?;
        Ok(serde_json::json!({ "url": url, "directory_url": directory_url }))
    }))
}

/// `{"message","directory","directory_url","now","tag"}` to `{"ok": Agent}`. `tag` is
/// optional and defaults to `web-bot-auth`.
#[cfg(feature = "verify")]
#[must_use]
pub fn verify_agent_json(input: &[u8]) -> Vec<u8> {
    respond(request::<AgentRequest>(input).and_then(|r| {
        crate::agent::verify_agent_with_tag(
            &r.message,
            &r.directory,
            &r.directory_url,
            r.now,
            r.tag(),
        )
    }))
}

#[cfg(feature = "sign")]
mod signing {
    //! Request signing and the key directory (feature `sign`).

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use serde::Deserialize;

    use super::{request, respond};
    use crate::sign::{self, RequestSignature};
    use crate::{agent, jws, Error, Message};

    pub(super) fn key(seed: &str) -> Result<SigningKey, Error> {
        let bytes: [u8; 32] = jws::unb64(seed)?
            .try_into()
            .map_err(|_| Error::Malformed("seed"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SignIn {
        message: Message,
        label: String,
        agent_url: String,
        created: i64,
        expires: i64,
        #[serde(default)]
        nonce: Option<String>,
        /// The signature's `tag`; Web Bot Auth's when absent.
        #[serde(default)]
        tag: Option<String>,
        /// The covered components; the method, authority and path when absent.
        #[serde(default)]
        components: Option<Vec<String>>,
        seed: String,
    }

    /// `{"message","label","agent_url","created","expires","nonce","tag","components",
    /// "seed"}` to `{"ok": Message}` with the three Web Bot Auth headers added.
    ///
    /// `nonce`, `tag` and `components` are optional. `tag` defaults to `web-bot-auth`
    /// and `components` to `["@method","@authority","@path"]`; a request that sends
    /// neither behaves exactly as it did before they existed. `signature-agent` is
    /// always covered in addition.
    #[must_use]
    pub fn sign_request_json(input: &[u8]) -> Vec<u8> {
        respond(request::<SignIn>(input).and_then(|mut r| {
            let owned = r.components.take();
            let components: Vec<&str> = owned.as_ref().map_or_else(
                || sign::DEFAULT_COMPONENTS.to_vec(),
                |c| c.iter().map(String::as_str).collect(),
            );
            sign::sign_request(
                &mut r.message,
                &RequestSignature {
                    label: &r.label,
                    agent_url: &r.agent_url,
                    created: r.created,
                    expires: r.expires,
                    nonce: r.nonce.as_deref(),
                    tag: r.tag.as_deref().unwrap_or(agent::TAG),
                    components: &components,
                },
                &key(&r.seed)?,
            )?;
            Ok(r.message)
        }))
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DirectoryIn {
        seeds: Vec<String>,
    }

    /// `{"seeds"}` to `{"ok": {"keys": [Jwk, ...]}}`: the body to serve at
    /// `/.well-known/http-message-signatures-directory`. Each key's `kid` is its JWK
    /// thumbprint, the `keyid` a signature carries. Pass every seed whose key a
    /// verifier may still need, so a rotation lists the old and new keys together.
    #[must_use]
    pub fn directory_json(input: &[u8]) -> Vec<u8> {
        respond(request::<DirectoryIn>(input).and_then(|r| {
            if r.seeds.is_empty() {
                return Err(Error::Malformed("seeds"));
            }
            let keys = r
                .seeds
                .iter()
                .map(|s| key(s).map(|k| k.verifying_key()))
                .collect::<Result<Vec<VerifyingKey>, _>>()?;
            sign::directory(&keys)
        }))
    }
}

#[cfg(feature = "sign")]
pub use signing::{directory_json, sign_request_json};

#[cfg(feature = "issue")]
mod issuing {
    //! Issuance entry points (feature `issue`).

    use serde::Deserialize;
    use serde_json::{Map, Value};

    use super::{request, respond, signing::key};
    use crate::{issue, Binding, Jwk, Offer};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JwkIn {
        seed: String,
        kid: String,
    }

    /// `{"seed","kid"}` to `{"ok": Jwk}`: the public key to publish.
    #[must_use]
    pub fn jwk_json(input: &[u8]) -> Vec<u8> {
        respond(
            request::<JwkIn>(input)
                .and_then(|r| Ok(Jwk::new(&key(&r.seed)?.verifying_key(), Some(&r.kid)))),
        )
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OfferIn {
        offer: Offer,
        kid: String,
        seed: String,
    }

    /// `{"offer","kid","seed"}` to `{"ok": "<offer JWS>"}`.
    #[must_use]
    pub fn issue_offer_json(input: &[u8]) -> Vec<u8> {
        respond(
            request::<OfferIn>(input)
                .and_then(|r| Ok(issue::offer(&r.offer, &r.kid, &key(&r.seed)?))),
        )
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MandateIn {
        claims: Map<String, Value>,
        /// `[salt, name, value]` triples; salts come from the host's randomness.
        disclosures: Vec<(String, String, Value)>,
        kid: String,
        seed: String,
    }

    /// `{"claims","disclosures","kid","seed"}` to `{"ok": "<issuer-jwt>~<d>~..."}`,
    /// the prefix an agent binds with `kzp_present`.
    #[must_use]
    pub fn issue_mandate_json(input: &[u8]) -> Vec<u8> {
        respond(request::<MandateIn>(input).and_then(|r| {
            let ds: Vec<String> = r
                .disclosures
                .iter()
                .map(|(salt, name, value)| issue::disclosure(salt, name, value))
                .collect();
            let jwt = issue::mandate(Value::Object(r.claims), &ds, &r.kid, &key(&r.seed)?);
            Ok(issue::prefix(&jwt, &ds))
        }))
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PresentIn {
        prefix: String,
        binding: Binding,
        seed: String,
    }

    /// `{"prefix","binding","seed"}` to `{"ok": "<presentation>"}` (fills `sd_hash`).
    #[must_use]
    pub fn present_json(input: &[u8]) -> Vec<u8> {
        respond(
            request::<PresentIn>(input)
                .and_then(|r| Ok(issue::present(&r.prefix, r.binding, &key(&r.seed)?))),
        )
    }
}

#[cfg(feature = "issue")]
pub use issuing::{issue_mandate_json, issue_offer_json, jwk_json, present_json};

#[cfg(any(target_arch = "wasm32", test))]
#[allow(unsafe_code, unreachable_pub)] // exported to the host, not to Rust
mod exports {
    //! The only `unsafe` in the crate: moving byte buffers across the host boundary.

    use std::ptr;

    /// Allocates `len` zeroed bytes for the host to write into. Returns null when
    /// `len` exceeds [`MAX_INPUT`](super::MAX_INPUT), so a hostile length can't trap.
    #[no_mangle]
    pub extern "C" fn kzp_alloc(len: usize) -> *mut u8 {
        if len > super::MAX_INPUT {
            return ptr::null_mut();
        }
        Box::into_raw(vec![0u8; len].into_boxed_slice()).cast::<u8>()
    }

    /// Frees a buffer from `kzp_alloc` or a response.
    ///
    /// # Safety
    ///
    /// `ptr` must come from `kzp_alloc(len)`, or be a response pointer with its length,
    /// and must not be freed twice. A null `ptr` is ignored.
    #[no_mangle]
    pub unsafe extern "C" fn kzp_free(ptr: *mut u8, len: usize) {
        if !ptr.is_null() {
            // SAFETY: the caller guarantees `ptr`/`len` describe a live boxed slice we
            // handed out, so rebuilding and dropping the box frees it exactly once.
            let mut buf = unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, len)) };
            // Requests may carry key seeds: never leave them in freed memory.
            for b in &mut *buf {
                // SAFETY: `b` is a valid, aligned `&mut u8` into the live buffer.
                unsafe { ptr::write_volatile(b, 0) };
            }
            drop(buf);
        }
    }

    /// # Safety
    ///
    /// `ptr` must point to `len` readable bytes; with `len` 0 any pointer is fine.
    unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
        if len == 0 || ptr.is_null() {
            &[]
        } else {
            // SAFETY: guaranteed by the caller.
            unsafe { std::slice::from_raw_parts(ptr, len) }
        }
    }

    /// Hands the response to the host by writing `[ptr, len]` into `ret`.
    ///
    /// # Safety
    ///
    /// `ret` must be valid for writing two `usize`s; null drops the response.
    unsafe fn output(bytes: Vec<u8>, ret: *mut usize) {
        if ret.is_null() {
            return;
        }
        let boxed = bytes.into_boxed_slice();
        let len = boxed.len();
        let out = Box::into_raw(boxed).cast::<u8>();
        // SAFETY: guaranteed by the caller; unaligned writes tolerate any host layout.
        unsafe {
            // The host sees pointers as integers; expose so the address stays valid.
            ret.write_unaligned(out.expose_provenance());
            ret.add(1).write_unaligned(len);
        }
    }

    #[cfg(any(feature = "verify", feature = "sign"))]
    macro_rules! export {
        ($($name:ident => $f:path),* $(,)?) => {$(
            /// See the module docs for the calling protocol.
            ///
            /// # Safety
            ///
            /// `ptr` must point to `len` readable bytes and `ret` to two writable `usize`s.
            #[no_mangle]
            pub unsafe extern "C" fn $name(ptr: *const u8, len: usize, ret: *mut usize) {
                // SAFETY: forwarded from the caller.
                unsafe { output($f(input(ptr, len)), ret) }
            }
        )*};
    }

    #[cfg(feature = "verify")]
    export! {
        kzp_verify_offer => super::verify_offer_json,
        kzp_verify => super::verify_json,
        kzp_signature_agent => super::signature_agent_json,
        kzp_verify_agent => super::verify_agent_json,
    }

    #[cfg(feature = "sign")]
    export! {
        kzp_sign_request => super::sign_request_json,
        kzp_directory => super::directory_json,
    }

    #[cfg(feature = "issue")]
    export! {
        kzp_jwk => super::jwk_json,
        kzp_issue_offer => super::issue_offer_json,
        kzp_issue_mandate => super::issue_mandate_json,
        kzp_present => super::present_json,
    }

    #[cfg(test)]
    #[allow(clippy::indexing_slicing, clippy::unwrap_used)]
    mod tests {
        //! Drives the exports exactly as a host does. Under Miri these prove the
        //! boundary code has no leak, double free or out-of-bounds access.

        use super::{kzp_alloc, kzp_free};

        type Export = unsafe extern "C" fn(*const u8, usize, *mut usize);

        /// Returns the response bytes after freeing every buffer involved.
        pub(crate) fn call(f: Export, req: &[u8]) -> Vec<u8> {
            let p = kzp_alloc(req.len());
            let mut ret = [0usize; 2];
            // SAFETY: `p` has `req.len()` writable bytes; `ret` holds two usizes; every
            // pointer is freed once with the length it came with.
            unsafe {
                std::ptr::copy_nonoverlapping(req.as_ptr(), p, req.len());
                f(p, req.len(), ret.as_mut_ptr());
                kzp_free(p, req.len());
                let resp = std::ptr::with_exposed_provenance_mut::<u8>(ret[0]);
                let out = std::slice::from_raw_parts(resp, ret[1]).to_vec();
                kzp_free(resp, ret[1]);
                out
            }
        }

        #[test]
        fn alloc_free_pairs() {
            for len in [0, 1, 7, 4096] {
                let p = kzp_alloc(len);
                assert!(!p.is_null());
                // SAFETY: freeing what we allocated, once.
                unsafe { kzp_free(p, len) };
            }
            // SAFETY: null is documented as ignored.
            unsafe { kzp_free(std::ptr::null_mut(), 0) };
            assert!(kzp_alloc(usize::MAX).is_null());
            assert!(kzp_alloc(super::super::MAX_INPUT + 1).is_null());
        }

        #[cfg(feature = "verify")]
        #[test]
        fn responses_round_trip() {
            use super::{kzp_verify, kzp_verify_offer};
            assert!(call(kzp_verify_offer, b"{}").starts_with(br#"{"error":"#));
            assert!(call(kzp_verify, b"not json").starts_with(br#"{"error":"#));
            assert!(call(kzp_verify, b"").starts_with(br#"{"error":"#));
        }

        #[cfg(feature = "sign")]
        #[test]
        fn null_ret_drops_the_response() {
            // SAFETY: null input with len 0 and null ret are both documented as fine.
            unsafe { super::kzp_directory(std::ptr::null(), 0, std::ptr::null_mut()) };
        }

        /// The two exports a signing-only host uses, across the boundary, with a seed in
        /// the request: the response is right and `kzp_free` has zeroed the seed.
        #[cfg(feature = "sign")]
        #[test]
        fn sign_and_directory_cross_the_boundary() {
            use super::{kzp_directory, kzp_sign_request};
            let seed = crate::jws::b64(&[5u8; 32]);
            let dir = call(
                kzp_directory,
                format!(r#"{{"seeds":["{seed}"]}}"#).as_bytes(),
            );
            let dir: serde_json::Value = serde_json::from_slice(&dir).unwrap();
            let kid = dir["ok"]["keys"][0]["kid"].as_str().unwrap().to_owned();

            let req = format!(
                r#"{{"message":{{"method":"GET","scheme":"https","authority":"a.example","path":"/","headers":[]}},
                "label":"sig","agent_url":"https://agent.example","created":1,"expires":2,
                "tag":"agent-payer-auth","components":["@authority"],"seed":"{seed}"}}"#
            );
            let out = call(kzp_sign_request, req.as_bytes());
            let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let input = out["ok"]["headers"][1][1].as_str().unwrap();
            assert!(input.contains(&format!(r#"keyid="{kid}""#)), "{input}");
            assert!(input.contains(r#"tag="agent-payer-auth""#), "{input}");
            assert!(input.starts_with(r#"sig=("@authority" "signature-agent";key="sig")"#));
        }
    }
}

#[cfg(all(test, feature = "verify"))]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::{verify_json, MAX_INPUT};

    #[test]
    fn errors_are_json_with_codes() {
        let out = verify_json(b"{");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap_or_default();
        assert_eq!(v["error"]["code"], "malformed");
        let big = vec![b' '; MAX_INPUT + 1];
        let v: serde_json::Value = serde_json::from_slice(&verify_json(&big)).unwrap_or_default();
        assert_eq!(v["error"]["message"], "malformed: request too large");
    }
}
