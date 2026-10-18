//! JSON-in, JSON-out entry points for hosts that load `kaze.wasm`.
//!
//! The safe functions here are plain Rust and run on every target. The `extern "C"`
//! exports exist only on `wasm32` (and in this crate's own tests). The protocol for a
//! host is:
//!
//! 1. `ptr = kaze_alloc(len)`, then copy the request JSON into `[ptr, ptr + len)`.
//! 2. `kaze_verify(ptr, len, ret)` (or `kaze_verify_offer`), where `ret` points to two
//!    writable `usize`s (8 bytes on wasm32). `ptr` is left untouched.
//! 3. The response is `ret[1]` bytes at `ret[0]`.
//! 4. `kaze_free(ptr, len)` and `kaze_free(ret[0], ret[1])`. Each pointer is freed
//!    exactly once, with the length it came with.
//!
//! The response is `{"ok": ...}` or `{"error": {"code": ..., "message": ...}}`.

use serde::{Deserialize, Serialize};

use crate::{json, verify, verify_offer, Context, Error, Jwk, Trust};

/// Requests larger than this are refused before parsing.
pub const MAX_INPUT: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferRequest {
    offer: String,
    jwks: Vec<Jwk>,
    iss: String,
    now: i64,
}

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

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Response<T> {
    Ok(T),
    Error { code: &'static str, message: String },
}

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

fn request<T: for<'de> Deserialize<'de>>(input: &[u8]) -> Result<T, Error> {
    if input.len() > MAX_INPUT {
        return Err(Error::Malformed("request too large"));
    }
    serde_json::from_value(json::parse(input)?).map_err(|_| Error::Malformed("request"))
}

/// `{"offer","jwks","iss","now"}` to `{"ok": Offer}`.
#[must_use]
pub fn verify_offer_json(input: &[u8]) -> Vec<u8> {
    respond(
        request::<OfferRequest>(input)
            .and_then(|r| verify_offer(&r.offer, &r.jwks, &r.iss, r.now))
            .map(crate::offer::Verified::into_inner),
    )
}

/// `{"offer","jwks","iss","now","operator","presentation","trust"}` to `{"ok": Grant}`.
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

#[cfg(any(target_arch = "wasm32", test))]
#[allow(unsafe_code, unreachable_pub)] // exported to the host, not to Rust
mod exports {
    //! The only `unsafe` in the crate: moving byte buffers across the host boundary.

    use std::ptr;

    /// Allocates `len` zeroed bytes for the host to write into. Returns null when
    /// `len` exceeds [`MAX_INPUT`](super::MAX_INPUT), so a hostile length can't trap.
    #[no_mangle]
    pub extern "C" fn kaze_alloc(len: usize) -> *mut u8 {
        if len > super::MAX_INPUT {
            return ptr::null_mut();
        }
        Box::into_raw(vec![0u8; len].into_boxed_slice()).cast::<u8>()
    }

    /// Frees a buffer from `kaze_alloc` or a response.
    ///
    /// # Safety
    ///
    /// `ptr` must come from `kaze_alloc(len)`, or be a response pointer with its length,
    /// and must not be freed twice. A null `ptr` is ignored.
    #[no_mangle]
    pub unsafe extern "C" fn kaze_free(ptr: *mut u8, len: usize) {
        if !ptr.is_null() {
            // SAFETY: the caller guarantees `ptr`/`len` describe a live boxed slice we
            // handed out, so rebuilding and dropping the box frees it exactly once.
            drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, len)) });
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

    /// Verifies an offer; see the module docs.
    ///
    /// # Safety
    ///
    /// `ptr` must point to `len` readable bytes and `ret` to two writable `usize`s.
    #[no_mangle]
    pub unsafe extern "C" fn kaze_verify_offer(ptr: *const u8, len: usize, ret: *mut usize) {
        // SAFETY: forwarded from the caller.
        unsafe { output(super::verify_offer_json(input(ptr, len)), ret) }
    }

    /// Verifies a presentation; see the module docs.
    ///
    /// # Safety
    ///
    /// `ptr` must point to `len` readable bytes and `ret` to two writable `usize`s.
    #[no_mangle]
    pub unsafe extern "C" fn kaze_verify(ptr: *const u8, len: usize, ret: *mut usize) {
        // SAFETY: forwarded from the caller.
        unsafe { output(super::verify_json(input(ptr, len)), ret) }
    }

    #[cfg(test)]
    #[allow(clippy::indexing_slicing)]
    mod tests {
        //! Drives the exports exactly as a host does. Under Miri these prove the
        //! boundary code has no leak, double free or out-of-bounds access.

        use super::{kaze_alloc, kaze_free, kaze_verify, kaze_verify_offer};

        type Export = unsafe extern "C" fn(*const u8, usize, *mut usize);

        /// Returns the response bytes after freeing every buffer involved.
        pub(crate) fn call(f: Export, req: &[u8]) -> Vec<u8> {
            let p = kaze_alloc(req.len());
            let mut ret = [0usize; 2];
            // SAFETY: `p` has `req.len()` writable bytes; `ret` holds two usizes; every
            // pointer is freed once with the length it came with.
            unsafe {
                std::ptr::copy_nonoverlapping(req.as_ptr(), p, req.len());
                f(p, req.len(), ret.as_mut_ptr());
                kaze_free(p, req.len());
                let resp = std::ptr::with_exposed_provenance_mut::<u8>(ret[0]);
                let out = std::slice::from_raw_parts(resp, ret[1]).to_vec();
                kaze_free(resp, ret[1]);
                out
            }
        }

        #[test]
        fn alloc_free_pairs() {
            for len in [0, 1, 7, 4096] {
                let p = kaze_alloc(len);
                assert!(!p.is_null());
                // SAFETY: freeing what we allocated, once.
                unsafe { kaze_free(p, len) };
            }
            // SAFETY: null is documented as ignored.
            unsafe { kaze_free(std::ptr::null_mut(), 0) };
            assert!(kaze_alloc(usize::MAX).is_null());
            assert!(kaze_alloc(super::super::MAX_INPUT + 1).is_null());
        }

        #[test]
        fn responses_round_trip() {
            assert!(call(kaze_verify_offer, b"{}").starts_with(br#"{"error":"#));
            assert!(call(kaze_verify, b"not json").starts_with(br#"{"error":"#));
            assert!(call(kaze_verify, b"").starts_with(br#"{"error":"#));
        }

        #[test]
        fn null_ret_drops_the_response() {
            // SAFETY: null input with len 0 and null ret are both documented as fine.
            unsafe { kaze_verify(std::ptr::null(), 0, std::ptr::null_mut()) };
        }
    }
}

#[cfg(test)]
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
