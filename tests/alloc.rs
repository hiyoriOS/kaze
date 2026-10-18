//! Deterministic memory checks: a counting global allocator proves every verification
//! path returns all memory it takes (no leaks), and pins how many allocations each
//! path makes so a regression shows up as a number, not a timing.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools,
    clippy::struct_excessive_bools,
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::needless_pass_by_value,
    clippy::map_unwrap_or,
    clippy::semicolon_if_nothing_returned,
    clippy::doc_markdown,
    missing_docs,
    unsafe_code,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;

use serde_json::{json, Value};

struct Counting;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
// Tests in one binary share the allocator; measure one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

// SAFETY: forwards to `System` and only adds relaxed counters.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        let live = LIVE.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(live, Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        if n >= l.size() {
            let live = LIVE.fetch_add(n - l.size(), Relaxed) + (n - l.size());
            PEAK.fetch_max(live, Relaxed);
        } else {
            LIVE.fetch_sub(l.size() - n, Relaxed);
        }
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn requests() -> Vec<(String, Vec<u8>)> {
    let file: Value = serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
    file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c.get("presentation").is_some())
        .map(|c| {
            let req = json!({
                "offer": c["offer"], "jwks": file["platform_jwks"], "iss": file["platform"], "now": c["now"],
                "operator": c["operator"], "presentation": c["presentation"], "trust": file["trust"],
            });
            (c["name"].as_str().unwrap().to_owned(), serde_json::to_vec(&req).unwrap())
        })
        .collect()
}

/// (allocations, peak bytes above baseline, bytes still live afterwards) for one call.
fn measure(req: &[u8]) -> (usize, usize, isize) {
    let base = LIVE.load(Relaxed);
    ALLOCS.store(0, Relaxed);
    PEAK.store(base, Relaxed);
    let out = kzp::abi::verify_json(req);
    drop(out);
    let after = LIVE.load(Relaxed);
    (
        ALLOCS.load(Relaxed),
        PEAK.load(Relaxed) - base,
        after as isize - base as isize,
    )
}

#[test]
fn every_vector_returns_all_memory() {
    let _g = SERIAL.lock().unwrap();
    let reqs = requests();
    for (name, req) in &reqs {
        // Warm once so lazy statics (if any) are not counted as a leak.
        let _ = kzp::abi::verify_json(req);
        let first = measure(req);
        for _ in 0..50 {
            let again = measure(req);
            assert_eq!(again.2, 0, "{name} leaked {} bytes", again.2);
            assert_eq!(
                again.0, first.0,
                "{name}: allocation count is not deterministic"
            );
        }
        assert_eq!(first.2, 0, "{name} leaked {} bytes", first.2);
    }
}

#[test]
fn allocation_budget() {
    let _g = SERIAL.lock().unwrap();
    let mut worst = (String::new(), 0, 0);
    let mut report = Vec::new();
    for (name, req) in requests() {
        let _ = kzp::abi::verify_json(&req);
        let (allocs, peak, _) = measure(&req);
        report.push(format!("{name:24} allocs {allocs:4}  peak {peak:6} B"));
        if allocs > worst.1 {
            worst = (name, allocs, peak);
        }
    }
    if std::env::var_os("KAZE_ALLOC_REPORT").is_some() {
        eprintln!("{}", report.join("\n"));
    }
    // Measured 2026-10-18: worst case ~330 allocations and ~18 KB peak, most of it the
    // request JSON. The budget fails the build if a change makes the hot path heavier.
    assert!(
        worst.1 <= 400,
        "worst case {} allocates {} times",
        worst.0,
        worst.1
    );
    assert!(
        worst.2 <= 32 * 1024,
        "worst case {} peaks at {} bytes",
        worst.0,
        worst.2
    );
}

#[test]
fn agent_vectors_return_all_memory() {
    let _g = SERIAL.lock().unwrap();
    let file: Value = serde_json::from_str(include_str!("../vectors/agent.json")).unwrap();
    for c in file["cases"].as_array().unwrap() {
        let req = serde_json::to_vec(
            &json!({"message": c["message"], "directory": c["directory"],
            "directory_url": c["directory_url"], "now": c["now"]}),
        )
        .unwrap();
        let _ = kzp::abi::verify_agent_json(&req);
        for _ in 0..20 {
            let base = LIVE.load(Relaxed);
            drop(kzp::abi::verify_agent_json(&req));
            let after = LIVE.load(Relaxed);
            assert_eq!(
                after,
                base,
                "{} leaked {} bytes",
                c["name"],
                after as isize - base as isize
            );
        }
    }
}
