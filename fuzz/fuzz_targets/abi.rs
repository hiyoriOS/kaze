//! Arbitrary bytes into both JSON entry points: must never panic, and every response
//! must be JSON with either `ok` or a known error `code`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    for out in [kaze::abi::verify_json(data), kaze::abi::verify_offer_json(data)] {
        let v: Value = serde_json::from_slice(&out).expect("response is JSON");
        assert!(v.get("ok").is_some() || v["error"]["code"].is_string(), "{v}");
    }
});
