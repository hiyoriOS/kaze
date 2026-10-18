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
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

//! Runs every case in `vectors/v1.json` through the verifier.

use kaze::{verify, verify_offer, Context, Jwk, Money, Trust};
use serde_json::Value;

#[test]
fn vectors() {
    let file: Value = serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
    let jwks: Vec<Jwk> = serde_json::from_value(file["platform_jwks"].clone()).unwrap();
    let trust: Trust = serde_json::from_value(file["trust"].clone()).unwrap();
    let platform = file["platform"].as_str().unwrap();

    let mut failed = Vec::new();
    let cases = file["cases"].as_array().unwrap();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let now = c["now"].as_i64().unwrap();
        let expect = &c["expect"];

        let got =
            verify_offer(c["offer"].as_str().unwrap(), &jwks, platform, now).and_then(|offer| {
                match c["presentation"].as_str() {
                    None => Ok(None),
                    Some(p) => {
                        let ctx = Context {
                            now,
                            operator: c["operator"].as_str().unwrap(),
                            offer: &offer,
                        };
                        verify(p, &ctx, &trust).map(Some)
                    }
                }
            });

        let ok = match (got, expect.get("ok"), expect.get("error")) {
            (Ok(Some(g)), Some(want), _) => {
                let amount: Option<Money> = serde_json::from_value(want["amount"].clone()).unwrap();
                g.act == want["act"]
                    && g.amount == amount
                    && g.jti == want["jti"]
                    && g.principal == want["principal"]
            }
            (Ok(None), None, None) => true,
            (Err(e), _, Some(code)) => e.code() == code,
            _ => false,
        };
        if !ok {
            failed.push(name.to_string());
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} vectors failed: {failed:?}",
        failed.len(),
        cases.len()
    );
}
