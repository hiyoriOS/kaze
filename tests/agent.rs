//! Runs every case in `vectors/agent.json` through `verify_agent`.

#![allow(missing_docs, clippy::unwrap_used, clippy::indexing_slicing)]

use kzp::agent::{verify_agent_with_tag, TAG};
use kzp::{Jwk, Message};
use serde_json::Value;

#[test]
fn agent_vectors() {
    let file: Value = serde_json::from_str(include_str!("../vectors/agent.json")).unwrap();
    let mut failed = Vec::new();
    let cases = file["cases"].as_array().unwrap();
    for c in cases {
        let m: Message = serde_json::from_value(c["message"].clone()).unwrap();
        let d: Vec<Jwk> = serde_json::from_value(c["directory"].clone()).unwrap();
        let got = verify_agent_with_tag(
            &m,
            &d,
            c["directory_url"].as_str().unwrap(),
            c["now"].as_i64().unwrap(),
            c.get("tag").map_or(TAG, |t| t.as_str().unwrap()),
        );
        let ok = match (&got, c["expect"].get("ok"), c["expect"].get("error")) {
            (Ok(a), Some(w), _) => a.operator == w["operator"] && a.label == w["label"],
            (Err(e), _, Some(code)) => e.code() == code,
            _ => false,
        };
        if !ok {
            failed.push(format!(
                "{}: {:?}",
                c["name"],
                got.map(|a| a.operator).map_err(|e| e.code())
            ));
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} failed: {failed:#?}",
        failed.len(),
        cases.len()
    );
}
