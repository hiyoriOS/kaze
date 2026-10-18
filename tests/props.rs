//! Property tests over the valid vectors.
//!
//! - Integrity: any change to a valid presentation (one byte, a truncation, an inserted
//!   `~` or `.`) is rejected. Nothing outside the signed and hashed bytes is
//!   load-bearing.
//! - Robustness: arbitrary strings never panic.

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

use kzp::{verify, verify_offer, Context, Jwk, Trust, Verified};
use proptest::prelude::*;
use serde_json::Value;

struct Fixture {
    offer: Verified,
    trust: Trust,
    now: i64,
    valid: Vec<String>,
}

fn fixture() -> Fixture {
    let file: Value = serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
    let jwks: Vec<Jwk> = serde_json::from_value(file["platform_jwks"].clone()).unwrap();
    let cases = file["cases"].as_array().unwrap();
    let ok = cases.iter().find(|c| c["name"] == "ok_order").unwrap();
    let now = ok["now"].as_i64().unwrap();
    let offer = verify_offer(
        ok["offer"].as_str().unwrap(),
        &jwks,
        file["platform"].as_str().unwrap(),
        now,
    )
    .unwrap();
    let valid = cases
        .iter()
        .filter(|c| c["expect"].get("ok").is_some() && c.get("presentation").is_some())
        .map(|c| c["presentation"].as_str().unwrap().to_owned())
        .collect();
    Fixture {
        offer,
        trust: serde_json::from_value(file["trust"].clone()).unwrap(),
        now,
        valid,
    }
}

fn check(f: &Fixture, p: &str) -> bool {
    let ctx = Context {
        now: f.now,
        operator: "https://agent.example",
        offer: &f.offer,
    };
    verify(p, &ctx, &f.trust).is_ok()
}

#[derive(Debug, Clone)]
enum Edit {
    Byte(usize, u8),
    Truncate(usize),
    Insert(usize, char),
    Delete(usize),
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Edit::Byte(i, b)),
        any::<usize>().prop_map(Edit::Truncate),
        (
            any::<usize>(),
            prop::sample::select(vec!['~', '.', 'A', '_', '-', '='])
        )
            .prop_map(|(i, c)| Edit::Insert(i, c)),
        any::<usize>().prop_map(Edit::Delete),
    ]
}

fn apply(p: &str, e: &Edit) -> String {
    let mut b = p.as_bytes().to_vec();
    match *e {
        Edit::Byte(i, v) => {
            let i = i % b.len();
            b[i] = v;
        }
        Edit::Truncate(i) => b.truncate(i % b.len()),
        Edit::Insert(i, c) => b.insert(i % (b.len() + 1), c as u8),
        Edit::Delete(i) => {
            b.remove(i % b.len());
        }
    }
    String::from_utf8_lossy(&b).into_owned()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    #[test]
    fn any_change_to_a_valid_presentation_is_rejected(which in any::<usize>(), e in edit()) {
        let f = fixture();
        let p = &f.valid[which % f.valid.len()];
        prop_assume!(check(&f, p));
        let q = apply(p, &e);
        prop_assume!(&q != p);
        prop_assert!(!check(&f, &q), "accepted a modified presentation: {e:?}");
    }

    #[test]
    fn arbitrary_input_never_panics(s in ".{0,512}") {
        let f = fixture();
        let _ = check(&f, &s);
        let _ = kzp::abi::verify_json(s.as_bytes());
        let _ = kzp::abi::verify_offer_json(s.as_bytes());
    }
}

mod agent {
    //! Integrity of Web Bot Auth: any change to a signed header or a covered
    //! component of a valid request is rejected.

    use kzp::{verify_agent, Jwk, Message};
    use proptest::prelude::*;
    use serde_json::Value;

    fn ok_case() -> (Message, Vec<Jwk>, String, i64) {
        let file: Value = serde_json::from_str(include_str!("../vectors/agent.json")).unwrap();
        let c = file["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "ok_agent")
            .unwrap()
            .clone();
        (
            serde_json::from_value(c["message"].clone()).unwrap(),
            serde_json::from_value(c["directory"].clone()).unwrap(),
            c["directory_url"].as_str().unwrap().to_owned(),
            c["now"].as_i64().unwrap(),
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

        #[test]
        fn any_change_to_a_signed_request_is_rejected(field in 0usize..6, at in any::<usize>(), byte in any::<u8>()) {
            let (mut m, d, u, now) = ok_case();
            prop_assume!(verify_agent(&m, &d, &u, now).is_ok());
            let target: &mut String = match field {
                0 => &mut m.method,
                1 => &mut m.authority,
                2 => &mut m.path,
                f => &mut m.headers[f - 3 + 1].1, // Signature-Agent, Signature-Input, Signature
            };
            let mut b = target.as_bytes().to_vec();
            let i = at % b.len();
            prop_assume!(b[i] != byte);
            b[i] = byte;
            let Ok(changed) = String::from_utf8(b) else { return Ok(()) };
            // Changing only the letter case of @authority is a no-op by design.
            prop_assume!(!(field == 1 && changed.eq_ignore_ascii_case(target)));
            *target = changed;
            prop_assert!(verify_agent(&m, &d, &u, now).is_err());
        }

        #[test]
        fn arbitrary_headers_never_panic(a in ".{0,200}", b in ".{0,200}", c in ".{0,200}") {
            let (mut m, d, u, now) = ok_case();
            m.headers = vec![("Signature-Agent".into(), a), ("Signature-Input".into(), b), ("Signature".into(), c)];
            let _ = verify_agent(&m, &d, &u, now);
            let _ = kzp::signature_agent(&m);
        }
    }
}
