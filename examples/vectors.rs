//! Regenerates `vectors/v1.json`. Every key comes from a fixed seed and Ed25519 is
//! deterministic, so the output is byte-for-byte reproducible.
//!
//!     cargo run --example vectors --features issue > vectors/v1.json

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
    clippy::expect_used,
    clippy::indexing_slicing
)]

use ed25519_dalek::SigningKey;
use kaze::issue;
use kaze::offer::{Checkout, LiabNeed, MandateNeed, Quota};
use kaze::{jws, Attestation, Binding, Jwk, Money, Offer, Term};
use serde_json::{json, Value};

const NOW: i64 = 1_792_300_000; // 2026-10-18T05:06:40Z
const SHOP: &str = "https://shop.example";
const OPERATOR: &str = "https://agent.example";
const PROVIDER: &str = "https://recourse.example";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn usd(value: u64) -> Money {
    Money {
        value,
        currency: "USD".into(),
    }
}

struct Keys {
    platform: SigningKey,
    issuer: SigningKey,
    agent: SigningKey,
    provider: SigningKey,
    rogue: SigningKey,
}

fn base_offer() -> Offer {
    Offer {
        iss: SHOP.into(),
        iat: NOW - 10,
        exp: NOW + 290,
        nonce: jws::b64(&[7u8; 16]),
        resource: format!("{SHOP}/orders"),
        terms: vec![
            Term {
                act: "order:create".into(),
                id: Some("signed".into()),
                mandate: Some(MandateNeed { hp: false }),
                liab: Some(LiabNeed {
                    cover: usd(50_000),
                    providers: vec![PROVIDER.into()],
                }),
                amount: Some(usd(1850)),
                price: Some(json!({
                    "x402": {"scheme": "exact", "network": "eip155:8453", "amount": "10000",
                             "asset": "USDC", "payTo": "0x0000000000000000000000000000000000000402"}
                })),
                quota: Some(Quota {
                    window: 3600,
                    max: 20,
                }),
                path: Some(format!("{SHOP}/mcp")),
                checkout: Some(Checkout::Platform),
            },
            Term {
                act: "menu:read".into(),
                id: Some("signed".into()),
                mandate: Some(MandateNeed { hp: false }),
                liab: None,
                amount: None,
                price: None,
                quota: Some(Quota {
                    window: 60,
                    max: 600,
                }),
                path: Some(format!("{SHOP}/mcp")),
                checkout: None,
            },
            Term {
                act: "account:trade".into(),
                id: Some("signed".into()),
                mandate: Some(MandateNeed { hp: true }),
                liab: Some(LiabNeed {
                    cover: usd(50_000),
                    providers: vec![PROVIDER.into()],
                }),
                amount: Some(usd(40_000)),
                price: None,
                quota: None,
                path: None,
                checkout: None,
            },
        ],
    }
}

fn base_acts() -> Value {
    json!([
        {"act": "order:*", "on": [SHOP, "https://cafe.example"], "max": {"value": 2500, "currency": "USD"}},
        {"act": "menu:read", "on": ["*"]},
        {"act": "account:trade", "on": [SHOP], "max": {"value": 100000, "currency": "USD"}}
    ])
}

fn att(iss: &str, by: &SigningKey, sub: &str, cover: u64, exp: i64) -> String {
    let a = Attestation {
        iss: iss.into(),
        sub: sub.into(),
        cover: usd(cover),
        iat: NOW - 86_400,
        exp,
    };
    issue::attestation(&a, "provider-1", by)
}

/// Knobs the cases turn; `Default` is the valid base presentation.
struct M {
    issuer_kid: &'static str,
    issuer_key: Option<u8>, // seed override
    iat: i64,
    exp: i64,
    vct: &'static str,
    acts: Value,
    liab: Option<Value>,
    disclose_email: bool,
    tamper_act: bool,
    tamper_payload: bool,
    alg: &'static str,
    kb_key: Option<u8>,
    kb: Binding,
    hash_email: bool,
}

fn base_binding() -> Binding {
    Binding {
        op: OPERATOR.into(),
        iat: NOW - 5,
        aud: SHOP.into(),
        nonce: jws::b64(&[7u8; 16]),
        sd_hash: String::new(),
        act: "order:create".into(),
        amt: Some(usd(1850)),
    }
}

fn base_m(k: &Keys) -> M {
    M {
        issuer_kid: "issuer-1",
        issuer_key: None,
        iat: NOW - 3600,
        exp: NOW + 7 * 86_400,
        vct: "kaze.mandate.1",
        acts: base_acts(),
        liab: Some(
            json!({"op": OPERATOR, "att": att(PROVIDER, &k.provider, OPERATOR, 100_000, NOW + 30 * 86_400)}),
        ),
        disclose_email: false,
        tamper_act: false,
        tamper_payload: false,
        alg: "EdDSA",
        kb_key: None,
        kb: base_binding(),
        hash_email: false,
    }
}

fn build(k: &Keys, m: M) -> String {
    let d_act = issue::disclosure("c2FsdC1hY3Q", "act", &m.acts);
    let d_email = issue::disclosure("c2FsdC1lbWFpbA", "email", &json!("payer@example.test"));
    let mut plain = json!({
        "iss": "https://ryo.example/authority",
        "sub": "payer_7f3a",
        "iat": m.iat,
        "exp": m.exp,
        "jti": "mdt_01",
        "vct": m.vct,
        "cnf": {"jwk": Jwk::new(&k.agent.verifying_key(), None)},
    });
    if let Some(l) = &m.liab {
        plain["liab"] = l.clone();
    }
    let issuer_key = m.issuer_key.map(key).unwrap_or_else(|| k.issuer.clone());
    let all = vec![d_act.clone(), d_email.clone()];
    let mut issuer = if m.alg == "EdDSA" {
        issue::mandate(plain, &all, m.issuer_kid, &issuer_key)
    } else {
        // header claims a different alg over a real EdDSA signature
        let signed = issue::mandate(plain, &all, m.issuer_kid, &issuer_key);
        let (_, rest) = signed.split_once('.').unwrap();
        let h = json!({"alg": m.alg, "typ": "kaze-mandate+sd-jwt", "kid": m.issuer_kid});
        format!("{}.{rest}", jws::b64(&serde_json::to_vec(&h).unwrap()))
    };
    if m.tamper_payload {
        // re-encode the payload with a longer expiry, keep the old signature
        let parts: Vec<&str> = issuer.split('.').collect();
        let mut p: Value = serde_json::from_slice(&jws::unb64(parts[1]).unwrap()).unwrap();
        p["exp"] = json!(m.exp + 365 * 86_400);
        issuer = format!(
            "{}.{}.{}",
            parts[0],
            jws::b64(&serde_json::to_vec(&p).unwrap()),
            parts[2]
        );
    }
    let shown_act = if m.tamper_act {
        let mut a = m.acts.clone();
        a[0]["max"]["value"] = json!(250_000);
        issue::disclosure("c2FsdC1hY3Q", "act", &a)
    } else {
        d_act
    };
    let mut shown = vec![shown_act];
    if m.disclose_email {
        shown.push(d_email.clone());
    }
    let prefix = issue::prefix(&issuer, &shown);
    let agent = m.kb_key.map(key).unwrap_or_else(|| k.agent.clone());
    if m.hash_email {
        // key binding computed over a different disclosure set than the one presented
        let other = issue::prefix(&issuer, &[shown[0].clone(), d_email]);
        let full = issue::present(&other, m.kb, &agent);
        let kb = &full[other.len()..];
        return format!("{prefix}{kb}");
    }
    issue::present(&prefix, m.kb, &agent)
}

/// Signs a hand-written header and payload, byte for byte.
fn raw(header: &str, payload: &str, key: &SigningKey) -> String {
    use ed25519_dalek::Signer;
    let input = format!(
        "{}.{}",
        jws::b64(header.as_bytes()),
        jws::b64(payload.as_bytes())
    );
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", jws::b64(&sig.to_bytes()))
}

fn case(
    name: &str,
    why: &str,
    now: i64,
    operator: &str,
    offer: &str,
    pres: Option<String>,
    expect: Value,
) -> Value {
    let mut c = json!({"name": name, "why": why, "now": now, "operator": operator, "offer": offer, "expect": expect});
    match pres {
        Some(p) => c["presentation"] = json!(p),
        None => c["kind"] = json!("offer"),
    }
    c
}

fn ok(act: &str, amt: Option<Money>) -> Value {
    json!({"ok": {"act": act, "amount": amt, "jti": "mdt_01", "principal": "payer_7f3a"}})
}

fn err(code: &str) -> Value {
    json!({"error": code})
}

fn main() {
    let k = Keys {
        platform: key(1),
        issuer: key(2),
        agent: key(3),
        provider: key(4),
        rogue: key(9),
    };
    let offer = issue::offer(&base_offer(), "platform-1", &k.platform);
    let jwk = |s: &SigningKey, kid: &str| Jwk::new(&s.verifying_key(), Some(kid));
    let mut cases = Vec::new();
    let mut add = |name: &str, why: &str, m: M| {
        cases.push(case(
            name,
            why,
            NOW,
            OPERATOR,
            &offer,
            Some(build(&k, m)),
            Value::Null,
        ));
    };

    // ---- valid
    add(
        "ok_order",
        "valid order within limit, liability covered",
        base_m(&k),
    );
    add(
        "ok_read",
        "read action, no amount, no liability needed",
        M {
            kb: Binding {
                act: "menu:read".into(),
                amt: None,
                ..base_binding()
            },
            ..base_m(&k)
        },
    );
    add(
        "ok_email",
        "an extra disclosed claim is accepted",
        M {
            disclose_email: true,
            ..base_m(&k)
        },
    );
    add(
        "ok_hp_trade",
        "human-present term met by a 5-minute hp mandate",
        M {
            iat: NOW - 60,
            exp: NOW + 240,
            acts: json!([{"act": "account:trade", "on": [SHOP], "max": {"value": 100000, "currency": "USD"}, "hp": true}]),
            kb: Binding {
                act: "account:trade".into(),
                amt: Some(usd(40_000)),
                ..base_binding()
            },
            ..base_m(&k)
        },
    );

    // ---- issuer and disclosure
    add(
        "unknown_key",
        "mandate signed under an untrusted kid",
        M {
            issuer_kid: "rogue-1",
            issuer_key: Some(9),
            ..base_m(&k)
        },
    );
    add(
        "issuer_signature",
        "payload changed after signing",
        M {
            tamper_payload: true,
            ..base_m(&k)
        },
    );
    add(
        "alg_none",
        "header claims alg none",
        M {
            alg: "none",
            ..base_m(&k)
        },
    );
    add(
        "disclosure",
        "act disclosure altered to raise the limit",
        M {
            tamper_act: true,
            ..base_m(&k)
        },
    );
    add(
        "vct",
        "wrong credential type",
        M {
            vct: "ap2.mandate.payment.1",
            ..base_m(&k)
        },
    );
    add(
        "mandate_expired",
        "mandate expired one second ago",
        M {
            exp: NOW - 1,
            ..base_m(&k)
        },
    );

    // ---- key binding
    add(
        "kb_signature",
        "key binding signed by a key other than cnf",
        M {
            kb_key: Some(9),
            ..base_m(&k)
        },
    );
    add(
        "audience",
        "key binding addressed to another platform",
        M {
            kb: Binding {
                aud: "https://other.example".into(),
                ..base_binding()
            },
            ..base_m(&k)
        },
    );
    add(
        "nonce",
        "replay against a different offer",
        M {
            kb: Binding {
                nonce: jws::b64(&[8u8; 16]),
                ..base_binding()
            },
            ..base_m(&k)
        },
    );
    add(
        "kb_stale",
        "key binding an hour old",
        M {
            kb: Binding {
                iat: NOW - 3600,
                ..base_binding()
            },
            ..base_m(&k)
        },
    );
    add(
        "sd_hash",
        "key binding covers a different disclosure set",
        M {
            hash_email: true,
            ..base_m(&k)
        },
    );

    // ---- action
    add(
        "not_offered",
        "action the platform did not offer",
        M {
            kb: Binding {
                act: "account:close".into(),
                amt: None,
                ..base_binding()
            },
            ..base_m(&k)
        },
    );
    add(
        "scope",
        "mandate covers orders only at another platform",
        M {
            acts: json!([{"act": "order:*", "on": ["https://cafe.example"], "max": {"value": 2500, "currency": "USD"}}]),
            ..base_m(&k)
        },
    );
    add(
        "human_presence",
        "hp term with a week-long mandate",
        M {
            kb: Binding {
                act: "account:trade".into(),
                amt: Some(usd(40_000)),
                ..base_binding()
            },
            ..base_m(&k)
        },
    );
    add(
        "currency",
        "USD amount against a EUR limit",
        M {
            acts: json!([{"act": "order:*", "on": [SHOP], "max": {"value": 2500, "currency": "EUR"}}]),
            ..base_m(&k)
        },
    );
    add(
        "over_limit",
        "offer amount above the per-action ceiling",
        M {
            acts: json!([{"act": "order:*", "on": [SHOP], "max": {"value": 1000, "currency": "USD"}}]),
            ..base_m(&k)
        },
    );

    // ---- liability
    add(
        "liab_missing",
        "order term needs liability; mandate has none",
        M {
            liab: None,
            ..base_m(&k)
        },
    );
    add(
        "liab_provider",
        "attestation from a provider the offer does not accept",
        M {
            liab: Some(
                json!({"op": OPERATOR, "att": att("https://rogue.example", &k.rogue, OPERATOR, 100_000, NOW + 86_400)}),
            ),
            ..base_m(&k)
        },
    );
    add(
        "liab_signature",
        "accepted provider name, wrong signing key",
        M {
            liab: Some(
                json!({"op": OPERATOR, "att": att(PROVIDER, &k.rogue, OPERATOR, 100_000, NOW + 86_400)}),
            ),
            ..base_m(&k)
        },
    );
    add(
        "liab_expired",
        "attestation expired",
        M {
            liab: Some(
                json!({"op": OPERATOR, "att": att(PROVIDER, &k.provider, OPERATOR, 100_000, NOW - 1)}),
            ),
            ..base_m(&k)
        },
    );
    add(
        "liab_cover",
        "cover below the offer's floor",
        M {
            liab: Some(
                json!({"op": OPERATOR, "att": att(PROVIDER, &k.provider, OPERATOR, 20_000, NOW + 86_400)}),
            ),
            ..base_m(&k)
        },
    );

    // expectations, in the order above
    let expects = [
        ok("order:create", Some(usd(1850))),
        ok("menu:read", None),
        ok("order:create", Some(usd(1850))),
        ok("account:trade", Some(usd(40_000))),
        err("unknown_key"),
        err("issuer_signature"),
        err("alg"),
        err("disclosure"),
        err("vct"),
        err("mandate_expired"),
        err("kb_signature"),
        err("audience"),
        err("nonce"),
        err("kb_stale"),
        err("sd_hash"),
        err("not_offered"),
        err("scope"),
        err("human_presence"),
        err("currency"),
        err("over_limit"),
        err("liab_missing"),
        err("liab_provider"),
        err("liab_signature"),
        err("liab_expired"),
        err("liab_cover"),
    ];
    assert_eq!(expects.len(), cases.len());
    for (c, e) in cases.iter_mut().zip(expects) {
        c["expect"] = e;
    }

    // cases that need a different context
    let base = build(&k, base_m(&k));
    cases.push(case(
        "offer_expired",
        "valid mandate, offer past exp",
        NOW + 300,
        OPERATOR,
        &offer,
        Some(base.clone()),
        err("offer_expired"),
    ));
    cases.push(case(
        "operator",
        "Web Bot Auth identified a different operator than the key binding names",
        NOW,
        "https://other-agent.example",
        &offer,
        Some(base),
        err("operator"),
    ));
    let forged = issue::offer(&base_offer(), "platform-1", &k.rogue);
    cases.push(case(
        "offer_signature",
        "offer signed by a key not in the platform JWKS",
        NOW,
        OPERATOR,
        &forged,
        None,
        err("offer_signature"),
    ));

    // ---- hardening: each case pins a fix from the adversarial review
    let mut more = |name: &str, why: &str, pres: String, expect: Value| {
        cases.push(case(name, why, NOW, OPERATOR, &offer, Some(pres), expect));
    };
    more(
        "all_covering_apply",
        "a looser exact entry does not override a tighter wildcard",
        build(
            &k,
            M {
                acts: json!([
                    {"act": "order:*", "on": [SHOP], "max": {"value": 1000, "currency": "USD"}},
                    {"act": "order:create", "on": [SHOP], "max": {"value": 5000, "currency": "USD"}}
                ]),
                ..base_m(&k)
            },
        ),
        err("over_limit"),
    );
    more(
        "ok_two_entries",
        "two covering entries that both allow the amount",
        build(
            &k,
            M {
                acts: json!([
                    {"act": "order:*", "on": [SHOP], "max": {"value": 2000, "currency": "USD"}},
                    {"act": "order:create", "on": ["*"]}
                ]),
                ..base_m(&k)
            },
        ),
        ok("order:create", Some(usd(1850))),
    );
    for (name, acts) in [
        (
            "order_capped_first",
            json!([{"act": "order:create", "on": [SHOP], "max": {"value": 1000, "currency": "USD"}}, {"act": "order:create", "on": ["*"]}]),
        ),
        (
            "order_capped_last",
            json!([{"act": "order:create", "on": ["*"]}, {"act": "order:create", "on": [SHOP], "max": {"value": 1000, "currency": "USD"}}]),
        ),
    ] {
        more(
            name,
            "array order never changes the outcome",
            build(&k, M { acts, ..base_m(&k) }),
            err("over_limit"),
        );
    }
    more(
        "amount_mismatch",
        "the agent declares less than the offer charges",
        build(
            &k,
            M {
                kb: Binding {
                    amt: Some(usd(1)),
                    ..base_binding()
                },
                ..base_m(&k)
            },
        ),
        err("amount"),
    );
    more(
        "amount_missing",
        "the key binding omits the offer's amount",
        build(
            &k,
            M {
                kb: Binding {
                    amt: None,
                    ..base_binding()
                },
                ..base_m(&k)
            },
        ),
        err("amount"),
    );
    more(
        "amount_extra",
        "an amount on a term that has none",
        build(
            &k,
            M {
                kb: Binding {
                    act: "menu:read".into(),
                    amt: Some(usd(5)),
                    ..base_binding()
                },
                ..base_m(&k)
            },
        ),
        err("amount"),
    );
    more(
        "operator_kb",
        "key binding names another operator",
        build(
            &k,
            M {
                kb: Binding {
                    op: "https://evil.example".into(),
                    ..base_binding()
                },
                ..base_m(&k)
            },
        ),
        err("operator"),
    );
    more(
        "liab_operator",
        "mandate names an operator other than the one acting, on a term without liab",
        build(
            &k,
            M {
                liab: Some(
                    json!({"op": "https://other-agent.example", "att": att(PROVIDER, &k.provider, "https://other-agent.example", 100_000, NOW + 86_400)}),
                ),
                kb: Binding {
                    act: "menu:read".into(),
                    amt: None,
                    ..base_binding()
                },
                ..base_m(&k)
            },
        ),
        err("liab_operator"),
    );
    more(
        "liab_att_operator",
        "attestation covers a different operator than liab.op",
        build(
            &k,
            M {
                liab: Some(
                    json!({"op": OPERATOR, "att": att(PROVIDER, &k.provider, "https://other-agent.example", 100_000, NOW + 86_400)}),
                ),
                ..base_m(&k)
            },
        ),
        err("liab_operator"),
    );
    more(
        "hp_wildcard_platform",
        "human presence must name this platform, not *",
        build(
            &k,
            M {
                iat: NOW - 60,
                exp: NOW + 240,
                acts: json!([{"act": "account:trade", "on": ["*"], "max": {"value": 100000, "currency": "USD"}, "hp": true}]),
                kb: Binding {
                    act: "account:trade".into(),
                    amt: Some(usd(40_000)),
                    ..base_binding()
                },
                ..base_m(&k)
            },
        ),
        err("human_presence"),
    );
    more(
        "kb_iat_min",
        "key binding iat of i64::MIN must not wrap into a fresh time",
        build(
            &k,
            M {
                kb: Binding {
                    iat: i64::MIN,
                    ..base_binding()
                },
                ..base_m(&k)
            },
        ),
        err("malformed"),
    );
    more(
        "mandate_iat_min",
        "mandate iat of i64::MIN must not make exp - iat look short",
        build(
            &k,
            M {
                iat: i64::MIN,
                ..base_m(&k)
            },
        ),
        err("malformed"),
    );
    more(
        "hp_eternal",
        "hp entry on a mandate valid until 2^53 - 1 is not human-present",
        build(
            &k,
            M {
                iat: 0,
                exp: (1 << 53) - 1,
                acts: json!([{"act": "account:trade", "on": [SHOP], "max": {"value": 100000, "currency": "USD"}, "hp": true}]),
                kb: Binding {
                    act: "account:trade".into(),
                    amt: Some(usd(40_000)),
                    ..base_binding()
                },
                ..base_m(&k)
            },
        ),
        err("human_presence"),
    );
    more(
        "act_unknown_field",
        "an act restriction the verifier does not know must fail closed",
        build(
            &k,
            M {
                acts: json!([{"act": "order:*", "on": [SHOP], "max": {"value": 2500, "currency": "USD"}, "count": 1}]),
                ..base_m(&k)
            },
        ),
        err("malformed"),
    );
    more(
        "amount_float",
        "money is integer minor units",
        {
            let base = build(&k, base_m(&k));
            let (prefix, _) = base.rsplit_once('~').unwrap();
            let prefix = format!("{prefix}~");
            let b = json!({"iat": NOW - 5, "aud": SHOP, "op": OPERATOR, "nonce": jws::b64(&[7u8; 16]),
                           "sd_hash": jws::digest(&prefix), "act": "order:create",
                           "amt": {"value": 1850.5, "currency": "USD"}});
            format!(
                "{prefix}{}",
                raw(
                    r#"{"alg":"EdDSA","typ":"kb+jwt"}"#,
                    &b.to_string(),
                    &k.agent
                )
            )
        },
        err("malformed"),
    );
    more(
        "liab_future",
        "attestation issued an hour in the future",
        build(
            &k,
            M {
                liab: Some(json!({"op": OPERATOR, "att": issue::attestation(
                &Attestation { iss: PROVIDER.into(), sub: OPERATOR.into(), cover: usd(100_000), iat: NOW + 3600, exp: NOW + 86_400 },
                "provider-1", &k.provider)})),
                ..base_m(&k)
            },
        ),
        err("liab_expired"),
    );
    // Hand-built issuer JWTs: duplicate keys and crit can't be expressed through serde_json::Value.
    let base = build(&k, base_m(&k));
    let issuer_jwt = base.split('~').next().unwrap();
    let payload =
        String::from_utf8(jws::unb64(issuer_jwt.split('.').nth(1).unwrap()).unwrap()).unwrap();
    let d_act = base.split('~').nth(1).unwrap().to_string();
    let with_issuer = |header: &str, payload: &str| {
        let iss = raw(header, payload, &k.issuer);
        issue::present(
            &issue::prefix(&iss, std::slice::from_ref(&d_act)),
            base_binding(),
            &k.agent,
        )
    };
    let hdr = r#"{"alg":"EdDSA","kid":"issuer-1","typ":"kaze-mandate+sd-jwt"}"#;
    more(
        "dup_key_payload",
        "issuer payload with a duplicate exp; parsers would disagree which one was signed",
        with_issuer(
            hdr,
            &payload.replacen(
                r#""iat":"#,
                &format!(r#""exp":{},"iat":"#, NOW + 999_999_999),
                1,
            ),
        ),
        err("malformed"),
    );
    more(
        "dup_key_header",
        "issuer header with a duplicate typ",
        with_issuer(
            r#"{"alg":"EdDSA","kid":"issuer-1","typ":"x","typ":"kaze-mandate+sd-jwt"}"#,
            &payload,
        ),
        err("malformed"),
    );
    more(
        "crit_header",
        "a crit header the verifier does not understand must be rejected",
        with_issuer(
            r#"{"alg":"EdDSA","crit":["exp"],"kid":"issuer-1","typ":"kaze-mandate+sd-jwt"}"#,
            &payload,
        ),
        err("alg"),
    );
    more(
        "issuer_iss_mismatch",
        "a trusted key signing for an issuer it does not belong to",
        with_issuer(
            hdr,
            &payload.replacen(
                "https://ryo.example/authority",
                "https://bank.example/authority",
                1,
            ),
        ),
        err("unknown_key"),
    );
    more(
        "ok_typ_media",
        "typ compares as a media type: case-insensitive, optional application/ prefix",
        with_issuer(
            r#"{"alg":"EdDSA","kid":"issuer-1","typ":"application/KAZE-MANDATE+SD-JWT"}"#,
            &payload,
        ),
        ok("order:create", Some(usd(1850))),
    );
    more(
        "empty_disclosure",
        "an empty disclosure slot is not silently skipped",
        base.replacen('~', "~~", 1),
        err("malformed"),
    );
    more(
        "disclosure_bad_base64",
        "a disclosure the issuer did sign, but which is not base64url",
        {
            let mut plain: Value = serde_json::from_str(&payload).unwrap();
            let obj = plain.as_object_mut().unwrap();
            obj.remove("_sd");
            obj.remove("_sd_alg");
            let bad = "not*base64".to_string();
            let iss = issue::mandate(plain, &[d_act.clone(), bad.clone()], "issuer-1", &k.issuer);
            issue::present(
                &issue::prefix(&iss, &[d_act.clone(), bad]),
                base_binding(),
                &k.agent,
            )
        },
        err("disclosure"),
    );
    more(
        "duplicate_disclosure",
        "the same disclosure presented twice",
        issue::present(
            &issue::prefix(issuer_jwt, &[d_act.clone(), d_act.clone()]),
            base_binding(),
            &k.agent,
        ),
        err("disclosure"),
    );
    let mut relayed = base_offer();
    relayed.iss = "https://bank.example".into();
    cases.push(case(
        "offer_issuer",
        "a valid signature by this platform over another platform's offer",
        NOW,
        OPERATOR,
        &issue::offer(&relayed, "platform-1", &k.platform),
        None,
        err("offer_issuer"),
    ));
    let mut dup_terms = base_offer();
    dup_terms.terms.push(dup_terms.terms[1].clone());
    cases.push(case(
        "offer_dup_terms",
        "two terms for the same act",
        NOW,
        OPERATOR,
        &issue::offer(&dup_terms, "platform-1", &k.platform),
        None,
        err("malformed"),
    ));

    let out = json!({
        "version": "kaze-vectors/1",
        "spec": "draft 0",
        "note": "Seeds are test-only: key(n) = Ed25519 from 32 bytes of n. platform=1 issuer=2 agent=3 provider=4 rogue=9.",
        "platform": SHOP,
        "platform_jwks": [jwk(&k.platform, "platform-1")],
        "trust": {
            "issuers": {"https://ryo.example/authority": [jwk(&k.issuer, "issuer-1")]},
            "providers": {PROVIDER: [jwk(&k.provider, "provider-1")]}
        },
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
