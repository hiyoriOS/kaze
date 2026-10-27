//! Web Bot Auth: which operator stands behind a request.
//!
//! Implements the HTTP Message Signatures profile in `draft-ietf-webbotauth-httpsig-protocol`
//! (RFC 9421 signatures, RFC 9651 structured fields). Like the rest of the crate, this
//! is a pure function. The host reads the agent URL with [`signature_agent`], fetches
//! the key directory at [`directory_url`] over HTTPS, and passes the keys to
//! [`verify_agent`]. The [`Agent`] it returns names the operator that
//! [`Context::operator`](crate::Context::operator) must carry.

use serde::{Deserialize, Serialize};
use sfv::{BareItem, Dictionary, FieldType, InnerList, Item, ListEntry, Parser};
use sha2::{Digest, Sha256};

use crate::{jws, Error, Jwk, SKEW};

/// The well-known path of an agent's key directory.
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
/// The `tag` a Web Bot Auth signature carries. Verifiers and signers take the tag as a
/// parameter; this is the value to pass for plain Web Bot Auth, and what the
/// parameterless functions use.
pub const TAG: &str = "web-bot-auth";
/// Longest `expires - created` accepted: 24 hours, as the draft recommends.
pub const MAX_AGE: i64 = 86_400;

/// The parts of an HTTP request a signature can cover.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    /// `GET`, `POST`, and so on.
    pub method: String,
    /// `https` or `http`.
    pub scheme: String,
    /// Host and optional port, as the request carried them.
    pub authority: String,
    /// The path, starting with `/`.
    pub path: String,
    /// The query without its `?`, if the request had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// Header fields in order. Names compare case-insensitively.
    pub headers: Vec<(String, String)>,
}

impl Message {
    /// Every value of a header, trimmed and joined with `", "` (RFC 9421 §2.1).
    fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }

    fn authority(&self) -> String {
        let a = self.authority.to_ascii_lowercase();
        let default = match self.scheme.to_ascii_lowercase().as_str() {
            "https" => ":443",
            "http" => ":80",
            _ => "",
        };
        match a.strip_suffix(default) {
            Some(host) if !default.is_empty() => host.to_owned(),
            _ => a,
        }
    }

    fn query(&self) -> String {
        format!("?{}", self.query.as_deref().unwrap_or_default())
    }

    fn path(&self) -> &str {
        if self.path.is_empty() {
            "/"
        } else {
            &self.path
        }
    }
}

/// The operator a valid Web Bot Auth signature proves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    /// The origin of the agent URL, e.g. `https://agent.example`. This is the operator.
    pub operator: String,
    /// The `Signature-Agent` URL as sent.
    pub url: String,
    /// The JWK thumbprint of the key that signed.
    pub keyid: String,
    /// The signature's label.
    pub label: String,
    /// `created`.
    pub created: i64,
    /// `expires`.
    pub expires: i64,
    /// `nonce`, if the agent sent one; replay protection is the caller's.
    pub nonce: Option<String>,
}

/// The base64url SHA-256 JWK thumbprint of an Ed25519 key (RFC 7638, RFC 8037 §A.3).
pub fn thumbprint(jwk: &Jwk) -> Result<String, Error> {
    jwk.key()?;
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, jwk.x);
    Ok(jws::b64(&Sha256::digest(canonical.as_bytes())))
}

/// The single signature on a request that carries the wanted `tag`.
struct Signed {
    label: String,
    components: InnerList,
    signature: Vec<u8>,
    url: String,
    /// The legacy form: `Signature-Agent` is a bare string, not a dictionary.
    legacy: bool,
}

fn dictionary(msg: &Message, name: &str) -> Result<Dictionary, Error> {
    let raw = msg.header(name).ok_or(Error::AgentHeader)?;
    Parser::new(&raw).parse().map_err(|_| Error::AgentHeader)
}

fn param<'a>(params: &'a sfv::Parameters, key: &str) -> Option<&'a BareItem> {
    params
        .iter()
        .find(|(k, _)| k.as_str() == key)
        .map(|(_, v)| v)
}

fn param_str<'a>(params: &'a sfv::Parameters, key: &str) -> Option<&'a str> {
    param(params, key)
        .and_then(|v| v.as_string())
        .map(sfv::StringRef::as_str)
}

fn signed(msg: &Message, tag: &str) -> Result<Signed, Error> {
    let inputs = dictionary(msg, "signature-input")?;
    let mut ours = inputs.iter().filter_map(|(label, entry)| match entry {
        ListEntry::InnerList(il) if param_str(&il.params, "tag") == Some(tag) => {
            Some((label.as_str().to_owned(), il.clone()))
        }
        _ => None,
    });
    // Exactly one signature with this tag: which key speaks for the request must
    // never depend on the order of a dictionary.
    let (label, components) = ours.next().ok_or(Error::AgentHeader)?;
    if ours.next().is_some() {
        return Err(Error::AgentHeader);
    }
    let signatures = dictionary(msg, "signature")?;
    let signature = match signatures.iter().find(|(k, _)| k.as_str() == label) {
        Some((_, ListEntry::Item(item))) => item.bare_item.as_byte_sequence().map(<[u8]>::to_vec),
        _ => None,
    }
    .ok_or(Error::AgentHeader)?;
    // RFC 9651 byte sequences are base64 with padding, but parsers accept spare
    // trailing bits, so many strings decode to one signature. Accept only the
    // canonical encoding: one signature, one header text.
    let canonical = {
        use base64::Engine;
        format!(
            ":{}:",
            base64::engine::general_purpose::STANDARD.encode(&signature)
        )
    };
    if !msg
        .header("signature")
        .is_some_and(|raw| raw.contains(&canonical))
    {
        return Err(Error::AgentHeader);
    }

    let raw = msg.header("signature-agent").ok_or(Error::AgentHeader)?;
    let (url, legacy) = if let Ok(dict) = Parser::new(&raw).parse::<Dictionary>() {
        let member = dict.iter().find(|(k, _)| k.as_str() == label);
        match member {
            Some((_, ListEntry::Item(item))) => item
                .bare_item
                .as_string()
                .map(|s| (s.as_str().to_owned(), false)),
            _ => None,
        }
    } else {
        Parser::new(&raw).parse::<Item>().ok().and_then(|item| {
            item.bare_item
                .as_string()
                .map(|s| (s.as_str().to_owned(), true))
        })
    }
    .ok_or(Error::AgentHeader)?;
    Ok(Signed {
        label,
        components,
        signature,
        url,
        legacy,
    })
}

/// `scheme://host[:port]` of an `https` URL with no userinfo.
fn origin(url: &str) -> Result<String, Error> {
    let rest = url.strip_prefix("https://").ok_or(Error::AgentKey)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest.get(..end).unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return Err(Error::AgentKey);
    }
    Ok(format!("https://{}", host.to_ascii_lowercase()))
}

/// The agent URL of the request's Web Bot Auth signature: fetch its directory first.
pub fn signature_agent(msg: &Message) -> Result<String, Error> {
    signature_agent_with_tag(msg, TAG)
}

/// [`signature_agent`] for the single signature whose `tag` is `tag`, such as the
/// `agent-payer-auth` a card network's agent protocol uses.
pub fn signature_agent_with_tag(msg: &Message, tag: &str) -> Result<String, Error> {
    let s = signed(msg, tag)?;
    origin(&s.url)?;
    Ok(s.url)
}

/// Where an agent URL's key directory lives.
pub fn directory_url(agent_url: &str) -> Result<String, Error> {
    Ok(format!("{}{DIRECTORY_PATH}", origin(agent_url)?))
}

/// One component's value (RFC 9421 §2.1, §2.2). Unsupported components fail closed.
fn component(msg: &Message, name: &str, params: &sfv::Parameters) -> Result<String, Error> {
    if let Some(derived) = name.strip_prefix('@') {
        if !params.is_empty() {
            return Err(Error::AgentComponents);
        }
        let query = msg
            .query
            .as_deref()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        return Ok(match derived {
            "method" => msg.method.clone(),
            "authority" => msg.authority(),
            "scheme" => msg.scheme.to_ascii_lowercase(),
            "path" => msg.path().to_owned(),
            "query" => msg.query(),
            "request-target" => format!("{}{query}", msg.path()),
            "target-uri" => format!(
                "{}://{}{}{query}",
                msg.scheme.to_ascii_lowercase(),
                msg.authority(),
                msg.path()
            ),
            _ => return Err(Error::AgentComponents),
        });
    }
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(Error::AgentComponents);
    }
    let value = msg.header(name).ok_or(Error::AgentComponents)?;
    match params.len() {
        0 => Ok(value),
        1 => {
            let key = param_str(params, "key").ok_or(Error::AgentComponents)?;
            let dict: Dictionary = Parser::new(&value)
                .parse()
                .map_err(|_| Error::AgentComponents)?;
            let entry = dict
                .iter()
                .find(|(k, _)| k.as_str() == key)
                .map(|(_, v)| v.clone())
                .ok_or(Error::AgentComponents)?;
            serialize_entry(entry)
        }
        _ => Err(Error::AgentComponents),
    }
}

fn serialize_entry(entry: ListEntry) -> Result<String, Error> {
    match entry {
        ListEntry::Item(item) => Ok(item.serialize()),
        inner @ ListEntry::InnerList(_) => vec![inner].serialize().ok_or(Error::AgentComponents),
    }
}

/// The signature base (RFC 9421 §2.5) for `components` over `msg`.
pub(crate) fn base(msg: &Message, components: &InnerList) -> Result<String, Error> {
    let mut out = String::new();
    let mut seen = std::collections::BTreeSet::new();
    for item in &components.items {
        let name = item
            .bare_item
            .as_string()
            .ok_or(Error::AgentComponents)?
            .as_str();
        let ident = item.serialize();
        if !seen.insert(ident.clone()) {
            return Err(Error::AgentComponents);
        }
        out.push_str(&ident);
        out.push_str(": ");
        out.push_str(&component(msg, name, &item.params)?);
        out.push('\n');
    }
    out.push_str("\"@signature-params\": ");
    out.push_str(&serialize_entry(ListEntry::InnerList(components.clone()))?);
    Ok(out)
}

/// Verifies the request's Web Bot Auth signature against the agent's key directory.
///
/// `directory_url` is where the host fetched `directory` from. It must be the
/// directory of the URL the request names, so keys from one agent can never speak
/// for another.
pub fn verify_agent(
    msg: &Message,
    directory: &[Jwk],
    directory_url: &str,
    now: i64,
) -> Result<Agent, Error> {
    verify_agent_with_tag(msg, directory, directory_url, now, TAG)
}

/// [`verify_agent`] for the single signature whose `tag` is `tag`. Everything else is
/// checked the same way, including that the signature covers its own `Signature-Agent`
/// member.
pub fn verify_agent_with_tag(
    msg: &Message,
    directory: &[Jwk],
    directory_url: &str,
    now: i64,
    tag: &str,
) -> Result<Agent, Error> {
    let now = crate::time(now)?;
    let s = signed(msg, tag)?;
    if self::directory_url(&s.url)? != directory_url {
        return Err(Error::AgentKey);
    }

    let names: Vec<(String, &sfv::Parameters)> = s
        .components
        .items
        .iter()
        .filter_map(|i| {
            i.bare_item
                .as_string()
                .map(|n| (n.as_str().to_owned(), &i.params))
        })
        .collect();
    let covers = |n: &str| names.iter().any(|(name, _)| name == n);
    let covers_agent = names.iter().any(|(name, params)| {
        name == "signature-agent"
            && if s.legacy {
                params.is_empty()
            } else {
                params.len() == 1 && param_str(params, "key") == Some(s.label.as_str())
            }
    });
    if !(covers("@authority") || covers("@target-uri")) || !covers_agent {
        return Err(Error::AgentComponents);
    }

    let p = &s.components.params;
    let int = |k| param(p, k).and_then(BareItem::as_integer).map(i64::from);
    let (created, expires) = match (int("created"), int("expires")) {
        (Some(c), Some(e)) => (crate::time(c)?, crate::time(e)?),
        _ => return Err(Error::AgentHeader),
    };
    if let Some(alg) = param(p, "alg") {
        if alg.as_string().map(sfv::StringRef::as_str) != Some("ed25519") {
            return Err(Error::Alg);
        }
    }
    let keyid = param_str(p, "keyid").ok_or(Error::AgentHeader)?.to_owned();
    if created > now.saturating_add(SKEW)
        || expires <= now
        || expires <= created
        || expires.saturating_sub(created) > MAX_AGE
    {
        return Err(Error::AgentExpired);
    }

    let key = directory
        .iter()
        .find(|k| thumbprint(k).is_ok_and(|t| t == keyid))
        .ok_or(Error::AgentKey)?
        .key()?;
    let base = base(msg, &s.components)?;
    let sig =
        ed25519_dalek::Signature::from_slice(&s.signature).map_err(|_| Error::AgentSignature)?;
    key.verify_strict(base.as_bytes(), &sig)
        .map_err(|_| Error::AgentSignature)?;

    Ok(Agent {
        operator: origin(&s.url)?,
        url: s.url,
        keyid,
        label: s.label,
        created,
        expires,
        nonce: param_str(p, "nonce").map(str::to_owned),
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::{base, origin, thumbprint, Message};
    use crate::{jws, Jwk};
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use sfv::{FieldType, InnerList, ListEntry, Parser};

    /// RFC 9421 Appendix B.2: test-request.
    fn rfc_request() -> Message {
        Message {
            method: "POST".into(),
            scheme: "https".into(),
            authority: "example.com".into(),
            path: "/foo".into(),
            query: Some("param=Value&Pet=dog".into()),
            headers: vec![
                ("Host".into(), "example.com".into()),
                ("Date".into(), "Tue, 20 Apr 2021 02:07:55 GMT".into()),
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), "18".into()),
            ],
        }
    }

    fn inner(sig_input: &str) -> InnerList {
        let dict: sfv::Dictionary = Parser::new(sig_input).parse().unwrap();
        match dict.into_iter().next().unwrap().1 {
            ListEntry::InnerList(il) => il,
            ListEntry::Item(_) => unreachable!(),
        }
    }

    /// RFC 9421 §B.2.6, known answer: same base, and Ed25519 being deterministic, the
    /// same signature bytes from test-key-ed25519.
    #[test]
    fn rfc9421_b26_ed25519() {
        let il = inner(
            r#"sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#,
        );
        let got = base(&rfc_request(), &il).unwrap();
        let want = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n\"content-type\": application/json\n\"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
        assert_eq!(got, want);

        let d: [u8; 32] = jws::unb64("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU")
            .unwrap()
            .try_into()
            .unwrap();
        let key = SigningKey::from_bytes(&d);
        assert_eq!(
            jws::b64(key.verifying_key().as_bytes()),
            "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
        );
        let sig = key.sign(got.as_bytes());
        let want_sig = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";
        let want_sig = base64::engine::general_purpose::STANDARD
            .decode(want_sig)
            .unwrap();
        assert_eq!(sig.to_bytes().to_vec(), want_sig);
    }

    #[test]
    fn derived_components() {
        let il = inner(r#"s=("@target-uri" "@query" "@request-target" "@scheme");created=1"#);
        let got = base(&rfc_request(), &il).unwrap();
        assert!(got.starts_with("\"@target-uri\": https://example.com/foo?param=Value&Pet=dog\n\"@query\": ?param=Value&Pet=dog\n\"@request-target\": /foo?param=Value&Pet=dog\n\"@scheme\": https\n"));
        let s = vec![ListEntry::InnerList(il)].serialize();
        assert_eq!(
            s.as_deref(),
            Some(r#"("@target-uri" "@query" "@request-target" "@scheme");created=1"#)
        );
    }

    #[test]
    fn rfc8037_thumbprint() {
        // RFC 8037 §A.3 example key and its thumbprint.
        let jwk = Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
            kid: None,
        };
        assert_eq!(
            thumbprint(&jwk).unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn origins() {
        assert_eq!(
            origin("https://Agent.Example/x?y").unwrap(),
            "https://agent.example"
        );
        assert_eq!(
            origin("https://agent.example:8443").unwrap(),
            "https://agent.example:8443"
        );
        assert!(origin("http://agent.example").is_err());
        assert!(origin("https://user@agent.example").is_err());
        assert!(origin("https://").is_err());
    }
}
