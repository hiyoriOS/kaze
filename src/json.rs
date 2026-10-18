//! Strict JSON: duplicate object keys are an error, not "last one wins".
//!
//! Two parsers that resolve `{"exp":1,"exp":2}` differently will disagree about what a
//! signature covered. Every JSON value this crate reads goes through [`parse`].

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::Error;

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, Error> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut de).map_err(|_| Error::Malformed("json"))?;
    de.end().map_err(|_| Error::Malformed("json"))?;
    Ok(value)
}

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON without duplicate keys")
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            let Strict(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::parse;

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        assert!(parse(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse(br#"{"a":{"b":1,"b":1}}"#).is_err());
        assert!(parse(br#"[{"x":1,"x":1}]"#).is_err());
    }

    #[test]
    fn rejects_trailing_data_and_deep_nesting() {
        assert!(parse(br#"{"a":1} {"a":2}"#).is_err());
        let deep = "[".repeat(200) + &"]".repeat(200);
        assert!(parse(deep.as_bytes()).is_err());
    }

    #[test]
    fn accepts_plain_json() {
        let v = parse(br#"{"a":[1,"x",null,true,{"b":2.5}]}"#).ok();
        assert_eq!(
            v.map(|v| v["a"][4]["b"].clone()),
            Some(serde_json::json!(2.5))
        );
    }
}
