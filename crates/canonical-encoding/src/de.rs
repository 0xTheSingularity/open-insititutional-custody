//! serde Deserializer over a strictly decoded canonical `Value`.
//!
//! Unknown struct fields are rejected (serde `deny_unknown_fields` is not
//! required on every type because this deserializer refuses to hand a struct
//! visitor a field it did not ask for, via `deserialize_struct`'s field list).

use crate::value::Value;
use serde::de::{self, DeserializeSeed, Deserializer as _, IntoDeserializer, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeError(pub String);

impl fmt::Display for DeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for DeError {}
impl de::Error for DeError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        DeError(msg.to_string())
    }
}

pub struct Deserializer {
    value: Value,
}

impl Deserializer {
    pub fn new(value: Value) -> Self {
        Deserializer { value }
    }
}

pub fn from_value<'de, T: de::Deserialize<'de>>(v: Value) -> Result<T, DeError> {
    T::deserialize(Deserializer::new(v))
}

fn ty(v: &Value) -> &'static str {
    match v {
        Value::Unsigned(_) => "unsigned",
        Value::Negative(_) => "negative",
        Value::Bytes(_) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Bool(_) => "bool",
        Value::Null => "null",
    }
}

fn mismatch(expected: &str, got: &Value) -> DeError {
    DeError(format!("expected {expected}, got {}", ty(got)))
}

struct SeqDe {
    iter: std::vec::IntoIter<Value>,
}

impl<'de> SeqAccess<'de> for SeqDe {
    type Error = DeError;
    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, DeError> {
        match self.iter.next() {
            Some(v) => seed.deserialize(Deserializer::new(v)).map(Some),
            None => Ok(None),
        }
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

struct MapDe {
    iter: std::collections::btree_map::IntoIter<Vec<u8>, (Value, Value)>,
    pending: Option<Value>,
    allowed: Option<&'static [&'static str]>,
}

impl<'de> MapAccess<'de> for MapDe {
    type Error = DeError;
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, DeError> {
        match self.iter.next() {
            Some((_, (k, v))) => {
                if let (Some(allowed), Value::Text(name)) = (self.allowed, &k) {
                    if !allowed.contains(&name.as_str()) {
                        return Err(DeError(format!("unknown field `{name}`")));
                    }
                }
                self.pending = Some(v);
                seed.deserialize(Deserializer::new(k)).map(Some)
            }
            None => Ok(None),
        }
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, DeError> {
        let v = self.pending.take().ok_or_else(|| DeError("value before key".into()))?;
        seed.deserialize(Deserializer::new(v))
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

struct EnumDe {
    variant: Value,
    payload: Option<Value>,
}

impl<'de> de::EnumAccess<'de> for EnumDe {
    type Error = DeError;
    type Variant = VariantDe;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, VariantDe), DeError> {
        let v = seed.deserialize(Deserializer::new(self.variant))?;
        Ok((v, VariantDe { payload: self.payload }))
    }
}

struct VariantDe {
    payload: Option<Value>,
}

impl<'de> de::VariantAccess<'de> for VariantDe {
    type Error = DeError;
    fn unit_variant(self) -> Result<(), DeError> {
        match self.payload {
            None | Some(Value::Null) => Ok(()),
            Some(v) => Err(mismatch("unit variant", &v)),
        }
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, DeError> {
        let v = self.payload.ok_or_else(|| DeError("newtype variant without payload".into()))?;
        seed.deserialize(Deserializer::new(v))
    }
    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, DeError> {
        let v = self.payload.ok_or_else(|| DeError("tuple variant without payload".into()))?;
        Deserializer::new(v).deserialize_seq(visitor)
    }
    fn struct_variant<V: Visitor<'de>>(self, fields: &'static [&'static str], visitor: V) -> Result<V::Value, DeError> {
        let v = self.payload.ok_or_else(|| DeError("struct variant without payload".into()))?;
        Deserializer::new(v).deserialize_struct("", fields, visitor)
    }
}

macro_rules! de_uint {
    ($fn:ident, $visit:ident, $t:ty) => {
        fn $fn<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
            match self.value {
                Value::Unsigned(u) => {
                    let x = <$t>::try_from(u).map_err(|_| DeError(format!("integer {u} out of range")))?;
                    visitor.$visit(x)
                }
                v => Err(mismatch("unsigned integer", &v)),
            }
        }
    };
}

macro_rules! de_int {
    ($fn:ident, $visit:ident, $t:ty) => {
        fn $fn<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
            let i = self.value.as_i128().ok_or_else(|| mismatch("integer", &self.value))?;
            let x = <$t>::try_from(i).map_err(|_| DeError(format!("integer {i} out of range")))?;
            visitor.$visit(x)
        }
    };
}

impl<'de> de::Deserializer<'de> for Deserializer {
    type Error = DeError;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Unsigned(u) => visitor.visit_u64(u),
            Value::Negative(n) => visitor.visit_i64(-1 - (n as i64)),
            Value::Bytes(b) => visitor.visit_byte_buf(b),
            Value::Text(s) => visitor.visit_string(s),
            Value::Array(a) => visitor.visit_seq(SeqDe { iter: a.into_iter() }),
            Value::Map(m) => visitor.visit_map(MapDe { iter: m.into_iter(), pending: None, allowed: None }),
            Value::Bool(b) => visitor.visit_bool(b),
            Value::Null => visitor.visit_unit(),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Bool(b) => visitor.visit_bool(b),
            v => Err(mismatch("bool", &v)),
        }
    }

    de_int!(deserialize_i8, visit_i8, i8);
    de_int!(deserialize_i16, visit_i16, i16);
    de_int!(deserialize_i32, visit_i32, i32);
    de_int!(deserialize_i64, visit_i64, i64);
    de_uint!(deserialize_u8, visit_u8, u8);
    de_uint!(deserialize_u16, visit_u16, u16);
    de_uint!(deserialize_u32, visit_u32, u32);
    de_uint!(deserialize_u64, visit_u64, u64);

    fn deserialize_i128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, DeError> {
        Err(DeError("i128 is not permitted in the canonical profile".into()))
    }
    fn deserialize_u128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, DeError> {
        Err(DeError("u128 is not permitted in the canonical profile".into()))
    }
    fn deserialize_f32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, DeError> {
        Err(DeError("floats are not permitted".into()))
    }
    fn deserialize_f64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, DeError> {
        Err(DeError("floats are not permitted".into()))
    }
    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Text(s) if s.chars().count() == 1 => visitor.visit_char(s.chars().next().unwrap()),
            v => Err(mismatch("single char", &v)),
        }
    }
    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Text(s) => visitor.visit_string(s),
            v => Err(mismatch("text", &v)),
        }
    }
    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        self.deserialize_str(visitor)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Bytes(b) => visitor.visit_byte_buf(b),
            v => Err(mismatch("bytes", &v)),
        }
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        self.deserialize_bytes(visitor)
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Null => visitor.visit_none(),
            v => visitor.visit_some(Deserializer::new(v)),
        }
    }
    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Null => visitor.visit_unit(),
            v => Err(mismatch("null", &v)),
        }
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value, DeError> {
        self.deserialize_unit(visitor)
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V) -> Result<V::Value, DeError> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Array(a) => visitor.visit_seq(SeqDe { iter: a.into_iter() }),
            v => Err(mismatch("array", &v)),
        }
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, DeError> {
        match &self.value {
            Value::Array(a) if a.len() == len => self.deserialize_seq(visitor),
            v => Err(mismatch(&format!("array of length {len}"), v)),
        }
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(self, _name: &'static str, len: usize, visitor: V) -> Result<V::Value, DeError> {
        self.deserialize_tuple(len, visitor)
    }
    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Map(m) => visitor.visit_map(MapDe { iter: m.into_iter(), pending: None, allowed: None }),
            v => Err(mismatch("map", &v)),
        }
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError> {
        match self.value {
            Value::Map(m) => visitor.visit_map(MapDe { iter: m.into_iter(), pending: None, allowed: Some(fields) }),
            v => Err(mismatch("struct map", &v)),
        }
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DeError> {
        match self.value {
            Value::Text(s) => visitor.visit_enum(EnumDe { variant: Value::Text(s), payload: None }),
            Value::Map(m) if m.len() == 1 => {
                let (_, (k, v)) = m.into_iter().next().unwrap();
                visitor.visit_enum(EnumDe { variant: k, payload: Some(v) })
            }
            v => Err(mismatch("enum (text or single-entry map)", &v)),
        }
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
        match self.value {
            Value::Text(s) => visitor.visit_string(s),
            Value::Unsigned(u) => visitor.visit_u64(u),
            v => Err(mismatch("identifier", &v)),
        }
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, DeError> {
        Err(DeError("unknown field is not permitted".into()))
    }
}

impl<'de> IntoDeserializer<'de, DeError> for Deserializer {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

#[allow(dead_code)]
fn _assert_map_type(_: BTreeMap<Vec<u8>, (Value, Value)>) {}
