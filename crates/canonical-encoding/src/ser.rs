//! serde Serializer producing the restricted canonical `Value` tree.
//!
//! Mapping:
//! * structs → maps keyed by field-name text
//! * unit enum variants → text
//! * newtype / tuple / struct enum variants → single-entry map `{variant: payload}`
//!   (internally tagged enums are flattened by serde into ordinary structs)
//! * `Option::None` → null, `Some(v)` → v
//! * `u128`/`i128` → rejected (domain types encode amounts as decimal text)
//! * floats → rejected

use crate::value::{map_insert, Value};
use serde::ser::{self, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerError(pub String);

impl fmt::Display for SerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SerError {}
impl ser::Error for SerError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        SerError(msg.to_string())
    }
}

pub struct Serializer;

pub fn to_value<T: Serialize + ?Sized>(v: &T) -> Result<Value, SerError> {
    v.serialize(Serializer)
}

pub struct SeqSer(Vec<Value>);
pub struct MapSer {
    map: BTreeMap<Vec<u8>, (Value, Value)>,
    pending_key: Option<Value>,
}
pub struct VariantSer {
    variant: &'static str,
    inner: Vec<Value>,
}
pub struct StructVariantSer {
    variant: &'static str,
    inner: MapSer,
}

fn int_err(what: &str) -> SerError {
    SerError(format!("{what} is not permitted in the canonical profile"))
}

impl ser::Serializer for Serializer {
    type Ok = Value;
    type Error = SerError;
    type SerializeSeq = SeqSer;
    type SerializeTuple = SeqSer;
    type SerializeTupleStruct = SeqSer;
    type SerializeTupleVariant = VariantSer;
    type SerializeMap = MapSer;
    type SerializeStruct = MapSer;
    type SerializeStructVariant = StructVariantSer;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, v: bool) -> Result<Value, SerError> {
        Ok(Value::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Value, SerError> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i16(self, v: i16) -> Result<Value, SerError> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i32(self, v: i32) -> Result<Value, SerError> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i64(self, v: i64) -> Result<Value, SerError> {
        if v >= 0 {
            Ok(Value::Unsigned(v as u64))
        } else {
            Ok(Value::Negative((-1 - v) as u64))
        }
    }
    fn serialize_i128(self, _v: i128) -> Result<Value, SerError> {
        Err(int_err("i128"))
    }
    fn serialize_u8(self, v: u8) -> Result<Value, SerError> {
        Ok(Value::Unsigned(v as u64))
    }
    fn serialize_u16(self, v: u16) -> Result<Value, SerError> {
        Ok(Value::Unsigned(v as u64))
    }
    fn serialize_u32(self, v: u32) -> Result<Value, SerError> {
        Ok(Value::Unsigned(v as u64))
    }
    fn serialize_u64(self, v: u64) -> Result<Value, SerError> {
        Ok(Value::Unsigned(v))
    }
    fn serialize_u128(self, _v: u128) -> Result<Value, SerError> {
        Err(int_err("u128"))
    }
    fn serialize_f32(self, _v: f32) -> Result<Value, SerError> {
        Err(int_err("f32"))
    }
    fn serialize_f64(self, _v: f64) -> Result<Value, SerError> {
        Err(int_err("f64"))
    }
    fn serialize_char(self, v: char) -> Result<Value, SerError> {
        Ok(Value::Text(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Value, SerError> {
        Ok(Value::Text(v.to_string()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Value, SerError> {
        Ok(Value::Bytes(v.to_vec()))
    }
    fn serialize_none(self) -> Result<Value, SerError> {
        Ok(Value::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Result<Value, SerError> {
        v.serialize(self)
    }
    fn serialize_unit(self) -> Result<Value, SerError> {
        Ok(Value::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, SerError> {
        Ok(Value::Null)
    }
    fn serialize_unit_variant(self, _name: &'static str, _idx: u32, variant: &'static str) -> Result<Value, SerError> {
        Ok(Value::Text(variant.to_string()))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _name: &'static str, v: &T) -> Result<Value, SerError> {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        v: &T,
    ) -> Result<Value, SerError> {
        let mut map = BTreeMap::new();
        map_insert(&mut map, Value::text(variant), v.serialize(Serializer)?);
        Ok(Value::Map(map))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSer, SerError> {
        Ok(SeqSer(Vec::with_capacity(len.unwrap_or(0).min(1024))))
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqSer, SerError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<SeqSer, SerError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<VariantSer, SerError> {
        Ok(VariantSer { variant, inner: Vec::new() })
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<MapSer, SerError> {
        Ok(MapSer { map: BTreeMap::new(), pending_key: None })
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<MapSer, SerError> {
        Ok(MapSer { map: BTreeMap::new(), pending_key: None })
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<StructVariantSer, SerError> {
        Ok(StructVariantSer { variant, inner: MapSer { map: BTreeMap::new(), pending_key: None } })
    }
}

impl ser::SerializeSeq for SeqSer {
    type Ok = Value;
    type Error = SerError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), SerError> {
        self.0.push(v.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Value, SerError> {
        Ok(Value::Array(self.0))
    }
}
impl ser::SerializeTuple for SeqSer {
    type Ok = Value;
    type Error = SerError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), SerError> {
        ser::SerializeSeq::serialize_element(self, v)
    }
    fn end(self) -> Result<Value, SerError> {
        ser::SerializeSeq::end(self)
    }
}
impl ser::SerializeTupleStruct for SeqSer {
    type Ok = Value;
    type Error = SerError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), SerError> {
        ser::SerializeSeq::serialize_element(self, v)
    }
    fn end(self) -> Result<Value, SerError> {
        ser::SerializeSeq::end(self)
    }
}
impl ser::SerializeTupleVariant for VariantSer {
    type Ok = Value;
    type Error = SerError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), SerError> {
        self.inner.push(v.serialize(Serializer)?);
        Ok(())
    }
    fn end(self) -> Result<Value, SerError> {
        let mut map = BTreeMap::new();
        map_insert(&mut map, Value::text(self.variant), Value::Array(self.inner));
        Ok(Value::Map(map))
    }
}
impl ser::SerializeMap for MapSer {
    type Ok = Value;
    type Error = SerError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, k: &T) -> Result<(), SerError> {
        self.pending_key = Some(k.serialize(Serializer)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), SerError> {
        let k = self.pending_key.take().ok_or_else(|| SerError("value without key".into()))?;
        if !map_insert(&mut self.map, k, v.serialize(Serializer)?) {
            return Err(SerError("duplicate map key".into()));
        }
        Ok(())
    }
    fn end(self) -> Result<Value, SerError> {
        Ok(Value::Map(self.map))
    }
}
impl ser::SerializeStruct for MapSer {
    type Ok = Value;
    type Error = SerError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, v: &T) -> Result<(), SerError> {
        if !map_insert(&mut self.map, Value::text(key), v.serialize(Serializer)?) {
            return Err(SerError(format!("duplicate struct field {key}")));
        }
        Ok(())
    }
    fn end(self) -> Result<Value, SerError> {
        Ok(Value::Map(self.map))
    }
}
impl ser::SerializeStructVariant for StructVariantSer {
    type Ok = Value;
    type Error = SerError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, v: &T) -> Result<(), SerError> {
        ser::SerializeStruct::serialize_field(&mut self.inner, key, v)
    }
    fn end(self) -> Result<Value, SerError> {
        let mut map = BTreeMap::new();
        map_insert(&mut map, Value::text(self.variant), Value::Map(self.inner.map));
        Ok(Value::Map(map))
    }
}
