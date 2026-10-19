//! Restricted deterministic-CBOR value model and byte-level codec.
//!
//! Profile (a strict subset of RFC 8949 §4.2.1 deterministic encoding):
//!
//! * Major types 0/1 (integers), 2 (bytes), 3 (text), 4 (array), 5 (map) and
//!   the simple values `false`, `true`, `null` only.
//! * Integers use the shortest possible argument encoding. Negative integers
//!   are permitted down to `-2^63`.
//! * No floats, no tags, no indefinite-length items, no undefined, no other
//!   simple values.
//! * Map keys are sorted by the bytewise lexicographic order of their
//!   canonical encodings. Duplicate keys are rejected.
//! * Nesting depth, element count and total size are bounded.
//!
//! Decoding rejects anything that does not round-trip to identical bytes.

use std::collections::BTreeMap;
use thiserror::Error;

pub const MAX_DEPTH: usize = 64;
pub const MAX_ITEMS: usize = 1 << 16;
pub const MAX_TOTAL_LEN: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CodecError {
    #[error("unexpected end of input at offset {0}")]
    Eof(usize),
    #[error("unsupported major type or simple value {0:#x} at offset {1}")]
    Unsupported(u8, usize),
    #[error("non-canonical integer encoding at offset {0}")]
    NonCanonicalInt(usize),
    #[error("indefinite-length item at offset {0}")]
    Indefinite(usize),
    #[error("floating point value at offset {0}")]
    Float(usize),
    #[error("tag at offset {0}")]
    Tag(usize),
    #[error("invalid utf-8 text at offset {0}")]
    Utf8(usize),
    #[error("map keys not in canonical order at offset {0}")]
    KeyOrder(usize),
    #[error("duplicate map key at offset {0}")]
    DuplicateKey(usize),
    #[error("nesting depth exceeds {MAX_DEPTH}")]
    Depth,
    #[error("collection size exceeds {MAX_ITEMS}")]
    TooManyItems,
    #[error("input exceeds {MAX_TOTAL_LEN} bytes")]
    TooLarge,
    #[error("trailing bytes after value at offset {0}")]
    Trailing(usize),
    #[error("integer out of supported range at offset {0}")]
    IntRange(usize),
}

/// Map keys are canonical encodings; ordering a `BTreeMap<Vec<u8>, Value>` by
/// key bytes therefore *is* the deterministic map order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Unsigned(u64),
    /// Stored as the non-negative magnitude minus one (CBOR major type 1 semantics): value = -1 - n.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(BTreeMap<Vec<u8>, (Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Value::Unsigned(u) => Some(*u as i128),
            Value::Negative(n) => Some(-1 - (*n as i128)),
            _ => None,
        }
    }
}

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg <= 0xff {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

pub fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Unsigned(u) => write_head(out, 0, *u),
        Value::Negative(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(a) => {
            write_head(out, 4, a.len() as u64);
            for x in a {
                encode_into(x, out);
            }
        }
        Value::Map(m) => {
            write_head(out, 5, m.len() as u64);
            for (kbytes, (_k, val)) in m {
                out.extend_from_slice(kbytes);
                encode_into(val, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    items: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, CodecError> {
        let b = *self.buf.get(self.pos).ok_or(CodecError::Eof(self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::Eof(self.pos))?;
        let s = self.buf.get(self.pos..end).ok_or(CodecError::Eof(self.pos))?;
        self.pos = end;
        Ok(s)
    }

    fn arg(&mut self, info: u8, at: usize) -> Result<u64, CodecError> {
        match info {
            0..=23 => Ok(info as u64),
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(CodecError::NonCanonicalInt(at));
                }
                Ok(v)
            }
            25 => {
                let v = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if v <= 0xff {
                    return Err(CodecError::NonCanonicalInt(at));
                }
                Ok(v)
            }
            26 => {
                let v = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if v <= 0xffff {
                    return Err(CodecError::NonCanonicalInt(at));
                }
                Ok(v)
            }
            27 => {
                let v = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if v <= 0xffff_ffff {
                    return Err(CodecError::NonCanonicalInt(at));
                }
                Ok(v)
            }
            31 => Err(CodecError::Indefinite(at)),
            _ => Err(CodecError::Unsupported(info, at)),
        }
    }

    fn count(&mut self, n: u64) -> Result<usize, CodecError> {
        let n = usize::try_from(n).map_err(|_| CodecError::TooManyItems)?;
        self.items = self.items.checked_add(n).ok_or(CodecError::TooManyItems)?;
        if self.items > MAX_ITEMS {
            return Err(CodecError::TooManyItems);
        }
        Ok(n)
    }

    fn value(&mut self, depth: usize) -> Result<Value, CodecError> {
        if depth > MAX_DEPTH {
            return Err(CodecError::Depth);
        }
        let at = self.pos;
        let ib = self.byte()?;
        let major = ib >> 5;
        let info = ib & 0x1f;
        match major {
            0 => Ok(Value::Unsigned(self.arg(info, at)?)),
            1 => {
                let n = self.arg(info, at)?;
                if n > (i64::MAX as u64) {
                    return Err(CodecError::IntRange(at));
                }
                Ok(Value::Negative(n))
            }
            2 => {
                let n = self.arg(info, at)?;
                let n = self.count(n)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.arg(info, at)?;
                let n = self.count(n)?;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| CodecError::Utf8(at))?;
                Ok(Value::Text(s.to_string()))
            }
            4 => {
                let n = self.arg(info, at)?;
                let n = self.count(n)?;
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.arg(info, at)?;
                let n = self.count(n)?;
                let mut map = BTreeMap::new();
                let mut last_key: Option<Vec<u8>> = None;
                for _ in 0..n {
                    let kstart = self.pos;
                    let key = self.value(depth + 1)?;
                    let kbytes = self.buf[kstart..self.pos].to_vec();
                    if let Some(prev) = &last_key {
                        match prev.as_slice().cmp(kbytes.as_slice()) {
                            std::cmp::Ordering::Less => {}
                            std::cmp::Ordering::Equal => return Err(CodecError::DuplicateKey(kstart)),
                            std::cmp::Ordering::Greater => return Err(CodecError::KeyOrder(kstart)),
                        }
                    }
                    let val = self.value(depth + 1)?;
                    last_key = Some(kbytes.clone());
                    map.insert(kbytes, (key, val));
                }
                Ok(Value::Map(map))
            }
            6 => Err(CodecError::Tag(at)),
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                25 | 26 | 27 => Err(CodecError::Float(at)),
                31 => Err(CodecError::Indefinite(at)),
                _ => Err(CodecError::Unsupported(ib, at)),
            },
            _ => unreachable!(),
        }
    }
}

/// Strictly decode one canonical value. Rejects every deviation from the
/// profile and any trailing bytes.
pub fn decode(buf: &[u8]) -> Result<Value, CodecError> {
    if buf.len() > MAX_TOTAL_LEN {
        return Err(CodecError::TooLarge);
    }
    let mut r = Reader { buf, pos: 0, items: 0 };
    let v = r.value(0)?;
    if r.pos != buf.len() {
        return Err(CodecError::Trailing(r.pos));
    }
    debug_assert_eq!(encode(&v), buf, "strict decoder accepted non-canonical bytes");
    Ok(v)
}

/// Insert into a canonical map by encoding the key.
pub fn map_insert(map: &mut BTreeMap<Vec<u8>, (Value, Value)>, key: Value, val: Value) -> bool {
    let kb = encode(&key);
    if map.contains_key(&kb) {
        return false;
    }
    map.insert(kb, (key, val));
    true
}
