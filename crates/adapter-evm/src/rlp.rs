//! Bounded, strict Recursive Length Prefix (RLP) codec.
//!
//! Strictness rules (any violation is a decode error, never a panic):
//!
//! * input larger than [`MAX_RLP_INPUT`] bytes is rejected before parsing;
//! * list nesting deeper than [`MAX_RLP_DEPTH`] is rejected;
//! * a single byte `< 0x80` must be encoded as itself, never as `0x81 b`;
//! * the long form (`0xb8..` / `0xf8..`) is only valid for payloads > 55 bytes,
//!   and its length-of-length must not carry leading zero bytes;
//! * a declared length must fit inside the remaining input;
//! * [`decode`] must consume the entire input (no trailing bytes);
//! * integers decoded with [`decode_uint`] must be minimal big-endian (no
//!   leading zero bytes; zero is the empty string).

use std::fmt;

/// Maximum accepted encoded size (128 KiB).
pub const MAX_RLP_INPUT: usize = 128 * 1024;
/// Maximum list nesting depth. The outermost list is depth 1.
pub const MAX_RLP_DEPTH: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

impl RlpItem {
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        RlpItem::Bytes(b.into())
    }

    pub fn uint(v: u128) -> Self {
        RlpItem::Bytes(uint_to_minimal_be(v))
    }

    pub fn as_bytes(&self) -> Result<&[u8], RlpError> {
        match self {
            RlpItem::Bytes(b) => Ok(b),
            RlpItem::List(_) => Err(RlpError::ExpectedBytes),
        }
    }

    pub fn as_list(&self) -> Result<&[RlpItem], RlpError> {
        match self {
            RlpItem::List(l) => Ok(l),
            RlpItem::Bytes(_) => Err(RlpError::ExpectedList),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlpError {
    Empty,
    TooLarge,
    TooDeep,
    Truncated,
    NonCanonicalSingleByte,
    NonCanonicalLongForm,
    LeadingZeroInLength,
    LengthOverflow,
    TrailingBytes,
    ExpectedBytes,
    ExpectedList,
    LeadingZeroInInteger,
    IntegerTooLarge,
}

impl fmt::Display for RlpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RlpError::Empty => "empty input",
            RlpError::TooLarge => "input exceeds 128 KiB bound",
            RlpError::TooDeep => "list nesting exceeds depth bound",
            RlpError::Truncated => "declared length exceeds remaining input",
            RlpError::NonCanonicalSingleByte => "single byte below 0x80 must encode as itself",
            RlpError::NonCanonicalLongForm => "long-form length used for payload of 55 bytes or less",
            RlpError::LeadingZeroInLength => "length-of-length has leading zero byte",
            RlpError::LengthOverflow => "length does not fit in usize",
            RlpError::TrailingBytes => "trailing bytes after item",
            RlpError::ExpectedBytes => "expected byte string, found list",
            RlpError::ExpectedList => "expected list, found byte string",
            RlpError::LeadingZeroInInteger => "integer has leading zero byte",
            RlpError::IntegerTooLarge => "integer exceeds field width",
        };
        f.write_str(s)
    }
}

impl std::error::Error for RlpError {}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Minimal big-endian representation (zero is the empty string).
pub fn uint_to_minimal_be(v: u128) -> Vec<u8> {
    let b = v.to_be_bytes();
    let first = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    b[first..].to_vec()
}

fn encode_length(out: &mut Vec<u8>, len: usize, short_base: u8, long_base: u8) {
    if len <= 55 {
        out.push(short_base + len as u8);
    } else {
        let lb = uint_to_minimal_be(len as u128);
        out.push(long_base + lb.len() as u8);
        out.extend_from_slice(&lb);
    }
}

pub fn encode_bytes_into(out: &mut Vec<u8>, b: &[u8]) {
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        encode_length(out, b.len(), 0x80, 0xb7);
        out.extend_from_slice(b);
    }
}

pub fn encode_into(out: &mut Vec<u8>, item: &RlpItem) {
    match item {
        RlpItem::Bytes(b) => encode_bytes_into(out, b),
        RlpItem::List(items) => {
            let mut payload = Vec::new();
            for i in items {
                encode_into(&mut payload, i);
            }
            encode_length(out, payload.len(), 0xc0, 0xf7);
            out.extend_from_slice(&payload);
        }
    }
}

pub fn encode(item: &RlpItem) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(&mut out, item);
    out
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode exactly one item spanning the whole input.
pub fn decode(input: &[u8]) -> Result<RlpItem, RlpError> {
    if input.is_empty() {
        return Err(RlpError::Empty);
    }
    if input.len() > MAX_RLP_INPUT {
        return Err(RlpError::TooLarge);
    }
    let (item, used) = decode_item(input, 0)?;
    if used != input.len() {
        return Err(RlpError::TrailingBytes);
    }
    Ok(item)
}

fn read_long_length(buf: &[u8], len_of_len: usize) -> Result<usize, RlpError> {
    if buf.len() < 1 + len_of_len {
        return Err(RlpError::Truncated);
    }
    let lb = &buf[1..1 + len_of_len];
    if lb[0] == 0 {
        return Err(RlpError::LeadingZeroInLength);
    }
    if len_of_len > std::mem::size_of::<usize>() {
        return Err(RlpError::LengthOverflow);
    }
    let mut len: usize = 0;
    for b in lb {
        len = (len << 8) | (*b as usize);
    }
    if len <= 55 {
        return Err(RlpError::NonCanonicalLongForm);
    }
    Ok(len)
}

/// Returns (item, bytes consumed). `depth` is the number of enclosing lists.
fn decode_item(buf: &[u8], depth: usize) -> Result<(RlpItem, usize), RlpError> {
    let prefix = *buf.first().ok_or(RlpError::Truncated)?;
    match prefix {
        0x00..=0x7f => Ok((RlpItem::Bytes(vec![prefix]), 1)),
        0x80..=0xb7 => {
            let len = (prefix - 0x80) as usize;
            let end = 1usize.checked_add(len).ok_or(RlpError::LengthOverflow)?;
            if buf.len() < end {
                return Err(RlpError::Truncated);
            }
            let payload = &buf[1..end];
            if len == 1 && payload[0] < 0x80 {
                return Err(RlpError::NonCanonicalSingleByte);
            }
            Ok((RlpItem::Bytes(payload.to_vec()), end))
        }
        0xb8..=0xbf => {
            let lol = (prefix - 0xb7) as usize;
            let len = read_long_length(buf, lol)?;
            let start = 1 + lol;
            let end = start.checked_add(len).ok_or(RlpError::LengthOverflow)?;
            if buf.len() < end {
                return Err(RlpError::Truncated);
            }
            Ok((RlpItem::Bytes(buf[start..end].to_vec()), end))
        }
        0xc0..=0xf7 => {
            let len = (prefix - 0xc0) as usize;
            let end = 1usize.checked_add(len).ok_or(RlpError::LengthOverflow)?;
            if buf.len() < end {
                return Err(RlpError::Truncated);
            }
            let items = decode_list_payload(&buf[1..end], depth + 1)?;
            Ok((RlpItem::List(items), end))
        }
        0xf8..=0xff => {
            let lol = (prefix - 0xf7) as usize;
            let len = read_long_length(buf, lol)?;
            let start = 1 + lol;
            let end = start.checked_add(len).ok_or(RlpError::LengthOverflow)?;
            if buf.len() < end {
                return Err(RlpError::Truncated);
            }
            let items = decode_list_payload(&buf[start..end], depth + 1)?;
            Ok((RlpItem::List(items), end))
        }
    }
}

fn decode_list_payload(mut payload: &[u8], depth: usize) -> Result<Vec<RlpItem>, RlpError> {
    if depth > MAX_RLP_DEPTH {
        return Err(RlpError::TooDeep);
    }
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, used) = decode_item(payload, depth)?;
        items.push(item);
        payload = &payload[used..];
    }
    Ok(items)
}

/// Decode a canonical unsigned integer of at most `max_len` bytes.
pub fn decode_uint(b: &[u8], max_len: usize) -> Result<u128, RlpError> {
    if b.len() > max_len || b.len() > 16 {
        return Err(RlpError::IntegerTooLarge);
    }
    if b.first() == Some(&0) {
        return Err(RlpError::LeadingZeroInInteger);
    }
    let mut v: u128 = 0;
    for x in b {
        v = (v << 8) | (*x as u128);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_str(s: &str) -> Vec<u8> {
        encode(&RlpItem::bytes(s.as_bytes()))
    }

    #[test]
    fn classic_vectors() {
        assert_eq!(enc_str("dog"), vec![0x83, b'd', b'o', b'g']);
        let catdog = RlpItem::List(vec![RlpItem::bytes(&b"cat"[..]), RlpItem::bytes(&b"dog"[..])]);
        assert_eq!(encode(&catdog), vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']);
        assert_eq!(enc_str(""), vec![0x80]);
        assert_eq!(encode(&RlpItem::List(vec![])), vec![0xc0]);
        assert_eq!(encode(&RlpItem::uint(0)), vec![0x80]);
        assert_eq!(encode(&RlpItem::bytes(vec![0u8])), vec![0x00]);
        assert_eq!(encode(&RlpItem::uint(15)), vec![0x0f]);
        assert_eq!(encode(&RlpItem::uint(1024)), vec![0x82, 0x04, 0x00]);
        // set-theoretic representation of three: [ [], [[]], [ [], [[]] ] ]
        let e = || RlpItem::List(vec![]);
        let three = RlpItem::List(vec![e(), RlpItem::List(vec![e()]), RlpItem::List(vec![e(), RlpItem::List(vec![e()])])]);
        assert_eq!(encode(&three), vec![0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]);
        let lorem = "Lorem ipsum dolor sit amet, consectetur adipisicing elit";
        let mut expected = vec![0xb8, 0x38];
        expected.extend_from_slice(lorem.as_bytes());
        assert_eq!(enc_str(lorem), expected);
    }

    #[test]
    fn round_trip_classic_vectors() {
        for item in [
            RlpItem::bytes(&b"dog"[..]),
            RlpItem::List(vec![RlpItem::bytes(&b"cat"[..]), RlpItem::bytes(&b"dog"[..])]),
            RlpItem::bytes(vec![]),
            RlpItem::uint(1024),
            RlpItem::bytes(vec![0xab; 1000]),
            RlpItem::List(vec![RlpItem::bytes(vec![0x01; 60]); 3]),
        ] {
            assert_eq!(decode(&encode(&item)).unwrap(), item);
        }
    }

    #[test]
    fn rejects_non_canonical() {
        assert_eq!(decode(&[0x81, 0x05]), Err(RlpError::NonCanonicalSingleByte));
        assert_eq!(decode(&[0xb8, 0x02, 0xaa, 0xbb]), Err(RlpError::NonCanonicalLongForm));
        assert_eq!(decode(&[0xf8, 0x01, 0x80]), Err(RlpError::NonCanonicalLongForm));
        let mut lead = vec![0xb9, 0x00, 0x40];
        lead.extend_from_slice(&[0u8; 64]);
        assert_eq!(decode(&lead), Err(RlpError::LeadingZeroInLength));
        assert_eq!(decode(&[0x83, b'd', b'o']), Err(RlpError::Truncated));
        assert_eq!(decode(&[0x80, 0x80]), Err(RlpError::TrailingBytes));
        assert_eq!(decode(&[]), Err(RlpError::Empty));
        assert_eq!(decode(&[0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), Err(RlpError::LengthOverflow));
        assert_eq!(decode(&[0xb9, 0x01, 0x00, 0x00]), Err(RlpError::Truncated));
        assert_eq!(decode_uint(&[0x00, 0x01], 8), Err(RlpError::LeadingZeroInInteger));
        assert_eq!(decode_uint(&[0x00], 8), Err(RlpError::LeadingZeroInInteger));
        assert_eq!(decode_uint(&[1; 9], 8), Err(RlpError::IntegerTooLarge));
        assert_eq!(decode_uint(&[], 8), Ok(0));
        assert_eq!(decode_uint(&[0x04, 0x00], 8), Ok(1024));
    }

    #[test]
    fn rejects_oversize_and_deep_nesting() {
        let big = vec![0u8; MAX_RLP_INPUT + 1];
        assert_eq!(decode(&big), Err(RlpError::TooLarge));
        // depth 8 accepted, depth 9 rejected
        let mut item = RlpItem::List(vec![]);
        for _ in 0..7 {
            item = RlpItem::List(vec![item]);
        }
        assert!(decode(&encode(&item)).is_ok());
        let deeper = RlpItem::List(vec![item]);
        assert_eq!(decode(&encode(&deeper)), Err(RlpError::TooDeep));
        // 100k nested empty-list prefixes (each 0xc0-style) is bounded
        let nested: Vec<u8> = std::iter::repeat_n(0xc1u8, 100_000).chain([0xc0]).collect();
        assert!(decode(&nested).is_err());
    }
}
