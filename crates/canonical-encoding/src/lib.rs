//! # oic-canonical-encoding
//!
//! One specified deterministic encoding for every security object (RFC 0001
//! §3.2) plus domain-separated hashing:
//!
//! ```text
//! EnvelopeHash = SHA256("OIC/AUTHORIZATION/v1" || CanonicalEncode(envelope_body))
//! ```
//!
//! REST JSON and other transports may carry these objects, but their
//! serializer output never becomes the security encoding; callers always
//! re-derive bytes with [`canonical_bytes`] before hashing or signing.

pub mod de;
pub mod ser;
pub mod value;

use oic_domain_types::{Hash32, OicError, OicResult};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

pub use value::{CodecError, Value};

/// Canonical bytes for any serializable security object.
pub fn canonical_bytes<T: Serialize + ?Sized>(v: &T) -> OicResult<Vec<u8>> {
    let value = ser::to_value(v).map_err(|e| OicError::invalid_request(format!("canonical encode: {e}")))?;
    Ok(value::encode(&value))
}

/// Strictly decode canonical bytes into a typed object. Non-canonical input,
/// unknown fields, floats, tags, and oversized collections are rejected.
pub fn from_canonical_bytes<T: DeserializeOwned>(bytes: &[u8]) -> OicResult<T> {
    let value = value::decode(bytes).map_err(|e| OicError::invalid_request(format!("canonical decode: {e}")))?;
    de::from_value(value).map_err(|e| OicError::invalid_request(format!("canonical decode: {e}")))
}

/// Domain-separated SHA-256 over already-canonical bytes.
pub fn domain_hash_bytes(domain: &str, canonical: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(canonical);
    Hash32(h.finalize().into())
}

/// `SHA256(domain || CanonicalEncode(v))`.
pub fn domain_hash<T: Serialize + ?Sized>(domain: &str, v: &T) -> OicResult<Hash32> {
    Ok(domain_hash_bytes(domain, &canonical_bytes(v)?))
}

/// Plain SHA-256 for raw byte commitments (public keys, native bytes).
pub fn sha256(bytes: &[u8]) -> Hash32 {
    Hash32(Sha256::digest(bytes).into())
}

/// Returns true iff `bytes` is exactly the canonical encoding of some value.
pub fn is_canonical(bytes: &[u8]) -> bool {
    value::decode(bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oic_domain_types::*;
    use proptest::prelude::*;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Sample {
        zeta: u64,
        alpha: String,
        bytes: Bytes,
        opt: Option<u32>,
        amount: Amount,
        nested: Vec<Inner>,
        tagged: AssetKind,
        map: BTreeMap<String, u8>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Inner {
        b: i64,
        a: bool,
    }

    fn sample() -> Sample {
        let mut map = BTreeMap::new();
        map.insert("b".into(), 2);
        map.insert("a".into(), 1);
        map.insert("aa".into(), 3);
        Sample {
            zeta: 300,
            alpha: "x".into(),
            bytes: Bytes(vec![1, 2, 3]),
            opt: None,
            amount: Amount(u128::MAX),
            nested: vec![Inner { b: -1, a: true }, Inner { b: 24, a: false }],
            tagged: AssetKind::Erc20 { contract: Bytes(vec![0xaa; 20]) },
            map,
        }
    }

    #[test]
    fn round_trips_and_sorts_keys() {
        let s = sample();
        let b = canonical_bytes(&s).unwrap();
        let back: Sample = from_canonical_bytes(&b).unwrap();
        assert_eq!(s, back);
        // keys sorted bytewise: "a" < "aa" < "b" inside `map`; top-level "alpha" < "amount" < "bytes" ...
        let v = value::decode(&b).unwrap();
        if let Value::Map(m) = v {
            let keys: Vec<_> = m.keys().cloned().collect();
            let mut sorted = keys.clone();
            sorted.sort();
            assert_eq!(keys, sorted);
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn golden_vector_matches_spec_layout() {
        // {"a": 1, "b": [true, null, h'0102'], "c": -25}
        #[derive(Serialize)]
        struct G {
            c: i32,
            a: u8,
            b: (bool, Option<u8>, Bytes),
        }
        let b = canonical_bytes(&G { c: -25, a: 1, b: (true, None, Bytes(vec![1, 2])) }).unwrap();
        assert_eq!(hex::encode(&b), "a3616101616283f5f642010261633818");
    }

    #[test]
    fn rejects_non_canonical_ints_and_unsorted_maps() {
        assert!(value::decode(&[0x18, 0x05]).is_err(), "0x05 encoded with 1-byte arg");
        assert!(value::decode(&[0x19, 0x00, 0xff]).is_err(), "0xff encoded with 2-byte arg");
        assert!(value::decode(&[0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02]).is_err(), "b before a");
        assert!(value::decode(&[0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02]).is_err(), "duplicate a");
        assert!(value::decode(&[0xf9, 0x00, 0x00]).is_err(), "float16");
        assert!(value::decode(&[0xc0, 0x00]).is_err(), "tag");
        assert!(value::decode(&[0x9f, 0xff]).is_err(), "indefinite array");
        assert!(value::decode(&[0x01, 0x02]).is_err(), "trailing");
        assert!(value::decode(&[0x61, 0xff]).is_err(), "invalid utf8");
    }

    #[test]
    fn rejects_unknown_fields() {
        #[derive(Serialize)]
        struct Wide {
            a: u8,
            extra: u8,
        }
        #[derive(Deserialize, Debug)]
        #[allow(dead_code)]
        struct Narrow {
            a: u8,
        }
        let b = canonical_bytes(&Wide { a: 1, extra: 2 }).unwrap();
        assert!(from_canonical_bytes::<Narrow>(&b).is_err());
    }

    #[test]
    fn payload_bytes_do_not_consume_the_item_budget() {
        let bytes = Bytes(vec![7; value::MAX_ITEMS + 1]);
        assert_eq!(from_canonical_bytes::<Bytes>(&canonical_bytes(&bytes).unwrap()).unwrap(), bytes);
        let text = "x".repeat(value::MAX_ITEMS + 1);
        assert_eq!(from_canonical_bytes::<String>(&canonical_bytes(&text).unwrap()).unwrap(), text);
        // A document of many short strings, like a growing authority snapshot.
        let ids: Vec<String> = (0..8_000).map(|i| format!("intent-{i:05}")).collect();
        assert_eq!(from_canonical_bytes::<Vec<String>>(&canonical_bytes(&ids).unwrap()).unwrap(), ids);
        // Domain `Bytes` keeps its own 1 MiB bound.
        let at_bound = value::encode(&Value::Bytes(vec![0; MAX_BYTES_LEN]));
        assert!(from_canonical_bytes::<Bytes>(&at_bound).is_ok());
        let over_bound = value::encode(&Value::Bytes(vec![0; MAX_BYTES_LEN + 1]));
        assert!(from_canonical_bytes::<Bytes>(&over_bound).is_err());
    }

    #[test]
    fn collection_items_and_total_size_stay_bounded() {
        let at_limit = value::encode(&Value::Array(vec![Value::Unsigned(0); value::MAX_ITEMS]));
        assert!(value::decode(&at_limit).is_ok());
        let over_limit = value::encode(&Value::Array(vec![Value::Unsigned(0); value::MAX_ITEMS + 1]));
        assert_eq!(value::decode(&over_limit), Err(CodecError::TooManyItems));
        let mut pairs = BTreeMap::new();
        for i in 0..=value::MAX_ITEMS as u64 {
            value::map_insert(&mut pairs, Value::Unsigned(i), Value::Null);
        }
        assert_eq!(value::decode(&value::encode(&Value::Map(pairs))), Err(CodecError::TooManyItems));
        // The payload header is a few bytes, so a maximal payload exceeds the total.
        let too_large = value::encode(&Value::Bytes(vec![0; value::MAX_TOTAL_LEN]));
        assert_eq!(value::decode(&too_large), Err(CodecError::TooLarge));
        // A declared length beyond the input is truncation, not an allocation.
        assert_eq!(value::decode(&[0x5a, 0xff, 0xff, 0xff, 0xff]), Err(CodecError::Eof(5)));
        assert_eq!(value::decode(&[0x7b, 0, 0, 0, 1, 0, 0, 0, 0]), Err(CodecError::Eof(9)));
    }

    #[test]
    fn domain_separation_changes_hash() {
        let s = sample();
        assert_ne!(domain_hash("OIC/A/v1", &s).unwrap(), domain_hash("OIC/B/v1", &s).unwrap());
    }

    proptest! {
        #[test]
        fn decode_encode_is_identity_on_canonical(xs in prop::collection::vec(any::<u64>(), 0..64), s in "[a-z]{0,16}", b in prop::collection::vec(any::<u8>(), 0..64)) {
            #[derive(Serialize)]
            struct P { xs: Vec<u64>, s: String, b: Bytes, n: i64 }
            let bytes = canonical_bytes(&P { xs: xs.clone(), s, b: Bytes(b), n: -(xs.len() as i64) }).unwrap();
            let v = value::decode(&bytes).unwrap();
            prop_assert_eq!(value::encode(&v), bytes);
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let _ = value::decode(&bytes);
        }
    }
}
