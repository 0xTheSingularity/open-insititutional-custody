//! Strict compact-u16 ("shortvec") codec used by Solana for every length prefix.
//!
//! Each byte carries 7 value bits, least-significant group first, with the high
//! bit set when another byte follows. The decoder rejects:
//!
//! * encodings longer than 3 bytes
//! * non-minimal encodings (a trailing `0x00` continuation group, e.g. `0x80 0x00`)
//! * values above `u16::MAX` (a third byte above `0x03`)
//! * truncated input

use oic_domain_types::{OicError, OicResult};

/// Maximum encoded length of a compact-u16.
pub const MAX_ENCODING_LENGTH: usize = 3;

/// Append the minimal compact-u16 encoding of `value`.
pub fn encode_into(out: &mut Vec<u8>, value: u16) {
    let mut v = value;
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

/// Minimal compact-u16 encoding of `value`.
pub fn encode(value: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_ENCODING_LENGTH);
    encode_into(&mut out, value);
    out
}

/// Encoded length of `value`.
pub fn encoded_len(value: u16) -> usize {
    match value {
        0..=0x7f => 1,
        0x80..=0x3fff => 2,
        _ => 3,
    }
}

/// Strictly decode a compact-u16 at the start of `bytes`. Returns the value and
/// the number of bytes consumed.
pub fn decode(bytes: &[u8]) -> OicResult<(u16, usize)> {
    let mut value: u32 = 0;
    for i in 0..MAX_ENCODING_LENGTH {
        let Some(&byte) = bytes.get(i) else {
            return Err(OicError::unverifiable("truncated compact-u16 length prefix"));
        };
        let group = (byte & 0x7f) as u32;
        if i == MAX_ENCODING_LENGTH - 1 {
            // Third byte: only 2 value bits remain for u16 and no continuation is allowed.
            if byte & 0x80 != 0 {
                return Err(OicError::unverifiable("compact-u16 longer than 3 bytes"));
            }
            if group > 0x03 {
                return Err(OicError::unverifiable("compact-u16 value exceeds u16::MAX"));
            }
        }
        if i > 0 && byte == 0 {
            return Err(OicError::unverifiable("non-minimal compact-u16 encoding"));
        }
        value |= group << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value as u16, i + 1));
        }
    }
    // Unreachable: the third iteration always returns or errors above.
    Err(OicError::unverifiable("compact-u16 longer than 3 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn known_vectors() {
        let cases: &[(u16, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (0x7f, &[0x7f]),
            (0x80, &[0x80, 0x01]),
            (0xff, &[0xff, 0x01]),
            (0x100, &[0x80, 0x02]),
            (0x3fff, &[0xff, 0x7f]),
            (0x4000, &[0x80, 0x80, 0x01]),
            (0xffff, &[0xff, 0xff, 0x03]),
        ];
        for (v, enc) in cases {
            assert_eq!(encode(*v), enc.to_vec(), "{v}");
            assert_eq!(encoded_len(*v), enc.len());
            assert_eq!(decode(enc).unwrap(), (*v, enc.len()));
        }
    }

    #[test]
    fn rejects_bad_encodings() {
        for bad in [
            &[0x80, 0x00][..],       // non-minimal 0
            &[0x81, 0x00],           // non-minimal 1
            &[0xff, 0x80, 0x00],     // non-minimal
            &[0x80, 0x80, 0x00],     // non-minimal
            &[0xff, 0xff, 0x04],     // > u16::MAX
            &[0x80, 0x80, 0x80, 0x01], // > 3 bytes
            &[0x80],                 // truncated
            &[0xff, 0xff],           // truncated
            &[],
        ] {
            assert!(decode(bad).is_err(), "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn round_trip(v in any::<u16>(), tail in prop::collection::vec(any::<u8>(), 0..4)) {
            let mut b = encode(v);
            let n = b.len();
            b.extend_from_slice(&tail);
            prop_assert_eq!(decode(&b).unwrap(), (v, n));
        }

        #[test]
        fn decode_is_injective(b in prop::collection::vec(any::<u8>(), 0..5)) {
            if let Ok((v, n)) = decode(&b) {
                prop_assert_eq!(encode(v), b[..n].to_vec());
            }
        }
    }
}
