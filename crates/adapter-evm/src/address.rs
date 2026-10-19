//! Keccak-256, secp256k1 address derivation, and EIP-55 display.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use oic_domain_types::{OicError, OicResult, PublicKey, SchemeId};
use sha3::{Digest, Keccak256};

pub type Address = [u8; 20];

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Address from an uncompressed SEC1 point (`0x04 || X || Y`).
pub fn address_from_uncompressed(point: &[u8]) -> OicResult<Address> {
    if point.len() != 65 || point[0] != 0x04 {
        return Err(OicError::invalid_request("expected 65-byte uncompressed SEC1 point"));
    }
    let h = keccak256(&point[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    Ok(a)
}

/// Address from a 33-byte compressed or 65-byte uncompressed SEC1 secp256k1 key.
pub fn address_from_sec1(bytes: &[u8]) -> OicResult<Address> {
    if bytes.len() != 33 && bytes.len() != 65 {
        return Err(OicError::invalid_request("secp256k1 public key must be 33 (compressed) or 65 (uncompressed) bytes"));
    }
    let pk = k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| OicError::invalid_request("public key is not a valid secp256k1 point"))?;
    let point = pk.to_encoded_point(false);
    address_from_uncompressed(point.as_bytes())
}

/// Address for an explicitly-schemed public key.
pub fn address_from_public_key(key: &PublicKey) -> OicResult<Address> {
    if key.scheme != SchemeId::EcdsaSecp256k1Keccak256Prehashed {
        return Err(OicError::unsupported(format!("EVM adapter does not support key scheme {:?}", key.scheme)));
    }
    address_from_sec1(key.bytes.as_slice())
}

/// EIP-55 mixed-case checksum encoding, `0x`-prefixed.
pub fn eip55(addr: &Address) -> String {
    let lower = hex::encode(addr);
    let h = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (h[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn to_address(b: &[u8], what: &str) -> OicResult<Address> {
    b.try_into().map_err(|_| OicError::invalid_request(format!("{what} must be a 20-byte EVM address")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_vectors() {
        // Vectors from EIP-55.
        for v in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let a: Address = hex::decode(&v[2..]).unwrap().try_into().unwrap();
            assert_eq!(eip55(&a), v);
        }
    }

    #[test]
    fn derives_known_address() {
        // secret key 1 -> generator point; well-known address.
        let sk = k256::SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        })
        .unwrap();
        let pk = sk.public_key();
        let unc = pk.to_encoded_point(false);
        let cmp = pk.to_encoded_point(true);
        let a1 = address_from_sec1(unc.as_bytes()).unwrap();
        let a2 = address_from_sec1(cmp.as_bytes()).unwrap();
        assert_eq!(a1, a2);
        assert_eq!(eip55(&a1), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }
}
