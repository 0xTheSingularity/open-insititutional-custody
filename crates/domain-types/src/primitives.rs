//! Bounded integers, hashes, byte strings, and time (RFC 0001 §3.1–3.2).
//!
//! No floating-point value exists anywhere in this crate. Amounts are `u128`
//! base units and every arithmetic operation is checked.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Unsigned amount in base units. Serialized as a decimal string so that JSON
/// transports cannot silently lose precision.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Amount(pub u128);

impl Amount {
    pub const ZERO: Amount = Amount(0);

    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }

    pub fn checked_mul(self, factor: u128) -> Option<Amount> {
        self.0.checked_mul(factor).map(Amount)
    }

    pub fn saturating_add(self, other: Amount) -> Amount {
        Amount(self.0.saturating_add(other.0))
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({})", self.0)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty() || s.len() > 39 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
            return Err(serde::de::Error::custom("amount must be a canonical decimal string"));
        }
        s.parse::<u128>().map(Amount).map_err(serde::de::Error::custom)
    }
}

/// 32-byte hash / commitment. Hex in JSON, raw bytes in canonical CBOR.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub const ZERO: Hash32 = Hash32([0u8; 32]);

    pub fn from_slice(b: &[u8]) -> Option<Hash32> {
        b.try_into().ok().map(Hash32)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Hash32> {
        let v = hex::decode(s.trim_start_matches("0x")).ok()?;
        Hash32::from_slice(&v)
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", self.to_hex())
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_hex())
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            Hash32::from_hex(&s).ok_or_else(|| serde::de::Error::custom("expected 32-byte hex"))
        } else {
            let b: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
            Hash32::from_slice(&b).ok_or_else(|| serde::de::Error::custom("expected 32 bytes"))
        }
    }
}

/// Bounded opaque byte string. Hex in JSON, raw bytes in canonical CBOR.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Bytes(pub Vec<u8>);

/// Upper bound on any single byte string in a security object. Oversized
/// transactions are a bounded rejection (A37), not a parser excursion.
pub const MAX_BYTES_LEN: usize = 1024 * 1024;

impl Bytes {
    pub fn new(v: Vec<u8>) -> Option<Bytes> {
        if v.len() > MAX_BYTES_LEN {
            None
        } else {
            Some(Bytes(v))
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Bytes(v)
    }
}

impl From<&[u8]> for Bytes {
    fn from(v: &[u8]) -> Self {
        Bytes(v.to_vec())
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() <= 64 {
            write!(f, "Bytes(0x{})", hex::encode(&self.0))
        } else {
            write!(f, "Bytes(0x{}.. {} bytes)", hex::encode(&self.0[..32]), self.0.len())
        }
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&format!("0x{}", hex::encode(&self.0)))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = if d.is_human_readable() {
            let s = String::deserialize(d)?;
            hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?
        } else {
            let b: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
            b.into_vec()
        };
        Bytes::new(v).ok_or_else(|| serde::de::Error::custom("byte string exceeds MAX_BYTES_LEN"))
    }
}

/// Seconds since the Unix epoch. Policy evaluation never reads the system
/// clock; time enters only through a validated `FreshnessContext`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct UnixSeconds(pub u64);

impl UnixSeconds {
    pub fn saturating_add(self, secs: u64) -> UnixSeconds {
        UnixSeconds(self.0.saturating_add(secs))
    }
    pub fn saturating_sub(self, secs: u64) -> UnixSeconds {
        UnixSeconds(self.0.saturating_sub(secs))
    }
}

/// A signature produced by a credential, service, or chain key. Scheme is
/// always explicit; raw bytes are never interpreted without it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignatureBytes {
    pub scheme: SchemeId,
    pub bytes: Bytes,
}

/// Public key with explicit scheme.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PublicKey {
    pub scheme: SchemeId,
    pub bytes: Bytes,
}

/// Signature schemes the system can *name*. Naming a scheme is not support for
/// it; `BackendDescriptor::capabilities` and adapter manifests declare support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemeId {
    /// secp256k1 ECDSA over a 32-byte Keccak-256 digest supplied by the caller
    /// (EVM transaction signing). Signature is 64-byte r||s plus recovery id.
    EcdsaSecp256k1Keccak256Prehashed,
    /// Pure Ed25519 (RFC 8032) over the full message (Solana messages, approval
    /// credentials, service receipts). Never Ed25519ph.
    Ed25519Pure,
    /// Approval-only WebAuthn ES256 assertion over a grant-hash challenge.
    /// Signature bytes carry canonical CBOR, never a chain-native signature.
    WebAuthnEs256,
    /// BIP-340 Schnorr over secp256k1 (Bitcoin Taproot). Named, not supported.
    SchnorrBip340,
    /// secp256k1 ECDSA over SHA-256d (Bitcoin legacy/SegWit). Named, not supported.
    EcdsaSecp256k1Sha256dPrehashed,
    /// secp256k1 ECDSA over SHA-256 (Cosmos SDK). Named, not supported.
    EcdsaSecp256k1Sha256Prehashed,
}
