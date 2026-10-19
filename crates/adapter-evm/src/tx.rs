//! EIP-1559 (type 2) and EIP-155 legacy transaction models with strict
//! encode/decode. No contract creation; `to` is always 20 bytes.
//!
//! ```text
//! type 2 unsigned = 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//!                                gas_limit, to, value, data, access_list])
//! type 2 signed   = 0x02 || rlp([... 9 fields ..., y_parity, r, s])
//! legacy unsigned = rlp([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0])   (EIP-155)
//! legacy signed   = rlp([nonce, gas_price, gas_limit, to, value, data, v, r, s]),  v = chain_id*2 + 35 + y
//! signing digest  = keccak256(unsigned encoding)
//! tx hash         = keccak256(signed encoding)
//! ```

use crate::address::{keccak256, Address};
use crate::rlp::{self, RlpError, RlpItem, MAX_RLP_INPUT};
use oic_domain_types::{OicError, OicResult};

pub const TYPE_EIP2930: u8 = 0x01;
pub const TYPE_EIP1559: u8 = 0x02;
pub const TYPE_EIP4844: u8 = 0x03;
pub const TYPE_EIP7702: u8 = 0x04;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Address,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Address,
    pub value: u128,
    pub data: Vec<u8>,
}

/// secp256k1 signature components. `y_parity` is the recovery id (0/1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawSignature {
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// Either supported transaction shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvmTx {
    Type2(Eip1559Tx),
    Legacy(LegacyTx),
}

pub(crate) fn rlp_err(field: &str, e: RlpError) -> OicError {
    OicError::unverifiable(format!("evm rlp ({field}): {e}"))
}

fn u64_field(item: &RlpItem, name: &str) -> OicResult<u64> {
    let b = item.as_bytes().map_err(|e| rlp_err(name, e))?;
    if b.len() > 8 {
        return Err(OicError::unverifiable(format!("{name} exceeds 64 bits")));
    }
    Ok(rlp::decode_uint(b, 8).map_err(|e| rlp_err(name, e))? as u64)
}

/// 256-bit RLP integer that must fit in u128.
fn u128_field(item: &RlpItem, name: &str) -> OicResult<u128> {
    let b = item.as_bytes().map_err(|e| rlp_err(name, e))?;
    if b.len() > 32 {
        return Err(OicError::unverifiable(format!("{name} exceeds 256 bits")));
    }
    if b.first() == Some(&0) {
        return Err(rlp_err(name, RlpError::LeadingZeroInInteger));
    }
    if b.len() > 16 {
        return Err(OicError::unverifiable(format!("{name} exceeds u128 (unsupported magnitude)")));
    }
    rlp::decode_uint(b, 16).map_err(|e| rlp_err(name, e))
}

fn to_field(item: &RlpItem) -> OicResult<Address> {
    let b = item.as_bytes().map_err(|e| rlp_err("to", e))?;
    match b.len() {
        0 => Err(OicError::unsupported("contract creation (empty `to`) is denied")),
        20 => Ok(b.try_into().expect("length checked")),
        n => Err(OicError::unverifiable(format!("`to` must be 20 bytes, got {n}"))),
    }
}

fn bytes_field(item: &RlpItem, name: &str) -> OicResult<Vec<u8>> {
    Ok(item.as_bytes().map_err(|e| rlp_err(name, e))?.to_vec())
}

fn scalar_field(item: &RlpItem, name: &str) -> OicResult<[u8; 32]> {
    let b = item.as_bytes().map_err(|e| rlp_err(name, e))?;
    if b.len() > 32 {
        return Err(OicError::invalid_signature(format!("signature {name} exceeds 32 bytes")));
    }
    if b.is_empty() {
        return Err(OicError::invalid_signature(format!("signature {name} is zero")));
    }
    if b[0] == 0 {
        return Err(rlp_err(name, RlpError::LeadingZeroInInteger));
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

fn scalar_item(x: &[u8; 32]) -> RlpItem {
    let first = x.iter().position(|b| *b != 0).unwrap_or(32);
    RlpItem::Bytes(x[first..].to_vec())
}

fn access_list_items(al: &[AccessListItem]) -> RlpItem {
    RlpItem::List(
        al.iter()
            .map(|e| {
                RlpItem::List(vec![
                    RlpItem::bytes(e.address.to_vec()),
                    RlpItem::List(e.storage_keys.iter().map(|k| RlpItem::bytes(k.to_vec())).collect()),
                ])
            })
            .collect(),
    )
}

fn access_list_field(item: &RlpItem) -> OicResult<Vec<AccessListItem>> {
    let list = item.as_list().map_err(|e| rlp_err("access_list", e))?;
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        let pair = entry.as_list().map_err(|e| rlp_err("access_list entry", e))?;
        if pair.len() != 2 {
            return Err(OicError::unverifiable("access_list entry must have 2 elements"));
        }
        let a = pair[0].as_bytes().map_err(|e| rlp_err("access_list address", e))?;
        let address: Address = a.try_into().map_err(|_| OicError::unverifiable("access_list address must be 20 bytes"))?;
        let keys = pair[1].as_list().map_err(|e| rlp_err("access_list keys", e))?;
        let mut storage_keys = Vec::with_capacity(keys.len());
        for k in keys {
            let kb = k.as_bytes().map_err(|e| rlp_err("storage key", e))?;
            storage_keys.push(kb.try_into().map_err(|_| OicError::unverifiable("storage key must be 32 bytes"))?);
        }
        out.push(AccessListItem { address, storage_keys });
    }
    Ok(out)
}

fn check_size(bytes: &[u8]) -> OicResult<()> {
    if bytes.is_empty() {
        return Err(OicError::unverifiable("empty transaction bytes"));
    }
    if bytes.len() > MAX_RLP_INPUT {
        return Err(OicError::unverifiable(format!("transaction exceeds {MAX_RLP_INPUT}-byte bound")));
    }
    Ok(())
}

/// Classify the leading byte of an EIP-2718 envelope; returns `Err` for
/// recognised but unsupported or invalid prefixes.
fn check_type_byte(b: u8) -> OicResult<()> {
    match b {
        TYPE_EIP1559 => Ok(()),
        TYPE_EIP2930 => Err(OicError::unsupported("EIP-2930 (type 0x01) access-list transactions are not enabled")),
        TYPE_EIP4844 => Err(OicError::unsupported("EIP-4844 (type 0x03) blob transactions are denied")),
        TYPE_EIP7702 => Err(OicError::unsupported("EIP-7702 (type 0x04) set-code authorization transactions are denied")),
        0x00 | 0x05..=0x7f => Err(OicError::unsupported(format!("unknown EIP-2718 transaction type 0x{b:02x}"))),
        0xc0..=0xff => Ok(()), // legacy RLP list
        _ => Err(OicError::unverifiable(format!("invalid transaction prefix byte 0x{b:02x}"))),
    }
}

fn decode_list(bytes: &[u8]) -> OicResult<Vec<RlpItem>> {
    match rlp::decode(bytes).map_err(|e| rlp_err("envelope", e))? {
        RlpItem::List(l) => Ok(l),
        RlpItem::Bytes(_) => Err(OicError::unverifiable("transaction payload is not an RLP list")),
    }
}

impl Eip1559Tx {
    fn unsigned_items(&self) -> Vec<RlpItem> {
        vec![
            RlpItem::uint(self.chain_id as u128),
            RlpItem::uint(self.nonce as u128),
            RlpItem::uint(self.max_priority_fee_per_gas),
            RlpItem::uint(self.max_fee_per_gas),
            RlpItem::uint(self.gas_limit as u128),
            RlpItem::bytes(self.to.to_vec()),
            RlpItem::uint(self.value),
            RlpItem::bytes(self.data.clone()),
            access_list_items(&self.access_list),
        ]
    }

    pub fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = vec![TYPE_EIP1559];
        rlp::encode_into(&mut out, &RlpItem::List(self.unsigned_items()));
        out
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        keccak256(&self.encode_unsigned())
    }

    pub fn encode_signed(&self, sig: &RawSignature) -> Vec<u8> {
        let mut items = self.unsigned_items();
        items.push(RlpItem::uint(sig.y_parity as u128));
        items.push(scalar_item(&sig.r));
        items.push(scalar_item(&sig.s));
        let mut out = vec![TYPE_EIP1559];
        rlp::encode_into(&mut out, &RlpItem::List(items));
        out
    }

    fn from_items(items: &[RlpItem]) -> OicResult<Self> {
        Ok(Eip1559Tx {
            chain_id: u64_field(&items[0], "chain_id")?,
            nonce: u64_field(&items[1], "nonce")?,
            max_priority_fee_per_gas: u128_field(&items[2], "max_priority_fee_per_gas")?,
            max_fee_per_gas: u128_field(&items[3], "max_fee_per_gas")?,
            gas_limit: u64_field(&items[4], "gas_limit")?,
            to: to_field(&items[5])?,
            value: u128_field(&items[6], "value")?,
            data: bytes_field(&items[7], "data")?,
            access_list: access_list_field(&items[8])?,
        })
    }

    fn payload(bytes: &[u8]) -> OicResult<Vec<RlpItem>> {
        check_size(bytes)?;
        check_type_byte(bytes[0])?;
        if bytes[0] != TYPE_EIP1559 {
            return Err(OicError::unverifiable("expected EIP-1559 type 0x02 envelope"));
        }
        decode_list(&bytes[1..])
    }

    pub fn decode_unsigned(bytes: &[u8]) -> OicResult<Self> {
        let items = Self::payload(bytes)?;
        if items.len() != 9 {
            return Err(OicError::unverifiable(format!("unsigned type-2 transaction must have 9 fields, got {}", items.len())));
        }
        Self::from_items(&items)
    }

    pub fn decode_signed(bytes: &[u8]) -> OicResult<(Self, RawSignature)> {
        let items = Self::payload(bytes)?;
        if items.len() != 12 {
            return Err(OicError::unverifiable(format!("signed type-2 transaction must have 12 fields, got {}", items.len())));
        }
        let tx = Self::from_items(&items[..9])?;
        let yp = u64_field(&items[9], "y_parity")?;
        if yp > 1 {
            return Err(OicError::invalid_signature("y_parity must be 0 or 1"));
        }
        let sig = RawSignature { y_parity: yp as u8, r: scalar_field(&items[10], "r")?, s: scalar_field(&items[11], "s")? };
        Ok((tx, sig))
    }
}

impl LegacyTx {
    fn base_items(&self) -> Vec<RlpItem> {
        vec![
            RlpItem::uint(self.nonce as u128),
            RlpItem::uint(self.gas_price),
            RlpItem::uint(self.gas_limit as u128),
            RlpItem::bytes(self.to.to_vec()),
            RlpItem::uint(self.value),
            RlpItem::bytes(self.data.clone()),
        ]
    }

    /// EIP-155 signing preimage: `rlp([..6 fields.., chain_id, 0, 0])`.
    pub fn encode_unsigned(&self) -> Vec<u8> {
        let mut items = self.base_items();
        items.push(RlpItem::uint(self.chain_id as u128));
        items.push(RlpItem::uint(0));
        items.push(RlpItem::uint(0));
        rlp::encode(&RlpItem::List(items))
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        keccak256(&self.encode_unsigned())
    }

    pub fn eip155_v(&self, y_parity: u8) -> u128 {
        (self.chain_id as u128) * 2 + 35 + y_parity as u128
    }

    pub fn encode_signed(&self, sig: &RawSignature) -> Vec<u8> {
        let mut items = self.base_items();
        items.push(RlpItem::uint(self.eip155_v(sig.y_parity)));
        items.push(scalar_item(&sig.r));
        items.push(scalar_item(&sig.s));
        rlp::encode(&RlpItem::List(items))
    }

    fn base_from_items(items: &[RlpItem], chain_id: u64) -> OicResult<Self> {
        Ok(LegacyTx {
            chain_id,
            nonce: u64_field(&items[0], "nonce")?,
            gas_price: u128_field(&items[1], "gas_price")?,
            gas_limit: u64_field(&items[2], "gas_limit")?,
            to: to_field(&items[3])?,
            value: u128_field(&items[4], "value")?,
            data: bytes_field(&items[5], "data")?,
        })
    }

    fn payload(bytes: &[u8]) -> OicResult<Vec<RlpItem>> {
        check_size(bytes)?;
        check_type_byte(bytes[0])?;
        if bytes[0] < 0xc0 {
            return Err(OicError::unverifiable("expected legacy RLP list"));
        }
        let items = decode_list(bytes)?;
        if items.len() == 6 {
            return Err(OicError::unsupported("pre-EIP-155 legacy transaction without replay protection is denied"));
        }
        if items.len() != 9 {
            return Err(OicError::unverifiable(format!("legacy transaction must have 9 fields, got {}", items.len())));
        }
        Ok(items)
    }

    pub fn decode_unsigned(bytes: &[u8]) -> OicResult<Self> {
        let items = Self::payload(bytes)?;
        let chain_id = u64_field(&items[6], "chain_id")?;
        if !items[7].as_bytes().map_err(|e| rlp_err("eip155 r", e))?.is_empty() || !items[8].as_bytes().map_err(|e| rlp_err("eip155 s", e))?.is_empty() {
            return Err(OicError::unverifiable("unsigned EIP-155 preimage must end with (chain_id, 0, 0)"));
        }
        if chain_id == 0 {
            return Err(OicError::unverifiable("EIP-155 chain_id must be non-zero"));
        }
        Self::base_from_items(&items, chain_id)
    }

    pub fn decode_signed(bytes: &[u8]) -> OicResult<(Self, RawSignature)> {
        let items = Self::payload(bytes)?;
        let vb = items[6].as_bytes().map_err(|e| rlp_err("v", e))?;
        let v = rlp::decode_uint(vb, 16).map_err(|e| rlp_err("v", e))?;
        if v == 27 || v == 28 {
            return Err(OicError::unsupported("pre-EIP-155 legacy signature (v=27/28) is denied"));
        }
        if v < 37 {
            return Err(OicError::invalid_signature(format!("invalid EIP-155 v value {v}")));
        }
        let chain_id: u64 = ((v - 35) / 2).try_into().map_err(|_| OicError::unverifiable("EIP-155 chain_id exceeds 64 bits"))?;
        let y_parity = ((v - 35) % 2) as u8;
        let tx = Self::base_from_items(&items, chain_id)?;
        let sig = RawSignature { y_parity, r: scalar_field(&items[7], "r")?, s: scalar_field(&items[8], "s")? };
        Ok((tx, sig))
    }
}

impl EvmTx {
    /// Strictly decode an unsigned candidate. Typed envelopes other than 0x02
    /// are rejected with `UnsupportedCapability`.
    pub fn decode_unsigned(bytes: &[u8]) -> OicResult<Self> {
        check_size(bytes)?;
        check_type_byte(bytes[0])?;
        if bytes[0] == TYPE_EIP1559 {
            Ok(EvmTx::Type2(Eip1559Tx::decode_unsigned(bytes)?))
        } else {
            Ok(EvmTx::Legacy(LegacyTx::decode_unsigned(bytes)?))
        }
    }

    pub fn decode_signed(bytes: &[u8]) -> OicResult<(Self, RawSignature)> {
        check_size(bytes)?;
        check_type_byte(bytes[0])?;
        if bytes[0] == TYPE_EIP1559 {
            let (t, s) = Eip1559Tx::decode_signed(bytes)?;
            Ok((EvmTx::Type2(t), s))
        } else {
            let (t, s) = LegacyTx::decode_signed(bytes)?;
            Ok((EvmTx::Legacy(t), s))
        }
    }

    pub fn encode_unsigned(&self) -> Vec<u8> {
        match self {
            EvmTx::Type2(t) => t.encode_unsigned(),
            EvmTx::Legacy(t) => t.encode_unsigned(),
        }
    }

    pub fn encode_signed(&self, sig: &RawSignature) -> Vec<u8> {
        match self {
            EvmTx::Type2(t) => t.encode_signed(sig),
            EvmTx::Legacy(t) => t.encode_signed(sig),
        }
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        keccak256(&self.encode_unsigned())
    }

    pub fn chain_id(&self) -> u64 {
        match self {
            EvmTx::Type2(t) => t.chain_id,
            EvmTx::Legacy(t) => t.chain_id,
        }
    }
    pub fn nonce(&self) -> u64 {
        match self {
            EvmTx::Type2(t) => t.nonce,
            EvmTx::Legacy(t) => t.nonce,
        }
    }
    pub fn to(&self) -> &Address {
        match self {
            EvmTx::Type2(t) => &t.to,
            EvmTx::Legacy(t) => &t.to,
        }
    }
    pub fn value(&self) -> u128 {
        match self {
            EvmTx::Type2(t) => t.value,
            EvmTx::Legacy(t) => t.value,
        }
    }
    pub fn data(&self) -> &[u8] {
        match self {
            EvmTx::Type2(t) => &t.data,
            EvmTx::Legacy(t) => &t.data,
        }
    }
    pub fn gas_limit(&self) -> u64 {
        match self {
            EvmTx::Type2(t) => t.gas_limit,
            EvmTx::Legacy(t) => t.gas_limit,
        }
    }
    /// Per-gas price cap: `max_fee_per_gas` (type 2) or `gas_price` (legacy).
    pub fn fee_cap_per_gas(&self) -> u128 {
        match self {
            EvmTx::Type2(t) => t.max_fee_per_gas,
            EvmTx::Legacy(t) => t.gas_price,
        }
    }
    /// Priority fee (type 2) or `gas_price` (legacy).
    pub fn priority_fee_per_gas(&self) -> u128 {
        match self {
            EvmTx::Type2(t) => t.max_priority_fee_per_gas,
            EvmTx::Legacy(t) => t.gas_price,
        }
    }
    /// `gas_limit * fee_cap_per_gas`, checked.
    pub fn max_fee(&self) -> OicResult<u128> {
        (self.gas_limit() as u128)
            .checked_mul(self.fee_cap_per_gas())
            .ok_or_else(|| OicError::unverifiable("gas_limit * max fee per gas overflows u128"))
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            EvmTx::Type2(_) => crate::VERSION_TYPE2,
            EvmTx::Legacy(_) => crate::VERSION_LEGACY,
        }
    }
    pub fn signing_context(&self) -> &'static str {
        match self {
            EvmTx::Type2(_) => crate::SIGNING_CONTEXT_TYPE2,
            EvmTx::Legacy(_) => crate::SIGNING_CONTEXT_LEGACY,
        }
    }
}

/// Transaction hash of signed bytes.
pub fn tx_hash(signed: &[u8]) -> [u8; 32] {
    keccak256(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 2,
            gas_limit: 21000,
            to: hex::decode("d8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap().try_into().unwrap(),
            value: 1,
            data: vec![],
            access_list: vec![],
        }
    }

    #[test]
    fn round_trips() {
        let t = sample();
        let u = t.encode_unsigned();
        assert_eq!(Eip1559Tx::decode_unsigned(&u).unwrap(), t);
        let sig = RawSignature { y_parity: 1, r: [0x11; 32], s: [0x22; 32] };
        let s = t.encode_signed(&sig);
        assert_eq!(Eip1559Tx::decode_signed(&s).unwrap(), (t.clone(), sig));
        let l = LegacyTx { chain_id: 5, nonce: 9, gas_price: 7, gas_limit: 21000, to: t.to, value: 3, data: vec![1, 2] };
        assert_eq!(LegacyTx::decode_unsigned(&l.encode_unsigned()).unwrap(), l);
        assert_eq!(LegacyTx::decode_signed(&l.encode_signed(&sig)).unwrap(), (l, sig));
    }

    #[test]
    fn rejects_value_above_u128_and_creation() {
        let mut items = sample().unsigned_items();
        items[6] = RlpItem::bytes(vec![1u8; 17]);
        let mut b = vec![2u8];
        rlp::encode_into(&mut b, &RlpItem::List(items.clone()));
        let e = Eip1559Tx::decode_unsigned(&b).unwrap_err();
        assert_eq!(e.code, oic_domain_types::ErrorCode::UnverifiableTransaction);
        items[6] = RlpItem::uint(1);
        items[5] = RlpItem::bytes(vec![]);
        let mut b = vec![2u8];
        rlp::encode_into(&mut b, &RlpItem::List(items));
        let e = Eip1559Tx::decode_unsigned(&b).unwrap_err();
        assert_eq!(e.code, oic_domain_types::ErrorCode::UnsupportedCapability);
    }

    #[test]
    fn rejects_unsupported_types() {
        for t in [0x01u8, 0x03, 0x04, 0x05, 0x7f, 0x00] {
            let mut b = vec![t];
            b.extend_from_slice(&sample().encode_unsigned()[1..]);
            assert_eq!(EvmTx::decode_unsigned(&b).unwrap_err().code, oic_domain_types::ErrorCode::UnsupportedCapability, "type {t:#x}");
        }
    }
}
