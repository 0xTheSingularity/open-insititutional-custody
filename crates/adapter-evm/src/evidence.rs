//! Evidence item keys and value formats understood by the EVM adapter.
//!
//! All hex in keys is lowercase, without a `0x` prefix.
//!
//! | key                               | value                                                    |
//! |-----------------------------------|----------------------------------------------------------|
//! | `chain_id`                        | 8-byte big-endian chain id (for `identify_network`)      |
//! | `nonce:<sender hex>`              | 8-byte big-endian next account nonce at evidence block   |
//! | `base_fee`                        | 16-byte big-endian base fee per gas                       |
//! | `priority_fee`                    | 16-byte big-endian priority fee per gas                   |
//! | `gas_limit`                       | 8-byte big-endian gas limit (estimate incl. margin)       |
//! | `code:<contract hex>`             | 32-byte keccak256 of the contract code at evidence block  |
//! | `tx:<tx hash hex>`                | canonical bytes of [`TxObservation`]                      |
//! | `signed_tx:<candidate_id>:<rev>`  | signed transaction bytes for a possibly-issued candidate  |

use crate::address::Address;
use oic_domain_types::{Amount, Bytes, EvidenceBundle, OicError, OicResult};
use serde::{Deserialize, Serialize};

pub const KEY_CHAIN_ID: &str = "chain_id";
pub const KEY_BASE_FEE: &str = "base_fee";
pub const KEY_PRIORITY_FEE: &str = "priority_fee";
pub const KEY_GAS_LIMIT: &str = "gas_limit";

/// keccak256 of empty code: an account with this code hash has no code.
pub const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82,
    0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

pub fn nonce_key(sender: &Address) -> String {
    format!("nonce:{}", hex::encode(sender))
}

pub fn code_key(contract: &Address) -> String {
    format!("code:{}", hex::encode(contract))
}

pub fn tx_key(hash: &[u8; 32]) -> String {
    format!("tx:{}", hex::encode(hash))
}

pub fn signed_tx_key(candidate_id: &str, revision: u32) -> String {
    format!("signed_tx:{candidate_id}:{revision}")
}

/// Receipt-level observation of one transaction hash at the evidence block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxObservation {
    pub included: bool,
    pub block_height: u64,
    pub block_hash: Bytes,
    pub success: bool,
    pub gas_used: u64,
    pub effective_gas_price: Amount,
    /// Blocks on the canonical chain from the inclusion block to the evidence head, inclusive.
    pub confirmations: u64,
    /// When `included == false`: hash of the *other* transaction that consumed this sender/nonce.
    pub nonce_consumed_by: Option<Bytes>,
}

pub fn get_item<'a>(ev: &'a EvidenceBundle, key: &str) -> OicResult<&'a [u8]> {
    ev.items
        .get(key)
        .map(|b| b.as_slice())
        .ok_or_else(|| OicError::stale_evidence(format!("required evidence item `{key}` is missing")))
}

fn fixed<const N: usize>(ev: &EvidenceBundle, key: &str) -> OicResult<[u8; N]> {
    get_item(ev, key)?
        .try_into()
        .map_err(|_| OicError::stale_evidence(format!("evidence item `{key}` must be {N} bytes")))
}

pub fn get_u64(ev: &EvidenceBundle, key: &str) -> OicResult<u64> {
    Ok(u64::from_be_bytes(fixed::<8>(ev, key)?))
}

pub fn get_u128(ev: &EvidenceBundle, key: &str) -> OicResult<u128> {
    Ok(u128::from_be_bytes(fixed::<16>(ev, key)?))
}

pub fn get_hash(ev: &EvidenceBundle, key: &str) -> OicResult<[u8; 32]> {
    fixed::<32>(ev, key)
}

pub fn get_tx_observation(ev: &EvidenceBundle, hash: &[u8; 32]) -> OicResult<TxObservation> {
    let key = tx_key(hash);
    let raw = get_item(ev, &key)?;
    let obs: TxObservation = oic_canonical_encoding::from_canonical_bytes(raw)
        .map_err(|e| OicError::stale_evidence(format!("evidence item `{key}` is not a canonical TxObservation: {}", e.detail)))?;
    if obs.included && obs.block_hash.len() != 32 {
        return Err(OicError::stale_evidence(format!("evidence item `{key}` block_hash must be 32 bytes")));
    }
    if let Some(other) = &obs.nonce_consumed_by {
        if other.len() != 32 {
            return Err(OicError::stale_evidence(format!("evidence item `{key}` nonce_consumed_by must be 32 bytes")));
        }
    }
    Ok(obs)
}
