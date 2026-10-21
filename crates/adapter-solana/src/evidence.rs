//! Evidence item keys and value formats understood by the Solana adapter.
//!
//! Addresses and signatures in keys are base58. Integers are little-endian.
//!
//! | key                                          | value                                                         |
//! |----------------------------------------------|---------------------------------------------------------------|
//! | `genesis_hash`                               | 32-byte genesis hash (network binding)                        |
//! | `recent_blockhash`                           | 32-byte recent blockhash the candidate must use               |
//! | `blockhash_last_valid_height`                | 8-byte LE last valid block height of `recent_blockhash`       |
//! | `blockhash_last_valid_height:<blockhash>`    | 8-byte LE last valid block height of that blockhash (invalidation) |
//! | `lamports_per_signature`                     | 8-byte LE base fee per signature                              |
//! | `rent_exempt_minimum:token_account`          | 8-byte LE rent-exempt minimum for a 165-byte token account    |
//! | `cu_limit`                                   | 4-byte LE compute-unit limit (build only, optional)           |
//! | `cu_price`                                   | 8-byte LE compute-unit price in micro-lamports (build only, optional) |
//! | `alt:<table>`                                | canonical [`AddressLookupTableEvidence`]                      |
//! | `token_account:<account>`                    | canonical [`TokenAccountEvidence`]                            |
//! | `tx:<signature>`                             | canonical [`TxObservation`]                                   |
//! | `signed_tx:<candidate_id>:<rev>`             | signed transaction bytes for a possibly-issued candidate      |

use crate::address::{to_base58, Pubkey};
use oic_domain_types::{Bytes, EvidenceBundle, OicError, OicResult};
use serde::{Deserialize, Serialize};

pub const KEY_GENESIS_HASH: &str = "genesis_hash";
pub const KEY_RECENT_BLOCKHASH: &str = "recent_blockhash";
pub const KEY_BLOCKHASH_LAST_VALID_HEIGHT: &str = "blockhash_last_valid_height";
pub const KEY_LAMPORTS_PER_SIGNATURE: &str = "lamports_per_signature";
pub const KEY_RENT_TOKEN_ACCOUNT: &str = "rent_exempt_minimum:token_account";
pub const KEY_CU_LIMIT: &str = "cu_limit";
pub const KEY_CU_PRICE: &str = "cu_price";

/// SPL token account states.
pub const TOKEN_ACCOUNT_UNINITIALIZED: u8 = 0;
pub const TOKEN_ACCOUNT_INITIALIZED: u8 = 1;
pub const TOKEN_ACCOUNT_FROZEN: u8 = 2;

/// Commitment levels in increasing strength.
pub const COMMITMENT_PROCESSED: &str = "processed";
pub const COMMITMENT_CONFIRMED: &str = "confirmed";
pub const COMMITMENT_FINALIZED: &str = "finalized";

pub fn alt_key(table: &Pubkey) -> String {
    format!("alt:{}", to_base58(table))
}

pub fn token_account_key(account: &Pubkey) -> String {
    format!("token_account:{}", to_base58(account))
}

pub fn tx_key(signature: &[u8; 64]) -> String {
    format!("tx:{}", to_base58(signature))
}

pub fn signed_tx_key(candidate_id: &str, revision: u32) -> String {
    format!("signed_tx:{candidate_id}:{revision}")
}

pub fn last_valid_height_key(blockhash: &[u8; 32]) -> String {
    format!("{KEY_BLOCKHASH_LAST_VALID_HEIGHT}:{}", to_base58(blockhash))
}

/// Resolved address lookup table at the evidence state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressLookupTableEvidence {
    /// Table contents in order; each entry is 32 bytes.
    pub addresses: Vec<Bytes>,
    /// `u64::MAX` while the table is active.
    pub deactivation_slot: u64,
    pub last_extended_slot: u64,
}

/// Decoded SPL token account at the evidence state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAccountEvidence {
    pub mint: Bytes,
    pub owner: Bytes,
    pub amount: u64,
    pub delegate: Option<Bytes>,
    pub close_authority: Option<Bytes>,
    /// 0 = uninitialized, 1 = initialized, 2 = frozen.
    pub state: u8,
}

/// Signature-status observation of one transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxObservation {
    pub slot: u64,
    pub block_hash: Bytes,
    /// `processed`, `confirmed`, or `finalized`.
    pub commitment: String,
    pub success: bool,
    /// Fee charged in lamports.
    pub fee: u64,
    /// Actual lamports spent creating supported token accounts. Required
    /// separately from the network fee; zero on failed execution. Together
    /// these settle the adapter's native-fee claim, which includes rent.
    pub account_funding: u64,
    pub err: Option<String>,
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

pub fn get_u32(ev: &EvidenceBundle, key: &str) -> OicResult<u32> {
    Ok(u32::from_le_bytes(fixed::<4>(ev, key)?))
}

pub fn get_u64(ev: &EvidenceBundle, key: &str) -> OicResult<u64> {
    Ok(u64::from_le_bytes(fixed::<8>(ev, key)?))
}

pub fn get_hash(ev: &EvidenceBundle, key: &str) -> OicResult<[u8; 32]> {
    fixed::<32>(ev, key)
}

fn canonical<T: serde::de::DeserializeOwned>(ev: &EvidenceBundle, key: &str, what: &str) -> OicResult<T> {
    let raw = get_item(ev, key)?;
    oic_canonical_encoding::from_canonical_bytes(raw)
        .map_err(|e| OicError::stale_evidence(format!("evidence item `{key}` is not a canonical {what}: {}", e.detail)))
}

fn check_32(b: &Bytes, key: &str, field: &str) -> OicResult<Pubkey> {
    b.as_slice()
        .try_into()
        .map_err(|_| OicError::stale_evidence(format!("evidence item `{key}` field `{field}` must be 32 bytes")))
}

/// Lookup table contents, validated: every address 32 bytes, at most 256 entries.
pub fn get_alt(ev: &EvidenceBundle, table: &Pubkey) -> OicResult<(AddressLookupTableEvidence, Vec<Pubkey>)> {
    let key = alt_key(table);
    let alt: AddressLookupTableEvidence = canonical(ev, &key, "AddressLookupTableEvidence")?;
    if alt.addresses.len() > 256 {
        return Err(OicError::stale_evidence(format!("evidence item `{key}` lists more than 256 addresses")));
    }
    let addrs = alt.addresses.iter().map(|a| check_32(a, &key, "addresses")).collect::<OicResult<Vec<_>>>()?;
    Ok((alt, addrs))
}

/// Validated token account: 32-byte mint/owner/delegate/close authority, known state.
pub fn get_token_account(ev: &EvidenceBundle, account: &Pubkey) -> OicResult<TokenAccountEvidence> {
    let key = token_account_key(account);
    let ta: TokenAccountEvidence = canonical(ev, &key, "TokenAccountEvidence")?;
    check_32(&ta.mint, &key, "mint")?;
    check_32(&ta.owner, &key, "owner")?;
    if let Some(d) = &ta.delegate {
        check_32(d, &key, "delegate")?;
    }
    if let Some(c) = &ta.close_authority {
        check_32(c, &key, "close_authority")?;
    }
    if ta.state > TOKEN_ACCOUNT_FROZEN {
        return Err(OicError::stale_evidence(format!("evidence item `{key}` has unknown token account state {}", ta.state)));
    }
    Ok(ta)
}

/// Rank of a commitment level; `None` for an unknown string.
pub fn commitment_rank(c: &str) -> Option<u8> {
    match c {
        COMMITMENT_PROCESSED => Some(0),
        COMMITMENT_CONFIRMED => Some(1),
        COMMITMENT_FINALIZED => Some(2),
        _ => None,
    }
}

/// Validated transaction observation.
pub fn get_tx_observation(ev: &EvidenceBundle, signature: &[u8; 64]) -> OicResult<TxObservation> {
    let key = tx_key(signature);
    let obs: TxObservation = canonical(ev, &key, "TxObservation")?;
    if obs.block_hash.len() != 32 {
        return Err(OicError::stale_evidence(format!("evidence item `{key}` block_hash must be 32 bytes")));
    }
    if commitment_rank(&obs.commitment).is_none() {
        return Err(OicError::stale_evidence(format!("evidence item `{key}` has unknown commitment `{}`", obs.commitment)));
    }
    if obs.success != obs.err.is_none() {
        return Err(OicError::stale_evidence(format!("evidence item `{key}` is inconsistent: success must hold exactly when err is absent")));
    }
    if !obs.success && obs.account_funding != 0 {
        return Err(OicError::stale_evidence("failed execution cannot create funded accounts"));
    }
    Ok(obs)
}
