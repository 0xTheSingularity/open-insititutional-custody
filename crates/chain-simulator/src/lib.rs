//! # oic-chain-simulator — DEVELOPMENT ONLY
//!
//! ```text
//!  ██████  DEVELOPMENT-ONLY SIMULATED CHAINS  ██████
//!  Every evidence bundle produced here carries
//!  `EvidenceTrustLevel::DevelopmentSimulator`. A production chain profile
//!  must never list that trust level; the simulator's keys (faucets, mint
//!  authorities) are derived from public seeds and are worthless by design.
//! ```
//!
//! Deterministic, in-process simulated chains for the two enrolled profile
//! families (RFC 0002 §9 "Development"; RFC 0001 §12.3, A18, A23, A30, A31):
//!
//! * [`evm::EvmSimulator`] — accounts, EIP-1559 fee market (settable base fee
//!   for fee-spike scenarios), native transfers and registered ERC-20
//!   `transfer(address,uint256)` contracts, mempool, blocks, receipts with
//!   `Transfer` logs, finality depth, and reorgs.
//! * [`solana::SolanaSimulator`] — slots/blockhashes with a validity window,
//!   lamports, classic SPL Token mints and token accounts (packed in the real
//!   165/82-byte layouts), ATA creation, compute-budget fees, address lookup
//!   tables, commitment levels, and forks.
//!
//! Each simulator is simultaneously:
//!
//! 1. a **broadcast target** that natively verifies signatures (secp256k1
//!    recovery / strict Ed25519) and applies economic effects;
//! 2. the **evidence source** that produces [`oic_domain_types::EvidenceBundle`]s
//!    in exactly the item formats the pinned adapters (`oic-adapter-evm`,
//!    `oic-adapter-solana`) consume; and
//! 3. a **block/effects feed** an indexer can scan for deposits, including
//!    reorgs/forks that change canonicality.
//!
//! All mutable state lives behind a `Mutex`, so a simulator is `Send + Sync`
//! and can be shared through an `Arc` between a broadcaster, an evidence
//! service and an indexer. Time comes only from a [`clock::SimClock`].
//!
//! Block / slot hashes are `SHA256(parent_hash || height_be || tx_id_0 || ... ||
//! tx_id_n [|| fork_be])`, where the fork counter is appended only once the
//! chain has been reorganised at least once (see [`block_hash`]).

pub mod clock;
pub mod evm;
pub mod solana;

pub use clock::SimClock;

use oic_domain_types::{OicError, OicResult};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, MutexGuard};

/// Verifier/producer identity written into every bundle's `verifier_version`.
pub const VERIFIER_VERSION: &str = concat!("oic-chain-simulator/", env!("CARGO_PKG_VERSION"));

/// Staleness window declared by every bundle (must not exceed the profile's 120 s).
pub const EVIDENCE_MAX_STALENESS_SECONDS: u64 = 60;

/// `max_evidence_age_seconds` of every simulator profile.
pub const PROFILE_MAX_EVIDENCE_AGE_SECONDS: u64 = 120;

/// Deterministic block / slot hash.
///
/// `SHA256(parent || height_be || tx_ids... )`, with `fork_be` appended when
/// `fork > 0` so that blocks re-mined after a reorg at the same height (even
/// with identical contents) get different hashes.
pub fn block_hash(parent: &[u8; 32], height: u64, tx_ids: &[&[u8]], fork: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(parent);
    h.update(height.to_be_bytes());
    for id in tx_ids {
        h.update(id);
    }
    if fork > 0 {
        h.update(fork.to_be_bytes());
    }
    h.finalize().into()
}

/// SHA-256 helper over concatenated parts.
pub(crate) fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Lock a mutex, recovering the data if a previous holder panicked. Every
/// mutation is applied to a scratch copy and committed only on success, so a
/// panic cannot leave a half-applied state behind.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn overflow(what: &str) -> OicError {
    OicError::invalid_request(format!("{what} overflows"))
}

pub(crate) fn checked<T>(v: Option<T>, what: &str) -> OicResult<T> {
    v.ok_or_else(|| overflow(what))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_hash_binds_every_input() {
        let p = [1u8; 32];
        let a = block_hash(&p, 5, &[b"tx1", b"tx2"], 0);
        assert_eq!(a, block_hash(&p, 5, &[b"tx1", b"tx2"], 0));
        assert_ne!(a, block_hash(&[2u8; 32], 5, &[b"tx1", b"tx2"], 0));
        assert_ne!(a, block_hash(&p, 6, &[b"tx1", b"tx2"], 0));
        assert_ne!(a, block_hash(&p, 5, &[b"tx2", b"tx1"], 0));
        assert_ne!(a, block_hash(&p, 5, &[b"tx1", b"tx2"], 1));
        // fork 0 is exactly the plain preimage
        assert_eq!(a, sha256_parts(&[&p, &5u64.to_be_bytes(), b"tx1", b"tx2"]));
    }

    #[test]
    fn checked_reports_overflow() {
        assert_eq!(checked(Some(3u8), "x").unwrap(), 3);
        assert_eq!(checked::<u8>(None, "x").unwrap_err().code, oic_domain_types::ErrorCode::InvalidRequest);
    }
}
