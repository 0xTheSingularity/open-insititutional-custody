//! # oic-authorization-state
//!
//! The authorization-state authority of RFC 0001 §5: an explicitly trusted,
//! single-writer, serializable component that atomically manages
//! reservations, native resource locks, policy epochs, freezes, issuance
//! records, and idempotency.
//!
//! * [`AuthorityStore`] abstracts the serializable transactional store. Every
//!   `transact` either commits all of its writes or none of them.
//!   [`InMemoryAuthorityStore`] and [`FileAuthorityStore`] are provided; a
//!   PostgreSQL implementation can replace them behind the same trait.
//! * [`Authority`] is the logic. It never reads the system clock directly;
//!   time comes from an injected [`Clock`]. Each instance holds a fencing
//!   token; a newer writer fences all older ones (§5.2, §6.3).
//! * Receipts and checkpoints are Ed25519 signatures over domain-separated
//!   canonical hashes; [`verify_receipt`] and [`verify_checkpoint`] are what
//!   signers and witnesses run.
//!
//! This baseline is not Byzantine fault tolerant against compromise of the
//! authority itself (§5.1).

mod authority;
mod clock;
mod receipts;
mod state;
mod store;
mod transition;

pub use authority::*;
pub use clock::*;
pub use receipts::*;
pub use state::*;
pub use store::*;
pub use transition::*;

/// Domain tags local to the authority. Never chain-native signing domains.
pub mod authority_domains {
    /// Derivation of authority-assigned identifiers.
    pub const AUTHORITY_ID: &str = "OIC/AUTHORITY_ID/v1";
    /// Hash of a canonical authority state snapshot.
    pub const AUTHORITY_STATE: &str = "OIC/AUTHORITY_STATE/v1";
    /// Signed checkpoint body.
    pub const AUTHORITY_CHECKPOINT: &str = "OIC/AUTHORITY_CHECKPOINT/v1";
}
