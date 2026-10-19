//! # oic-domain-types
//!
//! Chain-neutral security objects for Open Institutional Custody (RFC 0001 §3).
//!
//! This crate deliberately has no cryptography and no I/O. It defines the
//! *shape* of every object that crosses a trust boundary; canonical bytes and
//! hashes are produced by `oic-canonical-encoding`, and every chain-specific
//! meaning is owned by a pinned adapter crate.

pub mod errors;
pub mod ids;
pub mod objects;
pub mod primitives;

pub use errors::*;
pub use ids::*;
pub use objects::*;
pub use primitives::*;

/// Domain-separation tags for internal commitments (§3.2). These are never
/// chain-native signing domains.
pub mod domains {
    pub const AUTHORIZATION: &str = "OIC/AUTHORIZATION/v1";
    pub const INTENT: &str = "OIC/INTENT/v1";
    pub const CANDIDATE: &str = "OIC/CANDIDATE/v1";
    pub const DECODED_OPERATION: &str = "OIC/DECODED_OPERATION/v1";
    pub const EVIDENCE: &str = "OIC/EVIDENCE/v1";
    pub const POLICY: &str = "OIC/POLICY/v1";
    pub const APPROVAL: &str = "OIC/APPROVAL/v1";
    pub const PREVIEW: &str = "OIC/PREVIEW/v1";
    pub const AUTHORITY_RECEIPT: &str = "OIC/AUTHORITY_RECEIPT/v1";
    pub const CHAIN_PROFILE: &str = "OIC/CHAIN_PROFILE/v1";
    pub const AUDIT: &str = "OIC/AUDIT/v1";
    pub const KEY_DESCRIPTOR: &str = "OIC/KEY_DESCRIPTOR/v1";
    pub const PUBLIC_KEY: &str = "OIC/PUBLIC_KEY/v1";
    pub const CONFIG_PROPOSAL: &str = "OIC/CONFIG_PROPOSAL/v1";
    pub const SIGNER_FENCE: &str = "OIC/SIGNER_FENCE/v1";
}
