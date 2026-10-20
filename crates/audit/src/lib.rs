//! # oic-audit
//!
//! Append-only audit storage with independent signed checkpoints (RFC 0001
//! §14).
//!
//! * Every [`AuditEvent`](oic_domain_types::AuditEvent) is hash chained:
//!   `event_hash = SHA256("OIC/AUDIT/v1" || CanonicalEncode(body))` and
//!   `body.previous_event_hash` is the previous event's hash (`Hash32::ZERO`
//!   for sequence 1). Sequences start at 1 and increase by exactly one.
//! * Every event is signed (Ed25519, `verify_strict`) over its event hash by
//!   the audit service key named in `service_key_id`.
//! * [`AuditCheckpoint`]s are signed `(sequence, head_event_hash)` pairs that
//!   independent witnesses hold. Hash chaining alone does not stop an operator
//!   from presenting two different histories; comparing independently held
//!   checkpoints ([`compare_checkpoints`], [`first_divergence`]) does.
//! * [`MemoryAuditLog`] and [`FileAuditLog`] implement [`AuditLog`]; the file
//!   log is an fsynced, length-prefixed canonical CBOR frame file that is
//!   replayed and fully re-verified on open.
//! * [`AuthorityAuditSink`] adapts the authorization-state authority's
//!   [`AuditSink`](oic_authorization_state::AuditSink) to an [`AuditLog`].
//!
//! Secrets never belong in an audit log; [`AuditLog::append`] implementations
//! run [`validate_append`], which includes a cheap redaction guard.

mod chain;
mod checkpoint;
mod file;
mod memory;
mod sink;

pub use chain::*;
pub use checkpoint::*;
pub use file::*;
pub use memory::*;
pub use sink::*;

/// Domain tags local to the audit service. Never chain-native signing domains.
pub mod audit_domains {
    /// Content hash from which an event's `event_id` is derived (every body
    /// field except `event_id` itself).
    pub const AUDIT_EVENT_ID: &str = "OIC/AUDIT_EVENT_ID/v1";
    /// Signed audit checkpoint body.
    pub const AUDIT_CHECKPOINT: &str = "OIC/AUDIT_CHECKPOINT/v1";
    /// Commitment to an identifier-only object referenced by an audit event.
    pub const AUDIT_OBJECT: &str = "OIC/AUDIT_OBJECT/v1";
    /// Commitment to a complete authority event.
    pub const AUTHORITY_EVENT: &str = "OIC/AUTHORITY_EVENT/v1";
}
