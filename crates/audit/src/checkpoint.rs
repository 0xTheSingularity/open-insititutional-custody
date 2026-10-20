//! Signed audit checkpoints and witness comparison (RFC 0001 §14).

use crate::audit_domains;
use crate::chain::{sign_hash, verify_chain, verify_event, verify_hash};
use ed25519_dalek::{SigningKey, VerifyingKey};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpointBody {
    pub service_key_id: KeyId,
    /// Sequence of the head event; 0 for an empty log.
    pub sequence: u64,
    /// Hash of the head event; `Hash32::ZERO` for an empty log.
    pub head_event_hash: Hash32,
    pub at: UnixSeconds,
}

/// Service-signed statement "my history has this head". Independent
/// witnesses keep these and compare them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub body: AuditCheckpointBody,
    pub signature: SignatureBytes,
}

/// `SHA256("OIC/AUDIT_CHECKPOINT/v1" || CanonicalEncode(body))`.
pub fn audit_checkpoint_hash(body: &AuditCheckpointBody) -> OicResult<Hash32> {
    domain_hash(audit_domains::AUDIT_CHECKPOINT, body)
}

/// Sign a checkpoint body with the audit service key.
pub fn sign_audit_checkpoint(key: &SigningKey, body: AuditCheckpointBody) -> OicResult<AuditCheckpoint> {
    let h = audit_checkpoint_hash(&body)?;
    Ok(AuditCheckpoint { signature: sign_hash(key, &h), body })
}

/// Verify a checkpoint's signature under the audit service public key.
pub fn verify_checkpoint(checkpoint: &AuditCheckpoint, pubkey: &VerifyingKey) -> OicResult<()> {
    let h = audit_checkpoint_hash(&checkpoint.body)?;
    verify_hash(pubkey, &h, &checkpoint.signature).map_err(|_| OicError::invalid_signature("audit checkpoint signature does not verify"))
}

/// Result of comparing two independently held checkpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointComparison {
    /// Same sequence, same head hash.
    Consistent,
    /// The later checkpoint's history provably extends the earlier one.
    Extends { from_sequence: u64, to_sequence: u64 },
    /// The service signed two different histories. `at_sequence` is the
    /// sequence at which the witness holds proof of divergence: the shared
    /// sequence for equal-sequence checkpoints, the earlier checkpoint's
    /// sequence when the bridge does not link to it, or the later
    /// checkpoint's sequence when a signed bridge ends at a different head.
    /// Use [`first_divergence`] with both full histories to find the first
    /// differing event exactly.
    Diverged { at_sequence: u64 },
}

/// Witness comparison of two checkpoints signed by the same service key.
///
/// When the sequences differ, a checkpoint alone cannot show whether the
/// later history extends the earlier one, so the caller supplies `bridge`:
/// the events with sequences `lo+1 ..= hi` taken from the later history.
/// Every bridge event's signature is verified before any conclusion is drawn,
/// so forged events can never manufacture a divergence. A bridge that does
/// not cover exactly `lo+1 ..= hi`, or that is internally inconsistent, is an
/// error, not a verdict. For equal sequences `bridge` is ignored.
pub fn compare_checkpoints(a: &AuditCheckpoint, b: &AuditCheckpoint, pubkey: &VerifyingKey, bridge: &[AuditEvent]) -> OicResult<CheckpointComparison> {
    verify_checkpoint(a, pubkey)?;
    verify_checkpoint(b, pubkey)?;
    if a.body.service_key_id != b.body.service_key_id {
        return Err(OicError::invalid_request("checkpoints name different audit service keys"));
    }
    if a.body.sequence == b.body.sequence {
        return Ok(if a.body.head_event_hash == b.body.head_event_hash {
            CheckpointComparison::Consistent
        } else {
            CheckpointComparison::Diverged { at_sequence: a.body.sequence }
        });
    }
    let (lo, hi) = if a.body.sequence < b.body.sequence { (&a.body, &b.body) } else { (&b.body, &a.body) };
    let (Some(first), Some(last)) = (bridge.first(), bridge.last()) else {
        return Err(OicError::invalid_request("checkpoints at different sequences need the bridging events to compare"));
    };
    if first.body.sequence != lo.sequence + 1 || last.body.sequence != hi.sequence || bridge.len() as u64 != hi.sequence - lo.sequence {
        return Err(OicError::invalid_request(format!("bridge must contain exactly sequences {}..={}", lo.sequence + 1, hi.sequence)));
    }
    for e in bridge {
        verify_event(e, pubkey)?;
        if e.service_key_id != lo.service_key_id {
            return Err(OicError::invalid_request("bridge event names a different audit service key"));
        }
    }
    if first.body.previous_event_hash != lo.head_event_hash {
        return Ok(CheckpointComparison::Diverged { at_sequence: lo.sequence });
    }
    let (_, head) = verify_chain(bridge, pubkey, Some((lo.sequence, lo.head_event_hash)))?;
    if head == hi.head_event_hash {
        Ok(CheckpointComparison::Extends { from_sequence: lo.sequence, to_sequence: hi.sequence })
    } else {
        Ok(CheckpointComparison::Diverged { at_sequence: hi.sequence })
    }
}

/// Given two complete histories (each starting at sequence 1) signed by the
/// same key, verify both and return the first sequence at which their events
/// differ, or `None` when one is a prefix of the other.
pub fn first_divergence(a: &[AuditEvent], b: &[AuditEvent], pubkey: &VerifyingKey) -> OicResult<Option<u64>> {
    verify_chain(a, pubkey, None)?;
    verify_chain(b, pubkey, None)?;
    Ok(a.iter().zip(b.iter()).find(|(x, y)| x != y).map(|(x, _)| x.body.sequence))
}
