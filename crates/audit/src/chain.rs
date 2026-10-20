//! The audit log trait, event sealing, and chain verification.

use crate::audit_domains;
use crate::checkpoint::AuditCheckpoint;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use oic_authorization_state::Clock;
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use oic_policy_kernel::ed25519_signature;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Maximum size of an event's `detail` in bytes.
pub const MAX_DETAIL_BYTES: usize = 4096;
/// Maximum size of `actor` and `action` in bytes.
pub const MAX_LABEL_BYTES: usize = 256;
/// Maximum number of object commitments per event.
pub const MAX_COMMITMENTS: usize = 64;

/// Substrings (compared case-insensitively) that make `append` refuse a
/// detail string. This is a cheap tripwire against secrets reaching the log,
/// not a substitute for never passing secrets to it.
pub const REDACTION_MARKERS: [&str; 3] = ["begin private key", "seed:", "share:"];

/// An append-only, hash-chained, service-signed audit log.
pub trait AuditLog: Send + Sync {
    /// Seal and durably append one event. Returns the signed event.
    fn append(
        &self,
        actor: &str,
        action: &str,
        object_commitments: BTreeMap<String, Hash32>,
        policy_epoch: Epoch,
        detail: &str,
    ) -> OicResult<AuditEvent>;
    /// `(sequence, event_hash)` of the newest event, `None` when empty.
    fn head(&self) -> OicResult<Option<(u64, Hash32)>>;
    /// Up to `limit` events with sequence strictly greater than `sequence`,
    /// in sequence order. `events_since(0, n)` starts at the first event.
    fn events_since(&self, sequence: u64, limit: usize) -> OicResult<Vec<AuditEvent>>;
    /// Signed checkpoint over the current head (sequence 0 and `Hash32::ZERO`
    /// for an empty log).
    fn checkpoint(&self) -> OicResult<AuditCheckpoint>;
}

/// Identity, key, and time source of an audit service instance.
#[derive(Clone)]
pub struct AuditLogConfig {
    pub service_key_id: KeyId,
    pub signing_key: SigningKey,
    pub clock: Arc<dyn Clock>,
}

impl AuditLogConfig {
    pub fn new(service_key_id: KeyId, signing_key: SigningKey, clock: Arc<dyn Clock>) -> Self {
        AuditLogConfig { service_key_id, signing_key, clock }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// Reject inputs that may not be appended: empty or oversized actor/action,
/// empty or oversized commitment keys, too many commitments, oversized
/// detail, and details containing any [`REDACTION_MARKERS`].
pub fn validate_append(actor: &str, action: &str, object_commitments: &BTreeMap<String, Hash32>, detail: &str) -> OicResult<()> {
    if actor.is_empty() || actor.len() > MAX_LABEL_BYTES {
        return Err(OicError::invalid_request(format!("audit actor must be 1..={MAX_LABEL_BYTES} bytes")));
    }
    if action.is_empty() || action.len() > MAX_LABEL_BYTES {
        return Err(OicError::invalid_request(format!("audit action must be 1..={MAX_LABEL_BYTES} bytes")));
    }
    if object_commitments.len() > MAX_COMMITMENTS {
        return Err(OicError::invalid_request(format!("at most {MAX_COMMITMENTS} object commitments per audit event")));
    }
    for k in object_commitments.keys() {
        if k.is_empty() {
            return Err(OicError::invalid_request("audit object commitment key must not be empty"));
        }
        if k.len() > MAX_LABEL_BYTES {
            return Err(OicError::invalid_request(format!("audit object commitment key exceeds {MAX_LABEL_BYTES} bytes")));
        }
    }
    if detail.len() > MAX_DETAIL_BYTES {
        return Err(OicError::invalid_request(format!("audit detail exceeds {MAX_DETAIL_BYTES} bytes")));
    }
    let lower = detail.to_ascii_lowercase();
    if let Some(m) = REDACTION_MARKERS.iter().find(|m| lower.contains(*m)) {
        return Err(OicError::invalid_request(format!("audit detail contains forbidden secret marker `{m}`")));
    }
    Ok(())
}

/// `SHA256("OIC/AUDIT/v1" || CanonicalEncode(body))`.
pub fn event_hash(body: &AuditEventBody) -> OicResult<Hash32> {
    domain_hash(domains::AUDIT, body)
}

/// Every body field except `event_id`.
#[derive(Serialize)]
struct EventIdPreimage<'a> {
    sequence: u64,
    previous_event_hash: Hash32,
    at: UnixSeconds,
    actor: &'a str,
    action: &'a str,
    object_commitments: &'a BTreeMap<String, Hash32>,
    policy_epoch: Epoch,
    detail: &'a str,
}

/// `"evt-" + hex(first 16 bytes of SHA256("OIC/AUDIT_EVENT_ID/v1" ||
/// CanonicalEncode(body without event_id)))`.
///
/// The identifier cannot be derived from the event hash itself because the
/// event hash covers the body, which contains the identifier; it is therefore
/// derived from the content hash of every other body field. It is still a
/// pure function of the event content, and verification recomputes it.
pub fn derive_event_id(body: &AuditEventBody) -> OicResult<AuditEventId> {
    let pre = EventIdPreimage {
        sequence: body.sequence,
        previous_event_hash: body.previous_event_hash,
        at: body.at,
        actor: &body.actor,
        action: &body.action,
        object_commitments: &body.object_commitments,
        policy_epoch: body.policy_epoch,
        detail: &body.detail,
    };
    let h = domain_hash(audit_domains::AUDIT_EVENT_ID, &pre)?;
    Ok(AuditEventId::unchecked(format!("evt-{}", hex::encode(&h.0[..16]))))
}

pub(crate) fn sign_hash(key: &SigningKey, h: &Hash32) -> SignatureBytes {
    SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(key.sign(&h.0).to_bytes().to_vec()) }
}

pub(crate) fn verify_hash(key: &VerifyingKey, h: &Hash32, sig: &SignatureBytes) -> OicResult<()> {
    let sig = ed25519_signature(sig)?;
    key.verify_strict(&h.0, &sig).map_err(|_| OicError::invalid_signature("signature does not verify"))
}

/// What a log implementation supplies to seal the next event.
pub(crate) struct SealInput<'a> {
    pub head: Option<(u64, Hash32)>,
    pub actor: &'a str,
    pub action: &'a str,
    pub object_commitments: BTreeMap<String, Hash32>,
    pub policy_epoch: Epoch,
    pub detail: &'a str,
}

/// Validate, link, identify, and sign the event following `input.head`.
/// Returns the event and its hash.
pub(crate) fn seal_event(config: &AuditLogConfig, input: SealInput<'_>) -> OicResult<(AuditEvent, Hash32)> {
    validate_append(input.actor, input.action, &input.object_commitments, input.detail)?;
    let (prev_seq, prev_hash) = input.head.unwrap_or((0, Hash32::ZERO));
    let sequence = prev_seq.checked_add(1).ok_or_else(|| OicError::internal("audit sequence exhausted"))?;
    let mut body = AuditEventBody {
        event_id: AuditEventId::unchecked("evt-pending"),
        sequence,
        previous_event_hash: prev_hash,
        at: config.clock.now(),
        actor: input.actor.to_string(),
        action: input.action.to_string(),
        object_commitments: input.object_commitments,
        policy_epoch: input.policy_epoch,
        detail: input.detail.to_string(),
    };
    body.event_id = derive_event_id(&body)?;
    let h = event_hash(&body)?;
    let signature = sign_hash(&config.signing_key, &h);
    Ok((AuditEvent { body, service_key_id: config.service_key_id.clone(), signature }, h))
}

/// Verify one event in isolation: append validity of its content, its
/// derived `event_id`, and its signature. Returns its event hash.
pub fn verify_event(event: &AuditEvent, pubkey: &VerifyingKey) -> OicResult<Hash32> {
    let b = &event.body;
    validate_append(&b.actor, &b.action, &b.object_commitments, &b.detail)
        .map_err(|e| OicError::unverifiable(format!("event {} content invalid: {}", b.sequence, e.detail)))?;
    if b.sequence == 0 {
        return Err(OicError::unverifiable("audit sequence 0 is not a valid event sequence"));
    }
    if derive_event_id(b)? != b.event_id {
        return Err(OicError::unverifiable(format!("event {} has an event_id that does not match its content", b.sequence)));
    }
    let h = event_hash(b)?;
    verify_hash(pubkey, &h, &event.signature)
        .map_err(|_| OicError::invalid_signature(format!("event {} signature does not verify", b.sequence)))?;
    Ok(h)
}

/// Verify a contiguous run of events starting right after `from`
/// (`None` = the start of the log, i.e. sequence 0 / `Hash32::ZERO`).
/// Recomputes every hash and event id, checks strict `+1` sequencing,
/// `previous_event_hash` linkage, and every signature. Returns the new head;
/// an empty slice returns `from` (or `(0, ZERO)`).
///
/// Linkage and sequencing failures are `UnverifiableTransaction`; signature
/// failures are `InvalidSignature`.
pub fn verify_chain(events: &[AuditEvent], pubkey: &VerifyingKey, from: Option<(u64, Hash32)>) -> OicResult<(u64, Hash32)> {
    let mut head = from.unwrap_or((0, Hash32::ZERO));
    for e in events {
        head = verify_next(e, pubkey, head)?;
    }
    Ok(head)
}

/// Verify that `event` is the valid successor of `head`; returns the new head.
pub(crate) fn verify_next(event: &AuditEvent, pubkey: &VerifyingKey, head: (u64, Hash32)) -> OicResult<(u64, Hash32)> {
    let expected = head.0.checked_add(1).ok_or_else(|| OicError::unverifiable("audit sequence overflow"))?;
    if event.body.sequence != expected {
        return Err(OicError::unverifiable(format!("audit sequence gap or reorder: expected {expected}, found {}", event.body.sequence)));
    }
    if event.body.previous_event_hash != head.1 {
        return Err(OicError::unverifiable(format!("event {} does not link to the previous event hash", event.body.sequence)));
    }
    let h = verify_event(event, pubkey)?;
    Ok((expected, h))
}
