//! Adapter from the authorization-state authority's [`AuditSink`] to an
//! [`AuditLog`].

use crate::audit_domains;
use crate::chain::AuditLog;
use oic_authorization_state::{AbortReason, AuditSink, AuthorityEvent, FreezeScope};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// `SHA256("OIC/AUDIT_OBJECT/v1" || CanonicalEncode((kind, id)))`: the
/// commitment used for objects an authority event names only by identifier.
pub fn object_commitment(kind: &str, id: &str) -> OicResult<Hash32> {
    domain_hash(audit_domains::AUDIT_OBJECT, &(kind, id))
}

/// `SHA256("OIC/AUTHORITY_EVENT/v1" || CanonicalEncode(event))`.
pub fn authority_event_commitment(event: &AuthorityEvent) -> OicResult<Hash32> {
    domain_hash(audit_domains::AUTHORITY_EVENT, event)
}

/// The audit entry one authority event maps to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthorityAuditEntry {
    pub action: String,
    pub object_commitments: BTreeMap<String, Hash32>,
    pub policy_epoch: Epoch,
    pub detail: String,
}

fn scope_text(scope: &FreezeScope) -> String {
    match scope {
        FreezeScope::Global => "global".to_string(),
        FreezeScope::Vault { vault_id } => format!("vault:{vault_id}"),
    }
}

fn abort_text(r: &AbortReason) -> &'static str {
    match r {
        AbortReason::BeforeIssuance => "before_issuance",
        AbortReason::ApprovalExpired => "approval_expired",
    }
}

/// Map an authority event to its audit entry.
///
/// * `action` is `authority.<variant>` (`authority.opened`,
///   `authority.policy_activated`, `authority.reserved`, `authority.released`,
///   `authority.frozen`, `authority.unfrozen`, `authority.aborted`,
///   `authority.observed`).
/// * `object_commitments` always contains `authority_event` (commitment to
///   the full event) plus one entry per named object: `policy` (the policy
///   hash itself), `reservation`, `issuance`, `freeze_scope`,
///   `operation_family`, `candidate` (see [`object_commitment`]).
/// * `policy_epoch` is the event's own epoch for `PolicyActivated`, else
///   `known_policy_epoch`; when that is unknown it is `Epoch(0)` and the
///   detail says `policy_epoch=unknown`.
/// * `detail` is `key=value` pairs with the commit sequence and identifiers.
pub fn authority_event_entry(event: &AuthorityEvent, known_policy_epoch: Option<Epoch>) -> OicResult<AuthorityAuditEntry> {
    let mut c = BTreeMap::new();
    c.insert("authority_event".to_string(), authority_event_commitment(event)?);
    let mut epoch = known_policy_epoch;
    let (action, mut detail) = match event {
        AuthorityEvent::Opened { fence_token, authority_epoch, commit_sequence } => {
            ("authority.opened", format!("commit_sequence={commit_sequence} fence_token={fence_token} authority_epoch={authority_epoch}"))
        }
        AuthorityEvent::PolicyActivated { policy_epoch, policy_hash, commit_sequence } => {
            c.insert("policy".to_string(), *policy_hash);
            epoch = Some(*policy_epoch);
            ("authority.policy_activated", format!("commit_sequence={commit_sequence} policy_epoch={policy_epoch} policy_hash={policy_hash}"))
        }
        AuthorityEvent::CredentialChanged { credential_id, active, commit_sequence } => {
            c.insert("credential".to_string(), object_commitment("credential", credential_id.as_str())?);
            ("authority.credential_changed", format!("commit_sequence={commit_sequence} active={active}"))
        }
        AuthorityEvent::ApprovalRecorded { intent_id, credential_id, grant_id, commit_sequence } => {
            c.insert("intent".to_string(), object_commitment("intent", intent_id.as_str())?);
            c.insert("credential".to_string(), object_commitment("credential", credential_id.as_str())?);
            c.insert("grant".to_string(), object_commitment("grant", grant_id.as_str())?);
            ("authority.approval_recorded", format!("commit_sequence={commit_sequence}"))
        }
        AuthorityEvent::Reserved { reservation_id, commit_sequence } => {
            c.insert("reservation".to_string(), object_commitment("reservation", reservation_id.as_str())?);
            ("authority.reserved", format!("commit_sequence={commit_sequence} reservation_id={reservation_id}"))
        }
        AuthorityEvent::Released { reservation_id, issuance_id, commit_sequence } => {
            c.insert("reservation".to_string(), object_commitment("reservation", reservation_id.as_str())?);
            c.insert("issuance".to_string(), object_commitment("issuance", issuance_id.as_str())?);
            ("authority.released", format!("commit_sequence={commit_sequence} reservation_id={reservation_id} issuance_id={issuance_id}"))
        }
        AuthorityEvent::Frozen { scope, by, commit_sequence } => {
            c.insert("freeze_scope".to_string(), object_commitment("freeze_scope", &scope_text(scope))?);
            ("authority.frozen", format!("commit_sequence={commit_sequence} scope={} by={by}", scope_text(scope)))
        }
        AuthorityEvent::Unfrozen { scope, commit_sequence } => {
            c.insert("freeze_scope".to_string(), object_commitment("freeze_scope", &scope_text(scope))?);
            ("authority.unfrozen", format!("commit_sequence={commit_sequence} scope={}", scope_text(scope)))
        }
        AuthorityEvent::Aborted { reservation_id, reason, commit_sequence } => {
            c.insert("reservation".to_string(), object_commitment("reservation", reservation_id.as_str())?);
            ("authority.aborted", format!("commit_sequence={commit_sequence} reservation_id={reservation_id} reason={}", abort_text(reason)))
        }
        AuthorityEvent::Observed { family_id, candidate_id, lifecycle, commit_sequence } => {
            c.insert("operation_family".to_string(), object_commitment("operation_family", family_id.as_str())?);
            c.insert("candidate".to_string(), object_commitment("candidate", candidate_id.as_str())?);
            ("authority.observed", format!("commit_sequence={commit_sequence} family_id={family_id} candidate_id={candidate_id} lifecycle={lifecycle:?}"))
        }
    };
    if epoch.is_none() {
        detail.push_str(" policy_epoch=unknown");
    }
    Ok(AuthorityAuditEntry { action: action.to_string(), object_commitments: c, policy_epoch: epoch.unwrap_or(Epoch(0)), detail })
}

/// [`AuditSink`] that appends one audit event per [`AuthorityEvent`].
///
/// `AuditSink::record` returns `()`, so append failures cannot propagate to
/// the authority (which has already committed the change being reported).
/// Instead every failure increments [`failure_count`](Self::failure_count)
/// and is kept in [`last_error`](Self::last_error). Operators MUST monitor
/// these: a non-zero failure count means the audit log is missing authority
/// events and the relevant scope should be reviewed (RFC 0001 §14).
///
/// The sink remembers the latest policy epoch it has seen (from
/// `PolicyActivated`, or seeded with [`with_policy_epoch`](Self::with_policy_epoch))
/// and stamps it on subsequent events.
pub struct AuthorityAuditSink {
    log: Arc<dyn AuditLog>,
    actor: String,
    policy_epoch: Mutex<Option<Epoch>>,
    last_error: Mutex<Option<OicError>>,
    failures: AtomicU64,
    recorded: AtomicU64,
}

impl AuthorityAuditSink {
    /// `actor` identifies the authority instance in every event (e.g.
    /// `"authority:inst-1/testnet"`).
    pub fn new(log: Arc<dyn AuditLog>, actor: impl Into<String>) -> Self {
        AuthorityAuditSink {
            log,
            actor: actor.into(),
            policy_epoch: Mutex::new(None),
            last_error: Mutex::new(None),
            failures: AtomicU64::new(0),
            recorded: AtomicU64::new(0),
        }
    }

    /// Seed the policy epoch known to be active when the sink is attached.
    pub fn with_policy_epoch(self, epoch: Epoch) -> Self {
        *self.policy_epoch.lock() = Some(epoch);
        self
    }

    /// The most recent append failure, if any.
    pub fn last_error(&self) -> Option<OicError> {
        self.last_error.lock().clone()
    }

    /// Number of authority events that could not be appended.
    pub fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::SeqCst)
    }

    /// Number of authority events successfully appended.
    pub fn recorded_count(&self) -> u64 {
        self.recorded.load(Ordering::SeqCst)
    }

    /// Policy epoch the sink currently stamps on events.
    pub fn known_policy_epoch(&self) -> Option<Epoch> {
        *self.policy_epoch.lock()
    }

    fn try_record(&self, event: &AuthorityEvent) -> OicResult<()> {
        // Hold the epoch lock across mapping and append so concurrent records
        // observe policy activations in the order they are appended.
        let mut epoch = self.policy_epoch.lock();
        if let AuthorityEvent::PolicyActivated { policy_epoch, .. } = event {
            *epoch = Some(*policy_epoch);
        }
        let entry = authority_event_entry(event, *epoch)?;
        self.log.append(&self.actor, &entry.action, entry.object_commitments, entry.policy_epoch, &entry.detail)?;
        Ok(())
    }
}

impl AuditSink for AuthorityAuditSink {
    fn record(&self, event: &AuthorityEvent) {
        match self.try_record(event) {
            Ok(()) => {
                self.recorded.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                self.failures.fetch_add(1, Ordering::SeqCst);
                *self.last_error.lock() = Some(e);
            }
        }
    }
}
