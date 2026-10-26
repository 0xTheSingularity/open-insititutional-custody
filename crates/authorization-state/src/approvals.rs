//! Ordered, administratively enrolled approval credentials and recorded grants.
//! Enabling this profile is irreversible. Legacy D1 keeps its trusted-kernel
//! contract until enabled; it cannot accept WebAuthn without enrollment.

use crate::{AuthorityConfig, AuthorityEvent, AuthorityState, ReservationState};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use oic_policy_kernel::{count_quorum_signatures, intent_hash, verify_grant_counter, verify_grants, ApproverCredential, ApproverKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_APPROVER_CREDENTIALS: usize = 1024;

/// An immutable credential identity; `None` permanently retires it. Replacement
/// uses a new credential ID, so old assertions cannot revive after re-enrollment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledApprover {
    pub credential: Option<ApproverCredential>,
    /// Retained after removal so retiring a proposer credential cannot erase
    /// the person's identity and enable self-approval under another key.
    pub person_id: CredentialId,
    pub commit_sequence: u64,
    /// Highest WebAuthn signature counter recorded for this credential.
    /// Zero (never counted) is not encoded, so existing state keeps its hash.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub last_sign_count: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedApprovals {
    pub credentials: BTreeMap<CredentialId, EnrolledApprover>,
    pub grants: BTreeMap<IntentId, BTreeMap<CredentialId, RecordedApproval>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedApproval {
    pub grant: ApprovalGrant,
    pub credential_commit_sequence: u64,
    pub commit_sequence: u64,
}

/// Admin-quorum-signed configuration. `previous_change` is zero for a new ID,
/// or that credential's last ordered change for removal; not a caller clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialChange {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub credential_id: CredentialId,
    pub previous_change: u64,
    pub credential: Option<ApproverCredential>,
}

impl CredentialChange {
    pub fn hash(&self) -> OicResult<Hash32> {
        domain_hash("OIC/APPROVAL_CREDENTIAL_CHANGE/v1", self)
    }
}

pub(crate) fn change_credential(
    config: &AuthorityConfig,
    state: &mut AuthorityState,
    proposal: CredentialChange,
    signatures: &[CredentialSignature],
) -> OicResult<(u64, AuthorityEvent)> {
    if proposal.institution_id != config.institution_id || proposal.environment_id != config.environment_id {
        return Err(OicError::scope("credential change belongs to another authority scope"));
    }
    if config.admin_quorum == 0 || count_quorum_signatures(&proposal.hash()?.0, signatures, &config.admin_keys) < usize::from(config.admin_quorum) {
        return Err(OicError::invalid_signature("credential change requires the administrative quorum"));
    }
    let previous = state.ordered_approvals.as_ref().and_then(|a| a.credentials.get(&proposal.credential_id));
    if previous.map_or(0, |c| c.commit_sequence) != proposal.previous_change {
        return Err(OicError::new(ErrorCode::Conflict, "credential configuration changed"));
    }
    match &proposal.credential {
        Some(credential) => {
            credential.validate()?;
            if credential.credential_id != proposal.credential_id || previous.is_some() {
                return Err(OicError::new(ErrorCode::Conflict, "credential identities are immutable and cannot be reused"));
            }
            if state.ordered_approvals.as_ref().is_some_and(|a| a.credentials.len() >= MAX_APPROVER_CREDENTIALS) {
                return Err(OicError::invalid_request("approval credential capacity reached"));
            }
            if config.admin_keys.iter().chain(&config.freeze_responders).any(|(id, _)| id == &credential.credential_id) {
                return Err(OicError::invalid_request("approval and administrative credential identities must be separate"));
            }
            if let ApproverKey::Ed25519(key) = &credential.verifying_key {
                if config.admin_keys.iter().chain(&config.freeze_responders).any(|(_, k)| k == key) {
                    return Err(OicError::invalid_request("approval and administrative credentials must be separate"));
                }
            }
            if state.ordered_approvals.as_ref().is_some_and(|a| {
                a.credentials.values().any(|other| other.credential.as_ref().is_some_and(|c| same_key(&c.verifying_key, &credential.verifying_key)))
            }) {
                return Err(OicError::invalid_request("approval public key already enrolled"));
            }
        }
        None if previous.is_none_or(|p| p.credential.is_none()) => {
            return Err(OicError::new(ErrorCode::NotFound, "active approval credential not found"));
        }
        None => {}
    }
    if state.ordered_approvals.is_none() && state.reservations.values().any(|r| r.state == ReservationState::Reserved) {
        return Err(OicError::new(ErrorCode::Conflict, "abort pending legacy reservations before enabling ordered approvals"));
    }
    let person_id =
        proposal.credential.as_ref().map(|c| c.person_id.clone()).or_else(|| previous.map(|c| c.person_id.clone())).expect("validated credential change");
    state.commit_sequence = state.commit_sequence.checked_add(1).ok_or_else(|| OicError::internal("commit sequence exhausted"))?;
    let seq = state.commit_sequence;
    let active = proposal.credential.is_some();
    state
        .ordered_approvals
        .get_or_insert_default()
        .credentials
        .insert(proposal.credential_id.clone(), EnrolledApprover { credential: proposal.credential, person_id, commit_sequence: seq, last_sign_count: 0 });
    Ok((seq, AuthorityEvent::CredentialChanged { credential_id: proposal.credential_id, active, commit_sequence: seq }))
}

fn same_key(a: &ApproverKey, b: &ApproverKey) -> bool {
    match (a, b) {
        (ApproverKey::Ed25519(a), ApproverKey::Ed25519(b)) => a == b,
        (ApproverKey::WebAuthn { public_key_sec1: a, .. }, ApproverKey::WebAuthn { public_key_sec1: b, .. }) => a == b,
        _ => false,
    }
}

pub(crate) fn approve(
    config: &AuthorityConfig,
    state: &mut AuthorityState,
    intent: &Intent,
    grant: ApprovalGrant,
    now: UnixSeconds,
) -> OicResult<(u64, AuthorityEvent)> {
    let approvals = state.ordered_approvals.as_ref().ok_or_else(|| OicError::invalid_request("ordered approvals are not enabled"))?;
    let registered = state.intents.get(&intent.intent_id).ok_or_else(|| OicError::new(ErrorCode::NotFound, "intent not registered"))?;
    let body = &grant.body;
    if intent_hash(intent)? != registered.intent_hash
        || intent.vault_id != registered.vault_id
        || intent.institution_id != config.institution_id
        || intent.environment_id != config.environment_id
        || body.intent_id != intent.intent_id
        || body.intent_hash != registered.intent_hash
        || body.vault_id != intent.vault_id
        || body.institution_id != config.institution_id
        || body.environment_id != config.environment_id
    {
        return Err(OicError::scope("approval is not bound to the registered intent"));
    }
    let policy = state.policy.as_ref().ok_or_else(|| OicError::new(ErrorCode::StalePolicy, "no active policy"))?;
    if body.policy_id != policy.policy_id || body.policy_epoch != state.policy_epoch {
        return Err(OicError::new(ErrorCode::StalePolicy, "approval policy is not current"));
    }
    if state.freeze.blocking(&intent.vault_id).is_some() {
        return Err(OicError::new(ErrorCode::Frozen, "approval scope is frozen"));
    }
    let credentials: Vec<_> = approvals.credentials.values().filter_map(|r| r.credential.clone()).collect();
    let sign_count = verify_grant_counter(&grant, &credentials, now)?;
    let record = &approvals.credentials[&body.approver_credential_id];
    let credential = record.credential.as_ref().expect("verified enrollment");
    if body.approver_credential_id == intent.proposer_credential_id
        || approvals.credentials.get(&intent.proposer_credential_id).is_some_and(|proposer| proposer.person_id == credential.person_id)
    {
        return Err(OicError::policy_denied("proposer cannot approve their own intent"));
    }
    let previous = approvals.grants.get(&intent.intent_id);
    if previous.is_some_and(|grants| grants.contains_key(&body.approver_credential_id)) {
        return Err(OicError::new(ErrorCode::Conflict, "credential already approved this intent"));
    }
    if previous.is_some_and(|grants| grants.len() >= oic_policy_kernel::MAX_GRANTS) {
        return Err(OicError::invalid_request("approval grant capacity reached"));
    }
    // WebAuthn: when either counter is nonzero, a counter that did not
    // increase means the authenticator may have been cloned.
    if let Some(count) = sign_count {
        if (count != 0 || record.last_sign_count != 0) && count <= record.last_sign_count {
            return Err(OicError::invalid_signature("authenticator signature counter did not increase; the authenticator may be cloned"));
        }
    }
    let mut grants: Vec<_> = previous.into_iter().flat_map(|grants| grants.values().map(|g| g.grant.clone())).collect();
    // Removed/expired approvals remain historical records, not quorum members.
    grants.retain(|g| credentials.iter().any(|c| c.credential_id == g.body.approver_credential_id) && g.body.expires_at > now);
    grants.push(grant.clone());
    verify_grants(&grants, &credentials, now)?;
    let credential_commit_sequence = record.commit_sequence;
    let credential_id = body.approver_credential_id.clone();
    let grant_id = body.grant_id.clone();
    state.commit_sequence = state.commit_sequence.checked_add(1).ok_or_else(|| OicError::internal("commit sequence exhausted"))?;
    let seq = state.commit_sequence;
    let ordered = state.ordered_approvals.as_mut().expect("enabled");
    if let (Some(count), Some(record)) = (sign_count, ordered.credentials.get_mut(&credential_id)) {
        record.last_sign_count = count;
    }
    ordered
        .grants
        .entry(intent.intent_id.clone())
        .or_default()
        .insert(credential_id.clone(), RecordedApproval { grant, credential_commit_sequence, commit_sequence: seq });
    Ok((seq, AuthorityEvent::ApprovalRecorded { intent_id: intent.intent_id.clone(), credential_id, grant_id, commit_sequence: seq }))
}

pub(crate) fn require_recorded_grants(state: &AuthorityState, grants: &[ApprovalGrant], now: UnixSeconds) -> OicResult<()> {
    let Some(approvals) = &state.ordered_approvals else {
        if grants.iter().any(|g| g.signature.scheme == SchemeId::WebAuthnEs256) {
            return Err(OicError::invalid_signature("WebAuthn approval requires ordered enrollment"));
        }
        return Ok(());
    };
    let credentials: Vec<_> = approvals.credentials.values().filter_map(|r| r.credential.clone()).collect();
    verify_grants(grants, &credentials, now)?;
    for grant in grants {
        let body = &grant.body;
        let credential = &approvals.credentials[&body.approver_credential_id];
        let recorded = approvals.grants.get(&body.intent_id).and_then(|g| g.get(&body.approver_credential_id));
        if !recorded.is_some_and(|r| r.grant == *grant && r.credential_commit_sequence == credential.commit_sequence) {
            return Err(OicError::new(ErrorCode::ApprovalRequired, "grant is not recorded under the active credential"));
        }
    }
    Ok(())
}
