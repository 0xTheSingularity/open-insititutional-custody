//! Optional caller-enforced verification quorum (RFC 0003 §§5.1, 7).
//!
//! These objects are evidence, never a replacement for signer-local evaluation.
//! Constructing a collector does not activate a policy rule. The caller must
//! choose the requirement and independently derive the expected input snapshot
//! from trusted candidate, evidence, and committed policy/roster state.

use super::{require, roster_hash, verifying_key, CommitteeKind, PeerClass, SignedRoster};
use ed25519_dalek::{Signature, Signer, SigningKey};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The identical-input comparison excludes the attestor, its build, and the
/// attestation timestamps; independent verifiers may differ on those fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationInputs {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub roster_epoch: u64,
    pub roster_hash: Hash32,
    pub adapter_id: AdapterId,
    pub adapter_version: String,
    pub intent_hash: Hash32,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub decoded_operation_hash: Hash32,
    pub evidence_bundle_hash: Hash32,
    pub policy_id: PolicyId,
    pub policy_epoch: Epoch,
    pub policy_hash: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationDecision {
    Allow,
    Deny,
    RequireApprovals,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationAttestationBody {
    pub inputs: VerificationInputs,
    pub node_id: NodeId,
    pub verifier_build_hash: Hash32,
    pub decision: VerificationDecision,
    /// Stable operator-facing codes. They are signed but are not a different
    /// decision when only ordering or explanatory detail differs.
    pub reason_codes: Vec<String>,
    pub attested_at: UnixSeconds,
    /// Exclusive upper bound, committed by the signature.
    pub expires_at: UnixSeconds,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationAttestation {
    pub body: VerificationAttestationBody,
    pub signature: SignatureBytes,
}

pub fn attestation_hash(body: &VerificationAttestationBody) -> OicResult<Hash32> {
    domain_hash(domains::VERIFY_ATTESTATION, body)
}

/// Signing does not endorse the body or run the kernel. The caller must first
/// evaluate the exact bound inputs locally using an approved verifier build.
pub fn sign_attestation(key: &SigningKey, body: VerificationAttestationBody) -> OicResult<VerificationAttestation> {
    let hash = attestation_hash(&body)?;
    let signature = SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(key.sign(hash.as_ref()).to_bytes().to_vec()) };
    Ok(VerificationAttestation { body, signature })
}

fn check_inputs(roster: &SignedRoster, inputs: &VerificationInputs) -> OicResult<()> {
    let b = &roster.body;
    if inputs.institution_id != b.institution_id || inputs.environment_id != b.environment_id {
        return Err(OicError::scope("attestation institution or environment mismatch"));
    }
    if inputs.roster_epoch != b.roster_epoch || inputs.roster_hash != roster_hash(b)? {
        return Err(OicError::new(ErrorCode::RosterMismatch, "attestation roster epoch or hash mismatch"));
    }
    Ok(())
}

/// Verify evidence against an already-validated active roster and a locally
/// derived expected snapshot, not fields taken from the received attestation.
pub fn verify_attestation(attestation: &VerificationAttestation, roster: &SignedRoster, expected: &VerificationInputs, now: UnixSeconds) -> OicResult<()> {
    check_inputs(roster, expected)?;
    let b = &attestation.body;
    if b.inputs != *expected {
        return Err(OicError::scope("attestation input bindings differ from expected snapshot"));
    }
    let node = roster.node(&b.node_id).ok_or_else(|| OicError::new(ErrorCode::PeerNotAdmitted, "attestor is not in the roster"))?;
    if node.peer_class != PeerClass::Primary || !roster.verifier(node) {
        return Err(OicError::new(ErrorCode::PeerNotAdmitted, "attestor is not a roster verifier"));
    }
    if !node.approved_build_hashes.contains(&b.verifier_build_hash) {
        return Err(OicError::policy_denied("attestor build is not approved"));
    }
    if b.attested_at < roster.body.activation.not_before || b.expires_at <= b.attested_at || now < b.attested_at || now >= b.expires_at {
        return Err(OicError::stale_evidence("attestation is not currently valid"));
    }
    let key = node.attestation_key.as_ref().ok_or_else(|| OicError::invalid_signature("attestor lacks a roster attestation key"))?;
    if attestation.signature.scheme != SchemeId::Ed25519Pure {
        return Err(OicError::invalid_signature("attestation signature must use Ed25519Pure"));
    }
    let signature =
        Signature::from_slice(attestation.signature.bytes.as_slice()).map_err(|_| OicError::invalid_signature("malformed attestation signature"))?;
    verifying_key(key)?
        .verify_strict(attestation_hash(b)?.as_ref(), &signature)
        .map_err(|_| OicError::invalid_signature("attestation signature does not verify"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRequirement {
    pub committee_id: CommitteeId,
    pub threshold: u16,
    pub require_distinct_domains: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumStatus {
    Pending,
    /// A deny/approval quorum is evidence of that decision, not authorization.
    Reached(VerificationDecision),
    Quarantined,
}

/// One caller-owned input snapshot, with no global state, persistence, or I/O.
/// The roster borrow prevents changing membership underneath this collector.
/// After disagreement, both signed objects remain available for caller-owned
/// audit/alert storage; this collector can never clear its quarantine.
pub struct AttestationQuorum<'a> {
    roster: &'a SignedRoster,
    inputs: VerificationInputs,
    requirement: AttestationRequirement,
    members: BTreeSet<NodeId>,
    attestations: BTreeMap<NodeId, VerificationAttestation>,
    conflict: Option<(VerificationAttestation, VerificationAttestation)>,
}

impl<'a> AttestationQuorum<'a> {
    /// The requirement must not weaken the roster committee's threshold.
    pub fn new(roster: &'a SignedRoster, inputs: VerificationInputs, requirement: AttestationRequirement) -> OicResult<Self> {
        check_inputs(roster, &inputs)?;
        let committee = roster
            .body
            .committees
            .iter()
            .find(|c| c.committee_id == requirement.committee_id)
            .ok_or_else(|| OicError::invalid_request("unknown attestation committee"))?;
        require(matches!(committee.kind, CommitteeKind::Verification), "attestations require a verification committee")?;
        require(requirement.threshold > 0 && requirement.threshold >= committee.threshold, "attestation threshold weakens roster committee")?;
        let mut members = BTreeSet::new();
        let mut domains = BTreeSet::new();
        for id in &committee.members {
            let node = roster.node(id).ok_or_else(|| OicError::invalid_request("unknown attestation committee member"))?;
            require(node.peer_class == PeerClass::Primary && roster.verifier(node) && node.attestation_key.is_some(), "invalid attestation committee member")?;
            members.insert(id.clone());
            domains.insert(&node.domain_id);
        }
        require(usize::from(requirement.threshold) <= members.len(), "attestation threshold exceeds distinct committee nodes")?;
        require(
            !requirement.require_distinct_domains || usize::from(requirement.threshold) <= domains.len(),
            "attestation threshold exceeds distinct committee domains",
        )?;
        Ok(Self { roster, inputs, requirement, members, attestations: BTreeMap::new(), conflict: None })
    }

    /// Invalid or different-input objects are rejected without changing state.
    /// Every authenticated roster verifier can expose disagreement, including
    /// non-quorum members; only the selected committee counts toward quorum.
    pub fn add(&mut self, attestation: VerificationAttestation, now: UnixSeconds) -> OicResult<QuorumStatus> {
        if self.conflict.is_some() {
            return Err(OicError::new(ErrorCode::AttestationDisagreement, "verification input is quarantined"));
        }
        verify_attestation(&attestation, self.roster, &self.inputs, now)?;
        if let Some(prior) = self.attestations.values().find(|prior| prior.body.decision != attestation.body.decision) {
            self.conflict = Some((prior.clone(), attestation));
            return Err(OicError::new(ErrorCode::AttestationDisagreement, "approved verifiers disagree on identical inputs"));
        }
        // A node can renew its evidence, but cannot supply a second vote.
        let id = attestation.body.node_id.clone();
        if self.attestations.get(&id).is_none_or(|prior| attestation.body.attested_at > prior.body.attested_at) {
            self.attestations.insert(id, attestation);
        }
        Ok(self.status(now))
    }

    /// Expiration is re-evaluated on every use, not only at ingestion.
    pub fn status(&self, now: UnixSeconds) -> QuorumStatus {
        if self.conflict.is_some() {
            return QuorumStatus::Quarantined;
        }
        let mut nodes = 0;
        let mut domains = BTreeSet::new();
        let mut decision = None;
        for (id, attestation) in &self.attestations {
            let b = &attestation.body;
            if self.members.contains(id) && b.attested_at <= now && now < b.expires_at {
                nodes += 1;
                domains.insert(&self.roster.node(id).expect("member belongs to borrowed roster").domain_id);
                decision = Some(b.decision);
            }
        }
        let threshold = usize::from(self.requirement.threshold);
        if nodes >= threshold && (!self.requirement.require_distinct_domains || domains.len() >= threshold) {
            QuorumStatus::Reached(decision.expect("positive threshold has a decision"))
        } else {
            QuorumStatus::Pending
        }
    }

    /// The fail-closed caller gate: a reached DENY or REQUIRE_APPROVALS quorum
    /// never becomes success merely because the signature count is sufficient.
    pub fn require_allow(&self, now: UnixSeconds) -> OicResult<()> {
        match self.status(now) {
            QuorumStatus::Reached(VerificationDecision::Allow) => Ok(()),
            QuorumStatus::Reached(VerificationDecision::Deny) => Err(OicError::policy_denied("verification quorum denied the operation")),
            QuorumStatus::Reached(VerificationDecision::RequireApprovals) => {
                Err(OicError::new(ErrorCode::ApprovalRequired, "verification quorum requires approvals"))
            }
            QuorumStatus::Pending => Err(OicError::new(ErrorCode::ApprovalRequired, "verification attestation quorum not met")),
            QuorumStatus::Quarantined => Err(OicError::new(ErrorCode::AttestationDisagreement, "verification input is quarantined")),
        }
    }

    pub fn conflict(&self) -> Option<(&VerificationAttestation, &VerificationAttestation)> {
        self.conflict.as_ref().map(|(first, second)| (first, second))
    }
}
