use crate::{
    History, JournalFloor, WitnessRecord, WitnessTrust, invalid, replay_record, require,
    verify_floor_prefix,
};
use oic_audit::{
    AuditCheckpoint, CheckpointComparison, authority_event_entry, compare_checkpoints, verify_chain,
};
use oic_authorization_state::{
    AuthorityEvent, ReceiptExpectation, SignedCheckpoint, verify_receipt,
};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use oic_membership::{COMMONWARE_RELEASE, SignedRoster};
use oic_policy_kernel::{policy_hash, verify_policy_admin_signatures};
use oic_service_reconciler::OperationsExport;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Full signed per-node journal, including confidential detail. It is NEVER a
/// public witness message. Sequence 1 through the checkpoint must be present.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeJournal {
    pub node_id: NodeId,
    pub checkpoint: AuditCheckpoint,
    pub events: Vec<AuditEvent>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActivation {
    pub policy: PolicyBundle,
    pub event: AuthorityEvent,
    /// Must be present in the authority node's verified full audit journal.
    pub audit_event: AuditEvent,
}

/// Business artifact provenance is bound by the independent export commitment.
/// Native-chain signature/observation validity still requires that chain's
/// adapter and independent evidence; this witness does not assert those facts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasedSignature {
    pub issuance_id: IssuanceId,
    pub signature: SignatureBytes,
    pub observations: Vec<ChainObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildMetadata {
    pub node_id: NodeId,
    pub roster_epoch: u64,
    pub commonware_release: String,
    pub build_hash: Hash32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportArtifacts {
    pub operations: OperationsExport,
    pub policy_activations: Vec<PolicyActivation>,
    pub receipts: Vec<AuthorityReceipt>,
    pub issuance: Vec<IssuanceRecord>,
    pub journals: Vec<NodeJournal>,
    pub signatures: Vec<ReleasedSignature>,
    pub builds: Vec<BuildMetadata>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportBundle {
    pub version: u16,
    pub rosters: Vec<SignedRoster>,
    pub witness_records: Vec<WitnessRecord>,
    pub artifacts: ExportArtifacts,
}

impl fmt::Debug for ExportBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportBundle")
            .field("version", &self.version)
            .field("contents", &"[CONFIDENTIAL]")
            .finish()
    }
}

/// Retain/deliver this hash through an independent trusted channel. In
/// particular, never trust a hash simply included alongside an untrusted bundle.
/// It binds unsigned business maps, inclusion/completeness, and chain artifacts
/// that the individual service signatures do not cover.
pub fn export_hash(bundle: &ExportBundle) -> OicResult<Hash32> {
    domain_hash("OIC/WITNESS_EXPORT/v1", bundle)
}

/// Independently reconstructed witness and operations heads. A nonempty
/// evidence vector means quarantine, not a "valid therefore safe" endorsement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reconstruction {
    pub floor: JournalFloor,
    pub authority_checkpoint: Option<SignedCheckpoint>,
    pub audit_checkpoints: BTreeMap<KeyId, AuditCheckpoint>,
    pub evidence: Vec<crate::DivergenceEvidence>,
    pub operations_revision: u64,
    pub journal_head: (u64, Hash32),
    pub lifecycle_sequence: u64,
}

/// Pure offline verification: uses no local witness storage and contacts no
/// service. Trust keys, roster activation commitments, expected bundle hash and
/// minimum journal floor MUST be independently obtained. Historical signatures
/// are checked at their recorded observation/issuance times, not at export time.
/// This reconstructs supplied history; it cannot discover omitted real-world
/// events beyond the independently retained commitments/floors.
pub fn verify_export(
    bundle: &ExportBundle,
    trust: &WitnessTrust,
    expected_hash: Hash32,
    minimum_floor: JournalFloor,
    now: UnixSeconds,
) -> OicResult<Reconstruction> {
    require(
        bundle.version == 1 && export_hash(bundle)? == expected_hash,
        "offline export commitment mismatch",
    )?;
    require(
        minimum_floor.records != 0 || minimum_floor.head_hash == Hash32::ZERO,
        "invalid empty export floor",
    )?;
    // Verify the EXPORTED signed chain against external anchors, not the chain
    // handed to the online witness, and replay with that validated chain.
    let mut trust = trust.clone();
    trust.rosters = bundle.rosters.clone();
    trust.validate(now)?;
    let mut history = History::default();
    let mut head = JournalFloor::EMPTY;
    for record in &bundle.witness_records {
        replay_record(record, &trust, &mut history, &mut head)?;
        verify_floor_prefix(minimum_floor, head)?;
    }
    require(
        head.records >= minimum_floor.records,
        "offline witness history below independent floor",
    )?;
    let artifacts = &bundle.artifacts;
    verify_operations(&artifacts.operations, &trust)?;
    for journal in &artifacts.journals {
        let key = trust.audit(&journal.checkpoint.body.service_key_id)?;
        require(
            journal.node_id == key.node_id,
            "offline audit node identity mismatch",
        )?;
        oic_audit::verify_checkpoint(&journal.checkpoint, &key.key)?;
        require(
            journal
                .events
                .iter()
                .all(|e| e.service_key_id == key.key_id),
            "offline audit event key identity mismatch",
        )?;
        let actual = verify_chain(&journal.events, &key.key, None)?;
        require(
            actual
                == (
                    journal.checkpoint.body.sequence,
                    journal.checkpoint.body.head_event_hash,
                ),
            "offline audit checkpoint does not match full journal",
        )?;
    }
    // Every retained honest audit head needs a reconstructible full history.
    // Conflicting checkpoint proofs remain in witness_records/evidence even
    // when only the primary retained branch has a full exported journal.
    for (id, (_, checkpoint)) in &history.audits {
        let key = trust.audit(id)?;
        let mut covered = false;
        for journal in artifacts.journals.iter().filter(|j| {
            &j.checkpoint.body.service_key_id == id
                && j.checkpoint.body.sequence >= checkpoint.body.sequence
        }) {
            let start = usize::try_from(checkpoint.body.sequence)
                .map_err(|_| invalid("offline audit sequence overflow"))?;
            let bridge = journal
                .events
                .get(start..)
                .ok_or_else(|| invalid("offline audit prefix missing"))?;
            covered |= !matches!(
                compare_checkpoints(checkpoint, &journal.checkpoint, &key.key, bridge)?,
                CheckpointComparison::Diverged { .. }
            );
        }
        require(
            covered,
            "offline export lacks full journal for retained audit checkpoint",
        )?;
    }
    for activation in &artifacts.policy_activations {
        let policy = &activation.policy;
        require(
            policy.institution_id == trust.institution_id
                && policy.environment_id == trust.environment_id,
            "offline policy scope mismatch",
        )?;
        verify_policy_admin_signatures(
            policy,
            &trust.policy_admin_keys,
            trust.policy_admin_quorum,
        )?;
        let AuthorityEvent::PolicyActivated {
            policy_epoch,
            policy_hash: committed,
            ..
        } = &activation.event
        else {
            return Err(invalid("offline policy proof is not an activation"));
        };
        require(
            *policy_epoch == policy.policy_epoch && *committed == policy_hash(policy)?,
            "offline policy activation binding mismatch",
        )?;
        let expected = authority_event_entry(&activation.event, Some(policy.policy_epoch))?;
        let e = &activation.audit_event;
        let key = trust.audit(&e.service_key_id)?;
        require(
            key.node_id == trust.authority.node_id,
            "policy activation audit key is not authority's",
        )?;
        require(
            e.body.action == expected.action
                && e.body.object_commitments == expected.object_commitments
                && e.body.policy_epoch == expected.policy_epoch
                && e.body.detail == expected.detail,
            "policy activation audit commitment mismatch",
        )?;
        require(
            artifacts
                .journals
                .iter()
                .any(|j| j.node_id == key.node_id && j.events.contains(e)),
            "policy activation absent from verified journal",
        )?;
    }
    for receipt in &artifacts.receipts {
        let b = &receipt.body;
        require(
            b.institution_id == trust.institution_id
                && b.environment_id == trust.environment_id
                && receipt.authority_key_id == trust.authority.key_id,
            "offline receipt scope or key mismatch",
        )?;
        verify_receipt(
            receipt,
            &trust.authority.key,
            &ReceiptExpectation {
                kind: b.kind,
                envelope_body_hash: b.envelope_body_hash,
                signer_session_id: b.signer_session_id.clone(),
                candidate_id: b.candidate_id.clone(),
                candidate_revision: b.candidate_revision,
                now: b.issued_at,
                policy_epoch: b.policy_epoch,
            },
        )?;
    }
    let mut issuance_ids = BTreeSet::new();
    for issued in &artifacts.issuance {
        require(
            issuance_ids.insert(&issued.issuance_id),
            "duplicate offline issuance identity",
        )?;
        require(
            artifacts.receipts.iter().any(|r| {
                let b = &r.body;
                b.kind == ReceiptKind::Release
                    && b.commit_sequence == issued.commit_sequence
                    && b.candidate_id == issued.candidate_id
                    && b.candidate_revision == issued.candidate_revision
                    && b.envelope_body_hash == issued.envelope_hash
                    && b.signer_session_id == issued.signer_session_id
                    && b.issued_at == issued.committed_at
            }),
            "offline issuance lacks matching signed release",
        )?;
    }
    for signature in &artifacts.signatures {
        require(
            issuance_ids.contains(&signature.issuance_id),
            "offline signature lacks issuance record",
        )?;
    }
    for build in &artifacts.builds {
        let roster = trust.roster(build.roster_epoch)?;
        let node = roster
            .node(&build.node_id)
            .ok_or_else(|| invalid("unknown offline build node"))?;
        require(
            build.commonware_release == COMMONWARE_RELEASE
                && node.approved_build_hashes.contains(&build.build_hash),
            "offline build not roster approved",
        )?;
    }
    let journal_head = artifacts
        .operations
        .journal
        .last()
        .map(|e| (e.body.sequence, e.entry_hash))
        .unwrap_or((0, Hash32::ZERO));
    Ok(Reconstruction {
        floor: head,
        authority_checkpoint: history.authority.map(|(_, c)| c),
        audit_checkpoints: history
            .audits
            .into_iter()
            .map(|(k, (_, c))| (k, c))
            .collect(),
        evidence: history.evidence,
        operations_revision: artifacts.operations.revision,
        journal_head,
        lifecycle_sequence: artifacts.operations.events.len() as u64,
    })
}

fn verify_operations(operations: &OperationsExport, trust: &WitnessTrust) -> OicResult<()> {
    require(
        operations.institution_id.as_ref() == Some(&trust.institution_id)
            && operations.environment_id.as_ref() == Some(&trust.environment_id),
        "offline operations scope mismatch",
    )?;
    operations.verify(&trust.operations.key)?;
    for entry in &operations.journal {
        require(
            entry.body.institution_id == trust.institution_id
                && entry.body.environment_id == trust.environment_id,
            "offline journal scope mismatch",
        )?;
    }
    for event in &operations.events {
        require(
            event.signing_key_id == trust.operations.key_id
                && event.body.institution_id == trust.institution_id
                && event.body.environment_id == trust.environment_id,
            "offline lifecycle scope or key mismatch",
        )?;
    }
    require(
        operations
            .checkpoints
            .iter()
            .all(|c| c.reconciler_key_id == trust.operations.key_id),
        "offline reconciler key identity mismatch",
    )
}
