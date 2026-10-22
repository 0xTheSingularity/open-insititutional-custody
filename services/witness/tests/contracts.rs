mod common;
use common::{checkpoint, key, node_id, signature, trust};

use commonware_runtime::{Runner, Storage, Supervisor, buffer::paged::CacheRef, deterministic};
use commonware_storage::journal::segmented::variable::{Config, Journal};
use commonware_utils::{NZU16, NZUsize};
use oic_audit::{AuditLog, AuditLogConfig, MemoryAuditLog, authority_event_entry};
use oic_authorization_state::{AuthorityEvent, ManualClock, checkpoint_hash, receipt_hash};
use oic_canonical_encoding::{canonical_bytes, domain_hash, from_canonical_bytes};
use oic_domain_types::*;
use oic_membership::*;
use oic_peer_wire::{FrameKind, PeerFrameV1};
use oic_policy_kernel::policy_hash;
use oic_service_reconciler::OperationsExport;
use oic_service_witness::*;
use std::{collections::BTreeMap, sync::Arc};

fn log() -> MemoryAuditLog {
    MemoryAuditLog::new(AuditLogConfig::new(
        KeyId::unchecked("audit-key"),
        key(61),
        Arc::new(ManualClock::new(50)),
    ))
}
fn append(log: &MemoryAuditLog, action: &str) -> AuditEvent {
    log.append("authority", action, BTreeMap::new(), Epoch(1), "")
        .unwrap()
}
fn attestation(n: u8, candidate: &str, decision: VerificationDecision) -> VerificationAttestation {
    let roster = &trust().rosters[0];
    sign_attestation(
        &key(30 + n),
        VerificationAttestationBody {
            inputs: VerificationInputs {
                institution_id: roster.body.institution_id.clone(),
                environment_id: roster.body.environment_id.clone(),
                roster_epoch: 0,
                roster_hash: roster_hash(&roster.body).unwrap(),
                adapter_id: AdapterId::unchecked("evm"),
                adapter_version: "1".into(),
                intent_hash: Hash32([1; 32]),
                candidate_id: CandidateId::unchecked(candidate),
                candidate_revision: 3,
                decoded_operation_hash: Hash32([2; 32]),
                evidence_bundle_hash: Hash32([3; 32]),
                policy_id: PolicyId::unchecked("policy"),
                policy_epoch: Epoch(7),
                policy_hash: Hash32([4; 32]),
            },
            node_id: node_id(n),
            verifier_build_hash: Hash32([42; 32]),
            decision,
            reason_codes: vec!["POLICY_RESULT".into()],
            attested_at: UnixSeconds(40),
            expires_at: UnixSeconds(80),
        },
    )
    .unwrap()
}
async fn send(
    w: &mut Witness<deterministic::Context>,
    message: WitnessMessage,
    at: u64,
) -> OicResult<Observation> {
    let epoch = w.active_roster(UnixSeconds(at))?.body.roster_epoch;
    let frame = PeerFrameV1::encode_public(&message, epoch, FrameKind::Audit, 65536)
        .map_err(|_| OicError::invalid_request("test Audit frame encode rejected"))?;
    let frame = PeerFrameV1::decode(&frame, epoch, FrameKind::Audit, 65536)
        .map_err(|_| OicError::invalid_request("test Audit frame decode rejected"))?;
    w.handle_authenticated(&node_id(0), WITNESS_CHANNEL, frame.body(), UnixSeconds(at))
        .await
}

#[test]
fn honest_extension_reopen_and_independent_rollback_floors() {
    deterministic::Runner::default().start(|context| async move {
        let mut w = Witness::open(
            context.child("first"),
            "honest".into(),
            trust(),
            JournalFloor::EMPTY,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        assert_eq!(w.node_id(), &node_id(3));
        assert_eq!(
            w.active_roster(UnixSeconds(99)).unwrap().body.roster_epoch,
            0
        );
        assert_eq!(
            w.active_roster(UnixSeconds(100)).unwrap().body.roster_epoch,
            1
        );
        assert_eq!(
            send(
                &mut w,
                WitnessMessage::AuthorityCheckpoint(checkpoint(4, 4)),
                50
            )
            .await
            .unwrap(),
            Observation::Recorded
        );
        let prefix_floor = w.floor();
        assert_eq!(
            send(
                &mut w,
                WitnessMessage::AuthorityCheckpoint(checkpoint(5, 5)),
                110
            )
            .await
            .unwrap(),
            Observation::Recorded
        );
        let log = log();
        append(&log, "roster.applied");
        send(
            &mut w,
            WitnessMessage::AuditCheckpoint {
                checkpoint: log.checkpoint().unwrap(),
                bridge: vec![],
            },
            110,
        )
        .await
        .unwrap();
        let e2 = append(&log, "session.opened");
        let e3 = append(&log, "session.rejected");
        let cp = log.checkpoint().unwrap();
        send(
            &mut w,
            WitnessMessage::AuditCheckpoint {
                checkpoint: cp.clone(),
                bridge: vec![e2, e3],
            },
            110,
        )
        .await
        .unwrap();
        assert_eq!(w.floor().records, 4);
        let floor = w.floor();
        drop(w);
        let w = Witness::open(
            context.child("reopen"),
            "honest".into(),
            trust(),
            prefix_floor,
            UnixSeconds(120),
        )
        .await
        .unwrap();
        assert_eq!(w.floor(), floor);
        assert_eq!(w.authority_checkpoint(), Some(&checkpoint(5, 5)));
        assert_eq!(
            w.audit_checkpoint(&KeyId::unchecked("audit-key")),
            Some(&cp)
        );
        assert!(!w.quarantined());
        drop(w);
        let wrong_hash = JournalFloor {
            head_hash: Hash32([99; 32]),
            ..prefix_floor
        };
        assert!(
            Witness::open(
                context.child("hash"),
                "honest".into(),
                trust(),
                wrong_hash,
                UnixSeconds(120)
            )
            .await
            .is_err()
        );
        // A valid older snapshot, not merely a corrupt file, must fail recovery.
        let mut old = Witness::open(
            context.child("old"),
            "old".into(),
            trust(),
            JournalFloor::EMPTY,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        send(
            &mut old,
            WitnessMessage::AuthorityCheckpoint(checkpoint(4, 4)),
            50,
        )
        .await
        .unwrap();
        assert_eq!(old.floor(), prefix_floor);
        drop(old);
        assert!(
            Witness::open(
                context.child("rollback"),
                "old".into(),
                trust(),
                floor,
                UnixSeconds(120)
            )
            .await
            .is_err()
        );
        context.remove("honest", None).await.unwrap();
        assert!(
            Witness::open(
                context.child("lost"),
                "honest".into(),
                trust(),
                floor,
                UnixSeconds(120)
            )
            .await
            .is_err()
        );
    });
}

#[test]
fn unauthenticated_wrong_scope_expired_or_malformed_input_never_poisons() {
    deterministic::Runner::default().start(|context| async move {
        let mut w = Witness::open(
            context.child("w"),
            "reject".into(),
            trust(),
            JournalFloor::EMPTY,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        send(
            &mut w,
            WitnessMessage::AuthorityCheckpoint(checkpoint(4, 4)),
            50,
        )
        .await
        .unwrap();
        let floor = w.floor();
        let mut forged = checkpoint(999, 9);
        forged.signature = signature(63, checkpoint_hash(&forged.body).unwrap());
        assert!(
            send(&mut w, WitnessMessage::AuthorityCheckpoint(forged), 50)
                .await
                .is_err()
        );
        let mut scope = checkpoint(999, 9);
        scope.body.environment_id = EnvironmentId::unchecked("other");
        scope.signature = signature(60, checkpoint_hash(&scope.body).unwrap());
        assert_eq!(
            send(&mut w, WitnessMessage::AuthorityCheckpoint(scope), 50)
                .await
                .unwrap_err()
                .code,
            ErrorCode::ScopeMismatch
        );
        assert!(
            send(
                &mut w,
                WitnessMessage::AuthorityCheckpoint(checkpoint(3, 3)),
                50
            )
            .await
            .is_err()
        );
        let payload = WitnessMessage::AuthorityCheckpoint(checkpoint(5, 5))
            .encode()
            .unwrap();
        assert_eq!(
            w.handle_authenticated(&node_id(3), 30, &payload, UnixSeconds(50))
                .await
                .unwrap_err()
                .code,
            ErrorCode::PeerNotAdmitted
        );
        assert!(
            w.handle_authenticated(&node_id(0), 12, &payload, UnixSeconds(50))
                .await
                .is_err()
        );
        assert!(
            w.handle_authenticated(&node_id(0), 30, &[0xa0, 0x00], UnixSeconds(50))
                .await
                .is_err()
        );
        let a = attestation(2, "candidate", VerificationDecision::Allow);
        assert!(
            send(&mut w, WitnessMessage::Attestation(Box::new(a)), 80)
                .await
                .is_err()
        );
        let mut unknown_build = attestation(2, "candidate", VerificationDecision::Allow);
        unknown_build.body.verifier_build_hash = Hash32([99; 32]);
        unknown_build = sign_attestation(&key(32), unknown_build.body).unwrap();
        assert!(
            send(
                &mut w,
                WitnessMessage::Attestation(Box::new(unknown_build)),
                50
            )
            .await
            .is_err()
        );
        let mut cp = log().checkpoint().unwrap();
        cp.body.service_key_id = KeyId::unchecked("untrusted-audit");
        assert!(
            send(
                &mut w,
                WitnessMessage::AuditCheckpoint {
                    checkpoint: cp,
                    bridge: vec![]
                },
                50
            )
            .await
            .is_err()
        );
        let confidential = artifacts().journals.remove(0);
        let message = WitnessMessage::AuditCheckpoint {
            checkpoint: confidential.checkpoint,
            bridge: confidential.events,
        };
        assert!(
            message.encode().is_err(),
            "free-form audit detail is offline only"
        );
        assert!(
            w.handle_authenticated(
                &node_id(0),
                30,
                &canonical_bytes(&message).unwrap(),
                UnixSeconds(50)
            )
            .await
            .is_err(),
            "bypassing encode must not bypass public-data restrictions"
        );
        assert_eq!(w.floor(), floor);
        assert!(w.evidence().is_empty());
        assert_eq!(w.authority_checkpoint(), Some(&checkpoint(4, 4)));
    });
}

#[test]
fn genuine_late_authority_equivocation_remains_quarantined_after_reopen() {
    deterministic::Runner::default().start(|context| async move {
        let mut w = Witness::open(
            context.child("w"),
            "authority-fork".into(),
            trust(),
            JournalFloor::EMPTY,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        send(
            &mut w,
            WitnessMessage::AuthorityCheckpoint(checkpoint(4, 4)),
            50,
        )
        .await
        .unwrap();
        send(
            &mut w,
            WitnessMessage::AuthorityCheckpoint(checkpoint(5, 5)),
            50,
        )
        .await
        .unwrap();
        assert_eq!(
            send(
                &mut w,
                WitnessMessage::AuthorityCheckpoint(checkpoint(4, 99)),
                50
            )
            .await
            .unwrap(),
            Observation::Quarantined
        );
        assert_eq!(
            w.evidence()[0],
            DivergenceEvidence {
                kind: EvidenceKind::AuthorityEquivocation,
                first_record: 1,
                second_record: 3
            }
        );
        assert_eq!(
            send(
                &mut w,
                WitnessMessage::AuthorityCheckpoint(checkpoint(6, 6)),
                50
            )
            .await
            .unwrap(),
            Observation::Quarantined
        );
        let floor = w.floor();
        drop(w);
        let w = Witness::open(
            context.child("reopen"),
            "authority-fork".into(),
            trust(),
            floor,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        assert!(w.quarantined());
        assert_eq!(w.evidence().len(), 1);
        assert_eq!(w.records().len(), 4);
    });
}

#[test]
fn audit_malformed_bridges_are_not_equivocation_but_authenticated_forks_are() {
    deterministic::Runner::default().start(|context| async move {
        let mut w = Witness::open(
            context.child("w"),
            "audit-fork".into(),
            trust(),
            JournalFloor::EMPTY,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        let alternate = log();
        let log = log();
        append(&log, "first");
        send(
            &mut w,
            WitnessMessage::AuditCheckpoint {
                checkpoint: log.checkpoint().unwrap(),
                bridge: vec![],
            },
            50,
        )
        .await
        .unwrap();
        let floor = w.floor();
        append(&alternate, "other-first");
        let e2 = append(&alternate, "second");
        let e3 = append(&alternate, "third");
        append(&log, "original-second");
        let original_e3 = append(&log, "original-third");
        // Each event is genuinely signed. The supplied bridge is nevertheless
        // internally disconnected and starts off the retained branch. Endpoint
        // comparison alone would falsely flag equivocation before checking e3.
        assert!(
            send(
                &mut w,
                WitnessMessage::AuditCheckpoint {
                    checkpoint: alternate.checkpoint().unwrap(),
                    bridge: vec![e2.clone(), original_e3]
                },
                50
            )
            .await
            .is_err()
        );
        let mut forged = e3.clone();
        forged.body.action = "altered".into();
        assert!(
            send(
                &mut w,
                WitnessMessage::AuditCheckpoint {
                    checkpoint: alternate.checkpoint().unwrap(),
                    bridge: vec![e2.clone(), forged]
                },
                50
            )
            .await
            .is_err()
        );
        assert_eq!(w.floor(), floor);
        assert!(!w.quarantined());
        assert_eq!(
            send(
                &mut w,
                WitnessMessage::AuditCheckpoint {
                    checkpoint: alternate.checkpoint().unwrap(),
                    bridge: vec![e2, e3]
                },
                50
            )
            .await
            .unwrap(),
            Observation::Quarantined
        );
        assert!(matches!(
            w.evidence()[0].kind,
            EvidenceKind::AuditDivergence { at_sequence: 1, .. }
        ));
        let floor = w.floor();
        drop(w);
        let w = Witness::open(
            context.child("reopen"),
            "audit-fork".into(),
            trust(),
            floor,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        assert!(w.quarantined());
        assert_eq!(w.evidence().len(), 1);
    });
}

#[test]
fn only_real_identical_input_attestation_disagreement_is_retained() {
    deterministic::Runner::default().start(|context| async move {
        let mut w = Witness::open(
            context.child("w"),
            "attest-fork".into(),
            trust(),
            JournalFloor::EMPTY,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        send(
            &mut w,
            WitnessMessage::Attestation(Box::new(attestation(
                2,
                "candidate-a",
                VerificationDecision::Allow,
            ))),
            50,
        )
        .await
        .unwrap();
        let mut altered = attestation(4, "candidate-a", VerificationDecision::Deny);
        altered.body.inputs.candidate_revision += 1;
        assert!(
            send(&mut w, WitnessMessage::Attestation(Box::new(altered)), 50)
                .await
                .is_err()
        );
        assert_eq!(w.floor().records, 1);
        let mut different = attestation(4, "candidate-a", VerificationDecision::Deny);
        different.body.inputs.evidence_bundle_hash = Hash32([99; 32]);
        let different = sign_attestation(&key(34), different.body).unwrap();
        send(&mut w, WitnessMessage::Attestation(Box::new(different)), 50)
            .await
            .unwrap();
        assert!(!w.quarantined());
        assert_eq!(
            send(
                &mut w,
                WitnessMessage::Attestation(Box::new(attestation(
                    4,
                    "candidate-a",
                    VerificationDecision::Deny
                ))),
                50
            )
            .await
            .unwrap(),
            Observation::Quarantined
        );
        assert!(matches!(
            w.evidence()[0].kind,
            EvidenceKind::AttestationDisagreement { .. }
        ));
        let floor = w.floor();
        let bundle = w.export(artifacts());
        let offline = verify_export(
            &bundle,
            &trust(),
            export_hash(&bundle).unwrap(),
            floor,
            UnixSeconds(1000),
        )
        .unwrap();
        assert_eq!(offline.evidence, w.evidence());
        drop(w);
        // Expiration now does not erase authenticated historical disagreement.
        let w = Witness::open(
            context.child("reopen"),
            "attest-fork".into(),
            trust(),
            floor,
            UnixSeconds(1000),
        )
        .await
        .unwrap();
        assert!(w.quarantined());
        assert_eq!(w.evidence()[0].first_record, 1);
        assert_eq!(w.evidence()[0].second_record, 3);
    });
}

fn artifacts() -> ExportArtifacts {
    let trust = trust();
    let mut operations = OperationsExport::default();
    operations.institution_id = Some(trust.institution_id.clone());
    operations.environment_id = Some(trust.environment_id.clone());
    operations.revision = 9;
    let body = JournalEntryBody {
        entry_id: JournalEntryId::unchecked("entry-1"),
        sequence: 1,
        previous_entry_hash: Hash32::ZERO,
        at: UnixSeconds(50),
        institution_id: trust.institution_id.clone(),
        environment_id: trust.environment_id.clone(),
        vault_id: VaultId::unchecked("vault"),
        chain_wallet_id: ChainWalletId::unchecked("wallet"),
        asset_id: AssetId::unchecked("asset"),
        side: EntrySide::Credit,
        amount_base_units: Amount(37),
        kind: JournalEntryKind::AcceptedReceipt {
            movement_id: MovementId::unchecked("movement"),
        },
        posted_at_state: StateReference {
            height: 10,
            hash: vec![9; 32].into(),
            commitment: "finalized".into(),
        },
    };
    operations.journal.push(JournalEntry {
        entry_hash: domain_hash(domains::JOURNAL, &body).unwrap(),
        body,
    });
    let body = LifecycleEventBody {
        event_id: EventId::unchecked("lifecycle-1"),
        sequence: 1,
        institution_id: trust.institution_id.clone(),
        environment_id: trust.environment_id.clone(),
        at: UnixSeconds(50),
        kind: LifecycleEventKind::PolicyActivated {
            policy_id: PolicyId::unchecked("policy"),
            policy_epoch: Epoch(7),
        },
    };
    operations.events.push(LifecycleEvent {
        signature: signature(62, domain_hash(domains::WEBHOOK, &body).unwrap()),
        body,
        signing_key_id: KeyId::unchecked("operations-key"),
    });
    let mut policy = PolicyBundle {
        policy_id: PolicyId::unchecked("policy"),
        policy_epoch: Epoch(7),
        institution_id: trust.institution_id,
        environment_id: trust.environment_id,
        rules: vec![],
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 60,
        allowlist_version: 1,
        activation_epoch: Epoch(7),
        administrative_signatures: vec![],
    };
    policy.administrative_signatures.push(CredentialSignature {
        credential_id: CredentialId::unchecked("policy-admin"),
        signature: signature(2, policy_hash(&policy).unwrap()),
    });
    let event = AuthorityEvent::PolicyActivated {
        policy_epoch: Epoch(7),
        policy_hash: policy_hash(&policy).unwrap(),
        commit_sequence: 2,
    };
    let entry = authority_event_entry(&event, Some(Epoch(7))).unwrap();
    let log = log();
    let audit_event = log
        .append(
            "authority",
            &entry.action,
            entry.object_commitments,
            entry.policy_epoch,
            &entry.detail,
        )
        .unwrap();
    let receipt_body = AuthorityReceiptBody {
        kind: ReceiptKind::Release,
        institution_id: InstitutionId::unchecked("institution"),
        environment_id: EnvironmentId::unchecked("test"),
        authority_epoch: Epoch(2),
        reservation_id: ReservationId::unchecked("reservation"),
        reservation_version: 1,
        candidate_id: CandidateId::unchecked("candidate"),
        candidate_revision: 3,
        envelope_body_hash: Hash32([11; 32]),
        signer_session_id: SigningSessionId::unchecked("session"),
        intent_hash: Hash32([12; 32]),
        rule_id: "rule".into(),
        claims_hash: Hash32([13; 32]),
        policy_epoch: Epoch(7),
        freeze_epoch: Epoch(0),
        issued_at: UnixSeconds(50),
        expires_at: UnixSeconds(55),
        commit_sequence: 8,
    };
    let receipt = AuthorityReceipt {
        signature: signature(60, receipt_hash(&receipt_body).unwrap()),
        body: receipt_body,
        authority_key_id: KeyId::unchecked("receipt-key"),
    };
    ExportArtifacts {
        operations,
        policy_activations: vec![PolicyActivation {
            policy,
            event,
            audit_event,
        }],
        receipts: vec![receipt],
        issuance: vec![IssuanceRecord {
            issuance_id: IssuanceId::unchecked("issuance"),
            operation_family_id: OperationFamilyId::unchecked("family"),
            candidate_id: CandidateId::unchecked("candidate"),
            candidate_revision: 3,
            envelope_hash: Hash32([11; 32]),
            signer_session_id: SigningSessionId::unchecked("session"),
            commit_sequence: 8,
            committed_at: UnixSeconds(50),
        }],
        journals: vec![NodeJournal {
            node_id: node_id(0),
            checkpoint: log.checkpoint().unwrap(),
            events: log.events(),
        }],
        signatures: vec![],
        builds: vec![BuildMetadata {
            node_id: node_id(2),
            roster_epoch: 0,
            commonware_release: COMMONWARE_RELEASE.into(),
            build_hash: Hash32([42; 32]),
        }],
    }
}

#[test]
fn offline_reconstruction_needs_no_live_store_and_rejects_tampering() {
    deterministic::Runner::default().start(|context| async move {
        let mut w = Witness::open(
            context.child("w"),
            "offline".into(),
            trust(),
            JournalFloor::EMPTY,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        send(
            &mut w,
            WitnessMessage::AuthorityCheckpoint(checkpoint(8, 8)),
            50,
        )
        .await
        .unwrap();
        send(
            &mut w,
            WitnessMessage::Attestation(Box::new(attestation(
                2,
                "candidate-a",
                VerificationDecision::Allow,
            ))),
            50,
        )
        .await
        .unwrap();
        let bundle = w.export(artifacts());
        let floor = w.floor();
        let hash = export_hash(&bundle).unwrap();
        let bytes = canonical_bytes(&bundle).unwrap();
        drop(w);
        context.remove("offline", None).await.unwrap();
        let bundle: ExportBundle = from_canonical_bytes(&bytes).unwrap();
        let rebuilt = verify_export(&bundle, &trust(), hash, floor, UnixSeconds(1000)).unwrap();
        assert_eq!(rebuilt.floor, floor);
        assert_eq!(rebuilt.authority_checkpoint, Some(checkpoint(8, 8)));
        assert_eq!(rebuilt.operations_revision, 9);
        assert_eq!(
            rebuilt.journal_head,
            (
                1,
                domain_hash(domains::JOURNAL, &artifacts().operations.journal[0].body).unwrap()
            )
        );
        assert_eq!(rebuilt.lifecycle_sequence, 1);
        assert!(rebuilt.evidence.is_empty());
        assert!(!format!("{bundle:?}").contains("candidate"));
        // The confidential operations object is not accepted on the public seam.
        assert!(from_canonical_bytes::<WitnessMessage>(&bytes).is_err());
        let mut changed = bundle.clone();
        changed.artifacts.operations.revision += 1; // unsigned field: bundle hash is essential
        assert!(verify_export(&changed, &trust(), hash, floor, UnixSeconds(1000)).is_err());
        // Even when testing without the independent bundle hash barrier, all
        // underlying signatures, scope bindings, and included proofs reverify.
        let mutations: Vec<fn(&mut ExportBundle)> = vec![
            |b| b.artifacts.operations.events[0].body.at = UnixSeconds(51),
            |b| b.artifacts.operations.journal[0].body.amount_base_units = Amount(38),
            |b| b.artifacts.journals[0].events[0].body.action = "altered".into(),
            |b| {
                b.artifacts.policy_activations[0]
                    .policy
                    .max_evidence_age_seconds += 1
            },
            |b| b.artifacts.receipts[0].body.expires_at = UnixSeconds(999),
            |b| b.artifacts.issuance[0].candidate_revision = 4,
            |b| b.artifacts.builds[0].commonware_release = "other".into(),
            |b| {
                b.rosters[0].signatures[0].signature =
                    signature(3, roster_hash(&b.rosters[0].body).unwrap())
            },
            |b| {
                b.rosters.pop();
            },
            |b| b.artifacts.operations.environment_id = Some(EnvironmentId::unchecked("other")),
            |b| {
                b.witness_records[0].message = WitnessMessage::AuthorityCheckpoint(checkpoint(9, 9))
            },
        ];
        for mutate in mutations {
            let mut bad = bundle.clone();
            mutate(&mut bad);
            let rehashed = export_hash(&bad).unwrap();
            assert!(verify_export(&bad, &trust(), rehashed, floor, UnixSeconds(1000)).is_err());
        }
        let mut omitted = bundle.clone();
        omitted.witness_records.pop();
        assert!(
            verify_export(
                &omitted,
                &trust(),
                export_hash(&omitted).unwrap(),
                floor,
                UnixSeconds(1000)
            )
            .is_err()
        );
    });
}

#[test]
fn journal_replay_reverifies_signatures_even_without_a_hash_floor() {
    deterministic::Runner::default().start(|context| async move {
        let mut w = Witness::open(
            context.child("source"),
            "source".into(),
            trust(),
            JournalFloor::EMPTY,
            UnixSeconds(110),
        )
        .await
        .unwrap();
        send(
            &mut w,
            WitnessMessage::AuthorityCheckpoint(checkpoint(8, 8)),
            50,
        )
        .await
        .unwrap();
        let mut record = w.records()[0].clone();
        if let WitnessMessage::AuthorityCheckpoint(cp) = &mut record.message {
            cp.signature = signature(63, checkpoint_hash(&cp.body).unwrap());
        }
        drop(w);
        let ctx = context.child("tamper");
        let page_cache = CacheRef::from_pooler(&ctx, NZU16!(4096), NZUsize!(16));
        let journal = Journal::<_, Vec<u8>>::init(
            ctx,
            Config {
                partition: "tampered".into(),
                compression: None,
                codec_config: ((..=2 * MAX_BYTES_LEN).into(), ()),
                page_cache,
                write_buffer: NZUsize!(65536),
            },
        )
        .await
        .unwrap();
        let (journal, _, _) = journal
            .append(0, &canonical_bytes(&record).unwrap())
            .await
            .unwrap();
        drop(journal.sync_all().await.unwrap());
        let result = Witness::open(
            context.child("replay"),
            "tampered".into(),
            trust(),
            JournalFloor::EMPTY,
            UnixSeconds(110),
        )
        .await;
        assert!(matches!(
            result,
            Err(OicError {
                code: ErrorCode::InvalidSignature,
                ..
            })
        ));
    });
}
