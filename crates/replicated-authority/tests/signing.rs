//! Real certified follower → signer → native transaction contracts. Certificates
//! here are assembled from genuine votes; live Simplex is tested in runtime.rs.
//! Both native keys are explicitly development 1-of-1, not threshold evidence.
mod common;

use common::{Chain, Committee, Fixture, NOW, admin_signatures, authority, now, signer};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::TestRng;
use ed25519_dalek::SigningKey;
use oic_authorization_state::{AuthorityCommand, CredentialChange};
use oic_canonical_encoding::sha256;
use oic_crypto_provider::{CryptoProvider, KeygenCeremony, PeerMessage, ProtocolStep};
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_domain_types::*;
use oic_one_time_state_ledger::InMemoryLedger;
use oic_replicated_authority::*;
use oic_service_builder::signing_materials;
use oic_signer::{FinalizedAuthorityConfig, InMemoryGenerationStore, Signer, TrustRoots};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

fn signer(
    fixture: &Fixture,
    anchor: LogAnchor,
    floor: FinalizedFloor,
) -> (Signer, Arc<InMemoryLedger>) {
    let key = &fixture.built.package.key;
    let provider = Arc::new(
        DevSingleKeyProvider::new(key.scheme, [90; 32], Box::new(StdRng::seed_from_u64(917)))
            .unwrap(),
    );
    let generated = provider
        .generate_distributed_key(&KeygenCeremony {
            key_id: key.key_id.clone(),
            key_epoch: key.key_epoch,
            institution_id: key.institution_id.clone(),
            environment_id: key.environment_id.clone(),
            participants: key.participants.clone(),
            threshold: key.threshold,
            networks: key.networks.clone(),
            recovery_profile: key.recovery_profile.clone(),
        })
        .unwrap();
    assert_eq!(&generated.descriptor, key);
    let roots = TrustRoots {
        // Unrelated public key only: this test never constructs a D1 authority.
        authority_key_id: KeyId::unchecked("unused-d1"),
        authority_pubkey: SigningKey::from_bytes(&[199; 32]).verifying_key(),
        admin_keys: fixture.executor.authority.admin_keys.clone(),
        admin_quorum: 2,
        // Enrollment must come from the finalized log, not these local roots.
        approvers: vec![],
        accepted_verifier_builds: fixture
            .executor
            .adapters
            .iter()
            .map(|(id, adapter)| (id.clone(), vec![adapter.manifest().verifier_build_hash]))
            .collect(),
        chain_profiles: vec![fixture.profile.clone()],
        // The signer pins the same records the replica's registry pins.
        enrolled_materials: Some(common::registry_enrollment(&fixture.executor.registry)),
        max_clock_skew_seconds: 30,
    };
    let ledger = Arc::new(InMemoryLedger::new());
    let instance = Signer::open(
        signer::identity(&key.participants[0]),
        roots,
        fixture.executor.adapters.clone(),
        provider,
        ledger.clone(),
        Arc::new(InMemoryGenerationStore::new()),
    )
    .unwrap()
    .with_finalized_authority(FinalizedAuthorityConfig {
        anchor,
        minimum_floor: floor,
        max_age_seconds: 60,
    })
    .unwrap();
    instance
        .load_key(key, &generated.sealed_shares[0].1)
        .unwrap();
    (instance, ledger)
}

async fn append(
    follower: &mut Follower<deterministic::Context>,
    fixture: &Fixture,
    committee: &Committee,
    commands: &[Command],
    view: u64,
) {
    let (block, _) = fixture
        .executor
        .propose_block(
            follower.tip(),
            follower.state().clone(),
            committee.context(follower.tip(), view),
            commands,
            now(),
            now(),
        )
        .unwrap();
    let certificate = committee.certify(&block);
    follower
        .apply_finalized(&mut TestRng::new(view), block, certificate, now())
        .await
        .unwrap();
}

#[test]
fn only_exact_fresh_finalized_release_enables_once_only_native_signing() {
    for chain in [Chain::Evm, Chain::Solana] {
        deterministic::Runner::default().start(|context| async move {
            let fixture = Fixture::new(chain, 1);
            let committee = Committee::new();
            let genesis = fixture.genesis(&committee);
            let floor = FinalizedFloor::at(&genesis);
            let anchor = LogAnchor {
                genesis: floor.digest,
                roster: committee.trust.roster_hash().unwrap(),
            };
            let (instance, ledger) = signer(&fixture, anchor, floor);
            let mut follower = Follower::open(
                context.child("signing"),
                FollowerConfig {
                    partition: "signing".into(),
                    executor: fixture.executor.clone(),
                    trust: committee.trust.clone(),
                    genesis,
                    genesis_state: ReplicatedState::default(),
                    minimum_floor: floor,
                    local_now: now(),
                },
                &mut TestRng::new(14),
            )
            .await
            .unwrap();
            assert!(
                follower.verified_log().is_err(),
                "genesis has no finalized authorization"
            );
            let mut commands = fixture.bootstrap();
            commands.extend(fixture.approvals());
            commands.push(Command::Reserve(Box::new(fixture.proof())));
            append(&mut follower, &fixture, &committee, &commands, 1).await;
            let reserved = follower.verified_log().unwrap();
            let body = fixture.proof().envelope;
            let materials = signing_materials(&fixture.built.package);
            assert_eq!(
                instance
                    .open_finalized_session(&body, &materials, &reserved, now())
                    .unwrap_err()
                    .code,
                ErrorCode::SessionRejected
            );
            assert!(
                ledger.snapshot().is_empty(),
                "reserve cannot allocate a signing record"
            );
            append(&mut follower, &fixture, &committee, &[fixture.release()], 2).await;
            let released = follower.verified_log().unwrap();

            let mut bad_anchor = anchor;
            bad_anchor.roster = Hash32([8; 32]);
            let (foreign, foreign_ledger) = signer(&fixture, bad_anchor, floor);
            assert_eq!(
                foreign
                    .verify_finalized_envelope(&body, &materials, &released, now())
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidSignature
            );
            assert!(foreign_ledger.snapshot().is_empty());
            assert_eq!(
                instance
                    .verify_finalized_envelope(&body, &materials, &released, UnixSeconds(NOW + 61))
                    .unwrap_err()
                    .code,
                ErrorCode::StaleEvidence
            );
            let mut changed = body.clone();
            changed.signer_session_id = SigningSessionId::unchecked("substituted-session");
            assert!(
                instance
                    .open_finalized_session(&changed, &materials, &released, now())
                    .is_err()
            );
            assert!(
                ledger.snapshot().is_empty(),
                "rejected evidence cannot allocate a record"
            );
            let verified = instance
                .verify_finalized_envelope(&body, &materials, &released, now())
                .unwrap();
            assert_eq!(
                verified.approvers,
                vec![CredentialId::unchecked("approver-1")]
            );
            assert_eq!(
                instance
                    .open_finalized_session(&body, &materials, &released, now())
                    .unwrap(),
                ProtocolStep::Waiting
            );
            let session = &body.signer_session_id;
            let payload = &body.native_signing_payloads[0];
            let hash = sha256(payload.message_or_digest.as_slice());
            let message = PeerMessage {
                session_id: session.clone(),
                key_id: body.key_id.clone(),
                key_epoch: body.key_epoch,
                from: materials.key.participants[0].clone(),
                from_generation: instance.generation(),
                to: Some(materials.key.participants[0].clone()),
                round: 1,
                sequence: 1,
                protocol_version: oic_crypto_provider_dev::PROTOCOL_VERSION.into(),
                payload: hash.0.to_vec().into(),
            };
            assert_eq!(
                instance.receive(session, &message).unwrap(),
                ProtocolStep::Waiting
            );
            assert!(ledger.snapshot().iter().all(|record| !record.consumed));
            assert_eq!(
                instance
                    .release_finalized(session, &reserved, now())
                    .unwrap_err()
                    .code,
                ErrorCode::RecoveryRequired
            );
            let steps = instance
                .release_finalized(session, &released, now())
                .unwrap();
            let [ProtocolStep::Complete(signature)] = steps.as_slice() else {
                panic!("native signature absent: {steps:?}")
            };
            let adapter = &fixture.executor.adapters[&fixture.profile.adapter_id];
            let signed = adapter
                .assemble_signed_transaction(
                    &materials.candidate,
                    &materials.key,
                    std::slice::from_ref(signature),
                )
                .unwrap();
            adapter
                .verify_signed_transaction(&signed, &materials.candidate, &materials.key)
                .unwrap();
            let records = ledger.snapshot();
            assert_eq!(records.len(), 1);
            assert!(records[0].consumed);
            assert_eq!(records[0].bound_message_hash, Some(hash));
            assert_eq!(records[0].session_id.as_ref(), Some(session));
            assert_eq!(instance.finalized_floor(), Some(released.floor()));
            assert_eq!(
                instance.receive(session, &message).unwrap_err().code,
                ErrorCode::Conflict
            );
            assert_eq!(
                instance
                    .release_finalized(session, &released, now())
                    .unwrap_err()
                    .code,
                ErrorCode::Conflict
            );
            assert_eq!(
                instance
                    .open_finalized_session(&body, &materials, &released, now())
                    .unwrap_err()
                    .code,
                ErrorCode::Conflict
            );
            assert_eq!(ledger.snapshot(), records);
        });
    }
}

#[test]
fn removal_from_latest_ordered_enrollment_blocks_buffered_output() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = Fixture::new(Chain::Solana, 1);
        let committee = Committee::new();
        let genesis = fixture.genesis(&committee);
        let floor = FinalizedFloor::at(&genesis);
        let anchor = LogAnchor {
            genesis: floor.digest,
            roster: committee.trust.roster_hash().unwrap(),
        };
        let (instance, ledger) = signer(&fixture, anchor, floor);
        let mut follower = Follower::open(
            context.child("removal"),
            FollowerConfig {
                partition: "removal".into(),
                executor: fixture.executor.clone(),
                trust: committee.trust.clone(),
                genesis,
                genesis_state: ReplicatedState::default(),
                minimum_floor: floor,
                local_now: now(),
            },
            &mut TestRng::new(19),
        )
        .await
        .unwrap();
        let mut commands = fixture.bootstrap();
        commands.extend(fixture.approvals());
        commands.extend([
            Command::Reserve(Box::new(fixture.proof())),
            fixture.release(),
        ]);
        append(&mut follower, &fixture, &committee, &commands, 1).await;
        let body = fixture.proof().envelope;
        let materials = signing_materials(&fixture.built.package);
        instance
            .open_finalized_session(&body, &materials, &follower.verified_log().unwrap(), now())
            .unwrap();
        let message = PeerMessage {
            session_id: body.signer_session_id.clone(),
            key_id: body.key_id.clone(),
            key_epoch: body.key_epoch,
            from: materials.key.participants[0].clone(),
            from_generation: instance.generation(),
            to: Some(materials.key.participants[0].clone()),
            round: 1,
            sequence: 1,
            protocol_version: oic_crypto_provider_dev::PROTOCOL_VERSION.into(),
            payload: sha256(body.native_signing_payloads[0].message_or_digest.as_slice())
                .0
                .to_vec()
                .into(),
        };
        assert_eq!(
            instance.receive(&body.signer_session_id, &message).unwrap(),
            ProtocolStep::Waiting
        );
        let proposal = CredentialChange {
            institution_id: body.institution_id.clone(),
            environment_id: body.environment_id.clone(),
            credential_id: CredentialId::unchecked("approver-1"),
            previous_change: follower
                .state()
                .authority
                .ordered_approvals
                .as_ref()
                .unwrap()
                .credentials[&CredentialId::unchecked("approver-1")]
                .commit_sequence,
            credential: None,
        };
        let signatures = admin_signatures(proposal.hash().unwrap());
        append(
            &mut follower,
            &fixture,
            &committee,
            &[authority(AuthorityCommand::ChangeCredential {
                proposal,
                signatures,
            })],
            2,
        )
        .await;
        assert_eq!(
            instance
                .release_finalized(
                    &body.signer_session_id,
                    &follower.verified_log().unwrap(),
                    now()
                )
                .unwrap_err()
                .code,
            ErrorCode::InvalidSignature
        );
        assert!(ledger.snapshot().iter().all(|record| !record.consumed));
    });
}
