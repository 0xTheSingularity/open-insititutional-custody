//! External D2 IPC contracts with real 3-of-4 finalizations and FROST 2-of-3.
//! Live Simplex/TCP integration is exercised by signer-net/tests/finalized.rs.
#[path = "common/finalized.rs"]
mod support;

use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use oic_adapter_api::ChainAdapter;
use oic_audit::{AuditLog, AuditLogConfig, FileAuditLog};
use oic_authorization_state::ManualClock;
use oic_crypto_provider::ProtocolStep;
use oic_domain_types::*;
use oic_service_coordinator::SignerEndpoint;
use oic_service_signer_core::{CoreConfig, SignerCore};
use std::sync::Arc;
use support::{
    common::{signer, NOW},
    Contract, Harness, MAX_AGE,
};
use tokio::sync::watch;

#[test]
fn certified_release_over_private_ipc_produces_a_native_solana_signature() {
    deterministic::Runner::default().start(|context| async move {
        let contract = Contract::new();
        let (reserved, released) = contract.logs(context.child("history")).await;
        let (source, receiver) = watch::channel(Some(reserved));
        let harness = Harness::start(&contract, receiver, contract.pins()).unwrap();
        let body = &contract.proof.envelope;
        let materials = oic_service_builder::signing_materials(&contract.fixture.built.package);
        assert_eq!(
            harness.remote(0, "gateway").open_finalized(body, &materials).unwrap_err().code,
            ErrorCode::SessionRejected
        );
        assert!(harness.clients[0].outbound_at(0).unwrap().is_none());
        harness.assert_no_release();

        source.send(Some(released.clone())).unwrap();
        for caller in ["replica-0", "core-1", "witness", "not-admitted"] {
            assert_eq!(
                harness.remote(0, caller).open_finalized(body, &materials).unwrap_err().code,
                ErrorCode::PeerNotAdmitted,
                "{caller}"
            );
        }
        let mut tampered = materials.clone();
        tampered.candidate.native_unsigned_bytes.0[0] ^= 1;
        assert!(harness.remote(0, "gateway").open_finalized(body, &tampered).is_err());
        assert!(harness.clients[0].outbound_at(0).unwrap().is_none());
        harness.prepare(&contract);
        harness.assert_no_release();
        for caller in ["replica-0", "core-1", "witness", "not-admitted", "other-gateway"] {
            assert_eq!(
                harness.remote(0, caller).release_finalized(&body.signer_session_id).unwrap_err().code,
                ErrorCode::PeerNotAdmitted,
                "{caller}"
            );
        }
        harness.assert_no_release();
        // The freshness boundary is inclusive; the stale case below is +1.
        harness.clock.set(NOW + MAX_AGE);
        let shares = (0..2)
            .map(|index| {
                let mut steps = harness.remote(index, "gateway").release_finalized(&body.signer_session_id).unwrap();
                assert_eq!(steps.len(), 1);
                let ProtocolStep::Share(share) = steps.remove(0) else {
                    panic!("expected one FROST share")
                };
                (signer::pid(index as u8 + 1), share)
            })
            .collect::<Vec<_>>();
        let signature = harness.remote(0, "gateway").aggregate(&body.signer_session_id, &shares).unwrap();
        assert_eq!(signature.scheme, SchemeId::Ed25519Pure);
        let key = &materials.key;
        let public = VerifyingKey::from_bytes(key.public_key.bytes.as_slice().try_into().unwrap()).unwrap();
        let native_signature = Signature::from_slice(signature.bytes.as_slice()).unwrap();
        let message = &body.native_signing_payloads[0].message_or_digest;
        public.verify_strict(message.as_slice(), &native_signature).unwrap();
        let mut different_message = message.clone();
        different_message.0[0] ^= 1;
        assert!(public.verify_strict(different_message.as_slice(), &native_signature).is_err());
        let adapter = oic_adapter_solana::SolanaAdapter;
        let signed = adapter.assemble_signed_transaction(&materials.candidate, key, &[signature]).unwrap();
        let verified = adapter.verify_signed_transaction(&signed, &materials.candidate, key).unwrap();
        assert_eq!(verified.verified_signers, vec![key.public_key.bytes.clone()]);
        for audit in &harness.audits {
            let events = audit.events_since(0, 128).unwrap();
            let releases: Vec<_> = events.iter().filter(|event| event.body.action == "signer.share_released").collect();
            assert_eq!(releases.len(), 1);
            assert_eq!(releases[0].body.object_commitments["finalized_block"], released.floor().digest);
            assert_eq!(releases[0].body.object_commitments["envelope"], contract.proof.request.envelope_body_hash);
            oic_audit::verify_checkpoint(&audit.checkpoint().unwrap(), &audit.verifying_key()).unwrap();
        }
    });
}

#[test]
fn prepared_ipc_sessions_recheck_the_local_source_before_releasing_shares() {
    deterministic::Runner::default().start(|context| async move {
        let contract = Contract::new();
        let (reserved, released) = contract.logs(context.child("history")).await;
        for failure in ["missing", "closed", "rollback", "stale"] {
            let (source, receiver) = watch::channel(Some(released.clone()));
            let harness = Harness::start(&contract, receiver, contract.pins()).unwrap();
            harness.prepare(&contract);
            let expected = match failure {
                "missing" => {
                    source.send(None).unwrap();
                    ErrorCode::StaleEvidence
                }
                "closed" => {
                    drop(source);
                    ErrorCode::RecoveryRequired
                }
                "rollback" => {
                    source.send(Some(reserved.clone())).unwrap();
                    ErrorCode::RecoveryRequired
                }
                "stale" => {
                    harness.clock.set(NOW + MAX_AGE + 1);
                    ErrorCode::StaleEvidence
                }
                _ => unreachable!(),
            };
            let session = &contract.proof.envelope.signer_session_id;
            for index in 0..2 {
                assert_eq!(
                    harness.remote(index, "gateway").release_finalized(session).unwrap_err().code,
                    expected,
                    "{failure}"
                );
                assert!(harness.remote(index, "gateway").aggregate(session, &[]).is_err(), "{failure}");
            }
            harness.assert_no_release();
        }
    });
}

#[test]
fn ipc_open_rejects_missing_source_and_wrong_pins() {
    deterministic::Runner::default().start(|context| async move {
        let contract = Contract::new();
        let (_, released) = contract.logs(context.child("history")).await;
        let materials = oic_service_builder::signing_materials(&contract.fixture.built.package);
        for failure in ["missing", "closed", "genesis", "roster"] {
            let (source, receiver) = watch::channel(if failure == "missing" { None } else { Some(released.clone()) });
            let mut pins = contract.pins();
            if failure == "genesis" {
                pins.anchor.genesis = Hash32([91; 32]);
                pins.minimum_floor.digest = pins.anchor.genesis;
            }
            if failure == "roster" {
                pins.anchor.roster = Hash32([92; 32]);
            }
            if failure == "closed" {
                drop(source);
            }
            let result = Harness::start(&contract, receiver, pins);
            if failure == "roster" {
                assert!(matches!(result, Err(error) if error.code == ErrorCode::ScopeMismatch));
                continue;
            }
            let harness = result.unwrap();
            let expected = match failure {
                "missing" => ErrorCode::StaleEvidence,
                "closed" => ErrorCode::RecoveryRequired,
                "genesis" => ErrorCode::ScopeMismatch,
                _ => unreachable!(),
            };
            assert_eq!(
                harness
                    .remote(0, "gateway")
                    .open_finalized(&contract.proof.envelope, &materials)
                    .unwrap_err()
                    .code,
                expected,
                "{failure}"
            );
            assert!(harness.clients[0].outbound_at(0).unwrap().is_none());
            harness.assert_no_release();
        }
    });
}

#[test]
fn d2_startup_rejects_operator_or_audit_keys_reused_from_any_replica_vote_key() {
    // The commonware codec serializes the actual Ed25519 private seed, so
    // these controls possess the enrolled key rather than forging the roster.
    fn dalek(key: &impl commonware_cryptography::PrivateKey) -> SigningKey {
        SigningKey::from_bytes(key.encode().as_ref().try_into().unwrap())
    }
    let contract = Contract::new();
    for (replica, vote_key) in &contract.committee.keys {
        let vote_key = dalek(vote_key);
        assert_eq!(
            vote_key.verifying_key().as_bytes().as_slice(),
            contract
                .committee
                .roster
                .node(replica)
                .unwrap()
                .consensus_key
                .as_ref()
                .unwrap()
                .bytes
                .as_slice()
        );
        for purpose in ["operator", "audit", "distinct"] {
            let dir = tempfile::tempdir().unwrap();
            let clock = Arc::new(ManualClock::new(NOW));
            let operator = if purpose == "operator" {
                vote_key.clone()
            } else {
                SigningKey::from_bytes(&[220; 32])
            };
            let audit_key = if purpose == "audit" {
                vote_key.clone()
            } else {
                SigningKey::from_bytes(&[200; 32])
            };
            let audit = Arc::new(
                FileAuditLog::open(
                    dir.path().join("audit"),
                    Some(0),
                    AuditLogConfig::new(KeyId::unchecked("startup-audit"), audit_key, clock.clone()),
                )
                .unwrap(),
            );
            let signer = contract.open_signer(0, &contract.pins()).unwrap();
            let result = SignerCore::open(
                CoreConfig {
                    node_id: support::core_id(0),
                    roster: contract.committee.roster.clone(),
                    previous_roster: None,
                    admins: contract.committee.admins.clone(),
                    committed_roster_hash: contract.committee.anchor,
                    halt_state_path: dir.path().join("halt"),
                    minimum_halt_sequence: 0,
                    operator_key: operator.verifying_key(),
                    audit: audit.clone(),
                },
                Arc::new(signer),
                SigningKey::from_bytes(&[80; 32]),
                clock,
            );
            let events = audit.events_since(0, 16).unwrap();
            if purpose == "distinct" {
                assert!(result.is_ok(), "{replica}: distinct controls must open");
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].body.action, "node.roster_applied");
            } else {
                assert!(
                    matches!(
                        result,
                        Err(OicError {
                            code: ErrorCode::InvalidRequest,
                            ..
                        })
                    ),
                    "{replica}: {purpose}"
                );
                assert!(events.is_empty(), "{replica}: {purpose} was rejected after startup audit");
            }
        }
    }
}
