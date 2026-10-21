//! Real TCP Simplex -> two admitted keyless followers -> private IPC cores ->
//! TCP participant-authenticated FROST 2-of-3 -> native Solana verification.
//! No certificate fixture, synthetic VerifiedLog or D1 receipt key is used.
#[path = "../../signer-core/tests/common/finalized.rs"]
mod support;

use commonware_runtime::{Runner as _, Supervisor as _, tokio as runtime};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use oic_adapter_api::ChainAdapter;
use oic_approval_verifier::sign_grant;
use oic_audit::AuditLog;
use oic_authorization_state::{AuthorityCommand, ReleaseRequest, SystemClock};
use oic_canonical_encoding::{domain_hash, sha256};
use oic_crypto_provider::ProtocolStep;
use oic_domain_types::*;
use oic_membership::{Role, roster_hash};
use oic_node::{Config, Transport};
use oic_peer_wire::{FrameKind, PeerFrameV1, RosterState, SessionControl, SessionResult};
use oic_replicated_authority::{Command, FinalityTrust, FinalizedFloor, Follower, FollowerConfig, ReplicatedState};
use oic_service_coordinator::SignerEndpoint;
use oic_service_signer_net::consensus::ConsensusHost;
use std::{
    collections::BTreeSet,
    net::TcpListener,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::{
    Contract, Harness,
    common::{admin_signatures, authority, signer},
    core_id,
};
use tokio::time::{Instant, sleep, timeout};

fn now() -> UnixSeconds {
    UnixSeconds(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
}

fn live_contract() -> Contract {
    let clock = now();
    let mut contract = Contract::with_inputs(|inputs| {
        inputs.intent.created_at = UnixSeconds(clock.0 - 100);
        inputs.built_at = clock;
        inputs.evidence.observed_at = clock;
        // Real TCP startup can require 300s because of Commonware's per-IP
        // admission retry limit. Keep an explicit, checked 900s window.
        inputs.evidence.max_staleness_seconds = 900;
        inputs.profile.max_evidence_age_seconds = 900;
        inputs.policy.max_evidence_age_seconds = 900;
    });
    contract.fixture.profile = contract.fixture.executor.registry.profiles[0].clone();
    for (index, grant) in contract.fixture.grants.iter_mut().enumerate() {
        let mut body = grant.body.clone();
        body.issued_at = clock;
        body.expires_at = UnixSeconds(clock.0 + 900);
        *grant = sign_grant(&SigningKey::from_bytes(&[61 + index as u8; 32]), body).unwrap();
    }
    contract.proof = contract.fixture.proof();
    contract.proof.envelope.participant_set.truncate(2);
    contract.proof.envelope.issuance_deadline = UnixSeconds(clock.0 + 900);
    contract.proof.request.issuance_deadline = contract.proof.envelope.issuance_deadline;
    contract.proof.request.envelope_body_hash = domain_hash(domains::AUTHORIZATION, &contract.proof.envelope).unwrap();

    let committee = &mut contract.committee;
    // Reserve every address together, including offline roster members.
    let listeners: Vec<_> = committee
        .roster
        .body
        .nodes
        .iter()
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    for (node, listener) in committee.roster.body.nodes.iter_mut().zip(&listeners) {
        node.address = listener.local_addr().unwrap();
    }
    for acl in &mut committee.roster.body.channel_acl {
        if [0, 2, 4, 5].contains(&acl.channel) && !acl.receiver_roles.contains(&Role::Signer) {
            acl.receiver_roles.push(Role::Signer);
        }
        if [0, 5].contains(&acl.channel) && !acl.sender_roles.contains(&Role::Signer) {
            acl.sender_roles.push(Role::Signer);
        }
    }
    committee.anchor = roster_hash(&committee.roster.body).unwrap();
    committee.roster.signatures = admin_signatures(committee.anchor);
    committee.trust = FinalityTrust::from_genesis(
        committee.roster.clone(),
        &committee.admins,
        &signer::inst(),
        &signer::env_id(),
        committee.anchor,
        clock,
    )
    .unwrap();
    contract
}

fn follower(contract: &Contract, index: usize, floor: FinalizedFloor) -> FollowerConfig {
    FollowerConfig {
        partition: format!("native-signing-{index}"),
        executor: contract.fixture.executor.clone(),
        trust: contract.committee.trust.clone(),
        genesis: contract.fixture.genesis(&contract.committee),
        genesis_state: ReplicatedState::default(),
        minimum_floor: floor,
        local_now: now(),
    }
}

async fn boot(context: &runtime::Context, contract: &Contract, index: usize, floor: FinalizedFloor) -> ConsensusHost {
    let node = &contract.committee.roster.body.nodes[index];
    let transport = Transport::start(
        context.child("transport").with_attribute("index", index),
        Config {
            roster: contract.committee.roster.clone(),
            admins: contract.committee.admins.clone(),
            previous: None,
            institution_id: signer::inst(),
            environment_id: signer::env_id(),
            genesis_hash: contract.committee.anchor,
            committed_roster_hash: contract.committee.anchor,
            now: now(),
            node_id: node.node_id.clone(),
            transport_key: SigningKey::from_bytes(&[if index < 4 { 110 + index as u8 } else { 120 + index as u8 - 4 }; 32]),
        },
    )
    .unwrap();
    let context = context.child("consensus").with_attribute("index", index);
    if index < 4 {
        assert_ne!(node.transport_key, *node.consensus_key.as_ref().unwrap());
        ConsensusHost::start(
            context,
            transport,
            follower(contract, index, floor),
            contract.committee.keys[index].1.clone(),
        )
        .await
        .unwrap()
    } else {
        assert_eq!(node.node_id, core_id(index - 4));
        assert_eq!(node.roles, vec![Role::Signer]);
        assert!(node.consensus_key.is_none());
        assert!(!node.participant_keys.values().any(|key| *key == node.transport_key));
        let host = ConsensusHost::start_follower(context, transport, follower(contract, index, floor))
            .await
            .unwrap();
        assert!(host.runtime().proposer.is_none());
        host
    }
}

async fn ready(hosts: &mut [ConsensusHost], contract: &Contract) {
    let frame = PeerFrameV1::encode_public(
        &RosterState {
            roster_epoch: 0,
            roster_hash: contract.committee.anchor,
        },
        0,
        FrameKind::Control,
        1024,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut seen = BTreeSet::new();
    while seen.len() != hosts.len() * (hosts.len() - 1) {
        assert!(Instant::now() < deadline, "production TCP convergence exceeded 300s: {seen:?}");
        for (from, host) in hosts.iter().enumerate() {
            for (to, node) in contract.committee.roster.body.nodes[..hosts.len()].iter().enumerate() {
                if from != to {
                    // Only harmless readiness hints retry; ordered mutations
                    // below are each submitted once to one actual proposer.
                    let _ = host.sender().send(&node.node_id, 0, frame.clone()).await;
                }
            }
        }
        for (to, host) in hosts.iter_mut().enumerate() {
            while let Ok(Some(event)) = timeout(Duration::from_millis(5), host.recv()).await {
                if event.channel == 0 && event.bytes == frame {
                    seen.insert((event.from, to));
                }
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
    println!("30 directed authenticated TCP paths ready: four voting replicas and two independent keyless Signers");
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(45);
    while !predicate() {
        assert!(Instant::now() < deadline, "live finality did not converge");
        sleep(Duration::from_millis(50)).await;
    }
}

async fn ipc<T: Send + 'static>(harness: &Arc<Harness>, call: impl FnOnce(&Harness) -> T + Send + 'static) -> T {
    let harness = harness.clone();
    tokio::task::spawn_blocking(move || call(&harness)).await.unwrap()
}

async fn prepare_over_tcp(hosts: &mut [ConsensusHost], harness: &Arc<Harness>, session: &SigningSessionId) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut delivered = BTreeSet::new();
    loop {
        let frames = ipc(harness, |harness| {
            let mut frames = Vec::new();
            for (from, client) in harness.clients.iter().enumerate() {
                let mut offset = 0;
                while let Some(frame) = client.outbound_at(offset).unwrap() {
                    frames.push((from, frame));
                    offset += 1;
                }
            }
            frames
        })
        .await;
        for (from, frame) in frames {
            // Exact retained signed frames may retransmit. There is no direct
            // IPC peer relay: actual TCP origin comes from host.recv below.
            hosts[from].sender().send(&frame.to, 20, frame.frame).await.unwrap();
        }
        for (to, host) in hosts.iter_mut().enumerate() {
            while let Ok(Some(event)) = timeout(Duration::from_millis(10), host.recv()).await {
                if event.channel == 20 {
                    assert_eq!(event.from, core_id(1 - to));
                    delivered.insert((to, sha256(&event.bytes)));
                    ipc(harness, move |harness| harness.clients[to].deliver(&event.from, event.bytes).unwrap()).await;
                }
            }
        }
        let session = session.clone();
        let prepared = ipc(harness, move |harness| {
            harness.clients.iter().all(|client| {
                matches!(
                    client
                        .control(
                            &NodeId::unchecked("gateway"),
                            SessionControl::Status {
                                request_id: 1,
                                session_id: session.clone()
                            }
                        )
                        .unwrap()
                        .result,
                    Ok(SessionResult::Accepted)
                )
            })
        })
        .await;
        if prepared {
            // Two commitments and two signed round-two packages crossed TCP.
            assert_eq!(delivered.len(), 4);
            println!("four distinct participant-authenticated FROST round frames delivered over the followers' real TCP custody lane");
            break;
        }
        assert!(Instant::now() < deadline, "FROST TCP rounds did not prepare both cores");
        sleep(Duration::from_millis(20)).await;
    }
}

#[test]
fn live_simplex_keyless_followers_and_tcp_mpc_gate_one_native_threshold_signature() {
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let config = runtime::Config::default();
    let _cleanup = Cleanup(config.storage_directory().to_owned());
    runtime::Runner::new(config).start(|context| async move {
        timeout(Duration::from_secs(700), async {
            let contract = Arc::new(live_contract());
            let genesis = contract.fixture.genesis(&contract.committee);
            let floor = FinalizedFloor::at(&genesis);
            let mut commands = contract.fixture.bootstrap();
            commands.extend(contract.fixture.approvals());
            commands.push(Command::Reserve(Box::new(contract.proof.clone())));
            contract.fixture.executor.execute(ReplicatedState::default(), &commands, now()).expect("live native fixture must independently verify");
            let mut hosts = Vec::new();
            for index in 0..6 { hosts.push(boot(&context, &contract, index, floor).await); }
            ready(&mut hosts, &contract).await;
            hosts[0].runtime().proposer.as_ref().unwrap().submit(commands).unwrap();
            wait_for(|| hosts.iter().all(|host| host.runtime().progress.borrow().state.authority.reservations.len() == 1)).await;
            let sources = vec![hosts[4].runtime().verified_log.clone(), hosts[5].runtime().verified_log.clone()];
            for source in &sources {
                assert_eq!(source.borrow().as_ref().unwrap().authorize(&contract.proof.envelope).unwrap_err().code, ErrorCode::SessionRejected);
            }
            let setup = contract.clone();
            let harness = Arc::new(tokio::task::spawn_blocking(move || {
                let mut pins = setup.pins();
                pins.max_age_seconds = 900;
                Harness::start_sources(&setup, &sources, pins, Some(Arc::new(SystemClock))).unwrap()
            }).await.unwrap());
            let proof = contract.proof.clone();
            let materials = oic_service_builder::signing_materials(&contract.fixture.built.package);
            let initial_materials = materials.clone();
            ipc(&harness, move |harness| {
                for index in 0..2 {
                    assert_eq!(harness.remote(index, "gateway").open_finalized(&proof.envelope, &initial_materials).unwrap_err().code, ErrorCode::SessionRejected);
                    assert!(harness.clients[index].outbound_at(0).unwrap().is_none());
                }
                harness.assert_no_release();
            }).await;
            println!("reserve-only actual finalized logs rejected both IPC opens with no MPC frame or share audit");

            let body = &contract.proof.envelope;
            hosts[0].runtime().proposer.as_ref().unwrap().submit(vec![authority(AuthorityCommand::Release { request: ReleaseRequest {
                reservation_id: body.budget_reservation_id.clone(),
                reservation_version: body.reservation_version,
                envelope_body_hash: contract.proof.request.envelope_body_hash,
                signer_session_id: body.signer_session_id.clone(),
                expected_policy_epoch: body.policy_epoch,
                freshness: FreshnessContext { now: now() },
            }})]).unwrap();
            wait_for(|| hosts.iter().all(|host| host.runtime().verified_log.borrow().as_ref().is_some_and(|log| log.authorize(body).is_ok()))).await;
            for host in &hosts { assert_eq!(host.runtime().progress.borrow().state.authority.issuance.len(), 1); }

            // Stop voters only after both live followers durably re-execute
            // Release. Their still-running keyless runtimes and TCP MPC remain
            // live, but no new empty blocks can race the audit-floor assertion.
            let mut signers = hosts.split_off(4);
            for host in hosts { host.shutdown().await.unwrap(); }
            sleep(Duration::from_secs(2)).await;
            let floors: Vec<_> = signers.iter().map(|host| host.runtime().verified_log.borrow().as_ref().unwrap().floor()).collect();
            let open_body = body.clone();
            ipc(&harness, move |harness| {
                for index in 0..2 {
                    assert!(matches!(harness.remote(index, "gateway").open_finalized(&open_body, &materials).unwrap(), ProtocolStep::Waiting));
                }
                harness.assert_no_release();
            }).await;
            prepare_over_tcp(&mut signers, &harness, &body.signer_session_id).await;
            let session = body.signer_session_id.clone();
            let signature = ipc(&harness, move |harness| {
                harness.assert_no_release();
                let shares: Vec<_> = (0..2).map(|index| {
                    let mut steps = harness.remote(index, "gateway").release_finalized(&session).unwrap();
                    assert_eq!(steps.len(), 1);
                    let ProtocolStep::Share(share) = steps.remove(0) else { panic!("expected a FROST share") };
                    (signer::pid(index as u8 + 1), share)
                }).collect();
                let signature = harness.remote(0, "gateway").aggregate(&session, &shares).unwrap();
                // Retries return the same signature/share, not another release.
                assert_eq!(harness.remote(0, "gateway").aggregate(&session, &shares).unwrap(), signature);
                for (index, (_, share)) in shares.iter().enumerate() {
                    assert!(matches!(&harness.remote(index, "gateway").release_finalized(&session).unwrap()[0], ProtocolStep::Share(retry) if retry == share));
                }
                signature
            }).await;
            assert_eq!(signature.scheme, SchemeId::Ed25519Pure);
            let materials = oic_service_builder::signing_materials(&contract.fixture.built.package);
            let public = VerifyingKey::from_bytes(materials.key.public_key.bytes.as_slice().try_into().unwrap()).unwrap();
            let native = Signature::from_slice(signature.bytes.as_slice()).unwrap();
            let payload = &body.native_signing_payloads[0].message_or_digest;
            public.verify_strict(payload.as_slice(), &native).unwrap();
            let mut changed = payload.clone();
            changed.0[0] ^= 1;
            assert!(public.verify_strict(changed.as_slice(), &native).is_err());
            let adapter = oic_adapter_solana::SolanaAdapter;
            let signed = adapter.assemble_signed_transaction(&materials.candidate, &materials.key, &[signature]).unwrap();
            assert_eq!(adapter.verify_signed_transaction(&signed, &materials.candidate, &materials.key).unwrap().verified_signers, vec![materials.key.public_key.bytes.clone()]);

            for (index, audit) in harness.audits.iter().enumerate() {
                let events = audit.events_since(0, 128).unwrap();
                let releases: Vec<_> = events.iter().filter(|event| event.body.action == "signer.share_released").collect();
                assert_eq!(releases.len(), 1);
                assert_eq!(releases[0].body.object_commitments["finalized_block"], floors[index].digest);
                assert_eq!(releases[0].body.object_commitments["envelope"], contract.proof.request.envelope_body_hash);
                oic_audit::verify_checkpoint(&audit.checkpoint().unwrap(), &audit.verifying_key()).unwrap();
                assert_eq!(signers[index].runtime().progress.borrow().floor, floors[index]);
            }
            for host in signers { host.shutdown().await.unwrap(); }
            let mut rng = context.child("independent_certificate_check");
            for (index, floor) in floors.into_iter().enumerate() {
                let recovered = Follower::open(context.child("replay").with_attribute("index", index), follower(&contract, index + 4, floor), &mut rng).await.unwrap();
                assert_eq!(recovered.floor(), floor);
                let finalization = recovered.finalization().unwrap();
                contract.committee.trust.verify(&mut rng, recovered.tip(), finalization).unwrap();
                assert_eq!(finalization.certificate.signers.count(), 3);
                recovered.verified_log().unwrap().authorize(body).unwrap();
            }
            println!("native Solana signature independently verified; exactly one release per core, with each audit block tied to its own durable real 3-of-4 certificate");
            tokio::task::spawn_blocking(move || drop(harness)).await.unwrap();
        }).await.expect("live signing integration deadline");
    });
}
