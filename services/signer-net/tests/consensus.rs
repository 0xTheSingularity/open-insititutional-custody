//! Actual production Runner/TCP admission -> five native protocol channels ->
//! Simplex certificates -> marshal -> synced, independently re-executed log.
//! Reuse native/public fixtures, never Committee::certify or simulated networks.
#[path = "../../../crates/replicated-authority/tests/common/mod.rs"]
mod common;

use common::{Chain, Committee, Fixture, admin_signatures, authority, signer};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PrivateKey;
use commonware_runtime::{Runner as _, Supervisor as _, tokio as runtime};
use ed25519_dalek::SigningKey;
use oic_approval_verifier::sign_grant;
use oic_authorization_state::{AuthorityCommand, ReleaseRequest};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use oic_membership::{PeerClass, Role, TrustDomain, roster_hash};
use oic_node::{Config, SendHandle, Transport};
use oic_peer_wire::{ConsensusFrame, FrameKind, PeerFrameV1, RosterState};
use oic_replicated_authority::{Command, FinalityTrust, FinalizedFloor, Follower, FollowerConfig, ReplicatedState, ReserveCandidate};
use oic_service_signer_net::consensus::ConsensusHost;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::TcpListener,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, sleep, timeout};

fn now() -> UnixSeconds {
    UnixSeconds(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
}

fn run<F, Fut>(test: F)
where
    F: FnOnce(runtime::Context) -> Fut,
    Fut: Future<Output = ()>,
{
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let config = runtime::Config::default();
    let _cleanup = Cleanup(config.storage_directory().to_owned());
    runtime::Runner::new(config).start(|context| async move {
        timeout(Duration::from_secs(700), test(context)).await.expect("production consensus test deadline");
    });
}

fn committee() -> Committee {
    let mut committee = Committee::new();
    // Hold all ephemeral ports until the complete signed roster is assembled.
    let listeners: Vec<_> = (0..6).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    for (node, listener) in committee.roster.body.nodes.iter_mut().zip(&listeners) {
        node.address = listener.local_addr().unwrap();
        assert_ne!(node.transport_key, *node.consensus_key.as_ref().unwrap());
    }
    let mut independent = committee.roster.body.nodes[0].clone();
    independent.node_id = NodeId::unchecked("independent-signer");
    independent.domain_id = TrustDomainId::unchecked("independent-signer-domain");
    independent.roles = vec![Role::Signer];
    independent.consensus_key = None;
    independent.transport_key =
        PublicKey { scheme: SchemeId::Ed25519Pure, bytes: SigningKey::from_bytes(&[114; 32]).verifying_key().to_bytes().to_vec().into() };
    independent.attestation_key =
        Some(PublicKey { scheme: SchemeId::Ed25519Pure, bytes: SigningKey::from_bytes(&[117; 32]).verifying_key().to_bytes().to_vec().into() });
    independent.participant_keys = BTreeMap::from([(
        signer::pid(1),
        PublicKey { scheme: SchemeId::Ed25519Pure, bytes: SigningKey::from_bytes(&[118; 32]).verifying_key().to_bytes().to_vec().into() },
    )]);
    independent.approved_build_hashes = vec![Hash32([119; 32])];
    independent.address = listeners[4].local_addr().unwrap();
    committee.roster.body.trust_domains.push(TrustDomain {
        domain_id: independent.domain_id.clone(),
        administrators: vec![CredentialId::unchecked("independent-signer-owner")],
        failure_domain_notes: "Separate signer host, no consensus key".into(),
    });
    committee.roster.body.nodes.push(independent);
    let mut observer = committee.roster.body.nodes[0].clone();
    observer.node_id = NodeId::unchecked("independent-observer");
    observer.roles = vec![Role::Witness];
    observer.peer_class = PeerClass::Secondary;
    observer.consensus_key = None;
    observer.transport_key =
        PublicKey { scheme: SchemeId::Ed25519Pure, bytes: SigningKey::from_bytes(&[115; 32]).verifying_key().to_bytes().to_vec().into() };
    observer.address = listeners[5].local_addr().unwrap();
    committee.roster.body.nodes.push(observer);
    for acl in &mut committee.roster.body.channel_acl {
        if [0, 2, 4, 5].contains(&acl.channel) {
            acl.receiver_roles.push(Role::Signer);
        }
        if [0, 5].contains(&acl.channel) {
            acl.sender_roles.push(Role::Signer);
        }
    }
    resign(&mut committee);
    committee
}

fn resign(committee: &mut Committee) {
    committee.anchor = roster_hash(&committee.roster.body).unwrap();
    committee.roster.signatures = admin_signatures(committee.anchor);
    committee.trust =
        FinalityTrust::from_genesis(committee.roster.clone(), &committee.admins, &signer::inst(), &signer::env_id(), committee.anchor, now())
            .unwrap();
}

fn config(committee: &Committee, index: usize) -> Config {
    Config {
        roster: committee.roster.clone(),
        admins: committee.admins.clone(),
        previous: None,
        institution_id: signer::inst(),
        environment_id: signer::env_id(),
        genesis_hash: committee.anchor,
        committed_roster_hash: committee.anchor,
        now: now(),
        node_id: committee.roster.body.nodes[index].node_id.clone(),
        transport_key: SigningKey::from_bytes(&[110 + index as u8; 32]),
    }
}

fn follower(fixture: &Fixture, committee: &Committee, index: usize, floor: FinalizedFloor) -> FollowerConfig {
    FollowerConfig {
        partition: format!("socket-replica-{index}"),
        executor: fixture.executor.clone(),
        trust: committee.trust.clone(),
        genesis: fixture.genesis(committee),
        genesis_state: ReplicatedState::default(),
        minimum_floor: floor,
        local_now: now(),
    }
}

async fn boot(context: &runtime::Context, fixture: &Fixture, committee: &Committee, index: usize, floor: FinalizedFloor) -> ConsensusHost {
    let transport = Transport::start(context.child("transport").with_attribute("index", index), config(committee, index)).unwrap();
    ConsensusHost::start(
        context.child("consensus").with_attribute("index", index),
        transport,
        follower(fixture, committee, index, floor),
        committee.keys[index].1.clone(),
    )
    .await
    .unwrap()
}

async fn boot_follower(context: &runtime::Context, fixture: &Fixture, committee: &Committee, floor: FinalizedFloor) -> ConsensusHost {
    let transport = Transport::start(context.child("keyless_transport"), config(committee, 4)).unwrap();
    ConsensusHost::start_follower(context.child("keyless"), transport, follower(fixture, committee, 4, floor)).await.unwrap()
}

fn live_fixture() -> (Fixture, ReserveCandidate) {
    let clock = now();
    let mut fixture = Fixture::with_inputs(Chain::Evm, 2, |inputs| {
        inputs.intent.created_at = UnixSeconds(clock.0 - 100);
        inputs.built_at = clock;
        inputs.evidence.observed_at = clock;
        // The real socket admission budget is 300s; this fixture explicitly
        // grants a 900s evidence window rather than disabling freshness checks.
        inputs.evidence.max_staleness_seconds = 900;
        inputs.profile.max_evidence_age_seconds = 900;
        inputs.policy.max_evidence_age_seconds = 900;
    });
    fixture.profile = fixture.executor.registry.profiles[0].clone();
    for (index, grant) in fixture.grants.iter_mut().enumerate() {
        let mut body = grant.body.clone();
        body.issued_at = clock;
        body.expires_at = UnixSeconds(clock.0 + 900);
        *grant = sign_grant(&SigningKey::from_bytes(&[61 + index as u8; 32]), body).unwrap();
    }
    let mut proof = fixture.proof();
    proof.envelope.issuance_deadline = UnixSeconds(clock.0 + 900);
    proof.request.issuance_deadline = proof.envelope.issuance_deadline;
    proof.request.envelope_body_hash = domain_hash(domains::AUTHORIZATION, &proof.envelope).unwrap();
    (fixture, proof)
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(45);
    while !predicate() {
        assert!(Instant::now() < deadline, "native consensus did not converge");
        sleep(Duration::from_millis(50)).await;
    }
}

// Control DATA can arrive before the periodic internal roster HELLO. Only
// non-mutating malformed-certificate probes use this admission retry helper.
async fn send_probe(sender: &SendHandle, to: &NodeId, bytes: Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        match sender.send(to, 2, bytes.clone()).await {
            Ok(()) => break,
            Err(error) if matches!(error.code, ErrorCode::RosterMismatch | ErrorCode::Conflict) => {
                assert!(Instant::now() < deadline, "certificate probe admission exceeded 300s");
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("certificate probe rejected: {error:?}"),
        }
    }
}

// Only these harmless read-only convergence hints are retried. Ordered
// commands are submitted once; no automatic mutation retransmission.
async fn ready(hosts: &mut [ConsensusHost], committee: &Committee) {
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut seen = BTreeSet::new();
    let frame = PeerFrameV1::encode_public(&RosterState { roster_epoch: 0, roster_hash: committee.anchor }, 0, FrameKind::Control, 1024).unwrap();
    let count = hosts.len();
    while seen.len() != count * (count - 1) {
        assert!(Instant::now() < deadline, "production peer convergence exceeded 300s: {seen:?}");
        for (from, host) in hosts.iter().enumerate() {
            for (to, node) in committee.roster.body.nodes[..count].iter().enumerate() {
                if from != to {
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
    println!("all {} directed authenticated TCP paths converged (distinct transport/vote keys)", seen.len());
}

#[test]
fn four_replicas_and_late_keyless_signer_finalize_catch_up_and_reopen() {
    run(|context| async move {
        let committee = committee();
        let (fixture, proof) = live_fixture();
        let mut commands = fixture.bootstrap();
        commands.extend(fixture.approvals());
        commands.push(Command::Reserve(Box::new(proof.clone())));
        fixture.executor.execute(ReplicatedState::default(), &commands, now()).expect("live native fixture must independently verify");
        let genesis = fixture.genesis(&committee);
        let floor = FinalizedFloor::at(&genesis);
        let mut hosts = Vec::new();
        for index in 0..4 {
            hosts.push(boot(&context, &fixture, &committee, index, floor).await);
        }
        ready(&mut hosts, &committee).await;

        // Wrong carrier/epoch never enters a native actor. Honest empty blocks
        // may finalize during convergence, but cannot manufacture custody state.
        let target = &committee.keys[0].0;
        for frame in [vec![0xff], ConsensusFrame::encode(&[], 1, 2, 1024).unwrap(), ConsensusFrame::encode(&[], 0, 1, 1024).unwrap()] {
            send_probe(&hosts[1].sender(), target, frame).await;
        }
        sleep(Duration::from_millis(100)).await;
        for host in &hosts {
            assert_eq!(host.runtime().progress.borrow().state.hash().unwrap(), ReplicatedState::default().hash().unwrap());
            assert!(host.runtime().verified_log.borrow().as_ref().is_none_or(|log| log.authorize(&proof.envelope).is_err()));
        }

        // Submit once to one actual replica. Its next leader turn must carry
        // the batch; the adapter never retries an uncertain mutation.
        hosts[0].runtime().proposer.as_ref().unwrap().submit(commands).unwrap();
        wait_for(|| hosts.iter().all(|host| host.runtime().progress.borrow().state.authority.reservations.len() == 1)).await;
        for host in &hosts {
            assert!(host.runtime().progress.borrow().state.authority.issuance.is_empty());
            assert_eq!(
                host.runtime().verified_log.borrow().as_ref().unwrap().authorize(&proof.envelope).unwrap_err().code,
                ErrorCode::SessionRejected
            );
        }
        println!("genuine socket finality reserved the independently verified EVM candidate; no pre-Release authorization");

        let release = authority(AuthorityCommand::Release {
            request: ReleaseRequest {
                reservation_id: proof.envelope.budget_reservation_id.clone(),
                reservation_version: 1,
                envelope_body_hash: proof.request.envelope_body_hash,
                signer_session_id: proof.envelope.signer_session_id.clone(),
                expected_policy_epoch: proof.envelope.policy_epoch,
                freshness: FreshnessContext { now: now() },
            },
        });
        hosts[0].runtime().proposer.as_ref().unwrap().submit(vec![release]).unwrap();
        wait_for(|| hosts.iter().all(|host| host.runtime().verified_log.borrow().as_ref().is_some_and(|log| log.authorize(&proof.envelope).is_ok())))
            .await;
        let expected = hosts[0].runtime().progress.borrow().state.hash().unwrap();
        for host in &hosts {
            assert_eq!(host.runtime().progress.borrow().state.authority.issuance.len(), 1);
            assert_eq!(host.runtime().progress.borrow().state.hash().unwrap(), expected);
            assert_eq!(host.runtime().verified_log.borrow().as_ref().unwrap().anchor().roster, committee.anchor);
        }
        println!("four actual engines finalized Release, matching native state roots and synced VerifiedLog capabilities");

        // Start with genesis AFTER Release. The distinct primary-transport
        // Signer is a marshal secondary, never a committee-key alias. Native
        // finalization traffic on 2 and block/backfill on 4/5 must reconstruct
        // the earlier commands before it can mint its own VerifiedLog.
        let independent = &committee.roster.body.nodes[4];
        assert!(independent.consensus_key.is_none());
        let keyless = boot_follower(&context, &fixture, &committee, floor).await;
        assert!(keyless.runtime().proposer.is_none());
        hosts.push(keyless);
        ready(&mut hosts, &committee).await;
        wait_for(|| hosts[4].runtime().verified_log.borrow().as_ref().is_some_and(|log| log.authorize(&proof.envelope).is_ok())).await;
        assert_eq!(hosts[4].runtime().progress.borrow().state.hash().unwrap(), expected);
        assert_eq!(hosts[4].runtime().progress.borrow().state.authority.issuance.len(), 1);
        for channel in 1..=4 {
            assert_eq!(hosts[4].sender().send(target, channel, vec![]).await.unwrap_err().code, ErrorCode::PeerNotAdmitted);
        }
        for channel in [1, 3] {
            assert_eq!(hosts[0].sender().send(&independent.node_id, channel, vec![]).await.unwrap_err().code, ErrorCode::PeerNotAdmitted);
        }
        println!("late independent Signer caught up from genesis over real TCP, re-executed Release and published VerifiedLog without a vote key");

        // Do not drain unrelated traffic during this bounded burst. Consensus
        // keeps progressing and the independent custody queue still delivers.
        for _ in 0..300 {
            let _ = hosts[1].sender().send(target, 2, ConsensusFrame::encode(&[], 1, 2, 1024).unwrap()).await;
        }
        let custody = vec![42; 32];
        hosts[1].sender().send(target, 0, custody.clone()).await.unwrap();
        timeout(Duration::from_secs(5), async {
            loop {
                let event = hosts[0].recv().await.unwrap();
                if event.channel == 0 && event.bytes == custody {
                    break;
                }
            }
        })
        .await
        .expect("consensus flood blocked unrelated custody delivery");

        let floors: Vec<_> = hosts.iter().map(|host| host.runtime().progress.borrow().floor).collect();
        for host in hosts {
            host.shutdown().await.unwrap();
        }
        // Listener reuse is exercised by the actual production Transport, not
        // merely by a bare OS port probe. Local floor comes from outside replay.
        let restarted = boot(&context, &fixture, &committee, 0, floors[0]).await;
        assert!(restarted.runtime().progress.borrow().floor.height >= floors[0].height);
        assert_eq!(restarted.runtime().progress.borrow().state.hash().unwrap(), expected);
        restarted.runtime().verified_log.borrow().as_ref().unwrap().authorize(&proof.envelope).unwrap();
        restarted.shutdown().await.unwrap();
        let restarted_signer = boot_follower(&context, &fixture, &committee, floors[4]).await;
        assert!(restarted_signer.runtime().proposer.is_none());
        assert!(restarted_signer.runtime().progress.borrow().floor.height >= floors[4].height);
        assert_eq!(restarted_signer.runtime().progress.borrow().state.hash().unwrap(), expected);
        restarted_signer.runtime().verified_log.borrow().as_ref().unwrap().authorize(&proof.envelope).unwrap();
        restarted_signer.shutdown().await.unwrap();

        let mut rng = context.child("certificate_replay");
        for index in [0, 4] {
            let recovered = Follower::open(
                context.child("independent_reopen").with_attribute("index", index),
                follower(&fixture, &committee, index, floors[index]),
                &mut rng,
            )
            .await
            .unwrap();
            let certificate = recovered.finalization().unwrap();
            committee.trust.verify(&mut rng, recovered.tip(), certificate).unwrap();
            assert_eq!(certificate.certificate.signers.count(), 3, "certificate must contain a real quorum, never a synthetic snapshot");
            recovered.verified_log().unwrap().authorize(&proof.envelope).unwrap();
        }
        println!("replica and keyless Signer clean stop/listener reuse and durable replay verified genuine 3-of-4 certificates at retained floors");
    });
}

#[test]
fn constructors_reject_wrong_keys_rosters_roles_and_narrower_signed_acl() {
    run(|context| async move {
        let committee = committee();
        let fixture = Fixture::new(Chain::Evm, 2);
        let floor = FinalizedFloor::at(&fixture.genesis(&committee));
        let transport = Transport::start(context.child("wrong_key_transport"), config(&committee, 0)).unwrap();
        let transport_key = PrivateKey::decode([110; 32].as_slice()).unwrap();
        let result = ConsensusHost::start(context.child("wrong_key"), transport, follower(&fixture, &committee, 0, floor), transport_key).await;
        assert!(matches!(result, Err(OicError { code: ErrorCode::ScopeMismatch, .. })));

        let transport = Transport::start(context.child("wrong_roster_transport"), config(&committee, 0)).unwrap();
        let mut other = follower(&fixture, &committee, 0, floor);
        other.trust = Committee::with_seed(8123).trust;
        let result = ConsensusHost::start(context.child("wrong_roster"), transport, other, committee.keys[0].1.clone()).await;
        assert!(matches!(result, Err(OicError { code: ErrorCode::ScopeMismatch, .. })));

        let transport = Transport::start(context.child("observer_transport"), config(&committee, 4)).unwrap();
        let result =
            ConsensusHost::start(context.child("observer"), transport, follower(&fixture, &committee, 4, floor), committee.keys[0].1.clone()).await;
        assert!(
            matches!(result, Err(OicError { code: ErrorCode::PeerNotAdmitted, .. })),
            "a separately admitted observer cannot impersonate a replica"
        );
        for index in [0, 5] {
            let transport = Transport::start(context.child("wrong_follower_role").with_attribute("index", index), config(&committee, index)).unwrap();
            let result =
                ConsensusHost::start_follower(context.child("wrong_follower"), transport, follower(&fixture, &committee, index, floor)).await;
            assert!(matches!(result, Err(OicError { code: ErrorCode::PeerNotAdmitted, .. })), "neither a replica nor a Witness is a keyless Signer");
        }
        let mut narrower = committee;
        narrower.roster.body.channel_acl.iter_mut().find(|acl| acl.channel == 5).unwrap().sender_roles = vec![Role::Authority];
        resign(&mut narrower);
        let transport = Transport::start(context.child("narrower_transport"), config(&narrower, 4)).unwrap();
        let result = ConsensusHost::start_follower(context.child("narrower"), transport, follower(&fixture, &narrower, 4, floor)).await;
        assert!(matches!(result, Err(OicError { code: ErrorCode::PeerNotAdmitted, .. })), "local follower path cannot widen the signed ACL");
    });
}

#[test]
fn authenticated_malformed_certificates_cannot_advance_keyless_log() {
    run(|context| async move {
        let committee = committee();
        let fixture = Fixture::new(Chain::Evm, 2);
        let floor = FinalizedFloor::at(&fixture.genesis(&committee));
        // No voting engine runs here, so even honest empty finalizations cannot
        // mask false progress caused by an authenticated but invalid carrier.
        let mut peer = Transport::start(context.child("raw_replica"), config(&committee, 0)).unwrap();
        let mut keyless = boot_follower(&context, &fixture, &committee, floor).await;
        let replica_id = &committee.keys[0].0;
        let signer_id = &committee.roster.body.nodes[4].node_id;
        let probe = PeerFrameV1::encode_public(&RosterState { roster_epoch: 0, roster_hash: committee.anchor }, 0, FrameKind::Control, 1024).unwrap();
        let deadline = Instant::now() + Duration::from_secs(300);
        let (mut received_peer, mut received_signer) = (false, false);
        while !received_peer || !received_signer {
            assert!(Instant::now() < deadline, "keyless production connection exceeded 300s");
            let _ = peer.sender().send(signer_id, 0, probe.clone()).await;
            let _ = keyless.sender().send(replica_id, 0, probe.clone()).await;
            if let Ok(Some(event)) = timeout(Duration::from_millis(10), peer.recv()).await {
                received_peer |= event.channel == 0 && event.from == *signer_id && event.bytes == probe;
            }
            if let Ok(Some(event)) = timeout(Duration::from_millis(10), keyless.recv()).await {
                received_signer |= event.channel == 0 && event.from == *replica_id && event.bytes == probe;
            }
            sleep(Duration::from_millis(200)).await;
        }
        for channel in 1..=4 {
            assert_eq!(keyless.sender().send(replica_id, channel, vec![]).await.unwrap_err().code, ErrorCode::PeerNotAdmitted);
        }
        for channel in [1, 3] {
            assert_eq!(peer.sender().send(signer_id, channel, vec![]).await.unwrap_err().code, ErrorCode::PeerNotAdmitted);
        }
        for bytes in [
            vec![0xff],
            ConsensusFrame::encode(&[0xff], 0, 2, 1024).unwrap(),
            ConsensusFrame::encode(&[], 1, 2, 1024).unwrap(),
            ConsensusFrame::encode(&[], 0, 1, 1024).unwrap(),
        ] {
            send_probe(&peer.sender(), signer_id, bytes).await;
        }
        sleep(Duration::from_secs(1)).await;
        assert!(keyless.runtime().proposer.is_none());
        assert_eq!(keyless.runtime().progress.borrow().floor, floor);
        assert_eq!(keyless.runtime().progress.borrow().state.hash().unwrap(), ReplicatedState::default().hash().unwrap());
        assert!(keyless.runtime().verified_log.borrow().is_none());
        keyless.shutdown().await.unwrap();
        peer.shutdown().await.unwrap();
        println!("authenticated malformed native certificates, wrong epochs/kinds and forbidden vote directions produced no keyless finality");
    });
}
