//! Production Commonware sockets -> Bridge -> restricted public consumers.
//! The test driver holds the admitted producer's raw Transport only to inject
//! malformed frames. Extensions receive neither that handle nor a custody API.
#[path = "../../coordinator/tests/common/mod.rs"]
mod common;

use common::{World, authority_key_id, env_id, inst, now, policy, rule, vault_id};
use commonware_runtime::{Network as _, Runner as _, Supervisor as _, tokio as runtime};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use oic_authorization_state::{
    ReceiptExpectation, ReservationState, ReserveRequest, SignedCheckpoint, checkpoint_hash, verify_checkpoint, verify_receipt,
};
use oic_domain_types::*;
use oic_membership::{
    Activation, AdminTrust, ChannelSpec, Committee, CommitteeKind, Node, PeerClass, Role, RosterBody, SignedRoster, TrustDomain, roster_hash,
};
use oic_node::{Config, EXTENSION_MAILBOX_CAPACITY, Extension, ExtensionContext, ExtensionHandle, ReceiptMonitor, Transport};
use oic_peer_wire::{AuthorityRequest, FrameKind, HEADER_LEN, MAX_BODY_LEN, PeerFrameV1, SessionControl, WitnessMessage};
use oic_policy_kernel::Decision;
use oic_service_authority_rpc::{AuthorityEndpoint, AuthorityRpcClient, AuthorityRpcServer};
use oic_service_signer_core::ipc;
use oic_service_signer_net::{AuthorityHandler, Bridge};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::{Future, pending},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{oneshot, watch},
    time::{Instant, sleep, timeout},
};

const AUTHORITY: u8 = 0;
const GATEWAY: u8 = 1;
const PRODUCER: u8 = 2;
const OBSERVE: u64 = 1024;
const SLOW: u64 = 1025;

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
        timeout(Duration::from_secs(340), test(context)).await.expect("extension E2E deadline");
    });
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn node_id(n: u8) -> NodeId {
    NodeId::unchecked(format!("extension-e2e-{n}"))
}
fn public(key: &SigningKey) -> PublicKey {
    PublicKey { scheme: SchemeId::Ed25519Pure, bytes: key.verifying_key().to_bytes().to_vec().into() }
}
fn channel(channel: u64) -> ChannelSpec {
    ChannelSpec { channel, sender_roles: vec![Role::Extension], receiver_roles: vec![Role::Gateway], max_message_size: 8192, quota: 100 }
}
fn roster(world: &World) -> (SignedRoster, AdminTrust) {
    let listeners: Vec<_> = (0..3).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    let nodes: Vec<_> = [Role::Authority, Role::Gateway, Role::Extension]
        .into_iter()
        .enumerate()
        .map(|(n, role)| Node {
            node_id: node_id(n as u8),
            domain_id: TrustDomainId::unchecked(format!("domain-{n}")),
            roles: vec![role],
            transport_key: public(&key(100 + n as u8)),
            consensus_key: None,
            attestation_key: None,
            address: listeners[n].local_addr().unwrap(),
            peer_class: if role == Role::Extension { PeerClass::Secondary } else { PeerClass::Primary },
            participant_keys: BTreeMap::new(),
            approved_build_hashes: Vec::new(),
            signer_instance_generation: Epoch(0),
        })
        .collect();
    let primary = vec![Role::Gateway, Role::Authority];
    let body = RosterBody {
        institution_id: inst(),
        environment_id: env_id(),
        roster_epoch: 0,
        previous_roster_hash: Hash32::ZERO,
        genesis_hash: Hash32::ZERO,
        commonware_release: "2026.9.0".into(),
        wire_version: 1,
        trust_domains: nodes
            .iter()
            .map(|n| TrustDomain {
                domain_id: n.domain_id.clone(),
                administrators: vec![CredentialId::unchecked("domain-admin")],
                failure_domain_notes: "Independent operator/IAM/hardware/backup".into(),
            })
            .collect(),
        nodes,
        committees: vec![Committee {
            committee_id: CommitteeId::unchecked("authority"),
            kind: CommitteeKind::AuthorityD1,
            members: vec![node_id(AUTHORITY)],
            threshold: 1,
        }],
        channel_acl: vec![
            ChannelSpec { channel: 0, sender_roles: primary.clone(), receiver_roles: primary.clone(), max_message_size: 4096, quota: 100 },
            ChannelSpec { channel: 12, sender_roles: primary.clone(), receiver_roles: primary, max_message_size: 8192, quota: 100 },
            channel(OBSERVE),
            channel(SLOW),
        ],
        tolerated_domain_compromises: 1,
        activation: Activation { not_before: UnixSeconds(1), authority_commit_reference: None },
    };
    let hash = roster_hash(&body).unwrap();
    let signatures = world.admins[..2]
        .iter()
        .map(|(id, key)| CredentialSignature {
            credential_id: id.clone(),
            signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: key.sign(hash.as_ref()).to_bytes().to_vec().into() },
        })
        .collect();
    (
        SignedRoster { body, signatures },
        AdminTrust { threshold: 2, credentials: world.admins.iter().map(|(id, key)| (id.clone(), public(key))).collect() },
    )
}
fn config(roster: &SignedRoster, admins: &AdminTrust, node: u8) -> Config {
    let hash = roster_hash(&roster.body).unwrap();
    Config {
        roster: roster.clone(),
        admins: admins.clone(),
        previous: None,
        institution_id: inst(),
        environment_id: env_id(),
        genesis_hash: hash,
        committed_roster_hash: hash,
        now: now(),
        node_id: node_id(node),
        transport_key: key(100 + node),
    }
}
fn frame(checkpoint: &SignedCheckpoint) -> Vec<u8> {
    PeerFrameV1::encode_public(&WitnessMessage::AuthorityCheckpoint(checkpoint.clone()), 0, FrameKind::Audit, 8192 - HEADER_LEN).unwrap()
}

/// Fixture publications come from three real, distinct authority states. The
/// middle checkpoint is sent ONLY in invalid frames, making bypasses observable.
fn reserve_fixture(world: &World) -> (ReserveRequest, [SignedCheckpoint; 3]) {
    let first = world.authority.checkpoint().unwrap();
    let asset = AssetId::unchecked("asset");
    let active_rule = rule(&asset, 0, 200);
    let policy = world.sign_policy(policy(1, vec![active_rule.clone()]));
    world.authority.set_policy(&policy).unwrap();
    let middle = world.authority.checkpoint().unwrap();
    let intent = Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked("extension-concurrent-reserve"),
        institution_id: inst(),
        environment_id: env_id(),
        vault_id: vault_id(),
        chain_wallet_id: ChainWalletId::unchecked("wallet"),
        chain_profile_id: ChainProfileId::unchecked("profile"),
        operation: IntentOperation::AssetTransfer {
            asset_id: asset.clone(),
            amount_base_units: Amount(60),
            destination_id: DestinationId::unchecked("destination"),
            destination_version: 1,
        },
        constraints: IntentConstraints {
            max_network_fee_base_units: Amount(10),
            approval_mode: ApprovalMode::ExactCandidate,
            maximum_successful_payments: 1,
        },
        purpose: OperationPurpose::Settlement,
        external_reference: "fixture".into(),
        proposer_credential_id: CredentialId::unchecked("proposer"),
        created_at: now(),
    };
    world.register(&policy, &intent);
    let registered = world.authority.checkpoint().unwrap();
    let request = ReserveRequest {
        family_id: oic_authorization_state::family_id_for(&intent.intent_id).unwrap(),
        candidate_id: CandidateId::unchecked("candidate"),
        candidate_revision: 1,
        vault_id: vault_id(),
        intent_id: intent.intent_id,
        policy_epoch: policy.policy_epoch,
        policy_hash: world.authority.current_policy().unwrap().1,
        claims: ResourceClaims {
            resources: vec![NativeResource::EvmNonce { network_id: NetworkId::unchecked("network"), sender: vec![7; 20].into(), nonce: 1 }],
            asset_outflows: vec![AssetOutflow { asset_id: asset.clone(), amount_base_units: Amount(60) }],
            native_fees: Vec::new(),
        },
        grants: Vec::new(),
        envelope_body_hash: Hash32([50; 32]),
        signer_session_id: SigningSessionId::unchecked("session"),
        issuance_deadline: UnixSeconds(common::NOW + 300),
        policy_decision: Decision::Allow { rule_id: active_rule.rule_id },
        exposure_limits: active_rule.rolling_limits.into_iter().map(|limit| (asset.clone(), limit)).collect(),
    };
    (request, [first, middle, registered])
}

struct Live(Arc<AtomicUsize>);
impl Live {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count)
    }
}
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Debug, Default)]
struct Seen {
    hashes: BTreeSet<Hash32>,
    from: Option<NodeId>,
    channel: Option<u64>,
    namespace: String,
}

/// Read-only network reference consumer. Artifact verification stays explicit;
/// transport authentication alone does not authenticate an authority checkpoint.
struct CheckpointConsumer {
    key: VerifyingKey,
    seen: watch::Sender<Seen>,
    live: Arc<AtomicUsize>,
}
impl Extension for CheckpointConsumer {
    fn channels(&self) -> Vec<ChannelSpec> {
        vec![channel(OBSERVE)]
    }
    fn start(self: Box<Self>, mut context: ExtensionContext) -> ExtensionHandle {
        let live = Live::new(self.live.clone());
        tokio::spawn(async move {
            let _live = live;
            let mut seen = Seen { namespace: context.namespace().to_owned(), ..Seen::default() };
            while let Some(event) = context.recv().await {
                let WitnessMessage::AuthorityCheckpoint(checkpoint) = event.message else { continue };
                if checkpoint.body.institution_id != context.roster().body.institution_id
                    || checkpoint.body.environment_id != context.roster().body.environment_id
                    || checkpoint.authority_key_id != authority_key_id()
                    || verify_checkpoint(&checkpoint, &self.key).is_err()
                {
                    continue;
                }
                seen.hashes.insert(checkpoint_hash(&checkpoint.body).unwrap());
                seen.from = Some(event.from);
                seen.channel = Some(event.channel);
                self.seen.send_replace(seen.clone());
            }
        })
    }
}

struct SlowConsumer {
    resume: oneshot::Receiver<()>,
    drained: oneshot::Sender<usize>,
    live: Arc<AtomicUsize>,
}
impl Extension for SlowConsumer {
    fn channels(&self) -> Vec<ChannelSpec> {
        vec![channel(SLOW)]
    }
    fn start(self: Box<Self>, mut context: ExtensionContext) -> ExtensionHandle {
        let live = Live::new(self.live.clone());
        tokio::spawn(async move {
            let _live = live;
            let _ = self.resume.await;
            let mut count = 0;
            while let Ok(Some(_)) = timeout(Duration::ZERO, context.recv()).await {
                count += 1;
            }
            let _ = self.drained.send(count);
            // Shutdown must cancel even a consumer waiting on unrelated work.
            pending::<()>().await;
        })
    }
}

async fn observed(seen: &mut watch::Receiver<Seen>, hash: Hash32) {
    timeout(Duration::from_secs(10), async {
        while !seen.borrow_and_update().hashes.contains(&hash) {
            seen.changed().await.expect("consumer stopped");
        }
    })
    .await
    .expect("typed public delivery deadline");
}

#[test]
fn startup_rejects_epoch_core_and_duplicate_claims_without_leaking_started_tasks() {
    run(|context| async move {
        let world = World::new();
        let live = Arc::new(AtomicUsize::new(0));
        for case in 0..4 {
            let (roster, admins) = roster(&world);
            let transport = Transport::start(context.child("startup").with_attribute("case", case), config(&roster, &admins, GATEWAY)).unwrap();
            let core = (case == 1).then(|| ipc::Client::new("/unused-fixture-core.sock"));
            let (bridge, _) = Bridge::new(transport, if case == 0 { 1 } else { 0 }, core, None);
            let extension = || {
                let (seen, _) = watch::channel(Seen::default());
                Box::new(CheckpointConsumer { key: world.authority.verifying_key(), seen, live: live.clone() }) as Box<dyn Extension>
            };
            let result = match case {
                0 | 1 => bridge.with_extensions(Vec::new()),
                2 => bridge.with_extensions(vec![("first".into(), extension()), ("duplicate".into(), extension())]),
                _ => bridge.with_extensions(vec![("first".into(), extension())]).unwrap().with_extensions(Vec::new()),
            };
            assert_eq!(
                result.err().unwrap().code,
                match case {
                    0 => ErrorCode::RosterMismatch,
                    1 => ErrorCode::PolicyDenied,
                    2 => ErrorCode::PolicyDenied,
                    _ => ErrorCode::Conflict,
                }
            );
            timeout(Duration::from_secs(3), async {
                while live.load(Ordering::SeqCst) != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    });
}

#[test]
fn real_socket_public_consumer_rejects_bad_frames_and_full_extension_does_not_block_reserve() {
    run(|context| async move {
        let world = World::new();
        let (request, [first, forbidden, barrier]) = reserve_fixture(&world);
        let (roster, admins) = roster(&world);
        assert_eq!(roster.node(&node_id(PRODUCER)).unwrap().peer_class, PeerClass::Secondary);
        let addresses: Vec<_> = roster.body.nodes.iter().map(|node| node.address).collect();
        let authority_transport = Transport::start(context.child("authority"), config(&roster, &admins, AUTHORITY)).unwrap();
        let gateway_transport = Transport::start(context.child("gateway"), config(&roster, &admins, GATEWAY)).unwrap();
        let producer = Transport::start(context.child("extension"), config(&roster, &admins, PRODUCER)).unwrap();
        let sender = gateway_transport.sender();
        let probe = PeerFrameV1::encode_confidential(
            &SessionControl::Status { request_id: 99_000, session_id: SigningSessionId::unchecked("nonmutating-startup") },
            0,
            FrameKind::Content,
            MAX_BODY_LEN,
        )
        .unwrap();
        let (ready, mut authority_ready) = watch::channel(false);
        let mutations = Arc::new(AtomicUsize::new(0));
        let handler: AuthorityHandler = {
            let authority = world.authority.clone();
            let roster = roster.clone();
            let probe = probe.clone();
            let mutations = mutations.clone();
            Arc::new(move |from, bytes| {
                let server = AuthorityRpcServer::new(authority.as_ref(), &roster, &node_id(AUTHORITY))?;
                if bytes == probe {
                    let error = server.handle(from, bytes).unwrap_err();
                    assert_eq!(error.code, ErrorCode::InvalidRequest);
                    ready.send_replace(true);
                    return Err(error);
                }
                if AuthorityRequest::decode(bytes, 0, MAX_BODY_LEN).is_ok() {
                    mutations.fetch_add(1, Ordering::SeqCst);
                }
                server.handle(from, bytes)
            })
        };
        let (authority_bridge, authority_gateway) = Bridge::new(authority_transport, 0, None, Some(handler));
        let (gateway_bridge, gateway) = Bridge::new(gateway_transport, 0, None, None);
        let live = Arc::new(AtomicUsize::new(0));
        let (seen, mut observations) = watch::channel(Seen::default());
        let (resume, resumed) = oneshot::channel();
        let (drained, drain_count) = oneshot::channel();
        let (monitor, mut receipts) = ReceiptMonitor::new();
        let gateway_bridge = gateway_bridge
            .with_extensions(vec![
                ("checkpoints".into(), Box::new(CheckpointConsumer { key: world.authority.verifying_key(), seen, live: live.clone() })),
                ("slow".into(), Box::new(SlowConsumer { resume: resumed, drained, live: live.clone() })),
                ("receipts".into(), Box::new(monitor)),
            ])
            .unwrap();
        let (stop_authority, authority_stopped) = oneshot::channel();
        let authority_task = tokio::spawn(authority_bridge.run(authority_stopped));
        let (stop_gateway, gateway_stopped) = oneshot::channel();
        let gateway_task = tokio::spawn(gateway_bridge.run(gateway_stopped));

        let started = Instant::now();
        let initial_hash = checkpoint_hash(&first.body).unwrap();
        // Read-only retries only. Production loopback handshake quotas/cooldowns
        // remain unchanged; native mutation RPCs below are each submitted once.
        timeout(Duration::from_secs(300), async {
            while !*authority_ready.borrow_and_update() || !observations.borrow().hashes.contains(&initial_hash) {
                for result in
                    [sender.send(&node_id(AUTHORITY), 12, probe.clone()).await, producer.send(&node_id(GATEWAY), OBSERVE, frame(&first)).await]
                {
                    if let Err(error) = result {
                        assert!(matches!(error.code, ErrorCode::RosterMismatch | ErrorCode::Conflict), "read-only convergence: {error}");
                    }
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .expect("production socket convergence deadline");
        println!("extension/RPC socket readiness: {}ms", started.elapsed().as_millis());
        assert_eq!(mutations.load(Ordering::SeqCst), 0);
        assert_eq!(observations.borrow().from, Some(node_id(PRODUCER)));
        assert_eq!(observations.borrow().channel, Some(OBSERVE));
        assert_eq!(observations.borrow().namespace, "OIC/EXT/checkpoints/v1");
        let before = world.authority.store().snapshot();

        let mut malformed = frame(&forbidden);
        let wrong_length = (malformed.len() - HEADER_LEN + 1) as u32;
        malformed[12..16].copy_from_slice(&wrong_length.to_be_bytes());
        let mut wrong_epoch = frame(&forbidden);
        wrong_epoch[2..10].copy_from_slice(&1u64.to_be_bytes());
        let mut wrong_kind = frame(&forbidden);
        wrong_kind[10..12].copy_from_slice(&(FrameKind::Control as u16).to_be_bytes());
        for bytes in [malformed, wrong_epoch, wrong_kind] {
            producer.send(&node_id(GATEWAY), OBSERVE, bytes).await.unwrap();
        }
        // Same producer/connection/channel provides the processing barrier.
        producer.send(&node_id(GATEWAY), OBSERVE, frame(&barrier)).await.unwrap();
        let barrier_hash = checkpoint_hash(&barrier.body).unwrap();
        observed(&mut observations, barrier_hash).await;
        assert_eq!(observations.borrow().hashes, BTreeSet::from([initial_hash, barrier_hash]));
        assert_eq!(world.authority.store().snapshot(), before);
        assert_eq!(receipts.borrow().commit_sequence, None);

        let flood_sender = producer.sender();
        let flood_frame = frame(&barrier);
        let (halt_flood, mut flood_stopped) = oneshot::channel();
        let (submitted, mut submitted_count) = watch::channel(0usize);
        let flood = tokio::spawn(async move {
            let mut count = 0;
            loop {
                tokio::select! { _ = &mut flood_stopped => break, _ = sleep(Duration::from_millis(20)) => {} }
                match flood_sender.send(&node_id(GATEWAY), SLOW, flood_frame.clone()).await {
                    Ok(()) => {
                        count += 1;
                        submitted.send_replace(count);
                    }
                    Err(error) if error.code == ErrorCode::Conflict => {}
                    Err(error) => panic!("established read-only flood: {error}"),
                }
            }
            count
        });
        timeout(Duration::from_secs(10), async {
            while *submitted_count.borrow_and_update() < EXTENSION_MAILBOX_CAPACITY + 32 {
                submitted_count.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let rpc_gateway = gateway.clone();
        let rpc_roster = roster.clone();
        let reserve_request = request.clone();
        let rpc_started = Instant::now();
        let (reservation, receipt) = timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                AuthorityRpcClient::new(rpc_gateway, &rpc_roster, &node_id(GATEWAY), &node_id(AUTHORITY)).unwrap().reserve(reserve_request)
            }),
        )
        .await
        .expect("custody RPC blocked by extension backpressure")
        .unwrap()
        .unwrap();
        println!("reserve while extension full: {}ms", rpc_started.elapsed().as_millis());
        assert_eq!(mutations.load(Ordering::SeqCst), 1);
        assert_eq!(world.authority.reservation(&reservation.reservation_id).unwrap().state, ReservationState::Reserved);
        verify_receipt(
            &receipt,
            &world.authority.verifying_key(),
            &ReceiptExpectation {
                kind: ReceiptKind::Reserved,
                envelope_body_hash: request.envelope_body_hash,
                signer_session_id: request.signer_session_id,
                candidate_id: request.candidate_id,
                candidate_revision: request.candidate_revision,
                now: now(),
                policy_epoch: request.policy_epoch,
            },
        )
        .unwrap();
        assert_eq!(receipts.borrow().commit_sequence, None, "RPC reply implicitly published a record");

        let publisher = gateway.clone();
        let publish_receipt = receipt.clone();
        tokio::task::spawn_blocking(move || publisher.publish_extension_record(publish_receipt)).await.unwrap().unwrap();
        timeout(Duration::from_secs(3), async {
            while receipts.borrow_and_update().commit_sequence != Some(receipt.body.commit_sequence) {
                receipts.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(receipts.borrow().reservations, 1);
        assert_eq!(receipts.borrow().releases, 0);
        let publisher = authority_gateway.clone();
        let no_host_receipt = receipt.clone();
        assert_eq!(
            tokio::task::spawn_blocking(move || publisher.publish_extension_record(no_host_receipt)).await.unwrap().unwrap_err().code,
            ErrorCode::UnsupportedCapability
        );

        halt_flood.send(()).unwrap();
        let sent = flood.await.unwrap();
        assert!(sent > EXTENSION_MAILBOX_CAPACITY);
        // Observe another public barrier while the slow consumer is still
        // paused. Its own queue cannot prevent another extension's delivery.
        let latest = world.authority.checkpoint().unwrap();
        producer.send(&node_id(GATEWAY), OBSERVE, frame(&latest)).await.unwrap();
        observed(&mut observations, checkpoint_hash(&latest.body).unwrap()).await;
        resume.send(()).unwrap();
        assert_eq!(timeout(Duration::from_secs(3), drain_count).await.unwrap().unwrap(), EXTENSION_MAILBOX_CAPACITY);
        println!("slow extension: {sent} submitted; exactly {} buffered", EXTENSION_MAILBOX_CAPACITY);

        for address in &addresses {
            assert!(context.bind(*address).await.is_err(), "live listener unexpectedly allowed a second bind");
        }
        stop_gateway.send(()).unwrap();
        timeout(Duration::from_secs(10), gateway_task).await.unwrap().unwrap().unwrap();
        assert_eq!(live.load(Ordering::SeqCst), 0, "extension task outlived bridge shutdown");
        assert!(observations.has_changed().is_err());
        assert!(receipts.has_changed().is_err());
        assert_eq!(gateway.publish_extension_record(receipt).unwrap_err().code, ErrorCode::AuthorityUnavailable);
        stop_authority.send(()).unwrap();
        timeout(Duration::from_secs(10), authority_task).await.unwrap().unwrap().unwrap();
        producer.shutdown().await.unwrap();
        // Match the runtime's reuse-enabled bind, not std's TIME_WAIT check. An
        // aborted listener task can close its socket just after shutdown returns.
        timeout(Duration::from_secs(3), async {
            for address in &addresses {
                while context.bind(*address).await.is_err() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        })
        .await
        .expect("transport listener survived clean shutdown");
        assert_eq!(mutations.load(Ordering::SeqCst), 1, "mutation was retried");
    });
}
