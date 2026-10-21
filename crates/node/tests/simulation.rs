//! N0 and bounded N27 coverage using Commonware's actual deterministic simulator.
//!
//! These are THREE INDEPENDENT DEV THRESHOLD-1 sessions, not a threshold-3
//! ceremony. A dev signer has no other signing participants: its valid local
//! release-round input is buffered locally; cross-peer messages must be rejected
//! as nonparticipant input. Genuine authority release receipts travel over the
//! simulated network. No production transport admission/ACL/IPC, disk durability,
//! authority consensus, or threshold-protocol safety claim follows from this test.

#[path = "../../signer/tests/common/mod.rs"]
mod common;

use common::{Node, Setup, World, env_id, evm_key, evm_materials, evm_profile, inst, now, pid};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{Signer as _, ed25519};
use commonware_p2p::{Receiver as _, Recipients, Sender as _, simulated};
use commonware_runtime::{
    Clock as _, Handle, IoBuf, Quota, Runner as _, Spawner as _, Supervisor as _, deterministic,
};
use commonware_utils::{NZU32, NZUsize, probability};
use ed25519_dalek::SigningKey;
use oic_canonical_encoding::{from_canonical_bytes, sha256};
use oic_crypto_provider::{CryptoProvider, OneTimeStateLedger, PeerMessage, ProtocolStep};
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_domain_types::*;
use oic_one_time_state_ledger::InMemoryLedger;
use oic_peer_wire::{
    ExpectedPeerMessage, FrameKind, MAX_BODY_LEN, MessageScope, PeerFrameV1, SessionControl,
    SignedPeerMessage, WireError,
};
use oic_signer::InMemoryGenerationStore;
use rand::{SeedableRng as _, rngs::StdRng};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};
use tokio::sync::mpsc;

const MPC: u64 = 0;
const CONTROL: u64 = 1;
const EPOCH: u64 = 7;
const WINDOW: Duration = Duration::from_secs(1);
type PublicKey = ed25519::PublicKey;
type Sender = simulated::Sender<PublicKey, deterministic::Context>;

fn scope() -> MessageScope {
    MessageScope {
        institution_id: inst(),
        environment_id: env_id(),
        roster_epoch: EPOCH,
        roster_hash: Hash32([77; 32]),
    }
}

fn participant_key(index: usize) -> SigningKey {
    SigningKey::from_bytes(&[11 + index as u8; 32])
}

fn transport_key(index: usize) -> SigningKey {
    SigningKey::from_bytes(&[81 + index as u8; 32])
}

fn link(delivers: bool) -> simulated::Link {
    simulated::Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(3),
        success_rate: if delivers {
            probability!(1.0)
        } else {
            probability!(0.0)
        },
    }
}

struct Fixture {
    world: World,
    setup: Setup,
    envelope: AuthorizationEnvelope,
    key: KeyDescriptor,
    sealed: Bytes,
    ledger: Arc<InMemoryLedger>,
    generations: Arc<InMemoryGenerationStore>,
    seed: u64,
}

impl Fixture {
    fn new(seed: u64, index: usize) -> Self {
        let world = World::new();
        let provider = Self::provider(seed);
        let (key, sealed) = evm_key(&provider, &pid(index as u8 + 1));
        assert_eq!(key.threshold, 1);
        assert_eq!(key.participants.len(), 1);
        let mut materials = evm_materials(&key, 0);
        materials.policy = world.sign_policy(materials.policy);
        let setup = Setup::new(
            &world,
            evm_profile(),
            Arc::new(oic_adapter_evm::EvmAdapter),
            materials,
        );
        let envelope = setup.authorize(
            &world,
            &format!("independent-dev-session-{index}"),
            key.participants.clone(),
        );
        Self {
            world,
            setup,
            envelope,
            key,
            sealed,
            ledger: Arc::new(InMemoryLedger::new()),
            generations: Arc::new(InMemoryGenerationStore::new()),
            seed,
        }
    }

    fn provider(seed: u64) -> Arc<DevSingleKeyProvider> {
        Arc::new(
            DevSingleKeyProvider::new(
                SchemeId::EcdsaSecp256k1Keccak256Prehashed,
                [9; 32],
                Box::new(StdRng::seed_from_u64(seed)),
            )
            .unwrap(),
        )
    }

    fn boot(&self, index: usize) -> (Node, Arc<DevSingleKeyProvider>) {
        // Fresh provider/session memory on every actor start. Only the ledger and
        // generation-store interfaces survive a crash; they are in-memory here.
        let provider = Self::provider(self.seed);
        let node = common::open_node(
            &pid(index as u8 + 1),
            self.world.trust_roots(vec![evm_profile()]),
            self.setup.adapter.clone(),
            provider.clone(),
            self.ledger.clone(),
            self.generations.clone(),
        );
        node.signer.load_key(&self.key, &self.sealed).unwrap();
        assert!(matches!(
            node.signer
                .open_session(&self.envelope, &self.setup.m, now())
                .unwrap(),
            ProtocolStep::Waiting
        ));
        let mut local = common::dev_release_msg(&node, &self.envelope);
        local.to = Some(node.id.clone());
        let signed = SignedPeerMessage::sign(local, scope(), &participant_key(index)).unwrap();
        let bytes = signed
            .encode_point_to_point(FrameKind::MpcSign, MAX_BODY_LEN)
            .unwrap();
        let decoded = SignedPeerMessage::decode_point_to_point(
            &bytes,
            EPOCH,
            FrameKind::MpcSign,
            MAX_BODY_LEN,
        )
        .unwrap();
        let expected = expectation(&self.envelope, index, index, node.signer.generation());
        let message = decoded
            .verify(&expected, &participant_key(index).verifying_key())
            .unwrap();
        assert!(
            matches!(
                node.signer
                    .receive(&self.envelope.body.signer_session_id, message)
                    .unwrap(),
                ProtocolStep::Waiting
            ),
            "real share-producing input must not escape the pre-release gate"
        );
        assert_eq!(
            node.signer
                .aggregate(&self.envelope.body.signer_session_id, &[])
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        self.assert_unconsumed(node.signer.generation());
        (node, provider)
    }

    fn record(&self, generation: Epoch) -> oic_crypto_provider::OneTimeStateRecord {
        let records: Vec<_> = self
            .ledger
            .snapshot()
            .into_iter()
            .filter(|r| {
                r.key_id == self.key.key_id
                    && r.signer_generation == generation
                    && r.session_id.as_ref() == Some(&self.envelope.body.signer_session_id)
            })
            .collect();
        assert_eq!(
            records.len(),
            1,
            "one allocation for this actual dev session"
        );
        records.into_iter().next().unwrap()
    }

    fn assert_unconsumed(&self, generation: Epoch) {
        let record = self.record(generation);
        assert!(!record.consumed);
        assert_eq!(record.bound_message_hash, None);
    }

    fn assert_consumed_once(&self, generation: Epoch) {
        let record = self.record(generation);
        let hash = sha256(
            self.envelope.body.native_signing_payloads[0]
                .message_or_digest
                .as_ref(),
        );
        assert!(record.consumed);
        assert_eq!(record.bound_message_hash, Some(hash));
        assert_eq!(
            self.ledger
                .consume(&record.record_id, hash)
                .unwrap_err()
                .code,
            ErrorCode::ResourceConflict
        );
    }
}

fn expectation(
    envelope: &AuthorizationEnvelope,
    from: usize,
    to: usize,
    generation: Epoch,
) -> ExpectedPeerMessage {
    ExpectedPeerMessage {
        scope: scope(),
        session_id: envelope.body.signer_session_id.clone(),
        key_id: envelope.body.key_id.clone(),
        key_epoch: envelope.body.key_epoch,
        from: pid(from as u8 + 1),
        from_generation: generation,
        to: pid(to as u8 + 1),
        round: 1,
        sequence: 1,
        protocol_version: oic_crypto_provider_dev::PROTOCOL_VERSION.into(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Ready(Epoch, Hash32),
    WireRejected(WireError),
    SignerRejected(ErrorCode),
    Complete(Hash32),
    ControlRejected(ErrorCode),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    node: usize,
    elapsed_ms: u128,
    verdict: Verdict,
}

fn observe(
    context: &deterministic::Context,
    reports: &mpsc::UnboundedSender<Observation>,
    node: usize,
    verdict: Verdict,
) {
    reports
        .send(Observation {
            node,
            elapsed_ms: context
                .current()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            verdict,
        })
        .unwrap();
}

struct Simulation {
    context: deterministic::Context,
    oracle: simulated::Oracle<PublicKey, deterministic::Context>,
    peers: [PublicKey; 3],
    fixtures: [Fixture; 3],
    known_generations: Arc<Mutex<[Epoch; 3]>>,
    mpc: Vec<Sender>,
    control: Vec<Sender>,
    actors: Vec<Handle<()>>,
    network: Handle<()>,
    reports: mpsc::UnboundedSender<Observation>,
    received: mpsc::UnboundedReceiver<Observation>,
    trace: Vec<Observation>,
}

impl Simulation {
    async fn new(context: deterministic::Context, seed: u64) -> Self {
        let peers = std::array::from_fn(|i| {
            ed25519::PrivateKey::decode(transport_key(i).to_bytes().as_slice())
                .unwrap()
                .public_key()
        });
        let (network, oracle) = simulated::Network::new_with_peers(
            context.child("network"),
            simulated::Config {
                max_size: (MAX_BODY_LEN + 16) as u32,
                max_peers_per_set: NZUsize!(3),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            peers.iter().cloned(),
        )
        .await;
        let network = network.start();
        for from in &peers {
            for to in &peers {
                if from != to {
                    oracle
                        .add_link(from.clone(), to.clone(), link(true))
                        .await
                        .unwrap();
                }
            }
        }
        let (reports, received) = mpsc::unbounded_channel();
        let mut simulation = Self {
            context,
            oracle,
            peers,
            fixtures: std::array::from_fn(|i| Fixture::new(seed ^ (i as u64 + 1), i)),
            known_generations: Arc::new(Mutex::new([Epoch(1); 3])),
            mpc: Vec::new(),
            control: Vec::new(),
            actors: Vec::new(),
            network,
            reports,
            received,
            trace: Vec::new(),
        };
        for i in 0..3 {
            let (mpc, control, actor) = simulation.spawn(i).await;
            simulation.mpc.push(mpc);
            simulation.control.push(control);
            simulation.actors.push(actor);
            let ready = simulation.next().await;
            assert_eq!(ready.node, i);
            assert!(matches!(ready.verdict, Verdict::Ready(Epoch(1), _)));
        }
        simulation
    }

    async fn spawn(&self, index: usize) -> (Sender, Sender, Handle<()>) {
        let quota = Quota::per_second(NZU32!(1000));
        let control = self.oracle.control(self.peers[index].clone());
        let (mpc_sender, mut mpc_receiver) = control.register(MPC, quota).await.unwrap();
        let (control_sender, mut control_receiver) =
            control.register(CONTROL, quota).await.unwrap();
        let fixture = &self.fixtures[index];
        let (node, provider) = fixture.boot(index);
        let envelope = fixture.envelope.clone();
        let peers = self.peers.clone();
        let generations = self.known_generations.clone();
        let reports = self.reports.clone();
        let public_key = fixture.key.public_key.clone();
        let actor = self.context.child("signer").with_attribute("index", index).spawn(move |context| async move {
            observe(&context, &reports, index, Verdict::Ready(node.signer.generation(), sha256(public_key.bytes.as_ref())));
            loop {
                let verdict = tokio::select! {
                    biased;
                    frame = mpc_receiver.recv() => {
                        let (origin, bytes) = frame.unwrap();
                        // Expectations come from enrolled transport identity and
                        // local session state, never the frame's routing hints.
                        let sender = peers.iter().position(|p| *p == origin).unwrap();
                        let generation = generations.lock().unwrap()[sender];
                        let expected = expectation(&envelope, sender, index, generation);
                        let decoded = SignedPeerMessage::decode_point_to_point(bytes.as_ref(), EPOCH, FrameKind::MpcSign, MAX_BODY_LEN).unwrap();
                        match decoded.verify(&expected, &participant_key(sender).verifying_key()) {
                            Err(error) => Verdict::WireRejected(error),
                            Ok(message) => {
                                // Independent threshold-1 sessions have NO
                                // other signing participants, even if enrolled
                                // on the same simulated transport network.
                                let error = node.signer.receive(&envelope.body.signer_session_id, message).unwrap_err();
                                Verdict::SignerRejected(error.code)
                            }
                        }
                    },
                    frame = control_receiver.recv() => {
                        let (_origin, bytes) = frame.unwrap();
                        let frame = PeerFrameV1::decode(bytes.as_ref(), EPOCH, FrameKind::Content, MAX_BODY_LEN).unwrap();
                        let control: SessionControl = from_canonical_bytes(frame.body()).unwrap();
                        let SessionControl::Release { session_id, receipt, .. } = control else { panic!("unexpected control") };
                        match node.signer.release(&session_id, &receipt, now()) {
                            Err(error) => Verdict::ControlRejected(error.code),
                            Ok(steps) => {
                                let [ProtocolStep::Complete(signature)] = steps.as_slice() else { panic!("dev release must produce exactly one complete signature") };
                                provider.verify_result(&public_key, &envelope.body.native_signing_payloads[0], signature).unwrap();
                                Verdict::Complete(sha256(signature.bytes.as_ref()))
                            }
                        }
                    },
                };
                observe(&context, &reports, index, verdict);
            }
        });
        (mpc_sender, control_sender, actor)
    }

    async fn next(&mut self) -> Observation {
        let event = tokio::select! {
            biased;
            event = self.received.recv() => event.expect("actor report channel"),
            () = self.context.sleep(WINDOW) => panic!("simulated-time delivery deadline"),
        };
        self.trace.push(event.clone());
        event
    }

    async fn quiet(&mut self) {
        tokio::select! {
            biased;
            event = self.received.recv() => panic!("unexpected delivery/output: {event:?}"),
            () = self.context.sleep(WINDOW) => {},
        }
    }

    fn peer_message(&self, from: usize, to: usize, generation: Epoch) -> PeerMessage {
        let body = &self.fixtures[to].envelope.body;
        PeerMessage {
            session_id: body.signer_session_id.clone(),
            key_id: body.key_id.clone(),
            key_epoch: body.key_epoch,
            from: pid(from as u8 + 1),
            from_generation: generation,
            to: Some(pid(to as u8 + 1)),
            round: 1,
            sequence: 1,
            protocol_version: oic_crypto_provider_dev::PROTOCOL_VERSION.into(),
            payload: sha256(body.native_signing_payloads[0].message_or_digest.as_ref())
                .0
                .to_vec()
                .into(),
        }
    }

    fn send_peer(&mut self, from: usize, to: usize, message: PeerMessage, key: &SigningKey) {
        let bytes = SignedPeerMessage::sign(message, scope(), key)
            .unwrap()
            .encode_point_to_point(FrameKind::MpcSign, MAX_BODY_LEN)
            .unwrap();
        assert_eq!(
            self.mpc[from].send(
                Recipients::One(self.peers[to].clone()),
                IoBuf::from(bytes),
                true
            ),
            vec![self.peers[to].clone()]
        );
    }

    fn release(&mut self, from: usize, to: usize) {
        let fixture = &self.fixtures[to];
        let control = SessionControl::Release {
            request_id: to as u64,
            session_id: fixture.envelope.body.signer_session_id.clone(),
            receipt: fixture.world.release(&fixture.envelope),
        };
        let bytes =
            PeerFrameV1::encode_confidential(&control, EPOCH, FrameKind::Content, MAX_BODY_LEN)
                .unwrap();
        assert_eq!(
            self.control[from].send(
                Recipients::One(self.peers[to].clone()),
                IoBuf::from(bytes),
                true
            ),
            vec![self.peers[to].clone()]
        );
    }

    fn finish(self) -> Vec<Observation> {
        for actor in self.actors {
            actor.abort();
        }
        self.network.abort();
        self.trace
    }
}

#[derive(Clone, Copy)]
enum Scenario {
    AuthenticationAndRelease,
    PartitionAndDrop,
    CrashAndRecover,
}

fn run(seed: u64, scenario: Scenario) -> Vec<Observation> {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30))),
    );
    runner.start(|context| async move {
        let mut sim = Simulation::new(context, seed).await;
        match scenario {
            Scenario::AuthenticationAndRelease => {
                // Every peer exchanges an authenticated dev-shaped message;
                // transport membership must not turn it into a session member.
                for from in 0..3 {
                    let to = (from + 1) % 3;
                    sim.send_peer(
                        from,
                        to,
                        sim.peer_message(from, to, Epoch(1)),
                        &participant_key(from),
                    );
                    assert_eq!(
                        sim.next().await.verdict,
                        Verdict::SignerRejected(ErrorCode::ScopeMismatch)
                    );
                }
                // Each asymmetric mutation differs from a baseline frame that
                // passes participant authentication, then fails session membership.
                for (fault, expected) in [
                    (0, WireError::RecipientMismatch),
                    (1, WireError::SessionMismatch),
                    (2, WireError::GenerationMismatch),
                    (3, WireError::InvalidSignature),
                ] {
                    let mut message = sim.peer_message(0, 1, Epoch(1));
                    match fault {
                        0 => message.to = Some(pid(3)),
                        1 => {
                            message.session_id =
                                sim.fixtures[2].envelope.body.signer_session_id.clone()
                        }
                        2 => message.from_generation = Epoch(2),
                        _ => {}
                    }
                    // A network process really holding this transport key still
                    // cannot impersonate its participant-authentication key.
                    let key = if fault == 3 {
                        transport_key(0)
                    } else {
                        participant_key(0)
                    };
                    sim.send_peer(0, 1, message, &key);
                    assert_eq!(sim.next().await.verdict, Verdict::WireRejected(expected));
                }
                for to in 0..3 {
                    sim.fixtures[to].assert_unconsumed(Epoch(1));
                    sim.release((to + 1) % 3, to);
                    let complete = sim.next().await;
                    assert_eq!(complete.node, to);
                    assert!(matches!(complete.verdict, Verdict::Complete(_)));
                    sim.fixtures[to].assert_consumed_once(Epoch(1));
                    sim.release((to + 1) % 3, to);
                    assert_eq!(
                        sim.next().await.verdict,
                        Verdict::ControlRejected(ErrorCode::Conflict)
                    );
                }
            }
            Scenario::PartitionAndDrop => {
                // Isolate peer 2 in both directions. A release can be committed
                // at the authority without having reached the signer.
                for other in 0..2 {
                    sim.oracle
                        .remove_link(sim.peers[other].clone(), sim.peers[2].clone())
                        .await
                        .unwrap();
                    sim.oracle
                        .remove_link(sim.peers[2].clone(), sim.peers[other].clone())
                        .await
                        .unwrap();
                }
                sim.release(0, 2);
                sim.send_peer(0, 2, sim.peer_message(0, 2, Epoch(1)), &participant_key(0));
                sim.quiet().await;
                sim.fixtures[2].assert_unconsumed(Epoch(1));
                // The unpartitioned component can still finish its own key.
                sim.release(1, 0);
                assert!(matches!(sim.next().await.verdict, Verdict::Complete(_)));
                sim.fixtures[0].assert_consumed_once(Epoch(1));
                // An installed link with 100% packet loss is a distinct fault
                // from the missing directed edges above.
                sim.oracle
                    .add_link(sim.peers[1].clone(), sim.peers[2].clone(), link(false))
                    .await
                    .unwrap();
                sim.release(1, 2);
                sim.quiet().await;
                sim.fixtures[2].assert_unconsumed(Epoch(1));
                sim.oracle
                    .remove_link(sim.peers[1].clone(), sim.peers[2].clone())
                    .await
                    .unwrap();
                sim.oracle
                    .add_link(sim.peers[1].clone(), sim.peers[2].clone(), link(true))
                    .await
                    .unwrap();
                sim.release(1, 2);
                let complete = sim.next().await;
                assert_eq!(complete.node, 2);
                assert!(matches!(complete.verdict, Verdict::Complete(_)));
                sim.fixtures[2].assert_consumed_once(Epoch(1));
                sim.fixtures[1].assert_unconsumed(Epoch(1));
            }
            Scenario::CrashAndRecover => {
                let old_record = sim.fixtures[2].record(Epoch(1));
                let old_message = sim.peer_message(2, 1, Epoch(1));
                sim.actors[2].abort();
                assert!((&mut sim.actors[2]).await.is_err());
                let (mpc, control, actor) = sim.spawn(2).await;
                sim.mpc[2] = mpc;
                sim.control[2] = control;
                sim.actors[2] = actor;
                let ready = sim.next().await;
                assert_eq!(ready.node, 2);
                assert!(matches!(ready.verdict, Verdict::Ready(Epoch(2), _)));
                // Learned out-of-band from the restarted signer, not from the
                // incoming message or its claimed generation.
                sim.known_generations.lock().unwrap()[2] = Epoch(2);
                assert!(
                    sim.fixtures[2]
                        .ledger
                        .is_tombstoned(&old_record.record_id)
                        .unwrap()
                );
                assert_eq!(
                    sim.fixtures[2]
                        .ledger
                        .allocate(
                            &sim.fixtures[2].key.key_id,
                            Epoch(1),
                            Epoch(1),
                            &SigningSessionId::unchecked("stale-generation-allocation")
                        )
                        .unwrap_err()
                        .code,
                    ErrorCode::ResourceConflict
                );
                sim.send_peer(2, 1, old_message, &participant_key(2));
                assert_eq!(
                    sim.next().await.verdict,
                    Verdict::WireRejected(WireError::GenerationMismatch)
                );
                sim.send_peer(2, 1, sim.peer_message(2, 1, Epoch(2)), &participant_key(2));
                assert_eq!(
                    sim.next().await.verdict,
                    Verdict::SignerRejected(ErrorCode::ScopeMismatch)
                );
                sim.fixtures[2].assert_unconsumed(Epoch(2));
                sim.release(0, 2);
                assert!(matches!(sim.next().await.verdict, Verdict::Complete(_)));
                sim.fixtures[2].assert_consumed_once(Epoch(2));
                assert_ne!(
                    old_record.record_id,
                    sim.fixtures[2].record(Epoch(2)).record_id
                );
                assert!(
                    sim.fixtures[2]
                        .ledger
                        .is_tombstoned(&old_record.record_id)
                        .unwrap()
                );
                sim.fixtures[0].assert_unconsumed(Epoch(1));
                sim.fixtures[1].assert_unconsumed(Epoch(1));
            }
        }
        sim.quiet().await;
        sim.finish()
    })
}

#[test]
fn seeded_three_independent_dev_threshold1_sessions_authenticate_and_release_once() {
    let mut previous = None;
    for seed in [0, 1, 42, 202_609] {
        let trace = run(seed, Scenario::AuthenticationAndRelease);
        assert_eq!(
            trace,
            run(seed, Scenario::AuthenticationAndRelease),
            "seed {seed}"
        );
        if let Some(previous) = previous {
            assert_ne!(trace, previous, "the seed must affect the observable run");
        }
        previous = Some(trace);
    }
}

#[test]
fn seeded_independent_dev_threshold1_sessions_withhold_release_under_partition_and_drop() {
    for seed in [3, 5, 37, 99] {
        assert_eq!(
            run(seed, Scenario::PartitionAndDrop),
            run(seed, Scenario::PartitionAndDrop),
            "seed {seed}"
        );
    }
}

#[test]
fn seeded_independent_dev_threshold1_actor_recovery_fences_old_generation() {
    for seed in [2, 7, 43, 100] {
        assert_eq!(
            run(seed, Scenario::CrashAndRecover),
            run(seed, Scenario::CrashAndRecover),
            "seed {seed}"
        );
    }
}
