#[path = "../../coordinator/tests/common/mod.rs"]
mod common;

use common::*;
use ed25519_dalek::{Signer as _, SigningKey};
use oic_audit::{AuditLog, AuditLogConfig, FileAuditLog};
use oic_domain_types::*;
use oic_membership::Node;
use oic_membership::*;
use oic_peer_wire::SessionControl;
use oic_service_coordinator::{InMemoryOperationStore, SignerEndpoint};
use oic_service_signer_core::{
    halt_hash, ipc,
    remote::{LocalClient, RemoteSigner},
    CoreConfig, HaltBody, SignedHalt, SignerCore,
};
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

fn node_id(n: usize) -> NodeId {
    NodeId::unchecked(format!("node-{n}"))
}
fn public(seed: u8) -> PublicKey {
    PublicKey { scheme: SchemeId::Ed25519Pure, bytes: SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes().to_vec().into() }
}

fn roster(world: &World, chain: &Chain) -> (SignedRoster, AdminTrust) {
    let mut nodes = chain
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| Node {
            node_id: node_id(i),
            domain_id: TrustDomainId::unchecked(format!("domain-{i}")),
            roles: vec![Role::Signer],
            transport_key: public(120 + i as u8),
            consensus_key: None,
            attestation_key: Some(public(140 + i as u8)),
            address: format!("127.0.0.1:{}", 31000 + i).parse().unwrap(),
            peer_class: PeerClass::Primary,
            participant_keys: BTreeMap::from([(n.id.clone(), public(80 + i as u8))]),
            approved_build_hashes: vec![chain.adapter.manifest().verifier_build_hash],
            signer_instance_generation: n.signer.generation(),
        })
        .collect::<Vec<_>>();
    for (n, role) in [(3, Role::Gateway), (4, Role::Authority), (5, Role::Witness)] {
        nodes.push(Node {
            node_id: node_id(n),
            domain_id: TrustDomainId::unchecked(format!("domain-{n}")),
            roles: vec![role],
            transport_key: public(120 + n as u8),
            consensus_key: None,
            attestation_key: None,
            address: format!("127.0.0.1:{}", 31000 + n).parse().unwrap(),
            peer_class: if role == Role::Witness { PeerClass::Secondary } else { PeerClass::Primary },
            participant_keys: BTreeMap::new(),
            approved_build_hashes: vec![],
            signer_instance_generation: Epoch(0),
        });
    }
    let body = RosterBody {
        institution_id: inst(),
        environment_id: env_id(),
        roster_epoch: 0,
        previous_roster_hash: Hash32::ZERO,
        genesis_hash: Hash32::ZERO,
        commonware_release: COMMONWARE_RELEASE.into(),
        wire_version: WIRE_VERSION,
        trust_domains: nodes
            .iter()
            .map(|n| TrustDomain {
                domain_id: n.domain_id.clone(),
                administrators: vec![world.admins[0].0.clone()],
                failure_domain_notes: "Independent IAM, hardware, backups and operators".into(),
            })
            .collect(),
        nodes,
        committees: vec![
            Committee {
                committee_id: CommitteeId::unchecked("chain-key"),
                kind: CommitteeKind::Key {
                    key_id: chain.key.key_id.clone(),
                    key_epoch: chain.key.key_epoch,
                    participants: chain.key.participants.clone(),
                    backend: chain.nodes[0].signer.backend().clone(),
                },
                members: (0..3).map(node_id).collect(),
                threshold: 2,
            },
            Committee { committee_id: CommitteeId::unchecked("authority"), kind: CommitteeKind::AuthorityD1, members: vec![node_id(4)], threshold: 1 },
        ],
        channel_acl: vec![
            ChannelSpec {
                channel: 0,
                sender_roles: vec![Role::Gateway, Role::Signer, Role::Authority],
                receiver_roles: vec![Role::Gateway, Role::Signer, Role::Authority],
                max_message_size: 4096,
                quota: 100,
            },
            ChannelSpec {
                channel: 10,
                sender_roles: vec![Role::Gateway, Role::Signer],
                receiver_roles: vec![Role::Gateway, Role::Signer],
                max_message_size: 65536,
                quota: 100,
            },
            ChannelSpec { channel: 20, sender_roles: vec![Role::Signer], receiver_roles: vec![Role::Signer], max_message_size: 65536, quota: 100 },
        ],
        tolerated_domain_compromises: 1,
        activation: Activation { not_before: now(), authority_commit_reference: None },
    };
    let hash = roster_hash(&body).unwrap();
    let signatures = world.admins[..2]
        .iter()
        .map(|(id, key)| CredentialSignature {
            credential_id: id.clone(),
            signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: key.sign(hash.as_ref()).to_bytes().to_vec().into() },
        })
        .collect();
    let admins = AdminTrust {
        threshold: 2,
        credentials: world
            .admins
            .iter()
            .map(|(id, key)| (id.clone(), PublicKey { scheme: SchemeId::Ed25519Pure, bytes: key.verifying_key().to_bytes().to_vec().into() }))
            .collect(),
    };
    (SignedRoster { body, signatures }, admins)
}

struct Harness {
    _dir: tempfile::TempDir,
    clients: Vec<ipc::Client>,
    audits: Vec<Arc<FileAuditLog>>,
    stop: Arc<AtomicBool>,
    tasks: Vec<std::thread::JoinHandle<()>>,
    pump_stop: Arc<AtomicBool>,
    pump: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    fn new(world: &World, chain: &Chain) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (roster, admins) = roster(world, chain);
        let stop = Arc::new(AtomicBool::new(false));
        let mut clients = Vec::new();
        let mut audits = Vec::new();
        let mut tasks = Vec::new();
        for (i, node) in chain.nodes.iter().enumerate() {
            let audit = Arc::new(
                FileAuditLog::open(
                    dir.path().join(format!("audit-{i}")),
                    Some(0),
                    AuditLogConfig::new(KeyId::unchecked(format!("audit-{i}")), SigningKey::from_bytes(&[200 + i as u8; 32]), world.clock.clone()),
                )
                .unwrap(),
            );
            let core = Arc::new(
                SignerCore::open(
                    CoreConfig {
                        node_id: node_id(i),
                        roster: roster.clone(),
                        previous_roster: None,
                        admins: admins.clone(),
                        committed_roster_hash: roster_hash(&roster.body).unwrap(),
                        halt_state_path: dir.path().join(format!("halt-{i}")),
                        minimum_halt_sequence: 0,
                        operator_key: SigningKey::from_bytes(&[220 + i as u8; 32]).verifying_key(),
                        audit: audit.clone(),
                    },
                    node.signer.clone(),
                    SigningKey::from_bytes(&[80 + i as u8; 32]),
                    world.clock.clone(),
                )
                .unwrap(),
            );
            let path = dir.path().join(format!("core-{i}.sock"));
            let server = ipc::Server::bind(&path, core.clone()).unwrap();
            let stopping = stop.clone();
            tasks.push(std::thread::spawn(move || server.serve(&stopping).unwrap()));
            clients.push(ipc::Client::new(path));
            audits.push(audit);
        }
        Self { _dir: dir, clients, audits, stop, tasks, pump_stop: Arc::new(AtomicBool::new(false)), pump: None }
    }

    fn endpoints(&self) -> Vec<Arc<dyn SignerEndpoint>> {
        self.clients
            .iter()
            .enumerate()
            .map(|(i, client)| {
                Arc::new(RemoteSigner::new(
                    pid(i as u8 + 1),
                    Epoch(1),
                    Arc::new(LocalClient { ipc: client.clone(), gateway: node_id(3) }),
                    Duration::from_secs(5),
                )) as Arc<dyn SignerEndpoint>
            })
            .collect()
    }

    fn pump(&mut self) {
        let clients = self.clients.clone();
        let stop = self.pump_stop.clone();
        self.pump = Some(std::thread::spawn(move || {
            let mut sweep = 0;
            while !stop.load(Ordering::Acquire) {
                let mut frames = Vec::new();
                for (from, client) in clients.iter().enumerate() {
                    let mut offset = 0;
                    while let Some(message) = client.outbound_at(offset).unwrap() {
                        frames.push((node_id(from), message));
                        offset += 1;
                    }
                }
                // Drop the first sweep and reorder later sweeps. Core retries
                // must not reuse nonces or release a second share.
                if sweep > 0 {
                    frames.reverse();
                    for (from, frame) in frames {
                        let target = (0..clients.len()).find(|i| node_id(*i) == frame.to).unwrap();
                        let _ = clients[target].deliver(&from, frame.frame);
                    }
                }
                sweep += 1;
                std::thread::sleep(Duration::from_millis(5));
            }
        }));
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Finish every in-flight poll before closing its IPC server. A shared
        // stop flag races socket teardown against the final outbox request.
        self.pump_stop.store(true, Ordering::Release);
        if let Some(pump) = self.pump.take() {
            pump.join().unwrap();
        }
        self.stop.store(true, Ordering::Release);
        for task in self.tasks.drain(..) {
            task.join().unwrap();
        }
    }
}

fn authorization(world: &World, chain: &Chain, name: &str) -> (AuthorizationEnvelope, oic_signer::SigningMaterials) {
    let intent = chain.intent(name, (SOL / 3).into(), 10_000, ApprovalMode::ExactCandidate);
    let pol = world.sign_policy(policy(1, vec![rule(&chain.asset.asset_id, 1, 100 * SOL as u128)]));
    world.register(&pol, &intent);
    let job = job(world, chain, &pol, &intent, &format!("candidate-{name}"), 1, vec![pid(1), pid(2)]);
    let body = oic_service_builder::envelope_body(
        &job.built,
        chain.adapter.as_ref(),
        &chain.profile,
        job.grants,
        SigningSessionId::unchecked(format!("session-{name}")),
        job.participant_set,
        UnixSeconds(DEADLINE),
    )
    .unwrap();
    let envelope = world.reserve(&job.built, &pol.rules[0], body);
    (envelope, oic_service_builder::signing_materials(&job.built.package))
}

#[test]
fn frost_private_ipc_to_native_solana_with_reordered_rounds() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let chain = &sol.chain;
    let mut network = Harness::new(&world, chain);
    network.pump();
    let intent = chain.intent("ipc-native", (SOL / 3).into(), 10_000, ApprovalMode::ExactCandidate);
    let pol = world.sign_policy(policy(1, vec![rule(&chain.asset.asset_id, 1, 100 * SOL as u128)]));
    world.register(&pol, &intent);
    let coord = coordinator(&world, chain, network.endpoints(), Arc::new(InMemoryOperationStore::new()));
    let issued = coord.execute(job(&world, chain, &pol, &intent, "ipc-candidate", 1, vec![pid(1), pid(2)])).unwrap();
    let txid = sol.sim.submit(issued.signed.signed.signed_bytes.as_slice()).unwrap();
    sol.sim.advance_slot().unwrap();
    assert_eq!(sol.sim.lamports(&sol_dest_owner()), SOL / 3);
    assert!(!txid.as_str().is_empty());
    for node in &chain.nodes[..2] {
        assert_eq!(node.shares_produced(), 1);
        let events = node.events();
        let release = events.iter().position(|e| matches!(e, oic_signer::SignerEvent::Released { .. })).unwrap();
        let share = events.iter().position(|e| matches!(e, oic_signer::SignerEvent::ShareProduced { .. })).unwrap();
        assert!(release < share);
    }
    assert_eq!(chain.nodes[2].shares_produced(), 0);
    for audit in &network.audits[..2] {
        let events = audit.events_since(0, 16).unwrap();
        let release = events.iter().find(|e| e.body.action == "signer.share_released").unwrap();
        assert_eq!(release.body.object_commitments["envelope"], oic_signer::envelope_body_hash(&issued.envelope.body).unwrap());
        assert_eq!(
            release.body.object_commitments["release_receipt"],
            oic_canonical_encoding::sha256(&oic_canonical_encoding::canonical_bytes(&issued.release_receipt).unwrap())
        );
        oic_audit::verify_checkpoint(&audit.checkpoint().unwrap(), &audit.verifying_key()).unwrap();
    }
}

#[test]
fn tampered_open_and_gateway_mpc_forgery_produce_no_output() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let network = Harness::new(&world, &sol.chain);
    let (envelope, materials) = authorization(&world, &sol.chain, "tamper");
    let mut changed = materials.clone();
    changed.candidate.native_unsigned_bytes.0[0] ^= 1;
    let reply = network.clients[0].control(&node_id(3), SessionControl::Open { request_id: 1, envelope: envelope.clone(), materials: changed }).unwrap();
    assert!(reply.result.is_err());
    assert!(network.clients[0].outbound_at(0).unwrap().is_none());
    assert_eq!(network.clients[0].deliver(&node_id(3), vec![0; 16]).unwrap_err().code, ErrorCode::PeerNotAdmitted);

    let mut replay = envelope.clone();
    replay.body.signer_session_id = SigningSessionId::unchecked("different-session-same-reservation");
    assert!(network.clients[0]
        .control(&node_id(3), SessionControl::Open { request_id: 2, envelope: replay, materials: materials.clone() })
        .unwrap()
        .result
        .is_err());
    assert!(network.clients[0].outbound_at(0).unwrap().is_none());
    for client in &network.clients[..2] {
        client.control(&node_id(3), SessionControl::Open { request_id: 3, envelope: envelope.clone(), materials: materials.clone() }).unwrap().result.unwrap();
    }

    // Even the authenticated sender's own transport key cannot impersonate
    // the participant key sealed inside its core. Rejection must not poison
    // the round: the real core's frame still succeeds afterwards.
    let (roster, _) = roster(&world, &sol.chain);
    let forged = oic_peer_wire::SignedPeerMessage::sign(
        oic_crypto_provider::PeerMessage {
            session_id: envelope.body.signer_session_id.clone(),
            key_id: materials.key.key_id.clone(),
            key_epoch: materials.key.key_epoch,
            from: pid(1),
            from_generation: Epoch(1),
            to: Some(pid(2)),
            round: 1,
            sequence: 1,
            protocol_version: oic_crypto_provider_frost_ed25519::PROTOCOL_VERSION.into(),
            payload: Bytes(b"forged commitment".to_vec()),
        },
        oic_peer_wire::MessageScope { institution_id: inst(), environment_id: env_id(), roster_epoch: 0, roster_hash: roster_hash(&roster.body).unwrap() },
        &SigningKey::from_bytes(&[120; 32]),
    )
    .unwrap()
    .encode_point_to_point(oic_peer_wire::FrameKind::MpcSign, oic_peer_wire::MAX_BODY_LEN)
    .unwrap();
    assert_eq!(network.clients[1].deliver(&node_id(0), forged).unwrap_err().code, ErrorCode::InvalidSignature);
    let authentic = network.clients[0].outbound_at(0).unwrap().unwrap();
    assert_eq!(authentic.to, node_id(1));
    network.clients[1].deliver(&node_id(0), authentic.frame).unwrap();
    assert_eq!(sol.chain.nodes[0].shares_produced(), 0);
    assert_eq!(sol.chain.nodes[1].shares_produced(), 0);
}

#[test]
fn local_halt_is_signed_durable_and_stops_active_sessions() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let network = Harness::new(&world, &sol.chain);
    let (envelope, materials) = authorization(&world, &sol.chain, "halt");
    let id = envelope.body.signer_session_id.clone();
    network.clients[0].control(&node_id(3), SessionControl::Open { request_id: 1, envelope, materials }).unwrap().result.unwrap();
    assert!(network.clients[0].outbound_at(0).unwrap().is_some());
    let body = HaltBody {
        institution_id: inst(),
        environment_id: env_id(),
        node_id: node_id(0),
        roster_epoch: 0,
        sequence: 1,
        halted: true,
        issued_at: now(),
        expires_at: UnixSeconds(NOW + 30),
    };
    let sign = |key: u8| SignedHalt {
        signature: SignatureBytes {
            scheme: SchemeId::Ed25519Pure,
            bytes: SigningKey::from_bytes(&[key; 32]).sign(halt_hash(&body).unwrap().as_ref()).to_bytes().to_vec().into(),
        },
        body: body.clone(),
    };
    assert_eq!(network.clients[0].halt(sign(219)).unwrap_err().code, ErrorCode::InvalidSignature);
    let command = sign(220);
    network.clients[0].halt(command.clone()).unwrap();
    assert_eq!(network.clients[0].halt(command).unwrap_err().code, ErrorCode::InvalidRequest);
    assert!(network.clients[0].outbound_at(0).unwrap().is_none());
    assert_eq!(
        network.clients[0].control(&node_id(3), SessionControl::Status { request_id: 2, session_id: id }).unwrap().result.unwrap_err().code,
        ErrorCode::NodeHalted
    );
    assert!(sol.chain.nodes[0].aborted(&SigningSessionId::unchecked("session-halt")));
    assert_eq!(sol.chain.nodes[0].shares_produced(), 0);
    let (roster, admins) = roster(&world, &sol.chain);
    let reopened = SignerCore::open(
        CoreConfig {
            node_id: node_id(0),
            roster: roster.clone(),
            previous_roster: None,
            admins,
            committed_roster_hash: roster_hash(&roster.body).unwrap(),
            halt_state_path: network._dir.path().join("halt-0"),
            minimum_halt_sequence: 1,
            operator_key: SigningKey::from_bytes(&[220; 32]).verifying_key(),
            audit: network.audits[0].clone(),
        },
        sol.chain.nodes[0].signer.clone(),
        SigningKey::from_bytes(&[80; 32]),
        world.clock.clone(),
    )
    .unwrap();
    assert!(reopened.outbound_at(0).is_none());
    assert_eq!(
        reopened.control(&node_id(3), &SessionControl::Status { request_id: 3, session_id: SigningSessionId::unchecked("missing") }).result.unwrap_err().code,
        ErrorCode::NodeHalted
    );
}

#[test]
fn core_rejects_operator_and_audit_keys_enrolled_for_other_purposes() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let (roster, admins) = roster(&world, &sol.chain);
    let dir = tempfile::tempdir().unwrap();
    let operator = SigningKey::from_bytes(&[220; 32]);
    let audit = SigningKey::from_bytes(&[200; 32]);
    let aliases = [
        SigningKey::from_bytes(&[121; 32]), // Another node's transport key.
        SigningKey::from_bytes(&[81; 32]),  // Another node's participant key.
        SigningKey::from_bytes(&[141; 32]), // Another node's attestation key.
        world.admins[0].1.clone(),
    ];
    // Both key purposes must reject every enrolled alias. Include distinct
    // controls and operator/audit reuse without modifying the valid roster.
    for (index, (operator, audit, accepted)) in std::iter::once((operator.clone(), audit.clone(), true))
        .chain(aliases.iter().map(|alias| (alias.clone(), audit.clone(), false)))
        .chain(aliases.iter().map(|alias| (operator.clone(), alias.clone(), false)))
        .chain(std::iter::once((operator.clone(), operator.clone(), false)))
        .enumerate()
    {
        let audit = Arc::new(
            FileAuditLog::open(dir.path().join(format!("audit-{index}")), Some(0), AuditLogConfig::new(KeyId::unchecked("audit"), audit, world.clock.clone()))
                .unwrap(),
        );
        let result = SignerCore::open(
            CoreConfig {
                node_id: node_id(0),
                roster: roster.clone(),
                previous_roster: None,
                admins: admins.clone(),
                committed_roster_hash: roster_hash(&roster.body).unwrap(),
                halt_state_path: dir.path().join(format!("halt-{index}")),
                minimum_halt_sequence: 0,
                operator_key: operator.verifying_key(),
                audit: audit.clone(),
            },
            sol.chain.nodes[0].signer.clone(),
            SigningKey::from_bytes(&[80; 32]),
            world.clock.clone(),
        );
        if accepted {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.err().expect("cross-purpose key must be rejected").code, ErrorCode::InvalidRequest);
            assert!(audit.events_since(0, 16).unwrap().is_empty(), "rejection precedes startup evidence");
        }
    }
}
