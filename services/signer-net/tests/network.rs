//! Real Commonware TCP -> private Unix IPC -> separate FROST core processes.
//! Fixture DKG is offline provisioning; its in-process signers are dropped
//! before any network reactor starts. No live signer/share is held by a bridge.
#[path = "../../coordinator/tests/common/mod.rs"]
mod common;

use common::*;
use commonware_runtime::{Runner as _, Supervisor as _, tokio as runtime};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use oic_adapter_api::{ChainAdapter, ChainProfile};
use oic_audit::{AuditLog, AuditLogConfig, FileAuditLog, verify_chain};
use oic_authorization_state::{ManualClock, ReservationState};
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes, sha256};
use oic_crypto_provider::OneTimeStateRecord;
use oic_crypto_provider_frost_ed25519::FrostEd25519Provider;
use oic_domain_types::*;
use oic_membership::{
    Activation, AdminTrust, ChannelSpec, Committee, CommitteeKind, Node, PeerClass, Role,
    RosterBody, SignedRoster, TrustDomain, roster_hash,
};
use oic_node::{Config, Transport};
use oic_one_time_state_ledger::FileLedger;
use oic_peer_wire::{AuthorityRequest, FrameKind, MAX_BODY_LEN, PeerFrameV1, SessionControl};
use oic_service_authority_rpc::{AuthorityEndpoint, AuthorityRpcClient, AuthorityRpcServer};
use oic_service_coordinator::{
    InMemoryOperationStore, OperationStore, SignerEndpoint, SigningCoordinator,
};
use oic_service_signer_core::{CoreConfig, SignerCore, ipc, remote::RemoteSigner};
use oic_service_signer_net::{AuthorityHandler, Bridge, Gateway};
use oic_signer::{
    FileGenerationStore, GenerationStore, Signer, SignerEvent, SignerIdentity, TrustRoots,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    net::TcpListener,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

const GATEWAY: usize = 3;
const AUTHORITY: usize = 4;
const CORE_DIR: &str = "OIC_E2E_CORE_DIRECTORY";

fn node_id(index: usize) -> NodeId {
    NodeId::unchecked(format!("node-{index}"))
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> PublicKey {
    PublicKey {
        scheme: SchemeId::Ed25519Pure,
        bytes: key(seed).verifying_key().to_bytes().to_vec().into(),
    }
}
fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

// Public, out-of-band trust configuration. It contains no signing key.
#[derive(Serialize, Deserialize)]
struct PublicRoots {
    authority_id: KeyId,
    authority_key: [u8; 32],
    admins: Vec<(CredentialId, [u8; 32])>,
    quorum: u8,
    approvers: Vec<(CredentialId, [u8; 32], ApprovalRole)>,
    builds: BTreeMap<AdapterId, Vec<Hash32>>,
    profiles: Vec<ChainProfile>,
    skew: u64,
}
impl From<TrustRoots> for PublicRoots {
    fn from(roots: TrustRoots) -> Self {
        Self {
            authority_id: roots.authority_key_id,
            authority_key: roots.authority_pubkey.to_bytes(),
            admins: roots
                .admin_keys
                .into_iter()
                .map(|(id, key)| (id, key.to_bytes()))
                .collect(),
            quorum: roots.admin_quorum,
            approvers: roots
                .approvers
                .into_iter()
                .map(|c| {
                    let key = match c.verifying_key {
                        oic_approval_verifier::ApproverKey::Ed25519(key) => key.to_bytes(),
                        oic_approval_verifier::ApproverKey::WebAuthn { .. } => {
                            panic!("network fixture supports only Ed25519 approvers")
                        }
                    };
                    (c.credential_id, key, c.role)
                })
                .collect(),
            builds: roots.accepted_verifier_builds,
            profiles: roots.chain_profiles,
            skew: roots.max_clock_skew_seconds,
        }
    }
}
impl PublicRoots {
    fn into_roots(self) -> TrustRoots {
        TrustRoots {
            authority_key_id: self.authority_id,
            authority_pubkey: VerifyingKey::from_bytes(&self.authority_key).unwrap(),
            admin_keys: self
                .admins
                .into_iter()
                .map(|(id, key)| (id, VerifyingKey::from_bytes(&key).unwrap()))
                .collect(),
            admin_quorum: self.quorum,
            approvers: self
                .approvers
                .into_iter()
                .map(
                    |(credential_id, key, role)| oic_approval_verifier::ApproverCredential {
                        person_id: credential_id.clone(),
                        credential_id,
                        verifying_key: VerifyingKey::from_bytes(&key).unwrap().into(),
                        role,
                    },
                )
                .collect(),
            accepted_verifier_builds: self.builds,
            chain_profiles: self.profiles,
            max_clock_skew_seconds: self.skew,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ChildFixture {
    index: usize,
    roster: SignedRoster,
    admins: (u16, BTreeMap<CredentialId, PublicKey>),
    key: KeyDescriptor,
    sealed: Bytes,
    roots: PublicRoots,
}

#[derive(Serialize, Deserialize)]
struct Report {
    pid: u32,
    events: Vec<SignerEvent>,
    audit: Vec<AuditEvent>,
    ledger_sequence: u64,
    records: Vec<OneTimeStateRecord>,
}

/// This test is the private child entrypoint, not an alternative signer stub.
#[test]
#[ignore = "spawned by the real-process integration tests with a private fixture directory"]
fn signer_core_process() {
    let dir = PathBuf::from(std::env::var_os(CORE_DIR).expect("private core directory"));
    assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o077, 0);
    assert_eq!(
        fs::metadata(dir.join("fixture"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    let fixture: ChildFixture =
        from_canonical_bytes(&fs::read(dir.join("fixture")).unwrap()).unwrap();
    let clock = Arc::new(ManualClock::new(NOW)); // Local core clock, never gateway time.
    let provider = Arc::new(
        FrostEd25519Provider::with_os_rng(
            pid(fixture.index as u8 + 1),
            [0x50 + fixture.index as u8; 32],
        )
        .unwrap(),
    );
    let ledger = Arc::new(FileLedger::open(dir.join("ledger"), Some(0)).unwrap());
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let adapter: Arc<dyn ChainAdapter> = Arc::new(oic_adapter_solana::SolanaAdapter);
    let signer = Arc::new(
        Signer::open(
            SignerIdentity {
                participant_id: pid(fixture.index as u8 + 1),
                institution_id: inst(),
                environment_id: env_id(),
            },
            fixture.roots.into_roots(),
            BTreeMap::from([(adapter.manifest().adapter_id, adapter)]),
            provider,
            ledger.clone(),
            Arc::new(FileGenerationStore::new(dir.join("generation"))),
        )
        .unwrap()
        .with_event_sink(Arc::new(move |event| sink.lock().unwrap().push(event))),
    );
    signer.load_key(&fixture.key, &fixture.sealed).unwrap();
    let audit = Arc::new(
        FileAuditLog::open(
            dir.join("audit"),
            Some(0),
            AuditLogConfig::new(
                KeyId::unchecked(format!("core-audit-{}", fixture.index)),
                key(200 + fixture.index as u8),
                clock.clone(),
            ),
        )
        .unwrap(),
    );
    let core = Arc::new(
        SignerCore::open(
            CoreConfig {
                node_id: node_id(fixture.index),
                committed_roster_hash: roster_hash(&fixture.roster.body).unwrap(),
                roster: fixture.roster,
                previous_roster: None,
                admins: AdminTrust {
                    threshold: fixture.admins.0,
                    credentials: fixture.admins.1,
                },
                halt_state_path: dir.join("halt"),
                minimum_halt_sequence: 0,
                operator_key: key(220 + fixture.index as u8).verifying_key(),
                audit: audit.clone(),
            },
            signer,
            key(80 + fixture.index as u8),
            clock,
        )
        .unwrap(),
    );
    for name in ["ledger", "generation", "audit"] {
        fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let server = ipc::Server::bind(dir.join("core.sock"), core).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let stop_path = dir.join("stop");
    let watcher = thread::spawn(move || {
        while !stop_path.exists() {
            thread::sleep(Duration::from_millis(10));
        }
        flag.store(true, Ordering::Release);
    });
    private_write(&dir.join("ready"), &std::process::id().to_be_bytes());
    server.serve(&stop).unwrap();
    watcher.join().unwrap();
    private_write(
        &dir.join("report"),
        &canonical_bytes(&Report {
            pid: std::process::id(),
            events: events.lock().unwrap().clone(),
            audit: audit.events_since(0, 1024).unwrap(),
            ledger_sequence: ledger.sequence(),
            records: ledger.snapshot(),
        })
        .unwrap(),
    );
}

struct CoreProcess {
    dir: PathBuf,
    child: Option<Child>,
    pid: u32,
}
impl CoreProcess {
    fn start(dir: PathBuf, fixture: ChildFixture) -> Self {
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        private_write(&dir.join("fixture"), &canonical_bytes(&fixture).unwrap());
        let output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(dir.join("child.log"))
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "signer_core_process", "--nocapture"])
            .env(CORE_DIR, &dir)
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut process = Self {
            dir,
            child: Some(child),
            pid,
        };
        let start = Instant::now();
        while !process.dir.join("ready").exists() {
            if let Some(status) = process.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("core exited {status}: {}", process.log());
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "core startup deadline: {}",
                process.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read(process.dir.join("ready")).unwrap(),
            pid.to_be_bytes()
        );
        assert_ne!(pid, std::process::id());
        process
    }
    fn log(&self) -> String {
        fs::read_to_string(self.dir.join("child.log")).unwrap_or_default()
    }
    fn client(&self) -> ipc::Client {
        ipc::Client::new(self.dir.join("core.sock"))
    }
    fn finish(&mut self) -> Report {
        let _ = fs::write(self.dir.join("stop"), []);
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                assert!(status.success(), "core failed {status}: {}", self.log());
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "core shutdown deadline: {}",
                self.log()
            );
            thread::sleep(Duration::from_millis(10));
        }
        self.child.take();
        let report: Report =
            from_canonical_bytes(&fs::read(self.dir.join("report")).unwrap()).unwrap();
        assert_eq!(report.pid, self.pid);
        report
    }
}
impl Drop for CoreProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = fs::write(self.dir.join("stop"), []);
            for _ in 0..300 {
                if child.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    DropSignerControl,
    DropReleaseReply,
}

fn roster(world: &World, chain: &Chain) -> (SignedRoster, AdminTrust) {
    let listeners: Vec<_> = (0..5)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let nodes = (0..5)
        .map(|i| Node {
            node_id: node_id(i),
            domain_id: TrustDomainId::unchecked(format!("domain-{i}")),
            roles: vec![if i < 3 {
                Role::Signer
            } else if i == GATEWAY {
                Role::Gateway
            } else {
                Role::Authority
            }],
            transport_key: public(120 + i as u8),
            consensus_key: None,
            attestation_key: (i < 3).then(|| public(140 + i as u8)),
            address: listeners[i].local_addr().unwrap(),
            peer_class: PeerClass::Primary,
            participant_keys: if i < 3 {
                BTreeMap::from([(pid(i as u8 + 1), public(80 + i as u8))])
            } else {
                BTreeMap::new()
            },
            approved_build_hashes: if i < 3 {
                vec![chain.adapter.manifest().verifier_build_hash]
            } else {
                vec![]
            },
            signer_instance_generation: Epoch(1),
        })
        .collect::<Vec<_>>();
    let all = vec![Role::Gateway, Role::Signer, Role::Authority];
    let acl = |channel, sender_roles, receiver_roles| ChannelSpec {
        channel,
        sender_roles,
        receiver_roles,
        max_message_size: 65536,
        quota: 100,
    };
    let body = RosterBody {
        institution_id: inst(),
        environment_id: env_id(),
        roster_epoch: 0,
        previous_roster_hash: Hash32::ZERO,
        genesis_hash: Hash32::ZERO,
        commonware_release: oic_membership::COMMONWARE_RELEASE.into(),
        wire_version: oic_membership::WIRE_VERSION,
        trust_domains: nodes
            .iter()
            .map(|n| TrustDomain {
                domain_id: n.domain_id.clone(),
                administrators: vec![world.admins[0].0.clone()],
                failure_domain_notes: "Independent IAM, hardware, operators, recovery".into(),
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
            Committee {
                committee_id: CommitteeId::unchecked("authority"),
                kind: CommitteeKind::AuthorityD1,
                members: vec![node_id(AUTHORITY)],
                threshold: 1,
            },
        ],
        channel_acl: vec![
            acl(0, all.clone(), all),
            acl(
                10,
                vec![Role::Gateway, Role::Signer],
                vec![Role::Gateway, Role::Signer],
            ),
            acl(
                12,
                vec![Role::Gateway, Role::Authority],
                vec![Role::Gateway, Role::Authority],
            ),
            acl(20, vec![Role::Signer], vec![Role::Signer]),
        ],
        tolerated_domain_compromises: 1,
        activation: Activation {
            not_before: now(),
            authority_commit_reference: None,
        },
    };
    let hash = roster_hash(&body).unwrap();
    let signatures = world.admins[..2]
        .iter()
        .map(|(id, key)| CredentialSignature {
            credential_id: id.clone(),
            signature: SignatureBytes {
                scheme: SchemeId::Ed25519Pure,
                bytes: key.sign(hash.as_ref()).to_bytes().to_vec().into(),
            },
        })
        .collect();
    let admins = AdminTrust {
        threshold: 2,
        credentials: world
            .admins
            .iter()
            .map(|(id, key)| {
                (
                    id.clone(),
                    PublicKey {
                        scheme: SchemeId::Ed25519Pure,
                        bytes: key.verifying_key().to_bytes().to_vec().into(),
                    },
                )
            })
            .collect(),
    };
    (SignedRoster { body, signatures }, admins)
}

struct Network {
    gateway: Gateway,
    sender: oic_node::SendHandle,
    signer_senders: Vec<oic_node::SendHandle>,
    runtime: tokio::runtime::Handle,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Network {
    fn start(
        world: &World,
        roster: SignedRoster,
        admins: AdminTrust,
        clients: Vec<ipc::Client>,
        fault: Fault,
        calls: Arc<Mutex<Vec<&'static str>>>,
    ) -> Self {
        let authority = world.authority.clone();
        let (ready, receive) = mpsc::sync_channel(1);
        let (stop, stopped) = oneshot::channel();
        let thread = thread::spawn(move || {
            let config = runtime::Config::default();
            let storage = config.storage_directory().to_owned();
            runtime::Runner::new(config).start(move |context| async move {
                let mut tasks = Vec::new();
                let mut stops = Vec::new();
                let mut signer_senders = Vec::new();
                for index in 0..5 {
                    let hash = roster_hash(&roster.body).unwrap();
                    let transport = Transport::start(
                        context.child("node").with_attribute("index", index),
                        Config {
                            roster: roster.clone(),
                            admins: admins.clone(),
                            previous: None,
                            institution_id: inst(),
                            environment_id: env_id(),
                            genesis_hash: hash,
                            committed_roster_hash: hash,
                            now: now(),
                            node_id: node_id(index),
                            transport_key: key(120 + index as u8),
                        },
                    )
                    .unwrap();
                    let send = transport.sender();
                    if index < 3 {
                        signer_senders.push(send.clone());
                    }
                    let handler = if index == AUTHORITY {
                        let authority = authority.clone();
                        let roster = roster.clone();
                        let calls = calls.clone();
                        Some(Arc::new(move |from: &NodeId, frame: &[u8]| {
                            let request = AuthorityRequest::decode(frame, 0, MAX_BODY_LEN).ok();
                            let kind = match request {
                                Some(AuthorityRequest::Reserve { .. }) => Some("reserve"),
                                Some(AuthorityRequest::Release { .. }) => Some("release"),
                                Some(AuthorityRequest::AbortBeforeIssuance { .. }) => Some("abort"),
                                Some(AuthorityRequest::ChangeCredential { .. } | AuthorityRequest::Approve { .. }) | None => None,
                            };
                            if let Some(kind) = kind {
                                calls.lock().unwrap().push(kind);
                            }
                            let result = AuthorityRpcServer::new(
                                authority.as_ref(),
                                &roster,
                                &node_id(AUTHORITY),
                            )?
                            .handle(from, frame)?;
                            // The real authority has committed. Suppress only its
                            // response, so Gateway must exercise its RPC timeout.
                            if kind == Some("release") && fault == Fault::DropReleaseReply {
                                return Err(OicError::new(
                                    ErrorCode::AuthorityUnavailable,
                                    "injected lost release reply",
                                ));
                            }
                            Ok(result)
                        }) as AuthorityHandler)
                    } else {
                        None
                    };
                    // Deliberately discard this node's controls in one case.
                    // Its socket/roster remain live; its child still owns the key.
                    let core = clients
                        .get(index)
                        .filter(|_| !(index == 1 && fault == Fault::DropSignerControl))
                        .cloned();
                    let (bridge, gateway) = Bridge::new(transport, 0, core, handler);
                    let (stop, stopped) = oneshot::channel();
                    stops.push(stop);
                    tasks.push(tokio::spawn(bridge.run(stopped)));
                    if index == GATEWAY {
                        ready
                            .send((
                                gateway,
                                send,
                                std::mem::take(&mut signer_senders),
                                tokio::runtime::Handle::current(),
                            ))
                            .unwrap();
                    }
                }
                let _ = stopped.await;
                for stop in stops {
                    let _ = stop.send(());
                }
                for task in tasks {
                    task.await.unwrap().unwrap();
                }
            });
            fs::remove_dir_all(storage).unwrap();
        });
        let (gateway, sender, signer_senders, runtime) =
            receive.recv_timeout(Duration::from_secs(20)).unwrap();
        Self {
            gateway,
            sender,
            signer_senders,
            runtime,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    fn ready(&self, fault: Fault) {
        // The production lookup preset admits one handshake per IP per five
        // seconds and backs failed dials off by 60 seconds plus jitter. All
        // fixture nodes share loopback, so allow several connection attempts
        // without weakening transport limits or the mutation RPC deadline.
        let started = Instant::now();
        let deadline = started + Duration::from_secs(300);
        for index in 0..3 {
            let client = self.gateway.signer(node_id(index));
            loop {
                let result = client.request(SessionControl::Status {
                    request_id: 90_000 + index as u64,
                    session_id: SigningSessionId::unchecked("startup-no-session"),
                });
                match result {
                    Ok(reply) => {
                        assert_eq!(reply.result.unwrap_err().code, ErrorCode::NotFound);
                        break;
                    }
                    Err(e)
                        if index == 1
                            && fault == Fault::DropSignerControl
                            && e.code == ErrorCode::AuthorityUnavailable =>
                    {
                        break;
                    }
                    Err(e)
                        if matches!(
                            e.code,
                            ErrorCode::RosterMismatch
                                | ErrorCode::AuthorityUnavailable
                                | ErrorCode::Conflict
                        ) => {}
                    Err(e) => panic!("read-only startup probe: {e}"),
                }
                assert!(
                    Instant::now() < deadline,
                    "signer {index} convergence deadline"
                );
                thread::sleep(Duration::from_millis(100));
            }
        }
        // Authority RPC and signer peer links have no read-only query. Status
        // cannot decode as AuthorityRequest or SignedPeerMessage, so these
        // probes cannot mutate either boundary. Check the selected signer pair
        // too: gateway convergence alone does not prove their direct link ready.
        let probe = PeerFrameV1::encode_confidential(
            &SessionControl::Status {
                request_id: 99_000,
                session_id: SigningSessionId::unchecked("startup-no-session"),
            },
            0,
            FrameKind::Content,
            MAX_BODY_LEN,
        )
        .unwrap();
        for (sender, recipient, channel) in [
            (&self.sender, AUTHORITY, 12),
            (&self.signer_senders[0], 1, 20),
            (&self.signer_senders[1], 0, 20),
        ] {
            loop {
                match self.runtime.block_on(sender.send(
                    &node_id(recipient),
                    channel,
                    probe.clone(),
                )) {
                    Ok(()) => break,
                    Err(e) if matches!(e.code, ErrorCode::RosterMismatch | ErrorCode::Conflict) => {
                    }
                    Err(e) => panic!("nonmutating convergence probe: {e}"),
                }
                assert!(
                    Instant::now() < deadline,
                    "node {recipient}, channel {channel} convergence deadline"
                );
                thread::sleep(Duration::from_millis(100));
            }
        }
        println!("network readiness: {}ms", started.elapsed().as_millis());
    }
    fn shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Harness {
    network: Network,
    cores: Vec<CoreProcess>,
    calls: Arc<Mutex<Vec<&'static str>>>,
    roster: SignedRoster,
    _dir: tempfile::TempDir,
}
impl Harness {
    fn start(
        world: &World,
        sol: &mut SolChain,
        sealed: Vec<(ParticipantId, Bytes)>,
        fault: Fault,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (roster, admins) = roster(world, &sol.chain);
        let roots = world.trust_roots(vec![sol.chain.profile.clone()]);
        sol.chain.nodes.clear(); // No live participant provider in the network process.
        let cores = sealed
            .into_iter()
            .enumerate()
            .map(|(index, (participant, sealed))| {
                assert_eq!(participant, pid(index as u8 + 1));
                CoreProcess::start(
                    dir.path().join(format!("core-{index}")),
                    ChildFixture {
                        index,
                        roster: roster.clone(),
                        admins: (admins.threshold, admins.credentials.clone()),
                        key: sol.chain.key.clone(),
                        sealed,
                        roots: PublicRoots::from(roots.clone()),
                    },
                )
            })
            .collect::<Vec<_>>();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let network = Network::start(
            world,
            roster.clone(),
            admins,
            cores.iter().map(CoreProcess::client).collect(),
            fault,
            calls.clone(),
        );
        network.ready(fault);
        Self {
            network,
            cores,
            calls,
            roster,
            _dir: dir,
        }
    }
    fn coordinator(
        &self,
        world: &World,
        chain: &Chain,
        store: Arc<InMemoryOperationStore>,
    ) -> SigningCoordinator<dyn AuthorityEndpoint> {
        let authority: Arc<dyn AuthorityEndpoint> = Arc::new(
            AuthorityRpcClient::new(
                self.network.gateway.clone(),
                &self.roster,
                &node_id(GATEWAY),
                &node_id(AUTHORITY),
            )
            .unwrap(),
        );
        let signers = (0..3)
            .map(|i| {
                Arc::new(RemoteSigner::new(
                    pid(i as u8 + 1),
                    Epoch(1),
                    self.network.gateway.signer(node_id(i)),
                    Duration::from_secs(5),
                )) as Arc<dyn SignerEndpoint>
            })
            .collect();
        SigningCoordinator::new(
            authority,
            signers,
            vec![chain.adapter.clone()],
            world.clock.clone(),
            store,
        )
        .unwrap()
    }
    fn finish(mut self) -> Vec<Report> {
        self.network.shutdown();
        self.cores
            .iter_mut()
            .enumerate()
            .map(|(index, core)| {
                let report = core.finish();
                let ledger =
                    FileLedger::open(core.dir.join("ledger"), Some(report.ledger_sequence))
                        .unwrap();
                assert_eq!(ledger.snapshot(), report.records);
                assert_eq!(
                    FileGenerationStore::new(core.dir.join("generation"))
                        .load()
                        .unwrap(),
                    Some(Epoch(1))
                );
                let public: [u8; 32] = public(200 + index as u8)
                    .bytes
                    .as_slice()
                    .try_into()
                    .unwrap();
                verify_chain(
                    &report.audit,
                    &VerifyingKey::from_bytes(&public).unwrap(),
                    None,
                )
                .unwrap();
                assert_eq!(report.audit[0].body.action, "node.roster_applied");
                assert!(
                    report
                        .audit
                        .iter()
                        .all(|event| event.body.detail.is_empty())
                );
                report
            })
            .collect()
    }
}

fn signing_job(world: &World, chain: &Chain, name: &str) -> oic_service_coordinator::SigningJob {
    let intent = chain.intent(name, (SOL / 3).into(), 10_000, ApprovalMode::ExactCandidate);
    let policy = world.sign_policy(policy(
        1,
        vec![rule(&chain.asset.asset_id, 1, 100 * SOL as u128)],
    ));
    world.register(&policy, &intent);
    job(
        world,
        chain,
        &policy,
        &intent,
        &format!("candidate-{name}"),
        1,
        vec![pid(1), pid(2)],
    )
}
fn shares(report: &Report) -> usize {
    report
        .events
        .iter()
        .filter(|event| matches!(event, SignerEvent::ShareProduced { .. }))
        .count()
}

#[test]
fn real_process_frost_2_of_3_native_solana_transfer() {
    let world = World::new();
    let (mut sol, sealed) = sol_chain_with_sealed_shares(&world, false);
    let harness = Harness::start(&world, &mut sol, sealed, Fault::None);
    let store = Arc::new(InMemoryOperationStore::new());
    let job = signing_job(&world, &sol.chain, "real-network-success");
    let family = job.built.candidate.operation_family_id.clone();
    assert_eq!(sol.sim.lamports(&sol_dest_owner()), 0);
    let issued = harness
        .coordinator(&world, &sol.chain, store.clone())
        .execute(job)
        .unwrap();
    let txid = sol
        .sim
        .submit(issued.signed.signed.signed_bytes.as_slice())
        .unwrap();
    sol.sim.advance_slot().unwrap();
    assert_eq!(sol.sim.lamports(&sol_dest_owner()), SOL / 3);
    assert_eq!(txid, issued.signed.signed.chain_tx_id);
    assert_eq!(store.lifecycle(&family), LifecycleState::SignatureObserved);
    assert_eq!(*harness.calls.lock().unwrap(), ["reserve", "release"]);
    let expected_hash = sha256(
        issued.envelope.body.native_signing_payloads[0]
            .message_or_digest
            .as_slice(),
    );
    let reports = harness.finish();
    assert_eq!(reports.iter().map(shares).collect::<Vec<_>>(), [1, 1, 0]);
    for report in &reports[..2] {
        let release = report
            .events
            .iter()
            .position(|e| matches!(e, SignerEvent::Released { .. }))
            .unwrap();
        let share = report
            .events
            .iter()
            .position(|e| matches!(e, SignerEvent::ShareProduced { .. }))
            .unwrap();
        assert!(release < share);
        assert!(
            report
                .records
                .iter()
                .any(|record| record.session_id.as_ref()
                    == Some(&issued.envelope.body.signer_session_id)
                    && record.consumed
                    && record.bound_message_hash == Some(expected_hash))
        );
        assert_eq!(
            report
                .audit
                .iter()
                .filter(|event| event.body.action == "signer.share_released")
                .count(),
            1
        );
    }
    assert!(
        !reports[2]
            .events
            .iter()
            .any(|event| matches!(event, SignerEvent::SessionOpened { .. }))
    );
    assert!(reports[2].records.is_empty());
    println!(
        "native Solana: beneficiary={} lamports, txid={txid}, child_pids={:?}, shares={:?}; durable ledger/generation/audit verified",
        sol.sim.lamports(&sol_dest_owner()),
        reports.iter().map(|report| report.pid).collect::<Vec<_>>(),
        reports.iter().map(shares).collect::<Vec<_>>()
    );
}

#[test]
fn dropped_signer_control_times_out_before_release_and_aborts_reservation() {
    let world = World::new();
    let (mut sol, sealed) = sol_chain_with_sealed_shares(&world, false);
    let harness = Harness::start(&world, &mut sol, sealed, Fault::DropSignerControl);
    let store = Arc::new(InMemoryOperationStore::new());
    let job = signing_job(&world, &sol.chain, "lost-signer-open");
    let family = job.built.candidate.operation_family_id.clone();
    let started = Instant::now();
    let error = harness
        .coordinator(&world, &sol.chain, store.clone())
        .execute(job)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::AuthorityUnavailable);
    assert!(started.elapsed() >= Duration::from_secs(9));
    assert_eq!(
        store.lifecycle(&family),
        LifecycleState::AbortedBeforeIssuance
    );
    assert_eq!(*harness.calls.lock().unwrap(), ["reserve", "abort"]);
    assert_eq!(outstanding(&world, &sol.chain.asset.asset_id), Amount(0));
    assert_eq!(sol.sim.lamports(&sol_dest_owner()), 0);
    let reports = harness.finish();
    assert!(reports.iter().all(|report| shares(report) == 0));
    assert!(
        reports[0]
            .events
            .iter()
            .any(|event| matches!(event, SignerEvent::Aborted { .. }))
    );
    assert!(!reports.iter().any(|report| {
        report
            .events
            .iter()
            .any(|event| matches!(event, SignerEvent::Released { .. }))
    }));
    println!(
        "lost signer control: code={:?}, lifecycle={:?}, elapsed_ms={}, outstanding={}, shares={:?}; reserve=1 abort=1 release=0",
        error.code,
        store.lifecycle(&family),
        started.elapsed().as_millis(),
        outstanding(&world, &sol.chain.asset.asset_id).0,
        reports.iter().map(shares).collect::<Vec<_>>()
    );
}

#[test]
fn lost_committed_release_reply_times_out_without_retry_abort_or_signer_output() {
    let world = World::new();
    let (mut sol, sealed) = sol_chain_with_sealed_shares(&world, false);
    let harness = Harness::start(&world, &mut sol, sealed, Fault::DropReleaseReply);
    let store = Arc::new(InMemoryOperationStore::new());
    let job = signing_job(&world, &sol.chain, "lost-release-reply");
    let family = job.built.candidate.operation_family_id.clone();
    let started = Instant::now();
    let error = harness
        .coordinator(&world, &sol.chain, store.clone())
        .execute(job)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::IssuanceUncertain);
    assert!(started.elapsed() >= Duration::from_secs(9));
    assert_eq!(store.lifecycle(&family), LifecycleState::IssuanceUnknown);
    assert_eq!(*harness.calls.lock().unwrap(), ["reserve", "release"]);
    let reservation = store.operation(&family).unwrap().reservation_id.unwrap();
    assert!(matches!(
        world.authority.reservation(&reservation).unwrap().state,
        ReservationState::Released { .. }
    ));
    assert!(outstanding(&world, &sol.chain.asset.asset_id).0 > 0);
    assert_eq!(sol.sim.lamports(&sol_dest_owner()), 0);
    let reports = harness.finish();
    assert!(reports.iter().all(|report| shares(report) == 0));
    assert!(reports[..2].iter().all(|report| {
        report
            .events
            .iter()
            .any(|event| matches!(event, SignerEvent::SessionOpened { .. }))
    }));
    assert!(
        !reports
            .iter()
            .any(|report| report.events.iter().any(|event| matches!(
                event,
                SignerEvent::Released { .. } | SignerEvent::Aborted { .. }
            )))
    );
    println!(
        "lost committed release reply: code={:?}, lifecycle={:?}, elapsed_ms={}, outstanding={}, shares={:?}; reserve=1 release=1 abort=0",
        error.code,
        store.lifecycle(&family),
        started.elapsed().as_millis(),
        outstanding(&world, &sol.chain.asset.asset_id).0,
        reports.iter().map(shares).collect::<Vec<_>>()
    );
}
