//! Real TCP + Commonware encrypted lookup, including an admitted malicious
//! peer that bypasses the safe outbound API to test receiver-side rejection.
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519;
use commonware_p2p::{
    Address, AddressableManager as _, Receiver as _, Recipients, Sender as _, authenticated::lookup,
};
use commonware_runtime::{
    Handle, IoBuf, Quota, Runner as _, Spawner as _, Supervisor as _, tokio as runtime,
};
use commonware_utils::ordered::Map;
use ed25519_dalek::{Signer as _, SigningKey};
use oic_crypto_provider::{BackendDescriptor, MessageConvention, ThresholdTopology};
use oic_domain_types::*;
use oic_membership::*;
use oic_node::{Config, Event, Transport};
use oic_peer_wire::{FrameKind, PeerFrameV1, RosterState};
use std::{
    collections::BTreeMap,
    future::Future,
    net::TcpListener,
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};
use tokio::{
    sync::mpsc,
    time::{sleep, timeout},
};

fn run<F, Fut>(test: F)
where
    F: FnOnce(runtime::Context) -> Fut,
    Fut: Future<Output = ()>,
{
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let config = runtime::Config::default();
    let _cleanup = Cleanup(config.storage_directory().to_owned());
    runtime::Runner::new(config).start(test);
}

fn id(index: u8) -> NodeId {
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
fn admins() -> AdminTrust {
    AdminTrust {
        threshold: 1,
        credentials: BTreeMap::from([(CredentialId::unchecked("admin"), public(1))]),
    }
}
fn sign(body: RosterBody) -> SignedRoster {
    let signature = key(1).sign(roster_hash(&body).unwrap().as_ref());
    SignedRoster {
        body,
        signatures: vec![CredentialSignature {
            credential_id: CredentialId::unchecked("admin"),
            signature: SignatureBytes {
                scheme: SchemeId::Ed25519Pure,
                bytes: signature.to_bytes().to_vec().into(),
            },
        }],
    }
}

fn fixture() -> SignedRoster {
    let listeners: Vec<_> = (0..6)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let roles = [
        Role::Signer,
        Role::Signer,
        Role::Authority,
        Role::Witness,
        Role::Extension,
        Role::Gateway,
    ];
    let nodes: Vec<_> = roles
        .into_iter()
        .enumerate()
        .map(|(i, role)| Node {
            node_id: id(i as u8),
            domain_id: TrustDomainId::unchecked(format!("domain-{i}")),
            roles: vec![role],
            transport_key: public(11 + i as u8),
            attestation_key: (role == Role::Signer).then(|| public(41 + i as u8)),
            address: listeners[i].local_addr().unwrap(),
            peer_class: if matches!(role, Role::Witness | Role::Extension) {
                PeerClass::Secondary
            } else {
                PeerClass::Primary
            },
            participant_keys: if role == Role::Signer {
                BTreeMap::from([(
                    ParticipantId::unchecked(format!("participant-{i}")),
                    public(31 + i as u8),
                )])
            } else {
                BTreeMap::new()
            },
            approved_build_hashes: vec![Hash32([61 + i as u8; 32])],
            signer_instance_generation: Epoch(7),
        })
        .collect();
    let all = vec![Role::Signer, Role::Authority, Role::Gateway];
    let acl = |channel, sender_roles, receiver_roles, max_message_size, quota| ChannelSpec {
        channel,
        sender_roles,
        receiver_roles,
        max_message_size,
        quota,
    };
    let body = RosterBody {
        institution_id: InstitutionId::unchecked("institution"),
        environment_id: EnvironmentId::unchecked("testnet"),
        roster_epoch: 0,
        previous_roster_hash: Hash32::ZERO,
        genesis_hash: Hash32::ZERO,
        commonware_release: COMMONWARE_RELEASE.into(),
        wire_version: 1,
        trust_domains: nodes
            .iter()
            .map(|n| TrustDomain {
                domain_id: n.domain_id.clone(),
                administrators: vec![CredentialId::unchecked("domain-admin")],
                failure_domain_notes: "Independent operators, IAM, hardware, backups, recovery"
                    .into(),
            })
            .collect(),
        nodes,
        committees: vec![
            Committee {
                committee_id: CommitteeId::unchecked("chain-key"),
                kind: CommitteeKind::Key {
                    key_id: KeyId::unchecked("chain-key"),
                    key_epoch: Epoch(3),
                    participants: vec![
                        ParticipantId::unchecked("participant-0"),
                        ParticipantId::unchecked("participant-1"),
                    ],
                    backend: BackendDescriptor {
                        backend_id: "fixture".into(),
                        pinned_version: "1".into(),
                        license: "Apache-2.0".into(),
                        scheme: SchemeId::Ed25519Pure,
                        message_convention: MessageConvention::PureMessage,
                        topology: ThresholdTopology::Threshold {
                            max_participants: 7,
                            min_threshold: 2,
                        },
                        supports_refresh: false,
                        supports_recover_or_replace: false,
                        native_verifier_compatible: true,
                        has_one_time_state: true,
                        share_producing_round: 2,
                        security_note: "Topology fixture only".into(),
                    },
                },
                members: vec![id(0), id(1)],
                threshold: 2,
            },
            Committee {
                committee_id: CommitteeId::unchecked("authority"),
                kind: CommitteeKind::AuthorityD1,
                members: vec![id(2)],
                threshold: 1,
            },
        ],
        channel_acl: vec![
            acl(0, all.clone(), all, 512, 100),
            acl(
                10,
                vec![Role::Gateway, Role::Verifier],
                vec![Role::Gateway, Role::Verifier],
                64,
                100,
            ),
            acl(20, vec![Role::Signer], vec![Role::Signer], 32, 2),
            acl(30, vec![Role::Signer], vec![Role::Witness], 64, 100),
        ],
        tolerated_domain_compromises: 1,
        activation: Activation {
            not_before: UnixSeconds(1),
            authority_commit_reference: None,
        },
    };
    sign(body)
}

fn config(roster: &SignedRoster, local: u8) -> Config {
    let hash = roster_hash(&roster.body).unwrap();
    Config {
        roster: roster.clone(),
        admins: admins(),
        previous: None,
        institution_id: roster.body.institution_id.clone(),
        environment_id: roster.body.environment_id.clone(),
        genesis_hash: hash,
        committed_roster_hash: hash,
        now: UnixSeconds(2),
        node_id: id(local),
        transport_key: key(11 + local),
    }
}

async fn deliver(
    sender: &Transport,
    recipient: &mut Transport,
    to: u8,
    channel: u64,
    bytes: &[u8],
) -> Event {
    timeout(Duration::from_secs(90), async {
        loop {
            match sender.send(&id(to), channel, bytes.to_vec()).await {
                Ok(()) => {}
                Err(e) if matches!(e.code, ErrorCode::RosterMismatch | ErrorCode::Conflict) => {}
                Err(e) => panic!("unexpected send rejection: {e}"),
            }
            if let Ok(Some(event)) = timeout(Duration::from_millis(100), recipient.recv()).await {
                return event;
            }
        }
    })
    .await
    .expect("real-socket delivery deadline")
}

#[test]
fn startup_authenticates_admin_anchor_and_local_key_before_starting_network() {
    run(|context| async move {
        let roster = fixture();
        let mut cfg = config(&roster, 0);
        cfg.genesis_hash = Hash32([0xd3; 32]);
        assert_eq!(
            Transport::start(context.child("bad_anchor"), cfg)
                .err()
                .unwrap()
                .code,
            ErrorCode::ScopeMismatch
        );
        let mut cfg = config(&roster, 0);
        cfg.transport_key = key(90);
        assert_eq!(
            Transport::start(context.child("bad_key"), cfg)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidSignature
        );
        let mut cfg = config(&roster, 0);
        cfg.roster.signatures.clear();
        assert_eq!(
            Transport::start(context.child("bad_admin"), cfg)
                .err()
                .unwrap()
                .code,
            ErrorCode::ApprovalRequired
        );
    });
}

#[test]
fn real_socket_mpc_is_opaque_named_bounded_rate_limited_and_shutdown_releases_sockets() {
    run(|context| async move {
        let roster = fixture();
        let a = Transport::start(context.child("a"), config(&roster, 0)).unwrap();
        let mut b = Transport::start(context.child("b"), config(&roster, 1)).unwrap();
        let mut payload = [0x7b; 32]; // Exactly the channel limit, not CBOR or a PeerMessage.
        payload[..4].copy_from_slice(&[0xff, 0, 0x93, 0x81]);
        let event = deliver(&a, &mut b, 1, 20, &payload).await;
        assert_eq!(event.from, id(0));
        assert_eq!(event.channel, 20);
        assert_eq!(event.bytes, payload);
        assert_eq!(format!("{event:?}"), "Event([REDACTED])");
        assert_eq!(
            a.send(&id(4), 20, vec![1]).await.unwrap_err().code,
            ErrorCode::PeerNotAdmitted
        );
        assert_eq!(
            a.send(&id(1), 999, vec![1]).await.unwrap_err().code,
            ErrorCode::PeerNotAdmitted
        );
        assert_eq!(
            a.send(&id(1), 20, vec![1; 33]).await.unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        let sender = a.sender();
        let mut rejected = false;
        for _ in 0..20 {
            if sender
                .send(&id(1), 20, vec![1])
                .await
                .is_err_and(|e| e.code == ErrorCode::Conflict)
            {
                rejected = true;
            }
        }
        assert!(rejected, "per-channel quota must reject a burst");
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
        assert!(sender.send(&id(1), 20, vec![1]).await.is_err());
        timeout(Duration::from_secs(3), async {
            loop {
                if let (Ok(_a), Ok(_b)) = (
                    TcpListener::bind(roster.body.nodes[0].address),
                    TcpListener::bind(roster.body.nodes[1].address),
                ) {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("shutdown must release TCP listeners");
    });
}

struct RawPeer {
    senders: BTreeMap<u64, lookup::Sender<ed25519::PublicKey, runtime::Context>>,
    receive: mpsc::Receiver<(u64, IoBuf)>,
    tasks: Vec<Handle<()>>,
    target: ed25519::PublicKey,
}

impl RawPeer {
    fn start(
        context: runtime::Context,
        roster: &SignedRoster,
        local: u8,
        seed: u8,
        namespace: &[u8],
    ) -> Self {
        let node = &roster.body.nodes[local as usize];
        let crypto = ed25519::PrivateKey::decode(key(seed).as_bytes().as_slice()).unwrap();
        let cfg = lookup::Config::local(
            crypto,
            namespace,
            node.address,
            NonZeroUsize::new(8).unwrap(),
            1024,
        );
        let (mut network, mut oracle) = lookup::Network::new(context.child("lookup"), cfg);
        let target =
            ed25519::PublicKey::decode(roster.body.nodes[0].transport_key.bytes.as_slice())
                .unwrap();
        let peers: Map<_, Address> = vec![(target.clone(), roster.body.nodes[0].address.into())]
            .try_into()
            .unwrap();
        oracle.track(roster.body.roster_epoch, peers);
        let (events, receive) = mpsc::channel(128);
        let mut senders = BTreeMap::new();
        let mut tasks = Vec::new();
        for channel in [0, 10, 20, 30] {
            let (sender, mut receiver) =
                network.register(channel, Quota::per_second(NonZeroU32::new(100).unwrap()));
            senders.insert(channel, sender);
            let events = events.clone();
            tasks.push(
                context
                    .child("inbound")
                    .with_attribute("channel", channel)
                    .spawn(move |_| async move {
                        while let Ok((_, bytes)) = receiver.recv().await {
                            let _ = events.try_send((channel, bytes));
                        }
                    }),
            );
        }
        tasks.push(network.start());
        Self {
            senders,
            receive,
            tasks,
            target,
        }
    }

    fn send(&mut self, channel: u64, bytes: Vec<u8>) {
        let _ = self.senders.get_mut(&channel).unwrap().send(
            Recipients::One(self.target.clone()),
            IoBuf::from(bytes),
            false,
        );
    }

    async fn connected(&mut self) {
        timeout(Duration::from_secs(90), async {
            loop {
                if self
                    .receive
                    .recv()
                    .await
                    .is_some_and(|(channel, _)| channel == 0)
                {
                    return;
                }
            }
        })
        .await
        .expect("authenticated raw peer connection");
    }

    async fn shutdown(self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

fn packet(roster: &SignedRoster, variant: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 1, variant];
    bytes.extend(roster.body.roster_epoch.to_be_bytes());
    bytes.extend(roster_hash(&roster.body).unwrap().0);
    bytes.extend(body);
    bytes
}

fn hello(roster: &SignedRoster) -> Vec<u8> {
    let body = PeerFrameV1::encode_public(
        &RosterState {
            roster_epoch: roster.body.roster_epoch,
            roster_hash: roster_hash(&roster.body).unwrap(),
        },
        roster.body.roster_epoch,
        FrameKind::Control,
        256,
    )
    .unwrap();
    packet(roster, 0, &body)
}

async fn absent(transport: &mut Transport) {
    assert!(
        timeout(Duration::from_millis(250), transport.recv())
            .await
            .is_err(),
        "forbidden event escaped transport"
    );
}

#[test]
fn real_socket_receiver_enforces_convergence_acl_lower_size_and_rechecks_each_packet() {
    run(|context| async move {
        let roster = fixture();
        let mut a = Transport::start(context.child("a"), config(&roster, 0)).unwrap();
        let mut raw = RawPeer::start(
            context.child("raw"),
            &roster,
            5,
            16,
            &roster.namespace().unwrap(),
        );
        raw.connected().await;
        raw.send(10, packet(&roster, 1, b"no-hello"));
        absent(&mut a).await;
        let mut wrong_hash = hello(&roster);
        wrong_hash[11] ^= 1;
        raw.send(0, wrong_hash);
        raw.send(10, packet(&roster, 1, b"wrong-hash"));
        absent(&mut a).await;
        let mut wrong_epoch = hello(&roster);
        wrong_epoch[10] = 1;
        raw.send(0, wrong_epoch);
        raw.send(10, packet(&roster, 1, b"wrong-epoch"));
        absent(&mut a).await;
        timeout(Duration::from_secs(10), async {
            loop {
                raw.send(0, hello(&roster));
                raw.send(10, packet(&roster, 1, &[0xff, 7, 3]));
                if let Ok(Some(event)) = timeout(Duration::from_millis(100), a.recv()).await {
                    assert_eq!(event.from, id(5));
                    assert_eq!(event.bytes, [0xff, 7, 3]);
                    break;
                }
            }
        })
        .await
        .unwrap();
        raw.send(20, packet(&roster, 1, b"gateway-is-not-a-signer"));
        absent(&mut a).await;
        raw.send(10, packet(&roster, 1, &[1; 65]));
        absent(&mut a).await;
        let mut bad = packet(&roster, 1, b"changed-after-convergence");
        bad[42] ^= 1;
        raw.send(10, bad);
        absent(&mut a).await;
        raw.send(10, packet(&roster, 1, b"view-was-cleared"));
        absent(&mut a).await;
        raw.shutdown().await;
        a.shutdown().await.unwrap();
    });
}

#[test]
fn real_socket_secondary_dials_primary_and_only_receives_authorized_audit() {
    run(|context| async move {
        let roster = fixture();
        let a = Transport::start(context.child("signer"), config(&roster, 0)).unwrap();
        let mut witness = Transport::start(context.child("witness"), config(&roster, 3)).unwrap();
        let event = deliver(&a, &mut witness, 3, 30, b"audit-public-record").await;
        assert_eq!(event.from, id(0));
        assert_eq!(event.channel, 30);
        assert_eq!(event.bytes, b"audit-public-record");
        assert_eq!(
            witness.send(&id(0), 20, vec![9]).await.unwrap_err().code,
            ErrorCode::PeerNotAdmitted
        );
        assert_eq!(
            a.send(&id(3), 20, vec![9]).await.unwrap_err().code,
            ErrorCode::PeerNotAdmitted
        );
        a.shutdown().await.unwrap();
        witness.shutdown().await.unwrap();
    });
}

#[test]
fn real_socket_unknown_key_foreign_namespace_and_unregistered_source_ip_do_not_connect() {
    run(|context| async move {
        for mode in 0..3 {
            let mut roster = fixture();
            if mode == 2 {
                roster.body.nodes[5]
                    .address
                    .set_ip("127.0.0.2".parse().unwrap());
                roster = sign(roster.body);
            }
            let mut a = Transport::start(
                context.child("a").with_attribute("mode", mode),
                config(&roster, 0),
            )
            .unwrap();
            let mut raw_roster = roster.clone();
            raw_roster.body.nodes[5]
                .address
                .set_ip("127.0.0.1".parse().unwrap());
            let mut namespace = roster.namespace().unwrap();
            if mode == 1 {
                namespace.push(0x7f);
            }
            let mut raw = RawPeer::start(
                context.child("raw").with_attribute("mode", mode),
                &raw_roster,
                5,
                if mode == 0 { 99 } else { 16 },
                &namespace,
            );
            // Real listener is reachable, but no encrypted authenticated channel
            // completes. The positive raw-peer test uses the same sockets/code.
            timeout(Duration::from_secs(3), async {
                loop {
                    if tokio::net::TcpStream::connect(roster.body.nodes[0].address)
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            for _ in 0..20 {
                raw.send(0, hello(&roster));
                raw.send(10, packet(&roster, 1, b"must-not-arrive"));
                sleep(Duration::from_millis(250)).await;
            }
            assert!(
                raw.receive.try_recv().is_err(),
                "rejected identity/namespace/IP completed a channel: mode {mode}"
            );
            absent(&mut a).await;
            raw.shutdown().await;
            a.shutdown().await.unwrap();
        }
    });
}
