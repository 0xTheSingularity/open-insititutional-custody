//! Real TCP + Commonware encrypted lookup, including an admitted malicious
//! peer that bypasses the safe outbound API to test receiver-side rejection.
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519;
use commonware_p2p::{
    Address, AddressableManager as _, Receiver as _, Recipients, Sender as _, authenticated::lookup,
};
use commonware_runtime::{
    Handle, IoBuf, Network as _, Quota, Runner as _, Spawner as _, Supervisor as _, tokio as runtime,
};
use commonware_utils::ordered::Map;
use ed25519_dalek::{Signer as _, SigningKey};
use oic_crypto_provider::{BackendDescriptor, MessageConvention, PeerMessage, ThresholdTopology};
use oic_domain_types::*;
use oic_membership::*;
use oic_node::{Config, Event, PaddingProfile, Transport};
use oic_peer_wire::{ExpectedPeerMessage, FrameKind, MAX_BODY_LEN, MessageScope, PeerFrameV1, RosterState, SessionControl, SignedPeerMessage};
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
            consensus_key: None,
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
        let mut cfg = config(&roster, 0);
        cfg.roster.signatures.clear();
        assert_eq!(
            Transport::start_loopback(context.child("local_bad_admin"), cfg, PaddingProfile::Disabled).err().unwrap().code,
            ErrorCode::ApprovalRequired
        );
        for index in [0, 1] {
            let mut remote = roster.body.clone();
            remote.nodes[index].address = "192.0.2.1:12345".parse().unwrap();
            let cfg = config(&sign(remote), 0);
            assert_eq!(
                Transport::start_loopback(context.child("nonlocal").with_attribute("index", index), cfg, PaddingProfile::Disabled)
                    .err().unwrap().code,
                ErrorCode::InvalidRequest,
                "local retry must reject both a remote local address and a remote peer address"
            );
        }
    });
}

#[test]
fn real_socket_mpc_is_opaque_named_bounded_rate_limited_and_shutdown_releases_sockets() {
    run(|context| async move {
        let roster = fixture();
        let mut a = Transport::start_loopback(context.child("a"), config(&roster, 0), PaddingProfile::Disabled).unwrap();
        let mut b = Transport::start_loopback(context.child("b"), config(&roster, 1), PaddingProfile::Disabled).unwrap();
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
        assert_eq!(deliver(&b, &mut a, 0, 20, &payload).await.from, id(1));
        assert_eq!(sender.block(&id(0)).unwrap_err().code, ErrorCode::PeerNotAdmitted);
        assert_eq!(sender.block(&NodeId::unchecked("outsider")).unwrap_err().code, ErrorCode::PeerNotAdmitted);
        sender.block(&id(1)).unwrap();
        // Same command queue: this send is processed after the named block,
        // including its mapping to the authenticated Commonware transport key.
        assert_eq!(sender.send(&id(1), 20, vec![1]).await.unwrap_err().code, ErrorCode::PeerNotAdmitted);
        let _ = b.send(&id(0), 20, payload.to_vec()).await;
        assert!(timeout(Duration::from_millis(300), a.recv()).await.is_err(), "blocked peer cannot deliver");
        for node in &roster.body.nodes[..2] {
            assert!(context.bind(node.address).await.is_err(), "live listener unexpectedly allowed a second bind");
        }
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
        assert!(sender.send(&id(1), 20, vec![1]).await.is_err());
        timeout(Duration::from_secs(3), async {
            loop {
                // Match Commonware's reuse-enabled bind: TCP TIME_WAIT alone
                // must not be confused with a surviving listener.
                if let (Ok(_a), Ok(_b)) = (
                    context.bind(roster.body.nodes[0].address).await,
                    context.bind(roster.body.nodes[1].address).await,
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
            (oic_node::MAX_MESSAGE_SIZE + 43) as u32,
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
        for channel in [0, 10, 20, 21, 30] {
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
        // A startup dial collision costs the production profile a 60 s
        // cooldown, most of `connected()`'s budget. The receive path under
        // test is identical in both profiles.
        let mut a = Transport::start_loopback(context.child("a"), config(&roster, 0), PaddingProfile::Disabled).unwrap();
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

fn padding_roster() -> SignedRoster {
    let mut body = fixture().body;
    // A signer/gateway peer can exercise content and both named MPC channels.
    body.nodes[1].roles.push(Role::Gateway);
    for acl in &mut body.channel_acl {
        if acl.channel == 10 {
            acl.max_message_size = 4096;
        } else if acl.channel == 20 {
            acl.max_message_size = 1024;
            acl.quota = 100;
        }
    }
    body.channel_acl.push(ChannelSpec {
        channel: 21,
        sender_roles: vec![Role::Signer],
        receiver_roles: vec![Role::Signer],
        max_message_size: 1024,
        quota: 100,
    });
    sign(body)
}

fn native_solana_bytes(version: oic_adapter_solana::message::MessageVersion) -> Vec<u8> {
    use oic_adapter_solana::{instruction::system_transfer_data, message::*};
    let signer = key(91);
    let message = Message {
        version,
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        },
        account_keys: vec![signer.verifying_key().to_bytes(), [0x57; 32], [0; 32]],
        recent_blockhash: [0xb6; 32],
        instructions: vec![CompiledInstruction {
            program_id_index: 2,
            accounts: vec![0, 1],
            data: system_transfer_data(1_234_567),
        }],
        address_table_lookups: vec![],
    }.encode();
    Transaction::encode(&[signer.sign(&message).to_bytes()], &message)
}

fn native_peer_frame(
    roster: &SignedRoster,
    from: u8,
    to: u8,
    kind: FrameKind,
    native: &[u8],
) -> (Vec<u8>, ExpectedPeerMessage) {
    let scope = MessageScope {
        institution_id: roster.body.institution_id.clone(),
        environment_id: roster.body.environment_id.clone(),
        roster_epoch: roster.body.roster_epoch,
        roster_hash: roster_hash(&roster.body).unwrap(),
    };
    let message = PeerMessage {
        session_id: SigningSessionId::unchecked("native-padding-vector"),
        key_id: KeyId::unchecked("chain-key"),
        key_epoch: Epoch(3),
        from: ParticipantId::unchecked(format!("participant-{from}")),
        from_generation: Epoch(7),
        to: Some(ParticipantId::unchecked(format!("participant-{to}"))),
        round: 2,
        sequence: 19,
        protocol_version: "padding-native-vector/1".into(),
        payload: Bytes(native.to_vec()),
    };
    let expected = ExpectedPeerMessage {
        scope: scope.clone(),
        session_id: message.session_id.clone(),
        key_id: message.key_id.clone(),
        key_epoch: message.key_epoch,
        from: message.from.clone(),
        from_generation: message.from_generation,
        to: message.to.clone().unwrap(),
        round: message.round,
        sequence: message.sequence,
        protocol_version: message.protocol_version.clone(),
    };
    let signed = SignedPeerMessage::sign(message, scope, &key(31 + from)).unwrap();
    (signed.encode_point_to_point(kind, MAX_BODY_LEN).unwrap(), expected)
}

async fn capture_data(
    sender: &Transport,
    raw: &mut RawPeer,
    roster: &SignedRoster,
    channel: u64,
    frame: &[u8],
) -> Vec<u8> {
    timeout(Duration::from_secs(90), async {
        loop {
            raw.send(0, hello(roster));
            match sender.send(&id(1), channel, frame.to_vec()).await {
                Ok(()) => break,
                Err(e) if matches!(e.code, ErrorCode::RosterMismatch | ErrorCode::Conflict) => {
                    sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("unexpected padding send rejection: {e}"),
            }
        }
        loop {
            let (received_channel, bytes) = raw.receive.recv().await.unwrap();
            if received_channel == channel && bytes.as_ref()[2] == 1 {
                return bytes.as_ref().to_vec();
            }
        }
    }).await.expect("real encrypted socket capture")
}

#[test]
fn real_socket_padding_has_fixed_sizes_and_preserves_signed_native_solana_bytes() {
    run(|context| async move {
        use oic_adapter_solana::message::{MessageVersion, Transaction};
        let roster = padding_roster();
        let padding = PaddingProfile::FixedBucketsV1;
        let mut a = Transport::start_with_padding(context.child("padded"), config(&roster, 0), padding).unwrap();
        let mut raw = RawPeer::start(context.child("raw"), &roster, 1, 12, &roster.namespace().unwrap());
        raw.connected().await;
        for kind in [FrameKind::MpcSign, FrameKind::MpcCeremony] {
            let mut lengths = Vec::new();
            let mut originals = Vec::new();
            for version in [MessageVersion::Legacy, MessageVersion::V0] {
                // Real native signatures, not an MPC safety/threshold claim.
                let native = native_solana_bytes(version);
                let (frame, _) = native_peer_frame(&roster, 0, 1, kind, &native);
                originals.push(frame.len());
                let wire = capture_data(&a, &mut raw, &roster, kind as u64, &frame).await;
                lengths.push(wire.len());
                assert_eq!(padding.decode_point_to_point(&wire[43..], 0, kind, 1024).unwrap(), frame);

                let (reverse, expected) = native_peer_frame(&roster, 1, 0, kind, &native);
                let padded = padding.encode_point_to_point(reverse.clone(), 0, kind, 1024).unwrap();
                raw.send(kind as u64, packet(&roster, 1, &padded));
                let event = timeout(Duration::from_secs(10), a.recv()).await.unwrap().unwrap();
                assert_eq!(event.from, id(1));
                assert_eq!(event.channel, kind as u64);
                assert_eq!(event.bytes, reverse);
                let signed = SignedPeerMessage::decode_point_to_point(&event.bytes, 0, kind, MAX_BODY_LEN).unwrap();
                let verified = signed.verify(&expected, &key(32).verifying_key()).unwrap();
                assert_eq!(verified.payload.as_slice(), native);
                let tx = Transaction::decode(verified.payload.as_slice()).unwrap();
                assert_eq!(tx.message.version, version);
                key(91).verifying_key().verify_strict(
                    &tx.message_bytes,
                    &ed25519_dalek::Signature::from_bytes(&tx.signatures[0]),
                ).unwrap();
            }
            assert_ne!(originals[0], originals[1]);
            assert_eq!(lengths, [1067, 1067], "43-byte routing prefix + fixed 1024-byte bucket");
        }
        let control = SessionControl::Status {
            request_id: 27,
            session_id: SigningSessionId::unchecked("content-padding-vector"),
        };
        let frame = PeerFrameV1::encode_confidential(&control, 0, FrameKind::Content, MAX_BODY_LEN).unwrap();
        let wire = capture_data(&a, &mut raw, &roster, 10, &frame).await;
        assert_eq!(wire.len(), 1067);
        assert_eq!(padding.decode_point_to_point(&wire[43..], 0, FrameKind::Content, 4096).unwrap(), frame);
        raw.send(10, packet(&roster, 1, &wire[43..]));
        assert_eq!(timeout(Duration::from_secs(10), a.recv()).await.unwrap().unwrap().bytes, frame);
        eprintln!("padding: content10/mpc20/21 over real authenticated TCP; different native legacy/v0 byte lengths share 1024-byte buckets; participant/native signatures still verify");
        raw.shutdown().await;
        a.shutdown().await.unwrap();
    });
}

#[test]
fn real_socket_padding_rejects_mixed_malformed_and_oversized_before_delivery() {
    run(|context| async move {
        for profile in [PaddingProfile::Disabled, PaddingProfile::FixedBucketsV1] {
            let roster = padding_roster();
            let mut a = Transport::start_with_padding(context.child("receiver"), config(&roster, 0), profile).unwrap();
            let mut raw = RawPeer::start(context.child("raw"), &roster, 1, 12, &roster.namespace().unwrap());
            raw.connected().await;
            let native = native_solana_bytes(oic_adapter_solana::message::MessageVersion::Legacy);
            let (forward, _) = native_peer_frame(&roster, 0, 1, FrameKind::MpcSign, &native);
            capture_data(&a, &mut raw, &roster, 20, &forward).await;
            let (frame, _) = native_peer_frame(&roster, 1, 0, FrameKind::MpcSign, &native);
            let padded = PaddingProfile::FixedBucketsV1.encode_point_to_point(frame.clone(), 0, FrameKind::MpcSign, 1024).unwrap();
            let mixed = if profile == PaddingProfile::Disabled { &padded } else { &frame };
            raw.send(20, packet(&roster, 1, mixed));
            absent(&mut a).await;
            if profile == PaddingProfile::FixedBucketsV1 {
                let mut bad_tail = padded.clone();
                bad_tail[1023] = 1;
                let mut bad_length = padded.clone();
                bad_length[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
                let mut oversized = padded.clone();
                oversized.resize(4096, 0);
                for bad in [&padded[..1023], &bad_tail, &bad_length, &oversized] {
                    raw.send(20, packet(&roster, 1, bad));
                    absent(&mut a).await;
                }
                // The inner frame fits a 1024-byte ACL but its next bucket does not.
                let mut near_limit = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20];
                near_limit.extend(997u32.to_be_bytes());
                near_limit.resize(1013, 0xff);
                assert_eq!(a.send(&id(1), 20, near_limit).await.unwrap_err().code, ErrorCode::InvalidRequest);
                assert_eq!(a.send(&id(4), 20, forward.clone()).await.unwrap_err().code, ErrorCode::PeerNotAdmitted);
                // Even valid padding cannot authorize a signer to send audit to a signer.
                raw.send(30, packet(&roster, 1, b"not-authorized"));
                absent(&mut a).await;
            }
            let valid = if profile == PaddingProfile::Disabled { &frame } else { &padded };
            raw.send(20, packet(&roster, 1, valid));
            assert_eq!(timeout(Duration::from_secs(10), a.recv()).await.unwrap().unwrap().bytes, frame);
            // Unaffected control remains byte-exact in either local profile.
            raw.send(0, packet(&roster, 1, b"unchanged-control"));
            assert_eq!(timeout(Duration::from_secs(10), a.recv()).await.unwrap().unwrap().bytes, b"unchanged-control");
            raw.shutdown().await;
            a.shutdown().await.unwrap();
        }
        eprintln!("padding: both mixed-profile directions, malformed length/tail, ACL oversize and forbidden role produce no event; valid traffic still progresses");
    });
}

/// RFC 0003 §4.2 / T12: while the receiver is not reading, a peer flooding one
/// channel fills only that channel's queues; a message on another channel is
/// still delivered once the receiver drains.
#[test]
fn real_socket_flood_on_one_channel_does_not_drop_another_channels_message() {
    run(|context| async move {
        let roster = fixture();
        let a = Transport::start_loopback(context.child("a"), config(&roster, 0), PaddingProfile::Disabled).unwrap();
        let mut b = Transport::start_loopback(context.child("b"), config(&roster, 1), PaddingProfile::Disabled).unwrap();
        deliver(&a, &mut b, 1, 0, b"warm-up").await;
        // Flood channel 0 well past the old shared 128-entry queue while b is not reading.
        let mut accepted = 0;
        timeout(Duration::from_secs(30), async {
            while accepted < 250 {
                match a.send(&id(1), 0, b"flood".to_vec()).await {
                    Ok(()) => accepted += 1,
                    Err(e) if e.code == ErrorCode::Conflict => sleep(Duration::from_millis(5)).await,
                    Err(e) => panic!("unexpected flood rejection: {e}"),
                }
            }
        })
        .await
        .expect("flood submission deadline");
        let marker = [0x5a; 32];
        timeout(Duration::from_secs(30), async {
            loop {
                match a.send(&id(1), 20, marker.to_vec()).await {
                    Ok(()) => break,
                    Err(e) if e.code == ErrorCode::Conflict => sleep(Duration::from_millis(100)).await,
                    Err(e) => panic!("unexpected marker rejection: {e}"),
                }
            }
        })
        .await
        .expect("marker submission deadline");
        sleep(Duration::from_millis(500)).await;
        // Drain until the marker arrives. The old shared queue dropped it for
        // good, so the deadline only bounds a failure, never a pass.
        let found = timeout(Duration::from_secs(30), async {
            loop {
                match b.recv().await {
                    Some(event) if event.channel == 20 => {
                        assert_eq!(event.bytes, marker);
                        return true;
                    }
                    Some(_) => {}
                    None => return false,
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(found, "a flood on channel 0 must not drop the channel 20 message");
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    });
}
