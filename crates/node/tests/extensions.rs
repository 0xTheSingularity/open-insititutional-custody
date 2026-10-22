//! External embedding contracts. Uses admitted production Transport objects;
//! host-side dispatch inputs model authenticated events, not socket delivery.
use commonware_runtime::{Runner as _, Supervisor as _, tokio as runtime};
use ed25519_dalek::{Signer as _, SigningKey};
use oic_authorization_state::{CheckpointBody, ReceiptExpectation, SignedCheckpoint, checkpoint_hash, receipt_hash, verify_receipt};
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes};
use oic_domain_types::*;
use oic_membership::*;
use oic_node::*;
use oic_peer_wire::{FrameKind, HEADER_LEN, PeerFrameV1, WitnessMessage};
use std::{collections::BTreeMap, future::Future, net::TcpListener, path::PathBuf, time::Duration};
use tokio::{sync::oneshot, time::timeout};

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
    runtime::Runner::new(config).start(|context| async move {
        timeout(Duration::from_secs(20), test(context)).await.expect("extension contract deadline");
    });
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn id(n: u8) -> NodeId {
    NodeId::unchecked(format!("extension-node-{n}"))
}
fn public(seed: u8) -> PublicKey {
    PublicKey { scheme: SchemeId::Ed25519Pure, bytes: key(seed).verifying_key().to_bytes().to_vec().into() }
}
fn signature(seed: u8, hash: Hash32) -> SignatureBytes {
    SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: key(seed).sign(hash.as_ref()).to_bytes().to_vec().into() }
}
fn spec(channel: u64) -> ChannelSpec {
    ChannelSpec {
        channel,
        sender_roles: vec![Role::Gateway, Role::Extension, Role::Authority],
        receiver_roles: vec![Role::Gateway, Role::Extension],
        max_message_size: 4096,
        quota: 100,
    }
}
fn config(local: u8) -> Config {
    // Distinct held ports avoid fixture address reuse while constructing a roster.
    let listeners: Vec<_> = (0..6).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    let nodes: Vec<_> = [Role::Authority, Role::Gateway, Role::Extension, Role::Gateway, Role::Signer, Role::Recovery]
        .into_iter()
        .enumerate()
        .map(|(n, role)| Node {
            node_id: id(n as u8),
            domain_id: TrustDomainId::unchecked(format!("operator-{n}")),
            roles: vec![role],
            transport_key: public(10 + n as u8),
            attestation_key: (role == Role::Signer).then(|| public(40)),
            consensus_key: None,
            address: listeners[n].local_addr().unwrap(),
            peer_class: if role == Role::Extension { PeerClass::Secondary } else { PeerClass::Primary },
            participant_keys: if matches!(role, Role::Signer | Role::Recovery) {
                BTreeMap::from([(ParticipantId::unchecked(format!("participant-{n}")), public(41 + n as u8))])
            } else {
                BTreeMap::new()
            },
            approved_build_hashes: vec![Hash32([90; 32])],
            signer_instance_generation: Epoch(1),
        })
        .collect();
    let body = RosterBody {
        institution_id: InstitutionId::unchecked("institution"),
        environment_id: EnvironmentId::unchecked("test"),
        roster_epoch: 0,
        previous_roster_hash: Hash32::ZERO,
        genesis_hash: Hash32::ZERO,
        commonware_release: "2026.9.0".into(),
        wire_version: 1,
        trust_domains: nodes
            .iter()
            .map(|n| TrustDomain {
                domain_id: n.domain_id.clone(),
                administrators: vec![CredentialId::unchecked("admin")],
                failure_domain_notes: "Separate operator/IAM/hardware/backup".into(),
            })
            .collect(),
        nodes,
        committees: vec![Committee {
            committee_id: CommitteeId::unchecked("authority"),
            kind: CommitteeKind::AuthorityD1,
            members: vec![id(0)],
            threshold: 1,
        }],
        channel_acl: vec![
            ChannelSpec { channel: 0, sender_roles: vec![Role::Gateway], receiver_roles: vec![Role::Gateway], max_message_size: 512, quota: 100 },
            ChannelSpec { channel: 21, sender_roles: vec![Role::Recovery], receiver_roles: vec![Role::Recovery], max_message_size: 512, quota: 100 },
            spec(1024),
            spec(1025),
            spec(1026),
        ],
        tolerated_domain_compromises: 1,
        activation: Activation { not_before: UnixSeconds(1), authority_commit_reference: None },
    };
    let hash = roster_hash(&body).unwrap();
    Config {
        roster: SignedRoster {
            body: body.clone(),
            signatures: vec![CredentialSignature { credential_id: CredentialId::unchecked("admin"), signature: signature(1, hash) }],
        },
        admins: AdminTrust { threshold: 1, credentials: BTreeMap::from([(CredentialId::unchecked("admin"), public(1))]) },
        previous: None,
        institution_id: body.institution_id,
        environment_id: body.environment_id,
        genesis_hash: hash,
        committed_roster_hash: hash,
        now: UnixSeconds(2),
        node_id: id(local),
        transport_key: key(10 + local),
    }
}

struct Capture {
    claims: Vec<ChannelSpec>,
    output: oneshot::Sender<ExtensionContext>,
}
impl Extension for Capture {
    fn channels(&self) -> Vec<ChannelSpec> {
        self.claims.clone()
    }
    fn start(self: Box<Self>, context: ExtensionContext) -> ExtensionHandle {
        assert!(self.output.send(context).is_ok());
        tokio::spawn(async {})
    }
}
async fn capture(host: &mut ExtensionHost, name: &str, claims: Vec<ChannelSpec>) -> OicResult<ExtensionContext> {
    let (output, receive) = oneshot::channel();
    host.start(name, Box::new(Capture { claims, output }))?.await.unwrap();
    Ok(receive.await.unwrap())
}
fn message() -> WitnessMessage {
    let body = CheckpointBody {
        institution_id: InstitutionId::unchecked("institution"),
        environment_id: EnvironmentId::unchecked("test"),
        authority_epoch: Epoch(2),
        commit_sequence: 7,
        state_hash: Hash32([77; 32]),
    };
    let signature = signature(60, checkpoint_hash(&body).unwrap());
    WitnessMessage::AuthorityCheckpoint(SignedCheckpoint { body, authority_key_id: KeyId::unchecked("receipt-key"), signature })
}
fn event(from: u8, channel: u64) -> Event {
    Event { from: id(from), channel, bytes: PeerFrameV1::encode_public(&message(), 0, FrameKind::Audit, 4096).unwrap() }
}
fn receipt(sequence: u64, kind: ReceiptKind) -> AuthorityReceipt {
    let body = AuthorityReceiptBody {
        kind,
        institution_id: InstitutionId::unchecked("institution"),
        environment_id: EnvironmentId::unchecked("test"),
        authority_epoch: Epoch(2),
        reservation_id: ReservationId::unchecked("reservation"),
        reservation_version: 1,
        candidate_id: CandidateId::unchecked("candidate"),
        candidate_revision: 1,
        envelope_body_hash: Hash32([42; 32]),
        signer_session_id: SigningSessionId::unchecked("session"),
        intent_hash: Hash32([43; 32]),
        rule_id: "rule".into(),
        claims_hash: Hash32([44; 32]),
        policy_epoch: Epoch(1),
        freeze_epoch: Epoch(0),
        issued_at: UnixSeconds(2),
        expires_at: UnixSeconds(100),
        commit_sequence: sequence,
    };
    let receipt =
        AuthorityReceipt { signature: signature(60, receipt_hash(&body).unwrap()), authority_key_id: KeyId::unchecked("receipt-key"), body };
    verify_receipt(
        &receipt,
        &key(60).verifying_key(),
        &ReceiptExpectation {
            kind,
            envelope_body_hash: Hash32([42; 32]),
            signer_session_id: SigningSessionId::unchecked("session"),
            candidate_id: CandidateId::unchecked("candidate"),
            candidate_revision: 1,
            now: UnixSeconds(3),
            policy_epoch: Epoch(1),
        },
    )
    .unwrap();
    receipt
}

#[test]
fn actual_host_identity_atomic_grants_and_fixed_namespace() {
    run(|context| async move {
        for (label, node) in [("signer", 4), ("recovery", 5)] {
            let participant = Transport::start(context.child(label), config(node)).unwrap();
            assert_eq!(ExtensionHost::new(&participant).err().unwrap().code, ErrorCode::PolicyDenied);
            participant.shutdown().await.unwrap();
        }
        let transport = Transport::start(context.child("extension"), config(2)).unwrap();
        let mut host = ExtensionHost::new(&transport).unwrap();
        for channel in [0, 12, 20, 21, 1023, 9999] {
            assert!(capture(&mut host, "probe", vec![spec(channel)]).await.is_err());
        }
        // A rejected multi-claim must not consume its valid first channel/name.
        assert!(capture(&mut host, "probe", vec![spec(1024), spec(9999)]).await.is_err());
        for name in ["", "a/b", "A", "../x"] {
            assert!(capture(&mut host, name, Vec::new()).await.is_err());
        }
        for mut claim in [spec(1024), spec(1024), spec(1024), spec(1024), spec(1024)].into_iter().enumerate() {
            match claim.0 {
                0 => claim.1.sender_roles.push(Role::Signer),
                1 => claim.1.receiver_roles.push(Role::Authority),
                2 => claim.1.max_message_size += 1,
                3 => claim.1.quota += 1,
                _ => claim.1.quota = 0,
            }
            assert!(capture(&mut host, "probe", vec![claim.1]).await.is_err());
        }
        let context = capture(&mut host, "probe", vec![spec(1024)]).await.unwrap();
        assert_eq!(context.namespace(), "OIC/EXT/probe/v1");
        assert_eq!(context.node_id(), transport.node_id());
        assert_eq!(context.roster(), transport.roster());
        assert!(context.channel(1024).is_some());
        for channel in [0, 12, 20, 1025] {
            assert!(context.channel(channel).is_none());
        }
        assert!(capture(&mut host, "other", vec![spec(1024)]).await.is_err());
        assert!(capture(&mut host, "probe", Vec::new()).await.is_err());
        assert!(capture(&mut host, "duplicate", vec![spec(1025), spec(1025)]).await.is_err());
        transport.shutdown().await.unwrap();
    });
}

#[test]
fn narrower_grants_frame_boundaries_and_clone_shared_quotas() {
    run(|context| async move {
        let transport = Transport::start(context.child("extension"), config(2)).unwrap();
        let mut host = ExtensionHost::new(&transport).unwrap();
        let mut grant = spec(1024);
        grant.sender_roles.retain(|r| *r != Role::Authority);
        grant.quota = 1;
        grant.max_message_size = event(1, 1024).bytes.len() as u32;
        let mut smaller = grant.clone();
        smaller.channel = 1025;
        smaller.max_message_size -= 1;
        let mut receive_only = spec(1026);
        receive_only.receiver_roles = vec![Role::Extension];
        let mut ctx = capture(&mut host, "narrow", vec![grant.clone(), smaller, receive_only]).await.unwrap();
        assert_eq!(host.dispatch(&event(0, 1024)).unwrap_err().code, ErrorCode::PeerNotAdmitted);
        assert_eq!(host.dispatch(&event(99, 1024)).unwrap_err().code, ErrorCode::PeerNotAdmitted);
        let mut malformed = event(1, 1024);
        malformed.bytes[9] = 1; // wrong epoch, before consuming the one-message quota
        assert!(host.dispatch(&malformed).is_err());
        malformed = event(1, 1024);
        malformed.bytes[11] = FrameKind::Content as u8;
        assert!(host.dispatch(&malformed).is_err());
        assert!(host.dispatch(&event(1, 1025)).is_err());
        assert_eq!(host.dispatch(&event(1, 1024)).unwrap(), ExtensionDispatch::Delivered);
        let received = ctx.recv().await.unwrap();
        assert_eq!(received.from, id(1));
        assert_eq!(received.channel, 1024);
        assert_eq!(received.message, message());
        assert_eq!(host.dispatch(&event(1, 1024)).unwrap_err().code, ErrorCode::Conflict);
        // Per-peer budget: another admitted gateway still gets its own allowance.
        assert_eq!(host.dispatch(&event(3, 1024)).unwrap(), ExtensionDispatch::Delivered);
        let send = ctx.channel(1024).unwrap();
        assert_eq!(send.spec(), &grant);
        assert_eq!(send.send(&id(0), &message()).await.unwrap_err().code, ErrorCode::PeerNotAdmitted);
        assert_eq!(send.send(&id(99), &message()).await.unwrap_err().code, ErrorCode::PeerNotAdmitted);
        // Signed ACL permits gateway recipients; this claim deliberately does not.
        assert_eq!(ctx.channel(1026).unwrap().send(&id(1), &message()).await.unwrap_err().code, ErrorCode::PeerNotAdmitted);
        assert_eq!(ctx.channel(1025).unwrap().send(&id(1), &message()).await.unwrap_err().code, ErrorCode::InvalidRequest);
        // No peer transport runs: first valid submission reaches convergence
        // checking; a separately obtained clone cannot reset the local quota.
        assert_eq!(send.send(&id(1), &message()).await.unwrap_err().code, ErrorCode::RosterMismatch);
        assert_eq!(ctx.channel(1024).unwrap().send(&id(1), &message()).await.unwrap_err().code, ErrorCode::Conflict);
        tokio::time::sleep(Duration::from_millis(1050)).await;
        assert_eq!(host.dispatch(&event(1, 1024)).unwrap(), ExtensionDispatch::Delivered);
        assert_eq!(send.clone().send(&id(1), &message()).await.unwrap_err().code, ErrorCode::RosterMismatch);
        transport.shutdown().await.unwrap();
    });
}

#[test]
fn confidential_detail_and_nonpublic_payloads_cannot_enter_extension_mailbox() {
    run(|context| async move {
        let transport = Transport::start(context.child("extension"), config(2)).unwrap();
        let mut host = ExtensionHost::new(&transport).unwrap();
        let mut ctx = capture(&mut host, "public", vec![spec(1024)]).await.unwrap();
        // Construct the existing typed audit variant via its public serde API;
        // no extra audit crate dependency or blanket public carrier is needed.
        let public: WitnessMessage = from_canonical_bytes(&canonical_bytes(&message()).unwrap()).unwrap();
        let sig = match public {
            WitnessMessage::AuthorityCheckpoint(cp) => cp.signature,
            _ => unreachable!(),
        };
        let detail: WitnessMessage = serde_json::from_value(serde_json::json!({"audit_checkpoint": {
            "checkpoint": {"body": {"service_key_id": "audit", "sequence": 1, "head_event_hash": Hash32([5;32]), "at": 2}, "signature": sig},
            "bridge": [{"body": {"event_id":"event", "sequence":1, "previous_event_hash":Hash32::ZERO, "at":2, "actor":"public", "action":"public", "object_commitments":{}, "policy_epoch":1, "detail":"CONFIDENTIAL"}, "service_key_id":"audit", "signature":sig}]
        }})).unwrap();
        let mut raw = event(1, 1024);
        let body = canonical_bytes(&detail).unwrap();
        raw.bytes.truncate(HEADER_LEN);
        raw.bytes[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
        raw.bytes.extend(body);
        assert!(host.dispatch(&raw).is_err());
        assert!(ctx.channel(1024).unwrap().send(&id(1), &detail).await.is_err());
        let body = canonical_bytes(&BTreeMap::from([("secret", "CONFIDENTIAL")])).unwrap();
        raw.bytes.truncate(HEADER_LEN);
        raw.bytes[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
        raw.bytes.extend(body);
        assert!(host.dispatch(&raw).is_err());
        assert_eq!(host.dispatch(&event(1, 1024)).unwrap(), ExtensionDispatch::Delivered);
        assert_eq!(ctx.recv().await.unwrap().message, message());
        transport.shutdown().await.unwrap();
    });
}

#[test]
fn slow_extension_mailboxes_never_block_other_extensions_or_custody() {
    run(|context| async move {
        let transport = Transport::start(context.child("extension"), config(2)).unwrap();
        let mut host = ExtensionHost::new(&transport).unwrap();
        let mut slow = capture(&mut host, "slow", vec![spec(1024)]).await.unwrap();
        let mut fast = capture(&mut host, "fast", vec![spec(1025)]).await.unwrap();
        for i in 0..EXTENSION_MAILBOX_CAPACITY {
            assert_eq!(host.dispatch(&event(if i % 2 == 0 { 1 } else { 3 }, 1024)).unwrap(), ExtensionDispatch::Delivered);
        }
        assert_eq!(host.dispatch(&event(1, 1024)).unwrap(), ExtensionDispatch::Dropped);
        assert_eq!(host.dispatch(&event(1, 12)).unwrap(), ExtensionDispatch::Unclaimed);
        assert_eq!(host.dispatch(&event(1, 1025)).unwrap(), ExtensionDispatch::Delivered);
        assert_eq!(fast.recv().await.unwrap().message, message());
        for sequence in 1..=(EXTENSION_MAILBOX_CAPACITY as u64 + 1) {
            host.publish_record(receipt(sequence, ReceiptKind::Reserved)).unwrap();
            assert_eq!(fast.next_record().await.unwrap().body.commit_sequence, sequence);
        }
        for sequence in 1..=EXTENSION_MAILBOX_CAPACITY as u64 {
            assert_eq!(slow.next_record().await.unwrap().body.commit_sequence, sequence);
        }
        assert!(slow.next_record().await.is_none()); // gap closes, never hidden
        host.publish_record(receipt(999, ReceiptKind::Release)).unwrap();
        assert_eq!(fast.next_record().await.unwrap().body.commit_sequence, 999);
        transport.shutdown().await.unwrap();
    });
}

#[test]
fn reference_consumer_observes_ordered_receipts_without_mutation_capability() {
    run(|context| async move {
        let transport = Transport::start(context.child("extension"), config(2)).unwrap();
        let mut host = ExtensionHost::new(&transport).unwrap();
        let (monitor, mut progress) = ReceiptMonitor::new();
        assert!(monitor.channels().is_empty());
        let task = host.start("receipt-monitor", Box::new(monitor)).unwrap();
        host.publish_record(receipt(5, ReceiptKind::Reserved)).unwrap();
        host.publish_record(receipt(6, ReceiptKind::Reserved)).unwrap();
        let mut wrong_scope = receipt(99, ReceiptKind::Release);
        wrong_scope.body.environment_id = EnvironmentId::unchecked("other");
        assert_eq!(host.publish_record(wrong_scope).unwrap_err().code, ErrorCode::ScopeMismatch);
        assert_eq!(host.publish_record(receipt(6, ReceiptKind::Reserved)).unwrap_err().code, ErrorCode::Conflict);
        host.publish_record(receipt(8, ReceiptKind::Release)).unwrap();
        timeout(Duration::from_secs(3), async {
            while progress.borrow().commit_sequence != Some(8) {
                progress.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(*progress.borrow(), ReceiptProgress { commit_sequence: Some(8), reservations: 2, releases: 1, closed: false });
        drop(host);
        timeout(Duration::from_secs(3), task).await.unwrap().unwrap();
        assert!(progress.borrow().closed);
        transport.shutdown().await.unwrap();
    });
}
