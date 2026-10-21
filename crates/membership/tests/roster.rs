use ed25519_dalek::{Signer, SigningKey};
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes, value, Value};
use oic_crypto_provider::{BackendDescriptor, MessageConvention, ThresholdTopology};
use oic_domain_types::*;
use oic_membership::*;
use std::collections::BTreeMap;

mod attestations;

fn public(seed: u8) -> PublicKey {
    PublicKey { scheme: SchemeId::Ed25519Pure, bytes: SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes().to_vec().into() }
}

fn admins() -> AdminTrust {
    AdminTrust { threshold: 2, credentials: (1..=3).map(|i| (CredentialId::unchecked(format!("admin-{i}")), public(i))).collect() }
}

fn sign(body: RosterBody) -> SignedRoster {
    let hash = roster_hash(&body).unwrap();
    let signatures = (1..=2)
        .map(|i| CredentialSignature {
            credential_id: CredentialId::unchecked(format!("admin-{i}")),
            signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: SigningKey::from_bytes(&[i; 32]).sign(hash.as_ref()).to_bytes().to_vec().into() },
        })
        .collect();
    SignedRoster { body, signatures }
}

fn node(index: u8, role: Role) -> Node {
    Node {
        node_id: NodeId::unchecked(format!("node-{index}")),
        domain_id: TrustDomainId::unchecked(format!("domain-{index}")),
        roles: vec![role],
        transport_key: public(10 + index),
        consensus_key: None,
        attestation_key: matches!(role, Role::Signer | Role::Verifier).then(|| public(100 + index)),
        address: format!("127.0.0.1:{}", 9000 + u16::from(index)).parse().unwrap(),
        peer_class: if matches!(role, Role::Witness | Role::Extension) { PeerClass::Secondary } else { PeerClass::Primary },
        participant_keys: if matches!(role, Role::Signer | Role::Recovery) {
            BTreeMap::from([(ParticipantId::unchecked(format!("participant-{index}")), public(40 + index))])
        } else {
            BTreeMap::new()
        },
        approved_build_hashes: vec![Hash32([index + 1; 32])],
        signer_instance_generation: Epoch(7),
    }
}

fn acl(channel: u64, send: &[Role], receive: &[Role]) -> ChannelSpec {
    ChannelSpec { channel, sender_roles: send.into(), receiver_roles: receive.into(), max_message_size: 4096, quota: 100 }
}

fn body() -> RosterBody {
    let nodes = vec![
        node(0, Role::Signer),
        node(1, Role::Signer),
        node(2, Role::Signer),
        node(3, Role::Authority),
        node(4, Role::Gateway),
        node(5, Role::Witness),
        node(6, Role::Extension),
        node(7, Role::Verifier),
    ];
    let trust_domains = nodes
        .iter()
        .map(|n| TrustDomain {
            domain_id: n.domain_id.clone(),
            administrators: vec![CredentialId::unchecked("domain-owner")],
            failure_domain_notes: "Independent root IAM, hardware, image signing, backups, KMS, operators and recovery".into(),
        })
        .collect();
    RosterBody {
        institution_id: InstitutionId::unchecked("institution-a"),
        environment_id: EnvironmentId::unchecked("testnet"),
        roster_epoch: 0,
        previous_roster_hash: Hash32::ZERO,
        genesis_hash: Hash32::ZERO,
        commonware_release: COMMONWARE_RELEASE.into(),
        wire_version: WIRE_VERSION,
        trust_domains,
        nodes,
        committees: vec![
            Committee {
                committee_id: CommitteeId::unchecked("key"),
                kind: CommitteeKind::Key {
                    key_id: KeyId::unchecked("chain-key"),
                    key_epoch: Epoch(2),
                    participants: (0..3).map(|i| ParticipantId::unchecked(format!("participant-{i}"))).collect(),
                    backend: BackendDescriptor {
                        backend_id: "reviewed-test-topology".into(),
                        pinned_version: "1".into(),
                        license: "Apache-2.0".into(),
                        scheme: SchemeId::Ed25519Pure,
                        message_convention: MessageConvention::PureMessage,
                        topology: ThresholdTopology::Threshold { max_participants: 10, min_threshold: 2 },
                        supports_refresh: false,
                        supports_recover_or_replace: false,
                        native_verifier_compatible: true,
                        has_one_time_state: true,
                        share_producing_round: 2,
                        security_note: "Test descriptor, not a production backend endorsement".into(),
                    },
                },
                members: (0..3).map(|i| NodeId::unchecked(format!("node-{i}"))).collect(),
                threshold: 2,
            },
            Committee {
                committee_id: CommitteeId::unchecked("authority"),
                kind: CommitteeKind::AuthorityD1,
                members: vec![NodeId::unchecked("node-3")],
                threshold: 1,
            },
            Committee {
                committee_id: CommitteeId::unchecked("verification"),
                kind: CommitteeKind::Verification,
                members: vec![NodeId::unchecked("node-7")],
                threshold: 1,
            },
        ],
        channel_acl: vec![
            acl(0, &[Role::Gateway, Role::Signer, Role::Authority], &[Role::Gateway, Role::Signer, Role::Authority]),
            acl(10, &[Role::Gateway, Role::Verifier], &[Role::Gateway, Role::Verifier]),
            acl(11, &[Role::Verifier], &[Role::Gateway, Role::Authority]),
            acl(12, &[Role::Gateway, Role::Authority], &[Role::Gateway, Role::Authority]),
            acl(20, &[Role::Signer], &[Role::Signer]),
            acl(21, &[Role::Signer], &[Role::Signer]),
            acl(30, &[Role::Signer, Role::Authority, Role::Extension], &[Role::Witness]),
            acl(1024, &[Role::Extension], &[Role::Witness]),
        ],
        tolerated_domain_compromises: 1,
        activation: Activation { not_before: UnixSeconds(100), authority_commit_reference: None },
    }
}

fn validate(signed: &SignedRoster, previous: Option<&SignedRoster>) -> OicResult<()> {
    validate_roster(
        signed,
        &admins(),
        &InstitutionId::unchecked("institution-a"),
        &EnvironmentId::unchecked("testnet"),
        previous,
        UnixSeconds(100),
        roster_hash(&signed.body).unwrap(),
    )
}

fn rejected(body: RosterBody, previous: Option<&SignedRoster>, detail: &str) {
    let error = validate(&sign(body), previous).unwrap_err();
    assert!(error.detail.contains(detail), "expected {detail:?}, got {error}");
}

fn next(previous: &SignedRoster) -> RosterBody {
    let mut body = previous.body.clone();
    body.roster_epoch += 1;
    body.previous_roster_hash = roster_hash(&previous.body).unwrap();
    body.genesis_hash = if previous.body.roster_epoch == 0 { body.previous_roster_hash } else { previous.body.genesis_hash };
    body.activation.authority_commit_reference = Some(Hash32([99; 32]));
    body
}

#[test]
fn signed_canonical_roster_round_trips_and_rejects_unknown_fields() {
    let signed = sign(body());
    validate(&signed, None).unwrap();
    let bytes = canonical_bytes(&signed).unwrap();
    let decoded: SignedRoster = from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, signed);
    validate(&decoded, None).unwrap();
    let Value::Map(mut map) = value::decode(&bytes).unwrap() else { panic!("not a map") };
    let unknown = Value::text("unknown");
    map.insert(value::encode(&unknown), (unknown, Value::Bool(true)));
    assert!(from_canonical_bytes::<SignedRoster>(&value::encode(&Value::Map(map))).is_err());
    let mut noncanonical = vec![0xb8, 2]; // two-entry map encoded with a nonminimal length
    noncanonical.extend_from_slice(&bytes[1..]);
    assert!(from_canonical_bytes::<SignedRoster>(&noncanonical).is_err());
}

#[test]
fn ipv6_address_scopes_are_committed_without_loss() {
    let mut b = body();
    b.nodes[0].address = "[fe80::1%3]:9000".parse().unwrap();
    let first_hash = roster_hash(&b).unwrap();
    let decoded: RosterBody = from_canonical_bytes(&canonical_bytes(&b).unwrap()).unwrap();
    assert_eq!(decoded, b);
    b.nodes[0].address = "[fe80::1%4]:9000".parse().unwrap();
    assert_ne!(roster_hash(&b).unwrap(), first_hash);
    if let std::net::SocketAddr::V6(address) = &mut b.nodes[0].address {
        address.set_flowinfo(1);
    }
    assert!(roster_hash(&b).is_err()); // never sign an address field that is omitted
}

#[test]
fn quorum_requires_distinct_trusted_keys_and_authenticates_the_entire_body() {
    let signed = sign(body());
    let mut bad = signed.clone();
    bad.signatures.pop();
    assert_eq!(validate(&bad, None).unwrap_err().code, ErrorCode::ApprovalRequired);
    bad.signatures.push(bad.signatures[0].clone());
    assert!(validate(&bad, None).unwrap_err().detail.contains("duplicate administrative"));
    bad = signed.clone();
    bad.signatures[1].credential_id = CredentialId::unchecked("outsider");
    assert_eq!(validate(&bad, None).unwrap_err().code, ErrorCode::InvalidSignature);
    bad = signed.clone();
    bad.body.nodes[4].address.set_port(9123);
    assert_eq!(validate(&bad, None).unwrap_err().code, ErrorCode::InvalidSignature);
    bad = signed.clone();
    bad.signatures[1].signature.bytes.0[0] ^= 1;
    assert_eq!(validate(&bad, None).unwrap_err().code, ErrorCode::InvalidSignature);
    let mut aliases = admins();
    aliases.credentials.insert(CredentialId::unchecked("alias"), public(1));
    assert!(validate_roster(
        &signed,
        &aliases,
        &signed.body.institution_id,
        &signed.body.environment_id,
        None,
        UnixSeconds(100),
        roster_hash(&signed.body).unwrap()
    )
    .unwrap_err()
    .detail
    .contains("reuse a key"));
}

#[test]
fn scope_activation_and_pinned_versions_fail_closed() {
    let signed = sign(body());
    assert_eq!(
        validate_roster(
            &signed,
            &admins(),
            &signed.body.institution_id,
            &EnvironmentId::unchecked("mainnet"),
            None,
            UnixSeconds(100),
            roster_hash(&signed.body).unwrap()
        )
        .unwrap_err()
        .code,
        ErrorCode::ScopeMismatch
    );
    assert_eq!(
        validate_roster(
            &signed,
            &admins(),
            &InstitutionId::unchecked("other"),
            &signed.body.environment_id,
            None,
            UnixSeconds(100),
            roster_hash(&signed.body).unwrap()
        )
        .unwrap_err()
        .code,
        ErrorCode::ScopeMismatch
    );
    assert_eq!(
        validate_roster(&signed, &admins(), &signed.body.institution_id, &signed.body.environment_id, None, UnixSeconds(100), Hash32::ZERO).unwrap_err().code,
        ErrorCode::AuthorityUnavailable
    );
    assert!(validate_roster(
        &signed,
        &admins(),
        &signed.body.institution_id,
        &signed.body.environment_id,
        None,
        UnixSeconds(99),
        roster_hash(&signed.body).unwrap()
    )
    .unwrap_err()
    .detail
    .contains("future"));
    let mut b = body();
    b.commonware_release = "2026.10.0".into();
    rejected(b, None, "transport version");
    let mut b = body();
    b.wire_version = 2;
    rejected(b, None, "transport version");
}

#[test]
fn linked_epochs_preserve_genesis_namespace_and_reject_skips_forks_and_replay() {
    let genesis = sign(body());
    let update = sign(next(&genesis));
    validate(&update, Some(&genesis)).unwrap();
    assert_eq!(genesis.namespace().unwrap(), update.namespace().unwrap());
    let update2 = sign(next(&update));
    validate(&update2, Some(&update)).unwrap();
    assert_eq!(genesis.namespace().unwrap(), update2.namespace().unwrap());
    let mut b = next(&genesis);
    b.roster_epoch = 2;
    rejected(b, Some(&genesis), "advance exactly once");
    rejected(genesis.body.clone(), Some(&genesis), "advance exactly once");
    let mut b = next(&genesis);
    b.previous_roster_hash = Hash32([4; 32]);
    rejected(b, Some(&genesis), "previous roster hash");
    let mut b = next(&genesis);
    b.genesis_hash = Hash32([5; 32]);
    rejected(b, Some(&genesis), "genesis anchor");
    let mut b = next(&genesis);
    b.activation.authority_commit_reference = None;
    rejected(b, Some(&genesis), "activation reference");
    let mut b = body();
    b.genesis_hash = roster_hash(&b).unwrap();
    rejected(b, None, "bootstrap requires");
    rejected(update.body.clone(), None, "bootstrap requires");
    let mut other = update.clone();
    other.body.institution_id = InstitutionId::unchecked("institution-b");
    assert_ne!(other.namespace().unwrap(), update.namespace().unwrap());
    other = update.clone();
    other.body.environment_id = EnvironmentId::unchecked("mainnet");
    assert_ne!(other.namespace().unwrap(), update.namespace().unwrap());
    // Same concatenated strings must not collide with variable-length IDs.
    other.body.institution_id = InstitutionId::unchecked("a");
    other.body.environment_id = EnvironmentId::unchecked("bc");
    let mut collision = other.clone();
    collision.body.institution_id = InstitutionId::unchecked("ab");
    collision.body.environment_id = EnvironmentId::unchecked("c");
    assert_ne!(other.namespace().unwrap(), collision.namespace().unwrap());
}

#[test]
fn replacement_instances_need_new_generations_and_frames_need_exact_generation() {
    let old = sign(body());
    let participant = ParticipantId::unchecked("participant-0");
    assert!(old.accepts_generation(&participant, Epoch(7)));
    assert!(!old.accepts_generation(&participant, Epoch(6)));
    assert!(!old.accepts_generation(&participant, Epoch(8)));
    assert!(!old.accepts_generation(&ParticipantId::unchecked("outsider"), Epoch(7)));
    let mut b = next(&old);
    b.nodes[0].signer_instance_generation = Epoch(6);
    rejected(b, Some(&old), "generation regressed");
    let mut b = next(&old);
    b.nodes[0].transport_key = public(90);
    rejected(b.clone(), Some(&old), "newer generation");
    b.nodes[0].signer_instance_generation = Epoch(8);
    validate(&sign(b), Some(&old)).unwrap();
    let mut b = next(&old);
    b.nodes[0].participant_keys.insert(participant, public(91));
    rejected(b, Some(&old), "newer generation");
    let mut b = next(&old);
    let key = b.nodes[0].participant_keys.remove(&ParticipantId::unchecked("participant-0")).unwrap();
    b.nodes[0].participant_keys.insert(ParticipantId::unchecked("replacement"), key);
    let CommitteeKind::Key { participants, .. } = &mut b.committees[0].kind else { unreachable!() };
    participants[0] = ParticipantId::unchecked("replacement");
    rejected(b, Some(&old), "newer generation");
    let mut b = next(&old);
    b.nodes[0].address.set_port(9123);
    validate(&sign(b), Some(&old)).unwrap(); // signed address-only change need not refence
}

#[test]
fn duplicate_identities_and_cross_purpose_keys_are_rejected() {
    let mut b = body();
    b.nodes[1].node_id = b.nodes[0].node_id.clone();
    rejected(b, None, "duplicate nodes");
    let mut b = body();
    b.nodes[1].transport_key = b.nodes[0].transport_key.clone();
    rejected(b, None, "transport key reused");
    let mut b = body();
    b.nodes[0].transport_key = public(1);
    rejected(b, None, "transport key reused");
    let mut b = body();
    let reused = b.nodes[0].transport_key.clone();
    b.nodes[0].participant_keys.insert(ParticipantId::unchecked("extra"), reused);
    rejected(b, None, "participant key reused");
    let mut b = body();
    b.nodes[1].participant_keys = b.nodes[0].participant_keys.clone();
    rejected(b, None, "participant identity");
    let mut b = body();
    b.nodes[5].roles.push(Role::Signer);
    rejected(b, None, "must own participant keys");
    let mut b = body();
    b.nodes[3].roles.push(Role::Signer);
    b.nodes[3].participant_keys.insert(ParticipantId::unchecked("authority-share"), public(92));
    b.nodes[3].attestation_key = Some(public(93));
    rejected(b, None, "authority cannot hold shares");
}

#[test]
fn placement_counts_shares_not_nodes_and_checks_every_tolerated_domain_set() {
    let mut b = body();
    b.nodes[1].domain_id = b.nodes[0].domain_id.clone();
    rejected(b, None, "reconstruct a key");
    let mut b = body();
    b.nodes[3].domain_id = b.nodes[0].domain_id.clone();
    rejected(b, None, "separate trust domain");
    let mut b = body();
    b.tolerated_domain_compromises = 2;
    rejected(b.clone(), None, "reconstruct a key");
    b.committees[0].threshold = 3;
    validate(&sign(b), None).unwrap(); // two domains hold two shares, below t=3
    let mut b = body();
    b.nodes[0].participant_keys.insert(ParticipantId::unchecked("extra"), public(92));
    let CommitteeKind::Key { participants, .. } = &mut b.committees[0].kind else { unreachable!() };
    participants.push(ParticipantId::unchecked("extra"));
    rejected(b.clone(), None, "reconstruct a key");
    b.committees[0].threshold = 3;
    validate(&sign(b.clone()), None).unwrap(); // largest domain has two shares
    b.tolerated_domain_compromises = 2;
    rejected(b, None, "reconstruct a key"); // asymmetric 2+1 reaches t=3
    let mut b = body();
    let CommitteeKind::Key { backend, .. } = &mut b.committees[0].kind else { unreachable!() };
    backend.topology = ThresholdTopology::AllParticipants { participants: 3 };
    rejected(b, None, "requires all 3");
}

fn d2_body() -> RosterBody {
    let mut b = body();
    let mut replicas = vec![NodeId::unchecked("node-3")];
    for i in 8..=10 {
        let n = node(i, Role::Authority);
        b.trust_domains.push(TrustDomain {
            domain_id: n.domain_id.clone(),
            administrators: vec![CredentialId::unchecked("owner")],
            failure_domain_notes: "Independent root control".into(),
        });
        replicas.push(n.node_id.clone());
        b.nodes.push(n);
    }
    b.committees[1].kind = CommitteeKind::AuthorityD2 { faults: 1 };
    b.committees[1].members = replicas;
    b.committees[1].threshold = 3;
    for (index, node) in b.nodes.iter_mut().enumerate() {
        if b.committees[1].members.contains(&node.node_id) {
            node.consensus_key = Some(public(150 + index as u8));
        }
    }
    b.channel_acl.push(acl(1, &[Role::Authority], &[Role::Authority]));
    b.channel_acl.push(acl(2, &[Role::Authority], &[Role::Authority, Role::Signer]));
    b.channel_acl.push(acl(3, &[Role::Authority], &[Role::Authority]));
    b.channel_acl.push(acl(4, &[Role::Authority], &[Role::Authority, Role::Signer, Role::Witness]));
    b.channel_acl.push(acl(5, &[Role::Authority, Role::Signer], &[Role::Authority, Role::Signer]));
    b
}

#[test]
fn independent_signer_follows_certificates_and_requests_backfill_without_voting() {
    let signed = sign(d2_body());
    validate(&signed, None).unwrap();
    let replica = NodeId::unchecked("node-3");
    let signer = NodeId::unchecked("node-0");
    assert!(signed.node(&signer).unwrap().consensus_key.is_none());
    for channel in [2, 4, 5] {
        assert!(signed.allows(channel, &replica, &signer));
    }
    assert!(signed.allows(5, &signer, &replica));
    for channel in [1, 2, 3, 4] {
        assert!(!signed.allows(channel, &signer, &replica));
    }
    for channel in [1, 3] {
        assert!(!signed.allows(channel, &replica, &signer));
    }
    for outsider in ["node-4", "node-5", "node-6", "node-7"] {
        let outsider = NodeId::unchecked(outsider);
        assert!(!signed.allows(2, &replica, &outsider));
        assert!(!signed.allows(5, &outsider, &replica));
    }
    let mut narrower = d2_body();
    narrower.channel_acl.iter_mut().find(|acl| acl.channel == 5).unwrap().sender_roles = vec![Role::Authority];
    assert!(!sign(narrower).allows(5, &signer, &replica), "local ceiling cannot override signed narrower ACL");
}

#[test]
fn d2_checks_counts_and_compromise_bound_without_claiming_consensus() {
    let mut b = d2_body();
    b.nodes[3].domain_id = b.nodes[0].domain_id.clone();
    let signed = sign(b.clone());
    validate(&signed, None).unwrap();
    assert!(signed.allows(1, &NodeId::unchecked("node-3"), &NodeId::unchecked("node-8")));
    assert!(!signed.allows(1, &NodeId::unchecked("node-3"), &NodeId::unchecked("node-0")));
    assert!(signed.allows(4, &NodeId::unchecked("node-3"), &NodeId::unchecked("node-5")));
    assert!(!signed.allows(4, &NodeId::unchecked("node-5"), &NodeId::unchecked("node-3")));
    b.nodes[8].domain_id = b.nodes[3].domain_id.clone();
    rejected(b, None, "D2 fault bound");
    let mut b = d2_body();
    b.committees[1].threshold = 2;
    rejected(b, None, "n=3f+1");
    let mut b = d2_body();
    let removed = b.committees[1].members.pop().unwrap();
    b.nodes.iter_mut().find(|node| node.node_id == removed).unwrap().consensus_key = None;
    rejected(b, None, "n=3f+1");
}

#[test]
fn d2_vote_keys_are_roster_bound_and_separate_from_other_purposes() {
    let mut b = d2_body();
    b.nodes[3].consensus_key = None;
    rejected(b, None, "dedicated consensus keys");
    let mut b = d2_body();
    b.nodes[3].consensus_key = Some(b.nodes[3].transport_key.clone());
    rejected(b, None, "key purposes");
    let mut b = body();
    b.nodes[3].consensus_key = Some(public(150));
    rejected(b, None, "other nodes must not");
}

#[test]
fn channel_admission_intersects_roles_peer_class_committees_and_fixed_channel_ceiling() {
    let signed = sign(body());
    validate(&signed, None).unwrap();
    let id = |i| NodeId::unchecked(format!("node-{i}"));
    assert!(signed.allows(10, &id(4), &id(0))); // signer inherits verifier duties
    assert!(signed.allows(10, &id(7), &id(4)));
    assert!(signed.allows(11, &id(0), &id(3)));
    assert!(signed.allows(12, &id(4), &id(3)));
    assert!(signed.allows(20, &id(0), &id(1)));
    assert!(signed.allows(30, &id(0), &id(5)));
    assert!(signed.allows(1024, &id(6), &id(5)));
    assert!(!signed.allows(20, &id(6), &id(0)));
    assert!(!signed.allows(20, &id(0), &id(6)));
    assert!(!signed.allows(20, &id(4), &id(0)));
    assert!(!signed.allows(11, &id(3), &id(0)));
    assert!(!signed.allows(0, &id(5), &id(0)));
    assert!(!signed.allows(999, &id(0), &id(1)));
    assert!(!signed.allows(20, &id(99), &id(0)));
    let mut b = body();
    b.nodes[0].peer_class = PeerClass::Secondary;
    assert!(!sign(b.clone()).allows(20, &id(0), &id(1)));
    rejected(b, None, "must be primary");
    let mut b = body();
    b.channel_acl[4].sender_roles.push(Role::Extension);
    assert!(!sign(b.clone()).allows(20, &id(6), &id(0)));
    rejected(b, None, "extension is limited");
    let mut b = body();
    b.channel_acl.push(acl(999, &[Role::Signer], &[Role::Signer]));
    assert!(!sign(b.clone()).allows(999, &id(0), &id(1)));
    rejected(b, None, "unknown reserved");
    let mut b = body();
    b.committees.pop();
    assert!(!sign(b).allows(10, &id(7), &id(4))); // unenrolled verifier
    let mut b = body();
    b.nodes[6].peer_class = PeerClass::Primary;
    validate(&sign(b.clone()), None).unwrap();
    b.channel_acl[0].sender_roles.push(Role::Extension);
    assert!(!sign(b).allows(0, &id(6), &id(0)));
}

#[test]
fn recovery_is_online_only_for_ceremonies_and_cannot_use_signing_channel() {
    let mut b = body();
    b.nodes[0].roles = vec![Role::Recovery];
    b.nodes[0].attestation_key = None;
    rejected(b.clone(), None, "only in a ceremony roster");
    b.channel_acl[5].sender_roles.push(Role::Recovery);
    b.channel_acl[5].receiver_roles.push(Role::Recovery);
    let signed = sign(b);
    validate(&signed, None).unwrap();
    let recovery = NodeId::unchecked("node-0");
    let signer = NodeId::unchecked("node-1");
    assert!(signed.allows(21, &recovery, &signer));
    assert!(signed.allows(21, &signer, &recovery));
    assert!(!signed.allows(20, &recovery, &signer));
    assert!(!signed.allows(20, &signer, &recovery));
}
