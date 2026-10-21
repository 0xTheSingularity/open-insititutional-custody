use ed25519_dalek::{Signer, SigningKey};
use oic_authorization_state::*;
use oic_canonical_encoding::{canonical_bytes, value, Value};
use oic_domain_types::*;
use oic_membership::*;
use oic_peer_wire::{AuthorityReply, AuthorityRequest, AuthorityResult, FrameKind, PeerFrameV1, RosterState, WireError, HEADER_LEN, MAX_BODY_LEN};
use oic_policy_kernel::{intent_hash, policy_hash, Decision};
use oic_service_authority_rpc::*;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

const NOW: u64 = 1000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> PublicKey {
    PublicKey { scheme: SchemeId::Ed25519Pure, bytes: key(seed).verifying_key().to_bytes().to_vec().into() }
}

fn credential_signature(hash: Hash32) -> CredentialSignature {
    CredentialSignature { credential_id: CredentialId::unchecked("admin"), signature: signature(hash) }
}

fn signature(hash: Hash32) -> SignatureBytes {
    SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: key(1).sign(hash.as_ref()).to_bytes().to_vec().into() }
}

fn signed_roster(body: RosterBody) -> SignedRoster {
    let hash = roster_hash(&body).unwrap();
    let signed = SignedRoster { body, signatures: vec![credential_signature(hash)] };
    validate_roster(
        &signed,
        &AdminTrust { threshold: 1, credentials: BTreeMap::from([(CredentialId::unchecked("admin"), public(1))]) },
        &signed.body.institution_id,
        &signed.body.environment_id,
        None,
        UnixSeconds(NOW),
        hash,
    )
    .unwrap();
    signed
}

fn node_id(id: &str) -> NodeId {
    NodeId::unchecked(id)
}

fn roster() -> SignedRoster {
    let nodes = [("gateway", Role::Gateway), ("authority", Role::Authority), ("witness", Role::Witness)]
        .into_iter()
        .enumerate()
        .map(|(i, (id, role))| Node {
            node_id: node_id(id),
            domain_id: TrustDomainId::unchecked(id),
            roles: vec![role],
            transport_key: public(10 + i as u8),
            attestation_key: None,
            address: format!("127.0.0.1:{}", 9010 + i).parse().unwrap(),
            peer_class: if role == Role::Witness { PeerClass::Secondary } else { PeerClass::Primary },
            participant_keys: BTreeMap::new(),
            approved_build_hashes: vec![],
            signer_instance_generation: Epoch(0),
        })
        .collect::<Vec<_>>();
    signed_roster(RosterBody {
        institution_id: InstitutionId::unchecked("institution"),
        environment_id: EnvironmentId::unchecked("testnet"),
        roster_epoch: 0,
        previous_roster_hash: Hash32::ZERO,
        genesis_hash: Hash32::ZERO,
        commonware_release: COMMONWARE_RELEASE.into(),
        wire_version: WIRE_VERSION,
        trust_domains: nodes
            .iter()
            .map(|node| TrustDomain {
                domain_id: node.domain_id.clone(),
                administrators: vec![CredentialId::unchecked("domain-owner")],
                failure_domain_notes: "Separate IAM, hardware, image, backup and recovery".into(),
            })
            .collect(),
        nodes,
        committees: vec![Committee {
            committee_id: CommitteeId::unchecked("d1"),
            kind: CommitteeKind::AuthorityD1,
            members: vec![node_id("authority")],
            threshold: 1,
        }],
        channel_acl: vec![ChannelSpec {
            channel: 12,
            sender_roles: vec![Role::Gateway, Role::Authority],
            receiver_roles: vec![Role::Gateway, Role::Authority],
            max_message_size: 8192,
            quota: 10,
        }],
        tolerated_domain_compromises: 1,
        activation: Activation { not_before: UnixSeconds(NOW), authority_commit_reference: None },
    })
}

struct Env {
    authority: Authority<InMemoryAuthorityStore>,
    clock: Arc<ManualClock>,
    store: Arc<InMemoryAuthorityStore>,
    roster: SignedRoster,
}

impl Env {
    fn new() -> Self {
        let roster = roster();
        let clock = Arc::new(ManualClock::new(NOW));
        let store = Arc::new(InMemoryAuthorityStore::new());
        let authority = Authority::open(
            store.clone(),
            0,
            AuthorityConfig {
                institution_id: roster.body.institution_id.clone(),
                environment_id: roster.body.environment_id.clone(),
                authority_key_id: KeyId::unchecked("authority-key"),
                admin_keys: vec![(CredentialId::unchecked("admin"), key(1).verifying_key())],
                admin_quorum: 1,
                freeze_responders: vec![(CredentialId::unchecked("admin"), key(1).verifying_key())],
                release_receipt_ttl_seconds: 60,
                max_clock_skew_seconds: 10,
            },
            key(42),
            clock.clone(),
        )
        .unwrap();
        let mut policy = PolicyBundle {
            policy_id: PolicyId::unchecked("policy"),
            policy_epoch: Epoch(3),
            institution_id: roster.body.institution_id.clone(),
            environment_id: roster.body.environment_id.clone(),
            rules: vec![PolicyRule {
                rule_id: "rule".into(),
                vaults: vec![VaultId::unchecked("vault")],
                assets: vec![AssetId::unchecked("asset")],
                destinations: vec![],
                purposes: vec![],
                max_amount_per_operation: Amount(100),
                max_native_fee_per_operation: Amount(10),
                rolling_limits: vec![ExposureLimit { window_seconds: 600, max_outflow_base_units: Amount(200) }],
                required_approvals: 0,
                approval_roles: vec![],
                exclude_proposer: false,
                operating_window: None,
            }],
            denied_destinations: vec![],
            denied_assets: vec![],
            max_evidence_age_seconds: 60,
            allowlist_version: 1,
            activation_epoch: Epoch(3),
            administrative_signatures: vec![],
        };
        policy.administrative_signatures = vec![credential_signature(policy_hash(&policy).unwrap())];
        authority.set_policy(&policy).unwrap();
        Self { authority, clock, store, roster }
    }

    fn request(&self, n: u64) -> ReserveRequest {
        let intent = Intent {
            schema_version: 1,
            intent_id: IntentId::unchecked(format!("intent-{n}")),
            institution_id: self.roster.body.institution_id.clone(),
            environment_id: self.roster.body.environment_id.clone(),
            vault_id: VaultId::unchecked("vault"),
            chain_wallet_id: ChainWalletId::unchecked("wallet"),
            chain_profile_id: ChainProfileId::unchecked("profile"),
            operation: IntentOperation::AssetTransfer {
                asset_id: AssetId::unchecked("asset"),
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
            external_reference: format!("reference-{n}"),
            proposer_credential_id: CredentialId::unchecked("proposer"),
            created_at: UnixSeconds(NOW),
        };
        let registered = self
            .authority
            .register_intent(
                &intent,
                intent_hash(&intent).unwrap(),
                IdempotencyKey { institution_id: intent.institution_id.clone(), route: "register".into(), key: format!("idempotency-{n}") },
            )
            .unwrap();
        let (policy_epoch, policy_hash) = self.authority.current_policy().unwrap();
        ReserveRequest {
            family_id: registered.operation_family_id,
            candidate_id: CandidateId::unchecked(format!("candidate-{n}")),
            candidate_revision: 2,
            vault_id: intent.vault_id,
            intent_id: intent.intent_id,
            policy_epoch,
            policy_hash,
            claims: ResourceClaims {
                resources: vec![NativeResource::EvmNonce { network_id: NetworkId::unchecked("network"), sender: Bytes(vec![7; 20]), nonce: n }],
                asset_outflows: vec![AssetOutflow { asset_id: AssetId::unchecked("asset"), amount_base_units: Amount(60) }],
                native_fees: vec![],
            },
            grants: vec![],
            envelope_body_hash: Hash32([n as u8; 32]),
            signer_session_id: SigningSessionId::unchecked(format!("session-{n}")),
            issuance_deadline: UnixSeconds(NOW + 300),
            policy_decision: Decision::Allow { rule_id: "rule".into() },
            exposure_limits: vec![(AssetId::unchecked("asset"), ExposureLimit { window_seconds: 600, max_outflow_base_units: Amount(200) })],
        }
    }

    fn release(&self, request: &ReserveRequest) -> ReleaseRequest {
        ReleaseRequest {
            reservation_id: reservation_id_for(&request.family_id, &request.candidate_id, request.candidate_revision).unwrap(),
            reservation_version: 1,
            envelope_body_hash: request.envelope_body_hash,
            signer_session_id: request.signer_session_id.clone(),
            expected_policy_epoch: request.policy_epoch,
            freshness: FreshnessContext { now: self.clock.now() },
        }
    }

    fn server(&self) -> AuthorityRpcServer<'_, InMemoryAuthorityStore> {
        AuthorityRpcServer::new(&self.authority, &self.roster, &node_id("authority")).unwrap()
    }

    fn freeze(&self) {
        let proposal = FreezeProposal::new(
            self.roster.body.institution_id.clone(),
            self.roster.body.environment_id.clone(),
            FreezeScope::Global,
            CredentialId::unchecked("admin"),
            "incident",
        );
        self.authority.freeze(FreezeScope::Global, proposal.by.clone(), "incident", &signature(proposal.hash().unwrap())).unwrap();
    }
}

struct Loopback<'a> {
    server: AuthorityRpcServer<'a, InMemoryAuthorityStore>,
    fault: Option<Fault>,
    sent: Arc<AtomicUsize>,
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    DropAfterCommit,
    WrongId,
    WrongResult,
    Malformed,
    Unavailable,
}

impl AuthorityRpcTransport for Loopback<'_> {
    fn request(&self, authority: &NodeId, request_id: u64, frame: Vec<u8>) -> OicResult<Vec<u8>> {
        assert_eq!(authority, &node_id("authority"));
        self.sent.fetch_add(1, Ordering::SeqCst);
        let request = AuthorityRequest::decode(&frame, 0, MAX_BODY_LEN).unwrap();
        assert_eq!(request.request_id(), request_id);
        let reply = self.server.handle(&node_id("gateway"), &frame)?;
        if matches!(request, AuthorityRequest::Release { .. }) {
            match self.fault {
                Some(Fault::DropAfterCommit) => return Err(OicError::new(ErrorCode::AuthorityUnavailable, "timeout after commit")),
                Some(Fault::Malformed) => return Ok(vec![0]),
                Some(fault) => {
                    let mut reply = AuthorityReply::decode(&reply, 0, MAX_BODY_LEN).unwrap();
                    match fault {
                        Fault::WrongId => reply.request_id += 1,
                        Fault::WrongResult => reply.result = Ok(AuthorityResult::Aborted { commit_sequence: 1 }),
                        Fault::Unavailable => reply.result = Err(OicError::new(ErrorCode::AuthorityUnavailable, "backend unavailable")),
                        _ => unreachable!(),
                    }
                    return Ok(reply.encode(0, MAX_BODY_LEN).unwrap());
                }
                None => {}
            }
        }
        Ok(reply)
    }
}

fn client(env: &Env, fault: Option<Fault>, sent: Arc<AtomicUsize>) -> AuthorityRpcClient<Loopback<'_>> {
    AuthorityRpcClient::new(Loopback { server: env.server(), fault, sent }, &env.roster, &node_id("gateway"), &node_id("authority")).unwrap()
}

#[test]
fn rebuilt_clients_sharing_transport_never_reuse_ids_or_accept_a_late_reply() {
    #[derive(Clone, Default)]
    struct SharedTransport(Arc<Mutex<Vec<AuthorityReply>>>);

    impl AuthorityRpcTransport for SharedTransport {
        fn request(&self, _: &NodeId, request_id: u64, frame: Vec<u8>) -> OicResult<Vec<u8>> {
            assert_eq!(AuthorityRequest::decode(&frame, 0, MAX_BODY_LEN).unwrap().request_id(), request_id);
            let mut replies = self.0.lock().unwrap();
            replies.push(AuthorityReply { request_id, result: Ok(AuthorityResult::Aborted { commit_sequence: 77 }) });
            // Deliver the old client's delayed reply to the newly built client.
            let reply = if replies.len() == 2 { &replies[0] } else { replies.last().unwrap() };
            Ok(reply.encode(0, MAX_BODY_LEN).unwrap())
        }
    }

    let roster = roster();
    let transport = SharedTransport::default();
    let first = AuthorityRpcClient::new(transport.clone(), &roster, &node_id("gateway"), &node_id("authority")).unwrap();
    let reservation = ReservationId::unchecked("reservation");
    assert_eq!(first.abort_before_issuance(&reservation).unwrap(), 77);
    drop(first);
    let rebuilt = AuthorityRpcClient::new(transport.clone(), &roster, &node_id("gateway"), &node_id("authority")).unwrap();
    assert_eq!(rebuilt.abort_before_issuance(&reservation).unwrap_err().code, ErrorCode::AuthorityUnavailable);
    assert_eq!(rebuilt.abort_before_issuance(&reservation).unwrap(), 77);
    let replies = transport.0.lock().unwrap();
    assert_eq!(replies.len(), 3);
    assert!(replies.windows(2).all(|pair| pair[0].request_id < pair[1].request_id));
}

#[test]
fn handler_rejects_non_gateways_wrong_epoch_and_denied_reply_acl_before_mutation() {
    let env = Env::new();
    let request = AuthorityRequest::Reserve { request_id: 19, request: env.request(1) };
    let frame = request.encode(0, MAX_BODY_LEN).unwrap();
    let before = env.store.snapshot();
    for sender in ["witness", "authority", "unknown"] {
        assert_eq!(env.server().handle(&node_id(sender), &frame).unwrap_err().code, ErrorCode::PeerNotAdmitted);
    }
    assert_eq!(env.server().handle(&node_id("gateway"), &request.encode(1, MAX_BODY_LEN).unwrap()).unwrap_err().code, ErrorCode::InvalidRequest);
    let mut body = env.roster.body.clone();
    body.channel_acl[0].sender_roles = vec![Role::Gateway]; // request admitted, reply denied
    let roster = signed_roster(body);
    let server = AuthorityRpcServer::new(&env.authority, &roster, &node_id("authority")).unwrap();
    assert_eq!(server.handle(&node_id("gateway"), &frame).unwrap_err().code, ErrorCode::PeerNotAdmitted);
    assert_eq!(env.store.snapshot(), before);
    let mut body = env.roster.body.clone();
    body.environment_id = EnvironmentId::unchecked("production");
    let roster = signed_roster(body);
    assert_eq!(AuthorityRpcServer::new(&env.authority, &roster, &node_id("authority")).err().unwrap().code, ErrorCode::ScopeMismatch);
}

#[test]
fn server_rejects_receipt_key_reuse_for_enrolled_node_or_administrative_purposes() {
    let env = Env::new();
    assert!(AuthorityRpcServer::new(&env.authority, &env.roster, &node_id("authority")).is_ok());
    let receipt_key = PublicKey { scheme: SchemeId::Ed25519Pure, bytes: env.authority.verifying_key().to_bytes().to_vec().into() };
    for purpose in ["transport", "participant", "attestation", "admin", "freeze_responder"] {
        let mut body = env.roster.body.clone();
        let mut config = env.authority.config().clone();
        match purpose {
            "transport" => body.nodes[0].transport_key = receipt_key.clone(),
            "participant" => {
                body.nodes[0].roles.push(Role::Signer);
                body.nodes[0].participant_keys.insert(ParticipantId::unchecked("participant"), receipt_key.clone());
                body.nodes[0].attestation_key = Some(public(20));
                body.nodes[0].approved_build_hashes = vec![Hash32([21; 32])];
            }
            "attestation" => {
                body.nodes[0].roles.push(Role::Verifier);
                body.nodes[0].attestation_key = Some(receipt_key.clone());
                body.nodes[0].approved_build_hashes = vec![Hash32([21; 32])];
            }
            "admin" => config.admin_keys.push((CredentialId::unchecked("other-admin"), env.authority.verifying_key())),
            "freeze_responder" => config.freeze_responders.push((CredentialId::unchecked("other-responder"), env.authority.verifying_key())),
            _ => unreachable!(),
        }
        // Each roster still passes its independent membership validation:
        // only the authority knows which key actually signs its receipts.
        let roster = signed_roster(body);
        let store = Arc::new(InMemoryAuthorityStore::new());
        let authority = Authority::open(store.clone(), 0, config, key(42), env.clock.clone()).unwrap();
        let before = store.snapshot();
        let error = AuthorityRpcServer::new(&authority, &roster, &node_id("authority")).err().expect(purpose);
        assert_eq!(error.code, ErrorCode::InvalidRequest, "{purpose}");
        assert_eq!(store.snapshot(), before);
    }
}

#[test]
fn actual_reserve_release_freeze_and_abort_semantics_survive_wire_codec() {
    let env = Env::new();
    let endpoint = client(&env, None, Arc::default());
    let request = env.request(1);
    let (reservation, reserved) = endpoint.reserve(request.clone()).unwrap();
    assert_eq!(reservation.claims, request.claims);
    assert_eq!(reservation.candidate_revision, 2);
    let mut expected = ReceiptExpectation {
        kind: ReceiptKind::Reserved,
        envelope_body_hash: request.envelope_body_hash,
        signer_session_id: request.signer_session_id.clone(),
        candidate_id: request.candidate_id.clone(),
        candidate_revision: 2,
        now: UnixSeconds(NOW),
        policy_epoch: request.policy_epoch,
    };
    verify_receipt(&reserved, &env.authority.verifying_key(), &expected).unwrap();
    let mut release = env.release(&request);
    release.expected_policy_epoch = Epoch(2);
    assert_eq!(endpoint.release(release).unwrap_err().code, ErrorCode::StalePolicy);
    let mut release = env.release(&request);
    release.freshness.now = UnixSeconds(NOW - 11);
    assert_eq!(endpoint.release(release).unwrap_err().code, ErrorCode::StaleEvidence);
    let release = env.release(&request);
    let (receipt, issuance) = endpoint.release(release.clone()).unwrap();
    expected.kind = ReceiptKind::Release;
    verify_receipt(&receipt, &env.authority.verifying_key(), &expected).unwrap();
    assert_eq!(issuance.envelope_hash, request.envelope_body_hash);
    assert_eq!(issuance.signer_session_id, request.signer_session_id);
    assert_eq!(issuance.commit_sequence, receipt.body.commit_sequence);

    let never_released = env.request(2);
    let (pending, _) = endpoint.reserve(never_released.clone()).unwrap();
    env.freeze();
    env.clock.advance(1);
    let before = env.store.snapshot();
    assert_eq!(endpoint.release(env.release(&never_released)).unwrap_err().code, ErrorCode::Frozen);
    assert_eq!(endpoint.reserve(env.request(3)).unwrap_err().code, ErrorCode::Frozen);
    let (fresh_receipt, same_issuance) = endpoint.release(release).unwrap();
    assert_eq!(same_issuance, issuance); // existing release precedes freeze/freshness rechecks
    assert_eq!(fresh_receipt.body.issued_at, UnixSeconds(NOW + 1));
    assert_eq!(env.store.snapshot().issuance, before.issuance);
    assert_eq!(endpoint.abort_before_issuance(&reservation.reservation_id).unwrap_err().code, ErrorCode::IssuanceUncertain);
    let sequence = endpoint.abort_before_issuance(&pending.reservation_id).unwrap();
    assert_eq!(sequence, env.store.snapshot().commit_sequence);
    assert_eq!(env.authority.reservation(&pending.reservation_id).unwrap().state, ReservationState::Aborted { reason: AbortReason::BeforeIssuance });
}

#[test]
fn release_with_lost_invalid_or_uncorrelated_reply_is_uncertain_and_never_retried() {
    for fault in [Fault::DropAfterCommit, Fault::WrongId, Fault::WrongResult, Fault::Malformed, Fault::Unavailable] {
        let env = Env::new();
        let sent = Arc::<AtomicUsize>::default();
        let endpoint = client(&env, Some(fault), sent.clone());
        let request = env.request(1);
        let (reservation, _) = endpoint.reserve(request.clone()).unwrap();
        assert_eq!(endpoint.release(env.release(&request)).unwrap_err().code, ErrorCode::IssuanceUncertain, "{fault:?}");
        assert_eq!(sent.load(Ordering::SeqCst), 2, "reserve and exactly one release: {fault:?}");
        assert_eq!(env.store.snapshot().issuance.len(), 1);
        assert_eq!(endpoint.abort_before_issuance(&reservation.reservation_id).unwrap_err().code, ErrorCode::IssuanceUncertain);
        assert_eq!(env.store.snapshot().issuance.len(), 1);
    }
}

#[test]
fn authority_frames_are_bounded_strictly_typed_and_redacted() {
    let env = Env::new();
    let request = AuthorityRequest::Reserve { request_id: 37, request: env.request(1) };
    let frame = request.encode(0, MAX_BODY_LEN).unwrap();
    assert_eq!(AuthorityRequest::decode(&frame, 0, MAX_BODY_LEN).unwrap(), request);
    assert_eq!(AuthorityRequest::decode(&frame, 1, MAX_BODY_LEN), Err(WireError::UnexpectedEpoch));
    assert_eq!(request.encode(0, frame.len() - HEADER_LEN - 1), Err(WireError::TooLarge));
    assert_eq!(PeerFrameV1::encode_confidential(&request, 0, FrameKind::Content, MAX_BODY_LEN), Err(WireError::WrongCarrier));
    assert_eq!(
        PeerFrameV1::encode_public(&RosterState { roster_epoch: 0, roster_hash: Hash32::ZERO }, 0, FrameKind::AuthorityRpc, MAX_BODY_LEN),
        Err(WireError::WrongCarrier)
    );
    let reply = AuthorityReply { request_id: 37, result: Err(OicError::invalid_request("secret policy contents")) };
    assert_eq!(format!("{request:?}"), "AuthorityRequest([REDACTED])");
    assert_eq!(format!("{reply:?}"), "AuthorityReply([REDACTED])");
    assert_eq!(format!("{:?}", AuthorityResult::Aborted { commit_sequence: 123 }), "AuthorityResult([REDACTED])");

    // Unknown nested request fields cannot be silently dropped by remote serde.
    let Value::Map(mut outer) = value::decode(&canonical_bytes(&request).unwrap()).unwrap() else { panic!("request map") };
    let (_, (_, Value::Map(ref mut fields))) = outer.iter_mut().next().unwrap() else { panic!("variant fields") };
    let (_, (_, Value::Map(ref mut native))) = fields.iter_mut().find(|(_, (k, _))| *k == Value::Text("request".into())).unwrap() else {
        panic!("native fields")
    };
    let unknown = Value::Text("unreviewed".into());
    native.insert(value::encode(&unknown), (unknown, Value::Bool(true)));
    let body = value::encode(&Value::Map(outer));
    let mut invalid = frame[..HEADER_LEN].to_vec();
    invalid[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
    invalid.extend_from_slice(&body);
    assert_eq!(AuthorityRequest::decode(&invalid, 0, MAX_BODY_LEN), Err(WireError::InvalidBody));
    let before = env.store.snapshot();
    assert_eq!(env.server().handle(&node_id("gateway"), &invalid).unwrap_err().code, ErrorCode::InvalidRequest);
    assert_eq!(env.store.snapshot(), before);
}
