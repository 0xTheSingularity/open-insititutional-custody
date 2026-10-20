//! Coordinator end to end against the real authority, real signers, real
//! backends, and the chain simulators, plus adversarial cases.

mod common;

use common::*;
use ed25519_dalek::{Signer as _, SigningKey};
use oic_authorization_state::{receipt_hash, reservation_id_for, AbortReason, InMemoryAuthorityStore, ReservationState};
use oic_chain_simulator::solana::SolanaTxStatus;
use oic_crypto_provider::{PeerMessage, ProtocolStep};
use oic_domain_types::*;
use oic_policy_kernel::Decision;
use oic_service_coordinator::*;
use oic_signer::{envelope_body_hash, SigningMaterials};
use std::sync::{Arc, Mutex};

fn code<T: std::fmt::Debug>(r: OicResult<T>) -> ErrorCode {
    r.expect_err("expected an error").code
}

fn signed_policy(world: &World, asset: &Asset, required: u8, limit: u128) -> PolicyBundle {
    world.sign_policy(policy(1, vec![rule(&asset.asset_id, required, limit)]))
}

fn states(store: &dyn OperationStore, family: &OperationFamilyId) -> Vec<LifecycleState> {
    store.transitions(family).iter().map(|t| t.state).collect()
}

fn mem_store() -> Arc<InMemoryOperationStore> {
    Arc::new(InMemoryOperationStore::new())
}

/// Endpoint wrapper that forwards everything to `inner`, with optional
/// misbehaviour injected at `open_session` and `release`.
struct Wrapped {
    inner: Arc<dyn SignerEndpoint>,
    tamper_open: bool,
    fail_release: bool,
    /// Receipts tried (and expected to be refused) before the real one.
    foreign: Vec<AuthorityReceipt>,
    /// Authority key used to forge a receipt for another session.
    forger: Option<SigningKey>,
    log: Mutex<Vec<(String, Result<Vec<ProtocolStep>, ErrorCode>)>>,
    passed: Mutex<Vec<AuthorityReceipt>>,
}

impl Wrapped {
    fn new(inner: Arc<dyn SignerEndpoint>) -> Wrapped {
        Wrapped { inner, tamper_open: false, fail_release: false, foreign: vec![], forger: None, log: Mutex::new(vec![]), passed: Mutex::new(vec![]) }
    }
}

impl SignerEndpoint for Wrapped {
    fn participant_id(&self) -> ParticipantId {
        self.inner.participant_id()
    }
    fn generation(&self) -> Epoch {
        self.inner.generation()
    }
    fn open_session(&self, envelope: &AuthorizationEnvelope, materials: &SigningMaterials, now: UnixSeconds) -> OicResult<ProtocolStep> {
        if self.tamper_open {
            // A compromised coordinator alters the approved native bytes on the
            // way to this signer (candidate and envelope consistently).
            let mut env = envelope.clone();
            let mut m = materials.clone();
            let last = env.body.native_unsigned_bytes.0.len() - 1;
            env.body.native_unsigned_bytes.0[last] ^= 1;
            m.candidate.native_unsigned_bytes = env.body.native_unsigned_bytes.clone();
            return self.inner.open_session(&env, &m, now);
        }
        self.inner.open_session(envelope, materials, now)
    }
    fn receive(&self, session_id: &SigningSessionId, message: &PeerMessage) -> OicResult<ProtocolStep> {
        self.inner.receive(session_id, message)
    }
    fn release(&self, session_id: &SigningSessionId, release_receipt: &AuthorityReceipt, now: UnixSeconds) -> OicResult<Vec<ProtocolStep>> {
        self.passed.lock().unwrap().push(release_receipt.clone());
        let mut tries: Vec<(String, AuthorityReceipt)> = self.foreign.iter().map(|r| ("foreign".to_string(), r.clone())).collect();
        if let Some(sk) = &self.forger {
            let mut body = release_receipt.body.clone();
            body.signer_session_id = SigningSessionId::unchecked("sess-other");
            let h = receipt_hash(&body).unwrap();
            let forged = AuthorityReceipt {
                body,
                authority_key_id: release_receipt.authority_key_id.clone(),
                signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(sk.sign(&h.0).to_bytes().to_vec()) },
            };
            tries.push(("other-session".to_string(), forged));
        }
        for (what, r) in tries {
            let res = self.inner.release(session_id, &r, now).map_err(|e| e.code);
            self.log.lock().unwrap().push((what, res));
        }
        if self.fail_release {
            return Err(OicError::new(ErrorCode::AuthorityUnavailable, "signer unreachable after release"));
        }
        self.inner.release(session_id, release_receipt, now)
    }
    fn aggregate(&self, session_id: &SigningSessionId, shares: &[(ParticipantId, Bytes)]) -> OicResult<SignatureBytes> {
        self.inner.aggregate(session_id, shares)
    }
    fn abort(&self, session_id: &SigningSessionId) -> OicResult<()> {
        self.inner.abort(session_id)
    }
}

#[test]
fn evm_erc20_end_to_end_signs_and_mines_in_the_simulator() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10u128.pow(16), ApprovalMode::ExactCandidate);
    world.register(&pol, &intent);
    let store = mem_store();
    let coord = coordinator(&world, c, in_process(&c.nodes), store.clone());
    let j = job(&world, c, &pol, &intent, "cand-1", 1, vec![pid(1)]);
    let family = j.built.candidate.operation_family_id.clone();
    let iss = coord.execute(j).unwrap();

    assert_eq!(iss.envelope.authorization_state_receipt.body.kind, ReceiptKind::Reserved);
    assert_eq!(iss.release_receipt.body.kind, ReceiptKind::Release);
    let ebh = envelope_body_hash(&iss.envelope.body).unwrap();
    assert_eq!(iss.issuance_record.envelope_hash, ebh);
    assert_eq!(iss.release_receipt.body.envelope_body_hash, ebh);
    assert!(iss.envelope.body.signer_session_id.as_str().starts_with("sess-"));

    let id = evm.sim.submit(iss.signed.signed.signed_bytes.as_slice()).unwrap();
    assert_eq!(id, iss.signed.signed.chain_tx_id);
    evm.sim.mine().unwrap();
    let receipt = evm.sim.receipt(&id).unwrap().expect("mined");
    assert!(receipt.success);
    assert_eq!(evm.sim.erc20_balance(&evm.token, &[0xde; 20]).unwrap(), 1_000_000);

    assert_eq!(
        states(store.as_ref(), &family),
        vec![LifecycleState::Reserved, LifecycleState::Authorized, LifecycleState::IssuanceCommitted, LifecycleState::SignatureObserved]
    );
    let rec = store.operation(&family).unwrap();
    assert_eq!(rec.lifecycle, LifecycleState::SignatureObserved);
    assert_eq!(rec.signed_tx_id, Some(id));
    assert_eq!(rec.issuance_id, Some(iss.issuance_record.issuance_id.clone()));
    assert_eq!(rec.session_id, Some(iss.envelope.body.signer_session_id.clone()));
    assert_eq!(rec.envelope_body_hash, Some(ebh));
    let rid = iss.envelope.body.budget_reservation_id.clone();
    assert_eq!(rec.reservation_id, Some(rid.clone()));
    assert!(matches!(world.authority.reservation(&rid).unwrap().state, ReservationState::Released { .. }));
    assert_eq!(outstanding(&world, &c.asset.asset_id), Amount(1_000_000), "exposure stays outstanding until finality");
    assert_eq!(c.nodes[0].shares_produced(), 1);
}

#[test]
fn solana_frost_2_of_3_end_to_end_for_every_signing_pair() {
    for set in [[1u8, 2], [2, 3], [1, 3]] {
        let world = World::new();
        let sol = sol_chain(&world, false);
        let c = &sol.chain;
        let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
        let intent = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
        world.register(&pol, &intent);
        let store = mem_store();
        let coord = coordinator(&world, c, in_process(&c.nodes), store.clone());
        let participants: Vec<ParticipantId> = set.iter().map(|n| pid(*n)).collect();
        let j = job(&world, c, &pol, &intent, "cand-1", 1, participants.clone());
        let family = j.built.candidate.operation_family_id.clone();
        let iss = coord.execute(j).unwrap_or_else(|e| panic!("{set:?}: {e}"));
        assert_eq!(iss.envelope.body.participant_set, participants);

        let id = sol.sim.submit(iss.signed.signed.signed_bytes.as_slice()).unwrap();
        sol.sim.advance_slots(2).unwrap();
        match sol.sim.tx_status(&id).unwrap() {
            Some(SolanaTxStatus::Included { success: true, .. }) => {}
            other => panic!("{set:?}: {other:?}"),
        }
        assert_eq!(sol.sim.lamports(&sol_dest_owner()), 1_000_000);
        for n in &c.nodes {
            let expected = usize::from(participants.contains(&n.id));
            assert_eq!(n.shares_produced(), expected, "{set:?} {}", n.id);
        }
        assert_eq!(store.lifecycle(&family), LifecycleState::SignatureObserved);
    }
}

#[test]
fn solana_bounded_template_end_to_end() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 2_500_000, 10_000_000, ApprovalMode::BoundedDirectTransfer);
    world.register(&pol, &intent);
    let coord = coordinator(&world, c, in_process(&c.nodes), mem_store());
    let j = job(&world, c, &pol, &intent, "cand-1", 1, vec![pid(1), pid(3)]);
    let template = j.built.template.clone().expect("template");
    assert!(j.evaluation.decision.is_allow(), "{:?}", j.evaluation.decision);
    let iss = coord.execute(j).unwrap();
    assert!(matches!(&iss.envelope.body.approval_grants[0].body.scope, GrantScope::BoundedDirectTransfer { template: t } if *t == template));
    let id = sol.sim.submit(iss.signed.signed.signed_bytes.as_slice()).unwrap();
    sol.sim.advance_slot().unwrap();
    assert!(matches!(sol.sim.tx_status(&id).unwrap(), Some(SolanaTxStatus::Included { success: true, .. })));
    assert_eq!(sol.sim.lamports(&sol_dest_owner()), 2_500_000);
}

#[test]
fn a_native_bytes_altered_after_approval_abort_before_issuance_and_release_exposure() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    world.register(&pol, &intent);
    let mut eps = in_process(&c.nodes);
    let mut tamper = Wrapped::new(eps[1].clone());
    tamper.tamper_open = true;
    eps[1] = Arc::new(tamper);
    let store = mem_store();
    let coord = coordinator(&world, c, eps, store.clone());
    let j = job(&world, c, &pol, &intent, "cand-1", 1, vec![pid(1), pid(2)]);
    let family = j.built.candidate.operation_family_id.clone();
    let rid = reservation_id_for(&family, &j.built.candidate.candidate_id, 1).unwrap();

    assert_eq!(code(coord.execute(j)), ErrorCode::UnverifiableTransaction);
    assert_eq!(store.lifecycle(&family), LifecycleState::AbortedBeforeIssuance);
    assert_eq!(states(store.as_ref(), &family), vec![LifecycleState::Reserved, LifecycleState::AbortedBeforeIssuance]);
    let rec = store.operation(&family).unwrap();
    assert_eq!(rec.last_error.unwrap().code, ErrorCode::UnverifiableTransaction);
    assert_eq!(world.authority.reservation(&rid).unwrap().state, ReservationState::Aborted { reason: AbortReason::BeforeIssuance });
    assert_eq!(outstanding(&world, &c.asset.asset_id), Amount::ZERO, "exposure released");
    let session = rec.session_id.unwrap();
    assert!(c.nodes[0].aborted(&session), "the honest signer's opened session was aborted");
    assert!(c.nodes.iter().all(|n| n.shares_produced() == 0), "no share anywhere");
}

#[test]
fn b_signer_failing_after_release_leaves_issuance_unknown_and_exposure_retained() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    world.register(&pol, &intent);
    let mut eps = in_process(&c.nodes);
    let mut failing = Wrapped::new(eps[1].clone());
    failing.fail_release = true;
    eps[1] = Arc::new(failing);
    let store = mem_store();
    let coord = coordinator(&world, c, eps, store.clone());
    let j = job(&world, c, &pol, &intent, "cand-1", 1, vec![pid(1), pid(2)]);
    let family = j.built.candidate.operation_family_id.clone();
    let rid = reservation_id_for(&family, &j.built.candidate.candidate_id, 1).unwrap();

    let err = coord.execute(j).unwrap_err();
    assert_eq!(err.code, ErrorCode::IssuanceUncertain);
    let rec = store.operation(&family).unwrap();
    let session = rec.session_id.clone().unwrap();
    assert!(err.detail.contains(rid.as_str()) && err.detail.contains(session.as_str()), "{}", err.detail);
    assert_eq!(rec.lifecycle, LifecycleState::IssuanceUnknown);
    assert_eq!(
        states(store.as_ref(), &family),
        vec![LifecycleState::Reserved, LifecycleState::Authorized, LifecycleState::IssuanceCommitted, LifecycleState::IssuanceUnknown]
    );
    assert_eq!(rec.last_error.unwrap().code, ErrorCode::AuthorityUnavailable);
    // Not aborted: the reservation is still the released (possibly issued) one.
    let state = world.authority.reservation(&rid).unwrap().state;
    assert!(matches!(state, ReservationState::Released { .. }), "{state:?}");
    assert_eq!(outstanding(&world, &c.asset.asset_id), Amount(1_000_000), "exposure retained");
    assert_eq!(c.nodes[0].shares_produced(), 1, "the honest signer did release its share");
}

#[test]
fn c_two_jobs_within_limit_alone_exceed_it_together_and_the_second_fails_at_reserve() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 1_500_000);
    let i1 = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    let i2 = c.intent("intent-2", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    world.register(&pol, &i1);
    world.register(&pol, &i2);
    let store = mem_store();
    let coord = coordinator(&world, c, in_process(&c.nodes), store.clone());
    // Both evaluated against the same (empty) exposure: each fits alone.
    let j1 = job(&world, c, &pol, &i1, "cand-1", 1, vec![pid(1), pid(2)]);
    sol.sim.advance_slot().unwrap();
    let j2 = job(&world, c, &pol, &i2, "cand-2", 1, vec![pid(1), pid(2)]);
    assert!(j1.evaluation.decision.is_allow() && j2.evaluation.decision.is_allow());
    let f2 = j2.built.candidate.operation_family_id.clone();
    let rid2 = reservation_id_for(&f2, &j2.built.candidate.candidate_id, 1).unwrap();

    coord.execute(j1).unwrap();
    let err = coord.execute(j2).unwrap_err();
    assert_eq!(err.code, ErrorCode::BudgetExceeded, "{err}");
    assert_eq!(store.lifecycle(&f2), LifecycleState::Rejected);
    assert_eq!(code(world.authority.reservation(&rid2)), ErrorCode::NotFound);
    assert_eq!(outstanding(&world, &c.asset.asset_id), Amount(1_000_000));
    assert_eq!(c.nodes[0].shares_produced() + c.nodes[1].shares_produced(), 2, "only the first job produced shares");
}

#[test]
fn d_job_without_required_grants_never_reaches_the_authority() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    world.register(&pol, &intent);
    let store = mem_store();
    let coord = coordinator(&world, c, in_process(&c.nodes), store.clone());
    let j = job(&world, c, &pol, &intent, "cand-1", 0, vec![pid(1), pid(2)]);
    assert!(matches!(j.evaluation.decision, Decision::RequireApprovals { .. }));
    let family = j.built.candidate.operation_family_id.clone();
    let rid = reservation_id_for(&family, &j.built.candidate.candidate_id, 1).unwrap();
    assert_eq!(code(coord.execute(j.clone())), ErrorCode::ApprovalRequired);
    assert_eq!(store.lifecycle(&family), LifecycleState::AwaitingApproval);
    assert_eq!(code(world.authority.reservation(&rid)), ErrorCode::NotFound);

    let mut denied = j.clone();
    denied.evaluation.decision = Decision::Deny { reasons: vec![oic_policy_kernel::ReasonCode::DeniedDestination] };
    assert_eq!(code(coord.execute(denied)), ErrorCode::PolicyDenied);
    assert_eq!(store.lifecycle(&family), LifecycleState::Rejected);

    // A caller that lies about the decision (Allow without grants) is stopped
    // by the authority's own approver count; nothing is reserved.
    let mut lying = j;
    lying.evaluation.decision = Decision::Allow { rule_id: "r-1".into() };
    lying.evaluation.matched_rule = Some(pol.rules[0].clone());
    assert_eq!(code(coord.execute(lying)), ErrorCode::ApprovalRequired);
    assert_eq!(code(world.authority.reservation(&rid)), ErrorCode::NotFound);
    assert_eq!(outstanding(&world, &c.asset.asset_id), Amount::ZERO);
    assert!(c.nodes.iter().all(|n| !n.events().iter().any(|e| matches!(e, oic_signer::SignerEvent::SessionOpened { .. }))), "no signer session opened");
}

#[test]
fn e_receipts_other_than_the_authoritys_are_never_accepted_by_signers() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let i1 = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    let i2 = c.intent("intent-2", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    world.register(&pol, &i1);
    world.register(&pol, &i2);
    let first = coordinator(&world, c, in_process(&c.nodes), mem_store()).execute(job(&world, c, &pol, &i1, "cand-1", 1, vec![pid(1), pid(2)])).unwrap();
    sol.sim.advance_slot().unwrap();

    let probes: Vec<Arc<Wrapped>> = in_process(&c.nodes)
        .into_iter()
        .map(|inner| {
            let mut w = Wrapped::new(inner);
            w.foreign = vec![first.release_receipt.clone(), first.envelope.authorization_state_receipt.clone()];
            w.forger = Some(world.authority_sk.clone());
            Arc::new(w)
        })
        .collect();
    let eps: Vec<Arc<dyn SignerEndpoint>> = probes.iter().map(|p| p.clone() as Arc<dyn SignerEndpoint>).collect();
    let second = coordinator(&world, c, eps, mem_store()).execute(job(&world, c, &pol, &i2, "cand-2", 1, vec![pid(1), pid(2)])).unwrap();

    for p in &probes[..2] {
        assert_eq!(*p.passed.lock().unwrap(), vec![second.release_receipt.clone()], "the coordinator passed exactly the authority's receipt");
        let log = p.log.lock().unwrap().clone();
        assert_eq!(
            log,
            vec![
                ("foreign".to_string(), Err(ErrorCode::InvalidSignature)),
                ("foreign".to_string(), Err(ErrorCode::InvalidSignature)),
                ("other-session".to_string(), Err(ErrorCode::ScopeMismatch)),
            ]
        );
    }
    assert!(probes[2].passed.lock().unwrap().is_empty(), "the non-participant was never contacted");
    // One share per job per participant: the refused receipts produced none.
    assert_eq!(c.nodes[0].shares_produced(), 2);
    assert_eq!(c.nodes[1].shares_produced(), 2);
    assert_eq!(c.nodes[2].shares_produced(), 0);
}

#[test]
fn misconfigured_jobs_fail_before_anything_is_reserved() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    world.register(&pol, &intent);
    let store = mem_store();
    // Only signer-1 is reachable.
    let coord = coordinator(&world, c, in_process(&c.nodes[..1]), store.clone());
    let j = job(&world, c, &pol, &intent, "cand-1", 1, vec![pid(1), pid(2)]);
    let family = j.built.candidate.operation_family_id.clone();
    let rid = reservation_id_for(&family, &j.built.candidate.candidate_id, 1).unwrap();
    assert_eq!(code(coord.execute(j.clone())), ErrorCode::NotFound);
    let mut single = j.clone();
    single.participant_set = vec![pid(1)];
    assert_eq!(code(coord.execute(single)), ErrorCode::InvalidRequest, "FROST cannot sign with one participant");
    let mut stranger = j.clone();
    stranger.participant_set = vec![pid(1), pid(9)];
    assert_eq!(code(coord.execute(stranger)), ErrorCode::ScopeMismatch);
    let mut other_policy = j.clone();
    other_policy.policy = signed_policy(&world, &c.asset, 0, 10_000_000);
    assert_eq!(code(coord.execute(other_policy)), ErrorCode::StalePolicy);
    let mut wrong_rule = j.clone();
    wrong_rule.evaluation.matched_rule = None;
    assert_eq!(code(coord.execute(wrong_rule)), ErrorCode::InvalidRequest);
    let no_adapter = Coordinator::<InMemoryAuthorityStore>::new(world.authority.clone(), in_process(&c.nodes), vec![], world.clock.clone(), store.clone()).unwrap();
    assert_eq!(code(no_adapter.execute(j)), ErrorCode::UnsupportedCapability);
    assert_eq!(code(world.authority.reservation(&rid)), ErrorCode::NotFound);
    assert!(store.transitions(&family).iter().all(|t| t.state == LifecycleState::Rejected));
    // Duplicate endpoints or adapters are configuration errors.
    let mut dup = in_process(&c.nodes);
    dup.push(dup[0].clone());
    assert!(Coordinator::<InMemoryAuthorityStore>::new(world.authority.clone(), dup, vec![], world.clock.clone(), store.clone()).is_err());
    assert!(Coordinator::<InMemoryAuthorityStore>::new(world.authority.clone(), vec![], vec![c.adapter.clone(), c.adapter.clone()], world.clock.clone(), store).is_err());
}
