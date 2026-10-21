//! Acceptance tests for the authorization-state authority (RFC 0001 §5, §16).

use ed25519_dalek::{Signer, SigningKey};
use oic_authorization_state::*;
use oic_domain_types::*;
use oic_policy_kernel::{intent_hash, policy_hash, Decision};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const T0: u64 = 1_700_000_000;
const DAY: u64 = 86_400;
const LIMIT: u128 = 1000;

fn inst() -> InstitutionId {
    InstitutionId::unchecked("inst-1")
}
fn env() -> EnvironmentId {
    EnvironmentId::unchecked("testnet")
}
fn vault() -> VaultId {
    VaultId::unchecked("vault-ops")
}
fn usdc() -> AssetId {
    AssetId::unchecked("usdc-sepolia")
}
fn net() -> NetworkId {
    NetworkId::unchecked("evm-sepolia")
}

fn admin(n: u8) -> (CredentialId, SigningKey) {
    (CredentialId::unchecked(format!("admin-{n}")), SigningKey::from_bytes(&[n; 32]))
}
fn responder() -> (CredentialId, SigningKey) {
    (CredentialId::unchecked("responder-1"), SigningKey::from_bytes(&[77; 32]))
}
fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn config() -> AuthorityConfig {
    AuthorityConfig {
        institution_id: inst(),
        environment_id: env(),
        authority_key_id: KeyId::unchecked("authority-key-1"),
        admin_keys: (1..=3).map(admin).map(|(c, k)| (c, k.verifying_key())).collect(),
        admin_quorum: 2,
        freeze_responders: vec![(responder().0, responder().1.verifying_key())],
        release_receipt_ttl_seconds: 60,
        max_clock_skew_seconds: 30,
    }
}

fn sign_cred(who: &(CredentialId, SigningKey), h: &Hash32) -> CredentialSignature {
    CredentialSignature {
        credential_id: who.0.clone(),
        signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(who.1.sign(&h.0).to_bytes().to_vec()) },
    }
}

fn rule() -> PolicyRule {
    PolicyRule {
        rule_id: "r-ops".into(),
        vaults: vec![vault()],
        assets: vec![usdc()],
        destinations: vec![],
        purposes: vec![],
        max_amount_per_operation: Amount(1000),
        max_native_fee_per_operation: Amount(100),
        rolling_limits: vec![ExposureLimit { window_seconds: DAY, max_outflow_base_units: Amount(LIMIT) }],
        required_approvals: 0,
        approval_roles: vec![ApprovalRole::Automated],
        exclude_proposer: true,
        operating_window: None,
    }
}

fn policy(epoch: u64, signers: &[u8]) -> PolicyBundle {
    let mut b = PolicyBundle {
        policy_id: PolicyId::unchecked("pol-1"),
        policy_epoch: Epoch(epoch),
        institution_id: inst(),
        environment_id: env(),
        rules: vec![rule()],
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 60,
        allowlist_version: 1,
        activation_epoch: Epoch(epoch),
        administrative_signatures: vec![],
    };
    let h = policy_hash(&b).unwrap();
    b.administrative_signatures = signers.iter().map(|n| sign_cred(&admin(*n), &h)).collect();
    b
}

fn intent(n: u32) -> Intent {
    Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked(format!("intent-{n}")),
        institution_id: inst(),
        environment_id: env(),
        vault_id: vault(),
        chain_wallet_id: ChainWalletId::unchecked("wallet-1"),
        chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
        operation: IntentOperation::AssetTransfer {
            asset_id: usdc(),
            amount_base_units: Amount(100),
            destination_id: DestinationId::unchecked("dest-1"),
            destination_version: 1,
        },
        constraints: IntentConstraints { max_network_fee_base_units: Amount(100), approval_mode: ApprovalMode::ExactCandidate, maximum_successful_payments: 1 },
        purpose: OperationPurpose::Settlement,
        external_reference: format!("ref-{n}"),
        proposer_credential_id: CredentialId::unchecked("cred-proposer"),
        created_at: UnixSeconds(T0),
    }
}

fn evm_claims(nonce: u64, amount: u128, fee: u128) -> ResourceClaims {
    ResourceClaims {
        resources: vec![NativeResource::EvmNonce { network_id: net(), sender: Bytes(vec![0xcc; 20]), nonce }],
        asset_outflows: vec![AssetOutflow { asset_id: usdc(), amount_base_units: Amount(amount) }],
        native_fees: vec![NativeFee { network_id: net(), amount_base_units: Amount(fee) }],
    }
}

fn solana_claims(blockhash: u8, amount: u128) -> ResourceClaims {
    let sol = NetworkId::unchecked("solana-devnet");
    ResourceClaims {
        resources: vec![NativeResource::SolanaBlockhash { network_id: sol.clone(), fee_payer: Bytes(vec![1; 32]), blockhash: Bytes(vec![blockhash; 32]) }],
        asset_outflows: vec![AssetOutflow { asset_id: usdc(), amount_base_units: Amount(amount) }],
        native_fees: vec![NativeFee { network_id: sol, amount_base_units: Amount(50) }],
    }
}

struct Env {
    clock: Arc<ManualClock>,
    store: Arc<InMemoryAuthorityStore>,
    auth: Authority<InMemoryAuthorityStore>,
}

fn setup_with(store: InMemoryAuthorityStore) -> Env {
    let clock = Arc::new(ManualClock::new(T0));
    let store = Arc::new(store);
    let auth = Authority::open(store.clone(), 0, config(), authority_key(), clock.clone()).unwrap();
    auth.set_policy(&policy(1, &[1, 2])).unwrap();
    Env { clock, store, auth }
}

fn setup() -> Env {
    setup_with(InMemoryAuthorityStore::new())
}

impl Env {
    fn register(&self, n: u32) -> RegisteredIntent {
        let i = intent(n);
        self.auth
            .register_intent(
                &i,
                intent_hash(&i).unwrap(),
                IdempotencyKey { institution_id: inst(), route: "POST /v1/intents".into(), key: format!("idem-{n}") },
            )
            .unwrap()
    }

    fn request(&self, reg: &RegisteredIntent, cand: &str, rev: u32, claims: ResourceClaims) -> ReserveRequest {
        let (epoch, hash) = self.auth.current_policy().unwrap();
        ReserveRequest {
            family_id: reg.operation_family_id.clone(),
            candidate_id: CandidateId::unchecked(cand),
            candidate_revision: rev,
            vault_id: vault(),
            intent_id: reg.intent_id.clone(),
            policy_epoch: epoch,
            policy_hash: hash,
            exposure_limits: claims.asset_outflows.iter().map(|o| (o.asset_id.clone(), rule().rolling_limits[0].clone())).collect(),
            claims,
            grants: vec![],
            envelope_body_hash: oic_canonical_encoding::sha256(format!("env:{cand}:{rev}").as_bytes()),
            signer_session_id: SigningSessionId::unchecked(format!("sess-{cand}-{rev}")),
            issuance_deadline: UnixSeconds(self.clock.now().0 + 600),
            policy_decision: Decision::Allow { rule_id: "r-ops".into() },
        }
    }

    fn release_req(&self, req: &ReserveRequest) -> ReleaseRequest {
        ReleaseRequest {
            reservation_id: reservation_id_for(&req.family_id, &req.candidate_id, req.candidate_revision).unwrap(),
            reservation_version: 1,
            envelope_body_hash: req.envelope_body_hash,
            signer_session_id: req.signer_session_id.clone(),
            expected_policy_epoch: req.policy_epoch,
            freshness: FreshnessContext { now: self.clock.now() },
        }
    }

    fn exposure(&self) -> Amount {
        self.auth.exposure(&vault(), &BudgetKey::Asset { asset_id: usdc() }, DAY).unwrap()
    }

    fn view(&self) -> (Amount, Amount) {
        let v = self.auth.exposure_view(&vault(), &[usdc()], &[DAY], self.clock.now()).unwrap();
        (v.windows[0].settled, v.windows[0].outstanding)
    }

    fn freeze(&self, scope: FreezeScope) -> OicResult<u64> {
        let r = responder();
        let p = FreezeProposal::new(inst(), env(), scope.clone(), r.0.clone(), "incident");
        let sig = sign_cred(&r, &p.hash().unwrap()).signature;
        self.auth.freeze(scope, r.0, "incident", &sig)
    }

    fn unfreeze(&self, scope: FreezeScope, signers: &[u8]) -> OicResult<u64> {
        let rec = self.auth.freeze_record(&scope).unwrap().expect("frozen");
        let h = UnfreezeProposal::new(inst(), env(), scope.clone(), rec.at_commit_sequence).hash().unwrap();
        let sigs: Vec<_> = signers.iter().map(|n| sign_cred(&admin(*n), &h)).collect();
        self.auth.unfreeze(scope, &sigs)
    }
}

fn code<T>(r: OicResult<T>) -> ErrorCode {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.code,
    }
}

// ---------------------------------------------------------------------------

#[test]
fn keyless_transition_replays_canonical_commands_and_orders_freeze_against_release() {
    let e = setup();
    let registered = e.register(91);
    let request = e.request(&registered, "pure-candidate", 3, evm_claims(17, 373, 29));
    let initial = e.store.snapshot();
    let command = AuthorityCommand::Reserve { request: request.clone() };
    let encoded = oic_canonical_encoding::canonical_bytes(&command).unwrap();
    let decoded: AuthorityCommand = oic_canonical_encoding::from_canonical_bytes(&encoded).unwrap();
    let first = apply(&config(), initial.clone(), command, UnixSeconds(T0 + 7)).unwrap();
    let replay = apply(&config(), initial.clone(), decoded, UnixSeconds(T0 + 7)).unwrap();
    assert_eq!(first, replay);
    let (reserved, result, events) = first;
    let AuthorityOutput::Reserved { reservation, receipt } = result else { panic!("reserve output") };
    assert_eq!(reservation.created_at, UnixSeconds(T0 + 7), "only the explicit time enters the transition");
    assert_eq!(receipt.issued_at, UnixSeconds(T0 + 7));
    assert_eq!(receipt.envelope_body_hash, request.envelope_body_hash);
    assert_eq!(receipt.signer_session_id, request.signer_session_id);
    assert_eq!(reserved.outstanding(&vault(), &BudgetKey::Asset { asset_id: usdc() }), Some(Amount(373)));
    assert_eq!(events, vec![AuthorityEvent::Reserved { reservation_id: reservation.reservation_id.clone(), commit_sequence: initial.commit_sequence + 1 }]);
    assert_eq!(e.store.snapshot(), initial, "pure application does not touch the source store");

    let responder = responder();
    let proposal = FreezeProposal::new(inst(), env(), FreezeScope::Global, responder.0.clone(), "incident");
    let signature = sign_cred(&responder, &proposal.hash().unwrap()).signature;
    let freeze = AuthorityCommand::Freeze { scope: FreezeScope::Global, by: responder.0, reason: "incident".into(), signature };
    let release = AuthorityCommand::Release { request: e.release_req(&request) };
    let (frozen, _, _) = apply(&config(), reserved.clone(), freeze.clone(), UnixSeconds(T0 + 8)).unwrap();
    assert_eq!(code(apply(&config(), frozen, release.clone(), UnixSeconds(T0 + 9))), ErrorCode::Frozen);

    let (released, output, _) = apply(&config(), reserved, release.clone(), UnixSeconds(T0 + 8)).unwrap();
    let AuthorityOutput::Released { receipt, issuance } = output else { panic!("release output") };
    assert_eq!(receipt.expires_at, UnixSeconds(T0 + 68));
    assert_eq!(issuance.committed_at, UnixSeconds(T0 + 8));
    assert_eq!(issuance.commit_sequence, initial.commit_sequence + 2);
    let (frozen_after, _, _) = apply(&config(), released, freeze, UnixSeconds(T0 + 9)).unwrap();
    assert_eq!(frozen_after.issuance.len(), 1);
    assert_eq!(frozen_after.outstanding(&vault(), &BudgetKey::Asset { asset_id: usdc() }), Some(Amount(373)));
    let (repeated, output, events) = apply(&config(), frozen_after.clone(), release, UnixSeconds(T0 + 10)).unwrap();
    let AuthorityOutput::Released { issuance: repeated_issuance, .. } = output else { panic!("idempotent release output") };
    assert_eq!(repeated_issuance, issuance, "a later freeze cannot erase committed issuance");
    assert_eq!(repeated, frozen_after);
    assert!(events.is_empty());
}

#[test]
fn reserve_release_receipts_verify() {
    let e = setup();
    let reg = e.register(1);
    let req = e.request(&reg, "c1", 1, evm_claims(0, 400, 50));
    let (res, receipt) = e.auth.reserve(req.clone()).unwrap();
    let pk = e.auth.verifying_key();
    let mut exp = ReceiptExpectation {
        kind: ReceiptKind::Reserved,
        envelope_body_hash: req.envelope_body_hash,
        signer_session_id: req.signer_session_id.clone(),
        candidate_id: req.candidate_id.clone(),
        candidate_revision: 1,
        now: e.clock.now(),
        policy_epoch: Epoch(1),
    };
    verify_receipt(&receipt, &pk, &exp).unwrap();
    assert_eq!(res.reservation_id, reservation_id_for(&reg.operation_family_id, &req.candidate_id, 1).unwrap());

    let (rel, iss) = e.auth.release(e.release_req(&req)).unwrap();
    exp.kind = ReceiptKind::Release;
    verify_receipt(&rel, &pk, &exp).unwrap();
    assert_eq!(rel.body.commit_sequence, iss.commit_sequence);
    assert_eq!(e.auth.family(&reg.operation_family_id).unwrap().lifecycle, LifecycleState::IssuanceCommitted);

    // binding failures
    let mut wrong = exp.clone();
    wrong.envelope_body_hash = Hash32([9; 32]);
    assert_eq!(code(verify_receipt(&rel, &pk, &wrong)), ErrorCode::ScopeMismatch);
    let mut wrong = exp.clone();
    wrong.signer_session_id = SigningSessionId::unchecked("other");
    assert_eq!(code(verify_receipt(&rel, &pk, &wrong)), ErrorCode::ScopeMismatch);
    let mut wrong = exp.clone();
    wrong.kind = ReceiptKind::Reserved;
    assert_eq!(code(verify_receipt(&rel, &pk, &wrong)), ErrorCode::ScopeMismatch);
    let mut wrong = exp.clone();
    wrong.policy_epoch = Epoch(2);
    assert_eq!(code(verify_receipt(&rel, &pk, &wrong)), ErrorCode::StalePolicy);
    // release receipts are short-lived: valid until issued_at + 60, exclusive
    let mut later = exp.clone();
    later.now = UnixSeconds(rel.body.issued_at.0 + 59);
    verify_receipt(&rel, &pk, &later).unwrap();
    later.now = UnixSeconds(rel.body.issued_at.0 + 60);
    assert_eq!(code(verify_receipt(&rel, &pk, &later)), ErrorCode::ScopeMismatch);
    // tampered body / wrong key
    let mut tampered = rel.clone();
    tampered.body.commit_sequence += 1;
    assert_eq!(code(verify_receipt(&tampered, &pk, &exp)), ErrorCode::InvalidSignature);
    assert_eq!(code(verify_receipt(&rel, &SigningKey::from_bytes(&[1; 32]).verifying_key(), &exp)), ErrorCode::InvalidSignature);
}

#[test]
fn a07_duplicate_request_after_lost_response() {
    let e = setup();
    let i = intent(1);
    let key = IdempotencyKey { institution_id: inst(), route: "POST /v1/intents".into(), key: "k-1".into() };
    let a = e.auth.register_intent(&i, intent_hash(&i).unwrap(), key.clone()).unwrap();
    let b = e.auth.register_intent(&i, intent_hash(&i).unwrap(), key.clone()).unwrap();
    assert!(a.created && !b.created);
    assert_eq!(a.intent_id, b.intent_id);
    assert_eq!(a.operation_family_id, b.operation_family_id);
    assert_eq!(e.store.snapshot().families.len(), 1);

    // same key, different body
    let mut changed = intent(1);
    changed.external_reference = "different".into();
    assert_eq!(code(e.auth.register_intent(&changed, intent_hash(&changed).unwrap(), key.clone())), ErrorCode::Conflict);
    // different key, same intent id, different body
    let key2 = IdempotencyKey { key: "k-2".into(), ..key.clone() };
    assert_eq!(code(e.auth.register_intent(&changed, intent_hash(&changed).unwrap(), key2.clone())), ErrorCode::Conflict);
    // claimed hash must match the canonical body
    assert_eq!(code(e.auth.register_intent(&i, Hash32([1; 32]), key2)), ErrorCode::InvalidRequest);

    // idempotent reserve and release: no extra exposure, same issuance
    let req = e.request(&a, "c1", 1, evm_claims(0, 300, 10));
    let (r1, _) = e.auth.reserve(req.clone()).unwrap();
    let (r2, _) = e.auth.reserve(req.clone()).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(e.exposure(), Amount(300));
    let (_, i1) = e.auth.release(e.release_req(&req)).unwrap();
    let (rc2, i2) = e.auth.release(e.release_req(&req)).unwrap();
    assert_eq!(i1, i2);
    assert_eq!(rc2.body.commit_sequence, i1.commit_sequence);
    assert_eq!(e.store.snapshot().issuance.len(), 1);
    assert_eq!(e.exposure(), Amount(300));
    // same reservation, different session -> conflict
    let mut other = e.release_req(&req);
    other.signer_session_id = SigningSessionId::unchecked("sess-attacker");
    assert_eq!(code(e.auth.release(other)), ErrorCode::Conflict);
    let mut other = e.release_req(&req);
    other.envelope_body_hash = Hash32([3; 32]);
    assert_eq!(code(e.auth.release(other)), ErrorCode::Conflict);
    // reserve of same candidate revision with different content -> conflict
    let mut changed_req = req.clone();
    changed_req.claims = evm_claims(0, 301, 10);
    changed_req.exposure_limits = vec![(usdc(), rule().rolling_limits[0].clone())];
    assert_eq!(code(e.auth.reserve(changed_req)), ErrorCode::Conflict);
}

#[test]
fn a08_concurrent_reserves_cannot_overspend() {
    let e = Arc::new(setup());
    let mut regs = Vec::new();
    for n in 0..80 {
        regs.push(e.register(n));
    }
    let regs = Arc::new(regs);
    let mut handles = Vec::new();
    for t in 0..8u32 {
        let e = e.clone();
        let regs = regs.clone();
        handles.push(std::thread::spawn(move || {
            let mut ok = 0u32;
            for k in 0..10u32 {
                let n = (t * 10 + k) as usize;
                let req = e.request(&regs[n], &format!("cand-{n}"), 1, evm_claims(n as u64, 150, 1));
                match e.auth.reserve(req) {
                    Ok(_) => ok += 1,
                    Err(err) => assert_eq!(err.code, ErrorCode::BudgetExceeded, "{err}"),
                }
            }
            ok
        }));
    }
    let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 6, "6 × 15% fits in 100%, a 7th does not");
    assert!(e.exposure().0 <= LIMIT);
    assert_eq!(e.exposure(), Amount(900));
}

#[test]
fn a09_split_views_cannot_both_hold_the_nonce() {
    let e = setup();
    let f1 = e.register(1);
    let f2 = e.register(2);
    // A+C were shown family 1, B+C family 2, both spending (sender, nonce 7).
    e.auth.reserve(e.request(&f1, "c-a", 1, evm_claims(7, 100, 1))).unwrap();
    assert_eq!(code(e.auth.reserve(e.request(&f2, "c-b", 1, evm_claims(7, 100, 1)))), ErrorCode::ResourceConflict);
    // a candidate cannot be re-filed under another family
    assert_eq!(code(e.auth.reserve(e.request(&f2, "c-a", 2, evm_claims(8, 100, 1)))), ErrorCode::Conflict);

    // same family, *different* nonces: both may execute, so exposure is summed
    // and the second may not be released once the first is possibly issued.
    let f3 = e.register(3);
    let r1 = e.request(&f3, "c-x", 1, evm_claims(20, 300, 1));
    let r2 = e.request(&f3, "c-y", 1, evm_claims(21, 300, 1));
    e.auth.reserve(r1.clone()).unwrap();
    e.auth.reserve(r2.clone()).unwrap();
    assert_eq!(e.exposure(), Amount(700));
    e.auth.release(e.release_req(&r1)).unwrap();
    assert_eq!(code(e.auth.release(e.release_req(&r2))), ErrorCode::IssuanceUncertain);
}

#[test]
fn a10_authority_unavailable_fails_closed_without_partial_writes() {
    let fail = Arc::new(AtomicBool::new(false));
    let f = fail.clone();
    let store = InMemoryAuthorityStore::new().with_persist_hook(Box::new(move |_st| {
        if f.load(Ordering::SeqCst) {
            Err(OicError::new(ErrorCode::AuthorityUnavailable, "replica quorum unreachable"))
        } else {
            Ok(())
        }
    }));
    let e = setup_with(store);
    let reg = e.register(1);
    let ok = e.request(&reg, "c0", 1, evm_claims(0, 100, 1));
    e.auth.reserve(ok.clone()).unwrap();
    let before = e.store.snapshot();
    fail.store(true, Ordering::SeqCst);
    let reg2 = RegisteredIntent { intent_id: reg.intent_id.clone(), operation_family_id: reg.operation_family_id.clone(), created: false };
    assert_eq!(code(e.auth.reserve(e.request(&reg2, "c1", 1, evm_claims(1, 100, 1)))), ErrorCode::AuthorityUnavailable);
    assert_eq!(code(e.auth.release(e.release_req(&ok))), ErrorCode::AuthorityUnavailable);
    assert_eq!(e.store.snapshot(), before, "nothing partially persisted");
    fail.store(false, Ordering::SeqCst);
    e.auth.release(e.release_req(&ok)).unwrap();
}

#[test]
fn a14_old_policy_epoch_rejected_everywhere() {
    let e = setup();
    let reg = e.register(1);
    let old = e.request(&reg, "c1", 1, evm_claims(0, 100, 1));
    e.auth.reserve(old.clone()).unwrap();
    e.auth.set_policy(&policy(2, &[2, 3])).unwrap();
    // a reservation made under epoch 1 cannot be released under epoch 2
    let mut rel = e.release_req(&old);
    assert_eq!(code(e.auth.release(rel.clone())), ErrorCode::StalePolicy);
    rel.expected_policy_epoch = Epoch(2);
    assert_eq!(code(e.auth.release(rel)), ErrorCode::StalePolicy);
    // a new request presenting the old epoch is refused
    let mut stale = e.request(&reg, "c2", 1, evm_claims(1, 100, 1));
    stale.policy_epoch = Epoch(1);
    stale.policy_hash = policy_hash(&policy(1, &[])).unwrap();
    assert_eq!(code(e.auth.reserve(stale)), ErrorCode::StalePolicy);
    // re-activating the old (validly signed) bundle is a rollback
    assert_eq!(code(e.auth.set_policy(&policy(1, &[1, 2]))), ErrorCode::StalePolicy);
    assert_eq!(code(e.auth.set_policy(&policy(2, &[1, 2]))), ErrorCode::StalePolicy);
}

#[test]
fn a15_single_admin_cannot_change_policy_or_unfreeze() {
    let e = setup();
    assert_eq!(code(e.auth.set_policy(&policy(2, &[1]))), ErrorCode::InvalidSignature);
    assert_eq!(code(e.auth.set_policy(&policy(2, &[1, 1]))), ErrorCode::InvalidSignature);
    let mut forged = policy(2, &[1, 2]);
    forged.rules[0].rolling_limits[0].max_outflow_base_units = Amount(1_000_000);
    assert_eq!(code(e.auth.set_policy(&forged)), ErrorCode::InvalidSignature);
    e.freeze(FreezeScope::Global).unwrap();
    assert_eq!(code(e.unfreeze(FreezeScope::Global, &[3])), ErrorCode::InvalidSignature);
    e.unfreeze(FreezeScope::Global, &[1, 3]).unwrap();
    // a non-responder cannot freeze
    let a = admin(1);
    let p = FreezeProposal::new(inst(), env(), FreezeScope::Global, a.0.clone(), "x");
    let sig = sign_cred(&a, &p.hash().unwrap()).signature;
    assert_eq!(code(e.auth.freeze(FreezeScope::Global, a.0, "x", &sig)), ErrorCode::InvalidSignature);
}

#[test]
fn a16_freeze_races_release_with_ordered_result() {
    let e = setup();
    let f1 = e.register(1);
    let f2 = e.register(2);
    let r1 = e.request(&f1, "c1", 1, evm_claims(1, 200, 1));
    let r2 = e.request(&f2, "c2", 1, evm_claims(2, 200, 1));
    e.auth.reserve(r1.clone()).unwrap();
    e.auth.reserve(r2.clone()).unwrap();
    let (_, iss1) = e.auth.release(e.release_req(&r1)).unwrap();
    let freeze_seq = e.freeze(FreezeScope::Global).unwrap();
    assert!(iss1.commit_sequence < freeze_seq);
    // after the commit point: no new release, no new reservation
    assert_eq!(code(e.auth.release(e.release_req(&r2))), ErrorCode::Frozen);
    let f3 = e.register(3);
    assert_eq!(code(e.auth.reserve(e.request(&f3, "c3", 1, evm_claims(3, 10, 1)))), ErrorCode::Frozen);
    // prior release identified and retained; no false revocation
    let prior = e.auth.releases_before(freeze_seq).unwrap();
    assert_eq!(prior, vec![iss1.clone()]);
    let rid1 = reservation_id_for(&f1.operation_family_id, &r1.candidate_id, 1).unwrap();
    assert!(matches!(e.auth.reservation(&rid1).unwrap().state, ReservationState::Released { .. }));
    assert_eq!(e.exposure(), Amount(400));
    // the already committed release can still be re-fetched for its own session
    let (_, again) = e.auth.release(e.release_req(&r1)).unwrap();
    assert_eq!(again, iss1);
    // unfreeze needs quorum; then issuance resumes
    e.unfreeze(FreezeScope::Global, &[1, 2]).unwrap();
    let (_, iss2) = e.auth.release(e.release_req(&r2)).unwrap();
    assert!(iss2.commit_sequence > freeze_seq);
}

#[test]
fn vault_freeze_is_scoped_and_unfreeze_binds_the_freeze() {
    let e = setup();
    let f1 = e.register(1);
    let scope = FreezeScope::Vault { vault_id: vault() };
    let first = e.auth.freeze_record(&scope).unwrap();
    assert!(first.is_none());
    e.freeze(scope.clone()).unwrap();
    assert_eq!(code(e.auth.reserve(e.request(&f1, "c1", 1, evm_claims(1, 10, 1)))), ErrorCode::Frozen);
    // an unfreeze approval for an earlier freeze does not lift a later one
    let old_rec = e.auth.freeze_record(&scope).unwrap().unwrap();
    let h_old = UnfreezeProposal::new(inst(), env(), scope.clone(), old_rec.at_commit_sequence).hash().unwrap();
    let old_sigs = vec![sign_cred(&admin(1), &h_old), sign_cred(&admin(2), &h_old)];
    e.auth.unfreeze(scope.clone(), &old_sigs).unwrap();
    e.freeze(scope.clone()).unwrap();
    assert_eq!(code(e.auth.unfreeze(scope.clone(), &old_sigs)), ErrorCode::InvalidSignature);
    e.unfreeze(scope, &[2, 3]).unwrap();
    e.auth.reserve(e.request(&f1, "c1", 1, evm_claims(1, 10, 1))).unwrap();
}

#[test]
fn a17_approval_expiry_after_issuance_keeps_exposure() {
    let e = setup();
    let f1 = e.register(1);
    let f2 = e.register(2);
    let issued = e.request(&f1, "c1", 1, evm_claims(1, 300, 1));
    let pending = e.request(&f2, "c2", 1, evm_claims(2, 200, 1));
    e.auth.reserve(issued.clone()).unwrap();
    e.auth.reserve(pending.clone()).unwrap();
    e.auth.release(e.release_req(&issued)).unwrap();
    let rid_issued = reservation_id_for(&f1.operation_family_id, &issued.candidate_id, 1).unwrap();
    let rid_pending = reservation_id_for(&f2.operation_family_id, &pending.candidate_id, 1).unwrap();
    assert_eq!(code(e.auth.approval_expired(&rid_pending)), ErrorCode::InvalidRequest, "deadline not yet passed");
    e.clock.advance(601);
    let aborted = e.auth.expire_approvals().unwrap();
    assert_eq!(aborted, vec![rid_pending.clone()]);
    assert_eq!(e.exposure(), Amount(300), "possibly issued exposure retained");
    assert_eq!(code(e.auth.approval_expired(&rid_issued)), ErrorCode::IssuanceUncertain);
    assert_eq!(code(e.auth.abort_before_issuance(&rid_issued)), ErrorCode::IssuanceUncertain);
    assert!(matches!(e.auth.reservation(&rid_issued).unwrap().state, ReservationState::Released { .. }));
    assert_eq!(e.auth.family(&f2.operation_family_id).unwrap().lifecycle, LifecycleState::ApprovalExpired);
    // the expired reservation's nonce is free again
    let f3 = e.register(3);
    e.auth.reserve(e.request(&f3, "c3", 1, evm_claims(2, 100, 1))).unwrap();
    // a reserved-but-unreleased candidate past its deadline cannot be released
    let f4 = e.register(4);
    let late = e.request(&f4, "c4", 1, evm_claims(4, 10, 1));
    e.auth.reserve(late.clone()).unwrap();
    e.clock.advance(601);
    let mut rel = e.release_req(&late);
    rel.freshness = FreshnessContext { now: e.clock.now() };
    assert_eq!(code(e.auth.release(rel)), ErrorCode::PolicyDenied);
}

#[test]
fn a36_outstanding_exposure_survives_window_reset() {
    let e = setup();
    let f1 = e.register(1);
    let r1 = e.request(&f1, "c1", 1, evm_claims(1, 900, 10));
    e.auth.reserve(r1.clone()).unwrap();
    e.auth.release(e.release_req(&r1)).unwrap();
    e.clock.advance(2 * DAY);
    assert_eq!(e.view(), (Amount(0), Amount(900)), "outstanding never expires by time");
    let f2 = e.register(2);
    let r2 = e.request(&f2, "c2", 1, evm_claims(2, 200, 10));
    assert_eq!(code(e.auth.reserve(r2.clone())), ErrorCode::BudgetExceeded);
    // finalization moves outstanding to settled without double charging
    assert_eq!(
        e.auth
            .record_observation(
                &f1.operation_family_id,
                &r1.candidate_id,
                ChainObservation::Finalized {
                    tx_id: ChainTxId::unchecked("0xabc"),
                    state: StateReference { height: 10, hash: Bytes(vec![1; 32]), commitment: "finalized".into() },
                    execution_success: true,
                    fee_paid: Amount(7),
                    effects_hash: Hash32([0; 32]),
                }
            )
            .unwrap(),
        LifecycleState::FinalizedSuccess
    );
    assert_eq!(e.view(), (Amount(900), Amount(0)));
    assert_eq!(e.auth.exposure(&vault(), &BudgetKey::NativeFee { network_id: net() }, DAY).unwrap(), Amount(7));
    assert_eq!(code(e.auth.reserve(r2.clone())), ErrorCode::BudgetExceeded);
    // the settled debit rolls out of the window exactly one window later
    e.clock.advance(DAY - 1);
    assert_eq!(code(e.auth.reserve(e.request(&f2, "c2", 1, evm_claims(2, 200, 10)))), ErrorCode::BudgetExceeded);
    e.clock.advance(1);
    assert_eq!(e.view(), (Amount(0), Amount(0)));
    e.auth.reserve(e.request(&f2, "c2", 1, evm_claims(2, 200, 10))).unwrap();
}

#[test]
fn finalized_failure_settles_fee_only() {
    let e = setup();
    let f1 = e.register(1);
    let r1 = e.request(&f1, "c1", 1, evm_claims(1, 500, 30));
    e.auth.reserve(r1.clone()).unwrap();
    e.auth.release(e.release_req(&r1)).unwrap();
    let obs = ChainObservation::Finalized {
        tx_id: ChainTxId::unchecked("0x1"),
        state: StateReference { height: 1, hash: Bytes(vec![1; 32]), commitment: "finalized".into() },
        execution_success: false,
        fee_paid: Amount(21),
        effects_hash: Hash32::ZERO,
    };
    assert_eq!(e.auth.record_observation(&f1.operation_family_id, &r1.candidate_id, obs.clone()).unwrap(), LifecycleState::FinalizedFailure);
    assert_eq!(e.view(), (Amount(0), Amount(0)));
    assert_eq!(e.auth.exposure(&vault(), &BudgetKey::NativeFee { network_id: net() }, DAY).unwrap(), Amount(21));
    // repeated identical evidence is idempotent; contradicting evidence conflicts
    e.auth.record_observation(&f1.operation_family_id, &r1.candidate_id, obs).unwrap();
    let contra = ChainObservation::Finalized {
        tx_id: ChainTxId::unchecked("0x1"),
        state: StateReference { height: 1, hash: Bytes(vec![1; 32]), commitment: "finalized".into() },
        execution_success: true,
        fee_paid: Amount(21),
        effects_hash: Hash32::ZERO,
    };
    assert_eq!(code(e.auth.record_observation(&f1.operation_family_id, &r1.candidate_id, contra)), ErrorCode::Conflict);
    // the nonce lock is released
    assert!(e.store.snapshot().resource_locks.is_empty());
}

#[test]
fn reorg_and_invalidation() {
    let e = setup();
    let f1 = e.register(1);
    let r1 = e.request(&f1, "c1", 1, evm_claims(1, 500, 30));
    e.auth.reserve(r1.clone()).unwrap();
    e.auth.release(e.release_req(&r1)).unwrap();
    let st = StateReference { height: 5, hash: Bytes(vec![5; 32]), commitment: "latest".into() };
    let fam = &f1.operation_family_id;
    assert_eq!(
        e.auth
            .record_observation(
                fam,
                &r1.candidate_id,
                ChainObservation::Submitted { tx_id: ChainTxId::unchecked("t"), source: EvidenceSourceId::unchecked("node"), at: e.clock.now() }
            )
            .unwrap(),
        LifecycleState::Submitted
    );
    assert_eq!(
        e.auth
            .record_observation(
                fam,
                &r1.candidate_id,
                ChainObservation::Included { tx_id: ChainTxId::unchecked("t"), state: st.clone(), execution_success: true, fee_paid: Amount(1) }
            )
            .unwrap(),
        LifecycleState::Included
    );
    assert_eq!(
        e.auth.record_observation(fam, &r1.candidate_id, ChainObservation::Reorged { tx_id: ChainTxId::unchecked("t"), previous_state: st.clone() }).unwrap(),
        LifecycleState::Reorged
    );
    assert_eq!(e.view(), (Amount(0), Amount(500)), "reorg retains exposure");
    // conflicting evidence quarantines; nothing is released
    e.auth.record_observation(fam, &r1.candidate_id, ChainObservation::Conflict { sources: vec![], detail: "split".into() }).unwrap();
    assert!(e.auth.family(fam).unwrap().quarantined);
    assert_eq!(e.view(), (Amount(0), Amount(500)));
    // definitive invalidation releases exposure and the nonce
    assert_eq!(
        e.auth
            .record_observation(
                fam,
                &r1.candidate_id,
                ChainObservation::DefinitivelyInvalidated { reason: "nonce consumed by other tx".into(), state: st.clone() }
            )
            .unwrap(),
        LifecycleState::DefinitivelyInvalidated
    );
    assert_eq!(e.view(), (Amount(0), Amount(0)));
    let f2 = e.register(2);
    e.auth.reserve(e.request(&f2, "c2", 1, evm_claims(1, 100, 1))).unwrap();
    // observations require a possibly issued candidate
    assert_eq!(
        code(e.auth.record_observation(
            &f2.operation_family_id,
            &CandidateId::unchecked("c2"),
            ChainObservation::DefinitivelyInvalidated { reason: "x".into(), state: st.clone() }
        )),
        ErrorCode::NotFound
    );
    // reorg after finality needs manual recovery
    let f3 = e.register(3);
    let r3 = e.request(&f3, "c3", 1, evm_claims(3, 100, 1));
    e.auth.reserve(r3.clone()).unwrap();
    e.auth.release(e.release_req(&r3)).unwrap();
    e.auth
        .record_observation(
            &f3.operation_family_id,
            &r3.candidate_id,
            ChainObservation::Finalized {
                tx_id: ChainTxId::unchecked("t3"),
                state: st.clone(),
                execution_success: true,
                fee_paid: Amount(1),
                effects_hash: Hash32::ZERO,
            },
        )
        .unwrap();
    assert_eq!(
        code(e.auth.record_observation(
            &f3.operation_family_id,
            &r3.candidate_id,
            ChainObservation::Reorged { tx_id: ChainTxId::unchecked("t3"), previous_state: st }
        )),
        ErrorCode::RecoveryRequired
    );
}

#[test]
fn abort_before_issuance_releases_locks_and_exposure() {
    let e = setup();
    let f1 = e.register(1);
    let r1 = e.request(&f1, "c1", 1, evm_claims(9, 800, 1));
    e.auth.reserve(r1.clone()).unwrap();
    let rid = reservation_id_for(&f1.operation_family_id, &r1.candidate_id, 1).unwrap();
    e.auth.abort_before_issuance(&rid).unwrap();
    assert_eq!(code(e.auth.abort_before_issuance(&rid)), ErrorCode::Conflict);
    assert_eq!(code(e.auth.release(e.release_req(&r1))), ErrorCode::Conflict);
    assert_eq!(e.exposure(), Amount(0));
    assert_eq!(e.auth.family(&f1.operation_family_id).unwrap().lifecycle, LifecycleState::AbortedBeforeIssuance);
    let f2 = e.register(2);
    e.auth.reserve(e.request(&f2, "c2", 1, evm_claims(9, 800, 1))).unwrap();
}

#[test]
fn evm_nonce_replacements_reserve_max_not_sum() {
    let e = setup();
    let f = e.register(1);
    let orig = e.request(&f, "c-orig", 1, evm_claims(5, 600, 10));
    let bump = e.request(&f, "c-bump", 1, evm_claims(5, 700, 20));
    e.auth.reserve(orig.clone()).unwrap();
    e.auth.release(e.release_req(&orig)).unwrap();
    e.auth.reserve(bump.clone()).unwrap();
    assert_eq!(e.exposure(), Amount(700), "max(600, 700), not 1300");
    assert_eq!(e.auth.exposure(&vault(), &BudgetKey::NativeFee { network_id: net() }, DAY).unwrap(), Amount(20));
    let rid_bump = reservation_id_for(&f.operation_family_id, &bump.candidate_id, 1).unwrap();
    assert!(matches!(e.auth.reservation(&rid_bump).unwrap().claim_mode, ExposureClaimMode::MutuallyExclusiveWithFamily { .. }));
    assert_eq!(e.auth.family(&f.operation_family_id).unwrap().lifecycle, LifecycleState::ReplacementPending);
    // same (sender, nonce): the replacement may be released while the original is outstanding
    e.auth.release(e.release_req(&bump)).unwrap();
    // another family cannot use the nonce
    let g = e.register(2);
    assert_eq!(code(e.auth.reserve(e.request(&g, "c-g", 1, evm_claims(5, 1, 1)))), ErrorCode::ResourceConflict);
    // replacement lands: original definitively invalid, 700 settled, nonce free
    e.auth
        .record_observation(
            &f.operation_family_id,
            &bump.candidate_id,
            ChainObservation::Finalized {
                tx_id: ChainTxId::unchecked("0xb"),
                state: StateReference { height: 2, hash: Bytes(vec![2; 32]), commitment: "finalized".into() },
                execution_success: true,
                fee_paid: Amount(15),
                effects_hash: Hash32::ZERO,
            },
        )
        .unwrap();
    let rid_orig = reservation_id_for(&f.operation_family_id, &orig.candidate_id, 1).unwrap();
    assert!(matches!(e.auth.reservation(&rid_orig).unwrap().state, ReservationState::Invalidated { issuance_id: Some(_) }));
    assert_eq!(e.view(), (Amount(700), Amount(0)));
    assert!(e.store.snapshot().resource_locks.is_empty());
    // the family has paid: no further release in it
    let late = e.request(&f, "c-late", 1, evm_claims(6, 100, 1));
    e.auth.reserve(late.clone()).unwrap();
    assert_eq!(code(e.auth.release(e.release_req(&late))), ErrorCode::Conflict);
}

#[test]
fn solana_rebuilt_blockhash_candidates_are_summed() {
    let e = setup();
    let f = e.register(1);
    let a = e.request(&f, "s-a", 1, solana_claims(1, 600));
    let b = e.request(&f, "s-b", 1, solana_claims(2, 700));
    e.auth.reserve(a.clone()).unwrap();
    assert_eq!(code(e.auth.reserve(b)), ErrorCode::BudgetExceeded, "600 + 700 > 1000: no exclusivity proof");
    let b_small = e.request(&f, "s-b", 1, solana_claims(2, 400));
    e.auth.reserve(b_small.clone()).unwrap();
    assert_eq!(e.exposure(), Amount(1000));
    // A23: after `a` is possibly issued, a fresh-blockhash retry cannot be released
    e.auth.release(e.release_req(&a)).unwrap();
    assert_eq!(code(e.auth.release(e.release_req(&b_small))), ErrorCode::IssuanceUncertain);
}

#[test]
fn reserve_validation_fails_closed() {
    let e = setup();
    let f = e.register(1);
    let base = e.request(&f, "c1", 1, evm_claims(1, 100, 1));

    let mut r = base.clone();
    r.policy_decision = Decision::Deny { reasons: vec![] };
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::PolicyDenied);
    let mut r = base.clone();
    r.policy_decision = Decision::RequireApprovals { rule_id: "r-ops".into(), required: 1, satisfied: 0, roles: vec![], reasons: vec![] };
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::ApprovalRequired);
    let mut r = base.clone();
    r.policy_decision = Decision::Allow { rule_id: "nope".into() };
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::PolicyDenied);
    let mut r = base.clone();
    r.exposure_limits = vec![(usdc(), ExposureLimit { window_seconds: DAY, max_outflow_base_units: Amount(u128::MAX) })];
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::InvalidRequest, "caller cannot substitute limits");
    let mut r = base.clone();
    r.claims = evm_claims(1, 1001, 1);
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::PolicyDenied, "per-operation maximum");
    let mut r = base.clone();
    r.claims = evm_claims(1, 100, 101);
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::PolicyDenied, "fee maximum");
    let mut r = base.clone();
    r.claims.resources.push(r.claims.resources[0].clone());
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::InvalidRequest);
    let mut r = base.clone();
    r.issuance_deadline = e.clock.now();
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::InvalidRequest);
    let mut r = base.clone();
    r.vault_id = VaultId::unchecked("vault-other");
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::ScopeMismatch);
    let mut r = base.clone();
    r.intent_id = IntentId::unchecked("intent-unknown");
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::NotFound);
    let g = e.register(2);
    let mut r = base.clone();
    r.family_id = g.operation_family_id.clone();
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::Conflict);
    // grants must bind this intent
    let mut r = base.clone();
    r.grants = vec![ApprovalGrant {
        body: ApprovalGrantBody {
            grant_id: GrantId::unchecked("g"),
            institution_id: inst(),
            environment_id: env(),
            vault_id: vault(),
            intent_id: IntentId::unchecked("intent-2"),
            intent_hash: Hash32::ZERO,
            policy_id: PolicyId::unchecked("pol-1"),
            policy_epoch: Epoch(1),
            scope: GrantScope::ExactCandidate { candidate_id: CandidateId::unchecked("c1"), candidate_revision: 1, preview_hash: Hash32::ZERO },
            approver_credential_id: CredentialId::unchecked("cred-a"),
            approver_role: ApprovalRole::TreasuryApprover,
            issued_at: UnixSeconds(T0),
            expires_at: UnixSeconds(T0 + 100),
        },
        signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(vec![0; 64]) },
    }];
    assert_eq!(code(e.auth.reserve(r)), ErrorCode::ScopeMismatch);
    // nothing above changed state
    assert!(e.store.snapshot().reservations.is_empty());
    e.auth.reserve(base).unwrap();
}

#[test]
fn fencing_stale_writer_is_rejected() {
    let clock = Arc::new(ManualClock::new(T0));
    let store = Arc::new(InMemoryAuthorityStore::new());
    let first = Authority::open(store.clone(), 0, config(), authority_key(), clock.clone()).unwrap();
    first.set_policy(&policy(1, &[1, 2])).unwrap();
    let i = intent(1);
    let reg = first.register_intent(&i, intent_hash(&i).unwrap(), IdempotencyKey { institution_id: inst(), route: "r".into(), key: "k".into() }).unwrap();
    // a stale controller cannot open with an outdated expectation
    assert_eq!(code(Authority::open(store.clone(), 0, config(), authority_key(), clock.clone())), ErrorCode::AuthorityUnavailable);
    let second = Authority::open(store.clone(), first.fence_token(), config(), authority_key(), clock.clone()).unwrap();
    assert_eq!(second.fence_token(), first.fence_token() + 1);
    let before = store.snapshot();
    let i2 = intent(2);
    let e = first.register_intent(&i2, intent_hash(&i2).unwrap(), IdempotencyKey { institution_id: inst(), route: "r".into(), key: "k2".into() }).unwrap_err();
    assert_eq!(e.code, ErrorCode::AuthorityUnavailable);
    assert!(e.detail.contains("fenced"));
    assert_eq!(code(first.set_policy(&policy(2, &[1, 2]))), ErrorCode::AuthorityUnavailable);
    assert_eq!(code(first.checkpoint()), ErrorCode::AuthorityUnavailable);
    assert_eq!(code(first.exposure_view(&vault(), &[usdc()], &[DAY], clock.now())), ErrorCode::AuthorityUnavailable);
    assert_eq!(store.snapshot(), before);
    // the new writer proceeds
    let (epoch, hash) = second.current_policy().unwrap();
    let claims = evm_claims(0, 10, 1);
    second
        .reserve(ReserveRequest {
            family_id: reg.operation_family_id.clone(),
            candidate_id: CandidateId::unchecked("c"),
            candidate_revision: 1,
            vault_id: vault(),
            intent_id: reg.intent_id.clone(),
            policy_epoch: epoch,
            policy_hash: hash,
            exposure_limits: vec![(usdc(), rule().rolling_limits[0].clone())],
            claims,
            grants: vec![],
            envelope_body_hash: Hash32([1; 32]),
            signer_session_id: SigningSessionId::unchecked("s"),
            issuance_deadline: UnixSeconds(T0 + 60),
            policy_decision: Decision::Allow { rule_id: "r-ops".into() },
        })
        .unwrap();
    assert_eq!(store.snapshot().epoch, Epoch(2), "authority epoch bumped per writer generation");
}

#[test]
fn checkpoints_sign_state() {
    let e = setup();
    let f = e.register(1);
    e.auth.reserve(e.request(&f, "c1", 1, evm_claims(1, 10, 1))).unwrap();
    let cp = e.auth.checkpoint().unwrap();
    verify_checkpoint(&cp, &e.auth.verifying_key()).unwrap();
    assert_eq!(cp.body.commit_sequence, e.store.snapshot().commit_sequence);
    assert_eq!(cp.body.state_hash, state_hash(&e.store.snapshot()).unwrap());
    let mut bad = cp.clone();
    bad.body.commit_sequence -= 1;
    assert_eq!(code(verify_checkpoint(&bad, &e.auth.verifying_key())), ErrorCode::InvalidSignature);
    assert_eq!(code(verify_checkpoint(&cp, &SigningKey::from_bytes(&[3; 32]).verifying_key())), ErrorCode::InvalidSignature);
}

#[test]
fn audit_events_are_emitted_in_commit_order() {
    let clock = Arc::new(ManualClock::new(T0));
    let sink = Arc::new(MemoryAuditSink::default());
    let auth = Authority::open(Arc::new(InMemoryAuthorityStore::new()), 0, config(), authority_key(), clock).unwrap().with_audit(sink.clone());
    auth.set_policy(&policy(1, &[1, 2])).unwrap();
    let ev = sink.events();
    assert!(matches!(ev.as_slice(), [AuthorityEvent::PolicyActivated { policy_epoch: Epoch(1), .. }]));
}

// ---------------------------------------------------------------------------
// File-backed store: crash/restart round trip and rollback refusal (A12/A13)

struct TempDir(PathBuf);
impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("oic-authz-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn file_authority(path: &std::path::Path, fence: u64, clock: Arc<ManualClock>) -> OicResult<Authority<FileAuthorityStore>> {
    Authority::open(Arc::new(FileAuthorityStore::open(path, None)?), fence, config(), authority_key(), clock)
}

#[test]
fn file_store_round_trip_and_rollback_refusal() {
    let dir = TempDir::new("roundtrip");
    let path = dir.0.join("authority.state");
    let clock = Arc::new(ManualClock::new(T0));
    let i = intent(1);
    let key = IdempotencyKey { institution_id: inst(), route: "r".into(), key: "k".into() };

    let (reg, rid) = {
        let a = file_authority(&path, 0, clock.clone()).unwrap();
        a.set_policy(&policy(1, &[1, 2])).unwrap();
        let reg = a.register_intent(&i, intent_hash(&i).unwrap(), key.clone()).unwrap();
        let (epoch, hash) = a.current_policy().unwrap();
        let req = ReserveRequest {
            family_id: reg.operation_family_id.clone(),
            candidate_id: CandidateId::unchecked("c1"),
            candidate_revision: 1,
            vault_id: vault(),
            intent_id: reg.intent_id.clone(),
            policy_epoch: epoch,
            policy_hash: hash,
            exposure_limits: vec![(usdc(), rule().rolling_limits[0].clone())],
            claims: evm_claims(1, 400, 1),
            grants: vec![],
            envelope_body_hash: Hash32([4; 32]),
            signer_session_id: SigningSessionId::unchecked("s1"),
            issuance_deadline: UnixSeconds(T0 + 600),
            policy_decision: Decision::Allow { rule_id: "r-ops".into() },
        };
        let (res, _) = a.reserve(req).unwrap();
        (reg, res.reservation_id)
    };
    let old_snapshot = std::fs::read(&path).unwrap();
    let old_state = FileAuthorityStore::open(&path, None).unwrap().snapshot();

    // "crash" and restart: everything durable is back; idempotency preserved
    let witness = {
        let a = file_authority(&path, 1, clock.clone()).unwrap();
        assert!(matches!(a.reservation(&rid).unwrap().state, ReservationState::Reserved));
        let again = a.register_intent(&i, intent_hash(&i).unwrap(), key.clone()).unwrap();
        assert_eq!(again.operation_family_id, reg.operation_family_id);
        assert!(!again.created);
        a.release(ReleaseRequest {
            reservation_id: rid.clone(),
            reservation_version: 1,
            envelope_body_hash: Hash32([4; 32]),
            signer_session_id: SigningSessionId::unchecked("s1"),
            expected_policy_epoch: Epoch(1),
            freshness: FreshnessContext { now: clock.now() },
        })
        .unwrap();
        a.checkpoint().unwrap()
    };
    let newest = FileAuthorityStore::open(&path, None).unwrap().snapshot();
    assert!(newest.commit_sequence > old_state.commit_sequence);
    assert_eq!(newest.issuance.len(), 1);

    // rollback: restore the old snapshot file -> high-water mark refuses it
    let new_snapshot = std::fs::read(&path).unwrap();
    std::fs::write(&path, &old_snapshot).unwrap();
    assert_eq!(code(FileAuthorityStore::open(&path, None)), ErrorCode::RecoveryRequired);
    // attacker also deletes the sidecar: an explicit minimum or the witness still refuses
    std::fs::remove_file(dir.0.join("authority.state.hwm")).unwrap();
    FileAuthorityStore::open(&path, None).unwrap();
    assert_eq!(code(FileAuthorityStore::open(&path, Some(newest.commit_sequence))), ErrorCode::RecoveryRequired);
    let pk = authority_key().verifying_key();
    assert_eq!(code(FileAuthorityStore::open_with_witness(&path, &witness, &pk)), ErrorCode::RecoveryRequired);
    // the genuine latest snapshot is accepted by the witness
    std::fs::write(&path, &new_snapshot).unwrap();
    let ok = FileAuthorityStore::open_with_witness(&path, &witness, &pk).unwrap();
    assert_eq!(ok.snapshot(), newest);
    // a forged witness is rejected
    let mut forged = witness.clone();
    forged.body.commit_sequence += 100;
    assert_eq!(code(FileAuthorityStore::open_with_witness(&path, &forged, &pk)), ErrorCode::InvalidSignature);
    // same sequence but different content -> divergence detected
    let mut diverged = newest.clone();
    diverged.ledger.push(LedgerEntry {
        vault_id: vault(),
        budget: BudgetKey::Asset { asset_id: usdc() },
        amount: Amount(1),
        at: UnixSeconds(T0),
        reservation_id: rid,
    });
    drop(ok);
    let fake_dir = TempDir::new("diverged");
    let fake = fake_dir.0.join("authority.state");
    {
        let s = FileAuthorityStore::open(&fake, None).unwrap();
        s.transact(|st| {
            *st = diverged.clone();
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(code(FileAuthorityStore::open_with_witness(&fake, &witness, &pk)), ErrorCode::RecoveryRequired);
    // corrupted snapshot is a recovery condition, not a silent reset
    std::fs::write(&path, b"garbage").unwrap();
    assert_eq!(code(FileAuthorityStore::open(&path, None)), ErrorCode::RecoveryRequired);
}

#[test]
fn file_store_deleted_snapshot_is_detected() {
    let dir = TempDir::new("deleted");
    let path = dir.0.join("authority.state");
    let clock = Arc::new(ManualClock::new(T0));
    {
        let a = file_authority(&path, 0, clock.clone()).unwrap();
        a.set_policy(&policy(1, &[1, 2])).unwrap();
    }
    std::fs::remove_file(&path).unwrap();
    assert_eq!(code(FileAuthorityStore::open(&path, None)), ErrorCode::RecoveryRequired);
}
