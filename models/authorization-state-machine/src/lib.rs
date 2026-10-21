//! # oic-model-authorization-state
//!
//! Stateright model check of the **real** [`Authority`] (RFC 0001 §16: "use
//! model checking for reservation/issuance/freeze/replacement state
//! transitions"). The model does not re-implement the authority: each model
//! state is the canonical encoding of an [`AuthorityState`] plus the clock,
//! and each action is a call on a fresh `Authority` opened over an
//! in-memory store holding that state. A call that returns an error leaves
//! the state unchanged (no transition).
//!
//! Universe: one vault, one asset budget (limit 100 over a 1000 s window),
//! one native resource (EVM sender/nonce 0) and two operation families:
//!
//! * family 1: candidate `f1-a` (60) and same-nonce replacement `f1-b` (70)
//! * family 2: candidate `f2-a` (40), competing for the same nonce
//!
//! Properties:
//! * **P1** settled-in-window + outstanding never exceeds the limit;
//! * **P2** a possibly issued candidate never loses its exposure except via
//!   finalization or definitive invalidation;
//! * **P3** no two families hold the same resource simultaneously;
//! * **P4** no release is committed after a freeze that is in force;
//! * **P5** abort after possibly issued is impossible.
//!
//! The harness reopens the writer for every step (fencing is exercised by
//! the authority's own tests); the writer generation, authority epoch, and
//! the reopen's own commit are normalized out of the model state so that
//! equivalent states deduplicate.
//!
//! The separate [`replication`] model extends RFC003 with finalized-prefix
//! delivery, local halt/restart, and roster epochs under explicit assumptions.

pub mod replication;

use ed25519_dalek::{Signer, SigningKey};
use oic_authorization_state::*;
use oic_canonical_encoding::canonical_bytes;
use oic_domain_types::*;
use oic_policy_kernel::{intent_hash, policy_hash, Decision};
use stateright::{Model, Property};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

pub const T0: u64 = 1_700_000_000;
pub const LIMIT: u128 = 100;
pub const WINDOW: u64 = 1_000;
pub const TICK: u64 = 500;
pub const MAX_TICKS: u64 = 2;
pub const DEADLINE: u64 = 600;

/// Candidates in the universe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cand {
    F1a,
    F1b,
    F2a,
}

impl Cand {
    pub const ALL: [Cand; 3] = [Cand::F1a, Cand::F1b, Cand::F2a];
    fn family(self) -> u32 {
        match self {
            Cand::F1a | Cand::F1b => 1,
            Cand::F2a => 2,
        }
    }
    fn id(self) -> CandidateId {
        CandidateId::unchecked(match self {
            Cand::F1a => "f1-a",
            Cand::F1b => "f1-b",
            Cand::F2a => "f2-a",
        })
    }
    fn amount(self) -> u128 {
        match self {
            Cand::F1a => 60,
            Cand::F1b => 70,
            Cand::F2a => 40,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    Reserve(Cand),
    Release(Cand),
    Abort(Cand),
    Freeze,
    Unfreeze,
    Finalize(Cand, bool),
    Invalidate(Cand),
    ExpireApprovals,
    Tick,
}

/// Model state: canonical authority state + clock + property bits.
///
/// `violations` accumulates transition checks (history) and state-invariant
/// checks evaluated once when the state is created; `reached` records
/// reachability targets. Both are functions of the path/state, so they never
/// split otherwise-equal states when the implementation is correct.
#[derive(Clone)]
pub struct ModelState {
    pub snapshot: Vec<u8>,
    pub now: u64,
    pub violations: u8,
    pub reached: u8,
    /// Decoded form of `snapshot` (a cache; excluded from equality and hashing).
    decoded: Arc<AuthorityState>,
}

impl ModelState {
    fn new(state: AuthorityState, now: u64, violations: u8, reached: u8) -> Self {
        ModelState { snapshot: encode(&state), now, violations, reached, decoded: Arc::new(state) }
    }

    /// The authority state this model state stands for.
    pub fn state(&self) -> &AuthorityState {
        &self.decoded
    }
}

impl PartialEq for ModelState {
    fn eq(&self, o: &Self) -> bool {
        self.snapshot == o.snapshot && self.now == o.now && self.violations == o.violations && self.reached == o.reached
    }
}

impl Eq for ModelState {}

impl std::hash::Hash for ModelState {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        self.snapshot.hash(h);
        self.now.hash(h);
        self.violations.hash(h);
        self.reached.hash(h);
    }
}

impl std::fmt::Debug for ModelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.state();
        f.debug_struct("ModelState")
            .field("now", &self.now)
            .field("violations", &self.violations)
            .field("commit_sequence", &st.commit_sequence)
            .field("reservations", &st.reservations.values().map(|r| (r.reservation.candidate_id.as_str(), &r.state)).collect::<Vec<_>>())
            .field("ledger", &st.ledger.iter().map(|e| (&e.budget, e.amount, e.at)).collect::<Vec<_>>())
            .field("freeze", &st.freeze)
            .finish()
    }
}

const V_P1: u8 = 1;
const V_P2: u8 = 2;
const V_P3: u8 = 4;
const V_P4: u8 = 8;
const V_P5: u8 = 16;

const R_RELEASE: u8 = 1;
const R_REPLACEMENT: u8 = 2;
const R_FROZEN_RETAINED: u8 = 4;
const R_BOTH_SETTLED: u8 = 8;

/// State invariants P1–P4 evaluated on one authority state.
fn invariant_violations(st: &AuthorityState, now: u64) -> u8 {
    let mut v = 0;
    if !p1_holds(st, now) {
        v |= V_P1;
    }
    if !p2_holds(st) {
        v |= V_P2;
    }
    if !p3_holds(st) {
        v |= V_P3;
    }
    if !p4_holds(st) {
        v |= V_P4;
    }
    v
}

fn reached(st: &AuthorityState) -> u8 {
    let mut r = 0;
    if !st.issuance.is_empty() {
        r |= R_RELEASE;
    }
    if possibly_issued(st).len() >= 2 {
        r |= R_REPLACEMENT;
    }
    if st.freeze.global_freeze.is_some() && st.reservations.values().any(|x| matches!(x.state, ReservationState::Released { .. })) {
        r |= R_FROZEN_RETAINED;
    }
    let settled: BTreeSet<_> = st.reservations.values().filter(|x| matches!(x.state, ReservationState::Settled { .. })).map(|x| &x.reservation.operation_family_id).collect();
    if settled.len() == 2 {
        r |= R_BOTH_SETTLED;
    }
    r
}


/// The model. Stateless apart from fixed key material.
#[derive(Clone, Debug, Default)]
pub struct AuthorityModel;

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
    AssetId::unchecked("usdc")
}
fn net() -> NetworkId {
    NetworkId::unchecked("evm-test")
}
fn admin(n: u8) -> (CredentialId, SigningKey) {
    (CredentialId::unchecked(format!("admin-{n}")), SigningKey::from_bytes(&[n; 32]))
}
fn responder() -> (CredentialId, SigningKey) {
    (CredentialId::unchecked("responder"), SigningKey::from_bytes(&[77; 32]))
}
fn cred_sig(who: &(CredentialId, SigningKey), h: &Hash32) -> CredentialSignature {
    CredentialSignature {
        credential_id: who.0.clone(),
        signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(who.1.sign(&h.0).to_bytes().to_vec()) },
    }
}

fn config() -> AuthorityConfig {
    static CONFIG: OnceLock<AuthorityConfig> = OnceLock::new();
    CONFIG
        .get_or_init(|| AuthorityConfig {
            institution_id: inst(),
            environment_id: env(),
            authority_key_id: KeyId::unchecked("authority"),
            admin_keys: (1..=2).map(admin).map(|(c, k)| (c, k.verifying_key())).collect(),
            admin_quorum: 2,
            freeze_responders: vec![(responder().0, responder().1.verifying_key())],
            release_receipt_ttl_seconds: 60,
            max_clock_skew_seconds: 30,
        })
        .clone()
}

fn authority_key() -> SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| SigningKey::from_bytes(&[42; 32])).clone()
}

fn limit() -> ExposureLimit {
    ExposureLimit { window_seconds: WINDOW, max_outflow_base_units: Amount(LIMIT) }
}

fn policy() -> PolicyBundle {
    let mut b = PolicyBundle {
        policy_id: PolicyId::unchecked("pol"),
        policy_epoch: Epoch(1),
        institution_id: inst(),
        environment_id: env(),
        rules: vec![PolicyRule {
            rule_id: "auto".into(),
            vaults: vec![vault()],
            assets: vec![usdc()],
            destinations: vec![],
            purposes: vec![],
            max_amount_per_operation: Amount(LIMIT),
            max_native_fee_per_operation: Amount(10),
            rolling_limits: vec![limit()],
            required_approvals: 0,
            approval_roles: vec![ApprovalRole::Automated],
            exclude_proposer: true,
            operating_window: None,
        }],
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 60,
        allowlist_version: 1,
        activation_epoch: Epoch(1),
        administrative_signatures: vec![],
    };
    let h = policy_hash(&b).expect("policy hash");
    b.administrative_signatures = vec![cred_sig(&admin(1), &h), cred_sig(&admin(2), &h)];
    b
}

fn intent(n: u32) -> Intent {
    Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked(format!("intent-{n}")),
        institution_id: inst(),
        environment_id: env(),
        vault_id: vault(),
        chain_wallet_id: ChainWalletId::unchecked("wallet"),
        chain_profile_id: ChainProfileId::unchecked("evm-test-v1"),
        operation: IntentOperation::AssetTransfer {
            asset_id: usdc(),
            amount_base_units: Amount(1),
            destination_id: DestinationId::unchecked("dest"),
            destination_version: 1,
        },
        constraints: IntentConstraints { max_network_fee_base_units: Amount(10), approval_mode: ApprovalMode::BoundedDirectTransfer, maximum_successful_payments: 1 },
        purpose: OperationPurpose::Settlement,
        external_reference: format!("ref-{n}"),
        proposer_credential_id: CredentialId::unchecked("proposer"),
        created_at: UnixSeconds(T0),
    }
}

fn family(n: u32) -> OperationFamilyId {
    family_id_for(&IntentId::unchecked(format!("intent-{n}"))).expect("family id")
}

/// The single shared native resource.
pub fn the_resource() -> NativeResource {
    NativeResource::EvmNonce { network_id: net(), sender: Bytes(vec![0xcc; 20]), nonce: 0 }
}

fn claims(c: Cand) -> ResourceClaims {
    ResourceClaims {
        resources: vec![the_resource()],
        asset_outflows: vec![AssetOutflow { asset_id: usdc(), amount_base_units: Amount(c.amount()) }],
        native_fees: vec![NativeFee { network_id: net(), amount_base_units: Amount(5) }],
    }
}

fn envelope(c: Cand) -> Hash32 {
    oic_canonical_encoding::sha256(c.id().as_str().as_bytes())
}

fn session(c: Cand) -> SigningSessionId {
    SigningSessionId::unchecked(format!("sess-{}", c.id()))
}

fn rid(c: Cand) -> ReservationId {
    reservation_id_for(&family(c.family()), &c.id(), 1).expect("reservation id")
}

fn encode(st: &AuthorityState) -> Vec<u8> {
    canonical_bytes(st).expect("authority state is canonically encodable")
}

/// Open a writer over `state`, run `f`, and return the normalized post-state.
fn step(state: AuthorityState, now: u64, f: impl FnOnce(&Authority<InMemoryAuthorityStore>, &ManualClock) -> OicResult<()>) -> OicResult<AuthorityState> {
    let (fence, epoch) = (state.fence_token, state.epoch);
    let store = Arc::new(InMemoryAuthorityStore::from_state(state));
    let clock = Arc::new(ManualClock::new(now));
    let auth = Authority::open(store.clone(), fence, config(), authority_key(), clock.clone())?;
    f(&auth, &clock)?;
    let mut post = store.snapshot();
    post.fence_token = fence;
    post.epoch = epoch;
    post.commit_sequence -= 1; // elide the reopen's own commit
    Ok(post)
}

impl AuthorityModel {
    fn apply(&self, st: AuthorityState, now: u64, action: Action) -> OicResult<AuthorityState> {
        step(st, now, |a, clock| {
            match action {
                Action::Reserve(c) => {
                    let (epoch, hash) = a.current_policy()?;
                    a.reserve(ReserveRequest {
                        family_id: family(c.family()),
                        candidate_id: c.id(),
                        candidate_revision: 1,
                        vault_id: vault(),
                        intent_id: IntentId::unchecked(format!("intent-{}", c.family())),
                        policy_epoch: epoch,
                        policy_hash: hash,
                        claims: claims(c),
                        grants: vec![],
                        envelope_body_hash: envelope(c),
                        signer_session_id: session(c),
                        issuance_deadline: UnixSeconds(clock.now().0 + DEADLINE),
                        policy_decision: Decision::Allow { rule_id: "auto".into() },
                        exposure_limits: vec![(usdc(), limit())],
                    })?;
                }
                Action::Release(c) => {
                    let (epoch, _) = a.current_policy()?;
                    a.release(ReleaseRequest {
                        reservation_id: rid(c),
                        reservation_version: 1,
                        envelope_body_hash: envelope(c),
                        signer_session_id: session(c),
                        expected_policy_epoch: epoch,
                        freshness: FreshnessContext { now: clock.now() },
                    })?;
                }
                Action::Abort(c) => {
                    a.abort_before_issuance(&rid(c))?;
                }
                Action::Freeze => {
                    let r = responder();
                    let h = FreezeProposal::new(inst(), env(), FreezeScope::Global, r.0.clone(), "drill").hash()?;
                    a.freeze(FreezeScope::Global, r.0.clone(), "drill", &cred_sig(&r, &h).signature)?;
                }
                Action::Unfreeze => {
                    let rec = a.freeze_record(&FreezeScope::Global)?.ok_or_else(|| OicError::new(ErrorCode::NotFound, "not frozen"))?;
                    let h = UnfreezeProposal::new(inst(), env(), FreezeScope::Global, rec.at_commit_sequence).hash()?;
                    a.unfreeze(FreezeScope::Global, &[cred_sig(&admin(1), &h), cred_sig(&admin(2), &h)])?;
                }
                Action::Finalize(c, success) => {
                    a.record_observation(
                        &family(c.family()),
                        &c.id(),
                        ChainObservation::Finalized {
                            tx_id: ChainTxId::unchecked(format!("tx-{}", c.id())),
                            state: StateReference { height: 1, hash: Bytes(vec![1; 32]), commitment: "finalized".into() },
                            execution_success: success,
                            fee_paid: Amount(3),
                            effects_hash: Hash32::ZERO,
                        },
                    )?;
                }
                Action::Invalidate(c) => {
                    a.record_observation(
                        &family(c.family()),
                        &c.id(),
                        ChainObservation::DefinitivelyInvalidated {
                            reason: "nonce consumed elsewhere".into(),
                            state: StateReference { height: 1, hash: Bytes(vec![1; 32]), commitment: "finalized".into() },
                        },
                    )?;
                }
                Action::ExpireApprovals => {
                    if a.expire_approvals()?.is_empty() {
                        return Err(OicError::new(ErrorCode::NotFound, "nothing expired"));
                    }
                }
                Action::Tick => return Err(OicError::invalid_request("tick advances the model clock, not the authority")),
            }
            Ok(())
        })
    }

    fn initial() -> ModelState {
        let state = step(AuthorityState::default(), T0, |a, _| {
            a.set_policy(&policy())?;
            for n in 1..=2 {
                let i = intent(n);
                a.register_intent(&i, intent_hash(&i)?, IdempotencyKey { institution_id: inst(), route: "POST /v1/intents".into(), key: format!("k{n}") })?;
            }
            Ok(())
        })
        .expect("model initial state");
        let (v, r) = (invariant_violations(&state, T0), reached(&state));
        ModelState::new(state, T0, v, r)
    }
}

fn possibly_issued(st: &AuthorityState) -> BTreeSet<ReservationId> {
    st.reservations.iter().filter(|(_, r)| r.state.possibly_issued()).map(|(id, _)| id.clone()).collect()
}

/// Transition checks comparing the pre- and post-state of one real API call.
fn transition_violations(pre: &AuthorityState, post: &AuthorityState, action: Action) -> u8 {
    let mut v = 0;
    for id in possibly_issued(pre) {
        let after = &post.reservations[&id].state;
        let before = &pre.reservations[&id].state;
        // P5: never aborted once possibly issued.
        if matches!(after, ReservationState::Aborted { .. }) {
            v |= V_P5;
        }
        // P2: exposure leaves an outstanding reservation only via chain evidence.
        if before.is_active() && !after.is_active() && !matches!(action, Action::Finalize(..) | Action::Invalidate(_)) {
            v |= V_P2;
        }
        if !after.possibly_issued() {
            v |= V_P2;
        }
    }
    // P4: a release committed while a freeze was in force.
    if pre.freeze.blocking(&vault()).is_some() && post.issuance.len() > pre.issuance.len() {
        v |= V_P4;
    }
    v
}

fn p1_holds(st: &AuthorityState, now: u64) -> bool {
    st.exposure(&vault(), &BudgetKey::Asset { asset_id: usdc() }, WINDOW, UnixSeconds(now)).is_some_and(|e| e.0 <= LIMIT)
}

fn p2_holds(st: &AuthorityState) -> bool {
    // Every issuance record's reservation is still outstanding or resolved by chain evidence.
    st.issuance.values().all(|i| {
        st.reservations.values().any(|r| {
            r.reservation.candidate_id == i.candidate_id
                && r.reservation.operation_family_id == i.operation_family_id
                && matches!(r.state, ReservationState::Released { .. } | ReservationState::Settled { .. } | ReservationState::Invalidated { issuance_id: Some(_) })
        })
    })
}

fn p3_holds(st: &AuthorityState) -> bool {
    let mut holders: BTreeMap<&NativeResource, BTreeSet<&OperationFamilyId>> = BTreeMap::new();
    for r in st.reservations.values().filter(|r| r.state.is_active()) {
        for res in &r.reservation.claims.resources {
            holders.entry(res).or_default().insert(&r.reservation.operation_family_id);
            if st.resource_locks.get(res) != Some(&r.reservation.operation_family_id) {
                return false;
            }
        }
    }
    holders.values().all(|f| f.len() <= 1)
}

fn p4_holds(st: &AuthorityState) -> bool {
    match st.freeze.blocking(&vault()) {
        Some(f) => st.issuance.values().all(|i| i.commit_sequence < f.at_commit_sequence),
        None => true,
    }
}

impl Model for AuthorityModel {
    type State = ModelState;
    type Action = Action;

    fn init_states(&self) -> Vec<ModelState> {
        vec![Self::initial()]
    }

    fn actions(&self, state: &ModelState, actions: &mut Vec<Action>) {
        // Candidates without a reservation can only be reserved (every other
        // call on them is a NotFound, covered by the authority's unit tests).
        // Reserved candidates get every call, including ones that must be
        // refused (abort after release, release while frozen, ...).
        let st = state.state();
        for c in Cand::ALL {
            actions.push(Action::Reserve(c));
            if !st.reservations.contains_key(&rid(c)) {
                continue;
            }
            actions.push(Action::Release(c));
            actions.push(Action::Abort(c));
            actions.push(Action::Finalize(c, true));
            actions.push(Action::Finalize(c, false));
            actions.push(Action::Invalidate(c));
        }
        // Re-freezing an already frozen scope only moves its commit point;
        // the model freezes from the unfrozen state and unfreezes when frozen.
        if st.freeze.global_freeze.is_some() {
            actions.push(Action::Unfreeze);
        } else {
            actions.push(Action::Freeze);
        }
        actions.push(Action::ExpireApprovals);
        if state.now < T0 + MAX_TICKS * TICK {
            actions.push(Action::Tick);
        }
    }

    fn next_state(&self, last: &ModelState, action: Action) -> Option<ModelState> {
        let pre = last.state();
        if action == Action::Tick {
            let now = last.now + TICK;
            let violations = last.violations | invariant_violations(pre, now);
            return Some(ModelState { now, violations, ..last.clone() });
        }
        // A rejected call leaves the authority unchanged: no transition.
        let post = self.apply(pre.clone(), last.now, action).ok()?;
        let violations = last.violations | transition_violations(pre, &post, action) | invariant_violations(&post, last.now);
        let r = reached(&post);
        Some(ModelState::new(post, last.now, violations, r))
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always("P1 outstanding + settled <= limit", |_, s: &ModelState| s.violations & V_P1 == 0),
            Property::always("P2 possibly issued keeps exposure until chain resolution", |_, s: &ModelState| s.violations & V_P2 == 0),
            Property::always("P3 no two families hold one resource", |_, s: &ModelState| s.violations & V_P3 == 0),
            Property::always("P4 no release after a freeze in force", |_, s: &ModelState| s.violations & V_P4 == 0),
            Property::always("P5 no abort after possibly issued", |_, s: &ModelState| s.violations & V_P5 == 0),
            // Reachability: the checker actually explores the interesting interleavings.
            Property::sometimes("reach: a release is committed", |_, s: &ModelState| s.reached & R_RELEASE != 0),
            Property::sometimes("reach: same-nonce replacement both possibly issued", |_, s: &ModelState| s.reached & R_REPLACEMENT != 0),
            Property::sometimes("reach: frozen with a prior release retained", |_, s: &ModelState| s.reached & R_FROZEN_RETAINED != 0),
            Property::sometimes("reach: both families settled", |_, s: &ModelState| s.reached & R_BOTH_SETTLED != 0),
        ]
    }
}

/// Outcome of one bounded exploration.
#[derive(Clone, Debug)]
pub struct CheckReport {
    pub max_depth: usize,
    pub state_count: usize,
    pub unique_state_count: usize,
}

/// Breadth-first exploration to `depth`, panicking (with a counterexample
/// path) if any property is violated or any reachability target is missed.
pub fn check(depth: usize) -> CheckReport {
    use stateright::Checker;
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let checker = AuthorityModel.checker().threads(threads).target_max_depth(depth).spawn_bfs().join();
    checker.assert_properties();
    CheckReport { max_depth: checker.max_depth(), state_count: checker.state_count(), unique_state_count: checker.unique_state_count() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_check_bounded() {
        let r = check(8);
        assert!(r.unique_state_count > 100, "{r:?}");
    }

    #[test]
    fn transition_checks_detect_violations() {
        // Sanity: the property functions reject a forged bad state.
        let m = AuthorityModel::initial();
        let mut st = m.state().clone();
        assert!(p1_holds(&st, T0) && p2_holds(&st) && p3_holds(&st) && p4_holds(&st));
        st.ledger.push(LedgerEntry { vault_id: vault(), budget: BudgetKey::Asset { asset_id: usdc() }, amount: Amount(LIMIT + 1), at: UnixSeconds(T0), reservation_id: rid(Cand::F1a) });
        assert!(!p1_holds(&st, T0));
        assert!(p1_holds(&st, T0 + WINDOW), "settled debit leaves the window");
        st.issuance.insert(
            IssuanceId::unchecked("iss-x"),
            IssuanceRecord {
                issuance_id: IssuanceId::unchecked("iss-x"),
                operation_family_id: family(1),
                candidate_id: Cand::F1a.id(),
                candidate_revision: 1,
                envelope_hash: Hash32::ZERO,
                signer_session_id: session(Cand::F1a),
                commit_sequence: 10,
                committed_at: UnixSeconds(T0),
            },
        );
        assert!(!p2_holds(&st), "issuance without an outstanding reservation");
        st.freeze.global_freeze = Some(FreezeRecord { at_commit_sequence: 9, by: responder().0, reason: "x".into() });
        assert!(!p4_holds(&st));
    }

    #[test]
    fn rejected_calls_do_not_transition() {
        let m = AuthorityModel::initial();
        // Releasing before reserving is rejected by the real authority.
        assert!(AuthorityModel.next_state(&m, Action::Release(Cand::F1a)).is_none());
        let reserved = AuthorityModel.next_state(&m, Action::Reserve(Cand::F1a)).expect("reserve");
        // The other family cannot take the nonce.
        assert!(AuthorityModel.next_state(&reserved, Action::Reserve(Cand::F2a)).is_none());
        // The same-family replacement can, charging max(60, 70) not 130.
        let both = AuthorityModel.next_state(&reserved, Action::Reserve(Cand::F1b)).expect("replacement");
        let st = both.state();
        assert_eq!(st.outstanding(&vault(), &BudgetKey::Asset { asset_id: usdc() }), Some(Amount(70)));
    }
}
