//! Deterministic authority transitions. No storage, clock reads, or signing keys.

use crate::authority_domains;
use crate::receipts::*;
use crate::state::*;
use ed25519_dalek::VerifyingKey;
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use oic_policy_kernel::{count_quorum_signatures, intent_hash, policy_hash, verify_policy_admin_signatures, Decision};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeSet;

/// Static configuration of one authority deployment.
#[derive(Clone, Debug)]
pub struct AuthorityConfig {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub authority_key_id: KeyId,
    /// Administrative credentials (policy activation, unfreeze).
    pub admin_keys: Vec<(CredentialId, VerifyingKey)>,
    pub admin_quorum: u8,
    /// Designated emergency responders; any one may freeze (§4.2).
    pub freeze_responders: Vec<(CredentialId, VerifyingKey)>,
    /// Lifetime of a release receipt (§5.4 step 6).
    pub release_receipt_ttl_seconds: u64,
    /// Maximum difference between a caller's freshness context and the authority clock.
    pub max_clock_skew_seconds: u64,
}

/// Audit events emitted after each committed configuration or issuance change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityEvent {
    Opened { fence_token: u64, authority_epoch: Epoch, commit_sequence: u64 },
    PolicyActivated { policy_epoch: Epoch, policy_hash: Hash32, commit_sequence: u64 },
    CredentialChanged { credential_id: CredentialId, active: bool, commit_sequence: u64 },
    ApprovalRecorded { intent_id: IntentId, credential_id: CredentialId, grant_id: GrantId, commit_sequence: u64 },
    Reserved { reservation_id: ReservationId, commit_sequence: u64 },
    Released { reservation_id: ReservationId, issuance_id: IssuanceId, commit_sequence: u64 },
    Frozen { scope: FreezeScope, by: CredentialId, commit_sequence: u64 },
    Unfrozen { scope: FreezeScope, commit_sequence: u64 },
    Aborted { reservation_id: ReservationId, reason: AbortReason, commit_sequence: u64 },
    Observed { family_id: OperationFamilyId, candidate_id: CandidateId, lifecycle: LifecycleState, commit_sequence: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredIntent {
    pub intent_id: IntentId,
    pub operation_family_id: OperationFamilyId,
    /// False when an idempotent repeat returned the existing operation.
    pub created: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveRequest {
    pub family_id: OperationFamilyId,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub vault_id: VaultId,
    pub intent_id: IntentId,
    pub policy_epoch: Epoch,
    pub policy_hash: Hash32,
    pub claims: ResourceClaims,
    pub grants: Vec<ApprovalGrant>,
    pub envelope_body_hash: Hash32,
    pub signer_session_id: SigningSessionId,
    pub issuance_deadline: UnixSeconds,
    /// The kernel's decision; must be `Allow`.
    pub policy_decision: Decision,
    /// Rolling limits of the matched rule per asset; must equal what the
    /// authority derives from its active policy.
    pub exposure_limits: Vec<(AssetId, ExposureLimit)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub reservation_id: ReservationId,
    pub reservation_version: u32,
    pub envelope_body_hash: Hash32,
    pub signer_session_id: SigningSessionId,
    pub expected_policy_epoch: Epoch,
    pub freshness: FreshnessContext,
}

/// Signed by one designated responder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeProposal {
    pub action: String,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub scope: FreezeScope,
    pub by: CredentialId,
    pub reason: String,
}

impl FreezeProposal {
    pub fn new(institution_id: InstitutionId, environment_id: EnvironmentId, scope: FreezeScope, by: CredentialId, reason: impl Into<String>) -> Self {
        FreezeProposal { action: "freeze".into(), institution_id, environment_id, scope, by, reason: reason.into() }
    }
    /// `SHA256("OIC/CONFIG_PROPOSAL/v1" || CanonicalEncode(self))`.
    pub fn hash(&self) -> OicResult<Hash32> {
        domain_hash(domains::CONFIG_PROPOSAL, self)
    }
}

/// Signed by the administrative quorum. Binds the specific freeze being
/// lifted, so an old unfreeze approval cannot lift a later freeze.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnfreezeProposal {
    pub action: String,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub scope: FreezeScope,
    pub freeze_commit_sequence: u64,
}

impl UnfreezeProposal {
    pub fn new(institution_id: InstitutionId, environment_id: EnvironmentId, scope: FreezeScope, freeze_commit_sequence: u64) -> Self {
        UnfreezeProposal { action: "unfreeze".into(), institution_id, environment_id, scope, freeze_commit_sequence }
    }
    pub fn hash(&self) -> OicResult<Hash32> {
        domain_hash(domains::CONFIG_PROPOSAL, self)
    }
}

fn derive_id(prefix: &str, parts: &impl Serialize) -> OicResult<String> {
    let h = domain_hash(authority_domains::AUTHORITY_ID, &(prefix, parts))?;
    Ok(format!("{prefix}-{}", hex::encode(&h.0[..16])))
}

/// Deterministic reservation identifier, computable by the coordinator before
/// reserving so the envelope body (which names it) can be hashed up front.
pub fn reservation_id_for(family_id: &OperationFamilyId, candidate_id: &CandidateId, candidate_revision: u32) -> OicResult<ReservationId> {
    Ok(ReservationId::unchecked(derive_id("res", &(family_id, candidate_id, candidate_revision))?))
}

/// Deterministic operation-family identifier for an intent.
pub fn family_id_for(intent_id: &IntentId) -> OicResult<OperationFamilyId> {
    Ok(OperationFamilyId::unchecked(derive_id("fam", intent_id)?))
}

fn issuance_id_for(reservation_id: &ReservationId) -> OicResult<IssuanceId> {
    Ok(IssuanceId::unchecked(derive_id("iss", reservation_id)?))
}

fn err(code: ErrorCode, detail: impl Into<String>) -> OicError {
    OicError::new(code, detail)
}

/// Exposure limits the active policy imposes on `claims` under `rule`: every
/// asset outflow in the rule's asset scope gets every rolling limit.
fn derived_limits(rule: &PolicyRule, claims: &ResourceClaims) -> Vec<(AssetId, ExposureLimit)> {
    let assets: BTreeSet<&AssetId> = claims.asset_outflows.iter().map(|o| &o.asset_id).collect();
    let mut out = Vec::new();
    for a in assets {
        if rule.assets.is_empty() || rule.assets.contains(a) {
            for l in &rule.rolling_limits {
                out.push((a.clone(), l.clone()));
            }
        }
    }
    out
}

fn limit_sort_key(l: &(AssetId, ExposureLimit)) -> (AssetId, u64, Amount) {
    (l.0.clone(), l.1.window_seconds, l.1.max_outflow_base_units)
}

/// Commands accepted by the existing authority state machine. These are Class C
/// data, not authenticated network requests. In particular, `Reserve` retains
/// D1's trusted-kernel-decision contract. A replicated application must verify
/// candidate bytes, grants, evidence, and policy itself before applying it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCommand {
    RegisterIntent { intent: Intent, intent_hash: Hash32, key: IdempotencyKey },
    SetPolicy { bundle: PolicyBundle },
    ChangeCredential { proposal: crate::CredentialChange, signatures: Vec<CredentialSignature> },
    Approve { intent: Box<Intent>, grant: ApprovalGrant },
    Reserve { request: ReserveRequest },
    Release { request: ReleaseRequest },
    Freeze { scope: FreezeScope, by: CredentialId, reason: String, signature: SignatureBytes },
    Unfreeze { scope: FreezeScope, signatures: Vec<CredentialSignature> },
    AbortBeforeIssuance { reservation_id: ReservationId },
    ApprovalExpired { reservation_id: ReservationId },
    ExpireApprovals,
    RecordObservation { family_id: OperationFamilyId, candidate_id: CandidateId, observation: ChainObservation },
}

impl std::fmt::Debug for AuthorityCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorityCommand([REDACTED])")
    }
}

/// Unsigned transition results. A receipt body is not release evidence: D1
/// signs it only after durable commit; D2 needs finalized-log verification.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityOutput {
    Registered(RegisteredIntent),
    Committed(u64),
    Reserved { reservation: Reservation, receipt: AuthorityReceiptBody },
    Released { receipt: AuthorityReceiptBody, issuance: IssuanceRecord },
    Expired(Vec<ReservationId>),
    Observed(LifecycleState),
}

impl std::fmt::Debug for AuthorityOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorityOutput([REDACTED])")
    }
}

/// Re-execute one command with explicit time. Consumes a private state value;
/// an error yields no successor or audit events. This function performs no I/O
/// and contains no receipt signing key. `config` must be trusted configuration.
pub fn apply(
    config: &AuthorityConfig,
    state: AuthorityState,
    command: AuthorityCommand,
    now: UnixSeconds,
) -> OicResult<(AuthorityState, AuthorityOutput, Vec<AuthorityEvent>)> {
    let transition = Transition { state: RefCell::new(state), config, now, events: RefCell::new(Vec::new()) };
    let output = match command {
        AuthorityCommand::RegisterIntent { intent, intent_hash, key } => AuthorityOutput::Registered(transition.register_intent(&intent, intent_hash, key)?),
        AuthorityCommand::SetPolicy { bundle } => AuthorityOutput::Committed(transition.set_policy(&bundle)?),
        AuthorityCommand::ChangeCredential { proposal, signatures } => {
            let (sequence, event) = transition.tx(|st, _| crate::approvals::change_credential(config, st, proposal, &signatures))?;
            transition.emit(event);
            AuthorityOutput::Committed(sequence)
        }
        AuthorityCommand::Approve { intent, grant } => {
            let (sequence, event) = transition.tx(|st, now| crate::approvals::approve(config, st, &intent, grant, now))?;
            transition.emit(event);
            AuthorityOutput::Committed(sequence)
        }
        AuthorityCommand::Reserve { request } => {
            let (reservation, receipt) = transition.reserve(request)?;
            AuthorityOutput::Reserved { reservation, receipt }
        }
        AuthorityCommand::Release { request } => {
            let (receipt, issuance) = transition.release(request)?;
            AuthorityOutput::Released { receipt, issuance }
        }
        AuthorityCommand::Freeze { scope, by, reason, signature } => AuthorityOutput::Committed(transition.freeze(scope, by, &reason, &signature)?),
        AuthorityCommand::Unfreeze { scope, signatures } => AuthorityOutput::Committed(transition.unfreeze(scope, &signatures)?),
        AuthorityCommand::AbortBeforeIssuance { reservation_id } => AuthorityOutput::Committed(transition.abort_before_issuance(&reservation_id)?),
        AuthorityCommand::ApprovalExpired { reservation_id } => AuthorityOutput::Committed(transition.approval_expired(&reservation_id)?),
        AuthorityCommand::ExpireApprovals => AuthorityOutput::Expired(transition.expire_approvals()?),
        AuthorityCommand::RecordObservation { family_id, candidate_id, observation } => {
            AuthorityOutput::Observed(transition.record_observation(&family_id, &candidate_id, observation)?)
        }
    };
    Ok((transition.state.into_inner(), output, transition.events.into_inner()))
}

// Interior mutability keeps validation/configuration reads separate from the
// one command's working state without a store or an externally visible mutation.
struct Transition<'a> {
    state: RefCell<AuthorityState>,
    config: &'a AuthorityConfig,
    now: UnixSeconds,
    events: RefCell<Vec<AuthorityEvent>>,
}

impl Transition<'_> {
    fn emit(&self, event: AuthorityEvent) {
        self.events.borrow_mut().push(event);
    }

    fn tx<R>(&self, f: impl FnOnce(&mut AuthorityState, UnixSeconds) -> OicResult<R>) -> OicResult<R> {
        f(&mut self.state.borrow_mut(), self.now)
    }

    fn commit(st: &mut AuthorityState) -> u64 {
        st.commit_sequence += 1;
        st.commit_sequence
    }

    fn receipt(
        &self,
        st: &AuthorityState,
        kind: ReceiptKind,
        rec: &ReservationRecord,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
        commit_sequence: u64,
    ) -> OicResult<AuthorityReceiptBody> {
        let intent = st.intents.get(&rec.intent_id).ok_or_else(|| OicError::internal("reservation names an unregistered intent"))?;
        let body = AuthorityReceiptBody {
            kind,
            institution_id: self.config.institution_id.clone(),
            environment_id: self.config.environment_id.clone(),
            authority_epoch: st.epoch,
            reservation_id: rec.reservation.reservation_id.clone(),
            reservation_version: rec.reservation.reservation_version,
            candidate_id: rec.reservation.candidate_id.clone(),
            candidate_revision: rec.reservation.candidate_revision,
            envelope_body_hash: rec.envelope_body_hash,
            signer_session_id: rec.signer_session_id.clone(),
            intent_hash: intent.intent_hash,
            rule_id: rec.rule_id.clone(),
            claims_hash: claims_hash(&rec.reservation.claims)?,
            policy_epoch: rec.reservation.policy_epoch,
            freeze_epoch: st.freeze.freeze_epoch,
            issued_at,
            expires_at,
            commit_sequence,
        };
        // Fail canonical encoding before a caller commits the successor state.
        receipt_hash(&body)?;
        Ok(body)
    }

    // -----------------------------------------------------------------------
    // Intents and policy
    // -----------------------------------------------------------------------

    /// Register an intent under an idempotency key (A07). Same key and same
    /// canonical body returns the existing operation; same key with a
    /// different body is a `Conflict`.
    pub fn register_intent(&self, intent: &Intent, intent_hash_claimed: Hash32, key: IdempotencyKey) -> OicResult<RegisteredIntent> {
        let ih = intent_hash(intent)?;
        if ih != intent_hash_claimed {
            return Err(OicError::invalid_request("intent hash does not match canonical intent body"));
        }
        if intent.institution_id != self.config.institution_id || intent.environment_id != self.config.environment_id {
            return Err(OicError::scope("intent belongs to another institution or environment"));
        }
        if key.institution_id != intent.institution_id {
            return Err(OicError::invalid_request("idempotency key institution differs from intent"));
        }
        self.tx(|st, _now| {
            if let Some(rec) = st.idempotency.get(&key) {
                if rec.request_hash != ih {
                    return Err(err(ErrorCode::Conflict, "idempotency key reused with a different request body"));
                }
                return Ok(RegisteredIntent { intent_id: rec.intent_id.clone(), operation_family_id: rec.operation_family_id.clone(), created: false });
            }
            if let Some(existing) = st.intents.get(&intent.intent_id) {
                if existing.intent_hash != ih {
                    return Err(err(ErrorCode::Conflict, "intent id already registered with a different body"));
                }
                let out = RegisteredIntent { intent_id: intent.intent_id.clone(), operation_family_id: existing.operation_family_id.clone(), created: false };
                st.idempotency.insert(
                    key,
                    IdempotencyRecord { request_hash: ih, intent_id: out.intent_id.clone(), operation_family_id: out.operation_family_id.clone() },
                );
                Self::commit(st);
                return Ok(out);
            }
            let family_id = family_id_for(&intent.intent_id)?;
            st.families.insert(
                family_id.clone(),
                FamilyRecord {
                    intent_id: intent.intent_id.clone(),
                    vault_id: intent.vault_id.clone(),
                    candidates: vec![],
                    lifecycle: LifecycleState::Draft,
                    quarantined: false,
                },
            );
            st.intents
                .insert(intent.intent_id.clone(), IntentRecord { intent_hash: ih, operation_family_id: family_id.clone(), vault_id: intent.vault_id.clone() });
            st.idempotency.insert(key, IdempotencyRecord { request_hash: ih, intent_id: intent.intent_id.clone(), operation_family_id: family_id.clone() });
            Self::commit(st);
            Ok(RegisteredIntent { intent_id: intent.intent_id.clone(), operation_family_id: family_id, created: true })
        })
    }

    /// Activate a policy bundle: an ordered configuration change requiring
    /// the administrative quorum over `policy_hash(bundle)` and a strictly
    /// increasing policy epoch (I6: stale or rolled-back epochs fail closed).
    pub fn set_policy(&self, bundle: &PolicyBundle) -> OicResult<u64> {
        verify_policy_admin_signatures(bundle, &self.config.admin_keys, self.config.admin_quorum)?;
        if bundle.institution_id != self.config.institution_id || bundle.environment_id != self.config.environment_id {
            return Err(OicError::scope("policy belongs to another institution or environment"));
        }
        if bundle.activation_epoch > bundle.policy_epoch {
            return Err(OicError::invalid_request("policy activation epoch is after its own epoch"));
        }
        let h = policy_hash(bundle)?;
        let seq = self.tx(|st, _| {
            if bundle.policy_epoch <= st.policy_epoch {
                return Err(err(ErrorCode::StalePolicy, format!("policy epoch {} is not newer than active {}", bundle.policy_epoch, st.policy_epoch)));
            }
            st.policy = Some(bundle.clone());
            st.policy_epoch = bundle.policy_epoch;
            st.policy_hash = h;
            Ok(Self::commit(st))
        })?;
        self.emit(AuthorityEvent::PolicyActivated { policy_epoch: bundle.policy_epoch, policy_hash: h, commit_sequence: seq });
        Ok(seq)
    }

    // -----------------------------------------------------------------------
    // Reserve (§5.4 steps 1–4)
    // -----------------------------------------------------------------------

    pub fn reserve(&self, req: ReserveRequest) -> OicResult<(Reservation, AuthorityReceiptBody)> {
        let reservation_id = reservation_id_for(&req.family_id, &req.candidate_id, req.candidate_revision)?;
        let (reservation, receipt, fresh) = self.tx(|st, now| {
            // 1. validation: freeze, policy epoch, decision, intent/family, grants, candidate.
            if st.freeze.blocking(&req.vault_id).is_some() {
                return Err(err(ErrorCode::Frozen, "vault or institution is frozen"));
            }
            let policy = st.policy.as_ref().ok_or_else(|| err(ErrorCode::StalePolicy, "no active policy"))?;
            if req.policy_epoch != st.policy_epoch || req.policy_hash != st.policy_hash {
                return Err(err(ErrorCode::StalePolicy, "request policy epoch/hash is not the active policy"));
            }
            let rule_id = match &req.policy_decision {
                Decision::Allow { rule_id } => rule_id.clone(),
                Decision::RequireApprovals { .. } => return Err(err(ErrorCode::ApprovalRequired, "policy decision requires approvals")),
                Decision::Deny { .. } => return Err(OicError::policy_denied("policy decision is deny")),
            };
            let rule =
                policy.rules.iter().find(|r| r.rule_id == rule_id).ok_or_else(|| OicError::policy_denied("decision names a rule not in the active policy"))?;
            let intent = st.intents.get(&req.intent_id).ok_or_else(|| err(ErrorCode::NotFound, "intent not registered"))?;
            if intent.operation_family_id != req.family_id {
                return Err(err(ErrorCode::Conflict, "operation family does not belong to intent"));
            }
            let family = st.families.get(&req.family_id).ok_or_else(|| err(ErrorCode::NotFound, "operation family not found"))?;
            if family.vault_id != req.vault_id || intent.vault_id != req.vault_id {
                return Err(OicError::scope("vault does not match intent"));
            }
            if family.quarantined {
                return Err(err(ErrorCode::IssuanceUncertain, "operation family quarantined by conflicting chain evidence"));
            }
            crate::approvals::require_recorded_grants(st, &req.grants, now)?;
            let mut approvers: Vec<&CredentialId> = Vec::new();
            for g in &req.grants {
                let b = &g.body;
                if b.intent_id != req.intent_id
                    || b.intent_hash != intent.intent_hash
                    || b.vault_id != req.vault_id
                    || b.policy_epoch != st.policy_epoch
                    || b.policy_id != policy.policy_id
                {
                    return Err(OicError::scope("grant not bound to this intent, vault, and policy epoch"));
                }
                if st.ordered_approvals.is_some() {
                    if !rule.approval_roles.contains(&b.approver_role) {
                        return Err(OicError::policy_denied("approval role is not permitted by the matched rule"));
                    }
                    if let GrantScope::ExactCandidate { candidate_id, candidate_revision, .. } = &b.scope {
                        if candidate_id != &req.candidate_id || *candidate_revision != req.candidate_revision {
                            return Err(OicError::scope("recorded approval names a different candidate"));
                        }
                    }
                }
                if !approvers.contains(&&b.approver_credential_id) {
                    approvers.push(&b.approver_credential_id);
                }
            }
            if approvers.len() < usize::from(rule.required_approvals) {
                return Err(err(ErrorCode::ApprovalRequired, "fewer distinct approvers than the rule requires"));
            }
            if req.issuance_deadline <= now {
                return Err(OicError::invalid_request("issuance deadline already passed"));
            }
            let resources: BTreeSet<&NativeResource> = req.claims.resources.iter().collect();
            if resources.len() != req.claims.resources.len() {
                return Err(OicError::invalid_request("duplicate native resource claim"));
            }
            for o in &req.claims.asset_outflows {
                if !(rule.assets.is_empty() || rule.assets.contains(&o.asset_id)) {
                    return Err(OicError::policy_denied("asset outflow outside the matched rule's scope"));
                }
                if o.amount_base_units > rule.max_amount_per_operation {
                    return Err(OicError::policy_denied("asset outflow exceeds rule per-operation maximum"));
                }
            }
            for f in &req.claims.native_fees {
                if f.amount_base_units > rule.max_native_fee_per_operation {
                    return Err(OicError::policy_denied("native fee exceeds rule per-operation maximum"));
                }
            }
            let mut derived = derived_limits(rule, &req.claims);
            let mut claimed = req.exposure_limits.clone();
            derived.sort_by_key(limit_sort_key);
            claimed.sort_by_key(limit_sort_key);
            if derived != claimed {
                return Err(OicError::invalid_request("exposure limits do not match the active policy rule"));
            }

            // Idempotent repeat of the same reservation.
            if let Some(existing) = st.reservations.get(&reservation_id) {
                let same = existing.reservation.claims == req.claims
                    && existing.envelope_body_hash == req.envelope_body_hash
                    && existing.signer_session_id == req.signer_session_id
                    && existing.reservation.issuance_deadline == req.issuance_deadline;
                if same && existing.state == ReservationState::Reserved {
                    let r = self.receipt(
                        st,
                        ReceiptKind::Reserved,
                        existing,
                        existing.reservation.created_at,
                        existing.reservation.issuance_deadline,
                        st.commit_sequence,
                    )?;
                    return Ok((existing.reservation.clone(), r, false));
                }
                return Err(err(ErrorCode::Conflict, "reservation for this candidate revision already exists with different content or state"));
            }
            if let Some(f) = st.candidates.get(&req.candidate_id) {
                if f != &req.family_id {
                    return Err(err(ErrorCode::Conflict, "candidate already reserved under a different operation family"));
                }
            }

            // 2. acquire native resource locks in the defined (sorted) order.
            for r in &resources {
                match st.resource_locks.get(*r) {
                    Some(holder) if holder != &req.family_id => {
                        return Err(OicError::resource_conflict("native resource held by another operation family"));
                    }
                    _ => {}
                }
            }
            for r in &resources {
                st.resource_locks.insert((*r).clone(), req.family_id.clone());
            }

            let evm: Vec<&NativeResource> = resources.iter().copied().filter(|r| matches!(r, NativeResource::EvmNonce { .. })).collect();
            let claim_mode = match evm.as_slice() {
                [only] => ExposureClaimMode::MutuallyExclusiveWithFamily { resource: (*only).clone() },
                _ => ExposureClaimMode::Additive,
            };
            let reservation = Reservation {
                reservation_id: reservation_id.clone(),
                reservation_version: 1,
                operation_family_id: req.family_id.clone(),
                candidate_id: req.candidate_id.clone(),
                candidate_revision: req.candidate_revision,
                vault_id: req.vault_id.clone(),
                claims: req.claims.clone(),
                policy_epoch: st.policy_epoch,
                created_at: now,
                issuance_deadline: req.issuance_deadline,
            };
            let record = ReservationRecord {
                reservation: reservation.clone(),
                state: ReservationState::Reserved,
                claim_mode,
                intent_id: req.intent_id.clone(),
                rule_id,
                envelope_body_hash: req.envelope_body_hash,
                signer_session_id: req.signer_session_id.clone(),
                candidate_lifecycle: LifecycleState::Reserved,
                recorded_grants: if st.ordered_approvals.is_some() { req.grants.clone() } else { Vec::new() },
            };
            st.reservations.insert(reservation_id.clone(), record);
            st.candidates.insert(req.candidate_id.clone(), req.family_id.clone());

            // 3. confirm maximum possible exposure stays inside every limit.
            for (asset_id, limit) in &derived {
                let budget = BudgetKey::Asset { asset_id: asset_id.clone() };
                let total = st.exposure(&req.vault_id, &budget, limit.window_seconds, now).ok_or_else(|| OicError::budget("exposure arithmetic overflow"))?;
                if total > limit.max_outflow_base_units {
                    return Err(OicError::budget(format!(
                        "exposure {total} would exceed limit {} over {}s for {asset_id}",
                        limit.max_outflow_base_units, limit.window_seconds
                    )));
                }
            }

            // 4. persist reservation and family state.
            let family = st.families.get_mut(&req.family_id).ok_or_else(|| err(ErrorCode::NotFound, "operation family not found"))?;
            let any_issued = family.candidates.iter().any(|c| c.possibly_issued);
            family.candidates.push(FamilyCandidate {
                candidate_id: req.candidate_id.clone(),
                candidate_revision: req.candidate_revision,
                reservation_id: reservation_id.clone(),
                possibly_issued: false,
            });
            family.lifecycle = if any_issued { LifecycleState::ReplacementPending } else { LifecycleState::Reserved };
            let seq = Self::commit(st);
            let rec = &st.reservations[&reservation_id];
            let receipt = self.receipt(st, ReceiptKind::Reserved, rec, now, req.issuance_deadline, seq)?;
            Ok((reservation, receipt, true))
        })?;
        if fresh {
            self.emit(AuthorityEvent::Reserved { reservation_id, commit_sequence: receipt.commit_sequence });
        }
        Ok((reservation, receipt))
    }

    // -----------------------------------------------------------------------
    // Release (§5.4 steps 5–6)
    // -----------------------------------------------------------------------

    pub fn release(&self, req: ReleaseRequest) -> OicResult<(AuthorityReceiptBody, IssuanceRecord)> {
        let ttl = self.config.release_receipt_ttl_seconds;
        let skew = self.config.max_clock_skew_seconds;
        let (receipt, issuance, fresh) = self.tx(|st, now| {
            let rec = st.reservations.get(&req.reservation_id).ok_or_else(|| err(ErrorCode::NotFound, "reservation not found"))?;
            if rec.reservation.reservation_version != req.reservation_version {
                return Err(err(ErrorCode::Conflict, "reservation version mismatch"));
            }
            if rec.envelope_body_hash != req.envelope_body_hash || rec.signer_session_id != req.signer_session_id {
                return Err(err(ErrorCode::Conflict, "release bound to a different envelope or signing session"));
            }
            match &rec.state {
                ReservationState::Reserved => {}
                ReservationState::Released { issuance_id } => {
                    // Idempotent: the issuance stands; re-issue a fresh receipt for the same envelope/session.
                    let issuance = st.issuance.get(issuance_id).cloned().ok_or_else(|| OicError::internal("issuance record missing"))?;
                    let r = self.receipt(st, ReceiptKind::Release, rec, now, now.saturating_add(ttl), issuance.commit_sequence)?;
                    return Ok((r, issuance, false));
                }
                ReservationState::Aborted { .. } => return Err(err(ErrorCode::Conflict, "reservation was aborted")),
                ReservationState::Settled { .. } | ReservationState::Invalidated { .. } => {
                    return Err(err(ErrorCode::Conflict, "reservation already resolved on chain"));
                }
            }
            // Recheck freeze, policy, deadline, and freshness at the release point.
            if st.freeze.blocking(&rec.reservation.vault_id).is_some() {
                return Err(err(ErrorCode::Frozen, "frozen after reservation; no new issuance"));
            }
            if req.expected_policy_epoch != st.policy_epoch || rec.reservation.policy_epoch != st.policy_epoch {
                return Err(err(ErrorCode::StalePolicy, "policy epoch changed since reservation"));
            }
            if rec.reservation.issuance_deadline < now || rec.reservation.issuance_deadline < req.freshness.now {
                return Err(OicError::policy_denied("issuance deadline passed"));
            }
            if req.freshness.now.0.abs_diff(now.0) > skew {
                return Err(OicError::stale_evidence("caller freshness context disagrees with authority clock"));
            }
            crate::approvals::require_recorded_grants(st, &rec.recorded_grants, now)?;
            // A replacement that is not provably mutually exclusive with a
            // possibly issued sibling could be a second live payment (§3.4).
            let fam_id = rec.reservation.operation_family_id.clone();
            for (id, other) in &st.reservations {
                if id == &req.reservation_id || other.reservation.operation_family_id != fam_id {
                    continue;
                }
                let exclusive = matches!((&rec.claim_mode, &other.claim_mode),
                    (ExposureClaimMode::MutuallyExclusiveWithFamily { resource: a }, ExposureClaimMode::MutuallyExclusiveWithFamily { resource: b }) if a == b);
                match &other.state {
                    ReservationState::Released { .. } if !exclusive => {
                        return Err(err(ErrorCode::IssuanceUncertain, "a non-exclusive sibling may already be issued; invalidation evidence required"));
                    }
                    ReservationState::Settled { success: true, .. } => {
                        return Err(err(ErrorCode::Conflict, "operation already finalized successfully"));
                    }
                    _ => {}
                }
            }
            let issuance_id = issuance_id_for(&req.reservation_id)?;
            let (candidate_id, candidate_revision) = (rec.reservation.candidate_id.clone(), rec.reservation.candidate_revision);
            let seq = Self::commit(st);
            let issuance = IssuanceRecord {
                issuance_id: issuance_id.clone(),
                operation_family_id: fam_id.clone(),
                candidate_id,
                candidate_revision,
                envelope_hash: req.envelope_body_hash,
                signer_session_id: req.signer_session_id.clone(),
                commit_sequence: seq,
                committed_at: now,
            };
            st.issuance.insert(issuance_id.clone(), issuance.clone());
            let rec = st.reservations.get_mut(&req.reservation_id).ok_or_else(|| OicError::internal("reservation vanished"))?;
            rec.state = ReservationState::Released { issuance_id };
            rec.candidate_lifecycle = LifecycleState::IssuanceCommitted;
            let family = st.families.get_mut(&fam_id).ok_or_else(|| OicError::internal("family missing"))?;
            for c in family.candidates.iter_mut().filter(|c| c.reservation_id == req.reservation_id) {
                c.possibly_issued = true;
            }
            family.lifecycle = LifecycleState::IssuanceCommitted;
            let rec = &st.reservations[&req.reservation_id];
            let r = self.receipt(st, ReceiptKind::Release, rec, now, now.saturating_add(ttl), seq)?;
            Ok((r, issuance, true))
        })?;
        if fresh {
            self.emit(AuthorityEvent::Released {
                reservation_id: req.reservation_id,
                issuance_id: issuance.issuance_id.clone(),
                commit_sequence: issuance.commit_sequence,
            });
        }
        Ok((receipt, issuance))
    }

    // -----------------------------------------------------------------------
    // Freeze / unfreeze
    // -----------------------------------------------------------------------

    /// Emergency freeze by one designated responder. Stops new reserve and
    /// release after its commit point; prior releases stand (A16).
    pub fn freeze(&self, scope: FreezeScope, by: CredentialId, reason: &str, signature: &SignatureBytes) -> OicResult<u64> {
        let key = self
            .config
            .freeze_responders
            .iter()
            .find(|(id, _)| id == &by)
            .map(|(_, k)| *k)
            .ok_or_else(|| OicError::invalid_signature("not a designated freeze responder"))?;
        let proposal = FreezeProposal::new(self.config.institution_id.clone(), self.config.environment_id.clone(), scope.clone(), by.clone(), reason);
        let h = proposal.hash()?;
        crate::receipts::verify_hash(&key, &h, signature)?;
        let seq = self.tx(|st, _| {
            let seq = Self::commit(st);
            let record = FreezeRecord { at_commit_sequence: seq, by: by.clone(), reason: reason.to_string() };
            match &scope {
                FreezeScope::Global => st.freeze.global_freeze = Some(record),
                FreezeScope::Vault { vault_id } => {
                    st.freeze.frozen_vaults.insert(vault_id.clone(), record);
                }
            }
            st.freeze.freeze_epoch = st.freeze.freeze_epoch.next();
            Ok(seq)
        })?;
        self.emit(AuthorityEvent::Frozen { scope, by, commit_sequence: seq });
        Ok(seq)
    }

    /// Lift a freeze. Requires the administrative quorum over the
    /// [`UnfreezeProposal`] naming the freeze's commit sequence.
    pub fn unfreeze(&self, scope: FreezeScope, signatures: &[CredentialSignature]) -> OicResult<u64> {
        let seq = self.tx(|st, _| {
            let record = st.freeze.record(&scope).ok_or_else(|| err(ErrorCode::NotFound, "scope is not frozen"))?;
            let proposal =
                UnfreezeProposal::new(self.config.institution_id.clone(), self.config.environment_id.clone(), scope.clone(), record.at_commit_sequence);
            let h = proposal.hash()?;
            let n = count_quorum_signatures(&h.0, signatures, &self.config.admin_keys);
            if n < usize::from(self.config.admin_quorum) {
                return Err(OicError::invalid_signature(format!("unfreeze quorum not met: {n} of {}", self.config.admin_quorum)));
            }
            match &scope {
                FreezeScope::Global => st.freeze.global_freeze = None,
                FreezeScope::Vault { vault_id } => {
                    st.freeze.frozen_vaults.remove(vault_id);
                }
            }
            st.freeze.freeze_epoch = st.freeze.freeze_epoch.next();
            Ok(Self::commit(st))
        })?;
        self.emit(AuthorityEvent::Unfrozen { scope, commit_sequence: seq });
        Ok(seq)
    }

    // -----------------------------------------------------------------------
    // Abort / expiry
    // -----------------------------------------------------------------------

    fn abort_in(st: &mut AuthorityState, reservation_id: &ReservationId, reason: AbortReason) -> OicResult<()> {
        let rec = st.reservations.get_mut(reservation_id).ok_or_else(|| err(ErrorCode::NotFound, "reservation not found"))?;
        rec.state = ReservationState::Aborted { reason };
        rec.candidate_lifecycle = match reason {
            AbortReason::BeforeIssuance => LifecycleState::AbortedBeforeIssuance,
            AbortReason::ApprovalExpired => LifecycleState::ApprovalExpired,
        };
        let fam_id = rec.reservation.operation_family_id.clone();
        let lifecycle = rec.candidate_lifecycle;
        st.refresh_family_locks(&fam_id);
        let active = st.has_active_reservations(&fam_id);
        if let Some(f) = st.families.get_mut(&fam_id) {
            if !active && !f.lifecycle.terminal_released() {
                f.lifecycle = lifecycle;
            }
        }
        Ok(())
    }

    /// Abort a reservation that was never released. After release the
    /// signature may exist; this returns `IssuanceUncertain` (I5).
    pub fn abort_before_issuance(&self, reservation_id: &ReservationId) -> OicResult<u64> {
        let seq = self.tx(|st, _| {
            let rec = st.reservations.get(reservation_id).ok_or_else(|| err(ErrorCode::NotFound, "reservation not found"))?;
            match rec.state {
                ReservationState::Reserved => {}
                ReservationState::Aborted { .. } => return Err(err(ErrorCode::Conflict, "reservation already aborted")),
                _ => return Err(err(ErrorCode::IssuanceUncertain, "reservation possibly issued; abort impossible, invalidation evidence required")),
            }
            Self::abort_in(st, reservation_id, AbortReason::BeforeIssuance)?;
            Ok(Self::commit(st))
        })?;
        self.emit(AuthorityEvent::Aborted { reservation_id: reservation_id.clone(), reason: AbortReason::BeforeIssuance, commit_sequence: seq });
        Ok(seq)
    }

    /// Approval/issuance deadline passed for one reservation: aborts only if
    /// never released. A possibly issued reservation keeps its exposure (A17).
    pub fn approval_expired(&self, reservation_id: &ReservationId) -> OicResult<u64> {
        let seq = self.tx(|st, now| {
            let rec = st.reservations.get(reservation_id).ok_or_else(|| err(ErrorCode::NotFound, "reservation not found"))?;
            match rec.state {
                ReservationState::Reserved if rec.reservation.issuance_deadline < now => {}
                ReservationState::Reserved => return Err(OicError::invalid_request("issuance deadline not yet passed")),
                ReservationState::Aborted { .. } => return Err(err(ErrorCode::Conflict, "reservation already aborted")),
                _ => return Err(err(ErrorCode::IssuanceUncertain, "approval expiry does not cancel a possibly issued signature")),
            }
            Self::abort_in(st, reservation_id, AbortReason::ApprovalExpired)?;
            Ok(Self::commit(st))
        })?;
        self.emit(AuthorityEvent::Aborted { reservation_id: reservation_id.clone(), reason: AbortReason::ApprovalExpired, commit_sequence: seq });
        Ok(seq)
    }

    /// Abort every never-released reservation whose deadline has passed.
    /// Possibly issued reservations are untouched (A17).
    pub fn expire_approvals(&self) -> OicResult<Vec<ReservationId>> {
        let (ids, seq) = self.tx(|st, now| {
            let ids: Vec<ReservationId> = st
                .reservations
                .iter()
                .filter(|(_, r)| r.state == ReservationState::Reserved && r.reservation.issuance_deadline < now)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &ids {
                Self::abort_in(st, id, AbortReason::ApprovalExpired)?;
            }
            let seq = if ids.is_empty() { st.commit_sequence } else { Self::commit(st) };
            Ok((ids, seq))
        })?;
        for id in &ids {
            self.emit(AuthorityEvent::Aborted { reservation_id: id.clone(), reason: AbortReason::ApprovalExpired, commit_sequence: seq });
        }
        Ok(ids)
    }

    // -----------------------------------------------------------------------
    // Chain observations (§12)
    // -----------------------------------------------------------------------

    /// Apply reconciled chain evidence for a possibly issued candidate.
    pub fn record_observation(&self, family_id: &OperationFamilyId, candidate_id: &CandidateId, observation: ChainObservation) -> OicResult<LifecycleState> {
        let (lifecycle, seq) = self.tx(|st, now| {
            let family = st.families.get(family_id).ok_or_else(|| err(ErrorCode::NotFound, "operation family not found"))?;
            // Latest possibly issued revision of this candidate.
            let rid = family
                .candidates
                .iter()
                .rev()
                .find(|c| &c.candidate_id == candidate_id && c.possibly_issued)
                .map(|c| c.reservation_id.clone())
                .ok_or_else(|| err(ErrorCode::NotFound, "no possibly issued candidate with this id in the family"))?;
            let rec = st.reservations.get(&rid).ok_or_else(|| OicError::internal("reservation missing"))?.clone();
            let vault_id = rec.reservation.vault_id.clone();

            let lifecycle = match observation {
                ChainObservation::Conflict { .. } => {
                    let f = st.families.get_mut(family_id).ok_or_else(|| OicError::internal("family missing"))?;
                    f.quarantined = true;
                    f.lifecycle
                }
                ChainObservation::Submitted { .. } | ChainObservation::Included { .. } => {
                    let ReservationState::Released { .. } = rec.state else {
                        return Err(err(ErrorCode::Conflict, "observation for a candidate that is no longer outstanding"));
                    };
                    let l = if matches!(observation, ChainObservation::Submitted { .. }) { LifecycleState::Submitted } else { LifecycleState::Included };
                    Self::set_candidate_lifecycle(st, &rid, family_id, l)?;
                    l
                }
                ChainObservation::Reorged { .. } => match rec.state {
                    ReservationState::Released { .. } => {
                        Self::set_candidate_lifecycle(st, &rid, family_id, LifecycleState::Reorged)?;
                        LifecycleState::Reorged
                    }
                    _ => {
                        return Err(err(ErrorCode::RecoveryRequired, "reorg of a resolved candidate exceeds profile finality; manual reconciliation required"))
                    }
                },
                ChainObservation::Finalized { execution_success, fee_paid, .. } => {
                    let issuance_id = match &rec.state {
                        ReservationState::Released { issuance_id } => issuance_id.clone(),
                        ReservationState::Settled { success, fee_paid: f, .. } if *success == execution_success && *f == fee_paid => {
                            return Ok((st.families[family_id].lifecycle, None));
                        }
                        _ => return Err(err(ErrorCode::Conflict, "finality evidence conflicts with recorded state")),
                    };
                    if execution_success {
                        for o in &rec.reservation.claims.asset_outflows {
                            st.ledger.push(LedgerEntry {
                                vault_id: vault_id.clone(),
                                budget: BudgetKey::Asset { asset_id: o.asset_id.clone() },
                                amount: o.amount_base_units,
                                at: now,
                                reservation_id: rid.clone(),
                            });
                        }
                    }
                    if !fee_paid.is_zero() {
                        let network_id = rec
                            .reservation
                            .claims
                            .native_fees
                            .first()
                            .map(|f| f.network_id.clone())
                            .or_else(|| rec.reservation.claims.resources.first().map(|r| resource_network(r).clone()))
                            .ok_or_else(|| OicError::invalid_request("cannot attribute fee: reservation names no network"))?;
                        st.ledger.push(LedgerEntry {
                            vault_id: vault_id.clone(),
                            budget: BudgetKey::NativeFee { network_id },
                            amount: fee_paid,
                            at: now,
                            reservation_id: rid.clone(),
                        });
                    }
                    let l = if execution_success { LifecycleState::FinalizedSuccess } else { LifecycleState::FinalizedFailure };
                    {
                        let r = st.reservations.get_mut(&rid).ok_or_else(|| OicError::internal("reservation missing"))?;
                        r.state = ReservationState::Settled { issuance_id, success: execution_success, fee_paid };
                        r.candidate_lifecycle = l;
                    }
                    // The nonce is consumed: mutually exclusive siblings can never execute.
                    if let ExposureClaimMode::MutuallyExclusiveWithFamily { resource } = &rec.claim_mode {
                        for (id, other) in st.reservations.iter_mut() {
                            if id == &rid || &other.reservation.operation_family_id != family_id || !other.state.is_active() {
                                continue;
                            }
                            if matches!(&other.claim_mode, ExposureClaimMode::MutuallyExclusiveWithFamily { resource: r } if r == resource) {
                                let issued = match &other.state {
                                    ReservationState::Released { issuance_id } => Some(issuance_id.clone()),
                                    _ => None,
                                };
                                other.state = ReservationState::Invalidated { issuance_id: issued };
                                other.candidate_lifecycle = LifecycleState::DefinitivelyInvalidated;
                            }
                        }
                    }
                    st.refresh_family_locks(family_id);
                    let f = st.families.get_mut(family_id).ok_or_else(|| OicError::internal("family missing"))?;
                    f.lifecycle = l;
                    l
                }
                ChainObservation::DefinitivelyInvalidated { .. } => {
                    let issuance_id = match &rec.state {
                        ReservationState::Released { issuance_id } => issuance_id.clone(),
                        ReservationState::Invalidated { .. } => return Ok((st.families[family_id].lifecycle, None)),
                        _ => return Err(err(ErrorCode::Conflict, "invalidation evidence conflicts with recorded state")),
                    };
                    {
                        let r = st.reservations.get_mut(&rid).ok_or_else(|| OicError::internal("reservation missing"))?;
                        r.state = ReservationState::Invalidated { issuance_id: Some(issuance_id) };
                        r.candidate_lifecycle = LifecycleState::DefinitivelyInvalidated;
                    }
                    st.refresh_family_locks(family_id);
                    let active = st.has_active_reservations(family_id);
                    let l = if active { LifecycleState::ReplacementPending } else { LifecycleState::DefinitivelyInvalidated };
                    let f = st.families.get_mut(family_id).ok_or_else(|| OicError::internal("family missing"))?;
                    f.lifecycle = l;
                    l
                }
            };
            Ok((lifecycle, Some(Self::commit(st))))
        })?;
        if let Some(seq) = seq {
            self.emit(AuthorityEvent::Observed { family_id: family_id.clone(), candidate_id: candidate_id.clone(), lifecycle, commit_sequence: seq });
        }
        Ok(lifecycle)
    }

    fn set_candidate_lifecycle(st: &mut AuthorityState, rid: &ReservationId, family_id: &OperationFamilyId, l: LifecycleState) -> OicResult<()> {
        st.reservations.get_mut(rid).ok_or_else(|| OicError::internal("reservation missing"))?.candidate_lifecycle = l;
        st.families.get_mut(family_id).ok_or_else(|| OicError::internal("family missing"))?.lifecycle = l;
        Ok(())
    }
}
