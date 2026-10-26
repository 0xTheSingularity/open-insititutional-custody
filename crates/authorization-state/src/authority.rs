//! D1 storage, writer fencing, receipt signing, and post-commit audit delivery.

use crate::clock::Clock;
use crate::receipts::*;
use crate::state::*;
use crate::store::AuthorityStore;
use crate::transition::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use oic_domain_types::*;
use oic_policy_kernel::{ExposureView, WindowExposure};
use std::sync::Arc;

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuthorityEvent);
}

/// Audit sink that keeps events in memory (tests, embedding).
#[derive(Default)]
pub struct MemoryAuditSink(parking_lot::Mutex<Vec<AuthorityEvent>>);

impl MemoryAuditSink {
    pub fn events(&self) -> Vec<AuthorityEvent> {
        self.0.lock().clone()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: &AuthorityEvent) {
        self.0.lock().push(event.clone());
    }
}

/// Trusted single-writer authority. Every command uses the same deterministic
/// transition available to log followers, within a fenced store transaction.
pub struct Authority<S: AuthorityStore> {
    store: Arc<S>,
    config: AuthorityConfig,
    signing_key: SigningKey,
    clock: Arc<dyn Clock>,
    fence_token: u64,
    audit: Option<Arc<dyn AuditSink>>,
}

impl<S: AuthorityStore> Authority<S> {
    /// Take the next writer fence and authority epoch. Earlier instances can
    /// neither write nor read through this API after the fence moves.
    pub fn open(store: Arc<S>, expected_fence_token: u64, config: AuthorityConfig, signing_key: SigningKey, clock: Arc<dyn Clock>) -> OicResult<Self> {
        if config.admin_quorum == 0 || config.admin_keys.len() < usize::from(config.admin_quorum) {
            return Err(OicError::invalid_request("administrative quorum must be satisfiable and at least 1"));
        }
        let fence_token = store.transact(|st| {
            if st.fence_token != expected_fence_token {
                return Err(OicError::new(ErrorCode::AuthorityUnavailable, "fenced: store fence token moved; another writer opened"));
            }
            st.fence_token = st.fence_token.checked_add(1).ok_or_else(|| OicError::internal("fence token exhausted"))?;
            st.epoch = st.epoch.next();
            st.commit_sequence += 1;
            Ok(st.fence_token)
        })?;
        let a = Authority { store, config, signing_key, clock, fence_token, audit: None };
        let (epoch, seq) = a.store.read(|st| (st.epoch, st.commit_sequence))?;
        a.emit(AuthorityEvent::Opened { fence_token, authority_epoch: epoch, commit_sequence: seq });
        Ok(a)
    }

    pub fn with_audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    pub fn fence_token(&self) -> u64 {
        self.fence_token
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn config(&self) -> &AuthorityConfig {
        &self.config
    }

    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    fn emit(&self, event: AuthorityEvent) {
        if let Some(audit) = &self.audit {
            audit.record(&event);
        }
    }

    fn check_fence(&self, state: &AuthorityState) -> OicResult<()> {
        if state.fence_token != self.fence_token {
            return Err(OicError::new(ErrorCode::AuthorityUnavailable, "fenced: stale writer"));
        }
        Ok(())
    }

    fn execute(&self, command: AuthorityCommand) -> OicResult<AuthorityOutput> {
        let now = self.clock.now();
        let (output, events) = self.store.transact(|state| {
            self.check_fence(state)?;
            // The store already owns a private transaction copy. An error
            // discards it; no state, receipt, or event escapes a failed commit.
            let (successor, output, events) = apply(&self.config, std::mem::take(state), command, now)?;
            *state = successor;
            Ok((output, events))
        })?;
        for event in events {
            self.emit(event);
        }
        Ok(output)
    }

    fn view<R>(&self, f: impl FnOnce(&AuthorityState) -> OicResult<R>) -> OicResult<R> {
        self.store.read(|state| {
            self.check_fence(state)?;
            f(state)
        })?
    }

    /// Same canonical body and idempotency key returns the existing operation;
    /// a different body conflicts.
    pub fn register_intent(&self, intent: &Intent, intent_hash_claimed: Hash32, key: IdempotencyKey) -> OicResult<RegisteredIntent> {
        let AuthorityOutput::Registered(result) =
            self.execute(AuthorityCommand::RegisterIntent { intent: intent.clone(), intent_hash: intent_hash_claimed, key })?
        else {
            unreachable!()
        };
        Ok(result)
    }

    /// Activate an admin-quorum-signed, strictly newer policy epoch.
    pub fn set_policy(&self, bundle: &PolicyBundle) -> OicResult<u64> {
        let AuthorityOutput::Committed(sequence) = self.execute(AuthorityCommand::SetPolicy { bundle: bundle.clone() })? else { unreachable!() };
        Ok(sequence)
    }

    pub fn current_policy(&self) -> OicResult<(Epoch, Hash32)> {
        self.view(|state| Ok((state.policy_epoch, state.policy_hash)))
    }

    /// Enable ordered approvals by enrolling the first approval-only key, or
    /// permanently retire an enrolled identity. Every change requires the
    /// configured admin quorum and emits an ordered audit event.
    pub fn change_credential(&self, proposal: crate::CredentialChange, signatures: Vec<CredentialSignature>) -> OicResult<u64> {
        if proposal.credential.as_ref().is_some_and(|c| c.verifying_key == oic_policy_kernel::ApproverKey::Ed25519(self.verifying_key())) {
            return Err(OicError::invalid_request("approval and authority signing keys must be separate"));
        }
        let AuthorityOutput::Committed(sequence) = self.execute(AuthorityCommand::ChangeCredential { proposal, signatures })? else { unreachable!() };
        Ok(sequence)
    }

    /// Verify a grant against ordered enrollment and the registered intent;
    /// record it once per credential, before it can authorize a reservation.
    pub fn approve(&self, intent: &Intent, grant: ApprovalGrant) -> OicResult<u64> {
        let AuthorityOutput::Committed(sequence) = self.execute(AuthorityCommand::Approve { intent: Box::new(intent.clone()), grant })? else { unreachable!() };
        Ok(sequence)
    }

    /// `None` is the legacy trusted-kernel profile; `Some([])` means ordered
    /// enrollment is enabled with no active credentials, not a fallback.
    pub fn approval_credentials(&self) -> OicResult<Option<Vec<oic_policy_kernel::ApproverCredential>>> {
        self.view(|state| Ok(state.ordered_approvals.as_ref().map(|a| a.credentials.values().filter_map(|r| r.credential.clone()).collect())))
    }

    /// Historical approvals, including removed/expired credentials. Consumers
    /// must verify them against the current enrollment before counting them.
    pub fn recorded_approvals(&self, intent_id: &IntentId) -> OicResult<Vec<crate::RecordedApproval>> {
        self.view(|state| Ok(state.ordered_approvals.as_ref().and_then(|a| a.grants.get(intent_id)).into_iter().flat_map(|g| g.values().cloned()).collect()))
    }

    pub fn reserve(&self, request: ReserveRequest) -> OicResult<(Reservation, AuthorityReceipt)> {
        let AuthorityOutput::Reserved { reservation, receipt } = self.execute(AuthorityCommand::Reserve { request })? else { unreachable!() };
        Ok((reservation, sign_receipt(&self.signing_key, &self.config.authority_key_id, receipt)?))
    }

    /// Per-window settled and outstanding exposure for kernel evaluation.
    pub fn exposure_view(&self, vault_id: &VaultId, asset_ids: &[AssetId], windows: &[u64], now: UnixSeconds) -> OicResult<ExposureView> {
        self.view(|state| {
            let mut out = Vec::with_capacity(asset_ids.len().saturating_mul(windows.len()));
            for asset in asset_ids {
                let budget = BudgetKey::Asset { asset_id: asset.clone() };
                let outstanding = state.outstanding(vault_id, &budget).ok_or_else(|| OicError::budget("exposure arithmetic overflow"))?;
                for window in windows {
                    let settled = state.settled_in_window(vault_id, &budget, *window, now).ok_or_else(|| OicError::budget("exposure arithmetic overflow"))?;
                    out.push(WindowExposure { asset_id: asset.clone(), window_seconds: *window, settled, outstanding });
                }
            }
            Ok(ExposureView { windows: out })
        })
    }

    pub fn exposure(&self, vault_id: &VaultId, budget: &BudgetKey, window_seconds: u64) -> OicResult<Amount> {
        let now = self.clock.now();
        self.view(|state| state.exposure(vault_id, budget, window_seconds, now).ok_or_else(|| OicError::budget("exposure arithmetic overflow")))
    }

    /// Commit issuance before signing a receipt. Repeated release returns the
    /// original issuance; it does not authorize a new envelope or session.
    pub fn release(&self, request: ReleaseRequest) -> OicResult<(AuthorityReceipt, IssuanceRecord)> {
        let AuthorityOutput::Released { receipt, issuance } = self.execute(AuthorityCommand::Release { request })? else { unreachable!() };
        Ok((sign_receipt(&self.signing_key, &self.config.authority_key_id, receipt)?, issuance))
    }

    pub fn releases_before(&self, commit_sequence: u64) -> OicResult<Vec<IssuanceRecord>> {
        self.view(|state| Ok(state.releases_before(commit_sequence)))
    }

    /// One designated responder may freeze. Earlier releases still stand.
    pub fn freeze(&self, scope: FreezeScope, by: CredentialId, reason: &str, signature: &SignatureBytes) -> OicResult<u64> {
        let AuthorityOutput::Committed(sequence) =
            self.execute(AuthorityCommand::Freeze { scope, by, reason: reason.to_owned(), signature: signature.clone() })?
        else {
            unreachable!()
        };
        Ok(sequence)
    }

    /// Administrative quorum binds the exact freeze commit being lifted.
    pub fn unfreeze(&self, scope: FreezeScope, signatures: &[CredentialSignature]) -> OicResult<u64> {
        let AuthorityOutput::Committed(sequence) = self.execute(AuthorityCommand::Unfreeze { scope, signatures: signatures.to_vec() })? else { unreachable!() };
        Ok(sequence)
    }

    pub fn freeze_record(&self, scope: &FreezeScope) -> OicResult<Option<FreezeRecord>> {
        self.view(|state| Ok(state.freeze.record(scope).cloned()))
    }

    /// Possibly issued reservations cannot be aborted without chain evidence.
    pub fn abort_before_issuance(&self, reservation_id: &ReservationId) -> OicResult<u64> {
        let AuthorityOutput::Committed(sequence) = self.execute(AuthorityCommand::AbortBeforeIssuance { reservation_id: reservation_id.clone() })? else {
            unreachable!()
        };
        Ok(sequence)
    }

    pub fn approval_expired(&self, reservation_id: &ReservationId) -> OicResult<u64> {
        let AuthorityOutput::Committed(sequence) = self.execute(AuthorityCommand::ApprovalExpired { reservation_id: reservation_id.clone() })? else {
            unreachable!()
        };
        Ok(sequence)
    }

    pub fn expire_approvals(&self) -> OicResult<Vec<ReservationId>> {
        let AuthorityOutput::Expired(ids) = self.execute(AuthorityCommand::ExpireApprovals)? else { unreachable!() };
        Ok(ids)
    }

    /// [`Self::expire_approvals`], but commits only when a never-released
    /// reservation is past its deadline; an idle check is a read, not a
    /// store write.
    pub fn expire_due_approvals(&self) -> OicResult<Vec<ReservationId>> {
        let now = self.clock.now();
        let due = self.view(|st| {
            Ok(st.reservations.values().any(|r| r.state == ReservationState::Reserved && r.reservation.issuance_deadline < now))
        })?;
        if due { self.expire_approvals() } else { Ok(Vec::new()) }
    }

    pub fn record_observation(&self, family_id: &OperationFamilyId, candidate_id: &CandidateId, observation: ChainObservation) -> OicResult<LifecycleState> {
        let command = AuthorityCommand::RecordObservation { family_id: family_id.clone(), candidate_id: candidate_id.clone(), observation };
        let AuthorityOutput::Observed(lifecycle) = self.execute(command)? else { unreachable!() };
        Ok(lifecycle)
    }

    pub fn reservation(&self, id: &ReservationId) -> OicResult<ReservationRecord> {
        self.view(|state| state.reservations.get(id).cloned().ok_or_else(|| OicError::new(ErrorCode::NotFound, "reservation not found")))
    }

    pub fn family(&self, id: &OperationFamilyId) -> OicResult<FamilyRecord> {
        self.view(|state| state.families.get(id).cloned().ok_or_else(|| OicError::new(ErrorCode::NotFound, "family not found")))
    }

    pub fn checkpoint(&self) -> OicResult<SignedCheckpoint> {
        let body = self.view(|state| {
            Ok(CheckpointBody {
                institution_id: self.config.institution_id.clone(),
                environment_id: self.config.environment_id.clone(),
                authority_epoch: state.epoch,
                commit_sequence: state.commit_sequence,
                state_hash: state_hash(state)?,
            })
        })?;
        sign_checkpoint(&self.signing_key, &self.config.authority_key_id, body)
    }
}

/// Run [`Authority::expire_due_approvals`] every `every` on a background
/// thread until the authority is dropped, so reserved exposure whose
/// approvals expired is released even if the coordinator that reserved it
/// crashed (RFC 0003 §10). Errors are retried on the next tick.
pub fn spawn_approval_expiry_sweep<S: AuthorityStore + Send + Sync + 'static>(
    authority: &Arc<Authority<S>>,
    every: std::time::Duration,
) -> std::thread::JoinHandle<()> {
    let weak = Arc::downgrade(authority);
    std::thread::spawn(move || loop {
        std::thread::sleep(every);
        let Some(authority) = weak.upgrade() else { return };
        let _ = authority.expire_due_approvals();
    })
}
