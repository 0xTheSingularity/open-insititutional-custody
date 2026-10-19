//! The authority's durable state and the accounting rule over it (§5.3).
//!
//! Everything here is plain data with canonical encoding so that the whole
//! state can be snapshotted, hashed into signed checkpoints, and compared.

use oic_domain_types::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Durable authority state. Mutated only inside [`crate::AuthorityStore::transact`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityState {
    /// Authority epoch; bumped whenever a writer (re)opens the store (restore/failover).
    pub epoch: Epoch,
    /// Current writer generation. Writes from any other generation are fenced.
    pub fence_token: u64,
    /// Total order over every committed mutation (reserve, release, freeze...).
    pub commit_sequence: u64,
    /// Active administratively-signed policy bundle.
    pub policy: Option<PolicyBundle>,
    pub policy_epoch: Epoch,
    pub policy_hash: Hash32,
    pub freeze: FreezeState,
    pub reservations: BTreeMap<ReservationId, ReservationRecord>,
    /// Native resource -> family holding it. Replacement candidates in one family share a lock (§9.4).
    pub resource_locks: BTreeMap<NativeResource, OperationFamilyId>,
    pub families: BTreeMap<OperationFamilyId, FamilyRecord>,
    /// Candidate -> family; a candidate can never move between families.
    pub candidates: BTreeMap<CandidateId, OperationFamilyId>,
    pub issuance: BTreeMap<IssuanceId, IssuanceRecord>,
    /// Settled debits with settlement timestamps.
    pub ledger: Vec<LedgerEntry>,
    pub idempotency: BTreeMap<IdempotencyKey, IdempotencyRecord>,
    pub intents: BTreeMap<IntentId, IntentRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeScope {
    Vault { vault_id: VaultId },
    Global,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeRecord {
    /// The freeze's ordered commit point. Releases committed before it stand.
    pub at_commit_sequence: u64,
    pub by: CredentialId,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeState {
    pub frozen_vaults: BTreeMap<VaultId, FreezeRecord>,
    pub global_freeze: Option<FreezeRecord>,
    /// Bumped on every freeze/unfreeze; carried in receipts.
    pub freeze_epoch: Epoch,
}

impl FreezeState {
    /// The freeze (if any) that blocks issuance for `vault_id`.
    pub fn blocking(&self, vault_id: &VaultId) -> Option<&FreezeRecord> {
        self.global_freeze.as_ref().or_else(|| self.frozen_vaults.get(vault_id))
    }
    pub fn record(&self, scope: &FreezeScope) -> Option<&FreezeRecord> {
        match scope {
            FreezeScope::Global => self.global_freeze.as_ref(),
            FreezeScope::Vault { vault_id } => self.frozen_vaults.get(vault_id),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    BeforeIssuance,
    ApprovalExpired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    /// Exposure and locks held; no signature-enabling output released.
    Reserved,
    /// Final release committed: a signature may exist (possibly issued).
    Released { issuance_id: IssuanceId },
    /// Aborted before issuance; exposure and locks released.
    Aborted { reason: AbortReason },
    /// Finalized on chain. Asset debit (success only) and fee moved to the ledger.
    Settled { issuance_id: IssuanceId, success: bool, fee_paid: Amount },
    /// Definitively cannot execute (chain invalidation evidence, or a
    /// mutually exclusive sibling finalized).
    Invalidated { issuance_id: Option<IssuanceId> },
}

impl ReservationState {
    /// Outstanding exposure is charged while active (§5.3).
    pub fn is_active(&self) -> bool {
        matches!(self, ReservationState::Reserved | ReservationState::Released { .. })
    }
    pub fn possibly_issued(&self) -> bool {
        matches!(
            self,
            ReservationState::Released { .. } | ReservationState::Settled { .. } | ReservationState::Invalidated { issuance_id: Some(_) }
        )
    }
}

/// How a reservation's exposure combines with its family siblings (§5.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureClaimMode {
    /// Summed with every other reservation.
    Additive,
    /// Same-family candidates claiming this exact EVM (sender, nonce) can
    /// never both execute; the group is charged its maximum, not its sum.
    MutuallyExclusiveWithFamily { resource: NativeResource },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationRecord {
    pub reservation: Reservation,
    pub state: ReservationState,
    pub claim_mode: ExposureClaimMode,
    pub intent_id: IntentId,
    pub rule_id: String,
    pub envelope_body_hash: Hash32,
    pub signer_session_id: SigningSessionId,
    /// Latest chain-facing lifecycle for this candidate.
    pub candidate_lifecycle: LifecycleState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyCandidate {
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub reservation_id: ReservationId,
    pub possibly_issued: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyRecord {
    pub intent_id: IntentId,
    pub vault_id: VaultId,
    pub candidates: Vec<FamilyCandidate>,
    pub lifecycle: LifecycleState,
    /// Set by conflicting chain evidence; nothing is released while quarantined.
    pub quarantined: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKey {
    Asset { asset_id: AssetId },
    /// Fees are reserved and settled separately, in native units (§5.3).
    NativeFee { network_id: NetworkId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub vault_id: VaultId,
    pub budget: BudgetKey,
    pub amount: Amount,
    pub at: UnixSeconds,
    pub reservation_id: ReservationId,
}

/// Idempotency scope (§13.3): institution, route, client-supplied key. The
/// canonical request body hash is stored alongside and compared.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdempotencyKey {
    pub institution_id: InstitutionId,
    pub route: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub request_hash: Hash32,
    pub intent_id: IntentId,
    pub operation_family_id: OperationFamilyId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentRecord {
    pub intent_hash: Hash32,
    pub operation_family_id: OperationFamilyId,
    pub vault_id: VaultId,
}

// ---------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------

/// Network of a native resource (every resource names its network).
pub fn resource_network(r: &NativeResource) -> &NetworkId {
    match r {
        NativeResource::EvmNonce { network_id, .. }
        | NativeResource::SolanaBlockhash { network_id, .. }
        | NativeResource::SolanaDurableNonce { network_id, .. }
        | NativeResource::BitcoinUtxo { network_id, .. }
        | NativeResource::SuiObject { network_id, .. }
        | NativeResource::AptosSequence { network_id, .. }
        | NativeResource::CosmosSequence { network_id, .. }
        | NativeResource::XrplSequence { network_id, .. } => network_id,
    }
}

/// Worst-case charge of one claim set against one budget.
pub fn claim_charge(claims: &ResourceClaims, budget: &BudgetKey) -> Option<Amount> {
    let mut total = Amount::ZERO;
    match budget {
        BudgetKey::Asset { asset_id } => {
            for o in claims.asset_outflows.iter().filter(|o| &o.asset_id == asset_id) {
                total = total.checked_add(o.amount_base_units)?;
            }
        }
        BudgetKey::NativeFee { network_id } => {
            for f in claims.native_fees.iter().filter(|f| &f.network_id == network_id) {
                total = total.checked_add(f.amount_base_units)?;
            }
        }
    }
    Some(total)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum GroupKey<'a> {
    Exclusive(&'a OperationFamilyId, &'a NativeResource),
    Single(&'a ReservationId),
}

impl AuthorityState {
    /// Outstanding potential debits for (vault, budget) from every active
    /// reservation. Never expires by time. Provably mutually exclusive
    /// same-family EVM nonce replacements are charged their maximum; all
    /// other reservations are summed. `None` on overflow.
    pub fn outstanding(&self, vault_id: &VaultId, budget: &BudgetKey) -> Option<Amount> {
        let mut groups: BTreeMap<GroupKey<'_>, Amount> = BTreeMap::new();
        for (id, rec) in &self.reservations {
            if !rec.state.is_active() || &rec.reservation.vault_id != vault_id {
                continue;
            }
            let charge = claim_charge(&rec.reservation.claims, budget)?;
            let key = match &rec.claim_mode {
                ExposureClaimMode::MutuallyExclusiveWithFamily { resource } => GroupKey::Exclusive(&rec.reservation.operation_family_id, resource),
                ExposureClaimMode::Additive => GroupKey::Single(id),
            };
            let slot = groups.entry(key).or_insert(Amount::ZERO);
            *slot = (*slot).max(charge);
        }
        groups.values().try_fold(Amount::ZERO, |acc, a| acc.checked_add(*a))
    }

    /// Settled debits for (vault, budget) whose settlement time lies in the
    /// window `(now - window_seconds, now]` (and any future-dated entries).
    pub fn settled_in_window(&self, vault_id: &VaultId, budget: &BudgetKey, window_seconds: u64, now: UnixSeconds) -> Option<Amount> {
        self.ledger
            .iter()
            .filter(|e| &e.vault_id == vault_id && &e.budget == budget && e.at.0.saturating_add(window_seconds) > now.0)
            .try_fold(Amount::ZERO, |acc, e| acc.checked_add(e.amount))
    }

    /// Total exposure per §5.3 for one window.
    pub fn exposure(&self, vault_id: &VaultId, budget: &BudgetKey, window_seconds: u64, now: UnixSeconds) -> Option<Amount> {
        self.settled_in_window(vault_id, budget, window_seconds, now)?.checked_add(self.outstanding(vault_id, budget)?)
    }

    /// Drop locks of `family_id` that no active reservation of the family claims.
    pub fn refresh_family_locks(&mut self, family_id: &OperationFamilyId) {
        let active: BTreeSet<NativeResource> = self
            .reservations
            .values()
            .filter(|r| r.state.is_active() && &r.reservation.operation_family_id == family_id)
            .flat_map(|r| r.reservation.claims.resources.iter().cloned())
            .collect();
        self.resource_locks.retain(|res, fam| fam != family_id || active.contains(res));
    }

    pub fn has_active_reservations(&self, family_id: &OperationFamilyId) -> bool {
        self.reservations.values().any(|r| r.state.is_active() && &r.reservation.operation_family_id == family_id)
    }

    /// Issuance records committed strictly before `commit_sequence`, in order.
    pub fn releases_before(&self, commit_sequence: u64) -> Vec<IssuanceRecord> {
        let mut v: Vec<_> = self.issuance.values().filter(|i| i.commit_sequence < commit_sequence).cloned().collect();
        v.sort_by_key(|i| i.commit_sequence);
        v
    }
}
