//! Operational money-movement objects (RFC 0002 §4 deposits, §5 workflows,
//! §6 journal and reconciliation, §10 events).
//!
//! These objects are chain-neutral like everything else in this crate. The
//! three quantities RFC 0002 §6 insists on keeping apart each have one home:
//!
//! * chain holdings under a stated observation context → [`ReconciledBalance::chain_balance`]
//!   at a [`ReconciliationCheckpoint`];
//! * amount available to authorize after outstanding obligations →
//!   [`Holdings::available`], derived from the journal minus reservations;
//! * remaining policy allowance within a window → the authority's exposure
//!   view (RFC 0001 §5.3), never stored here.

use crate::ids::*;
use crate::objects::*;
use crate::primitives::*;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// §4 Deposit addresses
// ---------------------------------------------------------------------------

/// Whether the platform holds signing authority over an address. Watch-only
/// enrollment must never suggest the platform controls the address (§4, §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressCustody {
    /// Bound to a key whose shares are held by enrolled signers.
    Controlled,
    /// Monitored only; no key, no signing path, no sweeps.
    WatchOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositAddressState {
    /// Created but activation is incomplete (C03): not shown as ready.
    Inactive,
    /// All activation steps committed; deposits are credited under the profile.
    Active,
    /// No longer accepting deposits; movements create `RetiredAddress` cases.
    Retired,
}

/// One address enrolled for inbound monitoring (§4). `supported_assets` is
/// the explicit list that may be credited; anything else is quarantined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositAddress {
    pub deposit_address_id: DepositAddressId,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub vault_id: VaultId,
    /// Present for controlled addresses; `None` for watch-only.
    pub chain_wallet_id: Option<ChainWalletId>,
    pub chain_profile_id: ChainProfileId,
    pub network_id: NetworkId,
    pub address: Bytes,
    pub address_display: String,
    pub custody: AddressCustody,
    pub supported_assets: Vec<AssetId>,
    /// Required inbound reference (memo/tag) when the profile needs one.
    pub routing_reference: Option<String>,
    pub state: DepositAddressState,
    pub created_at: UnixSeconds,
    pub retired_at: Option<UnixSeconds>,
}

/// The four commitments that must all exist before an address is active
/// (§4). Each step records when it was committed so a crash between steps
/// leaves a visibly inactive address (C03).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressActivation {
    pub deposit_address_id: DepositAddressId,
    /// Adapter-derived address from the key's public key equals the stored
    /// address; carries the hash of the key descriptor that was checked.
    pub public_key_agreement: Option<ActivationStep>,
    /// Supported assets and the enrolled network profile are committed.
    pub asset_network_configuration: Option<ActivationStep>,
    /// Recovery metadata (key descriptor, participants, recovery profile)
    /// is committed to the recovery store.
    pub recovery_metadata: Option<ActivationStep>,
    /// The indexer has registered the address for monitoring.
    pub monitoring_registration: Option<ActivationStep>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationStep {
    pub committed_at: UnixSeconds,
    /// Commitment to the object that satisfied the step (key descriptor hash,
    /// configuration hash, recovery package hash, cursor id hash).
    pub commitment: Hash32,
    pub actor: String,
}

impl AddressActivation {
    pub fn new(deposit_address_id: DepositAddressId) -> Self {
        AddressActivation {
            deposit_address_id,
            public_key_agreement: None,
            asset_network_configuration: None,
            recovery_metadata: None,
            monitoring_registration: None,
        }
    }

    /// True only when every step is committed.
    pub fn is_complete(&self) -> bool {
        self.public_key_agreement.is_some()
            && self.asset_network_configuration.is_some()
            && self.recovery_metadata.is_some()
            && self.monitoring_registration.is_some()
    }

    /// Names of the steps that are still missing, for operator display.
    pub fn missing_steps(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.public_key_agreement.is_none() {
            v.push("public_key_agreement");
        }
        if self.asset_network_configuration.is_none() {
            v.push("asset_network_configuration");
        }
        if self.recovery_metadata.is_none() {
            v.push("recovery_metadata");
        }
        if self.monitoring_registration.is_none() {
            v.push("monitoring_registration");
        }
        v
    }
}

// ---------------------------------------------------------------------------
// §4 Observed movements, cursors, backfill, cases
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovementDirection {
    Inbound,
    Outbound,
}

/// How the movement was discovered; declared per transfer mechanism so an
/// operator can see which inflows are covered (§4: EVM internal native
/// movements need trace APIs, so only trace-enabled sources discover them).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMechanism {
    /// EVM: included transaction `to`/`value`.
    EvmTransactionValue,
    /// EVM: ERC-20 `Transfer` log.
    EvmErc20TransferLog,
    /// EVM: native value carried by a successful internal frame, from a
    /// `debug_trace*` callTracer (CALL, CREATE, CREATE2, SELFDESTRUCT).
    EvmInternalCallValue,
    /// Solana: pre/post lamport delta of the account.
    SolanaLamportDelta,
    /// Solana: pre/post token balance delta of a token account.
    SolanaTokenBalanceDelta,
}

/// Whether the containing block is still on the canonical chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Canonicality {
    /// On the canonical chain at `observed_state`.
    Canonical,
    /// The containing block was replaced; `at` is the head that replaced it.
    Reorged { at: StateReference },
}

/// Acceptance under the configured finality profile (§4 "display separately").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovementAcceptance {
    /// Seen but not yet final under the profile.
    Observed,
    /// Final under the profile; eligible for a journal credit.
    Accepted,
    /// Final but not creditable (unknown asset, dust, retired address...). A case exists.
    Quarantined,
    /// Was accepted, then reorged out; the journal carries a reversal.
    Reversed,
}

/// One inbound or outbound effect on a monitored address (§4). Identity for
/// deduplication is `(network_id, tx_id, effect_index)`; repeated
/// notifications of the same effect never create another record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedMovement {
    pub movement_id: MovementId,
    pub chain_profile_id: ChainProfileId,
    pub network_id: NetworkId,
    pub deposit_address_id: Option<DepositAddressId>,
    pub chain_wallet_id: Option<ChainWalletId>,
    pub address: Bytes,
    pub direction: MovementDirection,
    /// Chain-native asset identity as decoded; registry lookup may fail.
    pub asset: AssetKind,
    /// Registry asset when the decoded identity is enrolled; `None` = unknown.
    pub asset_id: Option<AssetId>,
    pub amount_base_units: Amount,
    pub counterparty: Bytes,
    pub tx_id: ChainTxId,
    /// Position of this effect within the transaction (log index, account index).
    pub effect_index: u32,
    pub mechanism: DiscoveryMechanism,
    /// Block/slot that contained the transaction when first observed.
    pub observed_state: StateReference,
    pub canonicality: Canonicality,
    pub acceptance: MovementAcceptance,
    /// Operation family when this is an outbound movement the platform issued.
    pub operation_family_id: Option<OperationFamilyId>,
    pub sources: Vec<EvidenceSourceId>,
    pub observed_at: UnixSeconds,
    pub updated_at: UnixSeconds,
}

impl ObservedMovement {
    /// Deduplication key (§4: repeated notifications must not create another credit).
    pub fn dedup_key(&self) -> (NetworkId, ChainTxId, u32) {
        (self.network_id.clone(), self.tx_id.clone(), self.effect_index)
    }
}

/// Durable indexer position per chain profile (§4). Survives restarts; a
/// gap between `last_scanned_height` and the head is a backfill candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexCursor {
    pub cursor_id: CursorId,
    pub chain_profile_id: ChainProfileId,
    pub network_id: NetworkId,
    /// Last height fully scanned; `None` before the first scan.
    pub last_scanned_height: Option<u64>,
    pub last_scanned_hash: Option<Bytes>,
    /// Highest height known final under the profile at last scan.
    pub finalized_height: u64,
    pub monitored_addresses: u64,
    pub updated_at: UnixSeconds,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackfillState {
    Pending,
    Running { next_height: u64 },
    Complete { movements_found: u64 },
    Failed { reason: String },
}

/// Scan of a height range the live cursor missed (C05). Until complete, the
/// affected range is reported as uncertain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillJob {
    pub job_id: BackfillJobId,
    pub chain_profile_id: ChainProfileId,
    pub from_height: u64,
    pub to_height: u64,
    pub reason: String,
    pub state: BackfillState,
    pub created_at: UnixSeconds,
    pub updated_at: UnixSeconds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    UnknownAsset,
    Dust,
    WrongNetwork,
    MissingRoutingReference,
    RetiredAddress,
    InactiveAddress,
    NonstandardAsset,
    Reorged,
    /// Journal and chain checkpoint disagree (§6, C19).
    ReconciliationDifference,
    /// Workflow stopped after its spend/attempt ceiling (§5).
    WorkflowExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseState {
    Open,
    /// Resolved under administrative authorization; `journal_entry_id` names
    /// the correcting entry when one was required (C19: never a silent rebalance).
    Resolved { resolution: String, resolved_by: Vec<CredentialId>, resolved_at: UnixSeconds, journal_entry_id: Option<JournalEntryId> },
}

/// Explicit exception for a movement or reconciliation difference (§4, §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositCase {
    pub case_id: CaseId,
    pub kind: CaseKind,
    pub severity: CaseSeverity,
    pub chain_profile_id: ChainProfileId,
    pub movement_id: Option<MovementId>,
    pub checkpoint_id: Option<CheckpointId>,
    pub workflow_id: Option<WorkflowId>,
    pub chain_wallet_id: Option<ChainWalletId>,
    pub asset_id: Option<AssetId>,
    pub amount_base_units: Option<Amount>,
    pub detail: String,
    pub owner: String,
    pub state: CaseState,
    pub opened_at: UnixSeconds,
}

// ---------------------------------------------------------------------------
// §6 Movement journal
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySide {
    /// Increases holdings of (wallet, asset).
    Credit,
    /// Decreases holdings of (wallet, asset).
    Debit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InternalLeg {
    Source,
    Destination,
}

/// Why an entry exists. Reservations are not entries: they have their own
/// lifecycle at the authority and are never double-counted as settled outflows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalEntryKind {
    /// Inbound movement accepted under the finality profile.
    AcceptedReceipt { movement_id: MovementId },
    /// Actual outgoing movement observed on chain for a platform operation.
    OutgoingMovement { operation_family_id: OperationFamilyId, movement_id: MovementId },
    /// Network fee actually paid, attributed to the operation that paid it.
    NetworkFee { operation_family_id: OperationFamilyId, tx_id: ChainTxId },
    /// Account funding / rent (Solana token-account creation and the like).
    AccountFunding { operation_family_id: OperationFamilyId, tx_id: ChainTxId, funded_account: Bytes },
    /// One leg of an internal wallet-to-wallet transfer; both legs link the
    /// same operation family so reporting never mistakes it for revenue or
    /// external spending.
    InternalTransfer { operation_family_id: OperationFamilyId, leg: InternalLeg, counterparty_wallet_id: ChainWalletId, movement_id: MovementId },
    /// Reversal of an earlier entry (reorg correction, C06).
    Reversal { reverses: JournalEntryId, reason: String },
    /// Externally authorized adjustment resolving a reconciliation case (C19).
    ExternalAdjustment { case_id: CaseId, authorized_by: Vec<CredentialId>, reason: String },
}

impl JournalEntryKind {
    /// Entries that represent money leaving or entering the institution,
    /// as opposed to internal moves, fees, and corrections.
    pub fn is_external(&self) -> bool {
        matches!(self, JournalEntryKind::AcceptedReceipt { .. } | JournalEntryKind::OutgoingMovement { .. })
    }
}

/// Unsigned body of an immutable per-asset journal entry (§6). Entries are
/// hash-chained per journal; `entry_hash = SHA256("OIC/JOURNAL/v1" || CanonicalEncode(body))`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntryBody {
    pub entry_id: JournalEntryId,
    pub sequence: u64,
    pub previous_entry_hash: Hash32,
    pub at: UnixSeconds,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub vault_id: VaultId,
    pub chain_wallet_id: ChainWalletId,
    pub asset_id: AssetId,
    pub side: EntrySide,
    pub amount_base_units: Amount,
    pub kind: JournalEntryKind,
    /// Chain state the entry was posted against (for checkpoint comparison).
    pub posted_at_state: StateReference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub body: JournalEntryBody,
    pub entry_hash: Hash32,
}

/// Derived holdings of one (wallet, asset) at a journal sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Holdings {
    pub chain_wallet_id: Option<ChainWalletId>,
    pub asset_id: Option<AssetId>,
    /// Sum of credits minus debits of accepted entries.
    pub settled: Amount,
    /// Outstanding reservations at the authority (worst-case outflow).
    pub reserved: Amount,
    /// Movements observed but not yet accepted under the finality profile.
    pub pending_inbound: Amount,
    /// `settled - reserved`, saturating at zero.
    pub available: Amount,
    pub as_of_sequence: u64,
}

// ---------------------------------------------------------------------------
// §6 Reconciliation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciledBalance {
    pub chain_wallet_id: ChainWalletId,
    pub asset_id: AssetId,
    /// Independently obtained chain holdings at the checkpoint state.
    pub chain_balance: Amount,
    /// Journal settled holdings at the checkpoint sequence; zero when the
    /// journal position is negative (see `journal_shortfall`).
    pub journal_balance: Amount,
    /// Magnitude by which journal debits exceed credits. Nonzero only when the
    /// journal position is negative, for example after eligible spends against
    /// quarantined receipts; `journal_balance` is then zero. The pair keeps the
    /// signed journal position representable without signed amounts.
    #[serde(default)]
    pub journal_shortfall: Amount,
    pub reserved: Amount,
    pub pending_inbound: Amount,
}

impl ReconciledBalance {
    /// Signed difference `chain - (journal_balance - journal_shortfall)` as
    /// (is_negative, magnitude). A shortfall means the authorized repair is a
    /// credit of `chain + shortfall`; the magnitude saturates rather than wraps.
    pub fn difference(&self) -> (bool, Amount) {
        if !self.journal_shortfall.is_zero() {
            (
                false,
                Amount(self.chain_balance.0.saturating_add(self.journal_shortfall.0)),
            )
        } else if self.chain_balance.0 >= self.journal_balance.0 {
            (false, Amount(self.chain_balance.0 - self.journal_balance.0))
        } else {
            (true, Amount(self.journal_balance.0 - self.chain_balance.0))
        }
    }

    pub fn is_consistent(&self) -> bool {
        self.journal_shortfall.is_zero() && self.chain_balance == self.journal_balance
    }
}

/// Journal versus chain at a compatible checkpoint (§6, C19). Unsigned body;
/// the reconciler signs `SHA256("OIC/RECONCILIATION/v1" || CanonicalEncode(body))`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationCheckpointBody {
    pub checkpoint_id: CheckpointId,
    pub chain_profile_id: ChainProfileId,
    pub network_id: NetworkId,
    /// Chain state the balances were read at (finalized under the profile).
    pub state: StateReference,
    /// Journal sequence the journal balances were computed at.
    pub journal_sequence: u64,
    pub journal_head_hash: Hash32,
    pub balances: Vec<ReconciledBalance>,
    /// Cases opened for every inconsistent balance.
    pub cases_opened: Vec<CaseId>,
    pub sources: Vec<EvidenceSourceId>,
    pub at: UnixSeconds,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationCheckpoint {
    pub body: ReconciliationCheckpointBody,
    pub reconciler_key_id: KeyId,
    pub signature: SignatureBytes,
}

impl ReconciliationCheckpointBody {
    pub fn is_consistent(&self) -> bool {
        self.balances.iter().all(ReconciledBalance::is_consistent)
    }
}

// ---------------------------------------------------------------------------
// §5 Workflows
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowKind {
    /// Top up native fee balance of an approved recipient wallet from a source wallet.
    GasFunding,
    /// Consolidate a supported asset from an operating wallet to the treasury destination.
    Sweep,
    /// Bounded treasury-to-operational funding.
    TreasuryFunding,
}

/// Durable trigger identity (§5): `trigger_id` is derived from the trigger's
/// content so a replayed notification maps to the same workflow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowTrigger {
    /// An accepted inbound movement (one top-up per accepted movement at most).
    DepositAccepted { movement_id: MovementId },
    /// Native balance below the configured minimum at a specific checkpoint.
    BalanceBelowMinimum { chain_wallet_id: ChainWalletId, asset_id: AssetId, observed_state: StateReference },
    /// Supported-asset balance above the sweep threshold at a specific checkpoint.
    SweepThreshold { chain_wallet_id: ChainWalletId, asset_id: AssetId, observed_state: StateReference },
    /// Operator-initiated with an external reference.
    Manual { external_reference: String, requested_by: CredentialId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseReason {
    FeeCeiling,
    UncertainIssuance,
    StaleEvidence,
    InsufficientFunds,
    PolicyConflict,
    ApprovalPending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowState {
    Pending,
    Running,
    Paused { reason: PauseReason, detail: String },
    Complete,
    /// Stopped after the attempt or spend ceiling; a case exists (§5).
    Exhausted { case_id: CaseId },
    Failed { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepState {
    Blocked,
    Ready,
    IntentCreated,
    Settled,
    Failed,
}

/// One child intent and its ordering dependencies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub step_index: u16,
    pub purpose: OperationPurpose,
    pub chain_wallet_id: ChainWalletId,
    pub asset_id: AssetId,
    pub amount_base_units: Amount,
    pub destination_id: DestinationId,
    pub destination_version: u32,
    pub depends_on: Vec<u16>,
    pub intent_id: Option<IntentId>,
    pub operation_family_id: Option<OperationFamilyId>,
    pub state: WorkflowStepState,
    pub attempts: u32,
    pub last_error: Option<String>,
}

/// Workflow record (§5): trigger identity, child intents, dependencies,
/// retry state, spend accounting, and completion. The controller creates
/// ordinary intents and has no signing bypass.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRecord {
    pub workflow_id: WorkflowId,
    pub kind: WorkflowKind,
    pub trigger_id: TriggerId,
    pub trigger: WorkflowTrigger,
    pub vault_id: VaultId,
    pub steps: Vec<WorkflowStep>,
    pub state: WorkflowState,
    pub attempts: u32,
    pub max_attempts: u32,
    /// Native units spent on fees + funding so far by this workflow.
    pub total_native_spent: Amount,
    pub max_native_spend: Amount,
    pub created_at: UnixSeconds,
    pub updated_at: UnixSeconds,
}

impl WorkflowRecord {
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, WorkflowState::Complete | WorkflowState::Exhausted { .. } | WorkflowState::Failed { .. })
    }

    /// Steps whose dependencies are all settled and which have not started.
    pub fn ready_steps(&self) -> Vec<u16> {
        self.steps
            .iter()
            .filter(|s| matches!(s.state, WorkflowStepState::Blocked | WorkflowStepState::Ready))
            .filter(|s| {
                s.depends_on
                    .iter()
                    .all(|d| self.steps.iter().any(|t| t.step_index == *d && t.state == WorkflowStepState::Settled))
            })
            .map(|s| s.step_index)
            .collect()
    }
}

/// Gas-funding configuration (§5). The recipient set is explicit; there is
/// no arbitrary spender or arbitrary fee payer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasFundingRule {
    pub rule_id: String,
    pub chain_profile_id: ChainProfileId,
    pub source_wallet_id: ChainWalletId,
    /// Recipient wallet → registered destination (id, version) for its address.
    pub recipients: Vec<GasRecipient>,
    pub native_asset_id: AssetId,
    pub minimum_balance: Amount,
    pub target_balance: Amount,
    pub max_refill_per_operation: Amount,
    pub max_refill_per_period: Amount,
    pub period_seconds: u64,
    pub max_attempts: u32,
    /// Maximum native fee the funding transaction itself may pay (C10).
    pub max_native_fee: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasRecipient {
    pub chain_wallet_id: ChainWalletId,
    pub destination_id: DestinationId,
    pub destination_version: u32,
}

/// Sweep configuration (§5): consolidate `asset_id` from `source_wallet_id`
/// to the treasury destination when the balance exceeds `threshold`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepRule {
    pub rule_id: String,
    pub chain_profile_id: ChainProfileId,
    pub source_wallet_id: ChainWalletId,
    pub asset_id: AssetId,
    pub destination_id: DestinationId,
    pub destination_version: u32,
    pub threshold: Amount,
    /// Minimum amount worth moving (below this, wait).
    pub minimum_useful_value: Amount,
    pub max_native_fee: Amount,
    /// Amount of native fee balance the sweep requires before building
    /// (triggers gas funding when below).
    pub required_native_balance: Amount,
    pub max_attempts: u32,
}

// ---------------------------------------------------------------------------
// §10 Events and webhooks (RFC 0001 §13.4)
// ---------------------------------------------------------------------------

/// Lifecycle event body. `sequence` is institution-global and gap-free so a
/// subscriber can detect and replay missed deliveries (C18). Signature covers
/// `SHA256("OIC/WEBHOOK/v1" || CanonicalEncode(body))`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEventBody {
    pub event_id: EventId,
    pub sequence: u64,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub at: UnixSeconds,
    pub kind: LifecycleEventKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEventKind {
    OperationStateChanged {
        intent_id: IntentId,
        operation_family_id: OperationFamilyId,
        candidate_id: Option<CandidateId>,
        candidate_revision: Option<u32>,
        from: Option<LifecycleState>,
        to: LifecycleState,
        tx_id: Option<ChainTxId>,
    },
    MovementObserved { movement_id: MovementId, acceptance: MovementAcceptance },
    CaseOpened { case_id: CaseId, kind: CaseKind },
    CaseResolved { case_id: CaseId },
    WorkflowStateChanged { workflow_id: WorkflowId, state: WorkflowState },
    CheckpointPublished { checkpoint_id: CheckpointId, consistent: bool },
    PolicyActivated { policy_id: PolicyId, policy_epoch: Epoch },
    DestinationActivated { destination_id: DestinationId, version: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub body: LifecycleEventBody,
    pub signing_key_id: KeyId,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookSubscription {
    pub subscription_id: WebhookSubscriptionId,
    pub institution_id: InstitutionId,
    pub url: String,
    /// Empty = all kinds.
    pub kinds: Vec<String>,
    /// Sequence of the last event the subscriber acknowledged.
    pub acknowledged_sequence: u64,
    pub active: bool,
    pub created_at: UnixSeconds,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(i: u16, deps: Vec<u16>, state: WorkflowStepState) -> WorkflowStep {
        WorkflowStep {
            step_index: i,
            purpose: OperationPurpose::Fees,
            chain_wallet_id: ChainWalletId::unchecked("w"),
            asset_id: AssetId::unchecked("a"),
            amount_base_units: Amount(1),
            destination_id: DestinationId::unchecked("d"),
            destination_version: 1,
            depends_on: deps,
            intent_id: None,
            operation_family_id: None,
            state,
            attempts: 0,
            last_error: None,
        }
    }

    #[test]
    fn activation_requires_all_four_steps() {
        let mut a = AddressActivation::new(DepositAddressId::unchecked("da"));
        assert!(!a.is_complete());
        assert_eq!(a.missing_steps().len(), 4);
        let s = ActivationStep { committed_at: UnixSeconds(1), commitment: Hash32::ZERO, actor: "t".into() };
        a.public_key_agreement = Some(s.clone());
        a.asset_network_configuration = Some(s.clone());
        a.recovery_metadata = Some(s.clone());
        assert_eq!(a.missing_steps(), vec!["monitoring_registration"]);
        a.monitoring_registration = Some(s);
        assert!(a.is_complete());
    }

    #[test]
    fn ready_steps_follow_dependencies() {
        let w = WorkflowRecord {
            workflow_id: WorkflowId::unchecked("wf"),
            kind: WorkflowKind::Sweep,
            trigger_id: TriggerId::unchecked("t"),
            trigger: WorkflowTrigger::Manual { external_reference: "x".into(), requested_by: CredentialId::unchecked("c") },
            vault_id: VaultId::unchecked("v"),
            steps: vec![step(0, vec![], WorkflowStepState::Settled), step(1, vec![0], WorkflowStepState::Blocked), step(2, vec![1], WorkflowStepState::Blocked)],
            state: WorkflowState::Running,
            attempts: 0,
            max_attempts: 3,
            total_native_spent: Amount::ZERO,
            max_native_spend: Amount(10),
            created_at: UnixSeconds(0),
            updated_at: UnixSeconds(0),
        };
        assert_eq!(w.ready_steps(), vec![1]);
        assert!(!w.is_terminal());
    }

    #[test]
    fn reconciled_difference_is_signed_magnitude() {
        let b = ReconciledBalance {
            chain_wallet_id: ChainWalletId::unchecked("w"),
            asset_id: AssetId::unchecked("a"),
            chain_balance: Amount(5),
            journal_balance: Amount(8),
            journal_shortfall: Amount::ZERO,
            reserved: Amount::ZERO,
            pending_inbound: Amount::ZERO,
        };
        assert_eq!(b.difference(), (true, Amount(3)));
        assert!(!b.is_consistent());
    }

    #[test]
    fn reconciled_shortfall_repairs_with_a_credit_of_chain_plus_shortfall() {
        let b = ReconciledBalance {
            chain_wallet_id: ChainWalletId::unchecked("w"),
            asset_id: AssetId::unchecked("a"),
            chain_balance: Amount(5),
            journal_balance: Amount::ZERO,
            journal_shortfall: Amount(3),
            reserved: Amount::ZERO,
            pending_inbound: Amount::ZERO,
        };
        assert_eq!(b.difference(), (false, Amount(8)));
        assert!(!b.is_consistent());
    }
}

// ---------------------------------------------------------------------------
// Approval package (RFC 0001 §4.3, RFC 0002 §8)
// ---------------------------------------------------------------------------

/// Every object an authorization envelope commits to, delivered together to
/// approvers (independent approval client), signers, and auditors. The
/// receiver never trusts the package's text: it recomputes each hash and
/// re-decodes the candidate against its own pinned adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPackage {
    pub schema_version: u16,
    pub intent: Intent,
    pub candidate: Candidate,
    pub vault: Vault,
    pub wallet: ChainWallet,
    pub key: KeyDescriptor,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub policy: PolicyBundle,
    pub evidence: EvidenceBundle,
}

impl ApprovalPackage {
    pub const SCHEMA_VERSION: u16 = 1;
}
