//! Core security objects (RFC 0001 §3.1). Every object here is chain-neutral.
//! Chain-specific detail lives behind `Bytes` fields whose decoding is owned by
//! the pinned adapter and whose canonical hash is committed in the envelope.

use crate::ids::*;
use crate::primitives::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Institution / vault / wallet / key
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Institution {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub display_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultTier {
    Operating,
    Treasury,
    Reserve,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub vault_id: VaultId,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub tier: VaultTier,
    pub policy_id: PolicyId,
    pub display_name: String,
}

/// One native address/account bound to one key and one network profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainWallet {
    pub chain_wallet_id: ChainWalletId,
    pub vault_id: VaultId,
    pub chain_profile_id: ChainProfileId,
    pub network_id: NetworkId,
    pub key_id: KeyId,
    pub key_epoch: Epoch,
    /// Chain-native address bytes as the adapter defines them (20 bytes EVM, 32 bytes Solana).
    pub address: Bytes,
    /// Adapter-defined human form, derived from `address`, used only for display.
    pub address_display: String,
    /// Deposits are not active until the ceremony and recovery metadata are committed (§13.1).
    pub active: bool,
}

/// Signed descriptor produced by a distributed key generation ceremony (§7.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDescriptor {
    pub key_id: KeyId,
    pub key_epoch: Epoch,
    pub scheme: SchemeId,
    pub public_key: PublicKey,
    pub backend_id: String,
    pub backend_commit: String,
    pub participants: Vec<ParticipantId>,
    pub threshold: u16,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub networks: Vec<NetworkId>,
    pub recovery_profile: String,
}

impl KeyDescriptor {
    pub fn public_key_hash_input(&self) -> &[u8] {
        self.public_key.bytes.as_slice()
    }
}

// ---------------------------------------------------------------------------
// Assets and destinations
// ---------------------------------------------------------------------------

/// Asset identity is network + contract/mint. Symbol and decimals are metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Native,
    Erc20 { contract: Bytes },
    SplToken { mint: Bytes, token_program: Bytes },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetBehaviorProfile {
    /// Plain transfer semantics verified against the pinned decoder.
    Standard,
    /// Known fee-on-transfer, rebasing, pausable, upgradeable, or extension-bearing.
    /// Watchable but not automatically sendable.
    Nonstandard,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub asset_id: AssetId,
    pub network_id: NetworkId,
    pub asset: AssetKind,
    pub decimals: u8,
    pub symbol: String,
    pub behavior: AssetBehaviorProfile,
}

/// Versioned, verified counterparty destination. Approval binds to a specific
/// version; a later edit is a new version and does not retroactively apply.
///
/// A destination is an administrative-quorum-signed object exactly like a
/// [`PolicyBundle`]: `administrative_signatures` sign
/// `SHA256("OIC/DESTINATION/v1" || CanonicalEncode(all other fields))`.
/// Every verifier that acts on a destination address (signer, independent
/// approval client, authority) checks the quorum, so a coordinator cannot
/// substitute an attacker address under a registered destination id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterpartyDestination {
    pub destination_id: DestinationId,
    pub version: u32,
    pub network_id: NetworkId,
    pub address: Bytes,
    pub address_display: String,
    pub display_name: String,
    /// Empty means any asset enrolled on `network_id`.
    pub allowed_assets: Vec<AssetId>,
    pub verification_evidence: String,
    pub activation_epoch: Epoch,
    /// Administrative quorum over the destination hash (RFC 0002 §7, §8).
    pub administrative_signatures: Vec<CredentialSignature>,
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPurpose {
    Settlement,
    Treasury,
    Payroll,
    Fees,
    Internal,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRole {
    TreasuryApprover,
    SecurityApprover,
    Administrator,
    Automated,
}

/// Rolling exposure limit over a window, scoped to (vault, asset).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureLimit {
    pub window_seconds: u64,
    pub max_outflow_base_units: Amount,
}

/// One deterministic allow rule. The kernel evaluates rules in order; the
/// first matching rule's requirements apply. Hard denials always dominate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub vaults: Vec<VaultId>,
    /// Empty = any enrolled asset.
    pub assets: Vec<AssetId>,
    /// Empty = any registered destination.
    pub destinations: Vec<DestinationId>,
    pub purposes: Vec<OperationPurpose>,
    pub max_amount_per_operation: Amount,
    pub max_native_fee_per_operation: Amount,
    pub rolling_limits: Vec<ExposureLimit>,
    pub required_approvals: u8,
    pub approval_roles: Vec<ApprovalRole>,
    /// Proposer may never also count as an approver when true.
    pub exclude_proposer: bool,
    /// Operating window as seconds-of-day UTC; `None` = always.
    pub operating_window: Option<(u32, u32)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub policy_id: PolicyId,
    pub policy_epoch: Epoch,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub rules: Vec<PolicyRule>,
    /// Hard denials evaluated first.
    pub denied_destinations: Vec<DestinationId>,
    pub denied_assets: Vec<AssetId>,
    pub max_evidence_age_seconds: u64,
    pub allowlist_version: u32,
    pub activation_epoch: Epoch,
    pub administrative_signatures: Vec<CredentialSignature>,
}

/// Signature by an enrolled credential over a domain-separated hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSignature {
    pub credential_id: CredentialId,
    pub signature: SignatureBytes,
}

// ---------------------------------------------------------------------------
// Intent
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    ExactCandidate,
    BoundedDirectTransfer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentOperation {
    AssetTransfer {
        asset_id: AssetId,
        amount_base_units: Amount,
        destination_id: DestinationId,
        destination_version: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentConstraints {
    pub max_network_fee_base_units: Amount,
    pub approval_mode: ApprovalMode,
    pub maximum_successful_payments: u8,
}

/// Immutable business intent (§13.2). The idempotency key scope is
/// (institution, route, canonical body).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    pub schema_version: u16,
    pub intent_id: IntentId,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub vault_id: VaultId,
    pub chain_wallet_id: ChainWalletId,
    pub chain_profile_id: ChainProfileId,
    pub operation: IntentOperation,
    pub constraints: IntentConstraints,
    pub purpose: OperationPurpose,
    pub external_reference: String,
    pub proposer_credential_id: CredentialId,
    pub created_at: UnixSeconds,
}

// ---------------------------------------------------------------------------
// Approval grants
// ---------------------------------------------------------------------------

/// Fields a bounded template permits the builder to fill after approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillableField {
    SolanaRecentBlockhash,
    EvmNonce,
    EvmFeeFields,
    EvmGasLimit,
}

/// Bounded-intent template (§3.4). V0 supports direct transfers only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedTransferTemplate {
    pub chain_wallet_id: ChainWalletId,
    pub network_id: NetworkId,
    pub asset_id: AssetId,
    pub amount_base_units: Amount,
    pub destination_id: DestinationId,
    pub destination_version: u32,
    pub destination_address: Bytes,
    pub max_native_fee_base_units: Amount,
    pub maximum_successful_payments: u8,
    pub fillable: Vec<FillableField>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    ExactCandidate {
        candidate_id: CandidateId,
        candidate_revision: u32,
        preview_hash: Hash32,
    },
    BoundedDirectTransfer {
        template: BoundedTransferTemplate,
    },
}

/// Unsigned body of an approval grant; `ApprovalGrant.signature` covers
/// `SHA256("OIC/APPROVAL/v1" || CanonicalEncode(body))`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalGrantBody {
    pub grant_id: GrantId,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub vault_id: VaultId,
    pub intent_id: IntentId,
    pub intent_hash: Hash32,
    pub policy_id: PolicyId,
    pub policy_epoch: Epoch,
    pub scope: GrantScope,
    pub approver_credential_id: CredentialId,
    pub approver_role: ApprovalRole,
    pub issued_at: UnixSeconds,
    pub expires_at: UnixSeconds,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalGrant {
    pub body: ApprovalGrantBody,
    pub signature: SignatureBytes,
}

// ---------------------------------------------------------------------------
// Candidates, decoded operations, resources
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSigningPayload {
    pub payload_index: u16,
    pub scheme_id: SchemeId,
    /// For prehashed schemes: the 32-byte digest. For pure schemes: the full message.
    pub message_or_digest: Bytes,
    pub required_key_id: KeyId,
    /// Adapter-defined context (e.g. `"evm-type2"`, `"solana-message-v0"`).
    pub native_signing_context: String,
}

/// Exact unsigned native transaction and the payloads the signer must derive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub intent_id: IntentId,
    pub operation_family_id: OperationFamilyId,
    pub chain_profile_id: ChainProfileId,
    pub adapter_id: AdapterId,
    pub adapter_version: String,
    pub native_unsigned_bytes: Bytes,
    pub signing_payloads: Vec<NativeSigningPayload>,
    pub evidence_bundle_hash: Hash32,
    pub built_at: UnixSeconds,
}

/// Chain-native resource that must be reserved before signing (§5.3, §9.2, §10.5).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeResource {
    EvmNonce { network_id: NetworkId, sender: Bytes, nonce: u64 },
    SolanaBlockhash { network_id: NetworkId, fee_payer: Bytes, blockhash: Bytes },
    SolanaDurableNonce { network_id: NetworkId, nonce_account: Bytes, nonce_value: Bytes },
    BitcoinUtxo { network_id: NetworkId, txid: Bytes, vout: u32 },
    SuiObject { network_id: NetworkId, object_id: Bytes, version: u64 },
    AptosSequence { network_id: NetworkId, sender: Bytes, sequence: u64 },
    CosmosSequence { network_id: NetworkId, account: Bytes, sequence: u64 },
    XrplSequence { network_id: NetworkId, account: Bytes, sequence: u32 },
}

/// Worst-case outflow for one asset, charged to the budget.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AssetOutflow {
    pub asset_id: AssetId,
    pub amount_base_units: Amount,
}

/// Worst-case native fee in native units. Reserved separately from asset outflow.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NativeFee {
    pub network_id: NetworkId,
    pub amount_base_units: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceClaims {
    pub resources: Vec<NativeResource>,
    pub asset_outflows: Vec<AssetOutflow>,
    pub native_fees: Vec<NativeFee>,
}

/// Chain-neutral meaning of a decoded candidate. An adapter MUST produce one of
/// these variants or fail with `UnsupportedCapability`; it must never
/// summarise an unrecognised transaction as a transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodedOperation {
    DirectTransfer {
        network_id: NetworkId,
        asset: AssetKind,
        sender: Bytes,
        recipient: Bytes,
        amount_base_units: Amount,
        /// Native value moved in addition to token amount (must be zero for ERC-20 transfers).
        native_value_base_units: Amount,
        max_native_fee_base_units: Amount,
        /// Adapter-specific verified detail, canonically encoded (e.g. decoded instruction list).
        native_detail: Bytes,
    },
}

impl DecodedOperation {
    pub fn recipient(&self) -> &Bytes {
        match self {
            DecodedOperation::DirectTransfer { recipient, .. } => recipient,
        }
    }
    pub fn sender(&self) -> &Bytes {
        match self {
            DecodedOperation::DirectTransfer { sender, .. } => sender,
        }
    }
    pub fn amount(&self) -> Amount {
        match self {
            DecodedOperation::DirectTransfer { amount_base_units, .. } => *amount_base_units,
        }
    }
    pub fn asset(&self) -> &AssetKind {
        match self {
            DecodedOperation::DirectTransfer { asset, .. } => asset,
        }
    }
    pub fn network_id(&self) -> &NetworkId {
        match self {
            DecodedOperation::DirectTransfer { network_id, .. } => network_id,
        }
    }
    pub fn max_native_fee(&self) -> Amount {
        match self {
            DecodedOperation::DirectTransfer { max_native_fee_base_units, .. } => *max_native_fee_base_units,
        }
    }
}

/// Output of signer-local verification: the decoded operation bound to the
/// exact bytes, the derived payloads, and the resource claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedOperation {
    pub decoded: DecodedOperation,
    pub decoded_operation_hash: Hash32,
    pub signing_payloads: Vec<NativeSigningPayload>,
    pub claims: ResourceClaims,
    pub adapter_id: AdapterId,
    pub adapter_version: String,
    pub verifier_build_hash: Hash32,
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTrustLevel {
    /// Operator-run validating node.
    ValidatingNode,
    /// Explicitly trusted provider with cross-check.
    TrustedProviderCrossChecked,
    /// Single provider, no cross-check. Usable only where policy permits.
    SingleProvider,
    /// In-process simulator for development and conformance tests only.
    DevelopmentSimulator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateReference {
    /// Block number / slot / ledger index.
    pub height: u64,
    /// Block hash / bank hash / ledger hash.
    pub hash: Bytes,
    /// Chain-profile-defined commitment ("finalized", "safe", "confirmed", ...).
    pub commitment: String,
}

/// State references, source identities, decoded dependencies, and freshness.
/// `items` carries chain-specific decoded dependencies keyed by adapter-defined
/// names (e.g. `"alt:<address>"`, `"account:<address>"`, `"code:<address>"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub chain_profile_id: ChainProfileId,
    pub network_id: NetworkId,
    pub state: StateReference,
    pub sources: Vec<EvidenceSourceId>,
    pub trust_level: EvidenceTrustLevel,
    pub observed_at: UnixSeconds,
    pub max_staleness_seconds: u64,
    pub verifier_version: String,
    pub items: BTreeMap<String, Bytes>,
}

/// Validated freshness context handed to the policy kernel. It is produced by
/// the authority or signer from a trusted clock source, never by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessContext {
    pub now: UnixSeconds,
}

// ---------------------------------------------------------------------------
// Reservation, authority receipt, issuance
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub reservation_id: ReservationId,
    pub reservation_version: u32,
    pub operation_family_id: OperationFamilyId,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub vault_id: VaultId,
    pub claims: ResourceClaims,
    pub policy_epoch: Epoch,
    pub created_at: UnixSeconds,
    pub issuance_deadline: UnixSeconds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    /// Reservation acquired; signing not yet released.
    Reserved,
    /// Final release: operation is marked possibly issued. Short-lived, session-bound.
    Release,
}

/// Unsigned body of an authority receipt; signature covers
/// `SHA256("OIC/AUTHORITY_RECEIPT/v1" || CanonicalEncode(body))`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityReceiptBody {
    pub kind: ReceiptKind,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub authority_epoch: Epoch,
    pub reservation_id: ReservationId,
    pub reservation_version: u32,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub envelope_body_hash: Hash32,
    pub signer_session_id: SigningSessionId,
    pub policy_epoch: Epoch,
    pub freeze_epoch: Epoch,
    pub issued_at: UnixSeconds,
    pub expires_at: UnixSeconds,
    /// Ordered commit sequence at the authority; totally orders releases vs freezes.
    pub commit_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityReceipt {
    pub body: AuthorityReceiptBody,
    pub authority_key_id: KeyId,
    pub signature: SignatureBytes,
}

/// Durable record that a signature may now exist (§5.4 step 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRecord {
    pub issuance_id: IssuanceId,
    pub operation_family_id: OperationFamilyId,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub envelope_hash: Hash32,
    pub signer_session_id: SigningSessionId,
    pub commit_sequence: u64,
    pub committed_at: UnixSeconds,
}

// ---------------------------------------------------------------------------
// Authorization envelope (§3.3)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainValidityConstraints {
    /// Chain-enforced expiry if any (Solana blockhash window end slot, Aptos expiration...).
    pub expires_at_height: Option<u64>,
    /// Human-readable note from the adapter manifest about replacement/expiry behavior.
    pub replacement_rule: String,
}

/// Body of the authorization envelope. `EnvelopeHash` is
/// `SHA256("OIC/AUTHORIZATION/v1" || CanonicalEncode(body))`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationEnvelopeBody {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub vault_id: VaultId,
    pub chain_wallet_id: ChainWalletId,
    pub intent_id: IntentId,
    pub intent_hash: Hash32,
    pub operation_family_id: OperationFamilyId,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub chain_profile_id: ChainProfileId,
    pub chain_profile_hash: Hash32,
    pub key_id: KeyId,
    pub key_epoch: Epoch,
    pub public_key_hash: Hash32,
    pub adapter_id: AdapterId,
    pub adapter_version: String,
    pub verifier_build_hash: Hash32,
    pub policy_id: PolicyId,
    pub policy_epoch: Epoch,
    pub policy_hash: Hash32,
    pub allowlist_version: u32,
    pub native_unsigned_bytes: Bytes,
    pub native_signing_payloads: Vec<NativeSigningPayload>,
    pub decoded_operation_hash: Hash32,
    pub evidence_bundle_hash: Hash32,
    /// `SHA256("OIC/DESTINATION/v1" || CanonicalEncode(destination without signatures))`
    /// of the exact admin-signed destination version the intent names.
    pub destination_hash: Hash32,
    pub approval_grants: Vec<ApprovalGrant>,
    pub budget_reservation_id: ReservationId,
    pub reservation_version: u32,
    pub resource_reservations: Vec<NativeResource>,
    pub maximum_asset_outflows: Vec<AssetOutflow>,
    pub maximum_native_fees: Vec<NativeFee>,
    pub issuance_deadline: UnixSeconds,
    pub expected_chain_validity_constraints: ChainValidityConstraints,
    pub signer_session_id: SigningSessionId,
    pub participant_set: Vec<ParticipantId>,
}

/// The complete envelope: body plus the authority's reserved receipt. The
/// release receipt is delivered separately at the final release point and is
/// bound to `envelope_body_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationEnvelope {
    pub body: AuthorizationEnvelopeBody,
    pub authorization_state_receipt: AuthorityReceipt,
}

// ---------------------------------------------------------------------------
// Signing session
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningSession {
    pub signer_session_id: SigningSessionId,
    pub key_id: KeyId,
    pub key_epoch: Epoch,
    pub backend_id: String,
    pub participants: Vec<ParticipantId>,
    pub envelope_hash: Hash32,
    pub created_at: UnixSeconds,
}

// ---------------------------------------------------------------------------
// Lifecycle and chain observation (§12)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    Draft,
    Built,
    Verified,
    PolicyEvaluated,
    AwaitingApproval,
    Reserved,
    Authorized,
    IssuanceCommitted,
    Signing,
    SignatureObserved,
    Submitted,
    Included,
    FinalizedSuccess,
    FinalizedFailure,
    Rejected,
    ApprovalExpired,
    AbortedBeforeIssuance,
    IssuanceUnknown,
    SubmissionUnknown,
    Reorged,
    ReplacementPending,
    DefinitivelyInvalidated,
}

impl LifecycleState {
    /// True when a signature may exist and exposure must be retained (I5).
    pub fn exposure_retained(self) -> bool {
        use LifecycleState::*;
        matches!(
            self,
            Reserved
                | Authorized
                | IssuanceCommitted
                | Signing
                | SignatureObserved
                | Submitted
                | Included
                | IssuanceUnknown
                | SubmissionUnknown
                | Reorged
                | ReplacementPending
        )
    }

    /// True once the operation can never again produce a chain effect.
    pub fn terminal_released(self) -> bool {
        use LifecycleState::*;
        matches!(
            self,
            FinalizedSuccess | FinalizedFailure | Rejected | ApprovalExpired | AbortedBeforeIssuance | DefinitivelyInvalidated
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainObservation {
    Submitted { tx_id: ChainTxId, source: EvidenceSourceId, at: UnixSeconds },
    Included { tx_id: ChainTxId, state: StateReference, execution_success: bool, fee_paid: Amount },
    Finalized { tx_id: ChainTxId, state: StateReference, execution_success: bool, fee_paid: Amount, effects_hash: Hash32 },
    Reorged { tx_id: ChainTxId, previous_state: StateReference },
    DefinitivelyInvalidated { reason: String, state: StateReference },
    Conflict { sources: Vec<EvidenceSourceId>, detail: String },
}

// ---------------------------------------------------------------------------
// Audit (§14)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventBody {
    pub event_id: AuditEventId,
    pub sequence: u64,
    pub previous_event_hash: Hash32,
    pub at: UnixSeconds,
    pub actor: String,
    pub action: String,
    pub object_commitments: BTreeMap<String, Hash32>,
    pub policy_epoch: Epoch,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub body: AuditEventBody,
    pub service_key_id: KeyId,
    pub signature: SignatureBytes,
}
