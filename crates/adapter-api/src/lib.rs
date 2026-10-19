//! # oic-adapter-api
//!
//! The shared core standardises authorization and lifecycle, not transaction
//! semantics (RFC 0001 §8). Each adapter ships a capability manifest and
//! pinned verification code and implements this interface:
//!
//! ```text
//! identify_network(profile, evidence) -> VerifiedNetworkContext
//! build_candidate(intent, resources, evidence) -> NativeCandidate
//! decode_candidate(candidate, evidence) -> DecodedOperation
//! verify_candidate(candidate, intent_or_grant, evidence) -> VerifiedOperation
//! resource_requirements(verified_operation) -> ResourceClaims
//! signing_payloads(verified_operation) -> NativeSigningPayload[]
//! assemble_signed_transaction(candidate, signatures) -> SignedTransaction
//! verify_signed_transaction(signed_transaction, candidate) -> VerifiedSignedTransaction
//! observe(transaction_id, chain_evidence) -> LifecycleObservation
//! prove_invalidation(operation_family, chain_evidence) -> InvalidationEvidence | Unknown
//! ```
//!
//! `decode_candidate`, `verify_candidate`, `signing_payloads` and
//! `verify_signed_transaction` are the signer-local functions; they must be
//! pure over their inputs. Building and simulation may run anywhere.

use oic_domain_types::*;
use serde::{Deserialize, Serialize};

/// Enrolled network profile. Its canonical hash is bound into the envelope as
/// `chain_profile_hash`, so a silently changed chain ID or genesis fails closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainProfile {
    pub chain_profile_id: ChainProfileId,
    pub adapter_id: AdapterId,
    pub network_id: NetworkId,
    /// EVM chain id, Solana genesis hash, etc., in adapter-defined canonical form.
    pub network_binding: Bytes,
    pub display_name: String,
    /// Accepted transaction/message versions, adapter-defined strings.
    pub accepted_versions: Vec<String>,
    /// Finality commitment this profile accepts for releasing obligations.
    pub finality_commitment: String,
    /// Confirmations required for `Included -> Finalized` where applicable.
    pub finality_depth: u64,
    pub max_evidence_age_seconds: u64,
    pub accepted_trust_levels: Vec<EvidenceTrustLevel>,
}

impl ChainProfile {
    pub fn hash(&self) -> OicResult<Hash32> {
        oic_canonical_encoding::domain_hash(domains::CHAIN_PROFILE, self)
    }
}

/// Capability manifest published with every adapter release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterManifest {
    pub adapter_id: AdapterId,
    pub adapter_version: String,
    pub verifier_build_hash: Hash32,
    pub signing_schemes: Vec<SchemeId>,
    pub accepted_transaction_versions: Vec<String>,
    pub supported_operations: Vec<String>,
    pub supported_asset_standards: Vec<String>,
    pub replay_protection: String,
    pub expiry_behavior: String,
    pub resource_lock_rules: String,
    pub fee_accounting: String,
    pub replacement_rules: String,
    pub known_external_authorities: Vec<String>,
    pub conformance_vector_set: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedNetworkContext {
    pub chain_profile_id: ChainProfileId,
    pub chain_profile_hash: Hash32,
    pub network_id: NetworkId,
    pub state: StateReference,
}

/// What the builder knows when constructing a candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildContext {
    pub intent: Intent,
    pub wallet: ChainWallet,
    pub key: KeyDescriptor,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub profile: ChainProfile,
    pub evidence: EvidenceBundle,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub operation_family_id: OperationFamilyId,
    pub built_at: UnixSeconds,
}

/// What the signer-local verifier is given. The adapter must not need
/// anything else to decide; absence fails closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyContext<'a> {
    pub profile: &'a ChainProfile,
    pub wallet: &'a ChainWallet,
    pub key: &'a KeyDescriptor,
    pub asset: &'a Asset,
    pub destination: &'a CounterpartyDestination,
    pub evidence: &'a EvidenceBundle,
}

/// Exact-candidate or bounded-template authorization target used in `verify_candidate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationTarget<'a> {
    Intent(&'a Intent),
    Template(&'a BoundedTransferTemplate),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub signed_bytes: Bytes,
    pub chain_tx_id: ChainTxId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedSignedTransaction {
    pub signed: SignedTransaction,
    /// Signer address/public key recovered or verified from the signature(s).
    pub verified_signers: Vec<Bytes>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationEvidence {
    Definitive { reason: String, state: StateReference },
    Unknown,
}

/// Chain adapter. Implementations must be deterministic and must never
/// perform I/O; all chain state arrives through `EvidenceBundle`.
pub trait ChainAdapter: Send + Sync {
    fn manifest(&self) -> AdapterManifest;

    fn identify_network(&self, profile: &ChainProfile, evidence: &EvidenceBundle) -> OicResult<VerifiedNetworkContext>;

    fn build_candidate(&self, ctx: &BuildContext) -> OicResult<Candidate>;

    fn decode_candidate(&self, candidate: &Candidate, ctx: &VerifyContext<'_>) -> OicResult<DecodedOperation>;

    fn verify_candidate(
        &self,
        candidate: &Candidate,
        target: &AuthorizationTarget<'_>,
        ctx: &VerifyContext<'_>,
    ) -> OicResult<VerifiedOperation>;

    fn resource_requirements(&self, verified: &VerifiedOperation) -> OicResult<ResourceClaims> {
        Ok(verified.claims.clone())
    }

    fn signing_payloads(&self, native_unsigned_bytes: &Bytes, key: &KeyDescriptor) -> OicResult<Vec<NativeSigningPayload>>;

    fn assemble_signed_transaction(
        &self,
        candidate: &Candidate,
        key: &KeyDescriptor,
        signatures: &[SignatureBytes],
    ) -> OicResult<SignedTransaction>;

    fn verify_signed_transaction(
        &self,
        signed: &SignedTransaction,
        candidate: &Candidate,
        key: &KeyDescriptor,
    ) -> OicResult<VerifiedSignedTransaction>;

    fn observe(&self, tx_id: &ChainTxId, profile: &ChainProfile, evidence: &EvidenceBundle) -> OicResult<ChainObservation>;

    fn prove_invalidation(
        &self,
        family: &OperationFamilyId,
        candidates: &[Candidate],
        profile: &ChainProfile,
        evidence: &EvidenceBundle,
    ) -> OicResult<InvalidationEvidence>;

    /// Chain-validity constraints to commit into the envelope for this candidate.
    fn validity_constraints(&self, candidate: &Candidate, evidence: &EvidenceBundle) -> OicResult<ChainValidityConstraints>;

    /// Derive the chain address for a public key under this adapter.
    fn derive_address(&self, key: &PublicKey) -> OicResult<(Bytes, String)>;
}

/// Common evidence checks every adapter performs before trusting a bundle.
pub fn check_evidence_scope(profile: &ChainProfile, evidence: &EvidenceBundle, now: Option<UnixSeconds>) -> OicResult<()> {
    if evidence.chain_profile_id != profile.chain_profile_id {
        return Err(OicError::scope("evidence chain_profile_id does not match profile"));
    }
    if evidence.network_id != profile.network_id {
        return Err(OicError::scope("evidence network_id does not match profile"));
    }
    if !profile.accepted_trust_levels.contains(&evidence.trust_level) {
        return Err(OicError::stale_evidence(format!("evidence trust level {:?} not accepted by profile", evidence.trust_level)));
    }
    if evidence.max_staleness_seconds > profile.max_evidence_age_seconds {
        return Err(OicError::stale_evidence("evidence declares a staleness window wider than the profile permits"));
    }
    if let Some(now) = now {
        if now.0 > evidence.observed_at.0.saturating_add(evidence.max_staleness_seconds) {
            return Err(OicError::stale_evidence("evidence is older than its permitted staleness"));
        }
    }
    Ok(())
}

/// Hash of a decoded operation for the envelope.
pub fn decoded_operation_hash(op: &DecodedOperation) -> OicResult<Hash32> {
    oic_canonical_encoding::domain_hash(domains::DECODED_OPERATION, op)
}

/// Hash of an evidence bundle for the envelope.
pub fn evidence_hash(ev: &EvidenceBundle) -> OicResult<Hash32> {
    oic_canonical_encoding::domain_hash(domains::EVIDENCE, ev)
}
