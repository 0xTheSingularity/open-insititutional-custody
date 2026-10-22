//! Authority receipts and signed checkpoints: signing and verification.

use crate::authority_domains;
use crate::state::AuthorityState;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use oic_policy_kernel::ed25519_signature;
use serde::{Deserialize, Serialize};

pub(crate) fn sign_hash(key: &SigningKey, h: &Hash32) -> SignatureBytes {
    SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(key.sign(&h.0).to_bytes().to_vec()) }
}

pub(crate) fn verify_hash(key: &VerifyingKey, h: &Hash32, sig: &SignatureBytes) -> OicResult<()> {
    let sig = ed25519_signature(sig)?;
    key.verify_strict(&h.0, &sig).map_err(|_| OicError::invalid_signature("signature does not verify"))
}

/// `SHA256("OIC/AUTHORITY_RECEIPT/v1" || CanonicalEncode(body))`.
pub fn receipt_hash(body: &AuthorityReceiptBody) -> OicResult<Hash32> {
    domain_hash(domains::AUTHORITY_RECEIPT, body)
}

/// `SHA256("OIC/RESOURCE_CLAIMS/v1" || CanonicalEncode(claims))`, the claims
/// commitment carried by every receipt.
pub fn claims_hash(claims: &ResourceClaims) -> OicResult<Hash32> {
    domain_hash(domains::RESOURCE_CLAIMS, claims)
}

pub(crate) fn sign_receipt(key: &SigningKey, key_id: &KeyId, body: AuthorityReceiptBody) -> OicResult<AuthorityReceipt> {
    let h = receipt_hash(&body)?;
    Ok(AuthorityReceipt { signature: sign_hash(key, &h), authority_key_id: key_id.clone(), body })
}

/// What a signer expects a receipt to bind before it releases output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptExpectation {
    pub kind: ReceiptKind,
    pub envelope_body_hash: Hash32,
    pub signer_session_id: SigningSessionId,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub now: UnixSeconds,
    pub policy_epoch: Epoch,
}

/// Verify an authority receipt's signature, binding, and validity window.
pub fn verify_receipt(receipt: &AuthorityReceipt, authority_pubkey: &VerifyingKey, expected: &ReceiptExpectation) -> OicResult<()> {
    verify_hash(authority_pubkey, &receipt_hash(&receipt.body)?, &receipt.signature)?;
    let b = &receipt.body;
    if b.kind != expected.kind {
        return Err(OicError::scope("receipt kind mismatch"));
    }
    if b.envelope_body_hash != expected.envelope_body_hash {
        return Err(OicError::scope("receipt bound to a different envelope"));
    }
    if b.signer_session_id != expected.signer_session_id {
        return Err(OicError::scope("receipt bound to a different signing session"));
    }
    if b.candidate_id != expected.candidate_id || b.candidate_revision != expected.candidate_revision {
        return Err(OicError::scope("receipt bound to a different candidate"));
    }
    if b.policy_epoch != expected.policy_epoch {
        return Err(OicError::new(ErrorCode::StalePolicy, "receipt policy epoch mismatch"));
    }
    if expected.now < b.issued_at || expected.now >= b.expires_at {
        return Err(OicError::scope("receipt not valid at this time"));
    }
    Ok(())
}

/// `SHA256("OIC/AUTHORITY_STATE/v1" || CanonicalEncode(state))`.
pub fn state_hash(state: &AuthorityState) -> OicResult<Hash32> {
    domain_hash(authority_domains::AUTHORITY_STATE, state)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBody {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub authority_epoch: Epoch,
    pub commit_sequence: u64,
    pub state_hash: Hash32,
}

/// Authority-signed checkpoint, held by independent witnesses to detect
/// snapshot rollback (§5.2, A12/A13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub body: CheckpointBody,
    pub authority_key_id: KeyId,
    pub signature: SignatureBytes,
}

pub fn checkpoint_hash(body: &CheckpointBody) -> OicResult<Hash32> {
    domain_hash(authority_domains::AUTHORITY_CHECKPOINT, body)
}

pub(crate) fn sign_checkpoint(key: &SigningKey, key_id: &KeyId, body: CheckpointBody) -> OicResult<SignedCheckpoint> {
    let h = checkpoint_hash(&body)?;
    Ok(SignedCheckpoint { signature: sign_hash(key, &h), authority_key_id: key_id.clone(), body })
}

pub fn verify_checkpoint(checkpoint: &SignedCheckpoint, authority_pubkey: &VerifyingKey) -> OicResult<()> {
    verify_hash(authority_pubkey, &checkpoint_hash(&checkpoint.body)?, &checkpoint.signature)
}
