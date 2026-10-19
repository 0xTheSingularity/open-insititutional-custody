//! Commitments the kernel binds to (RFC 0001 §3.2, §4.2) and administrative
//! quorum verification for policy bundles.

use ed25519_dalek::{Signature, VerifyingKey};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use serde::Serialize;

/// The signed portion of a [`PolicyBundle`]: every field except
/// `administrative_signatures`, which sign this view.
#[derive(Clone, Debug, Serialize)]
pub struct PolicyBundleUnsigned<'a> {
    pub policy_id: &'a PolicyId,
    pub policy_epoch: Epoch,
    pub institution_id: &'a InstitutionId,
    pub environment_id: &'a EnvironmentId,
    pub rules: &'a [PolicyRule],
    pub denied_destinations: &'a [DestinationId],
    pub denied_assets: &'a [AssetId],
    pub max_evidence_age_seconds: u64,
    pub allowlist_version: u32,
    pub activation_epoch: Epoch,
}

impl<'a> From<&'a PolicyBundle> for PolicyBundleUnsigned<'a> {
    fn from(b: &'a PolicyBundle) -> Self {
        PolicyBundleUnsigned {
            policy_id: &b.policy_id,
            policy_epoch: b.policy_epoch,
            institution_id: &b.institution_id,
            environment_id: &b.environment_id,
            rules: &b.rules,
            denied_destinations: &b.denied_destinations,
            denied_assets: &b.denied_assets,
            max_evidence_age_seconds: b.max_evidence_age_seconds,
            allowlist_version: b.allowlist_version,
            activation_epoch: b.activation_epoch,
        }
    }
}

/// `SHA256("OIC/POLICY/v1" || CanonicalEncode(PolicyBundleUnsigned))`.
pub fn policy_hash(bundle: &PolicyBundle) -> OicResult<Hash32> {
    domain_hash(domains::POLICY, &PolicyBundleUnsigned::from(bundle))
}

/// `SHA256("OIC/INTENT/v1" || CanonicalEncode(intent))`.
pub fn intent_hash(intent: &Intent) -> OicResult<Hash32> {
    domain_hash(domains::INTENT, intent)
}

/// The object an exact-candidate approval's preview hash commits to.
#[derive(Clone, Debug, Serialize)]
pub struct PreviewCommitment<'a> {
    pub candidate_id: &'a CandidateId,
    pub candidate_revision: u32,
    pub decoded_operation_hash: Hash32,
    pub evidence_bundle_hash: Hash32,
}

/// `SHA256("OIC/PREVIEW/v1" || CanonicalEncode(PreviewCommitment))`.
pub fn preview_hash(candidate_id: &CandidateId, candidate_revision: u32, decoded_operation_hash: Hash32, evidence_bundle_hash: Hash32) -> Hash32 {
    let c = PreviewCommitment { candidate_id, candidate_revision, decoded_operation_hash, evidence_bundle_hash };
    // Identifiers, integers, and hashes are always encodable in the canonical profile.
    domain_hash(domains::PREVIEW, &c).expect("preview commitment is canonically encodable")
}

/// Decode an explicit-scheme Ed25519 signature.
pub fn ed25519_signature(sig: &SignatureBytes) -> OicResult<Signature> {
    if sig.scheme != SchemeId::Ed25519Pure {
        return Err(OicError::invalid_signature("expected ed25519 signature"));
    }
    let bytes: [u8; 64] = sig.bytes.as_slice().try_into().map_err(|_| OicError::invalid_signature("ed25519 signature must be 64 bytes"))?;
    Ok(Signature::from_bytes(&bytes))
}

/// Count distinct enrolled credentials whose Ed25519 signature (verify_strict)
/// over `message` is valid. Signatures from unknown credentials are ignored;
/// a credential is counted at most once.
pub fn count_quorum_signatures(message: &[u8], signatures: &[CredentialSignature], keys: &[(CredentialId, VerifyingKey)]) -> usize {
    let mut counted: Vec<&CredentialId> = Vec::new();
    for s in signatures {
        if counted.contains(&&s.credential_id) {
            continue;
        }
        let Some((_, key)) = keys.iter().find(|(id, _)| id == &s.credential_id) else { continue };
        let Ok(sig) = ed25519_signature(&s.signature) else { continue };
        if key.verify_strict(message, &sig).is_ok() {
            counted.push(&s.credential_id);
        }
    }
    counted.len()
}

/// Verify that at least `quorum` distinct administrative credentials signed
/// `policy_hash(bundle)` (§4.2: a single administrator cannot activate a
/// policy). `quorum == 0` is rejected as a misconfiguration.
pub fn verify_policy_admin_signatures(bundle: &PolicyBundle, admin_keys: &[(CredentialId, VerifyingKey)], quorum: u8) -> OicResult<()> {
    if quorum == 0 {
        return Err(OicError::invalid_request("administrative quorum must be at least 1"));
    }
    let h = policy_hash(bundle)?;
    let n = count_quorum_signatures(&h.0, &bundle.administrative_signatures, admin_keys);
    if n < usize::from(quorum) {
        return Err(OicError::invalid_signature(format!("administrative quorum not met: {n} of {quorum}")));
    }
    Ok(())
}
