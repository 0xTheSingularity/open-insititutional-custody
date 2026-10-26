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

/// The signed portion of a [`CounterpartyDestination`]: every field except
/// `administrative_signatures`, which sign this view.
#[derive(Clone, Debug, Serialize)]
pub struct DestinationUnsigned<'a> {
    pub destination_id: &'a DestinationId,
    pub version: u32,
    pub network_id: &'a NetworkId,
    pub address: &'a Bytes,
    pub address_display: &'a str,
    pub display_name: &'a str,
    pub allowed_assets: &'a [AssetId],
    pub verification_evidence: &'a str,
    pub activation_epoch: Epoch,
}

impl<'a> From<&'a CounterpartyDestination> for DestinationUnsigned<'a> {
    fn from(d: &'a CounterpartyDestination) -> Self {
        DestinationUnsigned {
            destination_id: &d.destination_id,
            version: d.version,
            network_id: &d.network_id,
            address: &d.address,
            address_display: &d.address_display,
            display_name: &d.display_name,
            allowed_assets: &d.allowed_assets,
            verification_evidence: &d.verification_evidence,
            activation_epoch: d.activation_epoch,
        }
    }
}

/// `SHA256("OIC/DESTINATION/v1" || CanonicalEncode(DestinationUnsigned))`.
pub fn destination_hash(d: &CounterpartyDestination) -> OicResult<Hash32> {
    domain_hash(domains::DESTINATION, &DestinationUnsigned::from(d))
}

/// Verify that at least `quorum` distinct administrative credentials signed
/// `destination_hash(d)` (RFC 0002 §7: every beneficiary change follows the
/// administrative quorum process). `quorum == 0` is rejected.
pub fn verify_destination_admin_signatures(d: &CounterpartyDestination, admin_keys: &[(CredentialId, VerifyingKey)], quorum: u8) -> OicResult<()> {
    if quorum == 0 {
        return Err(OicError::invalid_request("administrative quorum must be at least 1"));
    }
    let h = destination_hash(d)?;
    let n = count_quorum_signatures(&h.0, &d.administrative_signatures, admin_keys);
    if n < usize::from(quorum) {
        return Err(OicError::invalid_signature(format!("destination administrative quorum not met: {n} of {quorum}")));
    }
    Ok(())
}

/// `SHA256("OIC/ASSET/v1" || CanonicalEncode(asset))` of the enrolled asset.
pub fn asset_hash(a: &Asset) -> OicResult<Hash32> {
    domain_hash(domains::ASSET, a)
}

/// `SHA256("OIC/CHAIN_WALLET/v1" || CanonicalEncode(wallet))` of the enrolled
/// chain wallet.
pub fn chain_wallet_hash(w: &ChainWallet) -> OicResult<Hash32> {
    domain_hash(domains::CHAIN_WALLET, w)
}

/// `SHA256("OIC/VAULT/v1" || CanonicalEncode(vault))` of the enrolled vault.
pub fn vault_hash(v: &Vault) -> OicResult<Hash32> {
    domain_hash(domains::VAULT, v)
}

/// `SHA256("OIC/KEY_DESCRIPTOR/v1" || CanonicalEncode(key))` of the enrolled
/// key descriptor (threshold, participants, scheme, networks — not only the
/// public key bytes, which `public_key_hash` covers separately).
pub fn key_descriptor_hash(k: &KeyDescriptor) -> OicResult<Hash32> {
    domain_hash(domains::KEY_DESCRIPTOR, k)
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
