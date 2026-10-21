//! Approval grants: the one signed object an approver produces (RFC 0001 §3.4).
//!
//! A grant signature is Ed25519 (`verify_strict`) over
//! `SHA256("OIC/APPROVAL/v1" || CanonicalEncode(ApprovalGrantBody))`. The body
//! names the intent hash, policy epoch, vault, institution, environment, and
//! either an exact candidate preview hash or a bounded transfer template, so a
//! grant can never be moved to another operation, vault, or policy epoch.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use oic_policy_kernel::ed25519_signature;

/// An enrolled approver credential: identity, public key, and the role the
/// administrative quorum assigned to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApproverCredential {
    pub credential_id: CredentialId,
    pub verifying_key: VerifyingKey,
    pub role: ApprovalRole,
}

/// `SHA256("OIC/APPROVAL/v1" || CanonicalEncode(body))`.
pub fn grant_signing_hash(body: &ApprovalGrantBody) -> OicResult<Hash32> {
    domain_hash(domains::APPROVAL, body)
}

/// Sign a grant body with an approver's credential key. The caller is the
/// approval client; the body must already describe exactly what the approver
/// saw on the trusted display.
pub fn sign_grant(key: &SigningKey, body: ApprovalGrantBody) -> OicResult<ApprovalGrant> {
    let h = grant_signing_hash(&body)?;
    let signature = SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(key.sign(&h.0).to_bytes().to_vec()) };
    Ok(ApprovalGrant { body, signature })
}

/// Verify one grant against the enrolled approver roster: the credential must
/// be enrolled, its role must equal the role claimed in the body, the
/// signature must verify, and `issued_at <= now < expires_at` in Unix seconds.
/// Returns `InvalidRequest` for a nonpositive validity interval,
/// `PolicyDenied` at or after expiry, and `StaleEvidence` before issuance.
/// Unknown credentials or invalid signatures return `InvalidSignature`; a role
/// mismatch returns `ScopeMismatch`. Grant hashing errors propagate.
pub fn verify_grant(grant: &ApprovalGrant, approvers: &[ApproverCredential], now: UnixSeconds) -> OicResult<()> {
    let b = &grant.body;
    let cred = approvers
        .iter()
        .find(|c| c.credential_id == b.approver_credential_id)
        .ok_or_else(|| OicError::invalid_signature(format!("approver credential {} is not enrolled", b.approver_credential_id)))?;
    if cred.role != b.approver_role {
        return Err(OicError::scope(format!(
            "grant claims role {:?} but credential {} is enrolled as {:?}",
            b.approver_role, b.approver_credential_id, cred.role
        )));
    }
    if b.expires_at <= b.issued_at {
        return Err(OicError::invalid_request("grant expiry is not after issuance"));
    }
    if now >= b.expires_at {
        return Err(OicError::policy_denied(format!("grant {} expired at {}", b.grant_id, b.expires_at.0)));
    }
    if now < b.issued_at {
        return Err(OicError::stale_evidence(format!("grant {} is issued in the future", b.grant_id)));
    }
    let h = grant_signing_hash(b)?;
    let sig = ed25519_signature(&grant.signature)?;
    cred.verifying_key
        .verify_strict(&h.0, &sig)
        .map_err(|_| OicError::invalid_signature(format!("grant {} signature does not verify", b.grant_id)))
}

/// Verify every grant and return the distinct approver credentials that
/// signed. Any invalid grant fails the whole set: a signer never silently
/// drops a bad grant and counts the rest.
pub fn verify_grants(grants: &[ApprovalGrant], approvers: &[ApproverCredential], now: UnixSeconds) -> OicResult<Vec<CredentialId>> {
    let mut distinct: Vec<CredentialId> = Vec::new();
    for g in grants {
        verify_grant(g, approvers, now)?;
        if !distinct.contains(&g.body.approver_credential_id) {
            distinct.push(g.body.approver_credential_id.clone());
        }
    }
    Ok(distinct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn body(cred: &str, role: ApprovalRole) -> ApprovalGrantBody {
        ApprovalGrantBody {
            grant_id: GrantId::unchecked("g1"),
            institution_id: InstitutionId::unchecked("inst"),
            environment_id: EnvironmentId::unchecked("dev"),
            vault_id: VaultId::unchecked("v"),
            intent_id: IntentId::unchecked("i"),
            intent_hash: Hash32([1; 32]),
            policy_id: PolicyId::unchecked("p"),
            policy_epoch: Epoch(3),
            scope: GrantScope::ExactCandidate { candidate_id: CandidateId::unchecked("c"), candidate_revision: 0, preview_hash: Hash32([2; 32]) },
            approver_credential_id: CredentialId::unchecked(cred),
            approver_role: role,
            issued_at: UnixSeconds(100),
            expires_at: UnixSeconds(200),
        }
    }

    fn roster() -> Vec<ApproverCredential> {
        vec![
            ApproverCredential { credential_id: CredentialId::unchecked("a"), verifying_key: key(1).verifying_key(), role: ApprovalRole::TreasuryApprover },
            ApproverCredential { credential_id: CredentialId::unchecked("b"), verifying_key: key(2).verifying_key(), role: ApprovalRole::SecurityApprover },
        ]
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let g = sign_grant(&key(1), body("a", ApprovalRole::TreasuryApprover)).unwrap();
        verify_grant(&g, &roster(), UnixSeconds(150)).unwrap();
        assert_eq!(verify_grants(&[g.clone(), g], &roster(), UnixSeconds(150)).unwrap(), vec![CredentialId::unchecked("a")]);
    }

    #[test]
    fn tampered_body_fails() {
        let mut g = sign_grant(&key(1), body("a", ApprovalRole::TreasuryApprover)).unwrap();
        g.body.intent_hash = Hash32([9; 32]);
        assert_eq!(verify_grant(&g, &roster(), UnixSeconds(150)).unwrap_err().code, ErrorCode::InvalidSignature);
    }

    #[test]
    fn wrong_key_unknown_credential_wrong_role_and_expiry_fail() {
        // Signed by b's key but claiming a's credential.
        let g = sign_grant(&key(2), body("a", ApprovalRole::TreasuryApprover)).unwrap();
        assert_eq!(verify_grant(&g, &roster(), UnixSeconds(150)).unwrap_err().code, ErrorCode::InvalidSignature);
        let g = sign_grant(&key(3), body("zzz", ApprovalRole::TreasuryApprover)).unwrap();
        assert_eq!(verify_grant(&g, &roster(), UnixSeconds(150)).unwrap_err().code, ErrorCode::InvalidSignature);
        let g = sign_grant(&key(1), body("a", ApprovalRole::Administrator)).unwrap();
        assert_eq!(verify_grant(&g, &roster(), UnixSeconds(150)).unwrap_err().code, ErrorCode::ScopeMismatch);
        let g = sign_grant(&key(1), body("a", ApprovalRole::TreasuryApprover)).unwrap();
        assert!(verify_grant(&g, &roster(), UnixSeconds(199)).is_ok());
        assert_eq!(verify_grant(&g, &roster(), UnixSeconds(200)).unwrap_err().code, ErrorCode::PolicyDenied);
        assert_eq!(verify_grant(&g, &roster(), UnixSeconds(201)).unwrap_err().code, ErrorCode::PolicyDenied);
        assert_eq!(verify_grant(&g, &roster(), UnixSeconds(99)).unwrap_err().code, ErrorCode::StaleEvidence);
        let ok = sign_grant(&key(1), body("a", ApprovalRole::TreasuryApprover)).unwrap();
        let bad = sign_grant(&key(2), body("a", ApprovalRole::TreasuryApprover)).unwrap();
        assert!(verify_grants(&[ok, bad], &roster(), UnixSeconds(150)).is_err());
    }
}
