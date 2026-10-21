//! Approval grants: the one signed object an approver produces (RFC 0001 §3.4).
//!
//! A grant signs `SHA256("OIC/APPROVAL/v1" || CanonicalEncode(ApprovalGrantBody))`
//! with Ed25519 or an enrolled approval-only WebAuthn ES256 credential. The body
//! names the intent hash, policy epoch, vault, institution, environment, and
//! either an exact candidate preview hash or a bounded transfer template, so a
//! grant can never be moved to another operation, vault, or policy epoch.

use ed25519_dalek::{Signer, SigningKey};
use oic_domain_types::*;
pub use oic_policy_kernel::{grant_signing_hash, verify_grant, verify_grants, ApproverCredential, ApproverKey};

/// Sign a grant body with an approver's credential key. The caller is the
/// approval client; the body must already describe exactly what the approver
/// saw on the trusted display.
pub fn sign_grant(key: &SigningKey, body: ApprovalGrantBody) -> OicResult<ApprovalGrant> {
    let h = grant_signing_hash(&body)?;
    let signature = SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(key.sign(&h.0).to_bytes().to_vec()) };
    Ok(ApprovalGrant { body, signature })
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
            ApproverCredential {
                credential_id: CredentialId::unchecked("a"),
                person_id: CredentialId::unchecked("person-a"),
                verifying_key: key(1).verifying_key().into(),
                role: ApprovalRole::TreasuryApprover,
            },
            ApproverCredential {
                credential_id: CredentialId::unchecked("b"),
                person_id: CredentialId::unchecked("person-b"),
                verifying_key: key(2).verifying_key().into(),
                role: ApprovalRole::SecurityApprover,
            },
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
