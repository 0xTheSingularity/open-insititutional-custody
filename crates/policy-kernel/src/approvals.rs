//! Pure grant authentication shared by authority, signers, and approval clients.

use crate::ed25519_signature;
use ed25519_dalek::VerifyingKey;
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use serde::{Deserialize, Serialize};

/// Trusted approval-only enrollment. The administrator binds a stable person
/// identity, not one identity per authenticator. This is not identity proofing.
/// Never enroll login, administrative, transport, or receipt-signing keys here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproverCredential {
    pub credential_id: CredentialId,
    pub person_id: CredentialId,
    pub verifying_key: ApproverKey,
    pub role: ApprovalRole,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ApproverKey {
    Ed25519(VerifyingKey),
    WebAuthn {
        /// Compressed SEC1 only, so equivalent encodings cannot alias a key.
        public_key_sec1: Bytes,
        rp_id: String,
        allowed_origins: Vec<String>,
        /// Authenticated BE must equal the value established at enrollment.
        /// Enrollment/attestation policy is outside assertion verification.
        backup_eligible: bool,
    },
}

impl From<VerifyingKey> for ApproverKey {
    fn from(key: VerifyingKey) -> Self {
        Self::Ed25519(key)
    }
}

impl ApproverCredential {
    pub fn validate(&self) -> OicResult<()> {
        if CredentialId::new(self.credential_id.as_str()).is_none() || CredentialId::new(self.person_id.as_str()).is_none() {
            return Err(OicError::invalid_request("invalid approval credential or person identity"));
        }
        match &self.verifying_key {
            ApproverKey::Ed25519(key) if key.is_weak() => Err(OicError::invalid_request("weak approval key")),
            ApproverKey::Ed25519(_) => Ok(()),
            ApproverKey::WebAuthn { public_key_sec1, rp_id, allowed_origins, .. } => {
                if public_key_sec1.len() != 33 || !matches!(public_key_sec1.0.first(), Some(2 | 3)) {
                    return Err(OicError::invalid_request("approval key must use compressed SEC1"));
                }
                let origins: Vec<_> = allowed_origins.iter().map(String::as_str).collect();
                oic_webauthn::validate_credential(&oic_webauthn::EnrolledCredential { public_key_sec1: &public_key_sec1.0, rp_id, allowed_origins: &origins })
                    .map_err(|_| OicError::invalid_request("invalid WebAuthn enrollment"))
            }
        }
    }
}

/// `SHA256("OIC/APPROVAL/v1" || CanonicalEncode(body))`.
pub fn grant_signing_hash(body: &ApprovalGrantBody) -> OicResult<Hash32> {
    domain_hash(domains::APPROVAL, body)
}

/// Verify the enrolled role, lifetime, scheme and signature. Enrollment comes
/// from independent trusted state; assertions cannot choose a key/RP/origin.
/// Validity is `issued_at <= now < expires_at` in Unix seconds. A nonpositive
/// interval returns `InvalidRequest`, expiry returns `PolicyDenied`, and future
/// issuance returns `StaleEvidence`. Unknown credentials or invalid signatures
/// return `InvalidSignature`; a role mismatch returns `ScopeMismatch`.
/// Enrollment validation and grant hashing errors propagate.
pub fn verify_grant(grant: &ApprovalGrant, approvers: &[ApproverCredential], now: UnixSeconds) -> OicResult<()> {
    let b = &grant.body;
    let mut matching = approvers.iter().filter(|c| c.credential_id == b.approver_credential_id);
    let cred = matching.next().ok_or_else(|| OicError::invalid_signature("approver credential is not enrolled"))?;
    if matching.next().is_some() {
        return Err(OicError::invalid_request("ambiguous approval credential enrollment"));
    }
    cred.validate()?;
    if cred.role != b.approver_role {
        return Err(OicError::scope("grant role differs from enrolled role"));
    }
    if b.expires_at <= b.issued_at {
        return Err(OicError::invalid_request("grant expiry is not after issuance"));
    }
    if now >= b.expires_at {
        return Err(OicError::policy_denied("approval grant expired"));
    }
    if now < b.issued_at {
        return Err(OicError::stale_evidence("approval grant is issued in the future"));
    }
    let h = grant_signing_hash(b)?;
    match (&cred.verifying_key, grant.signature.scheme) {
        (ApproverKey::Ed25519(key), SchemeId::Ed25519Pure) => {
            let sig = ed25519_signature(&grant.signature)?;
            key.verify_strict(&h.0, &sig).map_err(|_| OicError::invalid_signature("approval signature does not verify"))
        }
        (ApproverKey::WebAuthn { public_key_sec1, rp_id, allowed_origins, backup_eligible }, SchemeId::WebAuthnEs256) => {
            let origins: Vec<_> = allowed_origins.iter().map(String::as_str).collect();
            let verified = oic_webauthn::verify_canonical_assertion(
                &oic_webauthn::EnrolledCredential { public_key_sec1: &public_key_sec1.0, rp_id, allowed_origins: &origins },
                &h.0,
                &grant.signature.bytes.0,
            )
            .map_err(|_| OicError::invalid_signature("WebAuthn approval does not verify"))?;
            if verified.backup_eligible != *backup_eligible {
                return Err(OicError::invalid_signature("authenticator backup eligibility changed"));
            }
            Ok(())
        }
        _ => Err(OicError::invalid_signature("approval signature scheme differs from enrollment")),
    }
}

/// Any invalid grant fails the whole set. Multiple authenticators belonging to
/// one enrolled person cannot satisfy a multi-person quorum. Exact duplicates
/// of one credential retain the existing distinct-credential return contract.
pub fn verify_grants(grants: &[ApprovalGrant], approvers: &[ApproverCredential], now: UnixSeconds) -> OicResult<Vec<CredentialId>> {
    if grants.len() > crate::MAX_GRANTS {
        return Err(OicError::invalid_request("approval grant limit exceeded"));
    }
    let mut distinct = Vec::new();
    let mut people = Vec::new();
    for grant in grants {
        verify_grant(grant, approvers, now)?;
        let id = &grant.body.approver_credential_id;
        if !distinct.contains(id) {
            let credential = approvers.iter().find(|c| &c.credential_id == id).expect("verified enrollment");
            if people.contains(&&credential.person_id) {
                return Err(OicError::policy_denied("multiple approval credentials belong to one person"));
            }
            people.push(&credential.person_id);
            distinct.push(id.clone());
        }
    }
    Ok(distinct)
}
