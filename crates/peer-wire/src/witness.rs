//! Typed public witness exchange. Confidential offline exports have no carrier.

use oic_audit::AuditCheckpoint;
use oic_authorization_state::SignedCheckpoint;
use oic_canonical_encoding::canonical_bytes;
use oic_domain_types::{AuditEvent, MAX_BYTES_LEN, OicError, OicResult};
use oic_membership::VerificationAttestation;
use serde::{Deserialize, Serialize};

/// Public commitments only. Producers must use public actor/action/reason
/// labels; free-form audit detail belongs in confidential offline exports.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum WitnessMessage {
    AuthorityCheckpoint(SignedCheckpoint),
    AuditCheckpoint { checkpoint: AuditCheckpoint, bridge: Vec<AuditEvent> },
    Attestation(Box<VerificationAttestation>),
}

impl std::fmt::Debug for WitnessMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WitnessMessage([REDACTED])")
    }
}

impl WitnessMessage {
    /// Canonical payload for local persistence/verification. Network callers
    /// must use `PeerFrameV1::encode_public` with the Audit carrier and ACL cap.
    pub fn encode(&self) -> OicResult<Vec<u8>> {
        self.validate_public()?;
        let bytes = canonical_bytes(self)?;
        if bytes.len() > MAX_BYTES_LEN {
            return Err(OicError::invalid_request("witness message exceeds limit"));
        }
        Ok(bytes)
    }

    /// Prevent audit detail from escaping through the typed public carrier,
    /// even when a caller constructs this enum directly rather than via encode.
    pub fn validate_public(&self) -> OicResult<()> {
        if let Self::AuditCheckpoint { bridge, .. } = self {
            if bridge.iter().any(|event| !event.body.detail.is_empty()) {
                return Err(OicError::invalid_request("public audit exchange cannot contain detail"));
            }
        }
        Ok(())
    }
}
