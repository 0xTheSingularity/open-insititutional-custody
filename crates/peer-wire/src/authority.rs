//! Typed Class C D1 authority RPC. Encoding does not authenticate a peer or
//! authorize a mutation; channel 12 admission belongs to the server/transport.

use crate::{FrameKind, PeerFrameV1, WireError};
use oic_authorization_state::{CredentialChange, ReleaseRequest, ReserveRequest};
use oic_canonical_encoding::from_canonical_bytes;
use oic_domain_types::*;
use oic_policy_kernel::Decision;
use serde::{Deserialize, Serialize};

/// Class C mutations cannot enter public carriers, even if an operator chooses
/// a public frame kind at the call site.
/// ```compile_fail
/// use oic_peer_wire::{AuthorityRequest, FrameKind, PeerFrameV1, MAX_BODY_LEN};
/// fn broadcast(request: &AuthorityRequest) {
///     PeerFrameV1::encode_public(request, 0, FrameKind::Audit, MAX_BODY_LEN).unwrap();
/// }
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum AuthorityRequest {
    Reserve {
        request_id: u64,
        #[serde(with = "ReserveRequestDef")]
        request: ReserveRequest,
    },
    Release {
        request_id: u64,
        #[serde(with = "ReleaseRequestDef")]
        request: ReleaseRequest,
    },
    AbortBeforeIssuance {
        request_id: u64,
        reservation_id: ReservationId,
    },
    ChangeCredential {
        request_id: u64,
        proposal: CredentialChange,
        signatures: Vec<CredentialSignature>,
    },
    Approve {
        request_id: u64,
        intent: Intent,
        grant: ApprovalGrant,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityReply {
    pub request_id: u64,
    pub result: OicResult<AuthorityResult>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum AuthorityResult {
    Reserved { reservation: Reservation, receipt: AuthorityReceipt },
    Released { receipt: AuthorityReceipt, issuance: IssuanceRecord },
    Aborted { commit_sequence: u64 },
    CredentialChanged { commit_sequence: u64 },
    Approved { commit_sequence: u64 },
}

impl AuthorityRequest {
    pub fn request_id(&self) -> u64 {
        match self {
            Self::Reserve { request_id, .. }
            | Self::Release { request_id, .. }
            | Self::AbortBeforeIssuance { request_id, .. }
            | Self::ChangeCredential { request_id, .. }
            | Self::Approve { request_id, .. } => *request_id,
        }
    }
}

macro_rules! framed_body {
    ($($ty:ident),+ $(,)?) => { $(
        impl $ty {
            pub fn encode(&self, roster_epoch: u64, max_body_len: usize) -> Result<Vec<u8>, WireError> {
                PeerFrameV1::encode_confidential(self, roster_epoch, FrameKind::AuthorityRpc, max_body_len)
            }

            pub fn decode(bytes: &[u8], roster_epoch: u64, max_body_len: usize) -> Result<Self, WireError> {
                let frame = PeerFrameV1::decode(bytes, roster_epoch, FrameKind::AuthorityRpc, max_body_len)?;
                from_canonical_bytes(frame.body()).map_err(|_| WireError::InvalidBody)
            }
        }
    )+ };
}

framed_body!(AuthorityRequest, AuthorityReply);

macro_rules! redacted_debug {
    ($($ty:ident),+ $(,)?) => { $(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([REDACTED])"))
            }
        }
    )+ };
}

redacted_debug!(AuthorityRequest, AuthorityReply, AuthorityResult);

// Serde remote definitions keep the authority's native requests as the public
// API. Every field is transmitted unchanged; no transport-supplied clock,
// policy bypass, or alternate release operation is introduced.
#[derive(Serialize, Deserialize)]
#[serde(remote = "ReserveRequest", deny_unknown_fields)]
struct ReserveRequestDef {
    family_id: OperationFamilyId,
    candidate_id: CandidateId,
    candidate_revision: u32,
    vault_id: VaultId,
    intent_id: IntentId,
    policy_epoch: Epoch,
    policy_hash: Hash32,
    claims: ResourceClaims,
    grants: Vec<ApprovalGrant>,
    envelope_body_hash: Hash32,
    signer_session_id: SigningSessionId,
    issuance_deadline: UnixSeconds,
    policy_decision: Decision,
    exposure_limits: Vec<(AssetId, ExposureLimit)>,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "ReleaseRequest", deny_unknown_fields)]
struct ReleaseRequestDef {
    reservation_id: ReservationId,
    reservation_version: u32,
    envelope_body_hash: Hash32,
    signer_session_id: SigningSessionId,
    expected_policy_epoch: Epoch,
    freshness: FreshnessContext,
}
