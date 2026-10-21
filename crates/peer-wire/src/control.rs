use oic_domain_types::{
    AuthorityReceipt, AuthorizationEnvelope, AuthorizationEnvelopeBody, Bytes, OicResult, ParticipantId, SignatureBytes, SigningSessionId,
};
use oic_signer::SigningMaterials;
use serde::{Deserialize, Serialize};

/// Class C gateway/core requests. No clock or raw MPC frame is supplied by a
/// gateway: signer-core uses its own Clock and verifies the envelope/release.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
// Keep the agreed by-value IPC schema; Open is infrequent and frame-bounded.
#[allow(clippy::large_enum_variant)]
pub enum SessionControl {
    Open {
        request_id: u64,
        envelope: AuthorizationEnvelope,
        materials: SigningMaterials,
    },
    Release {
        request_id: u64,
        session_id: SigningSessionId,
        receipt: AuthorityReceipt,
    },
    /// No evidence/state is trusted from this request. The core must consult
    /// its own authenticated, synced, re-executed D2 follower.
    OpenFinalized {
        request_id: u64,
        body: AuthorizationEnvelopeBody,
        materials: SigningMaterials,
    },
    ReleaseFinalized {
        request_id: u64,
        session_id: SigningSessionId,
    },
    Aggregate {
        request_id: u64,
        session_id: SigningSessionId,
        shares: Vec<(ParticipantId, Bytes)>,
    },
    Abort {
        request_id: u64,
        session_id: SigningSessionId,
    },
    Status {
        request_id: u64,
        session_id: SigningSessionId,
    },
}

/// Class C replies. A core may expose Share/Complete only after its release gate
/// permits public output. Commitments and other MPC rounds never travel here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReply {
    pub request_id: u64,
    pub result: OicResult<SessionResult>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionResult {
    Accepted,
    Waiting,
    Share(Bytes),
    Complete(SignatureBytes),
    Aborted,
}

// Even Class C controls/results are not safe for logs or crash reports.
macro_rules! redacted_debug {
    ($($ty:ident),+ $(,)?) => { $(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([REDACTED])"))
            }
        }
    )+ };
}

redacted_debug!(SessionControl, SessionReply, SessionResult);
