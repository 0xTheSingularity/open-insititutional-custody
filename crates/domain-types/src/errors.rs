//! Stable error codes (RFC 0001 §13.3). Errors never carry secrets or
//! transcript contents; `detail` is a short operator-facing reason.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    UnsupportedCapability,
    UnverifiableTransaction,
    PolicyDenied,
    StalePolicy,
    ApprovalRequired,
    BudgetExceeded,
    ResourceConflict,
    StaleEvidence,
    IssuanceUncertain,
    RecoveryRequired,
    AuthorityUnavailable,
    ScopeMismatch,
    InvalidSignature,
    Frozen,
    NotFound,
    Conflict,
    InvalidRequest,
    Internal,
    RosterMismatch,
    PeerNotAdmitted,
    StaleGeneration,
    AttestationDisagreement,
    SessionRejected,
    NodeHalted,
    OrderingUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("{code:?}: {detail}")]
pub struct OicError {
    pub code: ErrorCode,
    pub detail: String,
}

impl OicError {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        OicError { code, detail: detail.into() }
    }
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnsupportedCapability, detail)
    }
    pub fn unverifiable(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnverifiableTransaction, detail)
    }
    pub fn policy_denied(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::PolicyDenied, detail)
    }
    pub fn scope(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::ScopeMismatch, detail)
    }
    pub fn invalid_signature(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidSignature, detail)
    }
    pub fn stale_evidence(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::StaleEvidence, detail)
    }
    pub fn budget(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::BudgetExceeded, detail)
    }
    pub fn resource_conflict(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::ResourceConflict, detail)
    }
    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, detail)
    }
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, detail)
    }
}

pub type OicResult<T> = Result<T, OicError>;
