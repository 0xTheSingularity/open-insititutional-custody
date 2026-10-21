//! D2 signing consumes a capability from the signer's locally re-executing
//! follower. It never accepts an unsigned state, inclusion claim or D1 receipt.

use crate::{SessionAuthorization, Signer, SignerEvent, SigningMaterials, VerifiedEnvelope};
use oic_crypto_provider::ProtocolStep;
use oic_domain_types::*;
use oic_replicated_authority::{FinalizedFloor, LogAnchor, VerifiedLog};
use parking_lot::Mutex;

/// Provision these independently of the gateway and retain the returned floor
/// outside the signer's rollback domain. The same bounded age applies to the
/// log view and the finalized Release; neither gains freshness from a retry.
pub struct FinalizedAuthorityConfig {
    pub anchor: LogAnchor,
    pub minimum_floor: FinalizedFloor,
    pub max_age_seconds: u64,
}

pub(crate) struct FinalizedAuthority {
    config: FinalizedAuthorityConfig,
    floor: Mutex<FinalizedFloor>,
}

impl Signer {
    /// Select D2 before loading keys or opening sessions. This irreversibly
    /// disables this instance's D1 entrypoints. Legacy authority public-key
    /// fields in TrustRoots are unused; no D1 private/signing key is needed.
    pub fn with_finalized_authority(mut self, config: FinalizedAuthorityConfig) -> OicResult<Self> {
        if self.finalized.is_some()
            || !self.keys.lock().is_empty()
            || !self.sessions.lock().is_empty()
            || config.max_age_seconds == 0
            || (config.minimum_floor.height == 0 && config.minimum_floor.digest != config.anchor.genesis)
        {
            return Err(OicError::invalid_request("D2 trust must be pinned once before loading keys or sessions"));
        }
        self.finalized = Some(FinalizedAuthority { floor: Mutex::new(config.minimum_floor), config });
        Ok(self)
    }

    pub fn finalized_anchor(&self) -> Option<LogAnchor> {
        self.finalized.as_ref().map(|authority| authority.config.anchor)
    }

    pub fn finalized_floor(&self) -> Option<FinalizedFloor> {
        self.finalized.as_ref().map(|authority| *authority.floor.lock())
    }

    fn check_finalized_log(&self, log: &VerifiedLog, now: UnixSeconds) -> OicResult<()> {
        let authority =
            self.finalized.as_ref().ok_or_else(|| OicError::new(ErrorCode::SessionRejected, "D1 signer cannot accept D2 authorization"))?;
        if log.anchor() != authority.config.anchor {
            return Err(OicError::invalid_signature("finalized history differs from independently pinned genesis or committee"));
        }
        if log.timestamp().0 > now.0.saturating_add(self.roots.max_clock_skew_seconds)
            || now.0 > log.timestamp().0.saturating_add(authority.config.max_age_seconds)
        {
            return Err(OicError::stale_evidence("finalized log view exceeds freshness bound"));
        }
        let mut floor = authority.floor.lock();
        let actual = log.floor();
        if actual.height < floor.height || (actual.height == floor.height && actual.digest != floor.digest) {
            return Err(OicError::new(ErrorCode::RecoveryRequired, "finalized log view regressed below signer floor"));
        }
        *floor = actual;
        Ok(())
    }

    pub fn verify_finalized_envelope(
        &self,
        body: &AuthorizationEnvelopeBody,
        materials: &SigningMaterials,
        log: &VerifiedLog,
        now: UnixSeconds,
    ) -> OicResult<VerifiedEnvelope> {
        let result = (|| {
            self.check_finalized_log(log, now)?;
            let approvers = log.approvers();
            self.verify_body(body, materials, now, &approvers, |_| log.authorize(body).map(|_| ()))
        })();
        self.emit(vec![match &result {
            Ok(verified) => {
                SignerEvent::EnvelopeVerified { envelope_body_hash: verified.envelope_body_hash, session: body.signer_session_id.clone() }
            }
            Err(error) => SignerEvent::EnvelopeRejected { code: error.code, detail: error.detail.clone() },
        }]);
        result
    }

    /// All local native/policy/approval checks still run, using credentials
    /// enrolled in finalized state. Reserve/notarization cannot start signing.
    pub fn open_finalized_session(
        &self,
        body: &AuthorizationEnvelopeBody,
        materials: &SigningMaterials,
        log: &VerifiedLog,
        now: UnixSeconds,
    ) -> OicResult<ProtocolStep> {
        let verified = self.verify_finalized_envelope(body, materials, log, now)?;
        self.open_verified_session(body, materials, verified, SessionAuthorization::D2(Box::new(body.clone())))
    }

    /// Recheck the latest local finalized history before releasing any buffered
    /// share-producing round. A D1 receipt cannot release this session.
    pub fn release_finalized(&self, session: &SigningSessionId, log: &VerifiedLog, now: UnixSeconds) -> OicResult<Vec<ProtocolStep>> {
        let mut events = Vec::new();
        let result = (|| {
            let mut sessions = self.sessions.lock();
            let record = sessions.get_mut(session).ok_or_else(|| OicError::new(ErrorCode::NotFound, "unknown signing session"))?;
            Self::check_live(record)?;
            if record.released {
                return Err(OicError::new(ErrorCode::Conflict, "session already released"));
            }
            let SessionAuthorization::D2(body) = &record.authorization else {
                return Err(OicError::new(ErrorCode::SessionRejected, "D2 evidence cannot release a D1 session"));
            };
            self.check_finalized_log(log, now)?;
            let issuance = log.authorize(body)?;
            let age = self.finalized.as_ref().expect("checked D2 authority").config.max_age_seconds;
            if body.issuance_deadline < now || now.0 > issuance.committed_at.0.saturating_add(age) {
                return Err(OicError::stale_evidence("finalized release is too old to enable signing"));
            }
            oic_approval_verifier::verify_grants(&body.approval_grants, &log.approvers(), now)?;
            self.release_buffered(session, record, issuance.commit_sequence, &mut events)
        })();
        self.emit(events);
        result
    }
}
