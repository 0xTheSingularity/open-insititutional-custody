//! The signer surface the coordinator drives (RFC 0001 §1.1, §6.4).
//!
//! Every method takes owned or `'static`-free borrowed inputs and returns
//! owned outputs, so an endpoint can equally be an in-process
//! [`oic_signer::Signer`] or a remote signer reached over an authenticated
//! transport. The coordinator never learns anything from an endpoint that
//! it could use to bypass a signer: signers re-verify every envelope and
//! gate every share on the authority's release receipt.

use oic_crypto_provider::{PeerMessage, ProtocolStep};
use oic_domain_types::*;
use oic_signer::{Signer, SigningMaterials};
use std::sync::Arc;

/// One signing participant as seen by the coordinator.
pub trait SignerEndpoint: Send + Sync {
    /// The participant this endpoint speaks for.
    fn participant_id(&self) -> ParticipantId;

    /// The signer instance's current generation (§6.3); stamped on
    /// coordinator-originated messages attributed to this participant.
    fn generation(&self) -> Epoch;

    /// Verify the envelope and start the backend protocol.
    fn open_session(&self, envelope: &AuthorizationEnvelope, materials: &SigningMaterials, now: UnixSeconds) -> OicResult<ProtocolStep>;

    /// Deliver one peer or coordinator message.
    fn receive(&self, session_id: &SigningSessionId, message: &PeerMessage) -> OicResult<ProtocolStep>;

    /// Present the authority's release receipt; returns the steps produced
    /// by the buffered share-round messages.
    fn release(&self, session_id: &SigningSessionId, release_receipt: &AuthorityReceipt, now: UnixSeconds) -> OicResult<Vec<ProtocolStep>>;

    /// Aggregate public shares into a natively verified signature.
    fn aggregate(&self, session_id: &SigningSessionId, shares: &[(ParticipantId, Bytes)]) -> OicResult<SignatureBytes>;

    /// Abort a session; it never produces output afterwards.
    fn abort(&self, session_id: &SigningSessionId) -> OicResult<()>;
}

/// A signer running in this process.
#[derive(Clone)]
pub struct InProcessSigner(pub Arc<Signer>);

impl SignerEndpoint for InProcessSigner {
    fn participant_id(&self) -> ParticipantId {
        self.0.identity().participant_id.clone()
    }

    fn generation(&self) -> Epoch {
        self.0.generation()
    }

    fn open_session(&self, envelope: &AuthorizationEnvelope, materials: &SigningMaterials, now: UnixSeconds) -> OicResult<ProtocolStep> {
        self.0.open_session(envelope, materials, now)
    }

    fn receive(&self, session_id: &SigningSessionId, message: &PeerMessage) -> OicResult<ProtocolStep> {
        self.0.receive(session_id, message)
    }

    fn release(&self, session_id: &SigningSessionId, release_receipt: &AuthorityReceipt, now: UnixSeconds) -> OicResult<Vec<ProtocolStep>> {
        self.0.release(session_id, release_receipt, now)
    }

    fn aggregate(&self, session_id: &SigningSessionId, shares: &[(ParticipantId, Bytes)]) -> OicResult<SignatureBytes> {
        self.0.aggregate(session_id, shares)
    }

    fn abort(&self, session_id: &SigningSessionId) -> OicResult<()> {
        self.0.abort(session_id)
    }
}
