//! Coordinator adapter for cores that exchange MPC rounds themselves.

use oic_crypto_provider::{PeerMessage, ProtocolStep};
use oic_domain_types::*;
use oic_peer_wire::{SessionControl, SessionReply, SessionResult};
use oic_service_coordinator::SignerEndpoint;
use oic_signer::SigningMaterials;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Implementations bind the response to the named, authenticated remote node.
/// Calls block and must run outside the async networking reactor.
pub trait ControlClient: Send + Sync {
    fn request(&self, control: SessionControl) -> OicResult<SessionReply>;
}

pub struct LocalClient {
    pub ipc: crate::ipc::Client,
    pub gateway: NodeId,
}

impl ControlClient for LocalClient {
    fn request(&self, control: SessionControl) -> OicResult<SessionReply> {
        self.ipc.control(&self.gateway, control)
    }
}

pub struct RemoteSigner {
    participant: ParticipantId,
    generation: Epoch,
    client: Arc<dyn ControlClient>,
    prepare_timeout: Duration,
}

impl RemoteSigner {
    pub fn new(participant: ParticipantId, generation: Epoch, client: Arc<dyn ControlClient>, prepare_timeout: Duration) -> Self {
        Self { participant, generation, client, prepare_timeout }
    }

    fn call(&self, make: impl FnOnce(u64) -> SessionControl) -> OicResult<SessionResult> {
        let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let reply = self.client.request(make(id))?;
        if reply.request_id != id {
            return Err(OicError::new(ErrorCode::SessionRejected, "misbound signer reply"));
        }
        reply.result
    }
}

impl SignerEndpoint for RemoteSigner {
    fn participant_id(&self) -> ParticipantId {
        self.participant.clone()
    }
    fn generation(&self) -> Epoch {
        self.generation
    }
    fn exchanges_peer_messages(&self) -> bool {
        true
    }

    fn open_session(&self, envelope: &AuthorizationEnvelope, materials: &SigningMaterials, _now: UnixSeconds) -> OicResult<ProtocolStep> {
        match self.call(|request_id| SessionControl::Open { request_id, envelope: envelope.clone(), materials: materials.clone() })? {
            SessionResult::Accepted | SessionResult::Waiting => Ok(ProtocolStep::Waiting),
            _ => Err(OicError::new(ErrorCode::SessionRejected, "unexpected signer open result")),
        }
    }

    fn await_prepared(&self, session_id: &SigningSessionId) -> OicResult<()> {
        let start = Instant::now();
        loop {
            match self.call(|request_id| SessionControl::Status { request_id, session_id: session_id.clone() })? {
                SessionResult::Accepted => return Ok(()),
                SessionResult::Waiting if start.elapsed() < self.prepare_timeout => std::thread::sleep(Duration::from_millis(20)),
                _ => return Err(OicError::new(ErrorCode::SessionRejected, "signer preparation failed or timed out")),
            }
        }
    }

    fn receive(&self, _session_id: &SigningSessionId, _message: &PeerMessage) -> OicResult<ProtocolStep> {
        Err(OicError::unsupported("gateway cannot deliver MPC frames to a network endpoint"))
    }

    fn release(&self, session_id: &SigningSessionId, receipt: &AuthorityReceipt, _now: UnixSeconds) -> OicResult<Vec<ProtocolStep>> {
        match self.call(|request_id| SessionControl::Release { request_id, session_id: session_id.clone(), receipt: receipt.clone() })? {
            SessionResult::Share(bytes) => Ok(vec![ProtocolStep::Share(bytes)]),
            SessionResult::Complete(signature) => Ok(vec![ProtocolStep::Complete(signature)]),
            _ => Err(OicError::new(ErrorCode::IssuanceUncertain, "signer did not return one public output")),
        }
    }

    fn aggregate(&self, session_id: &SigningSessionId, shares: &[(ParticipantId, Bytes)]) -> OicResult<SignatureBytes> {
        match self.call(|request_id| SessionControl::Aggregate { request_id, session_id: session_id.clone(), shares: shares.to_vec() })? {
            SessionResult::Complete(signature) => Ok(signature),
            _ => Err(OicError::new(ErrorCode::IssuanceUncertain, "signer did not return a verified signature")),
        }
    }

    fn abort(&self, session_id: &SigningSessionId) -> OicResult<()> {
        match self.call(|request_id| SessionControl::Abort { request_id, session_id: session_id.clone() })? {
            SessionResult::Aborted => Ok(()),
            _ => Err(OicError::new(ErrorCode::SessionRejected, "signer abort not acknowledged")),
        }
    }
}
