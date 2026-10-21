//! # oic-crypto-provider
//!
//! The narrow interface between the signer boundary and a selected threshold
//! signing backend (RFC 0001 §6.1):
//!
//! ```text
//! capabilities()
//! generate_distributed_key(ceremony)
//! start_signing_session(authorized_native_payloads, participant_set)
//! advance_protocol(session_id, authenticated_peer_message)
//! verify_result(public_key, native_payload, signature)
//! refresh_shares(ceremony)       # only if reviewed backend supports it
//! recover_or_replace(ceremony)   # explicit profile, never generic export
//! ```
//!
//! A backend declares exactly what it supports. The signer never calls an
//! operation the descriptor does not declare, and never treats a backend that
//! requires all participants as a t-of-n implementation.
//!
//! ## One-time state contract (§6.3)
//!
//! Every backend exposes its one-time secrets (nonces / preprocessing) through
//! [`OneTimeStateLedger`]. The signer consumes a record *before* it hands the
//! dependent protocol output to the coordinator. Backends never consume
//! implicitly.

use oic_domain_types::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Threshold topology the backend has been reviewed to support.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ThresholdTopology {
    /// Real t-of-n threshold signing. `min_threshold <= t <= n <= max_participants`.
    Threshold { max_participants: u16, min_threshold: u16 },
    /// Every participant must contribute. MUST NOT be exposed as t-of-n.
    AllParticipants { participants: u16 },
    /// Single key, no secret sharing. Development and conformance only.
    SingleKeyDevelopmentOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageConvention {
    /// Caller supplies a 32-byte digest; backend signs it directly.
    Prehashed32,
    /// Caller supplies the full message; backend applies the scheme's own hashing.
    PureMessage,
}

/// Declared capabilities. Absence is denial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendDescriptor {
    pub backend_id: String,
    /// Pinned upstream commit / crate version.
    pub pinned_version: String,
    pub license: String,
    pub scheme: SchemeId,
    pub message_convention: MessageConvention,
    pub topology: ThresholdTopology,
    pub supports_refresh: bool,
    pub supports_recover_or_replace: bool,
    /// Whether signatures verify under the chain's native verifier unchanged.
    pub native_verifier_compatible: bool,
    /// Whether one-time state (nonces/preprocessing) exists and must be ledgered.
    pub has_one_time_state: bool,
    /// First protocol round whose processing can reveal a signature share or
    /// a complete signature. The signer processes peer messages with
    /// `round < share_producing_round` freely (commitments, auxiliary data)
    /// and withholds messages at or after it until the authorization-state
    /// authority's *release* receipt is present (§5.4 step 5).
    pub share_producing_round: u16,
    /// Human-readable security note that MUST be shown in operator tooling.
    pub security_note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeygenCeremony {
    pub key_id: KeyId,
    pub key_epoch: Epoch,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub participants: Vec<ParticipantId>,
    pub threshold: u16,
    pub networks: Vec<NetworkId>,
    pub recovery_profile: String,
}

/// Authenticated protocol message between participants (§6.4). Transport
/// authenticates sender/recipient; the backend additionally binds
/// session, round, and sequence.
/// General-purpose serialization is deliberately unavailable for Class S.
/// ```compile_fail
/// use oic_crypto_provider::PeerMessage;
/// fn encode<T: serde::Serialize>(_: &T) {}
/// fn broadcast(message: &PeerMessage) { encode(message); }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PeerMessage {
    pub session_id: SigningSessionId,
    pub key_id: KeyId,
    pub key_epoch: Epoch,
    pub from: ParticipantId,
    /// Sender's signer-instance generation (§6.3). Peers reject messages from
    /// a generation older than the roster's current generation for `from`.
    pub from_generation: Epoch,
    /// `None` = broadcast.
    pub to: Option<ParticipantId>,
    pub round: u16,
    pub sequence: u64,
    pub protocol_version: String,
    pub payload: Bytes,
}

/// Result of advancing a protocol by one message. May contain Class S.
/// ```compile_fail
/// use oic_crypto_provider::ProtocolStep;
/// fn encode<T: serde::Serialize>(_: &T) {}
/// fn record(step: &ProtocolStep) { encode(step); }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub enum ProtocolStep {
    /// Messages this participant must send next.
    Send(Vec<PeerMessage>),
    /// Waiting for more peer input.
    Waiting,
    /// Protocol produced a signature share / partial that the coordinator aggregates.
    Share(Bytes),
    /// Protocol produced a complete signature (aggregating participants only).
    Complete(SignatureBytes),
    /// Protocol aborted; one-time state consumed and never reusable.
    Aborted(String),
}

impl fmt::Debug for PeerMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PeerMessage([REDACTED])")
    }
}

impl fmt::Debug for ProtocolStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtocolStep([REDACTED])")
    }
}

/// Record of a one-time secret's identity and durable consumption state (§6.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeStateRecord {
    pub record_id: String,
    pub key_id: KeyId,
    pub key_epoch: Epoch,
    pub signer_generation: Epoch,
    /// Session this record is bound to once allocated.
    pub session_id: Option<SigningSessionId>,
    /// Hash of the exact message the record was committed to.
    pub bound_message_hash: Option<Hash32>,
    pub consumed: bool,
}

/// Durable ledger for one-time state. Implementations must be crash-safe:
/// `consume` returns only after the record is durably marked consumed.
pub trait OneTimeStateLedger: Send + Sync {
    fn allocate(&self, key_id: &KeyId, key_epoch: Epoch, generation: Epoch, session_id: &SigningSessionId) -> OicResult<OneTimeStateRecord>;
    /// Bind to an exact message hash and durably consume. Fails if already consumed
    /// or bound to a different message.
    fn consume(&self, record_id: &str, message_hash: Hash32) -> OicResult<()>;
    fn get(&self, record_id: &str) -> OicResult<Option<OneTimeStateRecord>>;
    /// Discard all unconsumed records of older generations (after uncertain restore).
    fn tombstone_generations_before(&self, key_id: &KeyId, generation: Epoch) -> OicResult<u64>;
}

/// Ceremony output contains Class S sealed shares, not just its public descriptor.
/// ```compile_fail
/// use oic_crypto_provider::DistributedKeyResult;
/// fn encode<T: serde::Serialize>(_: &T) {}
/// fn publish(result: &DistributedKeyResult) { encode(result); }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct DistributedKeyResult {
    pub descriptor: KeyDescriptor,
    /// Per-participant opaque sealed share material. Never logged.
    pub sealed_shares: Vec<(ParticipantId, Bytes)>,
}

impl fmt::Debug for DistributedKeyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DistributedKeyResult([REDACTED])")
    }
}

/// A participant-local backend instance. One instance holds at most one
/// participant's share for a key; it never sees other shares.
pub trait CryptoProvider: Send + Sync {
    fn capabilities(&self) -> BackendDescriptor;

    /// Run (or simulate in-process for development) a distributed key generation.
    fn generate_distributed_key(&self, ceremony: &KeygenCeremony) -> OicResult<DistributedKeyResult>;

    /// Load this participant's sealed share for a key.
    fn load_share(&self, descriptor: &KeyDescriptor, participant: &ParticipantId, sealed: &Bytes) -> OicResult<()>;

    /// Begin a signing session for exactly one authorized payload. Returns the
    /// first outbound messages and the one-time state record allocated.
    fn start_signing_session(
        &self,
        session_id: &SigningSessionId,
        key_id: &KeyId,
        payload: &NativeSigningPayload,
        participants: &[ParticipantId],
        ledger: &dyn OneTimeStateLedger,
        signer_generation: Epoch,
    ) -> OicResult<ProtocolStep>;

    /// Feed one authenticated peer message. The backend MUST consume its
    /// one-time record via `ledger` before returning a step that reveals a
    /// signature share.
    fn advance_protocol(
        &self,
        session_id: &SigningSessionId,
        message: &PeerMessage,
        ledger: &dyn OneTimeStateLedger,
    ) -> OicResult<ProtocolStep>;

    /// Aggregate shares into a final signature. Only for backends whose
    /// descriptor declares aggregation is a public (non-secret) operation.
    fn aggregate(&self, session_id: &SigningSessionId, shares: &[(ParticipantId, Bytes)]) -> OicResult<SignatureBytes>;

    /// Verify a signature against a public key under the backend's scheme.
    fn verify_result(&self, public_key: &PublicKey, payload: &NativeSigningPayload, signature: &SignatureBytes) -> OicResult<()>;

    fn refresh_shares(&self, _ceremony: &KeygenCeremony) -> OicResult<DistributedKeyResult> {
        Err(OicError::unsupported("backend does not declare share refresh"))
    }

    fn recover_or_replace(&self, _ceremony: &KeygenCeremony) -> OicResult<DistributedKeyResult> {
        Err(OicError::unsupported("backend does not declare recover/replace"))
    }
}

impl fmt::Display for BackendDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{} [{:?}] {:?}", self.backend_id, self.pinned_version, self.scheme, self.topology)
    }
}

/// Validate that a ceremony is compatible with the declared topology. The
/// signer calls this before any keygen; a backend may also call it.
pub fn check_topology(desc: &BackendDescriptor, participants: usize, threshold: u16) -> OicResult<()> {
    let n = u16::try_from(participants).map_err(|_| OicError::invalid_request("too many participants"))?;
    match desc.topology {
        ThresholdTopology::Threshold { max_participants, min_threshold } => {
            if n > max_participants || threshold < min_threshold || threshold > n || threshold == 0 {
                return Err(OicError::unsupported(format!(
                    "backend {} supports threshold {min_threshold}..=n with n<={max_participants}; requested {threshold}-of-{n}",
                    desc.backend_id
                )));
            }
            Ok(())
        }
        ThresholdTopology::AllParticipants { participants: p } => {
            if n != p || threshold != p {
                return Err(OicError::unsupported(format!(
                    "backend {} requires all {p} participants; it MUST NOT be exposed as {threshold}-of-{n}",
                    desc.backend_id
                )));
            }
            Ok(())
        }
        ThresholdTopology::SingleKeyDevelopmentOnly => {
            if threshold != 1 || n != 1 {
                return Err(OicError::unsupported(format!(
                    "backend {} is single-key development-only; it provides no threshold security and cannot be exposed as {threshold}-of-{n}",
                    desc.backend_id
                )));
            }
            Ok(())
        }
    }
}
