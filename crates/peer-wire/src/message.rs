use crate::frame::{decode_frame, encode_frame};
use crate::{FrameKind, WireError, MAX_BODY_LEN};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oic_canonical_encoding::{canonical_bytes, domain_hash, from_canonical_bytes, sha256};
use oic_crypto_provider::PeerMessage;
use oic_domain_types::{
    domains, Bytes, EnvironmentId, Epoch, Hash32, InstitutionId, KeyId, ParticipantId,
    SigningSessionId, MAX_ID_LEN,
};
use serde::{Deserialize, Serialize};

/// Leaves room within the shared canonical decoder's aggregate item budget.
pub const MAX_PAYLOAD_LEN: usize = 32 * 1024;
pub const MAX_PROTOCOL_VERSION_LEN: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageScope {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub roster_epoch: u64,
    pub roster_hash: Hash32,
}

/// Trusted, caller-owned acceptance context, not values copied from the frame.
/// `from` must identify the participant owning the supplied roster verification
/// key. Exact round/sequence checks support caller-managed replay rejection;
/// verifying twice with unchanged expectations is intentionally stateless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedPeerMessage {
    pub scope: MessageScope,
    pub session_id: SigningSessionId,
    pub key_id: KeyId,
    pub key_epoch: Epoch,
    pub from: ParticipantId,
    pub from_generation: Epoch,
    pub to: ParticipantId,
    pub round: u16,
    pub sequence: u64,
    pub protocol_version: String,
}

/// Class S. Participant signatures originate in signer-core, never transport.
/// No `Serialize`, `Deserialize`, or public/confidential carrier traits exist.
pub struct SignedPeerMessage {
    scope: MessageScope,
    message: PeerMessage,
    signature: Signature,
}

impl std::fmt::Debug for SignedPeerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignedPeerMessage([REDACTED])")
    }
}

impl SignedPeerMessage {
    /// Untrusted routing hint, usable only to find independently verified state.
    pub fn session_id(&self) -> &SigningSessionId {
        &self.message.session_id
    }

    /// Untrusted routing hint, not evidence of the participant's identity.
    pub fn sender(&self) -> &ParticipantId {
        &self.message.from
    }

    /// Untrusted routing hint, not permission to advance the local protocol.
    pub fn round(&self) -> u16 {
        self.message.round
    }

    /// Sign with the participant key held by signer-core. Broadcast (`to=None`)
    /// is rejected; logically broadcast rounds must sign each named recipient.
    pub fn sign(
        message: PeerMessage,
        scope: MessageScope,
        key: &SigningKey,
    ) -> Result<Self, WireError> {
        validate(&message, &scope)?;
        let hash = commitment(&message, &scope)?;
        Ok(Self {
            scope,
            message,
            signature: key.sign(hash.as_ref()),
        })
    }

    pub fn verify(
        &self,
        expected: &ExpectedPeerMessage,
        key: &VerifyingKey,
    ) -> Result<&PeerMessage, WireError> {
        validate(&self.message, &self.scope)?;
        let m = &self.message;
        if self.scope != expected.scope {
            return Err(WireError::ScopeMismatch);
        }
        if m.from != expected.from {
            return Err(WireError::SenderMismatch);
        }
        if m.to.as_ref() != Some(&expected.to) {
            return Err(WireError::RecipientMismatch);
        }
        if m.from_generation != expected.from_generation {
            return Err(WireError::GenerationMismatch);
        }
        if m.session_id != expected.session_id {
            return Err(WireError::SessionMismatch);
        }
        if m.key_id != expected.key_id || m.key_epoch != expected.key_epoch {
            return Err(WireError::KeyMismatch);
        }
        if m.protocol_version != expected.protocol_version {
            return Err(WireError::ProtocolMismatch);
        }
        if m.round != expected.round {
            return Err(WireError::RoundMismatch);
        }
        if m.sequence != expected.sequence {
            return Err(WireError::SequenceMismatch);
        }
        key.verify_strict(commitment(m, &self.scope)?.as_ref(), &self.signature)
            .map_err(|_| WireError::InvalidSignature)?;
        Ok(m)
    }

    /// The returned bytes are Class S: deliver to exactly `message.to` over an
    /// admitted MPC channel; never log them or hand them to block/resolver APIs.
    pub fn encode_point_to_point(
        &self,
        kind: FrameKind,
        max_body_len: usize,
    ) -> Result<Vec<u8>, WireError> {
        if !kind.is_mpc() {
            return Err(WireError::WrongCarrier);
        }
        let wire = PrivateSignedMessage {
            scope: self.scope.clone(),
            message: PrivatePeerMessage::from(&self.message),
            signature: Bytes(self.signature.to_bytes().to_vec()),
        };
        let body = canonical_bytes(&wire).map_err(|_| WireError::InvalidBody)?;
        encode_frame(&body, self.scope.roster_epoch, kind, max_body_len)
    }

    /// Structural decode only. Call `verify` with a roster participant key and
    /// independent session expectations before delivering anything to a backend.
    pub fn decode_point_to_point(
        bytes: &[u8],
        expected_epoch: u64,
        kind: FrameKind,
        max_body_len: usize,
    ) -> Result<Self, WireError> {
        if !kind.is_mpc() {
            return Err(WireError::WrongCarrier);
        }
        let body = decode_frame(bytes, expected_epoch, kind, max_body_len.min(MAX_BODY_LEN))?;
        let wire: PrivateSignedMessage =
            from_canonical_bytes(body).map_err(|_| WireError::InvalidBody)?;
        if wire.scope.roster_epoch != expected_epoch {
            return Err(WireError::ScopeMismatch);
        }
        let message = wire.message.into_message();
        validate(&message, &wire.scope)?;
        let signature = Signature::from_slice(wire.signature.as_ref())
            .map_err(|_| WireError::InvalidSignature)?;
        Ok(Self {
            scope: wire.scope,
            message,
            signature,
        })
    }
}

fn valid_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())
}

fn validate(m: &PeerMessage, scope: &MessageScope) -> Result<(), WireError> {
    if m.payload.len() > MAX_PAYLOAD_LEN {
        return Err(WireError::TooLarge);
    }
    let to = m.to.as_ref().ok_or(WireError::RecipientMismatch)?;
    for s in [
        scope.institution_id.as_str(),
        scope.environment_id.as_str(),
        m.session_id.as_str(),
        m.key_id.as_str(),
        m.from.as_str(),
        to.as_str(),
    ] {
        if !valid_text(s, MAX_ID_LEN) {
            return Err(WireError::InvalidMessage);
        }
    }
    if !valid_text(&m.protocol_version, MAX_PROTOCOL_VERSION_LEN) {
        return Err(WireError::InvalidMessage);
    }
    Ok(())
}

#[derive(Serialize)]
struct Commitment<'a> {
    scope: &'a MessageScope,
    session_id: &'a SigningSessionId,
    key_id: &'a KeyId,
    key_epoch: Epoch,
    from: &'a ParticipantId,
    from_generation: Epoch,
    to: &'a Option<ParticipantId>,
    round: u16,
    sequence: u64,
    protocol_version: &'a str,
    payload_hash: Hash32,
}

fn commitment(m: &PeerMessage, scope: &MessageScope) -> Result<Hash32, WireError> {
    // Exhaustive destructuring forces a review when PeerMessage gains a field.
    let PeerMessage {
        session_id,
        key_id,
        key_epoch,
        from,
        from_generation,
        to,
        round,
        sequence,
        protocol_version,
        payload,
    } = m;
    domain_hash(
        domains::PEER_MESSAGE,
        &Commitment {
            scope,
            session_id,
            key_id,
            key_epoch: *key_epoch,
            from,
            from_generation: *from_generation,
            to,
            round: *round,
            sequence: *sequence,
            protocol_version,
            payload_hash: sha256(payload.as_ref()),
        },
    )
    .map_err(|_| WireError::InvalidBody)
}

// Private DTOs are the only serde path for release-sensitive protocol material.
// Do not expose these types or derive Debug.
#[derive(Serialize, Deserialize)]
struct PrivateSignedMessage {
    scope: MessageScope,
    message: PrivatePeerMessage,
    signature: Bytes,
}

#[derive(Serialize, Deserialize)]
struct PrivatePeerMessage {
    session_id: SigningSessionId,
    key_id: KeyId,
    key_epoch: Epoch,
    from: ParticipantId,
    from_generation: Epoch,
    to: Option<ParticipantId>,
    round: u16,
    sequence: u64,
    protocol_version: String,
    payload: Bytes,
}

impl From<&PeerMessage> for PrivatePeerMessage {
    fn from(m: &PeerMessage) -> Self {
        let PeerMessage {
            session_id,
            key_id,
            key_epoch,
            from,
            from_generation,
            to,
            round,
            sequence,
            protocol_version,
            payload,
        } = m;
        Self {
            session_id: session_id.clone(),
            key_id: key_id.clone(),
            key_epoch: *key_epoch,
            from: from.clone(),
            from_generation: *from_generation,
            to: to.clone(),
            round: *round,
            sequence: *sequence,
            protocol_version: protocol_version.clone(),
            payload: payload.clone(),
        }
    }
}

impl PrivatePeerMessage {
    fn into_message(self) -> PeerMessage {
        let Self {
            session_id,
            key_id,
            key_epoch,
            from,
            from_generation,
            to,
            round,
            sequence,
            protocol_version,
            payload,
        } = self;
        PeerMessage {
            session_id,
            key_id,
            key_epoch,
            from,
            from_generation,
            to,
            round,
            sequence,
            protocol_version,
            payload,
        }
    }
}
