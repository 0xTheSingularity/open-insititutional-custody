//! Backend message drivers (RFC 0001 §6.1, §6.4).
//!
//! A driver knows one threshold backend's wire contract well enough to move
//! its messages between participants. It carries no authority: every
//! message it produces is re-checked by each signer's scope checks
//! (`Signer::receive`) and by the backend itself, and every share-producing
//! message is withheld by the signers until the authority's release receipt
//! is presented.
//!
//! * [`FrostEd25519Driver`]: round 1 commitments are broadcast to the other
//!   session participants; the coordinator then builds the FROST
//!   `SigningPackage` from the collected commitments
//!   ([`build_signing_package`]) and relays it to each participant
//!   attributed to another session participant (the backend refuses
//!   `from == self`), with a sequence number above that participant's
//!   round-1 sequence.
//! * [`DevSingleKeyDriver`]: no round-1 traffic; one release message per
//!   session, attributed to the signer itself at its own generation, whose
//!   payload is `SHA-256(message_or_digest)`.

use oic_canonical_encoding::sha256;
use oic_crypto_provider::PeerMessage;
use oic_crypto_provider_frost_ed25519::build_signing_package;
use oic_domain_types::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One message to deliver to one participant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub to: ParticipantId,
    pub message: PeerMessage,
}

/// What a driver knows about the session it moves messages for.
#[derive(Clone, Copy, Debug)]
pub struct SessionContext<'a> {
    pub session_id: &'a SigningSessionId,
    pub key: &'a KeyDescriptor,
    /// The single payload this key signs in the session.
    pub payload: &'a NativeSigningPayload,
    /// The envelope's participant set, in envelope order.
    pub participants: &'a [ParticipantId],
    /// Current signer generation of every participant.
    pub generations: &'a BTreeMap<ParticipantId, Epoch>,
}

impl SessionContext<'_> {
    fn generation(&self, p: &ParticipantId) -> OicResult<Epoch> {
        self.generations.get(p).copied().ok_or_else(|| OicError::internal(format!("no generation known for participant {p}")))
    }
}

/// Round-1 output of each participant (`ProtocolStep::Send` messages from
/// `open_session`; an empty list for `Waiting`).
pub type Round1 = BTreeMap<ParticipantId, Vec<PeerMessage>>;

/// Moves one backend's protocol messages. See the module docs.
pub trait BackendDriver: Send + Sync {
    /// The `KeyDescriptor::backend_id` this driver speaks.
    fn backend_id(&self) -> &'static str;

    /// Refuse a key/participant set this backend cannot sign with, before
    /// anything is reserved.
    fn check_participants(&self, key: &KeyDescriptor, participants: &[ParticipantId]) -> OicResult<()>;

    /// Deliveries of the participants' round-1 messages to their peers.
    /// Every delivery must be answered with `Waiting`.
    fn relay_round1(&self, ctx: &SessionContext<'_>, round1: &Round1) -> OicResult<Vec<Delivery>>;

    /// The share-producing messages to deliver; signers buffer them until
    /// release.
    fn round2(&self, ctx: &SessionContext<'_>, round1: &Round1) -> OicResult<Vec<Delivery>>;
}

fn distinct_members(key: &KeyDescriptor, participants: &[ParticipantId]) -> OicResult<()> {
    let set: BTreeSet<&ParticipantId> = participants.iter().collect();
    if set.len() != participants.len() {
        return Err(OicError::invalid_request("participant set contains duplicates"));
    }
    if let Some(p) = participants.iter().find(|p| !key.participants.contains(p)) {
        return Err(OicError::scope(format!("{p} is not a participant of key {}", key.key_id)));
    }
    Ok(())
}

/// Driver for `oic-crypto-provider-frost-ed25519`.
#[derive(Clone, Copy, Debug, Default)]
pub struct FrostEd25519Driver;

impl FrostEd25519Driver {
    /// Validate that `round1` holds exactly one round-1 commitment from each
    /// participant, bound to this session and key; returns them in
    /// participant order with each sender's sequence number.
    fn commitments<'r>(ctx: &SessionContext<'_>, round1: &'r Round1) -> OicResult<Vec<&'r PeerMessage>> {
        if round1.len() != ctx.participants.len() || ctx.participants.iter().any(|p| !round1.contains_key(p)) {
            return Err(OicError::invalid_request("round-1 output must come from exactly the session participants"));
        }
        let mut out = Vec::with_capacity(ctx.participants.len());
        for p in ctx.participants {
            let msgs = &round1[p];
            let [m] = msgs.as_slice() else {
                return Err(OicError::invalid_request(format!("{p} must emit exactly one FROST round-1 commitment, emitted {}", msgs.len())));
            };
            if &m.from != p || m.round != 1 || m.to.is_some() {
                return Err(OicError::invalid_request(format!("{p}'s round-1 message is not its own broadcast commitment")));
            }
            if &m.session_id != ctx.session_id || m.key_id != ctx.key.key_id || m.key_epoch != ctx.key.key_epoch {
                return Err(OicError::scope(format!("{p}'s round-1 message is for another session or key")));
            }
            if m.protocol_version != oic_crypto_provider_frost_ed25519::PROTOCOL_VERSION {
                return Err(OicError::invalid_request(format!("{p}'s round-1 message has protocol version {}", m.protocol_version)));
            }
            out.push(m);
        }
        Ok(out)
    }
}

impl BackendDriver for FrostEd25519Driver {
    fn backend_id(&self) -> &'static str {
        oic_crypto_provider_frost_ed25519::BACKEND_ID
    }

    fn check_participants(&self, key: &KeyDescriptor, participants: &[ParticipantId]) -> OicResult<()> {
        if key.backend_id != self.backend_id() || key.scheme != SchemeId::Ed25519Pure {
            return Err(OicError::unsupported("FROST(Ed25519) driver requires an Ed25519Pure key of the frost-ed25519 backend"));
        }
        distinct_members(key, participants)?;
        let needed = usize::from(key.threshold.max(oic_crypto_provider_frost_ed25519::MIN_THRESHOLD));
        if participants.len() < needed {
            return Err(OicError::invalid_request(format!("FROST signing needs at least {needed} participants, got {}", participants.len())));
        }
        Ok(())
    }

    fn relay_round1(&self, ctx: &SessionContext<'_>, round1: &Round1) -> OicResult<Vec<Delivery>> {
        let commitments = Self::commitments(ctx, round1)?;
        let mut out = Vec::new();
        for m in commitments {
            for q in ctx.participants.iter().filter(|q| **q != m.from) {
                out.push(Delivery { to: q.clone(), message: m.clone() });
            }
        }
        Ok(out)
    }

    fn round2(&self, ctx: &SessionContext<'_>, round1: &Round1) -> OicResult<Vec<Delivery>> {
        let commitments = Self::commitments(ctx, round1)?;
        let pairs: Vec<(ParticipantId, Bytes)> = commitments.iter().map(|m| (m.from.clone(), m.payload.clone())).collect();
        let package = build_signing_package(&pairs, ctx.payload.message_or_digest.as_slice())?;
        let n = ctx.participants.len();
        let mut out = Vec::with_capacity(n);
        for (i, to) in ctx.participants.iter().enumerate() {
            let relay = commitments[(i + 1) % n];
            let sequence = relay.sequence.checked_add(1).ok_or_else(|| OicError::invalid_request("round-1 sequence exhausted"))?;
            out.push(Delivery {
                to: to.clone(),
                message: PeerMessage {
                    session_id: ctx.session_id.clone(),
                    key_id: ctx.key.key_id.clone(),
                    key_epoch: ctx.key.key_epoch,
                    from: relay.from.clone(),
                    from_generation: ctx.generation(&relay.from)?,
                    to: Some(to.clone()),
                    round: 2,
                    sequence,
                    protocol_version: oic_crypto_provider_frost_ed25519::PROTOCOL_VERSION.into(),
                    payload: package.clone(),
                },
            });
        }
        Ok(out)
    }
}

/// Driver for `oic-crypto-provider-dev` (single key, development only).
#[derive(Clone, Copy, Debug, Default)]
pub struct DevSingleKeyDriver;

impl BackendDriver for DevSingleKeyDriver {
    fn backend_id(&self) -> &'static str {
        oic_crypto_provider_dev::BACKEND_ID
    }

    fn check_participants(&self, key: &KeyDescriptor, participants: &[ParticipantId]) -> OicResult<()> {
        if key.backend_id != self.backend_id() || !matches!(key.scheme, SchemeId::EcdsaSecp256k1Keccak256Prehashed | SchemeId::Ed25519Pure) {
            return Err(OicError::unsupported("dev single-key driver requires a secp256k1 or Ed25519 key of the dev-single-key backend"));
        }
        distinct_members(key, participants)?;
        if participants.len() != 1 || key.participants.len() != 1 {
            return Err(OicError::invalid_request("the dev single-key backend signs with exactly its one participant"));
        }
        Ok(())
    }

    fn relay_round1(&self, ctx: &SessionContext<'_>, round1: &Round1) -> OicResult<Vec<Delivery>> {
        if round1.len() != ctx.participants.len() || round1.values().any(|m| !m.is_empty()) {
            return Err(OicError::invalid_request("the dev single-key backend emits no round-1 messages"));
        }
        Ok(Vec::new())
    }

    fn round2(&self, ctx: &SessionContext<'_>, round1: &Round1) -> OicResult<Vec<Delivery>> {
        self.relay_round1(ctx, round1)?;
        let [p] = ctx.participants else {
            return Err(OicError::invalid_request("the dev single-key backend signs with exactly one participant"));
        };
        Ok(vec![Delivery {
            to: p.clone(),
            message: PeerMessage {
                session_id: ctx.session_id.clone(),
                key_id: ctx.key.key_id.clone(),
                key_epoch: ctx.key.key_epoch,
                from: p.clone(),
                from_generation: ctx.generation(p)?,
                to: Some(p.clone()),
                round: 1,
                sequence: 1,
                protocol_version: oic_crypto_provider_dev::PROTOCOL_VERSION.into(),
                payload: Bytes(sha256(ctx.payload.message_or_digest.as_slice()).0.to_vec()),
            },
        }])
    }
}

/// The driver for a key, chosen by its signature scheme and backend:
/// `Ed25519Pure` on `frost-ed25519` → [`FrostEd25519Driver`];
/// `EcdsaSecp256k1Keccak256Prehashed` or `Ed25519Pure` on `dev-single-key`
/// → [`DevSingleKeyDriver`]. Anything else is `UnsupportedCapability`.
pub fn driver_for(key: &KeyDescriptor) -> OicResult<Arc<dyn BackendDriver>> {
    match (key.scheme, key.backend_id.as_str()) {
        (SchemeId::Ed25519Pure, oic_crypto_provider_frost_ed25519::BACKEND_ID) => Ok(Arc::new(FrostEd25519Driver)),
        (SchemeId::EcdsaSecp256k1Keccak256Prehashed | SchemeId::Ed25519Pure, oic_crypto_provider_dev::BACKEND_ID) => Ok(Arc::new(DevSingleKeyDriver)),
        (scheme, backend) => Err(OicError::unsupported(format!("no coordinator driver for scheme {scheme:?} on backend `{backend}`"))),
    }
}
