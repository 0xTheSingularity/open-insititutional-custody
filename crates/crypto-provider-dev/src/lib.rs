//! # oic-crypto-provider-dev
//!
//! [`DevSingleKeyProvider`]: a complete, real-cryptography implementation of
//! [`CryptoProvider`] with topology
//! [`ThresholdTopology::SingleKeyDevelopmentOnly`].
//!
//! ## Security claim it makes
//!
//! * Signatures are genuine: secp256k1 ECDSA over a caller-supplied 32-byte
//!   digest via `k256` (65 bytes `r ‖ s ‖ recid`, low-s enforced; scheme
//!   `EcdsaSecp256k1Keccak256Prehashed`) or pure Ed25519 (RFC 8032) over the
//!   full message via `ed25519-dalek` (64 bytes; scheme `Ed25519Pure`). They
//!   verify under the chains' native verifiers unchanged.
//! * The issuance boundary is exercised exactly as for a threshold backend:
//!   each session allocates a one-time-state record and the record is
//!   durably consumed, bound to `SHA-256(message_or_digest)`, **before** the
//!   signature is returned. A consumed or aborted session never signs again.
//! * Shares at rest are sealed with ChaCha20-Poly1305 under a provider-held
//!   key (see the `seal` module for the format); decrypted key material is
//!   zeroized on drop.
//!
//! ## Security claim it does NOT make
//!
//! **It provides NO threshold security.** The whole private key exists in
//! one process. Compromise of this one instance (or its sealing key) is
//! compromise of the key. It is for development and conformance testing
//! only and [`oic_crypto_provider::check_topology`] rejects every
//! configuration other than 1-of-1.
//!
//! ## Protocol (integrator contract)
//!
//! * `start_signing_session` → [`ProtocolStep::Waiting`].
//! * The coordinator then sends exactly one [`PeerMessage`] with
//!   `round == 1`, `protocol_version == "oic-dev-single-key/1"`
//!   ([`PROTOCOL_VERSION`]), matching session/key/epoch, `to` = `None` or this
//!   participant, and `payload` = the 32 raw bytes of
//!   `SHA-256(payload.message_or_digest)` (binds the release to the exact
//!   message). This is the share-producing round
//!   (`share_producing_round == 1`), so the signer withholds it until the
//!   authorization-state release receipt is present.
//! * `advance_protocol` consumes the ledger record, signs, and returns
//!   [`ProtocolStep::Complete`]; any later advance returns
//!   [`ProtocolStep::Aborted`].

mod seal;

use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, SigningKey as EcdsaSigningKey, VerifyingKey as EcdsaVerifyingKey};
use oic_canonical_encoding::sha256;
use oic_crypto_provider::*;
use oic_domain_types::*;
use parking_lot::Mutex;
use rand_core::{CryptoRngCore, OsRng};
use seal::{SealContext, SealingKey};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const BACKEND_ID: &str = "dev-single-key";
/// `PeerMessage.protocol_version` for the single release round.
pub const PROTOCOL_VERSION: &str = "oic-dev-single-key/1";
/// Pinned upstream crate versions (as resolved in the workspace `Cargo.lock`).
pub const PINNED_VERSIONS: &str = "k256=0.13.4;ed25519-dalek=2.2.0;chacha20poly1305=0.10.1";
pub const SECURITY_NOTE: &str = "DEVELOPMENT ONLY: single key, NO threshold security. The entire private key lives in one process; \
compromise of this instance or its sealing key is compromise of the key. Use only for development and conformance testing.";

/// Decrypted signing key, held in memory only. Both inner key types wipe
/// their secret scalar on drop.
enum Secret {
    Secp256k1(EcdsaSigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

struct LoadedKey {
    descriptor: KeyDescriptor,
    participant: ParticipantId,
    secret: Secret,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SessionState {
    AwaitingRelease,
    Completed,
    Aborted(String),
}

struct Session {
    key_id: KeyId,
    key_epoch: Epoch,
    participant: ParticipantId,
    payload: NativeSigningPayload,
    record_id: String,
    state: SessionState,
}

/// Single-key development provider for one scheme. See the crate docs.
pub struct DevSingleKeyProvider {
    scheme: SchemeId,
    sealing: SealingKey,
    rng: Mutex<Box<dyn CryptoRngCore + Send>>,
    keys: Mutex<BTreeMap<KeyId, LoadedKey>>,
    sessions: Mutex<BTreeMap<SigningSessionId, Session>>,
}

impl DevSingleKeyProvider {
    /// Create a provider for `scheme` (`EcdsaSecp256k1Keccak256Prehashed` or
    /// `Ed25519Pure`) with a 32-byte share-sealing key and an injectable RNG
    /// (used for key generation and sealing nonces).
    pub fn new(scheme: SchemeId, sealing_key: [u8; 32], rng: Box<dyn CryptoRngCore + Send>) -> OicResult<Self> {
        match scheme {
            SchemeId::EcdsaSecp256k1Keccak256Prehashed | SchemeId::Ed25519Pure => {}
            other => return Err(OicError::unsupported(format!("{BACKEND_ID} does not support scheme {other:?}"))),
        }
        Ok(DevSingleKeyProvider {
            scheme,
            sealing: SealingKey::new(sealing_key),
            rng: Mutex::new(rng),
            keys: Mutex::new(BTreeMap::new()),
            sessions: Mutex::new(BTreeMap::new()),
        })
    }

    /// [`Self::new`] with the operating-system CSPRNG.
    pub fn with_os_rng(scheme: SchemeId, sealing_key: [u8; 32]) -> OicResult<Self> {
        Self::new(scheme, sealing_key, Box::new(OsRng))
    }

    pub fn scheme(&self) -> SchemeId {
        self.scheme
    }

    fn seal_ctx<'a>(key_id: &'a KeyId, key_epoch: Epoch, participant: &'a ParticipantId) -> SealContext<'a> {
        SealContext { backend_id: BACKEND_ID, key_id, key_epoch, participant }
    }

    fn check_scheme(&self, scheme: SchemeId, what: &str) -> OicResult<()> {
        if scheme != self.scheme {
            return Err(OicError::unsupported(format!("{what} scheme {scheme:?} does not match provider scheme {:?}", self.scheme)));
        }
        Ok(())
    }

    fn check_message_shape(&self, payload: &NativeSigningPayload) -> OicResult<()> {
        if self.scheme == SchemeId::EcdsaSecp256k1Keccak256Prehashed && payload.message_or_digest.len() != 32 {
            return Err(OicError::invalid_request("prehashed secp256k1 payload must be exactly a 32-byte digest"));
        }
        Ok(())
    }

    fn abort(&self, session_id: &SigningSessionId, reason: &str) {
        if let Some(s) = self.sessions.lock().get_mut(session_id) {
            s.state = SessionState::Aborted(reason.to_string());
        }
    }
}

fn public_key_of(secret: &Secret) -> PublicKey {
    match secret {
        Secret::Secp256k1(sk) => PublicKey {
            scheme: SchemeId::EcdsaSecp256k1Keccak256Prehashed,
            bytes: Bytes(sk.verifying_key().to_encoded_point(true).as_bytes().to_vec()),
        },
        Secret::Ed25519(sk) => PublicKey { scheme: SchemeId::Ed25519Pure, bytes: Bytes(sk.verifying_key().to_bytes().to_vec()) },
    }
}

fn secret_bytes(secret: &Secret) -> Zeroizing<[u8; 32]> {
    match secret {
        Secret::Secp256k1(sk) => Zeroizing::new(sk.to_bytes().into()),
        Secret::Ed25519(sk) => Zeroizing::new(sk.to_bytes()),
    }
}

fn secret_from_bytes(scheme: SchemeId, bytes: &[u8]) -> OicResult<Secret> {
    let arr: Zeroizing<[u8; 32]> =
        Zeroizing::new(bytes.try_into().map_err(|_| OicError::invalid_request("unsealed share has the wrong length"))?);
    match scheme {
        SchemeId::EcdsaSecp256k1Keccak256Prehashed => EcdsaSigningKey::from_bytes((&*arr).into())
            .map(Secret::Secp256k1)
            .map_err(|_| OicError::invalid_request("unsealed share is not a valid secp256k1 scalar")),
        SchemeId::Ed25519Pure => Ok(Secret::Ed25519(ed25519_dalek::SigningKey::from_bytes(&arr))),
        other => Err(OicError::unsupported(format!("scheme {other:?}"))),
    }
}

/// Sign; for ECDSA returns `r ‖ s ‖ recid` with `s` normalized to the low half.
fn sign_with(secret: &Secret, message: &[u8]) -> OicResult<SignatureBytes> {
    match secret {
        Secret::Secp256k1(sk) => {
            let (sig, recid) = sk.sign_prehash_recoverable(message).map_err(|_| OicError::internal("ECDSA signing failed"))?;
            let (sig, recid) = match sig.normalize_s() {
                Some(low) => (low, RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced())),
                None => (sig, recid),
            };
            let mut b = sig.to_bytes().to_vec();
            b.push(recid.to_byte());
            Ok(SignatureBytes { scheme: SchemeId::EcdsaSecp256k1Keccak256Prehashed, bytes: Bytes(b) })
        }
        Secret::Ed25519(sk) => {
            use ed25519_dalek::Signer;
            Ok(SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(sk.sign(message).to_bytes().to_vec()) })
        }
    }
}

/// Native verification shared by `verify_result` and `aggregate`.
fn verify_native(public_key: &PublicKey, message: &[u8], signature: &SignatureBytes) -> OicResult<()> {
    if public_key.scheme != signature.scheme {
        return Err(OicError::invalid_signature("signature scheme does not match public key scheme"));
    }
    match public_key.scheme {
        SchemeId::EcdsaSecp256k1Keccak256Prehashed => {
            let b = signature.bytes.as_slice();
            if b.len() != 65 {
                return Err(OicError::invalid_signature("secp256k1 signature must be 65 bytes r||s||recid"));
            }
            if message.len() != 32 {
                return Err(OicError::invalid_request("prehashed secp256k1 message must be 32 bytes"));
            }
            let sig = EcdsaSignature::from_slice(&b[..64]).map_err(|_| OicError::invalid_signature("r or s out of range"))?;
            if sig.normalize_s().is_some() {
                return Err(OicError::invalid_signature("high-s signature rejected"));
            }
            let recid = RecoveryId::from_byte(b[64])
                .filter(|r| r.to_byte() <= 1)
                .ok_or_else(|| OicError::invalid_signature("recovery id must be 0 or 1"))?;
            let vk = EcdsaVerifyingKey::from_sec1_bytes(public_key.bytes.as_slice())
                .map_err(|_| OicError::invalid_request("public key is not a valid secp256k1 point"))?;
            use k256::ecdsa::signature::hazmat::PrehashVerifier;
            vk.verify_prehash(message, &sig).map_err(|_| OicError::invalid_signature("ECDSA verification failed"))?;
            let recovered = EcdsaVerifyingKey::recover_from_prehash(message, &sig, recid)
                .map_err(|_| OicError::invalid_signature("public key recovery failed"))?;
            if recovered != vk {
                return Err(OicError::invalid_signature("recovery id does not recover the signing key"));
            }
            Ok(())
        }
        SchemeId::Ed25519Pure => {
            let pk: [u8; 32] =
                public_key.bytes.as_slice().try_into().map_err(|_| OicError::invalid_request("Ed25519 public key must be 32 bytes"))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| OicError::invalid_request("invalid Ed25519 public key"))?;
            let sig = ed25519_dalek::Signature::from_slice(signature.bytes.as_slice())
                .map_err(|_| OicError::invalid_signature("Ed25519 signature must be 64 bytes"))?;
            vk.verify_strict(message, &sig).map_err(|_| OicError::invalid_signature("Ed25519 verification failed"))
        }
        other => Err(OicError::unsupported(format!("scheme {other:?}"))),
    }
}

impl CryptoProvider for DevSingleKeyProvider {
    fn capabilities(&self) -> BackendDescriptor {
        BackendDescriptor {
            backend_id: BACKEND_ID.into(),
            pinned_version: PINNED_VERSIONS.into(),
            license: "Apache-2.0".into(),
            scheme: self.scheme,
            message_convention: match self.scheme {
                SchemeId::Ed25519Pure => MessageConvention::PureMessage,
                _ => MessageConvention::Prehashed32,
            },
            topology: ThresholdTopology::SingleKeyDevelopmentOnly,
            supports_refresh: false,
            supports_recover_or_replace: false,
            native_verifier_compatible: true,
            has_one_time_state: true,
            share_producing_round: 1,
            security_note: SECURITY_NOTE.into(),
        }
    }

    fn generate_distributed_key(&self, ceremony: &KeygenCeremony) -> OicResult<DistributedKeyResult> {
        check_topology(&self.capabilities(), ceremony.participants.len(), ceremony.threshold)?;
        let participant = ceremony.participants[0].clone();
        let mut guard = self.rng.lock();
        let mut rng: &mut (dyn CryptoRngCore + Send) = &mut **guard;
        let secret = match self.scheme {
            SchemeId::EcdsaSecp256k1Keccak256Prehashed => Secret::Secp256k1(EcdsaSigningKey::random(&mut rng)),
            _ => Secret::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng)),
        };
        let raw = secret_bytes(&secret);
        let sealed =
            seal::seal(&self.sealing, rng, &Self::seal_ctx(&ceremony.key_id, ceremony.key_epoch, &participant), &raw[..])?;
        let descriptor = KeyDescriptor {
            key_id: ceremony.key_id.clone(),
            key_epoch: ceremony.key_epoch,
            scheme: self.scheme,
            public_key: public_key_of(&secret),
            backend_id: BACKEND_ID.into(),
            backend_commit: PINNED_VERSIONS.into(),
            participants: vec![participant.clone()],
            threshold: 1,
            institution_id: ceremony.institution_id.clone(),
            environment_id: ceremony.environment_id.clone(),
            networks: ceremony.networks.clone(),
            recovery_profile: ceremony.recovery_profile.clone(),
        };
        Ok(DistributedKeyResult { descriptor, sealed_shares: vec![(participant, Bytes(sealed))] })
    }

    fn load_share(&self, descriptor: &KeyDescriptor, participant: &ParticipantId, sealed: &Bytes) -> OicResult<()> {
        if descriptor.backend_id != BACKEND_ID {
            return Err(OicError::scope(format!("descriptor backend {} is not {BACKEND_ID}", descriptor.backend_id)));
        }
        self.check_scheme(descriptor.scheme, "descriptor")?;
        if descriptor.participants.as_slice() != std::slice::from_ref(participant) || descriptor.threshold != 1 {
            return Err(OicError::scope("descriptor is not a 1-of-1 key for this participant"));
        }
        let plain = seal::open(&self.sealing, &Self::seal_ctx(&descriptor.key_id, descriptor.key_epoch, participant), sealed.as_slice())?;
        let secret = secret_from_bytes(self.scheme, &plain)?;
        if public_key_of(&secret) != descriptor.public_key {
            return Err(OicError::scope("sealed share does not match the descriptor public key"));
        }
        self.keys
            .lock()
            .insert(descriptor.key_id.clone(), LoadedKey { descriptor: descriptor.clone(), participant: participant.clone(), secret });
        Ok(())
    }

    fn start_signing_session(
        &self,
        session_id: &SigningSessionId,
        key_id: &KeyId,
        payload: &NativeSigningPayload,
        participants: &[ParticipantId],
        ledger: &dyn OneTimeStateLedger,
        signer_generation: Epoch,
    ) -> OicResult<ProtocolStep> {
        if payload.required_key_id != *key_id {
            return Err(OicError::scope("payload required_key_id does not match session key"));
        }
        self.check_scheme(payload.scheme_id, "payload")?;
        self.check_message_shape(payload)?;
        let (key_epoch, participant) = {
            let keys = self.keys.lock();
            let k = keys.get(key_id).ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("no share loaded for key {key_id}")))?;
            (k.descriptor.key_epoch, k.participant.clone())
        };
        if participants != std::slice::from_ref(&participant) {
            return Err(OicError::scope("single-key session participant set must be exactly this participant"));
        }
        let mut sessions = self.sessions.lock();
        if sessions.contains_key(session_id) {
            return Err(OicError::resource_conflict(format!("session {session_id} already exists")));
        }
        let record = ledger.allocate(key_id, key_epoch, signer_generation, session_id)?;
        sessions.insert(
            session_id.clone(),
            Session {
                key_id: key_id.clone(),
                key_epoch,
                participant,
                payload: payload.clone(),
                record_id: record.record_id,
                state: SessionState::AwaitingRelease,
            },
        );
        Ok(ProtocolStep::Waiting)
    }

    fn advance_protocol(&self, session_id: &SigningSessionId, message: &PeerMessage, ledger: &dyn OneTimeStateLedger) -> OicResult<ProtocolStep> {
        // Hold the sessions lock across consume+sign so concurrent advances of
        // one session serialize; the ledger enforces single use regardless.
        let mut sessions = self.sessions.lock();
        let s = sessions
            .get_mut(session_id)
            .ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("unknown session {session_id}")))?;
        match &s.state {
            SessionState::AwaitingRelease => {}
            SessionState::Completed => {
                return Ok(ProtocolStep::Aborted("session already produced its signature; one-time record is consumed".into()))
            }
            SessionState::Aborted(r) => return Ok(ProtocolStep::Aborted(format!("session aborted: {r}"))),
        }
        if message.session_id != *session_id || message.key_id != s.key_id || message.key_epoch != s.key_epoch {
            return Err(OicError::scope("peer message session/key/epoch does not match the session"));
        }
        if message.protocol_version != PROTOCOL_VERSION {
            return Err(OicError::invalid_request(format!("protocol_version must be {PROTOCOL_VERSION}")));
        }
        if message.round != 1 {
            return Err(OicError::invalid_request("dev single-key protocol has exactly one round (1)"));
        }
        if message.to.as_ref().is_some_and(|to| *to != s.participant) {
            return Err(OicError::scope("peer message is addressed to another participant"));
        }
        let message_hash = sha256(s.payload.message_or_digest.as_slice());
        if message.payload.as_slice() != message_hash.0 {
            return Err(OicError::scope("release message does not bind SHA-256 of the session payload"));
        }

        // §6.3: durable consumption precedes any dependent output.
        if let Err(e) = ledger.consume(&s.record_id, message_hash) {
            s.state = SessionState::Aborted(format!("one-time record consume failed: {}", e.detail));
            return Err(e);
        }
        let signed = {
            let keys = self.keys.lock();
            match keys.get(&s.key_id) {
                Some(k) => sign_with(&k.secret, s.payload.message_or_digest.as_slice()),
                None => Err(OicError::new(ErrorCode::NotFound, "share unloaded during session")),
            }
        };
        match signed {
            Ok(sig) => {
                s.state = SessionState::Completed;
                Ok(ProtocolStep::Complete(sig))
            }
            Err(e) => {
                s.state = SessionState::Aborted(e.detail.clone());
                Err(e)
            }
        }
    }

    fn aggregate(&self, session_id: &SigningSessionId, shares: &[(ParticipantId, Bytes)]) -> OicResult<SignatureBytes> {
        let (participant, payload, key_id) = {
            let sessions = self.sessions.lock();
            let s = sessions
                .get(session_id)
                .ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("unknown session {session_id}")))?;
            (s.participant.clone(), s.payload.clone(), s.key_id.clone())
        };
        let [(from, bytes)] = shares else {
            return Err(OicError::invalid_request("single-key aggregation takes exactly one share"));
        };
        if *from != participant {
            return Err(OicError::scope("share is not from this session's participant"));
        }
        let public_key = {
            let keys = self.keys.lock();
            keys.get(&key_id).map(|k| k.descriptor.public_key.clone()).ok_or_else(|| OicError::new(ErrorCode::NotFound, "key not loaded"))?
        };
        let sig = SignatureBytes { scheme: self.scheme, bytes: bytes.clone() };
        verify_native(&public_key, payload.message_or_digest.as_slice(), &sig)?;
        Ok(sig)
    }

    fn verify_result(&self, public_key: &PublicKey, payload: &NativeSigningPayload, signature: &SignatureBytes) -> OicResult<()> {
        self.check_scheme(public_key.scheme, "public key")?;
        self.check_scheme(payload.scheme_id, "payload")?;
        verify_native(public_key, payload.message_or_digest.as_slice(), signature)
    }
}

impl DevSingleKeyProvider {
    /// Abort a session explicitly (e.g. coordinator timeout). Its one-time
    /// record is never consumed by this provider afterwards; a retry requires
    /// a new session and a new record.
    pub fn abort_session(&self, session_id: &SigningSessionId, reason: &str) -> OicResult<()> {
        if !self.sessions.lock().contains_key(session_id) {
            return Err(OicError::new(ErrorCode::NotFound, format!("unknown session {session_id}")));
        }
        self.abort(session_id, reason);
        Ok(())
    }

    /// The one-time-state record id allocated for a session.
    pub fn session_record_id(&self, session_id: &SigningSessionId) -> OicResult<String> {
        self.sessions
            .lock()
            .get(session_id)
            .map(|s| s.record_id.clone())
            .ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("unknown session {session_id}")))
    }
}
