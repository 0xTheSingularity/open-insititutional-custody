//! # oic-signer
//!
//! The signer boundary of RFC 0001 §1.1: the only component that holds a key
//! share. It trusts nothing the coordinator says about an operation. Before
//! contributing anything it re-verifies the whole authorization from the
//! objects themselves (I1–I3), and it withholds every share-producing
//! protocol step until the authorization-state authority's *release* receipt
//! for that exact envelope and session is presented (§5.4 steps 5–6).
//!
//! ## Verification ([`Signer::verify_envelope`])
//!
//! In order, failing closed with stable [`ErrorCode`]s:
//!
//! 1. **Scope** (I2, I8): institution/environment, key id/epoch (the key must
//!    be loaded and equal to the loaded descriptor), `public_key_hash`,
//!    wallet/vault/intent/candidate/chain-profile ids, vault policy id,
//!    participant set (contains this signer, members of the key, ≥ threshold).
//! 2. **Chain profile**: an enrolled profile with the envelope's id and
//!    canonical hash; evidence scope and freshness; evidence hash.
//! 3. **Adapter**: pinned adapter version and verifier build hash, the build
//!    hash accepted by the trust roots; candidate bytes equal envelope bytes.
//! 4. **Policy** (I6): administrative quorum signatures, policy id/epoch/hash,
//!    allowlist version, intent hash.
//! 5. **Grants**: every grant signature, role, and expiry
//!    ([`oic_approval_verifier::verify_grants`]) and binding to this intent,
//!    vault, policy epoch, institution, environment.
//! 6. **Native re-derivation** (I1): the signer's own pinned adapter
//!    re-decodes `native_unsigned_bytes` against the intent (or the bounded
//!    template, §3.4), re-derives the signing payloads, and the decoded
//!    operation hash, payloads, resources, outflow and fee maxima, and every
//!    exact-candidate preview hash must match the envelope.
//! 7. **Policy kernel**: [`oic_policy_kernel::evaluate`] must return `Allow`.
//!    The signer cannot see global exposure (RFC §5.1: a quorum of signers
//!    alone cannot establish a globally consistent spending counter), so I4
//!    (reserved exposure) is enforced by the authority and proven by its
//!    receipt (step 8). The kernel run here enforces every *local* rule: hard
//!    denials, allowlists, per-operation amount and fee limits, approvals,
//!    operating windows, and freshness. Rolling limits are evaluated with zero
//!    prior exposure (see `local_exposure_view`), i.e. this single operation
//!    must fit each window on its own; an empty [`oic_policy_kernel::ExposureView`]
//!    would make every rolling-limit rule deny for lack of data.
//! 8. **Authority receipt**: reservation id derivation, the *Reserved*
//!    receipt's signature by the enrolled authority key, binding to
//!    `envelope_body_hash`, session, candidate, reservation, policy epoch,
//!    institution/environment, validity window (skew applies to `issued_at`
//!    only), and the issuance deadline.
//! 9. **Payload selection**: exactly one payload for this key under the
//!    backend's scheme.
//!
//! ## Session and message gating
//!
//! * A session id is opened at most once per signer instance, ever (A11):
//!   a retry needs a new envelope, session id, and one-time record.
//! * [`Signer::receive`] checks the message's session, key id/epoch, that the
//!   sender is in the session's participant set, that it is addressed to
//!   this signer (or broadcast), and that `from_generation` is not below the
//!   sender's known generation ([`Signer::set_peer_generation`]; for messages
//!   attributed to this signer, exactly this instance's generation).
//!   Messages with `round < share_producing_round` advance the backend
//!   immediately; later rounds are buffered (bounded) until release.
//! * [`Signer::release`] verifies the *Release* receipt, marks the session
//!   released, and feeds the buffered messages in arrival order.
//! * Any `Share`/`Complete` step is handed out only if the session is
//!   released *and* the session's one-time-state record is durably consumed
//!   and bound to `SHA-256(message_or_digest)` in the ledger; otherwise the
//!   session is aborted and `Internal` is returned.
//! * An aborted session's one-time record is burned (consumed against a
//!   sentinel hash) when the ledger allows it, so the backend can never use
//!   it afterwards.
//!
//! * Coordinator-originated messages (dev release message, FROST round-2
//!   `SigningPackage`) must be attributed to a session participant: the dev
//!   backend's message to this signer itself (with this instance's
//!   generation), FROST packages to another signing participant (the FROST
//!   backend refuses `from == self`). Their content is verified by the
//!   backend, so attribution carries no authority.
//!
//! ## Destination authentication
//!
//! The [`CounterpartyDestination`] is an administrative-quorum-signed object
//! (`OIC/DESTINATION/v1`), and the envelope commits to its hash
//! (`destination_hash`). The signer verifies the quorum with the same admin
//! roots it uses for policies and checks the hash, the intent's destination
//! id/version, the decoded recipient, any bounded template, and (through
//! exact-candidate preview hashes) what approvers saw. A coordinator or
//! console therefore cannot substitute an address under a registered
//! destination id, even under a zero-approval automated rule.
//!
//! ## Generations and rollback (A12, A13)
//!
//! [`Signer::open`] bumps and persists the generation on every open. It also
//! keeps a per-participant *fence key* in the one-time-state ledger whose
//! generation floor is raised to the current generation on every open
//! (`tombstone_generations_before`). On the next open the signer verifies
//! that the ledger still refuses allocations below the previous generation;
//! a ledger restored from before the previous open (or a fresh ledger) does
//! not, and opening fails with `RecoveryRequired`. This relies on the ledger
//! enforcing tombstone floors on allocation, as both ledgers in
//! `oic-one-time-state-ledger` do. Rolling back the generation store *and*
//! the ledger together is not detectable locally (§6.3: local disk state
//! alone does not establish freshness). [`Signer::load_key`] tombstones every
//! unconsumed record of older generations for the key.
//!
//! ## Hashes defined here
//!
//! * [`public_key_hash`] = `SHA256("OIC/PUBLIC_KEY/v1" || CanonicalEncode(PublicKey{scheme, bytes}))`.
//! * [`envelope_body_hash`] = `SHA256("OIC/AUTHORIZATION/v1" || CanonicalEncode(body))` (RFC §3.2).
//! * Abort sentinel = `SHA256("OIC/SIGNER_FENCE/v1" || CanonicalEncode(("session-abort", session_id)))`.
//! * Fence key id = `"oic-signer-fence/" || hex(SHA256("OIC/SIGNER_FENCE/v1" || CanonicalEncode(participant_id)))[..32]`.

mod finalized;
mod generation;
mod verify;

pub use finalized::*;
pub use generation::*;

use ed25519_dalek::VerifyingKey;
use oic_adapter_api::{ChainAdapter, ChainProfile};
use oic_approval_verifier::ApproverCredential;
use oic_canonical_encoding::{domain_hash, sha256};
use oic_crypto_provider::{check_topology, BackendDescriptor, CryptoProvider, OneTimeStateLedger, OneTimeStateRecord, PeerMessage, ProtocolStep};
use oic_domain_types::*;
use oic_policy_kernel::Decision;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use verify::ReceiptBinding;

/// Upper bound on buffered share-round messages per session.
pub const MAX_BUFFERED_MESSAGES: usize = 64;

/// `SHA256("OIC/PUBLIC_KEY/v1" || CanonicalEncode(public_key))` — the
/// envelope's `public_key_hash`.
pub fn public_key_hash(public_key: &PublicKey) -> OicResult<Hash32> {
    domain_hash(domains::PUBLIC_KEY, public_key)
}

/// `SHA256("OIC/AUTHORIZATION/v1" || CanonicalEncode(body))` — what the
/// authority's receipts bind as `envelope_body_hash`.
pub fn envelope_body_hash(body: &AuthorizationEnvelopeBody) -> OicResult<Hash32> {
    domain_hash(domains::AUTHORIZATION, body)
}

fn abort_sentinel(session_id: &SigningSessionId) -> OicResult<Hash32> {
    domain_hash(domains::SIGNER_FENCE, &("session-abort", session_id))
}

/// Raise this signer's rollback-protected floor named `name` to `value`.
/// The floor lives in the one-time-state ledger, which detects restore, so
/// restoring older local configuration or state cannot lower it. Fails with
/// `RecoveryRequired` when `value` is below the floor already reached.
fn ratchet_floor(ledger: &dyn OneTimeStateLedger, participant: &ParticipantId, generation: Epoch, name: &str, value: u64) -> OicResult<()> {
    let h = domain_hash(domains::SIGNER_FENCE, &(name, participant))?;
    let key = KeyId::new(format!("oic-floor/{}", &h.to_hex()[..32])).ok_or_else(|| OicError::internal("floor key id"))?;
    let probe = SigningSessionId::unchecked(format!("oic-floor-{name}-{value}-generation-{}", generation.0));
    match ledger.allocate(&key, Epoch(0), Epoch(value), &probe) {
        Ok(_) => {}
        Err(e) if e.code == ErrorCode::ResourceConflict => {
            return Err(OicError::new(
                ErrorCode::RecoveryRequired,
                format!("{name} {value} is older than one this signer already accepted (restored or replayed state)"),
            ))
        }
        Err(e) => return Err(e),
    }
    ledger.tombstone_generations_before(&key, Epoch(value))?;
    Ok(())
}

fn fence_key(participant: &ParticipantId) -> OicResult<KeyId> {
    let h = domain_hash(domains::SIGNER_FENCE, participant)?;
    KeyId::new(format!("oic-signer-fence/{}", &h.to_hex()[..32])).ok_or_else(|| OicError::internal("fence key id"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerIdentity {
    pub participant_id: ParticipantId,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
}

/// Everything the signer trusts, configured out of band (never from the coordinator).
#[derive(Clone, Debug)]
pub struct TrustRoots {
    pub authority_key_id: KeyId,
    pub authority_pubkey: VerifyingKey,
    pub admin_keys: Vec<(CredentialId, VerifyingKey)>,
    pub admin_quorum: u8,
    pub approvers: Vec<ApproverCredential>,
    /// adapter id -> accepted verifier build hashes (the signer's own adapter must be one of them)
    pub accepted_verifier_builds: BTreeMap<AdapterId, Vec<Hash32>>,
    /// Enrolled profiles; `envelope.chain_profile_hash` must match one.
    pub chain_profiles: Vec<ChainProfile>,
    /// The institution's admin-quorum-signed enrollment of asset, wallet,
    /// vault, and key descriptor hashes. The envelope's `asset_hash`,
    /// `wallet_hash`, `vault_hash`, and `key_descriptor_hash` must each be in
    /// it. The envelope hashes alone only bind the signer to what the
    /// envelope producer chose; the enrollment binds them to what the
    /// administrative quorum enrolled, so a compromised D1 coordinator cannot
    /// add a forged record. Its trust anchor is `admin_keys`, the same keys
    /// that sign destinations and policy: whoever can replace `admin_keys`
    /// can also sign a new enrollment. [`Signer::open`] verifies the quorum.
    /// `None` fails closed.
    pub enrolled_materials: Option<MaterialEnrollment>,
    pub max_clock_skew_seconds: u64,
}

/// The objects an envelope commits to, delivered alongside it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningMaterials {
    pub intent: Intent,
    pub candidate: Candidate,
    pub vault: Vault,
    pub wallet: ChainWallet,
    pub key: KeyDescriptor,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub policy: PolicyBundle,
    pub evidence: EvidenceBundle,
}

/// Result of a successful [`Signer::verify_envelope`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEnvelope {
    pub envelope_body_hash: Hash32,
    pub verified: VerifiedOperation,
    pub decision: Decision,
    pub approvers: Vec<CredentialId>,
    /// The single payload this key signs.
    pub payload: NativeSigningPayload,
}

/// Audit events. They never carry secrets, shares, or transcript payloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerEvent {
    Opened { generation: SignerGeneration },
    EnvelopeVerified { envelope_body_hash: Hash32, session: SigningSessionId },
    EnvelopeRejected { code: ErrorCode, detail: String },
    SessionOpened { session: SigningSessionId, envelope_body_hash: Hash32, record_id: Option<String> },
    Released { session: SigningSessionId, release_commit_sequence: u64 },
    ShareProduced { session: SigningSessionId, record_id: Option<String> },
    Aborted { session: SigningSessionId, reason: String },
}

pub type EventSink = Arc<dyn Fn(SignerEvent) + Send + Sync>;

struct SessionRecord {
    envelope_body_hash: Hash32,
    authorization: SessionAuthorization,
    key_id: KeyId,
    key_epoch: Epoch,
    public_key: PublicKey,
    payload: NativeSigningPayload,
    payload_hash: Hash32,
    participants: Vec<ParticipantId>,
    record: Option<OneTimeStateRecord>,
    released: bool,
    output_produced: bool,
    aborted: Option<String>,
    buffered: Vec<PeerMessage>,
}

enum SessionAuthorization {
    D1(Box<AuthorityReceiptBody>),
    D2(Box<AuthorizationEnvelopeBody>),
}

/// Ledger wrapper that records the allocations a backend makes during
/// `start_signing_session`, so the signer learns the session's record id
/// without trusting the backend to report it.
struct CapturingLedger<'a> {
    inner: &'a dyn OneTimeStateLedger,
    allocated: Mutex<Vec<OneTimeStateRecord>>,
}

impl OneTimeStateLedger for CapturingLedger<'_> {
    fn allocate(&self, key_id: &KeyId, key_epoch: Epoch, generation: Epoch, session_id: &SigningSessionId) -> OicResult<OneTimeStateRecord> {
        let r = self.inner.allocate(key_id, key_epoch, generation, session_id)?;
        self.allocated.lock().push(r.clone());
        Ok(r)
    }
    fn consume(&self, record_id: &str, message_hash: Hash32) -> OicResult<()> {
        self.inner.consume(record_id, message_hash)
    }
    fn get(&self, record_id: &str) -> OicResult<Option<OneTimeStateRecord>> {
        self.inner.get(record_id)
    }
    fn tombstone_generations_before(&self, key_id: &KeyId, generation: Epoch) -> OicResult<u64> {
        self.inner.tombstone_generations_before(key_id, generation)
    }
}

/// One participant's signer instance. See the crate docs.
pub struct Signer {
    identity: SignerIdentity,
    roots: TrustRoots,
    adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>>,
    provider: Arc<dyn CryptoProvider>,
    backend: BackendDescriptor,
    ledger: Arc<dyn OneTimeStateLedger>,
    generation: Epoch,
    keys: Mutex<BTreeMap<KeyId, KeyDescriptor>>,
    peer_generations: Mutex<BTreeMap<ParticipantId, Epoch>>,
    sessions: Mutex<BTreeMap<SigningSessionId, SessionRecord>>,
    finalized: Option<FinalizedAuthority>,
    sink: Option<EventSink>,
}

impl Signer {
    /// Open a signer instance: validate configuration, check the ledger is
    /// not older than the previous open (else `RecoveryRequired`), and bump
    /// and persist the generation (A12: a clone/restore starts a new
    /// generation).
    pub fn open(
        identity: SignerIdentity,
        roots: TrustRoots,
        adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>>,
        provider: Arc<dyn CryptoProvider>,
        ledger: Arc<dyn OneTimeStateLedger>,
        generation_store: Arc<dyn GenerationStore>,
    ) -> OicResult<Signer> {
        if roots.admin_quorum == 0 || roots.admin_keys.len() < usize::from(roots.admin_quorum) {
            return Err(OicError::invalid_request("administrative quorum must be at least 1 and satisfiable"));
        }
        if let Some(e) = &roots.enrolled_materials {
            if e.institution_id != identity.institution_id || e.environment_id != identity.environment_id {
                return Err(OicError::invalid_request("material enrollment belongs to another institution or environment"));
            }
            oic_policy_kernel::verify_material_enrollment_admin_signatures(e, &roots.admin_keys, roots.admin_quorum)?;
        }
        for (id, a) in &adapters {
            let m = a.manifest();
            if &m.adapter_id != id {
                return Err(OicError::invalid_request(format!("adapter registered as {id} reports id {}", m.adapter_id)));
            }
        }
        let backend = provider.capabilities();
        let prev = generation_store.load()?;
        let generation = match prev {
            None => Epoch(1),
            Some(p) => Epoch(p.0.checked_add(1).ok_or_else(|| OicError::internal("signer generation exhausted"))?),
        };
        let fence = fence_key(&identity.participant_id)?;
        if let Some(p) = prev.filter(|p| p.0 > 0) {
            let probe_session = SigningSessionId::unchecked(format!("oic-signer-fence-probe-{}", p.0));
            match ledger.allocate(&fence, Epoch(0), Epoch(p.0 - 1), &probe_session) {
                Ok(_) => {
                    return Err(OicError::new(
                        ErrorCode::RecoveryRequired,
                        format!("one-time-state ledger does not carry the fence of generation {p}: it is older than the last signer open (restored or replaced)"),
                    ))
                }
                Err(e) if e.code == ErrorCode::ResourceConflict => {}
                Err(e) => return Err(e),
            }
        }
        ledger.tombstone_generations_before(&fence, generation)?;
        if let Some(e) = &roots.enrolled_materials {
            // An older, still validly signed enrollment would re-enroll records a newer one revoked.
            ratchet_floor(ledger.as_ref(), &identity.participant_id, generation, "material enrollment epoch", e.enrollment_epoch.0)?;
        }
        generation_store.store(generation)?;
        Ok(Signer {
            identity,
            roots,
            adapters,
            provider,
            backend,
            ledger,
            generation,
            keys: Mutex::new(BTreeMap::new()),
            peer_generations: Mutex::new(BTreeMap::new()),
            sessions: Mutex::new(BTreeMap::new()),
            finalized: None,
            sink: None,
        })
    }

    /// Install an audit hook. Emits `Opened` immediately.
    pub fn with_event_sink(mut self, sink: EventSink) -> Self {
        sink(SignerEvent::Opened { generation: SignerGeneration(self.generation) });
        self.sink = Some(sink);
        self
    }

    fn emit(&self, events: Vec<SignerEvent>) {
        if let Some(s) = &self.sink {
            for e in events {
                s(e);
            }
        }
    }

    /// Raise the rollback-protected floor `name` to `value`; see
    /// [`ratchet_floor`]. Used by the signer domain for state kept outside
    /// the signer, such as the local halt sequence.
    pub fn ratchet_floor(&self, name: &str, value: u64) -> OicResult<()> {
        ratchet_floor(self.ledger.as_ref(), &self.identity.participant_id, self.generation, name, value)
    }

    pub fn generation(&self) -> Epoch {
        self.generation
    }

    /// The local backend's capabilities, never supplied by a network peer.
    pub fn backend(&self) -> &BackendDescriptor {
        &self.backend
    }

    /// This instance's participant identity (configured at open).
    pub fn identity(&self) -> &SignerIdentity {
        &self.identity
    }

    /// Load this participant's sealed share for a key and tombstone every
    /// unconsumed one-time record of older generations for it.
    pub fn load_key(&self, descriptor: &KeyDescriptor, sealed_share: &Bytes) -> OicResult<()> {
        let id = &self.identity;
        if descriptor.institution_id != id.institution_id || descriptor.environment_id != id.environment_id {
            return Err(OicError::scope("key belongs to another institution or environment"));
        }
        if !descriptor.participants.contains(&id.participant_id) {
            return Err(OicError::scope("this signer is not a participant of the key"));
        }
        if descriptor.backend_id != self.backend.backend_id {
            return Err(OicError::unsupported(format!(
                "key backend {} is not this signer's backend {}",
                descriptor.backend_id, self.backend.backend_id
            )));
        }
        if descriptor.scheme != self.backend.scheme || descriptor.public_key.scheme != descriptor.scheme {
            return Err(OicError::unsupported("key scheme does not match the backend scheme"));
        }
        let mut distinct = descriptor.participants.clone();
        distinct.sort();
        distinct.dedup();
        if distinct.len() != descriptor.participants.len() {
            return Err(OicError::invalid_request("key participants contain duplicates"));
        }
        check_topology(&self.backend, descriptor.participants.len(), descriptor.threshold)?;
        if let Some(existing) = self.keys.lock().get(&descriptor.key_id) {
            if existing.key_epoch > descriptor.key_epoch || (existing.key_epoch == descriptor.key_epoch && existing != descriptor) {
                return Err(OicError::new(ErrorCode::Conflict, "a different or newer descriptor for this key is already loaded"));
            }
        }
        self.provider.load_share(descriptor, &id.participant_id, sealed_share)?;
        self.ledger.tombstone_generations_before(&descriptor.key_id, self.generation)?;
        self.keys.lock().insert(descriptor.key_id.clone(), descriptor.clone());
        Ok(())
    }

    /// Independently verify an envelope against the referenced objects. See
    /// the crate docs for the check order.
    pub fn verify_envelope(&self, env: &AuthorizationEnvelope, m: &SigningMaterials, now: UnixSeconds) -> OicResult<VerifiedEnvelope> {
        match self.verify_inner(env, m, now) {
            Ok(v) => {
                self.emit(vec![SignerEvent::EnvelopeVerified {
                    envelope_body_hash: v.envelope_body_hash,
                    session: env.body.signer_session_id.clone(),
                }]);
                Ok(v)
            }
            Err(e) => {
                self.emit(vec![SignerEvent::EnvelopeRejected { code: e.code, detail: e.detail.clone() }]);
                Err(e)
            }
        }
    }

    /// Verify the envelope and start the backend protocol for its single
    /// payload. Returns the backend's first step (never a share).
    pub fn open_session(&self, env: &AuthorizationEnvelope, m: &SigningMaterials, now: UnixSeconds) -> OicResult<ProtocolStep> {
        let v = self.verify_envelope(env, m, now)?;
        self.open_verified_session(&env.body, m, v, SessionAuthorization::D1(Box::new(env.authorization_state_receipt.body.clone())))
    }

    fn open_verified_session(
        &self,
        b: &AuthorizationEnvelopeBody,
        m: &SigningMaterials,
        v: VerifiedEnvelope,
        authorization: SessionAuthorization,
    ) -> OicResult<ProtocolStep> {
        let session_id = &b.signer_session_id;
        let mut events = Vec::new();
        let result = (|| {
            let mut sessions = self.sessions.lock();
            if sessions.contains_key(session_id) {
                return Err(OicError::new(ErrorCode::Conflict, format!("session {session_id} was already opened; a retry needs a fresh session")));
            }
            let capture = CapturingLedger { inner: &*self.ledger, allocated: Mutex::new(Vec::new()) };
            let started = self.provider.start_signing_session(session_id, &b.key_id, &v.payload, &b.participant_set, &capture, self.generation);
            let allocated = capture.allocated.into_inner();
            let step = match started {
                Ok(s) => s,
                Err(e) => {
                    for r in &allocated {
                        self.burn(&r.record_id, session_id);
                    }
                    return Err(e);
                }
            };
            let record = match (self.backend.has_one_time_state, allocated.as_slice()) {
                (false, []) => None,
                (true, [r])
                    if r.session_id.as_ref() == Some(session_id)
                        && r.key_id == b.key_id
                        && r.key_epoch == b.key_epoch
                        && r.signer_generation == self.generation
                        && !r.consumed =>
                {
                    Some(r.clone())
                }
                _ => {
                    for r in &allocated {
                        self.burn(&r.record_id, session_id);
                    }
                    return Err(OicError::internal(
                        "backend did not allocate exactly one one-time record bound to this session, key, and generation",
                    ));
                }
            };
            let mut rec = SessionRecord {
                envelope_body_hash: v.envelope_body_hash,
                authorization,
                key_id: b.key_id.clone(),
                key_epoch: b.key_epoch,
                public_key: m.key.public_key.clone(),
                payload_hash: sha256(v.payload.message_or_digest.as_slice()),
                payload: v.payload.clone(),
                participants: b.participant_set.clone(),
                record,
                released: false,
                output_produced: false,
                aborted: None,
                buffered: Vec::new(),
            };
            events.push(SignerEvent::SessionOpened {
                session: session_id.clone(),
                envelope_body_hash: v.envelope_body_hash,
                record_id: rec.record.as_ref().map(|r| r.record_id.clone()),
            });
            let out = self.gate(session_id, &mut rec, Ok(step), &mut events);
            sessions.insert(session_id.clone(), rec);
            out
        })();
        self.emit(events);
        result
    }

    /// Record a peer's current signer generation (monotonic).
    pub fn set_peer_generation(&self, participant: &ParticipantId, generation: Epoch) -> OicResult<()> {
        let mut g = self.peer_generations.lock();
        let cur = g.entry(participant.clone()).or_default();
        if generation < *cur {
            return Err(OicError::new(
                ErrorCode::Conflict,
                format!("peer generation for {participant} cannot move backwards from {cur} to {generation}"),
            ));
        }
        *cur = generation;
        Ok(())
    }

    fn check_message_scope(&self, rec: &SessionRecord, session_id: &SigningSessionId, msg: &PeerMessage) -> OicResult<()> {
        if &msg.session_id != session_id {
            return Err(OicError::scope("peer message is for a different session"));
        }
        if msg.key_id != rec.key_id || msg.key_epoch != rec.key_epoch {
            return Err(OicError::scope("peer message is for a different key or key epoch"));
        }
        if !rec.participants.contains(&msg.from) {
            return Err(OicError::scope(format!("{} is not in the session participant set", msg.from)));
        }
        if msg.to.as_ref().is_some_and(|to| *to != self.identity.participant_id) {
            return Err(OicError::scope("peer message is addressed to another participant"));
        }
        if msg.from == self.identity.participant_id {
            if msg.from_generation != self.generation {
                return Err(OicError::scope(format!(
                    "message attributed to this signer carries generation {} but this instance is generation {}",
                    msg.from_generation, self.generation
                )));
            }
        } else {
            let floor = self.peer_generations.lock().get(&msg.from).copied().unwrap_or_default();
            if msg.from_generation < floor {
                return Err(OicError::scope(format!(
                    "message from {} has stale generation {} below known generation {floor}",
                    msg.from, msg.from_generation
                )));
            }
        }
        Ok(())
    }

    /// Accept one peer/coordinator message. Pre-share rounds advance the
    /// backend; share-producing rounds are buffered until release.
    pub fn receive(&self, session_id: &SigningSessionId, msg: &PeerMessage) -> OicResult<ProtocolStep> {
        let mut events = Vec::new();
        let result = (|| {
            let mut sessions = self.sessions.lock();
            let rec = sessions.get_mut(session_id).ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("unknown session {session_id}")))?;
            Self::check_live(rec)?;
            self.check_message_scope(rec, session_id, msg)?;
            if msg.round < self.backend.share_producing_round {
                let r = self.provider.advance_protocol(session_id, msg, &*self.ledger);
                return self.gate(session_id, rec, r, &mut events);
            }
            if rec.released {
                let r = self.provider.advance_protocol(session_id, msg, &*self.ledger);
                return self.gate_share_round(session_id, rec, r, &mut events);
            }
            if rec.buffered.len() >= MAX_BUFFERED_MESSAGES {
                return Err(OicError::invalid_request("too many buffered share-round messages for this session"));
            }
            rec.buffered.push(msg.clone());
            Ok(ProtocolStep::Waiting)
        })();
        self.emit(events);
        result
    }

    fn check_live(rec: &SessionRecord) -> OicResult<()> {
        if let Some(r) = &rec.aborted {
            return Err(OicError::new(ErrorCode::Conflict, format!("session aborted: {r}")));
        }
        if rec.output_produced {
            return Err(OicError::new(ErrorCode::Conflict, "session already produced its output"));
        }
        Ok(())
    }

    /// Present the authority's *Release* receipt; feeds buffered messages.
    pub fn release(&self, session_id: &SigningSessionId, release_receipt: &AuthorityReceipt, now: UnixSeconds) -> OicResult<Vec<ProtocolStep>> {
        let mut events = Vec::new();
        let result = (|| {
            let mut sessions = self.sessions.lock();
            let rec = sessions.get_mut(session_id).ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("unknown session {session_id}")))?;
            Self::check_live(rec)?;
            if rec.released {
                return Err(OicError::new(ErrorCode::Conflict, "session already released"));
            }
            let SessionAuthorization::D1(reserved) = &rec.authorization else {
                return Err(OicError::new(ErrorCode::SessionRejected, "D1 receipt cannot release a D2 session"));
            };
            self.check_receipt(
                release_receipt,
                &ReceiptBinding {
                    kind: ReceiptKind::Release,
                    envelope_body_hash: rec.envelope_body_hash,
                    signer_session_id: session_id,
                    candidate_id: &reserved.candidate_id,
                    candidate_revision: reserved.candidate_revision,
                    reservation_id: &reserved.reservation_id,
                    reservation_version: reserved.reservation_version,
                    policy_epoch: reserved.policy_epoch,
                    // Checked against this signer's own derivation at open.
                    intent_hash: reserved.intent_hash,
                    rule_id: &reserved.rule_id,
                    claims_hash: reserved.claims_hash,
                },
                now,
            )?;
            if release_receipt.body.freeze_epoch != reserved.freeze_epoch {
                return Err(OicError::new(ErrorCode::Frozen, "freeze epoch changed between reservation and release"));
            }
            self.release_buffered(session_id, rec, release_receipt.body.commit_sequence, &mut events)
        })();
        self.emit(events);
        result
    }

    fn release_buffered(
        &self,
        session_id: &SigningSessionId,
        rec: &mut SessionRecord,
        sequence: u64,
        events: &mut Vec<SignerEvent>,
    ) -> OicResult<Vec<ProtocolStep>> {
        rec.released = true;
        events.push(SignerEvent::Released { session: session_id.clone(), release_commit_sequence: sequence });
        let buffered = std::mem::take(&mut rec.buffered);
        let mut steps = Vec::with_capacity(buffered.len());
        for message in &buffered {
            if rec.aborted.is_some() || rec.output_produced {
                break;
            }
            let result = self.provider.advance_protocol(session_id, message, &*self.ledger);
            steps.push(self.gate_share_round(session_id, rec, result, events)?);
        }
        Ok(steps)
    }

    /// Share-round advance: any backend error leaves the one-time state in an
    /// uncertain position, so the session is aborted.
    fn gate_share_round(
        &self,
        session_id: &SigningSessionId,
        rec: &mut SessionRecord,
        r: OicResult<ProtocolStep>,
        events: &mut Vec<SignerEvent>,
    ) -> OicResult<ProtocolStep> {
        if let Err(e) = &r {
            self.abort_record(session_id, rec, format!("backend error in share round: {}", e.detail), events);
        }
        self.gate(session_id, rec, r, events)
    }

    /// Output gate: a share or signature leaves only if the session is
    /// released and its one-time record is durably consumed for this payload.
    fn gate(
        &self,
        session_id: &SigningSessionId,
        rec: &mut SessionRecord,
        r: OicResult<ProtocolStep>,
        events: &mut Vec<SignerEvent>,
    ) -> OicResult<ProtocolStep> {
        let step = r?;
        match &step {
            ProtocolStep::Share(_) | ProtocolStep::Complete(_) => {
                if !rec.released {
                    self.abort_record(session_id, rec, "backend produced output before release".into(), events);
                    return Err(OicError::internal("backend produced a share before the release receipt; session aborted"));
                }
                if let Some(record) = &rec.record {
                    let current = self.ledger.get(&record.record_id);
                    let ok = matches!(&current, Ok(Some(r)) if r.consumed && r.bound_message_hash == Some(rec.payload_hash));
                    if !ok {
                        self.abort_record(session_id, rec, "one-time record not consumed for this payload".into(), events);
                        return Err(OicError::internal(
                            "backend output without a durably consumed one-time record; session aborted, output withheld",
                        ));
                    }
                }
                rec.output_produced = true;
                events.push(SignerEvent::ShareProduced { session: session_id.clone(), record_id: rec.record.as_ref().map(|r| r.record_id.clone()) });
                Ok(step)
            }
            ProtocolStep::Aborted(reason) => {
                self.abort_record(session_id, rec, format!("backend aborted: {reason}"), events);
                Ok(step)
            }
            ProtocolStep::Send(_) | ProtocolStep::Waiting => Ok(step),
        }
    }

    fn burn(&self, record_id: &str, session_id: &SigningSessionId) {
        // Best effort: an already consumed or tombstoned record cannot be used
        // by the backend either; a failing ledger is reported by the caller.
        if let Ok(h) = abort_sentinel(session_id) {
            let _ = self.ledger.consume(record_id, h);
        }
    }

    fn abort_record(&self, session_id: &SigningSessionId, rec: &mut SessionRecord, reason: String, events: &mut Vec<SignerEvent>) {
        if rec.aborted.is_some() {
            return;
        }
        if let Some(r) = &rec.record {
            if !rec.output_produced {
                self.burn(&r.record_id, session_id);
            }
        }
        rec.buffered.clear();
        rec.aborted = Some(reason.clone());
        events.push(SignerEvent::Aborted { session: session_id.clone(), reason });
    }

    /// Aggregate shares (public operation) and verify the result natively
    /// against the key's public key and the session payload.
    pub fn aggregate(&self, session_id: &SigningSessionId, shares: &[(ParticipantId, Bytes)]) -> OicResult<SignatureBytes> {
        let (public_key, payload) = {
            let sessions = self.sessions.lock();
            let rec = sessions.get(session_id).ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("unknown session {session_id}")))?;
            if let Some(r) = &rec.aborted {
                return Err(OicError::new(ErrorCode::Conflict, format!("session aborted: {r}")));
            }
            if !rec.released {
                return Err(OicError::new(ErrorCode::Conflict, "session not released"));
            }
            for (p, _) in shares {
                if !rec.participants.contains(p) {
                    return Err(OicError::scope(format!("share from {p}, who is not in the session participant set")));
                }
            }
            (rec.public_key.clone(), rec.payload.clone())
        };
        let sig = self.provider.aggregate(session_id, shares)?;
        if sig.scheme != payload.scheme_id {
            return Err(OicError::invalid_signature("aggregated signature scheme differs from the payload scheme"));
        }
        self.provider.verify_result(&public_key, &payload, &sig)?;
        Ok(sig)
    }

    /// Abort a session: it never produces output afterwards and its one-time
    /// record is burned. Idempotent.
    pub fn abort(&self, session_id: &SigningSessionId) -> OicResult<()> {
        let mut events = Vec::new();
        {
            let mut sessions = self.sessions.lock();
            let rec = sessions.get_mut(session_id).ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("unknown session {session_id}")))?;
            self.abort_record(session_id, rec, "aborted by caller".into(), &mut events);
        }
        self.emit(events);
        Ok(())
    }
}
