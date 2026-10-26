//! Signer-core owns participant authentication keys and chain shares. The net
//! process gets only named-recipient MPC frames and release-gated public results.
//! Gateway requests cannot supply the core clock or sign arbitrary messages.

pub mod ipc;
pub mod remote;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use oic_audit::{AuditLog, FileAuditLog};
use oic_authorization_state::Clock;
use oic_canonical_encoding::{canonical_bytes, domain_hash, from_canonical_bytes, sha256};
use oic_crypto_provider::{PeerMessage, ProtocolStep};
use oic_domain_types::*;
use oic_membership::{roster_hash, validate_roster, AdminTrust, CommitteeKind, Role, SignedRoster};
use oic_peer_wire::{ExpectedPeerMessage, FrameKind, MessageScope, SessionControl, SessionReply, SessionResult, SignedPeerMessage, MAX_BODY_LEN};
use oic_replicated_authority::VerifiedLog;
use oic_signer::Signer;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Write, path::PathBuf, sync::Arc};

const MAX_SESSIONS: usize = 128;
const HALT_DOMAIN: &str = "OIC/NODE_HALT/v1";

pub struct CoreConfig {
    pub node_id: NodeId,
    pub roster: SignedRoster,
    pub previous_roster: Option<SignedRoster>,
    pub admins: AdminTrust,
    pub committed_roster_hash: Hash32,
    pub halt_state_path: PathBuf,
    /// Independent operator/witness floor; local disk alone cannot detect rollback.
    pub minimum_halt_sequence: u64,
    pub operator_key: VerifyingKey,
    /// Dedicated-key, fsynced evidence journal, opened against a witness floor.
    pub audit: Arc<FileAuditLog>,
}

/// These bytes have exactly one permitted recipient. No general serde/debug.
pub struct Outbound {
    pub to: NodeId,
    pub frame: Vec<u8>,
}

struct NetworkSession {
    owner: NodeId,
    envelope_hash: Hash32,
    policy_epoch: Epoch,
    key_id: KeyId,
    key_epoch: Epoch,
    backend: String,
    participants: Vec<ParticipantId>,
    payload: NativeSigningPayload,
    deadline: UnixSeconds,
    commitments: BTreeMap<ParticipantId, Bytes>,
    received: BTreeMap<(ParticipantId, u16), Hash32>,
    package: Option<Bytes>,
    buffered_package: bool,
    outcome: Option<SessionResult>,
    outbound: Vec<Outbound>,
}

struct HaltState {
    institution_id: InstitutionId,
    environment_id: EnvironmentId,
    node_id: NodeId,
    sequence: u64,
    halted: bool,
}

struct State {
    halt: HaltState,
    sessions: BTreeMap<SigningSessionId, NetworkSession>,
    /// Refused session opens per gateway since start; journaled at powers
    /// of two so a misbehaving gateway cannot fill the journal.
    rejected_opens: BTreeMap<NodeId, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HaltBody {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub node_id: NodeId,
    pub roster_epoch: u64,
    pub sequence: u64,
    pub halted: bool,
    pub issued_at: UnixSeconds,
    pub expires_at: UnixSeconds,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedHalt {
    pub body: HaltBody,
    pub signature: SignatureBytes,
}

pub fn halt_hash(body: &HaltBody) -> OicResult<Hash32> {
    domain_hash(HALT_DOMAIN, body)
}

pub struct SignerCore {
    signer: Arc<Signer>,
    config: CoreConfig,
    participant_key: SigningKey,
    scope: MessageScope,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
    finalized_log: Option<tokio::sync::watch::Receiver<Option<VerifiedLog>>>,
}

fn rejected(code: ErrorCode) -> OicError {
    OicError::new(code, "signer-core request rejected")
}

impl SignerCore {
    pub fn open(config: CoreConfig, signer: Arc<Signer>, participant_key: SigningKey, clock: Arc<dyn Clock>) -> OicResult<Self> {
        let identity = signer.identity();
        validate_roster(
            &config.roster,
            &config.admins,
            &identity.institution_id,
            &identity.environment_id,
            config.previous_roster.as_ref(),
            clock.now(),
            config.committed_roster_hash,
        )?;
        let node = config.roster.node(&config.node_id).ok_or_else(|| rejected(ErrorCode::PeerNotAdmitted))?;
        let key = node.participant_keys.get(&identity.participant_id).ok_or_else(|| rejected(ErrorCode::PeerNotAdmitted))?;
        if !node.roles.contains(&Role::Signer)
            || node.signer_instance_generation != signer.generation()
            || key.bytes.as_slice() != participant_key.verifying_key().as_bytes()
            || key.scheme != SchemeId::Ed25519Pure
        {
            return Err(rejected(ErrorCode::StaleGeneration));
        }
        let audit_key = config.audit.verifying_key();
        if audit_key == config.operator_key
            || [&audit_key, &config.operator_key].into_iter().any(|key| {
                config.roster.body.nodes.iter().any(|n| {
                    n.transport_key.bytes.as_slice() == key.as_bytes()
                        || n.consensus_key.as_ref().is_some_and(|k| k.bytes.as_slice() == key.as_bytes())
                        || n.attestation_key.as_ref().is_some_and(|k| k.bytes.as_slice() == key.as_bytes())
                        || n.participant_keys.values().any(|k| k.bytes.as_slice() == key.as_bytes())
                }) || config.admins.credentials.values().any(|k| k.bytes.as_slice() == key.as_bytes())
            })
        {
            return Err(rejected(ErrorCode::InvalidRequest));
        }
        let scope = MessageScope {
            institution_id: identity.institution_id.clone(),
            environment_id: identity.environment_id.clone(),
            roster_epoch: config.roster.body.roster_epoch,
            roster_hash: roster_hash(&config.roster.body)?,
        };
        let halt = match std::fs::read(&config.halt_state_path) {
            Ok(bytes) => {
                let command = from_canonical_bytes::<SignedHalt>(&bytes).map_err(|_| rejected(ErrorCode::RecoveryRequired))?;
                let signature = Signature::from_slice(command.signature.bytes.as_slice()).map_err(|_| rejected(ErrorCode::RecoveryRequired))?;
                config
                    .operator_key
                    .verify_strict(halt_hash(&command.body)?.as_ref(), &signature)
                    .map_err(|_| rejected(ErrorCode::RecoveryRequired))?;
                if command.signature.scheme != SchemeId::Ed25519Pure || command.body.sequence < config.minimum_halt_sequence {
                    return Err(rejected(ErrorCode::RecoveryRequired));
                }
                HaltState {
                    institution_id: command.body.institution_id,
                    environment_id: command.body.environment_id,
                    node_id: command.body.node_id,
                    sequence: command.body.sequence,
                    halted: command.body.halted,
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && config.minimum_halt_sequence == 0 => HaltState {
                institution_id: identity.institution_id.clone(),
                environment_id: identity.environment_id.clone(),
                node_id: config.node_id.clone(),
                sequence: 0,
                halted: false,
            },
            Err(_) => return Err(rejected(ErrorCode::RecoveryRequired)),
        };
        if halt.institution_id != identity.institution_id || halt.environment_id != identity.environment_id || halt.node_id != config.node_id {
            return Err(rejected(ErrorCode::RecoveryRequired));
        }
        // A restored older halt file (for example an unhalt at a lower
        // sequence) must not lower the halt sequence this node reached.
        signer.ratchet_floor("halt sequence", halt.sequence).map_err(|_| rejected(ErrorCode::RecoveryRequired))?;
        let core =
            Self { signer, config, participant_key, scope, clock, state: Mutex::new(State { halt, sessions: BTreeMap::new(), rejected_opens: BTreeMap::new() }), finalized_log: None };
        core.journal("node.roster_applied", BTreeMap::from([("roster".into(), core.scope.roster_hash)]), Epoch(0))?;
        Ok(core)
    }

    /// The receiver comes from the core's own keyless follower, not IPC or a
    /// gateway. It carries a non-deserializable capability only after sync.
    pub fn with_finalized_log(mut self, log: tokio::sync::watch::Receiver<Option<VerifiedLog>>) -> OicResult<Self> {
        let anchor = self.signer.finalized_anchor().ok_or_else(|| rejected(ErrorCode::InvalidRequest))?;
        if self.finalized_log.is_some() || !self.state.lock().sessions.is_empty() || anchor.roster != self.scope.roster_hash {
            return Err(rejected(ErrorCode::ScopeMismatch));
        }
        self.finalized_log = Some(log);
        Ok(self)
    }

    fn verified_log(&self, policy_epoch: Epoch) -> OicResult<VerifiedLog> {
        let receiver = self.finalized_log.as_ref().ok_or_else(|| rejected(ErrorCode::StaleEvidence))?;
        if receiver.has_changed().is_err() {
            return Err(rejected(ErrorCode::RecoveryRequired));
        }
        let log = receiver.borrow().clone().ok_or_else(|| rejected(ErrorCode::StaleEvidence))?;
        if Some(log.anchor()) != self.signer.finalized_anchor() {
            return Err(rejected(ErrorCode::ScopeMismatch));
        }
        // Retain the exact source floor in the existing fsynced, independently
        // witnessed evidence journal before any signing state can advance.
        self.journal(
            "authority.finalized",
            BTreeMap::from([
                ("block".into(), log.floor().digest),
                ("floor".into(), domain_hash("OIC/FINALIZED_FLOOR/v1", &(log.floor().height, log.floor().digest))?),
            ]),
            policy_epoch,
        )?;
        Ok(log)
    }

    pub fn node_id(&self) -> &NodeId {
        &self.config.node_id
    }

    fn journal(&self, action: &str, commitments: BTreeMap<String, Hash32>, epoch: Epoch) -> OicResult<()> {
        self.config
            .audit
            .append(self.config.node_id.as_str(), action, commitments, epoch, "")
            .map(|_| ())
            .map_err(|_| rejected(ErrorCode::RecoveryRequired))
    }

    /// Local domain-operator authorization; never depends on network ordering.
    pub fn halt(&self, command: &SignedHalt) -> OicResult<()> {
        let mut state = self.state.lock();
        let b = &command.body;
        let now = self.clock.now();
        if b.institution_id != self.scope.institution_id
            || b.environment_id != self.scope.environment_id
            || b.node_id != self.config.node_id
            || b.roster_epoch != self.scope.roster_epoch
            || Some(b.sequence) != state.halt.sequence.checked_add(1)
            || b.issued_at > now
            || b.expires_at <= now
            || b.expires_at.0.saturating_sub(b.issued_at.0) > 120
            || command.signature.scheme != SchemeId::Ed25519Pure
        {
            return Err(rejected(ErrorCode::InvalidRequest));
        }
        let signature = Signature::from_slice(command.signature.bytes.as_slice()).map_err(|_| rejected(ErrorCode::InvalidSignature))?;
        self.config.operator_key.verify_strict(halt_hash(b)?.as_ref(), &signature).map_err(|_| rejected(ErrorCode::InvalidSignature))?;
        let next = HaltState {
            institution_id: b.institution_id.clone(),
            environment_id: b.environment_id.clone(),
            node_id: b.node_id.clone(),
            sequence: b.sequence,
            halted: b.halted,
        };
        // A storage failure must never leave the process contributing. For an
        // unhalt, remain stopped until the signed command is durably committed.
        state.halt.halted = true;
        for (id, session) in &mut state.sessions {
            self.signer.abort(id)?;
            session.outbound.clear();
            session.outcome = Some(SessionResult::Aborted);
        }
        let parent = self.config.halt_state_path.parent().ok_or_else(|| rejected(ErrorCode::RecoveryRequired))?;
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|_| rejected(ErrorCode::RecoveryRequired))?;
        file.write_all(&canonical_bytes(command)?).and_then(|_| file.as_file().sync_all()).map_err(|_| rejected(ErrorCode::RecoveryRequired))?;
        file.persist(&self.config.halt_state_path).map_err(|_| rejected(ErrorCode::RecoveryRequired))?;
        std::fs::File::open(parent).and_then(|f| f.sync_all()).map_err(|_| rejected(ErrorCode::RecoveryRequired))?;
        // Raised only after the command is durable, so a crash in between
        // leaves the file at or above the floor.
        self.signer.ratchet_floor("halt sequence", b.sequence).map_err(|_| rejected(ErrorCode::RecoveryRequired))?;
        self.journal(if b.halted { "node.halted" } else { "node.unhalted" }, BTreeMap::from([("halt_command".into(), halt_hash(b)?)]), Epoch(0))?;
        state.halt = next;
        Ok(())
    }

    pub fn control(&self, from: &NodeId, control: &SessionControl) -> SessionReply {
        let request_id = match control {
            SessionControl::Open { request_id, .. }
            | SessionControl::Release { request_id, .. }
            | SessionControl::OpenFinalized { request_id, .. }
            | SessionControl::ReleaseFinalized { request_id, .. }
            | SessionControl::Aggregate { request_id, .. }
            | SessionControl::Abort { request_id, .. }
            | SessionControl::Status { request_id, .. } => *request_id,
        };
        let result = (|| {
            if !self.config.roster.allows(10, from, &self.config.node_id)
                || !self.config.roster.node(from).is_some_and(|n| n.roles.contains(&Role::Gateway))
            {
                return Err(rejected(ErrorCode::PeerNotAdmitted));
            }
            let mut state = self.state.lock();
            if state.halt.halted {
                return Err(rejected(ErrorCode::NodeHalted));
            }
            match control {
                SessionControl::Open { .. } | SessionControl::Release { .. } if self.signer.finalized_anchor().is_some() => {
                    return Err(rejected(ErrorCode::SessionRejected));
                }
                SessionControl::OpenFinalized { .. } | SessionControl::ReleaseFinalized { .. } if self.signer.finalized_anchor().is_none() => {
                    return Err(rejected(ErrorCode::SessionRejected));
                }
                _ => {}
            }
            let requested_session = match control {
                SessionControl::Open { .. } | SessionControl::OpenFinalized { .. } => None,
                SessionControl::Status { session_id, .. }
                | SessionControl::Release { session_id, .. }
                | SessionControl::ReleaseFinalized { session_id, .. }
                | SessionControl::Aggregate { session_id, .. }
                | SessionControl::Abort { session_id, .. } => Some(session_id),
            };
            if requested_session.and_then(|id| state.sessions.get(id)).is_some_and(|s| &s.owner != from) {
                return Err(rejected(ErrorCode::PeerNotAdmitted));
            }
            match control {
                SessionControl::Open { .. } | SessionControl::OpenFinalized { .. } => {
                    let (body, materials, legacy) = match control {
                        SessionControl::Open { envelope, materials, .. } => (&envelope.body, materials, Some(envelope)),
                        SessionControl::OpenFinalized { body, materials, .. } => (body, materials, None),
                        _ => unreachable!(),
                    };
                    let id = &body.signer_session_id;
                    if state.sessions.contains_key(id) {
                        return Err(rejected(ErrorCode::SessionRejected));
                    }
                    if state.sessions.len() >= MAX_SESSIONS {
                        return Err(rejected(ErrorCode::Conflict));
                    }
                    if body.participant_set.len() > 16 {
                        return Err(rejected(ErrorCode::UnsupportedCapability));
                    }
                    let me = &self.signer.identity().participant_id;
                    let node = self.config.roster.node(&self.config.node_id).unwrap();
                    if !node.approved_build_hashes.contains(&body.verifier_build_hash) {
                        return Err(rejected(ErrorCode::SessionRejected));
                    }
                    let committee = self
                        .config
                        .roster
                        .body
                        .committees
                        .iter()
                        .find(|c| {
                            matches!(&c.kind,
                        CommitteeKind::Key { key_id, key_epoch, .. } if key_id == &materials.key.key_id && *key_epoch == materials.key.key_epoch)
                        })
                        .ok_or_else(|| rejected(ErrorCode::PeerNotAdmitted))?;
                    let CommitteeKind::Key { participants, backend, .. } = &committee.kind else { unreachable!() };
                    if participants != &materials.key.participants
                        || committee.threshold != materials.key.threshold
                        || backend != self.signer.backend()
                    {
                        return Err(rejected(ErrorCode::ScopeMismatch));
                    }
                    if backend.backend_id != oic_crypto_provider_dev::BACKEND_ID
                        && backend.backend_id != oic_crypto_provider_frost_ed25519::BACKEND_ID
                    {
                        return Err(rejected(ErrorCode::UnsupportedCapability));
                    }
                    for participant in &body.participant_set {
                        let peer = self.config.roster.participant(participant).ok_or_else(|| rejected(ErrorCode::PeerNotAdmitted))?;
                        self.signer.set_peer_generation(participant, peer.signer_instance_generation)?;
                    }
                    let (verified, step, evidence_kind, evidence_hash) = if let Some(envelope) = legacy {
                        let verified = self.signer.verify_envelope(envelope, materials, self.clock.now())?;
                        let step = self.signer.open_session(envelope, materials, self.clock.now())?;
                        (verified, step, "reservation_receipt", sha256(&canonical_bytes(&envelope.authorization_state_receipt)?))
                    } else {
                        let log = self.verified_log(body.policy_epoch)?;
                        let verified = self.signer.verify_finalized_envelope(body, materials, &log, self.clock.now())?;
                        let step = self.signer.open_finalized_session(body, materials, &log, self.clock.now())?;
                        (verified, step, "finalized_block", log.floor().digest)
                    };
                    let mut session = NetworkSession {
                        owner: from.clone(),
                        envelope_hash: verified.envelope_body_hash,
                        policy_epoch: body.policy_epoch,
                        key_id: materials.key.key_id.clone(),
                        key_epoch: materials.key.key_epoch,
                        backend: materials.key.backend_id.clone(),
                        participants: body.participant_set.clone(),
                        payload: verified.payload,
                        deadline: body.issuance_deadline,
                        commitments: BTreeMap::new(),
                        received: BTreeMap::new(),
                        package: None,
                        buffered_package: false,
                        outcome: None,
                        outbound: vec![],
                    };
                    let started = (|| {
                        match step {
                            ProtocolStep::Send(messages) => {
                                for message in messages {
                                    if message.from != *me || message.round != 1 || message.sequence != 1 {
                                        return Err(rejected(ErrorCode::SessionRejected));
                                    }
                                    session.commitments.insert(me.clone(), message.payload.clone());
                                    self.fanout(&mut session, message)?;
                                }
                            }
                            ProtocolStep::Waiting if session.backend == oic_crypto_provider_dev::BACKEND_ID => {}
                            _ => return Err(rejected(ErrorCode::SessionRejected)),
                        };
                        self.journal(
                            "signer.session_opened",
                            BTreeMap::from([("envelope".into(), session.envelope_hash), (evidence_kind.into(), evidence_hash)]),
                            session.policy_epoch,
                        )?;
                        Ok(())
                    })();
                    if let Err(error) = started {
                        self.signer.abort(id)?;
                        return Err(error);
                    }
                    let ready = session.backend == oic_crypto_provider_dev::BACKEND_ID;
                    state.sessions.insert(id.clone(), session);
                    Ok(if ready { SessionResult::Accepted } else { SessionResult::Waiting })
                }
                SessionControl::Status { session_id, .. } => {
                    let session = state.sessions.get_mut(session_id).ok_or_else(|| rejected(ErrorCode::NotFound))?;
                    self.check_deadline(session_id, session)?;
                    Ok(session.outcome.clone().unwrap_or(if session.buffered_package || session.backend == oic_crypto_provider_dev::BACKEND_ID {
                        SessionResult::Accepted
                    } else {
                        SessionResult::Waiting
                    }))
                }
                SessionControl::Release { session_id, .. } | SessionControl::ReleaseFinalized { session_id, .. } => {
                    let session = state.sessions.get_mut(session_id).ok_or_else(|| rejected(ErrorCode::NotFound))?;
                    self.check_deadline(session_id, session)?;
                    if let Some(outcome) = &session.outcome {
                        return Ok(outcome.clone());
                    }
                    if session.backend == oic_crypto_provider_dev::BACKEND_ID && !session.buffered_package {
                        let message = PeerMessage {
                            session_id: session_id.clone(),
                            key_id: session.key_id.clone(),
                            key_epoch: session.key_epoch,
                            from: self.signer.identity().participant_id.clone(),
                            from_generation: self.signer.generation(),
                            to: Some(self.signer.identity().participant_id.clone()),
                            round: 1,
                            sequence: 1,
                            protocol_version: oic_crypto_provider_dev::PROTOCOL_VERSION.into(),
                            payload: Bytes(sha256(session.payload.message_or_digest.as_slice()).0.to_vec()),
                        };
                        self.signer.receive(session_id, &message)?;
                        session.buffered_package = true;
                    } else if !session.buffered_package {
                        return Err(rejected(ErrorCode::StaleEvidence));
                    }
                    let (steps, evidence_kind, evidence_hash) = match control {
                        SessionControl::Release { receipt, .. } => {
                            (self.signer.release(session_id, receipt, self.clock.now())?, "release_receipt", sha256(&canonical_bytes(receipt)?))
                        }
                        SessionControl::ReleaseFinalized { .. } => {
                            let log = self.verified_log(session.policy_epoch)?;
                            (self.signer.release_finalized(session_id, &log, self.clock.now())?, "finalized_block", log.floor().digest)
                        }
                        _ => unreachable!(),
                    };
                    for step in steps {
                        Self::outcome(session, step)?;
                    }
                    if let Err(error) = self.journal(
                        "signer.share_released",
                        BTreeMap::from([("envelope".into(), session.envelope_hash), (evidence_kind.into(), evidence_hash)]),
                        session.policy_epoch,
                    ) {
                        self.signer.abort(session_id)?;
                        session.outcome = Some(SessionResult::Aborted);
                        session.outbound.clear();
                        state.halt.halted = true;
                        return Err(error);
                    }
                    session.outcome.clone().ok_or_else(|| rejected(ErrorCode::IssuanceUncertain))
                }
                SessionControl::Aggregate { session_id, shares, .. } => {
                    let session = state.sessions.get_mut(session_id).ok_or_else(|| rejected(ErrorCode::NotFound))?;
                    self.check_deadline(session_id, session)?;
                    if !matches!(session.outcome, Some(SessionResult::Share(_)) | Some(SessionResult::Complete(_))) {
                        return Err(rejected(ErrorCode::SessionRejected));
                    }
                    Ok(SessionResult::Complete(self.signer.aggregate(session_id, shares)?))
                }
                SessionControl::Abort { session_id, .. } => {
                    let session = state.sessions.get_mut(session_id).ok_or_else(|| rejected(ErrorCode::NotFound))?;
                    self.signer.abort(session_id)?;
                    session.outcome = Some(SessionResult::Aborted);
                    session.outbound.clear();
                    Ok(SessionResult::Aborted)
                }
            }
        })();
        // RFC 0003 §9: a refused session open is journaled with its reason
        // code. Status and other controls are not, so polling cannot fill
        // the journal.
        if let Err(e) = &result {
            let session = match control {
                SessionControl::Open { envelope, .. } => Some(&envelope.body.signer_session_id),
                SessionControl::OpenFinalized { body, .. } => Some(&body.signer_session_id),
                _ => None,
            };
            if let Some(session) = session {
                let count = {
                    let mut state = self.state.lock();
                    let n = state.rejected_opens.entry(from.clone()).or_insert(0);
                    *n += 1;
                    *n
                };
                if count.is_power_of_two() {
                    // The session id is attacker-chosen: commit to it by hash,
                    // never as journal text. `from` is a roster-admitted node.
                    let session_hash = oic_canonical_encoding::sha256(session.as_str().as_bytes());
                    let _ = self.config.audit.append(
                        self.config.node_id.as_str(),
                        "signer.session_rejected",
                        BTreeMap::from([("session".into(), session_hash)]),
                        Epoch(0),
                        &format!("from={from} code={:?} refused_from_sender={count}", e.code),
                    );
                }
            }
        }
        // Do not send detailed adapter/backend inputs back to a net process.
        SessionReply { request_id, result: result.map_err(|e| rejected(e.code)) }
    }

    fn check_deadline(&self, id: &SigningSessionId, session: &mut NetworkSession) -> OicResult<()> {
        if self.clock.now() >= session.deadline {
            self.signer.abort(id)?;
            session.outbound.clear();
            session.outcome = Some(SessionResult::Aborted);
            return Err(rejected(ErrorCode::SessionRejected));
        }
        Ok(())
    }

    fn fanout(&self, session: &mut NetworkSession, message: PeerMessage) -> OicResult<()> {
        for to in session.participants.iter().filter(|p| **p != message.from) {
            let node = self.config.roster.participant(to).ok_or_else(|| rejected(ErrorCode::PeerNotAdmitted))?;
            if !self.config.roster.allows(20, &self.config.node_id, &node.node_id) {
                return Err(rejected(ErrorCode::PeerNotAdmitted));
            }
            let mut directed = message.clone();
            directed.to = Some(to.clone());
            let frame = SignedPeerMessage::sign(directed, self.scope.clone(), &self.participant_key)
                .and_then(|m| m.encode_point_to_point(FrameKind::MpcSign, MAX_BODY_LEN))
                .map_err(|_| rejected(ErrorCode::InvalidRequest))?;
            session.outbound.push(Outbound { to: node.node_id.clone(), frame });
        }
        Ok(())
    }

    fn outcome(session: &mut NetworkSession, step: ProtocolStep) -> OicResult<()> {
        match step {
            ProtocolStep::Waiting => {}
            ProtocolStep::Share(bytes) => session.outcome = Some(SessionResult::Share(bytes)),
            ProtocolStep::Complete(signature) => session.outcome = Some(SessionResult::Complete(signature)),
            ProtocolStep::Aborted(_) => session.outcome = Some(SessionResult::Aborted),
            ProtocolStep::Send(_) => return Err(rejected(ErrorCode::UnsupportedCapability)),
        }
        Ok(())
    }

    /// Transport origin and participant signature must both match. Duplicate
    /// retransmissions are harmless; equivocation at an accepted round aborts.
    pub fn deliver(&self, from: &NodeId, frame: &[u8]) -> OicResult<()> {
        if !self.config.roster.allows(20, from, &self.config.node_id) {
            return Err(rejected(ErrorCode::PeerNotAdmitted));
        }
        let signed = SignedPeerMessage::decode_point_to_point(frame, self.scope.roster_epoch, FrameKind::MpcSign, MAX_BODY_LEN)
            .map_err(|_| rejected(ErrorCode::InvalidRequest))?;
        let origin = self.config.roster.node(from).ok_or_else(|| rejected(ErrorCode::PeerNotAdmitted))?;
        let key = origin.participant_keys.get(signed.sender()).ok_or_else(|| rejected(ErrorCode::PeerNotAdmitted))?;
        let key = VerifyingKey::from_bytes(key.bytes.as_slice().try_into().map_err(|_| rejected(ErrorCode::InvalidSignature))?)
            .map_err(|_| rejected(ErrorCode::InvalidSignature))?;
        let mut state = self.state.lock();
        if state.halt.halted {
            return Err(rejected(ErrorCode::NodeHalted));
        }
        let session = state.sessions.get_mut(signed.session_id()).ok_or_else(|| rejected(ErrorCode::NotFound))?;
        self.check_deadline(signed.session_id(), session)?;
        if !session.participants.contains(signed.sender()) || !matches!(signed.round(), 1 | 2) {
            return Err(rejected(ErrorCode::PeerNotAdmitted));
        }
        let expected = ExpectedPeerMessage {
            scope: self.scope.clone(),
            session_id: signed.session_id().clone(),
            key_id: session.key_id.clone(),
            key_epoch: session.key_epoch,
            from: signed.sender().clone(),
            from_generation: origin.signer_instance_generation,
            to: self.signer.identity().participant_id.clone(),
            round: signed.round(),
            sequence: signed.round() as u64,
            protocol_version: oic_crypto_provider_frost_ed25519::PROTOCOL_VERSION.into(),
        };
        let message = signed.verify(&expected, &key).map_err(|_| rejected(ErrorCode::InvalidSignature))?;
        let identity = (message.from.clone(), message.round);
        let hash = sha256(message.payload.as_slice());
        if let Some(previous) = session.received.get(&identity) {
            if *previous == hash {
                return Ok(());
            }
            self.signer.abort(&message.session_id)?;
            session.outcome = Some(SessionResult::Aborted);
            session.outbound.clear();
            return Err(rejected(ErrorCode::SessionRejected));
        }
        if session.outcome.is_some() {
            return Ok(());
        }
        if message.round == 2 {
            if session.package.as_ref() != Some(&message.payload) {
                return Err(rejected(ErrorCode::StaleEvidence));
            }
            if !session.buffered_package {
                Self::outcome(session, self.signer.receive(&message.session_id, message)?)?;
                session.buffered_package = true;
            }
        } else {
            Self::outcome(session, self.signer.receive(&message.session_id, message)?)?;
            session.commitments.insert(message.from.clone(), message.payload.clone());
        }
        session.received.insert(identity, hash);
        if session.package.is_none() && session.commitments.len() == session.participants.len() {
            let pairs = session.participants.iter().map(|p| (p.clone(), session.commitments[p].clone())).collect::<Vec<_>>();
            let package = oic_crypto_provider_frost_ed25519::build_signing_package(&pairs, session.payload.message_or_digest.as_slice())?;
            let outgoing = PeerMessage {
                session_id: message.session_id.clone(),
                key_id: session.key_id.clone(),
                key_epoch: session.key_epoch,
                from: self.signer.identity().participant_id.clone(),
                from_generation: self.signer.generation(),
                to: None,
                round: 2,
                sequence: 2,
                protocol_version: oic_crypto_provider_frost_ed25519::PROTOCOL_VERSION.into(),
                payload: package.clone(),
            };
            self.fanout(session, outgoing)?;
            session.package = Some(package);
        }
        Ok(())
    }

    /// Idempotent retransmission source. Deadline and halt checks suppress stale
    /// frames, including after a participant has already produced its share.
    pub fn outbound_at(&self, offset: usize) -> Option<Outbound> {
        let mut state = self.state.lock();
        if state.halt.halted {
            return None;
        }
        let now = self.clock.now();
        // Polling is also the independent timeout sweep. The signer retains its
        // replay tombstone; the bounded network cache can drop expired bodies.
        state.sessions.retain(|id, session| {
            if now < session.deadline {
                return true;
            }
            let _ = self.signer.abort(id);
            false
        });
        state
            .sessions
            .values()
            .filter(|s| self.clock.now() < s.deadline)
            .flat_map(|s| s.outbound.iter())
            .nth(offset)
            .map(|m| Outbound { to: m.to.clone(), frame: m.frame.clone() })
    }
}
