//! The broadcaster: durable submission, cross-checked observation, and
//! invalidation proofs, all reported to the authorization-state authority.

use crate::client::{ChainClient, Commitment, PossiblyIssued};
use crate::store::{AttemptOutcome, SubmissionAttempt, SubmissionRecord, SubmissionStore};
use oic_adapter_api::*;
use oic_authorization_state::{Authority, AuthorityStore, Clock};
use oic_domain_types::*;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;

/// What every configured source agreed (or did not agree) the chain shows.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Seen {
    /// Not on the canonical chain at the evidence state.
    NotVisible,
    Included { state: StateReference, execution_success: bool, fee_paid: Amount },
    /// Finalized under the profile's finality commitment.
    Finalized(ChainObservation),
}

/// Network registration: profile, pinned adapter, client.
struct Network {
    profile: ChainProfile,
    adapter: Arc<dyn ChainAdapter>,
    client: Arc<dyn ChainClient>,
}

/// Broadcaster service core. Holds no keys; it can only hand already signed
/// bytes to a chain and report what the chain shows.
pub struct Broadcaster<S: AuthorityStore> {
    authority: Arc<Authority<S>>,
    clients: BTreeMap<NetworkId, Arc<dyn ChainClient>>,
    adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>>,
    profiles: BTreeMap<ChainProfileId, ChainProfile>,
    store: Arc<dyn SubmissionStore>,
    clock: Arc<dyn Clock>,
    /// Per-family claim serializing every load-mutate-store sequence. A caller
    /// that waits here reloads the newest record, so a delayed submit cannot
    /// overwrite newer inclusion or finality evidence and concurrent submits
    /// cannot lose each other's attempt history.
    locks: Mutex<BTreeMap<OperationFamilyId, Arc<Mutex<()>>>>,
}

fn not_found(detail: impl Into<String>) -> OicError {
    OicError::new(ErrorCode::NotFound, detail)
}

impl<S: AuthorityStore> Broadcaster<S> {
    pub fn new(authority: Arc<Authority<S>>, store: Arc<dyn SubmissionStore>, clock: Arc<dyn Clock>) -> Self {
        Broadcaster { authority, clients: BTreeMap::new(), adapters: BTreeMap::new(), profiles: BTreeMap::new(), store, clock, locks: Mutex::new(BTreeMap::new()) }
    }

    /// The claim for one family's record. Public mutating entry points hold it
    /// across their whole read-modify-write sequence.
    fn family_claim(&self, family: &OperationFamilyId) -> Arc<Mutex<()>> {
        self.locks.lock().entry(family.clone()).or_default().clone()
    }

    /// Register a network. The client must serve the profile's network and
    /// the adapter must be the profile's adapter.
    pub fn register_network(&mut self, profile: ChainProfile, adapter: Arc<dyn ChainAdapter>, client: Arc<dyn ChainClient>) -> OicResult<()> {
        if client.network_id() != profile.network_id {
            return Err(OicError::scope(format!("client serves {} but profile {} is for {}", client.network_id(), profile.chain_profile_id, profile.network_id)));
        }
        if adapter.manifest().adapter_id != profile.adapter_id {
            return Err(OicError::scope(format!("adapter {} does not implement profile adapter {}", adapter.manifest().adapter_id, profile.adapter_id)));
        }
        if client.sources().is_empty() {
            return Err(OicError::invalid_request("chain client declares no evidence sources"));
        }
        self.clients.insert(profile.network_id.clone(), client);
        self.adapters.insert(profile.adapter_id.clone(), adapter);
        self.profiles.insert(profile.chain_profile_id.clone(), profile);
        Ok(())
    }

    pub fn authority(&self) -> &Arc<Authority<S>> {
        &self.authority
    }

    fn network(&self, profile_id: &ChainProfileId) -> OicResult<Network> {
        let profile = self.profiles.get(profile_id).cloned().ok_or_else(|| not_found(format!("chain profile {profile_id} is not registered")))?;
        let adapter = self.adapters.get(&profile.adapter_id).cloned().ok_or_else(|| not_found(format!("adapter {} is not registered", profile.adapter_id)))?;
        let client = self.clients.get(&profile.network_id).cloned().ok_or_else(|| not_found(format!("no client for network {}", profile.network_id)))?;
        Ok(Network { profile, adapter, client })
    }

    /// The stored record of a family, if any.
    pub fn record(&self, family: &OperationFamilyId) -> OicResult<Option<SubmissionRecord>> {
        self.store.get(family)
    }

    fn load(&self, family: &OperationFamilyId) -> OicResult<SubmissionRecord> {
        self.store.get(family)?.ok_or_else(|| not_found(format!("no submission record for family {family}")))
    }

    fn put(&self, rec: &mut SubmissionRecord) -> OicResult<()> {
        rec.updated_at = self.clock.now();
        self.store.put(rec)
    }

    fn check_binding(candidate: &Candidate, signed: &SignedTransaction, family: &OperationFamilyId, profile_id: &ChainProfileId) -> OicResult<()> {
        if &candidate.operation_family_id != family {
            return Err(OicError::scope("candidate belongs to another operation family"));
        }
        if &candidate.chain_profile_id != profile_id {
            return Err(OicError::scope("candidate was built for another chain profile"));
        }
        if signed.candidate_id != candidate.candidate_id || signed.candidate_revision != candidate.candidate_revision {
            return Err(OicError::scope("signed transaction is not bound to this candidate revision"));
        }
        Ok(())
    }

    /// Record (without broadcasting) a candidate whose signature may exist,
    /// e.g. recovered from a signer after an issuance timeout. The record
    /// shows `ISSUANCE_UNKNOWN` until chain evidence resolves it.
    pub fn register_possibly_issued(&self, family: &OperationFamilyId, candidate: &Candidate, signed: &SignedTransaction, profile_id: &ChainProfileId) -> OicResult<SubmissionRecord> {
        Self::check_binding(candidate, signed, family, profile_id)?;
        let net = self.network(profile_id)?;
        let claim = self.family_claim(family);
        let _claimed = claim.lock();
        if let Some(existing) = self.store.get(family)? {
            if existing.candidate == *candidate && existing.signed == *signed {
                return Ok(existing);
            }
            return Err(OicError::new(ErrorCode::Conflict, "family already has a different recorded candidate"));
        }
        let now = self.clock.now();
        let mut rec = SubmissionRecord {
            operation_family_id: family.clone(),
            chain_profile_id: profile_id.clone(),
            network_id: net.profile.network_id.clone(),
            candidate: candidate.clone(),
            signed: signed.clone(),
            attempts: vec![],
            lifecycle: LifecycleState::IssuanceUnknown,
            last_inclusion: None,
            last_observation: None,
            quarantined: false,
            created_at: now,
            updated_at: now,
        };
        self.put(&mut rec)?;
        Ok(rec)
    }

    /// Durably record a pending attempt, hand the bytes to the chain, then
    /// record the acknowledgement and report `Submitted` to the authority.
    /// A client error leaves the submission `SUBMISSION_UNKNOWN` (A18).
    ///
    /// Holds the per-family claim for the whole sequence: concurrent submits
    /// serialize, each reloads the newest record, and a record that already
    /// shows inclusion or a terminal lifecycle is returned without another
    /// network hand-off, so stored evidence never regresses.
    pub fn submit(&self, family: &OperationFamilyId, candidate: &Candidate, signed: &VerifiedSignedTransaction, profile_id: &ChainProfileId) -> OicResult<SubmissionRecord> {
        let signed = &signed.signed;
        Self::check_binding(candidate, signed, family, profile_id)?;
        let net = self.network(profile_id)?;
        let fam = self.authority.family(family)?;
        if fam.quarantined {
            return Err(OicError::new(ErrorCode::IssuanceUncertain, "operation family is quarantined by conflicting chain evidence"));
        }
        let claim = self.family_claim(family);
        let _claimed = claim.lock();
        let now = self.clock.now();
        let mut rec = match self.store.get(family)? {
            Some(existing) if existing.candidate == *candidate && existing.signed == *signed => {
                if existing.lifecycle.terminal_released() || existing.last_inclusion.is_some() {
                    return Ok(existing);
                }
                existing
            }
            Some(_) => return Err(OicError::new(ErrorCode::Conflict, "family already has a different recorded candidate; resolve it before broadcasting a replacement")),
            None => SubmissionRecord {
                operation_family_id: family.clone(),
                chain_profile_id: profile_id.clone(),
                network_id: net.profile.network_id.clone(),
                candidate: candidate.clone(),
                signed: signed.clone(),
                attempts: vec![],
                lifecycle: fam.lifecycle,
                last_inclusion: None,
                last_observation: None,
                quarantined: false,
                created_at: now,
                updated_at: now,
            },
        };
        self.attempt(&mut rec, &net)?;
        Ok(rec)
    }

    /// Hand the recorded signed bytes to the chain again (the same bytes; no
    /// new signature can be created here). Used after a reorg dropped the
    /// transaction or after an unacknowledged attempt.
    pub fn rebroadcast(&self, family: &OperationFamilyId) -> OicResult<SubmissionRecord> {
        let claim = self.family_claim(family);
        let _claimed = claim.lock();
        let mut rec = self.load(family)?;
        if rec.quarantined || self.authority.family(family)?.quarantined {
            return Err(OicError::new(ErrorCode::IssuanceUncertain, "operation family is quarantined by conflicting chain evidence"));
        }
        if rec.lifecycle.terminal_released() {
            return Err(OicError::new(ErrorCode::Conflict, format!("operation already resolved as {:?}", rec.lifecycle)));
        }
        let net = self.network(&rec.chain_profile_id)?;
        self.attempt(&mut rec, &net)?;
        Ok(rec)
    }

    fn attempt(&self, rec: &mut SubmissionRecord, net: &Network) -> OicResult<()> {
        let n = u32::try_from(rec.attempts.len() + 1).map_err(|_| OicError::internal("attempt counter overflow"))?;
        rec.attempts.push(SubmissionAttempt { attempt: n, started_at: self.clock.now(), outcome: AttemptOutcome::Pending });
        // Durable BEFORE the chain sees the bytes.
        self.put(rec)?;
        let result = net.client.submit(&rec.signed);
        let at = self.clock.now();
        let outcome = match result {
            Ok(tx_id) if tx_id == rec.signed.chain_tx_id => AttemptOutcome::Acknowledged { tx_id, at },
            Ok(other) => AttemptOutcome::ErrorReported {
                code: ErrorCode::UnverifiableTransaction,
                detail: format!("client acknowledged tx id {other}, expected {}", rec.signed.chain_tx_id),
                at,
            },
            Err(e) => AttemptOutcome::ErrorReported { code: e.code, detail: e.detail, at },
        };
        let acknowledged = matches!(outcome, AttemptOutcome::Acknowledged { .. });
        if let Some(last) = rec.attempts.last_mut() {
            last.outcome = outcome;
        }
        if acknowledged {
            if rec.last_inclusion.is_none() && !rec.lifecycle.terminal_released() {
                let source = net.client.sources().into_iter().next().ok_or_else(|| OicError::internal("client has no sources"))?;
                let obs = ChainObservation::Submitted { tx_id: rec.signed.chain_tx_id.clone(), source, at };
                rec.lifecycle = self.authority.record_observation(&rec.operation_family_id, &rec.candidate.candidate_id, obs.clone())?;
                rec.last_observation = Some(obs);
            }
        } else if rec.last_inclusion.is_none() && !rec.lifecycle.terminal_released() && !rec.attempts.iter().any(|a| matches!(a.outcome, AttemptOutcome::Acknowledged { .. })) {
            // Nothing ever acknowledged and nothing observed: the outcome is unknown.
            rec.lifecycle = LifecycleState::SubmissionUnknown;
        }
        self.put(rec)
    }

    /// After a restart: every attempt still `Pending` was interrupted between
    /// the durable record and the acknowledgement. Its outcome is unknown.
    /// Returns the affected families.
    pub fn recover(&self) -> OicResult<Vec<OperationFamilyId>> {
        let mut out = Vec::new();
        for rec in self.store.list()? {
            let claim = self.family_claim(&rec.operation_family_id);
            let _claimed = claim.lock();
            // Reload under the claim; another caller may have advanced it.
            let Some(mut rec) = self.store.get(&rec.operation_family_id)? else {
                continue;
            };
            let mut touched = false;
            for a in rec.attempts.iter_mut().filter(|a| a.outcome == AttemptOutcome::Pending) {
                a.outcome = AttemptOutcome::Interrupted { recovered_at: self.clock.now() };
                touched = true;
            }
            if touched {
                if rec.last_inclusion.is_none() && !rec.lifecycle.terminal_released() {
                    rec.lifecycle = LifecycleState::SubmissionUnknown;
                }
                self.put(&mut rec)?;
                out.push(rec.operation_family_id.clone());
            }
        }
        Ok(out)
    }

    /// Classify one adapter observation result. A `Finalized` result from a
    /// non-finality view is downgraded to `Included`.
    fn classify(result: OicResult<ChainObservation>) -> OicResult<Seen> {
        match result {
            Ok(ChainObservation::Submitted { .. }) => Ok(Seen::NotVisible),
            Ok(ChainObservation::Included { state, execution_success, fee_paid, .. }) | Ok(ChainObservation::Finalized { state, execution_success, fee_paid, .. }) => {
                Ok(Seen::Included { state, execution_success, fee_paid })
            }
            Ok(other) => Err(OicError::unverifiable(format!("adapter observe returned an unexpected observation {other:?}"))),
            // The scope was checked before observing; a missing transaction item
            // means the transaction is not on the canonical chain at that state.
            Err(e) if e.code == ErrorCode::StaleEvidence => Ok(Seen::NotVisible),
            Err(e) => Err(e),
        }
    }

    fn observe_source(&self, net: &Network, source: &EvidenceSourceId, tx_id: &ChainTxId) -> OicResult<Seen> {
        let now = Some(self.clock.now());
        let latest = net.client.evidence_for_tx(source, tx_id, Commitment::Latest)?;
        check_evidence_scope(&net.profile, &latest, now)?;
        if latest.state.height > net.client.head().height {
            return Err(OicError::stale_evidence(format!("source {source} reports a state above the client's head")));
        }
        let seen = Self::classify(net.adapter.observe(tx_id, &net.profile, &latest))?;
        if matches!(seen, Seen::NotVisible) {
            return Ok(seen);
        }
        let fin = net.client.evidence_for_tx(source, tx_id, Commitment::Finalized)?;
        check_evidence_scope(&net.profile, &fin, now)?;
        if fin.state.commitment == net.profile.finality_commitment && fin.state.height <= net.client.finalized().height {
            if let Ok(obs @ ChainObservation::Finalized { .. }) = net.adapter.observe(tx_id, &net.profile, &fin) {
                return Ok(Seen::Finalized(obs));
            }
        }
        Ok(seen)
    }

    /// Cross-check every source. `Ok(Ok(seen))` when they agree,
    /// `Ok(Err(conflict))` when they do not.
    fn observe_all(&self, net: &Network, tx_id: &ChainTxId) -> OicResult<Result<Seen, ChainObservation>> {
        let sources = net.client.sources();
        let mut seen: Vec<(EvidenceSourceId, Seen)> = Vec::with_capacity(sources.len());
        for s in &sources {
            seen.push((s.clone(), self.observe_source(net, s, tx_id)?));
        }
        let first = seen.first().map(|(_, v)| v.clone()).ok_or_else(|| OicError::internal("client has no sources"))?;
        if seen.iter().all(|(_, v)| *v == first) {
            return Ok(Ok(first));
        }
        let detail = seen.iter().map(|(s, v)| format!("{s}: {v:?}")).collect::<Vec<_>>().join("; ");
        Ok(Err(ChainObservation::Conflict { sources, detail: format!("sources disagree about {tx_id}: {detail}") }))
    }

    fn feed(&self, rec: &mut SubmissionRecord, obs: ChainObservation) -> OicResult<()> {
        rec.lifecycle = self.authority.record_observation(&rec.operation_family_id, &rec.candidate.candidate_id, obs.clone())?;
        rec.last_observation = Some(obs);
        Ok(())
    }

    /// Fetch evidence from every source, cross-check, and feed the agreed
    /// observation to the authority. Disagreement quarantines the family; a
    /// quarantined family is never fed again (no release, A30).
    pub fn poll(&self, family: &OperationFamilyId) -> OicResult<LifecycleState> {
        let claim = self.family_claim(family);
        let _claimed = claim.lock();
        let mut rec = self.load(family)?;
        self.poll_record(&mut rec)?;
        Ok(rec.lifecycle)
    }

    fn poll_record(&self, rec: &mut SubmissionRecord) -> OicResult<()> {
        if rec.lifecycle.terminal_released() {
            return Ok(());
        }
        let fam = self.authority.family(&rec.operation_family_id)?;
        if fam.quarantined || rec.quarantined {
            rec.quarantined = true;
            rec.lifecycle = fam.lifecycle;
            return self.put(rec);
        }
        let net = self.network(&rec.chain_profile_id)?;
        let tx_id = rec.signed.chain_tx_id.clone();
        match self.observe_all(&net, &tx_id)? {
            Err(conflict) => {
                self.feed(rec, conflict)?;
                rec.quarantined = true;
            }
            Ok(Seen::NotVisible) => {
                if let Some(previous_state) = rec.last_inclusion.take() {
                    self.feed(rec, ChainObservation::Reorged { tx_id, previous_state })?;
                }
            }
            Ok(Seen::Included { state, execution_success, fee_paid }) => {
                let same = rec.last_inclusion.as_ref() == Some(&state) && rec.lifecycle == LifecycleState::Included;
                if !same {
                    if let Some(previous_state) = rec.last_inclusion.take().filter(|p| p.hash != state.hash) {
                        self.feed(rec, ChainObservation::Reorged { tx_id: tx_id.clone(), previous_state })?;
                    }
                    self.feed(rec, ChainObservation::Included { tx_id, state: state.clone(), execution_success, fee_paid })?;
                    rec.last_inclusion = Some(state);
                }
            }
            Ok(Seen::Finalized(obs)) => {
                if let ChainObservation::Finalized { state, .. } = &obs {
                    rec.last_inclusion = Some(state.clone());
                }
                self.feed(rec, obs)?;
            }
        }
        self.put(rec)
    }

    /// Resolve `SUBMISSION_UNKNOWN` / `ISSUANCE_UNKNOWN`: first look for the
    /// signed transaction on chain (the real outcome wins); otherwise ask the
    /// adapter to prove invalidation from the possibly issued signed bytes
    /// at the finality view of every source. Only unanimous `Definitive`
    /// proofs release the reservation; anything else stays unknown.
    pub fn resolve_unknown(&self, family: &OperationFamilyId) -> OicResult<LifecycleState> {
        let claim = self.family_claim(family);
        let _claimed = claim.lock();
        let mut rec = self.load(family)?;
        self.poll_record(&mut rec)?;
        if rec.quarantined || rec.lifecycle.terminal_released() || rec.last_inclusion.is_some() {
            return Ok(rec.lifecycle);
        }
        let net = self.network(&rec.chain_profile_id)?;
        let issued = [PossiblyIssued { candidate: rec.candidate.clone(), signed: rec.signed.clone() }];
        let mut proof: Option<(String, StateReference)> = None;
        for s in net.client.sources() {
            let ev = net.client.evidence_for_candidates(&s, &issued, Commitment::Finalized)?;
            check_evidence_scope(&net.profile, &ev, Some(self.clock.now()))?;
            match net.adapter.prove_invalidation(family, std::slice::from_ref(&rec.candidate), &net.profile, &ev)? {
                InvalidationEvidence::Definitive { reason, state } => {
                    if proof.is_none() {
                        proof = Some((reason, state));
                    }
                }
                InvalidationEvidence::Unknown => return self.still_unknown(rec),
            }
        }
        let (reason, state) = proof.ok_or_else(|| OicError::internal("client has no sources"))?;
        self.feed(&mut rec, ChainObservation::DefinitivelyInvalidated { reason, state })?;
        self.put(&mut rec)?;
        Ok(rec.lifecycle)
    }

    fn still_unknown(&self, mut rec: SubmissionRecord) -> OicResult<LifecycleState> {
        if rec.attempts.is_empty() {
            rec.lifecycle = LifecycleState::IssuanceUnknown;
        } else if rec.has_unknown_attempt() && rec.lifecycle != LifecycleState::Reorged {
            rec.lifecycle = LifecycleState::SubmissionUnknown;
        }
        self.put(&mut rec)?;
        Ok(rec.lifecycle)
    }
}
