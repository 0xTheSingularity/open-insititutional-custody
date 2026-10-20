//! # oic-service-coordinator
//!
//! The untrusted MPC coordinator of RFC 0001 §1.1: it delivers protocol
//! messages and assembles results, and must possess neither policy override
//! nor share storage. It may be compromised without bypassing anything:
//! the authorization-state authority re-checks every reservation and
//! release (§5.4), and every signer independently re-verifies the envelope
//! and withholds its share until the authority's release receipt for that
//! exact envelope and session is presented. The coordinator's job is to make
//! the honest path complete and to record, conservatively, what happened.
//!
//! ## [`Coordinator::execute`]
//!
//! 1. A decision other than `Allow` fails (`ApprovalRequired` /
//!    `PolicyDenied`) without touching the authority.
//! 2. Static preparation: adapter, backend driver ([`driver_for`]),
//!    participant endpoints, a fresh UUID signer session id, and the
//!    envelope body ([`oic_service_builder::envelope_body`]).
//! 3. `Authority::reserve` with the matched rule's exposure limits; the
//!    Reserved receipt completes the envelope. Lifecycle `RESERVED`.
//! 4. Every participant opens its session (and re-verifies everything);
//!    round-1 messages are relayed and the share-round messages delivered,
//!    which signers buffer. Lifecycle `AUTHORIZED`.
//! 5. `Authority::release` with a fresh freshness context. Lifecycle
//!    `ISSUANCE_COMMITTED`: from here on a signature may exist.
//! 6. The release receipt — exactly the one the authority returned — goes to
//!    every participant; their outputs are aggregated on one participant;
//!    the adapter assembles and verifies the signed transaction. Lifecycle
//!    `SIGNATURE_OBSERVED`.
//!
//! ## Failure semantics (§5.4, §12.2)
//!
//! * Any failure before `release` succeeds: every opened session is
//!   aborted, the reservation is aborted (`abort_before_issuance`, which
//!   releases its exposure and locks), lifecycle `ABORTED_BEFORE_ISSUANCE`,
//!   and the original error is returned.
//! * Any failure after `release` succeeded: the reservation is NOT aborted
//!   (its exposure stays outstanding until chain evidence resolves it),
//!   lifecycle `ISSUANCE_UNKNOWN`, and `IssuanceUncertain` is returned naming
//!   the reservation and the signer session.

mod driver;
mod endpoint;
mod store;

pub use driver::*;
pub use endpoint::*;
pub use store::*;

use oic_adapter_api::{ChainAdapter, ChainProfile, VerifiedSignedTransaction};
use oic_authorization_state::{Authority, AuthorityStore, Clock, ReleaseRequest, ReserveRequest};
use oic_crypto_provider::ProtocolStep;
use oic_domain_types::*;
use oic_policy_kernel::{policy_hash, Decision};
use oic_service_builder::{envelope_body, signing_materials, BuiltCandidate, Evaluation};
use oic_signer::envelope_body_hash;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One authorized candidate to sign.
#[derive(Clone, Debug)]
pub struct SigningJob {
    pub built: BuiltCandidate,
    pub profile: ChainProfile,
    pub policy: PolicyBundle,
    pub grants: Vec<ApprovalGrant>,
    /// Must be `Allow`.
    pub evaluation: Evaluation,
    pub participant_set: Vec<ParticipantId>,
    pub issuance_deadline: UnixSeconds,
}

/// A completed issuance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issuance {
    pub envelope: AuthorizationEnvelope,
    pub release_receipt: AuthorityReceipt,
    pub issuance_record: IssuanceRecord,
    pub signed: VerifiedSignedTransaction,
}

/// The coordinator. See the crate docs.
pub struct Coordinator<S: AuthorityStore> {
    authority: Arc<Authority<S>>,
    signers: BTreeMap<ParticipantId, Arc<dyn SignerEndpoint>>,
    adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>>,
    clock: Arc<dyn Clock>,
    store: Arc<dyn OperationStore>,
}

/// Fields shared by every transition of one job.
struct JobRecord {
    family: OperationFamilyId,
    candidate_id: CandidateId,
    candidate_revision: u32,
    session_id: SigningSessionId,
    reservation_id: ReservationId,
    envelope_body_hash: Hash32,
}

fn uncertain(reservation_id: &ReservationId, session_id: &SigningSessionId, cause: &OicError) -> OicError {
    OicError::new(
        ErrorCode::IssuanceUncertain,
        format!("issuance uncertain for reservation {reservation_id}, signer session {session_id}: {:?}: {}", cause.code, cause.detail),
    )
}

fn with_note(mut e: OicError, note: Option<String>) -> OicError {
    if let Some(n) = note {
        e.detail = format!("{}; {n}", e.detail);
    }
    e
}

/// Rolling limits the authority derives for `claims` under `rule`: every
/// asset outflow in the rule's asset scope gets every rolling limit.
fn exposure_limits(rule: &PolicyRule, claims: &ResourceClaims) -> Vec<(AssetId, ExposureLimit)> {
    let assets: BTreeSet<&AssetId> = claims.asset_outflows.iter().map(|o| &o.asset_id).collect();
    let mut out = Vec::new();
    for a in assets.into_iter().filter(|a| rule.assets.is_empty() || rule.assets.contains(a)) {
        for l in &rule.rolling_limits {
            out.push((a.clone(), l.clone()));
        }
    }
    out
}

impl<S: AuthorityStore> Coordinator<S> {
    /// Endpoints are keyed by their participant id and adapters by their
    /// manifest id; duplicates are refused.
    pub fn new(
        authority: Arc<Authority<S>>,
        signers: Vec<Arc<dyn SignerEndpoint>>,
        adapters: Vec<Arc<dyn ChainAdapter>>,
        clock: Arc<dyn Clock>,
        store: Arc<dyn OperationStore>,
    ) -> OicResult<Self> {
        let mut by_participant = BTreeMap::new();
        for s in signers {
            let p = s.participant_id();
            if by_participant.insert(p.clone(), s).is_some() {
                return Err(OicError::invalid_request(format!("two signer endpoints for participant {p}")));
            }
        }
        let mut by_adapter = BTreeMap::new();
        for a in adapters {
            let id = a.manifest().adapter_id;
            if by_adapter.insert(id.clone(), a).is_some() {
                return Err(OicError::invalid_request(format!("two adapters with id {id}")));
            }
        }
        Ok(Coordinator { authority, signers: by_participant, adapters: by_adapter, clock, store })
    }

    pub fn store(&self) -> &Arc<dyn OperationStore> {
        &self.store
    }

    pub fn authority(&self) -> &Arc<Authority<S>> {
        &self.authority
    }

    fn record(&self, job: &JobRecord, state: LifecycleState, issuance_id: Option<IssuanceId>, signed_tx_id: Option<ChainTxId>, error: Option<OicError>) -> OicResult<()> {
        self.store.append(Transition {
            operation_family_id: job.family.clone(),
            candidate_id: job.candidate_id.clone(),
            candidate_revision: job.candidate_revision,
            state,
            at: self.clock.now(),
            session_id: Some(job.session_id.clone()),
            reservation_id: Some(job.reservation_id.clone()),
            envelope_body_hash: Some(job.envelope_body_hash),
            issuance_id,
            signed_tx_id,
            error,
        })
    }

    /// Record a refusal that happened before anything was reserved.
    fn refuse(&self, built: &BuiltCandidate, state: LifecycleState, error: OicError) -> OicError {
        let c = &built.candidate;
        let appended = self.store.append(Transition {
            operation_family_id: c.operation_family_id.clone(),
            candidate_id: c.candidate_id.clone(),
            candidate_revision: c.candidate_revision,
            state,
            at: self.clock.now(),
            session_id: None,
            reservation_id: None,
            envelope_body_hash: None,
            issuance_id: None,
            signed_tx_id: None,
            error: Some(error.clone()),
        });
        with_note(error, appended.err().map(|e| format!("lifecycle log append failed: {}", e.detail)))
    }

    /// Sign one job. See the crate docs for the steps and failure semantics.
    pub fn execute(&self, job: SigningJob) -> OicResult<Issuance> {
        let built = &job.built;
        let c = &built.candidate;

        // 1. Decision gate: nothing reaches the authority without `Allow`.
        let rule_id = match &job.evaluation.decision {
            Decision::Allow { rule_id } => rule_id,
            Decision::RequireApprovals { required, satisfied, roles, .. } => {
                let e = OicError::new(ErrorCode::ApprovalRequired, format!("policy requires {required} approvals ({roles:?}); {satisfied} valid"));
                return Err(self.refuse(built, LifecycleState::AwaitingApproval, e));
            }
            Decision::Deny { reasons } => {
                return Err(self.refuse(built, LifecycleState::Rejected, OicError::policy_denied(format!("policy denied: {reasons:?}"))));
            }
        };

        // 2. Static preparation.
        let prepared = (|| {
            if policy_hash(&job.policy)? != policy_hash(&built.package.policy)? {
                return Err(OicError::new(ErrorCode::StalePolicy, "job policy differs from the policy the candidate was built under"));
            }
            let rule = job.policy.rules.iter().find(|r| &r.rule_id == rule_id).ok_or_else(|| OicError::policy_denied("decision names a rule not in the policy"))?;
            if job.evaluation.matched_rule.as_ref() != Some(rule) {
                return Err(OicError::invalid_request("evaluation's matched rule is not the rule its decision names"));
            }
            let adapter = self.adapters.get(&c.adapter_id).ok_or_else(|| OicError::unsupported(format!("no adapter {} configured", c.adapter_id)))?.clone();
            let key = &built.package.key;
            let driver = driver_for(key)?;
            driver.check_participants(key, &job.participant_set)?;
            let endpoints = job
                .participant_set
                .iter()
                .map(|p| self.signers.get(p).cloned().map(|e| (p.clone(), e)).ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("no signer endpoint for participant {p}"))))
                .collect::<OicResult<Vec<_>>>()?;
            let session_id = SigningSessionId::new(format!("sess-{}", uuid::Uuid::new_v4())).ok_or_else(|| OicError::internal("session id"))?;
            let body = envelope_body(built, adapter.as_ref(), &job.profile, job.grants.clone(), session_id, job.participant_set.clone(), job.issuance_deadline)?;
            let payload = match body.native_signing_payloads.iter().filter(|p| p.required_key_id == key.key_id && p.scheme_id == key.scheme).collect::<Vec<_>>().as_slice() {
                [one] => (*one).clone(),
                _ => return Err(OicError::unsupported("the candidate must carry exactly one signing payload for the key")),
            };
            Ok((rule.clone(), adapter, driver, endpoints, body, payload))
        })();
        let (rule, adapter, driver, endpoints, body, payload) = prepared.map_err(|e| self.refuse(built, LifecycleState::Rejected, e))?;
        let jr = JobRecord {
            family: c.operation_family_id.clone(),
            candidate_id: c.candidate_id.clone(),
            candidate_revision: c.candidate_revision,
            session_id: body.signer_session_id.clone(),
            reservation_id: body.budget_reservation_id.clone(),
            envelope_body_hash: envelope_body_hash(&body)?,
        };

        // 3. Reserve.
        let reserved = self
            .authority
            .reserve(ReserveRequest {
                family_id: body.operation_family_id.clone(),
                candidate_id: body.candidate_id.clone(),
                candidate_revision: body.candidate_revision,
                vault_id: body.vault_id.clone(),
                intent_id: body.intent_id.clone(),
                policy_epoch: body.policy_epoch,
                policy_hash: body.policy_hash,
                claims: built.verified.claims.clone(),
                grants: body.approval_grants.clone(),
                envelope_body_hash: jr.envelope_body_hash,
                signer_session_id: jr.session_id.clone(),
                issuance_deadline: body.issuance_deadline,
                policy_decision: Decision::Allow { rule_id: rule.rule_id.clone() },
                exposure_limits: exposure_limits(&rule, &built.verified.claims),
            })
            .map(|(_, receipt)| receipt)
            .map_err(|e| self.refuse(built, LifecycleState::Rejected, e))?;
        let envelope = AuthorizationEnvelope { body, authorization_state_receipt: reserved };
        let mut opened: Vec<Arc<dyn SignerEndpoint>> = Vec::new();
        if let Err(e) = self.record(&jr, LifecycleState::Reserved, None, None, None) {
            return Err(self.abort_before_issuance(&jr, &opened, e));
        }

        // 4. Sessions, round 1, share-round delivery (buffered by signers).
        let materials = signing_materials(&built.package);
        let pre = self.pre_release(&envelope, &materials, &payload, driver.as_ref(), &endpoints, &mut opened);
        if let Err(e) = pre.and_then(|_| self.record(&jr, LifecycleState::Authorized, None, None, None)) {
            return Err(self.abort_before_issuance(&jr, &opened, e));
        }

        // 5. Release: the point of possible issuance.
        let released = self.authority.release(ReleaseRequest {
            reservation_id: jr.reservation_id.clone(),
            reservation_version: envelope.body.reservation_version,
            envelope_body_hash: jr.envelope_body_hash,
            signer_session_id: jr.session_id.clone(),
            expected_policy_epoch: envelope.body.policy_epoch,
            freshness: FreshnessContext { now: self.clock.now() },
        });
        let (release_receipt, issuance_record) = match released {
            Ok(r) => r,
            Err(e) => return Err(self.abort_before_issuance(&jr, &opened, e)),
        };

        // 6. Shares, aggregation, native assembly. Never abort from here on.
        let post = self
            .record(&jr, LifecycleState::IssuanceCommitted, Some(issuance_record.issuance_id.clone()), None, None)
            .and_then(|_| self.post_release(&envelope, &release_receipt, built, adapter.as_ref(), &endpoints))
            .and_then(|signed| {
                self.record(&jr, LifecycleState::SignatureObserved, Some(issuance_record.issuance_id.clone()), Some(signed.signed.chain_tx_id.clone()), None)?;
                Ok(signed)
            });
        match post {
            Ok(signed) => Ok(Issuance { envelope, release_receipt, issuance_record, signed }),
            Err(e) => {
                let err = uncertain(&jr.reservation_id, &jr.session_id, &e);
                let appended = self.record(&jr, LifecycleState::IssuanceUnknown, Some(issuance_record.issuance_id.clone()), None, Some(e));
                Err(with_note(err, appended.err().map(|a| format!("lifecycle log append failed: {}", a.detail))))
            }
        }
    }

    /// Open every session, relay round 1, and deliver the share-round
    /// messages. Every endpoint whose session opened is pushed to `opened`.
    fn pre_release(
        &self,
        envelope: &AuthorizationEnvelope,
        materials: &oic_signer::SigningMaterials,
        payload: &NativeSigningPayload,
        driver: &dyn BackendDriver,
        endpoints: &[(ParticipantId, Arc<dyn SignerEndpoint>)],
        opened: &mut Vec<Arc<dyn SignerEndpoint>>,
    ) -> OicResult<()> {
        let session_id = &envelope.body.signer_session_id;
        let generations: BTreeMap<ParticipantId, Epoch> = endpoints.iter().map(|(p, e)| (p.clone(), e.generation())).collect();
        let now = self.clock.now();
        let mut round1 = Round1::new();
        for (p, ep) in endpoints {
            let step = ep.open_session(envelope, materials, now)?;
            opened.push(ep.clone());
            let msgs = match step {
                ProtocolStep::Send(msgs) => msgs,
                ProtocolStep::Waiting => Vec::new(),
                other => return Err(OicError::internal(format!("{p} answered open_session with {other:?}"))),
            };
            round1.insert(p.clone(), msgs);
        }
        let ctx = SessionContext { session_id, key: &materials.key, payload, participants: &envelope.body.participant_set, generations: &generations };
        let deliveries = driver.relay_round1(&ctx, &round1)?.into_iter().chain(driver.round2(&ctx, &round1)?);
        for d in deliveries {
            let ep = endpoints.iter().find(|(p, _)| *p == d.to).map(|(_, e)| e).ok_or_else(|| OicError::internal(format!("driver addressed non-participant {}", d.to)))?;
            match ep.receive(session_id, &d.message)? {
                ProtocolStep::Waiting => {}
                other => return Err(OicError::internal(format!("{} answered a pre-release message with {other:?}", d.to))),
            }
        }
        Ok(())
    }

    /// Deliver the authority's release receipt, collect one output per
    /// participant, aggregate, assemble, and verify natively.
    fn post_release(
        &self,
        envelope: &AuthorizationEnvelope,
        release_receipt: &AuthorityReceipt,
        built: &BuiltCandidate,
        adapter: &dyn ChainAdapter,
        endpoints: &[(ParticipantId, Arc<dyn SignerEndpoint>)],
    ) -> OicResult<VerifiedSignedTransaction> {
        let session_id = &envelope.body.signer_session_id;
        let now = self.clock.now();
        let mut shares = Vec::with_capacity(endpoints.len());
        for (p, ep) in endpoints {
            let steps = ep.release(session_id, release_receipt, now)?;
            let share = match steps.as_slice() {
                [ProtocolStep::Share(b)] => b.clone(),
                [ProtocolStep::Complete(sig)] => sig.bytes.clone(),
                other => return Err(OicError::internal(format!("{p} produced {other:?} on release instead of one share"))),
            };
            shares.push((p.clone(), share));
        }
        let (_, aggregator) = endpoints.first().ok_or_else(|| OicError::internal("empty participant set"))?;
        let signature = aggregator.aggregate(session_id, &shares)?;
        let key = &built.package.key;
        let signed = adapter.assemble_signed_transaction(&built.candidate, key, &[signature])?;
        adapter.verify_signed_transaction(&signed, &built.candidate, key)
    }

    /// Pre-issuance failure: abort opened sessions and the reservation.
    fn abort_before_issuance(&self, job: &JobRecord, opened: &[Arc<dyn SignerEndpoint>], cause: OicError) -> OicError {
        // Without a release receipt no signer can produce output; aborting
        // additionally burns their one-time state. A failing abort is noted.
        let mut notes: Vec<String> = Vec::new();
        for ep in opened {
            if let Err(e) = ep.abort(&job.session_id) {
                notes.push(format!("abort at {} failed: {}", ep.participant_id(), e.detail));
            }
        }
        let (state, err) = match self.authority.abort_before_issuance(&job.reservation_id) {
            Ok(_) => (LifecycleState::AbortedBeforeIssuance, cause.clone()),
            Err(e) if e.code == ErrorCode::IssuanceUncertain => (LifecycleState::IssuanceUnknown, uncertain(&job.reservation_id, &job.session_id, &cause)),
            Err(e) => {
                // The reservation is still held (exposure retained) until it
                // expires; the lifecycle stays pre-issuance.
                notes.push(format!("reservation abort failed: {:?}: {}", e.code, e.detail));
                (LifecycleState::Reserved, cause.clone())
            }
        };
        if let Err(e) = self.record(job, state, None, None, Some(cause)) {
            notes.push(format!("lifecycle log append failed: {}", e.detail));
        }
        with_note(err, if notes.is_empty() { None } else { Some(notes.join("; ")) })
    }
}
