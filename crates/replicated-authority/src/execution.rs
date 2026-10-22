use oic_adapter_api::{AuthorizationTarget, ChainAdapter, ChainProfile, VerifyContext, check_evidence_scope, decoded_operation_hash, evidence_hash};
use oic_approval_verifier::{DisplayInputs, IndependentVerifier};
use oic_authorization_state::{AuthorityCommand, AuthorityConfig, AuthorityEvent, AuthorityOutput, AuthorityState, BudgetKey, ReserveRequest, apply};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use oic_policy_kernel::{ExposureView, PolicyInput, WindowExposure, destination_hash, evaluate, intent_hash, policy_hash, preview_hash, verify_grants};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

/// Independently provisioned registry snapshot. Proposal bodies cannot replace
/// registry entries or enroll a profile, verifier, wallet, vault, asset or key.
/// Changing this snapshot requires a new, independently approved deployment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub profiles: Vec<ChainProfile>,
    pub vaults: Vec<Vault>,
    pub wallets: Vec<ChainWallet>,
    pub keys: Vec<KeyDescriptor>,
    pub assets: Vec<Asset>,
    pub destinations: Vec<CounterpartyDestination>,
}

/// Confidential reservation proof. Every derived field is independently
/// recomputed, including the envelope binding and the claimed kernel decision.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReserveCandidate {
    pub request: ReserveRequest,
    pub envelope: AuthorizationEnvelopeBody,
    pub package: ApprovalPackage,
}

impl std::fmt::Debug for ReserveCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReserveCandidate([REDACTED])")
    }
}

/// The D2 application deliberately refuses raw D1 Reserve and observation
/// commands: neither a proposer's Allow nor an unverified settlement is proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Command {
    Authority(Box<AuthorityCommand>),
    Reserve(Box<ReserveCandidate>),
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicatedState {
    pub authority: AuthorityState,
    /// Retained so Release is reverified from actual bytes under ordered state.
    pub reservations: BTreeMap<ReservationId, ReserveCandidate>,
}

impl ReplicatedState {
    pub fn hash(&self) -> OicResult<Hash32> {
        domain_hash("OIC/REPLICATED_AUTHORITY_STATE/v1", self)
    }
}

impl std::fmt::Debug for ReplicatedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReplicatedState([REDACTED])")
    }
}

/// Pure execution; no receipt key, wall clock, storage, consensus vote or I/O.
/// All replicas and followers must independently pin the same configuration.
#[derive(Clone)]
pub struct Executor {
    pub authority: AuthorityConfig,
    pub registry: Registry,
    pub adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>>,
}

impl Executor {
    /// Pin all execution configuration in the genesis and every successor root.
    /// An adapter manifest is only as trustworthy as its independently pinned
    /// build; a proposer cannot select adapters or their manifests.
    pub fn state_hash(&self, state: &ReplicatedState) -> OicResult<Hash32> {
        let config = &self.authority;
        let manifests: Vec<_> = self.adapters.iter().map(|(id, adapter)| (id, adapter.manifest())).collect();
        domain_hash("OIC/D2_EXECUTION/v1", &(
            &config.institution_id, &config.environment_id, &config.authority_key_id,
            &config.admin_keys, config.admin_quorum, &config.freeze_responders,
            config.release_receipt_ttl_seconds, config.max_clock_skew_seconds,
            &self.registry, manifests, state,
        ))
    }

    /// Apply an atomic command batch against the specific parent's state. A
    /// failed command yields no successor, output, or committed partial batch.
    pub fn execute(&self, mut state: ReplicatedState, commands: &[Command], now: UnixSeconds) -> OicResult<(ReplicatedState, Vec<AuthorityOutput>, Vec<AuthorityEvent>)> {
        let mut outputs = Vec::new();
        let mut events = Vec::new();
        for command in commands {
            let command = match command {
                Command::Authority(command) => {
                    match command.as_ref() {
                        AuthorityCommand::Reserve { .. } | AuthorityCommand::RecordObservation { .. } => {
                            return Err(OicError::invalid_request("D2 requires independently verifiable native evidence"));
                        }
                        AuthorityCommand::Release { request } => {
                            let record = state.authority.reservations.get(&request.reservation_id)
                                .ok_or_else(|| OicError::new(ErrorCode::NotFound, "reservation absent"))?;
                            if record.state == oic_authorization_state::ReservationState::Reserved {
                                let proof = state.reservations.get(&request.reservation_id)
                                    .ok_or_else(|| OicError::unverifiable("reservation lacks native proof"))?;
                                self.verify_reserve(&state.authority, proof, now)?;
                            }
                        }
                        _ => {}
                    }
                    *command.clone()
                }
                Command::Reserve(proof) => {
                    self.verify_reserve(&state.authority, proof, now)?;
                    state.reservations.insert(proof.envelope.budget_reservation_id.clone(), *proof.clone());
                    AuthorityCommand::Reserve { request: proof.request.clone() }
                }
            };
            let (authority, output, emitted) = apply(&self.authority, state.authority, command, now)?;
            state.authority = authority;
            outputs.push(output);
            events.extend(emitted);
        }
        Ok((state, outputs, events))
    }

    fn verify_reserve(&self, state: &AuthorityState, proof: &ReserveCandidate, now: UnixSeconds) -> OicResult<()> {
        let p = &proof.package;
        let b = &proof.envelope;
        let r = &proof.request;
        let policy = state.policy.as_ref().ok_or_else(|| OicError::new(ErrorCode::StalePolicy, "no active D2 policy"))?;
        if p.schema_version != ApprovalPackage::SCHEMA_VERSION || &p.policy != policy
            || !self.registry.vaults.contains(&p.vault) || !self.registry.wallets.contains(&p.wallet)
            || !self.registry.keys.contains(&p.key) || !self.registry.assets.contains(&p.asset)
            || !self.registry.destinations.contains(&p.destination)
        {
            return Err(OicError::scope("proposal differs from committed policy or pinned registry"));
        }
        if p.intent.institution_id != self.authority.institution_id || p.intent.environment_id != self.authority.environment_id
            || p.candidate.operation_family_id != oic_authorization_state::family_id_for(&p.intent.intent_id)?
        {
            return Err(OicError::scope("candidate authority scope or family differs"));
        }
        // Grants bind the registered intent hash, but a zero-approval rule has no
        // grants: without this check another intent body could reserve under the id.
        let registered = state.intents.get(&p.intent.intent_id).ok_or_else(|| OicError::new(ErrorCode::NotFound, "intent not registered"))?;
        if registered.intent_hash != intent_hash(&p.intent)? {
            return Err(OicError::scope("proposal intent differs from the registered intent"));
        }
        let profile = self.registry.profiles.iter().find(|profile| profile.chain_profile_id == p.intent.chain_profile_id)
            .ok_or_else(|| OicError::scope("chain profile not pinned"))?;
        let adapter = self.adapters.get(&profile.adapter_id).ok_or_else(|| OicError::unsupported("adapter not pinned"))?;
        let verifier = IndependentVerifier::new(self.adapters.clone(), self.registry.profiles.clone(), self.authority.admin_keys.clone(), self.authority.admin_quorum);
        let display = verifier.render(&DisplayInputs {
            intent: &p.intent, candidate: &p.candidate, wallet: &p.wallet, key: &p.key, vault: &p.vault,
            asset: &p.asset, destination: &p.destination, policy, evidence: &p.evidence,
        }, now)?;
        if !display.destination_matches_registry {
            return Err(OicError::policy_denied("decoded destination differs from registry"));
        }
        check_evidence_scope(profile, &p.evidence, Some(now))?;
        let context = VerifyContext { profile, wallet: &p.wallet, key: &p.key, asset: &p.asset, destination: &p.destination, evidence: &p.evidence };
        let verified = adapter.verify_candidate(&p.candidate, &AuthorizationTarget::Intent(&p.intent), &context)?;
        if decoded_operation_hash(&verified.decoded)? != verified.decoded_operation_hash
            || verified.signing_payloads != p.candidate.signing_payloads
        {
            return Err(OicError::unverifiable("native candidate verification is inconsistent"));
        }
        let enrolled = state.ordered_approvals.as_ref().ok_or_else(|| OicError::invalid_request("D2 requires ordered approval enrollment"))?;
        let approvers: Vec<_> = enrolled.credentials.values().filter_map(|entry| entry.credential.clone()).collect();
        verify_grants(&r.grants, &approvers, now)?;
        let preview = preview_hash(&p.candidate.candidate_id, p.candidate.candidate_revision, verified.decoded_operation_hash, evidence_hash(&p.evidence)?);
        // Remove only this exact candidate's existing reservation for idempotent
        // verification/release; every other outstanding exposure remains charged.
        let mut accounting = state.clone();
        accounting.reservations.remove(&b.budget_reservation_id);
        let mut exposure = ExposureView::default();
        for rule in &policy.rules {
            for limit in &rule.rolling_limits {
                for asset in self.registry.assets.iter().map(|asset| &asset.asset_id) {
                    if exposure.find(asset, limit.window_seconds).is_some() { continue; }
                    let budget = BudgetKey::Asset { asset_id: asset.clone() };
                    exposure.windows.push(WindowExposure {
                        asset_id: asset.clone(), window_seconds: limit.window_seconds,
                        settled: accounting.settled_in_window(&p.vault.vault_id, &budget, limit.window_seconds, now)
                            .ok_or_else(|| OicError::policy_denied("settled exposure overflow"))?,
                        outstanding: accounting.outstanding(&p.vault.vault_id, &budget)
                            .ok_or_else(|| OicError::policy_denied("outstanding exposure overflow"))?,
                    });
                }
            }
        }
        let decision = evaluate(&PolicyInput {
            policy, policy_hash: state.policy_hash, expected_policy_epoch: state.policy_epoch,
            intent: &p.intent, intent_hash: intent_hash(&p.intent)?, verified: &verified, grants: &r.grants,
            destination: &p.destination, asset: &p.asset, vault: &p.vault, evidence: &p.evidence,
            freshness: FreshnessContext { now }, exposure: &exposure,
            candidate_id: &p.candidate.candidate_id, candidate_revision: p.candidate.candidate_revision, preview_hash: preview,
        });
        if !decision.is_allow() || decision != r.policy_decision {
            return Err(OicError::policy_denied("replica policy evaluation rejects proposer's decision"));
        }
        // Reconstruct from independently verified inputs, not a builder result.
        // This keeps the execution boundary independent of signer/service code.
        let manifest = adapter.manifest();
        let expected = AuthorizationEnvelopeBody {
            institution_id: p.intent.institution_id.clone(), environment_id: p.intent.environment_id.clone(),
            vault_id: p.vault.vault_id.clone(), chain_wallet_id: p.wallet.chain_wallet_id.clone(),
            intent_id: p.intent.intent_id.clone(), intent_hash: intent_hash(&p.intent)?,
            operation_family_id: p.candidate.operation_family_id.clone(), candidate_id: p.candidate.candidate_id.clone(), candidate_revision: p.candidate.candidate_revision,
            chain_profile_id: profile.chain_profile_id.clone(), chain_profile_hash: profile.hash()?,
            key_id: p.key.key_id.clone(), key_epoch: p.key.key_epoch, public_key_hash: domain_hash(domains::PUBLIC_KEY, &p.key.public_key)?,
            adapter_id: manifest.adapter_id, adapter_version: manifest.adapter_version, verifier_build_hash: manifest.verifier_build_hash,
            policy_id: policy.policy_id.clone(), policy_epoch: policy.policy_epoch, policy_hash: policy_hash(policy)?, allowlist_version: policy.allowlist_version,
            native_unsigned_bytes: p.candidate.native_unsigned_bytes.clone(), native_signing_payloads: verified.signing_payloads.clone(),
            decoded_operation_hash: verified.decoded_operation_hash, evidence_bundle_hash: evidence_hash(&p.evidence)?, destination_hash: destination_hash(&p.destination)?,
            approval_grants: r.grants.clone(), budget_reservation_id: oic_authorization_state::reservation_id_for(&r.family_id, &r.candidate_id, r.candidate_revision)?,
            reservation_version: 1, resource_reservations: verified.claims.resources.clone(), maximum_asset_outflows: verified.claims.asset_outflows.clone(),
            maximum_native_fees: verified.claims.native_fees.clone(), issuance_deadline: r.issuance_deadline,
            expected_chain_validity_constraints: adapter.validity_constraints(&p.candidate, &p.evidence)?, signer_session_id: r.signer_session_id.clone(),
            participant_set: b.participant_set.clone(),
        };
        let participants: std::collections::BTreeSet<_> = b.participant_set.iter().collect();
        if expected != *b || b.participant_set.len() != participants.len() || participants.len() < usize::from(p.key.threshold)
            || !b.participant_set.iter().all(|participant| p.key.participants.contains(participant))
            || r.envelope_body_hash != domain_hash(domains::AUTHORIZATION, b)?
            || r.family_id != p.candidate.operation_family_id || r.candidate_id != p.candidate.candidate_id
            || r.candidate_revision != p.candidate.candidate_revision || r.intent_id != p.intent.intent_id
            || r.vault_id != p.vault.vault_id || r.claims != verified.claims
            || r.policy_epoch != state.policy_epoch || r.policy_hash != policy_hash(policy)?
        {
            return Err(OicError::scope("reservation or envelope differs from native verification"));
        }
        Ok(())
    }
}
