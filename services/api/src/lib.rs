//! RFC002 development HTTP contract. Intake never holds chain keys, signs an
//! arbitrary digest, or skips the builder, policy, authority, and signer path.
//! Mount behind institution-controlled TLS; bearer credentials are explicit,
//! scoped capabilities, not approval grants. No production launcher is implied.
mod http;
mod store;
pub use http::router;
pub use store::ApiStore;

use oic_adapter_api::{ChainAdapter, ChainProfile};
use oic_approval_verifier::{verify_grant, ApproverCredential};
use oic_authorization_state::{AuthorityStore, Clock, IdempotencyKey};
use oic_canonical_encoding::sha256;
use oic_domain_types::*;
use oic_policy_kernel::intent_hash;
use oic_service_broadcaster::Broadcaster;
use oic_service_builder::{
    self as builder, BuildInputs, BuiltCandidate, EvidenceCommitment, EvidenceRequest,
    EvidenceSource,
};
use oic_service_coordinator::{Coordinator, Issuance, SigningJob};
use oic_service_reconciler::Reconciler;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Read,
    Propose,
    Approve,
    Submit,
}

/// Store only a SHA-256 digest of a randomly generated bearer token. Token
/// provisioning/offboarding is domain-local, not an unauthenticated route.
#[derive(Clone)]
pub struct ApiCredential {
    pub token_hash: Hash32,
    pub credential_id: CredentialId,
    pub vaults: Vec<VaultId>,
    pub scopes: Vec<Scope>,
}

/// Trusted deployment catalog, not caller-supplied builder inputs. Destinations
/// and active policy still require their normal administrative signatures.
#[derive(Default)]
pub struct Catalog {
    pub vaults: BTreeMap<VaultId, Vault>,
    pub wallets: BTreeMap<ChainWalletId, ChainWallet>,
    pub keys: BTreeMap<KeyId, KeyDescriptor>,
    pub assets: BTreeMap<AssetId, Asset>,
    pub destinations: BTreeMap<(DestinationId, u32), CounterpartyDestination>,
    pub profiles: BTreeMap<ChainProfileId, ChainProfile>,
    pub adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>>,
    pub evidence: BTreeMap<ChainProfileId, Arc<dyn EvidenceSource>>,
    pub participants: BTreeMap<KeyId, Vec<ParticipantId>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchState {
    Ready,
    Dispatching,
    Signed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentRecord {
    pub intent: Intent,
    pub built: BuiltCandidate,
    pub approvals: Vec<ApprovalGrant>,
    pub dispatch: DispatchState,
    pub issuance: Option<Issuance>,
    pub last_error: Option<OicError>,
}

pub struct Api<S: AuthorityStore> {
    pub store: Arc<ApiStore>,
    pub coordinator: Arc<Coordinator<S>>,
    pub broadcaster: Arc<Broadcaster<S>>,
    pub reconciler: Arc<Reconciler>,
    pub catalog: Catalog,
    pub credentials: Vec<ApiCredential>,
    pub approvers: Vec<ApproverCredential>,
    pub clock: Arc<dyn Clock>,
}

/// Construct a not-found error for an absent catalog or operation record.
fn missing(what: &str) -> OicError {
    OicError::new(ErrorCode::NotFound, what)
}

impl<S: AuthorityStore> Api<S> {
    /// Resolve a bearer token against the configured credential digests.
    /// Returns `ScopeMismatch` if no credential matches; vault and permission
    /// checks are performed separately by `authorize`.
    pub fn authenticate(&self, token: &str) -> OicResult<ApiCredential> {
        let hash = sha256(token.as_bytes());
        self.credentials
            .iter()
            .find(|c| c.token_hash == hash)
            .cloned()
            .ok_or_else(|| OicError::scope("invalid API credential"))
    }

    /// Check the active credential roster for the requested vault and permission.
    /// Returns `ScopeMismatch` if the store and authority scopes differ or the
    /// credential no longer has access. Retained copies of a credential do not
    /// preserve access after removal from the roster.
    pub fn authorize(
        &self,
        principal: &ApiCredential,
        vault: &VaultId,
        scope: Scope,
    ) -> OicResult<()> {
        let config = self.coordinator.authority().config();
        self.store
            .check_scope(&config.institution_id, &config.environment_id)?;
        // Recheck the active roster instead of trusting a previously cloned
        // principal if an application retains it across credential rotation.
        if !self.credentials.iter().any(|c| {
            c.token_hash == principal.token_hash
                && c.credential_id == principal.credential_id
                && c.vaults.contains(vault)
                && c.scopes.contains(&scope)
        }) {
            return Err(OicError::scope(
                "credential lacks the requested vault/scope",
            ));
        }
        Ok(())
    }

    /// Return a stored intent after checking access to its vault for `scope`.
    /// Propagates store errors, including `NotFound` and `RecoveryRequired` for
    /// corrupt records, and authorization errors.
    pub fn get(
        &self,
        principal: &ApiCredential,
        id: &IntentId,
        scope: Scope,
    ) -> OicResult<IntentRecord> {
        let record = self.store.get(id)?;
        self.authorize(principal, &record.intent.vault_id, scope)?;
        Ok(record)
    }

    /// Build and persist an intent, register it with the authority, and publish
    /// its current operation state. Requires propose access to the intent's vault.
    ///
    /// `idempotency_key` must contain 1 through 128 bytes and is scoped to the
    /// institution and create route. Repeating the same intent returns its stored
    /// candidate; conflicting intent or idempotency bindings fail. Invalid scope,
    /// version, proposer, or request fields are rejected before building.
    /// Builder, authority, storage, and event publication errors propagate; an
    /// error can occur after the intent has been registered or persisted.
    pub fn create(
        &self,
        principal: &ApiCredential,
        intent: Intent,
        idempotency_key: &str,
    ) -> OicResult<IntentRecord> {
        self.authorize(principal, &intent.vault_id, Scope::Propose)?;
        let authority = self.coordinator.authority();
        if intent.schema_version != 1
            || IntentId::new(intent.intent_id.to_string()).is_none()
            || intent.institution_id != authority.config().institution_id
            || intent.environment_id != authority.config().environment_id
            || intent.proposer_credential_id != principal.credential_id
            || intent.external_reference.trim().is_empty()
            || idempotency_key.is_empty()
            || idempotency_key.len() > 128
        {
            return Err(OicError::invalid_request(
                "intent scope, version, proposer, external reference, or idempotency key",
            ));
        }
        let key = IdempotencyKey {
            institution_id: intent.institution_id.clone(),
            route: "POST /v1/intents".into(),
            key: idempotency_key.into(),
        };
        match self.store.get(&intent.intent_id) {
            Ok(existing) => {
                authority.register_intent(&intent, intent_hash(&intent)?, key)?;
                if existing.intent != intent {
                    return Err(OicError::new(
                        ErrorCode::Conflict,
                        "immutable intent differs",
                    ));
                }
                self.publish_operation(&existing)?;
                return Ok(existing);
            }
            Err(e) if e.code == ErrorCode::NotFound => (),
            Err(e) => return Err(e),
        }
        let built = self.build(&intent)?;
        authority.register_intent(&intent, intent_hash(&intent)?, key)?;
        let record = self.store.insert(&IntentRecord {
            intent,
            built,
            approvals: vec![],
            dispatch: DispatchState::Ready,
            issuance: None,
            last_error: None,
        })?;
        self.publish_operation(&record)?;
        Ok(record)
    }

    /// Return the broadcaster's stored lifecycle when present, otherwise the
    /// authority's lifecycle. Authority lookup and submission-store errors
    /// propagate; an absent broadcaster record is the only fallback.
    pub fn lifecycle(&self, family: &OperationFamilyId) -> OicResult<LifecycleState> {
        let authorized = self.coordinator.authority().family(family)?.lifecycle;
        Ok(self
            .broadcaster
            .record(family)?
            .map(|s| s.lifecycle)
            .unwrap_or(authorized))
    }

    /// Publish the current operation lifecycle with any stored transaction ID.
    /// Lifecycle lookup and reconciler errors propagate. An unchanged observation
    /// is deduplicated by the reconciler.
    pub fn publish_operation(&self, record: &IntentRecord) -> OicResult<()> {
        let family = &record.built.candidate.operation_family_id;
        let state = self.lifecycle(family)?;
        self.reconciler.record_operation_state(
            &record.intent,
            &record.built.candidate,
            state,
            record
                .issuance
                .as_ref()
                .map(|i| i.signed.signed.chain_tx_id.clone()),
            self.clock.now(),
        )
    }

    /// Build the first candidate from the trusted catalog, active policy, and
    /// latest source evidence. Missing configuration returns `NotFound`;
    /// authority reads, evidence collection, and builder errors propagate.
    fn build(&self, intent: &Intent) -> OicResult<BuiltCandidate> {
        let c = &self.catalog;
        let IntentOperation::AssetTransfer {
            asset_id,
            destination_id,
            destination_version,
            ..
        } = &intent.operation;
        let wallet = c
            .wallets
            .get(&intent.chain_wallet_id)
            .ok_or_else(|| missing("wallet"))?;
        let profile = c
            .profiles
            .get(&intent.chain_profile_id)
            .ok_or_else(|| missing("profile"))?;
        let asset = c.assets.get(asset_id).ok_or_else(|| missing("asset"))?;
        let destination = c
            .destinations
            .get(&(destination_id.clone(), *destination_version))
            .ok_or_else(|| missing("destination version"))?;
        let policy = self
            .coordinator
            .authority()
            .store()
            .read(|s| s.policy.clone())?
            .ok_or_else(|| missing("active policy"))?;
        let evidence = c
            .evidence
            .get(&intent.chain_profile_id)
            .ok_or_else(|| missing("evidence source"))?
            .evidence(&EvidenceRequest {
                profile: profile.clone(),
                wallet: wallet.clone(),
                asset: asset.clone(),
                destination: destination.clone(),
                commitment: EvidenceCommitment::Latest,
                lookup_tables: vec![],
            })?;
        let family = oic_authorization_state::family_id_for(&intent.intent_id)?;
        builder::build(
            c.adapters
                .get(&profile.adapter_id)
                .ok_or_else(|| missing("adapter"))?
                .as_ref(),
            &BuildInputs {
                intent: intent.clone(),
                vault: c
                    .vaults
                    .get(&intent.vault_id)
                    .ok_or_else(|| missing("vault"))?
                    .clone(),
                wallet: wallet.clone(),
                key: c
                    .keys
                    .get(&wallet.key_id)
                    .ok_or_else(|| missing("key descriptor"))?
                    .clone(),
                asset: asset.clone(),
                destination: destination.clone(),
                profile: profile.clone(),
                policy,
                evidence,
                candidate_id: CandidateId::unchecked(format!("api-{}", family)),
                candidate_revision: 1,
                operation_family_id: family,
                built_at: self.clock.now(),
            },
        )
    }

    /// Verify and store a grant belonging to this principal and immutable intent.
    /// Requires approve access and a ready intent. An identical grant ID and body
    /// returns the current record; reusing the ID with different content returns
    /// `Conflict`. Invalid binding, grant verification, grant-count limits, and
    /// concurrent updates fail without adding the grant; store errors propagate.
    pub fn approve(
        &self,
        principal: &ApiCredential,
        id: &IntentId,
        grant: ApprovalGrant,
    ) -> OicResult<IntentRecord> {
        let old = self.get(principal, id, Scope::Approve)?;
        if old.dispatch != DispatchState::Ready {
            return Err(OicError::resource_conflict(
                "intent is no longer accepting approvals",
            ));
        }
        if grant.body.approver_credential_id != principal.credential_id
            || grant.body.intent_id != *id
            || grant.body.intent_hash != intent_hash(&old.intent)?
            || grant.body.institution_id != old.intent.institution_id
            || grant.body.environment_id != old.intent.environment_id
            || grant.body.vault_id != old.intent.vault_id
        {
            return Err(OicError::scope(
                "grant does not belong to this approver and intent",
            ));
        }
        let authority = self.coordinator.authority();
        let enrolled = authority.approval_credentials()?;
        verify_grant(
            &grant,
            enrolled.as_deref().unwrap_or(&self.approvers),
            self.clock.now(),
        )?;
        let existing = old
            .approvals
            .iter()
            .find(|g| g.body.grant_id == grant.body.grant_id);
        if existing.is_some_and(|g| g != &grant) {
            return Err(OicError::new(ErrorCode::Conflict, "grant id reused"));
        }
        if existing.is_none() && old.approvals.len() >= oic_policy_kernel::MAX_GRANTS {
            return Err(OicError::invalid_request("approval grant limit reached"));
        }
        if enrolled.is_some() {
            let recorded = authority.recorded_approvals(id)?;
            match recorded
                .iter()
                .find(|r| r.grant.body.approver_credential_id == grant.body.approver_credential_id)
            {
                Some(record) if record.grant != grant => {
                    return Err(OicError::new(
                        ErrorCode::Conflict,
                        "credential already approved this intent",
                    ))
                }
                Some(_) => {} // Recover a lost API-store ACK without replaying the mutation.
                None => {
                    authority.approve(&old.intent, grant.clone())?;
                }
            }
        }
        if existing.is_some() {
            return Ok(old);
        }
        let mut new = old.clone();
        new.approvals.push(grant);
        self.store.replace(&old, &new)?;
        Ok(new)
    }

    /// Evaluate approvals and policy, durably mark dispatch, obtain issuance,
    /// and persist the signed result before attempting broadcast.
    ///
    /// Requires submit access. A stored issuance is retried using its exact signed
    /// bytes. Cancelled intents return `ResourceConflict`; dispatch without a
    /// stored issuance returns `IssuanceUncertain`. Missing approvals return
    /// `ApprovalRequired`, and a denied evaluation returns `PolicyDenied`.
    ///
    /// Success returns the persisted intent record after a recorded broadcast
    /// attempt; it does not imply acknowledgment or finality. The broadcaster
    /// records chain-client errors in submission evidence rather than returning
    /// them. Authority, evaluation, coordinator, storage, and reconciler errors
    /// propagate. A coordinator error is saved when possible, and dispatch remains
    /// marked; later errors can also occur after signatures or a broadcast exist.
    pub fn submit(&self, principal: &ApiCredential, id: &IntentId) -> OicResult<IntentRecord> {
        let old = self.get(principal, id, Scope::Submit)?;
        let family = old.built.candidate.operation_family_id.clone();
        if let Some(issuance) = &old.issuance {
            let signed = &issuance.signed;
            // Lost HTTP ACK: only the same signed bytes can be submitted again.
            self.reconciler
                .link_operation(signed.signed.chain_tx_id.clone(), family.clone())?;
            self.broadcaster.submit(
                &family,
                &old.built.candidate,
                signed,
                &old.intent.chain_profile_id,
            )?;
            self.publish_operation(&old)?;
            return Ok(old);
        }
        if old.dispatch == DispatchState::Cancelled {
            return Err(OicError::resource_conflict(
                "intent was cancelled before dispatch",
            ));
        }
        if old.dispatch != DispatchState::Ready {
            return Err(OicError::new(
                ErrorCode::IssuanceUncertain,
                "dispatch may have reached signers; inspect the operation, do not create a replacement payment",
            ));
        }
        let policy = &old.built.package.policy;
        let authority = self.coordinator.authority();
        let windows: Vec<_> = policy
            .rules
            .iter()
            .flat_map(|r| r.rolling_limits.iter().map(|l| l.window_seconds))
            .collect();
        let assets: Vec<_> = old
            .built
            .verified
            .claims
            .asset_outflows
            .iter()
            .map(|o| o.asset_id.clone())
            .collect();
        let exposure =
            authority.exposure_view(&old.intent.vault_id, &assets, &windows, self.clock.now())?;
        let enrolled = authority.approval_credentials()?;
        let evaluation = builder::evaluate(
            &old.built,
            policy,
            authority.current_policy()?.0,
            &old.approvals,
            enrolled.as_deref().unwrap_or(&self.approvers),
            &exposure,
            self.clock.now(),
        )?;
        match &evaluation.decision {
            oic_policy_kernel::Decision::Allow { .. } => (),
            oic_policy_kernel::Decision::RequireApprovals { .. } => {
                return Err(OicError::new(
                    ErrorCode::ApprovalRequired,
                    "approval quorum incomplete",
                ));
            }
            oic_policy_kernel::Decision::Deny { reasons } => {
                let mut detail = format!("{reasons:?}");
                if reasons
                    .iter()
                    .any(|r| matches!(r, oic_policy_kernel::ReasonCode::EvidenceStale))
                {
                    detail.push_str(
                        "; stale evidence cannot be refreshed: create a new intent, then approve and submit within the evidence window",
                    );
                }
                if reasons
                    .iter()
                    .any(|r| matches!(r, oic_policy_kernel::ReasonCode::EvidenceFromFuture))
                {
                    detail.push_str(
                        "; evidence is timestamped in the future: check the evaluation clock against the evidence observed_at timestamp",
                    );
                }
                return Err(OicError::policy_denied(detail));
            }
        }
        let participants = self
            .catalog
            .participants
            .get(&old.built.package.key.key_id)
            .ok_or_else(|| missing("enrolled signing participant set"))?
            .clone();
        let profile = self
            .catalog
            .profiles
            .get(&old.intent.chain_profile_id)
            .ok_or_else(|| missing("profile"))?
            .clone();
        let mut pending = old.clone();
        pending.dispatch = DispatchState::Dispatching;
        self.store.replace(&old, &pending)?;
        let issuance = match self.coordinator.execute(SigningJob {
            built: old.built.clone(),
            profile,
            policy: policy.clone(),
            grants: old.approvals.clone(),
            evaluation,
            participant_set: participants,
            issuance_deadline: UnixSeconds(
                self.clock
                    .now()
                    .0
                    .checked_add(60)
                    .ok_or_else(|| OicError::invalid_request("clock overflow"))?,
            ),
        }) {
            Ok(issuance) => issuance,
            Err(e) => {
                let mut failed = pending.clone();
                failed.last_error = Some(e.clone());
                self.store.replace(&pending, &failed)?;
                return Err(e);
            }
        };
        let mut signed = pending.clone();
        signed.issuance = Some(issuance.clone());
        signed.dispatch = DispatchState::Signed;
        self.store.replace(&pending, &signed)?;
        self.reconciler
            .link_operation(issuance.signed.signed.chain_tx_id.clone(), family.clone())?;
        self.broadcaster.submit(
            &family,
            &signed.built.candidate,
            &issuance.signed,
            &signed.intent.chain_profile_id,
        )?;
        self.publish_operation(&signed)?;
        Ok(signed)
    }

    /// Persist cancellation while an intent is ready, requiring propose access.
    /// Repeating cancellation returns the cancelled record. Once dispatch has
    /// started, returns `IssuanceUncertain`; concurrent updates and store or
    /// access errors propagate. No chain transaction is cancelled here.
    pub fn cancel(&self, principal: &ApiCredential, id: &IntentId) -> OicResult<IntentRecord> {
        let old = self.get(principal, id, Scope::Propose)?;
        if old.dispatch == DispatchState::Cancelled {
            return Ok(old);
        }
        if old.dispatch != DispatchState::Ready {
            return Err(OicError::new(
                ErrorCode::IssuanceUncertain,
                "cannot cancel after dispatch; native authority may already exist",
            ));
        }
        let mut new = old.clone();
        new.dispatch = DispatchState::Cancelled;
        self.store.replace(&old, &new)?;
        Ok(new)
    }
}
