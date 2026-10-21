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

fn missing(what: &str) -> OicError {
    OicError::new(ErrorCode::NotFound, what)
}

impl<S: AuthorityStore> Api<S> {
    pub fn authenticate(&self, token: &str) -> OicResult<ApiCredential> {
        let hash = sha256(token.as_bytes());
        self.credentials
            .iter()
            .find(|c| c.token_hash == hash)
            .cloned()
            .ok_or_else(|| OicError::scope("invalid API credential"))
    }

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

    pub fn lifecycle(&self, family: &OperationFamilyId) -> OicResult<LifecycleState> {
        let authorized = self.coordinator.authority().family(family)?.lifecycle;
        Ok(self
            .broadcaster
            .record(family)?
            .map(|s| s.lifecycle)
            .unwrap_or(authorized))
    }

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
        verify_grant(&grant, &self.approvers, self.clock.now())?;
        if let Some(existing) = old
            .approvals
            .iter()
            .find(|g| g.body.grant_id == grant.body.grant_id)
        {
            return if existing == &grant {
                Ok(old)
            } else {
                Err(OicError::new(ErrorCode::Conflict, "grant id reused"))
            };
        }
        if old.approvals.len() >= oic_policy_kernel::MAX_GRANTS {
            return Err(OicError::invalid_request("approval grant limit reached"));
        }
        let mut new = old.clone();
        new.approvals.push(grant);
        self.store.replace(&old, &new)?;
        Ok(new)
    }

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
        let evaluation = builder::evaluate(
            &old.built,
            policy,
            authority.current_policy()?.0,
            &old.approvals,
            &self.approvers,
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
                return Err(OicError::policy_denied(format!("{reasons:?}")));
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
