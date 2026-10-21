//! A fixed-committee, provisioned D2 light client. Only finalizations plus
//! contiguous native reexecution change its private state. No snapshot import,
//! voter, chain-signing key, receipt key, or VerifiedLog constructor exists.

use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_consensus::{CertifiableBlock, Epochable, Heightable};
use commonware_cryptography::{Digestible, certificate::Verifier as _};
use ed25519_dalek::VerifyingKey;
use oic_adapter_api::{ChainAdapter, check_evidence_scope};
use oic_approval_verifier::{ApprovalDisplay, DisplayInputs, IndependentVerifier};
use oic_authorization_state::{AuthorityCommand, AuthorityConfig};
use oic_domain_types::*;
use oic_membership::{AdminTrust, SignedRoster};
use oic_policy_kernel::{ApproverKey, grant_signing_hash, intent_hash, verify_grant};
use oic_replicated_authority::{
    AuthorityBlock, AuthorityFinalization, Command, Executor, FinalityTrust, Registry,
    ReplicatedState,
};
use rand_commonware::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

/// Retained independently of artifact storage. Reinstallation must provision
/// the retained floor; deleting browser storage must never reset this to zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub height: u64,
    pub digest: Hash32,
}

impl Floor {
    pub fn at(block: &AuthorityBlock) -> Self {
        Self {
            height: block.height().get(),
            digest: Hash32::from_slice(block.digest().as_ref()).expect("SHA256"),
        }
    }
}

/// Installation input, NOT a network response or browser-storage format.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provision {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub authority_key_id: KeyId,
    pub admin_keys: Vec<(CredentialId, VerifyingKey)>,
    pub admin_quorum: u8,
    pub freeze_responders: Vec<(CredentialId, VerifyingKey)>,
    pub release_receipt_ttl_seconds: u64,
    pub max_clock_skew_seconds: u64,
    pub registry: Registry,
    pub adapter_builds: BTreeMap<AdapterId, Hash32>,
    pub roster: SignedRoster,
    pub roster_genesis: Hash32,
    pub genesis: Bytes,
    pub genesis_hash: Hash32,
    pub minimum_floor: Floor,
    pub origin: String,
    pub rp_id: String,
    pub max_view_age_seconds: u64,
    pub grant_ttl_seconds: u64,
    pub development: bool,
    /// Raw WebAuthn credential IDs (hex in JSON), mapped to ordered identities.
    /// The public key/role/person still come ONLY from ordered enrollment.
    pub credential_ids: BTreeMap<CredentialId, Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedEntry {
    pub block: Bytes,
    pub finalization: Bytes,
    /// Contiguous ancestors authenticated through the certified tip's parent
    /// hashes. Ancestors need not have finalizations of their own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<Bytes>,
}

impl FinalizedEntry {
    pub fn new(block: &AuthorityBlock, finalization: &AuthorityFinalization) -> Self {
        Self {
            block: block.encode().to_vec().into(),
            finalization: finalization.encode().to_vec().into(),
            ancestors: Vec::new(),
        }
    }
}

#[derive(Serialize)]
pub struct PreparedApproval {
    pub display: ApprovalDisplay,
    pub floor: Floor,
    pub view_age_seconds: u64,
    pub recorded_approvals: usize,
    pub challenge: Hash32,
    pub raw_credential_id: Bytes,
    pub rp_id: String,
    pub expires_at: UnixSeconds,
    pub view_expires_at: UnixSeconds,
    pub development: bool,
}

struct Pending {
    package: ApprovalPackage,
    display: ApprovalDisplay,
    body: ApprovalGrantBody,
    submitted: Option<ApprovalGrant>,
}

pub struct Client {
    provision: Provision,
    executor: Executor,
    trust: FinalityTrust,
    tip: AuthorityBlock,
    state: ReplicatedState,
    rng: StdRng,
    pending: Option<Pending>,
    last_now: UnixSeconds,
}

impl Client {
    /// Native callers supply installation data and an unpredictable CSPRNG
    /// seed, never an artifact hash. WASM obtains browser entropy itself and
    /// accepts no configuration: it uses only the build-time provision.
    pub fn new(
        provision: Provision,
        seed: [u8; 32],
        origin: &str,
        now: UnixSeconds,
    ) -> OicResult<Self> {
        if provision.origin != origin
            || provision.max_view_age_seconds == 0
            || provision.grant_ttl_seconds == 0
            || provision.grant_ttl_seconds > 300
            || provision.admin_quorum == 0
            || (!provision.development
                && (!origin.starts_with("https://") || provision.rp_id == "localhost"))
        {
            return Err(OicError::scope(
                "installation origin or trust configuration differs",
            ));
        }
        let mut adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::from([
            (
                AdapterId::unchecked(oic_adapter_evm::ADAPTER_ID),
                Arc::new(oic_adapter_evm::EvmAdapter) as Arc<dyn ChainAdapter>,
            ),
            (
                AdapterId::unchecked(oic_adapter_solana::ADAPTER_ID),
                Arc::new(oic_adapter_solana::SolanaAdapter) as Arc<dyn ChainAdapter>,
            ),
        ]);
        adapters.retain(|id, _| provision.adapter_builds.contains_key(id));
        if adapters.len() != provision.adapter_builds.len() {
            return Err(OicError::unsupported(
                "provision names an uninstalled adapter",
            ));
        }
        for profile in &provision.registry.profiles {
            let adapter = adapters
                .get(&profile.adapter_id)
                .ok_or_else(|| OicError::unsupported("uninstalled adapter"))?;
            if provision.adapter_builds.get(&profile.adapter_id)
                != Some(&adapter.manifest().verifier_build_hash)
            {
                return Err(OicError::scope(
                    "installed adapter differs from independently approved build",
                ));
            }
        }
        let executor = Executor {
            authority: AuthorityConfig {
                institution_id: provision.institution_id.clone(),
                environment_id: provision.environment_id.clone(),
                authority_key_id: provision.authority_key_id.clone(),
                admin_keys: provision.admin_keys.clone(),
                admin_quorum: provision.admin_quorum,
                freeze_responders: provision.freeze_responders.clone(),
                release_receipt_ttl_seconds: provision.release_receipt_ttl_seconds,
                max_clock_skew_seconds: provision.max_clock_skew_seconds,
            },
            registry: provision.registry.clone(),
            adapters,
        };
        let admins = AdminTrust {
            threshold: u16::from(provision.admin_quorum),
            credentials: provision
                .admin_keys
                .iter()
                .map(|(id, key)| {
                    (
                        id.clone(),
                        PublicKey {
                            scheme: SchemeId::Ed25519Pure,
                            bytes: key.to_bytes().to_vec().into(),
                        },
                    )
                })
                .collect(),
        };
        let trust = FinalityTrust::from_genesis(
            provision.roster.clone(),
            &admins,
            &provision.institution_id,
            &provision.environment_id,
            provision.roster_genesis,
            now,
        )?;
        let tip = AuthorityBlock::decode(provision.genesis.as_slice())
            .map_err(|_| OicError::unverifiable("invalid provisioned genesis"))?;
        let state = ReplicatedState::default();
        if Floor::at(&tip).digest != provision.genesis_hash
            || !tip.height().is_zero()
            || !tip.commands()?.is_empty()
            || tip.state_hash() != executor.state_hash(&state)?
            || tip.context().epoch() != trust.epoch()
            || (provision.minimum_floor.height == 0 && provision.minimum_floor != Floor::at(&tip))
        {
            return Err(OicError::scope(
                "genesis does not bind installed execution, registry and administrators",
            ));
        }
        Ok(Self {
            provision,
            executor,
            trust,
            tip,
            state,
            rng: StdRng::from_seed(seed),
            pending: None,
            last_now: now,
        })
    }

    fn clock(&mut self, now: UnixSeconds) -> OicResult<()> {
        if now < self.last_now {
            return Err(OicError::stale_evidence("local clock regressed"));
        }
        self.last_now = now;
        Ok(())
    }

    pub fn floor(&self) -> Floor {
        Floor::at(&self.tip)
    }

    /// Authenticate the actual certified tip, then reexecute its full linked
    /// checkpoint atomically. An ancestor never needs its own certificate.
    /// Only a single-block repeat of the current tip is idempotent.
    pub fn apply(&mut self, entry: &FinalizedEntry, now: UnixSeconds) -> OicResult<Floor> {
        self.clock(now)?;
        const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
        if entry.ancestors.len() >= 256
            || entry.block.len() > 128 * 1024
            || entry.finalization.len() > 64 * 1024
            || entry.ancestors.iter().any(|bytes| bytes.len() > 128 * 1024)
            || entry.ancestors.iter().map(Bytes::len).sum::<usize>()
                + entry.block.len()
                + entry.finalization.len()
                > MAX_RECORD_BYTES
            || oic_canonical_encoding::canonical_bytes(entry)?.len() > MAX_RECORD_BYTES
        {
            return Err(OicError::invalid_request("finalized record too large"));
        }
        let block = AuthorityBlock::decode(entry.block.as_slice())
            .map_err(|_| OicError::unverifiable("invalid block body"))?;
        let finalization = AuthorityFinalization::decode_cfg(
            entry.finalization.as_slice(),
            &self.trust.verifier().certificate_codec_config(),
        )
        .map_err(|_| OicError::invalid_signature("invalid finalization encoding"))?;
        self.trust.verify(&mut self.rng, &block, &finalization)?;
        if entry.ancestors.is_empty() && block.digest() == self.tip.digest() {
            return Ok(self.floor());
        }
        let mut tip = self.tip.clone();
        let mut state = self.state.clone();
        for bytes in entry.ancestors.iter().chain(std::iter::once(&entry.block)) {
            let child = AuthorityBlock::decode(bytes.as_slice())
                .map_err(|_| OicError::unverifiable("invalid checkpoint block"))?;
            state = self
                .executor
                .verify_block(&tip, state, &child.context(), &child, now)?;
            let floor = Floor::at(&child);
            if floor.height == self.provision.minimum_floor.height
                && floor != self.provision.minimum_floor
            {
                return Err(OicError::new(
                    ErrorCode::RecoveryRequired,
                    "history differs at independently retained floor",
                ));
            }
            tip = child;
        }
        self.tip = tip;
        self.state = state;
        Ok(self.floor())
    }

    fn fresh(&self, now: UnixSeconds) -> OicResult<()> {
        if self.floor().height < self.provision.minimum_floor.height
            || self.tip.height().is_zero()
            || self.tip.timestamp() > now
            || now.0.saturating_sub(self.tip.timestamp().0) > self.provision.max_view_age_seconds
        {
            return Err(OicError::stale_evidence(
                "verified view missing, stale, future-dated or below retained floor",
            ));
        }
        Ok(())
    }

    fn render(&self, p: &ApprovalPackage, now: UnixSeconds) -> OicResult<ApprovalDisplay> {
        self.fresh(now)?;
        let state = &self.state.authority;
        let registry = &self.executor.registry;
        let registered = state
            .intents
            .get(&p.intent.intent_id)
            .ok_or_else(|| OicError::scope("intent not finalized"))?;
        if p.schema_version != ApprovalPackage::SCHEMA_VERSION
            || registered.intent_hash != intent_hash(&p.intent)?
            || registered.operation_family_id != p.candidate.operation_family_id
            || state.policy.as_ref() != Some(&p.policy)
            || p.intent.institution_id != self.provision.institution_id
            || p.intent.environment_id != self.provision.environment_id
            || !registry.vaults.contains(&p.vault)
            || !registry.wallets.contains(&p.wallet)
            || !registry.keys.contains(&p.key)
            || !registry.assets.contains(&p.asset)
            || !registry.destinations.contains(&p.destination)
        {
            return Err(OicError::scope(
                "package differs from finalized state or provisioned registry",
            ));
        }
        if state.freeze.blocking(&p.vault.vault_id).is_some() {
            return Err(OicError::new(ErrorCode::Frozen, "vault frozen"));
        }
        let profile = registry
            .profiles
            .iter()
            .find(|profile| profile.chain_profile_id == p.intent.chain_profile_id)
            .ok_or_else(|| OicError::scope("profile not installed"))?;
        check_evidence_scope(profile, &p.evidence, Some(now))?;
        if p.evidence.observed_at > now
            || now.0.saturating_sub(p.evidence.observed_at.0) > p.policy.max_evidence_age_seconds
        {
            return Err(OicError::stale_evidence("evidence exceeds policy age"));
        }
        let display = IndependentVerifier::new(
            self.executor.adapters.clone(),
            registry.profiles.clone(),
            self.provision.admin_keys.clone(),
            self.provision.admin_quorum,
        )
        .render(
            &DisplayInputs {
                intent: &p.intent,
                candidate: &p.candidate,
                wallet: &p.wallet,
                key: &p.key,
                vault: &p.vault,
                asset: &p.asset,
                destination: &p.destination,
                policy: &p.policy,
                evidence: &p.evidence,
            },
            now,
        )?;
        if !display.destination_matches_registry
            || !p.wallet.active
            || (!self.provision.development
                && p.evidence.trust_level == EvidenceTrustLevel::DevelopmentSimulator)
        {
            return Err(OicError::policy_denied(
                "destination, wallet or production evidence is not approvable",
            ));
        }
        Ok(display)
    }

    /// Exact-candidate intents/grants only in this initial browser profile.
    pub fn prepare(
        &mut self,
        package: ApprovalPackage,
        credential_id: CredentialId,
        nonce: Hash32,
        now: UnixSeconds,
    ) -> OicResult<PreparedApproval> {
        self.pending = None;
        self.clock(now)?;
        if package.intent.constraints.approval_mode != ApprovalMode::ExactCandidate {
            return Err(OicError::unsupported(
                "installed browser profile requires exact-candidate intents",
            ));
        }
        let display = self.render(&package, now)?;
        let ordered = self
            .state
            .authority
            .ordered_approvals
            .as_ref()
            .ok_or_else(|| OicError::scope("ordered enrollment absent"))?;
        let credential = ordered
            .credentials
            .get(&credential_id)
            .and_then(|r| r.credential.as_ref())
            .ok_or_else(|| OicError::scope("credential not enrolled or removed"))?;
        let ApproverKey::WebAuthn {
            rp_id,
            allowed_origins,
            ..
        } = &credential.verifying_key
        else {
            return Err(OicError::scope("browser requires approval-only WebAuthn"));
        };
        if *rp_id != self.provision.rp_id
            || allowed_origins != std::slice::from_ref(&self.provision.origin)
        {
            return Err(OicError::scope(
                "enrollment does not exclusively bind this installed origin and RP",
            ));
        }
        let raw_credential_id = self
            .provision
            .credential_ids
            .get(&credential_id)
            .filter(|id| !id.is_empty() && id.len() <= 1024)
            .ok_or_else(|| OicError::scope("raw credential ID not installed"))?
            .clone();
        let body = ApprovalGrantBody {
            grant_id: GrantId::unchecked(format!("browser-{}", nonce.to_hex())),
            institution_id: package.intent.institution_id.clone(),
            environment_id: package.intent.environment_id.clone(),
            vault_id: package.vault.vault_id.clone(),
            intent_id: package.intent.intent_id.clone(),
            intent_hash: display.intent_hash,
            policy_id: package.policy.policy_id.clone(),
            policy_epoch: package.policy.policy_epoch,
            scope: GrantScope::ExactCandidate {
                candidate_id: package.candidate.candidate_id.clone(),
                candidate_revision: package.candidate.candidate_revision,
                preview_hash: display.preview_hash,
            },
            approver_credential_id: credential_id,
            approver_role: credential.role,
            issued_at: now,
            expires_at: UnixSeconds(
                now.0
                    .checked_add(self.provision.grant_ttl_seconds)
                    .ok_or_else(|| OicError::invalid_request("expiry overflow"))?,
            ),
        };
        // Apply the authoritative ordered-approval rules before asking for UV.
        // A signature is needed for apply(), so proposer/duplicate checks here
        // are repeated by the real executor after the assertion is verified.
        if body.approver_credential_id == package.intent.proposer_credential_id
            || ordered
                .credentials
                .get(&package.intent.proposer_credential_id)
                .is_some_and(|r| r.person_id == credential.person_id)
            || ordered
                .grants
                .get(&body.intent_id)
                .is_some_and(|g| g.contains_key(&body.approver_credential_id))
        {
            return Err(OicError::policy_denied(
                "self-approval or repeated credential approval",
            ));
        }
        let prepared = PreparedApproval {
            display: display.clone(),
            floor: self.floor(),
            view_age_seconds: now.0 - self.tip.timestamp().0,
            recorded_approvals: ordered.grants.get(&body.intent_id).map_or(0, BTreeMap::len),
            challenge: grant_signing_hash(&body)?,
            raw_credential_id,
            rp_id: self.provision.rp_id.clone(),
            expires_at: body.expires_at,
            development: self.provision.development,
            view_expires_at: UnixSeconds(
                self.tip
                    .timestamp()
                    .0
                    .saturating_add(self.provision.max_view_age_seconds),
            ),
        };
        self.pending = Some(Pending {
            package,
            display,
            body,
            submitted: None,
        });
        Ok(prepared)
    }

    /// Construct the canonical assertion carrier and verify it locally. The
    /// gateway receives only this independently constructed Approve command.
    pub fn assertion(
        &mut self,
        raw_id: &[u8],
        assertion: oic_webauthn::Assertion<'_>,
        now: UnixSeconds,
    ) -> OicResult<Command> {
        self.clock(now)?;
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| OicError::invalid_request("no displayed approval"))?;
        let mut display = pending.display.clone();
        let current = self.render(&pending.package, now)?;
        display.evidence_age_seconds = current.evidence_age_seconds;
        if display != current
            || self
                .provision
                .credential_ids
                .get(&pending.body.approver_credential_id)
                .map(Bytes::as_slice)
                != Some(raw_id)
        {
            return Err(OicError::scope("display or returned credential changed"));
        }
        let grant = ApprovalGrant {
            body: pending.body.clone(),
            signature: SignatureBytes {
                scheme: SchemeId::WebAuthnEs256,
                bytes: oic_webauthn::encode_assertion(assertion)
                    .map_err(|e| OicError::invalid_signature(e.to_string()))?
                    .into(),
            },
        };
        let credentials: Vec<_> = self
            .state
            .authority
            .ordered_approvals
            .as_ref()
            .into_iter()
            .flat_map(|ordered| {
                ordered
                    .credentials
                    .values()
                    .filter_map(|r| r.credential.clone())
            })
            .collect();
        verify_grant(&grant, &credentials, now)?;
        let command = Command::Authority(Box::new(AuthorityCommand::Approve {
            intent: Box::new(pending.package.intent.clone()),
            grant: grant.clone(),
        }));
        self.executor
            .execute(self.state.clone(), std::slice::from_ref(&command), now)?;
        self.pending.as_mut().expect("pending").submitted = Some(grant);
        Ok(command)
    }

    /// A gateway acknowledgement is never confirmation. The exact grant must
    /// exist under current enrollment after certificate-verified reexecution.
    pub fn confirmed(&mut self, now: UnixSeconds) -> OicResult<bool> {
        self.clock(now)?;
        self.fresh(now)?;
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| OicError::invalid_request("no pending approval"))?;
        let Some(grant) = &pending.submitted else {
            return Ok(false);
        };
        Ok(self
            .state
            .authority
            .ordered_approvals
            .as_ref()
            .is_some_and(|ordered| {
                ordered
                    .grants
                    .get(&grant.body.intent_id)
                    .and_then(|g| g.get(&grant.body.approver_credential_id))
                    .is_some_and(|record| {
                        record.grant == *grant
                            && ordered
                                .credentials
                                .get(&grant.body.approver_credential_id)
                                .is_some_and(|credential| {
                                    credential.credential.is_some()
                                        && credential.commit_sequence
                                            == record.credential_commit_sequence
                                })
                    })
            }))
    }
}

#[cfg(target_arch = "wasm32")]
mod browser;
