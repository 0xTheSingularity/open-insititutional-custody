//! Shared fixtures for the builder tests (trimmed from the signer fixture).
//!
//! A complete world: a real authorization-state authority, admin and
//! approver credentials, the in-process EVM and Solana simulators as
//! evidence sources, real crypto backends (dev single-key secp256k1 for EVM,
//! FROST 2-of-3 for Solana), and real `Signer` instances to prove that what
//! the builder produces is accepted by the signer boundary.
#![allow(dead_code)]

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use oic_adapter_api::*;
use oic_approval_verifier::{sign_grant, ApproverCredential};
use oic_authorization_state::*;
use oic_chain_simulator::evm::{EvmSimConfig, EvmSimulator};
use oic_chain_simulator::solana::{SolanaSimConfig, SolanaSimulator};
use oic_chain_simulator::SimClock;
use oic_crypto_provider::*;
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_crypto_provider_frost_ed25519::{run_dkg, FrostEd25519Provider};
use oic_domain_types::*;
use oic_one_time_state_ledger::InMemoryLedger;
use oic_policy_kernel::{destination_hash, intent_hash, policy_hash, Decision};
use oic_service_builder::*;
use oic_signer::*;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const T0: u64 = 1_700_000_000;
pub const NOW: u64 = T0 + 20;
pub const DAY: u64 = 86_400;
pub const DEADLINE: u64 = NOW + 300;
pub const SOL: u64 = 1_000_000_000;

pub fn now() -> UnixSeconds {
    UnixSeconds(NOW)
}
pub fn inst() -> InstitutionId {
    InstitutionId::unchecked("inst")
}
pub fn env_id() -> EnvironmentId {
    EnvironmentId::unchecked("dev")
}
pub fn vault_id() -> VaultId {
    VaultId::unchecked("vault-1")
}
pub fn policy_id() -> PolicyId {
    PolicyId::unchecked("pol-1")
}
pub fn pid(n: u8) -> ParticipantId {
    ParticipantId::unchecked(format!("signer-{n}"))
}
pub fn authority_key_id() -> KeyId {
    KeyId::unchecked("authority-key-1")
}

// ---------------------------------------------------------------------------
// Authority, admins, approvers
// ---------------------------------------------------------------------------

pub struct World {
    pub authority: Arc<Authority<InMemoryAuthorityStore>>,
    pub authority_sk: SigningKey,
    pub admins: Vec<(CredentialId, SigningKey)>,
    pub approvers: Vec<(CredentialId, SigningKey, ApprovalRole)>,
    pub clock: Arc<ManualClock>,
}

impl World {
    pub fn new() -> World {
        let authority_sk = SigningKey::from_bytes(&[42; 32]);
        let admins: Vec<(CredentialId, SigningKey)> =
            (1..=3u8).map(|n| (CredentialId::unchecked(format!("admin-{n}")), SigningKey::from_bytes(&[n; 32]))).collect();
        let approvers = vec![
            (CredentialId::unchecked("approver-1"), SigningKey::from_bytes(&[61; 32]), ApprovalRole::TreasuryApprover),
            (CredentialId::unchecked("approver-2"), SigningKey::from_bytes(&[62; 32]), ApprovalRole::SecurityApprover),
        ];
        let config = AuthorityConfig {
            institution_id: inst(),
            environment_id: env_id(),
            authority_key_id: authority_key_id(),
            admin_keys: admins.iter().map(|(c, k)| (c.clone(), k.verifying_key())).collect(),
            admin_quorum: 2,
            freeze_responders: vec![(CredentialId::unchecked("responder-1"), SigningKey::from_bytes(&[77; 32]).verifying_key())],
            release_receipt_ttl_seconds: 60,
            max_clock_skew_seconds: 30,
        };
        let clock = Arc::new(ManualClock::new(NOW));
        let authority = Arc::new(Authority::open(Arc::new(InMemoryAuthorityStore::new()), 0, config, authority_sk.clone(), clock.clone()).expect("authority open"));
        World { authority, authority_sk, admins, approvers, clock }
    }

    pub fn admin_keys(&self) -> Vec<(CredentialId, VerifyingKey)> {
        self.admins.iter().map(|(c, k)| (c.clone(), k.verifying_key())).collect()
    }

    pub fn approver_credentials(&self) -> Vec<ApproverCredential> {
        self.approvers.iter().map(|(c, k, r)| ApproverCredential { credential_id: c.clone(), person_id: c.clone(), verifying_key: k.verifying_key().into(), role: *r }).collect()
    }

    fn admin_quorum_signatures(&self, h: Hash32) -> Vec<CredentialSignature> {
        self.admins[..2]
            .iter()
            .map(|(c, k)| CredentialSignature {
                credential_id: c.clone(),
                signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(k.sign(&h.0).to_bytes().to_vec()) },
            })
            .collect()
    }

    pub fn sign_policy(&self, mut bundle: PolicyBundle) -> PolicyBundle {
        let h = policy_hash(&bundle).unwrap();
        bundle.administrative_signatures = self.admin_quorum_signatures(h);
        bundle
    }

    pub fn sign_destination(&self, mut d: CounterpartyDestination) -> CounterpartyDestination {
        let h = destination_hash(&d).unwrap();
        d.administrative_signatures = self.admin_quorum_signatures(h);
        d
    }

    pub fn trust_roots(&self, profiles: Vec<ChainProfile>) -> TrustRoots {
        let mut builds = BTreeMap::new();
        builds.insert(AdapterId::unchecked("evm"), vec![oic_adapter_evm::verifier_build_hash()]);
        builds.insert(AdapterId::unchecked("solana"), vec![oic_adapter_solana::verifier_build_hash()]);
        TrustRoots {
            authority_key_id: authority_key_id(),
            authority_pubkey: self.authority_sk.verifying_key(),
            admin_keys: self.admin_keys(),
            admin_quorum: 2,
            approvers: self.approver_credentials(),
            accepted_verifier_builds: builds,
            chain_profiles: profiles,
            max_clock_skew_seconds: 30,
        }
    }

    /// Register policy and intent at the authority.
    pub fn register(&self, policy: &PolicyBundle, intent: &Intent) {
        let (epoch, _) = self.authority.current_policy().unwrap();
        if epoch != policy.policy_epoch {
            self.authority.set_policy(policy).expect("set_policy");
        }
        let reg = self
            .authority
            .register_intent(intent, intent_hash(intent).unwrap(), IdempotencyKey { institution_id: inst(), route: "transfers".into(), key: intent.intent_id.to_string() })
            .expect("register intent");
        assert_eq!(reg.operation_family_id, family_id_for(&intent.intent_id).unwrap());
    }

    fn grant(&self, built: &BuiltCandidate, approver: usize, scope: GrantScope, expires_at: u64) -> ApprovalGrant {
        let (cred, sk, role) = &self.approvers[approver];
        let p = &built.package;
        sign_grant(
            sk,
            ApprovalGrantBody {
                grant_id: GrantId::unchecked(format!("grant-{}-{approver}", p.intent.intent_id)),
                institution_id: inst(),
                environment_id: env_id(),
                vault_id: vault_id(),
                intent_id: p.intent.intent_id.clone(),
                intent_hash: intent_hash(&p.intent).unwrap(),
                policy_id: p.policy.policy_id.clone(),
                policy_epoch: p.policy.policy_epoch,
                scope,
                approver_credential_id: cred.clone(),
                approver_role: *role,
                issued_at: UnixSeconds(T0),
                expires_at: UnixSeconds(expires_at),
            },
        )
        .unwrap()
    }

    pub fn exact_grant(&self, built: &BuiltCandidate, approver: usize) -> ApprovalGrant {
        let scope = GrantScope::ExactCandidate {
            candidate_id: built.candidate.candidate_id.clone(),
            candidate_revision: built.candidate.candidate_revision,
            preview_hash: built.preview_hash,
        };
        self.grant(built, approver, scope, NOW + 3600)
    }

    pub fn bounded_grant(&self, built: &BuiltCandidate, template: BoundedTransferTemplate, approver: usize) -> ApprovalGrant {
        self.grant(built, approver, GrantScope::BoundedDirectTransfer { template }, NOW + 3600)
    }

    /// One grant per required approval, in the scope the intent's mode demands.
    pub fn grants_for(&self, built: &BuiltCandidate, n: usize) -> Vec<ApprovalGrant> {
        (0..n)
            .map(|i| match &built.template {
                Some(t) => self.bounded_grant(built, t.clone(), i),
                None => self.exact_grant(built, i),
            })
            .collect()
    }

    /// Exposure the authority reports for the built candidate's vault/asset under `policy`.
    pub fn exposure(&self, built: &BuiltCandidate, policy: &PolicyBundle) -> oic_policy_kernel::ExposureView {
        let IntentOperation::AssetTransfer { asset_id, .. } = &built.package.intent.operation;
        let windows: Vec<u64> = policy.rules.iter().flat_map(|r| r.rolling_limits.iter().map(|l| l.window_seconds)).collect();
        self.authority.exposure_view(&vault_id(), std::slice::from_ref(asset_id), &windows, now()).unwrap()
    }

    /// Reserve `body` at the authority exactly as the coordinator does.
    pub fn reserve(&self, built: &BuiltCandidate, rule: &PolicyRule, body: AuthorizationEnvelopeBody) -> AuthorizationEnvelope {
        let exposure_limits = built
            .verified
            .claims
            .asset_outflows
            .iter()
            .flat_map(|o| rule.rolling_limits.iter().map(move |l| (o.asset_id.clone(), l.clone())))
            .collect();
        let (_, receipt) = self
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
                envelope_body_hash: envelope_body_hash(&body).unwrap(),
                signer_session_id: body.signer_session_id.clone(),
                issuance_deadline: body.issuance_deadline,
                policy_decision: Decision::Allow { rule_id: rule.rule_id.clone() },
                exposure_limits,
            })
            .expect("authority reserve");
        AuthorizationEnvelope { body, authorization_state_receipt: receipt }
    }
}

pub fn rule(asset: &AssetId, required_approvals: u8, daily_limit: u128) -> PolicyRule {
    PolicyRule {
        rule_id: "r-1".into(),
        vaults: vec![vault_id()],
        assets: vec![asset.clone()],
        destinations: vec![],
        purposes: vec![],
        max_amount_per_operation: Amount(1_000_000_000_000),
        max_native_fee_per_operation: Amount(10u128.pow(18)),
        rolling_limits: vec![ExposureLimit { window_seconds: DAY, max_outflow_base_units: Amount(daily_limit) }],
        required_approvals,
        approval_roles: if required_approvals == 0 {
            vec![ApprovalRole::Automated]
        } else {
            vec![ApprovalRole::TreasuryApprover, ApprovalRole::SecurityApprover]
        },
        exclude_proposer: true,
        operating_window: None,
    }
}

pub fn policy(epoch: u64, rules: Vec<PolicyRule>) -> PolicyBundle {
    PolicyBundle {
        policy_id: policy_id(),
        policy_epoch: Epoch(epoch),
        institution_id: inst(),
        environment_id: env_id(),
        rules,
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 120,
        allowlist_version: 1,
        activation_epoch: Epoch(1),
        administrative_signatures: vec![],
    }
}

pub fn vault() -> Vault {
    Vault {
        vault_id: vault_id(),
        institution_id: inst(),
        environment_id: env_id(),
        tier: VaultTier::Operating,
        policy_id: policy_id(),
        display_name: "Operating".into(),
    }
}

pub fn intent_for(id: &str, wallet: &ChainWallet, asset: &Asset, dest: &CounterpartyDestination, amount: u128, max_fee: u128, mode: ApprovalMode) -> Intent {
    Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked(id),
        institution_id: inst(),
        environment_id: env_id(),
        vault_id: vault_id(),
        chain_wallet_id: wallet.chain_wallet_id.clone(),
        chain_profile_id: wallet.chain_profile_id.clone(),
        operation: IntentOperation::AssetTransfer {
            asset_id: asset.asset_id.clone(),
            amount_base_units: Amount(amount),
            destination_id: dest.destination_id.clone(),
            destination_version: dest.version,
        },
        constraints: IntentConstraints { max_network_fee_base_units: Amount(max_fee), approval_mode: mode, maximum_successful_payments: 1 },
        purpose: OperationPurpose::Settlement,
        external_reference: "ref".into(),
        proposer_credential_id: CredentialId::unchecked("proposer-1"),
        created_at: UnixSeconds(T0 - 100),
    }
}

pub fn wallet_for(adapter: &dyn ChainAdapter, profile: &ChainProfile, key: &KeyDescriptor, id: &str) -> ChainWallet {
    let (address, address_display) = adapter.derive_address(&key.public_key).unwrap();
    ChainWallet {
        chain_wallet_id: ChainWalletId::unchecked(id),
        vault_id: vault_id(),
        chain_profile_id: profile.chain_profile_id.clone(),
        network_id: profile.network_id.clone(),
        key_id: key.key_id.clone(),
        key_epoch: key.key_epoch,
        address,
        address_display,
        active: true,
    }
}

pub fn destination(profile: &ChainProfile, id: &str, address: Vec<u8>, display: String) -> CounterpartyDestination {
    CounterpartyDestination {
        destination_id: DestinationId::unchecked(id),
        version: 2,
        network_id: profile.network_id.clone(),
        address: Bytes(address),
        address_display: display,
        display_name: "Counterparty".into(),
        allowed_assets: vec![],
        verification_evidence: "test".into(),
        activation_epoch: Epoch(1),
        administrative_signatures: vec![],
    }
}

// ---------------------------------------------------------------------------
// Signer nodes
// ---------------------------------------------------------------------------

pub struct Node {
    pub id: ParticipantId,
    pub signer: Arc<Signer>,
    pub ledger: Arc<InMemoryLedger>,
}

pub fn open_node(p: &ParticipantId, roots: TrustRoots, adapter: Arc<dyn ChainAdapter>, provider: Arc<dyn CryptoProvider>) -> Node {
    let mut adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::new();
    adapters.insert(adapter.manifest().adapter_id, adapter);
    let ledger = Arc::new(InMemoryLedger::new());
    let identity = SignerIdentity { participant_id: p.clone(), institution_id: inst(), environment_id: env_id() };
    let signer = Signer::open(identity, roots, adapters, provider, ledger.clone(), Arc::new(InMemoryGenerationStore::new())).expect("signer open");
    Node { id: p.clone(), signer: Arc::new(signer), ledger }
}

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

/// One chain wallet on one simulator, with its key, signers, and registry objects.
pub struct Chain {
    pub profile: ChainProfile,
    pub adapter: Arc<dyn ChainAdapter>,
    pub source: Arc<dyn EvidenceSource>,
    pub key: KeyDescriptor,
    pub wallet: ChainWallet,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub nodes: Vec<Node>,
}

impl Chain {
    pub fn request(&self, commitment: EvidenceCommitment) -> EvidenceRequest {
        EvidenceRequest {
            profile: self.profile.clone(),
            wallet: self.wallet.clone(),
            asset: self.asset.clone(),
            destination: self.destination.clone(),
            commitment,
            lookup_tables: vec![],
        }
    }

    /// Build inputs for `intent` from fresh evidence of the chain's source.
    pub fn inputs(&self, intent: &Intent, policy: &PolicyBundle, candidate: &str) -> BuildInputs {
        let evidence = self.source.evidence(&self.request(EvidenceCommitment::Latest)).expect("evidence");
        BuildInputs {
            intent: intent.clone(),
            vault: vault(),
            wallet: self.wallet.clone(),
            key: self.key.clone(),
            asset: self.asset.clone(),
            destination: self.destination.clone(),
            profile: self.profile.clone(),
            policy: policy.clone(),
            evidence,
            candidate_id: CandidateId::unchecked(candidate),
            candidate_revision: 1,
            operation_family_id: family_id_for(&intent.intent_id).unwrap(),
            built_at: UnixSeconds(T0 + 10),
        }
    }

    pub fn intent(&self, id: &str, amount: u128, max_fee: u128, mode: ApprovalMode) -> Intent {
        intent_for(id, &self.wallet, &self.asset, &self.destination, amount, max_fee, mode)
    }
}

pub struct EvmChain {
    pub chain: Chain,
    pub sim: Arc<EvmSimulator>,
    pub token: [u8; 20],
}

/// EVM simulator with a dev single-key wallet holding ETH and an ERC-20.
pub fn evm_chain(world: &World) -> EvmChain {
    let sim = Arc::new(EvmSimulator::new(EvmSimConfig::with_seed([7; 32]), SimClock::new(UnixSeconds(T0))).unwrap());
    let profile = sim.profile();
    let p1 = pid(1);
    let dev = Arc::new(DevSingleKeyProvider::with_os_rng(SchemeId::EcdsaSecp256k1Keccak256Prehashed, [9; 32]).unwrap());
    let keygen = dev
        .generate_distributed_key(&KeygenCeremony {
            key_id: KeyId::unchecked("key-evm"),
            key_epoch: Epoch(1),
            institution_id: inst(),
            environment_id: env_id(),
            participants: vec![p1.clone()],
            threshold: 1,
            networks: vec![profile.network_id.clone()],
            recovery_profile: "none".into(),
        })
        .unwrap();
    let key = keygen.descriptor.clone();
    let adapter: Arc<dyn ChainAdapter> = Arc::new(oic_adapter_evm::EvmAdapter);
    let wallet = wallet_for(adapter.as_ref(), &profile, &key, "wallet-evm");
    let sender: [u8; 20] = wallet.address.as_slice().try_into().unwrap();
    sim.fund(sender, 10u128.pow(18)).unwrap();
    let token = sim.deploy_erc20("USDC", 6, sender, 1_000_000_000_000).unwrap();
    sim.mine().unwrap();
    let asset = Asset {
        asset_id: AssetId::unchecked("devsim-usdc"),
        network_id: profile.network_id.clone(),
        asset: AssetKind::Erc20 { contract: Bytes(token.to_vec()) },
        decimals: 6,
        symbol: "USDC".into(),
        behavior: AssetBehaviorProfile::Standard,
    };
    let dest_addr = [0xde; 20];
    let destination = world.sign_destination(destination(&profile, "dest-evm", dest_addr.to_vec(), oic_adapter_evm::address::eip55(&dest_addr)));
    let node = open_node(&p1, world.trust_roots(vec![profile.clone()]), adapter.clone(), dev.clone());
    node.signer.load_key(&key, &keygen.sealed_shares[0].1).unwrap();
    let chain = Chain { profile, adapter, source: Arc::new(EvmSimulatorEvidence(sim.clone())), key, wallet, asset, destination, nodes: vec![node] };
    EvmChain { chain, sim, token }
}

pub struct SolChain {
    pub chain: Chain,
    pub sim: Arc<SolanaSimulator>,
    pub mint: Option<[u8; 32]>,
}

pub fn sol_dest_owner() -> [u8; 32] {
    SigningKey::from_bytes(&[0x77; 32]).verifying_key().to_bytes()
}

/// Solana simulator with a FROST 2-of-3 wallet holding SOL; with `spl`, also
/// a registered SPL mint and a funded source ATA (destination ATA absent).
pub fn sol_chain(world: &World, spl: bool) -> SolChain {
    let sim = Arc::new(SolanaSimulator::new(SolanaSimConfig::with_seed([3; 32]), SimClock::new(UnixSeconds(T0))).unwrap());
    let profile = sim.profile();
    let ids: Vec<ParticipantId> = (1..=3).map(pid).collect();
    let providers: Vec<Arc<FrostEd25519Provider>> =
        ids.iter().enumerate().map(|(i, p)| Arc::new(FrostEd25519Provider::with_os_rng(p.clone(), [0x50 + i as u8; 32]).unwrap())).collect();
    let refs: Vec<&FrostEd25519Provider> = providers.iter().map(|p| p.as_ref()).collect();
    let dkg = run_dkg(
        &refs,
        &KeygenCeremony {
            key_id: KeyId::unchecked("key-sol"),
            key_epoch: Epoch(1),
            institution_id: inst(),
            environment_id: env_id(),
            participants: ids.clone(),
            threshold: 2,
            networks: vec![profile.network_id.clone()],
            recovery_profile: "dkg".into(),
        },
    )
    .unwrap();
    let key = dkg.descriptor.clone();
    let adapter: Arc<dyn ChainAdapter> = Arc::new(oic_adapter_solana::SolanaAdapter);
    let wallet = wallet_for(adapter.as_ref(), &profile, &key, "wallet-sol");
    let wallet_pk: [u8; 32] = wallet.address.as_slice().try_into().unwrap();
    sim.airdrop(&wallet_pk, 10 * SOL).unwrap();
    let (asset, mint) = if spl {
        let mint = sim.create_mint(6, b"usdc-authority").unwrap();
        let src = sim.create_ata(&wallet_pk, &mint).unwrap();
        sim.mint_to(&mint, &src, 10_000_000).unwrap();
        let asset = Asset {
            asset_id: AssetId::unchecked("devsim-spl-usdc"),
            network_id: profile.network_id.clone(),
            asset: AssetKind::SplToken { mint: Bytes(mint.to_vec()), token_program: Bytes(oic_adapter_solana::address::TOKEN_PROGRAM_ID.to_vec()) },
            decimals: 6,
            symbol: "USDC".into(),
            behavior: AssetBehaviorProfile::Standard,
        };
        (asset, Some(mint))
    } else {
        let asset = Asset {
            asset_id: AssetId::unchecked("devsim-sol"),
            network_id: profile.network_id.clone(),
            asset: AssetKind::Native,
            decimals: 9,
            symbol: "SOL".into(),
            behavior: AssetBehaviorProfile::Standard,
        };
        (asset, None)
    };
    sim.advance_slot().unwrap();
    let owner = sol_dest_owner();
    let destination = world.sign_destination(destination(&profile, "dest-sol", owner.to_vec(), oic_adapter_solana::address::to_base58(&owner)));
    let mut nodes = Vec::new();
    for (i, p) in ids.iter().enumerate() {
        let node = open_node(p, world.trust_roots(vec![profile.clone()]), adapter.clone(), providers[i].clone());
        let sealed = &dkg.sealed_shares.iter().find(|(q, _)| q == p).unwrap().1;
        node.signer.load_key(&key, sealed).unwrap();
        nodes.push(node);
    }
    for a in &nodes {
        for b in &nodes {
            if a.id != b.id {
                a.signer.set_peer_generation(&b.id, b.signer.generation()).unwrap();
            }
        }
    }
    let chain = Chain { profile, adapter, source: Arc::new(SolanaSimulatorEvidence(sim.clone())), key, wallet, asset, destination, nodes };
    SolChain { chain, sim, mint }
}
