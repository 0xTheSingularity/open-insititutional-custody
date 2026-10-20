//! Shared fixtures for the signer acceptance tests.
//!
//! Each test builds a complete world: a real authorization-state authority
//! (receipts are genuine), real chain adapters, real crypto backends
//! (dev single-key secp256k1 for EVM, FROST 2-of-3 for Solana), real
//! one-time-state ledgers, and one or more `Signer` instances. The "coordinator"
//! role is played by the test code below; it is untrusted by construction.
#![allow(dead_code)]

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use oic_adapter_api::*;
use oic_approval_verifier::{sign_grant, ApproverCredential};
use oic_authorization_state::*;
use oic_canonical_encoding::sha256;
use oic_crypto_provider::*;
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_crypto_provider_frost_ed25519::{build_signing_package, run_dkg, FrostEd25519Provider};
use oic_domain_types::*;
use oic_one_time_state_ledger::InMemoryLedger;
use oic_policy_kernel::{intent_hash, policy_hash, preview_hash, Decision};
use oic_signer::*;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

pub const T0: u64 = 1_700_000_000;
pub const NOW: u64 = T0 + 20;
pub const DAY: u64 = 86_400;
pub const DEADLINE: u64 = NOW + 300;

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
pub fn sid(s: &str) -> SigningSessionId {
    SigningSessionId::unchecked(s)
}

// ---------------------------------------------------------------------------
// Authority, admins, approvers
// ---------------------------------------------------------------------------

pub struct World {
    pub authority: Authority<InMemoryAuthorityStore>,
    pub authority_sk: SigningKey,
    pub admins: Vec<(CredentialId, SigningKey)>,
    pub approvers: Vec<(CredentialId, SigningKey, ApprovalRole)>,
    pub clock: Arc<ManualClock>,
}

pub fn authority_key_id() -> KeyId {
    KeyId::unchecked("authority-key-1")
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
        let authority = Authority::open(Arc::new(InMemoryAuthorityStore::new()), 0, config, authority_sk.clone(), clock.clone()).expect("authority open");
        World { authority, authority_sk, admins, approvers, clock }
    }

    pub fn admin_keys(&self) -> Vec<(CredentialId, VerifyingKey)> {
        self.admins.iter().map(|(c, k)| (c.clone(), k.verifying_key())).collect()
    }

    pub fn approver_credentials(&self) -> Vec<ApproverCredential> {
        self.approvers
            .iter()
            .map(|(c, k, r)| ApproverCredential { credential_id: c.clone(), verifying_key: k.verifying_key(), role: *r })
            .collect()
    }

    pub fn sign_policy(&self, mut bundle: PolicyBundle) -> PolicyBundle {
        let h = policy_hash(&bundle).unwrap();
        bundle.administrative_signatures = self.admins[..2]
            .iter()
            .map(|(c, k)| CredentialSignature {
                credential_id: c.clone(),
                signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(k.sign(&h.0).to_bytes().to_vec()) },
            })
            .collect();
        bundle
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

    /// A receipt with a genuine authority signature over an arbitrary body
    /// (models a receipt the real authority issued for some other context).
    pub fn craft_receipt(&self, body: AuthorityReceiptBody) -> AuthorityReceipt {
        let h = receipt_hash(&body).unwrap();
        AuthorityReceipt {
            body,
            authority_key_id: authority_key_id(),
            signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(self.authority_sk.sign(&h.0).to_bytes().to_vec()) },
        }
    }

    pub fn release(&self, env: &AuthorizationEnvelope) -> AuthorityReceipt {
        let (r, _) = self
            .authority
            .release(ReleaseRequest {
                reservation_id: env.body.budget_reservation_id.clone(),
                reservation_version: env.body.reservation_version,
                envelope_body_hash: envelope_body_hash(&env.body).unwrap(),
                signer_session_id: env.body.signer_session_id.clone(),
                expected_policy_epoch: env.body.policy_epoch,
                freshness: FreshnessContext { now: now() },
            })
            .expect("authority release");
        r
    }
}

pub fn rule(asset: &AssetId, required_approvals: u8) -> PolicyRule {
    PolicyRule {
        rule_id: "r-1".into(),
        vaults: vec![vault_id()],
        assets: vec![asset.clone()],
        destinations: vec![],
        purposes: vec![],
        max_amount_per_operation: Amount(1_000_000_000_000),
        max_native_fee_per_operation: Amount(10u128.pow(18)),
        rolling_limits: vec![ExposureLimit { window_seconds: DAY, max_outflow_base_units: Amount(10_000_000_000_000) }],
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

pub fn intent_for(wallet: &ChainWallet, asset: &Asset, dest: &CounterpartyDestination, amount: u128, max_fee: u128, mode: ApprovalMode) -> Intent {
    Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked("intent-1"),
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

// ---------------------------------------------------------------------------
// Chain setup (profile + adapter + materials) and envelope construction
// ---------------------------------------------------------------------------

pub struct Setup {
    pub profile: ChainProfile,
    pub adapter: Arc<dyn ChainAdapter>,
    pub m: SigningMaterials,
}

pub fn family() -> OperationFamilyId {
    family_id_for(&IntentId::unchecked("intent-1")).unwrap()
}

pub fn build_ctx(s: &Setup, m: &SigningMaterials) -> BuildContext {
    BuildContext {
        intent: m.intent.clone(),
        wallet: m.wallet.clone(),
        key: m.key.clone(),
        asset: m.asset.clone(),
        destination: m.destination.clone(),
        profile: s.profile.clone(),
        evidence: m.evidence.clone(),
        candidate_id: CandidateId::unchecked("cand-1"),
        candidate_revision: 1,
        operation_family_id: family(),
        built_at: UnixSeconds(T0 + 10),
    }
}

impl Setup {
    /// Register policy + intent at the authority and build the candidate.
    pub fn new(world: &World, profile: ChainProfile, adapter: Arc<dyn ChainAdapter>, mut m: SigningMaterials) -> Setup {
        world.authority.set_policy(&m.policy).expect("set_policy");
        let ih = intent_hash(&m.intent).unwrap();
        let reg = world
            .authority
            .register_intent(&m.intent, ih, IdempotencyKey { institution_id: inst(), route: "transfers".into(), key: "idem-1".into() })
            .expect("register intent");
        assert_eq!(reg.operation_family_id, family());
        let mut s = Setup { profile, adapter, m: m.clone() };
        m.candidate = s.adapter.build_candidate(&build_ctx(&s, &m)).expect("build candidate");
        s.m = m;
        s
    }

    pub fn vctx<'a>(&'a self, m: &'a SigningMaterials) -> VerifyContext<'a> {
        VerifyContext { profile: &self.profile, wallet: &m.wallet, key: &m.key, asset: &m.asset, destination: &m.destination, evidence: &m.evidence }
    }

    pub fn verify_for(&self, m: &SigningMaterials) -> VerifiedOperation {
        self.adapter.verify_candidate(&m.candidate, &AuthorizationTarget::Intent(&m.intent), &self.vctx(m)).expect("coordinator-side verify")
    }

    pub fn verify(&self) -> VerifiedOperation {
        self.verify_for(&self.m)
    }

    pub fn exact_grant(&self, world: &World, m: &SigningMaterials, verified: &VerifiedOperation, approver: usize, expires_at: u64) -> ApprovalGrant {
        let (cred, sk, role) = &world.approvers[approver];
        let ph = preview_hash(&m.candidate.candidate_id, m.candidate.candidate_revision, verified.decoded_operation_hash, m.candidate.evidence_bundle_hash);
        sign_grant(
            sk,
            ApprovalGrantBody {
                grant_id: GrantId::unchecked(format!("grant-{approver}")),
                institution_id: inst(),
                environment_id: env_id(),
                vault_id: vault_id(),
                intent_id: m.intent.intent_id.clone(),
                intent_hash: intent_hash(&m.intent).unwrap(),
                policy_id: m.policy.policy_id.clone(),
                policy_epoch: m.policy.policy_epoch,
                scope: GrantScope::ExactCandidate {
                    candidate_id: m.candidate.candidate_id.clone(),
                    candidate_revision: m.candidate.candidate_revision,
                    preview_hash: ph,
                },
                approver_credential_id: cred.clone(),
                approver_role: *role,
                issued_at: UnixSeconds(T0),
                expires_at: UnixSeconds(expires_at),
            },
        )
        .unwrap()
    }

    /// Grants for the policy's first rule (one per required approval).
    pub fn grants_for(&self, world: &World, m: &SigningMaterials, verified: &VerifiedOperation) -> Vec<ApprovalGrant> {
        (0..usize::from(m.policy.rules[0].required_approvals)).map(|i| self.exact_grant(world, m, verified, i, NOW + 3600)).collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn body_for(
        &self,
        m: &SigningMaterials,
        verified: &VerifiedOperation,
        grants: Vec<ApprovalGrant>,
        session: &str,
        participants: Vec<ParticipantId>,
        deadline: u64,
    ) -> AuthorizationEnvelopeBody {
        let c = &m.candidate;
        let manifest = self.adapter.manifest();
        AuthorizationEnvelopeBody {
            institution_id: inst(),
            environment_id: env_id(),
            vault_id: m.vault.vault_id.clone(),
            chain_wallet_id: m.wallet.chain_wallet_id.clone(),
            intent_id: m.intent.intent_id.clone(),
            intent_hash: intent_hash(&m.intent).unwrap(),
            operation_family_id: c.operation_family_id.clone(),
            candidate_id: c.candidate_id.clone(),
            candidate_revision: c.candidate_revision,
            chain_profile_id: self.profile.chain_profile_id.clone(),
            chain_profile_hash: self.profile.hash().unwrap(),
            key_id: m.key.key_id.clone(),
            key_epoch: m.key.key_epoch,
            public_key_hash: public_key_hash(&m.key.public_key).unwrap(),
            adapter_id: c.adapter_id.clone(),
            adapter_version: manifest.adapter_version,
            verifier_build_hash: manifest.verifier_build_hash,
            policy_id: m.policy.policy_id.clone(),
            policy_epoch: m.policy.policy_epoch,
            policy_hash: policy_hash(&m.policy).unwrap(),
            allowlist_version: m.policy.allowlist_version,
            native_unsigned_bytes: c.native_unsigned_bytes.clone(),
            native_signing_payloads: verified.signing_payloads.clone(),
            decoded_operation_hash: verified.decoded_operation_hash,
            evidence_bundle_hash: c.evidence_bundle_hash,
            approval_grants: grants,
            budget_reservation_id: reservation_id_for(&c.operation_family_id, &c.candidate_id, c.candidate_revision).unwrap(),
            reservation_version: 1,
            resource_reservations: verified.claims.resources.clone(),
            maximum_asset_outflows: verified.claims.asset_outflows.clone(),
            maximum_native_fees: verified.claims.native_fees.clone(),
            issuance_deadline: UnixSeconds(deadline),
            expected_chain_validity_constraints: self.adapter.validity_constraints(c, &m.evidence).unwrap(),
            signer_session_id: sid(session),
            participant_set: participants,
        }
    }

    /// Reserve `body` at the authority and return the complete envelope. The
    /// coordinator passes `Allow` for the policy's first rule: the authority
    /// checks binding, approver count, and limits, not native bytes — which is
    /// exactly why the signer re-verifies everything.
    pub fn reserve(&self, world: &World, body: AuthorizationEnvelopeBody, verified: &VerifiedOperation) -> AuthorizationEnvelope {
        let rule = &self.m.policy.rules[0];
        let exposure_limits = verified
            .claims
            .asset_outflows
            .iter()
            .flat_map(|o| rule.rolling_limits.iter().map(move |l| (o.asset_id.clone(), l.clone())))
            .collect();
        let (_, receipt) = world
            .authority
            .reserve(ReserveRequest {
                family_id: body.operation_family_id.clone(),
                candidate_id: body.candidate_id.clone(),
                candidate_revision: body.candidate_revision,
                vault_id: body.vault_id.clone(),
                intent_id: body.intent_id.clone(),
                policy_epoch: body.policy_epoch,
                policy_hash: body.policy_hash,
                claims: verified.claims.clone(),
                grants: body.approval_grants.clone(),
                envelope_body_hash: envelope_body_hash(&body).unwrap(),
                signer_session_id: body.signer_session_id.clone(),
                issuance_deadline: body.issuance_deadline,
                policy_decision: Decision::Allow { rule_id: rule.rule_id.clone() },
                exposure_limits,
            })
            .expect("authority reserve");
        assert_eq!(receipt.body.kind, ReceiptKind::Reserved);
        AuthorizationEnvelope { body, authorization_state_receipt: receipt }
    }

    /// Happy-path envelope for `self.m` with the grants the rule requires.
    pub fn authorize(&self, world: &World, session: &str, participants: Vec<ParticipantId>) -> AuthorizationEnvelope {
        self.authorize_with_deadline(world, session, participants, DEADLINE)
    }

    pub fn authorize_with_deadline(&self, world: &World, session: &str, participants: Vec<ParticipantId>, deadline: u64) -> AuthorizationEnvelope {
        let verified = self.verify();
        let grants = self.grants_for(world, &self.m, &verified);
        let body = self.body_for(&self.m, &verified, grants, session, participants, deadline);
        self.reserve(world, body, &verified)
    }
}

// ---------------------------------------------------------------------------
// Signer nodes
// ---------------------------------------------------------------------------

pub struct Node {
    pub id: ParticipantId,
    pub signer: Signer,
    pub ledger: Arc<InMemoryLedger>,
    pub store: Arc<InMemoryGenerationStore>,
    pub events: Arc<Mutex<Vec<SignerEvent>>>,
}

impl Node {
    pub fn events(&self) -> Vec<SignerEvent> {
        self.events.lock().unwrap().clone()
    }

    /// True when no one-time record in this node's ledger is bound to any message.
    pub fn nothing_consumed(&self) -> bool {
        self.ledger.snapshot().iter().all(|r| r.bound_message_hash.is_none())
    }
}

pub fn identity(p: &ParticipantId) -> SignerIdentity {
    SignerIdentity { participant_id: p.clone(), institution_id: inst(), environment_id: env_id() }
}

pub fn open_node(
    p: &ParticipantId,
    roots: TrustRoots,
    adapter: Arc<dyn ChainAdapter>,
    provider: Arc<dyn CryptoProvider>,
    ledger: Arc<InMemoryLedger>,
    store: Arc<InMemoryGenerationStore>,
) -> Node {
    let mut adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::new();
    adapters.insert(adapter.manifest().adapter_id, adapter);
    let events = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let signer = Signer::open(identity(p), roots, adapters, provider, ledger.clone(), store.clone())
        .expect("signer open")
        .with_event_sink(Arc::new(move |e| ev.lock().unwrap().push(e)));
    Node { id: p.clone(), signer, ledger, store, events }
}

// ---------------------------------------------------------------------------
// EVM case: ERC-20 transfer, dev single-key secp256k1 backend
// ---------------------------------------------------------------------------

pub const EVM_CHAIN_ID: u64 = 11_155_111;
pub const EVM_NONCE: u64 = 5;

pub fn evm_profile() -> ChainProfile {
    ChainProfile {
        chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
        adapter_id: AdapterId::unchecked("evm"),
        network_id: NetworkId::unchecked("evm-11155111"),
        network_binding: oic_adapter_evm::network_binding_for_chain_id(EVM_CHAIN_ID),
        display_name: "Sepolia".into(),
        accepted_versions: vec![oic_adapter_evm::VERSION_TYPE2.to_string()],
        finality_commitment: "finalized".into(),
        finality_depth: 2,
        max_evidence_age_seconds: 120,
        accepted_trust_levels: vec![EvidenceTrustLevel::DevelopmentSimulator],
    }
}

pub fn token_contract() -> [u8; 20] {
    [0xc0; 20]
}

pub fn erc20_asset(contract: [u8; 20]) -> Asset {
    Asset {
        asset_id: AssetId::unchecked("sepolia-usdc"),
        network_id: NetworkId::unchecked("evm-11155111"),
        asset: AssetKind::Erc20 { contract: Bytes(contract.to_vec()) },
        decimals: 6,
        symbol: "USDC".into(),
        behavior: AssetBehaviorProfile::Standard,
    }
}

pub fn evm_destination(addr: [u8; 20]) -> CounterpartyDestination {
    CounterpartyDestination {
        destination_id: DestinationId::unchecked("dest-1"),
        version: 3,
        network_id: NetworkId::unchecked("evm-11155111"),
        address: Bytes(addr.to_vec()),
        address_display: oic_adapter_evm::address::eip55(&addr),
        display_name: "Counterparty".into(),
        allowed_assets: vec![],
        verification_evidence: "test".into(),
        activation_epoch: Epoch(1),
    }
}

pub fn evm_evidence(sender: &[u8; 20], nonce: u64) -> EvidenceBundle {
    use oic_adapter_evm::evidence::*;
    let mut items = BTreeMap::new();
    items.insert(nonce_key(sender), Bytes(nonce.to_be_bytes().to_vec()));
    items.insert(KEY_BASE_FEE.to_string(), Bytes(10_000_000_000u128.to_be_bytes().to_vec()));
    items.insert(KEY_PRIORITY_FEE.to_string(), Bytes(1_000_000_000u128.to_be_bytes().to_vec()));
    items.insert(KEY_GAS_LIMIT.to_string(), Bytes(65_000u64.to_be_bytes().to_vec()));
    items.insert(KEY_CHAIN_ID.to_string(), Bytes(EVM_CHAIN_ID.to_be_bytes().to_vec()));
    items.insert(code_key(&token_contract()), Bytes(vec![0xab; 32]));
    EvidenceBundle {
        chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
        network_id: NetworkId::unchecked("evm-11155111"),
        state: StateReference { height: 1000, hash: Bytes(vec![7; 32]), commitment: "finalized".into() },
        sources: vec![EvidenceSourceId::unchecked("dev-node")],
        trust_level: EvidenceTrustLevel::DevelopmentSimulator,
        observed_at: UnixSeconds(T0),
        max_staleness_seconds: 60,
        verifier_version: "test".into(),
        items,
    }
}

pub struct EvmCase {
    pub world: World,
    pub setup: Setup,
    pub node: Node,
    pub key: KeyDescriptor,
    pub sealed: Bytes,
    pub dev: Arc<DevSingleKeyProvider>,
}

pub fn evm_key(dev: &DevSingleKeyProvider, p: &ParticipantId) -> (KeyDescriptor, Bytes) {
    let r = dev
        .generate_distributed_key(&KeygenCeremony {
            key_id: KeyId::unchecked("key-evm"),
            key_epoch: Epoch(1),
            institution_id: inst(),
            environment_id: env_id(),
            participants: vec![p.clone()],
            threshold: 1,
            networks: vec![NetworkId::unchecked("evm-11155111")],
            recovery_profile: "none".into(),
        })
        .expect("dev keygen");
    (r.descriptor, r.sealed_shares[0].1.clone())
}

pub fn evm_wallet(key: &KeyDescriptor) -> ChainWallet {
    let (address, address_display) = oic_adapter_evm::EvmAdapter.derive_address(&key.public_key).unwrap();
    ChainWallet {
        chain_wallet_id: ChainWalletId::unchecked("wallet-evm"),
        vault_id: vault_id(),
        chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
        network_id: NetworkId::unchecked("evm-11155111"),
        key_id: key.key_id.clone(),
        key_epoch: key.key_epoch,
        address,
        address_display,
        active: true,
    }
}

pub fn evm_sender(wallet: &ChainWallet) -> [u8; 20] {
    wallet.address.as_slice().try_into().unwrap()
}

/// Candidate slot before `Setup::new` builds the real one.
pub fn unbuilt_candidate(adapter: &str) -> Candidate {
    Candidate {
        candidate_id: CandidateId::unchecked("unbuilt"),
        candidate_revision: 0,
        intent_id: IntentId::unchecked("unbuilt"),
        operation_family_id: family(),
        chain_profile_id: ChainProfileId::unchecked("unbuilt"),
        adapter_id: AdapterId::unchecked(adapter),
        adapter_version: String::new(),
        native_unsigned_bytes: Bytes(vec![]),
        signing_payloads: vec![],
        evidence_bundle_hash: Hash32::ZERO,
        built_at: UnixSeconds(0),
    }
}

/// EVM materials for `key` (candidate filled in by `Setup::new`).
pub fn evm_materials(key: &KeyDescriptor, required_approvals: u8) -> SigningMaterials {
    let wallet = evm_wallet(key);
    let asset = erc20_asset(token_contract());
    let destination = evm_destination([0xde; 20]);
    let intent = intent_for(&wallet, &asset, &destination, 1_000_000, 10u128.pow(16), ApprovalMode::ExactCandidate);
    let evidence = evm_evidence(&evm_sender(&wallet), EVM_NONCE);
    let policy = policy(1, vec![rule(&asset.asset_id, required_approvals)]);
    SigningMaterials {
        intent,
        candidate: unbuilt_candidate("evm"),
        vault: vault(),
        wallet,
        key: key.clone(),
        asset,
        destination,
        policy,
        evidence,
    }
}

pub fn evm_case(required_approvals: u8) -> EvmCase {
    evm_case_with(required_approvals, Arc::new(InMemoryLedger::new()), |d| d)
}

/// Build an EVM case with a custom ledger and an optional provider wrapper.
pub fn evm_case_with(
    required_approvals: u8,
    ledger: Arc<InMemoryLedger>,
    wrap: impl FnOnce(Arc<DevSingleKeyProvider>) -> Arc<dyn CryptoProvider>,
) -> EvmCase {
    let world = World::new();
    let p1 = pid(1);
    let dev = Arc::new(DevSingleKeyProvider::with_os_rng(SchemeId::EcdsaSecp256k1Keccak256Prehashed, [9; 32]).unwrap());
    let (key, sealed) = evm_key(&dev, &p1);
    let mut m = evm_materials(&key, required_approvals);
    m.policy = world.sign_policy(m.policy);
    let setup = Setup::new(&world, evm_profile(), Arc::new(oic_adapter_evm::EvmAdapter), m);
    let provider = wrap(dev.clone());
    let node = open_node(&p1, world.trust_roots(vec![evm_profile()]), setup.adapter.clone(), provider, ledger, Arc::new(InMemoryGenerationStore::new()));
    node.signer.load_key(&key, &sealed).expect("load key");
    EvmCase { world, setup, node, key, sealed, dev }
}

/// The dev backend's single release message: SHA-256 of the payload digest.
pub fn dev_release_msg(node: &Node, env: &AuthorizationEnvelope) -> PeerMessage {
    PeerMessage {
        session_id: env.body.signer_session_id.clone(),
        key_id: env.body.key_id.clone(),
        key_epoch: env.body.key_epoch,
        from: node.id.clone(),
        from_generation: node.signer.generation(),
        to: None,
        round: 1,
        sequence: 1,
        protocol_version: oic_crypto_provider_dev::PROTOCOL_VERSION.into(),
        payload: Bytes(sha256(env.body.native_signing_payloads[0].message_or_digest.as_slice()).0.to_vec()),
    }
}

// ---------------------------------------------------------------------------
// Solana case: native SOL transfer, FROST(Ed25519) 2-of-3 across three signers
// ---------------------------------------------------------------------------

pub const SOL_GENESIS: [u8; 32] = [0x6e; 32];
pub const SOL_BLOCKHASH: [u8; 32] = [0xbb; 32];

pub fn sol_profile() -> ChainProfile {
    ChainProfile {
        chain_profile_id: ChainProfileId::unchecked("solana-devnet-v1"),
        adapter_id: AdapterId::unchecked("solana"),
        network_id: NetworkId::unchecked("solana-devnet"),
        network_binding: Bytes(SOL_GENESIS.to_vec()),
        display_name: "Solana devnet".into(),
        accepted_versions: vec![oic_adapter_solana::VERSION_LEGACY.to_string(), oic_adapter_solana::VERSION_V0.to_string()],
        finality_commitment: "finalized".into(),
        finality_depth: 32,
        max_evidence_age_seconds: 120,
        accepted_trust_levels: vec![EvidenceTrustLevel::DevelopmentSimulator],
    }
}

pub fn sol_asset() -> Asset {
    Asset {
        asset_id: AssetId::unchecked("devnet-sol"),
        network_id: NetworkId::unchecked("solana-devnet"),
        asset: AssetKind::Native,
        decimals: 9,
        symbol: "SOL".into(),
        behavior: AssetBehaviorProfile::Standard,
    }
}

pub fn sol_dest_owner() -> [u8; 32] {
    SigningKey::from_bytes(&[0x77; 32]).verifying_key().to_bytes()
}

pub fn sol_destination() -> CounterpartyDestination {
    CounterpartyDestination {
        destination_id: DestinationId::unchecked("dest-sol"),
        version: 2,
        network_id: NetworkId::unchecked("solana-devnet"),
        address: Bytes(sol_dest_owner().to_vec()),
        address_display: oic_adapter_solana::address::to_base58(&sol_dest_owner()),
        display_name: "Counterparty".into(),
        allowed_assets: vec![],
        verification_evidence: "test".into(),
        activation_epoch: Epoch(1),
    }
}

pub fn sol_evidence() -> EvidenceBundle {
    use oic_adapter_solana::evidence::*;
    let le = |v: u64| Bytes(v.to_le_bytes().to_vec());
    let mut items = BTreeMap::new();
    items.insert(KEY_GENESIS_HASH.to_string(), Bytes(SOL_GENESIS.to_vec()));
    items.insert(KEY_RECENT_BLOCKHASH.to_string(), Bytes(SOL_BLOCKHASH.to_vec()));
    items.insert(KEY_BLOCKHASH_LAST_VALID_HEIGHT.to_string(), le(1_150));
    items.insert(KEY_LAMPORTS_PER_SIGNATURE.to_string(), le(5_000));
    items.insert(KEY_RENT_TOKEN_ACCOUNT.to_string(), le(2_039_280));
    EvidenceBundle {
        chain_profile_id: ChainProfileId::unchecked("solana-devnet-v1"),
        network_id: NetworkId::unchecked("solana-devnet"),
        state: StateReference { height: 1_000, hash: Bytes(vec![7; 32]), commitment: "finalized".into() },
        sources: vec![EvidenceSourceId::unchecked("dev-node")],
        trust_level: EvidenceTrustLevel::DevelopmentSimulator,
        observed_at: UnixSeconds(T0),
        max_staleness_seconds: 60,
        verifier_version: "test".into(),
        items,
    }
}

pub fn sol_wallet(key: &KeyDescriptor) -> ChainWallet {
    let (address, address_display) = oic_adapter_solana::SolanaAdapter.derive_address(&key.public_key).unwrap();
    ChainWallet {
        chain_wallet_id: ChainWalletId::unchecked("wallet-sol"),
        vault_id: vault_id(),
        chain_profile_id: ChainProfileId::unchecked("solana-devnet-v1"),
        network_id: NetworkId::unchecked("solana-devnet"),
        key_id: key.key_id.clone(),
        key_epoch: key.key_epoch,
        address,
        address_display,
        active: true,
    }
}

pub fn sol_materials(key: &KeyDescriptor, required_approvals: u8, mode: ApprovalMode) -> SigningMaterials {
    let wallet = sol_wallet(key);
    let asset = sol_asset();
    let destination = sol_destination();
    let intent = intent_for(&wallet, &asset, &destination, 1_000_000, 10_000_000, mode);
    let policy = policy(1, vec![rule(&asset.asset_id, required_approvals)]);
    SigningMaterials {
        intent,
        candidate: unbuilt_candidate("solana"),
        vault: vault(),
        wallet,
        key: key.clone(),
        asset,
        destination,
        policy,
        evidence: sol_evidence(),
    }
}

pub struct SolCase {
    pub world: World,
    pub setup: Setup,
    pub nodes: Vec<Node>,
    pub providers: Vec<Arc<FrostEd25519Provider>>,
    pub key: KeyDescriptor,
    pub sealed: Vec<(ParticipantId, Bytes)>,
}

pub fn sealing_key(n: u8) -> [u8; 32] {
    [0x50 + n; 32]
}

pub fn sol_case(required_approvals: u8) -> SolCase {
    sol_case_mode(required_approvals, ApprovalMode::ExactCandidate)
}

pub fn sol_case_mode(required_approvals: u8, mode: ApprovalMode) -> SolCase {
    let world = World::new();
    let ids: Vec<ParticipantId> = (1..=3).map(pid).collect();
    let providers: Vec<Arc<FrostEd25519Provider>> =
        ids.iter().enumerate().map(|(i, p)| Arc::new(FrostEd25519Provider::with_os_rng(p.clone(), sealing_key(i as u8 + 1)).unwrap())).collect();
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
            networks: vec![NetworkId::unchecked("solana-devnet")],
            recovery_profile: "dkg".into(),
        },
    )
    .expect("FROST DKG");
    let key = dkg.descriptor.clone();
    let mut m = sol_materials(&key, required_approvals, mode);
    m.policy = world.sign_policy(m.policy);
    let setup = Setup::new(&world, sol_profile(), Arc::new(oic_adapter_solana::SolanaAdapter), m);
    let mut nodes = Vec::new();
    for (i, p) in ids.iter().enumerate() {
        let node = open_node(
            p,
            world.trust_roots(vec![sol_profile()]),
            setup.adapter.clone(),
            providers[i].clone(),
            Arc::new(InMemoryLedger::new()),
            Arc::new(InMemoryGenerationStore::new()),
        );
        let sealed = &dkg.sealed_shares.iter().find(|(q, _)| q == p).unwrap().1;
        node.signer.load_key(&key, sealed).expect("load FROST share");
        nodes.push(node);
    }
    for a in &nodes {
        for b in &nodes {
            if a.id != b.id {
                a.signer.set_peer_generation(&b.id, b.signer.generation()).unwrap();
            }
        }
    }
    SolCase { world, setup, nodes, providers, key, sealed: dkg.sealed_shares }
}

/// In-memory authenticated transport between signer nodes: broadcast
/// messages reach every other node in the session, addressed ones only
/// their recipient. Records round-1 commitments for the coordinator.
#[derive(Default)]
pub struct Transport {
    pub queue: VecDeque<PeerMessage>,
    pub commitments: BTreeMap<ParticipantId, Bytes>,
}

impl Transport {
    pub fn post(&mut self, step: ProtocolStep) {
        match step {
            ProtocolStep::Send(msgs) => {
                for m in msgs {
                    if m.round == 1 {
                        self.commitments.insert(m.from.clone(), m.payload.clone());
                    }
                    self.queue.push_back(m);
                }
            }
            ProtocolStep::Waiting => {}
            other => panic!("unexpected step on transport: {other:?}"),
        }
    }

    /// Deliver everything queued to `nodes` (those in `members`), returning
    /// per-delivery results.
    pub fn pump(&mut self, nodes: &[&Node], members: &[ParticipantId]) -> Vec<(ParticipantId, OicResult<ProtocolStep>)> {
        let mut out = Vec::new();
        while let Some(m) = self.queue.pop_front() {
            for n in nodes {
                if n.id == m.from || !members.contains(&n.id) {
                    continue;
                }
                if m.to.as_ref().is_some_and(|to| *to != n.id) {
                    continue;
                }
                out.push((n.id.clone(), n.signer.receive(&m.session_id, &m)));
            }
        }
        out
    }
}

/// Coordinator round-2 message for `to`, relayed under the identity of
/// another session participant `relay` (the provider requires sender != self).
pub fn frost_round2(env: &AuthorizationEnvelope, pkg: &Bytes, to: &Node, relay: &Node) -> PeerMessage {
    PeerMessage {
        session_id: env.body.signer_session_id.clone(),
        key_id: env.body.key_id.clone(),
        key_epoch: env.body.key_epoch,
        from: relay.id.clone(),
        from_generation: relay.signer.generation(),
        to: Some(to.id.clone()),
        round: 2,
        sequence: 2,
        protocol_version: oic_crypto_provider_frost_ed25519::PROTOCOL_VERSION.into(),
        payload: pkg.clone(),
    }
}

/// Run sessions on `signing` nodes up to (and including) delivery of the
/// round-2 packages, which the signers buffer. Returns the signing package.
pub fn frost_until_release(case: &SolCase, env: &AuthorizationEnvelope, signing: &[&Node]) -> Bytes {
    let members: Vec<ParticipantId> = env.body.participant_set.clone();
    let mut t = Transport::default();
    for n in signing {
        let step = n.signer.open_session(env, &case.setup.m, now()).expect("open_session");
        assert!(matches!(step, ProtocolStep::Send(_)), "FROST round 1 emits a commitment");
        t.post(step);
    }
    for (who, r) in t.pump(signing, &members) {
        assert_eq!(r.unwrap_or_else(|e| panic!("{who}: {e}")), ProtocolStep::Waiting);
    }
    let commitments: Vec<(ParticipantId, Bytes)> = t.commitments.clone().into_iter().collect();
    let pkg = build_signing_package(&commitments, env.body.native_signing_payloads[0].message_or_digest.as_slice()).unwrap();
    for (i, n) in signing.iter().enumerate() {
        let relay = signing[(i + 1) % signing.len()];
        let msg = frost_round2(env, &pkg, n, relay);
        assert_eq!(n.signer.receive(&msg.session_id, &msg).unwrap(), ProtocolStep::Waiting, "round 2 is withheld before release");
    }
    pkg
}

pub fn expect_share(steps: Vec<ProtocolStep>) -> Bytes {
    match steps.as_slice() {
        [ProtocolStep::Share(b)] => b.clone(),
        other => panic!("expected exactly one share, got {other:?}"),
    }
}
