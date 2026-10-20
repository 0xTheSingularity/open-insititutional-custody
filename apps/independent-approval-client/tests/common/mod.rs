//! Fixtures for the approval-client tests: real EVM and Solana approval
//! packages whose candidates are built by the pinned adapters, with
//! admin-quorum-signed policies and destinations (modelled on
//! `crates/signer/tests/common` and `crates/approval-verifier/tests/common`),
//! plus envelope construction modelled on the signer's `Setup::body_for`.
#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use k256::ecdsa::SigningKey as K256Key;
use oic_adapter_api::*;
use oic_approval_client::keyfile::{ApproverKeyFile, MIN_PBKDF2_ITERATIONS};
use oic_approval_client::trust::TrustRoots;
use oic_authorization_state::{receipt_hash, reservation_id_for};
use oic_domain_types::*;
use oic_policy_kernel::{destination_hash, intent_hash, policy_hash};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const OBSERVED_AT: u64 = 1_700_000_000;
/// "Now": 20 s after the evidence was observed (fresh).
pub const NOW: u64 = OBSERVED_AT + 20;
pub const PASSPHRASE: &[u8] = b"correct horse battery staple";

// ---------------------------------------------------------------------------
// Administrators, approver, trust roots
// ---------------------------------------------------------------------------

pub fn admin(n: u8) -> (CredentialId, SigningKey) {
    (CredentialId::unchecked(format!("admin-{n}")), SigningKey::from_bytes(&[n; 32]))
}

pub fn approver_key() -> SigningKey {
    SigningKey::from_bytes(&[0x51; 32])
}

pub fn approver_id() -> CredentialId {
    CredentialId::unchecked("approver-treasury-1")
}

pub fn approver_arg() -> String {
    format!("{}={}=treasury_approver", approver_id(), hex::encode(approver_key().verifying_key().to_bytes()))
}

pub fn roster() -> Vec<oic_approval_verifier::ApproverCredential> {
    vec![oic_approval_verifier::ApproverCredential {
        credential_id: approver_id(),
        verifying_key: approver_key().verifying_key(),
        role: ApprovalRole::TreasuryApprover,
    }]
}

pub fn admin_signatures(h: Hash32, signers: &[u8]) -> Vec<CredentialSignature> {
    signers
        .iter()
        .map(|n| {
            let (id, k) = admin(*n);
            CredentialSignature { credential_id: id, signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(k.sign(&h.0).to_bytes().to_vec()) } }
        })
        .collect()
}

pub fn trust_roots() -> TrustRoots {
    TrustRoots::new((1..=3).map(admin).map(|(c, k)| (c, k.verifying_key())).collect(), 2, vec![evm_profile(), sol_profile()]).unwrap()
}

// ---------------------------------------------------------------------------
// Registry objects
// ---------------------------------------------------------------------------

pub fn vault() -> Vault {
    Vault {
        vault_id: VaultId::unchecked("vault-1"),
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        tier: VaultTier::Operating,
        policy_id: PolicyId::unchecked("pol-1"),
        display_name: "Operating".into(),
    }
}

/// Policy (epoch 4) with one two-approver rule, signed by `signers`
/// (the roster quorum is 2 of admins 1..=3).
pub fn policy(asset: &AssetId, signers: &[u8]) -> PolicyBundle {
    let mut b = PolicyBundle {
        policy_id: PolicyId::unchecked("pol-1"),
        policy_epoch: Epoch(4),
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        rules: vec![PolicyRule {
            rule_id: "r-1".into(),
            vaults: vec![VaultId::unchecked("vault-1")],
            assets: vec![asset.clone()],
            destinations: vec![],
            purposes: vec![],
            max_amount_per_operation: Amount(1_000_000_000_000_000_000),
            max_native_fee_per_operation: Amount(10u128.pow(18)),
            rolling_limits: vec![ExposureLimit { window_seconds: 86_400, max_outflow_base_units: Amount(10u128.pow(20)) }],
            required_approvals: 2,
            approval_roles: vec![ApprovalRole::TreasuryApprover, ApprovalRole::SecurityApprover],
            exclude_proposer: true,
            operating_window: None,
        }],
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 60,
        allowlist_version: 1,
        activation_epoch: Epoch(4),
        administrative_signatures: vec![],
    };
    b.administrative_signatures = admin_signatures(policy_hash(&b).unwrap(), signers);
    b
}

/// Register `d` with the given administrators' signatures.
pub fn signed_destination(mut d: CounterpartyDestination, signers: &[u8]) -> CounterpartyDestination {
    d.administrative_signatures = admin_signatures(destination_hash(&d).unwrap(), signers);
    d
}

fn intent(profile: &ChainProfile, asset: &Asset, destination: &CounterpartyDestination, amount: u128, max_fee: u128, mode: ApprovalMode) -> Intent {
    Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked("intent-1"),
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        vault_id: VaultId::unchecked("vault-1"),
        chain_wallet_id: ChainWalletId::unchecked("wallet-1"),
        chain_profile_id: profile.chain_profile_id.clone(),
        operation: IntentOperation::AssetTransfer {
            asset_id: asset.asset_id.clone(),
            amount_base_units: Amount(amount),
            destination_id: destination.destination_id.clone(),
            destination_version: destination.version,
        },
        constraints: IntentConstraints { max_network_fee_base_units: Amount(max_fee), approval_mode: mode, maximum_successful_payments: 1 },
        purpose: OperationPurpose::Settlement,
        external_reference: "INV-2026-0042".into(),
        proposer_credential_id: CredentialId::unchecked("cred-proposer"),
        created_at: UnixSeconds(OBSERVED_AT - 100),
    }
}

fn unbuilt(profile: &ChainProfile, intent: &Intent) -> Candidate {
    Candidate {
        candidate_id: CandidateId::unchecked("unbuilt"),
        candidate_revision: 0,
        intent_id: intent.intent_id.clone(),
        operation_family_id: OperationFamilyId::unchecked("family-1"),
        chain_profile_id: profile.chain_profile_id.clone(),
        adapter_id: profile.adapter_id.clone(),
        adapter_version: String::new(),
        native_unsigned_bytes: Bytes(vec![]),
        signing_payloads: vec![],
        evidence_bundle_hash: Hash32::ZERO,
        built_at: UnixSeconds(0),
    }
}

fn build_ctx(profile: &ChainProfile, p: &ApprovalPackage, destination: &CounterpartyDestination) -> BuildContext {
    BuildContext {
        intent: p.intent.clone(),
        wallet: p.wallet.clone(),
        key: p.key.clone(),
        asset: p.asset.clone(),
        destination: destination.clone(),
        profile: profile.clone(),
        evidence: p.evidence.clone(),
        candidate_id: CandidateId::unchecked("cand-1"),
        candidate_revision: 1,
        operation_family_id: OperationFamilyId::unchecked("family-1"),
        built_at: UnixSeconds(OBSERVED_AT + 10),
    }
}

fn key_descriptor(scheme: SchemeId, public_key: Vec<u8>, network: &NetworkId) -> KeyDescriptor {
    KeyDescriptor {
        key_id: KeyId::unchecked("key-1"),
        key_epoch: Epoch(1),
        scheme,
        public_key: PublicKey { scheme, bytes: Bytes(public_key) },
        backend_id: "dev".into(),
        backend_commit: "dev".into(),
        participants: vec![],
        threshold: 1,
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        networks: vec![network.clone()],
        recovery_profile: "none".into(),
    }
}

fn wallet(profile: &ChainProfile, key: &KeyDescriptor, address: Vec<u8>, display: String) -> ChainWallet {
    ChainWallet {
        chain_wallet_id: ChainWalletId::unchecked("wallet-1"),
        vault_id: VaultId::unchecked("vault-1"),
        chain_profile_id: profile.chain_profile_id.clone(),
        network_id: profile.network_id.clone(),
        key_id: key.key_id.clone(),
        key_epoch: key.key_epoch,
        address: Bytes(address),
        address_display: display,
        active: true,
    }
}

// ---------------------------------------------------------------------------
// EVM: ERC-20 USDC (6 decimals) on Sepolia
// ---------------------------------------------------------------------------

pub const EVM_CHAIN_ID: u64 = 11_155_111;

pub fn token_contract() -> [u8; 20] {
    [0xc0; 20]
}
pub fn evm_dest_address() -> [u8; 20] {
    [0xde; 20]
}
pub fn evm_attacker_address() -> [u8; 20] {
    [0xee; 20]
}

fn evm_signing_key() -> K256Key {
    let mut b = [0x11u8; 32];
    b[0] = 1;
    K256Key::from_bytes(&b.into()).unwrap()
}

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

pub fn evm_asset() -> Asset {
    Asset {
        asset_id: AssetId::unchecked("sepolia-usdc"),
        network_id: NetworkId::unchecked("evm-11155111"),
        asset: AssetKind::Erc20 { contract: Bytes(token_contract().to_vec()) },
        decimals: 6,
        symbol: "USDC".into(),
        behavior: AssetBehaviorProfile::Standard,
    }
}

pub fn evm_destination(address: [u8; 20]) -> CounterpartyDestination {
    signed_destination(
        CounterpartyDestination {
            destination_id: DestinationId::unchecked("dest-1"),
            version: 3,
            network_id: NetworkId::unchecked("evm-11155111"),
            address: Bytes(address.to_vec()),
            address_display: oic_adapter_evm::address::eip55(&address),
            display_name: "Acme Settlement LLC".into(),
            allowed_assets: vec![],
            verification_evidence: "callback 2026-01-02".into(),
            activation_epoch: Epoch(1),
            administrative_signatures: vec![],
        },
        &[1, 2],
    )
}

/// A real EVM package paying `amount` USDC base units. `paid_to` models a
/// compromised console/builder that builds the transaction to another
/// address while presenting the registry destination.
pub fn evm_package(amount: u128, mode: ApprovalMode, paid_to: Option<[u8; 20]>) -> ApprovalPackage {
    use oic_adapter_evm::evidence::*;
    let profile = evm_profile();
    let pubkey = evm_signing_key().verifying_key().to_encoded_point(true).as_bytes().to_vec();
    let sender = oic_adapter_evm::address::address_from_sec1(&pubkey).unwrap();
    let key = key_descriptor(SchemeId::EcdsaSecp256k1Keccak256Prehashed, pubkey, &profile.network_id);
    let wallet = wallet(&profile, &key, sender.to_vec(), oic_adapter_evm::address::eip55(&sender));
    let asset = evm_asset();
    let destination = evm_destination(evm_dest_address());
    let mut items = BTreeMap::new();
    items.insert(nonce_key(&sender), Bytes(5u64.to_be_bytes().to_vec()));
    items.insert(KEY_BASE_FEE.to_string(), Bytes(10_000_000_000u128.to_be_bytes().to_vec()));
    items.insert(KEY_PRIORITY_FEE.to_string(), Bytes(1_000_000_000u128.to_be_bytes().to_vec()));
    items.insert(KEY_GAS_LIMIT.to_string(), Bytes(65_000u64.to_be_bytes().to_vec()));
    items.insert(KEY_CHAIN_ID.to_string(), Bytes(EVM_CHAIN_ID.to_be_bytes().to_vec()));
    items.insert(code_key(&token_contract()), Bytes(vec![0xab; 32]));
    let evidence = EvidenceBundle {
        chain_profile_id: profile.chain_profile_id.clone(),
        network_id: profile.network_id.clone(),
        state: StateReference { height: 1000, hash: Bytes(vec![7; 32]), commitment: "finalized".into() },
        sources: vec![EvidenceSourceId::unchecked("dev-node")],
        trust_level: EvidenceTrustLevel::DevelopmentSimulator,
        observed_at: UnixSeconds(OBSERVED_AT),
        max_staleness_seconds: 60,
        verifier_version: "test".into(),
        items,
    };
    let intent = intent(&profile, &asset, &destination, amount, 10u128.pow(16), mode);
    let mut p = ApprovalPackage {
        schema_version: ApprovalPackage::SCHEMA_VERSION,
        candidate: unbuilt(&profile, &intent),
        intent,
        vault: vault(),
        wallet,
        key,
        policy: policy(&asset.asset_id, &[1, 2]),
        asset,
        destination,
        evidence,
    };
    let build_dest = evm_destination(paid_to.unwrap_or_else(evm_dest_address));
    p.candidate = oic_adapter_evm::EvmAdapter.build_candidate(&build_ctx(&profile, &p, &build_dest)).expect("EVM build");
    p
}

// ---------------------------------------------------------------------------
// Solana: native SOL (9 decimals) on devnet
// ---------------------------------------------------------------------------

pub const SOL_GENESIS: [u8; 32] = [0x6e; 32];

fn ed_key(seed: u8) -> SigningKey {
    let mut b = [0x22u8; 32];
    b[0] = seed;
    SigningKey::from_bytes(&b)
}

pub fn sol_dest_owner() -> [u8; 32] {
    ed_key(77).verifying_key().to_bytes()
}
pub fn sol_attacker_owner() -> [u8; 32] {
    ed_key(99).verifying_key().to_bytes()
}

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

pub fn sol_destination(owner: [u8; 32]) -> CounterpartyDestination {
    signed_destination(
        CounterpartyDestination {
            destination_id: DestinationId::unchecked("dest-sol"),
            version: 2,
            network_id: NetworkId::unchecked("solana-devnet"),
            address: Bytes(owner.to_vec()),
            address_display: oic_adapter_solana::address::to_base58(&owner),
            display_name: "Acme Settlement LLC".into(),
            allowed_assets: vec![],
            verification_evidence: "callback 2026-01-02".into(),
            activation_epoch: Epoch(1),
            administrative_signatures: vec![],
        },
        &[1, 2],
    )
}

/// A real Solana package; see [`evm_package`] for `paid_to`.
pub fn sol_package(amount: u128, mode: ApprovalMode, paid_to: Option<[u8; 32]>) -> ApprovalPackage {
    use oic_adapter_solana::evidence::*;
    let profile = sol_profile();
    let wallet_addr = ed_key(1).verifying_key().to_bytes();
    let key = key_descriptor(SchemeId::Ed25519Pure, wallet_addr.to_vec(), &profile.network_id);
    let wallet = wallet(&profile, &key, wallet_addr.to_vec(), oic_adapter_solana::address::to_base58(&wallet_addr));
    let asset = sol_asset();
    let destination = sol_destination(sol_dest_owner());
    let le = |v: u64| Bytes(v.to_le_bytes().to_vec());
    let mut items = BTreeMap::new();
    items.insert(KEY_GENESIS_HASH.to_string(), Bytes(SOL_GENESIS.to_vec()));
    items.insert(KEY_RECENT_BLOCKHASH.to_string(), Bytes(vec![0xbb; 32]));
    items.insert(KEY_BLOCKHASH_LAST_VALID_HEIGHT.to_string(), le(1_150));
    items.insert(KEY_LAMPORTS_PER_SIGNATURE.to_string(), le(5_000));
    items.insert(KEY_RENT_TOKEN_ACCOUNT.to_string(), le(2_039_280));
    let evidence = EvidenceBundle {
        chain_profile_id: profile.chain_profile_id.clone(),
        network_id: profile.network_id.clone(),
        state: StateReference { height: 1_000, hash: Bytes(vec![7; 32]), commitment: "finalized".into() },
        sources: vec![EvidenceSourceId::unchecked("dev-node")],
        trust_level: EvidenceTrustLevel::DevelopmentSimulator,
        observed_at: UnixSeconds(OBSERVED_AT),
        max_staleness_seconds: 60,
        verifier_version: "test".into(),
        items,
    };
    let intent = intent(&profile, &asset, &destination, amount, 10_000_000, mode);
    let mut p = ApprovalPackage {
        schema_version: ApprovalPackage::SCHEMA_VERSION,
        candidate: unbuilt(&profile, &intent),
        intent,
        vault: vault(),
        wallet,
        key,
        policy: policy(&asset.asset_id, &[1, 2]),
        asset,
        destination,
        evidence,
    };
    let build_dest = sol_destination(paid_to.unwrap_or_else(sol_dest_owner));
    p.candidate = oic_adapter_solana::SolanaAdapter.build_candidate(&build_ctx(&profile, &p, &build_dest)).expect("Solana build");
    p
}

// ---------------------------------------------------------------------------
// Envelopes (modelled on crates/signer/tests/common/mod.rs::Setup::body_for)
// ---------------------------------------------------------------------------

pub fn adapter_for(p: &ApprovalPackage) -> (ChainProfile, std::sync::Arc<dyn ChainAdapter>) {
    let profile = if p.candidate.adapter_id.as_str() == "evm" { evm_profile() } else { sol_profile() };
    let adapter: std::sync::Arc<dyn ChainAdapter> =
        if p.candidate.adapter_id.as_str() == "evm" { std::sync::Arc::new(oic_adapter_evm::EvmAdapter) } else { std::sync::Arc::new(oic_adapter_solana::SolanaAdapter) };
    (profile, adapter)
}

pub fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

/// The envelope a coordinator would assemble for `p` with `grants`, plus a
/// Reserved receipt signed by a test authority key over its body hash.
pub fn envelope_for(p: &ApprovalPackage, grants: Vec<ApprovalGrant>) -> AuthorizationEnvelope {
    let (profile, adapter) = adapter_for(p);
    let ctx = VerifyContext { profile: &profile, wallet: &p.wallet, key: &p.key, asset: &p.asset, destination: &p.destination, evidence: &p.evidence };
    let verified = adapter.verify_candidate(&p.candidate, &AuthorizationTarget::Intent(&p.intent), &ctx).expect("coordinator-side verify");
    let c = &p.candidate;
    let manifest = adapter.manifest();
    let body = AuthorizationEnvelopeBody {
        institution_id: p.intent.institution_id.clone(),
        environment_id: p.intent.environment_id.clone(),
        vault_id: p.vault.vault_id.clone(),
        chain_wallet_id: p.wallet.chain_wallet_id.clone(),
        intent_id: p.intent.intent_id.clone(),
        intent_hash: intent_hash(&p.intent).unwrap(),
        operation_family_id: c.operation_family_id.clone(),
        candidate_id: c.candidate_id.clone(),
        candidate_revision: c.candidate_revision,
        chain_profile_id: profile.chain_profile_id.clone(),
        chain_profile_hash: profile.hash().unwrap(),
        key_id: p.key.key_id.clone(),
        key_epoch: p.key.key_epoch,
        public_key_hash: oic_signer::public_key_hash(&p.key.public_key).unwrap(),
        adapter_id: c.adapter_id.clone(),
        adapter_version: manifest.adapter_version,
        verifier_build_hash: manifest.verifier_build_hash,
        policy_id: p.policy.policy_id.clone(),
        policy_epoch: p.policy.policy_epoch,
        policy_hash: policy_hash(&p.policy).unwrap(),
        allowlist_version: p.policy.allowlist_version,
        native_unsigned_bytes: c.native_unsigned_bytes.clone(),
        native_signing_payloads: verified.signing_payloads.clone(),
        decoded_operation_hash: verified.decoded_operation_hash,
        evidence_bundle_hash: c.evidence_bundle_hash,
        destination_hash: destination_hash(&p.destination).unwrap(),
        approval_grants: grants,
        budget_reservation_id: reservation_id_for(&c.operation_family_id, &c.candidate_id, c.candidate_revision).unwrap(),
        reservation_version: 1,
        resource_reservations: verified.claims.resources.clone(),
        maximum_asset_outflows: verified.claims.asset_outflows.clone(),
        maximum_native_fees: verified.claims.native_fees.clone(),
        issuance_deadline: UnixSeconds(NOW + 300),
        expected_chain_validity_constraints: adapter.validity_constraints(c, &p.evidence).unwrap(),
        signer_session_id: SigningSessionId::unchecked("session-1"),
        participant_set: vec![ParticipantId::unchecked("signer-1")],
    };
    let receipt_body = AuthorityReceiptBody {
        kind: ReceiptKind::Reserved,
        institution_id: body.institution_id.clone(),
        environment_id: body.environment_id.clone(),
        authority_epoch: Epoch(1),
        reservation_id: body.budget_reservation_id.clone(),
        reservation_version: body.reservation_version,
        candidate_id: body.candidate_id.clone(),
        candidate_revision: body.candidate_revision,
        envelope_body_hash: oic_signer::envelope_body_hash(&body).unwrap(),
        signer_session_id: body.signer_session_id.clone(),
        policy_epoch: body.policy_epoch,
        freeze_epoch: Epoch(0),
        issued_at: UnixSeconds(NOW),
        expires_at: UnixSeconds(NOW + 600),
        commit_sequence: 1,
    };
    let h = receipt_hash(&receipt_body).unwrap();
    let receipt = AuthorityReceipt {
        body: receipt_body,
        authority_key_id: KeyId::unchecked("authority-key-1"),
        signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(authority_key().sign(&h.0).to_bytes().to_vec()) },
    };
    AuthorizationEnvelope { body, authorization_state_receipt: receipt }
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Temp directory holding `trust.json` and the approver key file.
pub struct Files {
    pub dir: tempfile::TempDir,
}

impl Files {
    pub fn new() -> Files {
        let f = Files { dir: tempfile::tempdir().unwrap() };
        trust_roots().save(&f.path("trust.json")).unwrap();
        f
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn trust(&self) -> PathBuf {
        self.path("trust.json")
    }

    pub fn write_json<T: serde::Serialize>(&self, name: &str, v: &T) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
        p
    }

    /// The fixture approver credential, sealed under [`PASSPHRASE`] once per
    /// test process (PBKDF2 at production strength is slow in debug builds).
    pub fn approver_key(&self) -> PathBuf {
        static SEALED: std::sync::OnceLock<ApproverKeyFile> = std::sync::OnceLock::new();
        let p = self.path("approver.key");
        if !p.exists() {
            SEALED
                .get_or_init(|| ApproverKeyFile::seal(approver_id(), ApprovalRole::TreasuryApprover, &approver_key(), PASSPHRASE, MIN_PBKDF2_ITERATIONS).unwrap())
                .save(&p)
                .unwrap();
        }
        p
    }
}

pub fn exists(p: &Path) -> bool {
    p.exists()
}
