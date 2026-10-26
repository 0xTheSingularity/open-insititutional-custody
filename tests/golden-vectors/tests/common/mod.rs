//! Deterministic fixtures and the vector builders shared by the generator
//! and the conformance tests.
//!
//! The fixture values are copied from `crates/signer/tests/common/mod.rs`
//! (institution, vault, policy, EVM Sepolia ERC-20 case, Solana devnet case)
//! and `crates/chain-simulator/tests/common/mod.rs` (hand-built key
//! descriptors). Everything that would otherwise be random is derived from
//! fixed seeds: Ed25519 keys from fixed 32-byte seeds and the dev
//! secp256k1 key from [`DetRng`], so every run produces identical bytes.
//!
//! The EVM flow runs the real stack end to end: the authority reserves and
//! releases, the real signer independently verifies the envelope, opens a
//! session, accepts the release receipt, and aborts. The vectors are taken
//! from that run.
#![allow(dead_code)]

use ed25519_dalek::{Signer as _, SigningKey};
use oic_adapter_api::*;
use oic_adapter_solana::message::{AddressTableLookup, CompiledInstruction, Message as SolMessage, MessageHeader, MessageVersion};
use oic_approval_verifier::{sign_grant, ApproverCredential};
use oic_audit::{AuditLog, AuditLogConfig, AuthorityAuditSink, MemoryAuditLog};
use oic_authorization_state::*;
use oic_canonical_encoding::{canonical_bytes, sha256};
use oic_crypto_provider::*;
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_domain_types::*;
use oic_golden_vectors::*;
use oic_one_time_state_ledger::InMemoryLedger;
use oic_policy_kernel::{
    asset_hash, chain_wallet_hash, destination_hash, intent_hash, key_descriptor_hash, policy_hash,
    preview_hash, vault_hash, Decision,
};
use oic_signer::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub const T0: u64 = 1_700_000_000;
pub const NOW: u64 = T0 + 20;
pub const DAY: u64 = 86_400;
pub const DEADLINE: u64 = NOW + 300;
pub const SESSION: &str = "session-evm-1";

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
pub fn audit_key_id() -> KeyId {
    KeyId::unchecked("audit-key-1")
}

// ---------------------------------------------------------------------------
// Deterministic randomness
// ---------------------------------------------------------------------------

/// Deterministic RNG: block `i` is `SHA-256(seed || u64be(i))`. Used only
/// to make the dev backend's key generation and share sealing reproducible.
pub struct DetRng {
    seed: [u8; 32],
    counter: u64,
    buf: Vec<u8>,
}

impl DetRng {
    pub fn new(label: &str) -> DetRng {
        DetRng { seed: Sha256::digest(label.as_bytes()).into(), counter: 0, buf: Vec::new() }
    }
}

impl rand_core::RngCore for DetRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            if self.buf.is_empty() {
                let mut h = Sha256::new();
                h.update(self.seed);
                h.update(self.counter.to_be_bytes());
                self.counter += 1;
                self.buf = h.finalize().to_vec();
                self.buf.reverse();
            }
            *b = self.buf.pop().expect("refilled above");
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for DetRng {}

// ---------------------------------------------------------------------------
// Authority, admins, approvers, audit
// ---------------------------------------------------------------------------

pub struct World {
    pub authority: Authority<InMemoryAuthorityStore>,
    pub authority_sk: SigningKey,
    pub admins: Vec<(CredentialId, SigningKey)>,
    pub approvers: Vec<(CredentialId, SigningKey, ApprovalRole)>,
    pub responder: (CredentialId, SigningKey),
    pub clock: Arc<ManualClock>,
    pub audit_sk: SigningKey,
    pub audit: Arc<MemoryAuditLog>,
}

pub fn authority_config(admins: &[(CredentialId, SigningKey)], responder: &(CredentialId, SigningKey)) -> AuthorityConfig {
    AuthorityConfig {
        institution_id: inst(),
        environment_id: env_id(),
        authority_key_id: authority_key_id(),
        admin_keys: admins.iter().map(|(c, k)| (c.clone(), k.verifying_key())).collect(),
        admin_quorum: 2,
        freeze_responders: vec![(responder.0.clone(), responder.1.verifying_key())],
        release_receipt_ttl_seconds: 60,
        max_clock_skew_seconds: 30,
    }
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
        let responder = (CredentialId::unchecked("responder-1"), SigningKey::from_bytes(&[77; 32]));
        let clock = Arc::new(ManualClock::new(NOW));
        let audit_sk = SigningKey::from_bytes(&[0xa0; 32]);
        let audit = Arc::new(MemoryAuditLog::new(AuditLogConfig::new(audit_key_id(), audit_sk.clone(), clock.clone())));
        let authority = Authority::open(Arc::new(InMemoryAuthorityStore::new()), 0, authority_config(&admins, &responder), authority_sk.clone(), clock.clone())
            .expect("authority open")
            .with_audit(Arc::new(AuthorityAuditSink::new(audit.clone(), "authority:inst/dev")));
        World { authority, authority_sk, admins, approvers, responder, clock, audit_sk, audit }
    }

    pub fn approver_credentials(&self) -> Vec<ApproverCredential> {
        self.approvers
            .iter()
            .map(|(c, k, r)| ApproverCredential { credential_id: c.clone(), person_id: c.clone(), verifying_key: k.verifying_key().into(), role: *r })
            .collect()
    }

    /// Admin-quorum signatures (first two admins) over `h`.
    pub fn admin_quorum_signatures(&self, h: Hash32) -> Vec<CredentialSignature> {
        admin_signatures(&self.admins[..2], h)
    }

    pub fn trust_roots(&self, profiles: Vec<ChainProfile>) -> TrustRoots {
        let mut builds = BTreeMap::new();
        builds.insert(AdapterId::unchecked("evm"), vec![oic_adapter_evm::verifier_build_hash()]);
        builds.insert(AdapterId::unchecked("solana"), vec![oic_adapter_solana::verifier_build_hash()]);
        TrustRoots {
            authority_key_id: authority_key_id(),
            authority_pubkey: self.authority_sk.verifying_key(),
            admin_keys: self.admins.iter().map(|(c, k)| (c.clone(), k.verifying_key())).collect(),
            admin_quorum: 2,
            approvers: self.approver_credentials(),
            accepted_verifier_builds: builds,
            chain_profiles: profiles,
            enrolled_materials: None,
            max_clock_skew_seconds: 30,
        }
    }
}

pub fn admin_signatures(admins: &[(CredentialId, SigningKey)], h: Hash32) -> Vec<CredentialSignature> {
    admins
        .iter()
        .map(|(c, k)| CredentialSignature {
            credential_id: c.clone(),
            signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(k.sign(&h.0).to_bytes().to_vec()) },
        })
        .collect()
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

// ---------------------------------------------------------------------------
// EVM (Sepolia, ERC-20) fixtures
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

pub fn erc20_asset() -> Asset {
    Asset {
        asset_id: AssetId::unchecked("sepolia-usdc"),
        network_id: NetworkId::unchecked("evm-11155111"),
        asset: AssetKind::Erc20 { contract: Bytes(token_contract().to_vec()) },
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
        administrative_signatures: vec![],
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

/// Dev single-key secp256k1 provider whose key generation is reproducible.
pub fn evm_provider() -> Arc<DevSingleKeyProvider> {
    Arc::new(DevSingleKeyProvider::new(SchemeId::EcdsaSecp256k1Keccak256Prehashed, [9; 32], Box::new(DetRng::new("oic-golden-vectors/evm-key"))).expect("dev provider"))
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

// ---------------------------------------------------------------------------
// Solana (devnet, native SOL) fixtures
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
        administrative_signatures: vec![],
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

/// Ed25519 group key for the Solana wallet (seed `[0x5a; 32]`), described
/// like a FROST 2-of-3 key (chain-simulator `party` shape).
pub fn sol_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

pub fn sol_key() -> KeyDescriptor {
    let pk = PublicKey { scheme: SchemeId::Ed25519Pure, bytes: Bytes(sol_signing_key().verifying_key().to_bytes().to_vec()) };
    KeyDescriptor {
        key_id: KeyId::unchecked("key-sol"),
        key_epoch: Epoch(1),
        scheme: SchemeId::Ed25519Pure,
        public_key: pk,
        backend_id: "frost-ed25519".into(),
        backend_commit: "frost-ed25519=2.2.0".into(),
        participants: vec![pid(1), pid(2), pid(3)],
        threshold: 2,
        institution_id: inst(),
        environment_id: env_id(),
        networks: vec![NetworkId::unchecked("solana-devnet")],
        recovery_profile: "dkg".into(),
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

/// The Solana case: bounded-transfer intent, legacy candidate built by the
/// real adapter, verified against the intent.
pub struct SolCase {
    pub key: KeyDescriptor,
    pub wallet: ChainWallet,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub intent: Intent,
    pub evidence: EvidenceBundle,
    pub candidate: Candidate,
    pub verified: VerifiedOperation,
}

pub fn sol_case(admins: &[(CredentialId, SigningKey)]) -> SolCase {
    let key = sol_key();
    let wallet = sol_wallet(&key);
    let asset = sol_asset();
    let mut destination = sol_destination();
    destination.administrative_signatures = admin_signatures(admins, destination_hash(&destination).unwrap());
    let intent = intent_for("intent-sol-1", &wallet, &asset, &destination, 1_000_000, 10_000_000, ApprovalMode::BoundedDirectTransfer);
    let evidence = sol_evidence();
    let profile = sol_profile();
    let ctx = BuildContext {
        intent: intent.clone(),
        wallet: wallet.clone(),
        key: key.clone(),
        asset: asset.clone(),
        destination: destination.clone(),
        profile: profile.clone(),
        evidence: evidence.clone(),
        candidate_id: CandidateId::unchecked("cand-sol-1"),
        candidate_revision: 1,
        operation_family_id: family_id_for(&intent.intent_id).unwrap(),
        built_at: UnixSeconds(T0 + 10),
    };
    let adapter = oic_adapter_solana::SolanaAdapter;
    let candidate = adapter.build_candidate(&ctx).expect("solana build_candidate");
    let vctx = VerifyContext { profile: &profile, wallet: &wallet, key: &key, asset: &asset, destination: &destination, evidence: &evidence };
    let verified = adapter.verify_candidate(&candidate, &AuthorizationTarget::Intent(&intent), &vctx).expect("solana verify_candidate");
    SolCase { key, wallet, asset, destination, intent, evidence, candidate, verified }
}

// ---------------------------------------------------------------------------
// One-time-state ledger that records what the signer asks of it
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerCall {
    Allocate { key_id: KeyId, generation: Epoch, session_id: SigningSessionId, record_id: String },
    Consume { record_id: String, message_hash: Hash32 },
    Tombstone { key_id: KeyId, generation: Epoch },
}

pub struct RecordingLedger {
    pub inner: InMemoryLedger,
    pub calls: Mutex<Vec<LedgerCall>>,
}

impl OneTimeStateLedger for RecordingLedger {
    fn allocate(&self, key_id: &KeyId, key_epoch: Epoch, generation: Epoch, session_id: &SigningSessionId) -> OicResult<OneTimeStateRecord> {
        let r = self.inner.allocate(key_id, key_epoch, generation, session_id)?;
        self.calls.lock().unwrap().push(LedgerCall::Allocate { key_id: key_id.clone(), generation, session_id: session_id.clone(), record_id: r.record_id.clone() });
        Ok(r)
    }
    fn consume(&self, record_id: &str, message_hash: Hash32) -> OicResult<()> {
        self.inner.consume(record_id, message_hash)?;
        self.calls.lock().unwrap().push(LedgerCall::Consume { record_id: record_id.to_string(), message_hash });
        Ok(())
    }
    fn get(&self, record_id: &str) -> OicResult<Option<OneTimeStateRecord>> {
        self.inner.get(record_id)
    }
    fn tombstone_generations_before(&self, key_id: &KeyId, generation: Epoch) -> OicResult<u64> {
        self.calls.lock().unwrap().push(LedgerCall::Tombstone { key_id: key_id.clone(), generation });
        self.inner.tombstone_generations_before(key_id, generation)
    }
}

// ---------------------------------------------------------------------------
// The EVM end-to-end flow
// ---------------------------------------------------------------------------

pub struct EvmFlow {
    pub world: World,
    pub profile: ChainProfile,
    pub m: SigningMaterials,
    pub verified: VerifiedOperation,
    pub grant: ApprovalGrant,
    pub envelope: AuthorizationEnvelope,
    pub release: AuthorityReceipt,
    pub issuance: IssuanceRecord,
    pub ledger_calls: Vec<LedgerCall>,
    pub participant: ParticipantId,
    pub preview_hash: Hash32,
}

fn unbuilt_candidate() -> Candidate {
    Candidate {
        candidate_id: CandidateId::unchecked("unbuilt"),
        candidate_revision: 0,
        intent_id: IntentId::unchecked("unbuilt"),
        operation_family_id: OperationFamilyId::unchecked("unbuilt"),
        chain_profile_id: ChainProfileId::unchecked("unbuilt"),
        adapter_id: AdapterId::unchecked("evm"),
        adapter_version: String::new(),
        native_unsigned_bytes: Bytes(vec![]),
        signing_payloads: vec![],
        evidence_bundle_hash: Hash32::ZERO,
        built_at: UnixSeconds(0),
    }
}

/// Run the EVM ERC-20 authorization end to end on the real components.
/// Panics on any failure: every vector derived from it comes from a run in
/// which the real signer accepted the envelope and the release receipt.
pub fn evm_flow() -> EvmFlow {
    let world = World::new();
    let p1 = pid(1);
    let dev = evm_provider();
    let (key, sealed) = evm_key(&dev, &p1);
    let wallet = evm_wallet(&key);
    let asset = erc20_asset();
    let mut destination = evm_destination([0xde; 20]);
    destination.administrative_signatures = world.admin_quorum_signatures(destination_hash(&destination).unwrap());
    let intent = intent_for("intent-1", &wallet, &asset, &destination, 1_000_000, 10u128.pow(16), ApprovalMode::ExactCandidate);
    let sender: [u8; 20] = wallet.address.as_slice().try_into().unwrap();
    let evidence = evm_evidence(&sender, EVM_NONCE);
    let mut pol = policy(1, vec![rule(&asset.asset_id, 1)]);
    pol.administrative_signatures = world.admin_quorum_signatures(policy_hash(&pol).unwrap());
    let profile = evm_profile();
    let adapter = oic_adapter_evm::EvmAdapter;

    world.authority.set_policy(&pol).expect("set_policy");
    let ih = intent_hash(&intent).unwrap();
    let reg = world
        .authority
        .register_intent(&intent, ih, IdempotencyKey { institution_id: inst(), route: "transfers".into(), key: "idem-1".into() })
        .expect("register intent");

    let mut m = SigningMaterials {
        intent: intent.clone(),
        candidate: unbuilt_candidate(),
        vault: vault(),
        wallet,
        key: key.clone(),
        asset,
        destination,
        policy: pol,
        evidence,
    };
    m.candidate = adapter
        .build_candidate(&BuildContext {
            intent: m.intent.clone(),
            wallet: m.wallet.clone(),
            key: m.key.clone(),
            asset: m.asset.clone(),
            destination: m.destination.clone(),
            profile: profile.clone(),
            evidence: m.evidence.clone(),
            candidate_id: CandidateId::unchecked("cand-1"),
            candidate_revision: 1,
            operation_family_id: reg.operation_family_id.clone(),
            built_at: UnixSeconds(T0 + 10),
        })
        .expect("evm build_candidate");
    let vctx = VerifyContext { profile: &profile, wallet: &m.wallet, key: &m.key, asset: &m.asset, destination: &m.destination, evidence: &m.evidence };
    let verified = adapter.verify_candidate(&m.candidate, &AuthorizationTarget::Intent(&m.intent), &vctx).expect("evm verify_candidate");

    let c = &m.candidate;
    let ph = preview_hash(&c.candidate_id, c.candidate_revision, verified.decoded_operation_hash, c.evidence_bundle_hash);
    let (cred, sk, role) = &world.approvers[0];
    let grant = sign_grant(
        sk,
        ApprovalGrantBody {
            grant_id: GrantId::unchecked("grant-0"),
            institution_id: inst(),
            environment_id: env_id(),
            vault_id: vault_id(),
            intent_id: m.intent.intent_id.clone(),
            intent_hash: ih,
            policy_id: m.policy.policy_id.clone(),
            policy_epoch: m.policy.policy_epoch,
            scope: GrantScope::ExactCandidate { candidate_id: c.candidate_id.clone(), candidate_revision: c.candidate_revision, preview_hash: ph },
            approver_credential_id: cred.clone(),
            approver_role: *role,
            issued_at: UnixSeconds(T0),
            expires_at: UnixSeconds(NOW + 3600),
        },
    )
    .unwrap();

    let manifest = adapter.manifest();
    let body = AuthorizationEnvelopeBody {
        institution_id: inst(),
        environment_id: env_id(),
        vault_id: m.vault.vault_id.clone(),
        chain_wallet_id: m.wallet.chain_wallet_id.clone(),
        intent_id: m.intent.intent_id.clone(),
        intent_hash: ih,
        operation_family_id: c.operation_family_id.clone(),
        candidate_id: c.candidate_id.clone(),
        candidate_revision: c.candidate_revision,
        chain_profile_id: profile.chain_profile_id.clone(),
        chain_profile_hash: profile.hash().unwrap(),
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
        destination_hash: destination_hash(&m.destination).unwrap(),
        asset_hash: asset_hash(&m.asset).unwrap(),
        wallet_hash: chain_wallet_hash(&m.wallet).unwrap(),
        vault_hash: vault_hash(&m.vault).unwrap(),
        key_descriptor_hash: key_descriptor_hash(&m.key).unwrap(),
        approval_grants: vec![grant.clone()],
        budget_reservation_id: reservation_id_for(&c.operation_family_id, &c.candidate_id, c.candidate_revision).unwrap(),
        reservation_version: 1,
        resource_reservations: verified.claims.resources.clone(),
        maximum_asset_outflows: verified.claims.asset_outflows.clone(),
        maximum_native_fees: verified.claims.native_fees.clone(),
        issuance_deadline: UnixSeconds(DEADLINE),
        expected_chain_validity_constraints: adapter.validity_constraints(c, &m.evidence).unwrap(),
        signer_session_id: SigningSessionId::unchecked(SESSION),
        participant_set: vec![p1.clone()],
    };

    let r = &m.policy.rules[0];
    let exposure_limits = verified.claims.asset_outflows.iter().flat_map(|o| r.rolling_limits.iter().map(move |l| (o.asset_id.clone(), l.clone()))).collect();
    let (_, reserved) = world
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
            policy_decision: Decision::Allow { rule_id: r.rule_id.clone() },
            exposure_limits,
        })
        .expect("authority reserve");
    let envelope = AuthorizationEnvelope { body, authorization_state_receipt: reserved };

    // The real signer independently re-verifies everything.
    let ledger = Arc::new(RecordingLedger { inner: InMemoryLedger::new(), calls: Mutex::new(Vec::new()) });
    let mut adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::new();
    adapters.insert(AdapterId::unchecked("evm"), Arc::new(adapter));
    let signer = Signer::open(
        SignerIdentity { participant_id: p1.clone(), institution_id: inst(), environment_id: env_id() },
        {
            let mut roots = world.trust_roots(vec![profile.clone()]);
            let e = oic_policy_kernel::material_enrollment(inst(), env_id(), Epoch(1), [&m.asset], [&m.wallet], [&m.vault], [&m.key], [&m.destination]).unwrap();
            roots.enrolled_materials = Some(oic_policy_kernel::sign_material_enrollment(e, &world.admins[..2]).unwrap());
            roots
        },
        adapters,
        dev.clone(),
        ledger.clone(),
        Arc::new(InMemoryGenerationStore::new()),
    )
    .expect("signer open");
    signer.load_key(&key, &sealed).expect("load key");
    signer.verify_envelope(&envelope, &m, now()).expect("signer verifies the envelope");
    let step = signer.open_session(&envelope, &m, now()).expect("open session");
    assert_eq!(step, ProtocolStep::Waiting);
    let (release, issuance) = world
        .authority
        .release(ReleaseRequest {
            reservation_id: envelope.body.budget_reservation_id.clone(),
            reservation_version: envelope.body.reservation_version,
            envelope_body_hash: envelope_body_hash(&envelope.body).unwrap(),
            signer_session_id: envelope.body.signer_session_id.clone(),
            expected_policy_epoch: envelope.body.policy_epoch,
            freshness: FreshnessContext { now: now() },
        })
        .expect("authority release");
    assert!(signer.release(&envelope.body.signer_session_id, &release, now()).expect("signer accepts the release receipt").is_empty());
    signer.abort(&envelope.body.signer_session_id).expect("abort");
    let ledger_calls = ledger.calls.lock().unwrap().clone();
    EvmFlow { world, profile, m, verified, grant, envelope, release, issuance, ledger_calls, participant: p1, preview_hash: ph }
}

// ---------------------------------------------------------------------------
// RFC 0002 operational objects
// ---------------------------------------------------------------------------

pub fn state_ref(height: u64, fill: u8) -> StateReference {
    StateReference { height, hash: Bytes(vec![fill; 32]), commitment: "finalized".into() }
}

pub fn observed_movement() -> ObservedMovement {
    ObservedMovement {
        movement_id: MovementId::unchecked("mov-1"),
        chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
        network_id: NetworkId::unchecked("evm-11155111"),
        deposit_address_id: Some(DepositAddressId::unchecked("dep-1")),
        chain_wallet_id: Some(ChainWalletId::unchecked("wallet-evm")),
        address: Bytes(vec![0x11; 20]),
        direction: MovementDirection::Inbound,
        asset: AssetKind::Erc20 { contract: Bytes(token_contract().to_vec()) },
        asset_id: Some(AssetId::unchecked("sepolia-usdc")),
        amount_base_units: Amount(2_500_000),
        counterparty: Bytes(vec![0x22; 20]),
        tx_id: ChainTxId::unchecked("0x3f6a0b0e8f1c2d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b"),
        effect_index: 4,
        mechanism: DiscoveryMechanism::EvmErc20TransferLog,
        observed_state: state_ref(1_200, 0x31),
        canonicality: Canonicality::Canonical,
        acceptance: MovementAcceptance::Accepted,
        operation_family_id: None,
        sources: vec![EvidenceSourceId::unchecked("dev-node")],
        observed_at: UnixSeconds(T0 + 100),
        updated_at: UnixSeconds(T0 + 160),
    }
}

pub fn reorged_movement() -> ObservedMovement {
    ObservedMovement {
        movement_id: MovementId::unchecked("mov-2"),
        direction: MovementDirection::Outbound,
        canonicality: Canonicality::Reorged { at: state_ref(1_203, 0x32) },
        acceptance: MovementAcceptance::Reversed,
        deposit_address_id: None,
        asset: AssetKind::Native,
        asset_id: None,
        operation_family_id: Some(OperationFamilyId::unchecked("fam-1")),
        mechanism: DiscoveryMechanism::EvmTransactionValue,
        ..observed_movement()
    }
}

pub fn journal_entry_body() -> JournalEntryBody {
    JournalEntryBody {
        entry_id: JournalEntryId::unchecked("je-1"),
        sequence: 1,
        previous_entry_hash: Hash32::ZERO,
        at: UnixSeconds(T0 + 170),
        institution_id: inst(),
        environment_id: env_id(),
        vault_id: vault_id(),
        chain_wallet_id: ChainWalletId::unchecked("wallet-evm"),
        asset_id: AssetId::unchecked("sepolia-usdc"),
        side: EntrySide::Credit,
        amount_base_units: Amount(2_500_000),
        kind: JournalEntryKind::AcceptedReceipt { movement_id: MovementId::unchecked("mov-1") },
        posted_at_state: state_ref(1_200, 0x31),
    }
}

pub fn journal_entry_internal() -> JournalEntryBody {
    JournalEntryBody {
        entry_id: JournalEntryId::unchecked("je-2"),
        sequence: 2,
        previous_entry_hash: domain_hash_of(domains::JOURNAL, &journal_entry_body()),
        side: EntrySide::Debit,
        amount_base_units: Amount(1_000_000),
        kind: JournalEntryKind::InternalTransfer {
            operation_family_id: OperationFamilyId::unchecked("fam-1"),
            leg: InternalLeg::Source,
            counterparty_wallet_id: ChainWalletId::unchecked("wallet-treasury"),
            movement_id: MovementId::unchecked("mov-3"),
        },
        ..journal_entry_body()
    }
}

pub fn domain_hash_of<T: serde::Serialize>(tag: &str, v: &T) -> Hash32 {
    oic_canonical_encoding::domain_hash(tag, v).unwrap()
}

pub fn reconciliation_body() -> ReconciliationCheckpointBody {
    ReconciliationCheckpointBody {
        checkpoint_id: CheckpointId::unchecked("chk-1"),
        chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
        network_id: NetworkId::unchecked("evm-11155111"),
        state: state_ref(1_300, 0x41),
        journal_sequence: 2,
        journal_head_hash: domain_hash_of(domains::JOURNAL, &journal_entry_internal()),
        balances: vec![ReconciledBalance {
            chain_wallet_id: ChainWalletId::unchecked("wallet-evm"),
            asset_id: AssetId::unchecked("sepolia-usdc"),
            chain_balance: Amount(1_500_000),
            journal_balance: Amount(1_400_000),
            journal_shortfall: Amount(0),
            reserved: Amount(0),
            pending_inbound: Amount(0),
        }],
        cases_opened: vec![CaseId::unchecked("case-1")],
        sources: vec![EvidenceSourceId::unchecked("dev-node"), EvidenceSourceId::unchecked("provider-b")],
        at: UnixSeconds(T0 + 400),
    }
}

pub fn trigger_deposit() -> WorkflowTrigger {
    WorkflowTrigger::DepositAccepted { movement_id: MovementId::unchecked("mov-1") }
}

pub fn trigger_balance() -> WorkflowTrigger {
    WorkflowTrigger::BalanceBelowMinimum {
        chain_wallet_id: ChainWalletId::unchecked("wallet-evm"),
        asset_id: AssetId::unchecked("sepolia-eth"),
        observed_state: state_ref(1_250, 0x51),
    }
}

pub fn trigger_manual() -> WorkflowTrigger {
    WorkflowTrigger::Manual { external_reference: "ops-2026-10-20".into(), requested_by: CredentialId::unchecked("operator-1") }
}

pub fn lifecycle_event_body() -> LifecycleEventBody {
    LifecycleEventBody {
        event_id: EventId::unchecked("ev-7"),
        sequence: 7,
        institution_id: inst(),
        environment_id: env_id(),
        at: UnixSeconds(NOW),
        kind: LifecycleEventKind::OperationStateChanged {
            intent_id: IntentId::unchecked("intent-1"),
            operation_family_id: family_id_for(&IntentId::unchecked("intent-1")).unwrap(),
            candidate_id: Some(CandidateId::unchecked("cand-1")),
            candidate_revision: Some(1),
            from: Some(LifecycleState::Reserved),
            to: LifecycleState::IssuanceCommitted,
            tx_id: None,
        },
    }
}

pub fn lifecycle_event_workflow() -> LifecycleEventBody {
    LifecycleEventBody {
        event_id: EventId::unchecked("ev-8"),
        sequence: 8,
        kind: LifecycleEventKind::WorkflowStateChanged {
            workflow_id: WorkflowId::unchecked("wf-1"),
            state: WorkflowState::Paused { reason: PauseReason::FeeCeiling, detail: "base fee above ceiling".into() },
        },
        ..lifecycle_event_body()
    }
}

pub fn deposit_cases() -> Vec<DepositCase> {
    let open = DepositCase {
        case_id: CaseId::unchecked("case-1"),
        kind: CaseKind::ReconciliationDifference,
        severity: CaseSeverity::Critical,
        chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
        movement_id: None,
        checkpoint_id: Some(CheckpointId::unchecked("chk-1")),
        workflow_id: None,
        chain_wallet_id: Some(ChainWalletId::unchecked("wallet-evm")),
        asset_id: Some(AssetId::unchecked("sepolia-usdc")),
        amount_base_units: Some(Amount(100_000)),
        detail: "chain exceeds journal by 100000".into(),
        owner: "treasury-ops".into(),
        state: CaseState::Open,
        opened_at: UnixSeconds(T0 + 400),
    };
    let resolved = DepositCase {
        case_id: CaseId::unchecked("case-2"),
        kind: CaseKind::UnknownAsset,
        severity: CaseSeverity::Warning,
        movement_id: Some(MovementId::unchecked("mov-9")),
        checkpoint_id: None,
        amount_base_units: None,
        asset_id: None,
        state: CaseState::Resolved {
            resolution: "returned to sender".into(),
            resolved_by: vec![CredentialId::unchecked("admin-1"), CredentialId::unchecked("admin-2")],
            resolved_at: UnixSeconds(T0 + 900),
            journal_entry_id: Some(JournalEntryId::unchecked("je-9")),
        },
        ..open.clone()
    };
    vec![open, resolved]
}

pub fn workflow_record() -> WorkflowRecord {
    WorkflowRecord {
        workflow_id: WorkflowId::unchecked("wf-1"),
        kind: WorkflowKind::GasFunding,
        trigger_id: TriggerId::unchecked(format!("trg-{}", &domain_hash_of(domains::WORKFLOW_TRIGGER, &trigger_balance()).to_hex()[..32])),
        trigger: trigger_balance(),
        vault_id: vault_id(),
        steps: vec![WorkflowStep {
            step_index: 0,
            purpose: OperationPurpose::Fees,
            chain_wallet_id: ChainWalletId::unchecked("wallet-gas-source"),
            asset_id: AssetId::unchecked("sepolia-eth"),
            amount_base_units: Amount(5_000_000_000_000_000),
            destination_id: DestinationId::unchecked("dest-gas-wallet-evm"),
            destination_version: 1,
            depends_on: vec![],
            intent_id: Some(IntentId::unchecked("intent-gas-1")),
            operation_family_id: None,
            state: WorkflowStepState::IntentCreated,
            attempts: 1,
            last_error: None,
        }],
        state: WorkflowState::Running,
        attempts: 1,
        max_attempts: 3,
        total_native_spent: Amount(0),
        max_native_spend: Amount(20_000_000_000_000_000),
        created_at: UnixSeconds(T0 + 300),
        updated_at: UnixSeconds(T0 + 310),
    }
}

// ---------------------------------------------------------------------------
// Vector builders
// ---------------------------------------------------------------------------

fn ed(pk: &SigningKey, sig: &SignatureBytes) -> Ed25519OverHash {
    assert_eq!(sig.scheme, SchemeId::Ed25519Pure);
    Ed25519OverHash { public_key_hex: hex::encode(pk.verifying_key().to_bytes()), signature_hex: sig.bytes.to_hex() }
}

fn v<T: serde::Serialize>(name: &str, domain: &str, ty: &str, input: &T, expected: Hash32) -> DomainVector {
    make_vector(name, domain, ty, input, expected).unwrap_or_else(|e| panic!("vector {name}: {e}"))
}

/// Every domain-object vector, keyed by file name.
pub fn build_domain_vectors() -> BTreeMap<String, Vec<DomainVector>> {
    use local_domains as l;
    use oic_domain_types::domains as d;
    let f = evm_flow();
    let sol = sol_case(&f.world.admins[..2]);
    let w = &f.world;
    let mut out: Vec<DomainVector> = Vec::new();

    // AUTHORIZATION
    out.push(v("envelope-body-evm-erc20-exact-candidate", d::AUTHORIZATION, "AuthorizationEnvelopeBody", &f.envelope.body, envelope_body_hash(&f.envelope.body).unwrap()));

    // INTENT
    out.push(v("intent-evm-erc20-exact-candidate", d::INTENT, "Intent", &f.m.intent, intent_hash(&f.m.intent).unwrap()));
    out.push(v("intent-solana-sol-bounded-transfer", d::INTENT, "Intent", &sol.intent, intent_hash(&sol.intent).unwrap()));

    // CANDIDATE (tag defined; no dedicated producer)
    out.push(v("candidate-evm-erc20", d::CANDIDATE, "Candidate", &f.m.candidate, domain_hash_of(d::CANDIDATE, &f.m.candidate)));
    out.push(v("candidate-solana-sol-legacy", d::CANDIDATE, "Candidate", &sol.candidate, domain_hash_of(d::CANDIDATE, &sol.candidate)));

    // DECODED_OPERATION
    out.push(v("decoded-operation-evm-erc20", d::DECODED_OPERATION, "DecodedOperation", &f.verified.decoded, f.verified.decoded_operation_hash));
    out.push(v("decoded-operation-solana-sol", d::DECODED_OPERATION, "DecodedOperation", &sol.verified.decoded, sol.verified.decoded_operation_hash));

    // EVIDENCE
    out.push(v("evidence-evm-sepolia", d::EVIDENCE, "EvidenceBundle", &f.m.evidence, f.m.candidate.evidence_bundle_hash));
    out.push(v("evidence-solana-devnet", d::EVIDENCE, "EvidenceBundle", &sol.evidence, sol.candidate.evidence_bundle_hash));

    // POLICY (unsigned view; input carries the real admin signatures)
    out.push(v("policy-bundle-admin-signed", d::POLICY, "PolicyBundle", &f.m.policy, policy_hash(&f.m.policy).unwrap()));

    // APPROVAL
    let mut g = v("grant-exact-candidate", d::APPROVAL, "ApprovalGrantBody", &f.grant.body, oic_approval_verifier::grant_signing_hash(&f.grant.body).unwrap());
    g.ed25519 = Some(ed(&w.approvers[0].1, &f.grant.signature));
    out.push(g);
    let IntentOperation::AssetTransfer { asset_id, amount_base_units, destination_id, destination_version } = &sol.intent.operation;
    let bounded = sign_grant(
        &w.approvers[1].1,
        ApprovalGrantBody {
            grant_id: GrantId::unchecked("grant-sol-0"),
            institution_id: inst(),
            environment_id: env_id(),
            vault_id: vault_id(),
            intent_id: sol.intent.intent_id.clone(),
            intent_hash: intent_hash(&sol.intent).unwrap(),
            policy_id: policy_id(),
            policy_epoch: Epoch(1),
            scope: GrantScope::BoundedDirectTransfer {
                template: BoundedTransferTemplate {
                    chain_wallet_id: sol.wallet.chain_wallet_id.clone(),
                    network_id: sol.wallet.network_id.clone(),
                    asset_id: asset_id.clone(),
                    amount_base_units: *amount_base_units,
                    destination_id: destination_id.clone(),
                    destination_version: *destination_version,
                    destination_address: sol.destination.address.clone(),
                    max_native_fee_base_units: sol.intent.constraints.max_network_fee_base_units,
                    maximum_successful_payments: 1,
                    fillable: vec![FillableField::SolanaRecentBlockhash],
                },
            },
            approver_credential_id: w.approvers[1].0.clone(),
            approver_role: w.approvers[1].2,
            issued_at: UnixSeconds(T0),
            expires_at: UnixSeconds(NOW + 3600),
        },
    )
    .unwrap();
    let mut g = v("grant-bounded-direct-transfer", d::APPROVAL, "ApprovalGrantBody", &bounded.body, oic_approval_verifier::grant_signing_hash(&bounded.body).unwrap());
    g.ed25519 = Some(ed(&w.approvers[1].1, &bounded.signature));
    out.push(g);

    // PREVIEW
    let c = &f.m.candidate;
    let preview = PreviewCommitmentOwned {
        candidate_id: c.candidate_id.clone(),
        candidate_revision: c.candidate_revision,
        decoded_operation_hash: f.verified.decoded_operation_hash,
        evidence_bundle_hash: c.evidence_bundle_hash,
    };
    out.push(v("preview-evm-erc20", d::PREVIEW, "PreviewCommitment", &preview, f.preview_hash));

    // AUTHORITY_RECEIPT
    let reserved = &f.envelope.authorization_state_receipt;
    let mut r = v("receipt-reserved", d::AUTHORITY_RECEIPT, "AuthorityReceiptBody", &reserved.body, receipt_hash(&reserved.body).unwrap());
    r.ed25519 = Some(ed(&w.authority_sk, &reserved.signature));
    out.push(r);
    let mut r = v("receipt-release", d::AUTHORITY_RECEIPT, "AuthorityReceiptBody", &f.release.body, receipt_hash(&f.release.body).unwrap());
    r.ed25519 = Some(ed(&w.authority_sk, &f.release.signature));
    out.push(r);

    // RESOURCE_CLAIMS: the real authority's receipt commits to the verified claims.
    out.push(v("resource-claims-evm-erc20", d::RESOURCE_CLAIMS, "ResourceClaims", &f.verified.claims, reserved.body.claims_hash));

    // CHAIN_PROFILE
    out.push(v("chain-profile-evm-sepolia", d::CHAIN_PROFILE, "ChainProfile", &f.profile, f.envelope.body.chain_profile_hash));
    let sp = sol_profile();
    out.push(v("chain-profile-solana-devnet", d::CHAIN_PROFILE, "ChainProfile", &sp, sp.hash().unwrap()));

    // AUDIT (events the authority audit sink appended during the flow)
    let events = w.audit.events();
    assert!(events.len() >= 3, "policy_activated, reserved, released");
    for e in events.iter().take(3) {
        let name = format!("audit-event-{}-{}", e.body.sequence, e.body.action.replace('.', "-"));
        let mut a = v(&name, d::AUDIT, "AuditEventBody", &e.body, oic_audit::event_hash(&e.body).unwrap());
        a.ed25519 = Some(ed(&w.audit_sk, &e.signature));
        out.push(a);
    }

    // KEY_DESCRIPTOR (tag defined; no dedicated producer)
    out.push(v("key-descriptor-evm-dev-single-key", d::KEY_DESCRIPTOR, "KeyDescriptor", &f.m.key, domain_hash_of(d::KEY_DESCRIPTOR, &f.m.key)));
    out.push(v("key-descriptor-solana-frost-2-of-3", d::KEY_DESCRIPTOR, "KeyDescriptor", &sol.key, domain_hash_of(d::KEY_DESCRIPTOR, &sol.key)));

    // PUBLIC_KEY
    out.push(v("public-key-secp256k1-compressed", d::PUBLIC_KEY, "PublicKey", &f.m.key.public_key, f.envelope.body.public_key_hash));
    out.push(v("public-key-ed25519", d::PUBLIC_KEY, "PublicKey", &sol.key.public_key, public_key_hash(&sol.key.public_key).unwrap()));

    // CONFIG_PROPOSAL
    let freeze = FreezeProposal::new(inst(), env_id(), FreezeScope::Vault { vault_id: vault_id() }, w.responder.0.clone(), "suspicious destination");
    out.push(v("freeze-proposal-vault", d::CONFIG_PROPOSAL, "FreezeProposal", &freeze, freeze.hash().unwrap()));
    let unfreeze = UnfreezeProposal::new(inst(), env_id(), FreezeScope::Global, 12);
    out.push(v("unfreeze-proposal-global", d::CONFIG_PROPOSAL, "UnfreezeProposal", &unfreeze, unfreeze.hash().unwrap()));

    // DESTINATION (unsigned view; input carries the real admin signatures)
    out.push(v("destination-evm-admin-signed", d::DESTINATION, "CounterpartyDestination", &f.m.destination, f.envelope.body.destination_hash));
    out.push(v("destination-solana-admin-signed", d::DESTINATION, "CounterpartyDestination", &sol.destination, destination_hash(&sol.destination).unwrap()));

    // JOURNAL / OBSERVED_MOVEMENT / RECONCILIATION / WORKFLOW_TRIGGER / WEBHOOK
    let je1 = journal_entry_body();
    out.push(v("journal-entry-accepted-receipt", d::JOURNAL, "JournalEntryBody", &je1, domain_hash_of(d::JOURNAL, &je1)));
    let je2 = journal_entry_internal();
    out.push(v("journal-entry-internal-transfer", d::JOURNAL, "JournalEntryBody", &je2, domain_hash_of(d::JOURNAL, &je2)));
    let m1 = observed_movement();
    out.push(v("observed-movement-inbound-erc20-accepted", d::OBSERVED_MOVEMENT, "ObservedMovement", &m1, domain_hash_of(d::OBSERVED_MOVEMENT, &m1)));
    let m2 = reorged_movement();
    out.push(v("observed-movement-outbound-reorged", d::OBSERVED_MOVEMENT, "ObservedMovement", &m2, domain_hash_of(d::OBSERVED_MOVEMENT, &m2)));
    let rc = reconciliation_body();
    out.push(v("reconciliation-checkpoint-difference", d::RECONCILIATION, "ReconciliationCheckpointBody", &rc, domain_hash_of(d::RECONCILIATION, &rc)));
    for (name, t) in [("workflow-trigger-deposit-accepted", trigger_deposit()), ("workflow-trigger-balance-below-minimum", trigger_balance()), ("workflow-trigger-manual", trigger_manual())] {
        out.push(v(name, d::WORKFLOW_TRIGGER, "WorkflowTrigger", &t, domain_hash_of(d::WORKFLOW_TRIGGER, &t)));
    }
    let le = lifecycle_event_body();
    out.push(v("lifecycle-event-operation-state-changed", d::WEBHOOK, "LifecycleEventBody", &le, domain_hash_of(d::WEBHOOK, &le)));
    let le2 = lifecycle_event_workflow();
    out.push(v("lifecycle-event-workflow-paused", d::WEBHOOK, "LifecycleEventBody", &le2, domain_hash_of(d::WEBHOOK, &le2)));

    // SIGNER_FENCE (cross-checked against the ledger calls of the real signer)
    out.push(v("signer-fence-key", d::SIGNER_FENCE, "ParticipantId", &f.participant, domain_hash_of(d::SIGNER_FENCE, &f.participant)));
    let abort: SessionAbortPreimage = ("session-abort".into(), SigningSessionId::unchecked(SESSION));
    out.push(v("signer-abort-sentinel", d::SIGNER_FENCE, "SessionAbortPreimage", &abort, domain_hash_of(d::SIGNER_FENCE, &abort)));

    // AUTHORITY_ID
    let res: ReservationIdPreimage = ("res".into(), (c.operation_family_id.clone(), c.candidate_id.clone(), c.candidate_revision));
    out.push(v("authority-id-reservation", l::AUTHORITY_ID, "ReservationIdPreimage", &res, domain_hash_of(l::AUTHORITY_ID, &res)));
    let fam: FamilyIdPreimage = ("fam".into(), f.m.intent.intent_id.clone());
    out.push(v("authority-id-family", l::AUTHORITY_ID, "FamilyIdPreimage", &fam, domain_hash_of(l::AUTHORITY_ID, &fam)));
    let iss: IssuanceIdPreimage = ("iss".into(), f.envelope.body.budget_reservation_id.clone());
    out.push(v("authority-id-issuance", l::AUTHORITY_ID, "IssuanceIdPreimage", &iss, domain_hash_of(l::AUTHORITY_ID, &iss)));

    // AUTHORITY_STATE + AUTHORITY_CHECKPOINT: a fresh authority after one policy activation
    let (state, checkpoint) = fresh_authority_checkpoint(w, &f.m.policy);
    out.push(v("authority-state-after-policy-activation", l::AUTHORITY_STATE, "AuthorityState", &state, checkpoint.body.state_hash));
    let mut cp = v("authority-checkpoint", l::AUTHORITY_CHECKPOINT, "CheckpointBody", &checkpoint.body, checkpoint_hash(&checkpoint.body).unwrap());
    cp.ed25519 = Some(ed(&w.authority_sk, &checkpoint.signature));
    out.push(cp);

    // AUDIT_EVENT_ID
    let e1 = &events[0];
    out.push(v("audit-event-id-1", l::AUDIT_EVENT_ID, "AuditEventBody", &e1.body, domain_hash_of(l::AUDIT_EVENT_ID, &event_id_preimage(&e1.body))));

    // AUDIT_CHECKPOINT
    let acp = w.audit.checkpoint().unwrap();
    let mut a = v("audit-checkpoint", l::AUDIT_CHECKPOINT, "AuditCheckpointBody", &acp.body, oic_audit::audit_checkpoint_hash(&acp.body).unwrap());
    a.ed25519 = Some(ed(&w.audit_sk, &acp.signature));
    out.push(a);

    // AUDIT_OBJECT + AUTHORITY_EVENT
    let obj: AuditObjectPreimage = ("reservation".into(), f.envelope.body.budget_reservation_id.as_str().to_string());
    out.push(v("audit-object-reservation", l::AUDIT_OBJECT, "AuditObjectPreimage", &obj, oic_audit::object_commitment(&obj.0, &obj.1).unwrap()));
    for e in authority_events(&f) {
        let name = match &e {
            AuthorityEvent::Reserved { .. } => "authority-event-reserved",
            AuthorityEvent::Released { .. } => "authority-event-released",
            _ => "authority-event-policy-activated",
        };
        out.push(v(name, l::AUTHORITY_EVENT, "AuthorityEvent", &e, oic_audit::authority_event_commitment(&e).unwrap()));
    }

    let mut files: BTreeMap<String, Vec<DomainVector>> = BTreeMap::new();
    for vec in out {
        files.entry(file_name_for_domain(&vec.domain)).or_default().push(vec);
    }
    files
}

pub fn event_id_preimage(b: &AuditEventBody) -> AuditEventIdPreimageOwned {
    AuditEventIdPreimageOwned {
        sequence: b.sequence,
        previous_event_hash: b.previous_event_hash,
        at: b.at,
        actor: b.actor.clone(),
        action: b.action.clone(),
        object_commitments: b.object_commitments.clone(),
        policy_epoch: b.policy_epoch,
        detail: b.detail.clone(),
    }
}

/// The authority events of the flow, reconstructed from its receipts and
/// issuance record. [`AuthorityAuditSink`] recorded each one's commitment
/// under `authority_event` in the audit log; the conformance tests compare.
pub fn authority_events(f: &EvmFlow) -> Vec<AuthorityEvent> {
    let policy_seq = f.world.audit.events()[0].body.detail.split(' ').next().and_then(|kv| kv.strip_prefix("commit_sequence=")).and_then(|s| s.parse().ok()).expect("commit sequence in audit detail");
    vec![
        AuthorityEvent::PolicyActivated { policy_epoch: f.m.policy.policy_epoch, policy_hash: f.envelope.body.policy_hash, commit_sequence: policy_seq },
        AuthorityEvent::Reserved { reservation_id: f.envelope.body.budget_reservation_id.clone(), commit_sequence: f.envelope.authorization_state_receipt.body.commit_sequence },
        AuthorityEvent::Released {
            reservation_id: f.envelope.body.budget_reservation_id.clone(),
            issuance_id: f.issuance.issuance_id.clone(),
            commit_sequence: f.issuance.commit_sequence,
        },
    ]
}

/// A separate authority over a fresh store with only the policy activated:
/// its state is JSON-representable (no enum-keyed lock or idempotency maps).
pub fn fresh_authority_checkpoint(w: &World, policy: &PolicyBundle) -> (AuthorityState, SignedCheckpoint) {
    let a = Authority::open(Arc::new(InMemoryAuthorityStore::new()), 0, authority_config(&w.admins, &w.responder), w.authority_sk.clone(), w.clock.clone()).unwrap();
    a.set_policy(policy).unwrap();
    let state = a.store().read(|st| st.clone()).unwrap();
    let cp = a.checkpoint().unwrap();
    (state, cp)
}

// ---------------------------------------------------------------------------
// Native payload vectors
// ---------------------------------------------------------------------------

/// JSON description of a type-2 transaction (the vector `input`).
pub fn eip1559_json(t: &oic_adapter_evm::tx::Eip1559Tx) -> Value {
    assert!(t.access_list.is_empty(), "vectors use empty access lists");
    json!({
        "type": "eip1559",
        "chain_id": t.chain_id,
        "nonce": t.nonce,
        "max_priority_fee_per_gas": t.max_priority_fee_per_gas.to_string(),
        "max_fee_per_gas": t.max_fee_per_gas.to_string(),
        "gas_limit": t.gas_limit,
        "to": format!("0x{}", hex::encode(t.to)),
        "value": t.value.to_string(),
        "data": format!("0x{}", hex::encode(&t.data)),
        "access_list": [],
    })
}

/// Inverse of [`eip1559_json`].
pub fn eip1559_from_json(v: &Value) -> oic_adapter_evm::tx::Eip1559Tx {
    let s = |k: &str| v[k].as_str().unwrap_or_else(|| panic!("{k}"));
    let h = |k: &str| hex::decode(s(k).trim_start_matches("0x")).unwrap();
    assert_eq!(s("type"), "eip1559");
    assert_eq!(v["access_list"], json!([]));
    oic_adapter_evm::tx::Eip1559Tx {
        chain_id: v["chain_id"].as_u64().unwrap(),
        nonce: v["nonce"].as_u64().unwrap(),
        max_priority_fee_per_gas: s("max_priority_fee_per_gas").parse().unwrap(),
        max_fee_per_gas: s("max_fee_per_gas").parse().unwrap(),
        gas_limit: v["gas_limit"].as_u64().unwrap(),
        to: h("to").try_into().unwrap(),
        value: s("value").parse().unwrap(),
        data: h("data"),
        access_list: vec![],
    }
}

/// JSON description of a Solana message (the vector `input`).
pub fn sol_message_json(m: &SolMessage) -> Value {
    json!({
        "version": match m.version { MessageVersion::Legacy => "legacy", MessageVersion::V0 => "v0" },
        "header": {
            "num_required_signatures": m.header.num_required_signatures,
            "num_readonly_signed_accounts": m.header.num_readonly_signed_accounts,
            "num_readonly_unsigned_accounts": m.header.num_readonly_unsigned_accounts,
        },
        "account_keys": m.account_keys.iter().map(hex::encode).collect::<Vec<_>>(),
        "recent_blockhash": hex::encode(m.recent_blockhash),
        "instructions": m.instructions.iter().map(|i| json!({
            "program_id_index": i.program_id_index,
            "accounts": hex::encode(&i.accounts),
            "data": hex::encode(&i.data),
        })).collect::<Vec<_>>(),
        "address_table_lookups": m.address_table_lookups.iter().map(|l| json!({
            "account_key": hex::encode(l.account_key),
            "writable_indexes": hex::encode(&l.writable_indexes),
            "readonly_indexes": hex::encode(&l.readonly_indexes),
        })).collect::<Vec<_>>(),
    })
}

/// Inverse of [`sol_message_json`].
pub fn sol_message_from_json(v: &Value) -> SolMessage {
    let hx = |x: &Value| hex::decode(x.as_str().unwrap()).unwrap();
    let k32 = |x: &Value| -> [u8; 32] { hx(x).try_into().unwrap() };
    let u8f = |x: &Value| u8::try_from(x.as_u64().unwrap()).unwrap();
    SolMessage {
        version: match v["version"].as_str().unwrap() {
            "legacy" => MessageVersion::Legacy,
            "v0" => MessageVersion::V0,
            other => panic!("unknown message version {other}"),
        },
        header: MessageHeader {
            num_required_signatures: u8f(&v["header"]["num_required_signatures"]),
            num_readonly_signed_accounts: u8f(&v["header"]["num_readonly_signed_accounts"]),
            num_readonly_unsigned_accounts: u8f(&v["header"]["num_readonly_unsigned_accounts"]),
        },
        account_keys: v["account_keys"].as_array().unwrap().iter().map(k32).collect(),
        recent_blockhash: k32(&v["recent_blockhash"]),
        instructions: v["instructions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| CompiledInstruction { program_id_index: u8f(&i["program_id_index"]), accounts: hx(&i["accounts"]), data: hx(&i["data"]) })
            .collect(),
        address_table_lookups: v["address_table_lookups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| AddressTableLookup { account_key: k32(&l["account_key"]), writable_indexes: hx(&l["writable_indexes"]), readonly_indexes: hx(&l["readonly_indexes"]) })
            .collect(),
    }
}

/// Hand-built v0 SOL transfer whose recipient is resolved through one
/// address lookup table (writable index 0 of table `[0x11; 32]`).
pub fn sol_v0_message(key: &KeyDescriptor) -> SolMessage {
    let payer: [u8; 32] = key.public_key.bytes.as_slice().try_into().unwrap();
    SolMessage {
        version: MessageVersion::V0,
        header: MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 },
        account_keys: vec![payer, oic_adapter_solana::address::SYSTEM_PROGRAM_ID],
        recent_blockhash: SOL_BLOCKHASH,
        instructions: vec![CompiledInstruction { program_id_index: 1, accounts: vec![0, 2], data: oic_adapter_solana::instruction::system_transfer_data(1_000_000) }],
        address_table_lookups: vec![AddressTableLookup { account_key: [0x11; 32], writable_indexes: vec![0], readonly_indexes: vec![] }],
    }
}

/// Hand-built EIP-1559 native transfer.
pub fn evm_native_tx() -> oic_adapter_evm::tx::Eip1559Tx {
    oic_adapter_evm::tx::Eip1559Tx {
        chain_id: EVM_CHAIN_ID,
        nonce: 7,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 21_000_000_000,
        gas_limit: 21_000,
        to: [0xde; 20],
        value: 1_000_000_000_000_000,
        data: vec![],
        access_list: vec![],
    }
}

fn native_vector(name: &str, adapter: &dyn ChainAdapter, profile: &ChainProfile, input: Value, bytes: &[u8], key: &KeyDescriptor, differential: &str) -> NativeVector {
    let manifest = adapter.manifest();
    let payloads = adapter.signing_payloads(&Bytes(bytes.to_vec()), key).unwrap_or_else(|e| panic!("{name}: {e}"));
    let [payload] = payloads.as_slice() else { panic!("{name}: expected exactly one payload") };
    NativeVector {
        name: name.into(),
        adapter_id: manifest.adapter_id.as_str().into(),
        adapter_version: manifest.adapter_version,
        verifier_build_hash_hex: manifest.verifier_build_hash.to_hex(),
        chain_profile: serde_json::to_value(profile).unwrap(),
        input,
        native_unsigned_bytes_hex: hex::encode(bytes),
        signing_payload: serde_json::to_value(payload).unwrap(),
        signing_payload_canonical_cbor_hex: hex::encode(canonical_bytes(payload).unwrap()),
        differential: differential.into(),
    }
}

/// Native payload vectors keyed by file name.
pub fn build_native_vectors() -> BTreeMap<String, Vec<NativeVector>> {
    use oic_adapter_evm::tx::{EvmTx, Eip1559Tx};
    let f = evm_flow();
    let sol = sol_case(&f.world.admins[..2]);
    let evm = oic_adapter_evm::EvmAdapter;
    let solana = oic_adapter_solana::SolanaAdapter;
    let alloy = "alloy-consensus =2.5.0 TxEip1559::encode_for_signing / signature_hash";
    let sdk = "solana-message =6.0.0 VersionedMessage::serialize and bincode; solana-transaction =6.0.0 VersionedTransaction::verify_and_hash_message";

    let built = f.m.candidate.native_unsigned_bytes.as_slice();
    let EvmTx::Type2(erc20) = EvmTx::decode_unsigned(built).unwrap() else { panic!("type-2 candidate") };
    let native = evm_native_tx();
    let native_bytes = Eip1559Tx::encode_unsigned(&native);
    let evm_vectors = vec![
        native_vector("evm-eip1559-erc20-transfer-built", &evm, &f.profile, eip1559_json(&erc20), built, &f.m.key, alloy),
        native_vector("evm-eip1559-native-transfer", &evm, &f.profile, eip1559_json(&native), &native_bytes, &f.m.key, alloy),
    ];

    let legacy = SolMessage::decode(sol.candidate.native_unsigned_bytes.as_slice()).unwrap();
    let v0 = sol_v0_message(&sol.key);
    let v0_bytes = v0.encode();
    let sol_vectors = vec![
        native_vector("solana-legacy-sol-transfer-built", &solana, &sol_profile(), sol_message_json(&legacy), sol.candidate.native_unsigned_bytes.as_slice(), &sol.key, sdk),
        native_vector("solana-v0-sol-transfer-lookup-table", &solana, &sol_profile(), sol_message_json(&v0), &v0_bytes, &sol.key, sdk),
    ];
    let mut out = BTreeMap::new();
    out.insert("native-evm.json".to_string(), evm_vectors);
    out.insert("native-solana.json".to_string(), sol_vectors);
    out
}

/// Plain SHA-256 used where the tests recompute hashes independently.
pub fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex::encode(h.finalize())
}

/// Ensure the helper used by the flow and the signer agree on the payload hash.
pub fn payload_hash(p: &NativeSigningPayload) -> Hash32 {
    sha256(p.message_or_digest.as_slice())
}
