//! EVM fixtures (modelled on `crates/adapter-evm/tests/common`).

use super::*;
use k256::ecdsa::SigningKey as K256Key;
use oic_adapter_evm::address::{address_from_sec1, eip55, Address};
use oic_adapter_evm::evidence::*;
use oic_adapter_evm::*;

pub const CHAIN_ID: u64 = 11_155_111;
pub const NONCE: u64 = 5;
pub const BASE_FEE: u128 = 10_000_000_000;
pub const PRIORITY_FEE: u128 = 1_000_000_000;
pub const GAS_LIMIT: u64 = 65_000;

pub fn token_contract() -> Address {
    [0xc0; 20]
}
pub fn dest_address() -> Address {
    [0xde; 20]
}
pub fn attacker_address() -> Address {
    [0xee; 20]
}

pub fn signing_key() -> K256Key {
    let mut b = [0x11u8; 32];
    b[0] = 1;
    K256Key::from_bytes(&b.into()).unwrap()
}

pub fn sender() -> Address {
    address_from_sec1(signing_key().verifying_key().to_encoded_point(true).as_bytes()).unwrap()
}

pub fn profile() -> ChainProfile {
    ChainProfile {
        chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
        adapter_id: AdapterId::unchecked("evm"),
        network_id: NetworkId::unchecked("evm-11155111"),
        network_binding: network_binding_for_chain_id(CHAIN_ID),
        display_name: "Sepolia".into(),
        accepted_versions: vec![VERSION_TYPE2.to_string()],
        finality_commitment: "finalized".into(),
        finality_depth: 2,
        max_evidence_age_seconds: 120,
        accepted_trust_levels: vec![EvidenceTrustLevel::DevelopmentSimulator],
    }
}

pub fn native_asset() -> Asset {
    Asset {
        asset_id: AssetId::unchecked("sepolia-eth"),
        network_id: NetworkId::unchecked("evm-11155111"),
        asset: AssetKind::Native,
        decimals: 18,
        symbol: "ETH".into(),
        behavior: AssetBehaviorProfile::Standard,
    }
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

pub fn destination(address: Address) -> CounterpartyDestination {
    let d = CounterpartyDestination {
        destination_id: DestinationId::unchecked("dest-1"),
        version: 3,
        network_id: NetworkId::unchecked("evm-11155111"),
        address: Bytes(address.to_vec()),
        address_display: eip55(&address),
        display_name: "Acme Settlement LLC".into(),
        allowed_assets: vec![],
        verification_evidence: "callback 2026-01-02".into(),
        activation_epoch: Epoch(1),
        administrative_signatures: vec![],
    };
    signed_destination(d, &[1, 2])
}

/// A world whose candidate was built by the real EVM adapter. `paid_to`
/// models a compromised console/builder that builds the transaction to a
/// different address while presenting the registry destination.
pub fn world(asset: Asset, amount: u128, mode: ApprovalMode, paid_to: Option<Address>) -> World {
    let profile = profile();
    let sender = sender();
    let pubkey = signing_key().verifying_key().to_encoded_point(true).as_bytes().to_vec();
    let key = KeyDescriptor {
        key_id: KeyId::unchecked("key-1"),
        key_epoch: Epoch(1),
        scheme: SchemeId::EcdsaSecp256k1Keccak256Prehashed,
        public_key: PublicKey { scheme: SchemeId::EcdsaSecp256k1Keccak256Prehashed, bytes: Bytes(pubkey) },
        backend_id: "dev".into(),
        backend_commit: "dev".into(),
        participants: vec![],
        threshold: 1,
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        networks: vec![profile.network_id.clone()],
        recovery_profile: "none".into(),
    };
    let wallet = ChainWallet {
        chain_wallet_id: ChainWalletId::unchecked("wallet-1"),
        vault_id: VaultId::unchecked("vault-1"),
        chain_profile_id: profile.chain_profile_id.clone(),
        network_id: profile.network_id.clone(),
        key_id: key.key_id.clone(),
        key_epoch: key.key_epoch,
        address: Bytes(sender.to_vec()),
        address_display: eip55(&sender),
        active: true,
    };
    let registry = destination(dest_address());
    let mut items = BTreeMap::new();
    items.insert(nonce_key(&sender), Bytes(NONCE.to_be_bytes().to_vec()));
    items.insert(KEY_BASE_FEE.to_string(), Bytes(BASE_FEE.to_be_bytes().to_vec()));
    items.insert(KEY_PRIORITY_FEE.to_string(), Bytes(PRIORITY_FEE.to_be_bytes().to_vec()));
    items.insert(KEY_GAS_LIMIT.to_string(), Bytes(GAS_LIMIT.to_be_bytes().to_vec()));
    items.insert(KEY_CHAIN_ID.to_string(), Bytes(CHAIN_ID.to_be_bytes().to_vec()));
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
    let intent = base_intent(&profile, &asset, &registry, amount, 10u128.pow(16), mode);
    let placeholder = Candidate {
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
    };
    let mut w = World { profile, intent, candidate: placeholder, wallet, key, vault: vault(), asset, destination: registry, policy: policy(&[1, 2]), evidence };
    let build_dest = destination(paid_to.unwrap_or_else(dest_address));
    w.candidate = EvmAdapter.build_candidate(&w.build_ctx(&build_dest)).expect("EVM build");
    w
}
