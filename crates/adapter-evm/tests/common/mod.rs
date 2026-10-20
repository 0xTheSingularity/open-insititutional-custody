//! Shared fixtures for EVM adapter integration tests.
#![allow(dead_code)]

use k256::ecdsa::SigningKey;
use oic_adapter_api::*;
use oic_adapter_evm::address::{address_from_sec1, eip55, Address};
use oic_adapter_evm::evidence::*;
use oic_adapter_evm::*;
use oic_domain_types::*;
use std::collections::BTreeMap;

pub const CHAIN_ID: u64 = 11_155_111;
pub const OBSERVED_AT: u64 = 1_700_000_000;
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

pub struct Fx {
    pub sk: SigningKey,
    pub sender: Address,
    pub profile: ChainProfile,
    pub wallet: ChainWallet,
    pub key: KeyDescriptor,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub evidence: EvidenceBundle,
    pub intent: Intent,
}

pub fn signing_key(seed: u8) -> SigningKey {
    let mut b = [0x11u8; 32];
    b[0] = seed.max(1);
    SigningKey::from_bytes(&b.into()).unwrap()
}

pub fn profile(versions: &[&str]) -> ChainProfile {
    ChainProfile {
        chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
        adapter_id: AdapterId::unchecked("evm"),
        network_id: NetworkId::unchecked("evm-11155111"),
        network_binding: network_binding_for_chain_id(CHAIN_ID),
        display_name: "Sepolia".into(),
        accepted_versions: versions.iter().map(|s| s.to_string()).collect(),
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

pub fn erc20_asset(contract: Address) -> Asset {
    Asset {
        asset_id: AssetId::unchecked("sepolia-usdc"),
        network_id: NetworkId::unchecked("evm-11155111"),
        asset: AssetKind::Erc20 { contract: Bytes(contract.to_vec()) },
        decimals: 6,
        symbol: "USDC".into(),
        behavior: AssetBehaviorProfile::Standard,
    }
}

pub fn fixture_with(asset: Asset, seed: u8) -> Fx {
    let sk = signing_key(seed);
    let pubkey = sk.verifying_key().to_encoded_point(true).as_bytes().to_vec();
    let sender = address_from_sec1(&pubkey).unwrap();
    let profile = profile(&[VERSION_TYPE2]);
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
    let destination = CounterpartyDestination {
        destination_id: DestinationId::unchecked("dest-1"),
        version: 3,
        network_id: profile.network_id.clone(),
        address: Bytes(dest_address().to_vec()),
        address_display: eip55(&dest_address()),
        display_name: "Counterparty".into(),
        allowed_assets: vec![],
        verification_evidence: "test".into(),
        activation_epoch: Epoch(1),
        administrative_signatures: vec![],
    };
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
    let intent = Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked("intent-1"),
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        vault_id: wallet.vault_id.clone(),
        chain_wallet_id: wallet.chain_wallet_id.clone(),
        chain_profile_id: profile.chain_profile_id.clone(),
        operation: IntentOperation::AssetTransfer {
            asset_id: asset.asset_id.clone(),
            amount_base_units: Amount(1_000_000),
            destination_id: destination.destination_id.clone(),
            destination_version: destination.version,
        },
        constraints: IntentConstraints {
            max_network_fee_base_units: Amount(10u128.pow(16)),
            approval_mode: ApprovalMode::ExactCandidate,
            maximum_successful_payments: 1,
        },
        purpose: OperationPurpose::Settlement,
        external_reference: "ref".into(),
        proposer_credential_id: CredentialId::unchecked("cred"),
        created_at: UnixSeconds(OBSERVED_AT - 100),
    };
    Fx { sk, sender, profile, wallet, key, asset, destination, evidence, intent }
}

pub fn native_fixture() -> Fx {
    fixture_with(native_asset(), 1)
}

pub fn erc20_fixture() -> Fx {
    fixture_with(erc20_asset(token_contract()), 1)
}

impl Fx {
    pub fn build_ctx(&self) -> BuildContext {
        BuildContext {
            intent: self.intent.clone(),
            wallet: self.wallet.clone(),
            key: self.key.clone(),
            asset: self.asset.clone(),
            destination: self.destination.clone(),
            profile: self.profile.clone(),
            evidence: self.evidence.clone(),
            candidate_id: CandidateId::unchecked("cand-1"),
            candidate_revision: 1,
            operation_family_id: OperationFamilyId::unchecked("family-1"),
            built_at: UnixSeconds(OBSERVED_AT + 10),
        }
    }

    pub fn vctx(&self) -> VerifyContext<'_> {
        VerifyContext {
            profile: &self.profile,
            wallet: &self.wallet,
            key: &self.key,
            asset: &self.asset,
            destination: &self.destination,
            evidence: &self.evidence,
        }
    }

    pub fn build(&self) -> Candidate {
        EvmAdapter.build_candidate(&self.build_ctx()).expect("build")
    }

    /// Sign the candidate's first payload digest: 65 bytes r||s||v.
    pub fn sign(&self, candidate: &Candidate) -> SignatureBytes {
        sign_digest(&self.sk, candidate.signing_payloads[0].message_or_digest.as_slice())
    }

    /// Wrap arbitrary unsigned bytes into a candidate with correctly derived payloads.
    pub fn candidate_for(&self, bytes: Vec<u8>, revision: u32) -> Candidate {
        let mut c = self.build();
        c.candidate_revision = revision;
        c.native_unsigned_bytes = Bytes(bytes);
        c.signing_payloads = EvmAdapter.signing_payloads(&c.native_unsigned_bytes, &self.key).unwrap_or_default();
        c
    }
}

pub fn sign_digest(sk: &SigningKey, digest: &[u8]) -> SignatureBytes {
    let (sig, recid) = sk.sign_prehash_recoverable(digest).unwrap();
    let mut b = sig.to_bytes().to_vec();
    b.push(recid.to_byte());
    SignatureBytes { scheme: SchemeId::EcdsaSecp256k1Keccak256Prehashed, bytes: Bytes(b) }
}
