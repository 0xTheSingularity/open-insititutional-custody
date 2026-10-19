//! Shared fixtures for Solana adapter integration tests.
#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use oic_adapter_api::*;
use oic_adapter_solana::address::*;
use oic_adapter_solana::evidence::*;
use oic_adapter_solana::*;
use oic_domain_types::*;
use std::collections::BTreeMap;

pub const OBSERVED_AT: u64 = 1_700_000_000;
pub const STATE_HEIGHT: u64 = 1_000;
pub const LAST_VALID_HEIGHT: u64 = 1_150;
pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
pub const RENT: u64 = 2_039_280;
pub const AMOUNT: u128 = 1_000_000;
pub const FINALITY_DEPTH: u64 = 32;

pub const GENESIS: [u8; 32] = [0x6e; 32];
pub const BLOCKHASH: [u8; 32] = [0xbb; 32];

pub fn mint() -> Pubkey {
    [0xc0; 32]
}

/// Registered destination owner wallet.
pub fn dest_owner() -> Pubkey {
    signing_key(77).verifying_key().to_bytes()
}

pub struct Fx {
    pub sk: SigningKey,
    pub wallet_addr: Pubkey,
    pub profile: ChainProfile,
    pub wallet: ChainWallet,
    pub key: KeyDescriptor,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub evidence: EvidenceBundle,
    pub intent: Intent,
}

pub fn signing_key(seed: u8) -> SigningKey {
    let mut b = [0x22u8; 32];
    b[0] = seed;
    SigningKey::from_bytes(&b)
}

pub fn profile(versions: &[&str]) -> ChainProfile {
    ChainProfile {
        chain_profile_id: ChainProfileId::unchecked("solana-devnet-v1"),
        adapter_id: AdapterId::unchecked("solana"),
        network_id: NetworkId::unchecked("solana-devnet"),
        network_binding: Bytes(GENESIS.to_vec()),
        display_name: "Solana devnet".into(),
        accepted_versions: versions.iter().map(|s| s.to_string()).collect(),
        finality_commitment: "finalized".into(),
        finality_depth: FINALITY_DEPTH,
        max_evidence_age_seconds: 120,
        accepted_trust_levels: vec![EvidenceTrustLevel::DevelopmentSimulator],
    }
}

pub fn native_asset() -> Asset {
    Asset {
        asset_id: AssetId::unchecked("devnet-sol"),
        network_id: NetworkId::unchecked("solana-devnet"),
        asset: AssetKind::Native,
        decimals: 9,
        symbol: "SOL".into(),
        behavior: AssetBehaviorProfile::Standard,
    }
}

pub fn spl_asset(mint: Pubkey, token_program: Pubkey) -> Asset {
    Asset {
        asset_id: AssetId::unchecked("devnet-usdc"),
        network_id: NetworkId::unchecked("solana-devnet"),
        asset: AssetKind::SplToken { mint: Bytes(mint.to_vec()), token_program: Bytes(token_program.to_vec()) },
        decimals: 6,
        symbol: "USDC".into(),
        behavior: AssetBehaviorProfile::Standard,
    }
}

pub fn le64(v: u64) -> Bytes {
    Bytes(v.to_le_bytes().to_vec())
}

pub fn token_account(mint: Pubkey, owner: Pubkey) -> TokenAccountEvidence {
    TokenAccountEvidence {
        mint: Bytes(mint.to_vec()),
        owner: Bytes(owner.to_vec()),
        amount: 10_000_000,
        delegate: None,
        close_authority: None,
        state: TOKEN_ACCOUNT_INITIALIZED,
    }
}

pub fn canon<T: serde::Serialize>(v: &T) -> Bytes {
    Bytes(oic_canonical_encoding::canonical_bytes(v).unwrap())
}

pub fn fixture_with(asset: Asset, seed: u8) -> Fx {
    let sk = signing_key(seed);
    let wallet_addr = sk.verifying_key().to_bytes();
    let profile = profile(&[VERSION_LEGACY, VERSION_V0]);
    let key = KeyDescriptor {
        key_id: KeyId::unchecked("key-1"),
        key_epoch: Epoch(1),
        scheme: SchemeId::Ed25519Pure,
        public_key: PublicKey { scheme: SchemeId::Ed25519Pure, bytes: Bytes(wallet_addr.to_vec()) },
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
        address: Bytes(wallet_addr.to_vec()),
        address_display: to_base58(&wallet_addr),
        active: true,
    };
    let destination = CounterpartyDestination {
        destination_id: DestinationId::unchecked("dest-1"),
        version: 3,
        network_id: profile.network_id.clone(),
        address: Bytes(dest_owner().to_vec()),
        address_display: to_base58(&dest_owner()),
        display_name: "Counterparty".into(),
        allowed_assets: vec![],
        verification_evidence: "test".into(),
        activation_epoch: Epoch(1),
    };
    let mut items = BTreeMap::new();
    items.insert(KEY_GENESIS_HASH.to_string(), Bytes(GENESIS.to_vec()));
    items.insert(KEY_RECENT_BLOCKHASH.to_string(), Bytes(BLOCKHASH.to_vec()));
    items.insert(KEY_BLOCKHASH_LAST_VALID_HEIGHT.to_string(), le64(LAST_VALID_HEIGHT));
    items.insert(KEY_LAMPORTS_PER_SIGNATURE.to_string(), le64(LAMPORTS_PER_SIGNATURE));
    items.insert(KEY_RENT_TOKEN_ACCOUNT.to_string(), le64(RENT));
    if let AssetKind::SplToken { mint, token_program } = &asset.asset {
        if let (Ok(m), Ok(tp)) = (<[u8; 32]>::try_from(mint.as_slice()), <[u8; 32]>::try_from(token_program.as_slice())) {
            if let Ok(src) = associated_token_address(&wallet_addr, &m, &tp) {
                items.insert(token_account_key(&src), canon(&token_account(m, wallet_addr)));
            }
        }
    }
    let evidence = EvidenceBundle {
        chain_profile_id: profile.chain_profile_id.clone(),
        network_id: profile.network_id.clone(),
        state: StateReference { height: STATE_HEIGHT, hash: Bytes(vec![7; 32]), commitment: "finalized".into() },
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
            amount_base_units: Amount(AMOUNT),
            destination_id: destination.destination_id.clone(),
            destination_version: destination.version,
        },
        constraints: IntentConstraints {
            max_network_fee_base_units: Amount(10_000_000),
            approval_mode: ApprovalMode::ExactCandidate,
            maximum_successful_payments: 1,
        },
        purpose: OperationPurpose::Settlement,
        external_reference: "ref".into(),
        proposer_credential_id: CredentialId::unchecked("cred"),
        created_at: UnixSeconds(OBSERVED_AT - 100),
    };
    Fx { sk, wallet_addr, profile, wallet, key, asset, destination, evidence, intent }
}

pub fn native_fixture() -> Fx {
    fixture_with(native_asset(), 1)
}

pub fn spl_fixture() -> Fx {
    fixture_with(spl_asset(mint(), TOKEN_PROGRAM_ID), 1)
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
        SolanaAdapter.build_candidate(&self.build_ctx()).expect("build")
    }

    pub fn source_ata(&self) -> Pubkey {
        associated_token_address(&self.wallet_addr, &mint(), &TOKEN_PROGRAM_ID).unwrap()
    }

    pub fn dest_ata(&self) -> Pubkey {
        associated_token_address(&dest_owner(), &mint(), &TOKEN_PROGRAM_ID).unwrap()
    }

    /// Ed25519 signature over the candidate's message bytes.
    pub fn sign(&self, candidate: &Candidate) -> SignatureBytes {
        sign_message(&self.sk, candidate.signing_payloads[0].message_or_digest.as_slice())
    }

    /// Wrap arbitrary unsigned bytes into a candidate with correctly derived payloads.
    pub fn candidate_for(&self, bytes: Vec<u8>, revision: u32) -> Candidate {
        let mut c = self.build();
        c.candidate_revision = revision;
        c.native_unsigned_bytes = Bytes(bytes);
        c.signing_payloads = SolanaAdapter.signing_payloads(&c.native_unsigned_bytes, &self.key).unwrap_or_default();
        c
    }

    pub fn verify(&self, c: &Candidate) -> OicResult<VerifiedOperation> {
        SolanaAdapter.verify_candidate(c, &AuthorizationTarget::Intent(&self.intent), &self.vctx())
    }
}

pub fn sign_message(sk: &SigningKey, msg: &[u8]) -> SignatureBytes {
    SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(sk.sign(msg).to_bytes().to_vec()) }
}
