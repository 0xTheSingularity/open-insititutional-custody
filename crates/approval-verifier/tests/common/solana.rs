//! Solana fixtures (modelled on `crates/adapter-solana/tests/common`).

use super::*;
use oic_adapter_solana::address::*;
use oic_adapter_solana::evidence::*;
use oic_adapter_solana::*;

pub const LAST_VALID_HEIGHT: u64 = 1_150;
pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
pub const RENT: u64 = 2_039_280;
pub const GENESIS: [u8; 32] = [0x6e; 32];
pub const BLOCKHASH: [u8; 32] = [0xbb; 32];

pub fn mint() -> Pubkey {
    [0xc0; 32]
}

fn ed_key(seed: u8) -> SigningKey {
    let mut b = [0x22u8; 32];
    b[0] = seed;
    SigningKey::from_bytes(&b)
}

pub fn wallet_addr() -> Pubkey {
    ed_key(1).verifying_key().to_bytes()
}

/// Registered destination owner wallet.
pub fn dest_owner() -> Pubkey {
    ed_key(77).verifying_key().to_bytes()
}

/// Owner a compromised builder pays instead.
pub fn attacker_owner() -> Pubkey {
    ed_key(99).verifying_key().to_bytes()
}

pub fn profile() -> ChainProfile {
    ChainProfile {
        chain_profile_id: ChainProfileId::unchecked("solana-devnet-v1"),
        adapter_id: AdapterId::unchecked("solana"),
        network_id: NetworkId::unchecked("solana-devnet"),
        network_binding: Bytes(GENESIS.to_vec()),
        display_name: "Solana devnet".into(),
        accepted_versions: vec![VERSION_LEGACY.to_string(), VERSION_V0.to_string()],
        finality_commitment: "finalized".into(),
        finality_depth: 32,
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

pub fn spl_asset() -> Asset {
    Asset {
        asset_id: AssetId::unchecked("devnet-usdc"),
        network_id: NetworkId::unchecked("solana-devnet"),
        asset: AssetKind::SplToken { mint: Bytes(mint().to_vec()), token_program: Bytes(TOKEN_PROGRAM_ID.to_vec()) },
        decimals: 6,
        symbol: "USDC".into(),
        behavior: AssetBehaviorProfile::Standard,
    }
}

pub fn destination(owner: Pubkey) -> CounterpartyDestination {
    CounterpartyDestination {
        destination_id: DestinationId::unchecked("dest-1"),
        version: 3,
        network_id: NetworkId::unchecked("solana-devnet"),
        address: Bytes(owner.to_vec()),
        address_display: to_base58(&owner),
        display_name: "Acme Settlement LLC".into(),
        allowed_assets: vec![],
        verification_evidence: "callback 2026-01-02".into(),
        activation_epoch: Epoch(1),
    }
}

fn le64(v: u64) -> Bytes {
    Bytes(v.to_le_bytes().to_vec())
}

/// A world whose candidate was built by the real Solana adapter; see
/// [`super::evm::world`] for `paid_to`.
pub fn world(asset: Asset, amount: u128, mode: ApprovalMode, paid_to: Option<Pubkey>) -> World {
    let profile = profile();
    let wallet_addr = wallet_addr();
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
    let registry = destination(dest_owner());
    let mut items = BTreeMap::new();
    items.insert(KEY_GENESIS_HASH.to_string(), Bytes(GENESIS.to_vec()));
    items.insert(KEY_RECENT_BLOCKHASH.to_string(), Bytes(BLOCKHASH.to_vec()));
    items.insert(KEY_BLOCKHASH_LAST_VALID_HEIGHT.to_string(), le64(LAST_VALID_HEIGHT));
    items.insert(KEY_LAMPORTS_PER_SIGNATURE.to_string(), le64(LAMPORTS_PER_SIGNATURE));
    items.insert(KEY_RENT_TOKEN_ACCOUNT.to_string(), le64(RENT));
    if let AssetKind::SplToken { .. } = &asset.asset {
        let src = associated_token_address(&wallet_addr, &mint(), &TOKEN_PROGRAM_ID).unwrap();
        let acct = TokenAccountEvidence {
            mint: Bytes(mint().to_vec()),
            owner: Bytes(wallet_addr.to_vec()),
            amount: 10_000_000,
            delegate: None,
            close_authority: None,
            state: TOKEN_ACCOUNT_INITIALIZED,
        };
        items.insert(token_account_key(&src), Bytes(oic_canonical_encoding::canonical_bytes(&acct).unwrap()));
        // A compromised builder paying someone else also supplies (and binds by
        // hash) evidence for that owner's existing token account.
        if let Some(owner) = paid_to {
            let dst = associated_token_address(&owner, &mint(), &TOKEN_PROGRAM_ID).unwrap();
            let acct = TokenAccountEvidence { owner: Bytes(owner.to_vec()), amount: 0, ..acct };
            items.insert(token_account_key(&dst), Bytes(oic_canonical_encoding::canonical_bytes(&acct).unwrap()));
        }
    }
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
    let intent = base_intent(&profile, &asset, &registry, amount, 10_000_000, mode);
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
    let build_dest = destination(paid_to.unwrap_or_else(dest_owner));
    w.candidate = SolanaAdapter.build_candidate(&w.build_ctx(&build_dest)).expect("Solana build");
    w
}
