//! Registry objects shared by the simulator end-to-end tests.
#![allow(dead_code)]

use oic_adapter_api::*;
use oic_domain_types::*;

/// Key descriptor + chain wallet for one signing key on one profile.
pub struct Party {
    pub key: KeyDescriptor,
    pub wallet: ChainWallet,
}

pub fn party(profile: &ChainProfile, scheme: SchemeId, public_key: Vec<u8>, address: Vec<u8>, display: String, n: u32) -> Party {
    let key = KeyDescriptor {
        key_id: KeyId::unchecked(format!("key-{n}")),
        key_epoch: Epoch(1),
        scheme,
        public_key: PublicKey { scheme, bytes: Bytes(public_key) },
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
        chain_wallet_id: ChainWalletId::unchecked(format!("wallet-{n}")),
        vault_id: VaultId::unchecked("vault-1"),
        chain_profile_id: profile.chain_profile_id.clone(),
        network_id: profile.network_id.clone(),
        key_id: key.key_id.clone(),
        key_epoch: key.key_epoch,
        address: Bytes(address),
        address_display: display,
        active: true,
    };
    Party { key, wallet }
}

pub fn asset(profile: &ChainProfile, kind: AssetKind, decimals: u8, symbol: &str) -> Asset {
    Asset {
        asset_id: AssetId::unchecked(format!("{}-{symbol}", profile.network_id)),
        network_id: profile.network_id.clone(),
        asset: kind,
        decimals,
        symbol: symbol.into(),
        behavior: AssetBehaviorProfile::Standard,
    }
}

pub fn destination(profile: &ChainProfile, address: Vec<u8>, display: String) -> CounterpartyDestination {
    CounterpartyDestination {
        destination_id: DestinationId::unchecked("dest-1"),
        version: 1,
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

/// Everything the adapter needs to build/verify one transfer.
pub struct Transfer {
    pub profile: ChainProfile,
    pub party: Party,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub intent: Intent,
}

impl Transfer {
    pub fn new(profile: ChainProfile, party: Party, asset: Asset, destination: CounterpartyDestination, amount: u128, max_fee: u128) -> Self {
        let intent = Intent {
            schema_version: 1,
            intent_id: IntentId::unchecked("intent-1"),
            institution_id: InstitutionId::unchecked("inst"),
            environment_id: EnvironmentId::unchecked("dev"),
            vault_id: party.wallet.vault_id.clone(),
            chain_wallet_id: party.wallet.chain_wallet_id.clone(),
            chain_profile_id: profile.chain_profile_id.clone(),
            operation: IntentOperation::AssetTransfer {
                asset_id: asset.asset_id.clone(),
                amount_base_units: Amount(amount),
                destination_id: destination.destination_id.clone(),
                destination_version: destination.version,
            },
            constraints: IntentConstraints {
                max_network_fee_base_units: Amount(max_fee),
                approval_mode: ApprovalMode::ExactCandidate,
                maximum_successful_payments: 1,
            },
            purpose: OperationPurpose::Settlement,
            external_reference: "ref".into(),
            proposer_credential_id: CredentialId::unchecked("cred"),
            created_at: UnixSeconds(1),
        };
        Transfer { profile, party, asset, destination, intent }
    }

    pub fn build_ctx(&self, evidence: EvidenceBundle, candidate: &str, revision: u32, built_at: UnixSeconds) -> BuildContext {
        BuildContext {
            intent: self.intent.clone(),
            wallet: self.party.wallet.clone(),
            key: self.party.key.clone(),
            asset: self.asset.clone(),
            destination: self.destination.clone(),
            profile: self.profile.clone(),
            evidence,
            candidate_id: CandidateId::unchecked(candidate),
            candidate_revision: revision,
            operation_family_id: OperationFamilyId::unchecked("family-1"),
            built_at,
        }
    }

    pub fn vctx<'a>(&'a self, evidence: &'a EvidenceBundle) -> VerifyContext<'a> {
        VerifyContext {
            profile: &self.profile,
            wallet: &self.party.wallet,
            key: &self.party.key,
            asset: &self.asset,
            destination: &self.destination,
            evidence,
        }
    }
}
