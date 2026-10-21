//! Shared fixtures for approval display tests. Candidates are built by the
//! real pinned adapters from fixture state modelled on each adapter's own
//! `tests/common` fixtures, so every display is computed from genuine bytes.
#![allow(dead_code)]

pub mod evm;
pub mod solana;

use ed25519_dalek::{Signer, SigningKey};
use oic_adapter_api::*;
use oic_approval_verifier::*;
use oic_domain_types::*;
use oic_policy_kernel::{destination_hash, policy_hash};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const OBSERVED_AT: u64 = 1_700_000_000;
/// "Now" for rendering: 20 s after the evidence was observed (fresh).
pub const NOW: u64 = OBSERVED_AT + 20;

/// Every object a display is computed from, owned.
#[derive(Clone)]
pub struct World {
    pub profile: ChainProfile,
    pub intent: Intent,
    pub candidate: Candidate,
    pub wallet: ChainWallet,
    pub key: KeyDescriptor,
    pub vault: Vault,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub policy: PolicyBundle,
    pub evidence: EvidenceBundle,
}

impl World {
    pub fn inputs(&self) -> DisplayInputs<'_> {
        DisplayInputs {
            intent: &self.intent,
            candidate: &self.candidate,
            wallet: &self.wallet,
            key: &self.key,
            vault: &self.vault,
            asset: &self.asset,
            destination: &self.destination,
            policy: &self.policy,
            evidence: &self.evidence,
        }
    }

    pub fn build_ctx(&self, destination: &CounterpartyDestination) -> BuildContext {
        BuildContext {
            intent: self.intent.clone(),
            wallet: self.wallet.clone(),
            key: self.key.clone(),
            asset: self.asset.clone(),
            destination: destination.clone(),
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
}

pub fn admin(n: u8) -> (CredentialId, SigningKey) {
    (CredentialId::unchecked(format!("admin-{n}")), SigningKey::from_bytes(&[n; 32]))
}

pub fn approver() -> (CredentialId, SigningKey) {
    (CredentialId::unchecked("approver-treasury-1"), SigningKey::from_bytes(&[0x51; 32]))
}

pub fn roster() -> Vec<ApproverCredential> {
    vec![ApproverCredential { credential_id: approver().0, person_id: approver().0, verifying_key: approver().1.verifying_key().into(), role: ApprovalRole::TreasuryApprover }]
}

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

/// Policy signed by the listed administrators (quorum is 2 of admins 1..=3).
pub fn policy(signers: &[u8]) -> PolicyBundle {
    let mut b = PolicyBundle {
        policy_id: PolicyId::unchecked("pol-1"),
        policy_epoch: Epoch(4),
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        rules: vec![],
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 60,
        allowlist_version: 1,
        activation_epoch: Epoch(4),
        administrative_signatures: vec![],
    };
    let h = policy_hash(&b).unwrap();
    b.administrative_signatures = signers
        .iter()
        .map(|n| {
            let (id, k) = admin(*n);
            CredentialSignature { credential_id: id, signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(k.sign(&h.0).to_bytes().to_vec()) } }
        })
        .collect();
    b
}

/// Admin-quorum signatures over `h` by the listed administrators.
pub fn admin_signatures(h: Hash32, signers: &[u8]) -> Vec<CredentialSignature> {
    signers
        .iter()
        .map(|n| {
            let (id, k) = admin(*n);
            CredentialSignature { credential_id: id, signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(k.sign(&h.0).to_bytes().to_vec()) } }
        })
        .collect()
}

/// Destination registered by the listed administrators (RFC 0002 §8).
pub fn signed_destination(mut d: CounterpartyDestination, signers: &[u8]) -> CounterpartyDestination {
    let h = destination_hash(&d).unwrap();
    d.administrative_signatures = admin_signatures(h, signers);
    d
}

/// Verifier with both pinned adapters and both chain profiles enrolled.
pub fn verifier() -> IndependentVerifier {
    let mut adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::new();
    adapters.insert(AdapterId::unchecked("evm"), Arc::new(oic_adapter_evm::EvmAdapter::new()));
    adapters.insert(AdapterId::unchecked("solana"), Arc::new(oic_adapter_solana::SolanaAdapter::new()));
    IndependentVerifier::new(
        adapters,
        vec![evm::profile(), solana::profile()],
        (1..=3).map(admin).map(|(c, k)| (c, k.verifying_key())).collect(),
        2,
    )
}

pub fn base_intent(profile: &ChainProfile, asset: &Asset, destination: &CounterpartyDestination, amount: u128, max_fee: u128, mode: ApprovalMode) -> Intent {
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
