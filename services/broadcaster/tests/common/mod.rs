//! Shared fixture: registry objects (trimmed from the chain-simulator test
//! fixture), a real authority with a signed policy, and the
//! register → reserve → release path that makes a candidate possibly issued.
#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use oic_adapter_api::*;
use oic_authorization_state::*;
use oic_chain_simulator::SimClock;
use oic_domain_types::*;
use oic_policy_kernel::{intent_hash, policy_hash, Decision};
use std::sync::Arc;

pub const DAY: u64 = 86_400;

/// Authority clock driven by the same [`SimClock`] the simulators use, so
/// evidence freshness and authority deadlines share one time base.
pub struct SimTime(pub SimClock);

impl Clock for SimTime {
    fn now(&self) -> UnixSeconds {
        self.0.now()
    }
}

pub fn inst() -> InstitutionId {
    InstitutionId::unchecked("inst")
}
pub fn env() -> EnvironmentId {
    EnvironmentId::unchecked("dev")
}
pub fn vault() -> VaultId {
    VaultId::unchecked("vault-1")
}

pub struct Party {
    pub key: KeyDescriptor,
    pub wallet: ChainWallet,
}

pub fn party(profile: &ChainProfile, scheme: SchemeId, public_key: Vec<u8>, address: Vec<u8>, display: String) -> Party {
    let key = KeyDescriptor {
        key_id: KeyId::unchecked("key-1"),
        key_epoch: Epoch(1),
        scheme,
        public_key: PublicKey { scheme, bytes: Bytes(public_key) },
        backend_id: "dev".into(),
        backend_commit: "dev".into(),
        participants: vec![],
        threshold: 1,
        institution_id: inst(),
        environment_id: env(),
        networks: vec![profile.network_id.clone()],
        recovery_profile: "none".into(),
    };
    let wallet = ChainWallet {
        chain_wallet_id: ChainWalletId::unchecked("wallet-1"),
        vault_id: vault(),
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

pub struct Transfer {
    pub profile: ChainProfile,
    pub party: Party,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub intent: Intent,
}

impl Transfer {
    pub fn new(profile: ChainProfile, party: Party, asset: Asset, destination: CounterpartyDestination, amount: u128, max_fee: u128, n: u32) -> Self {
        let intent = Intent {
            schema_version: 1,
            intent_id: IntentId::unchecked(format!("intent-{n}")),
            institution_id: inst(),
            environment_id: env(),
            vault_id: vault(),
            chain_wallet_id: party.wallet.chain_wallet_id.clone(),
            chain_profile_id: profile.chain_profile_id.clone(),
            operation: IntentOperation::AssetTransfer {
                asset_id: asset.asset_id.clone(),
                amount_base_units: Amount(amount),
                destination_id: destination.destination_id.clone(),
                destination_version: destination.version,
            },
            constraints: IntentConstraints { max_network_fee_base_units: Amount(max_fee), approval_mode: ApprovalMode::ExactCandidate, maximum_successful_payments: 1 },
            purpose: OperationPurpose::Settlement,
            external_reference: format!("ref-{n}"),
            proposer_credential_id: CredentialId::unchecked("cred"),
            created_at: UnixSeconds(1),
        };
        Transfer { profile, party, asset, destination, intent }
    }

    pub fn family(&self) -> OperationFamilyId {
        family_id_for(&self.intent.intent_id).unwrap()
    }

    pub fn build_ctx(&self, evidence: EvidenceBundle, candidate: &str, built_at: UnixSeconds) -> BuildContext {
        BuildContext {
            intent: self.intent.clone(),
            wallet: self.party.wallet.clone(),
            key: self.party.key.clone(),
            asset: self.asset.clone(),
            destination: self.destination.clone(),
            profile: self.profile.clone(),
            evidence,
            candidate_id: CandidateId::unchecked(candidate),
            candidate_revision: 1,
            operation_family_id: self.family(),
            built_at,
        }
    }

    pub fn vctx<'a>(&'a self, evidence: &'a EvidenceBundle) -> VerifyContext<'a> {
        VerifyContext { profile: &self.profile, wallet: &self.party.wallet, key: &self.party.key, asset: &self.asset, destination: &self.destination, evidence }
    }
}

fn admin(n: u8) -> (CredentialId, SigningKey) {
    (CredentialId::unchecked(format!("admin-{n}")), SigningKey::from_bytes(&[n; 32]))
}

fn rule() -> PolicyRule {
    PolicyRule {
        rule_id: "r-all".into(),
        vaults: vec![vault()],
        assets: vec![],
        destinations: vec![],
        purposes: vec![],
        max_amount_per_operation: Amount(u128::MAX / 4),
        max_native_fee_per_operation: Amount(u128::MAX / 4),
        rolling_limits: vec![ExposureLimit { window_seconds: DAY, max_outflow_base_units: Amount(u128::MAX / 4) }],
        required_approvals: 0,
        approval_roles: vec![ApprovalRole::Automated],
        exclude_proposer: true,
        operating_window: None,
    }
}

/// A real authority with an administratively signed policy.
pub fn authority(clock: &SimClock) -> Arc<Authority<InMemoryAuthorityStore>> {
    let config = AuthorityConfig {
        institution_id: inst(),
        environment_id: env(),
        authority_key_id: KeyId::unchecked("authority-key"),
        admin_keys: (1..=2).map(admin).map(|(c, k)| (c, k.verifying_key())).collect(),
        admin_quorum: 2,
        freeze_responders: vec![],
        release_receipt_ttl_seconds: 60,
        max_clock_skew_seconds: 30,
    };
    let auth = Authority::open(Arc::new(InMemoryAuthorityStore::new()), 0, config, SigningKey::from_bytes(&[42; 32]), Arc::new(SimTime(clock.clone()))).unwrap();
    let mut b = PolicyBundle {
        policy_id: PolicyId::unchecked("pol-1"),
        policy_epoch: Epoch(1),
        institution_id: inst(),
        environment_id: env(),
        rules: vec![rule()],
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 120,
        allowlist_version: 1,
        activation_epoch: Epoch(1),
        administrative_signatures: vec![],
    };
    let h = policy_hash(&b).unwrap();
    b.administrative_signatures = [1u8, 2]
        .iter()
        .map(|n| {
            let (id, k) = admin(*n);
            CredentialSignature { credential_id: id, signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(k.sign(&h.0).to_bytes().to_vec()) } }
        })
        .collect();
    auth.set_policy(&b).unwrap();
    Arc::new(auth)
}

/// register intent → reserve the verified claims → final release. After
/// this the candidate is possibly issued and the authority accepts chain
/// observations for it. Returns the reservation id.
pub fn issue(auth: &Authority<InMemoryAuthorityStore>, clock: &SimClock, t: &Transfer, candidate: &Candidate, claims: &ResourceClaims) -> ReservationId {
    let reg = auth
        .register_intent(&t.intent, intent_hash(&t.intent).unwrap(), IdempotencyKey { institution_id: inst(), route: "POST /v1/intents".into(), key: t.intent.intent_id.to_string() })
        .unwrap();
    assert_eq!(reg.operation_family_id, candidate.operation_family_id);
    let (epoch, hash) = auth.current_policy().unwrap();
    let envelope = oic_canonical_encoding::sha256(candidate.candidate_id.as_str().as_bytes());
    let session = SigningSessionId::unchecked(format!("sess-{}", candidate.candidate_id));
    let limits = claims.asset_outflows.iter().map(|o| (o.asset_id.clone(), rule().rolling_limits[0].clone())).collect();
    let (res, _) = auth
        .reserve(ReserveRequest {
            family_id: reg.operation_family_id.clone(),
            candidate_id: candidate.candidate_id.clone(),
            candidate_revision: candidate.candidate_revision,
            vault_id: vault(),
            intent_id: reg.intent_id.clone(),
            policy_epoch: epoch,
            policy_hash: hash,
            claims: claims.clone(),
            grants: vec![],
            envelope_body_hash: envelope,
            signer_session_id: session.clone(),
            issuance_deadline: UnixSeconds(clock.now().0 + 600),
            policy_decision: Decision::Allow { rule_id: "r-all".into() },
            exposure_limits: limits,
        })
        .unwrap();
    auth.release(ReleaseRequest {
        reservation_id: res.reservation_id.clone(),
        reservation_version: res.reservation_version,
        envelope_body_hash: envelope,
        signer_session_id: session,
        expected_policy_epoch: epoch,
        freshness: FreshnessContext { now: clock.now() },
    })
    .unwrap();
    res.reservation_id
}

/// Outstanding (not yet settled or released) exposure of the asset.
pub fn outstanding(auth: &Authority<InMemoryAuthorityStore>, clock: &SimClock, asset: &AssetId) -> Amount {
    auth.exposure_view(&vault(), std::slice::from_ref(asset), &[DAY], clock.now()).unwrap().windows[0].outstanding
}

/// Settled exposure of the asset in the day window.
pub fn settled(auth: &Authority<InMemoryAuthorityStore>, clock: &SimClock, asset: &AssetId) -> Amount {
    auth.exposure_view(&vault(), std::slice::from_ref(asset), &[DAY], clock.now()).unwrap().windows[0].settled
}
