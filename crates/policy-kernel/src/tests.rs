use super::*;
use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;

const NOW: u64 = 1_700_000_000;

fn net() -> NetworkId {
    NetworkId::unchecked("evm-sepolia")
}

fn usdc() -> AssetId {
    AssetId::unchecked("usdc-sepolia")
}

fn dummy_sig() -> SignatureBytes {
    SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(vec![0u8; 64]) }
}

/// Owns every input object; `input()` borrows them into a `PolicyInput`.
#[derive(Clone, Debug)]
struct Fx {
    policy: PolicyBundle,
    policy_hash_override: Option<Hash32>,
    expected_policy_epoch: Epoch,
    intent: Intent,
    intent_hash_override: Option<Hash32>,
    verified: VerifiedOperation,
    grants: Vec<ApprovalGrant>,
    destination: CounterpartyDestination,
    asset: Asset,
    vault: Vault,
    evidence: EvidenceBundle,
    now: u64,
    exposure: ExposureView,
    candidate_id: CandidateId,
    candidate_revision: u32,
    preview_hash: Hash32,
}

fn rule() -> PolicyRule {
    PolicyRule {
        rule_id: "r-ops".into(),
        vaults: vec![VaultId::unchecked("vault-ops")],
        assets: vec![],
        destinations: vec![],
        purposes: vec![],
        max_amount_per_operation: Amount(1000),
        max_native_fee_per_operation: Amount(50),
        rolling_limits: vec![ExposureLimit { window_seconds: 86_400, max_outflow_base_units: Amount(5000) }],
        required_approvals: 2,
        approval_roles: vec![ApprovalRole::TreasuryApprover, ApprovalRole::SecurityApprover],
        exclude_proposer: true,
        operating_window: None,
    }
}

fn permissive_rule() -> PolicyRule {
    PolicyRule {
        rule_id: "r-anything".into(),
        vaults: vec![],
        assets: vec![],
        destinations: vec![],
        purposes: vec![],
        max_amount_per_operation: Amount(u128::MAX / 4),
        max_native_fee_per_operation: Amount(u128::MAX / 4),
        rolling_limits: vec![],
        required_approvals: 0,
        approval_roles: vec![ApprovalRole::Automated],
        exclude_proposer: false,
        operating_window: None,
    }
}

impl Fx {
    fn new() -> Fx {
        let policy = PolicyBundle {
            policy_id: PolicyId::unchecked("pol-1"),
            policy_epoch: Epoch(3),
            institution_id: InstitutionId::unchecked("inst-1"),
            environment_id: EnvironmentId::unchecked("testnet"),
            rules: vec![rule()],
            denied_destinations: vec![],
            denied_assets: vec![],
            max_evidence_age_seconds: 30,
            allowlist_version: 7,
            activation_epoch: Epoch(3),
            administrative_signatures: vec![],
        };
        let intent = Intent {
            schema_version: 1,
            intent_id: IntentId::unchecked("intent-1"),
            institution_id: InstitutionId::unchecked("inst-1"),
            environment_id: EnvironmentId::unchecked("testnet"),
            vault_id: VaultId::unchecked("vault-ops"),
            chain_wallet_id: ChainWalletId::unchecked("wallet-1"),
            chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
            operation: IntentOperation::AssetTransfer {
                asset_id: usdc(),
                amount_base_units: Amount(1000),
                destination_id: DestinationId::unchecked("dest-1"),
                destination_version: 2,
            },
            constraints: IntentConstraints {
                max_network_fee_base_units: Amount(50),
                approval_mode: ApprovalMode::ExactCandidate,
                maximum_successful_payments: 1,
            },
            purpose: OperationPurpose::Settlement,
            external_reference: "inv-42".into(),
            proposer_credential_id: CredentialId::unchecked("cred-proposer"),
            created_at: UnixSeconds(NOW - 500),
        };
        let verified = VerifiedOperation {
            decoded: DecodedOperation::DirectTransfer {
                network_id: net(),
                asset: AssetKind::Erc20 { contract: Bytes(vec![0xaa; 20]) },
                sender: Bytes(vec![0xcc; 20]),
                recipient: Bytes(vec![0xbb; 20]),
                amount_base_units: Amount(1000),
                native_value_base_units: Amount(0),
                max_native_fee_base_units: Amount(40),
                native_detail: Bytes(vec![]),
            },
            decoded_operation_hash: Hash32([1; 32]),
            signing_payloads: vec![],
            claims: ResourceClaims {
                resources: vec![NativeResource::EvmNonce { network_id: net(), sender: Bytes(vec![0xcc; 20]), nonce: 5 }],
                asset_outflows: vec![AssetOutflow { asset_id: usdc(), amount_base_units: Amount(1000) }],
                native_fees: vec![NativeFee { network_id: net(), amount_base_units: Amount(40) }],
            },
            adapter_id: AdapterId::unchecked("evm"),
            adapter_version: "0.1.0".into(),
            verifier_build_hash: Hash32([2; 32]),
        };
        let destination = CounterpartyDestination {
            destination_id: DestinationId::unchecked("dest-1"),
            version: 2,
            network_id: net(),
            address: Bytes(vec![0xbb; 20]),
            address_display: "0xbb..".into(),
            display_name: "Counterparty".into(),
            allowed_assets: vec![],
            verification_evidence: "kyc".into(),
            activation_epoch: Epoch(1),
        };
        let asset = Asset {
            asset_id: usdc(),
            network_id: net(),
            asset: AssetKind::Erc20 { contract: Bytes(vec![0xaa; 20]) },
            decimals: 6,
            symbol: "USDC".into(),
            behavior: AssetBehaviorProfile::Standard,
        };
        let vault = Vault {
            vault_id: VaultId::unchecked("vault-ops"),
            institution_id: InstitutionId::unchecked("inst-1"),
            environment_id: EnvironmentId::unchecked("testnet"),
            tier: VaultTier::Operating,
            policy_id: PolicyId::unchecked("pol-1"),
            display_name: "Ops".into(),
        };
        let evidence = EvidenceBundle {
            chain_profile_id: ChainProfileId::unchecked("evm-sepolia-v1"),
            network_id: net(),
            state: StateReference { height: 100, hash: Bytes(vec![9; 32]), commitment: "finalized".into() },
            sources: vec![EvidenceSourceId::unchecked("node-1")],
            trust_level: EvidenceTrustLevel::ValidatingNode,
            observed_at: UnixSeconds(NOW - 10),
            max_staleness_seconds: 60,
            verifier_version: "1".into(),
            items: Default::default(),
        };
        let candidate_id = CandidateId::unchecked("cand-1");
        let preview = preview_hash(&candidate_id, 1, Hash32([1; 32]), Hash32([3; 32]));
        let mut fx = Fx {
            policy,
            policy_hash_override: None,
            expected_policy_epoch: Epoch(3),
            intent,
            intent_hash_override: None,
            verified,
            grants: vec![],
            destination,
            asset,
            vault,
            evidence,
            now: NOW,
            exposure: ExposureView {
                windows: vec![WindowExposure { asset_id: usdc(), window_seconds: 86_400, settled: Amount(1000), outstanding: Amount(2000) }],
            },
            candidate_id,
            candidate_revision: 1,
            preview_hash: preview,
        };
        fx.grants = vec![
            fx.grant("g-1", "cred-alice", ApprovalRole::TreasuryApprover),
            fx.grant("g-2", "cred-bob", ApprovalRole::SecurityApprover),
        ];
        fx
    }

    fn ih(&self) -> Hash32 {
        self.intent_hash_override.unwrap_or_else(|| intent_hash(&self.intent).unwrap())
    }

    fn grant(&self, id: &str, cred: &str, role: ApprovalRole) -> ApprovalGrant {
        ApprovalGrant {
            body: ApprovalGrantBody {
                grant_id: GrantId::unchecked(id),
                institution_id: self.intent.institution_id.clone(),
                environment_id: self.intent.environment_id.clone(),
                vault_id: self.intent.vault_id.clone(),
                intent_id: self.intent.intent_id.clone(),
                intent_hash: intent_hash(&self.intent).unwrap(),
                policy_id: self.policy.policy_id.clone(),
                policy_epoch: self.policy.policy_epoch,
                scope: GrantScope::ExactCandidate {
                    candidate_id: self.candidate_id.clone(),
                    candidate_revision: self.candidate_revision,
                    preview_hash: self.preview_hash,
                },
                approver_credential_id: CredentialId::unchecked(cred),
                approver_role: role,
                issued_at: UnixSeconds(self.now - 100),
                expires_at: UnixSeconds(self.now + 100),
            },
            signature: dummy_sig(),
        }
    }

    fn template(&self) -> BoundedTransferTemplate {
        BoundedTransferTemplate {
            chain_wallet_id: self.intent.chain_wallet_id.clone(),
            network_id: net(),
            asset_id: usdc(),
            amount_base_units: Amount(1000),
            destination_id: DestinationId::unchecked("dest-1"),
            destination_version: 2,
            destination_address: Bytes(vec![0xbb; 20]),
            max_native_fee_base_units: Amount(40),
            maximum_successful_payments: 1,
            fillable: vec![FillableField::EvmNonce, FillableField::EvmFeeFields],
        }
    }

    fn eval(&self) -> Decision {
        let input = PolicyInput {
            policy: &self.policy,
            policy_hash: self.policy_hash_override.unwrap_or_else(|| policy_hash(&self.policy).unwrap()),
            expected_policy_epoch: self.expected_policy_epoch,
            intent: &self.intent,
            intent_hash: self.ih(),
            verified: &self.verified,
            grants: &self.grants,
            destination: &self.destination,
            asset: &self.asset,
            vault: &self.vault,
            evidence: &self.evidence,
            freshness: FreshnessContext { now: UnixSeconds(self.now) },
            exposure: &self.exposure,
            candidate_id: &self.candidate_id,
            candidate_revision: self.candidate_revision,
            preview_hash: self.preview_hash,
        };
        evaluate(&input)
    }

    fn set_decoded(&mut self, f: impl FnOnce(&mut Amount, &mut Amount, &mut Amount, &mut Bytes, &mut AssetKind)) {
        let DecodedOperation::DirectTransfer { amount_base_units, native_value_base_units, max_native_fee_base_units, recipient, asset, .. } =
            &mut self.verified.decoded;
        f(amount_base_units, native_value_base_units, max_native_fee_base_units, recipient, asset);
    }

    fn set_intent_amount(&mut self, a: u128) {
        let IntentOperation::AssetTransfer { amount_base_units, .. } = &mut self.intent.operation;
        *amount_base_units = Amount(a);
    }

    fn set_environment(&mut self, env: &str) {
        let e = EnvironmentId::unchecked(env);
        self.policy.environment_id = e.clone();
        self.intent.environment_id = e.clone();
        self.vault.environment_id = e;
        let gs: Vec<_> = self.grants.iter().map(|g| (g.body.grant_id.clone(), g.body.approver_credential_id.clone(), g.body.approver_role)).collect();
        self.grants = gs.into_iter().map(|(id, c, r)| self.grant(id.as_str(), c.as_str(), r)).collect();
    }
}

fn allowed(d: &Decision) -> bool {
    matches!(d, Decision::Allow { rule_id } if rule_id == "r-ops")
}

fn denied_with(d: &Decision, r: &ReasonCode) -> bool {
    matches!(d, Decision::Deny { reasons } if reasons.contains(r))
}

fn approvals_with(d: &Decision, satisfied_expected: u8, r: &ReasonCode) -> bool {
    matches!(d, Decision::RequireApprovals { satisfied, reasons, .. } if *satisfied == satisfied_expected && reasons.contains(r))
}

#[test]
fn baseline_allows() {
    let fx = Fx::new();
    assert!(allowed(&fx.eval()), "{:?}", fx.eval());
}

// ---------------------------------------------------------------- binding

#[test]
fn a14_old_policy_epoch_is_rejected() {
    let mut fx = Fx::new();
    // Authority has moved to epoch 4 after a privilege revocation; epoch 3 bundle is presented.
    fx.expected_policy_epoch = Epoch(4);
    let d = fx.eval();
    assert!(denied_with(&d, &ReasonCode::PolicyEpochMismatch), "{d:?}");
}

#[test]
fn newer_policy_than_authority_is_rejected() {
    let mut fx = Fx::new();
    fx.expected_policy_epoch = Epoch(2);
    let d = fx.eval();
    assert!(denied_with(&d, &ReasonCode::PolicyEpochMismatch), "{d:?}");
    assert!(denied_with(&d, &ReasonCode::PolicyNotActive), "{d:?}");
}

#[test]
fn not_yet_active_policy_is_rejected() {
    let mut fx = Fx::new();
    fx.policy.activation_epoch = Epoch(4);
    assert!(denied_with(&fx.eval(), &ReasonCode::PolicyNotActive));
    fx.policy.activation_epoch = Epoch(3);
    assert!(allowed(&fx.eval()));
}

#[test]
fn policy_hash_mismatch() {
    let mut fx = Fx::new();
    fx.policy_hash_override = Some(Hash32::ZERO);
    assert!(denied_with(&fx.eval(), &ReasonCode::PolicyHashMismatch));
}

#[test]
fn intent_hash_mismatch() {
    let mut fx = Fx::new();
    fx.intent_hash_override = Some(Hash32([7; 32]));
    assert!(denied_with(&fx.eval(), &ReasonCode::IntentHashMismatch));
}

#[test]
fn institution_environment_vault_policy_mismatches() {
    let mut fx = Fx::new();
    fx.vault.institution_id = InstitutionId::unchecked("inst-2");
    assert!(denied_with(&fx.eval(), &ReasonCode::InstitutionMismatch));

    let mut fx = Fx::new();
    fx.vault.environment_id = EnvironmentId::unchecked("mainnet");
    assert!(denied_with(&fx.eval(), &ReasonCode::EnvironmentMismatch));

    let mut fx = Fx::new();
    fx.intent.environment_id = EnvironmentId::unchecked("mainnet");
    assert!(denied_with(&fx.eval(), &ReasonCode::EnvironmentMismatch));

    let mut fx = Fx::new();
    fx.vault.vault_id = VaultId::unchecked("vault-treasury");
    assert!(denied_with(&fx.eval(), &ReasonCode::VaultMismatch));

    let mut fx = Fx::new();
    fx.vault.policy_id = PolicyId::unchecked("pol-2");
    assert!(denied_with(&fx.eval(), &ReasonCode::PolicyIdMismatch));
}

// ---------------------------------------------------------------- hard denials

#[test]
fn hard_denial_dominates_permissive_rule() {
    let mut fx = Fx::new();
    fx.policy.rules = vec![permissive_rule()];
    fx.grants.clear();
    assert!(matches!(fx.eval(), Decision::Allow { .. }));
    fx.policy.denied_destinations = vec![DestinationId::unchecked("dest-1")];
    let d = fx.eval();
    assert!(denied_with(&d, &ReasonCode::DeniedDestination), "{d:?}");

    let mut fx = Fx::new();
    fx.policy.rules = vec![permissive_rule()];
    fx.policy.denied_assets = vec![usdc()];
    assert!(denied_with(&fx.eval(), &ReasonCode::DeniedAsset));
}

#[test]
fn network_mismatches() {
    let other = NetworkId::unchecked("evm-mainnet");
    let mut fx = Fx::new();
    fx.destination.network_id = other.clone();
    assert!(denied_with(&fx.eval(), &ReasonCode::DestinationNetworkMismatch));
    let mut fx = Fx::new();
    fx.asset.network_id = other.clone();
    assert!(denied_with(&fx.eval(), &ReasonCode::AssetNetworkMismatch));
    let mut fx = Fx::new();
    fx.evidence.network_id = other;
    assert!(denied_with(&fx.eval(), &ReasonCode::EvidenceNetworkMismatch));
}

#[test]
fn destination_activation_and_registration() {
    let mut fx = Fx::new();
    fx.destination.activation_epoch = Epoch(4);
    assert!(denied_with(&fx.eval(), &ReasonCode::DestinationNotActive));
    fx.destination.activation_epoch = Epoch(3);
    assert!(allowed(&fx.eval()));

    let mut fx = Fx::new();
    fx.destination.allowed_assets = vec![AssetId::unchecked("eth-sepolia")];
    assert!(denied_with(&fx.eval(), &ReasonCode::DestinationNotRegisteredForAsset));
    fx.destination.allowed_assets.push(usdc());
    assert!(allowed(&fx.eval()));

    let mut fx = Fx::new();
    fx.destination.version = 3;
    assert!(denied_with(&fx.eval(), &ReasonCode::DestinationVersionMismatch));

    let mut fx = Fx::new();
    fx.destination.destination_id = DestinationId::unchecked("dest-2");
    assert!(denied_with(&fx.eval(), &ReasonCode::DestinationIdMismatch));
}

#[test]
fn asset_identity_and_behavior() {
    let mut fx = Fx::new();
    fx.asset.behavior = AssetBehaviorProfile::Nonstandard;
    assert!(denied_with(&fx.eval(), &ReasonCode::AssetNonstandard));

    let mut fx = Fx::new();
    fx.asset.asset_id = AssetId::unchecked("usdc-fake");
    assert!(denied_with(&fx.eval(), &ReasonCode::AssetIdMismatch));

    // A04: same symbol/decimals, different contract.
    let mut fx = Fx::new();
    fx.set_decoded(|_, _, _, _, asset| *asset = AssetKind::Erc20 { contract: Bytes(vec![0xab; 20]) });
    assert!(denied_with(&fx.eval(), &ReasonCode::AssetKindMismatch));
}

#[test]
fn evidence_freshness_boundaries() {
    // policy max age 30 is tighter than evidence 60
    let mut fx = Fx::new();
    fx.evidence.observed_at = UnixSeconds(NOW - 30);
    assert!(allowed(&fx.eval()));
    fx.evidence.observed_at = UnixSeconds(NOW - 31);
    assert!(denied_with(&fx.eval(), &ReasonCode::EvidenceStale));

    // evidence max staleness 20 is tighter than policy 30
    let mut fx = Fx::new();
    fx.evidence.max_staleness_seconds = 20;
    fx.evidence.observed_at = UnixSeconds(NOW - 20);
    assert!(allowed(&fx.eval()));
    fx.evidence.observed_at = UnixSeconds(NOW - 21);
    assert!(denied_with(&fx.eval(), &ReasonCode::EvidenceStale));

    let mut fx = Fx::new();
    fx.evidence.observed_at = UnixSeconds(NOW + 1);
    assert!(denied_with(&fx.eval(), &ReasonCode::EvidenceFromFuture));
}

#[test]
fn evidence_trust_by_environment() {
    let mut fx = Fx::new();
    fx.evidence.trust_level = EvidenceTrustLevel::DevelopmentSimulator;
    assert!(denied_with(&fx.eval(), &ReasonCode::EvidenceTrustInsufficient));
    fx.evidence.trust_level = EvidenceTrustLevel::SingleProvider;
    assert!(allowed(&fx.eval()));
    fx.set_environment("mainnet");
    assert!(denied_with(&fx.eval(), &ReasonCode::EvidenceTrustInsufficient));
    fx.evidence.trust_level = EvidenceTrustLevel::TrustedProviderCrossChecked;
    assert!(allowed(&fx.eval()), "{:?}", fx.eval());

    let mut fx = Fx::new();
    fx.set_environment("dev");
    fx.evidence.trust_level = EvidenceTrustLevel::DevelopmentSimulator;
    assert!(allowed(&fx.eval()));
}

#[test]
fn verified_operation_must_equal_intent() {
    let mut fx = Fx::new();
    fx.set_decoded(|_, _, _, r, _| *r = Bytes(vec![0xbc; 20]));
    assert!(denied_with(&fx.eval(), &ReasonCode::RecipientMismatch));

    let mut fx = Fx::new();
    fx.set_decoded(|a, _, _, _, _| *a = Amount(1001));
    assert!(denied_with(&fx.eval(), &ReasonCode::AmountMismatch));

    let mut fx = Fx::new();
    fx.set_decoded(|_, v, _, _, _| *v = Amount(1));
    assert!(denied_with(&fx.eval(), &ReasonCode::NativeValueMismatch));

    // Native transfer must move exactly the amount as native value.
    let mut fx = Fx::new();
    fx.asset.asset = AssetKind::Native;
    fx.set_decoded(|_, v, _, _, a| {
        *a = AssetKind::Native;
        *v = Amount(1000);
    });
    assert!(allowed(&fx.eval()));
    fx.set_decoded(|_, v, _, _, _| *v = Amount(999));
    assert!(denied_with(&fx.eval(), &ReasonCode::NativeValueMismatch));
}

#[test]
fn fee_against_intent_constraint() {
    let mut fx = Fx::new();
    fx.set_decoded(|_, _, f, _, _| *f = Amount(50));
    assert!(allowed(&fx.eval()));
    fx.set_decoded(|_, _, f, _, _| *f = Amount(51));
    let d = fx.eval();
    assert!(denied_with(&d, &ReasonCode::FeeExceedsIntentConstraint), "{d:?}");
}

#[test]
fn zero_payment_intent_unsupported() {
    let mut fx = Fx::new();
    fx.intent.constraints.maximum_successful_payments = 0;
    fx.intent_hash_override = None;
    assert!(denied_with(&fx.eval(), &ReasonCode::UnsupportedOperation));
}

#[test]
fn too_many_grants_rejected() {
    let mut fx = Fx::new();
    let g = fx.grants[0].clone();
    fx.grants = vec![g; MAX_GRANTS + 1];
    assert!(denied_with(&fx.eval(), &ReasonCode::TooManyGrants));
}

// ---------------------------------------------------------------- rules

#[test]
fn no_matching_rule_and_purpose() {
    let mut fx = Fx::new();
    fx.policy.rules[0].vaults = vec![VaultId::unchecked("vault-treasury")];
    let d = fx.eval();
    assert_eq!(d, Decision::Deny { reasons: vec![ReasonCode::NoMatchingRule] });

    let mut fx = Fx::new();
    fx.policy.rules[0].purposes = vec![OperationPurpose::Payroll];
    let d = fx.eval();
    assert_eq!(d, Decision::Deny { reasons: vec![ReasonCode::NoMatchingRule, ReasonCode::PurposeNotPermitted] });

    // first matching rule wins
    let mut fx = Fx::new();
    let mut strict = rule();
    strict.rule_id = "r-strict".into();
    strict.max_amount_per_operation = Amount(1);
    strict.destinations = vec![DestinationId::unchecked("dest-1")];
    fx.policy.rules.insert(0, strict);
    assert!(denied_with(&fx.eval(), &ReasonCode::AmountExceedsRule));
}

#[test]
fn per_operation_amount_and_fee_limits() {
    let mut fx = Fx::new();
    fx.policy.rules[0].max_amount_per_operation = Amount(1000);
    assert!(allowed(&fx.eval()));
    fx.policy.rules[0].max_amount_per_operation = Amount(999);
    assert!(denied_with(&fx.eval(), &ReasonCode::AmountExceedsRule));

    let mut fx = Fx::new();
    fx.policy.rules[0].max_native_fee_per_operation = Amount(40);
    assert!(allowed(&fx.eval()));
    fx.policy.rules[0].max_native_fee_per_operation = Amount(39);
    assert!(denied_with(&fx.eval(), &ReasonCode::FeeExceedsRule));
}

#[test]
fn operating_window_wraps_midnight() {
    let day = 19_000 * SECONDS_PER_DAY; // midnight UTC
    let w = Some((23 * 3600, 3600)); // 23:00–01:00
    assert!(!within_operating_window(w, UnixSeconds(day + 23 * 3600 - 1)));
    assert!(within_operating_window(w, UnixSeconds(day + 23 * 3600)));
    assert!(within_operating_window(w, UnixSeconds(day + 23 * 3600 + 1800)));
    assert!(within_operating_window(w, UnixSeconds(day)));
    assert!(within_operating_window(w, UnixSeconds(day + 1800)));
    assert!(within_operating_window(w, UnixSeconds(day + 3599)));
    assert!(!within_operating_window(w, UnixSeconds(day + 3600)));
    assert!(!within_operating_window(w, UnixSeconds(day + 12 * 3600)));
    // non-wrapping 09:00–17:00
    let w = Some((9 * 3600, 17 * 3600));
    assert!(within_operating_window(w, UnixSeconds(day + 9 * 3600)));
    assert!(!within_operating_window(w, UnixSeconds(day + 17 * 3600)));
    assert!(!within_operating_window(w, UnixSeconds(day + 8 * 3600)));
    // degenerate and invalid windows fail closed; None means always
    assert!(!within_operating_window(Some((100, 100)), UnixSeconds(day + 100)));
    assert!(!within_operating_window(Some((86_400, 10)), UnixSeconds(day + 5)));
    assert!(within_operating_window(None, UnixSeconds(day + 5)));
}

#[test]
fn operating_window_in_evaluation() {
    let mut fx = Fx::new();
    let day = (NOW / SECONDS_PER_DAY) * SECONDS_PER_DAY;
    fx.policy.rules[0].operating_window = Some((23 * 3600, 3600));
    fx.now = day + 23 * 3600 + 1800;
    fx.evidence.observed_at = UnixSeconds(fx.now - 5);
    fx.grants = vec![
        fx.grant("g-1", "cred-alice", ApprovalRole::TreasuryApprover),
        fx.grant("g-2", "cred-bob", ApprovalRole::SecurityApprover),
    ];
    assert!(allowed(&fx.eval()), "{:?}", fx.eval());
    fx.now = day + 12 * 3600;
    fx.evidence.observed_at = UnixSeconds(fx.now - 5);
    fx.grants = vec![
        fx.grant("g-1", "cred-alice", ApprovalRole::TreasuryApprover),
        fx.grant("g-2", "cred-bob", ApprovalRole::SecurityApprover),
    ];
    assert!(denied_with(&fx.eval(), &ReasonCode::OutsideOperatingWindow));
}

#[test]
fn rolling_limit_boundary() {
    let mut fx = Fx::new();
    // 1000 settled + 3000 outstanding + 1000 this op == 5000 limit
    fx.exposure.windows[0].outstanding = Amount(3000);
    assert!(allowed(&fx.eval()));
    fx.exposure.windows[0].outstanding = Amount(3001);
    let d = fx.eval();
    assert!(denied_with(&d, &ReasonCode::RollingLimitExceeded { rule_id: "r-ops".into(), window_seconds: 86_400 }), "{d:?}");
}

#[test]
fn a36_outstanding_counted_after_settled_window_resets() {
    let mut fx = Fx::new();
    // A transaction signed yesterday is still outstanding; settled debits have rolled out.
    fx.exposure.windows[0].settled = Amount(0);
    fx.exposure.windows[0].outstanding = Amount(4500);
    assert!(denied_with(&fx.eval(), &ReasonCode::RollingLimitExceeded { rule_id: "r-ops".into(), window_seconds: 86_400 }));
    fx.exposure.windows[0].outstanding = Amount(4000);
    assert!(allowed(&fx.eval()));
}

#[test]
fn missing_exposure_data_and_overflow() {
    let mut fx = Fx::new();
    fx.exposure.windows[0].window_seconds = 3600;
    assert!(denied_with(&fx.eval(), &ReasonCode::MissingExposureData { asset_id: usdc(), window_seconds: 86_400 }));

    let mut fx = Fx::new();
    fx.exposure.windows[0].asset_id = AssetId::unchecked("other");
    assert!(denied_with(&fx.eval(), &ReasonCode::MissingExposureData { asset_id: usdc(), window_seconds: 86_400 }));

    let mut fx = Fx::new();
    fx.exposure.windows[0].settled = Amount(u128::MAX);
    assert!(denied_with(&fx.eval(), &ReasonCode::ExposureOverflow));
}

#[test]
fn claimed_outflow_larger_than_amount_is_charged() {
    let mut fx = Fx::new();
    fx.exposure.windows[0].outstanding = Amount(3000);
    assert!(allowed(&fx.eval()));
    fx.verified.claims.asset_outflows.push(AssetOutflow { asset_id: usdc(), amount_base_units: Amount(1) });
    assert!(denied_with(&fx.eval(), &ReasonCode::RollingLimitExceeded { rule_id: "r-ops".into(), window_seconds: 86_400 }));
}

#[test]
fn automated_path() {
    let mut fx = Fx::new();
    fx.policy.rules[0].required_approvals = 0;
    fx.policy.rules[0].approval_roles = vec![ApprovalRole::Automated];
    fx.grants.clear();
    assert!(allowed(&fx.eval()));
    fx.policy.rules[0].approval_roles = vec![ApprovalRole::TreasuryApprover];
    assert!(denied_with(&fx.eval(), &ReasonCode::AutomatedApprovalNotPermitted));
}

// ---------------------------------------------------------------- grants

#[test]
fn no_grants_requires_approvals() {
    let mut fx = Fx::new();
    fx.grants.clear();
    assert_eq!(
        fx.eval(),
        Decision::RequireApprovals {
            rule_id: "r-ops".into(),
            required: 2,
            satisfied: 0,
            roles: vec![ApprovalRole::TreasuryApprover, ApprovalRole::SecurityApprover],
            reasons: vec![ReasonCode::InsufficientApprovals],
        }
    );
}

#[test]
fn grant_expiry_is_exclusive() {
    let mut fx = Fx::new();
    fx.grants[1].body.expires_at = UnixSeconds(NOW);
    assert!(approvals_with(&fx.eval(), 1, &ReasonCode::GrantExpired));
    fx.grants[1].body.expires_at = UnixSeconds(NOW + 1);
    assert!(allowed(&fx.eval()));
}

#[test]
fn grant_not_yet_valid() {
    let mut fx = Fx::new();
    fx.grants[1].body.issued_at = UnixSeconds(NOW + 1);
    assert!(approvals_with(&fx.eval(), 1, &ReasonCode::GrantNotYetValid));
    fx.grants[1].body.issued_at = UnixSeconds(NOW);
    assert!(allowed(&fx.eval()));
}

type GrantMutation = Box<dyn Fn(&mut ApprovalGrantBody)>;
type TemplateMutation = Box<dyn Fn(&mut BoundedTransferTemplate)>;

#[test]
fn grant_binding_failures() {
    let cases: Vec<(GrantMutation, ReasonCode)> = vec![
        (Box::new(|g| g.intent_hash = Hash32([5; 32])), ReasonCode::GrantWrongIntent),
        (Box::new(|g| g.intent_id = IntentId::unchecked("intent-2")), ReasonCode::GrantWrongIntent),
        (Box::new(|g| g.vault_id = VaultId::unchecked("vault-x")), ReasonCode::GrantScopeMismatch),
        (Box::new(|g| g.institution_id = InstitutionId::unchecked("inst-x")), ReasonCode::GrantScopeMismatch),
        (Box::new(|g| g.environment_id = EnvironmentId::unchecked("mainnet")), ReasonCode::GrantScopeMismatch),
        (Box::new(|g| g.policy_epoch = Epoch(2)), ReasonCode::GrantWrongPolicyEpoch),
        (Box::new(|g| g.policy_id = PolicyId::unchecked("pol-x")), ReasonCode::GrantWrongPolicyEpoch),
        (
            Box::new(|g| {
                if let GrantScope::ExactCandidate { preview_hash, .. } = &mut g.scope {
                    *preview_hash = Hash32([6; 32]);
                }
            }),
            ReasonCode::GrantScopeMismatch,
        ),
        (
            Box::new(|g| {
                if let GrantScope::ExactCandidate { candidate_revision, .. } = &mut g.scope {
                    *candidate_revision = 2;
                }
            }),
            ReasonCode::GrantScopeMismatch,
        ),
        (
            Box::new(|g| {
                if let GrantScope::ExactCandidate { candidate_id, .. } = &mut g.scope {
                    *candidate_id = CandidateId::unchecked("cand-2");
                }
            }),
            ReasonCode::GrantScopeMismatch,
        ),
        (Box::new(|g| g.approver_role = ApprovalRole::Administrator), ReasonCode::GrantRoleNotPermitted),
        (Box::new(|g| g.approver_credential_id = CredentialId::unchecked("cred-proposer")), ReasonCode::GrantProposerIsApprover),
    ];
    for (mutate, reason) in cases {
        let mut fx = Fx::new();
        mutate(&mut fx.grants[1].body);
        let d = fx.eval();
        assert!(approvals_with(&d, 1, &reason), "expected {reason:?}, got {d:?}");
    }
}

#[test]
fn proposer_may_approve_when_not_excluded() {
    let mut fx = Fx::new();
    fx.grants[1].body.approver_credential_id = CredentialId::unchecked("cred-proposer");
    assert!(approvals_with(&fx.eval(), 1, &ReasonCode::GrantProposerIsApprover));
    fx.policy.rules[0].exclude_proposer = false;
    assert!(allowed(&fx.eval()));
}

#[test]
fn duplicate_approver_counts_once() {
    let mut fx = Fx::new();
    let dup = fx.grant("g-3", "cred-alice", ApprovalRole::SecurityApprover);
    fx.grants = vec![fx.grants[0].clone(), dup];
    assert!(approvals_with(&fx.eval(), 1, &ReasonCode::DuplicateApprover));
    // three grants, two distinct approvers -> allow
    fx.grants.push(fx.grant("g-4", "cred-bob", ApprovalRole::SecurityApprover));
    assert!(allowed(&fx.eval()));
}

#[test]
fn bounded_template_grants() {
    let mut fx = Fx::new();
    fx.intent.constraints.approval_mode = ApprovalMode::BoundedDirectTransfer;
    let ih = intent_hash(&fx.intent).unwrap();
    let t = fx.template();
    let mk = |fx: &Fx, id: &str, cred: &str, role, t: BoundedTransferTemplate| {
        let mut g = fx.grant(id, cred, role);
        g.body.intent_hash = ih;
        g.body.scope = GrantScope::BoundedDirectTransfer { template: t };
        g
    };
    fx.grants = vec![
        mk(&fx, "g-1", "cred-alice", ApprovalRole::TreasuryApprover, t.clone()),
        mk(&fx, "g-2", "cred-bob", ApprovalRole::SecurityApprover, t.clone()),
    ];
    assert!(allowed(&fx.eval()), "{:?}", fx.eval());

    let variants: Vec<TemplateMutation> = vec![
        Box::new(|t| t.max_native_fee_base_units = Amount(39)),
        Box::new(|t| t.maximum_successful_payments = 0),
        Box::new(|t| t.destination_address = Bytes(vec![0xbc; 20])),
        Box::new(|t| t.destination_version = 1),
        Box::new(|t| t.destination_id = DestinationId::unchecked("dest-2")),
        Box::new(|t| t.amount_base_units = Amount(999)),
        Box::new(|t| t.asset_id = AssetId::unchecked("eth")),
        Box::new(|t| t.network_id = NetworkId::unchecked("evm-mainnet")),
        Box::new(|t| t.chain_wallet_id = ChainWalletId::unchecked("wallet-2")),
    ];
    for v in variants {
        let mut bad = t.clone();
        v(&mut bad);
        let mut fx2 = fx.clone();
        fx2.grants[1] = mk(&fx, "g-2", "cred-bob", ApprovalRole::SecurityApprover, bad);
        assert!(approvals_with(&fx2.eval(), 1, &ReasonCode::GrantScopeMismatch), "{:?}", fx2.eval());
    }
    // Template fee bound above the verified fee is fine.
    let mut generous = t.clone();
    generous.max_native_fee_base_units = Amount(40);
    fx.grants[1] = mk(&fx, "g-2", "cred-bob", ApprovalRole::SecurityApprover, generous);
    assert!(allowed(&fx.eval()));

    // Exact-candidate grant on a bounded intent is a scope mismatch.
    let mut exact = fx.grant("g-5", "cred-carol", ApprovalRole::SecurityApprover);
    exact.body.intent_hash = ih;
    fx.grants[1] = exact;
    assert!(approvals_with(&fx.eval(), 1, &ReasonCode::GrantScopeMismatch));
}

// ---------------------------------------------------------------- hashing / admin

#[test]
fn policy_hash_excludes_signatures_and_binds_rules() {
    let fx = Fx::new();
    let mut signed = fx.policy.clone();
    signed.administrative_signatures.push(CredentialSignature { credential_id: CredentialId::unchecked("admin-1"), signature: dummy_sig() });
    assert_eq!(policy_hash(&fx.policy).unwrap(), policy_hash(&signed).unwrap());
    let mut changed = fx.policy.clone();
    changed.rules[0].max_amount_per_operation = Amount(1001);
    assert_ne!(policy_hash(&fx.policy).unwrap(), policy_hash(&changed).unwrap());
}

#[test]
fn preview_hash_binds_every_field() {
    let c = CandidateId::unchecked("c");
    let base = preview_hash(&c, 1, Hash32([1; 32]), Hash32([2; 32]));
    assert_ne!(base, preview_hash(&c, 2, Hash32([1; 32]), Hash32([2; 32])));
    assert_ne!(base, preview_hash(&CandidateId::unchecked("d"), 1, Hash32([1; 32]), Hash32([2; 32])));
    assert_ne!(base, preview_hash(&c, 1, Hash32([9; 32]), Hash32([2; 32])));
    assert_ne!(base, preview_hash(&c, 1, Hash32([1; 32]), Hash32([9; 32])));
}

fn admin(n: u8) -> (CredentialId, SigningKey) {
    (CredentialId::unchecked(format!("admin-{n}")), SigningKey::from_bytes(&[n; 32]))
}

fn admin_sign(bundle: &PolicyBundle, who: &(CredentialId, SigningKey)) -> CredentialSignature {
    let h = policy_hash(bundle).unwrap();
    CredentialSignature {
        credential_id: who.0.clone(),
        signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(who.1.sign(&h.0).to_bytes().to_vec()) },
    }
}

#[test]
fn a15_single_admin_cannot_activate_policy() {
    let admins: Vec<_> = (1..=3).map(admin).collect();
    let keys: Vec<_> = admins.iter().map(|(c, k)| (c.clone(), k.verifying_key())).collect();
    let mut bundle = Fx::new().policy;
    bundle.administrative_signatures = vec![admin_sign(&bundle, &admins[0])];
    let e = verify_policy_admin_signatures(&bundle, &keys, 2).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidSignature);
    // the same admin twice still counts once
    bundle.administrative_signatures.push(admin_sign(&bundle, &admins[0]));
    assert!(verify_policy_admin_signatures(&bundle, &keys, 2).is_err());
    // an unenrolled credential does not count
    let outsider = admin(9);
    bundle.administrative_signatures.push(admin_sign(&bundle, &outsider));
    assert!(verify_policy_admin_signatures(&bundle, &keys, 2).is_err());
    // a second enrolled admin reaches quorum
    bundle.administrative_signatures.push(admin_sign(&bundle, &admins[1]));
    verify_policy_admin_signatures(&bundle, &keys, 2).unwrap();
    // any change to the bundle invalidates the signatures
    bundle.rules[0].max_amount_per_operation = Amount(10_000);
    assert!(verify_policy_admin_signatures(&bundle, &keys, 2).is_err());
    assert_eq!(verify_policy_admin_signatures(&bundle, &keys, 0).unwrap_err().code, ErrorCode::InvalidRequest);
}

#[test]
fn admin_signature_scheme_is_explicit() {
    let a = admin(1);
    let keys = vec![(a.0.clone(), a.1.verifying_key())];
    let mut bundle = Fx::new().policy;
    let mut s = admin_sign(&bundle, &a);
    s.signature.scheme = SchemeId::EcdsaSecp256k1Keccak256Prehashed;
    bundle.administrative_signatures = vec![s];
    assert!(verify_policy_admin_signatures(&bundle, &keys, 1).is_err());
}

#[test]
fn reason_codes_have_stable_names() {
    let mut fx = Fx::new();
    fx.policy.rules[0].vaults = vec![VaultId::unchecked("none")];
    let d = fx.eval();
    let json = format!("{d:?}");
    assert!(json.contains("NoMatchingRule"));
}

// ---------------------------------------------------------------- properties

fn arb_fx() -> impl Strategy<Value = Fx> {
    (
        0u128..3000,
        0u64..200,
        0u128..6000,
        0u128..6000,
        0u64..300,
        0u64..300,
        any::<bool>(),
        any::<bool>(),
        prop::option::of((0u32..86_400, 0u32..86_400)),
        0u64..86_400,
    )
        .prop_map(|(amount, age, settled, outstanding, exp1, exp2, same_approver, deny_dest, window, tod)| {
            let mut fx = Fx::new();
            fx.now = (NOW / SECONDS_PER_DAY) * SECONDS_PER_DAY + tod;
            fx.evidence.observed_at = UnixSeconds(fx.now.saturating_sub(age));
            fx.set_intent_amount(amount);
            fx.set_decoded(|a, _, _, _, _| *a = Amount(amount));
            fx.verified.claims.asset_outflows[0].amount_base_units = Amount(amount);
            fx.exposure.windows[0].settled = Amount(settled);
            fx.exposure.windows[0].outstanding = Amount(outstanding);
            fx.policy.rules[0].operating_window = window;
            if deny_dest {
                fx.policy.denied_destinations = vec![DestinationId::unchecked("dest-1")];
            }
            let mut g1 = fx.grant("g-1", "cred-alice", ApprovalRole::TreasuryApprover);
            let mut g2 = fx.grant("g-2", if same_approver { "cred-alice" } else { "cred-bob" }, ApprovalRole::SecurityApprover);
            g1.body.expires_at = UnixSeconds(fx.now - 150 + exp1);
            g2.body.expires_at = UnixSeconds(fx.now - 150 + exp2);
            fx.grants = vec![g1, g2];
            fx
        })
}

proptest! {
    #[test]
    fn evaluation_is_deterministic(fx in arb_fx()) {
        let a = fx.eval();
        let b = fx.clone().eval();
        let c = fx.eval();
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(&a, &c);
    }

    #[test]
    fn denied_destination_always_denies(fx in arb_fx(), permissive in any::<bool>()) {
        let mut fx = fx;
        if permissive {
            fx.policy.rules.insert(0, permissive_rule());
        }
        fx.policy.denied_destinations = vec![DestinationId::unchecked("dest-1")];
        let d = fx.eval();
        prop_assert!(denied_with(&d, &ReasonCode::DeniedDestination), "{:?}", d);
    }

    #[test]
    fn allow_implies_limits_respected(fx in arb_fx()) {
        if let Decision::Allow { .. } = fx.eval() {
            let w = &fx.exposure.windows[0];
            let total = w.settled.0 + w.outstanding.0 + fx.verified.decoded.amount().0;
            prop_assert!(total <= 5000);
            prop_assert!(fx.verified.decoded.amount().0 <= 1000);
            prop_assert!(fx.policy.denied_destinations.is_empty());
        }
    }
}
