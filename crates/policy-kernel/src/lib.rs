//! # oic-policy-kernel
//!
//! The pinned, deterministic policy enforcement kernel (RFC 0001 §4.1).
//!
//! * Pure: no I/O, no clock, no floating point, no randomness. Time enters only
//!   through [`FreshnessContext`]; global exposure enters only through the
//!   authority-supplied [`ExposureView`].
//! * Fail closed: any configuration mismatch, missing data, stale evidence or
//!   arithmetic overflow produces `Deny`.
//! * Hard denials dominate: they are evaluated before any rule is consulted,
//!   so no rule can override them.
//! * Bounded: every allocation is bounded by the size of the inputs; grant
//!   lists longer than [`MAX_GRANTS`] are rejected outright.
//!
//! Outputs are `Allow`, `Deny`, or `RequireApprovals` with stable
//! [`ReasonCode`]s.

mod hashing;

pub use hashing::*;

use oic_domain_types::*;
use serde::{Deserialize, Serialize};

/// Upper bound on the number of grants the kernel will examine.
pub const MAX_GRANTS: usize = 64;

/// Seconds in one UTC day; operating windows are seconds-of-day.
pub const SECONDS_PER_DAY: u64 = 86_400;

/// Everything the kernel needs to decide one candidate. All references are
/// authenticated by the caller (signatures over grants, policy, evidence);
/// the kernel checks binding, scope, freshness, and limits.
#[derive(Clone, Debug)]
pub struct PolicyInput<'a> {
    pub policy: &'a PolicyBundle,
    /// Caller-computed `policy_hash(policy)`; recomputed and compared.
    pub policy_hash: Hash32,
    /// The authority's current policy epoch.
    pub expected_policy_epoch: Epoch,
    pub intent: &'a Intent,
    /// Caller-computed `intent_hash(intent)`; recomputed and compared.
    pub intent_hash: Hash32,
    pub verified: &'a VerifiedOperation,
    /// Already signature-verified by the caller.
    pub grants: &'a [ApprovalGrant],
    pub destination: &'a CounterpartyDestination,
    pub asset: &'a Asset,
    pub vault: &'a Vault,
    pub evidence: &'a EvidenceBundle,
    pub freshness: FreshnessContext,
    pub exposure: &'a ExposureView,
    pub candidate_id: &'a CandidateId,
    pub candidate_revision: u32,
    pub preview_hash: Hash32,
}

/// Global exposure per (asset, window) as supplied by the authorization-state
/// authority for the intent's vault.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureView {
    pub windows: Vec<WindowExposure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowExposure {
    pub asset_id: AssetId,
    pub window_seconds: u64,
    /// Finalized debits whose settlement time falls inside the window.
    pub settled: Amount,
    /// Potential debits from reserved/issued operations; never expires by time.
    pub outstanding: Amount,
}

impl ExposureView {
    pub fn find(&self, asset_id: &AssetId, window_seconds: u64) -> Option<&WindowExposure> {
        self.windows.iter().find(|w| &w.asset_id == asset_id && w.window_seconds == window_seconds)
    }
}

/// Stable reason codes. Serialized names are part of the public API.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    // configuration binding
    PolicyEpochMismatch,
    PolicyNotActive,
    PolicyHashMismatch,
    PolicyIdMismatch,
    IntentHashMismatch,
    EnvironmentMismatch,
    InstitutionMismatch,
    VaultMismatch,
    // hard denials
    DeniedDestination,
    DeniedAsset,
    DestinationIdMismatch,
    DestinationNotRegisteredForAsset,
    DestinationVersionMismatch,
    DestinationNotActive,
    DestinationNetworkMismatch,
    AssetIdMismatch,
    AssetNetworkMismatch,
    AssetNonstandard,
    AssetKindMismatch,
    EvidenceNetworkMismatch,
    EvidenceStale,
    EvidenceFromFuture,
    EvidenceTrustInsufficient,
    RecipientMismatch,
    AmountMismatch,
    NativeValueMismatch,
    FeeExceedsIntentConstraint,
    UnsupportedOperation,
    TooManyGrants,
    // rule requirements
    NoMatchingRule,
    PurposeNotPermitted,
    AmountExceedsRule,
    FeeExceedsRule,
    OutsideOperatingWindow,
    RollingLimitExceeded { rule_id: String, window_seconds: u64 },
    MissingExposureData { asset_id: AssetId, window_seconds: u64 },
    ExposureOverflow,
    AutomatedApprovalNotPermitted,
    // grants
    GrantExpired,
    GrantNotYetValid,
    GrantScopeMismatch,
    GrantWrongIntent,
    GrantWrongPolicyEpoch,
    GrantRoleNotPermitted,
    GrantProposerIsApprover,
    DuplicateApprover,
    InsufficientApprovals,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow {
        rule_id: String,
    },
    Deny {
        reasons: Vec<ReasonCode>,
    },
    RequireApprovals {
        rule_id: String,
        required: u8,
        satisfied: u8,
        roles: Vec<ApprovalRole>,
        reasons: Vec<ReasonCode>,
    },
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
    pub fn reasons(&self) -> &[ReasonCode] {
        match self {
            Decision::Allow { .. } => &[],
            Decision::Deny { reasons } | Decision::RequireApprovals { reasons, .. } => reasons,
        }
    }
}

/// Evaluate one candidate. Deterministic: equal inputs always give equal output.
pub fn evaluate(input: &PolicyInput) -> Decision {
    let binding = check_binding(input);
    if !binding.is_empty() {
        return Decision::Deny { reasons: binding };
    }
    let hard = check_hard_denials(input);
    if !hard.is_empty() {
        return Decision::Deny { reasons: hard };
    }
    let rule = match select_rule(input) {
        Ok(rule) => rule,
        Err(reasons) => return Decision::Deny { reasons },
    };
    let rule_reasons = check_rule(input, rule);
    if !rule_reasons.is_empty() {
        return Decision::Deny { reasons: rule_reasons };
    }
    evaluate_approvals(input, rule)
}

fn intent_transfer(intent: &Intent) -> (&AssetId, Amount, &DestinationId, u32) {
    match &intent.operation {
        IntentOperation::AssetTransfer { asset_id, amount_base_units, destination_id, destination_version } => {
            (asset_id, *amount_base_units, destination_id, *destination_version)
        }
    }
}

/// Stage 1: the policy, intent, and vault must describe the same security
/// domain and the policy must be the authority's current epoch.
fn check_binding(input: &PolicyInput) -> Vec<ReasonCode> {
    let mut r = Vec::new();
    let p = input.policy;
    if p.policy_epoch != input.expected_policy_epoch {
        r.push(ReasonCode::PolicyEpochMismatch);
    }
    if p.activation_epoch > input.expected_policy_epoch {
        r.push(ReasonCode::PolicyNotActive);
    }
    match policy_hash(p) {
        Ok(h) if h == input.policy_hash => {}
        _ => r.push(ReasonCode::PolicyHashMismatch),
    }
    match intent_hash(input.intent) {
        Ok(h) if h == input.intent_hash => {}
        _ => r.push(ReasonCode::IntentHashMismatch),
    }
    if p.institution_id != input.intent.institution_id || p.institution_id != input.vault.institution_id {
        r.push(ReasonCode::InstitutionMismatch);
    }
    if p.environment_id != input.intent.environment_id || p.environment_id != input.vault.environment_id {
        r.push(ReasonCode::EnvironmentMismatch);
    }
    if input.intent.vault_id != input.vault.vault_id {
        r.push(ReasonCode::VaultMismatch);
    }
    if input.vault.policy_id != p.policy_id {
        r.push(ReasonCode::PolicyIdMismatch);
    }
    r
}

/// Evidence trust is bounded by environment: the in-process simulator is
/// acceptable only in `dev`, and a single uncross-checked provider never on
/// `mainnet`. Validating nodes and cross-checked providers are acceptable
/// everywhere.
fn trust_sufficient(level: EvidenceTrustLevel, env: &EnvironmentId) -> bool {
    match level {
        EvidenceTrustLevel::ValidatingNode | EvidenceTrustLevel::TrustedProviderCrossChecked => true,
        EvidenceTrustLevel::SingleProvider => env.as_str() != "mainnet",
        EvidenceTrustLevel::DevelopmentSimulator => env.as_str() == "dev",
    }
}

/// Stage 2: denials no rule can override.
fn check_hard_denials(input: &PolicyInput) -> Vec<ReasonCode> {
    let mut r = Vec::new();
    let p = input.policy;
    let (asset_id, amount, destination_id, destination_version) = intent_transfer(input.intent);
    let decoded = &input.verified.decoded;
    let network = decoded.network_id();

    if input.grants.len() > MAX_GRANTS {
        r.push(ReasonCode::TooManyGrants);
    }
    if input.intent.constraints.maximum_successful_payments == 0 {
        r.push(ReasonCode::UnsupportedOperation);
    }
    if &input.asset.asset_id != asset_id {
        r.push(ReasonCode::AssetIdMismatch);
    }
    if &input.destination.destination_id != destination_id {
        r.push(ReasonCode::DestinationIdMismatch);
    }
    if p.denied_destinations.iter().any(|d| d == destination_id || d == &input.destination.destination_id) {
        r.push(ReasonCode::DeniedDestination);
    }
    if p.denied_assets.iter().any(|a| a == asset_id || a == &input.asset.asset_id) {
        r.push(ReasonCode::DeniedAsset);
    }
    if &input.destination.network_id != network {
        r.push(ReasonCode::DestinationNetworkMismatch);
    }
    if &input.asset.network_id != network {
        r.push(ReasonCode::AssetNetworkMismatch);
    }
    if &input.evidence.network_id != network {
        r.push(ReasonCode::EvidenceNetworkMismatch);
    }
    if input.destination.activation_epoch > input.expected_policy_epoch {
        r.push(ReasonCode::DestinationNotActive);
    }
    if !input.destination.allowed_assets.is_empty() && !input.destination.allowed_assets.contains(asset_id) {
        r.push(ReasonCode::DestinationNotRegisteredForAsset);
    }
    if input.destination.version != destination_version {
        r.push(ReasonCode::DestinationVersionMismatch);
    }
    if input.asset.behavior == AssetBehaviorProfile::Nonstandard {
        r.push(ReasonCode::AssetNonstandard);
    }

    // Evidence freshness: the tighter of policy and evidence bounds applies.
    let now = input.freshness.now.0;
    let max_age = p.max_evidence_age_seconds.min(input.evidence.max_staleness_seconds);
    let observed = input.evidence.observed_at.0;
    if observed > now {
        r.push(ReasonCode::EvidenceFromFuture);
    } else if now - observed > max_age {
        r.push(ReasonCode::EvidenceStale);
    }
    if !trust_sufficient(input.evidence.trust_level, &p.environment_id) {
        r.push(ReasonCode::EvidenceTrustInsufficient);
    }

    // The verified operation must be exactly the intent.
    if decoded.recipient() != &input.destination.address {
        r.push(ReasonCode::RecipientMismatch);
    }
    if decoded.amount() != amount {
        r.push(ReasonCode::AmountMismatch);
    }
    if decoded.asset() != &input.asset.asset {
        r.push(ReasonCode::AssetKindMismatch);
    }
    let DecodedOperation::DirectTransfer { native_value_base_units, .. } = decoded;
    let native_ok = match decoded.asset() {
        AssetKind::Native => *native_value_base_units == decoded.amount(),
        AssetKind::Erc20 { .. } => native_value_base_units.is_zero(),
        // SPL native movement (ATA rent) is bounded by the adapter's max fee.
        AssetKind::SplToken { .. } => true,
    };
    if !native_ok {
        r.push(ReasonCode::NativeValueMismatch);
    }
    if decoded.max_native_fee() > input.intent.constraints.max_network_fee_base_units {
        r.push(ReasonCode::FeeExceedsIntentConstraint);
    }
    r
}

fn matches_list<T: PartialEq>(list: &[T], v: &T) -> bool {
    list.is_empty() || list.contains(v)
}

/// First rule (in bundle order) whose vault/asset/destination/purpose scope
/// matches. Empty lists match anything.
fn select_rule<'p>(input: &PolicyInput<'p>) -> Result<&'p PolicyRule, Vec<ReasonCode>> {
    match_rule(input.policy, &input.vault.vault_id, input.intent)
}

/// The rule [`evaluate`] would consult for `intent` in `vault_id`: the first
/// rule (in bundle order) whose vault/asset/destination/purpose scope
/// matches, with the same reasons on failure. Performs no binding, hard
/// denial, limit, or approval check; callers use it to explain what a policy
/// requires (e.g. which approvals are still missing), never to decide.
pub fn match_rule<'p>(policy: &'p PolicyBundle, vault_id: &VaultId, intent: &Intent) -> Result<&'p PolicyRule, Vec<ReasonCode>> {
    let (asset_id, _, destination_id, _) = intent_transfer(intent);
    let mut purpose_blocked = false;
    for rule in &policy.rules {
        let scope = matches_list(&rule.vaults, vault_id) && matches_list(&rule.assets, asset_id) && matches_list(&rule.destinations, destination_id);
        if !scope {
            continue;
        }
        if matches_list(&rule.purposes, &intent.purpose) {
            return Ok(rule);
        }
        purpose_blocked = true;
    }
    let mut r = vec![ReasonCode::NoMatchingRule];
    if purpose_blocked {
        r.push(ReasonCode::PurposeNotPermitted);
    }
    Err(r)
}

/// Whether `now` lies in the half-open operating window `[start, end)`
/// (seconds-of-day UTC). `start > end` wraps midnight. `start == end` and
/// out-of-range bounds are treated as an empty window (fail closed).
pub fn within_operating_window(window: Option<(u32, u32)>, now: UnixSeconds) -> bool {
    let Some((start, end)) = window else { return true };
    let (start, end) = (u64::from(start), u64::from(end));
    if start >= SECONDS_PER_DAY || end > SECONDS_PER_DAY || start == end {
        return false;
    }
    let sod = now.0 % SECONDS_PER_DAY;
    if start < end {
        start <= sod && sod < end
    } else {
        sod >= start || sod < end
    }
}

/// This operation's worst-case outflow for `asset_id`: the larger of the
/// verified amount and the sum of the adapter's claimed outflows.
fn operation_outflow(input: &PolicyInput, asset_id: &AssetId) -> Option<Amount> {
    let mut claimed = Amount::ZERO;
    for o in &input.verified.claims.asset_outflows {
        if &o.asset_id == asset_id {
            claimed = claimed.checked_add(o.amount_base_units)?;
        }
    }
    Some(claimed.max(input.verified.decoded.amount()))
}

fn check_rule(input: &PolicyInput, rule: &PolicyRule) -> Vec<ReasonCode> {
    let mut r = Vec::new();
    let (asset_id, amount, _, _) = intent_transfer(input.intent);
    if amount > rule.max_amount_per_operation {
        r.push(ReasonCode::AmountExceedsRule);
    }
    if input.verified.decoded.max_native_fee() > rule.max_native_fee_per_operation {
        r.push(ReasonCode::FeeExceedsRule);
    }
    if !within_operating_window(rule.operating_window, input.freshness.now) {
        r.push(ReasonCode::OutsideOperatingWindow);
    }
    let outflow = operation_outflow(input, asset_id);
    for limit in &rule.rolling_limits {
        let Some(w) = input.exposure.find(asset_id, limit.window_seconds) else {
            r.push(ReasonCode::MissingExposureData { asset_id: asset_id.clone(), window_seconds: limit.window_seconds });
            continue;
        };
        let total = outflow.and_then(|o| w.settled.checked_add(w.outstanding)?.checked_add(o));
        match total {
            None => r.push(ReasonCode::ExposureOverflow),
            Some(t) if t > limit.max_outflow_base_units => r.push(ReasonCode::RollingLimitExceeded {
                rule_id: rule.rule_id.clone(),
                window_seconds: limit.window_seconds,
            }),
            Some(_) => {}
        }
    }
    if rule.required_approvals == 0 && !rule.approval_roles.contains(&ApprovalRole::Automated) {
        r.push(ReasonCode::AutomatedApprovalNotPermitted);
    }
    r
}

/// Validate one grant against the intent, candidate, and rule. Returns the
/// first failing reason, in a fixed check order.
fn check_grant(input: &PolicyInput, rule: &PolicyRule, g: &ApprovalGrantBody) -> Result<(), ReasonCode> {
    let intent = input.intent;
    let (asset_id, amount, destination_id, destination_version) = intent_transfer(intent);
    let now = input.freshness.now;
    if g.intent_id != intent.intent_id || g.intent_hash != input.intent_hash {
        return Err(ReasonCode::GrantWrongIntent);
    }
    if g.institution_id != intent.institution_id || g.environment_id != intent.environment_id || g.vault_id != intent.vault_id {
        return Err(ReasonCode::GrantScopeMismatch);
    }
    if g.policy_id != input.policy.policy_id || g.policy_epoch != input.policy.policy_epoch {
        return Err(ReasonCode::GrantWrongPolicyEpoch);
    }
    if g.issued_at > now {
        return Err(ReasonCode::GrantNotYetValid);
    }
    if now >= g.expires_at {
        return Err(ReasonCode::GrantExpired);
    }
    let decoded = &input.verified.decoded;
    let scope_ok = match (&g.scope, intent.constraints.approval_mode) {
        (GrantScope::ExactCandidate { candidate_id, candidate_revision, preview_hash }, ApprovalMode::ExactCandidate) => {
            candidate_id == input.candidate_id && *candidate_revision == input.candidate_revision && *preview_hash == input.preview_hash
        }
        (GrantScope::BoundedDirectTransfer { template: t }, ApprovalMode::BoundedDirectTransfer) => {
            t.chain_wallet_id == intent.chain_wallet_id
                && &t.network_id == decoded.network_id()
                && &t.asset_id == asset_id
                && t.amount_base_units == amount
                && &t.destination_id == destination_id
                && t.destination_version == destination_version
                && t.destination_address == input.destination.address
                && t.max_native_fee_base_units >= decoded.max_native_fee()
                && t.maximum_successful_payments >= 1
        }
        _ => false,
    };
    if !scope_ok {
        return Err(ReasonCode::GrantScopeMismatch);
    }
    if !rule.approval_roles.contains(&g.approver_role) {
        return Err(ReasonCode::GrantRoleNotPermitted);
    }
    if rule.exclude_proposer && g.approver_credential_id == intent.proposer_credential_id {
        return Err(ReasonCode::GrantProposerIsApprover);
    }
    Ok(())
}

fn evaluate_approvals(input: &PolicyInput, rule: &PolicyRule) -> Decision {
    let required = rule.required_approvals;
    if required == 0 {
        // Preapproved automatic path (role `Automated`, checked in `check_rule`).
        return Decision::Allow { rule_id: rule.rule_id.clone() };
    }
    let mut reasons = Vec::new();
    let mut counted: Vec<&CredentialId> = Vec::with_capacity(input.grants.len().min(MAX_GRANTS));
    for grant in input.grants.iter().take(MAX_GRANTS) {
        let g = &grant.body;
        match check_grant(input, rule, g) {
            Err(reason) => reasons.push(reason),
            Ok(()) if counted.contains(&&g.approver_credential_id) => reasons.push(ReasonCode::DuplicateApprover),
            Ok(()) => counted.push(&g.approver_credential_id),
        }
    }
    let satisfied = u8::try_from(counted.len()).unwrap_or(u8::MAX);
    if satisfied >= required {
        return Decision::Allow { rule_id: rule.rule_id.clone() };
    }
    reasons.push(ReasonCode::InsufficientApprovals);
    Decision::RequireApprovals {
        rule_id: rule.rule_id.clone(),
        required,
        satisfied,
        roles: rule.approval_roles.clone(),
        reasons,
    }
}

#[cfg(test)]
mod tests;
