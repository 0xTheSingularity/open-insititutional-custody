//! # oic-service-builder
//!
//! The builder of RFC 0001 §1.1: it constructs candidates with a chain
//! profile's pinned adapter, verifies them, and explains what policy
//! requires. It has **no authority to determine what is approved**: the
//! decision it computes is a preview that the authorization-state authority
//! re-checks (§5.4) and every signer recomputes from the objects (I1–I3).
//! Everything here is pure and deterministic; chain state enters only
//! through an [`EvidenceSource`].
//!
//! * [`build`] checks that the intent, vault, wallet, key, asset,
//!   destination, profile, and policy reference each other consistently
//!   (`ScopeMismatch` otherwise, before the adapter runs), builds the
//!   candidate, re-verifies it from its bytes against the intent (and, in
//!   bounded mode, against the [`BoundedTransferTemplate`] derived from the
//!   intent exactly as the independent approval client derives it), and
//!   returns the [`ApprovalPackage`] every approver and signer receives.
//! * [`evaluate`] verifies grant signatures against the enrolled approver
//!   roster and runs the pinned policy kernel.
//! * [`required_approvals`] names the matched rule's approval requirement.
//! * [`envelope_body`] produces the [`AuthorizationEnvelopeBody`] (RFC 0001
//!   §3.3) for a built candidate, field for field what signers verify.
//! * [`signing_materials`] converts the package into the signer's input.

mod evidence;

pub use evidence::*;

use oic_adapter_api::{decoded_operation_hash, evidence_hash, AuthorizationTarget, BuildContext, ChainAdapter, ChainProfile, VerifyContext};
use oic_approval_verifier::{fillable_fields_for, verify_grants, ApproverCredential};
use oic_authorization_state::{family_id_for, reservation_id_for};
use oic_domain_types::*;
use oic_policy_kernel::{destination_hash, intent_hash, match_rule, policy_hash, preview_hash, Decision, ExposureView, PolicyInput};
use oic_signer::{public_key_hash, SigningMaterials};
use serde::{Deserialize, Serialize};

/// Everything the builder needs for one candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInputs {
    pub intent: Intent,
    pub vault: Vault,
    pub wallet: ChainWallet,
    pub key: KeyDescriptor,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub profile: ChainProfile,
    pub policy: PolicyBundle,
    pub evidence: EvidenceBundle,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub operation_family_id: OperationFamilyId,
    pub built_at: UnixSeconds,
}

/// A candidate built and re-verified from its own bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltCandidate {
    pub candidate: Candidate,
    /// Verification against the approval target: the intent in exact mode,
    /// the bounded template in bounded mode (what signers re-derive).
    pub verified: VerifiedOperation,
    pub decoded: DecodedOperation,
    /// `preview_hash(candidate_id, revision, decoded_operation_hash, evidence_bundle_hash)`.
    pub preview_hash: Hash32,
    /// The bounded template approvers sign in `BoundedDirectTransfer` mode.
    pub template: Option<BoundedTransferTemplate>,
    pub package: ApprovalPackage,
}

/// Result of [`evaluate`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub decision: Decision,
    /// Distinct approver credentials whose grant signatures verified.
    pub approvers: Vec<CredentialId>,
    /// The rule the decision names (`None` for `Deny`).
    pub matched_rule: Option<PolicyRule>,
}

fn ensure(cond: bool, detail: &str) -> OicResult<()> {
    if cond {
        Ok(())
    } else {
        Err(OicError::scope(detail.to_string()))
    }
}

/// Cross-reference checks between the build inputs. Every object must
/// belong to the intent's institution, environment, vault, wallet, key, and
/// network, and the profile must belong to the adapter that will build.
fn check_scope(adapter: &dyn ChainAdapter, i: &BuildInputs) -> OicResult<()> {
    let it = &i.intent;
    let net = &i.profile.network_id;
    let IntentOperation::AssetTransfer { asset_id, destination_id, destination_version, .. } = &it.operation;
    ensure(i.profile.adapter_id == adapter.manifest().adapter_id, "chain profile belongs to a different adapter")?;
    ensure(it.chain_profile_id == i.profile.chain_profile_id, "intent names a different chain profile")?;
    ensure(i.vault.vault_id == it.vault_id, "vault is not the intent's vault")?;
    ensure(i.vault.institution_id == it.institution_id && i.vault.environment_id == it.environment_id, "vault belongs to another institution or environment")?;
    ensure(i.vault.policy_id == i.policy.policy_id, "policy is not the vault's policy")?;
    ensure(i.policy.institution_id == it.institution_id && i.policy.environment_id == it.environment_id, "policy belongs to another institution or environment")?;
    let w = &i.wallet;
    ensure(w.chain_wallet_id == it.chain_wallet_id, "chain wallet is not the intent's wallet")?;
    ensure(w.vault_id == it.vault_id, "chain wallet is not in the intent's vault")?;
    ensure(w.chain_profile_id == i.profile.chain_profile_id, "chain wallet is enrolled on another chain profile")?;
    ensure(&w.network_id == net, "chain wallet network differs from the chain profile network")?;
    ensure(w.active, "chain wallet is not active")?;
    let k = &i.key;
    ensure(k.key_id == w.key_id && k.key_epoch == w.key_epoch, "key descriptor is not the wallet's key/epoch")?;
    ensure(k.institution_id == it.institution_id && k.environment_id == it.environment_id, "key belongs to another institution or environment")?;
    ensure(k.networks.contains(net), "key is not enrolled for the chain profile network")?;
    ensure(&i.asset.asset_id == asset_id, "registry asset is not the intent's asset")?;
    ensure(&i.asset.network_id == net, "asset is registered on a different network")?;
    let d = &i.destination;
    ensure(&d.destination_id == destination_id && d.version == *destination_version, "registry destination/version is not the intent's")?;
    ensure(&d.network_id == net, "destination is registered on a different network")?;
    ensure(i.evidence.chain_profile_id == i.profile.chain_profile_id && &i.evidence.network_id == net, "evidence is for a different chain profile or network")?;
    ensure(i.operation_family_id == family_id_for(&it.intent_id)?, "operation family is not the intent's operation family")?;
    Ok(())
}

/// The bounded template for a bounded-mode intent, exactly as the
/// independent approval client derives it: amount, destination, and fee
/// ceiling from the intent and registry, fillable fields per adapter.
fn bounded_template(i: &BuildInputs, decoded: &DecodedOperation) -> OicResult<BoundedTransferTemplate> {
    let c = &i.intent.constraints;
    Ok(BoundedTransferTemplate {
        chain_wallet_id: i.intent.chain_wallet_id.clone(),
        network_id: i.profile.network_id.clone(),
        asset_id: i.asset.asset_id.clone(),
        amount_base_units: decoded.amount(),
        destination_id: i.destination.destination_id.clone(),
        destination_version: i.destination.version,
        destination_address: i.destination.address.clone(),
        max_native_fee_base_units: c.max_network_fee_base_units,
        maximum_successful_payments: c.maximum_successful_payments,
        fillable: fillable_fields_for(&i.profile.adapter_id)?,
    })
}

/// Build, verify, and package one candidate. See the crate docs.
pub fn build(adapter: &dyn ChainAdapter, inputs: &BuildInputs) -> OicResult<BuiltCandidate> {
    check_scope(adapter, inputs)?;
    let candidate = adapter.build_candidate(&BuildContext {
        intent: inputs.intent.clone(),
        wallet: inputs.wallet.clone(),
        key: inputs.key.clone(),
        asset: inputs.asset.clone(),
        destination: inputs.destination.clone(),
        profile: inputs.profile.clone(),
        evidence: inputs.evidence.clone(),
        candidate_id: inputs.candidate_id.clone(),
        candidate_revision: inputs.candidate_revision,
        operation_family_id: inputs.operation_family_id.clone(),
        built_at: inputs.built_at,
    })?;
    if candidate.evidence_bundle_hash != evidence_hash(&inputs.evidence)? {
        return Err(OicError::unverifiable("adapter bound the candidate to a different evidence bundle"));
    }
    let vctx = VerifyContext {
        profile: &inputs.profile,
        wallet: &inputs.wallet,
        key: &inputs.key,
        asset: &inputs.asset,
        destination: &inputs.destination,
        evidence: &inputs.evidence,
    };
    let against_intent = adapter.verify_candidate(&candidate, &AuthorizationTarget::Intent(&inputs.intent), &vctx)?;
    if decoded_operation_hash(&against_intent.decoded)? != against_intent.decoded_operation_hash {
        return Err(OicError::unverifiable("adapter decoded-operation hash is inconsistent"));
    }
    if against_intent.signing_payloads != candidate.signing_payloads {
        return Err(OicError::unverifiable("re-derived signing payloads differ from the built candidate's payloads"));
    }
    let (verified, template) = match inputs.intent.constraints.approval_mode {
        ApprovalMode::ExactCandidate => (against_intent, None),
        ApprovalMode::BoundedDirectTransfer => {
            let t = bounded_template(inputs, &against_intent.decoded)?;
            let v = adapter.verify_candidate(&candidate, &AuthorizationTarget::Template(&t), &vctx)?;
            if v.decoded_operation_hash != against_intent.decoded_operation_hash || v.signing_payloads != against_intent.signing_payloads {
                return Err(OicError::unverifiable("template verification decodes a different operation than intent verification"));
            }
            (v, Some(t))
        }
    };
    let ph = preview_hash(&candidate.candidate_id, candidate.candidate_revision, verified.decoded_operation_hash, candidate.evidence_bundle_hash);
    let package = ApprovalPackage {
        schema_version: ApprovalPackage::SCHEMA_VERSION,
        intent: inputs.intent.clone(),
        candidate: candidate.clone(),
        vault: inputs.vault.clone(),
        wallet: inputs.wallet.clone(),
        key: inputs.key.clone(),
        asset: inputs.asset.clone(),
        destination: inputs.destination.clone(),
        policy: inputs.policy.clone(),
        evidence: inputs.evidence.clone(),
    };
    Ok(BuiltCandidate { decoded: verified.decoded.clone(), candidate, verified, preview_hash: ph, template, package })
}

/// Verify `grants` against the enrolled `approvers` (any invalid grant fails
/// the whole set) and run the pinned policy kernel for `built` under
/// `policy` at the authority's `expected_policy_epoch` and `exposure`.
///
/// `policy` must be the bundle the candidate was built under
/// (`StalePolicy` otherwise): the envelope commits to the package's policy.
pub fn evaluate(
    built: &BuiltCandidate,
    policy: &PolicyBundle,
    expected_policy_epoch: Epoch,
    grants: &[ApprovalGrant],
    approvers: &[ApproverCredential],
    exposure: &ExposureView,
    now: UnixSeconds,
) -> OicResult<Evaluation> {
    let p = &built.package;
    let ph = policy_hash(policy)?;
    if ph != policy_hash(&p.policy)? {
        return Err(OicError::new(ErrorCode::StalePolicy, "policy differs from the policy the candidate was built under"));
    }
    let verified_approvers = verify_grants(grants, approvers, now)?;
    let decision = oic_policy_kernel::evaluate(&PolicyInput {
        policy,
        policy_hash: ph,
        expected_policy_epoch,
        intent: &p.intent,
        intent_hash: intent_hash(&p.intent)?,
        verified: &built.verified,
        grants,
        destination: &p.destination,
        asset: &p.asset,
        vault: &p.vault,
        evidence: &p.evidence,
        freshness: FreshnessContext { now },
        exposure,
        candidate_id: &built.candidate.candidate_id,
        candidate_revision: built.candidate.candidate_revision,
        preview_hash: built.preview_hash,
    });
    let matched_rule = match &decision {
        Decision::Allow { rule_id } | Decision::RequireApprovals { rule_id, .. } => {
            Some(policy.rules.iter().find(|r| &r.rule_id == rule_id).cloned().ok_or_else(|| OicError::internal("kernel named a rule not in the policy"))?)
        }
        Decision::Deny { .. } => None,
    };
    Ok(Evaluation { decision, approvers: verified_approvers, matched_rule })
}

/// The approval requirement of the rule the kernel would consult for
/// `built`: `(rule_id, required_approvals, approval_roles)`. `None` when no
/// rule matches (the kernel denies) or the matched rule is the automated
/// zero-approval path. This explains a requirement; it never decides.
pub fn required_approvals(policy: &PolicyBundle, built: &BuiltCandidate) -> Option<(String, u8, Vec<ApprovalRole>)> {
    let rule = match_rule(policy, &built.package.vault.vault_id, &built.package.intent).ok()?;
    if rule.required_approvals == 0 {
        return None;
    }
    Some((rule.rule_id.clone(), rule.required_approvals, rule.approval_roles.clone()))
}

/// The authorization envelope body (RFC 0001 §3.3) for `built`, bound to
/// `grants`, the signer session, the participant set, and the issuance
/// deadline. The reservation id is the deterministic id the authority will
/// assign (`reservation_id_for`), at reservation version 1.
#[allow(clippy::too_many_arguments)]
pub fn envelope_body(
    built: &BuiltCandidate,
    adapter: &dyn ChainAdapter,
    profile: &ChainProfile,
    grants: Vec<ApprovalGrant>,
    session_id: SigningSessionId,
    participant_set: Vec<ParticipantId>,
    issuance_deadline: UnixSeconds,
) -> OicResult<AuthorizationEnvelopeBody> {
    let c = &built.candidate;
    let p = &built.package;
    let manifest = adapter.manifest();
    ensure(manifest.adapter_id == c.adapter_id && manifest.adapter_version == c.adapter_version, "adapter is not the adapter that built the candidate")?;
    ensure(profile.chain_profile_id == c.chain_profile_id && profile.adapter_id == c.adapter_id, "chain profile is not the candidate's chain profile")?;
    Ok(AuthorizationEnvelopeBody {
        institution_id: p.intent.institution_id.clone(),
        environment_id: p.intent.environment_id.clone(),
        vault_id: p.vault.vault_id.clone(),
        chain_wallet_id: p.wallet.chain_wallet_id.clone(),
        intent_id: p.intent.intent_id.clone(),
        intent_hash: intent_hash(&p.intent)?,
        operation_family_id: c.operation_family_id.clone(),
        candidate_id: c.candidate_id.clone(),
        candidate_revision: c.candidate_revision,
        chain_profile_id: profile.chain_profile_id.clone(),
        chain_profile_hash: profile.hash()?,
        key_id: p.key.key_id.clone(),
        key_epoch: p.key.key_epoch,
        public_key_hash: public_key_hash(&p.key.public_key)?,
        adapter_id: c.adapter_id.clone(),
        adapter_version: manifest.adapter_version,
        verifier_build_hash: manifest.verifier_build_hash,
        policy_id: p.policy.policy_id.clone(),
        policy_epoch: p.policy.policy_epoch,
        policy_hash: policy_hash(&p.policy)?,
        allowlist_version: p.policy.allowlist_version,
        native_unsigned_bytes: c.native_unsigned_bytes.clone(),
        native_signing_payloads: built.verified.signing_payloads.clone(),
        decoded_operation_hash: built.verified.decoded_operation_hash,
        evidence_bundle_hash: c.evidence_bundle_hash,
        destination_hash: destination_hash(&p.destination)?,
        approval_grants: grants,
        budget_reservation_id: reservation_id_for(&c.operation_family_id, &c.candidate_id, c.candidate_revision)?,
        reservation_version: 1,
        resource_reservations: built.verified.claims.resources.clone(),
        maximum_asset_outflows: built.verified.claims.asset_outflows.clone(),
        maximum_native_fees: built.verified.claims.native_fees.clone(),
        issuance_deadline,
        expected_chain_validity_constraints: adapter.validity_constraints(c, &p.evidence)?,
        signer_session_id: session_id,
        participant_set,
    })
}

/// The signer's view of an approval package.
pub fn signing_materials(package: &ApprovalPackage) -> SigningMaterials {
    SigningMaterials {
        intent: package.intent.clone(),
        candidate: package.candidate.clone(),
        vault: package.vault.clone(),
        wallet: package.wallet.clone(),
        key: package.key.clone(),
        asset: package.asset.clone(),
        destination: package.destination.clone(),
        policy: package.policy.clone(),
        evidence: package.evidence.clone(),
    }
}
