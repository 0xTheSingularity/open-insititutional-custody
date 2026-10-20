//! The independent approval client core (RFC 0001 §4.3, RFC 0002 §8).
//!
//! [`IndependentVerifier::render`] turns the raw signed/registered objects
//! into an [`ApprovalDisplay`] using only the pinned adapters and recomputed
//! hashes. [`IndependentVerifier::approve`] re-renders from the same inputs,
//! requires the result to equal what the approver confirmed, and only then
//! signs an [`ApprovalGrant`] binding exactly that object.

use crate::display::*;
use crate::grants::sign_grant;
use ed25519_dalek::{SigningKey, VerifyingKey};
use oic_adapter_api::*;
use oic_domain_types::*;
use oic_policy_kernel::{intent_hash, preview_hash, verify_destination_admin_signatures, verify_policy_admin_signatures};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Every object a display is computed from. The console may deliver these,
/// but none is trusted on its say-so: the policy is quorum-verified, the
/// candidate bytes are decoded by the pinned adapter, the evidence is bound
/// by hash, and every cross-reference between the objects is checked.
#[derive(Clone, Copy, Debug)]
pub struct DisplayInputs<'a> {
    pub intent: &'a Intent,
    pub candidate: &'a Candidate,
    pub wallet: &'a ChainWallet,
    pub key: &'a KeyDescriptor,
    pub vault: &'a Vault,
    pub asset: &'a Asset,
    pub destination: &'a CounterpartyDestination,
    pub policy: &'a PolicyBundle,
    pub evidence: &'a EvidenceBundle,
}

/// The verifier an independently distributed approval client embeds: pinned
/// adapters, enrolled chain profiles, and the administrative roster whose
/// quorum activates policies.
#[derive(Clone)]
pub struct IndependentVerifier {
    pub adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>>,
    pub chain_profiles: Vec<ChainProfile>,
    pub admin_keys: Vec<(CredentialId, VerifyingKey)>,
    pub admin_quorum: u8,
}

/// Fields a bounded template lets the builder fill, per pinned adapter:
/// EVM `[EvmNonce, EvmFeeFields, EvmGasLimit]`, Solana `[SolanaRecentBlockhash]`.
pub fn fillable_fields_for(adapter_id: &AdapterId) -> OicResult<Vec<FillableField>> {
    match adapter_id.as_str() {
        oic_adapter_evm::ADAPTER_ID => Ok(vec![FillableField::EvmNonce, FillableField::EvmFeeFields, FillableField::EvmGasLimit]),
        oic_adapter_solana::ADAPTER_ID => Ok(vec![FillableField::SolanaRecentBlockhash]),
        other => Err(OicError::unsupported(format!("bounded templates are not defined for adapter `{other}`"))),
    }
}

/// Everything `render` established, kept so `approve` signs the same objects.
struct Analysis {
    display: ApprovalDisplay,
    template: Option<BoundedTransferTemplate>,
}

fn scope_check(ok: bool, what: &str) -> OicResult<()> {
    if ok {
        Ok(())
    } else {
        Err(OicError::scope(what.to_string()))
    }
}

impl IndependentVerifier {
    pub fn new(
        adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>>,
        chain_profiles: Vec<ChainProfile>,
        admin_keys: Vec<(CredentialId, VerifyingKey)>,
        admin_quorum: u8,
    ) -> Self {
        IndependentVerifier { adapters, chain_profiles, admin_keys, admin_quorum }
    }

    /// Verify the inputs and compute what the approver must see.
    ///
    /// Fails with `InvalidSignature` when the policy lacks its administrative
    /// quorum, `ScopeMismatch` when the objects do not reference each other
    /// consistently or the chain profile is not enrolled,
    /// `UnsupportedCapability` when no pinned adapter exists, and
    /// `UnverifiableTransaction` when the candidate's evidence hash differs
    /// from the recomputed one or the adapter cannot verify the bytes.
    ///
    /// A decoded recipient that differs from the registry destination does
    /// NOT fail rendering: the approver must be able to see the mismatch. The
    /// display then carries `destination_matches_registry == false` and a
    /// warning, every other adapter check still runs (against a copy of the
    /// destination record whose address is the decoded one), and
    /// [`approve`](Self::approve) refuses to sign.
    pub fn render(&self, inputs: &DisplayInputs<'_>, now: UnixSeconds) -> OicResult<ApprovalDisplay> {
        Ok(self.analyse(inputs, now)?.display)
    }

    fn analyse(&self, inputs: &DisplayInputs<'_>, now: UnixSeconds) -> OicResult<Analysis> {
        let DisplayInputs { intent, candidate, wallet, key, vault, asset, destination, policy, evidence } = *inputs;

        // 1. Policy and destination identity: administrative quorum over
        //    policy_hash and destination_hash. An unsigned destination is not
        //    a registry entry, however plausible its label.
        verify_policy_admin_signatures(policy, &self.admin_keys, self.admin_quorum)?;
        verify_destination_admin_signatures(destination, &self.admin_keys, self.admin_quorum)?;

        // 2. Cross-references between the objects.
        scope_check(policy.institution_id == intent.institution_id && policy.environment_id == intent.environment_id, "policy belongs to another institution or environment")?;
        scope_check(vault.vault_id == intent.vault_id, "vault is not the intent's vault")?;
        scope_check(vault.institution_id == intent.institution_id && vault.environment_id == intent.environment_id, "vault belongs to another institution or environment")?;
        scope_check(vault.policy_id == policy.policy_id, "policy is not the vault's policy")?;
        scope_check(wallet.chain_wallet_id == intent.chain_wallet_id, "chain wallet is not the intent's wallet")?;
        scope_check(wallet.vault_id == intent.vault_id, "chain wallet is not in the intent's vault")?;
        scope_check(wallet.chain_profile_id == intent.chain_profile_id, "chain wallet is enrolled on another chain profile")?;
        scope_check(key.key_id == wallet.key_id && key.key_epoch == wallet.key_epoch, "key descriptor is not the wallet's key/epoch")?;
        scope_check(key.institution_id == intent.institution_id && key.environment_id == intent.environment_id, "key belongs to another institution or environment")?;
        scope_check(candidate.intent_id == intent.intent_id, "candidate is for another intent")?;
        scope_check(candidate.chain_profile_id == intent.chain_profile_id, "candidate is for another chain profile")?;
        let IntentOperation::AssetTransfer { asset_id, destination_id, destination_version, .. } = &intent.operation;
        scope_check(*asset_id == asset.asset_id, "registry asset is not the intent's asset")?;
        scope_check(*destination_id == destination.destination_id && *destination_version == destination.version, "registry destination/version is not the intent's")?;

        // 3. Enrolled chain profile and pinned adapter.
        let profile = self
            .chain_profiles
            .iter()
            .find(|p| p.chain_profile_id == intent.chain_profile_id)
            .ok_or_else(|| OicError::scope(format!("chain profile {} is not enrolled in this verifier", intent.chain_profile_id)))?;
        scope_check(profile.adapter_id == candidate.adapter_id, "candidate names a different adapter than the chain profile")?;
        scope_check(wallet.network_id == profile.network_id, "chain wallet network differs from the chain profile")?;
        let adapter = self
            .adapters
            .get(&profile.adapter_id)
            .ok_or_else(|| OicError::unsupported(format!("no pinned adapter `{}` in this verifier", profile.adapter_id)))?;

        // 4. Evidence binding.
        let ev_hash = evidence_hash(evidence)?;
        if candidate.evidence_bundle_hash != ev_hash {
            return Err(OicError::unverifiable("candidate evidence_bundle_hash does not match the recomputed evidence hash"));
        }

        // 5. Wallet address recomputed from the key.
        let (derived_address, wallet_address_display) = adapter.derive_address(&key.public_key)?;
        scope_check(derived_address == wallet.address, "wallet address does not match the address derived from its key")?;

        // 6. Decode from bytes; compare to the registry destination.
        let registry_ctx = VerifyContext { profile, wallet, key, asset, destination, evidence };
        let decoded = adapter.decode_candidate(candidate, &registry_ctx)?;
        let destination_matches_registry = destination.network_id == profile.network_id && decoded.recipient() == &destination.address;

        // 7. Full verification against the intent, from bytes.
        let shadow;
        let verify_dest = if destination_matches_registry {
            destination
        } else {
            shadow = CounterpartyDestination { address: decoded.recipient().clone(), network_id: profile.network_id.clone(), ..destination.clone() };
            &shadow
        };
        let verify_ctx = VerifyContext { destination: verify_dest, ..registry_ctx.clone() };
        let verified = adapter.verify_candidate(candidate, &AuthorizationTarget::Intent(intent), &verify_ctx)?;
        if verified.decoded != decoded {
            return Err(OicError::unverifiable("adapter decode and verify disagree about the candidate"));
        }

        // 8. Bounded template, verified to admit this candidate.
        let template = match intent.constraints.approval_mode {
            ApprovalMode::ExactCandidate => None,
            ApprovalMode::BoundedDirectTransfer => {
                let t = BoundedTransferTemplate {
                    chain_wallet_id: intent.chain_wallet_id.clone(),
                    network_id: profile.network_id.clone(),
                    asset_id: asset.asset_id.clone(),
                    amount_base_units: decoded.amount(),
                    destination_id: destination.destination_id.clone(),
                    destination_version: destination.version,
                    destination_address: destination.address.clone(),
                    max_native_fee_base_units: intent.constraints.max_network_fee_base_units,
                    maximum_successful_payments: intent.constraints.maximum_successful_payments,
                    fillable: fillable_fields_for(&profile.adapter_id)?,
                };
                if destination_matches_registry {
                    adapter.verify_candidate(candidate, &AuthorizationTarget::Template(&t), &registry_ctx)?;
                }
                Some(t)
            }
        };

        // 9. Commitments.
        let ih = intent_hash(intent)?;
        let ph = preview_hash(&candidate.candidate_id, candidate.candidate_revision, verified.decoded_operation_hash, ev_hash);

        // 10. Freshness and warnings.
        let evidence_age_seconds = now.0.saturating_sub(evidence.observed_at.0);
        let max_age = evidence.max_staleness_seconds.min(policy.max_evidence_age_seconds).min(profile.max_evidence_age_seconds);
        let mut warnings = Vec::new();
        if !destination_matches_registry {
            warnings.push(format!(
                "DESTINATION MISMATCH: transaction pays {}, registry destination {} v{} is {}",
                format_native_address(&profile.adapter_id, decoded.recipient().as_slice())?,
                destination.destination_id,
                destination.version,
                format_native_address(&profile.adapter_id, destination.address.as_slice()).unwrap_or_else(|_| format!("0x{}", destination.address.to_hex())),
            ));
        }
        // Nonstandard assets need no warning here: both pinned adapters refuse
        // them (`UnsupportedCapability`, watch-only), so rendering fails first.
        if evidence.trust_level == EvidenceTrustLevel::DevelopmentSimulator {
            warnings.push("DEVELOPMENT SIMULATOR EVIDENCE: not valid for production funds".to_string());
        }
        if evidence.trust_level == EvidenceTrustLevel::SingleProvider {
            warnings.push("SINGLE-PROVIDER EVIDENCE: chain state was not cross-checked".to_string());
        }
        if evidence.observed_at > now {
            warnings.push(format!("EVIDENCE TIMESTAMP IN THE FUTURE by {}s: check the approval client clock", evidence.observed_at.0 - now.0));
        } else if evidence_age_seconds > max_age {
            warnings.push(format!("STALE EVIDENCE: {evidence_age_seconds}s old, maximum {max_age}s"));
        }
        if !wallet.active {
            warnings.push("WALLET NOT ACTIVE: ceremony/recovery metadata not committed".to_string());
        }

        let template_summary = match &template {
            None => None,
            Some(t) => Some(TemplateSummary {
                chain_wallet_id: t.chain_wallet_id.clone(),
                network_id: t.network_id.clone(),
                asset_id: t.asset_id.clone(),
                amount_base_units: t.amount_base_units.to_string(),
                destination_id: t.destination_id.clone(),
                destination_version: t.destination_version,
                destination_address_display: format_native_address(&profile.adapter_id, t.destination_address.as_slice())?,
                max_native_fee_base_units: t.max_native_fee_base_units.to_string(),
                maximum_successful_payments: t.maximum_successful_payments,
                fillable: t.fillable.clone(),
            }),
        };

        let display = ApprovalDisplay {
            network_id: profile.network_id.clone(),
            chain_profile_id: profile.chain_profile_id.clone(),
            wallet_address_display,
            operation_kind: match &decoded {
                DecodedOperation::DirectTransfer { .. } => "direct_transfer".to_string(),
            },
            asset_identity: format_asset_identity(decoded.asset())?,
            asset_symbol_from_registry: asset.symbol.clone(),
            decimals: asset.decimals,
            amount_base_units: decoded.amount().to_string(),
            amount_display: format_amount(decoded.amount().0, asset.decimals),
            recipient_address_display: format_native_address(&profile.adapter_id, decoded.recipient().as_slice())?,
            destination_id: destination.destination_id.clone(),
            destination_version: destination.version,
            destination_display_name: destination.display_name.clone(),
            destination_matches_registry,
            max_native_fee_base_units: decoded.max_native_fee().to_string(),
            purpose: intent.purpose,
            intent_id: intent.intent_id.clone(),
            external_reference: intent.external_reference.clone(),
            candidate_id: candidate.candidate_id.clone(),
            candidate_revision: candidate.candidate_revision,
            policy_id: policy.policy_id.clone(),
            policy_epoch: policy.policy_epoch,
            preview_hash: ph,
            intent_hash: ih,
            evidence_state: EvidenceStateDisplay {
                height: evidence.state.height,
                hash: format!("0x{}", evidence.state.hash.to_hex()),
                commitment: evidence.state.commitment.clone(),
            },
            evidence_age_seconds,
            approval_mode: intent.constraints.approval_mode,
            template: template_summary,
            warnings,
        };
        Ok(Analysis { display, template })
    }

    /// Sign a grant for exactly what `display` shows.
    ///
    /// Re-renders from `inputs` at `now` and requires the result to equal
    /// `display` in every field except `evidence_age_seconds` (which advances
    /// with time); any other difference, including a warning that appeared
    /// since the approver looked (e.g. evidence became stale), is
    /// `ScopeMismatch`, so a UI cannot swap or edit the object between show
    /// and sign. A display whose decoded recipient is not the registry
    /// destination is never signed (`ScopeMismatch`). `ttl_seconds` must be
    /// positive.
    ///
    /// The grant scope is `ExactCandidate { candidate_id, candidate_revision,
    /// preview_hash }` in exact mode or `BoundedDirectTransfer { template }`
    /// in bounded mode (fillable fields per [`fillable_fields_for`]).
    pub fn approve(
        &self,
        display: &ApprovalDisplay,
        inputs: &DisplayInputs<'_>,
        credential: (CredentialId, ApprovalRole, &SigningKey),
        grant_id: GrantId,
        now: UnixSeconds,
        ttl_seconds: u64,
    ) -> OicResult<ApprovalGrant> {
        let (approver_credential_id, approver_role, signing_key) = credential;
        if ttl_seconds == 0 {
            return Err(OicError::invalid_request("grant ttl must be positive"));
        }
        let expires_at = now.0.checked_add(ttl_seconds).map(UnixSeconds).ok_or_else(|| OicError::invalid_request("grant expiry overflows"))?;
        let analysis = self.analyse(inputs, now)?;
        let mut confirmed = display.clone();
        confirmed.evidence_age_seconds = analysis.display.evidence_age_seconds;
        if confirmed != analysis.display {
            return Err(OicError::scope("the confirmed display does not match the verified object being signed"));
        }
        if !analysis.display.destination_matches_registry {
            return Err(OicError::scope("decoded recipient does not match the registry destination; refusing to sign"));
        }
        let intent = inputs.intent;
        // `analyse` produces a template exactly when the intent is in bounded mode.
        let scope = match analysis.template {
            None => GrantScope::ExactCandidate {
                candidate_id: inputs.candidate.candidate_id.clone(),
                candidate_revision: inputs.candidate.candidate_revision,
                preview_hash: analysis.display.preview_hash,
            },
            Some(template) => GrantScope::BoundedDirectTransfer { template },
        };
        let body = ApprovalGrantBody {
            grant_id,
            institution_id: intent.institution_id.clone(),
            environment_id: intent.environment_id.clone(),
            vault_id: intent.vault_id.clone(),
            intent_id: intent.intent_id.clone(),
            intent_hash: analysis.display.intent_hash,
            policy_id: inputs.policy.policy_id.clone(),
            policy_epoch: inputs.policy.policy_epoch,
            scope,
            approver_credential_id,
            approver_role,
            issued_at: now,
            expires_at,
        };
        sign_grant(signing_key, body)
    }
}
