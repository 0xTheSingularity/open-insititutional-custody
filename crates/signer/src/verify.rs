//! Envelope verification (`Signer::verify_envelope`), in the binding order
//! documented on [`crate::Signer::verify_envelope`]. Every check fails closed.

use crate::{envelope_body_hash, public_key_hash, Signer, SigningMaterials, VerifiedEnvelope};
use oic_adapter_api::{check_evidence_scope, decoded_operation_hash, evidence_hash, AuthorizationTarget, ChainProfile, VerifyContext};
use oic_approval_verifier::verify_grants;
use oic_authorization_state::{claims_hash, reservation_id_for, verify_receipt, ReceiptExpectation};
use oic_domain_types::*;
use oic_policy_kernel::{
    destination_hash, evaluate, intent_hash, policy_hash, preview_hash, verify_destination_admin_signatures, verify_policy_admin_signatures,
    Decision, ExposureView, PolicyInput, ReasonCode, WindowExposure,
};
use std::collections::BTreeSet;

fn ensure(cond: bool, err: impl FnOnce() -> OicError) -> OicResult<()> {
    if cond {
        Ok(())
    } else {
        Err(err())
    }
}

fn scope(detail: &str) -> impl FnOnce() -> OicError + '_ {
    move || OicError::scope(detail)
}

fn code(code: ErrorCode, detail: &str) -> impl FnOnce() -> OicError + '_ {
    move || OicError::new(code, detail)
}

/// What this signer derived for the reservation it is asked to honour.
pub(crate) struct ReservationCommitment<'a> {
    pub envelope_body_hash: Hash32,
    pub intent_hash: Hash32,
    pub rule_id: &'a str,
    pub claims_hash: Hash32,
}

/// What a receipt (reserved or release) must bind, besides its kind.
pub(crate) struct ReceiptBinding<'a> {
    pub kind: ReceiptKind,
    pub envelope_body_hash: Hash32,
    pub signer_session_id: &'a SigningSessionId,
    pub candidate_id: &'a CandidateId,
    pub candidate_revision: u32,
    pub reservation_id: &'a ReservationId,
    pub reservation_version: u32,
    pub policy_epoch: Epoch,
    pub intent_hash: Hash32,
    pub rule_id: &'a str,
    pub claims_hash: Hash32,
}

impl Signer {
    /// Shared authority-receipt check: issuing key, signature, kind, envelope
    /// and session binding, candidate, policy epoch, institution/environment,
    /// reservation identity, and validity window (with bounded clock skew on
    /// `issued_at` only; expiry is never extended).
    pub(crate) fn check_receipt(&self, r: &AuthorityReceipt, want: &ReceiptBinding<'_>, now: UnixSeconds) -> OicResult<()> {
        let rb = &r.body;
        ensure(r.authority_key_id == self.roots.authority_key_id, || {
            OicError::invalid_signature(format!("receipt issued by authority key {} which is not the enrolled authority key", r.authority_key_id))
        })?;
        // A receipt over a different envelope body is a signature that does not
        // cover this envelope: report it as such, whatever else differs.
        ensure(rb.envelope_body_hash == want.envelope_body_hash, || {
            OicError::invalid_signature("authority receipt signature does not cover this envelope body")
        })?;
        let effective_now = if rb.issued_at > now {
            ensure(
                rb.issued_at.0 <= now.0.saturating_add(self.roots.max_clock_skew_seconds),
                scope("receipt issued in the future beyond the permitted clock skew"),
            )?;
            rb.issued_at
        } else {
            now
        };
        verify_receipt(
            r,
            &self.roots.authority_pubkey,
            &ReceiptExpectation {
                kind: want.kind,
                envelope_body_hash: want.envelope_body_hash,
                signer_session_id: want.signer_session_id.clone(),
                candidate_id: want.candidate_id.clone(),
                candidate_revision: want.candidate_revision,
                now: effective_now,
                policy_epoch: want.policy_epoch,
            },
        )?;
        ensure(now < rb.expires_at, scope("receipt expired"))?;
        ensure(
            rb.institution_id == self.identity.institution_id && rb.environment_id == self.identity.environment_id,
            scope("receipt belongs to another institution or environment"),
        )?;
        ensure(
            &rb.reservation_id == want.reservation_id && rb.reservation_version == want.reservation_version,
            scope("receipt is for a different reservation or reservation version"),
        )?;
        // The authority charged limits with the claims and rule it was sent.
        // They must be exactly what this signer derived, or its shared-exposure
        // check did not cover this transaction.
        ensure(rb.intent_hash == want.intent_hash, scope("authority reserved a different intent than this envelope's intent"))?;
        ensure(rb.rule_id == want.rule_id, || {
            OicError::scope(format!(
                "authority charged policy rule {} but this signer's evaluation selects rule {}",
                rb.rule_id, want.rule_id
            ))
        })?;
        ensure(rb.claims_hash == want.claims_hash, scope("authority reserved claims that differ from this transaction's verified claims"))?;
        Ok(())
    }

    pub(crate) fn verify_inner(&self, env: &AuthorizationEnvelope, m: &SigningMaterials, now: UnixSeconds) -> OicResult<VerifiedEnvelope> {
        if self.finalized.is_some() {
            return Err(OicError::new(ErrorCode::SessionRejected, "D2 signer requires locally finalized authorization, not a D1 receipt"));
        }
        self.verify_body(&env.body, m, now, &self.roots.approvers, |derived| {
            let b = &env.body;
            self.check_receipt(
                &env.authorization_state_receipt,
                &ReceiptBinding {
                    kind: ReceiptKind::Reserved,
                    envelope_body_hash: derived.envelope_body_hash,
                    signer_session_id: &b.signer_session_id,
                    candidate_id: &b.candidate_id,
                    candidate_revision: b.candidate_revision,
                    reservation_id: &b.budget_reservation_id,
                    reservation_version: b.reservation_version,
                    policy_epoch: b.policy_epoch,
                    intent_hash: derived.intent_hash,
                    rule_id: derived.rule_id,
                    claims_hash: derived.claims_hash,
                },
                now,
            )
        })
    }

    pub(crate) fn verify_body(
        &self,
        b: &AuthorizationEnvelopeBody,
        m: &SigningMaterials,
        now: UnixSeconds,
        enrolled: &[oic_approval_verifier::ApproverCredential],
        check_reservation: impl FnOnce(&ReservationCommitment<'_>) -> OicResult<()>,
    ) -> OicResult<VerifiedEnvelope> {
        let id = &self.identity;
        let roots = &self.roots;
        let cand = &m.candidate;

        // ---- 1. Scope ------------------------------------------------------
        ensure(
            b.institution_id == id.institution_id && b.environment_id == id.environment_id,
            scope("envelope is for another institution or environment"),
        )?;
        ensure(b.key_id == m.key.key_id && b.key_epoch == m.key.key_epoch, scope("envelope key id/epoch does not match the key descriptor"))?;
        let loaded = self.keys.lock().get(&b.key_id).cloned();
        let loaded = loaded.ok_or_else(|| OicError::scope(format!("key {} is not loaded in this signer", b.key_id)))?;
        ensure(loaded == m.key, scope("key descriptor differs from the descriptor loaded in this signer"))?;
        ensure(
            m.key.institution_id == id.institution_id && m.key.environment_id == id.environment_id,
            scope("key belongs to another institution or environment"),
        )?;
        ensure(b.public_key_hash == public_key_hash(&m.key.public_key)?, scope("envelope public_key_hash does not match the key's public key"))?;
        let w = &m.wallet;
        ensure(w.chain_wallet_id == b.chain_wallet_id && w.vault_id == b.vault_id, scope("wallet id/vault does not match the envelope"))?;
        ensure(w.key_id == b.key_id && w.key_epoch == b.key_epoch, scope("wallet is bound to a different key or key epoch"))?;
        ensure(w.chain_profile_id == b.chain_profile_id, scope("wallet chain profile does not match the envelope"))?;
        ensure(w.active, scope("chain wallet is not active"))?;
        let v = &m.vault;
        ensure(v.vault_id == b.vault_id, scope("vault does not match the envelope"))?;
        ensure(
            v.institution_id == id.institution_id && v.environment_id == id.environment_id,
            scope("vault belongs to another institution or environment"),
        )?;
        ensure(v.policy_id == b.policy_id, scope("vault is governed by a different policy"))?;
        let it = &m.intent;
        ensure(it.intent_id == b.intent_id, scope("intent id does not match the envelope"))?;
        ensure(
            it.institution_id == id.institution_id && it.environment_id == id.environment_id,
            scope("intent belongs to another institution or environment"),
        )?;
        ensure(
            it.vault_id == b.vault_id && it.chain_wallet_id == b.chain_wallet_id && it.chain_profile_id == b.chain_profile_id,
            scope("intent vault/wallet/chain profile does not match the envelope"),
        )?;
        ensure(
            cand.candidate_id == b.candidate_id && cand.candidate_revision == b.candidate_revision,
            scope("candidate id/revision does not match the envelope"),
        )?;
        ensure(
            cand.intent_id == b.intent_id && cand.operation_family_id == b.operation_family_id,
            scope("candidate intent/operation family does not match the envelope"),
        )?;
        ensure(cand.chain_profile_id == b.chain_profile_id, scope("candidate chain profile does not match the envelope"))?;
        ensure(cand.adapter_id == b.adapter_id && cand.adapter_version == b.adapter_version, scope("candidate adapter does not match the envelope"))?;
        ensure(b.participant_set.contains(&id.participant_id), scope("this signer is not in the envelope participant set"))?;
        let distinct: BTreeSet<&ParticipantId> = b.participant_set.iter().collect();
        ensure(distinct.len() == b.participant_set.len(), scope("participant set contains duplicates"))?;
        ensure(b.participant_set.iter().all(|p| m.key.participants.contains(p)), scope("participant set includes a non-member of the key"))?;
        ensure(b.participant_set.len() >= usize::from(m.key.threshold), scope("participant set is smaller than the key threshold"))?;

        // ---- 2. Chain profile and evidence -----------------------------------
        let mut profile: Option<&ChainProfile> = None;
        for p in &roots.chain_profiles {
            if p.chain_profile_id == b.chain_profile_id && p.hash()? == b.chain_profile_hash {
                profile = Some(p);
                break;
            }
        }
        let profile = profile.ok_or_else(|| OicError::scope("envelope chain profile id/hash is not an enrolled chain profile"))?;
        ensure(profile.adapter_id == b.adapter_id, scope("enrolled chain profile belongs to a different adapter"))?;
        check_evidence_scope(profile, &m.evidence, Some(now))?;
        let eh = evidence_hash(&m.evidence)?;
        ensure(
            eh == b.evidence_bundle_hash && eh == cand.evidence_bundle_hash,
            code(ErrorCode::StaleEvidence, "evidence bundle does not hash to the envelope/candidate evidence hash"),
        )?;

        // ---- 3. Adapter --------------------------------------------------------
        let adapter =
            self.adapters.get(&b.adapter_id).ok_or_else(|| OicError::unsupported(format!("no pinned adapter {} in this signer", b.adapter_id)))?;
        let manifest = adapter.manifest();
        ensure(
            manifest.adapter_id == b.adapter_id && manifest.adapter_version == b.adapter_version,
            code(ErrorCode::UnsupportedCapability, "pinned adapter version differs from the envelope"),
        )?;
        ensure(
            manifest.verifier_build_hash == b.verifier_build_hash,
            code(ErrorCode::UnsupportedCapability, "pinned verifier build differs from the envelope"),
        )?;
        let accepted = roots.accepted_verifier_builds.get(&b.adapter_id).is_some_and(|v| v.contains(&b.verifier_build_hash));
        ensure(accepted, code(ErrorCode::UnsupportedCapability, "verifier build hash is not accepted by the trust roots"))?;
        ensure(
            cand.native_unsigned_bytes == b.native_unsigned_bytes,
            code(ErrorCode::UnverifiableTransaction, "candidate native bytes differ from the envelope native bytes"),
        )?;

        // ---- 4. Policy ---------------------------------------------------------
        let pol = &m.policy;
        verify_policy_admin_signatures(pol, &roots.admin_keys, roots.admin_quorum)?;
        ensure(
            pol.institution_id == id.institution_id && pol.environment_id == id.environment_id,
            scope("policy belongs to another institution or environment"),
        )?;
        ensure(pol.policy_id == b.policy_id, scope("policy id does not match the envelope"))?;
        ensure(pol.policy_epoch == b.policy_epoch, || {
            OicError::new(
                ErrorCode::StalePolicy,
                format!("policy bundle epoch {} differs from envelope policy epoch {}", pol.policy_epoch, b.policy_epoch),
            )
        })?;
        ensure(pol.activation_epoch <= pol.policy_epoch, code(ErrorCode::StalePolicy, "policy is not active at its own epoch"))?;
        ensure(policy_hash(pol)? == b.policy_hash, scope("policy bundle does not hash to the envelope policy_hash"))?;
        ensure(pol.allowlist_version == b.allowlist_version, code(ErrorCode::StalePolicy, "allowlist version differs from the envelope"))?;
        let ih = intent_hash(it)?;
        ensure(ih == b.intent_hash, scope("intent does not hash to the envelope intent_hash"))?;

        // ---- 4b. Destination registry ------------------------------------------
        // The destination is an admin-quorum-signed object; the envelope commits
        // to its hash, so neither the coordinator nor a console can substitute an
        // address under a registered destination id (closes the gap noted in
        // RFC 0001 §3.3 for zero-approval automated rules).
        let d = &m.destination;
        verify_destination_admin_signatures(d, &roots.admin_keys, roots.admin_quorum)?;
        ensure(destination_hash(d)? == b.destination_hash, scope("destination does not hash to the envelope destination_hash"))?;
        ensure(d.network_id == w.network_id, scope("destination is registered on a different network than the wallet"))?;

        // ---- 5. Grants ---------------------------------------------------------
        let approvers = verify_grants(&b.approval_grants, enrolled, now)?;
        for g in &b.approval_grants {
            let gb = &g.body;
            ensure(gb.intent_id == b.intent_id && gb.intent_hash == ih, scope("grant is bound to a different intent"))?;
            ensure(gb.vault_id == b.vault_id, scope("grant is bound to a different vault"))?;
            ensure(gb.policy_id == b.policy_id && gb.policy_epoch == b.policy_epoch, scope("grant is bound to a different policy or policy epoch"))?;
            ensure(
                gb.institution_id == id.institution_id && gb.environment_id == id.environment_id,
                scope("grant belongs to another institution or environment"),
            )?;
        }

        // ---- 6. Native re-derivation -------------------------------------------
        let templates: Vec<&BoundedTransferTemplate> = b
            .approval_grants
            .iter()
            .filter_map(|g| match &g.body.scope {
                GrantScope::BoundedDirectTransfer { template } => Some(template),
                GrantScope::ExactCandidate { .. } => None,
            })
            .collect();
        let bounded = !b.approval_grants.is_empty()
            && templates.len() == b.approval_grants.len()
            && it.constraints.approval_mode == ApprovalMode::BoundedDirectTransfer;
        let target = if bounded {
            let first = templates[0];
            ensure(templates.iter().all(|t| *t == first), scope("bounded grants carry different templates"))?;
            ensure(
                first.destination_address == m.destination.address,
                scope("template destination address differs from the registered destination"),
            )?;
            ensure(first.chain_wallet_id == b.chain_wallet_id, scope("template is for a different chain wallet"))?;
            AuthorizationTarget::Template(first)
        } else {
            AuthorizationTarget::Intent(it)
        };
        let IntentOperation::AssetTransfer { destination_id, destination_version, .. } = &it.operation;
        ensure(
            &m.destination.destination_id == destination_id && m.destination.version == *destination_version,
            scope("destination id/version differs from the intent"),
        )?;
        let vctx = VerifyContext { profile, wallet: w, key: &m.key, asset: &m.asset, destination: &m.destination, evidence: &m.evidence };
        let verified = adapter.verify_candidate(cand, &target, &vctx)?;
        ensure(
            decoded_operation_hash(&verified.decoded)? == verified.decoded_operation_hash,
            code(ErrorCode::UnverifiableTransaction, "adapter decoded-operation hash is inconsistent"),
        )?;
        ensure(
            verified.decoded_operation_hash == b.decoded_operation_hash,
            code(ErrorCode::UnverifiableTransaction, "decoded operation differs from the envelope decoded_operation_hash"),
        )?;
        ensure(
            verified.signing_payloads == b.native_signing_payloads && verified.signing_payloads == cand.signing_payloads,
            code(ErrorCode::UnverifiableTransaction, "derived signing payloads differ from the envelope/candidate payloads"),
        )?;
        ensure(
            verified.verifier_build_hash == b.verifier_build_hash
                && verified.adapter_id == b.adapter_id
                && verified.adapter_version == b.adapter_version,
            code(ErrorCode::UnsupportedCapability, "verification ran under a different adapter build than the envelope names"),
        )?;
        ensure(verified.claims.resources == b.resource_reservations, scope("native resources differ from the envelope resource reservations"))?;
        for o in &verified.claims.asset_outflows {
            let max = b.maximum_asset_outflows.iter().find(|x| x.asset_id == o.asset_id);
            ensure(max.is_some_and(|x| o.amount_base_units <= x.amount_base_units), || {
                OicError::scope(format!("asset outflow for {} is not covered by the envelope maximum outflows", o.asset_id))
            })?;
        }
        for f in &verified.claims.native_fees {
            let max = b.maximum_native_fees.iter().find(|x| x.network_id == f.network_id);
            ensure(max.is_some_and(|x| f.amount_base_units <= x.amount_base_units), || {
                OicError::scope(format!("native fee on {} is not covered by the envelope maximum native fees", f.network_id))
            })?;
        }
        let ph = preview_hash(&b.candidate_id, b.candidate_revision, verified.decoded_operation_hash, eh);
        for g in &b.approval_grants {
            if let GrantScope::ExactCandidate { candidate_id, candidate_revision, preview_hash } = &g.body.scope {
                ensure(
                    candidate_id == &b.candidate_id && *candidate_revision == b.candidate_revision && *preview_hash == ph,
                    scope("exact-candidate grant does not cover this candidate preview"),
                )?;
            }
        }

        // ---- 7. Policy kernel (local rules) -------------------------------------
        let exposure = local_exposure_view(pol, it);
        let decision = evaluate(&PolicyInput {
            policy: pol,
            policy_hash: b.policy_hash,
            expected_policy_epoch: b.policy_epoch,
            intent: it,
            intent_hash: ih,
            verified: &verified,
            grants: &b.approval_grants,
            destination: &m.destination,
            asset: &m.asset,
            vault: v,
            evidence: &m.evidence,
            freshness: FreshnessContext { now },
            exposure: &exposure,
            candidate_id: &b.candidate_id,
            candidate_revision: b.candidate_revision,
            preview_hash: ph,
        });
        let rule_id = match &decision {
            Decision::Allow { rule_id } => rule_id.clone(),
            Decision::RequireApprovals { required, satisfied, .. } => {
                return Err(OicError::new(ErrorCode::ApprovalRequired, format!("policy requires {required} approvals; {satisfied} valid")));
            }
            Decision::Deny { reasons } => return Err(deny_error(reasons)),
        };

        // ---- 8. Authority reserved receipt ---------------------------------------
        let rid = reservation_id_for(&b.operation_family_id, &b.candidate_id, b.candidate_revision)?;
        ensure(b.budget_reservation_id == rid, scope("envelope reservation id is not the reservation for this candidate revision"))?;
        let ebh = envelope_body_hash(b)?;
        check_reservation(&ReservationCommitment { envelope_body_hash: ebh, intent_hash: ih, rule_id: &rule_id, claims_hash: claims_hash(&verified.claims)? })?;
        ensure(b.issuance_deadline >= now, code(ErrorCode::PolicyDenied, "issuance deadline has passed"))?;

        // ---- 9. Payload selection -------------------------------------------------
        let mine: Vec<&NativeSigningPayload> =
            verified.signing_payloads.iter().filter(|p| p.required_key_id == b.key_id && p.scheme_id == self.backend.scheme).collect();
        let payload = match mine.as_slice() {
            [one] => (*one).clone(),
            [] => return Err(OicError::unsupported("no signing payload for this key under the backend's scheme")),
            _ => return Err(OicError::unsupported("more than one signing payload for this key; multi-payload sessions are not supported")),
        };

        Ok(VerifiedEnvelope { envelope_body_hash: ebh, verified, decision, approvers, payload })
    }
}

/// Map kernel denial reasons to a stable error code: stale policy binding and
/// stale evidence keep their own codes; everything else is `PolicyDenied`.
fn deny_error(reasons: &[ReasonCode]) -> OicError {
    let c = if reasons.iter().any(|r| matches!(r, ReasonCode::PolicyEpochMismatch | ReasonCode::PolicyNotActive)) {
        ErrorCode::StalePolicy
    } else if reasons.iter().any(|r| matches!(r, ReasonCode::EvidenceStale | ReasonCode::EvidenceFromFuture)) {
        ErrorCode::StaleEvidence
    } else {
        ErrorCode::PolicyDenied
    };
    OicError::new(c, format!("policy kernel denied: {reasons:?}"))
}

/// The signer has no view of global exposure. It supplies zero prior
/// exposure for every rolling window any rule declares for the intent's
/// asset, so the kernel still checks that this one operation alone fits
/// every window; the cumulative check (I4) is the authority's, proven by its
/// receipt.
pub(crate) fn local_exposure_view(policy: &PolicyBundle, intent: &Intent) -> ExposureView {
    let IntentOperation::AssetTransfer { asset_id, .. } = &intent.operation;
    let windows: BTreeSet<u64> = policy.rules.iter().flat_map(|r| r.rolling_limits.iter().map(|l| l.window_seconds)).collect();
    ExposureView {
        windows: windows
            .into_iter()
            .map(|window_seconds| WindowExposure { asset_id: asset_id.clone(), window_seconds, settled: Amount::ZERO, outstanding: Amount::ZERO })
            .collect(),
    }
}
