use crate::{holdings, BlockSource, Reconciler};
use oic_authorization_state::{family_id_for, Authority, AuthorityStore};
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WorkflowContext {
    pub gas_rule_id: String,
    pub period: u64,
    pub allocated_refill: Amount,
    pub required_sweep_native: Amount,
    pub intents: Vec<Intent>,
}

impl Reconciler {
    /// Plan only from an accepted, controlled, supported deposit. All children
    /// are ordinary intents; gas funding never inherits the token's limits.
    pub fn plan_sweep(
        &self,
        source: &dyn BlockSource,
        movement: &MovementId,
        gas: &GasFundingRule,
        sweep: &SweepRule,
        destinations: &[CounterpartyDestination],
        proposer: CredentialId,
    ) -> OicResult<WorkflowRecord> {
        let profile = source.profile();
        let now = source.now();
        if gas.period_seconds == 0
            || gas.max_attempts == 0
            || sweep.max_attempts == 0
            || gas.minimum_balance > gas.target_balance
            || gas.target_balance < sweep.required_native_balance
        {
            return Err(OicError::invalid_request("invalid funding/sweep bounds"));
        }
        self.store.transact(|s| {
            let trigger = WorkflowTrigger::DepositAccepted { movement_id: movement.clone() };
            let hash = domain_hash(domains::WORKFLOW_TRIGGER, &trigger)?;
            let id = WorkflowId::unchecked(format!("workflow-{hash}"));
            if let Some(existing) = s.workflows.get(&id) { return Ok(existing.clone()); }
            let m = &s.movements.get(movement).ok_or_else(|| OicError::new(ErrorCode::NotFound, "workflow deposit"))?.movement;
            if m.acceptance != MovementAcceptance::Accepted || m.canonicality != Canonicality::Canonical || m.direction != MovementDirection::Inbound || m.chain_wallet_id.as_ref() != Some(&sweep.source_wallet_id) || m.asset_id.as_ref() != Some(&sweep.asset_id) || m.chain_profile_id != profile.chain_profile_id || gas.chain_profile_id != profile.chain_profile_id || sweep.chain_profile_id != profile.chain_profile_id {
                return Err(OicError::policy_denied("workflow requires a canonical accepted deposit for the exact wallet, asset and profile"));
            }
            if s.workflows.values().any(|w| !w.is_terminal() && w.steps.iter().any(|step| step.chain_wallet_id == sweep.source_wallet_id && step.asset_id == sweep.asset_id)) {
                return Err(OicError::resource_conflict("another sweep already owns this wallet's token balance"));
            }
            let wallet = s.enrollments.values().find(|e| e.address.chain_wallet_id.as_ref() == Some(&sweep.source_wallet_id)).ok_or_else(|| OicError::scope("sweep wallet"))?.clone();
            if wallet.address.custody != AddressCustody::Controlled || wallet.address.state != DepositAddressState::Active { return Err(OicError::policy_denied("watch-only/inactive address cannot automate transfers")); }
            let amount = holdings(s, &sweep.source_wallet_id, &sweep.asset_id, Amount::ZERO)?.available;
            if amount < sweep.threshold || amount < sweep.minimum_useful_value || amount.is_zero() { return Err(OicError::policy_denied("sweep below useful threshold")); }
            if s.assets[&sweep.asset_id].asset == AssetKind::Native { return Err(OicError::unsupported("deposit-triggered gas funding is only for token sweeps")); }
            let native = s.assets.get(&gas.native_asset_id).ok_or_else(|| OicError::scope("native asset not enrolled"))?;
            if native.network_id != profile.network_id || native.asset != AssetKind::Native || !wallet.address.supported_assets.contains(&gas.native_asset_id) { return Err(OicError::scope("gas rule native asset mismatch")); }
            let destination = destinations.iter().find(|d| d.destination_id == sweep.destination_id && d.version == sweep.destination_version).ok_or_else(|| OicError::scope("sweep destination/version"))?;
            if destination.network_id != profile.network_id || !destination.allowed_assets.is_empty() && !destination.allowed_assets.contains(&sweep.asset_id) { return Err(OicError::scope("sweep destination asset/network")); }
            let balance = source.balance(&source.finalized(), &wallet.address.address, &AssetKind::Native)?;
            let mut steps = Vec::new();
            let mut fee_caps = Vec::new();
            let mut refill = Amount::ZERO;
            if balance < gas.minimum_balance || balance < sweep.required_native_balance {
                let recipient = gas.recipients.iter().find(|r| r.chain_wallet_id == sweep.source_wallet_id).ok_or_else(|| OicError::policy_denied("gas recipient not approved"))?;
                let destination = destinations.iter().find(|d| d.destination_id == recipient.destination_id && d.version == recipient.destination_version).ok_or_else(|| OicError::scope("gas recipient destination/version"))?;
                if destination.network_id != profile.network_id || destination.address != wallet.address.address || !destination.allowed_assets.is_empty() && !destination.allowed_assets.contains(&gas.native_asset_id) { return Err(OicError::scope("gas may fund only the exact approved token wallet")); }
                let funding = s.enrollments.values().find(|e| e.address.chain_wallet_id.as_ref() == Some(&gas.source_wallet_id)).ok_or_else(|| OicError::scope("gas source wallet"))?;
                if funding.address.state != DepositAddressState::Active || funding.address.network_id != profile.network_id || funding.address.custody != AddressCustody::Controlled || gas.source_wallet_id == sweep.source_wallet_id { return Err(OicError::policy_denied("gas source is not an active controlled source on this network")); }
                refill = Amount(gas.target_balance.0 - balance.0);
                if refill > gas.max_refill_per_operation { return Err(OicError::budget("refill operation ceiling")); }
                let allocated = s.workflow_contexts.values().filter(|c| c.gas_rule_id == gas.rule_id && c.period == now.0 / gas.period_seconds).try_fold(0u128, |a, c| a.checked_add(c.allocated_refill.0)).ok_or_else(|| OicError::budget("refill period overflow"))?;
                if allocated.checked_add(refill.0).is_none_or(|a| a > gas.max_refill_per_period.0) { return Err(OicError::budget("refill period ceiling (including in-flight funding)")); }
                steps.push(WorkflowStep { step_index: 0, purpose: OperationPurpose::Fees, chain_wallet_id: gas.source_wallet_id.clone(), asset_id: gas.native_asset_id.clone(), amount_base_units: refill, destination_id: recipient.destination_id.clone(), destination_version: recipient.destination_version, depends_on: vec![], intent_id: None, operation_family_id: None, state: WorkflowStepState::Ready, attempts: 0, last_error: None });
                fee_caps.push(gas.max_native_fee);
            }
            let index = steps.len() as u16;
            steps.push(WorkflowStep { step_index: index, purpose: OperationPurpose::Internal, chain_wallet_id: sweep.source_wallet_id.clone(), asset_id: sweep.asset_id.clone(), amount_base_units: amount, destination_id: sweep.destination_id.clone(), destination_version: sweep.destination_version, depends_on: if index == 0 { vec![] } else { vec![0] }, intent_id: None, operation_family_id: None, state: if index == 0 { WorkflowStepState::Ready } else { WorkflowStepState::Blocked }, attempts: 0, last_error: None });
            fee_caps.push(sweep.max_native_fee);
            let max_native_spend = fee_caps.iter().try_fold(refill, |a, cap| a.checked_add(*cap)).ok_or_else(|| OicError::budget("workflow native ceiling overflow"))?;
            let intents = steps.iter().zip(fee_caps).map(|(step, cap)| Intent { schema_version: 1, intent_id: IntentId::unchecked(format!("wf-{}-{}", hash, step.step_index)), institution_id: self.institution.clone(), environment_id: self.environment.clone(), vault_id: s.enrollments.values().find(|e| e.address.chain_wallet_id.as_ref() == Some(&step.chain_wallet_id)).expect("enrolled source").address.vault_id.clone(), chain_wallet_id: step.chain_wallet_id.clone(), chain_profile_id: profile.chain_profile_id.clone(), operation: IntentOperation::AssetTransfer { asset_id: step.asset_id.clone(), amount_base_units: step.amount_base_units, destination_id: step.destination_id.clone(), destination_version: step.destination_version }, constraints: IntentConstraints { max_network_fee_base_units: cap, approval_mode: ApprovalMode::ExactCandidate, maximum_successful_payments: 1 }, purpose: step.purpose, external_reference: format!("workflow:{hash}"), proposer_credential_id: proposer.clone(), created_at: now }).collect();
            let record = WorkflowRecord { workflow_id: id.clone(), kind: WorkflowKind::Sweep, trigger_id: TriggerId::unchecked(hash.to_hex()), trigger, vault_id: wallet.address.vault_id, steps, state: WorkflowState::Pending, attempts: 0, max_attempts: gas.max_attempts.saturating_add(sweep.max_attempts), total_native_spent: Amount::ZERO, max_native_spend, created_at: now, updated_at: now };
            s.workflow_contexts.insert(id.clone(), WorkflowContext { gas_rule_id: gas.rule_id.clone(), period: now.0 / gas.period_seconds, allocated_refill: refill, required_sweep_native: sweep.required_native_balance, intents });
            s.workflows.insert(id.clone(), record.clone());
            self.event(s, LifecycleEventKind::WorkflowStateChanged { workflow_id: id, state: record.state.clone() }, now)?;
            Ok(record)
        })
    }

    /// Returns the same immutable child intent after a lost acknowledgement.
    /// Nothing signs here. The caller submits it through the ordinary intent
    /// API, builder, approval, reserve, signer, and broadcast path.
    pub fn next_intent<S: AuthorityStore>(
        &self,
        id: &WorkflowId,
        authority: &Authority<S>,
        source: &dyn BlockSource,
        estimated_fee: Amount,
    ) -> OicResult<Option<Intent>> {
        let authority_state = authority.store().read(Clone::clone)?;
        self.store.transact(|s| {
            let mut w = s.workflows.get(id).cloned().ok_or_else(|| OicError::new(ErrorCode::NotFound, "workflow"))?;
            if w.is_terminal() { return Ok(None); }
            let context = s.workflow_contexts[id].clone();
            let mut spend = Amount::ZERO;
            for entry in &authority_state.ledger {
                if authority_state.reservations.get(&entry.reservation_id).is_some_and(|r| w.steps.iter().any(|step| step.operation_family_id.as_ref() == Some(&r.reservation.operation_family_id))) {
                    let native = match &entry.budget { oic_authorization_state::BudgetKey::NativeFee { .. } => true, oic_authorization_state::BudgetKey::Asset { asset_id } => s.assets.get(asset_id).is_some_and(|a| a.asset == AssetKind::Native) };
                    if native { spend = spend.checked_add(entry.amount).ok_or_else(|| OicError::budget("workflow spend overflow"))?; }
                }
            }
            w.total_native_spent = spend;
            w.updated_at = source.now();
            for step in &mut w.steps {
                if let Some(family) = &step.operation_family_id {
                    if let Some(f) = authority_state.families.get(family) {
                        if f.lifecycle == LifecycleState::FinalizedSuccess { step.state = WorkflowStepState::Settled; }
                        if f.lifecycle == LifecycleState::FinalizedFailure {
                            step.state = WorkflowStepState::Failed;
                            w.state = WorkflowState::Failed { reason: "child finalized unsuccessfully; fees remain recorded, no automatic re-signing".into() };
                            s.workflows.insert(id.clone(), w.clone());
                            self.event(s, LifecycleEventKind::WorkflowStateChanged { workflow_id: id.clone(), state: w.state }, source.now())?;
                            return Ok(None);
                        }
                        if matches!(f.lifecycle, LifecycleState::IssuanceUnknown | LifecycleState::SubmissionUnknown) {
                            w.state = WorkflowState::Paused { reason: PauseReason::UncertainIssuance, detail: "signature may exist; inspect evidence, never create a replacement child".into() };
                            w.updated_at = source.now();
                            s.workflows.insert(id.clone(), w.clone());
                            self.event(s, LifecycleEventKind::WorkflowStateChanged { workflow_id: id.clone(), state: w.state }, source.now())?;
                            return Ok(None);
                        }
                    }
                }
            }
            let ready = w.steps.iter().find(|step| step.state != WorkflowStepState::Settled && step.depends_on.iter().all(|d| w.steps.iter().any(|t| t.step_index == *d && t.state == WorkflowStepState::Settled))).map(|s| s.step_index as usize);
            let result = if w.steps.iter().all(|s| s.state == WorkflowStepState::Settled) {
                w.state = WorkflowState::Complete; None
            } else if let Some(index) = ready {
                let intent = &context.intents[index];
                let cursor = s.cursors.get(&intent.chain_profile_id);
                let WorkflowTrigger::DepositAccepted { movement_id } = &w.trigger else { return Err(OicError::invalid_request("unsupported workflow trigger")); };
                let canonical = s.movements.get(movement_id).is_some_and(|m| m.movement.acceptance == MovementAcceptance::Accepted && m.movement.canonicality == Canonicality::Canonical);
                let active = s.enrollments.values().any(|e| e.address.chain_wallet_id.as_ref() == Some(&intent.chain_wallet_id) && e.address.state == DepositAddressState::Active && e.address.custody == AddressCustody::Controlled);
                if !canonical || !active || authority_state.freeze.blocking(&intent.vault_id).is_some() {
                    w.state = WorkflowState::Paused { reason: PauseReason::PolicyConflict, detail: "deposit is no longer canonical/accepted, source is inactive, or its vault is frozen".into() }; None
                } else if source.profile().chain_profile_id != intent.chain_profile_id || cursor.is_none_or(|c| c.last_scanned_hash.as_ref() != Some(&source.head().hash) || source.now().0.saturating_sub(c.updated_at.0) > source.profile().max_evidence_age_seconds) {
                    w.state = WorkflowState::Paused { reason: PauseReason::StaleEvidence, detail: "index must catch up to the current source head".into() }; None
                } else if estimated_fee > intent.constraints.max_network_fee_base_units {
                    w.state = WorkflowState::Paused { reason: PauseReason::FeeCeiling, detail: "fee estimate exceeds the configured ceiling".into() }; None
                } else if w.steps[index].intent_id.is_none() && !self.workflow_funds_available(s, &authority_state, &w.steps[index], context.required_sweep_native, intent.constraints.max_network_fee_base_units, source)? {
                    w.state = WorkflowState::Paused { reason: PauseReason::InsufficientFunds, detail: "finalized source holdings do not cover the child and its native ceiling after active reservations".into() }; None
                } else if w.steps[index].intent_id.is_none() && (w.attempts >= w.max_attempts || spend > w.max_native_spend) {
                    let case_id = CaseId::unchecked(format!("exhausted-{id}"));
                    self.case(s, DepositCase { case_id: case_id.clone(), kind: CaseKind::WorkflowExhausted, severity: CaseSeverity::Critical, chain_profile_id: intent.chain_profile_id.clone(), movement_id: None, checkpoint_id: None, workflow_id: Some(id.clone()), chain_wallet_id: Some(intent.chain_wallet_id.clone()), asset_id: None, amount_base_units: Some(spend), detail: "workflow spend or attempt ceiling reached".into(), owner: "treasury-operations".into(), state: CaseState::Open, opened_at: source.now() })?;
                    w.state = WorkflowState::Exhausted { case_id }; None
                } else {
                    let step = &mut w.steps[index];
                    if step.intent_id.is_none() {
                        step.intent_id = Some(intent.intent_id.clone());
                        step.operation_family_id = Some(family_id_for(&intent.intent_id)?);
                        step.attempts += 1;
                        w.attempts += 1;
                    }
                    step.state = WorkflowStepState::IntentCreated;
                    w.state = WorkflowState::Running;
                    Some(intent.clone())
                }
            } else { None };
            w.updated_at = source.now();
            if s.workflows.get(id) != Some(&w) { self.event(s, LifecycleEventKind::WorkflowStateChanged { workflow_id: id.clone(), state: w.state.clone() }, source.now())?; }
            s.workflows.insert(id.clone(), w);
            Ok(result)
        })
    }

    fn workflow_funds_available(
        &self,
        s: &crate::OperationsExport,
        authority: &oic_authorization_state::AuthorityState,
        step: &WorkflowStep,
        required_sweep_native: Amount,
        fee_cap: Amount,
        source: &dyn BlockSource,
    ) -> OicResult<bool> {
        let address = &s
            .enrollments
            .values()
            .find(|e| e.address.chain_wallet_id.as_ref() == Some(&step.chain_wallet_id))
            .ok_or_else(|| OicError::scope("workflow source not enrolled"))?
            .address;
        let asset = &s.assets[&step.asset_id];
        let native = s
            .assets
            .values()
            .find(|a| a.network_id == address.network_id && a.asset == AssetKind::Native)
            .ok_or_else(|| OicError::scope("workflow native asset not enrolled"))?;
        let mut token_reserved = Amount::ZERO;
        let mut native_reserved = Amount::ZERO;
        for r in authority
            .reservations
            .values()
            .filter(|r| r.state.is_active())
        {
            let claims = &r.reservation.claims;
            if !claims.resources.iter().any(|resource| match resource {
                NativeResource::EvmNonce {
                    network_id, sender, ..
                } => network_id == &address.network_id && sender == &address.address,
                NativeResource::SolanaBlockhash {
                    network_id,
                    fee_payer,
                    ..
                } => network_id == &address.network_id && fee_payer == &address.address,
                _ => false,
            }) {
                continue;
            }
            for outflow in &claims.asset_outflows {
                if outflow.asset_id == step.asset_id {
                    token_reserved = token_reserved
                        .checked_add(outflow.amount_base_units)
                        .ok_or_else(|| OicError::budget("workflow reservation overflow"))?;
                }
                if outflow.asset_id == native.asset_id {
                    native_reserved = native_reserved
                        .checked_add(outflow.amount_base_units)
                        .ok_or_else(|| OicError::budget("workflow reservation overflow"))?;
                }
            }
            for fee in &claims.native_fees {
                if fee.network_id == address.network_id {
                    native_reserved = native_reserved
                        .checked_add(fee.amount_base_units)
                        .ok_or_else(|| OicError::budget("workflow fee reservation overflow"))?;
                }
            }
        }
        let required = if asset.asset == AssetKind::Native {
            step.amount_base_units
                .checked_add(fee_cap)
                .ok_or_else(|| OicError::budget("workflow native requirement overflow"))?
        } else {
            required_sweep_native.max(fee_cap)
        };
        let state = source.finalized();
        let balance = source.balance(&state, &address.address, &AssetKind::Native)?;
        let native_available = balance.0.saturating_sub(native_reserved.0);
        let token_available = source
            .balance(&state, &address.address, &asset.asset)?
            .0
            .saturating_sub(token_reserved.0);
        Ok(native_available >= required.0 && token_available >= step.amount_base_units.0)
    }
}
