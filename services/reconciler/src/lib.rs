//! RFC 0002 operational records. This service observes and proposes; it has
//! no chain keys and no signing entry point. Availability is not policy allowance.
mod source;
mod store;
mod workflow;
pub use source::*;
pub use store::{Enrollment, OperationsExport, OperationsStore, verify_signature};

use ed25519_dalek::{Signer as _, SigningKey};
use oic_adapter_api::ChainProfile;
use oic_authorization_state::AuthorityStore;
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use std::{collections::BTreeMap, sync::Arc};
use store::{MovementRecord, StoredEffectKind};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JournalCorrection {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub case_id: CaseId,
    pub checkpoint_id: CheckpointId,
    pub chain_wallet_id: ChainWalletId,
    pub asset_id: AssetId,
    pub side: EntrySide,
    pub amount: Amount,
    pub reason: String,
}

impl JournalCorrection {
    /// Return the domain-separated hash administrators sign to authorize this
    /// exact correction. Canonical encoding errors propagate.
    pub fn hash(&self) -> OicResult<Hash32> {
        domain_hash(domains::CONFIG_PROPOSAL, &("journal-correction", self))
    }
}

pub struct Reconciler {
    pub(crate) store: Arc<OperationsStore>,
    pub(crate) institution: InstitutionId,
    pub(crate) environment: EnvironmentId,
    pub(crate) key_id: KeyId,
    pub(crate) key: SigningKey,
}

impl Reconciler {
    /// Verify stored journal, event, and checkpoint evidence with the service key,
    /// then bind an unscoped store to this institution and environment.
    /// Returns `ScopeMismatch` for a different stored binding; integrity,
    /// signature, and store errors propagate. The supplied key signs future
    /// operational events and checkpoints.
    pub fn open(
        store: Arc<OperationsStore>,
        institution: InstitutionId,
        environment: EnvironmentId,
        key_id: KeyId,
        key: SigningKey,
    ) -> OicResult<Self> {
        let data = store.export()?;
        data.verify(&key.verifying_key())?;
        store.transact(|s| {
            if s.institution_id
                .as_ref()
                .is_some_and(|id| id != &institution)
                || s.environment_id
                    .as_ref()
                    .is_some_and(|id| id != &environment)
            {
                return Err(OicError::scope(
                    "operations store belongs to another institution/environment",
                ));
            }
            s.institution_id = Some(institution.clone());
            s.environment_id = Some(environment.clone());
            Ok(())
        })?;
        Ok(Self {
            store,
            institution,
            environment,
            key_id,
            key,
        })
    }

    /// Return a snapshot of operational records, propagating store recovery errors.
    pub fn export(&self) -> OicResult<OperationsExport> {
        self.store.export()
    }

    /// Trusted domain-local enrollment, not a custody activation shortcut.
    /// Callers must commit independent key/recovery/monitoring evidence before
    /// `activate`. Signer verification remains the authority over chain output.
    ///
    /// New addresses start inactive. `dust_threshold` is in each supported
    /// asset's base units; inbound amounts strictly below it are quarantined at
    /// acceptance. Rejects scope or asset mismatches and conflicting address,
    /// wallet, or asset identities. Matching address, wallet, and supported-asset
    /// lists under an existing ID leave the enrollment unchanged. Store errors
    /// propagate.
    pub fn enroll(
        &self,
        mut address: DepositAddress,
        assets: &[Asset],
        dust_threshold: Amount,
    ) -> OicResult<()> {
        if address.institution_id != self.institution || address.environment_id != self.environment
        {
            return Err(OicError::scope("deposit enrollment scope"));
        }
        if (address.custody == AddressCustody::Controlled) != address.chain_wallet_id.is_some() {
            return Err(OicError::invalid_request(
                "watch-only addresses cannot claim a controlled wallet",
            ));
        }
        if assets.iter().any(|a| a.network_id != address.network_id)
            || address
                .supported_assets
                .iter()
                .any(|id| !assets.iter().any(|a| &a.asset_id == id))
        {
            return Err(OicError::scope("asset/network enrollment mismatch"));
        }
        address.state = DepositAddressState::Inactive;
        self.store.transact(|s| {
            if let Some(old) = s.enrollments.get(&address.deposit_address_id) {
                if old.address.address == address.address
                    && old.address.chain_wallet_id == address.chain_wallet_id
                    && old.address.supported_assets == address.supported_assets
                {
                    return Ok(());
                }
                return Err(OicError::resource_conflict(
                    "enrollment identity already exists",
                ));
            }
            if s.enrollments.values().any(|e| {
                e.address.network_id == address.network_id
                    && (e.address.address == address.address
                        || address.chain_wallet_id.is_some()
                            && e.address.chain_wallet_id == address.chain_wallet_id)
            }) {
                return Err(OicError::resource_conflict(
                    "address or wallet already enrolled",
                ));
            }
            for a in assets {
                if s.assets.get(&a.asset_id).is_some_and(|old| old != a)
                    || s.assets.values().any(|old| {
                        old.asset_id != a.asset_id
                            && old.network_id == a.network_id
                            && old.asset == a.asset
                    })
                {
                    return Err(OicError::resource_conflict(
                        "asset identity is immutable and unique",
                    ));
                }
                s.assets.insert(a.asset_id.clone(), a.clone());
            }
            let id = address.deposit_address_id.clone();
            s.enrollments.insert(
                id.clone(),
                Enrollment {
                    address,
                    activation: AddressActivation::new(id),
                    dust_threshold,
                },
            );
            Ok(())
        })
    }

    /// Persist activation evidence and return active only when every step is
    /// present; partial evidence leaves the address inactive. Supplied steps need
    /// nonzero commitments and nonempty actors. Returns `NotFound` for an unknown
    /// address, `InvalidRequest` for invalid steps, or `ResourceConflict` for a
    /// retired address or changes to completed activation. Store errors propagate.
    pub fn activate(&self, activation: AddressActivation) -> OicResult<DepositAddressState> {
        self.store.transact(|s| {
            let e = s
                .enrollments
                .get_mut(&activation.deposit_address_id)
                .ok_or_else(|| OicError::new(ErrorCode::NotFound, "deposit address"))?;
            if e.address.state == DepositAddressState::Retired {
                return Err(OicError::resource_conflict("retired address"));
            }
            if [
                &activation.public_key_agreement,
                &activation.asset_network_configuration,
                &activation.recovery_metadata,
                &activation.monitoring_registration,
            ]
            .into_iter()
            .flatten()
            .any(|step| step.commitment == Hash32::ZERO || step.actor.is_empty())
            {
                return Err(OicError::invalid_request(
                    "activation needs nonempty commitments and actors",
                ));
            }
            if e.activation.is_complete() && e.activation != activation {
                return Err(OicError::resource_conflict(
                    "activation commitments are immutable",
                ));
            }
            e.address.state = if activation.is_complete() {
                DepositAddressState::Active
            } else {
                DepositAddressState::Inactive
            };
            e.activation = activation;
            Ok(e.address.state)
        })
    }

    /// Mark an enrolled address retired at `at` and retain its monitoring history.
    /// Returns `NotFound` for an unknown address; store errors propagate. Later
    /// retirement calls replace the retirement timestamp.
    pub fn retire(&self, id: &DepositAddressId, at: UnixSeconds) -> OicResult<()> {
        self.store.transact(|s| {
            let e = s
                .enrollments
                .get_mut(id)
                .ok_or_else(|| OicError::new(ErrorCode::NotFound, "deposit address"))?;
            e.address.state = DepositAddressState::Retired;
            e.address.retired_at = Some(at);
            Ok(())
        })
    }

    /// Bind a transaction to an operation before accepting its indexed effects.
    /// Repeating the same binding is allowed. Returns `ResourceConflict` if the
    /// transaction or an accepted movement is already associated differently;
    /// store errors propagate.
    pub fn link_operation(&self, tx: ChainTxId, family: OperationFamilyId) -> OicResult<()> {
        self.store.transact(|s| {
            if s.operations.get(&tx).is_some_and(|f| f != &family) {
                return Err(OicError::resource_conflict(
                    "transaction already bound to another operation",
                ));
            }
            if s.movements.values().any(|m| {
                m.movement.tx_id == tx
                    && m.movement.acceptance == MovementAcceptance::Accepted
                    && m.movement.operation_family_id.as_ref() != Some(&family)
            }) {
                return Err(OicError::resource_conflict(
                    "link issued operation before indexing finality",
                ));
            }
            s.operations.insert(tx, family);
            Ok(())
        })
    }

    /// Scan all missed heights in one atomic commit. Re-check the source's
    /// head before commit, so a moving fork cannot splice two histories.
    ///
    /// Deduplicates effects, reverses removed canonical movements, and accepts or
    /// quarantines observations through source finality. New address enrollments
    /// trigger a historical rescan. Returns the committed cursor; discontinuous
    /// or changing history returns `StaleEvidence`. Source, effect-validation,
    /// and hashing errors abort the scan. Store errors propagate and can leave
    /// persistence uncertain.
    pub fn sync(&self, source: &dyn BlockSource) -> OicResult<IndexCursor> {
        self.sync_from(source, None)
    }

    /// Catch up to the source head, optionally rescanning from an earlier height.
    /// Reconcile forks and finality in the same store transaction as the cursor;
    /// propagate scan or persistence errors.
    fn sync_from(
        &self,
        source: &dyn BlockSource,
        backfill_from: Option<u64>,
    ) -> OicResult<IndexCursor> {
        let profile = source.profile();
        let head = source.head();
        let finality = source.finalized();
        let now = source.now();
        self.store.transact(|s| {
            let previous = s
                .scanned_blocks
                .get(&profile.chain_profile_id)
                .cloned()
                .unwrap_or_default();
            let mut fork = None;
            for (height, hash) in &previous {
                if *height > head.height || source.block(*height)?.state.hash != *hash {
                    fork = Some(*height);
                    break;
                }
            }
            if let Some(height) = fork {
                let ids: Vec<_> = s
                    .movements
                    .values()
                    .filter(|r| {
                        r.movement.chain_profile_id == profile.chain_profile_id
                            && r.movement.observed_state.height >= height
                            && r.movement.canonicality == Canonicality::Canonical
                    })
                    .map(|r| r.movement.movement_id.clone())
                    .collect();
                for id in ids {
                    self.reverse(s, &id, &head, now)?;
                }
                s.scanned_blocks
                    .entry(profile.chain_profile_id.clone())
                    .or_default()
                    .retain(|h, _| *h < height);
            }
            let monitored = s
                .enrollments
                .values()
                .filter(|e| e.address.chain_profile_id == profile.chain_profile_id)
                .count() as u64;
            let start = if s
                .cursors
                .get(&profile.chain_profile_id)
                .is_some_and(|c| c.monitored_addresses != monitored)
            {
                0
            } else {
                s.scanned_blocks
                    .get(&profile.chain_profile_id)
                    .and_then(|b| b.last_key_value())
                    .map(|(h, _)| h + 1)
                    .unwrap_or(0)
            };
            let start = backfill_from.map(|from| from.min(start)).unwrap_or(start);
            for height in start..=head.height {
                let block = source.block(height)?;
                if height > 0
                    && s.scanned_blocks
                        .get(&profile.chain_profile_id)
                        .and_then(|b| b.get(&(height - 1)))
                        != Some(&block.parent_hash)
                {
                    return Err(OicError::stale_evidence(
                        "noncontiguous chain; backfill required",
                    ));
                }
                for effect in block.effects {
                    self.observe(s, &profile, &block.state, effect, source.source_id(), now)?;
                }
                s.scanned_blocks
                    .entry(profile.chain_profile_id.clone())
                    .or_default()
                    .insert(height, block.state.hash);
            }
            let ids: Vec<_> = s
                .movements
                .values()
                .filter(|r| {
                    r.movement.chain_profile_id == profile.chain_profile_id
                        && r.movement.canonicality == Canonicality::Canonical
                        && r.movement.acceptance == MovementAcceptance::Observed
                        && r.movement.observed_state.height <= finality.height
                })
                .map(|r| r.movement.movement_id.clone())
                .collect();
            for id in ids {
                self.accept(s, &id, now)?;
            }
            if source.head() != head || source.finalized() != finality {
                return Err(OicError::stale_evidence("chain changed during scan; retry"));
            }
            let cursor = IndexCursor {
                cursor_id: CursorId::unchecked(profile.chain_profile_id.to_string()),
                chain_profile_id: profile.chain_profile_id.clone(),
                network_id: profile.network_id.clone(),
                last_scanned_height: Some(head.height),
                last_scanned_hash: Some(head.hash.clone()),
                finalized_height: finality.height,
                monitored_addresses: s
                    .enrollments
                    .values()
                    .filter(|e| e.address.chain_profile_id == profile.chain_profile_id)
                    .count() as u64,
                updated_at: now,
            };
            s.cursors
                .insert(profile.chain_profile_id.clone(), cursor.clone());
            Ok(cursor)
        })
    }

    /// A durable job records uncertainty before attempting the catch-up scan.
    ///
    /// `from` and `to` are inclusive heights or slots used for the job's movement
    /// count; the rescan can begin earlier and continues through the current head.
    /// An invalid range returns `InvalidRequest`. Scan errors become a returned
    /// job with `Failed` state; job persistence errors still propagate.
    pub fn backfill(&self, source: &dyn BlockSource, from: u64, to: u64) -> OicResult<BackfillJob> {
        if from > to || to > source.head().height {
            return Err(OicError::invalid_request("backfill range"));
        }
        let id = self.store.transact(|s| {
            let id = BackfillJobId::unchecked(format!("backfill-{}", s.backfills.len() + 1));
            s.backfills.push(BackfillJob {
                job_id: id.clone(),
                chain_profile_id: source.profile().chain_profile_id,
                from_height: from,
                to_height: to,
                reason: "operator catch-up".into(),
                state: BackfillState::Running { next_height: from },
                created_at: source.now(),
                updated_at: source.now(),
            });
            Ok(id)
        })?;
        let result = self.sync_from(source, Some(from));
        self.store.transact(|s| {
            let count = s
                .movements
                .values()
                .filter(|m| {
                    m.movement.chain_profile_id == source.profile().chain_profile_id
                        && (from..=to).contains(&m.movement.observed_state.height)
                        && m.movement.canonicality == Canonicality::Canonical
                })
                .count() as u64;
            let job = s
                .backfills
                .iter_mut()
                .find(|j| j.job_id == id)
                .expect("job committed");
            job.state = match &result {
                Ok(_) => BackfillState::Complete {
                    movements_found: count,
                },
                Err(e) => BackfillState::Failed {
                    reason: e.to_string(),
                },
            };
            job.updated_at = source.now();
            Ok(job.clone())
        })
    }

    /// Record an enrolled address's effect once under its network/transaction/leg
    /// identity and append an observation event. Ignore unmonitored addresses;
    /// reject conflicting canonical effects with `UnverifiableTransaction`.
    /// Hashing and event errors propagate to the surrounding transaction.
    fn observe(
        &self,
        s: &mut OperationsExport,
        profile: &ChainProfile,
        state: &StateReference,
        effect: ChainEffect,
        source: EvidenceSourceId,
        now: UnixSeconds,
    ) -> OicResult<()> {
        let Some(enrollment) = s
            .enrollments
            .values()
            .find(|e| {
                e.address.chain_profile_id == profile.chain_profile_id
                    && e.address.network_id == profile.network_id
                    && e.address.address == effect.address
            })
            .cloned()
        else {
            return Ok(());
        };
        let id = MovementId::unchecked(
            domain_hash(
                domains::OBSERVED_MOVEMENT,
                &(
                    profile.network_id.clone(),
                    effect.tx_id.clone(),
                    effect.index,
                ),
            )?
            .to_hex(),
        );
        if let Some(old) = s.movements.get(&id) {
            if old.movement.canonicality == Canonicality::Canonical {
                if old.movement.address != effect.address
                    || old.movement.asset != effect.asset
                    || old.movement.direction != effect.direction
                    || old.movement.amount_base_units != effect.amount
                    || old.movement.observed_state.hash != state.hash
                {
                    return Err(OicError::unverifiable(
                        "conflicting effect under the same transaction identity",
                    ));
                }
                return Ok(());
            }
        }
        let asset_id = s
            .assets
            .values()
            .find(|a| a.network_id == profile.network_id && a.asset == effect.asset)
            .map(|a| a.asset_id.clone());
        let movement = ObservedMovement {
            movement_id: id.clone(),
            chain_profile_id: profile.chain_profile_id.clone(),
            network_id: profile.network_id.clone(),
            deposit_address_id: Some(enrollment.address.deposit_address_id),
            chain_wallet_id: enrollment.address.chain_wallet_id,
            address: effect.address,
            direction: effect.direction,
            asset: effect.asset,
            asset_id,
            amount_base_units: effect.amount,
            counterparty: effect.counterparty,
            tx_id: effect.tx_id.clone(),
            effect_index: effect.index,
            mechanism: effect.mechanism,
            observed_state: state.clone(),
            canonicality: Canonicality::Canonical,
            acceptance: MovementAcceptance::Observed,
            operation_family_id: s.operations.get(&effect.tx_id).cloned(),
            sources: vec![source],
            observed_at: now,
            updated_at: now,
        };
        s.movements.insert(
            id.clone(),
            MovementRecord {
                movement,
                kind: effect.kind.into(),
                entries: vec![],
            },
        );
        self.event(
            s,
            LifecycleEventKind::MovementObserved {
                movement_id: id,
                acceptance: MovementAcceptance::Observed,
            },
            now,
        )
    }

    /// Accept a finalized observation or quarantine it with a case. Accepted
    /// controlled-wallet movements post journal entries; watch-only movements do
    /// not. Append the resulting acceptance event; posting errors propagate.
    fn accept(&self, s: &mut OperationsExport, id: &MovementId, now: UnixSeconds) -> OicResult<()> {
        let r = s.movements.get(id).expect("movement").clone();
        let m = &r.movement;
        let e = &s.enrollments[m.deposit_address_id.as_ref().expect("enrolled")];
        let case = if m.asset_id.is_none()
            || !e
                .address
                .supported_assets
                .contains(m.asset_id.as_ref().expect("checked below"))
        {
            Some(CaseKind::UnknownAsset)
        } else if s.assets[m.asset_id.as_ref().expect("asset")].behavior
            != AssetBehaviorProfile::Standard
        {
            Some(CaseKind::NonstandardAsset)
        } else if e.address.state == DepositAddressState::Retired {
            Some(CaseKind::RetiredAddress)
        } else if e.address.state != DepositAddressState::Active {
            Some(CaseKind::InactiveAddress)
        } else if e.address.routing_reference.is_some() {
            Some(CaseKind::MissingRoutingReference)
        } else if m.direction == MovementDirection::Inbound
            && m.amount_base_units < e.dust_threshold
        {
            Some(CaseKind::Dust)
        } else {
            None
        };
        let acceptance = if let Some(kind) = case {
            self.case(
                s,
                DepositCase {
                    case_id: CaseId::unchecked(format!("movement-{id}")),
                    kind,
                    severity: CaseSeverity::Warning,
                    chain_profile_id: m.chain_profile_id.clone(),
                    movement_id: Some(id.clone()),
                    checkpoint_id: None,
                    workflow_id: None,
                    chain_wallet_id: m.chain_wallet_id.clone(),
                    asset_id: m.asset_id.clone(),
                    amount_base_units: Some(m.amount_base_units),
                    detail: "movement quarantined; no automatic funding or credit".into(),
                    owner: "treasury-operations".into(),
                    state: CaseState::Open,
                    opened_at: now,
                },
            )?;
            MovementAcceptance::Quarantined
        } else {
            if let Some(wallet) = &m.chain_wallet_id {
                let asset = m.asset_id.clone().expect("asset accepted");
                let family = m
                    .operation_family_id
                    .clone()
                    .unwrap_or_else(|| OperationFamilyId::unchecked(format!("external-{}", id)));
                let kind = match &r.kind {
                    StoredEffectKind::Fee => JournalEntryKind::NetworkFee {
                        operation_family_id: family,
                        tx_id: m.tx_id.clone(),
                    },
                    StoredEffectKind::AccountFunding { account } => {
                        JournalEntryKind::AccountFunding {
                            operation_family_id: family,
                            tx_id: m.tx_id.clone(),
                            funded_account: account.clone(),
                        }
                    }
                    StoredEffectKind::Transfer => {
                        let other = s.movements.values().find(|r| {
                            r.kind == StoredEffectKind::Transfer
                                && r.movement.tx_id == m.tx_id
                                && r.movement.chain_profile_id == m.chain_profile_id
                                && r.movement.asset == m.asset
                                && r.movement.direction != m.direction
                                && r.movement.amount_base_units == m.amount_base_units
                                && (m.counterparty.0.is_empty()
                                    || m.counterparty == r.movement.address)
                                && (r.movement.counterparty.0.is_empty()
                                    || r.movement.counterparty == m.address)
                                && r.movement.canonicality == Canonicality::Canonical
                                && r.movement.chain_wallet_id.is_some()
                                && r.movement.chain_wallet_id != m.chain_wallet_id
                        });
                        if let Some(other) = other.filter(|_| m.operation_family_id.is_some()) {
                            JournalEntryKind::InternalTransfer {
                                operation_family_id: family,
                                leg: if m.direction == MovementDirection::Outbound {
                                    InternalLeg::Source
                                } else {
                                    InternalLeg::Destination
                                },
                                counterparty_wallet_id: other
                                    .movement
                                    .chain_wallet_id
                                    .clone()
                                    .expect("wallet"),
                                movement_id: id.clone(),
                            }
                        } else if m.direction == MovementDirection::Inbound {
                            JournalEntryKind::AcceptedReceipt {
                                movement_id: id.clone(),
                            }
                        } else {
                            JournalEntryKind::OutgoingMovement {
                                operation_family_id: family,
                                movement_id: id.clone(),
                            }
                        }
                    }
                };
                let entry = self.post(
                    s,
                    wallet.clone(),
                    asset,
                    if m.direction == MovementDirection::Inbound {
                        EntrySide::Credit
                    } else {
                        EntrySide::Debit
                    },
                    m.amount_base_units,
                    kind,
                    &m.observed_state,
                    now,
                )?;
                s.movements
                    .get_mut(id)
                    .expect("movement")
                    .entries
                    .push(entry);
            }
            MovementAcceptance::Accepted
        };
        let record = s.movements.get_mut(id).expect("movement");
        record.movement.acceptance = acceptance;
        record.movement.updated_at = now;
        self.event(
            s,
            LifecycleEventKind::MovementObserved {
                movement_id: id.clone(),
                acceptance,
            },
            now,
        )
    }

    /// Reverse a removed canonical movement with compensating journal entries,
    /// a reorg case, and an event, retaining original postings. Posting and event
    /// errors propagate to the surrounding transaction.
    fn reverse(
        &self,
        s: &mut OperationsExport,
        id: &MovementId,
        head: &StateReference,
        now: UnixSeconds,
    ) -> OicResult<()> {
        let record = s.movements.get(id).expect("movement").clone();
        for entry_id in record.entries {
            let entry = s
                .journal
                .iter()
                .find(|e| e.body.entry_id == entry_id)
                .expect("entry")
                .body
                .clone();
            self.post(
                s,
                entry.chain_wallet_id,
                entry.asset_id,
                if entry.side == EntrySide::Credit {
                    EntrySide::Debit
                } else {
                    EntrySide::Credit
                },
                entry.amount_base_units,
                JournalEntryKind::Reversal {
                    reverses: entry.entry_id,
                    reason: "canonical block replaced".into(),
                },
                head,
                now,
            )?;
        }
        let m = &record.movement;
        self.case(
            s,
            DepositCase {
                case_id: CaseId::unchecked(format!("reorg-{}-{}", id, s.journal.len())),
                kind: CaseKind::Reorged,
                severity: CaseSeverity::Warning,
                chain_profile_id: m.chain_profile_id.clone(),
                movement_id: Some(id.clone()),
                checkpoint_id: None,
                workflow_id: None,
                chain_wallet_id: m.chain_wallet_id.clone(),
                asset_id: m.asset_id.clone(),
                amount_base_units: Some(m.amount_base_units),
                detail: "canonical effect removed; prior postings reversed, not deleted".into(),
                owner: "treasury-operations".into(),
                state: CaseState::Open,
                opened_at: now,
            },
        )?;
        let r = s.movements.get_mut(id).expect("movement");
        r.movement.canonicality = Canonicality::Reorged { at: head.clone() };
        r.movement.acceptance = MovementAcceptance::Reversed;
        r.movement.updated_at = now;
        r.entries.clear();
        self.event(
            s,
            LifecycleEventKind::MovementObserved {
                movement_id: id.clone(),
                acceptance: MovementAcceptance::Reversed,
            },
            now,
        )
    }

    /// Append a hash-linked journal entry for an enrolled wallet and return its ID.
    /// Amounts are asset base units. An unenrolled wallet returns `ScopeMismatch`;
    /// hashing errors propagate. The caller commits the containing snapshot.
    pub(crate) fn post(
        &self,
        s: &mut OperationsExport,
        wallet: ChainWalletId,
        asset: AssetId,
        side: EntrySide,
        amount: Amount,
        kind: JournalEntryKind,
        state: &StateReference,
        now: UnixSeconds,
    ) -> OicResult<JournalEntryId> {
        let e = s
            .enrollments
            .values()
            .find(|e| e.address.chain_wallet_id.as_ref() == Some(&wallet))
            .ok_or_else(|| OicError::scope("journal wallet not enrolled"))?;
        let seq = s.journal.len() as u64 + 1;
        let body = JournalEntryBody {
            entry_id: JournalEntryId::unchecked(format!("journal-{seq}")),
            sequence: seq,
            previous_entry_hash: s
                .journal
                .last()
                .map(|e| e.entry_hash)
                .unwrap_or(Hash32::ZERO),
            at: now,
            institution_id: self.institution.clone(),
            environment_id: self.environment.clone(),
            vault_id: e.address.vault_id.clone(),
            chain_wallet_id: wallet,
            asset_id: asset,
            side,
            amount_base_units: amount,
            kind,
            posted_at_state: state.clone(),
        };
        let id = body.entry_id.clone();
        s.journal.push(JournalEntry {
            entry_hash: domain_hash(domains::JOURNAL, &body)?,
            body,
        });
        Ok(id)
    }

    /// Append a sequenced, service-signed lifecycle event to the supplied snapshot.
    /// Hashing errors propagate; the caller is responsible for committing it.
    pub(crate) fn event(
        &self,
        s: &mut OperationsExport,
        kind: LifecycleEventKind,
        at: UnixSeconds,
    ) -> OicResult<()> {
        let seq = s.events.len() as u64 + 1;
        let body = LifecycleEventBody {
            event_id: EventId::unchecked(format!("event-{seq}")),
            sequence: seq,
            institution_id: self.institution.clone(),
            environment_id: self.environment.clone(),
            at,
            kind,
        };
        s.events.push(LifecycleEvent {
            signature: self.sign(domain_hash(domains::WEBHOOK, &body)?),
            body,
            signing_key_id: self.key_id.clone(),
        });
        Ok(())
    }

    /// Insert a case and its signed opening event, leaving an existing case ID
    /// unchanged. Event errors propagate to the surrounding transaction.
    pub(crate) fn case(&self, s: &mut OperationsExport, case: DepositCase) -> OicResult<()> {
        if s.cases.contains_key(&case.case_id) {
            return Ok(());
        }
        self.event(
            s,
            LifecycleEventKind::CaseOpened {
                case_id: case.case_id.clone(),
                kind: case.kind,
            },
            case.opened_at,
        )?;
        s.cases.insert(case.case_id.clone(), case);
        Ok(())
    }

    /// Sign the supplied hash bytes with the reconciler's Ed25519 service key.
    pub(crate) fn sign(&self, hash: Hash32) -> SignatureBytes {
        SignatureBytes {
            scheme: SchemeId::Ed25519Pure,
            bytes: Bytes(self.key.sign(&hash.0).to_bytes().to_vec()),
        }
    }

    /// Publish an operational observation, not an authorization receipt. The
    /// caller supplies an authority/coordinator-observed state. Repeated ACKs
    /// do not append another event; issuance safety never depends on this log.
    pub fn record_operation_state(
        &self,
        intent: &Intent,
        candidate: &Candidate,
        to: LifecycleState,
        tx_id: Option<ChainTxId>,
        at: UnixSeconds,
    ) -> OicResult<()> {
        if intent.institution_id != self.institution
            || intent.environment_id != self.environment
            || candidate.operation_family_id
                != oic_authorization_state::family_id_for(&intent.intent_id)?
        {
            return Err(OicError::scope("operation event scope"));
        }
        self.store.transact(|s| {
            let last = s.events.iter().rev().find_map(|e| match &e.body.kind {
                LifecycleEventKind::OperationStateChanged {
                    operation_family_id,
                    to,
                    tx_id,
                    candidate_id,
                    candidate_revision,
                    ..
                } if operation_family_id == &candidate.operation_family_id => Some((
                    *to,
                    tx_id.clone(),
                    candidate_id.clone(),
                    *candidate_revision,
                )),
                _ => None,
            });
            if last.as_ref()
                == Some(&(
                    to,
                    tx_id.clone(),
                    Some(candidate.candidate_id.clone()),
                    Some(candidate.candidate_revision),
                ))
            {
                return Ok(());
            }
            self.event(
                s,
                LifecycleEventKind::OperationStateChanged {
                    intent_id: intent.intent_id.clone(),
                    operation_family_id: candidate.operation_family_id.clone(),
                    candidate_id: Some(candidate.candidate_id.clone()),
                    candidate_revision: Some(candidate.candidate_revision),
                    from: last.map(|v| v.0),
                    to,
                    tx_id,
                },
                at,
            )
        })
    }

    /// Return at most `limit` signed events in sequence order, strictly after
    /// `sequence`. Zero starts from the first event. Limits outside 1 through
    /// 1000 return `InvalidRequest`; store recovery errors propagate.
    pub fn events_since(&self, sequence: u64, limit: usize) -> OicResult<Vec<LifecycleEvent>> {
        if limit == 0 || limit > 1000 {
            return Err(OicError::invalid_request("event limit must be 1..1000"));
        }
        Ok(self
            .export()?
            .events
            .into_iter()
            .filter(|e| e.body.sequence > sequence)
            .take(limit)
            .collect())
    }

    /// Return journal-settled and pending inbound holdings in asset base units.
    /// `reserved` is supplied by the caller and reduces available holdings with
    /// a floor of zero; pending inbound does not increase availability. Unknown
    /// wallet/asset pairs have zero journal holdings. Arithmetic overflow returns
    /// `UnverifiableTransaction`, negative settled holdings return
    /// `RecoveryRequired`, and store recovery errors propagate.
    pub fn holdings(
        &self,
        wallet: &ChainWalletId,
        asset: &AssetId,
        reserved: Amount,
    ) -> OicResult<Holdings> {
        holdings(&self.export()?, wallet, asset, reserved)
    }

    /// Explicit, scoped correction. The admin quorum signs the explanation
    /// and exact entry; a reconciliation difference never balances itself.
    ///
    /// Post the exact signed checkpoint difference, resolve its open case, and
    /// publish a resolution event atomically, returning the new journal entry ID.
    /// Invalid or insufficient administrator signatures return `InvalidSignature`;
    /// mismatched correction scope or amounts return `ScopeMismatch`. Missing
    /// cases/checkpoints return `NotFound`, resolved cases return `ResourceConflict`,
    /// and an advanced journal or checkpoint returns `StaleEvidence`. Hashing,
    /// journal posting, and store errors propagate.
    pub fn resolve_difference<S: AuthorityStore>(
        &self,
        correction: &JournalCorrection,
        signatures: &[CredentialSignature],
        authority: &oic_authorization_state::Authority<S>,
        now: UnixSeconds,
    ) -> OicResult<JournalEntryId> {
        let config = authority.config();
        if correction.institution_id != self.institution
            || correction.environment_id != self.environment
            || config.institution_id != self.institution
            || config.environment_id != self.environment
            || correction.reason.trim().is_empty()
            || correction.amount.is_zero()
        {
            return Err(OicError::scope("journal correction scope or explanation"));
        }
        let hash = correction.hash()?;
        let mut approved = std::collections::BTreeSet::new();
        for signature in signatures {
            let key = config
                .admin_keys
                .iter()
                .find(|(id, _)| id == &signature.credential_id)
                .ok_or_else(|| OicError::invalid_signature("unknown correction administrator"))?;
            verify_signature(&key.1, hash, &signature.signature)?;
            approved.insert(signature.credential_id.clone());
        }
        if approved.len() < config.admin_quorum as usize || approved.is_empty() {
            return Err(OicError::invalid_signature(
                "journal correction needs the administrative quorum",
            ));
        }
        self.store.transact(|s| {
            let case = s
                .cases
                .get(&correction.case_id)
                .ok_or_else(|| OicError::new(ErrorCode::NotFound, "correction case"))?;
            if case.kind != CaseKind::ReconciliationDifference
                || case.checkpoint_id.as_ref() != Some(&correction.checkpoint_id)
                || case.chain_wallet_id.as_ref() != Some(&correction.chain_wallet_id)
                || case.asset_id.as_ref() != Some(&correction.asset_id)
            {
                return Err(OicError::scope("correction does not match case"));
            }
            if !matches!(case.state, CaseState::Open) {
                return Err(OicError::resource_conflict("case already resolved"));
            }
            let checkpoint = s
                .checkpoints
                .iter()
                .find(|c| c.body.checkpoint_id == correction.checkpoint_id)
                .ok_or_else(|| OicError::new(ErrorCode::NotFound, "correction checkpoint"))?;
            if checkpoint.body.journal_sequence != s.journal.len() as u64
                || s.checkpoints
                    .iter()
                    .rev()
                    .find(|c| c.body.chain_profile_id == checkpoint.body.chain_profile_id)
                    .map(|c| &c.body.checkpoint_id)
                    != Some(&correction.checkpoint_id)
            {
                return Err(OicError::stale_evidence(
                    "journal/checkpoint advanced; reconcile and authorize a fresh correction",
                ));
            }
            let balance = checkpoint
                .body
                .balances
                .iter()
                .find(|b| {
                    b.chain_wallet_id == correction.chain_wallet_id
                        && b.asset_id == correction.asset_id
                })
                .ok_or_else(|| OicError::scope("checkpoint balance"))?;
            let (negative, magnitude) = balance.difference();
            if magnitude != correction.amount
                || correction.side
                    != if negative {
                        EntrySide::Debit
                    } else {
                        EntrySide::Credit
                    }
            {
                return Err(OicError::scope(
                    "correction must explain the exact checkpoint difference",
                ));
            }
            let state = checkpoint.body.state.clone();
            let entry = self.post(
                s,
                correction.chain_wallet_id.clone(),
                correction.asset_id.clone(),
                correction.side,
                correction.amount,
                JournalEntryKind::ExternalAdjustment {
                    case_id: correction.case_id.clone(),
                    authorized_by: approved.iter().cloned().collect(),
                    reason: correction.reason.clone(),
                },
                &state,
                now,
            )?;
            s.cases.get_mut(&correction.case_id).expect("case").state = CaseState::Resolved {
                resolution: correction.reason.clone(),
                resolved_by: approved.iter().cloned().collect(),
                resolved_at: now,
                journal_entry_id: Some(entry.clone()),
            };
            self.event(
                s,
                LifecycleEventKind::CaseResolved {
                    case_id: correction.case_id.clone(),
                },
                now,
            )?;
            Ok(entry)
        })
    }

    /// Compare only a fully indexed finalized checkpoint. Independent balance
    /// reads cannot silently create journal adjustments (C19).
    ///
    /// Persist and return a signed balance checkpoint, opening cases for
    /// differences. `reserved` supplies wallet/asset reservations in base units;
    /// missing pairs use zero. Returns `StaleEvidence` when indexing is behind
    /// finality or finality changes during comparison. Balance reads, holdings
    /// calculation, hashing, and store errors propagate.
    pub fn reconcile(
        &self,
        source: &dyn BlockSource,
        reserved: &BTreeMap<(ChainWalletId, AssetId), Amount>,
    ) -> OicResult<ReconciliationCheckpoint> {
        let state = source.finalized();
        let profile = source.profile();
        self.store.transact(|s| {
            if s.scanned_blocks
                .get(&profile.chain_profile_id)
                .and_then(|b| b.get(&state.height))
                != Some(&state.hash)
                || s.cursors
                    .get(&profile.chain_profile_id)
                    .is_none_or(|c| c.finalized_height != state.height)
            {
                return Err(OicError::stale_evidence(
                    "index must catch up to finalized checkpoint",
                ));
            }
            let id = CheckpointId::unchecked(format!("checkpoint-{}", s.checkpoints.len() + 1));
            let enrollments: Vec<_> = s
                .enrollments
                .values()
                .filter(|e| {
                    e.address.chain_profile_id == profile.chain_profile_id
                        && e.address.chain_wallet_id.is_some()
                })
                .cloned()
                .collect();
            let mut balances = Vec::new();
            let mut cases_opened = Vec::new();
            for e in enrollments {
                for asset_id in &e.address.supported_assets {
                    let wallet = e.address.chain_wallet_id.clone().expect("controlled");
                    let held = holdings(
                        s,
                        &wallet,
                        asset_id,
                        reserved
                            .get(&(wallet.clone(), asset_id.clone()))
                            .copied()
                            .unwrap_or_default(),
                    )?;
                    let balance = ReconciledBalance {
                        chain_wallet_id: wallet.clone(),
                        asset_id: asset_id.clone(),
                        chain_balance: source.balance(
                            &state,
                            &e.address.address,
                            &s.assets[asset_id].asset,
                        )?,
                        journal_balance: held.settled,
                        reserved: held.reserved,
                        pending_inbound: held.pending_inbound,
                    };
                    if !balance.is_consistent() {
                        let case_id =
                            CaseId::unchecked(format!("difference-{}-{}", id, balances.len()));
                        self.case(
                            s,
                            DepositCase {
                                case_id: case_id.clone(),
                                kind: CaseKind::ReconciliationDifference,
                                severity: CaseSeverity::Critical,
                                chain_profile_id: profile.chain_profile_id.clone(),
                                movement_id: None,
                                checkpoint_id: Some(id.clone()),
                                workflow_id: None,
                                chain_wallet_id: Some(wallet),
                                asset_id: Some(asset_id.clone()),
                                amount_base_units: Some(balance.difference().1),
                                detail: format!(
                                    "chain={} journal={}; investigation required",
                                    balance.chain_balance, balance.journal_balance
                                ),
                                owner: "treasury-operations".into(),
                                state: CaseState::Open,
                                opened_at: source.now(),
                            },
                        )?;
                        cases_opened.push(case_id);
                    }
                    balances.push(balance);
                }
            }
            if source.finalized() != state {
                return Err(OicError::stale_evidence(
                    "checkpoint changed during reconciliation",
                ));
            }
            let body = ReconciliationCheckpointBody {
                checkpoint_id: id.clone(),
                chain_profile_id: profile.chain_profile_id.clone(),
                network_id: profile.network_id.clone(),
                state,
                journal_sequence: s.journal.len() as u64,
                journal_head_hash: s
                    .journal
                    .last()
                    .map(|e| e.entry_hash)
                    .unwrap_or(Hash32::ZERO),
                balances,
                cases_opened,
                sources: vec![source.source_id()],
                at: source.now(),
            };
            let checkpoint = ReconciliationCheckpoint {
                signature: self.sign(domain_hash(domains::RECONCILIATION, &body)?),
                body,
                reconciler_key_id: self.key_id.clone(),
            };
            self.event(
                s,
                LifecycleEventKind::CheckpointPublished {
                    checkpoint_id: id,
                    consistent: checkpoint.body.is_consistent(),
                },
                source.now(),
            )?;
            s.checkpoints.push(checkpoint.clone());
            Ok(checkpoint)
        })
    }
}

/// Calculate settled credits minus debits and canonical, observed inbound
/// amounts for a wallet/asset pair. Supplied reservations reduce availability
/// to a minimum of zero. Overflow returns `UnverifiableTransaction`; negative
/// settled holdings require recovery.
fn holdings(
    s: &OperationsExport,
    wallet: &ChainWalletId,
    asset: &AssetId,
    reserved: Amount,
) -> OicResult<Holdings> {
    let mut credits = 0u128;
    let mut debits = 0u128;
    for e in s
        .journal
        .iter()
        .filter(|e| &e.body.chain_wallet_id == wallet && &e.body.asset_id == asset)
    {
        let total = if e.body.side == EntrySide::Credit {
            &mut credits
        } else {
            &mut debits
        };
        *total = total
            .checked_add(e.body.amount_base_units.0)
            .ok_or_else(|| OicError::unverifiable("journal amount overflow"))?;
    }
    let settled = credits.checked_sub(debits).ok_or_else(|| {
        OicError::new(
            ErrorCode::RecoveryRequired,
            "journal has negative holdings; investigate opening balance or missing receipts",
        )
    })?;
    let pending = s
        .movements
        .values()
        .filter(|r| {
            r.movement.chain_wallet_id.as_ref() == Some(wallet)
                && r.movement.asset_id.as_ref() == Some(asset)
                && r.movement.direction == MovementDirection::Inbound
                && r.movement.acceptance == MovementAcceptance::Observed
                && r.movement.canonicality == Canonicality::Canonical
        })
        .try_fold(0u128, |a, r| a.checked_add(r.movement.amount_base_units.0))
        .ok_or_else(|| OicError::unverifiable("pending amount overflow"))?;
    Ok(Holdings {
        chain_wallet_id: Some(wallet.clone()),
        asset_id: Some(asset.clone()),
        settled: Amount(settled),
        reserved,
        pending_inbound: Amount(pending),
        available: Amount(settled.saturating_sub(reserved.0)),
        as_of_sequence: s.journal.len() as u64,
    })
}

/// Conservative wallet-local reservations. Mutually exclusive candidates may
/// over-reserve here; the authority remains the source of policy exposure.
///
/// Sum active asset outflows and native fees by source wallet and asset in
/// base units. `native_assets` maps fee networks to their native asset IDs;
/// fees without a mapping are omitted. An unmatched source wallet returns
/// `ScopeMismatch`, sum overflow returns `UnverifiableTransaction`, and
/// authority-store read errors propagate.
pub fn outstanding_reservations<S: AuthorityStore>(
    store: &S,
    wallets: &[ChainWallet],
    native_assets: &BTreeMap<NetworkId, AssetId>,
) -> OicResult<BTreeMap<(ChainWalletId, AssetId), Amount>> {
    store.read(|s| {
        let mut totals = BTreeMap::<(ChainWalletId, AssetId), Amount>::new();
        for r in s.reservations.values().filter(|r| r.state.is_active()) {
            let claims = &r.reservation.claims;
            let wallet = wallets
                .iter()
                .find(|w| {
                    claims.resources.iter().any(|resource| match resource {
                        NativeResource::EvmNonce {
                            network_id, sender, ..
                        } => network_id == &w.network_id && sender == &w.address,
                        NativeResource::SolanaBlockhash {
                            network_id,
                            fee_payer,
                            ..
                        } => network_id == &w.network_id && fee_payer == &w.address,
                        _ => false,
                    })
                })
                .ok_or_else(|| {
                    OicError::scope("active reservation has no enrolled source wallet")
                })?;
            for outflow in &claims.asset_outflows {
                let total = totals
                    .entry((wallet.chain_wallet_id.clone(), outflow.asset_id.clone()))
                    .or_default();
                *total = total
                    .checked_add(outflow.amount_base_units)
                    .ok_or_else(|| OicError::unverifiable("reservation overflow"))?;
            }
            for fee in &claims.native_fees {
                if let Some(asset) = native_assets.get(&fee.network_id) {
                    let total = totals
                        .entry((wallet.chain_wallet_id.clone(), asset.clone()))
                        .or_default();
                    *total = total
                        .checked_add(fee.amount_base_units)
                        .ok_or_else(|| OicError::unverifiable("fee reservation overflow"))?;
                }
            }
        }
        Ok(totals)
    })?
}
