//! Read-only RFC003 witness. The caller authenticates the connection's NodeId,
//! supplies trust anchors, and stores each returned floor independently of this
//! journal. No observation authorizes signing or changes authority state.
//!
//! Only [`WitnessMessage`] belongs on channel 30. [`ExportBundle`] is confidential
//! offline business data and has no public-message conversion. D1 checkpoints
//! are unlinked: a higher sequence raises a rollback floor, not a consistency
//! proof. A same-sequence conflict is attributable evidence. Quarantine is sticky.

mod export;
mod trust;
pub use export::*;
pub use trust::*;

use commonware_runtime::{BufferPooler, Metrics, ReadOptions, Storage, buffer::paged::CacheRef};
use commonware_storage::journal::segmented::variable::{Config, Journal};
use commonware_utils::{NZU16, NZUsize};
use oic_audit::{AuditCheckpoint, CheckpointComparison, compare_checkpoints, verify_chain};
use oic_authorization_state::SignedCheckpoint;
use oic_canonical_encoding::{canonical_bytes, domain_hash, from_canonical_bytes};
use oic_domain_types::*;
use oic_membership::{SignedRoster, VerificationAttestation, roster_hash, verify_attestation};
pub use oic_peer_wire::WitnessMessage;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const WITNESS_CHANNEL: u64 = 30;
const RECORD_DOMAIN: &str = "OIC/WITNESS_RECORD/v1";
const INPUT_DOMAIN: &str = "OIC/WITNESS_INPUT/v1";
const MAX_RECORD_BYTES: usize = 2 * MAX_BYTES_LEN;

/// Keep this outside the witness's own storage failure/rollback domain. A peer
/// or an exported bundle must never choose the floor for reopening its history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalFloor {
    pub records: u64,
    pub head_hash: Hash32,
}

impl JournalFloor {
    /// Explicit first installation only, not a recovery fallback.
    pub const EMPTY: Self = Self {
        records: 0,
        head_hash: Hash32::ZERO,
    };
}

/// Hash-linked, canonical records retain the original authenticated objects,
/// their relay identity, the admitted roster, and local observation time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRecord {
    pub sequence: u64,
    pub previous_hash: Hash32,
    pub roster_epoch: u64,
    pub roster_hash: Hash32,
    pub from: NodeId,
    pub observed_at: UnixSeconds,
    pub message: WitnessMessage,
}

pub fn witness_record_hash(record: &WitnessRecord) -> OicResult<Hash32> {
    domain_hash(RECORD_DOMAIN, record)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    AuthorityEquivocation,
    AuditDivergence { key_id: KeyId, at_sequence: u64 },
    AttestationDisagreement { input_hash: Hash32 },
}

/// One-based indices into [`Witness::records`]; both signed objects (including
/// a divergent bridge) are retained. Evidence is derived again during replay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DivergenceEvidence {
    pub kind: EvidenceKind,
    pub first_record: u64,
    pub second_record: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    Recorded,
    Unchanged,
    Quarantined,
}

#[derive(Clone, Default)]
struct History {
    authority: Option<(u64, SignedCheckpoint)>,
    // Preserve every authenticated sequence, not just the newest, so a late
    // conflicting old checkpoint cannot escape detection as mere staleness.
    authority_seen: BTreeMap<u64, (u64, SignedCheckpoint)>,
    audits: BTreeMap<KeyId, (u64, AuditCheckpoint)>,
    audit_seen: BTreeMap<(KeyId, u64), (u64, AuditCheckpoint)>,
    attestations: BTreeMap<Hash32, (u64, VerificationAttestation)>,
    evidence: Vec<DivergenceEvidence>,
}

impl History {
    fn apply(&mut self, record: &WitnessRecord, trust: &WitnessTrust) -> OicResult<Observation> {
        let roster = trust.roster(record.roster_epoch)?;
        require(
            roster_hash(&roster.body)? == record.roster_hash,
            "record roster commitment mismatch",
        )?;
        if !roster.allows(WITNESS_CHANNEL, &record.from, &trust.witness_id) {
            return Err(OicError::new(
                ErrorCode::PeerNotAdmitted,
                "witness channel ACL rejected peer",
            ));
        }
        require(
            record.observed_at >= roster.body.activation.not_before,
            "observation predates roster activation",
        )?;
        // An old roster may be replayed, but was not current at its recorded time
        // once the independently committed next roster had activated.
        if let Some(next) = trust
            .rosters
            .iter()
            .find(|r| r.body.roster_epoch == record.roster_epoch + 1)
        {
            require(
                record.observed_at < next.body.activation.not_before,
                "observation used a superseded roster",
            )?;
        }
        let acl = roster
            .body
            .channel_acl
            .iter()
            .find(|acl| acl.channel == WITNESS_CHANNEL)
            .ok_or_else(|| invalid("missing witness ACL"))?;
        require(
            record.message.encode()?.len() <= acl.max_message_size as usize,
            "record exceeds admitted channel limit",
        )?;
        let mut changed = true;
        match &record.message {
            WitnessMessage::AuthorityCheckpoint(checkpoint) => {
                trust.verify_authority(checkpoint)?;
                let b = &checkpoint.body;
                if let Some((first, previous)) = self.authority_seen.get(&b.commit_sequence) {
                    if previous.body != *b {
                        self.evidence.push(DivergenceEvidence {
                            kind: EvidenceKind::AuthorityEquivocation,
                            first_record: *first,
                            second_record: record.sequence,
                        });
                    } else {
                        changed = false;
                    }
                } else {
                    if let Some((_, previous)) = &self.authority {
                        require(
                            b.commit_sequence > previous.body.commit_sequence,
                            "authority checkpoint below retained floor",
                        )?;
                        require(
                            b.authority_epoch >= previous.body.authority_epoch,
                            "authority epoch regressed",
                        )?;
                    }
                    self.authority_seen
                        .insert(b.commit_sequence, (record.sequence, checkpoint.clone()));
                    self.authority = Some((record.sequence, checkpoint.clone()));
                }
            }
            WitnessMessage::AuditCheckpoint { checkpoint, bridge } => {
                let key_id = &checkpoint.body.service_key_id;
                let binding = trust.audit(key_id)?;
                oic_audit::verify_checkpoint(checkpoint, &binding.key)?;
                require(
                    checkpoint.body.sequence != 0
                        || checkpoint.body.head_event_hash == Hash32::ZERO,
                    "nonempty zero audit checkpoint",
                )?;
                // Verify the bridge internally BEFORE comparing endpoints. A
                // signed but disordered/disconnected bridge is malformed input,
                // not proof that two checkpoint histories disagree.
                if let Some(first) = bridge.first() {
                    let prior = first
                        .body
                        .sequence
                        .checked_sub(1)
                        .ok_or_else(|| invalid("audit event sequence is zero"))?;
                    require(
                        bridge.iter().all(|e| &e.service_key_id == key_id),
                        "bridge audit identity mismatch",
                    )?;
                    verify_chain(
                        bridge,
                        &binding.key,
                        Some((prior, first.body.previous_event_hash)),
                    )?;
                }
                let seen_key = (key_id.clone(), checkpoint.body.sequence);
                let previous = self
                    .audit_seen
                    .get(&seen_key)
                    .or_else(|| self.audits.get(key_id));
                if let Some((first, previous)) = previous {
                    match compare_checkpoints(previous, checkpoint, &binding.key, bridge)? {
                        CheckpointComparison::Diverged { at_sequence } => {
                            self.evidence.push(DivergenceEvidence {
                                kind: EvidenceKind::AuditDivergence {
                                    key_id: key_id.clone(),
                                    at_sequence,
                                },
                                first_record: *first,
                                second_record: record.sequence,
                            })
                        }
                        CheckpointComparison::Consistent => changed = false,
                        CheckpointComparison::Extends { .. } => {
                            require(
                                checkpoint.body.sequence > previous.body.sequence,
                                "audit checkpoint below retained floor",
                            )?;
                            self.audit_seen
                                .insert(seen_key, (record.sequence, checkpoint.clone()));
                            self.audits
                                .insert(key_id.clone(), (record.sequence, checkpoint.clone()));
                        }
                    }
                } else {
                    // Bootstrap is a signed claim by the independently enrolled
                    // service, not a peer-supplied trust anchor. Offline exports
                    // additionally reconstruct its full journal from sequence 1.
                    self.audit_seen
                        .insert(seen_key, (record.sequence, checkpoint.clone()));
                    self.audits
                        .insert(key_id.clone(), (record.sequence, checkpoint.clone()));
                }
            }
            WitnessMessage::Attestation(attestation) => {
                // Observation only: these signed input commitments are NOT an
                // independently evaluated policy-authorization input snapshot.
                verify_attestation(
                    attestation,
                    roster,
                    &attestation.body.inputs,
                    record.observed_at,
                )?;
                let input_hash = domain_hash(INPUT_DOMAIN, &attestation.body.inputs)?;
                if let Some((first, previous)) = self.attestations.get(&input_hash) {
                    if previous.body.decision != attestation.body.decision {
                        self.evidence.push(DivergenceEvidence {
                            kind: EvidenceKind::AttestationDisagreement { input_hash },
                            first_record: *first,
                            second_record: record.sequence,
                        });
                    } else {
                        changed = previous != attestation.as_ref();
                    }
                } else {
                    self.attestations
                        .insert(input_hash, (record.sequence, attestation.as_ref().clone()));
                }
            }
        }
        Ok(if !self.evidence.is_empty() {
            Observation::Quarantined
        } else if changed {
            Observation::Recorded
        } else {
            Observation::Unchanged
        })
    }
}

/// Single writer per Commonware partition. The owner must serialize access and
/// exclude a second process using the same partition. Cancellation or I/O error
/// while appending poisons this instance; reopen and compare the independent
/// floor instead of retrying ambiguously persisted observations.
pub struct Witness<E: Storage + Metrics> {
    journal: Option<Journal<E, Vec<u8>>>,
    trust: WitnessTrust,
    history: History,
    records: Vec<WitnessRecord>,
    floor: JournalFloor,
}

impl<E: Storage + Metrics + BufferPooler> Witness<E> {
    pub async fn open(
        context: E,
        partition: String,
        trust: WitnessTrust,
        floor: JournalFloor,
        now: UnixSeconds,
    ) -> OicResult<Self> {
        trust.validate(now)?;
        require(
            floor.records != 0 || floor.head_hash == Hash32::ZERO,
            "invalid empty witness floor",
        )?;
        let page_cache = CacheRef::from_pooler(&context, NZU16!(4096), NZUsize!(16));
        let journal = Journal::<E, Vec<u8>>::init(
            context,
            Config {
                partition,
                compression: None,
                codec_config: ((..=MAX_RECORD_BYTES).into(), ()),
                page_cache,
                write_buffer: NZUsize!(65536),
            },
        )
        .await
        .map_err(storage_error)?;
        let mut replay = journal
            .replay(0, 0, NZUsize!(65536), ReadOptions::DONT_CACHE)
            .await
            .map_err(storage_error)?;
        let mut records = Vec::new();
        let mut history = History::default();
        let mut head = JournalFloor::EMPTY;
        while let Some(result) = replay.next().await {
            let (section, _, _, bytes) = result.map_err(storage_error)?;
            require(section == 0, "unexpected witness journal section")?;
            let record: WitnessRecord = from_canonical_bytes(&bytes)?;
            replay_record(&record, &trust, &mut history, &mut head)?;
            verify_floor_prefix(floor, head)?;
            records.push(record);
        }
        require(
            head.records >= floor.records,
            "witness journal below independently retained floor",
        )?;
        let journal = replay.finish().map_err(storage_error)?;
        Ok(Self {
            journal: Some(journal),
            trust,
            history,
            records,
            floor: head,
        })
    }

    /// `from` MUST come from the authenticated transport, never the payload.
    /// The bridge must additionally enforce its frame/roster/namespace binding.
    /// The service performs channel30 ACL, size, strict CBOR and object checks.
    /// A divergence returns Quarantined only AFTER both proofs have synced.
    pub async fn handle_authenticated(
        &mut self,
        from: &NodeId,
        channel: u64,
        payload: &[u8],
        now: UnixSeconds,
    ) -> OicResult<Observation> {
        require(self.journal.is_some(), "witness storage requires reopen")?;
        let roster = self.trust.active_roster(now)?;
        if channel != WITNESS_CHANNEL || !roster.allows(channel, from, &self.trust.witness_id) {
            return Err(OicError::new(
                ErrorCode::PeerNotAdmitted,
                "witness channel ACL rejected peer",
            ));
        }
        let acl = roster
            .body
            .channel_acl
            .iter()
            .find(|a| a.channel == channel)
            .ok_or_else(|| invalid("missing witness ACL"))?;
        require(
            payload.len() <= acl.max_message_size as usize && payload.len() <= MAX_BYTES_LEN,
            "witness message exceeds channel limit",
        )?;
        let message: WitnessMessage = from_canonical_bytes(payload)?;
        let record = WitnessRecord {
            sequence: self
                .floor
                .records
                .checked_add(1)
                .ok_or_else(|| invalid("witness sequence exhausted"))?,
            previous_hash: self.floor.head_hash,
            roster_epoch: roster.body.roster_epoch,
            roster_hash: roster_hash(&roster.body)?,
            from: from.clone(),
            observed_at: now,
            message,
        };
        let mut history = self.history.clone();
        let outcome = history.apply(&record, &self.trust)?;
        // Do not discard a duplicate when globally quarantined: retaining the
        // authenticated exchange is useful, and quarantine must not be cleared.
        if outcome == Observation::Unchanged {
            return Ok(outcome);
        }
        let bytes = canonical_bytes(&record)?;
        require(
            bytes.len() <= MAX_RECORD_BYTES,
            "witness record exceeds limit",
        )?;
        let hash = witness_record_hash(&record)?;
        let journal = self
            .journal
            .take()
            .ok_or_else(|| invalid("witness requires reopen"))?;
        let (journal, _, _) = journal.append(0, &bytes).await.map_err(storage_error)?;
        self.journal = Some(journal.sync_all().await.map_err(storage_error)?);
        self.history = history;
        self.floor = JournalFloor {
            records: record.sequence,
            head_hash: hash,
        };
        self.records.push(record);
        Ok(outcome)
    }

    pub fn node_id(&self) -> &NodeId {
        &self.trust.witness_id
    }
    pub fn active_roster(&self, now: UnixSeconds) -> OicResult<&SignedRoster> {
        self.trust.active_roster(now)
    }
    pub fn floor(&self) -> JournalFloor {
        self.floor
    }
    pub fn records(&self) -> &[WitnessRecord] {
        &self.records
    }
    pub fn evidence(&self) -> &[DivergenceEvidence] {
        &self.history.evidence
    }
    pub fn quarantined(&self) -> bool {
        !self.history.evidence.is_empty()
    }
    pub fn authority_checkpoint(&self) -> Option<&SignedCheckpoint> {
        self.history.authority.as_ref().map(|(_, c)| c)
    }
    pub fn audit_checkpoint(&self, key_id: &KeyId) -> Option<&AuditCheckpoint> {
        self.history.audits.get(key_id).map(|(_, c)| c)
    }

    /// No public transport encoding is offered for this confidential object.
    pub fn export(&self, artifacts: ExportArtifacts) -> ExportBundle {
        ExportBundle {
            version: 1,
            rosters: self.trust.rosters.clone(),
            witness_records: self.records.clone(),
            artifacts,
        }
    }
}

fn replay_record(
    record: &WitnessRecord,
    trust: &WitnessTrust,
    history: &mut History,
    head: &mut JournalFloor,
) -> OicResult<()> {
    require(
        head.records.checked_add(1) == Some(record.sequence)
            && record.previous_hash == head.head_hash,
        "witness record chain corrupt",
    )?;
    history.apply(record, trust)?;
    *head = JournalFloor {
        records: record.sequence,
        head_hash: witness_record_hash(record)?,
    };
    Ok(())
}

fn verify_floor_prefix(floor: JournalFloor, head: JournalFloor) -> OicResult<()> {
    require(
        head.records != floor.records || head.head_hash == floor.head_hash,
        "witness history differs at independently retained floor",
    )
}

fn require(ok: bool, detail: &str) -> OicResult<()> {
    if ok { Ok(()) } else { Err(invalid(detail)) }
}
fn invalid(detail: &str) -> OicError {
    OicError::new(ErrorCode::RecoveryRequired, detail)
}
fn storage_error(error: impl std::fmt::Display) -> OicError {
    OicError::new(
        ErrorCode::AuthorityUnavailable,
        format!("witness journal: {error}"),
    )
}
