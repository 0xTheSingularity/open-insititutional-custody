//! # oic-one-time-state-ledger
//!
//! Durable ledgers for one-time cryptographic state (nonces, preprocessing)
//! implementing [`oic_crypto_provider::OneTimeStateLedger`] (RFC 0001 §6.3).
//!
//! ## What this crate guarantees
//!
//! * Every record has an immutable identity derived from
//!   `SHA-256(key_id ‖ key_epoch ‖ generation ‖ session_id ‖ counter)` (see
//!   [`record_id_for`]), is bound to exactly one signing session at
//!   allocation, and can be consumed **exactly once**, for exactly one message
//!   hash. A second consume, a consume for a different message, or a consume
//!   of a tombstoned record fails with [`ErrorCode::ResourceConflict`]; an
//!   unknown record fails with [`ErrorCode::NotFound`].
//! * [`FileLedger`] appends every mutation to a length-prefixed,
//!   checksummed log of canonical-CBOR entries and `fsync`s it **before** the
//!   call returns, so a successful `consume` is durable (A11). Replay verifies
//!   that entry sequence numbers are contiguous and that every allocation's
//!   record id recomputes from the replayed counter.
//! * [`FileLedger::open`] refuses with [`ErrorCode::RecoveryRequired`] when
//!   the replayed mutation sequence is below the caller-supplied minimum or
//!   the `<path>.hwm` high-water-mark sidecar (restored backup / snapshot
//!   rollback, A12/A13).
//! * [`OneTimeStateLedger::tombstone_generations_before`] permanently retires
//!   every unconsumed record of older signer generations and raises a per-key
//!   generation floor: later allocations for an older generation are refused.
//!
//! ## What it does not guarantee
//!
//! * Rollback detection is only as strong as the minimum sequence the caller
//!   supplies from an *independent* source (e.g. the authorization-state
//!   authority). Rolling back the log file and its sidecar together, without
//!   such a witness, is undetectable locally — local disk state alone does not
//!   establish freshness (§6.3).
//! * The ledger stores record identities and consumption state only; it never
//!   stores secret nonce material.
//! * It does not take an OS-level lock on the log file; running two
//!   processes against one log is an operator error that the external
//!   signer-generation fencing (§6.3) must prevent.
//! * A torn final frame (crash during append, before `fsync` returned) is
//!   truncated on open: that mutation was never acknowledged to any caller.
//!   Any other malformed frame is treated as corruption and refuses to open.

use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes, sha256};
use oic_crypto_provider::{OneTimeStateLedger, OneTimeStateRecord};
use oic_domain_types::*;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Fault-injection / durability hook, called with the operation name
/// ([`OP_ALLOCATE`], [`OP_CONSUME`], [`OP_TOMBSTONE`]) and the record as it
/// would be after the mutation, immediately before the mutation commits. An
/// error aborts the mutation with no state change.
pub type FaultHook = Box<dyn Fn(&str, &OneTimeStateRecord) -> OicResult<()> + Send + Sync>;

pub const OP_ALLOCATE: &str = "allocate";
pub const OP_CONSUME: &str = "consume";
pub const OP_TOMBSTONE: &str = "tombstone";

/// Log format identifier, carried in every log entry.
pub const LOG_FORMAT: &str = "oic-one-time-state-log/v1";

/// Record identity: lowercase hex of
/// `SHA-256(u32be(len(key_id)) ‖ key_id ‖ u64be(key_epoch) ‖ u64be(generation) ‖
/// u32be(len(session_id)) ‖ session_id ‖ u64be(counter))`.
/// Variable-length fields are length-prefixed so distinct inputs never collide
/// by concatenation.
pub fn record_id_for(key_id: &KeyId, key_epoch: Epoch, generation: Epoch, session_id: &SigningSessionId, counter: u64) -> String {
    let mut buf = Vec::with_capacity(64 + key_id.as_str().len() + session_id.as_str().len());
    push_lp(&mut buf, key_id.as_str().as_bytes());
    buf.extend_from_slice(&key_epoch.0.to_be_bytes());
    buf.extend_from_slice(&generation.0.to_be_bytes());
    push_lp(&mut buf, session_id.as_str().as_bytes());
    buf.extend_from_slice(&counter.to_be_bytes());
    sha256(&buf).to_hex()
}

fn push_lp(buf: &mut Vec<u8>, b: &[u8]) {
    // Identifiers are bounded to MAX_ID_LEN bytes, so the cast cannot truncate.
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

// ---------------------------------------------------------------------------
// Shared state machine
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    record: OneTimeStateRecord,
    tombstoned: bool,
}

/// One durable mutation. Tombstones are logged by their parameters; replay
/// recomputes the affected set deterministically, so a log entry stays
/// bounded regardless of how many records it retires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mutation {
    Allocate { record: OneTimeStateRecord },
    Consume { record_id: String, message_hash: Hash32 },
    Tombstone { key_id: KeyId, generation: Epoch },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LogEntry {
    format: String,
    sequence: u64,
    mutation: Mutation,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LedgerState {
    records: BTreeMap<String, Entry>,
    /// Per-key generation floor raised by tombstoning.
    floors: BTreeMap<KeyId, Epoch>,
    /// Allocation counter (input to record ids).
    counter: u64,
    /// Number of applied mutations.
    sequence: u64,
}

/// A planned mutation plus the records it changes (for the fault hook).
struct Plan {
    mutation: Mutation,
    affected: Vec<(&'static str, OneTimeStateRecord)>,
    output: PlanOutput,
}

enum PlanOutput {
    Record(OneTimeStateRecord),
    Unit,
    Count(u64),
}

impl LedgerState {
    fn plan_allocate(&self, key_id: &KeyId, key_epoch: Epoch, generation: Epoch, session_id: &SigningSessionId) -> OicResult<Plan> {
        if let Some(floor) = self.floors.get(key_id) {
            if generation < *floor {
                return Err(OicError::resource_conflict(format!(
                    "signer generation {generation} for key {key_id} is below the tombstoned floor {floor}; stale generation is fenced"
                )));
            }
        }
        let record_id = record_id_for(key_id, key_epoch, generation, session_id, self.counter);
        if self.records.contains_key(&record_id) {
            return Err(OicError::internal("one-time record id collision"));
        }
        let record = OneTimeStateRecord {
            record_id,
            key_id: key_id.clone(),
            key_epoch,
            signer_generation: generation,
            session_id: Some(session_id.clone()),
            bound_message_hash: None,
            consumed: false,
        };
        Ok(Plan {
            mutation: Mutation::Allocate { record: record.clone() },
            affected: vec![(OP_ALLOCATE, record.clone())],
            output: PlanOutput::Record(record),
        })
    }

    fn plan_consume(&self, record_id: &str, message_hash: Hash32) -> OicResult<Plan> {
        let entry = self
            .records
            .get(record_id)
            .ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("one-time record {record_id} not found")))?;
        if entry.tombstoned {
            return Err(OicError::resource_conflict(format!("one-time record {record_id} is tombstoned and can never be used")));
        }
        if let Some(bound) = entry.record.bound_message_hash {
            if bound != message_hash {
                return Err(OicError::resource_conflict(format!("one-time record {record_id} is bound to a different message")));
            }
        }
        if entry.record.consumed {
            return Err(OicError::resource_conflict(format!("one-time record {record_id} is already consumed")));
        }
        let mut after = entry.record.clone();
        after.bound_message_hash = Some(message_hash);
        after.consumed = true;
        Ok(Plan {
            mutation: Mutation::Consume { record_id: record_id.to_string(), message_hash },
            affected: vec![(OP_CONSUME, after)],
            output: PlanOutput::Unit,
        })
    }

    fn tombstone_targets(&self, key_id: &KeyId, generation: Epoch) -> Vec<String> {
        self.records
            .iter()
            .filter(|(_, e)| !e.record.consumed && e.record.key_id == *key_id && e.record.signer_generation < generation)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// `None` when the tombstone would change nothing (no records, floor already at or above).
    fn plan_tombstone(&self, key_id: &KeyId, generation: Epoch) -> Option<Plan> {
        let targets = self.tombstone_targets(key_id, generation);
        let floor_raises = self.floors.get(key_id).is_none_or(|f| *f < generation);
        if targets.is_empty() && !floor_raises {
            return None;
        }
        let affected = targets
            .iter()
            .map(|id| {
                let mut r = self.records[id].record.clone();
                r.consumed = true;
                (OP_TOMBSTONE, r)
            })
            .collect::<Vec<_>>();
        let count = affected.len() as u64;
        Some(Plan {
            mutation: Mutation::Tombstone { key_id: key_id.clone(), generation },
            affected,
            output: PlanOutput::Count(count),
        })
    }

    /// Apply a mutation, re-validating it. Used both for live commits (after
    /// planning) and log replay.
    fn apply(&mut self, m: &Mutation) -> OicResult<()> {
        match m {
            Mutation::Allocate { record } => {
                let session = record.session_id.as_ref().ok_or_else(|| OicError::internal("allocation without session"))?;
                let plan = self.plan_allocate(&record.key_id, record.key_epoch, record.signer_generation, session)?;
                match plan.output {
                    PlanOutput::Record(expected) if expected == *record => {}
                    _ => return Err(OicError::internal("allocation record does not match recomputed identity")),
                }
                self.records.insert(record.record_id.clone(), Entry { record: record.clone(), tombstoned: false });
                self.counter += 1;
            }
            Mutation::Consume { record_id, message_hash } => {
                self.plan_consume(record_id, *message_hash)?;
                let e = self.records.get_mut(record_id).ok_or_else(|| OicError::internal("record vanished"))?;
                e.record.bound_message_hash = Some(*message_hash);
                e.record.consumed = true;
            }
            Mutation::Tombstone { key_id, generation } => {
                for id in self.tombstone_targets(key_id, *generation) {
                    let e = self.records.get_mut(&id).ok_or_else(|| OicError::internal("record vanished"))?;
                    e.record.consumed = true;
                    e.tombstoned = true;
                }
                let floor = self.floors.entry(key_id.clone()).or_default();
                if *floor < *generation {
                    *floor = *generation;
                }
            }
        }
        self.sequence += 1;
        Ok(())
    }

    fn get(&self, record_id: &str) -> Option<OneTimeStateRecord> {
        self.records.get(record_id).map(|e| e.record.clone())
    }

    fn is_tombstoned(&self, record_id: &str) -> OicResult<bool> {
        self.records
            .get(record_id)
            .map(|e| e.tombstoned)
            .ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("one-time record {record_id} not found")))
    }

    fn snapshot(&self) -> Vec<OneTimeStateRecord> {
        self.records.values().map(|e| e.record.clone()).collect()
    }
}

fn output_record(p: PlanOutput) -> OicResult<OneTimeStateRecord> {
    match p {
        PlanOutput::Record(r) => Ok(r),
        _ => Err(OicError::internal("unexpected plan output")),
    }
}

fn output_count(p: PlanOutput) -> u64 {
    match p {
        PlanOutput::Count(c) => c,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// In-memory ledger
// ---------------------------------------------------------------------------

/// In-memory ledger for tests and single-process development. Not durable
/// across process restarts. Optionally runs a [`FaultHook`] immediately
/// before each mutation commits.
#[derive(Default)]
pub struct InMemoryLedger {
    state: Mutex<LedgerState>,
    hook: Option<FaultHook>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a hook invoked just before a mutation commits; an error from
    /// the hook aborts the mutation (simulates a crash before the write).
    pub fn with_fault_hook(mut self, hook: FaultHook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Number of committed mutations.
    pub fn sequence(&self) -> u64 {
        self.state.lock().sequence
    }

    /// All records, ordered by record id.
    pub fn snapshot(&self) -> Vec<OneTimeStateRecord> {
        self.state.lock().snapshot()
    }

    /// Whether a record was retired by tombstoning (`NotFound` if unknown).
    pub fn is_tombstoned(&self, record_id: &str) -> OicResult<bool> {
        self.state.lock().is_tombstoned(record_id)
    }

    fn commit(&self, state: &mut LedgerState, plan: &Plan) -> OicResult<()> {
        if let Some(hook) = &self.hook {
            for (op, rec) in &plan.affected {
                hook(op, rec)?;
            }
        }
        state.apply(&plan.mutation)
    }
}

impl OneTimeStateLedger for InMemoryLedger {
    fn allocate(&self, key_id: &KeyId, key_epoch: Epoch, generation: Epoch, session_id: &SigningSessionId) -> OicResult<OneTimeStateRecord> {
        let mut st = self.state.lock();
        let plan = st.plan_allocate(key_id, key_epoch, generation, session_id)?;
        self.commit(&mut st, &plan)?;
        output_record(plan.output)
    }

    fn consume(&self, record_id: &str, message_hash: Hash32) -> OicResult<()> {
        let mut st = self.state.lock();
        let plan = st.plan_consume(record_id, message_hash)?;
        self.commit(&mut st, &plan)
    }

    fn get(&self, record_id: &str) -> OicResult<Option<OneTimeStateRecord>> {
        Ok(self.state.lock().get(record_id))
    }

    fn tombstone_generations_before(&self, key_id: &KeyId, generation: Epoch) -> OicResult<u64> {
        let mut st = self.state.lock();
        match st.plan_tombstone(key_id, generation) {
            None => Ok(0),
            Some(plan) => {
                self.commit(&mut st, &plan)?;
                Ok(output_count(plan.output))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// File ledger
// ---------------------------------------------------------------------------

/// Bytes of the SHA-256 checksum trailing every frame.
const CHECKSUM_LEN: usize = 32;
/// Upper bound on one frame's payload (canonical decoder limit).
const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;

fn unavailable(detail: impl std::fmt::Display) -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, format!("one-time ledger: {detail}"))
}

fn recovery(detail: impl Into<String>) -> OicError {
    OicError::new(ErrorCode::RecoveryRequired, detail)
}

struct FileInner {
    state: LedgerState,
    file: fs::File,
    /// Length of the durable, well-formed log prefix.
    len: u64,
    /// Set when a failed append could not be rolled back; every later call fails.
    poisoned: bool,
}

/// Durable append-only ledger.
///
/// Log format: a sequence of frames `u32be(len) ‖ payload ‖ SHA-256(payload)`
/// where `payload` is the canonical CBOR of
/// `{format: "oic-one-time-state-log/v1", sequence, mutation}` and sequences
/// are contiguous from 1. Every mutation is appended and `fsync`ed before the
/// call returns; then the `<path>.hwm` sidecar is atomically advanced.
pub struct FileLedger {
    path: PathBuf,
    inner: Mutex<FileInner>,
}

impl FileLedger {
    /// Open (or create) the log at `path` and replay it. Fails with
    /// `RecoveryRequired` if the log is corrupt, or if the replayed mutation
    /// sequence is below `expected_min_sequence` or the high-water-mark
    /// sidecar (rollback / restored backup).
    pub fn open(path: impl AsRef<Path>, expected_min_sequence: Option<u64>) -> OicResult<Self> {
        let path = path.as_ref().to_path_buf();
        let existed = path.exists();
        let mut file = fs::OpenOptions::new().read(true).append(true).create(true).open(&path).map_err(unavailable)?;
        if !existed {
            file.sync_all().map_err(unavailable)?;
            sync_dir(&path)?;
        }
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0)).map_err(unavailable)?;
        file.read_to_end(&mut bytes).map_err(unavailable)?;

        let (state, good_len) = replay(&bytes)?;
        let hwm = read_hwm(&path)?;
        let floor = hwm.max(expected_min_sequence.unwrap_or(0));
        if state.sequence < floor {
            return Err(recovery(format!(
                "one-time ledger sequence {} is older than highest seen {floor}: possible rollback or restored backup",
                state.sequence
            )));
        }
        if (good_len as usize) < bytes.len() {
            // Torn final frame: never acknowledged; drop it.
            file.set_len(good_len).map_err(unavailable)?;
            file.sync_all().map_err(unavailable)?;
        }
        Ok(FileLedger { path, inner: Mutex::new(FileInner { state, file, len: good_len, poisoned: false }) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of durable mutations replayed or committed.
    pub fn sequence(&self) -> u64 {
        self.inner.lock().state.sequence
    }

    /// All records, ordered by record id.
    pub fn snapshot(&self) -> Vec<OneTimeStateRecord> {
        self.inner.lock().state.snapshot()
    }

    /// Whether a record was retired by tombstoning (`NotFound` if unknown).
    pub fn is_tombstoned(&self, record_id: &str) -> OicResult<bool> {
        self.inner.lock().state.is_tombstoned(record_id)
    }

    fn commit(&self, inner: &mut FileInner, mutation: &Mutation) -> OicResult<()> {
        if inner.poisoned {
            return Err(recovery("one-time ledger is poisoned after an unrecoverable write failure; reopen required"));
        }
        // Validate against a scratch copy so an invalid mutation never reaches disk.
        let mut next = inner.state.clone();
        next.apply(mutation)?;
        let entry = LogEntry { format: LOG_FORMAT.into(), sequence: next.sequence, mutation: mutation.clone() };
        let payload = canonical_bytes(&entry).map_err(unavailable)?;
        if payload.len() > MAX_FRAME_LEN {
            return Err(unavailable("log entry exceeds frame limit"));
        }
        let mut frame = Vec::with_capacity(4 + payload.len() + CHECKSUM_LEN);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&sha256(&payload).0);

        let written = inner.file.write_all(&frame).and_then(|_| inner.file.sync_all());
        if let Err(e) = written {
            // Roll the log back to the last durable prefix.
            let rolled = inner.file.set_len(inner.len).and_then(|_| inner.file.sync_all());
            if rolled.is_err() {
                inner.poisoned = true;
            }
            return Err(unavailable(e));
        }
        inner.len += frame.len() as u64;
        inner.state = next;
        // The mutation is durable in the log from here on; a failing sidecar
        // write is reported but does not undo it (replay would re-apply it).
        write_atomic(&hwm_path(&self.path), inner.state.sequence.to_string().as_bytes())
            .map_err(|e| unavailable(format!("mutation durable but high-water mark not advanced: {}", e.detail)))
    }
}

impl OneTimeStateLedger for FileLedger {
    fn allocate(&self, key_id: &KeyId, key_epoch: Epoch, generation: Epoch, session_id: &SigningSessionId) -> OicResult<OneTimeStateRecord> {
        let mut inner = self.inner.lock();
        let plan = inner.state.plan_allocate(key_id, key_epoch, generation, session_id)?;
        self.commit(&mut inner, &plan.mutation)?;
        output_record(plan.output)
    }

    fn consume(&self, record_id: &str, message_hash: Hash32) -> OicResult<()> {
        let mut inner = self.inner.lock();
        let plan = inner.state.plan_consume(record_id, message_hash)?;
        self.commit(&mut inner, &plan.mutation)
    }

    fn get(&self, record_id: &str) -> OicResult<Option<OneTimeStateRecord>> {
        Ok(self.inner.lock().state.get(record_id))
    }

    fn tombstone_generations_before(&self, key_id: &KeyId, generation: Epoch) -> OicResult<u64> {
        let mut inner = self.inner.lock();
        match inner.state.plan_tombstone(key_id, generation) {
            None => Ok(0),
            Some(plan) => {
                self.commit(&mut inner, &plan.mutation)?;
                Ok(output_count(plan.output))
            }
        }
    }
}

/// Replay a log. Returns the state and the length of the well-formed prefix
/// (shorter than `bytes` only when the final frame is torn).
fn replay(bytes: &[u8]) -> OicResult<(LedgerState, u64)> {
    let mut state = LedgerState::default();
    let mut off = 0usize;
    while off < bytes.len() {
        let rest = &bytes[off..];
        if rest.len() < 4 {
            break; // torn length prefix
        }
        let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if len > MAX_FRAME_LEN {
            return Err(recovery(format!("one-time ledger frame at offset {off} has invalid length {len}")));
        }
        let total = 4 + len + CHECKSUM_LEN;
        if rest.len() < total {
            break; // torn payload or checksum
        }
        let payload = &rest[4..4 + len];
        if sha256(payload).0[..] != rest[4 + len..total] {
            return Err(recovery(format!("one-time ledger frame at offset {off} fails its checksum")));
        }
        let entry: LogEntry =
            from_canonical_bytes(payload).map_err(|e| recovery(format!("one-time ledger frame at offset {off} undecodable: {}", e.detail)))?;
        if entry.format != LOG_FORMAT {
            return Err(recovery(format!("unknown one-time ledger format {}", entry.format)));
        }
        if entry.sequence != state.sequence + 1 {
            return Err(recovery(format!("one-time ledger sequence gap: expected {}, found {}", state.sequence + 1, entry.sequence)));
        }
        state
            .apply(&entry.mutation)
            .map_err(|e| recovery(format!("one-time ledger entry {} is inconsistent: {}", entry.sequence, e.detail)))?;
        off += total;
    }
    Ok((state, off as u64))
}

fn hwm_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".hwm");
    PathBuf::from(s)
}

fn read_hwm(path: &Path) -> OicResult<u64> {
    match fs::read_to_string(hwm_path(path)) {
        Ok(s) => s.trim().parse::<u64>().map_err(|_| recovery("one-time ledger high-water-mark sidecar is corrupt")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(unavailable(e)),
    }
}

fn sync_dir(path: &Path) -> OicResult<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(d) = fs::File::open(dir) {
            d.sync_all().map_err(unavailable)?;
        }
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> OicResult<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = fs::File::create(&tmp).map_err(unavailable)?;
        f.write_all(bytes).map_err(unavailable)?;
        f.sync_all().map_err(unavailable)?;
    }
    fs::rename(&tmp, path).map_err(unavailable)?;
    sync_dir(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_id_is_length_prefixed() {
        let a = record_id_for(&KeyId::unchecked("ab"), Epoch(1), Epoch(1), &SigningSessionId::unchecked("c"), 0);
        let b = record_id_for(&KeyId::unchecked("a"), Epoch(1), Epoch(1), &SigningSessionId::unchecked("bc"), 0);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn replay_rejects_sequence_gap() {
        let entry = LogEntry {
            format: LOG_FORMAT.into(),
            sequence: 2,
            mutation: Mutation::Tombstone { key_id: KeyId::unchecked("k"), generation: Epoch(1) },
        };
        let payload = canonical_bytes(&entry).unwrap();
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&sha256(&payload).0);
        let err = replay(&frame).unwrap_err();
        assert_eq!(err.code, ErrorCode::RecoveryRequired);
    }
}
