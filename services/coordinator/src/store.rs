//! Operation lifecycle log (RFC 0001 §12, §14).
//!
//! Every lifecycle transition the coordinator drives is appended as one
//! [`Transition`] before the coordinator acts on it further. The log is
//! append-only and monotone with respect to issuance: once a candidate may
//! have produced a signature (any state outside the pre-issuance set, see
//! [`is_pre_issuance`]) it can never be recorded as pre-issuance again
//! (`Conflict`), and [`OperationStore::lifecycle`] of a family never reports
//! a pre-issuance state while any of its candidates possibly issued. A crash
//! therefore cannot turn `ISSUANCE_COMMITTED` into a silent
//! `ABORTED_BEFORE_ISSUANCE` (§12.2).
//!
//! [`FileOperationStore`] writes one JSON object per line and `fsync`s the
//! file after every append; `append` returns only after the line is
//! durable. On open it replays (and re-validates) every complete line; a
//! torn final line without its newline was never acknowledged and is
//! truncated away. A malformed complete line fails the open with
//! `RecoveryRequired`.

use oic_domain_types::*;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// One recorded lifecycle transition of one candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    pub operation_family_id: OperationFamilyId,
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub state: LifecycleState,
    pub at: UnixSeconds,
    pub session_id: Option<SigningSessionId>,
    pub reservation_id: Option<ReservationId>,
    pub envelope_body_hash: Option<Hash32>,
    pub issuance_id: Option<IssuanceId>,
    pub signed_tx_id: Option<ChainTxId>,
    pub error: Option<OicError>,
}

/// Folded view of one operation family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub operation_family_id: OperationFamilyId,
    /// Same as [`OperationStore::lifecycle`].
    pub lifecycle: LifecycleState,
    /// The candidate of the most recent transition.
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    /// Latest value recorded for that candidate.
    pub session_id: Option<SigningSessionId>,
    pub reservation_id: Option<ReservationId>,
    pub envelope_body_hash: Option<Hash32>,
    pub issuance_id: Option<IssuanceId>,
    pub signed_tx_id: Option<ChainTxId>,
    pub last_error: Option<OicError>,
    /// Every transition of the family, in append order.
    pub transitions: Vec<Transition>,
}

/// States in which no signature can exist yet for a candidate.
pub fn is_pre_issuance(s: LifecycleState) -> bool {
    use LifecycleState::*;
    matches!(s, Draft | Built | Verified | PolicyEvaluated | AwaitingApproval | Reserved | Authorized | Rejected | ApprovalExpired | AbortedBeforeIssuance)
}

/// Durable, append-only lifecycle log.
pub trait OperationStore: Send + Sync {
    /// Append one transition (validated, see the module docs); returns only
    /// once it is durable.
    fn append(&self, transition: Transition) -> OicResult<()>;

    /// Every transition of `family`, in append order.
    fn transitions(&self, family: &OperationFamilyId) -> Vec<Transition>;

    /// Folded record of `family`, `None` if nothing was recorded.
    fn operation(&self, family: &OperationFamilyId) -> Option<OperationRecord> {
        fold(family, self.transitions(family))
    }

    /// Lifecycle of `family`: the latest transition's state, except that a
    /// pre-issuance state never hides a candidate that possibly issued (that
    /// candidate's latest state is reported instead). `Draft` when nothing
    /// was recorded.
    fn lifecycle(&self, family: &OperationFamilyId) -> LifecycleState {
        self.operation(family).map(|r| r.lifecycle).unwrap_or(LifecycleState::Draft)
    }
}

fn fold(family: &OperationFamilyId, transitions: Vec<Transition>) -> Option<OperationRecord> {
    let last = transitions.last()?.clone();
    let mut latest_per_candidate: BTreeMap<(&CandidateId, u32), LifecycleState> = BTreeMap::new();
    for t in &transitions {
        latest_per_candidate.insert((&t.candidate_id, t.candidate_revision), t.state);
    }
    // Most recently touched candidate whose current state possibly issued.
    let latest_issued = transitions
        .iter()
        .rev()
        .map(|t| latest_per_candidate[&(&t.candidate_id, t.candidate_revision)])
        .find(|s| !is_pre_issuance(*s));
    let lifecycle = match latest_issued {
        Some(s) if is_pre_issuance(last.state) => s,
        _ => last.state,
    };
    let mut rec = OperationRecord {
        operation_family_id: family.clone(),
        lifecycle,
        candidate_id: last.candidate_id.clone(),
        candidate_revision: last.candidate_revision,
        session_id: None,
        reservation_id: None,
        envelope_body_hash: None,
        issuance_id: None,
        signed_tx_id: None,
        last_error: None,
        transitions: Vec::new(),
    };
    for t in transitions.iter().filter(|t| t.candidate_id == last.candidate_id && t.candidate_revision == last.candidate_revision) {
        rec.session_id = t.session_id.clone().or(rec.session_id);
        rec.reservation_id = t.reservation_id.clone().or(rec.reservation_id);
        rec.envelope_body_hash = t.envelope_body_hash.or(rec.envelope_body_hash);
        rec.issuance_id = t.issuance_id.clone().or(rec.issuance_id);
        rec.signed_tx_id = t.signed_tx_id.clone().or(rec.signed_tx_id);
        rec.last_error = t.error.clone().or(rec.last_error);
    }
    rec.transitions = transitions;
    Some(rec)
}

/// In-memory index shared by both stores; enforces the issuance monotonicity rule.
#[derive(Default)]
struct Index(BTreeMap<OperationFamilyId, Vec<Transition>>);

impl Index {
    fn check(&self, t: &Transition) -> OicResult<()> {
        let prior = self
            .0
            .get(&t.operation_family_id)
            .and_then(|v| v.iter().rev().find(|x| x.candidate_id == t.candidate_id && x.candidate_revision == t.candidate_revision))
            .map(|x| x.state);
        if let Some(p) = prior {
            if !is_pre_issuance(p) && is_pre_issuance(t.state) {
                return Err(OicError::new(
                    ErrorCode::Conflict,
                    format!("candidate {} rev {} possibly issued ({p:?}); it cannot move back to {:?}", t.candidate_id, t.candidate_revision, t.state),
                ));
            }
        }
        Ok(())
    }

    fn insert(&mut self, t: Transition) {
        self.0.entry(t.operation_family_id.clone()).or_default().push(t);
    }

    fn get(&self, family: &OperationFamilyId) -> Vec<Transition> {
        self.0.get(family).cloned().unwrap_or_default()
    }
}

/// Volatile store (tests, embedding).
#[derive(Default)]
pub struct InMemoryOperationStore(Mutex<Index>);

impl InMemoryOperationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl OperationStore for InMemoryOperationStore {
    fn append(&self, transition: Transition) -> OicResult<()> {
        let mut idx = self.0.lock();
        idx.check(&transition)?;
        idx.insert(transition);
        Ok(())
    }

    fn transitions(&self, family: &OperationFamilyId) -> Vec<Transition> {
        self.0.lock().get(family)
    }
}

fn io_err(what: &str, e: std::io::Error) -> OicError {
    OicError::internal(format!("operation store {what}: {e}"))
}

struct FileInner {
    file: File,
    index: Index,
}

/// Append-only JSON-lines store with an `fsync` after every append.
pub struct FileOperationStore {
    path: PathBuf,
    inner: Mutex<FileInner>,
}

impl FileOperationStore {
    /// Open (creating if absent) and replay the log at `path`.
    pub fn open(path: impl AsRef<Path>) -> OicResult<Self> {
        let path = path.as_ref().to_path_buf();
        let existed = path.exists();
        let mut file = OpenOptions::new().read(true).append(true).create(true).open(&path).map_err(|e| io_err("open", e))?;
        if !existed {
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                File::open(dir).and_then(|d| d.sync_all()).map_err(|e| io_err("directory sync", e))?;
            }
        }
        let mut raw = Vec::new();
        file.read_to_end(&mut raw).map_err(|e| io_err("read", e))?;
        let complete = raw.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        let mut index = Index::default();
        for (n, line) in raw[..complete].split(|b| *b == b'\n').enumerate().filter(|(_, l)| !l.is_empty()) {
            let t: Transition = serde_json::from_slice(line)
                .map_err(|e| OicError::new(ErrorCode::RecoveryRequired, format!("operation store line {} is malformed: {e}", n + 1)))?;
            index.check(&t).map_err(|e| OicError::new(ErrorCode::RecoveryRequired, format!("operation store line {} violates the log rules: {}", n + 1, e.detail)))?;
            index.insert(t);
        }
        if complete < raw.len() {
            // A torn tail was never acknowledged by `append`; drop it so the
            // next append starts on a line boundary.
            file.set_len(complete as u64).map_err(|e| io_err("truncate torn tail", e))?;
            file.sync_all().map_err(|e| io_err("sync", e))?;
        }
        file.seek(SeekFrom::End(0)).map_err(|e| io_err("seek", e))?;
        Ok(FileOperationStore { path, inner: Mutex::new(FileInner { file, index }) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl OperationStore for FileOperationStore {
    fn append(&self, transition: Transition) -> OicResult<()> {
        let mut g = self.inner.lock();
        g.index.check(&transition)?;
        let mut line = serde_json::to_vec(&transition).map_err(|e| OicError::internal(format!("operation store encode: {e}")))?;
        line.push(b'\n');
        let len = g.file.metadata().map_err(|e| io_err("stat", e))?.len();
        if let Err(e) = g.file.write_all(&line).and_then(|_| g.file.sync_data()) {
            // Never leave a partial line for the next append to extend. If
            // the rollback fails too, reopen drops a torn tail and replays a
            // complete line as recorded (the caller already saw the error).
            let _ = g.file.set_len(len);
            return Err(io_err("append", e));
        }
        g.index.insert(transition);
        Ok(())
    }

    fn transitions(&self, family: &OperationFamilyId) -> Vec<Transition> {
        self.inner.lock().index.get(family)
    }
}
