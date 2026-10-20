//! Durable submission records (RFC 0001 §12.2).
//!
//! A [`SubmissionRecord`] is written with a [`AttemptOutcome::Pending`]
//! attempt *before* the signed bytes are handed to the chain. If the process
//! dies after that write and before the acknowledgement is recorded, the
//! reopened store still shows the pending attempt, which
//! [`crate::Broadcaster::recover`] turns into `SUBMISSION_UNKNOWN` — never into
//! "not sent".

use crate::durable::JsonLines;
use oic_adapter_api::SignedTransaction;
use oic_domain_types::*;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Outcome of one hand-off of the signed bytes to a chain client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    /// Durably recorded, chain call in flight (or the process died here).
    Pending,
    /// The client acknowledged acceptance into its mempool/queue. Not inclusion.
    Acknowledged { tx_id: ChainTxId, at: UnixSeconds },
    /// The client reported an error. An RPC error is not proof the bytes
    /// were not accepted (A18), so the submission is unknown, not failed.
    ErrorReported { code: ErrorCode, detail: String, at: UnixSeconds },
    /// Found `Pending` after a restart: the outcome is unknown.
    Interrupted { recovered_at: UnixSeconds },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionAttempt {
    pub attempt: u32,
    pub started_at: UnixSeconds,
    pub outcome: AttemptOutcome,
}

/// Everything the broadcaster knows about one operation family's signed
/// transaction. The signed bytes are retained so that invalidation can be
/// proved against exactly what may exist (§5.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionRecord {
    pub operation_family_id: OperationFamilyId,
    pub chain_profile_id: ChainProfileId,
    pub network_id: NetworkId,
    pub candidate: Candidate,
    pub signed: SignedTransaction,
    pub attempts: Vec<SubmissionAttempt>,
    /// Lifecycle as last reported by the authority, or `SUBMISSION_UNKNOWN` /
    /// `ISSUANCE_UNKNOWN` while the broadcaster cannot know the outcome.
    pub lifecycle: LifecycleState,
    /// Inclusion block of the last agreeing observation, cleared by a reorg.
    pub last_inclusion: Option<StateReference>,
    pub last_observation: Option<ChainObservation>,
    /// Conflicting sources were observed; nothing is fed to the authority any more.
    pub quarantined: bool,
    pub created_at: UnixSeconds,
    pub updated_at: UnixSeconds,
}

impl SubmissionRecord {
    /// True when some attempt has no known outcome or reported an error.
    pub fn has_unknown_attempt(&self) -> bool {
        self.attempts.iter().any(|a| !matches!(a.outcome, AttemptOutcome::Acknowledged { .. }))
    }
}

/// Durable store of submission records keyed by operation family.
pub trait SubmissionStore: Send + Sync {
    /// Insert or replace the record for its family. Durable when `Ok`.
    fn put(&self, record: &SubmissionRecord) -> OicResult<()>;
    fn get(&self, family: &OperationFamilyId) -> OicResult<Option<SubmissionRecord>>;
    fn list(&self) -> OicResult<Vec<SubmissionRecord>>;
}

/// Non-durable store for tests and embedding.
#[derive(Default)]
pub struct MemorySubmissionStore(Mutex<BTreeMap<OperationFamilyId, SubmissionRecord>>);

impl MemorySubmissionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SubmissionStore for MemorySubmissionStore {
    fn put(&self, record: &SubmissionRecord) -> OicResult<()> {
        self.0.lock().insert(record.operation_family_id.clone(), record.clone());
        Ok(())
    }
    fn get(&self, family: &OperationFamilyId) -> OicResult<Option<SubmissionRecord>> {
        Ok(self.0.lock().get(family).cloned())
    }
    fn list(&self) -> OicResult<Vec<SubmissionRecord>> {
        Ok(self.0.lock().values().cloned().collect())
    }
}

/// Append-only JSON-lines file of record snapshots; the last snapshot of a
/// family wins on reload. Every `put` is fsynced before it returns.
pub struct FileSubmissionStore {
    inner: Mutex<(JsonLines, BTreeMap<OperationFamilyId, SubmissionRecord>)>,
}

impl FileSubmissionStore {
    pub fn open(path: impl AsRef<Path>) -> OicResult<Self> {
        let (file, rows) = JsonLines::open::<SubmissionRecord>(path)?;
        let mut map = BTreeMap::new();
        for r in rows {
            map.insert(r.operation_family_id.clone(), r);
        }
        Ok(FileSubmissionStore { inner: Mutex::new((file, map)) })
    }

    pub fn path(&self) -> std::path::PathBuf {
        self.inner.lock().0.path().to_path_buf()
    }
}

impl SubmissionStore for FileSubmissionStore {
    fn put(&self, record: &SubmissionRecord) -> OicResult<()> {
        let mut g = self.inner.lock();
        g.0.append(record)?;
        g.1.insert(record.operation_family_id.clone(), record.clone());
        Ok(())
    }
    fn get(&self, family: &OperationFamilyId) -> OicResult<Option<SubmissionRecord>> {
        Ok(self.inner.lock().1.get(family).cloned())
    }
    fn list(&self) -> OicResult<Vec<SubmissionRecord>> {
        Ok(self.inner.lock().1.values().cloned().collect())
    }
}
