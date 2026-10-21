use crate::source::EffectKind;
use ed25519_dalek::{Signature, VerifyingKey};
use fs2::FileExt;
use oic_canonical_encoding::domain_hash;
use oic_domain_types::*;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub address: DepositAddress,
    pub activation: AddressActivation,
    pub dust_threshold: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MovementRecord {
    pub movement: ObservedMovement,
    pub kind: StoredEffectKind,
    pub entries: Vec<JournalEntryId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum StoredEffectKind {
    Transfer,
    Fee,
    AccountFunding { account: Bytes },
}

impl From<EffectKind> for StoredEffectKind {
    /// Preserve the discovered effect kind in the persisted movement record.
    fn from(k: EffectKind) -> Self {
        match k {
            EffectKind::Transfer => Self::Transfer,
            EffectKind::Fee => Self::Fee,
            EffectKind::AccountFunding { account } => Self::AccountFunding { account },
        }
    }
}

/// Export contains only business records, never chain keys or MPC material.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationsExport {
    pub revision: u64,
    pub institution_id: Option<InstitutionId>,
    pub environment_id: Option<EnvironmentId>,
    pub enrollments: BTreeMap<DepositAddressId, Enrollment>,
    pub assets: BTreeMap<AssetId, Asset>,
    pub cursors: BTreeMap<ChainProfileId, IndexCursor>,
    pub scanned_blocks: BTreeMap<ChainProfileId, BTreeMap<u64, Bytes>>,
    pub(crate) movements: BTreeMap<MovementId, MovementRecord>,
    pub journal: Vec<JournalEntry>,
    pub cases: BTreeMap<CaseId, DepositCase>,
    pub checkpoints: Vec<ReconciliationCheckpoint>,
    pub events: Vec<LifecycleEvent>,
    pub backfills: Vec<BackfillJob>,
    pub workflows: BTreeMap<WorkflowId, WorkflowRecord>,
    pub(crate) workflow_contexts: BTreeMap<WorkflowId, crate::workflow::WorkflowContext>,
    pub(crate) operations: BTreeMap<ChainTxId, OperationFamilyId>,
}

impl OperationsExport {
    /// Return copies of all movement records, including quarantined and reversed movements.
    pub fn movements(&self) -> Vec<ObservedMovement> {
        self.movements
            .values()
            .map(|m| m.movement.clone())
            .collect()
    }

    /// Check journal hashes and sequence links, event sequences and signatures,
    /// and checkpoint signatures and journal commitments using the service key.
    /// Returns `RecoveryRequired` for broken chains or commitments and
    /// `InvalidSignature` for invalid service signatures; hashing errors propagate.
    pub fn verify(&self, key: &VerifyingKey) -> OicResult<()> {
        let mut previous = Hash32::ZERO;
        for (i, entry) in self.journal.iter().enumerate() {
            if entry.body.sequence != i as u64 + 1
                || entry.body.previous_entry_hash != previous
                || domain_hash(domains::JOURNAL, &entry.body)? != entry.entry_hash
            {
                return Err(OicError::new(
                    ErrorCode::RecoveryRequired,
                    "journal chain is corrupt",
                ));
            }
            previous = entry.entry_hash;
        }
        for (i, event) in self.events.iter().enumerate() {
            if event.body.sequence != i as u64 + 1 {
                return Err(OicError::new(
                    ErrorCode::RecoveryRequired,
                    "event sequence gap",
                ));
            }
            verify_signature(
                key,
                domain_hash(domains::WEBHOOK, &event.body)?,
                &event.signature,
            )?;
        }
        for checkpoint in &self.checkpoints {
            verify_signature(
                key,
                domain_hash(domains::RECONCILIATION, &checkpoint.body)?,
                &checkpoint.signature,
            )?;
            let seq = checkpoint.body.journal_sequence as usize;
            if seq > self.journal.len()
                || checkpoint.body.journal_head_hash
                    != seq
                        .checked_sub(1)
                        .map(|i| self.journal[i].entry_hash)
                        .unwrap_or(Hash32::ZERO)
            {
                return Err(OicError::new(
                    ErrorCode::RecoveryRequired,
                    "checkpoint journal commitment mismatch",
                ));
            }
        }
        Ok(())
    }
}

/// Verify an Ed25519 service signature over the supplied hash bytes.
/// Returns `InvalidSignature` for a different scheme, malformed signature,
/// or verification failure.
pub fn verify_signature(
    key: &VerifyingKey,
    hash: Hash32,
    signature: &SignatureBytes,
) -> OicResult<()> {
    if signature.scheme != SchemeId::Ed25519Pure {
        return Err(OicError::invalid_signature(
            "wrong service signature scheme",
        ));
    }
    let sig = Signature::from_slice(signature.bytes.as_slice())
        .map_err(|_| OicError::invalid_signature("service signature length"))?;
    key.verify_strict(&hash.0, &sig)
        .map_err(|_| OicError::invalid_signature("service signature invalid"))
}

/// Convert persistence failures to `AuthorityUnavailable`.
fn io_error(e: impl std::fmt::Display) -> OicError {
    OicError::new(
        ErrorCode::AuthorityUnavailable,
        format!("operations store: {e}"),
    )
}

/// One writer per file, atomic snapshots, fsynced file and directory. A failed
/// durability operation poisons the live store: reopen and recover, do not
/// continue dispatching intents with an ambiguous commit outcome.
pub struct OperationsStore {
    inner: Mutex<Option<OperationsExport>>,
    path: Option<PathBuf>,
    _lock: Option<File>,
}

impl OperationsStore {
    /// Create an empty operations store without file persistence or writer fencing.
    pub fn memory() -> Self {
        Self {
            inner: Mutex::new(Some(OperationsExport::default())),
            path: None,
            _lock: None,
        }
    }

    /// Open a snapshot while holding an exclusive sidecar writer lock.
    /// A missing snapshot starts empty. Returns `ResourceConflict` when the writer
    /// lock cannot be acquired, `RecoveryRequired` for unreadable snapshot data,
    /// a corrupt high-water mark, or a revision below that mark, and
    /// `AuthorityUnavailable` for I/O failures. Cryptographic integrity is checked
    /// separately when opening the reconciler.
    pub fn open(path: impl AsRef<Path>) -> OicResult<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.with_extension("lock"))
            .map_err(io_error)?;
        lock.try_lock_exclusive()
            .map_err(|_| OicError::resource_conflict("operations store already has a writer"))?;
        let data: OperationsExport = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                OicError::new(
                    ErrorCode::RecoveryRequired,
                    format!("operations snapshot unreadable: {e}"),
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => OperationsExport::default(),
            Err(e) => return Err(io_error(e)),
        };
        let hwm_path = path.with_extension("hwm");
        let floor: u64 = match fs::read_to_string(&hwm_path) {
            Ok(s) => s.parse().map_err(|_| {
                OicError::new(
                    ErrorCode::RecoveryRequired,
                    "operations high-water mark corrupt",
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(io_error(e)),
        };
        if data.revision < floor {
            return Err(OicError::new(
                ErrorCode::RecoveryRequired,
                "operations snapshot rollback detected",
            ));
        }
        Ok(Self {
            inner: Mutex::new(Some(data)),
            path: Some(path),
            _lock: Some(lock),
        })
    }

    /// Return a copy of the current snapshot. Returns `RecoveryRequired` if an
    /// ambiguous persistence failure has poisoned the store; reopen it to recover.
    pub fn export(&self) -> OicResult<OperationsExport> {
        self.inner.lock().clone().ok_or_else(|| {
            OicError::new(
                ErrorCode::RecoveryRequired,
                "reopen operations store after ambiguous write",
            )
        })
    }

    /// Apply a closure to a snapshot copy and commit only successful changes.
    /// Unchanged snapshots do not advance the revision. Closure errors propagate
    /// without committing. File persistence errors return `AuthorityUnavailable`
    /// and poison the store because the durable outcome is uncertain; subsequent
    /// access returns `RecoveryRequired`. Revision overflow returns `Internal`.
    pub(crate) fn transact<T>(
        &self,
        f: impl FnOnce(&mut OperationsExport) -> OicResult<T>,
    ) -> OicResult<T> {
        let mut guard = self.inner.lock();
        let mut work = guard.clone().ok_or_else(|| {
            OicError::new(
                ErrorCode::RecoveryRequired,
                "operations store must be reopened",
            )
        })?;
        let out = f(&mut work)?;
        if guard.as_ref() == Some(&work) {
            return Ok(out);
        }
        work.revision = work
            .revision
            .checked_add(1)
            .ok_or_else(|| OicError::internal("revision overflow"))?;
        if let Some(path) = &self.path {
            let bytes = serde_json::to_vec(&work).map_err(io_error)?;
            // Persist the fence first. An interrupted snapshot replacement can
            // only make a later open fail closed, never revive an old trigger.
            if let Err(e) = atomic_write(
                &path.with_extension("hwm"),
                work.revision.to_string().as_bytes(),
            )
            .and_then(|_| atomic_write(path, &bytes))
            {
                *guard = None;
                return Err(e);
            }
        }
        *guard = Some(work);
        Ok(out)
    }
}

/// Replace a snapshot through a temporary file and sync the file and directory.
/// Returns `AuthorityUnavailable` on I/O failure, possibly after replacement.
fn atomic_write(path: &Path, bytes: &[u8]) -> OicResult<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.as_file().sync_all().map_err(io_error)?;
    file.persist(path).map_err(io_error)?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(io_error)
}
