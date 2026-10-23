//! Serializable transactional stores for [`AuthorityState`].
//!
//! `transact` runs the closure against a private copy of the state under the
//! store's single lock; the copy replaces the committed state only if the
//! closure succeeds *and* the durability hook succeeds. A failing closure or
//! a failing persist therefore leaves no partial write (A10).

use crate::receipts::{state_hash, verify_checkpoint, SignedCheckpoint};
use crate::state::{AuthorityState, ReservationState};
use ed25519_dalek::VerifyingKey;
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes, is_canonical};
use oic_domain_types::*;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// A serializable store. All calls are atomic with respect to each other.
pub trait AuthorityStore: Send + Sync {
    /// Run `f` as one serializable transaction: all of its writes commit, or none.
    fn transact<R>(&self, f: impl FnOnce(&mut AuthorityState) -> OicResult<R>) -> OicResult<R>;
    /// Consistent read of the committed state.
    fn read<R>(&self, f: impl FnOnce(&AuthorityState) -> R) -> OicResult<R>;
}

/// Durability hook invoked with the would-be committed state; an error aborts the commit.
pub type PersistHook = Box<dyn Fn(&AuthorityState) -> OicResult<()> + Send + Sync>;

/// In-memory store behind one `parking_lot::Mutex`.
pub struct InMemoryAuthorityStore {
    state: Mutex<AuthorityState>,
    persist: Option<PersistHook>,
}

impl Default for InMemoryAuthorityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryAuthorityStore {
    pub fn new() -> Self {
        Self::from_state(AuthorityState::default())
    }
    pub fn from_state(state: AuthorityState) -> Self {
        InMemoryAuthorityStore { state: Mutex::new(state), persist: None }
    }
    /// Install a persist-on-commit hook (replication, WAL, fault injection).
    pub fn with_persist_hook(mut self, hook: PersistHook) -> Self {
        self.persist = Some(hook);
        self
    }
    /// Clone of the committed state.
    pub fn snapshot(&self) -> AuthorityState {
        self.state.lock().clone()
    }
}

impl AuthorityStore for InMemoryAuthorityStore {
    fn transact<R>(&self, f: impl FnOnce(&mut AuthorityState) -> OicResult<R>) -> OicResult<R> {
        let mut guard = self.state.lock();
        let mut work = guard.clone();
        let out = f(&mut work)?;
        if let Some(hook) = &self.persist {
            hook(&work)?;
        }
        *guard = work;
        Ok(out)
    }

    fn read<R>(&self, f: impl FnOnce(&AuthorityState) -> R) -> OicResult<R> {
        Ok(f(&self.state.lock()))
    }
}

/// Versioned on-disk snapshot wrapper.
#[derive(Serialize, Deserialize)]
struct SnapshotFile {
    format: String,
    state: AuthorityState,
}

const SNAPSHOT_FORMAT: &str = "oic-authority-snapshot/v2";
/// Snapshots written before `ReservationRecord::reserved_freeze_epoch` existed.
/// A pending reservation in one of these has no recoverable freeze epoch.
const SNAPSHOT_FORMAT_V1: &str = "oic-authority-snapshot/v1";

fn unavailable(detail: impl std::fmt::Display) -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, format!("store: {detail}"))
}

fn recovery(detail: impl Into<String>) -> OicError {
    OicError::new(ErrorCode::RecoveryRequired, detail)
}

/// File-backed store. After every successful transaction the canonical state
/// is written atomically (temp file, fsync, rename, directory fsync) and the
/// high-water-mark sidecar `<path>.hwm` is advanced. Opening a snapshot older
/// than the high-water mark, an explicit minimum, or an independent witness
/// checkpoint fails with `RecoveryRequired`.
///
/// Snapshots are bounded by the canonical decoder limits (4 MiB, 65 536
/// items); a commit that would exceed them is refused rather than written
/// unreadable.
pub struct FileAuthorityStore {
    path: PathBuf,
    state: Mutex<AuthorityState>,
}

impl FileAuthorityStore {
    /// Open (or create) the snapshot at `path`. Refuses when the snapshot's
    /// commit sequence is below the sidecar high-water mark or below
    /// `expected_min_commit_sequence`.
    pub fn open(path: impl AsRef<Path>, expected_min_commit_sequence: Option<u64>) -> OicResult<Self> {
        let path = path.as_ref().to_path_buf();
        let state = load_snapshot(&path)?;
        let hwm = read_hwm(&path)?;
        let floor = hwm.max(expected_min_commit_sequence.unwrap_or(0));
        if state.commit_sequence < floor {
            return Err(recovery(format!(
                "snapshot commit_sequence {} is older than highest seen {floor}: possible rollback",
                state.commit_sequence
            )));
        }
        Ok(FileAuthorityStore { path, state: Mutex::new(state) })
    }

    /// Open, additionally requiring the snapshot to be at least as new as an
    /// independently held, authority-signed checkpoint, and identical to it
    /// at the same commit sequence.
    pub fn open_with_witness(path: impl AsRef<Path>, witness: &SignedCheckpoint, authority_pubkey: &VerifyingKey) -> OicResult<Self> {
        verify_checkpoint(witness, authority_pubkey)?;
        let store = Self::open(path, Some(witness.body.commit_sequence))?;
        {
            let st = store.state.lock();
            if st.commit_sequence == witness.body.commit_sequence && state_hash(&st)? != witness.body.state_hash {
                return Err(recovery("snapshot diverges from witness checkpoint at the same commit sequence"));
            }
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn snapshot(&self) -> AuthorityState {
        self.state.lock().clone()
    }

    fn persist(&self, state: &AuthorityState) -> OicResult<()> {
        let file = SnapshotFile { format: SNAPSHOT_FORMAT.into(), state: state.clone() };
        let bytes = canonical_bytes(&file).map_err(unavailable)?;
        if !is_canonical(&bytes) {
            return Err(unavailable("state exceeds canonical snapshot limits"));
        }
        write_atomic(&self.path, &bytes)?;
        let hwm = read_hwm(&self.path)?.max(state.commit_sequence);
        write_atomic(&hwm_path(&self.path), hwm.to_string().as_bytes())
    }
}

impl AuthorityStore for FileAuthorityStore {
    fn transact<R>(&self, f: impl FnOnce(&mut AuthorityState) -> OicResult<R>) -> OicResult<R> {
        let mut guard = self.state.lock();
        let mut work = guard.clone();
        let out = f(&mut work)?;
        if work != *guard {
            self.persist(&work)?;
        }
        *guard = work;
        Ok(out)
    }

    fn read<R>(&self, f: impl FnOnce(&AuthorityState) -> R) -> OicResult<R> {
        Ok(f(&self.state.lock()))
    }
}

fn hwm_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".hwm");
    PathBuf::from(s)
}

fn load_snapshot(path: &Path) -> OicResult<AuthorityState> {
    match fs::read(path) {
        Ok(bytes) => {
            let file: SnapshotFile = from_canonical_bytes(&bytes).map_err(|e| recovery(format!("snapshot unreadable: {}", e.detail)))?;
            match file.format.as_str() {
                SNAPSHOT_FORMAT => Ok(file.state),
                SNAPSHOT_FORMAT_V1 => migrate_v1(file.state),
                other => Err(recovery(format!("unknown snapshot format {other}"))),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AuthorityState::default()),
        Err(e) => Err(unavailable(e)),
    }
}

/// Upgrade a v1 snapshot. v1 covers records written before
/// `reserved_freeze_epoch` existed, which serde gives an epoch of zero. A
/// pending (`Reserved`) record whose epoch matches the snapshot's current
/// freeze epoch is still releasable and its epoch is trustworthy: a stored
/// nonzero epoch came from a version that had the field, and a defaulted zero
/// against a current zero means no freeze ever happened, since the epoch only
/// increases. Terminal records never re-run the release check. A pending record
/// whose epoch differs is refused at release by this version and may be an old
/// record whose real epoch was lost, so the upgrade stops with
/// `RecoveryRequired` instead of loading it stuck. Draining has to happen on the
/// previous version, because this one refuses to open the store, and it has to
/// be an abort: a pre-field binary neither records nor checks the epoch, so
/// releasing there would cross the very freeze this check exists to respect.
fn migrate_v1(state: AuthorityState) -> OicResult<AuthorityState> {
    let current = state.freeze.freeze_epoch;
    let stale = state
        .reservations
        .values()
        .filter(|r| r.state == ReservationState::Reserved && r.reserved_freeze_epoch != current)
        .count();
    if stale > 0 {
        return Err(recovery(format!(
            "v1 snapshot has {stale} pending reservation(s) made under a freeze epoch other than the current one; \
             abort them with the previous version, upgrade with none pending, then re-reserve"
        )));
    }
    Ok(state)
}

fn read_hwm(path: &Path) -> OicResult<u64> {
    match fs::read_to_string(hwm_path(path)) {
        Ok(s) => s.trim().parse::<u64>().map_err(|_| recovery("high-water-mark sidecar is corrupt")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(unavailable(e)),
    }
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
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        // Directory fsync makes the rename durable on POSIX filesystems.
        if let Ok(d) = fs::File::open(dir) {
            d.sync_all().map_err(unavailable)?;
        }
    }
    Ok(())
}
