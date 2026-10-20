//! File-backed append-only audit log.
//!
//! On-disk format: a sequence of frames, each `u32` big-endian length followed
//! by exactly that many bytes of the canonical CBOR encoding of one
//! [`AuditEvent`]. Every append writes one whole frame and fsyncs the file
//! before the event is acknowledged, then advances a high-water-mark sidecar
//! `<path>.hwm` (atomic replace + fsync).
//!
//! On open the whole file is replayed and the chain is re-verified (hashes,
//! event ids, linkage, sequence, signatures, service key id):
//!
//! * a final frame that is incomplete (crash in the middle of a write) is
//!   truncated away: it was never acknowledged;
//! * a *complete* frame that fails to decode or verify means the history was
//!   altered and the open fails with `RecoveryRequired`;
//! * a head sequence below the sidecar high-water mark or below
//!   `expected_min_sequence` means the file was rolled back and the open fails
//!   with `RecoveryRequired`.

use crate::chain::{seal_event, verify_next, AuditLog, AuditLogConfig, SealInput};
use crate::checkpoint::{sign_audit_checkpoint, AuditCheckpoint, AuditCheckpointBody};
use ed25519_dalek::VerifyingKey;
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes};
use oic_domain_types::*;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Upper bound on one encoded event frame. Events are bounded far below this
/// by [`MAX_DETAIL_BYTES`](crate::MAX_DETAIL_BYTES) and friends.
pub const MAX_FRAME_BYTES: u32 = 1024 * 1024;

fn unavailable(detail: impl std::fmt::Display) -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, format!("audit store: {detail}"))
}

fn recovery(detail: impl Into<String>) -> OicError {
    OicError::new(ErrorCode::RecoveryRequired, detail)
}

struct Inner {
    file: File,
    /// Length of the verified, acknowledged prefix of the file.
    len: u64,
    /// `(offset of payload, payload length)` per event; index = sequence - 1.
    frames: Vec<(u64, u32)>,
    head: Option<(u64, Hash32)>,
    /// Set when a failed append could not be rolled back; the file tail is
    /// then unknown and no further appends are accepted.
    poisoned: bool,
}

/// Durable audit log in one append-only file.
pub struct FileAuditLog {
    path: PathBuf,
    config: AuditLogConfig,
    truncated_tail_bytes: u64,
    inner: Mutex<Inner>,
}

impl FileAuditLog {
    /// Open (or create) the log at `path`, replaying and verifying every
    /// frame against `config`'s service key. See the module docs for the
    /// recovery rules.
    pub fn open(path: impl AsRef<Path>, expected_min_sequence: Option<u64>, config: AuditLogConfig) -> OicResult<Self> {
        let path = path.as_ref().to_path_buf();
        let existed = path.exists();
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path).map_err(unavailable)?;
        if !existed {
            sync_parent_dir(&path)?;
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(unavailable)?;
        let pubkey = config.verifying_key();

        let mut pos: usize = 0;
        let mut frames = Vec::new();
        let mut head: Option<(u64, Hash32)> = None;
        while pos < bytes.len() {
            let rest = &bytes[pos..];
            if rest.len() < 4 {
                break; // torn length prefix
            }
            let n = u32::from_be_bytes(rest[..4].try_into().expect("4 bytes"));
            let frame_end = 4usize.saturating_add(n as usize);
            if rest.len() < frame_end {
                break; // torn payload
            }
            if n == 0 || n > MAX_FRAME_BYTES {
                return Err(recovery(format!("audit frame at offset {pos} has invalid length {n}")));
            }
            let payload = &rest[4..frame_end];
            let event: AuditEvent =
                from_canonical_bytes(payload).map_err(|e| recovery(format!("audit frame at offset {pos} unreadable: {}", e.detail)))?;
            if event.service_key_id != config.service_key_id {
                return Err(recovery(format!("audit event {} names service key {} not {}", event.body.sequence, event.service_key_id, config.service_key_id)));
            }
            let next = verify_next(&event, &pubkey, head.unwrap_or((0, Hash32::ZERO)))
                .map_err(|e| recovery(format!("audit chain broken at offset {pos}: {}", e.detail)))?;
            head = Some(next);
            frames.push(((pos + 4) as u64, n));
            pos += frame_end;
        }
        let len = pos as u64;
        let truncated_tail_bytes = bytes.len() as u64 - len;
        if truncated_tail_bytes > 0 {
            file.set_len(len).map_err(unavailable)?;
            file.sync_all().map_err(unavailable)?;
        }

        let seq = head.map(|h| h.0).unwrap_or(0);
        let floor = read_hwm(&path)?.max(expected_min_sequence.unwrap_or(0));
        if seq < floor {
            return Err(recovery(format!("audit log head sequence {seq} is older than highest seen {floor}: possible rollback")));
        }
        Ok(FileAuditLog { path, config, truncated_tail_bytes, inner: Mutex::new(Inner { file, len, frames, head, poisoned: false }) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.config.verifying_key()
    }

    /// Bytes of an incomplete trailing frame discarded during `open`.
    pub fn truncated_tail_bytes(&self) -> u64 {
        self.truncated_tail_bytes
    }

    fn write_frame(inner: &mut Inner, frame: &[u8]) -> std::io::Result<()> {
        inner.file.seek(SeekFrom::Start(inner.len))?;
        inner.file.write_all(frame)?;
        inner.file.sync_data()
    }

    fn read_frame(inner: &mut Inner, offset: u64, n: u32) -> OicResult<AuditEvent> {
        let mut buf = vec![0u8; n as usize];
        inner.file.seek(SeekFrom::Start(offset)).map_err(unavailable)?;
        inner.file.read_exact(&mut buf).map_err(unavailable)?;
        from_canonical_bytes(&buf).map_err(|e| recovery(format!("audit frame at offset {offset} unreadable: {}", e.detail)))
    }
}

impl AuditLog for FileAuditLog {
    /// Appends and fsyncs one frame. If the frame write fails, the file is
    /// truncated back to the acknowledged prefix; if that also fails the log
    /// refuses further appends (`RecoveryRequired`). If the frame is durable
    /// but the high-water-mark update fails, the event *is* committed (and
    /// the in-memory head advances) but `AuthorityUnavailable` is returned so
    /// the operator learns rollback protection is degraded.
    fn append(&self, actor: &str, action: &str, object_commitments: BTreeMap<String, Hash32>, policy_epoch: Epoch, detail: &str) -> OicResult<AuditEvent> {
        let mut inner = self.inner.lock();
        if inner.poisoned {
            return Err(recovery("audit log tail is in an unknown state after a failed append; reopen to recover"));
        }
        let (event, h) = seal_event(&self.config, SealInput { head: inner.head, actor, action, object_commitments, policy_epoch, detail })?;
        let payload = canonical_bytes(&event)?;
        let n = u32::try_from(payload.len()).ok().filter(|n| *n <= MAX_FRAME_BYTES).ok_or_else(|| OicError::invalid_request("audit event exceeds frame limit"))?;
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&n.to_be_bytes());
        frame.extend_from_slice(&payload);
        if let Err(e) = Self::write_frame(&mut inner, &frame) {
            let len = inner.len;
            if inner.file.set_len(len).and_then(|_| inner.file.sync_all()).is_err() {
                inner.poisoned = true;
            }
            return Err(unavailable(e));
        }
        let offset = inner.len + 4;
        inner.frames.push((offset, n));
        inner.len += frame.len() as u64;
        inner.head = Some((event.body.sequence, h));
        write_atomic(&hwm_path(&self.path), event.body.sequence.to_string().as_bytes())
            .map_err(|e| unavailable(format!("event {} appended but high-water mark not advanced: {}", event.body.sequence, e.detail)))?;
        Ok(event)
    }

    fn head(&self) -> OicResult<Option<(u64, Hash32)>> {
        Ok(self.inner.lock().head)
    }

    fn events_since(&self, sequence: u64, limit: usize) -> OicResult<Vec<AuditEvent>> {
        let mut inner = self.inner.lock();
        let start = usize::try_from(sequence).unwrap_or(usize::MAX).min(inner.frames.len());
        let wanted: Vec<(u64, u32)> = inner.frames[start..].iter().take(limit).copied().collect();
        wanted.into_iter().map(|(off, n)| Self::read_frame(&mut inner, off, n)).collect()
    }

    fn checkpoint(&self) -> OicResult<AuditCheckpoint> {
        let head = self.inner.lock().head.unwrap_or((0, Hash32::ZERO));
        sign_audit_checkpoint(
            &self.config.signing_key,
            AuditCheckpointBody { service_key_id: self.config.service_key_id.clone(), sequence: head.0, head_event_hash: head.1, at: self.config.clock.now() },
        )
    }
}

fn hwm_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".hwm");
    PathBuf::from(s)
}

fn read_hwm(path: &Path) -> OicResult<u64> {
    match fs::read_to_string(hwm_path(path)) {
        Ok(s) => s.trim().parse::<u64>().map_err(|_| recovery("audit high-water-mark sidecar is corrupt")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(unavailable(e)),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> OicResult<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = File::create(&tmp).map_err(unavailable)?;
        f.write_all(bytes).map_err(unavailable)?;
        f.sync_all().map_err(unavailable)?;
    }
    fs::rename(&tmp, path).map_err(unavailable)?;
    sync_parent_dir(path)
}

/// Directory fsync makes a create or rename durable on POSIX filesystems.
fn sync_parent_dir(path: &Path) -> OicResult<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(d) = File::open(dir) {
            d.sync_all().map_err(unavailable)?;
        }
    }
    Ok(())
}
