//! Append-only JSON-lines file with fsync on every append and verified replay.
//!
//! Each record is one line: `serde_json(record) || '\n'`. An append is
//! acknowledged only after `sync_data` returns. On open:
//!
//! * a final line without its terminating newline is a torn write that was
//!   never acknowledged; it is truncated away;
//! * a *complete* line that does not decode means the history was altered and
//!   the open fails with `RecoveryRequired`.

use oic_domain_types::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) fn unavailable(detail: impl std::fmt::Display) -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, format!("submission store: {detail}"))
}

pub(crate) fn recovery(detail: impl Into<String>) -> OicError {
    OicError::new(ErrorCode::RecoveryRequired, detail)
}

pub(crate) struct JsonLines {
    path: PathBuf,
    file: File,
    len: u64,
    /// Set when a failed append could not be rolled back.
    poisoned: bool,
}

impl JsonLines {
    /// Open (or create) the file and return every acknowledged record in order.
    pub(crate) fn open<T: DeserializeOwned>(path: impl AsRef<Path>) -> OicResult<(Self, Vec<T>)> {
        let path = path.as_ref().to_path_buf();
        let existed = path.exists();
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path).map_err(unavailable)?;
        if !existed {
            sync_parent_dir(&path)?;
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(unavailable)?;
        let mut records = Vec::new();
        let mut pos = 0usize;
        while let Some(nl) = bytes[pos..].iter().position(|b| *b == b'\n') {
            let line = &bytes[pos..pos + nl];
            let rec: T = serde_json::from_slice(line).map_err(|e| recovery(format!("{}: record at offset {pos} unreadable: {e}", path.display())))?;
            records.push(rec);
            pos += nl + 1;
        }
        let len = pos as u64;
        if (bytes.len() as u64) > len {
            file.set_len(len).map_err(unavailable)?;
            file.sync_all().map_err(unavailable)?;
        }
        Ok((JsonLines { path, file, len, poisoned: false }, records))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record and fsync before returning. A failed write is
    /// truncated back to the acknowledged prefix.
    pub(crate) fn append<T: Serialize>(&mut self, rec: &T) -> OicResult<()> {
        if self.poisoned {
            return Err(recovery("file tail is in an unknown state after a failed append; reopen to recover"));
        }
        let mut line = serde_json::to_vec(rec).map_err(|e| OicError::internal(format!("record serialization failed: {e}")))?;
        line.push(b'\n');
        let res = self.file.seek(SeekFrom::Start(self.len)).and_then(|_| self.file.write_all(&line)).and_then(|_| self.file.sync_data());
        if let Err(e) = res {
            if self.file.set_len(self.len).and_then(|_| self.file.sync_all()).is_err() {
                self.poisoned = true;
            }
            return Err(unavailable(e));
        }
        self.len += line.len() as u64;
        Ok(())
    }
}

/// Directory fsync makes a create durable on POSIX filesystems.
fn sync_parent_dir(path: &Path) -> OicResult<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(d) = File::open(dir) {
            d.sync_all().map_err(unavailable)?;
        }
    }
    Ok(())
}
