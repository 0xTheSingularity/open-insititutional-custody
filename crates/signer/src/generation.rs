//! Durable signer-instance generations (RFC 0001 §6.3, A12).
//!
//! Every [`crate::Signer::open`] loads the last generation, adds one, and
//! persists the result *before* the signer can allocate any one-time state.
//! A cloned VM, a restored image, or a second process over the same store
//! therefore always runs under a strictly newer generation than every
//! instance that opened before it, and peers fence the older one by
//! generation.

use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes};
use oic_domain_types::*;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// A signer-instance generation as persisted by a [`GenerationStore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignerGeneration(pub Epoch);

impl fmt::Display for SignerGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "generation {}", self.0)
    }
}

/// Durable, monotonic storage for the signer generation. `store` must return
/// only after the value is durable and must refuse to move backwards.
pub trait GenerationStore: Send + Sync {
    fn load(&self) -> OicResult<Option<Epoch>>;
    fn store(&self, g: Epoch) -> OicResult<()>;
}

fn backwards(cur: Epoch, g: Epoch) -> OicError {
    OicError::new(ErrorCode::Conflict, format!("signer generation cannot move backwards from {cur} to {g}"))
}

/// Process-local store for tests and embedding. Shared between instances via
/// `Arc` it models "two processes over the same durable store".
#[derive(Default)]
pub struct InMemoryGenerationStore(Mutex<Option<Epoch>>);

impl InMemoryGenerationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl GenerationStore for InMemoryGenerationStore {
    fn load(&self) -> OicResult<Option<Epoch>> {
        Ok(*self.0.lock())
    }

    fn store(&self, g: Epoch) -> OicResult<()> {
        let mut cur = self.0.lock();
        if let Some(c) = *cur {
            if g < c {
                return Err(backwards(c, g));
            }
        }
        *cur = Some(g);
        Ok(())
    }
}

/// File format tag of [`FileGenerationStore`].
pub const GENERATION_FILE_FORMAT: &str = "oic-signer-generation/v1";

#[derive(Serialize, Deserialize)]
struct GenerationFile {
    format: String,
    generation: SignerGeneration,
}

/// File-backed store. The file holds the canonical CBOR of
/// `{format: "oic-signer-generation/v1", generation}`; it is replaced
/// atomically (temp file, `fsync`, rename, directory `fsync`). An unreadable
/// or foreign file fails with `RecoveryRequired`; it is never silently reset.
pub struct FileGenerationStore(pub PathBuf);

impl FileGenerationStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        FileGenerationStore(path.as_ref().to_path_buf())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

fn unavailable(detail: impl fmt::Display) -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, format!("generation store: {detail}"))
}

impl GenerationStore for FileGenerationStore {
    fn load(&self) -> OicResult<Option<Epoch>> {
        match fs::read(&self.0) {
            Ok(bytes) => {
                let f: GenerationFile = from_canonical_bytes(&bytes)
                    .map_err(|e| OicError::new(ErrorCode::RecoveryRequired, format!("generation file unreadable: {}", e.detail)))?;
                if f.format != GENERATION_FILE_FORMAT {
                    return Err(OicError::new(ErrorCode::RecoveryRequired, format!("unknown generation file format {}", f.format)));
                }
                Ok(Some(f.generation.0))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(unavailable(e)),
        }
    }

    fn store(&self, g: Epoch) -> OicResult<()> {
        if let Some(cur) = self.load()? {
            if g < cur {
                return Err(backwards(cur, g));
            }
        }
        let bytes = canonical_bytes(&GenerationFile { format: GENERATION_FILE_FORMAT.into(), generation: SignerGeneration(g) })?;
        let mut tmp = self.0.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        {
            let mut f = fs::File::create(&tmp).map_err(unavailable)?;
            f.write_all(&bytes).map_err(unavailable)?;
            f.sync_all().map_err(unavailable)?;
        }
        fs::rename(&tmp, &self.0).map_err(unavailable)?;
        if let Some(dir) = self.0.parent().filter(|d| !d.as_os_str().is_empty()) {
            let d = fs::File::open(dir).map_err(unavailable)?;
            d.sync_all().map_err(unavailable)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_store_is_monotonic() {
        let s = InMemoryGenerationStore::new();
        assert_eq!(s.load().unwrap(), None);
        s.store(Epoch(3)).unwrap();
        s.store(Epoch(3)).unwrap();
        assert_eq!(s.store(Epoch(2)).unwrap_err().code, ErrorCode::Conflict);
        assert_eq!(s.load().unwrap(), Some(Epoch(3)));
    }

    #[test]
    fn file_store_round_trips_refuses_backwards_and_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gen");
        let s = FileGenerationStore::new(&path);
        assert_eq!(s.path(), path.as_path());
        assert_eq!(s.load().unwrap(), None);
        s.store(Epoch(7)).unwrap();
        assert_eq!(FileGenerationStore(path.clone()).load().unwrap(), Some(Epoch(7)));
        assert_eq!(s.store(Epoch(6)).unwrap_err().code, ErrorCode::Conflict);
        s.store(Epoch(8)).unwrap();
        assert_eq!(s.load().unwrap(), Some(Epoch(8)));
        fs::write(&path, b"garbage").unwrap();
        assert_eq!(s.load().unwrap_err().code, ErrorCode::RecoveryRequired);
        let foreign = canonical_bytes(&GenerationFile { format: "other/v9".into(), generation: SignerGeneration(Epoch(1)) }).unwrap();
        fs::write(&path, foreign).unwrap();
        assert_eq!(s.load().unwrap_err().code, ErrorCode::RecoveryRequired);
        assert_eq!(SignerGeneration(Epoch(4)).to_string(), "generation 4");
    }
}
