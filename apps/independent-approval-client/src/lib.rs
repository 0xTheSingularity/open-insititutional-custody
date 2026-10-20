//! # oic-approval-client
//!
//! The independently distributed approval client of RFC 0001 §4.3 and
//! RFC 0002 §8 (threat tests A34/C15). It never trusts text supplied by the
//! management console: every value it shows or signs is recomputed from the
//! signed objects of an [`ApprovalPackage`](oic_domain_types::ApprovalPackage)
//! by the chain adapters compiled into this binary, whose verifier build
//! hashes the operator pins in the trust file.
//!
//! * [`trust`]: the trust-roots file (administrative roster and quorum,
//!   enrolled chain profiles, accepted verifier builds) and the pinned
//!   adapters.
//! * [`keyfile`]: approver credentials encrypted at rest
//!   (PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305).
//! * [`commands`]: one function per `oic-approve` subcommand. The binary is
//!   a thin clap layer over these functions.
//!
//! Every command returns a [`ClientError`] whose [`exit_code`](ClientError::exit_code)
//! is the process exit status: `0` ok, `2` usage, `3` verification refused,
//! `4` destination mismatch, `5` I/O.

pub mod commands;
pub mod keyfile;
pub mod trust;

use oic_domain_types::{ErrorCode, OicError};
use std::fmt;
use std::io::Write;
use std::path::Path;

/// Success.
pub const EXIT_OK: i32 = 0;
/// Malformed command line or argument value.
pub const EXIT_USAGE: i32 = 2;
/// A signature, scope, hash, freshness, or confirmation check refused.
pub const EXIT_REFUSED: i32 = 3;
/// The candidate bytes pay an address other than the registry destination.
pub const EXIT_DESTINATION_MISMATCH: i32 = 4;
/// A file could not be read, parsed, or written.
pub const EXIT_IO: i32 = 5;

/// Typed failure of a client command; each variant maps to one exit code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// Bad argument value (exit 2).
    Usage(String),
    /// Verification refused (exit 3). Carries the stable verifier error.
    Refused(OicError),
    /// Decoded recipient differs from the registry destination (exit 4).
    DestinationMismatch(String),
    /// Reading, parsing, or writing a file failed (exit 5).
    Io(String),
}

impl ClientError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ClientError::Usage(_) => EXIT_USAGE,
            ClientError::Refused(_) => EXIT_REFUSED,
            ClientError::DestinationMismatch(_) => EXIT_DESTINATION_MISMATCH,
            ClientError::Io(_) => EXIT_IO,
        }
    }

    /// The verifier error code for refusals, if any.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ClientError::Refused(e) => Some(e.code),
            _ => None,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Usage(d) => write!(f, "usage: {d}"),
            ClientError::Refused(e) => write!(f, "refused: {e}"),
            ClientError::DestinationMismatch(d) => write!(f, "destination mismatch: {d}"),
            ClientError::Io(d) => write!(f, "i/o: {d}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<OicError> for ClientError {
    fn from(e: OicError) -> Self {
        ClientError::Refused(e)
    }
}

pub type ClientResult<T> = Result<T, ClientError>;

pub(crate) fn io_err(path: &Path, what: &str, e: impl fmt::Display) -> ClientError {
    ClientError::Io(format!("{what} {}: {e}", path.display()))
}

pub(crate) fn out_err(e: std::io::Error) -> ClientError {
    ClientError::Io(format!("writing output: {e}"))
}

/// Read and parse a JSON file.
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> ClientResult<T> {
    let bytes = std::fs::read(path).map_err(|e| io_err(path, "cannot read", e))?;
    serde_json::from_slice(&bytes).map_err(|e| io_err(path, "cannot parse", e))
}

/// Create `path` (which must not exist) with `bytes`. On Unix the file is
/// created with `mode` from the start, so secrets are never world-readable,
/// even briefly. A partially written file is removed.
pub fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> ClientResult<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(path).map_err(|e| io_err(path, "cannot create (refusing to overwrite an existing file)", e))?;
    let written = f.write_all(bytes).and_then(|_| f.sync_all());
    if let Err(e) = written {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(io_err(path, "cannot write", e));
    }
    Ok(())
}

/// Serialize `value` as pretty JSON into a new file.
pub fn write_new_json<T: serde::Serialize>(path: &Path, value: &T, mode: u32) -> ClientResult<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| ClientError::Io(format!("cannot serialize {}: {e}", path.display())))?;
    bytes.push(b'\n');
    write_new_file(path, &bytes, mode)
}
