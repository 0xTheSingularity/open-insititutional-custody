use oic_domain_types::*;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub(crate) fn io(error: impl std::fmt::Display) -> OicError {
    OicError::new(
        ErrorCode::RecoveryRequired,
        format!("local stack storage: {error}"),
    )
}

pub(crate) fn private_directory(path: &Path) -> OicResult<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(io)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(io(
                "state/credential directory must be a real directory with mode 0700",
            ));
        }
    } else {
        fs::create_dir_all(path).map_err(io)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io)?;
        File::open(path.parent().unwrap_or(Path::new(".")))
            .and_then(|f| f.sync_all())
            .map_err(io)?;
    }
    Ok(())
}

pub(crate) fn read<T: DeserializeOwned>(path: &Path) -> OicResult<T> {
    let metadata = fs::metadata(path).map_err(io)?;
    if metadata.len() > 16 * 1024 * 1024 {
        return Err(io("configuration exceeds 16 MiB"));
    }
    serde_json::from_slice(&fs::read(path).map_err(io)?).map_err(io)
}

pub(crate) fn write_new<T: Serialize>(path: &Path, value: &T) -> OicResult<()> {
    write_new_bytes(path, &serde_json::to_vec_pretty(value).map_err(io)?)
}

pub(crate) fn write_new_bytes(path: &Path, bytes: &[u8]) -> OicResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    File::open(path.parent().unwrap_or(Path::new(".")))
        .and_then(|f| f.sync_all())
        .map_err(io)
}

pub(crate) fn replace<T: Serialize>(path: &Path, value: &T) -> OicResult<()> {
    let temp = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .map_err(io)?;
    file.write_all(&serde_json::to_vec(value).map_err(io)?)
        .map_err(io)?;
    file.sync_all().map_err(io)?;
    fs::rename(&temp, path).map_err(io)?;
    File::open(path.parent().unwrap_or(Path::new(".")))
        .and_then(|f| f.sync_all())
        .map_err(io)
}

pub(crate) fn protect_files(path: &Path) -> OicResult<()> {
    for entry in fs::read_dir(path).map_err(io)? {
        let entry = entry.map_err(io)?;
        if entry.file_type().map_err(io)?.is_file() {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600)).map_err(io)?;
        }
    }
    Ok(())
}
