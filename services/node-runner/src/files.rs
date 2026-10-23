//! File formats of one provisioned node directory.
//!
//! Public configuration is JSON; roster-derived and secret material is the
//! workspace's canonical encoding. Secrets are mode 0600 under a 0700
//! directory, and reads refuse group/other access the same way the signer
//! core process does.

use oic_domain_types::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Signer,
    Gateway,
    Authority,
}

impl Role {
    pub fn membership_role(self) -> oic_membership::Role {
        match self {
            Role::Signer => oic_membership::Role::Signer,
            Role::Gateway => oic_membership::Role::Gateway,
            Role::Authority => oic_membership::Role::Authority,
        }
    }
}

/// `node.json`: the public description of one node directory.
#[derive(Serialize, Deserialize)]
pub struct NodeConfig {
    pub role: Role,
    pub index: usize,
    pub provisioned_at: UnixSeconds,
    /// Always true for directories this runner provisions. `run` refuses a
    /// configuration that claims otherwise, so nobody promotes these files
    /// to production by renaming a directory.
    pub development_only: bool,
}

/// Trust roots as provisioned bytes; Ed25519 credentials only.
#[derive(Serialize, Deserialize)]
pub struct ProvisionedRoots {
    pub authority_key: [u8; 32],
    pub admins: Vec<(CredentialId, [u8; 32])>,
    pub quorum: u8,
    pub builds: BTreeMap<AdapterId, Vec<Hash32>>,
    pub skew: u64,
}

impl ProvisionedRoots {
    pub fn into_roots(self) -> OicResult<oic_signer::TrustRoots> {
        let key = |bytes: &[u8; 32]| {
            ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| OicError::invalid_request("provisioned key is not a valid Ed25519 point"))
        };
        Ok(oic_signer::TrustRoots {
            authority_key_id: authority_key_id(),
            authority_pubkey: key(&self.authority_key)?,
            admin_keys: self.admins.iter().map(|(id, k)| Ok((id.clone(), key(k)?))).collect::<OicResult<Vec<_>>>()?,
            admin_quorum: self.quorum,
            approvers: Vec::new(),
            accepted_verifier_builds: self.builds,
            chain_profiles: Vec::new(),
            max_clock_skew_seconds: self.skew,
        })
    }
}

pub fn institution() -> InstitutionId {
    InstitutionId::unchecked("dev-institution")
}

pub fn environment() -> EnvironmentId {
    EnvironmentId::unchecked("dev-local")
}

pub fn key_id() -> KeyId {
    KeyId::unchecked("dev-chain-key")
}

pub fn authority_key_id() -> KeyId {
    KeyId::unchecked("dev-authority-key")
}

pub fn node_id(index: usize) -> NodeId {
    NodeId::unchecked(format!("node-{index}"))
}

pub fn participant(index: usize) -> ParticipantId {
    ParticipantId::unchecked(format!("participant-{index}"))
}

pub fn role_of(index: usize) -> Role {
    match index {
        0..=2 => Role::Signer,
        3 => Role::Gateway,
        _ => Role::Authority,
    }
}

fn io(what: &str) -> impl Fn(std::io::Error) -> OicError + '_ {
    move |e| OicError::internal(format!("{what}: {e}"))
}

pub fn private_dir(dir: &Path) -> OicResult<()> {
    fs::create_dir(dir).map_err(io("creating a node directory"))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io("restricting a node directory"))
}

pub fn write_secret(path: &Path, bytes: &[u8]) -> OicResult<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(io("creating a secret file"))?;
    file.write_all(bytes).map_err(io("writing a secret file"))?;
    file.sync_all().map_err(io("syncing a secret file"))
}

pub fn write_canonical<T: Serialize>(path: &Path, value: &T) -> OicResult<()> {
    write_secret(path, &oic_canonical_encoding::canonical_bytes(value)?)
}

/// Atomically replace a staged artifact, such as a roster update: write a
/// sibling temp file with the same 0600 discipline, then rename it over the
/// destination. `write_secret` stays refuse-to-overwrite for real secrets.
pub fn replace_canonical<T: Serialize>(path: &Path, value: &T) -> OicResult<()> {
    let staged = path.with_extension("staged");
    let _ = fs::remove_file(&staged);
    write_secret(&staged, &oic_canonical_encoding::canonical_bytes(value)?)?;
    fs::rename(&staged, path).map_err(io("staging a replacement file"))
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> OicResult<()> {
    let json = serde_json::to_vec_pretty(value).map_err(|e| OicError::internal(format!("encoding node.json: {e}")))?;
    write_secret(path, &json)
}

/// Read a file after checking the directory and file deny group/other access.
pub fn read_private(dir: &Path, name: &str) -> OicResult<Vec<u8>> {
    for target in [dir.to_path_buf(), dir.join(name)] {
        let mode = fs::metadata(&target).map_err(io("reading provisioned metadata"))?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(OicError::invalid_request(format!("{} is group/other accessible (mode {:o}); refuse to use it", target.display(), mode)));
        }
    }
    fs::read(dir.join(name)).map_err(io("reading a provisioned file"))
}

pub fn read_canonical<T: serde::de::DeserializeOwned>(dir: &Path, name: &str) -> OicResult<T> {
    oic_canonical_encoding::from_canonical_bytes(&read_private(dir, name)?)
}

pub fn read_key32(dir: &Path, name: &str) -> OicResult<[u8; 32]> {
    read_private(dir, name)?
        .try_into()
        .map_err(|_| OicError::invalid_request(format!("{name} must be exactly 32 bytes")))
}

pub fn read_config(dir: &Path) -> OicResult<NodeConfig> {
    let bytes = read_private(dir, "node.json")?;
    let config: NodeConfig = serde_json::from_slice(&bytes).map_err(|e| OicError::invalid_request(format!("node.json: {e}")))?;
    if !config.development_only {
        return Err(OicError::invalid_request("this runner only runs development_only directories (RFC 0002 §9: production provisioning is per security domain)"));
    }
    Ok(config)
}
