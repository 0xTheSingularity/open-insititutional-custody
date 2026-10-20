//! Trust roots of the approval client, configured out of band (never from
//! the console) and the adapters pinned into this build.
//!
//! The file is JSON:
//!
//! ```text
//! {
//!   "schema_version": 1,
//!   "admin_keys": [{ "credential_id": "admin-1", "public_key_hex": "<32-byte ed25519 hex>" }, ...],
//!   "admin_quorum": 2,
//!   "chain_profiles": [ChainProfile, ...],
//!   "accepted_verifier_builds": { "<adapter_id>": ["<verifier build hash hex>", ...] }
//! }
//! ```
//!
//! `init-trust` fills `accepted_verifier_builds` from the adapters compiled
//! into the producing binary, so a trust file pins that build: a client
//! whose pinned adapter for an enrolled profile has a build hash not listed
//! refuses to verify anything ([`TrustRoots::verifier`]).

use crate::{ClientError, ClientResult};
use ed25519_dalek::VerifyingKey;
use oic_adapter_api::{ChainAdapter, ChainProfile};
use oic_approval_verifier::IndependentVerifier;
use oic_domain_types::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

/// Current trust-file schema version.
pub const TRUST_SCHEMA_VERSION: u16 = 1;

/// One enrolled administrative credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminKeyEntry {
    pub credential_id: CredentialId,
    /// Lowercase hex of the 32-byte Ed25519 public key.
    pub public_key_hex: String,
}

/// Contents of `trust.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRoots {
    pub schema_version: u16,
    pub admin_keys: Vec<AdminKeyEntry>,
    pub admin_quorum: u8,
    pub chain_profiles: Vec<ChainProfile>,
    /// Adapter id -> verifier build hashes this client accepts.
    pub accepted_verifier_builds: BTreeMap<AdapterId, Vec<Hash32>>,
}

/// The chain adapters compiled into this binary, keyed by adapter id.
pub fn pinned_adapters() -> BTreeMap<AdapterId, Arc<dyn ChainAdapter>> {
    let mut adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::new();
    adapters.insert(AdapterId::unchecked(oic_adapter_evm::ADAPTER_ID), Arc::new(oic_adapter_evm::EvmAdapter::new()));
    adapters.insert(AdapterId::unchecked(oic_adapter_solana::ADAPTER_ID), Arc::new(oic_adapter_solana::SolanaAdapter::new()));
    adapters
}

/// Verifier build hashes of the adapters compiled into this binary.
pub fn compiled_verifier_builds() -> BTreeMap<AdapterId, Vec<Hash32>> {
    let mut builds = BTreeMap::new();
    builds.insert(AdapterId::unchecked(oic_adapter_evm::ADAPTER_ID), vec![oic_adapter_evm::verifier_build_hash()]);
    builds.insert(AdapterId::unchecked(oic_adapter_solana::ADAPTER_ID), vec![oic_adapter_solana::verifier_build_hash()]);
    builds
}

/// Decode a 32-byte Ed25519 public key from hex.
pub fn parse_verifying_key(hex_str: &str) -> OicResult<VerifyingKey> {
    let bytes = hex::decode(hex_str.trim().trim_start_matches("0x")).map_err(|_| OicError::invalid_request("public key is not hex"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| OicError::invalid_request("ed25519 public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| OicError::invalid_request("not a valid ed25519 public key"))
}

/// Parse a validated identifier from a command-line value.
pub fn parse_credential_id(s: &str) -> ClientResult<CredentialId> {
    CredentialId::new(s).ok_or_else(|| ClientError::Usage(format!("invalid credential id `{}`", oic_approval_verifier::sanitize_display_text(s))))
}

/// Parse `<credential_id>=<ed25519 public key hex>`.
pub fn parse_admin_key_arg(arg: &str) -> ClientResult<(CredentialId, VerifyingKey)> {
    let (id, key) = arg.split_once('=').ok_or_else(|| ClientError::Usage("--admin-key must be <credential_id>=<ed25519 pubkey hex>".into()))?;
    let id = parse_credential_id(id)?;
    let key = parse_verifying_key(key).map_err(|e| ClientError::Usage(format!("--admin-key {id}: {}", e.detail)))?;
    Ok((id, key))
}

impl TrustRoots {
    /// Build trust roots pinning this binary's adapter builds.
    pub fn new(admin_keys: Vec<(CredentialId, VerifyingKey)>, admin_quorum: u8, chain_profiles: Vec<ChainProfile>) -> OicResult<TrustRoots> {
        let t = TrustRoots {
            schema_version: TRUST_SCHEMA_VERSION,
            admin_keys: admin_keys.into_iter().map(|(credential_id, k)| AdminKeyEntry { credential_id, public_key_hex: hex::encode(k.to_bytes()) }).collect(),
            admin_quorum,
            chain_profiles,
            accepted_verifier_builds: compiled_verifier_builds(),
        };
        t.validate()?;
        Ok(t)
    }

    /// Structural checks: schema version, a satisfiable non-zero quorum over
    /// distinct, well-formed admin keys, distinct chain profiles, and a
    /// pinned adapter for every profile.
    pub fn validate(&self) -> OicResult<()> {
        if self.schema_version != TRUST_SCHEMA_VERSION {
            return Err(OicError::invalid_request(format!("unsupported trust schema version {}", self.schema_version)));
        }
        let keys = self.admin_verifying_keys()?;
        if self.admin_quorum == 0 {
            return Err(OicError::invalid_request("administrative quorum must be at least 1"));
        }
        if usize::from(self.admin_quorum) > keys.len() {
            return Err(OicError::invalid_request(format!("administrative quorum {} exceeds the {} enrolled admin keys", self.admin_quorum, keys.len())));
        }
        let ids: BTreeSet<&CredentialId> = keys.iter().map(|(c, _)| c).collect();
        let pks: BTreeSet<[u8; 32]> = keys.iter().map(|(_, k)| k.to_bytes()).collect();
        if ids.len() != keys.len() || pks.len() != keys.len() {
            return Err(OicError::invalid_request("admin credentials and keys must be distinct"));
        }
        if self.chain_profiles.is_empty() {
            return Err(OicError::invalid_request("at least one chain profile must be enrolled"));
        }
        let pids: BTreeSet<&ChainProfileId> = self.chain_profiles.iter().map(|p| &p.chain_profile_id).collect();
        if pids.len() != self.chain_profiles.len() {
            return Err(OicError::invalid_request("chain profile ids must be distinct"));
        }
        let adapters = pinned_adapters();
        for p in &self.chain_profiles {
            if !adapters.contains_key(&p.adapter_id) {
                return Err(OicError::unsupported(format!("chain profile {} needs adapter `{}`, which this client does not pin", p.chain_profile_id, p.adapter_id)));
            }
        }
        Ok(())
    }

    /// Decoded administrative roster.
    pub fn admin_verifying_keys(&self) -> OicResult<Vec<(CredentialId, VerifyingKey)>> {
        self.admin_keys
            .iter()
            .map(|e| {
                let k = parse_verifying_key(&e.public_key_hex).map_err(|err| OicError::invalid_request(format!("admin key {}: {}", e.credential_id, err.detail)))?;
                Ok((e.credential_id.clone(), k))
            })
            .collect()
    }

    /// The enrolled profile with `id`.
    pub fn profile(&self, id: &ChainProfileId) -> OicResult<&ChainProfile> {
        self.chain_profiles
            .iter()
            .find(|p| &p.chain_profile_id == id)
            .ok_or_else(|| OicError::scope(format!("chain profile {id} is not enrolled in the trust roots")))
    }

    /// The pinned adapter for `adapter_id`, provided the trust roots accept
    /// its verifier build.
    pub fn accepted_adapter(&self, adapter_id: &AdapterId) -> OicResult<Arc<dyn ChainAdapter>> {
        let adapter = pinned_adapters()
            .remove(adapter_id)
            .ok_or_else(|| OicError::unsupported(format!("no pinned adapter `{adapter_id}` in this client")))?;
        let build = adapter.manifest().verifier_build_hash;
        let accepted = self.accepted_verifier_builds.get(adapter_id).is_some_and(|v| v.contains(&build));
        if !accepted {
            return Err(OicError::unsupported(format!("this client's `{adapter_id}` verifier build {build} is not accepted by the trust roots")));
        }
        Ok(adapter)
    }

    /// The [`IndependentVerifier`] for these roots: every enrolled profile's
    /// pinned adapter must have an accepted build, otherwise the whole
    /// client refuses (a trust file pins the build that produced it).
    pub fn verifier(&self) -> OicResult<IndependentVerifier> {
        self.validate()?;
        let mut adapters = BTreeMap::new();
        for p in &self.chain_profiles {
            adapters.insert(p.adapter_id.clone(), self.accepted_adapter(&p.adapter_id)?);
        }
        Ok(IndependentVerifier::new(adapters, self.chain_profiles.clone(), self.admin_verifying_keys()?, self.admin_quorum))
    }

    /// Load and validate a trust file. Parse failures are I/O errors;
    /// invalid contents are refusals.
    pub fn load(path: &Path) -> ClientResult<TrustRoots> {
        let t: TrustRoots = crate::read_json(path)?;
        t.validate()?;
        Ok(t)
    }

    /// Write a new trust file (never overwrites).
    pub fn save(&self, path: &Path) -> ClientResult<()> {
        crate::write_new_json(path, self, 0o644)
    }
}
