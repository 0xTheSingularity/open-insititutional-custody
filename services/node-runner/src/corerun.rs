//! The signer-core child process: holds the sealed share, never the network.
//!
//! `oic-node run --dir <signer dir>` spawns this as a separate OS process
//! (`oic-node core --dir <dir>`), so share custody and the network reactor
//! stay in different address spaces, exactly like the integration harness
//! this was promoted from. Everything comes from the provisioned files; no
//! key material is derived from constants.

use crate::files::{self, Role};
use ed25519_dalek::SigningKey;
use oic_adapter_api::ChainAdapter;
use oic_audit::{AuditLogConfig, FileAuditLog};
use oic_authorization_state::SystemClock;
use oic_crypto_provider_frost_ed25519::FrostEd25519Provider;
use oic_domain_types::*;
use oic_membership::{roster_hash, AdminTrust, SignedRoster};
use oic_one_time_state_ledger::FileLedger;
use oic_service_signer_core::{ipc, CoreConfig, SignerCore};
use oic_signer::{FileGenerationStore, Signer, SignerIdentity};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Runs until the parent writes `<dir>/stop` or the process receives SIGTERM.
pub fn run(dir: &Path) -> OicResult<()> {
    let config = files::read_config(dir)?;
    if config.role != Role::Signer {
        return Err(OicError::invalid_request("`core` runs only in a signer directory"));
    }
    let index = config.index;
    let roster: SignedRoster = files::read_canonical(dir, "roster.bin")?;
    let (threshold, credentials): (u16, BTreeMap<CredentialId, PublicKey>) = files::read_canonical(dir, "admins.bin")?;
    let descriptor: KeyDescriptor = files::read_canonical(dir, "descriptor.bin")?;
    let roots: files::ProvisionedRoots = files::read_canonical(dir, "roots.bin")?;
    let sealed = Bytes(files::read_private(dir, "share.sealed")?);
    let sealing = files::read_key32(dir, "sealing.key")?;
    let peer_key = SigningKey::from_bytes(&files::read_key32(dir, "peer.key")?);
    let audit_key = SigningKey::from_bytes(&files::read_key32(dir, "audit.key")?);
    let operator_key = ed25519_dalek::VerifyingKey::from_bytes(&files::read_key32(dir, "operator.pub")?)
        .map_err(|_| OicError::invalid_request("operator.pub is not a valid Ed25519 point"))?;

    let clock = Arc::new(SystemClock);
    let provider = Arc::new(FrostEd25519Provider::with_os_rng(files::participant(index), sealing)?);
    let ledger = Arc::new(FileLedger::open(dir.join("ledger"), Some(0))?);
    let adapter: Arc<dyn ChainAdapter> = Arc::new(oic_adapter_solana::SolanaAdapter);
    let signer = Arc::new(Signer::open(
        SignerIdentity {
            participant_id: files::participant(index),
            institution_id: files::institution(),
            environment_id: files::environment(),
        },
        roots.into_roots()?,
        BTreeMap::from([(adapter.manifest().adapter_id, adapter)]),
        provider,
        ledger,
        Arc::new(FileGenerationStore::new(dir.join("generation"))),
    )?);
    signer.load_key(&descriptor, &sealed)?;
    let audit = Arc::new(FileAuditLog::open(
        dir.join("audit"),
        Some(0),
        AuditLogConfig::new(KeyId::unchecked(format!("dev-core-audit-{index}")), audit_key, clock.clone()),
    )?);
    let core = Arc::new(SignerCore::open(
        CoreConfig {
            node_id: files::node_id(index),
            committed_roster_hash: roster_hash(&roster.body)?,
            roster,
            previous_roster: dir
                .join("roster-previous.bin")
                .exists()
                .then(|| files::read_canonical(dir, "roster-previous.bin"))
                .transpose()?,
            admins: AdminTrust { threshold, credentials },
            halt_state_path: dir.join("halt"),
            minimum_halt_sequence: 0,
            operator_key,
            audit,
        },
        signer,
        peer_key,
        clock,
    )?);

    // Stop protocol: the parent writes `<dir>/stop`. A hard kill is also
    // safe: the one-time-state ledger is durable before any share-revealing
    // step (the A11 crash tests), so clean shutdown is a courtesy, not a
    // safety requirement.
    let socket = dir.join("core.sock");
    let _ = std::fs::remove_file(&socket);
    let server = ipc::Server::bind(&socket, core)?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let stop_path = dir.join("stop");
    let watcher = std::thread::spawn(move || {
        // Also end when serve() already returned (its error path sets the flag).
        while !stop_path.exists() && !flag.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(50));
        }
        flag.store(true, Ordering::Release);
    });
    files::write_secret(&dir.join("ready"), &std::process::id().to_be_bytes())?;
    let result = server.serve(&stop);
    stop.store(true, Ordering::Release);
    let _ = watcher.join();
    result
}
