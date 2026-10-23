//! DEVELOPMENT ONLY per-role node runner for the D1 reference topology.
//!
//! `provision` writes one directory per node; `run` starts exactly one role
//! from such a directory as its own OS process (a signer additionally spawns
//! the share-holding core as a separate child process); `check` runs on the
//! gateway and exits 0 once every signer answers a read-only probe and the
//! authority link converges. The transport always uses the production
//! profile: Commonware's recommended cooldowns, per-IP handshake quotas and
//! registered-address checks. What stays development-grade is provisioning —
//! one machine generates every secret, so these are not independent domains
//! (RFC 0002 §9) — and the chain, which remains the development simulator.

mod corerun;
mod files;
mod provision;
mod readmit;

use clap::{Parser, Subcommand};
use commonware_runtime::{Runner as _, Supervisor as _, tokio as cruntime};
use ed25519_dalek::SigningKey;
use files::Role;
use oic_authorization_state::{Authority, AuthorityConfig, AuthorityStore as _, FileAuthorityStore, SystemClock};
use oic_domain_types::*;
use oic_membership::{roster_hash, AdminTrust, SignedRoster};
use oic_node::{Config, Transport};
use oic_peer_wire::{AuthorityRequest, FrameKind, PeerFrameV1, SessionControl, MAX_BODY_LEN};
use oic_service_authority_rpc::AuthorityRpcServer;
use oic_service_signer_core::ipc;
use oic_service_signer_net::{AuthorityHandler, Bridge};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "oic-node", about = "DEVELOPMENT ONLY: run one node of the D1 reference topology from a provisioned directory", version)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// DEVELOPMENT ONLY: write every node directory of the reference
    /// topology. One machine generates all secrets; label it accordingly.
    Provision {
        /// Output directory; one `node-N` subdirectory per node is created.
        #[arg(long)]
        out: PathBuf,
        /// Exactly five listen addresses, node 0 through 4
        /// (signer, signer, signer, gateway, authority).
        #[arg(long, num_args = 5, required = true)]
        address: Vec<std::net::SocketAddr>,
    },
    /// Run one node from its provisioned directory until SIGTERM/SIGINT.
    Run {
        #[arg(long)]
        dir: PathBuf,
        /// Gateway only: exit 0 once the topology converges, instead of serving.
        #[arg(long)]
        check: bool,
        /// Budget for --check, in seconds. Production-profile cold starts
        /// legitimately take up to a connection-cooldown cycle.
        #[arg(long, default_value_t = 300)]
        check_budget: u64,
        /// Minimum signers that must answer the probe for --check to pass.
        /// Below the full roster this is a degraded-quorum check: it proves
        /// the surviving nodes still serve after a signer loss.
        #[arg(long, default_value_t = provision::SIGNERS)]
        check_require: usize,
    },
    /// DEVELOPMENT ONLY: stage the next roster epoch so stopped signers can
    /// rejoin. Pins each signer's next instance generation, signs the update
    /// with two of the three provisioned admin keys, and writes it to every
    /// node directory; restart each node onto it afterwards.
    Readmit {
        /// The topology directory `provision --out` created.
        #[arg(long)]
        base: PathBuf,
    },
    /// Internal: the signer-core child entrypoint. Spawned by `run`.
    #[command(hide = true)]
    Core {
        #[arg(long)]
        dir: PathBuf,
    },
}

fn main() -> std::process::ExitCode {
    // Transport diagnostics land on stderr; RUST_LOG picks the level.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let result = match Cli::parse().command {
        Cmd::Provision { out, address } => provision::provision(&out, &address, wall_clock()),
        Cmd::Run { dir, check, check_budget, check_require } => {
            run(&dir, check, Duration::from_secs(check_budget), check_require)
        }
        Cmd::Readmit { base } => readmit::readmit(&base, wall_clock()),
        Cmd::Core { dir } => corerun::run(&dir),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oic-node: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn wall_clock() -> UnixSeconds {
    UnixSeconds(SystemTime::now().duration_since(UNIX_EPOCH).expect("time went backwards").as_secs())
}

fn run(dir: &Path, check: bool, check_budget: Duration, check_require: usize) -> OicResult<()> {
    let config = files::read_config(dir)?;
    if check && (config.role != Role::Gateway || config.index != provision::GATEWAY) {
        return Err(OicError::invalid_request("--check runs on the gateway node"));
    }
    let roster: SignedRoster = files::read_canonical(dir, "roster.bin")?;
    // A staged roster update (the readmit ceremony) leaves the prior epoch
    // beside the current one; the transition is validated against it.
    let previous: Option<SignedRoster> = dir
        .join("roster-previous.bin")
        .exists()
        .then(|| files::read_canonical(dir, "roster-previous.bin"))
        .transpose()?;
    let (threshold, credentials): (u16, BTreeMap<CredentialId, PublicKey>) = files::read_canonical(dir, "admins.bin")?;
    let admins = AdminTrust { threshold, credentials };
    let transport_key = SigningKey::from_bytes(&files::read_key32(dir, "transport.key")?);
    let hash = roster_hash(&roster.body)?;
    let genesis = match &previous {
        Some(p) if p.body.roster_epoch == 0 => roster_hash(&p.body)?,
        Some(p) => p.body.genesis_hash,
        None => hash,
    };
    let node_id = files::node_id(config.index);

    // The signer's share-holding core runs as a separate OS process before
    // any network reactor starts in this one.
    let core = match config.role {
        Role::Signer => Some(spawn_core(dir)?),
        _ => None,
    };
    let core_client = core.as_ref().map(|c| ipc::Client::new(c.socket.clone()));

    // Authority state outlives restarts through its durable store.
    let authority_handler: Option<AuthorityHandler> = match config.role {
        Role::Authority => Some(authority_handler(dir, &roster, &admins, &node_id)?),
        _ => None,
    };

    let runtime_dir = dir.join("runtime");
    let cfg = cruntime::Config::default().with_storage_directory(&runtime_dir);
    let role = config.role;
    let dir = dir.to_path_buf();
    cruntime::Runner::new(cfg).start(move |context| async move {
        let transport = Transport::start(
            context.child("node"),
            Config {
                roster: roster.clone(),
                admins,
                previous: previous.clone(),
                institution_id: files::institution(),
                environment_id: files::environment(),
                genesis_hash: genesis,
                committed_roster_hash: hash,
                now: wall_clock(),
                node_id: node_id.clone(),
                transport_key,
            },
        )?;
        let sender = transport.sender();
        let (bridge, gateway) = Bridge::new(transport, 0, core_client, authority_handler);
        let (stop, stopped) = oneshot::channel();
        let bridge_task = tokio::spawn(bridge.run(stopped));
        eprintln!("oic-node: {node_id} up as {role:?} (DEVELOPMENT topology)");

        if check {
            let outcome = tokio::task::spawn_blocking({
                let gateway = gateway.clone();
                let handle = tokio::runtime::Handle::current();
                move || converged(&gateway, &sender, &handle, check_budget, check_require)
            })
            .await
            .map_err(|_| OicError::internal("the check task panicked"))?;
            let _ = stop.send(());
            let _ = bridge_task.await;
            return outcome;
        }
        drop(gateway);
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| OicError::internal(format!("installing the SIGTERM handler failed: {e}")))?;
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        eprintln!("oic-node: {node_id} stopping");
        let _ = stop.send(());
        let _ = bridge_task.await;
        if role == Role::Signer {
            let _ = std::fs::write(dir.join("stop"), []);
        }
        Ok(())
    })?;
    if let Some(mut core) = core {
        core.finish()?;
    }
    Ok(())
}

/// Gateway-view convergence: every signer answers a read-only Status probe
/// through its control channel, and a nonmutating probe reaches the
/// authority. Status cannot decode as an AuthorityRequest, so the authority
/// probe cannot mutate anything (the same argument as the integration
/// harness).
fn converged(gateway: &oic_service_signer_net::Gateway, sender: &oic_node::SendHandle, handle: &tokio::runtime::Handle, budget: Duration, require: usize) -> OicResult<()> {
    let require = require.min(provision::SIGNERS);
    let started = Instant::now();
    let deadline = started + budget;
    // Round-robin until `require` signers have answered: with a signer down,
    // a strict in-order wait would burn the whole budget on the dead node.
    let mut responded = std::collections::BTreeSet::new();
    let mut last_error: Option<OicError> = None;
    while responded.len() < require {
        for index in 0..provision::SIGNERS {
            if responded.contains(&index) {
                continue;
            }
            let client = gateway.signer(files::node_id(index));
            let probe = SessionControl::Status {
                request_id: 90_000 + index as u64,
                session_id: SigningSessionId::unchecked("oic-node-check-no-session"),
            };
            match client.request(probe) {
                Ok(reply) => {
                    let code = reply.result.err().map(|e| e.code);
                    if code == Some(ErrorCode::NotFound) {
                        responded.insert(index);
                    } else {
                        return Err(OicError::internal(format!("signer {index} returned an unexpected probe reply: {code:?}")));
                    }
                }
                Err(e) if matches!(e.code, ErrorCode::RosterMismatch | ErrorCode::AuthorityUnavailable | ErrorCode::Conflict) => {
                    last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        if responded.len() >= require {
            break;
        }
        if Instant::now() >= deadline {
            let detail = last_error.map(|e| e.to_string()).unwrap_or_else(|| "no probe error".into());
            return Err(OicError::new(
                ErrorCode::AuthorityUnavailable,
                format!("only {}/{require} required signers converged within {budget:?}; last error: {detail}", responded.len()),
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let probe = PeerFrameV1::encode_confidential(
        &SessionControl::Status { request_id: 99_000, session_id: SigningSessionId::unchecked("oic-node-check-no-session") },
        0,
        FrameKind::Content,
        MAX_BODY_LEN,
    )
    .map_err(|_| OicError::internal("encoding the authority probe failed"))?;
    loop {
        match handle.block_on(sender.send(&files::node_id(provision::AUTHORITY), 12, probe.clone())) {
            Ok(()) => break,
            Err(e) if matches!(e.code, ErrorCode::RosterMismatch | ErrorCode::Conflict) => {
                if Instant::now() >= deadline {
                    return Err(OicError::new(e.code, format!("the authority link did not converge within {budget:?}; last error: {e}")));
                }
            }
            Err(e) => return Err(e),
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("READY: topology converged in {}ms (development reference topology)", started.elapsed().as_millis());
    Ok(())
}

fn authority_handler(dir: &Path, roster: &SignedRoster, admins: &AdminTrust, node_id: &NodeId) -> OicResult<AuthorityHandler> {
    let authority_key = SigningKey::from_bytes(&files::read_key32(dir, "authority.key")?);
    let store = Arc::new(FileAuthorityStore::open(dir.join("authority.json"), None)?);
    let fence = store.read(|s| s.fence_token)?;
    let authority = Arc::new(Authority::open(
        store,
        fence,
        AuthorityConfig {
            institution_id: files::institution(),
            environment_id: files::environment(),
            authority_key_id: files::authority_key_id(),
            admin_keys: admins
                .credentials
                .iter()
                .map(|(id, key)| {
                    let bytes: [u8; 32] = key.bytes.as_slice().try_into().map_err(|_| OicError::invalid_request("admin key length"))?;
                    Ok((id.clone(), ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| OicError::invalid_request("admin key point"))?))
                })
                .collect::<OicResult<Vec<_>>>()?,
            admin_quorum: admins.threshold as u8,
            freeze_responders: vec![],
            release_receipt_ttl_seconds: 60,
            max_clock_skew_seconds: 30,
        },
        authority_key,
        Arc::new(SystemClock),
    )?);
    let roster = roster.clone();
    let node_id = node_id.clone();
    Ok(Arc::new(move |from: &NodeId, frame: &[u8]| {
        // Decoding is the server's job; this closure only routes.
        let _ = AuthorityRequest::decode(frame, 0, MAX_BODY_LEN);
        AuthorityRpcServer::new(authority.as_ref(), &roster, &node_id)?.handle(from, frame)
    }))
}

struct CoreProcess {
    child: Child,
    socket: PathBuf,
    dir: PathBuf,
}

fn spawn_core(dir: &Path) -> OicResult<CoreProcess> {
    fn io<E: std::fmt::Display>(what: &'static str) -> impl Fn(E) -> OicError {
        move |e| OicError::internal(format!("{what}: {e}"))
    }
    for stale in ["ready", "stop", "core.sock"] {
        let _ = std::fs::remove_file(dir.join(stale));
    }
    let exe = std::env::current_exe().map_err(io("resolving the runner executable"))?;
    let child = ProcessCommand::new(exe)
        .args(["core", "--dir"])
        .arg(dir)
        .stdin(Stdio::null())
        .spawn()
        .map_err(io("spawning the signer core"))?;
    let mut process = CoreProcess { child, socket: dir.join("core.sock"), dir: dir.to_path_buf() };
    let start = Instant::now();
    while !process.dir.join("ready").exists() {
        if let Some(status) = process.child.try_wait().map_err(io("waiting for the signer core"))? {
            return Err(OicError::internal(format!("the signer core exited during startup: {status}")));
        }
        if start.elapsed() > Duration::from_secs(30) {
            let _ = process.child.kill();
            return Err(OicError::internal("the signer core missed its startup deadline"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(process)
}

impl CoreProcess {
    fn finish(&mut self) -> OicResult<()> {
        let _ = std::fs::write(self.dir.join("stop"), []);
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => return Err(OicError::internal(format!("the signer core exited with {status}"))),
                Ok(None) if start.elapsed() > Duration::from_secs(10) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Err(OicError::internal("the signer core missed its shutdown deadline"));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(OicError::internal(format!("waiting for the signer core: {e}"))),
            }
        }
    }
}

impl Drop for CoreProcess {
    fn drop(&mut self) {
        let _ = std::fs::write(self.dir.join("stop"), []);
        for _ in 0..200 {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
