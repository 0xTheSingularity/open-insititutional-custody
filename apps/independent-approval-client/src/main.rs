//! `oic-approve`: the independent approval client CLI. A thin clap layer over
//! [`oic_approval_client::commands`]; see the library docs for behavior and
//! exit codes (0 ok, 2 usage, 3 refused, 4 destination mismatch, 5 I/O).

use clap::{Parser, Subcommand};
use oic_approval_client::commands::*;
use oic_approval_client::keyfile::passphrase_from_env;
use oic_approval_client::{ClientResult, EXIT_OK};
use oic_approval_verifier::sanitize_display_text;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "oic-approve", version, about = "Independent approval client: verifies and signs exactly what the signed objects authorize")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a trust-roots file pinning this binary's adapter builds.
    InitTrust {
        #[arg(long)]
        out: PathBuf,
        /// `<credential_id>=<ed25519 pubkey hex>`, repeated per administrator.
        #[arg(long = "admin-key", required = true)]
        admin_key: Vec<String>,
        #[arg(long)]
        admin_quorum: u8,
        /// Path of a ChainProfile JSON file, repeated per profile.
        #[arg(long = "profile", required = true)]
        profile: Vec<PathBuf>,
    },
    /// Generate an encrypted ed25519 approver credential.
    Keygen {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        credential_id: String,
        /// treasury_approver | security_approver | administrator | automated
        #[arg(long)]
        role: String,
        /// Environment variable holding the passphrase.
        #[arg(long)]
        passphrase_env: String,
    },
    /// Render the approval card recomputed from the package.
    Show {
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        package: PathBuf,
        /// Unix seconds to evaluate at (default: system clock).
        #[arg(long)]
        now: Option<u64>,
    },
    /// Render, confirm, and sign an approval grant.
    Approve {
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        passphrase_env: String,
        #[arg(long)]
        grant_id: String,
        #[arg(long)]
        ttl_seconds: u64,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        now: Option<u64>,
        /// Skip the interactive `y` confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Verify a grant's signature and that it binds the package.
    VerifyGrant {
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        grant: PathBuf,
        /// `<credential_id>=<ed25519 pubkey hex>=<role>`.
        #[arg(long)]
        approver: String,
        #[arg(long)]
        now: Option<u64>,
    },
    /// Check an authorization envelope field by field against the package.
    InspectEnvelope {
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long)]
        now: Option<u64>,
    },
}

fn run(cli: Cli, out: &mut dyn Write) -> ClientResult<()> {
    match cli.command {
        Command::InitTrust { out: path, admin_key, admin_quorum, profile } => {
            init_trust(&InitTrustArgs { out: path, admin_keys: admin_key, admin_quorum, profiles: profile }, out).map(|_| ())
        }
        Command::Keygen { out: path, credential_id, role, passphrase_env } => {
            let pass = passphrase_from_env(&passphrase_env)?;
            keygen(&KeygenArgs { out: path, credential_id, role }, &pass, out).map(|_| ())
        }
        Command::Show { trust, package, now } => show(&ShowArgs { trust, package, now }, out).map(|_| ()),
        Command::Approve { trust, package, key, passphrase_env, grant_id, ttl_seconds, out: path, now, yes } => {
            let pass = passphrase_from_env(&passphrase_env)?;
            let stdin = std::io::stdin();
            let mut confirm = stdin.lock();
            approve(&ApproveArgs { trust, package, key, grant_id, ttl_seconds, out: path, now, yes }, &pass, &mut confirm, out).map(|_| ())
        }
        Command::VerifyGrant { trust, package, grant, approver, now } => verify_grant(&VerifyGrantArgs { trust, package, grant, approver, now }, out).map(|_| ()),
        Command::InspectEnvelope { trust, package, envelope, now } => {
            inspect_envelope(&InspectEnvelopeArgs { trust, package, envelope, now }, out).map(|_| ())
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let code = match run(cli, &mut out) {
        Ok(()) => EXIT_OK,
        Err(e) => {
            let _ = out.flush();
            eprintln!("oic-approve: {}", sanitize_display_text(&e.to_string()));
            e.exit_code()
        }
    };
    let _ = out.flush();
    std::process::exit(code);
}
