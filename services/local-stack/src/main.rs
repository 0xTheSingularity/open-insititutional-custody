use clap::{Parser, Subcommand};
use oic_authorization_state::{Clock, SystemClock};
use oic_domain_types::*;
use oic_service_local_stack::{bootstrap, Stack, PROFILE};
use std::{io::Write, net::SocketAddr, os::unix::fs::OpenOptionsExt, path::PathBuf};

#[derive(Parser)]
#[command(about = "DEVELOPMENT ONLY: durable local D1 custody and native chain simulators")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Bootstrap {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        handoff: PathBuf,
        #[arg(long)]
        approver_public_key: String,
    },
    /// Write an unsigned native transfer intent from the enrolled public catalog.
    Intent {
        #[arg(long)]
        catalog: PathBuf,
        #[arg(long, value_parser = ["evm", "solana"])]
        chain: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        amount: u128,
        #[arg(long)]
        max_fee: u128,
        #[arg(long)]
        out: PathBuf,
    },
    Start {
        #[arg(long)]
        state: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        #[arg(long)]
        ready_file: Option<PathBuf>,
        #[arg(long)]
        enable_faults: bool,
        #[arg(long)]
        fail_after_release: bool,
    },
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        Command::Bootstrap {
            state,
            handoff,
            approver_public_key,
        } => {
            let key: [u8; 32] = hex::decode(approver_public_key)?
                .try_into()
                .map_err(|_| "approver public key must be 32 bytes")?;
            bootstrap(&state, &handoff, key)?;
            println!("{PROFILE}\nProvisioned; credentials written to separate private handoff files. Approval private key was not received.");
        }
        Command::Intent {
            catalog,
            chain,
            id,
            amount,
            max_fee,
            out,
        } => {
            let c: serde_json::Value = serde_json::from_slice(&std::fs::read(catalog)?)?;
            let i = if chain == "evm" { 0 } else { 1 };
            let wallet: ChainWallet = serde_json::from_value(c["wallets"][i].clone())?;
            let asset: Asset = serde_json::from_value(c["assets"][i].clone())?;
            let destination: CounterpartyDestination =
                serde_json::from_value(c["destinations"][i].clone())?;
            let intent = Intent {
                schema_version: 1,
                intent_id: IntentId::new(id).ok_or("invalid intent ID")?,
                institution_id: serde_json::from_value(c["institution_id"].clone())?,
                environment_id: serde_json::from_value(c["environment_id"].clone())?,
                vault_id: wallet.vault_id,
                chain_wallet_id: wallet.chain_wallet_id,
                chain_profile_id: wallet.chain_profile_id,
                operation: IntentOperation::AssetTransfer {
                    asset_id: asset.asset_id,
                    amount_base_units: Amount(amount),
                    destination_id: destination.destination_id,
                    destination_version: destination.version,
                },
                constraints: IntentConstraints {
                    max_network_fee_base_units: Amount(max_fee),
                    approval_mode: ApprovalMode::ExactCandidate,
                    maximum_successful_payments: 1,
                },
                purpose: OperationPurpose::Settlement,
                external_reference: "local simulator transfer".into(),
                proposer_credential_id: serde_json::from_value(
                    c["proposer_credential_id"].clone(),
                )?,
                created_at: SystemClock.now(),
            };
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(out)?;
            file.write_all(&serde_json::to_vec_pretty(&intent)?)?;
            file.sync_all()?;
            println!("Unsigned intent only; independent approval and submit are separate steps.");
        }
        Command::Start {
            state,
            listen,
            ready_file,
            enable_faults,
            fail_after_release,
        } => {
            if !listen.ip().is_loopback() {
                return Err("development server binds loopback only".into());
            }
            let stack = Stack::open(&state, enable_faults, fail_after_release)?;
            let listener = tokio::net::TcpListener::bind(listen).await?;
            let addr = listener.local_addr()?;
            if let Some(path) = ready_file {
                std::fs::write(
                    path,
                    serde_json::to_vec(
                        &serde_json::json!({"address":addr.to_string(),"pid":std::process::id()}),
                    )?,
                )?;
            }
            println!(
                "{PROFILE}\nListening at http://{addr}; all routes require scoped credentials."
            );
            axum::serve(listener, stack.router())
                .with_graceful_shutdown(async {
                    let mut term =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .expect("SIGTERM handler");
                    tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
                })
                .await?;
        }
    }
    Ok(())
}
