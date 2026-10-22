//! OpenInstitutionalCustody CLI.
//!
//! `oic demo` is the 5-minute self-host quickstart's headline command. It runs
//! the complete custody money-loop end-to-end, in a single process and a single
//! terminal, with ZERO prompts, against throwaway development simulators, then
//! prints a receipt + signed audit log and finishes on the blocked-theft proof.
//!
//! This binary is DEMO-ONLY and lives outside the production service crates. It
//! never touches a user-supplied or production state directory: `oic demo`
//! operates exclusively on its own `tempfile::TempDir`, which is discarded when
//! the command exits. No real funds are ever involved.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use oic_adapter_api::{ChainAdapter, ChainProfile};
use oic_approval_verifier::{ApprovalDisplay, DisplayInputs, IndependentVerifier};
use oic_authorization_state::{Clock, SystemClock};
use oic_domain_types::*;
use oic_service_api::{DispatchState, IntentRecord};
use oic_service_local_stack::{bootstrap, Stack, PROFILE};
use oic_service_reconciler::OperationsExport;
use rand_core::OsRng;
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fmt, fs,
    path::Path,
    process::ExitCode,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Parser)]
#[command(name = "oic", about = "OpenInstitutionalCustody CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the full custody flow end-to-end, in-process, against throwaway dev
    /// simulators (no prompts, no real funds), then print a receipt + audit log.
    Demo {
        /// CI mode: print one PASS line per assertion, then a RESULT line.
        /// Exit codes: 0 pass, 1 the check did not complete, 3 security
        /// regression (the verifier signed a tampered approval package).
        #[arg(long)]
        check: bool,
    },
}

/// Exit code when the independent verifier signs a tampered approval package.
/// Distinct from 1 (the flow did not complete) and 2 (clap usage error).
const EXIT_SECURITY_REGRESSION: u8 = 3;

/// The independent verifier signed a tampered approval package: the property
/// the demo exists to prove no longer holds.
#[derive(Debug)]
struct SecurityRegression(String);

impl fmt::Display for SecurityRegression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SECURITY REGRESSION: {}", self.0)
    }
}

impl std::error::Error for SecurityRegression {}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Demo { check } => finish(run_demo(check).await, check),
    }
}

fn finish(result: Result<()>, check: bool) -> ExitCode {
    let code = exit_code(&result);
    if let Err(e) = &result {
        eprintln!("Error: {e:?}");
    }
    if check {
        match code {
            0 => println!("RESULT: PASS"),
            EXIT_SECURITY_REGRESSION => println!("RESULT: FAIL (security regression, exit {code})"),
            _ => println!("RESULT: ERROR (the check did not complete, exit {code})"),
        }
    }
    ExitCode::from(code)
}

fn exit_code(result: &Result<()>) -> u8 {
    match result {
        Ok(()) => 0,
        Err(e) if e.is::<SecurityRegression>() => EXIT_SECURITY_REGRESSION,
        Err(_) => 1,
    }
}

// ---------------------------------------------------------------------------
// Transfer amount and expected fees are fixed to mirror the money-loop E2E
// (services/local-stack/tests/money_loop.rs).
// ---------------------------------------------------------------------------
const TRANSFER: u128 = 1_234_567;
const EVM_FEE: u128 = 21_000 * 1_100_000_000; // gas * price, per the EVM simulator profile
const SOL_FEE: u128 = 5_200; // lamports, per the Solana simulator profile

async fn run_demo(check: bool) -> Result<()> {
    let report = Report { check };

    // Demo/production separation: the demo ONLY ever operates on its own
    // throwaway temp dir. It accepts no state path from the caller and cannot
    // be pointed at a production installation.
    let tmp = tempfile::TempDir::new().context("create throwaway demo temp dir")?;
    let state = tmp.path().join("state");
    let handoff = tmp.path().join("handoff");

    // Ephemeral independent approver: generated here with the OS CSPRNG. Only
    // its PUBLIC key is handed to bootstrap; the stack never sees the private key.
    let approver_key = SigningKey::generate(&mut OsRng);

    bootstrap(&state, &handoff, approver_key.verifying_key().to_bytes())
        .map_err(|e| anyhow!("bootstrap failed: {e}"))?;

    let stack = Stack::open(&state, false, false).map_err(|e| anyhow!("stack open failed: {e}"))?;

    // Fail-closed dev guard (see guard_dev_only).
    let catalog = stack.catalog();
    guard_dev_only(&catalog)?;

    // Serve the stack router on an ephemeral loopback port in a background task
    // and drive it over HTTP from this same process — the money_loop harness,
    // collapsed into one process.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0u16))
        .await
        .context("bind loopback")?;
    let addr = listener.local_addr()?;
    let router = stack.router();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let h = Harness {
        base: format!("http://{addr}"),
        client: Client::builder().timeout(Duration::from_secs(30)).build()?,
        tokens: BTreeMap::from([
            ("console".to_string(), token(&handoff, "console")?),
            ("reader".to_string(), token(&handoff, "reader")?),
            ("approval".to_string(), token(&handoff, "approval")?),
            ("operator".to_string(), token(&handoff, "operator")?),
        ]),
        seq: AtomicU64::new(0),
    };
    let verifier = build_verifier(&handoff)?;

    report.header(&catalog);

    // (2) EVM transfer — DEVELOPMENT single-key secp256k1 (NOT threshold).
    let evm = settle(
        &h,
        &verifier,
        &approver_key,
        "evm",
        0,
        "DEVELOPMENT single-key secp256k1, 1-of-1",
    )
    .await
    .context("EVM settlement")?;
    report.settlement(1, "EVM", &evm);

    // (3) Solana transfer — FROST ed25519 2-of-3 threshold.
    let solana = settle(
        &h,
        &verifier,
        &approver_key,
        "solana",
        1,
        "FROST ed25519 2-of-3",
    )
    .await
    .context("Solana settlement")?;
    report.settlement(2, "Solana", &solana);

    // (4) THEFT BLOCKED — the headline security property.
    let refusal = attempt_theft(&verifier, &approver_key, &evm)?;
    report.theft_blocked(&refusal);

    // (5) Audit log — the signed OperationsExport journal.
    let export = h
        .ok("GET", "/v1/export", &h.tokens["reader"], None)
        .await
        .context("export")?;
    let audit = verify_audit(&export, &catalog)?;
    report.audit(&audit);

    server.abort();
    Ok(())
}

/// Fail closed unless this is the dev/development profile.
///
/// The boundary today: `provision::environment() == EnvironmentId::unchecked("dev")`
/// (services/local-stack/src/provision.rs:15). The policy kernel's
/// `trust_sufficient` only accepts `DevelopmentSimulator` evidence when the
/// environment is `"dev"` (crates/policy-kernel/src/lib.rs:226), so a stack that
/// is not dev/development must never be driven by this demo. We check the value
/// the authenticated catalog actually reports, and refuse otherwise. This does
/// not weaken any production guard — it only adds a demo-side one.
fn guard_dev_only(catalog: &Value) -> Result<()> {
    let env: EnvironmentId = serde_json::from_value(catalog["environment_id"].clone())
        .context("catalog environment_id")?;
    let profile = catalog["profile"].as_str().unwrap_or_default();
    let is_development_profile = profile.to_ascii_lowercase().contains("development")
        && PROFILE.to_ascii_lowercase().contains("development");
    if env != EnvironmentId::unchecked("dev") || !is_development_profile {
        bail!(
            "refusing to run: not a dev/development stack \
             (environment_id={env:?}, profile={profile:?}); see crates/policy-kernel/src/lib.rs:226"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP harness over loopback
// ---------------------------------------------------------------------------
struct Harness {
    base: String,
    client: Client,
    tokens: BTreeMap<String, String>,
    // Distinct logical requests need distinct idempotency keys; this whole flow
    // runs in one process against one server, so a per-call counter keeps the
    // shared `/v1/intents` path from colliding across the two chains.
    seq: AtomicU64,
}

impl Harness {
    async fn call(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        let mut r = self
            .client
            .request(Method::from_bytes(method.as_bytes())?, format!("{}{path}", self.base))
            .bearer_auth(token)
            .header(
                "idempotency-key",
                format!("{path}#{}", self.seq.fetch_add(1, Ordering::SeqCst)),
            );
        if let Some(body) = body {
            r = r.json(&body);
        }
        let response = r.send().await?;
        let status = response.status();
        let text = response.text().await?;
        let value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
        Ok((status, value))
    }

    async fn ok(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> Result<Value> {
        let (status, value) = self.call(method, path, token, body).await?;
        if status != StatusCode::OK {
            bail!("{method} {path} -> {status}: {value}");
        }
        Ok(value)
    }

    async fn control(&self, chain: &str, id: &str, action: Value) -> Result<Value> {
        let mut body = json!({ "id": id, "chain": chain });
        if let (Value::Object(dst), Value::Object(src)) = (&mut body, action) {
            dst.extend(src);
        }
        self.ok("POST", "/local/v1/controls", &self.tokens["operator"], Some(body))
            .await
    }

    async fn receive(&self, chain: &str, id: &str, amount: u128) -> Result<Value> {
        self.control(chain, id, json!({ "action": "receive", "amount": amount.to_string() }))
            .await
    }

    async fn fund_fees(&self, chain: &str, id: &str, amount: u128) -> Result<Value> {
        self.control(chain, id, json!({ "action": "fund_fees", "amount": amount.to_string() }))
            .await
    }

    async fn advance(&self, chain: &str, id: &str) -> Result<Value> {
        self.control(chain, id, json!({ "action": "advance", "blocks": 4 }))
            .await
    }
}

// ---------------------------------------------------------------------------
// Flow (mirrors money_loop.rs prepare + settle)
// ---------------------------------------------------------------------------
struct Settlement {
    label: &'static str,
    symbol: String,
    amount_base_units: String,
    amount_display: String,
    destination_name: String,
    destination_address: String,
    registry_match: bool,
    fee: u128,
    tx_id: String,
    // kept for the theft-blocked proof
    package: ApprovalPackage,
    display: ApprovalDisplay,
}

async fn settle(
    h: &Harness,
    verifier: &IndependentVerifier,
    approver_key: &SigningKey,
    chain: &str,
    index: usize,
    label: &'static str,
) -> Result<Settlement> {
    let console = h.tokens["console"].clone();
    let approval = h.tokens["approval"].clone();
    let reader = h.tokens["reader"].clone();

    let catalog = h.ok("GET", "/local/v1/catalog", &console, None).await?;

    // Operator funds the wallet, funds fees, and advances to finality.
    h.receive(chain, &format!("{chain}-receive"), 10_000_000).await?;
    let fee_funding: u128 = if chain == "evm" {
        100_000_000_000_000_000
    } else {
        100_000_000
    };
    h.fund_fees(chain, &format!("{chain}-fee-funding"), fee_funding).await?;
    h.advance(chain, &format!("{chain}-funding-finality")).await?;
    if chain == "solana" {
        h.advance(chain, &format!("{chain}-funding-finality-2")).await?;
    }

    // Build the transfer intent from the enrolled public catalog.
    let wallet: ChainWallet = serde_json::from_value(catalog["wallets"][index].clone())?;
    let asset: Asset = serde_json::from_value(catalog["assets"][index].clone())?;
    let destination: CounterpartyDestination =
        serde_json::from_value(catalog["destinations"][index].clone())?;
    let id = format!("demo-{chain}");
    let intent = Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked(id.clone()),
        institution_id: serde_json::from_value(catalog["institution_id"].clone())?,
        environment_id: serde_json::from_value(catalog["environment_id"].clone())?,
        vault_id: wallet.vault_id.clone(),
        chain_wallet_id: wallet.chain_wallet_id.clone(),
        chain_profile_id: wallet.chain_profile_id.clone(),
        operation: IntentOperation::AssetTransfer {
            asset_id: asset.asset_id.clone(),
            amount_base_units: Amount(TRANSFER),
            destination_id: destination.destination_id.clone(),
            destination_version: destination.version,
        },
        constraints: IntentConstraints {
            max_network_fee_base_units: Amount(if chain == "evm" {
                10u128.pow(16)
            } else {
                20_000
            }),
            approval_mode: ApprovalMode::ExactCandidate,
            maximum_successful_payments: 1,
        },
        purpose: OperationPurpose::Settlement,
        external_reference: format!("oic-demo-{chain}"),
        proposer_credential_id: serde_json::from_value(catalog["proposer_credential_id"].clone())?,
        created_at: SystemClock.now(),
    };
    h.ok("POST", "/v1/intents", &console, Some(serde_json::to_value(&intent)?))
        .await?;

    // Independent preview -> the approver recomputes the operation from bytes.
    let package: ApprovalPackage = serde_json::from_value(
        h.ok("GET", &format!("/v1/intents/{id}/preview"), &approval, None)
            .await?,
    )?;
    let now = SystemClock.now();
    let display = verifier.render(&inputs(&package), now)?;
    if !display.destination_matches_registry {
        bail!("{chain}: decoded recipient does not match the registry destination");
    }
    if display.amount_base_units != TRANSFER.to_string() {
        bail!(
            "{chain}: recomputed amount {} != expected {TRANSFER}",
            display.amount_base_units
        );
    }

    // The approver signs ONLY what it verified.
    let grant = verifier.approve(
        &display,
        &inputs(&package),
        (
            CredentialId::unchecked("independent-approver"),
            ApprovalRole::TreasuryApprover,
            approver_key,
        ),
        GrantId::unchecked(format!("grant-{chain}")),
        now,
        120,
    )?;
    let record: IntentRecord = serde_json::from_value(
        h.ok(
            "POST",
            &format!("/v1/intents/{id}/approvals"),
            &approval,
            Some(serde_json::to_value(&grant)?),
        )
        .await?,
    )?;
    if record.dispatch != DispatchState::Ready {
        bail!("{chain}: expected Ready after approval, got {:?}", record.dispatch);
    }

    // Snapshot funded wallet balance just before submission.
    let before = h.ok("GET", "/local/v1/status", &reader, None).await?;
    let wallet_before = amount(&before["balances"][index]["wallet_balance"])?;

    // Submit the signed transaction to the simulator.
    let issued = h
        .ok("POST", &format!("/v1/intents/{id}/submit"), &console, None)
        .await?;
    let issued_record: IntentRecord = serde_json::from_value(issued.clone())?;
    if issued_record.issuance.is_none() {
        bail!("{chain}: submission produced no issuance");
    }
    let tx_id = issued
        .pointer("/issuance/signed/signed/chain_tx_id")
        .map(render_tx_id)
        .unwrap_or_else(|| "<unknown>".to_string());

    // Advance to payment finality and confirm the economic effect.
    h.advance(chain, &format!("{chain}-payment-finality")).await?;
    if chain == "solana" {
        h.advance(chain, &format!("{chain}-payment-finality-2")).await?;
    }

    let status = h.ok("GET", "/local/v1/status", &reader, None).await?;
    let balance = &status["balances"][index];
    let beneficiary = amount(&balance["beneficiary_balance"])?;
    if beneficiary != TRANSFER {
        bail!("{chain}: beneficiary balance {beneficiary} != {TRANSFER}");
    }
    let wallet_after = amount(&balance["wallet_balance"])?;
    let fee = if chain == "evm" { EVM_FEE } else { SOL_FEE };
    if wallet_after != wallet_before - TRANSFER - fee {
        bail!(
            "{chain}: wallet debit mismatch: before {wallet_before}, after {wallet_after}, \
             expected {}",
            wallet_before - TRANSFER - fee
        );
    }

    Ok(Settlement {
        label,
        symbol: asset.symbol,
        amount_base_units: display.amount_base_units.clone(),
        amount_display: display.amount_display.clone(),
        destination_name: destination.display_name,
        destination_address: destination.address_display,
        registry_match: display.destination_matches_registry,
        fee,
        tx_id,
        package,
        display,
    })
}

fn inputs(p: &ApprovalPackage) -> DisplayInputs<'_> {
    DisplayInputs {
        intent: &p.intent,
        candidate: &p.candidate,
        wallet: &p.wallet,
        key: &p.key,
        vault: &p.vault,
        asset: &p.asset,
        destination: &p.destination,
        policy: &p.policy,
        evidence: &p.evidence,
    }
}

fn amount(v: &Value) -> Result<u128> {
    Ok(serde_json::from_value::<Amount>(v.clone())
        .with_context(|| format!("parse amount from {v}"))?
        .0)
}

fn render_tx_id(v: &Value) -> String {
    v.as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| v.to_string())
}

fn token(handoff: &Path, name: &str) -> Result<String> {
    let v: Value = serde_json::from_slice(&fs::read(handoff.join(format!("{name}.json")))?)
        .with_context(|| format!("parse handoff {name}.json"))?;
    Ok(v["token"]
        .as_str()
        .with_context(|| format!("{name} token missing"))?
        .to_string())
}

fn build_verifier(handoff: &Path) -> Result<IndependentVerifier> {
    let trust: Value = serde_json::from_slice(&fs::read(handoff.join("trust.json"))?)
        .context("parse handoff trust.json")?;
    let admins = trust["admin_keys"]
        .as_array()
        .context("trust.admin_keys")?
        .iter()
        .map(|v| {
            let cred: CredentialId = serde_json::from_value(v["credential_id"].clone())?;
            let bytes: [u8; 32] = hex::decode(v["public_key_hex"].as_str().context("public_key_hex")?)?
                .try_into()
                .map_err(|_| anyhow!("admin key is not 32 bytes"))?;
            Ok((cred, VerifyingKey::from_bytes(&bytes)?))
        })
        .collect::<Result<Vec<_>>>()?;
    let adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::from([
        (
            AdapterId::unchecked("evm"),
            Arc::new(oic_adapter_evm::EvmAdapter) as Arc<dyn ChainAdapter>,
        ),
        (
            AdapterId::unchecked("solana"),
            Arc::new(oic_adapter_solana::SolanaAdapter) as Arc<dyn ChainAdapter>,
        ),
    ]);
    let profiles: Vec<ChainProfile> = serde_json::from_value(trust["chain_profiles"].clone())?;
    Ok(IndependentVerifier::new(adapters, profiles, admins, 2))
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
fn print_header(catalog: &Value) {
    println!("================================================================================");
    println!("OIC — 5-minute self-host custody quickstart");
    println!("DEVELOPMENT profile · local simulators · ZERO prompts · NO real funds");
    println!("================================================================================");
    println!("profile:     {}", catalog["profile"].as_str().unwrap_or("?"));
    println!(
        "environment: {}   [dev-only guard passed — see crates/policy-kernel/src/lib.rs:226]",
        catalog["environment_id"].as_str().unwrap_or("?")
    );
    println!(
        "backend:     evm    = {}",
        catalog["backend_limits"]["evm"].as_str().unwrap_or("?")
    );
    println!(
        "             solana = {}",
        catalog["backend_limits"]["solana"].as_str().unwrap_or("?")
    );
    println!();
    println!("What each party verified:");
    println!("  • Independent approver — recomputed the operation from the candidate BYTES,");
    println!("    checked the destination against the registry, and signed ONLY the exact");
    println!("    bytes + rules it saw (no console-supplied text was trusted).");
    println!("  • Signer / D1 authority — enforced the destination quorum and released a");
    println!("    chain signature only for an approved candidate: no approval, no signature.");
}

fn print_settlement(n: usize, chain: &str, s: &Settlement) {
    println!();
    println!("[{n}/2] {chain} transfer  —  {}", s.label);
    println!(
        "       amount:      {} base units  ({}, {})",
        s.amount_base_units, s.symbol, s.amount_display
    );
    println!(
        "       destination: {}  \"{}\"",
        s.destination_address, s.destination_name
    );
    println!(
        "       registry:    {}",
        if s.registry_match {
            "MATCH (verified by the approver)"
        } else {
            "NO MATCH"
        }
    );
    println!("       network fee: {} base units", s.fee);
    println!("       receipt tx:  {}", s.tx_id);
    println!(
        "       {chain} SETTLED — beneficiary balance moved by {}; wallet debited amount + fee.",
        s.amount_base_units
    );
}

/// How the verifier refused the tampered package.
struct TheftRefusal {
    code: String,
    detail: String,
}

/// Clone a real, already-approved package, tamper the transfer amount, and ask
/// the independent verifier to sign it against the display the approver
/// confirmed. The verifier re-derives the operation from the candidate bytes and
/// must refuse; a signature here is a [`SecurityRegression`].
fn attempt_theft(
    verifier: &IndependentVerifier,
    approver_key: &SigningKey,
    evm: &Settlement,
) -> Result<TheftRefusal> {
    let mut tampered = evm.package.clone();
    let IntentOperation::AssetTransfer {
        ref mut amount_base_units,
        ..
    } = tampered.intent.operation;
    *amount_base_units = Amount(TRANSFER + 1); // 1234567 -> 1234568

    let now = SystemClock.now();
    let attempt = verifier.approve(
        &evm.display,
        &inputs(&tampered),
        (
            CredentialId::unchecked("independent-approver"),
            ApprovalRole::TreasuryApprover,
            approver_key,
        ),
        GrantId::unchecked("theft-attempt"),
        now,
        120,
    );
    judge_theft_attempt(attempt)
}

/// A signature for the tampered package is a [`SecurityRegression`]; a refusal
/// is the expected outcome.
fn judge_theft_attempt<T>(attempt: OicResult<T>) -> Result<TheftRefusal> {
    match attempt {
        Ok(_) => Err(SecurityRegression(format!(
            "the independent verifier signed a tampered approval package \
             (amount_base_units {TRANSFER} -> {})",
            TRANSFER + 1
        ))
        .into()),
        Err(e) => Ok(TheftRefusal {
            code: format!("{:?}", e.code),
            detail: e.detail.to_string(),
        }),
    }
}

fn print_theft_blocked(refusal: &TheftRefusal) {
    println!();
    println!("--------------------------------------------------------------------------------");
    println!(
        "THEFT BLOCKED: independent verifier refused to sign a substituted amount — no signature produced."
    );
    println!(
        "       attacker cloned the approval package and changed amount_base_units {TRANSFER} -> {},",
        TRANSFER + 1
    );
    println!("       so the changed operation is never signed by the independent verifier.");
    println!(
        "       verifier.approve(...) returned Err [{}]: {}",
        refusal.code, refusal.detail
    );
    println!("--------------------------------------------------------------------------------");
}

/// Entry counts of an audit export whose signature and hash links verified.
struct AuditSummary {
    journal: usize,
    events: usize,
    checkpoints: usize,
}

fn verify_audit(export: &Value, catalog: &Value) -> Result<AuditSummary> {
    let data: OperationsExport = serde_json::from_value(export["operations"].clone())
        .context("parse OperationsExport")?;
    let key_hex = catalog["event_verifying_key"]
        .as_str()
        .context("event_verifying_key")?;
    let key_bytes: [u8; 32] = hex::decode(key_hex)?
        .try_into()
        .map_err(|_| anyhow!("event_verifying_key is not 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)?;
    data.verify(&key).map_err(|e| anyhow!("audit export verification failed: {e}"))?;
    if data.journal.is_empty() {
        bail!("audit journal is empty");
    }
    Ok(AuditSummary {
        journal: data.journal.len(),
        events: data.events.len(),
        checkpoints: data.checkpoints.len(),
    })
}

fn print_audit(audit: &AuditSummary) {
    println!();
    println!("Audit log — signed OperationsExport (verified against catalog event_verifying_key):");
    println!(
        "       journal entries:  {}   (hash-linked and verified)",
        audit.journal
    );
    println!(
        "       lifecycle events: {}   (ed25519-signed)",
        audit.events
    );
    println!(
        "       checkpoints:      {}   (ed25519-signed)",
        audit.checkpoints
    );
    println!("       export signature: VERIFIED");
}

/// Prints the demo as a narrated walkthrough, or with `--check` as one PASS line
/// per assertion for CI logs. Failures are reported by `finish`.
struct Report {
    check: bool,
}

impl Report {
    fn header(&self, catalog: &Value) {
        if !self.check {
            return print_header(catalog);
        }
        println!("oic demo --check: DEVELOPMENT profile, local simulators, no real funds");
        println!(
            "PASS  dev-only guard: environment {}",
            catalog["environment_id"].as_str().unwrap_or("?")
        );
    }

    fn settlement(&self, n: usize, chain: &str, s: &Settlement) {
        if !self.check {
            return print_settlement(n, chain, s);
        }
        println!("PASS  {chain} transfer settled: {} (tx {})", s.label, s.tx_id);
    }

    fn theft_blocked(&self, refusal: &TheftRefusal) {
        if !self.check {
            return print_theft_blocked(refusal);
        }
        println!(
            "PASS  theft blocked: the verifier refused amount_base_units {TRANSFER} -> {} [{}]",
            TRANSFER + 1,
            refusal.code
        );
    }

    fn audit(&self, audit: &AuditSummary) {
        if !self.check {
            return print_audit(audit);
        }
        println!(
            "PASS  audit export verified: {} journal entries, {} events, {} checkpoints",
            audit.journal, audit.events, audit.checkpoints
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_separates_a_security_regression_from_an_incomplete_run() {
        assert_eq!(exit_code(&Ok(())), 0);
        assert_eq!(exit_code(&Err(anyhow!("EVM settlement failed"))), 1);

        let regression = SecurityRegression("tampered package signed".into());
        assert_eq!(exit_code(&Err(regression.into())), EXIT_SECURITY_REGRESSION);

        let with_context = anyhow::Error::new(SecurityRegression("tampered package signed".into()))
            .context("theft scene");
        assert_eq!(exit_code(&Err(with_context)), EXIT_SECURITY_REGRESSION);
    }

    #[test]
    fn a_signature_on_the_tampered_package_exits_with_the_regression_code() {
        let signed: OicResult<()> = Ok(());
        let regression = judge_theft_attempt(signed).err().expect("a signature must not pass");
        assert!(regression.is::<SecurityRegression>(), "{regression:?}");
        assert_eq!(exit_code(&Err(regression)), EXIT_SECURITY_REGRESSION);
    }
}
