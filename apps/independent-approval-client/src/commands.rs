//! One function per `oic-approve` subcommand.
//!
//! Each function takes plain arguments, writes its human-readable report to
//! `out`, and returns a typed result whose error maps to the exit code. No
//! function prints anything taken from the package without first passing it
//! through [`sanitize_display_text`]; the approval card itself is rendered by
//! [`ApprovalDisplay`]'s `Display`, which sanitizes every value.

use crate::keyfile::{parse_role, role_name, ApproverKeyFile, MIN_PBKDF2_ITERATIONS};
use crate::trust::{parse_admin_key_arg, parse_credential_id, parse_verifying_key, TrustRoots};
use crate::{out_err, read_json, write_new_json, ClientError, ClientResult};
use ed25519_dalek::SigningKey;
use oic_adapter_api::{decoded_operation_hash, evidence_hash, AuthorizationTarget, ChainAdapter, ChainProfile, VerifyContext};
use oic_approval_verifier::{fillable_fields_for, sanitize_display_text, verify_grant as verify_grant_signature, ApprovalDisplay, ApproverCredential, DisplayInputs};
use oic_authorization_state::reservation_id_for;
use oic_domain_types::*;
use oic_policy_kernel::{destination_hash, policy_hash};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// `now` from `--now` or the system clock.
pub fn resolve_now(now: Option<u64>) -> ClientResult<UnixSeconds> {
    match now {
        Some(n) => Ok(UnixSeconds(n)),
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| UnixSeconds(d.as_secs()))
            .map_err(|_| ClientError::Usage("system clock is before the Unix epoch; pass --now".into())),
    }
}

/// Load an approval package and check its schema version.
pub fn load_package(path: &Path) -> ClientResult<ApprovalPackage> {
    let p: ApprovalPackage = read_json(path)?;
    if p.schema_version != ApprovalPackage::SCHEMA_VERSION {
        return Err(ClientError::Refused(OicError::invalid_request(format!(
            "unsupported approval package schema version {} (expected {})",
            p.schema_version,
            ApprovalPackage::SCHEMA_VERSION
        ))));
    }
    Ok(p)
}

/// Borrow a package as verifier inputs.
pub fn package_inputs(p: &ApprovalPackage) -> DisplayInputs<'_> {
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

/// Fail closed on evidence that is older than the tightest of the evidence,
/// policy, and chain-profile windows, or timestamped in the future (RFC 0001
/// §4.1: stale evidence fails closed). The verifier only warns; this client
/// refuses to present such a display as approvable.
pub fn check_freshness(trust: &TrustRoots, p: &ApprovalPackage, now: UnixSeconds) -> OicResult<()> {
    let profile = trust.profile(&p.intent.chain_profile_id)?;
    let ev = &p.evidence;
    if ev.observed_at > now {
        return Err(OicError::stale_evidence(format!(
            "evidence is timestamped {}s in the future; check the approval client clock",
            ev.observed_at.0 - now.0
        )));
    }
    let age = now.0 - ev.observed_at.0;
    let max = ev.max_staleness_seconds.min(p.policy.max_evidence_age_seconds).min(profile.max_evidence_age_seconds);
    if age > max {
        return Err(OicError::stale_evidence(format!("evidence is {age}s old, maximum {max}s")));
    }
    Ok(())
}

fn write_card(out: &mut dyn Write, display: &ApprovalDisplay) -> ClientResult<()> {
    write!(out, "{display}").map_err(out_err)?;
    for w in &display.warnings {
        writeln!(out, "warning: {}", sanitize_display_text(w)).map_err(out_err)?;
    }
    Ok(())
}

fn mismatch_error(display: &ApprovalDisplay) -> ClientError {
    ClientError::DestinationMismatch(format!(
        "candidate pays {} but registry destination {} v{} is a different address; do not approve",
        display.recipient_address_display, display.destination_id, display.destination_version
    ))
}

/// Render the package and print the card. Returns the display whether or
/// not it is approvable; callers decide on mismatch/freshness.
fn render_and_print(trust: &TrustRoots, p: &ApprovalPackage, now: UnixSeconds, out: &mut dyn Write) -> ClientResult<ApprovalDisplay> {
    let verifier = trust.verifier()?;
    let display = verifier.render(&package_inputs(p), now)?;
    write_card(out, &display)?;
    Ok(display)
}

/// Refusals that apply after a card was shown: destination mismatch (exit
/// 4), then stale evidence (exit 3).
fn approvable(trust: &TrustRoots, p: &ApprovalPackage, display: &ApprovalDisplay, now: UnixSeconds) -> ClientResult<()> {
    if !display.destination_matches_registry {
        return Err(mismatch_error(display));
    }
    check_freshness(trust, p, now)?;
    Ok(())
}

/// The bounded template [`oic_approval_verifier::IndependentVerifier`]
/// grants for this package in `BoundedDirectTransfer` mode, recomputed from
/// the enrolled profile, registry objects, and the decoded amount.
pub fn expected_template(trust: &TrustRoots, p: &ApprovalPackage, display: &ApprovalDisplay) -> OicResult<BoundedTransferTemplate> {
    let profile = trust.profile(&p.intent.chain_profile_id)?;
    let amount: u128 = display.amount_base_units.parse().map_err(|_| OicError::internal("display amount is not an integer"))?;
    Ok(BoundedTransferTemplate {
        chain_wallet_id: p.intent.chain_wallet_id.clone(),
        network_id: profile.network_id.clone(),
        asset_id: p.asset.asset_id.clone(),
        amount_base_units: Amount(amount),
        destination_id: p.destination.destination_id.clone(),
        destination_version: p.destination.version,
        destination_address: p.destination.address.clone(),
        max_native_fee_base_units: p.intent.constraints.max_network_fee_base_units,
        maximum_successful_payments: p.intent.constraints.maximum_successful_payments,
        fillable: fillable_fields_for(&profile.adapter_id)?,
    })
}

fn profile_and_adapter<'t>(trust: &'t TrustRoots, p: &ApprovalPackage) -> OicResult<(&'t ChainProfile, Arc<dyn ChainAdapter>)> {
    let profile = trust.profile(&p.intent.chain_profile_id)?;
    let adapter = trust.accepted_adapter(&profile.adapter_id)?;
    Ok((profile, adapter))
}

fn registry_ctx<'a>(profile: &'a ChainProfile, p: &'a ApprovalPackage) -> VerifyContext<'a> {
    VerifyContext { profile, wallet: &p.wallet, key: &p.key, asset: &p.asset, destination: &p.destination, evidence: &p.evidence }
}

fn s(v: impl std::fmt::Display) -> String {
    sanitize_display_text(&v.to_string())
}

// ---------------------------------------------------------------------------
// init-trust
// ---------------------------------------------------------------------------

pub struct InitTrustArgs {
    pub out: PathBuf,
    /// `<credential_id>=<ed25519 pubkey hex>` per administrator.
    pub admin_keys: Vec<String>,
    pub admin_quorum: u8,
    /// Paths of `ChainProfile` JSON files.
    pub profiles: Vec<PathBuf>,
}

/// Write a trust file pinning this binary's adapter builds.
pub fn init_trust(args: &InitTrustArgs, out: &mut dyn Write) -> ClientResult<TrustRoots> {
    let admins = args.admin_keys.iter().map(|a| parse_admin_key_arg(a)).collect::<ClientResult<Vec<_>>>()?;
    let profiles = args.profiles.iter().map(|p| read_json::<ChainProfile>(p)).collect::<ClientResult<Vec<_>>>()?;
    let trust = TrustRoots::new(admins, args.admin_quorum, profiles).map_err(|e| ClientError::Usage(e.detail))?;
    trust.save(&args.out)?;
    writeln!(out, "trust roots written to {}", s(args.out.display())).map_err(out_err)?;
    writeln!(out, "admin quorum: {} of {}", trust.admin_quorum, trust.admin_keys.len()).map_err(out_err)?;
    for a in &trust.admin_keys {
        writeln!(out, "admin: {} {}", s(&a.credential_id), a.public_key_hex).map_err(out_err)?;
    }
    for p in &trust.chain_profiles {
        writeln!(out, "chain profile: {} adapter={} network={} hash={}", s(&p.chain_profile_id), s(&p.adapter_id), s(&p.network_id), p.hash()?).map_err(out_err)?;
    }
    for (adapter, builds) in &trust.accepted_verifier_builds {
        for b in builds {
            writeln!(out, "pinned verifier build: {} {}", s(adapter), b).map_err(out_err)?;
        }
    }
    Ok(trust)
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

pub struct KeygenArgs {
    pub out: PathBuf,
    pub credential_id: String,
    pub role: String,
}

/// What an administrator enrolls for a new approver credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeygenOutcome {
    pub credential_id: CredentialId,
    pub role: ApprovalRole,
    pub public_key_hex: String,
}

/// Generate an Ed25519 approver credential and write it encrypted under
/// `passphrase` with mode 0600.
pub fn keygen(args: &KeygenArgs, passphrase: &[u8], out: &mut dyn Write) -> ClientResult<KeygenOutcome> {
    let credential_id = parse_credential_id(&args.credential_id)?;
    let role = parse_role(&args.role)?;
    let signing_key = SigningKey::generate(&mut OsRng);
    let file = ApproverKeyFile::seal(credential_id.clone(), role, &signing_key, passphrase, MIN_PBKDF2_ITERATIONS).map_err(|e| ClientError::Usage(e.detail))?;
    file.save(&args.out)?;
    let outcome = KeygenOutcome { credential_id, role, public_key_hex: file.public_key_hex.clone() };
    writeln!(out, "approver key written to {} (mode 0600, encrypted)", s(args.out.display())).map_err(out_err)?;
    writeln!(out, "credential_id: {}", s(&outcome.credential_id)).map_err(out_err)?;
    writeln!(out, "role: {}", role_name(role)).map_err(out_err)?;
    writeln!(out, "public_key: {}", outcome.public_key_hex).map_err(out_err)?;
    writeln!(out, "enroll with: --approver {}={}={}", s(&outcome.credential_id), outcome.public_key_hex, role_name(role)).map_err(out_err)?;
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

pub struct ShowArgs {
    pub trust: PathBuf,
    pub package: PathBuf,
    pub now: Option<u64>,
}

/// Render and print the approval card. Errors after the card is printed
/// when the decoded recipient is not the registry destination (exit 4) or
/// the evidence is stale (exit 3).
pub fn show(args: &ShowArgs, out: &mut dyn Write) -> ClientResult<ApprovalDisplay> {
    let trust = TrustRoots::load(&args.trust)?;
    let package = load_package(&args.package)?;
    let now = resolve_now(args.now)?;
    let display = render_and_print(&trust, &package, now, out)?;
    approvable(&trust, &package, &display, now)?;
    writeln!(out, "verified: every value above was recomputed from the signed objects by the pinned adapters").map_err(out_err)?;
    Ok(display)
}

// ---------------------------------------------------------------------------
// approve
// ---------------------------------------------------------------------------

pub struct ApproveArgs {
    pub trust: PathBuf,
    pub package: PathBuf,
    pub key: PathBuf,
    pub grant_id: String,
    pub ttl_seconds: u64,
    pub out: PathBuf,
    pub now: Option<u64>,
    /// Skip the interactive confirmation.
    pub yes: bool,
}

/// Render, print, confirm, sign, and write an approval grant. Nothing is
/// written unless every check passes and the approver confirmed.
pub fn approve(args: &ApproveArgs, passphrase: &[u8], confirm: &mut dyn BufRead, out: &mut dyn Write) -> ClientResult<ApprovalGrant> {
    let trust = TrustRoots::load(&args.trust)?;
    let package = load_package(&args.package)?;
    let now = resolve_now(args.now)?;
    let grant_id = GrantId::new(args.grant_id.clone()).ok_or_else(|| ClientError::Usage(format!("invalid grant id `{}`", s(&args.grant_id))))?;
    if args.ttl_seconds == 0 {
        return Err(ClientError::Usage("--ttl-seconds must be positive".into()));
    }
    if args.out.exists() {
        return Err(ClientError::Io(format!("{} already exists; refusing to overwrite", s(args.out.display()))));
    }
    let keyfile = ApproverKeyFile::load(&args.key)?;
    let key = keyfile.open(passphrase)?;

    let display = render_and_print(&trust, &package, now, out)?;
    approvable(&trust, &package, &display, now)?;

    if !args.yes {
        write!(
            out,
            "Sign approval grant {} as {} ({}) for exactly the operation above? [y/N]: ",
            s(&grant_id),
            s(&key.credential_id),
            role_name(key.role)
        )
        .map_err(out_err)?;
        out.flush().map_err(out_err)?;
        let mut line = String::new();
        confirm.read_line(&mut line).map_err(|e| ClientError::Io(format!("reading confirmation: {e}")))?;
        let answer = line.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" {
            writeln!(out).map_err(out_err)?;
            return Err(ClientError::Refused(OicError::new(ErrorCode::ApprovalRequired, "approver did not confirm; no grant written")));
        }
    }

    let verifier = trust.verifier()?;
    let grant = verifier.approve(&display, &package_inputs(&package), (key.credential_id.clone(), key.role, &key.signing_key), grant_id, now, args.ttl_seconds)?;
    let self_roster = [ApproverCredential { credential_id: key.credential_id.clone(), verifying_key: key.verifying_key(), role: key.role }];
    verify_grant_signature(&grant, &self_roster, now)?;
    write_new_json(&args.out, &grant, 0o644)?;
    writeln!(out, "grant {} written to {}", s(&grant.body.grant_id), s(args.out.display())).map_err(out_err)?;
    write_scope(out, &grant.body.scope)?;
    writeln!(out, "expires at: {}", grant.body.expires_at.0).map_err(out_err)?;
    Ok(grant)
}

fn write_scope(out: &mut dyn Write, scope: &GrantScope) -> ClientResult<()> {
    match scope {
        GrantScope::ExactCandidate { candidate_id, candidate_revision, preview_hash } => {
            writeln!(out, "scope: exact candidate {} rev {} preview_hash {}", s(candidate_id), candidate_revision, preview_hash).map_err(out_err)
        }
        GrantScope::BoundedDirectTransfer { template } => {
            let fill: Vec<String> = template.fillable.iter().map(|f| format!("{f:?}")).collect();
            writeln!(
                out,
                "scope: bounded direct transfer of {} base units of {} from {} to {} v{} on {}, max fee {}, max payments {}, fillable [{}]",
                template.amount_base_units,
                s(&template.asset_id),
                s(&template.chain_wallet_id),
                s(&template.destination_id),
                template.destination_version,
                s(&template.network_id),
                template.max_native_fee_base_units,
                template.maximum_successful_payments,
                fill.join(", ")
            )
            .map_err(out_err)
        }
    }
}

// ---------------------------------------------------------------------------
// verify-grant
// ---------------------------------------------------------------------------

pub struct VerifyGrantArgs {
    pub trust: PathBuf,
    pub package: PathBuf,
    pub grant: PathBuf,
    /// `<credential_id>=<ed25519 pubkey hex>=<role>`.
    pub approver: String,
    pub now: Option<u64>,
}

/// A verified grant together with the display it binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantBinding {
    pub grant: ApprovalGrant,
    pub display: ApprovalDisplay,
}

/// Parse `<credential_id>=<ed25519 pubkey hex>=<role>`.
pub fn parse_approver_arg(arg: &str) -> ClientResult<ApproverCredential> {
    let parts: Vec<&str> = arg.splitn(3, '=').collect();
    let [id, key, role] = parts.as_slice() else {
        return Err(ClientError::Usage("--approver must be <credential_id>=<ed25519 pubkey hex>=<role>".into()));
    };
    Ok(ApproverCredential {
        credential_id: parse_credential_id(id)?,
        verifying_key: parse_verifying_key(key).map_err(|e| ClientError::Usage(format!("--approver: {}", e.detail)))?,
        role: parse_role(role)?,
    })
}

fn bind(ok: bool, what: &str) -> OicResult<()> {
    if ok {
        Ok(())
    } else {
        Err(OicError::scope(format!("grant does not bind this package: {what}")))
    }
}

/// Check one grant body's binding to the package and its recomputed display.
fn check_grant_binding(trust: &TrustRoots, p: &ApprovalPackage, display: &ApprovalDisplay, body: &ApprovalGrantBody) -> OicResult<()> {
    let it = &p.intent;
    bind(body.institution_id == it.institution_id && body.environment_id == it.environment_id, "institution/environment")?;
    bind(body.vault_id == it.vault_id, "vault")?;
    bind(body.intent_id == it.intent_id, "intent id")?;
    bind(body.intent_hash == display.intent_hash, "intent hash")?;
    bind(body.policy_id == p.policy.policy_id && body.policy_epoch == p.policy.policy_epoch, "policy id/epoch")?;
    match (&body.scope, it.constraints.approval_mode) {
        (GrantScope::ExactCandidate { candidate_id, candidate_revision, preview_hash }, ApprovalMode::ExactCandidate) => {
            bind(*candidate_id == p.candidate.candidate_id && *candidate_revision == p.candidate.candidate_revision, "candidate id/revision")?;
            bind(*preview_hash == display.preview_hash, "exact-candidate preview hash")
        }
        (GrantScope::BoundedDirectTransfer { template }, ApprovalMode::BoundedDirectTransfer) => {
            bind(*template == expected_template(trust, p, display)?, "bounded template")?;
            let (profile, adapter) = profile_and_adapter(trust, p)?;
            adapter.verify_candidate(&p.candidate, &AuthorizationTarget::Template(template), &registry_ctx(profile, p))?;
            Ok(())
        }
        _ => bind(false, "grant scope does not match the intent's approval mode"),
    }
}

/// Verify a grant's signature, role, and validity at `now` against the
/// given approver credential, and that it binds exactly this package.
pub fn verify_grant(args: &VerifyGrantArgs, out: &mut dyn Write) -> ClientResult<GrantBinding> {
    let trust = TrustRoots::load(&args.trust)?;
    let package = load_package(&args.package)?;
    let grant: ApprovalGrant = read_json(&args.grant)?;
    let approver = parse_approver_arg(&args.approver)?;
    let now = resolve_now(args.now)?;
    verify_grant_signature(&grant, std::slice::from_ref(&approver), now)?;
    let display = trust.verifier()?.render(&package_inputs(&package), now)?;
    if !display.destination_matches_registry {
        return Err(mismatch_error(&display));
    }
    check_grant_binding(&trust, &package, &display, &grant.body)?;
    let b = &grant.body;
    writeln!(out, "grant {} verified", s(&b.grant_id)).map_err(out_err)?;
    writeln!(out, "approver: {} ({})", s(&b.approver_credential_id), role_name(b.approver_role)).map_err(out_err)?;
    writeln!(out, "intent: {} hash {}", s(&b.intent_id), b.intent_hash).map_err(out_err)?;
    writeln!(out, "vault: {}", s(&b.vault_id)).map_err(out_err)?;
    writeln!(out, "policy: {} epoch {}", s(&b.policy_id), b.policy_epoch).map_err(out_err)?;
    write_scope(out, &b.scope)?;
    writeln!(out, "operation: {} {} to {}", display.amount_display, s(&display.asset_symbol_from_registry), s(&display.recipient_address_display)).map_err(out_err)?;
    writeln!(out, "max network fee: {} native base units", display.max_native_fee_base_units).map_err(out_err)?;
    writeln!(out, "valid: {} .. {}", b.issued_at.0, b.expires_at.0).map_err(out_err)?;
    Ok(GrantBinding { grant, display })
}

// ---------------------------------------------------------------------------
// inspect-envelope
// ---------------------------------------------------------------------------

pub struct InspectEnvelopeArgs {
    pub trust: PathBuf,
    pub package: PathBuf,
    pub envelope: PathBuf,
    pub now: Option<u64>,
}

/// One compared envelope field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldCheck {
    pub field: String,
    pub envelope: String,
    pub expected: String,
    pub ok: bool,
}

/// Field-by-field comparison of an envelope against the package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeReport {
    /// `oic_signer::envelope_body_hash` recomputed over the envelope body.
    pub envelope_body_hash: Hash32,
    pub checks: Vec<FieldCheck>,
}

impl EnvelopeReport {
    pub fn mismatches(&self) -> Vec<&str> {
        self.checks.iter().filter(|c| !c.ok).map(|c| c.field.as_str()).collect()
    }
}

#[derive(Default)]
struct Checks(Vec<FieldCheck>);

impl Checks {
    fn eq(&mut self, field: impl Into<String>, envelope: impl std::fmt::Display, expected: impl std::fmt::Display) {
        let (envelope, expected) = (envelope.to_string(), expected.to_string());
        let ok = envelope == expected;
        self.0.push(FieldCheck { field: field.into(), envelope, expected, ok });
    }
    fn with(&mut self, field: impl Into<String>, envelope: String, expected: String, ok: bool) {
        self.0.push(FieldCheck { field: field.into(), envelope, expected, ok });
    }
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{} ({} bytes)", hex::encode(Sha256::digest(bytes)), bytes.len())
}

fn json_digest<T: serde::Serialize>(v: &T) -> OicResult<String> {
    let bytes = serde_json::to_vec(v).map_err(|e| OicError::internal(format!("json encoding: {e}")))?;
    Ok(digest_of(&bytes))
}

fn grant_binding_summary(b: &ApprovalGrantBody) -> String {
    format!("{}/{} vault={} intent={} intent_hash={} policy={}@{}", b.institution_id, b.environment_id, b.vault_id, b.intent_id, b.intent_hash, b.policy_id, b.policy_epoch)
}

fn scope_summary(scope: &GrantScope) -> OicResult<String> {
    Ok(match scope {
        GrantScope::ExactCandidate { candidate_id, candidate_revision, preview_hash } => format!("exact {candidate_id} rev {candidate_revision} preview {preview_hash}"),
        GrantScope::BoundedDirectTransfer { template } => format!("bounded template {}", json_digest(template)?),
    })
}

/// Compare every envelope field an approver's view depends on with the
/// value recomputed from the package by the pinned adapter, and print a
/// field-by-field report. Any mismatch is a refusal (exit 3), or exit 4
/// when the candidate's decoded recipient is not the registry destination.
pub fn inspect_envelope(args: &InspectEnvelopeArgs, out: &mut dyn Write) -> ClientResult<EnvelopeReport> {
    let trust = TrustRoots::load(&args.trust)?;
    let p = load_package(&args.package)?;
    let envelope: AuthorizationEnvelope = read_json(&args.envelope)?;
    let now = resolve_now(args.now)?;
    let display = trust.verifier()?.render(&package_inputs(&p), now)?;
    let (profile, adapter) = profile_and_adapter(&trust, &p)?;
    let manifest = adapter.manifest();
    let ctx = registry_ctx(profile, &p);
    let b = &envelope.body;
    let c = &p.candidate;
    let body_hash = oic_signer::envelope_body_hash(b)?;

    let mut k = Checks::default();
    k.eq("institution_id", s(&b.institution_id), s(&p.intent.institution_id));
    k.eq("environment_id", s(&b.environment_id), s(&p.intent.environment_id));
    k.eq("vault_id", s(&b.vault_id), s(&p.vault.vault_id));
    k.eq("chain_wallet_id", s(&b.chain_wallet_id), s(&p.wallet.chain_wallet_id));
    k.eq("intent_id", s(&b.intent_id), s(&p.intent.intent_id));
    k.eq("intent_hash", b.intent_hash, display.intent_hash);
    k.eq("operation_family_id", s(&b.operation_family_id), s(&c.operation_family_id));
    k.eq("candidate_id", s(&b.candidate_id), s(&c.candidate_id));
    k.eq("candidate_revision", b.candidate_revision, c.candidate_revision);
    k.eq("chain_profile_id", s(&b.chain_profile_id), s(&profile.chain_profile_id));
    k.eq("chain_profile_hash", b.chain_profile_hash, profile.hash()?);
    k.eq("key_id", s(&b.key_id), s(&p.key.key_id));
    k.eq("key_epoch", b.key_epoch, p.key.key_epoch);
    k.eq("public_key_hash", b.public_key_hash, oic_signer::public_key_hash(&p.key.public_key)?);
    k.eq("adapter_id", s(&b.adapter_id), s(&manifest.adapter_id));
    k.eq("adapter_version", s(&b.adapter_version), s(&manifest.adapter_version));
    k.eq("verifier_build_hash", b.verifier_build_hash, manifest.verifier_build_hash);
    k.eq("policy_id", s(&b.policy_id), s(&p.policy.policy_id));
    k.eq("policy_epoch", b.policy_epoch, p.policy.policy_epoch);
    k.eq("policy_hash", b.policy_hash, policy_hash(&p.policy)?);
    k.eq("allowlist_version", b.allowlist_version, p.policy.allowlist_version);
    k.eq("native_unsigned_bytes", digest_of(b.native_unsigned_bytes.as_slice()), digest_of(c.native_unsigned_bytes.as_slice()));
    let payloads = adapter.signing_payloads(&c.native_unsigned_bytes, &p.key)?;
    k.eq("native_signing_payloads", json_digest(&b.native_signing_payloads)?, json_digest(&payloads)?);
    let decoded = adapter.decode_candidate(c, &ctx)?;
    k.eq("decoded_operation_hash", b.decoded_operation_hash, decoded_operation_hash(&decoded)?);
    k.eq("evidence_bundle_hash", b.evidence_bundle_hash, evidence_hash(&p.evidence)?);
    k.eq("destination_hash", b.destination_hash, destination_hash(&p.destination)?);
    k.with(
        "decoded_recipient_matches_registry",
        s(&display.recipient_address_display),
        format!("{} v{}", s(&display.destination_id), display.destination_version),
        display.destination_matches_registry,
    );
    k.eq("budget_reservation_id", s(&b.budget_reservation_id), s(reservation_id_for(&c.operation_family_id, &c.candidate_id, c.candidate_revision)?));
    if display.destination_matches_registry {
        let verified = adapter.verify_candidate(c, &AuthorizationTarget::Intent(&p.intent), &ctx)?;
        k.eq("resource_reservations", json_digest(&b.resource_reservations)?, json_digest(&verified.claims.resources)?);
        for o in &verified.claims.asset_outflows {
            let max = b.maximum_asset_outflows.iter().find(|x| x.asset_id == o.asset_id);
            k.with(
                format!("maximum_asset_outflows[{}]", s(&o.asset_id)),
                max.map(|m| m.amount_base_units.to_string()).unwrap_or_else(|| "absent".into()),
                format!(">= {}", o.amount_base_units),
                max.is_some_and(|m| o.amount_base_units <= m.amount_base_units),
            );
        }
        for f in &verified.claims.native_fees {
            let max = b.maximum_native_fees.iter().find(|x| x.network_id == f.network_id);
            k.with(
                format!("maximum_native_fees[{}]", s(&f.network_id)),
                max.map(|m| m.amount_base_units.to_string()).unwrap_or_else(|| "absent".into()),
                format!(">= {}", f.amount_base_units),
                max.is_some_and(|m| f.amount_base_units <= m.amount_base_units),
            );
        }
    }
    k.eq("expected_chain_validity_constraints", json_digest(&b.expected_chain_validity_constraints)?, json_digest(&adapter.validity_constraints(c, &p.evidence)?)?);
    let template = expected_template(&trust, &p, &display)?;
    for (i, g) in b.approval_grants.iter().enumerate() {
        let gb = &g.body;
        let want_binding = ApprovalGrantBody {
            institution_id: p.intent.institution_id.clone(),
            environment_id: p.intent.environment_id.clone(),
            vault_id: p.intent.vault_id.clone(),
            intent_id: p.intent.intent_id.clone(),
            intent_hash: display.intent_hash,
            policy_id: p.policy.policy_id.clone(),
            policy_epoch: p.policy.policy_epoch,
            ..gb.clone()
        };
        k.eq(format!("approval_grants[{i}].binding"), s(grant_binding_summary(gb)), s(grant_binding_summary(&want_binding)));
        let want_scope = match p.intent.constraints.approval_mode {
            ApprovalMode::ExactCandidate => GrantScope::ExactCandidate {
                candidate_id: c.candidate_id.clone(),
                candidate_revision: c.candidate_revision,
                preview_hash: display.preview_hash,
            },
            ApprovalMode::BoundedDirectTransfer => GrantScope::BoundedDirectTransfer { template: template.clone() },
        };
        k.eq(format!("approval_grants[{i}].scope"), s(scope_summary(&gb.scope)?), s(scope_summary(&want_scope)?));
    }
    let r = &envelope.authorization_state_receipt.body;
    k.eq("authorization_state_receipt.envelope_body_hash", r.envelope_body_hash, body_hash);
    k.eq("authorization_state_receipt.candidate", format!("{} rev {}", s(&r.candidate_id), r.candidate_revision), format!("{} rev {}", s(&c.candidate_id), c.candidate_revision));
    k.eq("authorization_state_receipt.signer_session_id", s(&r.signer_session_id), s(&b.signer_session_id));
    k.eq("authorization_state_receipt.policy_epoch", r.policy_epoch, p.policy.policy_epoch);
    k.eq("authorization_state_receipt.reservation", format!("{} v{}", s(&r.reservation_id), r.reservation_version), format!("{} v{}", s(&b.budget_reservation_id), b.reservation_version));
    k.eq("authorization_state_receipt.scope", format!("{}/{}", s(&r.institution_id), s(&r.environment_id)), format!("{}/{}", s(&p.intent.institution_id), s(&p.intent.environment_id)));

    let report = EnvelopeReport { envelope_body_hash: body_hash, checks: k.0 };
    writeln!(out, "envelope_body_hash (recomputed): {body_hash}").map_err(out_err)?;
    for chk in &report.checks {
        if chk.ok {
            writeln!(out, "MATCH     {}", chk.field).map_err(out_err)?;
        } else {
            writeln!(out, "MISMATCH  {}: envelope={} expected={}", chk.field, chk.envelope, chk.expected).map_err(out_err)?;
        }
    }
    writeln!(out, "note: the authority receipt signature is not checked here (the authority key is not an approval trust root); every signer verifies it").map_err(out_err)?;
    let bad = report.mismatches();
    if !bad.is_empty() {
        writeln!(out, "RESULT: {} mismatch(es): {}", bad.len(), bad.join(", ")).map_err(out_err)?;
    }
    if !display.destination_matches_registry {
        return Err(mismatch_error(&display));
    }
    if !bad.is_empty() {
        return Err(ClientError::Refused(OicError::scope(format!("envelope does not match the package: {}", bad.join(", ")))));
    }
    writeln!(out, "RESULT: envelope matches the package the approvers saw").map_err(out_err)?;
    Ok(report)
}
