//! End-to-end tests of every `oic-approve` command over real EVM and Solana
//! approval packages (RFC 0001 §4.3, §3.4, A34; RFC 0002 §8, C15).

mod common;

use common::*;
use oic_adapter_api::{decoded_operation_hash, evidence_hash, VerifyContext};
use oic_approval_client::commands::*;
use oic_approval_client::keyfile::{ApproverKeyFile, MIN_PBKDF2_ITERATIONS};
use oic_approval_client::trust::{compiled_verifier_builds, TrustRoots};
use oic_approval_client::{ClientError, EXIT_DESTINATION_MISMATCH, EXIT_IO, EXIT_REFUSED, EXIT_USAGE};
use oic_approval_verifier::verify_grant as verify_grant_signature;
use oic_domain_types::*;
use oic_policy_kernel::preview_hash;
use std::path::Path;
use std::process::Command;

fn show_at(f: &Files, package: &Path, now: u64) -> (Result<oic_approval_verifier::ApprovalDisplay, ClientError>, String) {
    let mut out = Vec::new();
    let r = show(&ShowArgs { trust: f.trust(), package: package.to_path_buf(), now: Some(now) }, &mut out);
    (r, String::from_utf8(out).unwrap())
}

fn approve_args(f: &Files, package: &Path, out: &str) -> ApproveArgs {
    ApproveArgs {
        trust: f.trust(),
        package: package.to_path_buf(),
        key: f.approver_key(),
        grant_id: "grant-1".into(),
        ttl_seconds: 300,
        out: f.path(out),
        now: Some(NOW),
        yes: true,
    }
}

fn run_approve(args: &ApproveArgs, passphrase: &[u8], stdin: &str) -> (Result<ApprovalGrant, ClientError>, String) {
    let mut out = Vec::new();
    let mut input = stdin.as_bytes();
    let r = approve(args, passphrase, &mut input, &mut out);
    (r, String::from_utf8(out).unwrap())
}

/// Preview hash computed independently of the verifier: decode with the
/// pinned adapter, hash, and combine per `oic_policy_kernel::preview_hash`.
fn independent_preview(p: &ApprovalPackage) -> Hash32 {
    let (profile, adapter) = adapter_for(p);
    let ctx = VerifyContext { profile: &profile, wallet: &p.wallet, key: &p.key, asset: &p.asset, destination: &p.destination, evidence: &p.evidence };
    let decoded = adapter.decode_candidate(&p.candidate, &ctx).unwrap();
    preview_hash(&p.candidate.candidate_id, p.candidate.candidate_revision, decoded_operation_hash(&decoded).unwrap(), evidence_hash(&p.evidence).unwrap())
}

fn decoded_max_fee(p: &ApprovalPackage) -> String {
    let (profile, adapter) = adapter_for(p);
    let ctx = VerifyContext { profile: &profile, wallet: &p.wallet, key: &p.key, asset: &p.asset, destination: &p.destination, evidence: &p.evidence };
    adapter.decode_candidate(&p.candidate, &ctx).unwrap().max_native_fee().to_string()
}

fn card_row(label: &str, value: &str) -> String {
    format!("| {label:<22}{value:<54} |")
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

#[test]
fn show_evm_card_has_destination_amount_fee_and_policy_epoch() {
    let f = Files::new();
    let p = evm_package(1_500_000, ApprovalMode::ExactCandidate, None);
    let pkg = f.write_json("package.json", &p);
    let (r, out) = show_at(&f, &pkg, NOW);
    let d = r.unwrap();
    let dest = oic_adapter_evm::address::eip55(&evm_dest_address());
    assert_eq!(dest, p.destination.address_display);
    assert!(out.contains(&card_row("TO ADDRESS", &dest)), "{out}");
    assert!(out.contains(&card_row("AMOUNT", "1.5 USDC")), "{out}");
    assert!(out.contains(&card_row("AMOUNT (BASE UNITS)", "1500000 (decimals 6)")), "{out}");
    let fee = decoded_max_fee(&p);
    assert!(out.contains(&card_row("MAX NETWORK FEE", &format!("{fee} native base units"))), "{out}");
    assert!(out.contains(&card_row("POLICY", "pol-1 epoch 4")), "{out}");
    assert!(out.contains(&card_row("REGISTRY MATCH", "YES")), "{out}");
    assert!(out.contains("warning: DEVELOPMENT SIMULATOR EVIDENCE"), "{out}");
    // The card is printed exactly as ApprovalDisplay renders it.
    assert!(out.starts_with(&d.to_string()), "{out}");
    assert!(d.to_string().lines().all(|l| l.len() == 80));
    assert_eq!(d.preview_hash, independent_preview(&p));
}

#[test]
fn show_solana_card_has_nine_decimal_amount() {
    let f = Files::new();
    let p = sol_package(1_234_567_891, ApprovalMode::ExactCandidate, None);
    let pkg = f.write_json("package.json", &p);
    let (r, out) = show_at(&f, &pkg, NOW);
    r.unwrap();
    let dest = oic_adapter_solana::address::to_base58(&sol_dest_owner());
    assert!(out.contains(&card_row("TO ADDRESS", &dest)), "{out}");
    assert!(out.contains(&card_row("AMOUNT", "1.234567891 SOL")), "{out}");
    let fee = decoded_max_fee(&p);
    assert!(out.contains(&card_row("MAX NETWORK FEE", &format!("{fee} native base units"))), "{out}");
    assert!(out.contains(&card_row("POLICY", "pol-1 epoch 4")), "{out}");
}

/// A34/C15: the console edited the destination's display text (and the
/// deceived administrators even signed the edited record), but the bytes pay
/// the real address. The card shows the address recomputed from the bytes.
#[test]
fn a34_c15_edited_address_text_is_never_shown() {
    let f = Files::new();
    let edited = "0xFEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE";
    let mut p = evm_package(1_500_000, ApprovalMode::ExactCandidate, None);
    let mut d = p.destination.clone();
    d.address_display = edited.into();
    p.destination = signed_destination(d, &[1, 2]);
    let pkg = f.write_json("package.json", &p);
    let (r, out) = show_at(&f, &pkg, NOW);
    let display = r.unwrap();
    let real = oic_adapter_evm::address::eip55(&evm_dest_address());
    assert_eq!(display.recipient_address_display, real);
    assert!(out.contains(&card_row("TO ADDRESS", &real)), "{out}");
    assert!(!out.contains(edited), "edited console text reached the card: {out}");

    // Same edit without a fresh admin quorum: the destination is no longer a
    // registry entry at all.
    let mut p2 = evm_package(1_500_000, ApprovalMode::ExactCandidate, None);
    p2.destination.address_display = edited.into();
    let pkg2 = f.write_json("package-unsigned-edit.json", &p2);
    let (r2, out2) = show_at(&f, &pkg2, NOW);
    let e = r2.unwrap_err();
    assert_eq!(e.exit_code(), EXIT_REFUSED);
    assert_eq!(e.code(), Some(ErrorCode::InvalidSignature));
    assert!(!out2.contains(edited));
}

/// A34/C15: the candidate bytes pay someone other than the registry
/// destination. `show` exits 4 showing the real payee; `approve` writes nothing.
#[test]
fn a34_c15_bytes_paying_another_address_exit_4_and_no_grant() {
    for (p, attacker) in [
        (evm_package(1_500_000, ApprovalMode::ExactCandidate, Some(evm_attacker_address())), oic_adapter_evm::address::eip55(&evm_attacker_address())),
        (sol_package(1_000_000, ApprovalMode::ExactCandidate, Some(sol_attacker_owner())), oic_adapter_solana::address::to_base58(&sol_attacker_owner())),
    ] {
        let f = Files::new();
        let pkg = f.write_json("package.json", &p);
        let (r, out) = show_at(&f, &pkg, NOW);
        let e = r.unwrap_err();
        assert_eq!(e.exit_code(), EXIT_DESTINATION_MISMATCH, "{e}");
        assert!(out.contains(&card_row("TO ADDRESS", &attacker)), "{out}");
        assert!(out.contains(&card_row("REGISTRY MATCH", "NO - DO NOT APPROVE")), "{out}");
        assert!(out.contains("warning: DESTINATION MISMATCH"), "{out}");

        let args = approve_args(&f, &pkg, "grant.json");
        let (r, _) = run_approve(&args, PASSPHRASE, "");
        assert_eq!(r.unwrap_err().exit_code(), EXIT_DESTINATION_MISMATCH);
        assert!(!exists(&args.out));
    }
}

#[test]
fn policy_with_one_admin_signature_exit_3() {
    let f = Files::new();
    let mut p = evm_package(1_500_000, ApprovalMode::ExactCandidate, None);
    p.policy = policy(&p.asset.asset_id, &[1]);
    let pkg = f.write_json("package.json", &p);
    let (r, out) = show_at(&f, &pkg, NOW);
    let e = r.unwrap_err();
    assert_eq!(e.exit_code(), EXIT_REFUSED);
    assert_eq!(e.code(), Some(ErrorCode::InvalidSignature));
    assert!(out.is_empty(), "no card for an unverified policy: {out}");
    let args = approve_args(&f, &pkg, "grant.json");
    assert_eq!(run_approve(&args, PASSPHRASE, "").0.unwrap_err().exit_code(), EXIT_REFUSED);
    assert!(!exists(&args.out));
}

#[test]
fn unsigned_destination_and_tampered_evidence_and_scope_mismatch_exit_3() {
    let f = Files::new();
    let base = sol_package(1_000_000, ApprovalMode::ExactCandidate, None);

    let mut p = base.clone();
    p.destination.administrative_signatures.clear();
    let (r, _) = show_at(&f, &f.write_json("unsigned-dest.json", &p), NOW);
    assert_eq!(r.unwrap_err().code(), Some(ErrorCode::InvalidSignature));

    let mut p = base.clone();
    p.evidence.state.height += 1;
    let (r, _) = show_at(&f, &f.write_json("evidence.json", &p), NOW);
    assert_eq!(r.unwrap_err().code(), Some(ErrorCode::UnverifiableTransaction));

    let mut p = base.clone();
    p.vault.policy_id = PolicyId::unchecked("pol-other");
    let (r, _) = show_at(&f, &f.write_json("scope.json", &p), NOW);
    let e = r.unwrap_err();
    assert_eq!(e.exit_code(), EXIT_REFUSED);
    assert_eq!(e.code(), Some(ErrorCode::ScopeMismatch));
}

#[test]
fn stale_evidence_shows_card_but_refuses() {
    let f = Files::new();
    let p = evm_package(1_500_000, ApprovalMode::ExactCandidate, None);
    let pkg = f.write_json("package.json", &p);
    let (r, out) = show_at(&f, &pkg, OBSERVED_AT + 61);
    let e = r.unwrap_err();
    assert_eq!(e.exit_code(), EXIT_REFUSED);
    assert_eq!(e.code(), Some(ErrorCode::StaleEvidence));
    assert!(out.contains("warning: STALE EVIDENCE"), "{out}");
    let mut args = approve_args(&f, &pkg, "grant.json");
    args.now = Some(OBSERVED_AT + 61);
    assert_eq!(run_approve(&args, PASSPHRASE, "").0.unwrap_err().code(), Some(ErrorCode::StaleEvidence));
    assert!(!exists(&args.out));
}

// ---------------------------------------------------------------------------
// trust roots
// ---------------------------------------------------------------------------

#[test]
fn init_trust_pins_this_build_and_foreign_builds_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let evm = dir.path().join("evm.json");
    let sol = dir.path().join("sol.json");
    std::fs::write(&evm, serde_json::to_vec(&evm_profile()).unwrap()).unwrap();
    std::fs::write(&sol, serde_json::to_vec(&sol_profile()).unwrap()).unwrap();
    let admin_args: Vec<String> = (1..=3).map(admin).map(|(c, k)| format!("{c}={}", hex::encode(k.verifying_key().to_bytes()))).collect();
    let out_path = dir.path().join("trust.json");
    let mut out = Vec::new();
    let t = init_trust(&InitTrustArgs { out: out_path.clone(), admin_keys: admin_args.clone(), admin_quorum: 2, profiles: vec![evm.clone(), sol.clone()] }, &mut out).unwrap();
    let loaded = TrustRoots::load(&out_path).unwrap();
    assert_eq!(loaded, t);
    assert_eq!(loaded, trust_roots());
    assert_eq!(loaded.accepted_verifier_builds, compiled_verifier_builds());
    assert_eq!(loaded.accepted_verifier_builds[&AdapterId::unchecked("evm")], vec![oic_adapter_evm::verifier_build_hash()]);
    assert_eq!(loaded.accepted_verifier_builds[&AdapterId::unchecked("solana")], vec![oic_adapter_solana::verifier_build_hash()]);
    assert!(String::from_utf8(out).unwrap().contains(&format!("pinned verifier build: evm {}", oic_adapter_evm::verifier_build_hash())));

    // Never overwrites.
    let again = init_trust(&InitTrustArgs { out: out_path.clone(), admin_keys: admin_args.clone(), admin_quorum: 2, profiles: vec![evm.clone()] }, &mut Vec::new());
    assert_eq!(again.unwrap_err().exit_code(), EXIT_IO);
    // Unsatisfiable quorum and malformed keys are usage errors.
    let bad = init_trust(&InitTrustArgs { out: dir.path().join("t2.json"), admin_keys: admin_args.clone(), admin_quorum: 4, profiles: vec![evm.clone()] }, &mut Vec::new());
    assert_eq!(bad.unwrap_err().exit_code(), EXIT_USAGE);
    let bad = init_trust(&InitTrustArgs { out: dir.path().join("t3.json"), admin_keys: vec!["admin-1=zz".into()], admin_quorum: 1, profiles: vec![evm] }, &mut Vec::new());
    assert_eq!(bad.unwrap_err().exit_code(), EXIT_USAGE);

    // A trust file produced by another build of the EVM verifier.
    let mut foreign = trust_roots();
    foreign.accepted_verifier_builds.insert(AdapterId::unchecked("evm"), vec![Hash32([0x99; 32])]);
    let foreign_path = dir.path().join("foreign.json");
    foreign.save(&foreign_path).unwrap();
    let p = evm_package(1_500_000, ApprovalMode::ExactCandidate, None);
    let pkg = dir.path().join("package.json");
    std::fs::write(&pkg, serde_json::to_vec(&p).unwrap()).unwrap();
    let e = show(&ShowArgs { trust: foreign_path, package: pkg, now: Some(NOW) }, &mut Vec::new()).unwrap_err();
    assert_eq!(e.exit_code(), EXIT_REFUSED);
    assert_eq!(e.code(), Some(ErrorCode::UnsupportedCapability));
}

// ---------------------------------------------------------------------------
// keygen and key files
// ---------------------------------------------------------------------------

#[test]
fn keygen_writes_encrypted_0600_key_that_only_the_passphrase_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("approver.key");
    let mut out = Vec::new();
    let k = keygen(&KeygenArgs { out: path.clone(), credential_id: "approver-9".into(), role: "security_approver".into() }, PASSPHRASE, &mut out).unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains(&format!("public_key: {}", k.public_key_hex)), "{out}");
    assert!(out.contains("credential_id: approver-9"), "{out}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let raw = std::fs::read_to_string(&path).unwrap();
    let file: ApproverKeyFile = serde_json::from_str(&raw).unwrap();
    assert_eq!(file.kdf.algorithm, "pbkdf2-hmac-sha256");
    assert!(file.kdf.iterations >= 600_000);
    assert_eq!(file.cipher.algorithm, "chacha20poly1305");
    assert_eq!(file.public_key_hex, k.public_key_hex);
    assert_eq!(file.role, ApprovalRole::SecurityApprover);

    let unlocked = file.open(PASSPHRASE).unwrap();
    assert_eq!(hex::encode(unlocked.verifying_key().to_bytes()), k.public_key_hex);
    assert!(!raw.contains(&hex::encode(unlocked.signing_key.to_bytes())), "seed stored in clear");
    assert_eq!(file.open(b"wrong passphrase!!").err().unwrap().code, ErrorCode::InvalidSignature);
    // Editing the header (e.g. upgrading the role) breaks the AEAD binding.
    let mut edited = file.clone();
    edited.role = ApprovalRole::Administrator;
    assert_eq!(edited.open(PASSPHRASE).err().unwrap().code, ErrorCode::InvalidSignature);
    // Weak KDF parameters are refused before any decryption.
    let mut weak = file.clone();
    weak.kdf.iterations = 1000;
    assert_eq!(weak.open(PASSPHRASE).err().unwrap().code, ErrorCode::InvalidRequest);
    // Short passphrases and unknown roles are refused at keygen.
    let short = keygen(&KeygenArgs { out: dir.path().join("k2"), credential_id: "a".into(), role: "treasury_approver".into() }, b"short", &mut Vec::new());
    assert_eq!(short.unwrap_err().exit_code(), EXIT_USAGE);
    let role = keygen(&KeygenArgs { out: dir.path().join("k3"), credential_id: "a".into(), role: "god".into() }, PASSPHRASE, &mut Vec::new());
    assert_eq!(role.unwrap_err().exit_code(), EXIT_USAGE);
    assert!(!dir.path().join("k2").exists() && !dir.path().join("k3").exists());
}

#[test]
fn wrong_passphrase_opens_nothing_and_writes_no_grant() {
    let f = Files::new();
    let p = evm_package(1_500_000, ApprovalMode::ExactCandidate, None);
    let pkg = f.write_json("package.json", &p);
    let args = approve_args(&f, &pkg, "grant.json");
    let (r, out) = run_approve(&args, b"not the passphrase", "");
    let e = r.unwrap_err();
    assert_eq!(e.exit_code(), EXIT_REFUSED);
    assert_eq!(e.code(), Some(ErrorCode::InvalidSignature));
    assert!(out.is_empty());
    assert!(!exists(&args.out));
}

// ---------------------------------------------------------------------------
// approve and verify-grant
// ---------------------------------------------------------------------------

#[test]
fn approve_exact_evm_and_solana_grants_verify_and_bind_the_preview() {
    for p in [evm_package(1_500_000, ApprovalMode::ExactCandidate, None), sol_package(1_000_000, ApprovalMode::ExactCandidate, None)] {
        let f = Files::new();
        let pkg = f.write_json("package.json", &p);
        let args = approve_args(&f, &pkg, "grant.json");
        let (r, out) = run_approve(&args, PASSPHRASE, "");
        let g = r.unwrap();
        assert!(out.contains("OIC INDEPENDENT APPROVAL"), "{out}");
        verify_grant_signature(&g, &roster(), UnixSeconds(NOW)).unwrap();
        assert_eq!(
            g.body.scope,
            GrantScope::ExactCandidate { candidate_id: p.candidate.candidate_id.clone(), candidate_revision: p.candidate.candidate_revision, preview_hash: independent_preview(&p) }
        );
        assert_eq!(g.body.intent_hash, oic_policy_kernel::intent_hash(&p.intent).unwrap());
        assert_eq!(g.body.policy_epoch, Epoch(4));
        assert_eq!(g.body.expires_at, UnixSeconds(NOW + 300));
        let on_disk: ApprovalGrant = serde_json::from_slice(&std::fs::read(&args.out).unwrap()).unwrap();
        assert_eq!(on_disk, g);

        // verify-grant accepts it and prints what it binds.
        let mut out = Vec::new();
        let b = verify_grant(&VerifyGrantArgs { trust: f.trust(), package: pkg.clone(), grant: args.out.clone(), approver: approver_arg(), now: Some(NOW + 10) }, &mut out).unwrap();
        assert_eq!(b.grant, g);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains(&format!("preview_hash {}", independent_preview(&p))), "{out}");

        // The same grant does not bind a different candidate revision.
        let mut other = p.clone();
        other.candidate.candidate_revision = 2;
        let other_pkg = f.write_json("other.json", &other);
        let e = verify_grant(&VerifyGrantArgs { trust: f.trust(), package: other_pkg, grant: args.out.clone(), approver: approver_arg(), now: Some(NOW + 10) }, &mut Vec::new()).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::ScopeMismatch));
        // A wrong enrolled role or an expired grant is refused.
        let wrong_role = approver_arg().replace("treasury_approver", "security_approver");
        let e = verify_grant(&VerifyGrantArgs { trust: f.trust(), package: pkg.clone(), grant: args.out.clone(), approver: wrong_role, now: Some(NOW + 10) }, &mut Vec::new()).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_REFUSED);
        let e = verify_grant(&VerifyGrantArgs { trust: f.trust(), package: pkg.clone(), grant: args.out.clone(), approver: approver_arg(), now: Some(NOW + 301) }, &mut Vec::new()).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::PolicyDenied));
        // Never overwrites an existing grant.
        assert_eq!(run_approve(&args, PASSPHRASE, "").0.unwrap_err().exit_code(), EXIT_IO);
    }
}

#[test]
fn approve_requires_interactive_confirmation_without_yes() {
    let f = Files::new();
    let p = sol_package(1_000_000, ApprovalMode::ExactCandidate, None);
    let pkg = f.write_json("package.json", &p);
    let mut args = approve_args(&f, &pkg, "grant.json");
    args.yes = false;
    for answer in ["", "n\n", "yes please\n"] {
        let (r, out) = run_approve(&args, PASSPHRASE, answer);
        let e = r.unwrap_err();
        assert_eq!(e.exit_code(), EXIT_REFUSED);
        assert_eq!(e.code(), Some(ErrorCode::ApprovalRequired));
        assert!(out.contains("[y/N]"), "{out}");
        assert!(!exists(&args.out));
    }
    let (r, _) = run_approve(&args, PASSPHRASE, "y\n");
    r.unwrap();
    assert!(exists(&args.out));
}

#[test]
fn bounded_mode_grant_binds_the_template_and_verifies() {
    for (p, fillable) in [
        (evm_package(1_500_000, ApprovalMode::BoundedDirectTransfer, None), vec![FillableField::EvmNonce, FillableField::EvmFeeFields, FillableField::EvmGasLimit]),
        (sol_package(1_000_000, ApprovalMode::BoundedDirectTransfer, None), vec![FillableField::SolanaRecentBlockhash]),
    ] {
        let f = Files::new();
        let pkg = f.write_json("package.json", &p);
        let args = approve_args(&f, &pkg, "grant.json");
        let (r, out) = run_approve(&args, PASSPHRASE, "");
        let g = r.unwrap();
        assert!(out.contains("BOUNDED TEMPLATE"), "{out}");
        verify_grant_signature(&g, &roster(), UnixSeconds(NOW)).unwrap();
        let GrantScope::BoundedDirectTransfer { template } = &g.body.scope else { panic!("expected a bounded grant, got {:?}", g.body.scope) };
        let IntentOperation::AssetTransfer { amount_base_units, .. } = &p.intent.operation;
        assert_eq!(template.amount_base_units, *amount_base_units);
        assert_eq!(template.destination_address, p.destination.address);
        assert_eq!(template.destination_id, p.destination.destination_id);
        assert_eq!(template.destination_version, p.destination.version);
        assert_eq!(template.chain_wallet_id, p.intent.chain_wallet_id);
        assert_eq!(template.asset_id, p.asset.asset_id);
        assert_eq!(template.max_native_fee_base_units, p.intent.constraints.max_network_fee_base_units);
        assert_eq!(template.maximum_successful_payments, 1);
        assert_eq!(template.fillable, fillable);
        verify_grant(&VerifyGrantArgs { trust: f.trust(), package: pkg, grant: args.out.clone(), approver: approver_arg(), now: Some(NOW) }, &mut Vec::new()).unwrap();
    }
}

// ---------------------------------------------------------------------------
// inspect-envelope
// ---------------------------------------------------------------------------

fn inspect(f: &Files, pkg: &Path, env: &AuthorizationEnvelope, name: &str) -> (Result<EnvelopeReport, ClientError>, String) {
    let env_path = f.write_json(name, env);
    let mut out = Vec::new();
    let r = inspect_envelope(&InspectEnvelopeArgs { trust: f.trust(), package: pkg.to_path_buf(), envelope: env_path, now: Some(NOW) }, &mut out);
    (r, String::from_utf8(out).unwrap())
}

#[test]
fn inspect_envelope_matches_and_names_altered_fields() {
    for mode in [ApprovalMode::ExactCandidate, ApprovalMode::BoundedDirectTransfer] {
        for p in [evm_package(1_500_000, mode, None), sol_package(1_000_000, mode, None)] {
            let f = Files::new();
            let pkg = f.write_json("package.json", &p);
            let args = approve_args(&f, &pkg, "grant.json");
            let g = run_approve(&args, PASSPHRASE, "").0.unwrap();
            let env = envelope_for(&p, vec![g]);

            let (r, out) = inspect(&f, &pkg, &env, "envelope.json");
            let report = r.unwrap_or_else(|e| panic!("{e}\n{out}"));
            assert!(report.mismatches().is_empty());
            assert_eq!(report.envelope_body_hash, oic_signer::envelope_body_hash(&env.body).unwrap());
            for field in ["intent_hash", "candidate_id", "candidate_revision", "policy_hash", "destination_hash", "decoded_operation_hash", "evidence_bundle_hash", "chain_profile_hash", "approval_grants[0].scope", "authorization_state_receipt.envelope_body_hash"] {
                assert!(out.contains(&format!("MATCH     {field}\n")), "{field} missing in\n{out}");
            }
            assert!(out.contains("RESULT: envelope matches"), "{out}");

            for (field, altered) in [("destination_hash", Hash32([0x0d; 32])), ("decoded_operation_hash", Hash32([0x0e; 32]))] {
                let mut bad = env.clone();
                match field {
                    "destination_hash" => bad.body.destination_hash = altered,
                    _ => bad.body.decoded_operation_hash = altered,
                }
                let (r, out) = inspect(&f, &pkg, &bad, &format!("bad-{field}.json"));
                let e = r.unwrap_err();
                assert_eq!(e.exit_code(), EXIT_REFUSED);
                assert!(e.to_string().contains(field), "{e}");
                assert!(out.contains(&format!("MISMATCH  {field}: envelope={altered}")), "{out}");
                // The altered body no longer matches the authority receipt either.
                assert!(out.contains("MISMATCH  authorization_state_receipt.envelope_body_hash"), "{out}");
            }
        }
    }
}

#[test]
fn inspect_envelope_flags_grants_for_another_candidate_and_mismatched_destination() {
    let f = Files::new();
    let p = evm_package(1_500_000, ApprovalMode::ExactCandidate, None);
    let pkg = f.write_json("package.json", &p);
    let g = run_approve(&approve_args(&f, &pkg, "grant.json"), PASSPHRASE, "").0.unwrap();
    let mut env = envelope_for(&p, vec![g.clone()]);
    if let GrantScope::ExactCandidate { preview_hash, .. } = &mut env.body.approval_grants[0].body.scope {
        *preview_hash = Hash32([1; 32]);
    }
    let (r, _) = inspect(&f, &pkg, &env, "env-grant.json");
    assert!(r.unwrap_err().to_string().contains("approval_grants[0].scope"));

    // Package whose bytes pay the attacker: exit 4.
    let bad = evm_package(1_500_000, ApprovalMode::ExactCandidate, Some(evm_attacker_address()));
    let bad_pkg = f.write_json("bad-package.json", &bad);
    let env = envelope_for(&p, vec![g]);
    let (r, out) = inspect(&f, &bad_pkg, &env, "env-mismatch.json");
    assert_eq!(r.unwrap_err().exit_code(), EXIT_DESTINATION_MISMATCH);
    assert!(out.contains("MISMATCH  decoded_recipient_matches_registry"), "{out}");
    assert!(out.contains("MISMATCH  decoded_operation_hash"), "{out}");
}

// ---------------------------------------------------------------------------
// The real binary
// ---------------------------------------------------------------------------

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_oic-approve"))
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn binary_show_exit_codes_and_card() {
    let f = Files::new();
    let p = evm_package(1_500_000, ApprovalMode::ExactCandidate, None);
    let pkg = f.write_json("package.json", &p);
    let o = bin().args(["show", "--trust", s(&f.trust()), "--package", s(&pkg), "--now", &NOW.to_string()]).output().unwrap();
    let stdout = String::from_utf8(o.stdout).unwrap();
    assert_eq!(o.status.code(), Some(0), "{stdout}\n{}", String::from_utf8_lossy(&o.stderr));
    assert!(stdout.contains("| OIC INDEPENDENT APPROVAL - VERIFY EVERY LINE BEFORE SIGNING"), "{stdout}");
    assert!(stdout.contains(&card_row("TO ADDRESS", &oic_adapter_evm::address::eip55(&evm_dest_address()))), "{stdout}");
    assert!(stdout.contains(&card_row("AMOUNT", "1.5 USDC")), "{stdout}");

    let bad = evm_package(1_500_000, ApprovalMode::ExactCandidate, Some(evm_attacker_address()));
    let bad_pkg = f.write_json("bad.json", &bad);
    let o = bin().args(["show", "--trust", s(&f.trust()), "--package", s(&bad_pkg), "--now", &NOW.to_string()]).output().unwrap();
    assert_eq!(o.status.code(), Some(EXIT_DESTINATION_MISMATCH));
    assert!(String::from_utf8(o.stdout).unwrap().contains("NO - DO NOT APPROVE"));
    assert!(String::from_utf8(o.stderr).unwrap().contains("destination mismatch"));

    let mut weak = p.clone();
    weak.policy = policy(&weak.asset.asset_id, &[2]);
    let weak_pkg = f.write_json("weak.json", &weak);
    let o = bin().args(["show", "--trust", s(&f.trust()), "--package", s(&weak_pkg), "--now", &NOW.to_string()]).output().unwrap();
    assert_eq!(o.status.code(), Some(EXIT_REFUSED));

    let o = bin().args(["show", "--trust", s(&f.path("missing.json")), "--package", s(&pkg)]).output().unwrap();
    assert_eq!(o.status.code(), Some(EXIT_IO));
    let o = bin().args(["show", "--trust"]).output().unwrap();
    assert_eq!(o.status.code(), Some(EXIT_USAGE));
}

#[test]
fn binary_keygen_approve_verify_and_inspect_end_to_end() {
    let f = Files::new();
    let p = sol_package(1_000_000, ApprovalMode::ExactCandidate, None);
    let pkg = f.write_json("package.json", &p);
    let key = f.path("me.key");
    let o = bin()
        .args(["keygen", "--out", s(&key), "--credential-id", "approver-cli", "--role", "treasury_approver", "--passphrase-env", "OIC_TEST_PASS"])
        .env("OIC_TEST_PASS", std::str::from_utf8(PASSPHRASE).unwrap())
        .output()
        .unwrap();
    let stdout = String::from_utf8(o.stdout).unwrap();
    assert_eq!(o.status.code(), Some(0), "{stdout}{}", String::from_utf8_lossy(&o.stderr));
    let pubkey = stdout.lines().find_map(|l| l.strip_prefix("public_key: ")).unwrap().to_string();

    let grant = f.path("grant.json");
    let approve_cmd = |pass: &str| {
        bin()
            .args(["approve", "--trust", s(&f.trust()), "--package", s(&pkg), "--key", s(&key), "--passphrase-env", "OIC_TEST_PASS"])
            .args(["--grant-id", "grant-cli", "--ttl-seconds", "600", "--out", s(&grant), "--now", &NOW.to_string(), "--yes"])
            .env("OIC_TEST_PASS", pass)
            .output()
            .unwrap()
    };
    let o = approve_cmd("wrong passphrase value");
    assert_eq!(o.status.code(), Some(EXIT_REFUSED));
    assert!(!grant.exists());
    let o = approve_cmd(std::str::from_utf8(PASSPHRASE).unwrap());
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(grant.exists());

    let o = bin()
        .args(["verify-grant", "--trust", s(&f.trust()), "--package", s(&pkg), "--grant", s(&grant), "--approver", &format!("approver-cli={pubkey}=treasury_approver"), "--now", &NOW.to_string()])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8(o.stdout).unwrap().contains("grant grant-cli verified"));

    let g: ApprovalGrant = serde_json::from_slice(&std::fs::read(&grant).unwrap()).unwrap();
    let env = f.write_json("envelope.json", &envelope_for(&p, vec![g]));
    let o = bin().args(["inspect-envelope", "--trust", s(&f.trust()), "--package", s(&pkg), "--envelope", s(&env), "--now", &NOW.to_string()]).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stdout));

    // Missing passphrase variable is a usage error.
    let o = bin()
        .args(["approve", "--trust", s(&f.trust()), "--package", s(&pkg), "--key", s(&key), "--passphrase-env", "OIC_TEST_UNSET_VAR"])
        .args(["--grant-id", "g2", "--ttl-seconds", "600", "--out", s(&f.path("g2.json")), "--yes"])
        .env_remove("OIC_TEST_UNSET_VAR")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(EXIT_USAGE));
}

#[test]
fn approver_key_fixture_uses_minimum_iterations() {
    // Guards the fixture: tests exercise the production KDF strength.
    let f = Files::new();
    let file = ApproverKeyFile::load(&f.approver_key()).unwrap();
    assert_eq!(file.kdf.iterations, MIN_PBKDF2_ITERATIONS);
}
