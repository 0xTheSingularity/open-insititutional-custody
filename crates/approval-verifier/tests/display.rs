//! Independent approval display and approval (RFC 0001 §4.3, A34; RFC 0002 §8, C15).

mod common;

use common::*;
use oic_adapter_api::*;
use oic_adapter_evm::address::eip55;
use oic_adapter_evm::EvmAdapter;
use oic_adapter_solana::address::to_base58;
use oic_adapter_solana::SolanaAdapter;
use oic_approval_verifier::*;
use oic_domain_types::*;
use oic_policy_kernel::{intent_hash, preview_hash};

const SIM_WARNING: &str = "DEVELOPMENT SIMULATOR EVIDENCE: not valid for production funds";

fn now() -> UnixSeconds {
    UnixSeconds(NOW)
}

fn approve(w: &World, d: &ApprovalDisplay, at: UnixSeconds) -> OicResult<ApprovalGrant> {
    let (id, key) = approver();
    verifier().approve(d, &w.inputs(), (id, ApprovalRole::TreasuryApprover, &key), GrantId::unchecked("grant-1"), at, 300)
}

/// The preview hash recomputed independently of `render`.
fn expected_preview(w: &World, decoded: &DecodedOperation) -> Hash32 {
    preview_hash(&w.candidate.candidate_id, w.candidate.candidate_revision, decoded_operation_hash(decoded).unwrap(), evidence_hash(&w.evidence).unwrap())
}

fn assert_common(w: &World, d: &ApprovalDisplay) {
    assert_eq!(d.operation_kind, "direct_transfer");
    assert_eq!(d.destination_id, DestinationId::unchecked("dest-1"));
    assert_eq!(d.destination_version, 3);
    assert_eq!(d.destination_display_name, "Acme Settlement LLC");
    assert_eq!(d.purpose, OperationPurpose::Settlement);
    assert_eq!(d.intent_id, IntentId::unchecked("intent-1"));
    assert_eq!(d.external_reference, "INV-2026-0042");
    assert_eq!(d.candidate_id, CandidateId::unchecked("cand-1"));
    assert_eq!(d.candidate_revision, 1);
    assert_eq!(d.policy_id, PolicyId::unchecked("pol-1"));
    assert_eq!(d.policy_epoch, Epoch(4));
    assert_eq!(d.intent_hash, intent_hash(&w.intent).unwrap());
    assert_eq!(d.evidence_state, EvidenceStateDisplay { height: 1000, hash: format!("0x{}", "07".repeat(32)), commitment: "finalized".into() });
    assert_eq!(d.evidence_age_seconds, 20);
}

#[test]
fn evm_native_display_and_exact_grant() {
    let w = evm::world(evm::native_asset(), 1_250_000_000_000_000_000, ApprovalMode::ExactCandidate, None);
    let d = verifier().render(&w.inputs(), now()).unwrap();
    let decoded = EvmAdapter.decode_candidate(&w.candidate, &w.vctx()).unwrap();

    assert_common(&w, &d);
    assert_eq!(d.network_id, NetworkId::unchecked("evm-11155111"));
    assert_eq!(d.chain_profile_id, ChainProfileId::unchecked("evm-sepolia-v1"));
    assert_eq!(d.wallet_address_display, eip55(&evm::sender()));
    assert_eq!(d.asset_identity, "native");
    assert_eq!(d.asset_symbol_from_registry, "ETH");
    assert_eq!(d.decimals, 18);
    assert_eq!(d.amount_base_units, "1250000000000000000");
    assert_eq!(d.amount_display, "1.25");
    assert_eq!(d.recipient_address_display, eip55(&evm::dest_address()));
    assert!(d.destination_matches_registry);
    assert_eq!(d.max_native_fee_base_units, decoded.max_native_fee().to_string());
    assert_eq!(d.preview_hash, expected_preview(&w, &decoded));
    assert_eq!(d.approval_mode, ApprovalMode::ExactCandidate);
    assert_eq!(d.template, None);
    assert_eq!(d.warnings, vec![SIM_WARNING.to_string()]);

    let g = approve(&w, &d, now()).unwrap();
    verify_grant(&g, &roster(), now()).unwrap();
    assert_eq!(
        g.body.scope,
        GrantScope::ExactCandidate { candidate_id: CandidateId::unchecked("cand-1"), candidate_revision: 1, preview_hash: expected_preview(&w, &decoded) }
    );
    assert_eq!(g.body.intent_hash, intent_hash(&w.intent).unwrap());
    assert_eq!(g.body.intent_id, w.intent.intent_id);
    assert_eq!(g.body.vault_id, w.intent.vault_id);
    assert_eq!(g.body.policy_epoch, Epoch(4));
    assert_eq!(g.body.approver_role, ApprovalRole::TreasuryApprover);
    assert_eq!(g.body.issued_at, now());
    assert_eq!(g.body.expires_at, UnixSeconds(NOW + 300));
}

#[test]
fn evm_erc20_display() {
    let w = evm::world(evm::erc20_asset(), 1_234_500, ApprovalMode::ExactCandidate, None);
    let d = verifier().render(&w.inputs(), now()).unwrap();
    let decoded = EvmAdapter.decode_candidate(&w.candidate, &w.vctx()).unwrap();
    assert_common(&w, &d);
    assert_eq!(d.asset_identity, format!("erc20 contract={}", eip55(&evm::token_contract())));
    assert!(d.asset_identity.starts_with("erc20 contract=0x"));
    assert_eq!(d.asset_symbol_from_registry, "USDC");
    assert_eq!(d.decimals, 6);
    assert_eq!(d.amount_base_units, "1234500");
    assert_eq!(d.amount_display, "1.2345");
    // The token recipient comes from calldata, not the transaction `to` (the contract).
    assert_eq!(d.recipient_address_display, eip55(&evm::dest_address()));
    assert!(d.destination_matches_registry);
    assert_eq!(d.preview_hash, expected_preview(&w, &decoded));
    let g = approve(&w, &d, now()).unwrap();
    verify_grant(&g, &roster(), now()).unwrap();
}

#[test]
fn solana_spl_display() {
    let w = solana::world(solana::spl_asset(), 1_000_000, ApprovalMode::ExactCandidate, None);
    let d = verifier().render(&w.inputs(), now()).unwrap();
    let decoded = SolanaAdapter.decode_candidate(&w.candidate, &w.vctx()).unwrap();
    assert_common(&w, &d);
    assert_eq!(d.network_id, NetworkId::unchecked("solana-devnet"));
    assert_eq!(d.wallet_address_display, to_base58(&solana::wallet_addr()));
    assert_eq!(d.asset_identity, "spl mint=DyRkUpQxYG2VnP2SkMdQs5BTsVPeKCpSHLxzByc2Sxvj program=TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    assert_eq!(d.asset_symbol_from_registry, "USDC");
    assert_eq!(d.decimals, 6);
    assert_eq!(d.amount_base_units, "1000000");
    assert_eq!(d.amount_display, "1");
    assert_eq!(d.recipient_address_display, to_base58(&solana::dest_owner()));
    assert!(d.destination_matches_registry);
    assert_eq!(d.max_native_fee_base_units, decoded.max_native_fee().to_string());
    assert_eq!(d.preview_hash, expected_preview(&w, &decoded));
    assert_eq!(d.warnings, vec![SIM_WARNING.to_string()]);
    let g = approve(&w, &d, now()).unwrap();
    verify_grant(&g, &roster(), now()).unwrap();
    assert!(matches!(g.body.scope, GrantScope::ExactCandidate { preview_hash, .. } if preview_hash == d.preview_hash));
}

#[test]
fn solana_native_display_nine_decimals() {
    let w = solana::world(solana::native_asset(), 1_000_000, ApprovalMode::ExactCandidate, None);
    let d = verifier().render(&w.inputs(), now()).unwrap();
    assert_eq!(d.asset_identity, "native");
    assert_eq!(d.asset_symbol_from_registry, "SOL");
    assert_eq!(d.decimals, 9);
    assert_eq!(d.amount_display, "0.001");
    assert_eq!(d.recipient_address_display, to_base58(&solana::dest_owner()));
    approve(&w, &d, now()).unwrap();
}

#[test]
fn bounded_mode_grants_bind_a_template() {
    let w = evm::world(evm::erc20_asset(), 2_000_000, ApprovalMode::BoundedDirectTransfer, None);
    let d = verifier().render(&w.inputs(), now()).unwrap();
    let t = d.template.clone().expect("bounded mode shows the template");
    assert_eq!(t.fillable, vec![FillableField::EvmNonce, FillableField::EvmFeeFields, FillableField::EvmGasLimit]);
    assert_eq!(t.amount_base_units, "2000000");
    assert_eq!(t.destination_address_display, eip55(&evm::dest_address()));
    assert_eq!(t.max_native_fee_base_units, 10u128.pow(16).to_string());
    let g = approve(&w, &d, now()).unwrap();
    verify_grant(&g, &roster(), now()).unwrap();
    let GrantScope::BoundedDirectTransfer { template } = &g.body.scope else { panic!("expected bounded scope") };
    assert_eq!(template.amount_base_units, Amount(2_000_000));
    assert_eq!(template.destination_address, Bytes(evm::dest_address().to_vec()));
    assert_eq!(template.destination_id, DestinationId::unchecked("dest-1"));
    assert_eq!(template.destination_version, 3);
    assert_eq!(template.asset_id, AssetId::unchecked("sepolia-usdc"));
    assert_eq!(template.chain_wallet_id, ChainWalletId::unchecked("wallet-1"));
    assert_eq!(template.maximum_successful_payments, 1);
    // The template genuinely admits the candidate under the pinned adapter.
    EvmAdapter.verify_candidate(&w.candidate, &AuthorizationTarget::Template(template), &w.vctx()).unwrap();

    let w = solana::world(solana::spl_asset(), 1_000_000, ApprovalMode::BoundedDirectTransfer, None);
    let d = verifier().render(&w.inputs(), now()).unwrap();
    assert_eq!(d.template.as_ref().unwrap().fillable, vec![FillableField::SolanaRecentBlockhash]);
    let g = approve(&w, &d, now()).unwrap();
    let GrantScope::BoundedDirectTransfer { template } = &g.body.scope else { panic!("expected bounded scope") };
    assert_eq!(template.destination_address, Bytes(solana::dest_owner().to_vec()));
    assert_eq!(fillable_fields_for(&AdapterId::unchecked("bitcoin")).unwrap_err().code, ErrorCode::UnsupportedCapability);
}

#[test]
fn a34_c15_decoded_recipient_differs_from_registry() {
    // EVM: the compromised console built the transfer to an attacker address
    // but presents the registry destination record.
    let w = evm::world(evm::erc20_asset(), 1_000_000, ApprovalMode::ExactCandidate, Some(evm::attacker_address()));
    let d = verifier().render(&w.inputs(), now()).unwrap();
    assert!(!d.destination_matches_registry);
    assert_eq!(d.recipient_address_display, eip55(&evm::attacker_address()));
    assert_eq!(d.destination_display_name, "Acme Settlement LLC");
    assert_eq!(
        d.warnings[0],
        format!("DESTINATION MISMATCH: transaction pays {}, registry destination dest-1 v3 is {}", eip55(&evm::attacker_address()), eip55(&evm::dest_address()))
    );
    assert!(d.to_string().contains("NO - DO NOT APPROVE"));
    assert_eq!(approve(&w, &d, now()).unwrap_err().code, ErrorCode::ScopeMismatch);
    // A UI that flips the flag and drops the warning is caught by re-rendering.
    let mut lie = d.clone();
    lie.destination_matches_registry = true;
    lie.recipient_address_display = eip55(&evm::dest_address());
    lie.warnings.remove(0);
    assert_eq!(approve(&w, &lie, now()).unwrap_err().code, ErrorCode::ScopeMismatch);

    // Solana SPL: same attack.
    let w = solana::world(solana::spl_asset(), 1_000_000, ApprovalMode::ExactCandidate, Some(solana::attacker_owner()));
    let d = verifier().render(&w.inputs(), now()).unwrap();
    assert!(!d.destination_matches_registry);
    assert_eq!(d.recipient_address_display, to_base58(&solana::attacker_owner()));
    assert!(d.warnings[0].starts_with("DESTINATION MISMATCH"));
    assert_eq!(approve(&w, &d, now()).unwrap_err().code, ErrorCode::ScopeMismatch);
}

#[test]
fn edited_or_swapped_display_is_refused() {
    let w = evm::world(evm::native_asset(), 1_250_000_000_000_000_000, ApprovalMode::ExactCandidate, None);
    let d = verifier().render(&w.inputs(), now()).unwrap();

    let mut edited = d.clone();
    edited.recipient_address_display = eip55(&evm::attacker_address());
    assert_eq!(approve(&w, &edited, now()).unwrap_err().code, ErrorCode::ScopeMismatch);
    let mut edited = d.clone();
    edited.amount_display = "0.125".into();
    assert_eq!(approve(&w, &edited, now()).unwrap_err().code, ErrorCode::ScopeMismatch);
    let mut edited = d.clone();
    edited.warnings.clear();
    assert_eq!(approve(&w, &edited, now()).unwrap_err().code, ErrorCode::ScopeMismatch);
    let mut edited = d.clone();
    edited.preview_hash = Hash32([3; 32]);
    assert_eq!(approve(&w, &edited, now()).unwrap_err().code, ErrorCode::ScopeMismatch);

    // The object swapped between show and sign: a different candidate revision.
    let mut swapped = w.clone();
    let mut ctx = w.build_ctx(&w.destination);
    ctx.candidate_revision = 2;
    swapped.candidate = EvmAdapter.build_candidate(&ctx).unwrap();
    assert_eq!(approve(&swapped, &d, now()).unwrap_err().code, ErrorCode::ScopeMismatch);

    // The unedited display still signs.
    approve(&w, &d, now()).unwrap();
}

#[test]
fn candidate_amount_differing_from_intent_is_unverifiable() {
    let mut w = evm::world(evm::erc20_asset(), 1_000_000, ApprovalMode::ExactCandidate, None);
    // The console presents an intent for a smaller amount than the bytes move.
    let IntentOperation::AssetTransfer { amount_base_units, .. } = &mut w.intent.operation;
    *amount_base_units = Amount(1_000);
    assert_eq!(verifier().render(&w.inputs(), now()).unwrap_err().code, ErrorCode::UnverifiableTransaction);
}

#[test]
fn tampered_evidence_is_unverifiable() {
    let mut w = evm::world(evm::native_asset(), 1_000, ApprovalMode::ExactCandidate, None);
    w.candidate.evidence_bundle_hash = Hash32([1; 32]);
    assert_eq!(verifier().render(&w.inputs(), now()).unwrap_err().code, ErrorCode::UnverifiableTransaction);

    let mut w = solana::world(solana::spl_asset(), 1_000_000, ApprovalMode::ExactCandidate, None);
    w.evidence.state.height += 1;
    assert_eq!(verifier().render(&w.inputs(), now()).unwrap_err().code, ErrorCode::UnverifiableTransaction);
}

#[test]
fn policy_without_quorum_is_rejected() {
    let mut w = evm::world(evm::native_asset(), 1_000, ApprovalMode::ExactCandidate, None);
    w.policy = policy(&[1]);
    assert_eq!(verifier().render(&w.inputs(), now()).unwrap_err().code, ErrorCode::InvalidSignature);
    // Duplicate signatures from one administrator do not make a quorum.
    w.policy = policy(&[1, 1]);
    assert_eq!(verifier().render(&w.inputs(), now()).unwrap_err().code, ErrorCode::InvalidSignature);
    // Edited after signing.
    w.policy = policy(&[1, 2]);
    w.policy.max_evidence_age_seconds = 86_400;
    assert_eq!(verifier().render(&w.inputs(), now()).unwrap_err().code, ErrorCode::InvalidSignature);
    // And approve refuses too, even for a display rendered from the good policy.
    let good = evm::world(evm::native_asset(), 1_000, ApprovalMode::ExactCandidate, None);
    let d = verifier().render(&good.inputs(), now()).unwrap();
    assert_eq!(approve(&w, &d, now()).unwrap_err().code, ErrorCode::InvalidSignature);
}

#[test]
fn inconsistent_objects_are_scope_mismatches() {
    let base = evm::world(evm::native_asset(), 1_000, ApprovalMode::ExactCandidate, None);
    let v = verifier();

    let mut w = base.clone();
    w.vault.policy_id = PolicyId::unchecked("pol-other");
    assert_eq!(v.render(&w.inputs(), now()).unwrap_err().code, ErrorCode::ScopeMismatch);

    let mut w = base.clone();
    w.wallet.address = Bytes(vec![0x99; 20]);
    assert_eq!(v.render(&w.inputs(), now()).unwrap_err().code, ErrorCode::ScopeMismatch);

    let mut w = base.clone();
    w.destination.version = 4;
    assert_eq!(v.render(&w.inputs(), now()).unwrap_err().code, ErrorCode::ScopeMismatch);

    let mut w = base.clone();
    w.candidate.intent_id = IntentId::unchecked("intent-other");
    assert_eq!(v.render(&w.inputs(), now()).unwrap_err().code, ErrorCode::ScopeMismatch);

    let mut only_solana = verifier();
    only_solana.chain_profiles.retain(|p| p.adapter_id.as_str() == "solana");
    assert_eq!(only_solana.render(&base.inputs(), now()).unwrap_err().code, ErrorCode::ScopeMismatch);

    let mut no_adapter = verifier();
    no_adapter.adapters.remove(&AdapterId::unchecked("evm"));
    assert_eq!(no_adapter.render(&base.inputs(), now()).unwrap_err().code, ErrorCode::UnsupportedCapability);
}

#[test]
fn warnings_for_stale_evidence_and_nonstandard_assets() {
    let w = evm::world(evm::native_asset(), 1_000, ApprovalMode::ExactCandidate, None);
    let d = verifier().render(&w.inputs(), now()).unwrap();
    // Time passes but evidence is still fresh: the same display still signs.
    approve(&w, &d, UnixSeconds(NOW + 30)).unwrap();
    // Evidence became stale after the approver looked: a new warning appears, so signing is refused.
    assert_eq!(approve(&w, &d, UnixSeconds(OBSERVED_AT + 61)).unwrap_err().code, ErrorCode::ScopeMismatch);
    let stale = verifier().render(&w.inputs(), UnixSeconds(OBSERVED_AT + 61)).unwrap();
    assert_eq!(stale.evidence_age_seconds, 61);
    assert!(stale.warnings.contains(&"STALE EVIDENCE: 61s old, maximum 60s".to_string()));
    // Clock behind the evidence.
    let early = verifier().render(&w.inputs(), UnixSeconds(OBSERVED_AT - 5)).unwrap();
    assert_eq!(early.evidence_age_seconds, 0);
    assert!(early.warnings.iter().any(|x| x.starts_with("EVIDENCE TIMESTAMP IN THE FUTURE by 5s")));

    // Nonstandard assets are watch-only: the pinned adapters refuse to verify them at all.
    let mut w = evm::world(evm::erc20_asset(), 1_000, ApprovalMode::ExactCandidate, None);
    w.asset.behavior = AssetBehaviorProfile::Nonstandard;
    assert_eq!(verifier().render(&w.inputs(), now()).unwrap_err().code, ErrorCode::UnsupportedCapability);
    let mut w = solana::world(solana::spl_asset(), 1_000_000, ApprovalMode::ExactCandidate, None);
    w.asset.behavior = AssetBehaviorProfile::Nonstandard;
    assert_eq!(verifier().render(&w.inputs(), now()).unwrap_err().code, ErrorCode::UnsupportedCapability);
}

#[test]
fn single_provider_evidence_and_inactive_wallet_warn() {
    let mut w = evm::world(evm::native_asset(), 1_000, ApprovalMode::ExactCandidate, None);
    w.profile.accepted_trust_levels = vec![EvidenceTrustLevel::SingleProvider];
    w.evidence.trust_level = EvidenceTrustLevel::SingleProvider;
    w.wallet.active = false;
    let ctx = w.build_ctx(&w.destination);
    w.candidate = EvmAdapter.build_candidate(&ctx).unwrap();
    let mut v = verifier();
    v.chain_profiles = vec![w.profile.clone()];
    let d = v.render(&w.inputs(), now()).unwrap();
    assert_eq!(
        d.warnings,
        vec![
            "SINGLE-PROVIDER EVIDENCE: chain state was not cross-checked".to_string(),
            "WALLET NOT ACTIVE: ceremony/recovery metadata not committed".to_string(),
        ]
    );
}

#[test]
fn ttl_must_be_positive() {
    let w = evm::world(evm::native_asset(), 1_000, ApprovalMode::ExactCandidate, None);
    let d = verifier().render(&w.inputs(), now()).unwrap();
    let (id, key) = approver();
    let err = verifier().approve(&d, &w.inputs(), (id, ApprovalRole::TreasuryApprover, &key), GrantId::unchecked("g"), now(), 0).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidRequest);
}

#[test]
fn card_rendering_is_fixed_width_ascii_and_sanitized() {
    let mut w = evm::world(evm::erc20_asset(), 1_234_500, ApprovalMode::BoundedDirectTransfer, None);
    w.intent.external_reference = "INV-1\u{1b}[2J\u{202e}gnp.exe\\".into();
    let mut ctx = w.build_ctx(&w.destination);
    ctx.intent = w.intent.clone();
    w.candidate = EvmAdapter.build_candidate(&ctx).unwrap();
    let d = verifier().render(&w.inputs(), now()).unwrap();
    let card = d.to_string();
    for line in card.lines() {
        assert_eq!(line.len(), CARD_WIDTH, "{line:?}");
        assert!(line.bytes().all(|b| (0x20..=0x7e).contains(&b)), "{line:?}");
    }
    let row = |label: &str, value: &str| format!("| {label:<22}{value:<54} |");
    assert!(card.lines().any(|l| l == row("AMOUNT", "1.2345 USDC")), "{card}");
    assert!(card.lines().any(|l| l == row("TO ADDRESS", &eip55(&evm::dest_address()))));
    assert!(card.lines().any(|l| l == row("REGISTRY MATCH", "YES")));
    assert!(card.lines().any(|l| l == row("EXTERNAL REFERENCE", "INV-1\\u{001b}[2J\\u{202e}gnp.exe\\\\")));
    assert!(card.lines().any(|l| l == row("TEMPLATE FILLABLE", "evm_nonce, evm_fee_fields, evm_gas_limit")));
    assert!(card.lines().any(|l| l == format!("| {:<76} |", format!("! {SIM_WARNING}"))));
    // 64-hex hashes wrap onto a continuation line rather than being truncated.
    let hex = d.preview_hash.to_hex();
    assert!(card.lines().any(|l| l == row("PREVIEW HASH", &hex[..54])));
    assert!(card.lines().any(|l| l == row("", &hex[54..])));

    // Serde round trip preserves the display exactly.
    let json = serde_json::to_string(&d).unwrap();
    let back: ApprovalDisplay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}
