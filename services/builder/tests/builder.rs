//! Builder end to end: simulator evidence -> build -> evaluate -> envelope
//! body accepted by a real signer.

mod common;

use common::*;
use oic_adapter_api::*;
use oic_adapter_solana::address::{associated_token_address, to_base58, TOKEN_PROGRAM_ID};
use oic_adapter_solana::message::{AddressTableLookup, CompiledInstruction, Message, MessageHeader, MessageVersion};
use oic_authorization_state::family_id_for;
use oic_domain_types::*;
use oic_policy_kernel::{Decision, ReasonCode};
use oic_service_builder::*;
use oic_signer::envelope_body_hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn code<T: std::fmt::Debug>(r: OicResult<T>) -> ErrorCode {
    r.expect_err("expected an error").code
}

fn signed_policy(world: &World, asset: &Asset, required: u8, limit: u128) -> PolicyBundle {
    world.sign_policy(policy(1, vec![rule(&asset.asset_id, required, limit)]))
}

#[test]
fn evm_erc20_build_and_evaluate_allows_only_with_the_required_grant() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10u128.pow(16), ApprovalMode::ExactCandidate);
    world.register(&pol, &intent);
    let inputs = c.inputs(&intent, &pol, "cand-1");
    // The source requested exactly the EVM items, including the sender nonce and token code.
    let sender: [u8; 20] = c.wallet.address.as_slice().try_into().unwrap();
    for k in [
        oic_adapter_evm::evidence::nonce_key(&sender),
        oic_adapter_evm::evidence::code_key(&evm.token),
        oic_adapter_evm::evidence::KEY_CHAIN_ID.to_string(),
        oic_adapter_evm::evidence::KEY_BASE_FEE.to_string(),
        oic_adapter_evm::evidence::KEY_PRIORITY_FEE.to_string(),
        oic_adapter_evm::evidence::KEY_GAS_LIMIT.to_string(),
    ] {
        assert!(inputs.evidence.items.contains_key(&k), "missing {k}");
    }

    let built = build(c.adapter.as_ref(), &inputs).unwrap();
    assert_eq!(built.template, None);
    assert_eq!(built.decoded, built.verified.decoded);
    assert_eq!(built.decoded.amount(), Amount(1_000_000));
    assert_eq!(built.package.candidate, built.candidate);
    assert_eq!(built.package.schema_version, ApprovalPackage::SCHEMA_VERSION);
    assert_eq!(built.candidate.operation_family_id, family_id_for(&intent.intent_id).unwrap());
    let exposure = world.exposure(&built, &pol);
    let approvers = world.approver_credentials();

    let grant = world.exact_grant(&built, 0);
    let ok = evaluate(&built, &pol, Epoch(1), std::slice::from_ref(&grant), &approvers, &exposure, now()).unwrap();
    assert_eq!(ok.decision, Decision::Allow { rule_id: "r-1".into() });
    assert_eq!(ok.approvers, vec![CredentialId::unchecked("approver-1")]);
    assert_eq!(ok.matched_rule, Some(pol.rules[0].clone()));

    let none = evaluate(&built, &pol, Epoch(1), &[], &approvers, &exposure, now()).unwrap();
    assert!(matches!(&none.decision, Decision::RequireApprovals { required: 1, satisfied: 0, .. }), "{:?}", none.decision);
    assert!(none.approvers.is_empty());
    assert_eq!(
        required_approvals(&pol, &built),
        Some(("r-1".to_string(), 1, vec![ApprovalRole::TreasuryApprover, ApprovalRole::SecurityApprover]))
    );

    // A grant over another preview does not count; a forged signature fails the set.
    let mut other = built.clone();
    other.preview_hash = Hash32([9; 32]);
    let stale = world.exact_grant(&other, 0);
    let d = evaluate(&built, &pol, Epoch(1), &[stale], &approvers, &exposure, now()).unwrap().decision;
    assert!(d.reasons().contains(&ReasonCode::GrantScopeMismatch), "{d:?}");
    let mut forged = grant.clone();
    forged.signature.bytes.0[0] ^= 1;
    assert_eq!(code(evaluate(&built, &pol, Epoch(1), &[forged], &approvers, &exposure, now())), ErrorCode::InvalidSignature);
    // Evaluating under a policy other than the one the candidate was built with is refused.
    let other_policy = signed_policy(&world, &c.asset, 0, 10_000_000);
    assert_eq!(code(evaluate(&built, &other_policy, Epoch(1), &[], &approvers, &exposure, now())), ErrorCode::StalePolicy);
    // A stale epoch is a kernel denial.
    let d = evaluate(&built, &pol, Epoch(2), std::slice::from_ref(&grant), &approvers, &exposure, now()).unwrap().decision;
    assert!(d.reasons().contains(&ReasonCode::PolicyEpochMismatch), "{d:?}");
}

#[test]
fn solana_native_build_and_evaluate_with_exposure_and_denials() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 2, 1_500_000);
    let intent = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    world.register(&pol, &intent);
    let inputs = c.inputs(&intent, &pol, "cand-1");
    use oic_adapter_solana::evidence::*;
    for k in [KEY_GENESIS_HASH, KEY_RECENT_BLOCKHASH, KEY_BLOCKHASH_LAST_VALID_HEIGHT, KEY_LAMPORTS_PER_SIGNATURE, KEY_RENT_TOKEN_ACCOUNT] {
        assert!(inputs.evidence.items.contains_key(k), "missing {k}");
    }
    assert!(!inputs.evidence.items.keys().any(|k| k.starts_with("token_account:")), "no token accounts for a native transfer");
    let built = build(c.adapter.as_ref(), &inputs).unwrap();
    assert_eq!(built.decoded.recipient().as_slice(), &sol_dest_owner()[..]);
    let approvers = world.approver_credentials();
    let exposure = world.exposure(&built, &pol);
    let grants = world.grants_for(&built, 2);

    let ok = evaluate(&built, &pol, Epoch(1), &grants, &approvers, &exposure, now()).unwrap();
    assert!(ok.decision.is_allow());
    assert_eq!(ok.approvers, vec![CredentialId::unchecked("approver-1"), CredentialId::unchecked("approver-2")]);
    let one = evaluate(&built, &pol, Epoch(1), &grants[..1], &approvers, &exposure, now()).unwrap();
    assert!(matches!(one.decision, Decision::RequireApprovals { required: 2, satisfied: 1, .. }));

    // Prior outstanding exposure pushes the operation over the rolling limit.
    let mut busy = exposure.clone();
    busy.windows[0].outstanding = Amount(600_000);
    let d = evaluate(&built, &pol, Epoch(1), &grants, &approvers, &busy, now()).unwrap();
    assert!(matches!(&d.decision, Decision::Deny { reasons } if reasons.contains(&ReasonCode::RollingLimitExceeded { rule_id: "r-1".into(), window_seconds: DAY })));
    assert_eq!(d.matched_rule, None);
    // A missing exposure window fails closed.
    let d = evaluate(&built, &pol, Epoch(1), &grants, &approvers, &Default::default(), now()).unwrap();
    assert!(!d.decision.is_allow());

    // A denied destination is a hard denial the kernel reports, whatever the grants.
    let mut denied = policy(1, vec![rule(&c.asset.asset_id, 2, 1_500_000)]);
    denied.denied_destinations = vec![c.destination.destination_id.clone()];
    let denied = world.sign_policy(denied);
    let mut inputs2 = inputs.clone();
    inputs2.policy = denied.clone();
    let built2 = build(c.adapter.as_ref(), &inputs2).unwrap();
    let d = evaluate(&built2, &denied, Epoch(1), &world.grants_for(&built2, 2), &approvers, &exposure, now()).unwrap();
    assert!(matches!(&d.decision, Decision::Deny { reasons } if reasons.contains(&ReasonCode::DeniedDestination)));
    // A policy whose rules match nothing reports no approval requirement.
    let unmatched = world.sign_policy(policy(1, vec![rule(&AssetId::unchecked("other"), 2, 1)]));
    assert_eq!(required_approvals(&unmatched, &built), None);
    let automated = world.sign_policy(policy(1, vec![rule(&c.asset.asset_id, 0, 1)]));
    assert_eq!(required_approvals(&automated, &built), None);
}

#[test]
fn solana_spl_build_requests_both_token_accounts_and_creates_destination_ata() {
    let world = World::new();
    let sol = sol_chain(&world, true);
    let c = &sol.chain;
    let mint = sol.mint.unwrap();
    let wallet: [u8; 32] = c.wallet.address.as_slice().try_into().unwrap();
    let src = associated_token_address(&wallet, &mint, &TOKEN_PROGRAM_ID).unwrap();
    let dest_ata = associated_token_address(&sol_dest_owner(), &mint, &TOKEN_PROGRAM_ID).unwrap();
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    world.register(&pol, &intent);
    let inputs = c.inputs(&intent, &pol, "cand-1");
    assert!(inputs.evidence.items.contains_key(&format!("token_account:{}", to_base58(&src))));
    // The destination ATA does not exist yet: the source asked for it and the chain had nothing.
    assert!(!inputs.evidence.items.contains_key(&format!("token_account:{}", to_base58(&dest_ata))));
    let built = build(c.adapter.as_ref(), &inputs).unwrap();
    let msg = Message::decode(built.candidate.native_unsigned_bytes.as_slice()).unwrap();
    assert!(msg.account_keys.contains(&oic_adapter_solana::address::ATA_PROGRAM_ID), "destination ATA is created");
    assert!(matches!(built.decoded.asset(), AssetKind::SplToken { .. }));
    let ev = evaluate(&built, &pol, Epoch(1), &world.grants_for(&built, 1), &world.approver_credentials(), &world.exposure(&built, &pol), now()).unwrap();
    assert!(ev.decision.is_allow(), "{:?}", ev.decision);
    let ev = evaluate(&built, &pol, Epoch(1), &[], &world.approver_credentials(), &world.exposure(&built, &pol), now()).unwrap();
    assert!(!ev.decision.is_allow());
}

#[test]
fn spl_wallet_without_source_account_fails_with_the_adapters_own_error() {
    let world = World::new();
    let sol = sol_chain(&world, true);
    let c = &sol.chain;
    // Another mint the wallet holds no token account for.
    let mint2 = sol.sim.create_mint(6, b"other-authority").unwrap();
    sol.sim.advance_slot().unwrap();
    let mut asset = c.asset.clone();
    asset.asset = AssetKind::SplToken { mint: Bytes(mint2.to_vec()), token_program: Bytes(TOKEN_PROGRAM_ID.to_vec()) };
    let req = EvidenceRequest { asset: asset.clone(), ..c.request(EvidenceCommitment::Latest) };
    let evidence = c.source.evidence(&req).unwrap();
    assert!(!evidence.items.keys().any(|k| k.starts_with("token_account:")));
    let pol = signed_policy(&world, &asset, 1, 10_000_000);
    let intent = intent_for("intent-1", &c.wallet, &asset, &c.destination, 1_000, 10_000_000, ApprovalMode::ExactCandidate);
    let mut inputs = c.inputs(&intent, &pol, "cand-1");
    inputs.asset = asset;
    inputs.evidence = evidence;
    let direct = c
        .adapter
        .build_candidate(&BuildContext {
            intent: inputs.intent.clone(),
            wallet: inputs.wallet.clone(),
            key: inputs.key.clone(),
            asset: inputs.asset.clone(),
            destination: inputs.destination.clone(),
            profile: inputs.profile.clone(),
            evidence: inputs.evidence.clone(),
            candidate_id: inputs.candidate_id.clone(),
            candidate_revision: 1,
            operation_family_id: inputs.operation_family_id.clone(),
            built_at: inputs.built_at,
        })
        .unwrap_err();
    let via_builder = build(c.adapter.as_ref(), &inputs).unwrap_err();
    assert_eq!(via_builder, direct);
}

/// Adapter wrapper counting `build_candidate` calls.
struct Counting {
    inner: Arc<dyn ChainAdapter>,
    builds: AtomicUsize,
}

impl ChainAdapter for Counting {
    fn manifest(&self) -> AdapterManifest {
        self.inner.manifest()
    }
    fn identify_network(&self, p: &ChainProfile, e: &EvidenceBundle) -> OicResult<VerifiedNetworkContext> {
        self.inner.identify_network(p, e)
    }
    fn build_candidate(&self, ctx: &BuildContext) -> OicResult<Candidate> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        self.inner.build_candidate(ctx)
    }
    fn decode_candidate(&self, c: &Candidate, ctx: &VerifyContext<'_>) -> OicResult<DecodedOperation> {
        self.inner.decode_candidate(c, ctx)
    }
    fn verify_candidate(&self, c: &Candidate, t: &AuthorizationTarget<'_>, ctx: &VerifyContext<'_>) -> OicResult<VerifiedOperation> {
        self.inner.verify_candidate(c, t, ctx)
    }
    fn signing_payloads(&self, b: &Bytes, k: &KeyDescriptor) -> OicResult<Vec<NativeSigningPayload>> {
        self.inner.signing_payloads(b, k)
    }
    fn assemble_signed_transaction(&self, c: &Candidate, k: &KeyDescriptor, s: &[SignatureBytes]) -> OicResult<SignedTransaction> {
        self.inner.assemble_signed_transaction(c, k, s)
    }
    fn verify_signed_transaction(&self, s: &SignedTransaction, c: &Candidate, k: &KeyDescriptor) -> OicResult<VerifiedSignedTransaction> {
        self.inner.verify_signed_transaction(s, c, k)
    }
    fn observe(&self, id: &ChainTxId, p: &ChainProfile, e: &EvidenceBundle) -> OicResult<ChainObservation> {
        self.inner.observe(id, p, e)
    }
    fn prove_invalidation(&self, f: &OperationFamilyId, c: &[Candidate], p: &ChainProfile, e: &EvidenceBundle) -> OicResult<InvalidationEvidence> {
        self.inner.prove_invalidation(f, c, p, e)
    }
    fn validity_constraints(&self, c: &Candidate, e: &EvidenceBundle) -> OicResult<ChainValidityConstraints> {
        self.inner.validity_constraints(c, e)
    }
    fn derive_address(&self, k: &PublicKey) -> OicResult<(Bytes, String)> {
        self.inner.derive_address(k)
    }
}

#[test]
fn inconsistent_references_are_scope_mismatch_before_the_adapter_runs() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    let good = c.inputs(&intent, &pol, "cand-1");
    let counting = Counting { inner: c.adapter.clone(), builds: AtomicUsize::new(0) };
    let other_net = NetworkId::unchecked("solana-elsewhere");
    let mutations: Vec<(&str, Box<dyn Fn(&mut BuildInputs)>)> = vec![
        ("wallet network", Box::new(|i| i.wallet.network_id = NetworkId::unchecked("solana-elsewhere"))),
        ("wallet vault", Box::new(|i| i.wallet.vault_id = VaultId::unchecked("vault-2"))),
        ("vault id", Box::new(|i| i.vault.vault_id = VaultId::unchecked("vault-2"))),
        ("vault policy", Box::new(|i| i.vault.policy_id = PolicyId::unchecked("pol-2"))),
        ("key epoch", Box::new(|i| i.key.key_epoch = Epoch(2))),
        ("key id", Box::new(|i| i.key.key_id = KeyId::unchecked("key-other"))),
        ("key networks", Box::new(|i| i.key.networks = vec![NetworkId::unchecked("solana-elsewhere")])),
        ("asset network", Box::new(|i| i.asset.network_id = NetworkId::unchecked("solana-elsewhere"))),
        ("asset id", Box::new(|i| i.asset.asset_id = AssetId::unchecked("other"))),
        ("destination network", Box::new(move |i| i.destination.network_id = other_net.clone())),
        ("destination version", Box::new(|i| i.destination.version += 1)),
        ("profile id", Box::new(|i| i.profile.chain_profile_id = ChainProfileId::unchecked("solana-other-v1"))),
        ("profile adapter", Box::new(|i| i.profile.adapter_id = AdapterId::unchecked("evm"))),
        ("intent wallet", Box::new(|i| i.intent.chain_wallet_id = ChainWalletId::unchecked("wallet-other"))),
        ("operation family", Box::new(|i| i.operation_family_id = OperationFamilyId::unchecked("fam-other"))),
        ("policy institution", Box::new(|i| i.policy.institution_id = InstitutionId::unchecked("inst-2"))),
        ("evidence profile", Box::new(|i| i.evidence.chain_profile_id = ChainProfileId::unchecked("solana-other-v1"))),
    ];
    for (what, m) in &mutations {
        let mut bad = good.clone();
        m(&mut bad);
        assert_eq!(code(build(&counting, &bad)), ErrorCode::ScopeMismatch, "{what}");
    }
    assert_eq!(counting.builds.load(Ordering::SeqCst), 0, "the adapter never ran");
    build(&counting, &good).unwrap();
    assert_eq!(counting.builds.load(Ordering::SeqCst), 1);
}

#[test]
fn bounded_mode_returns_a_template_the_adapter_and_signer_accept() {
    let world = World::new();
    let sol = sol_chain(&world, false);
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::BoundedDirectTransfer);
    world.register(&pol, &intent);
    let inputs = c.inputs(&intent, &pol, "cand-1");
    let built = build(c.adapter.as_ref(), &inputs).unwrap();
    let t = built.template.clone().expect("bounded mode returns a template");
    assert_eq!(t.fillable, oic_approval_verifier::fillable_fields_for(&c.profile.adapter_id).unwrap());
    assert_eq!(t.destination_address, c.destination.address);
    assert_eq!(t.amount_base_units, Amount(1_000_000));
    assert_eq!(t.max_native_fee_base_units, intent.constraints.max_network_fee_base_units);
    assert_eq!(t.network_id, c.profile.network_id);
    let vctx = VerifyContext { profile: &c.profile, wallet: &c.wallet, key: &c.key, asset: &c.asset, destination: &c.destination, evidence: &inputs.evidence };
    let v = c.adapter.verify_candidate(&built.candidate, &AuthorizationTarget::Template(&t), &vctx).unwrap();
    assert_eq!(v, built.verified);

    let grant = world.bounded_grant(&built, t, 0);
    let ev = evaluate(&built, &pol, Epoch(1), std::slice::from_ref(&grant), &world.approver_credentials(), &world.exposure(&built, &pol), now()).unwrap();
    assert!(ev.decision.is_allow(), "{:?}", ev.decision);
    let body = envelope_body(&built, c.adapter.as_ref(), &c.profile, vec![grant], SigningSessionId::unchecked("sess-b"), vec![pid(1), pid(2)], UnixSeconds(DEADLINE)).unwrap();
    let env = world.reserve(&built, &pol.rules[0], body);
    let verified = c.nodes[0].signer.verify_envelope(&env, &signing_materials(&built.package), now()).unwrap();
    assert!(verified.decision.is_allow());
    assert_eq!(verified.approvers, vec![CredentialId::unchecked("approver-1")]);
}

#[test]
fn envelope_body_hashes_like_the_signer_and_verifies_on_evm_and_solana() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000_000, 10u128.pow(16), ApprovalMode::ExactCandidate);
    world.register(&pol, &intent);
    let built = build(c.adapter.as_ref(), &c.inputs(&intent, &pol, "cand-1")).unwrap();
    let grants = world.grants_for(&built, 1);
    let body = envelope_body(&built, c.adapter.as_ref(), &c.profile, grants.clone(), SigningSessionId::unchecked("sess-1"), vec![pid(1)], UnixSeconds(DEADLINE)).unwrap();
    assert_eq!(body.budget_reservation_id, oic_authorization_state::reservation_id_for(&built.candidate.operation_family_id, &built.candidate.candidate_id, 1).unwrap());
    assert_eq!(body.reservation_version, 1);
    assert_eq!(body.destination_hash, oic_policy_kernel::destination_hash(&c.destination).unwrap());
    assert_eq!(body.expected_chain_validity_constraints, c.adapter.validity_constraints(&built.candidate, &built.package.evidence).unwrap());
    assert_eq!(body.approval_grants, grants);
    let h = envelope_body_hash(&body).unwrap();
    let env = world.reserve(&built, &pol.rules[0], body.clone());
    assert_eq!(env.authorization_state_receipt.body.envelope_body_hash, h);
    let m = signing_materials(&built.package);
    assert_eq!(m.candidate, built.candidate);
    assert_eq!(m.policy, pol);
    let v = c.nodes[0].signer.verify_envelope(&env, &m, now()).unwrap();
    assert_eq!(v.envelope_body_hash, h);
    assert_eq!(v.verified, built.verified);
    // A mismatched profile or adapter is refused.
    let mut other = c.profile.clone();
    other.chain_profile_id = ChainProfileId::unchecked("evm-other-v1");
    assert_eq!(code(envelope_body(&built, c.adapter.as_ref(), &other, vec![], SigningSessionId::unchecked("s"), vec![pid(1)], UnixSeconds(DEADLINE))), ErrorCode::ScopeMismatch);
    let sol_adapter = oic_adapter_solana::SolanaAdapter;
    assert_eq!(code(envelope_body(&built, &sol_adapter, &c.profile, vec![], SigningSessionId::unchecked("s"), vec![pid(1)], UnixSeconds(DEADLINE))), ErrorCode::ScopeMismatch);

    let world2 = World::new();
    let sol = sol_chain(&world2, false);
    let s = &sol.chain;
    let pol2 = signed_policy(&world2, &s.asset, 1, 10_000_000);
    let intent2 = s.intent("intent-1", 1_000_000, 10_000_000, ApprovalMode::ExactCandidate);
    world2.register(&pol2, &intent2);
    let built2 = build(s.adapter.as_ref(), &s.inputs(&intent2, &pol2, "cand-1")).unwrap();
    let body2 = envelope_body(&built2, s.adapter.as_ref(), &s.profile, world2.grants_for(&built2, 1), SigningSessionId::unchecked("sess-2"), vec![pid(2), pid(3)], UnixSeconds(DEADLINE)).unwrap();
    assert!(body2.expected_chain_validity_constraints.expires_at_height.is_some());
    let env2 = world2.reserve(&built2, &pol2.rules[0], body2);
    for n in &s.nodes[1..] {
        n.signer.verify_envelope(&env2, &signing_materials(&built2.package), now()).unwrap();
    }
    assert_eq!(code(s.nodes[0].signer.verify_envelope(&env2, &signing_materials(&built2.package), now())), ErrorCode::ScopeMismatch, "signer-1 is not in the set");
}

#[test]
fn evidence_sources_refuse_foreign_requests_and_fetch_lookup_tables() {
    let world = World::new();
    let evm = evm_chain(&world);
    let sol = sol_chain(&world, false);
    // A Solana request at the EVM source (and vice versa) is a scope mismatch.
    assert_eq!(code(evm.chain.source.evidence(&sol.chain.request(EvidenceCommitment::Latest))), ErrorCode::ScopeMismatch);
    assert_eq!(code(sol.chain.source.evidence(&evm.chain.request(EvidenceCommitment::Latest))), ErrorCode::ScopeMismatch);
    let mut bad_dest = evm.chain.request(EvidenceCommitment::Latest);
    bad_dest.destination.network_id = NetworkId::unchecked("evm-1");
    assert_eq!(code(evm.chain.source.evidence(&bad_dest)), ErrorCode::ScopeMismatch);
    let mut tables = evm.chain.request(EvidenceCommitment::Latest);
    tables.lookup_tables = vec![Bytes(vec![1; 32])];
    assert_eq!(code(evm.chain.source.evidence(&tables)), ErrorCode::InvalidRequest);
    let mut spl_on_evm = evm.chain.request(EvidenceCommitment::Latest);
    spl_on_evm.asset.asset = AssetKind::SplToken { mint: Bytes(vec![1; 32]), token_program: Bytes(TOKEN_PROGRAM_ID.to_vec()) };
    assert_eq!(code(evm.chain.source.evidence(&spl_on_evm)), ErrorCode::UnsupportedCapability);

    // Finalized evidence comes from the finalized view.
    let fin = evm.chain.source.evidence(&evm.chain.request(EvidenceCommitment::Finalized)).unwrap();
    assert_eq!(fin.state.commitment, "finalized");
    let latest = sol.chain.source.evidence(&sol.chain.request(EvidenceCommitment::Latest)).unwrap();
    assert_eq!(latest.state.commitment, "processed");

    // Lookup tables: a legacy candidate reads none; a v0 message names its table, and the
    // source returns the table's evidence item when asked.
    let c = &sol.chain;
    let pol = signed_policy(&world, &c.asset, 1, 10_000_000);
    let intent = c.intent("intent-1", 1_000, 10_000_000, ApprovalMode::ExactCandidate);
    let built = build(c.adapter.as_ref(), &c.inputs(&intent, &pol, "cand-1")).unwrap();
    assert_eq!(solana_lookup_tables(&built.candidate).unwrap(), Vec::<Bytes>::new());
    let table = sol.sim.create_lookup_table(vec![[0x01; 32], sol_dest_owner()]).unwrap();
    sol.sim.advance_slot().unwrap();
    let wallet: [u8; 32] = c.wallet.address.as_slice().try_into().unwrap();
    let v0 = Message {
        version: MessageVersion::V0,
        header: MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 },
        account_keys: vec![wallet, oic_adapter_solana::address::SYSTEM_PROGRAM_ID],
        recent_blockhash: sol.sim.latest_blockhash(),
        instructions: vec![CompiledInstruction { program_id_index: 1, accounts: vec![0, 2], data: oic_adapter_solana::instruction::system_transfer_data(1_000) }],
        address_table_lookups: vec![AddressTableLookup { account_key: table, writable_indexes: vec![1], readonly_indexes: vec![] }],
    };
    let mut v0_candidate = built.candidate.clone();
    v0_candidate.native_unsigned_bytes = Bytes(v0.encode());
    let tables = solana_lookup_tables(&v0_candidate).unwrap();
    assert_eq!(tables, vec![Bytes(table.to_vec())]);
    let ev = c.source.evidence(&EvidenceRequest { lookup_tables: tables, ..c.request(EvidenceCommitment::Latest) }).unwrap();
    assert!(ev.items.contains_key(&format!("alt:{}", to_base58(&table))));
    // With that evidence the adapter resolves the table and verifies the v0 message.
    v0_candidate.signing_payloads = c.adapter.signing_payloads(&v0_candidate.native_unsigned_bytes, &c.key).unwrap();
    v0_candidate.evidence_bundle_hash = evidence_hash(&ev).unwrap();
    let vctx = VerifyContext { profile: &c.profile, wallet: &c.wallet, key: &c.key, asset: &c.asset, destination: &c.destination, evidence: &ev };
    let v = c.adapter.verify_candidate(&v0_candidate, &AuthorizationTarget::Intent(&intent), &vctx).unwrap();
    assert_eq!(v.decoded.recipient().as_slice(), &sol_dest_owner()[..]);
    // EVM candidates have no lookup tables to ask for.
    assert_eq!(code(solana_lookup_tables(&Candidate { adapter_id: AdapterId::unchecked("evm"), ..built.candidate.clone() })), ErrorCode::UnsupportedCapability);
}
