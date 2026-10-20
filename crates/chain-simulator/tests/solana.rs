//! End-to-end: the pinned Solana adapter builds from simulator evidence, the
//! simulator verifies and executes the signed bytes, and the adapter observes
//! the result through simulator evidence.

mod common;

use common::*;
use ed25519_dalek::{Signer, SigningKey};
use oic_adapter_api::*;
use oic_adapter_solana::address::*;
use oic_adapter_solana::evidence::{get_token_account, get_tx_observation, TxObservation};
use oic_adapter_solana::instruction::*;
use oic_adapter_solana::message::{AddressTableLookup, CompiledInstruction, Message, MessageHeader, MessageVersion, Transaction};
use oic_adapter_solana::{compile_legacy_message, InstructionSpec, SolanaAdapter};
use oic_chain_simulator::solana::*;
use oic_chain_simulator::SimClock;
use oic_domain_types::*;
use std::sync::Arc;

const SOL: u64 = 1_000_000_000;
/// Evidence defaults: 1 signature * 5000 + ceil(200_000 CU * 1_000 µlamports / 1e6).
const FEE: u64 = 5_000 + 200;

fn sim_with(cfg: SolanaSimConfig) -> (Arc<SolanaSimulator>, SimClock) {
    let clock = SimClock::default();
    (Arc::new(SolanaSimulator::new(cfg, clock.clone()).unwrap()), clock)
}

fn default_sim() -> (Arc<SolanaSimulator>, SimClock) {
    sim_with(SolanaSimConfig::with_seed([3; 32]))
}

fn kp(seed: u8) -> SigningKey {
    let mut b = [0x33u8; 32];
    b[0] = seed;
    SigningKey::from_bytes(&b)
}

fn pk(sk: &SigningKey) -> Pubkey {
    sk.verifying_key().to_bytes()
}

fn sol_party(profile: &ChainProfile, sk: &SigningKey) -> Party {
    let a = pk(sk);
    party(profile, SchemeId::Ed25519Pure, a.to_vec(), a.to_vec(), to_base58(&a), 1)
}

fn native_transfer(sim: &SolanaSimulator, sk: &SigningKey, dest: Pubkey, amount: u64) -> Transfer {
    let p = sim.profile();
    let party = sol_party(&p, sk);
    let asset = asset(&p, AssetKind::Native, 9, "SOL");
    let d = destination(&p, dest.to_vec(), to_base58(&dest));
    Transfer::new(p, party, asset, d, amount as u128, 10_000_000)
}

fn spl_transfer(sim: &SolanaSimulator, sk: &SigningKey, mint: Pubkey, decimals: u8, dest_owner: Pubkey, amount: u64) -> Transfer {
    let p = sim.profile();
    let party = sol_party(&p, sk);
    let asset = asset(&p, AssetKind::SplToken { mint: Bytes(mint.to_vec()), token_program: Bytes(TOKEN_PROGRAM_ID.to_vec()) }, decimals, "USDC");
    let d = destination(&p, dest_owner.to_vec(), to_base58(&dest_owner));
    Transfer::new(p, party, asset, d, amount as u128, 10_000_000)
}

/// Build via the adapter from fresh simulator evidence, sign with Ed25519, assemble.
fn build_and_sign(sim: &SolanaSimulator, clock: &SimClock, t: &Transfer, sk: &SigningKey, cand: &str, token_accounts: &[Pubkey]) -> (Candidate, SignedTransaction) {
    let mut q = SolanaEvidenceQuery::processed();
    for a in token_accounts {
        q = q.token_account(*a);
    }
    let ev = sim.evidence(&q).unwrap();
    SolanaAdapter.identify_network(&t.profile, &ev).unwrap();
    let c = SolanaAdapter.build_candidate(&t.build_ctx(ev.clone(), cand, 1, clock.now())).unwrap();
    SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&t.intent), &t.vctx(&ev)).unwrap();
    let sig = SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(sk.sign(c.signing_payloads[0].message_or_digest.as_slice()).to_bytes().to_vec()) };
    let signed = SolanaAdapter.assemble_signed_transaction(&c, &t.party.key, &[sig]).unwrap();
    (c, signed)
}

fn observe(sim: &SolanaSimulator, id: &ChainTxId) -> OicResult<ChainObservation> {
    let ev = sim.evidence(&SolanaEvidenceQuery::processed().tx_id(id).unwrap()).unwrap();
    SolanaAdapter.observe(id, &sim.profile(), &ev)
}

fn transfer_tx(sim: &SolanaSimulator, from: &SigningKey, to: &Pubkey, lamports: u64) -> Vec<u8> {
    let spec = InstructionSpec { program_id: SYSTEM_PROGRAM_ID, accounts: vec![(pk(from), true, true), (*to, false, true)], data: system_transfer_data(lamports) };
    let msg = compile_legacy_message(&pk(from), &[spec], sim.latest_blockhash()).unwrap();
    sign_transaction(&[from], &msg.encode())
}

fn funded(sim: &SolanaSimulator, sk: &SigningKey, lamports: u64) -> Pubkey {
    let a = pk(sk);
    sim.airdrop(&a, lamports).unwrap();
    sim.advance_slot().unwrap();
    a
}

#[test]
fn profile_and_evidence_shape() {
    let (sim, clock) = default_sim();
    let p = sim.profile();
    assert_eq!(p.chain_profile_id.as_str(), "solana-devsim-v1");
    assert_eq!(p.network_id.as_str(), "solana-devsim");
    assert_eq!(p.network_binding, Bytes(sim.genesis_hash().to_vec()));
    assert_eq!(p.finality_depth, 4);
    assert_eq!(p.finality_commitment, "finalized");
    assert_eq!(p.max_evidence_age_seconds, 120);
    assert_eq!(p.accepted_trust_levels, vec![EvidenceTrustLevel::DevelopmentSimulator]);
    assert!(p.display_name.contains("DEVELOPMENT ONLY"));
    let ev = sim.evidence(&SolanaEvidenceQuery::processed()).unwrap();
    assert_eq!(ev.trust_level, EvidenceTrustLevel::DevelopmentSimulator);
    assert_eq!(ev.sources, vec![EvidenceSourceId::unchecked("devsim-solana")]);
    assert_eq!(ev.verifier_version, format!("oic-chain-simulator/{}", env!("CARGO_PKG_VERSION")));
    assert_eq!(ev.max_staleness_seconds, 60);
    assert_eq!(ev.observed_at, clock.now());
    assert_eq!(ev.state, sim.head());
    let le = |v: u64| Bytes(v.to_le_bytes().to_vec());
    assert_eq!(ev.items["genesis_hash"], Bytes(sim.genesis_hash().to_vec()));
    assert_eq!(ev.items["recent_blockhash"], Bytes(sim.latest_blockhash().to_vec()));
    assert_eq!(ev.items["blockhash_last_valid_height"], le(150));
    assert_eq!(ev.items[&format!("blockhash_last_valid_height:{}", to_base58(&sim.latest_blockhash()))], le(150));
    assert_eq!(ev.items["lamports_per_signature"], le(5_000));
    assert_eq!(ev.items["rent_exempt_minimum:token_account"], le(2_039_280));
    assert_eq!(ev.items["cu_limit"], Bytes(200_000u32.to_le_bytes().to_vec()));
    assert_eq!(ev.items["cu_price"], le(1_000));
    SolanaAdapter.identify_network(&p, &ev).unwrap();
    // A different genesis (another seed) fails network identification.
    let (other, _) = sim_with(SolanaSimConfig::with_seed([4; 32]));
    assert_ne!(other.genesis_hash(), sim.genesis_hash());
    assert_eq!(SolanaAdapter.identify_network(&other.profile(), &ev).unwrap_err().code, ErrorCode::ScopeMismatch);
    // Airdrop is a real signed System transfer that lands in a slot.
    let dest = [0x44; 32];
    let id = sim.airdrop(&dest, 1234).unwrap();
    assert_eq!(sim.tx_status(&id).unwrap(), Some(SolanaTxStatus::Queued));
    let b = sim.advance_slot().unwrap();
    assert_eq!(b.transactions.len(), 1);
    assert_eq!(b.transactions[0].account_keys[0], sim.faucet_address());
    assert!(b.transactions[0].success);
    assert_eq!(sim.lamports(&dest), 1234);
    assert_eq!(b.parent_blockhash, sim.block(0).unwrap().blockhash);
    assert_eq!(sim.account(&dest), Some(SolanaAccount { lamports: 1234, owner: SYSTEM_PROGRAM_ID, data: vec![] }));
    assert_eq!(sim.account(&[0x45; 32]), None);
    assert_eq!(sim.config(), SolanaSimConfig::with_seed([3; 32]));
    assert_eq!(sim.clock().now(), clock.now());
    // Identical airdrop against the same blockhash is a byte-identical replay.
    sim.airdrop(&dest, 1).unwrap();
    assert_eq!(sim.airdrop(&dest, 1).unwrap_err().code, ErrorCode::ResourceConflict);
}

#[test]
fn native_transfer_end_to_end_processed_confirmed_finalized() {
    let (sim, clock) = default_sim();
    let sk = kp(1);
    let wallet = funded(&sim, &sk, SOL);
    let dest = pk(&kp(2));
    let t = native_transfer(&sim, &sk, dest, 250_000);
    let (_, signed) = build_and_sign(&sim, &clock, &t, &sk, "cand-1", &[]);
    let id = sim.submit(signed.signed_bytes.as_slice()).unwrap();
    assert_eq!(id, signed.chain_tx_id);
    // Queued, not included: no tx item, the adapter fails closed.
    assert_eq!(observe(&sim, &id).unwrap_err().code, ErrorCode::StaleEvidence);
    let block = sim.advance_slot().unwrap();
    match observe(&sim, &id).unwrap() {
        ChainObservation::Included { state, execution_success, fee_paid, .. } => {
            assert!(execution_success);
            assert_eq!(fee_paid, Amount(FEE as u128));
            assert_eq!(state.height, block.slot);
            assert_eq!(state.hash, Bytes(block.blockhash.to_vec()));
            assert_eq!(state.commitment, "processed");
        }
        o => panic!("expected Included, got {o:?}"),
    }
    sim.advance_slot().unwrap();
    assert!(matches!(observe(&sim, &id).unwrap(), ChainObservation::Included { state, .. } if state.commitment == "confirmed"));
    sim.advance_slots(2).unwrap();
    assert!(matches!(observe(&sim, &id).unwrap(), ChainObservation::Included { .. }));
    sim.advance_slot().unwrap();
    assert_eq!(sim.finalized_slot(), block.slot);
    match observe(&sim, &id).unwrap() {
        ChainObservation::Finalized { state, execution_success, fee_paid, .. } => {
            assert!(execution_success);
            assert_eq!(fee_paid, Amount(FEE as u128));
            assert_eq!(state.commitment, "finalized");
        }
        o => panic!("expected Finalized, got {o:?}"),
    }
    assert_eq!(sim.lamports(&wallet), SOL - 250_000 - FEE);
    assert_eq!(sim.lamports(&dest), 250_000);
    match sim.tx_status(&id).unwrap().unwrap() {
        SolanaTxStatus::Included { fee, success, commitment, .. } => assert_eq!((fee, success, commitment.as_str()), (FEE, true, "finalized")),
        s => panic!("{s:?}"),
    }
    // Finalized-commitment evidence is anchored at the finalized slot.
    let ev = sim.evidence(&SolanaEvidenceQuery::finalized().tx_id(&id).unwrap()).unwrap();
    assert_eq!(ev.state, sim.finalized());
    assert_eq!(get_tx_observation(&ev, &parse_tx_id(&id).unwrap()).unwrap().commitment, "finalized");
}

#[test]
fn spl_transfer_with_ata_create_idempotent_reconciles() {
    let (sim, clock) = default_sim();
    let sk = kp(5);
    let wallet = pk(&sk);
    let mint = sim.create_mint(6, b"usdc-authority").unwrap();
    assert_eq!(sim.mint_info(&mint).unwrap().mint_authority, Some(mint_authority(b"usdc-authority")));
    let src = sim.create_ata(&wallet, &mint).unwrap();
    assert_eq!(src, associated_token_address(&wallet, &mint, &TOKEN_PROGRAM_ID).unwrap());
    sim.mint_to(&mint, &src, 10_000_000).unwrap();
    funded(&sim, &sk, SOL);
    let dest_owner = pk(&kp(6));
    let dest_ata = associated_token_address(&dest_owner, &mint, &TOKEN_PROGRAM_ID).unwrap();

    // Evidence: source present (canonical TokenAccountEvidence), destination absent.
    let ev = sim.evidence(&SolanaEvidenceQuery::processed().token_account(src).token_account(dest_ata)).unwrap();
    let ta = get_token_account(&ev, &src).unwrap();
    assert_eq!((ta.amount, ta.owner.as_slice(), ta.mint.as_slice(), ta.state), (10_000_000, &wallet[..], &mint[..], 1));
    assert!(!ev.items.contains_key(&format!("token_account:{}", to_base58(&dest_ata))));

    let t = spl_transfer(&sim, &sk, mint, 6, dest_owner, 1_000_000);
    let (c, signed) = build_and_sign(&sim, &clock, &t, &sk, "cand-1", &[src, dest_ata]);
    let msg = Message::decode(c.native_unsigned_bytes.as_slice()).unwrap();
    let programs: Vec<Pubkey> = msg.instructions.iter().map(|i| msg.account_keys[i.program_id_index as usize]).collect();
    assert_eq!(programs, vec![COMPUTE_BUDGET_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID, ATA_PROGRAM_ID, TOKEN_PROGRAM_ID]);

    let id = sim.submit(signed.signed_bytes.as_slice()).unwrap();
    let lamports_before: Vec<(Pubkey, u64)> = msg.account_keys.iter().map(|k| (*k, sim.lamports(k))).collect();
    let block = sim.advance_slot().unwrap();
    let rec = &block.transactions[0];
    assert!(rec.success, "{:?}", rec.err);
    assert_eq!(rec.fee, FEE);
    assert_eq!(sim.token_balance(&src), Some(9_000_000));
    assert_eq!(sim.token_balance(&dest_ata), Some(1_000_000));
    assert_eq!(sim.token_account(&dest_ata).unwrap().owner, dest_owner);
    assert_eq!(sim.lamports(&wallet), SOL - FEE - RENT_EXEMPT_TOKEN_ACCOUNT);
    assert_eq!(sim.lamports(&dest_ata), RENT_EXEMPT_TOKEN_ACCOUNT);

    // Block pre/post balances equal the state deltas, account by account.
    assert_eq!(rec.account_keys, msg.account_keys);
    for (i, (k, before)) in lamports_before.iter().enumerate() {
        assert_eq!(rec.pre_lamports[i], *before, "pre {}", to_base58(k));
        assert_eq!(rec.post_lamports[i], sim.lamports(k), "post {}", to_base58(k));
    }
    let pre_sum: u64 = rec.pre_lamports.iter().sum();
    let post_sum: u64 = rec.post_lamports.iter().sum();
    assert_eq!(pre_sum - post_sum, rec.fee);
    let bal = |v: &[TokenBalance], a: &Pubkey| v.iter().find(|b| b.account == *a).map(|b| b.amount);
    assert_eq!(bal(&rec.pre_token_balances, &src), Some(10_000_000));
    assert_eq!(bal(&rec.pre_token_balances, &dest_ata), None);
    assert_eq!(bal(&rec.post_token_balances, &src), Some(9_000_000));
    assert_eq!(bal(&rec.post_token_balances, &dest_ata), Some(1_000_000));
    let post = rec.post_token_balances.iter().find(|b| b.account == dest_ata).unwrap();
    assert_eq!((post.owner, post.mint, rec.account_keys[post.account_index]), (dest_owner, mint, dest_ata));

    sim.advance_slots(4).unwrap();
    assert!(matches!(observe(&sim, &id).unwrap(), ChainObservation::Finalized { execution_success: true, fee_paid, .. } if fee_paid == Amount(FEE as u128)));

    // Destination now exists: evidence carries it and the adapter omits the create.
    let mut t2 = spl_transfer(&sim, &sk, mint, 6, dest_owner, 500_000);
    t2.intent.intent_id = IntentId::unchecked("intent-2");
    let (c2, signed2) = build_and_sign(&sim, &clock, &t2, &sk, "cand-2", &[src, dest_ata]);
    let msg2 = Message::decode(c2.native_unsigned_bytes.as_slice()).unwrap();
    assert!(!msg2.account_keys.contains(&ATA_PROGRAM_ID));
    sim.submit(signed2.signed_bytes.as_slice()).unwrap();
    sim.advance_slot().unwrap();
    assert_eq!(sim.token_balance(&dest_ata), Some(1_500_000));
    assert_eq!(sim.lamports(&wallet), SOL - 2 * FEE - RENT_EXEMPT_TOKEN_ACCOUNT);
}

#[test]
fn expired_and_unknown_blockhash_rejected_and_invalidation_proved() {
    let (sim, clock) = sim_with(SolanaSimConfig { blockhash_validity_slots: 3, finality_depth: 2, ..SolanaSimConfig::with_seed([3; 32]) });
    let sk = kp(7);
    funded(&sim, &sk, SOL);
    let dest = pk(&kp(8));
    let t = native_transfer(&sim, &sk, dest, 1_000);
    let (cand, signed) = build_and_sign(&sim, &clock, &t, &sk, "cand-1", &[]);
    let bh = Message::decode(cand.native_unsigned_bytes.as_slice()).unwrap().recent_blockhash;
    let produced = sim.head().height;
    let ev = sim.evidence(&SolanaEvidenceQuery::processed()).unwrap();
    assert_eq!(SolanaAdapter.validity_constraints(&cand, &ev).unwrap().expires_at_height, Some(produced + 3));
    sim.advance_slots(3).unwrap();
    let e = sim.submit(signed.signed_bytes.as_slice()).unwrap_err();
    assert_eq!(e.code, ErrorCode::ResourceConflict);
    assert!(e.detail.contains("expired"), "{}", e.detail);
    assert_eq!(sim.lamports(&dest), 0);
    // Unknown blockhash.
    let spec = InstructionSpec { program_id: SYSTEM_PROGRAM_ID, accounts: vec![(pk(&sk), true, true), (dest, false, true)], data: system_transfer_data(5) };
    let msg = compile_legacy_message(&pk(&sk), &[spec], [0x5a; 32]).unwrap();
    let e = sim.submit(&sign_transaction(&[&sk], &msg.encode())).unwrap_err();
    assert_eq!(e.code, ErrorCode::ResourceConflict);
    assert!(e.detail.contains("blockhash not found"), "{}", e.detail);

    // Invalidation: finalized evidence past last_valid + finality_depth, naming the
    // family's signed bytes and showing the signature never succeeded.
    let fam = OperationFamilyId::unchecked("family-1");
    let sig = parse_tx_id(&signed.chain_tx_id).unwrap();
    let q = |q: SolanaEvidenceQuery| q.blockhash(bh).signature(sig).signed("cand-1", 1, signed.signed_bytes.0.clone());
    let ev = sim.evidence(&q(SolanaEvidenceQuery::finalized())).unwrap();
    assert_eq!(SolanaAdapter.prove_invalidation(&fam, std::slice::from_ref(&cand), &sim.profile(), &ev).unwrap(), InvalidationEvidence::Unknown);
    sim.advance_slots(4).unwrap();
    let ev = sim.evidence(&q(SolanaEvidenceQuery::finalized())).unwrap();
    assert_eq!(ev.items[&format!("blockhash_last_valid_height:{}", to_base58(&bh))], Bytes((produced + 3).to_le_bytes().to_vec()));
    assert!(!ev.items.contains_key(&format!("tx:{}", to_base58(&sig))));
    match SolanaAdapter.prove_invalidation(&fam, std::slice::from_ref(&cand), &sim.profile(), &ev).unwrap() {
        InvalidationEvidence::Definitive { state, .. } => assert_eq!(state, sim.finalized()),
        InvalidationEvidence::Unknown => panic!("expected definitive invalidation"),
    }
    // Processed-commitment evidence is never proof.
    let ev = sim.evidence(&q(SolanaEvidenceQuery::processed())).unwrap();
    assert_eq!(SolanaAdapter.prove_invalidation(&fam, &[cand], &sim.profile(), &ev).unwrap(), InvalidationEvidence::Unknown);
}

#[test]
fn replay_and_bad_signatures_rejected() {
    let (sim, _clock) = default_sim();
    let sk = kp(9);
    let wallet = funded(&sim, &sk, SOL);
    let dest = pk(&kp(10));
    let bytes = transfer_tx(&sim, &sk, &dest, 777);
    sim.submit(&bytes).unwrap();
    assert_eq!(sim.submit(&bytes).unwrap_err().code, ErrorCode::ResourceConflict);
    sim.advance_slot().unwrap();
    let e = sim.submit(&bytes).unwrap_err();
    assert_eq!(e.code, ErrorCode::ResourceConflict);
    assert!(e.detail.contains("already been processed"));
    sim.advance_slot().unwrap();
    assert_eq!(sim.lamports(&dest), 777);
    assert_eq!(sim.lamports(&wallet), SOL - 777 - 5_000);
    // Tampered signature.
    let mut bad = transfer_tx(&sim, &sk, &dest, 1);
    bad[10] ^= 0x01;
    assert_eq!(sim.submit(&bad).unwrap_err().code, ErrorCode::InvalidSignature);
    // Signed by the wrong key.
    let spec = InstructionSpec { program_id: SYSTEM_PROGRAM_ID, accounts: vec![(wallet, true, true), (dest, false, true)], data: system_transfer_data(1) };
    let msg = compile_legacy_message(&wallet, &[spec], sim.latest_blockhash()).unwrap();
    assert_eq!(sim.submit(&sign_transaction(&[&kp(11)], &msg.encode())).unwrap_err().code, ErrorCode::InvalidSignature);
    // Fee payer that cannot pay.
    let poor = kp(12);
    assert_eq!(sim.submit(&transfer_tx(&sim, &poor, &dest, 1)).unwrap_err().code, ErrorCode::ResourceConflict);
    // Garbage.
    assert!(sim.submit(&[1, 2, 3]).is_err());
}

#[test]
fn unknown_program_rejected_and_failed_instruction_is_atomic() {
    let (sim, _clock) = default_sim();
    let sk = kp(13);
    let wallet = pk(&sk);
    let mint = sim.create_mint(2, b"auth").unwrap();
    let src = sim.create_ata(&wallet, &mint).unwrap();
    sim.mint_to(&mint, &src, 100).unwrap();
    funded(&sim, &sk, SOL);
    let dest = pk(&kp(14));
    let dest_ata = sim.create_ata(&dest, &mint).unwrap();
    sim.advance_slot().unwrap();
    let before = sim.lamports(&wallet);

    // System transfer followed by an unknown program: refused whole, nothing applied or queued.
    let specs = [
        InstructionSpec { program_id: SYSTEM_PROGRAM_ID, accounts: vec![(wallet, true, true), (dest, false, true)], data: system_transfer_data(1_000) },
        InstructionSpec { program_id: [0x99; 32], accounts: vec![(wallet, true, true)], data: vec![1, 2, 3] },
    ];
    let msg = compile_legacy_message(&wallet, &specs, sim.latest_blockhash()).unwrap();
    let bytes = sign_transaction(&[&sk], &msg.encode());
    let e = sim.submit(&bytes).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
    let sig = Transaction::decode(&bytes).unwrap().signatures[0];
    assert_eq!(sim.tx_status(&tx_id(&sig)).unwrap(), None);
    let b = sim.advance_slot().unwrap();
    assert!(b.transactions.is_empty());
    assert_eq!((sim.lamports(&wallet), sim.lamports(&dest)), (before, 0));

    // System transfer followed by a TransferChecked that overdraws: included as
    // failed, fee charged, the earlier transfer rolled back.
    let specs = [
        InstructionSpec { program_id: SYSTEM_PROGRAM_ID, accounts: vec![(wallet, true, true), (dest, false, true)], data: system_transfer_data(1_000) },
        InstructionSpec {
            program_id: TOKEN_PROGRAM_ID,
            accounts: vec![(src, false, true), (mint, false, false), (dest_ata, false, true), (wallet, true, false)],
            data: transfer_checked_data(101, 2),
        },
    ];
    let msg = compile_legacy_message(&wallet, &specs, sim.latest_blockhash()).unwrap();
    let id = sim.submit(&sign_transaction(&[&sk], &msg.encode())).unwrap();
    let b = sim.advance_slot().unwrap();
    let rec = &b.transactions[0];
    assert!(!rec.success);
    assert!(rec.err.as_deref().unwrap().contains("insufficient funds"), "{:?}", rec.err);
    assert_eq!(sim.lamports(&wallet), before - 5_000);
    assert_eq!(sim.lamports(&dest), 0);
    assert_eq!((sim.token_balance(&src), sim.token_balance(&dest_ata)), (Some(100), Some(0)));
    assert_eq!(rec.pre_token_balances, rec.post_token_balances);
    assert!(matches!(observe(&sim, &id).unwrap(), ChainObservation::Included { execution_success: false, fee_paid, .. } if fee_paid == Amount(5_000)));

    // Wrong decimals and a frozen account also fail at execution.
    let wrong_dec = [InstructionSpec {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![(src, false, true), (mint, false, false), (dest_ata, false, true), (wallet, true, false)],
        data: transfer_checked_data(1, 9),
    }];
    let msg = compile_legacy_message(&wallet, &wrong_dec, sim.latest_blockhash()).unwrap();
    sim.submit(&sign_transaction(&[&sk], &msg.encode())).unwrap();
    sim.freeze_token_account(&dest_ata).unwrap();
    let b = sim.advance_slot().unwrap();
    assert!(b.transactions[0].err.as_deref().unwrap().contains("decimals mismatch"));
    let ok_amount = [InstructionSpec {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![(src, false, true), (mint, false, false), (dest_ata, false, true), (wallet, true, false)],
        data: transfer_checked_data(1, 2),
    }];
    let msg = compile_legacy_message(&wallet, &ok_amount, sim.latest_blockhash()).unwrap();
    sim.submit(&sign_transaction(&[&sk], &msg.encode())).unwrap();
    let b = sim.advance_slot().unwrap();
    assert!(b.transactions[0].err.as_deref().unwrap().contains("frozen"));
    assert_eq!(sim.token_balance(&src), Some(100));
    // Non-idempotent ATA Create on an existing account fails.
    let create = [InstructionSpec {
        program_id: ATA_PROGRAM_ID,
        accounts: vec![(wallet, true, true), (src, false, true), (wallet, false, false), (mint, false, false), (SYSTEM_PROGRAM_ID, false, false), (TOKEN_PROGRAM_ID, false, false)],
        data: vec![],
    }];
    let msg = compile_legacy_message(&wallet, &create, sim.latest_blockhash()).unwrap();
    sim.submit(&sign_transaction(&[&sk], &msg.encode())).unwrap();
    let b = sim.advance_slot().unwrap();
    assert!(b.transactions[0].err.as_deref().unwrap().contains("already in use"));
}

#[test]
fn fork_reorders_slots_and_observe_follows() {
    let (sim, _clock) = default_sim();
    let sk = kp(15);
    let wallet = funded(&sim, &sk, SOL);
    let d1 = pk(&kp(16));
    let d2 = pk(&kp(17));
    let b1 = transfer_tx(&sim, &sk, &d1, 100);
    let b2 = transfer_tx(&sim, &sk, &d2, 200);
    let fork_base = sim.head().height;
    let t1 = sim.submit(&b1).unwrap();
    let s1 = sim.advance_slot().unwrap();
    let t2 = sim.submit(&b2).unwrap();
    let s2 = sim.advance_slot().unwrap();
    assert_eq!((s1.transactions.len(), s2.transactions.len()), (1, 1));
    let old_state = match observe(&sim, &t1).unwrap() {
        ChainObservation::Included { state, .. } => state,
        o => panic!("{o:?}"),
    };

    // Fork without dropping: both re-queued in order and re-included in the first new slot.
    sim.fork(fork_base, &[]).unwrap();
    assert_eq!(sim.head().height, s2.slot);
    let n1 = sim.block(s1.slot).unwrap();
    let n2 = sim.block(s2.slot).unwrap();
    assert_ne!(n1.blockhash, s1.blockhash);
    assert_ne!(n2.blockhash, s2.blockhash);
    assert_eq!(n1.fork, 1);
    assert_eq!(n1.transactions.iter().map(|t| t.tx_id()).collect::<Vec<_>>(), vec![t1.clone(), t2.clone()]);
    assert!(n2.transactions.is_empty());
    match observe(&sim, &t2).unwrap() {
        ChainObservation::Included { state, .. } => {
            assert_eq!(state.height, s1.slot);
            assert_eq!(state.hash, Bytes(n1.blockhash.to_vec()));
        }
        o => panic!("{o:?}"),
    }
    assert!(matches!(observe(&sim, &t1).unwrap(), ChainObservation::Included { state, .. } if state.hash != old_state.hash));
    // The discarded blockhash is no longer usable.
    let spec = InstructionSpec { program_id: SYSTEM_PROGRAM_ID, accounts: vec![(wallet, true, true), (d1, false, true)], data: system_transfer_data(1) };
    let stale = compile_legacy_message(&wallet, &[spec], s1.blockhash).unwrap();
    assert!(sim.submit(&sign_transaction(&[&sk], &stale.encode())).unwrap_err().detail.contains("blockhash not found"));

    // Fork dropping t1: gone from the canonical chain, effects undone, t2 kept.
    sim.fork(fork_base, std::slice::from_ref(&t1)).unwrap();
    assert_eq!(observe(&sim, &t1).unwrap_err().code, ErrorCode::StaleEvidence);
    assert!(matches!(sim.tx_status(&t1).unwrap(), Some(SolanaTxStatus::Dropped { .. })));
    assert_eq!((sim.lamports(&d1), sim.lamports(&d2)), (0, 200));
    assert_eq!(sim.lamports(&wallet), SOL - 200 - 5_000);
    // Re-broadcast (its blockhash is still canonical): included again.
    sim.submit(&b1).unwrap();
    let again = sim.advance_slot().unwrap();
    assert!(matches!(observe(&sim, &t1).unwrap(), ChainObservation::Included { state, .. } if state.height == again.slot));
    assert_eq!(sim.lamports(&d1), 100);

    // Forks may not discard finalized slots.
    sim.advance_slots(6).unwrap();
    let fin = sim.finalized_slot();
    let head = sim.head();
    assert_eq!(sim.fork(fin - 1, &[]).unwrap_err().code, ErrorCode::ResourceConflict);
    assert_eq!(sim.fork(head.height, &[]).unwrap_err().code, ErrorCode::InvalidRequest);
    assert_eq!(sim.head(), head);
    sim.fork(fin, &[]).unwrap();
    assert_ne!(sim.head().hash, head.hash);
}

#[test]
fn v0_message_with_lookup_table_end_to_end() {
    let (sim, clock) = default_sim();
    let sk = kp(18);
    let wallet = funded(&sim, &sk, SOL);
    let dest = pk(&kp(19));
    let table = sim.create_lookup_table(vec![[0x01; 32], dest]).unwrap();
    sim.advance_slot().unwrap();
    let t = native_transfer(&sim, &sk, dest, 4_242);
    let ev = sim.evidence(&SolanaEvidenceQuery::processed().lookup_table(table)).unwrap();
    assert!(ev.items.contains_key(&format!("alt:{}", to_base58(&table))));
    // Static: [wallet, system program]; dest loaded writable from the table.
    let msg = Message {
        version: MessageVersion::V0,
        header: MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 },
        account_keys: vec![wallet, SYSTEM_PROGRAM_ID],
        recent_blockhash: sim.latest_blockhash(),
        instructions: vec![CompiledInstruction { program_id_index: 1, accounts: vec![0, 2], data: system_transfer_data(4_242) }],
        address_table_lookups: vec![AddressTableLookup { account_key: table, writable_indexes: vec![1], readonly_indexes: vec![] }],
    };
    let bytes = msg.encode();
    let cand = Candidate {
        candidate_id: CandidateId::unchecked("cand-v0"),
        candidate_revision: 1,
        intent_id: t.intent.intent_id.clone(),
        operation_family_id: OperationFamilyId::unchecked("family-1"),
        chain_profile_id: t.profile.chain_profile_id.clone(),
        adapter_id: AdapterId::unchecked(oic_adapter_solana::ADAPTER_ID),
        adapter_version: oic_adapter_solana::ADAPTER_VERSION.to_string(),
        signing_payloads: SolanaAdapter.signing_payloads(&Bytes(bytes.clone()), &t.party.key).unwrap(),
        native_unsigned_bytes: Bytes(bytes),
        evidence_bundle_hash: evidence_hash(&ev).unwrap(),
        built_at: clock.now(),
    };
    let verified = SolanaAdapter.verify_candidate(&cand, &AuthorizationTarget::Intent(&t.intent), &t.vctx(&ev)).unwrap();
    assert_eq!(verified.decoded.recipient().as_slice(), &dest[..]);
    let sig = SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(sk.sign(cand.signing_payloads[0].message_or_digest.as_slice()).to_bytes().to_vec()) };
    let signed = SolanaAdapter.assemble_signed_transaction(&cand, &t.party.key, &[sig]).unwrap();
    let id = sim.submit(signed.signed_bytes.as_slice()).unwrap();
    let b = sim.advance_slot().unwrap();
    assert_eq!(b.transactions[0].account_keys, vec![wallet, SYSTEM_PROGRAM_ID, dest]);
    assert!(b.transactions[0].success);
    assert_eq!(sim.lamports(&dest), 4_242);
    // No compute-budget instructions: 200_000 default CU at price 0 -> base fee only.
    assert!(matches!(observe(&sim, &id).unwrap(), ChainObservation::Included { fee_paid, .. } if fee_paid == Amount(5_000)));
    // A lookup into a table that does not exist is refused.
    let mut bad = msg.clone();
    bad.address_table_lookups[0].account_key = [0x77; 32];
    assert_eq!(sim.submit(&sign_transaction(&[&sk], &bad.encode())).unwrap_err().code, ErrorCode::InvalidRequest);
}

#[test]
fn conflicting_sources_a30() {
    let (sim, _clock) = default_sim();
    let sk = kp(20);
    funded(&sim, &sk, SOL);
    let id = sim.submit(&transfer_tx(&sim, &sk, &[0x55; 32], 10)).unwrap();
    let sig = parse_tx_id(&id).unwrap();
    let liar = EvidenceSourceId::unchecked("devsim-solana-liar");
    let head = sim.head();
    let lie = TxObservation { slot: head.height, block_hash: head.hash.clone(), commitment: "finalized".into(), success: true, fee: 5_000, err: None };
    sim.set_lie(&liar, sig, lie.clone()).unwrap();
    assert_eq!(sim.set_lie(&EvidenceSourceId::unchecked(SOURCE_ID), sig, lie).unwrap_err().code, ErrorCode::InvalidRequest);
    let q = SolanaEvidenceQuery::processed().signature(sig);
    let honest = sim.evidence(&q).unwrap();
    let lying = sim.evidence_from(&liar, &q).unwrap();
    assert_ne!(evidence_hash(&honest).unwrap(), evidence_hash(&lying).unwrap());
    assert_eq!(lying.sources, vec![liar.clone()]);
    let p = sim.profile();
    assert_eq!(SolanaAdapter.observe(&id, &p, &honest).unwrap_err().code, ErrorCode::StaleEvidence);
    assert!(matches!(SolanaAdapter.observe(&id, &p, &lying).unwrap(), ChainObservation::Finalized { .. }));
    sim.clear_lies(&liar);
    assert_eq!(sim.evidence_from(&liar, &q).unwrap().items, honest.items);
}

fn script(seed: [u8; 32]) -> (Vec<[u8; 32]>, Hash32) {
    let clock = SimClock::new(UnixSeconds(1_800_000_000));
    let sim = SolanaSimulator::new(SolanaSimConfig { finality_depth: 2, ..SolanaSimConfig::with_seed(seed) }, clock.clone()).unwrap();
    let sk = kp(21);
    let a = pk(&sk);
    let mint = sim.create_mint(6, b"det").unwrap();
    let src = sim.create_ata(&a, &mint).unwrap();
    sim.mint_to(&mint, &src, 1_000).unwrap();
    sim.airdrop(&a, SOL).unwrap();
    sim.advance_slot().unwrap();
    clock.advance(1).unwrap();
    let id = sim.submit(&transfer_tx(&sim, &sk, &[0x66; 32], 9)).unwrap();
    sim.advance_slots(2).unwrap();
    sim.fork(1, &[]).unwrap();
    let ev = sim.evidence(&SolanaEvidenceQuery::processed().token_account(src).tx_id(&id).unwrap()).unwrap();
    let hashes = (0..=sim.head().height).map(|s| sim.block(s).unwrap().blockhash).collect();
    (hashes, evidence_hash(&ev).unwrap())
}

#[test]
fn deterministic_for_same_seed_and_script() {
    let a = script([1; 32]);
    assert_eq!(a, script([1; 32]));
    let c = script([2; 32]);
    assert_ne!(a.0, c.0);
    assert_ne!(a.1, c.1);
}

#[test]
fn shareable_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SolanaSimulator>();
    let (sim, _clock) = default_sim();
    let handles: Vec<_> = (0..4u8)
        .map(|i| {
            let s = Arc::clone(&sim);
            std::thread::spawn(move || s.airdrop(&[i + 1; 32], 10).unwrap())
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(sim.advance_slot().unwrap().transactions.len(), 4);
}
