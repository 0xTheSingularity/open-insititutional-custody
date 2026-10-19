//! End-to-end adapter behaviour and RFC 0001 §16 acceptance cases
//! (A02, A04, A21, A22, A23, A24, A37) for the Solana adapter.

mod common;

use common::*;
use oic_adapter_api::*;
use oic_adapter_solana::address::*;
use oic_adapter_solana::evidence::*;
use oic_adapter_solana::instruction::*;
use oic_adapter_solana::message::*;
use oic_adapter_solana::*;
use oic_domain_types::*;
use proptest::prelude::*;

fn code<T: std::fmt::Debug>(r: OicResult<T>) -> ErrorCode {
    r.unwrap_err().code
}

fn detail(fx: &Fx, c: &Candidate) -> SolanaNativeDetail {
    let v = fx.verify(c).unwrap();
    let DecodedOperation::DirectTransfer { native_detail, .. } = &v.decoded;
    oic_canonical_encoding::from_canonical_bytes(native_detail.as_slice()).unwrap()
}

fn sol_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> InstructionSpec {
    InstructionSpec { program_id: SYSTEM_PROGRAM_ID, accounts: vec![(from, true, true), (to, false, true)], data: system_transfer_data(lamports) }
}

fn transfer_checked(fx: &Fx, dest: Pubkey, amount: u64, decimals: u8) -> InstructionSpec {
    InstructionSpec {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![(fx.source_ata(), false, true), (mint(), false, false), (dest, false, true), (fx.wallet_addr, true, false)],
        data: transfer_checked_data(amount, decimals),
    }
}

fn ata_create(fx: &Fx, ata: Pubkey, owner: Pubkey, mint: Pubkey) -> InstructionSpec {
    InstructionSpec {
        program_id: ATA_PROGRAM_ID,
        accounts: vec![
            (fx.wallet_addr, true, true),
            (ata, false, true),
            (owner, false, false),
            (mint, false, false),
            (SYSTEM_PROGRAM_ID, false, false),
            (TOKEN_PROGRAM_ID, false, false),
        ],
        data: ata_create_idempotent_data(),
    }
}

fn compile(fx: &Fx, specs: &[InstructionSpec]) -> Vec<u8> {
    compile_legacy_message(&fx.wallet_addr, specs, BLOCKHASH).unwrap().encode()
}

fn alt_item(addresses: &[Pubkey], deactivation_slot: u64) -> Bytes {
    canon(&AddressLookupTableEvidence {
        addresses: addresses.iter().map(|a| Bytes(a.to_vec())).collect(),
        deactivation_slot,
        last_extended_slot: 900,
    })
}

// --- happy paths -------------------------------------------------------------

#[test]
fn sol_build_verify_sign_round_trip() {
    let fx = native_fixture();
    let c = fx.build();
    let msg = Message::decode(c.native_unsigned_bytes.as_slice()).unwrap();
    assert_eq!(msg.version, MessageVersion::Legacy);
    assert_eq!(msg.account_keys[0], fx.wallet_addr);
    assert_eq!(msg.recent_blockhash, BLOCKHASH);
    assert_eq!(c.signing_payloads.len(), 1);
    let p = &c.signing_payloads[0];
    assert_eq!(p.payload_index, 0);
    assert_eq!(p.scheme_id, SchemeId::Ed25519Pure);
    assert_eq!(p.native_signing_context, "solana-message-legacy");
    assert_eq!(p.message_or_digest, c.native_unsigned_bytes, "pure Ed25519 signs the full message, not a hash");
    assert_eq!(c.evidence_bundle_hash, evidence_hash(&fx.evidence).unwrap());

    let v = fx.verify(&c).unwrap();
    assert_eq!(v.decoded.recipient().as_slice(), dest_owner());
    assert_eq!(v.decoded.sender().as_slice(), fx.wallet_addr);
    assert_eq!(v.decoded.amount(), Amount(AMOUNT));
    assert_eq!(v.decoded.asset(), &AssetKind::Native);
    assert_eq!(v.decoded.max_native_fee(), Amount(LAMPORTS_PER_SIGNATURE as u128));
    let DecodedOperation::DirectTransfer { native_value_base_units, .. } = &v.decoded;
    assert_eq!(*native_value_base_units, Amount(AMOUNT));
    assert_eq!(v.decoded_operation_hash, decoded_operation_hash(&v.decoded).unwrap());
    assert_eq!(v.verifier_build_hash, oic_canonical_encoding::sha256(VERIFIER_BUILD_ID.as_bytes()));
    assert_eq!(
        v.claims.resources,
        vec![NativeResource::SolanaBlockhash {
            network_id: fx.profile.network_id.clone(),
            fee_payer: Bytes(fx.wallet_addr.to_vec()),
            blockhash: Bytes(BLOCKHASH.to_vec())
        }]
    );
    assert_eq!(v.claims.asset_outflows, vec![AssetOutflow { asset_id: fx.asset.asset_id.clone(), amount_base_units: Amount(AMOUNT) }]);
    assert_eq!(
        v.claims.native_fees,
        vec![NativeFee { network_id: fx.profile.network_id.clone(), amount_base_units: Amount(LAMPORTS_PER_SIGNATURE as u128) }]
    );
    assert_eq!(SolanaAdapter.resource_requirements(&v).unwrap(), v.claims);
    assert_eq!(SolanaAdapter.decode_candidate(&c, &fx.vctx()).unwrap(), v.decoded);

    let d = detail(&fx, &c);
    assert_eq!(d.message_version, "legacy");
    assert_eq!(d.instructions, vec![format!("system.transfer({AMOUNT})")]);
    assert_eq!(d.resolved_account_keys.len(), 3);
    assert_eq!(d.message_sha256, oic_canonical_encoding::sha256(c.native_unsigned_bytes.as_slice()));

    let sig = fx.sign(&c);
    let signed = SolanaAdapter.assemble_signed_transaction(&c, &fx.key, std::slice::from_ref(&sig)).unwrap();
    assert_eq!(signed.signed_bytes.as_slice()[0], 1);
    assert_eq!(&signed.signed_bytes.as_slice()[1..65], sig.bytes.as_slice());
    assert_eq!(&signed.signed_bytes.as_slice()[65..], c.native_unsigned_bytes.as_slice());
    assert_eq!(signed.chain_tx_id.as_str(), bs58::encode(sig.bytes.as_slice()).into_string());
    let vs = SolanaAdapter.verify_signed_transaction(&signed, &c, &fx.key).unwrap();
    assert_eq!(vs.verified_signers, vec![Bytes(fx.wallet_addr.to_vec())]);

    let vc = SolanaAdapter.validity_constraints(&c, &fx.evidence).unwrap();
    assert_eq!(vc.expires_at_height, Some(LAST_VALID_HEIGHT));
    assert_eq!(vc.replacement_rule, REPLACEMENT_RULE);
}

#[test]
fn spl_build_with_ata_creation() {
    let fx = spl_fixture();
    let c = fx.build();
    let v = fx.verify(&c).unwrap();
    assert_eq!(v.decoded.asset(), &fx.asset.asset);
    assert_eq!(v.decoded.recipient().as_slice(), dest_owner());
    assert_eq!(v.decoded.amount(), Amount(AMOUNT));
    assert_eq!(v.decoded.max_native_fee(), Amount((LAMPORTS_PER_SIGNATURE + RENT) as u128));
    let DecodedOperation::DirectTransfer { native_value_base_units, .. } = &v.decoded;
    assert_eq!(*native_value_base_units, Amount(RENT as u128), "rent funding is native value, distinct from token amount");
    let d = detail(&fx, &c);
    assert_eq!(d.instructions, vec!["ata.create_idempotent".to_string(), format!("spl_token.transfer_checked({AMOUNT},6)")]);
    assert_eq!(d.created_associated_token_account, Some(Bytes(fx.dest_ata().to_vec())));
    assert_eq!(d.source_token_account, Some(Bytes(fx.source_ata().to_vec())));
    assert_eq!(d.rent_lamports, RENT);
    let signed = SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
    SolanaAdapter.verify_signed_transaction(&signed, &c, &fx.key).unwrap();

    // Missing rent evidence when an ATA must be created.
    let mut norent = spl_fixture();
    norent.evidence.items.remove(KEY_RENT_TOKEN_ACCOUNT);
    assert_eq!(code(SolanaAdapter.build_candidate(&norent.build_ctx())), ErrorCode::StaleEvidence);
    assert_eq!(code(norent.verify(&c)), ErrorCode::StaleEvidence);
}

#[test]
fn spl_build_existing_destination_account() {
    let mut fx = spl_fixture();
    fx.evidence.items.insert(token_account_key(&fx.dest_ata()), canon(&token_account(mint(), dest_owner())));
    let c = fx.build();
    let d = detail(&fx, &c);
    assert_eq!(d.instructions, vec![format!("spl_token.transfer_checked({AMOUNT},6)")]);
    assert_eq!(d.created_associated_token_account, None);
    let v = fx.verify(&c).unwrap();
    assert_eq!(v.decoded.max_native_fee(), Amount(LAMPORTS_PER_SIGNATURE as u128));

    // Destination evidence with a delegate or wrong state is rejected.
    let mut bad = token_account(mint(), dest_owner());
    bad.delegate = Some(Bytes(vec![9; 32]));
    let mut f2 = spl_fixture();
    f2.evidence.items.insert(token_account_key(&f2.dest_ata()), canon(&bad));
    assert_eq!(code(f2.verify(&c)), ErrorCode::UnverifiableTransaction);
    let mut frozen = token_account(mint(), dest_owner());
    frozen.state = TOKEN_ACCOUNT_FROZEN;
    f2.evidence.items.insert(token_account_key(&f2.dest_ata()), canon(&frozen));
    assert_eq!(code(f2.verify(&c)), ErrorCode::UnverifiableTransaction);
}

#[test]
fn spl_non_ata_destination_requires_evidence() {
    let fx = spl_fixture();
    let other_account = [0x44u8; 32];
    let bytes = compile(&fx, &[transfer_checked(&fx, other_account, AMOUNT as u64, 6)]);
    let c = fx.candidate_for(bytes, 2);
    // No evidence and not the derived ATA: owner cannot be established from address shape.
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnverifiableTransaction);
    // Evidence showing the registered owner makes it acceptable.
    let mut f2 = spl_fixture();
    f2.evidence.items.insert(token_account_key(&other_account), canon(&token_account(mint(), dest_owner())));
    let v = f2.verify(&c).unwrap();
    assert_eq!(v.decoded.recipient().as_slice(), dest_owner());
    // Evidence showing a different owner is a recipient mismatch.
    let mut f3 = spl_fixture();
    f3.evidence.items.insert(token_account_key(&other_account), canon(&token_account(mint(), [0x55; 32])));
    assert_eq!(code(f3.verify(&c)), ErrorCode::ScopeMismatch);
}

#[test]
fn spl_source_and_instruction_checks() {
    let fx = spl_fixture();
    // Missing source evidence.
    let c = fx.build();
    let mut f = spl_fixture();
    f.evidence.items.remove(&token_account_key(&fx.source_ata()));
    assert_eq!(code(f.verify(&c)), ErrorCode::StaleEvidence);
    // Source owned by someone else.
    let mut f = spl_fixture();
    f.evidence.items.insert(token_account_key(&fx.source_ata()), canon(&token_account(mint(), [3; 32])));
    assert_eq!(code(f.verify(&c)), ErrorCode::UnverifiableTransaction);
    // Decimals mismatch.
    let c2 = fx.candidate_for(compile(&fx, &[transfer_checked(&fx, fx.dest_ata(), AMOUNT as u64, 9)]), 2);
    assert_eq!(code(fx.verify(&c2)), ErrorCode::UnverifiableTransaction);
    // Extra multisig signer account.
    let mut spec = transfer_checked(&fx, fx.dest_ata(), AMOUNT as u64, 6);
    spec.accounts.push(([0x66; 32], false, false));
    let c3 = fx.candidate_for(compile(&fx, &[spec]), 3);
    assert_eq!(code(fx.verify(&c3)), ErrorCode::UnsupportedCapability);
    // Plain (unchecked) Transfer, tag 3.
    let spec = InstructionSpec {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![(fx.source_ata(), false, true), (fx.dest_ata(), false, true), (fx.wallet_addr, true, false)],
        data: [vec![3u8], (AMOUNT as u64).to_le_bytes().to_vec()].concat(),
    };
    let c4 = fx.candidate_for(compile(&fx, &[spec]), 4);
    let e = fx.verify(&c4).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
    assert!(e.detail.contains("Transfer (unchecked)"), "{}", e.detail);
    // Amount mismatch.
    let c5 = fx.candidate_for(compile(&fx, &[transfer_checked(&fx, fx.dest_ata(), 7, 6)]), 5);
    assert_eq!(code(fx.verify(&c5)), ErrorCode::UnverifiableTransaction);
    // Non-standard behavior.
    let mut ns = spl_fixture();
    ns.asset.behavior = AssetBehaviorProfile::Nonstandard;
    assert_eq!(code(SolanaAdapter.build_candidate(&ns.build_ctx())), ErrorCode::UnsupportedCapability);
    assert_eq!(code(SolanaAdapter.decode_candidate(&c, &ns.vctx())), ErrorCode::UnsupportedCapability);
}

#[test]
fn ata_creation_is_strictly_verified() {
    let fx = spl_fixture();
    let dest = fx.dest_ata();
    let tc = || transfer_checked(&fx, dest, AMOUNT as u64, 6);
    // Valid explicit create (non-idempotent form) is accepted.
    let mut create = ata_create(&fx, dest, dest_owner(), mint());
    create.data = vec![];
    let ok = fx.candidate_for(compile(&fx, &[create, tc()]), 2);
    assert_eq!(detail(&fx, &ok).instructions[0], "ata.create");
    // Owner that is not the destination owner.
    let c = fx.candidate_for(compile(&fx, &[ata_create(&fx, dest, [0x31; 32], mint()), tc()]), 3);
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnverifiableTransaction);
    // Created account is not the transfer destination / not the PDA.
    let c = fx.candidate_for(compile(&fx, &[ata_create(&fx, [0x32; 32], dest_owner(), mint()), tc()]), 4);
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnverifiableTransaction);
    // Create after the transfer.
    let c = fx.candidate_for(compile(&fx, &[tc(), ata_create(&fx, dest, dest_owner(), mint())]), 5);
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnverifiableTransaction);
    // Two creates.
    let c = fx.candidate_for(
        compile(&fx, &[ata_create(&fx, dest, dest_owner(), mint()), ata_create(&fx, dest, dest_owner(), mint()), tc()]),
        6,
    );
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnsupportedCapability);
    // ATA create next to a SOL transfer.
    let nfx = native_fixture();
    let c = nfx.candidate_for(
        compile(&nfx, &[ata_create(&nfx, dest, dest_owner(), mint()), sol_transfer(nfx.wallet_addr, dest_owner(), AMOUNT as u64)]),
        7,
    );
    assert_eq!(code(nfx.verify(&c)), ErrorCode::UnsupportedCapability);
    // Creation with the Token-2022 program.
    let mut t22 = ata_create(&fx, dest, dest_owner(), mint());
    t22.accounts[5].0 = TOKEN_2022_PROGRAM_ID;
    let c = fx.candidate_for(compile(&fx, &[t22, tc()]), 8);
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnsupportedCapability);
}

#[test]
fn compute_budget_feeds_fee_accounting() {
    let mut fx = native_fixture();
    fx.evidence.items.insert(KEY_CU_LIMIT.into(), Bytes(300_000u32.to_le_bytes().to_vec()));
    fx.evidence.items.insert(KEY_CU_PRICE.into(), le64(10_001));
    let c = fx.build();
    let v = fx.verify(&c).unwrap();
    // ceil(300_000 * 10_001 / 1_000_000) = ceil(3000.3) = 3001
    assert_eq!(v.decoded.max_native_fee(), Amount(LAMPORTS_PER_SIGNATURE as u128 + 3001));
    let d = detail(&fx, &c);
    assert_eq!(d.compute_unit_limit, 300_000);
    assert_eq!(d.priority_fee_lamports, 3001);

    // Price without explicit limit uses 200k per non-budget instruction.
    let price = InstructionSpec { program_id: COMPUTE_BUDGET_PROGRAM_ID, accounts: vec![], data: set_compute_unit_price_data(1_000_000) };
    let nfx = native_fixture();
    let c = nfx.candidate_for(compile(&nfx, &[price, sol_transfer(nfx.wallet_addr, dest_owner(), AMOUNT as u64)]), 2);
    assert_eq!(nfx.verify(&c).unwrap().decoded.max_native_fee(), Amount(LAMPORTS_PER_SIGNATURE as u128 + 200_000));

    // Duplicate limit, oversized limit, unsupported compute-budget instruction.
    let lim = |u: u32| InstructionSpec { program_id: COMPUTE_BUDGET_PROGRAM_ID, accounts: vec![], data: set_compute_unit_limit_data(u) };
    let t = || sol_transfer(nfx.wallet_addr, dest_owner(), AMOUNT as u64);
    let c = nfx.candidate_for(compile(&nfx, &[lim(1000), lim(2000), t()]), 3);
    assert_eq!(code(nfx.verify(&c)), ErrorCode::UnsupportedCapability);
    let c = nfx.candidate_for(compile(&nfx, &[lim(1_400_001), t()]), 4);
    assert_eq!(code(nfx.verify(&c)), ErrorCode::UnverifiableTransaction);
    let heap = InstructionSpec { program_id: COMPUTE_BUDGET_PROGRAM_ID, accounts: vec![], data: vec![1, 0, 0, 1, 0] };
    let e = nfx.verify(&nfx.candidate_for(compile(&nfx, &[heap, t()]), 5)).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
    assert!(e.detail.contains("RequestHeapFrame"));

    // Fee above the intent cap.
    let mut tight = native_fixture();
    tight.evidence.items.insert(KEY_CU_PRICE.into(), le64(1_000_000_000));
    assert_eq!(code(SolanaAdapter.build_candidate(&tight.build_ctx())), ErrorCode::BudgetExceeded);
    let mut cap = native_fixture();
    cap.intent.constraints.max_network_fee_base_units = Amount(4_999);
    assert_eq!(code(SolanaAdapter.build_candidate(&cap.build_ctx())), ErrorCode::BudgetExceeded);
    let c = nfx.build();
    assert_eq!(code(SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&cap.intent), &nfx.vctx())), ErrorCode::BudgetExceeded);
}

// --- A02 -------------------------------------------------------------------

#[test]
fn a02_changed_bytes_after_approval_fail() {
    for fx in [native_fixture(), spl_fixture()] {
        let c = fx.build();
        let signed = SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
        for i in 0..c.native_unsigned_bytes.len() {
            // Coordinator mutates the approved candidate bytes.
            let mut mutated = c.clone();
            mutated.native_unsigned_bytes.0[i] ^= 0x01;
            assert!(SolanaAdapter.verify_signed_transaction(&signed, &mutated, &fx.key).is_err(), "candidate byte {i}");
            assert!(fx.verify(&mutated).is_err(), "candidate byte {i}");
            // Coordinator mutates the message inside the signed transaction.
            let mut forged = signed.clone();
            forged.signed_bytes.0[65 + i] ^= 0x01;
            assert!(SolanaAdapter.verify_signed_transaction(&forged, &c, &fx.key).is_err(), "signed byte {i}");
        }
        // Signature by another key.
        let other = signing_key(9);
        let sig2 = sign_message(&other, c.native_unsigned_bytes.as_slice());
        assert_eq!(code(SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[sig2])), ErrorCode::InvalidSignature);
        // Wrong chain_tx_id.
        let mut wrong_id = signed.clone();
        wrong_id.chain_tx_id = ChainTxId::unchecked(bs58::encode([1u8; 64]).into_string());
        assert!(SolanaAdapter.verify_signed_transaction(&wrong_id, &c, &fx.key).is_err());
    }
}

#[test]
fn tampered_payload_array_rejected() {
    let fx = native_fixture();
    let mut c = fx.build();
    c.signing_payloads[0].native_signing_context = "solana-message-v0".into();
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnverifiableTransaction);
    let mut c = fx.build();
    c.signing_payloads[0].message_or_digest = Bytes(oic_canonical_encoding::sha256(c.native_unsigned_bytes.as_slice()).0.to_vec());
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnverifiableTransaction);
    let mut c = fx.build();
    c.adapter_version = "0.0.0".into();
    assert_eq!(code(fx.verify(&c)), ErrorCode::ScopeMismatch);
}

#[test]
fn signature_shape_checks() {
    let fx = native_fixture();
    let c = fx.build();
    let sig = fx.sign(&c);
    let mut short = sig.clone();
    short.bytes.0.pop();
    assert_eq!(code(SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[short])), ErrorCode::InvalidSignature);
    let mut scheme = sig.clone();
    scheme.scheme = SchemeId::EcdsaSecp256k1Keccak256Prehashed;
    assert_eq!(code(SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[scheme])), ErrorCode::InvalidSignature);
    assert!(SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[sig.clone(), sig.clone()]).is_err());
    assert!(SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[]).is_err());
    // Non-canonical S (S + L) is rejected by verify_strict.
    let mut s = sig.bytes.0.clone();
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = s[32 + i] as u16 + l[i] as u16 + carry;
        s[32 + i] = v as u8;
        carry = v >> 8;
    }
    let bad = SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(s) };
    assert_eq!(code(SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[bad])), ErrorCode::InvalidSignature);
    // Key with a non-Ed25519 scheme.
    let mut k = fx.key.clone();
    k.scheme = SchemeId::EcdsaSecp256k1Keccak256Prehashed;
    assert_eq!(code(SolanaAdapter.assemble_signed_transaction(&c, &k, &[sig])), ErrorCode::UnsupportedCapability);
}

// --- A04 -------------------------------------------------------------------

#[test]
fn a04_same_symbol_decimals_different_mint_rejected() {
    let real = spl_fixture();
    // Look-alike asset: same asset id, symbol, and decimals; different mint.
    let fake = fixture_with(spl_asset([0xbb; 32], TOKEN_PROGRAM_ID), 1);
    let c = fake.build();
    let e = real.verify(&c).unwrap_err();
    assert_eq!(e.code, ErrorCode::ScopeMismatch, "{e:?}");
    let e = SolanaAdapter.decode_candidate(&c, &real.vctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::ScopeMismatch, "{e:?}");
    // SOL candidate against an SPL registry entry and vice versa.
    let sol = native_fixture().build();
    assert_eq!(code(real.verify(&sol)), ErrorCode::ScopeMismatch);
    assert_eq!(code(native_fixture().verify(&real.build())), ErrorCode::ScopeMismatch);
}

// --- A21 -------------------------------------------------------------------

/// v0 SOL transfer whose destination comes from lookup table `table` at index 0 (writable).
fn v0_sol_transfer(fx: &Fx, table: Pubkey) -> Message {
    Message {
        version: MessageVersion::V0,
        header: MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 },
        account_keys: vec![fx.wallet_addr, SYSTEM_PROGRAM_ID],
        recent_blockhash: BLOCKHASH,
        instructions: vec![CompiledInstruction { program_id_index: 1, accounts: vec![0, 2], data: system_transfer_data(AMOUNT as u64) }],
        address_table_lookups: vec![AddressTableLookup { account_key: table, writable_indexes: vec![0], readonly_indexes: vec![] }],
    }
}

#[test]
fn a21_lookup_tables_fully_resolved() {
    let table = [0xa1u8; 32];
    let mut fx = native_fixture();
    let c = fx.candidate_for(v0_sol_transfer(&fx, table).encode(), 2);
    assert_eq!(c.signing_payloads[0].native_signing_context, "solana-message-v0");

    // Table absent from evidence -> StaleEvidence.
    assert_eq!(code(fx.verify(&c)), ErrorCode::StaleEvidence);

    // Table resolves to the registered destination -> accepted, resolution bound into detail.
    fx.evidence.items.insert(alt_key(&table), alt_item(&[dest_owner(), [0x99; 32]], u64::MAX));
    let v = fx.verify(&c).unwrap();
    assert_eq!(v.decoded.recipient().as_slice(), dest_owner());
    let d = detail(&fx, &c);
    assert_eq!(d.message_version, "v0");
    assert_eq!(d.resolved_account_keys[2], Bytes(dest_owner().to_vec()));
    assert_eq!(d.lookup_tables.len(), 1);
    assert_eq!(d.lookup_tables[0].table, Bytes(table.to_vec()));
    assert_eq!(d.lookup_tables[0].resolved_writable, vec![Bytes(dest_owner().to_vec())]);
    let signed = SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
    SolanaAdapter.verify_signed_transaction(&signed, &c, &fx.key).unwrap();

    // Same static bytes, table resolves to a hidden attacker account -> rejection.
    let mut evil = native_fixture();
    evil.evidence.items.insert(alt_key(&table), alt_item(&[[0x66; 32]], u64::MAX));
    assert_eq!(code(evil.verify(&c)), ErrorCode::ScopeMismatch);

    // Index out of range.
    let mut short = native_fixture();
    short.evidence.items.insert(alt_key(&table), alt_item(&[], u64::MAX));
    assert_eq!(code(short.verify(&c)), ErrorCode::UnverifiableTransaction);

    // Deactivated table.
    let mut deact = native_fixture();
    deact.evidence.items.insert(alt_key(&table), alt_item(&[dest_owner()], 500));
    assert_eq!(code(deact.verify(&c)), ErrorCode::UnverifiableTransaction);

    // Malformed table evidence.
    let mut junk = native_fixture();
    junk.evidence.items.insert(alt_key(&table), Bytes(vec![0xff]));
    assert_eq!(code(junk.verify(&c)), ErrorCode::StaleEvidence);

    // Lookup re-introducing a static key (the wallet) -> duplicate rejection.
    let mut dup = native_fixture();
    dup.evidence.items.insert(alt_key(&table), alt_item(&[fx.wallet_addr], u64::MAX));
    assert_eq!(code(dup.verify(&c)), ErrorCode::UnverifiableTransaction);

    // v0 not enabled by the profile.
    let mut legacy_only = native_fixture();
    legacy_only.profile.accepted_versions = vec![VERSION_LEGACY.into()];
    legacy_only.evidence.items.insert(alt_key(&table), alt_item(&[dest_owner()], u64::MAX));
    assert_eq!(code(legacy_only.verify(&c)), ErrorCode::UnsupportedCapability);
}

#[test]
fn a21_lookup_account_as_signer_rejected() {
    let table = [0xa2u8; 32];
    let mut fx = native_fixture();
    let attacker = [0x67u8; 32];
    // `from` (must sign) is a lookup-resolved account.
    let m = Message {
        version: MessageVersion::V0,
        header: MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 },
        account_keys: vec![fx.wallet_addr, SYSTEM_PROGRAM_ID],
        recent_blockhash: BLOCKHASH,
        instructions: vec![CompiledInstruction { program_id_index: 1, accounts: vec![2, 3], data: system_transfer_data(AMOUNT as u64) }],
        address_table_lookups: vec![AddressTableLookup { account_key: table, writable_indexes: vec![0, 1], readonly_indexes: vec![] }],
    };
    fx.evidence.items.insert(alt_key(&table), alt_item(&[attacker, dest_owner()], u64::MAX));
    let c = fx.candidate_for(m.encode(), 2);
    let e = fx.verify(&c).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnverifiableTransaction);
    assert!(e.detail.contains("lookup-resolved accounts can never be signers"), "{}", e.detail);

    // SPL: TransferChecked authority taken from a lookup table.
    let mut sfx = spl_fixture();
    let m = Message {
        version: MessageVersion::V0,
        header: MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 2 },
        account_keys: vec![sfx.wallet_addr, sfx.source_ata(), sfx.dest_ata(), mint(), TOKEN_PROGRAM_ID],
        recent_blockhash: BLOCKHASH,
        instructions: vec![CompiledInstruction { program_id_index: 4, accounts: vec![1, 3, 2, 5], data: transfer_checked_data(AMOUNT as u64, 6) }],
        address_table_lookups: vec![AddressTableLookup { account_key: table, writable_indexes: vec![], readonly_indexes: vec![0] }],
    };
    sfx.evidence.items.insert(alt_key(&table), alt_item(&[attacker], u64::MAX));
    let c = sfx.candidate_for(m.encode(), 3);
    let e = sfx.verify(&c).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnverifiableTransaction);
    assert!(e.detail.contains("signer"), "{}", e.detail);
}

// --- A22 -------------------------------------------------------------------

#[test]
fn a22_extra_authority_close_or_memo_rejected() {
    let fx = spl_fixture();
    let tc = transfer_checked(&fx, fx.dest_ata(), AMOUNT as u64, 6);
    let set_authority = InstructionSpec {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![(fx.source_ata(), false, true), (fx.wallet_addr, true, false)],
        data: [vec![6u8, 2, 1], vec![0x66; 32]].concat(),
    };
    let close = InstructionSpec {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![(fx.source_ata(), false, true), ([0x66; 32], false, true), (fx.wallet_addr, true, false)],
        data: vec![9],
    };
    let approve = InstructionSpec {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![(fx.source_ata(), false, true), ([0x66; 32], false, false), (fx.wallet_addr, true, false)],
        data: [vec![4u8], 5u64.to_le_bytes().to_vec()].concat(),
    };
    let memo = InstructionSpec { program_id: MEMO_V2_PROGRAM_ID, accounts: vec![(fx.wallet_addr, true, false)], data: b"invoice 42".to_vec() };
    let unknown = InstructionSpec { program_id: [0x42; 32], accounts: vec![], data: vec![1, 2, 3] };
    for (extra, name) in [(set_authority, "SetAuthority"), (close, "CloseAccount"), (approve, "Approve"), (memo, "Memo program"), (unknown, "unknown program")] {
        for order in [0, 1] {
            let specs = if order == 0 {
                vec![clone_spec(&tc), clone_spec(&extra)]
            } else {
                vec![clone_spec(&extra), clone_spec(&tc)]
            };
            let c = fx.candidate_for(compile(&fx, &specs), 2);
            let e = fx.verify(&c).unwrap_err();
            assert_eq!(e.code, ErrorCode::UnsupportedCapability, "{name}: {e:?}");
            assert!(e.detail.contains(name), "{name}: {}", e.detail);
            assert_eq!(code(SolanaAdapter.decode_candidate(&c, &fx.vctx())), ErrorCode::UnsupportedCapability);
        }
    }

    // SOL transfer plus System Assign / durable nonce advance / a second transfer.
    let nfx = native_fixture();
    let t = || sol_transfer(nfx.wallet_addr, dest_owner(), AMOUNT as u64);
    let assign = InstructionSpec {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![(nfx.wallet_addr, true, true)],
        data: [1u32.to_le_bytes().to_vec(), vec![0x42; 32]].concat(),
    };
    let advance = InstructionSpec {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![([0x70; 32], false, true), ([0x71; 32], false, false), (nfx.wallet_addr, true, false)],
        data: 4u32.to_le_bytes().to_vec(),
    };
    for (extra, name) in [(assign, "Assign"), (advance, "AdvanceNonceAccount")] {
        let c = nfx.candidate_for(compile(&nfx, &[extra, t()]), 3);
        let e = nfx.verify(&c).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnsupportedCapability);
        assert!(e.detail.contains(name), "{}", e.detail);
    }
    let c = nfx.candidate_for(compile(&nfx, &[t(), sol_transfer(nfx.wallet_addr, [0x72; 32], 1)]), 4);
    assert_eq!(code(nfx.verify(&c)), ErrorCode::UnsupportedCapability);
    // No value-moving instruction at all.
    let lim = InstructionSpec { program_id: COMPUTE_BUDGET_PROGRAM_ID, accounts: vec![], data: set_compute_unit_limit_data(1) };
    let c = nfx.candidate_for(compile(&nfx, &[lim]), 5);
    assert_eq!(code(nfx.verify(&c)), ErrorCode::UnsupportedCapability);
}

fn clone_spec(s: &InstructionSpec) -> InstructionSpec {
    InstructionSpec { program_id: s.program_id, accounts: s.accounts.clone(), data: s.data.clone() }
}

#[test]
fn multi_signer_and_wrong_fee_payer_rejected() {
    let fx = native_fixture();
    // Second signer.
    let mut t = sol_transfer(fx.wallet_addr, dest_owner(), AMOUNT as u64);
    t.accounts.push(([0x73; 32], true, false));
    let c = fx.candidate_for(compile(&fx, &[t]), 2);
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnsupportedCapability);
    // Fee payer is not the wallet.
    let other = [0x74u8; 32];
    let bytes = compile_legacy_message(&other, &[sol_transfer(other, dest_owner(), AMOUNT as u64)], BLOCKHASH).unwrap().encode();
    let c = fx.candidate_for(bytes, 3);
    assert_eq!(code(fx.verify(&c)), ErrorCode::ScopeMismatch);
    // System transfer whose `to` is readonly.
    let mut t = sol_transfer(fx.wallet_addr, dest_owner(), AMOUNT as u64);
    t.accounts[1].2 = false;
    let c = fx.candidate_for(compile(&fx, &[t]), 4);
    assert_eq!(code(fx.verify(&c)), ErrorCode::UnverifiableTransaction);
}

// --- A23 -------------------------------------------------------------------

fn tx_obs(success: bool, commitment: &str) -> Bytes {
    canon(&TxObservation {
        slot: 1_010,
        block_hash: Bytes(vec![0x5a; 32]),
        commitment: commitment.into(),
        success,
        fee: 5_000,
        err: if success { None } else { Some("InstructionError(0, Custom(1))".into()) },
    })
}

#[test]
fn a23_fresh_blockhash_retry_needs_invalidation_evidence() {
    let fx1 = native_fixture();
    let c1 = fx1.build();
    let fresh = [0xccu8; 32];
    let mut fx2 = native_fixture();
    fx2.evidence.items.insert(KEY_RECENT_BLOCKHASH.into(), Bytes(fresh.to_vec()));
    fx2.evidence.items.insert(KEY_BLOCKHASH_LAST_VALID_HEIGHT.into(), le64(1_300));
    let mut ctx2 = fx2.build_ctx();
    ctx2.candidate_revision = 2;
    let c2 = SolanaAdapter.build_candidate(&ctx2).unwrap();

    // A different candidate with a different blockhash resource: not mutually exclusive.
    assert_ne!(c1.native_unsigned_bytes, c2.native_unsigned_bytes);
    let r1 = fx1.verify(&c1).unwrap().claims.resources;
    let r2 = SolanaAdapter.verify_candidate(&c2, &AuthorizationTarget::Intent(&fx2.intent), &fx2.vctx()).unwrap().claims.resources;
    assert_ne!(r1, r2);
    assert!(matches!(&r2[0], NativeResource::SolanaBlockhash { blockhash, .. } if blockhash.as_slice() == fresh));

    let s1 = SolanaAdapter.assemble_signed_transaction(&c1, &fx1.key, &[fx1.sign(&c1)]).unwrap();
    let s2 = SolanaAdapter.assemble_signed_transaction(&c2, &fx2.key, &[fx2.sign(&c2)]).unwrap();
    let sig1: [u8; 64] = s1.signed_bytes.as_slice()[1..65].try_into().unwrap();
    let fam = c1.operation_family_id.clone();
    let cands = [c1.clone(), c2.clone()];

    let mut ev = fx1.evidence.clone();
    ev.items.insert(last_valid_height_key(&BLOCKHASH), le64(LAST_VALID_HEIGHT));
    ev.items.insert(last_valid_height_key(&fresh), le64(1_300));
    ev.items.insert(signed_tx_key("cand-1", 1), s1.signed_bytes.clone());
    ev.items.insert(signed_tx_key("cand-1", 2), s2.signed_bytes.clone());

    // Before last_valid_height (timeout only): Unknown.
    assert_eq!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &ev).unwrap(), InvalidationEvidence::Unknown);
    // First blockhash expired + depth, second not yet: still Unknown.
    ev.state.height = LAST_VALID_HEIGHT + FINALITY_DEPTH;
    assert_eq!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &ev).unwrap(), InvalidationEvidence::Unknown);
    // Exactly at last_valid + depth - 1 for the second: Unknown.
    ev.state.height = 1_300 + FINALITY_DEPTH - 1;
    assert_eq!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &ev).unwrap(), InvalidationEvidence::Unknown);
    // Both expired at finality: Definitive.
    ev.state.height = 1_300 + FINALITY_DEPTH;
    assert!(matches!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &ev).unwrap(), InvalidationEvidence::Definitive { .. }));

    // A failed landing does not prevent invalidation of the payment.
    let mut failed = ev.clone();
    failed.items.insert(tx_key(&sig1), tx_obs(false, "finalized"));
    assert!(matches!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &failed).unwrap(), InvalidationEvidence::Definitive { .. }));
    // The earlier transaction landed successfully: not an invalidation.
    let mut landed = ev.clone();
    landed.items.insert(tx_key(&sig1), tx_obs(true, "finalized"));
    assert_eq!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &landed).unwrap(), InvalidationEvidence::Unknown);
    // Evidence not at finality commitment.
    let mut conf = ev.clone();
    conf.state.commitment = "confirmed".into();
    assert_eq!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &conf).unwrap(), InvalidationEvidence::Unknown);
    // A possibly-issued candidate whose signature is unknown.
    let mut unaccounted = ev.clone();
    unaccounted.items.remove(&signed_tx_key("cand-1", 2));
    assert_eq!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &unaccounted).unwrap(), InvalidationEvidence::Unknown);
    // No last-valid-height evidence for a family blockhash.
    let mut nolvh = ev.clone();
    nolvh.items.remove(&last_valid_height_key(&fresh));
    assert_eq!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &nolvh).unwrap(), InvalidationEvidence::Unknown);
    // Forged signed_tx evidence.
    let mut forged = ev.clone();
    let mut b = s1.signed_bytes.0.clone();
    b[1] ^= 1;
    forged.items.insert(signed_tx_key("cand-1", 1), Bytes(b));
    assert!(SolanaAdapter.prove_invalidation(&fam, &cands, &fx1.profile, &forged).is_err());
    // Candidate from another family.
    let other = OperationFamilyId::unchecked("family-2");
    assert!(SolanaAdapter.prove_invalidation(&other, &cands, &fx1.profile, &ev).is_err());
}

// --- A24 -------------------------------------------------------------------

#[test]
fn a24_token_2022_rejected() {
    let fx = fixture_with(spl_asset(mint(), TOKEN_2022_PROGRAM_ID), 1);
    let e = SolanaAdapter.build_candidate(&fx.build_ctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
    assert!(e.detail.contains("Token-2022"));

    // A Token-2022 TransferChecked instruction is unsupported even against the original-program registry.
    let real = spl_fixture();
    let mut spec = transfer_checked(&real, real.dest_ata(), AMOUNT as u64, 6);
    spec.program_id = TOKEN_2022_PROGRAM_ID;
    let c = real.candidate_for(compile(&real, &[spec]), 2);
    let e = real.verify(&c).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
    assert!(e.detail.contains("Token-2022"));
    // ... and against a Token-2022 registry entry.
    assert_eq!(code(SolanaAdapter.decode_candidate(&c, &fx.vctx())), ErrorCode::UnsupportedCapability);
}

// --- template / scope / evidence -----------------------------------------------

fn template(fx: &Fx, fillable: Vec<FillableField>) -> BoundedTransferTemplate {
    BoundedTransferTemplate {
        chain_wallet_id: fx.wallet.chain_wallet_id.clone(),
        network_id: fx.profile.network_id.clone(),
        asset_id: fx.asset.asset_id.clone(),
        amount_base_units: Amount(AMOUNT),
        destination_id: fx.destination.destination_id.clone(),
        destination_version: fx.destination.version,
        destination_address: fx.destination.address.clone(),
        max_native_fee_base_units: Amount(10_000_000),
        maximum_successful_payments: 1,
        fillable,
    }
}

#[test]
fn template_requires_fillable_blockhash() {
    let fx = native_fixture();
    let c = fx.build();
    let ok = template(&fx, vec![FillableField::SolanaRecentBlockhash]);
    SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&ok), &fx.vctx()).unwrap();
    let fixed = template(&fx, vec![]);
    assert_eq!(code(SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&fixed), &fx.vctx())), ErrorCode::UnverifiableTransaction);
    let evm = template(&fx, vec![FillableField::SolanaRecentBlockhash, FillableField::EvmNonce]);
    assert_eq!(code(SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&evm), &fx.vctx())), ErrorCode::ScopeMismatch);
    let mut wrong = ok.clone();
    wrong.destination_address = Bytes(vec![1; 32]);
    assert_eq!(code(SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&wrong), &fx.vctx())), ErrorCode::ScopeMismatch);
    let mut tight = ok.clone();
    tight.max_native_fee_base_units = Amount(1);
    assert_eq!(code(SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&tight), &fx.vctx())), ErrorCode::BudgetExceeded);
    let mut amt = ok;
    amt.amount_base_units = Amount(AMOUNT + 1);
    assert_eq!(code(SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&amt), &fx.vctx())), ErrorCode::UnverifiableTransaction);
    // Even under a template, the blockhash must match evidence.
    let mut f2 = native_fixture();
    f2.evidence.items.insert(KEY_RECENT_BLOCKHASH.into(), Bytes(vec![0xcc; 32]));
    let t = template(&f2, vec![FillableField::SolanaRecentBlockhash]);
    assert_eq!(code(SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&t), &f2.vctx())), ErrorCode::UnverifiableTransaction);
}

#[test]
fn scope_and_evidence_checks() {
    let fx = native_fixture();
    let c = fx.build();

    let mut g = native_fixture();
    g.evidence.items.insert(KEY_GENESIS_HASH.into(), Bytes(vec![0x01; 32]));
    assert_eq!(code(g.verify(&c)), ErrorCode::ScopeMismatch);
    assert_eq!(code(SolanaAdapter.identify_network(&g.profile, &g.evidence)), ErrorCode::ScopeMismatch);
    let mut g2 = native_fixture();
    g2.evidence.items.remove(KEY_GENESIS_HASH);
    assert_eq!(code(g2.verify(&c)), ErrorCode::StaleEvidence);

    let mut w = native_fixture();
    w.wallet.address = Bytes(vec![0x12; 32]);
    assert_eq!(code(w.verify(&c)), ErrorCode::ScopeMismatch);

    let mut d = native_fixture();
    d.destination.version = 4;
    assert_eq!(code(d.verify(&c)), ErrorCode::ScopeMismatch);
    let mut d2 = native_fixture();
    d2.destination.address = Bytes(vec![0x13; 32]);
    assert_eq!(code(d2.verify(&c)), ErrorCode::ScopeMismatch);

    let mut e = native_fixture();
    e.evidence.chain_profile_id = ChainProfileId::unchecked("solana-mainnet-v1");
    assert_eq!(code(e.verify(&c)), ErrorCode::ScopeMismatch);

    let mut bh = native_fixture();
    bh.evidence.items.insert(KEY_RECENT_BLOCKHASH.into(), Bytes(vec![0xcc; 32]));
    assert_eq!(code(bh.verify(&c)), ErrorCode::UnverifiableTransaction);
    let mut exp = native_fixture();
    exp.evidence.state.height = LAST_VALID_HEIGHT + 1;
    assert_eq!(code(exp.verify(&c)), ErrorCode::StaleEvidence);
    let mut nolvh = native_fixture();
    nolvh.evidence.items.remove(KEY_BLOCKHASH_LAST_VALID_HEIGHT);
    assert_eq!(code(nolvh.verify(&c)), ErrorCode::StaleEvidence);
    let mut nolps = native_fixture();
    nolps.evidence.items.remove(KEY_LAMPORTS_PER_SIGNATURE);
    assert_eq!(code(nolps.verify(&c)), ErrorCode::StaleEvidence);

    let mut v = native_fixture();
    v.profile.accepted_versions.push("v1".into());
    assert_eq!(code(SolanaAdapter.decode_candidate(&c, &v.vctx())), ErrorCode::UnsupportedCapability);
    let mut lo = native_fixture();
    lo.profile.accepted_versions = vec![VERSION_V0.into()];
    assert_eq!(code(SolanaAdapter.build_candidate(&lo.build_ctx())), ErrorCode::UnsupportedCapability);

    let mut amt = native_fixture();
    let IntentOperation::AssetTransfer { amount_base_units, .. } = &mut amt.intent.operation;
    *amount_base_units = Amount(2);
    assert_eq!(code(SolanaAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&amt.intent), &fx.vctx())), ErrorCode::UnverifiableTransaction);

    // Message version 1 prefix is an unsupported capability, not a parse excursion.
    let mut b = c.native_unsigned_bytes.0.clone();
    b.insert(0, 0x81);
    assert_eq!(code(SolanaAdapter.decode_candidate(&fx.candidate_for(b, 2), &fx.vctx())), ErrorCode::UnsupportedCapability);
}

#[test]
fn observe_maps_lifecycle() {
    let fx = native_fixture();
    let c = fx.build();
    let signed = SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
    let sig: [u8; 64] = signed.signed_bytes.as_slice()[1..65].try_into().unwrap();
    let mut ev = fx.evidence.clone();
    assert_eq!(code(SolanaAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev)), ErrorCode::StaleEvidence);
    for commitment in ["processed", "confirmed"] {
        ev.items.insert(tx_key(&sig), tx_obs(true, commitment));
        match SolanaAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev).unwrap() {
            ChainObservation::Included { execution_success, fee_paid, state, .. } => {
                assert!(execution_success);
                assert_eq!(fee_paid, Amount(5_000));
                assert_eq!(state.height, 1_010);
                assert_eq!(state.commitment, commitment);
            }
            o => panic!("{o:?}"),
        }
    }
    ev.items.insert(tx_key(&sig), tx_obs(false, "finalized"));
    match SolanaAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev).unwrap() {
        ChainObservation::Finalized { execution_success, .. } => assert!(!execution_success),
        o => panic!("{o:?}"),
    }
    // A profile that finalizes at `confirmed`.
    let mut p = fx.profile.clone();
    p.finality_commitment = "confirmed".into();
    ev.items.insert(tx_key(&sig), tx_obs(true, "confirmed"));
    let mut ev2 = ev.clone();
    ev2.chain_profile_id = p.chain_profile_id.clone();
    assert!(matches!(SolanaAdapter.observe(&signed.chain_tx_id, &p, &ev2).unwrap(), ChainObservation::Finalized { .. }));
    // Malformed / inconsistent observations.
    ev.items.insert(tx_key(&sig), Bytes(vec![0xff, 0x00]));
    assert_eq!(code(SolanaAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev)), ErrorCode::StaleEvidence);
    ev.items.insert(tx_key(&sig), tx_obs(true, "rooted"));
    assert_eq!(code(SolanaAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev)), ErrorCode::StaleEvidence);
    let inconsistent = canon(&TxObservation {
        slot: 1,
        block_hash: Bytes(vec![1; 32]),
        commitment: "finalized".into(),
        success: true,
        fee: 1,
        err: Some("x".into()),
    });
    ev.items.insert(tx_key(&sig), inconsistent);
    assert_eq!(code(SolanaAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev)), ErrorCode::StaleEvidence);
    assert_eq!(code(SolanaAdapter.observe(&ChainTxId::unchecked("0xabc"), &fx.profile, &ev)), ErrorCode::InvalidRequest);
}

#[test]
fn manifest_identify_derive() {
    let fx = native_fixture();
    let m = SolanaAdapter.manifest();
    assert_eq!(m.adapter_id.as_str(), "solana");
    assert_eq!(m.adapter_version, ADAPTER_VERSION);
    assert_eq!(m.verifier_build_hash, verifier_build_hash());
    assert_eq!(m.signing_schemes, vec![SchemeId::Ed25519Pure]);
    assert_eq!(m.accepted_transaction_versions, vec!["legacy".to_string(), "v0".to_string()]);
    assert_eq!(
        m.known_external_authorities,
        vec!["mint authority", "freeze authority", "token-2022 permanent delegate (unsupported)", "transfer hook (unsupported)"]
    );
    let ctx = SolanaAdapter.identify_network(&fx.profile, &fx.evidence).unwrap();
    assert_eq!(ctx.chain_profile_hash, fx.profile.hash().unwrap());
    let (addr, disp) = SolanaAdapter.derive_address(&fx.key.public_key).unwrap();
    assert_eq!(addr.as_slice(), fx.wallet_addr);
    assert_eq!(disp, fx.wallet.address_display);
    assert_eq!(from_base58(&disp).unwrap(), fx.wallet_addr);
    let bad = PublicKey { scheme: SchemeId::EcdsaSecp256k1Keccak256Prehashed, bytes: Bytes(vec![2; 33]) };
    assert_eq!(code(SolanaAdapter.derive_address(&bad)), ErrorCode::UnsupportedCapability);
    let short = PublicKey { scheme: SchemeId::Ed25519Pure, bytes: Bytes(vec![2; 31]) };
    assert!(SolanaAdapter.derive_address(&short).is_err());
    let mut p = fx.profile.clone();
    p.network_binding = Bytes(vec![1; 8]);
    assert_eq!(code(SolanaAdapter.identify_network(&p, &fx.evidence)), ErrorCode::ScopeMismatch);
}

// --- A37 -------------------------------------------------------------------

#[test]
fn a37_oversized_rejected() {
    let fx = native_fixture();
    // tx = 65 + (139 + dlen); 1232 is the packet limit.
    let mk = |dlen: usize| Message {
        version: MessageVersion::Legacy,
        header: MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 },
        account_keys: vec![fx.wallet_addr, [0x11; 32], [0x12; 32]],
        recent_blockhash: BLOCKHASH,
        instructions: vec![CompiledInstruction { program_id_index: 2, accounts: vec![0, 1], data: vec![0xaa; dlen] }],
        address_table_lookups: vec![],
    };
    let at_limit = mk(1028).encode();
    assert_eq!(at_limit.len() + 65, 1232);
    Message::decode(&at_limit).unwrap();
    let over = mk(1029).encode();
    assert_eq!(code(Message::decode(&over)), ErrorCode::UnverifiableTransaction);
    assert!(Transaction::decode(&Transaction::encode(&[[0; 64]], &over)).is_err());
    assert_eq!(code(SolanaAdapter.decode_candidate(&fx.candidate_for(over, 2), &fx.vctx())), ErrorCode::UnverifiableTransaction);
    // 1 MiB of garbage.
    let garbage: Vec<u8> = (0..1024 * 1024).map(|i| (i * 31 % 251) as u8).collect();
    assert!(Message::decode(&garbage).is_err());
    assert!(Transaction::decode(&garbage).is_err());
    // More than 64 accounts.
    let mut many = mk(1);
    many.account_keys = (0..65u8).map(|i| [i.wrapping_add(1); 32]).collect();
    many.header.num_readonly_unsigned_accounts = 1;
    assert!(Message::decode(&many.encode()).is_err());
    // Lookups pushing the total over 64.
    let mut lk = mk(1);
    lk.version = MessageVersion::V0;
    lk.address_table_lookups = vec![AddressTableLookup { account_key: [0x21; 32], writable_indexes: (0..62).collect(), readonly_indexes: vec![] }];
    assert!(Message::decode(&lk.encode()).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn a37_arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = shortvec::decode(&bytes);
        let _ = Message::decode(&bytes);
        let _ = Transaction::decode(&bytes);
        let mut v0 = vec![0x80];
        v0.extend_from_slice(&bytes);
        let _ = Message::decode(&v0);
        let _ = Transaction::decode(&v0);
        let _ = oic_canonical_encoding::from_canonical_bytes::<AddressLookupTableEvidence>(&bytes);
        let _ = oic_canonical_encoding::from_canonical_bytes::<TokenAccountEvidence>(&bytes);
        let _ = oic_canonical_encoding::from_canonical_bytes::<TxObservation>(&bytes);
    }

    #[test]
    fn a37_arbitrary_candidate_bytes_never_panic_in_adapter(bytes in prop::collection::vec(any::<u8>(), 0..600), prefix in prop::sample::select(vec![0x01u8, 0x80, 0x81, 0xff, 0x00])) {
        let fx = spl_fixture();
        let mut b = vec![prefix];
        b.extend_from_slice(&bytes);
        let c = fx.candidate_for(b.clone(), 2);
        let _ = SolanaAdapter.decode_candidate(&c, &fx.vctx());
        let _ = fx.verify(&c);
        let _ = SolanaAdapter.signing_payloads(&Bytes(b.clone()), &fx.key);
        let _ = SolanaAdapter.validity_constraints(&c, &fx.evidence);
        let _ = SolanaAdapter.prove_invalidation(&c.operation_family_id, std::slice::from_ref(&c), &fx.profile, &fx.evidence);
        let signed = SignedTransaction {
            candidate_id: c.candidate_id.clone(),
            candidate_revision: c.candidate_revision,
            signed_bytes: Bytes(b),
            chain_tx_id: ChainTxId::unchecked("1"),
        };
        let _ = SolanaAdapter.verify_signed_transaction(&signed, &c, &fx.key);
    }

    #[test]
    fn mutated_valid_message_never_panics(pos in 0usize..400, val in any::<u8>(), v0 in any::<bool>()) {
        let mut fx = spl_fixture();
        let table = [0xa1u8; 32];
        fx.evidence.items.insert(alt_key(&table), alt_item(&[dest_owner(), fx.dest_ata()], u64::MAX));
        let mut bytes = if v0 { v0_sol_transfer(&fx, table).encode() } else { fx.build().native_unsigned_bytes.0 };
        let i = pos % bytes.len();
        bytes[i] = val;
        let c = fx.candidate_for(bytes.clone(), 2);
        let _ = fx.verify(&c);
        let _ = Transaction::decode(&Transaction::encode(&[[7; 64]], &bytes));
    }
}
