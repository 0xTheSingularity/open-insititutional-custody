//! Differential tests (RFC 0001 §16): our hand-written message/transaction
//! codec, instruction encoders, PDA derivation, and Ed25519 handling versus the
//! independent Solana SDK crates (`solana-message`, `solana-transaction`,
//! `solana-keypair`, `solana-system-interface`, `solana-compute-budget-interface`,
//! `spl-token-interface`, `spl-associated-token-account-interface`), which are
//! dev-dependencies only.

mod common;

use common::*;
use oic_adapter_api::*;
use oic_adapter_solana::address as ours_addr;
use oic_adapter_solana::evidence::*;
use oic_adapter_solana::instruction as ours_ix;
use oic_adapter_solana::message::{
    AddressTableLookup, CompiledInstruction as OurIx, Message as OurMessage, MessageHeader as OurHeader, MessageVersion, Transaction as OurTx,
};
use oic_adapter_solana::*;
use oic_domain_types::*;
use proptest::prelude::*;
use solana_keypair::Keypair;
use solana_message::compiled_instruction::CompiledInstruction as TheirIx;
use solana_message::v0::{self, MessageAddressTableLookup};
use solana_message::{Address, AddressLookupTableAccount, Hash, Message as LegacyMessage, MessageHeader as TheirHeader, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction as TheirTx;

/// Small deterministic generator seeded by proptest.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bool(&mut self) -> bool {
        self.next() & 1 == 1
    }
    fn key(&mut self) -> [u8; 32] {
        let mut k = [0u8; 32];
        for c in k.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        k
    }
    fn bytes(&mut self, max: u64) -> Vec<u8> {
        (0..self.below(max + 1)).map(|_| self.next() as u8).collect()
    }
}

fn addr(k: &[u8; 32]) -> Address {
    Address::new_from_array(*k)
}

fn their_header(h: &TheirHeader) -> OurHeader {
    OurHeader {
        num_required_signatures: h.num_required_signatures,
        num_readonly_signed_accounts: h.num_readonly_signed_accounts,
        num_readonly_unsigned_accounts: h.num_readonly_unsigned_accounts,
    }
}

fn their_ixs(ixs: &[TheirIx]) -> Vec<OurIx> {
    ixs.iter().map(|i| OurIx { program_id_index: i.program_id_index, accounts: i.accounts.clone(), data: i.data.clone() }).collect()
}

/// Field-by-field comparison of the SDK's decoded message with ours.
fn assert_same(theirs: &VersionedMessage, ours: &OurMessage) {
    assert_eq!(their_header(theirs.header()), ours.header);
    let keys: Vec<[u8; 32]> = theirs.static_account_keys().iter().map(|k| k.to_bytes()).collect();
    assert_eq!(keys, ours.account_keys);
    assert_eq!(theirs.recent_blockhash().to_bytes(), ours.recent_blockhash);
    assert_eq!(their_ixs(theirs.instructions()), ours.instructions);
    match theirs {
        VersionedMessage::Legacy(_) => {
            assert_eq!(ours.version, MessageVersion::Legacy);
            assert!(ours.address_table_lookups.is_empty());
        }
        VersionedMessage::V0(m) => {
            assert_eq!(ours.version, MessageVersion::V0);
            let l: Vec<AddressTableLookup> = m
                .address_table_lookups
                .iter()
                .map(|l| AddressTableLookup {
                    account_key: l.account_key.to_bytes(),
                    writable_indexes: l.writable_indexes.clone(),
                    readonly_indexes: l.readonly_indexes.clone(),
                })
                .collect();
            assert_eq!(l, ours.address_table_lookups);
        }
        other => panic!("unexpected SDK message version {other:?}"),
    }
}

/// Serialize through both SDK paths (serde+bincode and wincode) and require agreement.
fn sdk_bytes(m: &VersionedMessage) -> Vec<u8> {
    let b = bincode::serialize(m).unwrap();
    assert_eq!(b, m.serialize(), "bincode and wincode serializations disagree");
    b
}

/// Random SDK instructions over a pool of accounts and programs.
fn random_instructions(rng: &mut Rng, pool: &[[u8; 32]], programs: &[[u8; 32]]) -> Vec<solana_instruction::Instruction> {
    let n = 1 + rng.below(4);
    (0..n)
        .map(|_| {
            let program_id = addr(&programs[rng.below(programs.len() as u64) as usize]);
            let accounts = (0..rng.below(5))
                .map(|_| {
                    let k = addr(&pool[rng.below(pool.len() as u64) as usize]);
                    let w = rng.bool();
                    if rng.below(5) == 0 {
                        solana_instruction::AccountMeta { pubkey: k, is_signer: true, is_writable: w }
                    } else {
                        solana_instruction::AccountMeta { pubkey: k, is_signer: false, is_writable: w }
                    }
                })
                .collect();
            solana_instruction::Instruction { program_id, accounts, data: rng.bytes(40) }
        })
        .collect()
}

fn random_sdk_message(seed: u64, v0_msg: bool) -> VersionedMessage {
    let mut rng = Rng(seed | 1);
    let pool: Vec<[u8; 32]> = (0..3 + rng.below(9)).map(|_| rng.key()).collect();
    let programs: Vec<[u8; 32]> = (0..1 + rng.below(3)).map(|_| rng.key()).collect();
    let payer = addr(&pool[0]);
    let ixs = random_instructions(&mut rng, &pool, &programs);
    let hash = Hash::new_from_array(rng.key());
    if !v0_msg {
        return VersionedMessage::Legacy(LegacyMessage::new_with_blockhash(&ixs, Some(&payer), &hash));
    }
    // Tables containing a random subset of pool keys plus unrelated entries.
    let tables: Vec<AddressLookupTableAccount> = (0..1 + rng.below(2))
        .map(|_| {
            let mut addresses: Vec<Address> = (0..rng.below(4)).map(|_| addr(&rng.key())).collect();
            for k in &pool[1..] {
                if rng.bool() {
                    addresses.push(addr(k));
                }
            }
            AddressLookupTableAccount { key: addr(&rng.key()), addresses }
        })
        .collect();
    VersionedMessage::V0(v0::Message::try_compile(&payer, &ixs, &tables, hash).unwrap())
}

fn random_our_message(seed: u64, v0_msg: bool) -> OurMessage {
    let mut rng = Rng(seed | 1);
    let nstatic = 2 + rng.below(9) as usize;
    let account_keys: Vec<[u8; 32]> = (0..nstatic).map(|_| rng.key()).collect();
    let nsig = 1 + rng.below((nstatic as u64 - 1).min(3)) as u8;
    let ro_signed = rng.below(nsig as u64) as u8;
    let ro_unsigned = rng.below((nstatic - nsig as usize) as u64 + 1) as u8;
    let lookups: Vec<AddressTableLookup> = if v0_msg {
        (0..rng.below(3))
            .map(|_| {
                let mut w: Vec<u8> = (0..rng.below(4)).map(|_| rng.next() as u8).collect();
                let r: Vec<u8> = (0..rng.below(4)).map(|_| rng.next() as u8).collect();
                if w.is_empty() && r.is_empty() {
                    w.push(0);
                }
                AddressTableLookup { account_key: rng.key(), writable_indexes: w, readonly_indexes: r }
            })
            .collect()
    } else {
        vec![]
    };
    let total = nstatic + lookups.iter().map(|l| l.writable_indexes.len() + l.readonly_indexes.len()).sum::<usize>();
    let instructions = (0..rng.below(5))
        .map(|_| OurIx {
            program_id_index: 1 + rng.below(nstatic as u64 - 1) as u8,
            accounts: (0..rng.below(6)).map(|_| rng.below(total as u64) as u8).collect(),
            data: rng.bytes(48),
        })
        .collect();
    OurMessage {
        version: if v0_msg { MessageVersion::V0 } else { MessageVersion::Legacy },
        header: OurHeader { num_required_signatures: nsig, num_readonly_signed_accounts: ro_signed, num_readonly_unsigned_accounts: ro_unsigned },
        account_keys,
        recent_blockhash: rng.key(),
        instructions,
        address_table_lookups: lookups,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// SDK-built legacy and v0 messages decode with ours and re-encode byte-exactly.
    #[test]
    fn sdk_messages_decode_and_reencode_exactly(seed in any::<u64>(), v0_msg in any::<bool>()) {
        let theirs = random_sdk_message(seed, v0_msg);
        let bytes = sdk_bytes(&theirs);
        let ours = OurMessage::decode(&bytes).unwrap();
        assert_same(&theirs, &ours);
        prop_assert_eq!(ours.encode(), bytes.clone());
        // Transaction framing agrees as well.
        let n = theirs.header().num_required_signatures as usize;
        let vt = VersionedTransaction { signatures: (0..n).map(|i| [i as u8 + 1; 64].into()).collect(), message: theirs.clone() };
        let tx_bytes = bincode::serialize(&vt).unwrap();
        let ours_tx = OurTx::decode(&tx_bytes).unwrap();
        prop_assert_eq!(ours_tx.message_bytes, bytes);
        prop_assert_eq!(OurTx::encode(&ours_tx.signatures, &OurMessage::encode(&ours_tx.message)), tx_bytes);
    }

    /// Our messages deserialize with the SDK to the same fields, pass SDK sanitization,
    /// and the SDK re-serializes them to our bytes.
    #[test]
    fn our_messages_decode_with_sdk(seed in any::<u64>(), v0_msg in any::<bool>()) {
        let ours = random_our_message(seed, v0_msg);
        let bytes = ours.encode();
        prop_assert_eq!(OurMessage::decode(&bytes).unwrap(), ours.clone());
        let theirs: VersionedMessage = bincode::deserialize(&bytes).unwrap();
        prop_assert!(theirs.sanitize().is_ok(), "SDK sanitize rejected a message our strict decoder accepts");
        assert_same(&theirs, &ours);
        prop_assert_eq!(sdk_bytes(&theirs), bytes);
    }

    /// Our PDA / ATA derivation equals the SDK's `find_program_address` and the SPL
    /// ATA interface's `get_associated_token_address`.
    #[test]
    fn ata_derivation_matches_sdk(owner in any::<[u8; 32]>(), mint in any::<[u8; 32]>()) {
        let ours = ours_addr::associated_token_address(&owner, &mint, &ours_addr::TOKEN_PROGRAM_ID).unwrap();
        let (theirs, _) = solana_pubkey::Pubkey::find_program_address(
            &[&owner, &ours_addr::TOKEN_PROGRAM_ID, &mint],
            &solana_pubkey::Pubkey::new_from_array(ours_addr::ATA_PROGRAM_ID),
        );
        prop_assert_eq!(ours, theirs.to_bytes());
        let spl = spl_associated_token_account_interface::address::get_associated_token_address(&owner.into(), &mint.into());
        prop_assert_eq!(ours, spl.to_bytes());
    }
}

#[test]
fn program_ids_match_sdk() {
    assert_eq!(solana_system_interface::program::id().to_bytes(), ours_addr::SYSTEM_PROGRAM_ID);
    assert_eq!(solana_compute_budget_interface::id().to_bytes(), ours_addr::COMPUTE_BUDGET_PROGRAM_ID);
    assert_eq!(spl_token_interface::id().to_bytes(), ours_addr::TOKEN_PROGRAM_ID);
    assert_eq!(spl_associated_token_account_interface::program::id().to_bytes(), ours_addr::ATA_PROGRAM_ID);
}

#[test]
fn known_ata_vector() {
    // Fixed (owner, mint) pair: mainnet USDC mint and a fixed wallet owner.
    let usdc = ours_addr::from_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
    let owner = ours_addr::from_base58("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM").unwrap();
    let ours = ours_addr::associated_token_address(&owner, &usdc, &ours_addr::TOKEN_PROGRAM_ID).unwrap();
    let spl = spl_associated_token_account_interface::address::get_associated_token_address(&owner.into(), &usdc.into());
    assert_eq!(ours, spl.to_bytes());
    let (sdk, bump) = solana_pubkey::Pubkey::find_program_address(
        &[&owner, &ours_addr::TOKEN_PROGRAM_ID, &usdc],
        &solana_pubkey::Pubkey::new_from_array(ours_addr::ATA_PROGRAM_ID),
    );
    assert_eq!(ours, sdk.to_bytes());
    let (_, our_bump) =
        ours_addr::find_program_address(&[&owner, &ours_addr::TOKEN_PROGRAM_ID, &usdc], &ours_addr::ATA_PROGRAM_ID).unwrap();
    assert_eq!(our_bump, bump);
    assert!(ours_addr::is_off_curve(&ours));
}

#[test]
fn instruction_encodings_match_sdk_builders() {
    let from = [1u8; 32];
    let to = [2u8; 32];
    let t = solana_system_interface::instruction::transfer(&addr(&from), &addr(&to), 123_456_789);
    assert_eq!(t.data, ours_ix::system_transfer_data(123_456_789));
    assert_eq!(t.program_id.to_bytes(), ours_addr::SYSTEM_PROGRAM_ID);
    let decoded: solana_system_interface::instruction::SystemInstruction = bincode::deserialize(&ours_ix::system_transfer_data(42)).unwrap();
    assert_eq!(decoded, solana_system_interface::instruction::SystemInstruction::Transfer { lamports: 42 });

    let l = solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(300_000);
    assert_eq!(l.data, ours_ix::set_compute_unit_limit_data(300_000));
    assert_eq!(l.program_id.to_bytes(), ours_addr::COMPUTE_BUDGET_PROGRAM_ID);
    let p = solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_price(77_777);
    assert_eq!(p.data, ours_ix::set_compute_unit_price_data(77_777));

    let (src, mint, dst, auth) = ([3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32]);
    let tc = spl_token_interface::instruction::transfer_checked(
        &ours_addr::TOKEN_PROGRAM_ID.into(),
        &src.into(),
        &mint.into(),
        &dst.into(),
        &auth.into(),
        &[],
        1_000_000,
        6,
    )
    .unwrap();
    assert_eq!(tc.data, ours_ix::transfer_checked_data(1_000_000, 6));
    let metas: Vec<([u8; 32], bool, bool)> = tc.accounts.iter().map(|m| (m.pubkey.to_bytes(), m.is_signer, m.is_writable)).collect();
    assert_eq!(metas, vec![(src, false, true), (mint, false, false), (dst, false, true), (auth, true, false)]);

    let owner = [7u8; 32];
    let ata = spl_associated_token_account_interface::instruction::create_associated_token_account_idempotent(
        &auth.into(),
        &owner.into(),
        &mint.into(),
        &ours_addr::TOKEN_PROGRAM_ID.into(),
    );
    assert_eq!(ata.program_id.to_bytes(), ours_addr::ATA_PROGRAM_ID);
    assert_eq!(ata.data, ours_ix::ata_create_idempotent_data());
    let derived = ours_addr::associated_token_address(&owner, &mint, &ours_addr::TOKEN_PROGRAM_ID).unwrap();
    let metas: Vec<([u8; 32], bool, bool)> = ata.accounts.iter().map(|m| (m.pubkey.to_bytes(), m.is_signer, m.is_writable)).collect();
    assert_eq!(
        metas,
        vec![
            (auth, true, true),
            (derived, false, true),
            (owner, false, false),
            (mint, false, false),
            (ours_addr::SYSTEM_PROGRAM_ID, false, false),
            (ours_addr::TOKEN_PROGRAM_ID, false, false),
        ]
    );
    let create = spl_associated_token_account_interface::instruction::create_associated_token_account(
        &auth.into(),
        &owner.into(),
        &mint.into(),
        &ours_addr::TOKEN_PROGRAM_ID.into(),
    );
    assert_eq!(create.data, vec![ours_ix::ATA_IX_CREATE]);
}

fn keypair_for(seed: u8) -> Keypair {
    let sk = signing_key(seed);
    let kp = Keypair::new_from_array(sk.to_bytes());
    assert_eq!(kp.pubkey().to_bytes(), sk.verifying_key().to_bytes(), "SDK and ed25519-dalek derive the same public key");
    kp
}

/// The SDK signs our built candidate; our verifier accepts the SDK transaction bytes.
fn sdk_signs_ours_verifies(fx: &Fx, c: &Candidate) {
    let kp = keypair_for(1);
    let msg: VersionedMessage = bincode::deserialize(c.native_unsigned_bytes.as_slice()).unwrap();
    let vt = VersionedTransaction::try_new(msg, &[&kp]).unwrap();
    let signed_bytes = bincode::serialize(&vt).unwrap();
    let signed = SignedTransaction {
        candidate_id: c.candidate_id.clone(),
        candidate_revision: c.candidate_revision,
        signed_bytes: Bytes(signed_bytes),
        chain_tx_id: ChainTxId::unchecked(vt.signatures[0].to_string()),
    };
    let v = SolanaAdapter.verify_signed_transaction(&signed, c, &fx.key).unwrap();
    assert_eq!(v.verified_signers, vec![Bytes(kp.pubkey().to_bytes().to_vec())]);
    // A different SDK key is rejected.
    let other = keypair_for(9);
    let msg: VersionedMessage = bincode::deserialize(c.native_unsigned_bytes.as_slice()).unwrap();
    let mut forged = VersionedTransaction::try_new(msg, &[&kp]).unwrap();
    forged.signatures[0] = other.sign_message(c.native_unsigned_bytes.as_slice());
    let bad = SignedTransaction {
        signed_bytes: Bytes(bincode::serialize(&forged).unwrap()),
        chain_tx_id: ChainTxId::unchecked(forged.signatures[0].to_string()),
        ..signed
    };
    assert_eq!(SolanaAdapter.verify_signed_transaction(&bad, c, &fx.key).unwrap_err().code, ErrorCode::InvalidSignature);
}

/// We sign with ed25519-dalek and assemble; the SDK deserializes and verifies.
fn ours_signs_sdk_verifies(fx: &Fx, c: &Candidate) {
    let signed = SolanaAdapter.assemble_signed_transaction(c, &fx.key, &[fx.sign(c)]).unwrap();
    let vt: VersionedTransaction = bincode::deserialize(signed.signed_bytes.as_slice()).unwrap();
    vt.verify_and_hash_message().unwrap();
    assert_eq!(vt.signatures[0].to_string(), signed.chain_tx_id.as_str());
    assert_eq!(bincode::serialize(&vt).unwrap(), signed.signed_bytes.0);
    if let Some(legacy) = vt.into_legacy_transaction() {
        let t: TheirTx = legacy;
        t.verify().unwrap();
        let t2: TheirTx = bincode::deserialize(signed.signed_bytes.as_slice()).unwrap();
        t2.verify().unwrap();
    }
    // A flipped message byte makes the SDK reject it too.
    let mut b = signed.signed_bytes.0.clone();
    let last = b.len() - 1;
    b[last] ^= 1;
    if let Ok(vt) = bincode::deserialize::<VersionedTransaction>(&b) {
        assert!(vt.verify_and_hash_message().is_err());
    }
}

/// v0 SOL transfer compiled by the SDK with the destination in a lookup table.
fn sdk_v0_candidate(fx: &mut Fx) -> Candidate {
    let table = [0xa7u8; 32];
    let ix = solana_system_interface::instruction::transfer(&addr(&fx.wallet_addr), &addr(&dest_owner()), AMOUNT as u64);
    let alt = AddressLookupTableAccount { key: addr(&table), addresses: vec![addr(&[0x01; 32]), addr(&dest_owner())] };
    let m = v0::Message::try_compile(&addr(&fx.wallet_addr), &[ix], &[alt], Hash::new_from_array(BLOCKHASH)).unwrap();
    assert_eq!(m.address_table_lookups.len(), 1, "destination should come from the lookup table");
    assert_eq!(
        m.address_table_lookups[0],
        MessageAddressTableLookup { account_key: addr(&table), writable_indexes: vec![1], readonly_indexes: vec![] }
    );
    let bytes = sdk_bytes(&VersionedMessage::V0(m));
    fx.evidence.items.insert(alt_key(&table), canon(&AddressLookupTableEvidence {
        addresses: vec![Bytes(vec![0x01; 32]), Bytes(dest_owner().to_vec())],
        deactivation_slot: u64::MAX,
        last_extended_slot: 10,
    }));
    fx.candidate_for(bytes, 2)
}

#[test]
fn signatures_cross_verify_legacy_sol_and_spl() {
    for fx in [native_fixture(), spl_fixture()] {
        let c = fx.build();
        // The SDK decodes our candidate and agrees with our view.
        let theirs: VersionedMessage = bincode::deserialize(c.native_unsigned_bytes.as_slice()).unwrap();
        theirs.sanitize().unwrap();
        assert_same(&theirs, &OurMessage::decode(c.native_unsigned_bytes.as_slice()).unwrap());
        sdk_signs_ours_verifies(&fx, &c);
        ours_signs_sdk_verifies(&fx, &c);
    }
}

#[test]
fn sdk_compiled_v0_candidate_verifies_and_cross_signs() {
    let mut fx = native_fixture();
    let c = sdk_v0_candidate(&mut fx);
    let v = fx.verify(&c).unwrap();
    assert_eq!(v.decoded.recipient().as_slice(), dest_owner());
    assert_eq!(c.signing_payloads[0].native_signing_context, SIGNING_CONTEXT_V0);
    sdk_signs_ours_verifies(&fx, &c);
    ours_signs_sdk_verifies(&fx, &c);
}

#[test]
fn sdk_legacy_transaction_new_matches_our_bytes() {
    // The SDK's own legacy compiler for the same SOL transfer.
    let fx = native_fixture();
    let kp = keypair_for(1);
    let ix = solana_system_interface::instruction::transfer(&kp.pubkey(), &addr(&dest_owner()), AMOUNT as u64);
    let msg = LegacyMessage::new_with_blockhash(&[ix], Some(&kp.pubkey()), &Hash::new_from_array(BLOCKHASH));
    let tx = TheirTx::new(&[&kp], msg, Hash::new_from_array(BLOCKHASH));
    let tx_bytes = bincode::serialize(&tx).unwrap();
    let ours = OurTx::decode(&tx_bytes).unwrap();
    // Our builder produces exactly the SDK's legacy message for a plain SOL transfer.
    let c = fx.build();
    assert_eq!(ours.message_bytes, c.native_unsigned_bytes.0);
    let signed = SignedTransaction {
        candidate_id: c.candidate_id.clone(),
        candidate_revision: c.candidate_revision,
        signed_bytes: Bytes(tx_bytes),
        chain_tx_id: ChainTxId::unchecked(tx.signatures[0].to_string()),
    };
    SolanaAdapter.verify_signed_transaction(&signed, &c, &fx.key).unwrap();
    // And both ed25519 implementations produce the identical (deterministic) signature.
    let ours_signed = SolanaAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
    assert_eq!(ours_signed.signed_bytes, signed.signed_bytes);
}
