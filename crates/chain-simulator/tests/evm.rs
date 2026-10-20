//! End-to-end: the pinned EVM adapter builds from simulator evidence, the
//! simulator executes the signed bytes, and the adapter observes the result.

mod common;

use common::*;
use k256::ecdsa::SigningKey;
use oic_adapter_api::*;
use oic_adapter_evm::address::{eip55, Address};
use oic_adapter_evm::calldata::encode_transfer;
use oic_adapter_evm::evidence::{get_tx_observation, TxObservation};
use oic_adapter_evm::tx::{tx_hash, Eip1559Tx, EvmTx, LegacyTx, RawSignature};
use oic_adapter_evm::EvmAdapter;
use oic_chain_simulator::evm::*;
use oic_chain_simulator::SimClock;
use oic_domain_types::*;
use std::sync::Arc;

const ETH: u128 = 1_000_000_000_000_000_000;
const DEST: Address = [0xde; 20];

fn sim_with(depth: u64) -> (Arc<EvmSimulator>, SimClock) {
    let clock = SimClock::default();
    let cfg = EvmSimConfig { finality_depth: depth, ..EvmSimConfig::with_seed([7; 32]) };
    (Arc::new(EvmSimulator::new(cfg, clock.clone()).unwrap()), clock)
}

fn key(seed: u8) -> SigningKey {
    let mut b = [0x11u8; 32];
    b[0] = seed;
    SigningKey::from_bytes(&b.into()).unwrap()
}

fn evm_party(profile: &ChainProfile, sk: &SigningKey, n: u32) -> Party {
    let pk = sk.verifying_key().to_encoded_point(true).as_bytes().to_vec();
    let a = address_of(sk).unwrap();
    party(profile, SchemeId::EcdsaSecp256k1Keccak256Prehashed, pk, a.to_vec(), eip55(&a), n)
}

fn native_transfer(sim: &EvmSimulator, sk: &SigningKey, amount: u128) -> Transfer {
    let p = sim.profile();
    let party = evm_party(&p, sk, 1);
    let asset = asset(&p, AssetKind::Native, 18, "ETH");
    let dest = destination(&p, DEST.to_vec(), eip55(&DEST));
    Transfer::new(p, party, asset, dest, amount, 10u128.pow(16))
}

fn erc20_transfer(sim: &EvmSimulator, sk: &SigningKey, token: Address, amount: u128) -> Transfer {
    let p = sim.profile();
    let party = evm_party(&p, sk, 1);
    let asset = asset(&p, AssetKind::Erc20 { contract: Bytes(token.to_vec()) }, 6, "USDC");
    let dest = destination(&p, DEST.to_vec(), eip55(&DEST));
    Transfer::new(p, party, asset, dest, amount, 10u128.pow(16))
}

fn sign_digest(sk: &SigningKey, digest: &[u8]) -> SignatureBytes {
    let (sig, recid) = sk.sign_prehash_recoverable(digest).unwrap();
    let mut b = sig.to_bytes().to_vec();
    b.push(recid.to_byte());
    SignatureBytes { scheme: SchemeId::EcdsaSecp256k1Keccak256Prehashed, bytes: Bytes(b) }
}

/// Build via the adapter from fresh simulator evidence, sign, assemble.
fn build_and_sign(sim: &EvmSimulator, clock: &SimClock, t: &Transfer, sk: &SigningKey, cand: &str, contracts: &[Address]) -> (Candidate, SignedTransaction) {
    let sender = address_of(sk).unwrap();
    let mut q = EvmEvidenceQuery::latest().sender(sender);
    for c in contracts {
        q = q.contract(*c);
    }
    let ev = sim.evidence(&q).unwrap();
    EvmAdapter.identify_network(&t.profile, &ev).unwrap();
    let c = EvmAdapter.build_candidate(&t.build_ctx(ev.clone(), cand, 1, clock.now())).unwrap();
    EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&t.intent), &t.vctx(&ev)).unwrap();
    let sig = sign_digest(sk, c.signing_payloads[0].message_or_digest.as_slice());
    let signed = EvmAdapter.assemble_signed_transaction(&c, &t.party.key, &[sig]).unwrap();
    (c, signed)
}

fn observe(sim: &EvmSimulator, id: &ChainTxId) -> ChainObservation {
    let ev = sim.evidence(&EvmEvidenceQuery::latest().tx_id(id).unwrap()).unwrap();
    EvmAdapter.observe(id, &sim.profile(), &ev).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn raw_tx(sim: &EvmSimulator, sk: &SigningKey, nonce: u64, to: Address, value: u128, data: Vec<u8>, gas_limit: u64, prio: u128) -> Vec<u8> {
    let (base, _, _) = sim.fees();
    let tx = Eip1559Tx {
        chain_id: sim.chain_id(),
        nonce,
        max_priority_fee_per_gas: prio,
        max_fee_per_gas: 2 * base + prio,
        gas_limit,
        to,
        value,
        data,
        access_list: vec![],
    };
    sign_eip1559(sk, &tx).unwrap()
}

fn funded(sim: &EvmSimulator, sk: &SigningKey, amount: u128) -> Address {
    let a = address_of(sk).unwrap();
    sim.fund(a, amount).unwrap();
    sim.mine().unwrap();
    a
}

#[test]
fn profile_and_evidence_shape() {
    let (sim, clock) = sim_with(2);
    let p = sim.profile();
    assert_eq!(p.chain_profile_id.as_str(), "evm-devsim-v1");
    assert_eq!(p.network_id.as_str(), "evm-31337");
    assert_eq!(p.network_binding, oic_adapter_evm::network_binding_for_chain_id(31_337));
    assert_eq!(p.finality_depth, 2);
    assert_eq!(p.max_evidence_age_seconds, 120);
    assert_eq!(p.accepted_trust_levels, vec![EvidenceTrustLevel::DevelopmentSimulator]);
    assert!(p.display_name.contains("DEVELOPMENT ONLY"));
    assert_eq!(sim.config().finality_depth, 2);
    assert_eq!(sim.config().seed, [7; 32]);
    assert_eq!(sim.clock().now(), clock.now());
    assert_eq!(sim.account(&sim.faucet_address()), EvmAccount { balance: FAUCET_GENESIS_BALANCE, nonce: 0, code: vec![] });
    assert!(EvmSimulator::new(EvmSimConfig { finality_depth: 0, ..Default::default() }, clock.clone()).is_err());
    let ev = sim.evidence(&EvmEvidenceQuery::latest()).unwrap();
    assert_eq!(ev.trust_level, EvidenceTrustLevel::DevelopmentSimulator);
    assert_eq!(ev.sources, vec![EvidenceSourceId::unchecked("devsim-evm")]);
    assert_eq!(ev.verifier_version, format!("oic-chain-simulator/{}", env!("CARGO_PKG_VERSION")));
    assert_eq!(ev.max_staleness_seconds, 60);
    assert_eq!(ev.observed_at, clock.now());
    assert_eq!(ev.state, sim.head());
    assert_eq!(ev.state.commitment, "latest");
    for k in ["chain_id", "base_fee", "priority_fee", "gas_limit"] {
        assert!(ev.items.contains_key(k), "{k}");
    }
    check_evidence_scope(&p, &ev, Some(clock.now())).unwrap();
    clock.advance(61).unwrap();
    assert_eq!(check_evidence_scope(&p, &ev, Some(clock.now())).unwrap_err().code, ErrorCode::StaleEvidence);
    // A wrong chain id in the profile fails network identification.
    let mut other = p.clone();
    other.network_binding = oic_adapter_evm::network_binding_for_chain_id(1);
    assert_eq!(EvmAdapter.identify_network(&other, &ev).unwrap_err().code, ErrorCode::ScopeMismatch);
    // Faucet credit appears as a real included transfer with a receipt.
    let id = sim.fund(DEST, 5).unwrap();
    assert_eq!(sim.mempool(), vec![id.clone()]);
    assert!(sim.receipt(&id).unwrap().is_none());
    let b = sim.mine().unwrap();
    assert_eq!(b.transactions.len(), 1);
    assert_eq!(b.transactions[0].from, sim.faucet_address());
    assert!(sim.receipt(&id).unwrap().unwrap().success);
    assert_eq!(sim.balance(&DEST), 5);
}

#[test]
fn native_transfer_end_to_end_included_then_finalized() {
    let (sim, clock) = sim_with(2);
    let sk = key(1);
    let sender = funded(&sim, &sk, ETH);
    let t = native_transfer(&sim, &sk, 123_456_789);
    let (_, signed) = build_and_sign(&sim, &clock, &t, &sk, "cand-1", &[]);
    let id = sim.submit(signed.signed_bytes.as_slice()).unwrap();
    assert_eq!(id, signed.chain_tx_id);
    // Acknowledged, not included (I10).
    assert!(matches!(observe(&sim, &id), ChainObservation::Submitted { .. }));
    let before = sim.balance(&sender);
    let block = sim.mine().unwrap();
    assert_eq!(block.transactions.len(), 1);
    let (base, prio, _) = sim.fees();
    let fee = 21_000 * (base + prio);
    match observe(&sim, &id) {
        ChainObservation::Included { execution_success, fee_paid, state, .. } => {
            assert!(execution_success);
            assert_eq!(fee_paid, Amount(fee));
            assert_eq!(state.height, block.height);
            assert_eq!(state.hash, Bytes(block.hash.to_vec()));
        }
        o => panic!("expected Included, got {o:?}"),
    }
    sim.mine().unwrap();
    assert!(matches!(observe(&sim, &id), ChainObservation::Finalized { execution_success: true, .. }));
    assert_eq!(sim.balance(&sender), before - 123_456_789 - fee);
    assert_eq!(sim.balance(&DEST), 123_456_789);
    assert_eq!(sim.nonce(&sender), 1);
    let r = sim.receipt(&id).unwrap().unwrap();
    assert_eq!((r.gas_used, r.effective_gas_price, r.fee_paid()), (21_000, base + prio, fee));
    assert!(r.logs.is_empty());
    // Nonce evidence moved and a rebuild uses the next nonce.
    let ev = sim.evidence(&EvmEvidenceQuery::latest().sender(sender)).unwrap();
    assert_eq!(ev.items[&format!("nonce:{}", hex::encode(sender))], Bytes(1u64.to_be_bytes().to_vec()));
}

#[test]
fn erc20_transfer_end_to_end_with_transfer_log() {
    let (sim, clock) = sim_with(2);
    let sk = key(2);
    let sender = address_of(&sk).unwrap();
    let token = sim.deploy_erc20("USDC", 6, sim.faucet_address(), 1_000_000_000_000).unwrap();
    assert_eq!(sim.erc20_info(&token).unwrap().decimals, 6);
    assert_eq!(sim.account(&token).code, ERC20_CODE_MARKER.to_vec());
    sim.fund(sender, ETH).unwrap();
    sim.erc20_fund(token, sender, 5_000_000).unwrap();
    let b = sim.mine().unwrap();
    assert_eq!(b.system_ops.len(), 1);
    assert_eq!(sim.erc20_balance(&token, &sender).unwrap(), 5_000_000);
    let code_ev = sim.evidence(&EvmEvidenceQuery::latest().contract(token).contract(DEST)).unwrap();
    assert_eq!(code_ev.items[&format!("code:{}", hex::encode(token))], Bytes(oic_adapter_evm::code_hash(ERC20_CODE_MARKER).to_vec()));
    assert_eq!(code_ev.items[&format!("code:{}", hex::encode(DEST))], Bytes(oic_adapter_evm::evidence::EMPTY_CODE_HASH.to_vec()));

    let t = erc20_transfer(&sim, &sk, token, 1_000_000);
    let (_, signed) = build_and_sign(&sim, &clock, &t, &sk, "cand-1", &[token]);
    let id = sim.submit(signed.signed_bytes.as_slice()).unwrap();
    let native_before = sim.balance(&sender);
    sim.mine().unwrap();
    let r = sim.receipt(&id).unwrap().unwrap();
    assert!(r.success);
    assert_eq!(r.gas_used, 51_000);
    assert_eq!(r.logs.len(), 1);
    let log = &r.logs[0];
    assert_eq!(log.address, token);
    assert_eq!(log.topics, vec![transfer_topic0(), address_topic(&sender), address_topic(&DEST)]);
    assert_eq!(transfer_topic0().to_vec(), hex::decode("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef").unwrap());
    let mut data = vec![0u8; 16];
    data.extend_from_slice(&1_000_000u128.to_be_bytes());
    assert_eq!(log.data, data);
    assert_eq!(sim.erc20_balance(&token, &sender).unwrap(), 4_000_000);
    assert_eq!(sim.erc20_balance(&token, &DEST).unwrap(), 1_000_000);
    assert_eq!(sim.balance(&sender), native_before - r.fee_paid());
    assert!(matches!(observe(&sim, &id), ChainObservation::Included { execution_success: true, .. }));
    sim.mine().unwrap();
    assert!(matches!(observe(&sim, &id), ChainObservation::Finalized { execution_success: true, .. }));
    // Indexer view: the block carries the decoded transfer and its log.
    let blk = sim.block(r.block_height).unwrap();
    assert_eq!(blk.transactions[0].to, token);
    assert_eq!(blk.transactions[0].receipt, r);
}

#[test]
fn admission_rejections() {
    let (sim, _clock) = sim_with(2);
    let sk = key(3);
    let sender = funded(&sim, &sk, ETH);
    let (_, prio, _) = sim.fees();
    // Wrong chain id.
    let (base, _, _) = sim.fees();
    let wrong = Eip1559Tx {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: prio,
        max_fee_per_gas: 2 * base + prio,
        gas_limit: 21_000,
        to: DEST,
        value: 1,
        data: vec![],
        access_list: vec![],
    };
    assert_eq!(sim.submit(&sign_eip1559(&sk, &wrong).unwrap()).unwrap_err().code, ErrorCode::ScopeMismatch);
    // Tampered signature (s above n/2) -> InvalidSignature.
    let good = raw_tx(&sim, &sk, 0, DEST, 1, vec![], 21_000, prio);
    let (tx, sig) = EvmTx::decode_signed(&good).unwrap();
    let tampered = tx.encode_signed(&RawSignature { s: [0xff; 32], ..sig });
    assert_eq!(sim.submit(&tampered).unwrap_err().code, ErrorCode::InvalidSignature);
    // Flipping r recovers some other (unfunded) address: refused for funds, never credited to the real sender.
    let mut r = sig.r;
    r[31] ^= 1;
    if let Err(e) = sim.submit(&tx.encode_signed(&RawSignature { r, ..sig })) {
        assert!(matches!(e.code, ErrorCode::ResourceConflict | ErrorCode::InvalidSignature), "{e:?}");
    } else {
        panic!("tampered r accepted");
    }
    // Garbage bytes.
    assert!(sim.submit(&[0x02, 0x01]).is_err());
    // Gas below intrinsic.
    assert_eq!(sim.submit(&raw_tx(&sim, &sk, 0, DEST, 1, vec![], 20_999, prio)).unwrap_err().code, ErrorCode::InvalidRequest);
    // Nonce gap.
    assert_eq!(sim.submit(&raw_tx(&sim, &sk, 5, DEST, 1, vec![], 21_000, prio)).unwrap_err().code, ErrorCode::ResourceConflict);
    // Insufficient balance (value + gas_limit * max_fee).
    assert_eq!(sim.submit(&raw_tx(&sim, &sk, 0, DEST, ETH, vec![], 21_000, prio)).unwrap_err().code, ErrorCode::ResourceConflict);
    let poor = key(9);
    assert_eq!(sim.submit(&raw_tx(&sim, &poor, 0, DEST, 1, vec![], 21_000, prio)).unwrap_err().code, ErrorCode::ResourceConflict);
    // Accept, then duplicate while pending, then replay after inclusion.
    sim.submit(&good).unwrap();
    assert_eq!(sim.submit(&good).unwrap_err().code, ErrorCode::ResourceConflict);
    sim.mine().unwrap();
    assert_eq!(sim.submit(&good).unwrap_err().code, ErrorCode::ResourceConflict);
    // A different tx re-using the consumed nonce.
    let reuse = raw_tx(&sim, &sk, 0, DEST, 2, vec![], 21_000, prio);
    assert_eq!(sim.submit(&reuse).unwrap_err().code, ErrorCode::ResourceConflict);
    assert_eq!(sim.nonce(&sender), 1);
    // Pending-aware nonce and balance accounting: two consecutive pending txs.
    sim.submit(&raw_tx(&sim, &sk, 1, DEST, 1, vec![], 21_000, prio)).unwrap();
    sim.submit(&raw_tx(&sim, &sk, 2, DEST, 1, vec![], 21_000, prio)).unwrap();
    let b = sim.mine().unwrap();
    assert_eq!(b.transactions.iter().map(|t| t.nonce).collect::<Vec<_>>(), vec![1, 2]);
}

#[test]
fn eip155_legacy_transactions_are_executed() {
    let (sim, _clock) = sim_with(2);
    let sk = key(4);
    let sender = funded(&sim, &sk, ETH);
    let (base, _, _) = sim.fees();
    let tx = LegacyTx { chain_id: 31_337, nonce: 0, gas_price: base * 2, gas_limit: 21_000, to: DEST, value: 77, data: vec![] };
    let (sig, recid) = sk.sign_prehash_recoverable(&tx.signing_digest()).unwrap();
    let b = sig.to_bytes();
    let raw = RawSignature { y_parity: recid.to_byte(), r: b[..32].try_into().unwrap(), s: b[32..].try_into().unwrap() };
    let id = sim.submit(&tx.encode_signed(&raw)).unwrap();
    sim.mine().unwrap();
    let r = sim.receipt(&id).unwrap().unwrap();
    assert!(r.success);
    assert_eq!(r.effective_gas_price, base * 2);
    assert_eq!(sim.balance(&DEST), 77);
    assert_eq!(sim.nonce(&sender), 1);
}

#[test]
fn reverted_calls_charge_gas_and_move_nothing() {
    let (sim, clock) = sim_with(2);
    let sk = key(5);
    let sender = address_of(&sk).unwrap();
    let token = sim.deploy_erc20("USDT", 6, sim.faucet_address(), 1_000).unwrap();
    let reverter: Address = [0xcc; 20];
    sim.install_code(reverter, vec![0xfe]).unwrap();
    sim.fund(sender, ETH).unwrap();
    sim.mine().unwrap();
    let (base, prio, _) = sim.fees();
    let eff = base + prio;

    // Adapter-built ERC-20 transfer with no token balance: included, reverted.
    let t = erc20_transfer(&sim, &sk, token, 500);
    let (_, signed) = build_and_sign(&sim, &clock, &t, &sk, "cand-1", &[token]);
    let id = sim.submit(signed.signed_bytes.as_slice()).unwrap();
    let before = sim.balance(&sender);
    sim.mine().unwrap();
    let r = sim.receipt(&id).unwrap().unwrap();
    assert!(!r.success);
    assert_eq!(r.gas_used, 21_000);
    assert!(r.logs.is_empty());
    assert_eq!(sim.balance(&sender), before - 21_000 * eff);
    assert_eq!(sim.erc20_balance(&token, &DEST).unwrap(), 0);
    assert_eq!(sim.erc20_balance(&token, &sim.faucet_address()).unwrap(), 1_000);
    assert!(matches!(observe(&sim, &id), ChainObservation::Included { execution_success: false, .. }));

    // approve() calldata to a token -> revert.
    let mut approve = vec![0x09, 0x5e, 0xa7, 0xb3];
    approve.extend_from_slice(&[0u8; 64]);
    let a = sim.submit(&raw_tx(&sim, &sk, 1, token, 0, approve, 65_000, prio)).unwrap();
    // Value to a non-token contract -> revert, value stays with the sender.
    let c = sim.submit(&raw_tx(&sim, &sk, 2, reverter, 1_000, vec![], 65_000, prio)).unwrap();
    // ERC-20 transfer with too little gas -> out of gas, whole gas limit charged.
    sim.erc20_fund(token, sender, 10).unwrap();
    let o = sim.submit(&raw_tx(&sim, &sk, 3, token, 0, encode_transfer(&DEST, 5), 30_000, prio)).unwrap();
    let before = sim.balance(&sender);
    sim.mine().unwrap();
    let ra = sim.receipt(&a).unwrap().unwrap();
    let rc = sim.receipt(&c).unwrap().unwrap();
    let ro = sim.receipt(&o).unwrap().unwrap();
    assert!(!ra.success && !rc.success && !ro.success);
    assert_eq!((ra.gas_used, rc.gas_used, ro.gas_used), (21_000, 21_000, 30_000));
    assert_eq!(sim.balance(&reverter), 0);
    assert_eq!(sim.balance(&sender), before - (21_000 + 21_000 + 30_000) * eff);
    assert_eq!(sim.erc20_balance(&token, &sender).unwrap(), 10);
    assert_eq!(sim.nonce(&sender), 4);
}

#[test]
fn replacement_requires_ten_percent_bump_and_reports_consumer() {
    let (sim, _clock) = sim_with(2);
    let sk = key(6);
    let sender = funded(&sim, &sk, ETH);
    let (_, prio, _) = sim.fees();
    let first = raw_tx(&sim, &sk, 0, DEST, 1, vec![], 21_000, prio);
    let first_id = sim.submit(&first).unwrap();
    let small = raw_tx(&sim, &sk, 0, DEST, 2, vec![], 21_000, prio * 105 / 100);
    assert_eq!(sim.submit(&small).unwrap_err().code, ErrorCode::ResourceConflict);
    let bumped = raw_tx(&sim, &sk, 0, DEST, 3, vec![], 21_000, prio * 110 / 100);
    let bumped_id = sim.submit(&bumped).unwrap();
    assert_eq!(sim.mempool(), vec![bumped_id.clone()]);
    sim.mine().unwrap();
    assert_eq!(sim.balance(&DEST), 3);
    assert_eq!(sim.nonce(&sender), 1);
    let h = parse_tx_id(&first_id).unwrap();
    let ev = sim.evidence(&EvmEvidenceQuery::latest().tx(h)).unwrap();
    let obs = get_tx_observation(&ev, &h).unwrap();
    assert!(!obs.included);
    assert_eq!(obs.nonce_consumed_by, Some(Bytes(parse_tx_id(&bumped_id).unwrap().to_vec())));
    // An unknown hash is simply not included, with no consumer.
    let ev = sim.evidence(&EvmEvidenceQuery::latest().tx([9; 32])).unwrap();
    let obs = get_tx_observation(&ev, &[9; 32]).unwrap();
    assert!(!obs.included && obs.nonce_consumed_by.is_none());
}

#[test]
fn fee_spike_leaves_tx_pending_until_base_fee_falls() {
    let (sim, _clock) = sim_with(2);
    let sk = key(7);
    funded(&sim, &sk, ETH);
    let (base, prio, gas) = sim.fees();
    let id = sim.submit(&raw_tx(&sim, &sk, 0, DEST, 1, vec![], 21_000, prio)).unwrap();
    sim.set_fees(base * 3, prio, gas).unwrap();
    let b = sim.mine().unwrap();
    assert!(b.transactions.is_empty());
    assert_eq!(b.base_fee, base * 3);
    assert_eq!(sim.mempool(), vec![id.clone()]);
    // New submissions below the spiked base fee are refused.
    let sk2 = key(8);
    funded(&sim, &sk2, ETH);
    let low = Eip1559Tx {
        chain_id: 31_337,
        nonce: 0,
        max_priority_fee_per_gas: prio,
        max_fee_per_gas: base * 2,
        gas_limit: 21_000,
        to: DEST,
        value: 1,
        data: vec![],
        access_list: vec![],
    };
    assert_eq!(sim.submit(&sign_eip1559(&sk2, &low).unwrap()).unwrap_err().code, ErrorCode::ResourceConflict);
    let ev = sim.evidence(&EvmEvidenceQuery::latest()).unwrap();
    assert_eq!(ev.items["base_fee"], Bytes((base * 3).to_be_bytes().to_vec()));
    sim.set_fees(base, prio, gas).unwrap();
    sim.mine().unwrap();
    let r = sim.receipt(&id).unwrap().unwrap();
    assert_eq!(r.effective_gas_price, base + prio);
    assert!(sim.set_fees(base, prio, 100).is_err());
}

#[test]
fn reorg_drops_and_reincludes_transactions() {
    let (sim, _clock) = sim_with(4);
    let sk = key(10);
    let sender = funded(&sim, &sk, ETH);
    let (_, prio, _) = sim.fees();
    let t_bytes = raw_tx(&sim, &sk, 0, DEST, 1_000, vec![], 21_000, prio);
    let t = sim.submit(&t_bytes).unwrap();
    let mined = sim.mine().unwrap();
    sim.mine().unwrap();
    let head_before = sim.head();
    let included_before = observe(&sim, &t);
    assert!(matches!(&included_before, ChainObservation::Included { state, .. } if state.height == mined.height));

    // Reorg without dropping: same tx, same height, new block hash.
    sim.reorg(2, &[]).unwrap();
    assert_eq!(sim.head().height, head_before.height);
    assert_ne!(sim.head().hash, head_before.hash);
    let replacement = sim.block(mined.height).unwrap();
    assert_ne!(replacement.hash, mined.hash);
    assert_eq!(replacement.fork, 1);
    match observe(&sim, &t) {
        ChainObservation::Included { state, .. } => {
            assert_eq!(state.height, mined.height);
            assert_eq!(state.hash, Bytes(replacement.hash.to_vec()));
        }
        o => panic!("expected Included, got {o:?}"),
    }

    // Reorg dropping the tx: not included afterwards, state restored.
    sim.reorg(2, std::slice::from_ref(&t)).unwrap();
    assert!(matches!(observe(&sim, &t), ChainObservation::Submitted { .. }));
    assert!(sim.receipt(&t).unwrap().is_none());
    assert_eq!(sim.nonce(&sender), 0);
    assert_eq!(sim.balance(&DEST), 0);
    assert!(sim.mempool().is_empty());
    // Re-broadcast and re-mine: included again.
    sim.submit(&t_bytes).unwrap();
    let again = sim.mine().unwrap();
    assert!(matches!(observe(&sim, &t), ChainObservation::Included { state, .. } if state.height == again.height));
    assert_eq!(sim.balance(&DEST), 1_000);

    // Dropping something that is not in the reorganised range is refused.
    assert_eq!(sim.reorg(1, &[tx_id(&[1; 32])]).unwrap_err().code, ErrorCode::InvalidRequest);
}

#[test]
fn reorg_below_finalized_is_refused_and_atomic() {
    let (sim, _clock) = sim_with(2);
    sim.mine_blocks(5).unwrap();
    assert_eq!(sim.finalized_height(), 4);
    assert_eq!(sim.finalized().height, 4);
    let head = sim.head();
    assert_eq!(sim.reorg(2, &[]).unwrap_err().code, ErrorCode::ResourceConflict);
    assert_eq!(sim.reorg(0, &[]).unwrap_err().code, ErrorCode::InvalidRequest);
    assert_eq!(sim.head(), head);
    sim.reorg(1, &[]).unwrap();
    assert_eq!(sim.head().height, head.height);
    assert_ne!(sim.head().hash, head.hash);
}

#[test]
fn reorg_replays_system_operations() {
    let (sim, _clock) = sim_with(4);
    sim.mine().unwrap();
    let token = sim.deploy_erc20("DAI", 18, sim.faucet_address(), 10).unwrap();
    sim.mine().unwrap();
    sim.reorg(1, &[]).unwrap();
    assert_eq!(sim.block(2).unwrap().system_ops.len(), 1);
    assert_eq!(sim.erc20_balance(&token, &sim.faucet_address()).unwrap(), 10);
    let ev = sim.evidence(&EvmEvidenceQuery::latest().contract(token)).unwrap();
    assert_eq!(ev.items[&format!("code:{}", hex::encode(token))], Bytes(oic_adapter_evm::code_hash(ERC20_CODE_MARKER).to_vec()));
}

#[test]
fn prove_invalidation_when_nonce_consumed_by_other_tx() {
    let (sim, clock) = sim_with(2);
    let sk = key(11);
    let sender = funded(&sim, &sk, ETH);
    let t = native_transfer(&sim, &sk, 1_000);
    let (cand, signed) = build_and_sign(&sim, &clock, &t, &sk, "cand-a", &[]);
    // A different transaction consumes nonce 0 first.
    let (_, prio, _) = sim.fees();
    let other = sim.submit(&raw_tx(&sim, &sk, 0, [0x01; 20], 5, vec![], 21_000, prio)).unwrap();
    sim.mine().unwrap();
    // The candidate's broadcast is refused; the node remembers it.
    assert_eq!(sim.submit(signed.signed_bytes.as_slice()).unwrap_err().code, ErrorCode::ResourceConflict);
    let a = tx_hash(signed.signed_bytes.as_slice());
    let o = parse_tx_id(&other).unwrap();
    let query = |q: EvmEvidenceQuery| q.sender(sender).tx(a).tx(o).signed("cand-a", 1, signed.signed_bytes.0.clone());
    // Not yet finalized: Unknown.
    let ev = sim.evidence(&query(EvmEvidenceQuery::finalized())).unwrap();
    let fam = OperationFamilyId::unchecked("family-1");
    assert_eq!(EvmAdapter.prove_invalidation(&fam, std::slice::from_ref(&cand), &sim.profile(), &ev).unwrap(), InvalidationEvidence::Unknown);
    sim.mine_blocks(3).unwrap();
    let ev = sim.evidence(&query(EvmEvidenceQuery::finalized())).unwrap();
    assert_eq!(ev.state, sim.finalized());
    assert_eq!(get_tx_observation(&ev, &a).unwrap().nonce_consumed_by, Some(Bytes(o.to_vec())));
    match EvmAdapter.prove_invalidation(&fam, std::slice::from_ref(&cand), &sim.profile(), &ev).unwrap() {
        InvalidationEvidence::Definitive { state, .. } => assert_eq!(state, sim.finalized()),
        InvalidationEvidence::Unknown => panic!("expected definitive invalidation"),
    }
    // Latest-commitment evidence is never proof.
    let ev = sim.evidence(&query(EvmEvidenceQuery::latest())).unwrap();
    assert_eq!(EvmAdapter.prove_invalidation(&fam, &[cand], &sim.profile(), &ev).unwrap(), InvalidationEvidence::Unknown);
}

#[test]
fn never_broadcast_candidate_consumer_is_found_from_query() {
    let (sim, clock) = sim_with(2);
    let sk = key(12);
    let sender = funded(&sim, &sk, ETH);
    let t = native_transfer(&sim, &sk, 1_000);
    let (_, signed) = build_and_sign(&sim, &clock, &t, &sk, "cand-a", &[]);
    let (_, prio, _) = sim.fees();
    let other = sim.submit(&raw_tx(&sim, &sk, 0, [0x01; 20], 5, vec![], 21_000, prio)).unwrap();
    sim.mine().unwrap();
    let a = tx_hash(signed.signed_bytes.as_slice());
    let without = sim.evidence(&EvmEvidenceQuery::latest().tx(a)).unwrap();
    assert_eq!(get_tx_observation(&without, &a).unwrap().nonce_consumed_by, None);
    let with = sim.evidence(&EvmEvidenceQuery::latest().sender(sender).tx(a).signed("cand-a", 1, signed.signed_bytes.0.clone())).unwrap();
    assert_eq!(get_tx_observation(&with, &a).unwrap().nonce_consumed_by, Some(Bytes(parse_tx_id(&other).unwrap().to_vec())));
    assert_eq!(with.items["signed_tx:cand-a:1"], signed.signed_bytes);
    assert!(sim.evidence(&EvmEvidenceQuery::latest().signed("x", 1, vec![1, 2, 3])).is_err());
}

#[test]
fn conflicting_sources_a30() {
    let (sim, _clock) = sim_with(2);
    let sk = key(13);
    funded(&sim, &sk, ETH);
    let (_, prio, _) = sim.fees();
    let id = sim.submit(&raw_tx(&sim, &sk, 0, DEST, 1, vec![], 21_000, prio)).unwrap();
    let h = parse_tx_id(&id).unwrap();
    let liar = EvidenceSourceId::unchecked("devsim-evm-liar");
    let head = sim.head();
    let lie = TxObservation {
        included: true,
        block_height: head.height,
        block_hash: head.hash.clone(),
        success: true,
        gas_used: 21_000,
        effective_gas_price: Amount(1),
        confirmations: 10,
        nonce_consumed_by: None,
    };
    sim.set_lie(&liar, h, lie.clone()).unwrap();
    assert_eq!(sim.set_lie(&EvidenceSourceId::unchecked(SOURCE_ID), h, lie).unwrap_err().code, ErrorCode::InvalidRequest);
    let q = EvmEvidenceQuery::latest().tx(h);
    let honest = sim.evidence(&q).unwrap();
    let lying = sim.evidence_from(&liar, &q).unwrap();
    assert_ne!(honest.items, lying.items);
    assert_ne!(evidence_hash(&honest).unwrap(), evidence_hash(&lying).unwrap());
    assert_eq!(lying.sources, vec![liar.clone()]);
    let p = sim.profile();
    assert!(matches!(EvmAdapter.observe(&id, &p, &honest).unwrap(), ChainObservation::Submitted { .. }));
    assert!(matches!(EvmAdapter.observe(&id, &p, &lying).unwrap(), ChainObservation::Finalized { .. }));
    sim.clear_lies(&liar);
    assert_eq!(sim.evidence_from(&liar, &q).unwrap().items, honest.items);
}

fn script(seed: [u8; 32]) -> (Vec<[u8; 32]>, Hash32) {
    let clock = SimClock::new(UnixSeconds(1_800_000_000));
    let sim = EvmSimulator::new(EvmSimConfig { finality_depth: 3, ..EvmSimConfig::with_seed(seed) }, clock.clone()).unwrap();
    let sk = key(20);
    let a = address_of(&sk).unwrap();
    let token = sim.deploy_erc20("TKN", 6, sim.faucet_address(), 1_000_000).unwrap();
    sim.fund(a, ETH).unwrap();
    sim.erc20_fund(token, a, 1_000).unwrap();
    sim.mine().unwrap();
    clock.advance(12).unwrap();
    let (_, prio, _) = sim.fees();
    let t = sim.submit(&raw_tx(&sim, &sk, 0, token, 0, encode_transfer(&DEST, 10), 65_000, prio)).unwrap();
    sim.mine().unwrap();
    sim.mine().unwrap();
    sim.reorg(1, &[]).unwrap();
    let ev = sim.evidence(&EvmEvidenceQuery::latest().sender(a).contract(token).tx_id(&t).unwrap()).unwrap();
    let hashes = (0..=sim.head().height).map(|h| sim.block(h).unwrap().hash).collect();
    (hashes, evidence_hash(&ev).unwrap())
}

#[test]
fn deterministic_for_same_seed_and_script() {
    let a = script([1; 32]);
    let b = script([1; 32]);
    assert_eq!(a, b);
    let c = script([2; 32]);
    assert_ne!(a.0, c.0);
    assert_ne!(a.1, c.1);
}

#[test]
fn shareable_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EvmSimulator>();
    let (sim, _clock) = sim_with(2);
    let handles: Vec<_> = (0..4u8)
        .map(|i| {
            let s = Arc::clone(&sim);
            std::thread::spawn(move || s.fund([i + 1; 20], 10).unwrap())
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let b = sim.mine().unwrap();
    assert_eq!(b.transactions.len(), 4);
    assert_eq!(sim.nonce(&sim.faucet_address()), 4);
}
