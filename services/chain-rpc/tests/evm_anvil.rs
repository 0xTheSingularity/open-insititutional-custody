//! End-to-end checks against a real anvil node: submit, observe, discover and
//! settle a native transfer through the standard JSON-RPC API.
//!
//! Requires the `anvil` binary (Foundry). When it is absent the test prints a
//! skip notice and passes, so developer machines without Foundry stay green;
//! CI installs Foundry and runs it for real.
//!
//! Signing honesty: this loop signs with one development k256 key, exactly
//! like the EVM simulator. The repository has no reviewed threshold-ECDSA
//! backend (RFC 0002 §3.1); the Solana loop is threshold-signed with FROST,
//! and evm_vault.rs gets the same no-single-signer property on EVM from an
//! on-chain 2-of-3 quorum instead.

use oic_adapter_evm::evidence::{get_tx_observation, get_u128, get_u64, KEY_BASE_FEE, KEY_CHAIN_ID, KEY_GAS_LIMIT, KEY_PRIORITY_FEE};
use oic_adapter_evm::tx::{tx_hash, Eip1559Tx};
use oic_adapter_api::SignedTransaction;
use oic_chain_simulator::evm::{address_of, sign_eip1559, GAS_NATIVE_TRANSFER};
use oic_domain_types::*;
use oic_service_broadcaster::{ChainClient, Commitment, PossiblyIssued};
use oic_service_chain_rpc::evm::EvmRpcClient;
use oic_service_reconciler::{BlockSource, EffectKind};
use std::time::{Duration, Instant};

mod common;
use common::{connect, Anvil, DEV_KEY};

#[test]
fn real_node_native_transfer_submit_observe_discover_and_settle() {
    let Some(anvil) = Anvil::start() else {
        eprintln!("SKIPPED: the `anvil` binary is not installed; install Foundry to run this test");
        return;
    };
    let client = connect(&anvil.url);
    assert_eq!(client.chain_id(), 31_337);
    let profile = client.profile();
    assert_eq!(profile.network_id.as_str(), "evm-31337");

    // Build evidence carries the adapter-documented fee and nonce items.
    let key = k256::ecdsa::SigningKey::from_bytes((&DEV_KEY).into()).unwrap();
    let sender = address_of(&key).unwrap();
    let build = client.build_evidence(&[sender], &[], Commitment::Latest).unwrap();
    assert_eq!(get_u64(&build, KEY_CHAIN_ID).unwrap(), 31_337);
    assert_eq!(get_u64(&build, &format!("nonce:{}", hex::encode(sender))).unwrap(), 0);
    let base_fee = get_u128(&build, KEY_BASE_FEE).unwrap();
    let priority = get_u128(&build, KEY_PRIORITY_FEE).unwrap();
    assert!(get_u64(&build, KEY_GAS_LIMIT).unwrap() >= GAS_NATIVE_TRANSFER);

    // Sign and submit a real native transfer. One dev key signs: the
    // repository has no threshold-ECDSA backend (see the module docs).
    let beneficiary: [u8; 20] = [0x42; 20];
    let tx = Eip1559Tx {
        chain_id: 31_337,
        nonce: 0,
        max_priority_fee_per_gas: priority,
        max_fee_per_gas: base_fee * 2 + priority,
        gas_limit: GAS_NATIVE_TRANSFER,
        to: beneficiary,
        value: 1_000_000_000_000_000_000, // 1 ether
        data: Vec::new(),
        access_list: Vec::new(),
    };
    let signed_bytes = sign_eip1559(&key, &tx).unwrap();
    let hash = tx_hash(&signed_bytes);
    let signed = SignedTransaction {
        candidate_id: CandidateId::unchecked("real-evm-1"),
        candidate_revision: 1,
        signed_bytes: Bytes(signed_bytes.clone()),
        chain_tx_id: oic_chain_simulator::evm::tx_id(&hash),
    };
    let tx_id = client.submit(&signed).unwrap();
    assert_eq!(tx_id, signed.chain_tx_id);

    // Observation: included, successful, and canonically encoded for the adapter.
    let evidence = wait_included(&client, &tx_id, &hash);
    let obs = get_tx_observation(&evidence, &hash).unwrap();
    assert!(obs.success, "transfer must execute successfully");
    assert!(obs.confirmations >= 1);
    assert_eq!(obs.gas_used, GAS_NATIVE_TRANSFER);

    // The candidate path adds the sender nonce and echoes the signed bytes.
    let candidate = dummy_candidate();
    let by_candidates = client
        .evidence_for_candidates(
            &client.sources()[0],
            &[PossiblyIssued { candidate: candidate.clone(), signed: signed.clone() }],
            Commitment::Latest,
        )
        .unwrap();
    assert_eq!(get_u64(&by_candidates, &format!("nonce:{}", hex::encode(sender))).unwrap(), 1);
    assert_eq!(
        by_candidates.items.get("signed_tx:real-evm-1:1").map(|b| b.as_slice()),
        Some(signed_bytes.as_slice())
    );
    assert!(get_tx_observation(&by_candidates, &hash).unwrap().included);

    // An unknown transaction reports a not-included observation, not an error.
    let unknown = client
        .evidence_for_tx(&client.sources()[0], &oic_chain_simulator::evm::tx_id(&[0x77; 32]), Commitment::Latest)
        .unwrap();
    assert!(!get_tx_observation(&unknown, &[0x77; 32]).unwrap().included);

    // Discovery: the inclusion block yields the fee leg and both value legs.
    let included = get_tx_observation(&evidence, &hash).unwrap();
    let block = BlockSource::block(&client, included.block_height).unwrap();
    let fee = block
        .effects
        .iter()
        .find(|e| e.kind == EffectKind::Fee)
        .expect("fee effect");
    assert_eq!(fee.address.as_slice(), sender.as_slice());
    assert_eq!(fee.amount.0, u128::from(obs.gas_used) * obs.effective_gas_price.0);
    let legs: Vec<_> = block.effects.iter().filter(|e| e.kind == EffectKind::Transfer).collect();
    assert_eq!(legs.len(), 2, "outbound and inbound native legs");
    assert!(legs.iter().all(|e| e.amount.0 == tx.value));

    // Settlement: the beneficiary's balance at the inclusion state.
    let state = StateReference {
        height: included.block_height,
        hash: included.block_hash.clone(),
        commitment: "latest".into(),
    };
    let balance = BlockSource::balance(&client, &state, &Bytes(beneficiary.to_vec()), &AssetKind::Native).unwrap();
    assert_eq!(balance.0, tx.value);

    println!(
        "anvil loop: chain_id=31337 tx={} block={} gas_used={} fee={} beneficiary_balance={}",
        tx_id,
        included.block_height,
        obs.gas_used,
        fee.amount.0,
        balance.0
    );
}

/// Anvil automines, but give the receipt a bounded moment to appear.
fn wait_included(client: &EvmRpcClient, tx_id: &ChainTxId, hash: &[u8; 32]) -> EvidenceBundle {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let evidence = client.evidence_for_tx(&client.sources()[0], tx_id, Commitment::Latest).unwrap();
        if get_tx_observation(&evidence, hash).unwrap().included {
            return evidence;
        }
        assert!(Instant::now() < deadline, "transaction was never included");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Only the id and revision reach the evidence item key; the rest is inert.
fn dummy_candidate() -> Candidate {
    Candidate {
        candidate_id: CandidateId::unchecked("real-evm-1"),
        candidate_revision: 1,
        intent_id: IntentId::unchecked("intent-real-evm"),
        operation_family_id: OperationFamilyId::unchecked("fam-real-evm"),
        chain_profile_id: ChainProfileId::unchecked("evm-rpc-v1"),
        adapter_id: AdapterId::unchecked("evm"),
        adapter_version: "eip1559-type2".into(),
        native_unsigned_bytes: Bytes(Vec::new()),
        signing_payloads: Vec::new(),
        evidence_bundle_hash: Hash32::ZERO,
        built_at: UnixSeconds(0),
    }
}
