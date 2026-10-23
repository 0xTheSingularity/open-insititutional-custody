//! End-to-end checks against a real `solana-test-validator`: a FROST 2-of-3
//! threshold-signed native transfer is submitted, observed, discovered and
//! settled through the standard RPC API.
//!
//! This is the genuinely threshold-signed loop: distributed key generation
//! runs across three providers, two of them sign, and the aggregated Ed25519
//! signature is verified by the real validator. No participant ever holds the
//! group's private key.
//!
//! Requires the `solana-test-validator` binary. When it is absent the test
//! prints a skip notice and passes; CI installs the Solana tools and runs it
//! for real.

use oic_adapter_solana::address::{to_base58, Pubkey, SYSTEM_PROGRAM_ID};
use oic_adapter_solana::evidence::{
    get_hash, get_tx_observation, get_u64, KEY_BLOCKHASH_LAST_VALID_HEIGHT, KEY_GENESIS_HASH, KEY_LAMPORTS_PER_SIGNATURE,
    KEY_RECENT_BLOCKHASH, KEY_RENT_TOKEN_ACCOUNT,
};
use oic_adapter_solana::message::{CompiledInstruction, Message, MessageHeader, MessageVersion, Transaction};
use oic_adapter_api::SignedTransaction;
use oic_crypto_provider::{CryptoProvider as _, KeygenCeremony, PeerMessage, ProtocolStep};
use oic_crypto_provider_frost_ed25519::{build_signing_package, run_dkg, FrostEd25519Provider, PROTOCOL_VERSION};
use oic_domain_types::*;
use oic_one_time_state_ledger::InMemoryLedger;
use oic_service_broadcaster::{ChainClient, Commitment, PossiblyIssued};
use oic_service_chain_rpc::solana::{SolanaRpcClient, SolanaRpcConfig};
use oic_service_reconciler::{BlockSource, EffectKind};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TRANSFER_LAMPORTS: u64 = 1_000_000_000; // 1 SOL

struct Validator {
    child: Child,
    url: String,
    _ledger: tempfile::TempDir,
}

impl Validator {
    /// `None` when the binary is not installed. `mint` owns the genesis supply.
    fn start(mint: &Pubkey) -> Option<Self> {
        let ledger = tempfile::tempdir().unwrap();
        let rpc_port = free_port();
        let child = Command::new("solana-test-validator")
            .args([
                "--reset",
                "--quiet",
                "--bind-address",
                "127.0.0.1",
                "--rpc-port",
                &rpc_port.to_string(),
                "--faucet-port",
                &free_port().to_string(),
                "--gossip-port",
                &free_port().to_string(),
                "--ledger",
                ledger.path().to_str().unwrap(),
                "--mint",
                &to_base58(mint),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        Some(Validator { child, url: format!("http://127.0.0.1:{rpc_port}"), _ledger: ledger })
    }
}

impl Drop for Validator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn connect(url: &str) -> SolanaRpcClient {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match SolanaRpcClient::connect(SolanaRpcConfig::development(url)) {
            Ok(client) => return client,
            Err(e) => {
                assert!(Instant::now() < deadline, "solana-test-validator did not come up: {e}");
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FROST 2-of-3 over the transaction message (the provider's documented flow).
// ---------------------------------------------------------------------------

fn key_id() -> KeyId {
    KeyId::unchecked("real-solana-custody-key")
}

fn frost_providers() -> Vec<FrostEd25519Provider> {
    (0..3)
        .map(|i| {
            FrostEd25519Provider::new(
                ParticipantId::unchecked(format!("signer-{i}")),
                [i as u8 + 1; 32],
                Box::new(StdRng::seed_from_u64(7_000 + i as u64)),
            )
            .unwrap()
        })
        .collect()
}

fn ceremony(providers: &[FrostEd25519Provider]) -> KeygenCeremony {
    KeygenCeremony {
        key_id: key_id(),
        key_epoch: Epoch(1),
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        participants: providers.iter().map(|p| p.participant().clone()).collect(),
        threshold: 2,
        networks: vec![NetworkId::unchecked("solana-local")],
        recovery_profile: "test".into(),
    }
}

/// Sign `message` with exactly the two given providers.
fn frost_sign(signers: [&FrostEd25519Provider; 2], message: &[u8]) -> [u8; 64] {
    let session = SigningSessionId::unchecked("real-validator-transfer");
    let payload = NativeSigningPayload {
        payload_index: 0,
        scheme_id: SchemeId::Ed25519Pure,
        message_or_digest: Bytes(message.to_vec()),
        required_key_id: key_id(),
        native_signing_context: "solana-message-legacy".into(),
    };
    let set: Vec<ParticipantId> = signers.iter().map(|s| s.participant().clone()).collect();
    let ledgers: Vec<InMemoryLedger> = signers.iter().map(|_| InMemoryLedger::new()).collect();
    let mut round1 = Vec::new();
    for (s, ledger) in signers.iter().zip(&ledgers) {
        match s.start_signing_session(&session, &key_id(), &payload, &set, ledger, Epoch(1)).unwrap() {
            ProtocolStep::Send(msgs) => round1.extend(msgs),
            other => panic!("unexpected {other:?}"),
        }
    }
    for m in &round1 {
        for (s, ledger) in signers.iter().zip(&ledgers) {
            if s.participant() != &m.from {
                assert_eq!(s.advance_protocol(&session, m, ledger).unwrap(), ProtocolStep::Waiting);
            }
        }
    }
    let commitments: Vec<(ParticipantId, Bytes)> = round1.iter().map(|m| (m.from.clone(), m.payload.clone())).collect();
    let package = build_signing_package(&commitments, message).unwrap();
    let shares: Vec<(ParticipantId, Bytes)> = signers
        .iter()
        .zip(&ledgers)
        .map(|(s, ledger)| {
            let m = PeerMessage {
                session_id: session.clone(),
                key_id: key_id(),
                key_epoch: Epoch(1),
                from: ParticipantId::unchecked("coordinator"),
                from_generation: Epoch(1),
                to: Some(s.participant().clone()),
                round: 2,
                sequence: 10,
                protocol_version: PROTOCOL_VERSION.into(),
                payload: package.clone(),
            };
            match s.advance_protocol(&session, &m, ledger).unwrap() {
                ProtocolStep::Share(b) => (s.participant().clone(), b),
                other => panic!("unexpected {other:?}"),
            }
        })
        .collect();
    let signature = signers[0].aggregate(&session, &shares).unwrap();
    signature.bytes.as_slice().try_into().expect("64-byte Ed25519 signature")
}

/// Legacy native transfer: `from` pays `lamports` to `to`.
fn transfer_message(from: Pubkey, to: Pubkey, lamports: u64, recent_blockhash: [u8; 32]) -> Message {
    let mut data = 2u32.to_le_bytes().to_vec(); // SystemInstruction::Transfer
    data.extend_from_slice(&lamports.to_le_bytes());
    Message {
        version: MessageVersion::Legacy,
        header: MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 },
        account_keys: vec![from, to, SYSTEM_PROGRAM_ID],
        recent_blockhash,
        instructions: vec![CompiledInstruction { program_id_index: 2, accounts: vec![0, 1], data }],
        address_table_lookups: Vec::new(),
    }
}

#[test]
fn real_validator_frost_2_of_3_native_transfer() {
    // Distributed key generation first: the group key is the custody address
    // the validator's genesis supply is minted to.
    let providers = frost_providers();
    let dkg = run_dkg(&providers.iter().collect::<Vec<_>>(), &ceremony(&providers)).unwrap();
    let custody: Pubkey = dkg.descriptor.public_key.bytes.as_slice().try_into().unwrap();

    let Some(validator) = Validator::start(&custody) else {
        eprintln!("SKIPPED: the `solana-test-validator` binary is not installed; install the Solana tools to run this test");
        return;
    };
    let client = connect(&validator.url);

    // Build evidence carries the adapter-documented items.
    let build = client.build_evidence(&[], Commitment::Latest).unwrap();
    assert_eq!(get_hash(&build, KEY_GENESIS_HASH).unwrap(), client.genesis_hash());
    let recent_blockhash = get_hash(&build, KEY_RECENT_BLOCKHASH).unwrap();
    assert!(get_u64(&build, KEY_BLOCKHASH_LAST_VALID_HEIGHT).unwrap() > 0);
    assert_eq!(get_u64(&build, KEY_LAMPORTS_PER_SIGNATURE).unwrap(), 5_000);
    assert!(get_u64(&build, KEY_RENT_TOKEN_ACCOUNT).unwrap() > 0);

    // Two of three signers cooperate; no machine ever holds the group key.
    let beneficiary: Pubkey = [0x42; 32];
    let message = transfer_message(custody, beneficiary, TRANSFER_LAMPORTS, recent_blockhash);
    let message_bytes = message.encode();
    let signature = frost_sign([&providers[0], &providers[2]], &message_bytes);

    let mut wire = vec![1u8];
    wire.extend_from_slice(&signature);
    wire.extend_from_slice(&message_bytes);
    let decoded = Transaction::decode(&wire).unwrap();
    assert_eq!(decoded.signatures[0], signature);

    let signed = SignedTransaction {
        candidate_id: CandidateId::unchecked("real-sol-1"),
        candidate_revision: 1,
        signed_bytes: Bytes(wire.clone()),
        chain_tx_id: oic_chain_simulator::solana::tx_id(&signature),
    };
    let tx_id = client.submit(&signed).unwrap();
    assert_eq!(tx_id, signed.chain_tx_id);

    // Observation: the validator accepted the aggregated threshold signature.
    let evidence = wait_observed(&client, &tx_id, &signature);
    let obs = get_tx_observation(&evidence, &signature).unwrap();
    assert!(obs.success, "threshold-signed transfer must execute: {:?}", obs.err);
    // The test validator's fee governor ramps from zero, so the observed fee
    // is checked for consistency with discovery below, not for a constant.
    assert_eq!(obs.account_funding, 0);

    // The candidate path echoes the signed bytes next to the observation.
    let by_candidates = client
        .evidence_for_candidates(
            &client.sources()[0],
            &[PossiblyIssued { candidate: dummy_candidate(), signed: signed.clone() }],
            Commitment::Latest,
        )
        .unwrap();
    assert_eq!(by_candidates.items.get("signed_tx:real-sol-1:1").map(|b| b.as_slice()), Some(wire.as_slice()));
    assert!(get_tx_observation(&by_candidates, &signature).is_ok());

    // Discovery: the inclusion slot yields both native legs, plus the fee leg
    // exactly when a fee was charged, and the two paths must agree on it.
    // The same block legitimately holds the validator's own vote
    // transactions, so every assertion is scoped to this transfer's id.
    let block = BlockSource::block(&client, obs.slot).unwrap();
    let mine: Vec<_> = block.effects.iter().filter(|e| e.tx_id == tx_id).collect();
    let fee_paid = match mine.iter().find(|e| e.kind == EffectKind::Fee) {
        Some(fee) => {
            assert_eq!(fee.address.as_slice(), custody.as_slice());
            fee.amount.0
        }
        None => 0,
    };
    assert_eq!(fee_paid, obs.fee as u128, "discovery and observation disagree on the fee");
    let out = mine
        .iter()
        .find(|e| e.kind == EffectKind::Transfer && e.address.as_slice() == custody.as_slice())
        .expect("custody outbound leg");
    assert_eq!(out.direction, MovementDirection::Outbound);
    assert_eq!(out.amount.0, TRANSFER_LAMPORTS as u128);
    let inbound = mine
        .iter()
        .find(|e| e.kind == EffectKind::Transfer && e.address.as_slice() == beneficiary.as_slice())
        .expect("beneficiary inbound leg");
    assert_eq!(inbound.direction, MovementDirection::Inbound);
    assert_eq!(inbound.amount.0, TRANSFER_LAMPORTS as u128);

    // Settlement: plain RPC serves balances only at the node's current slot,
    // so take a fresh head checkpoint and retry the slot race briefly.
    let balance = settled_balance(&client, &beneficiary);
    assert_eq!(balance, TRANSFER_LAMPORTS as u128);

    println!(
        "validator loop: custody={} tx={} slot={} fee={} beneficiary_balance={} (FROST 2-of-3, signers 0+2)",
        to_base58(&custody),
        tx_id,
        obs.slot,
        fee_paid,
        balance
    );
}

/// The observation appears once the transaction reaches `confirmed`.
fn wait_observed(client: &SolanaRpcClient, tx_id: &ChainTxId, signature: &[u8; 64]) -> EvidenceBundle {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let evidence = client.evidence_for_tx(&client.sources()[0], tx_id, Commitment::Latest).unwrap();
        if get_tx_observation(&evidence, signature).is_ok() {
            return evidence;
        }
        assert!(Instant::now() < deadline, "transaction was never observed");
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn settled_balance(client: &SolanaRpcClient, address: &Pubkey) -> u128 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let state = BlockSource::head(client);
        match BlockSource::balance(client, &state, &Bytes(address.to_vec()), &AssetKind::Native) {
            Ok(amount) => return amount.0,
            Err(e) => {
                assert!(Instant::now() < deadline, "balance never settled: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// Only the id and revision reach the evidence item key; the rest is inert.
fn dummy_candidate() -> Candidate {
    Candidate {
        candidate_id: CandidateId::unchecked("real-sol-1"),
        candidate_revision: 1,
        intent_id: IntentId::unchecked("intent-real-sol"),
        operation_family_id: OperationFamilyId::unchecked("fam-real-sol"),
        chain_profile_id: ChainProfileId::unchecked("solana-rpc-v1"),
        adapter_id: AdapterId::unchecked("solana"),
        adapter_version: "legacy".into(),
        native_unsigned_bytes: Bytes(Vec::new()),
        signing_payloads: Vec::new(),
        evidence_bundle_hash: Hash32::ZERO,
        built_at: UnixSeconds(0),
    }
}
