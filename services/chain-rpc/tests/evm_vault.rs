//! The EVM money loop with no single signing machine: a 2-of-3 QuorumVault
//! on a real anvil node. Three owner keys live on three (simulated) nodes;
//! the chain enforces the quorum, so one machine's key moves nothing. A
//! relayer key pays gas and has no custody power (RFC 0002 §9: the audited
//! threshold-ECDSA decision stays open; this is the reviewed-primitives-only
//! route to a threshold EVM loop).
//!
//! Needs `anvil`, `forge` and `cast` (Foundry). Absent binaries print a
//! skip notice; CI installs them and fails on skips.
//!
//! Discovery honesty: the vault pays the beneficiary through an internal
//! call, which carries no transaction value, so block-effect discovery does
//! not see it (that needs trace APIs, a known gap shared with the
//! simulator). Settlement is proven by balances at a settled state instead.

use k256::ecdsa::SigningKey;
use oic_adapter_evm::evidence::{get_tx_observation, get_u128, get_u64, KEY_BASE_FEE, KEY_PRIORITY_FEE};
use oic_adapter_evm::tx::{tx_hash, Eip1559Tx};
use oic_adapter_api::SignedTransaction;
use oic_chain_simulator::evm::{address_of, sign_eip1559};
use oic_domain_types::*;
use oic_service_broadcaster::{ChainClient, Commitment};
use oic_service_chain_rpc::evm::EvmRpcClient;
use oic_service_reconciler::BlockSource;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

mod common;
use common::{connect, Anvil, DEV_KEY};

/// Anvil account 0: the relayer. It pays gas; it is not an owner.
const RELAYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

fn tool(name: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(name).args(args).output().ok()?;
    assert!(
        output.status.success(),
        "{name} {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8(output.stdout).unwrap().trim().to_string())
}

/// 65-byte r||s||v signature over a prehashed digest, low-s, v in {27, 28} —
/// exactly what one custody node contributes for its own owner key.
fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> [u8; 65] {
    let (mut sig, mut recid) = key.sign_prehash_recoverable(digest).unwrap();
    if let Some(normalized) = sig.normalize_s() {
        sig = normalized;
        recid = k256::ecdsa::RecoveryId::from_byte(recid.to_byte() ^ 1).unwrap();
    }
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + recid.to_byte();
    out
}

fn hex_addr(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

/// Sign with the relayer key at its live nonce and submit through the client.
fn relay(client: &EvmRpcClient, to: [u8; 20], value: u128, data: Vec<u8>) -> bool {
    let key = SigningKey::from_bytes((&DEV_KEY).into()).unwrap();
    let sender = address_of(&key).unwrap();
    let build = client.build_evidence(&[sender], &[], Commitment::Latest).unwrap();
    let base_fee = get_u128(&build, KEY_BASE_FEE).unwrap();
    let priority = get_u128(&build, KEY_PRIORITY_FEE).unwrap();
    let nonce = get_u64(&build, &format!("nonce:{}", hex::encode(sender))).unwrap();
    let tx = Eip1559Tx {
        chain_id: client.chain_id(),
        nonce,
        max_priority_fee_per_gas: priority,
        max_fee_per_gas: base_fee * 2 + priority,
        gas_limit: 200_000, // execute(): two ecrecover calls plus one value call
        to,
        value,
        data,
        access_list: Vec::new(),
    };
    let signed_bytes = sign_eip1559(&key, &tx).unwrap();
    let hash = tx_hash(&signed_bytes);
    let signed = SignedTransaction {
        candidate_id: CandidateId::unchecked(format!("vault-relay-{nonce}")),
        candidate_revision: 1,
        signed_bytes: Bytes(signed_bytes),
        chain_tx_id: oic_chain_simulator::evm::tx_id(&hash),
    };
    let tx_id = client.submit(&signed).unwrap();

    // The observation decides: included and successful, or included and
    // reverted. Reverts still consume the nonce and mine, so both paths
    // exercise the client's receipt handling.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let bundle = client.evidence_for_tx(&client.sources()[0], &tx_id, Commitment::Latest).unwrap();
        let observation = get_tx_observation(&bundle, &hash).unwrap();
        if observation.included {
            return observation.success;
        }
        assert!(Instant::now() < deadline, "transaction {tx_id:?} was not included");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn native_balance(client: &EvmRpcClient, address: [u8; 20]) -> u128 {
    let state = BlockSource::head(client);
    BlockSource::balance(client, &state, &Bytes(address.to_vec()), &AssetKind::Native).unwrap().0
}

#[test]
fn quorum_vault_withdrawal_needs_two_of_three_owners() {
    let Some(anvil) = Anvil::start() else {
        eprintln!("SKIPPED: the `anvil` binary is not installed; install Foundry to run this test");
        return;
    };
    if tool("forge", &["--version"]).is_none() || tool("cast", &["--version"]).is_none() {
        eprintln!("SKIPPED: `forge`/`cast` are not installed; install Foundry to run this test");
        return;
    }

    // Compile the vault from source, so reviewers never trust checked-in
    // bytecode.
    let contracts = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
    let out = tempfile::tempdir().unwrap();
    tool("forge", &["build", "--root", contracts.to_str().unwrap(), "--out", out.path().to_str().unwrap()]).unwrap();
    let artifact: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.path().join("QuorumVault.sol/QuorumVault.json")).unwrap())
            .unwrap();
    let bytecode = artifact["bytecode"]["object"].as_str().unwrap().to_string();

    // Three owner keys: in production each lives sealed on its own node, so
    // no single machine holds a quorum.
    let owners: Vec<SigningKey> =
        [[0x11u8; 32], [0x22; 32], [0x33; 32]].iter().map(|b| SigningKey::from_bytes(b.into()).unwrap()).collect();
    let owner_addrs: Vec<[u8; 20]> = owners.iter().map(|k| address_of(k).unwrap()).collect();

    let args = tool(
        "cast",
        &[
            "abi-encode",
            "constructor(address,address,address)",
            &hex_addr(&owner_addrs[0]),
            &hex_addr(&owner_addrs[1]),
            &hex_addr(&owner_addrs[2]),
        ],
    )
    .unwrap();
    let deployment = format!("{bytecode}{}", args.trim_start_matches("0x"));
    let receipt = tool(
        "cast",
        &["send", "--rpc-url", &anvil.url, "--unlocked", "--from", RELAYER_ADDRESS, "--json", "--create", &deployment],
    )
    .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    let vault_hex = receipt["contractAddress"].as_str().unwrap().to_string();
    let mut vault = [0u8; 20];
    vault.copy_from_slice(&hex::decode(vault_hex.trim_start_matches("0x")).unwrap());

    let client = connect(&anvil.url);

    // Deposit one ether into custody.
    let one_ether: u128 = 1_000_000_000_000_000_000;
    assert!(relay(&client, vault, one_ether, Vec::new()), "the deposit reverted");
    assert_eq!(native_balance(&client, vault), one_ether);

    // Withdrawal: owners 0 and 2 (an arbitrary quorum pair, as in the Solana
    // loop) sign the on-chain digest for 0.6 ether to the beneficiary.
    let beneficiary = [0x42u8; 20];
    let value = 600_000_000_000_000_000u128;
    let digest_hex = tool(
        "cast",
        &["call", "--rpc-url", &anvil.url, &vault_hex, "digest(address,uint256,bytes)(bytes32)", &hex_addr(&beneficiary), &value.to_string(), "0x"],
    )
    .unwrap();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hex::decode(digest_hex.trim_start_matches("0x")).unwrap());
    let sig0 = sign_digest(&owners[0], &digest);
    let sig2 = sign_digest(&owners[2], &digest);

    let execute = |sig_a: &[u8; 65], sig_b: &[u8; 65]| -> Vec<u8> {
        let calldata = tool(
            "cast",
            &[
                "calldata",
                "execute(address,uint256,bytes,bytes,bytes)",
                &hex_addr(&beneficiary),
                &value.to_string(),
                "0x",
                &format!("0x{}", hex::encode(sig_a)),
                &format!("0x{}", hex::encode(sig_b)),
            ],
        )
        .unwrap();
        hex::decode(calldata.trim_start_matches("0x")).unwrap()
    };

    // One owner alone (duplicated signature) must not move funds.
    assert!(!relay(&client, vault, 0, execute(&sig0, &sig0)), "a single owner moved funds");
    // A non-owner co-signature must not move funds.
    let outsider = SigningKey::from_bytes((&[0x44u8; 32]).into()).unwrap();
    assert!(!relay(&client, vault, 0, execute(&sig0, &sign_digest(&outsider, &digest))), "a non-owner moved funds");
    assert_eq!(native_balance(&client, vault), one_ether);

    // The real quorum succeeds exactly once: the nonce in the digest makes
    // the signatures single-use, so the replay reverts.
    let calldata = execute(&sig0, &sig2);
    assert!(relay(&client, vault, 0, calldata.clone()), "the quorum withdrawal reverted");
    assert_eq!(native_balance(&client, vault), one_ether - value);
    assert_eq!(native_balance(&client, beneficiary), value);
    assert!(!relay(&client, vault, 0, calldata), "a replayed authorization moved funds");
    assert_eq!(native_balance(&client, vault), one_ether - value);
}
