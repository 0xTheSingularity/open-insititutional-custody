//! Shared scaffolding for the anvil-backed tests: a guarded anvil child on a
//! free port and a patient client connect. Each test binary that declares
//! `mod common;` compiles its own copy.
#![allow(dead_code)]

use k256::ecdsa::SigningKey;
use oic_adapter_api::SignedTransaction;
use oic_adapter_evm::evidence::{get_tx_observation, get_u128, get_u64, KEY_BASE_FEE, KEY_PRIORITY_FEE};
use oic_adapter_evm::tx::{tx_hash, Eip1559Tx};
use oic_chain_simulator::evm::{address_of, sign_eip1559};
use oic_domain_types::*;
use oic_service_broadcaster::{ChainClient, Commitment};
use oic_service_chain_rpc::evm::{EvmRpcClient, EvmRpcConfig};
use oic_service_reconciler::BlockSource;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Anvil account 0: the relayer. It pays gas; it is not an owner.
pub const RELAYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// Anvil's first well-known development account.
pub const DEV_KEY: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed,
    0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];

pub struct Anvil {
    child: Child,
    pub url: String,
}

impl Anvil {
    /// `None` when the binary is not installed.
    pub fn start() -> Option<Self> {
        let port = free_port();
        // One slot per epoch: the node's "finalized" tag then trails the
        // head by a block or two, so finality-driven logic is testable.
        let child = Command::new("anvil")
            .args(["--port", &port.to_string(), "--silent", "--slots-in-an-epoch", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        Some(Anvil { child, url: format!("http://127.0.0.1:{port}") })
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Run a CLI tool; `None` when the binary is not installed, panic on a
/// failed invocation of an installed one.
pub fn tool(name: &str, args: &[&str]) -> Option<String> {
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
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> [u8; 65] {
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

pub fn hex_addr(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

/// Compile QuorumVault from source and deploy it with the given owners from
/// anvil's unlocked relayer account; the vault address comes back.
pub fn deploy_vault(url: &str, owner_addrs: &[[u8; 20]; 3]) -> [u8; 20] {
    let contracts = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
    let out = tempfile::tempdir().unwrap();
    tool("forge", &["build", "--root", contracts.to_str().unwrap(), "--out", out.path().to_str().unwrap()]).unwrap();
    let artifact: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.path().join("QuorumVault.sol/QuorumVault.json")).unwrap())
            .unwrap();
    let bytecode = artifact["bytecode"]["object"].as_str().unwrap().to_string();
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
        &["send", "--rpc-url", url, "--unlocked", "--from", RELAYER_ADDRESS, "--json", "--create", &deployment],
    )
    .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    let mut vault = [0u8; 20];
    vault.copy_from_slice(&hex::decode(receipt["contractAddress"].as_str().unwrap().trim_start_matches("0x")).unwrap());
    vault
}

/// Sign with the relayer key at its live nonce, submit through the client,
/// and report the outcome with the inclusion height.
pub fn relay(client: &EvmRpcClient, to: [u8; 20], value: u128, data: Vec<u8>) -> (bool, u64) {
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
            return (observation.success, observation.block_height);
        }
        assert!(Instant::now() < deadline, "transaction {tx_id:?} was not included");
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn native_balance(client: &EvmRpcClient, address: [u8; 20]) -> u128 {
    let state = BlockSource::head(client);
    BlockSource::balance(client, &state, &Bytes(address.to_vec()), &AssetKind::Native).unwrap().0
}

pub fn connect(url: &str) -> EvmRpcClient {
    connect_with(url, |_| {})
}

pub fn connect_with(url: &str, configure: impl Fn(&mut EvmRpcConfig)) -> EvmRpcClient {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut cfg = EvmRpcConfig::development(url);
        configure(&mut cfg);
        match EvmRpcClient::connect(cfg) {
            Ok(client) => return client,
            Err(e) => {
                assert!(Instant::now() < deadline, "anvil did not come up: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}
