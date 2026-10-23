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
//! Discovery: the vault pays the beneficiary through an internal call,
//! which carries no transaction value. With `trace_internal_transfers` on,
//! the client discovers that movement from callTracer traces, and this test
//! asserts the vault-to-beneficiary leg at the withdrawal block. On
//! providers without debug APIs the gap remains (the option then fails
//! loudly), so balance-based settlement stays asserted as well.

use k256::ecdsa::SigningKey;
use oic_chain_simulator::evm::address_of;
use oic_domain_types::*;
use oic_service_reconciler::BlockSource;

mod common;
use common::{connect_with, deploy_vault, hex_addr, native_balance, relay, sign_digest, tool, Anvil};

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

    // Three owner keys: in production each lives sealed on its own node, so
    // no single machine holds a quorum. The shared helper compiles the vault
    // from source and deploys it, so reviewers never trust checked-in bytecode.
    let owners: Vec<SigningKey> =
        [[0x11u8; 32], [0x22; 32], [0x33; 32]].iter().map(|b| SigningKey::from_bytes(b.into()).unwrap()).collect();
    let owner_addrs: Vec<[u8; 20]> = owners.iter().map(|k| address_of(k).unwrap()).collect();
    let vault = deploy_vault(&anvil.url, &[owner_addrs[0], owner_addrs[1], owner_addrs[2]]);
    let vault_hex = hex_addr(&vault);

    // Tracing on: this test's withdrawal moves value in an internal call,
    // and discovery must see it.
    let client = connect_with(&anvil.url, |cfg| cfg.trace_internal_transfers = true);

    // Deposit one ether into custody.
    let one_ether: u128 = 1_000_000_000_000_000_000;
    assert!(relay(&client, vault, one_ether, Vec::new()).0, "the deposit reverted");
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
    assert!(!relay(&client, vault, 0, execute(&sig0, &sig0)).0, "a single owner moved funds");
    // A non-owner co-signature must not move funds.
    let outsider = SigningKey::from_bytes((&[0x44u8; 32]).into()).unwrap();
    assert!(!relay(&client, vault, 0, execute(&sig0, &sign_digest(&outsider, &digest))).0, "a non-owner moved funds");
    assert_eq!(native_balance(&client, vault), one_ether);

    // The real quorum succeeds exactly once: the nonce in the digest makes
    // the signatures single-use, so the replay reverts.
    let calldata = execute(&sig0, &sig2);
    let (ok, withdrawal_height) = relay(&client, vault, 0, calldata.clone());
    assert!(ok, "the quorum withdrawal reverted");
    assert_eq!(native_balance(&client, vault), one_ether - value);
    assert_eq!(native_balance(&client, beneficiary), value);
    assert!(!relay(&client, vault, 0, calldata).0, "a replayed authorization moved funds");
    assert_eq!(native_balance(&client, vault), one_ether - value);

    // Trace-based discovery sees the internal payment as a movement pair at
    // the withdrawal block: the vault outbound, the beneficiary inbound.
    let block = BlockSource::block(&client, withdrawal_height).unwrap();
    let internal: Vec<_> =
        block.effects.iter().filter(|e| e.mechanism == DiscoveryMechanism::EvmInternalCallValue).collect();
    assert_eq!(internal.len(), 2, "expected exactly the vault's internal payment, got {internal:?}");
    for (leg, address, counterparty) in
        [(internal[0], vault, beneficiary), (internal[1], beneficiary, vault)]
    {
        assert_eq!(leg.address.as_slice(), address);
        assert_eq!(leg.counterparty.as_slice(), counterparty);
        assert_eq!(leg.amount.0, value);
        assert_eq!(leg.asset, AssetKind::Native);
    }
    assert_eq!(internal[0].direction, MovementDirection::Outbound);
    assert_eq!(internal[1].direction, MovementDirection::Inbound);
}
