//! The reconciler's intake loop fed only by a live node through the real
//! client: enroll the quorum vault as a custody deposit address, watch a
//! real deposit become settled holdings at real finality, then watch a
//! quorum withdrawal leave through an internal call — visible to discovery
//! only via traces — and require reconciliation to surface the unlinked
//! outflow instead of reconciling clean.
//!
//! This is the live-node counterpart of the simulator money-loop suite in
//! services/reconciler/tests/money_loop.rs; the full coordinator path
//! (policy, authority, FROST issuance) stays there and in the rfc002 work.
//! Needs `anvil`, `forge` and `cast`; skips with a notice when absent.

use ed25519_dalek::SigningKey as AuditKey;
use k256::ecdsa::SigningKey;
use oic_chain_simulator::evm::address_of;
use oic_domain_types::*;
use oic_service_reconciler::*;
use std::collections::BTreeMap;
use std::sync::Arc;

mod common;
use common::{connect_with, deploy_vault, hex_addr, native_balance, relay, sign_digest, tool, Anvil};

const ONE_ETHER: u128 = 1_000_000_000_000_000_000;

fn institution() -> InstitutionId {
    InstitutionId::unchecked("live-institution")
}

fn environment() -> EnvironmentId {
    EnvironmentId::unchecked("live-env")
}

fn mine(url: &str, blocks: &str) {
    tool("cast", &["rpc", "--rpc-url", url, "anvil_mine", blocks]).unwrap();
}

#[test]
fn live_reconciler_settles_the_deposit_and_surfaces_the_unlinked_outflow() {
    let Some(anvil) = Anvil::start() else {
        eprintln!("SKIPPED: the `anvil` binary is not installed; install Foundry to run this test");
        return;
    };
    if tool("forge", &["--version"]).is_none() || tool("cast", &["--version"]).is_none() {
        eprintln!("SKIPPED: `forge`/`cast` are not installed; install Foundry to run this test");
        return;
    }

    let owners: Vec<SigningKey> =
        [[0x11u8; 32], [0x22; 32], [0x33; 32]].iter().map(|b| SigningKey::from_bytes(b.into()).unwrap()).collect();
    let owner_addrs: Vec<[u8; 20]> = owners.iter().map(|k| address_of(k).unwrap()).collect();
    let vault = deploy_vault(&anvil.url, &[owner_addrs[0], owner_addrs[1], owner_addrs[2]]);
    let client = connect_with(&anvil.url, |cfg| cfg.trace_internal_transfers = true);
    let profile = client.profile();

    // A durable reconciler, exactly as the simulator suite builds one.
    let dir = tempfile::tempdir().unwrap();
    let reconciler = Reconciler::open(
        Arc::new(OperationsStore::open(&dir.path().join("operations.json")).unwrap()),
        institution(),
        environment(),
        KeyId::unchecked("live-reconciler"),
        AuditKey::from_bytes(&[44; 32]),
    )
    .unwrap();

    let wallet = ChainWalletId::unchecked("live-vault-wallet");
    let native = Asset {
        asset_id: AssetId::unchecked("native-evm"),
        network_id: profile.network_id.clone(),
        asset: AssetKind::Native,
        decimals: 9,
        symbol: "DEV".into(),
        behavior: AssetBehaviorProfile::Standard,
    };
    let id = DepositAddressId::unchecked("live-vault-address");
    reconciler
        .enroll(
            DepositAddress {
                deposit_address_id: id.clone(),
                institution_id: institution(),
                environment_id: environment(),
                vault_id: VaultId::unchecked("live-vault"),
                chain_wallet_id: Some(wallet.clone()),
                chain_profile_id: profile.chain_profile_id.clone(),
                network_id: profile.network_id.clone(),
                address: Bytes(vault.to_vec()),
                address_display: hex_addr(&vault),
                custody: AddressCustody::Controlled,
                supported_assets: vec![native.asset_id.clone()],
                routing_reference: None,
                state: DepositAddressState::Active,
                created_at: UnixSeconds(1),
                retired_at: None,
            },
            &[native.clone()],
            Amount(100),
        )
        .unwrap();
    let step = Some(ActivationStep { committed_at: UnixSeconds(1), commitment: Hash32([1; 32]), actor: "live-operator".into() });
    reconciler
        .activate(AddressActivation {
            deposit_address_id: id,
            public_key_agreement: step.clone(),
            asset_network_configuration: step.clone(),
            recovery_metadata: step.clone(),
            monitoring_registration: step,
        })
        .unwrap();

    // Deposit: a real transaction's value leg into custody.
    let (ok, _) = relay(&client, vault, ONE_ETHER, Vec::new());
    assert!(ok, "the deposit reverted");
    reconciler.sync(&client).unwrap();
    let holdings = reconciler.holdings(&wallet, &native.asset_id, Amount::ZERO).unwrap();
    assert_eq!(holdings.pending_inbound.0 + holdings.settled.0, ONE_ETHER, "the live deposit was not observed");

    // Real finality: mine past the deposit and reconcile against the node.
    mine(&anvil.url, "0x4");
    reconciler.sync(&client).unwrap();
    let checkpoint = reconciler.reconcile(&client, &BTreeMap::new()).unwrap();
    assert!(checkpoint.body.is_consistent(), "a clean deposit must reconcile: {:?}", checkpoint.body.balances);
    assert_eq!(
        reconciler.holdings(&wallet, &native.asset_id, Amount::ZERO).unwrap().settled,
        Amount(ONE_ETHER),
        "the deposit did not settle at finality"
    );

    // Quorum withdrawal with NO linked operation: 0.6 ether leaves through
    // the vault's internal call, which only trace discovery can see.
    let beneficiary = [0x42u8; 20];
    let value = 600_000_000_000_000_000u128;
    let digest_hex = tool(
        "cast",
        &["call", "--rpc-url", &anvil.url, &hex_addr(&vault), "digest(address,uint256,bytes)(bytes32)", &hex_addr(&beneficiary), &value.to_string(), "0x"],
    )
    .unwrap();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hex::decode(digest_hex.trim_start_matches("0x")).unwrap());
    let sig0 = sign_digest(&owners[0], &digest);
    let sig2 = sign_digest(&owners[2], &digest);
    let calldata = tool(
        "cast",
        &[
            "calldata",
            "execute(address,uint256,bytes,bytes,bytes)",
            &hex_addr(&beneficiary),
            &value.to_string(),
            "0x",
            &format!("0x{}", hex::encode(sig0)),
            &format!("0x{}", hex::encode(sig2)),
        ],
    )
    .unwrap();
    let (ok, _) = relay(&client, vault, 0, hex::decode(calldata.trim_start_matches("0x")).unwrap());
    assert!(ok, "the quorum withdrawal reverted");
    assert_eq!(native_balance(&client, vault), ONE_ETHER - value);

    // The unlinked outflow must be surfaced, never silently absorbed. The
    // reconciler books it truthfully (the checkpoint stays consistent with
    // the chain at 0.4 ether) and marks the journal entry with a synthetic
    // `external-` operation family: the queryable record monitoring keys on.
    mine(&anvil.url, "0x4");
    reconciler.sync(&client).unwrap();
    let checkpoint = reconciler.reconcile(&client, &BTreeMap::new()).unwrap();
    assert!(checkpoint.body.is_consistent(), "books must match the chain: {:?}", checkpoint.body.balances);
    assert_eq!(
        reconciler.holdings(&wallet, &native.asset_id, Amount::ZERO).unwrap().settled,
        Amount(ONE_ETHER - value),
        "the internal-call outflow was not discovered"
    );
    let journal = reconciler.export().unwrap().journal;
    let outflow = journal
        .iter()
        .find(|e| {
            matches!(
                &e.body.kind,
                JournalEntryKind::OutgoingMovement { operation_family_id, .. }
                    if operation_family_id.as_str().starts_with("external-")
            ) && e.body.amount_base_units == Amount(value)
        })
        .expect("the unlinked outflow must be journaled with a synthetic external family");
    assert_eq!(outflow.body.chain_wallet_id, wallet);
    println!(
        "live reconciler loop: deposit settled {ONE_ETHER}, internal-call outflow of {value} discovered by traces and surfaced as {}",
        match &outflow.body.kind {
            JournalEntryKind::OutgoingMovement { operation_family_id, .. } => operation_family_id.as_str(),
            _ => unreachable!(),
        }
    );
}
