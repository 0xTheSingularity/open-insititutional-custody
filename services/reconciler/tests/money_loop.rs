//! Real policy, authority, independent approval grants, signers, native
//! signatures, chain execution, durable index, and independent reconciliation.
#[path = "../../coordinator/tests/common/mod.rs"]
mod common;
use common::*;
use ed25519_dalek::SigningKey;
use oic_adapter_api::*;
use oic_authorization_state::*;
use oic_chain_simulator::{evm::*, solana::*, SimClock};
use oic_crypto_provider::*;
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_domain_types::*;
use oic_service_broadcaster::*;
use oic_service_coordinator::*;
use oic_service_reconciler::*;
use std::{collections::BTreeMap, sync::Arc};

fn reconciler(store: Arc<OperationsStore>) -> Reconciler {
    Reconciler::open(
        store,
        inst(),
        env_id(),
        KeyId::unchecked("reconciler"),
        SigningKey::from_bytes(&[44; 32]),
    )
    .unwrap()
}

fn enroll(r: &Reconciler, c: &Chain, native: &Asset) {
    let id = DepositAddressId::unchecked(c.wallet.chain_wallet_id.to_string());
    r.enroll(
        DepositAddress {
            deposit_address_id: id.clone(),
            institution_id: inst(),
            environment_id: env_id(),
            vault_id: vault_id(),
            chain_wallet_id: Some(c.wallet.chain_wallet_id.clone()),
            chain_profile_id: c.profile.chain_profile_id.clone(),
            network_id: c.profile.network_id.clone(),
            address: c.wallet.address.clone(),
            address_display: c.wallet.address_display.clone(),
            custody: AddressCustody::Controlled,
            supported_assets: if c.asset.asset == AssetKind::Native {
                vec![native.asset_id.clone()]
            } else {
                vec![native.asset_id.clone(), c.asset.asset_id.clone()]
            },
            routing_reference: None,
            state: DepositAddressState::Active,
            created_at: now(),
            retired_at: None,
        },
        &[native.clone(), c.asset.clone()],
        Amount(100),
    )
    .unwrap();
    assert_eq!(
        r.export().unwrap().enrollments[&id].address.state,
        DepositAddressState::Inactive
    );
    let step = Some(ActivationStep {
        committed_at: now(),
        commitment: Hash32([1; 32]),
        actor: "domain-operator".into(),
    });
    let mut activation = AddressActivation {
        deposit_address_id: id,
        public_key_agreement: step.clone(),
        asset_network_configuration: step.clone(),
        recovery_metadata: step.clone(),
        monitoring_registration: None,
    };
    assert_eq!(
        r.activate(activation.clone()).unwrap(),
        DepositAddressState::Inactive,
        "C03 crash before monitoring cannot show ready"
    );
    activation.monitoring_registration = step;
    assert_eq!(r.activate(activation).unwrap(), DepositAddressState::Active);
}

fn native(c: &Chain) -> Asset {
    Asset {
        asset_id: AssetId::unchecked(if c.profile.adapter_id.as_str() == "evm" {
            "native-evm"
        } else {
            "native-sol"
        }),
        network_id: c.profile.network_id.clone(),
        asset: AssetKind::Native,
        decimals: 9,
        symbol: "DEV".into(),
        behavior: AssetBehaviorProfile::Standard,
    }
}

fn issue(
    world: &World,
    c: &Chain,
    pol: &PolicyBundle,
    intent: &Intent,
    r: &Reconciler,
    broadcaster: &Broadcaster<InMemoryAuthorityStore>,
    participants: Vec<ParticipantId>,
) -> ChainTxId {
    world.register(pol, intent);
    let coord = coordinator(
        world,
        c,
        in_process(&c.nodes),
        Arc::new(InMemoryOperationStore::new()),
    );
    let candidate = format!("candidate-{}", intent.intent_id);
    let j = job(world, c, pol, intent, &candidate, 1, participants);
    let family = j.built.candidate.operation_family_id.clone();
    let candidate = j.built.candidate.clone();
    let issuance = coord.execute(j).unwrap();
    let tx = issuance.signed.signed.chain_tx_id.clone();
    r.link_operation(tx.clone(), family.clone()).unwrap();
    broadcaster
        .submit(
            &family,
            &candidate,
            &issuance.signed,
            &c.profile.chain_profile_id,
        )
        .unwrap();
    tx
}

#[test]
fn evm_receive_authorize_send_restart_backfill_and_reconcile_actual_fees() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let native = native(c);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operations.json");
    let r = reconciler(Arc::new(OperationsStore::open(&path).unwrap()));
    enroll(&r, c, &native);
    let source = EvmBlocks(evm.sim.clone());
    r.sync(&source).unwrap();
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &c.asset.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount::ZERO,
        "observed != accepted"
    );
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &c.asset.asset_id, Amount::ZERO)
            .unwrap()
            .pending_inbound,
        Amount(1_000_000_000_000)
    );
    drop(r); // death after observation but before finality
    evm.sim.mine_blocks(3).unwrap();
    let r = reconciler(Arc::new(OperationsStore::open(&path).unwrap()));
    let backfill = r.backfill(&source, 0, source.head().height).unwrap();
    assert!(matches!(backfill.state, BackfillState::Complete { .. }));
    let before = r.export().unwrap();
    r.sync(&source).unwrap();
    assert_eq!(
        r.export().unwrap().journal,
        before.journal,
        "C04 notification/restart replay never duplicates credit"
    );
    let pol = world.sign_policy(policy(1, vec![rule(&c.asset.asset_id, 1, 10_000_000)]));
    let intent = c.intent(
        "money-loop-evm",
        1_234_567,
        10u128.pow(16),
        ApprovalMode::ExactCandidate,
    );
    let mut broadcaster = Broadcaster::new(
        world.authority.clone(),
        Arc::new(MemorySubmissionStore::new()),
        world.clock.clone(),
    );
    broadcaster
        .register_network(
            c.profile.clone(),
            c.adapter.clone(),
            Arc::new(EvmSimulatorClient::new(evm.sim.clone())),
        )
        .unwrap();
    let tx = issue(&world, c, &pol, &intent, &r, &broadcaster, vec![pid(1)]);
    let reservations = outstanding_reservations(
        world.authority.store().as_ref(),
        std::slice::from_ref(&c.wallet),
        &BTreeMap::from([(c.profile.network_id.clone(), native.asset_id.clone())]),
    )
    .unwrap();
    assert_eq!(
        reservations[&(c.wallet.chain_wallet_id.clone(), c.asset.asset_id.clone())],
        Amount(1_234_567)
    );
    assert_eq!(
        r.holdings(
            &c.wallet.chain_wallet_id,
            &c.asset.asset_id,
            Amount(1_234_567)
        )
        .unwrap()
        .available,
        Amount(1_000_000_000_000 - 1_234_567)
    );
    evm.sim.mine_blocks(4).unwrap();
    assert_eq!(
        broadcaster
            .poll(&family_id_for(&intent.intent_id).unwrap())
            .unwrap(),
        LifecycleState::FinalizedSuccess
    );
    r.sync(&source).unwrap();
    let checkpoint = r.reconcile(&source, &BTreeMap::new()).unwrap();
    assert!(
        checkpoint.body.is_consistent(),
        "{:?}",
        checkpoint.body.balances
    );
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &c.asset.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(1_000_000_000_000 - 1_234_567)
    );
    let fee = 51_000 * 1_100_000_000u128;
    assert_eq!(evm.sim.receipt(&tx).unwrap().unwrap().fee_paid(), fee);
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &native.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(10u128.pow(18) - fee)
    );
    r.export()
        .unwrap()
        .verify(&SigningKey::from_bytes(&[44; 32]).verifying_key())
        .unwrap();
    let events = r.events_since(0, 1000).unwrap();
    let split = events.len() / 2;
    assert_eq!(
        r.events_since(events[split - 1].body.sequence, 1000)
            .unwrap(),
        events[split..],
        "C18 gap replay"
    );
}

#[test]
fn solana_spl_receive_send_including_ata_rent_and_frost_reconciles() {
    let world = World::new();
    let sol = sol_chain(&world, true);
    let c = &sol.chain;
    let native = native(c);
    let r = reconciler(Arc::new(OperationsStore::memory()));
    enroll(&r, c, &native);
    let source = SolanaBlocks(sol.sim.clone());
    sol.sim.advance_slots(6).unwrap();
    r.sync(&source).unwrap();
    assert!(r
        .reconcile(&source, &BTreeMap::new())
        .unwrap()
        .body
        .is_consistent());
    let pol = world.sign_policy(policy(1, vec![rule(&c.asset.asset_id, 1, 10_000_000)]));
    let intent = c.intent(
        "money-loop-sol",
        765_432,
        10_000_000,
        ApprovalMode::ExactCandidate,
    );
    let mut broadcaster = Broadcaster::new(
        world.authority.clone(),
        Arc::new(MemorySubmissionStore::new()),
        world.clock.clone(),
    );
    broadcaster
        .register_network(
            c.profile.clone(),
            c.adapter.clone(),
            Arc::new(SolanaSimulatorClient::new(sol.sim.clone())),
        )
        .unwrap();
    issue(
        &world,
        c,
        &pol,
        &intent,
        &r,
        &broadcaster,
        vec![pid(1), pid(3)],
    );
    sol.sim.advance_slots(7).unwrap();
    assert_eq!(
        broadcaster
            .poll(&family_id_for(&intent.intent_id).unwrap())
            .unwrap(),
        LifecycleState::FinalizedSuccess
    );
    r.sync(&source).unwrap();
    let checkpoint = r.reconcile(&source, &BTreeMap::new()).unwrap();
    assert!(
        checkpoint.body.is_consistent(),
        "{:?}",
        checkpoint.body.balances
    );
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &c.asset.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(10_000_000 - 765_432)
    );
    let export = r.export().unwrap();
    assert!(export.journal.iter().any(|e| matches!(
        e.body.kind,
        JournalEntryKind::AccountFunding { .. }
    ) && e.body.amount_base_units
        == Amount(RENT_EXEMPT_TOKEN_ACCOUNT as u128)));
    assert!(export
        .journal
        .iter()
        .any(|e| matches!(e.body.kind, JournalEntryKind::NetworkFee { .. })));
    export
        .verify(&SigningKey::from_bytes(&[44; 32]).verifying_key())
        .unwrap();
}

fn evm_wallet(
    world: &World,
    sim: Arc<EvmSimulator>,
    seed: u8,
    id: &str,
    asset: Asset,
    dest: CounterpartyDestination,
) -> Chain {
    let profile = sim.profile();
    let provider = Arc::new(
        DevSingleKeyProvider::with_os_rng(SchemeId::EcdsaSecp256k1Keccak256Prehashed, [seed; 32])
            .unwrap(),
    );
    let keygen = provider
        .generate_distributed_key(&KeygenCeremony {
            key_id: KeyId::unchecked(format!("key-{id}")),
            key_epoch: Epoch(1),
            institution_id: inst(),
            environment_id: env_id(),
            participants: vec![pid(1)],
            threshold: 1,
            networks: vec![profile.network_id.clone()],
            recovery_profile: "development".into(),
        })
        .unwrap();
    let adapter: Arc<dyn ChainAdapter> = Arc::new(oic_adapter_evm::EvmAdapter);
    let wallet = wallet_for(adapter.as_ref(), &profile, &keygen.descriptor, id);
    let mut roots = world.trust_roots(vec![profile.clone()]);
    roots.enrolled_materials = oic_signer::EnrolledMaterials::from_records([&asset], [&wallet], [&vault()]).unwrap();
    let node = open_node(
        &pid(1),
        roots,
        adapter.clone(),
        provider,
    );
    node.signer
        .load_key(&keygen.descriptor, &keygen.sealed_shares[0].1)
        .unwrap();
    Chain {
        profile,
        adapter,
        source: Arc::new(oic_service_builder::EvmSimulatorEvidence(sim)),
        key: keygen.descriptor,
        wallet,
        asset,
        destination: dest,
        nodes: vec![node],
    }
}

#[test]
fn token_without_gas_is_funded_once_through_policy_then_swept_and_both_legs_reconcile() {
    let world = World::new();
    let sim = Arc::new(
        EvmSimulator::new(
            EvmSimConfig::with_seed([12; 32]),
            SimClock::new(UnixSeconds(T0)),
        )
        .unwrap(),
    );
    let profile = sim.profile();
    let token = sim
        .deploy_erc20("USD", 6, sim.faucet_address(), 10_000_000)
        .unwrap();
    sim.mine().unwrap();
    let asset = Asset {
        asset_id: AssetId::unchecked("usd"),
        network_id: profile.network_id.clone(),
        asset: AssetKind::Erc20 {
            contract: Bytes(token.to_vec()),
        },
        decimals: 6,
        symbol: "USD".into(),
        behavior: AssetBehaviorProfile::Standard,
    };
    let treasury_dest = world.sign_destination(destination(
        &profile,
        "treasury",
        vec![0xab; 20],
        "treasury".into(),
    ));
    let operating = evm_wallet(
        &world,
        sim.clone(),
        80,
        "operating",
        asset.clone(),
        treasury_dest,
    );
    let native = native(&operating);
    let operating_dest = world.sign_destination(destination(
        &profile,
        "operating-dest",
        operating.wallet.address.0.clone(),
        operating.wallet.address_display.clone(),
    ));
    let funding = evm_wallet(
        &world,
        sim.clone(),
        81,
        "funding",
        native.clone(),
        operating_dest.clone(),
    );
    // A controlled treasury receiver makes consolidation an internal transfer.
    let treasury = evm_wallet(
        &world,
        sim.clone(),
        82,
        "treasury-wallet",
        asset.clone(),
        operating.destination.clone(),
    );
    let mut operating = operating;
    operating.destination = world.sign_destination(destination(
        &profile,
        "treasury",
        treasury.wallet.address.0.clone(),
        treasury.wallet.address_display.clone(),
    ));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operations.json");
    let r = reconciler(Arc::new(OperationsStore::open(&path).unwrap()));
    for c in [&operating, &funding, &treasury] {
        enroll(&r, c, &native);
    }
    sim.fund(
        funding.wallet.address.as_slice().try_into().unwrap(),
        10u128.pow(18),
    )
    .unwrap();
    let deposit_tx = sim
        .erc20_fund(
            token,
            operating.wallet.address.as_slice().try_into().unwrap(),
            1_234_000,
        )
        .unwrap();
    sim.mine_blocks(4).unwrap();
    let source = EvmBlocks(sim.clone());
    r.sync(&source).unwrap();
    assert_eq!(
        sim.balance(&operating.wallet.address.as_slice().try_into().unwrap()),
        0
    );
    let movement = r
        .export()
        .unwrap()
        .movements()
        .into_iter()
        .find(|m| m.tx_id == deposit_tx && m.direction == MovementDirection::Inbound)
        .unwrap()
        .movement_id;
    let gas = GasFundingRule {
        rule_id: "bounded-gas".into(),
        chain_profile_id: profile.chain_profile_id.clone(),
        source_wallet_id: funding.wallet.chain_wallet_id.clone(),
        recipients: vec![GasRecipient {
            chain_wallet_id: operating.wallet.chain_wallet_id.clone(),
            destination_id: operating_dest.destination_id.clone(),
            destination_version: operating_dest.version,
        }],
        native_asset_id: native.asset_id.clone(),
        minimum_balance: Amount(1_000_000_000_000_000),
        target_balance: Amount(2_000_000_000_000_000),
        max_refill_per_operation: Amount(2_000_000_000_000_000),
        max_refill_per_period: Amount(2_000_000_000_000_000),
        period_seconds: DAY,
        max_attempts: 1,
        max_native_fee: Amount(200_000_000_000_000),
    };
    let sweep = SweepRule {
        rule_id: "sweep".into(),
        chain_profile_id: profile.chain_profile_id.clone(),
        source_wallet_id: operating.wallet.chain_wallet_id.clone(),
        asset_id: asset.asset_id.clone(),
        destination_id: operating.destination.destination_id.clone(),
        destination_version: operating.destination.version,
        threshold: Amount(100_000),
        minimum_useful_value: Amount(100),
        max_native_fee: Amount(200_000_000_000_000),
        required_native_balance: Amount(200_000_000_000_000),
        max_attempts: 1,
    };
    let destinations = vec![operating_dest, operating.destination.clone()];
    let mut denied = gas.clone();
    denied.recipients.clear();
    assert_eq!(
        r.plan_sweep(
            &source,
            &movement,
            &denied,
            &sweep,
            &destinations,
            CredentialId::unchecked("automation")
        )
        .unwrap_err()
        .code,
        ErrorCode::PolicyDenied
    );
    let mut denied = gas.clone();
    denied.max_refill_per_period = Amount(gas.target_balance.0 - 1);
    assert_eq!(
        r.plan_sweep(
            &source,
            &movement,
            &denied,
            &sweep,
            &destinations,
            CredentialId::unchecked("automation")
        )
        .unwrap_err()
        .code,
        ErrorCode::BudgetExceeded
    );
    // A gas source whose enrollment does not support the native asset would
    // have its own fee/transfer effects quarantined at acceptance.
    let nonative = evm_wallet(
        &world,
        sim.clone(),
        83,
        "funding-nonative",
        asset.clone(),
        destinations[0].clone(),
    );
    let nonative_id = DepositAddressId::unchecked("funding-nonative");
    r.enroll(
        DepositAddress {
            deposit_address_id: nonative_id.clone(),
            institution_id: inst(),
            environment_id: env_id(),
            vault_id: vault_id(),
            chain_wallet_id: Some(nonative.wallet.chain_wallet_id.clone()),
            chain_profile_id: profile.chain_profile_id.clone(),
            network_id: profile.network_id.clone(),
            address: nonative.wallet.address.clone(),
            address_display: nonative.wallet.address_display.clone(),
            custody: AddressCustody::Controlled,
            supported_assets: vec![asset.asset_id.clone()],
            routing_reference: None,
            state: DepositAddressState::Active,
            created_at: now(),
            retired_at: None,
        },
        std::slice::from_ref(&asset),
        Amount(100),
    )
    .unwrap();
    let step = Some(ActivationStep {
        committed_at: now(),
        commitment: Hash32([2; 32]),
        actor: "domain-operator".into(),
    });
    r.activate(AddressActivation {
        deposit_address_id: nonative_id,
        public_key_agreement: step.clone(),
        asset_network_configuration: step.clone(),
        recovery_metadata: step.clone(),
        monitoring_registration: step,
    })
    .unwrap();
    let mut denied = gas.clone();
    denied.source_wallet_id = nonative.wallet.chain_wallet_id.clone();
    assert_eq!(
        r.plan_sweep(
            &source,
            &movement,
            &denied,
            &sweep,
            &destinations,
            CredentialId::unchecked("automation")
        )
        .unwrap_err()
        .code,
        ErrorCode::PolicyDenied,
        "gas source must support the configured native asset"
    );
    let w = r
        .plan_sweep(
            &source,
            &movement,
            &gas,
            &sweep,
            &destinations,
            CredentialId::unchecked("automation"),
        )
        .unwrap();
    assert_eq!(w.steps.len(), 2);
    assert!(r
        .next_intent(
            &w.workflow_id,
            world.authority.as_ref(),
            &source,
            Amount(gas.max_native_fee.0 + 1)
        )
        .unwrap()
        .is_none());
    assert!(
        matches!(
            r.export().unwrap().workflows[&w.workflow_id].state,
            WorkflowState::Paused {
                reason: PauseReason::FeeCeiling,
                ..
            }
        ),
        "C10"
    );
    let first = r
        .next_intent(&w.workflow_id, world.authority.as_ref(), &source, Amount(1))
        .unwrap()
        .unwrap();
    drop(r); // lost acknowledgement after durable dispatch
    let r = reconciler(Arc::new(OperationsStore::open(&path).unwrap()));
    assert_eq!(
        r.next_intent(&w.workflow_id, world.authority.as_ref(), &source, Amount(1))
            .unwrap(),
        Some(first.clone()),
        "C09 same child after restart"
    );
    assert_eq!(
        r.plan_sweep(
            &source,
            &movement,
            &gas,
            &sweep,
            &destinations,
            CredentialId::unchecked("automation")
        )
        .unwrap()
        .workflow_id,
        w.workflow_id
    );
    let mut gas_rule = rule(&native.asset_id, 1, 10u128.pow(18));
    gas_rule.rule_id = "gas".into();
    gas_rule.max_amount_per_operation = Amount(10u128.pow(18));
    let pol = world.sign_policy(policy(
        1,
        vec![rule(&asset.asset_id, 1, 10_000_000), gas_rule],
    ));
    let mut broadcaster = Broadcaster::new(
        world.authority.clone(),
        Arc::new(MemorySubmissionStore::new()),
        world.clock.clone(),
    );
    broadcaster
        .register_network(
            profile.clone(),
            operating.adapter.clone(),
            Arc::new(EvmSimulatorClient::new(sim.clone())),
        )
        .unwrap();
    issue(
        &world,
        &funding,
        &pol,
        &first,
        &r,
        &broadcaster,
        vec![pid(1)],
    );
    // The token child remains blocked until funding finalizes, not just ACK.
    assert_eq!(
        r.next_intent(&w.workflow_id, world.authority.as_ref(), &source, Amount(1))
            .unwrap(),
        Some(first.clone())
    );
    sim.mine_blocks(4).unwrap();
    assert_eq!(
        broadcaster
            .poll(&family_id_for(&first.intent_id).unwrap())
            .unwrap(),
        LifecycleState::FinalizedSuccess
    );
    r.sync(&source).unwrap();
    let second = r
        .next_intent(&w.workflow_id, world.authority.as_ref(), &source, Amount(1))
        .unwrap()
        .unwrap();
    assert_ne!(first.intent_id, second.intent_id);
    assert_eq!(second.chain_wallet_id, operating.wallet.chain_wallet_id);
    issue(
        &world,
        &operating,
        &pol,
        &second,
        &r,
        &broadcaster,
        vec![pid(1)],
    );
    sim.mine_blocks(4).unwrap();
    assert_eq!(
        broadcaster
            .poll(&family_id_for(&second.intent_id).unwrap())
            .unwrap(),
        LifecycleState::FinalizedSuccess
    );
    r.sync(&source).unwrap();
    assert!(r
        .next_intent(&w.workflow_id, world.authority.as_ref(), &source, Amount(1))
        .unwrap()
        .is_none());
    let export = r.export().unwrap();
    assert_eq!(
        export.workflows[&w.workflow_id].state,
        WorkflowState::Complete
    );
    assert_eq!(
        export.workflows[&w.workflow_id].total_native_spent,
        Amount(gas.target_balance.0 + (21_000 + 51_000) * 1_100_000_000)
    );
    assert_eq!(
        sim.erc20_balance(
            &token,
            &treasury.wallet.address.as_slice().try_into().unwrap()
        )
        .unwrap(),
        1_234_000
    );
    let checkpoint = r.reconcile(&source, &BTreeMap::new()).unwrap();
    assert!(
        checkpoint.body.is_consistent(),
        "{:?}",
        checkpoint.body.balances
    );
    assert_eq!(
        export
            .journal
            .iter()
            .filter(|e| matches!(e.body.kind, JournalEntryKind::InternalTransfer { .. }))
            .count(),
        4,
        "C11 both funding and sweep legs, no false revenue"
    );
}

fn sol_wallet(
    world: &World,
    sim: Arc<SolanaSimulator>,
    id: &str,
    asset: Asset,
    dest: CounterpartyDestination,
) -> Chain {
    use oic_crypto_provider_frost_ed25519::{run_dkg, FrostEd25519Provider};
    let profile = sim.profile();
    let ids: Vec<_> = (1..=3).map(pid).collect();
    let providers: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, p)| {
            Arc::new(FrostEd25519Provider::with_os_rng(p.clone(), [0x60 + i as u8; 32]).unwrap())
        })
        .collect();
    let refs: Vec<_> = providers.iter().map(|p| p.as_ref()).collect();
    let dkg = run_dkg(
        &refs,
        &KeygenCeremony {
            key_id: KeyId::unchecked(format!("key-{id}")),
            key_epoch: Epoch(1),
            institution_id: inst(),
            environment_id: env_id(),
            participants: ids.clone(),
            threshold: 2,
            networks: vec![profile.network_id.clone()],
            recovery_profile: "dkg".into(),
        },
    )
    .unwrap();
    let adapter: Arc<dyn ChainAdapter> = Arc::new(oic_adapter_solana::SolanaAdapter);
    let wallet = wallet_for(adapter.as_ref(), &profile, &dkg.descriptor, id);
    let nodes: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut roots = world.trust_roots(vec![profile.clone()]);
            roots.enrolled_materials = oic_signer::EnrolledMaterials::from_records([&asset], [&wallet], [&vault()]).unwrap();
            let node = open_node(
                p,
                roots,
                adapter.clone(),
                providers[i].clone(),
            );
            node.signer
                .load_key(
                    &dkg.descriptor,
                    &dkg.sealed_shares
                        .iter()
                        .find(|(participant, _)| participant == p)
                        .unwrap()
                        .1,
                )
                .unwrap();
            node
        })
        .collect();
    for a in &nodes {
        for b in nodes.iter().filter(|b| b.id != a.id) {
            a.signer
                .set_peer_generation(&b.id, b.signer.generation())
                .unwrap();
        }
    }
    Chain {
        profile,
        adapter,
        source: Arc::new(oic_service_builder::SolanaSimulatorEvidence(sim)),
        key: dkg.descriptor,
        wallet,
        asset,
        destination: dest,
        nodes,
    }
}

#[test]
fn solana_zero_gas_token_deposit_funding_sweep_restart_and_accounting() {
    let world = World::new();
    let sim = Arc::new(
        SolanaSimulator::new(
            SolanaSimConfig::with_seed([13; 32]),
            SimClock::new(UnixSeconds(T0)),
        )
        .unwrap(),
    );
    let profile = sim.profile();
    let mint = sim.create_mint(6, b"treasury-token").unwrap();
    let asset = Asset {
        asset_id: AssetId::unchecked("spl-usd"),
        network_id: profile.network_id.clone(),
        asset: AssetKind::SplToken {
            mint: Bytes(mint.to_vec()),
            token_program: Bytes(oic_adapter_solana::address::TOKEN_PROGRAM_ID.to_vec()),
        },
        decimals: 6,
        symbol: "USD".into(),
        behavior: AssetBehaviorProfile::Standard,
    };
    let treasury = sol_wallet(
        &world,
        sim.clone(),
        "treasury",
        asset.clone(),
        world.sign_destination(destination(
            &profile,
            "unused",
            sol_dest_owner().to_vec(),
            "unused".into(),
        )),
    );
    let treasury_dest = world.sign_destination(destination(
        &profile,
        "treasury-dest",
        treasury.wallet.address.0.clone(),
        treasury.wallet.address_display.clone(),
    ));
    let operating = sol_wallet(
        &world,
        sim.clone(),
        "operating",
        asset.clone(),
        treasury_dest.clone(),
    );
    let native = native(&operating);
    let operating_dest = world.sign_destination(destination(
        &profile,
        "operating-dest",
        operating.wallet.address.0.clone(),
        operating.wallet.address_display.clone(),
    ));
    let funding = sol_wallet(
        &world,
        sim.clone(),
        "funding",
        native.clone(),
        operating_dest.clone(),
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sol-operations.json");
    let r = reconciler(Arc::new(OperationsStore::open(&path).unwrap()));
    for c in [&operating, &funding, &treasury] {
        enroll(&r, c, &native);
    }
    let owner = operating.wallet.address.as_slice().try_into().unwrap();
    let ata = sim.create_ata(&owner, &mint).unwrap();
    sim.mint_to(&mint, &ata, 2_345_678).unwrap();
    sim.advance_slots(7).unwrap();
    let source = SolanaBlocks(sim.clone());
    r.sync(&source).unwrap();
    assert_eq!(
        source
            .balance(
                &source.finalized(),
                &operating.wallet.address,
                &AssetKind::Native
            )
            .unwrap(),
        Amount::ZERO
    );
    let movement = r
        .export()
        .unwrap()
        .movements()
        .into_iter()
        .find(|m| {
            m.chain_wallet_id.as_ref() == Some(&operating.wallet.chain_wallet_id)
                && m.asset_id.as_ref() == Some(&asset.asset_id)
        })
        .unwrap()
        .movement_id;
    let gas = GasFundingRule {
        rule_id: "sol-bounded-gas".into(),
        chain_profile_id: profile.chain_profile_id.clone(),
        source_wallet_id: funding.wallet.chain_wallet_id.clone(),
        recipients: vec![GasRecipient {
            chain_wallet_id: operating.wallet.chain_wallet_id.clone(),
            destination_id: operating_dest.destination_id.clone(),
            destination_version: operating_dest.version,
        }],
        native_asset_id: native.asset_id.clone(),
        minimum_balance: Amount(5_000_000),
        target_balance: Amount(10_000_000),
        max_refill_per_operation: Amount(10_000_000),
        max_refill_per_period: Amount(10_000_000),
        period_seconds: DAY,
        max_attempts: 1,
        max_native_fee: Amount(1_000_000),
    };
    let sweep = SweepRule {
        rule_id: "sol-sweep".into(),
        chain_profile_id: profile.chain_profile_id.clone(),
        source_wallet_id: operating.wallet.chain_wallet_id.clone(),
        asset_id: asset.asset_id.clone(),
        destination_id: treasury_dest.destination_id.clone(),
        destination_version: treasury_dest.version,
        threshold: Amount(100),
        minimum_useful_value: Amount(10),
        max_native_fee: Amount(5_000_000),
        required_native_balance: Amount(5_000_000),
        max_attempts: 1,
    };
    let destinations = [operating_dest, treasury_dest];
    let w = r
        .plan_sweep(
            &source,
            &movement,
            &gas,
            &sweep,
            &destinations,
            CredentialId::unchecked("automation"),
        )
        .unwrap();
    assert!(r
        .next_intent(
            &w.workflow_id,
            world.authority.as_ref(),
            &source,
            Amount(5_000)
        )
        .unwrap()
        .is_none());
    assert!(matches!(
        r.export().unwrap().workflows[&w.workflow_id].state,
        WorkflowState::Paused {
            reason: PauseReason::InsufficientFunds,
            ..
        }
    ));
    assert_eq!(
        r.export().unwrap().workflows[&w.workflow_id].attempts,
        0,
        "a shortage must not consume an attempt or create an intent"
    );
    sim.airdrop(&funding.wallet.address.as_slice().try_into().unwrap(), SOL)
        .unwrap();
    sim.advance_slots(7).unwrap();
    assert!(r
        .next_intent(
            &w.workflow_id,
            world.authority.as_ref(),
            &source,
            Amount(5_000)
        )
        .unwrap()
        .is_none());
    assert!(matches!(
        r.export().unwrap().workflows[&w.workflow_id].state,
        WorkflowState::Paused {
            reason: PauseReason::StaleEvidence,
            ..
        }
    ));
    r.sync(&source).unwrap();
    let first = r
        .next_intent(
            &w.workflow_id,
            world.authority.as_ref(),
            &source,
            Amount(5_000),
        )
        .unwrap()
        .unwrap();
    drop(r);
    let r = reconciler(Arc::new(OperationsStore::open(&path).unwrap()));
    assert_eq!(
        r.next_intent(
            &w.workflow_id,
            world.authority.as_ref(),
            &source,
            Amount(5_000)
        )
        .unwrap(),
        Some(first.clone())
    );
    let mut native_rule = rule(&native.asset_id, 1, SOL as u128);
    native_rule.rule_id = "gas".into();
    native_rule.max_amount_per_operation = Amount(SOL as u128);
    let pol = world.sign_policy(policy(
        1,
        vec![rule(&asset.asset_id, 1, 10_000_000), native_rule],
    ));
    let mut broadcaster = Broadcaster::new(
        world.authority.clone(),
        Arc::new(MemorySubmissionStore::new()),
        world.clock.clone(),
    );
    broadcaster
        .register_network(
            profile.clone(),
            operating.adapter.clone(),
            Arc::new(SolanaSimulatorClient::new(sim.clone())),
        )
        .unwrap();
    issue(
        &world,
        &funding,
        &pol,
        &first,
        &r,
        &broadcaster,
        vec![pid(1), pid(2)],
    );
    assert_eq!(
        r.next_intent(
            &w.workflow_id,
            world.authority.as_ref(),
            &source,
            Amount(5_000)
        )
        .unwrap(),
        Some(first.clone())
    );
    sim.advance_slots(7).unwrap();
    assert_eq!(
        broadcaster
            .poll(&family_id_for(&first.intent_id).unwrap())
            .unwrap(),
        LifecycleState::FinalizedSuccess
    );
    r.sync(&source).unwrap();
    let second = r
        .next_intent(
            &w.workflow_id,
            world.authority.as_ref(),
            &source,
            Amount(5_000),
        )
        .unwrap()
        .unwrap();
    assert_eq!(second.chain_wallet_id, operating.wallet.chain_wallet_id);
    issue(
        &world,
        &operating,
        &pol,
        &second,
        &r,
        &broadcaster,
        vec![pid(2), pid(3)],
    );
    sim.advance_slots(7).unwrap();
    assert_eq!(
        broadcaster
            .poll(&family_id_for(&second.intent_id).unwrap())
            .unwrap(),
        LifecycleState::FinalizedSuccess
    );
    r.sync(&source).unwrap();
    assert!(r
        .next_intent(
            &w.workflow_id,
            world.authority.as_ref(),
            &source,
            Amount(5_000)
        )
        .unwrap()
        .is_none());
    let export = r.export().unwrap();
    assert_eq!(
        export.workflows[&w.workflow_id].state,
        WorkflowState::Complete
    );
    // Two 5,000 signature fees plus 200 priority lamports each, and the
    // destination ATA's rent. Rent must stay spent in the authority budget.
    assert_eq!(
        export.workflows[&w.workflow_id].total_native_spent,
        Amount(10_000_000 + 10_400 + RENT_EXEMPT_TOKEN_ACCOUNT as u128)
    );
    assert_eq!(
        r.holdings(
            &operating.wallet.chain_wallet_id,
            &asset.asset_id,
            Amount::ZERO
        )
        .unwrap()
        .settled,
        Amount::ZERO
    );
    assert_eq!(
        r.holdings(
            &treasury.wallet.chain_wallet_id,
            &asset.asset_id,
            Amount::ZERO
        )
        .unwrap()
        .settled,
        Amount(2_345_678)
    );
    assert_eq!(
        export
            .journal
            .iter()
            .filter(|e| matches!(e.body.kind, JournalEntryKind::InternalTransfer { .. }))
            .count(),
        4
    );
    assert!(r
        .reconcile(&source, &BTreeMap::new())
        .unwrap()
        .body
        .is_consistent());
    export
        .verify(&SigningKey::from_bytes(&[44; 32]).verifying_key())
        .unwrap();
}

#[test]
fn missed_effect_is_detected_by_reconciliation_and_explicit_backfill_repairs_it_once() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let native = native(c);
    let r = reconciler(Arc::new(OperationsStore::memory()));
    enroll(&r, c, &native);
    let tx = evm
        .sim
        .fund(c.wallet.address.as_slice().try_into().unwrap(), 42_123)
        .unwrap();
    evm.sim.mine_blocks(4).unwrap();
    let source = EvmBlocks(evm.sim.clone());
    let missing = View {
        source: &source,
        early_finality: false,
        omit: Some(tx.clone()),
        balance_extra: 0,
    };
    r.sync(&missing).unwrap();
    assert!(
        !r.reconcile(&source, &BTreeMap::new())
            .unwrap()
            .body
            .is_consistent(),
        "C05 a cursor is not proof of complete effects"
    );
    r.sync(&source).unwrap();
    assert!(!r
        .export()
        .unwrap()
        .movements()
        .iter()
        .any(|m| m.tx_id == tx));
    r.backfill(&source, 0, source.head().height).unwrap();
    assert!(r
        .reconcile(&source, &BTreeMap::new())
        .unwrap()
        .body
        .is_consistent());
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &native.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(10u128.pow(18) + 42_123)
    );
    let entries = r.export().unwrap().journal;
    r.backfill(&source, 0, source.head().height).unwrap();
    assert_eq!(r.export().unwrap().journal, entries);
}

/// Fault-injecting observation service. `early_finality` tests correction
/// after a finality assumption fails, without teaching the simulator to reorg
/// its own finalized blocks. `omit` models a missed notification/range.
struct View<'a> {
    source: &'a dyn BlockSource,
    early_finality: bool,
    omit: Option<ChainTxId>,
    balance_extra: u128,
}
impl BlockSource for View<'_> {
    fn profile(&self) -> ChainProfile {
        self.source.profile()
    }
    fn source_id(&self) -> EvidenceSourceId {
        self.source.source_id()
    }
    fn now(&self) -> UnixSeconds {
        self.source.now()
    }
    fn head(&self) -> StateReference {
        self.source.head()
    }
    fn finalized(&self) -> StateReference {
        if self.early_finality {
            let mut h = self.head();
            h.commitment = "finalized".into();
            h
        } else {
            self.source.finalized()
        }
    }
    fn block(&self, height: u64) -> OicResult<IndexedBlock> {
        let mut b = self.source.block(height)?;
        b.effects.retain(|e| self.omit.as_ref() != Some(&e.tx_id));
        Ok(b)
    }
    fn balance(
        &self,
        state: &StateReference,
        address: &Bytes,
        asset: &AssetKind,
    ) -> OicResult<Amount> {
        Ok(Amount(
            self.source.balance(state, address, asset)?.0
                + if *asset == AssetKind::Native {
                    self.balance_extra
                } else {
                    0
                },
        ))
    }
}

#[test]
fn accepted_deposit_reorg_reversal_survives_restart_and_reinclusion() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let native = native(c);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operations.json");
    let r = reconciler(Arc::new(OperationsStore::open(&path).unwrap()));
    enroll(&r, c, &native);
    let source = EvmBlocks(evm.sim.clone());
    let early = View {
        source: &source,
        early_finality: true,
        omit: None,
        balance_extra: 0,
    };
    r.sync(&early).unwrap();
    let deposit = evm
        .sim
        .fund(c.wallet.address.as_slice().try_into().unwrap(), 987_654)
        .unwrap();
    let signed = evm.sim.mine().unwrap().transactions[0].signed_bytes.clone();
    r.sync(&early).unwrap();
    let entries = r.export().unwrap().journal;
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &native.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(10u128.pow(18) + 987_654)
    );
    drop(r);
    evm.sim.reorg(1, std::slice::from_ref(&deposit)).unwrap();
    let r = reconciler(Arc::new(OperationsStore::open(&path).unwrap()));
    r.sync(&early).unwrap();
    let export = r.export().unwrap();
    assert_eq!(
        &export.journal[..entries.len()],
        entries,
        "C06 history is not rewritten"
    );
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &native.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(10u128.pow(18))
    );
    assert!(export
        .journal
        .iter()
        .any(|e| matches!(e.body.kind, JournalEntryKind::Reversal { .. })));
    let movement = export
        .movements()
        .into_iter()
        .find(|m| m.tx_id == deposit)
        .unwrap();
    assert_eq!(movement.acceptance, MovementAcceptance::Reversed);
    r.sync(&early).unwrap();
    assert_eq!(
        r.export().unwrap().journal,
        export.journal,
        "reversal is also idempotent"
    );
    assert_eq!(
        evm.sim
            .balance_at(
                &movement.observed_state,
                &c.wallet.address.as_slice().try_into().unwrap(),
                &AssetKind::Native
            )
            .unwrap_err()
            .code,
        ErrorCode::StaleEvidence
    );
    assert_eq!(evm.sim.submit(&signed).unwrap(), deposit);
    evm.sim.mine().unwrap();
    r.sync(&early).unwrap();
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &native.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(10u128.pow(18) + 987_654)
    );
    let reinstated = r.export().unwrap().journal;
    assert_eq!(&reinstated[..export.journal.len()], export.journal);
    r.sync(&early).unwrap();
    assert_eq!(
        r.export().unwrap().journal,
        reinstated,
        "reinclusion credits once after the prior credit was reversed"
    );
}

/// A35: an effect that differs from expected contract behavior is
/// quarantined with a case, and a divergent independent read yields an
/// inconsistent checkpoint that only an explicit quorum correction repairs.
#[test]
fn unknown_token_is_quarantined_and_differences_need_unique_admin_quorum() {
    use ed25519_dalek::Signer as _;
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let native = native(c);
    let r = reconciler(Arc::new(OperationsStore::memory()));
    enroll(&r, c, &native);
    let unknown = evm
        .sim
        .deploy_erc20("UNKNOWN", 8, evm.sim.faucet_address(), 1000)
        .unwrap();
    evm.sim.mine().unwrap();
    let tx = evm
        .sim
        .erc20_fund(
            unknown,
            c.wallet.address.as_slice().try_into().unwrap(),
            777,
        )
        .unwrap();
    evm.sim.mine_blocks(4).unwrap();
    let source = EvmBlocks(evm.sim.clone());
    r.sync(&source).unwrap();
    let export = r.export().unwrap();
    assert_eq!(
        export
            .movements()
            .iter()
            .find(|m| m.tx_id == tx)
            .unwrap()
            .acceptance,
        MovementAcceptance::Quarantined
    );
    assert!(export
        .cases
        .values()
        .any(|c| c.kind == CaseKind::UnknownAsset));
    assert!(export.workflows.is_empty(), "C07 no automatic top-ups");
    // An independent read disagrees. No journal balancing happens implicitly.
    let divergent = View {
        source: &source,
        early_finality: false,
        omit: None,
        balance_extra: 37,
    };
    let checkpoint = r.reconcile(&divergent, &BTreeMap::new()).unwrap();
    assert!(!checkpoint.body.is_consistent());
    assert_eq!(
        r.export().unwrap().journal,
        export.journal,
        "C19 no silent rebalance"
    );
    let correction = JournalCorrection {
        institution_id: inst(),
        environment_id: env_id(),
        case_id: checkpoint.body.cases_opened[0].clone(),
        checkpoint_id: checkpoint.body.checkpoint_id.clone(),
        chain_wallet_id: c.wallet.chain_wallet_id.clone(),
        asset_id: native.asset_id.clone(),
        side: EntrySide::Credit,
        amount: Amount(37),
        reason: "Independently verified opening balance adjustment, evidence EX-37".into(),
    };
    let signatures: Vec<_> = world.admins[..2]
        .iter()
        .map(|(id, key)| CredentialSignature {
            credential_id: id.clone(),
            signature: SignatureBytes {
                scheme: SchemeId::Ed25519Pure,
                bytes: Bytes(key.sign(&correction.hash().unwrap().0).to_bytes().to_vec()),
            },
        })
        .collect();
    assert_eq!(
        r.resolve_difference(
            &correction,
            &signatures[..1],
            world.authority.as_ref(),
            now()
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidSignature
    );
    assert_eq!(
        r.resolve_difference(
            &correction,
            &[signatures[0].clone(), signatures[0].clone()],
            world.authority.as_ref(),
            now()
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidSignature
    );
    r.resolve_difference(&correction, &signatures, world.authority.as_ref(), now())
        .unwrap();
    assert!(r
        .reconcile(&divergent, &BTreeMap::new())
        .unwrap()
        .body
        .is_consistent());
    assert_eq!(
        r.resolve_difference(&correction, &signatures, world.authority.as_ref(), now())
            .unwrap_err()
            .code,
        ErrorCode::ResourceConflict
    );
    let export = r.export().unwrap();
    export
        .verify(&SigningKey::from_bytes(&[44; 32]).verifying_key())
        .unwrap();
    let mut corrupt = export.clone();
    corrupt.journal[0].body.amount_base_units = Amount(2);
    assert!(corrupt
        .verify(&SigningKey::from_bytes(&[44; 32]).verifying_key())
        .is_err());
}

#[test]
fn dust_threshold_is_inclusive_and_quarantine_does_not_turn_replay_into_credit() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let native = native(c);
    let r = reconciler(Arc::new(OperationsStore::memory()));
    enroll(&r, c, &native); // dust threshold = 100 base units
    let address = c.wallet.address.as_slice().try_into().unwrap();
    let dust = evm.sim.fund(address, 99).unwrap();
    let allowed = evm.sim.fund(address, 100).unwrap();
    evm.sim.mine_blocks(4).unwrap();
    let source = EvmBlocks(evm.sim.clone());
    r.sync(&source).unwrap();
    let export = r.export().unwrap();
    assert_eq!(
        export
            .movements()
            .iter()
            .find(|m| m.tx_id == dust)
            .unwrap()
            .acceptance,
        MovementAcceptance::Quarantined
    );
    assert_eq!(
        export
            .movements()
            .iter()
            .find(|m| m.tx_id == allowed)
            .unwrap()
            .acceptance,
        MovementAcceptance::Accepted
    );
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &native.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(10u128.pow(18) + 100)
    );
    r.backfill(&source, 0, source.head().height).unwrap();
    assert_eq!(r.export().unwrap().journal, export.journal);
    assert_eq!(
        r.export()
            .unwrap()
            .cases
            .values()
            .filter(|c| c.kind == CaseKind::Dust)
            .count(),
        1
    );
    assert!(r.export().unwrap().workflows.is_empty());
}

#[test]
fn file_store_refuses_concurrent_writer_and_old_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operations.json");
    let r = reconciler(Arc::new(OperationsStore::open(&path).unwrap()));
    assert!(OperationsStore::open(&path).is_err());
    let old = std::fs::read(&path).unwrap();
    let world = World::new();
    let evm = evm_chain(&world);
    enroll(&r, &evm.chain, &native(&evm.chain));
    drop(r);
    std::fs::write(&path, old).unwrap();
    assert_eq!(
        OperationsStore::open(&path).err().unwrap().code,
        ErrorCode::RecoveryRequired
    );
}

fn deposit_address(c: &Chain, native: &Asset) -> DepositAddress {
    DepositAddress {
        deposit_address_id: DepositAddressId::unchecked(c.wallet.chain_wallet_id.to_string()),
        institution_id: inst(),
        environment_id: env_id(),
        vault_id: vault_id(),
        chain_wallet_id: Some(c.wallet.chain_wallet_id.clone()),
        chain_profile_id: c.profile.chain_profile_id.clone(),
        network_id: c.profile.network_id.clone(),
        address: c.wallet.address.clone(),
        address_display: c.wallet.address_display.clone(),
        custody: AddressCustody::Controlled,
        supported_assets: vec![native.asset_id.clone(), c.asset.asset_id.clone()],
        routing_reference: None,
        state: DepositAddressState::Active,
        created_at: now(),
        retired_at: None,
    }
}

#[test]
fn enrollment_retry_must_match_configuration_and_wallet_ids_are_global() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let native = native(c);
    let r = reconciler(Arc::new(OperationsStore::memory()));
    enroll(&r, c, &native); // dust threshold = 100 base units, then activated
    let assets = [native.clone(), c.asset.clone()];
    let address = deposit_address(c, &native);
    // An identical retry is idempotent and keeps the activated state.
    r.enroll(address.clone(), &assets, Amount(100)).unwrap();
    let id = address.deposit_address_id.clone();
    assert_eq!(
        r.export().unwrap().enrollments[&id].address.state,
        DepositAddressState::Active
    );
    // A changed dust threshold must not silently keep the old configuration.
    assert_eq!(
        r.enroll(address.clone(), &assets, Amount(1_000))
            .unwrap_err()
            .code,
        ErrorCode::ResourceConflict
    );
    // A changed routing reference is a conflict, not an idempotent retry.
    let mut routed = address.clone();
    routed.routing_reference = Some("memo-1".into());
    assert_eq!(
        r.enroll(routed, &assets, Amount(100)).unwrap_err().code,
        ErrorCode::ResourceConflict
    );
    // A changed vault is a conflict.
    let mut moved = address.clone();
    moved.vault_id = VaultId::unchecked("vault-other");
    assert_eq!(
        r.enroll(moved, &assets, Amount(100)).unwrap_err().code,
        ErrorCode::ResourceConflict
    );
    // A controlled wallet identity is unique across networks, so journal
    // postings can never resolve the wrong enrollment by iteration order.
    let other_native = Asset {
        asset_id: AssetId::unchecked("native-other"),
        network_id: NetworkId::unchecked("net-other"),
        asset: AssetKind::Native,
        decimals: 9,
        symbol: "OTH".into(),
        behavior: AssetBehaviorProfile::Standard,
    };
    let mut cross = address.clone();
    cross.deposit_address_id = DepositAddressId::unchecked("cross-network");
    cross.chain_profile_id = ChainProfileId::unchecked("profile-other");
    cross.network_id = other_native.network_id.clone();
    cross.address = Bytes(vec![9; 20]);
    cross.address_display = "0x0909".into();
    cross.supported_assets = vec![other_native.asset_id.clone()];
    assert_eq!(
        r.enroll(cross, &[other_native], Amount(0)).unwrap_err().code,
        ErrorCode::ResourceConflict
    );
}

#[test]
fn linking_after_observation_classifies_the_operation_legs() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let native = native(c);
    let r = reconciler(Arc::new(OperationsStore::memory()));
    enroll(&r, c, &native);
    let source = EvmBlocks(evm.sim.clone());
    evm.sim.mine_blocks(4).unwrap();
    r.sync(&source).unwrap();
    let pol = world.sign_policy(policy(1, vec![rule(&c.asset.asset_id, 1, 10_000_000)]));
    let intent = c.intent(
        "late-link",
        1_234,
        10u128.pow(16),
        ApprovalMode::ExactCandidate,
    );
    world.register(&pol, &intent);
    let coord = coordinator(
        &world,
        c,
        in_process(&c.nodes),
        Arc::new(InMemoryOperationStore::new()),
    );
    let j = job(&world, c, &pol, &intent, "candidate-late-link", 1, vec![pid(1)]);
    let family = j.built.candidate.operation_family_id.clone();
    let candidate = j.built.candidate.clone();
    let issuance = coord.execute(j).unwrap();
    let tx = issuance.signed.signed.chain_tx_id.clone();
    let mut broadcaster = Broadcaster::new(
        world.authority.clone(),
        Arc::new(MemorySubmissionStore::new()),
        world.clock.clone(),
    );
    broadcaster
        .register_network(
            c.profile.clone(),
            c.adapter.clone(),
            Arc::new(EvmSimulatorClient::new(evm.sim.clone())),
        )
        .unwrap();
    broadcaster
        .submit(&family, &candidate, &issuance.signed, &c.profile.chain_profile_id)
        .unwrap();
    // Indexing observes the mined transaction before the operation is linked.
    evm.sim.mine().unwrap();
    r.sync(&source).unwrap();
    r.link_operation(tx.clone(), family.clone()).unwrap();
    evm.sim.mine_blocks(3).unwrap();
    r.sync(&source).unwrap();
    let export = r.export().unwrap();
    let movement = export
        .movements()
        .into_iter()
        .find(|m| m.tx_id == tx && m.direction == MovementDirection::Outbound)
        .unwrap();
    assert_eq!(movement.acceptance, MovementAcceptance::Accepted);
    assert_eq!(movement.operation_family_id.as_ref(), Some(&family));
    assert!(
        export.journal.iter().all(|e| match &e.body.kind {
            JournalEntryKind::NetworkFee {
                operation_family_id,
                ..
            }
            | JournalEntryKind::OutgoingMovement {
                operation_family_id,
                ..
            } => operation_family_id == &family,
            _ => true,
        }),
        "a late link must not journal operation legs under a synthetic external family: {:?}",
        export.journal
    );
}

#[test]
fn backfill_honors_the_requested_end_height() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let native = native(c);
    let r = reconciler(Arc::new(OperationsStore::memory()));
    enroll(&r, c, &native);
    let address = c.wallet.address.as_slice().try_into().unwrap();
    evm.sim.fund(address, 11_111).unwrap();
    evm.sim.mine().unwrap();
    let bounded_to = EvmBlocks(evm.sim.clone()).head().height;
    let late = evm.sim.fund(address, 22_222).unwrap();
    evm.sim.mine_blocks(4).unwrap();
    let source = EvmBlocks(evm.sim.clone());
    let job = r.backfill(&source, 0, bounded_to).unwrap();
    assert!(matches!(job.state, BackfillState::Complete { .. }), "{job:?}");
    let export = r.export().unwrap();
    assert!(
        !export.movements().iter().any(|m| m.tx_id == late),
        "a bounded backfill must not ingest effects above the requested range"
    );
    let cursor = &export.cursors[&c.profile.chain_profile_id];
    assert!(
        cursor.last_scanned_height.unwrap_or(0) <= bounded_to,
        "a bounded backfill must not advance the live cursor to the head: {cursor:?}"
    );
    // The ordinary sync still catches up without duplicating earlier credits.
    r.sync(&source).unwrap();
    let export = r.export().unwrap();
    assert!(export.movements().iter().any(|m| m.tx_id == late));
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &native.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(10u128.pow(18) + 11_111 + 22_222)
    );
}

/// Scripted observation source: fixed effects per height, fixed balances,
/// everything final. Used to drive journal states the simulators cannot
/// produce directly.
struct Scripted {
    profile: ChainProfile,
    effects: Vec<Vec<ChainEffect>>,
    native_balance: u128,
}
impl Scripted {
    fn state(&self, height: u64) -> StateReference {
        StateReference {
            height,
            hash: Bytes(vec![height as u8 + 1; 32]),
            commitment: self.profile.finality_commitment.clone(),
        }
    }
}
impl BlockSource for Scripted {
    fn profile(&self) -> ChainProfile {
        self.profile.clone()
    }
    fn source_id(&self) -> EvidenceSourceId {
        EvidenceSourceId::unchecked("scripted")
    }
    fn now(&self) -> UnixSeconds {
        now()
    }
    fn head(&self) -> StateReference {
        self.state(self.effects.len() as u64 - 1)
    }
    fn finalized(&self) -> StateReference {
        self.head()
    }
    fn block(&self, height: u64) -> OicResult<IndexedBlock> {
        let effects = self
            .effects
            .get(height as usize)
            .ok_or_else(|| OicError::stale_evidence("missing scripted block"))?
            .clone();
        Ok(IndexedBlock {
            state: self.state(height),
            parent_hash: if height == 0 {
                Bytes(vec![0; 32])
            } else {
                self.state(height - 1).hash
            },
            effects,
        })
    }
    fn balance(
        &self,
        _state: &StateReference,
        _address: &Bytes,
        asset: &AssetKind,
    ) -> OicResult<Amount> {
        Ok(Amount(if *asset == AssetKind::Native {
            self.native_balance
        } else {
            0
        }))
    }
}

#[test]
fn spending_against_quarantined_credits_reconciles_with_a_shortfall_and_quorum_repair() {
    use ed25519_dalek::Signer as _;
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    let native = native(c);
    let r = reconciler(Arc::new(OperationsStore::memory()));
    enroll(&r, c, &native); // dust threshold = 100 base units
    let effect = |tx: &str, direction, amount: u128| ChainEffect {
        tx_id: ChainTxId::unchecked(tx),
        index: 0,
        address: c.wallet.address.clone(),
        counterparty: Bytes(vec![0xcc; 20]),
        direction,
        asset: AssetKind::Native,
        amount: Amount(amount),
        mechanism: DiscoveryMechanism::EvmTransactionValue,
        kind: oic_service_reconciler::EffectKind::Transfer,
    };
    // 99 is quarantined as dust (no credit), 1_000 is credited, and the
    // outbound 1_050 posts a debit: the journal position is now -50 while the
    // chain still holds 49.
    let source = Scripted {
        profile: c.profile.clone(),
        effects: vec![
            vec![
                effect("dust-in", MovementDirection::Inbound, 99),
                effect("real-in", MovementDirection::Inbound, 1_000),
            ],
            vec![effect("spend-out", MovementDirection::Outbound, 1_050)],
        ],
        native_balance: 49,
    };
    r.sync(&source).unwrap();
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &native.asset_id, Amount::ZERO)
            .unwrap_err()
            .code,
        ErrorCode::RecoveryRequired,
        "spend paths must not operate on a negative journal"
    );
    // Reconciliation records the shortfall and opens a difference case
    // instead of failing, so the quorum repair path stays reachable.
    let checkpoint = r.reconcile(&source, &BTreeMap::new()).unwrap();
    assert!(!checkpoint.body.is_consistent());
    let balance = checkpoint
        .body
        .balances
        .iter()
        .find(|b| b.asset_id == native.asset_id)
        .unwrap();
    assert_eq!(balance.journal_balance, Amount::ZERO);
    assert_eq!(balance.journal_shortfall, Amount(50));
    assert_eq!(balance.difference(), (false, Amount(49 + 50)));
    assert_eq!(checkpoint.body.cases_opened.len(), 1);
    let correction = JournalCorrection {
        institution_id: inst(),
        environment_id: env_id(),
        case_id: checkpoint.body.cases_opened[0].clone(),
        checkpoint_id: checkpoint.body.checkpoint_id.clone(),
        chain_wallet_id: c.wallet.chain_wallet_id.clone(),
        asset_id: native.asset_id.clone(),
        side: EntrySide::Credit,
        amount: Amount(99),
        reason: "Quarantined receipts were spent on chain; evidence EX-99".into(),
    };
    let signatures: Vec<_> = world.admins[..2]
        .iter()
        .map(|(id, key)| CredentialSignature {
            credential_id: id.clone(),
            signature: SignatureBytes {
                scheme: SchemeId::Ed25519Pure,
                bytes: Bytes(key.sign(&correction.hash().unwrap().0).to_bytes().to_vec()),
            },
        })
        .collect();
    r.resolve_difference(&correction, &signatures, world.authority.as_ref(), now())
        .unwrap();
    assert_eq!(
        r.holdings(&c.wallet.chain_wallet_id, &native.asset_id, Amount::ZERO)
            .unwrap()
            .settled,
        Amount(49),
        "the authorized credit restores the journal to the chain position"
    );
    assert!(r
        .reconcile(&source, &BTreeMap::new())
        .unwrap()
        .body
        .is_consistent());
}
