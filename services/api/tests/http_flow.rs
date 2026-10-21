#[path = "../../coordinator/tests/common/mod.rs"]
mod common;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use common::*;
use ed25519_dalek::SigningKey;
use oic_adapter_api::SignedTransaction;
use oic_authorization_state::{BudgetKey, InMemoryAuthorityStore};
use oic_canonical_encoding::{domain_hash, sha256};
use oic_domain_types::*;
use oic_service_api::*;
use oic_service_broadcaster::*;
use oic_service_coordinator::InMemoryOperationStore;
use oic_service_reconciler::*;
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

fn api(
    world: &World,
    c: &Chain,
    client: Arc<dyn ChainClient>,
    path: &std::path::Path,
) -> Arc<Api<InMemoryAuthorityStore>> {
    let mut catalog = Catalog::default();
    catalog.vaults.insert(vault_id(), vault());
    catalog
        .wallets
        .insert(c.wallet.chain_wallet_id.clone(), c.wallet.clone());
    catalog.keys.insert(c.key.key_id.clone(), c.key.clone());
    catalog
        .assets
        .insert(c.asset.asset_id.clone(), c.asset.clone());
    catalog.destinations.insert(
        (c.destination.destination_id.clone(), c.destination.version),
        c.destination.clone(),
    );
    catalog
        .profiles
        .insert(c.profile.chain_profile_id.clone(), c.profile.clone());
    catalog
        .adapters
        .insert(c.profile.adapter_id.clone(), c.adapter.clone());
    catalog
        .evidence
        .insert(c.profile.chain_profile_id.clone(), c.source.clone());
    catalog.participants.insert(
        c.key.key_id.clone(),
        c.nodes
            .iter()
            .take(c.key.threshold as usize)
            .map(|n| n.id.clone())
            .collect(),
    );
    let mut broadcaster = Broadcaster::new(
        world.authority.clone(),
        Arc::new(MemorySubmissionStore::new()),
        world.clock.clone(),
    );
    broadcaster
        .register_network(c.profile.clone(), c.adapter.clone(), client)
        .unwrap();
    let credentials = [
        (
            "proposer",
            "proposer-1",
            vec![Scope::Read, Scope::Propose, Scope::Submit],
        ),
        ("approver", "approver-1", vec![Scope::Read, Scope::Approve]),
        ("reader", "observer", vec![Scope::Read]),
    ]
    .into_iter()
    .map(|(token, id, scopes)| ApiCredential {
        token_hash: sha256(token.as_bytes()),
        credential_id: CredentialId::unchecked(id),
        vaults: vec![vault_id()],
        scopes,
    })
    .collect();
    Arc::new(Api {
        store: Arc::new(ApiStore::open(path, inst(), env_id()).unwrap()),
        coordinator: Arc::new(coordinator(
            world,
            c,
            in_process(&c.nodes),
            Arc::new(InMemoryOperationStore::new()),
        )),
        broadcaster: Arc::new(broadcaster),
        reconciler: Arc::new(
            Reconciler::open(
                Arc::new(OperationsStore::memory()),
                inst(),
                env_id(),
                KeyId::unchecked("events"),
                SigningKey::from_bytes(&[44; 32]),
            )
            .unwrap(),
        ),
        catalog,
        credentials,
        approvers: world.approver_credentials(),
        clock: world.clock.clone(),
    })
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("idempotency-key", "external-payment-123")
        .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, value)
}

async fn transfer(
    world: &World,
    c: &Chain,
    api: &Arc<Api<InMemoryAuthorityStore>>,
) -> IntentRecord {
    let app = router(api.clone());
    let intent = c.intent(
        "http-money-loop",
        123_456,
        10_000_000_000_000_000,
        ApprovalMode::ExactCandidate,
    );
    let body = serde_json::to_value(&intent).unwrap();
    assert_eq!(
        call(&app, "POST", "/v1/intents", "reader", Some(body.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, "POST", "/v1/intents", "wrong", Some(body.clone()))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, created) = call(&app, "POST", "/v1/intents", "proposer", Some(body.clone())).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let record: IntentRecord = serde_json::from_value(created.clone()).unwrap();
    assert_eq!(
        call(&app, "POST", "/v1/intents", "proposer", Some(body.clone()))
            .await
            .1,
        created,
        "same idempotency key returns the same candidate, not new evidence/nonces"
    );
    let mut changed = intent.clone();
    let IntentOperation::AssetTransfer {
        ref mut amount_base_units,
        ..
    } = changed.operation;
    *amount_base_units = Amount(123_457);
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/intents",
            "proposer",
            Some(serde_json::to_value(changed).unwrap())
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let submit = "/v1/intents/http-money-loop/submit";
    let (status, error) = call(&app, "POST", submit, "proposer", None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "APPROVAL_REQUIRED");
    assert_eq!(
        api.store.get(&intent.intent_id).unwrap().dispatch,
        DispatchState::Ready,
        "missing approval must not poison the dispatch marker"
    );
    let grant = world.exact_grant(&record.built, 0);
    let grant_json = serde_json::to_value(grant).unwrap();
    let approvals = "/v1/intents/http-money-loop/approvals";
    let (status, approved) = call(
        &app,
        "POST",
        approvals,
        "approver",
        Some(grant_json.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(
        call(&app, "POST", approvals, "approver", Some(grant_json))
            .await
            .1,
        approved
    );
    let (status, signed) = call(&app, "POST", submit, "proposer", None).await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    assert_eq!(
        call(&app, "POST", submit, "proposer", None).await.1,
        signed,
        "lost acknowledgement must reuse exactly the signed transaction"
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/intents/http-money-loop/cancel",
            "proposer",
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    serde_json::from_value(signed).unwrap()
}

#[tokio::test]
async fn evm_http_approval_native_signature_execution_and_restart() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    world
        .authority
        .set_policy(&world.sign_policy(policy(1, vec![rule(&c.asset.asset_id, 1, 10_000_000)])))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sqlite");
    let api = api(
        &world,
        c,
        Arc::new(EvmSimulatorClient::new(evm.sim.clone())),
        &path,
    );
    let signed = transfer(&world, c, &api).await;
    evm.sim.mine_blocks(4).unwrap();
    let family = signed.built.candidate.operation_family_id.to_string();
    let (status, state) = call(
        &router(api.clone()),
        "POST",
        &format!("/v1/operations/{family}/refresh"),
        "proposer",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{state}");
    assert_eq!(
        serde_json::from_value::<LifecycleState>(state).unwrap(),
        LifecycleState::FinalizedSuccess
    );
    assert_eq!(
        evm.sim
            .erc20_balance(
                &evm.token,
                &c.destination.address.as_slice().try_into().unwrap()
            )
            .unwrap(),
        123_456
    );
    let reopened = ApiStore::open(&path, inst(), env_id()).unwrap();
    assert_eq!(reopened.get(&signed.intent.intent_id).unwrap(), signed);
    assert!(ApiStore::open(&path, inst(), EnvironmentId::unchecked("mainnet")).is_err());
    let issuance = signed.issuance.as_ref().unwrap();
    oic_authorization_state::verify_receipt(
        &issuance.release_receipt,
        &world.authority.verifying_key(),
        &oic_authorization_state::ReceiptExpectation {
            kind: ReceiptKind::Release,
            envelope_body_hash: oic_signer::envelope_body_hash(&issuance.envelope.body).unwrap(),
            signer_session_id: issuance.envelope.body.signer_session_id.clone(),
            candidate_id: signed.built.candidate.candidate_id.clone(),
            candidate_revision: signed.built.candidate.candidate_revision,
            now: issuance.release_receipt.body.issued_at,
            policy_epoch: signed.built.package.policy.policy_epoch,
        },
    )
    .unwrap();
    let app = router(api.clone());
    let mut replayed = vec![];
    loop {
        let after = replayed
            .last()
            .map(|e: &LifecycleEvent| e.body.sequence)
            .unwrap_or(0);
        let (status, page) = call(
            &app,
            "GET",
            &format!("/v1/events?after={after}&limit=1"),
            "reader",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: Vec<LifecycleEvent> = serde_json::from_value(page).unwrap();
        if page.is_empty() {
            break;
        }
        assert_eq!(page[0].body.sequence, after + 1);
        verify_signature(
            &SigningKey::from_bytes(&[44; 32]).verifying_key(),
            domain_hash(domains::WEBHOOK, &page[0].body).unwrap(),
            &page[0].signature,
        )
        .unwrap();
        replayed.extend(page);
    }
    assert_eq!(replayed, api.reconciler.events_since(0, 1000).unwrap());
    let observed_states: Vec<_> = replayed
        .iter()
        .filter_map(|e| match e.body.kind {
            LifecycleEventKind::OperationStateChanged { to, .. } => Some(to),
            _ => None,
        })
        .collect();
    assert_eq!(
        observed_states,
        vec![
            LifecycleState::Draft,
            LifecycleState::Submitted,
            LifecycleState::FinalizedSuccess
        ]
    );
    let (status, error) = call(&app, "GET", "/v1/events?after=garbage", "reader", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "INVALID_REQUEST");
    let (_, evidence) = call(
        &router(api),
        "GET",
        &format!("/v1/operations/{family}/evidence"),
        "reader",
        None,
    )
    .await;
    assert_eq!(
        serde_json::from_value::<IntentRecord>(evidence).unwrap(),
        signed
    );
}

/// Exercise real RPC acceptance followed by a lost acknowledgement, not a
/// fabricated signature or mocked accounting result.
struct LostAck(EvmSimulatorClient);
impl ChainClient for LostAck {
    fn network_id(&self) -> NetworkId {
        self.0.network_id()
    }
    fn sources(&self) -> Vec<EvidenceSourceId> {
        self.0.sources()
    }
    fn submit(&self, signed: &SignedTransaction) -> OicResult<ChainTxId> {
        self.0.submit(signed)?;
        Err(OicError::new(
            ErrorCode::AuthorityUnavailable,
            "lost RPC acknowledgement",
        ))
    }
    fn evidence_for_tx(
        &self,
        source: &EvidenceSourceId,
        id: &ChainTxId,
        commitment: Commitment,
    ) -> OicResult<EvidenceBundle> {
        self.0.evidence_for_tx(source, id, commitment)
    }
    fn evidence_for_candidates(
        &self,
        source: &EvidenceSourceId,
        candidates: &[PossiblyIssued],
        commitment: Commitment,
    ) -> OicResult<EvidenceBundle> {
        self.0
            .evidence_for_candidates(source, candidates, commitment)
    }
    fn head(&self) -> StateReference {
        self.0.head()
    }
    fn finalized(&self) -> StateReference {
        self.0.finalized()
    }
}

#[tokio::test]
async fn lost_rpc_ack_then_api_restart_reuses_signed_bytes_and_release_evidence() {
    let world = World::new();
    let evm = evm_chain(&world);
    let c = &evm.chain;
    world
        .authority
        .set_policy(&world.sign_policy(policy(1, vec![rule(&c.asset.asset_id, 0, 10_000_000)])))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sqlite");
    let first = api(
        &world,
        c,
        Arc::new(LostAck(EvmSimulatorClient::new(evm.sim.clone()))),
        &path,
    );
    let app = router(first.clone());
    let intent = c.intent(
        "lost-ack",
        765_432,
        10u128.pow(16),
        ApprovalMode::ExactCandidate,
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/intents",
            "proposer",
            Some(serde_json::to_value(&intent).unwrap())
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/intents/lost-ack/submit",
            "proposer",
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let before = first.store.get(&intent.intent_id).unwrap();
    assert_eq!(before.dispatch, DispatchState::Signed);
    assert!(before.issuance.is_some());
    assert_eq!(world.authority.store().snapshot().issuance.len(), 1);
    let family = &before.built.candidate.operation_family_id;
    let (status, operation) = call(
        &app,
        "GET",
        &format!("/v1/operations/{family}"),
        "reader",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        operation["lifecycle"],
        serde_json::to_value(LifecycleState::SubmissionUnknown).unwrap(),
        "HTTP success promises durable signed evidence, not RPC acknowledgement or finality"
    );
    assert!(matches!(
        first
            .reconciler
            .events_since(0, 100)
            .unwrap()
            .last()
            .unwrap()
            .body
            .kind,
        LifecycleEventKind::OperationStateChanged {
            to: LifecycleState::SubmissionUnknown,
            ..
        }
    ));
    drop(app);
    drop(first);
    let reopened = api(
        &world,
        c,
        Arc::new(EvmSimulatorClient::new(evm.sim.clone())),
        &path,
    );
    let (status, retried) = call(
        &router(reopened),
        "POST",
        "/v1/intents/lost-ack/submit",
        "proposer",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{retried}");
    assert_eq!(
        serde_json::from_value::<IntentRecord>(retried).unwrap(),
        before
    );
    assert_eq!(world.authority.store().snapshot().issuance.len(), 1);
    evm.sim.mine_blocks(4).unwrap();
    assert_eq!(
        evm.sim
            .erc20_balance(
                &evm.token,
                &c.destination.address.as_slice().try_into().unwrap()
            )
            .unwrap(),
        765_432
    );
}

#[tokio::test]
async fn independent_api_connections_racing_dispatch_and_cancel_do_not_overwrite_the_winner() {
    for race_cancel in [false, true] {
        let world = World::new();
        let evm = evm_chain(&world);
        let c = &evm.chain;
        world
            .authority
            .set_policy(&world.sign_policy(policy(1, vec![rule(&c.asset.asset_id, 0, 10_000_000)])))
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sqlite");
        let first = api(
            &world,
            c,
            Arc::new(EvmSimulatorClient::new(evm.sim.clone())),
            &path,
        );
        let second = api(
            &world,
            c,
            Arc::new(EvmSimulatorClient::new(evm.sim.clone())),
            &path,
        );
        let a = router(first.clone());
        let b = router(second);
        let intent = c.intent(
            "race",
            456_789,
            10u128.pow(16),
            ApprovalMode::ExactCandidate,
        );
        assert_eq!(
            call(
                &a,
                "POST",
                "/v1/intents",
                "proposer",
                Some(serde_json::to_value(&intent).unwrap())
            )
            .await
            .0,
            StatusCode::OK
        );
        let other = if race_cancel {
            "/v1/intents/race/cancel"
        } else {
            "/v1/intents/race/submit"
        };
        let (x, y) = tokio::join!(
            call(&a, "POST", "/v1/intents/race/submit", "proposer", None),
            call(&b, "POST", other, "proposer", None)
        );
        assert!(
            x.0 == StatusCode::OK || y.0 == StatusCode::OK,
            "{x:?} {y:?}"
        );
        assert!(
            [StatusCode::OK, StatusCode::CONFLICT].contains(&x.0),
            "{x:?}"
        );
        assert!(
            [StatusCode::OK, StatusCode::CONFLICT].contains(&y.0),
            "{y:?}"
        );
        let stored = first.store.get(&intent.intent_id).unwrap();
        let issuance_count = world.authority.store().snapshot().issuance.len();
        if stored.dispatch == DispatchState::Cancelled {
            assert!(race_cancel);
            assert_eq!(issuance_count, 0);
            assert!(stored.issuance.is_none());
        } else {
            assert_eq!(stored.dispatch, DispatchState::Signed);
            assert_eq!(issuance_count, 1);
            assert!(stored.issuance.is_some());
        }
    }
}

#[tokio::test]
async fn solana_http_approval_frost_execution_and_rent_budget() {
    let world = World::new();
    let sol = sol_chain(&world, true);
    let c = &sol.chain;
    world
        .authority
        .set_policy(&world.sign_policy(policy(1, vec![rule(&c.asset.asset_id, 1, 10_000_000)])))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let api = api(
        &world,
        c,
        Arc::new(SolanaSimulatorClient::new(sol.sim.clone())),
        &dir.path().join("api.sqlite"),
    );
    let signed = transfer(&world, c, &api).await;
    sol.sim.advance_slots(7).unwrap();
    assert_eq!(
        api.broadcaster
            .poll(&signed.built.candidate.operation_family_id)
            .unwrap(),
        LifecycleState::FinalizedSuccess
    );
    assert_eq!(
        world
            .authority
            .exposure(
                &vault_id(),
                &BudgetKey::NativeFee {
                    network_id: c.profile.network_id.clone()
                },
                DAY
            )
            .unwrap(),
        Amount(5_200 + oic_chain_simulator::solana::RENT_EXEMPT_TOKEN_ACCOUNT as u128)
    );
    let owner = c.destination.address.as_slice().try_into().unwrap();
    let ata = oic_adapter_solana::address::associated_token_address(
        &owner,
        &sol.mint.unwrap(),
        &oic_adapter_solana::address::TOKEN_PROGRAM_ID,
    )
    .unwrap();
    assert_eq!(sol.sim.token_balance(&ata), Some(123_456));
    assert!(
        api.reconciler
            .reconcile(&SolanaBlocks(sol.sim.clone()), &BTreeMap::new())
            .is_err(),
        "API never invents monitoring activation or a reconciliation checkpoint"
    );
}
