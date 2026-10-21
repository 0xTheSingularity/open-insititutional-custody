//! Public HTTP + real OS-process restart contracts; no production fixture imports.
use ed25519_dalek::{SigningKey, VerifyingKey};
use oic_adapter_api::{ChainAdapter, ChainProfile};
use oic_approval_verifier::{DisplayInputs, IndependentVerifier};
use oic_authorization_state::{family_id_for, Clock, SystemClock};
use oic_domain_types::*;
use oic_service_api::{DispatchState, IntentRecord};
use oic_service_reconciler::OperationsExport;
use rand::rngs::OsRng;
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

struct Installation {
    _dir: tempfile::TempDir,
    state: PathBuf,
    handoff: PathBuf,
    key: SigningKey,
}
impl Installation {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("server");
        let handoff = dir.path().join("handoff");
        let key = SigningKey::generate(&mut OsRng);
        let output = Command::new(env!("CARGO_BIN_EXE_oic-local-stack"))
            .args(["bootstrap", "--state"])
            .arg(&state)
            .arg("--handoff")
            .arg(&handoff)
            .arg("--approver-public-key")
            .arg(hex::encode(key.verifying_key().to_bytes()))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "bootstrap: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            _dir: dir,
            state,
            handoff,
            key,
        }
    }
    fn token(&self, name: &str) -> String {
        let v: Value =
            serde_json::from_slice(&fs::read(self.handoff.join(format!("{name}.json"))).unwrap())
                .unwrap();
        v["token"].as_str().unwrap().into()
    }
    fn verifier(&self) -> IndependentVerifier {
        let t: Value =
            serde_json::from_slice(&fs::read(self.handoff.join("trust.json")).unwrap()).unwrap();
        let admins = t["admin_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    serde_json::from_value(v["credential_id"].clone()).unwrap(),
                    VerifyingKey::from_bytes(
                        &hex::decode(v["public_key_hex"].as_str().unwrap())
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect();
        let adapters: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::from([
            (
                AdapterId::unchecked("evm"),
                Arc::new(oic_adapter_evm::EvmAdapter) as Arc<dyn ChainAdapter>,
            ),
            (
                AdapterId::unchecked("solana"),
                Arc::new(oic_adapter_solana::SolanaAdapter) as Arc<dyn ChainAdapter>,
            ),
        ]);
        IndependentVerifier::new(
            adapters,
            serde_json::from_value::<Vec<ChainProfile>>(t["chain_profiles"].clone()).unwrap(),
            admins,
            2,
        )
    }
}
struct Server {
    child: Child,
    url: String,
    client: Client,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Server {
    async fn start(install: &Installation, release_fault: bool) -> Self {
        let ready = install
            ._dir
            .path()
            .join(format!("ready-{}.json", rand::random::<u64>()));
        let log_path = ready.with_extension("log");
        let log = fs::File::create(&log_path).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_oic-local-stack"));
        command
            .arg("start")
            .arg("--state")
            .arg(&install.state)
            .args(["--listen", "127.0.0.1:0", "--enable-faults", "--ready-file"])
            .arg(&ready)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        if release_fault {
            command.arg("--fail-after-release");
        }
        let child = command.spawn().unwrap();
        let mut server = Self {
            child,
            url: String::new(),
            client: Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(bytes) = fs::read(&ready) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    server.url = format!("http://{}", v["address"].as_str().unwrap());
                    break;
                }
            }
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "server exited: {}",
                fs::read_to_string(&log_path).unwrap()
            );
            assert!(
                Instant::now() < deadline,
                "startup timeout: {}",
                fs::read_to_string(&log_path).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (status, body) = server
            .call("GET", "/local/v1/catalog", &install.token("reader"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        server
    }
    async fn call(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut r = self
            .client
            .request(
                Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{}{path}", self.url),
            )
            .bearer_auth(token)
            .header("idempotency-key", path);
        if let Some(body) = body {
            r = r.json(&body);
        }
        let response = r.send().await.unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        let body = serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw":text}));
        (status, body)
    }
    async fn ok(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> Value {
        let (s, b) = self.call(method, path, token, body).await;
        assert_eq!(s, StatusCode::OK, "{method} {path}: {b}");
        b
    }
    async fn control(
        &self,
        install: &Installation,
        chain: &str,
        id: &str,
        action: &str,
        amount: Option<u128>,
    ) -> Value {
        let mut v = json!({"chain":chain,"id":id,"action":action});
        if let Some(n) = amount {
            v["amount"] = json!(n.to_string());
        }
        if action == "advance" {
            v["blocks"] = json!(4);
        }
        self.ok(
            "POST",
            "/local/v1/controls",
            &install.token("operator"),
            Some(v),
        )
        .await
    }
    async fn status(&self, i: &Installation) -> Value {
        self.ok("GET", "/local/v1/status", &i.token("reader"), None)
            .await
    }
}
fn inputs(p: &ApprovalPackage) -> DisplayInputs<'_> {
    DisplayInputs {
        intent: &p.intent,
        candidate: &p.candidate,
        wallet: &p.wallet,
        key: &p.key,
        vault: &p.vault,
        asset: &p.asset,
        destination: &p.destination,
        policy: &p.policy,
        evidence: &p.evidence,
    }
}
fn amount(v: &Value) -> u128 {
    serde_json::from_value::<Amount>(v.clone()).unwrap().0
}
fn chain_index(chain: &str) -> usize {
    if chain == "evm" {
        0
    } else {
        1
    }
}

async fn prepare(install: &Installation, s: &Server, chain: &str, id: &str) -> IntentRecord {
    let token = install.token("console");
    let c = s.ok("GET", "/local/v1/catalog", &token, None).await;
    for forbidden in ["secrets", "sealed", "sealing", "token", "signing_key"] {
        assert!(c.get(forbidden).is_none());
    }
    assert_eq!(
        s.call("GET", "/local/v1/catalog", "invalid", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        s.call(
            "POST",
            "/local/v1/controls",
            &token,
            Some(json!({"id":"unauthorized","chain":chain,"action":"advance","blocks":4}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    s.control(install, chain, "receive", "receive", Some(10_000_000))
        .await;
    let fee_funding = if chain == "evm" {
        100_000_000_000_000_000
    } else {
        100_000_000
    };
    let first = s
        .control(
            install,
            chain,
            "fee-funding",
            "fund_fees",
            Some(fee_funding),
        )
        .await;
    let replay = s
        .control(
            install,
            chain,
            "fee-funding",
            "fund_fees",
            Some(fee_funding),
        )
        .await;
    assert_eq!(
        first["outcome"], replay["outcome"],
        "same local funding id is idempotent"
    );
    assert_eq!(
        s.call(
            "POST",
            "/local/v1/controls",
            &install.token("operator"),
            Some(json!({"id":"fee-funding","chain":chain,"action":"fund_fees","amount":"2"}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    s.control(install, chain, "funding-finality", "advance", None)
        .await;
    if chain == "solana" {
        s.control(install, chain, "funding-finality-next", "advance", None)
            .await;
    }
    let i = chain_index(chain);
    let wallet: ChainWallet = serde_json::from_value(c["wallets"][i].clone()).unwrap();
    let asset: Asset = serde_json::from_value(c["assets"][i].clone()).unwrap();
    let dest: CounterpartyDestination =
        serde_json::from_value(c["destinations"][i].clone()).unwrap();
    let intent = Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked(id),
        institution_id: serde_json::from_value(c["institution_id"].clone()).unwrap(),
        environment_id: serde_json::from_value(c["environment_id"].clone()).unwrap(),
        vault_id: wallet.vault_id.clone(),
        chain_wallet_id: wallet.chain_wallet_id,
        chain_profile_id: wallet.chain_profile_id,
        operation: IntentOperation::AssetTransfer {
            asset_id: asset.asset_id,
            amount_base_units: Amount(1_234_567),
            destination_id: dest.destination_id,
            destination_version: dest.version,
        },
        constraints: IntentConstraints {
            max_network_fee_base_units: Amount(if chain == "evm" {
                10u128.pow(16)
            } else {
                20_000
            }),
            approval_mode: ApprovalMode::ExactCandidate,
            maximum_successful_payments: 1,
        },
        purpose: OperationPurpose::Settlement,
        external_reference: format!("independent-test-{chain}"),
        proposer_credential_id: serde_json::from_value(c["proposer_credential_id"].clone())
            .unwrap(),
        created_at: SystemClock.now(),
    };
    let v = serde_json::to_value(&intent).unwrap();
    assert_eq!(
        s.call(
            "POST",
            "/v1/intents",
            &install.token("reader"),
            Some(v.clone())
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let created = s.ok("POST", "/v1/intents", &token, Some(v.clone())).await;
    assert_eq!(s.ok("POST", "/v1/intents", &token, Some(v)).await, created);
    let path = format!("/v1/intents/{id}/submit");
    let (status, error) = s.call("POST", &path, &token, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["code"], "APPROVAL_REQUIRED", "{error}");
    let package: ApprovalPackage = serde_json::from_value(
        s.ok(
            "GET",
            &format!("/v1/intents/{id}/preview"),
            &install.token("approval"),
            None,
        )
        .await,
    )
    .unwrap();
    let verifier = install.verifier();
    let now = SystemClock.now();
    let display = verifier.render(&inputs(&package), now).unwrap();
    assert!(display.destination_matches_registry);
    assert_eq!(display.amount_base_units, "1234567");
    let mut tampered = package.clone();
    let IntentOperation::AssetTransfer {
        ref mut amount_base_units,
        ..
    } = tampered.intent.operation;
    *amount_base_units = Amount(1_234_568);
    assert!(
        verifier
            .approve(
                &display,
                &inputs(&tampered),
                (
                    CredentialId::unchecked("independent-approver"),
                    ApprovalRole::TreasuryApprover,
                    &install.key
                ),
                GrantId::unchecked("bad"),
                now,
                120
            )
            .is_err(),
        "changed operation is never signed by independent verifier"
    );
    let grant = verifier
        .approve(
            &display,
            &inputs(&package),
            (
                CredentialId::unchecked("independent-approver"),
                ApprovalRole::TreasuryApprover,
                &install.key,
            ),
            GrantId::unchecked(format!("grant-{id}")),
            now,
            120,
        )
        .unwrap();
    let path = format!("/v1/intents/{id}/approvals");
    let body = serde_json::to_value(&grant).unwrap();
    assert_eq!(
        s.call("POST", &path, &token, Some(body.clone())).await.0,
        StatusCode::FORBIDDEN,
        "console bearer has no approval scope"
    );
    let mut forged = grant.clone();
    forged.signature.bytes.0[0] ^= 1;
    assert_eq!(
        s.call(
            "POST",
            &path,
            &install.token("approval"),
            Some(serde_json::to_value(forged).unwrap())
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let record: IntentRecord = serde_json::from_value(
        s.ok("POST", &path, &install.token("approval"), Some(body))
            .await,
    )
    .unwrap();
    assert_eq!(record.dispatch, DispatchState::Ready);
    record
}

fn verify_native(record: &IntentRecord, chain: &str) {
    let signed = &record.issuance.as_ref().unwrap().signed.signed;
    let wallet = &record.built.package.wallet;
    let destination = &record.built.package.destination;
    if chain == "evm" {
        let (tx, sig) =
            oic_adapter_evm::tx::EvmTx::decode_signed(signed.signed_bytes.as_slice()).unwrap();
        assert_eq!(
            oic_adapter_evm::recover_address(&tx.signing_digest(), &sig)
                .unwrap()
                .as_slice(),
            wallet.address.as_slice()
        );
        assert_eq!(tx.to().as_slice(), destination.address.as_slice());
        assert_eq!(tx.value(), 1_234_567);
    } else {
        let tx = oic_adapter_solana::message::Transaction::decode(signed.signed_bytes.as_slice())
            .unwrap();
        VerifyingKey::from_bytes(wallet.address.as_slice().try_into().unwrap())
            .unwrap()
            .verify_strict(
                &tx.message.encode(),
                &ed25519_dalek::Signature::from_bytes(&tx.signatures[0]),
            )
            .unwrap();
    }
    assert_eq!(
        record.built.verified.decoded.recipient(),
        &destination.address
    );
}

#[tokio::test]
async fn both_native_chains_survive_approval_and_pending_submission_process_death() {
    for chain in ["evm", "solana"] {
        let install = Installation::new();
        let s = Server::start(&install, false).await;
        let id = format!("restart-{chain}");
        prepare(&install, &s, chain, &id).await;
        let before = s.status(&install).await;
        let i = chain_index(chain);
        let before_balance = amount(&before["balances"][i]["wallet_balance"]);
        drop(s);
        let s = Server::start(&install, false).await;
        assert_eq!(
            s.ok("GET", "/local/v1/intents", &install.token("reader"), None)
                .await,
            json!([id])
        );
        let path = format!("/v1/intents/{id}/submit");
        let issued: IntentRecord =
            serde_json::from_value(s.ok("POST", &path, &install.token("console"), None).await)
                .unwrap();
        verify_native(&issued, chain);
        let txid = issued
            .issuance
            .as_ref()
            .unwrap()
            .signed
            .signed
            .chain_tx_id
            .clone();
        assert_eq!(
            amount(&s.status(&install).await["balances"][i]["beneficiary_balance"]),
            0,
            "broadcast acknowledgement is not an economic effect"
        );
        drop(s);
        let s = Server::start(&install, false).await;
        let reissued: IntentRecord =
            serde_json::from_value(s.ok("POST", &path, &install.token("console"), None).await)
                .unwrap();
        assert_eq!(
            reissued.issuance, issued.issuance,
            "only identical stored bytes rebroadcast after restart"
        );
        let mut finalized = s
            .control(&install, chain, "payment-finality", "advance", None)
            .await;
        if chain == "solana" {
            assert!(
                amount(&finalized["status"]["balances"][i]["holdings"]["reserved"]) >= 1_234_567,
                "inclusion before finality must not release exposure"
            );
            finalized = s
                .control(&install, chain, "payment-finality-next", "advance", None)
                .await;
        }
        let balance = &finalized["status"]["balances"][i];
        assert_eq!(amount(&balance["beneficiary_balance"]), 1_234_567);
        let expected_fee = if chain == "evm" {
            21_000 * 1_100_000_000u128
        } else {
            5_200
        };
        assert_eq!(
            amount(&balance["wallet_balance"]),
            before_balance - 1_234_567 - expected_fee
        );
        assert_eq!(amount(&balance["holdings"]["reserved"]), 0);
        let export = s
            .ok("GET", "/v1/export", &install.token("reader"), None)
            .await;
        let data: OperationsExport = serde_json::from_value(export["operations"].clone()).unwrap();
        let catalog = s
            .ok("GET", "/local/v1/catalog", &install.token("reader"), None)
            .await;
        data.verify(
            &VerifyingKey::from_bytes(
                &hex::decode(catalog["event_verifying_key"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!data.journal.is_empty());
        let journal = data.journal.clone();
        let events = data.events.clone();
        let head = balance["head"].clone();
        drop(s);
        let s = Server::start(&install, false).await;
        let status = s.status(&install).await;
        assert_eq!(status["balances"][i]["head"], head);
        assert_eq!(
            amount(&status["balances"][i]["beneficiary_balance"]),
            1_234_567
        );
        let recovered: IntentRecord = serde_json::from_value(
            s.ok(
                "GET",
                &format!("/v1/intents/{id}"),
                &install.token("reader"),
                None,
            )
            .await,
        )
        .unwrap();
        assert_eq!(recovered.issuance.unwrap().signed.signed.chain_tx_id, txid);
        let export = s
            .ok("GET", "/v1/export", &install.token("reader"), None)
            .await;
        let data: OperationsExport = serde_json::from_value(export["operations"].clone()).unwrap();
        assert_eq!(
            data.journal, journal,
            "no duplicate debit/credit on full-store reopen"
        );
        assert!(
            data.events.starts_with(&events),
            "persisted event prefix survives reopen"
        );
        assert!(
            data.events[events.len()..]
                .iter()
                .all(|e| matches!(e.body.kind, LifecycleEventKind::CheckpointPublished { .. })),
            "refresh may publish new checkpoints, but never duplicate movement/operation events"
        );
        eprintln!("{chain}: independent approval, real native signature, three OS-process restarts, pending mempool replay, one beneficiary payment, actual fee {expected_fee}, verified journal/export");
    }
}

#[tokio::test]
async fn both_native_chains_keep_lost_submission_ack_and_never_pay_twice() {
    for chain in ["evm", "solana"] {
        let install = Installation::new();
        let s = Server::start(&install, false).await;
        let id = format!("lost-ack-{chain}");
        prepare(&install, &s, chain, &id).await;
        s.control(
            &install,
            chain,
            "lose-ack",
            "lose_next_submission_ack",
            None,
        )
        .await;
        let path = format!("/v1/intents/{id}/submit");
        s.ok("POST", &path, &install.token("console"), None).await;
        let family = family_id_for(&IntentId::unchecked(&id)).unwrap();
        let operation = s
            .ok(
                "GET",
                &format!("/v1/operations/{family}"),
                &install.token("reader"),
                None,
            )
            .await;
        assert_eq!(serde_json::from_value::<LifecycleState>(operation["lifecycle"].clone()).unwrap(), LifecycleState::SubmissionUnknown, "HTTP 200 means the request was processed, not that the native RPC acknowledged submission");
        let stored: IntentRecord = serde_json::from_value(
            s.ok(
                "GET",
                &format!("/v1/intents/{id}"),
                &install.token("reader"),
                None,
            )
            .await,
        )
        .unwrap();
        assert_eq!(stored.dispatch, DispatchState::Signed);
        assert!(stored.issuance.is_some());
        drop(s);
        let s = Server::start(&install, false).await;
        let restored: IntentRecord =
            serde_json::from_value(s.ok("POST", &path, &install.token("console"), None).await)
                .unwrap();
        assert_eq!(restored.issuance, stored.issuance);
        let result = s
            .control(&install, chain, "ack-finality", "advance", None)
            .await;
        assert_eq!(
            amount(&result["status"]["balances"][chain_index(chain)]["beneficiary_balance"]),
            1_234_567
        );
        s.ok("POST", &path, &install.token("console"), None).await;
        s.control(&install, chain, "one-more-block-batch", "advance", None)
            .await;
        assert_eq!(
            amount(
                &s.status(&install).await["balances"][chain_index(chain)]["beneficiary_balance"]
            ),
            1_234_567
        );
        eprintln!("{chain}: RPC acknowledgement lost after durable native submission; process death recovered identical signed bytes and one payment");
    }
}

#[tokio::test]
async fn both_native_chains_keep_exposure_and_refuse_retry_after_ambiguous_release() {
    for chain in ["evm", "solana"] {
        let install = Installation::new();
        let s = Server::start(&install, true).await;
        let id = format!("release-uncertain-{chain}");
        let prepared = prepare(&install, &s, chain, &id).await;
        let path = format!("/v1/intents/{id}/submit");
        let (_, error) = s.call("POST", &path, &install.token("console"), None).await;
        assert_eq!(error["code"], "ISSUANCE_UNCERTAIN");
        drop(s);
        let s = Server::start(&install, false).await;
        let (_, error) = s.call("POST", &path, &install.token("console"), None).await;
        assert_eq!(error["code"], "ISSUANCE_UNCERTAIN");
        let state: IntentRecord = serde_json::from_value(
            s.ok(
                "GET",
                &format!("/v1/intents/{id}"),
                &install.token("reader"),
                None,
            )
            .await,
        )
        .unwrap();
        assert_eq!(state.dispatch, DispatchState::Dispatching);
        assert!(state.issuance.is_none());
        let family = family_id_for(&prepared.intent.intent_id).unwrap();
        let operation = s
            .ok(
                "GET",
                &format!("/v1/operations/{family}"),
                &install.token("reader"),
                None,
            )
            .await;
        assert!(
            operation.to_string().contains("issuance_unknown")
                || operation.to_string().contains("ISSUANCE_UNKNOWN"),
            "{operation}"
        );
        s.control(&install, chain, "empty-finality", "advance", None)
            .await;
        let status = s.status(&install).await;
        let b = &status["balances"][chain_index(chain)];
        assert_eq!(amount(&b["beneficiary_balance"]), 0);
        assert!(
            amount(&b["holdings"]["reserved"]) >= 1_234_567,
            "native spend+fee exposure stays reserved: {b}"
        );
        eprintln!("{chain}: acknowledgement lost after release/share output; restart retained issuance uncertainty/exposure and refused new signing");
    }
}

#[tokio::test]
async fn simulator_reopen_recovers_torn_tail_but_rejects_changed_outcome_or_local_rollback() {
    let install = Installation::new();
    let s = Server::start(&install, false).await;
    for (chain, funding) in [("evm", 123_456), ("solana", 654_321)] {
        s.control(&install, chain, chain, "receive", Some(funding))
            .await;
        s.control(&install, chain, &format!("mine-{chain}"), "advance", None)
            .await;
    }
    let before = s.status(&install).await;
    drop(s);
    let path = install.state.join("simulator.jsonl");
    let complete = fs::read(&path).unwrap();
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"{\"sequence\":").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let s = Server::start(&install, false).await;
    let after = s.status(&install).await;
    for i in 0..2 {
        assert_eq!(before["balances"][i]["head"], after["balances"][i]["head"]);
        assert_eq!(
            before["balances"][i]["wallet_balance"],
            after["balances"][i]["wallet_balance"]
        );
    }
    assert_eq!(fs::read(&path).unwrap(), complete);
    drop(s);

    let mut lines: Vec<_> = complete.split_inclusive(|b| *b == b'\n').collect();
    let last = lines.pop().unwrap();
    let prefix = lines.concat();
    let mut entry: Value = serde_json::from_slice(last).unwrap();
    entry["outcome"]["lost_ack"] = json!(true);
    let mut changed = prefix.clone();
    changed.extend(serde_json::to_vec(&entry).unwrap());
    changed.push(b'\n');
    fs::write(&path, changed).unwrap();
    assert_open_rejected(&install).await;
    fs::write(&path, prefix).unwrap();
    assert_open_rejected(&install).await;
    fs::write(&path, complete).unwrap();
    let s = Server::start(&install, false).await;
    let after = s.status(&install).await;
    assert_eq!(after["balances"][0]["wallet_balance"], "123456");
    assert_eq!(after["balances"][1]["wallet_balance"], "654321");
    eprintln!("simulator journal: both-chain heads/balances survive torn-tail recovery; changed replay outcome and journal below retained floor fail closed");
}

async fn assert_open_rejected(install: &Installation) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_oic-local-stack"))
        .arg("start")
        .arg("--state")
        .arg(&install.state)
        .args(["--listen", "127.0.0.1:0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "invalid durable state must fail startup");
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("invalid durable state started a server instead of refusing");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
