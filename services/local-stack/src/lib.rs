//! Development-only D1 custody composition. Not a production deployment profile.

mod chain;
mod http;
mod provision;
mod storage;
pub use chain::{Action, Chain, Control, Outcome};
pub use provision::bootstrap;

use ed25519_dalek::SigningKey;
use fs2::FileExt;
use oic_authorization_state::{
    Authority, AuthorityConfig, AuthorityStore, Clock, FileAuthorityStore, SystemClock,
};
use oic_crypto_provider::{CryptoProvider, PeerMessage, ProtocolStep};
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_crypto_provider_frost_ed25519::FrostEd25519Provider;
use oic_domain_types::*;
use oic_one_time_state_ledger::FileLedger;
use oic_service_api::{Api, ApiCredential, ApiStore, Catalog, Scope};
use oic_service_broadcaster::{Broadcaster, FileSubmissionStore};
use oic_service_coordinator::{Coordinator, FileOperationStore, InProcessSigner, SignerEndpoint};
use oic_service_reconciler::*;
use oic_signer::{FileGenerationStore, Signer, SignerIdentity, SigningMaterials, TrustRoots};
use provision::*;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use storage::*;

pub const PROFILE: &str = "DEVELOPMENT-ONLY local simulators / single D1 authority";

/// Owns the exclusive process lock for all local stores. Keep the returned
/// router alive only while this Arc is alive; every route retains it.
pub struct Stack {
    api: Arc<Api<FileAuthorityStore>>,
    chains: Arc<chain::DurableChains>,
    provisioned: Provisioned,
    operator_hash: Hash32,
    faults: bool,
    events_public_key: [u8; 32],
    _lock: File,
}

impl Stack {
    pub fn open(
        state: &Path,
        enable_faults: bool,
        fail_after_release: bool,
    ) -> OicResult<Arc<Self>> {
        if fail_after_release && !enable_faults {
            return Err(OicError::invalid_request(
                "release fault requires explicit --enable-faults",
            ));
        }
        Self::open_inner_with_fault(state, false, enable_faults, fail_after_release)
    }
    fn open_inner(state: &Path, initial: bool, faults: bool) -> OicResult<Arc<Self>> {
        Self::open_inner_with_fault(state, initial, faults, false)
    }
    fn open_inner_with_fault(
        state: &Path,
        initial: bool,
        faults: bool,
        fail_after_release: bool,
    ) -> OicResult<Arc<Self>> {
        private_directory(state)?;
        if !initial {
            if !state.join("provisioned.json").is_file() {
                return Err(io(format!(
                    "{} was never provisioned (no provisioned.json). fix: run scripts/local-stack/bootstrap.sh first; if an earlier bootstrap failed before completing, delete this directory and bootstrap again. Never delete a provisioned installation to resolve payment uncertainty",
                    state.display()
                )));
            }
            for name in [
                "ready.json",
                "authority.json",
                "api.sqlite",
                "coordinator.jsonl",
                "submissions.jsonl",
                "operations.json",
                "simulator.jsonl",
                "simulator.floor",
                "ledger-0",
                "ledger-1",
                "ledger-2",
                "ledger-3",
                "generation-0.json",
                "generation-1.json",
                "generation-2.json",
                "generation-3.json",
            ] {
                if !state.join(name).is_file() {
                    return Err(io(format!(
                        "missing persisted {name}; refusing to open a provisioned installation with incomplete stores. fix: restore the complete state directory from your copy; do not delete stores or bootstrap again — payment state may be unresolved"
                    )));
                }
            }
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(state.join("process.lock"))
            .map_err(io)?;
        lock.try_lock_exclusive().map_err(|_| {
            OicError::new(
                ErrorCode::AuthorityUnavailable,
                "another local-stack process holds the exclusive state lock",
            )
        })?;
        let p: Provisioned = read(&state.join("provisioned.json"))?;
        let secrets: Secrets = read(&state.join("secrets.json"))?;
        if p.schema_version != 1
            || p.keys.len() != 2
            || p.sealed.len() != 2
            || p.wallets.len() != 2
            || p.assets.len() != 2
            || p.destinations.len() != 2
            || p.profiles.len() != 2
            || secrets.sealing.len() != 4
        {
            return Err(io("invalid local provisioning format"));
        }
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let store = Arc::new(FileAuthorityStore::open(
            state.join("authority.json"),
            None,
        )?);
        let fence = store.read(|s| s.fence_token)?;
        let authority = Arc::new(Authority::open(
            store,
            fence,
            AuthorityConfig {
                institution_id: inst(),
                environment_id: environment(),
                authority_key_id: authority_key_id(),
                admin_keys: admins(&p)?,
                admin_quorum: 2,
                freeze_responders: vec![],
                release_receipt_ttl_seconds: 60,
                max_clock_skew_seconds: 30,
            },
            SigningKey::from_bytes(&secrets.authority),
            clock.clone(),
        )?);
        let roots = TrustRoots {
            authority_key_id: authority_key_id(),
            authority_pubkey: authority.verifying_key(),
            admin_keys: admins(&p)?,
            admin_quorum: 2,
            approvers: approver_credentials(&p)?,
            accepted_verifier_builds: builds(),
            chain_profiles: p.profiles.clone(),
            max_clock_skew_seconds: 30,
        };
        let adapter_list = adapters();
        let mut signers = Vec::new();
        let mut endpoints: Vec<Arc<dyn SignerEndpoint>> = Vec::new();
        let fail = Arc::new(AtomicBool::new(fail_after_release));
        for (key_index, key) in p.keys.iter().enumerate() {
            for (participant, sealed) in &p.sealed[key_index] {
                let i = signers.len();
                let provider: Arc<dyn CryptoProvider> = if key_index == 0 {
                    Arc::new(DevSingleKeyProvider::with_os_rng(
                        SchemeId::EcdsaSecp256k1Keccak256Prehashed,
                        secrets.sealing[i],
                    )?)
                } else {
                    Arc::new(FrostEd25519Provider::with_os_rng(
                        participant.clone(),
                        secrets.sealing[i],
                    )?)
                };
                let signer = Arc::new(Signer::open(
                    SignerIdentity {
                        participant_id: participant.clone(),
                        institution_id: inst(),
                        environment_id: environment(),
                    },
                    roots.clone(),
                    BTreeMap::from([(
                        p.profiles[key_index].adapter_id.clone(),
                        adapter_list[key_index].clone(),
                    )]),
                    provider,
                    Arc::new(FileLedger::open(state.join(format!("ledger-{i}")), None)?),
                    Arc::new(FileGenerationStore::new(
                        state.join(format!("generation-{i}.json")),
                    )),
                )?);
                signer.load_key(key, sealed)?;
                endpoints.push(Arc::new(ReleaseFault {
                    inner: InProcessSigner(signer.clone()),
                    fail: fail.clone(),
                }));
                signers.push(signer);
            }
        }
        for a in &signers {
            for b in &signers {
                if a.identity().participant_id != b.identity().participant_id {
                    a.set_peer_generation(&b.identity().participant_id, b.generation())?;
                }
            }
        }
        let chains = chain::DurableChains::open(
            &state.join("simulator.jsonl"),
            p.genesis,
            p.simulator_seeds,
            (
                p.wallets[0].address.as_slice().try_into().map_err(io)?,
                p.wallets[1].address.as_slice().try_into().map_err(io)?,
            ),
        )?;
        let (evm, solana) = chains.simulators()?;
        let coordinator = Arc::new(Coordinator::new(
            authority.clone(),
            endpoints,
            adapter_list.clone(),
            clock.clone(),
            Arc::new(FileOperationStore::open(state.join("coordinator.jsonl"))?),
        )?);
        let mut broadcaster = Broadcaster::new(
            authority.clone(),
            Arc::new(FileSubmissionStore::open(state.join("submissions.jsonl"))?),
            clock.clone(),
        );
        for (i, chain) in [Chain::Evm, Chain::Solana].iter().enumerate() {
            broadcaster.register_network(
                p.profiles[i].clone(),
                adapter_list[i].clone(),
                chains.client(*chain, clock.clone())?,
            )?;
        }
        broadcaster.recover()?;
        let reconciler = Arc::new(Reconciler::open(
            Arc::new(OperationsStore::open(state.join("operations.json"))?),
            inst(),
            environment(),
            KeyId::unchecked("local-reconciler-events"),
            SigningKey::from_bytes(&secrets.events),
        )?);
        let mut catalog = Catalog::default();
        catalog.vaults.insert(vault_id(), vault());
        for (i, adapter) in adapter_list.iter().enumerate() {
            catalog
                .wallets
                .insert(p.wallets[i].chain_wallet_id.clone(), p.wallets[i].clone());
            catalog
                .keys
                .insert(p.keys[i].key_id.clone(), p.keys[i].clone());
            catalog
                .assets
                .insert(p.assets[i].asset_id.clone(), p.assets[i].clone());
            catalog.destinations.insert(
                (
                    p.destinations[i].destination_id.clone(),
                    p.destinations[i].version,
                ),
                p.destinations[i].clone(),
            );
            catalog.profiles.insert(
                p.profiles[i].chain_profile_id.clone(),
                p.profiles[i].clone(),
            );
            catalog
                .adapters
                .insert(p.profiles[i].adapter_id.clone(), adapter.clone());
            catalog.participants.insert(
                p.keys[i].key_id.clone(),
                p.sealed[i]
                    .iter()
                    .take(p.keys[i].threshold as usize)
                    .map(|(id, _)| id.clone())
                    .collect(),
            );
        }
        catalog.evidence.insert(
            p.profiles[0].chain_profile_id.clone(),
            Arc::new(oic_service_builder::EvmSimulatorEvidence(evm)),
        );
        catalog.evidence.insert(
            p.profiles[1].chain_profile_id.clone(),
            Arc::new(oic_service_builder::SolanaSimulatorEvidence(solana)),
        );
        let credentials = [
            (
                &secrets.console,
                proposer(),
                vec![Scope::Read, Scope::Propose, Scope::Submit],
            ),
            (
                &secrets.reader,
                CredentialId::unchecked("local-observer"),
                vec![Scope::Read],
            ),
            (
                &secrets.approval,
                approver(),
                vec![Scope::Read, Scope::Approve],
            ),
        ]
        .into_iter()
        .map(|(token, id, scopes)| ApiCredential {
            token_hash: oic_canonical_encoding::sha256(token.as_bytes()),
            credential_id: id,
            vaults: vec![vault_id()],
            scopes,
        })
        .collect();
        let api = Arc::new(Api {
            store: Arc::new(ApiStore::open(
                state.join("api.sqlite"),
                inst(),
                environment(),
            )?),
            coordinator,
            broadcaster: Arc::new(broadcaster),
            reconciler,
            catalog,
            credentials,
            approvers: approver_credentials(&p)?,
            clock,
        });
        protect_files(state)?;
        Ok(Arc::new(Self {
            api,
            chains,
            provisioned: p,
            operator_hash: oic_canonical_encoding::sha256(secrets.operator.as_bytes()),
            faults,
            events_public_key: SigningKey::from_bytes(&secrets.events)
                .verifying_key()
                .to_bytes(),
            _lock: lock,
        }))
    }
    pub fn router(self: &Arc<Self>) -> axum::Router {
        http::router(self.clone())
    }
    /// Authenticated HTTP read model. It contains no bearer, sealing key,
    /// signing share, approver private key, or optimistic local custody truth.
    pub fn catalog(&self) -> Value {
        let p = &self.provisioned;
        json!({"schema_version":1,"profile":PROFILE,"institution_id":inst(),"environment_id":environment(),"proposer_credential_id":proposer(),"approver_credential_id":approver(),"vaults":[vault()],"wallets":p.wallets,"assets":p.assets,"destinations":p.destinations,"profiles":p.profiles,"keys":p.keys,"policy":p.policy,"event_verifying_key":hex::encode(self.events_public_key),"authority_verifying_key":hex::encode(self.api.coordinator.authority().verifying_key().to_bytes()),"backend_limits":{"evm":"DEVELOPMENT 1-of-1 secp256k1","solana":"FROST 2-of-3, co-resident in one development process","recovery":"local files only; no independent rollback witness"}})
    }
    fn enroll(&self) -> OicResult<()> {
        for (i, wallet) in self.provisioned.wallets.iter().enumerate() {
            let id = DepositAddressId::unchecked(wallet.chain_wallet_id.to_string());
            self.api.reconciler.enroll(
                DepositAddress {
                    deposit_address_id: id.clone(),
                    institution_id: inst(),
                    environment_id: environment(),
                    vault_id: vault_id(),
                    chain_wallet_id: Some(wallet.chain_wallet_id.clone()),
                    chain_profile_id: wallet.chain_profile_id.clone(),
                    network_id: wallet.network_id.clone(),
                    address: wallet.address.clone(),
                    address_display: wallet.address_display.clone(),
                    custody: AddressCustody::Controlled,
                    supported_assets: vec![self.provisioned.assets[i].asset_id.clone()],
                    routing_reference: None,
                    state: DepositAddressState::Inactive,
                    created_at: self.api.clock.now(),
                    retired_at: None,
                },
                std::slice::from_ref(&self.provisioned.assets[i]),
                Amount::ZERO,
            )?;
            let step = Some(ActivationStep {
                committed_at: self.api.clock.now(),
                commitment: oic_canonical_encoding::sha256(
                    &serde_json::to_vec(wallet).map_err(io)?,
                ),
                actor: "DEVELOPMENT single-machine bootstrap; not an independent-domain ceremony"
                    .into(),
            });
            self.api.reconciler.activate(AddressActivation {
                deposit_address_id: id,
                public_key_agreement: step.clone(),
                asset_network_configuration: step.clone(),
                recovery_metadata: step.clone(),
                monitoring_registration: step,
            })?;
        }
        Ok(())
    }
    fn sync(&self) -> OicResult<Value> {
        let (evm, solana) = self.chains.simulators()?;
        let sources: Vec<Box<dyn BlockSource>> = vec![
            Box::new(EvmBlocks(evm.clone())),
            Box::new(SolanaBlocks(solana.clone())),
        ];
        let families = self
            .api
            .coordinator
            .authority()
            .store()
            .read(|s| s.families.keys().cloned().collect::<Vec<_>>())?;
        for family in families {
            if self.api.broadcaster.record(&family)?.is_some() {
                self.api.broadcaster.poll(&family)?;
            }
        }
        let native = self
            .provisioned
            .assets
            .iter()
            .map(|a| (a.network_id.clone(), a.asset_id.clone()))
            .collect();
        let reservations = outstanding_reservations(
            self.api.coordinator.authority().store().as_ref(),
            &self.provisioned.wallets,
            &native,
        )?;
        let mut checkpoints = Vec::new();
        for source in &sources {
            self.api.reconciler.sync(source.as_ref())?;
            checkpoints.push(
                self.api
                    .reconciler
                    .reconcile(source.as_ref(), &reservations)?,
            );
        }
        let ids = self
            .api
            .coordinator
            .authority()
            .store()
            .read(|s| s.intents.keys().cloned().collect::<Vec<_>>())?;
        for id in ids {
            match self.api.store.get(&id) {
                Ok(record) => self.api.publish_operation(&record)?,
                Err(e) if e.code == ErrorCode::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let mut balances = Vec::new();
        for (i, source) in sources.iter().enumerate() {
            let p = &self.provisioned;
            balances.push(json!({"chain":if i==0 {"evm"} else {"solana"},"head":source.head(),"wallet_balance":source.balance(&source.head(),&p.wallets[i].address,&AssetKind::Native)?,"beneficiary_balance":source.balance(&source.head(),&p.destinations[i].address,&AssetKind::Native)?,"holdings":self.api.reconciler.holdings(&p.wallets[i].chain_wallet_id,&p.assets[i].asset_id,*reservations.get(&(p.wallets[i].chain_wallet_id.clone(),p.assets[i].asset_id.clone())).unwrap_or(&Amount::ZERO))?}));
        }
        Ok(json!({"balances":balances,"checkpoints":checkpoints}))
    }
}

struct ReleaseFault {
    inner: InProcessSigner,
    fail: Arc<AtomicBool>,
}
impl SignerEndpoint for ReleaseFault {
    fn participant_id(&self) -> ParticipantId {
        self.inner.participant_id()
    }
    fn generation(&self) -> Epoch {
        self.inner.generation()
    }
    fn open_session(
        &self,
        e: &AuthorizationEnvelope,
        m: &SigningMaterials,
        n: UnixSeconds,
    ) -> OicResult<ProtocolStep> {
        self.inner.open_session(e, m, n)
    }
    fn receive(&self, s: &SigningSessionId, m: &PeerMessage) -> OicResult<ProtocolStep> {
        self.inner.receive(s, m)
    }
    fn release(
        &self,
        s: &SigningSessionId,
        r: &AuthorityReceipt,
        n: UnixSeconds,
    ) -> OicResult<Vec<ProtocolStep>> {
        let output = self.inner.release(s, r, n)?;
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(OicError::new(ErrorCode::AuthorityUnavailable,"DEVELOPMENT fault after durable release/share output; coordinator acknowledgement lost"));
        }
        Ok(output)
    }
    fn aggregate(
        &self,
        s: &SigningSessionId,
        shares: &[(ParticipantId, Bytes)],
    ) -> OicResult<SignatureBytes> {
        self.inner.aggregate(s, shares)
    }
    fn abort(&self, s: &SigningSessionId) -> OicResult<()> {
        self.inner.abort(s)
    }
}
