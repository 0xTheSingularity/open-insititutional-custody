//! Shared real FROST key, admitted roster and private IPC cores. Certified
//! fixture logs are used only by the core contracts; live net tests attach
//! their own runtime-owned follower sources instead.
#![allow(dead_code)]
#[path = "../../../../crates/replicated-authority/tests/common/mod.rs"]
pub mod common;

use common::{signer, Chain, Committee, Fixture, NOW};
use commonware_runtime::deterministic;
use commonware_utils::TestRng;
use ed25519_dalek::SigningKey;
use oic_audit::{AuditLog, AuditLogConfig, FileAuditLog};
use oic_authorization_state::{AuthorityCommand, ManualClock, ReleaseRequest};
use oic_canonical_encoding::domain_hash;
use oic_crypto_provider::{CryptoProvider, KeygenCeremony, ProtocolStep};
use oic_crypto_provider_frost_ed25519::{run_dkg, FrostEd25519Provider};
use oic_domain_types::*;
use oic_membership::{self as membership, ChannelSpec, CommitteeKind, Node, PeerClass, Role, TrustDomain};
use oic_one_time_state_ledger::InMemoryLedger;
use oic_replicated_authority::{
    Command, FinalityTrust, FinalizedFloor, Follower, FollowerConfig, LogAnchor, ReplicatedState, ReserveCandidate, VerifiedLog,
};
use oic_service_coordinator::SignerEndpoint;
use oic_service_signer_core::{
    ipc,
    remote::{LocalClient, RemoteSigner},
    CoreConfig, SignerCore,
};
use oic_signer::{EnrolledMaterials, FinalizedAuthorityConfig, InMemoryGenerationStore, Signer, TrustRoots};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::watch;

pub const MAX_AGE: u64 = 30;

pub fn core_id(index: usize) -> NodeId {
    NodeId::unchecked(format!("core-{index}"))
}

fn public(seed: u8) -> PublicKey {
    PublicKey {
        scheme: SchemeId::Ed25519Pure,
        bytes: SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes().to_vec().into(),
    }
}

fn provider(index: usize) -> FrostEd25519Provider {
    FrostEd25519Provider::new(
        signer::pid(index as u8 + 1),
        signer::sealing_key(index as u8 + 1),
        Box::new(StdRng::seed_from_u64(800 + index as u64)),
    )
    .unwrap()
}

pub struct Contract {
    pub fixture: Fixture,
    pub committee: Committee,
    pub proof: ReserveCandidate,
    sealed: Vec<(ParticipantId, Bytes)>,
}

impl Contract {
    pub fn new() -> Self {
        Self::with_inputs(|_| {})
    }

    pub fn open_signer(&self, index: usize, pins: &FinalizedAuthorityConfig) -> OicResult<Signer> {
        let fixture = &self.fixture;
        let admins = fixture.executor.authority.admin_keys.clone();
        let signer = Signer::open(
            signer::identity(&signer::pid(index as u8 + 1)),
            TrustRoots {
                // D2 disables D1 entrypoints; this unused public field does
                // not require creating any D1 receipt signing key.
                authority_key_id: fixture.executor.authority.authority_key_id.clone(),
                authority_pubkey: admins[0].1,
                admin_keys: admins,
                admin_quorum: 2,
                approvers: vec![],
                accepted_verifier_builds: fixture
                    .executor
                    .adapters
                    .iter()
                    .map(|(id, adapter)| (id.clone(), vec![adapter.manifest().verifier_build_hash]))
                    .collect(),
                chain_profiles: vec![fixture.profile.clone()],
                // The signer pins the same records the replica's registry pins.
                enrolled_materials: EnrolledMaterials::from_records(
                    &fixture.executor.registry.assets,
                    &fixture.executor.registry.wallets,
                    &fixture.executor.registry.vaults,
                )
                .unwrap(),
                max_clock_skew_seconds: 30,
            },
            fixture.executor.adapters.clone(),
            Arc::new(provider(index)),
            Arc::new(InMemoryLedger::new()),
            Arc::new(InMemoryGenerationStore::new()),
        )?
        .with_finalized_authority(FinalizedAuthorityConfig {
            anchor: pins.anchor,
            minimum_floor: pins.minimum_floor,
            max_age_seconds: pins.max_age_seconds,
        })?;
        let sealed = &self.sealed.iter().find(|(id, _)| *id == signer::pid(index as u8 + 1)).unwrap().1;
        signer.load_key(&fixture.built.package.key, sealed)?;
        Ok(signer)
    }

    pub fn with_inputs(mutate: impl FnOnce(&mut oic_service_builder::BuildInputs)) -> Self {
        let providers: Vec<_> = (0..3).map(provider).collect();
        let dkg = run_dkg(
            &providers.iter().collect::<Vec<_>>(),
            &KeygenCeremony {
                key_id: KeyId::unchecked("ipc-d2-solana"),
                key_epoch: Epoch(1),
                institution_id: signer::inst(),
                environment_id: signer::env_id(),
                participants: (1..=3).map(signer::pid).collect(),
                threshold: 2,
                networks: vec![NetworkId::unchecked("solana-devnet")],
                recovery_profile: "test-dkg".into(),
            },
        )
        .unwrap();
        let fixture = Fixture::with_inputs(Chain::Solana, 1, |inputs| {
            inputs.key = dkg.descriptor.clone();
            inputs.wallet = signer::sol_wallet(&dkg.descriptor);
            mutate(inputs);
        });
        let mut committee = Committee::new();
        for index in 0..6 {
            let (node_id, roles, participant_keys) = match index {
                0..=2 => (
                    core_id(index),
                    vec![Role::Signer],
                    BTreeMap::from([(signer::pid(index as u8 + 1), public(80 + index as u8))]),
                ),
                3 => (NodeId::unchecked("gateway"), vec![Role::Gateway], BTreeMap::new()),
                4 => (NodeId::unchecked("other-gateway"), vec![Role::Gateway], BTreeMap::new()),
                _ => (NodeId::unchecked("witness"), vec![Role::Witness], BTreeMap::new()),
            };
            let domain_id = TrustDomainId::unchecked(format!("ipc-domain-{index}"));
            committee.roster.body.trust_domains.push(TrustDomain {
                domain_id: domain_id.clone(),
                administrators: vec![CredentialId::unchecked(format!("ipc-owner-{index}"))],
                failure_domain_notes: "Independent signer/gateway/witness operators".into(),
            });
            committee.roster.body.nodes.push(Node {
                node_id,
                domain_id,
                roles,
                transport_key: public(120 + index as u8),
                consensus_key: None,
                attestation_key: (index < 3).then(|| public(140 + index as u8)),
                address: format!("127.0.0.1:{}", 32000 + index).parse().unwrap(),
                peer_class: if index == 5 { PeerClass::Secondary } else { PeerClass::Primary },
                participant_keys,
                approved_build_hashes: if index < 3 {
                    vec![fixture.executor.adapters[&fixture.profile.adapter_id].manifest().verifier_build_hash]
                } else {
                    vec![]
                },
                signer_instance_generation: Epoch(if index < 3 { 1 } else { 0 }),
            });
        }
        committee.roster.body.committees.push(membership::Committee {
            committee_id: CommitteeId::unchecked("native-solana"),
            kind: CommitteeKind::Key {
                key_id: dkg.descriptor.key_id.clone(),
                key_epoch: dkg.descriptor.key_epoch,
                participants: dkg.descriptor.participants.clone(),
                backend: providers[0].capabilities(),
            },
            members: (0..3).map(core_id).collect(),
            threshold: 2,
        });
        committee.roster.body.channel_acl.extend([
            ChannelSpec {
                channel: 10,
                sender_roles: vec![Role::Gateway, Role::Signer],
                receiver_roles: vec![Role::Gateway, Role::Signer],
                max_message_size: 65536,
                quota: 100,
            },
            ChannelSpec {
                channel: 20,
                sender_roles: vec![Role::Signer],
                receiver_roles: vec![Role::Signer],
                max_message_size: 65536,
                quota: 100,
            },
        ]);
        committee.anchor = membership::roster_hash(&committee.roster.body).unwrap();
        committee.roster.signatures = common::admin_signatures(committee.anchor);
        committee.trust = FinalityTrust::from_genesis(
            committee.roster.clone(),
            &committee.admins,
            &signer::inst(),
            &signer::env_id(),
            committee.anchor,
            signer::now(),
        )
        .unwrap();
        let mut proof = fixture.proof();
        proof.envelope.participant_set.truncate(2);
        proof.request.envelope_body_hash = domain_hash(domains::AUTHORIZATION, &proof.envelope).unwrap();
        Self {
            fixture,
            committee,
            proof,
            sealed: dkg.sealed_shares,
        }
    }

    pub fn pins(&self) -> FinalizedAuthorityConfig {
        let genesis = self.fixture.genesis(&self.committee);
        FinalizedAuthorityConfig {
            anchor: LogAnchor {
                genesis: FinalizedFloor::at(&genesis).digest,
                roster: self.committee.anchor,
            },
            minimum_floor: FinalizedFloor::at(&genesis),
            max_age_seconds: MAX_AGE,
        }
    }

    pub async fn logs(&self, context: deterministic::Context) -> (VerifiedLog, VerifiedLog) {
        let genesis = self.fixture.genesis(&self.committee);
        let mut rng = TestRng::new(91);
        let mut follower = Follower::open(
            context,
            FollowerConfig {
                partition: "ipc-finalized".into(),
                executor: self.fixture.executor.clone(),
                trust: self.committee.trust.clone(),
                genesis: genesis.clone(),
                genesis_state: ReplicatedState::default(),
                minimum_floor: FinalizedFloor::at(&genesis),
                local_now: signer::now(),
            },
            &mut rng,
        )
        .await
        .unwrap();
        let mut commands = self.fixture.bootstrap();
        commands.extend(self.fixture.approvals());
        commands.push(Command::Reserve(Box::new(self.proof.clone())));
        let mut reserved = None;
        let body = &self.proof.envelope;
        let release = common::authority(AuthorityCommand::Release {
            request: ReleaseRequest {
                reservation_id: body.budget_reservation_id.clone(),
                reservation_version: body.reservation_version,
                envelope_body_hash: self.proof.request.envelope_body_hash,
                signer_session_id: body.signer_session_id.clone(),
                expected_policy_epoch: body.policy_epoch,
                freshness: FreshnessContext { now: signer::now() },
            },
        });
        for (view, commands) in [(1, commands), (2, vec![release])] {
            let (block, _) = self
                .fixture
                .executor
                .propose_block(
                    follower.tip(),
                    follower.state().clone(),
                    self.committee.context(follower.tip(), view),
                    &commands,
                    signer::now(),
                    signer::now(),
                )
                .unwrap();
            let certificate = self.committee.certify(&block);
            assert!(follower.apply_finalized(&mut rng, block, certificate, signer::now()).await.unwrap());
            if view == 1 {
                reserved = Some(follower.verified_log().unwrap());
            }
        }
        (reserved.unwrap(), follower.verified_log().unwrap())
    }
}

pub struct Harness {
    _dir: tempfile::TempDir,
    pub clients: Vec<ipc::Client>,
    pub audits: Vec<Arc<FileAuditLog>>,
    pub clock: Arc<ManualClock>,
    stop: Arc<AtomicBool>,
    tasks: Vec<std::thread::JoinHandle<()>>,
}

impl Harness {
    pub fn start(contract: &Contract, source: watch::Receiver<Option<VerifiedLog>>, pins: FinalizedAuthorityConfig) -> OicResult<Self> {
        Self::start_sources(contract, &[source.clone(), source], pins, None)
    }

    pub fn start_sources(
        contract: &Contract,
        sources: &[watch::Receiver<Option<VerifiedLog>>],
        pins: FinalizedAuthorityConfig,
        live_clock: Option<Arc<dyn oic_authorization_state::Clock>>,
    ) -> OicResult<Self> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut harness = Self {
            _dir: dir,
            clients: vec![],
            audits: vec![],
            clock: Arc::new(ManualClock::new(NOW)),
            stop: Arc::new(AtomicBool::new(false)),
            tasks: vec![],
        };
        let clock = live_clock.unwrap_or_else(|| harness.clock.clone());
        for (index, source) in sources[..2].iter().enumerate() {
            let signer = contract.open_signer(index, &pins)?;
            let audit = Arc::new(FileAuditLog::open(
                harness._dir.path().join(format!("audit-{index}")),
                Some(0),
                AuditLogConfig::new(
                    KeyId::unchecked(format!("audit-{index}")),
                    SigningKey::from_bytes(&[200 + index as u8; 32]),
                    clock.clone(),
                ),
            )?);
            let core = SignerCore::open(
                CoreConfig {
                    node_id: core_id(index),
                    roster: contract.committee.roster.clone(),
                    previous_roster: None,
                    admins: contract.committee.admins.clone(),
                    committed_roster_hash: contract.committee.anchor,
                    halt_state_path: harness._dir.path().join(format!("halt-{index}")),
                    minimum_halt_sequence: 0,
                    operator_key: SigningKey::from_bytes(&[220 + index as u8; 32]).verifying_key(),
                    audit: audit.clone(),
                },
                Arc::new(signer),
                SigningKey::from_bytes(&[80 + index as u8; 32]),
                clock.clone(),
            )?
            .with_finalized_log(source.clone())?;
            let path = harness._dir.path().join(format!("core-{index}.sock"));
            let server = ipc::Server::bind(&path, Arc::new(core))?;
            let stop = harness.stop.clone();
            harness.tasks.push(std::thread::spawn(move || server.serve(&stop).unwrap()));
            harness.clients.push(ipc::Client::new(path));
            harness.audits.push(audit);
        }
        Ok(harness)
    }

    pub fn remote(&self, index: usize, caller: &str) -> RemoteSigner {
        RemoteSigner::new(
            signer::pid(index as u8 + 1),
            Epoch(1),
            Arc::new(LocalClient {
                ipc: self.clients[index].clone(),
                gateway: NodeId::unchecked(caller),
            }),
            Duration::from_secs(1),
        )
    }

    pub fn prepare(&self, contract: &Contract) {
        let materials = oic_service_builder::signing_materials(&contract.fixture.built.package);
        for index in 0..2 {
            assert!(matches!(
                self.remote(index, "gateway")
                    .open_finalized(&contract.proof.envelope, &materials)
                    .unwrap(),
                ProtocolStep::Waiting
            ));
        }
        // Sweep commitments, then the signed packages they enable. Only the
        // named core recipient receives each participant-authenticated frame.
        for _ in 0..2 {
            let mut frames = vec![];
            for (index, client) in self.clients.iter().enumerate() {
                let mut offset = 0;
                while let Some(frame) = client.outbound_at(offset).unwrap() {
                    frames.push((core_id(index), frame));
                    offset += 1;
                }
            }
            for (from, frame) in frames {
                let index = (0..2).find(|i| core_id(*i) == frame.to).unwrap();
                self.clients[index].deliver(&from, frame.frame).unwrap();
            }
        }
        for index in 0..2 {
            self.remote(index, "gateway")
                .await_prepared(&contract.proof.envelope.signer_session_id)
                .unwrap();
        }
    }

    pub fn assert_no_release(&self) {
        for audit in &self.audits {
            assert!(!audit
                .events_since(0, 128)
                .unwrap()
                .iter()
                .any(|event| event.body.action == "signer.share_released"));
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for task in self.tasks.drain(..) {
            task.join().unwrap();
        }
    }
}
