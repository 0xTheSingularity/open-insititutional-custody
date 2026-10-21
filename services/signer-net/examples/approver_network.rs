//! Local-only live Simplex/browser harness. Test keys and virtual UV, never funds.
//! No manually minted certificates: all published history comes from real hosts.
#[path = "../../../apps/approver-client/tests/common/mod.rs"]
mod common;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{
    ORIGIN, RAW_ID, credential, credential_id,
    d2::{self, Committee, Fixture, signer},
    key,
};
use commonware_codec::Encode;
use commonware_runtime::{Runner as _, Supervisor as _, tokio as runtime};
use ed25519_dalek::SigningKey;
use oic_approver_client::{Floor, Provision};
use oic_authorization_state::{AuthorityCommand, CredentialChange, SystemClock};
use oic_canonical_encoding::sha256;
use oic_domain_types::*;
use oic_membership::roster_hash;
use oic_node::{Config, PaddingProfile, Transport};
use oic_peer_wire::{FrameKind, PeerFrameV1, RosterState};
use oic_replicated_authority::{FinalityTrust, FinalizedFloor, Follower, FollowerConfig, ReplicatedState};
use oic_service_signer_net::{
    consensus::ConsensusHost,
    http::{NodeApi, NodeCredential},
};
use rand::{RngCore as _, rngs::OsRng};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, sleep, timeout};

fn now() -> UnixSeconds {
    UnixSeconds(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
}
fn write(dir: &Path, name: &str, value: &impl serde::Serialize) {
    let tmp = dir.join(format!("{name}.tmp"));
    fs::write(&tmp, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    fs::rename(tmp, dir.join(name)).unwrap();
}
fn follower(fixture: &Fixture, committee: &Committee, index: usize) -> FollowerConfig {
    let genesis = fixture.genesis(committee);
    FollowerConfig {
        partition: format!("browser-live-{index}"),
        executor: fixture.executor.clone(),
        trust: committee.trust.clone(),
        minimum_floor: FinalizedFloor::at(&genesis),
        genesis,
        genesis_state: ReplicatedState::default(),
        local_now: now(),
    }
}
async fn ready(hosts: &mut [ConsensusHost], committee: &Committee) {
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut seen = BTreeSet::new();
    let frame = PeerFrameV1::encode_public(&RosterState { roster_epoch: 0, roster_hash: committee.anchor }, 0, FrameKind::Control, 1024).unwrap();
    while seen.len() != 12 {
        assert!(Instant::now() < deadline, "TCP admission deadline: {seen:?}");
        for (from, host) in hosts.iter().enumerate() {
            for (to, node) in committee.roster.body.nodes.iter().enumerate() {
                if from != to {
                    let _ = host.sender().send(&node.node_id, 0, frame.clone()).await;
                }
            }
        }
        for (to, host) in hosts.iter_mut().enumerate() {
            while let Ok(Some(event)) = timeout(Duration::from_millis(5), host.recv()).await {
                if event.channel == 0 && event.bytes == frame {
                    seen.insert((event.from, to));
                }
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn run(context: runtime::Context, dir: PathBuf, chain: d2::Chain) {
    let clock = now();
    let fixture = Fixture::with_inputs(chain, 0, |inputs| {
        inputs.intent.created_at = UnixSeconds(clock.0 - 100);
        inputs.built_at = clock;
        inputs.evidence.observed_at = clock;
        inputs.evidence.max_staleness_seconds = 900;
        inputs.profile.max_evidence_age_seconds = 900;
        inputs.policy.max_evidence_age_seconds = 900;
    });
    let mut committee = Committee::new();
    let listeners: Vec<_> = (0..4).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    for (node, listener) in committee.roster.body.nodes.iter_mut().zip(&listeners) {
        node.address = listener.local_addr().unwrap();
        assert_ne!(node.transport_key, *node.consensus_key.as_ref().unwrap());
    }
    committee.anchor = roster_hash(&committee.roster.body).unwrap();
    committee.roster.signatures = d2::admin_signatures(committee.anchor);
    committee.trust =
        FinalityTrust::from_genesis(committee.roster.clone(), &committee.admins, &signer::inst(), &signer::env_id(), committee.anchor, now())
            .unwrap();
    drop(listeners);
    let genesis = fixture.genesis(&committee);
    let authority = &fixture.executor.authority;
    let provision = Provision {
        institution_id: authority.institution_id.clone(),
        environment_id: authority.environment_id.clone(),
        authority_key_id: authority.authority_key_id.clone(),
        admin_keys: authority.admin_keys.clone(),
        admin_quorum: authority.admin_quorum,
        freeze_responders: authority.freeze_responders.clone(),
        release_receipt_ttl_seconds: authority.release_receipt_ttl_seconds,
        max_clock_skew_seconds: authority.max_clock_skew_seconds,
        registry: fixture.executor.registry.clone(),
        adapter_builds: fixture.executor.adapters.iter().map(|(id, adapter)| (id.clone(), adapter.manifest().verifier_build_hash)).collect(),
        roster: committee.roster.clone(),
        roster_genesis: committee.anchor,
        genesis: genesis.encode().to_vec().into(),
        genesis_hash: Floor::at(&genesis).digest,
        minimum_floor: Floor::at(&genesis),
        origin: ORIGIN.into(),
        rp_id: "localhost".into(),
        max_view_age_seconds: 120,
        grant_ttl_seconds: 300,
        development: true,
        credential_ids: BTreeMap::from([(credential_id(), RAW_ID.to_vec().into())]),
    };
    write(&dir, "provision.json", &provision);
    write(&dir, "package.json", &fixture.built.package);
    let point = key().verifying_key().to_encoded_point(false);
    write(
        &dir,
        "virtual-credential.json",
        &serde_json::json!({
            "rawId": RAW_ID.iter().map(|b| format!("{b:02x}")).collect::<String>(), "identity":credential_id(),
            "jwk":{"kty":"EC","crv":"P-256","d":URL_SAFE_NO_PAD.encode([42;32]),"x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())}
        }),
    );
    let mut hosts = Vec::new();
    for index in 0..4 {
        let transport = Transport::start_loopback(
            context.child("transport").with_attribute("index", index),
            Config {
                roster: committee.roster.clone(),
                admins: committee.admins.clone(),
                previous: None,
                institution_id: signer::inst(),
                environment_id: signer::env_id(),
                genesis_hash: committee.anchor,
                committed_roster_hash: committee.anchor,
                now: now(),
                node_id: committee.keys[index].0.clone(),
                transport_key: SigningKey::from_bytes(&[110 + index as u8; 32]),
            },
            PaddingProfile::Disabled,
        )
        .unwrap();
        hosts.push(
            ConsensusHost::start(
                context.child("consensus").with_attribute("index", index),
                transport,
                follower(&fixture, &committee, index),
                committee.keys[index].1.clone(),
            )
            .await
            .unwrap(),
        );
    }
    ready(&mut hosts, &committee).await;
    let proposal = CredentialChange {
        institution_id: authority.institution_id.clone(),
        environment_id: authority.environment_id.clone(),
        credential_id: credential_id(),
        previous_change: 0,
        credential: Some(credential()),
    };
    let mut commands = fixture.bootstrap();
    commands.push(d2::authority(AuthorityCommand::ChangeCredential { signatures: d2::admin_signatures(proposal.hash().unwrap()), proposal }));
    hosts[0].runtime().proposer.as_ref().unwrap().submit(commands).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !hosts.iter().all(|host| {
        host.runtime().progress.borrow().state.authority.ordered_approvals.as_ref().is_some_and(|s| s.credentials.contains_key(&credential_id()))
    }) {
        assert!(Instant::now() < deadline, "bootstrap did not finalize");
        sleep(Duration::from_millis(100)).await;
    }
    let mut random = [0; 32];
    OsRng.fill_bytes(&mut random);
    let token = URL_SAFE_NO_PAD.encode(random);
    let mut servers = Vec::new();
    let mut endpoints = Vec::new();
    for host in &hosts[..2] {
        let api = NodeApi::new(
            host.runtime(),
            fixture.executor.clone(),
            vec![NodeCredential { token_hash: sha256(token.as_bytes()), approver: Some(credential_id()) }],
            ORIGIN.into(),
            Arc::new(SystemClock),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        endpoints.push(format!("http://{}", listener.local_addr().unwrap()));
        servers.push(tokio::spawn(async move {
            axum::serve(listener, api.router()).await.unwrap();
        }));
    }
    write(&dir, "endpoints.json", &serde_json::json!({"nodes":endpoints,"token":token,"genesis":Floor::at(&genesis),"realSimplex":true}));
    println!("Live HTTP ready: {}", dir.display());
    let deadline = Instant::now() + Duration::from_secs(900);
    let mut observed = false;
    while !dir.join("stop").exists() {
        assert!(Instant::now() < deadline, "live browser harness deadline");
        if !observed
            && hosts.iter().all(|host| {
                host.runtime().progress.borrow().state.authority.ordered_approvals.as_ref().is_some_and(|s| s.grants.values().any(|g| !g.is_empty()))
            })
        {
            let replicas: Vec<_> = hosts.iter().map(|host| {
                let snapshot = host.runtime().progress.borrow();
                serde_json::json!({"floor":{"height":snapshot.floor.height,"digest":snapshot.floor.digest},"state_hash":snapshot.state.hash().unwrap(),"grants":snapshot.state.authority.ordered_approvals.as_ref().unwrap().grants})
            }).collect();
            write(&dir, "approval-observed.json", &serde_json::json!({"replicas":replicas,"realSimplex":true,"durablySynced":true}));
            observed = true;
        }
        sleep(Duration::from_millis(100)).await;
    }
    for server in servers {
        server.abort();
    }
    let retained_floors: Vec<_> = hosts.iter().map(|host| host.runtime().progress.borrow().floor).collect();
    let expected_state = hosts[0].runtime().progress.borrow().state.hash().unwrap();
    let command: oic_replicated_authority::Command = serde_json::from_slice(&fs::read(dir.join("command.json")).unwrap()).unwrap();
    let oic_replicated_authority::Command::Authority(inner) = command else { panic!("expected browser approval") };
    let AuthorityCommand::Approve { intent, grant } = *inner else { panic!("expected browser approval") };
    for host in hosts {
        host.shutdown().await.unwrap();
    }
    let mut replayed = Vec::new();
    let mut rng = context.child("certificate_replay");
    for (index, retained) in retained_floors[..2].iter().copied().enumerate() {
        let mut config = follower(&fixture, &committee, index);
        config.minimum_floor = retained;
        let follower = Follower::open(context.child("reopen").with_attribute("index", index), config, &mut rng).await.unwrap();
        let grants = &follower.state().authority.ordered_approvals.as_ref().unwrap().grants;
        assert_eq!(grants[&intent.intent_id][&credential_id()].grant, grant, "disk replay lost exact browser approval");
        assert_eq!(follower.state().hash().unwrap(), expected_state);
        let floor = follower.floor();
        assert!(floor.height >= retained.height);
        let certificate = follower.finalization().unwrap();
        committee.trust.verify(&mut rng, follower.tip(), certificate).unwrap();
        assert_eq!(certificate.certificate.signers.count(), 3);
        replayed.push(serde_json::json!({"retained_floor":{"height":retained.height,"digest":retained.digest},"floor":{"height":floor.height,"digest":floor.digest},"state_hash":follower.state().hash().unwrap(),"grants":grants,"certificate_signers":certificate.certificate.signers.count()}));
    }
    write(&dir, "journal-replay.json", &serde_json::json!({"replicas":replayed,"reopenedActualJournals":true}));
}
fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("approver_network OUTPUT_DIR [evm|solana]"));
    let chain = if args.next().as_deref() == Some("solana") { d2::Chain::Solana } else { d2::Chain::Evm };
    fs::create_dir_all(&dir).unwrap();
    assert!(!dir.join("journal").exists(), "use a fresh run directory");
    runtime::Runner::new(runtime::Config::new().with_storage_directory(dir.join("journal"))).start(|context| run(context, dir, chain));
}
