//! Executed Simplex/marshal/follower composition, not a model or fabricated
//! certificate feed. Transport is Commonware's deterministic simulated network;
//! native signing and production socket admission are separate acceptance paths.
mod common;

use common::{Chain, Committee, Fixture, NOW};
use commonware_cryptography::{Signer as _, certificate::Scheme as _, ed25519::PublicKey};
use commonware_p2p::simulated;
use commonware_runtime::{Clock as _, Metrics as _, Quota, Runner as _, Supervisor as _, deterministic, telemetry::metrics::count_running_tasks};
use commonware_utils::{NZU32, NZUsize, probability};
use oic_replicated_authority::{
    Command, FinalizedFloor, Follower, FollowerConfig, ReplicatedState,
    runtime::{self, Networks, Running, RuntimeConfig},
};
use std::time::{Duration, UNIX_EPOCH};

type Oracle = simulated::Oracle<PublicKey, deterministic::Context>;
type Send = simulated::Sender<PublicKey, deterministic::Context>;
type Receive = simulated::Receiver<PublicKey>;

fn link() -> simulated::Link {
    simulated::Link { latency: Duration::from_millis(30), jitter: Duration::from_millis(5), success_rate: probability!(1.0) }
}

fn follower_config(
    context: &deterministic::Context,
    fixture: &Fixture,
    committee: &Committee,
    index: usize,
    floor: FinalizedFloor,
) -> FollowerConfig {
    FollowerConfig {
        partition: format!("replica-{index}"),
        executor: fixture.executor.clone(),
        trust: committee.trust.clone(),
        genesis: fixture.genesis(committee),
        genesis_state: ReplicatedState::default(),
        minimum_floor: floor,
        local_now: oic_domain_types::UnixSeconds(context.current().duration_since(UNIX_EPOCH).unwrap().as_secs()),
    }
}

async fn boot(
    context: &deterministic::Context,
    oracle: &Oracle,
    fixture: &Fixture,
    committee: &Committee,
    index: usize,
    floor: FinalizedFloor,
    voting: bool,
) -> Running {
    let (id, key) = &committee.keys[index];
    let control = oracle.control(key.public_key());
    let quota = Quota::per_second(NZU32!(1000));
    let channels: Networks<Send, Receive> = Networks {
        vote: control.register(1, quota).await.unwrap(),
        certificate: control.register(2, quota).await.unwrap(),
        consensus_resolver: control.register(3, quota).await.unwrap(),
        blocks: control.register(4, quota).await.unwrap(),
        backfill: control.register(5, quota).await.unwrap(),
    };
    runtime::start(
        context.child("replica").with_attribute("index", index),
        RuntimeConfig {
            follower: follower_config(context, fixture, committee, index, floor),
            node_id: id.clone(),
            public_key: key.public_key(),
            vote_key: voting.then(|| key.clone()),
            peers: oracle.manager(),
            blocker: control,
        },
        channels,
    )
    .await
    .unwrap()
}

async fn wait_for(context: &deterministic::Context, mut predicate: impl FnMut() -> bool) {
    for _ in 0..600 {
        if predicate() {
            return;
        }
        context.sleep(Duration::from_millis(50)).await;
    }
    panic!("replicated runtime did not reach expected public state in 30 simulated seconds\n{}", context.encode());
}

#[test]
fn four_real_engines_halt_below_quorum_then_finalize_release_and_recover() {
    let config = deterministic::Config::default()
        .with_seed(812)
        .with_start_time(UNIX_EPOCH + Duration::from_secs(NOW))
        .with_timeout(Some(Duration::from_secs(150)));
    deterministic::Runner::new(config).start(|context| async move {
        let fixture = Fixture::new(Chain::Evm, 2);
        let committee = Committee::new();
        let peers: Vec<_> = committee.keys.iter().map(|(_, key)| key.public_key()).collect();
        let (network, oracle) = simulated::Network::new_with_peers(
            context.child("network"),
            simulated::Config { max_size: 128 * 1024, max_peers_per_set: NZUsize!(4), disconnect_on_block: true, tracked_peer_sets: NZUsize!(1) },
            peers.clone(),
        )
        .await;
        network.start();
        for from in &peers {
            for to in &peers {
                if from != to {
                    oracle.add_link(from.clone(), to.clone(), link()).await.unwrap();
                }
            }
        }
        let genesis = fixture.genesis(&committee);
        let mut nodes = Vec::new();
        for index in 0..4 {
            let node = boot(&context, &oracle, &fixture, &committee, index, FinalizedFloor::at(&genesis), true).await;
            if index == 0 {
                assert!(node.verified_log.borrow().is_none(), "genesis is not finalized release evidence");
            }
            nodes.push(node);
        }
        // Round-robin starts view one at participant one in the sorted set,
        // not fixture vector order. Submit once to that actual first leader.
        let leader = committee.trust.verifier().participants().iter().nth(1).unwrap().clone();
        let leader = peers.iter().position(|key| key == &leader).unwrap();
        let mut commands = fixture.bootstrap();
        commands.extend(fixture.approvals());
        commands.push(Command::Reserve(Box::new(fixture.proof())));
        nodes[leader].proposer.as_ref().unwrap().submit(commands).unwrap();
        let rid = fixture.proof().envelope.budget_reservation_id;
        wait_for(&context, || nodes.iter().all(|node| node.progress.borrow().state.authority.reservations.contains_key(&rid))).await;
        assert!(nodes.iter().all(|node| node.progress.borrow().state.authority.issuance.is_empty()));
        for node in &nodes {
            assert_eq!(
                node.verified_log.borrow().as_ref().unwrap().authorize(&fixture.proof().envelope).unwrap_err().code,
                oic_domain_types::ErrorCode::SessionRejected
            );
        }
        println!("four engines reserved under genuine finality; no capability authorizes before Release");

        // Install two disjoint components before submitting release. A valid
        // local transition/proposal is not a finalization or issuance.
        for left in 0..2 {
            for right in 2..4 {
                oracle.remove_link(peers[left].clone(), peers[right].clone()).await.unwrap();
                oracle.remove_link(peers[right].clone(), peers[left].clone()).await.unwrap();
            }
        }
        context.sleep(Duration::from_secs(10)).await;
        let stopped: Vec<_> = nodes.iter().map(|node| node.progress.borrow().floor).collect();
        let mut release = fixture.release();
        let Command::Authority(command) = &mut release else { unreachable!() };
        let oic_authorization_state::AuthorityCommand::Release { request } = command.as_mut() else { unreachable!() };
        request.freshness.now = oic_domain_types::UnixSeconds(context.current().duration_since(UNIX_EPOCH).unwrap().as_secs());
        for node in &nodes {
            node.proposer.as_ref().unwrap().submit(vec![release.clone()]).unwrap();
        }
        context.sleep(Duration::from_secs(20)).await;
        for (node, floor) in nodes.iter().zip(&stopped) {
            assert_eq!(node.progress.borrow().floor, *floor, "two votes cannot finalize a new block");
            assert!(node.progress.borrow().state.authority.issuance.is_empty(), "no finalization means no issuance");
            assert_eq!(node.verified_log.borrow().as_ref().unwrap().floor(), *floor);
            assert!(node.verified_log.borrow().as_ref().unwrap().authorize(&fixture.proof().envelope).is_err());
        }
        println!("2+2 partition: 20 simulated seconds, no floor advance or release authorization");

        // Restore only a third replica. The fourth stays isolated while a
        // genuine 3-of-4 certificate drives each connected follower's release.
        oracle.remove_link(peers[2].clone(), peers[3].clone()).await.unwrap();
        oracle.remove_link(peers[3].clone(), peers[2].clone()).await.unwrap();
        for left in 0..2 {
            oracle.add_link(peers[left].clone(), peers[2].clone(), link()).await.unwrap();
            oracle.add_link(peers[2].clone(), peers[left].clone(), link()).await.unwrap();
        }
        wait_for(&context, || nodes[..3].iter().all(|node| node.progress.borrow().state.authority.issuance.len() == 1)).await;
        let expected = nodes[0].progress.borrow().state.hash().unwrap();
        assert!(nodes[..3].iter().all(|node| node.progress.borrow().state.hash().unwrap() == expected));
        assert!(nodes[3].progress.borrow().state.authority.issuance.is_empty());
        for node in &nodes[..3] {
            let log = node.verified_log.borrow();
            let log = log.as_ref().unwrap();
            assert_eq!(log.floor(), node.progress.borrow().floor);
            assert_eq!(log.anchor().genesis, FinalizedFloor::at(&genesis).digest);
            assert_eq!(log.anchor().roster, committee.anchor);
            assert_eq!(log.approvers().len(), 2);
            log.authorize(&fixture.proof().envelope).unwrap();
        }
        println!("healed 3-of-4 component: one issuance, matching state roots and verified capabilities");

        // Stop/reopen one real engine plus its application and storage from
        // its caller-retained independent floor. It must not reset issuance.
        let old = nodes.remove(2);
        let floor = old.progress.borrow().floor;
        let stale_proposer = old.proposer.clone().unwrap();
        old.shutdown().await.unwrap();
        let restarted = boot(&context, &oracle, &fixture, &committee, 2, floor, true).await;
        assert!(restarted.progress.borrow().floor.height >= floor.height);
        assert_eq!(restarted.progress.borrow().state.authority.issuance.len(), 1);
        assert_eq!(restarted.progress.borrow().state.hash().unwrap(), expected);
        restarted.verified_log.borrow().as_ref().unwrap().authorize(&fixture.proof().envelope).unwrap();

        // The formerly isolated fourth replica restarts with NO voting key.
        // Real certificate gossip and marshal backfill must reconstruct Release.
        let isolated = nodes.pop().unwrap();
        let isolated_floor = isolated.progress.borrow().floor;
        isolated.shutdown().await.unwrap();
        let observer = boot(&context, &oracle, &fixture, &committee, 3, isolated_floor, false).await;
        assert!(observer.proposer.is_none());
        assert!(observer.verified_log.borrow().as_ref().unwrap().authorize(&fixture.proof().envelope).is_err());
        for peer in &peers[..3] {
            oracle.add_link(peer.clone(), peers[3].clone(), link()).await.unwrap();
            oracle.add_link(peers[3].clone(), peer.clone(), link()).await.unwrap();
        }
        wait_for(&context, || observer.verified_log.borrow().as_ref().is_some_and(|log| log.authorize(&fixture.proof().envelope).is_ok())).await;
        assert_eq!(observer.progress.borrow().state.hash().unwrap(), expected);
        println!("keyless follower: real certificate gossip/backfill reconstructed the finalized Release");
        observer.shutdown().await.unwrap();
        restarted.shutdown().await.unwrap();
        for node in nodes {
            node.shutdown().await.unwrap();
        }
        wait_for(&context, || count_running_tasks(&context, "replica") == 0).await;
        assert_eq!(stale_proposer.submit(vec![fixture.freeze()]).unwrap_err().code, oic_domain_types::ErrorCode::AuthorityUnavailable);

        // Inspect only after every writer is stopped. This certificate came
        // from the actual engines and survived sync/replay, not fixture.certify.
        let mut rng = context.child("replay_rng");
        let recovered = Follower::open(context.child("replay"), follower_config(&context, &fixture, &committee, 2, floor), &mut rng).await.unwrap();
        let certificate = recovered.finalization().unwrap();
        committee.trust.verify(&mut rng, recovered.tip(), certificate).unwrap();
        assert_eq!(certificate.certificate.signers.count(), 3);
        assert_eq!(recovered.state().hash().unwrap(), expected);
        recovered.verified_log().unwrap().authorize(&fixture.proof().envelope).unwrap();
        println!("durable reopen: real 3-signature certificate verified, issuance retained, all runtime descendants stopped");
    });
}
