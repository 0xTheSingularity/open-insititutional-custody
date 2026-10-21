//! Production Commonware sockets -> Audit frame -> synced witness -> replay.
//! The fixture module registers no tests; witness contracts run only once.
#[path = "../../witness/tests/common/mod.rs"]
mod common;

use common::{checkpoint, key, node_id, sign_roster, trust};
use commonware_runtime::{Runner as _, Supervisor as _, tokio as runtime};
use oic_authorization_state::ManualClock;
use oic_domain_types::*;
use oic_membership::{ChannelSpec, PeerClass, Role, roster_hash};
use oic_node::{Config, Transport};
use oic_peer_wire::{FrameKind, HEADER_LEN, PeerFrameV1};
use oic_service_signer_net::witness::{WitnessProgress, follow_witness};
use oic_service_witness::{
    EvidenceKind, JournalFloor, WITNESS_CHANNEL, Witness, WitnessMessage, WitnessTrust,
};
use std::{collections::BTreeMap, net::TcpListener, sync::Arc, time::Duration};
use tokio::{
    sync::{oneshot, watch},
    time::{sleep, timeout},
};

const NOW: UnixSeconds = UnixSeconds(110);
const FRAME_CAP: usize = 65536 - HEADER_LEN;

fn socket_trust() -> WitnessTrust {
    let mut trust = trust();
    // Reserve simultaneously so the OS cannot assign the same port twice.
    let listeners: Vec<_> = (0..trust.rosters[0].body.nodes.len())
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let mut genesis = trust.rosters[0].body.clone();
    for (node, listener) in genesis.nodes.iter_mut().zip(&listeners) {
        node.address = listener.local_addr().unwrap();
    }
    let roles = vec![Role::Authority, Role::Gateway, Role::Verifier];
    genesis.channel_acl.push(ChannelSpec {
        channel: 0,
        sender_roles: roles.clone(),
        receiver_roles: roles,
        max_message_size: 4096,
        quota: 100,
    });
    let mut next = genesis.clone();
    let genesis_hash = roster_hash(&genesis).unwrap();
    next.roster_epoch = 1;
    next.genesis_hash = genesis_hash;
    next.previous_roster_hash = genesis_hash;
    next.activation = trust.rosters[1].body.activation.clone();
    trust.committed_roster_hashes =
        BTreeMap::from([(0, genesis_hash), (1, roster_hash(&next).unwrap())]);
    trust.rosters = vec![sign_roster(genesis), sign_roster(next)];
    trust.validate(NOW).unwrap();
    trust
}

fn config(trust: &WitnessTrust, index: u8) -> Config {
    Config {
        roster: trust.rosters[1].clone(),
        admins: trust.admins.clone(),
        previous: Some(trust.rosters[0].clone()),
        institution_id: trust.institution_id.clone(),
        environment_id: trust.environment_id.clone(),
        genesis_hash: trust.committed_roster_hashes[&0],
        committed_roster_hash: trust.committed_roster_hashes[&1],
        now: NOW,
        node_id: node_id(index),
        transport_key: key(10 + index),
    }
}

fn frame(sequence: u64, state: u8) -> Vec<u8> {
    PeerFrameV1::encode_public(
        &WitnessMessage::AuthorityCheckpoint(checkpoint(sequence, state)),
        1,
        FrameKind::Audit,
        FRAME_CAP,
    )
    .unwrap()
}

async fn floor_after(
    progress: &mut watch::Receiver<WitnessProgress>,
    records: u64,
) -> WitnessProgress {
    timeout(Duration::from_secs(10), async {
        loop {
            let value = *progress.borrow_and_update();
            assert!(
                value.floor.records <= records,
                "unexpected durable witness record"
            );
            if value.floor.records == records {
                return value;
            }
            progress.changed().await.expect("witness follower stopped");
        }
    })
    .await
    .expect("synced witness progress deadline")
}

#[test]
fn real_socket_witness_rejects_bad_frames_retains_equivocation_and_reopens_at_independent_floor() {
    let runtime_config = runtime::Config::default();
    let storage = runtime_config.storage_directory().to_owned();
    // Keep cleanup owned outside Runner so it happens after supervised I/O stops.
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(storage);
    runtime::Runner::new(runtime_config).start(|context| async move {
        let trust = socket_trust();
        let address = trust.rosters[1].node(&node_id(3)).unwrap().address;
        assert_eq!(
            trust.rosters[1].node(&node_id(3)).unwrap().peer_class,
            PeerClass::Secondary
        );
        let authority =
            Transport::start(context.child("authority_transport"), config(&trust, 0)).unwrap();
        let transport =
            Transport::start(context.child("witness_transport"), config(&trust, 3)).unwrap();
        let witness = Witness::open(
            context.child("journal"),
            "socket_witness".into(),
            trust.clone(),
            JournalFloor::EMPTY,
            NOW,
        )
        .await
        .unwrap();
        let (stop, stopped) = oneshot::channel();
        let (publish, mut progress) = watch::channel(WitnessProgress {
            floor: JournalFloor::EMPTY,
            quarantined: false,
        });
        let follower = tokio::spawn(follow_witness(
            transport,
            witness,
            Arc::new(ManualClock::new(NOW.0)),
            stopped,
            publish,
        ));

        // Checkpoint exchange is read-only. Retry ONLY this initial convergence
        // probe; never change production lookup handshake quotas/cooldowns.
        timeout(Duration::from_secs(300), async {
            loop {
                if progress.borrow().floor.records != 0 {
                    break;
                }
                match authority
                    .send(&node_id(3), WITNESS_CHANNEL, frame(4, 4))
                    .await
                {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.code,
                            ErrorCode::RosterMismatch | ErrorCode::Conflict
                        ) => {}
                    Err(error) => panic!("unexpected convergence rejection: {error}"),
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .expect("production socket convergence deadline");
        let initial = floor_after(&mut progress, 1).await;
        assert!(!initial.quarantined);
        assert_ne!(initial.floor.head_hash, Hash32::ZERO);

        // Each otherwise genuine checkpoint disagrees at the retained sequence.
        // Skipping any header check would create durable false equivocation.
        let mut malformed = frame(4, 91);
        let announced = u32::from_be_bytes(malformed[12..16].try_into().unwrap());
        malformed[12..16].copy_from_slice(&(announced + 1).to_be_bytes());
        let mut wrong_epoch = frame(4, 92);
        wrong_epoch[2..10].copy_from_slice(&0u64.to_be_bytes());
        let mut wrong_kind = frame(4, 93);
        wrong_kind[10..12].copy_from_slice(&(FrameKind::Control as u16).to_be_bytes());
        for bytes in [malformed, wrong_epoch, wrong_kind] {
            authority
                .send(&node_id(3), WITNESS_CHANNEL, bytes)
                .await
                .unwrap();
        }
        // Same authenticated connection/channel: the honest extension is the
        // processing barrier after the rejected frames, not a timing-only sleep.
        authority
            .send(&node_id(3), WITNESS_CHANNEL, frame(5, 5))
            .await
            .unwrap();
        let extended = floor_after(&mut progress, 2).await;
        assert!(
            !extended.quarantined,
            "invalid frames manufactured equivocation"
        );

        // A LATE conflict with cp4 must remain detectable after cp5 raised the
        // head. Testing only a conflict with the current head misses this case.
        authority
            .send(&node_id(3), WITNESS_CHANNEL, frame(4, 99))
            .await
            .unwrap();
        let retained = floor_after(&mut progress, 3).await;
        assert!(retained.quarantined);
        stop.send(()).unwrap();
        let witness = timeout(Duration::from_secs(10), follower)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(witness.floor(), retained.floor);
        assert_eq!(witness.authority_checkpoint(), Some(&checkpoint(5, 5)));
        assert_eq!(witness.records().len(), 3);
        assert!(
            witness
                .records()
                .iter()
                .all(|r| r.from == node_id(0) && r.roster_epoch == 1)
        );
        assert_eq!(witness.evidence().len(), 1);
        assert_eq!(
            witness.evidence()[0].kind,
            EvidenceKind::AuthorityEquivocation
        );
        assert_eq!(
            (
                witness.evidence()[0].first_record,
                witness.evidence()[0].second_record
            ),
            (1, 3)
        );
        let evidence = witness.evidence().to_vec();
        drop(witness);

        // The recovery anchor comes from the independently retained watch value,
        // never from the peer, export bundle, or reopened journal's own head.
        let reopened = Witness::open(
            context.child("reopen"),
            "socket_witness".into(),
            trust,
            retained.floor,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(reopened.floor(), retained.floor);
        assert!(reopened.quarantined());
        assert_eq!(reopened.evidence(), evidence);
        assert_eq!(reopened.authority_checkpoint(), Some(&checkpoint(5, 5)));
        drop(reopened);
        authority.shutdown().await.unwrap();
        // follow_witness owns shutdown; a clean stop must release its listener.
        let _released =
            TcpListener::bind(address).expect("witness listener leaked after clean stop");
    });
}
