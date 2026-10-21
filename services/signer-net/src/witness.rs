//! Read-only network follower. A witness never receives an MPC or authority API.

use commonware_runtime::{BufferPooler, Metrics, Storage};
use oic_authorization_state::Clock;
use oic_domain_types::*;
use oic_membership::roster_hash;
use oic_node::Transport;
use oic_peer_wire::{FrameKind, HEADER_LEN, MAX_BODY_LEN, PeerFrameV1};
use oic_service_witness::{JournalFloor, WITNESS_CHANNEL, Witness};
use std::sync::Arc;
use tokio::sync::{oneshot, watch};

/// Synced progress only. The owner must retain the floor outside the witness's
/// rollback/failure domain; receiving this notification is not persistence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessProgress {
    pub floor: JournalFloor,
    pub quarantined: bool,
}

/// Follow authenticated Audit frames until stopped, then return the witness for
/// offline export/inspection. The watch channel carries the newest synced floor
/// and sticky quarantine, not confidential records. Malformed peer data is
/// discarded. Storage failure or a changed active roster stops the follower;
/// neither is retried against an ambiguously persisted journal.
///
/// `transport` must run on the production Commonware Tokio runtime. The witness
/// journal may use that same context or another supervised storage context.
pub async fn follow_witness<E: Storage + Metrics + BufferPooler>(
    mut transport: Transport,
    mut witness: Witness<E>,
    clock: Arc<dyn Clock>,
    mut stop: oneshot::Receiver<()>,
    progress: watch::Sender<WitnessProgress>,
) -> OicResult<Witness<E>> {
    let result = async {
        let epoch = transport.roster().body.roster_epoch;
        let transport_hash = roster_hash(&transport.roster().body)?;
        if transport.node_id() != witness.node_id() {
            return Err(OicError::scope("witness and transport identities differ"));
        }
        let max_body_len = transport
            .roster()
            .body
            .channel_acl
            .iter()
            .find(|acl| acl.channel == WITNESS_CHANNEL)
            .map(|acl| (acl.max_message_size as usize).saturating_sub(HEADER_LEN).min(MAX_BODY_LEN))
            .filter(|limit| *limit > 0)
            .ok_or_else(|| OicError::invalid_request("witness channel frame limit is absent or too small"))?;
        let active = witness.active_roster(clock.now())?;
        if roster_hash(&active.body)? != transport_hash {
            return Err(OicError::new(ErrorCode::RosterMismatch, "witness and transport roster views differ"));
        }
        progress.send_replace(WitnessProgress { floor: witness.floor(), quarantined: witness.quarantined() });
        loop {
            let event = tokio::select! {
                _ = &mut stop => break Ok(()),
                event = transport.recv() => event.ok_or_else(|| OicError::new(ErrorCode::AuthorityUnavailable, "witness transport stopped"))?,
            };
            let now = clock.now();
            if roster_hash(&witness.active_roster(now)?.body)? != transport_hash {
                return Err(OicError::new(ErrorCode::RosterMismatch, "witness roster changed; restart transport"));
            }
            if event.channel != WITNESS_CHANNEL {
                continue;
            }
            let Ok(frame) = PeerFrameV1::decode(&event.bytes, epoch, FrameKind::Audit, max_body_len) else {
                continue;
            };
            match witness.handle_authenticated(&event.from, event.channel, frame.body(), now).await {
                Ok(_) => {
                    progress.send_replace(WitnessProgress { floor: witness.floor(), quarantined: witness.quarantined() });
                }
                Err(error) if error.code == ErrorCode::AuthorityUnavailable => break Err(error),
                Err(_) => {}
            }
        }
    }
    .await;
    let shutdown = transport.shutdown().await;
    result?;
    shutdown?;
    Ok(witness)
}
