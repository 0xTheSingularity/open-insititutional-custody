//! D1 process bridge. This process has a transport key, never chain shares,
//! participant authentication keys or a generic signer operation. Run blocking
//! coordinator/client calls in `spawn_blocking`, not on this bridge's reactor.

use oic_canonical_encoding::from_canonical_bytes;
use oic_domain_types::*;
use oic_node::{Event, Transport};
use oic_peer_wire::{AuthorityReply, FrameKind, MAX_BODY_LEN, PeerFrameV1, SessionControl, SessionReply};
use oic_service_authority_rpc::AuthorityRpcTransport;
use oic_service_signer_core::{ipc, remote::ControlClient};
use std::{
    collections::BTreeMap,
    sync::{Arc, mpsc as sync},
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, MissedTickBehavior},
};

const MAX_PENDING: usize = 128;
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// The configured authority handler accepts authenticated node identities. It
/// must apply AuthorityRpcServer admission and existing authority transitions.
pub type AuthorityHandler = Arc<dyn Fn(&NodeId, &[u8]) -> OicResult<Vec<u8>> + Send + Sync>;

struct Command {
    to: NodeId,
    channel: u64,
    request_id: u64,
    frame: Vec<u8>,
    reply: sync::SyncSender<OicResult<Vec<u8>>>,
}

struct Pending {
    expires: Instant,
    reply: sync::SyncSender<OicResult<Vec<u8>>>,
}

fn unavailable() -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, "network RPC unavailable")
}

#[derive(Clone)]
pub struct Gateway {
    commands: mpsc::Sender<Command>,
    epoch: u64,
}

impl Gateway {
    fn request(&self, to: &NodeId, channel: u64, request_id: u64, frame: Vec<u8>) -> OicResult<Vec<u8>> {
        let (reply, receive) = sync::sync_channel(1);
        // Queue admission itself is bounded, so a stopped reactor cannot hold a
        // caller indefinitely before its timeout begins.
        self.commands.try_send(Command { to: to.clone(), channel, request_id, frame, reply }).map_err(|_| unavailable())?;
        receive.recv_timeout(RPC_TIMEOUT).map_err(|_| unavailable())?
    }

    pub fn signer(&self, node: NodeId) -> Arc<dyn ControlClient> {
        Arc::new(SignerClient { gateway: self.clone(), node })
    }
}

impl AuthorityRpcTransport for Gateway {
    fn request(&self, authority: &NodeId, request_id: u64, frame: Vec<u8>) -> OicResult<Vec<u8>> {
        self.request(authority, 12, request_id, frame)
    }
}

struct SignerClient {
    gateway: Gateway,
    node: NodeId,
}

impl ControlClient for SignerClient {
    fn request(&self, control: SessionControl) -> OicResult<SessionReply> {
        let id = request_id(&control);
        let frame = PeerFrameV1::encode_confidential(&control, self.gateway.epoch, FrameKind::Content, MAX_BODY_LEN).map_err(|_| unavailable())?;
        let bytes = self.gateway.request(&self.node, 10, id, frame)?;
        let frame = PeerFrameV1::decode(&bytes, self.gateway.epoch, FrameKind::Content, MAX_BODY_LEN).map_err(|_| unavailable())?;
        let reply: SessionReply = from_canonical_bytes(frame.body()).map_err(|_| unavailable())?;
        if reply.request_id != id {
            return Err(unavailable());
        }
        Ok(reply)
    }
}

fn request_id(control: &SessionControl) -> u64 {
    match control {
        SessionControl::Open { request_id, .. }
        | SessionControl::Release { request_id, .. }
        | SessionControl::Aggregate { request_id, .. }
        | SessionControl::Abort { request_id, .. }
        | SessionControl::Status { request_id, .. } => *request_id,
    }
}

pub struct Bridge {
    transport: Transport,
    epoch: u64,
    core: Option<ipc::Client>,
    authority: Option<AuthorityHandler>,
    commands: mpsc::Receiver<Command>,
    pending: BTreeMap<(NodeId, u64, u64), Pending>,
    outbound_offset: usize,
}

impl Bridge {
    /// `epoch` must be the active roster epoch used to start this transport.
    /// No core is needed on a gateway; no authority is needed on a signer.
    pub fn new(transport: Transport, epoch: u64, core: Option<ipc::Client>, authority: Option<AuthorityHandler>) -> (Self, Gateway) {
        let (send, commands) = mpsc::channel(MAX_PENDING);
        (Self { transport, epoch, core, authority, commands, pending: BTreeMap::new(), outbound_offset: 0 }, Gateway { commands: send, epoch })
    }

    pub async fn run(mut self, mut stop: oneshot::Receiver<()>) -> OicResult<()> {
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let result = loop {
            tokio::select! {
                _ = &mut stop => break Ok(()),
                Some(command) = self.commands.recv() => {
                    let key = (command.to.clone(), command.channel, command.request_id);
                    if self.pending.len() >= MAX_PENDING || self.pending.contains_key(&key) {
                        let _ = command.reply.send(Err(unavailable()));
                        continue;
                    }
                    match self.transport.send(&command.to, command.channel, command.frame).await {
                        Ok(()) => { self.pending.insert(key, Pending { expires: Instant::now() + RPC_TIMEOUT, reply: command.reply }); },
                        Err(error) => { let _ = command.reply.send(Err(error)); },
                    }
                }
                event = self.transport.recv() => {
                    let Some(event) = event else { break Err(unavailable()); };
                    self.incoming(event).await;
                }
                _ = tick.tick() => {
                    self.pending.retain(|_, request| {
                        if Instant::now() < request.expires { return true; }
                        let _ = request.reply.send(Err(unavailable()));
                        false
                    });
                    if let Some(core) = self.core.clone() {
                        let offset = self.outbound_offset;
                        let polled = tokio::task::spawn_blocking(move || {
                            let mut messages = Vec::new();
                            let mut next = offset;
                            for _ in 0..16 {
                                match core.outbound_at(next)? {
                                    Some(message) => { messages.push(message); next += 1; },
                                    None => { next = 0; break; },
                                }
                            }
                            Ok::<_, OicError>((messages, next))
                        }).await;
                        if let Ok(Ok((messages, next))) = polled {
                            self.outbound_offset = next;
                            for message in messages {
                                // Submission errors are retried by the next
                                // sweep, without constructing fresh MPC rounds.
                                let _ = self.transport.send(&message.to, 20, message.frame).await;
                            }
                        }
                    }
                }
            }
        };
        self.transport.shutdown().await?;
        result
    }

    async fn incoming(&mut self, event: Event) {
        match event.channel {
            20 => {
                if let Some(core) = self.core.clone() {
                    let _ = tokio::task::spawn_blocking(move || core.deliver(&event.from, event.bytes)).await;
                }
            }
            10 => {
                let Ok(frame) = PeerFrameV1::decode(&event.bytes, self.epoch, FrameKind::Content, MAX_BODY_LEN) else {
                    return;
                };
                if let Ok(reply) = from_canonical_bytes::<SessionReply>(frame.body()) {
                    if let Some(pending) = self.pending.remove(&(event.from, 10, reply.request_id)) {
                        let _ = pending.reply.send(Ok(event.bytes));
                    }
                    return;
                }
                let (Some(core), Ok(control)) = (self.core.clone(), from_canonical_bytes::<SessionControl>(frame.body())) else {
                    return;
                };
                let from = event.from.clone();
                if let Ok(Ok(reply)) = tokio::task::spawn_blocking(move || core.control(&from, control)).await
                    && let Ok(frame) = PeerFrameV1::encode_confidential(&reply, self.epoch, FrameKind::Content, MAX_BODY_LEN)
                {
                    let _ = self.transport.send(&event.from, 10, frame).await;
                }
            }
            12 => {
                if let Ok(reply) = AuthorityReply::decode(&event.bytes, self.epoch, MAX_BODY_LEN) {
                    if let Some(pending) = self.pending.remove(&(event.from, 12, reply.request_id)) {
                        let _ = pending.reply.send(Ok(event.bytes));
                    }
                    return;
                }
                if let Some(handler) = self.authority.clone() {
                    let from = event.from.clone();
                    if let Ok(Ok(frame)) = tokio::task::spawn_blocking(move || handler(&from, &event.bytes)).await {
                        let _ = self.transport.send(&event.from, 12, frame).await;
                    }
                }
            }
            _ => {}
        }
    }
}
