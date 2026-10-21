//! Host-only, fixed-committee Simplex networks over the admitted production
//! transport. This module is not an extension capability. Channels 1–3 carry
//! public consensus traffic; full blocks/backfill on 4–5 remain confidential.
//! Native protocol actors validate their own codecs and certificates after the
//! fixed carrier, signed ACL, epoch, identity and size checks here.

use commonware_actor::{Feedback, Unreliable};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_p2p::{
    BlockedSubscription, Blocker, PeerSetSubscription, PeerSetUpdate, Provider, Receiver, Recipients, TrackedPeers, UnlimitedSender,
    utils::limited::{self, Connected},
};
use commonware_runtime::{Handle, IoBuf, IoBufs, Quota, Spawner as _, Supervisor as _, tokio::Context};
use commonware_utils::{NZUsize, channel::ring, ordered::Set};
use oic_domain_types::*;
use oic_membership::{CommitteeKind, PeerClass, Role, SignedRoster, roster_hash};
use oic_node::{Event, SendHandle, Transport};
use oic_peer_wire::{ConsensusFrame, HEADER_LEN, MAX_BODY_LEN};
use oic_replicated_authority::{
    FollowerConfig,
    runtime::{self, Networks, Running, RuntimeConfig},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::sync::{mpsc, oneshot};

const CAPACITY: usize = 128;
type Message = (PublicKey, IoBuf);

/// Owns one actual Transport and one durable, re-executing runtime. Unrelated
/// custody traffic has a separate bounded queue and never waits on a consensus
/// consumer. Overflow drops network traffic, never fabricates delivery/finality.
pub struct ConsensusHost {
    running: Running,
    sender: SendHandle,
    events: mpsc::Receiver<Event>,
    stop: oneshot::Sender<()>,
    router: Handle<OicResult<()>>,
}

impl ConsensusHost {
    /// Bind the real transport's node/roster to independently provisioned
    /// follower trust and a distinct enrolled D2 vote key.
    pub async fn start(context: Context, transport: Transport, follower: FollowerConfig, vote_key: PrivateKey) -> OicResult<Self> {
        Self::start_bound(context, transport, follower, Some(vote_key)).await
    }

    /// Independently admitted Signer, identified to marshal by its actual
    /// transport public key, not a committee vote key. It receives 2/4 and uses
    /// 5 for backfill; no vote engine, vote key, proposer or channels 1/3.
    /// The signed roster must explicitly grant the complete follower path.
    pub async fn start_follower(context: Context, transport: Transport, follower: FollowerConfig) -> OicResult<Self> {
        Self::start_bound(context, transport, follower, None).await
    }

    async fn start_bound(context: Context, transport: Transport, follower: FollowerConfig, vote_key: Option<PrivateKey>) -> OicResult<Self> {
        let binding = bind(&transport, &follower, vote_key.as_ref());
        let (peers, identities, local) = match binding {
            Ok(binding) => binding,
            Err(error) => {
                transport.shutdown().await?;
                return Err(error);
            }
        };
        let sender = transport.sender();
        let blocked = Blocks::new(sender.clone(), identities.clone());
        let roster = Arc::new(transport.roster().clone());
        let (events, incoming) = mpsc::channel(CAPACITY);
        let mut ingress = BTreeMap::new();
        let mut workers = Vec::new();
        let mut channel = |number| {
            let acl = roster.body.channel_acl.iter().find(|acl| acl.channel == number).expect("binding checked ACL");
            let limit = (acl.max_message_size as usize).min(oic_node::MAX_MESSAGE_SIZE) - HEADER_LEN;
            let (outgoing, mut receive) = mpsc::channel::<Submission>(CAPACITY);
            let output = sender.clone();
            let mapping = identities.clone();
            let blocklist = blocked.clone();
            let epoch = roster.body.roster_epoch;
            workers.push(context.child("consensus_egress").with_attribute("channel", number).spawn(move |_| async move {
                while let Some(submission) = receive.recv().await {
                    let Ok(frame) = ConsensusFrame::encode(submission.bytes.as_ref(), epoch, number, limit) else { continue };
                    for peer in submission.recipients {
                        if blocklist.contains(&peer) {
                            continue;
                        }
                        let Some(id) = mapping.get(&peer) else { continue };
                        // Each lane is independent. A stalled transport admission
                        // is lossy network delivery, never an unbounded waiter.
                        let _ = tokio::time::timeout(Duration::from_secs(1), output.send(id, number, frame.clone())).await;
                    }
                }
            }));
            let raw = Outbound {
                outgoing,
                identities: identities.clone(),
                blocked: blocked.clone(),
                limit,
                roster: roster.clone(),
                local: local.0.clone(),
                channel: number,
            };
            let quota = Quota::per_second(NonZeroU32::new(acl.quota.min(oic_node::MAX_QUOTA)).expect("validated positive quota"));
            let send = limited::LimitedSender::new(raw, quota, context.child("consensus_quota").with_attribute("channel", number), peers.clone());
            let (input, receive) = mpsc::channel(CAPACITY);
            ingress.insert(number, input);
            (ChannelSender { inner: send, followers: peers.keys.secondary.iter().cloned().collect(), fanout: number == 2 }, Inbound(receive))
        };
        let networks =
            Networks { vote: channel(1), certificate: channel(2), consensus_resolver: channel(3), blocks: channel(4), backfill: channel(5) };
        let (stop, stopping) = oneshot::channel();
        let incoming_blocks = blocked.clone();
        let router = context.child("consensus_router").spawn(move |_| route(transport, roster, incoming_blocks, ingress, events, workers, stopping));
        let config = RuntimeConfig { follower, node_id: local.0, public_key: local.1, vote_key, peers, blocker: blocked };
        let running = match runtime::start(context.child("replica"), config, networks).await {
            Ok(running) => running,
            Err(error) => {
                let _ = stop.send(());
                let _ = router.await;
                return Err(error);
            }
        };
        Ok(Self { running, sender, events: incoming, stop, router })
    }

    pub fn runtime(&self) -> &Running {
        &self.running
    }

    /// Host-only named sends for unrelated admitted custody channels. Never
    /// provide this handle to an extension or a consensus message consumer.
    pub fn sender(&self) -> SendHandle {
        self.sender.clone()
    }

    pub async fn recv(&mut self) -> Option<Event> {
        self.events.recv().await
    }

    /// Stop writers before closing sockets; all published capabilities already
    /// passed re-execution and durable sync. Keep the floor independently.
    pub async fn shutdown(self) -> OicResult<()> {
        let runtime = self.running.shutdown().await;
        let _ = self.stop.send(());
        let router = self.router.await.map_err(|_| unavailable("consensus transport router stopped"))?;
        runtime.and(router)
    }
}

type Binding = (Peers, Arc<BTreeMap<PublicKey, NodeId>>, (NodeId, PublicKey));

fn bind(transport: &Transport, follower: &FollowerConfig, vote_key: Option<&PrivateKey>) -> OicResult<Binding> {
    let roster = transport.roster();
    if roster_hash(&roster.body)? != follower.trust.roster_hash()? {
        return Err(OicError::scope("transport and finality trust rosters differ"));
    }
    let committees: Vec<_> = roster.body.committees.iter().filter(|c| matches!(c.kind, CommitteeKind::AuthorityD2 { .. })).collect();
    if committees.len() != 1 {
        return Err(OicError::new(ErrorCode::PeerNotAdmitted, "consensus host requires exactly one D2 committee"));
    }
    let committee = committees[0];
    if let Some(vote_key) = vote_key {
        if !committee.members.contains(transport.node_id()) {
            return Err(OicError::new(ErrorCode::PeerNotAdmitted, "consensus host requires an enrolled D2 replica"));
        }
        follower.trust.signer(transport.node_id(), vote_key.clone())?;
    } else {
        let local = roster.node(transport.node_id()).expect("transport admitted local node");
        if !local.roles.contains(&Role::Signer) || local.peer_class != PeerClass::Primary || committee.members.contains(transport.node_id()) {
            return Err(OicError::new(ErrorCode::PeerNotAdmitted, "keyless follower requires an independent primary Signer"));
        }
    }
    let mut identities = BTreeMap::new();
    for id in &committee.members {
        let node = roster.node(id).expect("validated committee member");
        let key = node.consensus_key.as_ref().ok_or_else(|| OicError::invalid_request("replica vote key absent"))?;
        let key = PublicKey::decode(key.bytes.as_slice()).map_err(|_| OicError::invalid_request("invalid replica vote key"))?;
        identities.insert(key, id.clone());
        for channel in 1..=5 {
            let acl =
                roster.body.channel_acl.iter().find(|acl| acl.channel == channel).ok_or_else(|| OicError::invalid_request("consensus ACL absent"))?;
            if acl.max_message_size as usize <= HEADER_LEN || committee.members.iter().any(|other| other != id && !roster.allows(channel, id, other))
            {
                return Err(OicError::new(ErrorCode::PeerNotAdmitted, "consensus channel is not mutually admitted"));
            }
        }
    }
    let primary = Set::from_iter_dedup(identities.keys().cloned());
    let mut secondary = Vec::new();
    for node in &roster.body.nodes {
        // Provider secondary is a marshal role, independent of transport
        // PeerClass. Shareholding Signers remain transport primaries.
        if node.roles.contains(&Role::Signer)
            && node.peer_class == PeerClass::Primary
            && committee
                .members
                .iter()
                .all(|id| [2, 4, 5].into_iter().all(|channel| roster.allows(channel, id, &node.node_id)) && roster.allows(5, &node.node_id, id))
        {
            let key = PublicKey::decode(node.transport_key.bytes.as_slice()).map_err(|_| OicError::invalid_request("invalid follower identity"))?;
            secondary.push(key.clone());
            identities.insert(key, node.node_id.clone());
        }
    }
    let key = identities
        .iter()
        .find(|(_, id)| *id == transport.node_id())
        .ok_or_else(|| OicError::new(ErrorCode::PeerNotAdmitted, "signed ACL does not grant the complete follower path"))?
        .0
        .clone();
    let peers = Peers {
        epoch: roster.body.roster_epoch,
        keys: TrackedPeers::new(primary, Set::from_iter_dedup(secondary)),
        subscriptions: Arc::new(Mutex::new(Vec::new())),
        connected: Arc::new(Mutex::new(Vec::new())),
    };
    Ok((peers, Arc::new(identities), (transport.node_id().clone(), key)))
}

async fn route(
    mut transport: Transport,
    roster: Arc<SignedRoster>,
    blocked: Blocks,
    ingress: BTreeMap<u64, mpsc::Sender<Message>>,
    events: mpsc::Sender<Event>,
    workers: Vec<Handle<()>>,
    mut stopping: oneshot::Receiver<()>,
) -> OicResult<()> {
    let reverse: BTreeMap<_, _> = blocked.identities.iter().map(|(key, id)| (id.clone(), key.clone())).collect();
    let result = loop {
        tokio::select! {
            _ = &mut stopping => break Ok(()),
            event = transport.recv() => {
                let Some(event) = event else { break Err(unavailable("admitted transport closed")) };
                if let Some(input) = ingress.get(&event.channel) {
                    let Some(key) = reverse.get(&event.from) else { continue };
                    if blocked.contains(key) || !roster.allows(event.channel, &event.from, transport.node_id()) { continue; }
                    let acl = roster.body.channel_acl.iter().find(|a| a.channel == event.channel).expect("binding checked ACL");
                    let limit = (acl.max_message_size as usize).min(oic_node::MAX_MESSAGE_SIZE) - HEADER_LEN;
                    let Ok(frame) = ConsensusFrame::decode(&event.bytes, roster.body.roster_epoch, event.channel, limit) else { continue };
                    let _ = input.try_send((key.clone(), IoBuf::from(frame.payload().to_vec())));
                } else {
                    let _ = events.try_send(event);
                }
            }
        }
    };
    for worker in &workers {
        worker.abort();
    }
    for worker in workers {
        let _ = worker.await;
    }
    let stopped = transport.shutdown().await;
    result.and(stopped)
}

#[derive(Clone, Debug)]
struct Peers {
    epoch: u64,
    keys: TrackedPeers<PublicKey>,
    subscriptions: Arc<Mutex<Vec<mpsc::UnboundedSender<PeerSetUpdate<PublicKey>>>>>,
    connected: Arc<Mutex<Vec<ring::Sender<Vec<PublicKey>>>>>,
}

impl Provider for Peers {
    type PublicKey = PublicKey;
    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<PublicKey>> {
        (id == self.epoch).then(|| self.keys.clone())
    }
    async fn subscribe(&mut self) -> PeerSetSubscription<PublicKey> {
        let (send, receive) = mpsc::unbounded_channel();
        let peers = self.keys.clone();
        let _ = send.send(PeerSetUpdate { index: self.epoch, latest: peers.clone(), all: peers });
        let mut subscriptions = self.subscriptions.lock().expect("peer subscriptions");
        subscriptions.retain(|s| !s.is_closed());
        subscriptions.push(send);
        receive
    }
}

impl Connected for Peers {
    type PublicKey = PublicKey;
    fn peers(&self) -> Vec<PublicKey> {
        self.keys.clone().union().into_iter().collect()
    }
    fn subscribe(&self) -> ring::Receiver<Vec<PublicKey>> {
        let (send, receive) = ring::channel(NZUsize!(1));
        send.send_lossy(self.peers());
        let mut subscriptions = self.connected.lock().expect("connected subscriptions");
        subscriptions.retain(|s| !s.is_closed());
        subscriptions.push(send);
        receive
    }
}

#[derive(Clone)]
struct Blocks {
    sender: SendHandle,
    identities: Arc<BTreeMap<PublicKey, NodeId>>,
    state: Arc<Mutex<BlockState>>,
}
#[derive(Default)]
struct BlockState {
    keys: BTreeSet<PublicKey>,
    subscriptions: Vec<ring::Sender<Set<PublicKey>>>,
}
impl Blocks {
    fn new(sender: SendHandle, identities: Arc<BTreeMap<PublicKey, NodeId>>) -> Self {
        Self { sender, identities, state: Arc::new(Mutex::new(BlockState::default())) }
    }
    fn contains(&self, peer: &PublicKey) -> bool {
        self.state.lock().expect("blocklist").keys.contains(peer)
    }
}
impl Blocker for Blocks {
    type PublicKey = PublicKey;
    fn block(&mut self, peer: PublicKey) -> Feedback {
        let Some(id) = self.identities.get(&peer) else { return Feedback::Closed };
        if self.sender.block(id).is_err() {
            return Feedback::Closed;
        }
        let mut state = self.state.lock().expect("blocklist");
        state.keys.insert(peer);
        let keys = Set::from_iter_dedup(state.keys.iter().cloned());
        state.subscriptions.retain(|s| s.send_lossy(keys.clone()));
        Feedback::Ok
    }
    fn blocked(&mut self) -> BlockedSubscription<PublicKey> {
        let (send, receive) = ring::channel(NZUsize!(1));
        let mut state = self.state.lock().expect("blocklist");
        send.send_lossy(Set::from_iter_dedup(state.keys.iter().cloned()));
        state.subscriptions.push(send);
        receive
    }
}

#[derive(Clone)]
struct ChannelSender {
    inner: limited::LimitedSender<Context, Outbound, Peers>,
    followers: Vec<PublicKey>,
    fanout: bool,
}

impl commonware_p2p::LimitedSender for ChannelSender {
    type PublicKey = PublicKey;
    type Checked<'a> = limited::CheckedSender<'a, Outbound>;
    fn check(&mut self, mut recipients: Recipients<PublicKey>) -> Result<Self::Checked<'_>, SystemTime> {
        if self.fanout && !matches!(recipients, Recipients::All) {
            let mut targets = match recipients {
                Recipients::Some(peers) => peers,
                Recipients::One(peer) => vec![peer],
                Recipients::All => unreachable!(),
            };
            // Simplex targets committee recipients. Explicitly deliver its
            // native certificate traffic to admitted keyless consumers too;
            // only independently verified Finalization advances their log.
            targets.extend(self.followers.iter().cloned());
            recipients = Recipients::Some(Set::from_iter_dedup(targets).into_iter().collect());
        }
        self.inner.check(recipients)
    }
}

struct Submission {
    recipients: Vec<PublicKey>,
    bytes: IoBuf,
}

#[derive(Clone)]
struct Outbound {
    outgoing: mpsc::Sender<Submission>,
    identities: Arc<BTreeMap<PublicKey, NodeId>>,
    blocked: Blocks,
    limit: usize,
    roster: Arc<SignedRoster>,
    local: NodeId,
    channel: u64,
}
impl UnlimitedSender for Outbound {
    type PublicKey = PublicKey;
    fn send(&mut self, recipients: Recipients<PublicKey>, message: impl Into<IoBufs> + Send, _priority: bool) -> Unreliable<Feedback> {
        let bytes = message.into().coalesce();
        if bytes.len() > self.limit.min(MAX_BODY_LEN) {
            return Unreliable::rejected();
        }
        let peers = match recipients {
            Recipients::All => self.identities.keys().cloned().collect(),
            Recipients::Some(peers) => peers,
            Recipients::One(peer) => vec![peer],
        };
        let recipients = peers
            .into_iter()
            .filter(|p| {
                !self.blocked.contains(p)
                    && self.identities.get(p).is_some_and(|id| id != &self.local && self.roster.allows(self.channel, &self.local, id))
            })
            .collect();
        match self.outgoing.try_send(Submission { recipients, bytes }) {
            Ok(()) => Unreliable::new(Feedback::Ok),
            Err(mpsc::error::TrySendError::Closed(_)) => Unreliable::new(Feedback::Closed),
            Err(mpsc::error::TrySendError::Full(_)) => Unreliable::rejected(),
        }
    }
}

struct Inbound(mpsc::Receiver<Message>);
impl std::fmt::Debug for Inbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConsensusInbound([REDACTED])")
    }
}
impl Receiver for Inbound {
    type PublicKey = PublicKey;
    type Error = OicError;
    async fn recv(&mut self) -> OicResult<Message> {
        self.0.recv().await.ok_or_else(|| unavailable("consensus input closed"))
    }
}

fn unavailable(detail: &str) -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, detail)
}
