use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519;
use commonware_p2p::{Address, AddressableManager as _, AddressableTrackedPeers, Blocker as _, Receiver as _, Recipients, Sender as _, authenticated::lookup};
use commonware_runtime::{Handle, IoBuf, Quota, Spawner as _, Supervisor as _, tokio::Context};
use commonware_utils::ordered::Map;
use ed25519_dalek::SigningKey;
use oic_domain_types::*;
use oic_membership::{AdminTrust, PeerClass, SignedRoster, roster_hash, validate_roster};
use oic_peer_wire::{FrameKind, PaddingProfile, PeerFrameV1, RosterState};
use std::{collections::{BTreeMap, BTreeSet}, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};

/// Application bytes, excluding the private transport routing container.
pub const MAX_MESSAGE_SIZE: usize = oic_peer_wire::HEADER_LEN + oic_peer_wire::MAX_BODY_LEN;
/// A roster may lower these per-peer/per-channel messages-per-second limits.
pub const MAX_QUOTA: u32 = 100;
const QUEUE_SIZE: usize = 128;
/// Per-channel bound for inbound arrivals and for delivered events. Each
/// channel has its own queues (RFC 0003 §4.2, T12): a peer flooding one
/// channel fills only that channel's queues and cannot crowd out `Hello` or
/// `authority.rpc` replies on another channel.
const CHANNEL_QUEUE_SIZE: usize = 32;
const CONVERGENCE_TTL: Duration = Duration::from_secs(5);
// Unsigned container hints: version:u16, variant:u8, epoch:u64, roster_hash:32.
const PREFIX_LEN: usize = 43;
const HELLO: u8 = 0;
const DATA: u8 = 1;

/// Startup trust comes from local configuration, never a received peer record.
/// `previous`, when present, must be the caller's already-validated active roster
/// (the same contract as membership::validate_roster). `genesis_hash` is the
/// independently compared ceremony hash; `committed_roster_hash` is authority
/// authenticated. Transport configuration is immutable; roster changes restart
/// this transport after the caller validates and orders their activation.
pub struct Config {
    pub roster: SignedRoster,
    pub admins: AdminTrust,
    pub previous: Option<SignedRoster>,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub genesis_hash: Hash32,
    pub committed_roster_hash: Hash32,
    pub now: UnixSeconds,
    pub node_id: NodeId,
    pub transport_key: SigningKey,
}

/// Authenticated node identity; contents remain untrusted to signer-core.
pub struct Event {
    pub from: NodeId,
    pub channel: u64,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Event([REDACTED])")
    }
}

struct Policy {
    roster: SignedRoster,
    local: NodeId,
    hash: Hash32,
    peers: BTreeMap<NodeId, ed25519::PublicKey>,
    identities: BTreeMap<ed25519::PublicKey, NodeId>,
    sizes: BTreeMap<u64, usize>,
    padding: PaddingProfile,
}

impl Policy {
    fn check(&self, to: &NodeId, channel: u64, len: usize) -> OicResult<()> {
        if to == &self.local || !self.roster.allows(channel, &self.local, to) {
            return Err(OicError::new(ErrorCode::PeerNotAdmitted, "recipient or channel is not admitted"));
        }
        if len > self.sizes[&channel] {
            return Err(OicError::invalid_request("message exceeds channel size limit"));
        }
        Ok(())
    }

    fn packet(&self, variant: u8, bytes: &[u8]) -> IoBuf {
        let mut packet = Vec::with_capacity(PREFIX_LEN + bytes.len());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.push(variant);
        packet.extend_from_slice(&self.roster.body.roster_epoch.to_be_bytes());
        packet.extend_from_slice(self.hash.as_ref());
        packet.extend_from_slice(bytes);
        IoBuf::from(packet)
    }
}

fn padding_kind(channel: u64) -> Option<FrameKind> {
    match channel {
        10 => Some(FrameKind::Content),
        20 => Some(FrameKind::MpcSign),
        21 => Some(FrameKind::MpcCeremony),
        _ => None,
    }
}

enum Command {
    Send { to: NodeId, channel: u64, bytes: Vec<u8>, reply: oneshot::Sender<OicResult<()>> },
    Block { to: NodeId },
    Shutdown,
}

struct Incoming {
    from: ed25519::PublicKey,
    channel: u64,
    bytes: IoBuf,
}

/// Clone this handle to send while `Transport::recv` is pending elsewhere.
#[derive(Clone)]
pub struct SendHandle {
    commands: mpsc::Sender<Command>,
    policy: Arc<Policy>,
}

impl SendHandle {
    /// Queue a named peer block without waiting on the networking reactor.
    /// Commonware disconnects the authenticated transport key and applies its
    /// connection-block policy; the application router refuses it for the rest
    /// of this transport's lifetime. Queue refusal is an error, not a block.
    pub fn block(&self, to: &NodeId) -> OicResult<()> {
        if to == &self.policy.local || !self.policy.peers.contains_key(to) {
            return Err(OicError::new(ErrorCode::PeerNotAdmitted, "block target is not an admitted remote node"));
        }
        self.commands.try_send(Command::Block { to: to.clone() })
            .map_err(|_| OicError::new(ErrorCode::Conflict, "transport block queue unavailable"))
    }

    /// Named recipient only. RosterMismatch means convergence is absent/stale;
    /// Conflict means the channel quota or router queue refused submission.
    ///
    /// Broadcast recipient sets cannot enter this API, even on MPC channels.
    /// ```compile_fail,E0308
    /// use commonware_cryptography::ed25519::PublicKey;
    /// use commonware_p2p::Recipients;
    /// use oic_node::SendHandle;
    /// async fn broadcast(handle: &SendHandle) {
    ///     let everyone = Recipients::<PublicKey>::All;
    ///     handle.send(&everyone, 20, vec![1]).await.unwrap();
    /// }
    /// ```
    pub async fn send(&self, to: &NodeId, channel: u64, bytes: Vec<u8>) -> OicResult<()> {
        self.policy.check(to, channel, bytes.len())?;
        let bytes = match padding_kind(channel) {
            Some(kind) => self.policy.padding.encode_point_to_point(
                bytes, self.policy.roster.body.roster_epoch, kind, self.policy.sizes[&channel],
            ).map_err(|_| OicError::invalid_request("invalid padded frame or padded channel size limit exceeded"))?,
            None => bytes,
        };
        let (reply, receive) = oneshot::channel();
        self.commands.send(Command::Send { to: to.clone(), channel, bytes, reply }).await.map_err(|_| closed())?;
        receive.await.map_err(|_| closed())?
    }
}

pub struct Transport {
    sender: SendHandle,
    events: mpsc::Receiver<Event>,
    task: Option<Handle<()>>,
}

impl Transport {
    pub fn start(context: Context, config: Config) -> OicResult<Self> {
        Self::start_with_padding(context, config, PaddingProfile::Disabled)
    }

    /// Opt-in local profile for complete encoded frames on channels 10/20/21.
    /// Other channels, including native consensus 1–5, remain unchanged.
    /// Padded lengths must fit existing ACL/absolute caps; undersized ACLs fail
    /// sends, never grow implicitly. Receivers reject mixed profiles before
    /// event delivery. Restart both endpoints to enable or disable the profile.
    pub fn start_with_padding(context: Context, config: Config, padding: PaddingProfile) -> OicResult<Self> {
        Self::start_configured(context, config, padding, false)
    }

    /// Explicit single-machine development profile. Every signed roster address
    /// must be loopback. Only the peer reservation/retry cooldown becomes two
    /// seconds: authentication, IP checks, handshake/channel quotas, admission,
    /// convergence and padding are identical to the normal constructors.
    /// This does not qualify production startup or change its recommended limits.
    pub fn start_loopback(context: Context, config: Config, padding: PaddingProfile) -> OicResult<Self> {
        if config.roster.body.nodes.iter().any(|node| !node.address.ip().is_loopback()) {
            return Err(OicError::invalid_request("local retry profile requires an entirely loopback roster"));
        }
        Self::start_configured(context, config, padding, true)
    }

    fn start_configured(context: Context, config: Config, padding: PaddingProfile, loopback: bool) -> OicResult<Self> {
        validate_roster(
            &config.roster,
            &config.admins,
            &config.institution_id,
            &config.environment_id,
            config.previous.as_ref(),
            config.now,
            config.committed_roster_hash,
        )?;
        let hash = roster_hash(&config.roster.body)?;
        let anchor = if config.roster.body.roster_epoch == 0 { hash } else { config.roster.body.genesis_hash };
        if anchor != config.genesis_hash {
            return Err(OicError::scope("roster does not match the configured genesis anchor"));
        }
        let local = config.roster.node(&config.node_id).ok_or_else(|| OicError::new(ErrorCode::PeerNotAdmitted, "local node is not admitted"))?;
        if local.transport_key.bytes.as_ref() != config.transport_key.verifying_key().as_bytes() {
            return Err(OicError::invalid_signature("local transport key does not match the roster"));
        }
        if config.roster.body.nodes.len() > 64 || config.roster.body.channel_acl.len() > 64 {
            return Err(OicError::invalid_request("transport supports at most 64 nodes and 64 channels"));
        }
        let hello = PeerFrameV1::encode_public(
            &RosterState { roster_epoch: config.roster.body.roster_epoch, roster_hash: hash },
            config.roster.body.roster_epoch,
            FrameKind::Control,
            256,
        )
        .map_err(|_| OicError::invalid_request("invalid roster convergence record"))?;
        let sizes: BTreeMap<_, _> =
            config.roster.body.channel_acl.iter().map(|acl| (acl.channel, (acl.max_message_size as usize).min(MAX_MESSAGE_SIZE))).collect();
        if sizes.get(&0).is_none_or(|limit| *limit < hello.len()) {
            return Err(OicError::invalid_request("control ACL must allow the bounded convergence record"));
        }
        let mut primary = Vec::new();
        let mut secondary = Vec::new();
        let mut peers = BTreeMap::new();
        let mut identities = BTreeMap::new();
        for node in &config.roster.body.nodes {
            let key = ed25519::PublicKey::decode(node.transport_key.bytes.as_slice()).map_err(|_| OicError::invalid_request("invalid transport public key"))?;
            peers.insert(node.node_id.clone(), key.clone());
            identities.insert(key.clone(), node.node_id.clone());
            let entry = (key, Address::from(node.address));
            match node.peer_class {
                PeerClass::Primary => primary.push(entry),
                PeerClass::Secondary => secondary.push(entry),
            }
        }
        let crypto =
            ed25519::PrivateKey::decode(config.transport_key.as_bytes().as_slice()).map_err(|_| OicError::invalid_request("invalid transport private key"))?;
        let max_size = sizes.values().copied().max().unwrap() + PREFIX_LEN;
        let mut lookup =
            lookup::Config::recommended(crypto, &config.roster.namespace()?, local.address, NonZeroUsize::new(peers.len()).unwrap(), max_size as u32);
        if loopback {
            // When idle, Commonware's dialer wakes at the next jittered dial
            // time, clamped to [dial_frequency, cooldown] from now. A cooldown
            // equal to the dial interval collapses that range: nodes started
            // together then dial on one shared one-second grid, and two peers
            // that dial each other on the same tick reject each other's
            // handshake on every retry. Keep the range open.
            lookup.peer_connection_cooldown = lookup.dial_frequency * 2;
        }
        lookup.allow_private_ips = true;
        lookup.allow_dns = false; // Signed rosters currently contain SocketAddr only.
        lookup.bypass_ip_check = false;
        lookup.tracked_peer_sets = NonZeroUsize::new(2).unwrap();
        let primary: Map<_, _> = primary.try_into().map_err(|_| OicError::invalid_request("duplicate primary transport key"))?;
        let secondary: Map<_, _> = secondary.try_into().map_err(|_| OicError::invalid_request("duplicate secondary transport key"))?;
        let policy = Arc::new(Policy { roster: config.roster, local: config.node_id, hash, peers, identities, sizes, padding });
        let (commands, receive) = mpsc::channel(QUEUE_SIZE);
        let (events, event_receive) = mpsc::channel(QUEUE_SIZE);
        let actor_policy = policy.clone();
        let task = context.spawn(move |context| run(context, lookup, AddressableTrackedPeers::new(primary, secondary), actor_policy, hello, receive, events));
        Ok(Self { sender: SendHandle { commands, policy }, events: event_receive, task: Some(task) })
    }

    pub fn sender(&self) -> SendHandle {
        self.sender.clone()
    }

    /// The immutable, validated admission view actually used by this transport.
    pub fn roster(&self) -> &SignedRoster {
        &self.sender.policy.roster
    }

    pub fn node_id(&self) -> &NodeId {
        &self.sender.policy.local
    }

    /// Submission owns only the cloneable sender, not a shared borrow of the
    /// transport's non-Sync runtime supervisor. It can run in a spawned task.
    pub fn send(&self, to: &NodeId, channel: u64, bytes: Vec<u8>) -> impl std::future::Future<Output = OicResult<()>> + Send + 'static + use<> {
        let sender = self.sender();
        let to = to.clone();
        async move { sender.send(&to, channel, bytes).await }
    }

    pub async fn recv(&mut self) -> Option<Event> {
        self.events.recv().await
    }

    /// Stops only this transport's supervised subtree, not the caller's runtime.
    pub async fn shutdown(mut self) -> OicResult<()> {
        let _ = self.sender.commands.send(Command::Shutdown).await;
        if let Some(task) = self.task.take() {
            task.await.map_err(|_| closed())?;
        }
        Ok(())
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn closed() -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, "transport stopped")
}

/// Receive from the per-channel inbound queues round-robin, starting after the
/// channel served last, so no channel can monopolize the actor loop.
fn next_fair<'a>(queues: &'a mut [mpsc::Receiver<Incoming>], next: &'a mut usize) -> impl std::future::Future<Output = Option<Incoming>> + 'a {
    std::future::poll_fn(move |cx| {
        let n = queues.len();
        let mut closed = 0;
        for offset in 0..n {
            let index = (*next + offset) % n;
            match queues[index].poll_recv(cx) {
                std::task::Poll::Ready(Some(message)) => {
                    *next = (index + 1) % n;
                    return std::task::Poll::Ready(Some(message));
                }
                std::task::Poll::Ready(None) => closed += 1,
                std::task::Poll::Pending => {}
            }
        }
        if closed == n { std::task::Poll::Ready(None) } else { std::task::Poll::Pending }
    })
}

fn converged(peers: &BTreeMap<NodeId, Instant>, peer: &NodeId) -> bool {
    peers.get(peer).is_some_and(|seen| seen.elapsed() < CONVERGENCE_TTL)
}

async fn run(
    context: Context,
    config: lookup::Config<ed25519::PrivateKey>,
    peers: AddressableTrackedPeers<ed25519::PublicKey>,
    policy: Arc<Policy>,
    hello: Vec<u8>,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
) {
    let (mut network, mut oracle) = lookup::Network::new(context.child("lookup"), config);
    oracle.track(policy.roster.body.roster_epoch, peers);
    let mut inbound_queues = Vec::new();
    let mut channel_events = BTreeMap::new();
    let mut senders = BTreeMap::new();
    let mut workers = Vec::new();
    for acl in &policy.roster.body.channel_acl {
        let channel = acl.channel;
        let quota = Quota::per_second(std::num::NonZeroU32::new(acl.quota.min(MAX_QUOTA)).unwrap());
        let (sender, mut receiver) = network.register(channel, quota);
        senders.insert(channel, sender);
        let (incoming, queue) = mpsc::channel(CHANNEL_QUEUE_SIZE);
        inbound_queues.push(queue);
        workers.push(context.child("inbound").with_attribute("channel", channel).spawn(move |_| async move {
            while let Ok((from, bytes)) = receiver.recv().await {
                // A busy consumer drops this channel's arrivals only.
                let _ = incoming.try_send(Incoming { from, channel, bytes });
            }
        }));
        let (deliver, mut pending) = mpsc::channel::<Event>(CHANNEL_QUEUE_SIZE);
        channel_events.insert(channel, deliver);
        let events = events.clone();
        workers.push(context.child("events").with_attribute("channel", channel).spawn(move |_| async move {
            // Waiting senders get shared-queue space in arrival order, so a
            // flooding channel takes turns with the others instead of filling it.
            while let Some(event) = pending.recv().await {
                if events.send(event).await.is_err() {
                    break;
                }
            }
        }));
    }
    let mut next_queue = 0;
    let mut network_task = network.start();
    let mut network_finished = false;
    let mut views = BTreeMap::new();
    let mut blocked = BTreeSet::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = &mut network_task => { network_finished = true; break; },
            _ = events.closed() => break,
            _ = tick.tick() => {
                // Internal convergence is not application control: secondary
                // witnesses/extensions also need to prove the active roster.
                let hello = policy.packet(HELLO, &hello);
                for (id, key) in &policy.peers {
                    if id != &policy.local && !blocked.contains(id) {
                        let _ = senders.get_mut(&0).unwrap().send(Recipients::One(key.clone()), hello.clone(), true);
                    }
                }
            }
            command = commands.recv() => match command {
                Some(Command::Send { to, channel, bytes, reply }) => {
                    let result = if blocked.contains(&to) {
                        Err(OicError::new(ErrorCode::PeerNotAdmitted, "recipient is blocked"))
                    } else if channel != 0 && !converged(&views, &to) {
                        Err(OicError::new(ErrorCode::RosterMismatch, "recipient roster has not converged"))
                    } else {
                        let key = policy.peers[&to].clone();
                        let packet = policy.packet(DATA, &bytes);
                        if senders.get_mut(&channel).unwrap().send(Recipients::One(key), packet, false).is_empty() {
                            Err(OicError::new(ErrorCode::Conflict, "channel quota or queue refused submission"))
                        } else { Ok(()) }
                    };
                    let _ = reply.send(result);
                }
                Some(Command::Block { to }) => {
                    views.remove(&to);
                    blocked.insert(to.clone());
                    if !oracle.block(policy.peers[&to].clone()).accepted() { break; }
                }
                Some(Command::Shutdown) | None => break,
            },
            Some(inbound) = next_fair(&mut inbound_queues, &mut next_queue) => {
                let Some(from) = policy.identities.get(&inbound.from) else { continue };
                if blocked.contains(from) { continue; }
                let bytes = inbound.bytes.as_ref();
                let limit = policy.sizes[&inbound.channel];
                if bytes.len() < PREFIX_LEN || bytes.len() > PREFIX_LEN + limit || bytes[..2] != 1u16.to_be_bytes() { continue; }
                if bytes[3..11] != policy.roster.body.roster_epoch.to_be_bytes() || bytes[11..43] != policy.hash.0 {
                    views.remove(from);
                    continue;
                }
                let payload = &bytes[PREFIX_LEN..];
                match bytes[2] {
                    HELLO if inbound.channel == 0
                        // Exact canonical expected bytes: no arbitrary control
                        // body or additional allocation is accepted internally.
                        && payload == hello => { views.insert(from.clone(), Instant::now()); }
                    DATA if policy.roster.allows(inbound.channel, from, &policy.local)
                        && (inbound.channel == 0 || converged(&views, from)) => {
                        let payload = match padding_kind(inbound.channel) {
                            Some(kind) => {
                                let Ok(frame) = policy.padding.decode_point_to_point(
                                    payload, policy.roster.body.roster_epoch, kind, limit,
                                ) else { continue };
                                frame
                            }
                            None => payload,
                        };
                        if let Some(deliver) = channel_events.get(&inbound.channel) {
                            let _ = deliver.try_send(Event { from: from.clone(), channel: inbound.channel, bytes: payload.to_vec() });
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    for worker in &workers {
        worker.abort();
    }
    for worker in workers {
        let _ = worker.await;
    }
    if !network_finished {
        network_task.abort();
        let _ = network_task.await;
    }
}
