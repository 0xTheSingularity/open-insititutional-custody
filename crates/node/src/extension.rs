//! Restricted, public-only RFC 0003 extension embedding.
//!
//! The trusted host constructs this router from the real admitted transport,
//! dispatches its authenticated events, and publishes already-verified ordered
//! receipts. Extensions cannot register additional channels through a context.
//! This is an API capability boundary, not a sandbox for arbitrary native code.
//! Run untrusted native code in a separate process; Tokio tasks do not isolate
//! CPU, memory, filesystem access, or capabilities captured outside the context.

use crate::{Event, MAX_MESSAGE_SIZE, MAX_QUOTA, SendHandle, Transport};
use oic_canonical_encoding::from_canonical_bytes;
use oic_domain_types::{AuthorityReceipt, ErrorCode, NodeId, OicError, OicResult, ReceiptKind};
use oic_membership::{ChannelSpec, Role, SignedRoster};
use oic_peer_wire::{FrameKind, HEADER_LEN, PeerFrameV1, WitnessMessage};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};

pub const EXTENSION_MAILBOX_CAPACITY: usize = 128;
pub type ExtensionHandle = tokio::task::JoinHandle<()>;

/// Start hooks should only spawn their task and return, as ReceiptMonitor does.
/// A host must not invoke arbitrary blocking native start hooks on a custody task.
pub trait Extension: Send + 'static {
    fn channels(&self) -> Vec<ChannelSpec>;
    fn start(self: Box<Self>, context: ExtensionContext) -> ExtensionHandle;
}

/// No sender, raw bytes, Oracle, signer-core, MPC, proposer, or Class C handle.
/// The roster currently has no confidential extension-grant schema, so no
/// confidential API exists. New public protocols require a reviewed wire DTO;
/// this profile forwards only the existing typed public witness commitments.
///
/// ```compile_fail,E0599
/// use oic_node::ExtensionContext;
/// fn escape(context: ExtensionContext) { let _ = context.sender(); }
/// ```
pub struct ExtensionContext {
    namespace: String,
    shared: Arc<Shared>,
    channels: BTreeMap<u64, ExtensionChannel>,
    incoming: mpsc::Receiver<ExtensionEvent>,
    records: mpsc::Receiver<AuthorityReceipt>,
}

impl ExtensionContext {
    /// Namespace for any future extension-specific signatures. Forwarded native
    /// authority/audit/attestation signatures retain their original domains;
    /// this context exposes no signing key or custom protocol signing API.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn node_id(&self) -> &NodeId {
        &self.shared.local
    }
    pub fn roster(&self) -> &SignedRoster {
        &self.shared.roster
    }
    pub fn channel(&self, channel: u64) -> Option<ExtensionChannel> {
        self.channels.get(&channel).cloned()
    }
    pub async fn recv(&mut self) -> Option<ExtensionEvent> {
        self.incoming.recv().await
    }

    /// Strictly increasing, host-verified receipts, not peer-supplied records.
    /// Overflow disconnects this stream rather than hiding an ordering gap.
    /// A closed stream requires a fresh host subscription and reconstruction.
    pub async fn next_record(&mut self) -> Option<AuthorityReceipt> {
        self.records.recv().await
    }
}

/// Authenticated peer identity plus a reviewed Class P body, never raw bytes.
/// Authentication does not verify the embedded artifact's own signature.
#[derive(Debug)]
pub struct ExtensionEvent {
    pub from: NodeId,
    pub channel: u64,
    pub message: WitnessMessage,
}

struct Shared {
    sender: SendHandle,
    roster: SignedRoster,
    local: NodeId,
}

/// A fixed channel with named recipients only. Clones share the narrower
/// grant's per-peer rolling-second attempt quota. Failed submissions consume
/// quota too; this prevents retry loops from bypassing the extension budget.
///
/// ```compile_fail,E0308
/// use oic_node::ExtensionChannel;
/// use oic_domain_types::{Intent, NodeId};
/// async fn confidential(channel: ExtensionChannel, peer: &NodeId, intent: &Intent) {
///     channel.send(peer, intent).await.unwrap();
/// }
/// ```
/// ```compile_fail,E0061
/// use oic_node::ExtensionChannel;
/// use oic_domain_types::NodeId;
/// use oic_peer_wire::WitnessMessage;
/// async fn custody(channel: ExtensionChannel, peer: &NodeId, body: &WitnessMessage) {
///     channel.send(peer, 20, body).await.unwrap();
/// }
#[derive(Clone)]
pub struct ExtensionChannel {
    shared: Arc<Shared>,
    spec: ChannelSpec,
    quota: Arc<Budget>,
}

impl ExtensionChannel {
    pub fn spec(&self) -> &ChannelSpec {
        &self.spec
    }

    pub async fn send(&self, to: &NodeId, message: &WitnessMessage) -> OicResult<()> {
        check_peer(&self.shared, &self.spec, &self.shared.local, to)?;
        let bytes = PeerFrameV1::encode_public(
            message,
            self.shared.roster.body.roster_epoch,
            FrameKind::Audit,
            self.spec.max_message_size as usize - HEADER_LEN,
        )
        .map_err(|_| OicError::invalid_request("invalid or oversized public extension message"))?;
        self.quota.take(to)?;
        self.shared.sender.send(to, self.spec.channel, bytes).await
    }
}

#[derive(Default)]
struct Budget {
    limit: u32,
    attempts: Mutex<BTreeMap<NodeId, VecDeque<Instant>>>,
}

impl Budget {
    fn new(limit: u32) -> Self {
        Self { limit, ..Self::default() }
    }
    fn take(&self, peer: &NodeId) -> OicResult<()> {
        let mut attempts = self.attempts.lock().map_err(|_| OicError::internal("extension budget unavailable"))?;
        let times = attempts.entry(peer.clone()).or_default();
        let now = Instant::now();
        while times.front().is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(1)) {
            times.pop_front();
        }
        if times.len() >= self.limit as usize {
            return Err(OicError::new(ErrorCode::Conflict, "extension quota exhausted"));
        }
        times.push_back(now);
        Ok(())
    }
}

struct Route {
    spec: ChannelSpec,
    incoming: mpsc::Sender<ExtensionEvent>,
    quota: Budget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionDispatch {
    Unclaimed,
    Delivered,
    Dropped,
}

/// Host-only router. Do not give this object or its transport to an extension.
/// Channel claims last for this host/roster lifetime, even after an extension
/// exits. Restart transport/host after roster changes; no dynamic admission.
pub struct ExtensionHost {
    shared: Arc<Shared>,
    names: BTreeSet<String>,
    routes: BTreeMap<u64, Route>,
    subscribers: Vec<mpsc::Sender<AuthorityReceipt>>,
    last_sequence: Option<u64>,
}

impl ExtensionHost {
    pub fn new(transport: &Transport) -> OicResult<Self> {
        let roster = transport.roster();
        let node = roster.node(transport.node_id()).ok_or_else(|| OicError::new(ErrorCode::PeerNotAdmitted, "extension host is not admitted"))?;
        // Recovery participants also hold shares inside ceremony roster epochs.
        if !node.participant_keys.is_empty() {
            return Err(OicError::policy_denied("extensions cannot run on signer or recovery nodes"));
        }
        Ok(Self {
            shared: Arc::new(Shared { sender: transport.sender(), roster: roster.clone(), local: transport.node_id().clone() }),
            names: BTreeSet::new(),
            routes: BTreeMap::new(),
            subscribers: Vec::new(),
            last_sequence: None,
        })
    }

    /// Claim all channels atomically, with no widening of signed roles, size,
    /// or effective transport quota. Empty claims support read-only consumers.
    pub fn start(&mut self, name: &str, extension: Box<dyn Extension>) -> OicResult<ExtensionHandle> {
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || self.names.contains(name)
        {
            return Err(OicError::invalid_request("invalid or duplicate extension name"));
        }
        let claims = extension.channels();
        let mut claimed = BTreeSet::new();
        for claim in &claims {
            let signed = self
                .shared
                .roster
                .body
                .channel_acl
                .iter()
                .find(|acl| acl.channel == claim.channel)
                .ok_or_else(|| OicError::new(ErrorCode::PeerNotAdmitted, "extension channel absent from roster"))?;
            if claim.channel < 1024
                || self.routes.contains_key(&claim.channel)
                || !claimed.insert(claim.channel)
                || claim.sender_roles.is_empty()
                || claim.receiver_roles.is_empty()
                || !claim.sender_roles.iter().all(|r| signed.sender_roles.contains(r))
                || !claim.receiver_roles.iter().all(|r| signed.receiver_roles.contains(r))
                || claim.max_message_size as usize <= HEADER_LEN
                || claim.max_message_size > signed.max_message_size
                || claim.max_message_size as usize > MAX_MESSAGE_SIZE
                || claim.quota == 0
                || claim.quota > signed.quota.min(MAX_QUOTA)
            {
                return Err(OicError::policy_denied("extension claim exceeds or conflicts with roster grant"));
            }
        }
        let (incoming, receive) = mpsc::channel(EXTENSION_MAILBOX_CAPACITY);
        let (records, record_receive) = mpsc::channel(EXTENSION_MAILBOX_CAPACITY);
        let mut channels = BTreeMap::new();
        for spec in claims {
            channels
                .insert(spec.channel, ExtensionChannel { shared: self.shared.clone(), quota: Arc::new(Budget::new(spec.quota)), spec: spec.clone() });
            self.routes.insert(spec.channel, Route { quota: Budget::new(spec.quota), spec, incoming: incoming.clone() });
        }
        self.subscribers.push(records);
        self.names.insert(name.to_owned());
        Ok(extension.start(ExtensionContext {
            namespace: format!("OIC/EXT/{name}/v1"),
            shared: self.shared.clone(),
            channels,
            incoming: receive,
            records: record_receive,
        }))
    }

    /// Pass events from this host's Transport::recv, never peer-asserted IDs.
    /// An unclaimed event remains available to the host's custody dispatcher.
    /// Typed decoding, narrower ACLs, size and quota are checked before delivery.
    /// Full/closed extension mailboxes drop arrivals without waiting on them.
    pub fn dispatch(&self, event: &Event) -> OicResult<ExtensionDispatch> {
        let Some(route) = self.routes.get(&event.channel) else {
            return Ok(ExtensionDispatch::Unclaimed);
        };
        check_peer(&self.shared, &route.spec, &event.from, &self.shared.local)?;
        let frame = PeerFrameV1::decode(
            &event.bytes,
            self.shared.roster.body.roster_epoch,
            FrameKind::Audit,
            route.spec.max_message_size as usize - HEADER_LEN,
        )
        .map_err(|_| OicError::invalid_request("invalid extension frame"))?;
        let message: WitnessMessage = from_canonical_bytes(frame.body()).map_err(|_| OicError::invalid_request("invalid public extension body"))?;
        message.validate_public()?;
        route.quota.take(&event.from)?;
        Ok(if route.incoming.try_send(ExtensionEvent { from: event.from.clone(), channel: event.channel, message }).is_ok() {
            ExtensionDispatch::Delivered
        } else {
            ExtensionDispatch::Dropped
        })
    }

    /// Host must verify receipt signatures/ordering against its actual authority
    /// before publishing. This API checks scope/order, not an authority key that
    /// the transport roster does not contain. Never publish peer input directly.
    /// A slow consumer is disconnected; it cannot delay other consumers/custody.
    pub fn publish_record(&mut self, receipt: AuthorityReceipt) -> OicResult<()> {
        if receipt.body.institution_id != self.shared.roster.body.institution_id
            || receipt.body.environment_id != self.shared.roster.body.environment_id
        {
            return Err(OicError::scope("public record scope mismatch"));
        }
        if self.last_sequence.is_some_and(|last| receipt.body.commit_sequence <= last) {
            return Err(OicError::new(ErrorCode::Conflict, "public record sequence did not advance"));
        }
        self.last_sequence = Some(receipt.body.commit_sequence);
        self.subscribers.retain(|subscriber| subscriber.try_send(receipt.clone()).is_ok());
        Ok(())
    }
}

fn check_peer(shared: &Shared, spec: &ChannelSpec, from: &NodeId, to: &NodeId) -> OicResult<()> {
    let has_role = |id: &NodeId, roles: &[Role]| {
        shared
            .roster
            .node(id)
            .is_some_and(|node| roles.iter().any(|role| node.roles.contains(role) || (*role == Role::Verifier && node.roles.contains(&Role::Signer))))
    };
    if from == to || !shared.roster.allows(spec.channel, from, to) || !has_role(from, &spec.sender_roles) || !has_role(to, &spec.receiver_roles) {
        return Err(OicError::new(ErrorCode::PeerNotAdmitted, "peer outside extension grant"));
    }
    Ok(())
}

/// Read-only reference consumer of the host's ordered public receipt stream.
/// Counts are observations, not authorization, release evidence, or a durable
/// audit. Reconstruct from the host's log on restart or a disconnected stream.
pub struct ReceiptMonitor {
    updates: watch::Sender<ReceiptProgress>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiptProgress {
    pub commit_sequence: Option<u64>,
    pub reservations: u64,
    pub releases: u64,
    pub closed: bool,
}

impl ReceiptMonitor {
    pub fn new() -> (Self, watch::Receiver<ReceiptProgress>) {
        let (updates, receive) = watch::channel(ReceiptProgress::default());
        (Self { updates }, receive)
    }
}

impl Extension for ReceiptMonitor {
    fn channels(&self) -> Vec<ChannelSpec> {
        Vec::new()
    }
    fn start(self: Box<Self>, mut context: ExtensionContext) -> ExtensionHandle {
        tokio::spawn(async move {
            let mut progress = ReceiptProgress::default();
            while let Some(receipt) = context.next_record().await {
                progress.commit_sequence = Some(receipt.body.commit_sequence);
                match receipt.body.kind {
                    ReceiptKind::Reserved => progress.reservations = progress.reservations.saturating_add(1),
                    ReceiptKind::Release => progress.releases = progress.releases.saturating_add(1),
                }
                self.updates.send_replace(progress);
            }
            progress.closed = true;
            self.updates.send_replace(progress);
        })
    }
}
