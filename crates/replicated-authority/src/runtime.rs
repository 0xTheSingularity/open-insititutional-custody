//! Runtime-owned composition of BETA Simplex, full-block marshal and the local
//! re-executing follower. Supply roster-admitted networks whose peer identities
//! map to committee vote keys. Transport credentials remain distinct. All storage
//! partitions contain Class C data and require an encrypted storage deployment.

use crate::{
    AuthorityBlock, FinalizedFloor, FinalizedPage, Follower, FollowerConfig, Proposer,
    ReplicaApplication, ReplicatedState, VerifiedLog,
};
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_codec::Decode;
use commonware_consensus::{
    Epochable, Heightable, Reporter,
    marshal::{
        self, Identifier, Update, core::Actor, resolver::p2p as resolver, standard::Standard,
    },
    simplex::{
        self,
        config::{Floor, ForwardPolicy, SkipPolicy},
        elector::RoundRobin,
        types::{Activity, Certificate},
    },
    types::{Epoch, EpochInfo, Epocher, Height, ViewDelta},
};
use commonware_cryptography::{
    Digestible, Signer,
    certificate::{ConstantProvider, Verifier},
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_macros::select;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock, Handle, Metrics, Spawner, Storage, buffer::paged::CacheRef,
};
use commonware_storage::archive::immutable;
use commonware_utils::{
    Acknowledgement, NZU16, NZU64, NZUsize,
    channel::{mpsc, oneshot},
};
use oic_domain_types::*;
use rand_core_commonware::CryptoRng;
use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use tokio::sync::{mpsc as queries, oneshot as response, watch};

/// All five channels must be isolated, bounded, authenticated and ACL-checked
/// by the host. Signer/witness followers receive no vote key and run no engine.
pub struct Networks<S, R> {
    pub vote: (S, R),
    pub certificate: (S, R),
    pub consensus_resolver: (S, R),
    pub blocks: (S, R),
    pub backfill: (S, R),
}

pub struct RuntimeConfig<P, B> {
    pub follower: FollowerConfig,
    pub node_id: NodeId,
    /// Consensus-facing identity, mapped by the host to a transport identity.
    pub public_key: PublicKey,
    pub vote_key: Option<PrivateKey>,
    pub peers: P,
    pub blocker: B,
}

/// Published only after native re-execution and follower journal sync, not on a
/// marshal Tip notification. Retain floor independently before trusting rollback
/// recovery. The snapshot remains confidential and is not release evidence by
/// itself outside the process that verified its history.
#[derive(Clone)]
pub struct FinalizedSnapshot {
    pub floor: FinalizedFloor,
    pub state: Arc<ReplicatedState>,
}

struct ReadRequest {
    after: FinalizedFloor,
    reply: response::Sender<OicResult<FinalizedPage>>,
}

/// Bounded, read-only access to the follower's synced journal. This exposes
/// portable confidential evidence, never a signing capability or live writer.
#[derive(Clone)]
pub struct FinalizedReader(queries::Sender<ReadRequest>);

impl FinalizedReader {
    pub async fn read_page(&self, after: FinalizedFloor) -> OicResult<FinalizedPage> {
        let (reply, receive) = response::channel();
        self.0
            .try_send(ReadRequest { after, reply })
            .map_err(|_| unavailable("finalized history read queue unavailable"))?;
        receive
            .await
            .map_err(|_| unavailable("finalized history reader stopped"))?
    }
}

pub struct Running {
    pub proposer: Option<Proposer>,
    pub progress: watch::Receiver<FinalizedSnapshot>,
    /// Process-local authorization capability, minted only by the synced
    /// re-executing follower. Genesis has no finalized log and publishes None.
    pub verified_log: watch::Receiver<Option<VerifiedLog>>,
    pub history: FinalizedReader,
    stop: oneshot::Sender<()>,
    task: Handle<OicResult<()>>,
}

impl Running {
    /// Stops the owning task and its supervised consensus/marshal descendants.
    /// Every published state already passed sync; no in-memory queue is a commit.
    pub async fn shutdown(self) -> OicResult<()> {
        let _ = self.stop.send(());
        self.task
            .await
            .map_err(|_| unavailable("replicated runtime stopped unexpectedly"))?
    }
}

#[derive(Clone)]
struct FinalizedReporter(mpsc::Sender<Update<AuthorityBlock>>);

impl Reporter for FinalizedReporter {
    type Activity = Update<AuthorityBlock>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if matches!(update, Update::Tip(..)) {
            return Feedback::Ok;
        }
        match self.0.try_send(update) {
            Ok(()) => Feedback::Ok,
            // Dropping the acknowledgement makes marshal stop; never silently
            // acknowledge or skip a block on overflow or local consumer failure.
            Err(_) => Feedback::Closed,
        }
    }
}

/// One fixed committee; no implicit epoch rollover. Ordered committee activation
/// is deliberately unavailable until its transition and handoff are implemented.
#[derive(Clone)]
struct SingleEpoch(Epoch);

impl Epocher for SingleEpoch {
    fn containing(&self, height: Height) -> Option<EpochInfo> {
        Some(EpochInfo::new(
            self.0,
            height,
            Height::zero(),
            Height::new(u64::MAX),
        ))
    }
    fn first(&self, epoch: Epoch) -> Option<Height> {
        (epoch == self.0).then_some(Height::zero())
    }
    fn last(&self, epoch: Epoch) -> Option<Height> {
        (epoch == self.0).then_some(Height::new(u64::MAX))
    }
}

pub async fn start<E, P, B, S, R>(
    context: E,
    mut config: RuntimeConfig<P, B>,
    networks: Networks<S, R>,
) -> OicResult<Running>
where
    E: BufferPooler + CryptoRng + Spawner + Metrics + Clock + Storage,
    P: Provider<PublicKey = PublicKey>,
    B: Blocker<PublicKey = PublicKey>,
    S: Sender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
{
    let (ready, started) = oneshot::channel();
    let (stop, mut stopping) = oneshot::channel();
    let (read, mut reads) = queries::channel::<ReadRequest>(8);
    let task = context.spawn(move |mut context| async move {
        let trust = config.follower.trust.clone();
        let genesis = config.follower.genesis.clone();
        let executor = config.follower.executor.clone();
        let partition = config.follower.partition.clone();
        config.follower.local_now = now(&context);
        let mut follower = Follower::open(context.child("follower"), config.follower, &mut context).await?;
        if config.vote_key.as_ref().is_some_and(|key| key.public_key() != config.public_key) {
            return Err(OicError::scope("local consensus-facing identity differs from vote key"));
        }
        let scheme = config.vote_key.map(|key| trust.signer(&config.node_id, key)).transpose()?;
        let verifier = trust.verifier();
        let cache = CacheRef::from_pooler(&context, NZU16!(4096), NZUsize!(64));
        let certificates = immutable::Archive::init(context.child("certificates"), archive_config(
            &format!("{partition}-certificates"), verifier.certificate_codec_config(), cache.clone(),
        )).await.map_err(|_| unavailable("certificate archive recovery failed"))?;
        let blocks = immutable::Archive::init(context.child("blocks"), archive_config(&format!("{partition}-blocks"), (), cache.clone()))
            .await.map_err(|_| unavailable("block archive recovery failed"))?;
        let (marshal, mailbox, floor) = Actor::<_, Standard<AuthorityBlock>, _, _, _, _, _, _>::init(context.child("marshal"), certificates, blocks, marshal::Config {
            provider: ConstantProvider::<_, Epoch>::new(verifier.clone()), epocher: SingleEpoch(trust.epoch()),
            start: marshal::Start::Genesis(genesis.clone()), partition_prefix: format!("{partition}-marshal"), mailbox_size: NZUsize!(64),
            view_retention: ViewDelta::new(128), prunable_items_per_section: NZU64!(64), page_cache: cache.clone(),
            replay_buffer: NZUsize!(65536), key_write_buffer: NZUsize!(65536), value_write_buffer: NZUsize!(65536),
            block_codec_config: (), max_repair: NZUsize!(16), max_pending_acks: NZUsize!(1), strategy: Sequential,
        }).await;
        if floor.height().is_some_and(|height| height > follower.tip().height()) {
            return Err(OicError::new(ErrorCode::RecoveryRequired, "marshal processed floor exceeds locally re-executed history"));
        }
        let resolver = resolver::init(context.child("backfill"), resolver::Config {
            public_key: config.public_key.clone(), peer_provider: config.peers.clone(), blocker: config.blocker.clone(),
            mailbox_size: NZUsize!(64), timeout: Duration::from_secs(5), fetch_retry_timeout: Duration::from_secs(1),
            priority_requests: false, priority_responses: false,
        }, networks.backfill);
        let (broadcast, buffer) = buffered::Engine::new(context.child("broadcast"), buffered::Config {
            public_key: config.public_key, mailbox_size: NZUsize!(64), deque_size: 128, priority: false, codec_config: (), peer_provider: config.peers,
        });
        let mut broadcast_task = broadcast.start(networks.blocks);
        let (updates, mut delivered) = mpsc::channel(2);
        let mut marshal_task = marshal.start(FinalizedReporter(updates), buffer, resolver);
        let (application, proposer) = ReplicaApplication::new(context.child("application"), executor, mailbox.clone(), &follower)?;
        let (proposer, mut consensus_task) = if let Some(scheme) = scheme {
            let floor = follower.finalization().cloned().map_or_else(|| Floor::Genesis(genesis.digest()), Floor::Finalized);
            let engine = simplex::Engine::new(context.child("simplex"), simplex::Config {
                scheme, elector: RoundRobin::<commonware_cryptography::Sha256>::default(), blocker: config.blocker, automaton: application.clone(), relay: application.clone(),
                reporter: mailbox.clone(), track_historical_votes: true, strategy: Sequential, partition: format!("{partition}-votes"),
                mailbox_size: NZUsize!(64), epoch: trust.epoch(), floor, replay_buffer: NZUsize!(65536), write_buffer: NZUsize!(65536), page_cache: cache,
                leader_timeout: Duration::from_secs(2), certification_timeout: Duration::from_secs(5), timeout_retry: Duration::from_secs(1),
                view_retention: ViewDelta::new(128), skip: SkipPolicy::Disabled, fetch_timeout: Duration::from_secs(5), forward: ForwardPolicy::SilentVoters,
            });
            let task = engine.start(networks.vote, networks.certificate, networks.consensus_resolver);
            (Some(proposer), task)
        } else {
            // Followers do not instantiate a signer or run the voting engine.
            // They authenticate certificate-channel finalizations themselves;
            // notarizations never enter the finalized-delivery path.
            let mut certificates = networks.certificate.1;
            let mut mailbox = mailbox.clone();
            let epoch = trust.epoch();
            let task = context.child("follow_certificates").spawn(move |mut rng| async move {
                while let Ok((_, bytes)) = certificates.recv().await {
                    let Ok(Certificate::Finalization(finalization)) = Certificate::<_, Digest>::decode_cfg(bytes, &verifier.certificate_codec_config()) else { continue; };
                    if finalization.epoch() == epoch && finalization.verify(&mut rng, &verifier, &Sequential)
                        && !mailbox.report(Activity::Finalization(finalization)).accepted()
                    {
                        break;
                    }
                }
            });
            (None, task)
        };
        let (publish, progress) = watch::channel(snapshot(&follower));
        let initial_log = if follower.tip().height().is_zero() { None } else { Some(follower.verified_log()?) };
        let (publish_log, verified_log) = watch::channel(initial_log);
        let _ = ready.send((proposer, progress, verified_log));
        loop {
            select! {
                _ = &mut stopping => return Ok(()),
                _ = &mut broadcast_task => return Err(unavailable("block broadcast stopped")),
                _ = &mut marshal_task => return Err(unavailable("marshal stopped")),
                _ = &mut consensus_task => return Err(unavailable("consensus or certificate follower stopped")),
                request = reads.recv() => {
                    let Some(request) = request else { return Err(unavailable("history reader stopped")); };
                    if !request.reply.is_closed() {
                        let _ = request.reply.send(follower.read_page(request.after).await);
                    }
                },
                update = delivered.recv() => {
                    let Some(Update::Block(block, ack)) = update else { return Err(unavailable("marshal delivery stopped")); };
                    if block.height().is_zero() && block.digest() == genesis.digest() {
                        ack.acknowledge();
                        continue;
                    }
                    if block.height() <= follower.tip().height() {
                        if !follower.checkpoint_contains(&block) {
                            return Err(OicError::new(ErrorCode::RecoveryRequired, "marshal redelivery differs from synced checkpoint"));
                        }
                        ack.acknowledge();
                        continue;
                    }
                    // Marshal finalizes ancestors through a descendant's
                    // certificate; its exact-height lookup is local/best-effort.
                    // With one pending ack we cannot wait for another delivery.
                    // Fetch and authenticate the nearest certified checkpoint,
                    // re-execute its entire ancestry, then acknowledge each
                    // matching redelivery from the synced checkpoint above.
                    let latest = mailbox.get_info(Identifier::Latest).await.ok_or_else(|| unavailable("finalized archive has no tip"))?.0;
                    let mut height = block.height();
                    let mut blocks = vec![block.as_ref().clone()];
                    let finalization = loop {
                        if let Some(certificate) = mailbox.get_finalization(height).await { break certificate; }
                        if height >= latest || blocks.len() >= crate::follower::MAX_CHECKPOINT_BLOCKS {
                            return Err(unavailable("finalized ancestry lacks a bounded certified checkpoint"));
                        }
                        height = Height::new(height.get().checked_add(1).ok_or_else(|| unavailable("finalized height exhausted"))?);
                        blocks.push(mailbox.get_block(height).await.ok_or_else(|| unavailable("finalized ancestor missing from archive"))?);
                    };
                    let local_now = now(&context);
                    follower.apply_finalized_chain(&mut context, blocks, finalization, local_now).await?;
                    application.advance(&follower)?;
                    publish.send_replace(snapshot(&follower));
                    publish_log.send_replace(Some(follower.verified_log()?));
                    ack.acknowledge();
                }
            }
        }
    });
    match started.await {
        Ok((proposer, progress, verified_log)) => Ok(Running {
            proposer,
            progress,
            verified_log,
            history: FinalizedReader(read),
            stop,
            task,
        }),
        Err(_) => match task.await {
            Ok(Err(error)) => Err(error),
            _ => Err(unavailable("replicated runtime failed to initialize")),
        },
    }
}

fn snapshot<E: Storage + Metrics + BufferPooler>(follower: &Follower<E>) -> FinalizedSnapshot {
    FinalizedSnapshot {
        floor: follower.floor(),
        state: Arc::new(follower.state().clone()),
    }
}

fn now(context: &impl Clock) -> UnixSeconds {
    UnixSeconds(
        context
            .current()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}
fn unavailable(detail: &str) -> OicError {
    OicError::new(ErrorCode::AuthorityUnavailable, detail)
}

fn archive_config<C>(prefix: &str, codec_config: C, cache: CacheRef) -> immutable::Config<C> {
    immutable::Config {
        metadata_partition: format!("{prefix}-metadata"),
        freezer_table_partition: format!("{prefix}-table"),
        freezer_table_initial_size: 1024,
        freezer_table_resize_frequency: 10,
        freezer_table_resize_chunk_size: 1024,
        freezer_key_partition: format!("{prefix}-keys"),
        freezer_key_page_cache: cache,
        freezer_value_partition: format!("{prefix}-values"),
        freezer_value_target_size: 1024 * 1024,
        freezer_value_compression: None,
        ordinal_partition: format!("{prefix}-ordinal"),
        items_per_section: NZU64!(64),
        freezer_key_write_buffer: NZUsize!(65536),
        freezer_value_write_buffer: NZUsize!(65536),
        ordinal_write_buffer: NZUsize!(65536),
        replay_buffer: NZUsize!(65536),
        codec_config,
    }
}
