use crate::{AuthorityBlock, Command, ConsensusContext, Executor, Follower, MAX_COMMANDS, ReplicatedState};
use commonware_actor::Feedback;
use commonware_consensus::{
    Automaton, Block, CertifiableAutomaton, CertifiableBlock, Epochable, Heightable, Relay,
    marshal::{
        core::{CommitmentFallback, DigestFallback, Mailbox},
        standard::Standard,
    },
    simplex::{Plan, scheme::ed25519::Scheme},
    types::Round,
};
use commonware_cryptography::{Digestible, ed25519::PublicKey, sha256::Digest};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{Clock, Spawner};
use commonware_utils::channel::{fallible::OneshotExt, mpsc, oneshot};
use oic_domain_types::*;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};

pub type AuthorityMailbox = Mailbox<Scheme, Standard<AuthorityBlock>>;
const MAX_ANCESTRY: usize = 256;

/// Local bounded admission only, not a committed-command acknowledgement.
/// Callers reconcile ordered state after a lost proposal; this queue does not
/// automatically resubmit a command whose execution may already have committed.
#[derive(Clone)]
pub struct Proposer(mpsc::Sender<Vec<Command>>);

impl Proposer {
    pub fn submit(&self, commands: Vec<Command>) -> OicResult<()> {
        if commands.is_empty()
            || commands.len() > MAX_COMMANDS
            || oic_canonical_encoding::canonical_bytes(&commands)?.len() > crate::MAX_COMMAND_BYTES
        {
            return Err(OicError::invalid_request("proposal batch outside limits"));
        }
        self.0.try_send(commands).map_err(|_| OicError::new(ErrorCode::AuthorityUnavailable, "proposal queue unavailable"))
    }
}

type Executed = (Arc<AuthorityBlock>, ReplicatedState);

struct Cache {
    anchor: Executed,
    speculative: BTreeMap<Digest, Executed>,
    order: VecDeque<Digest>,
}

impl Cache {
    fn get(&self, digest: Digest) -> Option<Executed> {
        if self.anchor.0.digest() == digest {
            return Some(self.anchor.clone());
        }
        self.speculative.get(&digest).cloned()
    }

    fn insert(&mut self, block: Arc<AuthorityBlock>, state: ReplicatedState) {
        let digest = block.digest();
        if self.speculative.contains_key(&digest) {
            return;
        }
        while self.order.len() >= MAX_ANCESTRY {
            if let Some(oldest) = self.order.pop_front() {
                self.speculative.remove(&oldest);
            }
        }
        self.order.push_back(digest);
        self.speculative.insert(digest, (block, state));
    }
}

/// BETA-trait Simplex application without Commonware's ALPHA application
/// wrappers. Re-executes the exact requested ancestry, including speculative
/// parents ahead of the finalized tip. A vote waits for marshal persistence;
/// this conservative profile trades pipelined disk latency for a smaller gate.
pub struct ReplicaApplication<E> {
    context: Arc<E>,
    executor: Arc<Executor>,
    marshal: AuthorityMailbox,
    cache: Arc<Mutex<Cache>>,
    proposals: Arc<Mutex<mpsc::Receiver<Vec<Command>>>>,
}

impl<E> Clone for ReplicaApplication<E> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            executor: self.executor.clone(),
            marshal: self.marshal.clone(),
            cache: self.cache.clone(),
            proposals: self.proposals.clone(),
        }
    }
}

impl<E: Clock + Spawner> ReplicaApplication<E> {
    /// Seed only from the locally re-executed, synced follower, never a peer's
    /// snapshot. Reopening the follower and checking its independent floor must
    /// precede restarting consensus and its durable vote journal.
    pub fn new<S: commonware_runtime::Storage + commonware_runtime::Metrics + commonware_runtime::BufferPooler>(
        context: E,
        executor: Executor,
        marshal: AuthorityMailbox,
        follower: &Follower<S>,
    ) -> OicResult<(Self, Proposer)> {
        if executor.state_hash(follower.state())? != follower.tip().state_hash() {
            return Err(OicError::unverifiable("follower execution configuration differs"));
        }
        let (send, receive) = mpsc::channel(32);
        let cache =
            Cache { anchor: (Arc::new(follower.tip().clone()), follower.state().clone()), speculative: BTreeMap::new(), order: VecDeque::new() };
        Ok((
            Self {
                context: Arc::new(context),
                executor: Arc::new(executor),
                marshal,
                cache: Arc::new(Mutex::new(cache)),
                proposals: Arc::new(Mutex::new(receive)),
            },
            Proposer(send),
        ))
    }

    /// Advance only after the follower has synced its independently verified
    /// finalized block. Speculative cache entries are never release evidence.
    pub fn advance<S: commonware_runtime::Storage + commonware_runtime::Metrics + commonware_runtime::BufferPooler>(
        &self,
        follower: &Follower<S>,
    ) -> OicResult<()> {
        if self.executor.state_hash(follower.state())? != follower.tip().state_hash() {
            return Err(OicError::unverifiable("follower execution configuration differs"));
        }
        let mut cache = self.cache.lock().expect("application cache");
        if follower.tip().height() < cache.anchor.0.height()
            || (follower.tip().height() == cache.anchor.0.height() && follower.tip().digest() != cache.anchor.0.digest())
        {
            return Err(OicError::unverifiable("application anchor regressed or forked"));
        }
        cache.anchor = (Arc::new(follower.tip().clone()), follower.state().clone());
        Ok(())
    }

    fn now(&self) -> UnixSeconds {
        UnixSeconds(self.context.current().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs())
    }

    async fn dependency(&self, digest: Digest, round: Round) -> Option<Executed> {
        let mut missing = Vec::new();
        let mut wanted = digest;
        let mut wanted_round = round;
        let (mut parent, mut state) = loop {
            if let Some(executed) = self.cache.lock().expect("application cache").get(wanted) {
                break executed;
            }
            if missing.len() >= MAX_ANCESTRY {
                return None;
            }
            let block = self.marshal.subscribe_by_commitment(wanted, CommitmentFallback::FetchByRound { round: wanted_round }).await.ok()?;
            if block.digest() != wanted || block.height() <= self.cache.lock().expect("application cache").anchor.0.height() {
                return None;
            }
            wanted = block.parent();
            wanted_round = Round::new(block.context().epoch(), block.context().parent.0);
            missing.push(block);
        };
        for block in missing.into_iter().rev() {
            self.wait_for_time(block.timestamp()).await;
            state = self.executor.verify_block(&parent, state, &block.context(), &block, self.now()).ok()?;
            self.cache.lock().expect("application cache").insert(block.clone(), state.clone());
            parent = block;
        }
        Some((parent, state))
    }

    async fn wait_for_time(&self, timestamp: UnixSeconds) {
        let earliest = timestamp.0.saturating_sub(self.executor.authority.max_clock_skew_seconds);
        self.context.sleep_until(UNIX_EPOCH + Duration::from_secs(earliest)).await;
    }

    async fn validate(&self, context: &ConsensusContext, block: Arc<AuthorityBlock>) -> bool {
        let Some((parent, state)) = self.dependency(context.parent.1, Round::new(context.epoch(), context.parent.0)).await else {
            return false;
        };
        self.wait_for_time(block.timestamp()).await;
        let Ok(state) = self.executor.verify_block(&parent, state, context, &block, self.now()) else {
            return false;
        };
        if !self.marshal.verified(context.round, block.clone()).await {
            return false;
        }
        self.cache.lock().expect("application cache").insert(block, state);
        true
    }
}

impl<E: Clock + Spawner> Automaton for ReplicaApplication<E> {
    type Context = ConsensusContext;
    type Digest = Digest;

    #[allow(clippy::async_yields_async)]
    async fn propose(&mut self, context: ConsensusContext) -> oneshot::Receiver<Digest> {
        let app = self.clone();
        let (mut send, receive) = oneshot::channel();
        self.context.child("propose").spawn(move |_| async move {
            let work = async {
                // Reusing or replacing a pre-crash proposal for this round could
                // equivocate. Nullify it instead and propose in a fresh view.
                if app.marshal.get_verified(context.round).await.is_some() {
                    return None;
                }
                let (parent, state) = app.dependency(context.parent.1, Round::new(context.epoch(), context.parent.0)).await?;
                app.wait_for_time(parent.timestamp()).await;
                let now = app.now();
                let commands = app.proposals.lock().expect("proposal queue").try_recv().unwrap_or_default();
                let (block, state) = app.executor.propose_block(&parent, state, context.clone(), &commands, now.max(parent.timestamp()), now).ok()?;
                let block = Arc::new(block);
                if !app.marshal.verified(context.round, block.clone()).await {
                    return None;
                }
                let digest = block.digest();
                app.cache.lock().expect("application cache").insert(block, state);
                Some(digest)
            };
            select! { _ = send.closed() => {}, result = work => { if let Some(digest) = result { send.send_lossy(digest); } } }
        });
        receive
    }

    #[allow(clippy::async_yields_async)]
    async fn verify(&mut self, context: ConsensusContext, digest: Digest) -> oneshot::Receiver<bool> {
        let app = self.clone();
        let (mut send, receive) = oneshot::channel();
        self.context.child("verify").spawn(move |_| async move {
            let verdict = async {
                let block = app.marshal.subscribe_by_digest(digest, DigestFallback::Wait).await.ok()?;
                Some(app.validate(&context, block).await)
            };
            select! { _ = send.closed() => {}, result = verdict => { if let Some(valid) = result { send.send_lossy(valid); } } }
        });
        receive
    }
}

impl<E: Clock + Spawner> CertifiableAutomaton for ReplicaApplication<E> {
    #[allow(clippy::async_yields_async)]
    async fn certify(&mut self, round: Round, digest: Digest) -> oneshot::Receiver<bool> {
        let app = self.clone();
        let (mut send, receive) = oneshot::channel();
        self.context.child("certify").spawn(move |_| async move {
            let verdict = async {
                let block = app.marshal.subscribe_by_commitment(digest, CommitmentFallback::FetchByRound { round }).await.ok()?;
                if block.context().round != round {
                    return Some(false);
                }
                let valid = app.validate(&block.context(), block.clone()).await && app.marshal.certified(round, block).await;
                Some(valid)
            };
            select! { _ = send.closed() => {}, result = verdict => { if let Some(valid) = result { send.send_lossy(valid); } } }
        });
        receive
    }
}

impl<E: Clock + Spawner> Relay for ReplicaApplication<E> {
    type Digest = Digest;
    type PublicKey = PublicKey;
    type Plan = Plan<PublicKey>;

    fn broadcast(&mut self, digest: Digest, plan: Self::Plan) -> Feedback {
        match plan {
            Plan::Propose { round } => self.marshal.forward(round, digest, Recipients::All),
            Plan::Forward { round, recipients } => self.marshal.forward(round, digest, recipients),
        }
    }
}
