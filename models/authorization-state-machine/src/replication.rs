//! Finite RFC003 composition model, not a consensus algorithm or a D2 runtime.
//!
//! Two followers independently re-execute real canonical `AuthorityCommand`s
//! with `oic_authorization_state::apply`. Three fixed, valid histories cover a
//! release before freeze/rotation, rotation before a fresh session, and freeze
//! refusing a new release. Finalization and delivery advance independently.
//!
//! Assumptions: one authenticated, fork-free finalization order; authenticated
//! admin-approved roster activation and local operator halt/unhalt; fixed
//! monotonic block time; atomic durable prefix/halt recovery. Each epoch has one
//! trusted roster: its hash, signatures, and topology are not verified here.
//! Roster activation
//! and output admission below are explicit MODEL contracts, not calls to an
//! actual D2 follower or signer-core. They fence sessions on local roster
//! activation, not instantaneously at nodes that have not learned a new roster.
//! No quorum signatures, Simplex voting, kernel evaluation, real MPC, storage
//! faults, or guarantees of eventual delivery are modeled.
//!
//! The universe is finite: three histories of at most four entries, two nodes,
//! two roster epochs, one crash/restart after progress per node, local halt/session/
//! output state. Observation records only the last boundary, not an unbounded
//! trace or a power set of prior reachability flags. The checker still reports
//! a bounded search honestly; finite does not mean the chosen depth exhausts it.

use super::*;
use oic_canonical_encoding::from_canonical_bytes;
use std::hash::{Hash, Hasher};

const PREFIX: u16 = 1 << 5;
const HALT: u16 = 1 << 6;
const SCOPE: u16 = 1 << 7;
const RECOVERY: u16 = 1 << 8;
const REPLAY: u16 = 1 << 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Entry {
    Reserve(u8),
    Release(u8),
    Freeze,
    /// Abstract authenticated roster activation; no authority command invoked.
    Roster(u8),
}

impl Entry {
    fn command(self, prefix: &Prefix) -> Option<AuthorityCommand> {
        let command = match self {
            Self::Reserve(epoch) => AuthorityCommand::Reserve {
                request: ReserveRequest {
                    family_id: family(1),
                    candidate_id: Cand::F1a.id(),
                    candidate_revision: 1,
                    vault_id: vault(),
                    intent_id: intent(1).intent_id,
                    policy_epoch: prefix.state.policy_epoch,
                    policy_hash: prefix.state.policy_hash,
                    claims: claims(Cand::F1a),
                    grants: vec![],
                    envelope_body_hash: envelope(Cand::F1a),
                    signer_session_id: scoped_session(epoch),
                    issuance_deadline: UnixSeconds(T0 + DEADLINE),
                    policy_decision: Decision::Allow { rule_id: "auto".into() },
                    exposure_limits: vec![(usdc(), limit())],
                },
            },
            Self::Release(epoch) => AuthorityCommand::Release {
                request: ReleaseRequest {
                    reservation_id: rid(Cand::F1a),
                    reservation_version: 1,
                    envelope_body_hash: envelope(Cand::F1a),
                    signer_session_id: scoped_session(epoch),
                    expected_policy_epoch: prefix.state.policy_epoch,
                    freshness: FreshnessContext { now: UnixSeconds(T0) },
                },
            },
            Self::Freeze => {
                static SIGNATURE: OnceLock<CredentialSignature> = OnceLock::new();
                let signature = SIGNATURE.get_or_init(|| {
                    let r = responder();
                    let h = FreezeProposal::new(inst(), env(), FreezeScope::Global, r.0.clone(), "drill")
                        .hash()
                        .unwrap();
                    cred_sig(&r, &h)
                });
                AuthorityCommand::Freeze {
                    scope: FreezeScope::Global,
                    by: responder().0,
                    reason: "drill".into(),
                    signature: signature.signature.clone(),
                }
            }
            Self::Roster(_) => return None,
        };
        // Follow the actual security-object encoding, not a second decoder.
        Some(from_canonical_bytes(&canonical_bytes(&command).unwrap()).unwrap())
    }

    fn old_action(self) -> Option<Action> {
        match self {
            Self::Reserve(_) => Some(Action::Reserve(Cand::F1a)),
            Self::Release(_) => Some(Action::Release(Cand::F1a)),
            Self::Freeze => Some(Action::Freeze),
            Self::Roster(_) => None,
        }
    }
}

fn scoped_session(epoch: u8) -> SigningSessionId {
    SigningSessionId::unchecked(format!("session-f1-a-roster-{epoch}"))
}

/// Immutable decoded cache plus canonical state identity. Equal real prefixes
/// share their allocation, keeping the search small without hiding divergence.
#[derive(Clone)]
struct Prefix {
    bytes: Vec<u8>,
    state: AuthorityState,
    roster: u8,
}

impl Prefix {
    fn new(state: AuthorityState, roster: u8) -> Self {
        Self {
            bytes: encode(&state),
            state,
            roster,
        }
    }

    fn apply(&self, entry: Entry) -> OicResult<Self> {
        if let Some(command) = entry.command(self) {
            let (state, _, _) = oic_authorization_state::apply(&config(), self.state.clone(), command, UnixSeconds(T0))?;
            Ok(Self::new(state, self.roster))
        } else if let Entry::Roster(epoch) = entry {
            if epoch != self.roster + 1 {
                return Err(OicError::scope("model roster epochs must advance consecutively"));
            }
            Ok(Self::new(self.state.clone(), epoch))
        } else {
            unreachable!()
        }
    }
}

impl PartialEq for Prefix {
    fn eq(&self, other: &Self) -> bool {
        self.roster == other.roster && self.bytes == other.bytes
    }
}
impl Eq for Prefix {}
impl Hash for Prefix {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.roster.hash(h);
        self.bytes.hash(h);
    }
}
impl std::fmt::Debug for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prefix")
            .field("roster", &self.roster)
            .field("commit", &self.state.commit_sequence)
            .field("issuance", &self.state.issuance.len())
            .field("freeze", &self.state.freeze.global_freeze.is_some())
            .finish()
    }
}

struct History {
    entries: Vec<Entry>,
    prefixes: Vec<Arc<Prefix>>,
}

fn histories() -> &'static [History] {
    static HISTORIES: OnceLock<Vec<History>> = OnceLock::new();
    HISTORIES.get_or_init(|| {
        let initial = Arc::new(Prefix::new(AuthorityModel::initial().state().clone(), 0));
        [
            vec![Entry::Reserve(0), Entry::Release(0), Entry::Roster(1), Entry::Freeze],
            vec![Entry::Roster(1), Entry::Reserve(1), Entry::Release(1), Entry::Freeze],
            vec![Entry::Reserve(0), Entry::Freeze, Entry::Roster(1)],
        ]
        .into_iter()
        .map(|entries| {
            let mut prefixes = vec![initial.clone()];
            for entry in &entries {
                let post = prefixes.last().unwrap().apply(*entry).expect("valid finalized history");
                prefixes.push(Arc::new(post));
            }
            History { entries, prefixes }
        })
        .collect()
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Process {
    Running,
    Down,
    Recovered,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Replica {
    /// All three fields are durable in this model. Halt changes do not require
    /// ordering availability. A crash drops only the volatile session.
    applied: u8,
    prefix: Arc<Prefix>,
    halted: bool,
    process: Process,
    session: Option<u8>,
    output: bool,
}

/// Inputs are deliveries/requests, not fabricated finalization certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReplicationAction {
    FinalizeNext,
    Deliver { node: usize, height: u8 },
    Halt(usize),
    Unhalt(usize),
    Crash(usize),
    Restart(usize),
    Open { node: usize, epoch: u8 },
    Output { node: usize, epoch: u8 },
    TryReleaseWhileFrozen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Observation {
    None,
    Duplicate,
    Stale,
    Gap,
    Unfinalized,
    RestartedHalted,
    CatchupAfterRestart,
    HaltedOutput,
    ActiveSessionHalted,
    ActiveSessionFenced,
    EpochDivergence,
    StaleSession,
    Output { node: usize, epoch: u8 },
    FrozenReleaseRejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplicationState {
    history: usize,
    finalized: u8,
    source: Arc<Prefix>,
    replicas: [Replica; 2],
    violations: u16,
    observation: Observation,
}

impl ReplicationState {
    fn initial(history: usize) -> Self {
        let source = histories()[history].prefixes[0].clone();
        let replica = Replica {
            applied: 0,
            prefix: source.clone(),
            halted: false,
            process: Process::Running,
            session: None,
            output: false,
        };
        Self {
            history,
            finalized: 0,
            source,
            replicas: [replica.clone(), replica],
            violations: 0,
            observation: Observation::None,
        }
    }

    fn history(&self) -> &'static History {
        &histories()[self.history]
    }

    fn violations(&self) -> u16 {
        let mut violations = self.violations | u16::from(invariant_violations(&self.source.state, T0));
        if self.source != self.history().prefixes[usize::from(self.finalized)] {
            violations |= PREFIX;
        }
        for replica in &self.replicas {
            violations |= u16::from(invariant_violations(&replica.prefix.state, T0));
            if replica.applied > self.finalized || replica.prefix != self.history().prefixes[usize::from(replica.applied)] {
                violations |= PREFIX;
            }
            if replica.session.is_some_and(|epoch| epoch != replica.prefix.roster) {
                violations |= SCOPE;
            }
            if (replica.halted || replica.process == Process::Down) && replica.session.is_some() {
                violations |= HALT;
            }
        }
        if let Observation::Output { node, epoch } = self.observation {
            let replica = &self.replicas[node];
            if replica.halted || replica.process == Process::Down {
                violations |= HALT;
            }
            if replica.prefix.roster != epoch || self.replicas[1 - node].prefix.roster != epoch || replica.session != Some(epoch) {
                violations |= SCOPE;
            }
            if !replica
                .prefix
                .state
                .issuance
                .values()
                .any(|i| i.signer_session_id == scoped_session(epoch))
            {
                violations |= PREFIX;
            }
        }
        violations
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReplicationModel;

impl Model for ReplicationModel {
    type State = ReplicationState;
    type Action = ReplicationAction;

    fn init_states(&self) -> Vec<Self::State> {
        (0..histories().len()).map(ReplicationState::initial).collect()
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        if usize::from(state.finalized) < state.history().entries.len() {
            actions.push(ReplicationAction::FinalizeNext);
        }
        if state.source.state.freeze.global_freeze.is_some() && state.source.state.issuance.is_empty() {
            actions.push(ReplicationAction::TryReleaseWhileFrozen);
        }
        for (node, replica) in state.replicas.iter().enumerate() {
            if replica.process == Process::Down {
                actions.push(ReplicationAction::Restart(node));
                continue;
            }
            if replica.process == Process::Running && replica.applied > 0 {
                actions.push(ReplicationAction::Crash(node));
            }
            actions.push(if replica.halted {
                ReplicationAction::Unhalt(node)
            } else {
                ReplicationAction::Halt(node)
            });
            for height in 1..=state.history().entries.len() as u8 {
                actions.push(ReplicationAction::Deliver { node, height });
            }
            for epoch in 0..=1 {
                actions.push(ReplicationAction::Open { node, epoch });
                actions.push(ReplicationAction::Output { node, epoch });
            }
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        use ReplicationAction::*;
        let mut next = last.clone();
        next.observation = Observation::None;
        match action {
            FinalizeNext => {
                let entry = *last.history().entries.get(usize::from(last.finalized))?;
                let actual = Arc::new(last.source.apply(entry).expect("validated finalization entry"));
                next.finalized += 1;
                let expected = &last.history().prefixes[usize::from(next.finalized)];
                if let Some(action) = entry.old_action() {
                    next.violations |= u16::from(transition_violations(&last.source.state, &actual.state, action));
                }
                next.source = if &actual == expected { expected.clone() } else { actual };
            }
            Deliver { node, height } => {
                let replica = next.replicas.get_mut(node)?;
                if replica.process == Process::Down {
                    return None;
                }
                if height == 0 || usize::from(height) > last.history().entries.len() {
                    return None;
                }
                if height > last.finalized {
                    next.observation = Observation::Unfinalized;
                } else if height <= replica.applied {
                    next.observation = if height == replica.applied {
                        Observation::Duplicate
                    } else {
                        Observation::Stale
                    };
                } else if height != replica.applied + 1 {
                    next.observation = Observation::Gap;
                } else {
                    let entry = last.history().entries[usize::from(height - 1)];
                    let actual = Arc::new(replica.prefix.apply(entry).expect("same deterministic finalized prefix"));
                    let expected = &last.history().prefixes[usize::from(height)];
                    if let Some(action) = entry.old_action() {
                        next.violations |= u16::from(transition_violations(&replica.prefix.state, &actual.state, action));
                    }
                    if replica.prefix.roster != actual.roster {
                        if replica.session.is_some() {
                            next.observation = Observation::ActiveSessionFenced;
                        }
                        replica.session = None;
                    }
                    replica.prefix = if &actual == expected { expected.clone() } else { actual };
                    replica.applied = height;
                    if replica.process == Process::Recovered {
                        next.observation = Observation::CatchupAfterRestart;
                    }
                }
                // Duplicates, stale heights, gaps and unfinalized inputs must
                // not apply a command, rewind the cursor, or emit output.
                if matches!(
                    next.observation,
                    Observation::Duplicate | Observation::Stale | Observation::Gap | Observation::Unfinalized
                ) && replica != &last.replicas[node]
                {
                    next.violations |= REPLAY;
                }
            }
            Halt(node) | Unhalt(node) => {
                let replica = next.replicas.get_mut(node)?;
                if replica.process == Process::Down {
                    return None;
                }
                replica.halted = matches!(action, Halt(_));
                if replica.halted {
                    if replica.session.is_some() {
                        next.observation = Observation::ActiveSessionHalted;
                    }
                    replica.session = None;
                }
            }
            Crash(node) => {
                let replica = next.replicas.get_mut(node)?;
                if replica.process != Process::Running || replica.applied == 0 {
                    return None;
                }
                replica.process = Process::Down;
                replica.session = None;
            }
            Restart(node) => {
                let replica = next.replicas.get_mut(node)?;
                if replica.process != Process::Down {
                    return None;
                }
                let recovered = Prefix::new(
                    from_canonical_bytes(&replica.prefix.bytes).expect("durable canonical authority snapshot"),
                    replica.prefix.roster,
                );
                if recovered != *replica.prefix {
                    next.violations |= RECOVERY;
                }
                replica.process = Process::Recovered;
                if replica.halted && !replica.prefix.state.issuance.is_empty() {
                    next.observation = Observation::RestartedHalted;
                }
            }
            Open { node, epoch } | Output { node, epoch } => {
                let peer_roster = next.replicas.get(1usize.checked_sub(node)?)?.prefix.roster;
                let replica = next.replicas.get_mut(node)?;
                if replica.process == Process::Down {
                    return None;
                }
                let issued = !replica.prefix.state.issuance.is_empty();
                if replica.halted {
                    if issued && matches!(action, Output { .. }) {
                        next.observation = Observation::HaltedOutput;
                    }
                } else if epoch != replica.prefix.roster {
                    if issued && epoch < replica.prefix.roster {
                        next.observation = Observation::StaleSession;
                    }
                } else if replica.prefix.roster != peer_roster {
                    next.observation = Observation::EpochDivergence;
                } else if let Some(reservation) = replica.prefix.state.reservations.get(&rid(Cand::F1a)) {
                    if reservation.signer_session_id != scoped_session(epoch) {
                        next.observation = Observation::StaleSession;
                    } else if matches!(action, Open { .. }) {
                        replica.session = Some(epoch);
                    } else if issued && replica.session == Some(epoch) {
                        replica.output = true;
                        next.observation = Observation::Output { node, epoch };
                    }
                }
            }
            TryReleaseWhileFrozen => {
                last.source.state.freeze.global_freeze.as_ref()?;
                match last.source.apply(Entry::Release(0)) {
                    Err(e) if e.code == ErrorCode::Frozen => next.observation = Observation::FrozenReleaseRejected,
                    Ok(actual) => {
                        next.violations |=
                            u16::from(transition_violations(&last.source.state, &actual.state, Action::Release(Cand::F1a))) | PREFIX;
                    }
                    Err(e) => panic!("expected the real freeze gate, got {e:?}"),
                }
            }
        }
        for (before, after) in last.replicas.iter().zip(&next.replicas) {
            if matches!(action, Crash(_) | Restart(_))
                && (before.applied != after.applied
                    || before.prefix != after.prefix
                    || before.halted != after.halted
                    || before.output != after.output)
            {
                next.violations |= RECOVERY;
            }
        }
        next.violations |= next.violations();
        (next != *last).then_some(next)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        let mut properties = vec![
            Property::always("replication P1 exposure bound", |_, s: &ReplicationState| {
                s.violations & u16::from(V_P1) == 0
            }),
            Property::always("replication P2 issued exposure retained", |_, s: &ReplicationState| {
                s.violations & u16::from(V_P2) == 0
            }),
            Property::always("replication P3 resource exclusivity", |_, s: &ReplicationState| {
                s.violations & u16::from(V_P3) == 0
            }),
            Property::always("replication P4 ordered freeze", |_, s: &ReplicationState| {
                s.violations & u16::from(V_P4) == 0
            }),
            Property::always("replication P5 no issued abort", |_, s: &ReplicationState| {
                s.violations & u16::from(V_P5) == 0
            }),
            Property::always("P6 every replica is an exact finalized prefix", |_, s: &ReplicationState| {
                s.violations & PREFIX == 0
            }),
            Property::always("P7 local halt prevents contribution", |_, s: &ReplicationState| {
                s.violations & HALT == 0
            }),
            Property::always("P8 sessions and output are roster fenced", |_, s: &ReplicationState| {
                s.violations & SCOPE == 0
            }),
            Property::always("P9 restart retains durable prefix and halt", |_, s: &ReplicationState| {
                s.violations & RECOVERY == 0
            }),
            Property::always("P10 rejected deliveries have no effects", |_, s: &ReplicationState| {
                s.violations & REPLAY == 0
            }),
        ];
        for &(name, observation) in WITNESSES {
            // Stateright properties use function pointers, so the individual
            // predicates are supplied below rather than capturing a closure.
            let predicate: fn(&Self, &ReplicationState) -> bool = match observation {
                Observation::Duplicate => |_, s| s.observation == Observation::Duplicate,
                Observation::Stale => |_, s| s.observation == Observation::Stale,
                Observation::Gap => |_, s| s.observation == Observation::Gap,
                Observation::Unfinalized => |_, s| s.observation == Observation::Unfinalized,
                Observation::RestartedHalted => |_, s| s.observation == Observation::RestartedHalted,
                Observation::CatchupAfterRestart => |_, s| s.observation == Observation::CatchupAfterRestart,
                Observation::HaltedOutput => |_, s| s.observation == Observation::HaltedOutput,
                Observation::ActiveSessionHalted => |_, s| s.observation == Observation::ActiveSessionHalted,
                Observation::ActiveSessionFenced => |_, s| s.observation == Observation::ActiveSessionFenced,
                Observation::EpochDivergence => |_, s| s.observation == Observation::EpochDivergence,
                Observation::StaleSession => |_, s| s.observation == Observation::StaleSession,
                Observation::Output { .. } => |_, s| matches!(s.observation, Observation::Output { epoch: 1, .. }),
                Observation::FrozenReleaseRejected => |_, s| s.observation == Observation::FrozenReleaseRejected,
                Observation::None => unreachable!(),
            };
            properties.push(Property::sometimes(name, predicate));
        }
        properties
    }
}

const WITNESSES: &[(&str, Observation)] = &[
    ("reach: duplicate finalized delivery", Observation::Duplicate),
    ("reach: stale finalized replay", Observation::Stale),
    ("reach: gap rejected", Observation::Gap),
    ("reach: unfinalized input rejected", Observation::Unfinalized),
    ("reach: halted issued prefix survives restart", Observation::RestartedHalted),
    ("reach: finalized catchup after restart", Observation::CatchupAfterRestart),
    ("reach: halted signer refuses issued output", Observation::HaltedOutput),
    ("reach: local halt cancels active session", Observation::ActiveSessionHalted),
    ("reach: roster activation fences active session", Observation::ActiveSessionFenced),
    ("reach: divergent roster peers refused", Observation::EpochDivergence),
    ("reach: stale session fenced", Observation::StaleSession),
    ("reach: converged new epoch contributes", Observation::Output { node: 0, epoch: 1 }),
    ("reach: real authority refuses frozen release", Observation::FrozenReleaseRejected),
];

#[derive(Clone, Debug)]
pub struct ReplicationReport {
    pub search: CheckReport,
    /// Single-thread BFS witness paths, sorted in the declared contract order.
    pub witnesses: Vec<(&'static str, Vec<ReplicationAction>)>,
}

pub fn check_replication(depth: usize) -> ReplicationReport {
    use stateright::Checker;
    let checker = ReplicationModel.checker().threads(1).target_max_depth(depth).spawn_bfs().join();
    checker.assert_properties();
    let witnesses = WITNESSES
        .iter()
        .map(|&(name, _)| (name, checker.discovery(name).expect("reachability witness").into_actions()))
        .collect();
    ReplicationReport {
        search: CheckReport {
            max_depth: checker.max_depth(),
            state_count: checker.state_count(),
            unique_state_count: checker.unique_state_count(),
        },
        witnesses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replicated_model_reaches_each_boundary() {
        let report = check_replication(11);
        assert_eq!(report.witnesses.len(), WITNESSES.len());
        // Re-run each externally reported action path through the Model API.
        // A witness must actually satisfy its named public model property.
        for (name, actions) in &report.witnesses {
            assert!(
                ReplicationModel.init_states().into_iter().any(|initial| {
                    let final_state = actions
                        .iter()
                        .try_fold(initial, |state, action| ReplicationModel.next_state(&state, *action));
                    final_state.is_some_and(|state| {
                        ReplicationModel
                            .properties()
                            .iter()
                            .any(|property| property.name == *name && (property.condition)(&ReplicationModel, &state))
                    })
                }),
                "{name}: {actions:?}"
            );
        }
    }
}
