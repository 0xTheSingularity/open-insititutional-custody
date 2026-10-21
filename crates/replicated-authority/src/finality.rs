use crate::{AuthorityBlock, Command, ConsensusContext, Executor, ReplicatedState};
use commonware_codec::DecodeExt;
use commonware_consensus::{
    Block, CertifiableBlock, Epochable, Heightable, Viewable,
    simplex::{scheme::ed25519::Scheme, types::Finalization},
    types::{Epoch, Height},
};
use commonware_cryptography::{
    Digestible, Signer,
    certificate::Scheme as _,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::{TryFromIterator, ordered::Set};
use oic_canonical_encoding::canonical_bytes;
use oic_domain_types::*;
use oic_membership::{AdminTrust, CommitteeKind, SignedRoster, validate_roster};
use rand_core_commonware::CryptoRng;

pub type AuthorityFinalization = Finalization<Scheme, Digest>;

/// Independently authenticated initial D2 committee. This initial profile does
/// not change committees in place: an epoch change must halt and be reconfigured
/// from an independently authenticated ordered activation, never peer input.
#[derive(Clone)]
pub struct FinalityTrust {
    roster: SignedRoster,
    namespace: Vec<u8>,
    scheme: Scheme,
}

impl FinalityTrust {
    pub fn from_genesis(
        roster: SignedRoster,
        admins: &AdminTrust,
        institution: &InstitutionId,
        environment: &EnvironmentId,
        expected_genesis: Hash32,
        now: UnixSeconds,
    ) -> OicResult<Self> {
        validate_roster(&roster, admins, institution, environment, None, now, expected_genesis)?;
        let committees: Vec<_> =
            roster.body.committees.iter().filter(|committee| matches!(committee.kind, CommitteeKind::AuthorityD2 { .. })).collect();
        if committees.len() != 1 {
            return Err(OicError::invalid_request("D2 requires exactly one ordered authority committee"));
        }
        let keys = committees[0]
            .members
            .iter()
            .map(|node_id| {
                let key = roster
                    .node(node_id)
                    .and_then(|node| node.consensus_key.as_ref())
                    .ok_or_else(|| OicError::invalid_request("replica vote key absent"))?;
                PublicKey::decode(key.bytes.as_slice()).map_err(|_| OicError::invalid_request("invalid replica vote key"))
            })
            .collect::<OicResult<Vec<_>>>()?;
        let participants = Set::try_from_iter(keys).map_err(|_| OicError::invalid_request("duplicate replica vote key"))?;
        let mut namespace = b"OIC/SIMPLEX/v1".to_vec();
        namespace.extend(canonical_bytes(&(institution, environment, expected_genesis))?);
        let scheme = Scheme::verifier(&namespace, participants);
        Ok(Self { roster, namespace, scheme })
    }

    pub fn epoch(&self) -> Epoch {
        Epoch::new(self.roster.body.roster_epoch)
    }

    pub fn roster_hash(&self) -> OicResult<Hash32> {
        oic_membership::roster_hash(&self.roster.body)
    }

    /// Follower-only scheme contains no private key. Replicas need their own
    /// distinct vote key, and must never substitute a D1 receipt key here.
    pub fn verifier(&self) -> Scheme {
        self.scheme.clone()
    }

    pub fn signer(&self, node_id: &NodeId, key: PrivateKey) -> OicResult<Scheme> {
        let enrolled = self
            .roster
            .node(node_id)
            .and_then(|node| node.consensus_key.as_ref())
            .ok_or_else(|| OicError::new(ErrorCode::PeerNotAdmitted, "node is not an enrolled replica"))?;
        if key.public_key().as_ref() != enrolled.bytes.as_slice() {
            return Err(OicError::scope("vote key differs from enrolled replica"));
        }
        Scheme::signer(&self.namespace, self.scheme.participants().clone(), key).ok_or_else(|| OicError::scope("vote key is outside committee"))
    }

    pub fn verify<R: CryptoRng>(&self, rng: &mut R, block: &AuthorityBlock, finalization: &AuthorityFinalization) -> OicResult<()> {
        let context = block.context();
        if finalization.epoch() != self.epoch()
            || context.epoch() != self.epoch()
            || finalization.proposal.round != context.round
            || finalization.proposal.parent != context.parent.0
            || finalization.proposal.payload != block.digest()
            || !finalization.verify(rng, &self.scheme, &Sequential)
        {
            return Err(OicError::invalid_signature("finalization does not authenticate this block in the active epoch"));
        }
        Ok(())
    }
}

impl Executor {
    /// Build against the exact dependency supplied by consensus, which may be
    /// ahead of or different from this replica's currently finalized tip.
    pub fn propose_block(
        &self,
        parent: &AuthorityBlock,
        state: ReplicatedState,
        context: ConsensusContext,
        commands: &[Command],
        timestamp: UnixSeconds,
        local_now: UnixSeconds,
    ) -> OicResult<(AuthorityBlock, ReplicatedState)> {
        self.check_parent(parent, &state, &context, timestamp, local_now)?;
        let (state, _, _) = self.execute(state, commands, timestamp)?;
        let height = parent.height().get().checked_add(1).ok_or_else(|| OicError::invalid_request("block height exhausted"))?;
        Ok((AuthorityBlock::new(context, Height::new(height), timestamp, self.state_hash(&state)?, commands)?, state))
    }

    /// Re-execute every command; never accept the proposed post-state on trust.
    pub fn verify_block(
        &self,
        parent: &AuthorityBlock,
        state: ReplicatedState,
        context: &ConsensusContext,
        block: &AuthorityBlock,
        local_now: UnixSeconds,
    ) -> OicResult<ReplicatedState> {
        self.check_parent(parent, &state, context, block.timestamp(), local_now)?;
        if &block.context() != context || block.parent() != parent.digest() || parent.height().get().checked_add(1) != Some(block.height().get()) {
            return Err(OicError::unverifiable("block context, parent or height mismatch"));
        }
        let (state, _, _) = self.execute(state, &block.commands()?, block.timestamp())?;
        if block.state_hash() != self.state_hash(&state)? {
            return Err(OicError::unverifiable("proposed post-state differs from local execution"));
        }
        Ok(state)
    }

    fn check_parent(
        &self,
        parent: &AuthorityBlock,
        state: &ReplicatedState,
        context: &ConsensusContext,
        timestamp: UnixSeconds,
        local_now: UnixSeconds,
    ) -> OicResult<()> {
        if parent.state_hash() != self.state_hash(state)?
            || context.parent.1 != parent.digest()
            || context.parent.0 != parent.context().view()
            || context.view() <= context.parent.0
            || context.epoch() != parent.context().epoch()
        {
            return Err(OicError::unverifiable("proposal dependency differs from supplied parent state"));
        }
        if timestamp < parent.timestamp() || timestamp.0 > local_now.0.saturating_add(self.authority.max_clock_skew_seconds) {
            return Err(OicError::stale_evidence("block time regressed or exceeds local skew bound"));
        }
        Ok(())
    }
}
