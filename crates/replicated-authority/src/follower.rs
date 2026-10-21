use crate::{AuthorityBlock, AuthorityFinalization, Executor, FinalityTrust, ReplicatedState};
use commonware_codec::{Decode, DecodeExt, Encode};
use commonware_consensus::{CertifiableBlock, Epochable, Heightable};
use commonware_cryptography::{Digestible, certificate::Verifier as _};
use commonware_runtime::{BufferPooler, Metrics, ReadOptions, Storage, buffer::paged::CacheRef};
use commonware_storage::journal::segmented::variable::{Config, Journal};
use commonware_utils::{NZU16, NZUsize};
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes};
use oic_domain_types::*;
use rand_core_commonware::CryptoRng;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

// Match the canonical decoder's bound, including an ancestry checkpoint.
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_CHECKPOINT_BLOCKS: usize = 256;

/// Keep this outside the follower's rollback domain. Genesis is an explicit
/// first installation, not a fallback when recovering a lost journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedFloor {
    pub height: u64,
    pub digest: Hash32,
}

impl FinalizedFloor {
    pub fn at(block: &AuthorityBlock) -> Self {
        Self {
            height: block.height().get(),
            digest: Hash32::from_slice(block.digest().as_ref()).expect("SHA256 digest"),
        }
    }
}

/// Provisioned independently, never accepted from the peer serving the log.
pub struct FollowerConfig {
    pub partition: String,
    pub executor: Executor,
    pub trust: FinalityTrust,
    pub genesis: AuthorityBlock,
    pub genesis_state: ReplicatedState,
    pub minimum_floor: FinalizedFloor,
    pub local_now: UnixSeconds,
}

/// Confidential, portable evidence, not a serialized VerifiedLog capability.
/// Readers must authenticate the certificate and re-execute every linked block.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedEntry {
    pub block: Bytes,
    pub finalization: Bytes,
    // Old single-block entries retain their exact encoding. A checkpoint's
    // certificate authenticates block and, through parent hashes, ancestors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ancestors: Vec<Bytes>,
}

/// One bounded journal checkpoint per page. `tip` certifies this page, not an
/// unsigned remote head. Continue from its verified floor while `more` is true.
#[derive(Serialize)]
pub struct FinalizedPage {
    pub entries: Vec<FinalizedEntry>,
    pub tip: FinalizedEntry,
    pub more: bool,
}

/// A single-writer, keyless finalization consumer. Journal replay verifies real
/// Simplex certificates and re-executes the full contiguous prefix from genesis.
/// I/O error or cancellation while appending poisons the instance: reopen with
/// the independently retained floor, never retry an ambiguous write in place.
pub struct Follower<E: Storage + Metrics> {
    journal: Option<Journal<E, Vec<u8>>>,
    executor: Executor,
    trust: FinalityTrust,
    tip: AuthorityBlock,
    state: ReplicatedState,
    finalization: Option<AuthorityFinalization>,
    anchor: LogAnchor,
    // Marshal may redeliver the last synced checkpoint before its individual
    // acknowledgements catch up, including after restart. Earlier checkpoints
    // must already have been acknowledged before this one could be delivered.
    checkpoint: BTreeMap<u64, commonware_cryptography::sha256::Digest>,
    // Derived from verified journal records, rebuilt on open. Values are byte
    // offsets, not duplicated confidential bodies or a second durable store.
    history: BTreeMap<u64, u64>,
}

impl<E: Storage + Metrics + BufferPooler> Follower<E> {
    pub async fn open<R: CryptoRng>(
        context: E,
        config: FollowerConfig,
        rng: &mut R,
    ) -> OicResult<Self> {
        let FollowerConfig {
            partition,
            executor,
            trust,
            genesis,
            genesis_state,
            minimum_floor,
            local_now,
        } = config;
        if !genesis.height().is_zero()
            || !genesis.commands()?.is_empty()
            || genesis.context().epoch() != trust.epoch()
            || genesis.state_hash() != executor.state_hash(&genesis_state)?
        {
            return Err(recovery("invalid independently provisioned genesis"));
        }
        check_floor(minimum_floor, FinalizedFloor::at(&genesis))?;
        let anchor = LogAnchor {
            genesis: FinalizedFloor::at(&genesis).digest,
            roster: trust.roster_hash()?,
        };
        let cache = CacheRef::from_pooler(&context, NZU16!(4096), NZUsize!(16));
        let journal = Journal::<E, Vec<u8>>::init(
            context,
            Config {
                partition,
                compression: None,
                codec_config: ((..=MAX_RECORD_BYTES).into(), ()),
                page_cache: cache,
                write_buffer: NZUsize!(65536),
            },
        )
        .await
        .map_err(storage)?;
        let mut replay = journal
            .replay(0, 0, NZUsize!(65536), ReadOptions::DONT_CACHE)
            .await
            .map_err(storage)?;
        let mut tip = genesis;
        let mut state = genesis_state;
        let mut latest_finalization = None;
        let mut checkpoint = BTreeMap::new();
        let mut history = BTreeMap::new();
        while let Some(record) = replay.next().await {
            let (section, offset, _, bytes) = record.map_err(storage)?;
            if section != 0 {
                return Err(recovery("unexpected finalized journal section"));
            }
            let entry: FinalizedEntry = from_canonical_bytes(&bytes)?;
            let block = AuthorityBlock::decode(entry.block.as_slice())
                .map_err(|_| recovery("invalid persisted block"))?;
            let finalization = AuthorityFinalization::decode_cfg(
                entry.finalization.as_slice(),
                &trust.verifier().certificate_codec_config(),
            )
            .map_err(|_| recovery("invalid persisted finalization"))?;
            trust.verify(rng, &block, &finalization)?;
            if entry.ancestors.len() >= MAX_CHECKPOINT_BLOCKS {
                return Err(recovery("finalized ancestry exceeds checkpoint bound"));
            }
            checkpoint.clear();
            for bytes in entry.ancestors {
                let ancestor = AuthorityBlock::decode(bytes.as_slice())
                    .map_err(|_| recovery("invalid persisted ancestor"))?;
                state = executor.verify_block(
                    &tip,
                    state,
                    &ancestor.context(),
                    &ancestor,
                    local_now,
                )?;
                check_floor(minimum_floor, FinalizedFloor::at(&ancestor))?;
                checkpoint.insert(ancestor.height().get(), ancestor.digest());
                tip = ancestor;
            }
            state = executor.verify_block(&tip, state, &block.context(), &block, local_now)?;
            check_floor(minimum_floor, FinalizedFloor::at(&block))?;
            checkpoint.insert(block.height().get(), block.digest());
            tip = block;
            latest_finalization = Some(finalization);
            history.insert(tip.height().get(), offset);
        }
        if tip.height().get() < minimum_floor.height {
            return Err(recovery(
                "finalized history below independently retained floor",
            ));
        }
        let journal = replay.finish().map_err(storage)?;
        Ok(Self {
            journal: Some(journal),
            executor,
            trust,
            tip,
            state,
            finalization: latest_finalization,
            anchor,
            checkpoint,
            history,
        })
    }

    /// No notarization overload exists. An authentic finalization still needs
    /// correct parent/height, local native re-execution and the claimed state root.
    /// Returns true only after the verified block has synced; false is an exact
    /// repeat of the current finalized tip and never re-executes issuance.
    pub async fn apply_finalized<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        block: AuthorityBlock,
        finalization: AuthorityFinalization,
        local_now: UnixSeconds,
    ) -> OicResult<bool> {
        self.apply_finalized_chain(rng, vec![block], finalization, local_now)
            .await
    }

    /// Authenticate a descendant's genuine certificate, then re-execute its
    /// entire contiguous ancestry. No intermediate state becomes a capability:
    /// the full checkpoint syncs atomically before publishing the certified tip.
    pub async fn apply_finalized_chain<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        mut blocks: Vec<AuthorityBlock>,
        finalization: AuthorityFinalization,
        local_now: UnixSeconds,
    ) -> OicResult<bool> {
        if self.journal.is_none() {
            return Err(recovery("follower storage requires reopen"));
        }
        if blocks.is_empty() || blocks.len() > MAX_CHECKPOINT_BLOCKS {
            return Err(OicError::invalid_request(
                "finalized ancestry outside checkpoint bound",
            ));
        }
        let block = blocks.pop().expect("nonempty checkpoint");
        self.trust.verify(rng, &block, &finalization)?;
        if blocks.is_empty() && block.digest() == self.tip.digest() {
            return Ok(false);
        }
        let bytes = canonical_bytes(&FinalizedEntry {
            ancestors: blocks
                .iter()
                .map(|ancestor| ancestor.encode().to_vec().into())
                .collect(),
            block: block.encode().to_vec().into(),
            finalization: finalization.encode().to_vec().into(),
        })?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(OicError::invalid_request(
                "finalized journal record exceeds bound",
            ));
        }
        let mut parent = &self.tip;
        let mut state = self.state.clone();
        let mut checkpoint = BTreeMap::new();
        for child in blocks.iter().chain(std::iter::once(&block)) {
            state =
                self.executor
                    .verify_block(parent, state, &child.context(), child, local_now)?;
            checkpoint.insert(child.height().get(), child.digest());
            parent = child;
        }
        let journal = self
            .journal
            .take()
            .ok_or_else(|| recovery("follower requires reopen"))?;
        let (journal, offset, _) = journal.append(0, &bytes).await.map_err(storage)?;
        self.journal = Some(journal.sync_all().await.map_err(storage)?);
        self.tip = block;
        self.state = state;
        self.finalization = Some(finalization);
        self.checkpoint = checkpoint;
        self.history.insert(self.tip.height().get(), offset);
        Ok(true)
    }

    /// Read only synced history. The supplied cursor must match the exact
    /// block, including a floor inside a descendant-certified checkpoint.
    /// Each read is bounded to two existing records; it never replays, consumes
    /// or repairs the journal, and never changes the signing capability.
    pub async fn read_page(&self, after: FinalizedFloor) -> OicResult<FinalizedPage> {
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| recovery("follower storage requires reopen"))?;
        let certificate = self
            .finalization
            .as_ref()
            .ok_or_else(|| recovery("no synced finalization"))?;
        if after.height > self.tip.height().get()
            || (after.height == 0 && after.digest != self.anchor.genesis)
        {
            return Err(recovery("finalized log cursor is outside this history"));
        }
        if after == self.floor() {
            return Ok(FinalizedPage {
                entries: Vec::new(),
                tip: FinalizedEntry {
                    block: self.tip.encode().to_vec().into(),
                    finalization: certificate.encode().to_vec().into(),
                    ancestors: Vec::new(),
                },
                more: false,
            });
        }
        let (&height, &offset) = self
            .history
            .range(after.height..)
            .next()
            .ok_or_else(|| recovery("finalized cursor record missing"))?;
        let mut entry: FinalizedEntry =
            from_canonical_bytes(&journal.get(0, offset).await.map_err(storage)?)?;
        if after.height > 0 {
            let mut matched = false;
            for bytes in entry.ancestors.iter().chain(std::iter::once(&entry.block)) {
                let block = AuthorityBlock::decode(bytes.as_slice())
                    .map_err(|_| recovery("invalid indexed block"))?;
                if block.height().get() == after.height {
                    matched = FinalizedFloor::at(&block) == after;
                    break;
                }
            }
            if !matched {
                return Err(recovery(
                    "finalized cursor digest differs from synced history",
                ));
            }
        }
        let page_height = if height == after.height {
            let (&height, &offset) = self
                .history
                .range((
                    std::ops::Bound::Excluded(height),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .ok_or_else(|| recovery("finalized suffix record missing"))?;
            entry = from_canonical_bytes(&journal.get(0, offset).await.map_err(storage)?)?;
            height
        } else {
            height
        };
        let mut ancestors = Vec::new();
        for bytes in entry.ancestors {
            let block = AuthorityBlock::decode(bytes.as_slice())
                .map_err(|_| recovery("invalid indexed ancestor"))?;
            if block.height().get() > after.height {
                ancestors.push(bytes);
            }
        }
        entry.ancestors = ancestors;
        let tip = FinalizedEntry {
            ancestors: Vec::new(),
            ..entry.clone()
        };
        Ok(FinalizedPage {
            entries: vec![entry],
            tip,
            more: page_height < self.tip.height().get(),
        })
    }

    pub(crate) fn checkpoint_contains(&self, block: &AuthorityBlock) -> bool {
        self.checkpoint.get(&block.height().get()) == Some(&block.digest())
    }

    pub fn floor(&self) -> FinalizedFloor {
        FinalizedFloor::at(&self.tip)
    }

    pub fn state(&self) -> &ReplicatedState {
        &self.state
    }

    pub fn finalization(&self) -> Option<&AuthorityFinalization> {
        self.finalization.as_ref()
    }

    /// A process-local capability, minted only after authenticated contiguous
    /// re-execution and journal sync. Never decode a peer's claimed state into
    /// this type. Consumers pin both anchors and retain a rollback floor.
    pub fn verified_log(&self) -> OicResult<VerifiedLog> {
        if self.journal.is_none() || self.finalization.is_none() {
            return Err(recovery("no healthy synced finalized log"));
        }
        Ok(VerifiedLog {
            anchor: self.anchor,
            floor: self.floor(),
            timestamp: self.tip.timestamp(),
            state: Arc::new(self.state.clone()),
        })
    }

    pub fn tip(&self) -> &AuthorityBlock {
        &self.tip
    }
}

/// Independently provisioned signer/light-client pins. The genesis digest
/// commits execution configuration; the roster hash pins the certificate keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogAnchor {
    pub genesis: Hash32,
    pub roster: Hash32,
}

/// Not serializable or publicly constructible. An arbitrary `ReplicatedState`,
/// proposal, notarization or watch snapshot cannot grant signing authority.
///
/// ```compile_fail,E0599
/// use oic_replicated_authority::VerifiedLog;
/// let claimed = VerifiedLog::default();
/// ```
#[derive(Clone)]
pub struct VerifiedLog {
    anchor: LogAnchor,
    floor: FinalizedFloor,
    timestamp: UnixSeconds,
    state: Arc<ReplicatedState>,
}

impl VerifiedLog {
    pub fn anchor(&self) -> LogAnchor {
        self.anchor
    }
    pub fn floor(&self) -> FinalizedFloor {
        self.floor
    }
    pub fn timestamp(&self) -> UnixSeconds {
        self.timestamp
    }

    /// Current ordered enrollment, not a coordinator-supplied credential list.
    pub fn approvers(&self) -> Vec<oic_approval_verifier::ApproverCredential> {
        self.state
            .authority
            .ordered_approvals
            .as_ref()
            .into_iter()
            .flat_map(|ordered| {
                ordered
                    .credentials
                    .values()
                    .filter_map(|entry| entry.credential.clone())
            })
            .collect()
    }

    /// D2 starts signing only after the exact Release is finalized. A reserve
    /// alone is insufficient even for allocating a backend signing session.
    pub fn authorize(&self, body: &AuthorizationEnvelopeBody) -> OicResult<&IssuanceRecord> {
        let proof = self
            .state
            .reservations
            .get(&body.budget_reservation_id)
            .ok_or_else(|| {
                OicError::new(ErrorCode::NotFound, "finalized native reservation absent")
            })?;
        let record = self
            .state
            .authority
            .reservations
            .get(&body.budget_reservation_id)
            .ok_or_else(|| OicError::new(ErrorCode::NotFound, "finalized reservation absent"))?;
        if proof.envelope != *body
            || record.envelope_body_hash
                != oic_canonical_encoding::domain_hash(domains::AUTHORIZATION, body)?
            || record.signer_session_id != body.signer_session_id
        {
            return Err(OicError::scope(
                "finalized reservation differs from signing envelope",
            ));
        }
        let oic_authorization_state::ReservationState::Released { issuance_id } = &record.state
        else {
            return Err(OicError::new(
                ErrorCode::SessionRejected,
                "no finalized unresolved release for this reservation",
            ));
        };
        self.state
            .authority
            .issuance
            .get(issuance_id)
            .ok_or_else(|| recovery("finalized issuance absent"))
    }
}

fn check_floor(expected: FinalizedFloor, actual: FinalizedFloor) -> OicResult<()> {
    if expected.height == actual.height && expected.digest != actual.digest {
        return Err(recovery("finalized history differs at independent floor"));
    }
    Ok(())
}

fn recovery(detail: &str) -> OicError {
    OicError::new(ErrorCode::RecoveryRequired, detail)
}

fn storage(error: impl std::fmt::Display) -> OicError {
    OicError::new(
        ErrorCode::AuthorityUnavailable,
        format!("finalized journal: {error}"),
    )
}
