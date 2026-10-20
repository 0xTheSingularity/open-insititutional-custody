//! Chain clients: the broadcast target and the evidence sources of one network.
//!
//! A client names one or more [`EvidenceSourceId`]s. The broadcaster fetches
//! the same evidence from every source and cross-checks the adapter's
//! observations; disagreement is a `Conflict` that quarantines the family
//! (RFC 0001 §12.3, A30). Two endpoints of one provider may share a failure
//! domain; the source list is a declaration, not a proof of independence.

use oic_adapter_api::SignedTransaction;
use oic_adapter_evm::recover_address;
use oic_adapter_evm::tx::{tx_hash, EvmTx};
use oic_adapter_solana::message::Transaction as SolanaTransaction;
use oic_chain_simulator::evm::{EvmEvidenceQuery, EvmSimulator, SOURCE_ID as EVM_SOURCE_ID};
use oic_chain_simulator::solana::{SolanaEvidenceQuery, SolanaSimulator, SOURCE_ID as SOLANA_SOURCE_ID};
use oic_domain_types::*;
use std::sync::Arc;

/// Which view of the chain an evidence bundle is anchored at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commitment {
    /// Head / processed view.
    Latest,
    /// The profile's finality view; only this may produce `Finalized`.
    Finalized,
}

/// A candidate that may have produced a signature, with its signed bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PossiblyIssued {
    pub candidate: Candidate,
    pub signed: SignedTransaction,
}

/// Broadcast target and evidence provider for one network.
pub trait ChainClient: Send + Sync {
    fn network_id(&self) -> NetworkId;
    /// Evidence sources this client can query; never empty.
    fn sources(&self) -> Vec<EvidenceSourceId>;
    /// Hand signed bytes to the network. `Ok` is an acknowledgement, not inclusion (I10).
    fn submit(&self, signed: &SignedTransaction) -> OicResult<ChainTxId>;
    /// Evidence about one transaction id from one source.
    fn evidence_for_tx(&self, source: &EvidenceSourceId, tx_id: &ChainTxId, commitment: Commitment) -> OicResult<EvidenceBundle>;
    /// Evidence for `ChainAdapter::prove_invalidation` over possibly issued candidates.
    fn evidence_for_candidates(&self, source: &EvidenceSourceId, candidates: &[PossiblyIssued], commitment: Commitment) -> OicResult<EvidenceBundle>;
    fn head(&self) -> StateReference;
    fn finalized(&self) -> StateReference;
}

fn check_source(sources: &[EvidenceSourceId], source: &EvidenceSourceId) -> OicResult<()> {
    if sources.contains(source) {
        Ok(())
    } else {
        Err(OicError::invalid_request(format!("evidence source {source} is not configured for this client")))
    }
}

fn non_empty(sources: Vec<EvidenceSourceId>) -> OicResult<Vec<EvidenceSourceId>> {
    if sources.is_empty() {
        return Err(OicError::invalid_request("a chain client needs at least one evidence source"));
    }
    Ok(sources)
}

/// Client for the development EVM simulator.
pub struct EvmSimulatorClient {
    sim: Arc<EvmSimulator>,
    sources: Vec<EvidenceSourceId>,
}

impl EvmSimulatorClient {
    /// Single honest source.
    pub fn new(sim: Arc<EvmSimulator>) -> Self {
        EvmSimulatorClient { sim, sources: vec![EvidenceSourceId::unchecked(EVM_SOURCE_ID)] }
    }

    /// Cross-checked sources (each read through `evidence_from`).
    pub fn with_sources(sim: Arc<EvmSimulator>, sources: Vec<EvidenceSourceId>) -> OicResult<Self> {
        Ok(EvmSimulatorClient { sim, sources: non_empty(sources)? })
    }

    fn query(commitment: Commitment) -> EvmEvidenceQuery {
        match commitment {
            Commitment::Latest => EvmEvidenceQuery::latest(),
            Commitment::Finalized => EvmEvidenceQuery::finalized(),
        }
    }
}

impl ChainClient for EvmSimulatorClient {
    fn network_id(&self) -> NetworkId {
        self.sim.profile().network_id
    }
    fn sources(&self) -> Vec<EvidenceSourceId> {
        self.sources.clone()
    }
    fn submit(&self, signed: &SignedTransaction) -> OicResult<ChainTxId> {
        self.sim.submit(signed.signed_bytes.as_slice())
    }
    fn evidence_for_tx(&self, source: &EvidenceSourceId, tx_id: &ChainTxId, commitment: Commitment) -> OicResult<EvidenceBundle> {
        check_source(&self.sources, source)?;
        self.sim.evidence_from(source, &Self::query(commitment).tx_id(tx_id)?)
    }
    fn evidence_for_candidates(&self, source: &EvidenceSourceId, candidates: &[PossiblyIssued], commitment: Commitment) -> OicResult<EvidenceBundle> {
        check_source(&self.sources, source)?;
        let mut q = Self::query(commitment);
        for c in candidates {
            let bytes = c.signed.signed_bytes.as_slice();
            let (tx, sig) = EvmTx::decode_signed(bytes)?;
            let sender = recover_address(&tx.signing_digest(), &sig)?;
            q = q.sender(sender).tx(tx_hash(bytes)).signed(c.candidate.candidate_id.as_str(), c.candidate.candidate_revision, bytes.to_vec());
        }
        self.sim.evidence_from(source, &q)
    }
    fn head(&self) -> StateReference {
        self.sim.head()
    }
    fn finalized(&self) -> StateReference {
        self.sim.finalized()
    }
}

/// Client for the development Solana simulator.
pub struct SolanaSimulatorClient {
    sim: Arc<SolanaSimulator>,
    sources: Vec<EvidenceSourceId>,
}

impl SolanaSimulatorClient {
    pub fn new(sim: Arc<SolanaSimulator>) -> Self {
        SolanaSimulatorClient { sim, sources: vec![EvidenceSourceId::unchecked(SOLANA_SOURCE_ID)] }
    }

    pub fn with_sources(sim: Arc<SolanaSimulator>, sources: Vec<EvidenceSourceId>) -> OicResult<Self> {
        Ok(SolanaSimulatorClient { sim, sources: non_empty(sources)? })
    }

    fn query(commitment: Commitment) -> SolanaEvidenceQuery {
        match commitment {
            Commitment::Latest => SolanaEvidenceQuery::processed(),
            Commitment::Finalized => SolanaEvidenceQuery::finalized(),
        }
    }
}

impl ChainClient for SolanaSimulatorClient {
    fn network_id(&self) -> NetworkId {
        self.sim.profile().network_id
    }
    fn sources(&self) -> Vec<EvidenceSourceId> {
        self.sources.clone()
    }
    fn submit(&self, signed: &SignedTransaction) -> OicResult<ChainTxId> {
        self.sim.submit(signed.signed_bytes.as_slice())
    }
    fn evidence_for_tx(&self, source: &EvidenceSourceId, tx_id: &ChainTxId, commitment: Commitment) -> OicResult<EvidenceBundle> {
        check_source(&self.sources, source)?;
        self.sim.evidence_from(source, &Self::query(commitment).tx_id(tx_id)?)
    }
    fn evidence_for_candidates(&self, source: &EvidenceSourceId, candidates: &[PossiblyIssued], commitment: Commitment) -> OicResult<EvidenceBundle> {
        check_source(&self.sources, source)?;
        let mut q = Self::query(commitment);
        for c in candidates {
            let bytes = c.signed.signed_bytes.as_slice();
            let tx = SolanaTransaction::decode(bytes)?;
            for sig in &tx.signatures {
                q = q.signature(*sig);
            }
            q = q.blockhash(tx.message.recent_blockhash).signed(c.candidate.candidate_id.as_str(), c.candidate.candidate_revision, bytes.to_vec());
        }
        self.sim.evidence_from(source, &q)
    }
    fn head(&self) -> StateReference {
        self.sim.head()
    }
    fn finalized(&self) -> StateReference {
        self.sim.finalized()
    }
}
