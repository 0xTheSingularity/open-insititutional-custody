//! Durable replay of real simulator calls, including unmined signed submissions.
//! The journal is local development storage, not an independent rollback witness.
use crate::storage::{io, replace};
use oic_adapter_api::SignedTransaction;
use oic_canonical_encoding::sha256;
use oic_chain_simulator::{
    evm::{EvmSimConfig, EvmSimulator},
    solana::{SolanaSimConfig, SolanaSimulator},
    SimClock,
};
use oic_domain_types::*;
use oic_service_broadcaster::{
    ChainClient, Commitment, EvmSimulatorClient, PossiblyIssued, SolanaSimulatorClient,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    Evm,
    Solana,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Receive { amount: Amount },
    FundFees { amount: Amount },
    Advance { blocks: u8 },
    LoseNextSubmissionAck,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub chain: Chain,
    #[serde(flatten)]
    pub action: Action,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Mutation {
    Control(Control),
    Submit { chain: Chain, bytes: Bytes },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub tx_id: Option<ChainTxId>,
    pub lost_ack: bool,
    pub evm_head: Option<StateReference>,
    pub solana_head: Option<StateReference>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    sequence: u64,
    previous: Hash32,
    at: UnixSeconds,
    id: String,
    mutation: Mutation,
    outcome: Outcome,
}

struct Pair {
    evm: Arc<EvmSimulator>,
    solana: Arc<SolanaSimulator>,
    evm_wallet: [u8; 20],
    solana_wallet: [u8; 32],
    fault: [bool; 2],
}
impl Pair {
    fn new(
        genesis: UnixSeconds,
        evm_seed: [u8; 32],
        solana_seed: [u8; 32],
        evm_wallet: [u8; 20],
        solana_wallet: [u8; 32],
    ) -> OicResult<Self> {
        Ok(Self {
            evm: Arc::new(EvmSimulator::new(
                EvmSimConfig::with_seed(evm_seed),
                SimClock::new(genesis),
            )?),
            solana: Arc::new(SolanaSimulator::new(
                SolanaSimConfig::with_seed(solana_seed),
                SimClock::new(genesis),
            )?),
            evm_wallet,
            solana_wallet,
            fault: [false; 2],
        })
    }
    fn apply(&mut self, mutation: &Mutation, at: UnixSeconds) -> OicResult<Outcome> {
        self.evm.clock().set(at)?;
        self.solana.clock().set(at)?;
        let mut result = Outcome::default();
        match mutation {
            Mutation::Control(c) => match c.action {
                Action::Receive { amount } | Action::FundFees { amount } => {
                    if amount.0 == 0 || amount.0 > 100_000_000_000_000_000_000u128 {
                        return Err(OicError::invalid_request(
                            "development funding amount outside bounds",
                        ));
                    }
                    result.tx_id = Some(match c.chain {
                        Chain::Evm => self.evm.fund(self.evm_wallet, amount.0)?,
                        Chain::Solana => self.solana.airdrop(
                            &self.solana_wallet,
                            amount
                                .0
                                .try_into()
                                .map_err(|_| OicError::invalid_request("lamports exceed u64"))?,
                        )?,
                    });
                }
                Action::Advance { blocks } => {
                    if !(1..=64).contains(&blocks) {
                        return Err(OicError::invalid_request("advance requires 1..64 blocks"));
                    }
                    match c.chain {
                        Chain::Evm => {
                            self.evm.mine_blocks(u64::from(blocks))?;
                        }
                        Chain::Solana => {
                            self.solana.advance_slots(u64::from(blocks))?;
                        }
                    }
                }
                Action::LoseNextSubmissionAck => {
                    self.fault[match c.chain {
                        Chain::Evm => 0,
                        Chain::Solana => 1,
                    }] = true
                }
            },
            Mutation::Submit { chain, bytes } => {
                result.tx_id = Some(match chain {
                    Chain::Evm => self.evm.submit(bytes.as_slice())?,
                    Chain::Solana => self.solana.submit(bytes.as_slice())?,
                });
                let index = match chain {
                    Chain::Evm => 0,
                    Chain::Solana => 1,
                };
                result.lost_ack = std::mem::take(&mut self.fault[index]);
            }
        }
        result.evm_head = Some(self.evm.head());
        result.solana_head = Some(self.solana.head());
        Ok(result)
    }
}

struct Journal {
    file: File,
    entries: Vec<Entry>,
    last: Hash32,
    pair: Pair,
    poisoned: bool,
}
pub(crate) struct DurableChains {
    inner: Mutex<Journal>,
    floor: PathBuf,
    genesis: UnixSeconds,
    seeds: ([u8; 32], [u8; 32]),
    wallets: ([u8; 20], [u8; 32]),
}
impl DurableChains {
    pub(crate) fn open(
        path: &Path,
        genesis: UnixSeconds,
        seeds: ([u8; 32], [u8; 32]),
        wallets: ([u8; 20], [u8; 32]),
    ) -> OicResult<Arc<Self>> {
        let floor = path.with_extension("floor");
        let minimum: u64 = if floor.exists() {
            crate::storage::read(&floor)?
        } else {
            0
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(path)
            .map_err(io)?;
        if file.metadata().map_err(io)?.len() > 64 * 1024 * 1024 {
            return Err(io("simulator journal exceeds 64 MiB"));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io)?;
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        let mut pair = Pair::new(genesis, seeds.0, seeds.1, wallets.0, wallets.1)?;
        let mut entries: Vec<Entry> = Vec::new();
        let mut last = Hash32::ZERO;
        for line in bytes[..complete]
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
        {
            let entry: Entry = serde_json::from_slice(line).map_err(io)?;
            if entry.sequence != entries.len() as u64 + 1
                || entry.previous != last
                || entries.iter().any(|e| e.id == entry.id)
            {
                return Err(io("simulator journal sequence/hash/identity mismatch"));
            }
            if pair.apply(&entry.mutation, entry.at)? != entry.outcome {
                return Err(io("simulator replay changed its outcome"));
            }
            last = sha256(line);
            entries.push(entry);
        }
        if (entries.len() as u64) < minimum {
            return Err(io("simulator journal below retained local floor"));
        }
        if complete < bytes.len() {
            file.set_len(complete as u64).map_err(io)?;
            file.sync_all().map_err(io)?;
        }
        replace(&floor, &(entries.len() as u64))?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Journal {
                file,
                entries,
                last,
                pair,
                poisoned: false,
            }),
            floor,
            genesis,
            seeds,
            wallets,
        }))
    }
    fn apply(&self, id: String, mutation: Mutation, at: UnixSeconds) -> OicResult<Outcome> {
        let mut journal = self.inner.lock().map_err(io)?;
        if journal.poisoned {
            return Err(io("journal write/effect was ambiguous; restart required"));
        }
        if let Some(existing) = journal.entries.iter().find(|e| e.id == id) {
            if existing.mutation != mutation {
                return Err(OicError::new(
                    ErrorCode::Conflict,
                    "local command id reused with different contents",
                ));
            }
            return Ok(Outcome {
                lost_ack: false,
                ..existing.outcome.clone()
            });
        }
        let at = at
            .max(journal.pair.evm.clock().now())
            .max(journal.pair.solana.clock().now());
        if journal.entries.len() >= 20_000
            || journal.file.metadata().map_err(io)?.len() > 60 * 1024 * 1024
        {
            return Err(io("development simulator journal capacity reached"));
        }
        // Validate deterministically against a fresh replay before persisting a
        // command. Rejected RPCs must not make the journal unrecoverable.
        let mut scratch = Pair::new(
            self.genesis,
            self.seeds.0,
            self.seeds.1,
            self.wallets.0,
            self.wallets.1,
        )?;
        for e in &journal.entries {
            scratch.apply(&e.mutation, e.at)?;
        }
        let outcome = scratch.apply(&mutation, at)?;
        let entry = Entry {
            sequence: journal.entries.len() as u64 + 1,
            previous: journal.last,
            at,
            id,
            mutation,
            outcome: outcome.clone(),
        };
        let encoded = serde_json::to_vec(&entry).map_err(io)?;
        journal.poisoned = true;
        journal
            .file
            .write_all(&encoded)
            .and_then(|_| journal.file.write_all(b"\n"))
            .and_then(|_| journal.file.sync_all())
            .map_err(io)?;
        replace(&self.floor, &entry.sequence)?;
        if journal.pair.apply(&entry.mutation, entry.at)? != outcome {
            return Err(io("live simulator disagrees with durable replay"));
        }
        journal.last = sha256(&encoded);
        journal.entries.push(entry);
        journal.poisoned = false;
        Ok(outcome)
    }
    pub(crate) fn control(&self, control: Control, at: UnixSeconds) -> OicResult<Outcome> {
        if control.id.is_empty() || control.id.len() > 128 {
            return Err(OicError::invalid_request(
                "local command id must be 1..128 bytes",
            ));
        }
        self.apply(
            format!("operator/{}", control.id),
            Mutation::Control(control),
            at,
        )
    }
    pub(crate) fn simulators(&self) -> OicResult<(Arc<EvmSimulator>, Arc<SolanaSimulator>)> {
        let j = self.inner.lock().map_err(io)?;
        Ok((j.pair.evm.clone(), j.pair.solana.clone()))
    }
    pub(crate) fn tick(&self, now: UnixSeconds) -> OicResult<()> {
        let j = self.inner.lock().map_err(io)?;
        if j.poisoned {
            return Err(io("ambiguous simulator write; restart required"));
        }
        j.pair.evm.clock().set(now)?;
        j.pair.solana.clock().set(now)
    }
    pub(crate) fn client(
        self: &Arc<Self>,
        chain: Chain,
        clock: Arc<dyn oic_authorization_state::Clock>,
    ) -> OicResult<Arc<dyn ChainClient>> {
        let (evm, solana) = self.simulators()?;
        let delegate: Arc<dyn ChainClient> = match chain {
            Chain::Evm => Arc::new(EvmSimulatorClient::new(evm)),
            Chain::Solana => Arc::new(SolanaSimulatorClient::new(solana)),
        };
        Ok(Arc::new(DurableClient {
            journal: self.clone(),
            chain,
            delegate,
            clock,
        }))
    }
}
struct DurableClient {
    journal: Arc<DurableChains>,
    chain: Chain,
    delegate: Arc<dyn ChainClient>,
    clock: Arc<dyn oic_authorization_state::Clock>,
}
impl ChainClient for DurableClient {
    fn network_id(&self) -> NetworkId {
        self.delegate.network_id()
    }
    fn sources(&self) -> Vec<EvidenceSourceId> {
        self.delegate.sources()
    }
    fn submit(&self, signed: &SignedTransaction) -> OicResult<ChainTxId> {
        if signed.signed_bytes.as_slice().len() > 16_384 {
            return Err(OicError::invalid_request(
                "signed transaction exceeds local profile",
            ));
        }
        let result = self.journal.apply(
            format!(
                "submission/{:?}/{}",
                self.chain,
                sha256(signed.signed_bytes.as_slice())
            ),
            Mutation::Submit {
                chain: self.chain,
                bytes: signed.signed_bytes.clone(),
            },
            self.clock.now(),
        )?;
        if result.lost_ack {
            return Err(OicError::new(
                ErrorCode::AuthorityUnavailable,
                "DEVELOPMENT fault: submitted durably but RPC acknowledgement lost",
            ));
        }
        result
            .tx_id
            .ok_or_else(|| OicError::internal("submission missing tx id"))
    }
    fn evidence_for_tx(
        &self,
        source: &EvidenceSourceId,
        tx: &ChainTxId,
        c: Commitment,
    ) -> OicResult<EvidenceBundle> {
        self.delegate.evidence_for_tx(source, tx, c)
    }
    fn evidence_for_candidates(
        &self,
        source: &EvidenceSourceId,
        items: &[PossiblyIssued],
        c: Commitment,
    ) -> OicResult<EvidenceBundle> {
        self.delegate.evidence_for_candidates(source, items, c)
    }
    fn head(&self) -> StateReference {
        self.delegate.head()
    }
    fn finalized(&self) -> StateReference {
        self.delegate.finalized()
    }
}
