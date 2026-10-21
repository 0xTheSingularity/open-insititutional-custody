//! Simulated EVM chain — DEVELOPMENT ONLY.
//!
//! Model:
//!
//! * Accounts `{balance, nonce, code}`. A simulator-held faucet EOA (key derived
//!   from the configured seed) owns [`FAUCET_GENESIS_BALANCE`] at genesis.
//! * Transactions: signed EIP-1559 type-2 and EIP-155 legacy, decoded with the
//!   pinned adapter decoder ([`oic_adapter_evm::tx::EvmTx`]); the sender is
//!   recovered with [`oic_adapter_evm::recover_address`] (low-s enforced).
//!   Non-empty access lists are refused (not modelled).
//! * Submission is an RPC acknowledgement into the mempool, never inclusion (I10).
//!   Admission rules: chain id matches; not a duplicate hash; nonce must equal
//!   the sender's next nonce (account nonce plus contiguous pending nonces) or
//!   replace a pending transaction with the same `(sender, nonce)`; replacement
//!   requires the new priority fee to be strictly higher **and** at least
//!   [`REPLACEMENT_BUMP_PERCENT`]% above the pending one's; `max_fee_per_gas >=
//!   base_fee`; `balance >= Σ pending (value + gas_limit * max_fee) + this`.
//!   A transaction whose nonce is already consumed is refused with
//!   `ResourceConflict`, but remembered so that later evidence reports which
//!   transaction consumed its nonce (`nonce_consumed_by`).
//! * [`EvmSimulator::mine`] includes every includable mempool transaction,
//!   per sender in nonce order, across senders in arrival order. A pending
//!   transaction whose fee cap is below the current base fee (fee spike, C10)
//!   or whose sender cannot cover its worst case stays pending.
//! * Execution: effective gas price `min(max_fee, base_fee + priority)` (legacy:
//!   `gas_price`); charged `gas_used * effective`. Gas used: [`GAS_NATIVE_TRANSFER`]
//!   for a transfer to an account without code (any calldata to an EOA is
//!   ignored), [`GAS_ERC20_TRANSFER`] for a successful registered ERC-20
//!   `transfer(address,uint256)`, [`GAS_REVERTED_CALL`] for a revert, and the
//!   whole `gas_limit` when an ERC-20 transfer is sent with a gas limit below
//!   [`GAS_ERC20_TRANSFER`] (out of gas). Reverts: non-`transfer` calldata or
//!   non-zero value to a token, insufficient token balance, any call to code
//!   that is not a registered token. A revert moves no value and no tokens.
//! * Successful ERC-20 transfers emit `Transfer(address indexed, address indexed,
//!   uint256)` logs.
//! * **Not modelled (declared per RFC 0002 §4):** contract-internal native
//!   movements (there is no general EVM; native inflows are discoverable only
//!   from included transactions' `to` + `value`), contract creation
//!   transactions (denied by the adapter decoder anyway), access lists,
//!   calldata gas, refunds, and base-fee adjustment by block fullness (the base
//!   fee changes only through [`EvmSimulator::set_fees`]).
//! * Setup operations ([`EvmSimulator::deploy_erc20`], [`EvmSimulator::install_code`])
//!   are *system operations*: they take effect at once for submission and
//!   query methods, and are recorded in (and visible to evidence from) the
//!   next mined block. Reorgs replay them.
//! * Query methods read the head working state; evidence reads produced blocks only.

use crate::clock::SimClock;
use crate::{checked, lock, sha256_parts, EVIDENCE_MAX_STALENESS_SECONDS, PROFILE_MAX_EVIDENCE_AGE_SECONDS, VERIFIER_VERSION};
use k256::ecdsa::SigningKey;
use oic_adapter_api::ChainProfile;
use oic_adapter_evm::address::{address_from_sec1, keccak256, Address};
use oic_adapter_evm::calldata;
use oic_adapter_evm::evidence::{code_key, nonce_key, signed_tx_key, tx_key, TxObservation, KEY_BASE_FEE, KEY_CHAIN_ID, KEY_GAS_LIMIT, KEY_PRIORITY_FEE};
use oic_adapter_evm::tx::{tx_hash, Eip1559Tx, EvmTx, RawSignature};
use oic_adapter_evm::{network_binding_for_chain_id, recover_address, ADAPTER_ID, VERSION_TYPE2};
use oic_domain_types::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

pub const DEFAULT_CHAIN_ID: u64 = 31_337;
pub const CHAIN_PROFILE_ID: &str = "evm-devsim-v1";
/// Honest evidence source id.
pub const SOURCE_ID: &str = "devsim-evm";
pub const DEFAULT_FINALITY_DEPTH: u64 = 2;
pub const FINALITY_COMMITMENT: &str = "finalized";
pub const LATEST_COMMITMENT: &str = "latest";
pub const GAS_NATIVE_TRANSFER: u64 = 21_000;
pub const GAS_ERC20_TRANSFER: u64 = 51_000;
pub const GAS_REVERTED_CALL: u64 = 21_000;
/// 1 gwei.
pub const DEFAULT_BASE_FEE: u128 = 1_000_000_000;
/// 0.1 gwei.
pub const DEFAULT_PRIORITY_FEE: u128 = 100_000_000;
/// Gas-limit estimate published as evidence (covers an ERC-20 transfer).
pub const DEFAULT_GAS_LIMIT: u64 = 65_000;
/// 10^9 ETH in wei.
pub const FAUCET_GENESIS_BALANCE: u128 = 1_000_000_000_000_000_000_000_000_000;
/// Fixed non-empty code installed at every simulated ERC-20 address.
pub const ERC20_CODE_MARKER: &[u8] = b"OIC-DEVSIM-ERC20/v1 transfer(address,uint256)";
/// Minimum priority-fee bump for a same-nonce mempool replacement.
pub const REPLACEMENT_BUMP_PERCENT: u128 = 10;

/// `keccak256("Transfer(address,address,uint256)")`.
pub fn transfer_topic0() -> [u8; 32] {
    keccak256(b"Transfer(address,address,uint256)")
}

/// Left-pad an address into a 32-byte log topic.
pub fn address_topic(a: &Address) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(a);
    t
}

/// `0x`-prefixed lowercase hex transaction id, as the adapter produces it.
pub fn tx_id(hash: &[u8; 32]) -> ChainTxId {
    ChainTxId::unchecked(format!("0x{}", hex::encode(hash)))
}

/// Parse a transaction id (with or without `0x`).
pub fn parse_tx_id(id: &ChainTxId) -> OicResult<[u8; 32]> {
    let s = id.as_str();
    let v = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| OicError::invalid_request("EVM tx id must be hex"))?;
    v.try_into().map_err(|_| OicError::invalid_request("EVM tx id must be 32 bytes"))
}

// ---------------------------------------------------------------------------
// public data
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmSimConfig {
    /// Seeds the faucet key and the genesis hash.
    pub seed: [u8; 32],
    pub chain_id: u64,
    pub finality_depth: u64,
    pub base_fee: u128,
    pub priority_fee: u128,
    /// Gas-limit estimate published in evidence (`gas_limit`).
    pub gas_limit: u64,
}

impl Default for EvmSimConfig {
    fn default() -> Self {
        EvmSimConfig {
            seed: [0u8; 32],
            chain_id: DEFAULT_CHAIN_ID,
            finality_depth: DEFAULT_FINALITY_DEPTH,
            base_fee: DEFAULT_BASE_FEE,
            priority_fee: DEFAULT_PRIORITY_FEE,
            gas_limit: DEFAULT_GAS_LIMIT,
        }
    }
}

impl EvmSimConfig {
    pub fn with_seed(seed: [u8; 32]) -> Self {
        EvmSimConfig { seed, ..Default::default() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EvmAccount {
    pub balance: u128,
    pub nonce: u64,
    pub code: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Erc20Info {
    pub address: Address,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmLog {
    pub address: Address,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmReceipt {
    pub tx_hash: [u8; 32],
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub tx_index: u32,
    pub success: bool,
    pub gas_used: u64,
    pub effective_gas_price: u128,
    pub logs: Vec<EvmLog>,
}

impl EvmReceipt {
    /// `gas_used * effective_gas_price`.
    pub fn fee_paid(&self) -> u128 {
        self.gas_used as u128 * self.effective_gas_price
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmIncludedTx {
    pub hash: [u8; 32],
    pub from: Address,
    pub to: Address,
    pub nonce: u64,
    pub value: u128,
    pub data: Vec<u8>,
    pub signed_bytes: Vec<u8>,
    pub receipt: EvmReceipt,
}

/// Out-of-band setup operation recorded in a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvmSystemOp {
    DeployErc20 { address: Address, symbol: String, decimals: u8, holder: Address, supply: u128 },
    InstallCode { address: Address, code: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    /// Reorg counter at the time the block was mined (0 before any reorg).
    pub fork: u64,
    pub base_fee: u128,
    pub timestamp: UnixSeconds,
    pub system_ops: Vec<EvmSystemOp>,
    pub transactions: Vec<EvmIncludedTx>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EvmCommitment {
    /// Head block, `commitment = "latest"`.
    #[default]
    Latest,
    /// Highest finalized block, `commitment = "finalized"`.
    Finalized,
}

/// Signed bytes of a possibly-issued candidate (`signed_tx:<cand>:<rev>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxItem {
    pub candidate_id: String,
    pub revision: u32,
    pub signed_bytes: Vec<u8>,
}

/// What an evidence bundle should contain beyond the always-present
/// `chain_id`, `base_fee`, `priority_fee` and `gas_limit`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EvmEvidenceQuery {
    pub commitment: EvmCommitment,
    /// `nonce:<sender>`
    pub senders: Vec<Address>,
    /// `code:<contract>`
    pub contracts: Vec<Address>,
    /// `tx:<hash>`
    pub tx_hashes: Vec<[u8; 32]>,
    /// `signed_tx:<cand>:<rev>`
    pub signed_txs: Vec<SignedTxItem>,
}

impl EvmEvidenceQuery {
    pub fn latest() -> Self {
        Self::default()
    }
    pub fn finalized() -> Self {
        EvmEvidenceQuery { commitment: EvmCommitment::Finalized, ..Default::default() }
    }
    pub fn sender(mut self, a: Address) -> Self {
        self.senders.push(a);
        self
    }
    pub fn contract(mut self, a: Address) -> Self {
        self.contracts.push(a);
        self
    }
    pub fn tx(mut self, hash: [u8; 32]) -> Self {
        self.tx_hashes.push(hash);
        self
    }
    pub fn tx_id(self, id: &ChainTxId) -> OicResult<Self> {
        Ok(self.tx(parse_tx_id(id)?))
    }
    pub fn signed(mut self, candidate_id: impl Into<String>, revision: u32, signed_bytes: Vec<u8>) -> Self {
        self.signed_txs.push(SignedTxItem { candidate_id: candidate_id.into(), revision, signed_bytes });
        self
    }
}

// ---------------------------------------------------------------------------
// internal state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct Token {
    symbol: String,
    decimals: u8,
    total_supply: u128,
    balances: BTreeMap<Address, u128>,
}

/// Everything a block changes. Cloned per block as a snapshot.
#[derive(Clone, Debug, Default)]
struct State {
    accounts: BTreeMap<Address, EvmAccount>,
    tokens: BTreeMap<Address, Token>,
}

impl State {
    fn account(&self, a: &Address) -> EvmAccount {
        self.accounts.get(a).cloned().unwrap_or_default()
    }

    fn nonce(&self, a: &Address) -> u64 {
        self.accounts.get(a).map(|x| x.nonce).unwrap_or(0)
    }

    fn balance(&self, a: &Address) -> u128 {
        self.accounts.get(a).map(|x| x.balance).unwrap_or(0)
    }

    fn has_code(&self, a: &Address) -> bool {
        self.accounts.get(a).is_some_and(|x| !x.code.is_empty())
    }

    fn apply_op(&mut self, op: &EvmSystemOp) -> OicResult<()> {
        match op {
            EvmSystemOp::DeployErc20 { address, symbol, decimals, holder, supply } => {
                if self.has_code(address) || self.tokens.contains_key(address) {
                    return Err(OicError::resource_conflict(format!("address 0x{} already has code", hex::encode(address))));
                }
                self.accounts.entry(*address).or_default().code = ERC20_CODE_MARKER.to_vec();
                let mut balances = BTreeMap::new();
                if *supply > 0 {
                    balances.insert(*holder, *supply);
                }
                self.tokens.insert(*address, Token { symbol: symbol.clone(), decimals: *decimals, total_supply: *supply, balances });
            }
            EvmSystemOp::InstallCode { address, code } => {
                if code.is_empty() {
                    return Err(OicError::invalid_request("cannot install empty code"));
                }
                if self.has_code(address) || self.tokens.contains_key(address) {
                    return Err(OicError::resource_conflict(format!("address 0x{} already has code", hex::encode(address))));
                }
                self.accounts.entry(*address).or_default().code = code.clone();
            }
        }
        Ok(())
    }

    /// Whether `p` can be included now.
    fn includable(&self, p: &Pending, base_fee: u128) -> bool {
        if p.tx.nonce() != self.nonce(&p.from) || p.tx.fee_cap_per_gas() < base_fee {
            return false;
        }
        match worst_case_cost(&p.tx) {
            Ok(c) => self.balance(&p.from) >= c,
            Err(_) => false,
        }
    }

    /// Apply one includable transaction. Caller has checked `includable`.
    fn execute(&mut self, p: &Pending, base_fee: u128) -> (bool, u64, u128, Vec<EvmLog>) {
        let tx = &p.tx;
        let effective = tx.fee_cap_per_gas().min(base_fee.saturating_add(tx.priority_fee_per_gas()));
        let to = *tx.to();
        let value = tx.value();
        let mut logs = Vec::new();
        let (success, gas_used) = if let Some(token) = self.tokens.get_mut(&to) {
            match calldata::decode_transfer(tx.data()) {
                Ok(t) if value == 0 => {
                    if tx.gas_limit() < GAS_ERC20_TRANSFER {
                        (false, tx.gas_limit())
                    } else {
                        let from_bal = token.balances.get(&p.from).copied().unwrap_or(0);
                        if from_bal < t.amount {
                            (false, GAS_REVERTED_CALL)
                        } else {
                            token.balances.insert(p.from, from_bal - t.amount);
                            let to_bal = token.balances.get(&t.recipient).copied().unwrap_or(0);
                            // Total supply bounds every balance, so this cannot overflow.
                            token.balances.insert(t.recipient, to_bal.saturating_add(t.amount));
                            token.balances.retain(|_, v| *v > 0);
                            logs.push(EvmLog {
                                address: to,
                                topics: vec![transfer_topic0(), address_topic(&p.from), address_topic(&t.recipient)],
                                data: {
                                    let mut d = vec![0u8; 16];
                                    d.extend_from_slice(&t.amount.to_be_bytes());
                                    d
                                },
                            });
                            (true, GAS_ERC20_TRANSFER)
                        }
                    }
                }
                _ => (false, GAS_REVERTED_CALL),
            }
        } else if self.has_code(&to) {
            (false, GAS_REVERTED_CALL)
        } else {
            (true, GAS_NATIVE_TRANSFER)
        };
        // includable() guaranteed balance >= value + gas_limit * fee_cap >= value + fee.
        let fee = gas_used as u128 * effective;
        let sender = self.accounts.entry(p.from).or_default();
        sender.nonce += 1;
        sender.balance -= fee;
        if success && value > 0 {
            sender.balance -= value;
            let r = self.accounts.entry(to).or_default();
            r.balance = r.balance.saturating_add(value);
        }
        (success, gas_used, effective, logs)
    }
}

fn worst_case_cost(tx: &EvmTx) -> OicResult<u128> {
    checked(tx.max_fee()?.checked_add(tx.value()), "value + gas_limit * max_fee")
}

#[derive(Clone, Debug)]
struct Pending {
    hash: [u8; 32],
    from: Address,
    tx: EvmTx,
    signed: Vec<u8>,
    arrival: u64,
}

#[derive(Clone, Debug)]
struct Inner {
    cfg: EvmSimConfig,
    /// Head working state (last block's snapshot + pending system ops).
    state: State,
    blocks: Vec<EvmBlock>,
    /// `snapshots[h]` = state after block `h`.
    snapshots: Vec<State>,
    mempool: Vec<Pending>,
    pending_ops: Vec<EvmSystemOp>,
    next_arrival: u64,
    fork: u64,
    finalized: u64,
    base_fee: u128,
    priority_fee: u128,
    gas_limit: u64,
    deploy_counter: u64,
    /// Every accepted (or nonce-too-low but validly signed) tx: hash -> (sender, nonce).
    seen: BTreeMap<[u8; 32], (Address, u64)>,
    /// Canonical inclusion index: hash -> (height, index in block).
    tx_index: BTreeMap<[u8; 32], (u64, usize)>,
    lies: BTreeMap<String, BTreeMap<[u8; 32], TxObservation>>,
}

impl Inner {
    fn head(&self) -> &EvmBlock {
        self.blocks.last().expect("genesis always present")
    }

    fn next_nonce(&self, sender: &Address) -> u64 {
        let mut n = self.state.nonce(sender);
        while self.mempool.iter().any(|p| p.from == *sender && p.tx.nonce() == n) {
            n += 1;
        }
        n
    }

    fn submit(&mut self, bytes: &[u8]) -> OicResult<[u8; 32]> {
        let (tx, sig) = EvmTx::decode_signed(bytes)?;
        if tx.encode_signed(&sig) != bytes {
            return Err(OicError::unverifiable("signed transaction bytes are not canonical"));
        }
        if let EvmTx::Type2(t) = &tx {
            if !t.access_list.is_empty() {
                return Err(OicError::unsupported("access lists are not modelled by the EVM simulator"));
            }
            if t.max_priority_fee_per_gas > t.max_fee_per_gas {
                return Err(OicError::invalid_request("max_priority_fee_per_gas exceeds max_fee_per_gas"));
            }
        }
        if tx.chain_id() != self.cfg.chain_id {
            return Err(OicError::scope(format!("transaction chain_id {} does not match simulator chain_id {}", tx.chain_id(), self.cfg.chain_id)));
        }
        let from = recover_address(&tx.signing_digest(), &sig)?;
        let hash = tx_hash(bytes);
        if self.tx_index.contains_key(&hash) || self.mempool.iter().any(|p| p.hash == hash) {
            return Err(OicError::resource_conflict(format!("transaction 0x{} is already known", hex::encode(hash))));
        }
        if tx.gas_limit() < GAS_NATIVE_TRANSFER {
            return Err(OicError::invalid_request(format!("gas limit {} is below intrinsic gas {GAS_NATIVE_TRANSFER}", tx.gas_limit())));
        }
        let account_nonce = self.state.nonce(&from);
        if tx.nonce() < account_nonce {
            self.seen.insert(hash, (from, tx.nonce()));
            return Err(OicError::resource_conflict(format!(
                "nonce {} already consumed (account nonce {account_nonce})",
                tx.nonce()
            )));
        }
        let replacing = self.mempool.iter().position(|p| p.from == from && p.tx.nonce() == tx.nonce());
        let next = self.next_nonce(&from);
        if replacing.is_none() && tx.nonce() != next {
            return Err(OicError::resource_conflict(format!("nonce {} is not the sender's next nonce {next}", tx.nonce())));
        }
        if tx.fee_cap_per_gas() < self.base_fee {
            return Err(OicError::resource_conflict(format!(
                "max fee per gas {} is below the current base fee {}",
                tx.fee_cap_per_gas(),
                self.base_fee
            )));
        }
        if let Some(i) = replacing {
            let old = self.mempool[i].tx.priority_fee_per_gas();
            let new = tx.priority_fee_per_gas();
            let bumped = new.checked_mul(100).zip(old.checked_mul(100 + REPLACEMENT_BUMP_PERCENT)).is_some_and(|(n, o)| n >= o);
            if new <= old || !bumped {
                return Err(OicError::resource_conflict(format!(
                    "replacement underpriced: priority fee {new} must exceed the pending {old} by at least {REPLACEMENT_BUMP_PERCENT}%"
                )));
            }
        }
        let mut required = worst_case_cost(&tx)?;
        for (i, p) in self.mempool.iter().enumerate() {
            if p.from == from && Some(i) != replacing {
                required = checked(required.checked_add(worst_case_cost(&p.tx)?), "pending cost")?;
            }
        }
        let balance = self.state.balance(&from);
        if balance < required {
            return Err(OicError::resource_conflict(format!(
                "insufficient funds: balance {balance} < value + gas_limit * max_fee (incl. pending) {required}"
            )));
        }
        if let Some(i) = replacing {
            self.mempool.remove(i);
        }
        self.seen.insert(hash, (from, tx.nonce()));
        let arrival = self.next_arrival;
        self.next_arrival += 1;
        self.mempool.push(Pending { hash, from, tx, signed: bytes.to_vec(), arrival });
        Ok(hash)
    }

    fn mine(&mut self, timestamp: UnixSeconds) -> EvmBlock {
        let parent = self.head().clone();
        let height = parent.height + 1;
        let base_fee = self.base_fee;
        let system_ops = std::mem::take(&mut self.pending_ops);
        let mut executed: Vec<(Pending, bool, u64, u128, Vec<EvmLog>)> = Vec::new();
        loop {
            let pick = self
                .mempool
                .iter()
                .enumerate()
                .filter(|(_, p)| self.state.includable(p, base_fee))
                .min_by_key(|(_, p)| p.arrival)
                .map(|(i, _)| i);
            let Some(i) = pick else { break };
            let p = self.mempool.remove(i);
            let (ok, gas, eff, logs) = self.state.execute(&p, base_fee);
            executed.push((p, ok, gas, eff, logs));
        }
        // Pending txs whose nonce is now consumed can never be included.
        let state = &self.state;
        self.mempool.retain(|p| p.tx.nonce() >= state.nonce(&p.from));

        let ids: Vec<&[u8]> = executed.iter().map(|e| e.0.hash.as_slice()).collect();
        let hash = crate::block_hash(&parent.hash, height, &ids, self.fork);
        let transactions: Vec<EvmIncludedTx> = executed
            .into_iter()
            .enumerate()
            .map(|(i, (p, success, gas_used, effective_gas_price, logs))| EvmIncludedTx {
                hash: p.hash,
                from: p.from,
                to: *p.tx.to(),
                nonce: p.tx.nonce(),
                value: p.tx.value(),
                data: p.tx.data().to_vec(),
                signed_bytes: p.signed,
                receipt: EvmReceipt {
                    tx_hash: p.hash,
                    block_height: height,
                    block_hash: hash,
                    tx_index: i as u32,
                    success,
                    gas_used,
                    effective_gas_price,
                    logs,
                },
            })
            .collect();
        for (i, t) in transactions.iter().enumerate() {
            self.tx_index.insert(t.hash, (height, i));
        }
        let block = EvmBlock { height, hash, parent_hash: parent.hash, fork: self.fork, base_fee, timestamp, system_ops, transactions };
        self.blocks.push(block.clone());
        self.snapshots.push(self.state.clone());
        let candidate = (height + 1).saturating_sub(self.cfg.finality_depth.max(1));
        self.finalized = self.finalized.max(candidate);
        block
    }

    fn reorg(&mut self, depth: u64, drop: &[ChainTxId], timestamp: UnixSeconds) -> OicResult<()> {
        let head = self.head().height;
        if depth == 0 {
            return Err(OicError::invalid_request("reorg depth must be at least 1"));
        }
        if depth > head - self.finalized {
            return Err(OicError::resource_conflict(format!(
                "reorg of depth {depth} from head {head} would cross the finalized height {}",
                self.finalized
            )));
        }
        let drop: BTreeSet<[u8; 32]> = drop.iter().map(parse_tx_id).collect::<OicResult<_>>()?;
        let fork_point = (head - depth) as usize;
        let removed = self.blocks.split_off(fork_point + 1);
        self.snapshots.truncate(fork_point + 1);
        let removed_hashes: BTreeSet<[u8; 32]> = removed.iter().flat_map(|b| b.transactions.iter().map(|t| t.hash)).collect();
        if let Some(missing) = drop.iter().find(|h| !removed_hashes.contains(*h)) {
            return Err(OicError::invalid_request(format!("tx 0x{} to drop is not in the reorganised blocks", hex::encode(missing))));
        }
        self.fork += 1;
        self.state = self.snapshots[fork_point].clone();
        let ops: Vec<EvmSystemOp> = removed.iter().flat_map(|b| b.system_ops.iter().cloned()).chain(self.pending_ops.drain(..)).collect();
        for op in &ops {
            self.state.apply_op(op)?;
        }
        self.pending_ops = ops;
        let mut returned = Vec::new();
        for t in removed.iter().flat_map(|b| b.transactions.iter()) {
            if drop.contains(&t.hash) {
                continue;
            }
            let (tx, _) = EvmTx::decode_signed(&t.signed_bytes)?;
            returned.push(Pending { hash: t.hash, from: t.from, tx, signed: t.signed_bytes.clone(), arrival: 0 });
        }
        let old = std::mem::take(&mut self.mempool);
        let mut pool = returned;
        for p in old {
            if !pool.iter().any(|r| r.from == p.from && r.tx.nonce() == p.tx.nonce()) {
                pool.push(p);
            }
        }
        for p in &mut pool {
            p.arrival = self.next_arrival;
            self.next_arrival += 1;
        }
        self.mempool = pool;
        self.tx_index.clear();
        for b in &self.blocks {
            for (i, t) in b.transactions.iter().enumerate() {
                self.tx_index.insert(t.hash, (b.height, i));
            }
        }
        for _ in 0..depth {
            self.mine(timestamp);
        }
        Ok(())
    }

    fn view_height(&self, c: EvmCommitment) -> u64 {
        match c {
            EvmCommitment::Latest => self.head().height,
            EvmCommitment::Finalized => self.finalized,
        }
    }

    fn observation(&self, view: u64, hash: &[u8; 32], known: &BTreeMap<[u8; 32], (Address, u64)>) -> TxObservation {
        if let Some(&(h, i)) = self.tx_index.get(hash) {
            if h <= view {
                let b = &self.blocks[h as usize];
                let r = &b.transactions[i].receipt;
                return TxObservation {
                    included: true,
                    block_height: h,
                    block_hash: Bytes(b.hash.to_vec()),
                    success: r.success,
                    gas_used: r.gas_used,
                    effective_gas_price: Amount(r.effective_gas_price),
                    confirmations: view - h + 1,
                    nonce_consumed_by: None,
                };
            }
        }
        let consumed_by = known.get(hash).and_then(|(from, nonce)| {
            self.blocks[..=view as usize]
                .iter()
                .flat_map(|b| b.transactions.iter())
                .find(|t| t.from == *from && t.nonce == *nonce && t.hash != *hash)
                .map(|t| Bytes(t.hash.to_vec()))
        });
        TxObservation {
            included: false,
            block_height: 0,
            block_hash: Bytes(Vec::new()),
            success: false,
            gas_used: 0,
            effective_gas_price: Amount::ZERO,
            confirmations: 0,
            nonce_consumed_by: consumed_by,
        }
    }

    fn bundle(&self, source: &EvidenceSourceId, q: &EvmEvidenceQuery, now: UnixSeconds) -> OicResult<EvidenceBundle> {
        let view = self.view_height(q.commitment);
        let snap = &self.snapshots[view as usize];
        let block = &self.blocks[view as usize];
        let mut items = BTreeMap::new();
        items.insert(KEY_CHAIN_ID.to_string(), Bytes(self.cfg.chain_id.to_be_bytes().to_vec()));
        items.insert(KEY_BASE_FEE.to_string(), Bytes(self.base_fee.to_be_bytes().to_vec()));
        items.insert(KEY_PRIORITY_FEE.to_string(), Bytes(self.priority_fee.to_be_bytes().to_vec()));
        items.insert(KEY_GAS_LIMIT.to_string(), Bytes(self.gas_limit.to_be_bytes().to_vec()));
        for s in &q.senders {
            items.insert(nonce_key(s), Bytes(snap.nonce(s).to_be_bytes().to_vec()));
        }
        for c in &q.contracts {
            items.insert(code_key(c), Bytes(keccak256(&snap.account(c).code).to_vec()));
        }
        let mut known = self.seen.clone();
        for s in &q.signed_txs {
            let (tx, sig) = EvmTx::decode_signed(&s.signed_bytes)?;
            let from = recover_address(&tx.signing_digest(), &sig)?;
            known.insert(tx_hash(&s.signed_bytes), (from, tx.nonce()));
            items.insert(signed_tx_key(&s.candidate_id, s.revision), Bytes(s.signed_bytes.clone()));
        }
        let lies = self.lies.get(source.as_str());
        for h in &q.tx_hashes {
            let obs = match lies.and_then(|l| l.get(h)) {
                Some(lie) => lie.clone(),
                None => self.observation(view, h, &known),
            };
            items.insert(tx_key(h), Bytes(oic_canonical_encoding::canonical_bytes(&obs)?));
        }
        let commitment = match q.commitment {
            EvmCommitment::Latest => LATEST_COMMITMENT,
            EvmCommitment::Finalized => FINALITY_COMMITMENT,
        };
        Ok(EvidenceBundle {
            chain_profile_id: ChainProfileId::unchecked(CHAIN_PROFILE_ID),
            network_id: network_id(self.cfg.chain_id),
            state: StateReference { height: view, hash: Bytes(block.hash.to_vec()), commitment: commitment.to_string() },
            sources: vec![source.clone()],
            trust_level: EvidenceTrustLevel::DevelopmentSimulator,
            observed_at: now,
            max_staleness_seconds: EVIDENCE_MAX_STALENESS_SECONDS,
            verifier_version: VERIFIER_VERSION.to_string(),
            items,
        })
    }
}

fn network_id(chain_id: u64) -> NetworkId {
    NetworkId::unchecked(format!("evm-{chain_id}"))
}

/// Sign an EIP-1559 transaction with a k256 key; returns canonical signed bytes.
pub fn sign_eip1559(sk: &SigningKey, tx: &Eip1559Tx) -> OicResult<Vec<u8>> {
    let digest = tx.signing_digest();
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).map_err(|_| OicError::internal("secp256k1 signing failed"))?;
    let b = sig.to_bytes();
    let raw = RawSignature { y_parity: recid.to_byte(), r: b[..32].try_into().expect("32"), s: b[32..].try_into().expect("32") };
    Ok(tx.encode_signed(&raw))
}

/// EVM address of a k256 signing key.
pub fn address_of(sk: &SigningKey) -> OicResult<Address> {
    address_from_sec1(sk.verifying_key().to_encoded_point(true).as_bytes())
}

// ---------------------------------------------------------------------------
// simulator
// ---------------------------------------------------------------------------

/// Simulated EVM chain. `Send + Sync`; share it with `Arc`.
pub struct EvmSimulator {
    inner: Mutex<Inner>,
    clock: SimClock,
    faucet: SigningKey,
    faucet_address: Address,
}

impl EvmSimulator {
    /// Build a simulator at genesis (height 0). The faucet EOA holds
    /// [`FAUCET_GENESIS_BALANCE`].
    pub fn new(cfg: EvmSimConfig, clock: SimClock) -> OicResult<Self> {
        if cfg.finality_depth == 0 {
            return Err(OicError::invalid_request("finality_depth must be at least 1"));
        }
        if cfg.gas_limit < GAS_NATIVE_TRANSFER {
            return Err(OicError::invalid_request("gas_limit estimate must cover intrinsic gas"));
        }
        let mut counter = 0u32;
        let faucet = loop {
            let k = sha256_parts(&[b"oic-devsim-evm-faucet", &cfg.seed, &counter.to_be_bytes()]);
            if let Ok(sk) = SigningKey::from_bytes(&k.into()) {
                break sk;
            }
            counter += 1;
        };
        let faucet_address = address_of(&faucet)?;
        let mut state = State::default();
        state.accounts.insert(faucet_address, EvmAccount { balance: FAUCET_GENESIS_BALANCE, nonce: 0, code: vec![] });
        let genesis_hash = sha256_parts(&[b"oic-devsim-evm-genesis", &cfg.seed, &cfg.chain_id.to_be_bytes()]);
        let genesis = EvmBlock {
            height: 0,
            hash: genesis_hash,
            parent_hash: [0u8; 32],
            fork: 0,
            base_fee: cfg.base_fee,
            timestamp: clock.now(),
            system_ops: vec![],
            transactions: vec![],
        };
        let inner = Inner {
            base_fee: cfg.base_fee,
            priority_fee: cfg.priority_fee,
            gas_limit: cfg.gas_limit,
            cfg,
            snapshots: vec![state.clone()],
            state,
            blocks: vec![genesis],
            mempool: vec![],
            pending_ops: vec![],
            next_arrival: 0,
            fork: 0,
            finalized: 0,
            deploy_counter: 0,
            seen: BTreeMap::new(),
            tx_index: BTreeMap::new(),
            lies: BTreeMap::new(),
        };
        Ok(EvmSimulator { inner: Mutex::new(inner), clock, faucet, faucet_address })
    }

    pub fn config(&self) -> EvmSimConfig {
        lock(&self.inner).cfg.clone()
    }

    pub fn clock(&self) -> &SimClock {
        &self.clock
    }

    pub fn chain_id(&self) -> u64 {
        lock(&self.inner).cfg.chain_id
    }

    /// The enrolled development profile for this chain.
    pub fn profile(&self) -> ChainProfile {
        let g = lock(&self.inner);
        ChainProfile {
            chain_profile_id: ChainProfileId::unchecked(CHAIN_PROFILE_ID),
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            network_id: network_id(g.cfg.chain_id),
            network_binding: network_binding_for_chain_id(g.cfg.chain_id),
            display_name: format!("OIC EVM development simulator (chain {}) — DEVELOPMENT ONLY", g.cfg.chain_id),
            accepted_versions: vec![VERSION_TYPE2.to_string()],
            finality_commitment: FINALITY_COMMITMENT.to_string(),
            finality_depth: g.cfg.finality_depth,
            max_evidence_age_seconds: PROFILE_MAX_EVIDENCE_AGE_SECONDS,
            accepted_trust_levels: vec![EvidenceTrustLevel::DevelopmentSimulator],
        }
    }

    pub fn faucet_address(&self) -> Address {
        self.faucet_address
    }

    /// Current `(base_fee, priority_fee, gas_limit estimate)`.
    pub fn fees(&self) -> (u128, u128, u64) {
        let g = lock(&self.inner);
        (g.base_fee, g.priority_fee, g.gas_limit)
    }

    /// Change the fee market. Raising the base fee above a pending
    /// transaction's fee cap leaves it stuck in the mempool (C10).
    pub fn set_fees(&self, base_fee: u128, priority_fee: u128, gas_limit: u64) -> OicResult<()> {
        if gas_limit < GAS_NATIVE_TRANSFER {
            return Err(OicError::invalid_request("gas_limit estimate must cover intrinsic gas"));
        }
        base_fee.checked_mul(2).and_then(|x| x.checked_add(priority_fee)).ok_or_else(|| crate::overflow("2 * base_fee + priority_fee"))?;
        let mut g = lock(&self.inner);
        g.base_fee = base_fee;
        g.priority_fee = priority_fee;
        g.gas_limit = gas_limit;
        Ok(())
    }

    /// Register an ERC-20 contract. Address = first 20 bytes of
    /// `SHA256("erc20" || symbol || deploy_counter_be)`; code = [`ERC20_CODE_MARKER`];
    /// `supply` is credited to `initial_holder`. Pass [`Self::faucet_address`]
    /// as holder to make the token fundable with [`Self::erc20_fund`].
    pub fn deploy_erc20(&self, symbol: &str, decimals: u8, initial_holder: Address, supply: u128) -> OicResult<Address> {
        if symbol.is_empty() || symbol.len() > 32 {
            return Err(OicError::invalid_request("symbol must be 1..=32 bytes"));
        }
        let mut g = lock(&self.inner);
        let mut counter = g.deploy_counter;
        let address = loop {
            let h = sha256_parts(&[b"erc20", symbol.as_bytes(), &counter.to_be_bytes()]);
            let a: Address = h[..20].try_into().expect("20 bytes");
            counter += 1;
            if !g.state.has_code(&a) && !g.state.tokens.contains_key(&a) {
                break a;
            }
        };
        let op = EvmSystemOp::DeployErc20 { address, symbol: symbol.to_string(), decimals, holder: initial_holder, supply };
        g.state.apply_op(&op)?;
        g.deploy_counter = counter;
        g.pending_ops.push(op);
        Ok(address)
    }

    /// Install arbitrary (non-token) code at an address, e.g. to model a
    /// contract that reverts every call.
    pub fn install_code(&self, address: Address, code: Vec<u8>) -> OicResult<()> {
        let mut g = lock(&self.inner);
        let op = EvmSystemOp::InstallCode { address, code };
        g.state.apply_op(&op)?;
        g.pending_ops.push(op);
        Ok(())
    }

    fn faucet_tx(&self, g: &Inner, to: Address, value: u128, data: Vec<u8>, gas_limit: u64) -> OicResult<Vec<u8>> {
        let max_fee = checked(g.base_fee.checked_mul(2).and_then(|x| x.checked_add(g.priority_fee)), "faucet max fee")?;
        let tx = Eip1559Tx {
            chain_id: g.cfg.chain_id,
            nonce: g.next_nonce(&self.faucet_address),
            max_priority_fee_per_gas: g.priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit,
            to,
            value,
            data,
            access_list: vec![],
        };
        sign_eip1559(&self.faucet, &tx)
    }

    /// Faucet credit: a real signed native transfer from the faucet EOA,
    /// accepted into the mempool and included by the next [`Self::mine`].
    pub fn fund(&self, to: Address, amount: u128) -> OicResult<ChainTxId> {
        let mut g = lock(&self.inner);
        let bytes = self.faucet_tx(&g, to, amount, vec![], GAS_NATIVE_TRANSFER)?;
        g.submit(&bytes).map(|h| tx_id(&h))
    }

    /// Token credit: a real signed ERC-20 `transfer` from the faucet EOA
    /// (which must hold the tokens, i.e. was the deploy holder), included by
    /// the next [`Self::mine`].
    pub fn erc20_fund(&self, token: Address, to: Address, amount: u128) -> OicResult<ChainTxId> {
        let mut g = lock(&self.inner);
        let held = g
            .state
            .tokens
            .get(&token)
            .ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("0x{} is not a registered ERC-20", hex::encode(token))))?
            .balances
            .get(&self.faucet_address)
            .copied()
            .unwrap_or(0);
        if held < amount {
            return Err(OicError::resource_conflict(format!("faucet holds {held} tokens, cannot fund {amount}")));
        }
        let bytes = self.faucet_tx(&g, token, 0, calldata::encode_transfer(&to, amount), GAS_ERC20_TRANSFER)?;
        g.submit(&bytes).map(|h| tx_id(&h))
    }

    /// Broadcast signed bytes. `Ok` is an acknowledgement into the mempool, not inclusion.
    pub fn submit(&self, signed_bytes: &[u8]) -> OicResult<ChainTxId> {
        lock(&self.inner).submit(signed_bytes).map(|h| tx_id(&h))
    }

    /// Produce the next block. Timestamp = clock now.
    pub fn mine(&self) -> OicResult<EvmBlock> {
        let now = self.clock.now();
        let mut g = lock(&self.inner);
        if g.head().height == u64::MAX {
            return Err(crate::overflow("block height"));
        }
        Ok(g.mine(now))
    }

    /// Mine `n` blocks, returning them in order.
    pub fn mine_blocks(&self, n: u64) -> OicResult<Vec<EvmBlock>> {
        (0..n).map(|_| self.mine()).collect()
    }

    /// Remove the last `depth` blocks (refused if that crosses the finalized
    /// height), restore the fork-point snapshot, replay system operations,
    /// return the removed transactions except `drop_tx_ids` to the front of
    /// the mempool, and mine `depth` replacement blocks with new hashes.
    /// All-or-nothing.
    pub fn reorg(&self, depth: u64, drop_tx_ids: &[ChainTxId]) -> OicResult<()> {
        let now = self.clock.now();
        let mut g = lock(&self.inner);
        let mut scratch = g.clone();
        scratch.reorg(depth, drop_tx_ids, now)?;
        *g = scratch;
        Ok(())
    }

    pub fn head(&self) -> StateReference {
        let g = lock(&self.inner);
        let b = g.head();
        StateReference { height: b.height, hash: Bytes(b.hash.to_vec()), commitment: LATEST_COMMITMENT.to_string() }
    }

    pub fn finalized_height(&self) -> u64 {
        lock(&self.inner).finalized
    }

    pub fn finalized(&self) -> StateReference {
        let g = lock(&self.inner);
        let b = &g.blocks[g.finalized as usize];
        StateReference { height: b.height, hash: Bytes(b.hash.to_vec()), commitment: FINALITY_COMMITMENT.to_string() }
    }

    pub fn block(&self, height: u64) -> Option<EvmBlock> {
        lock(&self.inner).blocks.get(usize::try_from(height).ok()?).cloned()
    }

    /// Holdings at an exact canonical block, not at the current head. A
    /// concurrent reorg invalidates the reference instead of mixing checkpoints.
    pub fn balance_at(&self, state: &StateReference, address: &Address, asset: &AssetKind) -> OicResult<Amount> {
        let g = lock(&self.inner);
        let h = usize::try_from(state.height).map_err(|_| OicError::stale_evidence("block height out of range"))?;
        let block = g.blocks.get(h).ok_or_else(|| OicError::stale_evidence("block missing"))?;
        if block.hash.as_slice() != state.hash.as_slice() {
            return Err(OicError::stale_evidence("block is no longer canonical"));
        }
        let snapshot = &g.snapshots[h];
        match asset {
            AssetKind::Native => Ok(Amount(snapshot.balance(address))),
            AssetKind::Erc20 { contract } => {
                let contract: Address = contract.as_slice().try_into().map_err(|_| OicError::invalid_request("ERC-20 contract length"))?;
                Ok(Amount(snapshot.tokens.get(&contract).and_then(|t| t.balances.get(address)).copied().unwrap_or(0)))
            }
            _ => Err(OicError::unsupported("EVM balance asset")),
        }
    }

    /// Receipt of a canonically included transaction.
    pub fn receipt(&self, id: &ChainTxId) -> OicResult<Option<EvmReceipt>> {
        let h = parse_tx_id(id)?;
        let g = lock(&self.inner);
        Ok(g.tx_index.get(&h).map(|&(height, i)| g.blocks[height as usize].transactions[i].receipt.clone()))
    }

    /// Pending transaction ids in arrival order.
    pub fn mempool(&self) -> Vec<ChainTxId> {
        let g = lock(&self.inner);
        let mut v: Vec<&Pending> = g.mempool.iter().collect();
        v.sort_by_key(|p| p.arrival);
        v.into_iter().map(|p| tx_id(&p.hash)).collect()
    }

    pub fn account(&self, a: &Address) -> EvmAccount {
        lock(&self.inner).state.account(a)
    }

    pub fn balance(&self, a: &Address) -> u128 {
        lock(&self.inner).state.balance(a)
    }

    pub fn nonce(&self, a: &Address) -> u64 {
        lock(&self.inner).state.nonce(a)
    }

    pub fn erc20_balance(&self, token: &Address, holder: &Address) -> OicResult<u128> {
        let g = lock(&self.inner);
        let t = g
            .state
            .tokens
            .get(token)
            .ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("0x{} is not a registered ERC-20", hex::encode(token))))?;
        Ok(t.balances.get(holder).copied().unwrap_or(0))
    }

    pub fn erc20_info(&self, token: &Address) -> Option<Erc20Info> {
        let g = lock(&self.inner);
        g.state.tokens.get(token).map(|t| Erc20Info { address: *token, symbol: t.symbol.clone(), decimals: t.decimals, total_supply: t.total_supply })
    }

    /// Evidence from the honest source [`SOURCE_ID`].
    pub fn evidence(&self, query: &EvmEvidenceQuery) -> OicResult<EvidenceBundle> {
        self.evidence_from(&EvidenceSourceId::unchecked(SOURCE_ID), query)
    }

    /// Evidence as reported by `source`. Identical to the honest source except
    /// for observations overridden with [`Self::set_lie`] (A30).
    pub fn evidence_from(&self, source: &EvidenceSourceId, query: &EvmEvidenceQuery) -> OicResult<EvidenceBundle> {
        let now = self.clock.now();
        lock(&self.inner).bundle(source, query, now)
    }

    /// Make `source` report `obs` for `tx_hash` whenever that tx is queried.
    /// The honest source cannot be made to lie.
    pub fn set_lie(&self, source: &EvidenceSourceId, tx_hash: [u8; 32], obs: TxObservation) -> OicResult<()> {
        if source.as_str() == SOURCE_ID {
            return Err(OicError::invalid_request("the honest simulator source cannot be configured to lie"));
        }
        lock(&self.inner).lies.entry(source.as_str().to_string()).or_default().insert(tx_hash, obs);
        Ok(())
    }

    pub fn clear_lies(&self, source: &EvidenceSourceId) {
        lock(&self.inner).lies.remove(source.as_str());
    }
}
