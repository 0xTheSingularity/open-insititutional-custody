//! EVM JSON-RPC chain client for live development networks (anvil, reth, geth).
//!
//! Implements the broadcaster's [`ChainClient`] and the reconciler's
//! [`BlockSource`] against the standard `eth_*` API, assembling exactly the
//! [`EvidenceBundle`] items the EVM adapter documents in
//! `oic_adapter_evm::evidence`. Transaction ids reuse the simulator's format
//! so movements from both sources deduplicate identically.
//!
//! Trust: one endpoint is one evidence source. The default trust level is
//! [`EvidenceTrustLevel::SingleProvider`]; an operator running their own
//! validating node can declare [`EvidenceTrustLevel::ValidatingNode`].
//! Declaring it does not make it true (RFC 0001 §12.3).

use crate::jsonrpc::{data_bytes, data_fixed, quantity_u128, quantity_u64, to_hex, to_quantity, Endpoint};
use oic_adapter_api::{ChainProfile, SignedTransaction};
use oic_adapter_evm::address::{keccak256, Address};
use oic_adapter_evm::evidence::{
    code_key, nonce_key, signed_tx_key, tx_key, TxObservation, KEY_BASE_FEE, KEY_CHAIN_ID, KEY_GAS_LIMIT, KEY_PRIORITY_FEE,
};
use oic_adapter_evm::tx::{tx_hash, EvmTx};
use oic_adapter_evm::{network_binding_for_chain_id, recover_address, ADAPTER_ID, VERSION_TYPE2};
use oic_chain_simulator::evm::{parse_tx_id, tx_id, transfer_topic0, FINALITY_COMMITMENT, LATEST_COMMITMENT};
use oic_chain_simulator::EVIDENCE_MAX_STALENESS_SECONDS;
use oic_domain_types::*;
use oic_service_broadcaster::{ChainClient, Commitment, PossiblyIssued};
use oic_service_reconciler::{BlockSource, ChainEffect, EffectKind, IndexedBlock};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Chain profile id for a live EVM endpoint.
pub const CHAIN_PROFILE_ID: &str = "evm-rpc-v1";
/// Version string recorded in produced evidence bundles.
pub const VERIFIER_VERSION: &str = concat!("oic-chain-rpc/", env!("CARGO_PKG_VERSION"));
/// How many recent blocks to scan for the transaction that consumed a nonce.
const NONCE_SCAN_WINDOW: u64 = 64;

/// Configuration for [`EvmRpcClient::connect`].
pub struct EvmRpcConfig {
    pub url: String,
    /// Evidence source identity recorded in bundles and movements.
    pub source_id: EvidenceSourceId,
    pub display_name: String,
    /// End-to-end timeout for each RPC call.
    pub timeout: Duration,
    /// Trust level declared for this endpoint's evidence.
    pub trust_level: EvidenceTrustLevel,
    /// `Included -> Finalized` confirmations recorded in the profile.
    pub finality_depth: u64,
    /// Gas limit reported as build evidence (includes margin).
    pub evidence_gas_limit: u64,
    /// Also discover native value moved by internal call frames, through
    /// `debug_traceBlockByNumber` with the callTracer. Off by default:
    /// public providers often disable debug APIs, and the capability must
    /// degrade loudly - when tracing is on, a node that refuses or garbles
    /// the call fails `block()` instead of returning partial effects.
    pub trace_internal_transfers: bool,
}

impl EvmRpcConfig {
    /// Single-provider profile for a local development node.
    pub fn development(url: impl Into<String>) -> Self {
        EvmRpcConfig {
            url: url.into(),
            source_id: EvidenceSourceId::unchecked("evm-rpc"),
            display_name: "EVM development network".into(),
            timeout: Duration::from_secs(10),
            trust_level: EvidenceTrustLevel::SingleProvider,
            finality_depth: 1,
            evidence_gas_limit: 65_000,
            trace_internal_transfers: false,
        }
    }
}

/// Live EVM node speaking standard JSON-RPC.
pub struct EvmRpcClient {
    rpc: Endpoint,
    cfg: EvmRpcConfig,
    chain_id: u64,
}

impl EvmRpcClient {
    /// Connect and bind to the node's chain id. The id is read once; the
    /// adapter re-checks it against `network_binding` on every verification.
    pub fn connect(cfg: EvmRpcConfig) -> OicResult<Self> {
        let rpc = Endpoint::new(cfg.url.clone(), cfg.timeout)?;
        let chain_id = quantity_u64(&rpc.call_value("eth_chainId", json!([]))?, "eth_chainId")?;
        Ok(EvmRpcClient { rpc, cfg, chain_id })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn profile(&self) -> ChainProfile {
        ChainProfile {
            chain_profile_id: ChainProfileId::unchecked(CHAIN_PROFILE_ID),
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            network_id: self.network_id(),
            network_binding: network_binding_for_chain_id(self.chain_id),
            display_name: self.cfg.display_name.clone(),
            accepted_versions: vec![VERSION_TYPE2.to_string()],
            finality_commitment: FINALITY_COMMITMENT.to_string(),
            finality_depth: self.cfg.finality_depth,
            max_evidence_age_seconds: oic_chain_simulator::PROFILE_MAX_EVIDENCE_AGE_SECONDS,
            accepted_trust_levels: vec![self.cfg.trust_level],
        }
    }

    /// Evidence for building a candidate: fees, gas, nonces and code hashes at
    /// the requested view. The adapter validates everything it reads from it.
    pub fn build_evidence(&self, senders: &[Address], contracts: &[Address], commitment: Commitment) -> OicResult<EvidenceBundle> {
        let view = self.block_by_tag(tag(commitment))?;
        let mut items = self.base_items(&view)?;
        for sender in senders {
            items.insert(nonce_key(sender), self.nonce_item(sender, &view)?);
        }
        for contract in contracts {
            let code = data_bytes(
                &self.rpc.call_value("eth_getCode", json!([to_hex(contract), block_ref(&view)]))?,
                "eth_getCode",
            )?;
            items.insert(code_key(contract), Bytes(keccak256(&code).to_vec()));
        }
        self.bundle(view, commitment, items)
    }

    fn network_id(&self) -> NetworkId {
        NetworkId::unchecked(format!("evm-{}", self.chain_id))
    }

    /// Fee and chain-identity items present in every bundle.
    fn base_items(&self, view: &BlockHeader) -> OicResult<BTreeMap<String, Bytes>> {
        let mut items = BTreeMap::new();
        items.insert(KEY_CHAIN_ID.to_string(), Bytes(self.chain_id.to_be_bytes().to_vec()));
        items.insert(KEY_BASE_FEE.to_string(), Bytes(view.base_fee.to_be_bytes().to_vec()));
        let priority = quantity_u128(&self.rpc.call_value("eth_maxPriorityFeePerGas", json!([]))?, "eth_maxPriorityFeePerGas")?;
        items.insert(KEY_PRIORITY_FEE.to_string(), Bytes(priority.to_be_bytes().to_vec()));
        items.insert(KEY_GAS_LIMIT.to_string(), Bytes(self.cfg.evidence_gas_limit.to_be_bytes().to_vec()));
        Ok(items)
    }

    fn nonce_item(&self, sender: &Address, view: &BlockHeader) -> OicResult<Bytes> {
        let nonce = quantity_u64(
            &self.rpc.call_value("eth_getTransactionCount", json!([to_hex(sender), block_ref(view)]))?,
            "eth_getTransactionCount",
        )?;
        Ok(Bytes(nonce.to_be_bytes().to_vec()))
    }

    fn account_nonce(&self, sender: &Address, view: &BlockHeader) -> OicResult<u64> {
        Ok(u64::from_be_bytes(self.nonce_item(sender, view)?.as_slice().try_into().expect("8 bytes")))
    }

    fn bundle(&self, view: BlockHeader, commitment: Commitment, items: BTreeMap<String, Bytes>) -> OicResult<EvidenceBundle> {
        Ok(EvidenceBundle {
            chain_profile_id: ChainProfileId::unchecked(CHAIN_PROFILE_ID),
            network_id: self.network_id(),
            state: StateReference { height: view.height, hash: Bytes(view.hash.to_vec()), commitment: commitment_str(commitment).to_string() },
            sources: vec![self.cfg.source_id.clone()],
            trust_level: self.cfg.trust_level,
            observed_at: wall_clock(),
            max_staleness_seconds: EVIDENCE_MAX_STALENESS_SECONDS,
            verifier_version: VERIFIER_VERSION.to_string(),
            items,
        })
    }

    /// Header of the block a tag or number resolves to right now.
    fn block_by_tag(&self, tag: &str) -> OicResult<BlockHeader> {
        let v = self.rpc.call_value("eth_getBlockByNumber", json!([tag, false]))?;
        if v.is_null() {
            return Err(OicError::stale_evidence(format!("the node has no `{tag}` block")));
        }
        BlockHeader::decode(&v)
    }

    /// Observation of one transaction hash at the view, mirroring the
    /// simulator's semantics: included only when its block is canonical at or
    /// below the view height; otherwise a not-included record whose
    /// `nonce_consumed_by` names a replacing transaction when one is found in
    /// the recent canonical history.
    fn observation(&self, view: &BlockHeader, hash: &[u8; 32], known: &BTreeMap<[u8; 32], (Address, u64)>) -> OicResult<TxObservation> {
        let receipt = self.rpc.call_value("eth_getTransactionReceipt", json!([to_hex(hash)]))?;
        if !receipt.is_null() {
            let height = quantity_u64(&receipt["blockNumber"], "receipt blockNumber")?;
            let block_hash: [u8; 32] = data_fixed(&receipt["blockHash"], "receipt blockHash")?;
            // Canonical at the view: the height is within it and the canonical
            // block at that height is the inclusion block.
            if height <= view.height {
                let canonical = self.block_by_tag(&to_quantity(height))?;
                if canonical.hash == block_hash {
                    return Ok(TxObservation {
                        included: true,
                        block_height: height,
                        block_hash: Bytes(block_hash.to_vec()),
                        success: quantity_u64(&receipt["status"], "receipt status")? == 1,
                        gas_used: quantity_u64(&receipt["gasUsed"], "receipt gasUsed")?,
                        effective_gas_price: Amount(quantity_u128(&receipt["effectiveGasPrice"], "receipt effectiveGasPrice")?),
                        confirmations: view.height - height + 1,
                        nonce_consumed_by: None,
                    });
                }
            }
        }
        let nonce_consumed_by = match known.get(hash) {
            Some((from, nonce)) if self.account_nonce(from, view)? > *nonce => self.find_nonce_consumer(view, from, *nonce, hash)?,
            _ => None,
        };
        Ok(TxObservation {
            included: false,
            block_height: 0,
            block_hash: Bytes(Vec::new()),
            success: false,
            gas_used: 0,
            effective_gas_price: Amount::ZERO,
            confirmations: 0,
            nonce_consumed_by,
        })
    }

    /// Bounded scan of recent canonical blocks for the other transaction that
    /// consumed `from`'s `nonce`. `None` when it is outside the window; the
    /// adapter treats the consumed nonce itself as the conflict.
    fn find_nonce_consumer(&self, view: &BlockHeader, from: &Address, nonce: u64, not: &[u8; 32]) -> OicResult<Option<Bytes>> {
        let start = view.height.saturating_sub(NONCE_SCAN_WINDOW);
        for height in start..=view.height {
            let block = self.rpc.call_value("eth_getBlockByNumber", json!([to_quantity(height), true]))?;
            if block.is_null() {
                continue;
            }
            for tx in transactions(&block)? {
                let hash: [u8; 32] = data_fixed(&tx["hash"], "tx hash")?;
                let sender: Address = data_fixed(&tx["from"], "tx from")?;
                if sender == *from && quantity_u64(&tx["nonce"], "tx nonce")? == nonce && hash != *not {
                    return Ok(Some(Bytes(hash.to_vec())));
                }
            }
        }
        Ok(None)
    }
}

impl ChainClient for EvmRpcClient {
    fn network_id(&self) -> NetworkId {
        EvmRpcClient::network_id(self)
    }

    fn sources(&self) -> Vec<EvidenceSourceId> {
        vec![self.cfg.source_id.clone()]
    }

    fn submit(&self, signed: &SignedTransaction) -> OicResult<ChainTxId> {
        let returned: [u8; 32] = data_fixed(
            &self.rpc.call_value("eth_sendRawTransaction", json!([to_hex(signed.signed_bytes.as_slice())]))?,
            "eth_sendRawTransaction",
        )?;
        let local = tx_hash(signed.signed_bytes.as_slice());
        if returned != local {
            return Err(OicError::unverifiable(format!(
                "the node acknowledged hash {} for a transaction whose canonical hash is {}",
                hex::encode(returned),
                hex::encode(local)
            )));
        }
        Ok(tx_id(&returned))
    }

    fn evidence_for_tx(&self, source: &EvidenceSourceId, tx: &ChainTxId, commitment: Commitment) -> OicResult<EvidenceBundle> {
        self.check_source(source)?;
        let hash = parse_tx_id(tx)?;
        let view = self.block_by_tag(tag(commitment))?;
        let mut items = self.base_items(&view)?;
        let obs = self.observation(&view, &hash, &BTreeMap::new())?;
        items.insert(tx_key(&hash), Bytes(oic_canonical_encoding::canonical_bytes(&obs)?));
        self.bundle(view, commitment, items)
    }

    fn evidence_for_candidates(&self, source: &EvidenceSourceId, candidates: &[PossiblyIssued], commitment: Commitment) -> OicResult<EvidenceBundle> {
        self.check_source(source)?;
        let view = self.block_by_tag(tag(commitment))?;
        let mut items = self.base_items(&view)?;
        let mut known = BTreeMap::new();
        for c in candidates {
            let bytes = c.signed.signed_bytes.as_slice();
            let (tx, sig) = EvmTx::decode_signed(bytes)?;
            let sender = recover_address(&tx.signing_digest(), &sig)?;
            let hash = tx_hash(bytes);
            known.insert(hash, (sender, tx.nonce()));
            items.insert(nonce_key(&sender), self.nonce_item(&sender, &view)?);
            items.insert(signed_tx_key(c.candidate.candidate_id.as_str(), c.candidate.candidate_revision), Bytes(bytes.to_vec()));
        }
        for hash in known.keys() {
            let obs = self.observation(&view, hash, &known)?;
            items.insert(tx_key(hash), Bytes(oic_canonical_encoding::canonical_bytes(&obs)?));
        }
        self.bundle(view, commitment, items)
    }

    fn head(&self) -> StateReference {
        self.state_reference(LATEST_COMMITMENT)
    }

    fn finalized(&self) -> StateReference {
        self.state_reference(FINALITY_COMMITMENT)
    }
}

impl EvmRpcClient {
    fn check_source(&self, source: &EvidenceSourceId) -> OicResult<()> {
        if *source == self.cfg.source_id {
            Ok(())
        } else {
            Err(OicError::invalid_request(format!("evidence source {source} is not configured for this client")))
        }
    }

    /// `head`/`finalized` cannot return errors; an unreachable node reports
    /// height 0 with an empty hash, which no fresh evidence check accepts.
    fn state_reference(&self, tag: &str) -> StateReference {
        match self.block_by_tag(tag) {
            Ok(view) => StateReference { height: view.height, hash: Bytes(view.hash.to_vec()), commitment: tag.to_string() },
            Err(_) => StateReference { height: 0, hash: Bytes(Vec::new()), commitment: tag.to_string() },
        }
    }
}

impl BlockSource for EvmRpcClient {
    fn profile(&self) -> ChainProfile {
        EvmRpcClient::profile(self)
    }

    fn source_id(&self) -> EvidenceSourceId {
        self.cfg.source_id.clone()
    }

    fn now(&self) -> UnixSeconds {
        wall_clock()
    }

    fn head(&self) -> StateReference {
        self.state_reference(LATEST_COMMITMENT)
    }

    fn finalized(&self) -> StateReference {
        self.state_reference(FINALITY_COMMITMENT)
    }

    /// Discover nonzero fee, successful transaction-value, and classic ERC-20
    /// Transfer legs, mirroring the development-simulator source exactly so a
    /// movement is attributed identically whichever source observed it. With
    /// `trace_internal_transfers` on, internal native value legs join them.
    fn block(&self, height: u64) -> OicResult<IndexedBlock> {
        let block = self.rpc.call_value("eth_getBlockByNumber", json!([to_quantity(height), true]))?;
        if block.is_null() {
            return Err(OicError::stale_evidence("missing block; backfill required"));
        }
        let header = BlockHeader::decode(&block)?;
        let receipts = self.rpc.call_value("eth_getBlockReceipts", json!([to_quantity(height)]))?;
        let receipts = receipts
            .as_array()
            .ok_or_else(|| OicError::stale_evidence("eth_getBlockReceipts did not return a list"))?;
        let txs = transactions(&block)?;
        if txs.len() != receipts.len() {
            return Err(OicError::stale_evidence("block transactions and receipts differ in length"));
        }
        let state = StateReference { height, hash: Bytes(header.hash.to_vec()), commitment: LATEST_COMMITMENT.to_string() };
        let mut effects = Vec::new();
        // Per transaction: the first effect index a trace leg may use, past
        // the fee, value and log legs numbered below.
        let mut trace_bases = Vec::with_capacity(txs.len());
        for (tx, receipt) in txs.iter().zip(receipts) {
            let hash: [u8; 32] = data_fixed(&tx["hash"], "tx hash")?;
            // The two reads race a reorg: bind every receipt to this exact
            // block and transaction before pairing their fields.
            if data_fixed::<32>(&receipt["blockHash"], "receipt blockHash")? != header.hash
                || data_fixed::<32>(&receipt["transactionHash"], "receipt transactionHash")? != hash
            {
                return Err(OicError::stale_evidence("receipts belong to a different block; backfill required"));
            }
            let id = tx_id(&hash);
            let from: Address = data_fixed(&tx["from"], "tx from")?;
            let to: Address = match &tx["to"] {
                Value::Null => [0; 20],
                v => data_fixed(v, "tx to")?,
            };
            let value = quantity_u128(&tx["value"], "tx value")?;
            let success = quantity_u64(&receipt["status"], "receipt status")? == 1;
            let fee = u128::from(quantity_u64(&receipt["gasUsed"], "receipt gasUsed")?)
                .checked_mul(quantity_u128(&receipt["effectiveGasPrice"], "receipt effectiveGasPrice")?)
                .ok_or_else(|| OicError::unverifiable("fee overflows u128"))?;
            let mut push = |index, address: Address, counterparty: Address, direction, asset, amount, mechanism, kind| {
                if amount > 0 {
                    effects.push(ChainEffect {
                        tx_id: id.clone(),
                        index,
                        address: Bytes(address.to_vec()),
                        counterparty: Bytes(counterparty.to_vec()),
                        direction,
                        asset,
                        amount: Amount(amount),
                        mechanism,
                        kind,
                    });
                }
            };
            push(0, from, [0; 20], MovementDirection::Outbound, AssetKind::Native, fee, DiscoveryMechanism::EvmTransactionValue, EffectKind::Fee);
            let log_count = receipt["logs"].as_array().map(Vec::len).unwrap_or(0);
            trace_bases.push(
                u32::try_from(log_count)
                    .ok()
                    .and_then(|n| n.checked_mul(2))
                    .and_then(|n| n.checked_add(3))
                    .ok_or_else(|| OicError::unverifiable("too many logs"))?,
            );
            if success {
                push(1, from, to, MovementDirection::Outbound, AssetKind::Native, value, DiscoveryMechanism::EvmTransactionValue, EffectKind::Transfer);
                push(2, to, from, MovementDirection::Inbound, AssetKind::Native, value, DiscoveryMechanism::EvmTransactionValue, EffectKind::Transfer);
                let logs = receipt["logs"].as_array().ok_or_else(|| OicError::stale_evidence("receipt logs is not a list"))?;
                for (i, log) in logs.iter().enumerate() {
                    let topics = log["topics"].as_array().ok_or_else(|| OicError::stale_evidence("log topics is not a list"))?;
                    if topics.len() != 3 || data_fixed::<32>(&topics[0], "log topic0")? != transfer_topic0() {
                        continue;
                    }
                    let data = data_bytes(&log["data"], "log data")?;
                    let t1: [u8; 32] = data_fixed(&topics[1], "log topic1")?;
                    let t2: [u8; 32] = data_fixed(&topics[2], "log topic2")?;
                    if data.len() != 32 || data[..16].iter().any(|b| *b != 0) || t1[..12].iter().chain(&t2[..12]).any(|b| *b != 0) {
                        return Err(OicError::unverifiable("malformed Transfer log"));
                    }
                    let log_from: Address = t1[12..].try_into().expect("20 bytes");
                    let log_to: Address = t2[12..].try_into().expect("20 bytes");
                    let amount = u128::from_be_bytes(data[16..].try_into().expect("16 bytes"));
                    let contract: Address = data_fixed(&log["address"], "log address")?;
                    let asset = AssetKind::Erc20 { contract: Bytes(contract.to_vec()) };
                    let index = u32::try_from(i)
                        .ok()
                        .and_then(|i| i.checked_mul(2))
                        .and_then(|i| i.checked_add(3))
                        .ok_or_else(|| OicError::unverifiable("too many logs"))?;
                    push(index, log_from, log_to, MovementDirection::Outbound, asset.clone(), amount, DiscoveryMechanism::EvmErc20TransferLog, EffectKind::Transfer);
                    push(index + 1, log_to, log_from, MovementDirection::Inbound, asset, amount, DiscoveryMechanism::EvmErc20TransferLog, EffectKind::Transfer);
                }
            }
        }
        if self.cfg.trace_internal_transfers {
            self.trace_effects(txs, &trace_bases, &mut effects)?;
        }
        Ok(IndexedBlock { state, parent_hash: Bytes(header.parent_hash.to_vec()), effects })
    }

    fn balance(&self, state: &StateReference, address: &Bytes, asset: &AssetKind) -> OicResult<Amount> {
        let address: Address = address
            .as_slice()
            .try_into()
            .map_err(|_| OicError::invalid_request("EVM address length"))?;
        let at = json!({ "blockHash": to_hex(state.hash.as_slice()), "requireCanonical": true });
        match asset {
            AssetKind::Native => Ok(Amount(quantity_u128(
                &self.rpc.call_value("eth_getBalance", json!([to_hex(&address), at]))?,
                "eth_getBalance",
            )?)),
            AssetKind::Erc20 { contract } => {
                // balanceOf(address): selector 70a08231 + left-padded address.
                let mut data = vec![0x70, 0xa0, 0x82, 0x31];
                data.extend_from_slice(&[0; 12]);
                data.extend_from_slice(&address);
                let call = json!({ "to": to_hex(contract.as_slice()), "input": to_hex(&data) });
                let out = data_bytes(&self.rpc.call_value("eth_call", json!([call, at]))?, "eth_call")?;
                let word: [u8; 32] = out
                    .as_slice()
                    .try_into()
                    .map_err(|_| OicError::unverifiable("balanceOf returned a non-word value"))?;
                if word[..16].iter().any(|b| *b != 0) {
                    return Err(OicError::unverifiable("balanceOf exceeds u128"));
                }
                Ok(Amount(u128::from_be_bytes(word[16..].try_into().expect("16 bytes"))))
            }
            AssetKind::SplToken { .. } => Err(OicError::unsupported("SPL tokens are not an EVM asset")),
        }
    }
}

impl EvmRpcClient {
    /// Native value moved by successful internal frames, from each
    /// transaction's callTracer trace. `debug_traceTransaction` is the most
    /// widely supported trace API and binds every trace to its hash. Loud by
    /// design: a node that refuses a call or returns a malformed trace fails
    /// the whole read - partial effect lists would quietly turn real
    /// movements invisible again.
    ///
    /// Counted frames: CALL, CREATE, CREATE2 and SELFDESTRUCT with nonzero
    /// value, outside reverted subtrees. The root frame is the transaction
    /// itself, already discovered as transaction value. DELEGATECALL,
    /// STATICCALL and CALLCODE move no value between distinct accounts (some
    /// nodes still echo a value field on them), so they are skipped.
    fn trace_effects(&self, txs: &[Value], bases: &[u32], effects: &mut Vec<ChainEffect>) -> OicResult<()> {
        for (tx, base) in txs.iter().zip(bases) {
            let hash: [u8; 32] = data_fixed(&tx["hash"], "tx hash")?;
            let root = self
                .rpc
                .call_value("debug_traceTransaction", json!([to_hex(&hash), { "tracer": "callTracer" }]))?;
            // A node that ignores the tracer argument answers with struct
            // logs; silence on that shape would hide real movements.
            if root.get("type").and_then(Value::as_str).is_none() {
                return Err(OicError::unverifiable("the node did not honor the callTracer"));
            }
            if root.get("error").is_some_and(|e| !e.is_null()) {
                continue; // the whole transaction reverted; nothing persisted
            }
            let root = &root;
            let id = tx_id(&hash);
            let mut next = *base;
            // Iterative walk: a hostile node must not pick our stack depth.
            let mut frames: Vec<&Value> = subcalls(root)?.iter().rev().collect();
            while let Some(frame) = frames.pop() {
                if frame.get("error").is_some_and(|e| !e.is_null()) {
                    continue; // reverted subtree: its effects were rolled back
                }
                let kind = frame["type"].as_str().ok_or_else(|| OicError::unverifiable("trace frame has no type"))?;
                let value = match frame.get("value") {
                    None | Some(Value::Null) => 0,
                    Some(v) => quantity_u128(v, "frame value")?,
                };
                if matches!(kind, "CALL" | "CREATE" | "CREATE2" | "SELFDESTRUCT") && value > 0 {
                    let from: Address = data_fixed(&frame["from"], "frame from")?;
                    let to: Address = data_fixed(&frame["to"], "frame to")?;
                    for (index, address, counterparty, direction) in
                        [(next, from, to, MovementDirection::Outbound), (next + 1, to, from, MovementDirection::Inbound)]
                    {
                        effects.push(ChainEffect {
                            tx_id: id.clone(),
                            index,
                            address: Bytes(address.to_vec()),
                            counterparty: Bytes(counterparty.to_vec()),
                            direction,
                            asset: AssetKind::Native,
                            amount: Amount(value),
                            mechanism: DiscoveryMechanism::EvmInternalCallValue,
                            kind: EffectKind::Transfer,
                        });
                    }
                    next = next.checked_add(2).ok_or_else(|| OicError::unverifiable("too many internal transfers"))?;
                }
                for child in subcalls(frame)?.iter().rev() {
                    frames.push(child);
                }
            }
        }
        Ok(())
    }
}

fn tag(commitment: Commitment) -> &'static str {
    commitment_str(commitment)
}

fn commitment_str(commitment: Commitment) -> &'static str {
    match commitment {
        Commitment::Latest => LATEST_COMMITMENT,
        Commitment::Finalized => FINALITY_COMMITMENT,
    }
}

fn wall_clock() -> UnixSeconds {
    UnixSeconds(SystemTime::now().duration_since(UNIX_EPOCH).expect("time went backwards").as_secs())
}

/// EIP-1898 block reference pinning reads to the view block by hash.
fn block_ref(view: &BlockHeader) -> Value {
    json!({ "blockHash": to_hex(&view.hash), "requireCanonical": true })
}

fn transactions(block: &Value) -> OicResult<&Vec<Value>> {
    block["transactions"]
        .as_array()
        .ok_or_else(|| OicError::stale_evidence("block transactions is not a list"))
}

/// A callTracer frame's child frames; absent means none.
fn subcalls(frame: &Value) -> OicResult<&[Value]> {
    match frame.get("calls") {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(calls)) => Ok(calls),
        Some(_) => Err(OicError::unverifiable("trace calls is not a list")),
    }
}

/// The header fields this client reads from `eth_getBlockByNumber`.
struct BlockHeader {
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    base_fee: u128,
}

impl BlockHeader {
    fn decode(v: &Value) -> OicResult<Self> {
        Ok(BlockHeader {
            height: quantity_u64(&v["number"], "block number")?,
            hash: data_fixed(&v["hash"], "block hash")?,
            parent_hash: data_fixed(&v["parentHash"], "block parentHash")?,
            base_fee: quantity_u128(&v["baseFeePerGas"], "block baseFeePerGas")?,
        })
    }
}
