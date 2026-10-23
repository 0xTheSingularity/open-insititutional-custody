//! Solana JSON-RPC chain client for live development networks
//! (`solana-test-validator`, devnet).
//!
//! Implements the broadcaster's [`ChainClient`] and the reconciler's
//! [`BlockSource`] against the standard Solana RPC API, assembling the
//! [`EvidenceBundle`] items the Solana adapter documents in
//! `oic_adapter_solana::evidence`. This is the genuinely threshold-signed
//! path: FROST Ed25519 shares aggregate to the standard signature Solana
//! verifies.
//!
//! Honest limits, stated rather than papered over:
//! - A validity height for an arbitrary old blockhash is not queryable over
//!   RPC, so only the view blockhash gets its own `blockhash_last_valid_height:`
//!   item; the adapter's documented fallback to the bundle-wide key covers the
//!   rest.
//! - `lastValidBlockHeight` is a block height while evidence states carry
//!   slots. On an unskipped development chain they coincide; this client is
//!   not mainnet qualification.
//! - Historical balances are not queryable over plain RPC. [`BlockSource::balance`]
//!   answers only while the node still stands at the checkpoint's slot and
//!   returns `StaleEvidence` otherwise.
//! - Address lookup tables are not resolved yet; evidence for a candidate that
//!   needs one reports `UnsupportedCapability`.

use crate::jsonrpc::Endpoint;
use oic_adapter_api::{ChainProfile, SignedTransaction};
use oic_adapter_solana::address::{from_base58, to_base58, Pubkey, TOKEN_PROGRAM_ID};
use oic_adapter_solana::evidence::{
    last_valid_height_key, signed_tx_key, token_account_key, tx_key, TokenAccountEvidence, TxObservation, COMMITMENT_CONFIRMED,
    COMMITMENT_FINALIZED, COMMITMENT_PROCESSED, KEY_BLOCKHASH_LAST_VALID_HEIGHT, KEY_GENESIS_HASH, KEY_LAMPORTS_PER_SIGNATURE,
    KEY_RECENT_BLOCKHASH, KEY_RENT_TOKEN_ACCOUNT,
};
use oic_adapter_solana::message::Transaction;
use oic_adapter_solana::{ADAPTER_ID, VERSION_LEGACY, VERSION_V0};
use oic_chain_simulator::solana::{parse_tx_id, tx_id, TOKEN_ACCOUNT_LEN};
use oic_chain_simulator::{EVIDENCE_MAX_STALENESS_SECONDS, PROFILE_MAX_EVIDENCE_AGE_SECONDS};
use oic_domain_types::*;
use oic_service_broadcaster::{ChainClient, Commitment, PossiblyIssued};
use oic_service_reconciler::{BlockSource, ChainEffect, EffectKind, IndexedBlock};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Chain profile id for a live Solana endpoint.
pub const CHAIN_PROFILE_ID: &str = "solana-rpc-v1";
/// Version string recorded in produced evidence bundles.
pub const VERIFIER_VERSION: &str = concat!("oic-chain-rpc/", env!("CARGO_PKG_VERSION"));

/// Configuration for [`SolanaRpcClient::connect`].
pub struct SolanaRpcConfig {
    pub url: String,
    pub source_id: EvidenceSourceId,
    pub display_name: String,
    pub timeout: Duration,
    pub trust_level: EvidenceTrustLevel,
    /// `Included -> Finalized` confirmations recorded in the profile.
    pub finality_depth: u64,
    /// Base fee reported as build evidence; verified against observations later.
    pub lamports_per_signature: u64,
}

impl SolanaRpcConfig {
    /// Single-provider profile for a local test validator.
    pub fn development(url: impl Into<String>) -> Self {
        SolanaRpcConfig {
            url: url.into(),
            source_id: EvidenceSourceId::unchecked("solana-rpc"),
            display_name: "Solana development network".into(),
            timeout: Duration::from_secs(15),
            trust_level: EvidenceTrustLevel::SingleProvider,
            finality_depth: 4,
            lamports_per_signature: 5_000,
        }
    }
}

/// Live Solana node speaking standard JSON-RPC.
pub struct SolanaRpcClient {
    rpc: Endpoint,
    cfg: SolanaRpcConfig,
    genesis_hash: [u8; 32],
    network_id: NetworkId,
}

impl SolanaRpcClient {
    /// Connect and bind to the node's genesis hash, the network identity the
    /// adapter re-checks on every verification.
    pub fn connect(cfg: SolanaRpcConfig) -> OicResult<Self> {
        let rpc = Endpoint::new(cfg.url.clone(), cfg.timeout)?;
        let genesis: String = rpc.call("getGenesisHash", json!([]))?;
        let genesis_hash = from_base58(&genesis)?;
        let network_id = NetworkId::unchecked(format!("solana-{}", &to_base58(&genesis_hash)[..8]));
        Ok(SolanaRpcClient { rpc, cfg, genesis_hash, network_id })
    }

    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub fn profile(&self) -> ChainProfile {
        ChainProfile {
            chain_profile_id: ChainProfileId::unchecked(CHAIN_PROFILE_ID),
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            network_id: self.network_id.clone(),
            network_binding: Bytes(self.genesis_hash.to_vec()),
            display_name: self.cfg.display_name.clone(),
            accepted_versions: vec![VERSION_LEGACY.to_string(), VERSION_V0.to_string()],
            finality_commitment: COMMITMENT_FINALIZED.to_string(),
            finality_depth: self.cfg.finality_depth,
            max_evidence_age_seconds: PROFILE_MAX_EVIDENCE_AGE_SECONDS,
            accepted_trust_levels: vec![self.cfg.trust_level],
        }
    }

    /// Evidence for building a candidate: the current blockhash, fees, rent,
    /// and the named SPL token accounts at the requested view.
    pub fn build_evidence(&self, token_accounts: &[Pubkey], commitment: Commitment) -> OicResult<EvidenceBundle> {
        let view = self.view(commitment)?;
        let mut items = self.base_items(&view)?;
        for account in token_accounts {
            items.insert(token_account_key(account), Bytes(oic_canonical_encoding::canonical_bytes(&self.token_account(account, commitment)?)?));
        }
        self.bundle(view, items)
    }

    fn commitment_arg(commitment: Commitment) -> &'static str {
        match commitment {
            Commitment::Latest => COMMITMENT_PROCESSED,
            Commitment::Finalized => COMMITMENT_FINALIZED,
        }
    }

    /// The view the bundle is anchored at: the latest blockhash at the
    /// commitment, with its slot and validity horizon.
    fn view(&self, commitment: Commitment) -> OicResult<View> {
        self.view_at(Self::commitment_arg(commitment))
    }

    fn view_at(&self, c: &'static str) -> OicResult<View> {
        let v = self.rpc.call_value("getLatestBlockhash", json!([{ "commitment": c }]))?;
        let slot = v["context"]["slot"]
            .as_u64()
            .ok_or_else(|| OicError::stale_evidence("getLatestBlockhash has no context slot"))?;
        let blockhash = from_base58(
            v["value"]["blockhash"]
                .as_str()
                .ok_or_else(|| OicError::stale_evidence("getLatestBlockhash has no blockhash"))?,
        )?;
        let last_valid = v["value"]["lastValidBlockHeight"]
            .as_u64()
            .ok_or_else(|| OicError::stale_evidence("getLatestBlockhash has no lastValidBlockHeight"))?;
        Ok(View { slot, blockhash, last_valid, commitment: c })
    }

    fn base_items(&self, view: &View) -> OicResult<BTreeMap<String, Bytes>> {
        let le = |v: u64| Bytes(v.to_le_bytes().to_vec());
        let mut items = BTreeMap::new();
        items.insert(KEY_GENESIS_HASH.to_string(), Bytes(self.genesis_hash.to_vec()));
        items.insert(KEY_RECENT_BLOCKHASH.to_string(), Bytes(view.blockhash.to_vec()));
        items.insert(KEY_BLOCKHASH_LAST_VALID_HEIGHT.to_string(), le(view.last_valid));
        items.insert(last_valid_height_key(&view.blockhash), le(view.last_valid));
        items.insert(KEY_LAMPORTS_PER_SIGNATURE.to_string(), le(self.cfg.lamports_per_signature));
        let rent: u64 = self.rpc.call("getMinimumBalanceForRentExemption", json!([TOKEN_ACCOUNT_LEN]))?;
        items.insert(KEY_RENT_TOKEN_ACCOUNT.to_string(), le(rent));
        Ok(items)
    }

    fn bundle(&self, view: View, items: BTreeMap<String, Bytes>) -> OicResult<EvidenceBundle> {
        Ok(EvidenceBundle {
            chain_profile_id: ChainProfileId::unchecked(CHAIN_PROFILE_ID),
            network_id: self.network_id.clone(),
            state: StateReference { height: view.slot, hash: Bytes(view.blockhash.to_vec()), commitment: view.commitment.to_string() },
            sources: vec![self.cfg.source_id.clone()],
            trust_level: self.cfg.trust_level,
            observed_at: wall_clock(),
            max_staleness_seconds: EVIDENCE_MAX_STALENESS_SECONDS,
            verifier_version: VERIFIER_VERSION.to_string(),
            items,
        })
    }

    /// Decoded SPL token account at the commitment.
    fn token_account(&self, account: &Pubkey, commitment: Commitment) -> OicResult<TokenAccountEvidence> {
        let c = Self::commitment_arg(commitment);
        let v = self
            .rpc
            .call_value("getAccountInfo", json!([to_base58(account), { "encoding": "base64", "commitment": c }]))?;
        let value = &v["value"];
        if value.is_null() {
            return Err(OicError::stale_evidence(format!("account {} does not exist at {c}", to_base58(account))));
        }
        let owner = value["owner"].as_str().unwrap_or_default();
        if from_base58(owner)? != TOKEN_PROGRAM_ID {
            return Err(OicError::invalid_request(format!("account {} is not an SPL token account", to_base58(account))));
        }
        let data = account_data(value)?;
        decode_spl_token_account(&data)
    }

    /// Observation of one signature; `None` while no supported commitment has it.
    fn observation(&self, signature: &[u8; 64]) -> OicResult<Option<TxObservation>> {
        let sig = to_base58(signature);
        // `getTransaction` serves confirmed and finalized only; a transaction
        // seen merely at `processed` is not yet evidence.
        let v = self
            .rpc
            .call_value("getTransaction", json!([sig, { "commitment": COMMITMENT_CONFIRMED, "maxSupportedTransactionVersion": 0, "encoding": "json" }]))?;
        if v.is_null() {
            return Ok(None);
        }
        let slot = v["slot"].as_u64().ok_or_else(|| OicError::stale_evidence("getTransaction has no slot"))?;
        let meta = &v["meta"];
        let err = &meta["err"];
        let fee = meta["fee"].as_u64().ok_or_else(|| OicError::stale_evidence("getTransaction has no fee"))?;
        let statuses = self
            .rpc
            .call_value("getSignatureStatuses", json!([[sig], { "searchTransactionHistory": true }]))?;
        let commitment = statuses["value"][0]["confirmationStatus"]
            .as_str()
            .unwrap_or(COMMITMENT_CONFIRMED)
            .to_string();
        // The inclusion block's blockhash anchors the observation.
        let block = self
            .rpc
            .call_value("getBlock", json!([slot, { "transactionDetails": "none", "rewards": false, "commitment": COMMITMENT_CONFIRMED, "maxSupportedTransactionVersion": 0 }]))?;
        let blockhash = from_base58(
            block["blockhash"]
                .as_str()
                .ok_or_else(|| OicError::stale_evidence("inclusion block has no blockhash"))?,
        )?;
        let post_balances = u64_list(&meta["postBalances"], "postBalances")?;
        let account_funding = created_token_accounts(meta)?
            .into_iter()
            .map(|index| post_balances.get(index).copied().unwrap_or(0))
            .sum();
        Ok(Some(TxObservation {
            slot,
            block_hash: Bytes(blockhash.to_vec()),
            commitment,
            success: err.is_null(),
            fee,
            account_funding: if err.is_null() { account_funding } else { 0 },
            err: if err.is_null() { None } else { Some(err.to_string()) },
        }))
    }
}

/// The resolved anchor of one evidence bundle.
struct View {
    slot: u64,
    blockhash: [u8; 32],
    last_valid: u64,
    commitment: &'static str,
}

impl ChainClient for SolanaRpcClient {
    fn network_id(&self) -> NetworkId {
        self.network_id.clone()
    }

    fn sources(&self) -> Vec<EvidenceSourceId> {
        vec![self.cfg.source_id.clone()]
    }

    fn submit(&self, signed: &SignedTransaction) -> OicResult<ChainTxId> {
        let tx = Transaction::decode(signed.signed_bytes.as_slice())?;
        let local = *tx
            .signatures
            .first()
            .ok_or_else(|| OicError::invalid_request("a signed transaction needs a signature"))?;
        let returned: String = self.rpc.call(
            "sendTransaction",
            json!([bs58::encode(signed.signed_bytes.as_slice()).into_string(), { "encoding": "base58", "preflightCommitment": COMMITMENT_PROCESSED }]),
        )?;
        let returned = bs58::decode(&returned)
            .into_vec()
            .ok()
            .and_then(|v| <[u8; 64]>::try_from(v).ok())
            .ok_or_else(|| OicError::unverifiable("the node acknowledged a non-signature id"))?;
        if returned != local {
            return Err(OicError::unverifiable("the node acknowledged a different signature than the transaction's"));
        }
        Ok(tx_id(&local))
    }

    fn evidence_for_tx(&self, source: &EvidenceSourceId, tx: &ChainTxId, commitment: Commitment) -> OicResult<EvidenceBundle> {
        self.check_source(source)?;
        let signature = parse_tx_id(tx)?;
        let view = self.view(commitment)?;
        let mut items = self.base_items(&view)?;
        if let Some(obs) = self.observation(&signature)? {
            items.insert(tx_key(&signature), Bytes(oic_canonical_encoding::canonical_bytes(&obs)?));
        }
        self.bundle(view, items)
    }

    fn evidence_for_candidates(&self, source: &EvidenceSourceId, candidates: &[PossiblyIssued], commitment: Commitment) -> OicResult<EvidenceBundle> {
        self.check_source(source)?;
        let view = self.view(commitment)?;
        let mut items = self.base_items(&view)?;
        for c in candidates {
            let bytes = c.signed.signed_bytes.as_slice();
            let tx = Transaction::decode(bytes)?;
            if !tx.message.address_table_lookups.is_empty() {
                return Err(OicError::unsupported("address lookup tables are not resolved by this client yet"));
            }
            items.insert(signed_tx_key(c.candidate.candidate_id.as_str(), c.candidate.candidate_revision), Bytes(bytes.to_vec()));
            for signature in &tx.signatures {
                if let Some(obs) = self.observation(signature)? {
                    items.insert(tx_key(signature), Bytes(oic_canonical_encoding::canonical_bytes(&obs)?));
                }
            }
        }
        self.bundle(view, items)
    }

    fn head(&self) -> StateReference {
        self.state_reference(Commitment::Latest)
    }

    fn finalized(&self) -> StateReference {
        self.state_reference(Commitment::Finalized)
    }
}

impl SolanaRpcClient {
    fn check_source(&self, source: &EvidenceSourceId) -> OicResult<()> {
        if *source == self.cfg.source_id {
            Ok(())
        } else {
            Err(OicError::invalid_request(format!("evidence source {source} is not configured for this client")))
        }
    }

    /// `head`/`finalized` cannot return errors; an unreachable node reports
    /// slot 0 with an empty hash, which no fresh evidence check accepts.
    fn state_reference(&self, commitment: Commitment) -> StateReference {
        let c = Self::commitment_arg(commitment);
        match self.view(commitment) {
            Ok(view) => StateReference { height: view.slot, hash: Bytes(view.blockhash.to_vec()), commitment: c.to_string() },
            Err(_) => StateReference { height: 0, hash: Bytes(Vec::new()), commitment: c.to_string() },
        }
    }
}

impl BlockSource for SolanaRpcClient {
    fn profile(&self) -> ChainProfile {
        SolanaRpcClient::profile(self)
    }

    fn source_id(&self) -> EvidenceSourceId {
        self.cfg.source_id.clone()
    }

    fn now(&self) -> UnixSeconds {
        wall_clock()
    }

    fn head(&self) -> StateReference {
        // The scan head must sit at the tier the block reader serves: a
        // processed-tip head makes sync chase slots `getBlock(confirmed)`
        // cannot serve yet, which surfaces as a permanent "missing block".
        match self.view_at(COMMITMENT_CONFIRMED) {
            Ok(view) => StateReference {
                height: view.slot,
                hash: Bytes(view.blockhash.to_vec()),
                commitment: COMMITMENT_CONFIRMED.to_string(),
            },
            Err(_) => StateReference { height: 0, hash: Bytes(Vec::new()), commitment: COMMITMENT_CONFIRMED.to_string() },
        }
    }

    fn finalized(&self) -> StateReference {
        self.state_reference(Commitment::Finalized)
    }

    /// Discover lamport and classic-token deltas, separating fees and newly
    /// funded token-account rent from transfers — the simulator source's
    /// semantics applied to `getBlock` metadata.
    fn block(&self, height: u64) -> OicResult<IndexedBlock> {
        let block = self.rpc.call_value(
            "getBlock",
            json!([height, { "encoding": "json", "transactionDetails": "full", "rewards": false, "commitment": COMMITMENT_CONFIRMED, "maxSupportedTransactionVersion": 0 }]),
        );
        let block = match block {
            Ok(v) if !v.is_null() => v,
            // A skipped or not-yet-available slot is backfillable history.
            _ => return Err(OicError::stale_evidence("missing block; backfill required")),
        };
        let blockhash = from_base58(block["blockhash"].as_str().unwrap_or_default())?;
        let parent = from_base58(block["previousBlockhash"].as_str().unwrap_or_default())?;
        let state = StateReference { height, hash: Bytes(blockhash.to_vec()), commitment: COMMITMENT_PROCESSED.to_string() };
        let mut effects = Vec::new();
        let txs = block["transactions"]
            .as_array()
            .ok_or_else(|| OicError::stale_evidence("block transactions is not a list"))?;
        for entry in txs {
            let meta = &entry["meta"];
            let message = &entry["transaction"]["message"];
            let signature = entry["transaction"]["signatures"][0]
                .as_str()
                .ok_or_else(|| OicError::stale_evidence("transaction has no signature"))?;
            let id = ChainTxId::unchecked(signature.to_string());
            let mut account_keys = pubkey_list(&message["accountKeys"], "accountKeys")?;
            for key in &["writable", "readonly"] {
                if let Some(loaded) = meta["loadedAddresses"][key].as_array() {
                    for a in loaded {
                        account_keys.push(from_base58(a.as_str().unwrap_or_default())?);
                    }
                }
            }
            let fee = meta["fee"].as_u64().ok_or_else(|| OicError::stale_evidence("transaction has no fee"))?;
            let pre = u64_list(&meta["preBalances"], "preBalances")?;
            let post = u64_list(&meta["postBalances"], "postBalances")?;
            if pre.len() != account_keys.len() || post.len() != account_keys.len() {
                return Err(OicError::stale_evidence("balance lists do not match the account keys"));
            }
            let pre_tokens = token_balances(&meta["preTokenBalances"])?;
            let post_tokens = token_balances(&meta["postTokenBalances"])?;
            // Every token-balance index is untrusted RPC data: it must name
            // one of this transaction's accounts.
            for t in pre_tokens.iter().chain(&post_tokens) {
                if t.index >= account_keys.len() {
                    return Err(OicError::stale_evidence("token balance names an account index outside the transaction"));
                }
            }
            if account_keys.is_empty() {
                return Err(OicError::stale_evidence("a transaction needs at least its fee payer account"));
            }
            let mut index = 0;
            let mut push = |address: Pubkey, asset, pre_amount: u128, post_amount: u128, mechanism, kind| {
                if pre_amount != post_amount {
                    effects.push(ChainEffect {
                        tx_id: id.clone(),
                        index,
                        address: Bytes(address.to_vec()),
                        counterparty: Bytes::default(),
                        direction: if pre_amount > post_amount { MovementDirection::Outbound } else { MovementDirection::Inbound },
                        asset,
                        amount: Amount(pre_amount.abs_diff(post_amount)),
                        mechanism,
                        kind,
                    });
                }
                index += 1;
            };
            let payer = account_keys[0];
            push(payer, AssetKind::Native, fee as u128, 0, DiscoveryMechanism::SolanaLamportDelta, EffectKind::Fee);
            // Attribute newly created token-account rent separately from fees.
            let created: Vec<usize> = post_tokens
                .iter()
                .filter(|t| !pre_tokens.iter().any(|p| p.index == t.index))
                .map(|t| t.index)
                .collect();
            let mut rent = 0u128;
            for i in &created {
                let amount = post[*i] as u128;
                rent = rent.checked_add(amount).ok_or_else(|| OicError::unverifiable("rent overflow"))?;
                push(
                    payer,
                    AssetKind::Native,
                    amount,
                    0,
                    DiscoveryMechanism::SolanaLamportDelta,
                    EffectKind::AccountFunding { account: Bytes(account_keys[*i].to_vec()) },
                );
            }
            for (i, account) in account_keys.iter().enumerate() {
                // Token-account rent is not the owner's spendable native holdings.
                if pre_tokens.iter().chain(&post_tokens).any(|t| t.index == i) {
                    continue;
                }
                let post_adjusted = post[i] as u128 + if i == 0 { fee as u128 + rent } else { 0 };
                push(*account, AssetKind::Native, pre[i] as u128, post_adjusted, DiscoveryMechanism::SolanaLamportDelta, EffectKind::Transfer);
            }
            for t in &post_tokens {
                let pre_amount = pre_tokens.iter().find(|p| p.index == t.index).map(|p| p.amount).unwrap_or(0);
                push(
                    t.owner,
                    AssetKind::SplToken { mint: Bytes(t.mint.to_vec()), token_program: Bytes(TOKEN_PROGRAM_ID.to_vec()) },
                    pre_amount as u128,
                    t.amount as u128,
                    DiscoveryMechanism::SolanaTokenBalanceDelta,
                    EffectKind::Transfer,
                );
            }
        }
        Ok(IndexedBlock { state, parent_hash: Bytes(parent.to_vec()), effects })
    }

    /// Plain RPC has no historical balances: this answers only while the node
    /// still stands at the checkpoint's slot, and otherwise reports stale
    /// evidence so the caller re-anchors the checkpoint.
    fn balance(&self, state: &StateReference, address: &Bytes, asset: &AssetKind) -> OicResult<Amount> {
        let address: Pubkey = address
            .as_slice()
            .try_into()
            .map_err(|_| OicError::invalid_request("Solana address length"))?;
        let c = if state.commitment == COMMITMENT_FINALIZED { COMMITMENT_FINALIZED } else { COMMITMENT_PROCESSED };
        match asset {
            AssetKind::Native => {
                let v = self.rpc.call_value("getBalance", json!([to_base58(&address), { "commitment": c, "minContextSlot": state.height }]))?;
                let slot = v["context"]["slot"].as_u64().unwrap_or(0);
                if slot != state.height {
                    return Err(OicError::stale_evidence(format!(
                        "balance at slot {} is not queryable over RPC; the node answers at slot {slot}",
                        state.height
                    )));
                }
                Ok(Amount(v["value"].as_u64().unwrap_or(0) as u128))
            }
            AssetKind::SplToken { mint, .. } => {
                let v = self.rpc.call_value(
                    "getTokenAccountsByOwner",
                    json!([to_base58(&address), { "mint": to_base58(mint.as_slice()) }, { "encoding": "base64", "commitment": c, "minContextSlot": state.height }]),
                )?;
                let slot = v["context"]["slot"].as_u64().unwrap_or(0);
                if slot != state.height {
                    return Err(OicError::stale_evidence(format!(
                        "balance at slot {} is not queryable over RPC; the node answers at slot {slot}",
                        state.height
                    )));
                }
                let mut total: u128 = 0;
                for account in v["value"].as_array().unwrap_or(&Vec::new()) {
                    let data = account_data(&account["account"])?;
                    total = total
                        .checked_add(decode_spl_token_account(&data)?.amount as u128)
                        .ok_or_else(|| OicError::unverifiable("token balance overflows u128"))?;
                }
                Ok(Amount(total))
            }
            AssetKind::Erc20 { .. } => Err(OicError::unsupported("ERC-20 is not a Solana asset")),
        }
    }
}

fn wall_clock() -> UnixSeconds {
    UnixSeconds(SystemTime::now().duration_since(UNIX_EPOCH).expect("time went backwards").as_secs())
}

fn account_data(account: &Value) -> OicResult<Vec<u8>> {
    use base64::Engine as _;
    let encoded = account["data"][0]
        .as_str()
        .ok_or_else(|| OicError::stale_evidence("account data is not base64"))?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| OicError::stale_evidence("account data is not valid base64"))
}

fn u64_list(v: &Value, what: &str) -> OicResult<Vec<u64>> {
    v.as_array()
        .ok_or_else(|| OicError::stale_evidence(format!("{what} is not a list")))?
        .iter()
        .map(|x| x.as_u64().ok_or_else(|| OicError::stale_evidence(format!("{what} entry is not a u64"))))
        .collect()
}

fn pubkey_list(v: &Value, what: &str) -> OicResult<Vec<Pubkey>> {
    v.as_array()
        .ok_or_else(|| OicError::stale_evidence(format!("{what} is not a list")))?
        .iter()
        .map(|x| from_base58(x.as_str().unwrap_or_default()))
        .collect()
}

/// One decoded `preTokenBalances`/`postTokenBalances` entry.
struct TokenBalance {
    index: usize,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
}

/// Account indexes of token accounts this transaction created.
fn created_token_accounts(meta: &Value) -> OicResult<Vec<usize>> {
    let pre = token_balances(&meta["preTokenBalances"])?;
    Ok(token_balances(&meta["postTokenBalances"])?
        .into_iter()
        .filter(|t| !pre.iter().any(|p| p.index == t.index))
        .map(|t| t.index)
        .collect())
}

fn token_balances(v: &Value) -> OicResult<Vec<TokenBalance>> {
    let Some(list) = v.as_array() else { return Ok(Vec::new()) };
    list.iter()
        .map(|t| {
            Ok(TokenBalance {
                index: t["accountIndex"]
                    .as_u64()
                    .ok_or_else(|| OicError::stale_evidence("token balance has no accountIndex"))? as usize,
                mint: from_base58(t["mint"].as_str().unwrap_or_default())?,
                owner: from_base58(t["owner"].as_str().unwrap_or_default())?,
                amount: t["uiTokenAmount"]["amount"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| OicError::stale_evidence("token balance amount is not a u64 string"))?,
            })
        })
        .collect()
}

/// Decode the classic SPL token account layout (165 bytes).
fn decode_spl_token_account(data: &[u8]) -> OicResult<TokenAccountEvidence> {
    if data.len() != TOKEN_ACCOUNT_LEN {
        return Err(OicError::stale_evidence(format!("an SPL token account has {TOKEN_ACCOUNT_LEN} bytes, got {}", data.len())));
    }
    let coption_pubkey = |offset: usize| -> Option<Bytes> {
        let tag = u32::from_le_bytes(data[offset..offset + 4].try_into().expect("4 bytes"));
        (tag == 1).then(|| Bytes(data[offset + 4..offset + 36].to_vec()))
    };
    Ok(TokenAccountEvidence {
        mint: Bytes(data[0..32].to_vec()),
        owner: Bytes(data[32..64].to_vec()),
        amount: u64::from_le_bytes(data[64..72].try_into().expect("8 bytes")),
        delegate: coption_pubkey(72),
        state: data[108],
        close_authority: coption_pubkey(129),
    })
}
