//! Simulated Solana chain — DEVELOPMENT ONLY.
//!
//! Model:
//!
//! * One block per slot (no skipped slots), so block height == slot. Each slot
//!   has one blockhash; a blockhash produced at slot `s` is usable by a
//!   transaction included at slot `t` iff `t <= s + blockhash_validity_slots`
//!   (evidence `blockhash_last_valid_height = s + validity`).
//! * Accounts `{lamports, owner, data}`. SPL mints (82 bytes) and token
//!   accounts (165 bytes) are stored in the real classic SPL Token packed
//!   layouts and owned by the SPL Token program. Token-2022 is deliberately
//!   not modelled. Address lookup tables are kept in a separate table store.
//! * A simulator faucet keypair (Ed25519, derived from the seed) holds
//!   [`FAUCET_GENESIS_LAMPORTS`]; [`SolanaSimulator::airdrop`] is a real signed
//!   System transfer from it.
//! * [`SolanaSimulator::submit`] decodes with the pinned adapter decoder,
//!   verifies **every** required signature with `verify_strict` over the exact
//!   message bytes, checks the blockhash window, resolves lookup tables, decodes
//!   every instruction (System Transfer, Compute Budget limit/price, SPL Token
//!   `TransferChecked`, ATA Create/CreateIdempotent, Memo v1/v2), checks the fee
//!   payer can pay the fee, and queues the transaction. Any other program or
//!   instruction is refused at submission (the whole transaction, nothing is
//!   applied), as is a replayed signature.
//! * [`SolanaSimulator::advance_slot`] produces the next slot and includes the
//!   queue in arrival order. A queued transaction whose blockhash has expired
//!   (or is no longer canonical after a fork) or whose fee payer can no longer
//!   pay is dropped without effect. Otherwise the fee
//!   `num_signatures * lamports_per_signature + ceil(cu_limit * cu_price / 1e6)`
//!   (cu_limit defaults to 200 000 per non-compute-budget instruction, capped at
//!   1 400 000) is charged and the instructions run atomically: if any fails
//!   the transaction is recorded as failed (`err`), the fee stays charged and
//!   no instruction effect remains.
//! * Commitment of a slot `s` with head `H`: `processed` when `s == H`,
//!   `confirmed` when `s < H`, `finalized` when `s <= H - finality_depth`.
//! * **Not modelled:** rent collection and rent-exemption checks for system
//!   accounts (only token-account rent paid at ATA creation), delegates,
//!   multisig authorities, native (wrapped SOL) token accounts, durable nonces,
//!   lookup-table deactivation/extension, CPI, and any program other than those
//!   listed above.
//! * Setup operations ([`SolanaSimulator::create_mint`], [`SolanaSimulator::create_ata`],
//!   [`SolanaSimulator::mint_to`], [`SolanaSimulator::freeze_token_account`],
//!   [`SolanaSimulator::create_lookup_table`]) are *system operations*: they
//!   take effect at once for submission and queries, are recorded in (and
//!   visible to evidence from) the next slot, and are replayed after a fork.
//!   Their rent lamports are created out of band.
//! * Evidence omits `token_account:<a>` for an account that does not exist —
//!   that absence is exactly what makes the adapter add an ATA creation — and
//!   omits `tx:<sig>` for a signature that is not on the canonical chain at the
//!   evidence slot (the adapter then fails closed with `StaleEvidence`).

use crate::clock::SimClock;
use crate::{checked, lock, sha256_parts, EVIDENCE_MAX_STALENESS_SECONDS, PROFILE_MAX_EVIDENCE_AGE_SECONDS, VERIFIER_VERSION};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oic_adapter_api::ChainProfile;
use oic_adapter_solana::address::*;
use oic_adapter_solana::evidence::*;
use oic_adapter_solana::instruction::*;
use oic_adapter_solana::message::{Message, Transaction};
use oic_adapter_solana::{compile_legacy_message, InstructionSpec, ADAPTER_ID, VERSION_LEGACY, VERSION_V0};
use oic_domain_types::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

pub const CHAIN_PROFILE_ID: &str = "solana-devsim-v1";
pub const NETWORK_ID: &str = "solana-devsim";
/// Honest evidence source id.
pub const SOURCE_ID: &str = "devsim-solana";
pub const DEFAULT_FINALITY_DEPTH: u64 = 4;
pub const DEFAULT_BLOCKHASH_VALIDITY_SLOTS: u64 = 150;
pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
/// Rent-exempt minimum of a 165-byte token account.
pub const RENT_EXEMPT_TOKEN_ACCOUNT: u64 = 2_039_280;
/// Rent-exempt minimum of an 82-byte mint.
pub const RENT_EXEMPT_MINT: u64 = 1_461_600;
pub const DEFAULT_CU_LIMIT: u32 = 200_000;
/// Micro-lamports per compute unit.
pub const DEFAULT_CU_PRICE: u64 = 1_000;
/// 10^9 SOL.
pub const FAUCET_GENESIS_LAMPORTS: u64 = 1_000_000_000_000_000_000;
pub const TOKEN_ACCOUNT_LEN: usize = 165;
pub const MINT_LEN: usize = 82;
pub const MAX_LOOKUP_TABLE_ADDRESSES: usize = 256;

pub fn tx_id(sig: &[u8; 64]) -> ChainTxId {
    ChainTxId::unchecked(to_base58(sig))
}

pub fn parse_tx_id(id: &ChainTxId) -> OicResult<[u8; 64]> {
    let v = bs58::decode(id.as_str()).into_vec().map_err(|_| OicError::invalid_request("Solana tx id must be base58"))?;
    v.try_into().map_err(|_| OicError::invalid_request("Solana tx id must be a 64-byte signature"))
}

/// Keypair of a mint authority derived from a seed.
pub fn mint_authority_keypair(seed: &[u8]) -> SigningKey {
    SigningKey::from_bytes(&sha256_parts(&[b"oic-devsim-solana-mint-authority", seed]))
}

/// Public key of a mint authority derived from a seed.
pub fn mint_authority(seed: &[u8]) -> Pubkey {
    mint_authority_keypair(seed).verifying_key().to_bytes()
}

/// Serialize a signed transaction: sign `message_bytes` with each key in order.
pub fn sign_transaction(signers: &[&SigningKey], message_bytes: &[u8]) -> Vec<u8> {
    let sigs: Vec<[u8; 64]> = signers.iter().map(|k| k.sign(message_bytes).to_bytes()).collect();
    Transaction::encode(&sigs, message_bytes)
}

// ---------------------------------------------------------------------------
// packed SPL layouts
// ---------------------------------------------------------------------------

fn put_option(out: &mut Vec<u8>, v: &Option<Pubkey>) {
    match v {
        Some(k) => {
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(k);
        }
        None => out.extend_from_slice(&[0u8; 36]),
    }
}

fn get_option(b: &[u8]) -> OicResult<Option<Pubkey>> {
    match u32::from_le_bytes(b[..4].try_into().expect("4")) {
        0 if b[4..36].iter().all(|x| *x == 0) => Ok(None),
        1 => Ok(Some(b[4..36].try_into().expect("32"))),
        _ => Err(OicError::invalid_request("malformed COption<Pubkey>")),
    }
}

/// Classic SPL Token account (165-byte packed layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenAccountData {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    /// 0 uninitialized, 1 initialized, 2 frozen.
    pub state: u8,
    pub close_authority: Option<Pubkey>,
}

impl TokenAccountData {
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TOKEN_ACCOUNT_LEN);
        out.extend_from_slice(&self.mint);
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.amount.to_le_bytes());
        put_option(&mut out, &self.delegate);
        out.push(self.state);
        out.extend_from_slice(&[0u8; 12]); // is_native: COption<u64> = None
        out.extend_from_slice(&[0u8; 8]); // delegated_amount
        put_option(&mut out, &self.close_authority);
        out
    }

    /// Strict unpack; native (wrapped SOL) accounts and delegated amounts are rejected (not modelled).
    pub fn unpack(b: &[u8]) -> OicResult<Self> {
        if b.len() != TOKEN_ACCOUNT_LEN {
            return Err(OicError::invalid_request("token account data must be 165 bytes"));
        }
        let state = b[108];
        if state > TOKEN_ACCOUNT_FROZEN {
            return Err(OicError::invalid_request("token account state is invalid"));
        }
        if b[109..129].iter().any(|x| *x != 0) {
            return Err(OicError::invalid_request("native token accounts / delegated amounts are not modelled"));
        }
        Ok(TokenAccountData {
            mint: b[0..32].try_into().expect("32"),
            owner: b[32..64].try_into().expect("32"),
            amount: u64::from_le_bytes(b[64..72].try_into().expect("8")),
            delegate: get_option(&b[72..108])?,
            state,
            close_authority: get_option(&b[129..165])?,
        })
    }

    pub fn to_evidence(&self) -> TokenAccountEvidence {
        TokenAccountEvidence {
            mint: Bytes(self.mint.to_vec()),
            owner: Bytes(self.owner.to_vec()),
            amount: self.amount,
            delegate: self.delegate.map(|d| Bytes(d.to_vec())),
            close_authority: self.close_authority.map(|c| Bytes(c.to_vec())),
            state: self.state,
        }
    }
}

/// Classic SPL Token mint (82-byte packed layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintData {
    pub mint_authority: Option<Pubkey>,
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
    pub freeze_authority: Option<Pubkey>,
}

impl MintData {
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MINT_LEN);
        put_option(&mut out, &self.mint_authority);
        out.extend_from_slice(&self.supply.to_le_bytes());
        out.push(self.decimals);
        out.push(self.is_initialized as u8);
        put_option(&mut out, &self.freeze_authority);
        out
    }

    pub fn unpack(b: &[u8]) -> OicResult<Self> {
        if b.len() != MINT_LEN {
            return Err(OicError::invalid_request("mint data must be 82 bytes"));
        }
        let is_initialized = match b[45] {
            0 => false,
            1 => true,
            _ => return Err(OicError::invalid_request("mint is_initialized must be 0 or 1")),
        };
        Ok(MintData {
            mint_authority: get_option(&b[0..36])?,
            supply: u64::from_le_bytes(b[36..44].try_into().expect("8")),
            decimals: b[44],
            is_initialized,
            freeze_authority: get_option(&b[46..82])?,
        })
    }
}

// ---------------------------------------------------------------------------
// public data
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaSimConfig {
    /// Seeds the genesis hash and the faucet keypair.
    pub seed: [u8; 32],
    pub finality_depth: u64,
    pub blockhash_validity_slots: u64,
    pub lamports_per_signature: u64,
    pub rent_exempt_token_account: u64,
    /// Published as evidence `cu_limit` when `Some`.
    pub cu_limit: Option<u32>,
    /// Published as evidence `cu_price` when `Some`.
    pub cu_price: Option<u64>,
}

impl Default for SolanaSimConfig {
    fn default() -> Self {
        SolanaSimConfig {
            seed: [0u8; 32],
            finality_depth: DEFAULT_FINALITY_DEPTH,
            blockhash_validity_slots: DEFAULT_BLOCKHASH_VALIDITY_SLOTS,
            lamports_per_signature: LAMPORTS_PER_SIGNATURE,
            rent_exempt_token_account: RENT_EXEMPT_TOKEN_ACCOUNT,
            cu_limit: Some(DEFAULT_CU_LIMIT),
            cu_price: Some(DEFAULT_CU_PRICE),
        }
    }
}

impl SolanaSimConfig {
    pub fn with_seed(seed: [u8; 32]) -> Self {
        SolanaSimConfig { seed, ..Default::default() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SolanaAccount {
    pub lamports: u64,
    pub owner: Pubkey,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupTable {
    pub addresses: Vec<Pubkey>,
    pub last_extended_slot: u64,
}

/// Token balance of one account of a transaction (pre or post).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBalance {
    /// Index into the transaction's resolved account keys.
    pub account_index: usize,
    pub account: Pubkey,
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaTxRecord {
    pub signature: [u8; 64],
    pub slot: u64,
    pub success: bool,
    pub err: Option<String>,
    pub fee: u64,
    /// Static keys, then lookup-resolved writable, then readonly.
    pub account_keys: Vec<Pubkey>,
    pub pre_lamports: Vec<u64>,
    pub post_lamports: Vec<u64>,
    pub pre_token_balances: Vec<TokenBalance>,
    pub post_token_balances: Vec<TokenBalance>,
    pub signed_bytes: Vec<u8>,
}

impl SolanaTxRecord {
    pub fn tx_id(&self) -> ChainTxId {
        tx_id(&self.signature)
    }
}

/// Out-of-band setup operation recorded in a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SolanaSystemOp {
    CreateMint { mint: Pubkey, authority: Pubkey, decimals: u8 },
    CreateTokenAccount { account: Pubkey, owner: Pubkey, mint: Pubkey },
    MintTo { mint: Pubkey, account: Pubkey, amount: u64 },
    FreezeAccount { account: Pubkey },
    CreateLookupTable { table: Pubkey, addresses: Vec<Pubkey> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaBlock {
    pub slot: u64,
    pub blockhash: [u8; 32],
    pub parent_blockhash: [u8; 32],
    /// Fork counter at production time (0 before any fork).
    pub fork: u64,
    pub timestamp: UnixSeconds,
    pub system_ops: Vec<SolanaSystemOp>,
    pub transactions: Vec<SolanaTxRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SolanaTxStatus {
    Queued,
    Included { slot: u64, blockhash: [u8; 32], commitment: String, success: bool, fee: u64, err: Option<String> },
    Dropped { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SolanaCommitment {
    #[default]
    Processed,
    Confirmed,
    Finalized,
}

impl SolanaCommitment {
    pub fn as_str(self) -> &'static str {
        match self {
            SolanaCommitment::Processed => COMMITMENT_PROCESSED,
            SolanaCommitment::Confirmed => COMMITMENT_CONFIRMED,
            SolanaCommitment::Finalized => COMMITMENT_FINALIZED,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTxItem {
    pub candidate_id: String,
    pub revision: u32,
    pub signed_bytes: Vec<u8>,
}

/// What an evidence bundle should contain beyond the always-present network,
/// blockhash and fee items.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SolanaEvidenceQuery {
    pub commitment: SolanaCommitment,
    pub token_accounts: Vec<Pubkey>,
    pub lookup_tables: Vec<Pubkey>,
    pub signatures: Vec<[u8; 64]>,
    /// Extra `blockhash_last_valid_height:<hash>` items (invalidation proofs).
    pub blockhashes: Vec<[u8; 32]>,
    pub signed_txs: Vec<SignedTxItem>,
}

impl SolanaEvidenceQuery {
    pub fn processed() -> Self {
        Self::default()
    }
    pub fn confirmed() -> Self {
        SolanaEvidenceQuery { commitment: SolanaCommitment::Confirmed, ..Default::default() }
    }
    pub fn finalized() -> Self {
        SolanaEvidenceQuery { commitment: SolanaCommitment::Finalized, ..Default::default() }
    }
    pub fn token_account(mut self, a: Pubkey) -> Self {
        self.token_accounts.push(a);
        self
    }
    pub fn lookup_table(mut self, t: Pubkey) -> Self {
        self.lookup_tables.push(t);
        self
    }
    pub fn signature(mut self, s: [u8; 64]) -> Self {
        self.signatures.push(s);
        self
    }
    pub fn tx_id(self, id: &ChainTxId) -> OicResult<Self> {
        Ok(self.signature(parse_tx_id(id)?))
    }
    pub fn blockhash(mut self, h: [u8; 32]) -> Self {
        self.blockhashes.push(h);
        self
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
struct State {
    accounts: BTreeMap<Pubkey, SolanaAccount>,
    lookup_tables: BTreeMap<Pubkey, LookupTable>,
}

fn token_account_of(acct: &SolanaAccount) -> Option<TokenAccountData> {
    if acct.owner != TOKEN_PROGRAM_ID || acct.data.len() != TOKEN_ACCOUNT_LEN {
        return None;
    }
    TokenAccountData::unpack(&acct.data).ok().filter(|t| t.state != TOKEN_ACCOUNT_UNINITIALIZED)
}

fn mint_of(acct: &SolanaAccount) -> Option<MintData> {
    if acct.owner != TOKEN_PROGRAM_ID || acct.data.len() != MINT_LEN {
        return None;
    }
    MintData::unpack(&acct.data).ok().filter(|m| m.is_initialized)
}

impl State {
    fn lamports(&self, k: &Pubkey) -> u64 {
        self.accounts.get(k).map(|a| a.lamports).unwrap_or(0)
    }

    fn token_account(&self, k: &Pubkey) -> Option<TokenAccountData> {
        self.accounts.get(k).and_then(token_account_of)
    }

    fn mint(&self, k: &Pubkey) -> Option<MintData> {
        self.accounts.get(k).and_then(mint_of)
    }

    fn apply_op(&mut self, op: &SolanaSystemOp, slot: u64, rent_token: u64) -> OicResult<()> {
        match op {
            SolanaSystemOp::CreateMint { mint, authority, decimals } => {
                if self.accounts.contains_key(mint) {
                    return Err(OicError::resource_conflict(format!("mint address {} already in use", to_base58(mint))));
                }
                let data = MintData { mint_authority: Some(*authority), supply: 0, decimals: *decimals, is_initialized: true, freeze_authority: Some(*authority) };
                self.accounts.insert(*mint, SolanaAccount { lamports: RENT_EXEMPT_MINT, owner: TOKEN_PROGRAM_ID, data: data.pack() });
            }
            SolanaSystemOp::CreateTokenAccount { account, owner, mint } => {
                if self.accounts.contains_key(account) {
                    return Err(OicError::resource_conflict(format!("token account {} already exists", to_base58(account))));
                }
                if self.mint(mint).is_none() {
                    return Err(OicError::new(ErrorCode::NotFound, format!("mint {} does not exist", to_base58(mint))));
                }
                let data = TokenAccountData { mint: *mint, owner: *owner, amount: 0, delegate: None, state: TOKEN_ACCOUNT_INITIALIZED, close_authority: None };
                self.accounts.insert(*account, SolanaAccount { lamports: rent_token, owner: TOKEN_PROGRAM_ID, data: data.pack() });
            }
            SolanaSystemOp::MintTo { mint, account, amount } => {
                let mut m = self.mint(mint).ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("mint {} does not exist", to_base58(mint))))?;
                let mut t = self
                    .token_account(account)
                    .ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("token account {} does not exist", to_base58(account))))?;
                if t.mint != *mint {
                    return Err(OicError::invalid_request("token account belongs to a different mint"));
                }
                if t.state == TOKEN_ACCOUNT_FROZEN {
                    return Err(OicError::new(ErrorCode::Frozen, "token account is frozen"));
                }
                m.supply = checked(m.supply.checked_add(*amount), "mint supply")?;
                t.amount = checked(t.amount.checked_add(*amount), "token amount")?;
                self.accounts.get_mut(mint).expect("checked").data = m.pack();
                self.accounts.get_mut(account).expect("checked").data = t.pack();
            }
            SolanaSystemOp::FreezeAccount { account } => {
                let mut t = self
                    .token_account(account)
                    .ok_or_else(|| OicError::new(ErrorCode::NotFound, format!("token account {} does not exist", to_base58(account))))?;
                t.state = TOKEN_ACCOUNT_FROZEN;
                self.accounts.get_mut(account).expect("checked").data = t.pack();
            }
            SolanaSystemOp::CreateLookupTable { table, addresses } => {
                if self.lookup_tables.contains_key(table) || self.accounts.contains_key(table) {
                    return Err(OicError::resource_conflict(format!("lookup table address {} already in use", to_base58(table))));
                }
                if addresses.len() > MAX_LOOKUP_TABLE_ADDRESSES {
                    return Err(OicError::invalid_request("a lookup table holds at most 256 addresses"));
                }
                self.lookup_tables.insert(*table, LookupTable { addresses: addresses.clone(), last_extended_slot: slot });
            }
        }
        Ok(())
    }

    fn token_balances(&self, keys: &[Pubkey]) -> Vec<TokenBalance> {
        keys.iter()
            .enumerate()
            .filter_map(|(i, k)| {
                self.token_account(k).map(|t| TokenBalance { account_index: i, account: *k, mint: t.mint, owner: t.owner, amount: t.amount })
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
enum Ix {
    Decoded(SolanaInstruction),
    Memo(Vec<u8>),
}

#[derive(Clone, Debug)]
struct Queued {
    sig: [u8; 64],
    recent_blockhash: [u8; 32],
    keys: Vec<Pubkey>,
    ixs: Vec<Ix>,
    fee: u64,
    signed: Vec<u8>,
    arrival: u64,
}

/// Accounts touched by one transaction; committed only if every instruction succeeds.
struct Overlay<'a> {
    base: &'a State,
    rent_token: u64,
    changed: BTreeMap<Pubkey, SolanaAccount>,
}

impl Overlay<'_> {
    fn get(&self, k: &Pubkey) -> Option<SolanaAccount> {
        self.changed.get(k).cloned().or_else(|| self.base.accounts.get(k).cloned())
    }

    fn put(&mut self, k: Pubkey, a: SolanaAccount) {
        self.changed.insert(k, a);
    }

    fn token(&self, k: &Pubkey, what: &str) -> Result<TokenAccountData, String> {
        self.get(k).as_ref().and_then(token_account_of).ok_or_else(|| format!("{what} {} is not an initialized token account", to_base58(k)))
    }

    fn run(&mut self, ix: &Ix) -> Result<(), String> {
        match ix {
            Ix::Memo(data) => std::str::from_utf8(data).map(|_| ()).map_err(|_| "memo is not valid UTF-8".to_string()),
            Ix::Decoded(SolanaInstruction::SetComputeUnitLimit { .. }) | Ix::Decoded(SolanaInstruction::SetComputeUnitPrice { .. }) => Ok(()),
            Ix::Decoded(SolanaInstruction::SystemTransfer { from, to, lamports }) => {
                let mut src = self.get(from).ok_or_else(|| format!("transfer source {} does not exist", to_base58(from)))?;
                if src.owner != SYSTEM_PROGRAM_ID || !src.data.is_empty() {
                    return Err("transfer source is not a system account without data".into());
                }
                if src.lamports < *lamports {
                    return Err(format!("insufficient lamports {} for transfer of {lamports}", src.lamports));
                }
                src.lamports -= lamports;
                self.put(*from, src);
                let mut dst = self.get(to).unwrap_or_default();
                dst.lamports = dst.lamports.checked_add(*lamports).ok_or("recipient lamports overflow")?;
                self.put(*to, dst);
                Ok(())
            }
            Ix::Decoded(SolanaInstruction::TokenTransferChecked { token_program, source, mint, destination, authority, amount, decimals }) => {
                if *token_program != TOKEN_PROGRAM_ID {
                    return Err("token program is not the classic SPL Token program".into());
                }
                let mint_data = self.get(mint).as_ref().and_then(mint_of).ok_or_else(|| format!("mint {} does not exist", to_base58(mint)))?;
                if mint_data.decimals != *decimals {
                    return Err(format!("decimals mismatch: instruction {decimals}, mint {}", mint_data.decimals));
                }
                let mut src = self.token(source, "source")?;
                let mut dst = self.token(destination, "destination")?;
                if src.mint != *mint || dst.mint != *mint {
                    return Err("token account mint mismatch".into());
                }
                if src.state == TOKEN_ACCOUNT_FROZEN || dst.state == TOKEN_ACCOUNT_FROZEN {
                    return Err("account is frozen".into());
                }
                if src.owner != *authority {
                    return Err("owner does not match (delegates are not modelled)".into());
                }
                if src.amount < *amount {
                    return Err(format!("insufficient funds: token balance {} < {amount}", src.amount));
                }
                if source != destination {
                    src.amount -= amount;
                    dst.amount = dst.amount.checked_add(*amount).ok_or("token amount overflow")?;
                    let mut sa = self.get(source).expect("exists");
                    sa.data = src.pack();
                    self.put(*source, sa);
                    let mut da = self.get(destination).expect("exists");
                    da.data = dst.pack();
                    self.put(*destination, da);
                }
                Ok(())
            }
            Ix::Decoded(SolanaInstruction::CreateAssociatedTokenAccount { idempotent, payer, ata, owner, mint, token_program }) => {
                let expected = associated_token_address(owner, mint, token_program).map_err(|e| e.detail)?;
                if expected != *ata {
                    return Err("associated token account address does not match the PDA derivation".into());
                }
                if self.get(mint).as_ref().and_then(mint_of).is_none() {
                    return Err(format!("mint {} does not exist", to_base58(mint)));
                }
                if let Some(existing) = self.get(ata) {
                    if !idempotent {
                        return Err("account already in use".into());
                    }
                    return match token_account_of(&existing) {
                        Some(t) if t.owner == *owner && t.mint == *mint => Ok(()),
                        _ => Err("existing account is not the expected associated token account".into()),
                    };
                }
                let mut p = self.get(payer).ok_or("payer does not exist")?;
                if p.owner != SYSTEM_PROGRAM_ID || !p.data.is_empty() {
                    return Err("payer is not a system account".into());
                }
                if p.lamports < self.rent_token {
                    return Err(format!("insufficient lamports {} for rent {}", p.lamports, self.rent_token));
                }
                p.lamports -= self.rent_token;
                self.put(*payer, p);
                let data = TokenAccountData { mint: *mint, owner: *owner, amount: 0, delegate: None, state: TOKEN_ACCOUNT_INITIALIZED, close_authority: None };
                self.put(*ata, SolanaAccount { lamports: self.rent_token, owner: TOKEN_PROGRAM_ID, data: data.pack() });
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Inner {
    cfg: SolanaSimConfig,
    genesis_hash: [u8; 32],
    state: State,
    blocks: Vec<SolanaBlock>,
    snapshots: Vec<State>,
    queue: Vec<Queued>,
    pending_ops: Vec<SolanaSystemOp>,
    next_arrival: u64,
    fork: u64,
    finalized: u64,
    counter: u64,
    sig_index: BTreeMap<[u8; 64], (u64, usize)>,
    blockhash_index: BTreeMap<[u8; 32], u64>,
    dropped: BTreeMap<[u8; 64], String>,
    lies: BTreeMap<String, BTreeMap<[u8; 64], TxObservation>>,
}

impl Inner {
    fn head(&self) -> &SolanaBlock {
        self.blocks.last().expect("genesis always present")
    }

    fn compute_fee(&self, nsig: usize, ixs: &[Ix]) -> OicResult<u64> {
        let mut limit = None;
        let mut price = None;
        let mut non_budget = 0u32;
        for ix in ixs {
            match ix {
                Ix::Decoded(SolanaInstruction::SetComputeUnitLimit { units }) => {
                    if limit.replace(*units).is_some() {
                        return Err(OicError::invalid_request("duplicate SetComputeUnitLimit instruction"));
                    }
                }
                Ix::Decoded(SolanaInstruction::SetComputeUnitPrice { micro_lamports }) => {
                    if price.replace(*micro_lamports).is_some() {
                        return Err(OicError::invalid_request("duplicate SetComputeUnitPrice instruction"));
                    }
                }
                _ => non_budget += 1,
            }
        }
        let limit = match limit {
            Some(u) if u > MAX_COMPUTE_UNIT_LIMIT => return Err(OicError::invalid_request(format!("compute unit limit {u} exceeds {MAX_COMPUTE_UNIT_LIMIT}"))),
            Some(u) => u,
            None => DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT.saturating_mul(non_budget).min(MAX_COMPUTE_UNIT_LIMIT),
        };
        let priority = (limit as u128 * price.unwrap_or(0) as u128).div_ceil(1_000_000);
        let total = (nsig as u128) * self.cfg.lamports_per_signature as u128 + priority;
        u64::try_from(total).map_err(|_| crate::overflow("transaction fee"))
    }

    /// Decode, verify every signature, resolve lookups and decode instructions against the head state.
    fn prepare(&self, bytes: &[u8]) -> OicResult<Queued> {
        let tx = Transaction::decode(bytes)?;
        if Transaction::encode(&tx.signatures, &tx.message_bytes) != bytes {
            return Err(OicError::unverifiable("transaction bytes are not canonical"));
        }
        let msg: &Message = &tx.message;
        for (i, sig) in tx.signatures.iter().enumerate() {
            let vk = VerifyingKey::from_bytes(&msg.account_keys[i]).map_err(|_| OicError::invalid_signature("signer key is not a valid Ed25519 point"))?;
            vk.verify_strict(&tx.message_bytes, &Signature::from_bytes(sig))
                .map_err(|_| OicError::invalid_signature(format!("signature {i} does not verify over the message bytes")))?;
        }
        let mut writable = Vec::new();
        let mut readonly = Vec::new();
        for l in &msg.address_table_lookups {
            let t = self
                .state
                .lookup_tables
                .get(&l.account_key)
                .ok_or_else(|| OicError::invalid_request(format!("address lookup table {} not found", to_base58(&l.account_key))))?;
            let pick = |idx: &[u8], out: &mut Vec<Pubkey>| -> OicResult<()> {
                for i in idx {
                    out.push(*t.addresses.get(*i as usize).ok_or_else(|| OicError::invalid_request("lookup table index out of range"))?);
                }
                Ok(())
            };
            pick(&l.writable_indexes, &mut writable)?;
            pick(&l.readonly_indexes, &mut readonly)?;
        }
        let mut keys = msg.account_keys.clone();
        keys.extend(writable);
        keys.extend(readonly);
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return Err(OicError::unverifiable("resolved account list contains a duplicate account"));
        }
        let mut ixs = Vec::with_capacity(msg.instructions.len());
        for ix in &msg.instructions {
            let program = keys[ix.program_id_index as usize];
            if program == MEMO_V1_PROGRAM_ID || program == MEMO_V2_PROGRAM_ID {
                ixs.push(Ix::Memo(ix.data.clone()));
            } else {
                ixs.push(Ix::Decoded(decode_instruction(msg, &keys, ix).map_err(|e| {
                    OicError::new(e.code, format!("transaction rejected by the simulator (no effects applied): {}", e.detail))
                })?));
            }
        }
        let fee = self.compute_fee(tx.signatures.len(), &ixs)?;
        Ok(Queued { sig: tx.signatures[0], recent_blockhash: msg.recent_blockhash, keys, ixs, fee, signed: bytes.to_vec(), arrival: 0 })
    }

    fn fee_payer_can_pay(&self, q: &Queued) -> bool {
        self.state.accounts.get(&q.keys[0]).is_some_and(|a| a.owner == SYSTEM_PROGRAM_ID && a.data.is_empty() && a.lamports >= q.fee)
    }

    fn submit(&mut self, bytes: &[u8]) -> OicResult<[u8; 64]> {
        let mut q = self.prepare(bytes)?;
        if self.sig_index.contains_key(&q.sig) || self.queue.iter().any(|x| x.sig == q.sig) {
            return Err(OicError::resource_conflict(format!("transaction {} has already been processed", to_base58(&q.sig))));
        }
        let next_slot = self.head().slot + 1;
        match self.blockhash_index.get(&q.recent_blockhash) {
            None => return Err(OicError::resource_conflict("blockhash not found (unknown or not canonical)")),
            Some(s) if next_slot > s.saturating_add(self.cfg.blockhash_validity_slots) => {
                return Err(OicError::resource_conflict(format!(
                    "blockhash expired: produced at slot {s}, valid through slot {}, next slot {next_slot}",
                    s.saturating_add(self.cfg.blockhash_validity_slots)
                )))
            }
            Some(_) => {}
        }
        if !self.fee_payer_can_pay(&q) {
            return Err(OicError::resource_conflict(format!(
                "fee payer {} cannot pay fee {} (insufficient lamports or not a system account)",
                to_base58(&q.keys[0]),
                q.fee
            )));
        }
        q.arrival = self.next_arrival;
        self.next_arrival += 1;
        self.dropped.remove(&q.sig);
        let sig = q.sig;
        self.queue.push(q);
        Ok(sig)
    }

    fn advance(&mut self, timestamp: UnixSeconds) -> SolanaBlock {
        let parent = self.head().clone();
        let slot = parent.slot + 1;
        let system_ops = std::mem::take(&mut self.pending_ops);
        let mut queue = std::mem::take(&mut self.queue);
        queue.sort_by_key(|q| q.arrival);
        let rent_token = self.cfg.rent_exempt_token_account;
        let mut records = Vec::new();
        for q in queue {
            let window_ok = self.blockhash_index.get(&q.recent_blockhash).is_some_and(|s| slot <= s.saturating_add(self.cfg.blockhash_validity_slots));
            if !window_ok {
                self.dropped.insert(q.sig, "blockhash expired or not canonical before inclusion".to_string());
                continue;
            }
            if !self.fee_payer_can_pay(&q) {
                self.dropped.insert(q.sig, "fee payer could not pay the fee at inclusion".to_string());
                continue;
            }
            let pre_lamports: Vec<u64> = q.keys.iter().map(|k| self.state.lamports(k)).collect();
            let pre_token_balances = self.state.token_balances(&q.keys);
            self.state.accounts.get_mut(&q.keys[0]).expect("fee payer checked").lamports -= q.fee;
            let mut overlay = Overlay { base: &self.state, rent_token, changed: BTreeMap::new() };
            let mut err = None;
            for (i, ix) in q.ixs.iter().enumerate() {
                if let Err(e) = overlay.run(ix) {
                    err = Some(format!("instruction {i}: {e}"));
                    break;
                }
            }
            if err.is_none() {
                let changed = overlay.changed;
                self.state.accounts.extend(changed);
            }
            let post_lamports: Vec<u64> = q.keys.iter().map(|k| self.state.lamports(k)).collect();
            let post_token_balances = self.state.token_balances(&q.keys);
            records.push(SolanaTxRecord {
                signature: q.sig,
                slot,
                success: err.is_none(),
                err,
                fee: q.fee,
                account_keys: q.keys,
                pre_lamports,
                post_lamports,
                pre_token_balances,
                post_token_balances,
                signed_bytes: q.signed,
            });
        }
        let ids: Vec<&[u8]> = records.iter().map(|r| r.signature.as_slice()).collect();
        let blockhash = crate::block_hash(&parent.blockhash, slot, &ids, self.fork);
        for (i, r) in records.iter().enumerate() {
            self.sig_index.insert(r.signature, (slot, i));
        }
        self.blockhash_index.insert(blockhash, slot);
        let block = SolanaBlock { slot, blockhash, parent_blockhash: parent.blockhash, fork: self.fork, timestamp, system_ops, transactions: records };
        self.blocks.push(block.clone());
        self.snapshots.push(self.state.clone());
        self.finalized = self.finalized.max(slot.saturating_sub(self.cfg.finality_depth));
        block
    }

    fn reindex(&mut self) {
        self.sig_index.clear();
        self.blockhash_index.clear();
        for b in &self.blocks {
            self.blockhash_index.insert(b.blockhash, b.slot);
            for (i, t) in b.transactions.iter().enumerate() {
                self.sig_index.insert(t.signature, (b.slot, i));
            }
        }
    }

    fn fork(&mut self, discard_after_slot: u64, drop: &[ChainTxId], timestamp: UnixSeconds) -> OicResult<()> {
        let head = self.head().slot;
        if discard_after_slot >= head {
            return Err(OicError::invalid_request(format!("no slots above {discard_after_slot} to discard (head {head})")));
        }
        if discard_after_slot < self.finalized {
            return Err(OicError::resource_conflict(format!(
                "fork after slot {discard_after_slot} would discard finalized slots (finalized {})",
                self.finalized
            )));
        }
        let drop: BTreeSet<[u8; 64]> = drop.iter().map(parse_tx_id).collect::<OicResult<_>>()?;
        let n = head - discard_after_slot;
        let keep = discard_after_slot as usize + 1;
        let removed = self.blocks.split_off(keep);
        self.snapshots.truncate(keep);
        let removed_sigs: BTreeSet<[u8; 64]> = removed.iter().flat_map(|b| b.transactions.iter().map(|t| t.signature)).collect();
        if let Some(missing) = drop.iter().find(|s| !removed_sigs.contains(*s)) {
            return Err(OicError::invalid_request(format!("tx {} to drop is not in the discarded slots", to_base58(missing))));
        }
        self.fork += 1;
        self.state = self.snapshots[discard_after_slot as usize].clone();
        self.reindex();
        let ops: Vec<SolanaSystemOp> = removed.iter().flat_map(|b| b.system_ops.iter().cloned()).chain(self.pending_ops.drain(..)).collect();
        for op in &ops {
            self.state.apply_op(op, discard_after_slot, self.cfg.rent_exempt_token_account)?;
        }
        self.pending_ops = ops;
        let mut pool = Vec::new();
        for t in removed.iter().flat_map(|b| b.transactions.iter()) {
            if drop.contains(&t.signature) {
                self.dropped.insert(t.signature, "discarded by fork".to_string());
                continue;
            }
            match self.prepare(&t.signed_bytes) {
                Ok(q) => pool.push(q),
                Err(e) => {
                    self.dropped.insert(t.signature, format!("not re-executable after fork: {}", e.detail));
                }
            }
        }
        for q in std::mem::take(&mut self.queue) {
            if !pool.iter().any(|p| p.sig == q.sig) {
                pool.push(q);
            }
        }
        for q in &mut pool {
            q.arrival = self.next_arrival;
            self.next_arrival += 1;
        }
        self.queue = pool;
        for _ in 0..n {
            self.advance(timestamp);
        }
        Ok(())
    }

    fn commitment_of(&self, slot: u64) -> &'static str {
        if slot <= self.finalized {
            COMMITMENT_FINALIZED
        } else if slot < self.head().slot {
            COMMITMENT_CONFIRMED
        } else {
            COMMITMENT_PROCESSED
        }
    }

    fn view_slot(&self, c: SolanaCommitment) -> u64 {
        match c {
            SolanaCommitment::Processed => self.head().slot,
            SolanaCommitment::Confirmed => self.head().slot.saturating_sub(1).max(self.finalized),
            SolanaCommitment::Finalized => self.finalized,
        }
    }

    fn observation(&self, view: u64, sig: &[u8; 64]) -> Option<TxObservation> {
        let &(slot, i) = self.sig_index.get(sig)?;
        if slot > view {
            return None;
        }
        let b = &self.blocks[slot as usize];
        let r = &b.transactions[i];
        Some(TxObservation {
            slot,
            block_hash: Bytes(b.blockhash.to_vec()),
            commitment: self.commitment_of(slot).to_string(),
            success: r.success,
            fee: r.fee,
            account_funding: r.post_token_balances.iter()
                .filter(|post| !r.pre_token_balances.iter().any(|pre| pre.account == post.account))
                .map(|post| r.post_lamports[post.account_index])
                .sum(),
            err: r.err.clone(),
        })
    }

    fn bundle(&self, source: &EvidenceSourceId, q: &SolanaEvidenceQuery, now: UnixSeconds) -> OicResult<EvidenceBundle> {
        let view = self.view_slot(q.commitment);
        let block = &self.blocks[view as usize];
        let snap = &self.snapshots[view as usize];
        let validity = self.cfg.blockhash_validity_slots;
        let le = |v: u64| Bytes(v.to_le_bytes().to_vec());
        let mut items = BTreeMap::new();
        items.insert(KEY_GENESIS_HASH.to_string(), Bytes(self.genesis_hash.to_vec()));
        items.insert(KEY_RECENT_BLOCKHASH.to_string(), Bytes(block.blockhash.to_vec()));
        items.insert(KEY_BLOCKHASH_LAST_VALID_HEIGHT.to_string(), le(view.saturating_add(validity)));
        items.insert(last_valid_height_key(&block.blockhash), le(view.saturating_add(validity)));
        for h in &q.blockhashes {
            if let Some(&s) = self.blockhash_index.get(h) {
                if s <= view {
                    items.insert(last_valid_height_key(h), le(s.saturating_add(validity)));
                }
            }
        }
        items.insert(KEY_LAMPORTS_PER_SIGNATURE.to_string(), le(self.cfg.lamports_per_signature));
        items.insert(KEY_RENT_TOKEN_ACCOUNT.to_string(), le(self.cfg.rent_exempt_token_account));
        if let Some(l) = self.cfg.cu_limit {
            items.insert(KEY_CU_LIMIT.to_string(), Bytes(l.to_le_bytes().to_vec()));
        }
        if let Some(p) = self.cfg.cu_price {
            items.insert(KEY_CU_PRICE.to_string(), le(p));
        }
        for a in &q.token_accounts {
            if let Some(acct) = snap.accounts.get(a) {
                let t = token_account_of(acct)
                    .ok_or_else(|| OicError::invalid_request(format!("account {} is not an SPL token account", to_base58(a))))?;
                items.insert(token_account_key(a), Bytes(oic_canonical_encoding::canonical_bytes(&t.to_evidence())?));
            }
        }
        for t in &q.lookup_tables {
            if let Some(lt) = snap.lookup_tables.get(t) {
                let ev = AddressLookupTableEvidence {
                    addresses: lt.addresses.iter().map(|a| Bytes(a.to_vec())).collect(),
                    deactivation_slot: u64::MAX,
                    last_extended_slot: lt.last_extended_slot,
                };
                items.insert(alt_key(t), Bytes(oic_canonical_encoding::canonical_bytes(&ev)?));
            }
        }
        let lies = self.lies.get(source.as_str());
        for s in &q.signatures {
            let obs = match lies.and_then(|l| l.get(s)) {
                Some(lie) => Some(lie.clone()),
                None => self.observation(view, s),
            };
            if let Some(o) = obs {
                items.insert(tx_key(s), Bytes(oic_canonical_encoding::canonical_bytes(&o)?));
            }
        }
        for s in &q.signed_txs {
            Transaction::decode(&s.signed_bytes)?;
            items.insert(signed_tx_key(&s.candidate_id, s.revision), Bytes(s.signed_bytes.clone()));
        }
        Ok(EvidenceBundle {
            chain_profile_id: ChainProfileId::unchecked(CHAIN_PROFILE_ID),
            network_id: NetworkId::unchecked(NETWORK_ID),
            state: StateReference { height: view, hash: Bytes(block.blockhash.to_vec()), commitment: q.commitment.as_str().to_string() },
            sources: vec![source.clone()],
            trust_level: EvidenceTrustLevel::DevelopmentSimulator,
            observed_at: now,
            max_staleness_seconds: EVIDENCE_MAX_STALENESS_SECONDS,
            verifier_version: VERIFIER_VERSION.to_string(),
            items,
        })
    }
}

// ---------------------------------------------------------------------------
// simulator
// ---------------------------------------------------------------------------

/// Simulated Solana chain. `Send + Sync`; share it with `Arc`.
pub struct SolanaSimulator {
    inner: Mutex<Inner>,
    clock: SimClock,
    faucet: SigningKey,
}

impl SolanaSimulator {
    /// Build a simulator at slot 0. Genesis hash = `SHA256("oic-devsim-solana-genesis" || seed)`.
    pub fn new(cfg: SolanaSimConfig, clock: SimClock) -> OicResult<Self> {
        if cfg.finality_depth == 0 {
            return Err(OicError::invalid_request("finality_depth must be at least 1"));
        }
        if cfg.blockhash_validity_slots == 0 {
            return Err(OicError::invalid_request("blockhash_validity_slots must be at least 1"));
        }
        if cfg.cu_limit.is_some_and(|l| l > MAX_COMPUTE_UNIT_LIMIT) {
            return Err(OicError::invalid_request("cu_limit exceeds the maximum compute unit limit"));
        }
        let genesis_hash = sha256_parts(&[b"oic-devsim-solana-genesis", &cfg.seed]);
        let faucet = SigningKey::from_bytes(&sha256_parts(&[b"oic-devsim-solana-faucet", &cfg.seed]));
        let mut state = State::default();
        state.accounts.insert(faucet.verifying_key().to_bytes(), SolanaAccount { lamports: FAUCET_GENESIS_LAMPORTS, owner: SYSTEM_PROGRAM_ID, data: vec![] });
        let blockhash = crate::block_hash(&genesis_hash, 0, &[], 0);
        let genesis = SolanaBlock {
            slot: 0,
            blockhash,
            parent_blockhash: genesis_hash,
            fork: 0,
            timestamp: clock.now(),
            system_ops: vec![],
            transactions: vec![],
        };
        let mut blockhash_index = BTreeMap::new();
        blockhash_index.insert(blockhash, 0);
        let inner = Inner {
            cfg,
            genesis_hash,
            snapshots: vec![state.clone()],
            state,
            blocks: vec![genesis],
            queue: vec![],
            pending_ops: vec![],
            next_arrival: 0,
            fork: 0,
            finalized: 0,
            counter: 0,
            sig_index: BTreeMap::new(),
            blockhash_index,
            dropped: BTreeMap::new(),
            lies: BTreeMap::new(),
        };
        Ok(SolanaSimulator { inner: Mutex::new(inner), clock, faucet })
    }

    pub fn config(&self) -> SolanaSimConfig {
        lock(&self.inner).cfg.clone()
    }

    pub fn clock(&self) -> &SimClock {
        &self.clock
    }

    pub fn genesis_hash(&self) -> [u8; 32] {
        lock(&self.inner).genesis_hash
    }

    pub fn faucet_address(&self) -> Pubkey {
        self.faucet.verifying_key().to_bytes()
    }

    /// The enrolled development profile for this chain.
    pub fn profile(&self) -> ChainProfile {
        let g = lock(&self.inner);
        ChainProfile {
            chain_profile_id: ChainProfileId::unchecked(CHAIN_PROFILE_ID),
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            network_id: NetworkId::unchecked(NETWORK_ID),
            network_binding: Bytes(g.genesis_hash.to_vec()),
            display_name: "OIC Solana development simulator — DEVELOPMENT ONLY".to_string(),
            accepted_versions: vec![VERSION_LEGACY.to_string(), VERSION_V0.to_string()],
            finality_commitment: COMMITMENT_FINALIZED.to_string(),
            finality_depth: g.cfg.finality_depth,
            max_evidence_age_seconds: PROFILE_MAX_EVIDENCE_AGE_SECONDS,
            accepted_trust_levels: vec![EvidenceTrustLevel::DevelopmentSimulator],
        }
    }

    fn system_op(&self, g: &mut Inner, op: SolanaSystemOp) -> OicResult<()> {
        let slot = g.head().slot + 1;
        let rent = g.cfg.rent_exempt_token_account;
        g.state.apply_op(&op, slot, rent)?;
        g.pending_ops.push(op);
        Ok(())
    }

    /// Create a classic SPL mint whose mint and freeze authority is
    /// [`mint_authority`]`(mint_authority_seed)`.
    pub fn create_mint(&self, decimals: u8, mint_authority_seed: &[u8]) -> OicResult<Pubkey> {
        let authority = mint_authority(mint_authority_seed);
        let mut g = lock(&self.inner);
        let mint = loop {
            let m = sha256_parts(&[b"oic-devsim-solana-mint", &authority, &g.counter.to_be_bytes()]);
            g.counter += 1;
            if !g.state.accounts.contains_key(&m) {
                break m;
            }
        };
        self.system_op(&mut g, SolanaSystemOp::CreateMint { mint, authority, decimals })?;
        Ok(mint)
    }

    /// Create the associated token account of `(owner, mint)` and return its address.
    pub fn create_ata(&self, owner: &Pubkey, mint: &Pubkey) -> OicResult<Pubkey> {
        let account = associated_token_address(owner, mint, &TOKEN_PROGRAM_ID)?;
        let mut g = lock(&self.inner);
        self.system_op(&mut g, SolanaSystemOp::CreateTokenAccount { account, owner: *owner, mint: *mint })?;
        Ok(account)
    }

    /// Mint `amount` base units into a token account (by the mint authority).
    pub fn mint_to(&self, mint: &Pubkey, account: &Pubkey, amount: u64) -> OicResult<()> {
        let mut g = lock(&self.inner);
        self.system_op(&mut g, SolanaSystemOp::MintTo { mint: *mint, account: *account, amount })
    }

    /// Freeze a token account (by the freeze authority).
    pub fn freeze_token_account(&self, account: &Pubkey) -> OicResult<()> {
        let mut g = lock(&self.inner);
        self.system_op(&mut g, SolanaSystemOp::FreezeAccount { account: *account })
    }

    /// Create an active address lookup table and return its address.
    pub fn create_lookup_table(&self, addresses: Vec<Pubkey>) -> OicResult<Pubkey> {
        let mut g = lock(&self.inner);
        let table = loop {
            let t = sha256_parts(&[b"oic-devsim-solana-alt", &g.counter.to_be_bytes()]);
            g.counter += 1;
            if !g.state.accounts.contains_key(&t) && !g.state.lookup_tables.contains_key(&t) {
                break t;
            }
        };
        self.system_op(&mut g, SolanaSystemOp::CreateLookupTable { table, addresses })?;
        Ok(table)
    }

    /// Real signed System transfer from the faucet, using the head blockhash;
    /// included by the next [`Self::advance_slot`]. Ed25519 signing is
    /// deterministic, so a second airdrop with the same `(to, lamports)`
    /// against the same head blockhash is byte-identical and is refused as a
    /// replay, exactly as a real cluster would; advance a slot or vary the amount.
    pub fn airdrop(&self, to: &Pubkey, lamports: u64) -> OicResult<ChainTxId> {
        let mut g = lock(&self.inner);
        let faucet = self.faucet_address();
        let spec = InstructionSpec { program_id: SYSTEM_PROGRAM_ID, accounts: vec![(faucet, true, true), (*to, false, true)], data: system_transfer_data(lamports) };
        let msg = compile_legacy_message(&faucet, &[spec], g.head().blockhash)?;
        let bytes = sign_transaction(&[&self.faucet], &msg.encode());
        g.submit(&bytes).map(|s| tx_id(&s))
    }

    /// Broadcast signed bytes. `Ok` is a queue acknowledgement, not inclusion.
    pub fn submit(&self, signed_bytes: &[u8]) -> OicResult<ChainTxId> {
        lock(&self.inner).submit(signed_bytes).map(|s| tx_id(&s))
    }

    /// Produce the next slot, including queued transactions.
    pub fn advance_slot(&self) -> OicResult<SolanaBlock> {
        let now = self.clock.now();
        let mut g = lock(&self.inner);
        if g.head().slot == u64::MAX {
            return Err(crate::overflow("slot"));
        }
        Ok(g.advance(now))
    }

    pub fn advance_slots(&self, n: u64) -> OicResult<Vec<SolanaBlock>> {
        (0..n).map(|_| self.advance_slot()).collect()
    }

    /// Discard every (non-finalized) slot above `discard_after_slot`, restore
    /// that slot's snapshot, replay system operations, re-queue the discarded
    /// transactions except `drop_tx_ids`, and re-produce the same number of
    /// slots with new blockhashes. All-or-nothing.
    pub fn fork(&self, discard_after_slot: u64, drop_tx_ids: &[ChainTxId]) -> OicResult<()> {
        let now = self.clock.now();
        let mut g = lock(&self.inner);
        let mut scratch = g.clone();
        scratch.fork(discard_after_slot, drop_tx_ids, now)?;
        *g = scratch;
        Ok(())
    }

    pub fn head(&self) -> StateReference {
        let g = lock(&self.inner);
        let b = g.head();
        StateReference { height: b.slot, hash: Bytes(b.blockhash.to_vec()), commitment: COMMITMENT_PROCESSED.to_string() }
    }

    pub fn finalized_slot(&self) -> u64 {
        lock(&self.inner).finalized
    }

    pub fn finalized(&self) -> StateReference {
        let g = lock(&self.inner);
        let b = &g.blocks[g.finalized as usize];
        StateReference { height: b.slot, hash: Bytes(b.blockhash.to_vec()), commitment: COMMITMENT_FINALIZED.to_string() }
    }

    pub fn latest_blockhash(&self) -> [u8; 32] {
        lock(&self.inner).head().blockhash
    }

    pub fn block(&self, slot: u64) -> Option<SolanaBlock> {
        lock(&self.inner).blocks.get(usize::try_from(slot).ok()?).cloned()
    }

    /// Holdings at an exact canonical slot. SPL holdings aggregate initialized
    /// classic-token accounts owned by `owner`; rent is not spendable SOL.
    pub fn balance_at(&self, state: &StateReference, owner: &Pubkey, asset: &AssetKind) -> OicResult<Amount> {
        let g = lock(&self.inner);
        let h = usize::try_from(state.height).map_err(|_| OicError::stale_evidence("slot out of range"))?;
        let block = g.blocks.get(h).ok_or_else(|| OicError::stale_evidence("slot missing"))?;
        if block.blockhash.as_slice() != state.hash.as_slice() {
            return Err(OicError::stale_evidence("slot is no longer canonical"));
        }
        let snapshot = &g.snapshots[h];
        match asset {
            AssetKind::Native => Ok(Amount(snapshot.lamports(owner) as u128)),
            AssetKind::SplToken { mint, token_program } if token_program.as_slice() == TOKEN_PROGRAM_ID => {
                let mint: Pubkey = mint.as_slice().try_into().map_err(|_| OicError::invalid_request("SPL mint length"))?;
                let amount = snapshot.accounts.values().filter_map(token_account_of)
                    .filter(|t| t.owner == *owner && t.mint == mint)
                    .try_fold(0u128, |a, t| a.checked_add(t.amount as u128))
                    .ok_or_else(|| OicError::unverifiable("SPL holdings overflow"))?;
                Ok(Amount(amount))
            }
            _ => Err(OicError::unsupported("Solana balance asset")),
        }
    }

    pub fn account(&self, k: &Pubkey) -> Option<SolanaAccount> {
        lock(&self.inner).state.accounts.get(k).cloned()
    }

    pub fn lamports(&self, k: &Pubkey) -> u64 {
        lock(&self.inner).state.lamports(k)
    }

    /// Token balance of an initialized token account (`None` if absent / not a token account).
    pub fn token_balance(&self, account: &Pubkey) -> Option<u64> {
        lock(&self.inner).state.token_account(account).map(|t| t.amount)
    }

    pub fn token_account(&self, account: &Pubkey) -> Option<TokenAccountData> {
        lock(&self.inner).state.token_account(account)
    }

    pub fn mint_info(&self, mint: &Pubkey) -> Option<MintData> {
        lock(&self.inner).state.mint(mint)
    }

    pub fn tx_status(&self, id: &ChainTxId) -> OicResult<Option<SolanaTxStatus>> {
        let sig = parse_tx_id(id)?;
        let g = lock(&self.inner);
        if let Some(&(slot, i)) = g.sig_index.get(&sig) {
            let b = &g.blocks[slot as usize];
            let r = &b.transactions[i];
            return Ok(Some(SolanaTxStatus::Included {
                slot,
                blockhash: b.blockhash,
                commitment: g.commitment_of(slot).to_string(),
                success: r.success,
                fee: r.fee,
                err: r.err.clone(),
            }));
        }
        if g.queue.iter().any(|q| q.sig == sig) {
            return Ok(Some(SolanaTxStatus::Queued));
        }
        Ok(g.dropped.get(&sig).map(|reason| SolanaTxStatus::Dropped { reason: reason.clone() }))
    }

    /// Evidence from the honest source [`SOURCE_ID`].
    pub fn evidence(&self, query: &SolanaEvidenceQuery) -> OicResult<EvidenceBundle> {
        self.evidence_from(&EvidenceSourceId::unchecked(SOURCE_ID), query)
    }

    /// Evidence as reported by `source`, honest except for [`Self::set_lie`] overrides.
    pub fn evidence_from(&self, source: &EvidenceSourceId, query: &SolanaEvidenceQuery) -> OicResult<EvidenceBundle> {
        let now = self.clock.now();
        lock(&self.inner).bundle(source, query, now)
    }

    /// Make `source` report `obs` for `signature` whenever it is queried.
    pub fn set_lie(&self, source: &EvidenceSourceId, signature: [u8; 64], obs: TxObservation) -> OicResult<()> {
        if source.as_str() == SOURCE_ID {
            return Err(OicError::invalid_request("the honest simulator source cannot be configured to lie"));
        }
        lock(&self.inner).lies.entry(source.as_str().to_string()).or_default().insert(signature, obs);
        Ok(())
    }

    pub fn clear_lies(&self, source: &EvidenceSourceId) {
        lock(&self.inner).lies.remove(source.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_layouts_round_trip() {
        let t = TokenAccountData { mint: [1; 32], owner: [2; 32], amount: 7, delegate: Some([3; 32]), state: 2, close_authority: None };
        let p = t.pack();
        assert_eq!(p.len(), TOKEN_ACCOUNT_LEN);
        assert_eq!(TokenAccountData::unpack(&p).unwrap(), t);
        let mut bad = p.clone();
        bad[110] = 1;
        assert!(TokenAccountData::unpack(&bad).is_err());
        assert!(TokenAccountData::unpack(&p[..164]).is_err());
        let m = MintData { mint_authority: Some([9; 32]), supply: 5, decimals: 6, is_initialized: true, freeze_authority: None };
        let mp = m.pack();
        assert_eq!(mp.len(), MINT_LEN);
        assert_eq!(MintData::unpack(&mp).unwrap(), m);
        let mut bad = mp.clone();
        bad[45] = 2;
        assert!(MintData::unpack(&bad).is_err());
        let mut bad = mp;
        bad[0] = 2;
        assert!(MintData::unpack(&bad).is_err());
    }

    #[test]
    fn tx_id_round_trip() {
        let s = [7u8; 64];
        assert_eq!(parse_tx_id(&tx_id(&s)).unwrap(), s);
        assert!(parse_tx_id(&ChainTxId::unchecked("0OIl")).is_err());
        assert!(parse_tx_id(&ChainTxId::unchecked("abc")).is_err());
    }
}
