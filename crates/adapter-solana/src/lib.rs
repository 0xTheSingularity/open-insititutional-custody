//! # oic-adapter-solana
//!
//! Solana chain adapter for Open Institutional Custody (RFC 0001 §8, §10).
//!
//! Supported: legacy messages (build, decode, verify, assemble) and, only when
//! the profile enables `"v0"`, decode/verify/assemble of v0 messages with
//! address lookup tables resolved from evidence. Semantics: one SOL transfer
//! (System Program `Transfer`) or one original SPL Token `TransferChecked` of a
//! registered mint, optionally preceded by `SetComputeUnitLimit` /
//! `SetComputeUnitPrice` and, for SPL, one strictly verified associated token
//! account creation for the destination. Everything else fails with
//! `UnsupportedCapability`.
//!
//! The adapter is pure: no I/O, no clock, no Solana SDK code in production.
//! All chain state arrives through `EvidenceBundle` items described in
//! [`evidence`].

pub mod address;
pub mod evidence;
pub mod instruction;
pub mod message;
pub mod shortvec;

use address::*;
use ed25519_dalek::{Signature, VerifyingKey};
use evidence::*;
use instruction::*;
use message::{CompiledInstruction, Message, MessageHeader, MessageVersion, Transaction};
use oic_adapter_api::*;
use oic_domain_types::*;
use serde::{Deserialize, Serialize};

pub const ADAPTER_ID: &str = "solana";
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Identity of the pinned verification code; its SHA-256 is `verifier_build_hash`.
pub const VERIFIER_BUILD_ID: &str =
    concat!("oic-adapter-solana/", env!("CARGO_PKG_VERSION"), "/verifier/strict-legacy-v0-sol-transfer-spl-transferchecked-ata-v1");

/// `ChainProfile.accepted_versions` strings understood by this adapter.
pub const VERSION_LEGACY: &str = "legacy";
pub const VERSION_V0: &str = "v0";

pub const SIGNING_CONTEXT_LEGACY: &str = "solana-message-legacy";
pub const SIGNING_CONTEXT_V0: &str = "solana-message-v0";

pub const REPLACEMENT_RULE: &str = "Solana messages expire when their recent blockhash passes its last valid block height; a fresh-blockhash \
     rebuild is a new candidate and NOT mutually exclusive with the original; exposure retained until every family blockhash is \
     past last_valid_height + finality_depth at finality commitment and no family signature succeeded";

/// `SHA256(VERIFIER_BUILD_ID)`.
pub fn verifier_build_hash() -> Hash32 {
    oic_canonical_encoding::sha256(VERIFIER_BUILD_ID.as_bytes())
}

/// One resolved address lookup table, bound into `native_detail`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupTableBinding {
    pub table: Bytes,
    pub writable_indexes: Bytes,
    pub readonly_indexes: Bytes,
    pub resolved_writable: Vec<Bytes>,
    pub resolved_readonly: Vec<Bytes>,
    pub last_extended_slot: u64,
}

/// Canonically-encoded `native_detail` of a decoded Solana operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaNativeDetail {
    pub message_version: String,
    pub message_sha256: Hash32,
    pub fee_payer: Bytes,
    pub recent_blockhash: Bytes,
    /// Static keys, then lookup-resolved writable, then lookup-resolved readonly.
    pub resolved_account_keys: Vec<Bytes>,
    pub lookup_tables: Vec<LookupTableBinding>,
    pub instructions: Vec<String>,
    pub compute_unit_limit: u32,
    pub compute_unit_price_micro_lamports: u64,
    pub lamports_per_signature: u64,
    pub priority_fee_lamports: u64,
    pub rent_lamports: u64,
    pub source_token_account: Option<Bytes>,
    pub destination_token_account: Option<Bytes>,
    pub created_associated_token_account: Option<Bytes>,
}

/// The Solana adapter. Stateless.
#[derive(Clone, Copy, Debug, Default)]
pub struct SolanaAdapter;

impl SolanaAdapter {
    pub fn new() -> Self {
        SolanaAdapter
    }
}

// ---------------------------------------------------------------------------
// profile / key / scope helpers
// ---------------------------------------------------------------------------

/// Genesis hash from `profile.network_binding` (32 bytes).
pub fn genesis_hash_from_profile(profile: &ChainProfile) -> OicResult<[u8; 32]> {
    profile
        .network_binding
        .as_slice()
        .try_into()
        .map_err(|_| OicError::scope("Solana profile network_binding must be the 32-byte genesis hash"))
}

fn check_profile(profile: &ChainProfile) -> OicResult<[u8; 32]> {
    if profile.adapter_id.as_str() != ADAPTER_ID {
        return Err(OicError::scope(format!("profile adapter_id `{}` is not `{ADAPTER_ID}`", profile.adapter_id)));
    }
    if profile.accepted_versions.is_empty() {
        return Err(OicError::unsupported("profile enables no Solana message versions"));
    }
    for v in &profile.accepted_versions {
        if v != VERSION_LEGACY && v != VERSION_V0 {
            return Err(OicError::unsupported(format!("profile accepted version `{v}` is not supported by this adapter")));
        }
    }
    if commitment_rank(&profile.finality_commitment).is_none() {
        return Err(OicError::unsupported(format!("profile finality commitment `{}` is not a Solana commitment level", profile.finality_commitment)));
    }
    genesis_hash_from_profile(profile)
}

fn version_enabled(profile: &ChainProfile, v: &str) -> bool {
    profile.accepted_versions.iter().any(|x| x == v)
}

fn check_genesis_evidence(profile: &ChainProfile, evidence: &EvidenceBundle) -> OicResult<()> {
    let expected = genesis_hash_from_profile(profile)?;
    let observed = get_hash(evidence, KEY_GENESIS_HASH)?;
    if observed != expected {
        return Err(OicError::scope("evidence genesis hash does not match the profile network binding"));
    }
    Ok(())
}

/// Ed25519 public key bytes of a key descriptor (the wallet address).
fn ed25519_key(public_key: &PublicKey) -> OicResult<Pubkey> {
    if public_key.scheme != SchemeId::Ed25519Pure {
        return Err(OicError::unsupported(format!("Solana adapter does not support key scheme {:?}", public_key.scheme)));
    }
    let pk: Pubkey = public_key
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| OicError::invalid_request("Ed25519 public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&pk).map_err(|_| OicError::invalid_request("Ed25519 public key is not a valid curve point"))?;
    Ok(pk)
}

fn check_key_scheme(key: &KeyDescriptor) -> OicResult<Pubkey> {
    if key.scheme != SchemeId::Ed25519Pure {
        return Err(OicError::unsupported(format!("Solana adapter does not support key scheme {:?}", key.scheme)));
    }
    ed25519_key(&key.public_key)
}

fn check_wallet_scope(profile: &ChainProfile, wallet: &ChainWallet, key: &KeyDescriptor) -> OicResult<Pubkey> {
    let derived = check_key_scheme(key)?;
    if wallet.address.as_slice() != derived {
        return Err(OicError::scope("wallet address does not match the Ed25519 public key of the key descriptor"));
    }
    if wallet.chain_profile_id != profile.chain_profile_id {
        return Err(OicError::scope("wallet chain_profile_id does not match profile"));
    }
    if wallet.network_id != profile.network_id {
        return Err(OicError::scope("wallet network_id does not match profile"));
    }
    if wallet.key_id != key.key_id || wallet.key_epoch != key.key_epoch {
        return Err(OicError::scope("wallet key_id/key_epoch does not match key descriptor"));
    }
    if !key.networks.contains(&profile.network_id) {
        return Err(OicError::scope("key descriptor is not enrolled for this network"));
    }
    Ok(derived)
}

fn check_candidate_scope(candidate: &Candidate, profile: &ChainProfile) -> OicResult<()> {
    if candidate.chain_profile_id != profile.chain_profile_id {
        return Err(OicError::scope("candidate chain_profile_id does not match profile"));
    }
    if candidate.adapter_id.as_str() != ADAPTER_ID {
        return Err(OicError::scope("candidate was not built for the Solana adapter"));
    }
    if candidate.adapter_version != ADAPTER_VERSION {
        return Err(OicError::scope(format!(
            "candidate adapter_version `{}` does not match pinned verifier `{ADAPTER_VERSION}`",
            candidate.adapter_version
        )));
    }
    Ok(())
}

/// Strictly decode candidate message bytes and apply profile version gating.
fn parse_candidate_message(bytes: &[u8], profile: &ChainProfile) -> OicResult<Message> {
    check_profile(profile)?;
    let msg = Message::decode(bytes)?;
    if !version_enabled(profile, msg.version.profile_name()) {
        return Err(OicError::unsupported(format!("message version `{}` is not enabled by the chain profile", msg.version.profile_name())));
    }
    Ok(msg)
}

fn payloads_for(message_bytes: &[u8], version: MessageVersion, key: &KeyDescriptor) -> Vec<NativeSigningPayload> {
    vec![NativeSigningPayload {
        payload_index: 0,
        scheme_id: SchemeId::Ed25519Pure,
        message_or_digest: Bytes(message_bytes.to_vec()),
        required_key_id: key.key_id.clone(),
        native_signing_context: version.signing_context().to_string(),
    }]
}

// ---------------------------------------------------------------------------
// account resolution
// ---------------------------------------------------------------------------

/// Resolve the full account list (static, lookup writable, lookup readonly)
/// from evidence. Missing table -> `StaleEvidence`; deactivated table or index
/// out of range -> `UnverifiableTransaction`; duplicate accounts are rejected.
pub fn resolve_accounts(msg: &Message, evidence: &EvidenceBundle) -> OicResult<(Vec<Pubkey>, Vec<LookupTableBinding>)> {
    let mut writable = Vec::new();
    let mut readonly = Vec::new();
    let mut bindings = Vec::with_capacity(msg.address_table_lookups.len());
    for l in &msg.address_table_lookups {
        let (alt, addrs) = get_alt(evidence, &l.account_key)?;
        if alt.deactivation_slot != u64::MAX {
            return Err(OicError::unverifiable(format!(
                "address lookup table {} is deactivated (deactivation_slot {})",
                to_base58(&l.account_key),
                alt.deactivation_slot
            )));
        }
        let pick = |idx: &[u8]| -> OicResult<Vec<Pubkey>> {
            idx.iter()
                .map(|i| {
                    addrs.get(*i as usize).copied().ok_or_else(|| {
                        OicError::unverifiable(format!("lookup index {i} is out of range for table {} ({} entries)", to_base58(&l.account_key), addrs.len()))
                    })
                })
                .collect()
        };
        let w = pick(&l.writable_indexes)?;
        let r = pick(&l.readonly_indexes)?;
        bindings.push(LookupTableBinding {
            table: Bytes(l.account_key.to_vec()),
            writable_indexes: Bytes(l.writable_indexes.clone()),
            readonly_indexes: Bytes(l.readonly_indexes.clone()),
            resolved_writable: w.iter().map(|k| Bytes(k.to_vec())).collect(),
            resolved_readonly: r.iter().map(|k| Bytes(k.to_vec())).collect(),
            last_extended_slot: alt.last_extended_slot,
        });
        writable.extend(w);
        readonly.extend(r);
    }
    let mut keys = msg.account_keys.clone();
    keys.extend(writable);
    keys.extend(readonly);
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(OicError::unverifiable("resolved account list contains a duplicate account (static key repeated via lookup table?)"));
    }
    Ok((keys, bindings))
}

// ---------------------------------------------------------------------------
// semantic decode
// ---------------------------------------------------------------------------

struct Decoded {
    op: DecodedOperation,
    version: MessageVersion,
    fee_payer: Pubkey,
    recent_blockhash: [u8; 32],
}

fn to_amount(x: u64) -> Amount {
    Amount(x as u128)
}

fn check_destination_token_account(ev: &EvidenceBundle, account: &Pubkey, mint: &Pubkey) -> OicResult<Option<TokenAccountEvidence>> {
    if !ev.items.contains_key(&token_account_key(account)) {
        return Ok(None);
    }
    let ta = get_token_account(ev, account)?;
    if ta.mint.as_slice() != mint {
        return Err(OicError::scope("destination token account evidence is for a different mint"));
    }
    if ta.state != TOKEN_ACCOUNT_INITIALIZED {
        return Err(OicError::unverifiable(format!("destination token account state {} is not initialized", ta.state)));
    }
    if ta.delegate.is_some() {
        return Err(OicError::unverifiable("destination token account has a delegate"));
    }
    if let Some(c) = &ta.close_authority {
        if c != &ta.owner {
            return Err(OicError::unverifiable("destination token account has a close authority other than its owner"));
        }
    }
    Ok(Some(ta))
}

fn decode_message(msg: &Message, message_bytes: &[u8], ctx: &VerifyContext<'_>, wallet: &Pubkey) -> OicResult<Decoded> {
    let ev = ctx.evidence;
    if msg.header.num_required_signatures != 1 {
        return Err(OicError::unsupported(format!(
            "message requires {} signatures; only a single fee-payer signer is supported",
            msg.header.num_required_signatures
        )));
    }
    let fee_payer = msg.account_keys[0];
    if &fee_payer != wallet {
        return Err(OicError::scope("fee payer is not the registered wallet address"));
    }
    let (keys, lookup_tables) = resolve_accounts(msg, ev)?;

    let mut decoded_ixs = Vec::with_capacity(msg.instructions.len());
    for ix in &msg.instructions {
        decoded_ixs.push(decode_instruction(msg, &keys, ix)?);
    }

    let mut cu_limit: Option<u32> = None;
    let mut cu_price: Option<u64> = None;
    let mut value_moving: Option<(usize, SolanaInstruction)> = None;
    let mut ata_create: Option<(usize, SolanaInstruction)> = None;
    let mut non_budget = 0u32;
    for (i, d) in decoded_ixs.iter().enumerate() {
        match d {
            SolanaInstruction::SetComputeUnitLimit { units } => {
                if cu_limit.replace(*units).is_some() {
                    return Err(OicError::unsupported("duplicate SetComputeUnitLimit instruction"));
                }
            }
            SolanaInstruction::SetComputeUnitPrice { micro_lamports } => {
                if cu_price.replace(*micro_lamports).is_some() {
                    return Err(OicError::unsupported("duplicate SetComputeUnitPrice instruction"));
                }
            }
            SolanaInstruction::SystemTransfer { .. } | SolanaInstruction::TokenTransferChecked { .. } => {
                non_budget += 1;
                if value_moving.replace((i, d.clone())).is_some() {
                    return Err(OicError::unsupported("more than one value-moving instruction; only a single direct transfer is supported"));
                }
            }
            SolanaInstruction::CreateAssociatedTokenAccount { .. } => {
                non_budget += 1;
                if ata_create.replace((i, d.clone())).is_some() {
                    return Err(OicError::unsupported("more than one associated token account creation"));
                }
            }
        }
    }
    let Some((transfer_index, transfer)) = value_moving else {
        return Err(OicError::unsupported("message contains no supported value-moving instruction"));
    };

    if ctx.asset.network_id != ctx.profile.network_id {
        return Err(OicError::scope("registered asset belongs to a different network"));
    }

    let mut rent: u64 = 0;
    let mut source_token_account = None;
    let mut destination_token_account = None;
    let mut created_ata = None;
    let (asset, recipient, amount, native_value) = match transfer {
        SolanaInstruction::SystemTransfer { from, to, lamports } => {
            if ata_create.is_some() {
                return Err(OicError::unsupported("associated token account creation is only permitted alongside an SPL TransferChecked"));
            }
            if ctx.asset.asset != AssetKind::Native {
                return Err(OicError::scope("SOL transfer but the registered asset is not native SOL"));
            }
            if from != fee_payer {
                return Err(OicError::unverifiable("System Transfer source is not the fee payer"));
            }
            (AssetKind::Native, to, lamports, lamports)
        }
        SolanaInstruction::TokenTransferChecked { token_program, source, mint, destination, authority, amount, decimals } => {
            let (asset_mint, asset_program) = match &ctx.asset.asset {
                AssetKind::SplToken { mint, token_program } => (to_pubkey(mint.as_slice(), "asset mint")?, to_pubkey(token_program.as_slice(), "asset token program")?),
                other => return Err(OicError::scope(format!("SPL TransferChecked but the registered asset is {other:?}, not an SPL mint"))),
            };
            if asset_program == TOKEN_2022_PROGRAM_ID {
                return Err(OicError::unsupported("registered asset uses Token-2022, which is not supported in this release"));
            }
            if asset_program != TOKEN_PROGRAM_ID {
                return Err(OicError::unsupported("registered asset token program is not the original SPL Token program"));
            }
            if token_program != asset_program {
                return Err(OicError::scope("instruction token program is not the registered asset's token program"));
            }
            if mint != asset_mint {
                return Err(OicError::scope("TransferChecked mint is not the registered asset mint"));
            }
            if ctx.asset.behavior != AssetBehaviorProfile::Standard {
                return Err(OicError::unsupported("asset behavior profile is non-standard; watch-only, not automatically sendable"));
            }
            if decimals != ctx.asset.decimals {
                return Err(OicError::unverifiable(format!("TransferChecked decimals {decimals} differ from registered decimals {}", ctx.asset.decimals)));
            }
            if authority != fee_payer {
                return Err(OicError::unverifiable("TransferChecked authority is not the wallet"));
            }
            let src = get_token_account(ev, &source)?;
            if src.owner.as_slice() != wallet {
                return Err(OicError::unverifiable("source token account is not owned by the wallet"));
            }
            if src.mint.as_slice() != mint {
                return Err(OicError::scope("source token account evidence is for a different mint"));
            }
            if src.state != TOKEN_ACCOUNT_INITIALIZED {
                return Err(OicError::unverifiable(format!("source token account state {} is not initialized", src.state)));
            }
            // Establish the destination owner: PDA derivation against the registered
            // destination, or explicit token-account evidence. Never address shape.
            let registered = ctx.destination.address.as_slice();
            let derived_for_registered = match <[u8; 32]>::try_from(registered) {
                Ok(owner) => Some((owner, associated_token_address(&owner, &mint, &TOKEN_PROGRAM_ID)?)),
                Err(_) => None,
            };
            let dest_evidence = check_destination_token_account(ev, &destination, &mint)?;
            let owner: Pubkey = match (derived_for_registered, &dest_evidence) {
                (Some((owner, ata)), ev_ta) if ata == destination => {
                    if let Some(ta) = ev_ta {
                        if ta.owner.as_slice() != owner {
                            return Err(OicError::unverifiable("destination ATA evidence owner differs from its PDA derivation"));
                        }
                    }
                    owner
                }
                (_, Some(ta)) => to_pubkey(ta.owner.as_slice(), "token account owner")?,
                _ => {
                    return Err(OicError::unverifiable(
                        "cannot establish the destination token account owner: not the derived ATA of the registered destination and no token_account evidence",
                    ))
                }
            };
            if let Some((ata_index, SolanaInstruction::CreateAssociatedTokenAccount { payer, ata, owner: ata_owner, mint: ata_mint, token_program: ata_tp, .. })) = &ata_create {
                if *ata_index > transfer_index {
                    return Err(OicError::unverifiable("associated token account creation must precede the transfer"));
                }
                if *payer != fee_payer {
                    return Err(OicError::unverifiable("ATA creation payer is not the fee payer wallet"));
                }
                if *ata != destination {
                    return Err(OicError::unverifiable("ATA creation is not for the transfer destination"));
                }
                if *ata_mint != mint {
                    return Err(OicError::scope("ATA creation mint is not the registered asset mint"));
                }
                if *ata_owner != owner {
                    return Err(OicError::unverifiable("ATA creation owner is not the destination owner"));
                }
                if *ata_tp != TOKEN_PROGRAM_ID {
                    return Err(OicError::unsupported("ATA creation token program is not the original SPL Token program"));
                }
                if associated_token_address(ata_owner, ata_mint, ata_tp)? != *ata {
                    return Err(OicError::unverifiable("ATA creation account does not match the PDA derivation of (owner, token program, mint)"));
                }
                rent = get_u64(ev, KEY_RENT_TOKEN_ACCOUNT)?;
                created_ata = Some(Bytes(ata.to_vec()));
            }
            source_token_account = Some(Bytes(source.to_vec()));
            destination_token_account = Some(Bytes(destination.to_vec()));
            (AssetKind::SplToken { mint: Bytes(mint.to_vec()), token_program: Bytes(token_program.to_vec()) }, owner, amount, rent)
        }
        _ => return Err(OicError::internal("non value-moving instruction classified as transfer")),
    };

    // Fee accounting (all checked u128).
    let lamports_per_signature = get_u64(ev, KEY_LAMPORTS_PER_SIGNATURE)?;
    let unit_limit = match cu_limit {
        Some(u) if u > MAX_COMPUTE_UNIT_LIMIT => {
            return Err(OicError::unverifiable(format!("SetComputeUnitLimit {u} exceeds the {MAX_COMPUTE_UNIT_LIMIT} maximum")))
        }
        Some(u) => u,
        None => DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT.saturating_mul(non_budget).min(MAX_COMPUTE_UNIT_LIMIT),
    };
    let price = cu_price.unwrap_or(0);
    let priority = (unit_limit as u128 * price as u128).div_ceil(1_000_000);
    let sig_fee = msg.header.num_required_signatures as u128 * lamports_per_signature as u128;
    let max_fee = sig_fee
        .checked_add(priority)
        .and_then(|x| x.checked_add(rent as u128))
        .ok_or_else(|| OicError::unverifiable("fee computation overflows"))?;
    let priority_u64 = u64::try_from(priority).map_err(|_| OicError::unverifiable("priority fee exceeds u64"))?;

    let detail = SolanaNativeDetail {
        message_version: msg.version.profile_name().to_string(),
        message_sha256: oic_canonical_encoding::sha256(message_bytes),
        fee_payer: Bytes(fee_payer.to_vec()),
        recent_blockhash: Bytes(msg.recent_blockhash.to_vec()),
        resolved_account_keys: keys.iter().map(|k| Bytes(k.to_vec())).collect(),
        lookup_tables,
        instructions: decoded_ixs.iter().map(|d| d.label()).collect(),
        compute_unit_limit: unit_limit,
        compute_unit_price_micro_lamports: price,
        lamports_per_signature,
        priority_fee_lamports: priority_u64,
        rent_lamports: rent,
        source_token_account,
        destination_token_account,
        created_associated_token_account: created_ata,
    };
    let op = DecodedOperation::DirectTransfer {
        network_id: ctx.profile.network_id.clone(),
        asset,
        sender: Bytes(fee_payer.to_vec()),
        recipient: Bytes(recipient.to_vec()),
        amount_base_units: to_amount(amount),
        native_value_base_units: to_amount(native_value),
        max_native_fee_base_units: Amount(max_fee),
        native_detail: Bytes(oic_canonical_encoding::canonical_bytes(&detail)?),
    };
    Ok(Decoded { op, version: msg.version, fee_payer, recent_blockhash: msg.recent_blockhash })
}

/// Bounded-template rule for Solana: only the recent blockhash may be filled by
/// the builder, and only when the template declares it fillable.
fn check_template_fill(template: &BoundedTransferTemplate) -> OicResult<()> {
    for f in &template.fillable {
        match f {
            FillableField::SolanaRecentBlockhash => {}
            other => return Err(OicError::scope(format!("template declares EVM fillable field {other:?} for a Solana wallet"))),
        }
    }
    if !template.fillable.contains(&FillableField::SolanaRecentBlockhash) {
        return Err(OicError::unverifiable("template does not permit the builder to fill SolanaRecentBlockhash"));
    }
    Ok(())
}

fn check_blockhash_evidence(blockhash: &[u8; 32], evidence: &EvidenceBundle) -> OicResult<u64> {
    let ev_hash = get_hash(evidence, KEY_RECENT_BLOCKHASH)?;
    if &ev_hash != blockhash {
        return Err(OicError::unverifiable("message recent_blockhash differs from the evidence recent_blockhash"));
    }
    let last_valid = get_u64(evidence, KEY_BLOCKHASH_LAST_VALID_HEIGHT)?;
    if evidence.state.height > last_valid {
        return Err(OicError::stale_evidence(format!(
            "recent blockhash expired: evidence height {} is past last valid height {last_valid}",
            evidence.state.height
        )));
    }
    Ok(last_valid)
}

fn parse_signature_id(tx_id: &ChainTxId) -> OicResult<[u8; 64]> {
    let v = bs58::decode(tx_id.as_str()).into_vec().map_err(|_| OicError::invalid_request("Solana tx id must be base58"))?;
    v.try_into().map_err(|_| OicError::invalid_request("Solana tx id must be a 64-byte signature"))
}

fn verify_ed25519(pubkey: &Pubkey, message: &[u8], sig: &[u8; 64]) -> OicResult<()> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| OicError::invalid_signature("signer public key is not a valid Ed25519 point"))?;
    vk.verify_strict(message, &Signature::from_bytes(sig))
        .map_err(|_| OicError::invalid_signature("Ed25519 signature does not verify over the message bytes"))
}

// ---------------------------------------------------------------------------
// builder
// ---------------------------------------------------------------------------

/// Instruction description used by the legacy compiler.
pub struct InstructionSpec {
    pub program_id: Pubkey,
    /// (account, is_signer, is_writable)
    pub accounts: Vec<(Pubkey, bool, bool)>,
    pub data: Vec<u8>,
}

/// Compile instructions into a legacy message: fee payer first, then
/// signer-writable, signer-readonly, writable, readonly (first-appearance order
/// within each group). The result is re-decoded strictly.
pub fn compile_legacy_message(payer: &Pubkey, instructions: &[InstructionSpec], recent_blockhash: [u8; 32]) -> OicResult<Message> {
    let mut entries: Vec<(Pubkey, bool, bool)> = vec![(*payer, true, true)];
    let mut upsert = |k: Pubkey, s: bool, w: bool| {
        if let Some(e) = entries.iter_mut().find(|e| e.0 == k) {
            e.1 |= s;
            e.2 |= w;
        } else {
            entries.push((k, s, w));
        }
    };
    for ix in instructions {
        for (k, s, w) in &ix.accounts {
            upsert(*k, *s, *w);
        }
        upsert(ix.program_id, false, false);
    }
    let group = |s: bool, w: bool| entries.iter().filter(move |e| e.1 == s && e.2 == w).map(|e| e.0);
    let ordered: Vec<Pubkey> = group(true, true).chain(group(true, false)).chain(group(false, true)).chain(group(false, false)).collect();
    let nsig = entries.iter().filter(|e| e.1).count();
    let ro_signed = entries.iter().filter(|e| e.1 && !e.2).count();
    let ro_unsigned = entries.iter().filter(|e| !e.1 && !e.2).count();
    let idx = |k: &Pubkey| -> OicResult<u8> {
        let i = ordered.iter().position(|o| o == k).ok_or_else(|| OicError::internal("compiled key missing"))?;
        u8::try_from(i).map_err(|_| OicError::invalid_request("too many accounts"))
    };
    let to_u8 = |n: usize| u8::try_from(n).map_err(|_| OicError::invalid_request("too many accounts"));
    let mut compiled = Vec::with_capacity(instructions.len());
    for ix in instructions {
        compiled.push(CompiledInstruction {
            program_id_index: idx(&ix.program_id)?,
            accounts: ix.accounts.iter().map(|(k, _, _)| idx(k)).collect::<OicResult<Vec<_>>>()?,
            data: ix.data.clone(),
        });
    }
    let msg = Message {
        version: MessageVersion::Legacy,
        header: MessageHeader {
            num_required_signatures: to_u8(nsig)?,
            num_readonly_signed_accounts: to_u8(ro_signed)?,
            num_readonly_unsigned_accounts: to_u8(ro_unsigned)?,
        },
        account_keys: ordered,
        recent_blockhash,
        instructions: compiled,
        address_table_lookups: vec![],
    };
    Message::decode(&msg.encode())
}

fn compute_budget_specs(evidence: &EvidenceBundle) -> OicResult<Vec<InstructionSpec>> {
    let mut v = Vec::new();
    if evidence.items.contains_key(KEY_CU_LIMIT) {
        let units = get_u32(evidence, KEY_CU_LIMIT)?;
        v.push(InstructionSpec { program_id: COMPUTE_BUDGET_PROGRAM_ID, accounts: vec![], data: set_compute_unit_limit_data(units) });
    }
    if evidence.items.contains_key(KEY_CU_PRICE) {
        let price = get_u64(evidence, KEY_CU_PRICE)?;
        v.push(InstructionSpec { program_id: COMPUTE_BUDGET_PROGRAM_ID, accounts: vec![], data: set_compute_unit_price_data(price) });
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// ChainAdapter
// ---------------------------------------------------------------------------

impl ChainAdapter for SolanaAdapter {
    fn manifest(&self) -> AdapterManifest {
        AdapterManifest {
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            adapter_version: ADAPTER_VERSION.to_string(),
            verifier_build_hash: verifier_build_hash(),
            signing_schemes: vec![SchemeId::Ed25519Pure],
            accepted_transaction_versions: vec![VERSION_LEGACY.to_string(), VERSION_V0.to_string()],
            supported_operations: vec![
                "system_program.transfer (SOL)".to_string(),
                "spl_token.transfer_checked (original SPL Token program)".to_string(),
                "associated_token_account.create / create_idempotent (destination ATA only, PDA-verified)".to_string(),
                "compute_budget.set_compute_unit_limit / set_compute_unit_price (at most one each)".to_string(),
            ],
            supported_asset_standards: vec![
                "native SOL".to_string(),
                "SPL Token mint under TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA (registered mint, behavior=standard)".to_string(),
            ],
            replay_protection: "Ed25519 signature over the exact message, which commits to a recent blockhash; genesis hash bound \
                via profile network_binding and evidence `genesis_hash` (the message itself carries no network id)"
                .to_string(),
            expiry_behavior: "a message expires once the chain passes the blockhash's last valid block height (evidence \
                `blockhash_last_valid_height`, committed as expires_at_height); durable nonces are not supported"
                .to_string(),
            resource_lock_rules: "reserve SolanaBlockhash{network_id, fee_payer, blockhash}; a fresh blockhash is a new resource and \
                does not conflict with the earlier candidate"
                .to_string(),
            fee_accounting: "max fee = num_signatures * lamports_per_signature + ceil(cu_limit * cu_price / 1e6) + token-account rent \
                when an ATA is created; cu_limit defaults to 200000 per non-compute-budget instruction capped at 1400000; checked u128"
                .to_string(),
            replacement_rules: REPLACEMENT_RULE.to_string(),
            known_external_authorities: vec![
                "mint authority".to_string(),
                "freeze authority".to_string(),
                "token-2022 permanent delegate (unsupported)".to_string(),
                "transfer hook (unsupported)".to_string(),
            ],
            conformance_vector_set: format!(
                "oic-adapter-solana/{ADAPTER_VERSION}: shortvec vectors, solana-message/solana-transaction differential (legacy + v0 \
                 encode/decode, Ed25519 signatures both directions), ATA PDA vector"
            ),
        }
    }

    fn identify_network(&self, profile: &ChainProfile, evidence: &EvidenceBundle) -> OicResult<VerifiedNetworkContext> {
        check_profile(profile)?;
        check_evidence_scope(profile, evidence, None)?;
        check_genesis_evidence(profile, evidence)?;
        Ok(VerifiedNetworkContext {
            chain_profile_id: profile.chain_profile_id.clone(),
            chain_profile_hash: profile.hash()?,
            network_id: profile.network_id.clone(),
            state: evidence.state.clone(),
        })
    }

    fn build_candidate(&self, ctx: &BuildContext) -> OicResult<Candidate> {
        let profile = &ctx.profile;
        check_profile(profile)?;
        if !version_enabled(profile, VERSION_LEGACY) {
            return Err(OicError::unsupported("building requires `legacy` to be enabled; v0 building is not supported"));
        }
        check_evidence_scope(profile, &ctx.evidence, Some(ctx.built_at))?;
        check_genesis_evidence(profile, &ctx.evidence)?;
        let wallet = check_wallet_scope(profile, &ctx.wallet, &ctx.key)?;
        let intent = &ctx.intent;
        if intent.chain_profile_id != profile.chain_profile_id || intent.chain_wallet_id != ctx.wallet.chain_wallet_id || intent.vault_id != ctx.wallet.vault_id {
            return Err(OicError::scope("intent wallet/profile/vault does not match build context"));
        }
        let IntentOperation::AssetTransfer { asset_id, amount_base_units, destination_id, destination_version } = &intent.operation;
        if *asset_id != ctx.asset.asset_id || ctx.asset.network_id != profile.network_id {
            return Err(OicError::scope("intent asset does not match the registered asset for this network"));
        }
        if *destination_id != ctx.destination.destination_id
            || *destination_version != ctx.destination.version
            || ctx.destination.network_id != profile.network_id
        {
            return Err(OicError::scope("intent destination/version/network does not match the registered destination"));
        }
        let dest = to_pubkey(ctx.destination.address.as_slice(), "destination address")?;
        if dest == wallet {
            return Err(OicError::invalid_request("destination is the wallet itself"));
        }
        let amount = u64::try_from(amount_base_units.0).map_err(|_| OicError::invalid_request("amount exceeds u64 lamports/base units"))?;
        let blockhash = get_hash(&ctx.evidence, KEY_RECENT_BLOCKHASH)?;
        get_u64(&ctx.evidence, KEY_BLOCKHASH_LAST_VALID_HEIGHT)?;

        let mut specs = compute_budget_specs(&ctx.evidence)?;
        match &ctx.asset.asset {
            AssetKind::Native => {
                specs.push(InstructionSpec {
                    program_id: SYSTEM_PROGRAM_ID,
                    accounts: vec![(wallet, true, true), (dest, false, true)],
                    data: system_transfer_data(amount),
                });
            }
            AssetKind::SplToken { mint, token_program } => {
                let mint = to_pubkey(mint.as_slice(), "asset mint")?;
                let tp = to_pubkey(token_program.as_slice(), "asset token program")?;
                if tp == TOKEN_2022_PROGRAM_ID {
                    return Err(OicError::unsupported("Token-2022 assets are not supported in this release"));
                }
                if tp != TOKEN_PROGRAM_ID {
                    return Err(OicError::unsupported("asset token program is not the original SPL Token program"));
                }
                if ctx.asset.behavior != AssetBehaviorProfile::Standard {
                    return Err(OicError::unsupported("asset behavior profile is non-standard; not automatically sendable"));
                }
                let source = associated_token_address(&wallet, &mint, &TOKEN_PROGRAM_ID)?;
                get_token_account(&ctx.evidence, &source)?;
                let dest_ata = associated_token_address(&dest, &mint, &TOKEN_PROGRAM_ID)?;
                if !ctx.evidence.items.contains_key(&token_account_key(&dest_ata)) {
                    get_u64(&ctx.evidence, KEY_RENT_TOKEN_ACCOUNT)?;
                    specs.push(InstructionSpec {
                        program_id: ATA_PROGRAM_ID,
                        accounts: vec![
                            (wallet, true, true),
                            (dest_ata, false, true),
                            (dest, false, false),
                            (mint, false, false),
                            (SYSTEM_PROGRAM_ID, false, false),
                            (TOKEN_PROGRAM_ID, false, false),
                        ],
                        data: ata_create_idempotent_data(),
                    });
                }
                specs.push(InstructionSpec {
                    program_id: TOKEN_PROGRAM_ID,
                    accounts: vec![(source, false, true), (mint, false, false), (dest_ata, false, true), (wallet, true, false)],
                    data: transfer_checked_data(amount, ctx.asset.decimals),
                });
            }
            other => return Err(OicError::unsupported(format!("asset kind {other:?} is not a Solana asset"))),
        }
        let msg = compile_legacy_message(&wallet, &specs, blockhash)?;
        let bytes = msg.encode();

        let vctx = VerifyContext {
            profile,
            wallet: &ctx.wallet,
            key: &ctx.key,
            asset: &ctx.asset,
            destination: &ctx.destination,
            evidence: &ctx.evidence,
        };
        let decoded = decode_message(&msg, &bytes, &vctx, &wallet)?;
        let fee = decoded.op.max_native_fee();
        if fee > intent.constraints.max_network_fee_base_units {
            return Err(OicError::budget(format!(
                "worst-case fee {fee} exceeds intent max network fee {}",
                intent.constraints.max_network_fee_base_units
            )));
        }
        let candidate = Candidate {
            candidate_id: ctx.candidate_id.clone(),
            candidate_revision: ctx.candidate_revision,
            intent_id: intent.intent_id.clone(),
            operation_family_id: ctx.operation_family_id.clone(),
            chain_profile_id: profile.chain_profile_id.clone(),
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            adapter_version: ADAPTER_VERSION.to_string(),
            signing_payloads: payloads_for(&bytes, msg.version, &ctx.key),
            native_unsigned_bytes: Bytes(bytes),
            evidence_bundle_hash: evidence_hash(&ctx.evidence)?,
            built_at: ctx.built_at,
        };
        // Builder self-check with the same verifier the signer runs.
        self.verify_candidate(&candidate, &AuthorizationTarget::Intent(intent), &vctx)?;
        Ok(candidate)
    }

    fn decode_candidate(&self, candidate: &Candidate, ctx: &VerifyContext<'_>) -> OicResult<DecodedOperation> {
        check_candidate_scope(candidate, ctx.profile)?;
        let wallet = check_key_scheme(ctx.key)?;
        let msg = parse_candidate_message(candidate.native_unsigned_bytes.as_slice(), ctx.profile)?;
        Ok(decode_message(&msg, candidate.native_unsigned_bytes.as_slice(), ctx, &wallet)?.op)
    }

    fn verify_candidate(&self, candidate: &Candidate, target: &AuthorizationTarget<'_>, ctx: &VerifyContext<'_>) -> OicResult<VerifiedOperation> {
        let profile = ctx.profile;
        check_evidence_scope(profile, ctx.evidence, None)?;
        check_candidate_scope(candidate, profile)?;
        let wallet = check_wallet_scope(profile, ctx.wallet, ctx.key)?;
        check_genesis_evidence(profile, ctx.evidence)?;
        let bytes = candidate.native_unsigned_bytes.as_slice();
        let msg = parse_candidate_message(bytes, profile)?;
        let d = decode_message(&msg, bytes, ctx, &wallet)?;
        let decoded = d.op;

        // The signer derives payloads itself; the candidate's array is only a comparison target.
        let payloads = payloads_for(bytes, d.version, ctx.key);
        if candidate.signing_payloads != payloads {
            return Err(OicError::unverifiable("candidate signing payloads differ from payloads derived from native bytes"));
        }

        // Asset identity is network + mint (+ token program), never symbol/decimals.
        if decoded.asset() != &ctx.asset.asset {
            return Err(OicError::scope("decoded asset identity does not match the registered asset"));
        }

        let dest = ctx.destination;
        if dest.network_id != profile.network_id {
            return Err(OicError::scope("destination network does not match profile"));
        }
        if dest.address.as_slice() != decoded.recipient().as_slice() {
            return Err(OicError::scope("decoded recipient does not match the registered destination address"));
        }
        if !dest.allowed_assets.is_empty() && !dest.allowed_assets.contains(&ctx.asset.asset_id) {
            return Err(OicError::scope("destination does not allow this asset"));
        }

        let (asset_id, amount, dest_id, dest_version, max_fee, wallet_id) = match target {
            AuthorizationTarget::Intent(intent) => {
                if intent.chain_profile_id != profile.chain_profile_id {
                    return Err(OicError::scope("intent chain_profile_id does not match profile"));
                }
                if candidate.intent_id != intent.intent_id {
                    return Err(OicError::scope("candidate intent_id does not match intent"));
                }
                let IntentOperation::AssetTransfer { asset_id, amount_base_units, destination_id, destination_version } = &intent.operation;
                (asset_id, *amount_base_units, destination_id, *destination_version, intent.constraints.max_network_fee_base_units, &intent.chain_wallet_id)
            }
            AuthorizationTarget::Template(t) => {
                if t.network_id != profile.network_id {
                    return Err(OicError::scope("template network does not match profile"));
                }
                if t.destination_address != dest.address {
                    return Err(OicError::scope("template destination address does not match the registered destination"));
                }
                check_template_fill(t)?;
                (&t.asset_id, t.amount_base_units, &t.destination_id, t.destination_version, t.max_native_fee_base_units, &t.chain_wallet_id)
            }
        };
        if *wallet_id != ctx.wallet.chain_wallet_id {
            return Err(OicError::scope("authorization target is for a different chain wallet"));
        }
        if *asset_id != ctx.asset.asset_id {
            return Err(OicError::scope("authorization target asset_id does not match the registered asset"));
        }
        if *dest_id != dest.destination_id || dest_version != dest.version {
            return Err(OicError::scope("authorization target destination/version does not match the registered destination"));
        }
        if decoded.amount() != amount {
            return Err(OicError::unverifiable(format!("decoded amount {} differs from authorized amount {amount}", decoded.amount())));
        }
        if decoded.max_native_fee() > max_fee {
            return Err(OicError::budget(format!("worst-case native fee {} exceeds authorized maximum {max_fee}", decoded.max_native_fee())));
        }

        // The blockhash is always bound to evidence and reserved as a resource.
        check_blockhash_evidence(&d.recent_blockhash, ctx.evidence)?;

        let claims = ResourceClaims {
            resources: vec![NativeResource::SolanaBlockhash {
                network_id: profile.network_id.clone(),
                fee_payer: Bytes(d.fee_payer.to_vec()),
                blockhash: Bytes(d.recent_blockhash.to_vec()),
            }],
            asset_outflows: vec![AssetOutflow { asset_id: ctx.asset.asset_id.clone(), amount_base_units: decoded.amount() }],
            native_fees: vec![NativeFee { network_id: profile.network_id.clone(), amount_base_units: decoded.max_native_fee() }],
        };
        Ok(VerifiedOperation {
            decoded_operation_hash: decoded_operation_hash(&decoded)?,
            decoded,
            signing_payloads: payloads,
            claims,
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            adapter_version: ADAPTER_VERSION.to_string(),
            verifier_build_hash: verifier_build_hash(),
        })
    }

    fn signing_payloads(&self, native_unsigned_bytes: &Bytes, key: &KeyDescriptor) -> OicResult<Vec<NativeSigningPayload>> {
        check_key_scheme(key)?;
        let msg = Message::decode(native_unsigned_bytes.as_slice())?;
        Ok(payloads_for(native_unsigned_bytes.as_slice(), msg.version, key))
    }

    fn assemble_signed_transaction(&self, candidate: &Candidate, key: &KeyDescriptor, signatures: &[SignatureBytes]) -> OicResult<SignedTransaction> {
        let [sig] = signatures else {
            return Err(OicError::invalid_signature(format!("Solana transfers need exactly one signature, got {}", signatures.len())));
        };
        if sig.scheme != SchemeId::Ed25519Pure {
            return Err(OicError::invalid_signature(format!("signature scheme {:?} is not pure Ed25519", sig.scheme)));
        }
        let raw: [u8; 64] = sig.bytes.as_slice().try_into().map_err(|_| OicError::invalid_signature("Ed25519 signature must be 64 bytes"))?;
        let pk = check_key_scheme(key)?;
        let msg = Message::decode(candidate.native_unsigned_bytes.as_slice())?;
        if msg.header.num_required_signatures != 1 || msg.account_keys[0] != pk {
            return Err(OicError::scope("candidate fee payer / signer set does not match the signing key"));
        }
        verify_ed25519(&pk, candidate.native_unsigned_bytes.as_slice(), &raw)?;
        let signed_bytes = Transaction::encode(&[raw], candidate.native_unsigned_bytes.as_slice());
        let signed = SignedTransaction {
            candidate_id: candidate.candidate_id.clone(),
            candidate_revision: candidate.candidate_revision,
            signed_bytes: Bytes(signed_bytes),
            chain_tx_id: ChainTxId::unchecked(to_base58(&raw)),
        };
        self.verify_signed_transaction(&signed, candidate, key)?;
        Ok(signed)
    }

    fn verify_signed_transaction(&self, signed: &SignedTransaction, candidate: &Candidate, key: &KeyDescriptor) -> OicResult<VerifiedSignedTransaction> {
        if signed.candidate_id != candidate.candidate_id || signed.candidate_revision != candidate.candidate_revision {
            return Err(OicError::scope("signed transaction is for a different candidate/revision"));
        }
        let pk = check_key_scheme(key)?;
        let tx = Transaction::decode(signed.signed_bytes.as_slice())?;
        if tx.message_bytes != candidate.native_unsigned_bytes.as_slice() {
            return Err(OicError::unverifiable("signed transaction message differs from the approved candidate bytes"));
        }
        let [sig] = tx.signatures.as_slice() else {
            return Err(OicError::unverifiable("signed transaction must carry exactly one signature"));
        };
        if tx.message.account_keys[0] != pk {
            return Err(OicError::invalid_signature("fee payer is not the registered key"));
        }
        if parse_signature_id(&signed.chain_tx_id)? != *sig {
            return Err(OicError::unverifiable("chain_tx_id is not the base58 fee-payer signature"));
        }
        verify_ed25519(&pk, &tx.message_bytes, sig)?;
        Ok(VerifiedSignedTransaction { signed: signed.clone(), verified_signers: vec![Bytes(pk.to_vec())] })
    }

    /// Read inclusion or finality from scoped signature-status evidence.
    /// `fee_paid` includes both network fees and actual token-account funding in
    /// lamports. Returns `Finalized` at or above the profile's finality commitment,
    /// otherwise `Included`, including for failed execution. Profile, evidence,
    /// and transaction-ID validation errors propagate; missing evidence is an
    /// error rather than a not-yet-visible result.
    fn observe(&self, tx_id: &ChainTxId, profile: &ChainProfile, evidence: &EvidenceBundle) -> OicResult<ChainObservation> {
        check_profile(profile)?;
        check_evidence_scope(profile, evidence, None)?;
        let sig = parse_signature_id(tx_id)?;
        let obs = get_tx_observation(evidence, &sig)?;
        let rank = commitment_rank(&obs.commitment).ok_or_else(|| OicError::stale_evidence("unknown commitment"))?;
        let final_rank = commitment_rank(&profile.finality_commitment).ok_or_else(|| OicError::unsupported("unknown profile commitment"))?;
        let state = StateReference { height: obs.slot, hash: obs.block_hash.clone(), commitment: obs.commitment.clone() };
        // The reserved native ceiling includes ATA rent. Settling just the
        // RPC fee would incorrectly replenish allowance already spent on rent.
        let native_cost = Amount(obs.fee as u128 + obs.account_funding as u128);
        if rank >= final_rank {
            let raw = get_item(evidence, &tx_key(&sig))?;
            Ok(ChainObservation::Finalized {
                tx_id: tx_id.clone(),
                state,
                execution_success: obs.success,
                fee_paid: native_cost,
                effects_hash: oic_canonical_encoding::sha256(raw),
            })
        } else {
            Ok(ChainObservation::Included { tx_id: tx_id.clone(), state, execution_success: obs.success, fee_paid: native_cost })
        }
    }

    fn prove_invalidation(
        &self,
        family: &OperationFamilyId,
        candidates: &[Candidate],
        profile: &ChainProfile,
        evidence: &EvidenceBundle,
    ) -> OicResult<InvalidationEvidence> {
        check_profile(profile)?;
        check_evidence_scope(profile, evidence, None)?;
        check_genesis_evidence(profile, evidence)?;
        if candidates.is_empty() {
            return Ok(InvalidationEvidence::Unknown);
        }
        for c in candidates {
            if &c.operation_family_id != family {
                return Err(OicError::invalid_request("candidate does not belong to the operation family"));
            }
            check_candidate_scope(c, profile)?;
        }
        // Expiry must be observed under the profile's finality commitment. A timeout is never proof.
        if evidence.state.commitment != profile.finality_commitment {
            return Ok(InvalidationEvidence::Unknown);
        }
        let mut expired = Vec::with_capacity(candidates.len());
        for c in candidates {
            let msg = Message::decode(c.native_unsigned_bytes.as_slice())?;
            let bh = msg.recent_blockhash;
            let last_valid = if let Some(v) = evidence.items.get(&last_valid_height_key(&bh)) {
                let b: [u8; 8] = v.as_slice().try_into().map_err(|_| OicError::stale_evidence("last valid height item must be 8 bytes"))?;
                u64::from_le_bytes(b)
            } else if evidence.items.get(KEY_RECENT_BLOCKHASH).map(|b| b.as_slice()) == Some(&bh[..]) {
                get_u64(evidence, KEY_BLOCKHASH_LAST_VALID_HEIGHT)?
            } else {
                return Ok(InvalidationEvidence::Unknown);
            };
            if evidence.state.height < last_valid.saturating_add(profile.finality_depth) {
                return Ok(InvalidationEvidence::Unknown);
            }
            // Every possibly-issued candidate's signature must be known so that a
            // landing before expiry can be ruled out.
            let Some(signed) = evidence.items.get(&signed_tx_key(c.candidate_id.as_str(), c.candidate_revision)) else {
                return Ok(InvalidationEvidence::Unknown);
            };
            let tx = Transaction::decode(signed.as_slice())?;
            if tx.message_bytes != c.native_unsigned_bytes.as_slice() {
                return Err(OicError::unverifiable("signed_tx evidence does not match the candidate message bytes"));
            }
            for (i, sig) in tx.signatures.iter().enumerate() {
                verify_ed25519(&tx.message.account_keys[i], &tx.message_bytes, sig)?;
                if evidence.items.contains_key(&tx_key(sig)) && get_tx_observation(evidence, sig)?.success {
                    return Ok(InvalidationEvidence::Unknown);
                }
            }
            expired.push(format!("{}@{last_valid}", to_base58(&bh)));
        }
        Ok(InvalidationEvidence::Definitive {
            reason: format!(
                "all family blockhashes expired: evidence block height {} >= last_valid_height + finality_depth {} under `{}` for [{}]; no family signature succeeded",
                evidence.state.height,
                profile.finality_depth,
                profile.finality_commitment,
                expired.join(", ")
            ),
            state: evidence.state.clone(),
        })
    }

    fn validity_constraints(&self, candidate: &Candidate, evidence: &EvidenceBundle) -> OicResult<ChainValidityConstraints> {
        let msg = Message::decode(candidate.native_unsigned_bytes.as_slice())?;
        let last_valid = if get_hash(evidence, KEY_RECENT_BLOCKHASH)? == msg.recent_blockhash {
            get_u64(evidence, KEY_BLOCKHASH_LAST_VALID_HEIGHT)?
        } else {
            get_u64(evidence, &last_valid_height_key(&msg.recent_blockhash))?
        };
        Ok(ChainValidityConstraints { expires_at_height: Some(last_valid), replacement_rule: REPLACEMENT_RULE.to_string() })
    }

    fn derive_address(&self, key: &PublicKey) -> OicResult<(Bytes, String)> {
        let pk = ed25519_key(key)?;
        Ok((Bytes(pk.to_vec()), to_base58(&pk)))
    }
}
