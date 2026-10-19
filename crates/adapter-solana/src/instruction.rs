//! Pinned decoders for the instructions this adapter understands.
//!
//! Every top-level instruction is decoded here or rejected. A rejection names
//! the program and the instruction tag. Account permissions (signer, writable)
//! are checked against the message header, and account counts are exact: extra
//! accounts (for example SPL multisig signers) are rejected.

use crate::address::*;
use crate::message::{CompiledInstruction, Message};
use oic_domain_types::{OicError, OicResult};

/// Default compute-unit limit charged per non-compute-budget instruction.
pub const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT: u32 = 200_000;
/// Maximum compute units per transaction.
pub const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub const SYSTEM_IX_TRANSFER: u32 = 2;
pub const SYSTEM_IX_ADVANCE_NONCE: u32 = 4;
pub const COMPUTE_BUDGET_IX_SET_LIMIT: u8 = 2;
pub const COMPUTE_BUDGET_IX_SET_PRICE: u8 = 3;
pub const TOKEN_IX_TRANSFER: u8 = 3;
pub const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;
pub const ATA_IX_CREATE: u8 = 0;
pub const ATA_IX_CREATE_IDEMPOTENT: u8 = 1;

/// A decoded, permission-checked instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SolanaInstruction {
    SystemTransfer { from: Pubkey, to: Pubkey, lamports: u64 },
    SetComputeUnitLimit { units: u32 },
    SetComputeUnitPrice { micro_lamports: u64 },
    TokenTransferChecked { token_program: Pubkey, source: Pubkey, mint: Pubkey, destination: Pubkey, authority: Pubkey, amount: u64, decimals: u8 },
    CreateAssociatedTokenAccount { idempotent: bool, payer: Pubkey, ata: Pubkey, owner: Pubkey, mint: Pubkey, token_program: Pubkey },
}

impl SolanaInstruction {
    /// Short stable label bound into `native_detail`.
    pub fn label(&self) -> String {
        match self {
            SolanaInstruction::SystemTransfer { lamports, .. } => format!("system.transfer({lamports})"),
            SolanaInstruction::SetComputeUnitLimit { units } => format!("compute_budget.set_compute_unit_limit({units})"),
            SolanaInstruction::SetComputeUnitPrice { micro_lamports } => format!("compute_budget.set_compute_unit_price({micro_lamports})"),
            SolanaInstruction::TokenTransferChecked { amount, decimals, .. } => format!("spl_token.transfer_checked({amount},{decimals})"),
            SolanaInstruction::CreateAssociatedTokenAccount { idempotent: true, .. } => "ata.create_idempotent".to_string(),
            SolanaInstruction::CreateAssociatedTokenAccount { idempotent: false, .. } => "ata.create".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// data encoders (builder side)
// ---------------------------------------------------------------------------

pub fn system_transfer_data(lamports: u64) -> Vec<u8> {
    let mut d = SYSTEM_IX_TRANSFER.to_le_bytes().to_vec();
    d.extend_from_slice(&lamports.to_le_bytes());
    d
}

pub fn set_compute_unit_limit_data(units: u32) -> Vec<u8> {
    let mut d = vec![COMPUTE_BUDGET_IX_SET_LIMIT];
    d.extend_from_slice(&units.to_le_bytes());
    d
}

pub fn set_compute_unit_price_data(micro_lamports: u64) -> Vec<u8> {
    let mut d = vec![COMPUTE_BUDGET_IX_SET_PRICE];
    d.extend_from_slice(&micro_lamports.to_le_bytes());
    d
}

pub fn transfer_checked_data(amount: u64, decimals: u8) -> Vec<u8> {
    let mut d = vec![TOKEN_IX_TRANSFER_CHECKED];
    d.extend_from_slice(&amount.to_le_bytes());
    d.push(decimals);
    d
}

pub fn ata_create_idempotent_data() -> Vec<u8> {
    vec![ATA_IX_CREATE_IDEMPOTENT]
}

// ---------------------------------------------------------------------------
// names for rejections
// ---------------------------------------------------------------------------

pub fn system_instruction_name(tag: u32) -> &'static str {
    match tag {
        0 => "CreateAccount",
        1 => "Assign",
        2 => "Transfer",
        3 => "CreateAccountWithSeed",
        4 => "AdvanceNonceAccount (durable nonce)",
        5 => "WithdrawNonceAccount",
        6 => "InitializeNonceAccount",
        7 => "AuthorizeNonceAccount",
        8 => "Allocate",
        9 => "AllocateWithSeed",
        10 => "AssignWithSeed",
        11 => "TransferWithSeed",
        12 => "UpgradeNonceAccount",
        13 => "CreateAccountAllowPrefund",
        _ => "unknown",
    }
}

pub fn compute_budget_instruction_name(tag: u8) -> &'static str {
    match tag {
        0 => "RequestUnits (deprecated)",
        1 => "RequestHeapFrame",
        2 => "SetComputeUnitLimit",
        3 => "SetComputeUnitPrice",
        4 => "SetLoadedAccountsDataSizeLimit",
        _ => "unknown",
    }
}

pub fn token_instruction_name(tag: u8) -> &'static str {
    match tag {
        0 => "InitializeMint",
        1 => "InitializeAccount",
        2 => "InitializeMultisig",
        3 => "Transfer (unchecked)",
        4 => "Approve",
        5 => "Revoke",
        6 => "SetAuthority",
        7 => "MintTo",
        8 => "Burn",
        9 => "CloseAccount",
        10 => "FreezeAccount",
        11 => "ThawAccount",
        12 => "TransferChecked",
        13 => "ApproveChecked",
        14 => "MintToChecked",
        15 => "BurnChecked",
        16 => "InitializeAccount2",
        17 => "SyncNative",
        18 => "InitializeAccount3",
        19 => "InitializeMultisig2",
        20 => "InitializeMint2",
        21 => "GetAccountDataSize",
        22 => "InitializeImmutableOwner",
        23 => "AmountToUiAmount",
        24 => "UiAmountToAmount",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// decoder
// ---------------------------------------------------------------------------

struct Accounts<'a> {
    msg: &'a Message,
    keys: &'a [Pubkey],
    ix: &'a CompiledInstruction,
    what: &'static str,
}

impl Accounts<'_> {
    fn expect_count(&self, n: usize) -> OicResult<()> {
        if self.ix.accounts.len() != n {
            return Err(OicError::unsupported(format!(
                "{} must reference exactly {n} accounts, found {} (extra signers / multisig are not supported)",
                self.what,
                self.ix.accounts.len()
            )));
        }
        Ok(())
    }

    fn get(&self, pos: usize, name: &str, signer: bool, writable: bool) -> OicResult<Pubkey> {
        let idx = *self.ix.accounts.get(pos).ok_or_else(|| OicError::unverifiable(format!("{} is missing account `{name}`", self.what)))? as usize;
        let key = *self.keys.get(idx).ok_or_else(|| OicError::unverifiable("instruction account index out of range"))?;
        if signer && !self.msg.is_signer(idx) {
            let why = if idx >= self.msg.account_keys.len() { " (lookup-resolved accounts can never be signers)" } else { "" };
            return Err(OicError::unverifiable(format!("{} account `{name}` must be a signer{why}", self.what)));
        }
        if writable && !self.msg.is_writable(idx) {
            return Err(OicError::unverifiable(format!("{} account `{name}` must be writable", self.what)));
        }
        Ok(key)
    }
}

fn exact<const N: usize>(data: &[u8], what: &str) -> OicResult<[u8; N]> {
    data.try_into().map_err(|_| OicError::unverifiable(format!("{what} instruction data must be exactly {N} bytes, found {}", data.len())))
}

/// Decode one top-level instruction against the fully resolved account list.
pub fn decode_instruction(msg: &Message, keys: &[Pubkey], ix: &CompiledInstruction) -> OicResult<SolanaInstruction> {
    let program = *keys.get(ix.program_id_index as usize).ok_or_else(|| OicError::unverifiable("program id index out of range"))?;
    let data = ix.data.as_slice();
    match program {
        SYSTEM_PROGRAM_ID => {
            let tag = data.get(..4).map(|t| u32::from_le_bytes([t[0], t[1], t[2], t[3]]));
            let Some(tag) = tag else {
                return Err(OicError::unverifiable("System Program instruction data shorter than its 4-byte tag"));
            };
            if tag != SYSTEM_IX_TRANSFER {
                return Err(OicError::unsupported(format!(
                    "System Program instruction {tag} `{}` is not supported; only Transfer",
                    system_instruction_name(tag)
                )));
            }
            let d = exact::<12>(data, "System Program Transfer")?;
            let lamports = u64::from_le_bytes(d[4..12].try_into().expect("8 bytes"));
            let a = Accounts { msg, keys, ix, what: "System Program Transfer" };
            a.expect_count(2)?;
            let from = a.get(0, "from", true, true)?;
            let to = a.get(1, "to", false, true)?;
            Ok(SolanaInstruction::SystemTransfer { from, to, lamports })
        }
        COMPUTE_BUDGET_PROGRAM_ID => {
            let Some(&tag) = data.first() else {
                return Err(OicError::unverifiable("Compute Budget instruction has empty data"));
            };
            if !ix.accounts.is_empty() {
                return Err(OicError::unverifiable("Compute Budget instructions take no accounts"));
            }
            match tag {
                COMPUTE_BUDGET_IX_SET_LIMIT => {
                    let d = exact::<5>(data, "SetComputeUnitLimit")?;
                    Ok(SolanaInstruction::SetComputeUnitLimit { units: u32::from_le_bytes(d[1..5].try_into().expect("4 bytes")) })
                }
                COMPUTE_BUDGET_IX_SET_PRICE => {
                    let d = exact::<9>(data, "SetComputeUnitPrice")?;
                    Ok(SolanaInstruction::SetComputeUnitPrice { micro_lamports: u64::from_le_bytes(d[1..9].try_into().expect("8 bytes")) })
                }
                other => Err(OicError::unsupported(format!(
                    "Compute Budget instruction {other} `{}` is not supported",
                    compute_budget_instruction_name(other)
                ))),
            }
        }
        TOKEN_PROGRAM_ID => {
            let Some(&tag) = data.first() else {
                return Err(OicError::unverifiable("SPL Token instruction has empty data"));
            };
            if tag != TOKEN_IX_TRANSFER_CHECKED {
                return Err(OicError::unsupported(format!(
                    "SPL Token instruction {tag} `{}` is not supported; only TransferChecked",
                    token_instruction_name(tag)
                )));
            }
            let d = exact::<10>(data, "SPL Token TransferChecked")?;
            let amount = u64::from_le_bytes(d[1..9].try_into().expect("8 bytes"));
            let decimals = d[9];
            let a = Accounts { msg, keys, ix, what: "SPL Token TransferChecked" };
            a.expect_count(4)?;
            let source = a.get(0, "source", false, true)?;
            let mint = a.get(1, "mint", false, false)?;
            let destination = a.get(2, "destination", false, true)?;
            let authority = a.get(3, "authority", true, false)?;
            Ok(SolanaInstruction::TokenTransferChecked { token_program: program, source, mint, destination, authority, amount, decimals })
        }
        TOKEN_2022_PROGRAM_ID => Err(OicError::unsupported(format!(
            "Token-2022 program ({}) instruction {} is not supported in this release; Token-2022 requires extension-aware onboarding",
            to_base58(&TOKEN_2022_PROGRAM_ID),
            data.first().map(|t| t.to_string()).unwrap_or_else(|| "<empty>".into())
        ))),
        ATA_PROGRAM_ID => {
            let idempotent = match data {
                [] => false,
                [ATA_IX_CREATE_IDEMPOTENT] => true,
                [t, ..] => {
                    let name = match *t {
                        ATA_IX_CREATE => "Create (with trailing data)",
                        ATA_IX_CREATE_IDEMPOTENT => "CreateIdempotent (with trailing data)",
                        2 => "RecoverNested",
                        _ => "unknown",
                    };
                    return Err(OicError::unsupported(format!("Associated Token Account instruction {t} `{name}` is not supported")));
                }
            };
            let a = Accounts { msg, keys, ix, what: "Associated Token Account Create" };
            a.expect_count(6)?;
            let payer = a.get(0, "payer", true, true)?;
            let ata = a.get(1, "associated_token_account", false, true)?;
            let owner = a.get(2, "wallet_owner", false, false)?;
            let mint = a.get(3, "mint", false, false)?;
            let system = a.get(4, "system_program", false, false)?;
            let token_program = a.get(5, "token_program", false, false)?;
            if system != SYSTEM_PROGRAM_ID {
                return Err(OicError::unverifiable("ATA Create system_program account is not the System Program"));
            }
            if token_program == TOKEN_2022_PROGRAM_ID {
                return Err(OicError::unsupported("ATA Create for a Token-2022 account is not supported in this release"));
            }
            if token_program != TOKEN_PROGRAM_ID {
                return Err(OicError::unverifiable("ATA Create token_program account is not the original SPL Token program"));
            }
            Ok(SolanaInstruction::CreateAssociatedTokenAccount { idempotent, payer, ata, owner, mint, token_program })
        }
        other => {
            let tag = data.first().map(|t| t.to_string()).unwrap_or_else(|| "<empty>".into());
            Err(OicError::unsupported(format!("instruction for {} (first data byte {tag}) is not supported", describe_program(&other))))
        }
    }
}
