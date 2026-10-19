//! Solana addresses, well-known program ids, and program-derived addresses.
//!
//! An address is 32 raw bytes, shown as base58. Program-derived addresses
//! (PDAs) are derived exactly as the runtime derives them:
//!
//! ```text
//! candidate = SHA256(seed_0 || ... || seed_n || [bump] || program_id || "ProgramDerivedAddress")
//! ```
//!
//! `find_program_address` searches bumps 255..=0 and returns the first candidate
//! that is **not** a valid compressed Ed25519 point (off curve), so no private key
//! can exist for it. Associated token accounts (ATAs) are the PDA of
//! `[owner, token_program, mint]` under the ATA program.

use curve25519_dalek::edwards::CompressedEdwardsY;
use oic_domain_types::{OicError, OicResult};
use sha2::{Digest, Sha256};

/// A 32-byte Solana address (public key or PDA).
pub type Pubkey = [u8; 32];

/// `11111111111111111111111111111111`
pub const SYSTEM_PROGRAM_ID: Pubkey = [0u8; 32];
/// `ComputeBudget111111111111111111111111111111`
pub const COMPUTE_BUDGET_PROGRAM_ID: Pubkey = [
    3, 6, 70, 111, 229, 33, 23, 50, 255, 236, 173, 186, 114, 195, 155, 231, 188, 140, 229, 187, 197, 247, 18, 107, 44, 67, 155, 58, 64, 0, 0, 0,
];
/// `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` (original SPL Token program)
pub const TOKEN_PROGRAM_ID: Pubkey = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255,
    0, 169,
];
/// `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` (Token-2022, unsupported in this release)
pub const TOKEN_2022_PROGRAM_ID: Pubkey = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77, 131, 185, 13, 39, 254, 189, 249, 40, 216, 161,
    139, 252,
];
/// `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`
pub const ATA_PROGRAM_ID: Pubkey = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233,
    248, 89,
];
/// `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`
pub const MEMO_V2_PROGRAM_ID: Pubkey = [
    5, 74, 83, 90, 153, 41, 33, 6, 77, 36, 232, 113, 96, 218, 56, 124, 124, 53, 181, 221, 188, 146, 187, 129, 228, 31, 168, 64, 65, 5, 68, 141,
];
/// `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo`
pub const MEMO_V1_PROGRAM_ID: Pubkey = [
    5, 74, 83, 80, 248, 93, 200, 130, 214, 20, 165, 86, 114, 120, 138, 41, 109, 223, 30, 171, 171, 208, 166, 6, 120, 136, 73, 50, 244, 238, 246,
    160,
];
/// `AddressLookupTab1e1111111111111111111111111`
pub const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: Pubkey = [
    2, 119, 166, 175, 151, 51, 155, 122, 200, 141, 24, 146, 201, 4, 70, 245, 0, 2, 48, 146, 102, 246, 46, 83, 193, 24, 36, 73, 130, 0, 0, 0,
];
/// `Stake11111111111111111111111111111111111111`
pub const STAKE_PROGRAM_ID: Pubkey = [
    6, 161, 216, 23, 145, 55, 84, 42, 152, 52, 55, 189, 254, 42, 122, 178, 85, 127, 83, 92, 138, 120, 114, 43, 104, 164, 157, 192, 0, 0, 0, 0,
];
/// `Vote111111111111111111111111111111111111111`
pub const VOTE_PROGRAM_ID: Pubkey = [
    7, 97, 72, 29, 53, 116, 116, 187, 124, 77, 118, 36, 235, 211, 189, 179, 216, 53, 94, 115, 209, 16, 67, 252, 13, 163, 83, 128, 0, 0, 0, 0,
];
/// `BPFLoaderUpgradeab1e11111111111111111111111`
pub const BPF_LOADER_UPGRADEABLE_PROGRAM_ID: Pubkey = [
    2, 168, 246, 145, 78, 136, 161, 176, 226, 16, 21, 62, 247, 99, 174, 43, 0, 194, 185, 61, 22, 193, 36, 210, 192, 83, 122, 16, 4, 128, 0, 0,
];

/// Marker appended to every PDA hash input.
pub const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";
/// Maximum number of seeds and maximum seed length accepted by the runtime.
pub const MAX_SEEDS: usize = 16;
pub const MAX_SEED_LEN: usize = 32;

/// Base58 display form of an address.
pub fn to_base58(key: &[u8]) -> String {
    bs58::encode(key).into_string()
}

/// Parse a base58 address. Must decode to exactly 32 bytes.
pub fn from_base58(s: &str) -> OicResult<Pubkey> {
    let v = bs58::decode(s).into_vec().map_err(|_| OicError::invalid_request("address is not valid base58"))?;
    v.try_into().map_err(|_| OicError::invalid_request("base58 address must decode to 32 bytes"))
}

/// Interpret a byte slice as a 32-byte address.
pub fn to_pubkey(b: &[u8], what: &str) -> OicResult<Pubkey> {
    b.try_into().map_err(|_| OicError::scope(format!("{what} must be a 32-byte Solana address")))
}

/// True iff `bytes` is **not** a valid compressed Edwards point.
pub fn is_off_curve(bytes: &Pubkey) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_none()
}

/// `create_program_address`: hash the seeds and reject results on the curve.
pub fn create_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> OicResult<Pubkey> {
    if seeds.len() > MAX_SEEDS {
        return Err(OicError::invalid_request("too many PDA seeds"));
    }
    let mut h = Sha256::new();
    for s in seeds {
        if s.len() > MAX_SEED_LEN {
            return Err(OicError::invalid_request("PDA seed longer than 32 bytes"));
        }
        h.update(s);
    }
    h.update(program_id);
    h.update(PDA_MARKER);
    let out: Pubkey = h.finalize().into();
    if is_off_curve(&out) {
        Ok(out)
    } else {
        Err(OicError::invalid_request("PDA candidate lies on the Ed25519 curve"))
    }
}

/// `find_program_address`: bump search from 255 down to 0.
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> OicResult<(Pubkey, u8)> {
    if seeds.len() >= MAX_SEEDS {
        return Err(OicError::invalid_request("too many PDA seeds (one slot is reserved for the bump)"));
    }
    for bump in (0..=u8::MAX).rev() {
        let bump_seed = [bump];
        let mut with_bump: Vec<&[u8]> = seeds.to_vec();
        with_bump.push(&bump_seed);
        if let Ok(addr) = create_program_address(&with_bump, program_id) {
            return Ok((addr, bump));
        }
    }
    Err(OicError::unverifiable("no viable PDA bump seed"))
}

/// Associated token account of `(owner, mint)` under `token_program`.
pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> OicResult<Pubkey> {
    find_program_address(&[owner, token_program, mint], &ATA_PROGRAM_ID).map(|(a, _)| a)
}

/// Human-readable name of a well-known program id, for error messages.
pub fn program_name(id: &Pubkey) -> Option<&'static str> {
    Some(match *id {
        SYSTEM_PROGRAM_ID => "System Program",
        COMPUTE_BUDGET_PROGRAM_ID => "Compute Budget program",
        TOKEN_PROGRAM_ID => "SPL Token program",
        TOKEN_2022_PROGRAM_ID => "Token-2022 program",
        ATA_PROGRAM_ID => "Associated Token Account program",
        MEMO_V1_PROGRAM_ID | MEMO_V2_PROGRAM_ID => "Memo program",
        ADDRESS_LOOKUP_TABLE_PROGRAM_ID => "Address Lookup Table program",
        STAKE_PROGRAM_ID => "Stake program",
        VOTE_PROGRAM_ID => "Vote program",
        BPF_LOADER_UPGRADEABLE_PROGRAM_ID => "BPF Upgradeable Loader",
        _ => return None,
    })
}

/// `"<name> (<base58>)"` or `"unknown program <base58>"`.
pub fn describe_program(id: &Pubkey) -> String {
    match program_name(id) {
        Some(n) => format!("{n} ({})", to_base58(id)),
        None => format!("unknown program {}", to_base58(id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_ids_match_base58() {
        for (id, s) in [
            (SYSTEM_PROGRAM_ID, "11111111111111111111111111111111"),
            (COMPUTE_BUDGET_PROGRAM_ID, "ComputeBudget111111111111111111111111111111"),
            (TOKEN_PROGRAM_ID, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            (TOKEN_2022_PROGRAM_ID, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
            (ATA_PROGRAM_ID, "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
            (MEMO_V2_PROGRAM_ID, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"),
            (MEMO_V1_PROGRAM_ID, "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"),
            (ADDRESS_LOOKUP_TABLE_PROGRAM_ID, "AddressLookupTab1e1111111111111111111111111"),
            (STAKE_PROGRAM_ID, "Stake11111111111111111111111111111111111111"),
            (VOTE_PROGRAM_ID, "Vote111111111111111111111111111111111111111"),
            (BPF_LOADER_UPGRADEABLE_PROGRAM_ID, "BPFLoaderUpgradeab1e11111111111111111111111"),
        ] {
            assert_eq!(to_base58(&id), s);
            assert_eq!(from_base58(s).unwrap(), id);
        }
    }

    #[test]
    fn pda_is_off_curve_and_deterministic() {
        let owner = [7u8; 32];
        let mint = [9u8; 32];
        let a = associated_token_address(&owner, &mint, &TOKEN_PROGRAM_ID).unwrap();
        assert!(is_off_curve(&a));
        assert_eq!(a, associated_token_address(&owner, &mint, &TOKEN_PROGRAM_ID).unwrap());
        assert_ne!(a, associated_token_address(&owner, &mint, &TOKEN_2022_PROGRAM_ID).unwrap());
        // The Ed25519 base point is on the curve.
        let base = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        assert!(!is_off_curve(&base));
    }

    #[test]
    fn seed_bounds() {
        assert!(create_program_address(&[&[0u8; 33]], &ATA_PROGRAM_ID).is_err());
        let many: Vec<&[u8]> = vec![&[1u8]; 16];
        assert!(find_program_address(&many, &ATA_PROGRAM_ID).is_err());
    }
}
