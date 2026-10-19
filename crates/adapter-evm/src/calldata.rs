//! Pinned calldata schema: exactly one recognised call, ERC-20
//! `transfer(address,uint256)`. Everything else is denied with a specific reason.

use crate::address::Address;
use oic_domain_types::{OicError, OicResult};

pub const SELECTOR_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
pub const TRANSFER_CALLDATA_LEN: usize = 4 + 32 + 32;

/// Known selectors that are explicitly denied by RFC 0001 §9.3, with reasons.
const DENIED_SELECTORS: &[([u8; 4], &str)] = &[
    ([0x09, 0x5e, 0xa7, 0xb3], "ERC-20 approve(address,uint256) is denied"),
    ([0x23, 0xb8, 0x72, 0xdd], "ERC-20 transferFrom(address,address,uint256) is denied"),
    ([0xd5, 0x05, 0xac, 0xcf], "EIP-2612 permit(...) is denied"),
    ([0x8f, 0xcb, 0xaf, 0x0c], "DAI-style permit(...) is denied"),
    ([0x39, 0x50, 0x93, 0x51], "increaseAllowance(address,uint256) is denied"),
    ([0xa4, 0x57, 0xc2, 0xd7], "decreaseAllowance(address,uint256) is denied"),
    ([0xa2, 0x2c, 0xb4, 0x65], "setApprovalForAll(address,bool) operator approval is denied"),
    ([0x2b, 0x67, 0xb5, 0x70], "Permit2 permit(...) is denied"),
    ([0x2a, 0x2d, 0x80, 0xd1], "Permit2 permit batch (...) is denied"),
    ([0x87, 0x51, 0x7c, 0x45], "Permit2 approve(...) is denied"),
    ([0xac, 0x96, 0x50, 0xd8], "multicall(bytes[]) is denied"),
    ([0x5a, 0xe4, 0x01, 0xdc], "multicall(uint256,bytes[]) is denied"),
    ([0x82, 0xad, 0x56, 0xcb], "aggregate3 multicall is denied"),
    ([0x25, 0x2d, 0xba, 0x42], "aggregate multicall is denied"),
    ([0x6a, 0x76, 0x12, 0x02], "Safe execTransaction(...) is denied"),
    ([0xb6, 0x1d, 0x27, 0xf6], "execute(address,uint256,bytes) account execution is denied"),
    ([0x34, 0xfc, 0xd5, 0xbe], "executeBatch account execution is denied"),
    ([0x1f, 0xad, 0x94, 0x8c], "ERC-4337 handleOps is denied"),
];

/// Decoded ERC-20 transfer arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Erc20Transfer {
    pub recipient: Address,
    pub amount: u128,
}

pub fn selector(data: &[u8]) -> Option<[u8; 4]> {
    data.get(..4).map(|s| s.try_into().expect("4 bytes"))
}

/// Reject any calldata whose selector is not `transfer`.
pub fn require_transfer_selector(data: &[u8]) -> OicResult<()> {
    let sel = selector(data).ok_or_else(|| OicError::unsupported(format!("calldata of {} bytes has no 4-byte selector", data.len())))?;
    if sel == SELECTOR_TRANSFER {
        return Ok(());
    }
    if let Some((_, why)) = DENIED_SELECTORS.iter().find(|(s, _)| *s == sel) {
        return Err(OicError::unsupported(format!("{why} (selector 0x{})", hex::encode(sel))));
    }
    Err(OicError::unsupported(format!("unrecognised calldata selector 0x{}; only ERC-20 transfer is supported", hex::encode(sel))))
}

/// Decode `transfer(address,uint256)` calldata strictly.
pub fn decode_transfer(data: &[u8]) -> OicResult<Erc20Transfer> {
    require_transfer_selector(data)?;
    if data.len() != TRANSFER_CALLDATA_LEN {
        return Err(OicError::unverifiable(format!("ERC-20 transfer calldata must be exactly {TRANSFER_CALLDATA_LEN} bytes, got {}", data.len())));
    }
    let word1 = &data[4..36];
    let word2 = &data[36..68];
    if word1[..12].iter().any(|b| *b != 0) {
        return Err(OicError::unverifiable("ERC-20 transfer recipient word has non-zero high bytes"));
    }
    if word2[..16].iter().any(|b| *b != 0) {
        return Err(OicError::unverifiable("ERC-20 transfer amount exceeds u128"));
    }
    let recipient: Address = word1[12..].try_into().expect("20 bytes");
    let amount = u128::from_be_bytes(word2[16..].try_into().expect("16 bytes"));
    Ok(Erc20Transfer { recipient, amount })
}

pub fn encode_transfer(recipient: &Address, amount: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSFER_CALLDATA_LEN);
    out.extend_from_slice(&SELECTOR_TRANSFER);
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(recipient);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&amount.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::keccak256;

    #[test]
    fn selectors_match_signatures() {
        assert_eq!(keccak256(b"transfer(address,uint256)")[..4], SELECTOR_TRANSFER);
        let sigs = [
            "approve(address,uint256)",
            "transferFrom(address,address,uint256)",
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
            "increaseAllowance(address,uint256)",
            "decreaseAllowance(address,uint256)",
            "setApprovalForAll(address,bool)",
            "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
            "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)",
            "approve(address,address,uint160,uint48)",
            "multicall(bytes[])",
            "multicall(uint256,bytes[])",
            "aggregate3((address,bool,bytes)[])",
            "aggregate((address,bytes)[])",
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
            "execute(address,uint256,bytes)",
            "executeBatch((address,uint256,bytes)[])",
            "handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address)",
        ];
        assert_eq!(sigs.len(), DENIED_SELECTORS.len());
        for (i, s) in sigs.iter().enumerate() {
            assert_eq!(keccak256(s.as_bytes())[..4], DENIED_SELECTORS[i].0, "{s}");
        }
    }

    #[test]
    fn transfer_round_trip_and_strictness() {
        let r = [0x42u8; 20];
        let d = encode_transfer(&r, 12345);
        assert_eq!(decode_transfer(&d).unwrap(), Erc20Transfer { recipient: r, amount: 12345 });
        let mut long = d.clone();
        long.push(0);
        assert!(decode_transfer(&long).is_err());
        let mut dirty = d.clone();
        dirty[5] = 1;
        assert!(decode_transfer(&dirty).is_err());
        let mut huge = d.clone();
        huge[36] = 1;
        assert!(decode_transfer(&huge).is_err());
    }
}
