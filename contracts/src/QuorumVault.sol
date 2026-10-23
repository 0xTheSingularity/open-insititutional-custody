// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// DEVELOPMENT REFERENCE ONLY (RFC 0002 §9). A minimal 2-of-3 owner-quorum
/// vault: the chain enforces the quorum, so no machine that holds one owner
/// key can move funds alone. This is the EVM counterpart of the Solana FROST
/// loop while RFC 0002 §3 decision 1 (an audited threshold-ECDSA backend)
/// stays open. It must not hold real value before independent review; a
/// production deployment would more likely use Safe's audited contracts.
///
/// Signers are custody nodes, not wallets, so the authorization digest is a
/// plain keccak256 over (chainid, vault, nonce, to, value, keccak256(data))
/// with no EIP-191/712 envelope: nodes sign exactly the 32 bytes that
/// `digest()` derives on-chain, via the prehashed secp256k1 scheme the
/// signer pipeline already carries.
contract QuorumVault {
    address public immutable owner0;
    address public immutable owner1;
    address public immutable owner2;
    uint256 public nonce;

    event Deposited(address indexed from, uint256 value);
    event Executed(uint256 indexed nonce, address indexed to, uint256 value, bytes data);

    constructor(address a, address b, address c) {
        require(a != address(0) && b != address(0) && c != address(0), "zero owner");
        require(a != b && a != c && b != c, "duplicate owner");
        owner0 = a;
        owner1 = b;
        owner2 = c;
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    function isOwner(address who) public view returns (bool) {
        return who == owner0 || who == owner1 || who == owner2;
    }

    /// The digest two distinct owners must sign to authorize the next call.
    /// The live nonce makes every authorization single-use.
    function digest(address to, uint256 value, bytes calldata data) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), nonce, to, value, keccak256(data)));
    }

    /// Anyone may relay a quorum-authorized call and pay its gas; custody
    /// power lives only in the two distinct owner signatures.
    function execute(address to, uint256 value, bytes calldata data, bytes calldata sig0, bytes calldata sig1)
        external
    {
        bytes32 h = digest(to, value, data);
        address s0 = recover(h, sig0);
        address s1 = recover(h, sig1);
        require(isOwner(s0) && isOwner(s1), "not an owner");
        require(s0 != s1, "duplicate signer");
        // Effects before interaction: a reentrant call sees the spent nonce.
        nonce += 1;
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        emit Executed(nonce - 1, to, value, data);
    }

    function recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad signature length");
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        // EIP-2 low-s only, so a third party cannot malleate one owner's
        // signature into a "distinct" second one.
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "malleable s");
        require(v == 27 || v == 28, "bad v");
        address signer = ecrecover(h, v, r, s);
        require(signer != address(0), "bad signature");
        return signer;
    }
}
