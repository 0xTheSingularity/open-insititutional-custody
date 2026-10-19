//! Differential tests (RFC 0001 §16): our hand-written encoder/verifier versus
//! the independent `alloy-consensus` implementation, plus published vectors.

mod common;

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address as AAddress, Bytes as ABytes, TxKind, U256};
use common::*;
use oic_adapter_api::ChainAdapter;
use oic_adapter_evm::address::keccak256;
use oic_adapter_evm::tx::{Eip1559Tx, EvmTx, LegacyTx, RawSignature};
use oic_adapter_evm::*;
use proptest::prelude::*;

fn alloy_1559(t: &Eip1559Tx) -> TxEip1559 {
    TxEip1559 {
        chain_id: t.chain_id,
        nonce: t.nonce,
        gas_limit: t.gas_limit,
        max_fee_per_gas: t.max_fee_per_gas,
        max_priority_fee_per_gas: t.max_priority_fee_per_gas,
        to: TxKind::Call(AAddress::from(t.to)),
        value: U256::from(t.value),
        access_list: Default::default(),
        input: ABytes::from(t.data.clone()),
    }
}

fn alloy_legacy(t: &LegacyTx) -> TxLegacy {
    TxLegacy {
        chain_id: Some(t.chain_id),
        nonce: t.nonce,
        gas_price: t.gas_price,
        gas_limit: t.gas_limit,
        to: TxKind::Call(AAddress::from(t.to)),
        value: U256::from(t.value),
        input: ABytes::from(t.data.clone()),
    }
}

fn vitalik() -> [u8; 20] {
    hex::decode("d8da6bf26964af9d7eed9e03e53415d37aa96045").unwrap().try_into().unwrap()
}

/// Published unsigned EIP-1559 encodings (InternetOfPeers/ethereum-transaction-tools README).
#[test]
fn golden_published_eip1559_vectors() {
    let t = Eip1559Tx {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 2,
        gas_limit: 21000,
        to: vitalik(),
        value: 1,
        data: vec![],
        access_list: vec![],
    };
    assert_eq!(hex::encode(t.encode_unsigned()), "02df0180010282520894d8da6bf26964af9d7eed9e03e53415d37aa960450180c0");
    let t2 = Eip1559Tx {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 2_000_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 21000,
        to: vitalik(),
        value: 100_000_000_000_000_000,
        data: vec![],
        access_list: vec![],
    };
    assert_eq!(
        hex::encode(t2.encode_unsigned()),
        "02f0018084773594008506fc23ac0082520894d8da6bf26964af9d7eed9e03e53415d37aa9604588016345785d8a000080c0"
    );
    // Decoding the published bytes yields the same transaction.
    assert_eq!(Eip1559Tx::decode_unsigned(&t2.encode_unsigned()).unwrap(), t2);

    // Signing digest pinned as a regression vector, and checked against alloy.
    for t in [&t, &t2] {
        assert_eq!(t.signing_digest(), alloy_1559(t).signature_hash().0);
    }
    assert_eq!(hex::encode(t.signing_digest()), GOLDEN_DIGEST_1);
    assert_eq!(hex::encode(t2.signing_digest()), GOLDEN_DIGEST_2);
}

/// keccak256 of the published unsigned encodings above (computed by alloy-consensus 2.5.0
/// and by this crate; pinned to catch regressions in either the encoder or the hasher).
const GOLDEN_DIGEST_1: &str = "ad231b3bc30272b8e101ee61173f8f9e644cf3fc33926f05d2a75b5cab08e2c6";
const GOLDEN_DIGEST_2: &str = "230b6126512e103dee524e9591ef9905c9cc782d3bbc3b868048ac1bad5bde40";

/// EIP-155 example from the EIP text: nonce 9, 20 gwei, 21000 gas, 1 ether, chain 1.
#[test]
fn golden_eip155_vector() {
    let t = LegacyTx {
        chain_id: 1,
        nonce: 9,
        gas_price: 20_000_000_000,
        gas_limit: 21000,
        to: [0x35; 20],
        value: 1_000_000_000_000_000_000,
        data: vec![],
    };
    assert_eq!(
        hex::encode(t.encode_unsigned()),
        "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
    );
    assert_eq!(hex::encode(t.signing_digest()), "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53");
    assert_eq!(t.signing_digest(), alloy_legacy(&t).signature_hash().0);
    // Private key 0x4646..46 from the EIP produces the published signed transaction.
    let sk = k256::ecdsa::SigningKey::from_bytes(&[0x46u8; 32].into()).unwrap();
    let (sig, recid) = sk.sign_prehash_recoverable(&t.signing_digest()).unwrap();
    let raw = RawSignature { y_parity: recid.to_byte(), r: sig.r().to_bytes().into(), s: sig.s().to_bytes().into() };
    assert_eq!(
        hex::encode(t.encode_signed(&raw)),
        "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
    );
}

fn arb_1559() -> impl Strategy<Value = Eip1559Tx> {
    (
        any::<u64>(),
        any::<u64>(),
        any::<u128>(),
        any::<u128>(),
        any::<u64>(),
        any::<[u8; 20]>(),
        any::<u128>(),
        prop::collection::vec(any::<u8>(), 0..300),
    )
        .prop_map(|(chain_id, nonce, prio, max, gas_limit, to, value, data)| Eip1559Tx {
            chain_id,
            nonce,
            max_priority_fee_per_gas: prio,
            max_fee_per_gas: max,
            gas_limit,
            to,
            value,
            data,
            access_list: vec![],
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Ours vs alloy: unsigned encoding and signing digest.
    #[test]
    fn signing_hash_matches_alloy(t in arb_1559()) {
        let a = alloy_1559(&t);
        let mut alloy_bytes = Vec::new();
        a.encode_for_signing(&mut alloy_bytes);
        prop_assert_eq!(&t.encode_unsigned(), &alloy_bytes);
        prop_assert_eq!(t.signing_digest(), a.signature_hash().0);
        prop_assert_eq!(Eip1559Tx::decode_unsigned(&alloy_bytes).unwrap(), t);
    }

    #[test]
    fn legacy_signing_hash_matches_alloy(chain_id in 1u64..u64::MAX / 4, nonce in any::<u64>(), gp in any::<u128>(), gas in any::<u64>(), to in any::<[u8; 20]>(), value in any::<u128>(), data in prop::collection::vec(any::<u8>(), 0..100)) {
        let t = LegacyTx { chain_id, nonce, gas_price: gp, gas_limit: gas, to, value, data };
        prop_assert_eq!(t.signing_digest(), alloy_legacy(&t).signature_hash().0);
    }

    /// Sign with a random key; alloy decodes our signed bytes and recovers the same signer and hash.
    #[test]
    fn alloy_recovers_our_signer(t in arb_1559(), seed in any::<[u8; 32]>()) {
        let Ok(sk) = k256::ecdsa::SigningKey::from_bytes(&seed.into()) else { return Ok(()); };
        let digest = t.signing_digest();
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let raw = RawSignature { y_parity: recid.to_byte(), r: sig.r().to_bytes().into(), s: sig.s().to_bytes().into() };
        let signed = t.encode_signed(&raw);
        let ours = recover_address(&digest, &raw).unwrap();
        let expected = oic_adapter_evm::address::address_from_sec1(
            sk.verifying_key().to_encoded_point(false).as_bytes()).unwrap();
        prop_assert_eq!(ours, expected);

        let env = TxEnvelope::decode_2718(&mut signed.as_slice()).unwrap();
        prop_assert_eq!(env.recover_signer().unwrap().0 .0, ours);
        prop_assert_eq!(env.tx_hash().0, keccak256(&signed));
        // And our strict decoder round-trips alloy's re-encoding.
        let mut re = Vec::new();
        alloy_eips::eip2718::Encodable2718::encode_2718(&env, &mut re);
        prop_assert_eq!(&re, &signed);
        let (back, back_sig) = EvmTx::decode_signed(&re).unwrap();
        prop_assert_eq!(back, EvmTx::Type2(t));
        prop_assert_eq!(back_sig, raw);
    }
}

/// Full adapter path: build -> sign -> assemble; alloy recovers the wallet address.
#[test]
fn adapter_signed_bytes_accepted_by_alloy() {
    for fx in [native_fixture(), erc20_fixture()] {
        let c = fx.build();
        let signed = EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
        let env = TxEnvelope::decode_2718(&mut signed.signed_bytes.as_slice()).unwrap();
        assert_eq!(env.recover_signer().unwrap().0 .0, fx.sender);
        assert_eq!(format!("{:#x}", env.tx_hash()), signed.chain_tx_id.as_str());
    }
}
