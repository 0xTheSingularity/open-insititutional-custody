//! End-to-end adapter behaviour and RFC 0001 §16 acceptance cases
//! (A02, A04, A19, A20, A37) for the EVM adapter.

mod common;

use common::*;
use oic_adapter_api::*;
use oic_adapter_evm::calldata::encode_transfer;
use oic_adapter_evm::evidence::*;
use oic_adapter_evm::rlp::{self, RlpItem};
use oic_adapter_evm::tx::{AccessListItem, Eip1559Tx, EvmTx, LegacyTx, RawSignature};
use oic_adapter_evm::*;
use oic_domain_types::*;
use proptest::prelude::*;

fn code(e: OicError) -> ErrorCode {
    e.code
}

fn type2(fx: &Fx) -> Eip1559Tx {
    match EvmTx::decode_unsigned(fx.build().native_unsigned_bytes.as_slice()).unwrap() {
        EvmTx::Type2(t) => t,
        EvmTx::Legacy(_) => unreachable!(),
    }
}

#[test]
fn native_build_verify_sign_round_trip() {
    let fx = native_fixture();
    let c = fx.build();
    assert_eq!(c.native_unsigned_bytes.as_slice()[0], 0x02);
    assert_eq!(c.signing_payloads.len(), 1);
    let p = &c.signing_payloads[0];
    assert_eq!(p.payload_index, 0);
    assert_eq!(p.scheme_id, SchemeId::EcdsaSecp256k1Keccak256Prehashed);
    assert_eq!(p.native_signing_context, "evm-type2-eip1559");
    assert_eq!(p.message_or_digest.len(), 32);
    assert_eq!(c.evidence_bundle_hash, evidence_hash(&fx.evidence).unwrap());

    let v = EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).unwrap();
    assert_eq!(v.decoded.recipient().as_slice(), dest_address());
    assert_eq!(v.decoded.sender().as_slice(), fx.sender);
    assert_eq!(v.decoded.amount(), Amount(1_000_000));
    assert_eq!(v.decoded.asset(), &AssetKind::Native);
    let max_fee = GAS_LIMIT as u128 * (2 * BASE_FEE + PRIORITY_FEE);
    assert_eq!(v.decoded.max_native_fee(), Amount(max_fee));
    assert_eq!(v.decoded_operation_hash, decoded_operation_hash(&v.decoded).unwrap());
    assert_eq!(v.verifier_build_hash, oic_canonical_encoding::sha256(VERIFIER_BUILD_ID.as_bytes()));
    assert_eq!(
        v.claims.resources,
        vec![NativeResource::EvmNonce { network_id: fx.profile.network_id.clone(), sender: Bytes(fx.sender.to_vec()), nonce: NONCE }]
    );
    assert_eq!(v.claims.asset_outflows, vec![AssetOutflow { asset_id: fx.asset.asset_id.clone(), amount_base_units: Amount(1_000_000) }]);
    assert_eq!(v.claims.native_fees, vec![NativeFee { network_id: fx.profile.network_id.clone(), amount_base_units: Amount(max_fee) }]);
    assert_eq!(EvmAdapter.resource_requirements(&v).unwrap(), v.claims);

    let DecodedOperation::DirectTransfer { native_detail, .. } = &v.decoded;
    let detail: EvmNativeDetail = oic_canonical_encoding::from_canonical_bytes(native_detail.as_slice()).unwrap();
    assert_eq!(detail.nonce, NONCE);
    assert_eq!(detail.chain_id, CHAIN_ID);
    assert_eq!(detail.selector, None);

    let decoded = EvmAdapter.decode_candidate(&c, &fx.vctx()).unwrap();
    assert_eq!(decoded, v.decoded);

    let sig = fx.sign(&c);
    let signed = EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[sig]).unwrap();
    let vs = EvmAdapter.verify_signed_transaction(&signed, &c, &fx.key).unwrap();
    assert_eq!(vs.verified_signers, vec![Bytes(fx.sender.to_vec())]);
    assert_eq!(signed.chain_tx_id.as_str(), format!("0x{}", hex::encode(address::keccak256(signed.signed_bytes.as_slice()))));
}

#[test]
fn erc20_build_verify_round_trip() {
    let fx = erc20_fixture();
    let c = fx.build();
    let t = type2(&fx);
    assert_eq!(t.to, token_contract());
    assert_eq!(t.value, 0);
    assert_eq!(t.data, encode_transfer(&dest_address(), 1_000_000));
    let v = EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).unwrap();
    assert_eq!(v.decoded.asset(), &AssetKind::Erc20 { contract: Bytes(token_contract().to_vec()) });
    assert_eq!(v.decoded.recipient().as_slice(), dest_address());
    let signed = EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
    EvmAdapter.verify_signed_transaction(&signed, &c, &fx.key).unwrap();
}

#[test]
fn uncompressed_key_supported() {
    let mut fx = native_fixture();
    fx.key.public_key.bytes = Bytes(fx.sk.verifying_key().to_encoded_point(false).as_bytes().to_vec());
    let c = fx.build();
    let signed = EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
    EvmAdapter.verify_signed_transaction(&signed, &c, &fx.key).unwrap();
    let (addr, disp) = EvmAdapter.derive_address(&fx.key.public_key).unwrap();
    assert_eq!(addr.as_slice(), fx.sender);
    assert_eq!(disp, fx.wallet.address_display);
}

// --- A02 -------------------------------------------------------------------

#[test]
fn a02_changed_bytes_after_approval_fail() {
    let fx = native_fixture();
    let c = fx.build();
    let signed = EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();

    // Every single-byte mutation of the approved candidate bytes is rejected.
    for i in 0..c.native_unsigned_bytes.len() {
        let mut mutated = c.clone();
        mutated.native_unsigned_bytes.0[i] ^= 0x01;
        assert!(EvmAdapter.verify_signed_transaction(&signed, &mutated, &fx.key).is_err(), "byte {i}");
        assert!(EvmAdapter.verify_candidate(&mutated, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).is_err(), "byte {i}");
    }
    // Coordinator-swapped signed bytes (different value) also fail.
    let mut t = type2(&fx);
    t.value += 1;
    let mut forged = signed.clone();
    let (_, sig) = EvmTx::decode_signed(signed.signed_bytes.as_slice()).unwrap();
    forged.signed_bytes = Bytes(t.encode_signed(&sig));
    assert!(EvmAdapter.verify_signed_transaction(&forged, &c, &fx.key).is_err());
    // Signature by another key fails.
    let other = signing_key(9);
    let sig2 = sign_digest(&other, c.signing_payloads[0].message_or_digest.as_slice());
    assert_eq!(code(EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[sig2]).unwrap_err()), ErrorCode::InvalidSignature);
}

#[test]
fn tampered_payload_array_rejected() {
    let fx = native_fixture();
    let mut c = fx.build();
    c.signing_payloads[0].message_or_digest = Bytes(vec![0u8; 32]);
    assert_eq!(
        code(EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).unwrap_err()),
        ErrorCode::UnverifiableTransaction
    );
}

// --- A04 -------------------------------------------------------------------

#[test]
fn a04_same_symbol_decimals_different_contract_rejected() {
    let real = erc20_fixture();
    // Attacker builds against a look-alike asset: same id/symbol/decimals, different contract.
    let mut fake = fixture_with(erc20_asset([0xbb; 20]), 1);
    fake.evidence.items.insert(code_key(&[0xbb; 20]), Bytes(vec![0xcd; 32]));
    let c = fake.build();
    let e = EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&real.intent), &real.vctx()).unwrap_err();
    assert!(matches!(e.code, ErrorCode::ScopeMismatch | ErrorCode::UnverifiableTransaction), "{e:?}");
    let e = EvmAdapter.decode_candidate(&c, &real.vctx()).unwrap_err();
    assert!(matches!(e.code, ErrorCode::ScopeMismatch | ErrorCode::UnverifiableTransaction), "{e:?}");
}

#[test]
fn native_candidate_against_erc20_registry_rejected() {
    let native = native_fixture();
    let erc = erc20_fixture();
    let c = native.build();
    let e = EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&erc.intent), &erc.vctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::ScopeMismatch);
}

// --- A19 -------------------------------------------------------------------

#[test]
fn a19_fee_bump_changing_recipient_rejected() {
    let fx = native_fixture();
    let mut t = type2(&fx);
    t.max_fee_per_gas += 5_000_000_000;
    t.max_priority_fee_per_gas += 1_000_000_000;
    t.to = [0x66; 20];
    let bump = fx.candidate_for(t.encode_unsigned(), 2);
    let e = EvmAdapter.verify_candidate(&bump, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::ScopeMismatch);

    // Fee bump that sneaks in calldata is rejected too.
    let mut t = type2(&fx);
    t.max_fee_per_gas += 5_000_000_000;
    t.data = vec![0xde, 0xad, 0xbe, 0xef];
    let bump = fx.candidate_for(t.encode_unsigned(), 3);
    let e = EvmAdapter.verify_candidate(&bump, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
}

fn template(fx: &Fx, fillable: Vec<FillableField>) -> BoundedTransferTemplate {
    BoundedTransferTemplate {
        chain_wallet_id: fx.wallet.chain_wallet_id.clone(),
        network_id: fx.profile.network_id.clone(),
        asset_id: fx.asset.asset_id.clone(),
        amount_base_units: Amount(1_000_000),
        destination_id: fx.destination.destination_id.clone(),
        destination_version: fx.destination.version,
        destination_address: fx.destination.address.clone(),
        max_native_fee_base_units: Amount(10u128.pow(16)),
        maximum_successful_payments: 1,
        fillable,
    }
}

#[test]
fn template_fillable_fields_enforced() {
    let fx = native_fixture();
    let c = fx.build();
    let fixed = template(&fx, vec![]);
    EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&fixed), &fx.vctx()).unwrap();

    let mut t = type2(&fx);
    t.max_fee_per_gas += 1;
    let bumped = fx.candidate_for(t.encode_unsigned(), 2);
    assert_eq!(
        code(EvmAdapter.verify_candidate(&bumped, &AuthorizationTarget::Template(&fixed), &fx.vctx()).unwrap_err()),
        ErrorCode::UnverifiableTransaction
    );
    let fee_ok = template(&fx, vec![FillableField::EvmFeeFields]);
    EvmAdapter.verify_candidate(&bumped, &AuthorizationTarget::Template(&fee_ok), &fx.vctx()).unwrap();

    let mut t = type2(&fx);
    t.nonce += 1;
    t.gas_limit += 1;
    let moved = fx.candidate_for(t.encode_unsigned(), 3);
    assert!(EvmAdapter.verify_candidate(&moved, &AuthorizationTarget::Template(&fee_ok), &fx.vctx()).is_err());
    let all = template(&fx, vec![FillableField::EvmNonce, FillableField::EvmGasLimit]);
    EvmAdapter.verify_candidate(&moved, &AuthorizationTarget::Template(&all), &fx.vctx()).unwrap();

    // Fee cap above the template max is a budget failure even when fees are fillable.
    let mut tight = template(&fx, vec![FillableField::EvmFeeFields]);
    tight.max_native_fee_base_units = Amount(1);
    assert_eq!(
        code(EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&tight), &fx.vctx()).unwrap_err()),
        ErrorCode::BudgetExceeded
    );
    // Template for a different destination address fails.
    let mut wrong = template(&fx, vec![]);
    wrong.destination_address = Bytes(vec![0x01; 20]);
    assert_eq!(
        code(EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Template(&wrong), &fx.vctx()).unwrap_err()),
        ErrorCode::ScopeMismatch
    );
}

// --- A20 -------------------------------------------------------------------

#[test]
fn a20_approve_permit_and_7702_denied() {
    let fx = erc20_fixture();
    let mut t = type2(&fx);
    t.data[..4].copy_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]); // approve(address,uint256)
    let c = fx.candidate_for(t.encode_unsigned(), 2);
    let e = EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
    assert!(e.detail.contains("approve"), "{}", e.detail);

    let mut t = type2(&fx);
    t.data = [vec![0xd5, 0x05, 0xac, 0xcf], vec![0u8; 7 * 32]].concat(); // EIP-2612 permit
    let c = fx.candidate_for(t.encode_unsigned(), 3);
    let e = EvmAdapter.decode_candidate(&c, &fx.vctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
    assert!(e.detail.contains("permit"));

    // Type 0x04 (EIP-7702) envelope disguised with a harmless-looking body.
    let mut b = type2(&fx).encode_unsigned();
    b[0] = 0x04;
    let c = fx.candidate_for(b.clone(), 4);
    let e = EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
    assert!(e.detail.contains("7702"));
    assert_eq!(code(EvmAdapter.signing_payloads(&Bytes(b), &fx.key).unwrap_err()), ErrorCode::UnsupportedCapability);

    for ty in [0x01u8, 0x03, 0x05, 0x7f] {
        let mut b = type2(&fx).encode_unsigned();
        b[0] = ty;
        assert_eq!(code(EvmAdapter.decode_candidate(&fx.candidate_for(b, 5), &fx.vctx()).unwrap_err()), ErrorCode::UnsupportedCapability);
    }
}

#[test]
fn access_list_and_contract_creation_denied() {
    let fx = native_fixture();
    let mut t = type2(&fx);
    t.access_list = vec![AccessListItem { address: [1; 20], storage_keys: vec![[2; 32]] }];
    let c = fx.candidate_for(t.encode_unsigned(), 2);
    assert_eq!(code(EvmAdapter.decode_candidate(&c, &fx.vctx()).unwrap_err()), ErrorCode::UnsupportedCapability);

    // Contract creation: empty `to`.
    let items = vec![
        RlpItem::uint(CHAIN_ID as u128),
        RlpItem::uint(0),
        RlpItem::uint(1),
        RlpItem::uint(2),
        RlpItem::uint(21000),
        RlpItem::bytes(vec![]),
        RlpItem::uint(0),
        RlpItem::bytes(vec![0x60, 0x00]),
        RlpItem::List(vec![]),
    ];
    let mut b = vec![0x02];
    rlp::encode_into(&mut b, &RlpItem::List(items));
    let c = fx.candidate_for(b, 3);
    let e = EvmAdapter.decode_candidate(&c, &fx.vctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);
    assert!(e.detail.contains("contract creation"));
}

#[test]
fn erc20_semantic_checks() {
    let fx = erc20_fixture();
    // Non-zero native value with a token transfer.
    let mut t = type2(&fx);
    t.value = 1;
    let c = fx.candidate_for(t.encode_unsigned(), 2);
    assert_eq!(code(EvmAdapter.decode_candidate(&c, &fx.vctx()).unwrap_err()), ErrorCode::UnverifiableTransaction);
    // Amount above u128.
    let mut t = type2(&fx);
    t.data[36] = 1;
    let c = fx.candidate_for(t.encode_unsigned(), 3);
    assert_eq!(code(EvmAdapter.decode_candidate(&c, &fx.vctx()).unwrap_err()), ErrorCode::UnverifiableTransaction);
    // Dirty recipient high bytes.
    let mut t = type2(&fx);
    t.data[4] = 1;
    let c = fx.candidate_for(t.encode_unsigned(), 4);
    assert_eq!(code(EvmAdapter.decode_candidate(&c, &fx.vctx()).unwrap_err()), ErrorCode::UnverifiableTransaction);
    // Trailing calldata.
    let mut t = type2(&fx);
    t.data.push(0);
    let c = fx.candidate_for(t.encode_unsigned(), 5);
    assert_eq!(code(EvmAdapter.decode_candidate(&c, &fx.vctx()).unwrap_err()), ErrorCode::UnverifiableTransaction);
    // Non-standard behavior profile.
    let mut ns = erc20_fixture();
    ns.asset.behavior = AssetBehaviorProfile::Nonstandard;
    assert_eq!(code(EvmAdapter.build_candidate(&ns.build_ctx()).unwrap_err()), ErrorCode::UnsupportedCapability);
    let c = fx.build();
    assert_eq!(code(EvmAdapter.decode_candidate(&c, &ns.vctx()).unwrap_err()), ErrorCode::UnsupportedCapability);
    // Missing code evidence.
    let mut nocode = erc20_fixture();
    nocode.evidence.items.remove(&code_key(&token_contract()));
    assert_eq!(
        code(EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&nocode.intent), &nocode.vctx()).unwrap_err()),
        ErrorCode::StaleEvidence
    );
    // Evidence showing empty code.
    let mut empty = erc20_fixture();
    empty.evidence.items.insert(code_key(&token_contract()), Bytes(EMPTY_CODE_HASH.to_vec()));
    assert!(EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&empty.intent), &empty.vctx()).is_err());
}

#[test]
fn scope_nonce_fee_and_chain_checks() {
    let fx = native_fixture();
    let c = fx.build();
    let intent = AuthorizationTarget::Intent(&fx.intent);

    // Missing nonce evidence -> StaleEvidence.
    let mut f2 = native_fixture();
    f2.evidence.items.remove(&nonce_key(&f2.sender));
    assert_eq!(code(EvmAdapter.verify_candidate(&c, &intent, &f2.vctx()).unwrap_err()), ErrorCode::StaleEvidence);
    assert_eq!(code(EvmAdapter.build_candidate(&f2.build_ctx()).unwrap_err()), ErrorCode::StaleEvidence);

    // Nonce already consumed.
    let mut f3 = native_fixture();
    f3.evidence.items.insert(nonce_key(&f3.sender), Bytes((NONCE + 1).to_be_bytes().to_vec()));
    assert_eq!(code(EvmAdapter.verify_candidate(&c, &intent, &f3.vctx()).unwrap_err()), ErrorCode::ResourceConflict);

    // Intent fee cap below the worst-case fee.
    let mut f4 = native_fixture();
    f4.intent.constraints.max_network_fee_base_units = Amount(1000);
    assert_eq!(code(EvmAdapter.build_candidate(&f4.build_ctx()).unwrap_err()), ErrorCode::BudgetExceeded);
    assert_eq!(
        code(EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&f4.intent), &fx.vctx()).unwrap_err()),
        ErrorCode::BudgetExceeded
    );

    // Gas-fee overflow is unverifiable, not a wrap-around.
    let mut t = type2(&fx);
    t.gas_limit = u64::MAX;
    t.max_fee_per_gas = u128::MAX;
    let c2 = fx.candidate_for(t.encode_unsigned(), 2);
    assert_eq!(code(EvmAdapter.decode_candidate(&c2, &fx.vctx()).unwrap_err()), ErrorCode::UnverifiableTransaction);

    // Wrong chain id.
    let mut t = type2(&fx);
    t.chain_id = 1;
    let c3 = fx.candidate_for(t.encode_unsigned(), 3);
    assert_eq!(code(EvmAdapter.verify_candidate(&c3, &intent, &fx.vctx()).unwrap_err()), ErrorCode::ScopeMismatch);

    // Wallet address not derived from key.
    let mut f5 = native_fixture();
    f5.wallet.address = Bytes(vec![0x12; 20]);
    assert_eq!(code(EvmAdapter.verify_candidate(&c, &intent, &f5.vctx()).unwrap_err()), ErrorCode::ScopeMismatch);

    // Destination version / amount mismatch.
    let mut f6 = native_fixture();
    f6.destination.version = 4;
    assert_eq!(code(EvmAdapter.verify_candidate(&c, &intent, &f6.vctx()).unwrap_err()), ErrorCode::ScopeMismatch);
    let mut f7 = native_fixture();
    let IntentOperation::AssetTransfer { amount_base_units, .. } = &mut f7.intent.operation;
    *amount_base_units = Amount(2);
    assert_eq!(
        code(EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&f7.intent), &fx.vctx()).unwrap_err()),
        ErrorCode::UnverifiableTransaction
    );

    // Evidence for another profile.
    let mut f8 = native_fixture();
    f8.evidence.chain_profile_id = ChainProfileId::unchecked("evm-mainnet-v1");
    assert_eq!(code(EvmAdapter.verify_candidate(&c, &intent, &f8.vctx()).unwrap_err()), ErrorCode::ScopeMismatch);

    // Unknown accepted version string fails closed.
    let mut f9 = native_fixture();
    f9.profile.accepted_versions.push("eip7702".into());
    assert_eq!(code(EvmAdapter.decode_candidate(&c, &f9.vctx()).unwrap_err()), ErrorCode::UnsupportedCapability);
}

#[test]
fn signature_canonicality() {
    let fx = native_fixture();
    let c = fx.build();
    let sig = fx.sign(&c);
    // High-s twin (n - s, flipped parity) is a valid ECDSA signature but must be rejected.
    let s = k256::Scalar::from_repr(*k256::FieldBytes::from_slice(&sig.bytes.as_slice()[32..64])).unwrap();
    let high = -s;
    let mut b = sig.bytes.0.clone();
    b[32..64].copy_from_slice(&high.to_bytes());
    b[64] ^= 1;
    let e = EvmAdapter
        .assemble_signed_transaction(&c, &fx.key, &[SignatureBytes { scheme: sig.scheme, bytes: Bytes(b) }])
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidSignature);
    // Wrong length / scheme / v / count.
    let mut short = sig.clone();
    short.bytes.0.pop();
    assert_eq!(code(EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[short]).unwrap_err()), ErrorCode::InvalidSignature);
    let mut v27 = sig.clone();
    v27.bytes.0[64] = 27;
    assert_eq!(code(EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[v27]).unwrap_err()), ErrorCode::InvalidSignature);
    let mut ed = sig.clone();
    ed.scheme = SchemeId::Ed25519Pure;
    assert_eq!(code(EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[ed]).unwrap_err()), ErrorCode::InvalidSignature);
    assert!(EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[sig.clone(), sig]).is_err());
}

use k256::elliptic_curve::PrimeField;

#[test]
fn legacy_gated_by_profile() {
    let mut fx = native_fixture();
    let t = type2(&fx);
    let legacy = LegacyTx {
        chain_id: CHAIN_ID,
        nonce: t.nonce,
        gas_price: t.max_fee_per_gas,
        gas_limit: t.gas_limit,
        to: t.to,
        value: t.value,
        data: vec![],
    };
    let c = fx.candidate_for(legacy.encode_unsigned(), 2);
    assert_eq!(c.signing_payloads[0].native_signing_context, "evm-legacy-eip155");
    let e = EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedCapability);

    fx.profile.accepted_versions = vec![VERSION_TYPE2.into(), VERSION_LEGACY.into()];
    fx.wallet.chain_profile_id = fx.profile.chain_profile_id.clone();
    EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx()).unwrap();
    let signed = EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
    assert!(signed.signed_bytes.as_slice()[0] >= 0xc0);
    EvmAdapter.verify_signed_transaction(&signed, &c, &fx.key).unwrap();

    // Legacy-only profile cannot build.
    fx.profile.accepted_versions = vec![VERSION_LEGACY.into()];
    assert_eq!(code(EvmAdapter.build_candidate(&fx.build_ctx()).unwrap_err()), ErrorCode::UnsupportedCapability);
}

// --- observe / invalidation ---------------------------------------------------

fn obs(included: bool, confirmations: u64, consumed_by: Option<[u8; 32]>) -> Bytes {
    Bytes(
        oic_canonical_encoding::canonical_bytes(&TxObservation {
            included,
            block_height: if included { 990 } else { 0 },
            block_hash: Bytes(if included { vec![9; 32] } else { vec![] }),
            success: included,
            gas_used: if included { 21000 } else { 0 },
            effective_gas_price: Amount(if included { 11_000_000_000 } else { 0 }),
            confirmations,
            nonce_consumed_by: consumed_by.map(|h| Bytes(h.to_vec())),
        })
        .unwrap(),
    )
}

#[test]
fn observe_maps_lifecycle() {
    let fx = native_fixture();
    let c = fx.build();
    let signed = EvmAdapter.assemble_signed_transaction(&c, &fx.key, &[fx.sign(&c)]).unwrap();
    let hash: [u8; 32] = address::keccak256(signed.signed_bytes.as_slice());
    let mut ev = fx.evidence.clone();
    assert_eq!(code(EvmAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev).unwrap_err()), ErrorCode::StaleEvidence);

    ev.items.insert(tx_key(&hash), obs(false, 0, None));
    assert!(matches!(EvmAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev).unwrap(), ChainObservation::Submitted { .. }));

    let mut head = ev.clone();
    head.state.commitment = "latest".into();
    head.items.insert(tx_key(&hash), obs(true, 1, None));
    match EvmAdapter.observe(&signed.chain_tx_id, &fx.profile, &head).unwrap() {
        ChainObservation::Included { execution_success, fee_paid, state, .. } => {
            assert!(execution_success);
            assert_eq!(fee_paid, Amount(21000 * 11_000_000_000));
            assert_eq!(state.height, 990);
        }
        o => panic!("{o:?}"),
    }
    // Inclusion inside the finalized view is final at one confirmation: the
    // view already trails the head by the finality depth.
    ev.items.insert(tx_key(&hash), obs(true, 0, None));
    assert!(matches!(EvmAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev).unwrap(), ChainObservation::Included { .. }), "inclusion without confirmations is never final");
    ev.items.insert(tx_key(&hash), obs(true, 1, None));
    assert!(matches!(EvmAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev).unwrap(), ChainObservation::Finalized { .. }));

    // Audit 0001-08: the same confirmations seen at the latest head are only
    // inclusion. Finality comes from evidence at the finalized view.
    let mut latest = ev.clone();
    latest.state.commitment = "latest".into();
    latest.items.insert(tx_key(&hash), obs(true, 50, None));
    assert!(matches!(EvmAdapter.observe(&signed.chain_tx_id, &fx.profile, &latest).unwrap(), ChainObservation::Included { .. }));

    ev.items.insert(tx_key(&hash), Bytes(vec![0xff, 0x00]));
    assert_eq!(code(EvmAdapter.observe(&signed.chain_tx_id, &fx.profile, &ev).unwrap_err()), ErrorCode::StaleEvidence);
}

#[test]
fn prove_invalidation_requires_finalized_foreign_consumer() {
    let fx = native_fixture();
    let c1 = fx.build();
    let mut t = type2(&fx);
    t.max_fee_per_gas += 1_000_000_000;
    let c2 = fx.candidate_for(t.encode_unsigned(), 2);
    let s1 = EvmAdapter.assemble_signed_transaction(&c1, &fx.key, &[fx.sign(&c1)]).unwrap();
    let s2 = EvmAdapter.assemble_signed_transaction(&c2, &fx.key, &[fx.sign(&c2)]).unwrap();
    let h1 = address::keccak256(s1.signed_bytes.as_slice());
    let h2 = address::keccak256(s2.signed_bytes.as_slice());
    let foreign = [0x77u8; 32];
    let fam = c1.operation_family_id.clone();
    let cands = [c1.clone(), c2.clone()];

    let mut ev = fx.evidence.clone();
    ev.items.insert(nonce_key(&fx.sender), Bytes((NONCE + 1).to_be_bytes().to_vec()));
    ev.items.insert(signed_tx_key("cand-1", 1), s1.signed_bytes.clone());
    ev.items.insert(signed_tx_key("cand-1", 2), s2.signed_bytes.clone());
    ev.items.insert(tx_key(&h1), obs(false, 0, Some(foreign)));
    ev.items.insert(tx_key(&h2), obs(false, 0, Some(foreign)));
    ev.items.insert(tx_key(&foreign), obs(true, 5, None));
    assert!(matches!(
        EvmAdapter.prove_invalidation(&fam, &cands, &fx.profile, &ev).unwrap(),
        InvalidationEvidence::Definitive { .. }
    ));

    // A family replacement consuming the nonce is not invalidation.
    let mut ev2 = ev.clone();
    ev2.items.insert(tx_key(&h1), obs(false, 0, Some(h2)));
    ev2.items.insert(tx_key(&h2), obs(true, 5, None));
    assert_eq!(EvmAdapter.prove_invalidation(&fam, &cands, &fx.profile, &ev2).unwrap(), InvalidationEvidence::Unknown);

    // Merely submitted foreign tx is not proof.
    let mut ev3 = ev.clone();
    ev3.items.insert(tx_key(&foreign), obs(false, 0, None));
    assert_eq!(EvmAdapter.prove_invalidation(&fam, &cands, &fx.profile, &ev3).unwrap(), InvalidationEvidence::Unknown);

    // Nonce not advanced.
    let mut ev4 = ev.clone();
    ev4.items.insert(nonce_key(&fx.sender), Bytes(NONCE.to_be_bytes().to_vec()));
    assert_eq!(EvmAdapter.prove_invalidation(&fam, &cands, &fx.profile, &ev4).unwrap(), InvalidationEvidence::Unknown);

    // Unaccounted possibly-issued candidate.
    let mut ev5 = ev.clone();
    ev5.items.remove(&signed_tx_key("cand-1", 2));
    assert_eq!(EvmAdapter.prove_invalidation(&fam, &cands, &fx.profile, &ev5).unwrap(), InvalidationEvidence::Unknown);

    // Evidence not at the profile's finality commitment.
    let mut ev6 = ev.clone();
    ev6.state.commitment = "latest".into();
    assert_eq!(EvmAdapter.prove_invalidation(&fam, &cands, &fx.profile, &ev6).unwrap(), InvalidationEvidence::Unknown);
}

#[test]
fn manifest_identify_validity() {
    let fx = native_fixture();
    let m = EvmAdapter.manifest();
    assert_eq!(m.adapter_id.as_str(), "evm");
    assert_eq!(m.adapter_version, ADAPTER_VERSION);
    assert_eq!(m.verifier_build_hash, verifier_build_hash());
    assert_eq!(m.signing_schemes, vec![SchemeId::EcdsaSecp256k1Keccak256Prehashed]);
    let ctx = EvmAdapter.identify_network(&fx.profile, &fx.evidence).unwrap();
    assert_eq!(ctx.chain_profile_hash, fx.profile.hash().unwrap());
    let mut ev = fx.evidence.clone();
    ev.items.insert(KEY_CHAIN_ID.into(), Bytes(1u64.to_be_bytes().to_vec()));
    assert_eq!(code(EvmAdapter.identify_network(&fx.profile, &ev).unwrap_err()), ErrorCode::ScopeMismatch);
    let v = EvmAdapter.validity_constraints(&fx.build(), &fx.evidence).unwrap();
    assert_eq!(v.expires_at_height, None);
    assert_eq!(v.replacement_rule, REPLACEMENT_RULE);
}

// --- A37 -------------------------------------------------------------------

#[test]
fn a37_oversized_and_deeply_nested_bounded() {
    let fx = native_fixture();
    // 1 MiB of garbage behind a type-2 prefix and as a legacy list.
    let mut garbage = vec![0x02u8];
    garbage.extend((0..1024 * 1024).map(|i| (i * 31 % 251) as u8));
    let c = fx.candidate_for(garbage.clone(), 2);
    assert_eq!(code(EvmAdapter.decode_candidate(&c, &fx.vctx()).unwrap_err()), ErrorCode::UnverifiableTransaction);
    garbage[0] = 0xf9;
    assert!(EvmTx::decode_unsigned(&garbage).is_err());
    assert!(EvmTx::decode_signed(&garbage).is_err());

    // Deeply nested RLP inside the access-list slot.
    let mut nested = RlpItem::List(vec![]);
    for _ in 0..64 {
        nested = RlpItem::List(vec![nested]);
    }
    let mut b = vec![0x02];
    let items = vec![
        RlpItem::uint(CHAIN_ID as u128),
        RlpItem::uint(0),
        RlpItem::uint(1),
        RlpItem::uint(2),
        RlpItem::uint(21000),
        RlpItem::bytes(vec![1; 20]),
        RlpItem::uint(0),
        RlpItem::bytes(vec![]),
        nested,
    ];
    rlp::encode_into(&mut b, &RlpItem::List(items));
    let e = EvmTx::decode_unsigned(&b).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnverifiableTransaction);
    // A long run of list prefixes.
    let deep: Vec<u8> = std::iter::once(0x02).chain(std::iter::repeat_n(0xc1, 50_000)).collect();
    assert!(EvmTx::decode_unsigned(&deep).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn a37_arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = rlp::decode(&bytes);
        let _ = EvmTx::decode_unsigned(&bytes);
        let _ = EvmTx::decode_signed(&bytes);
        let mut typed = vec![0x02];
        typed.extend_from_slice(&bytes);
        let _ = EvmTx::decode_unsigned(&typed);
        let _ = EvmTx::decode_signed(&typed);
    }

    #[test]
    fn a37_arbitrary_candidate_bytes_never_panic_in_adapter(bytes in prop::collection::vec(any::<u8>(), 0..512), prefix in prop::sample::select(vec![0x02u8, 0xc0, 0xf8, 0x04, 0x80])) {
        let fx = native_fixture();
        let mut b = vec![prefix];
        b.extend_from_slice(&bytes);
        let c = fx.candidate_for(b.clone(), 2);
        let _ = EvmAdapter.decode_candidate(&c, &fx.vctx());
        let _ = EvmAdapter.verify_candidate(&c, &AuthorizationTarget::Intent(&fx.intent), &fx.vctx());
        let _ = EvmAdapter.signing_payloads(&Bytes(b.clone()), &fx.key);
        let signed = SignedTransaction {
            candidate_id: c.candidate_id.clone(),
            candidate_revision: c.candidate_revision,
            signed_bytes: Bytes(b),
            chain_tx_id: ChainTxId::unchecked("0x00"),
        };
        let _ = EvmAdapter.verify_signed_transaction(&signed, &c, &fx.key);
    }

    #[test]
    fn mutated_valid_tx_never_panics(pos in 0usize..200, val in any::<u8>()) {
        let fx = erc20_fixture();
        let c = fx.build();
        let sig = fx.sign(&c);
        let raw = RawSignature { y_parity: sig.bytes.as_slice()[64], r: sig.bytes.as_slice()[..32].try_into().unwrap(), s: sig.bytes.as_slice()[32..64].try_into().unwrap() };
        let mut signed = EvmTx::decode_unsigned(c.native_unsigned_bytes.as_slice()).unwrap().encode_signed(&raw);
        let i = pos % signed.len();
        signed[i] = val;
        let _ = EvmTx::decode_signed(&signed);
        let mut unsigned = c.native_unsigned_bytes.0.clone();
        let j = pos % unsigned.len();
        unsigned[j] = val;
        let _ = EvmAdapter.decode_candidate(&fx.candidate_for(unsigned, 2), &fx.vctx());
    }
}
