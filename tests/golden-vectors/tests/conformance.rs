//! Conformance tests over the committed vector files (spec/protocol-v1.md §14).
//!
//! * (a) every domain vector's `input` re-encodes to `canonical_cbor_hex`
//!   and re-hashes to `hash_hex` through the real producer function, and
//!   `hash_hex` equals an independent `SHA-256(domain || canonical)`;
//! * (b) `canonical_cbor_hex` strictly decodes back to the input (or to the
//!   input's signed view);
//! * (c) native payloads are re-derived by the real adapters and
//!   cross-checked against the dev-only differential implementations
//!   (`alloy-consensus`, `solana-message`, `solana-transaction`);
//! * the files are exactly what the generator produces from the fixtures
//!   today, and every domain tag the workspace defines has vectors.

mod common;

use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{Address as AAddress, Bytes as ABytes, TxKind, U256};
use common::*;
use ed25519_dalek::{Signature, VerifyingKey};
use oic_adapter_api::ChainAdapter;
use oic_adapter_evm::tx::{Eip1559Tx, EvmTx};
use oic_adapter_solana::message::Message as SolMessage;
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes};
use oic_domain_types::*;
use oic_golden_vectors::*;
use solana_message::{v0, Address, Hash, MessageHeader as TheirHeader, VersionedMessage};
use solana_signer::Signer as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

fn read_domain_files() -> BTreeMap<String, Vec<DomainVector>> {
    let mut out = BTreeMap::new();
    for e in fs::read_dir(vectors_dir()).expect("vectors/ exists; run the generator") {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if !name.ends_with(".json") || name.starts_with("native-") {
            continue;
        }
        let vs: Vec<DomainVector> = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap_or_else(|e| panic!("{name}: {e}"));
        out.insert(name, vs);
    }
    out
}

fn read_native(file: &str) -> Vec<NativeVector> {
    serde_json::from_str(&fs::read_to_string(vectors_dir().join(file)).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}

#[test]
fn vector_files_are_exactly_what_the_generator_produces() {
    let dir = vectors_dir();
    let regen = "vector files are stale; run `OIC_REGENERATE_VECTORS=1 cargo test -p oic-golden-vectors --test generate`";
    let domain = common::build_domain_vectors();
    let native = common::build_native_vectors();
    let mut expected_files: BTreeSet<String> = domain.keys().cloned().collect();
    expected_files.extend(native.keys().cloned());
    let on_disk: BTreeSet<String> =
        fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).filter(|n| n.ends_with(".json")).collect();
    assert_eq!(on_disk, expected_files, "{regen}");
    for (file, vs) in &domain {
        assert_eq!(fs::read_to_string(dir.join(file)).unwrap(), to_file_json(vs).unwrap(), "{file}: {regen}");
    }
    for (file, vs) in &native {
        assert_eq!(fs::read_to_string(dir.join(file)).unwrap(), to_file_json(vs).unwrap(), "{file}: {regen}");
    }
}

#[test]
fn every_domain_tag_has_vectors_in_its_own_file() {
    use oic_domain_types::domains as d;
    let tags = [
        d::AUTHORIZATION,
        d::INTENT,
        d::CANDIDATE,
        d::DECODED_OPERATION,
        d::EVIDENCE,
        d::POLICY,
        d::APPROVAL,
        d::PREVIEW,
        d::AUTHORITY_RECEIPT,
        d::CHAIN_PROFILE,
        d::AUDIT,
        d::KEY_DESCRIPTOR,
        d::PUBLIC_KEY,
        d::CONFIG_PROPOSAL,
        d::DESTINATION,
        d::JOURNAL,
        d::OBSERVED_MOVEMENT,
        d::RECONCILIATION,
        d::WORKFLOW_TRIGGER,
        d::WEBHOOK,
        d::SIGNER_FENCE,
        local_domains::AUTHORITY_ID,
        local_domains::AUTHORITY_STATE,
        local_domains::AUTHORITY_CHECKPOINT,
        local_domains::AUDIT_EVENT_ID,
        local_domains::AUDIT_CHECKPOINT,
        local_domains::AUDIT_OBJECT,
        local_domains::AUTHORITY_EVENT,
    ];
    let files = read_domain_files();
    let names: BTreeSet<String> = tags.iter().map(|t| file_name_for_domain(t)).collect();
    assert_eq!(names.len(), tags.len(), "file names are distinct per tag");
    assert_eq!(files.keys().cloned().collect::<BTreeSet<_>>(), names);
    let mut seen = BTreeSet::new();
    for tag in tags {
        let vs = &files[&file_name_for_domain(tag)];
        assert!(!vs.is_empty(), "{tag} has no vectors");
        for v in vs {
            assert_eq!(v.domain, tag);
            assert!(seen.insert(v.name.clone()), "duplicate vector name {}", v.name);
        }
    }
}

/// (a) re-encode and re-hash every input through the real producers.
#[test]
fn domain_vectors_reencode_to_the_recorded_bytes_and_hashes() {
    let mut n = 0;
    for (file, vs) in read_domain_files() {
        for v in vs {
            let c = compute(&v.domain, &v.type_name, &v.input).unwrap_or_else(|e| panic!("{file}/{}: {e}", v.name));
            assert_eq!(hex::encode(&c.canonical), v.canonical_cbor_hex, "{}: canonical bytes", v.name);
            assert_eq!(c.hash.to_hex(), v.hash_hex, "{}: hash", v.name);
            assert_eq!(c.derived_id, v.derived_id, "{}: derived id", v.name);
            assert_eq!(c.producer, v.producer, "{}", v.name);
            assert_eq!(c.encoded_type, v.encoded_type, "{}", v.name);
            // Byte layout: SHA-256 over the ASCII tag immediately followed by the canonical bytes.
            assert_eq!(sha256_hex(&[v.domain.as_bytes(), &unhex(&v.canonical_cbor_hex)]), v.hash_hex, "{}: SHA256(domain || canonical)", v.name);
            // The recorded JSON is the serde JSON form of the typed value (it round-trips).
            if v.encoded_type == v.type_name {
                assert_eq!(c.encoded_json, v.input, "{}: JSON input is not in serde's canonical JSON form", v.name);
            }
            n += 1;
        }
    }
    assert!(n >= 50, "only {n} domain vectors");
}

/// (b) strictly decode the canonical bytes and compare to the input.
#[test]
fn domain_vectors_decode_back_to_the_input() {
    for (_, vs) in read_domain_files() {
        for v in vs {
            let bytes = unhex(&v.canonical_cbor_hex);
            assert!(oic_canonical_encoding::is_canonical(&bytes), "{}", v.name);
            let decoded = decode(&v.encoded_type, &bytes).unwrap_or_else(|e| panic!("{}: {e}", v.name));
            let c = compute(&v.domain, &v.type_name, &v.input).unwrap();
            assert_eq!(decoded, c.encoded_json, "{}: decoded value differs", v.name);
            if v.encoded_type == v.type_name {
                assert_eq!(decoded, v.input, "{}: decoded value differs from input", v.name);
            } else {
                // Signed views: the input minus exactly the omitted fields.
                let mut expected = v.input.clone();
                let obj = expected.as_object_mut().unwrap();
                let omitted = match v.encoded_type.as_str() {
                    "PolicyBundleUnsigned" | "DestinationUnsigned" => "administrative_signatures",
                    "AuditEventIdPreimage" => "event_id",
                    other => panic!("unexpected view {other}"),
                };
                assert!(obj.remove(omitted).is_some());
                assert_eq!(decoded, expected, "{}: view differs from input minus {omitted}", v.name);
            }
        }
    }
}

/// Ed25519 (`verify_strict`) signatures in the vectors sign the 32-byte hash.
#[test]
fn ed25519_signatures_cover_the_hash() {
    let mut n = 0;
    for (_, vs) in read_domain_files() {
        for v in vs {
            let Some(sig) = &v.ed25519 else { continue };
            let pk = VerifyingKey::from_bytes(&unhex(&sig.public_key_hex).try_into().unwrap()).unwrap();
            let s = Signature::from_slice(&unhex(&sig.signature_hex)).unwrap();
            pk.verify_strict(&unhex(&v.hash_hex), &s).unwrap_or_else(|_| panic!("{}: signature over hash", v.name));
            assert!(pk.verify_strict(&unhex(&v.canonical_cbor_hex), &s).is_err(), "{}: signature is not over the canonical bytes", v.name);
            n += 1;
        }
    }
    assert!(n >= 8, "only {n} signed vectors");
}

/// Policy and destination vectors carry real administrative signatures over
/// their unsigned-view hash; the real quorum verifiers accept them.
#[test]
fn admin_signed_inputs_verify_under_the_real_quorum_check() {
    let w = World::new();
    let admin_keys: Vec<(CredentialId, VerifyingKey)> = w.admins.iter().map(|(c, k)| (c.clone(), k.verifying_key())).collect();
    let files = read_domain_files();
    for v in &files["policy.json"] {
        let b: PolicyBundle = serde_json::from_value(v.input.clone()).unwrap();
        oic_policy_kernel::verify_policy_admin_signatures(&b, &admin_keys, 2).unwrap();
    }
    for v in &files["destination.json"] {
        let d: CounterpartyDestination = serde_json::from_value(v.input.clone()).unwrap();
        oic_policy_kernel::verify_destination_admin_signatures(&d, &admin_keys, 2).unwrap();
    }
}

/// Values that only the private functions of the signer, the authority, and
/// the audit sink compute are checked against what those components did in
/// the real end-to-end flow.
#[test]
fn private_derivations_match_the_real_components() {
    let f = evm_flow();
    let files = read_domain_files();
    let by_name = |file: &str, name: &str| files[file].iter().find(|v| v.name == name).unwrap_or_else(|| panic!("{name}")).clone();

    // Signer fence key: the first ledger call of `Signer::open` tombstones it.
    let fence = by_name("signer_fence.json", "signer-fence-key");
    let tombstoned: Vec<String> = f.ledger_calls.iter().filter_map(|c| if let LedgerCall::Tombstone { key_id, .. } = c { Some(key_id.as_str().to_string()) } else { None }).collect();
    assert_eq!(tombstoned.first(), fence.derived_id.as_ref());
    // Abort sentinel: the abort burns the session record against it.
    let sentinel = by_name("signer_fence.json", "signer-abort-sentinel");
    let burned = f.ledger_calls.iter().rev().find_map(|c| if let LedgerCall::Consume { message_hash, .. } = c { Some(message_hash.to_hex()) } else { None });
    assert_eq!(burned, Some(sentinel.hash_hex));

    // Issuance identifier assigned by the authority at release.
    let iss = by_name("authority_id.json", "authority-id-issuance");
    assert_eq!(iss.derived_id.as_deref(), Some(f.issuance.issuance_id.as_str()));

    // Authority-event commitments the audit sink recorded.
    let recorded: Vec<Hash32> = f.world.audit.events().iter().map(|e| e.body.object_commitments["authority_event"]).collect();
    for (i, v) in files["authority_event.json"].iter().enumerate() {
        assert_eq!(recorded[i].to_hex(), v.hash_hex, "{}", v.name);
    }
    // Audit object commitment recorded for the reservation.
    let obj = by_name("audit_object.json", "audit-object-reservation");
    assert_eq!(f.world.audit.events()[1].body.object_commitments["reservation"].to_hex(), obj.hash_hex);

    // The envelope body vector is exactly the body the signer verified.
    let env = by_name("authorization.json", "envelope-body-evm-erc20-exact-candidate");
    assert_eq!(env.input, serde_json::to_value(&f.envelope.body).unwrap());
    assert_eq!(f.envelope.authorization_state_receipt.body.envelope_body_hash.to_hex(), env.hash_hex);
    assert_eq!(f.release.body.envelope_body_hash.to_hex(), env.hash_hex);
}

// ---------------------------------------------------------------------------
// (c) native payloads
// ---------------------------------------------------------------------------

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

fn check_payload_common(v: &NativeVector, adapter: &dyn ChainAdapter, key: &KeyDescriptor) -> NativeSigningPayload {
    let m = adapter.manifest();
    assert_eq!(v.adapter_id, m.adapter_id.as_str());
    assert_eq!(v.adapter_version, m.adapter_version);
    assert_eq!(v.verifier_build_hash_hex, m.verifier_build_hash.to_hex());
    let bytes = unhex(&v.native_unsigned_bytes_hex);
    let derived = adapter.signing_payloads(&Bytes(bytes), key).unwrap();
    assert_eq!(derived.len(), 1);
    let recorded: NativeSigningPayload = serde_json::from_value(v.signing_payload.clone()).unwrap();
    assert_eq!(derived[0], recorded, "{}: adapter re-derives the recorded payload", v.name);
    let cbor = canonical_bytes(&recorded).unwrap();
    assert_eq!(hex::encode(&cbor), v.signing_payload_canonical_cbor_hex);
    assert_eq!(from_canonical_bytes::<NativeSigningPayload>(&cbor).unwrap(), recorded);
    recorded
}

#[test]
fn native_evm_vectors_match_adapter_and_alloy() {
    let f = evm_flow();
    let vs = read_native("native-evm.json");
    assert_eq!(vs.len(), 2);
    for v in &vs {
        let p = check_payload_common(v, &oic_adapter_evm::EvmAdapter, &f.m.key);
        let bytes = unhex(&v.native_unsigned_bytes_hex);
        // (a) the input fields re-encode to the recorded unsigned bytes.
        let tx = eip1559_from_json(&v.input);
        assert_eq!(tx.encode_unsigned(), bytes, "{}", v.name);
        // (b) the bytes strictly decode to the input fields.
        let EvmTx::Type2(decoded) = EvmTx::decode_unsigned(&bytes).unwrap() else { panic!("type 2") };
        assert_eq!(decoded, tx);
        assert_eq!(eip1559_json(&decoded), v.input);
        // Payload convention: secp256k1 over keccak256(0x02 || rlp(fields)).
        assert_eq!(p.scheme_id, SchemeId::EcdsaSecp256k1Keccak256Prehashed);
        assert_eq!(p.native_signing_context, oic_adapter_evm::SIGNING_CONTEXT_TYPE2);
        assert_eq!(p.payload_index, 0);
        assert_eq!(p.required_key_id, f.m.key.key_id);
        assert_eq!(p.message_or_digest.as_slice(), oic_adapter_evm::address::keccak256(&bytes));
        // (c) differential: alloy's signing encoding and signature hash.
        let a = alloy_1559(&tx);
        let mut alloy_bytes = Vec::new();
        a.encode_for_signing(&mut alloy_bytes);
        assert_eq!(alloy_bytes, bytes, "{}: alloy encode_for_signing", v.name);
        assert_eq!(a.signature_hash().0.as_slice(), p.message_or_digest.as_slice(), "{}: alloy signature_hash", v.name);
    }
    // The built vector is the candidate the real signer authorized.
    assert_eq!(unhex(&vs[0].native_unsigned_bytes_hex), f.envelope.body.native_unsigned_bytes.0);
    assert_eq!(serde_json::to_value(&f.envelope.body.native_signing_payloads[0]).unwrap(), vs[0].signing_payload);
}

fn their_message(m: &SolMessage) -> VersionedMessage {
    let header = TheirHeader {
        num_required_signatures: m.header.num_required_signatures,
        num_readonly_signed_accounts: m.header.num_readonly_signed_accounts,
        num_readonly_unsigned_accounts: m.header.num_readonly_unsigned_accounts,
    };
    let keys: Vec<Address> = m.account_keys.iter().map(|k| Address::new_from_array(*k)).collect();
    let ixs = m
        .instructions
        .iter()
        .map(|i| solana_message::compiled_instruction::CompiledInstruction { program_id_index: i.program_id_index, accounts: i.accounts.clone(), data: i.data.clone() })
        .collect();
    let blockhash = Hash::new_from_array(m.recent_blockhash);
    match m.version {
        oic_adapter_solana::message::MessageVersion::Legacy => {
            VersionedMessage::Legacy(solana_message::Message { header, account_keys: keys, recent_blockhash: blockhash, instructions: ixs })
        }
        oic_adapter_solana::message::MessageVersion::V0 => VersionedMessage::V0(v0::Message {
            header,
            account_keys: keys,
            recent_blockhash: blockhash,
            instructions: ixs,
            address_table_lookups: m
                .address_table_lookups
                .iter()
                .map(|l| v0::MessageAddressTableLookup {
                    account_key: Address::new_from_array(l.account_key),
                    writable_indexes: l.writable_indexes.clone(),
                    readonly_indexes: l.readonly_indexes.clone(),
                })
                .collect(),
        }),
    }
}

#[test]
fn native_solana_vectors_match_adapter_and_solana_sdk() {
    let key = sol_key();
    let vs = read_native("native-solana.json");
    assert_eq!(vs.len(), 2);
    let kp = solana_keypair::Keypair::new_from_array(sol_signing_key().to_bytes());
    for v in &vs {
        let p = check_payload_common(v, &oic_adapter_solana::SolanaAdapter, &key);
        let bytes = unhex(&v.native_unsigned_bytes_hex);
        // (a) the input message re-encodes to the recorded bytes.
        let msg = sol_message_from_json(&v.input);
        assert_eq!(msg.encode(), bytes, "{}", v.name);
        // (b) the bytes strictly decode to the input message.
        let decoded = SolMessage::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(sol_message_json(&decoded), v.input);
        // Payload convention: pure Ed25519 over the full serialized message.
        assert_eq!(p.scheme_id, SchemeId::Ed25519Pure);
        assert_eq!(p.message_or_digest.as_slice(), bytes.as_slice());
        assert_eq!(p.payload_index, 0);
        assert_eq!(p.required_key_id, key.key_id);
        let expected_ctx = if v.input["version"] == "v0" { oic_adapter_solana::SIGNING_CONTEXT_V0 } else { oic_adapter_solana::SIGNING_CONTEXT_LEGACY };
        assert_eq!(p.native_signing_context, expected_ctx);
        // (c) differential: the SDK builds the same message bytes from the
        // same fields, decodes ours, and verifies a signature over our payload.
        let theirs = their_message(&msg);
        assert_eq!(theirs.serialize(), bytes, "{}: solana-message serialize", v.name);
        assert_eq!(bincode::serialize(&theirs).unwrap(), bytes, "{}: solana-message bincode", v.name);
        let parsed: VersionedMessage = bincode::deserialize(&bytes).unwrap();
        assert_eq!(parsed, theirs);
        let sig = kp.sign_message(p.message_or_digest.as_slice());
        let vt = solana_transaction::versioned::VersionedTransaction { signatures: vec![sig], message: parsed };
        vt.verify_and_hash_message().unwrap_or_else(|e| panic!("{}: SDK rejects a signature over the payload: {e}", v.name));
    }
}
