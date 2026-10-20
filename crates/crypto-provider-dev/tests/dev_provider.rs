use ed25519_dalek::Verifier;
use oic_adapter_evm::address::address_from_sec1;
use oic_adapter_evm::recover_address;
use oic_adapter_evm::tx::RawSignature;
use oic_canonical_encoding::sha256;
use oic_crypto_provider::*;
use oic_crypto_provider_dev::*;
use oic_domain_types::*;
use oic_one_time_state_ledger::{InMemoryLedger, OP_CONSUME};
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const SEALING: [u8; 32] = [0x5a; 32];

fn provider(scheme: SchemeId, seed: u64) -> DevSingleKeyProvider {
    DevSingleKeyProvider::new(scheme, SEALING, Box::new(StdRng::seed_from_u64(seed))).unwrap()
}

fn me() -> ParticipantId {
    ParticipantId::unchecked("p1")
}

fn ceremony(participants: Vec<ParticipantId>, threshold: u16) -> KeygenCeremony {
    KeygenCeremony {
        key_id: KeyId::unchecked("key-1"),
        key_epoch: Epoch(1),
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        participants,
        threshold,
        networks: vec![NetworkId::unchecked("net")],
        recovery_profile: "dev".into(),
    }
}

fn payload(scheme: SchemeId, msg: &[u8]) -> NativeSigningPayload {
    NativeSigningPayload {
        payload_index: 0,
        scheme_id: scheme,
        message_or_digest: Bytes(msg.to_vec()),
        required_key_id: KeyId::unchecked("key-1"),
        native_signing_context: "test".into(),
    }
}

fn sid(n: u32) -> SigningSessionId {
    SigningSessionId::unchecked(format!("s-{n}"))
}

fn release(session: &SigningSessionId, msg: &[u8]) -> PeerMessage {
    PeerMessage {
        session_id: session.clone(),
        key_id: KeyId::unchecked("key-1"),
        key_epoch: Epoch(1),
        from: ParticipantId::unchecked("coordinator"),
        from_generation: Epoch(1),
        to: None,
        round: 1,
        sequence: 1,
        protocol_version: PROTOCOL_VERSION.into(),
        payload: Bytes(sha256(msg).0.to_vec()),
    }
}

fn setup(scheme: SchemeId, seed: u64) -> (DevSingleKeyProvider, DistributedKeyResult) {
    let p = provider(scheme, seed);
    let res = p.generate_distributed_key(&ceremony(vec![me()], 1)).unwrap();
    p.load_share(&res.descriptor, &me(), &res.sealed_shares[0].1).unwrap();
    (p, res)
}

fn sign(p: &DevSingleKeyProvider, ledger: &InMemoryLedger, n: u32, scheme: SchemeId, msg: &[u8]) -> OicResult<SignatureBytes> {
    let step = p.start_signing_session(&sid(n), &KeyId::unchecked("key-1"), &payload(scheme, msg), &[me()], ledger, Epoch(1))?;
    assert_eq!(step, ProtocolStep::Waiting);
    match p.advance_protocol(&sid(n), &release(&sid(n), msg), ledger)? {
        ProtocolStep::Complete(sig) => Ok(sig),
        other => panic!("unexpected step {other:?}"),
    }
}

#[test]
fn descriptor_declares_dev_only() {
    let p = provider(SchemeId::Ed25519Pure, 1);
    let d = p.capabilities();
    assert_eq!(d.backend_id, "dev-single-key");
    assert_eq!(d.topology, ThresholdTopology::SingleKeyDevelopmentOnly);
    assert!(d.has_one_time_state);
    assert_eq!(d.share_producing_round, 1);
    assert!(d.security_note.contains("NO threshold security"));
    assert_eq!(d.message_convention, MessageConvention::PureMessage);
    assert_eq!(provider(SchemeId::EcdsaSecp256k1Keccak256Prehashed, 1).capabilities().message_convention, MessageConvention::Prehashed32);
    assert_eq!(p.scheme(), SchemeId::Ed25519Pure);
    assert!(DevSingleKeyProvider::new(SchemeId::SchnorrBip340, SEALING, Box::new(StdRng::seed_from_u64(0))).is_err());
    assert!(DevSingleKeyProvider::with_os_rng(SchemeId::Ed25519Pure, SEALING).is_ok());
}

#[test]
fn pinned_versions_match_lockfile() {
    let lock = include_str!("../../../Cargo.lock");
    for pin in PINNED_VERSIONS.split(';') {
        let (name, ver) = pin.split_once('=').unwrap();
        let needle = format!("name = \"{name}\"\nversion = \"{ver}\"");
        assert!(lock.contains(&needle), "Cargo.lock does not resolve {name} to {ver}");
    }
}

#[test]
fn topology_rejects_threshold_configs() {
    let p = provider(SchemeId::Ed25519Pure, 1);
    let three = vec![me(), ParticipantId::unchecked("p2"), ParticipantId::unchecked("p3")];
    assert_eq!(check_topology(&p.capabilities(), 3, 2).unwrap_err().code, ErrorCode::UnsupportedCapability);
    assert_eq!(p.generate_distributed_key(&ceremony(three, 2)).unwrap_err().code, ErrorCode::UnsupportedCapability);
    assert!(check_topology(&p.capabilities(), 1, 1).is_ok());
}

#[test]
fn secp256k1_sign_verify_and_evm_recovery() {
    let (p, res) = setup(SchemeId::EcdsaSecp256k1Keccak256Prehashed, 7);
    assert_eq!(res.descriptor.public_key.bytes.len(), 33, "SEC1 compressed");
    assert_eq!(res.descriptor.threshold, 1);
    assert_eq!(res.descriptor.participants, vec![me()]);
    assert_eq!(res.descriptor.backend_commit, PINNED_VERSIONS);
    let ledger = InMemoryLedger::new();
    let digest = sha256(b"evm tx");
    let sig = sign(&p, &ledger, 1, SchemeId::EcdsaSecp256k1Keccak256Prehashed, &digest.0).unwrap();
    assert_eq!(sig.scheme, SchemeId::EcdsaSecp256k1Keccak256Prehashed);
    assert_eq!(sig.bytes.len(), 65);
    let b = sig.bytes.as_slice();
    let raw = RawSignature { y_parity: b[64], r: b[..32].try_into().unwrap(), s: b[32..64].try_into().unwrap() };
    let recovered = recover_address(&digest.0, &raw).unwrap();
    assert_eq!(recovered, address_from_sec1(res.descriptor.public_key.bytes.as_slice()).unwrap());
    let pl = payload(SchemeId::EcdsaSecp256k1Keccak256Prehashed, &digest.0);
    p.verify_result(&res.descriptor.public_key, &pl, &sig).unwrap();
    assert!(p.aggregate(&sid(1), &[(me(), sig.bytes.clone())]).is_ok());

    // Tampered signature / other digest / flipped recid fail.
    let mut bad = sig.clone();
    bad.bytes.0[10] ^= 1;
    assert!(p.verify_result(&res.descriptor.public_key, &pl, &bad).is_err());
    let mut flipped = sig.clone();
    flipped.bytes.0[64] ^= 1;
    assert_eq!(p.verify_result(&res.descriptor.public_key, &pl, &flipped).unwrap_err().code, ErrorCode::InvalidSignature);
    let other = payload(SchemeId::EcdsaSecp256k1Keccak256Prehashed, &sha256(b"other").0);
    assert!(p.verify_result(&res.descriptor.public_key, &other, &sig).is_err());
}

#[test]
fn secp256k1_rejects_non_digest_payload_and_high_s() {
    let (p, res) = setup(SchemeId::EcdsaSecp256k1Keccak256Prehashed, 8);
    let ledger = InMemoryLedger::new();
    let err = p
        .start_signing_session(&sid(1), &KeyId::unchecked("key-1"), &payload(SchemeId::EcdsaSecp256k1Keccak256Prehashed, b"short"), &[me()], &ledger, Epoch(1))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidRequest);
    assert_eq!(ledger.sequence(), 0, "no record allocated for a rejected payload");

    let digest = sha256(b"x");
    let sig = sign(&p, &ledger, 2, SchemeId::EcdsaSecp256k1Keccak256Prehashed, &digest.0).unwrap();
    // Build the high-s twin (n - s) with flipped parity: valid ECDSA, must be rejected.
    let s = k256::ecdsa::Signature::from_slice(&sig.bytes.0[..64]).unwrap();
    let (r, s_scalar) = s.split_scalars();
    let high = k256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s_scalar).to_bytes()).unwrap();
    let mut hb = high.to_bytes().to_vec();
    hb.push(sig.bytes.0[64] ^ 1);
    let high_sig = SignatureBytes { scheme: sig.scheme, bytes: Bytes(hb) };
    let pl = payload(SchemeId::EcdsaSecp256k1Keccak256Prehashed, &digest.0);
    assert_eq!(p.verify_result(&res.descriptor.public_key, &pl, &high_sig).unwrap_err().code, ErrorCode::InvalidSignature);
}

#[test]
fn ed25519_sign_verify_with_dalek() {
    let (p, res) = setup(SchemeId::Ed25519Pure, 9);
    assert_eq!(res.descriptor.public_key.bytes.len(), 32);
    let ledger = InMemoryLedger::new();
    let msg = b"a full solana message, not a digest".to_vec();
    let sig = sign(&p, &ledger, 1, SchemeId::Ed25519Pure, &msg).unwrap();
    assert_eq!(sig.bytes.len(), 64);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(res.descriptor.public_key.bytes.as_slice().try_into().unwrap()).unwrap();
    let dsig = ed25519_dalek::Signature::from_slice(sig.bytes.as_slice()).unwrap();
    vk.verify(&msg, &dsig).unwrap();
    vk.verify_strict(&msg, &dsig).unwrap();
    p.verify_result(&res.descriptor.public_key, &payload(SchemeId::Ed25519Pure, &msg), &sig).unwrap();
    assert!(p.verify_result(&res.descriptor.public_key, &payload(SchemeId::Ed25519Pure, b"other"), &sig).is_err());
    // Scheme mismatch in verify.
    let wrong = SignatureBytes { scheme: SchemeId::EcdsaSecp256k1Keccak256Prehashed, bytes: sig.bytes.clone() };
    assert!(p.verify_result(&res.descriptor.public_key, &payload(SchemeId::Ed25519Pure, &msg), &wrong).is_err());
}

#[test]
fn record_consumed_before_signature_and_bound_to_message() {
    let (p, _) = setup(SchemeId::Ed25519Pure, 10);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let o2 = observed.clone();
    let ledger = InMemoryLedger::new().with_fault_hook(Box::new(move |op, rec| {
        o2.lock().unwrap().push((op.to_string(), rec.clone()));
        Ok(())
    }));
    let msg = b"m";
    let sig = sign(&p, &ledger, 1, SchemeId::Ed25519Pure, msg).unwrap();
    assert!(!sig.bytes.is_empty());
    let rid = p.session_record_id(&sid(1)).unwrap();
    let rec = ledger.get(&rid).unwrap().unwrap();
    assert!(rec.consumed);
    assert_eq!(rec.bound_message_hash, Some(sha256(msg)));
    assert_eq!(rec.session_id, Some(sid(1)));
    let ops = observed.lock().unwrap();
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[1].0, OP_CONSUME);
}

#[test]
fn consume_failure_produces_no_signature() {
    let (p, _) = setup(SchemeId::EcdsaSecp256k1Keccak256Prehashed, 11);
    let fail = Arc::new(AtomicBool::new(true));
    let f2 = fail.clone();
    let ledger = InMemoryLedger::new().with_fault_hook(Box::new(move |op, _| {
        if op == OP_CONSUME && f2.load(Ordering::SeqCst) {
            Err(OicError::internal("crash before consume write"))
        } else {
            Ok(())
        }
    }));
    let digest = sha256(b"d").0;
    p.start_signing_session(&sid(1), &KeyId::unchecked("key-1"), &payload(SchemeId::EcdsaSecp256k1Keccak256Prehashed, &digest), &[me()], &ledger, Epoch(1))
        .unwrap();
    let err = p.advance_protocol(&sid(1), &release(&sid(1), &digest), &ledger).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    let rid = p.session_record_id(&sid(1)).unwrap();
    assert!(!ledger.get(&rid).unwrap().unwrap().consumed);
    // Even once the ledger recovers, the aborted session never signs.
    fail.store(false, Ordering::SeqCst);
    assert!(matches!(p.advance_protocol(&sid(1), &release(&sid(1), &digest), &ledger).unwrap(), ProtocolStep::Aborted(_)));
    assert!(!ledger.get(&rid).unwrap().unwrap().consumed);
    // A retry needs a new session (and gets a new record).
    let sig = sign(&p, &ledger, 2, SchemeId::EcdsaSecp256k1Keccak256Prehashed, &digest).unwrap();
    assert_ne!(p.session_record_id(&sid(2)).unwrap(), rid);
    assert_eq!(sig.bytes.len(), 65);
}

#[test]
fn replayed_advance_does_not_sign_twice() {
    let (p, _) = setup(SchemeId::Ed25519Pure, 12);
    let ledger = InMemoryLedger::new();
    sign(&p, &ledger, 1, SchemeId::Ed25519Pure, b"once").unwrap();
    let again = p.advance_protocol(&sid(1), &release(&sid(1), b"once"), &ledger).unwrap();
    assert!(matches!(again, ProtocolStep::Aborted(_)));
    // Restarting the same session id is refused.
    let err = p
        .start_signing_session(&sid(1), &KeyId::unchecked("key-1"), &payload(SchemeId::Ed25519Pure, b"once"), &[me()], &ledger, Epoch(1))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ResourceConflict);
    // Ledger shows a single consume.
    assert_eq!(ledger.sequence(), 2);
}

#[test]
fn wrong_key_scheme_session_and_binding_rejected() {
    let (p, _) = setup(SchemeId::Ed25519Pure, 13);
    let ledger = InMemoryLedger::new();
    let k = KeyId::unchecked("key-1");
    // payload bound to another key
    let mut pl = payload(SchemeId::Ed25519Pure, b"m");
    pl.required_key_id = KeyId::unchecked("other");
    assert_eq!(p.start_signing_session(&sid(1), &k, &pl, &[me()], &ledger, Epoch(1)).unwrap_err().code, ErrorCode::ScopeMismatch);
    // session for an unloaded key
    let mut pl2 = payload(SchemeId::Ed25519Pure, b"m");
    pl2.required_key_id = KeyId::unchecked("other");
    assert_eq!(
        p.start_signing_session(&sid(1), &KeyId::unchecked("other"), &pl2, &[me()], &ledger, Epoch(1)).unwrap_err().code,
        ErrorCode::NotFound
    );
    // wrong scheme
    let pl3 = payload(SchemeId::EcdsaSecp256k1Keccak256Prehashed, &[0u8; 32]);
    assert_eq!(p.start_signing_session(&sid(1), &k, &pl3, &[me()], &ledger, Epoch(1)).unwrap_err().code, ErrorCode::UnsupportedCapability);
    // wrong participant set
    let two = [me(), ParticipantId::unchecked("p2")];
    assert_eq!(
        p.start_signing_session(&sid(1), &k, &payload(SchemeId::Ed25519Pure, b"m"), &two, &ledger, Epoch(1)).unwrap_err().code,
        ErrorCode::ScopeMismatch
    );
    assert_eq!(ledger.sequence(), 0);

    p.start_signing_session(&sid(1), &k, &payload(SchemeId::Ed25519Pure, b"m"), &[me()], &ledger, Epoch(1)).unwrap();
    // unknown session
    assert_eq!(p.advance_protocol(&sid(9), &release(&sid(9), b"m"), &ledger).unwrap_err().code, ErrorCode::NotFound);
    // message for another session routed here
    assert_eq!(p.advance_protocol(&sid(1), &release(&sid(2), b"m"), &ledger).unwrap_err().code, ErrorCode::ScopeMismatch);
    // binding to another message
    assert_eq!(p.advance_protocol(&sid(1), &release(&sid(1), b"evil"), &ledger).unwrap_err().code, ErrorCode::ScopeMismatch);
    // wrong round / version / epoch / recipient
    let mut m = release(&sid(1), b"m");
    m.round = 2;
    assert!(p.advance_protocol(&sid(1), &m, &ledger).is_err());
    let mut m = release(&sid(1), b"m");
    m.protocol_version = "x".into();
    assert!(p.advance_protocol(&sid(1), &m, &ledger).is_err());
    let mut m = release(&sid(1), b"m");
    m.key_epoch = Epoch(2);
    assert!(p.advance_protocol(&sid(1), &m, &ledger).is_err());
    let mut m = release(&sid(1), b"m");
    m.to = Some(ParticipantId::unchecked("p2"));
    assert!(p.advance_protocol(&sid(1), &m, &ledger).is_err());
    // Rejections before consumption leave the record unconsumed and the session usable.
    let rid = p.session_record_id(&sid(1)).unwrap();
    assert!(!ledger.get(&rid).unwrap().unwrap().consumed);
    let mut m = release(&sid(1), b"m");
    m.to = Some(me());
    assert!(matches!(p.advance_protocol(&sid(1), &m, &ledger).unwrap(), ProtocolStep::Complete(_)));
}

#[test]
fn abort_session_prevents_signing() {
    let (p, _) = setup(SchemeId::Ed25519Pure, 14);
    let ledger = InMemoryLedger::new();
    p.start_signing_session(&sid(1), &KeyId::unchecked("key-1"), &payload(SchemeId::Ed25519Pure, b"m"), &[me()], &ledger, Epoch(1)).unwrap();
    p.abort_session(&sid(1), "coordinator timeout").unwrap();
    assert!(matches!(p.advance_protocol(&sid(1), &release(&sid(1), b"m"), &ledger).unwrap(), ProtocolStep::Aborted(r) if r.contains("timeout")));
    assert_eq!(p.abort_session(&sid(5), "x").unwrap_err().code, ErrorCode::NotFound);
    assert_eq!(p.session_record_id(&sid(5)).unwrap_err().code, ErrorCode::NotFound);
}

#[test]
fn aggregate_validates_single_share() {
    let (p, _) = setup(SchemeId::Ed25519Pure, 15);
    let ledger = InMemoryLedger::new();
    let sig = sign(&p, &ledger, 1, SchemeId::Ed25519Pure, b"m").unwrap();
    assert_eq!(p.aggregate(&sid(1), &[(me(), sig.bytes.clone())]).unwrap(), sig);
    assert!(p.aggregate(&sid(1), &[]).is_err());
    assert!(p.aggregate(&sid(1), &[(me(), sig.bytes.clone()), (me(), sig.bytes.clone())]).is_err());
    assert!(p.aggregate(&sid(1), &[(ParticipantId::unchecked("p2"), sig.bytes.clone())]).is_err());
    let mut bad = sig.bytes.clone();
    bad.0[0] ^= 1;
    assert!(p.aggregate(&sid(1), &[(me(), bad)]).is_err());
    assert_eq!(p.aggregate(&sid(9), &[(me(), sig.bytes)]).unwrap_err().code, ErrorCode::NotFound);
}

#[test]
fn sealed_share_is_not_plaintext_and_is_bound() {
    for scheme in [SchemeId::Ed25519Pure, SchemeId::EcdsaSecp256k1Keccak256Prehashed] {
        let p = provider(scheme, 42);
        let res = p.generate_distributed_key(&ceremony(vec![me()], 1)).unwrap();
        // Re-derive the same secret from the same seed to know the raw bytes.
        let mut rng = StdRng::seed_from_u64(42);
        let raw: [u8; 32] = match scheme {
            SchemeId::Ed25519Pure => ed25519_dalek::SigningKey::generate(&mut rng).to_bytes(),
            _ => k256::ecdsa::SigningKey::random(&mut rng).to_bytes().into(),
        };
        let sealed = res.sealed_shares[0].1.as_slice();
        assert!(!sealed.windows(32).any(|w| w == raw), "raw secret found in sealed share");
        assert!(sealed.starts_with(b"OICSEAL1"));

        // Wrong sealing key cannot load.
        let other = DevSingleKeyProvider::new(scheme, [0x11; 32], Box::new(StdRng::seed_from_u64(1))).unwrap();
        assert_eq!(other.load_share(&res.descriptor, &me(), &res.sealed_shares[0].1).unwrap_err().code, ErrorCode::InvalidSignature);
        // Epoch-shifted descriptor cannot load (AAD binding).
        let mut d2 = res.descriptor.clone();
        d2.key_epoch = Epoch(2);
        assert!(p.load_share(&d2, &me(), &res.sealed_shares[0].1).is_err());
        // Descriptor claiming a different public key cannot load.
        let mut d3 = res.descriptor.clone();
        let other_key = provider(scheme, 43).generate_distributed_key(&ceremony(vec![me()], 1)).unwrap();
        d3.public_key = other_key.descriptor.public_key;
        assert_eq!(p.load_share(&d3, &me(), &res.sealed_shares[0].1).unwrap_err().code, ErrorCode::ScopeMismatch);
        // Wrong participant / backend.
        assert!(p.load_share(&res.descriptor, &ParticipantId::unchecked("p2"), &res.sealed_shares[0].1).is_err());
        let mut d4 = res.descriptor.clone();
        d4.backend_id = "frost".into();
        assert!(p.load_share(&d4, &me(), &res.sealed_shares[0].1).is_err());
        p.load_share(&res.descriptor, &me(), &res.sealed_shares[0].1).unwrap();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn ecdsa_signatures_are_low_s_and_recoverable(digest in any::<[u8; 32]>()) {
        let (p, res) = setup(SchemeId::EcdsaSecp256k1Keccak256Prehashed, 99);
        let ledger = InMemoryLedger::new();
        let sig = sign(&p, &ledger, 1, SchemeId::EcdsaSecp256k1Keccak256Prehashed, &digest).unwrap();
        let s = k256::ecdsa::Signature::from_slice(&sig.bytes.0[..64]).unwrap();
        prop_assert!(s.normalize_s().is_none(), "high-s signature produced");
        prop_assert!(sig.bytes.0[64] <= 1);
        let b = sig.bytes.as_slice();
        let raw = RawSignature { y_parity: b[64], r: b[..32].try_into().unwrap(), s: b[32..64].try_into().unwrap() };
        prop_assert_eq!(recover_address(&digest, &raw).unwrap(), address_from_sec1(res.descriptor.public_key.bytes.as_slice()).unwrap());
    }
}
