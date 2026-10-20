use ed25519_dalek::Verifier;
use frost_ed25519 as frost;
use oic_canonical_encoding::sha256;
use oic_crypto_provider::*;
use oic_crypto_provider_frost_ed25519::*;
use oic_domain_types::*;
use oic_one_time_state_ledger::{InMemoryLedger, OP_CONSUME};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const KEY: &str = "frost-key-1";

fn pid(s: &str) -> ParticipantId {
    ParticipantId::unchecked(s)
}

fn key() -> KeyId {
    KeyId::unchecked(KEY)
}

fn sid(s: &str) -> SigningSessionId {
    SigningSessionId::unchecked(s)
}

fn make(names: &[&str], same_sealing: bool) -> Vec<FrostEd25519Provider> {
    names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let sealing = if same_sealing { [9u8; 32] } else { [i as u8 + 1; 32] };
            FrostEd25519Provider::new(pid(n), sealing, Box::new(StdRng::seed_from_u64(1000 + i as u64))).unwrap()
        })
        .collect()
}

fn ceremony(names: &[&str], t: u16, profile: &str) -> KeygenCeremony {
    KeygenCeremony {
        key_id: key(),
        key_epoch: Epoch(1),
        institution_id: InstitutionId::unchecked("inst"),
        environment_id: EnvironmentId::unchecked("dev"),
        participants: names.iter().map(|n| pid(n)).collect(),
        threshold: t,
        networks: vec![NetworkId::unchecked("solana-devnet")],
        recovery_profile: profile.into(),
    }
}

fn payload(msg: &[u8]) -> NativeSigningPayload {
    NativeSigningPayload {
        payload_index: 0,
        scheme_id: SchemeId::Ed25519Pure,
        message_or_digest: Bytes(msg.to_vec()),
        required_key_id: key(),
        native_signing_context: "solana-message-v0".into(),
    }
}

fn round2_msg(session: &SigningSessionId, to: &ParticipantId, pkg: &Bytes, seq: u64) -> PeerMessage {
    PeerMessage {
        session_id: session.clone(),
        key_id: key(),
        key_epoch: Epoch(1),
        from: pid("coordinator"),
        from_generation: Epoch(1),
        to: Some(to.clone()),
        round: 2,
        sequence: seq,
        protocol_version: PROTOCOL_VERSION.into(),
        payload: pkg.clone(),
    }
}

/// In-process coordinator + transport for one signing session.
struct Run<'a> {
    signers: Vec<&'a FrostEd25519Provider>,
    ledgers: BTreeMap<ParticipantId, InMemoryLedger>,
    session: SigningSessionId,
    round1: Vec<PeerMessage>,
}

impl<'a> Run<'a> {
    fn start(signers: Vec<&'a FrostEd25519Provider>, session: &str, msg: &[u8]) -> Run<'a> {
        let ledgers = signers.iter().map(|s| (s.participant().clone(), InMemoryLedger::new())).collect();
        Self::start_with(signers, ledgers, session, msg)
    }

    fn start_with(signers: Vec<&'a FrostEd25519Provider>, ledgers: BTreeMap<ParticipantId, InMemoryLedger>, session: &str, msg: &[u8]) -> Run<'a> {
        let set: Vec<ParticipantId> = signers.iter().map(|s| s.participant().clone()).collect();
        let session = sid(session);
        let mut round1 = Vec::new();
        for s in &signers {
            match s.start_signing_session(&session, &key(), &payload(msg), &set, &ledgers[s.participant()], Epoch(1)).unwrap() {
                ProtocolStep::Send(msgs) => {
                    assert_eq!(msgs.len(), 1);
                    assert_eq!(msgs[0].round, 1);
                    assert_eq!(msgs[0].to, None);
                    assert_eq!(msgs[0].protocol_version, "frost-ed25519/2");
                    round1.extend(msgs);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let run = Run { signers, ledgers, session, round1 };
        run.exchange_round1();
        run
    }

    fn exchange_round1(&self) {
        for m in &self.round1 {
            for s in &self.signers {
                if s.participant() != &m.from {
                    assert_eq!(s.advance_protocol(&self.session, m, self.ledger(s)).unwrap(), ProtocolStep::Waiting);
                }
            }
        }
    }

    fn ledger(&self, s: &FrostEd25519Provider) -> &InMemoryLedger {
        &self.ledgers[s.participant()]
    }

    fn commitments(&self) -> Vec<(ParticipantId, Bytes)> {
        self.round1.iter().map(|m| (m.from.clone(), m.payload.clone())).collect()
    }

    fn package(&self, msg: &[u8]) -> Bytes {
        build_signing_package(&self.commitments(), msg).unwrap()
    }

    fn shares(&self, pkg: &Bytes) -> Vec<(ParticipantId, Bytes)> {
        self.signers
            .iter()
            .map(|s| match s.advance_protocol(&self.session, &round2_msg(&self.session, s.participant(), pkg, 10), self.ledger(s)).unwrap() {
                ProtocolStep::Share(b) => (s.participant().clone(), b),
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    fn sign(&self, msg: &[u8]) -> OicResult<SignatureBytes> {
        let pkg = self.package(msg);
        let shares = self.shares(&pkg);
        self.signers[0].aggregate(&self.session, &shares)
    }
}

fn dalek_verify(pk: &PublicKey, msg: &[u8], sig: &SignatureBytes) {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk.bytes.as_slice().try_into().unwrap()).unwrap();
    let s = ed25519_dalek::Signature::from_slice(sig.bytes.as_slice()).unwrap();
    vk.verify(msg, &s).unwrap();
    vk.verify_strict(msg, &s).unwrap();
}

#[test]
fn descriptor() {
    let p = &make(&["a"], false)[0];
    let d = p.capabilities();
    assert_eq!(d.backend_id, "frost-ed25519");
    assert_eq!(d.scheme, SchemeId::Ed25519Pure);
    assert_eq!(d.message_convention, MessageConvention::PureMessage);
    assert_eq!(d.topology, ThresholdTopology::Threshold { max_participants: 16, min_threshold: 2 });
    assert!(d.native_verifier_compatible && d.has_one_time_state);
    assert!(!d.supports_refresh && !d.supports_recover_or_replace);
    assert_eq!(d.share_producing_round, 2);
    assert_eq!(p.refresh_shares(&ceremony(&["a", "b"], 2, "x")).unwrap_err().code, ErrorCode::UnsupportedCapability);
    assert_eq!(p.recover_or_replace(&ceremony(&["a", "b"], 2, "x")).unwrap_err().code, ErrorCode::UnsupportedCapability);
    assert!(FrostEd25519Provider::with_os_rng(pid("z"), [0; 32]).is_ok());
}

#[test]
fn pinned_versions_match_lockfile() {
    let lock = include_str!("../../../Cargo.lock");
    for pin in PINNED_VERSIONS.split(';') {
        let (name, ver) = pin.split_once('=').unwrap();
        assert!(lock.contains(&format!("name = \"{name}\"\nversion = \"{ver}\"")), "Cargo.lock does not resolve {name} to {ver}");
    }
}

#[test]
fn topology_rejects_1_of_1_and_oversize() {
    let ps = make(&["a"], false);
    let d = ps[0].capabilities();
    assert_eq!(check_topology(&d, 1, 1).unwrap_err().code, ErrorCode::UnsupportedCapability);
    assert!(check_topology(&d, 17, 2).is_err());
    assert!(check_topology(&d, 3, 2).is_ok());
    assert_eq!(ps[0].dkg_part1(&ceremony(&["a"], 1, "dkg")).unwrap_err().code, ErrorCode::UnsupportedCapability);
    assert!(ps[0].generate_distributed_key(&ceremony(&["a"], 1, DEALER_PROFILE)).is_err());
}

#[test]
fn dkg_2_of_3_every_subset_verifies_with_ed25519_dalek() {
    let names = ["alice", "bob", "carol"];
    let ps = make(&names, false);
    let refs: Vec<&FrostEd25519Provider> = ps.iter().collect();
    let res = run_dkg(&refs, &ceremony(&names, 2, "dkg")).unwrap();
    assert_eq!(res.descriptor.public_key.bytes.len(), 32);
    assert_eq!(res.descriptor.threshold, 2);
    assert_eq!(res.sealed_shares.len(), 3);
    for (i, j) in [(0, 1), (0, 2), (1, 2), (1, 0), (2, 0), (2, 1)] {
        let msg = format!("solana message signed by {i}{j}");
        let run = Run::start(vec![&ps[i], &ps[j]], &format!("s-{i}-{j}"), msg.as_bytes());
        let sig = run.sign(msg.as_bytes()).unwrap();
        assert_eq!(sig.bytes.len(), 64);
        dalek_verify(&res.descriptor.public_key, msg.as_bytes(), &sig);
        ps[2].verify_result(&res.descriptor.public_key, &payload(msg.as_bytes()), &sig).unwrap();
        assert!(ps[2].verify_result(&res.descriptor.public_key, &payload(b"other"), &sig).is_err());
        // Both signers' records consumed and bound to the message hash.
        for s in &run.signers {
            let rec = run.ledger(s).get(&s.session_record_id(&run.session).unwrap()).unwrap().unwrap();
            assert!(rec.consumed);
            assert_eq!(rec.bound_message_hash, Some(sha256(msg.as_bytes())));
        }
    }
    // run_dkg refuses a provider set that does not match the ceremony participants.
    assert!(run_dkg(&refs[..2], &ceremony(&names, 2, "dkg")).is_err());
}

#[test]
fn dkg_shares_are_sealed_per_instance_and_reload() {
    let names = ["alice", "bob", "carol"];
    let ps = make(&names, false);
    let refs: Vec<&FrostEd25519Provider> = ps.iter().collect();
    let res = run_dkg(&refs, &ceremony(&names, 2, "dkg")).unwrap();
    for (p, sealed) in &res.sealed_shares {
        assert!(sealed.as_slice().starts_with(b"OICSEAL1"));
        // bob's instance cannot open alice's share (different sealing key and participant).
        if p.as_str() == "alice" {
            assert!(ps[1].load_share(&res.descriptor, p, sealed).is_err());
        }
    }
    // Fresh instances (same participant + sealing key, i.e. restarted signers) reload and sign.
    let fresh = make(&names, false);
    for (i, (p, sealed)) in res.sealed_shares.iter().enumerate() {
        fresh[i].load_share(&res.descriptor, p, sealed).unwrap();
    }
    let run = Run::start(vec![&fresh[0], &fresh[2]], "reloaded", b"after restart");
    let sig = run.sign(b"after restart").unwrap();
    dalek_verify(&res.descriptor.public_key, b"after restart", &sig);

    // Descriptor tampering is caught on load.
    let mut d = res.descriptor.clone();
    d.threshold = 3;
    let again = make(&names, false);
    assert_eq!(again[0].load_share(&d, &pid("alice"), &res.sealed_shares[0].1).unwrap_err().code, ErrorCode::ScopeMismatch);
    let mut d2 = res.descriptor.clone();
    d2.public_key.bytes.0[0] ^= 1;
    assert!(again[0].load_share(&d2, &pid("alice"), &res.sealed_shares[0].1).is_err());
    let mut d3 = res.descriptor.clone();
    d3.backend_id = "dev-single-key".into();
    assert!(again[0].load_share(&d3, &pid("alice"), &res.sealed_shares[0].1).is_err());
}

#[test]
fn trusted_dealer_path_is_explicit_and_works() {
    let names = ["alice", "bob", "carol"];
    let ps = make(&names, true);
    let err = ps[0].generate_distributed_key(&ceremony(&names, 2, "production")).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedCapability);
    assert!(err.detail.contains("run_dkg"));

    let res = ps[0].generate_distributed_key(&ceremony(&names, 2, DEALER_PROFILE)).unwrap();
    assert_eq!(res.descriptor.recovery_profile, "dev-trusted-dealer");
    for (i, (p, sealed)) in res.sealed_shares.iter().enumerate() {
        assert_eq!(p, ps[i].participant());
        ps[i].load_share(&res.descriptor, p, sealed).unwrap();
    }
    // Loading another participant's share into an instance is refused.
    assert!(ps[0].load_share(&res.descriptor, &pid("bob"), &res.sealed_shares[1].1).is_err());
    let run = Run::start(vec![&ps[1], &ps[2]], "dealer", b"dealer message");
    let sig = run.sign(b"dealer message").unwrap();
    dalek_verify(&res.descriptor.public_key, b"dealer message", &sig);
}

#[test]
fn dkg_3_of_5() {
    let names = ["p1", "p2", "p3", "p4", "p5"];
    let ps = make(&names, false);
    let refs: Vec<&FrostEd25519Provider> = ps.iter().collect();
    let res = run_dkg(&refs, &ceremony(&names, 3, "dkg")).unwrap();
    let run = Run::start(vec![&ps[0], &ps[2], &ps[4]], "s1", b"three of five");
    dalek_verify(&res.descriptor.public_key, b"three of five", &run.sign(b"three of five").unwrap());
    let run = Run::start(vec![&ps[1], &ps[2], &ps[3], &ps[4]], "s2", b"four of five");
    dalek_verify(&res.descriptor.public_key, b"four of five", &run.sign(b"four of five").unwrap());
    // Below threshold: refused before any record is allocated.
    let ledger = InMemoryLedger::new();
    let err = ps[0].start_signing_session(&sid("s3"), &key(), &payload(b"x"), &[pid("p1"), pid("p2")], &ledger, Epoch(1)).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidRequest);
    assert_eq!(ledger.sequence(), 0);
}

fn dkg3() -> (Vec<FrostEd25519Provider>, DistributedKeyResult) {
    let names = ["alice", "bob", "carol"];
    let ps = make(&names, false);
    let res = {
        let refs: Vec<&FrostEd25519Provider> = ps.iter().collect();
        run_dkg(&refs, &ceremony(&names, 2, "dkg")).unwrap()
    };
    (ps, res)
}

#[test]
fn malicious_share_is_detected_and_no_signature() {
    let (ps, _res) = dkg3();
    // bob is malicious: he answers the real session with a share he produced
    // for a different message in another session.
    let other = Run::start(vec![&ps[0], &ps[1]], "other", b"something else");
    let other_shares = other.shares(&other.package(b"something else"));
    let bogus = other_shares[1].1.clone();

    let run = Run::start(vec![&ps[0], &ps[1]], "real", b"authorized");
    let pkg = run.package(b"authorized");
    let honest = run.shares(&pkg);
    let mut shares = honest.clone();
    shares[1].1 = bogus;
    let err = ps[0].aggregate(&run.session, &shares).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidSignature);
    assert!(err.detail.contains("bob"), "culprit named: {}", err.detail);

    // Garbage bytes are rejected too.
    shares[1].1 = Bytes(vec![0xff; 32]);
    assert_eq!(ps[0].aggregate(&run.session, &shares).unwrap_err().code, ErrorCode::InvalidSignature);
    // Missing share, duplicate share, outsider share.
    assert!(ps[0].aggregate(&run.session, &shares[..1]).is_err());
    assert!(ps[0].aggregate(&run.session, &[honest[0].clone(), honest[0].clone()]).is_err());
    assert!(ps[0].aggregate(&run.session, &[honest[0].clone(), (pid("carol"), honest[0].1.clone())]).is_err());
}

#[test]
fn honest_aggregate_after_rejections_and_aggregate_preconditions() {
    let (ps, res) = dkg3();
    let run = Run::start(vec![&ps[0], &ps[1]], "agg", b"m");
    // Before releasing a share the instance holds no package.
    assert_eq!(ps[0].aggregate(&run.session, &[]).unwrap_err().code, ErrorCode::InvalidRequest);
    let pkg = run.package(b"m");
    let shares = run.shares(&pkg);
    // carol never signed this session: unknown session for her.
    assert_eq!(ps[2].aggregate(&run.session, &shares).unwrap_err().code, ErrorCode::NotFound);
    let sig = ps[1].aggregate(&run.session, &shares).unwrap();
    dalek_verify(&res.descriptor.public_key, b"m", &sig);
    assert_eq!(ps[0].aggregate(&run.session, &shares).unwrap(), sig);
}

#[test]
fn coordinator_substitution_rejected_before_consumption() {
    let (ps, res) = dkg3();
    let run = Run::start(vec![&ps[0], &ps[1]], "sub", b"authorized message");
    let alice = &ps[0];
    let record = alice.session_record_id(&run.session).unwrap();
    let send = |pkg: &Bytes, seq: u64| alice.advance_protocol(&run.session, &round2_msg(&run.session, alice.participant(), pkg, seq), run.ledger(alice));

    // 1. Different message.
    let evil = build_signing_package(&run.commitments(), b"drain the vault").unwrap();
    assert_eq!(send(&evil, 2).unwrap_err().code, ErrorCode::ScopeMismatch);
    // 2. Own commitment replaced by a fresh one from elsewhere.
    let other = Run::start(vec![&ps[0], &ps[1]], "decoy", b"authorized message");
    let mut swapped = run.commitments();
    swapped[0].1 = other.commitments()[0].1.clone();
    assert_eq!(send(&build_signing_package(&swapped, b"authorized message").unwrap(), 3).unwrap_err().code, ErrorCode::ScopeMismatch);
    // 3. Peer commitment substituted (bob's).
    let mut swapped = run.commitments();
    swapped[1].1 = other.commitments()[1].1.clone();
    assert_eq!(send(&build_signing_package(&swapped, b"authorized message").unwrap(), 4).unwrap_err().code, ErrorCode::ScopeMismatch);
    // 4. Participant set changed (carol added).
    let carol_commit = match ps[2].start_signing_session(&sid("c"), &key(), &payload(b"x"), &[pid("alice"), pid("carol")], &InMemoryLedger::new(), Epoch(1)).unwrap() {
        ProtocolStep::Send(m) => m[0].payload.clone(),
        _ => unreachable!(),
    };
    let mut extended = run.commitments();
    extended.push((pid("carol"), carol_commit));
    assert_eq!(send(&build_signing_package(&extended, b"authorized message").unwrap(), 5).unwrap_err().code, ErrorCode::ScopeMismatch);
    // 5. Garbage package.
    assert!(send(&Bytes(vec![1, 2, 3]), 6).is_err());

    // Nothing consumed by any of the above.
    assert!(!run.ledger(alice).get(&record).unwrap().unwrap().consumed);
    assert_eq!(run.ledger(alice).sequence(), 1);

    // The honest package still works and the signature verifies.
    let pkg = run.package(b"authorized message");
    let a = match send(&pkg, 7).unwrap() {
        ProtocolStep::Share(b) => b,
        o => panic!("{o:?}"),
    };
    let b = match ps[1].advance_protocol(&run.session, &round2_msg(&run.session, ps[1].participant(), &pkg, 1), run.ledger(&ps[1])).unwrap() {
        ProtocolStep::Share(b) => b,
        o => panic!("{o:?}"),
    };
    let sig = alice.aggregate(&run.session, &[(pid("alice"), a), (pid("bob"), b)]).unwrap();
    dalek_verify(&res.descriptor.public_key, b"authorized message", &sig);
}

#[test]
fn replayed_round2_produces_no_second_share() {
    let (ps, _) = dkg3();
    let run = Run::start(vec![&ps[0], &ps[1]], "replay", b"once");
    let pkg = run.package(b"once");
    let _ = run.shares(&pkg);
    let alice = &ps[0];
    let again = alice.advance_protocol(&run.session, &round2_msg(&run.session, alice.participant(), &pkg, 99), run.ledger(alice)).unwrap();
    assert!(matches!(again, ProtocolStep::Aborted(_)));
    assert_eq!(run.ledger(alice).sequence(), 2, "one allocate + one consume");
    // Restarting the same session id is refused.
    let err = alice
        .start_signing_session(&run.session, &key(), &payload(b"once"), &[pid("alice"), pid("bob")], run.ledger(alice), Epoch(1))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ResourceConflict);
}

#[test]
fn consume_failure_produces_no_share_and_aborts() {
    let (ps, res) = dkg3();
    let fail = Arc::new(AtomicBool::new(true));
    let f2 = fail.clone();
    let mut ledgers = BTreeMap::new();
    ledgers.insert(
        pid("alice"),
        InMemoryLedger::new().with_fault_hook(Box::new(move |op, _| {
            if op == OP_CONSUME && f2.load(Ordering::SeqCst) {
                Err(OicError::internal("crash before consume write"))
            } else {
                Ok(())
            }
        })),
    );
    ledgers.insert(pid("bob"), InMemoryLedger::new());
    let run = Run::start_with(vec![&ps[0], &ps[1]], ledgers, "fault", b"m");
    let pkg = run.package(b"m");
    let alice = &ps[0];
    let err = alice.advance_protocol(&run.session, &round2_msg(&run.session, alice.participant(), &pkg, 5), run.ledger(alice)).unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal);
    let record = alice.session_record_id(&run.session).unwrap();
    assert!(!run.ledger(alice).get(&record).unwrap().unwrap().consumed);
    // Ledger healthy again: the aborted session still never signs (nonces wiped).
    fail.store(false, Ordering::SeqCst);
    let again = alice.advance_protocol(&run.session, &round2_msg(&run.session, alice.participant(), &pkg, 6), run.ledger(alice)).unwrap();
    assert!(matches!(again, ProtocolStep::Aborted(_)));
    // Retry = new session, new record, fresh nonces.
    let retry = Run::start(vec![&ps[0], &ps[1]], "fault-retry", b"m");
    assert_ne!(alice.session_record_id(&retry.session).unwrap(), record);
    dalek_verify(&res.descriptor.public_key, b"m", &retry.sign(b"m").unwrap());
}

#[test]
fn abort_session_wipes_nonces() {
    let (ps, _) = dkg3();
    let run = Run::start(vec![&ps[0], &ps[1]], "abort", b"m");
    ps[0].abort_session(&run.session, "timeout").unwrap();
    let pkg = run.package(b"m");
    let r = ps[0].advance_protocol(&run.session, &round2_msg(&run.session, &pid("alice"), &pkg, 5), run.ledger(&ps[0])).unwrap();
    assert!(matches!(r, ProtocolStep::Aborted(ref s) if s.contains("timeout")));
    assert_eq!(ps[0].abort_session(&sid("nope"), "x").unwrap_err().code, ErrorCode::NotFound);
}

#[test]
fn peer_message_validation_and_stale_generation() {
    let (ps, _) = dkg3();
    let (alice, bob) = (&ps[0], &ps[1]);
    alice.set_roster_generation(&pid("bob"), Epoch(5)).unwrap();
    assert_eq!(alice.roster_generation(&pid("bob")), Epoch(5));
    assert_eq!(alice.roster_generation(&pid("carol")), Epoch(0));
    assert_eq!(alice.set_roster_generation(&pid("bob"), Epoch(4)).unwrap_err().code, ErrorCode::ResourceConflict);

    let la = InMemoryLedger::new();
    let lb = InMemoryLedger::new();
    let set = [pid("alice"), pid("bob")];
    let s = sid("gen");
    alice.start_signing_session(&s, &key(), &payload(b"m"), &set, &la, Epoch(1)).unwrap();
    let mut bob_r1 = match bob.start_signing_session(&s, &key(), &payload(b"m"), &set, &lb, Epoch(4)).unwrap() {
        ProtocolStep::Send(m) => m[0].clone(),
        _ => unreachable!(),
    };
    assert_eq!(bob_r1.from_generation, Epoch(4));
    // Stale generation (4 < roster 5) rejected.
    assert_eq!(alice.advance_protocol(&s, &bob_r1, &la).unwrap_err().code, ErrorCode::ScopeMismatch);

    let check = |m: &PeerMessage| alice.advance_protocol(&s, m, &la);
    bob_r1.from_generation = Epoch(5);
    let mut m = bob_r1.clone();
    m.protocol_version = "frost-ed25519/1".into();
    assert!(check(&m).is_err());
    let mut m = bob_r1.clone();
    m.session_id = sid("other");
    assert_eq!(check(&m).unwrap_err().code, ErrorCode::ScopeMismatch);
    let mut m = bob_r1.clone();
    m.key_epoch = Epoch(9);
    assert!(check(&m).is_err());
    let mut m = bob_r1.clone();
    m.from = pid("carol");
    assert_eq!(check(&m).unwrap_err().code, ErrorCode::ScopeMismatch, "carol is not in the signing set");
    let mut m = bob_r1.clone();
    m.from = pid("alice");
    assert!(check(&m).is_err(), "spoofed self");
    let mut m = bob_r1.clone();
    m.to = Some(pid("carol"));
    assert!(check(&m).is_err());
    let mut m = bob_r1.clone();
    m.round = 3;
    assert!(check(&m).is_err());
    let mut m = bob_r1.clone();
    m.payload = Bytes(vec![0; 5]);
    assert!(check(&m).is_err());
    assert_eq!(alice.advance_protocol(&sid("unknown"), &bob_r1, &la).unwrap_err().code, ErrorCode::NotFound);

    // Current generation accepted once; duplicates and non-monotonic sequences rejected.
    assert_eq!(check(&bob_r1).unwrap(), ProtocolStep::Waiting);
    assert_eq!(check(&bob_r1).unwrap_err().code, ErrorCode::ResourceConflict);
    let mut dup = bob_r1.clone();
    dup.sequence = 2;
    assert_eq!(check(&dup).unwrap_err().code, ErrorCode::ResourceConflict, "duplicate commitment");

    // The roster snapshot is per session: raising it later does not affect this session,
    // but a new session enforces it.
    alice.set_roster_generation(&pid("bob"), Epoch(6)).unwrap();
    let s2 = sid("gen2");
    alice.start_signing_session(&s2, &key(), &payload(b"m"), &set, &la, Epoch(1)).unwrap();
    let mut m = bob_r1.clone();
    m.session_id = s2.clone();
    assert_eq!(alice.advance_protocol(&s2, &m, &la).unwrap_err().code, ErrorCode::ScopeMismatch);
}

#[test]
fn start_session_rejections() {
    let (ps, _) = dkg3();
    let l = InMemoryLedger::new();
    let set = [pid("alice"), pid("bob")];
    let mut pl = payload(b"m");
    pl.scheme_id = SchemeId::EcdsaSecp256k1Keccak256Prehashed;
    assert_eq!(ps[0].start_signing_session(&sid("a"), &key(), &pl, &set, &l, Epoch(1)).unwrap_err().code, ErrorCode::UnsupportedCapability);
    let mut pl = payload(b"m");
    pl.required_key_id = KeyId::unchecked("other");
    assert_eq!(ps[0].start_signing_session(&sid("a"), &key(), &pl, &set, &l, Epoch(1)).unwrap_err().code, ErrorCode::ScopeMismatch);
    assert_eq!(
        ps[0].start_signing_session(&sid("a"), &KeyId::unchecked("other"), &pl, &set, &l, Epoch(1)).unwrap_err().code,
        ErrorCode::NotFound
    );
    assert_eq!(
        ps[0].start_signing_session(&sid("a"), &key(), &payload(b"m"), &[pid("bob"), pid("carol")], &l, Epoch(1)).unwrap_err().code,
        ErrorCode::ScopeMismatch,
        "self not in set"
    );
    assert_eq!(
        ps[0].start_signing_session(&sid("a"), &key(), &payload(b"m"), &[pid("alice"), pid("mallory")], &l, Epoch(1)).unwrap_err().code,
        ErrorCode::ScopeMismatch
    );
    assert!(ps[0].start_signing_session(&sid("a"), &key(), &payload(b"m"), &[pid("alice"), pid("alice")], &l, Epoch(1)).is_err());
    assert_eq!(l.sequence(), 0);
}

#[test]
fn serialized_share_round_trips() {
    let (ps, _) = dkg3();
    let run = Run::start(vec![&ps[0], &ps[1]], "rt", b"m");
    let shares = run.shares(&run.package(b"m"));
    for (_, b) in &shares {
        assert_eq!(b.len(), 32);
        let parsed = frost::round2::SignatureShare::deserialize(b.as_slice()).unwrap();
        assert_eq!(parsed.serialize(), b.0);
    }
    // Round-1 commitments and the package also round-trip.
    let c = frost::round1::SigningCommitments::deserialize(run.round1[0].payload.as_slice()).unwrap();
    assert_eq!(c.serialize().unwrap(), run.round1[0].payload.0);
    let pkg = run.package(b"m");
    let parsed = frost::SigningPackage::deserialize(pkg.as_slice()).unwrap();
    assert_eq!(parsed.message().as_slice(), b"m");
    assert_eq!(parsed.serialize().unwrap(), pkg.0);
}

#[test]
fn build_signing_package_rejects_duplicates_and_garbage() {
    let (ps, _) = dkg3();
    let run = Run::start(vec![&ps[0], &ps[1]], "b", b"m");
    let mut c = run.commitments();
    c.push(c[0].clone());
    assert!(build_signing_package(&c, b"m").is_err());
    assert!(build_signing_package(&[(pid("alice"), Bytes(vec![1]))], b"m").is_err());
    assert_ne!(participant_identifier(&pid("alice")).unwrap(), participant_identifier(&pid("bob")).unwrap());
}

#[test]
fn dkg_per_participant_misuse() {
    let names = ["alice", "bob", "carol"];
    let ps = make(&names, false);
    let c = ceremony(&names, 2, "dkg");
    // Outsider cannot join.
    let outsider = &make(&["mallory"], false)[0];
    assert_eq!(outsider.dkg_part1(&c).unwrap_err().code, ErrorCode::ScopeMismatch);
    // Out-of-order calls.
    assert_eq!(ps[0].dkg_part2(&key(), &BTreeMap::new()).unwrap_err().code, ErrorCode::NotFound);
    assert_eq!(ps[0].dkg_part3(&key(), &BTreeMap::new(), &BTreeMap::new()).unwrap_err().code, ErrorCode::NotFound);
    let r1: BTreeMap<ParticipantId, Bytes> = ps.iter().map(|p| (p.participant().clone(), p.dkg_part1(&c).unwrap())).collect();
    assert_eq!(ps[0].dkg_part1(&c).unwrap_err().code, ErrorCode::ResourceConflict);
    assert!(ps[0].dkg_part3(&key(), &BTreeMap::new(), &BTreeMap::new()).is_err(), "round 3 before round 2");
    // Missing a peer's round-1 package fails and ends that participant's run.
    let only_bob: BTreeMap<_, _> = r1.iter().filter(|(k, _)| k.as_str() == "bob").map(|(k, v)| (k.clone(), v.clone())).collect();
    assert!(ps[0].dkg_part2(&key(), &only_bob).is_err());
    assert_eq!(ps[0].dkg_part2(&key(), &only_bob).unwrap_err().code, ErrorCode::NotFound);
    // run_dkg requires exactly one provider per participant.
    let fresh = make(&names, false);
    assert!(run_dkg(&[&fresh[0], &fresh[1]], &c).is_err());
}
