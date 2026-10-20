//! Acceptance tests for the audit log (RFC 0001 §14).

use ed25519_dalek::{Signer, SigningKey};
use oic_audit::verify_checkpoint;
use oic_audit::*;
use oic_authorization_state::*;
use oic_domain_types::*;
use oic_policy_kernel::policy_hash;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::sync::Arc;

const T0: u64 = 1_700_000_000;

fn service_key() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

fn config_with(clock: Arc<ManualClock>) -> AuditLogConfig {
    AuditLogConfig::new(KeyId::unchecked("audit-key-1"), service_key(), clock)
}

fn config() -> (AuditLogConfig, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(T0));
    (config_with(clock.clone()), clock)
}

fn commits(name: &str, b: u8) -> BTreeMap<String, Hash32> {
    BTreeMap::from([(name.to_string(), Hash32([b; 32]))])
}

fn fill(log: &dyn AuditLog, n: u8) -> Vec<AuditEvent> {
    (1..=n).map(|i| log.append("operator:alice", "test.action", commits("intent", i), Epoch(1), &format!("step {i}")).unwrap()).collect()
}

#[test]
fn appends_chain_and_verify() {
    let (cfg, clock) = config();
    let log = MemoryAuditLog::new(cfg);
    assert_eq!(log.head().unwrap(), None);
    let e1 = log.append("operator:alice", "intent.created", commits("intent", 1), Epoch(3), "created").unwrap();
    clock.advance(5);
    let e2 = log.append("operator:bob", "grant.signed", commits("grant", 2), Epoch(3), "signed").unwrap();

    assert_eq!(e1.body.sequence, 1);
    assert_eq!(e1.body.previous_event_hash, Hash32::ZERO);
    assert_eq!(e1.body.at, UnixSeconds(T0));
    assert_eq!(e2.body.at, UnixSeconds(T0 + 5));
    assert_eq!(e2.body.sequence, 2);
    let h1 = event_hash(&e1.body).unwrap();
    assert_eq!(e2.body.previous_event_hash, h1);
    assert_eq!(e1.service_key_id, KeyId::unchecked("audit-key-1"));
    assert!(e1.body.event_id.as_str().starts_with("evt-"));
    assert_eq!(e1.body.event_id.as_str().len(), 4 + 32);
    assert_eq!(derive_event_id(&e1.body).unwrap(), e1.body.event_id);
    assert_ne!(e1.body.event_id, e2.body.event_id);

    let h2 = event_hash(&e2.body).unwrap();
    assert_eq!(log.head().unwrap(), Some((2, h2)));
    let pk = log.verifying_key();
    assert_eq!(verify_chain(&log.events(), &pk, None).unwrap(), (2, h2));
    // Incremental verification from a known head.
    assert_eq!(verify_chain(std::slice::from_ref(&e2), &pk, Some((1, h1))).unwrap(), (2, h2));
    assert_eq!(verify_chain(&[], &pk, Some((1, h1))).unwrap(), (1, h1));
    assert_eq!(verify_chain(&[], &pk, None).unwrap(), (0, Hash32::ZERO));

    assert_eq!(log.events_since(0, 10).unwrap(), vec![e1.clone(), e2.clone()]);
    assert_eq!(log.events_since(1, 10).unwrap(), vec![e2.clone()]);
    assert_eq!(log.events_since(0, 1).unwrap(), vec![e1]);
    assert!(log.events_since(2, 10).unwrap().is_empty());
    assert!(log.events_since(u64::MAX, 10).unwrap().is_empty());
}

#[test]
fn chain_verification_detects_tampering() {
    let (cfg, _) = config();
    let log = MemoryAuditLog::new(cfg);
    let events = fill(&log, 4);
    let pk = log.verifying_key();
    verify_chain(&events, &pk, None).unwrap();

    // Body edit (detail) without re-deriving anything.
    let mut t = events.clone();
    t[1].body.detail = "step 2 (edited)".into();
    assert_eq!(verify_chain(&t, &pk, None).unwrap_err().code, ErrorCode::UnverifiableTransaction);

    // Body edit with a consistently re-derived event id: the signature no longer covers it.
    let mut t = events.clone();
    t[3].body.policy_epoch = Epoch(99);
    t[3].body.event_id = derive_event_id(&t[3].body).unwrap();
    assert_eq!(verify_chain(&t, &pk, None).unwrap_err().code, ErrorCode::InvalidSignature);

    // Signature swap between two events.
    let mut t = events.clone();
    let s = t[0].signature.clone();
    t[0].signature = t[1].signature.clone();
    t[1].signature = s;
    assert_eq!(verify_chain(&t, &pk, None).unwrap_err().code, ErrorCode::InvalidSignature);

    // Reorder.
    let mut t = events.clone();
    t.swap(1, 2);
    assert_eq!(verify_chain(&t, &pk, None).unwrap_err().code, ErrorCode::UnverifiableTransaction);

    // Gap.
    let mut t = events.clone();
    t.remove(2);
    assert_eq!(verify_chain(&t, &pk, None).unwrap_err().code, ErrorCode::UnverifiableTransaction);

    // Wrong starting point and wrong key.
    assert_eq!(verify_chain(&events[1..], &pk, None).unwrap_err().code, ErrorCode::UnverifiableTransaction);
    assert_eq!(verify_chain(&events[1..], &pk, Some((1, Hash32([1; 32])))).unwrap_err().code, ErrorCode::UnverifiableTransaction);
    let other = SigningKey::from_bytes(&[10; 32]).verifying_key();
    assert_eq!(verify_chain(&events, &other, None).unwrap_err().code, ErrorCode::InvalidSignature);
}

#[test]
fn append_validation_and_redaction_guard() {
    let (cfg, _) = config();
    let log = MemoryAuditLog::new(cfg);
    let bad = |actor: &str, action: &str, c: BTreeMap<String, Hash32>, detail: &str| {
        log.append(actor, action, c, Epoch(1), detail).unwrap_err().code
    };
    assert_eq!(bad("a", "b", commits("", 1), "ok"), ErrorCode::InvalidRequest);
    assert_eq!(bad("", "b", commits("x", 1), "ok"), ErrorCode::InvalidRequest);
    assert_eq!(bad("a", "", commits("x", 1), "ok"), ErrorCode::InvalidRequest);
    assert_eq!(bad("a", "b", commits("x", 1), &"d".repeat(MAX_DETAIL_BYTES + 1)), ErrorCode::InvalidRequest);
    for secret in [
        "-----BEGIN PRIVATE KEY-----\nMC4CAQ",
        "-----begin private key-----",
        "wallet seed: abandon abandon",
        "SEED:deadbeef",
        "participant Share: 0x01",
        "share:1/3",
    ] {
        assert_eq!(bad("a", "b", commits("x", 1), secret), ErrorCode::InvalidRequest, "{secret}");
    }
    // Nothing was appended by any refused call.
    assert_eq!(log.head().unwrap(), None);

    // Boundary: exactly MAX_DETAIL_BYTES, words that merely resemble markers, and no commitments are fine.
    log.append("a", "b", commits("x", 1), Epoch(1), &"d".repeat(MAX_DETAIL_BYTES)).unwrap();
    log.append("a", "b", BTreeMap::new(), Epoch(1), "seedling shares rotated; private key material never logged").unwrap();
    assert_eq!(log.head().unwrap().unwrap().0, 2);
    verify_chain(&log.events(), &log.verifying_key(), None).unwrap();
}

#[test]
fn file_log_persists_and_replays() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let (cfg, _) = config();
    let events = {
        let log = FileAuditLog::open(&path, None, cfg.clone()).unwrap();
        fill(&log, 3)
    };
    let log = FileAuditLog::open(&path, Some(3), cfg).unwrap();
    assert_eq!(log.truncated_tail_bytes(), 0);
    assert_eq!(log.events_since(0, 100).unwrap(), events);
    assert_eq!(log.events_since(2, 100).unwrap(), events[2..].to_vec());
    let head = verify_chain(&events, &log.verifying_key(), None).unwrap();
    assert_eq!(log.head().unwrap(), Some(head));
    let e4 = log.append("operator:alice", "test.action", commits("intent", 4), Epoch(1), "step 4").unwrap();
    assert_eq!(e4.body.sequence, 4);
    assert_eq!(e4.body.previous_event_hash, head.1);
    assert_eq!(fs::read_to_string(dir.path().join("audit.log.hwm")).unwrap(), "4");
}

#[test]
fn file_log_truncates_half_written_tail_frame() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let (cfg, _) = config();
    let events = {
        let log = FileAuditLog::open(&path, None, cfg.clone()).unwrap();
        fill(&log, 3)
    };
    let good_len = fs::metadata(&path).unwrap().len();

    // Crash mid-payload: complete length prefix, partial body.
    {
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&200u32.to_be_bytes()).unwrap();
        f.write_all(&[0xa9; 10]).unwrap();
    }
    let log = FileAuditLog::open(&path, None, cfg.clone()).unwrap();
    assert_eq!(log.truncated_tail_bytes(), 14);
    assert_eq!(fs::metadata(&path).unwrap().len(), good_len);
    assert_eq!(log.events_since(0, 100).unwrap(), events);
    let e4 = log.append("operator:alice", "test.action", commits("intent", 4), Epoch(1), "after crash").unwrap();
    assert_eq!(e4.body.sequence, 4);
    drop(log);

    // Crash mid-length-prefix.
    {
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0x00, 0x00]).unwrap();
    }
    let log = FileAuditLog::open(&path, Some(4), cfg).unwrap();
    assert_eq!(log.truncated_tail_bytes(), 2);
    let all = log.events_since(0, 100).unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(all[3], e4);
    verify_chain(&all, &log.verifying_key(), None).unwrap();
}

#[test]
fn file_log_refuses_broken_chain_and_foreign_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let (cfg, _) = config();
    {
        let log = FileAuditLog::open(&path, None, cfg.clone()).unwrap();
        fill(&log, 3);
    }
    let original = fs::read(&path).unwrap();

    // Flip one byte inside the detail of the first complete frame ("step 1" -> "step 9").
    let mut bytes = original.clone();
    let at = bytes.windows(6).position(|w| w == b"step 1").unwrap();
    bytes[at + 5] = b'9';
    fs::write(&path, &bytes).unwrap();
    assert_eq!(FileAuditLog::open(&path, None, cfg.clone()).err().unwrap().code, ErrorCode::RecoveryRequired);

    // Remove the middle frame entirely: complete frames, broken linkage.
    let len0 = u32::from_be_bytes(original[0..4].try_into().unwrap()) as usize + 4;
    let len1 = u32::from_be_bytes(original[len0..len0 + 4].try_into().unwrap()) as usize + 4;
    let mut gap = original[..len0].to_vec();
    gap.extend_from_slice(&original[len0 + len1..]);
    fs::write(&path, &gap).unwrap();
    assert_eq!(FileAuditLog::open(&path, None, cfg.clone()).err().unwrap().code, ErrorCode::RecoveryRequired);

    // Same file opened with another service key.
    fs::write(&path, &original).unwrap();
    let foreign = AuditLogConfig::new(KeyId::unchecked("audit-key-1"), SigningKey::from_bytes(&[11; 32]), Arc::new(ManualClock::new(T0)));
    assert_eq!(FileAuditLog::open(&path, None, foreign).err().unwrap().code, ErrorCode::RecoveryRequired);
    let renamed = AuditLogConfig::new(KeyId::unchecked("audit-key-2"), service_key(), Arc::new(ManualClock::new(T0)));
    assert_eq!(FileAuditLog::open(&path, None, renamed).err().unwrap().code, ErrorCode::RecoveryRequired);
    FileAuditLog::open(&path, None, cfg).unwrap();
}

#[test]
fn file_log_detects_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let (cfg, _) = config();
    {
        let log = FileAuditLog::open(&path, None, cfg.clone()).unwrap();
        fill(&log, 2);
    }
    let old = fs::read(&path).unwrap();
    {
        let log = FileAuditLog::open(&path, None, cfg.clone()).unwrap();
        log.append("operator:alice", "test.action", commits("intent", 3), Epoch(1), "step 3").unwrap();
        log.append("operator:alice", "test.action", commits("intent", 4), Epoch(1), "step 4").unwrap();
    }
    // Restore the older copy of the log: the sidecar high-water mark catches it.
    fs::write(&path, &old).unwrap();
    let err = FileAuditLog::open(&path, None, cfg.clone()).err().unwrap();
    assert_eq!(err.code, ErrorCode::RecoveryRequired);
    assert!(err.detail.contains("rollback"));

    // Without the sidecar, an independently held minimum still catches it.
    fs::remove_file(dir.path().join("audit.log.hwm")).unwrap();
    assert_eq!(FileAuditLog::open(&path, Some(4), cfg.clone()).err().unwrap().code, ErrorCode::RecoveryRequired);
    let log = FileAuditLog::open(&path, Some(2), cfg).unwrap();
    assert_eq!(log.head().unwrap().unwrap().0, 2);
}

#[test]
fn checkpoints_sign_and_detect_divergence() {
    // Two logs with the same key and clock produce identical events for
    // identical appends (Ed25519 is deterministic), then diverge.
    let clock = Arc::new(ManualClock::new(T0));
    let a = MemoryAuditLog::new(config_with(clock.clone()));
    let b = MemoryAuditLog::new(config_with(clock.clone()));
    let pk = a.verifying_key();

    let empty = a.checkpoint().unwrap();
    assert_eq!((empty.body.sequence, empty.body.head_event_hash), (0, Hash32::ZERO));
    verify_checkpoint(&empty, &pk).unwrap();

    fill(&a, 2);
    fill(&b, 2);
    assert_eq!(a.events(), b.events());
    let a2 = a.checkpoint().unwrap();
    let b2 = b.checkpoint().unwrap();
    verify_checkpoint(&a2, &pk).unwrap();
    assert_eq!(compare_checkpoints(&a2, &b2, &pk, &[]).unwrap(), CheckpointComparison::Consistent);

    // A tampered checkpoint or a foreign key fails.
    let mut forged = a2.clone();
    forged.body.sequence = 7;
    assert_eq!(verify_checkpoint(&forged, &pk).unwrap_err().code, ErrorCode::InvalidSignature);
    let other = SigningKey::from_bytes(&[10; 32]).verifying_key();
    assert_eq!(verify_checkpoint(&a2, &other).unwrap_err().code, ErrorCode::InvalidSignature);
    assert_eq!(compare_checkpoints(&forged, &b2, &pk, &[]).unwrap_err().code, ErrorCode::InvalidSignature);

    // Histories split at sequence 3.
    a.append("operator:alice", "payment.sent", commits("intent", 0xaa), Epoch(1), "to counterparty A").unwrap();
    b.append("operator:alice", "payment.sent", commits("intent", 0xbb), Epoch(1), "to counterparty B").unwrap();
    b.append("operator:alice", "payment.sent", commits("intent", 0xcc), Epoch(1), "more").unwrap();
    let a3 = a.checkpoint().unwrap();
    let b4 = b.checkpoint().unwrap();
    let b3_events = b.events_since(0, 3).unwrap();
    let b3 = MemoryAuditLog::new(config_with(clock.clone()));
    for e in &b3_events {
        b3.append(&e.body.actor, &e.body.action, e.body.object_commitments.clone(), e.body.policy_epoch, &e.body.detail).unwrap();
    }
    let b3 = b3.checkpoint().unwrap();
    assert_eq!(b3.body.sequence, 3);

    // Same sequence, different heads.
    assert_eq!(compare_checkpoints(&a3, &b3, &pk, &[]).unwrap(), CheckpointComparison::Diverged { at_sequence: 3 });
    // a3 vs b4 with b's bridge (event 4): does not link to a's head at 3.
    let bridge = b.events_since(3, 10).unwrap();
    assert_eq!(compare_checkpoints(&a3, &b4, &pk, &bridge).unwrap(), CheckpointComparison::Diverged { at_sequence: 3 });
    // Order of arguments does not matter.
    assert_eq!(compare_checkpoints(&b4, &a3, &pk, &bridge).unwrap(), CheckpointComparison::Diverged { at_sequence: 3 });
    // a2 vs b4 with b's bridge (events 3..=4): b extends the shared prefix.
    let bridge = b.events_since(2, 10).unwrap();
    assert_eq!(compare_checkpoints(&a2, &b4, &pk, &bridge).unwrap(), CheckpointComparison::Extends { from_sequence: 2, to_sequence: 4 });
    // a2 vs b3 bridged with a's event 3: a valid signed chain from a2 that ends at a different head than b3.
    let a_bridge = a.events_since(2, 10).unwrap();
    assert_eq!(compare_checkpoints(&a2, &b3, &pk, &a_bridge).unwrap(), CheckpointComparison::Diverged { at_sequence: 3 });

    // Bridges must cover exactly lo+1..=hi and be genuinely signed.
    assert_eq!(compare_checkpoints(&a2, &b4, &pk, &[]).unwrap_err().code, ErrorCode::InvalidRequest);
    assert_eq!(compare_checkpoints(&a2, &b4, &pk, &bridge[..1]).unwrap_err().code, ErrorCode::InvalidRequest);
    let mut forged_bridge = bridge.clone();
    forged_bridge[0].body.detail = "rewritten".into();
    forged_bridge[0].body.event_id = derive_event_id(&forged_bridge[0].body).unwrap();
    assert_eq!(compare_checkpoints(&a2, &b4, &pk, &forged_bridge).unwrap_err().code, ErrorCode::InvalidSignature);

    // Exact first divergence given both full histories.
    assert_eq!(first_divergence(&a.events(), &b.events(), &pk).unwrap(), Some(3));
    assert_eq!(first_divergence(&a.events()[..2], &b.events(), &pk).unwrap(), None);
}

// ---------------------------------------------------------------------------
// Authority sink
// ---------------------------------------------------------------------------

fn admin(n: u8) -> (CredentialId, SigningKey) {
    (CredentialId::unchecked(format!("admin-{n}")), SigningKey::from_bytes(&[n; 32]))
}
fn responder() -> (CredentialId, SigningKey) {
    (CredentialId::unchecked("responder-1"), SigningKey::from_bytes(&[77; 32]))
}
fn sign_cred(who: &(CredentialId, SigningKey), h: &Hash32) -> CredentialSignature {
    CredentialSignature {
        credential_id: who.0.clone(),
        signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(who.1.sign(&h.0).to_bytes().to_vec()) },
    }
}

fn authority_config() -> AuthorityConfig {
    AuthorityConfig {
        institution_id: InstitutionId::unchecked("inst-1"),
        environment_id: EnvironmentId::unchecked("testnet"),
        authority_key_id: KeyId::unchecked("authority-key-1"),
        admin_keys: (1..=3).map(admin).map(|(c, k)| (c, k.verifying_key())).collect(),
        admin_quorum: 2,
        freeze_responders: vec![(responder().0, responder().1.verifying_key())],
        release_receipt_ttl_seconds: 60,
        max_clock_skew_seconds: 30,
    }
}

fn policy(epoch: u64) -> PolicyBundle {
    let mut b = PolicyBundle {
        policy_id: PolicyId::unchecked("pol-1"),
        policy_epoch: Epoch(epoch),
        institution_id: InstitutionId::unchecked("inst-1"),
        environment_id: EnvironmentId::unchecked("testnet"),
        rules: vec![],
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 60,
        allowlist_version: 1,
        activation_epoch: Epoch(epoch),
        administrative_signatures: vec![],
    };
    let h = policy_hash(&b).unwrap();
    b.administrative_signatures = [1, 2].iter().map(|n| sign_cred(&admin(*n), &h)).collect();
    b
}

#[test]
fn authority_sink_round_trip() {
    let (cfg, clock) = config();
    let log = Arc::new(MemoryAuditLog::new(cfg));
    let sink = Arc::new(AuthorityAuditSink::new(log.clone(), "authority:inst-1/testnet"));
    let store = Arc::new(InMemoryAuthorityStore::new());
    let authority = Authority::open(store, 0, authority_config(), SigningKey::from_bytes(&[42; 32]), clock.clone()).unwrap().with_audit(sink.clone());

    let p1 = policy(1);
    let seq1 = authority.set_policy(&p1).unwrap();
    let p2 = policy(2);
    authority.set_policy(&p2).unwrap();
    let scope = FreezeScope::Vault { vault_id: VaultId::unchecked("vault-ops") };
    let proposal = FreezeProposal::new(InstitutionId::unchecked("inst-1"), EnvironmentId::unchecked("testnet"), scope.clone(), responder().0, "incident");
    let sig = sign_cred(&responder(), &proposal.hash().unwrap()).signature;
    authority.freeze(scope.clone(), responder().0, "incident", &sig).unwrap();
    // A rejected change (stale epoch) emits nothing.
    assert!(authority.set_policy(&p1).is_err());

    assert_eq!(sink.failure_count(), 0);
    assert_eq!(sink.last_error(), None);
    assert_eq!(sink.recorded_count(), 3);
    assert_eq!(sink.known_policy_epoch(), Some(Epoch(2)));
    let events = log.events();
    assert_eq!(events.len(), 3);
    verify_chain(&events, &log.verifying_key(), None).unwrap();

    let e = &events[0].body;
    assert_eq!(e.actor, "authority:inst-1/testnet");
    assert_eq!(e.action, "authority.policy_activated");
    assert_eq!(e.policy_epoch, Epoch(1));
    assert_eq!(e.object_commitments["policy"], policy_hash(&p1).unwrap());
    let expected = AuthorityEvent::PolicyActivated { policy_epoch: Epoch(1), policy_hash: policy_hash(&p1).unwrap(), commit_sequence: seq1 };
    assert_eq!(e.object_commitments["authority_event"], authority_event_commitment(&expected).unwrap());
    assert!(e.detail.contains(&format!("commit_sequence={seq1}")));
    assert!(!e.detail.contains("unknown"));

    assert_eq!(events[1].body.object_commitments["policy"], policy_hash(&p2).unwrap());
    assert_eq!(events[1].body.policy_epoch, Epoch(2));

    let f = &events[2].body;
    assert_eq!(f.action, "authority.frozen");
    assert_eq!(f.policy_epoch, Epoch(2));
    assert_eq!(f.object_commitments["freeze_scope"], object_commitment("freeze_scope", "vault:vault-ops").unwrap());
    assert!(f.detail.contains("scope=vault:vault-ops"));
    assert!(f.detail.contains("by=responder-1"));
}

#[test]
fn authority_event_mapping_covers_every_variant() {
    let rid = ReservationId::unchecked("res-1");
    let cases = vec![
        (AuthorityEvent::Opened { fence_token: 1, authority_epoch: Epoch(1), commit_sequence: 1 }, "authority.opened", vec![]),
        (AuthorityEvent::Reserved { reservation_id: rid.clone(), commit_sequence: 2 }, "authority.reserved", vec!["reservation"]),
        (
            AuthorityEvent::Released { reservation_id: rid.clone(), issuance_id: IssuanceId::unchecked("iss-1"), commit_sequence: 3 },
            "authority.released",
            vec!["issuance", "reservation"],
        ),
        (AuthorityEvent::Unfrozen { scope: FreezeScope::Global, commit_sequence: 4 }, "authority.unfrozen", vec!["freeze_scope"]),
        (AuthorityEvent::Aborted { reservation_id: rid.clone(), reason: AbortReason::ApprovalExpired, commit_sequence: 5 }, "authority.aborted", vec!["reservation"]),
        (
            AuthorityEvent::Observed {
                family_id: OperationFamilyId::unchecked("fam-1"),
                candidate_id: CandidateId::unchecked("cand-1"),
                lifecycle: LifecycleState::Included,
                commit_sequence: 6,
            },
            "authority.observed",
            vec!["candidate", "operation_family"],
        ),
    ];
    for (ev, action, keys) in cases {
        let unknown = authority_event_entry(&ev, None).unwrap();
        assert_eq!(unknown.action, action);
        assert_eq!(unknown.policy_epoch, Epoch(0));
        assert!(unknown.detail.ends_with("policy_epoch=unknown"), "{}", unknown.detail);
        let mut expected_keys: Vec<&str> = keys.clone();
        expected_keys.push("authority_event");
        expected_keys.sort();
        assert_eq!(unknown.object_commitments.keys().map(String::as_str).collect::<Vec<_>>(), expected_keys);
        let known = authority_event_entry(&ev, Some(Epoch(4))).unwrap();
        assert_eq!(known.policy_epoch, Epoch(4));
        assert!(!known.detail.contains("unknown"));
    }
    let e = authority_event_entry(&AuthorityEvent::Reserved { reservation_id: rid.clone(), commit_sequence: 2 }, None).unwrap();
    assert_eq!(e.object_commitments["reservation"], object_commitment("reservation", "res-1").unwrap());
    assert_ne!(object_commitment("reservation", "res-1").unwrap(), object_commitment("issuance", "res-1").unwrap());

    // Mapped entries are appendable as-is.
    let (cfg, _) = config();
    let log = Arc::new(MemoryAuditLog::new(cfg));
    let sink = AuthorityAuditSink::new(log.clone(), "authority").with_policy_epoch(Epoch(7));
    sink.record(&AuthorityEvent::Reserved { reservation_id: rid, commit_sequence: 2 });
    assert_eq!(sink.recorded_count(), 1);
    assert_eq!(log.events()[0].body.policy_epoch, Epoch(7));
}

/// An audit log whose storage is unavailable, to exercise the sink's
/// failure reporting (the only channel, since `AuditSink::record` returns `()`).
struct UnavailableLog;

impl AuditLog for UnavailableLog {
    fn append(&self, _: &str, _: &str, _: BTreeMap<String, Hash32>, _: Epoch, _: &str) -> OicResult<AuditEvent> {
        Err(OicError::new(ErrorCode::AuthorityUnavailable, "audit storage offline"))
    }
    fn head(&self) -> OicResult<Option<(u64, Hash32)>> {
        Ok(None)
    }
    fn events_since(&self, _: u64, _: usize) -> OicResult<Vec<AuditEvent>> {
        Ok(vec![])
    }
    fn checkpoint(&self) -> OicResult<AuditCheckpoint> {
        Err(OicError::new(ErrorCode::AuthorityUnavailable, "audit storage offline"))
    }
}

#[test]
fn authority_sink_reports_failures() {
    let clock = Arc::new(ManualClock::new(T0));
    let sink = Arc::new(AuthorityAuditSink::new(Arc::new(UnavailableLog), "authority"));
    let authority =
        Authority::open(Arc::new(InMemoryAuthorityStore::new()), 0, authority_config(), SigningKey::from_bytes(&[42; 32]), clock).unwrap().with_audit(sink.clone());
    // The authority's change still commits; the sink records the failure.
    authority.set_policy(&policy(1)).unwrap();
    assert_eq!(authority.current_policy().unwrap().0, Epoch(1));
    assert_eq!(sink.failure_count(), 1);
    assert_eq!(sink.recorded_count(), 0);
    assert_eq!(sink.last_error().unwrap().code, ErrorCode::AuthorityUnavailable);
    // Epoch tracking still advanced, so later events are stamped correctly once storage returns.
    assert_eq!(sink.known_policy_epoch(), Some(Epoch(1)));
}

#[test]
fn authority_sink_on_file_log_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let (cfg, clock) = config();
    {
        let log = Arc::new(FileAuditLog::open(&path, None, cfg.clone()).unwrap());
        let sink = Arc::new(AuthorityAuditSink::new(log, "authority"));
        let authority =
            Authority::open(Arc::new(InMemoryAuthorityStore::new()), 0, authority_config(), SigningKey::from_bytes(&[42; 32]), clock).unwrap().with_audit(sink.clone());
        authority.set_policy(&policy(1)).unwrap();
        assert_eq!(sink.recorded_count(), 1);
    }
    let log = FileAuditLog::open(&path, Some(1), cfg).unwrap();
    let events = log.events_since(0, 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].body.action, "authority.policy_activated");
    let cp = log.checkpoint().unwrap();
    verify_checkpoint(&cp, &log.verifying_key()).unwrap();
    assert_eq!((cp.body.sequence, cp.body.head_event_hash), log.head().unwrap().unwrap());
}
