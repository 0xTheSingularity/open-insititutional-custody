use oic_canonical_encoding::sha256;
use oic_crypto_provider::{OneTimeStateLedger, OneTimeStateRecord};
use oic_domain_types::*;
use oic_one_time_state_ledger::*;
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn key() -> KeyId {
    KeyId::unchecked("key-1")
}

fn sess(n: u32) -> SigningSessionId {
    SigningSessionId::unchecked(format!("session-{n}"))
}

fn h(n: u8) -> Hash32 {
    sha256(&[n])
}

/// Runs the full single-use contract against any ledger.
fn contract(l: &dyn OneTimeStateLedger) {
    let r = l.allocate(&key(), Epoch(3), Epoch(7), &sess(1)).unwrap();
    assert_eq!(r.record_id, record_id_for(&key(), Epoch(3), Epoch(7), &sess(1), 0));
    assert_eq!(r.session_id, Some(sess(1)));
    assert_eq!(r.key_epoch, Epoch(3));
    assert_eq!(r.signer_generation, Epoch(7));
    assert!(!r.consumed && r.bound_message_hash.is_none());

    // Same inputs, fresh counter: distinct identity.
    let r2 = l.allocate(&key(), Epoch(3), Epoch(7), &sess(1)).unwrap();
    assert_ne!(r.record_id, r2.record_id);

    l.consume(&r.record_id, h(1)).unwrap();
    let got = l.get(&r.record_id).unwrap().unwrap();
    assert!(got.consumed);
    assert_eq!(got.bound_message_hash, Some(h(1)));

    assert_eq!(l.consume(&r.record_id, h(1)).unwrap_err().code, ErrorCode::ResourceConflict);
    assert_eq!(l.consume(&r.record_id, h(2)).unwrap_err().code, ErrorCode::ResourceConflict);
    assert_eq!(l.consume("deadbeef", h(1)).unwrap_err().code, ErrorCode::NotFound);
    assert!(l.get("deadbeef").unwrap().is_none());

    // Untouched by the failures above.
    assert!(!l.get(&r2.record_id).unwrap().unwrap().consumed);
}

fn tombstone_contract(l: &dyn OneTimeStateLedger) -> (String, String, String) {
    let old_unconsumed = l.allocate(&key(), Epoch(1), Epoch(1), &sess(10)).unwrap();
    let old_consumed = l.allocate(&key(), Epoch(1), Epoch(1), &sess(11)).unwrap();
    l.consume(&old_consumed.record_id, h(9)).unwrap();
    let other_key = l.allocate(&KeyId::unchecked("key-2"), Epoch(1), Epoch(1), &sess(12)).unwrap();
    let current = l.allocate(&key(), Epoch(1), Epoch(2), &sess(13)).unwrap();

    assert_eq!(l.tombstone_generations_before(&key(), Epoch(2)).unwrap(), 1);
    // Idempotent: nothing left to tombstone, floor unchanged.
    assert_eq!(l.tombstone_generations_before(&key(), Epoch(2)).unwrap(), 0);

    let t = l.get(&old_unconsumed.record_id).unwrap().unwrap();
    assert!(t.consumed);
    assert!(t.bound_message_hash.is_none());
    assert_eq!(l.consume(&old_unconsumed.record_id, h(1)).unwrap_err().code, ErrorCode::ResourceConflict);
    // Previously consumed record keeps its binding.
    assert_eq!(l.get(&old_consumed.record_id).unwrap().unwrap().bound_message_hash, Some(h(9)));
    // Other keys and the current generation are untouched.
    assert!(!l.get(&other_key.record_id).unwrap().unwrap().consumed);
    assert!(!l.get(&current.record_id).unwrap().unwrap().consumed);
    // Stale generation is fenced from allocating again.
    assert_eq!(l.allocate(&key(), Epoch(1), Epoch(1), &sess(14)).unwrap_err().code, ErrorCode::ResourceConflict);
    l.allocate(&key(), Epoch(1), Epoch(2), &sess(14)).unwrap();
    (old_unconsumed.record_id, current.record_id, other_key.record_id)
}

#[test]
fn in_memory_contract() {
    let l = InMemoryLedger::new();
    contract(&l);
    assert_eq!(l.sequence(), 3);
    assert_eq!(l.snapshot().len(), 2);
}

#[test]
fn in_memory_tombstones() {
    let l = InMemoryLedger::new();
    let (tomb, current, _) = tombstone_contract(&l);
    assert!(l.is_tombstoned(&tomb).unwrap());
    assert!(!l.is_tombstoned(&current).unwrap());
    assert_eq!(l.is_tombstoned("nope").unwrap_err().code, ErrorCode::NotFound);
}

#[test]
fn file_contract_and_tombstones() {
    let dir = tempfile::tempdir().unwrap();
    let l = FileLedger::open(dir.path().join("ledger.log"), None).unwrap();
    contract(&l);
    let (tomb, current, _) = tombstone_contract(&l);
    assert!(l.is_tombstoned(&tomb).unwrap());
    assert!(!l.is_tombstoned(&current).unwrap());
    assert_eq!(l.path(), dir.path().join("ledger.log"));
}

#[test]
fn fault_hook_aborts_before_commit() {
    let fail = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(parking_lot_free::Log::default());
    let (f2, s2) = (fail.clone(), seen.clone());
    let l = InMemoryLedger::new().with_fault_hook(Box::new(move |op: &str, rec: &OneTimeStateRecord| {
        s2.push(op, rec);
        if f2.load(Ordering::SeqCst) {
            Err(OicError::internal("injected crash before write"))
        } else {
            Ok(())
        }
    }));
    let r = l.allocate(&key(), Epoch(1), Epoch(1), &sess(1)).unwrap();
    fail.store(true, Ordering::SeqCst);
    assert_eq!(l.consume(&r.record_id, h(1)).unwrap_err().code, ErrorCode::Internal);
    // Crash before write: record still unconsumed and unbound.
    let got = l.get(&r.record_id).unwrap().unwrap();
    assert!(!got.consumed && got.bound_message_hash.is_none());
    assert!(l.allocate(&key(), Epoch(1), Epoch(1), &sess(2)).is_err());
    assert_eq!(l.snapshot().len(), 1);
    assert_eq!(l.sequence(), 1);
    fail.store(false, Ordering::SeqCst);
    l.consume(&r.record_id, h(1)).unwrap();
    let ops = seen.ops();
    assert_eq!(ops[0].0, OP_ALLOCATE);
    assert!(!ops[0].1.consumed);
    assert_eq!(ops[1].0, OP_CONSUME);
    assert!(ops[1].1.consumed, "hook sees the would-be committed record");
    assert_eq!(ops.last().unwrap().0, OP_CONSUME);
}

#[test]
fn fault_hook_sees_tombstones() {
    let fail = Arc::new(AtomicBool::new(false));
    let f2 = fail.clone();
    let l = InMemoryLedger::new().with_fault_hook(Box::new(move |op: &str, _rec: &OneTimeStateRecord| {
        if op == OP_TOMBSTONE && f2.load(Ordering::SeqCst) {
            Err(OicError::internal("crash"))
        } else {
            Ok(())
        }
    }));
    let r = l.allocate(&key(), Epoch(1), Epoch(1), &sess(1)).unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(l.tombstone_generations_before(&key(), Epoch(2)).is_err());
    assert!(!l.is_tombstoned(&r.record_id).unwrap());
    fail.store(false, Ordering::SeqCst);
    assert_eq!(l.tombstone_generations_before(&key(), Epoch(2)).unwrap(), 1);
}

/// Minimal thread-safe recorder for hook observations.
mod parking_lot_free {
    use oic_crypto_provider::OneTimeStateRecord;
    use std::sync::Mutex;
    #[derive(Default)]
    pub struct Log(Mutex<Vec<(String, OneTimeStateRecord)>>);
    impl Log {
        pub fn push(&self, op: &str, r: &OneTimeStateRecord) {
            self.0.lock().unwrap().push((op.to_string(), r.clone()));
        }
        pub fn ops(&self) -> Vec<(String, OneTimeStateRecord)> {
            self.0.lock().unwrap().clone()
        }
    }
}

#[test]
fn crash_restore_state_identical() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.log");
    let (snap, seq, consumed_id, open_id) = {
        let l = FileLedger::open(&path, None).unwrap();
        let a = l.allocate(&key(), Epoch(1), Epoch(1), &sess(1)).unwrap();
        let b = l.allocate(&key(), Epoch(1), Epoch(1), &sess(2)).unwrap();
        l.consume(&a.record_id, h(1)).unwrap();
        l.tombstone_generations_before(&KeyId::unchecked("other"), Epoch(5)).unwrap();
        (l.snapshot(), l.sequence(), a.record_id, b.record_id)
    };
    assert_eq!(seq, 4);
    let l = FileLedger::open(&path, Some(4)).unwrap();
    assert_eq!(l.snapshot(), snap);
    assert_eq!(l.sequence(), seq);
    // Consumption survived the restart.
    assert_eq!(l.consume(&consumed_id, h(1)).unwrap_err().code, ErrorCode::ResourceConflict);
    // Counter survived: next allocation gets a fresh id.
    let c = l.allocate(&key(), Epoch(1), Epoch(1), &sess(1)).unwrap();
    assert_eq!(c.record_id, record_id_for(&key(), Epoch(1), Epoch(1), &sess(1), 2));
    l.consume(&open_id, h(2)).unwrap();
    // Floor survived.
    assert!(l.allocate(&KeyId::unchecked("other"), Epoch(1), Epoch(4), &sess(3)).is_err());
}

#[test]
fn rollback_detected_by_expected_min_and_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.log");
    let l = FileLedger::open(&path, None).unwrap();
    let a = l.allocate(&key(), Epoch(1), Epoch(1), &sess(1)).unwrap();
    let backup = std::fs::read(&path).unwrap();
    l.consume(&a.record_id, h(1)).unwrap();
    drop(l);

    // Restore the older log (consumption would re-enter circulation).
    std::fs::write(&path, &backup).unwrap();
    let err = FileLedger::open(&path, None).err().unwrap();
    assert_eq!(err.code, ErrorCode::RecoveryRequired, "sidecar high-water mark detects the restore");

    // Even with the sidecar also rolled back, the independent minimum detects it.
    std::fs::remove_file(dir.path().join("ledger.log.hwm")).unwrap();
    let err = FileLedger::open(&path, Some(2)).err().unwrap();
    assert_eq!(err.code, ErrorCode::RecoveryRequired);
    // Without any witness it opens (documented limitation).
    assert_eq!(FileLedger::open(&path, None).unwrap().sequence(), 1);
}

#[test]
fn torn_tail_is_truncated_and_corruption_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.log");
    let l = FileLedger::open(&path, None).unwrap();
    let a = l.allocate(&key(), Epoch(1), Epoch(1), &sess(1)).unwrap();
    drop(l);
    let good = std::fs::read(&path).unwrap();

    // Torn append: partial frame after the durable prefix.
    let mut torn = good.clone();
    torn.extend_from_slice(&[0, 0, 0, 50, 1, 2, 3]);
    std::fs::write(&path, &torn).unwrap();
    let l = FileLedger::open(&path, Some(1)).unwrap();
    assert_eq!(l.sequence(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), good);
    l.consume(&a.record_id, h(1)).unwrap();
    drop(l);
    assert_eq!(FileLedger::open(&path, None).unwrap().sequence(), 2);

    // Flipped byte inside a complete frame: corruption, refuse.
    let mut bad = std::fs::read(&path).unwrap();
    bad[10] ^= 0xff;
    std::fs::write(&path, &bad).unwrap();
    assert_eq!(FileLedger::open(&path, None).err().unwrap().code, ErrorCode::RecoveryRequired);
}

#[test]
fn file_ledger_is_shareable_across_threads() {
    let dir = tempfile::tempdir().unwrap();
    let l = Arc::new(FileLedger::open(dir.path().join("l.log"), None).unwrap());
    let r = l.allocate(&key(), Epoch(1), Epoch(1), &sess(1)).unwrap();
    let wins: usize = (0..4)
        .map(|i| {
            let l = l.clone();
            let id = r.record_id.clone();
            std::thread::spawn(move || l.consume(&id, h(i as u8)).is_ok())
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| t.join().unwrap() as usize)
        .sum();
    assert_eq!(wins, 1);
}

#[derive(Clone, Debug)]
enum Op {
    Allocate(u8),
    Consume(u8, u8),
    Tombstone(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..4).prop_map(Op::Allocate),
        (0u8..16, 0u8..3).prop_map(|(r, m)| Op::Consume(r, m)),
        (0u8..4).prop_map(Op::Tombstone),
    ]
}

fn run_interleaving(l: &dyn OneTimeStateLedger, ops: &[Op]) -> Result<(), TestCaseError> {
    let mut ids: Vec<String> = Vec::new();
    let mut wins: BTreeMap<String, u32> = BTreeMap::new();
    let mut gen = 1u64;
    for op in ops {
        match op {
            Op::Allocate(s) => {
                if let Ok(r) = l.allocate(&key(), Epoch(1), Epoch(gen), &sess(*s as u32)) {
                    prop_assert!(!ids.contains(&r.record_id));
                    ids.push(r.record_id);
                }
            }
            Op::Consume(r, m) => {
                let id = if ids.is_empty() { "unknown".to_string() } else { ids[*r as usize % ids.len()].clone() };
                if l.consume(&id, h(*m)).is_ok() {
                    *wins.entry(id).or_default() += 1;
                }
            }
            Op::Tombstone(d) => {
                gen += *d as u64;
                l.tombstone_generations_before(&key(), Epoch(gen)).unwrap();
            }
        }
    }
    for (id, n) in wins {
        prop_assert_eq!(n, 1, "record {} consumed {} times", id, n);
    }
    Ok(())
}

proptest! {
    #[test]
    fn never_two_successful_consumes_in_memory(ops in prop::collection::vec(op(), 1..60)) {
        run_interleaving(&InMemoryLedger::new(), &ops)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn never_two_successful_consumes_file_with_reopen(ops in prop::collection::vec(op(), 1..30)) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l.log");
        let (seq, snap) = {
            let l = FileLedger::open(&path, None).unwrap();
            run_interleaving(&l, &ops)?;
            (l.sequence(), l.snapshot())
        };
        let l = FileLedger::open(&path, Some(seq)).unwrap();
        prop_assert_eq!(l.snapshot(), snap.clone());
        for r in snap.iter().filter(|r| r.consumed) {
            prop_assert!(l.consume(&r.record_id, r.bound_message_hash.unwrap_or(h(0))).is_err());
        }
    }
}
