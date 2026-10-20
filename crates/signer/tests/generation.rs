//! Signer generations, rollback detection, and key loading (A12, A13).

mod common;

use common::*;
use oic_adapter_api::ChainAdapter;
use oic_adapter_evm::EvmAdapter;
use oic_crypto_provider::*;
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_domain_types::*;
use oic_one_time_state_ledger::{FileLedger, InMemoryLedger};
use oic_signer::*;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

fn adapters() -> BTreeMap<AdapterId, Arc<dyn ChainAdapter>> {
    let mut a: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::new();
    a.insert(AdapterId::unchecked("evm"), Arc::new(EvmAdapter));
    a
}

fn dev() -> Arc<DevSingleKeyProvider> {
    Arc::new(DevSingleKeyProvider::with_os_rng(SchemeId::EcdsaSecp256k1Keccak256Prehashed, [9; 32]).unwrap())
}

fn open(world: &World, ledger: Arc<dyn OneTimeStateLedger>, store: Arc<dyn GenerationStore>) -> OicResult<Signer> {
    Signer::open(identity(&pid(1)), world.trust_roots(vec![evm_profile()]), adapters(), dev(), ledger, store)
}

fn copy_ledger(from: &Path, to: &Path) {
    std::fs::copy(from, to).unwrap();
    let hwm = |p: &Path| {
        let mut s = p.as_os_str().to_owned();
        s.push(".hwm");
        std::path::PathBuf::from(s)
    };
    std::fs::copy(hwm(from), hwm(to)).unwrap();
}

#[test]
fn every_open_bumps_and_persists_the_generation() {
    let world = World::new();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FileGenerationStore::new(dir.path().join("generation")));
    let ledger: Arc<dyn OneTimeStateLedger> = Arc::new(InMemoryLedger::new());
    assert_eq!(open(&world, ledger.clone(), store.clone()).unwrap().generation(), Epoch(1));
    assert_eq!(open(&world, ledger.clone(), store.clone()).unwrap().generation(), Epoch(2));
    assert_eq!(store.load().unwrap(), Some(Epoch(2)));
    let reopened = Arc::new(FileGenerationStore::new(dir.path().join("generation")));
    assert_eq!(open(&world, ledger, reopened).unwrap().generation(), Epoch(3));
}

#[test]
fn a13_restored_older_ledger_requires_recovery() {
    let world = World::new();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("ots.log");
    let backup = dir.path().join("backup.log");
    let store: Arc<dyn GenerationStore> = Arc::new(FileGenerationStore::new(dir.path().join("generation")));

    {
        let ledger = Arc::new(FileLedger::open(&log, None).unwrap());
        assert_eq!(open(&world, ledger, store.clone()).unwrap().generation(), Epoch(1));
    }
    copy_ledger(&log, &backup); // backup taken at generation 1
    {
        let ledger = Arc::new(FileLedger::open(&log, None).unwrap());
        assert_eq!(open(&world, ledger, store.clone()).unwrap().generation(), Epoch(2));
    }
    let current = dir.path().join("current.log");
    copy_ledger(&log, &current);

    // Restoring only the log is caught by the ledger's own high-water mark.
    std::fs::copy(&backup, &log).unwrap();
    assert_eq!(FileLedger::open(&log, None).err().unwrap().code, ErrorCode::RecoveryRequired);

    // Restoring log and sidecar together passes the ledger but not the signer fence.
    copy_ledger(&backup, &log);
    let restored = Arc::new(FileLedger::open(&log, None).expect("restored ledger opens on its own"));
    assert_eq!(open(&world, restored, store.clone()).err().unwrap().code, ErrorCode::RecoveryRequired);
    assert_eq!(store.load().unwrap(), Some(Epoch(2)), "a refused open does not advance the generation");

    // A brand-new empty ledger is equally refused.
    let fresh = Arc::new(FileLedger::open(dir.path().join("fresh.log"), None).unwrap());
    assert_eq!(open(&world, fresh, store.clone()).err().unwrap().code, ErrorCode::RecoveryRequired);

    // The real current ledger still opens.
    copy_ledger(&current, &log);
    let ledger = Arc::new(FileLedger::open(&log, None).unwrap());
    assert_eq!(open(&world, ledger, store).unwrap().generation(), Epoch(3));
}

#[test]
fn load_key_tombstones_older_generation_records_and_checks_scope() {
    let world = World::new();
    let ledger = Arc::new(InMemoryLedger::new());
    let store = Arc::new(InMemoryGenerationStore::new());
    let provider = dev();
    let (key, sealed) = evm_key(&provider, &pid(1));
    let first = Signer::open(identity(&pid(1)), world.trust_roots(vec![evm_profile()]), adapters(), provider.clone(), ledger.clone(), store.clone()).unwrap();
    first.load_key(&key, &sealed).unwrap();
    let old = ledger.allocate(&key.key_id, key.key_epoch, first.generation(), &sid("old-session")).unwrap();

    let second = Signer::open(identity(&pid(1)), world.trust_roots(vec![evm_profile()]), adapters(), provider.clone(), ledger.clone(), store).unwrap();
    assert!(!ledger.is_tombstoned(&old.record_id).unwrap());
    second.load_key(&key, &sealed).unwrap();
    assert!(ledger.is_tombstoned(&old.record_id).unwrap());
    // The old generation can no longer allocate for this key.
    assert_eq!(ledger.allocate(&key.key_id, key.key_epoch, first.generation(), &sid("again")).unwrap_err().code, ErrorCode::ResourceConflict);

    let mut other_inst = key.clone();
    other_inst.institution_id = InstitutionId::unchecked("inst-2");
    assert_eq!(second.load_key(&other_inst, &sealed).unwrap_err().code, ErrorCode::ScopeMismatch);
    let mut not_member = key.clone();
    not_member.participants = vec![pid(2)];
    assert_eq!(second.load_key(&not_member, &sealed).unwrap_err().code, ErrorCode::ScopeMismatch);
    let mut other_backend = key.clone();
    other_backend.backend_id = "frost-ed25519".into();
    assert_eq!(second.load_key(&other_backend, &sealed).unwrap_err().code, ErrorCode::UnsupportedCapability);
    let mut older = key.clone();
    older.key_epoch = Epoch(0);
    assert_eq!(second.load_key(&older, &sealed).unwrap_err().code, ErrorCode::Conflict);
    let mut tampered = sealed.clone();
    tampered.0[10] ^= 1;
    assert!(second.load_key(&key, &tampered).is_err(), "sealed share authentication fails");
}

#[test]
fn open_rejects_misconfiguration() {
    let world = World::new();
    let ledger: Arc<dyn OneTimeStateLedger> = Arc::new(InMemoryLedger::new());
    let mut roots = world.trust_roots(vec![evm_profile()]);
    roots.admin_quorum = 0;
    let r = Signer::open(identity(&pid(1)), roots, adapters(), dev(), ledger.clone(), Arc::new(InMemoryGenerationStore::new()));
    assert_eq!(r.err().unwrap().code, ErrorCode::InvalidRequest);
    let mut wrong: BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = BTreeMap::new();
    wrong.insert(AdapterId::unchecked("solana"), Arc::new(EvmAdapter));
    let r = Signer::open(identity(&pid(1)), world.trust_roots(vec![evm_profile()]), wrong, dev(), ledger, Arc::new(InMemoryGenerationStore::new()));
    assert_eq!(r.err().unwrap().code, ErrorCode::InvalidRequest);
}
