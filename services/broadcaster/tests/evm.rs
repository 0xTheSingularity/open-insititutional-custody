//! Broadcaster against the EVM development simulator and a real authority:
//! submitted → included → finalized, A18, A30, A31, crash before ack.

mod common;

use common::*;
use k256::ecdsa::SigningKey;
use oic_adapter_api::*;
use oic_adapter_evm::address::{eip55, Address};
use oic_adapter_evm::evidence::TxObservation;
use oic_adapter_evm::EvmAdapter;
use oic_authorization_state::*;
use oic_chain_simulator::evm::*;
use oic_chain_simulator::SimClock;
use oic_domain_types::*;
use oic_service_broadcaster::*;
use std::sync::Arc;

const ETH: u128 = 1_000_000_000_000_000_000;
const DEST: Address = [0xde; 20];
const AMOUNT: u128 = ETH / 10;

struct Fixture {
    sim: Arc<EvmSimulator>,
    clock: SimClock,
    auth: Arc<Authority<InMemoryAuthorityStore>>,
    t: Transfer,
    candidate: Candidate,
    verified: VerifiedSignedTransaction,
    reservation: ReservationId,
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x21u8; 32].into()).unwrap()
}

fn sign_digest(sk: &SigningKey, digest: &[u8]) -> SignatureBytes {
    let (sig, recid) = sk.sign_prehash_recoverable(digest).unwrap();
    let mut b = sig.to_bytes().to_vec();
    b.push(recid.to_byte());
    SignatureBytes { scheme: SchemeId::EcdsaSecp256k1Keccak256Prehashed, bytes: Bytes(b) }
}

/// Build a native transfer via the adapter, sign it, and make it possibly
/// issued at a real authority.
fn fixture() -> Fixture {
    let clock = SimClock::default();
    let sim = Arc::new(EvmSimulator::new(EvmSimConfig::with_seed([9; 32]), clock.clone()).unwrap());
    let sk = key();
    let sender = address_of(&sk).unwrap();
    sim.fund(sender, ETH).unwrap();
    sim.mine().unwrap();
    let p = sim.profile();
    let pk = sk.verifying_key().to_encoded_point(true).as_bytes().to_vec();
    let party = party(&p, SchemeId::EcdsaSecp256k1Keccak256Prehashed, pk, sender.to_vec(), eip55(&sender));
    let a = asset(&p, AssetKind::Native, 18, "ETH");
    let d = destination(&p, DEST.to_vec(), eip55(&DEST));
    let t = Transfer::new(p, party, a, d, AMOUNT, 10u128.pow(16), 1);
    let ev = sim.evidence(&EvmEvidenceQuery::latest().sender(sender)).unwrap();
    let candidate = EvmAdapter.build_candidate(&t.build_ctx(ev.clone(), "cand-1", clock.now())).unwrap();
    let op = EvmAdapter.verify_candidate(&candidate, &AuthorizationTarget::Intent(&t.intent), &t.vctx(&ev)).unwrap();
    let sig = sign_digest(&sk, candidate.signing_payloads[0].message_or_digest.as_slice());
    let signed = EvmAdapter.assemble_signed_transaction(&candidate, &t.party.key, &[sig]).unwrap();
    let verified = EvmAdapter.verify_signed_transaction(&signed, &candidate, &t.party.key).unwrap();
    let auth = authority(&clock);
    let reservation = issue(&auth, &clock, &t, &candidate, &op.claims);
    Fixture { sim, clock, auth, t, candidate, verified, reservation }
}

fn broadcaster(f: &Fixture, client: Arc<dyn ChainClient>, store: Arc<dyn SubmissionStore>) -> Broadcaster<InMemoryAuthorityStore> {
    let mut b = Broadcaster::new(f.auth.clone(), store, Arc::new(SimTime(f.clock.clone())));
    b.register_network(f.sim.profile(), Arc::new(EvmAdapter), client).unwrap();
    b
}

/// Delegates everything; `submit` really submits, then claims failure (A18).
struct FailureClaimingClient(EvmSimulatorClient);

impl ChainClient for FailureClaimingClient {
    fn network_id(&self) -> NetworkId {
        self.0.network_id()
    }
    fn sources(&self) -> Vec<EvidenceSourceId> {
        self.0.sources()
    }
    fn submit(&self, signed: &SignedTransaction) -> OicResult<ChainTxId> {
        self.0.submit(signed)?;
        Err(OicError::new(ErrorCode::AuthorityUnavailable, "rpc timeout"))
    }
    fn evidence_for_tx(&self, s: &EvidenceSourceId, id: &ChainTxId, c: Commitment) -> OicResult<EvidenceBundle> {
        self.0.evidence_for_tx(s, id, c)
    }
    fn evidence_for_candidates(&self, s: &EvidenceSourceId, c: &[PossiblyIssued], k: Commitment) -> OicResult<EvidenceBundle> {
        self.0.evidence_for_candidates(s, c, k)
    }
    fn head(&self) -> StateReference {
        self.0.head()
    }
    fn finalized(&self) -> StateReference {
        self.0.finalized()
    }
}

/// Really submits, then the process "dies" before the acknowledgement returns.
struct CrashingClient(EvmSimulatorClient);

impl ChainClient for CrashingClient {
    fn network_id(&self) -> NetworkId {
        self.0.network_id()
    }
    fn sources(&self) -> Vec<EvidenceSourceId> {
        self.0.sources()
    }
    fn submit(&self, signed: &SignedTransaction) -> OicResult<ChainTxId> {
        self.0.submit(signed).unwrap();
        panic!("simulated crash after the chain accepted the bytes and before the acknowledgement was recorded");
    }
    fn evidence_for_tx(&self, s: &EvidenceSourceId, id: &ChainTxId, c: Commitment) -> OicResult<EvidenceBundle> {
        self.0.evidence_for_tx(s, id, c)
    }
    fn evidence_for_candidates(&self, s: &EvidenceSourceId, c: &[PossiblyIssued], k: Commitment) -> OicResult<EvidenceBundle> {
        self.0.evidence_for_candidates(s, c, k)
    }
    fn head(&self) -> StateReference {
        self.0.head()
    }
    fn finalized(&self) -> StateReference {
        self.0.finalized()
    }
}

#[test]
fn evm_submitted_included_finalized_settles_exposure() {
    let f = fixture();
    let b = broadcaster(&f, Arc::new(EvmSimulatorClient::new(f.sim.clone())), Arc::new(MemorySubmissionStore::new()));
    let fam = f.t.family();
    let rec = b.submit(&fam, &f.candidate, &f.verified, &f.t.profile.chain_profile_id).unwrap();
    assert_eq!(rec.lifecycle, LifecycleState::Submitted);
    assert!(matches!(rec.attempts[0].outcome, AttemptOutcome::Acknowledged { .. }));
    assert!(!rec.has_unknown_attempt());
    // Acknowledged is not inclusion.
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Submitted);
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT));

    f.sim.mine().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    // One more block: latest-view confirmations reach the depth, but only the
    // finality view may finalize.
    f.sim.mine().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    f.sim.mine().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::FinalizedSuccess);
    assert!(matches!(f.auth.reservation(&f.reservation).unwrap().state, ReservationState::Settled { success: true, .. }));
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount::ZERO);
    assert_eq!(settled(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT));
    assert_eq!(f.auth.family(&fam).unwrap().lifecycle, LifecycleState::FinalizedSuccess);
    // Terminal: further polls are stable and a rebroadcast is refused.
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::FinalizedSuccess);
    assert_eq!(b.rebroadcast(&fam).unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(f.sim.balance(&DEST), AMOUNT);
}

#[test]
fn a18_client_claims_failure_but_transaction_lands() {
    let f = fixture();
    let client = FailureClaimingClient(EvmSimulatorClient::new(f.sim.clone()));
    let b = broadcaster(&f, Arc::new(client), Arc::new(MemorySubmissionStore::new()));
    let fam = f.t.family();
    let rec = b.submit(&fam, &f.candidate, &f.verified, &f.t.profile.chain_profile_id).unwrap();
    assert_eq!(rec.lifecycle, LifecycleState::SubmissionUnknown);
    assert!(rec.has_unknown_attempt());
    assert!(matches!(&rec.attempts[0].outcome, AttemptOutcome::ErrorReported { code: ErrorCode::AuthorityUnavailable, .. }));
    // The claimed failure released nothing.
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT));
    f.sim.mine().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    f.sim.mine_blocks(2).unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::FinalizedSuccess);
    assert_eq!(f.sim.balance(&DEST), AMOUNT);
}

#[test]
fn a31_reorg_drops_transaction_then_reinclusion_finalizes() {
    let f = fixture();
    let b = broadcaster(&f, Arc::new(EvmSimulatorClient::new(f.sim.clone())), Arc::new(MemorySubmissionStore::new()));
    let fam = f.t.family();
    b.submit(&fam, &f.candidate, &f.verified, &f.t.profile.chain_profile_id).unwrap();
    f.sim.mine().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    let included_at = b.record(&fam).unwrap().unwrap().last_inclusion.unwrap();

    f.sim.reorg(1, std::slice::from_ref(&f.verified.signed.chain_tx_id)).unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Reorged);
    assert_eq!(f.auth.family(&fam).unwrap().lifecycle, LifecycleState::Reorged);
    // Exposure retained: the signed bytes can still execute.
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT));
    let rec = b.record(&fam).unwrap().unwrap();
    assert_eq!(rec.last_inclusion, None);
    assert_eq!(rec.last_observation, Some(ChainObservation::Reorged { tx_id: f.verified.signed.chain_tx_id.clone(), previous_state: included_at }));

    let rec = b.rebroadcast(&fam).unwrap();
    assert_eq!(rec.lifecycle, LifecycleState::Submitted);
    assert_eq!(rec.attempts.len(), 2);
    f.sim.mine().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    f.sim.mine_blocks(2).unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::FinalizedSuccess);
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount::ZERO);
}

#[test]
fn a31_reorg_reincluding_in_another_block_updates_inclusion() {
    let f = fixture();
    let b = broadcaster(&f, Arc::new(EvmSimulatorClient::new(f.sim.clone())), Arc::new(MemorySubmissionStore::new()));
    let fam = f.t.family();
    b.submit(&fam, &f.candidate, &f.verified, &f.t.profile.chain_profile_id).unwrap();
    f.sim.mine().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    let first = b.record(&fam).unwrap().unwrap().last_inclusion.unwrap();
    // Reorg without dropping: re-included in the replacement block (new hash).
    f.sim.reorg(1, &[]).unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    let second = b.record(&fam).unwrap().unwrap().last_inclusion.unwrap();
    assert_eq!(first.height, second.height);
    assert_ne!(first.hash, second.hash);
    f.sim.mine_blocks(2).unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::FinalizedSuccess);
}

#[test]
fn a30_conflicting_sources_quarantine_and_never_release() {
    let f = fixture();
    let honest = EvidenceSourceId::unchecked(SOURCE_ID);
    let liar = EvidenceSourceId::unchecked("devsim-evm-liar");
    let client = EvmSimulatorClient::with_sources(f.sim.clone(), vec![honest, liar.clone()]).unwrap();
    let b = broadcaster(&f, Arc::new(client), Arc::new(MemorySubmissionStore::new()));
    let fam = f.t.family();
    b.submit(&fam, &f.candidate, &f.verified, &f.t.profile.chain_profile_id).unwrap();
    // The liar claims deep inclusion while the transaction is still pending.
    let head = f.sim.head();
    let hash = parse_tx_id(&f.verified.signed.chain_tx_id).unwrap();
    let lie = TxObservation {
        included: true,
        block_height: head.height,
        block_hash: head.hash.clone(),
        success: true,
        gas_used: GAS_NATIVE_TRANSFER,
        effective_gas_price: Amount(DEFAULT_BASE_FEE),
        confirmations: 50,
        nonce_consumed_by: None,
    };
    f.sim.set_lie(&liar, hash, lie).unwrap();
    let lifecycle = b.poll(&fam).unwrap();
    assert_eq!(lifecycle, LifecycleState::Submitted);
    assert!(f.auth.family(&fam).unwrap().quarantined);
    let rec = b.record(&fam).unwrap().unwrap();
    assert!(rec.quarantined);
    assert!(matches!(rec.last_observation, Some(ChainObservation::Conflict { ref sources, .. }) if sources.len() == 2));

    // Even after the transaction really finalizes and the liar stops lying,
    // nothing is released while quarantined.
    f.sim.clear_lies(&liar);
    f.sim.mine_blocks(4).unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Submitted);
    assert_eq!(b.resolve_unknown(&fam).unwrap(), LifecycleState::Submitted);
    assert!(matches!(f.auth.reservation(&f.reservation).unwrap().state, ReservationState::Released { .. }));
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT));
    assert_eq!(b.rebroadcast(&fam).unwrap_err().code, ErrorCode::IssuanceUncertain);
    assert_eq!(b.submit(&fam, &f.candidate, &f.verified, &f.t.profile.chain_profile_id).unwrap_err().code, ErrorCode::IssuanceUncertain);
}

#[test]
fn crash_before_ack_reopens_as_submission_unknown_then_resolves() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("submissions.jsonl");
    let fam = f.t.family();
    {
        let store = Arc::new(FileSubmissionStore::open(&path).unwrap());
        assert_eq!(store.path(), path);
        let b = broadcaster(&f, Arc::new(CrashingClient(EvmSimulatorClient::new(f.sim.clone()))), store);
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b.submit(&fam, &f.candidate, &f.verified, &f.t.profile.chain_profile_id)));
        assert!(crashed.is_err());
    }
    // Restart: the pending attempt was durable before the chain call.
    let store = Arc::new(FileSubmissionStore::open(&path).unwrap());
    let rec = store.get(&fam).unwrap().unwrap();
    assert_eq!(rec.attempts.len(), 1);
    assert_eq!(rec.attempts[0].outcome, AttemptOutcome::Pending);
    let b = broadcaster(&f, Arc::new(EvmSimulatorClient::new(f.sim.clone())), store.clone());
    assert_eq!(b.recover().unwrap(), vec![fam.clone()]);
    assert_eq!(b.recover().unwrap(), Vec::<OperationFamilyId>::new());
    let rec = b.record(&fam).unwrap().unwrap();
    assert_eq!(rec.lifecycle, LifecycleState::SubmissionUnknown);
    assert!(matches!(rec.attempts[0].outcome, AttemptOutcome::Interrupted { .. }));
    // Not yet mined, nonce not consumed: invalidation cannot be proved.
    assert_eq!(b.resolve_unknown(&fam).unwrap(), LifecycleState::SubmissionUnknown);
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT));

    // The chain had accepted the bytes: once mined, the real outcome wins.
    f.sim.mine().unwrap();
    assert_eq!(b.resolve_unknown(&fam).unwrap(), LifecycleState::Included);
    f.sim.mine_blocks(2).unwrap();
    assert_eq!(b.resolve_unknown(&fam).unwrap(), LifecycleState::FinalizedSuccess);
    drop(b);

    // The file survives a torn tail (truncated) but not an altered record.
    let reopened = FileSubmissionStore::open(&path).unwrap();
    assert_eq!(reopened.get(&fam).unwrap().unwrap().lifecycle, LifecycleState::FinalizedSuccess);
    drop(reopened);
    std::fs::OpenOptions::new().append(true).open(&path).and_then(|mut fh| std::io::Write::write_all(&mut fh, b"{\"torn")).unwrap();
    let reopened = FileSubmissionStore::open(&path).unwrap();
    assert_eq!(reopened.list().unwrap().len(), 1);
    drop(reopened);
    std::fs::OpenOptions::new().append(true).open(&path).and_then(|mut fh| std::io::Write::write_all(&mut fh, b"not json\n")).unwrap();
    assert_eq!(FileSubmissionStore::open(&path).err().unwrap().code, ErrorCode::RecoveryRequired);
}

#[test]
fn bindings_and_registration_are_checked() {
    let f = fixture();
    let mut b = Broadcaster::new(f.auth.clone(), Arc::new(MemorySubmissionStore::new()), Arc::new(SimTime(f.clock.clone())));
    // Client for another network than the profile.
    let other = Arc::new(EvmSimulator::new(EvmSimConfig { chain_id: 5, ..EvmSimConfig::with_seed([1; 32]) }, f.clock.clone()).unwrap());
    assert_eq!(b.register_network(f.sim.profile(), Arc::new(EvmAdapter), Arc::new(EvmSimulatorClient::new(other))).unwrap_err().code, ErrorCode::ScopeMismatch);
    assert_eq!(
        b.register_network(f.sim.profile(), Arc::new(oic_adapter_solana::SolanaAdapter), Arc::new(EvmSimulatorClient::new(f.sim.clone()))).unwrap_err().code,
        ErrorCode::ScopeMismatch
    );
    assert!(EvmSimulatorClient::with_sources(f.sim.clone(), vec![]).is_err());
    let client = EvmSimulatorClient::new(f.sim.clone());
    assert_eq!(
        client.evidence_for_tx(&EvidenceSourceId::unchecked("unknown"), &f.verified.signed.chain_tx_id, Commitment::Latest).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    b.register_network(f.sim.profile(), Arc::new(EvmAdapter), Arc::new(client)).unwrap();
    let prof = f.t.profile.chain_profile_id.clone();
    // Wrong family / wrong profile.
    assert_eq!(b.submit(&OperationFamilyId::unchecked("fam-x"), &f.candidate, &f.verified, &prof).unwrap_err().code, ErrorCode::ScopeMismatch);
    assert_eq!(b.submit(&f.t.family(), &f.candidate, &f.verified, &ChainProfileId::unchecked("other")).unwrap_err().code, ErrorCode::ScopeMismatch);
    assert_eq!(b.poll(&f.t.family()).unwrap_err().code, ErrorCode::NotFound);
    // A different candidate for an already recorded family is refused.
    b.submit(&f.t.family(), &f.candidate, &f.verified, &prof).unwrap();
    let mut other_candidate = f.candidate.clone();
    other_candidate.candidate_id = CandidateId::unchecked("cand-2");
    let mut other_signed = f.verified.clone();
    other_signed.signed.candidate_id = other_candidate.candidate_id.clone();
    assert_eq!(b.submit(&f.t.family(), &other_candidate, &other_signed, &prof).unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(b.register_possibly_issued(&f.t.family(), &other_candidate, &other_signed.signed, &prof).unwrap_err().code, ErrorCode::Conflict);
    // Same candidate again is an idempotent re-registration / rebroadcast.
    assert_eq!(b.register_possibly_issued(&f.t.family(), &f.candidate, &f.verified.signed, &prof).unwrap().attempts.len(), 1);
    let again = b.submit(&f.t.family(), &f.candidate, &f.verified, &prof).unwrap();
    assert_eq!(again.attempts.len(), 2);
    assert!(matches!(again.attempts[1].outcome, AttemptOutcome::ErrorReported { code: ErrorCode::ResourceConflict, .. }));
    assert_eq!(again.lifecycle, LifecycleState::Submitted);
    assert!(Arc::ptr_eq(b.authority(), &f.auth));
}
