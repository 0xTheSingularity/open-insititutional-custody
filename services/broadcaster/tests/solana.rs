//! Broadcaster against the Solana development simulator: submitted →
//! finalized with two agreeing sources, fork correction, and invalidation
//! of an expired possibly issued candidate.

mod common;

use common::*;
use ed25519_dalek::{Signer, SigningKey};
use oic_adapter_api::*;
use oic_adapter_solana::address::to_base58;
use oic_adapter_solana::SolanaAdapter;
use oic_authorization_state::*;
use oic_chain_simulator::solana::*;
use oic_chain_simulator::SimClock;
use oic_domain_types::*;
use oic_service_broadcaster::*;
use std::sync::Arc;

const SOL: u64 = 1_000_000_000;
const AMOUNT: u64 = 250_000;

struct Fixture {
    sim: Arc<SolanaSimulator>,
    clock: SimClock,
    auth: Arc<Authority<InMemoryAuthorityStore>>,
    t: Transfer,
    candidate: Candidate,
    verified: VerifiedSignedTransaction,
    reservation: ReservationId,
}

fn fixture(cfg: SolanaSimConfig) -> Fixture {
    let clock = SimClock::default();
    let sim = Arc::new(SolanaSimulator::new(cfg, clock.clone()).unwrap());
    let sk = SigningKey::from_bytes(&[0x31; 32]);
    let me = sk.verifying_key().to_bytes();
    sim.airdrop(&me, SOL).unwrap();
    sim.advance_slot().unwrap();
    let dest = [0x77u8; 32];
    let p = sim.profile();
    let party = party(&p, SchemeId::Ed25519Pure, me.to_vec(), me.to_vec(), to_base58(&me));
    let a = asset(&p, AssetKind::Native, 9, "SOL");
    let d = destination(&p, dest.to_vec(), to_base58(&dest));
    let t = Transfer::new(p, party, a, d, AMOUNT as u128, 10_000_000, 1);
    let ev = sim.evidence(&SolanaEvidenceQuery::processed()).unwrap();
    let candidate = SolanaAdapter.build_candidate(&t.build_ctx(ev.clone(), "cand-1", clock.now())).unwrap();
    let op = SolanaAdapter.verify_candidate(&candidate, &AuthorizationTarget::Intent(&t.intent), &t.vctx(&ev)).unwrap();
    let sig = SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: Bytes(sk.sign(candidate.signing_payloads[0].message_or_digest.as_slice()).to_bytes().to_vec()) };
    let signed = SolanaAdapter.assemble_signed_transaction(&candidate, &t.party.key, &[sig]).unwrap();
    let verified = SolanaAdapter.verify_signed_transaction(&signed, &candidate, &t.party.key).unwrap();
    let auth = authority(&clock);
    let reservation = issue(&auth, &clock, &t, &candidate, &op.claims);
    Fixture { sim, clock, auth, t, candidate, verified, reservation }
}

fn broadcaster(f: &Fixture, client: SolanaSimulatorClient) -> Broadcaster<InMemoryAuthorityStore> {
    let mut b = Broadcaster::new(f.auth.clone(), Arc::new(MemorySubmissionStore::new()), Arc::new(SimTime(f.clock.clone())));
    b.register_network(f.sim.profile(), Arc::new(SolanaAdapter), Arc::new(client)).unwrap();
    b
}

fn two_sources(sim: &Arc<SolanaSimulator>) -> SolanaSimulatorClient {
    SolanaSimulatorClient::with_sources(sim.clone(), vec![EvidenceSourceId::unchecked(SOURCE_ID), EvidenceSourceId::unchecked("devsim-solana-second")]).unwrap()
}

#[test]
fn solana_submitted_to_finalized_with_two_agreeing_sources() {
    let f = fixture(SolanaSimConfig::with_seed([5; 32]));
    let b = broadcaster(&f, two_sources(&f.sim));
    let fam = f.t.family();
    assert_eq!(b.submit(&fam, &f.candidate, &f.verified, &f.t.profile.chain_profile_id).unwrap().lifecycle, LifecycleState::Submitted);
    // Queued, not included: the adapter has no tx item, so not visible.
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Submitted);
    f.sim.advance_slot().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    f.sim.advance_slots(3).unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT as u128));
    f.sim.advance_slot().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::FinalizedSuccess);
    assert!(matches!(f.auth.reservation(&f.reservation).unwrap().state, ReservationState::Settled { success: true, .. }));
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount::ZERO);
    assert_eq!(settled(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT as u128));
    assert_eq!(f.sim.lamports(&[0x77; 32]), AMOUNT);
    assert!(SolanaSimulatorClient::with_sources(f.sim.clone(), vec![]).is_err());
}

#[test]
fn solana_fork_drops_then_rebroadcast_finalizes() {
    let f = fixture(SolanaSimConfig::with_seed([6; 32]));
    let b = broadcaster(&f, SolanaSimulatorClient::new(f.sim.clone()));
    let fam = f.t.family();
    b.submit(&fam, &f.candidate, &f.verified, &f.t.profile.chain_profile_id).unwrap();
    let base = f.sim.head().height;
    f.sim.advance_slot().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    f.sim.fork(base, std::slice::from_ref(&f.verified.signed.chain_tx_id)).unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Reorged);
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT as u128));
    assert_eq!(f.sim.lamports(&[0x77; 32]), 0);
    // Its blockhash is still canonical: the same bytes land again.
    assert_eq!(b.rebroadcast(&fam).unwrap().lifecycle, LifecycleState::Submitted);
    f.sim.advance_slot().unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::Included);
    f.sim.advance_slots(4).unwrap();
    assert_eq!(b.poll(&fam).unwrap(), LifecycleState::FinalizedSuccess);
    assert_eq!(f.sim.lamports(&[0x77; 32]), AMOUNT);
}

#[test]
fn issuance_unknown_resolves_only_with_definitive_expiry_proof() {
    let f = fixture(SolanaSimConfig { blockhash_validity_slots: 3, finality_depth: 2, ..SolanaSimConfig::with_seed([7; 32]) });
    let b = broadcaster(&f, two_sources(&f.sim));
    let fam = f.t.family();
    // Signature may exist but was never broadcast by us.
    let rec = b.register_possibly_issued(&fam, &f.candidate, &f.verified.signed, &f.t.profile.chain_profile_id).unwrap();
    assert_eq!(rec.lifecycle, LifecycleState::IssuanceUnknown);
    assert!(rec.attempts.is_empty());
    // Blockhash still valid: no proof, stays unknown, exposure retained.
    assert_eq!(b.resolve_unknown(&fam).unwrap(), LifecycleState::IssuanceUnknown);
    f.sim.advance_slots(3).unwrap();
    assert_eq!(b.resolve_unknown(&fam).unwrap(), LifecycleState::IssuanceUnknown);
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount(AMOUNT as u128));
    // Past last_valid_height + finality depth at the finalized view.
    f.sim.advance_slots(6).unwrap();
    assert_eq!(b.resolve_unknown(&fam).unwrap(), LifecycleState::DefinitivelyInvalidated);
    assert!(matches!(f.auth.reservation(&f.reservation).unwrap().state, ReservationState::Invalidated { .. }));
    assert_eq!(outstanding(&f.auth, &f.clock, &f.t.asset.asset_id), Amount::ZERO);
    assert_eq!(settled(&f.auth, &f.clock, &f.t.asset.asset_id), Amount::ZERO);
    // The expired bytes are refused by the chain; nothing changes.
    assert_eq!(b.rebroadcast(&fam).unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(b.resolve_unknown(&fam).unwrap(), LifecycleState::DefinitivelyInvalidated);
}
