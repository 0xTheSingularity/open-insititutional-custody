//! Solana (native SOL, FROST(Ed25519) 2-of-3 across three signers) acceptance tests.

mod common;

use common::*;
use oic_adapter_api::ChainAdapter;
use oic_adapter_solana::SolanaAdapter;
use oic_approval_verifier::sign_grant;
use oic_crypto_provider::*;
use oic_crypto_provider_frost_ed25519::FrostEd25519Provider;
use oic_domain_types::*;
use oic_policy_kernel::intent_hash;
use oic_signer::*;
use std::sync::Arc;

fn code<T: std::fmt::Debug>(r: OicResult<T>) -> ErrorCode {
    r.expect_err("expected rejection").code
}

#[test]
fn frost_2_of_3_happy_path_produces_solana_accepted_signature() {
    let c = sol_case(1);
    let (n1, n2, n3) = (&c.nodes[0], &c.nodes[1], &c.nodes[2]);
    let env = c.setup.authorize(&c.world, "sol-1", vec![pid(1), pid(2)]);
    let s = &env.body.signer_session_id;

    // The third key holder is not in this signing set and refuses to take part.
    assert_eq!(code(n3.signer.open_session(&env, &c.setup.m, now())), ErrorCode::ScopeMismatch);

    frost_until_release(&c, &env, &[n1, n2]);
    assert!(n1.nothing_consumed() && n2.nothing_consumed(), "no share before release");

    let rr = c.world.release(&env);
    let z1 = expect_share(n1.signer.release(s, &rr, now()).unwrap());
    let z2 = expect_share(n2.signer.release(s, &rr, now()).unwrap());
    for n in [n1, n2] {
        let consumed: Vec<_> = n.ledger.snapshot().into_iter().filter(|r| r.consumed).collect();
        assert_eq!(consumed.len(), 1);
        assert!(consumed[0].bound_message_hash.is_some());
        assert!(n.events().iter().any(|e| matches!(e, SignerEvent::ShareProduced { session, .. } if session == s)));
    }
    assert!(n3.nothing_consumed());

    let sig = n1.signer.aggregate(s, &[(pid(1), z1.clone()), (pid(2), z2.clone())]).unwrap();
    assert_eq!(sig.scheme, SchemeId::Ed25519Pure);
    let signed = SolanaAdapter.assemble_signed_transaction(&c.setup.m.candidate, &c.key, std::slice::from_ref(&sig)).expect("Solana adapter accepts");
    SolanaAdapter.verify_signed_transaction(&signed, &c.setup.m.candidate, &c.key).unwrap();
    // Either signing participant can aggregate the public shares.
    assert_eq!(n2.signer.aggregate(s, &[(pid(1), z1), (pid(2), z2)]).unwrap().bytes.len(), 64);
}

#[test]
fn a06_bogus_share_from_malicious_participant_yields_no_signature() {
    let c = sol_case(1);
    let (n1, n2) = (&c.nodes[0], &c.nodes[1]);
    let env = c.setup.authorize(&c.world, "sol-1", vec![pid(1), pid(2)]);
    let s = &env.body.signer_session_id;
    frost_until_release(&c, &env, &[n1, n2]);
    let rr = c.world.release(&env);
    let z1 = expect_share(n1.signer.release(s, &rr, now()).unwrap());
    let z2 = expect_share(n2.signer.release(s, &rr, now()).unwrap());
    // Participant 2 substitutes a well-formed but wrong share.
    assert_eq!(code(n1.signer.aggregate(s, &[(pid(1), z1.clone()), (pid(2), z1.clone())])), ErrorCode::InvalidSignature);
    let mut flipped = z2.clone();
    flipped.0[0] ^= 1;
    assert_eq!(code(n1.signer.aggregate(s, &[(pid(1), z1.clone()), (pid(2), flipped)])), ErrorCode::InvalidSignature);
    // Missing share: no signature.
    assert!(n1.signer.aggregate(s, &[(pid(1), z1.clone())]).is_err());
    // The honest shares still aggregate.
    n1.signer.aggregate(s, &[(pid(1), z1), (pid(2), z2)]).unwrap();
}

#[test]
fn a12_stale_clone_is_fenced_by_generation_and_ledger() {
    let c = sol_case(1);
    let (n1, n2) = (&c.nodes[0], &c.nodes[1]);
    let env = c.setup.authorize(&c.world, "sol-1", vec![pid(1), pid(2)]);
    let s = &env.body.signer_session_id;
    let pkg = frost_until_release(&c, &env, &[n1, n2]);
    let old_gen = n1.signer.generation();
    let old_record = n1.ledger.snapshot().into_iter().find(|r| r.session_id.as_ref() == Some(s)).unwrap();

    // Signer 1's image is cloned/restored and opened over the same durable
    // generation store and ledger: it starts a new generation and tombstones
    // the old generation's one-time state when it loads the key.
    let provider = Arc::new(FrostEd25519Provider::with_os_rng(pid(1), sealing_key(1)).unwrap());
    let clone = open_node(&pid(1), c.world.trust_roots_for(vec![sol_profile()], &c.setup.m), c.setup.adapter.clone(), provider, n1.ledger.clone(), n1.store.clone());
    assert_eq!(clone.signer.generation(), old_gen.next());
    let sealed = &c.sealed.iter().find(|(p, _)| *p == pid(1)).unwrap().1;
    clone.signer.load_key(&c.key, sealed).unwrap();
    assert!(n1.ledger.is_tombstoned(&old_record.record_id).unwrap());

    // Peers learn the new generation and reject the stale instance's messages.
    n2.signer.set_peer_generation(&pid(1), clone.signer.generation()).unwrap();
    let stale_msg = frost_round2(&env, &pkg, n2, n1);
    assert_eq!(stale_msg.from_generation, old_gen);
    assert_eq!(code(n2.signer.receive(s, &stale_msg)), ErrorCode::ScopeMismatch);
    let mut current = stale_msg.clone();
    current.from_generation = clone.signer.generation();
    current.sequence = 3;
    assert_eq!(n2.signer.receive(s, &current).unwrap(), ProtocolStep::Waiting, "current generation accepted (buffered)");

    // The stale instance cannot produce a share: its one-time record is tombstoned.
    let rr = c.world.release(&env);
    assert_eq!(code(n1.signer.release(s, &rr, now())), ErrorCode::ResourceConflict, "tombstoned record cannot be consumed");
    let rec = n1.ledger.snapshot().into_iter().find(|r| r.record_id == old_record.record_id).unwrap();
    assert_eq!(rec.bound_message_hash, None, "never consumed for any message");
    assert!(n1.events().iter().any(|e| matches!(e, SignerEvent::Aborted { session, .. } if session == s)));
    assert!(!n1.events().iter().any(|e| matches!(e, SignerEvent::ShareProduced { .. })));
    assert_eq!(code(n1.signer.aggregate(s, &[])), ErrorCode::Conflict);
}

#[test]
fn peer_generation_is_monotonic() {
    let c = sol_case(1);
    let n1 = &c.nodes[0];
    n1.signer.set_peer_generation(&pid(2), Epoch(5)).unwrap();
    n1.signer.set_peer_generation(&pid(2), Epoch(5)).unwrap();
    assert_eq!(code(n1.signer.set_peer_generation(&pid(2), Epoch(4))), ErrorCode::Conflict);
}

#[test]
fn round2_from_outside_the_signing_set_is_rejected() {
    let c = sol_case(1);
    let (n1, n2, n3) = (&c.nodes[0], &c.nodes[1], &c.nodes[2]);
    let env = c.setup.authorize(&c.world, "sol-1", vec![pid(1), pid(2)]);
    let pkg = frost_until_release(&c, &env, &[n1, n2]);
    let msg = frost_round2(&env, &pkg, n1, n3);
    assert_eq!(code(n1.signer.receive(&env.body.signer_session_id, &msg)), ErrorCode::ScopeMismatch);
}

fn template(c: &SolCase, dest_address: Bytes) -> BoundedTransferTemplate {
    let decoded_fee = c.setup.verify().decoded.max_native_fee();
    BoundedTransferTemplate {
        chain_wallet_id: c.setup.m.wallet.chain_wallet_id.clone(),
        network_id: NetworkId::unchecked("solana-devnet"),
        asset_id: c.setup.m.asset.asset_id.clone(),
        amount_base_units: Amount(1_000_000),
        destination_id: c.setup.m.destination.destination_id.clone(),
        destination_version: c.setup.m.destination.version,
        destination_address: dest_address,
        max_native_fee_base_units: decoded_fee,
        maximum_successful_payments: 1,
        fillable: vec![FillableField::SolanaRecentBlockhash],
    }
}

fn bounded_grant(c: &SolCase, t: BoundedTransferTemplate) -> ApprovalGrant {
    let (cred, sk, role) = &c.world.approvers[0];
    sign_grant(
        sk,
        ApprovalGrantBody {
            grant_id: GrantId::unchecked("grant-bounded"),
            institution_id: inst(),
            environment_id: env_id(),
            vault_id: vault_id(),
            intent_id: c.setup.m.intent.intent_id.clone(),
            intent_hash: intent_hash(&c.setup.m.intent).unwrap(),
            policy_id: policy_id(),
            policy_epoch: c.setup.m.policy.policy_epoch,
            scope: GrantScope::BoundedDirectTransfer { template: t },
            approver_credential_id: cred.clone(),
            approver_role: *role,
            issued_at: UnixSeconds(T0),
            expires_at: UnixSeconds(NOW + 3600),
        },
    )
    .unwrap()
}

#[test]
fn bounded_template_grant_is_verified_against_the_template() {
    let c = sol_case_mode(1, ApprovalMode::BoundedDirectTransfer);
    let n1 = &c.nodes[0];
    let verified = c.setup.verify();
    let good = bounded_grant(&c, template(&c, c.setup.m.destination.address.clone()));
    let body = c.setup.body_for(&c.setup.m, &verified, vec![good], "sol-b", vec![pid(1), pid(2)], DEADLINE);
    let env = c.setup.reserve(&c.world, body, &verified);
    let v = n1.signer.verify_envelope(&env, &c.setup.m, now()).unwrap();
    assert!(v.decision.is_allow());
    assert_eq!(v.approvers, vec![CredentialId::unchecked("approver-1")]);

    // A template naming another destination address is refused.
    let bad = bounded_grant(&c, template(&c, Bytes(vec![0x99; 32])));
    let mut env2 = env.clone();
    env2.body.approval_grants = vec![bad];
    assert_eq!(code(n1.signer.verify_envelope(&env2, &c.setup.m, now())), ErrorCode::ScopeMismatch);
    // A template without the blockhash fill permission is refused by the adapter.
    let mut t = template(&c, c.setup.m.destination.address.clone());
    t.fillable.clear();
    let mut env3 = env.clone();
    env3.body.approval_grants = vec![bounded_grant(&c, t)];
    assert_eq!(code(n1.signer.verify_envelope(&env3, &c.setup.m, now())), ErrorCode::UnverifiableTransaction);
    assert!(n1.nothing_consumed());
}
