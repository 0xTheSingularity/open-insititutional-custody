//! EVM (ERC-20, dev single-key secp256k1 backend) signer acceptance tests.

mod common;

use common::*;
use oic_adapter_api::ChainAdapter;
use oic_adapter_evm::EvmAdapter;
use oic_canonical_encoding::sha256;
use oic_crypto_provider::*;
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_domain_types::*;
use oic_one_time_state_ledger::{InMemoryLedger, OP_CONSUME};
use oic_signer::*;
use std::sync::Arc;

fn code<T: std::fmt::Debug>(r: OicResult<T>) -> ErrorCode {
    r.expect_err("expected rejection").code
}

/// Verify and open_session both reject with `c`; nothing is consumed and no
/// session exists afterwards.
fn rejected(node: &Node, env: &AuthorizationEnvelope, m: &SigningMaterials, at: UnixSeconds, c: ErrorCode) {
    assert_eq!(code(node.signer.verify_envelope(env, m, at)), c);
    assert_eq!(code(node.signer.open_session(env, m, at)), c);
    assert!(node.nothing_consumed());
    assert_eq!(code(node.signer.abort(&env.body.signer_session_id)), ErrorCode::NotFound, "no session was opened");
}

fn payload_hash(env: &AuthorizationEnvelope) -> Hash32 {
    sha256(env.body.native_signing_payloads[0].message_or_digest.as_slice())
}

#[test]
fn happy_path_signs_after_release_and_evm_accepts_signature() {
    let c = evm_case(1);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let s = &env.body.signer_session_id;

    let v = c.node.signer.verify_envelope(&env, &c.setup.m, now()).unwrap();
    assert_eq!(v.envelope_body_hash, envelope_body_hash(&env.body).unwrap());
    assert!(v.decision.is_allow());
    assert_eq!(v.approvers, vec![CredentialId::unchecked("approver-1")]);
    assert_eq!(v.payload, env.body.native_signing_payloads[0]);
    assert_eq!(v.verified.decoded_operation_hash, env.body.decoded_operation_hash);

    assert_eq!(c.node.signer.open_session(&env, &c.setup.m, now()).unwrap(), ProtocolStep::Waiting);
    let msg = dev_release_msg(&c.node, &env);
    assert_eq!(c.node.signer.receive(s, &msg).unwrap(), ProtocolStep::Waiting, "share round withheld before release");
    assert!(c.node.nothing_consumed());
    assert_eq!(code(c.node.signer.aggregate(s, &[(pid(1), Bytes(vec![0; 65]))])), ErrorCode::Conflict, "no aggregation before release");

    let rr = c.world.release(&env);
    let steps = c.node.signer.release(s, &rr, now()).unwrap();
    let sig = match steps.as_slice() {
        [ProtocolStep::Complete(sig)] => sig.clone(),
        other => panic!("expected Complete, got {other:?}"),
    };
    let consumed: Vec<_> = c.node.ledger.snapshot().into_iter().filter(|r| r.consumed).collect();
    assert_eq!(consumed.len(), 1);
    assert_eq!(consumed[0].bound_message_hash, Some(payload_hash(&env)));
    assert_eq!(consumed[0].session_id.as_ref(), Some(s));
    assert_eq!(consumed[0].signer_generation, c.node.signer.generation());

    let agg = c.node.signer.aggregate(s, &[(pid(1), sig.bytes.clone())]).unwrap();
    assert_eq!(agg, sig);
    assert_eq!(code(c.node.signer.aggregate(s, &[(pid(9), sig.bytes.clone())])), ErrorCode::ScopeMismatch);
    let signed = EvmAdapter.assemble_signed_transaction(&c.setup.m.candidate, &c.key, &[sig]).expect("EVM adapter accepts the signature");
    EvmAdapter.verify_signed_transaction(&signed, &c.setup.m.candidate, &c.key).unwrap();

    // The session is spent: further input and release are refused.
    assert_eq!(code(c.node.signer.receive(s, &msg)), ErrorCode::Conflict);
    assert_eq!(code(c.node.signer.release(s, &rr, now())), ErrorCode::Conflict);
    assert_eq!(code(c.node.signer.open_session(&env, &c.setup.m, now())), ErrorCode::Conflict, "a session id opens once");

    let ev = c.node.events();
    assert!(matches!(ev[0], SignerEvent::Opened { generation: SignerGeneration(Epoch(1)) }));
    assert!(ev.contains(&SignerEvent::EnvelopeVerified { envelope_body_hash: v.envelope_body_hash, session: s.clone() }));
    assert!(ev.iter().any(|e| matches!(e, SignerEvent::SessionOpened { session, record_id: Some(_), .. } if session == s)));
    assert!(ev.contains(&SignerEvent::Released { session: s.clone(), release_commit_sequence: rr.body.commit_sequence }));
    assert!(ev.contains(&SignerEvent::ShareProduced { session: s.clone(), record_id: Some(consumed[0].record_id.clone()) }));
}

#[test]
fn a01_no_grants_when_rule_requires_one() {
    let c = evm_case(1);
    let mut env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    env.body.approval_grants.clear();
    rejected(&c.node, &env, &c.setup.m, now(), ErrorCode::ApprovalRequired);
    assert!(c.node.events().iter().any(|e| matches!(e, SignerEvent::EnvelopeRejected { code: ErrorCode::ApprovalRequired, .. })));
}

#[test]
fn a02_altered_native_bytes_with_rehashed_body_fail_receipt_signature() {
    let c = evm_case(0);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    // Coordinator rebuilds the transaction with another nonce after approval,
    // updates every body field consistently, and keeps the old receipt.
    let mut m2 = c.setup.m.clone();
    m2.evidence = evm_evidence(&evm_sender(&m2.wallet), EVM_NONCE + 1);
    m2.candidate = EvmAdapter.build_candidate(&build_ctx(&c.setup, &m2)).unwrap();
    assert_ne!(m2.candidate.native_unsigned_bytes, c.setup.m.candidate.native_unsigned_bytes);
    let verified2 = c.setup.verify_for(&m2);
    let body2 = c.setup.body_for(&m2, &verified2, vec![], "sess-1", vec![pid(1)], DEADLINE);
    let forged = AuthorizationEnvelope { body: body2.clone(), authorization_state_receipt: env.authorization_state_receipt.clone() };
    rejected(&c.node, &forged, &m2, now(), ErrorCode::InvalidSignature);

    // Rewriting the receipt's envelope hash breaks the authority signature.
    let mut forged2 = forged.clone();
    forged2.authorization_state_receipt.body.envelope_body_hash = envelope_body_hash(&body2).unwrap();
    rejected(&c.node, &forged2, &m2, now(), ErrorCode::InvalidSignature);

    // Swapping only the envelope bytes (candidate unchanged) is caught before.
    let mut swapped = env.clone();
    swapped.body.native_unsigned_bytes = m2.candidate.native_unsigned_bytes.clone();
    rejected(&c.node, &swapped, &c.setup.m, now(), ErrorCode::UnverifiableTransaction);
    let mut payloads = env.clone();
    payloads.body.native_signing_payloads = m2.candidate.signing_payloads.clone();
    rejected(&c.node, &payloads, &c.setup.m, now(), ErrorCode::UnverifiableTransaction);
}

#[test]
fn a02_genuinely_reserved_envelope_with_different_recipient_is_rejected_by_adapter() {
    let c = evm_case(0);
    // Compromised coordinator builds a transfer to its own address and gets the
    // authority (which does not decode bytes) to reserve that exact body.
    let mut attacker = c.setup.m.clone();
    attacker.destination.address = Bytes(vec![0xaa; 20]);
    attacker.candidate = EvmAdapter.build_candidate(&build_ctx(&c.setup, &attacker)).unwrap();
    let verified = c.setup.verify_for(&attacker);
    let body = c.setup.body_for(&attacker, &verified, vec![], "sess-evil", vec![pid(1)], DEADLINE);
    let env = c.setup.reserve(&c.world, body, &verified);
    // The signer is given the registered destination; the decoded recipient differs.
    let mut m = attacker.clone();
    m.destination = c.setup.m.destination.clone();
    rejected(&c.node, &env, &m, now(), ErrorCode::ScopeMismatch);
}

/// Zero-approval automated rule: the coordinator hands the signer a
/// destination record with the registered id/version but its own address,
/// consistent with the bytes it built and the envelope it reserved. Without
/// the admin-quorum signature over the destination this would verify.
#[test]
fn a02_substituted_destination_record_fails_registry_quorum() {
    let c = evm_case(0);
    let mut attacker = c.setup.m.clone();
    attacker.destination.address = Bytes(vec![0xaa; 20]);
    attacker.destination.address_display = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    attacker.candidate = EvmAdapter.build_candidate(&build_ctx(&c.setup, &attacker)).unwrap();
    let verified = c.setup.verify_for(&attacker);
    let body = c.setup.body_for(&attacker, &verified, vec![], "sess-evil-2", vec![pid(1)], DEADLINE);
    let env = c.setup.reserve(&c.world, body, &verified);
    // Stale signatures from the registered record do not cover the new address.
    rejected(&c.node, &env, &attacker, now(), ErrorCode::InvalidSignature);
    // Signed by only one administrator: still below quorum.
    let mut one_admin = attacker.clone();
    let h = oic_policy_kernel::destination_hash(&one_admin.destination).unwrap();
    one_admin.destination.administrative_signatures = c.world.admin_quorum_signatures(h)[..1].to_vec();
    rejected(&c.node, &env, &one_admin, now(), ErrorCode::InvalidSignature);
    // Registered destination presented instead: hash bound in the envelope differs.
    let mut registered = attacker.clone();
    registered.destination = c.setup.m.destination.clone();
    rejected(&c.node, &env, &registered, now(), ErrorCode::ScopeMismatch);
}

#[test]
fn a03_envelope_replayed_for_another_vault_network_key_or_environment() {
    let c = evm_case(1);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);

    let mut other_vault = c.setup.m.clone();
    other_vault.vault.vault_id = VaultId::unchecked("vault-2");
    rejected(&c.node, &env, &other_vault, now(), ErrorCode::ScopeMismatch);
    let mut other_wallet = c.setup.m.clone();
    other_wallet.wallet.vault_id = VaultId::unchecked("vault-2");
    rejected(&c.node, &env, &other_wallet, now(), ErrorCode::ScopeMismatch);

    // A signer enrolled for a different network (chain id) does not recognise the profile hash.
    let mut mainnet = evm_profile();
    mainnet.network_binding = oic_adapter_evm::network_binding_for_chain_id(1);
    let other_net = open_node(
        &pid(1),
        c.world.trust_roots(vec![mainnet]),
        c.setup.adapter.clone(),
        c.dev.clone(),
        Arc::new(InMemoryLedger::new()),
        Arc::new(InMemoryGenerationStore::new()),
    );
    other_net.signer.load_key(&c.key, &c.sealed).unwrap();
    rejected(&other_net, &env, &c.setup.m, now(), ErrorCode::ScopeMismatch);

    // Another key: not loaded here, or a different descriptor than the envelope names.
    let no_key = open_node(
        &pid(1),
        c.world.trust_roots(vec![evm_profile()]),
        c.setup.adapter.clone(),
        c.dev.clone(),
        Arc::new(InMemoryLedger::new()),
        Arc::new(InMemoryGenerationStore::new()),
    );
    rejected(&no_key, &env, &c.setup.m, now(), ErrorCode::ScopeMismatch);
    let mut other_key = c.setup.m.clone();
    other_key.key.key_id = KeyId::unchecked("key-evm-2");
    rejected(&c.node, &env, &other_key, now(), ErrorCode::ScopeMismatch);
    let mut forged_pub = c.setup.m.clone();
    forged_pub.key.public_key.bytes.0[5] ^= 1;
    rejected(&c.node, &env, &forged_pub, now(), ErrorCode::ScopeMismatch);

    // A signer of another environment.
    let mut adapters: std::collections::BTreeMap<AdapterId, Arc<dyn ChainAdapter>> = Default::default();
    adapters.insert(AdapterId::unchecked("evm"), c.setup.adapter.clone());
    let testnet = Signer::open(
        SignerIdentity { participant_id: pid(1), institution_id: inst(), environment_id: EnvironmentId::unchecked("testnet") },
        c.world.trust_roots(vec![evm_profile()]),
        adapters,
        c.dev.clone(),
        Arc::new(InMemoryLedger::new()),
        Arc::new(InMemoryGenerationStore::new()),
    )
    .unwrap();
    assert_eq!(code(testnet.verify_envelope(&env, &c.setup.m, now())), ErrorCode::ScopeMismatch);
    assert_eq!(code(testnet.load_key(&c.key, &c.sealed)), ErrorCode::ScopeMismatch);
}

#[test]
fn a04_same_symbol_and_decimals_but_different_contract_is_rejected() {
    let c = evm_case(1);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let mut m = c.setup.m.clone();
    m.asset = erc20_asset([0xc1; 20]);
    assert_eq!((m.asset.symbol.as_str(), m.asset.decimals, &m.asset.asset_id), ("USDC", 6, &c.setup.m.asset.asset_id));
    rejected(&c.node, &env, &m, now(), ErrorCode::ScopeMismatch);
}

#[test]
fn a11_ledger_consume_failure_yields_no_share_and_aborts_session() {
    let ledger = Arc::new(InMemoryLedger::new().with_fault_hook(Box::new(|op, _| {
        if op == OP_CONSUME {
            Err(OicError::internal("injected crash before consume commits"))
        } else {
            Ok(())
        }
    })));
    let c = evm_case_with(1, ledger, |d| d);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let s = &env.body.signer_session_id;
    c.node.signer.open_session(&env, &c.setup.m, now()).unwrap();
    c.node.signer.receive(s, &dev_release_msg(&c.node, &env)).unwrap();
    let rr = c.world.release(&env);
    assert_eq!(code(c.node.signer.release(s, &rr, now())), ErrorCode::Internal);
    assert!(c.node.nothing_consumed());
    assert_eq!(code(c.node.signer.receive(s, &dev_release_msg(&c.node, &env))), ErrorCode::Conflict);
    assert_eq!(code(c.node.signer.aggregate(s, &[(pid(1), Bytes(vec![0; 65]))])), ErrorCode::Conflict);
    assert_eq!(code(c.node.signer.open_session(&env, &c.setup.m, now())), ErrorCode::Conflict, "retry needs a fresh session");
    assert!(c.node.events().iter().any(|e| matches!(e, SignerEvent::Aborted { session, .. } if session == s)));
    assert!(!c.node.events().iter().any(|e| matches!(e, SignerEvent::ShareProduced { .. })));
}

/// A backend that returns a signature without durably consuming its record
/// (it hands the backend a ledger whose `consume` is a no-op).
struct NonConsumingProvider(Arc<DevSingleKeyProvider>);

struct NoopConsume<'a>(&'a dyn OneTimeStateLedger);

impl OneTimeStateLedger for NoopConsume<'_> {
    fn allocate(&self, k: &KeyId, e: Epoch, g: Epoch, s: &SigningSessionId) -> OicResult<OneTimeStateRecord> {
        self.0.allocate(k, e, g, s)
    }
    fn consume(&self, _record_id: &str, _message_hash: Hash32) -> OicResult<()> {
        Ok(())
    }
    fn get(&self, record_id: &str) -> OicResult<Option<OneTimeStateRecord>> {
        self.0.get(record_id)
    }
    fn tombstone_generations_before(&self, k: &KeyId, g: Epoch) -> OicResult<u64> {
        self.0.tombstone_generations_before(k, g)
    }
}

impl CryptoProvider for NonConsumingProvider {
    fn capabilities(&self) -> BackendDescriptor {
        self.0.capabilities()
    }
    fn generate_distributed_key(&self, c: &KeygenCeremony) -> OicResult<DistributedKeyResult> {
        self.0.generate_distributed_key(c)
    }
    fn load_share(&self, d: &KeyDescriptor, p: &ParticipantId, s: &Bytes) -> OicResult<()> {
        self.0.load_share(d, p, s)
    }
    fn start_signing_session(
        &self,
        s: &SigningSessionId,
        k: &KeyId,
        p: &NativeSigningPayload,
        ps: &[ParticipantId],
        l: &dyn OneTimeStateLedger,
        g: Epoch,
    ) -> OicResult<ProtocolStep> {
        self.0.start_signing_session(s, k, p, ps, l, g)
    }
    fn advance_protocol(&self, s: &SigningSessionId, m: &PeerMessage, l: &dyn OneTimeStateLedger) -> OicResult<ProtocolStep> {
        self.0.advance_protocol(s, m, &NoopConsume(l))
    }
    fn aggregate(&self, s: &SigningSessionId, sh: &[(ParticipantId, Bytes)]) -> OicResult<SignatureBytes> {
        self.0.aggregate(s, sh)
    }
    fn verify_result(&self, k: &PublicKey, p: &NativeSigningPayload, s: &SignatureBytes) -> OicResult<()> {
        self.0.verify_result(k, p, s)
    }
}

#[test]
fn a11_output_without_consumed_record_is_withheld_and_session_aborted() {
    let c = evm_case_with(1, Arc::new(InMemoryLedger::new()), |d| Arc::new(NonConsumingProvider(d)));
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let s = &env.body.signer_session_id;
    c.node.signer.open_session(&env, &c.setup.m, now()).unwrap();
    c.node.signer.receive(s, &dev_release_msg(&c.node, &env)).unwrap();
    let rr = c.world.release(&env);
    assert_eq!(code(c.node.signer.release(s, &rr, now())), ErrorCode::Internal);
    // The record was never consumed for the payload; the abort burned it with a sentinel.
    let recs = c.node.ledger.snapshot();
    assert_eq!(recs.len(), 1);
    assert!(recs[0].consumed);
    assert_ne!(recs[0].bound_message_hash, Some(payload_hash(&env)));
    assert!(!c.node.events().iter().any(|e| matches!(e, SignerEvent::ShareProduced { .. })));
    assert_eq!(code(c.node.signer.aggregate(s, &[(pid(1), Bytes(vec![0; 65]))])), ErrorCode::Conflict);
}

#[test]
fn a14_older_policy_epoch_than_body_or_receipt_is_stale() {
    let mut c = evm_case(1);
    let old_policy = c.setup.m.policy.clone();
    let new_policy = c.world.sign_policy(policy(2, old_policy.rules.clone()));
    c.world.authority.set_policy(&new_policy).unwrap();
    c.setup.m.policy = new_policy;
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    c.node.signer.verify_envelope(&env, &c.setup.m, now()).expect("current epoch verifies");

    let mut stale = c.setup.m.clone();
    stale.policy = old_policy;
    rejected(&c.node, &env, &stale, now(), ErrorCode::StalePolicy);

    // A genuine authority signature over a receipt naming a newer policy epoch.
    let mut rb = env.authorization_state_receipt.body.clone();
    rb.policy_epoch = Epoch(3);
    let newer = AuthorizationEnvelope { body: env.body.clone(), authorization_state_receipt: c.world.craft_receipt(rb) };
    rejected(&c.node, &newer, &c.setup.m, now(), ErrorCode::StalePolicy);
}

#[test]
fn a17_release_gating_rejects_wrong_receipts_and_never_feeds_buffer() {
    let c = evm_case(1);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let s = &env.body.signer_session_id;
    c.node.signer.open_session(&env, &c.setup.m, now()).unwrap();
    c.node.signer.receive(s, &dev_release_msg(&c.node, &env)).unwrap();

    // Reserved receipt presented as a release.
    assert_eq!(code(c.node.signer.release(s, &env.authorization_state_receipt, now())), ErrorCode::ScopeMismatch);
    let release_body = |f: &dyn Fn(&mut AuthorityReceiptBody)| {
        let mut b = env.authorization_state_receipt.body.clone();
        b.kind = ReceiptKind::Release;
        b.issued_at = now();
        b.expires_at = UnixSeconds(NOW + 60);
        f(&mut b);
        c.world.craft_receipt(b)
    };
    // Genuinely signed release receipts for another session / envelope / freeze epoch / reservation.
    let other_session = release_body(&|b| b.signer_session_id = sid("sess-other"));
    assert_eq!(code(c.node.signer.release(s, &other_session, now())), ErrorCode::ScopeMismatch);
    let other_env = release_body(&|b| b.envelope_body_hash = Hash32([9; 32]));
    assert_eq!(code(c.node.signer.release(s, &other_env, now())), ErrorCode::InvalidSignature);
    let frozen = release_body(&|b| b.freeze_epoch = Epoch(b.freeze_epoch.0 + 1));
    assert_eq!(code(c.node.signer.release(s, &frozen, now())), ErrorCode::Frozen);
    let other_res = release_body(&|b| b.reservation_version = 2);
    assert_eq!(code(c.node.signer.release(s, &other_res, now())), ErrorCode::ScopeMismatch);
    let future = release_body(&|b| b.issued_at = UnixSeconds(NOW + 31));
    assert_eq!(code(c.node.signer.release(s, &future, now())), ErrorCode::ScopeMismatch);
    let mut forged_sig = release_body(&|_| {});
    forged_sig.signature.bytes.0[0] ^= 1;
    assert_eq!(code(c.node.signer.release(s, &forged_sig, now())), ErrorCode::InvalidSignature);

    // Genuine release receipt, but expired by the time it is presented.
    let rr = c.world.release(&env);
    assert_eq!(code(c.node.signer.release(s, &rr, UnixSeconds(rr.body.expires_at.0))), ErrorCode::ScopeMismatch);
    assert!(c.node.nothing_consumed(), "buffered round was never fed");
    assert!(!c.node.events().iter().any(|e| matches!(e, SignerEvent::Released { .. })));

    // Within skew of a slightly-ahead authority clock, the genuine receipt releases the buffered message.
    let steps = c.node.signer.release(s, &rr, UnixSeconds(NOW - 10)).unwrap();
    assert!(matches!(steps.as_slice(), [ProtocolStep::Complete(_)]));
}

#[test]
fn expired_grant_is_policy_denied() {
    let c = evm_case(1);
    let verified = c.setup.verify();
    let grant = c.setup.exact_grant(&c.world, &c.setup.m, &verified, 0, NOW - 1);
    let body = c.setup.body_for(&c.setup.m, &verified, vec![grant], "sess-1", vec![pid(1)], DEADLINE);
    let env = c.setup.reserve(&c.world, body, &verified);
    rejected(&c.node, &env, &c.setup.m, now(), ErrorCode::PolicyDenied);
}

#[test]
fn grant_bound_to_another_candidate_preview_is_rejected() {
    let c = evm_case(1);
    let verified = c.setup.verify();
    let mut other = verified.clone();
    other.decoded_operation_hash = Hash32([3; 32]);
    let grant = c.setup.exact_grant(&c.world, &c.setup.m, &other, 0, NOW + 3600);
    let body = c.setup.body_for(&c.setup.m, &verified, vec![grant], "sess-1", vec![pid(1)], DEADLINE);
    let env = c.setup.reserve(&c.world, body, &verified);
    rejected(&c.node, &env, &c.setup.m, now(), ErrorCode::ScopeMismatch);
}

#[test]
fn expired_reserved_receipt_is_rejected() {
    let c = evm_case(1);
    let env = c.setup.authorize_with_deadline(&c.world, "sess-1", vec![pid(1)], NOW + 5);
    c.node.signer.verify_envelope(&env, &c.setup.m, UnixSeconds(NOW + 4)).expect("valid before expiry");
    rejected(&c.node, &env, &c.setup.m, UnixSeconds(NOW + 6), ErrorCode::ScopeMismatch);
}

#[test]
fn wrong_authority_key_is_invalid_signature() {
    let c = evm_case(1);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let mut roots = c.world.trust_roots(vec![evm_profile()]);
    roots.authority_pubkey = ed25519_dalek::SigningKey::from_bytes(&[43; 32]).verifying_key();
    let node = open_node(&pid(1), roots, c.setup.adapter.clone(), c.dev.clone(), Arc::new(InMemoryLedger::new()), Arc::new(InMemoryGenerationStore::new()));
    node.signer.load_key(&c.key, &c.sealed).unwrap();
    rejected(&node, &env, &c.setup.m, now(), ErrorCode::InvalidSignature);

    let mut roots = c.world.trust_roots(vec![evm_profile()]);
    roots.authority_key_id = KeyId::unchecked("authority-key-2");
    let node = open_node(&pid(1), roots, c.setup.adapter.clone(), c.dev.clone(), Arc::new(InMemoryLedger::new()), Arc::new(InMemoryGenerationStore::new()));
    node.signer.load_key(&c.key, &c.sealed).unwrap();
    rejected(&node, &env, &c.setup.m, now(), ErrorCode::InvalidSignature);
}

#[test]
fn unknown_verifier_build_hash_is_unsupported() {
    let c = evm_case(1);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let mut roots = c.world.trust_roots(vec![evm_profile()]);
    roots.accepted_verifier_builds.insert(AdapterId::unchecked("evm"), vec![Hash32([1; 32])]);
    let node = open_node(&pid(1), roots, c.setup.adapter.clone(), c.dev.clone(), Arc::new(InMemoryLedger::new()), Arc::new(InMemoryGenerationStore::new()));
    node.signer.load_key(&c.key, &c.sealed).unwrap();
    rejected(&node, &env, &c.setup.m, now(), ErrorCode::UnsupportedCapability);
}

#[test]
fn evidence_mismatch_and_staleness_are_rejected() {
    let c = evm_case(1);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let mut m = c.setup.m.clone();
    m.evidence.sources.push(EvidenceSourceId::unchecked("other-node"));
    rejected(&c.node, &env, &m, now(), ErrorCode::StaleEvidence);
    // Evidence older than its staleness window (observed T0, 60 s).
    rejected(&c.node, &env, &c.setup.m, UnixSeconds(T0 + 61), ErrorCode::StaleEvidence);
}

#[test]
fn single_operation_over_rolling_limit_is_denied_locally() {
    let mut c = evm_case(0);
    let mut r = rule(&c.setup.m.asset.asset_id, 0);
    r.rolling_limits[0].max_outflow_base_units = Amount(500_000);
    let p2 = c.world.sign_policy(policy(2, vec![r]));
    c.world.authority.set_policy(&p2).unwrap();
    c.setup.m.policy = p2;
    let verified = c.setup.verify();
    let body = c.setup.body_for(&c.setup.m, &verified, vec![], "sess-1", vec![pid(1)], DEADLINE);
    // The authority would refuse to reserve this; the signer refuses even with a receipt.
    let mut rb = AuthorityReceiptBody {
        kind: ReceiptKind::Reserved,
        institution_id: inst(),
        environment_id: env_id(),
        authority_epoch: Epoch(1),
        reservation_id: body.budget_reservation_id.clone(),
        reservation_version: 1,
        candidate_id: body.candidate_id.clone(),
        candidate_revision: body.candidate_revision,
        envelope_body_hash: envelope_body_hash(&body).unwrap(),
        signer_session_id: body.signer_session_id.clone(),
        policy_epoch: body.policy_epoch,
        freeze_epoch: Epoch(0),
        issued_at: now(),
        expires_at: UnixSeconds(DEADLINE),
        commit_sequence: 1,
    };
    let env = AuthorizationEnvelope { body: body.clone(), authorization_state_receipt: c.world.craft_receipt(rb.clone()) };
    rejected(&c.node, &env, &c.setup.m, now(), ErrorCode::PolicyDenied);
    // Control: with a limit that fits, the same crafted-but-genuinely-signed receipt verifies.
    let mut r = rule(&c.setup.m.asset.asset_id, 0);
    r.rolling_limits[0].max_outflow_base_units = Amount(1_000_000);
    let p3 = c.world.sign_policy(policy(3, vec![r]));
    c.setup.m.policy = p3;
    let body = c.setup.body_for(&c.setup.m, &verified, vec![], "sess-1", vec![pid(1)], DEADLINE);
    rb.envelope_body_hash = envelope_body_hash(&body).unwrap();
    rb.policy_epoch = Epoch(3);
    let env = AuthorizationEnvelope { body, authorization_state_receipt: c.world.craft_receipt(rb) };
    c.node.signer.verify_envelope(&env, &c.setup.m, now()).unwrap();
}

#[test]
fn abort_burns_record_and_is_final() {
    let c = evm_case(1);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let s = &env.body.signer_session_id;
    c.node.signer.open_session(&env, &c.setup.m, now()).unwrap();
    c.node.signer.receive(s, &dev_release_msg(&c.node, &env)).unwrap();
    c.node.signer.abort(s).unwrap();
    c.node.signer.abort(s).unwrap();
    assert_eq!(code(c.node.signer.abort(&sid("nope"))), ErrorCode::NotFound);
    let rr = c.world.release(&env);
    assert_eq!(code(c.node.signer.release(s, &rr, now())), ErrorCode::Conflict);
    assert_eq!(code(c.node.signer.receive(s, &dev_release_msg(&c.node, &env))), ErrorCode::Conflict);
    assert_eq!(code(c.node.signer.open_session(&env, &c.setup.m, now())), ErrorCode::Conflict);
    let recs = c.node.ledger.snapshot();
    assert_eq!(recs.len(), 1);
    assert!(recs[0].consumed && recs[0].bound_message_hash != Some(payload_hash(&env)), "record burned, never used for the payload");
    assert!(c.node.events().contains(&SignerEvent::Aborted { session: s.clone(), reason: "aborted by caller".into() }));
}

#[test]
fn receive_validates_message_scope() {
    let c = evm_case(1);
    let env = c.setup.authorize(&c.world, "sess-1", vec![pid(1)]);
    let s = &env.body.signer_session_id;
    c.node.signer.open_session(&env, &c.setup.m, now()).unwrap();
    let good = dev_release_msg(&c.node, &env);
    let bad = |f: &dyn Fn(&mut PeerMessage)| {
        let mut m = good.clone();
        f(&mut m);
        m
    };
    assert_eq!(code(c.node.signer.receive(&sid("unknown"), &good)), ErrorCode::NotFound);
    assert_eq!(code(c.node.signer.receive(s, &bad(&|m| m.session_id = sid("other")))), ErrorCode::ScopeMismatch);
    assert_eq!(code(c.node.signer.receive(s, &bad(&|m| m.key_epoch = Epoch(2)))), ErrorCode::ScopeMismatch);
    assert_eq!(code(c.node.signer.receive(s, &bad(&|m| m.key_id = KeyId::unchecked("k2")))), ErrorCode::ScopeMismatch);
    assert_eq!(code(c.node.signer.receive(s, &bad(&|m| m.from = pid(9)))), ErrorCode::ScopeMismatch);
    assert_eq!(code(c.node.signer.receive(s, &bad(&|m| m.to = Some(pid(2))))), ErrorCode::ScopeMismatch);
    assert_eq!(code(c.node.signer.receive(s, &bad(&|m| m.from_generation = Epoch(0)))), ErrorCode::ScopeMismatch);
    // Buffer is bounded.
    for _ in 0..MAX_BUFFERED_MESSAGES {
        assert_eq!(c.node.signer.receive(s, &good).unwrap(), ProtocolStep::Waiting);
    }
    assert_eq!(code(c.node.signer.receive(s, &good)), ErrorCode::InvalidRequest);
    assert!(c.node.nothing_consumed());
}

#[test]
fn signer_set_and_payload_scope_checks() {
    let c = evm_case(1);
    // Participant set without this signer.
    let verified = c.setup.verify();
    let grants = c.setup.grants_for(&c.world, &c.setup.m, &verified);
    let body = c.setup.body_for(&c.setup.m, &verified, grants, "sess-x", vec![pid(2)], DEADLINE);
    let env = c.setup.reserve(&c.world, body, &verified);
    rejected(&c.node, &env, &c.setup.m, now(), ErrorCode::ScopeMismatch);
    // Inactive wallet.
    let env = {
        let mut e = env.clone();
        e.body.participant_set = vec![pid(1)];
        e
    };
    let mut m = c.setup.m.clone();
    m.wallet.active = false;
    rejected(&c.node, &env, &m, now(), ErrorCode::ScopeMismatch);
}
