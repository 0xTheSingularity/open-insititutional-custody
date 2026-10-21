use super::*;

fn roster() -> SignedRoster {
    let mut b = body();
    // Dedicated verifiers can share a signer domain without holding shares.
    b.nodes[7].domain_id = b.nodes[0].domain_id.clone();
    b.committees[2].members = [0, 1, 2, 7].map(|i| NodeId::unchecked(format!("node-{i}"))).into();
    b.committees[2].threshold = 2;
    let roster = sign(b);
    validate(&roster, None).unwrap();
    roster
}

fn inputs(roster: &SignedRoster) -> VerificationInputs {
    VerificationInputs {
        institution_id: roster.body.institution_id.clone(),
        environment_id: roster.body.environment_id.clone(),
        roster_epoch: roster.body.roster_epoch,
        roster_hash: roster_hash(&roster.body).unwrap(),
        adapter_id: AdapterId::unchecked("solana"),
        adapter_version: "0.1.0".into(),
        intent_hash: Hash32([20; 32]),
        candidate_id: CandidateId::unchecked("candidate-a"),
        candidate_revision: 4,
        decoded_operation_hash: Hash32([21; 32]),
        evidence_bundle_hash: Hash32([22; 32]),
        policy_id: PolicyId::unchecked("treasury"),
        policy_epoch: Epoch(9),
        policy_hash: Hash32([23; 32]),
    }
}

fn attestation(roster: &SignedRoster, index: u8, decision: VerificationDecision) -> VerificationAttestation {
    let body = VerificationAttestationBody {
        inputs: inputs(roster),
        node_id: NodeId::unchecked(format!("node-{index}")),
        verifier_build_hash: Hash32([index + 1; 32]),
        decision,
        reason_codes: if decision == VerificationDecision::Allow { vec![] } else { vec!["policy_denied".into()] },
        attested_at: UnixSeconds(110),
        expires_at: UnixSeconds(200),
    };
    sign_attestation(&SigningKey::from_bytes(&[100 + index; 32]), body).unwrap()
}

fn requirement(distinct: bool) -> AttestationRequirement {
    AttestationRequirement { committee_id: CommitteeId::unchecked("verification"), threshold: 2, require_distinct_domains: distinct }
}

#[test]
fn canonical_attestations_bind_every_expected_input_and_every_signed_field() {
    let roster = roster();
    let expected = inputs(&roster);
    let valid = attestation(&roster, 0, VerificationDecision::Allow);
    verify_attestation(&valid, &roster, &expected, UnixSeconds(110)).unwrap();
    let bytes = canonical_bytes(&valid).unwrap();
    let decoded: VerificationAttestation = from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, valid);
    verify_attestation(&decoded, &roster, &expected, UnixSeconds(110)).unwrap();

    // Every mutation is re-signed: rejection must come from expected bindings,
    // not merely a signature failure on a changed body.
    let mutations: &[fn(&mut VerificationInputs)] = &[
        |i| i.institution_id = InstitutionId::unchecked("other"),
        |i| i.environment_id = EnvironmentId::unchecked("mainnet"),
        |i| i.roster_epoch += 1,
        |i| i.roster_hash = Hash32([77; 32]),
        |i| i.adapter_id = AdapterId::unchecked("evm"),
        |i| i.adapter_version = "0.2.0".into(),
        |i| i.intent_hash = Hash32([78; 32]),
        |i| i.candidate_id = CandidateId::unchecked("other"),
        |i| i.candidate_revision += 1,
        |i| i.decoded_operation_hash = Hash32([79; 32]),
        |i| i.evidence_bundle_hash = Hash32([80; 32]),
        |i| i.policy_id = PolicyId::unchecked("other"),
        |i| i.policy_epoch = Epoch(10),
        |i| i.policy_hash = Hash32([81; 32]),
    ];
    for (index, mutation) in mutations.iter().enumerate() {
        let mut changed = valid.body.clone();
        mutation(&mut changed.inputs);
        let signed = sign_attestation(&SigningKey::from_bytes(&[100; 32]), changed).unwrap();
        assert_eq!(verify_attestation(&signed, &roster, &expected, UnixSeconds(110)).unwrap_err().code, ErrorCode::ScopeMismatch, "input mutation {index}");
    }

    let signed_mutations: &[fn(&mut VerificationAttestationBody)] = &[
        |b| b.decision = VerificationDecision::Deny,
        |b| b.reason_codes.push("different_reason".into()),
        |b| b.attested_at = UnixSeconds(109),
        |b| b.expires_at = UnixSeconds(201),
    ];
    for mutation in signed_mutations {
        let mut changed = valid.clone();
        mutation(&mut changed.body);
        assert_eq!(verify_attestation(&changed, &roster, &expected, UnixSeconds(110)).unwrap_err().code, ErrorCode::InvalidSignature);
    }
    let mut wrong_key = valid.clone();
    wrong_key.signature = sign_attestation(&SigningKey::from_bytes(&[10; 32]), valid.body).unwrap().signature;
    assert_eq!(verify_attestation(&wrong_key, &roster, &expected, UnixSeconds(110)).unwrap_err().code, ErrorCode::InvalidSignature);
}

#[test]
fn roster_role_build_scope_and_exclusive_expiry_are_checked() {
    let roster = roster();
    let expected = inputs(&roster);
    let valid = attestation(&roster, 7, VerificationDecision::Allow);
    verify_attestation(&valid, &roster, &expected, UnixSeconds(199)).unwrap();
    for now in [109, 200, 201] {
        assert_eq!(verify_attestation(&valid, &roster, &expected, UnixSeconds(now)).unwrap_err().code, ErrorCode::StaleEvidence);
    }
    let mut invalid = valid.body.clone();
    invalid.expires_at = invalid.attested_at;
    let invalid = sign_attestation(&SigningKey::from_bytes(&[107; 32]), invalid).unwrap();
    assert_eq!(verify_attestation(&invalid, &roster, &expected, UnixSeconds(110)).unwrap_err().code, ErrorCode::StaleEvidence);
    let mut invalid = valid.body.clone();
    invalid.verifier_build_hash = Hash32([99; 32]);
    let invalid = sign_attestation(&SigningKey::from_bytes(&[107; 32]), invalid).unwrap();
    assert_eq!(verify_attestation(&invalid, &roster, &expected, UnixSeconds(110)).unwrap_err().code, ErrorCode::PolicyDenied);
    for index in [3, 4, 5, 6] {
        let invalid = attestation(&roster, index, VerificationDecision::Allow);
        assert_eq!(verify_attestation(&invalid, &roster, &expected, UnixSeconds(110)).unwrap_err().code, ErrorCode::PeerNotAdmitted);
    }
    let mut other = expected.clone();
    other.roster_hash = Hash32([99; 32]);
    assert_eq!(verify_attestation(&valid, &roster, &other, UnixSeconds(110)).unwrap_err().code, ErrorCode::RosterMismatch);
    other = expected.clone();
    other.environment_id = EnvironmentId::unchecked("mainnet");
    assert_eq!(verify_attestation(&valid, &roster, &other, UnixSeconds(110)).unwrap_err().code, ErrorCode::ScopeMismatch);

    let mut b = body();
    b.nodes[0].attestation_key = Some(b.nodes[0].transport_key.clone());
    rejected(b, None, "attestation key reused");
    let mut b = body();
    b.nodes[0].attestation_key = None;
    rejected(b, None, "must have an attestation key");
    let mut b = body();
    b.nodes[1].attestation_key = b.nodes[0].attestation_key.clone();
    rejected(b, None, "attestation key reused");
}

#[test]
fn quorum_counts_distinct_nodes_and_domains_and_rechecks_expiration() {
    let roster = roster();
    let mut quorum = AttestationQuorum::new(&roster, inputs(&roster), requirement(true)).unwrap();
    let now = UnixSeconds(110);
    let first = attestation(&roster, 0, VerificationDecision::Allow);
    assert_eq!(quorum.add(first.clone(), now).unwrap(), QuorumStatus::Pending);
    assert_eq!(quorum.add(first, now).unwrap(), QuorumStatus::Pending);
    // Node 7 is a different, authentic verifier in node 0's domain.
    let same_domain = attestation(&roster, 7, VerificationDecision::Allow);
    assert_eq!(quorum.add(same_domain, now).unwrap(), QuorumStatus::Pending);
    assert!(quorum.require_allow(now).is_err());
    let mut second = attestation(&roster, 1, VerificationDecision::Allow).body;
    second.expires_at = UnixSeconds(150);
    let second = sign_attestation(&SigningKey::from_bytes(&[101; 32]), second).unwrap();
    assert_eq!(quorum.add(second, now).unwrap(), QuorumStatus::Reached(VerificationDecision::Allow));
    quorum.require_allow(UnixSeconds(149)).unwrap();
    assert_eq!(quorum.status(UnixSeconds(150)), QuorumStatus::Pending);
    assert!(quorum.require_allow(UnixSeconds(150)).is_err());

    let mut quorum = AttestationQuorum::new(&roster, inputs(&roster), requirement(false)).unwrap();
    quorum.add(attestation(&roster, 0, VerificationDecision::Allow), now).unwrap();
    assert_eq!(quorum.add(attestation(&roster, 7, VerificationDecision::Allow), now).unwrap(), QuorumStatus::Reached(VerificationDecision::Allow));
}

#[test]
fn real_disagreement_quarantines_after_quorum_and_retains_both_signed_decisions() {
    let roster = roster();
    let mut quorum = AttestationQuorum::new(&roster, inputs(&roster), requirement(true)).unwrap();
    let now = UnixSeconds(110);
    for index in [0, 1] {
        quorum.add(attestation(&roster, index, VerificationDecision::Allow), now).unwrap();
    }
    quorum.require_allow(now).unwrap();
    let disagree = attestation(&roster, 7, VerificationDecision::Deny);
    // This is a real, correctly signed DENY for the same inputs, from another
    // approved build. A duplicate signature cannot simulate this scenario.
    verify_attestation(&disagree, &roster, &inputs(&roster), now).unwrap();
    assert_eq!(quorum.add(disagree.clone(), now).unwrap_err().code, ErrorCode::AttestationDisagreement);
    assert_eq!(quorum.status(now), QuorumStatus::Quarantined);
    assert_eq!(quorum.require_allow(now).unwrap_err().code, ErrorCode::AttestationDisagreement);
    let (allow, deny) = quorum.conflict().unwrap();
    assert_eq!(allow.body.inputs, deny.body.inputs);
    assert_eq!(allow.body.decision, VerificationDecision::Allow);
    assert_eq!(deny, &disagree);
    for signed in [allow, deny] {
        verify_attestation(signed, &roster, &inputs(&roster), now).unwrap();
    }
    assert_eq!(quorum.add(attestation(&roster, 2, VerificationDecision::Allow), now).unwrap_err().code, ErrorCode::AttestationDisagreement);
    assert_eq!(quorum.status(UnixSeconds(500)), QuorumStatus::Quarantined);

    // Equivocation by a single enrolled node is also a genuine disagreement.
    let mut quorum = AttestationQuorum::new(&roster, inputs(&roster), requirement(true)).unwrap();
    quorum.add(attestation(&roster, 0, VerificationDecision::Allow), now).unwrap();
    assert_eq!(quorum.add(attestation(&roster, 0, VerificationDecision::RequireApprovals), now).unwrap_err().code, ErrorCode::AttestationDisagreement);
}

#[test]
fn forged_or_different_input_deny_cannot_poison_the_collector() {
    let roster = roster();
    let now = UnixSeconds(110);
    let mut quorum = AttestationQuorum::new(&roster, inputs(&roster), requirement(true)).unwrap();
    quorum.add(attestation(&roster, 0, VerificationDecision::Allow), now).unwrap();
    let mut forged = attestation(&roster, 7, VerificationDecision::Deny);
    forged.signature.bytes.0[0] ^= 1;
    assert_eq!(quorum.add(forged, now).unwrap_err().code, ErrorCode::InvalidSignature);
    let mut different = attestation(&roster, 7, VerificationDecision::Deny).body;
    different.inputs.candidate_revision += 1;
    let different = sign_attestation(&SigningKey::from_bytes(&[107; 32]), different).unwrap();
    assert_eq!(quorum.add(different, now).unwrap_err().code, ErrorCode::ScopeMismatch);
    assert!(quorum.conflict().is_none());
    assert_eq!(quorum.status(now), QuorumStatus::Pending);
    quorum.add(attestation(&roster, 1, VerificationDecision::Allow), now).unwrap();
    quorum.require_allow(now).unwrap();
}

#[test]
fn only_selected_committee_votes_count_but_other_verifiers_can_expose_disagreement() {
    let mut b = roster().body;
    b.committees[2].members.retain(|id| id != &NodeId::unchecked("node-2"));
    // Node 2 remains a signer and therefore a default roster verifier.
    let roster = sign(b);
    validate(&roster, None).unwrap();
    let mut quorum = AttestationQuorum::new(&roster, inputs(&roster), requirement(true)).unwrap();
    let now = UnixSeconds(110);
    quorum.add(attestation(&roster, 0, VerificationDecision::Allow), now).unwrap();
    assert_eq!(quorum.add(attestation(&roster, 2, VerificationDecision::Allow), now).unwrap(), QuorumStatus::Pending);
    assert_eq!(quorum.add(attestation(&roster, 2, VerificationDecision::Deny), now).unwrap_err().code, ErrorCode::AttestationDisagreement);
}

#[test]
fn non_allow_quorums_and_invalid_requirements_never_authorize() {
    let roster = roster();
    let now = UnixSeconds(110);
    for (decision, code) in [(VerificationDecision::Deny, ErrorCode::PolicyDenied), (VerificationDecision::RequireApprovals, ErrorCode::ApprovalRequired)] {
        let mut quorum = AttestationQuorum::new(&roster, inputs(&roster), requirement(true)).unwrap();
        for index in [0, 1] {
            quorum.add(attestation(&roster, index, decision), now).unwrap();
        }
        assert_eq!(quorum.status(now), QuorumStatus::Reached(decision));
        assert_eq!(quorum.require_allow(now).unwrap_err().code, code);
    }
    for threshold in [0, 1, 5] {
        let mut invalid = requirement(true);
        invalid.threshold = threshold;
        assert!(AttestationQuorum::new(&roster, inputs(&roster), invalid).is_err());
    }
    let mut impossible = requirement(true);
    impossible.threshold = 4; // four nodes, only three domains
    assert!(AttestationQuorum::new(&roster, inputs(&roster), impossible).is_err());
    let mut wrong = requirement(true);
    wrong.committee_id = CommitteeId::unchecked("key");
    assert!(AttestationQuorum::new(&roster, inputs(&roster), wrong).is_err());
}
