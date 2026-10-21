mod common;
use common::{
    d2::{self, Chain},
    *,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    CertifiableBlock,
    types::{Epoch as ConsensusEpoch, Height},
};
use oic_approver_client::{Client, FinalizedEntry};
use oic_authorization_state::{AuthorityCommand, CredentialChange};
use oic_domain_types::*;
use oic_replicated_authority::AuthorityBlock;

#[test]
fn native_operation_and_browser_grant_are_confirmed_only_after_ordering_on_both_chains() {
    for chain in [Chain::Evm, Chain::Solana] {
        let mut scenario = Scenario::new(chain);
        let mut client = scenario.client();
        let prepared = client
            .prepare(
                scenario.fixture.built.package.clone(),
                credential_id(),
                Hash32([7; 32]),
                d2::now(),
            )
            .unwrap();
        assert_eq!(prepared.display.amount_base_units, "1000000");
        assert_eq!(
            prepared.display.preview_hash,
            scenario.fixture.built.preview_hash
        );
        match chain {
            Chain::Evm => assert_eq!(
                prepared.display.recipient_address_display.to_lowercase(),
                "0xdededededededededededededededededededede"
            ),
            Chain::Solana => assert_eq!(
                prepared.display.recipient_address_display,
                "EUzYVniKtgNNgFweMtRA9vciTWtE8MDTRfh6ai6VvXoU"
            ),
        }
        assert!(!client.confirmed(d2::now()).unwrap());
        let assertion = Assertion::new(prepared.challenge, ORIGIN, "localhost", 5, "webauthn.get");
        let command = client
            .assertion(RAW_ID, assertion.raw(), d2::now())
            .unwrap();
        assert!(!client.confirmed(d2::now()).unwrap());
        let entry = scenario.order(std::slice::from_ref(&command)).unwrap();
        client.apply(&entry, d2::now()).unwrap();
        assert!(client.confirmed(d2::now()).unwrap());
        assert!(scenario.order(&[command]).is_err());
        assert!(
            client
                .prepare(
                    scenario.fixture.built.package.clone(),
                    credential_id(),
                    Hash32([8; 32]),
                    d2::now()
                )
                .is_err()
        );
    }
}

#[test]
fn rejects_wrong_committee_epoch_body_state_and_rollback_without_snapshot_import() {
    let mut scenario = Scenario::new(Chain::Evm);
    let mut client = scenario.client();
    let before = client.floor();
    let block = AuthorityBlock::decode(scenario.initial.block.as_slice()).unwrap();
    let other = d2::Committee::with_seed(977);
    assert!(
        client
            .apply(
                &FinalizedEntry::new(&block, &other.certify(&block)),
                d2::now()
            )
            .is_err()
    );
    let mut context = block.context();
    context.round =
        commonware_consensus::types::Round::new(ConsensusEpoch::new(1), context.round.view());
    let epoch = AuthorityBlock::new(
        context,
        Height::new(1),
        d2::now(),
        block.state_hash(),
        &block.commands().unwrap(),
    )
    .unwrap();
    assert!(
        client
            .apply(
                &FinalizedEntry::new(&epoch, &scenario.committee.certify(&epoch)),
                d2::now()
            )
            .is_err()
    );
    let tampered = AuthorityBlock::new(
        block.context(),
        Height::new(1),
        UnixSeconds(d2::NOW + 1),
        block.state_hash(),
        &block.commands().unwrap(),
    )
    .unwrap();
    let mut entry = scenario.initial.clone();
    entry.block = tampered.encode().to_vec().into();
    assert!(client.apply(&entry, d2::now()).is_err());
    let invalid = AuthorityBlock::new(
        scenario.committee.context(&scenario.tip, 2),
        Height::new(2),
        d2::now(),
        Hash32([91; 32]),
        &[],
    )
    .unwrap();
    assert!(
        client
            .apply(
                &FinalizedEntry::new(&invalid, &scenario.committee.certify(&invalid)),
                d2::now()
            )
            .is_err()
    );
    assert_eq!(client.floor(), before);
    let second = scenario.order(&[]).unwrap();
    client.apply(&second, d2::now()).unwrap();
    assert!(client.apply(&scenario.initial, d2::now()).is_err());
    let mut provision = scenario.provision.clone();
    provision.minimum_floor = client.floor();
    let mut restored = Client::new(provision.clone(), [1; 32], ORIGIN, d2::now()).unwrap();
    restored.apply(&scenario.initial, d2::now()).unwrap();
    assert!(
        restored
            .prepare(
                scenario.fixture.built.package.clone(),
                credential_id(),
                Hash32([1; 32]),
                d2::now()
            )
            .is_err()
    );
    provision.minimum_floor.digest = Hash32([33; 32]);
    let mut restored = Client::new(provision, [1; 32], ORIGIN, d2::now()).unwrap();
    restored.apply(&scenario.initial, d2::now()).unwrap();
    assert!(restored.apply(&second, d2::now()).is_err());
    for mutate in [0, 1, 2] {
        let mut provision = scenario.provision.clone();
        match mutate {
            0 => provision.institution_id = InstitutionId::unchecked("attacker"),
            1 => provision.registry.assets[0].decimals += 1,
            _ => provision.admin_quorum = 1,
        }
        assert!(Client::new(provision, [1; 32], ORIGIN, d2::now()).is_err());
    }
    assert!(
        Client::new(
            scenario.provision,
            [1; 32],
            "https://console.example",
            d2::now()
        )
        .is_err()
    );
}

#[test]
fn descendant_certificate_authenticates_ancestors_only_after_atomic_native_replay() {
    let mut scenario = Scenario::new(Chain::Evm);
    let mut client = scenario.client();
    let prepared = client
        .prepare(
            scenario.fixture.built.package.clone(),
            credential_id(),
            Hash32([73; 32]),
            d2::now(),
        )
        .unwrap();
    let assertion = Assertion::new(prepared.challenge, ORIGIN, "localhost", 5, "webauthn.get");
    let command = client
        .assertion(RAW_ID, assertion.raw(), d2::now())
        .unwrap();
    let approval = scenario.order(&[command]).unwrap();
    let middle = scenario.order(&[]).unwrap();
    let mut checkpoint = scenario.order(&[]).unwrap();
    // Only the height-4 tip's certificate is delivered. The approval at height
    // 2 and the height-3 ancestor have no individual finalizations in this input.
    checkpoint.ancestors = vec![approval.block, middle.block];
    let before = client.floor();
    for case in 0..4 {
        let mut invalid = checkpoint.clone();
        match case {
            0 => {
                invalid.ancestors.remove(0);
            }
            1 => invalid.ancestors.swap(0, 1),
            2 => invalid.ancestors[1].0[0] ^= 1,
            _ => invalid.ancestors = vec![invalid.ancestors[0].clone(); 256],
        }
        assert!(client.apply(&invalid, d2::now()).is_err());
        assert_eq!(client.floor(), before);
        assert!(!client.confirmed(d2::now()).unwrap());
    }
    let mut provision = scenario.provision.clone();
    provision.minimum_floor = oic_approver_client::Floor {
        height: 2,
        digest: Hash32([11; 32]),
    };
    let mut restored = Client::new(provision, [81; 32], ORIGIN, d2::now()).unwrap();
    restored.apply(&scenario.initial, d2::now()).unwrap();
    assert!(restored.apply(&checkpoint, d2::now()).is_err());
    assert_eq!(restored.floor(), before);
    assert_eq!(client.apply(&checkpoint, d2::now()).unwrap().height, 4);
    assert!(client.confirmed(d2::now()).unwrap());
}

#[test]
fn assertions_fail_for_uv_login_origin_rp_challenge_and_returned_credential() {
    let scenario = Scenario::new(Chain::Solana);
    for case in 0..7 {
        let mut client = scenario.client();
        let prepared = client
            .prepare(
                scenario.fixture.built.package.clone(),
                credential_id(),
                Hash32([7; 32]),
                d2::now(),
            )
            .unwrap();
        let challenge = if case == 4 {
            Hash32([99; 32])
        } else {
            prepared.challenge
        };
        let assertion = Assertion::new(
            challenge,
            if case == 1 {
                "https://console.example"
            } else {
                ORIGIN
            },
            if case == 2 {
                "console.example"
            } else {
                "localhost"
            },
            if case == 0 { 1 } else { 5 },
            if case == 3 {
                "webauthn.create"
            } else {
                "webauthn.get"
            },
        );
        let now = if case == 6 {
            UnixSeconds(d2::NOW + 121)
        } else {
            d2::now()
        };
        assert!(
            client
                .assertion(
                    if case == 5 { b"login-key" } else { RAW_ID },
                    assertion.raw(),
                    now
                )
                .is_err()
        );
        assert!(client.confirmed(now).is_err() || !client.confirmed(now).unwrap());
    }
}

#[test]
fn stale_frozen_removed_self_approved_and_changed_policy_cannot_prepare() {
    for case in 0..7 {
        let mut scenario = Scenario::new(Chain::Evm);
        let mut client = scenario.client();
        let mut package = scenario.fixture.built.package.clone();
        let mut now = d2::now();
        match case {
            0 => now = UnixSeconds(d2::NOW + 61),
            1 => {
                let freeze = scenario.fixture.freeze();
                let entry = scenario.order(&[freeze]).unwrap();
                client.apply(&entry, now).unwrap();
            }
            2 => {
                let previous_change = scenario
                    .state
                    .authority
                    .ordered_approvals
                    .as_ref()
                    .unwrap()
                    .credentials[&credential_id()]
                    .commit_sequence;
                let proposal = CredentialChange {
                    institution_id: package.intent.institution_id.clone(),
                    environment_id: package.intent.environment_id.clone(),
                    credential_id: credential_id(),
                    previous_change,
                    credential: None,
                };
                let command = d2::authority(AuthorityCommand::ChangeCredential {
                    signatures: d2::admin_signatures(proposal.hash().unwrap()),
                    proposal,
                });
                let entry = scenario.order(&[command]).unwrap();
                client.apply(&entry, now).unwrap();
            }
            3 => {
                let proposer = oic_policy_kernel::ApproverCredential {
                    credential_id: package.intent.proposer_credential_id.clone(),
                    person_id: credential().person_id,
                    role: ApprovalRole::TreasuryApprover,
                    verifying_key: ed25519_dalek::SigningKey::from_bytes(&[94; 32])
                        .verifying_key()
                        .into(),
                };
                let proposal = CredentialChange {
                    institution_id: package.intent.institution_id.clone(),
                    environment_id: package.intent.environment_id.clone(),
                    credential_id: proposer.credential_id.clone(),
                    previous_change: 0,
                    credential: Some(proposer),
                };
                let command = d2::authority(AuthorityCommand::ChangeCredential {
                    signatures: d2::admin_signatures(proposal.hash().unwrap()),
                    proposal,
                });
                let entry = scenario.order(&[command]).unwrap();
                client.apply(&entry, now).unwrap();
            }
            4 => package.policy.policy_epoch = Epoch(package.policy.policy_epoch.0 + 1),
            5 => package.destination.version += 1,
            _ => package.intent.constraints.approval_mode = ApprovalMode::BoundedDirectTransfer,
        }
        assert!(
            client
                .prepare(package, credential_id(), Hash32([7; 32]), now)
                .is_err()
        );
    }
}
