//! External D2 contracts: real 3-of-4 Commonware finalizations and native
//! candidates. This is not a Simplex network or a threshold-signing test.
mod common;

use common::{Chain, Committee, Fixture, NOW, approver, authority, now};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    CertifiableBlock, Heightable,
    simplex::types::{Finalize, Proposal},
    types::{Epoch as ConsensusEpoch, Height, Round, View},
};
use commonware_cryptography::{Digestible, Hasher, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::{TestRng, non_empty};
use oic_authorization_state::{
    AuthorityCommand, AuthorityOutput, BudgetKey, ReservationState, apply,
};
use oic_canonical_encoding::canonical_bytes;
use oic_domain_types::*;
use oic_policy_kernel::{policy_hash, verify_grants};
use oic_replicated_authority::*;

fn ready(fixture: &Fixture) -> ReplicatedState {
    let mut commands = fixture.bootstrap();
    commands.extend(fixture.approvals());
    fixture
        .executor
        .execute(ReplicatedState::default(), &commands, now())
        .unwrap()
        .0
}

#[test]
fn finalization_authenticates_body_context_epoch_and_enrolled_vote_keys() {
    let fixture = Fixture::new(Chain::Evm, 1);
    let committee = Committee::new();
    let genesis = fixture.genesis(&committee);
    let context = committee.context(&genesis, 1);
    let (block, _) = fixture
        .executor
        .propose_block(
            &genesis,
            ReplicatedState::default(),
            context.clone(),
            &fixture.bootstrap(),
            now(),
            now(),
        )
        .unwrap();
    let finalization = committee.certify(&block);
    let mut rng = TestRng::new(31);
    committee
        .trust
        .verify(&mut rng, &block, &finalization)
        .unwrap();
    let decoded = AuthorityBlock::decode(block.encode()).unwrap();
    assert_eq!(decoded, block);
    assert_eq!(decoded.digest(), block.digest());
    committee
        .trust
        .verify(&mut rng, &decoded, &finalization)
        .unwrap();

    let recreate = |context, height, time, root, commands: &[Command]| {
        AuthorityBlock::new(context, height, time, root, commands).unwrap()
    };
    let mut leader = context.clone();
    leader.leader = genesis.context().leader;
    let mut parent = context.clone();
    parent.parent.1 = Sha256::hash(&[b"different parent digest"]);
    let mut parent_view = context.clone();
    parent_view.parent.0 = View::new(9);
    let mut view = context.clone();
    view.round = Round::new(committee.trust.epoch(), View::new(3));
    let mut epoch = context.clone();
    epoch.round = Round::new(ConsensusEpoch::new(1), View::new(1));
    let commands = block.commands().unwrap();
    let mutations = [
        recreate(
            context.clone(),
            block.height(),
            now(),
            block.state_hash(),
            &[],
        ),
        recreate(leader, block.height(), now(), block.state_hash(), &commands),
        recreate(parent, block.height(), now(), block.state_hash(), &commands),
        recreate(
            parent_view,
            block.height(),
            now(),
            block.state_hash(),
            &commands,
        ),
        recreate(view, block.height(), now(), block.state_hash(), &commands),
        recreate(
            epoch.clone(),
            block.height(),
            now(),
            block.state_hash(),
            &commands,
        ),
        recreate(
            context.clone(),
            Height::new(9),
            now(),
            block.state_hash(),
            &commands,
        ),
        recreate(
            context.clone(),
            block.height(),
            UnixSeconds(NOW + 1),
            block.state_hash(),
            &commands,
        ),
        recreate(
            context.clone(),
            block.height(),
            now(),
            Hash32([7; 32]),
            &commands,
        ),
    ];
    for (index, tampered) in mutations.iter().enumerate() {
        assert_ne!(
            tampered.digest(),
            block.digest(),
            "mutation {index} must actually change the signed block"
        );
        assert_eq!(
            committee
                .trust
                .verify(&mut rng, tampered, &finalization)
                .unwrap_err()
                .code,
            ErrorCode::InvalidSignature,
            "mutation {index}"
        );
    }
    // Correct committee signatures cannot turn an unactivated epoch into trust.
    let future = recreate(epoch, block.height(), now(), block.state_hash(), &commands);
    assert_eq!(
        committee
            .trust
            .verify(&mut rng, &future, &committee.certify(&future))
            .unwrap_err()
            .code,
        ErrorCode::InvalidSignature
    );
    let foreign = Committee::with_seed(900);
    let foreign_certificate = foreign.certify(&block);
    foreign
        .trust
        .verify(&mut rng, &block, &foreign_certificate)
        .unwrap();
    assert_eq!(
        committee
            .trust
            .verify(&mut rng, &block, &foreign_certificate)
            .unwrap_err()
            .code,
        ErrorCode::InvalidSignature
    );
    assert!(
        committee
            .trust
            .signer(&committee.keys[0].0, foreign.keys[0].1.clone())
            .is_err()
    );
    assert!(
        committee
            .trust
            .signer(
                &NodeId::unchecked("not-enrolled"),
                committee.keys[0].1.clone()
            )
            .is_err()
    );

    let proposal = Proposal::new(context.round, context.parent.0, block.digest());
    let votes: Vec<_> = committee.keys[..2]
        .iter()
        .map(|(node, key)| {
            Finalize::sign(
                &committee.trust.signer(node, key.clone()).unwrap(),
                proposal.clone(),
            )
            .unwrap()
        })
        .collect();
    assert!(
        AuthorityFinalization::from_finalizes(
            &committee.trust.verifier(),
            non_empty![@votes.iter()],
            &Sequential
        )
        .is_err()
    );
}

#[test]
fn authentic_three_of_four_finalization_is_not_proof_of_correct_execution() {
    let fixture = Fixture::new(Chain::Evm, 1);
    let committee = Committee::new();
    let genesis = fixture.genesis(&committee);
    let context = committee.context(&genesis, 1);
    let (valid, expected) = fixture
        .executor
        .propose_block(
            &genesis,
            ReplicatedState::default(),
            context.clone(),
            &fixture.bootstrap(),
            now(),
            now(),
        )
        .unwrap();
    assert_eq!(
        fixture
            .executor
            .verify_block(
                &genesis,
                ReplicatedState::default(),
                &context,
                &valid,
                now()
            )
            .unwrap(),
        expected
    );
    let invalid = AuthorityBlock::new(
        context.clone(),
        valid.height(),
        now(),
        Hash32([0x93; 32]),
        &valid.commands().unwrap(),
    )
    .unwrap();
    let finalization = committee.certify(&invalid);
    committee
        .trust
        .verify(&mut TestRng::new(4), &invalid, &finalization)
        .unwrap();
    assert_eq!(
        fixture
            .executor
            .verify_block(
                &genesis,
                ReplicatedState::default(),
                &context,
                &invalid,
                now()
            )
            .unwrap_err()
            .code,
        ErrorCode::UnverifiableTransaction
    );
}

#[test]
fn exact_parent_reexecution_and_both_timestamp_boundaries_are_enforced() {
    let fixture = Fixture::new(Chain::Evm, 1);
    let committee = Committee::new();
    let genesis = fixture.genesis(&committee);
    let context = committee.context(&genesis, 1);
    let (parent, state) = fixture
        .executor
        .propose_block(
            &genesis,
            ReplicatedState::default(),
            context.clone(),
            &fixture.bootstrap(),
            now(),
            now(),
        )
        .unwrap();
    let successor_context = committee.context(&parent, 2);
    let (child, child_state) = fixture
        .executor
        .propose_block(
            &parent,
            state.clone(),
            successor_context.clone(),
            &fixture.approvals(),
            now(),
            now(),
        )
        .unwrap();
    assert_eq!(
        fixture
            .executor
            .verify_block(&parent, state.clone(), &successor_context, &child, now())
            .unwrap(),
        child_state
    );
    assert!(
        fixture
            .executor
            .verify_block(
                &parent,
                ReplicatedState::default(),
                &successor_context,
                &child,
                now()
            )
            .is_err()
    );
    assert!(
        fixture
            .executor
            .verify_block(
                &genesis,
                ReplicatedState::default(),
                &successor_context,
                &child,
                now()
            )
            .is_err()
    );
    assert!(
        fixture
            .executor
            .verify_block(&parent, state.clone(), &context, &child, now())
            .is_err()
    );
    let wrong_height = AuthorityBlock::new(
        successor_context.clone(),
        Height::new(4),
        now(),
        child.state_hash(),
        &child.commands().unwrap(),
    )
    .unwrap();
    assert!(
        fixture
            .executor
            .verify_block(
                &parent,
                state.clone(),
                &successor_context,
                &wrong_height,
                now()
            )
            .is_err()
    );

    for timestamp in [UnixSeconds(NOW - 1), UnixSeconds(NOW + 31)] {
        assert_eq!(
            fixture
                .executor
                .propose_block(
                    &parent,
                    state.clone(),
                    successor_context.clone(),
                    &[],
                    timestamp,
                    now()
                )
                .unwrap_err()
                .code,
            ErrorCode::StaleEvidence
        );
        let hostile = AuthorityBlock::new(
            successor_context.clone(),
            Height::new(2),
            timestamp,
            parent.state_hash(),
            &[],
        )
        .unwrap();
        assert_eq!(
            fixture
                .executor
                .verify_block(&parent, state.clone(), &successor_context, &hostile, now())
                .unwrap_err()
                .code,
            ErrorCode::StaleEvidence
        );
    }
    // Equality at parent time and exactly +skew are valid, unlike either side.
    for timestamp in [now(), UnixSeconds(NOW + 30)] {
        let (block, expected) = fixture
            .executor
            .propose_block(
                &parent,
                state.clone(),
                successor_context.clone(),
                &[],
                timestamp,
                now(),
            )
            .unwrap();
        assert_eq!(
            fixture
                .executor
                .verify_block(&parent, state.clone(), &successor_context, &block, now())
                .unwrap(),
            expected
        );
    }
    // Another proposal may depend on genesis even after this caller saw parent.
    let (branch, branch_state) = fixture
        .executor
        .propose_block(
            &genesis,
            ReplicatedState::default(),
            context.clone(),
            &[],
            now(),
            now(),
        )
        .unwrap();
    assert_eq!(
        fixture
            .executor
            .verify_block(
                &genesis,
                ReplicatedState::default(),
                &context,
                &branch,
                now()
            )
            .unwrap(),
        branch_state
    );
    assert!(
        fixture
            .executor
            .verify_block(&genesis, state, &context, &branch, now())
            .is_err()
    );
}

#[test]
fn real_native_evm_and_solana_reserve_release_require_ordered_enrollment_and_grants() {
    for chain in [Chain::Evm, Chain::Solana] {
        let fixture = Fixture::new(chain, 2);
        let proof = fixture.proof();
        assert!(!proof.package.candidate.native_unsigned_bytes.is_empty());
        let legacy = fixture
            .executor
            .execute(ReplicatedState::default(), &fixture.bootstrap()[..2], now())
            .unwrap()
            .0;
        assert_eq!(
            fixture
                .executor
                .execute(legacy, &[Command::Reserve(Box::new(proof.clone()))], now())
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
        let (enrolled, _, _) = fixture
            .executor
            .execute(ReplicatedState::default(), &fixture.bootstrap(), now())
            .unwrap();
        verify_grants(&fixture.grants, &[approver(1), approver(2)], now()).unwrap();
        let reserve = Command::Reserve(Box::new(proof.clone()));
        assert_eq!(
            fixture
                .executor
                .execute(enrolled.clone(), std::slice::from_ref(&reserve), now())
                .unwrap_err()
                .code,
            ErrorCode::ApprovalRequired
        );
        let state = fixture
            .executor
            .execute(enrolled, &fixture.approvals(), now())
            .unwrap()
            .0;
        let (reserved, output, _) = fixture.executor.execute(state, &[reserve], now()).unwrap();
        let id = &proof.envelope.budget_reservation_id;
        assert_eq!(
            reserved.authority.reservations[id].state,
            ReservationState::Reserved
        );
        assert!(
            matches!(output.as_slice(), [AuthorityOutput::Reserved { receipt, .. }] if receipt.kind == ReceiptKind::Reserved)
        );
        assert_eq!(reserved.reservations[id], proof);
        let (released, output, _) = fixture
            .executor
            .execute(reserved, &[fixture.release()], now())
            .unwrap();
        let [AuthorityOutput::Released { receipt, issuance }] = output.as_slice() else {
            panic!("missing unsigned issuance result")
        };
        assert_eq!(receipt.kind, ReceiptKind::Release);
        assert_eq!(issuance.envelope_hash, proof.request.envelope_body_hash);
        assert_eq!(issuance.signer_session_id, proof.request.signer_session_id);
        assert_eq!(released.authority.issuance.len(), 1);
        assert!(matches!(
            released.authority.reservations[id].state,
            ReservationState::Released { .. }
        ));
        assert!(
            released.authority.families[&proof.request.family_id].candidates[0].possibly_issued
        );
        let (again, repeated, events) = fixture
            .executor
            .execute(released.clone(), &[fixture.release()], now())
            .unwrap();
        assert_eq!(again, released);
        assert_eq!(repeated, output);
        assert!(events.is_empty());
    }
}

#[test]
fn signed_native_proofs_cannot_substitute_an_allow_for_policy_or_proposer_checks() {
    for chain in [Chain::Evm, Chain::Solana] {
        // Valid native bytes, valid admin policy signatures and real approvals;
        // the active policy still denies this amount despite the claimed Allow.
        let denied = Fixture::with_inputs(chain, 1, |inputs| {
            inputs.policy.rules[0].max_amount_per_operation = Amount(999_999)
        });
        let state = ready(&denied);
        let proof = denied.proof();
        verify_grants(&proof.request.grants, &[approver(1)], now()).unwrap();
        assert!(proof.request.policy_decision.is_allow());
        let committee = Committee::new();
        let genesis = denied.genesis(&committee);
        let context = committee.context(&genesis, 1);
        let mut commands = denied.bootstrap();
        commands.extend(denied.approvals());
        commands.push(Command::Reserve(Box::new(proof.clone())));
        let hostile = AuthorityBlock::new(
            context.clone(),
            Height::new(1),
            now(),
            Hash32::ZERO,
            &commands,
        )
        .unwrap();
        committee
            .trust
            .verify(&mut TestRng::new(8), &hostile, &committee.certify(&hostile))
            .unwrap();
        assert_eq!(
            denied
                .executor
                .verify_block(
                    &genesis,
                    ReplicatedState::default(),
                    &context,
                    &hostile,
                    now()
                )
                .unwrap_err()
                .code,
            ErrorCode::PolicyDenied
        );
        assert_eq!(
            denied
                .executor
                .execute(state, &[Command::Reserve(Box::new(proof))], now())
                .unwrap_err()
                .code,
            ErrorCode::PolicyDenied
        );

        let self_approved = Fixture::with_inputs(chain, 1, |inputs| {
            inputs.intent.proposer_credential_id = approver(1).credential_id
        });
        let state = self_approved
            .executor
            .execute(
                ReplicatedState::default(),
                &self_approved.bootstrap(),
                now(),
            )
            .unwrap()
            .0;
        verify_grants(&self_approved.grants, &[approver(1)], now()).unwrap();
        assert_eq!(
            self_approved
                .executor
                .execute(state.clone(), &self_approved.approvals(), now())
                .unwrap_err()
                .code,
            ErrorCode::PolicyDenied
        );
        assert_eq!(
            self_approved
                .executor
                .execute(
                    state,
                    &[Command::Reserve(Box::new(self_approved.proof()))],
                    now()
                )
                .unwrap_err()
                .code,
            ErrorCode::PolicyDenied
        );

        let fixture = Fixture::new(chain, 1);
        let mut wrong_policy = fixture.proof();
        wrong_policy.package.policy.rules[0].max_amount_per_operation = Amount(2_000_000_000_000);
        wrong_policy.package.policy.administrative_signatures =
            common::admin_signatures(policy_hash(&wrong_policy.package.policy).unwrap());
        assert_eq!(
            fixture
                .executor
                .execute(
                    ready(&fixture),
                    &[Command::Reserve(Box::new(wrong_policy))],
                    now()
                )
                .unwrap_err()
                .code,
            ErrorCode::ScopeMismatch
        );
        let raw = authority(AuthorityCommand::Reserve {
            request: fixture.proof().request,
        });
        assert_eq!(
            fixture
                .executor
                .execute(ready(&fixture), &[raw], now())
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
        let observation = authority(AuthorityCommand::RecordObservation {
            family_id: fixture.proof().request.family_id,
            candidate_id: fixture.built.candidate.candidate_id.clone(),
            observation: ChainObservation::Conflict {
                sources: vec![],
                detail: "unverified observation".into(),
            },
        });
        assert_eq!(
            fixture
                .executor
                .execute(ready(&fixture), &[observation], now())
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
    }
}

#[test]
fn freeze_release_order_matches_real_authority_and_does_not_erase_issued_exposure() {
    let fixture = Fixture::new(Chain::Solana, 1);
    let proof = fixture.proof();
    let state = fixture
        .executor
        .execute(
            ready(&fixture),
            &[Command::Reserve(Box::new(proof.clone()))],
            now(),
        )
        .unwrap()
        .0;
    let release = fixture.release();
    let freeze = fixture.freeze();
    let (released_frozen, _, _) = fixture
        .executor
        .execute(state.clone(), &[release.clone(), freeze.clone()], now())
        .unwrap();
    let mut direct = state.authority.clone();
    for command in [&release, &freeze] {
        let Command::Authority(command) = command else {
            unreachable!()
        };
        direct = apply(&fixture.executor.authority, direct, *command.clone(), now())
            .unwrap()
            .0;
    }
    assert_eq!(
        canonical_bytes(&direct).unwrap(),
        canonical_bytes(&released_frozen.authority).unwrap()
    );
    assert_eq!(released_frozen.authority.issuance.len(), 1);
    assert!(released_frozen.authority.freeze.global_freeze.is_some());
    assert_eq!(
        released_frozen.authority.outstanding(
            &proof.request.vault_id,
            &BudgetKey::Asset {
                asset_id: fixture.built.package.asset.asset_id.clone()
            }
        ),
        Some(Amount(1_000_000))
    );
    assert_eq!(
        released_frozen.authority.outstanding(
            &proof.request.vault_id,
            &BudgetKey::NativeFee {
                network_id: fixture.built.package.asset.network_id.clone()
            }
        ),
        Some(Amount(5_000))
    );
    let (repeat, _, events) = fixture
        .executor
        .execute(
            released_frozen.clone(),
            std::slice::from_ref(&release),
            now(),
        )
        .unwrap();
    assert_eq!(repeat, released_frozen);
    assert!(events.is_empty());

    let frozen = fixture
        .executor
        .execute(state.clone(), std::slice::from_ref(&freeze), now())
        .unwrap()
        .0;
    assert_eq!(
        fixture
            .executor
            .execute(frozen.clone(), std::slice::from_ref(&release), now())
            .unwrap_err()
            .code,
        ErrorCode::Frozen
    );
    assert_eq!(
        fixture
            .executor
            .execute(state, &[freeze, release.clone()], now())
            .unwrap_err()
            .code,
        ErrorCode::Frozen
    );
    let Command::Authority(release) = release else {
        unreachable!()
    };
    assert_eq!(
        apply(
            &fixture.executor.authority,
            frozen.authority.clone(),
            *release,
            now()
        )
        .unwrap_err()
        .code,
        ErrorCode::Frozen
    );
    assert!(frozen.authority.issuance.is_empty());
    assert_eq!(
        frozen.authority.reservations[&proof.envelope.budget_reservation_id].state,
        ReservationState::Reserved
    );
}

#[test]
fn follower_sync_reopen_independent_floor_and_gap_replay_contract() {
    for chain in [Chain::Evm, Chain::Solana] {
        deterministic::Runner::default().start(move |context| async move {
            let fixture = Fixture::new(chain, 1);
            let committee = Committee::new();
            let genesis = fixture.genesis(&committee);
            let mut bootstrap = fixture.bootstrap();
            bootstrap.extend(fixture.approvals());
            let (first, state1) = fixture
                .executor
                .propose_block(
                    &genesis,
                    ReplicatedState::default(),
                    committee.context(&genesis, 1),
                    &bootstrap,
                    now(),
                    now(),
                )
                .unwrap();
            let (second, state2) = fixture
                .executor
                .propose_block(
                    &first,
                    state1.clone(),
                    committee.context(&first, 2),
                    &[Command::Reserve(Box::new(fixture.proof()))],
                    now(),
                    now(),
                )
                .unwrap();
            let (third, state3) = fixture
                .executor
                .propose_block(
                    &second,
                    state2.clone(),
                    committee.context(&second, 3),
                    &[fixture.release()],
                    now(),
                    now(),
                )
                .unwrap();
            let config = |partition: &str, floor| FollowerConfig {
                partition: partition.into(),
                executor: fixture.executor.clone(),
                trust: committee.trust.clone(),
                genesis: genesis.clone(),
                genesis_state: ReplicatedState::default(),
                minimum_floor: floor,
                local_now: now(),
            };
            let mut rng = TestRng::new(13);
            let mut follower = Follower::open(
                context.child("first_open"),
                config("finalized", FinalizedFloor::at(&genesis)),
                &mut rng,
            )
            .await
            .unwrap();
            assert!(follower.finalization().is_none());
            assert!(
                follower
                    .apply_finalized(&mut rng, second.clone(), committee.certify(&second), now())
                    .await
                    .is_err()
            );
            assert_eq!(follower.floor(), FinalizedFloor::at(&genesis));
            let wrong_root = AuthorityBlock::new(
                first.context(),
                first.height(),
                now(),
                Hash32([91; 32]),
                &first.commands().unwrap(),
            )
            .unwrap();
            let certificate = committee.certify(&wrong_root);
            committee
                .trust
                .verify(&mut rng, &wrong_root, &certificate)
                .unwrap();
            assert_eq!(
                follower
                    .apply_finalized(&mut rng, wrong_root, certificate, now())
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::UnverifiableTransaction
            );
            assert_eq!(follower.state(), &ReplicatedState::default());
            assert!(
                follower
                    .apply_finalized(&mut rng, first.clone(), committee.certify(&first), now())
                    .await
                    .unwrap()
            );
            assert_eq!(follower.state(), &state1);
            assert!(
                !follower
                    .apply_finalized(&mut rng, first.clone(), committee.certify(&first), now())
                    .await
                    .unwrap()
            );
            let mut bad_repeat = committee.certify(&first);
            bad_repeat.proposal.payload = genesis.digest();
            assert_eq!(
                follower
                    .apply_finalized(&mut rng, first.clone(), bad_repeat, now())
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidSignature
            );
            assert!(
                follower
                    .apply_finalized(&mut rng, second.clone(), committee.certify(&second), now())
                    .await
                    .unwrap()
            );
            let floor2 = follower.floor();
            assert_eq!(follower.state(), &state2);
            drop(follower);

            let mut follower = Follower::open(
                context.child("reopen_reserved"),
                config("finalized", floor2),
                &mut rng,
            )
            .await
            .unwrap();
            assert_eq!(follower.floor(), floor2);
            assert_eq!(follower.state(), &state2);
            assert_eq!(
                follower.finalization().unwrap().proposal.payload,
                second.digest()
            );
            assert!(
                follower
                    .apply_finalized(&mut rng, first.clone(), committee.certify(&first), now())
                    .await
                    .is_err()
            );
            assert_eq!(follower.floor(), floor2);
            assert!(
                follower
                    .apply_finalized(&mut rng, third.clone(), committee.certify(&third), now())
                    .await
                    .unwrap()
            );
            assert!(
                !follower
                    .apply_finalized(&mut rng, third.clone(), committee.certify(&third), now())
                    .await
                    .unwrap()
            );
            assert_eq!(follower.state(), &state3);
            assert_eq!(follower.state().authority.issuance.len(), 1);
            let floor3 = follower.floor();
            drop(follower);

            let follower = Follower::open(
                context.child("reopen_issued"),
                config("finalized", floor3),
                &mut rng,
            )
            .await
            .unwrap();
            assert_eq!(follower.floor(), floor3);
            assert_eq!(follower.state(), &state3);
            assert_eq!(
                follower.finalization().unwrap().proposal.payload,
                third.digest()
            );
            // Ordinary journal records paginate without fabricating ancestor
            // certificates or changing the already-synced authorization state.
            let mut cursor = FinalizedFloor::at(&genesis);
            for (index, expected) in [&first, &second, &third].into_iter().enumerate() {
                let page = follower.read_page(cursor).await.unwrap();
                assert_eq!(page.entries.len(), 1);
                assert!(page.entries[0].ancestors.is_empty());
                assert_eq!(page.entries[0].block.as_slice(), expected.encode().as_ref());
                assert_eq!(page.tip.block, page.entries[0].block);
                assert_eq!(page.more, index < 2);
                cursor = FinalizedFloor::at(expected);
            }
            let page = follower.read_page(cursor).await.unwrap();
            assert!(page.entries.is_empty());
            assert!(!page.more);
            assert_eq!(follower.state(), &state3);
            drop(follower);
            let wrong_floor = FinalizedFloor {
                height: floor3.height,
                digest: Hash32([81; 32]),
            };
            let result = Follower::open(
                context.child("wrong_floor"),
                config("finalized", wrong_floor),
                &mut rng,
            )
            .await;
            assert!(matches!(result, Err(error) if error.code == ErrorCode::RecoveryRequired));
            let result = Follower::open(
                context.child("missing_history"),
                config("lost-partition", floor3),
                &mut rng,
            )
            .await;
            assert!(matches!(result, Err(error) if error.code == ErrorCode::RecoveryRequired));
            let ahead = FinalizedFloor {
                height: floor3.height + 1,
                digest: floor3.digest,
            };
            let result = Follower::open(
                context.child("ahead_floor"),
                config("finalized", ahead),
                &mut rng,
            )
            .await;
            assert!(matches!(result, Err(error) if error.code == ErrorCode::RecoveryRequired));

            // Marshal may finalize ancestors through a descendant certificate.
            // No certificate for first/second exists in this independent log.
            let mut caught_up = Follower::open(
                context.child("ancestry"),
                config("ancestry", FinalizedFloor::at(&genesis)),
                &mut rng,
            )
            .await
            .unwrap();
            assert!(caught_up.verified_log().is_err());
            for blocks in [
                vec![third.clone()],
                vec![first.clone(), third.clone()],
                vec![second.clone(), first.clone(), third.clone()],
            ] {
                assert!(
                    caught_up
                        .apply_finalized_chain(&mut rng, blocks, committee.certify(&third), now())
                        .await
                        .is_err()
                );
                assert_eq!(caught_up.floor(), FinalizedFloor::at(&genesis));
                assert!(caught_up.verified_log().is_err());
            }
            let mut wrong_certificate = committee.certify(&third);
            wrong_certificate.proposal.payload = second.digest();
            assert!(
                caught_up
                    .apply_finalized_chain(
                        &mut rng,
                        vec![first.clone(), second.clone(), third.clone()],
                        wrong_certificate,
                        now()
                    )
                    .await
                    .is_err()
            );
            caught_up
                .apply_finalized_chain(
                    &mut rng,
                    vec![first.clone(), second.clone(), third.clone()],
                    committee.certify(&third),
                    now(),
                )
                .await
                .unwrap();
            assert_eq!(caught_up.floor(), FinalizedFloor::at(&third));
            assert_eq!(caught_up.state(), &state3);
            caught_up
                .verified_log()
                .unwrap()
                .authorize(&fixture.proof().envelope)
                .unwrap();
            for (floor, remaining) in [
                (FinalizedFloor::at(&genesis), 2),
                (FinalizedFloor::at(&first), 1),
                (FinalizedFloor::at(&second), 0),
            ] {
                let page = caught_up.read_page(floor).await.unwrap();
                assert_eq!(page.entries.len(), 1);
                assert_eq!(page.entries[0].ancestors.len(), remaining);
                assert_eq!(page.entries[0].block.as_slice(), third.encode().as_ref());
                assert_eq!(
                    page.entries[0].finalization.as_slice(),
                    committee.certify(&third).encode().as_ref()
                );
                assert!(!page.more);
            }
            for floor in [
                FinalizedFloor {
                    height: 0,
                    digest: Hash32([81; 32]),
                },
                FinalizedFloor {
                    height: 2,
                    digest: Hash32([81; 32]),
                },
                FinalizedFloor {
                    height: 3,
                    digest: Hash32([81; 32]),
                },
                FinalizedFloor {
                    height: 4,
                    digest: Hash32([81; 32]),
                },
            ] {
                assert!(caught_up.read_page(floor).await.is_err());
            }
            drop(caught_up);
            // An independent floor can fall inside the certified ancestry, not
            // just at a journal checkpoint. Replay must check its exact digest.
            let caught_up = Follower::open(
                context.child("ancestry_reopen"),
                config("ancestry", FinalizedFloor::at(&second)),
                &mut rng,
            )
            .await
            .unwrap();
            assert_eq!(caught_up.floor(), FinalizedFloor::at(&third));
            assert_eq!(caught_up.state(), &state3);
            committee
                .trust
                .verify(&mut rng, caught_up.tip(), caught_up.finalization().unwrap())
                .unwrap();
            caught_up
                .verified_log()
                .unwrap()
                .authorize(&fixture.proof().envelope)
                .unwrap();
            let page = caught_up
                .read_page(FinalizedFloor::at(&first))
                .await
                .unwrap();
            assert_eq!(
                page.entries[0].ancestors,
                vec![second.encode().to_vec().into()]
            );
            assert_eq!(page.entries[0].block.as_slice(), third.encode().as_ref());
            drop(caught_up);
            let wrong_middle = FinalizedFloor {
                height: second.height().get(),
                digest: Hash32([81; 32]),
            };
            let result = Follower::open(
                context.child("ancestry_wrong_floor"),
                config("ancestry", wrong_middle),
                &mut rng,
            )
            .await;
            assert!(matches!(result, Err(error) if error.code == ErrorCode::RecoveryRequired));
        });
    }
}
