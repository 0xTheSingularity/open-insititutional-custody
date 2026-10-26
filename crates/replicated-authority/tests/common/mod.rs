//! Public D2 fixtures, shared with runtime tests. Native keys are dev 1-of-1;
//! no threshold signing or D1 receipt signing is performed here.
#![allow(dead_code)]

#[path = "../../../signer/tests/common/mod.rs"]
pub mod signer;

use commonware_consensus::{
    CertifiableBlock,
    simplex::types::{Finalize, Proposal},
    types::{Epoch as ConsensusEpoch, Height, Round, View},
};
use commonware_cryptography::{Digestible, Hasher, Sha256, Signer as _, ed25519::PrivateKey};
use commonware_parallel::Sequential;
use commonware_utils::non_empty;
use ed25519_dalek::{Signer as _, SigningKey};
use oic_approval_verifier::{ApproverCredential, sign_grant};
use oic_authorization_state::*;
use oic_canonical_encoding::domain_hash;
use oic_crypto_provider::{CryptoProvider, KeygenCeremony};
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_domain_types::*;
use oic_membership::*;
use oic_policy_kernel::{Decision, destination_hash, intent_hash, policy_hash};
use oic_replicated_authority::*;
use oic_service_builder::{BuildInputs, BuiltCandidate, build, envelope_body};
use rand::{SeedableRng, rngs::StdRng};
use std::{collections::BTreeMap, sync::Arc};

pub use signer::{NOW, now};

#[derive(Clone, Copy, Debug)]
pub enum Chain {
    Evm,
    Solana,
}

/// Admin-quorum enrollment of every record the replica's registry holds.
#[allow(dead_code)]
pub fn registry_enrollment(r: &oic_replicated_authority::Registry) -> MaterialEnrollment {
    let mut e = oic_policy_kernel::material_enrollment(
        r.vaults[0].institution_id.clone(),
        r.vaults[0].environment_id.clone(),
        Epoch(1),
        &r.assets,
        &r.wallets,
        &r.vaults,
        &r.keys,
    )
    .unwrap();
    e.administrative_signatures = admin_signatures(oic_policy_kernel::material_enrollment_hash(&e).unwrap());
    e
}

pub fn admin_signatures(hash: Hash32) -> Vec<CredentialSignature> {
    [1, 2]
        .into_iter()
        .map(|seed| CredentialSignature {
            credential_id: CredentialId::unchecked(format!("admin-{seed}")),
            signature: SignatureBytes {
                scheme: SchemeId::Ed25519Pure,
                bytes: SigningKey::from_bytes(&[seed; 32])
                    .sign(&hash.0)
                    .to_bytes()
                    .to_vec()
                    .into(),
            },
        })
        .collect()
}

pub fn authority(command: AuthorityCommand) -> Command {
    Command::Authority(Box::new(command))
}

pub fn approver(index: u8) -> ApproverCredential {
    ApproverCredential {
        credential_id: CredentialId::unchecked(format!("approver-{index}")),
        person_id: CredentialId::unchecked(format!("person-{index}")),
        verifying_key: SigningKey::from_bytes(&[60 + index; 32])
            .verifying_key()
            .into(),
        role: if index == 1 {
            ApprovalRole::TreasuryApprover
        } else {
            ApprovalRole::SecurityApprover
        },
    }
}

pub struct Fixture {
    pub executor: Executor,
    pub profile: oic_adapter_api::ChainProfile,
    pub built: BuiltCandidate,
    pub grants: Vec<ApprovalGrant>,
}

impl Fixture {
    pub fn new(chain: Chain, required: u8) -> Self {
        Self::with_inputs(chain, required, |_| {})
    }

    /// Mutate real builder inputs before policy/destination signatures, native
    /// construction and grants, allowing internally consistent hostile inputs.
    pub fn with_inputs(chain: Chain, required: u8, mutate: impl FnOnce(&mut BuildInputs)) -> Self {
        assert!(required <= 2);
        let scheme = match chain {
            Chain::Evm => SchemeId::EcdsaSecp256k1Keccak256Prehashed,
            Chain::Solana => SchemeId::Ed25519Pure,
        };
        let provider =
            DevSingleKeyProvider::new(scheme, [90; 32], Box::new(StdRng::seed_from_u64(917)))
                .unwrap();
        let (profile, adapter, materials): (_, Arc<dyn oic_adapter_api::ChainAdapter>, _) =
            match chain {
                Chain::Evm => {
                    let (key, _) = signer::evm_key(&provider, &signer::pid(1));
                    (
                        signer::evm_profile(),
                        Arc::new(oic_adapter_evm::EvmAdapter),
                        signer::evm_materials(&key, required),
                    )
                }
                Chain::Solana => {
                    let key = provider
                        .generate_distributed_key(&KeygenCeremony {
                            key_id: KeyId::unchecked("native-sol-key"),
                            key_epoch: Epoch(1),
                            institution_id: signer::inst(),
                            environment_id: signer::env_id(),
                            participants: vec![signer::pid(1)],
                            threshold: 1,
                            networks: vec![NetworkId::unchecked("solana-devnet")],
                            recovery_profile: "test-dev".into(),
                        })
                        .unwrap()
                        .descriptor;
                    (
                        signer::sol_profile(),
                        Arc::new(oic_adapter_solana::SolanaAdapter),
                        signer::sol_materials(&key, required, ApprovalMode::ExactCandidate),
                    )
                }
            };
        let mut inputs = BuildInputs {
            intent: materials.intent,
            vault: materials.vault,
            wallet: materials.wallet,
            key: materials.key,
            asset: materials.asset,
            destination: materials.destination,
            profile: profile.clone(),
            policy: materials.policy,
            evidence: materials.evidence,
            candidate_id: CandidateId::unchecked("candidate-d2"),
            candidate_revision: 1,
            operation_family_id: signer::family(),
            built_at: UnixSeconds(signer::T0 + 10),
        };
        mutate(&mut inputs);
        inputs.policy.administrative_signatures =
            admin_signatures(policy_hash(&inputs.policy).unwrap());
        inputs.destination.administrative_signatures =
            admin_signatures(destination_hash(&inputs.destination).unwrap());
        let built = build(adapter.as_ref(), &inputs).unwrap();
        let grants = (1..=required)
            .map(|index| {
                let credential = approver(index);
                sign_grant(
                    &SigningKey::from_bytes(&[60 + index; 32]),
                    ApprovalGrantBody {
                        grant_id: GrantId::unchecked(format!("grant-d2-{index}")),
                        institution_id: signer::inst(),
                        environment_id: signer::env_id(),
                        vault_id: inputs.vault.vault_id.clone(),
                        intent_id: inputs.intent.intent_id.clone(),
                        intent_hash: intent_hash(&inputs.intent).unwrap(),
                        policy_id: inputs.policy.policy_id.clone(),
                        policy_epoch: inputs.policy.policy_epoch,
                        scope: GrantScope::ExactCandidate {
                            candidate_id: built.candidate.candidate_id.clone(),
                            candidate_revision: 1,
                            preview_hash: built.preview_hash,
                        },
                        approver_credential_id: credential.credential_id,
                        approver_role: credential.role,
                        issued_at: UnixSeconds(signer::T0),
                        expires_at: UnixSeconds(NOW + 600),
                    },
                )
                .unwrap()
            })
            .collect();
        let executor = Executor {
            authority: AuthorityConfig {
                institution_id: signer::inst(),
                environment_id: signer::env_id(),
                authority_key_id: KeyId::unchecked("d2-no-receipt-key"),
                admin_keys: (1..=3)
                    .map(|seed| {
                        (
                            CredentialId::unchecked(format!("admin-{seed}")),
                            SigningKey::from_bytes(&[seed; 32]).verifying_key(),
                        )
                    })
                    .collect(),
                admin_quorum: 2,
                freeze_responders: vec![(
                    CredentialId::unchecked("responder"),
                    SigningKey::from_bytes(&[77; 32]).verifying_key(),
                )],
                release_receipt_ttl_seconds: 60,
                max_clock_skew_seconds: 30,
            },
            registry: Registry {
                profiles: vec![inputs.profile.clone()],
                vaults: vec![inputs.vault],
                wallets: vec![inputs.wallet],
                keys: vec![inputs.key],
                assets: vec![inputs.asset],
                destinations: vec![inputs.destination],
            },
            adapters: BTreeMap::from([(profile.adapter_id.clone(), adapter)]),
        };
        Self {
            executor,
            profile,
            built,
            grants,
        }
    }

    /// Activate signed policy, register intent, and admin-quorum-enroll keys.
    /// Approvals remain a separate ordered step, never inferred from signatures.
    pub fn bootstrap(&self) -> Vec<Command> {
        let mut commands = vec![
            authority(AuthorityCommand::SetPolicy {
                bundle: self.built.package.policy.clone(),
            }),
            authority(AuthorityCommand::RegisterIntent {
                intent: self.built.package.intent.clone(),
                intent_hash: intent_hash(&self.built.package.intent).unwrap(),
                key: IdempotencyKey {
                    institution_id: signer::inst(),
                    route: "intents".into(),
                    key: "d2-1".into(),
                },
            }),
        ];
        for index in 1..=2 {
            let credential = approver(index);
            let proposal = CredentialChange {
                institution_id: signer::inst(),
                environment_id: signer::env_id(),
                credential_id: credential.credential_id.clone(),
                previous_change: 0,
                credential: Some(credential),
            };
            let signatures = admin_signatures(proposal.hash().unwrap());
            commands.push(authority(AuthorityCommand::ChangeCredential {
                proposal,
                signatures,
            }));
        }
        commands
    }

    pub fn approvals(&self) -> Vec<Command> {
        self.grants
            .iter()
            .cloned()
            .map(|grant| {
                authority(AuthorityCommand::Approve {
                    intent: Box::new(self.built.package.intent.clone()),
                    grant,
                })
            })
            .collect()
    }

    pub fn proof(&self) -> ReserveCandidate {
        let p = &self.built.package;
        let envelope = envelope_body(
            &self.built,
            self.executor.adapters[&self.profile.adapter_id].as_ref(),
            &self.profile,
            self.grants.clone(),
            signer::sid("d2-native-session"),
            p.key.participants.clone(),
            UnixSeconds(signer::DEADLINE),
        )
        .unwrap();
        let request = ReserveRequest {
            family_id: envelope.operation_family_id.clone(),
            candidate_id: envelope.candidate_id.clone(),
            candidate_revision: envelope.candidate_revision,
            vault_id: envelope.vault_id.clone(),
            intent_id: envelope.intent_id.clone(),
            policy_epoch: envelope.policy_epoch,
            policy_hash: envelope.policy_hash,
            claims: self.built.verified.claims.clone(),
            grants: self.grants.clone(),
            envelope_body_hash: domain_hash(domains::AUTHORIZATION, &envelope).unwrap(),
            signer_session_id: envelope.signer_session_id.clone(),
            issuance_deadline: envelope.issuance_deadline,
            policy_decision: Decision::Allow {
                rule_id: p.policy.rules[0].rule_id.clone(),
            },
            exposure_limits: self
                .built
                .verified
                .claims
                .asset_outflows
                .iter()
                .flat_map(|outflow| {
                    p.policy.rules[0]
                        .rolling_limits
                        .iter()
                        .map(move |limit| (outflow.asset_id.clone(), limit.clone()))
                })
                .collect(),
        };
        ReserveCandidate {
            request,
            envelope,
            package: p.clone(),
        }
    }

    pub fn release(&self) -> Command {
        let proof = self.proof();
        authority(AuthorityCommand::Release {
            request: ReleaseRequest {
                reservation_id: proof.envelope.budget_reservation_id,
                reservation_version: 1,
                envelope_body_hash: proof.request.envelope_body_hash,
                signer_session_id: proof.request.signer_session_id,
                expected_policy_epoch: proof.request.policy_epoch,
                freshness: FreshnessContext { now: now() },
            },
        })
    }

    pub fn freeze(&self) -> Command {
        let proposal = FreezeProposal::new(
            signer::inst(),
            signer::env_id(),
            FreezeScope::Global,
            CredentialId::unchecked("responder"),
            "D2 contract",
        );
        let hash = proposal.hash().unwrap();
        authority(AuthorityCommand::Freeze {
            scope: proposal.scope,
            by: proposal.by.clone(),
            reason: proposal.reason.clone(),
            signature: SignatureBytes {
                scheme: SchemeId::Ed25519Pure,
                bytes: SigningKey::from_bytes(&[77; 32])
                    .sign(&hash.0)
                    .to_bytes()
                    .to_vec()
                    .into(),
            },
        })
    }

    pub fn genesis(&self, committee: &Committee) -> AuthorityBlock {
        AuthorityBlock::new(
            ConsensusContext {
                round: Round::new(ConsensusEpoch::new(0), View::new(0)),
                leader: committee.keys[0].1.public_key(),
                parent: (
                    View::new(0),
                    Sha256::hash(&[b"D2 independent genesis parent"]),
                ),
            },
            Height::new(0),
            now(),
            self.executor
                .state_hash(&ReplicatedState::default())
                .unwrap(),
            &[],
        )
        .unwrap()
    }
}

pub struct Committee {
    pub keys: Vec<(NodeId, PrivateKey)>,
    pub trust: FinalityTrust,
    pub roster: SignedRoster,
    pub admins: AdminTrust,
    pub anchor: Hash32,
}

impl Default for Committee {
    fn default() -> Self {
        Self::new()
    }
}

impl Committee {
    pub fn new() -> Self {
        Self::with_seed(700)
    }

    pub fn with_seed(seed: u64) -> Self {
        let keys: Vec<_> = (0..4)
            .map(|i| {
                (
                    NodeId::unchecked(format!("replica-{i}")),
                    PrivateKey::from_seed(seed + i),
                )
            })
            .collect();
        let nodes: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, (id, key))| Node {
                node_id: id.clone(),
                domain_id: TrustDomainId::unchecked(format!("replica-domain-{i}")),
                roles: vec![Role::Authority],
                transport_key: PublicKey {
                    scheme: SchemeId::Ed25519Pure,
                    bytes: SigningKey::from_bytes(&[110 + i as u8; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec()
                        .into(),
                },
                consensus_key: Some(PublicKey {
                    scheme: SchemeId::Ed25519Pure,
                    bytes: key.public_key().as_ref().to_vec().into(),
                }),
                attestation_key: None,
                address: format!("127.0.0.1:{}", 18000 + i).parse().unwrap(),
                peer_class: PeerClass::Primary,
                participant_keys: BTreeMap::new(),
                approved_build_hashes: vec![],
                signer_instance_generation: Epoch(0),
            })
            .collect();
        let body = RosterBody {
            institution_id: signer::inst(),
            environment_id: signer::env_id(),
            roster_epoch: 0,
            previous_roster_hash: Hash32::ZERO,
            genesis_hash: Hash32::ZERO,
            commonware_release: COMMONWARE_RELEASE.into(),
            wire_version: WIRE_VERSION,
            trust_domains: nodes
                .iter()
                .map(|node| TrustDomain {
                    domain_id: node.domain_id.clone(),
                    administrators: vec![CredentialId::unchecked(format!(
                        "owner-{}",
                        node.node_id
                    ))],
                    failure_domain_notes: "Four independently controlled replica domains".into(),
                })
                .collect(),
            committees: vec![oic_membership::Committee {
                committee_id: CommitteeId::unchecked("D2"),
                kind: CommitteeKind::AuthorityD2 { faults: 1 },
                members: keys.iter().map(|(id, _)| id.clone()).collect(),
                threshold: 3,
            }],
            nodes,
            channel_acl: vec![0, 1, 2, 3, 4, 5]
                .into_iter()
                .map(|channel| ChannelSpec {
                    channel,
                    sender_roles: vec![Role::Authority],
                    receiver_roles: vec![Role::Authority],
                    max_message_size: 262144,
                    quota: 100,
                })
                .collect(),
            tolerated_domain_compromises: 1,
            activation: Activation {
                not_before: now(),
                authority_commit_reference: None,
            },
        };
        let anchor = roster_hash(&body).unwrap();
        let roster = SignedRoster {
            signatures: admin_signatures(anchor),
            body,
        };
        let admins = AdminTrust {
            threshold: 2,
            credentials: (1..=3)
                .map(|i| {
                    (
                        CredentialId::unchecked(format!("admin-{i}")),
                        PublicKey {
                            scheme: SchemeId::Ed25519Pure,
                            bytes: SigningKey::from_bytes(&[i; 32])
                                .verifying_key()
                                .to_bytes()
                                .to_vec()
                                .into(),
                        },
                    )
                })
                .collect(),
        };
        let trust = FinalityTrust::from_genesis(
            roster.clone(),
            &admins,
            &signer::inst(),
            &signer::env_id(),
            anchor,
            now(),
        )
        .unwrap();
        Self {
            keys,
            trust,
            roster,
            admins,
            anchor,
        }
    }

    pub fn context(&self, parent: &AuthorityBlock, view: u64) -> ConsensusContext {
        ConsensusContext {
            round: Round::new(self.trust.epoch(), View::new(view)),
            leader: self.keys[view as usize % 4].1.public_key(),
            parent: (parent.context().round.view(), parent.digest()),
        }
    }

    pub fn certify(&self, block: &AuthorityBlock) -> AuthorityFinalization {
        let context = block.context();
        let proposal = Proposal::new(context.round, context.parent.0, block.digest());
        let votes: Vec<_> = self.keys[..3]
            .iter()
            .map(|(id, key)| {
                Finalize::sign(
                    &self.trust.signer(id, key.clone()).unwrap(),
                    proposal.clone(),
                )
                .unwrap()
            })
            .collect();
        AuthorityFinalization::from_finalizes(
            &self.trust.verifier(),
            non_empty![@votes.iter()],
            &Sequential,
        )
        .unwrap()
    }
}
