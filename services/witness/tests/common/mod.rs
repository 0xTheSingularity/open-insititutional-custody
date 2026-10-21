//! Shared signed trust/checkpoint fixtures, with no test registration or runtime.
use ed25519_dalek::{Signer, SigningKey};
use oic_authorization_state::{CheckpointBody, SignedCheckpoint, checkpoint_hash};
use oic_domain_types::*;
use oic_membership::*;
use oic_service_witness::{ServiceKey, WitnessTrust};
use std::collections::BTreeMap;

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
pub fn signature(seed: u8, hash: Hash32) -> SignatureBytes {
    SignatureBytes {
        scheme: SchemeId::Ed25519Pure,
        bytes: key(seed).sign(hash.as_ref()).to_bytes().to_vec().into(),
    }
}
fn public(seed: u8) -> PublicKey {
    PublicKey {
        scheme: SchemeId::Ed25519Pure,
        bytes: key(seed).verifying_key().to_bytes().to_vec().into(),
    }
}
pub fn node_id(n: u8) -> NodeId {
    NodeId::unchecked(format!("node-{n}"))
}
fn service(seed: u8, n: u8, id: &str) -> ServiceKey {
    ServiceKey {
        node_id: node_id(n),
        key_id: KeyId::unchecked(id),
        key: key(seed).verifying_key(),
    }
}
pub fn sign_roster(body: RosterBody) -> SignedRoster {
    let hash = roster_hash(&body).unwrap();
    SignedRoster {
        body,
        signatures: vec![CredentialSignature {
            credential_id: CredentialId::unchecked("admin"),
            signature: signature(1, hash),
        }],
    }
}
pub fn trust() -> WitnessTrust {
    let nodes: Vec<_> = [
        Role::Authority,
        Role::Gateway,
        Role::Verifier,
        Role::Witness,
        Role::Verifier,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, role)| {
        let n = i as u8;
        Node {
            node_id: node_id(n),
            domain_id: TrustDomainId::unchecked(format!("domain-{n}")),
            roles: vec![role],
            transport_key: public(10 + n),
            attestation_key: (role == Role::Verifier).then(|| public(30 + n)),
            address: format!("127.0.0.1:{}", 9000 + i).parse().unwrap(),
            peer_class: if role == Role::Witness {
                PeerClass::Secondary
            } else {
                PeerClass::Primary
            },
            participant_keys: BTreeMap::new(),
            approved_build_hashes: vec![Hash32([42; 32])],
            signer_instance_generation: Epoch(1),
        }
    })
    .collect();
    let genesis = sign_roster(RosterBody {
        institution_id: InstitutionId::unchecked("institution"),
        environment_id: EnvironmentId::unchecked("test"),
        roster_epoch: 0,
        previous_roster_hash: Hash32::ZERO,
        genesis_hash: Hash32::ZERO,
        commonware_release: COMMONWARE_RELEASE.into(),
        wire_version: WIRE_VERSION,
        trust_domains: nodes
            .iter()
            .map(|n| TrustDomain {
                domain_id: n.domain_id.clone(),
                administrators: vec![CredentialId::unchecked("admin")],
                failure_domain_notes: "Independent IAM, hardware and recovery".into(),
            })
            .collect(),
        nodes,
        committees: vec![
            Committee {
                committee_id: CommitteeId::unchecked("authority"),
                kind: CommitteeKind::AuthorityD1,
                members: vec![node_id(0)],
                threshold: 1,
            },
            Committee {
                committee_id: CommitteeId::unchecked("verify"),
                kind: CommitteeKind::Verification,
                members: vec![node_id(2), node_id(4)],
                threshold: 2,
            },
        ],
        channel_acl: vec![ChannelSpec {
            channel: 30,
            sender_roles: vec![Role::Authority, Role::Gateway, Role::Verifier],
            receiver_roles: vec![Role::Witness],
            max_message_size: 65536,
            quota: 100,
        }],
        tolerated_domain_compromises: 1,
        activation: Activation {
            not_before: UnixSeconds(1),
            authority_commit_reference: None,
        },
    });
    let genesis_hash = roster_hash(&genesis.body).unwrap();
    let mut next = genesis.body.clone();
    next.roster_epoch = 1;
    next.previous_roster_hash = genesis_hash;
    next.genesis_hash = genesis_hash;
    next.activation = Activation {
        not_before: UnixSeconds(100),
        authority_commit_reference: Some(Hash32([77; 32])),
    };
    let next = sign_roster(next);
    WitnessTrust {
        institution_id: genesis.body.institution_id.clone(),
        environment_id: genesis.body.environment_id.clone(),
        witness_id: node_id(3),
        admins: AdminTrust {
            threshold: 1,
            credentials: BTreeMap::from([(CredentialId::unchecked("admin"), public(1))]),
        },
        committed_roster_hashes: BTreeMap::from([
            (0, genesis_hash),
            (1, roster_hash(&next.body).unwrap()),
        ]),
        rosters: vec![genesis, next],
        authority: service(60, 0, "receipt-key"),
        audits: vec![service(61, 0, "audit-key")],
        operations: service(62, 1, "operations-key"),
        policy_admin_keys: vec![(
            CredentialId::unchecked("policy-admin"),
            key(2).verifying_key(),
        )],
        policy_admin_quorum: 1,
    }
}
pub fn checkpoint(sequence: u64, state: u8) -> SignedCheckpoint {
    let body = CheckpointBody {
        institution_id: InstitutionId::unchecked("institution"),
        environment_id: EnvironmentId::unchecked("test"),
        authority_epoch: Epoch(2),
        commit_sequence: sequence,
        state_hash: Hash32([state; 32]),
    };
    let sig = signature(60, checkpoint_hash(&body).unwrap());
    SignedCheckpoint {
        body,
        authority_key_id: KeyId::unchecked("receipt-key"),
        signature: sig,
    }
}
