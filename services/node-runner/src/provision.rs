//! DEVELOPMENT ONLY provisioning for the reference D1 topology.
//!
//! One command writes every node's directory on one machine, so by
//! construction nothing here is an independent production domain (RFC 0002
//! §9). Production provisioning happens per security domain and is out of
//! scope for this runner. Secrets are written once, mode 0600, under a
//! mode 0700 directory, and never printed.

use crate::files::{self, NodeConfig, ProvisionedRoots, Role};
use ed25519_dalek::SigningKey;
use oic_adapter_api::ChainAdapter as _;
use oic_crypto_provider::{CryptoProvider as _, KeygenCeremony};
use oic_crypto_provider_frost_ed25519::{run_dkg, FrostEd25519Provider};
use oic_domain_types::*;
use oic_membership::{Activation, AdminTrust, ChannelSpec, Committee, CommitteeKind, Node, PeerClass, RosterBody, SignedRoster, TrustDomain, roster_hash};
use rand::rngs::OsRng;
use rand::RngCore as _;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;

pub const SIGNERS: usize = 3;
pub const GATEWAY: usize = 3;
pub const AUTHORITY: usize = 4;
pub const NODES: usize = 5;

fn random_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

fn random_secret() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn public(key: &SigningKey) -> PublicKey {
    PublicKey { scheme: SchemeId::Ed25519Pure, bytes: key.verifying_key().to_bytes().to_vec().into() }
}

/// Write one directory per node under `out`. `addresses` must name one
/// listen address per node; the roster is signed over exactly those.
pub fn provision(out: &Path, addresses: &[SocketAddr], now: UnixSeconds) -> OicResult<()> {
    if addresses.len() != NODES {
        return Err(OicError::invalid_request(format!("the reference topology has {NODES} nodes; got {} addresses", addresses.len())));
    }
    let io = |e: std::io::Error| OicError::internal(format!("provisioning write failed: {e}"));
    std::fs::create_dir_all(out).map_err(io)?;

    // Identity and trust material. All of it is generated here, on one
    // machine, which is exactly why this is a development profile.
    let transport_keys: Vec<SigningKey> = (0..NODES).map(|_| random_key()).collect();
    let peer_keys: Vec<SigningKey> = (0..SIGNERS).map(|_| random_key()).collect();
    let attestation_keys: Vec<SigningKey> = (0..SIGNERS).map(|_| random_key()).collect();
    let audit_keys: Vec<SigningKey> = (0..SIGNERS).map(|_| random_key()).collect();
    let operator_keys: Vec<SigningKey> = (0..SIGNERS).map(|_| random_key()).collect();
    let authority_key = random_key();
    let admin_keys: Vec<(CredentialId, SigningKey)> =
        (1..=3u8).map(|n| (CredentialId::unchecked(format!("dev-admin-{n}")), random_key())).collect();

    // Distributed key generation across the three signer providers. The
    // sealing keys are per-signer secrets; the group key never exists.
    let sealing: Vec<[u8; 32]> = (0..SIGNERS).map(|_| random_secret()).collect();
    let providers: Vec<FrostEd25519Provider> = (0..SIGNERS)
        .map(|i| FrostEd25519Provider::with_os_rng(files::participant(i), sealing[i]))
        .collect::<OicResult<Vec<_>>>()?;
    let ceremony = KeygenCeremony {
        key_id: files::key_id(),
        key_epoch: Epoch(1),
        institution_id: files::institution(),
        environment_id: files::environment(),
        participants: (0..SIGNERS).map(files::participant).collect(),
        threshold: 2,
        networks: vec![NetworkId::unchecked("dev-reference")],
        recovery_profile: "development-only".into(),
    };
    let dkg = run_dkg(&providers.iter().collect::<Vec<_>>(), &ceremony)?;

    let adapter = oic_adapter_solana::SolanaAdapter;
    let build_hash = adapter.manifest().verifier_build_hash;
    let nodes: Vec<Node> = (0..NODES)
        .map(|i| Node {
            node_id: files::node_id(i),
            domain_id: TrustDomainId::unchecked(format!("dev-domain-{i}")),
            roles: vec![files::role_of(i).membership_role()],
            transport_key: public(&transport_keys[i]),
            consensus_key: None,
            attestation_key: (i < SIGNERS).then(|| public(&attestation_keys[i])),
            address: addresses[i],
            peer_class: PeerClass::Primary,
            participant_keys: if i < SIGNERS {
                BTreeMap::from([(files::participant(i), public(&peer_keys[i]))])
            } else {
                BTreeMap::new()
            },
            approved_build_hashes: if i < SIGNERS { vec![build_hash] } else { vec![] },
            signer_instance_generation: Epoch(1),
        })
        .collect();
    let all = vec![oic_membership::Role::Gateway, oic_membership::Role::Signer, oic_membership::Role::Authority];
    let acl = |channel, sender_roles, receiver_roles| ChannelSpec { channel, sender_roles, receiver_roles, max_message_size: 65536, quota: 100 };
    let body = RosterBody {
        institution_id: files::institution(),
        environment_id: files::environment(),
        roster_epoch: 0,
        previous_roster_hash: Hash32::ZERO,
        genesis_hash: Hash32::ZERO,
        commonware_release: oic_membership::COMMONWARE_RELEASE.into(),
        wire_version: oic_membership::WIRE_VERSION,
        trust_domains: nodes
            .iter()
            .map(|n| TrustDomain {
                domain_id: n.domain_id.clone(),
                administrators: vec![admin_keys[0].0.clone()],
                failure_domain_notes: "DEVELOPMENT ONLY: one machine, no independent domains".into(),
            })
            .collect(),
        nodes,
        committees: vec![
            Committee {
                committee_id: CommitteeId::unchecked("dev-chain-key"),
                kind: CommitteeKind::Key {
                    key_id: files::key_id(),
                    key_epoch: Epoch(1),
                    participants: (0..SIGNERS).map(files::participant).collect(),
                    backend: providers[0].capabilities(),
                },
                members: (0..SIGNERS).map(files::node_id).collect(),
                threshold: 2,
            },
            Committee {
                committee_id: CommitteeId::unchecked("dev-authority"),
                kind: CommitteeKind::AuthorityD1,
                members: vec![files::node_id(AUTHORITY)],
                threshold: 1,
            },
        ],
        channel_acl: vec![
            acl(0, all.clone(), all),
            acl(10, vec![oic_membership::Role::Gateway, oic_membership::Role::Signer], vec![oic_membership::Role::Gateway, oic_membership::Role::Signer]),
            acl(12, vec![oic_membership::Role::Gateway, oic_membership::Role::Authority], vec![oic_membership::Role::Gateway, oic_membership::Role::Authority]),
            acl(20, vec![oic_membership::Role::Signer], vec![oic_membership::Role::Signer]),
        ],
        tolerated_domain_compromises: 1,
        activation: Activation { not_before: now, authority_commit_reference: None },
    };
    let hash = roster_hash(&body)?;
    let signatures = admin_keys[..2]
        .iter()
        .map(|(id, key)| {
            use ed25519_dalek::Signer as _;
            CredentialSignature {
                credential_id: id.clone(),
                signature: SignatureBytes { scheme: SchemeId::Ed25519Pure, bytes: key.sign(hash.as_ref()).to_bytes().to_vec().into() },
            }
        })
        .collect();
    let roster = SignedRoster { body, signatures };
    let admins = AdminTrust {
        threshold: 2,
        credentials: admin_keys.iter().map(|(id, key)| (id.clone(), public(key))).collect(),
    };
    let roots = ProvisionedRoots {
        authority_key: authority_key.verifying_key().to_bytes(),
        admins: admin_keys.iter().map(|(id, key)| (id.clone(), key.verifying_key().to_bytes())).collect(),
        quorum: 2,
        builds: BTreeMap::from([(adapter.manifest().adapter_id, vec![build_hash])]),
        // This topology provisions a key, but no payment records. Empty
        // asset/wallet/vault sets keep those records unenrolled.
        material_enrollment: oic_policy_kernel::sign_material_enrollment(
            oic_policy_kernel::material_enrollment(files::institution(), files::environment(), Epoch(1), [], [], [], [&dkg.descriptor], [])?,
            &admin_keys[..2],
        )?,
        skew: 30,
    };

    for index in 0..NODES {
        let dir = out.join(format!("node-{index}"));
        files::private_dir(&dir)?;
        files::write_json(
            &dir.join("node.json"),
            &NodeConfig { role: files::role_of(index), index, provisioned_at: now, development_only: true },
        )?;
        files::write_canonical(&dir.join("roster.bin"), &roster)?;
        files::write_canonical(&dir.join("admins.bin"), &(admins.threshold, admins.credentials.clone()))?;
        files::write_secret(&dir.join("transport.key"), &transport_keys[index].to_bytes())?;
        match files::role_of(index) {
            Role::Signer => {
                files::write_secret(&dir.join("sealing.key"), &sealing[index])?;
                files::write_secret(&dir.join("peer.key"), &peer_keys[index].to_bytes())?;
                files::write_secret(&dir.join("audit.key"), &audit_keys[index].to_bytes())?;
                files::write_secret(&dir.join("share.sealed"), dkg.sealed_shares[index].1.as_slice())?;
                files::write_canonical(&dir.join("descriptor.bin"), &dkg.descriptor)?;
                files::write_canonical(&dir.join("roots.bin"), &roots)?;
                files::write_secret(&dir.join("operator.pub"), &operator_keys[index].verifying_key().to_bytes())?;
            }
            Role::Authority => {
                files::write_secret(&dir.join("authority.key"), &authority_key.to_bytes())?;
            }
            Role::Gateway => {}
        }
    }
    // DEVELOPMENT ONLY: keep the admin credential keys beside the topology
    // so the readmit ceremony can sign roster updates. Production admins
    // are people with their own credentials; no such directory may exist.
    let ceremony = out.join("admin-ceremony");
    files::private_dir(&ceremony)?;
    for (n, (_, key)) in admin_keys.iter().enumerate() {
        files::write_secret(&ceremony.join(format!("dev-admin-{}.key", n + 1)), &key.to_bytes())?;
    }
    println!("DEVELOPMENT ONLY: provisioned {NODES} node directories under {}", out.display());
    println!("roster hash {}", hash.to_hex());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oic_signer::{InMemoryGenerationStore, Signer, SignerIdentity};
    use std::sync::Arc;

    fn provisioned() -> tempfile::TempDir {
        let out = tempfile::tempdir().unwrap();
        let addresses: Vec<_> = (0..NODES).map(|i| SocketAddr::from(([127, 0, 0, 1], 20000 + i as u16))).collect();
        provision(out.path(), &addresses, UnixSeconds(1_000)).unwrap();
        out
    }

    fn open(roots: ProvisionedRoots) -> Result<(), ErrorCode> {
        Signer::open(
            SignerIdentity {
                participant_id: files::participant(0),
                institution_id: files::institution(),
                environment_id: files::environment(),
            },
            roots.into_roots().unwrap(),
            BTreeMap::new(),
            Arc::new(FrostEd25519Provider::with_os_rng(files::participant(0), [0; 32]).unwrap()),
            Arc::new(oic_one_time_state_ledger::InMemoryLedger::new()),
            Arc::new(InMemoryGenerationStore::new()),
        )
        .map(|_| ())
        .map_err(|e| e.code)
    }

    #[test]
    fn provisioned_roots_preserve_the_signed_key_enrollment() {
        let out = provisioned();
        for index in 0..SIGNERS {
            let dir = out.path().join(format!("node-{index}"));
            let provisioned: ProvisionedRoots = files::read_canonical(&dir, "roots.bin").unwrap();
            let descriptor: KeyDescriptor = files::read_canonical(&dir, "descriptor.bin").unwrap();
            let enrollment = provisioned.material_enrollment.clone();
            let roots = provisioned.into_roots().unwrap();
            assert_eq!(roots.enrolled_materials.as_ref(), Some(&enrollment));
            assert_eq!(enrollment.keys, [oic_policy_kernel::key_descriptor_hash(&descriptor).unwrap()].into());
            assert!(enrollment.assets.is_empty() && enrollment.wallets.is_empty() && enrollment.vaults.is_empty());
            oic_policy_kernel::verify_material_enrollment_admin_signatures(&enrollment, &roots.admin_keys, roots.admin_quorum).unwrap();
        }
    }

    #[test]
    fn provisioned_enrollment_is_checked_by_signer_open() {
        let out = provisioned();
        let dir = out.path().join("node-0");
        let roots = || files::read_canonical::<ProvisionedRoots>(&dir, "roots.bin").unwrap();
        assert_eq!(open(roots()), Ok(()));

        let mut unsigned = roots();
        unsigned.material_enrollment.administrative_signatures.clear();
        assert_eq!(open(unsigned), Err(ErrorCode::InvalidSignature));

        let mut below_quorum = roots();
        below_quorum.material_enrollment.administrative_signatures.truncate(1);
        assert_eq!(open(below_quorum), Err(ErrorCode::InvalidSignature));

        let mut tampered = roots();
        tampered.material_enrollment.assets.insert(Hash32([0xaa; 32]));
        assert_eq!(open(tampered), Err(ErrorCode::InvalidSignature));

        let admin_dir = out.path().join("admin-ceremony");
        let admins: Vec<_> = (1..=2)
            .map(|i| {
                (
                    CredentialId::unchecked(format!("dev-admin-{i}")),
                    SigningKey::from_bytes(&files::read_key32(&admin_dir, &format!("dev-admin-{i}.key")).unwrap()),
                )
            })
            .collect();
        for foreign_institution in [true, false] {
            let mut foreign = roots();
            if foreign_institution {
                foreign.material_enrollment.institution_id = InstitutionId::unchecked("other-institution");
            } else {
                foreign.material_enrollment.environment_id = EnvironmentId::unchecked("other-environment");
            }
            foreign.material_enrollment = oic_policy_kernel::sign_material_enrollment(foreign.material_enrollment, &admins).unwrap();
            assert_eq!(open(foreign), Err(ErrorCode::InvalidRequest));
        }
    }
}
