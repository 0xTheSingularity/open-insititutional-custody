use crate::{storage::*, *};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use oic_crypto_provider::{CryptoProvider, KeygenCeremony};
use oic_crypto_provider_dev::DevSingleKeyProvider;
use oic_crypto_provider_frost_ed25519::{run_dkg, FrostEd25519Provider};
use oic_policy_kernel::{destination_hash, policy_hash};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub(crate) fn inst() -> InstitutionId {
    InstitutionId::unchecked("local-institution")
}
pub(crate) fn environment() -> EnvironmentId {
    // The kernel accepts DevelopmentSimulator evidence only in this scope.
    EnvironmentId::unchecked("dev")
}
pub(crate) fn vault_id() -> VaultId {
    VaultId::unchecked("operating")
}
pub(crate) fn proposer() -> CredentialId {
    CredentialId::unchecked("local-proposer")
}
pub(crate) fn approver() -> CredentialId {
    CredentialId::unchecked("independent-approver")
}
pub(crate) fn authority_key_id() -> KeyId {
    KeyId::unchecked("local-d1-authority")
}
pub(crate) fn seed() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
fn bearer() -> String {
    hex::encode(seed())
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Secrets {
    pub authority: [u8; 32],
    pub events: [u8; 32],
    pub sealing: Vec<[u8; 32]>,
    pub console: String,
    pub reader: String,
    pub approval: String,
    pub operator: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Provisioned {
    pub schema_version: u16,
    pub genesis: UnixSeconds,
    pub simulator_seeds: ([u8; 32], [u8; 32]),
    pub admins: Vec<(CredentialId, Bytes)>,
    pub approver_public_key: Bytes,
    pub keys: Vec<KeyDescriptor>,
    pub sealed: Vec<Vec<(ParticipantId, Bytes)>>,
    pub wallets: Vec<ChainWallet>,
    pub assets: Vec<Asset>,
    pub destinations: Vec<CounterpartyDestination>,
    pub profiles: Vec<oic_adapter_api::ChainProfile>,
    pub policy: PolicyBundle,
}

pub(crate) fn admins(p: &Provisioned) -> OicResult<Vec<(CredentialId, VerifyingKey)>> {
    p.admins
        .iter()
        .map(|(id, k)| {
            Ok((
                id.clone(),
                VerifyingKey::from_bytes(k.as_slice().try_into().map_err(io)?).map_err(io)?,
            ))
        })
        .collect()
}
pub(crate) fn approver_credentials(
    p: &Provisioned,
) -> OicResult<Vec<oic_approval_verifier::ApproverCredential>> {
    Ok(vec![oic_approval_verifier::ApproverCredential {
        credential_id: approver(),
        person_id: approver(),
        verifying_key: VerifyingKey::from_bytes(
            p.approver_public_key.as_slice().try_into().map_err(io)?,
        )
        .map_err(io)?
        .into(),
        role: ApprovalRole::TreasuryApprover,
    }])
}
pub(crate) fn signatures(
    keys: &[(CredentialId, SigningKey)],
    hash: Hash32,
) -> Vec<CredentialSignature> {
    keys[..2]
        .iter()
        .map(|(id, key)| CredentialSignature {
            credential_id: id.clone(),
            signature: SignatureBytes {
                scheme: SchemeId::Ed25519Pure,
                bytes: Bytes(key.sign(&hash.0).to_bytes().to_vec()),
            },
        })
        .collect()
}
pub(crate) fn builds() -> BTreeMap<AdapterId, Vec<Hash32>> {
    BTreeMap::from([
        (
            AdapterId::unchecked("evm"),
            vec![oic_adapter_evm::verifier_build_hash()],
        ),
        (
            AdapterId::unchecked("solana"),
            vec![oic_adapter_solana::verifier_build_hash()],
        ),
    ])
}
pub(crate) fn vault() -> Vault {
    Vault {
        vault_id: vault_id(),
        institution_id: inst(),
        environment_id: environment(),
        tier: VaultTier::Operating,
        policy_id: PolicyId::unchecked("local-policy"),
        display_name: "DEVELOPMENT operating vault".into(),
    }
}

/// Provision once. The independent approver supplies only its public key;
/// this process never creates, loads, or stores the approval private key.
/// `handoff` must be outside `state`, and contains separate scoped capabilities.
pub fn bootstrap(state: &Path, handoff: &Path, approval_public_key: [u8; 32]) -> OicResult<()> {
    VerifyingKey::from_bytes(&approval_public_key).map_err(io)?;
    private_directory(state)?;
    private_directory(handoff)?;
    let state_real = state.canonicalize().map_err(io)?;
    let handoff_real = handoff.canonicalize().map_err(io)?;
    if handoff_real.starts_with(&state_real) || state_real.starts_with(&handoff_real) {
        return Err(OicError::invalid_request(
            "handoff and server-state directories must be disjoint",
        ));
    }
    if state.read_dir().map_err(io)?.next().is_some()
        || handoff.read_dir().map_err(io)?.next().is_some()
    {
        return Err(OicError::invalid_request(
            "bootstrap requires empty private directories; never rerun on an existing installation",
        ));
    }
    let secrets = Secrets {
        authority: seed(),
        events: seed(),
        sealing: (0..4).map(|_| seed()).collect(),
        console: bearer(),
        reader: bearer(),
        approval: bearer(),
        operator: bearer(),
    };
    let admin_keys: Vec<_> = (1..=3)
        .map(|i| {
            (
                CredentialId::unchecked(format!("local-admin-{i}")),
                SigningKey::from_bytes(&seed()),
            )
        })
        .collect();
    let genesis = oic_authorization_state::SystemClock.now();
    let simulator_seeds = (seed(), seed());
    let evm = oic_chain_simulator::evm::EvmSimulator::new(
        oic_chain_simulator::evm::EvmSimConfig::with_seed(simulator_seeds.0),
        oic_chain_simulator::SimClock::new(genesis),
    )?;
    let sol = oic_chain_simulator::solana::SolanaSimulator::new(
        oic_chain_simulator::solana::SolanaSimConfig::with_seed(simulator_seeds.1),
        oic_chain_simulator::SimClock::new(genesis),
    )?;
    let profiles = vec![evm.profile(), sol.profile()];
    let ids: Vec<_> = (1..=3)
        .map(|i| ParticipantId::unchecked(format!("local-sol-{i}")))
        .collect();
    let ceremony = |key: &str, participants: Vec<ParticipantId>, threshold, network: NetworkId| {
        KeygenCeremony {
            key_id: KeyId::unchecked(key),
            key_epoch: Epoch(1),
            institution_id: inst(),
            environment_id: environment(),
            participants,
            threshold,
            networks: vec![network],
            recovery_profile: "DEVELOPMENT local sealed shares; no independent recovery domains"
                .into(),
        }
    };
    let dev = DevSingleKeyProvider::with_os_rng(
        SchemeId::EcdsaSecp256k1Keccak256Prehashed,
        secrets.sealing[0],
    )?;
    let evm_key = dev.generate_distributed_key(&ceremony(
        "local-evm",
        vec![ParticipantId::unchecked("local-evm-1")],
        1,
        profiles[0].network_id.clone(),
    ))?;
    let providers: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, p)| FrostEd25519Provider::with_os_rng(p.clone(), secrets.sealing[i + 1]))
        .collect::<OicResult<_>>()?;
    let sol_key = run_dkg(
        &providers.iter().collect::<Vec<_>>(),
        &ceremony("local-sol", ids, 2, profiles[1].network_id.clone()),
    )?;
    let keys = vec![evm_key.descriptor, sol_key.descriptor];
    let mut wallets = Vec::new();
    let mut assets = Vec::new();
    let mut destinations = Vec::new();
    for (i, adapter) in adapters().iter().enumerate() {
        let (address, display) = adapter.derive_address(&keys[i].public_key)?;
        let name = if i == 0 { "evm" } else { "solana" };
        wallets.push(ChainWallet {
            chain_wallet_id: ChainWalletId::unchecked(format!("wallet-{name}")),
            vault_id: vault_id(),
            chain_profile_id: profiles[i].chain_profile_id.clone(),
            network_id: profiles[i].network_id.clone(),
            key_id: keys[i].key_id.clone(),
            key_epoch: Epoch(1),
            address,
            address_display: display,
            active: true,
        });
        assets.push(Asset {
            asset_id: AssetId::unchecked(format!("native-{name}")),
            network_id: profiles[i].network_id.clone(),
            asset: AssetKind::Native,
            decimals: if i == 0 { 18 } else { 9 },
            symbol: if i == 0 {
                "DEV-ETH".into()
            } else {
                "DEV-SOL".into()
            },
            behavior: AssetBehaviorProfile::Standard,
        });
        let (address, display) = if i == 0 {
            let address = [0xde; 20];
            (address.to_vec(), oic_adapter_evm::address::eip55(&address))
        } else {
            let address = SigningKey::from_bytes(&seed()).verifying_key().to_bytes();
            (
                address.to_vec(),
                oic_adapter_solana::address::to_base58(&address),
            )
        };
        let mut destination = CounterpartyDestination {
            destination_id: DestinationId::unchecked(format!("beneficiary-{name}")),
            version: 1,
            network_id: profiles[i].network_id.clone(),
            address: Bytes(address),
            address_display: display,
            display_name: format!("DEVELOPMENT {name} beneficiary"),
            allowed_assets: vec![assets[i].asset_id.clone()],
            verification_evidence:
                "Local simulator recipient only; never a real beneficiary enrollment".into(),
            activation_epoch: Epoch(1),
            administrative_signatures: vec![],
        };
        destination.administrative_signatures =
            signatures(&admin_keys, destination_hash(&destination)?);
        destinations.push(destination);
    }
    let rules = assets
        .iter()
        .map(|a| PolicyRule {
            rule_id: format!("local-{}", a.asset_id),
            vaults: vec![vault_id()],
            assets: vec![a.asset_id.clone()],
            destinations: vec![],
            purposes: vec![OperationPurpose::Settlement],
            max_amount_per_operation: Amount(10u128.pow(19)),
            max_native_fee_per_operation: Amount(10u128.pow(17)),
            rolling_limits: vec![ExposureLimit {
                window_seconds: 86_400,
                max_outflow_base_units: Amount(10u128.pow(20)),
            }],
            required_approvals: 1,
            approval_roles: vec![ApprovalRole::TreasuryApprover],
            exclude_proposer: true,
            operating_window: None,
        })
        .collect();
    let mut policy = PolicyBundle {
        policy_id: PolicyId::unchecked("local-policy"),
        policy_epoch: Epoch(1),
        institution_id: inst(),
        environment_id: environment(),
        rules,
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 120,
        allowlist_version: 1,
        activation_epoch: Epoch(1),
        administrative_signatures: vec![],
    };
    policy.administrative_signatures = signatures(&admin_keys, policy_hash(&policy)?);
    let p = Provisioned {
        schema_version: 1,
        genesis,
        simulator_seeds,
        admins: admin_keys
            .iter()
            .map(|(id, k)| (id.clone(), Bytes(k.verifying_key().to_bytes().to_vec())))
            .collect(),
        approver_public_key: Bytes(approval_public_key.to_vec()),
        keys,
        sealed: vec![evm_key.sealed_shares, sol_key.sealed_shares],
        wallets,
        assets,
        destinations,
        profiles,
        policy,
    };
    write_new(&state.join("provisioned.json"), &p)?;
    write_new(&state.join("secrets.json"), &secrets)?;
    let stack = Stack::open_inner(state, true, false)?;
    stack.api.coordinator.authority().set_policy(&p.policy)?;
    let credential = approver_credentials(&p)?.remove(0);
    let change = oic_authorization_state::CredentialChange {
        institution_id: inst(),
        environment_id: environment(),
        credential_id: approver(),
        previous_change: 0,
        credential: Some(credential),
    };
    let hash = change.hash()?;
    stack
        .api
        .coordinator
        .authority()
        .change_credential(change, signatures(&admin_keys, hash))?;
    stack.enroll()?;
    write_new(
        &handoff.join("console.json"),
        &json!({"token":secrets.console,"credential_id":proposer(),"scopes":["read","propose","submit"]}),
    )?;
    write_new_bytes(
        &handoff.join("console.env"),
        format!(
            "OIC_CONSOLE_CUSTODY_ORIGIN=http://127.0.0.1:8787\nOIC_CONSOLE_CUSTODY_TOKEN={}\n",
            secrets.console
        )
        .as_bytes(),
    )?;
    write_new(
        &handoff.join("reader.json"),
        &json!({"token":secrets.reader,"scopes":["read"]}),
    )?;
    write_new(
        &handoff.join("approval.json"),
        &json!({"token":secrets.approval,"credential_id":approver(),"scopes":["read","approve"]}),
    )?;
    write_new(
        &handoff.join("operator.json"),
        &json!({"token":secrets.operator,"scopes":["local_simulator_control"]}),
    )?;
    // This is the public wire format consumed by the existing oic-approve CLI.
    write_new(
        &handoff.join("trust.json"),
        &json!({"schema_version":1,"admin_keys":p.admins.iter().map(|(id,k)|json!({"credential_id":id,"public_key_hex":hex::encode(k.as_slice())})).collect::<Vec<_>>(),"admin_quorum":2,"chain_profiles":p.profiles,"accepted_verifier_builds":builds()}),
    )?;
    write_new(&handoff.join("catalog.json"), &stack.catalog())?;
    write_new(
        &state.join("ready.json"),
        &json!({"schema_version":1,"profile":PROFILE}),
    )?;
    protect_files(state)?;
    Ok(())
}

pub(crate) fn adapters() -> Vec<Arc<dyn oic_adapter_api::ChainAdapter>> {
    vec![
        Arc::new(oic_adapter_evm::EvmAdapter),
        Arc::new(oic_adapter_solana::SolanaAdapter),
    ]
}
