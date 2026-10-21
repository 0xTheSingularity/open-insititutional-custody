#![allow(dead_code)]
#[path = "../../../../crates/replicated-authority/tests/common/mod.rs"]
pub mod d2;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use commonware_codec::Encode;
use d2::{Committee, Fixture, authority};
use oic_approver_client::{Client, FinalizedEntry, Floor, Provision};
use oic_authorization_state::{AuthorityCommand, CredentialChange};
use oic_domain_types::*;
use oic_policy_kernel::{ApproverCredential, ApproverKey};
use oic_replicated_authority::{AuthorityBlock, Command, ReplicatedState};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub const ORIGIN: &str = "http://localhost:4317";
pub const RAW_ID: &[u8] = b"oic-browser-approval-only";

pub fn credential_id() -> CredentialId {
    CredentialId::unchecked("browser-approver")
}
pub fn key() -> SigningKey {
    SigningKey::from_bytes((&[42; 32]).into()).unwrap()
}
pub fn credential() -> ApproverCredential {
    ApproverCredential {
        credential_id: credential_id(),
        person_id: CredentialId::unchecked("browser-person"),
        role: ApprovalRole::TreasuryApprover,
        verifying_key: ApproverKey::WebAuthn {
            public_key_sec1: key()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()
                .into(),
            rp_id: "localhost".into(),
            allowed_origins: vec![ORIGIN.into()],
            backup_eligible: false,
        },
    }
}

pub struct Scenario {
    pub fixture: Fixture,
    pub committee: Committee,
    pub provision: Provision,
    pub initial: FinalizedEntry,
    pub tip: AuthorityBlock,
    pub state: ReplicatedState,
}

impl Scenario {
    pub fn new(chain: d2::Chain) -> Self {
        let fixture = Fixture::new(chain, 0);
        let committee = Committee::new();
        let genesis = fixture.genesis(&committee);
        let config = &fixture.executor.authority;
        let provision = Provision {
            institution_id: config.institution_id.clone(),
            environment_id: config.environment_id.clone(),
            authority_key_id: config.authority_key_id.clone(),
            admin_keys: config.admin_keys.clone(),
            admin_quorum: config.admin_quorum,
            freeze_responders: config.freeze_responders.clone(),
            release_receipt_ttl_seconds: config.release_receipt_ttl_seconds,
            max_clock_skew_seconds: config.max_clock_skew_seconds,
            registry: fixture.executor.registry.clone(),
            adapter_builds: fixture
                .executor
                .adapters
                .iter()
                .map(|(id, adapter)| (id.clone(), adapter.manifest().verifier_build_hash))
                .collect(),
            roster: committee.roster.clone(),
            roster_genesis: committee.anchor,
            genesis: genesis.encode().to_vec().into(),
            genesis_hash: Floor::at(&genesis).digest,
            minimum_floor: Floor::at(&genesis),
            origin: ORIGIN.into(),
            rp_id: "localhost".into(),
            max_view_age_seconds: 60,
            grant_ttl_seconds: 120,
            development: true,
            credential_ids: BTreeMap::from([(credential_id(), RAW_ID.to_vec().into())]),
        };
        let proposal = CredentialChange {
            institution_id: config.institution_id.clone(),
            environment_id: config.environment_id.clone(),
            credential_id: credential_id(),
            previous_change: 0,
            credential: Some(credential()),
        };
        let mut commands = fixture.bootstrap();
        commands.push(authority(AuthorityCommand::ChangeCredential {
            signatures: d2::admin_signatures(proposal.hash().unwrap()),
            proposal,
        }));
        let (tip, state) = fixture
            .executor
            .propose_block(
                &genesis,
                ReplicatedState::default(),
                committee.context(&genesis, 1),
                &commands,
                d2::now(),
                d2::now(),
            )
            .unwrap();
        let initial = FinalizedEntry::new(&tip, &committee.certify(&tip));
        Self {
            fixture,
            committee,
            provision,
            initial,
            tip,
            state,
        }
    }

    pub fn client(&self) -> Client {
        let mut client = Client::new(self.provision.clone(), [81; 32], ORIGIN, d2::now()).unwrap();
        client.apply(&self.initial, d2::now()).unwrap();
        client
    }

    pub fn order(&mut self, commands: &[Command]) -> OicResult<FinalizedEntry> {
        use commonware_consensus::Heightable;
        let (tip, state) = self.fixture.executor.propose_block(
            &self.tip,
            self.state.clone(),
            self.committee
                .context(&self.tip, self.tip.height().get() + 1),
            commands,
            d2::now(),
            d2::now(),
        )?;
        let entry = FinalizedEntry::new(&tip, &self.committee.certify(&tip));
        self.tip = tip;
        self.state = state;
        Ok(entry)
    }
}

pub struct Assertion {
    pub auth: Vec<u8>,
    pub client: Vec<u8>,
    pub signature: Vec<u8>,
}
impl Assertion {
    pub fn new(challenge: Hash32, origin: &str, rp: &str, flags: u8, ceremony: &str) -> Self {
        let mut auth = Sha256::digest(rp).to_vec();
        auth.push(flags);
        auth.extend(1u32.to_be_bytes());
        let client = serde_json::to_vec(&serde_json::json!({"type":ceremony,"challenge":URL_SAFE_NO_PAD.encode(challenge.0),"origin":origin,"crossOrigin":false})).unwrap();
        let mut message = auth.clone();
        message.extend(Sha256::digest(&client));
        let signature: Signature = key().sign(&message);
        Self {
            auth,
            client,
            signature: signature.to_der().as_bytes().to_vec(),
        }
    }
    pub fn raw(&self) -> oic_webauthn::Assertion<'_> {
        oic_webauthn::Assertion {
            authenticator_data: &self.auth,
            client_data_json: &self.client,
            signature: &self.signature,
        }
    }
}
