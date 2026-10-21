//! Ordered approval contracts through public D1 and deterministic replay APIs.
//! These tests authenticate real ES256 assertions; they do not exercise browser
//! enrollment, a consensus network, or the adapter/kernel evaluation of a payment.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey as AdminKey};
use oic_authorization_state::*;
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes};
use oic_domain_types::*;
use oic_policy_kernel::{
    grant_signing_hash, intent_hash, policy_hash, ApproverCredential, ApproverKey, Decision,
};
use oic_webauthn::{encode_assertion, Assertion};
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const NOW: u64 = 1_800_000_007;
const RP: &str = "custody.example";
const ORIGIN: &str = "https://approver.custody.example";

fn config() -> AuthorityConfig {
    AuthorityConfig {
        institution_id: InstitutionId::unchecked("institution-approvals"),
        environment_id: EnvironmentId::unchecked("test-approvals"),
        authority_key_id: KeyId::unchecked("authority-receipts"),
        admin_keys: [21, 22, 23]
            .into_iter()
            .map(|seed| (admin_id(seed), admin_key(seed).verifying_key()))
            .collect(),
        admin_quorum: 2,
        freeze_responders: vec![],
        release_receipt_ttl_seconds: 60,
        max_clock_skew_seconds: 10,
    }
}

fn admin_id(seed: u8) -> CredentialId {
    CredentialId::unchecked(format!("admin-{seed}"))
}

fn admin_key(seed: u8) -> AdminKey {
    AdminKey::from_bytes(&[seed; 32])
}

fn signatures(hash: Hash32) -> Vec<CredentialSignature> {
    [21, 23]
        .into_iter()
        .map(|seed| CredentialSignature {
            credential_id: admin_id(seed),
            signature: SignatureBytes {
                scheme: SchemeId::Ed25519Pure,
                bytes: Bytes(admin_key(seed).sign(&hash.0).to_bytes().to_vec()),
            },
        })
        .collect()
}

fn change(
    credential_id: CredentialId,
    previous_change: u64,
    credential: Option<ApproverCredential>,
) -> CredentialChange {
    CredentialChange {
        institution_id: config().institution_id,
        environment_id: config().environment_id,
        credential_id,
        previous_change,
        credential,
    }
}

fn policy(required: u8) -> PolicyBundle {
    let mut policy = PolicyBundle {
        policy_id: PolicyId::unchecked("policy-approvals"),
        policy_epoch: Epoch(4),
        institution_id: config().institution_id,
        environment_id: config().environment_id,
        rules: vec![PolicyRule {
            rule_id: "treasury-transfer".into(),
            vaults: vec![VaultId::unchecked("treasury-vault")],
            assets: vec![AssetId::unchecked("native-sol")],
            destinations: vec![],
            purposes: vec![],
            max_amount_per_operation: Amount(1000),
            max_native_fee_per_operation: Amount(100),
            rolling_limits: vec![],
            required_approvals: required,
            approval_roles: vec![ApprovalRole::TreasuryApprover],
            exclude_proposer: true,
            operating_window: None,
        }],
        denied_destinations: vec![],
        denied_assets: vec![],
        max_evidence_age_seconds: 60,
        allowlist_version: 1,
        activation_epoch: Epoch(4),
        administrative_signatures: vec![],
    };
    policy.administrative_signatures = signatures(policy_hash(&policy).unwrap());
    policy
}

fn intent(proposer: &str) -> Intent {
    Intent {
        schema_version: 1,
        intent_id: IntentId::unchecked("intent-payroll-7"),
        institution_id: config().institution_id,
        environment_id: config().environment_id,
        vault_id: VaultId::unchecked("treasury-vault"),
        chain_wallet_id: ChainWalletId::unchecked("solana-wallet"),
        chain_profile_id: ChainProfileId::unchecked("solana-devnet-v1"),
        operation: IntentOperation::AssetTransfer {
            asset_id: AssetId::unchecked("native-sol"),
            amount_base_units: Amount(137),
            destination_id: DestinationId::unchecked("beneficiary-9"),
            destination_version: 3,
        },
        constraints: IntentConstraints {
            max_network_fee_base_units: Amount(11),
            approval_mode: ApprovalMode::ExactCandidate,
            maximum_successful_payments: 1,
        },
        purpose: OperationPurpose::Settlement,
        external_reference: "payroll-7".into(),
        proposer_credential_id: CredentialId::unchecked(proposer),
        created_at: UnixSeconds(NOW),
    }
}

struct Passkey {
    key: SigningKey,
    credential: ApproverCredential,
}

impl Passkey {
    fn new(seed: u8, credential: &str, person: &str) -> Self {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public_key_sec1 = Bytes(
            key.verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        );
        Self {
            key,
            credential: ApproverCredential {
                credential_id: CredentialId::unchecked(credential),
                person_id: CredentialId::unchecked(person),
                verifying_key: ApproverKey::WebAuthn {
                    public_key_sec1,
                    rp_id: RP.into(),
                    allowed_origins: vec![ORIGIN.into()],
                    backup_eligible: false,
                },
                role: ApprovalRole::TreasuryApprover,
            },
        }
    }

    fn proposal(&self) -> CredentialChange {
        change(
            self.credential.credential_id.clone(),
            0,
            Some(self.credential.clone()),
        )
    }

    fn grant(&self, body: ApprovalGrantBody) -> ApprovalGrant {
        let hash = grant_signing_hash(&body).unwrap();
        self.grant_with(body, hash, ORIGIN, 0x05)
    }

    fn grant_with(
        &self,
        body: ApprovalGrantBody,
        challenge: Hash32,
        origin: &str,
        flags: u8,
    ) -> ApprovalGrant {
        let client = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get", "challenge": URL_SAFE_NO_PAD.encode(challenge.0),
            "origin": origin, "crossOrigin": false,
        }))
        .unwrap();
        let mut auth = Sha256::digest(RP.as_bytes()).to_vec();
        auth.push(flags);
        auth.extend_from_slice(&0x0102_0304_u32.to_be_bytes());
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature: Signature = self.key.sign(&signed);
        let der = signature.to_der();
        let bytes = encode_assertion(Assertion {
            authenticator_data: &auth,
            client_data_json: &client,
            signature: der.as_bytes(),
        })
        .unwrap();
        ApprovalGrant {
            body,
            signature: SignatureBytes {
                scheme: SchemeId::WebAuthnEs256,
                bytes: Bytes(bytes),
            },
        }
    }
}

struct Scenario<S: AuthorityStore> {
    authority: Authority<S>,
    clock: Arc<ManualClock>,
    intent: Intent,
    registered: RegisteredIntent,
}

impl<S: AuthorityStore> Scenario<S> {
    fn new(store: Arc<S>, required: u8, proposer: &str) -> Self {
        let clock = Arc::new(ManualClock::new(NOW));
        let authority = Authority::open(store, 0, config(), admin_key(90), clock.clone()).unwrap();
        authority.set_policy(&policy(required)).unwrap();
        let intent = intent(proposer);
        let registered = authority
            .register_intent(
                &intent,
                intent_hash(&intent).unwrap(),
                IdempotencyKey {
                    institution_id: config().institution_id,
                    route: "POST /v1/intents".into(),
                    key: "payroll-7".into(),
                },
            )
            .unwrap();
        Self {
            authority,
            clock,
            intent,
            registered,
        }
    }

    fn enroll(&self, passkey: &Passkey) -> u64 {
        let proposal = passkey.proposal();
        self.authority
            .change_credential(proposal.clone(), signatures(proposal.hash().unwrap()))
            .unwrap()
    }

    fn body(&self, passkey: &Passkey) -> ApprovalGrantBody {
        ApprovalGrantBody {
            grant_id: GrantId::unchecked(format!("grant-{}", passkey.credential.credential_id)),
            institution_id: config().institution_id,
            environment_id: config().environment_id,
            vault_id: self.intent.vault_id.clone(),
            intent_id: self.intent.intent_id.clone(),
            intent_hash: intent_hash(&self.intent).unwrap(),
            policy_id: PolicyId::unchecked("policy-approvals"),
            policy_epoch: Epoch(4),
            scope: GrantScope::ExactCandidate {
                candidate_id: CandidateId::unchecked("candidate-payroll-7"),
                candidate_revision: 3,
                preview_hash: Hash32([0x41; 32]),
            },
            approver_credential_id: passkey.credential.credential_id.clone(),
            approver_role: ApprovalRole::TreasuryApprover,
            issued_at: UnixSeconds(NOW),
            expires_at: UnixSeconds(NOW + 120),
        }
    }

    fn request(&self, grants: Vec<ApprovalGrant>) -> ReserveRequest {
        let (policy_epoch, policy_hash) = self.authority.current_policy().unwrap();
        ReserveRequest {
            family_id: self.registered.operation_family_id.clone(),
            candidate_id: CandidateId::unchecked("candidate-payroll-7"),
            candidate_revision: 3,
            vault_id: self.intent.vault_id.clone(),
            intent_id: self.intent.intent_id.clone(),
            policy_epoch,
            policy_hash,
            claims: ResourceClaims {
                resources: vec![NativeResource::SolanaBlockhash {
                    network_id: NetworkId::unchecked("solana-devnet"),
                    fee_payer: Bytes(vec![0x91; 32]),
                    blockhash: Bytes(vec![0x92; 32]),
                }],
                asset_outflows: vec![AssetOutflow {
                    asset_id: AssetId::unchecked("native-sol"),
                    amount_base_units: Amount(137),
                }],
                native_fees: vec![NativeFee {
                    network_id: NetworkId::unchecked("solana-devnet"),
                    amount_base_units: Amount(11),
                }],
            },
            grants,
            envelope_body_hash: Hash32([0x42; 32]),
            signer_session_id: SigningSessionId::unchecked("signer-session-7"),
            issuance_deadline: UnixSeconds(NOW + 90),
            policy_decision: Decision::Allow {
                rule_id: "treasury-transfer".into(),
            },
            exposure_limits: vec![],
        }
    }

    fn release(&self, request: &ReserveRequest) -> ReleaseRequest {
        ReleaseRequest {
            reservation_id: reservation_id_for(
                &request.family_id,
                &request.candidate_id,
                request.candidate_revision,
            )
            .unwrap(),
            reservation_version: 1,
            envelope_body_hash: request.envelope_body_hash,
            signer_session_id: request.signer_session_id.clone(),
            expected_policy_epoch: request.policy_epoch,
            freshness: FreshnessContext {
                now: self.clock.now(),
            },
        }
    }

    fn snapshot(&self) -> AuthorityState {
        self.authority.store().read(Clone::clone).unwrap()
    }

    fn reject<T>(&self, expected: ErrorCode, operation: impl FnOnce() -> OicResult<T>) {
        let before = self.snapshot();
        let error = operation().err().expect("operation must fail");
        assert_eq!(error.code, expected, "{}", error.detail);
        assert_eq!(
            self.snapshot(),
            before,
            "a rejection must not consume an approval or issue output"
        );
    }
}

fn setup(required: u8, proposer: &str) -> Scenario<InMemoryAuthorityStore> {
    Scenario::new(Arc::new(InMemoryAuthorityStore::new()), required, proposer)
}

#[test]
fn real_two_person_webauthn_grants_require_ordered_approval_before_reserve() {
    let scenario = setup(2, "proposer");
    let alice = Passkey::new(51, "alice-passkey", "alice");
    let bob = Passkey::new(63, "bob-passkey", "bob");
    let alice_grant = alice.grant(scenario.body(&alice));
    let bob_grant = bob.grant(scenario.body(&bob));
    let request = scenario.request(vec![alice_grant.clone(), bob_grant.clone()]);
    assert_eq!(scenario.authority.approval_credentials().unwrap(), None);
    scenario.reject(ErrorCode::InvalidSignature, || {
        scenario.authority.reserve(request.clone())
    });
    scenario.enroll(&alice);
    scenario.enroll(&bob);
    scenario.reject(ErrorCode::ApprovalRequired, || {
        scenario.authority.reserve(request.clone())
    });
    let first = scenario
        .authority
        .approve(&scenario.intent, alice_grant.clone())
        .unwrap();
    scenario.reject(ErrorCode::ApprovalRequired, || {
        scenario.authority.reserve(request.clone())
    });
    scenario.reject(ErrorCode::ApprovalRequired, || {
        scenario
            .authority
            .reserve(scenario.request(vec![alice_grant.clone()]))
    });
    let second = scenario
        .authority
        .approve(&scenario.intent, bob_grant)
        .unwrap();
    assert!(second > first);
    assert_eq!(
        scenario
            .authority
            .recorded_approvals(&scenario.intent.intent_id)
            .unwrap()
            .len(),
        2
    );
    let (reservation, receipt) = scenario.authority.reserve(request.clone()).unwrap();
    assert_eq!(receipt.body.kind, ReceiptKind::Reserved);
    assert_eq!(
        reservation.claims.asset_outflows[0].amount_base_units,
        Amount(137)
    );
    let (receipt, issuance) = scenario
        .authority
        .release(scenario.release(&request))
        .unwrap();
    verify_receipt(
        &receipt,
        &scenario.authority.verifying_key(),
        &ReceiptExpectation {
            kind: ReceiptKind::Release,
            envelope_body_hash: request.envelope_body_hash,
            signer_session_id: request.signer_session_id,
            candidate_id: request.candidate_id,
            candidate_revision: 3,
            now: UnixSeconds(NOW),
            policy_epoch: Epoch(4),
        },
    )
    .unwrap();
    assert!(issuance.commit_sequence > second);
    assert_eq!(scenario.snapshot().issuance.len(), 1);
}

#[test]
fn correctly_signed_wrong_challenge_origin_up_or_uv_cannot_be_recorded() {
    let scenario = setup(1, "proposer");
    let alice = Passkey::new(51, "alice-passkey", "alice");
    scenario.enroll(&alice);
    let body = scenario.body(&alice);
    let hash = grant_signing_hash(&body).unwrap();
    let mut wrong_hash = hash;
    wrong_hash.0[17] ^= 1;
    for (challenge, origin, flags) in [
        (wrong_hash, ORIGIN, 0x05),
        (hash, "https://console.custody.example", 0x05),
        (hash, ORIGIN, 0x04),
        (hash, ORIGIN, 0x01),
    ] {
        let grant = alice.grant_with(body.clone(), challenge, origin, flags);
        scenario.reject(ErrorCode::InvalidSignature, || {
            scenario.authority.approve(&scenario.intent, grant)
        });
    }
    let good = alice.grant(body);
    scenario
        .authority
        .approve(&scenario.intent, good.clone())
        .unwrap();
    scenario
        .authority
        .reserve(scenario.request(vec![good]))
        .unwrap();
}

#[test]
fn valid_signatures_do_not_override_intent_policy_scope_or_proposer_separation() {
    let scenario = setup(1, "proposer");
    let alice = Passkey::new(51, "alice-passkey", "alice");
    scenario.enroll(&alice);
    for case in 0..6 {
        let mut body = scenario.body(&alice);
        let expected = match case {
            0 => {
                body.intent_id = IntentId::unchecked("other-intent");
                ErrorCode::ScopeMismatch
            }
            1 => {
                body.intent_hash.0[19] ^= 1;
                ErrorCode::ScopeMismatch
            }
            2 => {
                body.environment_id = EnvironmentId::unchecked("other-environment");
                ErrorCode::ScopeMismatch
            }
            3 => {
                body.policy_epoch = Epoch(3);
                ErrorCode::StalePolicy
            }
            4 => {
                body.policy_id = PolicyId::unchecked("other-policy");
                ErrorCode::StalePolicy
            }
            5 => {
                body.vault_id = VaultId::unchecked("other-vault");
                ErrorCode::ScopeMismatch
            }
            _ => unreachable!(),
        };
        let grant = alice.grant(body);
        scenario.reject(expected, || {
            scenario.authority.approve(&scenario.intent, grant)
        });
    }
    let grant = alice.grant(scenario.body(&alice));
    let mut changed_intent = scenario.intent.clone();
    changed_intent.external_reference.push_str("-changed");
    scenario.reject(ErrorCode::ScopeMismatch, || {
        scenario.authority.approve(&changed_intent, grant)
    });
    for (same_credential, retire_proposer) in [(true, false), (false, false), (false, true)] {
        let scenario = setup(1, "alice-proposer");
        let proposer = Passkey::new(52, "alice-proposer", "alice");
        let other_key = Passkey::new(53, "alice-other-device", "alice");
        let proposer_sequence = scenario.enroll(&proposer);
        scenario.enroll(&other_key);
        if retire_proposer {
            let removal = change(
                proposer.credential.credential_id.clone(),
                proposer_sequence,
                None,
            );
            scenario
                .authority
                .change_credential(removal.clone(), signatures(removal.hash().unwrap()))
                .unwrap();
        }
        let approver = if same_credential {
            &proposer
        } else {
            &other_key
        };
        scenario.reject(ErrorCode::PolicyDenied, || {
            scenario
                .authority
                .approve(&scenario.intent, approver.grant(scenario.body(approver)))
        });
    }
}

#[test]
fn duplicate_credential_or_one_person_two_authenticators_cannot_form_quorum() {
    let scenario = setup(2, "proposer");
    let first = Passkey::new(51, "alice-one", "alice");
    let second = Passkey::new(52, "alice-two", "alice");
    let bob = Passkey::new(63, "bob-key", "bob");
    for passkey in [&first, &second, &bob] {
        scenario.enroll(passkey);
    }
    let grant = first.grant(scenario.body(&first));
    scenario
        .authority
        .approve(&scenario.intent, grant.clone())
        .unwrap();
    let mut body = scenario.body(&first);
    body.grant_id = GrantId::unchecked("new-grant-same-credential");
    scenario.reject(ErrorCode::Conflict, || {
        scenario
            .authority
            .approve(&scenario.intent, first.grant(body))
    });
    scenario.reject(ErrorCode::PolicyDenied, || {
        scenario
            .authority
            .approve(&scenario.intent, second.grant(scenario.body(&second)))
    });
    scenario.reject(ErrorCode::ApprovalRequired, || {
        scenario
            .authority
            .reserve(scenario.request(vec![grant.clone(), grant.clone()]))
    });
    let bob_grant = bob.grant(scenario.body(&bob));
    scenario
        .authority
        .approve(&scenario.intent, bob_grant.clone())
        .unwrap();
    scenario
        .authority
        .reserve(scenario.request(vec![grant, bob_grant]))
        .unwrap();
}

#[test]
fn enrollment_requires_admin_quorum_and_retired_credential_ids_never_revive() {
    let scenario = setup(1, "proposer");
    let alice = Passkey::new(51, "alice-key", "alice");
    let proposal = alice.proposal();
    let mut partial = signatures(proposal.hash().unwrap());
    partial.pop();
    scenario.reject(ErrorCode::InvalidSignature, || {
        scenario
            .authority
            .change_credential(proposal.clone(), partial)
    });
    let mut foreign = proposal.clone();
    foreign.institution_id = InstitutionId::unchecked("other-institution");
    scenario.reject(ErrorCode::ScopeMismatch, || {
        scenario
            .authority
            .change_credential(foreign.clone(), signatures(foreign.hash().unwrap()))
    });
    let enrollment_sequence = scenario.enroll(&alice);
    scenario.reject(ErrorCode::Conflict, || {
        scenario
            .authority
            .change_credential(proposal.clone(), signatures(proposal.hash().unwrap()))
    });
    let mut alias = alice.credential.clone();
    alias.credential_id = CredentialId::unchecked("different-id-same-key");
    let alias = change(alias.credential_id.clone(), 0, Some(alias));
    scenario.reject(ErrorCode::InvalidRequest, || {
        scenario
            .authority
            .change_credential(alias.clone(), signatures(alias.hash().unwrap()))
    });
    let removal = change(
        alice.credential.credential_id.clone(),
        enrollment_sequence,
        None,
    );
    scenario
        .authority
        .change_credential(removal.clone(), signatures(removal.hash().unwrap()))
        .unwrap();
    let retired = scenario.snapshot().ordered_approvals.unwrap().credentials
        [&alice.credential.credential_id]
        .clone();
    assert!(retired.credential.is_none());
    let revival = change(
        alice.credential.credential_id.clone(),
        retired.commit_sequence,
        Some(alice.credential.clone()),
    );
    scenario.reject(ErrorCode::Conflict, || {
        scenario
            .authority
            .change_credential(revival.clone(), signatures(revival.hash().unwrap()))
    });
    scenario.reject(ErrorCode::InvalidSignature, || {
        scenario
            .authority
            .approve(&scenario.intent, alice.grant(scenario.body(&alice)))
    });
    assert!(
        scenario.snapshot().ordered_approvals.is_some(),
        "removing the last credential must not restore legacy mode"
    );
    assert_eq!(
        scenario.authority.approval_credentials().unwrap(),
        Some(vec![])
    );
    scenario.reject(ErrorCode::ApprovalRequired, || {
        scenario.authority.reserve(scenario.request(vec![]))
    });
}

#[test]
fn enabling_ordered_profile_requires_aborting_pending_legacy_reservations() {
    let scenario = setup(0, "proposer");
    let alice = Passkey::new(51, "alice-key", "alice");
    let request = scenario.request(vec![]);
    let (reservation, _) = scenario.authority.reserve(request).unwrap();
    let proposal = alice.proposal();
    scenario.reject(ErrorCode::Conflict, || {
        scenario
            .authority
            .change_credential(proposal.clone(), signatures(proposal.hash().unwrap()))
    });
    assert!(scenario.snapshot().ordered_approvals.is_none());
    scenario
        .authority
        .abort_before_issuance(&reservation.reservation_id)
        .unwrap();
    scenario.enroll(&alice);
    assert!(scenario.snapshot().ordered_approvals.is_some());
}

#[test]
fn removal_blocks_new_issuance_but_already_issued_release_stays_idempotent() {
    for issued_before_removal in [false, true] {
        let scenario = setup(1, "proposer");
        let alice = Passkey::new(51, "alice-key", "alice");
        let enrollment_sequence = scenario.enroll(&alice);
        let grant = alice.grant(scenario.body(&alice));
        scenario
            .authority
            .approve(&scenario.intent, grant.clone())
            .unwrap();
        let request = scenario.request(vec![grant]);
        let (reservation, _) = scenario.authority.reserve(request.clone()).unwrap();
        let issuance = issued_before_removal.then(|| {
            scenario
                .authority
                .release(scenario.release(&request))
                .unwrap()
                .1
        });
        let removal = change(
            alice.credential.credential_id.clone(),
            enrollment_sequence,
            None,
        );
        scenario
            .authority
            .change_credential(removal.clone(), signatures(removal.hash().unwrap()))
            .unwrap();
        if let Some(issuance) = issuance {
            let before = scenario.snapshot();
            scenario.clock.advance(7);
            let (receipt, repeated) = scenario
                .authority
                .release(scenario.release(&request))
                .unwrap();
            assert_eq!(repeated, issuance);
            assert_eq!(receipt.body.commit_sequence, issuance.commit_sequence);
            assert_eq!(receipt.body.envelope_body_hash, request.envelope_body_hash);
            assert_eq!(
                scenario.snapshot(),
                before,
                "repeat must not issue a second record"
            );
        } else {
            scenario.reject(ErrorCode::InvalidSignature, || {
                scenario.authority.release(scenario.release(&request))
            });
            assert_eq!(
                scenario
                    .authority
                    .reservation(&reservation.reservation_id)
                    .unwrap()
                    .state,
                ReservationState::Reserved
            );
            assert!(scenario.snapshot().issuance.is_empty());
        }
    }
}

#[test]
fn canonical_enrollment_approval_and_reserve_commands_replay_identically() {
    let scenario = setup(1, "proposer");
    let alice = Passkey::new(51, "alice-key", "alice");
    let proposal = alice.proposal();
    let commands = [
        AuthorityCommand::ChangeCredential {
            signatures: signatures(proposal.hash().unwrap()),
            proposal,
        },
        AuthorityCommand::Approve {
            intent: Box::new(scenario.intent.clone()),
            grant: alice.grant(scenario.body(&alice)),
        },
        AuthorityCommand::Reserve {
            request: scenario.request(vec![alice.grant(scenario.body(&alice))]),
        },
    ];
    let mut state = scenario.snapshot();
    for command in commands {
        let encoded = canonical_bytes(&command).unwrap();
        let decoded: AuthorityCommand = from_canonical_bytes(&encoded).unwrap();
        let result = apply(&config(), state.clone(), command, UnixSeconds(NOW)).unwrap();
        assert_eq!(
            apply(&config(), state, decoded, UnixSeconds(NOW)).unwrap(),
            result
        );
        state = result.0;
        assert_eq!(
            from_canonical_bytes::<AuthorityState>(&canonical_bytes(&state).unwrap()).unwrap(),
            state
        );
    }
    assert_eq!(
        state.ordered_approvals.as_ref().unwrap().grants[&scenario.intent.intent_id].len(),
        1
    );
    assert_eq!(state.reservations.len(), 1);
    assert!(state.issuance.is_empty());
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "oic-ordered-approvals-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn file_reopen_preserves_enrollment_recorded_approval_and_removal_before_release() {
    let directory = TestDirectory::new();
    let path = directory.0.join("authority.cbor");
    let store = Arc::new(FileAuthorityStore::open(&path, None).unwrap());
    let scenario = Scenario::new(store.clone(), 1, "proposer");
    let alice = Passkey::new(51, "alice-key", "alice");
    let enrollment_sequence = scenario.enroll(&alice);
    let grant = alice.grant(scenario.body(&alice));
    let approval_sequence = scenario
        .authority
        .approve(&scenario.intent, grant.clone())
        .unwrap();
    let request = scenario.request(vec![grant.clone()]);
    let before = store.snapshot();
    let fence = scenario.authority.fence_token();
    let clock = scenario.clock.clone();
    let intent = scenario.intent.clone();
    drop(scenario);
    drop(store);

    let store = Arc::new(FileAuthorityStore::open(&path, Some(approval_sequence)).unwrap());
    assert_eq!(store.snapshot(), before);
    let record = store.snapshot().ordered_approvals.unwrap().grants[&intent.intent_id]
        [&alice.credential.credential_id]
        .clone();
    assert_eq!(record.grant, grant);
    assert_eq!(record.credential_commit_sequence, enrollment_sequence);
    assert_eq!(record.commit_sequence, approval_sequence);
    let authority =
        Authority::open(store.clone(), fence, config(), admin_key(90), clock.clone()).unwrap();
    assert_eq!(
        authority.approve(&intent, grant).unwrap_err().code,
        ErrorCode::Conflict
    );
    let (reservation, _) = authority.reserve(request.clone()).unwrap();
    let removal = change(
        alice.credential.credential_id.clone(),
        enrollment_sequence,
        None,
    );
    let removal_sequence = authority
        .change_credential(removal.clone(), signatures(removal.hash().unwrap()))
        .unwrap();
    let fence = authority.fence_token();
    drop(authority);
    drop(store);

    let store = Arc::new(FileAuthorityStore::open(&path, Some(removal_sequence)).unwrap());
    let authority = Authority::open(store.clone(), fence, config(), admin_key(90), clock).unwrap();
    let before_release = store.snapshot();
    let release = ReleaseRequest {
        reservation_id: reservation.reservation_id,
        reservation_version: reservation.reservation_version,
        envelope_body_hash: request.envelope_body_hash,
        signer_session_id: request.signer_session_id,
        expected_policy_epoch: request.policy_epoch,
        freshness: FreshnessContext {
            now: UnixSeconds(NOW),
        },
    };
    assert_eq!(
        authority.release(release).unwrap_err().code,
        ErrorCode::InvalidSignature
    );
    assert_eq!(store.snapshot(), before_release);
    assert!(store.snapshot().issuance.is_empty());
    assert_eq!(authority.approval_credentials().unwrap(), Some(vec![]));
    assert_eq!(
        authority.recorded_approvals(&intent.intent_id).unwrap(),
        vec![record]
    );
}
