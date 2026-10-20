//! # oic-golden-vectors
//!
//! Golden vectors and conformance machinery for the OIC authorization
//! protocol v1 (`spec/protocol-v1.md`, RFC 0001 §3.2 and §19 item 7,
//! RFC 0002 §3).
//!
//! * `vectors/*.json` hold the vectors. Each domain-object file is a JSON
//!   list of [`DomainVector`]; `native-evm.json` and `native-solana.json` are
//!   lists of [`NativeVector`].
//! * [`compute`] re-derives a domain vector's canonical bytes, hash, and
//!   derived identifier from its `input` JSON by calling the *real*
//!   producer function of the workspace (for example
//!   `oic_policy_kernel::intent_hash` or `oic_signer::envelope_body_hash`).
//! * [`decode`] strictly decodes canonical bytes back into the encoded Rust
//!   type and returns its JSON form, which must equal
//!   [`Computed::encoded_json`].
//!
//! The vector generator and the conformance tests live in `tests/`; the
//! generator only writes files when `OIC_REGENERATE_VECTORS=1`.

use oic_adapter_api::ChainProfile;
use oic_authorization_state::{AuthorityEvent, AuthorityState, CheckpointBody, FreezeProposal, UnfreezeProposal};
use oic_canonical_encoding::{canonical_bytes, domain_hash, from_canonical_bytes};
use oic_domain_types::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Directory holding the vector files.
pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

/// Directory holding the JSON Schema documents.
pub fn schemas_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schemas")
}

/// Domain tags defined outside `oic_domain_types::domains`, in the crates
/// that own them (`authority_domains`, `audit_domains`).
pub mod local_domains {
    pub use oic_audit::audit_domains::{AUDIT_CHECKPOINT, AUDIT_EVENT_ID, AUDIT_OBJECT, AUTHORITY_EVENT};
    pub use oic_authorization_state::authority_domains::{AUTHORITY_CHECKPOINT, AUTHORITY_ID, AUTHORITY_STATE};
}

/// File name (without directory) of the vector file for a domain tag:
/// `"OIC/AUTHORITY_RECEIPT/v1"` → `"authority_receipt.json"`.
pub fn file_name_for_domain(domain: &str) -> String {
    let middle = domain.strip_prefix("OIC/").and_then(|s| s.strip_suffix("/v1")).unwrap_or(domain);
    format!("{}.json", middle.to_ascii_lowercase())
}

/// An Ed25519 signature that the producing component makes over the
/// vector's 32-byte `hash_hex` (never over the canonical bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519OverHash {
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// One domain-separated commitment vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainVector {
    pub name: String,
    /// The domain-separation tag; `hash = SHA256(domain || canonical_cbor)`.
    pub domain: String,
    /// Rust type of `input` (its serde JSON form).
    #[serde(rename = "type")]
    pub type_name: String,
    /// Rust type that is canonically encoded. Differs from `type` for
    /// signed views that omit fields (`PolicyBundleUnsigned`, ...).
    pub encoded_type: String,
    /// The workspace function whose output `hash_hex` is.
    pub producer: String,
    pub input: Value,
    pub canonical_cbor_hex: String,
    pub hash_hex: String,
    /// Identifier derived from the hash, where the protocol derives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519: Option<Ed25519OverHash>,
}

/// One native signing-payload vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeVector {
    pub name: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub verifier_build_hash_hex: String,
    /// Chain profile the payload was produced under.
    pub chain_profile: Value,
    /// Structured description of the unsigned transaction / message.
    pub input: Value,
    pub native_unsigned_bytes_hex: String,
    /// `NativeSigningPayload` JSON exactly as the adapter derived it.
    pub signing_payload: Value,
    pub signing_payload_canonical_cbor_hex: String,
    /// Independent implementation the payload is cross-checked against.
    pub differential: String,
}

/// Re-derived content of a domain vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Computed {
    pub canonical: Vec<u8>,
    pub hash: Hash32,
    pub derived_id: Option<String>,
    /// JSON form of the encoded value; [`decode`] of `canonical` must equal it.
    pub encoded_json: Value,
    /// Name of the producing function.
    pub producer: &'static str,
    pub encoded_type: &'static str,
}

/// Every field of [`PolicyBundle`] except `administrative_signatures`
/// (owned mirror of `oic_policy_kernel::PolicyBundleUnsigned`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundleUnsignedOwned {
    pub policy_id: PolicyId,
    pub policy_epoch: Epoch,
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub rules: Vec<PolicyRule>,
    pub denied_destinations: Vec<DestinationId>,
    pub denied_assets: Vec<AssetId>,
    pub max_evidence_age_seconds: u64,
    pub allowlist_version: u32,
    pub activation_epoch: Epoch,
}

/// Every field of [`CounterpartyDestination`] except
/// `administrative_signatures` (owned mirror of `oic_policy_kernel::DestinationUnsigned`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationUnsignedOwned {
    pub destination_id: DestinationId,
    pub version: u32,
    pub network_id: NetworkId,
    pub address: Bytes,
    pub address_display: String,
    pub display_name: String,
    pub allowed_assets: Vec<AssetId>,
    pub verification_evidence: String,
    pub activation_epoch: Epoch,
}

/// Owned mirror of `oic_policy_kernel::PreviewCommitment`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewCommitmentOwned {
    pub candidate_id: CandidateId,
    pub candidate_revision: u32,
    pub decoded_operation_hash: Hash32,
    pub evidence_bundle_hash: Hash32,
}

/// Every field of [`AuditEventBody`] except `event_id` (owned mirror of the
/// private `EventIdPreimage` in `oic-audit`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventIdPreimageOwned {
    pub sequence: u64,
    pub previous_event_hash: Hash32,
    pub at: UnixSeconds,
    pub actor: String,
    pub action: String,
    pub object_commitments: BTreeMap<String, Hash32>,
    pub policy_epoch: Epoch,
    pub detail: String,
}

/// `(prefix, parts)` preimage of an authority-assigned identifier.
pub type ReservationIdPreimage = (String, (OperationFamilyId, CandidateId, u32));
pub type FamilyIdPreimage = (String, IntentId);
pub type IssuanceIdPreimage = (String, ReservationId);
/// `("session-abort", session_id)` preimage of the signer abort sentinel.
pub type SessionAbortPreimage = (String, SigningSessionId);
/// `(kind, id)` preimage of an audit object commitment.
pub type AuditObjectPreimage = (String, String);

fn json_err(e: serde_json::Error) -> OicError {
    OicError::invalid_request(format!("vector input JSON: {e}"))
}

fn parse<T: DeserializeOwned>(input: &Value) -> OicResult<T> {
    serde_json::from_value(input.clone()).map_err(json_err)
}

fn to_json<T: Serialize>(v: &T) -> OicResult<Value> {
    serde_json::to_value(v).map_err(json_err)
}

/// `"<prefix>-" || hex(hash[..16])`, the authority and audit identifier form.
pub fn id_from_hash(prefix: &str, h: &Hash32) -> String {
    format!("{prefix}-{}", hex::encode(&h.0[..16]))
}

/// The signer's fence key id for a participant:
/// `"oic-signer-fence/" || hex(hash)[..32]`.
pub fn fence_key_from_hash(h: &Hash32) -> String {
    format!("oic-signer-fence/{}", &h.to_hex()[..32])
}

/// `SHA256(tag || CanonicalEncode(o))` for tags without a dedicated producer.
fn generic<T: Serialize>(tag: &'static str) -> impl FnOnce(&T) -> OicResult<Hash32> {
    move |o| domain_hash(tag, o)
}

struct Out {
    canonical: Vec<u8>,
    hash: Hash32,
    encoded_json: Value,
}

/// Encode `obj` itself and hash it with `producer`.
fn whole<T: Serialize>(obj: &T, producer: impl FnOnce(&T) -> OicResult<Hash32>) -> OicResult<Out> {
    Ok(Out { canonical: canonical_bytes(obj)?, hash: producer(obj)?, encoded_json: to_json(obj)? })
}

/// Encode a signed view `view` of the input and hash the input with `producer`.
fn view<T, V: Serialize>(obj: &T, view: &V, producer: impl FnOnce(&T) -> OicResult<Hash32>) -> OicResult<Out> {
    Ok(Out { canonical: canonical_bytes(view)?, hash: producer(obj)?, encoded_json: to_json(view)? })
}

fn policy_view(b: &PolicyBundle) -> PolicyBundleUnsignedOwned {
    PolicyBundleUnsignedOwned {
        policy_id: b.policy_id.clone(),
        policy_epoch: b.policy_epoch,
        institution_id: b.institution_id.clone(),
        environment_id: b.environment_id.clone(),
        rules: b.rules.clone(),
        denied_destinations: b.denied_destinations.clone(),
        denied_assets: b.denied_assets.clone(),
        max_evidence_age_seconds: b.max_evidence_age_seconds,
        allowlist_version: b.allowlist_version,
        activation_epoch: b.activation_epoch,
    }
}

fn destination_view(d: &CounterpartyDestination) -> DestinationUnsignedOwned {
    DestinationUnsignedOwned {
        destination_id: d.destination_id.clone(),
        version: d.version,
        network_id: d.network_id.clone(),
        address: d.address.clone(),
        address_display: d.address_display.clone(),
        display_name: d.display_name.clone(),
        allowed_assets: d.allowed_assets.clone(),
        verification_evidence: d.verification_evidence.clone(),
        activation_epoch: d.activation_epoch,
    }
}

fn event_id_view(b: &AuditEventBody) -> AuditEventIdPreimageOwned {
    AuditEventIdPreimageOwned {
        sequence: b.sequence,
        previous_event_hash: b.previous_event_hash,
        at: b.at,
        actor: b.actor.clone(),
        action: b.action.clone(),
        object_commitments: b.object_commitments.clone(),
        policy_epoch: b.policy_epoch,
        detail: b.detail.clone(),
    }
}

/// Re-derive canonical bytes, hash, and derived identifier of a vector
/// from `(domain, type, input)` with the workspace's producer function.
/// Also checks that every borrowed signed view (`PolicyBundleUnsigned`,
/// `DestinationUnsigned`, `PreviewCommitment`) and its owned mirror encode
/// identically, and that the producer hash equals the generic
/// `SHA256(domain || canonical)`.
pub fn compute(domain: &str, type_name: &str, input: &Value) -> OicResult<Computed> {
    use local_domains as l;
    use oic_domain_types::domains as d;
    let mut derived_id = None;
    let (out, producer, encoded_type): (Out, &'static str, &'static str) = match (domain, type_name) {
        (d::AUTHORIZATION, "AuthorizationEnvelopeBody") => {
            (whole(&parse::<AuthorizationEnvelopeBody>(input)?, oic_signer::envelope_body_hash)?, "oic_signer::envelope_body_hash", "AuthorizationEnvelopeBody")
        }
        (d::INTENT, "Intent") => (whole(&parse::<Intent>(input)?, oic_policy_kernel::intent_hash)?, "oic_policy_kernel::intent_hash", "Intent"),
        (d::CANDIDATE, "Candidate") => (
            whole(&parse::<Candidate>(input)?, |o| domain_hash(d::CANDIDATE, o))?,
            "oic_canonical_encoding::domain_hash (no dedicated producer)",
            "Candidate",
        ),
        (d::DECODED_OPERATION, "DecodedOperation") => {
            (whole(&parse::<DecodedOperation>(input)?, oic_adapter_api::decoded_operation_hash)?, "oic_adapter_api::decoded_operation_hash", "DecodedOperation")
        }
        (d::EVIDENCE, "EvidenceBundle") => (whole(&parse::<EvidenceBundle>(input)?, oic_adapter_api::evidence_hash)?, "oic_adapter_api::evidence_hash", "EvidenceBundle"),
        (d::POLICY, "PolicyBundle") => {
            let b: PolicyBundle = parse(input)?;
            let borrowed = canonical_bytes(&oic_policy_kernel::PolicyBundleUnsigned::from(&b))?;
            let out = view(&b, &policy_view(&b), oic_policy_kernel::policy_hash)?;
            ensure_eq(&borrowed, &out.canonical, "PolicyBundleUnsigned mirror")?;
            (out, "oic_policy_kernel::policy_hash", "PolicyBundleUnsigned")
        }
        (d::APPROVAL, "ApprovalGrantBody") => {
            (whole(&parse::<ApprovalGrantBody>(input)?, oic_approval_verifier::grant_signing_hash)?, "oic_approval_verifier::grant_signing_hash", "ApprovalGrantBody")
        }
        (d::PREVIEW, "PreviewCommitment") => {
            let p: PreviewCommitmentOwned = parse(input)?;
            let borrowed = canonical_bytes(&oic_policy_kernel::PreviewCommitment {
                candidate_id: &p.candidate_id,
                candidate_revision: p.candidate_revision,
                decoded_operation_hash: p.decoded_operation_hash,
                evidence_bundle_hash: p.evidence_bundle_hash,
            })?;
            let out = whole(&p, |p| Ok(oic_policy_kernel::preview_hash(&p.candidate_id, p.candidate_revision, p.decoded_operation_hash, p.evidence_bundle_hash)))?;
            ensure_eq(&borrowed, &out.canonical, "PreviewCommitment mirror")?;
            (out, "oic_policy_kernel::preview_hash", "PreviewCommitment")
        }
        (d::AUTHORITY_RECEIPT, "AuthorityReceiptBody") => {
            (whole(&parse::<AuthorityReceiptBody>(input)?, oic_authorization_state::receipt_hash)?, "oic_authorization_state::receipt_hash", "AuthorityReceiptBody")
        }
        (d::CHAIN_PROFILE, "ChainProfile") => (whole(&parse::<ChainProfile>(input)?, ChainProfile::hash)?, "oic_adapter_api::ChainProfile::hash", "ChainProfile"),
        (d::AUDIT, "AuditEventBody") => (whole(&parse::<AuditEventBody>(input)?, oic_audit::event_hash)?, "oic_audit::event_hash", "AuditEventBody"),
        (d::KEY_DESCRIPTOR, "KeyDescriptor") => {
            (whole(&parse::<KeyDescriptor>(input)?, generic(d::KEY_DESCRIPTOR))?, "oic_canonical_encoding::domain_hash (no dedicated producer)", "KeyDescriptor")
        }
        (d::PUBLIC_KEY, "PublicKey") => (whole(&parse::<PublicKey>(input)?, oic_signer::public_key_hash)?, "oic_signer::public_key_hash", "PublicKey"),
        (d::CONFIG_PROPOSAL, "FreezeProposal") => (whole(&parse::<FreezeProposal>(input)?, FreezeProposal::hash)?, "oic_authorization_state::FreezeProposal::hash", "FreezeProposal"),
        (d::CONFIG_PROPOSAL, "UnfreezeProposal") => {
            (whole(&parse::<UnfreezeProposal>(input)?, UnfreezeProposal::hash)?, "oic_authorization_state::UnfreezeProposal::hash", "UnfreezeProposal")
        }
        (d::DESTINATION, "CounterpartyDestination") => {
            let dst: CounterpartyDestination = parse(input)?;
            let borrowed = canonical_bytes(&oic_policy_kernel::DestinationUnsigned::from(&dst))?;
            let out = view(&dst, &destination_view(&dst), oic_policy_kernel::destination_hash)?;
            ensure_eq(&borrowed, &out.canonical, "DestinationUnsigned mirror")?;
            (out, "oic_policy_kernel::destination_hash", "DestinationUnsigned")
        }
        (d::JOURNAL, "JournalEntryBody") => {
            (whole(&parse::<JournalEntryBody>(input)?, generic(d::JOURNAL))?, "oic_canonical_encoding::domain_hash (no dedicated producer)", "JournalEntryBody")
        }
        (d::OBSERVED_MOVEMENT, "ObservedMovement") => (
            whole(&parse::<ObservedMovement>(input)?, generic(d::OBSERVED_MOVEMENT))?,
            "oic_canonical_encoding::domain_hash (no dedicated producer)",
            "ObservedMovement",
        ),
        (d::RECONCILIATION, "ReconciliationCheckpointBody") => (
            whole(&parse::<ReconciliationCheckpointBody>(input)?, generic(d::RECONCILIATION))?,
            "oic_canonical_encoding::domain_hash (no dedicated producer)",
            "ReconciliationCheckpointBody",
        ),
        (d::WORKFLOW_TRIGGER, "WorkflowTrigger") => (
            whole(&parse::<WorkflowTrigger>(input)?, generic(d::WORKFLOW_TRIGGER))?,
            "oic_canonical_encoding::domain_hash (no dedicated producer)",
            "WorkflowTrigger",
        ),
        (d::WEBHOOK, "LifecycleEventBody") => (
            whole(&parse::<LifecycleEventBody>(input)?, generic(d::WEBHOOK))?,
            "oic_canonical_encoding::domain_hash (no dedicated producer)",
            "LifecycleEventBody",
        ),
        (d::SIGNER_FENCE, "ParticipantId") => {
            let out = whole(&parse::<ParticipantId>(input)?, generic(d::SIGNER_FENCE))?;
            derived_id = Some(fence_key_from_hash(&out.hash));
            (out, "oic_signer (private fence_key)", "ParticipantId")
        }
        (d::SIGNER_FENCE, "SessionAbortPreimage") => {
            (whole(&parse::<SessionAbortPreimage>(input)?, generic(d::SIGNER_FENCE))?, "oic_signer (private abort_sentinel)", "SessionAbortPreimage")
        }
        (l::AUTHORITY_ID, "ReservationIdPreimage") => {
            let p: ReservationIdPreimage = parse(input)?;
            let out = whole(&p, generic(l::AUTHORITY_ID))?;
            let id = id_from_hash(&p.0, &out.hash);
            let real = oic_authorization_state::reservation_id_for(&p.1 .0, &p.1 .1, p.1 .2)?;
            ensure_eq(id.as_bytes(), real.as_str().as_bytes(), "reservation_id_for")?;
            derived_id = Some(id);
            (out, "oic_authorization_state::reservation_id_for", "ReservationIdPreimage")
        }
        (l::AUTHORITY_ID, "FamilyIdPreimage") => {
            let p: FamilyIdPreimage = parse(input)?;
            let out = whole(&p, generic(l::AUTHORITY_ID))?;
            let id = id_from_hash(&p.0, &out.hash);
            let real = oic_authorization_state::family_id_for(&p.1)?;
            ensure_eq(id.as_bytes(), real.as_str().as_bytes(), "family_id_for")?;
            derived_id = Some(id);
            (out, "oic_authorization_state::family_id_for", "FamilyIdPreimage")
        }
        (l::AUTHORITY_ID, "IssuanceIdPreimage") => {
            let p: IssuanceIdPreimage = parse(input)?;
            let out = whole(&p, generic(l::AUTHORITY_ID))?;
            derived_id = Some(id_from_hash(&p.0, &out.hash));
            (out, "oic_authorization_state (private issuance_id_for)", "IssuanceIdPreimage")
        }
        (l::AUTHORITY_STATE, "AuthorityState") => {
            (whole(&parse::<AuthorityState>(input)?, oic_authorization_state::state_hash)?, "oic_authorization_state::state_hash", "AuthorityState")
        }
        (l::AUTHORITY_CHECKPOINT, "CheckpointBody") => {
            (whole(&parse::<CheckpointBody>(input)?, oic_authorization_state::checkpoint_hash)?, "oic_authorization_state::checkpoint_hash", "CheckpointBody")
        }
        (l::AUDIT_EVENT_ID, "AuditEventBody") => {
            let b: AuditEventBody = parse(input)?;
            let out = view(&b, &event_id_view(&b), |v| domain_hash(l::AUDIT_EVENT_ID, &event_id_view(v)))?;
            let id = id_from_hash("evt", &out.hash);
            let real = oic_audit::derive_event_id(&b)?;
            ensure_eq(id.as_bytes(), real.as_str().as_bytes(), "derive_event_id")?;
            derived_id = Some(id);
            (out, "oic_audit::derive_event_id", "AuditEventIdPreimage")
        }
        (l::AUDIT_CHECKPOINT, "AuditCheckpointBody") => {
            (whole(&parse::<oic_audit::AuditCheckpointBody>(input)?, oic_audit::audit_checkpoint_hash)?, "oic_audit::audit_checkpoint_hash", "AuditCheckpointBody")
        }
        (l::AUDIT_OBJECT, "AuditObjectPreimage") => {
            (whole(&parse::<AuditObjectPreimage>(input)?, |p| oic_audit::object_commitment(&p.0, &p.1))?, "oic_audit::object_commitment", "AuditObjectPreimage")
        }
        (l::AUTHORITY_EVENT, "AuthorityEvent") => {
            (whole(&parse::<AuthorityEvent>(input)?, oic_audit::authority_event_commitment)?, "oic_audit::authority_event_commitment", "AuthorityEvent")
        }
        (dom, ty) => return Err(OicError::invalid_request(format!("no vector producer for domain {dom} and type {ty}"))),
    };
    let generic_hash = oic_canonical_encoding::domain_hash_bytes(domain, &out.canonical);
    ensure_eq(&generic_hash.0, &out.hash.0, "producer hash vs SHA256(domain || canonical)")?;
    Ok(Computed { canonical: out.canonical, hash: out.hash, derived_id, encoded_json: out.encoded_json, producer, encoded_type })
}

fn ensure_eq(a: &[u8], b: &[u8], what: &str) -> OicResult<()> {
    if a == b {
        Ok(())
    } else {
        Err(OicError::internal(format!("{what}: {} != {}", hex::encode(a), hex::encode(b))))
    }
}

fn dec<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> OicResult<Value> {
    to_json(&from_canonical_bytes::<T>(bytes)?)
}

/// Strictly decode `canonical` as the vector's encoded type and return the
/// JSON form of the decoded value.
pub fn decode(encoded_type: &str, canonical: &[u8]) -> OicResult<Value> {
    match encoded_type {
        "AuthorizationEnvelopeBody" => dec::<AuthorizationEnvelopeBody>(canonical),
        "Intent" => dec::<Intent>(canonical),
        "Candidate" => dec::<Candidate>(canonical),
        "DecodedOperation" => dec::<DecodedOperation>(canonical),
        "EvidenceBundle" => dec::<EvidenceBundle>(canonical),
        "PolicyBundleUnsigned" => dec::<PolicyBundleUnsignedOwned>(canonical),
        "ApprovalGrantBody" => dec::<ApprovalGrantBody>(canonical),
        "PreviewCommitment" => dec::<PreviewCommitmentOwned>(canonical),
        "AuthorityReceiptBody" => dec::<AuthorityReceiptBody>(canonical),
        "ChainProfile" => dec::<ChainProfile>(canonical),
        "AuditEventBody" => dec::<AuditEventBody>(canonical),
        "KeyDescriptor" => dec::<KeyDescriptor>(canonical),
        "PublicKey" => dec::<PublicKey>(canonical),
        "FreezeProposal" => dec::<FreezeProposal>(canonical),
        "UnfreezeProposal" => dec::<UnfreezeProposal>(canonical),
        "DestinationUnsigned" => dec::<DestinationUnsignedOwned>(canonical),
        "JournalEntryBody" => dec::<JournalEntryBody>(canonical),
        "ObservedMovement" => dec::<ObservedMovement>(canonical),
        "ReconciliationCheckpointBody" => dec::<ReconciliationCheckpointBody>(canonical),
        "WorkflowTrigger" => dec::<WorkflowTrigger>(canonical),
        "LifecycleEventBody" => dec::<LifecycleEventBody>(canonical),
        "ParticipantId" => dec::<ParticipantId>(canonical),
        "SessionAbortPreimage" => dec::<SessionAbortPreimage>(canonical),
        "ReservationIdPreimage" => dec::<ReservationIdPreimage>(canonical),
        "FamilyIdPreimage" => dec::<FamilyIdPreimage>(canonical),
        "IssuanceIdPreimage" => dec::<IssuanceIdPreimage>(canonical),
        "AuthorityState" => dec::<AuthorityState>(canonical),
        "CheckpointBody" => dec::<CheckpointBody>(canonical),
        "AuditEventIdPreimage" => dec::<AuditEventIdPreimageOwned>(canonical),
        "AuditCheckpointBody" => dec::<oic_audit::AuditCheckpointBody>(canonical),
        "AuditObjectPreimage" => dec::<AuditObjectPreimage>(canonical),
        "AuthorityEvent" => dec::<AuthorityEvent>(canonical),
        other => Err(OicError::invalid_request(format!("no decoder for encoded type {other}"))),
    }
}

/// Build a complete [`DomainVector`] from an input value, checking that the
/// hash the caller obtained directly from the typed object (`expected_hash`)
/// equals what [`compute`] derives from the JSON form.
pub fn make_vector<T: Serialize>(name: &str, domain: &str, type_name: &str, input: &T, expected_hash: Hash32) -> OicResult<DomainVector> {
    let input = to_json(input)?;
    let c = compute(domain, type_name, &input)?;
    if c.hash != expected_hash {
        return Err(OicError::internal(format!("{name}: typed producer hash {expected_hash} != JSON-derived hash {}", c.hash)));
    }
    Ok(DomainVector {
        name: name.to_string(),
        domain: domain.to_string(),
        type_name: type_name.to_string(),
        encoded_type: c.encoded_type.to_string(),
        producer: c.producer.to_string(),
        input,
        canonical_cbor_hex: hex::encode(&c.canonical),
        hash_hex: c.hash.to_hex(),
        derived_id: c.derived_id,
        ed25519: None,
    })
}

/// Pretty JSON with a trailing newline, the on-disk vector form.
pub fn to_file_json<T: Serialize>(v: &T) -> OicResult<String> {
    let mut s = serde_json::to_string_pretty(v).map_err(json_err)?;
    s.push('\n');
    Ok(s)
}
