//! The public producer schemas must agree with real committed protocol vectors.
use ed25519_dalek::{Signer as _, SigningKey};
use oic_domain_types::{Amount, ApprovalGrantBody, Intent, LifecycleEventBody};
use oic_golden_vectors::{schemas_dir, vectors_dir, DomainVector};
use serde_json::{json, Value};

fn validator(name: &str) -> jsonschema::Validator {
    let mut schema: Value = serde_json::from_str(
        &std::fs::read_to_string(schemas_dir().join("protocol-v1.json")).unwrap(),
    )
    .unwrap();
    schema.as_object_mut().unwrap().remove("oneOf");
    schema["$ref"] = json!(format!("#/$defs/{name}"));
    jsonschema::validator_for(&schema).unwrap()
}

fn vectors(file: &str) -> Vec<DomainVector> {
    serde_json::from_str(&std::fs::read_to_string(vectors_dir().join(file)).unwrap()).unwrap()
}

#[test]
fn public_schemas_validate_committed_intents_approvals_and_event_bodies() {
    let mut count = 0;
    for file in ["intent.json", "approval.json", "webhook.json"] {
        for vector in vectors(file) {
            let schema = validator(&vector.type_name);
            schema
                .validate(&vector.input)
                .unwrap_or_else(|e| panic!("{}: {e}", vector.name));
            // Decode the same representation through the real public types.
            match vector.type_name.as_str() {
                "Intent" => {
                    serde_json::from_value::<Intent>(vector.input.clone()).unwrap();
                }
                "ApprovalGrantBody" => {
                    serde_json::from_value::<ApprovalGrantBody>(vector.input.clone()).unwrap();
                }
                "LifecycleEventBody" => {
                    serde_json::from_value::<LifecycleEventBody>(vector.input.clone()).unwrap();
                }
                other => panic!("unexpected public vector {other}"),
            }
            if vector.type_name != "Intent" {
                let hash = hex::decode(&vector.hash_hex).unwrap();
                let signature = SigningKey::from_bytes(&[44; 32]).sign(&hash);
                let mut signed = json!({ "body": vector.input, "signature": { "scheme": "ed25519_pure", "bytes": format!("0x{}", hex::encode(signature.to_bytes())) } });
                let name = if vector.type_name == "ApprovalGrantBody" {
                    "ApprovalGrant"
                } else {
                    signed["signing_key_id"] = json!("event-key");
                    "LifecycleEvent"
                };
                validator(name).validate(&signed).unwrap();
                signed["signature"]["bytes"] = json!("00");
                assert!(
                    !validator(name).is_valid(&signed),
                    "signature truncation must fail"
                );
            }
            count += 1;
        }
    }
    assert!(count >= 6);
}

#[test]
fn public_schemas_reject_lossy_amounts_ambiguous_scopes_and_omitted_signed_fields() {
    let intent = vectors("intent.json").remove(0).input;
    let schema = validator("Intent");
    for invalid in [
        json!(9007199254740993u64),
        json!("01"),
        json!("-1"),
        json!("1.0"),
        json!("1e18"),
    ] {
        let mut changed = intent.clone();
        changed["operation"]["asset_transfer"]["amount_base_units"] = invalid;
        assert!(!schema.is_valid(&changed));
    }
    let mut maximum = intent.clone();
    maximum["operation"]["asset_transfer"]["amount_base_units"] =
        json!("340282366920938463463374607431768211455");
    assert!(schema.is_valid(&maximum));
    let typed: Intent = serde_json::from_value(maximum).unwrap();
    let oic_domain_types::IntentOperation::AssetTransfer {
        amount_base_units, ..
    } = typed.operation;
    assert_eq!(amount_base_units, Amount(u128::MAX));
    // The structural length/pattern schema is deliberately not a u128 parser.
    assert!(
        serde_json::from_value::<Amount>(json!("340282366920938463463374607431768211456")).is_err()
    );

    let grants = vectors("approval.json");
    let mut ambiguous = grants[0].input.clone();
    ambiguous["scope"]["bounded_direct_transfer"] =
        grants[1].input["scope"]["bounded_direct_transfer"].clone();
    assert!(!validator("ApprovalGrantBody").is_valid(&ambiguous));
    let mut wrong_hash = grants[0].input.clone();
    wrong_hash["scope"]["exact_candidate"]["preview_hash"] = json!("abcd");
    assert!(!validator("ApprovalGrantBody").is_valid(&wrong_hash));

    let mut event = vectors("webhook.json").remove(0).input;
    event["kind"]["operation_state_changed"]
        .as_object_mut()
        .unwrap()
        .remove("tx_id");
    assert!(
        !validator("LifecycleEventBody").is_valid(&event),
        "null is part of the signed representation, not an omitted field"
    );
    event["kind"]["operation_state_changed"]["tx_id"] = Value::Null;
    assert!(validator("LifecycleEventBody").is_valid(&event));
}
