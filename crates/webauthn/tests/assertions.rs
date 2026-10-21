use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use oic_canonical_encoding::{canonical_bytes, value::Value};
use oic_webauthn::{
    encode_assertion, validate_credential, verify_assertion, verify_canonical_assertion, Assertion,
    EnrolledCredential, Error, VerifiedAssertion, MAX_ALLOWED_ORIGINS, MAX_ASSERTION_LEN,
    MAX_CLIENT_DATA_JSON_LEN, MAX_ORIGIN_LEN, MAX_RP_ID_LEN, MAX_SIGNATURE_LEN,
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

const RP: &str = "custody.example";
const ORIGIN: &str = "https://approver.custody.example";
const GRANT: [u8; 32] = [0x42; 32];

struct Fixture {
    key: SigningKey,
    public: Vec<u8>,
    auth: Vec<u8>,
    client: Vec<u8>,
    signature: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let public = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let mut auth = Sha256::digest(RP.as_bytes()).to_vec();
        auth.push(0x05); // UP + UV, single-device credential.
        auth.extend_from_slice(&0x0102_0304_u32.to_be_bytes());
        let client = serde_json::to_vec(&json!({
            "type": "webauthn.get", "challenge": URL_SAFE_NO_PAD.encode(GRANT),
            "origin": ORIGIN, "crossOrigin": false,
        }))
        .unwrap();
        let mut fixture = Self {
            key,
            public,
            auth,
            client,
            signature: Vec::new(),
        };
        fixture.sign();
        fixture
    }

    fn sign(&mut self) {
        let mut message = self.auth.clone();
        message.extend_from_slice(&Sha256::digest(&self.client));
        let signature: Signature = self.key.sign(&message);
        self.signature = signature.to_der().as_bytes().to_vec();
    }

    fn set_client(&mut self, field: &str, value: serde_json::Value) {
        let mut client: serde_json::Value = serde_json::from_slice(&self.client).unwrap();
        client[field] = value;
        self.client = serde_json::to_vec(&client).unwrap();
        self.sign();
    }

    fn assertion(&self) -> Assertion<'_> {
        Assertion {
            authenticator_data: &self.auth,
            client_data_json: &self.client,
            signature: &self.signature,
        }
    }

    fn enrolled(&self) -> EnrolledCredential<'_> {
        EnrolledCredential {
            public_key_sec1: &self.public,
            rp_id: RP,
            allowed_origins: &[ORIGIN],
        }
    }

    fn verify(&self) -> Result<VerifiedAssertion, Error> {
        verify_assertion(&self.enrolled(), &GRANT, self.assertion())
    }

    fn carrier(&self) -> BTreeMap<&str, serde_bytes::ByteBuf> {
        BTreeMap::from([
            ("authenticator_data", self.auth.clone().into()),
            ("client_data_json", self.client.clone().into()),
            ("signature", self.signature.clone().into()),
        ])
    }
}

#[test]
fn genuine_assertion_roundtrips_canonical_with_both_sec1_key_encodings() {
    let fixture = Fixture::new();
    let expected = VerifiedAssertion {
        sign_count: 0x0102_0304,
        backup_eligible: false,
        backup_state: false,
    };
    assert_eq!(fixture.verify(), Ok(expected));
    let encoded = encode_assertion(fixture.assertion()).unwrap();
    assert_eq!(encoded, canonical_bytes(&fixture.carrier()).unwrap());
    assert_eq!(
        verify_canonical_assertion(&fixture.enrolled(), &GRANT, &encoded),
        Ok(expected)
    );
    let compressed = fixture.key.verifying_key().to_encoded_point(true);
    let enrollment = EnrolledCredential {
        public_key_sec1: compressed.as_bytes(),
        ..fixture.enrolled()
    };
    assert_eq!(
        verify_canonical_assertion(&enrollment, &GRANT, &encoded),
        Ok(expected)
    );
    let enrollment = EnrolledCredential {
        allowed_origins: &["https://other-approved.custody.example", ORIGIN],
        ..fixture.enrolled()
    };
    assert_eq!(
        verify_assertion(&enrollment, &GRANT, fixture.assertion()),
        Ok(expected)
    );
    let Value::Map(fields) = oic_canonical_encoding::value::decode(&encoded).unwrap() else {
        panic!("map required")
    };
    assert_eq!(fields.len(), 3);
    assert!(fields.values().all(|(_, v)| matches!(v, Value::Bytes(_))));
}

#[test]
fn enrollment_validation_checks_key_points_and_configuration_without_an_assertion() {
    let fixture = Fixture::new();
    assert_eq!(validate_credential(&fixture.enrolled()), Ok(()));
    let compressed = fixture.key.verifying_key().to_encoded_point(true);
    assert_eq!(
        validate_credential(&EnrolledCredential {
            public_key_sec1: compressed.as_bytes(),
            ..fixture.enrolled()
        }),
        Ok(())
    );
    let mut off_curve = vec![0; 65];
    off_curve[0] = 4;
    for key in [vec![], vec![0; 32], vec![0; 33], off_curve] {
        assert_eq!(
            validate_credential(&EnrolledCredential {
                public_key_sec1: &key,
                ..fixture.enrolled()
            }),
            Err(Error::InvalidPublicKey)
        );
    }
    let long_rp = "r".repeat(MAX_RP_ID_LEN + 1);
    for rp in ["", "has space.example", "rp.example\n", long_rp.as_str()] {
        assert_eq!(
            validate_credential(&EnrolledCredential {
                rp_id: rp,
                ..fixture.enrolled()
            }),
            Err(Error::InvalidConfiguration)
        );
    }
    let long_origin = "o".repeat(MAX_ORIGIN_LEN + 1);
    for origins in [
        vec![],
        vec!["null"],
        vec![""],
        vec!["https://bad.example\n"],
        vec![long_origin.as_str()],
        vec![ORIGIN; MAX_ALLOWED_ORIGINS + 1],
    ] {
        assert_eq!(
            validate_credential(&EnrolledCredential {
                allowed_origins: &origins,
                ..fixture.enrolled()
            }),
            Err(Error::InvalidConfiguration)
        );
    }
    assert_eq!(
        validate_credential(&EnrolledCredential {
            allowed_origins: &[ORIGIN; MAX_ALLOWED_ORIGINS],
            ..fixture.enrolled()
        }),
        Ok(())
    );
}

#[test]
fn unchanged_independent_w3c_es256_assertion_with_high_s_verifies() {
    // W3C WebAuthn Level 3, Recommendation 2026-08-25, §16.6:
    // https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-test-vectors-none-es256-long-credential-id
    // Public x/y are copied from the registration's COSE key; assertion bytes,
    // challenge, and DER signature are copied unchanged. No signing in this test.
    let public = hex::decode(concat!(
        "04",
        "3b8176b7504489cc593046d7988abb7905a742de6ac2cdc748a873c663e90cb1",
        "1436d5edc9a75f23999eef9d5950a5c2455514ee1014084720f841a06b828a11"
    ))
    .unwrap();
    let grant: [u8; 32] =
        hex::decode("ef1deba56dce48f674a447ccf63b9599258ce87648e5c396f2ef0ca1da460e3b")
            .unwrap()
            .try_into()
            .unwrap();
    let auth =
        hex::decode("bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000")
            .unwrap();
    let client = hex::decode("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22377833727057334f53505a307045664d396a75566d53574d36485a4935634f573875384d6f647047446a73222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d").unwrap();
    let signature = hex::decode("304502203ecef83fb12a0cae7841055f9f87103a99fd14b424194bbf06c4623d3ee6e3fd022100d2ace346db262b1374a6b70faa51f518a42ddca13a4125ce6f5052a75bac9fb6").unwrap();
    assert!(
        Signature::from_der(&signature)
            .unwrap()
            .normalize_s()
            .is_some(),
        "fixture specifically covers high-S"
    );
    let enrolled = EnrolledCredential {
        public_key_sec1: &public,
        rp_id: "example.org",
        allowed_origins: &["https://example.org"],
    };
    let raw = Assertion {
        authenticator_data: &auth,
        client_data_json: &client,
        signature: &signature,
    };
    let expected = VerifiedAssertion {
        sign_count: 0,
        backup_eligible: true,
        backup_state: false,
    };
    assert_eq!(verify_assertion(&enrolled, &grant, raw), Ok(expected));
    assert_eq!(
        verify_canonical_assertion(&enrolled, &grant, &encode_assertion(raw).unwrap()),
        Ok(expected)
    );
    let low_s = Signature::from_der(&signature)
        .unwrap()
        .normalize_s()
        .unwrap()
        .to_der();
    assert_eq!(
        verify_assertion(
            &enrolled,
            &grant,
            Assertion {
                signature: low_s.as_bytes(),
                ..raw
            }
        ),
        Ok(expected)
    );
    // Change only the encoding of the genuine valid r/s, not its scalar values.
    // A permissive ASN.1 reader would otherwise accept the same signature.
    let mut nonminimal = signature.clone();
    nonminimal[1] += 1;
    nonminimal[3] += 1;
    nonminimal.insert(4, 0); // Redundant INTEGER sign-padding for r = 0x3e….
    assert_eq!(nonminimal.len(), MAX_SIGNATURE_LEN);
    assert_eq!(
        verify_assertion(
            &enrolled,
            &grant,
            Assertion {
                signature: &nonminimal,
                ..raw
            }
        ),
        Err(Error::InvalidSignature)
    );
    let mut trailing = signature.clone();
    trailing.push(0);
    assert_eq!(
        verify_assertion(
            &enrolled,
            &grant,
            Assertion {
                signature: &trailing,
                ..raw
            }
        ),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn correctly_signed_wrong_type_challenge_origin_and_rp_are_rejected() {
    let challenge = URL_SAFE_NO_PAD.encode(GRANT);
    let mut noncanonical_bits = challenge.clone().into_bytes();
    // GRANT's final canonical character is I (value 8). J has the same useful
    // high four bits, but nonzero unused bits; permissive decoders alias these.
    assert_eq!(noncanonical_bits.last(), Some(&b'I'));
    *noncanonical_bits.last_mut().unwrap() = b'J';
    for (field, value, expected) in [
        ("type", json!("webauthn.create"), Error::WrongType),
        ("type", json!("login"), Error::WrongType),
        (
            "challenge",
            json!(URL_SAFE_NO_PAD.encode([0x24; 32])),
            Error::WrongChallenge,
        ),
        (
            "challenge",
            json!(format!("{challenge}=")),
            Error::WrongChallenge,
        ),
        (
            "challenge",
            json!(String::from_utf8(noncanonical_bits).unwrap()),
            Error::WrongChallenge,
        ),
        ("challenge", json!("*".repeat(43)), Error::WrongChallenge),
        (
            "origin",
            json!("https://console.custody.example"),
            Error::WrongOrigin,
        ),
        (
            "origin",
            json!("https://approver.custody.example.attacker.test"),
            Error::WrongOrigin,
        ),
        (
            "origin",
            json!("https://approver.custody.example:443"),
            Error::WrongOrigin,
        ),
        ("origin", json!("null"), Error::WrongOrigin),
    ] {
        let mut fixture = Fixture::new();
        fixture.set_client(field, value);
        assert_eq!(fixture.verify(), Err(expected), "{field}");
    }
    let mut fixture = Fixture::new();
    fixture.auth[0] ^= 1;
    fixture.sign();
    assert_eq!(fixture.verify(), Err(Error::WrongRpId));
    let fixture = Fixture::new();
    assert_eq!(
        verify_assertion(&fixture.enrolled(), &[0x24; 32], fixture.assertion()),
        Err(Error::WrongChallenge)
    );
    let enrollment = EnrolledCredential {
        rp_id: "other.example",
        ..fixture.enrolled()
    };
    assert_eq!(
        verify_assertion(&enrollment, &GRANT, fixture.assertion()),
        Err(Error::WrongRpId)
    );
}

#[test]
fn raw_json_authenticator_data_key_and_signature_tampering_fail() {
    let mut fixture = Fixture::new();
    fixture.client.push(b' '); // Same parsed JSON, different signed raw bytes.
    assert_eq!(fixture.verify(), Err(Error::InvalidSignature));
    let mut fixture = Fixture::new();
    fixture.auth[35] ^= 1; // Change an asymmetric big-endian counter, not scope.
    assert_eq!(fixture.verify(), Err(Error::InvalidSignature));
    let mut fixture = Fixture::new();
    fixture.signature[10] ^= 1;
    assert_eq!(fixture.verify(), Err(Error::InvalidSignature));
    let mut fixture = Fixture::new();
    let other = SigningKey::from_slice(&[8; 32]).unwrap();
    fixture.public = other
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    assert_eq!(fixture.verify(), Err(Error::InvalidSignature));
    fixture.public = vec![0; 65];
    fixture.public[0] = 4; // Correct SEC1 shape, invalid curve point.
    assert_eq!(fixture.verify(), Err(Error::InvalidPublicKey));
}

#[test]
fn presence_verification_and_backup_flags_have_explicit_semantics() {
    for (flags, expected) in [
        (0x04, Error::UserPresenceRequired),
        (0x01, Error::UserVerificationRequired),
        (0x15, Error::InvalidBackupFlags),       // BS without BE.
        (0x45, Error::InvalidAuthenticatorData), // Registration data.
        (0x85, Error::InvalidAuthenticatorData), // Unnegotiated extension data.
        (0x07, Error::InvalidAuthenticatorData), // RFU1.
        (0x25, Error::InvalidAuthenticatorData), // RFU2.
    ] {
        let mut fixture = Fixture::new();
        fixture.auth[32] = flags;
        fixture.sign();
        assert_eq!(fixture.verify(), Err(expected));
    }
    for (flags, count, be, bs) in [
        (0x05, 0_u32, false, false),
        (0x0d, 3, true, false),
        (0x1d, u32::MAX, true, true),
    ] {
        let mut fixture = Fixture::new();
        fixture.auth[32] = flags;
        fixture.auth[33..].copy_from_slice(&count.to_be_bytes());
        fixture.sign();
        let expected = VerifiedAssertion {
            sign_count: count,
            backup_eligible: be,
            backup_state: bs,
        };
        assert_eq!(fixture.verify(), Ok(expected));
        // This stateless primitive intentionally makes no replay/clone claim.
        assert_eq!(fixture.verify(), Ok(expected));
    }
}

#[test]
fn cross_origin_and_any_top_origin_are_rejected_with_valid_signatures() {
    let mut fixture = Fixture::new();
    fixture.set_client("crossOrigin", json!(true));
    assert_eq!(fixture.verify(), Err(Error::CrossOrigin));
    for value in [
        json!("https://console.custody.example"),
        json!(null),
        json!(false),
    ] {
        let mut fixture = Fixture::new();
        fixture.set_client("topOrigin", value);
        assert_eq!(fixture.verify(), Err(Error::CrossOrigin));
    }
    for value in [json!(null), json!("false"), json!(0)] {
        let mut fixture = Fixture::new();
        fixture.set_client("crossOrigin", value);
        assert_eq!(fixture.verify(), Err(Error::InvalidClientData));
    }
}

#[test]
fn duplicate_escaped_duplicate_unknown_missing_and_malformed_json_are_rejected() {
    for extra in [
        r#", "type":"webauthn.get""#,
        r#", "\u0074ype":"webauthn.get""#,
        r#", "challenge":"wrong""#,
        r#", "origin":"https://approver.custody.example""#,
        r#", "crossOrigin":false"#,
        r#", "extraData":"unsupported in this profile""#,
    ] {
        let mut fixture = Fixture::new();
        fixture.client.pop();
        fixture.client.extend_from_slice(extra.as_bytes());
        fixture.client.push(b'}');
        fixture.sign();
        assert_eq!(fixture.verify(), Err(Error::InvalidClientData), "{extra}");
    }
    for missing in ["type", "challenge", "origin"] {
        let mut fixture = Fixture::new();
        let mut client: serde_json::Value = serde_json::from_slice(&fixture.client).unwrap();
        client.as_object_mut().unwrap().remove(missing);
        fixture.client = serde_json::to_vec(&client).unwrap();
        fixture.sign();
        assert_eq!(fixture.verify(), Err(Error::InvalidClientData));
    }
    let struct_array = serde_json::to_vec(&json!([
        "webauthn.get",
        URL_SAFE_NO_PAD.encode(GRANT),
        ORIGIN
    ]))
    .unwrap();
    for client in [
        b"{} {}".as_slice(),
        b"[]",
        b"{\"type\":\"\xff\"}",
        b"",
        &struct_array,
    ] {
        let mut fixture = Fixture::new();
        fixture.client = client.to_vec();
        fixture.sign();
        assert_eq!(fixture.verify(), Err(Error::InvalidClientData));
    }
}

#[test]
fn valid_json_reordering_escaping_whitespace_and_utf8_bom_preserve_raw_signing() {
    let mut fixture = Fixture::new();
    fixture.client = format!(
        r#"{{ "origin": "{ORIGIN}", "challenge": "{}", "type": "webauthn.\u0067et" }}"#,
        URL_SAFE_NO_PAD.encode(GRANT)
    )
    .into_bytes();
    fixture.sign();
    assert!(fixture.verify().is_ok()); // crossOrigin absent means false.
    fixture.client.splice(..0, [0xef, 0xbb, 0xbf]);
    fixture.sign();
    assert!(fixture.verify().is_ok());
    fixture.client.drain(..3); // Same parsed data; hash must still include BOM.
    assert_eq!(fixture.verify(), Err(Error::InvalidSignature));
}

#[test]
fn field_and_carrier_size_boundaries_and_truncation_fail_closed() {
    let mut fixture = Fixture::new();
    fixture.client.resize(MAX_CLIENT_DATA_JSON_LEN, b' ');
    fixture.sign();
    assert!(fixture.verify().is_ok());
    let encoded = encode_assertion(fixture.assertion()).unwrap();
    assert!(verify_canonical_assertion(&fixture.enrolled(), &GRANT, &encoded).is_ok());
    fixture.client.push(b' ');
    assert_eq!(fixture.verify(), Err(Error::TooLarge));
    assert_eq!(encode_assertion(fixture.assertion()), Err(Error::TooLarge));
    let mut fixture = Fixture::new();
    fixture.auth.pop();
    assert_eq!(fixture.verify(), Err(Error::InvalidAuthenticatorData));
    fixture.auth.extend_from_slice(&[0, 0]);
    assert_eq!(fixture.verify(), Err(Error::TooLarge));
    let mut fixture = Fixture::new();
    fixture.signature.resize(MAX_SIGNATURE_LEN + 1, 0);
    assert_eq!(fixture.verify(), Err(Error::TooLarge));
    assert_eq!(
        verify_canonical_assertion(&fixture.enrolled(), &GRANT, &vec![0; MAX_ASSERTION_LEN + 1]),
        Err(Error::TooLarge)
    );
    assert_eq!(
        verify_canonical_assertion(&fixture.enrolled(), &GRANT, &vec![0; MAX_ASSERTION_LEN]),
        Err(Error::InvalidCbor)
    );
    // Huge declared bstr with no payload: shared bounded codec must reject it,
    // rather than allocating according to this attacker-controlled length.
    assert_eq!(
        verify_canonical_assertion(
            &fixture.enrolled(),
            &GRANT,
            &hex::decode("a1697369676e61747572655bffffffffffffffff").unwrap()
        ),
        Err(Error::InvalidCbor)
    );
}

#[test]
fn der_not_raw_rs_and_canonical_cbor_are_required() {
    let mut fixture = Fixture::new();
    fixture.signature = Signature::from_der(&fixture.signature)
        .unwrap()
        .to_bytes()
        .to_vec();
    assert_eq!(fixture.verify(), Err(Error::InvalidSignature));
    for bad_der in [
        "300702020001020101",
        "300602010102010100",
        "3006020100020101",
    ] {
        fixture.signature = hex::decode(bad_der).unwrap();
        assert_eq!(fixture.verify(), Err(Error::InvalidSignature));
    }
    let fixture = Fixture::new();
    let encoded = encode_assertion(fixture.assertion()).unwrap();
    let mut trailing = encoded.clone();
    trailing.push(0);
    let mut nonminimal = vec![0xb8, 3];
    nonminimal.extend_from_slice(&encoded[1..]);
    let mut indefinite = encoded.clone();
    indefinite[0] = 0xbf;
    indefinite.push(0xff);
    let mut carrier = fixture.carrier();
    carrier.insert("untrusted_key", vec![9; 33].into());
    let unknown = canonical_bytes(&carrier).unwrap();
    let mut duplicate = encoded.clone();
    duplicate[0] = 0xa4;
    // authenticator_data is the final key under the canonical encoded-key order.
    let last = canonical_bytes(&BTreeMap::from([(
        "authenticator_data",
        serde_bytes::ByteBuf::from(fixture.auth.clone()),
    )]))
    .unwrap();
    duplicate.extend_from_slice(&last[1..]);
    let arrays = canonical_bytes(&BTreeMap::from([
        ("authenticator_data", fixture.auth.clone()),
        ("client_data_json", fixture.client.clone()),
        ("signature", fixture.signature.clone()),
    ]))
    .unwrap();
    for malformed in [trailing, nonminimal, indefinite, unknown, duplicate, arrays] {
        assert_eq!(
            verify_canonical_assertion(&fixture.enrolled(), &GRANT, &malformed),
            Err(Error::InvalidCbor)
        );
    }
}
