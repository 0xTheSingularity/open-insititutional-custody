use ed25519_dalek::SigningKey;
use oic_canonical_encoding::{from_canonical_bytes, value, Value};
use oic_crypto_provider::PeerMessage;
use oic_domain_types::*;
use oic_peer_wire::*;

type ExpectationEdit = fn(&mut ExpectedPeerMessage);

fn message() -> PeerMessage {
    PeerMessage {
        session_id: SigningSessionId::unchecked("session-17"),
        key_id: KeyId::unchecked("key-2"),
        key_epoch: Epoch(9),
        from: ParticipantId::unchecked("alice"),
        from_generation: Epoch(13),
        to: Some(ParticipantId::unchecked("bob")),
        round: 3,
        sequence: 27,
        protocol_version: "frost-v2.1".into(),
        payload: Bytes(vec![0xf1, 0x7a, 0x04]),
    }
}

fn scope() -> MessageScope {
    MessageScope {
        institution_id: InstitutionId::unchecked("institution-4"),
        environment_id: EnvironmentId::unchecked("mainnet"),
        roster_epoch: 21,
        roster_hash: Hash32([0xa3; 32]),
    }
}

fn expected() -> ExpectedPeerMessage {
    let m = message();
    ExpectedPeerMessage {
        scope: scope(),
        session_id: m.session_id,
        key_id: m.key_id,
        key_epoch: m.key_epoch,
        from: m.from,
        from_generation: m.from_generation,
        to: m.to.unwrap(),
        round: m.round,
        sequence: m.sequence,
        protocol_version: m.protocol_version,
    }
}

#[test]
fn participant_signed_point_to_point_roundtrip() {
    let key = SigningKey::from_bytes(&[0x51; 32]);
    let signed = SignedPeerMessage::sign(message(), scope(), &key).unwrap();
    let wire = signed
        .encode_point_to_point(FrameKind::MpcSign, MAX_BODY_LEN)
        .unwrap();
    let decoded =
        SignedPeerMessage::decode_point_to_point(&wire, 21, FrameKind::MpcSign, MAX_BODY_LEN)
            .unwrap();
    assert_eq!(
        decoded.verify(&expected(), &key.verifying_key()).unwrap(),
        &message()
    );
    assert_eq!(decoded.session_id().as_str(), "session-17");
    assert_eq!(decoded.sender().as_str(), "alice");
    assert_eq!(decoded.round(), 3);
    assert_eq!(format!("{signed:?}"), "SignedPeerMessage([REDACTED])");
}

#[test]
fn scope_generation_recipient_and_replay_expectations_are_exact() {
    let key = SigningKey::from_bytes(&[0x51; 32]);
    let signed = SignedPeerMessage::sign(message(), scope(), &key).unwrap();
    let cases: &[(ExpectationEdit, WireError)] = &[
        (
            |e| e.scope.institution_id = InstitutionId::unchecked("institution-5"),
            WireError::ScopeMismatch,
        ),
        (
            |e| e.scope.environment_id = EnvironmentId::unchecked("testnet"),
            WireError::ScopeMismatch,
        ),
        (|e| e.scope.roster_epoch += 1, WireError::ScopeMismatch),
        (|e| e.scope.roster_hash.0[19] ^= 1, WireError::ScopeMismatch),
        (
            |e| e.from = ParticipantId::unchecked("carol"),
            WireError::SenderMismatch,
        ),
        (
            |e| e.to = ParticipantId::unchecked("carol"),
            WireError::RecipientMismatch,
        ),
        (
            |e| e.from_generation = Epoch(12),
            WireError::GenerationMismatch,
        ),
        (
            |e| e.from_generation = Epoch(14),
            WireError::GenerationMismatch,
        ),
        (
            |e| e.session_id = SigningSessionId::unchecked("session-18"),
            WireError::SessionMismatch,
        ),
        (
            |e| e.key_id = KeyId::unchecked("key-3"),
            WireError::KeyMismatch,
        ),
        (|e| e.key_epoch = Epoch(10), WireError::KeyMismatch),
        (
            |e| e.protocol_version = "frost-v3".into(),
            WireError::ProtocolMismatch,
        ),
        (|e| e.round += 1, WireError::RoundMismatch),
        (|e| e.sequence += 1, WireError::SequenceMismatch),
    ];
    for (change, error) in cases {
        let mut context = expected();
        change(&mut context);
        assert_eq!(
            signed.verify(&context, &key.verifying_key()).unwrap_err(),
            *error
        );
    }
    // A transport process's perfectly valid signature is not a participant signature.
    let transport_key = SigningKey::from_bytes(&[0x62; 32]);
    let forged = SignedPeerMessage::sign(message(), scope(), &transport_key).unwrap();
    assert_eq!(
        forged
            .verify(&expected(), &key.verifying_key())
            .unwrap_err(),
        WireError::InvalidSignature
    );
}

fn replace_field(value: &mut Value, path: &[&str], replacement: Value) {
    let Value::Map(map) = value else {
        panic!("expected map")
    };
    let (_, field) = map.get_mut(&value::encode(&Value::text(path[0]))).unwrap();
    if path.len() == 1 {
        *field = replacement;
    } else {
        replace_field(field, &path[1..], replacement);
    }
}

fn rewrite_body(wire: &[u8], path: &[&str], replacement: Value) -> Vec<u8> {
    let mut body = value::decode(&wire[HEADER_LEN..]).unwrap();
    replace_field(&mut body, path, replacement);
    let body = value::encode(&body);
    let mut wire = wire[..HEADER_LEN].to_vec();
    wire[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
    wire.extend(body);
    wire
}

#[test]
fn signature_binds_every_message_field_and_network_scope_even_if_hints_are_rewritten() {
    let key = SigningKey::from_bytes(&[0x51; 32]);
    let signed = SignedPeerMessage::sign(message(), scope(), &key).unwrap();
    let wire = signed
        .encode_point_to_point(FrameKind::MpcSign, MAX_BODY_LEN)
        .unwrap();
    let cases: &[(&[&str], Value, ExpectationEdit)] = &[
        (
            &["scope", "institution_id"],
            Value::text("institution-5"),
            |e| e.scope.institution_id = InstitutionId::unchecked("institution-5"),
        ),
        (&["scope", "environment_id"], Value::text("testnet"), |e| {
            e.scope.environment_id = EnvironmentId::unchecked("testnet")
        }),
        (&["scope", "roster_epoch"], Value::Unsigned(22), |e| {
            e.scope.roster_epoch = 22
        }),
        (
            &["scope", "roster_hash"],
            Value::Bytes(vec![0xb4; 32]),
            |e| e.scope.roster_hash = Hash32([0xb4; 32]),
        ),
        (&["message", "session_id"], Value::text("session-18"), |e| {
            e.session_id = SigningSessionId::unchecked("session-18")
        }),
        (&["message", "key_id"], Value::text("key-3"), |e| {
            e.key_id = KeyId::unchecked("key-3")
        }),
        (&["message", "key_epoch"], Value::Unsigned(10), |e| {
            e.key_epoch = Epoch(10)
        }),
        (&["message", "from"], Value::text("carol"), |e| {
            e.from = ParticipantId::unchecked("carol")
        }),
        (&["message", "from_generation"], Value::Unsigned(14), |e| {
            e.from_generation = Epoch(14)
        }),
        (&["message", "to"], Value::text("carol"), |e| {
            e.to = ParticipantId::unchecked("carol")
        }),
        (&["message", "round"], Value::Unsigned(4), |e| e.round = 4),
        (&["message", "sequence"], Value::Unsigned(28), |e| {
            e.sequence = 28
        }),
        (
            &["message", "protocol_version"],
            Value::text("frost-v3"),
            |e| e.protocol_version = "frost-v3".into(),
        ),
        (
            &["message", "payload"],
            Value::Bytes(vec![0xf1, 0x7a, 0x05]),
            |_| {},
        ),
        (&["signature"], Value::Bytes(vec![0x93; 64]), |_| {}),
    ];
    for (path, replacement, change) in cases {
        let mut context = expected();
        change(&mut context);
        let mut tampered = rewrite_body(&wire, path, replacement.clone());
        tampered[2..10].copy_from_slice(&context.scope.roster_epoch.to_be_bytes());
        let decoded = SignedPeerMessage::decode_point_to_point(
            &tampered,
            context.scope.roster_epoch,
            FrameKind::MpcSign,
            MAX_BODY_LEN,
        )
        .unwrap();
        assert_eq!(
            decoded.verify(&context, &key.verifying_key()).unwrap_err(),
            WireError::InvalidSignature,
            "tampered {path:?}"
        );
    }
}

#[test]
fn public_frame_roundtrip_and_strict_version_epoch_kind_length_and_cbor() {
    let record = RosterState {
        roster_epoch: 21,
        roster_hash: Hash32([0xa3; 32]),
    };
    let wire = PeerFrameV1::encode_public(&record, 21, FrameKind::Control, MAX_BODY_LEN).unwrap();
    // Independent literal for version, epoch, and kind; framing is big-endian.
    assert_eq!(&wire[..12], &[0, 1, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0]);
    let frame = PeerFrameV1::decode(&wire, 21, FrameKind::Control, MAX_BODY_LEN).unwrap();
    assert_eq!(
        from_canonical_bytes::<RosterState>(frame.body()).unwrap(),
        record
    );
    assert_eq!(format!("{frame:?}"), "PeerFrameV1([REDACTED])");
    assert_eq!(
        PeerFrameV1::decode(&wire, 22, FrameKind::Control, MAX_BODY_LEN).unwrap_err(),
        WireError::UnexpectedEpoch
    );
    assert_eq!(
        PeerFrameV1::decode(&wire, 21, FrameKind::Audit, MAX_BODY_LEN).unwrap_err(),
        WireError::UnexpectedKind
    );
    for (offset, value, error) in [
        (1, 2, WireError::UnsupportedVersion),
        (11, 255, WireError::UnexpectedKind),
    ] {
        let mut bad = wire.clone();
        bad[offset] = value;
        assert_eq!(
            PeerFrameV1::decode(&bad, 21, FrameKind::Control, MAX_BODY_LEN).unwrap_err(),
            error
        );
    }
    for bad in [
        &wire[..15],
        &wire[..wire.len() - 1],
        &[wire.clone(), vec![0]].concat(),
    ] {
        assert_eq!(
            PeerFrameV1::decode(bad, 21, FrameKind::Control, MAX_BODY_LEN).unwrap_err(),
            WireError::InvalidLength
        );
    }
    let mut noncanonical = wire[..HEADER_LEN].to_vec();
    noncanonical[12..16].copy_from_slice(&2u32.to_be_bytes());
    noncanonical.extend([0x18, 0x01]); // 1 with an unnecessary argument byte.
    assert_eq!(
        PeerFrameV1::decode(&noncanonical, 21, FrameKind::Control, MAX_BODY_LEN).unwrap_err(),
        WireError::InvalidBody
    );
}

#[test]
fn oversize_is_rejected_from_header_before_body_is_present_or_parsed() {
    let mut header = [0u8; HEADER_LEN];
    header[0..2].copy_from_slice(&1u16.to_be_bytes());
    header[2..10].copy_from_slice(&21u64.to_be_bytes());
    header[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        PeerFrameV1::decode(&header, 21, FrameKind::Control, usize::MAX).unwrap_err(),
        WireError::TooLarge
    );
    header[10..12].copy_from_slice(&20u16.to_be_bytes());
    assert_eq!(
        SignedPeerMessage::decode_point_to_point(&header, 21, FrameKind::MpcSign, usize::MAX)
            .unwrap_err(),
        WireError::TooLarge
    );
    let key = SigningKey::from_bytes(&[0x51; 32]);
    let mut m = message();
    m.payload = Bytes(vec![0x85; MAX_PAYLOAD_LEN]);
    let signed = SignedPeerMessage::sign(m.clone(), scope(), &key).unwrap();
    let wire = signed
        .encode_point_to_point(FrameKind::MpcSign, MAX_BODY_LEN)
        .unwrap();
    assert!(
        SignedPeerMessage::decode_point_to_point(&wire, 21, FrameKind::MpcSign, MAX_BODY_LEN)
            .is_ok()
    );
    let body_len = wire.len() - HEADER_LEN;
    assert!(signed
        .encode_point_to_point(FrameKind::MpcSign, body_len)
        .is_ok());
    assert_eq!(
        signed
            .encode_point_to_point(FrameKind::MpcSign, body_len - 1)
            .unwrap_err(),
        WireError::TooLarge
    );
    assert_eq!(
        SignedPeerMessage::decode_point_to_point(&wire, 21, FrameKind::MpcSign, body_len - 1)
            .unwrap_err(),
        WireError::TooLarge
    );
    m.payload.0.push(0x86);
    assert_eq!(
        SignedPeerMessage::sign(m, scope(), &key).unwrap_err(),
        WireError::TooLarge
    );
}

#[test]
fn point_to_point_refuses_broadcast_wrong_carriers_and_unsigned_epoch_changes() {
    let key = SigningKey::from_bytes(&[0x51; 32]);
    let mut m = message();
    m.to = None;
    assert_eq!(
        SignedPeerMessage::sign(m, scope(), &key).unwrap_err(),
        WireError::RecipientMismatch
    );
    let signed = SignedPeerMessage::sign(message(), scope(), &key).unwrap();
    assert_eq!(
        signed
            .encode_point_to_point(FrameKind::Content, MAX_BODY_LEN)
            .unwrap_err(),
        WireError::WrongCarrier
    );
    let mut wire = signed
        .encode_point_to_point(FrameKind::MpcCeremony, MAX_BODY_LEN)
        .unwrap();
    assert_eq!(
        PeerFrameV1::decode(&wire, 21, FrameKind::MpcCeremony, MAX_BODY_LEN).unwrap_err(),
        WireError::WrongCarrier
    );
    assert_eq!(
        SignedPeerMessage::decode_point_to_point(&wire, 21, FrameKind::MpcSign, MAX_BODY_LEN)
            .unwrap_err(),
        WireError::UnexpectedKind
    );
    wire[2..10].copy_from_slice(&22u64.to_be_bytes());
    assert_eq!(
        SignedPeerMessage::decode_point_to_point(&wire, 22, FrameKind::MpcCeremony, MAX_BODY_LEN)
            .unwrap_err(),
        WireError::ScopeMismatch
    );
}

#[test]
fn confidential_session_controls_and_replies_roundtrip_without_protocol_frames() {
    let controls = [
        SessionControl::Status {
            request_id: 19,
            session_id: SigningSessionId::unchecked("session-17"),
        },
        SessionControl::Abort {
            request_id: 20,
            session_id: SigningSessionId::unchecked("session-18"),
        },
        SessionControl::Aggregate {
            request_id: 21,
            session_id: SigningSessionId::unchecked("session-19"),
            shares: vec![(ParticipantId::unchecked("bob"), Bytes(vec![4, 8, 15]))],
        },
    ];
    for control in controls {
        let wire = PeerFrameV1::encode_confidential(&control, 21, FrameKind::Content, MAX_BODY_LEN)
            .unwrap();
        let frame = PeerFrameV1::decode(&wire, 21, FrameKind::Content, MAX_BODY_LEN).unwrap();
        assert_eq!(
            from_canonical_bytes::<SessionControl>(frame.body()).unwrap(),
            control
        );
        assert_eq!(
            PeerFrameV1::encode_confidential(&control, 21, FrameKind::Audit, MAX_BODY_LEN)
                .unwrap_err(),
            WireError::WrongCarrier
        );
        assert_eq!(format!("{control:?}"), "SessionControl([REDACTED])");
    }
    for result in [
        Ok(SessionResult::Accepted),
        Ok(SessionResult::Waiting),
        Ok(SessionResult::Share(Bytes(vec![16, 23, 42]))),
        Ok(SessionResult::Complete(SignatureBytes {
            scheme: SchemeId::Ed25519Pure,
            bytes: Bytes(vec![1; 64]),
        })),
        Ok(SessionResult::Aborted),
        Err(OicError::new(
            ErrorCode::SessionRejected,
            "release required",
        )),
    ] {
        let reply = SessionReply {
            request_id: 93,
            result,
        };
        let wire =
            PeerFrameV1::encode_confidential(&reply, 21, FrameKind::Content, MAX_BODY_LEN).unwrap();
        let frame = PeerFrameV1::decode(&wire, 21, FrameKind::Content, MAX_BODY_LEN).unwrap();
        assert_eq!(
            from_canonical_bytes::<SessionReply>(frame.body()).unwrap(),
            reply
        );
        assert_eq!(format!("{reply:?}"), "SessionReply([REDACTED])");
    }
}
