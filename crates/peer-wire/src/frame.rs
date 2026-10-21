use crate::{AuthorityReply, AuthorityRequest, SessionControl, SessionReply, WireError, WitnessMessage};
use oic_canonical_encoding::{canonical_bytes, is_canonical};
use oic_domain_types::{ApprovalGrant, AuthorityReceipt, AuthorizationEnvelope, Candidate, EvidenceBundle, Hash32, Intent, IssuanceRecord, KeyDescriptor};
use serde::{Deserialize, Serialize};

pub const WIRE_VERSION: u16 = 1;
/// Fixed big-endian header: version:u16, roster_epoch:u64, kind:u16, body_len:u32.
pub const HEADER_LEN: usize = 16;
/// Absolute body cap; the channel ACL may impose a smaller limit on every call.
pub const MAX_BODY_LEN: usize = 64 * 1024;

/// V1 routing kinds. A kind is not a transport channel or proof of admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FrameKind {
    Control = 0,
    Content = 10,
    Attestation = 11,
    AuthorityRpc = 12,
    MpcSign = 20,
    MpcCeremony = 21,
    Audit = 30,
}

impl FrameKind {
    pub(crate) fn is_mpc(self) -> bool {
        matches!(self, Self::MpcSign | Self::MpcCeremony)
    }

    fn is_confidential(self) -> bool {
        matches!(self, Self::Content | Self::AuthorityRpc)
    }
}

mod sealed {
    pub trait Public {
        fn allows_frame(_kind: super::FrameKind) -> bool {
            true
        }
        fn validate_public(&self) -> Result<(), super::WireError> {
            Ok(())
        }
    }
    pub trait Confidential {
        fn allows_frame(kind: super::FrameKind) -> bool;
    }
}

/// Only explicitly reviewed Class P security bodies can use a public carrier.
/// No blanket implementation for `Serialize`, byte strings, or backend frames.
pub trait PublicBody: sealed::Public + Serialize {}
/// Only explicitly reviewed Class C bodies can use content/authority carriers.
pub trait ConfidentialBody: sealed::Confidential + Serialize {}

macro_rules! public_body {
    ($($ty:ty),+ $(,)?) => { $(
        impl sealed::Public for $ty {}
        impl PublicBody for $ty {}
    )+ };
}

macro_rules! confidential_body {
    ($kind:pat => $($ty:ty),+ $(,)?) => { $(
        impl sealed::Confidential for $ty {
            fn allows_frame(kind: FrameKind) -> bool { matches!(kind, $kind) }
        }
        impl ConfidentialBody for $ty {}
    )+ };
}

/// Roster convergence hint; admission still requires admin-signed roster validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterState {
    pub roster_epoch: u64,
    pub roster_hash: Hash32,
}

public_body!(RosterState, KeyDescriptor, AuthorityReceipt, IssuanceRecord);
impl sealed::Public for WitnessMessage {
    fn allows_frame(kind: FrameKind) -> bool {
        kind == FrameKind::Audit
    }
    fn validate_public(&self) -> Result<(), WireError> {
        WitnessMessage::validate_public(self).map_err(|_| WireError::InvalidBody)
    }
}
impl PublicBody for WitnessMessage {}

confidential_body!(FrameKind::Content | FrameKind::AuthorityRpc =>
    Intent,
    Candidate,
    EvidenceBundle,
    ApprovalGrant,
    AuthorizationEnvelope,
    SessionControl,
    SessionReply
);
confidential_body!(FrameKind::AuthorityRpc => AuthorityRequest, AuthorityReply);

/// Borrowed Class P/C frame. Decode checks all header expectations before CBOR
/// parsing; body bytes are borrowed, never copied according to a declared length.
/// Debug is redacted because a decoded frame may contain confidential records.
pub struct PeerFrameV1<'a> {
    pub wire_version: u16,
    pub roster_epoch: u64,
    pub kind: FrameKind,
    body: &'a [u8],
}

impl std::fmt::Debug for PeerFrameV1<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerFrameV1([REDACTED])")
    }
}

impl<'a> PeerFrameV1<'a> {
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Decode one complete frame; concatenated frames and trailing data fail.
    /// MPC frames require `SignedPeerMessage::decode_point_to_point` instead.
    pub fn decode(bytes: &'a [u8], expected_epoch: u64, expected_kind: FrameKind, max_body_len: usize) -> Result<Self, WireError> {
        if expected_kind.is_mpc() {
            return Err(WireError::WrongCarrier);
        }
        let body = decode_frame(bytes, expected_epoch, expected_kind, max_body_len)?;
        if !is_canonical(body) {
            return Err(WireError::InvalidBody);
        }
        Ok(Self { wire_version: WIRE_VERSION, roster_epoch: expected_epoch, kind: expected_kind, body })
    }

    pub fn encode_public<T: PublicBody>(body: &T, roster_epoch: u64, kind: FrameKind, max_body_len: usize) -> Result<Vec<u8>, WireError> {
        if kind.is_mpc() || kind.is_confidential() || !T::allows_frame(kind) {
            return Err(WireError::WrongCarrier);
        }
        body.validate_public()?;
        encode_security_body(body, roster_epoch, kind, max_body_len)
    }

    pub fn encode_confidential<T: ConfidentialBody>(body: &T, roster_epoch: u64, kind: FrameKind, max_body_len: usize) -> Result<Vec<u8>, WireError> {
        if !kind.is_confidential() || !T::allows_frame(kind) {
            return Err(WireError::WrongCarrier);
        }
        encode_security_body(body, roster_epoch, kind, max_body_len)
    }
}

fn encode_security_body<T: Serialize>(body: &T, roster_epoch: u64, kind: FrameKind, max_body_len: usize) -> Result<Vec<u8>, WireError> {
    let body = canonical_bytes(body).map_err(|_| WireError::InvalidBody)?;
    if body.len() > max_body_len.min(MAX_BODY_LEN) {
        return Err(WireError::TooLarge);
    }
    // The shared canonical profile also bounds depth and aggregate item count.
    if !is_canonical(&body) {
        return Err(WireError::InvalidBody);
    }
    encode_frame(&body, roster_epoch, kind, max_body_len)
}

pub(crate) fn encode_frame(body: &[u8], roster_epoch: u64, kind: FrameKind, max_body_len: usize) -> Result<Vec<u8>, WireError> {
    if body.len() > max_body_len.min(MAX_BODY_LEN) {
        return Err(WireError::TooLarge);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&roster_epoch.to_be_bytes());
    out.extend_from_slice(&(kind as u16).to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

pub(crate) fn decode_frame(bytes: &[u8], expected_epoch: u64, expected_kind: FrameKind, max_body_len: usize) -> Result<&[u8], WireError> {
    let limit = max_body_len.min(MAX_BODY_LEN);
    if bytes.len() > HEADER_LEN + limit {
        return Err(WireError::TooLarge);
    }
    let header = bytes.get(..HEADER_LEN).ok_or(WireError::InvalidLength)?;
    if u16::from_be_bytes(header[0..2].try_into().unwrap()) != WIRE_VERSION {
        return Err(WireError::UnsupportedVersion);
    }
    if u64::from_be_bytes(header[2..10].try_into().unwrap()) != expected_epoch {
        return Err(WireError::UnexpectedEpoch);
    }
    if u16::from_be_bytes(header[10..12].try_into().unwrap()) != expected_kind as u16 {
        return Err(WireError::UnexpectedKind);
    }
    let len = u32::from_be_bytes(header[12..16].try_into().unwrap()) as usize;
    // Inspect the announced length before accessing, copying, or decoding body.
    if len > limit {
        return Err(WireError::TooLarge);
    }
    if bytes.len() - HEADER_LEN != len {
        return Err(WireError::InvalidLength);
    }
    Ok(&bytes[HEADER_LEN..])
}
