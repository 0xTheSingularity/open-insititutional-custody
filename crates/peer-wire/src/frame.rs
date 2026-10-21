use crate::{AuthorityReply, AuthorityRequest, SessionControl, SessionReply, WireError, WitnessMessage};
use oic_canonical_encoding::{canonical_bytes, is_canonical};
use oic_domain_types::{ApprovalGrant, AuthorityReceipt, AuthorizationEnvelope, Candidate, EvidenceBundle, Hash32, Intent, IssuanceRecord, KeyDescriptor};
use serde::{Deserialize, Serialize};

pub const WIRE_VERSION: u16 = 1;
/// Fixed big-endian header: version:u16, roster_epoch:u64, kind:u16, body_len:u32.
pub const HEADER_LEN: usize = 16;
/// Absolute body cap; the channel ACL may impose a smaller limit on every call.
pub const MAX_BODY_LEN: usize = 64 * 1024;

/// Complete padded application-frame sizes, excluding the node routing prefix
/// and Commonware encryption/framing. Padding never raises an ACL or wire cap.
pub const PADDING_BUCKETS_V1: [usize; 4] = [1024, 4096, 16384, HEADER_LEN + MAX_BODY_LEN];
const PADDING_MAGIC: &[u8; 8] = b"OIC/PAD\x01";
const PADDING_HEADER_LEN: usize = 12;

/// Explicit local transport profile, not a change to canonical or signed bytes.
/// Enable consistently at both endpoints; no fallback or wire negotiation exists.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PaddingProfile {
    #[default]
    Disabled,
    FixedBucketsV1,
}

impl PaddingProfile {
    /// Wrap an already encoded frame for one named recipient on channel 10,
    /// 20 or 21 only. Returned MPC bytes remain Class S; this is not a public,
    /// block, broadcast, extension or resolver encoder. `max_wire_len` bounds
    /// the complete padded frame, unlike body limits on the security codecs.
    ///
    /// FixedBucketsV1 uses magic `OIC/PAD\x01`, the original frame length as a
    /// big-endian u32, the unchanged frame, then zeroes to the smallest bucket.
    /// The encrypted transport hides this length header, not bucket membership.
    pub fn encode_point_to_point(
        self,
        frame: Vec<u8>,
        expected_epoch: u64,
        kind: FrameKind,
        max_wire_len: usize,
    ) -> Result<Vec<u8>, WireError> {
        check_padding_kind(kind)?;
        let limit = max_wire_len.min(HEADER_LEN + MAX_BODY_LEN);
        if frame.len() > limit {
            return Err(WireError::TooLarge);
        }
        if self == Self::Disabled {
            reject_padding_marker(&frame)?;
            return Ok(frame);
        }
        // Structural validation only: canonical security-body interpretation and
        // participant authentication remain in their existing reviewed codecs.
        decode_frame(&frame, expected_epoch, kind, MAX_BODY_LEN)?;
        let bucket = padding_bucket(frame.len(), limit)?;
        let mut out = Vec::with_capacity(bucket);
        out.extend_from_slice(PADDING_MAGIC);
        out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        out.extend_from_slice(&frame);
        out.resize(bucket, 0);
        Ok(out)
    }

    /// Borrow the original frame without allocation, before parsing its body.
    /// Reject mixed profiles, oversized announcements, nonminimal buckets,
    /// truncated frames, nonzero padding and wrong inner version/epoch/kind.
    /// Unpadding does not authenticate a participant or authorize a release.
    pub fn decode_point_to_point(
        self,
        bytes: &[u8],
        expected_epoch: u64,
        kind: FrameKind,
        max_wire_len: usize,
    ) -> Result<&[u8], WireError> {
        check_padding_kind(kind)?;
        let limit = max_wire_len.min(HEADER_LEN + MAX_BODY_LEN);
        if bytes.len() > limit {
            return Err(WireError::TooLarge);
        }
        if self == Self::Disabled {
            reject_padding_marker(bytes)?;
            return Ok(bytes);
        }
        let header = bytes.get(..PADDING_HEADER_LEN).ok_or(WireError::InvalidLength)?;
        if &header[..8] != PADDING_MAGIC {
            return Err(WireError::InvalidPadding);
        }
        let len = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
        // This is checked before any length-derived slice or allocation.
        let bucket = padding_bucket(len, limit)?;
        if bytes.len() != bucket {
            return Err(WireError::InvalidPadding);
        }
        let end = PADDING_HEADER_LEN + len;
        let frame = &bytes[PADDING_HEADER_LEN..end];
        if bytes[end..].iter().any(|byte| *byte != 0) {
            return Err(WireError::InvalidPadding);
        }
        decode_frame(frame, expected_epoch, kind, MAX_BODY_LEN)?;
        Ok(frame)
    }
}

fn check_padding_kind(kind: FrameKind) -> Result<(), WireError> {
    if matches!(kind, FrameKind::Content | FrameKind::MpcSign | FrameKind::MpcCeremony) {
        Ok(())
    } else {
        Err(WireError::WrongCarrier)
    }
}

fn reject_padding_marker(bytes: &[u8]) -> Result<(), WireError> {
    if bytes.starts_with(&PADDING_MAGIC[..7]) {
        Err(WireError::InvalidPadding)
    } else {
        Ok(())
    }
}

fn padding_bucket(frame_len: usize, limit: usize) -> Result<usize, WireError> {
    if frame_len > (HEADER_LEN + MAX_BODY_LEN) - PADDING_HEADER_LEN {
        return Err(WireError::TooLarge);
    }
    if frame_len < HEADER_LEN {
        return Err(WireError::InvalidLength);
    }
    PADDING_BUCKETS_V1.into_iter()
        .find(|bucket| *bucket >= PADDING_HEADER_LEN + frame_len && *bucket <= limit)
        .ok_or(WireError::TooLarge)
}

/// V1 routing kinds. A kind is not a transport channel or proof of admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FrameKind {
    Control = 0,
    ConsensusVote = 1,
    ConsensusCertificate = 2,
    ConsensusResolver = 3,
    MarshalBlock = 4,
    MarshalBackfill = 5,
    Content = 10,
    Attestation = 11,
    AuthorityRpc = 12,
    MpcSign = 20,
    MpcCeremony = 21,
    Audit = 30,
}

impl FrameKind {
    pub(crate) fn is_consensus(self) -> bool {
        matches!(self, Self::ConsensusVote | Self::ConsensusCertificate | Self::ConsensusResolver | Self::MarshalBlock | Self::MarshalBackfill)
    }

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
    /// Native consensus and MPC frames require their separate reviewed codecs.
    pub fn decode(bytes: &'a [u8], expected_epoch: u64, expected_kind: FrameKind, max_body_len: usize) -> Result<Self, WireError> {
        if expected_kind.is_mpc() || expected_kind.is_consensus() {
            return Err(WireError::WrongCarrier);
        }
        let body = decode_frame(bytes, expected_epoch, expected_kind, max_body_len)?;
        if !is_canonical(body) {
            return Err(WireError::InvalidBody);
        }
        Ok(Self { wire_version: WIRE_VERSION, roster_epoch: expected_epoch, kind: expected_kind, body })
    }

    pub fn encode_public<T: PublicBody>(body: &T, roster_epoch: u64, kind: FrameKind, max_body_len: usize) -> Result<Vec<u8>, WireError> {
        if kind.is_mpc() || kind.is_consensus() || kind.is_confidential() || !T::allows_frame(kind) {
            return Err(WireError::WrongCarrier);
        }
        body.validate_public()?;
        encode_security_body(body, roster_epoch, kind, max_body_len)
    }

    pub fn encode_confidential<T: ConfidentialBody>(body: &T, roster_epoch: u64, kind: FrameKind, max_body_len: usize) -> Result<Vec<u8>, WireError> {
        if kind.is_consensus() || !kind.is_confidential() || !T::allows_frame(kind) {
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
