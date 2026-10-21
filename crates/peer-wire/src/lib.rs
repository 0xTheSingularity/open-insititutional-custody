//! Bounded peer framing and signer-core participant authentication (RFC 0003).
//!
//! Frame metadata is an untrusted routing hint. Only [`SignedPeerMessage::verify`]
//! authenticates MPC contents. Callers obtain participant keys and generations
//! from an activated roster, and advance round/sequence expectations themselves.
//! Decoding is not authorization, replay tracking, or decryption.
//!
//! Class S has no general-purpose serialization or public carrier implementation:
//!
//! ```compile_fail
//! use oic_peer_wire::{SignedPeerMessage, PeerFrameV1, FrameKind, MAX_BODY_LEN};
//! fn broadcast(secret: &SignedPeerMessage) {
//!     PeerFrameV1::encode_public(secret, 1, FrameKind::Audit, MAX_BODY_LEN).unwrap();
//! }
//! ```
//! ```compile_fail
//! use oic_peer_wire::{SignedPeerMessage, PeerFrameV1, FrameKind, MAX_BODY_LEN};
//! fn block(secret: &SignedPeerMessage) {
//!     PeerFrameV1::encode_confidential(secret, 1, FrameKind::Content, MAX_BODY_LEN).unwrap();
//! }
//! ```
//! ```compile_fail
//! use oic_peer_wire::SignedPeerMessage;
//! fn resolver(secret: &SignedPeerMessage) {
//!     oic_canonical_encoding::canonical_bytes(secret).unwrap();
//! }
//! ```
//! The allowlist is sealed; external crates cannot mark their own secret wrapper
//! public. There is intentionally no raw-bytes public frame constructor.
//!
//! ```compile_fail
//! use oic_peer_wire::PublicBody;
//! #[derive(serde::Serialize)]
//! struct SmuggledSecret(Vec<u8>);
//! impl PublicBody for SmuggledSecret {}
//! ```
//!
//! Confidential session controls cannot enter a public broadcast/block carrier:
//! ```compile_fail
//! use oic_peer_wire::{SessionControl, PeerFrameV1, FrameKind, MAX_BODY_LEN};
//! fn broadcast(control: &SessionControl) {
//!     PeerFrameV1::encode_public(control, 1, FrameKind::Audit, MAX_BODY_LEN).unwrap();
//! }
//! ```

mod authority;
mod control;
mod frame;
mod message;

pub use authority::{AuthorityReply, AuthorityRequest, AuthorityResult};
pub use control::{SessionControl, SessionReply, SessionResult};
pub use frame::{
    ConfidentialBody, FrameKind, PeerFrameV1, PublicBody, RosterState, HEADER_LEN, MAX_BODY_LEN,
    WIRE_VERSION,
};
pub use message::{
    ExpectedPeerMessage, MessageScope, SignedPeerMessage, MAX_PAYLOAD_LEN, MAX_PROTOCOL_VERSION_LEN,
};

/// Bounded rejection reasons. Errors never contain payloads or attacker input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    TooLarge,
    InvalidLength,
    UnsupportedVersion,
    UnexpectedEpoch,
    UnexpectedKind,
    WrongCarrier,
    InvalidBody,
    InvalidMessage,
    ScopeMismatch,
    SenderMismatch,
    RecipientMismatch,
    GenerationMismatch,
    SessionMismatch,
    KeyMismatch,
    ProtocolMismatch,
    RoundMismatch,
    SequenceMismatch,
    InvalidSignature,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer wire: {self:?}")
    }
}

impl std::error::Error for WireError {}
