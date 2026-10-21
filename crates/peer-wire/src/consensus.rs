//! Fixed D2 host carrier for native Commonware codec messages, not CBOR and
//! not a generic application/extension encoder. Channels1–3 carry public
//! consensus records;4–5 carry confidential block/resolver records. Hosts must
//! enforce signed ACLs and feed payloads only to their matching native codecs.

use crate::{
    FrameKind, WireError,
    frame::{decode_frame, encode_frame},
};

pub struct ConsensusFrame<'a> {
    payload: &'a [u8],
}

impl std::fmt::Debug for ConsensusFrame<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConsensusFrame([REDACTED])")
    }
}

impl<'a> ConsensusFrame<'a> {
    /// Accept only bytes produced by the native codec for this fixed channel.
    /// This host API is not available through ExtensionContext. Class S peer
    /// messages have no implicit conversion into it.
    ///
    /// ```compile_fail,E0308
    /// use oic_peer_wire::{ConsensusFrame, SignedPeerMessage};
    /// fn leak(secret: &SignedPeerMessage) {
    ///     ConsensusFrame::encode(secret, 0, 1, 1024).unwrap();
    /// }
    /// ```
    pub fn encode(
        payload: &[u8],
        epoch: u64,
        channel: u64,
        max_len: usize,
    ) -> Result<Vec<u8>, WireError> {
        encode_frame(payload, epoch, kind(channel)?, max_len)
    }

    /// Checks the exact epoch, fixed native channel/kind and announced length
    /// before borrowing any payload. Native decoding/authentication follows.
    pub fn decode(
        bytes: &'a [u8],
        epoch: u64,
        channel: u64,
        max_len: usize,
    ) -> Result<Self, WireError> {
        Ok(Self {
            payload: decode_frame(bytes, epoch, kind(channel)?, max_len)?,
        })
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

fn kind(channel: u64) -> Result<FrameKind, WireError> {
    match channel {
        1 => Ok(FrameKind::ConsensusVote),
        2 => Ok(FrameKind::ConsensusCertificate),
        3 => Ok(FrameKind::ConsensusResolver),
        4 => Ok(FrameKind::MarshalBlock),
        5 => Ok(FrameKind::MarshalBackfill),
        _ => Err(WireError::WrongCarrier),
    }
}
