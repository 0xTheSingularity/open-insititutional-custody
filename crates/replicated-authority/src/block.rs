use crate::Command;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{Block as ConsensusBlock, CertifiableBlock, Heightable, simplex::types::Context, types::Height};
use commonware_cryptography::{Digestible, Hasher, Sha256, ed25519::PublicKey, sha256::Digest};
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes};
use oic_domain_types::{Hash32, OicError, OicResult, UnixSeconds};

pub const MAX_COMMANDS: usize = 64;
pub const MAX_COMMAND_BYTES: usize = 64 * 1024;
pub type ConsensusContext = Context<Digest, PublicKey>;

/// A bounded confidential command batch inside Commonware's codec. The digest
/// commits to the complete context, parent, height, time, post-state and body.
/// No cached or peer-supplied digest is trusted during decoding.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorityBlock {
    context: ConsensusContext,
    height: Height,
    timestamp: UnixSeconds,
    state_hash: Hash32,
    body: Vec<u8>,
}

impl std::fmt::Debug for AuthorityBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityBlock").field("height", &self.height).finish_non_exhaustive()
    }
}

impl AuthorityBlock {
    pub fn new(context: ConsensusContext, height: Height, timestamp: UnixSeconds, state_hash: Hash32, commands: &[Command]) -> OicResult<Self> {
        if commands.len() > MAX_COMMANDS {
            return Err(OicError::invalid_request("too many authority commands"));
        }
        let body = canonical_bytes(commands)?;
        if body.len() > MAX_COMMAND_BYTES {
            return Err(OicError::invalid_request("authority command batch exceeds limit"));
        }
        Ok(Self { context, height, timestamp, state_hash, body })
    }

    pub fn commands(&self) -> OicResult<Vec<Command>> {
        from_canonical_bytes(&self.body)
    }

    pub fn timestamp(&self) -> UnixSeconds {
        self.timestamp
    }

    pub fn state_hash(&self) -> Hash32 {
        self.state_hash
    }
}

impl Write for AuthorityBlock {
    fn write(&self, writer: &mut impl BufMut) {
        self.context.write(writer);
        self.height.write(writer);
        self.timestamp.0.write(writer);
        writer.put_slice(&self.state_hash.0);
        (self.body.len() as u32).write(writer);
        writer.put_slice(&self.body);
    }
}

impl Read for AuthorityBlock {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let context = ConsensusContext::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UnixSeconds(u64::read(reader)?);
        if reader.remaining() < 32 {
            return Err(Error::EndOfBuffer);
        }
        let mut state_hash = [0; 32];
        reader.copy_to_slice(&mut state_hash);
        let len = u32::read(reader)? as usize;
        if len > MAX_COMMAND_BYTES || reader.remaining() < len {
            return Err(Error::Invalid("AuthorityBlock", "invalid body length"));
        }
        let body = reader.copy_to_bytes(len);
        let commands: Vec<Command> = from_canonical_bytes(&body).map_err(|_| Error::Invalid("AuthorityBlock", "invalid canonical commands"))?;
        let block = Self::new(context, height, timestamp, Hash32(state_hash), &commands)
            .map_err(|_| Error::Invalid("AuthorityBlock", "invalid command batch"))?;
        if block.body.as_slice() != body.as_ref() {
            return Err(Error::Invalid("AuthorityBlock", "command representation changed"));
        }
        Ok(block)
    }
}

impl EncodeSize for AuthorityBlock {
    fn encode_size(&self) -> usize {
        self.context.encode_size() + self.height.encode_size() + 8 + 32 + 4 + self.body.len()
    }
}

impl Digestible for AuthorityBlock {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[b"OIC/AUTHORITY_BLOCK/v1", self.encode().as_ref()])
    }
}

impl Heightable for AuthorityBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for AuthorityBlock {
    fn parent(&self) -> Digest {
        self.context.parent.1
    }
}

impl CertifiableBlock for AuthorityBlock {
    type Context = ConsensusContext;

    fn context(&self) -> ConsensusContext {
        self.context.clone()
    }
}
