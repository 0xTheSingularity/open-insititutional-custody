//! Strict, hand-written Solana message and transaction wire formats.
//!
//! ```text
//! legacy message = header(3) || shortvec(n) || n*32 static keys || blockhash(32)
//!                  || shortvec(m) || m*instruction
//! v0 message     = 0x80 || <legacy layout> || shortvec(k) || k*lookup
//! instruction    = program_id_index(1) || shortvec(a) || a*index(1) || shortvec(d) || d bytes
//! lookup         = table(32) || shortvec(w) || w*index || shortvec(r) || r*index
//! transaction    = shortvec(s) || s*signature(64) || message
//! ```
//!
//! Decoding is strict: minimal shortvecs, no trailing bytes, bounded sizes
//! (the serialized transaction must fit in one 1232-byte packet), a sane header,
//! at most 64 accounts, and every index in range. Re-encoding a decoded value is
//! byte-exact. A version prefix other than v0 fails with `UnsupportedCapability`.

use crate::address::Pubkey;
use crate::shortvec;
use oic_domain_types::{OicError, OicResult};

/// Maximum serialized transaction size (IPv6 MTU minus headers).
pub const PACKET_DATA_SIZE: usize = 1232;
/// Maximum number of accounts (static + lookup-resolved) this adapter accepts.
pub const MAX_ACCOUNTS: usize = 64;
/// High bit of the first message byte marks a versioned message.
pub const MESSAGE_VERSION_PREFIX: u8 = 0x80;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageVersion {
    Legacy,
    V0,
}

impl MessageVersion {
    /// `ChainProfile.accepted_versions` string.
    pub fn profile_name(self) -> &'static str {
        match self {
            MessageVersion::Legacy => crate::VERSION_LEGACY,
            MessageVersion::V0 => crate::VERSION_V0,
        }
    }

    /// `NativeSigningPayload.native_signing_context`.
    pub fn signing_context(self) -> &'static str {
        match self {
            MessageVersion::Legacy => crate::SIGNING_CONTEXT_LEGACY,
            MessageVersion::V0 => crate::SIGNING_CONTEXT_V0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct AddressTableLookup {
    pub account_key: Pubkey,
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

/// A decoded legacy or v0 message. `address_table_lookups` is always empty for legacy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Message {
    pub version: MessageVersion,
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
    pub address_table_lookups: Vec<AddressTableLookup>,
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    fn take(&mut self, n: usize, what: &str) -> OicResult<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.b.len());
        let Some(end) = end else {
            return Err(OicError::unverifiable(format!("truncated message: {what}")));
        };
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self, what: &str) -> OicResult<u8> {
        Ok(self.take(1, what)?[0])
    }
    fn array32(&mut self, what: &str) -> OicResult<[u8; 32]> {
        let s = self.take(32, what)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn len(&mut self) -> OicResult<usize> {
        let (v, n) = shortvec::decode(&self.b[self.pos..])?;
        self.pos += n;
        // Every element takes at least one byte; reject impossible lengths early.
        if (v as usize) > self.b.len() - self.pos {
            return Err(OicError::unverifiable("length prefix exceeds remaining bytes"));
        }
        Ok(v as usize)
    }
    fn bytes_vec(&mut self, what: &str) -> OicResult<Vec<u8>> {
        let n = self.len()?;
        Ok(self.take(n, what)?.to_vec())
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
}

fn push_len(out: &mut Vec<u8>, n: usize) {
    // All lengths are bounded by PACKET_DATA_SIZE in valid messages; encoding a
    // longer vector is a programming error that we surface by saturating, which
    // the strict decoder then rejects.
    shortvec::encode_into(out, u16::try_from(n).unwrap_or(u16::MAX));
}

impl Message {
    /// Static keys followed by lookup-resolved writable then readonly counts.
    pub fn num_lookup_accounts(&self) -> usize {
        self.address_table_lookups.iter().map(|l| l.writable_indexes.len() + l.readonly_indexes.len()).sum()
    }

    pub fn num_total_accounts(&self) -> usize {
        self.account_keys.len() + self.num_lookup_accounts()
    }

    pub fn num_lookup_writable(&self) -> usize {
        self.address_table_lookups.iter().map(|l| l.writable_indexes.len()).sum()
    }

    /// True iff the account at `index` in the full (resolved) account list is a required signer.
    /// Only static keys can be signers.
    pub fn is_signer(&self, index: usize) -> bool {
        index < self.header.num_required_signatures as usize
    }

    /// Declared writability of the account at `index` in the full account list.
    pub fn is_writable(&self, index: usize) -> bool {
        let h = &self.header;
        let nsig = h.num_required_signatures as usize;
        let nstatic = self.account_keys.len();
        if index < nsig {
            index < nsig - h.num_readonly_signed_accounts as usize
        } else if index < nstatic {
            index < nstatic - h.num_readonly_unsigned_accounts as usize
        } else {
            index - nstatic < self.num_lookup_writable()
        }
    }

    /// Serialize the message exactly as signed.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        if self.version == MessageVersion::V0 {
            out.push(MESSAGE_VERSION_PREFIX);
        }
        out.push(self.header.num_required_signatures);
        out.push(self.header.num_readonly_signed_accounts);
        out.push(self.header.num_readonly_unsigned_accounts);
        push_len(&mut out, self.account_keys.len());
        for k in &self.account_keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&self.recent_blockhash);
        push_len(&mut out, self.instructions.len());
        for ix in &self.instructions {
            out.push(ix.program_id_index);
            push_len(&mut out, ix.accounts.len());
            out.extend_from_slice(&ix.accounts);
            push_len(&mut out, ix.data.len());
            out.extend_from_slice(&ix.data);
        }
        if self.version == MessageVersion::V0 {
            push_len(&mut out, self.address_table_lookups.len());
            for l in &self.address_table_lookups {
                out.extend_from_slice(&l.account_key);
                push_len(&mut out, l.writable_indexes.len());
                out.extend_from_slice(&l.writable_indexes);
                push_len(&mut out, l.readonly_indexes.len());
                out.extend_from_slice(&l.readonly_indexes);
            }
        }
        out
    }

    /// Strictly decode a serialized message (no trailing bytes).
    pub fn decode(bytes: &[u8]) -> OicResult<Message> {
        let mut r = Reader::new(bytes);
        let msg = Self::decode_from(&mut r)?;
        if r.remaining() != 0 {
            return Err(OicError::unverifiable("trailing bytes after message"));
        }
        msg.validate(bytes.len())?;
        // Defence in depth: the strict decoder must be the inverse of the encoder.
        if msg.encode() != bytes {
            return Err(OicError::unverifiable("message does not re-encode byte-exactly"));
        }
        Ok(msg)
    }

    fn decode_from(r: &mut Reader<'_>) -> OicResult<Message> {
        if r.remaining() > PACKET_DATA_SIZE {
            return Err(OicError::unverifiable(format!("message exceeds the {PACKET_DATA_SIZE}-byte packet limit")));
        }
        let first = r.u8("header")?;
        let (version, nsig) = if first & MESSAGE_VERSION_PREFIX != 0 {
            let v = first & !MESSAGE_VERSION_PREFIX;
            if v != 0 {
                return Err(OicError::unsupported(format!("Solana message version {v} is not supported (only legacy and v0)")));
            }
            (MessageVersion::V0, r.u8("header")?)
        } else {
            (MessageVersion::Legacy, first)
        };
        let header = MessageHeader {
            num_required_signatures: nsig,
            num_readonly_signed_accounts: r.u8("header")?,
            num_readonly_unsigned_accounts: r.u8("header")?,
        };
        let nkeys = r.len()?;
        if nkeys > MAX_ACCOUNTS {
            return Err(OicError::unverifiable(format!("message has {nkeys} static accounts; limit is {MAX_ACCOUNTS}")));
        }
        let mut account_keys = Vec::with_capacity(nkeys);
        for _ in 0..nkeys {
            account_keys.push(r.array32("account key")?);
        }
        let recent_blockhash = r.array32("recent blockhash")?;
        let nix = r.len()?;
        let mut instructions = Vec::with_capacity(nix.min(64));
        for _ in 0..nix {
            let program_id_index = r.u8("instruction program index")?;
            let accounts = r.bytes_vec("instruction accounts")?;
            let data = r.bytes_vec("instruction data")?;
            instructions.push(CompiledInstruction { program_id_index, accounts, data });
        }
        let mut address_table_lookups = Vec::new();
        if version == MessageVersion::V0 {
            let nl = r.len()?;
            for _ in 0..nl {
                let account_key = r.array32("lookup table address")?;
                let writable_indexes = r.bytes_vec("lookup writable indexes")?;
                let readonly_indexes = r.bytes_vec("lookup readonly indexes")?;
                address_table_lookups.push(AddressTableLookup { account_key, writable_indexes, readonly_indexes });
            }
        }
        Ok(Message { version, header, account_keys, recent_blockhash, instructions, address_table_lookups })
    }

    /// Structural checks equivalent to (and in places stricter than) runtime sanitization.
    pub fn validate(&self, encoded_len: usize) -> OicResult<()> {
        let h = &self.header;
        let nsig = h.num_required_signatures as usize;
        let nstatic = self.account_keys.len();
        if nsig == 0 {
            return Err(OicError::unverifiable("message requires no signatures (no fee payer)"));
        }
        if h.num_readonly_signed_accounts >= h.num_required_signatures {
            return Err(OicError::unverifiable("header marks the fee payer readonly (readonly signed >= required signatures)"));
        }
        if nsig + h.num_readonly_unsigned_accounts as usize > nstatic {
            return Err(OicError::unverifiable("header signer/readonly counts exceed the static account list"));
        }
        // Serialized transaction = shortvec(nsig) || nsig*64 || message must fit one packet.
        let tx_len = shortvec::encoded_len(nsig as u16) + nsig * SIGNATURE_LEN + encoded_len;
        if tx_len > PACKET_DATA_SIZE {
            return Err(OicError::unverifiable(format!(
                "serialized transaction would be {tx_len} bytes; packet limit is {PACKET_DATA_SIZE}"
            )));
        }
        for l in &self.address_table_lookups {
            if l.writable_indexes.is_empty() && l.readonly_indexes.is_empty() {
                return Err(OicError::unverifiable("address table lookup loads no accounts"));
            }
        }
        let total = self.num_total_accounts();
        if total > MAX_ACCOUNTS {
            return Err(OicError::unverifiable(format!("message references {total} accounts; limit is {MAX_ACCOUNTS}")));
        }
        for ix in &self.instructions {
            let p = ix.program_id_index as usize;
            if p == 0 {
                return Err(OicError::unverifiable("the fee payer cannot be invoked as a program"));
            }
            if p >= nstatic {
                return Err(OicError::unverifiable("program id index is not a static account (programs cannot come from lookup tables)"));
            }
            if ix.accounts.iter().any(|a| *a as usize >= total) {
                return Err(OicError::unverifiable("instruction account index out of range"));
            }
        }
        let mut seen = self.account_keys.clone();
        seen.sort_unstable();
        if seen.windows(2).any(|w| w[0] == w[1]) {
            return Err(OicError::unverifiable("duplicate static account key"));
        }
        Ok(())
    }
}

/// A signed (or partially signed) transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub signatures: Vec<[u8; SIGNATURE_LEN]>,
    pub message: Message,
    /// Exact serialized message bytes (the signed payload).
    pub message_bytes: Vec<u8>,
}

impl Transaction {
    pub fn encode(signatures: &[[u8; SIGNATURE_LEN]], message_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + signatures.len() * SIGNATURE_LEN + message_bytes.len());
        push_len(&mut out, signatures.len());
        for s in signatures {
            out.extend_from_slice(s);
        }
        out.extend_from_slice(message_bytes);
        out
    }

    /// Strictly decode a serialized transaction. The signature count must equal
    /// the message's `num_required_signatures`.
    pub fn decode(bytes: &[u8]) -> OicResult<Transaction> {
        if bytes.len() > PACKET_DATA_SIZE {
            return Err(OicError::unverifiable(format!("transaction exceeds the {PACKET_DATA_SIZE}-byte packet limit")));
        }
        let (n, used) = shortvec::decode(bytes)?;
        let n = n as usize;
        let sig_end = n.checked_mul(SIGNATURE_LEN).and_then(|x| x.checked_add(used)).filter(|e| *e <= bytes.len());
        let Some(sig_end) = sig_end else {
            return Err(OicError::unverifiable("truncated transaction signatures"));
        };
        let mut signatures = Vec::with_capacity(n);
        for i in 0..n {
            let start = used + i * SIGNATURE_LEN;
            let mut s = [0u8; SIGNATURE_LEN];
            s.copy_from_slice(&bytes[start..start + SIGNATURE_LEN]);
            signatures.push(s);
        }
        let message_bytes = bytes[sig_end..].to_vec();
        let message = Message::decode(&message_bytes)?;
        if signatures.len() != message.header.num_required_signatures as usize {
            return Err(OicError::unverifiable(format!(
                "transaction carries {} signatures but the message requires {}",
                signatures.len(),
                message.header.num_required_signatures
            )));
        }
        Ok(Transaction { signatures, message, message_bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(version: MessageVersion) -> Message {
        Message {
            version,
            header: MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 },
            account_keys: vec![[1; 32], [2; 32], [0; 32]],
            recent_blockhash: [9; 32],
            instructions: vec![CompiledInstruction { program_id_index: 2, accounts: vec![0, 1], data: vec![2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0] }],
            address_table_lookups: if version == MessageVersion::V0 {
                vec![AddressTableLookup { account_key: [5; 32], writable_indexes: vec![0], readonly_indexes: vec![1, 2] }]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn round_trip_both_versions() {
        for v in [MessageVersion::Legacy, MessageVersion::V0] {
            let m = sample(v);
            let b = m.encode();
            assert_eq!(Message::decode(&b).unwrap(), m);
            let tx = Transaction::encode(&[[3; 64]], &b);
            let d = Transaction::decode(&tx).unwrap();
            assert_eq!(d.message, m);
            assert_eq!(d.message_bytes, b);
        }
    }

    #[test]
    fn permissions() {
        let m = sample(MessageVersion::V0);
        assert!(m.is_signer(0) && !m.is_signer(1) && !m.is_signer(3));
        assert!(m.is_writable(0) && m.is_writable(1) && !m.is_writable(2));
        assert!(m.is_writable(3) && !m.is_writable(4) && !m.is_writable(5));
    }

    #[test]
    fn rejects_malformed() {
        let b = sample(MessageVersion::Legacy).encode();
        let mut t = b.clone();
        t.push(0);
        assert!(Message::decode(&t).is_err(), "trailing");
        assert!(Message::decode(&b[..b.len() - 1]).is_err(), "truncated");
        let mut v1 = sample(MessageVersion::V0).encode();
        v1[0] = 0x81;
        assert_eq!(Message::decode(&v1).unwrap_err().code, oic_domain_types::ErrorCode::UnsupportedCapability);
        let mut bad = sample(MessageVersion::Legacy);
        bad.header.num_readonly_signed_accounts = 1;
        assert!(Message::decode(&bad.encode()).is_err());
        let mut bad = sample(MessageVersion::Legacy);
        bad.header.num_required_signatures = 0;
        assert!(Message::decode(&bad.encode()).is_err());
        let mut bad = sample(MessageVersion::Legacy);
        bad.instructions[0].program_id_index = 0;
        assert!(Message::decode(&bad.encode()).is_err());
        let mut bad = sample(MessageVersion::Legacy);
        bad.instructions[0].accounts.push(3);
        assert!(Message::decode(&bad.encode()).is_err());
        let mut bad = sample(MessageVersion::Legacy);
        bad.account_keys[1] = bad.account_keys[0];
        assert!(Message::decode(&bad.encode()).is_err());
        let mut bad = sample(MessageVersion::V0);
        bad.address_table_lookups[0].writable_indexes.clear();
        bad.address_table_lookups[0].readonly_indexes.clear();
        assert!(Message::decode(&bad.encode()).is_err());
        // Signature count must match header.
        let tx = Transaction::encode(&[[3; 64], [4; 64]], &b);
        assert!(Transaction::decode(&tx).is_err());
    }
}
