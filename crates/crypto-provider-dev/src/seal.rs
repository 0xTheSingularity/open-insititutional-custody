//! Share sealing at rest (identical copy in `oic-crypto-provider-dev` and
//! `oic-crypto-provider-frost-ed25519`; keep them in sync).
//!
//! Format: `"OICSEAL1" ‖ nonce (12 bytes, random) ‖ ChaCha20-Poly1305(ciphertext ‖ tag)`.
//! AAD: canonical CBOR of
//! `{format: "oic-sealed-share/v1", backend_id, key_id, key_epoch, participant}`,
//! so a sealed share cannot be replayed under another key, epoch,
//! participant, or backend. The sealing key is held by the provider and
//! zeroized on drop; decrypted plaintext is returned in a [`Zeroizing`] buffer.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use oic_canonical_encoding::canonical_bytes;
use oic_domain_types::*;
use rand_core::CryptoRngCore;
use serde::Serialize;
use zeroize::Zeroizing;

pub(crate) const SEAL_MAGIC: &[u8; 8] = b"OICSEAL1";
pub(crate) const SEAL_FORMAT: &str = "oic-sealed-share/v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Provider-held 32-byte sealing key, wiped on drop.
pub(crate) struct SealingKey(Zeroizing<[u8; 32]>);

impl SealingKey {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        SealingKey(Zeroizing::new(bytes))
    }
}

/// Context bound into the AAD.
pub(crate) struct SealContext<'a> {
    pub backend_id: &'a str,
    pub key_id: &'a KeyId,
    pub key_epoch: Epoch,
    pub participant: &'a ParticipantId,
}

#[derive(Serialize)]
struct Aad<'a> {
    format: &'a str,
    backend_id: &'a str,
    key_id: &'a KeyId,
    key_epoch: Epoch,
    participant: &'a ParticipantId,
}

fn aad(ctx: &SealContext<'_>) -> OicResult<Vec<u8>> {
    canonical_bytes(&Aad {
        format: SEAL_FORMAT,
        backend_id: ctx.backend_id,
        key_id: ctx.key_id,
        key_epoch: ctx.key_epoch,
        participant: ctx.participant,
    })
}

pub(crate) fn seal(key: &SealingKey, rng: &mut dyn CryptoRngCore, ctx: &SealContext<'_>, plaintext: &[u8]) -> OicResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0[..]));
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = aad(ctx)?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| OicError::internal("share sealing failed"))?;
    let mut out = Vec::with_capacity(SEAL_MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(SEAL_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(crate) fn open(key: &SealingKey, ctx: &SealContext<'_>, sealed: &[u8]) -> OicResult<Zeroizing<Vec<u8>>> {
    if sealed.len() < SEAL_MAGIC.len() + NONCE_LEN + TAG_LEN || &sealed[..SEAL_MAGIC.len()] != SEAL_MAGIC {
        return Err(OicError::invalid_request("sealed share has an unknown format"));
    }
    let nonce = &sealed[SEAL_MAGIC.len()..SEAL_MAGIC.len() + NONCE_LEN];
    let ct = &sealed[SEAL_MAGIC.len() + NONCE_LEN..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0[..]));
    let aad = aad(ctx)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map(Zeroizing::new)
        .map_err(|_| OicError::invalid_signature("sealed share failed authentication (wrong sealing key, key, epoch, participant, or tampered)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn ctx<'a>(k: &'a KeyId, p: &'a ParticipantId, epoch: u64) -> SealContext<'a> {
        SealContext { backend_id: "b", key_id: k, key_epoch: Epoch(epoch), participant: p }
    }

    #[test]
    fn roundtrip_and_binding() {
        let key = SealingKey::new([7u8; 32]);
        let (k, p) = (KeyId::unchecked("k"), ParticipantId::unchecked("p"));
        let secret = [0xAAu8; 32];
        let sealed = seal(&key, &mut OsRng, &ctx(&k, &p, 1), &secret).unwrap();
        assert!(sealed.starts_with(SEAL_MAGIC));
        assert!(!sealed.windows(32).any(|w| w == secret));
        assert_eq!(&open(&key, &ctx(&k, &p, 1), &sealed).unwrap()[..], &secret[..]);

        // Wrong epoch, key, participant, sealing key: all rejected.
        assert!(open(&key, &ctx(&k, &p, 2), &sealed).is_err());
        let k2 = KeyId::unchecked("k2");
        assert!(open(&key, &ctx(&k2, &p, 1), &sealed).is_err());
        let p2 = ParticipantId::unchecked("p2");
        assert!(open(&key, &ctx(&k, &p2, 1), &sealed).is_err());
        assert!(open(&SealingKey::new([8u8; 32]), &ctx(&k, &p, 1), &sealed).is_err());

        // Tamper and truncation.
        let mut t = sealed.clone();
        *t.last_mut().unwrap() ^= 1;
        assert!(open(&key, &ctx(&k, &p, 1), &t).is_err());
        assert!(open(&key, &ctx(&k, &p, 1), &sealed[..20]).is_err());
        let mut m = sealed.clone();
        m[0] = b'X';
        assert!(open(&key, &ctx(&k, &p, 1), &m).is_err());
    }

    #[test]
    fn nonces_are_fresh() {
        let key = SealingKey::new([1u8; 32]);
        let (k, p) = (KeyId::unchecked("k"), ParticipantId::unchecked("p"));
        let a = seal(&key, &mut OsRng, &ctx(&k, &p, 1), b"x").unwrap();
        let b = seal(&key, &mut OsRng, &ctx(&k, &p, 1), b"x").unwrap();
        assert_ne!(a, b);
    }
}
