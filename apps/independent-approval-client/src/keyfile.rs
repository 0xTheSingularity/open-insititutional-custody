//! Approver credentials encrypted at rest.
//!
//! An approval credential is an Ed25519 key distinct from administrative
//! credentials and signing shares (RFC 0001 §4.3). The key file is JSON:
//!
//! ```text
//! {
//!   "format": "oic-approver-key/v1",
//!   "credential_id": "approver-1",
//!   "role": "treasury_approver",
//!   "public_key_hex": "<32-byte ed25519 public key hex>",
//!   "kdf":    { "algorithm": "pbkdf2-hmac-sha256", "iterations": 600000, "salt_hex": "<16 bytes>" },
//!   "cipher": { "algorithm": "chacha20poly1305", "nonce_hex": "<12 bytes>", "ciphertext_hex": "<32-byte seed + 16-byte tag>" }
//! }
//! ```
//!
//! The 32-byte encryption key is `PBKDF2-HMAC-SHA256(passphrase, salt,
//! iterations)`. The ciphertext seals the 32-byte Ed25519 seed; the AEAD
//! associated data is [`ApproverKeyFile::associated_data`] (format, credential
//! id, role, public key, and KDF parameters), so editing any header field
//! makes the file refuse to open. After decryption the derived public key
//! must equal `public_key_hex`. The file is created with mode `0600`.

use crate::{ClientError, ClientResult};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use oic_domain_types::*;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const KEYFILE_FORMAT: &str = "oic-approver-key/v1";
pub const KDF_ALGORITHM: &str = "pbkdf2-hmac-sha256";
pub const CIPHER_ALGORITHM: &str = "chacha20poly1305";
/// Minimum (and default) PBKDF2 iteration count; files below it are refused.
pub const MIN_PBKDF2_ITERATIONS: u32 = 600_000;
/// Upper bound accepted when opening, so a hostile file cannot hang the client.
pub const MAX_PBKDF2_ITERATIONS: u32 = 100_000_000;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
/// Minimum passphrase length in bytes.
pub const MIN_PASSPHRASE_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub salt_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherParams {
    pub algorithm: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

/// On-disk approver credential; see the module docs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverKeyFile {
    pub format: String,
    pub credential_id: CredentialId,
    pub role: ApprovalRole,
    pub public_key_hex: String,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
}

/// A decrypted approver credential. The signing key zeroizes on drop.
pub struct UnlockedApproverKey {
    pub credential_id: CredentialId,
    pub role: ApprovalRole,
    pub signing_key: SigningKey,
}

impl UnlockedApproverKey {
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// PBKDF2 (RFC 8018 §5.2) with HMAC-SHA256 as the PRF, filling `out`.
/// The HMAC is keyed once; each iteration clones the keyed state.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    assert!(iterations > 0, "PBKDF2 requires at least one iteration");
    let prf = <Hmac<Sha256> as Mac>::new_from_slice(password).expect("HMAC accepts keys of any length");
    for (i, block) in out.chunks_mut(32).enumerate() {
        let index = u32::try_from(i + 1).expect("PBKDF2 block index fits in u32");
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&index.to_be_bytes());
        let mut u: [u8; 32] = mac.finalize().into_bytes().into();
        let mut t = u;
        for _ in 1..iterations {
            let mut mac = prf.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes().into();
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        block.copy_from_slice(&t[..block.len()]);
        u.zeroize();
        t.zeroize();
    }
}

fn refuse_open() -> OicError {
    OicError::invalid_signature("approver key file cannot be opened: wrong passphrase or modified file")
}

fn hex_field<const N: usize>(name: &str, s: &str) -> OicResult<[u8; N]> {
    let v = hex::decode(s).map_err(|_| OicError::invalid_request(format!("key file {name} is not hex")))?;
    v.as_slice().try_into().map_err(|_| OicError::invalid_request(format!("key file {name} must be {N} bytes")))
}

fn derive_key(passphrase: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac_sha256(passphrase, salt, iterations, k.as_mut());
    k
}

impl ApproverKeyFile {
    /// Encrypt `signing_key` under `passphrase` with a fresh random salt and nonce.
    pub fn seal(credential_id: CredentialId, role: ApprovalRole, signing_key: &SigningKey, passphrase: &[u8], iterations: u32) -> OicResult<ApproverKeyFile> {
        if passphrase.len() < MIN_PASSPHRASE_LEN {
            return Err(OicError::invalid_request(format!("passphrase must be at least {MIN_PASSPHRASE_LEN} bytes")));
        }
        if !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
            return Err(OicError::invalid_request(format!("PBKDF2 iterations must be between {MIN_PBKDF2_ITERATIONS} and {MAX_PBKDF2_ITERATIONS}")));
        }
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let mut file = ApproverKeyFile {
            format: KEYFILE_FORMAT.to_string(),
            credential_id,
            role,
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            kdf: KdfParams { algorithm: KDF_ALGORITHM.to_string(), iterations, salt_hex: hex::encode(salt) },
            cipher: CipherParams { algorithm: CIPHER_ALGORITHM.to_string(), nonce_hex: hex::encode(nonce), ciphertext_hex: String::new() },
        };
        let key = derive_key(passphrase, &salt, iterations);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let seed = Zeroizing::new(signing_key.to_bytes());
        let aad = file.associated_data()?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: seed.as_ref(), aad: &aad })
            .map_err(|_| OicError::internal("key file encryption failed"))?;
        file.cipher.ciphertext_hex = hex::encode(ct);
        Ok(file)
    }

    /// Bytes authenticated (not encrypted) alongside the seed.
    pub fn associated_data(&self) -> OicResult<Vec<u8>> {
        serde_json::to_vec(&(&self.format, &self.credential_id, &self.role, &self.public_key_hex, &self.kdf))
            .map_err(|e| OicError::internal(format!("key file header encoding: {e}")))
    }

    /// The public key recorded in the header.
    pub fn verifying_key(&self) -> OicResult<VerifyingKey> {
        crate::trust::parse_verifying_key(&self.public_key_hex)
    }

    /// Decrypt the credential. Fails with `InvalidSignature` for a wrong
    /// passphrase or any modification, and `InvalidRequest` for an
    /// unsupported format or KDF parameters.
    pub fn open(&self, passphrase: &[u8]) -> OicResult<UnlockedApproverKey> {
        if self.format != KEYFILE_FORMAT || self.kdf.algorithm != KDF_ALGORITHM || self.cipher.algorithm != CIPHER_ALGORITHM {
            return Err(OicError::invalid_request("unsupported approver key file format"));
        }
        if !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&self.kdf.iterations) {
            return Err(OicError::invalid_request(format!("key file PBKDF2 iterations {} outside the accepted range", self.kdf.iterations)));
        }
        let salt: [u8; SALT_LEN] = hex_field("salt", &self.kdf.salt_hex)?;
        let nonce: [u8; NONCE_LEN] = hex_field("nonce", &self.cipher.nonce_hex)?;
        let ct = hex::decode(&self.cipher.ciphertext_hex).map_err(|_| OicError::invalid_request("key file ciphertext is not hex"))?;
        let expected_pk = self.verifying_key()?;
        let key = derive_key(passphrase, &salt, self.kdf.iterations);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let aad = self.associated_data()?;
        let plain = Zeroizing::new(cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: &aad }).map_err(|_| refuse_open())?);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(plain.as_slice().try_into().map_err(|_| refuse_open())?);
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key() != expected_pk {
            return Err(refuse_open());
        }
        Ok(UnlockedApproverKey { credential_id: self.credential_id.clone(), role: self.role, signing_key })
    }

    pub fn load(path: &Path) -> ClientResult<ApproverKeyFile> {
        crate::read_json(path)
    }

    /// Write a new key file with mode `0600` (never overwrites).
    pub fn save(&self, path: &Path) -> ClientResult<()> {
        crate::write_new_json(path, self, 0o600)
    }
}

/// Read a passphrase from the environment variable `var` (never from argv,
/// where it would be visible to other users).
pub fn passphrase_from_env(var: &str) -> ClientResult<Zeroizing<Vec<u8>>> {
    match std::env::var_os(var) {
        Some(v) => Ok(Zeroizing::new(v.into_encoded_bytes())),
        None => Err(ClientError::Usage(format!("passphrase environment variable `{}` is not set", oic_approval_verifier::sanitize_display_text(var)))),
    }
}

/// Parse an approval role (`treasury_approver`, `security_approver`,
/// `administrator`, `automated`).
pub fn parse_role(s: &str) -> ClientResult<ApprovalRole> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|_| ClientError::Usage(format!("unknown role `{}`", oic_approval_verifier::sanitize_display_text(s))))
}

/// Snake-case name of a role, as accepted by [`parse_role`].
pub fn role_name(role: ApprovalRole) -> String {
    match serde_json::to_value(role) {
        Ok(serde_json::Value::String(s)) => s,
        _ => format!("{role:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pbkdf2_hex(p: &[u8], s: &[u8], c: u32, len: usize) -> String {
        let mut out = vec![0u8; len];
        pbkdf2_hmac_sha256(p, s, c, &mut out);
        hex::encode(out)
    }

    /// RFC 7914 §11 PBKDF2-HMAC-SHA256 vectors (multi-block output) and a
    /// truncated single-block vector.
    #[test]
    fn pbkdf2_hmac_sha256_known_answers() {
        assert_eq!(
            pbkdf2_hex(b"passwd", b"salt", 1, 64),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
        assert_eq!(
            pbkdf2_hex(b"Password", b"NaCl", 80_000, 64),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
        );
        assert_eq!(pbkdf2_hex(b"password", b"salt", 4096, 20), "c5e478d59288c841aa530db6845c4c8d962893a0");
    }

    #[test]
    fn seal_open_round_trip_and_tamper_detection() {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let f = ApproverKeyFile::seal(CredentialId::unchecked("a"), ApprovalRole::TreasuryApprover, &sk, b"long enough passphrase", MIN_PBKDF2_ITERATIONS).unwrap();
        assert_eq!(f.open(b"long enough passphrase").unwrap().signing_key.to_bytes(), sk.to_bytes());
        let mut ct = f.clone();
        let mut bytes = hex::decode(&ct.cipher.ciphertext_hex).unwrap();
        bytes[0] ^= 1;
        ct.cipher.ciphertext_hex = hex::encode(bytes);
        assert_eq!(ct.open(b"long enough passphrase").err().unwrap().code, ErrorCode::InvalidSignature);
        let mut pk = f.clone();
        pk.public_key_hex = hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
        assert_eq!(pk.open(b"long enough passphrase").err().unwrap().code, ErrorCode::InvalidSignature);
        assert_eq!(
            ApproverKeyFile::seal(CredentialId::unchecked("a"), ApprovalRole::TreasuryApprover, &sk, b"long enough passphrase", 1000).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }
}
