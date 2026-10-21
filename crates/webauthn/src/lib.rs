//! Pure WebAuthn ES256 approval assertions (RFC 0003 §§15.5–15.6).
//!
//! Trust is entirely caller supplied: an already enrolled **approval-only** P-256
//! key, its RP ID and exact serialized approver origins, and the independently
//! computed 32-byte grant hash. Nothing in an assertion enrolls a key or selects
//! an RP, origin, algorithm, or challenge. SEC1 compressed and uncompressed keys
//! are accepted; COSE key/enrollment/attestation parsing is outside this crate.
//!
//! This deliberately narrow profile requires UP and UV, forbids cross-origin
//! use and any `topOrigin`, rejects unknown/duplicate JSON members, and supports
//! exactly 37-byte authenticator data: no attested data, extensions, or reserved
//! flag bits. JSON itself need not be canonical. One leading UTF-8 BOM is stripped
//! for parsing, but the signature hashes the **original** client data bytes.
//!
//! A login also uses `webauthn.get`. If the caller enrolls the same key/RP/origins
//! for login and approval, a login with a grant-hash challenge is indistinguishable
//! from approval. Purpose separation and admin-approved enrollment are mandatory
//! caller responsibilities. This verifier does not perform grant expiry, policy,
//! proposer separation, distinct-person/quorum checks, ordering, replay tracking,
//! browser ceremony handling, or approval recording.
//!
//! Returned backup flags and counters are authenticated observations, not policy.
//! Callers must compare BE with enrollment and apply device-bound/attestation
//! policy themselves. BS may change; BS without BE is invalid. Zero counters are
//! valid. Non-increasing counters can be alerts, but **are not clone defense**.
//!
//! References: W3C WebAuthn Level 3 [§7.2][assertion], [§6.1][auth-data], and
//! [§6.5.5][der]. The canonical CBOR carrier is the repository security profile,
//! not JSON/base64 text or an unconstrained browser response object.
//!
//! [assertion]: https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
//! [auth-data]: https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
//! [der]: https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use oic_canonical_encoding::{canonical_bytes, from_canonical_bytes};
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use serde::{de::IgnoredAny, Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

pub const AUTHENTICATOR_DATA_LEN: usize = 37;
pub const MAX_CLIENT_DATA_JSON_LEN: usize = 4096;
pub const MAX_SIGNATURE_LEN: usize = 72;
/// Checked before canonical CBOR decoding allocates any assertion fields.
pub const MAX_ASSERTION_LEN: usize = 8192;
pub const MAX_RP_ID_LEN: usize = 253;
pub const MAX_ORIGIN_LEN: usize = 2048;
pub const MAX_ALLOWED_ORIGINS: usize = 16;

/// Already trusted enrollment configuration, never copied from assertion fields.
/// Origins are exact serialized strings: no wildcards, suffix matching, URL
/// normalization, or discovery. Enrollment must validate the RP/origin relation
/// and the security of each distribution channel.
#[derive(Clone, Copy, Debug)]
pub struct EnrolledCredential<'a> {
    pub public_key_sec1: &'a [u8],
    pub rp_id: &'a str,
    pub allowed_origins: &'a [&'a str],
}

/// Original assertion bytes. `signature` is an ASN.1 DER Ecdsa-Sig-Value, not
/// IEEE-P1363 `r || s`. Both high- and low-S valid ES256 signatures are accepted.
#[derive(Clone, Copy)]
pub struct Assertion<'a> {
    pub authenticator_data: &'a [u8],
    pub client_data_json: &'a [u8],
    pub signature: &'a [u8],
}

impl std::fmt::Debug for Assertion<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Assertion([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedAssertion {
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Stable rejection categories without attacker-controlled error strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfiguration,
    InvalidPublicKey,
    TooLarge,
    InvalidCbor,
    InvalidClientData,
    InvalidAuthenticatorData,
    WrongType,
    WrongChallenge,
    WrongOrigin,
    CrossOrigin,
    WrongRpId,
    UserPresenceRequired,
    UserVerificationRequired,
    InvalidBackupFlags,
    InvalidSignature,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WebAuthn assertion: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Validate bounded enrollment configuration and a P-256 SEC1 curve point,
/// without requiring an assertion. This is not enrollment authorization or proof
/// of key possession. Both SEC1 encodings are accepted; consumers requiring one
/// representation must additionally require 33-byte compressed SEC1 at enrollment.
/// RP/origin relationship, channel security, purpose, and BE policy remain external.
pub fn validate_credential(enrolled: &EnrolledCredential<'_>) -> Result<(), Error> {
    credential_key(enrolled).map(|_| ())
}

/// Verify one raw assertion against independent enrollment and grant state.
/// This function has no clock, storage, network, entropy, or mutable state.
pub fn verify_assertion(
    enrolled: &EnrolledCredential<'_>,
    expected_grant_hash: &[u8; 32],
    assertion: Assertion<'_>,
) -> Result<VerifiedAssertion, Error> {
    check_limits(assertion)?;
    let public_key = credential_key(enrolled)?;

    let json = assertion
        .client_data_json
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(assertion.client_data_json);
    // Serde's struct visitor also accepts positional arrays. WebAuthn requires
    // a JSON object; serde_json still validates all syntax and duplicate fields.
    if json.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(Error::InvalidClientData);
    }
    let client: ClientData = serde_json::from_slice(json).map_err(|_| Error::InvalidClientData)?;
    if client.ceremony_type != "webauthn.get" {
        return Err(Error::WrongType);
    }
    // A fixed grant hash has exactly 43 canonical unpadded base64url characters.
    // The library also rejects nonzero unused bits and padding/alternate alphabets.
    if client.challenge.len() != 43
        || URL_SAFE_NO_PAD
            .decode(client.challenge.as_bytes())
            .ok()
            .as_deref()
            != Some(expected_grant_hash.as_slice())
    {
        return Err(Error::WrongChallenge);
    }
    if !enrolled.allowed_origins.contains(&client.origin.as_str()) {
        return Err(Error::WrongOrigin);
    }
    if client.cross_origin || client.top_origin_present {
        return Err(Error::CrossOrigin);
    }

    let auth = assertion.authenticator_data;
    if auth[..32] != Sha256::digest(enrolled.rp_id.as_bytes())[..] {
        return Err(Error::WrongRpId);
    }
    let flags = auth[32];
    // AT, ED, and both RFU bits are outside this bounded v1 profile.
    if flags & (0x40 | 0x80 | 0x02 | 0x20) != 0 {
        return Err(Error::InvalidAuthenticatorData);
    }
    if flags & 0x01 == 0 {
        return Err(Error::UserPresenceRequired);
    }
    if flags & 0x04 == 0 {
        return Err(Error::UserVerificationRequired);
    }
    let backup_eligible = flags & 0x08 != 0;
    let backup_state = flags & 0x10 != 0;
    if backup_state && !backup_eligible {
        return Err(Error::InvalidBackupFlags);
    }

    let signature =
        Signature::from_der(assertion.signature).map_err(|_| Error::InvalidSignature)?;
    let mut signed = [0_u8; AUTHENTICATOR_DATA_LEN + 32];
    signed[..AUTHENTICATOR_DATA_LEN].copy_from_slice(auth);
    signed[AUTHENTICATOR_DATA_LEN..].copy_from_slice(&Sha256::digest(assertion.client_data_json));
    // ES256 hashes this 69-byte message once more with SHA-256. The original
    // clientDataJSON is hashed above, never reserialized/normalized JSON.
    public_key
        .verify(&signed, &signature)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(VerifiedAssertion {
        sign_count: u32::from_be_bytes([auth[33], auth[34], auth[35], auth[36]]),
        backup_eligible,
        backup_state,
    })
}

/// Verify `SignatureBytes.bytes` for `WebAuthnEs256`: exactly the canonical CBOR
/// map `{authenticator_data: bstr, client_data_json: bstr, signature: bstr}`.
/// Duplicate/unknown keys, nonminimal/indefinite encodings, arrays instead of
/// byte strings, and trailing bytes are rejected by the shared canonical codec.
pub fn verify_canonical_assertion(
    enrolled: &EnrolledCredential<'_>,
    expected_grant_hash: &[u8; 32],
    encoded: &[u8],
) -> Result<VerifiedAssertion, Error> {
    if encoded.len() > MAX_ASSERTION_LEN {
        return Err(Error::TooLarge);
    }
    let raw: OwnedAssertion = from_canonical_bytes(encoded).map_err(|_| Error::InvalidCbor)?;
    verify_assertion(
        enrolled,
        expected_grant_hash,
        Assertion {
            authenticator_data: &raw.authenticator_data,
            client_data_json: &raw.client_data_json,
            signature: &raw.signature,
        },
    )
}

/// Encode the bounded raw fields into the canonical carrier. Encoding is not
/// verification: callers must still verify before recording an approval.
pub fn encode_assertion(assertion: Assertion<'_>) -> Result<Vec<u8>, Error> {
    check_limits(assertion)?;
    canonical_bytes(&BorrowedAssertion {
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
    })
    .map_err(|_| Error::InvalidCbor)
}

fn check_limits(assertion: Assertion<'_>) -> Result<(), Error> {
    if assertion.authenticator_data.len() > AUTHENTICATOR_DATA_LEN
        || assertion.client_data_json.len() > MAX_CLIENT_DATA_JSON_LEN
        || assertion.signature.len() > MAX_SIGNATURE_LEN
    {
        return Err(Error::TooLarge);
    }
    if assertion.authenticator_data.len() != AUTHENTICATOR_DATA_LEN {
        return Err(Error::InvalidAuthenticatorData);
    }
    Ok(())
}

fn credential_key(enrolled: &EnrolledCredential<'_>) -> Result<VerifyingKey, Error> {
    let valid_text = |s: &str, max: usize| {
        !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())
    };
    if !valid_text(enrolled.rp_id, MAX_RP_ID_LEN)
        || enrolled.allowed_origins.is_empty()
        || enrolled.allowed_origins.len() > MAX_ALLOWED_ORIGINS
        || enrolled
            .allowed_origins
            .iter()
            .any(|o| !valid_text(o, MAX_ORIGIN_LEN) || *o == "null")
    {
        return Err(Error::InvalidConfiguration);
    }
    if !matches!(enrolled.public_key_sec1.len(), 33 | 65) {
        return Err(Error::InvalidPublicKey);
    }
    VerifyingKey::from_sec1_bytes(enrolled.public_key_sec1).map_err(|_| Error::InvalidPublicKey)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientData {
    #[serde(rename = "type")]
    ceremony_type: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
    #[serde(default, rename = "topOrigin", deserialize_with = "present")]
    top_origin_present: bool,
}

fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedAssertion {
    #[serde(with = "serde_bytes")]
    authenticator_data: Vec<u8>,
    #[serde(with = "serde_bytes")]
    client_data_json: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct BorrowedAssertion<'a> {
    #[serde(with = "serde_bytes")]
    authenticator_data: &'a [u8],
    #[serde(with = "serde_bytes")]
    client_data_json: &'a [u8],
    #[serde(with = "serde_bytes")]
    signature: &'a [u8],
}
