//! Minimal blocking JSON-RPC 2.0 client with bounded timeouts.
//!
//! Every call is one POST with one request object. Transport failures,
//! HTTP errors, JSON-RPC error objects and malformed results all map to
//! `AuthorityUnavailable`-free, source-scoped `OicError`s so a flaky node
//! can never masquerade as chain evidence.

use oic_domain_types::{OicError, OicResult};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// One HTTP JSON-RPC endpoint.
pub struct Endpoint {
    url: String,
    /// Scheme and host only. Errors carry this, never the full URL: RPC URLs
    /// routinely embed provider API keys in their path or query.
    redacted: String,
    http: reqwest::blocking::Client,
    next_id: AtomicU64,
}

impl Endpoint {
    /// `timeout` bounds each call end to end; connect time is bounded separately.
    pub fn new(url: impl Into<String>, timeout: Duration) -> OicResult<Self> {
        let url = url.into();
        let redacted = redact(&url);
        let http = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| OicError::internal(format!("building the RPC HTTP client failed: {e}")))?;
        Ok(Endpoint { url, redacted, http, next_id: AtomicU64::new(1) })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// One JSON-RPC call; `params` must be a JSON array.
    pub fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> OicResult<T> {
        let value = self.call_value(method, params)?;
        serde_json::from_value(value).map_err(|e| rpc_error(&self.url, method, format!("unexpected result shape: {e}")))
    }

    /// Like [`Endpoint::call`], returning the raw JSON result (may be `null`).
    pub fn call_value(&self, method: &str, params: Value) -> OicResult<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|e| rpc_error(&self.redacted, method, format!("transport failure: {}", e.without_url())))?;
        let status = response.status();
        if !status.is_success() {
            return Err(rpc_error(&self.redacted, method, format!("HTTP {status}")));
        }
        let envelope: Value = response
            .json()
            .map_err(|e| rpc_error(&self.redacted, method, format!("response is not JSON: {}", e.without_url())))?;
        if let Some(error) = envelope.get("error").filter(|e| !e.is_null()) {
            return Err(rpc_error(&self.redacted, method, format!("node error: {error}")));
        }
        envelope
            .get("result")
            .cloned()
            .ok_or_else(|| rpc_error(&self.redacted, method, "response has no result".into()))
    }
}

fn rpc_error(redacted: &str, method: &str, detail: String) -> OicError {
    OicError::stale_evidence(format!("{method} against {redacted}: {detail}"))
}

/// Scheme and host(:port) only: no userinfo, path or query.
fn redact(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if scheme.is_empty() { host.to_string() } else { format!("{scheme}://{host}") }
}

/// Decode a 0x-prefixed hex quantity (variable length) into `u128`.
pub fn quantity_u128(v: &Value, what: &str) -> OicResult<u128> {
    let s = hex_str(v, what)?;
    u128::from_str_radix(s, 16).map_err(|_| OicError::stale_evidence(format!("{what} is not a hex quantity")))
}

/// Decode a 0x-prefixed hex quantity into `u64`.
pub fn quantity_u64(v: &Value, what: &str) -> OicResult<u64> {
    let q = quantity_u128(v, what)?;
    u64::try_from(q).map_err(|_| OicError::stale_evidence(format!("{what} exceeds u64")))
}

/// Decode 0x-prefixed hex data of exactly `N` bytes.
pub fn data_fixed<const N: usize>(v: &Value, what: &str) -> OicResult<[u8; N]> {
    let bytes = data_bytes(v, what)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| OicError::stale_evidence(format!("{what} must be {N} bytes, got {}", bytes.len())))
}

/// Decode 0x-prefixed hex data of any length.
pub fn data_bytes(v: &Value, what: &str) -> OicResult<Vec<u8>> {
    let s = hex_str(v, what)?;
    if s.len() % 2 != 0 {
        return Err(OicError::stale_evidence(format!("{what} has odd-length hex data")));
    }
    hex::decode(s).map_err(|_| OicError::stale_evidence(format!("{what} is not hex data")))
}

fn hex_str<'a>(v: &'a Value, what: &str) -> OicResult<&'a str> {
    v.as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or_else(|| OicError::stale_evidence(format!("{what} is not a 0x-prefixed string")))
}

/// Encode bytes as 0x-prefixed hex.
pub fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Encode an integer as a 0x-prefixed minimal hex quantity.
pub fn to_quantity(value: u64) -> String {
    format!("0x{value:x}")
}
