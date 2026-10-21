use super::*;
use wasm_bindgen::prelude::*;

include!(concat!(env!("OUT_DIR"), "/provision.rs"));

fn js(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
fn json<T: for<'de> Deserialize<'de>>(text: &str, limit: usize) -> Result<T, JsValue> {
    if text.len() > limit {
        return Err(js("artifact exceeds size limit"));
    }
    serde_json::from_str(text).map_err(js)
}

#[wasm_bindgen]
pub struct BrowserClient(Client);

#[wasm_bindgen]
impl BrowserClient {
    #[wasm_bindgen(constructor)]
    pub fn new(origin: &str, now: u64) -> Result<BrowserClient, JsValue> {
        if PROVISION.is_empty() {
            return Err(js(
                "Client is not independently provisioned. Install an institution-approved build.",
            ));
        }
        let mut seed = [0; 32];
        getrandom::getrandom(&mut seed).map_err(js)?;
        Ok(Self(
            Client::new(
                json(PROVISION, 4 * 1024 * 1024)?,
                seed,
                origin,
                UnixSeconds(now),
            )
            .map_err(js)?,
        ))
    }

    pub fn apply(&mut self, entry: &str, now: u64) -> Result<String, JsValue> {
        let floor = self
            .0
            .apply(&json(entry, 9 * 1024 * 1024)?, UnixSeconds(now))
            .map_err(js)?;
        serde_json::to_string(&floor).map_err(js)
    }

    pub fn floor(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0.floor()).map_err(js)
    }

    pub fn prepare(
        &mut self,
        package: &str,
        credential_id: &str,
        now: u64,
    ) -> Result<String, JsValue> {
        let credential =
            CredentialId::new(credential_id).ok_or_else(|| js("invalid credential identity"))?;
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(js)?;
        let prepared = self
            .0
            .prepare(
                json(package, 2 * 1024 * 1024)?,
                credential,
                Hash32(nonce),
                UnixSeconds(now),
            )
            .map_err(js)?;
        serde_json::to_string(&prepared).map_err(js)
    }

    pub fn assertion(
        &mut self,
        raw_id: &[u8],
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
        now: u64,
    ) -> Result<String, JsValue> {
        let command = self
            .0
            .assertion(
                raw_id,
                oic_webauthn::Assertion {
                    authenticator_data,
                    client_data_json,
                    signature,
                },
                UnixSeconds(now),
            )
            .map_err(js)?;
        serde_json::to_string(&command).map_err(js)
    }

    pub fn confirmed(&mut self, now: u64) -> Result<bool, JsValue> {
        self.0.confirmed(UnixSeconds(now)).map_err(js)
    }
}
