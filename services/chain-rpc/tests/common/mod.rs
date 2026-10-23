//! Shared scaffolding for the anvil-backed tests: a guarded anvil child on a
//! free port and a patient client connect. Each test binary that declares
//! `mod common;` compiles its own copy.
#![allow(dead_code)]

use oic_service_chain_rpc::evm::{EvmRpcClient, EvmRpcConfig};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Anvil's first well-known development account.
pub const DEV_KEY: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed,
    0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];

pub struct Anvil {
    child: Child,
    pub url: String,
}

impl Anvil {
    /// `None` when the binary is not installed.
    pub fn start() -> Option<Self> {
        let port = free_port();
        let child = Command::new("anvil")
            .args(["--port", &port.to_string(), "--silent"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        Some(Anvil { child, url: format!("http://127.0.0.1:{port}") })
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub fn connect(url: &str) -> EvmRpcClient {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match EvmRpcClient::connect(EvmRpcConfig::development(url)) {
            Ok(client) => return client,
            Err(e) => {
                assert!(Instant::now() < deadline, "anvil did not come up: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}
