//! Chain clients for live nodes, speaking each network's standard RPC.
//!
//! The development simulators stay the conformance oracle; these clients
//! implement the same traits against a real endpoint so the money loop runs
//! on an actual development network (RFC 0002, Gate B). Evidence bundles
//! follow the adapter-documented item contracts byte for byte, and movement
//! ids reuse the simulator formats so both source kinds deduplicate
//! identically.
//!
//! Signing honesty (RFC 0002 §3.1): the repository's threshold backend is
//! FROST over Ed25519, so only Solana transactions are threshold-signed
//! today. EVM transactions are signed by a single development k256 key; no
//! reviewed threshold-ECDSA backend exists here, and none is improvised.
//! State that plainly anywhere these clients are demonstrated.

pub mod evm;
pub mod jsonrpc;
pub mod solana;
