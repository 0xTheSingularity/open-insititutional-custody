//! # oic-approval-verifier
//!
//! The library behind the independent approval client (RFC 0001 §4.3, RFC 0002
//! §8). It never trusts text supplied by the management console: it recomputes
//! what a candidate does from the candidate bytes using the pinned chain
//! adapters, recomputes every hash an approval binds to, and only then signs
//! an [`ApprovalGrant`] over what the approver actually saw.
//!
//! * `grants` is the shared signing/verification primitive used by the
//!   client, the coordinator, and every signer.
//! * `display` defines the [`ApprovalDisplay`] card and its exact amount and
//!   address formatting.
//! * `client` is the [`IndependentVerifier`] that renders displays from
//!   verified inputs and signs grants only for an unchanged display.

pub mod client;
pub mod display;
pub mod grants;

pub use client::*;
pub use display::*;
pub use grants::*;
