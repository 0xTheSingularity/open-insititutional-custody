//! # oic-service-broadcaster
//!
//! Hands already signed transactions to a chain and reports what the chain
//! actually shows to the authorization-state authority (RFC 0001 §12).
//!
//! * [`Broadcaster::submit`] durably records a pending
//!   [`SubmissionAttempt`] *before* the chain call. A crash between that
//!   record and the acknowledgement is recovered as `SUBMISSION_UNKNOWN`
//!   ([`Broadcaster::recover`]), never as "not sent". A client error is also
//!   `SUBMISSION_UNKNOWN`: an RPC failure claim is not evidence (A18).
//! * [`Broadcaster::poll`] fetches evidence from every configured
//!   [`EvidenceSourceId`](oic_domain_types::EvidenceSourceId) of a
//!   [`ChainClient`], runs the pinned adapter's `observe` per source and
//!   compares. Agreement feeds one observation (`Included`, `Finalized`,
//!   `Reorged`) to the authority; disagreement feeds `Conflict`, which
//!   quarantines the family, after which nothing more is fed (A30). Only
//!   evidence anchored at the profile's finality commitment may produce
//!   `Finalized`. A transaction that disappears after inclusion is reported
//!   `Reorged`, which keeps its exposure (A31).
//! * [`Broadcaster::resolve_unknown`] first looks for the transaction on chain
//!   and otherwise asks the adapter to `prove_invalidation` from the
//!   possibly issued signed bytes; only unanimous `Definitive` proofs release
//!   the reservation.
//! * [`SubmissionStore`] has in-memory and append-only fsynced JSON-lines
//!   file implementations.

mod broadcaster;
mod client;
mod durable;
mod store;

pub use broadcaster::*;
pub use client::*;
pub use store::*;
