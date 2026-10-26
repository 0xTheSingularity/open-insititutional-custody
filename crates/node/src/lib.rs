//! Roster-admitted Commonware lookup transport (RFC 0003, D1).
//!
//! Supply a production `commonware_runtime::tokio::Context` from its `Runner`.
//! Handles use Tokio channels, so callers can send/receive across runtimes.
//! Startup schedules the network; Commonware owns socket binding and reports
//! listener/task failures through its runtime supervisor. `send` acknowledges
//! local submission, not reliable delivery. Retry idempotently above this layer.
//!
//! Transport authenticates node keys, not participant messages. MPC bytes stay
//! opaque; signer-core must verify participant signatures and release evidence.
//! No signer-core dependency or key is present here.

mod extension;
mod transport;

pub use extension::{
    EXTENSION_MAILBOX_CAPACITY, Extension, ExtensionChannel, ExtensionContext, ExtensionDispatch, ExtensionEvent, ExtensionHandle, ExtensionHost,
    ReceiptMonitor, ReceiptProgress,
};
pub use transport::{Config, Event, MAX_MESSAGE_SIZE, MAX_QUOTA, SendHandle, Transport, TransportStats};
pub use oic_peer_wire::PaddingProfile;
pub const COMMONWARE_RELEASE: &str = "2026.9.0";
