//! Keyless authority execution for RFC 0003 D2. Canonical commands and native
//! candidates are confidential. A block or an unsigned transition result alone
//! is never release evidence; followers require authenticated finalization and
//! contiguous local re-execution. No D1 receipt signing key enters this crate.

#[cfg(feature = "runtime")]
mod application;
mod block;
mod execution;
mod finality;
#[cfg(feature = "runtime")]
mod follower;
#[cfg(feature = "runtime")]
pub mod runtime;

#[cfg(feature = "runtime")]
pub use application::*;
pub use block::*;
pub use execution::*;
pub use finality::*;
#[cfg(feature = "runtime")]
pub use follower::*;
