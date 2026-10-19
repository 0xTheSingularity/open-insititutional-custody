//! Injected time source. Authority logic only ever asks a [`Clock`].

use oic_domain_types::UnixSeconds;
use std::sync::atomic::{AtomicU64, Ordering};

pub trait Clock: Send + Sync {
    fn now(&self) -> UnixSeconds;
}

/// Deterministic clock for tests, model checking, and simulations.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(now: u64) -> Self {
        ManualClock(AtomicU64::new(now))
    }
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> UnixSeconds {
        UnixSeconds(self.0.load(Ordering::SeqCst))
    }
}

/// Wall-clock source for deployments. A clock that reads before the Unix
/// epoch reports zero, which makes every deadline already passed (fail closed).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixSeconds {
        UnixSeconds(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
    }
}
