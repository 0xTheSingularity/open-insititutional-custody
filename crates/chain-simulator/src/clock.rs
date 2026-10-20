//! Manual simulation clock. Evidence `observed_at` and block timestamps come
//! from here, never from the system clock, so runs are reproducible.

use oic_domain_types::{OicError, OicResult, UnixSeconds};
use std::sync::{Arc, Mutex};

/// Shared, manually-driven clock. Cloning shares the same time source, so a
/// test can hold one handle and advance time seen by every simulator built
/// with another handle. Time never moves backwards.
#[derive(Clone, Debug)]
pub struct SimClock {
    now: Arc<Mutex<UnixSeconds>>,
}

impl SimClock {
    pub fn new(start: UnixSeconds) -> Self {
        SimClock { now: Arc::new(Mutex::new(start)) }
    }

    pub fn now(&self) -> UnixSeconds {
        *crate::lock(&self.now)
    }

    /// Set the clock. Moving backwards is refused (`InvalidRequest`).
    pub fn set(&self, t: UnixSeconds) -> OicResult<()> {
        let mut g = crate::lock(&self.now);
        if t < *g {
            return Err(OicError::invalid_request(format!("SimClock cannot move backwards from {} to {}", g.0, t.0)));
        }
        *g = t;
        Ok(())
    }

    /// Advance by `secs`, returning the new time. Overflow is refused.
    pub fn advance(&self, secs: u64) -> OicResult<UnixSeconds> {
        let mut g = crate::lock(&self.now);
        let next = g.0.checked_add(secs).ok_or_else(|| crate::overflow("SimClock advance"))?;
        *g = UnixSeconds(next);
        Ok(*g)
    }
}

impl Default for SimClock {
    /// Starts at 2023-11-14T22:13:20Z (`1_700_000_000`).
    fn default() -> Self {
        SimClock::new(UnixSeconds(1_700_000_000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_advance_and_share() {
        let c = SimClock::new(UnixSeconds(100));
        let d = c.clone();
        assert_eq!(c.advance(5).unwrap(), UnixSeconds(105));
        assert_eq!(d.now(), UnixSeconds(105));
        d.set(UnixSeconds(200)).unwrap();
        assert_eq!(c.now(), UnixSeconds(200));
        assert!(c.set(UnixSeconds(199)).is_err());
        c.set(UnixSeconds(200)).unwrap();
        assert!(c.advance(u64::MAX).is_err());
        assert_eq!(c.now(), UnixSeconds(200));
        assert_eq!(SimClock::default().now(), UnixSeconds(1_700_000_000));
    }
}
