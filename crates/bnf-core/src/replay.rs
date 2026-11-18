//! Strictly monotonic counter guard (replay protection).
//!
//! Gaps are allowed (lost packets must not stall the motor loop), but a counter
//! is only accepted if it is strictly greater than every counter accepted before
//! it in the same session. A fresh session (new ML-KEM exchange, new key) makes
//! packets captured in older sessions fail MAC verification outright.

use crate::error::Rejection;

/// Tracks the highest accepted counter of the active session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplayGuard {
    last_accepted: u64,
}

impl ReplayGuard {
    /// New guard; the first valid counter is 1.
    #[must_use]
    pub const fn new() -> Self {
        Self { last_accepted: 0 }
    }

    /// Accepts and consumes `counter` if it is strictly greater than the last
    /// accepted one. Call only after the packet's MAC has verified.
    ///
    /// # Errors
    /// [`Rejection::ReplayDetected`] if `counter <= last_accepted`.
    pub const fn accept(&mut self, counter: u64) -> Result<(), Rejection> {
        if counter > self.last_accepted {
            self.last_accepted = counter;
            Ok(())
        } else {
            Err(Rejection::ReplayDetected {
                counter,
                last_accepted: self.last_accepted,
            })
        }
    }

    /// Highest accepted counter (0 if none yet).
    #[must_use]
    pub const fn last_accepted(&self) -> u64 {
        self.last_accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn monotonic_with_gaps() {
        let mut g = ReplayGuard::new();
        assert_eq!(g, ReplayGuard::default());
        assert!(g.accept(0).is_err());
        g.accept(1).unwrap();
        g.accept(5).unwrap();
        assert_eq!(
            g.accept(5),
            Err(Rejection::ReplayDetected {
                counter: 5,
                last_accepted: 5
            })
        );
        assert_eq!(
            g.accept(3),
            Err(Rejection::ReplayDetected {
                counter: 3,
                last_accepted: 5
            })
        );
        assert_eq!(g.last_accepted(), 5);
        g.accept(6).unwrap();
    }

    #[test]
    fn saturates_at_max() {
        let mut g = ReplayGuard::new();
        g.accept(u64::MAX).unwrap();
        assert!(g.accept(u64::MAX).is_err());
        assert_eq!(g.last_accepted(), u64::MAX);
    }

    proptest! {
        /// The guard behaves exactly like "accept iff greater than the running maximum".
        #[test]
        fn prop_matches_reference_model(counters in proptest::collection::vec(any::<u64>(), 0..200)) {
            let mut g = ReplayGuard::new();
            let mut max_seen = 0u64;
            for c in counters {
                let accepted = g.accept(c).is_ok();
                prop_assert_eq!(accepted, c > max_seen);
                if accepted {
                    max_seen = c;
                }
                prop_assert_eq!(g.last_accepted(), max_seen);
            }
        }
    }
}
