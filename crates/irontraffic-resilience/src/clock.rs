// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wrapping time value types for the resilience subsystems.
//!
//! [`Millis`] comes from the data-plane clock seam at the call boundary. This crate
//! does not read a clock itself.

/// Milliseconds since process start, sourced from `irontraffic_time::CoarseMono`.
///
/// Wraps every 2^32 ms (49.7 days). Every interval this crate computes is bounded by
/// a timeout, an interval, or a decay window far shorter than that, so wrapping
/// arithmetic is exact. Never compare the inner `u32` directly; use [`Millis::since`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
pub struct Millis(pub u32);

impl Millis {
    /// Half of the `u32` range. A computed difference larger than this is read as
    /// "the other value is in the future", and [`Millis::since`] returns 0 for it.
    #[allow(clippy::integer_division, reason = "documented horizon constant")]
    pub const HORIZON_MS: u32 = u32::MAX / 2;

    /// Milliseconds elapsed from `earlier` to `self`, saturating at 0.
    ///
    /// Returns 0 when `self` is at or before `earlier`, including the coarse-clock
    /// reordering case where two cores disagree by one refresh.
    #[inline]
    #[must_use]
    pub fn since(self, earlier: Millis) -> u32 {
        let d = self.0.wrapping_sub(earlier.0);
        if d > Self::HORIZON_MS { 0 } else { d }
    }

    /// `self` advanced by `ms` milliseconds, wrapping.
    #[inline]
    #[must_use]
    pub fn add_ms(self, ms: u32) -> Millis {
        Millis(self.0.wrapping_add(ms))
    }

    /// True when `self` is at or before `other` on the wrapping timeline.
    #[inline]
    #[must_use]
    pub fn is_at_or_before(self, other: Millis) -> bool {
        self.since(other) == 0
    }
}

/// Microseconds from the precise monotonic clock.
///
/// Used ONLY for upstream-attempt latency samples, at most twice per upstream
/// attempt: once when the attempt is dispatched and once when it completes. No other
/// subsystem in this crate may take a `Micros`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub struct Micros(pub u64);

impl Micros {
    /// Microseconds elapsed from `earlier` to `self`, saturating at 0.
    #[inline]
    #[must_use]
    pub fn since(self, earlier: Micros) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::{ProptestConfig, proptest};

    #[test]
    fn since_equal_is_zero() {
        assert_eq!(Millis(7).since(Millis(7)), 0);
    }

    #[test]
    fn since_normal_forward() {
        assert_eq!(Millis(1_000).since(Millis(250)), 750);
    }

    #[test]
    fn since_backwards_is_zero() {
        assert_eq!(Millis(250).since(Millis(1_000)), 0);
    }

    #[test]
    fn since_across_wrap() {
        assert_eq!(Millis(5).since(Millis(u32::MAX - 4)), 10);
    }

    #[test]
    fn add_ms_wraps() {
        assert_eq!(Millis(u32::MAX).add_ms(3), Millis(2));
        assert_eq!(Millis(u32::MAX).add_ms(3).since(Millis(u32::MAX)), 3);
    }

    #[test]
    fn is_at_or_before_boundaries() {
        assert!(Millis(1).is_at_or_before(Millis(1)));
        assert!(Millis(1).is_at_or_before(Millis(2)));
        assert!(!Millis(2).is_at_or_before(Millis(1)));
    }

    #[test]
    fn micros_since_saturates() {
        assert_eq!(Micros(5).since(Micros(9)), 0);
        assert_eq!(Micros(9).since(Micros(5)), 4);
    }

    #[test]
    fn prop_add_then_since_roundtrip() {
        proptest!(
            ProptestConfig::default(),
            |(a in 0..=u32::MAX, d in 0..=Millis::HORIZON_MS)| {
                assert_eq!(Millis(a).add_ms(d).since(Millis(a)), d);
            }
        );
    }

    #[test]
    fn prop_since_never_exceeds_horizon() {
        proptest!(
            ProptestConfig::default(),
            |(a in 0..=u32::MAX, b in 0..=u32::MAX)| {
                assert!(Millis(a).since(Millis(b)) <= Millis::HORIZON_MS);
            }
        );
    }
}
