// SPDX-License-Identifier: MIT OR Apache-2.0

//! The four clock newtypes and their arithmetic.

use core::mem::size_of;

const _: () = assert!(size_of::<CoarseMono>() == 4);
const _: () = assert!(size_of::<CoarseWall>() == 8);
const _: () = assert!(size_of::<Boot>() == 8);
const _: () = assert!(size_of::<PreciseMono>() == 8);

const _: () = assert!(CoarseMono::MAX_INTERVAL_MS < CoarseMono::HALF_MODULUS_MS);

/// Milliseconds since process start, truncated to 32 bits.
///
/// Wraps every 49.7 days. Deliberately not `Ord`: use [`CoarseMono::reached`].
///
/// The following are deliberately absent so that mixing clocks or misusing
/// wrapping arithmetic is a type error rather than a silent bug:
///
/// - `PartialOrd` or `Ord`: ordering is not meaningful across a wrap boundary.
/// - The `-` operator: elapsed time is [`CoarseMono::elapsed_ms_since`].
/// - `From` into any other clock type: clock domains must not convert silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CoarseMono(u32);

impl CoarseMono {
    /// Half the 32-bit modulus: the largest interval `reached` can distinguish.
    pub const HALF_MODULUS_MS: u32 = 1 << 31;

    /// The largest interval this type is contracted for: `u32::MAX / 4`,
    /// which is `1_073_741_823` ms, about 12.4 days.
    ///
    /// Every caller that turns a configured duration into a deadline clamps it to
    /// this value first. Passing a larger interval to
    /// [`CoarseMono::saturating_add_ms`] yields a deadline that is already reached,
    /// which fires the timeout immediately; that is the safe direction, and it trips
    /// a `debug_assert` so it cannot survive a test run.
    #[rustfmt::skip]
    #[allow(clippy::integer_division, reason = "exact integer quarter of the modulus")]
    pub const MAX_INTERVAL_MS: u32 = u32::MAX / 4;

    /// Builds a timestamp from milliseconds since process start.
    ///
    /// `pub(crate)`, not `pub`: the only legitimate way to obtain a
    /// `CoarseMono` is to read it from the clock. That path is the
    /// `TimeSource` seam (`time-source-seam`, #5), which lives in this
    /// crate and can see this constructor; a downstream crate building one
    /// out of a bare integer it happened to have is always a bug, and
    /// privacy refuses it at compile time instead of relying on review.
    #[must_use]
    #[rustfmt::skip]
    pub(crate) const fn from_millis_since_start(ms: u32) -> Self {
        Self(ms)
    }

    /// Milliseconds since process start, as stored.
    #[must_use]
    pub const fn as_millis_since_start(self) -> u32 {
        self.0
    }

    /// True when `self` is at or after `deadline`, comparing wrap-safely.
    ///
    /// Correct for any interval under 24.85 days in either direction.
    /// `t.reached(t)` is true.
    #[must_use]
    pub const fn reached(self, deadline: Self) -> bool {
        let d = self.0.wrapping_sub(deadline.0);
        d < Self::HALF_MODULUS_MS
    }

    /// Milliseconds from `earlier` to `self`, wrapping.
    ///
    /// Correct for any interval under 49.7 days. If `earlier` is in the future
    /// the result is the (very large) wrapped difference, which callers detect
    /// with `reached` rather than by inspecting this value.
    #[must_use]
    pub const fn elapsed_ms_since(self, earlier: Self) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }

    /// A deadline `ms` milliseconds after `self`.
    ///
    /// Wraps rather than saturating at `u32::MAX`, which is what keeps
    /// [`CoarseMono::reached`] correct across the wrap boundary. Do not change
    /// this to `saturating_add`.
    ///
    /// `ms` must be at most [`CoarseMono::MAX_INTERVAL_MS`]. A larger value is a
    /// caller bug: it yields a deadline that [`CoarseMono::reached`] already
    /// reports as reached, so the timeout fires immediately. A `debug_assert`
    /// catches it in debug builds and in every test; the release behaviour is
    /// deliberately fail-fast rather than fail-never.
    ///
    /// Stays a `const fn`: `debug_assert!` is permitted in a `const fn`, and in a
    /// compile-time evaluation a violated assertion is a compile error, which is
    /// the strongest possible version of the check.
    #[must_use]
    pub const fn saturating_add_ms(self, ms: u32) -> Self {
        debug_assert!(
            ms <= Self::MAX_INTERVAL_MS,
            "interval exceeds the contract bound"
        );
        Self(self.0.wrapping_add(ms))
    }
}

/// Milliseconds since the Unix epoch. Wall clock: may step forwards or backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CoarseWall(u64);

impl CoarseWall {
    /// Builds a wall timestamp from milliseconds since the Unix epoch.
    ///
    /// `pub(crate)`, not `pub`: see [`CoarseMono::from_millis_since_start`]
    /// for why a raw-integer constructor for a clock type must not be
    /// public.
    #[must_use]
    #[rustfmt::skip]
    pub(crate) const fn from_unix_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_unix_millis(self) -> u64 {
        self.0
    }

    /// Milliseconds from `earlier` to `self`, or `None` if the clock stepped
    /// backwards (`earlier > self`). Callers must handle `None`; never assume
    /// a wall clock is monotonic.
    #[must_use]
    pub const fn elapsed_ms_since(self, earlier: Self) -> Option<u64> {
        if earlier.0 > self.0 {
            None
        } else {
            Some(self.0 - earlier.0)
        }
    }
}

/// Nanoseconds on `CLOCK_BOOTTIME`: monotonic and inclusive of suspend time.
///
/// Used only for rate-limit theoretical arrival times.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Boot(u64);

impl Boot {
    /// Builds a boot timestamp from nanoseconds on `CLOCK_BOOTTIME`.
    ///
    /// `pub(crate)`, not `pub`: see [`CoarseMono::from_millis_since_start`]
    /// for why a raw-integer constructor for a clock type must not be
    /// public.
    #[must_use]
    #[rustfmt::skip]
    pub(crate) const fn from_boottime_nanos(ns: u64) -> Self {
        Self(ns)
    }

    /// Nanoseconds on `CLOCK_BOOTTIME`, as stored.
    #[must_use]
    pub const fn as_boottime_nanos(self) -> u64 {
        self.0
    }

    /// Nanoseconds from `earlier` to `self`, saturating at 0.
    #[must_use]
    pub const fn elapsed_nanos_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// High resolution monotonic nanoseconds, for measurement only.
///
/// Never use on the request path: reading this costs a full `clock_gettime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PreciseMono(u64);

impl PreciseMono {
    /// Builds a measurement timestamp from nanoseconds.
    ///
    /// `pub(crate)`, not `pub`: see [`CoarseMono::from_millis_since_start`]
    /// for why a raw-integer constructor for a clock type must not be
    /// public.
    #[must_use]
    #[rustfmt::skip]
    pub(crate) const fn from_measurement_nanos(ns: u64) -> Self {
        Self(ns)
    }

    /// Nanoseconds, as stored.
    #[must_use]
    pub const fn as_measurement_nanos(self) -> u64 {
        self.0
    }

    /// Whole microseconds, truncating.
    #[must_use]
    #[rustfmt::skip]
    #[allow(clippy::integer_division, reason = "documented truncation to whole microseconds")]
    pub const fn as_micros(self) -> u64 {
        self.0 / 1_000
    }

    /// Nanoseconds from `earlier` to `self`, saturating at 0.
    #[must_use]
    pub const fn elapsed_nanos_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn coarse_mono_reached_is_true_at_equality() {
        assert!(
            CoarseMono::from_millis_since_start(7).reached(CoarseMono::from_millis_since_start(7))
        );
    }

    #[test]
    fn coarse_mono_reached_is_false_before_deadline() {
        assert!(
            !CoarseMono::from_millis_since_start(10)
                .reached(CoarseMono::from_millis_since_start(11))
        );
    }

    #[test]
    fn coarse_mono_reached_across_wrap() {
        assert!(
            CoarseMono::from_millis_since_start(0)
                .reached(CoarseMono::from_millis_since_start(u32::MAX))
        );
        assert!(
            !CoarseMono::from_millis_since_start(u32::MAX)
                .reached(CoarseMono::from_millis_since_start(0))
        );
    }

    #[test]
    fn coarse_mono_reached_at_half_modulus_is_false() {
        assert!(
            !CoarseMono::from_millis_since_start(CoarseMono::HALF_MODULUS_MS)
                .reached(CoarseMono::from_millis_since_start(0))
        );
    }

    #[test]
    fn coarse_mono_elapsed_wraps_exactly() {
        assert_eq!(
            CoarseMono::from_millis_since_start(5)
                .elapsed_ms_since(CoarseMono::from_millis_since_start(u32::MAX)),
            6
        );
    }

    #[test]
    fn coarse_mono_add_wraps() {
        assert_eq!(
            CoarseMono::from_millis_since_start(u32::MAX).saturating_add_ms(1),
            CoarseMono::from_millis_since_start(0)
        );
    }

    #[test]
    fn coarse_wall_elapsed_none_when_backwards() {
        assert_eq!(
            CoarseWall::from_unix_millis(100).elapsed_ms_since(CoarseWall::from_unix_millis(101)),
            None
        );
        assert_eq!(
            CoarseWall::from_unix_millis(101).elapsed_ms_since(CoarseWall::from_unix_millis(100)),
            Some(1)
        );
    }

    #[test]
    fn boot_elapsed_saturates_at_zero() {
        assert_eq!(
            Boot::from_boottime_nanos(5).elapsed_nanos_since(Boot::from_boottime_nanos(9)),
            0
        );
    }

    #[test]
    fn precise_as_micros_truncates() {
        assert_eq!(PreciseMono::from_measurement_nanos(1_999).as_micros(), 1);
    }

    #[test]
    #[rustfmt::skip]
    #[allow(clippy::assertions_on_constants, reason = "tests documented constants")]
    #[allow(clippy::integer_division, reason = "exact integer quarter of the modulus")]
    fn max_interval_is_a_usable_deadline() {
        assert_eq!(CoarseMono::MAX_INTERVAL_MS, u32::MAX / 4);
        assert!(CoarseMono::MAX_INTERVAL_MS < CoarseMono::HALF_MODULUS_MS);
        let now = CoarseMono::from_millis_since_start(7);
        let d = now.saturating_add_ms(CoarseMono::MAX_INTERVAL_MS);
        assert!(!now.reached(d));
        assert!(
            CoarseMono::from_millis_since_start(7u32.wrapping_add(CoarseMono::MAX_INTERVAL_MS))
                .reached(d)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]
        #[test]
        fn prop_reached_is_consistent_with_wrapping_order(
            base: u32,
            delta in 0..=CoarseMono::MAX_INTERVAL_MS,
        ) {
            let deadline = CoarseMono::from_millis_since_start(base).saturating_add_ms(delta);
            assert!(deadline.reached(CoarseMono::from_millis_since_start(base)));
            if delta > 0 {
                assert!(!CoarseMono::from_millis_since_start(base).reached(deadline));
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]
        #[test]
        fn prop_elapsed_inverts_add(
            base: u32,
            delta in 0..=CoarseMono::MAX_INTERVAL_MS,
        ) {
            let elapsed = CoarseMono::from_millis_since_start(base)
                .saturating_add_ms(delta)
                .elapsed_ms_since(CoarseMono::from_millis_since_start(base));
            assert_eq!(elapsed, delta);
        }
    }

    // `prop_elapsed_inverts_add` above is bounded to `0..=MAX_INTERVAL_MS` because
    // `saturating_add_ms` carries `debug_assert!(ms <= MAX_INTERVAL_MS)`, so it can
    // never exercise a delta that actually crosses the 32-bit wrap boundary. The
    // wraparound identity is still a claim this type makes (`elapsed_ms_since` is
    // documented as correct "for any interval under 49.7 days" and is implemented
    // with `wrapping_sub`), so it needs its own test that reaches it directly with
    // `wrapping_add`/`wrapping_sub`, bypassing `saturating_add_ms` and its contract
    // bound entirely. No `MAX_INTERVAL_MS` clamp applies here: `delta` ranges over
    // the full `u32`.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]
        #[test]
        fn prop_elapsed_since_inverts_wrapping_add_beyond_contract(base: u32, delta: u32) {
            let later = CoarseMono::from_millis_since_start(base.wrapping_add(delta));
            let earlier = CoarseMono::from_millis_since_start(base);
            assert_eq!(later.elapsed_ms_since(earlier), delta);
        }
    }
}
