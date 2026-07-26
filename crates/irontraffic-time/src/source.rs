// SPDX-License-Identifier: MIT OR Apache-2.0

//! The time source seam: every clock read in the workspace goes through here.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{Boot, CoarseMono, CoarseWall, PreciseMono};

/// Produces the four clock values. The only clock-reading interface in the workspace.
///
/// Implementations must be cheap: `coarse_mono` and `coarse_wall` are read once per
/// event loop turn by every worker.
pub trait TimeSource: Send + Sync + 'static {
    /// Milliseconds since this source was constructed.
    fn coarse_mono(&self) -> CoarseMono;
    /// Milliseconds since the Unix epoch, as the operating system reports it.
    ///
    /// A return of `CoarseWall::from_unix_millis(0)` means the wall clock is
    /// unusable (a system clock set before 1970), not "midnight on 1 January
    /// 1970". Any consumer that makes a trust decision from a wall timestamp
    /// (certificate validity, token expiry, cache freshness) MUST treat 0 as
    /// unknown and fail closed: reject the credential, treat the entry as stale.
    /// The two values are deliberately not distinguished in the type, because a
    /// process whose wall clock is set to 1970 has no business validating
    /// anything either way.
    fn coarse_wall(&self) -> CoarseWall;
    /// `CLOCK_BOOTTIME` nanoseconds on Linux, `CLOCK_MONOTONIC` elsewhere.
    fn boot(&self) -> Boot;
    /// High resolution monotonic nanoseconds. Measurement only.
    fn precise(&self) -> PreciseMono;
}

/// Shared handle to the process clock.
pub type SharedTime = std::sync::Arc<dyn TimeSource>;

/// Milliseconds since process start, truncated to the low 32 bits.
///
/// Split out of [`SystemTimeSource::coarse_mono`] so the documented 49.7 day
/// wrap (edge cases 3 and 6a) can be pinned by a test without a 49.7 day
/// process.
fn coarse_mono_ms_from(millis: u128) -> u32 {
    let low = millis & 0xFFFF_FFFF;
    u32::try_from(low).unwrap_or(0)
}

/// Milliseconds since the Unix epoch, or the 0 "wall clock unavailable" sentinel.
///
/// `None` is the system-clock-set-before-1970 case (edge case 1). `Some`
/// saturates to `u64::MAX` rather than wrapping when the duration does not fit
/// in a `u64` of milliseconds (edge case 2). Split out of
/// [`SystemTimeSource::coarse_wall`] so both directions can be pinned without
/// moving the operating system's wall clock.
fn wall_millis_from(since_epoch: Option<Duration>) -> u64 {
    match since_epoch {
        Some(d) => u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
        None => 0,
    }
}

/// Nanoseconds from a `Timespec`, saturating rather than wrapping.
///
/// `tv_sec` and `tv_nsec` are converted independently, so a negative field
/// (edge case 6) becomes 0 rather than a panic or a silently wrapped value;
/// the scaling then saturates at `u64::MAX` rather than overflowing (edge
/// case 2a). Taking the whole `Timespec`, rather than the two fields as
/// separate positional arguments, means there is no argument order left at
/// the call site in [`SystemTimeSource::boot`] to get backwards; the one
/// place `tv_sec` and `tv_nsec` could still be transposed is inside this
/// function's own body, where a test reads a `Timespec` it built itself and
/// pins the two fields directly.
fn boot_nanos_from(ts: rustix::time::Timespec) -> u64 {
    let seconds: u64 = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanoseconds: u64 = u64::try_from(ts.tv_nsec).unwrap_or(0);
    seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanoseconds)
}

/// Nanoseconds since process start, saturating at `u64::MAX` (edge case 4).
///
/// Split out of [`SystemTimeSource::precise`] so the saturation can be pinned
/// by a test without a 584 year process.
fn precise_nanos_from(nanos: u128) -> u64 {
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// Reads the operating system clocks. Construct exactly one per process.
#[derive(Debug)]
pub struct SystemTimeSource {
    start: Instant,
}

impl SystemTimeSource {
    /// Captures process start. `CoarseMono` values are relative to this call,
    /// so a process must construct this once and share it.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemTimeSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for SystemTimeSource {
    fn coarse_mono(&self) -> CoarseMono {
        CoarseMono::from_millis_since_start(coarse_mono_ms_from(self.start.elapsed().as_millis()))
    }

    fn coarse_wall(&self) -> CoarseWall {
        // `.ok()` discards a `SystemTimeError` that carries no usable information:
        // its only meaning is "the clock is before 1970", which is the `None` case.
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).ok();
        CoarseWall::from_unix_millis(wall_millis_from(since_epoch))
    }

    fn boot(&self) -> Boot {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let ts = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        Boot::from_boottime_nanos(boot_nanos_from(ts))
    }

    fn precise(&self) -> PreciseMono {
        PreciseMono::from_measurement_nanos(precise_nanos_from(self.start.elapsed().as_nanos()))
    }
}

/// A clock that only moves when a test moves it.
#[derive(Debug)]
pub struct TestTimeSource {
    mono_ms: AtomicU32,
    wall_ms: AtomicU64,
    boot_ns: AtomicU64,
}

impl Default for TestTimeSource {
    /// Exactly [`TestTimeSource::new`]. Deliberately hand-written rather than
    /// derived: a derived `Default` would zero every atomic and give a wall clock
    /// of 0, which is a different starting state from `new` and would make two
    /// tests that build the source two different ways disagree.
    fn default() -> Self {
        Self::new()
    }
}

impl TestTimeSource {
    /// Monotonic 0, wall `1_600_000_000_000`, boot 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mono_ms: AtomicU32::new(0),
            wall_ms: AtomicU64::new(1_600_000_000_000),
            boot_ns: AtomicU64::new(0),
        }
    }

    /// Advances the monotonic, wall, and boot clocks together by `ms`.
    /// This is the only way to move time in a test that is faithful to reality.
    ///
    /// All three fields are updated with `Ordering::Relaxed`. A concurrent
    /// reader may observe `advance_ms` half-applied; no test asserts otherwise.
    pub fn advance_ms(&self, ms: u32) {
        // Monotonic clock wraps by design, matching `CoarseMono` semantics.
        self.mono_ms.fetch_add(ms, Ordering::Relaxed);

        // Wall clock saturates: it does not wrap.
        let delta_wall = u64::from(ms);
        loop {
            let old = self.wall_ms.load(Ordering::Relaxed);
            let new = old.saturating_add(delta_wall);
            if self
                .wall_ms
                .compare_exchange_weak(old, new, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        // Boot clock saturates: it does not wrap.
        let delta_boot = u64::from(ms).saturating_mul(1_000_000);
        loop {
            let old = self.boot_ns.load(Ordering::Relaxed);
            let new = old.saturating_add(delta_boot);
            if self
                .boot_ns
                .compare_exchange_weak(old, new, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Sets the wall clock alone, leaving monotonic and boot untouched.
    /// Exists to simulate an NTP step, including a step backwards.
    pub fn set_wall_unix_millis(&self, ms: u64) {
        self.wall_ms.store(ms, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain AtomicU64 replacement of a cached test clock value, not an ArcSwap config snapshot publish
    }
}

impl TimeSource for TestTimeSource {
    fn coarse_mono(&self) -> CoarseMono {
        CoarseMono::from_millis_since_start(self.mono_ms.load(Ordering::Relaxed))
    }

    fn coarse_wall(&self) -> CoarseWall {
        CoarseWall::from_unix_millis(self.wall_ms.load(Ordering::Relaxed))
    }

    fn boot(&self) -> Boot {
        Boot::from_boottime_nanos(self.boot_ns.load(Ordering::Relaxed))
    }

    fn precise(&self) -> PreciseMono {
        let mono_ms = self.mono_ms.load(Ordering::Relaxed);
        PreciseMono::from_measurement_nanos(u64::from(mono_ms) * 1_000_000)
    }
}

// Compile-time proof that `TestTimeSource` can be shared across threads.
const _: fn() = || {
    fn f<T: Send + Sync>() {}
    f::<TestTimeSource>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn system_mono_is_monotonic_over_many_reads() {
        let source = SystemTimeSource::new();
        let mut prev = source.coarse_mono();
        for _ in 1..1_000 {
            let cur = source.coarse_mono();
            assert!(cur.reached(prev));
            prev = cur;
        }
    }

    #[test]
    fn system_wall_is_after_2020() {
        let source = SystemTimeSource::new();
        assert!(source.coarse_wall().as_unix_millis() > 1_600_000_000_000);
    }

    #[test]
    fn system_boot_advances() {
        let source = SystemTimeSource::new();
        let start = source.boot();
        let mut advanced = None;
        for i in 0..10_000_000 {
            let now = source.boot();
            if now.as_boottime_nanos() > start.as_boottime_nanos() {
                advanced = Some((now, i));
                break;
            }
        }
        assert!(
            advanced.is_some(),
            "boot clock did not advance within 10_000_000 reads"
        );
    }

    #[test]
    fn system_precise_advances_within_a_read_pair() {
        let source = SystemTimeSource::new();
        let start = source.precise();
        for _ in 0..1_000 {
            std::hint::black_box(source.precise());
        }
        let end = source.precise();
        assert!(end.elapsed_nanos_since(start) > 0);
    }

    #[test]
    fn test_source_starts_at_zero_mono() {
        let ts = TestTimeSource::new();
        assert_eq!(ts.coarse_mono(), CoarseMono::from_millis_since_start(0));
        assert_eq!(
            ts.coarse_wall(),
            CoarseWall::from_unix_millis(1_600_000_000_000)
        );
    }

    #[test]
    fn test_source_advance_moves_all_three() {
        let ts = TestTimeSource::new();
        ts.advance_ms(1_500);
        assert_eq!(ts.coarse_mono(), CoarseMono::from_millis_since_start(1_500));
        assert_eq!(
            ts.coarse_wall(),
            CoarseWall::from_unix_millis(1_600_000_001_500)
        );
        assert_eq!(ts.boot().as_boottime_nanos(), 1_500_000_000);
    }

    #[test]
    fn test_source_advance_zero_is_noop() {
        let ts = TestTimeSource::new();
        let mono = ts.coarse_mono();
        let wall = ts.coarse_wall();
        let boot = ts.boot();
        let precise = ts.precise();
        ts.advance_ms(0);
        assert_eq!(ts.coarse_mono(), mono);
        assert_eq!(ts.coarse_wall(), wall);
        assert_eq!(ts.boot(), boot);
        assert_eq!(ts.precise(), precise);
    }

    #[test]
    fn test_source_wall_step_backwards_is_observable() {
        let ts = TestTimeSource::new();
        ts.advance_ms(1_000);
        ts.set_wall_unix_millis(1_500_000_000_000);
        assert_eq!(ts.coarse_mono(), CoarseMono::from_millis_since_start(1_000));
        assert_eq!(
            ts.coarse_wall(),
            CoarseWall::from_unix_millis(1_500_000_000_000)
        );
        assert_eq!(
            CoarseWall::from_unix_millis(1_600_000_001_000).elapsed_ms_since(ts.coarse_wall()),
            Some(100_000_001_000)
        );
        assert_eq!(
            ts.coarse_wall()
                .elapsed_ms_since(CoarseWall::from_unix_millis(1_600_000_001_000)),
            None
        );
    }

    #[test]
    fn test_source_mono_wraps_at_u32_max() {
        let ts = TestTimeSource::new();
        ts.advance_ms(u32::MAX);
        ts.advance_ms(2);
        assert_eq!(ts.coarse_mono(), CoarseMono::from_millis_since_start(1));
        // The exact post-condition: 1_600_000_000_000 + u32::MAX + 2. The wall
        // clock does not wrap, so an equality here (not merely a lower bound)
        // pins that the two `advance_ms` calls added exactly what they should.
        assert_eq!(ts.coarse_wall().as_unix_millis(), 1_604_294_967_297);
    }

    #[test]
    fn test_source_precise_is_mono_millis_in_nanos() {
        let ts = TestTimeSource::new();
        assert_eq!(ts.precise().as_measurement_nanos(), 0);
        ts.advance_ms(1_500);
        assert_eq!(ts.precise().as_measurement_nanos(), 1_500_000_000);
        // 4296 ms in nanoseconds exceeds u32::MAX (4_294_967_295), so a
        // multiply that happens before the widening to u64 overflows the u32
        // and produces a value unrelated to 4_296_000_000.
        ts.advance_ms(2_796);
        assert_eq!(ts.coarse_mono(), CoarseMono::from_millis_since_start(4_296));
        assert_eq!(ts.precise().as_measurement_nanos(), 4_296_000_000);
    }

    #[test]
    fn test_source_wall_and_boot_saturate_at_the_top() {
        let ts = TestTimeSource::new();
        ts.set_wall_unix_millis(u64::MAX);
        ts.advance_ms(5);
        assert_eq!(ts.coarse_wall(), CoarseWall::from_unix_millis(u64::MAX));

        // boot_ns needs a bit over 4295 whole u32::MAX advances to reach
        // u64::MAX; 4400 clears that with margin.
        let ts2 = TestTimeSource::new();
        for _ in 0..4_400 {
            ts2.advance_ms(u32::MAX);
        }
        assert_eq!(ts2.boot().as_boottime_nanos(), u64::MAX);
        ts2.advance_ms(1);
        assert_eq!(ts2.boot().as_boottime_nanos(), u64::MAX);
    }

    #[test]
    fn test_source_default_equals_new() {
        let d = TestTimeSource::default();
        let n = TestTimeSource::new();
        assert_eq!(d.coarse_mono(), n.coarse_mono());
        assert_eq!(d.coarse_wall(), n.coarse_wall());
        assert_eq!(d.boot(), n.boot());
        assert_eq!(d.precise(), n.precise());
    }

    #[test]
    fn system_wall_is_before_2100() {
        // 4_102_444_800_000 is 2100-01-01T00:00:00Z in milliseconds. A reading
        // at or above it means the value is not milliseconds (paired with
        // `system_wall_is_after_2020` this brackets the unit both ways; the
        // existing test alone cannot catch an over-scaling mutant).
        let source = SystemTimeSource::new();
        let w = source.coarse_wall().as_unix_millis();
        assert!(
            w < 4_102_444_800_000,
            "coarse_wall returned {w}, which is not a millisecond timestamp"
        );
    }

    #[test]
    fn system_boot_is_uptime_not_a_wall_clock() {
        // BOOTTIME and MONOTONIC count from boot; REALTIME counts from 1970.
        // A rate limiter fed a REALTIME-scale value would treat every request
        // as arriving decades after its actual theoretical arrival time.
        let source = SystemTimeSource::new();
        let ns = source.boot().as_boottime_nanos();
        assert!(
            ns < 1_600_000_000_000_000_000,
            "boot() returned {ns} ns, which is wall-clock scale, not uptime"
        );
    }

    #[test]
    fn coarse_mono_ms_truncates_only_at_the_49_day_wrap() {
        assert_eq!(coarse_mono_ms_from(0), 0);
        assert_eq!(coarse_mono_ms_from(1_500), 1_500);
        assert_eq!(coarse_mono_ms_from(65_536), 65_536);
        assert_eq!(coarse_mono_ms_from(u128::from(u32::MAX)), u32::MAX);
        assert_eq!(coarse_mono_ms_from(u128::from(u32::MAX) + 1), 0);
        assert_eq!(coarse_mono_ms_from(u128::from(u32::MAX) + 6), 5);
    }

    #[test]
    fn wall_millis_none_is_the_zero_unavailable_sentinel() {
        assert_eq!(wall_millis_from(None), 0);
        assert_eq!(
            wall_millis_from(Some(Duration::from_secs(1_600_000_000))),
            1_600_000_000_000
        );
        assert_eq!(wall_millis_from(Some(Duration::MAX)), u64::MAX);
    }

    #[test]
    fn boot_nanos_scales_seconds_and_saturates_upward() {
        // Building a real `rustix::time::Timespec` (its fields are public)
        // and reading it through `boot_nanos_from` exercises the exact
        // expression `boot()` evaluates, so a mutation that transposes
        // `tv_sec` and `tv_nsec` inside `boot_nanos_from` is caught here; there
        // is no separate call-site argument order left to get backwards.
        let ts = |tv_sec, tv_nsec| rustix::time::Timespec { tv_sec, tv_nsec };
        assert_eq!(boot_nanos_from(ts(0, 0)), 0);
        assert_eq!(boot_nanos_from(ts(2, 3)), 2_000_000_003);
        assert_eq!(boot_nanos_from(ts(0, 999_999_999)), 999_999_999);
        assert_eq!(boot_nanos_from(ts(-1, -1)), 0);
        assert_eq!(boot_nanos_from(ts(-1, 5)), 5);
        assert_eq!(boot_nanos_from(ts(i64::MAX, 999_999_999)), u64::MAX);
        assert_eq!(boot_nanos_from(ts(20_000_000_000, 0)), u64::MAX);
    }

    #[test]
    fn precise_nanos_saturates_at_u64_max() {
        assert_eq!(precise_nanos_from(0), 0);
        assert_eq!(precise_nanos_from(1_000), 1_000);
        assert_eq!(precise_nanos_from(u128::from(u64::MAX)), u64::MAX);
        assert_eq!(precise_nanos_from(u128::from(u64::MAX) + 1), u64::MAX);
    }

    // Bounded to 0..1_000_000 per operand deliberately, not merely by default:
    // `ts2.advance_ms(a + b)` computes `a + b` as an ordinary (overflow
    // checked) `u32` addition, so a generator wide enough to make that sum
    // exceed `u32::MAX` would panic in the test itself rather than exercise
    // the mono wrap, and there is no single `u32` argument that represents
    // "the combined effect of two advances whose true sum does not fit in a
    // u32" for the wall and boot fields, which grow by the real (unwrapped)
    // sum. Reaching the mono wrap, the wall saturation ceiling, and the
    // `precise()` 4295 ms overflow through this generator is therefore not
    // merely low probability, it is unreachable by construction, whatever the
    // bound: those three boundaries are covered instead by the dedicated
    // deterministic tests above (`test_source_mono_wraps_at_u32_max`,
    // `test_source_wall_and_boot_saturate_at_the_top`,
    // `test_source_precise_is_mono_millis_in_nanos`) and by the property
    // below, which restates the mono-wrap comparison in a form that is valid
    // over the full `u32` range.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_024))]
        #[test]
        fn prop_test_source_advance_is_additive(
            a in 0..1_000_000u32,
            b in 0..1_000_000u32,
        ) {
            let ts1 = TestTimeSource::new();
            ts1.advance_ms(a);
            ts1.advance_ms(b);

            let ts2 = TestTimeSource::new();
            ts2.advance_ms(a + b);

            assert_eq!(ts1.coarse_mono(), ts2.coarse_mono());
            assert_eq!(ts1.coarse_wall(), ts2.coarse_wall());
            assert_eq!(ts1.boot(), ts2.boot());
        }
    }

    // Companion to `prop_test_source_advance_is_additive` over the full `u32`
    // range: compares only `coarse_mono`, against `a.wrapping_add(b)` rather
    // than a second `advance_ms` call, which is the one comparison that stays
    // well defined once the true sum no longer fits in a `u32`. This is the
    // test that gives the mono wrap a non-zero probability of being exercised.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_024))]
        #[test]
        fn prop_test_source_mono_wraps_like_wrapping_add(a: u32, b: u32) {
            let ts = TestTimeSource::new();
            ts.advance_ms(a);
            ts.advance_ms(b);
            assert_eq!(
                ts.coarse_mono(),
                CoarseMono::from_millis_since_start(a.wrapping_add(b))
            );
        }
    }
}
