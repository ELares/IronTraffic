// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-worker cached coarse clocks, refreshed once per event loop turn.
//!
//! Two shapes of the same idea, for two different ownership stories.
//! [`CoarseCache`] is owned by exactly one worker: plain `Clone, Copy` fields,
//! read and written by the same thread, with no migration concern.
//! [`AtomicCoarseCache`] lives in a shared, `'static` slot that outlives any
//! single scope, so a *different* thread may read it after the owning worker
//! has moved on; its fields are atomics instead, and both types stay reachable
//! only through this crate's sanctioned constructors, never through a raw
//! integer a caller happened to have.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::{CoarseMono, CoarseWall, TimeSource};

/// Per-worker cached coarse clocks, refreshed once per event loop turn.
///
/// Reading through this cache is the only permitted way for the request path to
/// learn the time. `Boot` is deliberately absent: the rate limiter reads it directly.
#[derive(Debug, Clone, Copy)]
pub struct CoarseCache {
    mono: CoarseMono,
    wall: CoarseWall,
}

// A `CoarseMono` (4 bytes) plus a `CoarseWall` (8 bytes) in a structure aligned
// to 8 occupies 16 bytes. Checked at compile time, not only in
// `cache_size_is_sixteen_bytes` below, so a future field addition fails the
// build instead of a test run.
const _: () = assert!(core::mem::size_of::<CoarseCache>() == 16);

impl CoarseCache {
    /// Reads both coarse clocks once.
    #[must_use]
    pub fn new(ts: &dyn TimeSource) -> Self {
        Self {
            mono: ts.coarse_mono(),
            wall: ts.coarse_wall(),
        }
    }

    /// Reads both coarse clocks once and stores them. Call at the top of an
    /// event loop turn, never per request.
    pub fn refresh(&mut self, ts: &dyn TimeSource) {
        self.mono = ts.coarse_mono();
        self.wall = ts.coarse_wall();
    }

    /// The cached monotonic timestamp. No clock read, no atomic.
    #[must_use]
    #[inline]
    pub fn mono(&self) -> CoarseMono {
        self.mono
    }

    /// The cached wall timestamp. No clock read, no atomic.
    #[must_use]
    #[inline]
    pub fn wall(&self) -> CoarseWall {
        self.wall
    }
}

/// A cross-thread, atomically shared cache of both coarse clocks.
///
/// [`CoarseCache`] cannot serve a per-core slot: `CoarseMono` and `CoarseWall`
/// are plain structs, not atomics, so a field of either type reached from two
/// threads (the worker that owns a slot, and a task that migrated away from it
/// mid-request) would be a data race. This type stores the same millisecond
/// bit patterns those two types wrap, in an `AtomicU32` and an `AtomicU64`, so
/// it can be placed in a shared, `'static` slot and read with no lock and no
/// torn value.
///
/// [`AtomicCoarseCache::refresh`] is the only write path, and it is exactly
/// the "read the clock once, store the result" pattern [`TimeSource`]
/// sanctions elsewhere in this crate. [`AtomicCoarseCache::mono`] and
/// [`AtomicCoarseCache::wall`] are relaxed loads: no clock read and no
/// `TimeSource` in hand required, which is what lets a scope that has only
/// this cache (never the clock that fed it) reconstruct a real `CoarseMono`
/// or `CoarseWall`, through this crate's own constructors, rather than a raw
/// integer the caller assembled itself.
///
/// The two fields are independent atomics, written by two separate relaxed
/// stores inside `refresh`. A reader racing a `refresh` can therefore observe
/// one field from the new reading and the other still from the previous one,
/// but never a torn integer: each field is always a complete value that was
/// genuinely read from the clock at some point. That is safe here because the
/// two clock domains are never combined; `CoarseMono` and `CoarseWall` are
/// deliberately not interconvertible, so nothing in this crate ever compares
/// one against the other.
///
/// Every value handed back by `mono`/`wall` is either the all-zero starting
/// state or something a real [`TimeSource`] returned verbatim: this type
/// never adds to, subtracts from, or otherwise transforms the stored integer,
/// so it cannot manufacture a value the clock never produced, and it cannot
/// reintroduce the wrapped-subtraction bug that [`CoarseWall::elapsed_ms_since`]
/// exists to prevent. In particular, when the underlying wall clock steps
/// backwards (an NTP correction), `refresh` stores the smaller value exactly
/// as read; it is never clamped, floored, or replaced with the previous
/// (larger) cached value, because doing so would hide the step from
/// `elapsed_ms_since`, which relies on comparing two genuine readings to
/// return `None` rather than a wrapped duration.
#[derive(Debug)]
pub struct AtomicCoarseCache {
    mono_ms: AtomicU32,
    wall_ms: AtomicU64,
}

// An `AtomicU32` (4 bytes) plus an `AtomicU64` (8 bytes) in a structure
// aligned to 8 occupies 16 bytes, the same layout as `CoarseCache`. Checked at
// compile time, not only in `atomic_cache_size_is_sixteen_bytes` below, so a
// future field addition (which would also grow every per-core slot that
// embeds this type) fails the build instead of a test run.
const _: () = assert!(core::mem::size_of::<AtomicCoarseCache>() == 16);

// Compile-time proof that `AtomicCoarseCache` can be shared across threads,
// which is the entire reason it exists rather than `CoarseCache`: a per-core
// slot is `'static` and reachable by whichever thread currently owns that
// core.
const _: fn() = || {
    fn f<T: Send + Sync>() {}
    f::<AtomicCoarseCache>();
};

impl AtomicCoarseCache {
    /// A cache with both clocks at their all-zero starting state. Call
    /// [`AtomicCoarseCache::refresh`] before trusting either reading: until
    /// then, `mono()` reads as a genuine (if coincidental) zero timestamp, and
    /// `wall()` reads as the wall-clock-unavailable sentinel documented on
    /// [`TimeSource::coarse_wall`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mono_ms: AtomicU32::new(0),
            wall_ms: AtomicU64::new(0),
        }
    }

    /// Reads both coarse clocks once and stores them with a relaxed store
    /// each. Call at the top of an event loop turn, never per request; this
    /// is the only method that touches `ts`, and the only write path this
    /// type has.
    pub fn refresh(&self, ts: &dyn TimeSource) {
        let mono_ms = ts.coarse_mono().as_millis_since_start();
        let wall_ms = ts.coarse_wall().as_unix_millis();
        self.mono_ms.store(mono_ms, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain AtomicU32 cache field write, not an ArcSwap config snapshot publish; this is the cache's own single write path, mirroring the existing AtomicU64 store in source.rs
        self.wall_ms.store(wall_ms, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain AtomicU64 cache field write, not an ArcSwap config snapshot publish; this is the cache's own single write path, mirroring the existing AtomicU64 store in source.rs
    }

    /// The cached monotonic timestamp, as of the last `refresh`. A relaxed
    /// load: no clock read, no `TimeSource` required.
    #[must_use]
    #[inline]
    pub fn mono(&self) -> CoarseMono {
        CoarseMono::from_millis_since_start(self.mono_ms.load(Ordering::Relaxed))
    }

    /// The cached wall timestamp, as of the last `refresh`. A relaxed load:
    /// no clock read, no `TimeSource` required.
    #[must_use]
    #[inline]
    pub fn wall(&self) -> CoarseWall {
        CoarseWall::from_unix_millis(self.wall_ms.load(Ordering::Relaxed))
    }
}

impl Default for AtomicCoarseCache {
    /// Exactly [`AtomicCoarseCache::new`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use proptest::prelude::*;

    use super::*;
    use crate::TestTimeSource;

    #[test]
    fn cache_reads_are_frozen_between_refreshes() {
        let ts = TestTimeSource::new();
        let mut cache = CoarseCache::new(&ts);
        ts.advance_ms(5_000);
        assert_eq!(cache.mono(), CoarseMono::from_millis_since_start(0));
        cache.refresh(&ts);
        assert_eq!(cache.mono(), CoarseMono::from_millis_since_start(5_000));
    }

    #[test]
    fn cache_size_is_sixteen_bytes() {
        assert_eq!(size_of::<CoarseCache>(), 16);
    }

    #[test]
    fn cache_wall_is_frozen_between_refreshes() {
        let ts = TestTimeSource::new();
        let mut cache = CoarseCache::new(&ts);
        assert_eq!(
            cache.wall(),
            CoarseWall::from_unix_millis(1_600_000_000_000)
        );
        ts.advance_ms(5_000);
        assert_eq!(
            cache.wall(),
            CoarseWall::from_unix_millis(1_600_000_000_000)
        );
        cache.refresh(&ts);
        assert_eq!(
            cache.wall(),
            CoarseWall::from_unix_millis(1_600_000_005_000)
        );
    }

    #[test]
    fn atomic_cache_starts_unrefreshed_at_zero() {
        let cache = AtomicCoarseCache::new();
        assert_eq!(cache.mono(), CoarseMono::from_millis_since_start(0));
        assert_eq!(cache.wall(), CoarseWall::from_unix_millis(0));
    }

    #[test]
    fn atomic_cache_default_equals_new() {
        let d = AtomicCoarseCache::default();
        let n = AtomicCoarseCache::new();
        assert_eq!(d.mono(), n.mono());
        assert_eq!(d.wall(), n.wall());
    }

    #[test]
    fn atomic_cache_size_is_sixteen_bytes() {
        assert_eq!(size_of::<AtomicCoarseCache>(), 16);
    }

    #[test]
    fn atomic_cache_refresh_reads_both_clocks_once() {
        let ts = TestTimeSource::new();
        let cache = AtomicCoarseCache::new();
        cache.refresh(&ts);
        assert_eq!(cache.mono(), CoarseMono::from_millis_since_start(0));
        assert_eq!(
            cache.wall(),
            CoarseWall::from_unix_millis(1_600_000_000_000)
        );
    }

    #[test]
    fn atomic_cache_reads_are_frozen_between_refreshes() {
        let ts = TestTimeSource::new();
        let cache = AtomicCoarseCache::new();
        cache.refresh(&ts);
        ts.advance_ms(5_000);
        assert_eq!(cache.mono(), CoarseMono::from_millis_since_start(0));
        assert_eq!(
            cache.wall(),
            CoarseWall::from_unix_millis(1_600_000_000_000)
        );
    }

    // Targets a "stale value" mutant directly: a `refresh` that is a no-op, that
    // stores a constant, or that discards the new reading and keeps the old one
    // would still pass a test that only checks the FIRST refresh (any of those
    // mutants produces the right value once, by coincidence with `new`'s zeroed
    // start or the first real reading). Refreshing a second time to a third,
    // distinct value is what forces the mutant to actually track the clock.
    #[test]
    fn atomic_cache_refresh_updates_to_the_new_reading_not_the_old_one() {
        let ts = TestTimeSource::new();
        let cache = AtomicCoarseCache::new();
        cache.refresh(&ts);
        ts.advance_ms(1_234);
        cache.refresh(&ts);
        assert_eq!(cache.mono(), CoarseMono::from_millis_since_start(1_234));
        assert_eq!(
            cache.wall(),
            CoarseWall::from_unix_millis(1_600_000_001_234)
        );
        ts.advance_ms(6_000);
        cache.refresh(&ts);
        assert_eq!(cache.mono(), CoarseMono::from_millis_since_start(7_234));
        assert_eq!(
            cache.wall(),
            CoarseWall::from_unix_millis(1_600_000_007_234)
        );
    }

    #[test]
    fn atomic_cache_mono_wraps_exactly_like_the_underlying_clock() {
        let ts = TestTimeSource::new();
        let cache = AtomicCoarseCache::new();
        ts.advance_ms(u32::MAX);
        ts.advance_ms(2);
        cache.refresh(&ts);
        assert_eq!(cache.mono(), CoarseMono::from_millis_since_start(1));
    }

    // Targets a "goes backwards" mutant directly: this is constraint 1 from
    // issue #499, restated as a test. A cache that clamps a backward wall step
    // to the previous (larger) cached value, or that leaves the old value in
    // place instead of overwriting it, would look "more monotonic" than the
    // real clock, but it would hide the step from `elapsed_ms_since`, which
    // is the exact underflow-prevention property this cache must not undo.
    // The assertions below fail for any of those mutants: the first checks the
    // cache reports the smaller value exactly (not clamped, not stale), and
    // the second and third check that comparing two genuine cache readings
    // still tells backwards from forwards correctly, through the cache, the
    // same as it would reading straight from the clock.
    #[test]
    fn atomic_cache_reports_a_real_wall_backward_step_exactly() {
        let ts = TestTimeSource::new();
        let cache = AtomicCoarseCache::new();
        cache.refresh(&ts);
        let before = cache.wall();
        assert_eq!(before, CoarseWall::from_unix_millis(1_600_000_000_000));

        ts.set_wall_unix_millis(1_500_000_000_000);
        cache.refresh(&ts);
        let after = cache.wall();

        assert_eq!(after, CoarseWall::from_unix_millis(1_500_000_000_000));
        assert_eq!(after.elapsed_ms_since(before), None);
        assert_eq!(before.elapsed_ms_since(after), Some(100_000_000_000));
    }

    // Compile-time proof, exercised at runtime: `AtomicCoarseCache` is usable
    // exactly where `CoreCtx::now_mono`/`now_wall` (issue #13) need it, a
    // shared slot written by one thread and read by another with no
    // `TimeSource` in hand on the read side.
    #[test]
    fn atomic_cache_refresh_and_read_work_across_threads() {
        let ts = TestTimeSource::new();
        ts.advance_ms(42);
        let cache = AtomicCoarseCache::new();
        std::thread::scope(|scope| {
            scope.spawn(|| cache.refresh(&ts)).join().unwrap();
        });
        std::thread::scope(|scope| {
            let mono = scope.spawn(|| cache.mono()).join().unwrap();
            let wall = scope.spawn(|| cache.wall()).join().unwrap();
            assert_eq!(mono, CoarseMono::from_millis_since_start(42));
            assert_eq!(wall, CoarseWall::from_unix_millis(1_600_000_000_042));
        });
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn prop_atomic_cache_refresh_always_matches_the_source_exactly(
            advances in proptest::collection::vec(0u32..1_000_000, 1..20),
        ) {
            let ts = TestTimeSource::new();
            let cache = AtomicCoarseCache::new();
            for step in advances {
                ts.advance_ms(step);
                cache.refresh(&ts);
                assert_eq!(cache.mono(), ts.coarse_mono());
                assert_eq!(cache.wall(), ts.coarse_wall());
            }
        }
    }
}
