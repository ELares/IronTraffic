// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-worker cached coarse clocks, refreshed once per event loop turn.

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

#[cfg(test)]
mod tests {
    use core::mem::size_of;

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
}
