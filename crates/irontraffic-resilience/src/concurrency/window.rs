// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`MonotonicMinDeque`], the exact sliding-window minimum the adaptive
//! concurrency controller's baseline is built from.

use std::collections::VecDeque;

/// Exact sliding-window minimum over the last `capacity` pushed values, in
/// `O(1)` amortized time and `O(capacity)` space.
///
/// Push back while popping any tail element greater than or equal to the new
/// value, and pop the front when it ages out. Exact, unlike an exponentially
/// decayed minimum, and free of drift, unlike a periodically reset minimum.
pub struct MonotonicMinDeque {
    /// `(value, sequence)` pairs, non-decreasing in value from front to back.
    buf: VecDeque<(u64, u64)>,
    seq: u64,
    capacity: usize,
}

impl MonotonicMinDeque {
    /// A deque retaining the minimum over the last `capacity` values.
    /// `capacity` of 0 is raised to 1.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            seq: 0,
            capacity: capacity.max(1),
        }
    }

    /// Push a value.
    ///
    /// 1. Advance the sequence counter (saturating, so it can never wrap back
    ///    into the live window).
    /// 2. Pop every back element whose value is greater than or equal to
    ///    `value`: it can never again be the minimum while `value` is still
    ///    in the window, so keeping it around would only waste space.
    /// 3. Push `(value, seq)`.
    /// 4. Pop the front while its sequence has aged out of the last
    ///    `capacity` pushes.
    ///
    /// Each value is pushed once and popped at most once, so this is `O(1)`
    /// amortized even though a single call can pop many elements.
    pub fn push(&mut self, value: u64) {
        self.seq = self.seq.saturating_add(1);
        while let Some(&(back_value, _)) = self.buf.back() {
            if back_value >= value {
                self.buf.pop_back();
            } else {
                break;
            }
        }
        self.buf.push_back((value, self.seq));

        // `usize` widens to a 64-bit unsigned value without truncation on every
        // platform this workspace targets (usize is at most 64 bits wide), matching
        // the precedent at irontraffic-resilience/src/limits/mod.rs's conversion of
        // a worker count for the same reason. This is a widening conversion, not a
        // narrowing one, so it falls outside the scope of the invariant lint that
        // flags narrowing integer conversions.
        let capacity_u64 = self.capacity as u64;
        let cutoff = self.seq.saturating_sub(capacity_u64);
        while let Some(&(_, front_seq)) = self.buf.front() {
            if front_seq <= cutoff {
                self.buf.pop_front();
            } else {
                break;
            }
        }
    }

    /// The minimum of the retained window, or `None` before the first push.
    #[must_use]
    pub fn min(&self) -> Option<u64> {
        self.buf.front().map(|&(v, _)| v)
    }

    /// Values pushed so far, saturating.
    #[must_use]
    pub fn pushes(&self) -> u64 {
        self.seq
    }

    /// Elements currently retained, which is at most `capacity`.
    #[must_use]
    pub fn retained(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::MonotonicMinDeque;

    /// Test 1: pushing 5, 3, 4 gives `min() == 3`.
    #[test]
    fn deque_min_basic() {
        let mut d = MonotonicMinDeque::new(10);
        d.push(5);
        d.push(3);
        d.push(4);
        assert_eq!(d.min(), Some(3));
    }

    /// Test 2: capacity 1; pushing 5 then 9 gives `min() == 9`.
    #[test]
    fn deque_capacity_one() {
        let mut d = MonotonicMinDeque::new(1);
        d.push(5);
        d.push(9);
        assert_eq!(d.min(), Some(9));
    }

    /// Test 3: capacity 0 behaves as capacity 1.
    #[test]
    fn deque_capacity_zero_raised() {
        let mut d = MonotonicMinDeque::new(0);
        d.push(5);
        d.push(9);
        assert_eq!(d.min(), Some(9));
        assert_eq!(d.retained(), 1);
    }

    /// Test 4: capacity 3; push 1, 5, 6, 7 gives `min() == 5` after the 1
    /// ages out.
    #[test]
    fn deque_ages_out() {
        let mut d = MonotonicMinDeque::new(3);
        d.push(1);
        d.push(5);
        d.push(6);
        d.push(7);
        assert_eq!(d.min(), Some(5));
    }

    /// Test 5: capacity 4; push 1, 2, 3, 4 gives `retained() == 4`.
    #[test]
    fn deque_increasing_retains_all() {
        let mut d = MonotonicMinDeque::new(4);
        d.push(1);
        d.push(2);
        d.push(3);
        d.push(4);
        assert_eq!(d.retained(), 4);
    }

    /// Test 6: capacity 4; push 4, 3, 2, 1 gives `retained() == 1` and
    /// `min() == 1`.
    #[test]
    fn deque_decreasing_retains_one() {
        let mut d = MonotonicMinDeque::new(4);
        d.push(4);
        d.push(3);
        d.push(2);
        d.push(1);
        assert_eq!(d.retained(), 1);
        assert_eq!(d.min(), Some(1));
    }

    /// Test 7: pushing 5 then 5 leaves `retained() == 1`, because the pop
    /// condition is `>=`.
    #[test]
    fn deque_equal_values_pop() {
        let mut d = MonotonicMinDeque::new(10);
        d.push(5);
        d.push(5);
        assert_eq!(d.retained(), 1);
    }

    /// `pushes()` counts every call, even ones whose value is immediately popped
    /// (back-popped for being non-decreasing, or later aged out of the front): it is
    /// a count of pushes, not of retained elements, and `retained()` alone (which
    /// this suite otherwise exercises for capacity, aging, and pop behaviour) cannot
    /// distinguish "3 values pushed, all popped but one" from "1 value pushed".
    #[test]
    fn deque_pushes_counts_every_push_not_retained_elements() {
        let mut d = MonotonicMinDeque::new(2);
        assert_eq!(d.pushes(), 0);
        d.push(5);
        assert_eq!(d.pushes(), 1);
        // Back-popped: 5 >= 3, so retained() stays 1, but pushes() still counts it.
        d.push(3);
        assert_eq!(d.pushes(), 2);
        assert_eq!(d.retained(), 1);
        // Ages the first entry out of a capacity-2 window.
        d.push(9);
        d.push(9);
        assert_eq!(d.pushes(), 4);
    }

    /// Test 8: `min().is_none()` before any push.
    #[test]
    fn deque_min_before_push() {
        let d = MonotonicMinDeque::new(10);
        assert!(d.min().is_none());
    }

    /// Test 9 (property test): for arbitrary capacities in `1..=64` and
    /// arbitrary `u64` sequences up to 500 long, `min()` equals a naive
    /// `O(n)` minimum over the last `capacity` pushes at every step.
    #[test]
    fn prop_deque_matches_naive() {
        proptest!(ProptestConfig::with_cases(64), |(
            capacity in 1usize..=64,
            values in prop::collection::vec(0u64..=1_000_000, 0..=500),
        )| {
            let mut d = MonotonicMinDeque::new(capacity);
            let mut history: Vec<u64> = Vec::new();
            for &v in &values {
                d.push(v);
                history.push(v);
                let window_start = history.len().saturating_sub(capacity);
                let naive = history[window_start..].iter().copied().min();
                prop_assert_eq!(d.min(), naive);
            }
        });
    }
}
