// SPDX-License-Identifier: MIT OR Apache-2.0
//! Random helpers for the resilience subsystems.

use irontraffic_rand::Rng;

pub use irontraffic_rand::split_mix64;

/// Uniform integer in `[0, n)`, delegating to `irontraffic_rand::Rng::bounded_u32`.
///
/// Returns 0 when `n == 0` WITHOUT drawing from `rng`. Bias is at most `n / 2^32`.
/// Division-free and branch-free apart from the empty-range check, with no rejection
/// loop.
#[inline]
#[must_use]
pub fn below(rng: &mut Rng, n: u32) -> u32 {
    rng.bounded_u32(n)
}

/// Uniform integer in `[-span_ms, +span_ms]`.
///
/// Symmetric on purpose: an always-positive jitter biases the mean interval upward
/// and does not de-synchronize an already synchronized fleet. `span_ms` is clamped
/// to the maximum positive i32 value (stored in a `u32`) so the internal
/// `2 * span + 1` cannot wrap.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_wrap, reason = "result fits in i32")]
#[allow(clippy::cast_sign_loss, reason = "result fits in i32")]
pub fn symmetric_jitter_ms(rng: &mut Rng, span_ms: u32) -> i32 {
    let span_ms = span_ms.min(i32::MAX as u32); // it-allow: unchecked-cast reason: i32::MAX is positive and fits in u32
    if span_ms == 0 {
        return 0;
    }
    let u = below(rng, 2 * span_ms + 1);
    u.wrapping_sub(span_ms) as i32 // it-allow: unchecked-cast reason: the wrapping result is in [-span, +span], which fits i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::{ProptestConfig, proptest};

    #[test]
    fn below_zero_and_one() {
        let mut rng = Rng::from_seed(0x5EED);
        let before = rng.state();
        assert_eq!(below(&mut rng, 0), 0);
        assert_eq!(rng.state(), before);
        assert_eq!(below(&mut rng, 1), 0);
    }

    #[test]
    fn jitter_zero_span() {
        let mut rng = Rng::from_seed(0x5EED);
        let before = rng.state();
        assert_eq!(symmetric_jitter_ms(&mut rng, 0), 0);
        assert_eq!(rng.state(), before);
    }

    #[test]
    fn prop_below_in_range() {
        proptest!(
            ProptestConfig::default(),
            |(seed: u64, n in 1..=u32::MAX)| {
                let mut rng = Rng::from_seed(seed);
                assert!(below(&mut rng, n) < n);
            }
        );
    }

    #[test]
    fn prop_jitter_symmetric_bound() {
        proptest!(
            ProptestConfig::default(),
            |(seed: u64, span in 0..=1_000_000u32)| {
                let mut rng = Rng::from_seed(seed);
                let j = symmetric_jitter_ms(&mut rng, span);
                assert!(j.unsigned_abs() <= span);
            }
        );
    }

    #[test]
    fn prop_jitter_covers_both_signs() {
        let mut rng = Rng::from_seed(0x5EED);
        let span = 100;
        let mut negative = 0usize;
        let mut positive = 0usize;
        for _ in 0..10_000 {
            let j = symmetric_jitter_ms(&mut rng, span);
            if j < 0 {
                negative += 1;
            } else if j > 0 {
                positive += 1;
            }
        }
        assert!(negative >= 4_000, "got only {negative} negative draws");
        assert!(positive >= 4_000, "got only {positive} positive draws");
    }
}
