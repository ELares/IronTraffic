// SPDX-License-Identifier: MIT OR Apache-2.0
//! The median-and-MAD robust success-rate ejection threshold.
//!
//! Envoy's `DetectorImpl::successRateEjectionThreshold` computes the
//! arithmetic mean of per-host success rates, then the population standard
//! deviation over the SAME set that contains the outlier, then
//! `threshold = mean - stdev_factor * stdev`. Both the mean and the standard
//! deviation have a zero percent breakdown point: a single arbitrarily bad
//! host can move them arbitrarily far, which is enough to mask a second bad
//! host and disable the whole detector. The `envoy_masking_regression` test
//! below proves this numerically.
//!
//! The median has a breakdown point that tends to 50 percent, so this module
//! computes the ejection threshold as `median(SR) - k * 1.4826 * MAD(SR)`
//! instead, where `MAD(SR)` is the median absolute deviation from the
//! median. Because more than half of a healthy pool commonly reports the
//! same success rate, `MAD` is frequently exactly zero, and a threshold of
//! exactly the median would flag roughly half the pool. When the scaled
//! `MAD` falls below a configured floor, this module falls back to
//! `median(SR) - min_absolute_gap` instead.
//!
//! A success rate is a division of two counters and can therefore be
//! non-finite or out of `[0, 1]` if a counter is corrupted. `f32` has no
//! total ordering trait, so every comparison here uses `f32::total_cmp`, a
//! total order that cannot panic, and every non-finite or out-of-range value
//! is dropped by [`compact_valid`] before it reaches a comparison.
//!
//! This module allocates nothing: every function that needs scratch space
//! takes it as a caller-owned `&mut [f32]`.

use crate::config::{ConfigError, in_range_f64};

/// The constant that makes `1.4826 * MAD` a consistent estimator of sigma
/// for normally distributed data. It is `1 / Phi^{-1}(3/4)`. Its purpose is
/// to make `k` interpretable in the same units as Envoy's
/// `success_rate_stdev_factor`, so an operator migrating from Envoy can
/// reason about it directly. Never change this to a "more precise" value:
/// doing so would silently change every operator's existing tuning.
pub const MAD_TO_SIGMA: f32 = 1.4826;

/// Tuning for the robust success-rate threshold.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct RobustThresholdConfig {
    /// Multiples of the robust sigma below the median at which an endpoint
    /// is an outlier. Default 3.0.
    pub k: f32,
    /// When `1.4826 * MAD` is below this, the `MAD` is treated as degenerate
    /// and the absolute-gap fallback is used instead. Default 0.01.
    pub mad_floor: f32,
    /// The fallback gap below the median, used when the `MAD` is
    /// degenerate. Default 0.05.
    pub min_absolute_gap: f32,
    /// Minimum number of endpoints with a valid rate before the detector
    /// will produce a threshold at all. Default 5.
    pub min_hosts: usize,
}

impl Default for RobustThresholdConfig {
    fn default() -> Self {
        Self {
            k: 3.0,
            mad_floor: 0.01,
            min_absolute_gap: 0.05,
            min_hosts: 5,
        }
    }
}

impl RobustThresholdConfig {
    /// Validate against invariant 8: rejects `k` that is not finite or
    /// outside `[0.0, 100.0]`; `mad_floor` that is not finite or outside
    /// `[0.0, 1.0]`; `min_absolute_gap` that is not finite or outside
    /// `[0.0, 1.0]`; and `min_hosts == 0`.
    ///
    /// The three `f32` fields are widened to `f64` for the range check:
    /// widening is exact and `is_finite` has the same answer in both
    /// widths, so no precision argument is needed. `min_hosts` is a `usize`
    /// and is checked directly rather than through a range helper.
    ///
    /// # Errors
    /// Returns the first [`ConfigError`] found, naming the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        in_range_f64("outlier.k", f64::from(self.k), 0.0, 100.0)?;
        in_range_f64("outlier.mad_floor", f64::from(self.mad_floor), 0.0, 1.0)?;
        in_range_f64(
            "outlier.min_absolute_gap",
            f64::from(self.min_absolute_gap),
            0.0,
            1.0,
        )?;
        if self.min_hosts == 0 {
            return Err(ConfigError::new(
                "outlier.min_hosts",
                "0",
                "must be at least 1",
            ));
        }
        Ok(())
    }
}

/// Move every finite value in `[0, 1]` to the front of `rates` and return
/// how many there are. Values after the returned length are unspecified.
///
/// Exists because a success rate is a division of two counters and can be
/// non-finite, and because `f32` has no total ordering trait, so sorting an
/// unfiltered slice by the fallible partial-order comparison either does not
/// compile or panics on a `NaN` input.
///
/// A negative zero passes the `[0, 1]` check (`-0.0 >= 0.0` is true in IEEE
/// 754) and is kept, behaving as `0.0`; this is deliberate, not an oversight.
#[must_use]
pub fn compact_valid(rates: &mut [f32]) -> usize {
    let len = rates.len();
    let mut write_idx = 0usize;
    for read_idx in 0..len {
        let Some(value) = rates.get(read_idx).copied() else {
            break;
        };
        if !(value.is_finite() && (0.0..=1.0).contains(&value)) {
            continue;
        }
        if let Some(dst) = rates.get_mut(write_idx) {
            *dst = value;
        }
        write_idx += 1;
    }
    write_idx
}

/// The LOWER median: the element at index `(len - 1) / 2` after selection.
///
/// Deliberately NOT the average of the two middle elements for an even
/// length. That average would need two selections instead of one, and it is
/// not exactly representable in `f32`, so the result would depend on
/// floating point rounding; the lower median needs one selection and its
/// value is always one of the inputs. The lower median's breakdown point is
/// `floor((n - 1) / 2) / n`, which tends to 50 percent as `n` grows, so the
/// robustness argument survives. Do not change this to an average.
///
/// Reorders `xs` in place using [`f32::total_cmp`], a total order that
/// cannot panic on a `NaN` input. Returns `None` for an empty slice.
#[must_use]
pub fn median_lower_in_place(xs: &mut [f32]) -> Option<f32> {
    if xs.is_empty() {
        return None;
    }
    #[allow(
        clippy::integer_division,
        reason = "the LOWER median is defined as index (len - 1) / 2 after \
                  selection; truncation toward zero is the documented \
                  choice, not an approximation of the average of the two \
                  middle elements for an even length"
    )]
    let mid = (xs.len() - 1) / 2;
    xs.select_nth_unstable_by(mid, f32::total_cmp);
    xs.get(mid).copied()
}

/// Median absolute deviation from `median`, computed into caller-owned
/// `scratch`.
///
/// `scratch` must be at least `xs.len()` long; a shorter one returns `None`
/// rather than panicking. Allocates nothing. Reorders both `xs` and the used
/// prefix of `scratch` in place.
#[must_use]
pub fn mad_in_place(xs: &mut [f32], median: f32, scratch: &mut [f32]) -> Option<f32> {
    if xs.is_empty() {
        return None;
    }
    let scratch = scratch.get_mut(..xs.len())?;
    for (dst, &value) in scratch.iter_mut().zip(xs.iter()) {
        *dst = (value - median).abs();
    }
    median_lower_in_place(scratch)
}

/// The success-rate ejection threshold: eject endpoint `h` when
/// `sr_h < threshold`.
///
/// Returns `None` when fewer than `cfg.min_hosts` valid rates are present
/// (this function applies only the host-count gate; the caller applies the
/// request-volume gate, because only the caller knows per-endpoint request
/// counts), or when `scratch` is shorter than the number of valid rates, in
/// which case the caller has passed too small a buffer and the detector
/// abstains rather than panicking.
///
/// Reorders `rates` in place and allocates nothing. The result is always
/// finite and always in `[-1.0, 1.0]`, and is never above the median: both
/// branches of the fallback subtract a quantity that is non-negative given a
/// validated `cfg`. A threshold below `0.0` can never eject anything, which
/// is the correct behaviour for a cluster whose dispersion genuinely is that
/// wide, or for a cluster that is uniformly unhealthy: a relative detector
/// cannot say anything useful about a fault every endpoint shares equally.
#[must_use]
pub fn robust_success_rate_threshold(
    rates: &mut [f32],
    scratch: &mut [f32],
    cfg: &RobustThresholdConfig,
) -> Option<f32> {
    let n = compact_valid(rates);
    if n < cfg.min_hosts {
        return None;
    }
    if scratch.len() < n {
        return None;
    }
    let xs = rates.get_mut(..n)?;
    let median = median_lower_in_place(xs)?;
    let mad = mad_in_place(xs, median, scratch)?;
    let sigma = MAD_TO_SIGMA * mad;
    let threshold = if sigma < cfg.mad_floor {
        median - cfg.min_absolute_gap
    } else {
        median - cfg.k * sigma
    };
    // `f32::clamp` does not rescue a `NaN`: it returns a `NaN` unchanged
    // when `self` is a `NaN`, which would make `sr_h < threshold` false for
    // every endpoint and silently disable the detector with no error
    // anywhere. This explicit gate cannot fire given a validated `cfg` and
    // inputs already compacted to `[0, 1]`, and it is written anyway
    // because it is the only thing that makes "always finite" true BY
    // CONSTRUCTION rather than by an argument a later change could
    // invalidate. Abstaining is the safe direction.
    if !threshold.is_finite() {
        return None;
    }
    Some(threshold.clamp(-1.0, 1.0))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Epsilon for every float comparison in this module's tests: `1e-6`.
    const EPS: f32 = 1e-6;

    fn assert_close(actual: f32, expected: f32) {
        assert!(
            (actual - expected).abs() < EPS,
            "expected {expected} within {EPS}, got {actual}"
        );
    }

    /// Success rates drawn from the domain this module actually operates
    /// on.
    fn clean_rate() -> impl Strategy<Value = f32> {
        0.0f32..=1.0
    }

    /// Any bit pattern a corrupted pair of counters could produce for a
    /// success rate: `NaN`, infinities, denormals, and values far outside
    /// `[0, 1]`, alongside ordinary valid rates.
    fn hostile_rate() -> impl Strategy<Value = f32> {
        any::<f32>()
    }

    // Test 1.
    #[test]
    fn default_config_values() {
        let cfg = RobustThresholdConfig::default();
        assert_close(cfg.k, 3.0);
        assert_close(cfg.mad_floor, 0.01);
        assert_close(cfg.min_absolute_gap, 0.05);
        assert_eq!(cfg.min_hosts, 5);
    }

    // Test 2: one row per clause of invariant 8, plus the boundary values
    // that must still validate.
    #[test]
    fn validate_rejects_table() {
        let base = RobustThresholdConfig::default();

        let mut c = base;
        c.k = f32::NAN;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.k"),
            Ok(()) => panic!("k = NaN must be rejected"),
        }

        let mut c = base;
        c.k = -1.0;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.k"),
            Ok(()) => panic!("k = -1.0 must be rejected"),
        }

        let mut c = base;
        c.k = 101.0;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.k"),
            Ok(()) => panic!("k = 101.0 must be rejected"),
        }

        let mut c = base;
        c.mad_floor = f32::INFINITY;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.mad_floor"),
            Ok(()) => panic!("mad_floor = INFINITY must be rejected"),
        }

        let mut c = base;
        c.mad_floor = -0.1;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.mad_floor"),
            Ok(()) => panic!("mad_floor = -0.1 must be rejected"),
        }

        let mut c = base;
        c.mad_floor = 1.5;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.mad_floor"),
            Ok(()) => panic!("mad_floor = 1.5 must be rejected"),
        }

        let mut c = base;
        c.min_absolute_gap = f32::NAN;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.min_absolute_gap"),
            Ok(()) => panic!("min_absolute_gap = NaN must be rejected"),
        }

        let mut c = base;
        c.min_absolute_gap = -0.1;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.min_absolute_gap"),
            Ok(()) => panic!("min_absolute_gap = -0.1 must be rejected"),
        }

        let mut c = base;
        c.min_absolute_gap = 1.5;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.min_absolute_gap"),
            Ok(()) => panic!("min_absolute_gap = 1.5 must be rejected"),
        }

        let mut c = base;
        c.min_hosts = 0;
        match c.validate() {
            Err(e) => assert_eq!(e.field, "outlier.min_hosts"),
            Ok(()) => panic!("min_hosts = 0 must be rejected"),
        }

        // The boundary values themselves must still validate: a rule
        // written as `>` that a mutation flips to `>=` would reject exactly
        // these.
        let mut c = base;
        c.k = 100.0;
        c.mad_floor = 1.0;
        c.min_absolute_gap = 1.0;
        c.min_hosts = 1;
        assert!(c.validate().is_ok());

        assert!(base.validate().is_ok());
    }

    // Test 3.
    #[test]
    fn compact_valid_filters() {
        let mut input = [0.5, f32::NAN, 1.0, f32::INFINITY, -0.5, 1.5, 0.0];
        let n = compact_valid(&mut input);
        assert_eq!(n, 3);
        assert_close(input[0], 0.5);
        assert_close(input[1], 1.0);
        assert_close(input[2], 0.0);
    }

    // Test 4.
    #[test]
    fn compact_valid_keeps_negative_zero() {
        let mut input = [-0.0f32, 0.5];
        let n = compact_valid(&mut input);
        assert_eq!(n, 2);
    }

    // Test 5.
    #[test]
    fn median_lower_odd() {
        let mut xs = [3.0, 1.0, 2.0];
        match median_lower_in_place(&mut xs) {
            Some(v) => assert_close(v, 2.0),
            None => panic!("median_lower_in_place must return Some for a non-empty slice"),
        }
    }

    // Test 6: pins the LOWER median choice. The average of the two middle
    // elements (2.0 and 3.0) would be 2.5.
    #[test]
    fn median_lower_even() {
        let mut xs = [1.0, 2.0, 3.0, 4.0];
        match median_lower_in_place(&mut xs) {
            Some(v) => assert_close(v, 2.0),
            None => panic!("median_lower_in_place must return Some for a non-empty slice"),
        }
    }

    // Test 7.
    #[test]
    fn median_empty() {
        let mut xs: [f32; 0] = [];
        assert_eq!(median_lower_in_place(&mut xs), None);
    }

    // Test 8.
    #[test]
    fn median_single() {
        let mut xs = [0.7];
        match median_lower_in_place(&mut xs) {
            Some(v) => assert_close(v, 0.7),
            None => panic!("median_lower_in_place must return Some for a single-element slice"),
        }
    }

    // Test 9.
    #[test]
    fn mad_all_identical() {
        let mut xs = [1.0; 5];
        let mut scratch = [0.0; 5];
        let Some(median) = median_lower_in_place(&mut xs) else {
            panic!("median_lower_in_place must return Some for a non-empty slice");
        };
        assert_close(median, 1.0);
        match mad_in_place(&mut xs, median, &mut scratch) {
            Some(m) => assert_close(m, 0.0),
            None => panic!("mad_in_place must return Some for a non-empty slice"),
        }
    }

    // Test 10.
    #[test]
    fn mad_symmetric() {
        let mut xs = [0.2, 0.4, 0.6, 0.8, 1.0];
        let mut scratch = [0.0; 5];
        let Some(median) = median_lower_in_place(&mut xs) else {
            panic!("median_lower_in_place must return Some for a non-empty slice");
        };
        assert_close(median, 0.6);
        match mad_in_place(&mut xs, median, &mut scratch) {
            Some(m) => assert_close(m, 0.2),
            None => panic!("mad_in_place must return Some for a non-empty slice"),
        }
    }

    // Test 11.
    #[test]
    fn mad_short_scratch() {
        let mut xs = [1.0, 2.0, 3.0, 4.0, 5.0];
        let mut scratch = [0.0; 2];
        assert_eq!(mad_in_place(&mut xs, 3.0, &mut scratch), None);
    }

    // Test 12.
    #[test]
    fn threshold_gated_by_min_hosts() {
        let cfg = RobustThresholdConfig::default();
        let mut scratch = [0.0; 5];

        let mut four = [1.0, 1.0, 1.0, 0.0];
        assert_eq!(
            robust_success_rate_threshold(&mut four, &mut scratch, &cfg),
            None
        );

        let mut five = [1.0, 1.0, 1.0, 1.0, 0.0];
        assert!(robust_success_rate_threshold(&mut five, &mut scratch, &cfg).is_some());
    }

    // Test 13.
    #[test]
    fn threshold_all_identical_uses_fallback() {
        let cfg = RobustThresholdConfig::default();
        let mut xs = [1.0; 8];
        let mut scratch = [0.0; 8];
        match robust_success_rate_threshold(&mut xs, &mut scratch, &cfg) {
            Some(t) => assert_close(t, 0.95),
            None => panic!("expected Some(0.95) for an all-identical healthy cluster"),
        }
    }

    // Test 14.
    #[test]
    fn threshold_zero_cluster() {
        let cfg = RobustThresholdConfig::default();
        let mut xs = [0.0; 8];
        let mut scratch = [0.0; 8];
        match robust_success_rate_threshold(&mut xs, &mut scratch, &cfg) {
            Some(t) => assert_close(t, -0.05),
            None => panic!("expected Some(-0.05) for an all-dead cluster"),
        }
    }

    // Test 15: the regression test that justifies the whole issue. The
    // mean-and-standard-deviation formula appears ONLY in this test, to
    // prove the correction.
    #[test]
    fn envoy_masking_regression() {
        #[allow(
            clippy::cast_precision_loss,
            reason = "n is the small fixed length of these regression \
                      fixtures (5), far below f32's 24-bit exact-integer \
                      range"
        )]
        fn envoy_threshold(rates: &[f32]) -> f32 {
            let n = rates.len() as f32;
            let mean: f32 = rates.iter().sum::<f32>() / n;
            let variance: f32 = rates.iter().map(|r| (r - mean) * (r - mean)).sum::<f32>() / n;
            mean - 1.9 * variance.sqrt()
        }

        let cfg = RobustThresholdConfig::default();
        let mut scratch = [0.0; 5];

        // Case 1: a single dead host among four healthy ones. Envoy's
        // formula still (barely) catches it.
        let mut single_dead = [1.0f32, 1.0, 1.0, 1.0, 0.0];
        let envoy_single = envoy_threshold(&single_dead);
        assert_close(envoy_single, 0.04);
        assert!(0.0 < envoy_single);
        let Some(ours_single) = robust_success_rate_threshold(&mut single_dead, &mut scratch, &cfg)
        else {
            panic!("expected Some for the single-dead-host case");
        };
        assert_close(ours_single, 0.95);
        assert!(0.0 < ours_single);

        // Case 2: the masking case. A second, half-broken host pulls
        // Envoy's threshold negative, so it flags nothing at all, while the
        // robust threshold is unaffected because the median has a 50
        // percent breakdown point.
        let mut masked = [1.0f32, 1.0, 1.0, 0.5, 0.0];
        let envoy_masked = envoy_threshold(&masked);
        assert_close(envoy_masked, -0.06);
        assert!(envoy_masked < 0.0);
        let Some(ours_masked) = robust_success_rate_threshold(&mut masked, &mut scratch, &cfg)
        else {
            panic!("expected Some for the masked case");
        };
        assert_close(ours_masked, 0.95);

        // Both degraded hosts (rate 0.0 and rate 0.5) are below OUR
        // threshold and at or above Envoy's masked threshold, i.e. not
        // flagged by it: Envoy's masked threshold is a known finite value
        // here (asserted above), so `>=` is the correct negation of `<`.
        assert!(0.0 < ours_masked);
        assert!(0.0 >= envoy_masked);
        assert!(0.5 < ours_masked);
        assert!(0.5 >= envoy_masked);
    }

    // Test 16.
    #[test]
    fn threshold_spread_cluster_abstains() {
        let cfg = RobustThresholdConfig::default();
        let mut xs = [0.2, 0.4, 0.6, 0.8, 1.0];
        let mut scratch = [0.0; 5];
        match robust_success_rate_threshold(&mut xs, &mut scratch, &cfg) {
            Some(t) => {
                assert!(
                    t < 0.0,
                    "expected a negative, abstaining threshold, got {t}"
                );
                // Pins the exact value from the design doc's worked example
                // (median 0.6, MAD 0.2, sigma 0.29652): a mutation of the
                // `cfg.k * sigma` multiplication into an addition or a
                // division would still land below zero here, so the bare
                // `t < 0.0` check above cannot tell them apart; this can.
                assert_close(t, -0.289_56);
            }
            None => panic!("expected Some for a five-host cluster"),
        }
    }

    // Test 17.
    #[test]
    fn threshold_clamped_low() {
        let cfg = RobustThresholdConfig {
            k: 100.0,
            ..RobustThresholdConfig::default()
        };
        let mut xs = [0.2, 0.4, 0.6, 0.8, 1.0];
        let mut scratch = [0.0; 5];
        match robust_success_rate_threshold(&mut xs, &mut scratch, &cfg) {
            Some(t) => assert_close(t, -1.0),
            None => panic!("expected Some"),
        }
    }

    // Test 18.
    #[test]
    fn threshold_never_above_median() {
        let cfg = RobustThresholdConfig::default();
        let inputs: [[f32; 5]; 6] = [
            [1.0, 1.0, 1.0, 1.0, 0.0],
            [1.0, 1.0, 1.0, 0.5, 0.0],
            [0.2, 0.4, 0.6, 0.8, 1.0],
            [0.0, 0.0, 0.0, 0.0, 0.0],
            [1.0, 1.0, 1.0, 1.0, 1.0],
            [0.9, 0.95, 0.2, 0.99, 0.91],
        ];
        for input in inputs {
            let mut for_median = input;
            let Some(median) = median_lower_in_place(&mut for_median) else {
                panic!("median_lower_in_place must return Some for a non-empty slice");
            };

            let mut for_threshold = input;
            let mut scratch = [0.0; 5];
            match robust_success_rate_threshold(&mut for_threshold, &mut scratch, &cfg) {
                Some(t) => assert!(t <= median, "threshold {t} exceeded median {median}"),
                None => panic!("expected Some for a five-host cluster"),
            }
        }
    }

    // Test 19.
    #[test]
    fn threshold_permutation_invariant() {
        let cfg = RobustThresholdConfig::default();
        let mut base = [1.0f32, 1.0, 0.9, 1.0, 0.2];
        let shuffles: [[f32; 5]; 3] = [
            [0.2, 1.0, 1.0, 0.9, 1.0],
            [1.0, 0.2, 1.0, 1.0, 0.9],
            [0.9, 1.0, 0.2, 1.0, 1.0],
        ];

        let mut scratch = [0.0; 5];
        let Some(base_threshold) = robust_success_rate_threshold(&mut base, &mut scratch, &cfg)
        else {
            panic!("expected Some for a five-host cluster");
        };

        for shuffle in shuffles {
            let mut xs = shuffle;
            match robust_success_rate_threshold(&mut xs, &mut scratch, &cfg) {
                Some(t) => assert_close(t, base_threshold),
                None => panic!("expected Some for a five-host cluster"),
            }
        }
    }

    // Test 20.
    #[test]
    fn threshold_short_scratch_none() {
        let cfg = RobustThresholdConfig::default();
        let mut xs = [1.0, 1.0, 1.0, 1.0, 0.0, 0.5, 0.6, 0.7];
        let mut scratch = [0.0; 4];
        assert_eq!(
            robust_success_rate_threshold(&mut xs, &mut scratch, &cfg),
            None
        );
    }

    // Test 20a: documents in an executable form why the explicit
    // `is_finite` gate in `robust_success_rate_threshold` exists and why
    // `clamp` is not a substitute for it.
    #[test]
    fn threshold_non_finite_abstains() {
        assert!(f32::NAN.clamp(-1.0, 1.0).is_nan());

        let cfg = RobustThresholdConfig {
            k: 100.0,
            ..RobustThresholdConfig::default()
        };
        let mut xs = [0.0, 0.0, 0.0, 1.0, 1.0, 1.0];
        let mut scratch = [0.0; 6];
        match robust_success_rate_threshold(&mut xs, &mut scratch, &cfg) {
            Some(t) => assert!(t.is_finite()),
            None => panic!("expected Some with a validated config"),
        }
    }

    // Not one of the 27 named tests: added because mutation testing found
    // that no named test pins the `sigma < cfg.mad_floor` branch condition
    // at EXACT equality, so a mutation from `<` to `<=` survived. `mad` is
    // built from values with power-of-two denominators (0.0, 0.25, 0.5,
    // 0.75, 1.0), so every subtraction the median absolute deviation needs
    // is exact in `f32`, and `mad_floor` is set to the SAME expression the
    // production code evaluates for `sigma`, so the two are bit-identical
    // rather than merely close. At exact equality, `sigma < mad_floor` must
    // be false, taking the `median - k * sigma` branch; a `<=` mutant would
    // wrongly take the fallback branch instead, giving a very different
    // result.
    #[test]
    fn threshold_mad_floor_exact_boundary_takes_sigma_branch() {
        let mad = 0.25f32;
        let sigma_boundary = MAD_TO_SIGMA * mad;
        let cfg = RobustThresholdConfig {
            mad_floor: sigma_boundary,
            ..RobustThresholdConfig::default()
        };
        let mut xs = [0.0f32, 0.25, 0.5, 0.75, 1.0];
        let mut scratch = [0.0; 5];

        let median = 0.5f32;
        let expected = median - cfg.k * sigma_boundary;

        match robust_success_rate_threshold(&mut xs, &mut scratch, &cfg) {
            Some(t) => assert_close(t, expected),
            None => panic!("expected Some for a five-host cluster"),
        }
    }

    // Test 21 (property test).
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_never_above_median(
            raw in prop::collection::vec(clean_rate(), 0..200),
        ) {
            let cfg = RobustThresholdConfig::default();
            let mut rates = raw.clone();
            let mut scratch = raw.clone();
            if let Some(t) = robust_success_rate_threshold(&mut rates, &mut scratch, &cfg) {
                let mut valid = raw;
                let n = compact_valid(&mut valid);
                valid.truncate(n);
                let Some(median) = median_lower_in_place(&mut valid) else {
                    panic!("a Some threshold implies at least one valid rate");
                };
                prop_assert!(t <= median);
            }
        }

        // Test 22.
        #[test]
        fn prop_permutation_invariant(
            raw in prop::collection::vec(clean_rate(), 0..64),
            swaps in prop::collection::vec((0usize..64, 0usize..64), 0..64),
        ) {
            let cfg = RobustThresholdConfig::default();

            let mut rates = raw.clone();
            let mut scratch = raw.clone();
            let base_result = robust_success_rate_threshold(&mut rates, &mut scratch, &cfg);

            let mut permuted = raw;
            let len = permuted.len();
            for (i, j) in swaps {
                if len == 0 {
                    continue;
                }
                permuted.swap(i % len, j % len);
            }
            let mut scratch2 = permuted.clone();
            let permuted_result = robust_success_rate_threshold(&mut permuted, &mut scratch2, &cfg);

            match (base_result, permuted_result) {
                (Some(a), Some(b)) => prop_assert!((a - b).abs() < EPS),
                (None, None) => {}
                _ => prop_assert!(false, "permutation changed whether a threshold was produced"),
            }
        }

        // Test 23: asserted on the MEDIAN, not on the threshold. The
        // threshold is NOT invariant under this operation, because the two
        // extra zero deviations can only lower the MAD (see invariant 5).
        #[test]
        fn prop_append_two_medians_invariant(
            raw in prop::collection::vec(clean_rate(), 1..64),
        ) {
            let mut xs = raw.clone();
            let Some(median) = median_lower_in_place(&mut xs) else {
                panic!("a non-empty generator must produce Some");
            };

            let mut extended = raw;
            extended.push(median);
            extended.push(median);
            let Some(median_after) = median_lower_in_place(&mut extended) else {
                panic!("a non-empty generator must produce Some");
            };

            prop_assert!((median - median_after).abs() < EPS);
        }

        // Test 24.
        #[test]
        fn prop_min_hosts_gate(
            raw in prop::collection::vec(hostile_rate(), 0..64),
            min_hosts in 1usize..=20,
            scratch_len in 0usize..64,
        ) {
            let cfg = RobustThresholdConfig {
                min_hosts,
                ..RobustThresholdConfig::default()
            };

            let mut valid_count_input = raw.clone();
            let valid_count = compact_valid(&mut valid_count_input);

            let mut rates = raw;
            let mut scratch: Vec<f32> = core::iter::repeat_n(0.0f32, scratch_len).collect();
            let result = robust_success_rate_threshold(&mut rates, &mut scratch, &cfg);

            let expect_none = valid_count < min_hosts || scratch_len < valid_count;
            prop_assert_eq!(result.is_none(), expect_none);
        }

        // Test 25.
        #[test]
        fn prop_finite_and_in_range(
            raw in prop::collection::vec(hostile_rate(), 0..128),
        ) {
            let cfg = RobustThresholdConfig::default();
            let mut rates = raw.clone();
            let mut scratch = raw;
            if let Some(t) = robust_success_rate_threshold(&mut rates, &mut scratch, &cfg) {
                prop_assert!(t.is_finite());
                prop_assert!((-1.0..=1.0).contains(&t));
            }
        }

        // Test 26.
        #[test]
        fn prop_pure(
            raw in prop::collection::vec(clean_rate(), 0..64),
        ) {
            let cfg = RobustThresholdConfig::default();

            let mut rates1 = raw.clone();
            let mut scratch1 = raw.clone();
            let result1 = robust_success_rate_threshold(&mut rates1, &mut scratch1, &cfg);

            let mut rates2 = raw.clone();
            let mut scratch2 = raw;
            let result2 = robust_success_rate_threshold(&mut rates2, &mut scratch2, &cfg);

            match (result1, result2) {
                (Some(a), Some(b)) => prop_assert!((a - b).abs() < EPS),
                (None, None) => {}
                _ => prop_assert!(
                    false,
                    "calling the function twice on identical fresh inputs must agree"
                ),
            }
        }
    }
}
