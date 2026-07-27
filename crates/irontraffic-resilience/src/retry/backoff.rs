// SPDX-License-Identifier: MIT OR Apache-2.0
//! Full-jitter exponential backoff and gRPC service-config backoff.
//!
//! The default retry shape is AWS Full Jitter:
//! `sleep = uniform(0, min(cap, base * 2^(attempt-1)))`.
//! It is deliberately not monotone in its returned values; jitter is the whole
//! point. The gRPC shape is honoured only when a gRPC service config specified
//! it.
//!
//! This module is pure, allocation-free, and performs no I/O.

use crate::config::{ConfigError, in_range_u32, ordered_u32};
use irontraffic_rand::Rng;

/// Backoff tuning for one route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BackoffConfig {
    /// Window for the first retry. Default 25.
    pub base_interval_ms: u32,
    /// Cap on the doubling window. Default 250.
    pub max_interval_ms: u32,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            base_interval_ms: 25,
            max_interval_ms: 250,
        }
    }
}

impl BackoffConfig {
    /// Validate against invariant 9 of `retry-backoff-full-jitter` (#103):
    /// rejects `base_interval_ms == 0`, `base_interval_ms > max_interval_ms`,
    /// and `max_interval_ms > 60_000`.
    ///
    /// # Errors
    /// Returns the first [`ConfigError`] found, naming the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        in_range_u32("base_interval_ms", self.base_interval_ms, 1, u32::MAX)?;
        ordered_u32(
            "base_interval_ms",
            self.base_interval_ms,
            "max_interval_ms",
            self.max_interval_ms,
        )?;
        in_range_u32("max_interval_ms", self.max_interval_ms, 0, 60_000)?;
        Ok(())
    }
}

/// AWS Full Jitter: `sleep = uniform(0, min(cap, base * 2^(attempt-1)))`.
///
/// The returned values are deliberately NOT monotone: jitter is the point. Equal
/// Jitter and Decorrelated Jitter are rejected, and so is gRPC's multiplicative
/// `random(0.8, 1.2)`, which blurs a synchronized herd rather than breaking it.
#[derive(Clone, Copy, Debug)]
pub struct FullJitterBackoff {
    base_ms: u32,
    cap_ms: u32,
    attempt: u32,
}

impl FullJitterBackoff {
    /// A fresh backoff at attempt 0.
    #[must_use]
    pub fn new(cfg: BackoffConfig) -> Self {
        Self {
            base_ms: cfg.base_interval_ms,
            cap_ms: cfg.max_interval_ms,
            attempt: 0,
        }
    }

    /// Advance the attempt counter and draw the next sleep, in milliseconds.
    ///
    /// Call exactly once per retry decision: calling it twice doubles the window.
    #[inline]
    pub fn next(&mut self, rng: &mut Rng) -> u32 {
        self.attempt = self.attempt.saturating_add(1);
        let window = self.window_for(self.attempt);
        // `window` is at most `cap_ms`, and `cap_ms <= 60_000`, so `window + 1`
        // cannot overflow. The draw is uniform on `[0, window]` inclusive.
        rng.bounded_u32(window.saturating_add(1))
    }

    /// The attempt counter, for metrics and tests.
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The window the NEXT call to `next` will draw from, without advancing.
    ///
    /// A fresh backoff has `attempt == 0`, so `peek_window_ms()` is
    /// `base_ms.min(cap_ms)`.
    #[must_use]
    pub fn peek_window_ms(&self) -> u32 {
        self.window_for(self.attempt.saturating_add(1))
    }

    /// The window for a given attempt number.
    #[inline]
    #[must_use]
    fn window_for(self, attempt: u32) -> u32 {
        let shift = attempt.saturating_sub(1).min(31);
        // `shift <= 31` and `base_ms` is `u32`, so the widened shift cannot wrap.
        let widened = u64::from(self.base_ms) << shift;
        u32::try_from(widened.min(u64::from(self.cap_ms))).unwrap_or(u32::MAX)
    }

    /// The configured base interval, in milliseconds.
    #[must_use]
    pub fn base_interval_ms(&self) -> u32 {
        self.base_ms
    }
}

/// gRPC service-config backoff parameters, honoured only when a gRPC service
/// config specified them. Our own default is full jitter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GrpcBackoffParams {
    /// `initialBackoff` in milliseconds.
    pub initial_backoff_ms: u32,
    /// `maxBackoff` in milliseconds.
    pub max_backoff_ms: u32,
    /// `backoffMultiplier` times 1000, so 1.6 is 1600. Integer so the sequence is
    /// reproducible across targets.
    pub backoff_multiplier_milli: u32,
}

impl GrpcBackoffParams {
    /// Validate against invariant 9 of `retry-backoff-full-jitter` (#103):
    /// rejects `initial_backoff_ms == 0`, `initial > max`,
    /// `max_backoff_ms > 600_000`, `backoff_multiplier_milli < 1_000`, and
    /// `backoff_multiplier_milli > 100_000`.
    ///
    /// # Errors
    /// Returns the first [`ConfigError`] found, naming the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        in_range_u32("initial_backoff_ms", self.initial_backoff_ms, 1, u32::MAX)?;
        ordered_u32(
            "initial_backoff_ms",
            self.initial_backoff_ms,
            "max_backoff_ms",
            self.max_backoff_ms,
        )?;
        in_range_u32("max_backoff_ms", self.max_backoff_ms, 0, 600_000)?;
        in_range_u32(
            "backoff_multiplier_milli",
            self.backoff_multiplier_milli,
            1_000,
            100_000,
        )?;
        Ok(())
    }
}

/// gRFC A6's backoff: `min(initial * multiplier^(n-1), max) * random(0.8, 1.2)`.
///
/// Used ONLY when a gRPC service config specified backoff parameters. Our own
/// default is full jitter.
#[must_use]
pub fn grpc_backoff_ms(params: &GrpcBackoffParams, attempt: u32, rng: &mut Rng) -> u32 {
    let max = u64::from(params.max_backoff_ms);
    let mut nominal = u64::from(params.initial_backoff_ms);
    for _ in 0..attempt.saturating_sub(1).min(31) {
        nominal = nominal
            .saturating_mul(u64::from(params.backoff_multiplier_milli))
            .saturating_div(1000);
        if nominal >= max {
            nominal = max;
            break;
        }
    }

    // Multiplicative jitter: factor in `[800, 1200]`, giving +/- 20 percent.
    let factor = 800 + u64::from(rng.bounded_u32(401));
    nominal = nominal.saturating_mul(factor).saturating_div(1000);

    u32::try_from(nominal).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::{ProptestConfig, proptest};

    #[test]
    fn default_config_values() {
        assert_eq!(
            BackoffConfig::default(),
            BackoffConfig {
                base_interval_ms: 25,
                max_interval_ms: 250,
            }
        );
    }

    #[test]
    fn validate_rejects_table() {
        let base = BackoffConfig::default();

        let err = BackoffConfig {
            base_interval_ms: 0,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "base_interval_ms");

        let err = BackoffConfig {
            base_interval_ms: 251,
            max_interval_ms: 250,
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "base_interval_ms");

        let err = BackoffConfig {
            max_interval_ms: 60_001,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "max_interval_ms");

        assert!(base.validate().is_ok());

        let grpc_base = GrpcBackoffParams {
            initial_backoff_ms: 100,
            max_backoff_ms: 1000,
            backoff_multiplier_milli: 1600,
        };

        let err = GrpcBackoffParams {
            initial_backoff_ms: 0,
            ..grpc_base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "initial_backoff_ms");

        let err = GrpcBackoffParams {
            initial_backoff_ms: 1001,
            ..grpc_base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "initial_backoff_ms");

        let err = GrpcBackoffParams {
            max_backoff_ms: 600_001,
            ..grpc_base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "max_backoff_ms");

        let err = GrpcBackoffParams {
            backoff_multiplier_milli: 999,
            ..grpc_base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "backoff_multiplier_milli");

        let err = GrpcBackoffParams {
            backoff_multiplier_milli: 100_001,
            ..grpc_base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "backoff_multiplier_milli");

        assert!(grpc_base.validate().is_ok());
    }

    #[test]
    fn window_sequence() {
        let cfg = BackoffConfig::default();
        let mut backoff = FullJitterBackoff::new(cfg);
        let expected = [25, 50, 100, 200, 250, 250];
        let mut actual = [0; 6];
        for slot in &mut actual {
            *slot = backoff.peek_window_ms();
            backoff.next(&mut Rng::from_seed(0xabc));
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn window_saturates_at_huge_attempt() {
        let cfg = BackoffConfig::default();
        let mut backoff = FullJitterBackoff::new(cfg);
        for _ in 0..40 {
            backoff.next(&mut Rng::from_seed(0xabc));
        }
        assert_eq!(backoff.peek_window_ms(), 250);
    }

    #[test]
    fn draw_within_window() {
        let cfg = BackoffConfig::default();
        let mut rng = Rng::from_seed(0xabc);
        for attempt in 1..=6 {
            let mut backoff = FullJitterBackoff::new(cfg);
            for _ in 0..attempt - 1 {
                backoff.next(&mut rng);
            }
            let window = backoff.peek_window_ms();
            for _ in 0..10_000 {
                let mut per_attempt_backoff = backoff;
                let v = per_attempt_backoff.next(&mut rng);
                assert!(v <= window, "attempt {attempt}: {v} > {window}");
            }
        }
    }

    #[test]
    #[allow(
        clippy::cast_precision_loss,
        reason = "sum of 100_000 draws each at most 250 fits exactly in f64"
    )]
    fn draw_mean_within_five_percent() {
        let cfg = BackoffConfig::default();
        let mut rng = Rng::from_seed(0xabc);
        let mut backoff = FullJitterBackoff::new(cfg);
        backoff.next(&mut rng);
        backoff.next(&mut rng);
        let window = backoff.peek_window_ms();
        assert_eq!(window, 100);
        let mut sum = 0u64;
        for _ in 0..100_000 {
            let mut b = backoff;
            sum += u64::from(b.next(&mut rng));
        }
        let mean = sum as f64 / 100_000.0;
        let expected = f64::from(window) / 2.0;
        let relative = (mean - expected).abs() / expected;
        assert!(
            relative <= 0.05,
            "mean {mean} is more than 5% from expected {expected}"
        );
    }

    #[test]
    fn draw_is_not_monotone() {
        let cfg = BackoffConfig {
            base_interval_ms: 100,
            max_interval_ms: 100,
        };
        let mut rng = Rng::from_seed(0xabc);
        let mut backoff = FullJitterBackoff::new(cfg);
        let mut prev = backoff.next(&mut rng);
        let mut saw_smaller = false;
        for _ in 0..999 {
            let mut b = backoff;
            let v = b.next(&mut rng);
            if v < prev {
                saw_smaller = true;
                break;
            }
            prev = v;
        }
        assert!(saw_smaller, "full jitter never drew smaller than previous");
    }

    #[test]
    fn grpc_backoff_attempt_one() {
        let params = GrpcBackoffParams {
            initial_backoff_ms: 100,
            max_backoff_ms: 1000,
            backoff_multiplier_milli: 1600,
        };
        let mut rng = Rng::from_seed(0xabc);
        let v = grpc_backoff_ms(&params, 1, &mut rng);
        assert!((80..=120).contains(&v), "attempt 1: {v}");
    }

    #[test]
    fn grpc_backoff_growth() {
        let params = GrpcBackoffParams {
            initial_backoff_ms: 100,
            max_backoff_ms: 1000,
            backoff_multiplier_milli: 1600,
        };
        let mut rng = Rng::from_seed(0xabc);
        let v = grpc_backoff_ms(&params, 3, &mut rng);
        // Nominal is 256; jittered range is [204, 307].
        assert!((204..=307).contains(&v), "attempt 3: {v}");
    }

    #[test]
    fn grpc_backoff_caps() {
        let params = GrpcBackoffParams {
            initial_backoff_ms: 100,
            max_backoff_ms: 1000,
            backoff_multiplier_milli: 1600,
        };
        let mut rng = Rng::from_seed(0xabc);
        let v = grpc_backoff_ms(&params, 20, &mut rng);
        assert!((800..=1200).contains(&v), "attempt 20: {v}");
    }

    #[test]
    fn grpc_backoff_multiplier_one() {
        let params = GrpcBackoffParams {
            initial_backoff_ms: 100,
            max_backoff_ms: 1000,
            backoff_multiplier_milli: 1000,
        };
        let mut rng = Rng::from_seed(0xabc);
        let v = grpc_backoff_ms(&params, 10, &mut rng);
        // Nominal stays 100; jittered range is [80, 120].
        assert!(
            (80..=120).contains(&v),
            "attempt 10 with multiplier 1.0: {v}"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]
        #[test]
        fn prop_next_in_window(
            base_interval_ms in 1u32..=250u32,
            max_interval_ms in 1u32..=250u32,
            seed: u64,
            extra_attempts in 0u32..=40u32,
        ) {
            let cfg = BackoffConfig {
                base_interval_ms,
                max_interval_ms: max_interval_ms.max(base_interval_ms),
            };
            let mut rng = Rng::from_seed(seed);
            let mut backoff = FullJitterBackoff::new(cfg);
            for _ in 0..extra_attempts {
                let window_before = backoff.peek_window_ms();
                let v = backoff.next(&mut rng);
                assert!(v <= window_before);
            }
        }
    }
}
