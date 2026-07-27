#![no_main]
//! Fuzz target for `outlier::robust_success_rate_threshold`.
//!
//! Input domain: `FuzzInput` derives `Arbitrary`, which for a `Vec<f32>`
//! consumes the fuzzer's raw bytes as `f32` bit patterns, so it naturally
//! covers `NaN` payloads (including signalling `NaN`s), infinities, and
//! denormals alongside ordinary values, with no domain restriction. The
//! vector is truncated to at most 512 entries. `k`, `mad_floor`,
//! `min_absolute_gap`, and `min_hosts` are likewise arbitrary and are first
//! passed through `RobustThresholdConfig::validate`; an invalid config is
//! skipped rather than exercised, matching the documented precondition that
//! `robust_success_rate_threshold` trusts a validated config not to produce
//! a `NaN` in its own arithmetic.
//!
//! Contract: must not panic, must not hang; when the result is `Some(t)`,
//! `t` is finite and lies in `[-1.0, 1.0]`. This is the target that proves
//! no `NaN` or out-of-range rate propagates into an ejection decision.

use arbitrary::Arbitrary;
use irontraffic_resilience::outlier::{RobustThresholdConfig, robust_success_rate_threshold};
use libfuzzer_sys::fuzz_target;

const MAX_RATES: usize = 512;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    rates: Vec<f32>,
    k: f32,
    mad_floor: f32,
    min_absolute_gap: f32,
    min_hosts: usize,
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|input: FuzzInput| {
    let mut rates = input.rates;
    rates.truncate(MAX_RATES);

    let cfg = RobustThresholdConfig {
        k: input.k,
        mad_floor: input.mad_floor,
        min_absolute_gap: input.min_absolute_gap,
        min_hosts: input.min_hosts,
    };
    if cfg.validate().is_err() {
        return;
    }

    let mut scratch = rates.clone();
    if let Some(t) = robust_success_rate_threshold(&mut rates, &mut scratch, &cfg) {
        assert!(t.is_finite());
        assert!((-1.0..=1.0).contains(&t));
    }
});
