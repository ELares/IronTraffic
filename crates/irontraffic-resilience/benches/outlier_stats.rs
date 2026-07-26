// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "benchmark entry is not public API")]
//! Control-tick microbenchmarks for the median-and-MAD robust success-rate
//! threshold. This runs once per cluster per 10-second control tick, never
//! on the request path; the budget noted on each benchmark is a sanity
//! check against an accidentally quadratic algorithm, not a hot-path
//! requirement.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use irontraffic_resilience::outlier::{
    RobustThresholdConfig, median_lower_in_place, robust_success_rate_threshold,
};

/// A deterministic, reproducible input of `n` success rates spanning
/// `[0, 1]`, so the benchmark input is identical across runs.
#[allow(
    clippy::cast_precision_loss,
    reason = "n is a benchmark size (8, 64, or 1024), far below f32's \
              24-bit exact-integer range"
)]
fn sample_rates(n: usize) -> Vec<f32> {
    let denom = (n.max(1)) as f32;
    (0..n).map(|i| (i as f32) / denom).collect()
}

/// `outlier/threshold/{8, 64, 1024}`: the full
/// `robust_success_rate_threshold` over a freshly cloned input of each
/// size. Budget: under 5 microseconds at `u = 1024`.
fn bench_threshold(c: &mut Criterion) {
    let cfg = RobustThresholdConfig::default();
    for n in [8usize, 64, 1024] {
        let base = sample_rates(n);
        c.bench_function(&format!("outlier/threshold/{n}"), |b| {
            b.iter_batched(
                || (base.clone(), base.clone()),
                |(mut rates, mut scratch)| {
                    std::hint::black_box(robust_success_rate_threshold(
                        std::hint::black_box(&mut rates),
                        &mut scratch,
                        std::hint::black_box(&cfg),
                    ))
                },
                BatchSize::SmallInput,
            );
        });
    }
}

/// `outlier/median/{64, 1024}`: `median_lower_in_place` alone, for
/// comparison against the full threshold computation above.
fn bench_median(c: &mut Criterion) {
    for n in [64usize, 1024] {
        let base = sample_rates(n);
        c.bench_function(&format!("outlier/median/{n}"), |b| {
            b.iter_batched(
                || base.clone(),
                |mut xs| std::hint::black_box(median_lower_in_place(std::hint::black_box(&mut xs))),
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, bench_threshold, bench_median);
criterion_main!(benches);
