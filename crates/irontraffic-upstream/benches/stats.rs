// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "benchmark entry is not public API")]
//! Request-path microbenchmarks for the peak-EWMA codec and the two RAII
//! balances. The budgets these benchmarks are compared against by hand exist
//! so that the 25 ns P2C pick budget documented in
//! `crates/irontraffic-upstream/src/ewma.rs` is arithmetically reachable: two
//! `cost_key` calls at under 6 ns each plus the sampling arithmetic leaves
//! headroom for two cold `EndpointStats` lines.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_upstream::{CostCtx, EndpointStats, EwmaCfg, InflightGuard, exp_neg};

/// A tiny deterministic xorshift32 generator. This crate may not add a new
/// dependency, including `irontraffic-rand`, only to produce benchmark inputs,
/// and a benchmark's input spread does not need cryptographic quality, only
/// enough variation that the branch predictor and the compiler cannot
/// special-case a single repeated value.
fn xorshift32(state: &mut u32) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}

/// 1024 pseudo-random `x` values in `[0, 20]`.
fn exp_neg_inputs() -> Vec<f32> {
    let mut state = 0x9E37_79B9u32;
    (0..1024)
        .map(|_| {
            let bits = xorshift32(&mut state);
            #[allow(
                clippy::cast_precision_loss,
                reason = "a 32-bit pseudo-random value scaled into [0, 20] as a benchmark \
                          input spread; precision below f32's mantissa is immaterial here"
            )]
            let unit = (bits as f32) / (u32::MAX as f32);
            unit * 20.0
        })
        .collect()
}

fn bench_exp_neg(c: &mut Criterion) {
    let inputs = exp_neg_inputs();
    let mut cycle = inputs.iter().cycle();
    c.bench_function("stats/exp_neg", |b| {
        b.iter(|| {
            // `unwrap_or`, not indexing: `inputs` is a fixed non-empty `Vec`, so
            // `.cycle()` never actually yields `None`, but this avoids both a
            // panicking `[i % len]` index and an `.unwrap()` clippy denies here.
            let x = *cycle.next().unwrap_or(&0.0);
            black_box(exp_neg(black_box(x)))
        });
    });
}

fn bench_cost_key(c: &mut Criterion) {
    let stats = EndpointStats::default();
    stats.seed_cost_if_unset(10.0, 0);
    let cx = CostCtx {
        now_ms: 1_000,
        decay_ms: 10_000,
        default_rtt_ms: 1_000.0,
        max_requests: u32::MAX,
    };
    c.bench_function("stats/cost_key", |b| {
        b.iter(|| black_box(stats.cost_key(black_box(1.0), black_box(&cx))));
    });
}

fn bench_record_rtt_uncontended(c: &mut Criterion) {
    let stats = EndpointStats::default();
    let cfg = EwmaCfg::default();
    let mut now = 0u32;
    c.bench_function("stats/record_rtt_uncontended", |b| {
        b.iter(|| {
            now = now.wrapping_add(1);
            stats.record_rtt(black_box(10.0), black_box(now), black_box(&cfg));
        });
    });
}

fn bench_inflight_guard_acquire_drop(c: &mut Criterion) {
    let stats = EndpointStats::default();
    c.bench_function("stats/inflight_guard_acquire_drop", |b| {
        b.iter(|| {
            let g = InflightGuard::acquire(black_box(&stats));
            drop(g);
        });
    });
}

criterion_group!(
    benches,
    bench_exp_neg,
    bench_cost_key,
    bench_record_rtt_uncontended,
    bench_inflight_guard_acquire_drop
);
criterion_main!(benches);
