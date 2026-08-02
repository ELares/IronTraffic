// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! Sample recording and window update microbenchmarks for
//! [`GradientController`]. `record_sample` and `note_inflight` are on the
//! request path, once per upstream attempt; `maybe_close_window` runs from the
//! fast control tick, far more often than a window actually closes.
//!
//! [`GradientController`]: irontraffic_resilience::concurrency::GradientController

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_resilience::clock::{Micros, Millis};
use irontraffic_resilience::concurrency::{GradientConfig, GradientController, MonotonicMinDeque};
use irontraffic_resilience::limits::LeasedSemaphore;

/// `gradient/record_sample`: one histogram record. Budget: under 10 ns.
fn bench_record_sample(c: &mut Criterion) {
    let cfg = GradientConfig::default();
    let Ok(mut controller) = GradientController::new(Millis(0), cfg) else {
        return;
    };
    c.bench_function("gradient/record_sample", |b| {
        b.iter(|| controller.record_sample(black_box(Micros(1_234))));
    });
}

/// `gradient/note_inflight`: one `max`. Budget: under 2 ns.
fn bench_note_inflight(c: &mut Criterion) {
    let cfg = GradientConfig::default();
    let Ok(mut controller) = GradientController::new(Millis(0), cfg) else {
        return;
    };
    c.bench_function("gradient/note_inflight", |b| {
        b.iter(|| controller.note_inflight(black_box(42)));
    });
}

/// `gradient/maybe_close_window_not_due`: the early return before a window's time or
/// sample threshold is met. Budget: under 5 ns, because it is called far more often
/// than a window closes.
fn bench_maybe_close_window_not_due(c: &mut Criterion) {
    let cfg = GradientConfig::default();
    let Ok(mut controller) = GradientController::new(Millis(0), cfg) else {
        return;
    };
    let sem = LeasedSemaphore::new(1_000, 1, 1, 100);
    c.bench_function("gradient/maybe_close_window_not_due", |b| {
        b.iter(|| black_box(controller.maybe_close_window(black_box(Millis(1)), &sem)));
    });
}

/// `gradient/maybe_close_window_due`: a full window update including the quantile
/// computation. Budget: under 3 microseconds.
fn bench_maybe_close_window_due(c: &mut Criterion) {
    let cfg = GradientConfig::default();
    let sem = LeasedSemaphore::new(1_000_000, 1, 1, 100);
    c.bench_function("gradient/maybe_close_window_due", |b| {
        b.iter(|| {
            let Ok(mut controller) = GradientController::new(Millis(0), cfg) else {
                return None;
            };
            for _ in 0..cfg.window_min_samples {
                controller.record_sample(Micros(1_000));
            }
            controller.note_inflight(1_000_000);
            black_box(controller.maybe_close_window(Millis(cfg.window_min_ms), &sem))
        });
    });
}

/// `deque/push`, increasing case (worst space: every element retained). Budget:
/// under 20 ns.
fn bench_deque_push_increasing(c: &mut Criterion) {
    c.bench_function("deque/push_increasing", |b| {
        b.iter_batched(
            || MonotonicMinDeque::new(600),
            |mut deque| {
                for v in 0..600u64 {
                    deque.push(black_box(v));
                }
                black_box(&deque);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

/// `deque/push`, decreasing case (worst pop cascade, amortized `O(1)`). Budget:
/// under 20 ns.
fn bench_deque_push_decreasing(c: &mut Criterion) {
    c.bench_function("deque/push_decreasing", |b| {
        b.iter_batched(
            || MonotonicMinDeque::new(600),
            |mut deque| {
                for v in (0..600u64).rev() {
                    deque.push(black_box(v));
                }
                black_box(&deque);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_record_sample,
    bench_note_inflight,
    bench_maybe_close_window_not_due,
    bench_maybe_close_window_due,
    bench_deque_push_increasing,
    bench_deque_push_decreasing,
);
criterion_main!(benches);
