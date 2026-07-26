// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! Acquire/release microbenchmarks for [`LeasedSemaphore`], uncontended and
//! at 16 threads, plus the rejection path and the metrics-only `in_use`
//! call. `try_acquire` and `Permit::drop` are on the request path, once per
//! upstream attempt for `max_requests` and once per connection for
//! `max_connections`; `in_use` runs only on the control tick.
//!
//! [`LeasedSemaphore`]: irontraffic_resilience::limits::LeasedSemaphore

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_resilience::clock::Millis;
use irontraffic_resilience::limits::LeasedSemaphore;

const WORKERS: usize = 16;

/// `try_acquire` then drop, single thread, batched mode with a warm credit
/// cell. Budget: under 15 ns combined.
fn bench_uncontended_batched(c: &mut Criterion) {
    let sem = LeasedSemaphore::new(1_000_000, 1, 64, 100);
    // Warm the credit cell: one acquire/drop pair leaves 64 idle credits
    // behind, so the timed loop below never takes the slow (charging) path.
    drop(sem.try_acquire(0, Millis(0)));
    c.bench_function("limits/acquire_release/uncontended_batched", |b| {
        b.iter(|| {
            let p = sem.try_acquire(0, Millis(0));
            black_box(&p);
            drop(p);
        });
    });
}

/// The same in exact mode, so every acquisition CASes the shared line.
/// Budget: under 30 ns combined; the gap against the batched case above is
/// the measured value of batching.
fn bench_uncontended_exact(c: &mut Criterion) {
    let sem = LeasedSemaphore::new(1, 1, 1, 100);
    c.bench_function("limits/acquire_release/uncontended_exact", |b| {
        b.iter(|| {
            let p = sem.try_acquire(0, Millis(0));
            black_box(&p);
            drop(p);
        });
    });
}

/// 16 threads, each on its own worker index, acquiring and releasing in
/// batched mode. Budget: under 25 ns per operation, and within 2x of the
/// uncontended batched time.
fn bench_16_threads_batched(c: &mut Criterion) {
    let sem = Arc::new(LeasedSemaphore::new(100_000_000, WORKERS, 64, 100));
    c.bench_function("limits/acquire_release/16_threads_batched", |b| {
        b.iter_custom(|iters| {
            let per_thread = iters.div_ceil(WORKERS as u64).max(1);
            let start = Instant::now();
            std::thread::scope(|scope| {
                for w in 0..WORKERS {
                    let sem = Arc::clone(&sem);
                    scope.spawn(move || {
                        for _ in 0..per_thread {
                            let p = sem.try_acquire(w, Millis(0));
                            black_box(&p);
                            drop(p);
                        }
                    });
                }
            });
            start.elapsed()
        });
    });
}

/// 16 threads in exact mode. No budget; recorded so the contention cost of
/// exact mode is a number in the repository.
fn bench_16_threads_exact(c: &mut Criterion) {
    let sem = Arc::new(LeasedSemaphore::new(u32::from(u16::MAX), WORKERS, 1, 100));
    c.bench_function("limits/acquire_release/16_threads_exact", |b| {
        b.iter_custom(|iters| {
            let per_thread = iters.div_ceil(WORKERS as u64).max(1);
            let start = Instant::now();
            std::thread::scope(|scope| {
                for w in 0..WORKERS {
                    let sem = Arc::clone(&sem);
                    scope.spawn(move || {
                        for _ in 0..per_thread {
                            let p = sem.try_acquire(w, Millis(0));
                            black_box(&p);
                            drop(p);
                        }
                    });
                }
            });
            start.elapsed()
        });
    });
}

/// `try_acquire` on an exhausted semaphore. Budget: under 10 ns, because the
/// overload path must be cheaper than the success path.
fn bench_rejected(c: &mut Criterion) {
    let sem = LeasedSemaphore::new(1, 1, 1, 100);
    let held = sem.try_acquire(0, Millis(0));
    c.bench_function("limits/rejected", |b| {
        b.iter(|| black_box(sem.try_acquire(0, Millis(0))));
    });
    drop(held);
}

/// One `in_use()` call over 16 workers. Budget: under 100 ns. It runs on the
/// control tick, not per request.
fn bench_in_use_16_workers(c: &mut Criterion) {
    let sem = LeasedSemaphore::new(1_000_000, WORKERS, 64, 100);
    let mut held = Vec::new();
    for w in 0..WORKERS {
        held.push(sem.try_acquire(w, Millis(0)));
    }
    c.bench_function("limits/in_use/16_workers", |b| {
        b.iter(|| black_box(sem.in_use()));
    });
    drop(held);
}

criterion_group!(
    benches,
    bench_uncontended_batched,
    bench_uncontended_exact,
    bench_16_threads_batched,
    bench_16_threads_exact,
    bench_rejected,
    bench_in_use_16_workers
);
criterion_main!(benches);
