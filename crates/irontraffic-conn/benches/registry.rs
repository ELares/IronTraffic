// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! `ConnRegistry` microbenchmarks (issue #17).
//!
//! `registry/try_admit_uncontended` is gated by a budget stated in the issue: under
//! 25 nanoseconds per admit-and-drop pair on the reference machine, checked by a
//! human against the criterion HTML report. `registry/try_admit_8_threads` is
//! reported only, not gated, because contended throughput is machine dependent; its
//! purpose is to record that a single padded atomic is the contention point, as a
//! baseline for a later milestone that might propose sharding it.

use std::hint::black_box;
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_conn::ConnRegistry;

/// One admit-and-drop pair, uncontended on a single thread. Budget: under 25
/// nanoseconds (two atomic read-modify-writes).
fn bench_try_admit_uncontended(c: &mut Criterion) {
    let registry = ConnRegistry::new(1_000_000);
    c.bench_function("registry/try_admit_uncontended", |b| {
        b.iter(|| {
            let guard = ConnRegistry::try_admit(black_box(&registry));
            black_box(guard);
        });
    });
}

/// The same admit-and-drop pair with 8 threads contending on one registry.
/// Reported, not gated: the number is machine dependent, and the point of this
/// benchmark is to record that a single cache-padded atomic is the contention
/// point, not to enforce a budget on it.
#[allow(
    clippy::integer_division,
    reason = "splitting criterion's requested iteration count evenly across 8 fixed threads; \
              the remainder from the truncation is simply not run, which does not affect the \
              per-iteration timing this benchmark reports"
)]
fn bench_try_admit_8_threads(c: &mut Criterion) {
    let registry = ConnRegistry::new(1_000_000);
    c.bench_function("registry/try_admit_8_threads", |b| {
        b.iter_custom(|iters| {
            let per_thread = iters / 8;
            let start = std::time::Instant::now();
            std::thread::scope(|scope| {
                for _ in 0..8 {
                    let registry = Arc::clone(&registry);
                    scope.spawn(move || {
                        for _ in 0..per_thread {
                            let guard = ConnRegistry::try_admit(black_box(&registry));
                            black_box(guard);
                        }
                    });
                }
            });
            start.elapsed()
        });
    });
}

criterion_group!(
    registry,
    bench_try_admit_uncontended,
    bench_try_admit_8_threads
);
criterion_main!(registry);
