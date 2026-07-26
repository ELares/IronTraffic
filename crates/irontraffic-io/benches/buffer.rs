// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! Request-path microbenchmarks for the pooled buffer allocator.
//!
//! `buffer/acquire_release_hot` is gated on zero allocations across the whole
//! timed run (checked against `stats().allocations` before and after), because
//! that is the entire point of the pool: a hot acquire/release pair must never
//! reach the allocator. The other three are reported, not gated; state the
//! measured numbers and the machine when quoting this benchmark.

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_io::{PooledBuf, acquire, compact_exact, stats};
use std::hint::black_box;

/// Acquire and immediately drop, with the pool warm. Budget: under 20
/// nanoseconds per iteration on the reference machine, with zero allocations
/// across the whole run.
fn bench_acquire_release_hot(c: &mut Criterion) {
    // Warm the pool: one acquire/drop pair leaves one chunk in the free list,
    // so the timed loop below only ever pops and pushes that same chunk.
    drop(acquire());

    let allocations_before = stats().allocations;
    c.bench_function("buffer/acquire_release_hot", |b| {
        b.iter(|| {
            let buf = acquire();
            black_box(&buf);
            drop(buf);
        });
    });
    let allocations_after = stats().allocations;
    assert_eq!(
        allocations_before, allocations_after,
        "acquire_release_hot must not reach the allocator once the pool is warm"
    );
}

/// Acquire with an empty pool, which allocates and zeroes 32 KiB. Reported,
/// not gated: expect single-digit microseconds.
///
/// Every acquired buffer is held for the whole benchmark rather than dropped,
/// because dropping one would return its chunk to this thread's free list and
/// make the next iteration a warm hit instead of a cold miss.
fn bench_acquire_cold(c: &mut Criterion) {
    let mut held: Vec<PooledBuf> = Vec::new();
    c.bench_function("buffer/acquire_cold", |b| {
        b.iter(|| {
            held.push(black_box(acquire()));
        });
    });
    drop(held);
}

/// Compacting a 20-byte header value, the small end of the header compaction
/// range. Budget: under 60 nanoseconds.
fn bench_compact_exact_20b(c: &mut Criterion) {
    let data = vec![0xAB_u8; 20];
    c.bench_function("buffer/compact_exact_20b", |b| {
        b.iter(|| compact_exact(black_box(&data)));
    });
}

/// Compacting a 900-byte header value, the large end of the header compaction
/// range. Budget: under 200 nanoseconds.
fn bench_compact_exact_900b(c: &mut Criterion) {
    let data = vec![0xAB_u8; 900];
    c.bench_function("buffer/compact_exact_900b", |b| {
        b.iter(|| compact_exact(black_box(&data)));
    });
}

// `acquire_cold` holds every acquired chunk for the whole run (see above), so
// it gets its own group with a small sample size and a short measurement
// window: at 32 KiB per iteration, the default multi-second measurement
// window would hold gigabytes of chunks in memory for no extra precision.
criterion_group!(
    name = cold;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_millis(200));
    targets = bench_acquire_cold
);
criterion_group!(
    hot_and_compact,
    bench_acquire_release_hot,
    bench_compact_exact_20b,
    bench_compact_exact_900b
);
criterion_main!(cold, hot_and_compact);
