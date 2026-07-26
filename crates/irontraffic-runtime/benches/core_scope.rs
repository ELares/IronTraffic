// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! Per-core seam microbenchmarks (issue #13).
//!
//! `core/with_empty`, `core/bump`, and `core/rand_u64` are reported, not gated
//! by an assertion in this file: the criterion HTML report is where the budgets
//! stated in the issue (under 3ns, 5ns, and 5ns respectively) are checked by a
//! human against the reference machine. `core/bump_fetch_add_baseline` is the
//! same increment written with `fetch_add` instead of the load-add-store
//! `CoreCtx::bump` uses, published purely for comparison: it is expected to be
//! roughly 4x slower, which is the number that justifies the load-add-store
//! choice over a `lock xadd` on the hottest path in the product.

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_runtime::{Counter, with};

/// The cost every consumer pays for the seam: one thread-local read, one
/// bounds-checked index, one closure call. Budget: under 3 nanoseconds.
fn bench_with_empty(c: &mut Criterion) {
    c.bench_function("core/with_empty", |b| {
        b.iter(|| with(|ctx| black_box(ctx.index())));
    });
}

/// A relaxed load-add-store counter increment. Budget: under 5 nanoseconds.
fn bench_bump(c: &mut Criterion) {
    c.bench_function("core/bump", |b| {
        b.iter(|| with(|ctx| ctx.bump(Counter::BytesToUpstream, 1)));
    });
}

/// The same increment written with `fetch_add` on a plain atomic, for
/// comparison only; not gated by an assertion here.
fn bench_bump_fetch_add_baseline(c: &mut Criterion) {
    let counter = AtomicU64::new(0);
    c.bench_function("core/bump_fetch_add_baseline", |b| {
        b.iter(|| counter.fetch_add(black_box(1), Ordering::Relaxed));
    });
}

/// A per-core `WyRand` draw: relaxed load, `wyrand_step`, relaxed store.
/// Budget: under 5 nanoseconds.
fn bench_rand_u64(c: &mut Criterion) {
    c.bench_function("core/rand_u64", |b| {
        b.iter(|| with(|ctx| black_box(ctx.rand_u64())));
    });
}

criterion_group!(
    core_scope,
    bench_with_empty,
    bench_bump,
    bench_bump_fetch_add_baseline,
    bench_rand_u64
);
criterion_main!(core_scope);
