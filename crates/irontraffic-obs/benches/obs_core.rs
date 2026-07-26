// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! Core primitive microbenchmarks (issue #159).
//!
//! `obs/cell_add_local`, `obs/render_u64`, and `obs/cached_wall_hit` are checked by a
//! human against the reference machine against the issue's stated budgets (under 4ns,
//! 12ns, and 3ns respectively). `obs/cell_fetch_add_baseline` and
//! `obs/cached_wall_miss` are reported only, not gated by an assertion in this file:
//! the first publishes the ratio a `lock xadd` costs over the load-add-store
//! `Cell64::add_local` uses (expected 3x to 5x), and the second runs once per second
//! per writer thread in real use, so it has no per-call budget to check.

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_obs::{CachedWall, Cell64, Shards, render_u64};
use irontraffic_time::{TestTimeSource, TimeSource as _};

/// The cost every consumer pays for a counter increment: one thread-local read, one
/// bounds-checked index, one relaxed load-add-store. Budget: under 4 nanoseconds.
fn bench_cell_add_local(c: &mut Criterion) {
    let shards: Shards<Cell64> = Shards::new(1, |_| Cell64::new(0));
    c.bench_function("obs/cell_add_local", |b| {
        b.iter(|| shards.with_current(|cell| cell.add_local(1)));
    });
}

/// The same increment written as `fetch_add` on a plain atomic, for comparison only;
/// not gated by an assertion here.
fn bench_cell_fetch_add_baseline(c: &mut Criterion) {
    let counter = AtomicU64::new(0);
    c.bench_function("obs/cell_fetch_add_baseline", |b| {
        b.iter(|| counter.fetch_add(black_box(1), Ordering::Relaxed));
    });
}

/// Rendering a 6 digit value into a reused `Vec`. Budget: under 12 nanoseconds.
fn bench_render_u64(c: &mut Criterion) {
    let mut out = Vec::with_capacity(20);
    c.bench_function("obs/render_u64", |b| {
        b.iter(|| {
            out.clear();
            render_u64(black_box(123_456), &mut out);
        });
    });
}

/// `CachedWall::refresh` when the whole second is unchanged. Budget: under 3
/// nanoseconds.
fn bench_cached_wall_hit(c: &mut Criterion) {
    let ts = TestTimeSource::new();
    let mut wall = CachedWall::new();
    wall.refresh(ts.coarse_wall());
    c.bench_function("obs/cached_wall_hit", |b| {
        b.iter(|| black_box(wall.refresh(ts.coarse_wall())));
    });
}

/// `CachedWall::refresh` when the whole second changed. Reported only: in real use
/// this runs once per second per writer thread, so it has no per-call budget.
fn bench_cached_wall_miss(c: &mut Criterion) {
    let ts = TestTimeSource::new();
    let mut wall = CachedWall::new();
    c.bench_function("obs/cached_wall_miss", |b| {
        b.iter(|| {
            ts.advance_ms(1_000);
            black_box(wall.refresh(ts.coarse_wall()));
        });
    });
}

criterion_group!(
    obs_core,
    bench_cell_add_local,
    bench_cell_fetch_add_baseline,
    bench_render_u64,
    bench_cached_wall_hit,
    bench_cached_wall_miss
);
criterion_main!(obs_core);
