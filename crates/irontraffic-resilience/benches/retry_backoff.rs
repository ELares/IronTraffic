// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! Retry backoff and pushback parser microbenchmarks.
//!
//! These are on the retry decision path, which is the failure path; the budgets
//! exist so that a retry storm's decision cost stays negligible relative to the
//! work it is avoiding.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_rand::Rng;
use irontraffic_resilience::clock::Millis;
use irontraffic_resilience::deadline::Deadline;
use irontraffic_resilience::retry::{
    BackoffConfig, BackoffInputs, FullJitterBackoff, parse_grpc_pushback, parse_retry_after,
    resolve_backoff,
};

const NOV_1994_MS: u64 = 784_111_777_000;

/// One full-jitter draw. Budget: under 5 ns.
fn bench_next(c: &mut Criterion) {
    let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
    let mut rng = Rng::from_seed(0xabc);
    c.bench_function("backoff/next", |b| {
        b.iter(|| black_box(backoff.next(&mut rng)));
    });
}

/// Parse a delta-seconds `Retry-After`. Budget: under 10 ns.
fn bench_parse_retry_after_delta(c: &mut Criterion) {
    c.bench_function("pushback/parse_retry_after_delta", |b| {
        b.iter(|| black_box(parse_retry_after(b"120", NOV_1994_MS)));
    });
}

/// Parse the 29-byte IMF-fixdate form. Budget: under 60 ns.
fn bench_parse_retry_after_imf(c: &mut Criterion) {
    c.bench_function("pushback/parse_retry_after_imf", |b| {
        b.iter(|| {
            black_box(parse_retry_after(
                b"Sun, 06 Nov 1994 08:49:37 GMT",
                NOV_1994_MS,
            ))
        });
    });
}

/// Parse a `grpc-retry-pushback-ms` value. Budget: under 10 ns.
fn bench_parse_grpc(c: &mut Criterion) {
    c.bench_function("pushback/parse_grpc", |b| {
        b.iter(|| black_box(parse_grpc_pushback(b"250")));
    });
}

/// The common path: no pushback, draw own backoff. Budget: under 15 ns.
fn bench_resolve_no_pushback(c: &mut Criterion) {
    let inputs = BackoffInputs {
        grpc_pushback: None,
        retry_after: None,
        deadline: Deadline::from_now(Millis(0), 10_000),
        now: Millis(0),
        now_wall_ms: NOV_1994_MS,
        min_attempt_estimate_ms: 0,
    };
    let backoff = FullJitterBackoff::new(BackoffConfig::default());
    let mut rng = Rng::from_seed(0xabc);
    c.bench_function("pushback/resolve_no_pushback", |b| {
        b.iter(|| {
            let mut per_iter_backoff = backoff;
            black_box(resolve_backoff(inputs, &mut per_iter_backoff, &mut rng));
        });
    });
}

criterion_group!(
    benches,
    bench_next,
    bench_parse_retry_after_delta,
    bench_parse_retry_after_imf,
    bench_parse_grpc,
    bench_resolve_no_pushback
);
criterion_main!(benches);
