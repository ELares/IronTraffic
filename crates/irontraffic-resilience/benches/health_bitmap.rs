// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "benchmark entry is not public API")]

//! Microbenchmarks for the two-bit-per-endpoint health bitmap and its weight array.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_resilience::health::{ClusterHealth, EndpointHealth, HealthBitmap};
use irontraffic_resilience::ids::EndpointIdx;

fn bench_get_16(c: &mut Criterion) {
    let b = HealthBitmap::new(16, EndpointHealth::Healthy);
    c.bench_function("bitmap/get/16", |bench| {
        bench.iter(|| black_box(&b).get(black_box(EndpointIdx(7))));
    });
}

fn bench_get_1024(c: &mut Criterion) {
    let b = HealthBitmap::new(1024, EndpointHealth::Healthy);
    c.bench_function("bitmap/get/1024", |bench| {
        bench.iter(|| black_box(&b).get(black_box(EndpointIdx(512))));
    });
}

fn bench_get_65536(c: &mut Criterion) {
    let b = HealthBitmap::new(65_536, EndpointHealth::Healthy);
    c.bench_function("bitmap/get/65536", |bench| {
        bench.iter(|| black_box(&b).get(black_box(EndpointIdx(32_768))));
    });
}

fn bench_get_four_candidates_1024(c: &mut Criterion) {
    let b = HealthBitmap::new(1024, EndpointHealth::Healthy);
    let base = 512;
    c.bench_function("bitmap/get_four_candidates/1024", |bench| {
        bench.iter(|| {
            let r0 = black_box(&b).get(black_box(EndpointIdx(base)));
            let r1 = black_box(&b).get(black_box(EndpointIdx(base + 1)));
            let r2 = black_box(&b).get(black_box(EndpointIdx(base + 2)));
            let r3 = black_box(&b).get(black_box(EndpointIdx(base + 3)));
            black_box((r0, r1, r2, r3));
        });
    });
}

fn bench_set_1024(c: &mut Criterion) {
    let b = HealthBitmap::new(1024, EndpointHealth::Healthy);
    c.bench_function("bitmap/set/1024", |bench| {
        bench.iter(|| {
            let _ = black_box(&b).set(black_box(EndpointIdx(512)), EndpointHealth::Unhealthy);
        });
    });
}

fn bench_weight_bp_1024(c: &mut Criterion) {
    let ch = ClusterHealth::new(1024, 0);
    c.bench_function("cluster/weight_bp/1024", |bench| {
        bench.iter(|| {
            let r = black_box(&ch).weight_bp(black_box(EndpointIdx(512)));
            black_box(r);
        });
    });
}

criterion_group!(
    benches,
    bench_get_16,
    bench_get_1024,
    bench_get_65536,
    bench_get_four_candidates_1024,
    bench_set_1024,
    bench_weight_bp_1024
);
criterion_main!(benches);
