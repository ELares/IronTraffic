// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "benchmark entry is not public API")]
//! Request-path microbenchmarks for the resilience primitives.

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_rand::Rng;
use irontraffic_resilience::clock::Millis;
use irontraffic_resilience::pressure::SharedPressure;
use irontraffic_resilience::rng::{below, symmetric_jitter_ms};

fn bench_millis_since(c: &mut Criterion) {
    let a = Millis(1_000);
    let b = Millis(250);
    c.bench_function("clock/millis_since", |bench| {
        bench.iter(|| std::hint::black_box(a).since(std::hint::black_box(b)));
    });
}

fn bench_below_1000(c: &mut Criterion) {
    let mut rng = Rng::from_seed(0x5EED);
    c.bench_function("rng/below_1000", |bench| {
        bench.iter(|| below(std::hint::black_box(&mut rng), std::hint::black_box(1_000)));
    });
}

fn bench_symmetric_jitter_500(c: &mut Criterion) {
    let mut rng = Rng::from_seed(0x5EED);
    c.bench_function("rng/symmetric_jitter_500", |bench| {
        bench.iter(|| {
            symmetric_jitter_ms(std::hint::black_box(&mut rng), std::hint::black_box(500))
        });
    });
}

fn bench_pressure_get_bp(c: &mut Criterion) {
    let p = SharedPressure::new();
    c.bench_function("pressure/get_bp", |bench| {
        bench.iter(|| std::hint::black_box(&p).get_bp());
    });
}

criterion_group!(
    benches,
    bench_millis_since,
    bench_below_1000,
    bench_symmetric_jitter_500,
    bench_pressure_get_bp
);
criterion_main!(benches);
