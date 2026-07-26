// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "benchmark entry is not public API")]
//! Request-path microbenchmarks for deadline establishment, remaining-budget reads,
//! and header emission.

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_resilience::clock::Millis;
use irontraffic_resilience::deadline::headers::{emit_expected_rq_timeout_ms, emit_grpc_timeout};
use irontraffic_resilience::deadline::{Deadline, DeadlineConfig, InboundTimeouts, establish};

fn bench_remaining_ms(c: &mut Criterion) {
    let now = Millis(0);
    let deadline = Deadline::from_now(now, 30_000);
    let later = now.add_ms(1_000);
    c.bench_function("deadline/remaining_ms", |bench| {
        bench.iter(|| std::hint::black_box(deadline).remaining_ms(std::hint::black_box(later)));
    });
}

fn bench_establish_grpc(c: &mut Criterion) {
    let cfg = DeadlineConfig::default();
    let now = Millis(0);
    c.bench_function("deadline/establish_grpc", |bench| {
        bench.iter(|| {
            let inbound = InboundTimeouts {
                grpc_timeout: Some(std::hint::black_box(&b"250m"[..])),
                ..InboundTimeouts::default()
            };
            establish(
                std::hint::black_box(now),
                inbound,
                std::hint::black_box(5_000),
                std::hint::black_box(false),
                std::hint::black_box(&cfg),
            )
        });
    });
}

fn bench_emit_both_headers(c: &mut Criterion) {
    c.bench_function("deadline/emit_both_headers", |bench| {
        bench.iter(|| {
            let mut grpc_buf = [0u8; 12];
            let mut expected_buf = [0u8; 10];
            let grpc_len = emit_grpc_timeout(std::hint::black_box(4_500), &mut grpc_buf);
            let expected_len = emit_expected_rq_timeout_ms(
                std::hint::black_box(4_500),
                std::hint::black_box(4_500),
                &mut expected_buf,
            );
            std::hint::black_box((grpc_len, expected_len))
        });
    });
}

criterion_group!(
    benches,
    bench_remaining_ms,
    bench_establish_grpc,
    bench_emit_both_headers
);
criterion_main!(benches);
