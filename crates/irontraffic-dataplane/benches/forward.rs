// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! Throughput and allocation benchmarks for the forwarding loop, run over the
//! in-memory `DuplexTransport` double (`test-support` feature) so the
//! measurement isolates the loop rather than the kernel.
//!
//! `forward/throughput_8mib` and `forward/idle_poll` are gated on zero pooled
//! buffer allocations across the whole timed run (checked against
//! `irontraffic_io::buffer::stats().allocations` before and after), the same
//! pattern `irontraffic-io`'s own `buffer.rs` benchmark uses.
//! `forward/small_writes_1kib` is reported, not gated: state the measured
//! numbers and the machine when quoting this benchmark.

use std::task::{Context, Waker};
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_dataplane::duplex::DuplexTransport;
use irontraffic_dataplane::{ForwardLimits, forward_bidirectional};
use irontraffic_io::{ShutdownController, SystemTimer, buffer};

const EIGHT_MIB: usize = 8 * 1024 * 1024;

fn generous_limits() -> ForwardLimits {
    ForwardLimits {
        idle: Duration::from_secs(60),
        half_close: Duration::from_secs(60),
        max_bytes_per_direction: None,
        max_lifetime: None,
    }
}

/// Forwards `payload` one direction (client to upstream) over an in-memory pair
/// and discards the outcome: the timed loop cares only about the work done, not
/// the result, and every input here is well-formed by construction.
async fn forward_one_direction(client: Vec<u8>) {
    let mut client = DuplexTransport::new(client);
    let mut upstream = DuplexTransport::new(Vec::new());
    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let _ = forward_bidirectional(
        &mut client,
        &mut upstream,
        &timer,
        &token,
        &generous_limits(),
    )
    .await;
}

/// 8 MiB one direction over an in-memory pair. Budget: at least 4 GiB per second
/// on the reference machine, and zero allocations after the first two buffer
/// acquisitions.
fn bench_throughput_8mib(c: &mut Criterion) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    let payload = vec![0xAB_u8; EIGHT_MIB];

    // Warm the pool with one real transfer before measuring allocations across
    // the whole timed run below.
    rt.block_on(forward_one_direction(payload.clone()));
    let allocations_before = buffer::stats().allocations;

    let mut group = c.benchmark_group("forward");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(
        u64::try_from(EIGHT_MIB).unwrap_or(u64::MAX),
    ));
    group.bench_function("throughput_8mib", |b| {
        b.iter_batched(
            || payload.clone(),
            |p| rt.block_on(forward_one_direction(p)),
            BatchSize::LargeInput,
        );
    });
    group.finish();

    let allocations_after = buffer::stats().allocations;
    assert_eq!(
        allocations_before, allocations_after,
        "throughput_8mib must not reach the allocator once the pool is warm"
    );
}

/// 8 MiB in 1 KiB read chunks, which measures the per-round overhead rather than
/// the copy. Reported, not gated.
fn bench_small_writes_1kib(c: &mut Criterion) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    let payload = vec![0xCD_u8; EIGHT_MIB];

    let mut group = c.benchmark_group("forward");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(
        u64::try_from(EIGHT_MIB).unwrap_or(u64::MAX),
    ));
    group.bench_function("small_writes_1kib", |b| {
        b.iter_batched(
            || payload.clone(),
            |p| {
                rt.block_on(async {
                    let mut client = DuplexTransport::new(p).with_read_cap(1024);
                    let mut upstream = DuplexTransport::new(Vec::new());
                    let (_controller, token) = ShutdownController::new();
                    let timer = SystemTimer::new();
                    let _ = forward_bidirectional(
                        &mut client,
                        &mut upstream,
                        &timer,
                        &token,
                        &generous_limits(),
                    )
                    .await;
                });
            },
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

/// Polls a connection with no data available, one million times over the
/// course of the run. Budget: under 100 nanoseconds per poll, and zero pool
/// allocations, which is what proves the release-on-`Pending` path is not
/// thrashing the pool.
fn bench_idle_poll(c: &mut Criterion) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    let _enter = rt.enter();

    let mut client = DuplexTransport::new(Vec::new()).never_closes();
    let mut upstream = DuplexTransport::new(Vec::new()).never_closes();
    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = generous_limits();

    let fut = forward_bidirectional(&mut client, &mut upstream, &timer, &token, &limits);
    let mut fut = std::pin::pin!(fut);

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let allocations_before = buffer::stats().allocations;
    c.bench_function("forward/idle_poll", |b| {
        b.iter(|| {
            // The connection never ends, so this always yields `Pending`; only
            // the cost of one round through the loop is being measured.
            let _ = std::future::Future::poll(fut.as_mut(), &mut cx);
        });
    });
    let allocations_after = buffer::stats().allocations;
    assert_eq!(
        allocations_before, allocations_after,
        "idle_poll must not thrash the buffer pool"
    );
}

criterion_group!(
    forward,
    bench_throughput_8mib,
    bench_small_writes_1kib,
    bench_idle_poll
);
criterion_main!(forward);
