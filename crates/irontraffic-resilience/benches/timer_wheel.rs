// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "benchmark entry is not public API")]
//! Confirms or refutes the order-of-magnitude claim that motivated the timer
//! wheel: a `BinaryHeap` sift-down touches `log2(H)` scattered cache lines on
//! every reschedule, where the wheel touches a handful of stores into a list
//! it is already holding. See `crates/irontraffic-resilience/src/health/wheel.rs`.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_rand::Rng;
use irontraffic_resilience::clock::Millis;
use irontraffic_resilience::health::TimerWheel;
use irontraffic_resilience::rng::below;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Endpoint counts the benchmark sweeps over, chosen to match the health
/// checker's own scaling claims (H = 50,000 typical, H = 500,000 worst case).
const SIZES: [u32; 3] = [1_000, 50_000, 500_000];

/// A wheel with `h` ids already scheduled at random deadlines within one
/// 100-second interval, for benchmarks that measure a steady-state operation
/// against an already-populated wheel.
fn populated_wheel(h: u32) -> TimerWheel {
    let mut rng = Rng::from_seed(0x5EED);
    let mut wheel = TimerWheel::new(Millis(0), h as usize);
    for id in 0..h {
        let delay = below(&mut rng, 100_000);
        let _ = wheel.schedule(id, Millis(0).add_ms(delay));
    }
    wheel
}

/// `h` random deadlines within one 100-second interval, paired with their
/// would-be ids, generated once per batch so the timed routine only pays for
/// the `schedule` calls themselves.
fn random_deadlines(h: u32) -> Vec<(u32, Millis)> {
    let mut rng = Rng::from_seed(0x00C0_FFEE);
    (0..h)
        .map(|id| (id, Millis(0).add_ms(below(&mut rng, 100_000))))
        .collect()
}

fn bench_schedule_fresh(c: &mut Criterion) {
    let mut group = c.benchmark_group("wheel/schedule_fresh");
    for &h in &SIZES {
        group.throughput(Throughput::Elements(u64::from(h)));
        group.bench_function(format!("{h}"), |b| {
            b.iter_batched(
                || (TimerWheel::new(Millis(0), h as usize), random_deadlines(h)),
                |(mut wheel, deadlines)| {
                    for &(id, deadline) in &deadlines {
                        let _ = wheel
                            .schedule(std::hint::black_box(id), std::hint::black_box(deadline));
                    }
                    wheel
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_reschedule_steady(c: &mut Criterion) {
    let mut group = c.benchmark_group("wheel/reschedule_steady");
    for &h in &SIZES {
        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("{h}"), |b| {
            b.iter_batched(
                || populated_wheel(h),
                |mut wheel| {
                    let fresh = wheel.now().add_ms(12_345);
                    let _ = wheel.schedule(std::hint::black_box(0), std::hint::black_box(fresh));
                    wheel
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_advance_empty_slot(c: &mut Criterion) {
    let mut wheel = TimerWheel::new(Millis(0), 0);
    let mut out = Vec::new();
    c.bench_function("wheel/advance_1ms_empty_slot", |b| {
        b.iter(|| {
            let now = wheel.now().add_ms(1);
            let stats = wheel.advance(std::hint::black_box(now), &mut out);
            out.clear();
            std::hint::black_box(&stats);
        });
    });
}

fn bench_advance_with_cascade(c: &mut Criterion) {
    c.bench_function("wheel/advance_1ms_with_cascade", |b| {
        b.iter_batched(
            || {
                let mut wheel = TimerWheel::new(Millis(0), 64);
                let mut out = Vec::new();
                // Advance to one ms short of the level-1 cascade boundary,
                // then schedule 64 nodes into the level-1 slot that boundary
                // will cascade, without pushing them into `out`.
                let _ = wheel.advance(Millis(255), &mut out);
                for id in 0..64u32 {
                    let _ = wheel.schedule(id, Millis(300));
                }
                out.clear();
                (wheel, out)
            },
            |(mut wheel, mut out)| {
                let stats = wheel.advance(std::hint::black_box(Millis(256)), &mut out);
                std::hint::black_box(&stats);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_cancel(c: &mut Criterion) {
    let mut group = c.benchmark_group("wheel/cancel");
    for &h in &[1_000u32, 50_000u32] {
        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("{h}"), |b| {
            b.iter_batched(
                || populated_wheel(h),
                |mut wheel| {
                    let cancelled = wheel.cancel(std::hint::black_box(0));
                    std::hint::black_box(cancelled);
                    wheel
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

/// A `BinaryHeap` with lazy deletion: rescheduling pushes a fresh `(deadline,
/// id)` entry and leaves the stale one in place, to be discarded whenever a
/// pop eventually finds it. No comparison budget is asserted; this bar exists
/// so the wheel's advantage is a number in the repository rather than a claim.
fn heap_reschedule_steady(c: &mut Criterion) {
    let mut group = c.benchmark_group("heap_reference/reschedule_steady");
    for &h in &SIZES {
        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("{h}"), |b| {
            b.iter_batched(
                || {
                    let mut rng = Rng::from_seed(0x5EED);
                    let mut heap: BinaryHeap<Reverse<(u32, u32)>> = BinaryHeap::new();
                    for id in 0..h {
                        let delay = below(&mut rng, 100_000);
                        heap.push(Reverse((delay, id)));
                    }
                    heap
                },
                |mut heap: BinaryHeap<Reverse<(u32, u32)>>| {
                    heap.push(std::hint::black_box(Reverse((12_345, 0))));
                    heap
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_schedule_fresh,
    bench_reschedule_steady,
    bench_advance_empty_slot,
    bench_advance_with_cascade,
    bench_cancel,
    heap_reschedule_steady,
);
criterion_main!(benches);
