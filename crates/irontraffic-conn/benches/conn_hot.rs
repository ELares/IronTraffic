// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmark for `ConnBudget::on_frame`, the per-frame hot path
//! debited before any per-stream state is allocated. `harness = false` in
//! `Cargo.toml`: criterion supplies its own `main`, and a `[[bench]]` entry
//! without that flag runs under libtest instead and fails at startup.
//!
//! Budget (reference runner: GitHub Actions `ubuntu-latest`, 4 vCPU, release
//! profile with `lto = "thin"`, see `[profile.bench]` in the workspace
//! `Cargo.toml`): `on_frame` itself must complete in under 6 nanoseconds per
//! frame, and the overhead the accounting adds over a no-op comparison loop
//! must be under 2 percent of a 300 nanosecond frame-dispatch cost, that is,
//! under 6 nanoseconds. Criterion does not enforce either budget itself;
//! compare the reported time against them by hand.
//!
//! `ConnBudget` is a plain-integer-field struct with no heap-owning member,
//! so the zero-allocation property is structural rather than measured here:
//! it is checked by
//! `grep -nE "Vec::|String::|Box::|to_vec\(|format!" crates/irontraffic-conn/src/budget.rs`
//! returning nothing.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_conn::{ConnBudget, FrameEvent};
use std::hint::black_box;

/// A fixed rotation of frame events representative of ordinary multiplexed
/// traffic: mostly `Ordinary` frames with an occasional `HeadersOpen`,
/// `RstStreamReceived` and `Ping`, so the loop exercises every arm of
/// `cost_of`'s match rather than always taking the cheapest one.
const EVENTS: [FrameEvent; 8] = [
    FrameEvent::Ordinary,
    FrameEvent::Ordinary,
    FrameEvent::HeadersOpen,
    FrameEvent::Ordinary,
    FrameEvent::Ordinary,
    FrameEvent::RstStreamReceived,
    FrameEvent::Ordinary,
    FrameEvent::Ping,
];

/// A no-op stand-in with the same call shape as [`ConnBudget::on_frame`]: a
/// plain saturating subtraction on a bare counter, with no cost table and no
/// refill. The comparison loop built from this measures dispatch overhead
/// alone, so the DIFFERENCE between `budget_on` and `budget_off` below is the
/// accounting's true added cost.
fn no_budget_on_frame(counter: &mut i64, ev: FrameEvent) {
    let cost = if matches!(ev, FrameEvent::Ordinary) {
        1
    } else {
        2
    };
    *counter = counter.saturating_sub(cost);
}

fn bench_frame_debit(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_frame_debit");
    group.throughput(Throughput::Elements(1_000));

    group.bench_function("budget_on", |b| {
        b.iter(|| {
            let mut budget = ConnBudget::new(0);
            let mut now_ms = 0u32;
            for (i, &ev) in EVENTS.iter().cycle().take(1_000).enumerate() {
                if i % 64 == 0 {
                    now_ms = now_ms.wrapping_add(1);
                }
                let _ = black_box(budget.on_frame(black_box(ev), black_box(now_ms)));
            }
            black_box(budget.tokens())
        });
    });

    group.bench_function("budget_off", |b| {
        b.iter(|| {
            let mut counter = 10_000_i64;
            for (i, &ev) in EVENTS.iter().cycle().take(1_000).enumerate() {
                // `now_ms` plays no role in the no-op path; the branch below
                // mirrors the real loop's shape so both loops do the same
                // number of comparisons and branches, leaving only the
                // accounting itself as the measured difference.
                let _ = black_box(i % 64 == 0);
                no_budget_on_frame(&mut counter, black_box(ev));
            }
            black_box(counter)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_frame_debit);
criterion_main!(benches);
