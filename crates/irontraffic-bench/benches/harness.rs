// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! `LatencyRecorder`'s own cost on the measurement path: `record_ns` runs
//! inside the probe client's request loop, so a regression here silently
//! changes every latency number the harness reports rather than failing an
//! obviously-attributable test. `merge` and `percentiles` run once per run,
//! not per request, so their budgets are informational rather than gates.
//!
//! Budgets: `record_ns/in_range` under 25 nanoseconds; `record_ns/out_of_range`
//! under 10 nanoseconds (the branch must be cheaper than the record it
//! replaces); `merge/two_full` and `percentiles/query` under 200 microseconds
//! each (one pass over the 27,648 slot counts array), informational only.
//!
//! Measured on an Apple M4 Pro (macOS, `aarch64`, debug assertions off,
//! `cargo bench`, criterion 0.8): `record_ns/in_range` ~2.08 ns,
//! `record_ns/out_of_range` ~0.72 ns, `merge/two_full` ~8.99 us,
//! `percentiles/query` ~35.0 us. All four pass with headroom on this machine;
//! re-measure on the project's actual benchmark host before trusting these as
//! the reference numbers, per the Benchmarks section of issue #405.
//!
//! `schedule/due_ns`, `schedule/releasable_at/steady` and
//! `schedule/releasable_at/after_1s_stall` (issue #406) measure
//! [`Schedule`]'s two hot-path operations. Budgets: `schedule/due_ns` under
//! 25 nanoseconds (a multiply, an add and a 128-bit divide by a runtime
//! divisor, which lowers to a `__udivti3` call rather than a single
//! instruction: that call, not the arithmetic, is the cost, so this is not
//! budgeted as if it were a 64-bit divide). `schedule/releasable_at/steady`
//! under 50 nanoseconds (two of the divides above; this runs once per
//! released request in the probe client, so it is on the measurement path).
//! `schedule/releasable_at/after_1s_stall` under 100 nanoseconds, the same
//! cost as the steady call: this is the assertion that catch-up entitlement
//! is closed form and not a loop (a loop implementation would iterate
//! 1,000,000 times at the `R = 1,000,000` this benchmark uses, roughly four
//! orders of magnitude over this budget), so this benchmark is also the
//! regression test for that algorithmic choice.
//!
//! Measured on an Apple M4 Pro (macOS, `aarch64`, debug assertions off,
//! `cargo bench`, criterion 0.8): `schedule/due_ns` ~1.67 ns,
//! `schedule/releasable_at/steady` ~6.43 ns,
//! `schedule/releasable_at/after_1s_stall` ~3.94 ns. All three pass with
//! headroom on this machine; re-measure on the project's actual benchmark
//! host before trusting these as the reference numbers.
//!
//! `probe/request_bytes_build`, `probe/scan_response/1kb` and
//! `probe/wait_until/1ms` (issue #410) measure the probe's own per-request
//! cost, which must not contaminate the measurement it exists to take.
//! Budgets: `probe/request_bytes_build` under 2 microseconds, informational
//! (runs once per probe, not per request). `probe/scan_response/1kb` under
//! 300 nanoseconds (runs once per probe request, on the measurement path).
//! `probe/wait_until/1ms` reports the DEADLINE OVERSHOOT, not the wall time
//! `b.iter_custom` timed: median overshoot under 30 microseconds, p99
//! overshoot under 200 microseconds. An overshoot larger than this is added
//! to every probe sample as a constant bias, so it is the probe's own
//! accuracy floor and belongs in the methodology document.
//!
//! Measured in a sandboxed macOS container (NOT the project's dedicated,
//! isolated benchmark host; see the AWS c7g recipe posted on issue #284),
//! `cargo bench`, criterion 0.8: `probe/request_bytes_build` ~5.8 ns (well
//! under budget). `probe/scan_response/1kb` ~190 to 400 ns across repeated
//! runs, over budget in some runs, matching the budget in others: this
//! module has no authorization to add `memchr`, and the SWAR-based
//! `find_byte` below is the fastest portable, `unsafe`-free substitute
//! found; it lands close to the 300 ns line rather than comfortably under
//! it, and it should be re-measured on the real, isolated benchmark host
//! before trusting either direction. `probe/wait_until/1ms` median overshoot
//! ranged from about 5.7 us to over 200 us across repeated runs on this
//! shared, virtualised host: a `park_timeout` wakeup's own scheduling jitter
//! is exactly what a shared or virtualised CPU adds, and the 30 us / 200 us
//! budget describes a thread genuinely pinned to its own core on real
//! hardware, which this sandbox cannot provide (`core_affinity` itself is
//! unauthoritative here for the same reason). NONE of the three numbers
//! above should be trusted as the reference measurement; re-measure all
//! three on the project's actual, isolated benchmark host, per the
//! Benchmarks section, before publishing them anywhere else.

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_bench::{
    HIGH_NS, LatencyRecorder, MAX_REQUEST_BYTES, ScanOutcome, Schedule, build_request,
    scan_response_head, wait_until,
};
use irontraffic_time::{SharedTime, SystemTimeSource};
use std::hint::black_box;
use std::sync::Arc;

/// Deterministic pseudo-random sequence generator (`SplitMix64`), used only to
/// build fixed benchmark fixtures. Not a production entropy source: this
/// file is under `benches/`, excluded from the request path and from the
/// `determinism-seam` invariant lint's production scan by construction (see
/// `scripts/invariant-lints.sh`'s `rust_non_test_files`).
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// 4,096 fixed pseudo-random in-range nanosecond values, `1..=HIGH_NS`.
fn in_range_sequence() -> Vec<u64> {
    let mut rng = SplitMix64(0x5EED_5EED_5EED_5EED);
    (0..4096).map(|_| 1 + rng.next() % HIGH_NS).collect()
}

/// 4,096 fixed pseudo-random out-of-range nanosecond values, strictly above
/// `HIGH_NS`.
fn out_of_range_sequence() -> Vec<u64> {
    let mut rng = SplitMix64(0x0BAD_0BAD_0BAD_0BAD);
    (0..4096)
        .map(|_| HIGH_NS + 1 + rng.next() % HIGH_NS)
        .collect()
}

/// `values[i % values.len()]`, without the `indexing_slicing` lint: `values`
/// is always non-empty (both callers pass a fixed, non-empty 4,096 element
/// sequence), so the fallback is never actually reached.
#[allow(
    clippy::indexing_slicing,
    reason = "cyclic access into a fixed non-empty benchmark fixture, not a request-path slice"
)]
fn cyclic(values: &[u64], i: usize) -> u64 {
    values.get(i % values.len()).copied().unwrap_or(1)
}

/// A fully populated recorder: the in-range sequence recorded 256 times over
/// (1,048,576 samples), so `merge` and `percentiles` measure a counts array
/// with real, spread-out occupancy rather than an all-but-empty one.
#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: LOW_NS/HIGH_NS/SIGNIFICANT_DIGITS \
              are the crate's own fixed, valid constants, so construction cannot fail"
)]
fn full_recorder() -> LatencyRecorder {
    let mut r = LatencyRecorder::new().expect("fixed configuration always constructs");
    let values = in_range_sequence();
    for _ in 0..256 {
        for &v in &values {
            r.record_ns(v);
        }
    }
    r
}

// Each criterion "iteration" below is exactly one `record_ns` call against a
// recorder built ONCE outside the timed closure, so criterion's reported
// per-iteration time IS the per-record budget the issue names, with no
// manual division. The value recorded cycles through the fixed pseudorandom
// sequence (rather than repeating one value) so the measurement is not just
// the cost of re-touching a single counts-array slot.
#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: LOW_NS/HIGH_NS/SIGNIFICANT_DIGITS \
              are the crate's own fixed, valid constants, so construction cannot fail"
)]
fn bench_record_ns_in_range(c: &mut Criterion) {
    let values = in_range_sequence();
    let mut r = LatencyRecorder::new().expect("fixed configuration always constructs");
    let mut i: usize = 0;
    c.bench_function("record_ns/in_range", |b| {
        b.iter(|| {
            let v = cyclic(&values, i);
            i += 1;
            r.record_ns(black_box(v));
        });
    });
}

#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: LOW_NS/HIGH_NS/SIGNIFICANT_DIGITS \
              are the crate's own fixed, valid constants, so construction cannot fail"
)]
fn bench_record_ns_out_of_range(c: &mut Criterion) {
    let values = out_of_range_sequence();
    let mut r = LatencyRecorder::new().expect("fixed configuration always constructs");
    let mut i: usize = 0;
    c.bench_function("record_ns/out_of_range", |b| {
        b.iter(|| {
            let v = cyclic(&values, i);
            i += 1;
            r.record_ns(black_box(v));
        });
    });
}

#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: both recorders share the crate's \
              one fixed configuration, so merge cannot fail"
)]
fn bench_merge_two_full(c: &mut Criterion) {
    let a = full_recorder();
    let b = full_recorder();
    c.bench_function("merge/two_full", |bencher| {
        // `iter_batched`, not `iter`, because `a.clone()` (216 KiB) must be
        // outside the timed portion: this budget is `merge`'s own O(B) cost,
        // not the cost of preparing a fresh target to merge into.
        bencher.iter_batched(
            || a.clone(),
            |mut merged| {
                merged
                    .merge(black_box(&b))
                    .expect("same fixed configuration always merges");
                merged
            },
            criterion::BatchSize::LargeInput,
        );
    });
}

fn bench_percentiles_query(c: &mut Criterion) {
    let r = full_recorder();
    c.bench_function("percentiles/query", |b| {
        b.iter(|| black_box(r.percentiles()));
    });
}

// ---------------------------------------------------------------------------
// `Schedule` (issue #406): `due_ns` and `releasable_at`'s two shapes.
// ---------------------------------------------------------------------------

#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: these are the crate's own fixed, \
              valid Schedule::new arguments, so construction cannot fail"
)]
fn bench_schedule_due_ns(c: &mut Criterion) {
    let schedule = Schedule::new(0, 1_000_000, 64).expect("valid schedule");
    // Cycles through a growing index rather than one fixed value, the same
    // discipline `cyclic` applies to `record_ns` above, so the measurement
    // is not just the cost of re-touching one cached computation.
    let mut i: u64 = 0;
    c.bench_function("schedule/due_ns", |b| {
        b.iter(|| {
            let idx = i;
            i = i.wrapping_add(1);
            black_box(schedule.due_ns(black_box(idx)))
        });
    });
}

#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: these are the crate's own fixed, \
              valid Schedule::new arguments, so construction cannot fail"
)]
fn bench_schedule_releasable_at_steady(c: &mut Criterion) {
    let mut schedule = Schedule::new(0, 1_000_000, 64).expect("valid schedule");
    // `now_ns` tracks exactly this iteration's due time, so every call
    // releases exactly one request and never accrues debt: the "no debt"
    // steady state the budget above is written against.
    let mut i: u64 = 0;
    c.bench_function("schedule/releasable_at/steady", |b| {
        b.iter(|| {
            let now_ns = i * 1000;
            i += 1;
            black_box(schedule.releasable_at(black_box(now_ns)))
        });
    });
}

#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: these are the crate's own fixed, \
              valid Schedule::new arguments, so construction cannot fail"
)]
fn bench_schedule_releasable_at_after_1s_stall(c: &mut Criterion) {
    c.bench_function("schedule/releasable_at/after_1s_stall", |b| {
        // `iter_batched`, not `iter`: each timed call must carry a full one
        // second of debt, which only holds if every measured call starts
        // from a freshly built, never-advanced Schedule. Reusing one
        // Schedule across iterations (the way the steady benchmark above
        // deliberately does) would drain the debt after roughly 15,625
        // calls (1,000,000 requests owed, released 64 at a time) and this
        // benchmark would silently start measuring the cheap post-drain
        // case for the remainder of the run, on a machine fast enough to
        // run that many iterations inside criterion's default measurement
        // window, which it is.
        b.iter_batched(
            || Schedule::new(0, 1_000_000, 64).expect("valid schedule"),
            |mut schedule| black_box(schedule.releasable_at(black_box(1_000_000_000))),
            criterion::BatchSize::SmallInput,
        );
    });
}

// ---------------------------------------------------------------------------
// `probe` (issue #410): the request builder, the response scanner and the
// pacing function's own overshoot. All three run on the probe's measurement
// path (once per probe, or once per request), so a regression here silently
// biases the published percentiles instead of failing an obviously
// attributable test.
// ---------------------------------------------------------------------------

/// Assembling the fixed request: runs once per probe, not per request.
/// Budget: under 2 microseconds, informational.
fn bench_probe_request_bytes_build(c: &mut Criterion) {
    let mut buf = [0u8; MAX_REQUEST_BYTES];
    c.bench_function("probe/request_bytes_build", |b| {
        b.iter(|| {
            black_box(build_request(
                black_box(&mut buf),
                black_box("bench.example"),
                black_box("/probe"),
            ))
        });
    });
}

/// A 1 KiB response head fixture: a status line, a real `Content-Length`,
/// and a handful of realistic headers (the shape a proxy actually adds:
/// `Date`, `Server`, `Cache-Control`, a trace id) padded to exactly 1,024
/// bytes with one long trailing value, rather than dozens of short lines.
/// This is what makes the header COUNT (and so the number of colon and
/// name-comparison scans) representative of a real response rather than an
/// artificially line-heavy one; the byte COUNT (1 KiB) is what the issue's
/// budget names.
fn one_kib_response_head_fixture() -> Vec<u8> {
    let mut head = Vec::from(
        &b"HTTP/1.1 200 OK\r\n\
Content-Length: 1024\r\n\
Content-Type: text/plain\r\n\
Date: Fri, 24 Jul 2026 00:00:00 GMT\r\n\
Server: it-origin\r\n\
Connection: keep-alive\r\n\
X-Trace-Id: "[..],
    );
    let fixed_tail_len = b"\r\n\r\n".len();
    let padding_len = 1024usize
        .saturating_sub(head.len())
        .saturating_sub(fixed_tail_len);
    head.extend(std::iter::repeat_n(b'a', padding_len));
    head.extend_from_slice(b"\r\n\r\n");
    assert_eq!(head.len(), 1024, "fixture must be exactly 1 KiB");
    head
}

/// Scanning a 1 KiB response head plus body accounting: runs once per probe
/// request, on the measurement path. Budget: under 300 nanoseconds.
fn bench_probe_scan_response_1kb(c: &mut Criterion) {
    let head = one_kib_response_head_fixture();
    c.bench_function("probe/scan_response/1kb", |b| {
        b.iter(|| {
            let outcome = scan_response_head(black_box(&head));
            black_box(matches!(outcome, ScanOutcome::Complete(_)))
        });
    });
}

/// `wait_until` for a deadline 1 millisecond out. Reports the DEADLINE
/// OVERSHOOT (`actual - deadline`), not the wall time `iter_custom`'s own
/// batch duration would otherwise represent, via a `Duration` built from the
/// summed overshoot rather than from when the closure actually returned.
/// Budgets: median overshoot under 30 microseconds, p99 overshoot under 200
/// microseconds. An overshoot larger than this becomes a constant bias added
/// to every published sample, so it is the probe's own accuracy floor.
fn bench_probe_wait_until_1ms(c: &mut Criterion) {
    let time: SharedTime = Arc::new(SystemTimeSource::new());
    c.bench_function("probe/wait_until/1ms", |b| {
        b.iter_custom(|iters| {
            let mut total_overshoot_ns: u64 = 0;
            for _ in 0..iters {
                let now = time.precise().as_measurement_nanos();
                let deadline_ns = now.saturating_add(1_000_000);
                wait_until(&time, black_box(deadline_ns));
                let after = time.precise().as_measurement_nanos();
                total_overshoot_ns =
                    total_overshoot_ns.saturating_add(after.saturating_sub(deadline_ns));
            }
            std::time::Duration::from_nanos(total_overshoot_ns)
        });
    });
}

criterion_group!(
    benches,
    bench_record_ns_in_range,
    bench_record_ns_out_of_range,
    bench_merge_two_full,
    bench_percentiles_query,
    bench_schedule_due_ns,
    bench_schedule_releasable_at_steady,
    bench_schedule_releasable_at_after_1s_stall,
    bench_probe_request_bytes_build,
    bench_probe_scan_response_1kb,
    bench_probe_wait_until_1ms
);
criterion_main!(benches);
