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

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_bench::{HIGH_NS, LatencyRecorder};
use std::hint::black_box;

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

criterion_group!(
    benches,
    bench_record_ns_in_range,
    bench_record_ns_out_of_range,
    bench_merge_two_full,
    bench_percentiles_query
);
criterion_main!(benches);
