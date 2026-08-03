// SPDX-License-Identifier: MIT OR Apache-2.0

//! Criterion benchmark for the P2C pickers. Draws come from a precomputed table so the RNG
//! is never inside the measured closure.
//!
//! `pick/excluding_fallback` DEVIATION FROM THE ISSUE TEXT, DOCUMENTED HERE AND IN THE
//! IMPLEMENTATION REPORT: the issue asks for this group's `u == 64` case to use an `exclude`
//! list "covering all but one endpoint", so the bounded resamples always fail and the
//! deterministic O(u) scan always runs, measuring its cost at u = 64. `MAX_EXCLUDE == 3`
//! makes that expressible ONLY up to u == 4 (excluding 3 of 4 leaves exactly one, matching
//! the phrase exactly); at u == 64 an `exclude` list "covering all but one" would need 63
//! entries, which `pick_excluding` rejects outright (edge case 9), so no such call is
//! possible through this crate's own public API. This bench instead excludes the maximum
//! `MAX_EXCLUDE` entries at every `u`, which forces the scan deterministically at u == 4 as
//! the issue intends, but only occasionally at u == 64 (the bounded resamples usually find
//! one of the 61 remaining non-excluded candidates first). This group is explicitly
//! "ungated" in the issue's own acceptance criteria and `cargo bench -- --test` does not
//! assert on the numbers it reports, so this does not fail any check; it does mean the u ==
//! 64 number here is not the ~400 ns full-scan figure the issue predicts.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use irontraffic_balancer::{
    CostKind, MAX_EXCLUDE, pick_excluding, pick_least_request, pick_peak_ewma,
};
use irontraffic_upstream::{CostCtx, EndpointAddr, EndpointId, EndpointIdentity, EndpointRegistry};

/// Draw table length. 1024 keeps the table itself cheap to build while being far larger than
/// any single benchmark's iteration count that would let the compiler notice a repeating
/// pattern.
const DRAW_TABLE_LEN: usize = 1024;

/// `SplitMix64`, the same three-line generator used by the crate's own tests, run once to fill
/// a fixed table so the RNG itself never sits inside a measured closure.
fn draw_table() -> Vec<u64> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    (0..DRAW_TABLE_LEN)
        .map(|_| {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        })
        .collect()
}

/// Builds a leaked registry with `n` interned endpoints and plain `ids`/`weights`/`slice`
/// arrays, identical in shape to the crate's own test fixture.
#[allow(
    clippy::expect_used,
    reason = "bench fixture helper reachable only from criterion's bench_* entry points; a \
              malformed fixture must fail the bench loudly rather than propagate a Result \
              through every bench function signature in this file"
)]
fn fixture(
    n: u32,
) -> (
    &'static EndpointRegistry,
    Vec<EndpointId>,
    Vec<u32>,
    Vec<u32>,
) {
    let (reg, mut writer) =
        EndpointRegistry::install(n.max(1)).expect("n.max(1) is nonzero and under MAX_CAPACITY");
    let mut ids = Vec::with_capacity(n as usize);
    for i in 0..n {
        let identity = EndpointIdentity {
            addr: EndpointAddr::Socket(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(0x0A00_0000u32.wrapping_add(i)),
                80,
            ))),
            hostname: None,
        };
        let id = writer
            .intern(&identity)
            .expect("fixture registry is sized exactly for n distinct endpoints");
        ids.push(id);
    }
    let weights = vec![1u32; n as usize];
    let slice: Vec<u32> = (0..n).collect();
    (reg, ids, weights, slice)
}

fn default_ctx() -> CostCtx {
    CostCtx {
        now_ms: 1_000,
        decay_ms: 10_000,
        default_rtt_ms: 1_000.0,
        max_requests: u32::MAX,
    }
}

fn bench_peak_ewma(c: &mut Criterion) {
    let draws = draw_table();
    let mut group = c.benchmark_group("pick/peak_ewma");
    for &u in &[1u32, 2, 4, 8, 16, 64, 256, 1024, 4096] {
        let (reg, ids, weights, slice) = fixture(u);
        let stats = reg.stats_slice();
        let cx = default_ctx();
        group.bench_with_input(BenchmarkId::from_parameter(u), &u, |b, _| {
            let mut i = 0usize;
            b.iter(|| {
                let draw = *draws.get(i % DRAW_TABLE_LEN).unwrap_or(&0);
                i = i.wrapping_add(1);
                pick_peak_ewma(&slice, &ids, &weights, stats, &cx, draw)
            });
        });
    }
    group.finish();
}

fn bench_least_request(c: &mut Criterion) {
    let draws = draw_table();
    let mut group = c.benchmark_group("pick/least_request");
    for &u in &[1u32, 2, 4, 8, 16, 64, 256, 1024, 4096] {
        let (reg, ids, weights, slice) = fixture(u);
        let stats = reg.stats_slice();
        let cx = default_ctx();
        group.bench_with_input(BenchmarkId::from_parameter(u), &u, |b, _| {
            let mut i = 0usize;
            b.iter(|| {
                let draw = *draws.get(i % DRAW_TABLE_LEN).unwrap_or(&0);
                i = i.wrapping_add(1);
                pick_least_request(&slice, &ids, &weights, stats, &cx, draw)
            });
        });
    }
    group.finish();
}

fn bench_excluding(c: &mut Criterion) {
    let draws = draw_table();
    let mut group = c.benchmark_group("pick/excluding");
    for &u in &[4u32, 64] {
        let (reg, ids, weights, slice) = fixture(u);
        let stats = reg.stats_slice();
        let cx = default_ctx();
        let exclude = vec![*slice.first().unwrap_or(&0)];
        group.bench_with_input(BenchmarkId::from_parameter(u), &u, |b, _| {
            let mut i = 0usize;
            b.iter(|| {
                let draw = *draws.get(i % DRAW_TABLE_LEN).unwrap_or(&0);
                i = i.wrapping_add(1);
                pick_excluding(
                    CostKind::LeastRequest,
                    &slice,
                    &ids,
                    &weights,
                    stats,
                    &cx,
                    draw,
                    &exclude,
                )
            });
        });
    }
    group.finish();
}

fn bench_excluding_fallback(c: &mut Criterion) {
    let draws = draw_table();
    let mut group = c.benchmark_group("pick/excluding_fallback");
    for &u in &[4u32, 64] {
        let (reg, ids, weights, slice) = fixture(u);
        let stats = reg.stats_slice();
        let cx = default_ctx();
        // See the module doc comment: MAX_EXCLUDE bounds this to "all but one" only at
        // u == 4; at u == 64 it excludes the maximum allowed 3 of 64.
        let exclude: Vec<u32> = slice.iter().skip(1).take(MAX_EXCLUDE).copied().collect();
        group.bench_with_input(BenchmarkId::from_parameter(u), &u, |b, _| {
            let mut i = 0usize;
            b.iter(|| {
                let draw = *draws.get(i % DRAW_TABLE_LEN).unwrap_or(&0);
                i = i.wrapping_add(1);
                pick_excluding(
                    CostKind::LeastRequest,
                    &slice,
                    &ids,
                    &weights,
                    stats,
                    &cx,
                    draw,
                    &exclude,
                )
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_peak_ewma,
    bench_least_request,
    bench_excluding,
    bench_excluding_fallback
);
criterion_main!(benches);
