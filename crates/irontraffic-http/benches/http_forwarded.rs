// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmarks for forwarding-chain parsing in `irontraffic-http`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and SILENTLY
//! MEASURES NOTHING. Measured, because this comment used to claim it "fails
//! at startup": removing the flag leaves `cargo bench` exiting 0 with "0
//! measured", and `invariant-lints.sh` clean. Nothing announces it.
//!
//! ONE BENCH TARGET PER SURFACE (issue #630). This file benchmarks the
//! `ForwardedChain` surface and nothing else. Do not append a benchmark for
//! another surface here: add `benches/http_<surface>.rs` with its own
//! `criterion_group!`/`criterion_main!` and its own `[[bench]]` entry, which
//! is what stops two issues from ever conflicting in one shared bench file.
//! `scripts/invariant-lints.sh`'s `bench-registration` rule refuses a
//! `fn bench_*` in this file that no `criterion_group!` in this file
//! registers.
//!
//! Budget (reference runner: GitHub Actions `ubuntu-latest`, 4 vCPU, release
//! profile with `lto = "thin"`, see `[profile.bench]` in the workspace
//! `Cargo.toml`). Criterion does not enforce a budget itself; compare the
//! reported throughput against these numbers by hand.

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::Limits;
use irontraffic_http::forwarded::ForwardedChain;
use std::hint::black_box;

/// Benchmarks `ForwardedChain::parse_into` on the three inputs the design
/// budgets (reference runner, same as above): under 90 ns for the
/// single-entry `X-Forwarded-For` case, under 300 ns for the `Forwarded`
/// case, and under 2.5 microseconds for the 32-entry case. Each case reuses
/// one `BytesMut` across iterations, exactly as `bench_authority_parse`
/// does: `parse_into` only ever writes a `host` claim into it, and that
/// write is taken back out with `split_off` at the end of every call, so the
/// buffer never grows across iterations regardless of whether a `host` was
/// present.
fn bench_forwarded_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_forwarded_parse");

    let xff_single: &[u8] = b"203.0.113.7";
    group.throughput(Throughput::Bytes(xff_single.len() as u64));
    let mut out_single = BytesMut::new();
    group.bench_function("xff_single_entry", |b| {
        b.iter(|| {
            black_box(ForwardedChain::parse_into(
                core::iter::empty(),
                core::iter::once(black_box(xff_single)),
                core::iter::empty(),
                &Limits::DEFAULT.clamped(),
                &mut out_single,
            ))
        });
    });

    let forwarded_case: &[u8] = b"for=203.0.113.7;proto=https;host=a.example, for=198.51.100.2";
    group.throughput(Throughput::Bytes(forwarded_case.len() as u64));
    let mut out_forwarded = BytesMut::new();
    group.bench_function("forwarded_two_elements", |b| {
        b.iter(|| {
            black_box(ForwardedChain::parse_into(
                core::iter::once(black_box(forwarded_case)),
                core::iter::empty(),
                core::iter::empty(),
                &Limits::DEFAULT.clamped(),
                &mut out_forwarded,
            ))
        });
    });

    // 32 XFF entries across 4 lines: the cap.
    let xff_lines: [Vec<u8>; 4] = core::array::from_fn(|_| {
        let mut line = Vec::new();
        for i in 0..8_u32 {
            if i > 0 {
                line.extend_from_slice(b", ");
            }
            line.extend_from_slice(b"203.0.113.7");
        }
        line
    });
    let total_bytes: u64 = xff_lines.iter().map(|line| line.len() as u64).sum();
    group.throughput(Throughput::Bytes(total_bytes));
    let mut out_capped = BytesMut::new();
    group.bench_function("xff_32_entries_across_4_lines", |b| {
        b.iter(|| {
            black_box(ForwardedChain::parse_into(
                core::iter::empty(),
                black_box(xff_lines.iter().map(Vec::as_slice)),
                core::iter::empty(),
                &Limits::DEFAULT.clamped(),
                &mut out_capped,
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_forwarded_parse);
criterion_main!(benches);
