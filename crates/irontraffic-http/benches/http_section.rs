// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmarks for field-section lookup in `irontraffic-http`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and SILENTLY
//! MEASURES NOTHING. Measured, because this comment used to claim it "fails
//! at startup": removing the flag leaves `cargo bench` exiting 0 with "0
//! measured", and `invariant-lints.sh` clean. Nothing announces it.
//!
//! ONE BENCH TARGET PER SURFACE (issue #630). This file benchmarks the
//! `FieldSection` lookup surface and nothing else. Do not append a benchmark
//! for another surface here: add `benches/http_<surface>.rs` with its own
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
use irontraffic_http::known::KnownHeader;
use irontraffic_http::section::{FieldSection, FieldSectionBuilder};
use std::hint::black_box;

/// Builds a section with `h` fields under `Limits::DEFAULT`, the last of
/// which is `authorization: Bearer token`, the worst case for a linear scan
/// (the target is the LAST field, so a scan cannot short-circuit early).
///
/// `h` up to 100 (`Limits::DEFAULT.max_field_count`) always fits: every
/// earlier field is `x-bench-NNNN: v`, comfortably under
/// `max_field_line_bytes`, and h fields of that shape stay far under
/// `max_header_list_bytes` (65536) even at h = 100.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: h <= Limits::DEFAULT.max_field_count \
              (100) and every name/value pushed here is a short fixed literal well inside \
              every limit, so push cannot fail for any h this file calls this with"
)]
fn section_with_h_fields(h: usize) -> FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    for i in 0..h.saturating_sub(1) {
        let name = format!("x-bench-{i:04}");
        builder.push(&mut arena, name.as_bytes(), b"v").unwrap();
    }
    builder
        .push(&mut arena, b"authorization", b"Bearer token")
        .unwrap();
    builder.finish(&mut arena)
}

/// `get_unique_known(KnownHeader::Authorization)` over sections of h in
/// {5, 20, 50, 100} fields where the target is the last field (worst case).
/// Budget: under 40 ns at h = 20 and under 180 ns at h = 100. Also records
/// `get_unique(b"x-not-present")` at h = 100, which must be under 200 ns.
///
/// The point of the h sweep is to keep the "flat scan beats a hash map"
/// claim honest in CI: a `HashMap` lookup pays one `SipHash` of a 13-byte key
/// (roughly 20 to 40 cycles) plus a probe into a cold bucket array (one to
/// two L2/L3 misses, roughly 40 to 200 cycles) regardless of h, while this
/// design pays a handful of already-resident cache lines and at most h
/// one-byte comparisons; the sweep is what shows that cost actually stays
/// flat rather than growing with the header count.
fn bench_header_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_header_lookup");

    for h in [5_usize, 20, 50, 100] {
        let section = section_with_h_fields(h);
        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("authorization_last_of_{h}"), |b| {
            b.iter(|| black_box(&section).get_unique_known(black_box(KnownHeader::Authorization)));
        });
    }

    let section_100 = section_with_h_fields(100);
    group.throughput(Throughput::Elements(1));
    group.bench_function("absent_x_not_present_at_100", |b| {
        b.iter(|| black_box(&section_100).get_unique(black_box(b"x-not-present")));
    });

    group.finish();
}

criterion_group!(benches, bench_header_lookup);
criterion_main!(benches);
