// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmarks for request framing resolution in `irontraffic-http`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and SILENTLY
//! MEASURES NOTHING. Measured, because this comment used to claim it "fails
//! at startup": removing the flag leaves `cargo bench` exiting 0 with "0
//! measured", and `invariant-lints.sh` clean. Nothing announces it.
//!
//! ONE BENCH TARGET PER SURFACE (issue #630). This file benchmarks the
//! request framing surface and nothing else. Do not append a benchmark for
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
use irontraffic_http::framing::{OtherCodings, resolve_request_framing};
use irontraffic_http::response::resolve_response_framing;
use irontraffic_http::section::{FieldSection, FieldSectionBuilder};
use irontraffic_http::{Limits, Method, StatusCode, WireVersion};
use std::hint::black_box;

/// Builds the "typical section" input for [`bench_resolve_framing`]: 16
/// fields under `Limits::DEFAULT`, the last of which is
/// `content-length: 1234`.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: every name/value pushed here is a \
              short fixed literal well inside every limit, so push cannot fail"
)]
fn typical_framing_section() -> FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    for i in 0..15_u32 {
        let name = format!("x-bench-{i:02}");
        builder.push(&mut arena, name.as_bytes(), b"v").unwrap();
    }
    builder
        .push(&mut arena, b"content-length", b"1234")
        .unwrap();
    builder.finish(&mut arena)
}

/// Builds the "chunked section" input for [`bench_resolve_framing`]: 16
/// fields under `Limits::DEFAULT`, the last of which is
/// `transfer-encoding: chunked`.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: every name/value pushed here is a \
              short fixed literal well inside every limit, so push cannot fail"
)]
fn chunked_framing_section() -> FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    for i in 0..15_u32 {
        let name = format!("x-bench-{i:02}");
        builder.push(&mut arena, name.as_bytes(), b"v").unwrap();
    }
    builder
        .push(&mut arena, b"transfer-encoding", b"chunked")
        .unwrap();
    builder.finish(&mut arena)
}

/// Builds the "adversarial section" input for [`bench_resolve_framing`]: 100
/// fields under `Limits::DEFAULT`, with 8 `transfer-encoding` tokens spread
/// across 3 field lines (none of them `chunked`), refused as
/// `TransferEncodingFinalNotChunked` only after the whole combined list has
/// been scanned.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: every name/value pushed here is a \
              short fixed literal well inside every limit, so push cannot fail"
)]
fn adversarial_framing_section() -> FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    for i in 0..97_u32 {
        let name = format!("x-bench-{i:03}");
        builder.push(&mut arena, name.as_bytes(), b"v").unwrap();
    }
    builder
        .push(&mut arena, b"transfer-encoding", b"a, b, c")
        .unwrap();
    builder
        .push(&mut arena, b"transfer-encoding", b"d, e, f")
        .unwrap();
    builder
        .push(&mut arena, b"transfer-encoding", b"g, h")
        .unwrap();
    builder.finish(&mut arena)
}

/// Benchmarks `resolve_request_framing` on the three inputs the design
/// budgets (reference runner, same as above): under 120 ns for the two
/// accepting cases and under 500 ns for the refusing case. Framing
/// resolution runs once per request and must not be a measurable fraction
/// of a 300,000 requests-per-second per-core budget (3.3 microseconds per
/// request). Criterion does not enforce a budget itself; compare the
/// reported time against it by hand.
fn bench_resolve_framing(c: &mut Criterion) {
    let typical = typical_framing_section();
    let chunked = chunked_framing_section();
    let adversarial = adversarial_framing_section();

    let mut group = c.benchmark_group("bench_resolve_framing");

    group.throughput(Throughput::Elements(1));
    group.bench_function("typical_content_length", |b| {
        b.iter(|| {
            resolve_request_framing(
                black_box(&Method::Post),
                black_box(WireVersion::Http11),
                black_box(&typical),
                black_box(OtherCodings::Reject),
            )
        });
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("chunked", |b| {
        b.iter(|| {
            resolve_request_framing(
                black_box(&Method::Post),
                black_box(WireVersion::Http11),
                black_box(&chunked),
                black_box(OtherCodings::Reject),
            )
        });
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("adversarial_refused", |b| {
        b.iter(|| {
            resolve_request_framing(
                black_box(&Method::Post),
                black_box(WireVersion::Http11),
                black_box(&adversarial),
                black_box(OtherCodings::Reject),
            )
        });
    });

    group.finish();
}

#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: every name/value pushed here is a \
              short fixed literal well inside every limit, so push cannot fail"
)]
fn typical_response_section() -> FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    for i in 0..15_u32 {
        let name = format!("x-bench-{i:02}");
        builder.push(&mut arena, name.as_bytes(), b"v").unwrap();
    }
    builder
        .push(&mut arena, b"content-length", b"1234")
        .unwrap();
    builder.finish(&mut arena)
}

#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: every name/value pushed here is a \
              short fixed literal well inside every limit, so push cannot fail"
)]
fn not_modified_response_section() -> FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    builder
        .push(&mut arena, b"content-length", b"1234")
        .unwrap();
    builder.finish(&mut arena)
}

/// Benchmarks `resolve_response_framing` on the two inputs the design
/// budgets (reference runner, same as `bench_resolve_framing` above): under
/// 120 ns each. `check_expect` and `InterimBudget::charge` get no separate
/// benchmark: `check_expect` is one duplicate check plus one trimmed
/// byte-slice comparison, and `InterimBudget::charge` is two saturating
/// integer adds and two comparisons, neither of which has a multi-branch,
/// data-dependent path the way framing resolution does, so there is no
/// distinct case here for criterion to distinguish.
fn bench_resolve_response_framing(c: &mut Criterion) {
    let typical = typical_response_section();
    let not_modified = not_modified_response_section();

    let mut group = c.benchmark_group("bench_resolve_response_framing");

    group.throughput(Throughput::Elements(1));
    group.bench_function("typical_200_content_length", |b| {
        b.iter(|| {
            resolve_response_framing(
                black_box(StatusCode::OK),
                black_box(&Method::Get),
                black_box(WireVersion::Http11),
                black_box(&typical),
                black_box(OtherCodings::Reject),
            )
        });
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("not_modified_304_content_length", |b| {
        b.iter(|| {
            resolve_response_framing(
                black_box(StatusCode::NOT_MODIFIED),
                black_box(&Method::Get),
                black_box(WireVersion::Http11),
                black_box(&not_modified),
                black_box(OtherCodings::Reject),
            )
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_resolve_framing,
    bench_resolve_response_framing
);
criterion_main!(benches);
