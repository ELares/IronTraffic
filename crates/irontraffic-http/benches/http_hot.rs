// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmarks for the hot field-validation path in
//! `irontraffic-http`. `harness = false` in `Cargo.toml`: criterion supplies
//! its own `main`, and a `[[bench]]` entry without that flag runs under
//! libtest instead and fails at startup.
//!
//! Budget (reference runner: GitHub Actions `ubuntu-latest`, 4 vCPU, release
//! profile with `lto = "thin"`, see `[profile.bench]` in the workspace
//! `Cargo.toml`): the 640-byte typical head must complete in under 900 ns;
//! the two 8 KiB cases must complete in under 11 microseconds. These are
//! roughly 4x looser than the 1-byte-per-cycle scalar-table design target
//! and exist to catch an accidental O(n^2) or an accidental allocation, not
//! to microtune. Criterion does not enforce a budget itself; compare the
//! reported throughput against these numbers by hand.

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::authority::Authority;
use irontraffic_http::field::{validate_name, validate_value};
use irontraffic_http::framing::{OtherCodings, resolve_request_framing};
use irontraffic_http::known::{self, KnownHeader};
use irontraffic_http::section::{FieldSection, FieldSectionBuilder};
use irontraffic_http::{Limits, Method, Scheme, WireVersion};
use std::hint::black_box;

/// Sixteen (name, value) pairs, 40 bytes each (an 8-byte name, a 32-byte
/// value): "a typical head's worth of field bytes", 640 bytes total.
fn typical_fields() -> Vec<(String, Vec<u8>)> {
    (0..16_u32)
        .map(|i| (format!("field-{i:02}"), vec![b'x'; 32]))
        .collect()
}

fn bench_field_validate(c: &mut Criterion) {
    let fields = typical_fields();
    let total_bytes: u64 = fields
        .iter()
        .map(|(name, value)| (name.len() + value.len()) as u64)
        .sum();

    let mut group = c.benchmark_group("bench_field_validate");

    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("typical_640b_head", |b| {
        b.iter(|| {
            for (name, value) in &fields {
                // Both the input AND the output go through black_box: validate_name
                // and validate_value are pure and side-effect free, so a result
                // that is merely discarded (`let _ = ...`) is dead code an
                // optimizing backend is free to remove entirely, which would time
                // an empty loop instead of the validators.
                let _ = black_box(validate_name(
                    black_box(name.as_bytes()),
                    WireVersion::Http11,
                ));
                let _ = black_box(validate_value(
                    black_box(value.as_slice()),
                    WireVersion::Http11,
                ));
            }
        });
    });

    let legal_8k = vec![b'x'; 8192];
    group.throughput(Throughput::Bytes(legal_8k.len() as u64));
    group.bench_function("legal_8kib_value", |b| {
        b.iter(|| validate_value(black_box(&legal_8k), WireVersion::Http11));
    });

    // Worst case: the whole 8 KiB scan runs before the reject, because the
    // one bad byte (a trailing CR) sits at the very end.
    let mut worst_8k = vec![b'x'; 8192];
    if let Some(last) = worst_8k.last_mut() {
        *last = 0x0D;
    }
    group.throughput(Throughput::Bytes(worst_8k.len() as u64));
    group.bench_function("worst_case_8kib_trailing_cr", |b| {
        b.iter(|| validate_value(black_box(&worst_8k), WireVersion::Http11));
    });

    group.finish();
}

/// Classify a fixed rotation of 16 real header names (8 known, 8 unknown) per
/// iteration. Budget: under 8 ns per name on the reference runner. This
/// exists to catch someone replacing the jump table with a linear scan over
/// all 51 spellings.
fn bench_known_classify(c: &mut Criterion) {
    let names: [&[u8]; 16] = [
        b"host",
        b"x-bench-aa",
        b"content-length",
        b"x-bench-bb",
        b"authorization",
        b"x-bench-cc",
        b"user-agent",
        b"x-bench-dd",
        b"accept-encoding",
        b"x-bench-ee",
        b"cookie",
        b"x-bench-ff",
        b"via",
        b"x-bench-gg",
        b"etag",
        b"x-bench-hh",
    ];

    let mut group = c.benchmark_group("bench_known_classify");
    group.throughput(Throughput::Elements(names.len() as u64));
    group.bench_function("rotation_16", |b| {
        b.iter(|| {
            for name in &names {
                // The result is discarded via an explicit `let _ =` (not a bare
                // statement) for the same reason as `bench_field_validate`
                // above: `classify` is pure, so an unobserved call is dead code
                // an optimizing backend may remove, timing an empty loop.
                let _ = black_box(known::classify(black_box(name)));
            }
        });
    });
    group.finish();
}

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

/// Benchmarks `Authority::parse_into` on the three inputs the design budgets
/// (reference runner, same as above): under 70 ns each. `Authority::parse_into`
/// runs once per request and shares the head-parse budget with field
/// validation above; criterion does not enforce the budget itself, so
/// compare the reported time against it by hand.
///
/// Each case reuses one `BytesMut` across iterations and calls `reserve`
/// before every `parse_into` call, the exact contract `parse_into`'s own doc
/// comment states for a caller building several values from one buffer: the
/// per-iteration cost this measures is the parse itself, not a buffer grow
/// that a correctly written caller would never pay for repeatedly either.
fn bench_authority_parse(c: &mut Criterion) {
    let cases: [(&str, &[u8]); 3] = [
        ("reg_name", b"example.com"),
        ("reg_name_with_port", b"example.com:8443"),
        ("ipv6_bracketed_with_port", b"[2001:db8::1]:8443"),
    ];

    let mut group = c.benchmark_group("bench_authority_parse");
    for (label, raw) in cases {
        group.throughput(Throughput::Bytes(raw.len() as u64));
        let mut out = BytesMut::with_capacity(raw.len());
        group.bench_function(label, |b| {
            b.iter(|| {
                out.reserve(raw.len());
                black_box(Authority::parse_into(
                    black_box(raw),
                    Scheme::Https,
                    &Limits::DEFAULT.clamped(),
                    &mut out,
                ))
            });
        });
    }
    group.finish();
}

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

criterion_group!(
    benches,
    bench_authority_parse,
    bench_field_validate,
    bench_header_lookup,
    bench_known_classify,
    bench_resolve_framing,
);
criterion_main!(benches);
