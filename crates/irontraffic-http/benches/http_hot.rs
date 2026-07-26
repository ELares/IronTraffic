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
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::authority::Authority;
use irontraffic_http::field::{UnderscorePolicy, validate_name, validate_value};
use irontraffic_http::forwarded::ForwardedChain;
use irontraffic_http::framing::{OtherCodings, resolve_request_framing};
use irontraffic_http::h1::H1Parser;
use irontraffic_http::known::{self, KnownHeader};
use irontraffic_http::section::{FieldSection, FieldSectionBuilder};
use irontraffic_http::strip;
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

/// Builds the "typical section" input for `bench_strip_ingress`: 16 fields,
/// one `connection: keep-alive`.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: every name/value here is a \
              short fixed literal well inside Limits::DEFAULT, so push cannot fail"
)]
fn typical_strip_section() -> FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    for i in 0_u32..15 {
        let name = format!("x-typical-{i:02}");
        builder.push(&mut arena, name.as_bytes(), b"v").unwrap();
    }
    builder
        .push(&mut arena, b"connection", b"keep-alive")
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

/// Builds the "adversarial section" input for `bench_strip_ingress`: 100
/// fields, two `connection` lines naming 32 tokens combined
/// (`x-adv-00..x-adv-31`), of which only the first 16 (`x-adv-00..x-adv-15`)
/// match a field actually present. The other 16 name nothing, so the
/// `O(h * w)` match pass cannot short circuit once every real field has
/// already been found.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: every name/value here is a \
              short fixed literal well inside Limits::DEFAULT, so push cannot fail"
)]
fn adversarial_strip_section() -> FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    for i in 0_u32..16 {
        let name = format!("x-adv-{i:02}");
        builder.push(&mut arena, name.as_bytes(), b"v").unwrap();
    }
    for i in 0_u32..82 {
        let name = format!("x-fill-{i:02}");
        builder.push(&mut arena, name.as_bytes(), b"v").unwrap();
    }
    let first_line = (0_u32..16)
        .map(|i| format!("x-adv-{i:02}"))
        .collect::<Vec<_>>()
        .join(",");
    let second_line = (16_u32..32)
        .map(|i| format!("x-adv-{i:02}"))
        .collect::<Vec<_>>()
        .join(",");
    builder
        .push(&mut arena, b"connection", first_line.as_bytes())
        .unwrap();
    builder
        .push(&mut arena, b"connection", second_line.as_bytes())
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

/// Benchmarks `strip::strip_ingress` on the two inputs the design budgets
/// (reference runner, same methodology as the rest of this file): under
/// 400 ns for the typical 16-field section and under 6 microseconds for the
/// adversarial 100-field, 32-token section, the `O(h * w)` worst case this
/// benchmark exists to keep visible. Criterion does not enforce the budget
/// itself; compare the reported time against it by hand.
///
/// `strip_ingress` mutates its section in place by removing fields, so each
/// iteration is measured with `iter_batched`: reusing one section across
/// iterations would strip it once on the first call and time an
/// already-stripped section on every call after that.
fn bench_strip_ingress(c: &mut Criterion) {
    let limits = Limits::DEFAULT.clamped();
    let mut group = c.benchmark_group("bench_strip_ingress");

    group.throughput(Throughput::Elements(1));
    group.bench_function("typical_16_fields", |b| {
        b.iter_batched(
            typical_strip_section,
            |mut section| {
                black_box(strip::strip_ingress(
                    black_box(&mut section),
                    black_box(&limits),
                ))
            },
            BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("adversarial_100_fields_32_tokens", |b| {
        b.iter_batched(
            adversarial_strip_section,
            |mut section| {
                black_box(strip::strip_ingress(
                    black_box(&mut section),
                    black_box(&limits),
                ))
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

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

/// A 400-byte typical browser head: 10 fields.
fn typical_400b_head() -> Vec<u8> {
    let field_names = [
        "Host",
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Connection",
        "Referer",
        "Cookie",
        "Cache-Control",
        "X-Requested-With",
    ];
    let build = |first_value_len: usize| -> Vec<u8> {
        let mut head = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for (i, name) in field_names.iter().enumerate() {
            let value = if i == 0 {
                "v".repeat(first_value_len)
            } else {
                "v".to_owned()
            };
            head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        head
    };
    // Build once with a 1-byte first value to measure the fixed skeleton,
    // then rebuild with exactly the padding needed to land on 400 bytes.
    let baseline = build(1);
    let extra = 400_usize.saturating_sub(baseline.len());
    build(1_usize.saturating_add(extra))
}

/// An 8 KiB adversarial head: 100 field lines (the field-count limit) at
/// roughly 78 bytes each, which is the field-count limit reached inside
/// 8 KiB rather than the byte limit.
fn adversarial_8kib_head() -> Vec<u8> {
    let mut head = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
    for i in 0..100_u32 {
        // "X-NNN: " (7 bytes) + a value padded so each line is ~78 bytes
        // including its CRLF.
        let value = "v".repeat(69);
        head.extend_from_slice(format!("X-{i:03}: {value}\r\n").as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    head
}

/// An 8 KiB head with a bare LF at byte 8000: the worst-case refusal, where
/// the bare-CR/bare-LF pass scans nearly the whole head before rejecting.
fn worst_case_bare_lf_head() -> Vec<u8> {
    let mut head = Vec::from(&b"GET / HTTP/1.1\r\nX: "[..]);
    head.extend(std::iter::repeat_n(
        b'v',
        8000_usize.saturating_sub(head.len()),
    ));
    head.push(b'\n');
    head.extend(std::iter::repeat_n(b'v', 100));
    head.extend_from_slice(b"\r\n\r\n");
    head
}

/// Benchmarks `H1Parser::parse_request_head` on the four inputs the design
/// budgets (reference runner, same as above): under 600 ns for the 400-byte
/// head, under 13 microseconds for the 8 KiB cases. Criterion does not
/// enforce the budget itself; compare the reported throughput against these
/// numbers by hand. The allocation counts are asserted by
/// `tests/alloc_gate.rs`, not here.
fn bench_h1_head_parse(c: &mut Criterion) {
    let parser = H1Parser::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);

    let typical = typical_400b_head();
    let adversarial = adversarial_8kib_head();
    let worst_case = worst_case_bare_lf_head();

    let mut group = c.benchmark_group("bench_h1_head_parse");

    group.throughput(Throughput::Bytes(typical.len() as u64));
    group.bench_function("typical_400b_head", |b| {
        b.iter(|| black_box(parser.parse_request_head(black_box(&typical))));
    });

    group.throughput(Throughput::Bytes(adversarial.len() as u64));
    group.bench_function("adversarial_8kib_head", |b| {
        b.iter(|| black_box(parser.parse_request_head(black_box(&adversarial))));
    });

    // The `Partial` cost: the same typical head, fed as a 200-byte prefix
    // first, so the parser re-scans from offset zero and returns `Partial`
    // without ever completing.
    let prefix = typical.get(..200).unwrap_or(&typical[..]);
    group.throughput(Throughput::Bytes(prefix.len() as u64));
    group.bench_function("typical_head_as_200b_prefix", |b| {
        b.iter(|| black_box(parser.parse_request_head(black_box(prefix))));
    });

    group.throughput(Throughput::Bytes(worst_case.len() as u64));
    group.bench_function("worst_case_8kib_bare_lf", |b| {
        b.iter(|| black_box(parser.parse_request_head(black_box(&worst_case))));
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
    bench_strip_ingress,
    bench_forwarded_parse,
    bench_h1_head_parse
);
criterion_main!(benches);
