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
use irontraffic_http::{Limits, Scheme, WireVersion};
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

criterion_group!(benches, bench_field_validate, bench_authority_parse);
criterion_main!(benches);
