// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmarks for authority parsing in `irontraffic-http`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and SILENTLY
//! MEASURES NOTHING. Measured, because this comment used to claim it "fails
//! at startup": removing the flag leaves `cargo bench` exiting 0 with "0
//! measured", and `invariant-lints.sh` clean. Nothing announces it.
//!
//! ONE BENCH TARGET PER SURFACE (issue #630). This file benchmarks the
//! `Authority` surface and nothing else. Do not append a benchmark for another
//! surface here: add `benches/http_<surface>.rs` with its own
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
use irontraffic_http::authority::Authority;
use irontraffic_http::{Limits, Scheme};
use std::hint::black_box;

/// Benchmarks `Authority::parse_into` on the three inputs the design budgets
/// (reference runner, same as above): under 70 ns each. `Authority::parse_into`
/// runs once per request and shares the head-parse budget with field
/// validation in `benches/http_field.rs`; criterion does not enforce the
/// budget itself, so compare the reported time against it by hand.
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

criterion_group!(benches, bench_authority_parse);
criterion_main!(benches);
