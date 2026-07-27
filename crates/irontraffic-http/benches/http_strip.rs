// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmarks for the hop-by-hop ingress strip in
//! `irontraffic-http`. `harness = false` in `Cargo.toml`: criterion supplies
//! its own `main`, and a `[[bench]]` entry without that flag runs under
//! libtest instead and SILENTLY MEASURES NOTHING. Measured, because this
//! comment used to claim it "fails at startup": removing the flag leaves
//! `cargo bench` exiting 0 with "0 measured", and `invariant-lints.sh`
//! clean. Nothing announces it.
//!
//! ONE BENCH TARGET PER SURFACE (issue #630). This file benchmarks the
//! ingress strip surface and nothing else. Do not append a benchmark for
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
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::Limits;
use irontraffic_http::section::{FieldSection, FieldSectionBuilder};
use irontraffic_http::strip;
use std::hint::black_box;

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

criterion_group!(benches, bench_strip_ingress);
criterion_main!(benches);
