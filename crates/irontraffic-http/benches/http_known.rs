// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmarks for the known-header classification jump table in
//! `irontraffic-http`. `harness = false` in `Cargo.toml`: criterion supplies
//! its own `main`, and a `[[bench]]` entry without that flag runs under
//! libtest instead and SILENTLY MEASURES NOTHING. Measured, because this
//! comment used to claim it "fails at startup": removing the flag leaves
//! `cargo bench` exiting 0 with "0 measured", and `invariant-lints.sh`
//! clean. Nothing announces it.
//!
//! ONE BENCH TARGET PER SURFACE (issue #630). This file benchmarks the
//! `known::classify` surface and nothing else. Do not append a benchmark for
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

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::known;
use std::hint::black_box;

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
                // in `benches/http_field.rs`: `classify` is pure, so an
                // unobserved call is dead code an optimizing backend may
                // remove, timing an empty loop.
                let _ = black_box(known::classify(black_box(name)));
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_known_classify);
criterion_main!(benches);
