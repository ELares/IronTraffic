// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmark for `irontraffic_http::priority::parse_priority_field`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and fails
//! at startup.
//!
//! Its own bench target rather than appended to `http_hot`, per issue #630:
//! one bench file per parsed surface, never a shared one.
//!
//! Budget (reference runner: see `http_hot.rs` for the exact machine and
//! profile): under 40 nanoseconds for the short field and under 30
//! microseconds for the 4096-byte adversarial field. The 30 microsecond
//! figure is what makes the linear-time claim checkable: a quadratic member
//! scan over 4096 bytes would land far above it. Criterion does not enforce a
//! budget itself; compare the reported time against these numbers by hand.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::priority::parse_priority_field;
use std::hint::black_box;

/// A 4096-byte field of `u=1,` repetitions: the adversarial input from edge
/// case 18 of issue #42, the one that keeps the linear-time claim honest.
fn adversarial_4096b_field() -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    while buf.len() < 4096 {
        buf.extend_from_slice(b"u=1,");
    }
    buf
}

fn bench_priority_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_priority_parse");

    let short: &[u8] = b"u=1, i";
    group.throughput(Throughput::Bytes(short.len() as u64));
    group.bench_function("short_field", |b| {
        b.iter(|| black_box(parse_priority_field(black_box(short))));
    });

    let adversarial = adversarial_4096b_field();
    group.throughput(Throughput::Bytes(adversarial.len() as u64));
    group.bench_function("adversarial_4096b_field", |b| {
        b.iter(|| black_box(parse_priority_field(black_box(&adversarial))));
    });

    group.finish();
}

criterion_group!(benches, bench_priority_parse);
criterion_main!(benches);
