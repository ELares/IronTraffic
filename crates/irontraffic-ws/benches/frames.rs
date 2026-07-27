// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmarks for the `ws_frames` group: `FrameDecoder::decode_header`
//! and `TunnelBudget::debit`. `harness = false` in `Cargo.toml`: criterion
//! supplies its own `main`, and a `[[bench]]` entry without that flag runs
//! under libtest instead and fails at startup.
//!
//! Budgets (reference runner: GitHub Actions `ubuntu-latest`, 4 vCPU, release
//! profile, see `[profile.bench]` in the workspace `Cargo.toml`):
//! `decode_header_short` (a 2-byte masked binary header) under 6 nanoseconds,
//! `decode_header_long` (a full 14-byte header) under 12 nanoseconds, and
//! `budget_debit` (one debit) under 8 nanoseconds and under 2% of the decode
//! benchmarks' per-frame cost. Criterion does not enforce a budget itself;
//! compare the reported numbers against these by hand.

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_ws::{Direction, FrameDecoder, FrameHeader, Opcode, TunnelBudget};
use std::hint::black_box;

/// A 2-byte header: a masked, zero-length `Binary` frame from client to
/// server. The shortest possible header shape.
fn short_header() -> Vec<u8> {
    vec![0x82, 0x80, 0x11, 0x22, 0x33, 0x44]
}

/// A 14-byte header: the 64-bit extended length form plus a mask key, the
/// longest possible header shape.
fn long_header() -> Vec<u8> {
    let mut out = vec![0x82u8, 0xFF];
    out.extend_from_slice(&100_000u64.to_be_bytes());
    out.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    out
}

/// Decodes `bytes` for one-time bench setup. No `.expect(...)`: this is a
/// plain function, not a `#[test]` (clippy's `expect_used` exemption for
/// test code applies only to functions carrying `#[test]` themselves, the
/// same rule `crates/irontraffic-conn/tests/sharded_bind.rs` states against
/// the same lint). `bytes` is always the fixed, well-formed `short_header()`
/// fixture, so the fallback below is not expected to be reached.
fn decode_or_fallback(decoder: &FrameDecoder, bytes: &[u8]) -> FrameHeader {
    match decoder.decode_header(bytes) {
        Ok(Some(header)) => header,
        Ok(None) | Err(_) => FrameHeader {
            opcode: Opcode::Binary,
            fin: true,
            payload_len: 0,
            mask: None,
            consumed: 2,
        },
    }
}

fn bench_decode_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("ws_frames");

    let short = short_header();
    group.bench_function("decode_header_short", |b| {
        let decoder = FrameDecoder::new(Direction::ClientToServer);
        b.iter(|| {
            let _ = black_box(decoder.decode_header(black_box(&short)));
        });
    });

    let long = long_header();
    group.bench_function("decode_header_long", |b| {
        let decoder = FrameDecoder::new(Direction::ClientToServer);
        b.iter(|| {
            let _ = black_box(decoder.decode_header(black_box(&long)));
        });
    });

    group.bench_function("budget_debit", |b| {
        let decoder = FrameDecoder::new(Direction::ClientToServer);
        let header = decode_or_fallback(&decoder, &short);
        let mut budget = TunnelBudget::new(0);
        b.iter(|| {
            let _ = black_box(budget.debit(black_box(&header), black_box(0)));
        });
    });

    group.finish();
}

criterion_group!(ws_frames, bench_decode_header);
criterion_main!(ws_frames);
