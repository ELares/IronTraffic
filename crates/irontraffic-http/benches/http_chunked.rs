// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API, matching \
              benches/http_hot.rs's own precedent for this exact crate root"
)]
//! Criterion benchmarks for `irontraffic_http::h1::chunked::ChunkedDecoder`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and fails
//! at startup.
//!
//! Its own bench target, never appended to `benches/http_hot.rs`: one bench
//! target per surface (issue #630).
//!
//! Budget (reference runner: GitHub Actions `ubuntu-latest`, 4 vCPU, release
//! profile with `lto = "thin"`, see `[profile.bench]` in the workspace
//! `Cargo.toml`): the 1 MiB single-chunk body must complete in under 25
//! microseconds total (over 40 GiB per second, achievable only because body
//! bytes are never scanned; a scanning implementation would be at best 1 GiB
//! per second and would fail this budget by 40x). The 64-byte-chunk case must
//! complete in under 1.1 milliseconds (about 67 ns per chunk). Criterion does
//! not enforce a budget itself; compare the reported throughput against these
//! numbers by hand.

use bytes::BytesMut;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::Limits;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::chunked::{ChunkedDecoder, ChunkedEvent};
use std::hint::black_box;

/// Runs `decoder` over `wire`, revealing the whole buffer up front (the
/// non-adversarial, "arrives in one read" case every one of this file's
/// benchmarks measures), looping `decode` calls until `Done` or an error.
/// Panics on an unexpected error: every wire built in this file is well
/// formed by construction, so an error here is a bug in the bench harness,
/// not something to time.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness, not request-path code: every wire this file builds is well \
              formed by construction, and an error decoding it is a harness bug worth \
              panicking loudly on immediately rather than silently timing a partial run"
)]
fn drive_whole(decoder: &mut ChunkedDecoder, wire: &[u8]) -> usize {
    let mut pos = 0usize;
    let mut delivered = 0usize;
    loop {
        let buf = wire.get(pos..).unwrap_or(&[]);
        let mut arena = BytesMut::new();
        match decoder.decode(black_box(buf), &mut arena).unwrap() {
            ChunkedEvent::Data { len, .. } => {
                delivered = delivered.saturating_add(len);
                pos = pos.saturating_add(decoder.consumed_this_call());
            }
            ChunkedEvent::NeedMore => {
                pos = pos.saturating_add(decoder.consumed_this_call());
            }
            ChunkedEvent::Done { .. } => return delivered,
        }
    }
}

/// As `drive_whole`, but reveals at most `chunk` MORE bytes of `wire` per
/// `decode` call, mimicking a real read loop that appends whatever arrived
/// since the last wakeup. Used only by `one_mib_single_chunk`, whose own
/// budget names "fed in 64 KiB pieces" explicitly: revealing the whole 1 MiB
/// at once would time one `Data` event covering the entire body instead of
/// the sixteen 64 KiB reads the budget is about.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness, not request-path code: every wire this file builds is well \
              formed by construction, and an error decoding it is a harness bug worth \
              panicking loudly on immediately rather than silently timing a partial run"
)]
fn drive_split(decoder: &mut ChunkedDecoder, wire: &[u8], chunk: usize) -> usize {
    let mut pos = 0usize;
    let mut revealed = 0usize;
    let mut delivered = 0usize;
    loop {
        if revealed < wire.len() {
            revealed = revealed.saturating_add(chunk).min(wire.len());
        }
        let buf = wire.get(pos..revealed).unwrap_or(&[]);
        let mut arena = BytesMut::new();
        match decoder.decode(black_box(buf), &mut arena).unwrap() {
            ChunkedEvent::Data { len, .. } => {
                delivered = delivered.saturating_add(len);
                pos = pos.saturating_add(decoder.consumed_this_call());
            }
            ChunkedEvent::NeedMore => {
                pos = pos.saturating_add(decoder.consumed_this_call());
            }
            ChunkedEvent::Done { .. } => return delivered,
        }
    }
}

fn new_decoder() -> ChunkedDecoder {
    ChunkedDecoder::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject)
}

/// A 1 MiB body as one chunk.
fn one_mib_single_chunk() -> Vec<u8> {
    let len = 1024 * 1024;
    let mut wire = format!("{len:x}\r\n").into_bytes();
    wire.extend(std::iter::repeat_n(b'x', len));
    wire.extend_from_slice(b"\r\n0\r\n\r\n");
    wire
}

/// A 1 MiB body as 16384 chunks of 64 bytes: the size-line-dominated case.
fn many_64_byte_chunks() -> Vec<u8> {
    let mut wire = Vec::new();
    for _ in 0..16384 {
        wire.extend_from_slice(b"40\r\n");
        wire.extend(std::iter::repeat_n(b'y', 64));
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}

/// A body of 1000 one-byte chunks: the adversarial case (six wire bytes per
/// body byte, the worst-case framing-to-data ratio this decoder ever sees).
fn thousand_one_byte_chunks() -> Vec<u8> {
    let mut wire = Vec::new();
    for _ in 0..1000 {
        wire.extend_from_slice(b"1\r\nz\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}

/// A trailer section with 8 fields, after an otherwise empty body.
fn trailer_section_8_fields() -> Vec<u8> {
    let mut wire = Vec::from(&b"0\r\n"[..]);
    for i in 0..8 {
        wire.extend_from_slice(format!("x-bench-{i}: v\r\n").as_bytes());
    }
    wire.extend_from_slice(b"\r\n");
    wire
}

fn bench_chunked_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_chunked_decode");

    let one_chunk = one_mib_single_chunk();
    group.throughput(Throughput::Bytes(one_chunk.len() as u64));
    group.bench_function("one_mib_single_chunk_in_64kib_pieces", |b| {
        b.iter_batched(
            new_decoder,
            |mut decoder| black_box(drive_split(&mut decoder, &one_chunk, 64 * 1024)),
            BatchSize::SmallInput,
        );
    });

    let many_chunks = many_64_byte_chunks();
    group.throughput(Throughput::Bytes(many_chunks.len() as u64));
    group.bench_function("sixteen_thousand_64_byte_chunks", |b| {
        b.iter_batched(
            new_decoder,
            |mut decoder| black_box(drive_whole(&mut decoder, &many_chunks)),
            BatchSize::SmallInput,
        );
    });

    let adversarial = thousand_one_byte_chunks();
    group.throughput(Throughput::Bytes(adversarial.len() as u64));
    group.bench_function("thousand_one_byte_chunks", |b| {
        b.iter_batched(
            new_decoder,
            |mut decoder| black_box(drive_whole(&mut decoder, &adversarial)),
            BatchSize::SmallInput,
        );
    });

    let trailers = trailer_section_8_fields();
    group.throughput(Throughput::Bytes(trailers.len() as u64));
    group.bench_function("trailer_section_8_fields", |b| {
        b.iter_batched(
            new_decoder,
            |mut decoder| black_box(drive_whole(&mut decoder, &trailers)),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_chunked_decode);
criterion_main!(benches);
