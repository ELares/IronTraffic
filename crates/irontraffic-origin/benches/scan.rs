// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(missing_docs, reason = "criterion_group! generates this pub item")]

//! `scan_head`'s own per-request cost: a regression here shows up as a lower
//! `origin_ceiling_rps`, which silently invalidates every benchmark cell, so
//! it is worth a dedicated gate.
//!
//! Budget: `scan_head/typical` under 400 nanoseconds; `scan_head/8kib` under
//! 6 microseconds. `scan_head/100_headers` is reported, not gated.
//!
//! Measured on an Apple M4 Pro (macOS, `aarch64`, debug assertions off,
//! `cargo bench`, criterion 0.8): `scan_head/typical` ~66 ns,
//! `scan_head/100_headers` ~1.12 us, `scan_head/8kib` ~3.86 us. Both budgets
//! pass with headroom on this machine; re-measure on the project's actual
//! benchmark host before trusting these as the reference numbers, per the
//! Benchmarks section.

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_origin::serve::scan_head;
use std::hint::black_box;

/// A realistic small head: a request line, three ordinary headers, and the
/// one honoured delay header, terminated normally.
fn typical_head() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
    buf.extend_from_slice(b"Host: bench.example\r\n");
    buf.extend_from_slice(b"User-Agent: it-origin-bench/1.0\r\n");
    buf.extend_from_slice(b"Accept: */*\r\n");
    buf.extend_from_slice(b"X-Origin-Delay-Us: 0\r\n");
    buf.extend_from_slice(b"\r\n");
    buf
}

/// 100 header lines, one of them the honoured `Content-Length`, totalling
/// roughly 8 KiB: the published adversarial cell from edge case 4.
fn hundred_headers_head() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
    for i in 0..99u32 {
        buf.extend_from_slice(format!("X-Filler-{i:03}: {:0width$}\r\n", i, width = 60).as_bytes());
    }
    buf.extend_from_slice(b"Content-Length: 0\r\n");
    buf.extend_from_slice(b"\r\n");
    buf
}

/// An 8 KiB head with no honoured headers at all: the worst case for the
/// terminator search, which must still scan the whole thing once.
fn eight_kib_head() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
    while buf.len() < 8192 - 21 {
        buf.extend_from_slice(b"X-Padding: filler\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

fn bench_scan_head_typical(c: &mut Criterion) {
    let head = typical_head();
    c.bench_function("scan_head/typical", |b| {
        b.iter(|| scan_head(black_box(&head)));
    });
}

fn bench_scan_head_100_headers(c: &mut Criterion) {
    let head = hundred_headers_head();
    c.bench_function("scan_head/100_headers", |b| {
        b.iter(|| scan_head(black_box(&head)));
    });
}

fn bench_scan_head_8kib(c: &mut Criterion) {
    let head = eight_kib_head();
    c.bench_function("scan_head/8kib", |b| {
        b.iter(|| scan_head(black_box(&head)));
    });
}

criterion_group!(
    benches,
    bench_scan_head_typical,
    bench_scan_head_100_headers,
    bench_scan_head_8kib
);
criterion_main!(benches);
