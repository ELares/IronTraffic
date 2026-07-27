// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmarks for the HTTP/1 head parser in `irontraffic-http`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and SILENTLY
//! MEASURES NOTHING. Measured, because this comment used to claim it "fails
//! at startup": removing the flag leaves `cargo bench` exiting 0 with "0
//! measured", and `invariant-lints.sh` clean. Nothing announces it.
//!
//! ONE BENCH TARGET PER SURFACE (issue #630). This file benchmarks the
//! `H1Parser` surface and nothing else. Do not append a benchmark for another
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

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::Limits;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::H1Parser;
use std::hint::black_box;

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
/// `tests/alloc_gate_h1.rs`, not here.
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

criterion_group!(benches, bench_h1_head_parse);
criterion_main!(benches);
