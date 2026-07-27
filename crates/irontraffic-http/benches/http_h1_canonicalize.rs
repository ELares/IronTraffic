// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmark for `h1::canonicalize_request` in `irontraffic-http`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and SILENTLY
//! MEASURES NOTHING.
//!
//! Its own bench target, one per surface, never appended to a shared file
//! (issue #630).
//!
//! Budget (reference runner: GitHub Actions `ubuntu-latest`, 4 vCPU, release
//! profile with `lto = "thin"`, see `[profile.bench]` in the workspace
//! `Cargo.toml`): under 1.6 microseconds for the 400-byte head and under 20
//! microseconds for the 8 KiB head. Criterion does not enforce a budget itself;
//! compare the reported throughput against these numbers by hand. The
//! allocation counts are asserted by `tests/alloc_gate_h1_canonicalize.rs`,
//! not here.

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::Limits;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::H1Parser;
use irontraffic_http::h1::canonicalize::H1Context;
use irontraffic_http::h1::canonicalize::canonicalize_request;
use irontraffic_http::path::PathPolicy;
use irontraffic_http::peer::TrustPolicy;
use irontraffic_http::scalar::Scheme;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
    let baseline = build(1);
    let extra = 400_usize.saturating_sub(baseline.len());
    build(1_usize.saturating_add(extra))
}

/// An 8 KiB head: 100 field lines (the field-count limit).
fn adversarial_8kib_head() -> Vec<u8> {
    let mut head = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
    for i in 0..100_u32 {
        let value = "v".repeat(69);
        head.extend_from_slice(format!("X-{i:03}: {value}\r\n").as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    head
}

#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: these test inputs are well \
              formed and cannot fail parsing"
)]
fn bench_h1_canonicalize(c: &mut Criterion) {
    let parser = H1Parser::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);
    let ctx = H1Context {
        limits: Limits::DEFAULT.clamped(),
        path_policy: PathPolicy::DEFAULT,
        codings: irontraffic_http::framing::OtherCodings::Reject,
        underscores: UnderscorePolicy::Reject,
        scheme: Scheme::Http,
        socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        proxy_proto: None,
        trust: &TrustPolicy::None,
        default_authority: None,
        forward_proxy: false,
        will_buffer_body: false,
    };

    let typical = typical_400b_head();
    let typical_head = parser
        .parse_request_head(&typical)
        .unwrap()
        .into_complete()
        .unwrap()
        .0;

    let adversarial = adversarial_8kib_head();
    let adversarial_head = parser
        .parse_request_head(&adversarial)
        .unwrap()
        .into_complete()
        .unwrap()
        .0;

    let mut group = c.benchmark_group("bench_h1_canonicalize");

    let mut arena = BytesMut::new();
    arena.reserve(16 * 1024);

    group.throughput(Throughput::Bytes(typical.len() as u64));
    group.bench_function("typical_400b_head", |b| {
        b.iter(|| {
            arena.clear();
            black_box(canonicalize_request(
                black_box(&typical_head),
                black_box(&ctx),
                black_box(&mut arena),
            ))
        });
    });

    let mut arena2 = BytesMut::new();
    arena2.reserve(16 * 1024);

    group.throughput(Throughput::Bytes(adversarial.len() as u64));
    group.bench_function("adversarial_8kib_head", |b| {
        b.iter(|| {
            arena2.clear();
            black_box(canonicalize_request(
                black_box(&adversarial_head),
                black_box(&ctx),
                black_box(&mut arena2),
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_h1_canonicalize);
criterion_main!(benches);
