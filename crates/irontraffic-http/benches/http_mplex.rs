// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmark for `mplex::head::MplexHeadBuilder::push` and `finish` in
//! `irontraffic-http`. `harness = false` in `Cargo.toml`: criterion supplies its own
//! `main`, and a `[[bench]]` entry without that flag runs under libtest instead and
//! SILENTLY MEASURES NOTHING.
//!
//! Its own bench target, one per surface, never appended to a shared file
//! (issue #630).
//!
//! Budget (reference runner: GitHub Actions `ubuntu-latest`, 4 vCPU, release
//! profile with `lto = "thin"`, see `[profile.bench]` in the workspace
//! `Cargo.toml`): under 1.4 microseconds for the typical head, under 1.6
//! microseconds for the crumb-split variant, under 14 microseconds for the
//! 100-pair head. Criterion does not enforce a budget itself; compare the
//! reported throughput against these numbers by hand. The crumb variant must
//! not be more than 25% slower than the single-cookie variant, which is the
//! honest cost of the per-crumb charging this crate does on purpose. The
//! allocation counts are asserted by `tests/alloc_gate_mplex.rs`, not here.

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::Limits;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::framing::OtherCodings;
use irontraffic_http::mplex::{MplexContext, MplexHeadBuilder};
use irontraffic_http::path::PathPolicy;
use irontraffic_http::peer::TrustPolicy;
use irontraffic_http::scalar::{Scheme, WireVersion};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// A typical browser H2 head: 4 pseudo-headers plus 12 fields, one `cookie`
/// (unsplit).
fn typical_head() -> Vec<(&'static [u8], &'static [u8])> {
    vec![
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"example.com"),
        (b":path", b"/a/b?x=1"),
        (b"user-agent", b"Mozilla/5.0 (compatible)"),
        (b"accept", b"text/html,application/xhtml+xml"),
        (b"accept-language", b"en-US,en;q=0.9"),
        (b"accept-encoding", b"gzip, deflate, br"),
        (b"referer", b"https://example.com/"),
        (b"cache-control", b"max-age=0"),
        (b"sec-ch-ua-mobile", b"?0"),
        (b"upgrade-insecure-requests", b"1"),
        (b"x-requested-with", b"XMLHttpRequest"),
        (b"cookie", b"session=abc123; theme=dark; lang=en"),
        (b"host", b"example.com"),
        (b"x-forwarded-for", b"203.0.113.9"),
    ]
}

/// The same head with the `cookie` split into 8 crumbs (RFC 9113 Section
/// 8.2.3), for measuring the honest cost of per-crumb charging.
fn crumb_split_head() -> Vec<(&'static [u8], &'static [u8])> {
    let mut fields: Vec<(&'static [u8], &'static [u8])> = typical_head()
        .into_iter()
        .filter(|(name, _)| *name != b"cookie")
        .collect();
    fields.extend_from_slice(&[
        (b"cookie", &b"a=1"[..]),
        (b"cookie", b"b=2"),
        (b"cookie", b"c=3"),
        (b"cookie", b"d=4"),
        (b"cookie", b"e=5"),
        (b"cookie", b"f=6"),
        (b"cookie", b"g=7"),
        (b"cookie", b"h=8"),
    ]);
    fields
}

/// A head of 4 pseudo-headers plus 96 regular fields, exactly 100 charged
/// pairs, the largest block that passes `max_field_count: 100`.
fn hundred_pair_head() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut fields: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method"[..].to_vec(), b"GET"[..].to_vec()),
        (b":scheme"[..].to_vec(), b"https"[..].to_vec()),
        (b":authority"[..].to_vec(), b"example.com"[..].to_vec()),
        (b":path"[..].to_vec(), b"/"[..].to_vec()),
    ];
    for i in 0..96u32 {
        fields.push((format!("x-bench-{i:03}").into_bytes(), b"v".to_vec()));
    }
    fields
}

fn build(ctx: &MplexContext<'_>, seq: &[(&[u8], &[u8])]) {
    let mut arena = BytesMut::new();
    let mut builder = MplexHeadBuilder::new(&arena, &ctx.limits, WireVersion::H2);
    for &(name, value) in seq {
        let _ = builder.push(&mut arena, name, value);
    }
    let _ = builder.finish(ctx, &mut arena);
}

fn build_owned(ctx: &MplexContext<'_>, seq: &[(Vec<u8>, Vec<u8>)]) {
    let mut arena = BytesMut::new();
    let mut builder = MplexHeadBuilder::new(&arena, &ctx.limits, WireVersion::H2);
    for (name, value) in seq {
        let _ = builder.push(&mut arena, name, value);
    }
    let _ = builder.finish(ctx, &mut arena);
}

fn bench_mplex_head_build(c: &mut Criterion) {
    let trust = TrustPolicy::None;
    let ctx = MplexContext {
        limits: Limits::DEFAULT.clamped(),
        path_policy: PathPolicy::DEFAULT,
        codings: OtherCodings::Reject,
        underscores: UnderscorePolicy::Reject,
        scheme: Scheme::Https,
        socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        proxy_proto: None,
        trust: &trust,
        will_buffer_body: false,
    };

    let typical = typical_head();
    let crumb_split = crumb_split_head();
    let hundred = hundred_pair_head();

    let mut group = c.benchmark_group("bench_mplex_head_build");

    group.throughput(Throughput::Elements(typical.len() as u64));
    group.bench_function("typical_head", |b| {
        b.iter(|| build(black_box(&ctx), black_box(&typical)));
    });

    group.throughput(Throughput::Elements(crumb_split.len() as u64));
    group.bench_function("crumb_split_head", |b| {
        b.iter(|| build(black_box(&ctx), black_box(&crumb_split)));
    });

    group.throughput(Throughput::Elements(hundred.len() as u64));
    group.bench_function("hundred_pair_head", |b| {
        b.iter(|| build_owned(black_box(&ctx), black_box(&hundred)));
    });

    group.finish();
}

criterion_group!(benches, bench_mplex_head_build);
criterion_main!(benches);
