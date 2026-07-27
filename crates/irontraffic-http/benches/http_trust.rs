// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmark for `resolve_identity` in `irontraffic-http::peer`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and fails
//! at startup. Its own bench target, never appended to `http_hot.rs` (issue
//! #630).
//!
//! Budget (reference runner: same methodology as `http_hot.rs`): under 15 ns
//! for `TrustPolicy::None` with an empty chain, under 25 ns for
//! `HopCount(1)` with a one-element chain, and under 1.2 microseconds for
//! `TrustedCidrs` with two prefixes over a 32-element chain (the element
//! cap). Criterion does not enforce a budget itself; compare the reported
//! time against these numbers by hand.

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::Limits;
use irontraffic_http::cidr::IpCidr;
use irontraffic_http::forwarded::ForwardedChain;
use irontraffic_http::peer::{TrustPolicy, resolve_identity};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn socket_peer() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 54321)
}

/// A socket peer INSIDE `10.0.0.0/8`, used only for the `TrustedCidrs`
/// benchmark case below: the walk over `trusted_32_chain` is only reached at
/// all (and only then hits the `O(T * C)` worst case that chain is built to
/// exercise) when the base address itself is trusted (design step 5a); an
/// untrusted base fails closed before a single element is examined.
fn trusted_socket_peer() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)), 54321)
}

/// A chain of one entry, `203.0.113.7`, matching `bench_forwarded_parse`'s
/// own `xff_single_entry` fixture in `http_hot.rs`.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: this single, well formed entry \
              cannot exceed any default limit, so parse_into cannot fail"
)]
fn one_element_chain() -> ForwardedChain {
    let mut out = BytesMut::new();
    ForwardedChain::parse_into(
        core::iter::empty(),
        core::iter::once(&b"203.0.113.7"[..]),
        core::iter::empty(),
        &Limits::DEFAULT.clamped(),
        &mut out,
    )
    .unwrap()
}

/// A chain of 32 entries across 4 XFF lines of 8, all inside `10.0.0.0/8`, so
/// a `TrustedCidrs` walk here consumes every element as trusted and exercises
/// the `O(T * C)` worst case the design budgets: the walk never stops early.
#[allow(
    clippy::unwrap_used,
    reason = "bench harness setup, not request-path code: every entry pushed here is a short, \
              well formed literal comfortably inside every default limit, so parse_into cannot \
              fail for this fixed input"
)]
fn trusted_32_chain() -> ForwardedChain {
    let lines: [Vec<u8>; 4] = core::array::from_fn(|line_idx| {
        let mut buf = Vec::new();
        for i in 0_u32..8 {
            if i > 0 {
                buf.extend_from_slice(b", ");
            }
            let host = line_idx
                .saturating_mul(8)
                .saturating_add(usize::try_from(i).unwrap_or(0))
                .saturating_add(1);
            buf.extend_from_slice(format!("10.0.0.{host}").as_bytes());
        }
        buf
    });
    let mut out = BytesMut::new();
    ForwardedChain::parse_into(
        core::iter::empty(),
        lines.iter().map(Vec::as_slice),
        core::iter::empty(),
        &Limits::DEFAULT.clamped(),
        &mut out,
    )
    .unwrap()
}

/// The two prefixes the `TrustedCidrs` benchmark case configures.
#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: both literals are valid IPv4 \
              prefixes, so IpCidr::new cannot return None for either"
)]
fn two_trusted_prefixes() -> Vec<IpCidr> {
    vec![
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("10.0.0.0/8 must be valid"),
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16)
            .expect("192.168.0.0/16 must be valid"),
    ]
}

fn bench_resolve_identity(c: &mut Criterion) {
    let peer = socket_peer();
    let mut group = c.benchmark_group("bench_resolve_identity");

    let empty = ForwardedChain::default();
    group.throughput(Throughput::Elements(1));
    group.bench_function("none_empty_chain", |b| {
        b.iter(|| {
            black_box(resolve_identity(
                black_box(peer),
                black_box(None),
                black_box(&empty),
                black_box(&TrustPolicy::None),
            ))
        });
    });

    let one = one_element_chain();
    group.throughput(Throughput::Elements(1));
    group.bench_function("hop_count_1_one_element", |b| {
        b.iter(|| {
            black_box(resolve_identity(
                black_box(peer),
                black_box(None),
                black_box(&one),
                black_box(&TrustPolicy::HopCount(1)),
            ))
        });
    });

    let thirty_two = trusted_32_chain();
    let trusted_cidrs_policy = TrustPolicy::TrustedCidrs(two_trusted_prefixes());
    let trusted_peer = trusted_socket_peer();
    group.throughput(Throughput::Elements(32));
    group.bench_function("trusted_cidrs_two_prefixes_32_elements", |b| {
        b.iter(|| {
            black_box(resolve_identity(
                black_box(trusted_peer),
                black_box(None),
                black_box(&thirty_two),
                black_box(&trusted_cidrs_policy),
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_resolve_identity);
criterion_main!(benches);
