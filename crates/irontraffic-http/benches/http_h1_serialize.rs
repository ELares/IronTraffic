// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    clippy::unwrap_used,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API; and \
              unwrap in bench helpers is test-only infrastructure, not \
              request-path code"
)]
//! Criterion benchmark for the HTTP/1 serializer in `irontraffic-http`.
//! `harness = false` in `Cargo.toml`: criterion supplies its own `main`, and a
//! `[[bench]]` entry without that flag runs under libtest instead and SILENTLY
//! MEASURES NOTHING.
//!
//! Its own bench target, one per surface, never appended to a shared file
//! (issue #630).
//!
//! Budget (reference runner: GitHub Actions `ubuntu-latest`, 4 vCPU, release
//! profile with `lto = "thin"`, see `[profile.bench]` in the workspace
//! `Cargo.toml`): under 800 nanoseconds for the 10-field typical request and
//! under 15 microseconds for the 100-field request. Criterion does not enforce
//! a budget itself; compare the reported throughput against these numbers by
//! hand. The allocation counts are asserted by
//! `tests/alloc_gate_h1_serialize.rs`, not here.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::Limits;
use irontraffic_http::authority::Authority;
use irontraffic_http::canonical::{CanonicalRequest, CanonicalRequestBuilder};
use irontraffic_http::framing::RequestFraming;
use irontraffic_http::h1::serialize::{
    BodySource, ConnectionMode, serialize_request_head, serialize_request_head_len,
};
use irontraffic_http::path::PathPolicy;
use irontraffic_http::peer::{ForwardEmit, IdentitySource, PeerIdentity};
use irontraffic_http::scalar::{Method, Scheme, WireVersion};
use irontraffic_http::section::{FieldSection, FieldSectionBuilder};

fn clamped() -> irontraffic_http::limits::ClampedLimits {
    Limits::DEFAULT.clamped()
}

fn authority() -> Authority {
    let limits = clamped();
    let mut out = BytesMut::new();
    Authority::parse_into(b"example.com", Scheme::Https, &limits, &mut out).unwrap()
}

fn path_query() -> (
    irontraffic_http::path::NormalizedPath,
    Option<irontraffic_http::path::RawQuery>,
) {
    let limits = clamped();
    let mut out = BytesMut::new();
    irontraffic_http::path::NormalizedPath::parse_into(
        b"/api/v1/resource",
        &PathPolicy::DEFAULT,
        &limits,
        &mut out,
    )
    .unwrap()
}

fn build_fields(field_count: usize) -> FieldSection {
    let limits = clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    builder.push(&mut arena, b"accept", b"text/html").unwrap();
    if field_count > 0 {
        for i in 0..field_count.saturating_sub(1) {
            let name = format!("x-custom-{i}");
            builder.push(&mut arena, name.as_bytes(), b"value").unwrap();
        }
    }
    builder.finish(&mut arena)
}

fn peer() -> PeerIdentity {
    PeerIdentity {
        client: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        client_port: Some(54321),
        source: IdentitySource::Socket,
        forwarded_proto: None,
        trusted_hops: 0,
        peer_trusted: false,
    }
}

fn build_request(field_count: usize) -> CanonicalRequest {
    let (path, query) = path_query();
    CanonicalRequestBuilder::new()
        .method(Method::Get)
        .scheme(Scheme::Http)
        .authority(authority())
        .path(path, query)
        .headers(build_fields(field_count))
        .framing(RequestFraming::Exact { len: 42 })
        .version(WireVersion::Http11)
        .peer(peer())
        .build()
        .unwrap()
}

fn local_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080)
}

fn bench_h1_serialize_request_head(c: &mut Criterion) {
    let typical = build_request(10);
    let adversarial = build_request(100);

    let emit = ForwardEmit {
        emit_forwarded: true,
        emit_x_forwarded: true,
    };
    let local = local_addr();

    let mut group = c.benchmark_group("bench_h1_serialize_request_head");

    let typical_len = serialize_request_head_len(
        &typical,
        BodySource::Exact { len: 42 },
        ConnectionMode::KeepAlive,
        emit,
        local,
    );
    group.throughput(Throughput::Bytes(typical_len as u64));
    group.bench_function("typical_10_fields", |b| {
        let mut buf = BytesMut::new();
        buf.reserve(4096);
        b.iter(|| {
            buf.clear();
            let result = serialize_request_head(
                black_box(&typical),
                BodySource::Exact { len: 42 },
                ConnectionMode::KeepAlive,
                emit,
                local,
                &mut buf,
            );
            result.unwrap();
            black_box(());
        });
    });

    let adversarial_len = serialize_request_head_len(
        &adversarial,
        BodySource::Streaming,
        ConnectionMode::KeepAlive,
        emit,
        local,
    );
    group.throughput(Throughput::Bytes(adversarial_len as u64));
    group.bench_function("adversarial_100_fields", |b| {
        let mut buf = BytesMut::new();
        buf.reserve(16 * 1024);
        b.iter(|| {
            buf.clear();
            let result = serialize_request_head(
                black_box(&adversarial),
                BodySource::Streaming,
                ConnectionMode::KeepAlive,
                emit,
                local,
                &mut buf,
            );
            result.unwrap();
            black_box(());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_h1_serialize_request_head);
criterion_main!(benches);
