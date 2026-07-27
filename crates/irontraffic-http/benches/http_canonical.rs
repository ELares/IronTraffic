// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmark for `CanonicalRequestBuilder::build` in
//! `irontraffic-http::canonical`. `harness = false` in `Cargo.toml`: criterion
//! supplies its own `main`, and a `[[bench]]` entry without that flag runs under
//! libtest instead and fails at startup. Its own bench target, never appended to
//! `http_hot.rs` (issue #630).
//!
//! Budget (reference runner: same methodology as `http_hot.rs`): under 200 ns for
//! `bench_canonical_build`, which builds a `CanonicalRequest` from pre-parsed parts
//! with a 16-field header section. Criterion does not enforce a budget itself;
//! compare the reported time against this number by hand.
//!
//! `RewriteLedger::apply` is NOT separately benchmarked here: its own cost is
//! `NormalizedPath::parse_into` (measured by `bench_path_normalize`, the path
//! module's own benchmark) plus two integer operations (the ledger bound check and
//! increment), so `bench_path_normalize`'s number already covers it.

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_http::Limits;
use irontraffic_http::authority::Authority;
use irontraffic_http::canonical::CanonicalRequestBuilder;
use irontraffic_http::framing::RequestFraming;
use irontraffic_http::path::{NormalizedPath, PathPolicy};
use irontraffic_http::peer::{IdentitySource, PeerIdentity};
use irontraffic_http::scalar::{Method, Scheme, WireVersion};
use irontraffic_http::section::FieldSectionBuilder;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

/// A validated authority, `example.com`, built once and reused for every iteration:
/// this benchmark measures `build`, not `Authority::parse_into`, which
/// `bench_authority_parse` in `http_hot.rs` already covers.
#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: this literal is a well \
              formed authority, so parse_into cannot fail"
)]
fn authority() -> Authority {
    let mut out = BytesMut::new();
    Authority::parse_into(
        b"example.com",
        Scheme::Https,
        &Limits::DEFAULT.clamped(),
        &mut out,
    )
    .expect("example.com must parse")
}

/// A normalized path and query, built once and reused: this benchmark measures
/// `build`, not `NormalizedPath::parse_into`.
#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: this literal is a well \
              formed target, so parse_into cannot fail"
)]
fn path_and_query() -> (NormalizedPath, Option<irontraffic_http::path::RawQuery>) {
    let mut out = BytesMut::new();
    NormalizedPath::parse_into(
        b"/api/v1/widgets/42?verbose=1",
        &PathPolicy::DEFAULT,
        &Limits::DEFAULT.clamped(),
        &mut out,
    )
    .expect("well formed target must parse")
}

/// A 16-field header section, already through the shape `strip_ingress` leaves
/// behind (no hop-by-hop, identity or reserved-prefix field), matching the design's
/// own benchmark input.
#[allow(
    clippy::expect_used,
    reason = "bench harness setup, not request-path code: every name/value pushed \
              here is a short, well formed literal comfortably inside every \
              default limit, so push cannot fail"
)]
fn sixteen_field_headers() -> irontraffic_http::section::FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    builder
        .push(&mut arena, b"host", b"example.com")
        .expect("valid field");
    builder
        .push(&mut arena, b"accept", b"application/json")
        .expect("valid field");
    builder
        .push(&mut arena, b"accept-encoding", b"gzip, br")
        .expect("valid field");
    builder
        .push(&mut arena, b"accept-language", b"en-US")
        .expect("valid field");
    builder
        .push(&mut arena, b"user-agent", b"bench-agent/1.0")
        .expect("valid field");
    builder
        .push(&mut arena, b"authorization", b"Bearer token.value.here")
        .expect("valid field");
    builder
        .push(&mut arena, b"cookie", b"session=abc123")
        .expect("valid field");
    builder
        .push(&mut arena, b"content-type", b"application/json")
        .expect("valid field");
    builder
        .push(&mut arena, b"cache-control", b"no-cache")
        .expect("valid field");
    builder
        .push(&mut arena, b"referer", b"https://example.com/")
        .expect("valid field");
    builder
        .push(&mut arena, b"origin", b"https://example.com")
        .expect("valid field");
    builder
        .push(&mut arena, b"x-request-id", b"abcdefg-1234")
        .expect("valid field");
    builder
        .push(&mut arena, b"x-custom-a", b"v1")
        .expect("valid field");
    builder
        .push(&mut arena, b"x-custom-b", b"v2")
        .expect("valid field");
    builder
        .push(&mut arena, b"x-custom-c", b"v3")
        .expect("valid field");
    builder
        .push(&mut arena, b"x-custom-d", b"v4")
        .expect("valid field");
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

fn bench_canonical_build(c: &mut Criterion) {
    // Every part is parsed exactly once, outside the timed closure: this benchmark
    // measures `build` alone, "from pre-parsed parts", not the parsing that produces
    // them (`bench_authority_parse`, `bench_h1_head_parse` and `http_hot.rs`'s other
    // benchmarks already cover that). Each iteration clones the pre-parsed parts
    // (`Authority`, `NormalizedPath`, `Option<RawQuery>` and `FieldSection` are all
    // `Bytes`-backed, so cloning is a refcount bump plus a copy of the inline slot
    // array, not a re-parse) because `build` consumes its builder's parts by value.
    let authority = authority();
    let (path, query) = path_and_query();
    let headers = sixteen_field_headers();
    let peer_identity = peer();

    let mut group = c.benchmark_group("bench_canonical_build");
    group.throughput(Throughput::Elements(1));
    group.bench_function("sixteen_field_section", |b| {
        b.iter(|| {
            black_box(
                CanonicalRequestBuilder::new()
                    .method(black_box(Method::Get))
                    .scheme(black_box(Scheme::Https))
                    .authority(black_box(authority.clone()))
                    .path(black_box(path.clone()), black_box(query.clone()))
                    .headers(black_box(headers.clone()))
                    .framing(black_box(RequestFraming::Empty))
                    .version(black_box(WireVersion::Http11))
                    .peer(black_box(peer_identity))
                    .build(),
            )
        });
    });
    group.finish();
}

criterion_group!(benches, bench_canonical_build);
criterion_main!(benches);
