// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz target for the HTTP/1 parse-then-serialize-then-reparse round-trip:
//! this is the P-ROUNDTRIP property from `h1-request-serializer` (#37), and
//! it is the fuzz target that proves the serializer and the parser agree
//! about framing, because the only way they disagree is a smuggling gadget.
//!
//! Input domain (#37's own words): "arbitrary bytes treated as a request
//! head." There is no fixed literal anywhere in this target: the fuzzer's
//! bytes ARE the request head, method, target, version and fields
//! included. Every prior version of this file fixed the method, path,
//! authority and fields as constants and varied only a framing-selector
//! byte and the input length, which meant the parser's own decisions about
//! method, target-form, authority and field validity were never exercised
//! by this target at all (#724 BLOCKING 7).
//!
//! Procedure, exactly as #37 specifies: parse `data` with [`H1Parser`], feed
//! the result to [`canonicalize_request`]; if either refuses, return (not
//! every byte string is a request, and rejecting one is not a finding).
//! Otherwise serialize the resulting `CanonicalRequest` back out with the
//! `BodySource` derived from its own resolved framing (`Empty` to `None`,
//! `Exact { len }` to `Exact { len }`, `Streamed` to `Streaming`) and the
//! `TargetForm` `canonicalize_request` itself returned, then re-parse and
//! re-canonicalize the bytes we just wrote.
//!
//! Contract: the re-parse and re-canonicalization MUST succeed, and the
//! second `CanonicalRequest`'s framing MUST equal the first's -- any input
//! where reserialization changes the framing is a smuggling bug and fails
//! the case -- and the method, authority, path bytes and query MUST be
//! equal. Run with `cargo +nightly fuzz run fuzz_h1_roundtrip` from
//! `crates/irontraffic-http/fuzz/`.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::BytesMut;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::framing::{OtherCodings, RequestFraming};
use irontraffic_http::h1::H1Parser;
use irontraffic_http::h1::canonicalize::{H1Context, canonicalize_request};
use irontraffic_http::h1::serialize::{BodySource, ConnectionMode, serialize_request_head};
use irontraffic_http::limits::Limits;
use irontraffic_http::path::PathPolicy;
use irontraffic_http::peer::{ForwardEmit, TrustPolicy};
use irontraffic_http::scalar::{ParseStatus, Scheme};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cheap run counters, printed periodically to stderr so a `cargo fuzz run`
/// session gives direct evidence of how often the corpus reaches PAST the
/// first parse and canonicalization into the round-trip logic this target
/// exists to exercise, rather than being rejected as not-a-request at the
/// first hurdle: a target that rejects nearly everything at parse time
/// tests nothing past the parser's own front door.
static REACHED: AtomicU64 = AtomicU64::new(0);
static PARSED: AtomicU64 = AtomicU64::new(0);
static CANONICALIZED: AtomicU64 = AtomicU64::new(0);

fn report(n: u64) {
    if n.is_multiple_of(200_000) {
        let parsed = PARSED.load(Ordering::Relaxed);
        let canon = CANONICALIZED.load(Ordering::Relaxed);
        eprintln!(
            "fuzz_h1_roundtrip: {n} reached, {parsed} parsed a complete head \
             ({:.1}%), {canon} reached canonicalize_request Ok ({:.1}%)",
            100.0 * parsed as f64 / n as f64,
            100.0 * canon as f64 / n as f64,
        );
    }
}

/// No proxy chain in front, matching the simplest reverse-proxy listener
/// configuration. Trust policy is not part of #37's input domain -- the
/// property under test is about framing, method, target and field
/// round-tripping, not about identity resolution -- so this is fixed, not
/// fuzzed.
const TRUST: TrustPolicy = TrustPolicy::None;

/// The fixed listener configuration this target canonicalizes against, on
/// both the first parse and the reparse. `forward_proxy: false` is what
/// keeps `TargetForm::Absolute` out of the input domain this target
/// reaches: `canonicalize_request` refuses absolute-form with
/// `TargetFormInvalid` on a non-forward-proxy listener before a
/// `CanonicalRequest` can even exist, so `serialize_request_head` is never
/// asked to serialize the one form it refuses to emit.
fn ctx() -> H1Context<'static> {
    H1Context {
        limits: Limits::DEFAULT.clamped(),
        path_policy: PathPolicy::DEFAULT,
        codings: OtherCodings::Reject,
        underscores: UnderscorePolicy::Reject,
        scheme: Scheme::Http,
        socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
        proxy_proto: None,
        trust: &TRUST,
        default_authority: None,
        forward_proxy: false,
        will_buffer_body: false,
    }
}

/// The address `serialize_request_head` would attribute to itself in a
/// `Forwarded` / `X-Forwarded-*` element. Fixed and irrelevant here:
/// `ForwardEmit` below asks for neither field, so this value is never read.
fn local_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080)
}

fuzz_target!(|data: &[u8]| {
    // `Limits::DEFAULT` already bounds every individual piece (request line,
    // field count, field size); this just keeps libFuzzer from spending
    // cycles constructing pathologically huge inputs whose rejection reason
    // is uninteresting (RequestLineTooLong or similar) well before reaching
    // any of the logic this target exists to exercise.
    if data.len() > 65536 {
        return;
    }

    let n = REACHED.fetch_add(1, Ordering::Relaxed) + 1;
    report(n);

    let limits = Limits::DEFAULT.clamped();
    let parser = H1Parser::new(&limits, UnderscorePolicy::Reject);

    let head = match parser.parse_request_head(data) {
        Ok(ParseStatus::Complete { value, .. }) => value,
        _ => return,
    };
    PARSED.fetch_add(1, Ordering::Relaxed);

    let mut arena = BytesMut::new();
    let (req, _expect_action, form) = match canonicalize_request(&head, &ctx(), &mut arena) {
        Ok(v) => v,
        Err(_) => return,
    };
    CANONICALIZED.fetch_add(1, Ordering::Relaxed);

    // The OUTBOUND framing is derived from the CanonicalRequest's own
    // resolved framing, exactly as #37 specifies -- never independently
    // chosen -- because the property under test is that regenerating the
    // SAME framing round-trips, not that some other framing would also
    // work.
    let body = match req.framing {
        RequestFraming::Empty => BodySource::None,
        RequestFraming::Exact { len } => BodySource::Exact { len },
        RequestFraming::Streamed => BodySource::Streaming,
    };

    let no_emit = ForwardEmit {
        emit_forwarded: false,
        emit_x_forwarded: false,
    };

    let mut out = BytesMut::new();
    let write_result = serialize_request_head(
        &req,
        form,
        body,
        ConnectionMode::Close,
        no_emit,
        local_addr(),
        &mut out,
    );
    assert!(
        write_result.is_ok(),
        "serialize_request_head refused a request our own parser and \
         canonicalize_request just accepted: {write_result:?}, req={req:?}"
    );

    // Re-parse and re-canonicalize the bytes we just wrote, with the same
    // fixed listener configuration used for the first pass.
    let head2 = match parser.parse_request_head(&out) {
        Ok(ParseStatus::Complete { value, .. }) => value,
        other => {
            panic!( // it-allow: no-panic reason: fuzz target reports a finding by panicking; a head this same call just serialized failing to reparse is the P-ROUNDTRIP violation this target exists to catch, never a normal outcome
                "reparse of our own serialized head failed: {other:?}, out={out:?}, \
                 original data={data:?}"
            );
        }
    };
    let mut arena2 = BytesMut::new();
    let req2 = match canonicalize_request(&head2, &ctx(), &mut arena2) {
        Ok((r, _, _)) => r,
        Err(reason) => {
            panic!( // it-allow: no-panic reason: fuzz target reports a finding by panicking; RECANONICALIZE of our own just-serialized head being refused is the P-ROUNDTRIP violation this target exists to catch (the exact shape of #724 BLOCKING 1's HostDuplicate finding), never a normal outcome
                "RECANONICALIZE of our own head REFUSED: {reason:?} (framing_in={:?}), \
                 out={out:?}, original data={data:?}",
                req.framing
            );
        }
    };

    // The contract: framing must survive exactly (the smuggling-critical
    // part), and so must method, authority, path bytes and query.
    assert_eq!(
        req2.framing, req.framing,
        "framing diverged across the round-trip: a smuggling bug, out={out:?}"
    );
    assert_eq!(req2.method.as_bytes(), req.method.as_bytes(), "method diverged");
    assert_eq!(
        req2.authority.host(),
        req.authority.host(),
        "authority host diverged"
    );
    assert_eq!(
        req2.authority.port(),
        req.authority.port(),
        "authority port diverged"
    );
    assert_eq!(req2.path.as_bytes(), req.path.as_bytes(), "path diverged");
    assert_eq!(
        req2.query.as_ref().map(irontraffic_http::path::RawQuery::as_bytes),
        req.query.as_ref().map(irontraffic_http::path::RawQuery::as_bytes),
        "query diverged"
    );
});
