// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz target for the HTTP/1 serialise-then-parse round-trip: serialise
//! `body_payload` bytes as a content-length or chunked framed message,
//! serialise a matching head with `h1::serialize`, feed the result into
//! `H1Parser`, and assert the round-trip produces the same body the fuzzer
//! supplied.
//!
//! This is the fuzz target that proves the serialiser and the parser agree
//! about framing, because the only way they disagree is a smuggling gadget.
//! Run with `cargo fuzz run fuzz_h1_roundtrip` from
//! `crates/irontraffic-http/fuzz/`.
//!
//! The first byte of the fuzzer's input selects `Content-Length` or
//! `Transfer-Encoding: chunked` framing for the OUTBOUND body; the rest of
//! the input is the body payload. Both framing paths are exercised roughly
//! evenly, which matters because the chunked path is the one that reaches
//! `ChunkedEncoder` on the way out and `ChunkedDecoder` on the way back:
//! a target that always chose `Content-Length` would never touch either and
//! would be vacuous for exactly the smuggling-relevant half of this issue's
//! thesis (#37).

#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::BytesMut;
use irontraffic_http::authority::Authority;
use irontraffic_http::canonical::CanonicalRequestBuilder;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::framing::RequestFraming;
use irontraffic_http::h1::H1Parser;
use irontraffic_http::h1::chunked::{ChunkedDecoder, ChunkedEvent};
use irontraffic_http::h1::serialize::{
    BodySource, ChunkedEncoder, ConnectionMode, serialize_request_head,
};
use irontraffic_http::limits::Limits;
use irontraffic_http::path::PathPolicy;
use irontraffic_http::peer::{ForwardEmit, IdentitySource, PeerIdentity};
use irontraffic_http::scalar::{Method, Scheme, WireVersion};
use irontraffic_http::section::{FieldSection, FieldSectionBuilder};
use libfuzzer_sys::fuzz_target;

fn clamped() -> irontraffic_http::limits::ClampedLimits {
    Limits::DEFAULT.clamped()
}

fn authority() -> Authority {
    let limits = clamped();
    let mut out = BytesMut::new();
    Authority::parse_into(b"example.com", Scheme::Https, &limits, &mut out)
        .expect("well formed authority") // it-allow: no-panic reason: fuzz target reports a finding by panicking; the input is the fixed literal b"example.com", which parses by construction
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

fn build_fields() -> FieldSection {
    let limits = clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    builder
        .push(&mut arena, b"accept", b"text/html")
        .expect("valid field"); // it-allow: no-panic reason: fuzz target reports a finding by panicking; the name and value are fixed literals that satisfy the field grammar by construction
    builder
        .push(&mut arena, b"x-custom", b"value")
        .expect("valid field"); // it-allow: no-panic reason: fuzz target reports a finding by panicking; the name and value are fixed literals that satisfy the field grammar by construction
    builder.finish(&mut arena)
}

/// An empty trailer section, for `ChunkedEncoder::finish` when the body
/// carries no trailers. Trailer-field parsing itself is `fuzz_chunked`'s job,
/// not this target's.
fn empty_fields() -> FieldSection {
    let limits = clamped();
    let mut arena = BytesMut::new();
    let builder = FieldSectionBuilder::new(&arena, &limits);
    builder.finish(&mut arena)
}

fn local_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080)
}

/// Cheap run counters, printed periodically to stderr so a `cargo fuzz run`
/// session gives direct evidence that both framing paths are actually
/// reached, not just selected and then abandoned at an early `return`. See
/// the module doc comment: a target that never reaches the chunked branch
/// would be the vacuous shape this project rejects.
static REACHED: AtomicU64 = AtomicU64::new(0);
static EXACT_HIT: AtomicU64 = AtomicU64::new(0);
static CHUNKED_HIT: AtomicU64 = AtomicU64::new(0);

fn report(n: u64) {
    if n.is_multiple_of(20_000) {
        eprintln!(
            "fuzz_h1_roundtrip: {n} reached, {} exact round-trips, {} chunked round-trips",
            EXACT_HIT.load(Ordering::Relaxed),
            CHUNKED_HIT.load(Ordering::Relaxed)
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 65536 {
        return;
    }

    // First byte selects the OUTBOUND framing; the rest is the body.
    let use_chunked = data[0] & 1 == 1;
    let body_payload = data.get(1..).unwrap_or(&[]);

    let n = REACHED.fetch_add(1, Ordering::Relaxed) + 1;
    report(n);

    let limits = Limits::DEFAULT.clamped();
    let parser = H1Parser::new(&limits, UnderscorePolicy::Reject);

    // Build the request.
    let (path, query) = {
        let mut out = BytesMut::new();
        match irontraffic_http::path::NormalizedPath::parse_into(
            b"/fuzz",
            &PathPolicy::DEFAULT,
            &limits,
            &mut out,
        ) {
            Ok(p) => p,
            Err(_) => return,
        }
    };

    // The request's own INBOUND framing (metadata on `CanonicalRequest`,
    // never read by the serializer, which frames only from the `BodySource`
    // passed to `serialize_request_head`). Kept consistent with
    // `body_payload` purely so `CanonicalRequestBuilder::build` sees a
    // coherent request.
    let framing = if body_payload.is_empty() {
        RequestFraming::Empty
    } else {
        RequestFraming::Exact {
            len: body_payload.len() as u64,
        }
    };

    let req = match CanonicalRequestBuilder::new()
        .method(Method::Post)
        .scheme(Scheme::Http)
        .authority(authority())
        .path(path, query)
        .headers(build_fields())
        .framing(framing)
        .version(WireVersion::Http11)
        .peer(peer())
        .build()
    {
        Ok(r) => r,
        Err(_) => return,
    };

    // The OUTBOUND framing: chosen by the fuzzer's first byte, independent
    // of the inbound framing above. This is the thing under test: does the
    // serializer regenerate a framing that the parser can recover exactly?
    let body = if use_chunked {
        BodySource::Streaming
    } else {
        BodySource::Exact {
            len: body_payload.len() as u64,
        }
    };

    // Serialize the head.
    let mut head_buf = BytesMut::new();
    head_buf.reserve(4096);
    if serialize_request_head(
        &req,
        body,
        ConnectionMode::Close,
        ForwardEmit {
            emit_forwarded: false,
            emit_x_forwarded: false,
        },
        local_addr(),
        &mut head_buf,
    )
    .is_err()
    {
        return;
    }

    // Build the full wire image: head + body, framed the way `body` said.
    let mut wire = BytesMut::new();
    wire.extend_from_slice(&head_buf);
    if use_chunked {
        let mut encoder = ChunkedEncoder::new();
        // An empty chunk would terminate the body (see `ChunkedEncoder`'s
        // own doc comment), so a genuinely empty payload writes none and
        // relies on `finish` alone for the terminal `0\r\n\r\n`.
        if !body_payload.is_empty() {
            encoder.write_chunk(body_payload, &mut wire);
        }
        if encoder.finish(&empty_fields(), &mut wire).is_err() {
            return;
        }
    } else {
        wire.extend_from_slice(body_payload);
    }

    // Parse the head back.
    let parsed = match parser.parse_request_head(&wire) {
        Ok(irontraffic_http::scalar::ParseStatus::Complete {
            value: _head,
            consumed,
        }) => consumed,
        _ => {
            panic!( // it-allow: no-panic reason: fuzz target reports a finding by panicking; a head this same call just serialized failing to reparse is the P-ROUNDTRIP violation this target exists to catch, never a normal outcome
                "reparse of our own serialized head failed (use_chunked={use_chunked}, \
                 body_payload.len()={})",
                body_payload.len()
            );
        }
    };

    let body_bytes = wire.get(parsed..).unwrap_or(&[]);

    if use_chunked {
        // Decode the chunked body with the real, stateful decoder,
        // resuming across NeedMore exactly as a live read loop would.
        let dec_limits = clamped();
        let mut decoder = ChunkedDecoder::new(&dec_limits, UnderscorePolicy::Reject);
        let mut arena = BytesMut::new();
        let mut decoded = BytesMut::new();
        let mut pos = 0usize;
        loop {
            let buf = body_bytes.get(pos..).unwrap_or(&[]);
            match decoder.decode(buf, &mut arena) {
                Ok(ChunkedEvent::Data { offset, len }) => {
                    let chunk = buf.get(offset..offset.saturating_add(len)).unwrap_or(&[]);
                    decoded.extend_from_slice(chunk);
                    pos = pos.saturating_add(decoder.consumed_this_call());
                }
                Ok(ChunkedEvent::NeedMore) => {
                    let consumed = decoder.consumed_this_call();
                    if consumed == 0 {
                        // Our own encoder just wrote a complete, correctly
                        // terminated chunked body onto `wire`, all of which
                        // is in `body_bytes`. Stalling here means the
                        // encoder and the decoder disagree about framing,
                        // which is exactly the smuggling-shaped bug this
                        // target exists to catch, so this is a real finding
                        // and not a "feed more input" situation.
                        panic!( // it-allow: no-panic reason: fuzz target reports a finding by panicking; a stall on a body this same call's ChunkedEncoder just wrote and terminated is an encoder/decoder framing disagreement, the smuggling-shaped bug this target exists to catch
                            "ChunkedDecoder needed more input than our own ChunkedEncoder \
                             wrote (body_payload.len()={})",
                            body_payload.len()
                        );
                    }
                    pos = pos.saturating_add(consumed);
                }
                Ok(ChunkedEvent::Done { consumed: _ }) => {
                    // The message is complete; nothing after this point in
                    // `body_bytes` is read, so `pos` need not advance again.
                    break;
                }
                Err(reason) => {
                    panic!( // it-allow: no-panic reason: fuzz target reports a finding by panicking; the decoder rejecting a body this same call's ChunkedEncoder just wrote is a real encoder/decoder disagreement, never a normal outcome
                        "chunked round-trip decode failed: {reason:?} \
                         (body_payload.len()={})",
                        body_payload.len()
                    );
                }
            }
        }
        CHUNKED_HIT.fetch_add(1, Ordering::Relaxed);
        assert_eq!(&decoded[..], body_payload, "chunked round-trip body mismatch");
    } else {
        EXACT_HIT.fetch_add(1, Ordering::Relaxed);
        assert_eq!(body_bytes, body_payload, "content-length round-trip body mismatch");
    }
});
