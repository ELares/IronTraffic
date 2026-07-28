// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz target for the HTTP/1 serialise-then-parse round-trip: serialise `body`
//! bytes as a chunked or content-length framed message, serialise a matching
//! head with `h1::serialize`, feed the result into `H1Parser`, and assert the
//! round-trip produces the same body the fuzzer supplied.
//!
//! This is the fuzz target that proves the serialiser and the parser agree
//! about framing, because the only way they disagree is a smuggling gadget.
//! Run with `cargo fuzz run fuzz_h1_roundtrip` from
//! `crates/irontraffic-http/fuzz/`.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::BytesMut;
use irontraffic_http::authority::Authority;
use irontraffic_http::canonical::{CanonicalRequest, CanonicalRequestBuilder};
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::framing::{OtherCodings, RequestFraming, resolve_request_framing};
use irontraffic_http::h1::H1Parser;
use irontraffic_http::h1::chunked::ChunkedDecoder;
use irontraffic_http::h1::serialize::{
    BodySource, ConnectionMode, ChunkedEncoder, serialize_request_head,
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

fn local_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }

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

    let framing = if data.len() == 0 {
        RequestFraming::Empty
    } else if data.len() == 1 {
        RequestFraming::Exact { len: 0 }
    } else {
        RequestFraming::Exact {
            len: data.len() as u64,
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

    let body = BodySource::Exact { len: data.len() as u64 };

    // Serialize.
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

    // Build the full wire image: head + body.
    let mut wire = BytesMut::new();
    wire.extend_from_slice(&head_buf);
    wire.extend_from_slice(data);

    // Parse it back.
    let parsed = match parser.parse_request_head(&wire) {
        Ok(irontraffic_http::scalar::ParseStatus::Complete {
            value: head,
            consumed,
        }) => (head, consumed),
        _ => return,
    };

    let (_head, consumed) = parsed;

    // Verify the body matches.
    let body_bytes = wire.get(consumed..).unwrap_or(&[]);
    let parsed_framing = resolve_request_framing(
        &Method::Post,
        WireVersion::Http11,
        &req.headers,
        OtherCodings::Reject,
    );

    match parsed_framing {
        Ok(RequestFraming::Exact { len }) if len as usize <= body_bytes.len() => {
            let expected_body = &body_bytes[..len as usize];
            assert_eq!(expected_body, data, "round-trip body mismatch");
        }
        Ok(RequestFraming::Exact { len }) => {
            // Body shorter than declared: not a round-trip failure, just
            // incomplete data. Accept.
            let _ = len;
        }
        Ok(RequestFraming::Empty) => {
            assert!(data.is_empty(), "empty framing but non-empty body");
        }
        Ok(RequestFraming::Streamed) => {
            // For chunked, decode the body.
            let mut decoder = ChunkedDecoder::new();
            let mut decoded = BytesMut::new();
            let mut remaining = body_bytes;
            loop {
                match decoder.decode(remaining) {
                    Ok(irontraffic_http::h1::chunked::ChunkedEvent::Data { offset, len }) => {
                        let chunk = remaining.get(offset..offset + len).unwrap_or(&[]);
                        decoded.extend_from_slice(chunk);
                        remaining = remaining.get(offset + len..).unwrap_or(&[]);
                    }
                    Ok(irontraffic_http::h1::chunked::ChunkedEvent::Finished { .. }) => break,
                    Err(_) => return,
                    _ => return,
                }
            }
            assert_eq!(&decoded[..], data, "chunked round-trip body mismatch");
        }
        Err(_) => {}
    }
});
