// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for `irontraffic_ws::handshake`.
//!
//! Every test that names a REQUEST goes through [`upgrade`], which drives the real
//! HTTP/1 parse path (`H1Parser` + `canonicalize_request`) so the field section is
//! exactly what production sees, and separately builds the PRE-strip section by hand
//! (replicating `canonicalize_request`'s own field-compaction step) so `UpgradeTokens`
//! is read from evidence that still exists. A test that hand-built a `CanonicalRequest`
//! with an `Upgrade` field in it would be testing a value the type system forbids and
//! would prove nothing; see edge case 22 / test 18 below for why this matters.
//!
//! Tests that name only a RESPONSE build a `FieldSection` directly with
//! `FieldSectionBuilder`, matching `irontraffic-http/src/strip.rs`'s own test
//! convention: `UpgradeResponse::verify` takes a `&FieldSection` and `UpgradeTokens`
//! straight, with no `CanonicalResponse` in between, so there is nothing an H1 response
//! parse would add here.

use base64ct::{Base64, Encoding};
use bytes::BytesMut;
use irontraffic_http::canonical::CanonicalRequest;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::framing::OtherCodings;
use irontraffic_http::h1::H1Parser;
use irontraffic_http::h1::canonicalize::{H1Context, canonicalize_request};
use irontraffic_http::known::KnownHeader;
use irontraffic_http::path::PathPolicy;
use irontraffic_http::peer::TrustPolicy;
use irontraffic_http::scalar::ParseStatus;
use irontraffic_http::section::{FieldSection, FieldSectionBuilder};
use irontraffic_http::{Limits, Method, Scheme};
use irontraffic_ws::{
    HandshakeError, HandshakeSide, UpgradeRequest, UpgradeResponse, UpgradeTokens, accept_key,
};
use sha1::{Digest, Sha1};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// A canonical browser upgrade, built from the RFC 6455 Section 1.3 test key so its
/// accept value is the well-known vector.
const BROWSER_UPGRADE: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

const DEFAULT_TRUST: TrustPolicy = TrustPolicy::None;

fn ctx() -> H1Context<'static> {
    H1Context {
        limits: Limits::DEFAULT.clamped(),
        path_policy: PathPolicy::DEFAULT,
        codings: OtherCodings::Reject,
        underscores: UnderscorePolicy::Reject,
        scheme: Scheme::Http,
        socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        proxy_proto: None,
        trust: &DEFAULT_TRUST,
        default_authority: None,
        forward_proxy: false,
        will_buffer_body: false,
    }
}

/// Parses `head_bytes` as an HTTP/1.1 request head, builds the field section the
/// hop-by-hop strip will consume (replicating `canonicalize_request`'s own steps 1-2,
/// the only way to see the field values BEFORE the strip removes them), reads
/// `Upgrade`/`Connection` out of THAT pre-strip section into an `UpgradeTokens`, and
/// separately runs the real `canonicalize_request` to get the post-strip
/// `CanonicalRequest` production actually builds.
///
/// The pre-strip section is leaked to `'static` with `Box::leak`, the same technique
/// `irontraffic-http/src/h1/canonicalize.rs`'s own tests use for a fixture
/// (`default_auth_ref`) that must outlive the function that built it: this helper
/// returns a value borrowing from it, crossing a function boundary, and a leak in a
/// bounded test binary costs nothing that matters.
///
/// Returns `None` on any parse failure rather than panicking: `clippy::expect_used`'s
/// test-code exemption applies to functions carrying `#[test]` themselves, not to a
/// plain helper a test merely calls (see `crates/irontraffic-ws/tests/frames.rs`'s
/// `minimal_length_encoding` for the same rule against the same lint), so a shared
/// builder like this one must stay panic-free; every call site unwraps with its own
/// `.expect(...)`, which IS inside a `#[test]` function and is where the exemption
/// actually applies.
fn upgrade(head_bytes: &[u8]) -> Option<(CanonicalRequest, UpgradeTokens<'static>)> {
    let limits = Limits::DEFAULT.clamped();
    let parser = H1Parser::new(&limits, UnderscorePolicy::Reject);
    let ParseStatus::Complete { value: head, .. } = parser.parse_request_head(head_bytes).ok()?
    else {
        return None;
    };

    let mut pre_arena = BytesMut::with_capacity(16 * 1024);
    let mut pre_builder = FieldSectionBuilder::new(&pre_arena, &limits);
    for i in 0..head.field_count() {
        let name = head.field_name(i)?;
        let value = head.field_value(i)?;
        pre_builder
            .push_normalized(
                &mut pre_arena,
                name,
                UnderscorePolicy::Reject,
                value,
                head.version,
            )
            .ok()?;
    }
    let pre = pre_builder.finish(&mut pre_arena);
    let pre: &'static FieldSection = Box::leak(Box::new(pre));

    let duplicate_upgrade = pre.get_unique_known(KnownHeader::Upgrade).is_err();
    let upgrade_value = pre.get_unique_known(KnownHeader::Upgrade).ok().flatten();
    let connection_has_upgrade = irontraffic_http::strip::connection_has_token(pre, b"upgrade");
    let tokens = UpgradeTokens {
        upgrade: upgrade_value,
        connection_has_upgrade,
        duplicate_upgrade,
    };

    let mut arena = BytesMut::with_capacity(16 * 1024);
    let (req, _, _) = canonicalize_request(&head, &ctx(), &mut arena).ok()?;

    Some((req, tokens))
}

/// Builds a `FieldSection` directly from `fields`, matching
/// `irontraffic-http/src/strip.rs`'s own `section()` test helper.
///
/// Returns `None` on a malformed fixture rather than panicking, for the same reason
/// [`upgrade`] does.
fn build_section(fields: &[(&[u8], &[u8])]) -> Option<FieldSection> {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    for (name, value) in fields {
        builder.push(&mut arena, name, value).ok()?;
    }
    Some(builder.finish(&mut arena))
}

/// `UpgradeTokens` for a response `FieldSection` built directly with
/// [`build_section`], mirroring [`upgrade`]'s own construction but for a section that
/// is already in scope rather than one built from wire bytes.
fn response_tokens(headers: &FieldSection) -> UpgradeTokens<'_> {
    let duplicate_upgrade = headers.get_unique_known(KnownHeader::Upgrade).is_err();
    let upgrade_value = headers
        .get_unique_known(KnownHeader::Upgrade)
        .ok()
        .flatten();
    let connection_has_upgrade = irontraffic_http::strip::connection_has_token(headers, b"upgrade");
    UpgradeTokens {
        upgrade: upgrade_value,
        connection_has_upgrade,
        duplicate_upgrade,
    }
}

/// A well-formed accepting `101` response section for `req`, with no
/// `Sec-WebSocket-Protocol`. Returns `None` on a malformed fixture rather than
/// panicking, for the same reason [`upgrade`] does.
fn accepting_response(req: &UpgradeRequest) -> Option<FieldSection> {
    let accept = accept_key(req.key_b64());
    build_section(&[
        (b"upgrade", b"websocket"),
        (b"connection", b"Upgrade"),
        (b"sec-websocket-accept", &accept[..]),
    ])
}

#[test]
fn rfc_6455_accept_vector() {
    let key_b64 = *b"dGhlIHNhbXBsZSBub25jZQ==";
    assert_eq!(accept_key(&key_b64), *b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn accept_is_not_the_decoded_key() {
    let key_b64 = *b"dGhlIHNhbXBsZSBub25jZQ==";
    let correct = accept_key(&key_b64);

    // The specific bug RFC 6455 Section 4.2.2 warns against: hashing the DECODED
    // key bytes ("the sample nonce", the 16 raw bytes `key_b64` decodes to) plus
    // the GUID, instead of the base64 STRING plus the GUID.
    let decoded_key = *b"the sample nonce";
    let mut hasher = Sha1::new();
    hasher.update(decoded_key);
    hasher.update(irontraffic_ws::handshake::WS_GUID);
    let digest = hasher.finalize();
    let mut wrong = [0_u8; 28];
    Base64::encode(&digest[..], &mut wrong).expect("a 28-byte buffer fits a 20-byte digest");

    assert_ne!(correct, wrong);
}

#[test]
fn valid_upgrade_parses() {
    let (req, tokens) = upgrade(BROWSER_UPGRADE).expect("test fixture must parse and canonicalize");
    let parsed = UpgradeRequest::parse(&req, tokens)
        .expect("valid upgrade must parse")
        .expect("must be an upgrade");
    assert_eq!(parsed.key_b64(), b"dGhlIHNhbXBsZSBub25jZQ==");
    assert_eq!(parsed.key(), b"the sample nonce");
    assert_eq!(parsed.subprotocols().count(), 0);
}

#[test]
fn non_upgrade_is_none() {
    let (req, tokens) = upgrade(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .expect("test fixture must parse and canonicalize");
    assert_eq!(UpgradeRequest::parse(&req, tokens), Ok(None));
}

#[test]
fn connection_token_table() {
    // The eight rows the issue names, over the `upgrade` token itself.
    let rows: &[(Option<&str>, bool)] = &[
        (Some("Upgrade"), true),
        (Some("upgrade"), true),
        (Some("keep-alive, Upgrade"), true),
        (Some("Upgrade, keep-alive"), true),
        (Some("Upgraded"), false),
        (Some("upgrad"), false),
        (Some(""), false),
        (None, false),
    ];
    for (value, accepted) in rows {
        let mut head =
            String::from("GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n");
        if let Some(v) = value {
            head.push_str("Connection: ");
            head.push_str(v);
            head.push_str("\r\n");
        }
        head.push_str(
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        );
        let (req, tokens) =
            upgrade(head.as_bytes()).expect("test fixture must parse and canonicalize");
        if *accepted {
            assert!(
                UpgradeRequest::parse(&req, tokens).unwrap().is_some(),
                "{value:?} must be accepted"
            );
        } else {
            assert_eq!(
                UpgradeRequest::parse(&req, tokens).unwrap_err(),
                HandshakeError::ConnectionTokenMissing,
                "{value:?} must be refused"
            );
        }
    }

    // The SAME eight shapes, re-spelled against a token that is NOT also a member
    // of `strip_ingress`'s static hop-by-hop set (unlike `upgrade` and
    // `keep-alive`, both of which `strip_ingress` removes unconditionally
    // regardless of what `Connection` says, so whether a field literally named
    // `upgrade` survives the strip tells us nothing about the connection-named
    // removal path specifically). This is what proves `connection_has_token` and
    // `strip_ingress`'s own token matching cannot drift: for every row, a custom
    // field named after the row's token is removed by `strip_ingress` if and only
    // if `connection_has_token` says the `Connection` value names it.
    let custom_rows: &[(Option<&str>, bool)] = &[
        (Some("X-Custom-Marker"), true),
        (Some("x-custom-marker"), true),
        (Some("keep-alive, X-Custom-Marker"), true),
        (Some("X-Custom-Marker, keep-alive"), true),
        (Some("X-Custom-Markerx"), false),
        (Some("x-custom-marke"), false),
        (Some(""), false),
        (None, false),
    ];
    let limits = Limits::DEFAULT.clamped();
    for (value, names_it) in custom_rows {
        let fields: Vec<(&[u8], &[u8])> = match value {
            Some(v) => vec![
                (b"connection".as_slice(), v.as_bytes()),
                (b"x-custom-marker", b"z"),
                (b"host", b"h"),
            ],
            None => vec![(b"x-custom-marker".as_slice(), b"z"), (b"host", b"h")],
        };
        let mut sec = build_section(&fields).expect("test fixture fields must be valid");
        let has_token = irontraffic_http::strip::connection_has_token(&sec, b"x-custom-marker");
        assert_eq!(
            has_token, *names_it,
            "connection_has_token disagrees for {value:?}"
        );

        let report = irontraffic_http::strip::strip_ingress(&mut sec, &limits)
            .expect("test fixture connection value must be well formed");
        let removed_by_connection = report.connection_named > 0;
        assert_eq!(
            has_token, removed_by_connection,
            "connection_has_token and strip_ingress disagree for {value:?}"
        );
    }
}

#[test]
fn upgrade_value_table() {
    let head = |value: &str| -> Vec<u8> {
        format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: {value}\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .into_bytes()
    };

    for value in ["websocket", "WebSocket", "WEBSOCKET", "websocket "] {
        let (req, tokens) =
            upgrade(&head(value)).expect("test fixture must parse and canonicalize");
        assert!(
            UpgradeRequest::parse(&req, tokens).unwrap().is_some(),
            "{value:?} must be accepted"
        );
    }

    for value in ["websocket, h2c", "h2c", "web socket"] {
        let (req, tokens) =
            upgrade(&head(value)).expect("test fixture must parse and canonicalize");
        assert_eq!(
            UpgradeRequest::parse(&req, tokens).unwrap_err(),
            HandshakeError::UpgradeTokenNotWebsocket,
            "{value:?} must be refused"
        );
    }
}

#[test]
fn method_and_body_table() {
    let head = |method: &str, extra: &str| -> Vec<u8> {
        format!(
            "{method} / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
        )
        .into_bytes()
    };

    let (req, tokens) =
        upgrade(&head("POST", "")).expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::MethodNotGet {
            method: Method::Post
        }
    );

    let (req, tokens) = upgrade(&head("GET", "Content-Length: 5\r\n"))
        .expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::UpgradeWithBody
    );

    let (req, tokens) = upgrade(&head("GET", "Content-Length: 0\r\n"))
        .expect("test fixture must parse and canonicalize");
    assert!(UpgradeRequest::parse(&req, tokens).unwrap().is_some());

    let (req, tokens) =
        upgrade(&head("PUT", "")).expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::MethodNotGet {
            method: Method::Put
        }
    );
}

#[test]
fn version_table() {
    let head = |version: Option<&str>| -> Vec<u8> {
        let mut h = String::from(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        );
        if let Some(v) = version {
            h.push_str("Sec-WebSocket-Version: ");
            h.push_str(v);
            h.push_str("\r\n");
        }
        h.push_str("\r\n");
        h.into_bytes()
    };

    let (req, tokens) =
        upgrade(&head(Some("13"))).expect("test fixture must parse and canonicalize");
    assert!(UpgradeRequest::parse(&req, tokens).unwrap().is_some());

    for (v, found) in [("8", 8_u32), ("0", 0), ("14", 14)] {
        let (req, tokens) =
            upgrade(&head(Some(v))).expect("test fixture must parse and canonicalize");
        assert_eq!(
            UpgradeRequest::parse(&req, tokens).unwrap_err(),
            HandshakeError::UnsupportedVersion { found },
            "version {v:?}"
        );
    }

    let (req, tokens) = upgrade(&head(None)).expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::VersionMissing
    );

    let (req, tokens) =
        upgrade(&head(Some("13abc"))).expect("test fixture must parse and canonicalize");
    assert!(matches!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::Field(_)
    ));
}

#[test]
fn version_error_is_426() {
    let err = HandshakeError::UnsupportedVersion { found: 8 };
    assert_eq!(err.status(HandshakeSide::Request), 426);
    assert_eq!(err.status(HandshakeSide::Response), 502);
}

#[test]
fn key_table() {
    let head = |key: Option<&str>| -> Vec<u8> {
        let mut h = String::from(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n",
        );
        if let Some(k) = key {
            h.push_str("Sec-WebSocket-Key: ");
            h.push_str(k);
            h.push_str("\r\n");
        }
        h.push_str("\r\n");
        h.into_bytes()
    };

    // A valid 24-character key.
    let (req, tokens) = upgrade(&head(Some("dGhlIHNhbXBsZSBub25jZQ==")))
        .expect("test fixture must parse and canonicalize");
    assert!(UpgradeRequest::parse(&req, tokens).unwrap().is_some());

    // 23 characters (one short of the trailing `=`).
    let (req, tokens) = upgrade(&head(Some("dGhlIHNhbXBsZSBub25jZQ=")))
        .expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::KeyWrongLength { len: 23 }
    );

    // 25 characters (one past the valid key).
    let (req, tokens) = upgrade(&head(Some("dGhlIHNhbXBsZSBub25jZQ==A")))
        .expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::KeyWrongLength { len: 25 }
    );

    // 24 characters with a `!`, not in the base64 alphabet.
    let (req, tokens) = upgrade(&head(Some("!GhlIHNhbXBsZSBub25jZQ==")))
        .expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::KeyNotBase64
    );

    // An empty key.
    let (req, tokens) = upgrade(&head(Some(""))).expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::KeyWrongLength { len: 0 }
    );

    // Absent.
    let (req, tokens) = upgrade(&head(None)).expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::KeyMissing
    );
}

#[test]
fn too_many_subprotocols() {
    // Nine offered.
    let nine = "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: p0, p1, p2, p3, p4, p5, p6, p7, p8\r\n\r\n";
    let (req, tokens) = upgrade(nine.as_bytes()).expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::TooManySubprotocols
    );

    // Eight is accepted, all eight readable in order, and still readable after the
    // source request buffer that produced them has been dropped: the inline copy
    // is what this proves.
    let parsed_eight = {
        let eight = String::from(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: p0, p1, p2, p3, p4, p5, p6, p7\r\n\r\n",
        )
        .into_bytes();
        let (req, tokens) = upgrade(&eight).expect("test fixture must parse and canonicalize");
        UpgradeRequest::parse(&req, tokens).unwrap().unwrap()
        // `eight`, `req` and `tokens` are all dropped here.
    };
    let names: Vec<&[u8]> = parsed_eight.subprotocols().collect();
    assert_eq!(
        names,
        vec![
            b"p0".as_slice(),
            b"p1",
            b"p2",
            b"p3",
            b"p4",
            b"p5",
            b"p6",
            b"p7"
        ]
    );

    // Eight names totalling 257 bytes: seven of 32 bytes plus one of 33.
    let mut names: Vec<String> = (0..7).map(|_| "a".repeat(32)).collect();
    names.push("a".repeat(33));
    let joined = names.join(", ");
    let head = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {joined}\r\n\r\n"
    );
    let (req, tokens) = upgrade(head.as_bytes()).expect("test fixture must parse and canonicalize");
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::SubprotocolListTooLong { len: 257 }
    );
}

#[test]
fn response_accept_mismatch() {
    let (req, tokens) = upgrade(BROWSER_UPGRADE).expect("test fixture must parse and canonicalize");
    let upgrade_req = UpgradeRequest::parse(&req, tokens).unwrap().unwrap();
    let mut accept = accept_key(upgrade_req.key_b64());
    accept[0] = if accept[0] == b'a' { b'b' } else { b'a' };
    let headers = build_section(&[
        (b"upgrade", b"websocket"),
        (b"connection", b"Upgrade"),
        (b"sec-websocket-accept", &accept[..]),
    ])
    .expect("test fixture fields must be valid");
    let htokens = response_tokens(&headers);
    let err = UpgradeResponse::verify(&upgrade_req, 101, &headers, htokens).unwrap_err();
    assert_eq!(err, HandshakeError::AcceptMismatch);
    assert_eq!(err.status(HandshakeSide::Response), 502);
}

#[test]
fn response_wrong_status() {
    let (req, tokens) = upgrade(BROWSER_UPGRADE).expect("test fixture must parse and canonicalize");
    let upgrade_req = UpgradeRequest::parse(&req, tokens).unwrap().unwrap();
    let headers = accepting_response(&upgrade_req).expect("test fixture response must be valid");
    let htokens = response_tokens(&headers);
    for status in [200_u16, 204, 400, 500] {
        let err = UpgradeResponse::verify(&upgrade_req, status, &headers, htokens).unwrap_err();
        assert_eq!(err, HandshakeError::NotSwitchingProtocols { status });
    }
}

#[test]
fn response_unrequested_extension() {
    let (req, tokens) = upgrade(BROWSER_UPGRADE).expect("test fixture must parse and canonicalize");
    let upgrade_req = UpgradeRequest::parse(&req, tokens).unwrap().unwrap();
    let accept = accept_key(upgrade_req.key_b64());
    let headers = build_section(&[
        (b"upgrade", b"websocket"),
        (b"connection", b"Upgrade"),
        (b"sec-websocket-accept", &accept[..]),
        (b"sec-websocket-extensions", b"permessage-deflate"),
    ])
    .expect("test fixture fields must be valid");
    let htokens = response_tokens(&headers);
    let err = UpgradeResponse::verify(&upgrade_req, 101, &headers, htokens).unwrap_err();
    assert_eq!(err, HandshakeError::UnrequestedExtension);
}

#[test]
fn response_unoffered_subprotocol() {
    let head = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: superchat\r\n\r\n";
    let (req, tokens) = upgrade(head).expect("test fixture must parse and canonicalize");
    let upgrade_req = UpgradeRequest::parse(&req, tokens).unwrap().unwrap();
    let accept = accept_key(upgrade_req.key_b64());

    // The upstream selects "chat", which was never offered.
    let bad = build_section(&[
        (b"upgrade", b"websocket"),
        (b"connection", b"Upgrade"),
        (b"sec-websocket-accept", &accept[..]),
        (b"sec-websocket-protocol", b"chat"),
    ])
    .expect("test fixture fields must be valid");
    let bad_tokens = response_tokens(&bad);
    assert_eq!(
        UpgradeResponse::verify(&upgrade_req, 101, &bad, bad_tokens).unwrap_err(),
        HandshakeError::UnofferedSubprotocol
    );

    // The upstream selects "superchat", which WAS offered: accepted, and the
    // returned range resolves, via the section's own slot data (ground truth
    // independent of this module's own computation), to exactly the
    // `sec-websocket-protocol` slot.
    let good = build_section(&[
        (b"upgrade", b"websocket"),
        (b"connection", b"Upgrade"),
        (b"sec-websocket-accept", &accept[..]),
        (b"sec-websocket-protocol", b"superchat"),
    ])
    .expect("test fixture fields must be valid");
    let good_tokens = response_tokens(&good);
    let ok = UpgradeResponse::verify(&upgrade_req, 101, &good, good_tokens).unwrap();
    let slot = good
        .slots()
        .iter()
        .enumerate()
        .find(|(i, _)| good.name_at(*i) == Some(b"sec-websocket-protocol".as_slice()))
        .map(|(_, s)| *s)
        .expect("sec-websocket-protocol slot exists");
    let expected_start = u16::try_from(slot.value_off).unwrap();
    let expected_end =
        u16::try_from(u64::from(slot.value_off).saturating_add(u64::from(slot.value_len))).unwrap();
    assert_eq!(
        ok.selected_subprotocol,
        Some((expected_start, expected_end))
    );

    // Selecting none is legal.
    let none = build_section(&[
        (b"upgrade", b"websocket"),
        (b"connection", b"Upgrade"),
        (b"sec-websocket-accept", &accept[..]),
    ])
    .expect("test fixture fields must be valid");
    let none_tokens = response_tokens(&none);
    let ok_none = UpgradeResponse::verify(&upgrade_req, 101, &none, none_tokens).unwrap();
    assert_eq!(ok_none.selected_subprotocol, None);
}

#[test]
fn h2c_upgrade_is_refused() {
    let head = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAA\r\n\r\n";
    let (req, tokens) = upgrade(head).expect("test fixture must parse and canonicalize");
    assert!(matches!(
        req.headers.get_unique(b"http2-settings"),
        Ok(None)
    ));
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::UpgradeTokenNotWebsocket
    );
}

#[test]
fn no_allocation_in_the_handshake() {
    // The issue asks for this proven "with an allocation counter installed". Per
    // CODER-PROMPT.md's standing rule for this corpus (matching this crate's own
    // `no_allocation_in_the_codec` in tests/frames.rs, written for the same reason
    // against ws-crate-and-frame-codec, #202): `irontraffic-ws` carries
    // `#![forbid(unsafe_code)]`, `GlobalAlloc` is an `unsafe trait`, so a counting
    // `#[global_allocator]` cannot compile here, and a process-wide one would count
    // allocations made by every other test in the same binary regardless of
    // legality. The proof is static instead: `UpgradeResponse` is `Copy`, which
    // means it cannot own a heap allocation, and a text scan of handshake.rs's own
    // PRODUCTION code (everything before its `#[cfg(test)]` module, which
    // legitimately builds owned fixtures) for the allocating-call vocabulary finds
    // none. What follows is the volume half of the test the issue asks for: 10,000
    // parse-plus-verify round trips, real coverage against a panic or an incorrect
    // result at scale, independent of the allocation question.
    const fn assert_copy<T: Copy>() {}
    assert_copy::<UpgradeResponse>();

    let source = include_str!("../src/handshake.rs");
    let production_with_comments = source
        .split("#[cfg(test)]")
        .next()
        .expect("handshake.rs always has a segment before its first #[cfg(test)]");
    // Comment lines are stripped before the scan: this module's own doc comments
    // explain, in prose, exactly why `#[from]` is not used (naming `format!("{err}")`
    // as the reason `RejectReason` withholds `Display`), and a scan that could not
    // tell prose from code would fail on its own documentation.
    let production: String = production_with_comments
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "with_capacity",
        "Vec::new",
        "String::new",
        ".to_vec()",
        ".to_owned()",
        "format!",
        ".collect(",
        "Box::new",
    ] {
        assert!(
            !production.contains(needle),
            "handshake.rs's production code contains `{needle}`, which can allocate"
        );
    }

    let (req, tokens) = upgrade(BROWSER_UPGRADE).expect("test fixture must parse and canonicalize");
    let baseline = UpgradeRequest::parse(&req, tokens).unwrap().unwrap();
    let headers = accepting_response(&baseline).expect("test fixture response must be valid");
    let htokens = response_tokens(&headers);

    for _ in 0_u32..10_000 {
        let parsed = UpgradeRequest::parse(&req, tokens).unwrap().unwrap();
        assert_eq!(parsed.key(), baseline.key());
        let verified = UpgradeResponse::verify(&parsed, 101, &headers, htokens).unwrap();
        assert_eq!(verified.selected_subprotocol, None);
    }
}

#[test]
fn canonical_request_carries_no_upgrade_evidence() {
    let (req, tokens) = upgrade(BROWSER_UPGRADE).expect("test fixture must parse and canonicalize");
    assert!(matches!(req.headers.get_unique(b"upgrade"), Ok(None)));
    assert!(matches!(req.headers.get_unique(b"connection"), Ok(None)));
    assert_eq!(
        UpgradeRequest::parse(&req, UpgradeTokens::default()),
        Ok(None)
    );
    assert!(matches!(UpgradeRequest::parse(&req, tokens), Ok(Some(_))));
}

#[test]
fn response_tokens_are_required_too() {
    let (req, tokens) = upgrade(BROWSER_UPGRADE).expect("test fixture must parse and canonicalize");
    let upgrade_req = UpgradeRequest::parse(&req, tokens).unwrap().unwrap();
    let headers = accepting_response(&upgrade_req).expect("test fixture response must be valid");
    let err =
        UpgradeResponse::verify(&upgrade_req, 101, &headers, UpgradeTokens::default()).unwrap_err();
    assert_eq!(err, HandshakeError::UpgradeTokenNotWebsocket);
    assert_eq!(err.status(HandshakeSide::Response), 502);
}

/// Not one of the 19 named tests: RFC 6455 Section 4.4 permits (and requires) two
/// `Upgrade` field lines to be a rejection rather than a silent choice, per edge
/// case 7 and invariant 1 of the module's own issue. None of the 19 named tests
/// exercises `UpgradeTokens::duplicate_upgrade` directly, so this pins it.
#[test]
fn duplicate_upgrade_field_is_refused() {
    let head = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let (req, tokens) = upgrade(head).expect("test fixture must parse and canonicalize");
    assert!(
        tokens.duplicate_upgrade,
        "the helper must observe the duplicate Upgrade line"
    );
    assert_eq!(
        UpgradeRequest::parse(&req, tokens).unwrap_err(),
        HandshakeError::DuplicateUpgrade
    );
}

/// Not one of the 19 named tests: RFC 9110 Section 5.6.1's `#list` grammar says an
/// empty element does not contribute to the count of elements present, the same
/// rule `irontraffic_http::strip::collect_connection_tokens` applies to `Connection`
/// tokens. `Sec-WebSocket-Protocol` is the same `#list` shape, so an empty element
/// here must be skipped rather than stored as a zero-length name or counted against
/// `MAX_SUBPROTOCOLS`.
#[test]
fn subprotocol_empty_elements_are_skipped() {
    let head = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat,,superchat\r\n\r\n";
    let (req, tokens) = upgrade(head).expect("test fixture must parse and canonicalize");
    let parsed = UpgradeRequest::parse(&req, tokens).unwrap().unwrap();
    let names: Vec<&[u8]> = parsed.subprotocols().collect();
    assert_eq!(names, vec![b"chat".as_slice(), b"superchat"]);
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: 1024,
        ..proptest::prelude::ProptestConfig::default()
    })]

    #[test]
    fn prop_accept_roundtrip(
        key_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 16..=16),
        other_bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 16..=16),
    ) {
        let mut key_arr = [0_u8; 16];
        key_arr.copy_from_slice(&key_bytes);
        let mut other_arr = [0_u8; 16];
        other_arr.copy_from_slice(&other_bytes);

        let mut key_b64 = [0_u8; 24];
        Base64::encode(&key_arr, &mut key_b64).expect("a 24-byte buffer fits a 16-byte key");
        let accept = accept_key(&key_b64);

        let mut decoded = [0_u8; 20];
        let result = Base64::decode(accept, &mut decoded);
        proptest::prop_assert!(result.is_ok());
        proptest::prop_assert_eq!(result.unwrap().len(), 20);

        if key_arr != other_arr {
            let mut other_b64 = [0_u8; 24];
            Base64::encode(&other_arr, &mut other_b64).expect("a 24-byte buffer fits a 16-byte key");
            let other_accept = accept_key(&other_b64);
            proptest::prop_assert_ne!(accept, other_accept);
        }
    }
}
