// SPDX-License-Identifier: MIT OR Apache-2.0
//! Convert a parsed HTTP/1 head into a [`CanonicalRequest`] or
//! [`CanonicalResponse`], compacting every name and value into a caller-supplied
//! arena so the read buffer can return to the pool.
//!
//! This is the assembly boundary for HTTP/1: method parsing, field compaction,
//! the `Host` rule, target-form classification, path normalization, authority
//! reconciliation, framing resolution, forwarding-chain resolution, the
//! `Expect` policy, the hop-by-hop strip and the invariant-checking build all
//! happen here, in a fixed order that is itself a security property.

use std::net::SocketAddr;

use bytes::BytesMut;

use crate::authority::{Authority, reconcile_authority};
use crate::canonical::{CanonicalRequest, CanonicalRequestBuilder, CanonicalResponse};
use crate::error::RejectReason;
use crate::expect::{ExpectAction, check_expect};
use crate::field::UnderscorePolicy;
use crate::forwarded::ForwardedChain;
use crate::framing::{OtherCodings, resolve_request_framing};
use crate::h1::parser::{RawHead, RawResponseHead};
use crate::known::KnownHeader;
use crate::limits::ClampedLimits;
use crate::path::{NormalizedPath, PathPolicy, TargetForm};
use crate::peer::{TrustPolicy, resolve_identity};
use crate::response::resolve_response_framing;
use crate::scalar::{Method, Scheme};
use crate::section::FieldSectionBuilder;
use crate::strip;

/// Everything about the connection and the configuration that the head itself does
/// not carry. Built once per connection by the caller, not per request.
#[derive(Clone, Debug)]
pub struct H1Context<'c> {
    /// Limits for this listener.
    pub limits: ClampedLimits,
    /// Path normalization policy for this listener.
    pub path_policy: PathPolicy,
    /// Transfer-coding policy for this listener.
    pub codings: OtherCodings,
    /// Underscore policy for this listener.
    pub underscores: UnderscorePolicy,
    /// `Http` for a plaintext listener, `Https` for a TLS one.
    pub scheme: Scheme,
    /// The socket peer address.
    pub socket_peer: SocketAddr,
    /// The source address a validated PROXY protocol header declared, when the listener
    /// uses PROXY protocol.
    pub proxy_proto: Option<SocketAddr>,
    /// How much of the forwarding chain to believe.
    pub trust: &'c TrustPolicy,
    /// Authority to use when an HTTP/1.0 request omits `Host`.
    pub default_authority: Option<&'c Authority>,
    /// True only on a listener explicitly configured as a forward proxy.
    pub forward_proxy: bool,
    /// True when some route-compiled feature will buffer the request body, which decides
    /// whether we answer `100 Continue` ourselves.
    pub will_buffer_body: bool,
}

/// Resolves the authority for an authority-form or absolute-form target, refusing
/// a mismatch with an explicit `Host` field.
///
/// The target authority is parsed once. When a `Host` field is also present it is
/// parsed separately and the two canonical authorities are compared. This helper
/// keeps the extra parse on the absolute/authority branch so the common origin
/// path pays for exactly one authority resolution.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "ClampedLimits is Copy but Authority::parse_into takes &ClampedLimits and this \
              function passes limits through without owning it"
)]
fn resolve_target_authority(
    target_authority_bytes: &[u8],
    host_field: Option<&[u8]>,
    scheme: Scheme,
    limits: &ClampedLimits,
    arena: &mut BytesMut,
) -> Result<Authority, RejectReason> {
    let target_auth = Authority::parse_into(target_authority_bytes, scheme, limits, arena)?;
    if let Some(host_bytes) = host_field {
        let host_auth = Authority::parse_into(host_bytes, scheme, limits, arena)?;
        if host_auth != target_auth {
            return Err(RejectReason::AuthorityMismatch);
        }
    }
    Ok(target_auth)
}

/// Splits an absolute-form target into its authority and path-and-query portions,
/// refusing schemes other than `http` and `https`.
fn split_absolute_target(raw: &[u8]) -> Result<(&[u8], &[u8]), RejectReason> {
    let scheme_end = raw
        .windows(3)
        .position(|w| w == b"://")
        .ok_or(RejectReason::TargetFormInvalid)?;
    let scheme = raw
        .get(..scheme_end)
        .ok_or(RejectReason::TargetFormInvalid)?;
    if !scheme.eq_ignore_ascii_case(b"http") && !scheme.eq_ignore_ascii_case(b"https") {
        return Err(RejectReason::TargetFormInvalid);
    }
    let after_scheme = raw
        .get(scheme_end.saturating_add(3)..)
        .ok_or(RejectReason::TargetFormInvalid)?;
    let auth_end = after_scheme
        .iter()
        .position(|&b| b == b'/' || b == b'?' || b == b'#')
        .unwrap_or(after_scheme.len());
    let authority = after_scheme
        .get(..auth_end)
        .ok_or(RejectReason::TargetFormInvalid)?;
    let path_and_query = if auth_end == after_scheme.len() {
        &b"/"[..]
    } else {
        after_scheme
            .get(auth_end..)
            .ok_or(RejectReason::TargetFormInvalid)?
    };
    Ok((authority, path_and_query))
}

/// Turns a parsed HTTP/1 head into the canonical request, compacting the head into
/// `arena` so the read buffer can be returned to the pool.
///
/// Runs, in this order: method, compaction, the `Host` rule, target-form classification,
/// path normalization, authority reconciliation, framing resolution, forwarding-chain
/// resolution, the `Expect` policy, the hop-by-hop strip, and the invariant-checking
/// build. The order is a security property: framing, the chain and `Expect` read fields
/// that the strip deletes.
///
/// # Errors
/// Every `RejectReason` the constituent steps can return, notably `HostMissing`,
/// `HostDuplicate`, `TargetFormInvalid`, `AuthorityMismatch` and `ExpectUnsupported`.
#[allow(
    clippy::too_many_lines,
    reason = "one linear twelve-step assembly over one head; splitting it would scatter the \
              step ordering the design and its edge cases both depend on across several \
              functions with no clearer seam"
)]
pub fn canonicalize_request(
    head: &RawHead<'_>,
    ctx: &H1Context<'_>,
    arena: &mut BytesMut,
) -> Result<(CanonicalRequest, ExpectAction, TargetForm), RejectReason> {
    // Step 1: method.
    let method = Method::parse(head.method_bytes(), &ctx.limits)?;

    // Step 2: compact the fields into the arena.
    let mut builder = FieldSectionBuilder::new(arena, &ctx.limits);
    for i in 0..head.field_count() {
        // A field whose bytes cannot be read REFUSES the request. Substituting b""
        // would silently forward a field with an empty value, which is a different
        // request from the one the peer sent.
        let (Some(name), Some(value)) = (head.field_name(i), head.field_value(i)) else {
            return Err(RejectReason::FieldNameInvalidByte);
        };
        builder.push_normalized(arena, name, ctx.underscores, value, head.version)?;
    }
    let mut fields = builder.finish(arena);

    // Step 3: the zero-or-more-than-one `Host` rule.
    let host_count = fields.count_known(KnownHeader::Host);
    if host_count > 1 {
        return Err(RejectReason::HostDuplicate);
    }

    // Step 4: target-form classification.
    let form = crate::path::classify_target(head.target_bytes(), &method)?;

    // Step 5/6: path normalization and authority resolution, together because both
    // depend on the target form.
    let (path, query, authority) = match form {
        TargetForm::Origin => {
            let (p, q) = NormalizedPath::parse_into(
                head.target_bytes(),
                &ctx.path_policy,
                &ctx.limits,
                arena,
            )?;
            let Some(host_value) = host_field(&fields, ctx.default_authority)? else {
                return Err(RejectReason::HostMissing);
            };
            let a = reconcile_authority(
                Some(host_value),
                None,
                ctx.scheme,
                head.version,
                &ctx.limits,
                arena,
            )?;
            (p, q, a)
        }
        TargetForm::Asterisk => {
            let Some(host_value) = host_field(&fields, ctx.default_authority)? else {
                return Err(RejectReason::HostMissing);
            };
            let a = reconcile_authority(
                Some(host_value),
                None,
                ctx.scheme,
                head.version,
                &ctx.limits,
                arena,
            )?;
            (NormalizedPath::root(), None, a)
        }
        TargetForm::Authority => {
            let target = head.target_bytes();
            if target.starts_with(b"/") {
                // CONNECT with an origin-form target is not authority-form.
                return Err(RejectReason::TargetFormInvalid);
            }
            let host = host_field(&fields, None)?;
            let a = resolve_target_authority(target, host, ctx.scheme, &ctx.limits, arena)?;
            (NormalizedPath::root(), None, a)
        }
        TargetForm::Absolute => {
            if !ctx.forward_proxy {
                return Err(RejectReason::TargetFormInvalid);
            }
            let (authority_bytes, path_and_query) = split_absolute_target(head.target_bytes())?;
            let (p, q) =
                NormalizedPath::parse_into(path_and_query, &ctx.path_policy, &ctx.limits, arena)?;
            let host = host_field(&fields, None)?;
            let a =
                resolve_target_authority(authority_bytes, host, ctx.scheme, &ctx.limits, arena)?;
            (p, q, a)
        }
    };

    // Step 7: framing.
    let framing = resolve_request_framing(&method, head.version, &fields, ctx.codings)?;

    // Step 8: forwarding chain and identity.
    let chain = ForwardedChain::from_section(&fields, &ctx.limits, arena)?;
    let peer = resolve_identity(ctx.socket_peer, ctx.proxy_proto, &chain, ctx.trust);

    // Step 9: Expect.
    let expect_action = check_expect(&fields, ctx.will_buffer_body)?;
    if expect_action == ExpectAction::AnswerLocally {
        fields.remove_known(KnownHeader::Expect);
    }

    // Step 10: strip hop-by-hop and identity fields.
    strip::strip_ingress(&mut fields, &ctx.limits)?;

    // Step 11: build.
    let request = CanonicalRequestBuilder::new()
        .method(method)
        .scheme(ctx.scheme)
        .authority(authority)
        .path(path, query)
        .headers(fields)
        .framing(framing)
        .version(head.version)
        .peer(peer)
        .build()?;

    Ok((request, expect_action, form))
}

/// Returns the `Host` field value when present, or the listener's default authority
/// host bytes when it is not. Returns `Ok(None)` only when the caller has supplied
/// no default and the section has no `Host`; callers turn that into `HostMissing`.
fn host_field<'a>(
    fields: &'a crate::section::FieldSection,
    default_authority: Option<&'a Authority>,
) -> Result<Option<&'a [u8]>, RejectReason> {
    let from_field = fields
        .get_unique_known(KnownHeader::Host)
        .map_err(|_| RejectReason::HostDuplicate)?;
    Ok(match (from_field, default_authority) {
        (Some(v), _) => Some(v),
        (None, Some(d)) => Some(d.host()),
        (None, None) => None,
    })
}

/// Turns a parsed HTTP/1 response head into the canonical response, and returns the
/// `Content-Length` the UPSTREAM declared, captured before `strip_response` deletes it.
///
/// That second element exists for exactly one consumer: a response to `HEAD` must carry
/// downstream the length a `GET` would have returned (`h1-request-serializer` (#37)
/// step 2). It is `None` when the upstream declared none. It is NOT a body length: the
/// body length is `CanonicalResponse::framing`, and nothing may size a buffer, a
/// reservation or a timeout from this value.
///
/// # Errors
/// Every `RejectReason` `resolve_response_framing` and the field validators can return.
pub fn canonicalize_response(
    head: &RawResponseHead<'_>,
    request_method: &Method,
    ctx: &H1Context<'_>,
    arena: &mut BytesMut,
) -> Result<(CanonicalResponse, Option<u64>), RejectReason> {
    // Step 1: compact the fields.
    let mut builder = FieldSectionBuilder::new(arena, &ctx.limits);
    for i in 0..head.field_count() {
        let (Some(name), Some(value)) = (head.field_name(i), head.field_value(i)) else {
            return Err(RejectReason::FieldNameInvalidByte);
        };
        builder.push_normalized(arena, name, ctx.underscores, value, head.version)?;
    }
    let mut fields = builder.finish(arena);

    // Step 2: framing.
    let framing = resolve_response_framing(
        head.status,
        request_method,
        head.version,
        &fields,
        ctx.codings,
    )?;

    // Step 3: capture the upstream's declared length before the strip deletes it.
    let declared_len = match fields.get_unique(b"content-length") {
        Ok(None) => None,
        Ok(Some(value)) => Some(crate::framing::parse_content_length(value)?),
        Err(_) => return Err(RejectReason::ContentLengthDuplicate),
    };

    // Step 4: strip.
    strip::strip_response(&mut fields, &ctx.limits)?;

    // Step 5: build.
    let response = CanonicalResponse::new(head.status, fields, framing, head.version)?;

    Ok((response, declared_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;
    use crate::field::UnderscorePolicy;
    use crate::framing::RequestFraming;
    use crate::h1::H1Parser;
    use crate::peer::IdentitySource;
    use crate::response::ResponseFraming;
    use crate::scalar::ParseStatus;
    use bytes::BytesMut;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const DEFAULT_TRUST: TrustPolicy = TrustPolicy::None;

    fn parse_request_head(buf: &[u8], underscores: UnderscorePolicy) -> RawHead<'_> {
        let parser = H1Parser::new(&Limits::DEFAULT.clamped(), underscores);
        match parser.parse_request_head(buf).unwrap() {
            ParseStatus::Complete { value, .. } => value,
            ParseStatus::Partial => panic!("unexpected partial request head"),
        }
    }

    fn try_parse_request_head(
        buf: &[u8],
        underscores: UnderscorePolicy,
    ) -> Result<RawHead<'_>, RejectReason> {
        let parser = H1Parser::new(&Limits::DEFAULT.clamped(), underscores);
        match parser.parse_request_head(buf)? {
            ParseStatus::Complete { value, .. } => Ok(value),
            ParseStatus::Partial => panic!("unexpected partial request head"),
        }
    }

    fn parse_response_head(buf: &[u8], underscores: UnderscorePolicy) -> RawResponseHead<'_> {
        let parser = H1Parser::new(&Limits::DEFAULT.clamped(), underscores);
        match parser.parse_response_head(buf).unwrap() {
            ParseStatus::Complete { value, .. } => value,
            ParseStatus::Partial => panic!("unexpected partial response head"),
        }
    }

    fn ctx_with(
        scheme: Scheme,
        forward_proxy: bool,
        will_buffer_body: bool,
        default_authority: Option<&'static Authority>,
        trust: &'static TrustPolicy,
        underscores: UnderscorePolicy,
    ) -> H1Context<'static> {
        H1Context {
            limits: Limits::DEFAULT.clamped(),
            path_policy: PathPolicy::DEFAULT,
            codings: OtherCodings::Reject,
            underscores,
            scheme,
            socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            proxy_proto: None,
            trust,
            default_authority,
            forward_proxy,
            will_buffer_body,
        }
    }

    fn ctx() -> H1Context<'static> {
        ctx_with(
            Scheme::Http,
            false,
            false,
            None,
            &DEFAULT_TRUST,
            UnderscorePolicy::Reject,
        )
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Expected {
        Err(RejectReason),
        Ok {
            host: &'static [u8],
            path: &'static [u8],
            query: Option<&'static [u8]>,
            scheme: Scheme,
            framing: RequestFraming,
            form: TargetForm,
            expect: ExpectAction,
        },
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table of edge cases the issue names by number; splitting it would break \
                  the 1:1 mapping to that numbered list"
    )]
    #[test]
    fn corpus_table() {
        let assert_case = |head: &[u8], ctx: &H1Context<'_>, expected: &Expected| {
            let raw = match try_parse_request_head(head, ctx.underscores) {
                Ok(raw) => raw,
                Err(reason) => {
                    assert!(
                        matches!(expected, Expected::Err(e) if *e == reason),
                        "for {head:?}: parser returned {reason:?}, expected {expected:?}"
                    );
                    return;
                }
            };
            let mut arena = BytesMut::new();
            let got = canonicalize_request(&raw, ctx, &mut arena);
            match (expected, got) {
                (Expected::Err(reason), Err(got_reason)) => {
                    assert_eq!(*reason, got_reason, "reject reason mismatch for {head:?}");
                }
                (
                    Expected::Ok {
                        host,
                        path,
                        query,
                        scheme,
                        framing,
                        form,
                        expect,
                    },
                    Ok((req, got_expect, got_form)),
                ) => {
                    assert_eq!(req.authority.host(), *host, "host mismatch for {head:?}");
                    assert_eq!(req.path.as_bytes(), *path, "path mismatch for {head:?}");
                    assert_eq!(
                        req.query.as_ref().map(crate::path::RawQuery::as_bytes),
                        *query,
                        "query mismatch for {head:?}"
                    );
                    assert_eq!(req.scheme, *scheme, "scheme mismatch for {head:?}");
                    assert_eq!(req.framing, *framing, "framing mismatch for {head:?}");
                    assert_eq!(got_form, *form, "target form mismatch for {head:?}");
                    assert_eq!(got_expect, *expect, "expect action mismatch for {head:?}");
                }
                (expected, got) => panic!("for {head:?}: expected {expected:?}, got {got:?}"),
            }
        };

        let default_auth = Authority::parse_into(
            b"default.example.com",
            Scheme::Http,
            &Limits::DEFAULT.clamped(),
            &mut BytesMut::new(),
        )
        .unwrap();
        let default_auth_ref: &'static Authority = Box::leak(Box::new(default_auth));

        let cases: &[(&[u8], H1Context<'static>, Expected)] = &[
            // 1: HTTP/1.1 with no Host.
            (
                b"GET / HTTP/1.1\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::HostMissing),
            ),
            // 2: HTTP/1.1 with two identical Host lines.
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::HostDuplicate),
            ),
            // 3: HTTP/1.1 with two different Host lines.
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::HostDuplicate),
            ),
            // 4: HTTP/1.0 with no Host and a default authority.
            (
                b"GET / HTTP/1.0\r\n\r\n",
                ctx_with(Scheme::Http, false, false, Some(default_auth_ref), &DEFAULT_TRUST, UnderscorePolicy::Reject),
                Expected::Ok {
                    host: b"default.example.com",
                    path: b"/",
                    query: None,
                    scheme: Scheme::Http,
                    framing: RequestFraming::Empty,
                    form: TargetForm::Origin,
                    expect: ExpectAction::None,
                },
            ),
            // 5: HTTP/1.0 with no Host and no default_authority.
            (
                b"GET / HTTP/1.0\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::HostMissing),
            ),
            // 6: HTTP/1.0 with two Host lines.
            (
                b"GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::HostDuplicate),
            ),
            // 7: Host: evil.com with absolute-form target http://good.com/p on forward proxy.
            (
                b"GET http://good.com/p HTTP/1.1\r\nHost: evil.com\r\n\r\n",
                ctx_with(Scheme::Http, true, false, None, &DEFAULT_TRUST, UnderscorePolicy::Reject),
                Expected::Err(RejectReason::AuthorityMismatch),
            ),
            // 8: Absolute target on reverse proxy.
            (
                b"GET http://good.com/p HTTP/1.1\r\nHost: good.com\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::TargetFormInvalid),
            ),
            // 8b: GET ftp://internal/x on forward proxy.
            (
                b"GET ftp://internal/x HTTP/1.1\r\n\r\n",
                ctx_with(Scheme::Http, true, false, None, &DEFAULT_TRUST, UnderscorePolicy::Reject),
                Expected::Err(RejectReason::TargetFormInvalid),
            ),
            // 8c: GET https://good.com/p on plaintext forward proxy.
            (
                b"GET https://good.com/p HTTP/1.1\r\n\r\n",
                ctx_with(Scheme::Http, true, false, None, &DEFAULT_TRUST, UnderscorePolicy::Reject),
                Expected::Ok {
                    host: b"good.com",
                    path: b"/p",
                    query: None,
                    scheme: Scheme::Http,
                    framing: RequestFraming::Empty,
                    form: TargetForm::Absolute,
                    expect: ExpectAction::None,
                },
            ),
            // 9: OPTIONS *.
            (
                b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
                ctx(),
                Expected::Ok {
                    host: b"example.com",
                    path: b"/",
                    query: None,
                    scheme: Scheme::Http,
                    framing: RequestFraming::Empty,
                    form: TargetForm::Asterisk,
                    expect: ExpectAction::None,
                },
            ),
            // 10: GET *.
            (
                b"GET * HTTP/1.1\r\nHost: example.com\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::TargetFormInvalid),
            ),
            // 11: CONNECT host:443.
            (
                b"CONNECT host:443 HTTP/1.1\r\n\r\n",
                ctx(),
                Expected::Ok {
                    host: b"host",
                    path: b"/",
                    query: None,
                    scheme: Scheme::Http,
                    framing: RequestFraming::Empty,
                    form: TargetForm::Authority,
                    expect: ExpectAction::None,
                },
            ),
            // 12: CONNECT host:443 with content-length: 5.
            (
                b"CONNECT host:443 HTTP/1.1\r\ncontent-length: 5\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::BodyNotAllowedForMethod),
            ),
            // 13: CONNECT /p.
            (
                b"CONNECT /p HTTP/1.1\r\nHost: example.com\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::TargetFormInvalid),
            ),
            // 14: Uppercase field names lowercased.
            (
                b"GET / HTTP/1.1\r\nHOST: EXAMPLE.COM\r\n\r\n",
                ctx(),
                Expected::Ok {
                    host: b"example.com",
                    path: b"/",
                    query: None,
                    scheme: Scheme::Http,
                    framing: RequestFraming::Empty,
                    form: TargetForm::Origin,
                    expect: ExpectAction::None,
                },
            ),
            // 15: X_Custom under Reject.
            (
                b"GET / HTTP/1.1\r\nHost: example.com\r\nX_Custom: v\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::FieldNameUnderscore),
            ),
            // 16: X_Forwarded_For under MapToHyphen (tested separately for survival).
            // 17: content-length + x-forwarded-for + expect (tested separately for ordering).
            // 18: expect answered locally (tested separately).
            // 19: expect bogus (tested separately).
            // 20: Zero fields on HTTP/1.0 with a default authority.
            (
                b"GET / HTTP/1.0\r\n\r\n",
                ctx_with(Scheme::Http, false, false, Some(default_auth_ref), &DEFAULT_TRUST, UnderscorePolicy::Reject),
                Expected::Ok {
                    host: b"default.example.com",
                    path: b"/",
                    query: None,
                    scheme: Scheme::Http,
                    framing: RequestFraming::Empty,
                    form: TargetForm::Origin,
                    expect: ExpectAction::None,
                },
            ),
            // 21: 100 fields.
            (
                &make_head_with_field_count(100),
                ctx(),
                Expected::Ok {
                    host: b"example.com",
                    path: b"/",
                    query: None,
                    scheme: Scheme::Http,
                    framing: RequestFraming::Empty,
                    form: TargetForm::Origin,
                    expect: ExpectAction::None,
                },
            ),
            // 22: 200-byte name lowercasing (tested separately).
            // 23: /a/../b -> /b.
            (
                b"GET /a/../b HTTP/1.1\r\nHost: example.com\r\n\r\n",
                ctx(),
                Expected::Ok {
                    host: b"example.com",
                    path: b"/b",
                    query: None,
                    scheme: Scheme::Http,
                    framing: RequestFraming::Empty,
                    form: TargetForm::Origin,
                    expect: ExpectAction::None,
                },
            ),
            // 24: /a/..%2fb under EncodedSlash::Reject.
            (
                b"GET /a/..%2fb HTTP/1.1\r\nHost: example.com\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::PathEncodedSlash),
            ),
            // 25: transfer-encoding chunked + content-length 5.
            (
                b"GET / HTTP/1.1\r\nHost: example.com\r\ntransfer-encoding: chunked\r\ncontent-length: 5\r\n\r\n",
                ctx(),
                Expected::Err(RejectReason::TransferEncodingWithContentLength),
            ),
        ];

        for (head, ctx, expected) in cases {
            assert_case(head, ctx, expected);
        }
    }

    fn make_head_with_field_count(count: usize) -> Vec<u8> {
        let mut head = Vec::from(&b"GET / HTTP/1.1\r\nHost: example.com\r\n"[..]);
        for i in 0..count.saturating_sub(1) {
            head.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");
        head
    }

    #[test]
    fn host_rules() {
        let no_host = b"GET / HTTP/1.1\r\n\r\n";
        assert!(matches!(
            canonicalize_request(
                &parse_request_head(no_host, UnderscorePolicy::Reject),
                &ctx(),
                &mut BytesMut::new()
            ),
            Err(RejectReason::HostMissing)
        ));

        let dup_same = b"GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n";
        assert!(matches!(
            canonicalize_request(
                &parse_request_head(dup_same, UnderscorePolicy::Reject),
                &ctx(),
                &mut BytesMut::new()
            ),
            Err(RejectReason::HostDuplicate)
        ));

        let dup_diff = b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n";
        assert!(matches!(
            canonicalize_request(
                &parse_request_head(dup_diff, UnderscorePolicy::Reject),
                &ctx(),
                &mut BytesMut::new()
            ),
            Err(RejectReason::HostDuplicate)
        ));

        let default_auth = Authority::parse_into(
            b"default.example.com",
            Scheme::Http,
            &Limits::DEFAULT.clamped(),
            &mut BytesMut::new(),
        )
        .unwrap();
        let default_auth_ref: &'static Authority = Box::leak(Box::new(default_auth));
        let http10_no_host_default = b"GET / HTTP/1.0\r\n\r\n";
        let ctx_default = ctx_with(
            Scheme::Http,
            false,
            false,
            Some(default_auth_ref),
            &DEFAULT_TRUST,
            UnderscorePolicy::Reject,
        );
        let (req, _, _) = canonicalize_request(
            &parse_request_head(http10_no_host_default, UnderscorePolicy::Reject),
            &ctx_default,
            &mut BytesMut::new(),
        )
        .unwrap();
        assert_eq!(req.authority.host(), b"default.example.com");

        let http10_no_host_no_default = b"GET / HTTP/1.0\r\n\r\n";
        assert!(matches!(
            canonicalize_request(
                &parse_request_head(http10_no_host_no_default, UnderscorePolicy::Reject),
                &ctx(),
                &mut BytesMut::new()
            ),
            Err(RejectReason::HostMissing)
        ));

        let http10_dup = b"GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n";
        assert!(matches!(
            canonicalize_request(
                &parse_request_head(http10_dup, UnderscorePolicy::Reject),
                &ctx(),
                &mut BytesMut::new()
            ),
            Err(RejectReason::HostDuplicate)
        ));
    }

    #[test]
    fn target_forms() {
        let forward = ctx_with(
            Scheme::Http,
            true,
            false,
            None,
            &DEFAULT_TRUST,
            UnderscorePolicy::Reject,
        );

        // 7: Host disagrees with absolute-form target.
        let head = parse_request_head(
            b"GET http://good.com/p HTTP/1.1\r\nHost: evil.com\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        assert!(matches!(
            canonicalize_request(&head, &forward, &mut BytesMut::new()),
            Err(RejectReason::AuthorityMismatch)
        ));

        // 8: Absolute on reverse proxy.
        let head = parse_request_head(
            b"GET http://good.com/p HTTP/1.1\r\nHost: good.com\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        assert!(matches!(
            canonicalize_request(&head, &ctx(), &mut BytesMut::new()),
            Err(RejectReason::TargetFormInvalid)
        ));

        // 8b: ftp scheme.
        let head = parse_request_head(
            b"GET ftp://internal/x HTTP/1.1\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        assert!(matches!(
            canonicalize_request(&head, &forward, &mut BytesMut::new()),
            Err(RejectReason::TargetFormInvalid)
        ));

        // 8b: file scheme.
        let head = parse_request_head(
            b"GET file:///etc/passwd HTTP/1.1\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        assert!(matches!(
            canonicalize_request(&head, &forward, &mut BytesMut::new()),
            Err(RejectReason::TargetFormInvalid)
        ));

        // 8b: HTTP scheme is accepted case-insensitively.
        let head = parse_request_head(
            b"GET HTTP://GOOD.COM/p HTTP/1.1\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        let (req, _, form) = canonicalize_request(&head, &forward, &mut BytesMut::new()).unwrap();
        assert_eq!(form, TargetForm::Absolute);
        assert_eq!(req.scheme, Scheme::Http);
        assert_eq!(req.authority.host(), b"good.com");

        // 8c: target scheme is ignored; listener scheme wins.
        let head = parse_request_head(
            b"GET https://good.com/p HTTP/1.1\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        let (req, _, form) = canonicalize_request(&head, &forward, &mut BytesMut::new()).unwrap();
        assert_eq!(form, TargetForm::Absolute);
        assert_eq!(req.scheme, Scheme::Http);

        // 9: OPTIONS *.
        let head = parse_request_head(
            b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        let (req, _, form) = canonicalize_request(&head, &ctx(), &mut BytesMut::new()).unwrap();
        assert_eq!(form, TargetForm::Asterisk);
        assert_eq!(req.path.as_bytes(), b"/");

        // 10: GET *.
        let head = parse_request_head(
            b"GET * HTTP/1.1\r\nHost: example.com\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        assert!(matches!(
            canonicalize_request(&head, &ctx(), &mut BytesMut::new()),
            Err(RejectReason::TargetFormInvalid)
        ));

        // 11: CONNECT host:443.
        let head = parse_request_head(
            b"CONNECT host:443 HTTP/1.1\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        let (req, _, form) = canonicalize_request(&head, &ctx(), &mut BytesMut::new()).unwrap();
        assert_eq!(form, TargetForm::Authority);
        assert_eq!(req.path.as_bytes(), b"/");
        assert_eq!(req.framing, RequestFraming::Empty);

        // 12: CONNECT with content-length.
        let head = parse_request_head(
            b"CONNECT host:443 HTTP/1.1\r\ncontent-length: 5\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        assert!(matches!(
            canonicalize_request(&head, &ctx(), &mut BytesMut::new()),
            Err(RejectReason::BodyNotAllowedForMethod)
        ));

        // 13: CONNECT /p.
        let head = parse_request_head(
            b"CONNECT /p HTTP/1.1\r\nHost: example.com\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        assert!(matches!(
            canonicalize_request(&head, &ctx(), &mut BytesMut::new()),
            Err(RejectReason::TargetFormInvalid)
        ));
    }

    #[test]
    fn step_order_is_observable() {
        let head = parse_request_head(
            b"GET / HTTP/1.1\r\nHost: example.com\r\ncontent-length: 5\r\nx-forwarded-for: 1.2.3.4\r\nexpect: 100-continue\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        let trust: &'static TrustPolicy = Box::leak(Box::new(TrustPolicy::HopCount(1)));
        let ctx = ctx_with(
            Scheme::Http,
            false,
            false,
            None,
            trust,
            UnderscorePolicy::Reject,
        );
        let (req, action, _) = canonicalize_request(&head, &ctx, &mut BytesMut::new()).unwrap();

        assert_eq!(req.framing, RequestFraming::Exact { len: 5 });
        assert_eq!(req.peer.source, IdentitySource::ForwardedChain);
        assert_eq!(action, ExpectAction::ForwardToUpstream);
        assert!(matches!(
            req.headers.get_unique(b"content-length"),
            Ok(None)
        ));
        assert!(matches!(
            req.headers.get_unique(b"x-forwarded-for"),
            Ok(None)
        ));
        // expect is forwarded, so it survives the strip.
        assert!(matches!(req.headers.get_unique(b"expect"), Ok(Some(v)) if v == b"100-continue"));
    }

    #[test]
    fn underscore_variant_cannot_survive() {
        // CVE-2026-54763 regression: an underscore variant of an identity header
        // is mapped to the hyphen form and then stripped.
        let head = parse_request_head(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX_Forwarded_For: 1.2.3.4\r\n\r\n",
            UnderscorePolicy::MapToHyphen,
        );
        let ctx = ctx_with(
            Scheme::Http,
            false,
            false,
            None,
            &DEFAULT_TRUST,
            UnderscorePolicy::MapToHyphen,
        );
        let (req, _, _) = canonicalize_request(&head, &ctx, &mut BytesMut::new()).unwrap();
        assert!(matches!(
            req.headers.get_unique(b"x-forwarded-for"),
            Ok(None)
        ));
    }

    #[test]
    fn expect_removed_when_answered_locally() {
        // 18: expect: 100-continue with will_buffer_body: true.
        let head = parse_request_head(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nexpect: 100-continue\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        let buffering_ctx = ctx_with(
            Scheme::Http,
            false,
            true,
            None,
            &DEFAULT_TRUST,
            UnderscorePolicy::Reject,
        );
        let (req, action, _) =
            canonicalize_request(&head, &buffering_ctx, &mut BytesMut::new()).unwrap();
        assert_eq!(action, ExpectAction::AnswerLocally);
        assert!(matches!(req.headers.get_unique(b"expect"), Ok(None)));

        // 19: expect: bogus.
        let head = parse_request_head(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nexpect: bogus\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        assert!(matches!(
            canonicalize_request(&head, &ctx(), &mut BytesMut::new()),
            Err(RejectReason::ExpectUnsupported)
        ));
    }

    #[test]
    fn arena_is_reused_across_pipelined_requests() {
        let buf = b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: b\r\n\r\n";
        let parser = H1Parser::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);
        let first = parser
            .parse_request_head(buf)
            .unwrap()
            .into_complete()
            .unwrap();
        let head1 = first.0;
        let consumed1 = first.1;
        let mut arena = BytesMut::new();
        let (req1, _, _) = canonicalize_request(&head1, &ctx(), &mut arena).unwrap();

        let head2 = parser
            .parse_request_head(&buf[consumed1..])
            .unwrap()
            .into_complete()
            .unwrap()
            .0;
        let (req2, _, _) = canonicalize_request(&head2, &ctx(), &mut arena).unwrap();

        assert_eq!(req1.authority.host(), b"a");
        assert_eq!(req2.authority.host(), b"b");
    }

    #[test]
    fn long_name_lowercasing() {
        let name: Vec<u8> = std::iter::once(b'X')
            .chain((0..198).map(|i| b'a' + u8::try_from(i % 26).unwrap()))
            .collect();
        let mut head = Vec::from(&b"GET / HTTP/1.1\r\nHost: example.com\r\n"[..]);
        head.extend_from_slice(&name);
        head.extend_from_slice(b": v\r\n\r\n");
        let head = parse_request_head(&head, UnderscorePolicy::Reject);
        let (req, _, _) = canonicalize_request(&head, &ctx(), &mut BytesMut::new()).unwrap();
        let lowered: Vec<u8> = name.iter().map(u8::to_ascii_lowercase).collect();
        assert!(matches!(req.headers.get_unique(&lowered), Ok(Some(v)) if v == b"v"));
    }

    #[test]
    fn request_does_not_borrow_the_read_buffer() {
        let (req, _, _) = {
            let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
            let head = parse_request_head(&buf, UnderscorePolicy::Reject);
            let mut arena = BytesMut::new();
            canonicalize_request(&head, &ctx(), &mut arena).unwrap()
        };
        assert_eq!(req.authority.host(), b"example.com");
        assert_eq!(req.path.as_bytes(), b"/");
        assert!(matches!(req.headers.get_unique(b"host"), Ok(Some(v)) if v == b"example.com"));
    }

    #[test]
    fn response_declared_length_survives_the_strip() {
        let check = |head: &[u8], expected_len: Option<u64>, expected_framing: ResponseFraming| {
            let raw = parse_response_head(head, UnderscorePolicy::Reject);
            let (resp, declared) =
                canonicalize_response(&raw, &Method::Head, &ctx(), &mut BytesMut::new()).unwrap();
            assert_eq!(declared, expected_len);
            assert_eq!(resp.framing, expected_framing);
            assert!(matches!(
                resp.headers.get_unique(b"content-length"),
                Ok(None)
            ));
        };

        check(
            b"HTTP/1.1 200 OK\r\ncontent-length: 4096\r\n\r\n",
            Some(4096),
            ResponseFraming::Empty,
        );
        check(
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n",
            Some(0),
            ResponseFraming::Empty,
        );
        check(b"HTTP/1.1 200 OK\r\n\r\n", None, ResponseFraming::Empty);

        // 27c: GET with transfer-encoding: chunked.
        let raw = parse_response_head(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
            UnderscorePolicy::Reject,
        );
        let (resp, declared) =
            canonicalize_response(&raw, &Method::Get, &ctx(), &mut BytesMut::new()).unwrap();
        assert_eq!(declared, None);
        assert_eq!(resp.framing, ResponseFraming::Streamed);
        assert!(matches!(
            resp.headers.get_unique(b"content-length"),
            Ok(None)
        ));
        assert!(matches!(
            resp.headers.get_unique(b"transfer-encoding"),
            Ok(None)
        ));
    }
}
