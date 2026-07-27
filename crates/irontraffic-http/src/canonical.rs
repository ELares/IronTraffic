// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`CanonicalRequest`] and [`CanonicalResponse`], the single internal
//! representations every wire protocol parses into and serializes out of,
//! and [`CanonicalRequestBuilder`], the only way to build the former.
//!
//! Nothing downstream of the parser sees wire bytes and nothing upstream of
//! the serializer sees them either: routing, authorization, logging, cache
//! keys and the bytes written upstream all derive from a
//! [`CanonicalRequest`]'s fields, never from a second, raw representation.
//!
//! Two invariants are enforced by [`CanonicalRequestBuilder::build`] rather
//! than by convention, because a convention is a comment and a constructor
//! is a compiler:
//!
//! **I2.** After construction, `headers` contains no field in the
//! hop-by-hop strip set and no `content-length` or `transfer-encoding`.
//! [`CanonicalRequestBuilder::build`] checks this and returns an error
//! rather than building, which is what makes framing regeneration at egress
//! unconditional: there is no inbound value left to accidentally forward.
//! [`CanonicalResponse::new`] applies the response-side twin of the same
//! rule.
//!
//! **P1.** There is exactly one path value. [`CanonicalRequest`] has no
//! `raw_target`, `original_path` or `uri` field, and
//! [`crate::path::NormalizedPath::as_bytes`] is the only accessor for its
//! bytes. Adding a second path field is the bug this milestone exists to
//! prevent.
//!
//! P2, the rewrite invariant, is [`crate::rewrite::RewriteLedger`]'s job,
//! not this module's: see that module's own documentation.
//!
//! **What this issue does not deliver.** This module does not route and
//! does not authorize; it produces the value the routing milestone
//! consumes.

use bytes::BytesMut;

use crate::authority::Authority;
use crate::error::RejectReason;
use crate::framing::RequestFraming;
use crate::path::{NormalizedPath, RawQuery};
use crate::peer::PeerIdentity;
use crate::response::ResponseFraming;
use crate::scalar::{Method, Scheme, StatusCode, WireVersion};
use crate::section::FieldSection;
use crate::strip;

/// The single internal representation of a request, whatever protocol it arrived on.
///
/// Nothing downstream of the parser sees wire bytes and nothing upstream of the
/// serializer does either. In particular there is deliberately no raw request target,
/// no second path value and no inbound framing field: routing, authorization, logging,
/// cache keys and the bytes we write upstream all derive from the fields below.
#[derive(Clone, Debug)]
pub struct CanonicalRequest {
    /// The request method.
    pub method: Method,
    /// From `:scheme` on HTTP/2 and HTTP/3, or from the listener on HTTP/1.
    pub scheme: Scheme,
    /// Validated, ASCII-only, lowercased host with an optional non-default port.
    pub authority: Authority,
    /// The ONE path value in the system.
    pub path: NormalizedPath,
    /// The query, byte-preserved. `None` means there was no `?`.
    pub query: Option<RawQuery>,
    /// End-to-end fields only: hop-by-hop fields are already gone.
    pub headers: FieldSection,
    /// Resolved, unambiguous framing.
    pub framing: RequestFraming,
    /// What we received on. Observability and framing rules only.
    pub version: WireVersion,
    /// The one client identity.
    pub peer: PeerIdentity,
}

/// Builds a [`CanonicalRequest`], refusing to produce one that violates the parse-boundary
/// invariants.
#[derive(Debug, Default)]
pub struct CanonicalRequestBuilder {
    method: Option<Method>,
    scheme: Option<Scheme>,
    authority: Option<Authority>,
    path: Option<(NormalizedPath, Option<RawQuery>)>,
    headers: Option<FieldSection>,
    framing: Option<RequestFraming>,
    version: Option<WireVersion>,
    peer: Option<PeerIdentity>,
}

impl CanonicalRequestBuilder {
    /// A new, empty builder.
    #[must_use]
    pub fn new() -> Self {
        CanonicalRequestBuilder::default()
    }

    /// Sets the method. Required.
    #[must_use]
    pub fn method(mut self, m: Method) -> Self {
        self.method = Some(m);
        self
    }

    /// Sets the scheme. Required.
    #[must_use]
    pub fn scheme(mut self, s: Scheme) -> Self {
        self.scheme = Some(s);
        self
    }

    /// Sets the authority. Required.
    #[must_use]
    pub fn authority(mut self, a: Authority) -> Self {
        self.authority = Some(a);
        self
    }

    /// Sets the path and query. Required.
    #[must_use]
    pub fn path(mut self, p: NormalizedPath, q: Option<RawQuery>) -> Self {
        self.path = Some((p, q));
        self
    }

    /// Sets the header section. Required. MUST already have been through `strip_ingress`.
    #[must_use]
    pub fn headers(mut self, h: FieldSection) -> Self {
        self.headers = Some(h);
        self
    }

    /// Sets the resolved framing. Required.
    #[must_use]
    pub fn framing(mut self, f: RequestFraming) -> Self {
        self.framing = Some(f);
        self
    }

    /// Sets the wire version. Required.
    #[must_use]
    pub fn version(mut self, v: WireVersion) -> Self {
        self.version = Some(v);
        self
    }

    /// Sets the client identity. Required.
    #[must_use]
    pub fn peer(mut self, p: PeerIdentity) -> Self {
        self.peer = Some(p);
        self
    }

    /// Builds the request, checking invariant I2 and the framing consistency rules.
    ///
    /// Every one of the eight required parts (method, scheme, authority, path plus
    /// query, headers, framing, version, peer) must have been set, checked in that
    /// declaration order; a missing part of any kind is `RequestLineMalformed` rather
    /// than a per-part reason, because a missing part is a programming error in the
    /// caller, not a property of the input.
    ///
    /// # Errors
    /// `RequestLineMalformed` when a required part was not set;
    /// `ConnectionSpecificField` when `headers` still contains a hop-by-hop, identity or
    /// reserved-prefix field (the caller forgot `strip_ingress`);
    /// `TransferEncodingOnHttp10` for `Streamed` framing on HTTP/1.0;
    /// `BodyNotAllowedForMethod` for a non-`Empty` framing on `CONNECT`.
    pub fn build(self) -> Result<CanonicalRequest, RejectReason> {
        let method = self.method.ok_or(RejectReason::RequestLineMalformed)?;
        let scheme = self.scheme.ok_or(RejectReason::RequestLineMalformed)?;
        let authority = self.authority.ok_or(RejectReason::RequestLineMalformed)?;
        let (path, query) = self.path.ok_or(RejectReason::RequestLineMalformed)?;
        let headers = self.headers.ok_or(RejectReason::RequestLineMalformed)?;
        let framing = self.framing.ok_or(RejectReason::RequestLineMalformed)?;
        let version = self.version.ok_or(RejectReason::RequestLineMalformed)?;
        let peer = self.peer.ok_or(RejectReason::RequestLineMalformed)?;

        // I2 check. Walk the section by index so both the classification and
        // the name bytes are available.
        for (i, slot) in headers.slots().iter().enumerate() {
            // A slot whose name cannot be read REFUSES the build. Substituting an
            // empty name here would hand it to `is_reserved_prefix`, which answers
            // false, which builds a `CanonicalRequest` carrying a field nobody
            // checked. The failure direction for an invariant check is always "do
            // not build". This is unreachable with a `FieldSection` produced by
            // `FieldSectionBuilder::push` (edge case 25); the debug assertion below
            // makes the mistake loud in tests if that ever stops being true, without
            // making the release build panic on it (it returns an error either way).
            let name_at_i = headers.name_at(i);
            debug_assert!(
                name_at_i.is_some(),
                "FieldSection slot {i} could not be read back; every slot \
                 FieldSectionBuilder::push writes reads back, so this indicates the \
                 caller bypassed that constructor"
            );
            let Some(name) = name_at_i else {
                return Err(RejectReason::ConnectionSpecificField);
            };
            if strip::is_hop_by_hop(slot.known)
                || strip::is_identity_field(slot.known)
                || strip::is_reserved_prefix(name)
            {
                return Err(RejectReason::ConnectionSpecificField);
            }
        }

        // Framing consistency.
        if matches!(framing, RequestFraming::Streamed) && matches!(version, WireVersion::Http10) {
            return Err(RejectReason::TransferEncodingOnHttp10);
        }
        if method.is_connect() && !matches!(framing, RequestFraming::Empty) {
            return Err(RejectReason::BodyNotAllowedForMethod);
        }

        Ok(CanonicalRequest {
            method,
            scheme,
            authority,
            path,
            query,
            headers,
            framing,
            version,
            peer,
        })
    }
}

impl CanonicalRequest {
    /// True when this request has a body to forward.
    #[must_use]
    pub const fn has_body(&self) -> bool {
        self.framing.has_body()
    }

    /// The path and query as they will be written upstream, appended to `out`.
    /// Returns the number of bytes written. `/path?query` with no `?` when the query
    /// was absent.
    pub fn write_target(&self, out: &mut BytesMut) -> usize {
        let start = out.len();
        out.extend_from_slice(self.path.as_bytes());
        if let Some(query) = &self.query {
            out.extend_from_slice(b"?");
            out.extend_from_slice(query.as_bytes());
        }
        out.len().saturating_sub(start)
    }

    /// The number of bytes `write_target` will write.
    #[must_use]
    pub fn target_len(&self) -> usize {
        let query_len = self.query.as_ref().map_or(0, |q| q.len().saturating_add(1));
        self.path.len().saturating_add(query_len)
    }
}

/// The single internal representation of a response.
#[derive(Clone, Debug)]
pub struct CanonicalResponse {
    /// The status code.
    pub status: StatusCode,
    /// End-to-end fields only.
    pub headers: FieldSection,
    /// Resolved, unambiguous framing.
    pub framing: ResponseFraming,
    /// What we received it on.
    pub version: WireVersion,
}

impl CanonicalResponse {
    /// Builds a response, checking that hop-by-hop fields are already stripped.
    ///
    /// Applies the I2 check for the RESPONSE strip set, which is narrower than the
    /// request one: it checks `strip::is_hop_by_hop` (which already covers
    /// `content-length` and `transfer-encoding`) and a literal `x-irontraffic-` prefix
    /// match only. It does NOT check `is_identity_field` (a response carries no client
    /// identity) and it does NOT check the full reserved-prefix set: `x-envoy-*` on a
    /// response is interop information the resilience layer reads, exactly as in
    /// `strip_response`, and using the request-side check here would refuse every
    /// response an Envoy-shaped upstream sends.
    ///
    /// # Errors
    /// `ConnectionSpecificField` when a hop-by-hop field remains, or when a field named
    /// with the `x-irontraffic-` prefix remains.
    pub fn new(
        status: StatusCode,
        headers: FieldSection,
        framing: ResponseFraming,
        version: WireVersion,
    ) -> Result<CanonicalResponse, RejectReason> {
        for (i, slot) in headers.slots().iter().enumerate() {
            // Same fail-closed rule as `CanonicalRequestBuilder::build`'s I2 check
            // above: a slot whose name cannot be read refuses the build rather than
            // being treated as an empty, harmless name.
            let name_at_i = headers.name_at(i);
            debug_assert!(
                name_at_i.is_some(),
                "FieldSection slot {i} could not be read back; every slot \
                 FieldSectionBuilder::push writes reads back, so this indicates the \
                 caller bypassed that constructor"
            );
            let Some(name) = name_at_i else {
                return Err(RejectReason::ConnectionSpecificField);
            };
            if strip::is_hop_by_hop(slot.known) || name.starts_with(b"x-irontraffic-") {
                return Err(RejectReason::ConnectionSpecificField);
            }
        }

        Ok(CanonicalResponse {
            status,
            headers,
            framing,
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::section::FieldSectionBuilder;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::path::PathPolicy;
    use crate::peer::IdentitySource;

    fn clamped() -> crate::limits::ClampedLimits {
        Limits::DEFAULT.clamped()
    }

    fn valid_authority() -> Authority {
        let limits = clamped();
        let mut out = BytesMut::new();
        Authority::parse_into(b"example.com", Scheme::Https, &limits, &mut out)
            .expect("well formed authority")
    }

    fn valid_path() -> (NormalizedPath, Option<RawQuery>) {
        let limits = clamped();
        let mut out = BytesMut::new();
        NormalizedPath::parse_into(b"/a/b", &PathPolicy::DEFAULT, &limits, &mut out)
            .expect("well formed path")
    }

    fn parsed_path(raw: &[u8]) -> (NormalizedPath, Option<RawQuery>) {
        let limits = clamped();
        let mut out = BytesMut::new();
        NormalizedPath::parse_into(raw, &PathPolicy::DEFAULT, &limits, &mut out)
            .expect("well formed path")
    }

    fn valid_headers() -> FieldSection {
        let limits = clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder
            .push(&mut arena, b"host", b"example.com")
            .expect("valid field");
        builder
            .push(&mut arena, b"x-custom", b"v")
            .expect("valid field");
        builder.finish(&mut arena)
    }

    fn headers_with(name: &[u8], value: &[u8]) -> FieldSection {
        let limits = clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder.push(&mut arena, name, value).expect("valid field");
        builder.finish(&mut arena)
    }

    fn valid_peer() -> PeerIdentity {
        PeerIdentity {
            client: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            client_port: Some(54321),
            source: IdentitySource::Socket,
            forwarded_proto: None,
            trusted_hops: 0,
            peer_trusted: false,
        }
    }

    fn valid_builder() -> CanonicalRequestBuilder {
        let (path, query) = valid_path();
        CanonicalRequestBuilder::new()
            .method(Method::Get)
            .scheme(Scheme::Https)
            .authority(valid_authority())
            .path(path, query)
            .headers(valid_headers())
            .framing(RequestFraming::Empty)
            .version(WireVersion::Http11)
            .peer(valid_peer())
    }

    /// Builds with every one of the eight required parts set EXCEPT the one at
    /// `skip` (in declaration order: 0 method, 1 scheme, 2 authority, 3 path, 4
    /// headers, 5 framing, 6 version, 7 peer).
    fn builder_omitting(
        skip: usize,
        authority: &Authority,
        path: &(NormalizedPath, Option<RawQuery>),
        headers: &FieldSection,
        peer: PeerIdentity,
    ) -> CanonicalRequestBuilder {
        let mut b = CanonicalRequestBuilder::new();
        if skip != 0 {
            b = b.method(Method::Get);
        }
        if skip != 1 {
            b = b.scheme(Scheme::Https);
        }
        if skip != 2 {
            b = b.authority(authority.clone());
        }
        if skip != 3 {
            b = b.path(path.0.clone(), path.1.clone());
        }
        if skip != 4 {
            b = b.headers(headers.clone());
        }
        if skip != 5 {
            b = b.framing(RequestFraming::Empty);
        }
        if skip != 6 {
            b = b.version(WireVersion::Http11);
        }
        if skip != 7 {
            b = b.peer(peer);
        }
        b
    }

    #[test]
    fn builder_requires_every_part() {
        let path = valid_path();
        let headers = valid_headers();
        let peer = valid_peer();
        let authority = valid_authority();

        for skip in 0..8 {
            let result = builder_omitting(skip, &authority, &path, &headers, peer).build();
            assert!(
                matches!(result, Err(RejectReason::RequestLineMalformed)),
                "omitting part {skip} must give RequestLineMalformed, got {result:?}"
            );
        }

        // Every one of the eight must build successfully once all are present.
        assert!(valid_builder().build().is_ok());
    }

    #[test]
    fn i2_is_enforced() {
        for (name, value) in [
            (&b"content-length"[..], &b"5"[..]),
            (b"transfer-encoding", b"chunked"),
            (b"connection", b"close"),
            (b"keep-alive", b"timeout=5"),
            (b"x-forwarded-for", b"1.2.3.4"),
            (b"forwarded", b"for=1.2.3.4"),
            (b"x-irontraffic-a", b"1"),
        ] {
            let result = valid_builder().headers(headers_with(name, value)).build();
            assert!(
                matches!(result, Err(RejectReason::ConnectionSpecificField)),
                "{name:?} must be refused, got {result:?}"
            );
        }

        // `te: trailers` survives `strip_ingress` and must build successfully.
        let ok = valid_builder()
            .headers(headers_with(b"te", b"trailers"))
            .build();
        assert!(ok.is_ok(), "te: trailers must build, got {ok:?}");
    }

    #[test]
    fn framing_consistency() {
        // Edge case 7: Streamed framing on HTTP/1.0.
        let streamed_on_10 = valid_builder()
            .framing(RequestFraming::Streamed)
            .version(WireVersion::Http10)
            .build();
        assert!(matches!(
            streamed_on_10,
            Err(RejectReason::TransferEncodingOnHttp10)
        ));

        // Empty framing on HTTP/1.0 must NOT be refused: this is what distinguishes
        // the Streamed-on-1.0 check's `&&` from a `||`, which would refuse every
        // HTTP/1.0 request regardless of framing.
        let empty_on_10 = valid_builder().version(WireVersion::Http10).build();
        assert!(empty_on_10.is_ok());

        // Edge case 8: Exact { len: 5 } on CONNECT.
        let body_on_connect = valid_builder()
            .method(Method::Connect)
            .framing(RequestFraming::Exact { len: 5 })
            .build();
        assert!(matches!(
            body_on_connect,
            Err(RejectReason::BodyNotAllowedForMethod)
        ));

        // Edge case 9: Empty framing on CONNECT is fine, and carries no body.
        let empty_on_connect = valid_builder()
            .method(Method::Connect)
            .framing(RequestFraming::Empty)
            .build()
            .expect("Empty framing on CONNECT must build");
        assert!(!empty_on_connect.has_body());

        // A non-CONNECT method with a non-Empty framing must NOT be refused: this is
        // what distinguishes the CONNECT check's `&&` from a `||`, which would refuse
        // every non-Empty framing regardless of method. `has_body` must also report
        // true here, the opposite of the CONNECT case just above.
        let body_on_get = valid_builder()
            .framing(RequestFraming::Exact { len: 5 })
            .build()
            .expect("non-Empty framing on a non-CONNECT method must build");
        assert!(body_on_get.has_body());
    }

    #[test]
    fn write_target_and_len_agree() {
        // Edge case 10: no query.
        let (path, query) = parsed_path(b"/path");
        let req = valid_builder().path(path, query).build().unwrap();
        let mut out = BytesMut::new();
        let written = req.write_target(&mut out);
        assert_eq!(&out[..], b"/path");
        assert_eq!(written, 5);
        assert_eq!(req.target_len(), written);

        // Edge case 11: empty query, preserving the distinction from no query.
        let (path, query) = parsed_path(b"/path?");
        let req = valid_builder().path(path, query).build().unwrap();
        let mut out = BytesMut::new();
        let written = req.write_target(&mut out);
        assert_eq!(&out[..], b"/path?");
        assert_eq!(written, 6);
        assert_eq!(req.target_len(), written);

        // Edge case 12: a query.
        let (path, query) = parsed_path(b"/path?a=1");
        let req = valid_builder().path(path, query).build().unwrap();
        let mut out = BytesMut::new();
        let written = req.write_target(&mut out);
        assert_eq!(&out[..], b"/path?a=1");
        assert_eq!(written, 9);
        assert_eq!(req.target_len(), written);
    }

    #[test]
    fn no_raw_target_field() {
        // Invariant P1: there is exactly one path value, `req.path`, and the only
        // accessor for its bytes is `NormalizedPath::as_bytes`. A convention is a
        // comment and a constructor is a compiler, so the enforcement here is
        // exhaustive destructuring, not a field read: every field is named and none
        // is swallowed by `..`, so a tenth field added to `CanonicalRequest` (a
        // `raw_target`, `original_path` or `uri`) is a compile error at this exact
        // line rather than a silent pass. The acceptance criteria's grep is a second,
        // independent check; this is the first, at the point a reader will look for
        // it.
        let req = valid_builder().build().expect("valid request builds");
        let CanonicalRequest {
            method: _,
            scheme: _,
            authority: _,
            path,
            query: _,
            headers: _,
            framing: _,
            version: _,
            peer: _,
        } = req;
        assert_eq!(path.as_bytes(), b"/a/b");
    }

    #[test]
    fn response_strip_is_enforced() {
        let limits = clamped();

        for (name, value) in [
            (&b"content-length"[..], &b"5"[..]),
            (b"connection", b"close"),
            (b"x-irontraffic-a", b"1"),
        ] {
            let mut arena = BytesMut::new();
            let mut builder = FieldSectionBuilder::new(&arena, &limits);
            builder.push(&mut arena, name, value).expect("valid field");
            let headers = builder.finish(&mut arena);
            let result = CanonicalResponse::new(
                StatusCode::OK,
                headers,
                ResponseFraming::Empty,
                WireVersion::Http11,
            );
            assert!(
                matches!(result, Err(RejectReason::ConnectionSpecificField)),
                "{name:?} must be refused"
            );
        }

        // `x-envoy-*` is interop information on a response and must survive: this
        // pins that the response check is not the request's `is_reserved_prefix`.
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder
            .push(&mut arena, b"x-envoy-attempt-count", b"1")
            .expect("valid field");
        let headers = builder.finish(&mut arena);
        let result = CanonicalResponse::new(
            StatusCode::OK,
            headers,
            ResponseFraming::Empty,
            WireVersion::Http11,
        );
        assert!(result.is_ok(), "x-envoy-* must survive, got {result:?}");
    }
}
