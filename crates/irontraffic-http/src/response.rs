// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`ResponseFraming`] and [`resolve_response_framing`], the response-side
//! twin of [`crate::framing::resolve_request_framing`]: the single function
//! that reads a response's status, the request method it answers, and its
//! `content-length` / `transfer-encoding` fields, and decides where its body
//! ends.
//!
//! **Why a fourth variant.** A request that matches none of RFC 9112 Section
//! 6.3's framing rules has a body length of zero (item 7); a response that
//! matches none of them is legally delimited by the connection close (item
//! 8, the response-only "otherwise"). That is unambiguous only because the
//! connection cannot be reused afterwards, so [`ResponseFraming`] has a
//! fourth variant, [`ResponseFraming::UntilClose`], that
//! [`crate::framing::RequestFraming`] does not, and its presence MUST force
//! the connection out of the upstream pool
//! ([`ResponseFraming::forbids_reuse`]).
//!
//! **Bodyless-by-status and bodyless-by-method run before field
//! inspection.** A `1xx`, `204` or `304` response has no body whatever its
//! fields claim, and a response to `HEAD` has no body whatever its
//! `Content-Length` claims (that value is still preserved for the caller,
//! but never as a body length: see `resolve_response_framing`'s doc
//! comment). Refusing a `Content-Length` on one of these would be the
//! opposite of RFC 9112 Section 6.3's intent: a `304` carrying the
//! `Content-Length` of the resource it did not resend is completely normal.
//!
//! **This function reuses [`crate::framing::parse_content_length`] and
//! [`crate::framing::tokenize_transfer_encoding`] unchanged.** Request
//! smuggling and response desynchronisation are the same bug in two
//! directions on one connection: if the two directions disagreed about how
//! `content-length` or `transfer-encoding` are parsed, the disagreement
//! itself would be the smuggling primitive, even with both directions
//! individually "correct". Sharing the parsers is what makes that
//! disagreement structurally impossible rather than merely untested.
//!
//! **Enforcement.** This function, [`crate::framing::resolve_request_framing`]
//! and the egress serializer are the only places in the codebase permitted
//! to read [`crate::known::KnownHeader::ContentLength`] or
//! [`crate::known::KnownHeader::TransferEncoding`] on a message. A CI grep
//! (`scripts/invariant-lints.sh`'s `framing-fields-confined` rule) enforces
//! it.

use crate::error::RejectReason;
use crate::field::trim_ows;
use crate::framing::{OtherCodings, parse_content_length, tokenize_transfer_encoding};
use crate::known::KnownHeader;
use crate::scalar::{Method, StatusCode, WireVersion};
use crate::section::FieldSection;

/// Where a response body ends. Resolved once, per response head.
///
/// Unlike [`crate::framing::RequestFraming`] this has a fourth variant,
/// [`ResponseFraming::UntilClose`], because a response with no framing field
/// is legally delimited by the connection close (RFC 9112 Section 6.3 item
/// 8, the response-only "otherwise"). That is unambiguous only because the
/// connection cannot be reused afterwards, so `UntilClose` forces the
/// connection out of the upstream pool.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseFraming {
    /// No body, by status or by request method.
    Empty,
    /// Exactly `len` bytes follow.
    Exact {
        /// The declared body length in bytes. Always greater than zero: a
        /// declared length of zero resolves to [`ResponseFraming::Empty`]
        /// instead.
        len: u64,
    },
    /// Chunked. Terminated by the terminal chunk on HTTP/1, `END_STREAM` on
    /// H2, FIN on H3.
    Streamed,
    /// Delimited by the connection close. The connection MUST NOT be
    /// pooled.
    UntilClose,
}

impl ResponseFraming {
    /// True for anything other than `Empty`.
    #[must_use]
    pub const fn has_body(self) -> bool {
        !matches!(self, ResponseFraming::Empty)
    }

    /// The declared length when known: `Some(0)` for `Empty`, `Some(len)`
    /// for `Exact`, and `None` for `Streamed` or `UntilClose`, neither of
    /// which the response head can size in advance.
    #[must_use]
    pub const fn known_len(self) -> Option<u64> {
        match self {
            ResponseFraming::Empty => Some(0),
            ResponseFraming::Exact { len } => Some(len),
            ResponseFraming::Streamed | ResponseFraming::UntilClose => None,
        }
    }

    /// True for `UntilClose`. A connection carrying such a response MUST NOT
    /// be pooled: nothing marks where this response ended except the peer
    /// closing the socket, so nothing on this connection can be trusted to
    /// be a later response's head.
    #[must_use]
    pub const fn forbids_reuse(self) -> bool {
        matches!(self, ResponseFraming::UntilClose)
    }
}

/// Resolves the framing of an inbound response.
///
/// `request_method` is the method of the request this response answers; it
/// is required because a response to `HEAD` has no body regardless of its
/// fields, and a `2xx` answer to `CONNECT` becomes a tunnel. A response to
/// `HEAD` still carries its `Content-Length` on the wire (RFC 9110 Section
/// 9.3.2: "the server SHOULD send that header field in a response to a HEAD
/// request"), and a caller that must preserve that value for observability
/// or for the downstream `HEAD` response has to capture it from the field
/// section BEFORE the framing fields are stripped, since `Ok(Empty)` here is
/// a statement about framing only and does not license discarding the
/// value; nothing may use it to size a buffer.
///
/// # Errors
/// `ContentLengthDuplicate`, `ContentLengthInvalid`, `ContentLengthOverflow`,
/// `TransferEncodingWithContentLength`, `TransferEncodingOnHttp10`,
/// `TransferEncodingFinalNotChunked`, `TransferEncodingChunkedRepeated`,
/// `TransferEncodingEmptyToken`, `TransferEncodingUnsupportedCoding`,
/// `ConnectionSpecificField`.
pub fn resolve_response_framing(
    status: StatusCode,
    request_method: &Method,
    version: WireVersion,
    fields: &FieldSection,
    policy: OtherCodings,
) -> Result<ResponseFraming, RejectReason> {
    // Step 1: duplicate content-length, unconditionally, whatever else is
    // present and whatever the status. This runs BEFORE the bodyless
    // shortcuts in steps 3 and 4: a duplicated length on a 304 or a HEAD
    // response still means the upstream is broken and the connection must
    // be poisoned, exactly as for any other response.
    let cl_count = fields.count_known(KnownHeader::ContentLength);
    if cl_count > 1 {
        return Err(RejectReason::ContentLengthDuplicate);
    }

    // Step 2: both present. Never forwarded with Content-Length deleted,
    // the same refusal the request side makes and for the same reason (see
    // crate::framing's module doc).
    let te_present = fields.contains_known(KnownHeader::TransferEncoding);
    if te_present && cl_count == 1 {
        return Err(RejectReason::TransferEncodingWithContentLength);
    }

    // Step 3: bodyless by status, before any further field inspection. A
    // 304 carrying `content-length: 1234` is completely normal; the framing
    // fields are ignored here, not validated, and are removed later by
    // `strip_response`.
    if status.is_interim() || status.as_u16() == 204 || status.as_u16() == 304 {
        return Ok(ResponseFraming::Empty);
    }

    // Step 4: bodyless by method. A response to HEAD never has a body no
    // matter what it declares; a 2xx answer to CONNECT turns the connection
    // into a tunnel. Both ignore the fields the same way step 3 does: a
    // `403` answering CONNECT falls through to the ordinary field rules
    // instead (edge case 6).
    if request_method.is_head() {
        return Ok(ResponseFraming::Empty);
    }
    if request_method.is_connect() && (200..300).contains(&status.as_u16()) {
        return Ok(ResponseFraming::Empty);
    }

    // Step 5: multiplexed protocols. A body on H2 or H3 always ends at
    // END_STREAM or FIN, never at a connection close, so `UntilClose` can
    // never be produced on a multiplexed protocol.
    if version.is_multiplexed() {
        if te_present {
            return Err(RejectReason::ConnectionSpecificField);
        }
        return Ok(match declared_len(fields)? {
            Some(0) => ResponseFraming::Empty,
            Some(len) => ResponseFraming::Exact { len },
            None => ResponseFraming::Streamed,
        });
    }

    // Step 6: the chunked path. `version` is Http10 or Http11 here: the
    // multiplexed case already returned in step 5.
    if te_present {
        if version == WireVersion::Http10 {
            return Err(RejectReason::TransferEncodingOnHttp10);
        }
        // Deliberately stricter than RFC 9112 Section 6.3 item 3, which
        // would fall through to a close-delimited body when the final
        // coding of a response is not `chunked`. An upstream that emits an
        // undecodable coding list is one whose framing cannot be trusted,
        // so this refuses with the same `TransferEncodingFinalNotChunked`
        // reason used on requests (via `tokenize_transfer_encoding`) rather
        // than falling through to `UntilClose`, which is reserved for "no
        // framing field was sent at all". Do not "fix" this to fall through
        // after reading the RFC.
        let _codings = tokenize_transfer_encoding(
            fields.get_all_known(KnownHeader::TransferEncoding),
            policy,
        )?;
        return Ok(ResponseFraming::Streamed);
    }

    // Step 7: the content-length path.
    match declared_len(fields)? {
        Some(0) => return Ok(ResponseFraming::Empty),
        Some(len) => return Ok(ResponseFraming::Exact { len }),
        None => {}
    }

    // Step 8: neither field is present. Unlike a request (RFC 9112 Section
    // 6.3 item 7: a request matching none of the preceding cases has a body
    // length of zero, and a request is never close-delimited), a response
    // reaching this point is legally delimited by the connection close
    // (item 8, the response-only "otherwise"). This is the one outcome a
    // response can produce that a request never can; the connection MUST
    // NOT be pooled afterwards (see `ResponseFraming::forbids_reuse`).
    Ok(ResponseFraming::UntilClose)
}

/// Reads the declared `content-length` value, if any.
///
/// Step 1 of [`resolve_response_framing`] already established
/// `count_known(ContentLength) <= 1`, so the `Err` arm below cannot occur in
/// practice; it is still handled, because a function that is total does not
/// depend on another step having run first.
fn declared_len(fields: &FieldSection) -> Result<Option<u64>, RejectReason> {
    let Ok(raw) = fields.get_unique_known(KnownHeader::ContentLength) else {
        return Err(RejectReason::ContentLengthDuplicate);
    };
    match raw {
        None => Ok(None),
        Some(v) => Ok(Some(parse_content_length(trim_ows(v))?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::section::FieldSectionBuilder;
    use bytes::BytesMut;

    const ALL_VERSIONS: [WireVersion; 4] = [
        WireVersion::Http10,
        WireVersion::Http11,
        WireVersion::H2,
        WireVersion::H3,
    ];
    const ALL_METHODS: [Method; 3] = [Method::Get, Method::Head, Method::Connect];
    const CL_STRATEGY_VALUES: [&str; 7] = ["0", "1", "5", "+5", "18446744073709551616", "", "abc"];
    const TE_STRATEGY_VALUES: [&str; 6] = [
        "chunked",
        "identity",
        "gzip, chunked",
        "chunked, chunked",
        "",
        "chunkedX",
    ];

    /// Builds a `FieldSection` from `fields` (already canonical names and
    /// already OWS-trimmed values, exactly as `FieldSectionBuilder::push`
    /// requires), constructs the status from `status`, and resolves the
    /// response framing under `OtherCodings::Reject`.
    fn resolve(
        fields: &[(&[u8], &[u8])],
        status: u16,
        method: Method,
        version: WireVersion,
    ) -> Result<ResponseFraming, RejectReason> {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        for (name, value) in fields {
            builder
                .push(&mut arena, name, value)
                .expect("test fixture fields must already be well formed field bytes");
        }
        let section = builder.finish(&mut arena);
        let status = StatusCode::from_u16(status).expect("test fixture status must be 100..=599");
        resolve_response_framing(status, &method, version, &section, OtherCodings::Reject)
    }

    #[test]
    fn four_variants_and_reuse_rule() {
        // Exhaustive match with no wildcard arm: this fails to compile the
        // moment a fifth variant is added to `ResponseFraming`, which is the
        // point of this test rather than anything it computes at run time.
        fn ordinal(f: ResponseFraming) -> u8 {
            match f {
                ResponseFraming::Empty => 0,
                ResponseFraming::Exact { len: _ } => 1,
                ResponseFraming::Streamed => 2,
                ResponseFraming::UntilClose => 3,
            }
        }
        assert_eq!(ordinal(ResponseFraming::Empty), 0);
        assert_eq!(ordinal(ResponseFraming::Exact { len: 5 }), 1);
        assert_eq!(ordinal(ResponseFraming::Streamed), 2);
        assert_eq!(ordinal(ResponseFraming::UntilClose), 3);

        assert!(!ResponseFraming::Empty.has_body());
        assert!(ResponseFraming::Exact { len: 5 }.has_body());
        assert!(ResponseFraming::Streamed.has_body());
        assert!(ResponseFraming::UntilClose.has_body());

        assert_eq!(ResponseFraming::Empty.known_len(), Some(0));
        assert_eq!(ResponseFraming::Exact { len: 5 }.known_len(), Some(5));
        assert_eq!(ResponseFraming::Streamed.known_len(), None);
        assert_eq!(ResponseFraming::UntilClose.known_len(), None);

        assert!(!ResponseFraming::Empty.forbids_reuse());
        assert!(!ResponseFraming::Exact { len: 5 }.forbids_reuse());
        assert!(!ResponseFraming::Streamed.forbids_reuse());
        assert!(ResponseFraming::UntilClose.forbids_reuse());
    }

    #[test]
    fn bodyless_by_status() {
        for status in [100_u16, 101, 103, 199, 204, 304] {
            assert_eq!(
                resolve(
                    &[(b"content-length", b"5")],
                    status,
                    Method::Get,
                    WireVersion::Http11
                ),
                Ok(ResponseFraming::Empty),
                "status {status} with content-length"
            );
            assert_eq!(
                resolve(
                    &[(b"transfer-encoding", b"chunked")],
                    status,
                    Method::Get,
                    WireVersion::Http11
                ),
                Ok(ResponseFraming::Empty),
                "status {status} with transfer-encoding"
            );
        }
    }

    #[test]
    fn content_length_on_304_is_not_an_error() {
        assert_eq!(
            resolve(
                &[(b"content-length", b"1234")],
                304,
                Method::Get,
                WireVersion::Http11
            ),
            Ok(ResponseFraming::Empty)
        );
    }

    #[test]
    fn bodyless_by_method() {
        assert_eq!(
            resolve(
                &[(b"content-length", b"4096")],
                200,
                Method::Head,
                WireVersion::Http11
            ),
            Ok(ResponseFraming::Empty)
        );
        assert_eq!(
            resolve(&[], 200, Method::Connect, WireVersion::Http11),
            Ok(ResponseFraming::Empty)
        );
        assert_eq!(
            resolve(
                &[(b"content-length", b"9")],
                403,
                Method::Connect,
                WireVersion::Http11
            ),
            Ok(ResponseFraming::Exact { len: 9 })
        );
    }

    #[test]
    fn until_close_on_h1_only() {
        assert_eq!(
            resolve(&[], 200, Method::Get, WireVersion::Http11),
            Ok(ResponseFraming::UntilClose)
        );
        assert_eq!(
            resolve(&[], 200, Method::Get, WireVersion::Http10),
            Ok(ResponseFraming::UntilClose)
        );
        assert_eq!(
            resolve(&[], 200, Method::Get, WireVersion::H2),
            Ok(ResponseFraming::Streamed)
        );
        assert_eq!(
            resolve(&[], 200, Method::Get, WireVersion::H3),
            Ok(ResponseFraming::Streamed)
        );
    }

    #[test]
    fn duplicate_cl_beats_bodyless_shortcut() {
        assert_eq!(
            resolve(
                &[(b"content-length", b"5"), (b"content-length", b"5")],
                304,
                Method::Get,
                WireVersion::Http11
            ),
            Err(RejectReason::ContentLengthDuplicate)
        );
        assert_eq!(
            resolve(
                &[(b"content-length", b"5"), (b"content-length", b"6")],
                200,
                Method::Head,
                WireVersion::Http11
            ),
            Err(RejectReason::ContentLengthDuplicate)
        );
    }

    #[test]
    fn te_and_cl_together() {
        assert_eq!(
            resolve(
                &[
                    (b"content-length", b"5"),
                    (b"transfer-encoding", b"chunked"),
                ],
                200,
                Method::Get,
                WireVersion::Http11
            ),
            Err(RejectReason::TransferEncodingWithContentLength)
        );
    }

    #[test]
    fn te_rules_by_version() {
        assert_eq!(
            resolve(
                &[(b"transfer-encoding", b"chunked")],
                200,
                Method::Get,
                WireVersion::Http11
            ),
            Ok(ResponseFraming::Streamed)
        );
        assert_eq!(
            resolve(
                &[(b"transfer-encoding", b"chunked")],
                200,
                Method::Get,
                WireVersion::Http10
            ),
            Err(RejectReason::TransferEncodingOnHttp10)
        );
        for version in [WireVersion::H2, WireVersion::H3] {
            assert_eq!(
                resolve(
                    &[(b"transfer-encoding", b"chunked")],
                    200,
                    Method::Get,
                    version
                ),
                Err(RejectReason::ConnectionSpecificField),
                "{version:?}"
            );
        }
    }

    #[test]
    fn zero_length_is_empty() {
        assert_eq!(
            resolve(
                &[(b"content-length", b"0")],
                200,
                Method::Get,
                WireVersion::Http11
            ),
            Ok(ResponseFraming::Empty)
        );
        assert_eq!(
            resolve(
                &[(b"content-length", b"1")],
                200,
                Method::Get,
                WireVersion::Http11
            ),
            Ok(ResponseFraming::Exact { len: 1 })
        );
    }

    proptest::proptest! {
        #[test]
        fn prop_response_framing_total(
            status_num in 100_u16..=599,
            method in proptest::sample::select(&ALL_METHODS[..]),
            version in proptest::sample::select(&ALL_VERSIONS[..]),
            cl_values in proptest::collection::vec(
                proptest::sample::select(&CL_STRATEGY_VALUES[..]),
                0..=2,
            ),
            te_values in proptest::collection::vec(
                proptest::sample::select(&TE_STRATEGY_VALUES[..]),
                0..=2,
            ),
        ) {
            let limits = Limits::DEFAULT.clamped();
            let mut arena = BytesMut::new();
            let mut builder = FieldSectionBuilder::new(&arena, &limits);
            for v in &cl_values {
                builder
                    .push(&mut arena, b"content-length", v.as_bytes())
                    .expect("every candidate value is well formed field bytes");
            }
            for v in &te_values {
                builder
                    .push(&mut arena, b"transfer-encoding", v.as_bytes())
                    .expect("every candidate value is well formed field bytes");
            }
            let section = builder.finish(&mut arena);
            let status = StatusCode::from_u16(status_num)
                .expect("every u16 in 100..=599 is a valid StatusCode");

            let result =
                resolve_response_framing(status, &method, version, &section, OtherCodings::Reject);

            if let Ok(ResponseFraming::UntilClose) = result {
                assert!(cl_values.is_empty(), "UntilClose with a content-length present");
                assert!(te_values.is_empty(), "UntilClose with a transfer-encoding present");
                assert!(!version.is_multiplexed(), "UntilClose on a multiplexed protocol");
            }
        }
    }
}
