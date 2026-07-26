// SPDX-License-Identifier: MIT OR Apache-2.0
//! Why IronTraffic refused a message.
//!
//! [`RejectReason`] is the closed set of reasons this crate refuses to turn
//! a byte stream into a request or a response. See `docs/THREAT-MODEL.md`
//! section 3 ("Refusal is not an oracle") for why the type carries no
//! payload.

use crate::scalar::StatusCode;

// D1 (decision record, PR #447 rework). `RejectReason`, `RejectReason::ALL`,
// `RejectReason::status` and `RejectReason::metric_label` used to be four
// hand-maintained artifacts. A reviewer demonstrated that adding a variant
// and making only the edits the compiler forced left it absent from `ALL`
// and defaulted to a 400 status from a wildcard arm nobody wrote, with the
// full test suite still green: every completeness test iterates `ALL`, so a
// variant missing from `ALL` is checked for nothing.
//
// This macro closes that hole structurally instead of by discipline: there
// is exactly one list, `(Variant, "metric_label", STATUS)` triples below,
// and the enum, `ALL`, `status` and `metric_label` are all generated from
// it. A new variant that forgets a status or a label is a syntax error, not
// a silent 400; a new variant is automatically a member of `ALL`, so every
// completeness test (uniqueness, snake_case shape, status range) reaches it
// for free. 25 downstream issues add variants to this enum; this is the
// only file any of them touch to do it.
macro_rules! reject_reasons {
    (
        $(
            $(#[$meta:meta])*
            ($variant:ident, $label:literal, $status:expr)
        ),+ $(,)?
    ) => {
        /// Why IronTraffic refused a message.
        ///
        /// Every variant maps to exactly one HTTP status
        /// ([`RejectReason::status`]) and one stable, `snake_case` metric
        /// label ([`RejectReason::metric_label`]). Every reject closes the
        /// connection it happened on: once a message is ambiguous we no
        /// longer know where the next message begins, so there is
        /// deliberately no "reject and continue" path.
        ///
        /// This enum, [`RejectReason::ALL`], [`RejectReason::status`] and
        /// [`RejectReason::metric_label`] are all generated from one list;
        /// see the `reject_reasons!` macro above for why.
        ///
        /// Deliberately no [`core::fmt::Display`] or [`std::error::Error`]
        /// impl (D3): `metric_label` is for metrics and logs only, and a
        /// `Display` impl would put it in reach of `format!("{err}")` in a
        /// responder, handing an attacker the exact branch that refused
        /// their message. Log sites call `.metric_label()` explicitly, so
        /// leaking it is a compile error rather than a documentation rule.
        /// [`core::fmt::Debug`] is still derived and is safe to log: it is
        /// never written to a response.
        #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
        pub enum RejectReason {
            $(
                $(#[$meta])*
                $variant,
            )+
        }

        impl RejectReason {
            /// Every variant, in declaration order.
            pub const ALL: [RejectReason; [$($label),+].len()] = [
                $(RejectReason::$variant,)+
            ];

            /// The HTTP status IronTraffic answers with when refusing for
            /// this reason.
            ///
            /// Generated from the same one list as [`RejectReason::ALL`]
            /// and [`RejectReason::metric_label`] (D1): a new variant names
            /// its status right next to its label, so there is no wildcard
            /// arm a new variant could silently fall into.
            #[must_use]
            pub const fn status(self) -> StatusCode {
                match self {
                    $(RejectReason::$variant => $status,)+
                }
            }

            /// The stable, `snake_case` metric label for this reason. Never
            /// changes once shipped: operator dashboards and alerts are
            /// keyed on it.
            ///
            /// This value is for metrics and logs ONLY. It must never
            /// appear in a response body, a response header or a reason
            /// phrase: naming the branch that refused turns every refusal
            /// into a desync-probing oracle. See `docs/THREAT-MODEL.md`
            /// section 3.
            #[must_use]
            pub const fn metric_label(self) -> &'static str {
                match self {
                    $(RejectReason::$variant => $label,)+
                }
            }
        }
    };
}

reject_reasons! {
    // request line, method and version (HTTP/1 unless noted)
    /// The HTTP/1 request line, including its trailing CRLF, exceeded
    /// `Limits::max_request_line_bytes`.
    (RequestLineTooLong, "request_line_too_long", StatusCode::URI_TOO_LONG),
    /// The HTTP/1 request line could not be split into a method, a target
    /// and a version.
    (RequestLineMalformed, "request_line_malformed", StatusCode::BAD_REQUEST),
    /// The method token was empty or contained a byte that is not a `tchar`.
    (MethodInvalid, "method_invalid", StatusCode::BAD_REQUEST),
    /// The method token exceeded the effective method length cap.
    (MethodTooLong, "method_too_long", StatusCode::NOT_IMPLEMENTED),
    /// The declared HTTP version is not one this crate implements.
    (VersionUnsupported, "version_unsupported", StatusCode::VERSION_NOT_SUPPORTED),
    /// The request target is not a valid origin-form, absolute-form,
    /// authority-form or asterisk-form target, OR it is syntactically one
    /// of those forms but is refused on reverse-proxy policy grounds rather
    /// than on syntax: for example `GET http://evil.com/path`, whose
    /// absolute-form target is well formed but names an origin this proxy
    /// will not relay to.
    (TargetFormInvalid, "target_form_invalid", StatusCode::BAD_REQUEST),
    /// The request target carried a fragment (`#...`), which is never valid
    /// on the wire.
    (TargetFragment, "target_fragment", StatusCode::BAD_REQUEST),
    // field syntax, applied identically to H1, H2 and H3
    /// A field line named an empty field name.
    (FieldNameEmpty, "field_name_empty", StatusCode::BAD_REQUEST),
    /// A field name contained a byte that is not a valid field-name
    /// character.
    (FieldNameInvalidByte, "field_name_invalid_byte", StatusCode::BAD_REQUEST),
    /// A field name contained an uppercase ASCII letter. Version
    /// independent: malformed on H2 and H3, and on H1 it means the caller
    /// skipped `normalize_name_into`.
    (FieldNameUppercase, "field_name_uppercase", StatusCode::BAD_REQUEST),
    /// A field name contained an underscore. Refused anywhere in the name,
    /// not only at the start, because NGINX, CGI and PHP fold `-` and `_`
    /// together while Go does not.
    (FieldNameUnderscore, "field_name_underscore", StatusCode::BAD_REQUEST),
    /// A field value contained a byte that is not permitted in a field
    /// value.
    (FieldValueInvalidByte, "field_value_invalid_byte", StatusCode::BAD_REQUEST),
    /// A field value on a multiplexed protocol (H2 or H3) began with SP or
    /// HTAB. Such a value is malformed and is refused rather than trimmed;
    /// on HTTP/1 the surrounding OWS is stripped and this reason does not
    /// apply.
    (FieldValueLeadingWhitespace, "field_value_leading_whitespace", StatusCode::BAD_REQUEST),
    /// A field value on a multiplexed protocol (H2 or H3) ended with SP or
    /// HTAB. Such a value is malformed and is refused rather than trimmed;
    /// on HTTP/1 the surrounding OWS is stripped and this reason does not
    /// apply.
    (FieldValueTrailingWhitespace, "field_value_trailing_whitespace", StatusCode::BAD_REQUEST),
    /// A field line had whitespace between the field name and the colon.
    (WhitespaceBeforeColon, "whitespace_before_colon", StatusCode::BAD_REQUEST),
    /// A field line used obsolete line folding.
    (ObsFold, "obs_fold", StatusCode::BAD_REQUEST),
    /// A bare CR appeared where only CRLF is permitted.
    (BareCr, "bare_cr", StatusCode::BAD_REQUEST),
    /// A bare LF appeared where only CRLF is permitted.
    (BareLf, "bare_lf", StatusCode::BAD_REQUEST),
    /// One field line exceeded `Limits::max_field_line_bytes`.
    (FieldLineTooLong, "field_line_too_long", StatusCode::HEADERS_TOO_LARGE),
    /// The header section exceeded `Limits::max_field_count` field lines.
    (FieldCountExceeded, "field_count_exceeded", StatusCode::HEADERS_TOO_LARGE),
    /// The header section exceeded `Limits::max_header_list_bytes`.
    (HeaderListTooLarge, "header_list_too_large", StatusCode::HEADERS_TOO_LARGE),
    // framing
    /// `Content-Length` appeared more than once. Identical values are
    /// refused too.
    (ContentLengthDuplicate, "content_length_duplicate", StatusCode::BAD_REQUEST),
    /// `Content-Length`'s value is not a valid non-negative decimal integer.
    (ContentLengthInvalid, "content_length_invalid", StatusCode::BAD_REQUEST),
    /// `Content-Length`'s value overflowed the type used to hold it.
    (ContentLengthOverflow, "content_length_overflow", StatusCode::BAD_REQUEST),
    /// The number of body bytes received did not match the declared
    /// `Content-Length`.
    (ContentLengthMismatch, "content_length_mismatch", StatusCode::BAD_REQUEST),
    /// Both `Transfer-Encoding` and `Content-Length` were present, which
    /// RFC 9112 forbids.
    (TransferEncodingWithContentLength, "transfer_encoding_with_content_length", StatusCode::BAD_REQUEST),
    /// `Transfer-Encoding` was present on an HTTP/1.0 message, which does
    /// not define it.
    (TransferEncodingOnHttp10, "transfer_encoding_on_http10", StatusCode::BAD_REQUEST),
    /// `Transfer-Encoding`'s final coding was not `chunked`. Checked before
    /// `TransferEncodingUnsupportedCoding`, so an unrecognized but
    /// well-formed final coding such as `gzip` is refused for this reason
    /// instead.
    (TransferEncodingFinalNotChunked, "transfer_encoding_final_not_chunked", StatusCode::BAD_REQUEST),
    /// `chunked` appeared more than once in `Transfer-Encoding`.
    (TransferEncodingChunkedRepeated, "transfer_encoding_chunked_repeated", StatusCode::BAD_REQUEST),
    /// `Transfer-Encoding` contained an empty coding token.
    (TransferEncodingEmptyToken, "transfer_encoding_empty_token", StatusCode::BAD_REQUEST),
    /// `Transfer-Encoding` named a coding this crate does not implement.
    /// Reserved for a malformed coding token, for example one containing a
    /// control byte; a well-formed but unrecognized final coding is instead
    /// refused as `TransferEncodingFinalNotChunked`, which is checked
    /// first.
    (TransferEncodingUnsupportedCoding, "transfer_encoding_unsupported_coding", StatusCode::NOT_IMPLEMENTED),
    /// A body was present on a message for which the method or status
    /// forbids one.
    (BodyNotAllowedForMethod, "body_not_allowed_for_method", StatusCode::BAD_REQUEST),
    // chunked framing and trailers
    /// A chunk size line is not a valid hexadecimal chunk size.
    (ChunkSizeInvalid, "chunk_size_invalid", StatusCode::BAD_REQUEST),
    /// A chunk size overflowed the type used to hold it.
    (ChunkSizeOverflow, "chunk_size_overflow", StatusCode::BAD_REQUEST),
    /// A chunk extension is not syntactically valid.
    (ChunkExtInvalid, "chunk_ext_invalid", StatusCode::BAD_REQUEST),
    /// A chunk's extensions exceeded `Limits::max_chunk_ext_bytes`.
    (ChunkExtTooLong, "chunk_ext_too_long", StatusCode::BAD_REQUEST),
    /// A chunk was not followed by the expected CRLF terminator.
    (ChunkTerminatorInvalid, "chunk_terminator_invalid", StatusCode::BAD_REQUEST),
    /// A trailer section named a field that is forbidden in trailers.
    (TrailerFieldForbidden, "trailer_field_forbidden", StatusCode::BAD_REQUEST),
    /// Bytes followed the terminating chunk and trailer section.
    (TrailingGarbage, "trailing_garbage", StatusCode::BAD_REQUEST),
    // host and authority
    /// No `Host` field was present on a message that requires one.
    (HostMissing, "host_missing", StatusCode::BAD_REQUEST),
    /// `Host` appeared more than once.
    (HostDuplicate, "host_duplicate", StatusCode::BAD_REQUEST),
    /// The authority component was empty.
    (AuthorityEmpty, "authority_empty", StatusCode::BAD_REQUEST),
    /// The authority component exceeded `Limits::max_authority_bytes`.
    (AuthorityTooLong, "authority_too_long", StatusCode::BAD_REQUEST),
    /// The authority component contained a byte that is not permitted in an
    /// authority.
    (AuthorityInvalidByte, "authority_invalid_byte", StatusCode::BAD_REQUEST),
    /// The authority component contained a non-ASCII byte.
    (AuthorityNonAscii, "authority_non_ascii", StatusCode::BAD_REQUEST),
    /// The authority component's port is not a valid port number.
    (AuthorityPortInvalid, "authority_port_invalid", StatusCode::BAD_REQUEST),
    /// The authority in the request target disagreed with the `Host` field.
    (AuthorityMismatch, "authority_mismatch", StatusCode::BAD_REQUEST),
    // path and query
    /// The request target's path component was empty.
    (PathEmpty, "path_empty", StatusCode::BAD_REQUEST),
    /// The request target's path component exceeded `Limits::max_path_bytes`.
    (PathTooLong, "path_too_long", StatusCode::URI_TOO_LONG),
    /// The path contained a byte that is not permitted unencoded.
    (PathInvalidByte, "path_invalid_byte", StatusCode::BAD_REQUEST),
    /// A percent-encoding in the path was truncated at the end of the path.
    (PathPercentTruncated, "path_percent_truncated", StatusCode::BAD_REQUEST),
    /// A percent-encoding in the path was followed by a non-hexadecimal
    /// digit.
    (PathPercentInvalidHex, "path_percent_invalid_hex", StatusCode::BAD_REQUEST),
    /// A percent-encoding in the path decoded to a NUL byte.
    (PathEncodedNul, "path_encoded_nul", StatusCode::BAD_REQUEST),
    /// A percent-encoding in the path decoded to a dot-segment component.
    (PathEncodedDot, "path_encoded_dot", StatusCode::BAD_REQUEST),
    /// A percent-encoding in the path decoded to a path separator.
    (PathEncodedSlash, "path_encoded_slash", StatusCode::BAD_REQUEST),
    /// Normalizing the path's dot segments would climb above the root.
    (PathTraversalAboveRoot, "path_traversal_above_root", StatusCode::BAD_REQUEST),
    /// The query component contained a byte that is not permitted.
    (QueryInvalidByte, "query_invalid_byte", StatusCode::BAD_REQUEST),
    // expectation and interim responses
    /// The `Expect` field named an expectation this crate does not
    /// understand.
    (ExpectUnsupported, "expect_unsupported", StatusCode::EXPECTATION_FAILED),
    /// More interim (1xx) responses were relayed for one request than
    /// `Limits::max_interim_responses` permits.
    (InterimResponseCountExceeded, "interim_response_count_exceeded", StatusCode::BAD_GATEWAY),
    /// The interim (1xx) responses relayed for one request exceeded
    /// `Limits::max_interim_bytes`.
    (InterimResponseBytesExceeded, "interim_response_bytes_exceeded", StatusCode::BAD_GATEWAY),
    // multiplexed protocols (H2, H3)
    /// A pseudo-header field named a pseudo-header this crate does not
    /// define, or named one it does define but with a malformed value: a
    /// bare `:`, a `:status` on a request, an unsupported `:scheme`, and
    /// similar. The one exception is a `:protocol` value other than
    /// `websocket`, which RFC 9220 Section 3 requires a 501 for; that case
    /// is the separate `PseudoProtocolUnsupported` reason below, because one
    /// variant cannot carry two statuses.
    (PseudoHeaderUnknown, "pseudo_header_unknown", StatusCode::BAD_REQUEST),
    /// A `:protocol` pseudo-header on an extended-CONNECT request named a
    /// protocol other than `websocket`, the only one this crate implements.
    /// RFC 9220 Section 3 requires 501 for this specific case; every other
    /// malformed pseudo-header, including an unrelated unknown name, is
    /// `PseudoHeaderUnknown` (400) above.
    (PseudoProtocolUnsupported, "pseudo_protocol_unsupported", StatusCode::NOT_IMPLEMENTED),
    /// A pseudo-header field appeared more than once.
    (PseudoHeaderDuplicate, "pseudo_header_duplicate", StatusCode::BAD_REQUEST),
    /// A required pseudo-header field was absent.
    (PseudoHeaderMissing, "pseudo_header_missing", StatusCode::BAD_REQUEST),
    /// A pseudo-header field appeared after a regular field.
    (PseudoHeaderAfterField, "pseudo_header_after_field", StatusCode::BAD_REQUEST),
    /// A pseudo-header field appeared in a trailer section, where none are
    /// permitted.
    (PseudoHeaderInTrailer, "pseudo_header_in_trailer", StatusCode::BAD_REQUEST),
    /// A connection-specific field (forbidden on a multiplexed protocol)
    /// was present.
    (ConnectionSpecificField, "connection_specific_field", StatusCode::BAD_REQUEST),
    /// The `TE` field carried a value other than `trailers`.
    (TeValueNotTrailers, "te_value_not_trailers", StatusCode::BAD_REQUEST),
    // forwarding chain
    /// The forwarding chain exceeded `Limits::max_forwarded_elements`.
    (ForwardedElementLimit, "forwarded_element_limit", StatusCode::BAD_REQUEST),
    /// The forwarding chain's field values exceeded
    /// `Limits::max_forwarded_bytes`.
    (ForwardedBytesLimit, "forwarded_bytes_limit", StatusCode::BAD_REQUEST),
    /// A forwarding chain element repeated a parameter that must appear at
    /// most once.
    (ForwardedDuplicateParam, "forwarded_duplicate_param", StatusCode::BAD_REQUEST),
    /// A forwarding chain element is not syntactically valid.
    (ForwardedSyntax, "forwarded_syntax", StatusCode::BAD_REQUEST),
    // rewrite pipeline
    /// A rewrite chain performed more re-route cycles than
    /// `Limits::max_rewrites` (clamped) permits.
    (RewriteLimitExceeded, "rewrite_limit_exceeded", StatusCode::INTERNAL_ERROR),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_has_72_entries() {
        // Name predates D10 (PR #447 rework), which added
        // `PseudoProtocolUnsupported` and raised the true count to 73; kept
        // as-is rather than renamed, because scripts/test-census.sh treats
        // a disappearing test name as a possible regression and this crate
        // has no local override for that. The assertion below is accurate.
        assert_eq!(RejectReason::ALL.len(), 73);
    }

    #[test]
    fn all_contains_every_variant() {
        // An exhaustive match: adding a variant to `RejectReason` without
        // adding an arm here is a compile error, which is what keeps this
        // test honest as the enum grows.
        fn seen(r: RejectReason) -> usize {
            match r {
                RejectReason::RequestLineTooLong => 0,
                RejectReason::RequestLineMalformed => 1,
                RejectReason::MethodInvalid => 2,
                RejectReason::MethodTooLong => 3,
                RejectReason::VersionUnsupported => 4,
                RejectReason::TargetFormInvalid => 5,
                RejectReason::TargetFragment => 6,
                RejectReason::FieldNameEmpty => 7,
                RejectReason::FieldNameInvalidByte => 8,
                RejectReason::FieldNameUppercase => 9,
                RejectReason::FieldNameUnderscore => 10,
                RejectReason::FieldValueInvalidByte => 11,
                RejectReason::FieldValueLeadingWhitespace => 12,
                RejectReason::FieldValueTrailingWhitespace => 13,
                RejectReason::WhitespaceBeforeColon => 14,
                RejectReason::ObsFold => 15,
                RejectReason::BareCr => 16,
                RejectReason::BareLf => 17,
                RejectReason::FieldLineTooLong => 18,
                RejectReason::FieldCountExceeded => 19,
                RejectReason::HeaderListTooLarge => 20,
                RejectReason::ContentLengthDuplicate => 21,
                RejectReason::ContentLengthInvalid => 22,
                RejectReason::ContentLengthOverflow => 23,
                RejectReason::ContentLengthMismatch => 24,
                RejectReason::TransferEncodingWithContentLength => 25,
                RejectReason::TransferEncodingOnHttp10 => 26,
                RejectReason::TransferEncodingFinalNotChunked => 27,
                RejectReason::TransferEncodingChunkedRepeated => 28,
                RejectReason::TransferEncodingEmptyToken => 29,
                RejectReason::TransferEncodingUnsupportedCoding => 30,
                RejectReason::BodyNotAllowedForMethod => 31,
                RejectReason::ChunkSizeInvalid => 32,
                RejectReason::ChunkSizeOverflow => 33,
                RejectReason::ChunkExtInvalid => 34,
                RejectReason::ChunkExtTooLong => 35,
                RejectReason::ChunkTerminatorInvalid => 36,
                RejectReason::TrailerFieldForbidden => 37,
                RejectReason::TrailingGarbage => 38,
                RejectReason::HostMissing => 39,
                RejectReason::HostDuplicate => 40,
                RejectReason::AuthorityEmpty => 41,
                RejectReason::AuthorityTooLong => 42,
                RejectReason::AuthorityInvalidByte => 43,
                RejectReason::AuthorityNonAscii => 44,
                RejectReason::AuthorityPortInvalid => 45,
                RejectReason::AuthorityMismatch => 46,
                RejectReason::PathEmpty => 47,
                RejectReason::PathTooLong => 48,
                RejectReason::PathInvalidByte => 49,
                RejectReason::PathPercentTruncated => 50,
                RejectReason::PathPercentInvalidHex => 51,
                RejectReason::PathEncodedNul => 52,
                RejectReason::PathEncodedDot => 53,
                RejectReason::PathEncodedSlash => 54,
                RejectReason::PathTraversalAboveRoot => 55,
                RejectReason::QueryInvalidByte => 56,
                RejectReason::ExpectUnsupported => 57,
                RejectReason::InterimResponseCountExceeded => 58,
                RejectReason::InterimResponseBytesExceeded => 59,
                RejectReason::PseudoHeaderUnknown => 60,
                RejectReason::PseudoProtocolUnsupported => 61,
                RejectReason::PseudoHeaderDuplicate => 62,
                RejectReason::PseudoHeaderMissing => 63,
                RejectReason::PseudoHeaderAfterField => 64,
                RejectReason::PseudoHeaderInTrailer => 65,
                RejectReason::ConnectionSpecificField => 66,
                RejectReason::TeValueNotTrailers => 67,
                RejectReason::ForwardedElementLimit => 68,
                RejectReason::ForwardedBytesLimit => 69,
                RejectReason::ForwardedDuplicateParam => 70,
                RejectReason::ForwardedSyntax => 71,
                RejectReason::RewriteLimitExceeded => 72,
            }
        }

        // D9: this used to sort both sides before comparing, which cannot
        // observe two entries of `ALL` being swapped (both orderings sort
        // to the same result). Compare the UNSORTED positions directly
        // against `0..73` instead: `ALL`'s declaration order must exactly
        // match `seen`'s index for every variant, at its own position.
        let indices: Vec<usize> = RejectReason::ALL.iter().copied().map(seen).collect();
        let expected: Vec<usize> = (0..73).collect();
        assert_eq!(indices, expected);
    }

    #[test]
    fn metric_labels_are_unique() {
        let mut labels: Vec<&str> = RejectReason::ALL.iter().map(|r| r.metric_label()).collect();
        labels.sort_unstable();
        assert_eq!(labels.len(), 73);
        for pair in labels.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate metric label: {}", pair[0]);
        }
    }

    #[test]
    fn metric_labels_are_snake_case() {
        for reason in RejectReason::ALL {
            let label = reason.metric_label();
            assert!(!label.is_empty(), "{reason:?} has an empty metric label");
            assert!(
                label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{reason:?}'s metric label {label:?} has a byte outside a-z, 0-9, _"
            );
            assert!(
                !label.starts_with('_') && !label.ends_with('_'),
                "{reason:?}'s metric label {label:?} starts or ends with _"
            );
        }
    }

    #[test]
    fn metric_labels_match_debug_name() {
        // D9: metric label VALUES were unpinned. Renaming `bare_lf`, and
        // swapping the labels of `PathEncodedDot` and `PathEncodedSlash`,
        // both survived every prior test. Derive the expected label from
        // the `Debug` name (an INDEPENDENT oracle: it comes from
        // `#[derive(Debug)]`, not from the macro's `$label` literal this
        // test is checking) so a swap or a rename shows up as a mismatch
        // instead of silently passing.
        fn snake_case_of_debug_name(name: &str) -> String {
            let mut out = String::new();
            for (i, c) in name.chars().enumerate() {
                if c.is_ascii_uppercase() {
                    if i != 0 {
                        out.push('_');
                    }
                    out.push(c.to_ascii_lowercase());
                } else {
                    out.push(c);
                }
            }
            out
        }

        for reason in RejectReason::ALL {
            let want = snake_case_of_debug_name(&format!("{reason:?}"));
            assert_eq!(
                reason.metric_label(),
                want,
                "{reason:?}'s metric label diverges from its own Debug name"
            );
        }
    }

    #[test]
    fn status_codes_in_range() {
        for reason in RejectReason::ALL {
            let code = reason.status().as_u16();
            assert!(
                (100..=599).contains(&code),
                "{reason:?} maps to out-of-range status {code}"
            );
        }
    }

    #[test]
    fn specific_status_mappings() {
        assert_eq!(RejectReason::RequestLineTooLong.status().as_u16(), 414);
        assert_eq!(RejectReason::PathTooLong.status().as_u16(), 414);
        assert_eq!(RejectReason::ExpectUnsupported.status().as_u16(), 417);
        assert_eq!(RejectReason::FieldLineTooLong.status().as_u16(), 431);
        assert_eq!(RejectReason::FieldCountExceeded.status().as_u16(), 431);
        assert_eq!(RejectReason::HeaderListTooLarge.status().as_u16(), 431);
        assert_eq!(RejectReason::MethodTooLong.status().as_u16(), 501);
        assert_eq!(
            RejectReason::TransferEncodingUnsupportedCoding
                .status()
                .as_u16(),
            501
        );
        assert_eq!(RejectReason::VersionUnsupported.status().as_u16(), 505);
        assert_eq!(
            RejectReason::InterimResponseCountExceeded.status().as_u16(),
            502
        );
        assert_eq!(
            RejectReason::InterimResponseBytesExceeded.status().as_u16(),
            502
        );
        assert_eq!(RejectReason::RewriteLimitExceeded.status().as_u16(), 500);
        assert_eq!(RejectReason::BareLf.status().as_u16(), 400);
    }

    #[test]
    fn full_status_table() {
        // D9: 59 of the (then) 72 status mappings were unasserted behind
        // `specific_status_mappings`' partial, hand-picked list; only
        // `status_codes_in_range` covered the rest, and it only checks
        // 100..=599, not the exact value. One entry per position of `ALL`,
        // so this cannot omit a variant the way a hand-picked list can.
        const EXPECTED: [u16; 73] = [
            414, // RequestLineTooLong
            400, // RequestLineMalformed
            400, // MethodInvalid
            501, // MethodTooLong
            505, // VersionUnsupported
            400, // TargetFormInvalid
            400, // TargetFragment
            400, // FieldNameEmpty
            400, // FieldNameInvalidByte
            400, // FieldNameUppercase
            400, // FieldNameUnderscore
            400, // FieldValueInvalidByte
            400, // FieldValueLeadingWhitespace
            400, // FieldValueTrailingWhitespace
            400, // WhitespaceBeforeColon
            400, // ObsFold
            400, // BareCr
            400, // BareLf
            431, // FieldLineTooLong
            431, // FieldCountExceeded
            431, // HeaderListTooLarge
            400, // ContentLengthDuplicate
            400, // ContentLengthInvalid
            400, // ContentLengthOverflow
            400, // ContentLengthMismatch
            400, // TransferEncodingWithContentLength
            400, // TransferEncodingOnHttp10
            400, // TransferEncodingFinalNotChunked
            400, // TransferEncodingChunkedRepeated
            400, // TransferEncodingEmptyToken
            501, // TransferEncodingUnsupportedCoding
            400, // BodyNotAllowedForMethod
            400, // ChunkSizeInvalid
            400, // ChunkSizeOverflow
            400, // ChunkExtInvalid
            400, // ChunkExtTooLong
            400, // ChunkTerminatorInvalid
            400, // TrailerFieldForbidden
            400, // TrailingGarbage
            400, // HostMissing
            400, // HostDuplicate
            400, // AuthorityEmpty
            400, // AuthorityTooLong
            400, // AuthorityInvalidByte
            400, // AuthorityNonAscii
            400, // AuthorityPortInvalid
            400, // AuthorityMismatch
            400, // PathEmpty
            414, // PathTooLong
            400, // PathInvalidByte
            400, // PathPercentTruncated
            400, // PathPercentInvalidHex
            400, // PathEncodedNul
            400, // PathEncodedDot
            400, // PathEncodedSlash
            400, // PathTraversalAboveRoot
            400, // QueryInvalidByte
            417, // ExpectUnsupported
            502, // InterimResponseCountExceeded
            502, // InterimResponseBytesExceeded
            400, // PseudoHeaderUnknown
            501, // PseudoProtocolUnsupported
            400, // PseudoHeaderDuplicate
            400, // PseudoHeaderMissing
            400, // PseudoHeaderAfterField
            400, // PseudoHeaderInTrailer
            400, // ConnectionSpecificField
            400, // TeValueNotTrailers
            400, // ForwardedElementLimit
            400, // ForwardedBytesLimit
            400, // ForwardedDuplicateParam
            400, // ForwardedSyntax
            500, // RewriteLimitExceeded
        ];
        assert_eq!(EXPECTED.len(), RejectReason::ALL.len());
        for (reason, want) in RejectReason::ALL.iter().zip(EXPECTED.iter()) {
            assert_eq!(
                reason.status().as_u16(),
                *want,
                "{reason:?} expected status {want}"
            );
        }
    }

    #[test]
    fn reject_reason_is_payload_free() {
        assert_eq!(std::mem::size_of::<RejectReason>(), 1);
    }
}
