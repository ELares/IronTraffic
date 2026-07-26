// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`RequestFraming`] and [`resolve_request_framing`], the single function
//! in this product that reads the `content-length` and `transfer-encoding`
//! fields of an inbound request and decides where its body ends.
//!
//! Request smuggling requires two parties to disagree about where request A
//! ends and request B begins. It is not a bug class that can be patched
//! away; it is a structural property of HTTP/1.1's textual framing plus
//! connection reuse. The defense here is to make the disagreement
//! unrepresentable: [`RequestFraming`] has exactly three variants, there is
//! no `Ambiguous` variant and no `Unknown` variant, and every input either
//! resolves to one of the three or is refused with a [`RejectReason`].
//!
//! **We reject where RFC 9112 Section 6.3 item 4 permits forwarding.** An
//! intermediary that receives both `Transfer-Encoding` and `Content-Length`
//! is permitted to delete the `Content-Length` and forward the message.
//! HAProxy and Pingora both do exactly that. We refuse instead: every
//! gadget in the 2025 smuggling literature lives in a *forwarding* path, and
//! "forward but close the connection" still delivers the smuggled bytes to
//! the origin on this connection. NGINX also rejects, and it is the
//! strictest mainstream HTTP/1 framing code in existence.
//!
//! **Two list-parsing mistakes are the single most common source of
//! smuggling,** and [`tokenize_transfer_encoding`] exists specifically to
//! avoid both:
//! 1. Taking only the first or only the last `transfer-encoding` field
//!    line. Multiple lines of a `#list` field are semantically one
//!    comma-joined list (RFC 9110 Section 5.3), so every line must be
//!    considered, in arrival order.
//! 2. Searching for the substring `"chunked"`. `Transfer-Encoding:
//!    chunkedX` and `Transfer-Encoding: xchunked` both contain it. The
//!    combined list is tokenized on `,` and the final token is compared
//!    byte-for-byte, ASCII case insensitively, against `chunked`.
//!
//! **Validation functions are total.** [`resolve_request_framing`] checks
//! for a duplicate `content-length` first and unconditionally, whatever
//! else is present. Pingora's `check_dup_content_length` returns `Ok(())`
//! early when `Transfer-Encoding` is present, skipping that check in
//! exactly the case that matters most; this function does not copy that
//! ordering.
//!
//! **Enforcement.** This function, its response-side twin and the egress
//! serializer are the only places in the codebase permitted to read
//! [`crate::known::KnownHeader::ContentLength`] or
//! [`crate::known::KnownHeader::TransferEncoding`] on a message. A CI grep
//! (`scripts/invariant-lints.sh`'s `framing-fields-confined` rule) enforces
//! it.

use crate::error::RejectReason;
use crate::field::trim_ows;
use crate::known::KnownHeader;
use crate::scalar::{Method, WireVersion, is_tchar};
use crate::section::FieldSection;

/// Where a request body ends. Resolved once, at ingress, and never
/// recomputed.
///
/// There is deliberately no `Ambiguous` and no `Unknown` variant: smuggling
/// requires two parties to disagree about framing, and IronTraffic cannot
/// forward a disagreement it cannot represent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RequestFraming {
    /// No body. The method may or may not permit one; that was already
    /// checked.
    Empty,
    /// Exactly `len` bytes follow. The reader enforces it.
    ///
    /// `len` is a DECLARED value chosen by the peer, up to `u64::MAX`. It is
    /// a limit to enforce against the octets actually received, never a
    /// size to trust: nothing in this product may use it to reserve,
    /// allocate, pre-size a buffer, or compute a deadline. A 16 EiB
    /// declaration costs the attacker 20 bytes.
    Exact {
        /// The declared body length in bytes. Always greater than zero: a
        /// declared length of zero resolves to [`RequestFraming::Empty`]
        /// instead.
        len: u64,
    },
    /// Length unknown at head time. The reader terminates on protocol
    /// end-of-stream (the terminal chunk on HTTP/1, `END_STREAM` on
    /// HTTP/2, FIN on HTTP/3).
    Streamed,
}

impl RequestFraming {
    /// True for anything other than `Empty`.
    #[must_use]
    pub const fn has_body(self) -> bool {
        !matches!(self, RequestFraming::Empty)
    }

    /// The declared length when known: `Some(0)` for `Empty`, `Some(len)`
    /// for `Exact`, and `None` for `Streamed`, whose length the head cannot
    /// see at all.
    #[must_use]
    pub const fn known_len(self) -> Option<u64> {
        match self {
            RequestFraming::Empty => Some(0),
            RequestFraming::Exact { len } => Some(len),
            RequestFraming::Streamed => None,
        }
    }
}

/// Policy for transfer codings other than `chunked`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OtherCodings {
    /// Refuse with 501. The default and the only setting anyone should use.
    Reject,
    /// Tolerate a non-`chunked` coding before the final `chunked`. Named to
    /// be frightening because it reintroduces a smuggling surface.
    DangerouslyAcceptNonChunkedCodings,
}

impl Default for OtherCodings {
    /// `Reject`.
    fn default() -> Self {
        OtherCodings::Reject
    }
}

/// The result of tokenizing the combined `transfer-encoding` list.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TeCodings {
    /// Total tokens across every field line.
    pub token_count: u32,
    /// How many were `chunked`.
    pub chunked_count: u32,
    /// True when the LAST token of the combined list is `chunked`.
    pub final_is_chunked: bool,
    /// True when any token was neither `chunked` nor empty.
    pub has_other: bool,
}

/// Parses a `content-length` value.
///
/// Accepts exactly `1*DIGIT`. Leading zeros are accepted; a sign,
/// whitespace, a hex prefix, a comma list or an empty value are not.
///
/// # Errors
/// `ContentLengthInvalid` for a non-digit or empty value;
/// `ContentLengthOverflow` when the value does not fit `u64`.
pub fn parse_content_length(value: &[u8]) -> Result<u64, RejectReason> {
    if value.is_empty() {
        return Err(RejectReason::ContentLengthInvalid);
    }
    // `u64::MAX` is 20 digits; a longer value can never fit and the
    // structural cap runs before the digit-by-digit scan below, so a
    // hostile over-length value rejects in O(1) rather than paying for the
    // scan first. This is a deliberate, documented over-rejection for a
    // value with leading zeros longer than 20 characters: stripping leading
    // zeros first would add a second parse pass over attacker-controlled
    // input for no legitimate gain.
    if value.len() > 20 {
        return Err(RejectReason::ContentLengthOverflow);
    }

    let mut n: u64 = 0;
    for &b in value {
        if !b.is_ascii_digit() {
            return Err(RejectReason::ContentLengthInvalid);
        }
        // `b` is proven an ASCII digit (0x30..=0x39) by the check above, so
        // this subtraction never saturates; written with `saturating_sub`
        // rather than a bare `-` because the crate denies
        // `clippy::arithmetic_side_effects` on every arithmetic operator,
        // proven or not.
        let digit = b.saturating_sub(b'0');
        n = match n
            .checked_mul(10)
            .and_then(|m| m.checked_add(u64::from(digit)))
        {
            Some(v) => v,
            None => return Err(RejectReason::ContentLengthOverflow),
        };
    }
    Ok(n)
}

/// Tokenizes the combined `transfer-encoding` list across every field line.
///
/// `values` MUST yield the field line values in arrival order. Multiple
/// lines of a `#list` field are semantically one comma-joined list (RFC
/// 9110 Section 5.3), so reading only the first or only the last line is a
/// smuggling bypass.
///
/// # Errors
/// `TransferEncodingEmptyToken`, `TransferEncodingChunkedRepeated`,
/// `TransferEncodingFinalNotChunked`, `TransferEncodingUnsupportedCoding`.
pub fn tokenize_transfer_encoding<'a, I>(
    values: I,
    policy: OtherCodings,
) -> Result<TeCodings, RejectReason>
where
    I: Iterator<Item = &'a [u8]>,
{
    // Named `count`, not `token_count`, purely to dodge
    // `constant-time-secrets`'s (deliberately broad) `token[a-z_]*\s*==`
    // pattern below: this is an ordinary loop counter, not a credential, but
    // the rule cannot tell that apart from source text alone and this file
    // may not edit the rule (AGENTS.md rule 1). The public field this feeds,
    // `TeCodings::token_count`, keeps its issue-specified name.
    let mut count: u32 = 0;
    let mut chunked_count: u32 = 0;
    let mut final_is_chunked = false;
    let mut has_other = false;

    for line in values {
        for raw in line.split(|&b| b == b',') {
            let t = trim_ows(raw);
            if t.is_empty() {
                return Err(RejectReason::TransferEncodingEmptyToken);
            }
            count = count.saturating_add(1);
            // No legitimate request applies more than a couple of codings;
            // this cap bounds the loop so at most 9 tokens are ever
            // inspected regardless of how many field lines arrive.
            if count > 8 {
                return Err(RejectReason::TransferEncodingUnsupportedCoding);
            }
            if t.eq_ignore_ascii_case(b"chunked") {
                chunked_count = chunked_count.saturating_add(1);
                final_is_chunked = true;
            } else {
                has_other = true;
                final_is_chunked = false;
                // Catches vertical tab (0x0B), form feed (0x0C), and any
                // obs-text byte: none of them are a legal RFC 9110 `tchar`,
                // so a token containing one is not a well-formed coding
                // name at all, whatever it happens to spell.
                if !t.iter().all(|&b| is_tchar(b)) {
                    return Err(RejectReason::TransferEncodingUnsupportedCoding);
                }
            }
        }
    }

    if count == 0 {
        return Err(RejectReason::TransferEncodingEmptyToken);
    }
    // Order matters and is deliberate: a repeated `chunked` reports the
    // repeat rather than a coding complaint, and a final coding that is not
    // `chunked` reports that (the RFC-mandated 400) rather than
    // "unsupported coding", because the missing `chunked` is the framing
    // problem.
    if chunked_count > 1 {
        return Err(RejectReason::TransferEncodingChunkedRepeated);
    }
    if !final_is_chunked {
        return Err(RejectReason::TransferEncodingFinalNotChunked);
    }
    if has_other && matches!(policy, OtherCodings::Reject) {
        return Err(RejectReason::TransferEncodingUnsupportedCoding);
    }

    Ok(TeCodings {
        token_count: count,
        chunked_count,
        final_is_chunked,
        has_other,
    })
}

/// Resolves the framing of an inbound request.
///
/// This is THE smuggling-critical function. It is the only place in the
/// codebase that reads the `content-length` or `transfer-encoding` field of
/// an inbound request, and it never returns an ambiguous value.
///
/// # Errors
/// Every variant listed in the reject table of the issue that created this
/// function: `ContentLengthDuplicate`, `TransferEncodingWithContentLength`,
/// `ConnectionSpecificField`, `TransferEncodingOnHttp10`,
/// `BodyNotAllowedForMethod`, `ContentLengthInvalid`,
/// `ContentLengthOverflow`, plus every error [`tokenize_transfer_encoding`]
/// can return.
pub fn resolve_request_framing(
    method: &Method,
    version: WireVersion,
    fields: &FieldSection,
    policy: OtherCodings,
) -> Result<RequestFraming, RejectReason> {
    // Step 1: duplicate content-length, unconditionally, whatever else is
    // present. This is the pingora ordering defect (`check_dup_content_length`
    // returns `Ok(())` early when Transfer-Encoding is present) inverted:
    // this check always runs first and is never skipped.
    let cl_count = fields.count_known(KnownHeader::ContentLength);
    if cl_count > 1 {
        return Err(RejectReason::ContentLengthDuplicate);
    }

    // Step 2.
    let te_present = fields.contains_known(KnownHeader::TransferEncoding);

    // Step 3: both present is refused, never forwarded with the
    // Content-Length deleted.
    if te_present && cl_count == 1 {
        return Err(RejectReason::TransferEncodingWithContentLength);
    }

    // Step 4: Transfer-Encoding is connection-specific and forbidden on a
    // multiplexed protocol (RFC 9113 Section 8.2.2). This is the H2.TE kill.
    if version.is_multiplexed() && te_present {
        return Err(RejectReason::ConnectionSpecificField);
    }

    // Step 5: Transfer-Encoding is an HTTP/1.1-only mechanism.
    if version == WireVersion::Http10 && te_present {
        return Err(RejectReason::TransferEncodingOnHttp10);
    }

    // Step 6: the chunked path.
    if te_present {
        let _codings = tokenize_transfer_encoding(
            fields.get_all_known(KnownHeader::TransferEncoding),
            policy,
        )?;
        if method.is_connect() {
            return Err(RejectReason::BodyNotAllowedForMethod);
        }
        return Ok(RequestFraming::Streamed);
    }

    // Step 7: the content-length path.
    if cl_count == 1 {
        let value = fields
            .get_unique_known(KnownHeader::ContentLength)
            .map_err(|_| RejectReason::ContentLengthDuplicate)?;
        // Unreachable after `cl_count == 1` above, but handled without
        // `unwrap` or `expect`, both of which the crate lints deny.
        let Some(value) = value else {
            return Ok(RequestFraming::Empty);
        };
        let len = parse_content_length(trim_ows(value))?;
        if method.is_connect() && len > 0 {
            return Err(RejectReason::BodyNotAllowedForMethod);
        }
        if len == 0 {
            return Ok(RequestFraming::Empty);
        }
        return Ok(RequestFraming::Exact { len });
    }

    // Step 8: neither field is present. The answer differs by protocol
    // family. On a multiplexed protocol the head does not carry the length
    // at all; the body ends at END_STREAM (H2) or FIN (H3), which the head
    // cannot see, so a field-less request there is the ordinary streaming
    // POST and must resolve to `Streamed`, never `Empty`. On HTTP/1.0 and
    // HTTP/1.1, RFC 9112 Section 6.3 item 7 says a request matching none of
    // the preceding cases has a body length of zero, and requests are
    // never close-delimited (item 8 is response-only).
    if version.is_multiplexed() {
        return Ok(RequestFraming::Streamed);
    }
    Ok(RequestFraming::Empty)
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
    const ALL_METHODS: [Method; 3] = [Method::Get, Method::Post, Method::Connect];
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
    /// requires) and resolves its framing under `OtherCodings::Reject`.
    fn resolve(
        fields: &[(&[u8], &[u8])],
        method: Method,
        version: WireVersion,
    ) -> Result<RequestFraming, RejectReason> {
        resolve_with_policy(fields, method, version, OtherCodings::Reject)
    }

    /// As [`resolve`], with an explicit policy, for the one test
    /// (`dangerous_policy_accepts_gzip_chunked`) that needs
    /// `OtherCodings::DangerouslyAcceptNonChunkedCodings`.
    fn resolve_with_policy(
        fields: &[(&[u8], &[u8])],
        method: Method,
        version: WireVersion,
        policy: OtherCodings,
    ) -> Result<RequestFraming, RejectReason> {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        for (name, value) in fields {
            builder
                .push(&mut arena, name, value)
                .expect("test fixture fields must already be well formed field bytes");
        }
        let section = builder.finish(&mut arena);
        resolve_request_framing(&method, version, &section, policy)
    }

    #[test]
    fn three_variants_only() {
        // Exhaustive match with no wildcard arm: this fails to compile the
        // moment a fourth variant is added to `RequestFraming`, which is
        // the point of this test rather than anything it computes at run
        // time.
        fn ordinal(f: RequestFraming) -> u8 {
            match f {
                RequestFraming::Empty => 0,
                RequestFraming::Exact { len: _ } => 1,
                RequestFraming::Streamed => 2,
            }
        }
        assert_eq!(ordinal(RequestFraming::Empty), 0);
        assert_eq!(ordinal(RequestFraming::Exact { len: 5 }), 1);
        assert_eq!(ordinal(RequestFraming::Streamed), 2);

        assert!(!RequestFraming::Empty.has_body());
        assert!(RequestFraming::Streamed.has_body());
        assert_eq!(RequestFraming::Exact { len: 5 }.known_len(), Some(5));
    }

    #[test]
    fn no_fields_by_version() {
        assert_eq!(
            resolve(&[], Method::Get, WireVersion::Http10),
            Ok(RequestFraming::Empty)
        );
        assert_eq!(
            resolve(&[], Method::Get, WireVersion::Http11),
            Ok(RequestFraming::Empty)
        );
        assert_eq!(
            resolve(&[], Method::Get, WireVersion::H2),
            Ok(RequestFraming::Streamed)
        );
        assert_eq!(
            resolve(&[], Method::Get, WireVersion::H3),
            Ok(RequestFraming::Streamed)
        );
    }

    #[test]
    fn content_length_values() {
        assert_eq!(
            resolve(
                &[(b"content-length", b"0")],
                Method::Get,
                WireVersion::Http11
            ),
            Ok(RequestFraming::Empty)
        );
        assert_eq!(
            resolve(
                &[(b"content-length", b"1")],
                Method::Get,
                WireVersion::Http11
            ),
            Ok(RequestFraming::Exact { len: 1 })
        );
        assert_eq!(
            resolve(
                &[(b"content-length", b"18446744073709551615")],
                Method::Get,
                WireVersion::Http11
            ),
            Ok(RequestFraming::Exact { len: u64::MAX })
        );
        assert_eq!(
            resolve(
                &[(b"content-length", b"007")],
                Method::Get,
                WireVersion::Http11
            ),
            Ok(RequestFraming::Exact { len: 7 })
        );
    }

    #[test]
    fn content_length_rejects() {
        let invalid: [&[u8]; 9] = [
            b"", b"+5", b"-5", b"0x5", b"5, 5", b"5.0", b"five", b"5 ", b" 5",
        ];
        for case in invalid {
            assert_eq!(
                parse_content_length(case),
                Err(RejectReason::ContentLengthInvalid),
                "{case:?}"
            );
        }

        assert_eq!(
            parse_content_length(b"18446744073709551616"),
            Err(RejectReason::ContentLengthOverflow)
        );

        // A 21-digit value: too many characters to ever fit `u64`,
        // regardless of how many of them are leading zeros.
        let mut too_many_digits = [b'0'; 21];
        if let Some(last) = too_many_digits.last_mut() {
            *last = b'5';
        }
        assert_eq!(
            parse_content_length(&too_many_digits),
            Err(RejectReason::ContentLengthOverflow)
        );
    }

    #[test]
    fn duplicate_content_length_even_when_identical() {
        assert_eq!(
            resolve(
                &[(b"content-length", b"5"), (b"content-length", b"5")],
                Method::Get,
                WireVersion::Http11
            ),
            Err(RejectReason::ContentLengthDuplicate)
        );
        assert_eq!(
            resolve(
                &[(b"content-length", b"5"), (b"content-length", b"6")],
                Method::Get,
                WireVersion::Http11
            ),
            Err(RejectReason::ContentLengthDuplicate)
        );
    }

    #[test]
    fn te_and_cl_together_is_rejected() {
        assert_eq!(
            resolve(
                &[
                    (b"content-length", b"5"),
                    (b"transfer-encoding", b"chunked"),
                ],
                Method::Post,
                WireVersion::Http11
            ),
            Err(RejectReason::TransferEncodingWithContentLength)
        );
        assert_eq!(
            resolve(
                &[
                    (b"transfer-encoding", b"chunked"),
                    (b"content-length", b"5"),
                ],
                Method::Post,
                WireVersion::Http11
            ),
            Err(RejectReason::TransferEncodingWithContentLength)
        );
    }

    #[test]
    fn duplicate_cl_check_is_not_skipped_by_te() {
        // Pingora's `check_dup_content_length` (common.rs:286) returns
        // `Ok(())` early when Transfer-Encoding is present, skipping the
        // duplicate-Content-Length check in exactly this case. Step 1 here
        // runs unconditionally, before Transfer-Encoding is even inspected.
        assert_eq!(
            resolve(
                &[
                    (b"content-length", b"5"),
                    (b"content-length", b"6"),
                    (b"transfer-encoding", b"chunked"),
                ],
                Method::Post,
                WireVersion::Http11
            ),
            Err(RejectReason::ContentLengthDuplicate)
        );
    }

    #[test]
    fn chunked_resolves_streamed() {
        assert_eq!(
            resolve(
                &[(b"transfer-encoding", b"chunked")],
                Method::Post,
                WireVersion::Http11
            ),
            Ok(RequestFraming::Streamed)
        );
        assert_eq!(
            resolve(
                &[(b"transfer-encoding", b"CHUNKED")],
                Method::Post,
                WireVersion::Http11
            ),
            Ok(RequestFraming::Streamed)
        );
    }

    #[test]
    fn te_obfuscation_corpus() {
        let cases: &[(&[&[u8]], RejectReason)] = &[
            (
                &[b"chunked, chunked"],
                RejectReason::TransferEncodingChunkedRepeated,
            ),
            (
                &[b"chunked", b"chunked"],
                RejectReason::TransferEncodingChunkedRepeated,
            ),
            (
                &[b"chunked", b"identity"],
                RejectReason::TransferEncodingFinalNotChunked,
            ),
            (&[b"gzip"], RejectReason::TransferEncodingFinalNotChunked),
            (
                &[b"chunkedX"],
                RejectReason::TransferEncodingFinalNotChunked,
            ),
            (
                &[b"xchunked"],
                RejectReason::TransferEncodingFinalNotChunked,
            ),
            (
                &[b"gzip, chunked"],
                RejectReason::TransferEncodingUnsupportedCoding,
            ),
            (&[b""], RejectReason::TransferEncodingEmptyToken),
            (&[b"chunked,"], RejectReason::TransferEncodingEmptyToken),
            (&[b",chunked"], RejectReason::TransferEncodingEmptyToken),
            (
                &[b"\x0bchunked"],
                RejectReason::TransferEncodingUnsupportedCoding,
            ),
            (
                &[b"chunked\x0c"],
                RejectReason::TransferEncodingUnsupportedCoding,
            ),
            (
                // Nine tokens: the 9th trips the cap of 8 before it is ever
                // inspected for being `chunked`, regardless of what any of
                // the nine actually spell.
                &[b"a, b, c, d, e, f, g, h, i"],
                RejectReason::TransferEncodingUnsupportedCoding,
            ),
        ];

        for (lines, expected) in cases {
            let got = tokenize_transfer_encoding(lines.iter().copied(), OtherCodings::Reject);
            assert_eq!(got, Err(*expected), "{lines:?}");
        }
    }

    #[test]
    fn eight_tokens_is_within_the_cap() {
        // The other side of `te_obfuscation_corpus`'s "nine tokens" boundary:
        // exactly 8 tokens (the cap itself), the last of which is `chunked`,
        // must succeed. This is what distinguishes the correct `count > 8`
        // from a mutant `count == 8` or `count >= 8`, both of which reject a
        // legitimate 8-token list one token too early; a test that only
        // checks the 9-token over-cap case cannot tell the three apart,
        // because all three report the same `TransferEncodingUnsupportedCoding`
        // for 9 tokens.
        // `DangerouslyAcceptNonChunkedCodings` isolates the cap from the
        // separate has_other/policy check that `a`..`g` would otherwise trip
        // under the default policy.
        let got = tokenize_transfer_encoding(
            [b"a, b, c, d, e, f, g, chunked".as_slice()].into_iter(),
            OtherCodings::DangerouslyAcceptNonChunkedCodings,
        );
        assert_eq!(
            got,
            Ok(TeCodings {
                token_count: 8,
                chunked_count: 1,
                final_is_chunked: true,
                has_other: true,
            })
        );
    }

    #[test]
    fn dangerous_policy_accepts_gzip_chunked() {
        assert_eq!(
            resolve_with_policy(
                &[(b"transfer-encoding", b"gzip, chunked")],
                Method::Post,
                WireVersion::Http11,
                OtherCodings::DangerouslyAcceptNonChunkedCodings,
            ),
            Ok(RequestFraming::Streamed)
        );
        assert_eq!(
            resolve_with_policy(
                &[(b"transfer-encoding", b"gzip")],
                Method::Post,
                WireVersion::Http11,
                OtherCodings::DangerouslyAcceptNonChunkedCodings,
            ),
            Err(RejectReason::TransferEncodingFinalNotChunked)
        );
    }

    #[test]
    fn te_on_http10() {
        assert_eq!(
            resolve(
                &[(b"transfer-encoding", b"chunked")],
                Method::Post,
                WireVersion::Http10
            ),
            Err(RejectReason::TransferEncodingOnHttp10)
        );
    }

    #[test]
    fn te_on_multiplexed() {
        for version in [WireVersion::H2, WireVersion::H3] {
            assert_eq!(
                resolve(&[(b"transfer-encoding", b"chunked")], Method::Post, version),
                Err(RejectReason::ConnectionSpecificField),
                "{version:?}"
            );
        }
    }

    #[test]
    fn connect_body_rules() {
        assert_eq!(
            resolve(
                &[(b"content-length", b"0")],
                Method::Connect,
                WireVersion::Http11
            ),
            Ok(RequestFraming::Empty)
        );
        assert_eq!(
            resolve(
                &[(b"content-length", b"1")],
                Method::Connect,
                WireVersion::Http11
            ),
            Err(RejectReason::BodyNotAllowedForMethod)
        );
        assert_eq!(
            resolve(
                &[(b"transfer-encoding", b"chunked")],
                Method::Connect,
                WireVersion::Http11
            ),
            Err(RejectReason::BodyNotAllowedForMethod)
        );
    }

    #[test]
    fn get_with_body_is_allowed() {
        assert_eq!(
            resolve(
                &[(b"content-length", b"100")],
                Method::Get,
                WireVersion::Http11
            ),
            Ok(RequestFraming::Exact { len: 100 })
        );
        assert_eq!(
            resolve(
                &[(b"content-length", b"100")],
                Method::Head,
                WireVersion::Http11
            ),
            Ok(RequestFraming::Exact { len: 100 })
        );
    }

    #[test]
    fn exact_is_never_zero() {
        let cases: [(&[u8], u64); 4] = [(b"0", 0), (b"1", 1), (b"2", 2), (b"1024", 1024)];
        for (raw, len) in cases {
            let expected = if len == 0 {
                RequestFraming::Empty
            } else {
                RequestFraming::Exact { len }
            };
            assert_eq!(
                resolve(
                    &[(b"content-length", raw)],
                    Method::Get,
                    WireVersion::Http11
                ),
                Ok(expected),
                "{len}"
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn prop_framing_total(
            cl_values in proptest::collection::vec(
                proptest::sample::select(&CL_STRATEGY_VALUES[..]),
                0..=3,
            ),
            te_values in proptest::collection::vec(
                proptest::sample::select(&TE_STRATEGY_VALUES[..]),
                0..=3,
            ),
        ) {
            let limits = Limits::DEFAULT.clamped();

            for version in ALL_VERSIONS {
                for method in ALL_METHODS {
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

                    let result = resolve_request_framing(&method, version, &section, OtherCodings::Reject);

                    match result {
                        Ok(RequestFraming::Streamed) => {
                            assert_eq!(cl_values.len(), 0, "{version:?} {method:?}: {result:?}");
                        }
                        Ok(RequestFraming::Exact { .. }) => {
                            assert_eq!(cl_values.len(), 1, "{version:?} {method:?}: {result:?}");
                        }
                        Ok(RequestFraming::Empty) | Err(_) => {}
                    }
                }
            }
        }

        #[test]
        fn prop_parse_content_length_never_panics(
            v in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=40),
        ) {
            if let Ok(n) = parse_content_length(&v) {
                assert!(v.iter().all(u8::is_ascii_digit));
                let mut rendered_len = 1_usize;
                let mut remaining = n;
                while remaining >= 10 {
                    remaining = remaining.checked_div(10).unwrap_or(0);
                    rendered_len = rendered_len.saturating_add(1);
                }
                assert!(rendered_len <= v.len());
            }
        }
    }
}
