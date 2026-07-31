// SPDX-License-Identifier: MIT OR Apache-2.0
//! The fixed request bytes and the response head scanner for [`super`].
//!
//! Sans-IO: every function here is a pure transform over a byte slice, with
//! no socket, no clock and no allocation. [`build_request`] assembles the
//! probe's one, unchanging request into a caller-owned fixed buffer.
//! [`scan_response_head`] answers, from whatever bytes have been read so
//! far, whether a complete and framing-safe head is present, more bytes are
//! needed, or the head is a shape the probe refuses to trust.
//!
//! # Why framing-unsafe heads are `Bad`, not merely `bad` at the end
//!
//! A response with a chunked, duplicated-and-conflicting, or absurdly large
//! `Content-Length` leaves the probe unable to know where this response ends
//! and the next one would begin. [`super`]'s caller closes the connection on
//! every [`BadReason`] for exactly that reason: continuing to read from the
//! socket without a trustworthy boundary would desynchronize on the very
//! next exchange. A response that is merely a non-200 status, with an
//! otherwise valid and singly-declared `Content-Length`, is framing SAFE and
//! is not a concern of this module at all: [`super`] classifies that case
//! itself, after reading exactly the declared body, and keeps the
//! connection.
//!
//! # Absent framing information is refused, not defaulted to zero
//!
//! A response that declares neither `Content-Length` nor
//! `Transfer-Encoding` has told this scanner nothing about where its body
//! ends. An earlier version of this module defaulted that case to a
//! zero-length body, which is indistinguishable, from the caller's side,
//! from a response that genuinely has none: the exchange completes the
//! instant the head terminator arrives, is classified `ok` or `bad` on
//! whatever status came back, and the connection is kept. Any body bytes the
//! peer then actually sends are read as the front of the NEXT response,
//! silently desynchronizing every exchange after it. [`scan_response_head`]
//! instead refuses this shape with [`BadReason::MissingContentLength`], for
//! every status except `304`: RFC 9110 Section 8.6 defines a `304` response
//! as never carrying a body, so the absence of a length on that one status
//! is not ambiguous, and `it-origin` itself omits the header only for it
//! (see `crates/irontraffic-origin/src/response.rs`).
//!
//! The identical silent-zero failure is reachable through a header name this
//! scanner fails to recognise for a reason that has nothing to do with what
//! header it is: `Content-Length : 5` (a space before the colon) is read as
//! the name `"Content-Length "`, which does not case-insensitively equal
//! `"content-length"`, so a matcher that only compares names is fooled into
//! treating it as an ordinary, uninspected header. The same shape on
//! `Transfer-Encoding` is worse: it lets a chunked response smuggle past the
//! [`BadReason::Chunked`] refusal entirely, riding on an unrelated declared
//! `Content-Length` instead. RFC 9112 Section 5.1 requires a server to
//! REJECT (not merely ignore) a field line carrying whitespace between the
//! name and the colon; this module does the same, with
//! [`BadReason::MalformedHeaderName`], before either honoured name is ever
//! compared. `irontraffic_origin`'s own request-side scanner refuses the
//! identical shape for the identical reason
//! (`crates/irontraffic-origin/src/serve.rs`).

/// Largest number of bytes [`scan_response_head`] will scan looking for the
/// head terminator, matching the probe's fixed read buffer
/// ([`super::READ_BUFFER_BYTES`]). A head that has not terminated by then is
/// [`BadReason::HeadTooLarge`]: the probe's buffer is fixed and never grows.
const MAX_RESPONSE_HEAD_BYTES: usize = super::READ_BUFFER_BYTES;

/// Largest digit run [`scan_response_head`] will parse for a `Content-Length`
/// value. `u64::MAX` is `18446744073709551615`, 20 ASCII digits; a run longer
/// than this is rejected as [`BadReason::ContentLengthDigitsTooLong`] without
/// ever being parsed, so the parse itself cannot overflow.
const MAX_CONTENT_LENGTH_DIGITS: usize = 20;

/// A successfully parsed, framing-safe response head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHead {
    /// Bytes of head consumed, including the terminating `\r\n\r\n`.
    pub head_len: usize,
    /// The three-digit status code.
    pub status: u16,
    /// Declared body length. Always at most
    /// [`super::MAX_RESPONSE_BODY_BYTES`]: a larger declared value is
    /// [`BadReason::ContentLengthTooLarge`] instead of ever reaching here.
    pub content_length: u64,
}

/// Why [`scan_response_head`] refused a head. Every variant means the
/// connection must be closed and reconnected: see the module doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadReason {
    /// No `\r\n\r\n` within [`MAX_RESPONSE_HEAD_BYTES`].
    HeadTooLarge,
    /// The first line was not `HTTP/x.x SSS ...` with a three ASCII digit
    /// status code.
    MalformedStatusLine,
    /// A header line carried no `:`.
    MalformedHeaderLine,
    /// A header's name carried ASCII whitespace before its `:` (for example
    /// `Content-Length : 5`). RFC 9112 Section 5.1 requires this to be
    /// refused rather than matched loosely or silently skipped as an
    /// unrecognised header: the latter is exactly how a space before the
    /// colon can make this scanner fail to recognise `Content-Length` or
    /// `Transfer-Encoding` at all. See the module doc comment.
    MalformedHeaderName,
    /// A `Content-Length` value that is not a plain ASCII digit run.
    MalformedContentLength,
    /// Two `Content-Length` headers with different values.
    ConflictingContentLength,
    /// A `Content-Length` digit run longer than
    /// [`MAX_CONTENT_LENGTH_DIGITS`], rejected without being parsed.
    ContentLengthDigitsTooLong,
    /// A `Content-Length` above [`super::MAX_RESPONSE_BODY_BYTES`].
    ContentLengthTooLarge,
    /// `Transfer-Encoding` was present. `it-origin` never sends this: seeing
    /// it means whatever sits between the probe and `it-origin` transformed
    /// the response, and the cell is not measuring what it claims to.
    Chunked,
    /// Neither `Content-Length` nor `Transfer-Encoding` was present, on a
    /// status other than `304`. See the module doc comment: guessing a
    /// zero-length body here is the failure this scanner exists to prevent.
    MissingContentLength,
}

/// What [`scan_response_head`] found in the bytes accumulated so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    /// No head terminator yet, and the buffer has room for more. Read again.
    NeedMore,
    /// A complete, framing-safe head.
    Complete(ResponseHead),
    /// A head the probe refuses to trust. See [`BadReason`].
    Bad(BadReason),
}

/// Bytes per SWAR word in [`find_byte`].
const WORD_BYTES: usize = 8;

/// Broadcasts `byte` into all eight lanes of a `u64`.
fn broadcast(byte: u8) -> u64 {
    u64::from_ne_bytes([byte; WORD_BYTES])
}

/// True when at least one of `word`'s eight byte lanes is exactly zero.
///
/// The classic "haszero" SWAR bit trick (Bit Twiddling Hacks, also how glibc
/// finds a NUL byte in `strlen`): exact, with no false positive or false
/// negative lane, despite the subtraction's carries crossing lane
/// boundaries, which is precisely the identity this trick exploits rather
/// than something it has to work around.
fn has_zero_byte(word: u64) -> bool {
    const LOW_BITS: u64 = 0x0101_0101_0101_0101;
    const HIGH_BITS: u64 = 0x8080_8080_8080_8080;
    (word.wrapping_sub(LOW_BITS) & !word & HIGH_BITS) != 0
}

/// The byte offset of the first occurrence of `needle` in `buf`, or `None`.
///
/// Scans [`WORD_BYTES`] bytes at a time with the SWAR trick above rather
/// than a byte-at-a-time loop: this crate has no authorization to add
/// `memchr` (the SIMD-accelerated search `it-origin`'s own request scanner
/// uses), and this is the cheapest portable, `unsafe`-free substitute. See
/// `probe/scan_response/1kb` in `benches/harness.rs` for the measured cost
/// this shape buys back over a plain `.iter().position(..)`.
fn find_byte(buf: &[u8], needle: u8) -> Option<usize> {
    let needle_word = broadcast(needle);
    let mut chunk_start = 0usize;
    while let Some(chunk) = buf.get(chunk_start..chunk_start.saturating_add(WORD_BYTES)) {
        let Ok(chunk_array) = <[u8; WORD_BYTES]>::try_from(chunk) else {
            break;
        };
        if has_zero_byte(u64::from_ne_bytes(chunk_array) ^ needle_word)
            && let Some(offset) = chunk.iter().position(|&b| b == needle)
        {
            return Some(chunk_start.saturating_add(offset));
        }
        chunk_start = chunk_start.saturating_add(WORD_BYTES);
    }
    let tail = buf.get(chunk_start..)?;
    tail.iter()
        .position(|&b| b == needle)
        .map(|offset| chunk_start.saturating_add(offset))
}

/// The byte offset of the first `\r\n` in `buf`, or `None` if there is none.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    let mut start = 0usize;
    loop {
        let rest = buf.get(start..)?;
        let cr = find_byte(rest, b'\r')?;
        if rest.get(cr.saturating_add(1)) == Some(&b'\n') {
            return Some(start.saturating_add(cr));
        }
        start = start.saturating_add(cr).saturating_add(1);
    }
}

/// The byte offset of the first `\r\n\r\n` in `buf`, or `None` if there is
/// none. Same single-byte-scan shape as [`find_crlf`], checking the three
/// bytes that must follow a candidate `\r` in one comparison.
fn find_head_terminator(buf: &[u8]) -> Option<usize> {
    let mut start = 0usize;
    loop {
        let rest = buf.get(start..)?;
        let cr = find_byte(rest, b'\r')?;
        if rest.get(cr..cr.saturating_add(4)) == Some(&b"\r\n\r\n"[..]) {
            return Some(start.saturating_add(cr));
        }
        start = start.saturating_add(cr).saturating_add(1);
    }
}

/// Parses an ASCII digit run into a `u64`, saturating rather than rejecting
/// on overflow (the caller has already bounded the digit COUNT before
/// calling this, so the only remaining question is the value, and a
/// saturated value still compares correctly against
/// [`super::MAX_RESPONSE_BODY_BYTES`]). `None` for an empty value or one
/// containing any non-digit byte.
fn parse_ascii_u64(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        let digit = u64::from(byte - b'0');
        acc = acc.saturating_mul(10).saturating_add(digit);
    }
    Some(acc)
}

/// Parses `"HTTP/x.x SSS <reason>"` into the three-digit status code. `None`
/// if there is no space-delimited three ASCII digit field right after the
/// first space, or if a fourth digit immediately follows it (a longer digit
/// run is not a three digit status code).
fn parse_status(status_line: &[u8]) -> Option<u16> {
    let space = status_line.iter().position(|&b| b == b' ')?;
    let rest = status_line.get(space.saturating_add(1)..)?;
    let code = rest.get(..3)?;
    if !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if rest.get(3).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let mut value: u16 = 0;
    for &b in code {
        value = value.saturating_mul(10).saturating_add(u16::from(b - b'0'));
    }
    Some(value)
}

/// Scans an already-terminator-confirmed head (`head`'s last four bytes are
/// `\r\n\r\n`) for the status code and the headers this probe honours.
fn parse_head(head: &[u8], head_len: usize) -> ScanOutcome {
    let Some(status_line_end) = find_crlf(head) else {
        return ScanOutcome::Bad(BadReason::MalformedStatusLine);
    };
    let status_line = head.get(..status_line_end).unwrap_or(&[]);
    let Some(status) = parse_status(status_line) else {
        return ScanOutcome::Bad(BadReason::MalformedStatusLine);
    };

    let mut pos = status_line_end.saturating_add(2);
    let mut content_length_raw: Option<u64> = None;
    let mut digits_too_long = false;
    let mut has_transfer_encoding = false;

    loop {
        let rest = head.get(pos..).unwrap_or(&[]);
        // The final blank line (the closing CRLF of `\r\n\r\n`) ends the
        // header section; anything shorter than one CRLF cannot be a line.
        if rest.len() < 2 {
            break;
        }
        let Some(line_end_rel) = find_crlf(rest) else {
            break;
        };
        let line = rest.get(..line_end_rel).unwrap_or(&[]);
        if line.is_empty() {
            break;
        }

        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return ScanOutcome::Bad(BadReason::MalformedHeaderLine);
        };
        let name = line.get(..colon).unwrap_or(&[]);
        // RFC 9112 Section 5.1: refuse a field name carrying whitespace
        // before the colon rather than silently treating it as some other,
        // unrecognised header. Checked before either honoured name is
        // compared, so `Content-Length : 5` and `Transfer-Encoding :
        // chunked` alike are caught here rather than falling through to the
        // "any other header: skip" branch below. See the module doc
        // comment.
        if name.iter().any(u8::is_ascii_whitespace) {
            return ScanOutcome::Bad(BadReason::MalformedHeaderName);
        }
        let raw_value = line.get(colon.saturating_add(1)..).unwrap_or(&[]);
        let value = raw_value.trim_ascii();

        if name.eq_ignore_ascii_case(b"content-length") {
            if value.len() > MAX_CONTENT_LENGTH_DIGITS {
                digits_too_long = true;
            } else {
                match parse_ascii_u64(value) {
                    Some(parsed) => match content_length_raw {
                        Some(existing) if existing != parsed => {
                            return ScanOutcome::Bad(BadReason::ConflictingContentLength);
                        }
                        Some(_) => {}
                        None => content_length_raw = Some(parsed),
                    },
                    None => return ScanOutcome::Bad(BadReason::MalformedContentLength),
                }
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            has_transfer_encoding = true;
        }
        // Any other header: skip. Its value is never inspected.

        pos = pos.saturating_add(line_end_rel).saturating_add(2);
    }

    if has_transfer_encoding {
        return ScanOutcome::Bad(BadReason::Chunked);
    }
    if digits_too_long {
        return ScanOutcome::Bad(BadReason::ContentLengthDigitsTooLong);
    }
    // Neither header was present. `304` is the one status RFC 9110 Section
    // 8.6 defines as never carrying a body, so its absence of a declared
    // length is not ambiguous; `it-origin` itself omits the header only for
    // it (`crates/irontraffic-origin/src/response.rs`). Every other status
    // is refused rather than assumed empty: see the module doc comment for
    // why a zero default here is exactly the failure this scanner exists to
    // prevent.
    let content_length = match content_length_raw {
        Some(value) => value,
        None if status == 304 => 0,
        None => return ScanOutcome::Bad(BadReason::MissingContentLength),
    };
    if content_length > super::MAX_RESPONSE_BODY_BYTES {
        return ScanOutcome::Bad(BadReason::ContentLengthTooLarge);
    }

    ScanOutcome::Complete(ResponseHead {
        head_len,
        status,
        content_length,
    })
}

/// Scans `buf` (everything read from the connection so far, from the start
/// of this response) for a complete, framing-safe head.
///
/// Total: always returns one of the three [`ScanOutcome`] variants, never
/// panics and never indexes out of bounds, for any input of any length or
/// content. The terminator search is bounded to `buf`'s first
/// [`MAX_RESPONSE_HEAD_BYTES`] bytes, exactly like the probe's own fixed read
/// buffer, so a direct caller (this module's own tests, and the property
/// test in `tests/probe.rs`) handing this a longer slice than a real
/// connection ever could gets the identical answer a real, buffer-bounded
/// connection would have gotten from the same prefix.
#[must_use]
pub fn scan_response_head(buf: &[u8]) -> ScanOutcome {
    let capped = buf.get(..MAX_RESPONSE_HEAD_BYTES).unwrap_or(buf);
    match find_head_terminator(capped) {
        Some(pos) => {
            let head_len = pos.saturating_add(4);
            let head = buf.get(..head_len).unwrap_or(&[]);
            parse_head(head, head_len)
        }
        None => {
            if buf.len() >= MAX_RESPONSE_HEAD_BYTES {
                ScanOutcome::Bad(BadReason::HeadTooLarge)
            } else {
                ScanOutcome::NeedMore
            }
        }
    }
}

/// Assembles `"GET <path> HTTP/1.1\r\nHost: <host>\r\nUser-Agent:
/// it-probe\r\n\r\n"` into `dst`, starting at offset 0, and returns the
/// number of bytes written.
///
/// # Errors
/// [`crate::BenchError::Cell`] when the assembled request would exceed
/// `dst.len()` (which is [`super::MAX_REQUEST_BYTES`] at the one real call
/// site).
///
/// `pub`, beyond issue #410's own Files table line for `lib.rs`, for the
/// same reason [`scan_response_head`] is: the Benchmarks section's own
/// `probe/request_bytes_build` criterion target needs to measure this exact
/// function in isolation from `benches/harness.rs`, a separate crate that
/// can see only this crate's public API.
pub fn build_request(
    dst: &mut [u8; super::MAX_REQUEST_BYTES],
    host: &str,
    path: &str,
) -> Result<usize, crate::BenchError> {
    let mut len = 0usize;
    write_piece(dst, &mut len, b"GET ")?;
    write_piece(dst, &mut len, path.as_bytes())?;
    write_piece(dst, &mut len, b" HTTP/1.1\r\nHost: ")?;
    write_piece(dst, &mut len, host.as_bytes())?;
    write_piece(dst, &mut len, b"\r\nUser-Agent: it-probe\r\n\r\n")?;
    Ok(len)
}

/// Appends `bytes` to `dst` at `*len`, advancing `*len`.
///
/// # Errors
/// [`crate::BenchError::Cell`] if `bytes` would not fit in the remaining
/// space.
fn write_piece(
    dst: &mut [u8; super::MAX_REQUEST_BYTES],
    len: &mut usize,
    bytes: &[u8],
) -> Result<(), crate::BenchError> {
    let end = len
        .checked_add(bytes.len())
        .filter(|&end| end <= super::MAX_REQUEST_BYTES)
        .ok_or(crate::BenchError::Cell(
            "assembled probe request exceeds MAX_REQUEST_BYTES",
        ))?;
    let target = dst.get_mut(*len..end).ok_or(crate::BenchError::Cell(
        "assembled probe request exceeds MAX_REQUEST_BYTES",
    ))?;
    target.copy_from_slice(bytes);
    *len = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_byte_on_empty_and_absent_needle() {
        assert_eq!(find_byte(b"", b'x'), None);
        assert_eq!(find_byte(b"abcdefgh", b'x'), None);
        assert_eq!(find_byte(b"abcdefghijklmnop", b'x'), None);
    }

    #[test]
    fn find_byte_at_every_position_across_two_chunks_and_a_tail() {
        // 19 bytes: two full 8 byte chunks (0..8, 8..16) plus a 3 byte tail
        // (16..19). One needle occurrence at a time, at every index,
        // exercises the first-chunk path, the second-chunk path, and the
        // tail path, including the first and last byte of each.
        let base = b"0123456789abcdefghi";
        assert_eq!(base.len(), 19);
        for i in 0..base.len() {
            let mut buf = base.to_vec();
            buf[i] = b'X';
            assert_eq!(
                find_byte(&buf, b'X'),
                Some(i),
                "needle at index {i} in a 19 byte buffer"
            );
        }
    }

    #[test]
    fn find_byte_returns_the_first_occurrence() {
        assert_eq!(find_byte(b"ab X cd X ef", b'X'), Some(3));
    }

    #[test]
    fn find_byte_needle_exactly_at_a_chunk_boundary() {
        // Index 8 is the first byte of the SECOND 8 byte chunk.
        let mut buf = [b'.'; 16];
        buf[8] = b'X';
        assert_eq!(find_byte(&buf, b'X'), Some(8));
        // Index 7 is the LAST byte of the FIRST chunk.
        let mut buf2 = [b'.'; 16];
        buf2[7] = b'X';
        assert_eq!(find_byte(&buf2, b'X'), Some(7));
    }

    #[test]
    fn has_zero_byte_detects_every_lane_independently() {
        for lane in 0..8 {
            let mut bytes = [0xFFu8; 8];
            bytes[lane] = 0x00;
            assert!(
                has_zero_byte(u64::from_ne_bytes(bytes)),
                "lane {lane} zero must be detected"
            );
        }
        assert!(!has_zero_byte(u64::from_ne_bytes([0xFFu8; 8])));
        assert!(has_zero_byte(0));
    }

    #[test]
    fn build_request_assembles_the_fixed_shape() {
        let mut buf = [0u8; super::super::MAX_REQUEST_BYTES];
        let len = build_request(&mut buf, "example.test", "/probe").expect("fits");
        assert_eq!(
            buf.get(..len),
            Some(&b"GET /probe HTTP/1.1\r\nHost: example.test\r\nUser-Agent: it-probe\r\n\r\n"[..])
        );
    }

    #[test]
    fn build_request_rejects_oversized_assembly() {
        let mut buf = [0u8; super::super::MAX_REQUEST_BYTES];
        let long_path = "/".to_owned() + &"a".repeat(2000);
        let result = build_request(&mut buf, "example.test", &long_path);
        assert!(matches!(result, Err(crate::BenchError::Cell(_))));
    }

    #[test]
    fn assembled_request_exactly_at_the_cap_is_accepted_one_byte_more_is_not() {
        // Edge case 6: "A path plus host assembling to exactly 1,024 bytes
        // is accepted, 1,025 is Err(BenchError::Cell)." The fixed overhead
        // (everything the template writes besides path and host) is
        // measured directly with an empty host and path, rather than
        // hand-counted, so this test cannot silently drift from the literal
        // template string above if that ever changes.
        let cap = super::super::MAX_REQUEST_BYTES;
        let mut probe_buf = [0u8; super::super::MAX_REQUEST_BYTES];
        let overhead = build_request(&mut probe_buf, "", "").expect("empty host and path fits");
        let fill = cap - overhead;

        let at_cap_path = "/".to_owned() + &"a".repeat(fill.saturating_sub(1));
        assert_eq!(at_cap_path.len(), fill);
        let mut buf = [0u8; super::super::MAX_REQUEST_BYTES];
        let len = build_request(&mut buf, "", &at_cap_path)
            .expect("a request assembling to exactly the cap must be accepted");
        assert_eq!(len, cap);

        let one_more_path = "/".to_owned() + &"a".repeat(fill);
        assert_eq!(one_more_path.len(), fill + 1);
        let mut buf2 = [0u8; super::super::MAX_REQUEST_BYTES];
        let result = build_request(&mut buf2, "", &one_more_path);
        assert!(
            matches!(result, Err(crate::BenchError::Cell(_))),
            "one byte past the cap must be rejected, got {result:?}"
        );
    }

    #[test]
    fn needs_more_below_the_cap() {
        assert_eq!(
            scan_response_head(b"HTTP/1.1 200 OK\r\n"),
            ScanOutcome::NeedMore
        );
        assert_eq!(scan_response_head(b""), ScanOutcome::NeedMore);
    }

    #[test]
    fn head_too_large_without_terminator() {
        let buf = vec![b'a'; MAX_RESPONSE_HEAD_BYTES];
        assert_eq!(
            scan_response_head(&buf),
            ScanOutcome::Bad(BadReason::HeadTooLarge)
        );
    }

    #[test]
    fn minimal_head_with_no_content_length_or_transfer_encoding_is_bad() {
        // Formerly `complete_minimal_head_defaults_content_length_to_zero`,
        // which pinned a `Complete(content_length: 0)` default as intended.
        // That default is exactly the shape the review demonstrated
        // publishing a 20x understated latency as a healthy run: a real
        // body with no Content-Length and no Transfer-Encoding completed
        // the exchange the instant the head terminator arrived. See the
        // module doc comment.
        let outcome = scan_response_head(b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(outcome, ScanOutcome::Bad(BadReason::MissingContentLength));
    }

    #[test]
    fn not_modified_without_content_length_is_complete_with_zero_body() {
        // The one documented, tested exception: RFC 9110 Section 8.6 defines
        // a 304 response as never carrying a body, so the absence of
        // Content-Length here is not ambiguous framing. `it-origin` itself
        // omits the header only for this status
        // (crates/irontraffic-origin/src/response.rs), so this is the exact
        // shape a real run can see.
        let outcome = scan_response_head(b"HTTP/1.1 304 Not Modified\r\n\r\n");
        match outcome {
            ScanOutcome::Complete(head) => {
                assert_eq!(head.status, 304);
                assert_eq!(head.content_length, 0);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn header_name_with_space_before_colon_is_rejected_not_silently_skipped() {
        // `Content-Length : 5`: read as the name `"Content-Length "`, which
        // fails `eq_ignore_ascii_case` against `"content-length"`. Before
        // the whitespace refusal this fell through to "any other header:
        // skip", reaching the exact same silent-zero shape as the test
        // above with an ostensibly present Content-Length header (the
        // BLOCKING finding's second reproduction).
        let outcome = scan_response_head(b"HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\n");
        assert_eq!(outcome, ScanOutcome::Bad(BadReason::MalformedHeaderName));
    }

    #[test]
    fn transfer_encoding_with_space_before_colon_is_rejected_not_silently_skipped() {
        // The same whitespace-in-name gap on the OTHER honoured header is
        // worse than a silent zero: without this refusal, "Transfer-Encoding
        // " never matches "transfer-encoding", so a genuinely chunked
        // response smuggles past the Chunked refusal entirely by riding on
        // an unrelated declared Content-Length.
        let outcome = scan_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding : chunked\r\n\r\n",
        );
        assert_eq!(outcome, ScanOutcome::Bad(BadReason::MalformedHeaderName));
    }

    #[test]
    fn conflicting_content_length_is_bad() {
        let outcome = scan_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        );
        assert_eq!(
            outcome,
            ScanOutcome::Bad(BadReason::ConflictingContentLength)
        );
    }

    #[test]
    fn duplicate_content_length_same_value_is_accepted() {
        let outcome = scan_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
        );
        match outcome {
            ScanOutcome::Complete(head) => assert_eq!(head.content_length, 5),
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn chunked_is_bad() {
        let outcome = scan_response_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(outcome, ScanOutcome::Bad(BadReason::Chunked));
    }

    #[test]
    fn absurd_content_length_is_too_large_not_parsed_into_garbage() {
        let outcome =
            scan_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n");
        assert_eq!(outcome, ScanOutcome::Bad(BadReason::ContentLengthTooLarge));
    }

    #[test]
    fn thirty_digit_content_length_is_rejected_without_parsing() {
        let value = "9".repeat(30);
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\n");
        let outcome = scan_response_head(head.as_bytes());
        assert_eq!(
            outcome,
            ScanOutcome::Bad(BadReason::ContentLengthDigitsTooLong)
        );
    }

    #[test]
    fn content_length_digit_count_exactly_at_and_one_past_the_cap() {
        // Exactly 20 digits: at the cap, so it IS parsed. This particular
        // 20 digit value is comfortably within u64 and under
        // MAX_RESPONSE_BODY_BYTES, so it must come back Complete, not
        // merely "not ContentLengthDigitsTooLong".
        let at_cap = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            "0".repeat(19) + "5"
        );
        match scan_response_head(at_cap.as_bytes()) {
            ScanOutcome::Complete(head) => assert_eq!(head.content_length, 5),
            other => panic!("20 digits must be parsed, got {other:?}"),
        }

        // Exactly 21 digits: one past the cap, rejected WITHOUT parsing,
        // never ConflictingContentLength or any other reason.
        let one_past = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            "0".repeat(20) + "5"
        );
        assert_eq!(
            scan_response_head(one_past.as_bytes()),
            ScanOutcome::Bad(BadReason::ContentLengthDigitsTooLong)
        );
    }

    #[test]
    fn content_length_exactly_at_the_cap_is_accepted_one_past_is_not() {
        let at_cap = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            super::super::MAX_RESPONSE_BODY_BYTES
        );
        match scan_response_head(at_cap.as_bytes()) {
            ScanOutcome::Complete(head) => {
                assert_eq!(head.content_length, super::super::MAX_RESPONSE_BODY_BYTES);
            }
            other => panic!("expected Complete at exactly the cap, got {other:?}"),
        }

        let one_past = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            super::super::MAX_RESPONSE_BODY_BYTES + 1
        );
        assert_eq!(
            scan_response_head(one_past.as_bytes()),
            ScanOutcome::Bad(BadReason::ContentLengthTooLarge)
        );
    }
}
