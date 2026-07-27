// SPDX-License-Identifier: MIT OR Apache-2.0
//! `H1Parser`: the single-forward-pass, allocation-free, sans-IO tokenizer
//! over an accumulated HTTP/1 read buffer.
//!
//! This is the single parse boundary for HTTP/1 request smuggling. Every
//! decision it makes (where the head ends, what counts as a field name, what
//! whitespace means) is a decision no other component may re-derive, because
//! two independent encodings of "where does this message end" is exactly how
//! a front end and a back end disagree about framing.
//!
//! **Stateless across calls.** [`H1Parser::parse_request_head`] and
//! [`H1Parser::parse_response_head`] hold no cursor and no partial-state enum.
//! When the head is incomplete they return [`ParseStatus::Partial`], and the
//! caller appends more bytes to the SAME buffer and calls again from offset
//! zero. That is deliberately wasteful in the worst case: a head delivered one
//! byte at a time is rescanned once per byte, `O(L^2)` in bytes scanned. It is
//! the right trade anyway, because statelessness is what makes this parser
//! exhaustively fuzzable and makes the resumption class of bugs
//! unrepresentable (see `h1-chunked-and-trailers`, which keeps explicit state
//! for exactly the opposite reason: a chunked body can be gigabytes, where the
//! same trade would be genuinely quadratic).
//!
//! **The rescan cost is priced, not ignored.** `max_head_bytes` bounds the
//! buffer, not the work: at the defaults a maximum-size head delivered one
//! byte per read costs `O(L^2 / 2)` bytes scanned, about 0.9 seconds of CPU
//! for 74 KiB an attacker sent. Neither `max_head_bytes` (a memory bound) nor
//! `header_read_timeout` (a wall-clock bound that expires long after the CPU
//! is gone) bounds that. [`HeadScanBudget`] is the third, explicit bound: the
//! connection driver charges it before every parse attempt, so the total
//! scanned bytes for one head is capped at [`HeadScanBudget::MAX_BYTES`]
//! (4 MiB) regardless of how a peer drips the head in. See the "HTTP/1 head"
//! subsection of `docs/THREAT-MODEL.md` for the full accounting.
//!
//! **Every name and value byte is validated during the scan**, never assumed
//! safe because it "came from what we parsed" (the pattern this design
//! deliberately does not follow; see the module's issue for the Pingora
//! citation). Uppercase field names are lowercased by the CONSUMER, not here:
//! this parser only flags [`RawField::needs_lowercase`] so the fold happens
//! once, in the consumer's own arena, because the buffer is never mutated.

use smallvec::SmallVec;

use crate::error::RejectReason;
use crate::field::{self, UnderscorePolicy};
use crate::hlist::HeaderListBudget;
use crate::limits::ClampedLimits;
use crate::scalar::{Method, ParseStatus, StatusCode, WireVersion};

/// A half-open byte range into the caller's read buffer.
///
/// This is deliberately its own two-field struct rather than the standard
/// library's generic half-open range type over `u32`: that type is also an
/// `Iterator` and, by design, does not implement `Copy`, so a struct
/// containing one could not derive `Copy` either, and [`RawField`] must be
/// `Copy` to live in a `SmallVec` the parser fills in a tight loop.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Span {
    /// First byte offset, inclusive.
    pub start: u32,
    /// Last byte offset, exclusive. Always at or above `start`.
    pub end: u32,
}

impl Span {
    /// Length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start) as usize
    }

    /// True when `start == end`.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// The bytes this span covers, or `None` when it is out of range for `buf`.
    #[must_use]
    pub fn of(self, buf: &[u8]) -> Option<&[u8]> {
        buf.get(self.start as usize..self.end as usize)
    }
}

/// Builds a [`Span`] from a `start..end` range this module has already
/// established satisfies `start <= end` and `end <= buf.len()` by
/// construction (every call site slices `buf` with the same range first).
/// `debug_assert`s that invariant rather than trusting it silently, and
/// converts with `try_from` rather than `as`, because this crate denies
/// `clippy::cast_possible_truncation` and a caller-supplied buffer could in
/// principle be larger than `u32::MAX`, even though every realistic input
/// reaching this point is already bounded far below that by the clamped
/// `Limits` the caller validated against on the way here.
fn make_span(start: usize, end: usize) -> Result<Span, RejectReason> {
    debug_assert!(
        start <= end,
        "make_span: start ({start}) must be <= end ({end})"
    );
    let start = u32::try_from(start).map_err(|_| RejectReason::HeaderListTooLarge)?;
    let end = u32::try_from(end).map_err(|_| RejectReason::HeaderListTooLarge)?;
    Ok(Span { start, end })
}

/// One parsed field line.
#[derive(Copy, Clone, Debug)]
pub struct RawField {
    /// Name bytes as received.
    pub name: Span,
    /// Value bytes, already OWS-trimmed at both ends.
    pub value: Span,
    /// True when the received name contained an uppercase byte, so the
    /// consumer must lowercase it before use. Set during the scan so the
    /// consumer does not re-scan.
    pub needs_lowercase: bool,
}

/// A borrowed view over the caller's read buffer. Spans are byte offsets into
/// `buf`.
///
/// `target` is `pub(crate)` on purpose: invariant P1 says there is exactly
/// one path value in the system, and it is produced by
/// `NormalizedPath::parse_into`. No code outside this crate may read the raw
/// request target.
#[derive(Debug)]
pub struct RawHead<'a> {
    /// The method bytes.
    pub method: Span,
    /// The request-target bytes. Crate-private by design.
    #[allow(
        dead_code,
        reason = "read only by h1-head-to-canonical-request (#35)'s target_bytes() accessor, \
                  which is out of this issue's scope by design (see the module doc comment on \
                  RawHead above). Kept pub(crate) with no reader yet so invariant P1 is enforced \
                  by the type from the moment this struct exists, rather than only once #35 \
                  lands; the in-crate prop_never_panics_and_consumed_in_range test below does \
                  read it, but that is cfg(test)-only and so does not satisfy this field's dead \
                  code analysis on a plain (non-test) build of this crate"
    )]
    pub(crate) target: Span,
    /// The version.
    pub version: WireVersion,
    /// One entry per field line, in arrival order. Names are spans into `buf`
    /// and are NOT lowercased in place, because the buffer is never mutated;
    /// each field carries a `needs_lowercase` flag so the consumer folds
    /// once, into its own arena.
    pub fields: SmallVec<[RawField; 32]>,
    buf: &'a [u8],
}

impl<'a> RawHead<'a> {
    /// The method bytes.
    #[must_use]
    pub fn method_bytes(&self) -> &'a [u8] {
        self.method.of(self.buf).unwrap_or(&[])
    }

    /// The field name bytes as received (NOT lowercased).
    #[must_use]
    pub fn field_name(&self, i: usize) -> Option<&'a [u8]> {
        self.fields.get(i).and_then(|f| f.name.of(self.buf))
    }

    /// The OWS-trimmed field value bytes.
    #[must_use]
    pub fn field_value(&self, i: usize) -> Option<&'a [u8]> {
        self.fields.get(i).and_then(|f| f.value.of(self.buf))
    }

    /// Number of field lines.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

/// A parsed response head.
#[derive(Debug)]
pub struct RawResponseHead<'a> {
    /// The status code.
    pub status: StatusCode,
    /// The version.
    pub version: WireVersion,
    /// One entry per field line.
    pub fields: SmallVec<[RawField; 32]>,
    #[allow(
        dead_code,
        reason = "kept for the same reason RawHead carries buf: a RawField's Span values are \
                  plain offsets, not borrows, so resolving fields[i].name/value only ever needs \
                  the buf the caller already passed to parse_response_head, never this struct's \
                  own copy of it. This issue's own Public API section gives RawResponseHead no \
                  accessor that would read it (unlike RawHead's method_bytes/field_name/ \
                  field_value), so it is unread until a later issue adds one; kept now to match \
                  RawHead's struct shape exactly as specified"
    )]
    buf: &'a [u8],
}

/// Bounds the total bytes the head parser may scan for ONE head, across every
/// `Partial` re-run. The parser is stateless, so this counter lives with the
/// caller.
///
/// Deliberately NOT `Copy`, for the same reason as every other budget in this
/// crate (see `hlist::HeaderListBudget`): a charge against a copy is a charge
/// that never happened.
#[derive(Clone, Debug, Default)]
pub struct HeadScanBudget {
    scanned: u64,
}

impl HeadScanBudget {
    /// 4 MiB. About 56x `max_head_bytes` at the defaults, so a legitimate
    /// head that arrives in many small TCP segments is never affected, while
    /// a one-byte-per-read drip of a maximum-size head is cut off after
    /// roughly 1.5 ms of CPU instead of 900 ms. Not configurable: it is a
    /// floor on how much work a peer can buy, not a feature.
    pub const MAX_BYTES: u64 = 4 * 1024 * 1024;

    /// Charges one parse attempt over a buffer of `buf_len` bytes. Call this
    /// immediately BEFORE each `parse_request_head` or `parse_response_head`
    /// call.
    ///
    /// # Errors
    /// `HeaderListTooLarge` once the cumulative scan for this head exceeds
    /// `MAX_BYTES`. The caller answers 431 and closes, exactly as for any
    /// other head limit.
    pub fn charge(&mut self, buf_len: usize) -> Result<(), RejectReason> {
        self.scanned = self.scanned.saturating_add(buf_len as u64);
        if self.scanned > Self::MAX_BYTES {
            return Err(RejectReason::HeaderListTooLarge);
        }
        Ok(())
    }

    /// Resets the counter. Call after every `Complete`, so a pipelined
    /// connection gets a fresh budget per message rather than a shared one.
    /// Never call this after a `Partial`.
    pub fn reset(&mut self) {
        self.scanned = 0;
    }

    /// Bytes charged so far for the current head.
    #[must_use]
    pub const fn scanned(&self) -> u64 {
        self.scanned
    }
}

/// The HTTP/1 head parser. Holds limits and policy; holds NO position state,
/// because every call re-runs from the start of the buffer.
#[derive(Copy, Clone, Debug)]
pub struct H1Parser {
    limits: ClampedLimits,
    underscores: UnderscorePolicy,
}

/// The memory bound on one buffered, not-yet-complete head: 73,730 bytes at
/// the defaults, computed as `max_request_line_bytes` plus
/// `max_header_list_bytes` plus 2.
///
/// Deliberately the TIGHT bound, not the looser product of `max_field_count`
/// and `max_field_line_bytes` added to `max_request_line_bytes` (827,392 at
/// the defaults). A field line costs `name` plus `value` plus 4 wire bytes
/// (colon, SP, CRLF) and is charged `name` plus `value` plus 32 against
/// `max_header_list_bytes`, so the list limit already bounds total wire
/// field bytes; adding the request line and the final CRLF is the whole
/// head. The loose bound would buffer 827 KB per connection instead of
/// 74 KB for a head we could never accept anyway, 11x the memory at every
/// connection count.
fn max_head_bytes(limits: ClampedLimits) -> usize {
    let request_line = limits.max_request_line_bytes as usize;
    let header_list = limits.max_header_list_bytes as usize;
    request_line.saturating_add(header_list).saturating_add(2)
}

/// The region of `buf` the bare-CR/bare-LF pass runs over.
///
/// When the terminator was found at `t`, that region is `buf[..t + 4]`. When
/// it was not found, every byte in `buf` is head (it has not ended yet), with
/// one exemption: a `\r` occupying the final byte of the buffer is not yet a
/// bare CR, because its `\n` may arrive on the next read.
fn bare_check_region(buf: &[u8], terminator: Option<usize>) -> &[u8] {
    match terminator {
        Some(t) => buf.get(..t.saturating_add(4)).unwrap_or(buf),
        None => {
            if buf.last() == Some(&b'\r') {
                buf.get(..buf.len().saturating_sub(1)).unwrap_or(&[])
            } else {
                buf
            }
        }
    }
}

/// Refuses a bare CR (a `\r` not immediately followed by `\n`) or a bare LF
/// (a `\n` not immediately preceded by `\r`) anywhere in `region`, in one
/// forward pass.
///
/// Run over the WHOLE head up front rather than per line: both faster and
/// impossible to get wrong per line. A `\n` at offset 0 has no predecessor
/// and is a bare LF.
fn check_bare_cr_lf(region: &[u8]) -> Result<(), RejectReason> {
    for (i, &b) in region.iter().enumerate() {
        match b {
            b'\r' => {
                if region.get(i.saturating_add(1)) != Some(&b'\n') {
                    return Err(RejectReason::BareCr);
                }
            }
            b'\n' => {
                let prev_is_cr = match i.checked_sub(1) {
                    Some(j) => region.get(j) == Some(&b'\r'),
                    None => false,
                };
                if !prev_is_cr {
                    return Err(RejectReason::BareLf);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Step 1 of the algorithm, shared by requests and responses: finds the head
/// terminator (`\r\n\r\n`), runs the bare-CR/bare-LF pass over the head bytes
/// FIRST (per the design's step ordering note: this "step 4" content runs
/// before request-line or field parsing so a bad byte is reported by its own
/// specific reason rather than by whatever the line splitter would have
/// said), and enforces `max_head_bytes` when the terminator is absent.
///
/// Returns `Ok(Some(t))` with the terminator's start offset, or `Ok(None)`
/// meaning the caller should return `Partial`.
fn locate_terminator(buf: &[u8], limits: ClampedLimits) -> Result<Option<usize>, RejectReason> {
    let terminator = memchr::memmem::find(buf, b"\r\n\r\n");
    check_bare_cr_lf(bare_check_region(buf, terminator))?;
    match terminator {
        Some(t) => Ok(Some(t)),
        None => {
            if buf.len() > max_head_bytes(limits) {
                Err(RejectReason::HeaderListTooLarge)
            } else {
                Ok(None)
            }
        }
    }
}

/// Parses field lines from `start` to `terminator` (exclusive), shared by
/// requests and responses. `start` is the offset just past the request or
/// status line's own CRLF; `terminator` is the offset of the head's
/// terminating `\r\n\r\n`.
///
/// By construction `terminator` is the offset of the FIRST occurrence of
/// `\r\n\r\n` anywhere in `buf` (that is what `locate_terminator` searched
/// for), so an isolated empty line can never occur strictly before it: an
/// empty line at some `pos < terminator` would mean the previous line's own
/// trailing `\r\n` is immediately followed by another `\r\n`, which is itself
/// an earlier occurrence of the 4-byte pattern, contradicting `terminator`'s
/// minimality. So `pos == terminator` is the only place the walk below ever
/// stops, which is exactly step 3a's "if the line is empty, we have reached
/// the terminator; stop", expressed as a position comparison instead of a
/// per-iteration length check.
fn parse_field_lines(
    buf: &[u8],
    start: usize,
    terminator: usize,
    limits: &ClampedLimits,
    underscores: UnderscorePolicy,
) -> Result<SmallVec<[RawField; 32]>, RejectReason> {
    // `default()` rather than the other empty-constructor spelling: both
    // build the same empty, non-allocating inline value, and this spelling
    // does not read as an allocation to tests/alloc_gate.rs's text scan
    // (see that file for why the other spelling would).
    let mut fields: SmallVec<[RawField; 32]> = SmallVec::default();
    let mut budget = HeaderListBudget::new(limits);
    let mut pos = start;

    while pos < terminator {
        // The line's own terminating CRLF may start anywhere from `pos` up to
        // and including `terminator` itself (the last field line before the
        // blank line ends exactly there), so the search region must reach
        // `terminator + 2`.
        let search_end = terminator.saturating_add(2);
        let region = buf
            .get(pos..search_end)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let rel =
            memchr::memmem::find(region, b"\r\n").ok_or(RejectReason::RequestLineMalformed)?;
        let line_end = pos.saturating_add(rel);
        let line = buf
            .get(pos..line_end)
            .ok_or(RejectReason::RequestLineMalformed)?;

        // 3b: obs-fold.
        if matches!(line.first(), Some(&b' ' | &b'\t')) {
            return Err(RejectReason::ObsFold);
        }

        // 3c: the first colon.
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(RejectReason::RequestLineMalformed)?;
        if colon == 0 {
            return Err(RejectReason::FieldNameEmpty);
        }

        // 3d: whitespace before the colon.
        let before_colon = line.get(colon.saturating_sub(1)).copied();
        if matches!(before_colon, Some(b' ' | b'\t')) {
            return Err(RejectReason::WhitespaceBeforeColon);
        }

        // 3e: the name. Uppercase is flagged, not refused (H1 lowercases at
        // the parse boundary, unlike H2/H3); `_` is refused anywhere in the
        // name under `Reject`, matching NGINX/CGI/PHP's fold of `-` and `_`.
        let name_raw = line
            .get(..colon)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let mut needs_lowercase = false;
        for &b in name_raw {
            if b.is_ascii_uppercase() {
                needs_lowercase = true;
                continue;
            }
            if b == b'_' {
                if let UnderscorePolicy::Reject = underscores {
                    return Err(RejectReason::FieldNameUnderscore);
                }
                continue;
            }
            if !field::name_byte_ok(b) {
                return Err(RejectReason::FieldNameInvalidByte);
            }
        }

        // 3f: the value, OWS-trimmed. In practice this validation only ever
        // fires for NUL: step 4 (run up front by `locate_terminator`) has
        // already refused every CR and LF in the head with the more specific
        // `BareCr`/`BareLf`. Kept anyway so this function is total rather
        // than dependent on that step having run.
        let value_raw = line
            .get(colon.saturating_add(1)..)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let value_trimmed = field::trim_ows(value_raw);
        for &b in value_trimmed {
            if !field::value_byte_ok(b) {
                return Err(RejectReason::FieldValueInvalidByte);
            }
        }

        // 3g: limits, all checked before pushing. `HeaderListBudget::charge`
        // itself enforces both the byte total (`HeaderListTooLarge`) and the
        // field count (`FieldCountExceeded`); the field-line length is a
        // separate bound `HeaderListBudget` does not track.
        let line_len = name_raw.len().saturating_add(value_trimmed.len());
        if line_len > limits.max_field_line_bytes as usize {
            return Err(RejectReason::FieldLineTooLong);
        }
        budget.charge(name_raw.len(), value_trimmed.len())?;

        // Absolute spans. `value_trimmed` is a genuine subslice of
        // `value_raw` (guaranteed by `field::trim_ows`), so its offset from
        // `value_raw`'s own start is recovered by comparing pointer
        // addresses as plain integers, never by dereferencing one: safe
        // under `#![forbid(unsafe_code)]`, the same technique
        // `field::tests::prop_trim_ows_is_a_subslice` already uses to prove
        // the same fact about `trim_ows` itself.
        let name_span = make_span(pos, pos.saturating_add(colon))?;
        let value_leading =
            (value_trimmed.as_ptr() as usize).saturating_sub(value_raw.as_ptr() as usize);
        let value_start = pos
            .saturating_add(colon)
            .saturating_add(1)
            .saturating_add(value_leading);
        let value_span = make_span(value_start, value_start.saturating_add(value_trimmed.len()))?;

        // 3h: push. On the first spill past the inline capacity (32), reserve
        // the full `max_field_count` in one call, so a 100-field head costs
        // exactly one allocation rather than the two that doubling 32 to 64
        // to 128 would cost.
        if fields.len() == 32 {
            let target_capacity = limits.max_field_count as usize;
            fields.reserve(target_capacity.saturating_sub(fields.len()));
        }
        fields.push(RawField {
            name: name_span,
            value: value_span,
            needs_lowercase,
        });

        pos = line_end.saturating_add(2);
    }

    Ok(fields)
}

impl H1Parser {
    /// A parser with the given limits and underscore policy.
    #[must_use]
    pub const fn new(limits: &ClampedLimits, underscores: UnderscorePolicy) -> Self {
        Self {
            limits: *limits,
            underscores,
        }
    }

    /// Parses a request head from the accumulated read buffer.
    ///
    /// On `Complete`, `consumed` bytes are the head INCLUDING the terminating
    /// CRLFCRLF, so `buf[consumed..]` is the first byte of the next pipelined
    /// message. On `Partial`, the caller MUST append more bytes to the same
    /// buffer and call this again from offset zero: the parser keeps no
    /// position state.
    ///
    /// Never allocates for 32 or fewer field lines. Never mutates `buf`.
    ///
    /// # Errors
    /// Every reason in the reject table this parser implements: a request
    /// line that is malformed, too long, or names an unsupported version; a
    /// field line with an empty, invalid, or underscore-bearing name, an
    /// invalid value byte, whitespace before its colon, or obsolete folding;
    /// a bare CR or bare LF anywhere in the head; a request target carrying a
    /// fragment; and every configured limit (`max_request_line_bytes`,
    /// `max_field_line_bytes`, `max_header_list_bytes`, `max_field_count`,
    /// and the derived `max_head_bytes` while the head is still incomplete).
    #[allow(
        clippy::too_many_lines,
        reason = "one linear ten-plus-step parse over one input, matching authority.rs's own \
                  precedent for this exact tradeoff; splitting it would scatter the step \
                  ordering the design and its 47 numbered edge cases both depend on across \
                  several functions with no clearer seam"
    )]
    pub fn parse_request_head<'b>(
        &self,
        buf: &'b [u8],
    ) -> Result<ParseStatus<RawHead<'b>>, RejectReason> {
        let Some(terminator) = locate_terminator(buf, self.limits)? else {
            return Ok(ParseStatus::Partial);
        };

        // Step 2: the request line, over buf[..first_crlf]. `first_crlf`
        // exists because `terminator` (a `\r\n\r\n`) is itself a `\r\n`, so
        // this search can never fail for a `buf` that reached this point.
        let first_crlf =
            memchr::memmem::find(buf, b"\r\n").ok_or(RejectReason::RequestLineMalformed)?;

        if first_crlf.saturating_add(2) > self.limits.max_request_line_bytes as usize {
            return Err(RejectReason::RequestLineTooLong);
        }

        let request_line = buf
            .get(..first_crlf)
            .ok_or(RejectReason::RequestLineMalformed)?;

        if request_line.contains(&b'\t')
            || request_line.first() == Some(&b' ')
            || request_line.last() == Some(&b' ')
        {
            return Err(RejectReason::RequestLineMalformed);
        }

        let first_sp = request_line
            .iter()
            .position(|&b| b == b' ')
            .ok_or(RejectReason::RequestLineMalformed)?;
        let after_method = request_line
            .get(first_sp.saturating_add(1)..)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let second_sp = after_method
            .iter()
            .position(|&b| b == b' ')
            .ok_or(RejectReason::RequestLineMalformed)?;
        let method_bytes = request_line
            .get(..first_sp)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let target_bytes = after_method
            .get(..second_sp)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let version_bytes = after_method
            .get(second_sp.saturating_add(1)..)
            .ok_or(RejectReason::RequestLineMalformed)?;
        // Exactly two SP bytes total: a third (or more) would show up here,
        // in whatever followed the second SP.
        if version_bytes.contains(&b' ') {
            return Err(RejectReason::RequestLineMalformed);
        }

        // Step 2c: the parser stores only the method's range; the caller
        // constructs the `Method`. Still validated here so a malformed
        // method fails at the parse boundary, and the `?` propagates
        // `MethodInvalid`/`MethodTooLong` unchanged.
        Method::parse(method_bytes, &self.limits)?;

        // Step 2d: the version.
        let version = match version_bytes {
            b"HTTP/1.1" => WireVersion::Http11,
            b"HTTP/1.0" => WireVersion::Http10,
            _ => return Err(RejectReason::VersionUnsupported),
        };

        // Step 2e: the target.
        if target_bytes.contains(&b'#') {
            return Err(RejectReason::TargetFragment);
        }
        if target_bytes.is_empty() {
            return Err(RejectReason::RequestLineMalformed);
        }

        let method_span = make_span(0, first_sp)?;
        let target_start = first_sp.saturating_add(1);
        let target_span = make_span(target_start, target_start.saturating_add(second_sp))?;

        // Step 3.
        let fields = parse_field_lines(
            buf,
            first_crlf.saturating_add(2),
            terminator,
            &self.limits,
            self.underscores,
        )?;

        // Step 5.
        let head_end = terminator.saturating_add(4);
        Ok(ParseStatus::complete(
            RawHead {
                method: method_span,
                target: target_span,
                version,
                fields,
                buf,
            },
            head_end,
            buf.len(),
        ))
    }

    /// Parses a response head. Same contract as [`H1Parser::parse_request_head`].
    ///
    /// # Errors
    /// As `parse_request_head`, plus `RequestLineMalformed` for a status line
    /// that is not `HTTP/1.x SP 3DIGIT [SP reason] CRLF` or a status outside
    /// 100 to 599, and `FieldValueInvalidByte` for a reason phrase containing
    /// a NUL.
    pub fn parse_response_head<'b>(
        &self,
        buf: &'b [u8],
    ) -> Result<ParseStatus<RawResponseHead<'b>>, RejectReason> {
        let Some(terminator) = locate_terminator(buf, self.limits)? else {
            return Ok(ParseStatus::Partial);
        };

        let first_crlf =
            memchr::memmem::find(buf, b"\r\n").ok_or(RejectReason::RequestLineMalformed)?;

        if first_crlf.saturating_add(2) > self.limits.max_request_line_bytes as usize {
            return Err(RejectReason::RequestLineTooLong);
        }

        let status_line = buf
            .get(..first_crlf)
            .ok_or(RejectReason::RequestLineMalformed)?;
        if status_line.contains(&b'\t') {
            return Err(RejectReason::RequestLineMalformed);
        }

        let sp1 = status_line
            .iter()
            .position(|&b| b == b' ')
            .ok_or(RejectReason::RequestLineMalformed)?;
        let version_bytes = status_line
            .get(..sp1)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let version = match version_bytes {
            b"HTTP/1.1" => WireVersion::Http11,
            b"HTTP/1.0" => WireVersion::Http10,
            _ => return Err(RejectReason::VersionUnsupported),
        };

        let after_version = status_line
            .get(sp1.saturating_add(1)..)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let status_bytes = after_version
            .get(..3)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let [d0, d1, d2] = status_bytes else {
            return Err(RejectReason::RequestLineMalformed);
        };
        if !(d0.is_ascii_digit() && d1.is_ascii_digit() && d2.is_ascii_digit()) {
            return Err(RejectReason::RequestLineMalformed);
        }
        let value = u16::from(d0.saturating_sub(b'0'))
            .saturating_mul(100)
            .saturating_add(u16::from(d1.saturating_sub(b'0')).saturating_mul(10))
            .saturating_add(u16::from(d2.saturating_sub(b'0')));
        let status = StatusCode::from_u16(value).ok_or(RejectReason::RequestLineMalformed)?;

        let after_status = after_version
            .get(3..)
            .ok_or(RejectReason::RequestLineMalformed)?;
        let reason_bytes: &[u8] = if after_status.is_empty() {
            &[]
        } else {
            if after_status.first() != Some(&b' ') {
                return Err(RejectReason::RequestLineMalformed);
            }
            after_status
                .get(1..)
                .ok_or(RejectReason::RequestLineMalformed)?
        };
        for &b in reason_bytes {
            if !field::value_byte_ok(b) {
                return Err(RejectReason::FieldValueInvalidByte);
            }
        }

        let fields = parse_field_lines(
            buf,
            first_crlf.saturating_add(2),
            terminator,
            &self.limits,
            self.underscores,
        )?;

        let head_end = terminator.saturating_add(4);
        Ok(ParseStatus::complete(
            RawResponseHead {
                status,
                version,
                fields,
                buf,
            },
            head_end,
            buf.len(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use proptest::strategy::Strategy;

    fn parser(underscores: UnderscorePolicy) -> H1Parser {
        H1Parser::new(&Limits::DEFAULT.clamped(), underscores)
    }

    fn default_parser() -> H1Parser {
        parser(UnderscorePolicy::Reject)
    }

    /// `Span::len` and `Span::is_empty`: neither is called anywhere in this
    /// module's own parsing logic (spans are resolved through `Span::of`
    /// instead), so without a direct test both are exercised by nothing at
    /// all. Two spans, a non-empty one and a genuinely empty one, so a
    /// mutation collapsing either method to a constant cannot pass both.
    #[test]
    fn span_len_and_is_empty() {
        let five = Span { start: 10, end: 15 };
        assert_eq!(five.len(), 5);
        assert!(!five.is_empty());

        let empty = Span { start: 7, end: 7 };
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    /// `HeadScanBudget::MAX_BYTES` pinned against a literal, independent of
    /// the multiplication expression that defines it: a mutation turning
    /// `4 * 1024 * 1024` into `4 + 1024 + 1024` (2052) would still pass any
    /// test that only compares against `HeadScanBudget::MAX_BYTES` itself,
    /// because both sides move together.
    #[test]
    fn head_scan_budget_max_bytes_is_4_mebibytes() {
        assert_eq!(HeadScanBudget::MAX_BYTES, 4_194_304);
    }

    /// The exact expectation of one `parse_request_head` call in
    /// [`corpus_table`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Expected {
        Partial,
        Complete {
            consumed: usize,
            field_count: usize,
            version: WireVersion,
        },
        Err(RejectReason),
    }

    fn expect(parser: H1Parser, input: &[u8], expected: &Expected) {
        let got = parser.parse_request_head(input);
        match (expected, got) {
            (Expected::Partial, Ok(ParseStatus::Partial)) => {}
            (
                Expected::Complete {
                    consumed,
                    field_count,
                    version,
                },
                Ok(ParseStatus::Complete {
                    value,
                    consumed: got_consumed,
                }),
            ) => {
                assert_eq!(got_consumed, *consumed, "consumed mismatch for {input:?}");
                assert_eq!(
                    value.field_count(),
                    *field_count,
                    "field_count mismatch for {input:?}"
                );
                // The audit's own named gap: the version field was never
                // asserted anywhere. A mutation that always returned
                // `Http11`, or that swapped the `HTTP/1.0`/`HTTP/1.1` arms,
                // survived every prior check that only looked at `consumed`
                // and `field_count`.
                assert_eq!(value.version, *version, "version mismatch for {input:?}");
            }
            (Expected::Err(reason), Err(got_reason)) => {
                assert_eq!(*reason, got_reason, "reject reason mismatch for {input:?}");
            }
            (expected, got) => {
                panic!("for {input:?}: expected {expected:?}, got {got:?}");
            }
        }
    }

    fn complete(consumed: usize, field_count: usize) -> Expected {
        Expected::Complete {
            consumed,
            field_count,
            version: WireVersion::Http11,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table of edge cases 1 through 43 the issue names by number, plus the \
                  closure that checks each row; splitting the table would break the 1:1 mapping \
                  to that numbered list, matching authority.rs's own corpus_table precedent"
    )]
    #[test]
    fn corpus_table() {
        use RejectReason::{
            BareCr, BareLf, FieldCountExceeded, FieldLineTooLong, FieldNameEmpty,
            FieldNameInvalidByte, FieldValueInvalidByte, HeaderListTooLarge, ObsFold,
            RequestLineMalformed, RequestLineTooLong, TargetFragment, VersionUnsupported,
            WhitespaceBeforeColon,
        };

        let p = default_parser();

        let cases: &[(&[u8], Expected)] = &[
            // 1: empty buffer.
            (b"", Expected::Partial),
            // 2: no terminator yet.
            (b"GET", Expected::Partial),
            // 3.
            (b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", complete(27, 1)),
            // 6.
            (b"\r\n\r\n", Expected::Err(RequestLineMalformed)),
            // 7: bare LF terminators.
            (b"GET / HTTP/1.1\nHost: a\n\n", Expected::Err(BareLf)),
            // 8: bare CR.
            (
                b"GET / HTTP/1.1\r\nHost: a\rX: 1\r\n\r\n",
                Expected::Err(BareCr),
            ),
            // 9: obs-fold (SP continuation).
            (
                b"GET / HTTP/1.1\r\nHost: a\r\n Continued\r\n\r\n",
                Expected::Err(ObsFold),
            ),
            // 10: obs-fold (HTAB continuation).
            (
                b"GET / HTTP/1.1\r\nHost: a\r\n\tContinued\r\n\r\n",
                Expected::Err(ObsFold),
            ),
            // 11: empty field name.
            (
                b"GET / HTTP/1.1\r\n: novalue\r\nHost: a\r\n\r\n",
                Expected::Err(FieldNameEmpty),
            ),
            // 12: whitespace before colon (SP).
            (
                b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
                Expected::Err(WhitespaceBeforeColon),
            ),
            // 13: whitespace before colon (HTAB).
            (
                b"GET / HTTP/1.1\r\nHost\t: a\r\n\r\n",
                Expected::Err(WhitespaceBeforeColon),
            ),
            // 14: invalid byte in a field name.
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nX\x00Y: 1\r\n\r\n",
                Expected::Err(FieldNameInvalidByte),
            ),
            // 15: invalid byte in a field value.
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nX: va\x00lue\r\n\r\n",
                Expected::Err(FieldValueInvalidByte),
            ),
            // 16: bare CR inside a value wins over field-value validation.
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nX: va\rlue\r\n\r\n",
                Expected::Err(BareCr),
            ),
            // 17: bare LF inside a value.
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nX: va\nlue\r\n\r\n",
                Expected::Err(BareLf),
            ),
            // 19: high-bit byte in a field name.
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nX\xffY: 1\r\n\r\n",
                Expected::Err(FieldNameInvalidByte),
            ),
            // 20: duplicate Host is the parser's business to accept; the
            // caller (field-section owner) refuses the duplicate.
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
                complete(36, 2),
            ),
            // 21: double space.
            (
                b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
                Expected::Err(RequestLineMalformed),
            ),
            // 22: trailing space.
            (
                b"GET / HTTP/1.1 \r\nHost: a\r\n\r\n",
                Expected::Err(RequestLineMalformed),
            ),
            // 23: HTAB in the request line.
            (
                b"GET\t/ HTTP/1.1\r\nHost: a\r\n\r\n",
                Expected::Err(RequestLineMalformed),
            ),
            // 24: unsupported version.
            (
                b"GET / HTTP/1.2\r\nHost: a\r\n\r\n",
                Expected::Err(VersionUnsupported),
            ),
            // 25: HTTP/0.9-style version string.
            (
                b"GET / HTTP/0.9\r\nHost: a\r\n\r\n",
                Expected::Err(VersionUnsupported),
            ),
            // 26: no version at all.
            (
                b"GET /\r\nHost: a\r\n\r\n",
                Expected::Err(RequestLineMalformed),
            ),
            // 27: HTTP/1.0.
            (
                b"GET / HTTP/1.0\r\n\r\n",
                Expected::Complete {
                    consumed: 18,
                    field_count: 0,
                    version: WireVersion::Http10,
                },
            ),
            // 28: lowercase method is the parser's business to accept.
            (b"get / HTTP/1.1\r\nHost: a\r\n\r\n", complete(27, 1)),
            // 29: fragment in the target.
            (
                b"GET /path#frag HTTP/1.1\r\nHost: a\r\n\r\n",
                Expected::Err(TargetFragment),
            ),
            // 35: empty value, accepted.
            (b"GET / HTTP/1.1\r\nX-A:\r\n\r\n", complete(24, 1)),
            // Not one of the 43 numbered cases: a request line malformed
            // because the colon search inside a field line finds none at
            // all, which step 3c also names `RequestLineMalformed` for.
            (
                b"GET / HTTP/1.1\r\nHostvalue\r\n\r\n",
                Expected::Err(RequestLineMalformed),
            ),
            // Not one of the 43 numbered cases: a SP as the first byte of
            // the request line, alone (no HTAB, no trailing SP, and exactly
            // two SP total so the later "exactly two SP" check cannot also
            // catch it). Isolates edge case 21/22's leading-SP clause: with
            // only this one clause true, a mutation that AND'd the three
            // leading/trailing/HTAB checks together instead of OR'ing them
            // would fail to reject here and instead read the leading SP as
            // an empty method, giving `MethodInvalid` instead.
            (
                b" / HTTP/1.1\r\nHost: a\r\n\r\n",
                Expected::Err(RequestLineMalformed),
            ),
        ];

        for (input, expected) in cases {
            expect(p, input, expected);
        }

        // 4: no Host field at all.
        expect(p, b"GET / HTTP/1.1\r\n\r\n", &complete(18, 0));

        // 30: request line boundary, exactly 8192 bytes including CRLF.
        // "GET " (4) + target + " HTTP/1.1" (9) + CRLF (2) == 8192.
        let target_len: usize = 8192 - 4 - 9 - 2;
        let mut ok_line = Vec::new();
        ok_line.extend_from_slice(b"GET /");
        ok_line.extend(std::iter::repeat_n(b'a', target_len.saturating_sub(1)));
        ok_line.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
        let request_line_len = 4 + target_len + 9 + 2;
        assert_eq!(request_line_len, 8192);
        expect(p, &ok_line, &complete(ok_line.len(), 1));

        let mut too_long_line = Vec::new();
        too_long_line.extend_from_slice(b"GET /");
        too_long_line.extend(std::iter::repeat_n(b'a', target_len));
        too_long_line.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
        expect(p, &too_long_line, &Expected::Err(RequestLineTooLong));

        // 31: 100 field lines accepted, 101 refused.
        let mut hundred = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..100 {
            hundred.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        hundred.extend_from_slice(b"\r\n");
        expect(p, &hundred, &complete(hundred.len(), 100));

        let mut hundred_one = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..101 {
            hundred_one.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        hundred_one.extend_from_slice(b"\r\n");
        expect(p, &hundred_one, &Expected::Err(FieldCountExceeded));

        // 32: one field line of exactly 8192 bytes of name plus value.
        let name = b"X";
        let value_len = 8192 - name.len();
        let mut one_line = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        one_line.extend_from_slice(name);
        one_line.extend_from_slice(b":");
        one_line.extend(std::iter::repeat_n(b'v', value_len));
        one_line.extend_from_slice(b"\r\n\r\n");
        expect(p, &one_line, &complete(one_line.len(), 1));

        let mut one_line_too_long = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        one_line_too_long.extend_from_slice(name);
        one_line_too_long.extend_from_slice(b":");
        one_line_too_long.extend(std::iter::repeat_n(b'v', value_len.saturating_add(1)));
        one_line_too_long.extend_from_slice(b"\r\n\r\n");
        expect(p, &one_line_too_long, &Expected::Err(FieldLineTooLong));

        // 33: header list total over 65536 by the `name+value+32` formula,
        // using field lines short enough to stay under max_field_line_bytes
        // and max_field_count individually.
        let mut over_list = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        // 100 fields of name(4)+value(1000)+32 = 1036 bytes each -> 103600,
        // well over 65536, and 100 fields is exactly max_field_count so the
        // count check does not fire first.
        for i in 0..100 {
            let value = "v".repeat(1000);
            over_list.extend_from_slice(format!("X{i:03}: {value}\r\n").as_bytes());
        }
        over_list.extend_from_slice(b"\r\n");
        expect(p, &over_list, &Expected::Err(HeaderListTooLarge));

        // 34: a buffer larger than max_head_bytes (73,730 at the defaults)
        // with no terminator: HeaderListTooLarge, not an unbounded Partial.
        // Tested at the EXACT threshold in both directions, not a gray zone.
        let at_boundary = vec![b'a'; 73_730];
        expect(p, &at_boundary, &Expected::Partial);
        let over_boundary = vec![b'a'; 73_731];
        expect(p, &over_boundary, &Expected::Err(HeaderListTooLarge));

        // 36: 40 field lines, past the 32-entry SmallVec spill.
        let mut forty = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..40 {
            forty.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        forty.extend_from_slice(b"\r\n");
        let result = p.parse_request_head(&forty);
        match result {
            Ok(ParseStatus::Complete { value, consumed }) => {
                assert_eq!(consumed, forty.len());
                assert_eq!(value.field_count(), 40);
                for i in 0..40 {
                    assert_eq!(value.field_name(i), Some(format!("X-{i}").as_bytes()));
                    assert_eq!(value.field_value(i), Some(&b"v"[..]));
                }
            }
            other => panic!("expected a 40-field Complete, got {other:?}"),
        }
    }

    /// Edge case 35, isolated: `field_value` for an empty value returns
    /// `Some(&[])`, not `None`. The audit's own named gap: an empty slice and
    /// a missing index both satisfy `.unwrap_or_default().is_empty()`, so
    /// only comparing against the concrete `Some(&[][..])` distinguishes
    /// them.
    #[test]
    fn field_value_of_empty_value_is_some_empty_slice() {
        let p = default_parser();
        let raw = b"GET / HTTP/1.1\r\nX-A:\r\n\r\n";
        match p.parse_request_head(raw) {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert_eq!(value.field_count(), 1);
                assert_eq!(value.field_name(0), Some(&b"X-A"[..]));
                assert_eq!(value.field_value(0), Some(&[][..]));
                assert!(value.field_value(0).is_some_and(<[u8]>::is_empty));
                // Out of range is genuinely `None`, the distinguishing case
                // from the in-range empty slice above.
                assert_eq!(value.field_value(1), None);
                assert_eq!(value.field_name(1), None);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn consumed_is_exact() {
        let p = default_parser();
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        match p.parse_request_head(raw) {
            Ok(ParseStatus::Complete { value, consumed }) => {
                assert_eq!(consumed, 27);
                // `method_bytes` against the literal, not merely
                // `!is_empty()`: a stub returning some other fixed non-empty
                // slice would still pass a non-emptiness check.
                assert_eq!(value.method_bytes(), b"GET");
            }
            other => panic!("expected Complete, got {other:?}"),
        }

        let mut pipelined = raw.to_vec();
        pipelined.extend_from_slice(b"GET /x HTTP/1.1\r\n");
        match p.parse_request_head(&pipelined) {
            Ok(ParseStatus::Complete { consumed, .. }) => {
                assert_eq!(consumed, 27);
                assert!(
                    pipelined
                        .get(consumed..)
                        .is_some_and(|rest| rest.starts_with(b"GET /x"))
                );
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn resumption_at_every_split() {
        let p = default_parser();

        let mut twenty_fields = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..20 {
            twenty_fields.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        twenty_fields.extend_from_slice(b"\r\n");

        let mut long_value = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        long_value.extend_from_slice(b"X: ");
        long_value.extend(std::iter::repeat_n(b'v', 500));
        long_value.extend_from_slice(b"\r\n\r\n");

        let mut pipelined = Vec::from(&b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"[..]);
        pipelined.extend_from_slice(b"GET /x HTTP/1.1\r\n");

        let inputs: [&[u8]; 4] = [
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            &twenty_fields,
            &long_value,
            &pipelined,
        ];

        for full in inputs {
            let whole = match p.parse_request_head(full) {
                Ok(ParseStatus::Complete { value, consumed }) => (value.field_count(), consumed),
                other => panic!("expected a Complete for the full buffer, got {other:?}"),
            };
            let (whole_field_count, head_len) = whole;
            // Every prefix strictly shorter than the head itself must be
            // Partial. A prefix at or past the head's own length must give
            // the IDENTICAL Complete, whether or not extra (pipelined) bytes
            // follow the head in `full`: `consumed` never depends on how much
            // of the buffer lies past the terminator.
            for n in 0..full.len() {
                let prefix = full.get(..n).expect("n <= full.len()");
                match p.parse_request_head(prefix) {
                    Ok(ParseStatus::Partial) if n < head_len => {}
                    Ok(ParseStatus::Complete { value, consumed }) if n >= head_len => {
                        assert_eq!(
                            (value.field_count(), consumed),
                            whole,
                            "prefix of length {n} disagreed with the full parse for {full:?}"
                        );
                    }
                    other => panic!(
                        "prefix of length {n} (head_len {head_len}) gave unexpected {other:?} \
                         for {full:?}"
                    ),
                }
            }
            match p.parse_request_head(full) {
                Ok(ParseStatus::Complete { value, consumed }) => {
                    assert_eq!((value.field_count(), consumed), whole);
                    assert_eq!(value.field_count(), whole_field_count);
                }
                other => panic!("expected the full buffer to complete again, got {other:?}"),
            }
        }
    }

    #[test]
    fn bare_cr_and_lf_win_over_line_splitting() {
        let p = default_parser();
        let cases: [(&[u8], RejectReason); 4] = [
            (b"GET / HTTP/1.1\nHost: a\n\n", RejectReason::BareLf),
            (
                b"GET / HTTP/1.1\r\nHost: a\rX: 1\r\n\r\n",
                RejectReason::BareCr,
            ),
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nX: va\rlue\r\n\r\n",
                RejectReason::BareCr,
            ),
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nX: va\nlue\r\n\r\n",
                RejectReason::BareLf,
            ),
        ];
        for (input, reason) in cases {
            match p.parse_request_head(input) {
                Err(got) => assert_eq!(got, reason, "{input:?}"),
                other => panic!("for {input:?}: expected Err({reason:?}), got {other:?}"),
            }
        }
    }

    #[test]
    fn value_trimming_is_ows_only() {
        let p = default_parser();
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\nX:  leading-ows-only \r\n\r\n";
        match p.parse_request_head(raw) {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert_eq!(value.field_value(1), Some(&b"leading-ows-only"[..]));
            }
            other => panic!("expected Complete, got {other:?}"),
        }

        let mut nbsp = Vec::from(&b"GET / HTTP/1.1\r\nHost: a\r\nX: "[..]);
        nbsp.extend_from_slice(b"\xc2\xa0x");
        nbsp.extend_from_slice(b"\r\n\r\n");
        match p.parse_request_head(&nbsp) {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert_eq!(value.field_value(1), Some(&b"\xc2\xa0x"[..]));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn limits_are_enforced() {
        let p = default_parser();

        // 30.
        let target_len: usize = 8192 - 4 - 9 - 2;
        let mut ok_line = Vec::new();
        ok_line.extend_from_slice(b"GET /");
        ok_line.extend(std::iter::repeat_n(b'a', target_len.saturating_sub(1)));
        ok_line.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(p.parse_request_head(&ok_line).is_ok());

        let mut too_long_line = Vec::new();
        too_long_line.extend_from_slice(b"GET /");
        too_long_line.extend(std::iter::repeat_n(b'a', target_len));
        too_long_line.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n\r\n");
        match p.parse_request_head(&too_long_line) {
            Err(reason) => assert_eq!(reason, RejectReason::RequestLineTooLong),
            other => panic!("expected Err(RequestLineTooLong), got {other:?}"),
        }

        // 31.
        let mut hundred = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..100 {
            hundred.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        hundred.extend_from_slice(b"\r\n");
        assert!(p.parse_request_head(&hundred).is_ok());

        let mut hundred_one = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..101 {
            hundred_one.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        hundred_one.extend_from_slice(b"\r\n");
        match p.parse_request_head(&hundred_one) {
            Err(reason) => assert_eq!(reason, RejectReason::FieldCountExceeded),
            other => panic!("expected Err(FieldCountExceeded), got {other:?}"),
        }

        // 32.
        let name = b"X";
        let value_len = 8192 - name.len();
        let mut one_line = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        one_line.extend_from_slice(name);
        one_line.extend_from_slice(b":");
        one_line.extend(std::iter::repeat_n(b'v', value_len));
        one_line.extend_from_slice(b"\r\n\r\n");
        assert!(p.parse_request_head(&one_line).is_ok());

        let mut one_line_too_long = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        one_line_too_long.extend_from_slice(name);
        one_line_too_long.extend_from_slice(b":");
        one_line_too_long.extend(std::iter::repeat_n(b'v', value_len.saturating_add(1)));
        one_line_too_long.extend_from_slice(b"\r\n\r\n");
        match p.parse_request_head(&one_line_too_long) {
            Err(reason) => assert_eq!(reason, RejectReason::FieldLineTooLong),
            other => panic!("expected Err(FieldLineTooLong), got {other:?}"),
        }

        // 33.
        let mut over_list = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..100 {
            let value = "v".repeat(1000);
            over_list.extend_from_slice(format!("X{i:03}: {value}\r\n").as_bytes());
        }
        over_list.extend_from_slice(b"\r\n");
        match p.parse_request_head(&over_list) {
            Err(reason) => assert_eq!(reason, RejectReason::HeaderListTooLarge),
            other => panic!("expected Err(HeaderListTooLarge), got {other:?}"),
        }

        // 34: the EXACT boundary, both sides. This is the precise gap the
        // audit named: a prior version of this suite tested a "gray zone"
        // rather than the literal max_head_bytes threshold, so a mutation
        // that shifted the boundary by one byte in either direction would
        // have survived.
        let at_boundary = vec![b'a'; 73_730];
        match p.parse_request_head(&at_boundary) {
            Ok(ParseStatus::Partial) => {}
            other => panic!(
                "exactly max_head_bytes with no terminator must still be Partial, got {other:?}"
            ),
        }
        let over_boundary = vec![b'a'; 73_731];
        match p.parse_request_head(&over_boundary) {
            Err(reason) => assert_eq!(
                reason,
                RejectReason::HeaderListTooLarge,
                "one byte past max_head_bytes with no terminator must be refused"
            ),
            other => panic!("one byte past max_head_bytes must be refused, got {other:?}"),
        }
    }

    #[test]
    fn uppercase_names_are_flagged_not_refused() {
        let p = default_parser();
        match p.parse_request_head(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n") {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert!(value.fields.first().expect("one field").needs_lowercase);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
        match p.parse_request_head(b"GET / HTTP/1.1\r\nhost: a\r\n\r\n") {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert!(!value.fields.first().expect("one field").needs_lowercase);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn underscore_policy() {
        let reject = parser(UnderscorePolicy::Reject);
        match reject.parse_request_head(b"GET / HTTP/1.1\r\nX_A: 1\r\n\r\n") {
            Err(reason) => assert_eq!(reason, RejectReason::FieldNameUnderscore),
            other => panic!("expected Err(FieldNameUnderscore), got {other:?}"),
        }

        let map = parser(UnderscorePolicy::MapToHyphen);
        match map.parse_request_head(b"GET / HTTP/1.1\r\nX_A: 1\r\n\r\n") {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert_eq!(value.field_name(0), Some(&b"X_A"[..]));
                assert_eq!(value.field_value(0), Some(&b"1"[..]));
            }
            other => panic!("expected Complete under MapToHyphen, got {other:?}"),
        }
    }

    #[test]
    fn response_head_cases() {
        let p = default_parser();

        // 38.
        match p.parse_response_head(b"HTTP/1.1 200 OK\r\n\r\n") {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert_eq!(value.status, StatusCode::OK);
                assert_eq!(value.version, WireVersion::Http11);
            }
            other => panic!("expected Complete, got {other:?}"),
        }

        // HTTP/1.0, the other supported response version: the audit's own
        // named gap, version was asserted for HTTP/1.1 responses only, so a
        // mutation deleting the `b"HTTP/1.0"` match arm entirely (falling
        // through to `VersionUnsupported`) survived every prior check here.
        match p.parse_response_head(b"HTTP/1.0 200 OK\r\n\r\n") {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert_eq!(value.version, WireVersion::Http10);
            }
            other => panic!("expected Complete, got {other:?}"),
        }

        // 39: no reason phrase.
        match p.parse_response_head(b"HTTP/1.1 200\r\n\r\n") {
            Ok(ParseStatus::Complete { value, .. }) => {
                assert_eq!(value.status.as_u16(), 200);
            }
            other => panic!("expected Complete, got {other:?}"),
        }

        // 40: two digits.
        match p.parse_response_head(b"HTTP/1.1 20 OK\r\n\r\n") {
            Err(reason) => assert_eq!(reason, RejectReason::RequestLineMalformed),
            other => panic!("expected Err(RequestLineMalformed), got {other:?}"),
        }

        // 41: below 100.
        match p.parse_response_head(b"HTTP/1.1 099 OK\r\n\r\n") {
            Err(reason) => assert_eq!(reason, RejectReason::RequestLineMalformed),
            other => panic!("expected Err(RequestLineMalformed), got {other:?}"),
        }

        // 42: NUL in the reason phrase.
        match p.parse_response_head(b"HTTP/1.1 200 O\0K\r\n\r\n") {
            Err(reason) => assert_eq!(reason, RejectReason::FieldValueInvalidByte),
            other => panic!("expected Err(FieldValueInvalidByte), got {other:?}"),
        }

        // Above 599 (not itself one of the 43 numbered cases, but the
        // upper-bound twin of case 41).
        match p.parse_response_head(b"HTTP/1.1 600 x\r\n\r\n") {
            Err(reason) => assert_eq!(reason, RejectReason::RequestLineMalformed),
            other => panic!("expected Err(RequestLineMalformed), got {other:?}"),
        }

        // The middle status digit invalid, with no reason phrase (so the
        // separate "reason phrase must start with SP" check cannot ALSO
        // reject this input and mask a broken digit check): `2`, `:`
        // (0x3A, one past `9`) and `0`. A mutation replacing either `&&` in
        // `d0.is_ascii_digit() && d1.is_ascii_digit() && d2.is_ascii_digit()`
        // with `||` still rejects "20 OK" and "HTTP/1.1 20X" above (a
        // DIFFERENT check downstream happens to also fire), but here the
        // bypassed check would let `saturating_sub(b'0')` turn `:` into 10,
        // computing status 300 (2*100 + 10*10 + 0), which is genuinely in
        // 100..=599 and would be wrongly ACCEPTED.
        match p.parse_response_head(b"HTTP/1.1 2:0\r\n\r\n") {
            Err(reason) => assert_eq!(reason, RejectReason::RequestLineMalformed),
            other => panic!("expected Err(RequestLineMalformed), got {other:?}"),
        }
    }

    #[test]
    fn response_status_line_length_boundary() {
        // The response-head twin of `limits_are_enforced`'s request-line
        // boundary (edge case 30), at the exact threshold in both
        // directions: `parse_response_head` has its own, separately written
        // `first_crlf.saturating_add(2) > max_request_line_bytes` check.
        let p = default_parser();

        let target_len: usize = 8192 - "HTTP/1.1 200 ".len() - 2;
        let mut ok_line = Vec::from(&b"HTTP/1.1 200 "[..]);
        ok_line.extend(std::iter::repeat_n(b'x', target_len));
        ok_line.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            "HTTP/1.1 200 ".len() + target_len + 2,
            8192,
            "test setup: the status line plus its CRLF must be exactly 8192 bytes"
        );
        assert!(p.parse_response_head(&ok_line).is_ok());

        let mut too_long_line = Vec::from(&b"HTTP/1.1 200 "[..]);
        too_long_line.extend(std::iter::repeat_n(b'x', target_len.saturating_add(1)));
        too_long_line.extend_from_slice(b"\r\n\r\n");
        match p.parse_response_head(&too_long_line) {
            Err(reason) => assert_eq!(reason, RejectReason::RequestLineTooLong),
            other => panic!("expected Err(RequestLineTooLong), got {other:?}"),
        }
    }

    #[test]
    fn head_scan_budget_bounds_the_rescan() {
        // Charges through a `&mut` borrow rather than a copy: the
        // distinguishing helper for the `Copy` assertion near the end of
        // this test. Declared first because Rust items must precede
        // statements in a block.
        fn charge_via_borrow(budget: &mut HeadScanBudget, n: usize) {
            budget.charge(n).expect("well under the budget");
        }

        // 45: a max_head_bytes-sized head delivered one byte per read. The
        // cumulative charge crosses HeadScanBudget::MAX_BYTES well before the
        // full head ever arrives.
        let mut budget = HeadScanBudget::default();
        let mut last_ok_at: Option<usize> = None;
        let mut failed_at: Option<usize> = None;
        for n in 1..=73_730_usize {
            match budget.charge(n) {
                Ok(()) => {
                    assert!(
                        budget.scanned() <= HeadScanBudget::MAX_BYTES,
                        "charge() returned Ok but scanned() ({}) exceeds MAX_BYTES at n={n}",
                        budget.scanned()
                    );
                    last_ok_at = Some(n);
                }
                Err(reason) => {
                    assert_eq!(reason, RejectReason::HeaderListTooLarge);
                    assert!(
                        budget.scanned() > HeadScanBudget::MAX_BYTES,
                        "charge() failed but scanned() ({}) did not exceed MAX_BYTES",
                        budget.scanned()
                    );
                    failed_at = Some(n);
                    break;
                }
            }
        }
        let last_ok = last_ok_at.expect("at least one call must succeed");
        let failed = failed_at.expect("the schedule must eventually cross MAX_BYTES");
        assert!(
            last_ok < failed,
            "the last accepted call must precede the first refused one"
        );
        // Every Ok call was strictly under 5 MiB of cumulative scan: refusing
        // happens close to the 4 MiB budget, not after an unbounded drift.
        assert!(budget.scanned() < 5 * 1024 * 1024);

        // 46: a legitimate 8 KiB head delivered in six segments never trips
        // the budget.
        let mut small = HeadScanBudget::default();
        for _ in 0..6 {
            assert_eq!(small.charge(1400), Ok(()));
        }
        assert!(small.scanned() < HeadScanBudget::MAX_BYTES);

        // 47: reset restores a full budget.
        let mut resettable = HeadScanBudget::default();
        assert_eq!(
            resettable.charge(usize::try_from(HeadScanBudget::MAX_BYTES).unwrap_or(usize::MAX)),
            Ok(())
        );
        assert_eq!(resettable.scanned(), HeadScanBudget::MAX_BYTES);
        resettable.reset();
        assert_eq!(resettable.scanned(), 0);
        assert_eq!(resettable.charge(1), Ok(()));

        // The distinguishing assertion for `Copy`: charging through a `&mut`
        // borrow inside a helper is visible to the owner. If `HeadScanBudget`
        // were ever made `Copy`, a caller passing it by value here would
        // charge a copy and `owner.scanned()` below would read 0, not the
        // charged amount.
        let mut owner = HeadScanBudget::default();
        charge_via_borrow(&mut owner, 100);
        charge_via_borrow(&mut owner, 200);
        assert_eq!(owner.scanned(), 300);
    }

    /// Exact target bytes for each of the four request-target forms RFC 9112
    /// Section 3.2 names (origin-form, absolute-form, authority-form and
    /// asterisk-form), checked against `RawHead::target` directly (this test
    /// lives inside the crate, so the `pub(crate)` field is visible here,
    /// same as `prop_never_panics_and_consumed_in_range` above).
    ///
    /// This is the assertion issue #584 found missing: every prior check
    /// only asked `target.of(&input).is_some()`, which a wrong span (for
    /// example one that starts one byte early, per the issue's own
    /// `target_start = first_sp` reproduction) still satisfies as long as it
    /// stays in bounds. Comparing the exact bytes is what a wrong span
    /// cannot survive.
    #[test]
    fn target_span_is_exact_for_every_request_target_form() {
        let p = default_parser();
        let cases: &[(&[u8], &[u8])] = &[
            // Origin-form.
            (b"GET / HTTP/1.1\r\n\r\n", b"/"),
            (b"GET /a/b?c=1 HTTP/1.1\r\n\r\n", b"/a/b?c=1"),
            // Absolute-form.
            (
                b"GET http://example.com/a HTTP/1.1\r\n\r\n",
                b"http://example.com/a",
            ),
            (
                b"GET http://example.com:8080/a/b HTTP/1.1\r\n\r\n",
                b"http://example.com:8080/a/b",
            ),
            // Authority-form (the CONNECT method's target).
            (
                b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
                b"example.com:443",
            ),
            (
                b"CONNECT 203.0.113.5:8080 HTTP/1.1\r\n\r\n",
                b"203.0.113.5:8080",
            ),
            // Asterisk-form (OPTIONS's target).
            (b"OPTIONS * HTTP/1.1\r\n\r\n", b"*"),
        ];
        for (input, expected_target) in cases {
            match p.parse_request_head(input) {
                Ok(ParseStatus::Complete { value, .. }) => {
                    assert_eq!(
                        value.target.of(input),
                        Some(*expected_target),
                        "target span mismatch for {input:?}"
                    );
                }
                other => panic!("expected Complete for {input:?}, got {other:?}"),
            }
        }
    }

    /// A syntactically plausible HTTP/1.1 request head: a known method, one
    /// request-target of each of the four forms RFC 9112 Section 3.2 names
    /// (origin-form, absolute-form, authority-form, asterisk-form), a
    /// supported version, and zero to four ordinary field lines.
    ///
    /// This exists because the OLD generator below (pure random bytes with
    /// one byte forced to a delimiter) never produces a well-formed head:
    /// issue #584 replicated it over 20 million samples and measured zero
    /// `Complete` results, which means every assertion inside
    /// `prop_never_panics_and_consumed_in_range`'s `Complete` arm, including
    /// the one that checks `RawHead::target`, was dead code that no CI run
    /// ever executed. A mostly-valid head is short (tens of bytes) next to
    /// `mutation_index`'s `0..2048` range, so most of the time the mutation
    /// below lands out of bounds and is a no-op (`input.get_mut` returns
    /// `None`), and the still-valid head reaches `Complete`; the times it
    /// does land in range exercise the same corruption-resilience property
    /// the old generator was written for, just starting from a realistic
    /// head instead of noise. Mixed with the old generator via `prop_oneof!`
    /// below, not a replacement for it: arbitrary bytes remain in the mix
    /// for the coverage they alone provide over the `Err` and `Partial`
    /// paths.
    fn plausible_head() -> impl Strategy<Value = Vec<u8>> {
        let method = proptest::sample::select(
            &["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "CONNECT"][..],
        );
        let target = proptest::sample::select(
            &[
                // Origin-form.
                "/",
                "/a/b?c=1",
                // Absolute-form.
                "http://example.com/a",
                "http://example.com:8080/a/b",
                // Authority-form.
                "example.com:443",
                "203.0.113.5:8080",
                // Asterisk-form.
                "*",
            ][..],
        );
        let version = proptest::sample::select(&["HTTP/1.1", "HTTP/1.0"][..]);
        let field = (
            proptest::sample::select(&["Host", "X-A", "Accept", "User-Agent"][..]),
            proptest::sample::select(&["a", "example.com", "", "text/plain"][..]),
        );
        let fields = proptest::collection::vec(field, 0..=4);
        (method, target, version, fields).prop_map(|(method, target, version, fields)| {
            let mut buf = Vec::new();
            buf.extend_from_slice(method.as_bytes());
            buf.push(b' ');
            buf.extend_from_slice(target.as_bytes());
            buf.push(b' ');
            buf.extend_from_slice(version.as_bytes());
            buf.extend_from_slice(b"\r\n");
            for (name, value) in fields {
                buf.extend_from_slice(name.as_bytes());
                buf.extend_from_slice(b": ");
                buf.extend_from_slice(value.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
            buf.extend_from_slice(b"\r\n");
            buf
        })
    }

    proptest::proptest! {
        #[test]
        fn prop_never_panics_and_consumed_in_range(
            input in proptest::prop_oneof![
                proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=2048),
                plausible_head(),
            ],
            mutation_index in 0..2048_usize,
            mutation_byte in proptest::sample::select(&[b'\r', b'\n', b':', b' ', b'\t', 0u8][..]),
        ) {
            let mut input = input;
            if let Some(slot) = input.get_mut(mutation_index) {
                *slot = mutation_byte;
            }
            let p = default_parser();
            let result = p.parse_request_head(&input);
            if let Ok(ParseStatus::Complete { value, consumed }) = result {
                assert!(consumed <= input.len());
                assert!(value.method.of(&input).is_some());
                assert!(value.target.of(&input).is_some());
                for i in 0..value.field_count() {
                    assert!(value.field_name(i).is_some());
                    assert!(value.field_value(i).is_some());
                }
            }
        }
    }
}
