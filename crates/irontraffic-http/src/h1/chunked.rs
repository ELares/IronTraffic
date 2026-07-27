// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`ChunkedDecoder`]: the resumable HTTP/1 chunked-transfer-coding decoder,
//! and [`trailer_denied`]/[`TRAILER_DENIED`], the trailer field deny-list.
//!
//! **Unlike [`super::parser::H1Parser`], this decoder KEEPS STATE across
//! calls.** The head parser can afford to re-run from the start of a bounded
//! buffer on every call; a chunked body cannot, because re-scanning a
//! gigabyte upload on every read wakeup is quadratic in the body size. So
//! this is an explicit state machine, fed incrementally: [`ChunkedDecoder::decode`]
//! consumes as much of the caller's buffer as it can, returns one
//! [`ChunkedEvent`], and the caller re-calls with whatever the decoder did
//! not consume plus anything newly arrived. State-machine resumption bugs
//! are where chunked parsers actually break in the wild, so every state that
//! can be observed mid-value (a partial chunk-size, a partial chunk
//! extension, a partial trailer field) is a real, explicit case here, never
//! an implicit assumption that a whole token arrives in one call.
//!
//! **The decoder never reads a byte of chunk data.** Once a chunk-size is
//! known, `remaining` bytes of data are an opaque `advance(n)`: the decoder
//! reports `ChunkedEvent::Data { offset, len }`, the caller moves those bytes
//! itself (straight from the read buffer to the upstream writer), and the
//! decoder never indexes into that region. A naive implementation that scans
//! every body byte turns a 1 GiB upload into a 1 GiB scan for no reason: the
//! data does not need validating, because it is never re-encoded here
//! (`h1-request-serializer`, #37, owns outbound chunking, and it never
//! re-emits the client's own chunk boundaries).
//!
//! **Trailers are never merged into the header section.** A request that
//! passed an `Authorization`-based policy on its headers must not be able to
//! add a `Content-Length` or a `Host` in a trailer: [`TRAILER_DENIED`] refuses
//! 18 field names outright (`Err(RejectReason::TrailerFieldForbidden)`, never
//! a silent drop), and this module deliberately has no `merge_trailers`, no
//! `promote_trailers`, and no `headers_including_trailers` method. The
//! trailer section, once parsed, is reachable only through
//! [`ChunkedDecoder::trailers`], a completely separate [`FieldSection`] from
//! whatever the caller built for the request's own header section.
//!
//! **A note on this module's `ChunkedDecoder` fields versus the issue that
//! specified them.** The issue's own field list for `ChunkedDecoder` has no
//! room to resume correctly in the middle of a chunk-extension: RFC 9112's
//! `chunk-ext` grammar has its own internal modes (top level vs. inside a
//! quoted-string, and whether the previous quoted-string byte was an
//! unescaped backslash), and those modes must survive exactly the kind of
//! split `split_invariance`'s own case 7 (`1;ext=value\r\nA\r\n0\r\n\r\n`,
//! tested at every split size from 1 to its length, which includes a split
//! immediately after the leading `;`) exercises. Implementing chunk-ext
//! parsing without that state would either reject some legal splits or, worse,
//! silently misparse a quoted extension split across two reads, which is
//! precisely the resumption-bug class this whole design exists to rule out.
//! [`ExtMode`] (four unit variants, no heap data) and the `ext_mode` field
//! below are the minimal addition that fixes this; a defect has been filed
//! against the issue rather than silently working around it. Every other
//! field matches the issue's field list exactly.

use bytes::BytesMut;

use crate::error::RejectReason;
use crate::field::{self, UnderscorePolicy};
use crate::hlist::HeaderListBudget;
use crate::known::{self, KnownHeader};
use crate::limits::ClampedLimits;
use crate::scalar::{WireVersion, is_tchar};
use crate::section::{FieldSection, FieldSectionBuilder};

use super::parser::HeadScanBudget;

/// What the decoder produced from the bytes it was given.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChunkedEvent {
    /// `len` bytes of body data start at `offset` in the input slice. The
    /// caller moves them; the decoder has NOT looked at them.
    Data {
        /// Offset into the `buf` this `decode` call was given.
        offset: usize,
        /// Number of body bytes available starting at `offset`.
        len: usize,
    },
    /// Not enough bytes to make progress. Feed more and call again.
    NeedMore,
    /// The body and its trailer section are complete. `consumed` bytes of
    /// the input belonged to this message; `buf[consumed..]` is the first
    /// byte after it.
    Done {
        /// Bytes of the `buf` this `decode` call was given that belonged to
        /// the tail of this message.
        consumed: usize,
    },
}

/// Which byte the size-line state machine is currently reading.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum State {
    /// Reading hex digits of a chunk-size.
    Size,
    /// Reading chunk-ext bytes after a `;`.
    Ext,
    /// Expecting the `\n` that ends the size line (the `\r` is already
    /// consumed by `Size` or `Ext`).
    SizeCrlf,
    /// Delivering `remaining` data bytes.
    Data,
    /// Expecting the CRLF that follows the chunk data.
    DataCrlf,
    /// Reading the trailer section after the terminal 0-size chunk.
    Trailers,
    /// Complete.
    Done,
}

/// Sub-state inside [`State::Ext`], NOT part of the issue's own field list;
/// see the module doc comment for why one is necessary. Chunk-ext parsing is
/// its own small grammar (RFC 9112 Section 7.1.1) with modes that must
/// themselves survive being split across two `decode` calls.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ExtMode {
    /// Just consumed a `;` (the one that entered `Ext`, or one found at the
    /// top level since). The next byte must not be `;` or `\r`: either would
    /// mean an empty `chunk-ext-name`.
    AfterSemicolon,
    /// At the top level of one chunk-ext entry, outside any quoted-string.
    TopLevel,
    /// Inside a quoted-string; the previous byte was not an unescaped `\`.
    Quoted,
    /// Inside a quoted-string, immediately after an unescaped `\`: this byte
    /// is a `quoted-pair` literal (unless it is `\r` or `\n`, which are
    /// refused even here).
    QuotedEscaped,
}

/// Outcome of one internal parsing step, shared by every `step_*` helper.
enum Step {
    /// Keep looping: this step made progress and another step should run.
    Continue,
    /// Not enough bytes to finish this step. Stop and report `NeedMore`.
    NeedMore,
    /// The trailer section (and therefore the whole message) is complete.
    /// Only `step_trailers` ever produces this.
    Done,
}

/// Resumable chunked-transfer-coding decoder. One per request or response
/// body.
///
/// Unlike the head parser this KEEPS state across calls: re-running from the
/// start of a gigabyte body on every read wakeup would be quadratic.
#[derive(Debug)]
pub struct ChunkedDecoder {
    state: State,
    /// Bytes of the current chunk still to be delivered.
    remaining: u64,
    /// Total body octets delivered so far, for reconciliation.
    delivered: u64,
    /// chunk-ext bytes seen on the current chunk.
    ext_bytes: u32,
    /// Hex digits seen on the current chunk-size, for the 16-digit cap.
    size_digits: u8,
    /// See [`ExtMode`] and the module doc comment: not part of the issue's
    /// own field list, added so a chunk-ext split across two `decode` calls
    /// (including mid-quoted-string) resumes correctly instead of silently
    /// misparsing.
    ext_mode: ExtMode,
    /// The trailer section under construction, created on entry to
    /// `Trailers`. It is a `FieldSectionBuilder`, not a `FieldSection`,
    /// because the trailer section can span several `decode` calls, which is
    /// possible only because `FieldSectionBuilder` holds no borrow of the
    /// arena.
    trailer_builder: Option<FieldSectionBuilder>,
    /// The finished trailer section, moved here on entry to `Done`.
    trailers: Option<FieldSection>,
    /// Running header-list budget for the trailer section. Fresh, never
    /// shared with the head's.
    trailer_budget: HeaderListBudget,
    /// Cumulative bytes SEARCHED (not consumed) while looking for the end of
    /// a trailer line, across every `decode` call. Bounds the re-scan a
    /// drip-feeding peer can buy; see state `Trailers`. Compared against
    /// `HeadScanBudget::MAX_BYTES`.
    trailer_scan: u64,
    /// Bytes of the buffer the most recent `decode` call consumed. Reported
    /// by `consumed_this_call` and reset at the top of every call.
    last_consumed: usize,
    /// `arena.len()` as observed at the end of the most recent `decode`
    /// call. Used only to `debug_assert` the precondition documented on
    /// `decode`: while `trailer_builder` is `Some`, the caller's `arena`
    /// must never shrink below this between calls. See issue #658: a
    /// caller that instead hands `decode` a fresh or reclaimed buffer on a
    /// later call does not error, it silently corrupts the trailer section
    /// (every offset `FieldSectionBuilder` recorded against the old buffer
    /// becomes wrong), or, if the new buffer is shorter than `base`, makes
    /// `FieldSectionBuilder::finish`'s `split_off` panic on the request
    /// path. This cannot detect a caller that swaps in a DIFFERENT buffer
    /// of at least the same length (no unsafe pointer identity check is
    /// available in a crate that denies `unsafe`), but it catches the
    /// shrink, which is what every harness in this crate got wrong before
    /// the fix.
    trailer_arena_watermark: usize,
    limits: ClampedLimits,
    underscores: UnderscorePolicy,
}

/// Maximum legal hex digits in a chunk-size, per RFC 9112 Section 7.1.1's
/// implicit bound and this crate's own explicit one.
const MAX_SIZE_DIGITS: u8 = 16;

/// Bounds the `memchr` scan window used to find the end of a chunk-size run.
/// The byte right after `MAX_SIZE_DIGITS` legal hex digits is always
/// decisive (the `;`/`\r` boundary, an invalid byte, or the digit that
/// overflows the cap), so no legal or illegal chunk-size line ever needs
/// more than this many bytes inspected to resolve, regardless of how large
/// the caller's buffer is. This is what keeps the `memchr` call itself O(1)
/// rather than O(`buf.len()`) when a peer hands a huge buffer containing no
/// chunk-size terminator at all.
const SIZE_LINE_SCAN_CAP: usize = 24;

/// The longest canonical `KnownHeader` spelling is 19 bytes
/// (`if-unmodified-since`, `proxy-authorization`); `known::classify` returns
/// `Unknown` unconditionally for any longer name (its outer `match` on
/// length has no arm past 19). A trailer name longer than this can therefore
/// never be one of the 18 denied headers, so this buffer never needs to be
/// sized to the wire's much larger `max_field_line_bytes` ceiling.
const MAX_DENIABLE_NAME_LEN: usize = 19;

/// Slack added to `max_field_line_bytes` when bounding how far
/// `step_trailers` searches for one trailer line's terminating CRLF. See the
/// comment at its one call site for why the issue's own literal "+2" is not
/// enough room: a field-line's raw wire bytes include the colon and RFC 9110
/// OWS around the value, neither of which this decoder's `line_len` check
/// (name plus TRIMMED value, matching `h1-head-parser`'s identical formula)
/// counts, so a maximal-length field sent with even a single space after the
/// colon has raw bytes past what "+2" can see. 64 is generous slack for the
/// colon and any realistic amount of OWS while keeping the search
/// `O(max_field_line_bytes)` rather than unbounded.
const TRAILER_SEARCH_CAP_SLACK: usize = 64;

/// Classifies `name`, `pass` for whether the classification is `Unknown`,
/// canonicalizing it first exactly as `push_normalized` does (lowercase,
/// with `policy` applied to `_`), without needing a way to read back the
/// bytes `push_normalized` already wrote into the arena. See the module doc
/// comment: `FieldSectionBuilder` has no accessor for the slot it just
/// pushed, so this recomputes the canonical form independently rather than
/// reading it back.
fn classify_trailer_name(raw_name: &[u8], policy: UnderscorePolicy) -> KnownHeader {
    if raw_name.len() > MAX_DENIABLE_NAME_LEN {
        return KnownHeader::Unknown;
    }
    let mut buf = [0_u8; MAX_DENIABLE_NAME_LEN];
    match field::normalize_name_into(raw_name, policy, &mut buf) {
        Ok(n) => buf.get(..n).map_or(KnownHeader::Unknown, known::classify),
        Err(_) => KnownHeader::Unknown,
    }
}

/// The value of hex digit `b`, or `None` if it is not `0`-`9`, `a`-`f`, or
/// `A`-`F`.
fn hex_digit_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// True for a byte legal at the TOP level of a chunk-ext (outside any
/// quoted-string), other than `;` and `"`, which the caller matches
/// separately because they change mode.
fn is_ext_top_byte(b: u8) -> bool {
    b == b'=' || b == b' ' || b == b'\t' || is_tchar(b)
}

/// Fields that may never appear in a trailer section.
///
/// Trailers are NEVER merged into the header map. A request that passed an
/// `Authorization`-based policy on its headers must not be able to add a
/// `Content-Length` or a `Host` in a trailer.
///
/// Exactly 18 entries, in exactly this order (`trailer_deny_list` pins both
/// facts). A field name starting with `:` (a pseudo-header smuggled into a
/// trailer) is refused by the field name validator because `:` is not a name
/// byte, and a reserved-prefix name is refused by `strip::is_reserved_prefix`
/// when the trailer section is later stripped; neither needs an entry here.
const TRAILER_DENIED: [KnownHeader; 18] = [
    KnownHeader::TransferEncoding,
    KnownHeader::ContentLength,
    KnownHeader::Host,
    KnownHeader::Expect,
    KnownHeader::MaxForwards,
    KnownHeader::CacheControl,
    KnownHeader::IfMatch,
    KnownHeader::IfNoneMatch,
    KnownHeader::IfModifiedSince,
    KnownHeader::IfUnmodifiedSince,
    KnownHeader::IfRange,
    KnownHeader::Range,
    KnownHeader::Te,
    KnownHeader::Authorization,
    KnownHeader::ProxyAuthorization,
    KnownHeader::Cookie,
    KnownHeader::SetCookie,
    KnownHeader::Trailer,
];

/// True when `k` may never appear in a trailer section.
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "total by construction: i is bounded by the while condition against \
              TRAILER_DENIED.len() on every iteration, the same pattern field.rs's \
              build_name_ok/build_value_ok use for a const fn table scan"
)]
pub const fn trailer_denied(k: KnownHeader) -> bool {
    let target = k as u8; // it-allow: unchecked-cast reason: repr(u8) enum tag, exact by construction
    let mut i = 0usize;
    while i < TRAILER_DENIED.len() {
        let candidate = TRAILER_DENIED[i] as u8; // it-allow: unchecked-cast reason: repr(u8) enum tag, exact by construction
        if target == candidate {
            return true;
        }
        i = i.saturating_add(1);
    }
    false
}

impl ChunkedDecoder {
    /// A decoder for one request or response body.
    #[must_use]
    pub fn new(limits: &ClampedLimits, underscores: UnderscorePolicy) -> Self {
        Self {
            state: State::Size,
            remaining: 0,
            delivered: 0,
            ext_bytes: 0,
            size_digits: 0,
            ext_mode: ExtMode::TopLevel,
            trailer_builder: None,
            trailers: None,
            trailer_budget: HeaderListBudget::new(limits),
            trailer_scan: 0,
            last_consumed: 0,
            trailer_arena_watermark: 0,
            limits: *limits,
            underscores,
        }
    }

    /// Consumes as much of `buf` as it can and returns one event.
    ///
    /// `buf` MUST start at the first byte this decoder has not already
    /// consumed. The caller ALWAYS advances by `consumed_this_call()`,
    /// whatever the event was: that is one rule for all three events instead
    /// of three rules. Concretely it equals `offset + len` after a `Data`
    /// (because `offset` is relative to the start of `buf`, so it already
    /// includes the size line consumed in the same call), `consumed` after a
    /// `Done`, and, after a `NeedMore`, however many framing bytes this call
    /// was able to consume, which may be 0 and is never more than
    /// `buf.len()`. A `NeedMore` returning a nonzero value is normal: a
    /// partial size line is consumed into the decoder's own `remaining` and
    /// `size_digits` state.
    ///
    /// `arena` MUST be the SAME growing buffer across every call for one
    /// body, from the first call through the one that returns `Done`.
    /// Internally, once the terminal chunk is seen, this decoder starts a
    /// [`FieldSectionBuilder`] for the trailer section and writes each
    /// trailer field's bytes into `arena` as it is parsed, across as many
    /// calls as the trailer section spans; the builder records offsets
    /// relative to `arena`'s length at the moment it was created, and
    /// [`FieldSectionBuilder::finish`] later splits those bytes back out of
    /// `arena`. Handing this decoder a fresh, shorter, or otherwise
    /// different buffer on a later call does not error: it silently
    /// corrupts the trailer section (every previously recorded offset now
    /// points at the wrong bytes, or past the end of the new buffer), and
    /// in the worst case makes `finish`'s internal `split_off` panic
    /// because the new buffer is shorter than the offset it expects to
    /// split at. A body with no trailer section never touches `arena` at
    /// all, so this precondition is free to satisfy there: one
    /// `BytesMut::new()` reused for the whole body, exactly like the
    /// buffer this decoder's own `Data` events already assume the caller
    /// is not reallocating out from under. Debug builds `debug_assert` a
    /// necessary (not sufficient, since no `unsafe` pointer-identity check
    /// is available here) condition for this: `arena` must never SHRINK
    /// between two calls while a trailer section is being built.
    ///
    /// The decoder never reads chunk data. `Data` reports where the bytes
    /// are and the caller moves them.
    ///
    /// # Errors
    /// `ChunkSizeInvalid`, `ChunkSizeOverflow`, `ChunkExtInvalid`,
    /// `ChunkExtTooLong`, `ChunkTerminatorInvalid`, `TrailerFieldForbidden`,
    /// plus every field-syntax reason the trailer section can produce
    /// (`ObsFold`, `BareCr`, `BareLf`, `FieldNameEmpty`,
    /// `WhitespaceBeforeColon`, `FieldNameUnderscore`, `FieldNameInvalidByte`,
    /// `FieldValueInvalidByte`, `FieldLineTooLong`, `FieldCountExceeded`,
    /// `HeaderListTooLarge`, `RequestLineMalformed`).
    pub fn decode(
        &mut self,
        buf: &[u8],
        arena: &mut BytesMut,
    ) -> Result<ChunkedEvent, RejectReason> {
        if self.trailer_builder.is_some() {
            debug_assert!(
                arena.len() >= self.trailer_arena_watermark,
                "ChunkedDecoder::decode precondition violated: arena must be the SAME \
                 growing buffer across every call while a trailer section is being built \
                 (arena.len() == {}, expected at least {}); see issue #658",
                arena.len(),
                self.trailer_arena_watermark
            );
        }
        let mut cursor = 0usize;
        let result = self.run(buf, &mut cursor, arena);
        self.last_consumed = cursor;
        self.trailer_arena_watermark = arena.len();
        result
    }

    /// Bytes of `buf` the last `decode` call consumed for framing purposes,
    /// including the bytes reported as `Data`. The caller advances by
    /// exactly this much.
    #[must_use]
    pub const fn consumed_this_call(&self) -> usize {
        self.last_consumed
    }

    /// Total body octets delivered so far.
    #[must_use]
    pub const fn delivered(&self) -> u64 {
        self.delivered
    }

    /// True once the terminal chunk and the trailer section have been
    /// parsed.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// The validated trailer section, available only after `Done`.
    #[must_use]
    pub fn trailers(&self) -> Option<&FieldSection> {
        self.trailers.as_ref()
    }

    /// The main state-machine loop for one `decode` call. Runs every step it
    /// can from `cursor` onward, stopping (and reporting) the moment there is
    /// an event to report or the input runs out.
    fn run(
        &mut self,
        buf: &[u8],
        cursor: &mut usize,
        arena: &mut BytesMut,
    ) -> Result<ChunkedEvent, RejectReason> {
        loop {
            match self.state {
                State::Size => match self.step_size(buf, cursor)? {
                    Step::Continue => {}
                    Step::NeedMore | Step::Done => return Ok(ChunkedEvent::NeedMore),
                },
                State::Ext => match self.step_ext(buf, cursor)? {
                    Step::Continue => {}
                    Step::NeedMore | Step::Done => return Ok(ChunkedEvent::NeedMore),
                },
                State::SizeCrlf => match self.step_size_crlf(buf, cursor, arena)? {
                    Step::Continue => {}
                    Step::NeedMore | Step::Done => return Ok(ChunkedEvent::NeedMore),
                },
                State::Data => match self.step_data(buf, cursor) {
                    Some(event) => return Ok(event),
                    None => return Ok(ChunkedEvent::NeedMore),
                },
                State::DataCrlf => match self.step_data_crlf(buf, cursor)? {
                    Step::Continue => {}
                    Step::NeedMore | Step::Done => return Ok(ChunkedEvent::NeedMore),
                },
                State::Trailers => match self.step_trailers(buf, cursor, arena)? {
                    Step::Continue => {}
                    Step::NeedMore => return Ok(ChunkedEvent::NeedMore),
                    Step::Done => return Ok(ChunkedEvent::Done { consumed: *cursor }),
                },
                State::Done => return Ok(ChunkedEvent::Done { consumed: 0 }),
            }
        }
    }

    /// Accepts one hex digit into `remaining`/`size_digits`.
    ///
    /// # Errors
    /// `ChunkSizeInvalid` if `b` is not a hex digit; `ChunkSizeOverflow` if
    /// this digit would push `size_digits` past `MAX_SIZE_DIGITS` or make
    /// `remaining` overflow `u64`.
    fn accept_size_digit(&mut self, b: u8) -> Result<(), RejectReason> {
        let digit = hex_digit_value(b).ok_or(RejectReason::ChunkSizeInvalid)?;
        self.size_digits = self.size_digits.saturating_add(1);
        if self.size_digits > MAX_SIZE_DIGITS {
            return Err(RejectReason::ChunkSizeOverflow);
        }
        self.remaining = self
            .remaining
            .checked_mul(16)
            .and_then(|v| v.checked_add(u64::from(digit)))
            .ok_or(RejectReason::ChunkSizeOverflow)?;
        Ok(())
    }

    /// Step 1: reading hex digits of a chunk-size, per `memchr` on a bounded
    /// window (see `SIZE_LINE_SCAN_CAP`) followed by validating the digits it
    /// found.
    fn step_size(&mut self, buf: &[u8], cursor: &mut usize) -> Result<Step, RejectReason> {
        let region = buf.get(*cursor..).unwrap_or(&[]);
        let window_len = region.len().min(SIZE_LINE_SCAN_CAP);
        let window = region.get(..window_len).unwrap_or(&[]);
        let boundary = memchr::memchr3(b';', b'\r', b'\n', window);
        let digits_len = boundary.unwrap_or(window_len);

        for &b in window.get(..digits_len).unwrap_or(&[]) {
            self.accept_size_digit(b)?;
        }
        *cursor = cursor.saturating_add(digits_len);

        let Some(boundary_pos) = boundary else {
            // No boundary within the window. If that is because the window
            // was capped rather than genuinely exhausted, every byte in it
            // validated as a legal digit above, which is impossible past
            // MAX_SIZE_DIGITS: accept_size_digit would already have returned
            // ChunkSizeOverflow. So reaching here means region.len() was
            // itself < window_len's cap: a genuine end of available input.
            return Ok(Step::NeedMore);
        };

        match window.get(boundary_pos) {
            Some(b';') => {
                if self.size_digits == 0 {
                    return Err(RejectReason::ChunkSizeInvalid);
                }
                self.ext_bytes = 1;
                self.ext_mode = ExtMode::AfterSemicolon;
                self.state = State::Ext;
                *cursor = cursor.saturating_add(1);
                Ok(Step::Continue)
            }
            Some(b'\r') => {
                if self.size_digits == 0 {
                    return Err(RejectReason::ChunkSizeInvalid);
                }
                self.state = State::SizeCrlf;
                *cursor = cursor.saturating_add(1);
                Ok(Step::Continue)
            }
            _ => Err(RejectReason::ChunkTerminatorInvalid),
        }
    }

    /// Step 2: chunk-ext bytes after a `;`, one byte at a time so the small
    /// grammar (top level vs. quoted-string, escapes) resumes correctly
    /// across a split. See `ExtMode`.
    fn step_ext(&mut self, buf: &[u8], cursor: &mut usize) -> Result<Step, RejectReason> {
        let region = buf.get(*cursor..).unwrap_or(&[]);
        for (i, &b) in region.iter().enumerate() {
            self.ext_bytes = self.ext_bytes.saturating_add(1);
            if self.ext_bytes > self.limits.max_chunk_ext_bytes {
                return Err(RejectReason::ChunkExtTooLong);
            }
            match (self.ext_mode, b) {
                (ExtMode::AfterSemicolon, b';' | b'\r')
                | (ExtMode::Quoted | ExtMode::QuotedEscaped, b'\r' | b'\n') => {
                    return Err(RejectReason::ChunkExtInvalid);
                }
                (ExtMode::AfterSemicolon | ExtMode::TopLevel, b'"') => {
                    self.ext_mode = ExtMode::Quoted;
                }
                (ExtMode::AfterSemicolon, other) => {
                    if !is_ext_top_byte(other) {
                        return Err(RejectReason::ChunkExtInvalid);
                    }
                    self.ext_mode = ExtMode::TopLevel;
                }
                (ExtMode::TopLevel, b'\r') => {
                    *cursor = cursor.saturating_add(i).saturating_add(1);
                    self.state = State::SizeCrlf;
                    return Ok(Step::Continue);
                }
                (ExtMode::TopLevel, b';') => self.ext_mode = ExtMode::AfterSemicolon,
                (ExtMode::TopLevel, other) => {
                    if !is_ext_top_byte(other) {
                        return Err(RejectReason::ChunkExtInvalid);
                    }
                }
                (ExtMode::Quoted, b'\\') => self.ext_mode = ExtMode::QuotedEscaped,
                (ExtMode::Quoted, b'"') => self.ext_mode = ExtMode::TopLevel,
                (ExtMode::Quoted, _) => {}
                (ExtMode::QuotedEscaped, _) => self.ext_mode = ExtMode::Quoted,
            }
        }
        *cursor = cursor.saturating_add(region.len());
        Ok(Step::NeedMore)
    }

    /// Step 3: the `\n` ending the size line (the `\r` was already consumed
    /// by `Size` or `Ext`). On success, either starts the trailer section
    /// (terminal chunk) or resets for the next chunk's data.
    fn step_size_crlf(
        &mut self,
        buf: &[u8],
        cursor: &mut usize,
        arena: &mut BytesMut,
    ) -> Result<Step, RejectReason> {
        let Some(&b) = buf.get(*cursor) else {
            return Ok(Step::NeedMore);
        };
        if b != b'\n' {
            return Err(RejectReason::ChunkTerminatorInvalid);
        }
        *cursor = cursor.saturating_add(1);
        if self.remaining == 0 {
            self.trailer_builder = Some(FieldSectionBuilder::new(arena, &self.limits));
            self.trailer_budget = HeaderListBudget::new(&self.limits);
            self.state = State::Trailers;
        } else {
            self.ext_bytes = 0;
            self.size_digits = 0;
            self.state = State::Data;
        }
        Ok(Step::Continue)
    }

    /// Step 4: delivering `remaining` data bytes. Computes `n` from
    /// `remaining` and the available length only; never indexes `buf`.
    fn step_data(&mut self, buf: &[u8], cursor: &mut usize) -> Option<ChunkedEvent> {
        // `min` rather than a hand-written `if remaining < available` branch:
        // at the exact boundary (remaining == available) the two branches of
        // that comparison compute the identical value anyway (try_from of a
        // u64 already known to fit in usize always succeeds), so a `<` vs
        // `<=` mutant there is provably unobservable. Writing the formula
        // this way removes that equivalent-mutant surface instead of leaving
        // it for a comment to excuse.
        let available = buf.len().saturating_sub(*cursor);
        let n = usize::try_from(self.remaining.min(available as u64)).unwrap_or(available);
        if n == 0 {
            return None;
        }
        let offset = *cursor;
        self.remaining = self.remaining.saturating_sub(n as u64);
        self.delivered = self.delivered.saturating_add(n as u64);
        *cursor = cursor.saturating_add(n);
        if self.remaining == 0 {
            self.state = State::DataCrlf;
        }
        Some(ChunkedEvent::Data { offset, len: n })
    }

    /// Step 5: exactly `\r` then `\n` after chunk data. Consumes neither
    /// byte until both are confirmed present, so a split between them needs
    /// no extra state: the caller re-presents the unconsumed `\r` next call.
    fn step_data_crlf(&mut self, buf: &[u8], cursor: &mut usize) -> Result<Step, RejectReason> {
        let region = buf.get(*cursor..).unwrap_or(&[]);
        match region.first() {
            None => Ok(Step::NeedMore),
            Some(b'\r') => match region.get(1) {
                None => Ok(Step::NeedMore),
                Some(b'\n') => {
                    *cursor = cursor.saturating_add(2);
                    self.state = State::Size;
                    Ok(Step::Continue)
                }
                Some(_) => Err(RejectReason::ChunkTerminatorInvalid),
            },
            Some(_) => Err(RejectReason::ChunkTerminatorInvalid),
        }
    }

    /// Step 6: the trailer section, applying exactly the head parser's field
    /// rules to whole CRLF-terminated lines only. May process several lines
    /// within one call; stops the moment a line is incomplete, the section
    /// ends, or an error fires.
    fn step_trailers(
        &mut self,
        buf: &[u8],
        cursor: &mut usize,
        arena: &mut BytesMut,
    ) -> Result<Step, RejectReason> {
        loop {
            let region = buf.get(*cursor..).unwrap_or(&[]);
            // TRAILER_SEARCH_CAP_SLACK bytes of margin beyond max_field_line_bytes: the
            // issue's own text specifies "+2" here, sized only for the terminating CRLF.
            // That is not enough room to ever find the CRLF of a line whose name plus
            // TRIMMED value sits exactly at the cap (the legal maximum), because the raw
            // wire bytes also include the colon and RFC 9110 OWS around the value, which
            // this decoder's own line_len check (matching h1-head-parser's identical
            // formula) does not count. A "+2" window can therefore never see the CRLF of
            // a maximal-length field sent with even a single space after the colon (the
            // overwhelmingly common wire form), and a decoder that cannot see its own
            // legal maximum's terminator is wrong, not merely strict: see the filed
            // defect against this issue. The slack below absorbs the colon and generous
            // OWS while the search remains `O(max_field_line_bytes)`, not unbounded.
            let search_cap = (self.limits.max_field_line_bytes as usize)
                .saturating_add(TRAILER_SEARCH_CAP_SLACK);
            let window_len = region.len().min(search_cap);
            let window = region.get(..window_len).unwrap_or(&[]);

            // Charge the search, not the consumed bytes: this is what bounds
            // the re-scan a drip-feeding peer can buy across many `decode`
            // calls that each re-search the same still-incomplete line. The
            // charge is the number of bytes ACTUALLY searched to reach a
            // verdict on this call, not the whole capped window: when
            // `memchr::memmem::find` fails, every byte of `window` was
            // genuinely inspected, but when it succeeds at `rel`, only
            // `rel + 2` bytes were needed. Charging `window.len()`
            // unconditionally (the earlier version of this code) overcounts
            // by the untouched remainder of the window on every line, which
            // turns one `decode` call that parses N legitimate short
            // trailer lines out of one large buffer (the ordinary
            // multi-field case, not a drip-feed) into an O(N * window)
            // charge instead of the O(sum of line lengths) it should be,
            // risking `FieldLineTooLong` on traffic nowhere near either
            // real limit.
            let Some(rel) = memchr::memmem::find(window, b"\r\n") else {
                self.trailer_scan = self.trailer_scan.saturating_add(window.len() as u64);
                if self.trailer_scan > HeadScanBudget::MAX_BYTES {
                    return Err(RejectReason::FieldLineTooLong);
                }
                if region.len() > search_cap {
                    return Err(RejectReason::FieldLineTooLong);
                }
                return Ok(Step::NeedMore);
            };
            self.trailer_scan = self
                .trailer_scan
                .saturating_add(rel.saturating_add(2) as u64);
            if self.trailer_scan > HeadScanBudget::MAX_BYTES {
                return Err(RejectReason::FieldLineTooLong);
            }

            let line = window.get(..rel).unwrap_or(&[]);
            let line_start = *cursor;
            let line_end = line_start.saturating_add(rel);

            if line.is_empty() {
                let Some(builder) = self.trailer_builder.take() else {
                    return Err(RejectReason::ChunkTerminatorInvalid);
                };
                self.trailers = Some(builder.finish(arena));
                self.state = State::Done;
                *cursor = line_end.saturating_add(2);
                return Ok(Step::Done);
            }

            if matches!(line.first(), Some(&b' ' | &b'\t')) {
                return Err(RejectReason::ObsFold);
            }
            if let Some(bad) = line.iter().position(|&b| b == b'\r' || b == b'\n') {
                return Err(if line.get(bad) == Some(&b'\r') {
                    RejectReason::BareCr
                } else {
                    RejectReason::BareLf
                });
            }

            let Some(colon) = line.iter().position(|&b| b == b':') else {
                return Err(RejectReason::RequestLineMalformed);
            };
            if colon == 0 {
                return Err(RejectReason::FieldNameEmpty);
            }
            if matches!(line.get(colon.saturating_sub(1)), Some(&b' ' | &b'\t')) {
                return Err(RejectReason::WhitespaceBeforeColon);
            }

            let name_raw = line.get(..colon).unwrap_or(&[]);
            let value_raw = line.get(colon.saturating_add(1)..).unwrap_or(&[]);
            let value_trimmed = field::trim_ows(value_raw);

            let line_len = name_raw.len().saturating_add(value_trimmed.len());
            if line_len > self.limits.max_field_line_bytes as usize {
                return Err(RejectReason::FieldLineTooLong);
            }
            self.trailer_budget
                .charge(name_raw.len(), value_trimmed.len())?;

            let Some(builder) = self.trailer_builder.as_mut() else {
                return Err(RejectReason::ChunkTerminatorInvalid);
            };
            builder.push_normalized(
                arena,
                name_raw,
                self.underscores,
                value_trimmed,
                WireVersion::Http11,
            )?;

            if trailer_denied(classify_trailer_name(name_raw, self.underscores)) {
                return Err(RejectReason::TrailerFieldForbidden);
            }

            *cursor = line_end.saturating_add(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::section::FieldFlags;
    use proptest::strategy::Strategy;

    /// The final outcome of driving a decoder to completion (or failure),
    /// for use in the corpus table below. The `Data` bytes collected along
    /// the way are compared separately, so this carries no data of its own.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Outcome {
        NeedMore,
        Done { consumed: usize },
        Err(RejectReason),
    }

    fn new_decoder() -> ChunkedDecoder {
        ChunkedDecoder::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject)
    }

    /// Feeds all of `input` to `decoder` in one buffer, looping `decode`
    /// calls (since `decode` returns after every event) until `Done`, an
    /// error, or a `NeedMore` that made no progress. Returns the
    /// concatenated `Data` bytes and the final outcome (`Done` or `Err`), or
    /// `NeedMore` if the whole input was consumed without either.
    ///
    /// `arena` is declared ONCE, outside the loop, and reused for every
    /// `decode` call: `decode`'s own documented precondition (issue #658)
    /// is that `arena` is the SAME growing buffer across the whole body,
    /// not a fresh one per call. A fresh arena per call still passes every
    /// assertion this function's callers make on `Data` bytes and the
    /// final `Outcome`, because those never depend on the arena; only a
    /// caller that reads `decoder.trailers()` back afterward would notice
    /// the corruption, which is exactly why the earlier version of this
    /// helper (one `BytesMut::new()` per call) hid the bug this issue
    /// reports instead of catching it.
    fn drive(decoder: &mut ChunkedDecoder, input: &[u8]) -> (Vec<u8>, Outcome) {
        let mut pos = 0usize;
        let mut data = Vec::new();
        let mut arena = BytesMut::new();
        loop {
            let buf = input.get(pos..).unwrap_or(&[]);
            match decoder.decode(buf, &mut arena) {
                Ok(ChunkedEvent::Data { offset, len }) => {
                    let slice = buf.get(offset..offset.saturating_add(len)).unwrap_or(&[]);
                    data.extend_from_slice(slice);
                    pos = pos.saturating_add(decoder.consumed_this_call());
                }
                Ok(ChunkedEvent::NeedMore) => {
                    let consumed = decoder.consumed_this_call();
                    if consumed == 0 {
                        return (data, Outcome::NeedMore);
                    }
                    pos = pos.saturating_add(consumed);
                }
                Ok(ChunkedEvent::Done { consumed }) => {
                    // `consumed` is local to THIS call's own `buf` (which
                    // starts at `pos`, not at the message start), per
                    // ChunkedEvent::Done's own contract; `pos + consumed` is
                    // the cumulative offset from the message's first byte,
                    // which is what every corpus row's expected `consumed`
                    // value actually names.
                    return (
                        data,
                        Outcome::Done {
                            consumed: pos.saturating_add(consumed),
                        },
                    );
                }
                Err(reason) => return (data, Outcome::Err(reason)),
            }
        }
    }

    /// As `drive`, but feeds `input` in pieces of at most `split` bytes at a
    /// time: each round reveals up to `split` MORE bytes than the decoder has
    /// already consumed, mimicking a real read loop that appends whatever
    /// arrived since the last wakeup.
    ///
    /// `arena` is declared ONCE, outside the loop; see `drive`'s doc comment
    /// for why (issue #658).
    fn drive_split(decoder: &mut ChunkedDecoder, input: &[u8], split: usize) -> (Vec<u8>, Outcome) {
        let mut pos = 0usize;
        let mut revealed = 0usize;
        let mut data = Vec::new();
        let mut arena = BytesMut::new();
        loop {
            if revealed < input.len() {
                revealed = revealed.saturating_add(split).min(input.len());
            }
            let buf = input.get(pos..revealed).unwrap_or(&[]);
            match decoder.decode(buf, &mut arena) {
                Ok(ChunkedEvent::Data { offset, len }) => {
                    let slice = buf.get(offset..offset.saturating_add(len)).unwrap_or(&[]);
                    data.extend_from_slice(slice);
                    pos = pos.saturating_add(decoder.consumed_this_call());
                }
                Ok(ChunkedEvent::NeedMore) => {
                    let consumed = decoder.consumed_this_call();
                    pos = pos.saturating_add(consumed);
                    if consumed == 0 && revealed >= input.len() {
                        return (data, Outcome::NeedMore);
                    }
                }
                Ok(ChunkedEvent::Done { consumed }) => {
                    return (
                        data,
                        Outcome::Done {
                            consumed: pos.saturating_add(consumed),
                        },
                    );
                }
                Err(reason) => return (data, Outcome::Err(reason)),
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table of edge cases 1 through 44 the issue names by number, plus the \
                  closure that checks each row; splitting the table would break the 1:1 mapping \
                  to that numbered list, matching h1::parser::tests::corpus_table's own precedent"
    )]
    #[test]
    fn corpus_table() {
        use RejectReason::{
            BareCr, ChunkExtInvalid, ChunkExtTooLong, ChunkSizeInvalid, ChunkSizeOverflow,
            ChunkTerminatorInvalid, FieldCountExceeded, FieldNameEmpty, FieldNameUnderscore,
            HeaderListTooLarge, ObsFold, TrailerFieldForbidden, WhitespaceBeforeColon,
        };

        let cases: &[(&[u8], Outcome)] = &[
            // 1.
            (b"1\r\nA\r\n0\r\n\r\n", Outcome::Done { consumed: 11 }),
            // 2.
            (b"0\r\n\r\n", Outcome::Done { consumed: 5 }),
            // 3.
            (b"", Outcome::NeedMore),
            // 4.
            (b"1", Outcome::NeedMore),
            // 5.
            (b"1\r\n", Outcome::NeedMore),
            // 7.
            (
                b"1;ext=value\r\nA\r\n0\r\n\r\n",
                Outcome::Done { consumed: 21 },
            ),
            // 8.
            (
                b"1;ext=\"quoted;with;semis\"\r\nA\r\n0\r\n\r\n",
                Outcome::Done { consumed: 35 },
            ),
            // 9.
            (
                b"1;ext=\"unterminated\r\nA\r\n0\r\n\r\n",
                Outcome::Err(ChunkExtInvalid),
            ),
            // 10.
            (b"1;\r\nA\r\n0\r\n\r\n", Outcome::Err(ChunkExtInvalid)),
            // 11.
            (b"1;;a=b\r\nA\r\n0\r\n\r\n", Outcome::Err(ChunkExtInvalid)),
            // 13.
            (b"+1\r\nA\r\n0\r\n\r\n", Outcome::Err(ChunkSizeInvalid)),
            // 14.
            (b" 1\r\nA\r\n0\r\n\r\n", Outcome::Err(ChunkSizeInvalid)),
            // 15.
            (b"1 \r\nA\r\n0\r\n\r\n", Outcome::Err(ChunkSizeInvalid)),
            // 16.
            (b"0x1\r\nA\r\n0\r\n\r\n", Outcome::Err(ChunkSizeInvalid)),
            // 17.
            (b"\r\n", Outcome::Err(ChunkSizeInvalid)),
            // 18: 17 hex digits.
            (b"FFFFFFFFFFFFFFFFF\r\n", Outcome::Err(ChunkSizeOverflow)),
            // 20: bare CR in the size line.
            (b"1\rA\r\n0\r\n\r\n", Outcome::Err(ChunkTerminatorInvalid)),
            // 21: bare LF ending the size line.
            (b"1\nA\r\n0\r\n\r\n", Outcome::Err(ChunkTerminatorInvalid)),
            // 22: bare LF after chunk data.
            (b"1\r\nA\n0\r\n\r\n", Outcome::Err(ChunkTerminatorInvalid)),
            // 23: CR not followed by LF after data.
            (b"1\r\nA\rX0\r\n\r\n", Outcome::Err(ChunkTerminatorInvalid)),
            // 24: two data bytes for a size of 1.
            (
                b"1\r\nAB\r\n0\r\n\r\n",
                Outcome::Err(ChunkTerminatorInvalid),
            ),
            // 25.
            (
                b"0\r\nContent-Length: 10\r\n\r\n",
                Outcome::Err(TrailerFieldForbidden),
            ),
            // 26.
            (
                b"0\r\nHost: evil\r\n\r\n",
                Outcome::Err(TrailerFieldForbidden),
            ),
            // 27.
            (
                b"0\r\nAuthorization: Bearer x\r\n\r\n",
                Outcome::Err(TrailerFieldForbidden),
            ),
            // 28.
            (
                b"0\r\nCookie: a=b\r\n\r\n",
                Outcome::Err(TrailerFieldForbidden),
            ),
            // 29.
            (
                b"0\r\nTrailer: x\r\n\r\n",
                Outcome::Err(TrailerFieldForbidden),
            ),
            // 30.
            (
                b"0\r\nTransfer-Encoding: chunked\r\n\r\n",
                Outcome::Err(TrailerFieldForbidden),
            ),
            // 31: OWS on both sides is trimmed before the push.
            (
                b"0\r\nX-Checksum: abc\r\n\r\n",
                Outcome::Done { consumed: 22 },
            ),
            (
                b"0\r\nX-Checksum:   abc  \r\n\r\n",
                Outcome::Done { consumed: 26 },
            ),
            // 32.
            (
                b"0\r\nx_checksum: abc\r\n\r\n",
                Outcome::Err(FieldNameUnderscore),
            ),
            // 33.
            (b"0\r\n: v\r\n\r\n", Outcome::Err(FieldNameEmpty)),
            // 34.
            (b"0\r\nX : v\r\n\r\n", Outcome::Err(WhitespaceBeforeColon)),
            // 35.
            (b"0\r\n X: v\r\n\r\n", Outcome::Err(ObsFold)),
            // 36.
            (b"0\r\nX: v\r\r\n\r\n", Outcome::Err(BareCr)),
            // 37.
            (b"0\r\n\r\nGARBAGE", Outcome::Done { consumed: 5 }),
        ];

        for (input, expected) in cases {
            let mut decoder = new_decoder();
            let (data, outcome) = drive(&mut decoder, input);
            assert_eq!(&outcome, expected, "{input:?}: data so far {data:?}");
        }

        // 1, restated to check the delivered data byte and the empty trailers.
        let mut basic_decoder = new_decoder();
        let (basic_body, basic_outcome) = drive(&mut basic_decoder, b"1\r\nA\r\n0\r\n\r\n");
        assert_eq!(basic_body, b"A");
        assert_eq!(basic_outcome, Outcome::Done { consumed: 11 });
        assert!(basic_decoder.trailers().is_some_and(FieldSection::is_empty));

        // 2, restated to check empty trailers.
        let mut empty_decoder = new_decoder();
        let (empty_body, empty_outcome) = drive(&mut empty_decoder, b"0\r\n\r\n");
        assert!(empty_body.is_empty());
        assert_eq!(empty_outcome, Outcome::Done { consumed: 5 });
        assert!(empty_decoder.trailers().is_some_and(FieldSection::is_empty));

        // 6.
        let mut partial_decoder = new_decoder();
        let mut partial_arena = BytesMut::new();
        match partial_decoder.decode(b"1\r\nA", &mut partial_arena) {
            Ok(ChunkedEvent::Data { offset, len }) => {
                assert_eq!((offset, len), (3, 1));
                assert_eq!(partial_decoder.consumed_this_call(), 4);
            }
            other => panic!("case 6 first call: expected Data, got {other:?}"),
        }
        assert_eq!(
            partial_decoder.decode(b"", &mut partial_arena),
            Ok(ChunkedEvent::NeedMore)
        );

        // 12: `1;ext=` followed by 300 bytes, over max_chunk_ext_bytes (256).
        let mut ext_too_long = Vec::from(&b"1;ext="[..]);
        ext_too_long.extend(std::iter::repeat_n(b'a', 300));
        ext_too_long.extend_from_slice(b"\r\nA\r\n0\r\n\r\n");
        let mut ext_cap_decoder = new_decoder();
        assert_eq!(
            drive(&mut ext_cap_decoder, &ext_too_long).1,
            Outcome::Err(ChunkExtTooLong)
        );

        // 19: 16 hex digits (u64::MAX) is an accepted SIZE; the body never
        // arrives, which is a body-size-limit problem, not a framing one.
        let mut huge_size_decoder = new_decoder();
        let mut huge_size_arena = BytesMut::new();
        assert_eq!(
            huge_size_decoder.decode(b"FFFFFFFFFFFFFFFF\r\n", &mut huge_size_arena),
            Ok(ChunkedEvent::NeedMore)
        );
        assert_eq!(huge_size_decoder.consumed_this_call(), 18);

        // 38: 101 trailer fields.
        let mut too_many_fields = Vec::from(&b"0\r\n"[..]);
        for i in 0..101 {
            too_many_fields.extend_from_slice(format!("x-{i}: v\r\n").as_bytes());
        }
        too_many_fields.extend_from_slice(b"\r\n");
        let mut field_count_decoder = new_decoder();
        assert_eq!(
            drive(&mut field_count_decoder, &too_many_fields).1,
            Outcome::Err(FieldCountExceeded)
        );

        // 39: a trailer section exceeding max_header_list_bytes (65536), via
        // 100 fields of name(4)+value(1000)+32 = 1036 bytes each.
        let mut over_list = Vec::from(&b"0\r\n"[..]);
        for i in 0..100 {
            let value = "v".repeat(1000);
            over_list.extend_from_slice(format!("x{i:03}: {value}\r\n").as_bytes());
        }
        over_list.extend_from_slice(b"\r\n");
        let mut list_bytes_decoder = new_decoder();
        assert_eq!(
            drive(&mut list_bytes_decoder, &over_list).1,
            Outcome::Err(HeaderListTooLarge)
        );

        // 40: a 1 MiB single chunk delivered in 64 KiB pieces.
        let one_mib = 1024 * 1024;
        let mut large_body_decoder = new_decoder();
        let mut large_body_wire = format!("{one_mib:x}\r\n").into_bytes();
        large_body_wire.extend(std::iter::repeat_n(b'x', one_mib));
        large_body_wire.extend_from_slice(b"\r\n0\r\n\r\n");
        let (large_body, large_body_outcome) =
            drive_split(&mut large_body_decoder, &large_body_wire, 64 * 1024);
        assert_eq!(large_body.len(), one_mib);
        assert!(matches!(large_body_outcome, Outcome::Done { .. }));

        // 41: the case-1 input fed one byte at a time.
        let mut byte_at_a_time_decoder = new_decoder();
        let (drip_body, drip_outcome) =
            drive_split(&mut byte_at_a_time_decoder, b"1\r\nA\r\n0\r\n\r\n", 1);
        assert_eq!(drip_body, b"A");
        assert_eq!(drip_outcome, Outcome::Done { consumed: 11 });

        // 42: two Data events of 1 byte each.
        let mut two_chunk_decoder = new_decoder();
        let (two_chunk_body, two_chunk_outcome) =
            drive(&mut two_chunk_decoder, b"1\r\nA\r\n1\r\nB\r\n0\r\n\r\n");
        assert_eq!(two_chunk_body, b"AB");
        assert!(matches!(two_chunk_outcome, Outcome::Done { .. }));

        // 43: calling decode after Done is idempotent.
        let mut idempotent_decoder = new_decoder();
        let mut idempotent_arena = BytesMut::new();
        assert_eq!(
            drive(&mut idempotent_decoder, b"0\r\n\r\n").1,
            Outcome::Done { consumed: 5 }
        );
        assert!(idempotent_decoder.is_done());
        assert_eq!(
            idempotent_decoder.decode(b"whatever", &mut idempotent_arena),
            Ok(ChunkedEvent::Done { consumed: 0 })
        );
        assert_eq!(idempotent_decoder.consumed_this_call(), 0);
        assert_eq!(
            idempotent_decoder.decode(b"", &mut idempotent_arena),
            Ok(ChunkedEvent::Done { consumed: 0 })
        );

        // 44: non-UTF-8 body bytes are never inspected.
        let mut binary_decoder = new_decoder();
        let mut binary_wire = Vec::from(&b"4\r\n"[..]);
        binary_wire.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x80]);
        binary_wire.extend_from_slice(b"\r\n0\r\n\r\n");
        let (binary_body, binary_outcome) = drive(&mut binary_decoder, &binary_wire);
        assert_eq!(binary_body, vec![0xFF, 0xFE, 0x00, 0x80]);
        assert!(matches!(binary_outcome, Outcome::Done { .. }));

        // The trailer-field-split-across-two-calls row named by the issue's
        // own test 1 description: the first call must return NeedMore having
        // consumed only the bytes through "0\r\n", and the second must
        // complete with the field readable from trailers().
        let mut d_split_trailer = new_decoder();
        let mut arena_st = BytesMut::new();
        match d_split_trailer.decode(b"0\r\nx-check", &mut arena_st) {
            Ok(ChunkedEvent::NeedMore) => {
                assert_eq!(d_split_trailer.consumed_this_call(), 3);
            }
            other => panic!("expected NeedMore consuming only \"0\\r\\n\", got {other:?}"),
        }
        // The caller re-presents whatever the first call did NOT consume
        // ("x-check", 7 bytes) followed by whatever newly arrived.
        match d_split_trailer.decode(b"x-checksum: abc\r\n\r\n", &mut arena_st) {
            Ok(ChunkedEvent::Done { consumed }) => {
                assert_eq!(consumed, 19);
            }
            other => panic!("expected Done, got {other:?}"),
        }
        assert_eq!(
            d_split_trailer
                .trailers()
                .and_then(|t| t.get_unique(b"x-checksum").ok().flatten()),
            Some(&b"abc"[..])
        );
    }

    /// One trailer field as owned bytes plus flags, for comparing the
    /// `FieldSection`s two DIFFERENT decoders (built into two different
    /// arenas) produced for what should be the same trailer section. `None`
    /// (no trailer section yet, or the message errored before one existed)
    /// snapshots as an empty vec, same as an empty-but-present section:
    /// `split_invariance` and `prop_split_invariance` already assert the
    /// two decoders' `Outcome`s agree with each other before ever comparing
    /// this, so a real "one has a section and the other does not"
    /// divergence is caught there first.
    fn trailer_snapshot(section: Option<&FieldSection>) -> Vec<(Vec<u8>, Vec<u8>, FieldFlags)> {
        section.map_or_else(Vec::new, |t| {
            t.iter()
                .map(|(name, value, flags)| (name.to_vec(), value.to_vec(), flags))
                .collect()
        })
    }

    #[test]
    fn split_invariance() {
        let inputs: [&[u8]; 9] = [
            b"1\r\nA\r\n0\r\n\r\n",
            b"1;ext=value\r\nA\r\n0\r\n\r\n",
            b"1\r\nA\r\n1\r\nB\r\n0\r\n\r\n",
            b"0\r\n\r\n",
            b"0\r\nX-Checksum: abc\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
            b"1\r\nA\r\n0\r\nX-A: 1\r\nX-B: 2\r\n\r\n",
            b"3\r\nfoo\r\n2\r\nba\r\n0\r\n\r\n",
            // A quoted-string chunk-ext containing an escaped quote: the
            // sharpest ExtMode::QuotedEscaped resumption case, split at
            // every byte boundary including immediately after the `\`.
            b"1;e=\"a\\\"z\"\r\nA\r\n0\r\n\r\n",
        ];

        for input in inputs {
            let mut whole_decoder = new_decoder();
            let (whole_data, whole_outcome) = drive(&mut whole_decoder, input);
            let whole_trailers = trailer_snapshot(whole_decoder.trailers());

            for split in 1..=input.len() {
                let mut decoder = new_decoder();
                let (data, outcome) = drive_split(&mut decoder, input, split);
                assert_eq!(
                    data, whole_data,
                    "input {input:?} split {split}: Data bytes disagreed"
                );
                assert_eq!(
                    outcome, whole_outcome,
                    "input {input:?} split {split}: final outcome disagreed"
                );
                // Issue #658: the headline resumption invariant above was
                // being checked for chunk data only. A decoder that
                // silently corrupts the trailer section (recording offsets
                // against the wrong arena) would still pass both asserts
                // above unchanged, because neither `Data` bytes nor
                // `consumed` depends on the arena at all; only reading
                // `trailers()` back exposes it.
                assert_eq!(
                    trailer_snapshot(decoder.trailers()),
                    whole_trailers,
                    "input {input:?} split {split}: trailer section disagreed"
                );
            }
        }
    }

    #[test]
    fn size_grammar() {
        use RejectReason::{ChunkSizeInvalid, ChunkSizeOverflow};
        let cases: &[(&[u8], RejectReason)] = &[
            (b"+1\r\nA\r\n0\r\n\r\n", ChunkSizeInvalid),
            (b" 1\r\nA\r\n0\r\n\r\n", ChunkSizeInvalid),
            (b"1 \r\nA\r\n0\r\n\r\n", ChunkSizeInvalid),
            (b"0x1\r\nA\r\n0\r\n\r\n", ChunkSizeInvalid),
            (b"\r\n", ChunkSizeInvalid),
            (b"FFFFFFFFFFFFFFFFF\r\n", ChunkSizeOverflow),
        ];
        for (input, reason) in cases {
            let mut decoder = new_decoder();
            assert_eq!(
                drive(&mut decoder, input).1,
                Outcome::Err(*reason),
                "{input:?}"
            );
        }

        // 19: 16 hex digits (u64::MAX) is accepted as a size.
        let mut decoder = new_decoder();
        let mut arena = BytesMut::new();
        assert_eq!(
            decoder.decode(b"FFFFFFFFFFFFFFFF\r\n", &mut arena),
            Ok(ChunkedEvent::NeedMore)
        );
    }

    #[test]
    fn terminator_strictness() {
        use RejectReason::ChunkTerminatorInvalid;
        let cases: [&[u8]; 5] = [
            b"1\rA\r\n0\r\n\r\n",
            b"1\nA\r\n0\r\n\r\n",
            b"1\r\nA\n0\r\n\r\n",
            b"1\r\nA\rX0\r\n\r\n",
            b"1\r\nAB\r\n0\r\n\r\n",
        ];
        for input in cases {
            let mut decoder = new_decoder();
            assert_eq!(
                drive(&mut decoder, input).1,
                Outcome::Err(ChunkTerminatorInvalid),
                "{input:?}"
            );
        }
    }

    #[test]
    fn ext_grammar() {
        use RejectReason::ChunkExtInvalid;

        let mut ok1 = new_decoder();
        assert_eq!(
            drive(&mut ok1, b"1;ext=value\r\nA\r\n0\r\n\r\n").1,
            Outcome::Done { consumed: 21 }
        );

        let mut ok2 = new_decoder();
        assert_eq!(
            drive(&mut ok2, b"1;ext=\"quoted;with;semis\"\r\nA\r\n0\r\n\r\n").1,
            Outcome::Done { consumed: 35 }
        );

        let bad: [&[u8]; 3] = [
            b"1;ext=\"unterminated\r\nA\r\n0\r\n\r\n",
            b"1;\r\nA\r\n0\r\n\r\n",
            b"1;;a=b\r\nA\r\n0\r\n\r\n",
        ];
        for input in bad {
            let mut decoder = new_decoder();
            assert_eq!(
                drive(&mut decoder, input).1,
                Outcome::Err(ChunkExtInvalid),
                "{input:?}"
            );
        }

        // 12.
        let mut too_long = Vec::from(&b"1;ext="[..]);
        too_long.extend(std::iter::repeat_n(b'a', 300));
        too_long.extend_from_slice(b"\r\nA\r\n0\r\n\r\n");
        let mut decoder = new_decoder();
        assert_eq!(
            drive(&mut decoder, &too_long).1,
            Outcome::Err(RejectReason::ChunkExtTooLong)
        );
    }

    #[test]
    fn trailer_deny_list() {
        assert_eq!(TRAILER_DENIED.len(), 18);

        for denied in TRAILER_DENIED {
            let name = denied.as_bytes();
            let mut wire = Vec::from(&b"0\r\n"[..]);
            wire.extend_from_slice(name);
            wire.extend_from_slice(b": x\r\n\r\n");
            let mut decoder = new_decoder();
            assert_eq!(
                drive(&mut decoder, &wire).1,
                Outcome::Err(RejectReason::TrailerFieldForbidden),
                "{denied:?} ({name:?}) was not refused as a trailer field"
            );
        }

        let mut accepted = new_decoder();
        assert!(matches!(
            drive(&mut accepted, b"0\r\nx-checksum: abc\r\n\r\n").1,
            Outcome::Done { .. }
        ));
    }

    #[test]
    fn trailers_are_not_merged() {
        let mut decoder = new_decoder();
        let (data, outcome) = drive(&mut decoder, b"0\r\nX-Checksum: abc\r\n\r\n");
        assert!(data.is_empty());
        assert!(matches!(outcome, Outcome::Done { .. }));

        let trailers = decoder
            .trailers()
            .expect("trailer section must be present after Done");
        assert_eq!(trailers.get_unique(b"x-checksum"), Ok(Some(&b"abc"[..])));
        assert_eq!(trailers.len(), 1);

        // No method on ChunkedDecoder merges this into any other section:
        // trailers() is the only way to reach it, and it is a plain
        // &FieldSection with no reference back to any header section.
        let _: &FieldSection = trailers;
    }

    #[test]
    fn consumed_is_exact_with_trailing_bytes() {
        let mut decoder = new_decoder();
        let mut arena = BytesMut::new();
        let full = b"0\r\n\r\nGARBAGE";
        match decoder.decode(full, &mut arena) {
            Ok(ChunkedEvent::Done { consumed }) => {
                assert_eq!(consumed, 5);
                assert_eq!(decoder.consumed_this_call(), 5);
                assert_eq!(full.get(consumed..), Some(&b"GARBAGE"[..]));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn trailer_rescan_is_bounded() {
        // 46: a partial trailer line that never terminates, drip-fed one
        // byte per call, must be cut off by the trailer_scan budget rather
        // than loop forever.
        let mut wire = Vec::from(&b"0\r\nx-a: "[..]);
        wire.extend(std::iter::repeat_n(b'v', 4096));
        let mut decoder = new_decoder();
        let mut pos = 0usize;
        let mut revealed = 0usize;
        let mut calls = 0u64;
        // One arena for the whole drive, per decode's documented
        // precondition (issue #658), even though this particular input
        // never reaches a push (the line never completes).
        let mut arena = BytesMut::new();
        let outcome = loop {
            if revealed < wire.len() {
                revealed = revealed.saturating_add(1).min(wire.len());
            }
            let buf = wire.get(pos..revealed).unwrap_or(&[]);
            calls = calls.saturating_add(1);
            match decoder.decode(buf, &mut arena) {
                Ok(ChunkedEvent::NeedMore) => {
                    let consumed = decoder.consumed_this_call();
                    pos = pos.saturating_add(consumed);
                    if consumed == 0 && revealed >= wire.len() {
                        break Outcome::NeedMore;
                    }
                    assert!(
                        calls < 10_000_000,
                        "decoder is looping rather than bounding the re-scan"
                    );
                }
                Ok(ChunkedEvent::Done { consumed }) => break Outcome::Done { consumed },
                Err(reason) => break Outcome::Err(reason),
                Ok(ChunkedEvent::Data { .. }) => {
                    panic!("a trailer-only body must never produce a Data event")
                }
            }
        };
        assert_eq!(outcome, Outcome::Err(RejectReason::FieldLineTooLong));
        // A 4 MiB budget charged roughly 1, 2, 3, ... bytes per call reaches
        // the cap after on the order of sqrt(2 * 4 MiB) ~= 2896 calls; a
        // generous two-sided bound catches both "never bounds it" (would
        // hit the 10,000,000 assert above) and "bounds it far too early"
        // (a single-digit or three-digit call count).
        assert!(
            (1_000..10_000).contains(&calls),
            "expected on the order of a few thousand decode calls before the \
             4 MiB scan budget fires, got {calls}"
        );

        // 47: a normal 8-field trailer section in two calls completes well
        // under the budget.
        let mut normal = Vec::from(&b"0\r\n"[..]);
        for i in 0..8 {
            normal.extend_from_slice(format!("x-{i}: v\r\n").as_bytes());
        }
        normal.extend_from_slice(b"\r\n");
        let mut normal_decoder = new_decoder();
        let split = normal.len().checked_div(2).unwrap_or(1).max(1);
        let (normal_body, normal_outcome) = drive_split(&mut normal_decoder, &normal, split);
        assert!(normal_body.is_empty());
        assert!(matches!(normal_outcome, Outcome::Done { .. }));
    }

    proptest::proptest! {
        #[test]
        fn prop_split_invariance(
            chunks in proptest::collection::vec(
                (
                    1_usize..=32,
                    // Issue #658 SHOULD_FIX: a bare token name (the original
                    // generator) never exercises ExtMode::Quoted or
                    // ::QuotedEscaped, so a split landing inside a
                    // quoted-string chunk-ext, including immediately after
                    // an escaping `\`, was never generated. The second and
                    // third arms add a quoted value with an embedded `;`
                    // (legal only because quoting suspends its delimiter
                    // meaning) and an escaped `"` inside the quotes.
                    proptest::option::of(proptest::prop_oneof![
                        "[a-z]{1,8}",
                        ("[a-z]{1,4}", "[a-z]{1,4}")
                            .prop_map(|(n, v)| format!("{n}=\"{v};z\"")),
                        "[a-z]{1,4}".prop_map(|n| format!("{n}=\"a\\\"z\"")),
                    ]),
                ),
                1..=8,
            ),
            trailer_fields in proptest::collection::vec(
                ("[a-z]{1,8}", "[a-z]{0,8}"),
                0..=4,
            ),
            split_sizes in proptest::collection::vec(1_usize..=16, 1..=16),
        ) {
            let mut wire = Vec::new();
            let mut expected_body = Vec::new();
            for (len, ext) in &chunks {
                let bytes: Vec<u8> = (0..*len)
                    .map(|i| {
                        let offset = u8::try_from(i.checked_rem(26).unwrap_or(0)).unwrap_or(0);
                        b'a'.wrapping_add(offset)
                    })
                    .collect();
                wire.extend_from_slice(format!("{len:x}").as_bytes());
                if let Some(ext_name) = ext {
                    wire.extend_from_slice(b";");
                    wire.extend_from_slice(ext_name.as_bytes());
                }
                wire.extend_from_slice(b"\r\n");
                wire.extend_from_slice(&bytes);
                wire.extend_from_slice(b"\r\n");
                expected_body.extend_from_slice(&bytes);
            }
            wire.extend_from_slice(b"0\r\n");
            for (name, value) in &trailer_fields {
                wire.extend_from_slice(format!("x-{name}: {value}\r\n").as_bytes());
            }
            wire.extend_from_slice(b"\r\n");

            let mut whole_decoder = new_decoder();
            let (whole_data, whole_outcome) = drive(&mut whole_decoder, &wire);
            assert_eq!(whole_data, expected_body);
            assert_eq!(whole_outcome, Outcome::Done { consumed: wire.len() });
            let whole_trailers = trailer_snapshot(whole_decoder.trailers());

            let mut cycle = split_sizes.iter().copied().cycle();
            let mut decoder = new_decoder();
            let mut pos = 0usize;
            let mut revealed = 0usize;
            let mut data = Vec::new();
            // One arena for the whole drive; see drive's doc comment
            // (issue #658).
            let mut arena = BytesMut::new();
            let outcome = loop {
                if revealed < wire.len() {
                    let step = cycle.next().unwrap_or(1);
                    revealed = revealed.saturating_add(step).min(wire.len());
                }
                let buf = wire.get(pos..revealed).unwrap_or(&[]);
                match decoder.decode(buf, &mut arena) {
                    Ok(ChunkedEvent::Data { offset, len }) => {
                        let slice = buf.get(offset..offset.saturating_add(len)).unwrap_or(&[]);
                        data.extend_from_slice(slice);
                        pos = pos.saturating_add(decoder.consumed_this_call());
                    }
                    Ok(ChunkedEvent::NeedMore) => {
                        let consumed = decoder.consumed_this_call();
                        pos = pos.saturating_add(consumed);
                        if consumed == 0 && revealed >= wire.len() {
                            break Outcome::NeedMore;
                        }
                    }
                    Ok(ChunkedEvent::Done { consumed }) => {
                        break Outcome::Done {
                            consumed: pos.saturating_add(consumed),
                        };
                    }
                    Err(reason) => break Outcome::Err(reason),
                }
            };
            assert_eq!(data, expected_body);
            assert_eq!(outcome, Outcome::Done { consumed: wire.len() });
            // Issue #658: prove the resumption property for the trailer
            // section too, not only for chunk data (see split_invariance's
            // identical comment).
            assert_eq!(trailer_snapshot(decoder.trailers()), whole_trailers);
        }
    }

    /// Acceptance criterion: the decoder never reads chunk data. A 1 MiB
    /// payload of `0xFF` bytes, which is not valid anywhere in the framing
    /// grammar (not a hex digit, not a valid CRLF byte, not a valid
    /// chunk-ext byte), must decode successfully: it cannot if any framing
    /// rule looked at a payload byte instead of trusting `remaining`.
    #[test]
    fn chunk_data_bytes_are_never_inspected() {
        let one_mib = 1024 * 1024;
        let mut wire = format!("{one_mib:x}\r\n").into_bytes();
        wire.extend(std::iter::repeat_n(0xFFu8, one_mib));
        wire.extend_from_slice(b"\r\n0\r\n\r\n");

        let mut decoder = new_decoder();
        let (data, outcome) = drive(&mut decoder, &wire);
        assert_eq!(data.len(), one_mib);
        assert!(data.iter().all(|&b| b == 0xFF));
        assert!(matches!(outcome, Outcome::Done { .. }));
    }

    // ---------- mutation-closing tests (cargo mutants -j 1, whole-file run) ----------
    //
    // A first `cargo mutants -j 1 --file src/h1/chunked.rs` pass on the tests above
    // found 15 of 76 mutants missed. Every test below is named for, and closes,
    // exactly one of them; see each test's own comment for the specific mutant.

    /// `is_ext_top_byte` accepts SP and HTAB, and refuses a byte outside
    /// `tchar`/`=`/SP/HTAB. Closes four missed mutants at that function: the
    /// whole body collapsed to `true`, the `||` joining the SP and HTAB
    /// checks flipped to `&&` (which silently makes both unreachable, since
    /// a byte can never equal both at once), and each of those two `==`
    /// checks flipped to `!=`. None of the other ext tests ever exercise a
    /// literal SP, a literal HTAB, or a byte outside the accepted classes at
    /// the top level of an extension, so all four survived until this test.
    #[test]
    fn ext_top_level_accepts_ows_and_refuses_other_bytes() {
        let mut with_space = new_decoder();
        assert!(matches!(
            drive(&mut with_space, b"1;ext=a b\r\nA\r\n0\r\n\r\n").1,
            Outcome::Done { .. }
        ));

        let mut with_tab = new_decoder();
        assert!(matches!(
            drive(&mut with_tab, b"1;ext=a\tb\r\nA\r\n0\r\n\r\n").1,
            Outcome::Done { .. }
        ));

        // NUL: not a tchar, not '=', not SP, not HTAB, not ';' or '"'.
        let mut with_nul = new_decoder();
        assert_eq!(
            drive(&mut with_nul, b"1;ext=a\0b\r\nA\r\n0\r\n\r\n").1,
            Outcome::Err(RejectReason::ChunkExtInvalid)
        );
    }

    /// `delivered()` reports the true cumulative total, not a constant.
    /// Closes two missed mutants (`delivered` replaced with `0` and with
    /// `1`): no earlier test ever asserted on `delivered()`'s own return
    /// value for an input whose body is neither 0 nor 1 byte.
    #[test]
    fn delivered_tracks_the_true_cumulative_total() {
        let mut decoder = new_decoder();
        assert_eq!(decoder.delivered(), 0);

        // decode() returns after the FIRST Data event ("foo", 3 bytes), so
        // delivered() must already read 3 there, before the second chunk
        // ("ba") has even been reached.
        let mut arena = BytesMut::new();
        assert_eq!(
            decoder.decode(b"3\r\nfoo\r\n2\r\nba\r\n0\r\n\r\n", &mut arena),
            Ok(ChunkedEvent::Data { offset: 3, len: 3 })
        );
        assert_eq!(decoder.delivered(), 3);

        // Re-present the unconsumed remainder (the caller's contract) to
        // reach the second chunk and the final total.
        let full: &[u8] = b"3\r\nfoo\r\n2\r\nba\r\n0\r\n\r\n";
        let remainder = full.get(decoder.consumed_this_call()..).unwrap_or(&[]);
        let (data, outcome) = drive(&mut decoder, remainder);
        assert_eq!(data, b"ba");
        assert!(matches!(outcome, Outcome::Done { .. }));
        assert_eq!(decoder.delivered(), 5);
    }

    /// `is_done()` is false before completion, not a constant `true`.
    /// Closes a missed mutant (`is_done` replaced with `true`): every
    /// earlier test that called `is_done()` did so only AFTER driving a
    /// decoder to `Done`.
    #[test]
    fn is_done_is_false_before_completion() {
        let decoder = new_decoder();
        assert!(!decoder.is_done());

        let mut mid_decoder = new_decoder();
        let mut arena = BytesMut::new();
        assert_eq!(
            mid_decoder.decode(b"1\r\nA\r\n", &mut arena),
            Ok(ChunkedEvent::Data { offset: 3, len: 1 })
        );
        assert!(!mid_decoder.is_done());
    }

    /// `max_chunk_ext_bytes` (256 by default) is enforced with `>`, not `==`
    /// or `>=`: exactly 256 ext bytes succeeds, 257 fails. Closes two missed
    /// mutants at `step_ext`'s cap check. The existing `ext_grammar` test
    /// only checked a case 300 bytes over the cap, which cannot distinguish
    /// `>` from `==` or `>=` the way an exact-boundary pair can.
    #[test]
    fn ext_bytes_cap_is_exact() {
        let cap = usize::try_from(Limits::DEFAULT.max_chunk_ext_bytes).unwrap_or(0);

        // The leading `;` counts as the first ext byte and the terminating
        // `\r` (which step_ext also consumes, before handing off to
        // SizeCrlf) counts as the last one, so `cap - 2` bytes of `a` in
        // between lands the total exactly on the cap.
        let mut at_cap = Vec::from(&b"1;"[..]);
        at_cap.extend(std::iter::repeat_n(b'a', cap.saturating_sub(2)));
        at_cap.extend_from_slice(b"\r\nA\r\n0\r\n\r\n");
        let mut decoder = new_decoder();
        assert!(matches!(
            drive(&mut decoder, &at_cap).1,
            Outcome::Done { .. }
        ));

        let mut over_cap = Vec::from(&b"1;"[..]);
        over_cap.extend(std::iter::repeat_n(b'a', cap.saturating_sub(1)));
        over_cap.extend_from_slice(b"\r\nA\r\n0\r\n\r\n");
        let mut decoder2 = new_decoder();
        assert_eq!(
            drive(&mut decoder2, &over_cap).1,
            Outcome::Err(RejectReason::ChunkExtTooLong)
        );
    }

    /// The trailer per-line search bound (`max_field_line_bytes` plus
    /// `TRAILER_SEARCH_CAP_SLACK`) is enforced with `>`, not `==` or `>=`: a
    /// partial line of exactly that many bytes with no CRLF is still merely
    /// incomplete (`NeedMore`), and one byte more is `FieldLineTooLong`.
    /// Closes a missed mutant at that check (`region.len() > search_cap`).
    #[test]
    fn trailer_search_cap_is_exact() {
        let search_cap = usize::try_from(Limits::DEFAULT.max_field_line_bytes)
            .unwrap_or(0)
            .saturating_add(TRAILER_SEARCH_CAP_SLACK);

        let mut at_cap = Vec::from(&b"0\r\n"[..]);
        at_cap.extend(std::iter::repeat_n(b'v', search_cap));
        let mut decoder = new_decoder();
        let mut arena = BytesMut::new();
        assert_eq!(
            decoder.decode(&at_cap, &mut arena),
            Ok(ChunkedEvent::NeedMore)
        );

        let mut over_cap = Vec::from(&b"0\r\n"[..]);
        over_cap.extend(std::iter::repeat_n(b'v', search_cap.saturating_add(1)));
        let mut decoder2 = new_decoder();
        assert_eq!(
            drive(&mut decoder2, &over_cap).1,
            Outcome::Err(RejectReason::FieldLineTooLong)
        );
    }

    /// `max_field_line_bytes` on a COMPLETE trailer line is enforced with
    /// `>`, not `==` or `>=`: a line whose name plus trimmed value lands
    /// exactly on the cap succeeds, one byte more fails. Closes two missed
    /// mutants at that check. Distinct from `trailer_search_cap_is_exact`
    /// above, which bounds an INCOMPLETE line with no CRLF at all; this one
    /// bounds a complete, well-formed line that is simply too long.
    #[test]
    fn trailer_line_length_cap_is_exact() {
        let cap = usize::try_from(Limits::DEFAULT.max_field_line_bytes).unwrap_or(0);
        // name "x-a" (3 bytes) plus a value padded so name + value == cap.
        let value_len = cap.saturating_sub(3);

        let mut at_cap = Vec::from(&b"0\r\nx-a: "[..]);
        at_cap.extend(std::iter::repeat_n(b'v', value_len));
        at_cap.extend_from_slice(b"\r\n\r\n");
        let mut decoder = new_decoder();
        assert!(matches!(
            drive(&mut decoder, &at_cap).1,
            Outcome::Done { .. }
        ));

        let mut over_cap = Vec::from(&b"0\r\nx-a: "[..]);
        over_cap.extend(std::iter::repeat_n(b'v', value_len.saturating_add(1)));
        over_cap.extend_from_slice(b"\r\n\r\n");
        let mut decoder2 = new_decoder();
        assert_eq!(
            drive(&mut decoder2, &over_cap).1,
            Outcome::Err(RejectReason::FieldLineTooLong)
        );
    }

    /// `trailer_scan`'s own budget (`HeadScanBudget::MAX_BYTES`) is enforced
    /// with `>`, not `>=`: a cumulative search of exactly that many bytes is
    /// still accepted, one byte more is refused. Closes a missed mutant at
    /// that check. `trailer_rescan_is_bounded` only proves the budget fires
    /// SOMEWHERE within a documented order of magnitude; it cannot land on
    /// the exact byte the way this test does, which calls the private
    /// `step_trailers` step directly (this `tests` module is a child of
    /// `chunked` and may see its parent's private items) after presetting
    /// `trailer_scan` to one byte short of the budget, so a single one-byte
    /// charge lands exactly on it.
    #[test]
    fn trailer_scan_budget_is_exact() {
        let limits = Limits::DEFAULT.clamped();
        let mut decoder = ChunkedDecoder::new(&limits, UnderscorePolicy::Reject);
        let mut arena = BytesMut::new();
        decoder.trailer_builder = Some(FieldSectionBuilder::new(&arena, &limits));
        decoder.state = State::Trailers;
        decoder.trailer_scan = HeadScanBudget::MAX_BYTES.saturating_sub(1);

        let mut cursor = 0usize;
        let result = decoder.step_trailers(b"v", &mut cursor, &mut arena);
        assert!(matches!(result, Ok(Step::NeedMore)));
        assert_eq!(decoder.trailer_scan, HeadScanBudget::MAX_BYTES);

        let mut cursor2 = 0usize;
        let result2 = decoder.step_trailers(b"v", &mut cursor2, &mut arena);
        assert!(matches!(result2, Err(RejectReason::FieldLineTooLong)));
    }

    /// As `trailer_scan_budget_is_exact`, but for the OTHER charge site: the
    /// bytes-actually-searched charge on a line whose CRLF WAS found
    /// (`rel + 2`), not the whole-window charge on a line whose CRLF was
    /// not found. `cargo mutants` found this one independently missed by
    /// the corpus above: `>` there can degrade to `==` or `>=` without any
    /// existing test noticing, because `trailer_scan_budget_is_exact` only
    /// ever drives the NOT-found branch (its `b"v"` line never contains a
    /// `\r\n`). A complete line "x-a: 1\r\n" charges exactly `rel + 2 == 8`.
    #[test]
    fn trailer_scan_budget_is_exact_on_a_found_line() {
        let limits = Limits::DEFAULT.clamped();
        let line: &[u8] = b"x-a: 1\r\n";

        // At the cap: charging exactly 8 more bytes lands exactly on
        // MAX_BYTES, which must still be accepted (the line is short and
        // there is nothing left to search afterward, so NeedMore).
        let mut at_cap_decoder = ChunkedDecoder::new(&limits, UnderscorePolicy::Reject);
        let mut at_cap_arena = BytesMut::new();
        at_cap_decoder.trailer_builder = Some(FieldSectionBuilder::new(&at_cap_arena, &limits));
        at_cap_decoder.state = State::Trailers;
        at_cap_decoder.trailer_scan = HeadScanBudget::MAX_BYTES.saturating_sub(8);
        let mut at_cap_cursor = 0usize;
        let at_cap_result =
            at_cap_decoder.step_trailers(line, &mut at_cap_cursor, &mut at_cap_arena);
        assert!(matches!(at_cap_result, Ok(Step::NeedMore)));
        assert_eq!(at_cap_decoder.trailer_scan, HeadScanBudget::MAX_BYTES);

        // One byte over: the same line, charged from one byte closer to the
        // cap, must be refused instead.
        let mut over_cap_decoder = ChunkedDecoder::new(&limits, UnderscorePolicy::Reject);
        let mut over_cap_arena = BytesMut::new();
        over_cap_decoder.trailer_builder = Some(FieldSectionBuilder::new(&over_cap_arena, &limits));
        over_cap_decoder.state = State::Trailers;
        over_cap_decoder.trailer_scan = HeadScanBudget::MAX_BYTES.saturating_sub(7);
        let mut over_cap_cursor = 0usize;
        let over_cap_result =
            over_cap_decoder.step_trailers(line, &mut over_cap_cursor, &mut over_cap_arena);
        assert!(matches!(
            over_cap_result,
            Err(RejectReason::FieldLineTooLong)
        ));
    }

    /// Hand-written adversarial check, not a `cargo mutants`-generated one:
    /// an underscore-obfuscated denied header name must still be denied once
    /// `UnderscorePolicy::MapToHyphen` maps it to its canonical hyphenated
    /// form. Every other test in this file uses `Reject`, so this is the
    /// only test that would notice `classify_trailer_name` and
    /// `push_normalized` canonicalizing a name differently under the other
    /// policy, which is exactly the shape of a smuggling bypass this crate's
    /// own `field.rs` module doc comment names (Traefik CVE-2026-54763): an
    /// `X_Forwarded_User`-style underscore variant of a name a hyphen-based
    /// check would otherwise miss.
    #[test]
    fn trailer_deny_list_holds_under_map_to_hyphen() {
        let limits = Limits::DEFAULT.clamped();
        let mut decoder = ChunkedDecoder::new(&limits, UnderscorePolicy::MapToHyphen);
        assert_eq!(
            drive(&mut decoder, b"0\r\nContent_Length: 10\r\n\r\n").1,
            Outcome::Err(RejectReason::TrailerFieldForbidden)
        );
    }

    // ---------- fixes for issue #658 (blocking) and its 4 SHOULD_FIX findings ----------

    /// Issue #658, reproduced by execution before the fix (`Ok(None)`
    /// instead of `Ok(Some(b"abc"))`, matching the issue's own report
    /// exactly): `decode`'s undocumented precondition that `arena` is the
    /// SAME growing buffer across every call for one body. This test drives
    /// the exact scenario by hand, one byte per call, with a single shared
    /// `arena` declared ONCE outside the loop, which is the correct usage
    /// `decode`'s doc comment now states explicitly. `split_invariance` and
    /// `prop_split_invariance` also cover this (every split size, many
    /// generated bodies), but this one stays as a direct, minimal
    /// regression for the issue's own named reproduction.
    #[test]
    fn trailer_field_split_byte_by_byte_is_readable_after_done() {
        let wire: &[u8] = b"0\r\nX-Checksum: abc\r\n\r\n";
        let mut decoder = new_decoder();
        let mut pos = 0usize;
        let mut revealed = 0usize;
        let mut arena = BytesMut::new();
        loop {
            if revealed < wire.len() {
                revealed += 1;
            }
            let buf = wire.get(pos..revealed).unwrap_or(&[]);
            match decoder.decode(buf, &mut arena) {
                Ok(ChunkedEvent::NeedMore) => {
                    pos = pos.saturating_add(decoder.consumed_this_call());
                }
                Ok(ChunkedEvent::Done { consumed }) => {
                    pos = pos.saturating_add(consumed);
                    break;
                }
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!(pos, 22);
        let trailers = decoder.trailers().expect("trailers must be present");
        assert_eq!(trailers.len(), 1, "the field slot must exist");
        assert_eq!(trailers.get_unique(b"x-checksum"), Ok(Some(&b"abc"[..])));
    }

    /// Coverage gap closed: `trailer_scan` must charge the bytes actually searched to
    /// find each line's terminator, not the whole (possibly much larger)
    /// remaining window. Two short trailer lines plus the terminating empty
    /// line, all available in ONE buffer: the bytes actually needed to find
    /// each CRLF are 8 ("x-a: 1\r\n"), 8 ("x-b: 2\r\n") and 2 ("\r\n"), 18
    /// total. Reproduced by execution before the fix: the old code charged
    /// the whole shrinking remaining-window length on every line instead
    /// (18 + 10 + 2 = 30), which over time turns one `decode` call parsing
    /// many short, legitimate trailer lines out of one large buffer into an
    /// O(N * window) charge instead of O(sum of line lengths), risking
    /// `FieldLineTooLong` on traffic nowhere near either real limit.
    #[test]
    fn trailer_scan_charges_only_bytes_searched_not_the_whole_window() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut decoder = ChunkedDecoder::new(&limits, UnderscorePolicy::Reject);
        decoder.trailer_builder = Some(FieldSectionBuilder::new(&arena, &limits));
        decoder.state = State::Trailers;
        let mut cursor = 0usize;
        let buf: &[u8] = b"x-a: 1\r\nx-b: 2\r\n\r\n";
        let result = decoder.step_trailers(buf, &mut cursor, &mut arena);
        assert!(matches!(result, Ok(Step::Done)), "expected Done");
        assert_eq!(decoder.trailer_scan, 18);
    }

    /// Coverage gap closed: no earlier test decoded a body of more than four chunks,
    /// leaving the per-chunk reset of `size_digits` (and `ext_bytes`)
    /// unproven. 20 one-byte chunks is more than `MAX_SIZE_DIGITS` (16), so
    /// an accumulation bug across chunks (either counter failing to reset
    /// between chunks) would trip a spurious `ChunkSizeOverflow` or
    /// `ChunkExtTooLong` around the 17th chunk even though no single chunk
    /// is anywhere near either cap. Verified by execution: this already
    /// passes on the current implementation (the reset is unconditional on
    /// every non-terminal `SizeCrlf` transition), so this closes a coverage
    /// gap rather than a defect.
    #[test]
    fn many_chunks_reset_per_chunk_state() {
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for i in 0..20u8 {
            let byte = b'a'.wrapping_add(i % 26);
            wire.extend_from_slice(b"1\r\n");
            wire.push(byte);
            wire.extend_from_slice(b"\r\n");
            expected.push(byte);
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let mut decoder = new_decoder();
        let (data, outcome) = drive(&mut decoder, &wire);
        assert_eq!(data, expected);
        assert!(matches!(outcome, Outcome::Done { .. }));

        // Interspersing a chunk-ext on every other chunk proves ext_bytes
        // resets too: a carried-over count would eventually trip
        // ChunkExtTooLong on a chunk whose own extension is tiny.
        let mut wire_ext = Vec::new();
        let mut expected_ext = Vec::new();
        for i in 0..20u8 {
            let byte = b'a'.wrapping_add(i % 26);
            if i % 2 == 0 {
                wire_ext.extend_from_slice(b"1;e=1\r\n");
            } else {
                wire_ext.extend_from_slice(b"1\r\n");
            }
            wire_ext.push(byte);
            wire_ext.extend_from_slice(b"\r\n");
            expected_ext.push(byte);
        }
        wire_ext.extend_from_slice(b"0\r\n\r\n");
        let mut decoder_ext = new_decoder();
        let (data_ext, outcome_ext) = drive(&mut decoder_ext, &wire_ext);
        assert_eq!(data_ext, expected_ext);
        assert!(matches!(outcome_ext, Outcome::Done { .. }));
    }

    /// Coverage gap closed: `trailer_deny_list` above places the denied field as the
    /// ONLY trailer, so a deny check that inspected just the first field
    /// pushed would still pass every case there. This proves the same 18
    /// names are refused when preceded by an innocuous field. Verified by
    /// execution: this already passes on the current implementation (the
    /// deny check runs inside `step_trailers`'s per-line loop, on every
    /// line, not only the first), so this closes a coverage gap rather than
    /// a defect.
    #[test]
    fn trailer_deny_list_when_not_first_field() {
        for denied in TRAILER_DENIED {
            let name = denied.as_bytes();
            let mut wire = Vec::from(&b"0\r\nx-before: 1\r\n"[..]);
            wire.extend_from_slice(name);
            wire.extend_from_slice(b": x\r\n\r\n");
            let mut decoder = new_decoder();
            assert_eq!(
                drive(&mut decoder, &wire).1,
                Outcome::Err(RejectReason::TrailerFieldForbidden),
                "{denied:?} ({name:?}) not refused when not the first trailer field"
            );
        }
    }
}
