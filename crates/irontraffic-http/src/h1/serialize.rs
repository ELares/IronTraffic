// SPDX-License-Identifier: MIT OR Apache-2.0
//! HTTP/1 serializer: regenerates framing from [`BodySource`], not from
//! inbound fields, so no downgrade can leak H2.CL-, H2.TE- or H3.CL-based
//! smuggling into HTTP/1.
//!
//! # Security
//!
//! This module is THE smuggling kill switch. Every byte it writes comes from
//! a [`CanonicalRequest`] or [`CanonicalResponse`] whose framing fields were
//! already stripped at ingress, and the only framing values it emits are
//! derived from the resolved [`BodySource`] the caller passes in. An inbound
//! `Content-Length` or `Transfer-Encoding` can never reach the wire here,
//! not even by accident: the variable-length fields the module writes are
//! never indexed by name, only by stable slot position, so a malformed
//! inbound collision between a framing name and a custom name is structurally
//! unreachable.
//!
//! Every name and value this module writes is validated against the same
//! tables ingress already checked them against (`field::validate_name`,
//! `field::validate_value`). The section came from our own parser, so this
//! is a second check of already-checked bytes, and it is deliberate: the
//! alternative is that any bug anywhere between ingress and egress (a
//! filter, a rewrite, a synthesized header) becomes a CRLF-injection
//! primitive with no backstop.
//!
//! The outbound version is always `HTTP/1.1`, whatever version the message
//! arrived on, and the outbound request target is always origin-form,
//! asterisk-form or authority-form: absolute-form is refused with
//! `TargetFormInvalid` rather than ever forwarded, because the upstream is a
//! specific origin we chose. `serialize_response_head` applies the
//! bodyless-by-status rule (RFC 9112 Section 6.3) and the `HEAD` exception
//! before it ever looks at `body`.
//!
//! # Zero allocation
//!
//! Every serializer writes directly into a caller-supplied `BytesMut` and
//! every length function derives its answer from the same arithmetic the
//! writer uses, without allocating a buffer of its own. The one exception is
//! `ChunkedEncoder`, which holds 16 bytes of state (the partial-hex scratch
//! buffer for the chunk-size line) and never allocates.
//!
//! # Field ordering
//!
//! The fields this module emits are in a fixed, documented order so that a
//! receiver that depends on field ordering (none should, but some do) gets a
//! predictable output. The order is:
//!
//! 1. `Host` (requests only)
//! 2. `Content-Length` or `Transfer-Encoding`
//! 3. `Connection`
//! 4. `Forwarded` and/or `X-Forwarded-*` (requests only, optional)
//! 5. End-to-end fields, in the same order they arrived
//!
//! The end-to-end pass refuses (`ConnectionSpecificField`) any field
//! [`crate::strip::is_hop_by_hop`] returns true for -- the last-line
//! backstop against a filter or native extension that mutated the section
//! after [`crate::canonical::CanonicalRequestBuilder::build`] ran -- and
//! silently skips `Host` (already written at step 1) and `TE` (never
//! forwarded), and any field whose name matches a reserved prefix.

use std::net::SocketAddr;

use bytes::{BufMut, BytesMut};

use crate::authority::Authority;
use crate::canonical::{CanonicalRequest, CanonicalResponse};
use crate::error::RejectReason;
use crate::field::{validate_name, validate_value};
use crate::h1::chunked::trailer_denied;
use crate::known::KnownHeader;
use crate::path::TargetForm;
use crate::peer::{ForwardEmit, write_forwarded_element};
use crate::scalar::{Method, Scheme, StatusCode, WireVersion};
use crate::section::FieldSection;
use crate::strip::{is_hop_by_hop, is_reserved_prefix};

/// Whether the serializer emits a body framing header, and what kind.
///
/// Derived by the caller from whichever framing resolution is authoritative
/// for the current message (request or response). The serializer never looks
/// at the inbound framing fields; it always trusts this value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BodySource {
    /// No body. Neither `Content-Length` nor `Transfer-Encoding` is emitted.
    None,
    /// Exactly `len` bytes follow. A `Content-Length` header for `len` is
    /// emitted.
    Exact {
        /// The declared body length.
        len: u64,
    },
    /// The body length is not known in advance. On HTTP/1.1 a
    /// `Transfer-Encoding: chunked` header is emitted; on HTTP/1.0 the
    /// caller must close the connection.
    Streaming,
}

/// Whether to emit `Connection: keep-alive` or `Connection: close` on the
/// request line to the upstream.
///
/// The outbound version is always `HTTP/1.1` -- `serialize_request_head`
/// never emits `HTTP/1.0` upstream, whatever version the downstream request
/// arrived on -- so `KeepAlive` always means "write nothing": HTTP/1.1
/// implies a persistent connection by default and no explicit header is
/// needed. `Close` always writes the field. The default wiring (which lives
/// outside this module, in the caller that holds the listener
/// configuration) chooses between the two.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Write nothing: `HTTP/1.1` implies keep-alive by default.
    KeepAlive,
    /// Emit `Connection: close`.
    Close,
}

// ---------------------------------------------------------------------------
// Wire literals shared between every writer and its matching length function
// ---------------------------------------------------------------------------
//
// A writer and a length function that each spell out their own copy of a
// literal such as "Transfer-Encoding: chunked\r\n" can drift: one gets
// edited, the other does not, and the two silently disagree about how many
// bytes a call will produce. Every constant below is the ONLY place its text
// is spelled out; both the writer and the length function compute from
// `CONST.len()`, so a wrong byte count is now a wrong constant, not two
// independent wrong counts that happen to differ.

const CRLF: &[u8] = b"\r\n";
const HOST_PREFIX: &[u8] = b"Host: ";
const CONTENT_LENGTH_PREFIX: &[u8] = b"Content-Length: ";
const TRANSFER_ENCODING_CHUNKED_LINE: &[u8] = b"Transfer-Encoding: chunked\r\n";
const CONNECTION_CLOSE_LINE: &[u8] = b"Connection: close\r\n";
const CONNECTION_KEEPALIVE_LINE: &[u8] = b"Connection: keep-alive\r\n";
const FORWARDED_PREFIX: &[u8] = b"Forwarded: ";
const X_FORWARDED_FOR_PREFIX: &[u8] = b"X-Forwarded-For: ";
const X_FORWARDED_PROTO_PREFIX: &[u8] = b"X-Forwarded-Proto: ";
const X_FORWARDED_HOST_PREFIX: &[u8] = b"X-Forwarded-Host: ";
const X_FORWARDED_PORT_PREFIX: &[u8] = b"X-Forwarded-Port: ";

// ---------------------------------------------------------------------------
// Decimal rendering helpers
// ---------------------------------------------------------------------------

/// Renders `v`'s decimal digits least-significant-digit first into a fixed
/// 20-byte buffer, returning the buffer and how many of its leading slots
/// hold a digit (1 to 20). Shared by every function that writes a numeric
/// value and its matching length-prediction function so the two can never
/// disagree about how many bytes a number renders to.
fn decimal_digits(v: u64) -> ([u8; 20], usize) {
    let mut digits = [0_u8; 20];
    let mut count = 0_usize;
    let mut remaining = v;
    loop {
        let digit = remaining.checked_rem(10).unwrap_or(0);
        let digit_byte = u8::try_from(digit).unwrap_or(0);
        if let Some(slot) = digits.get_mut(count) {
            *slot = b'0'.saturating_add(digit_byte);
        }
        count = count.saturating_add(1);
        remaining = remaining.checked_div(10).unwrap_or(0);
        if remaining == 0 {
            break;
        }
    }
    (digits, count)
}

/// Writes `v`'s decimal digits into `out` and returns how many bytes were
/// written. Always agrees with [`decimal_digits`]`(v).1`.
fn write_u64(v: u64, out: &mut BytesMut) -> usize {
    let (digits, count) = decimal_digits(v);
    for i in (0..count).rev() {
        if let Some(&b) = digits.get(i) {
            out.put_u8(b);
        }
    }
    count
}

/// The number of decimal digits needed for `v`; at least 1.
fn u64_len(v: u64) -> usize {
    decimal_digits(v).1
}

// ---------------------------------------------------------------------------
// Hex rendering helpers
// ---------------------------------------------------------------------------

const HEX: [u8; 16] = *b"0123456789abcdef";

/// Renders `len` as lowercase hex digits into the trailing bytes of `scratch`,
/// returning how many trailing bytes of the 16-byte buffer hold the
/// representation (1 to 16, or 0 when `len == 0` for the terminal chunk).
fn hex_digits(mut len: usize, scratch: &mut [u8; 16]) -> usize {
    let mut count = 0_usize;
    loop {
        let nibble = len & 0xF;
        let ch = HEX.get(nibble).copied().unwrap_or(b'0');
        let pos = 15_usize.saturating_sub(count);
        if let Some(slot) = scratch.get_mut(pos) {
            *slot = ch;
        }
        count = count.saturating_add(1);
        len >>= 4;
        if len == 0 {
            break;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// ChunkedEncoder
// ---------------------------------------------------------------------------

/// Writes chunked encoding frames into a `BytesMut` without allocation.
///
/// Each call to [`write_chunk`](ChunkedEncoder::write_chunk) emits the
/// chunk-size line, the chunk data, and the trailing CRLF. An empty `data`
/// writes nothing and returns 0: an empty chunk IS the terminal chunk, so
/// writing one mid-body would silently end the message and hand the
/// upstream everything after it as the start of the next request (#724
/// BLOCKING 2). The caller passes the entire chunk at once. After all
/// chunks are written, [`finish`](ChunkedEncoder::finish) emits the terminal
/// chunk and optional trailer fields exactly once: both methods refuse to
/// write anything once the encoder is finished (#724 BLOCKING 3).
///
/// The encoder validates trailer field names and values through
/// [`validate_name`] and [`validate_value`] and refuses forbidden names via
/// [`trailer_denied`].
pub struct ChunkedEncoder {
    /// Scratch buffer for building the hex chunk-size line. Sized for the
    /// worst-case `usize` (16 hex digits on 64-bit).
    scratch: [u8; 16],
    /// True after `finish` has completed successfully.
    finished: bool,
}

impl ChunkedEncoder {
    /// A new encoder. No allocation occurs.
    #[must_use]
    pub fn new() -> Self {
        ChunkedEncoder {
            scratch: [0_u8; 16],
            finished: false,
        }
    }

    /// Writes one chunk: hex-size line, data bytes, CRLF. Returns the number
    /// of bytes written into `out`.
    ///
    /// Writes nothing and returns 0 when `data` is empty (an empty chunk
    /// would terminate the body) or when [`is_finished`](Self::is_finished)
    /// is already true (appending after termination puts a spare frame on
    /// the wire that the upstream reads as the start of the next message).
    ///
    /// The chunk boundaries are OURS: this encoder does not reproduce the
    /// boundaries the client used. Copies `data` into `out`; a vectored
    /// variant that avoids the copy is deliberately out of scope for this
    /// issue.
    ///
    /// # Panics
    ///
    /// Never.
    pub fn write_chunk(&mut self, data: &[u8], out: &mut BytesMut) -> usize {
        if self.is_finished() || data.is_empty() {
            return 0;
        }
        let count = hex_digits(data.len(), &mut self.scratch);
        let start = 16_usize.saturating_sub(count);
        let mut written = 0_usize;
        if let Some(slice) = self.scratch.get(start..) {
            out.extend_from_slice(slice);
            written = written.saturating_add(slice.len());
        }
        out.extend_from_slice(CRLF);
        written = written.saturating_add(CRLF.len());
        out.extend_from_slice(data);
        written = written.saturating_add(data.len());
        out.extend_from_slice(CRLF);
        written = written.saturating_add(CRLF.len());
        written
    }

    /// Writes the terminal chunk (`0\r\n`) and optional trailers, and marks
    /// the encoder as finished. Returns the number of bytes written.
    ///
    /// Idempotent: once [`is_finished`](Self::is_finished) is true, further
    /// calls write nothing and return `Ok(0)` (#724 BLOCKING 3). This
    /// matters on a keep-alive connection: a second terminal chunk on the
    /// wire is read by the upstream as the start of the next message.
    ///
    /// When `trailers` is non-empty every trailer field is emitted as
    /// `Name: Value\r\n`, validated with the same [`validate_name`] /
    /// [`validate_value`] checks the end-to-end field pass uses, and
    /// refused when [`trailer_denied`] answers true for it. The deny-list is
    /// applied on egress as well as on ingress, because a filter could have
    /// added a field to the trailer section after the decoder validated it.
    /// On any error nothing new is left in `out`: it is truncated back to
    /// the length it had on entry.
    ///
    /// # Errors
    /// `TrailerFieldForbidden` when a trailer field uses a denied name.
    /// `FieldNameInvalidByte` when a trailer slot cannot be read back, or
    /// whatever [`validate_name`] / [`validate_value`] returns when a
    /// trailer name or value fails validation.
    pub fn finish(
        &mut self,
        trailers: &FieldSection,
        out: &mut BytesMut,
    ) -> Result<usize, RejectReason> {
        if self.is_finished() {
            return Ok(0);
        }
        let start = out.len();
        match write_trailers(trailers, out) {
            Ok(()) => {
                self.finished = true;
                Ok(out.len().saturating_sub(start))
            }
            Err(e) => {
                out.truncate(start);
                Err(e)
            }
        }
    }

    /// True once [`finish`](ChunkedEncoder::finish) has completed
    /// successfully.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }
}

impl Default for ChunkedEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// The body of [`ChunkedEncoder::finish`]: the terminal chunk plus optional
/// trailers, with no truncate-on-error bookkeeping of its own (the caller
/// does that once, around the whole call).
fn write_trailers(trailers: &FieldSection, out: &mut BytesMut) -> Result<(), RejectReason> {
    out.extend_from_slice(b"0\r\n");
    for (i, slot) in trailers.slots().iter().enumerate() {
        if trailer_denied(slot.known) {
            return Err(RejectReason::TrailerFieldForbidden);
        }
        let (Some(name), Some(value)) = (trailers.name_at(i), trailers.value_at(i)) else {
            return Err(RejectReason::FieldNameInvalidByte);
        };
        validate_name(name, WireVersion::Http11)?;
        validate_value(value, WireVersion::Http11)?;
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(CRLF);
    }
    out.extend_from_slice(CRLF);
    Ok(())
}

// ---------------------------------------------------------------------------
// IPv6 helpers (RFC 5952 canonical form)
// ---------------------------------------------------------------------------

/// Finds the longest run of two or more consecutive zero 16-bit groups,
/// ties broken toward the leftmost run. Returns `None` when no run of
/// length 2 or more exists.
fn longest_zero_run(segments: [u16; 8]) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    let mut current_start = 0_usize;
    let mut current_len = 0_usize;
    for (i, &group) in segments.iter().enumerate() {
        if group == 0 {
            if current_len == 0 {
                current_start = i;
            }
            current_len = current_len.saturating_add(1);
        } else {
            if current_len >= 2 && best.is_none_or(|(_, best_len)| current_len > best_len) {
                best = Some((current_start, current_len));
            }
            current_len = 0;
        }
    }
    if current_len >= 2 && best.is_none_or(|(_, best_len)| current_len > best_len) {
        best = Some((current_start, current_len));
    }
    best
}

/// The number of hex digits [`write_group_hex`] writes for `group`: 1 to 4,
/// with no leading zeros, except a single `0` for the value zero itself.
fn group_hex_len(group: u16) -> usize {
    if group < 0x10 {
        1
    } else if group < 0x100 {
        2
    } else if group < 0x1000 {
        3
    } else {
        4
    }
}

/// Writes one IPv6 group's hex digits (no leading zeros, lowercase) into
/// `out`. Always writes exactly [`group_hex_len`]`(group)` bytes.
fn write_group_hex(group: u16, out: &mut BytesMut) -> usize {
    let nibbles = [
        (group >> 12) & 0xF,
        (group >> 8) & 0xF,
        (group >> 4) & 0xF,
        group & 0xF,
    ];
    let first_nonzero = nibbles.iter().position(|&n| n != 0).unwrap_or(3);
    let mut written = 0_usize;
    for &nibble in nibbles.get(first_nonzero..).unwrap_or(&[]) {
        let ch = HEX.get(usize::from(nibble)).copied().unwrap_or(b'0');
        out.put_u8(ch);
        written = written.saturating_add(1);
    }
    written
}

/// Writes an IPv6 address in RFC 5952 canonical hex form into `out`: lower
/// case, no leading zeros within a group, and the leftmost longest run of
/// two or more zero groups replaced by `::`.
fn write_ipv6(addr: std::net::Ipv6Addr, out: &mut BytesMut) -> usize {
    let segments = addr.segments();
    let run = longest_zero_run(segments);
    let mut written = 0_usize;
    let mut wrote_group = false;
    let mut idx = 0_usize;
    while idx < 8 {
        if let Some((start, run_len)) = run
            && idx == start
        {
            out.extend_from_slice(b"::");
            written = written.saturating_add(2);
            idx = idx.saturating_add(run_len.max(1));
            wrote_group = false;
            continue;
        }
        if wrote_group {
            out.put_u8(b':');
            written = written.saturating_add(1);
        }
        let group = segments.get(idx).copied().unwrap_or(0);
        written = written.saturating_add(write_group_hex(group, out));
        wrote_group = true;
        idx = idx.saturating_add(1);
    }
    written
}

/// IPv6 canonical length. Mirrors [`write_ipv6`]'s own loop.
fn ipv6_len(addr: std::net::Ipv6Addr) -> usize {
    let segments = addr.segments();
    let run = longest_zero_run(segments);
    let mut len = 0_usize;
    let mut wrote_group = false;
    let mut idx = 0_usize;
    while idx < 8 {
        if let Some((start, run_len)) = run
            && idx == start
        {
            len = len.saturating_add(2);
            idx = idx.saturating_add(run_len.max(1));
            wrote_group = false;
            continue;
        }
        if wrote_group {
            len = len.saturating_add(1);
        }
        let group = segments.get(idx).copied().unwrap_or(0);
        len = len.saturating_add(group_hex_len(group));
        wrote_group = true;
        idx = idx.saturating_add(1);
    }
    len
}

// ---------------------------------------------------------------------------
// Node value rendering (for X-Forwarded-For etc.)
// ---------------------------------------------------------------------------

/// Writes `addr`'s text form (dotted-decimal for IPv4, RFC 5952 canonical
/// hex for IPv6, bracketed when IPv6) into `out`, with an optional `:port`
/// suffix.
fn write_node(addr: std::net::IpAddr, port: Option<u16>, out: &mut BytesMut) -> usize {
    let mut written = 0_usize;
    match addr {
        std::net::IpAddr::V4(v4) => {
            for (i, octet) in v4.octets().iter().enumerate() {
                if i > 0 {
                    out.put_u8(b'.');
                    written = written.saturating_add(1);
                }
                written = written.saturating_add(write_u64(u64::from(*octet), out));
            }
        }
        std::net::IpAddr::V6(v6) => {
            out.put_u8(b'[');
            written = written.saturating_add(1);
            written = written.saturating_add(write_ipv6(v6, out));
            out.put_u8(b']');
            written = written.saturating_add(1);
        }
    }
    if let Some(p) = port {
        out.put_u8(b':');
        written = written.saturating_add(1);
        written = written.saturating_add(write_u64(u64::from(p), out));
    }
    written
}

/// The byte length of the node value that [`write_node`] will write.
fn node_len(addr: std::net::IpAddr, port: Option<u16>) -> usize {
    let mut len = match addr {
        std::net::IpAddr::V4(v4) => {
            let mut l = 3_usize;
            for octet in v4.octets() {
                l = l.saturating_add(u64_len(u64::from(octet)));
            }
            l
        }
        std::net::IpAddr::V6(v6) => ipv6_len(v6).saturating_add(2),
    };
    if let Some(p) = port {
        len = len.saturating_add(1).saturating_add(u64_len(u64::from(p)));
    }
    len
}

// ---------------------------------------------------------------------------
// Request target rendering (TargetForm)
// ---------------------------------------------------------------------------

/// Writes `authority`'s `host:port` form for `TargetForm::Authority`
/// (`CONNECT`), always including a port. `CONNECT` never omits one: an
/// absent explicit port falls back to `authority.effective_port(scheme)`
/// (`443` for `https`, `80` for `http`), unlike [`Authority::write_to`],
/// which omits the port entirely when it equals the scheme default.
fn write_authority_target(authority: &Authority, scheme: Scheme, out: &mut BytesMut) {
    out.extend_from_slice(authority.host());
    out.put_u8(b':');
    write_u64(u64::from(authority.effective_port(scheme)), out);
}

/// The byte count [`write_authority_target`] will write.
fn authority_target_len(authority: &Authority, scheme: Scheme) -> usize {
    authority
        .host()
        .len()
        .saturating_add(1)
        .saturating_add(u64_len(u64::from(authority.effective_port(scheme))))
}

/// Writes the request-line target for `form`.
///
/// `TargetForm::Origin` writes the normalized path plus `?query` when
/// present (`req.write_target`). `TargetForm::Asterisk` writes a single
/// `*`. `TargetForm::Authority` writes the authority's canonical
/// `host:port` form, always including a port. `TargetForm::Absolute` is
/// never emitted upstream -- we always speak origin-form (or asterisk or
/// authority form) even when we received absolute-form on a forward-proxy
/// listener, because the upstream is a specific origin we chose -- and is
/// refused with `TargetFormInvalid`.
///
/// # Errors
/// `TargetFormInvalid` for `TargetForm::Absolute`.
fn write_target_form(
    req: &CanonicalRequest,
    form: TargetForm,
    out: &mut BytesMut,
) -> Result<(), RejectReason> {
    match form {
        TargetForm::Origin => {
            req.write_target(out);
        }
        TargetForm::Asterisk => out.put_u8(b'*'),
        TargetForm::Authority => write_authority_target(&req.authority, req.scheme, out),
        TargetForm::Absolute => return Err(RejectReason::TargetFormInvalid),
    }
    Ok(())
}

/// The byte count [`write_target_form`] will write.
///
/// # Errors
/// As [`write_target_form`].
fn target_form_len(req: &CanonicalRequest, form: TargetForm) -> Result<usize, RejectReason> {
    match form {
        TargetForm::Origin => Ok(req.target_len()),
        TargetForm::Asterisk => Ok(1),
        TargetForm::Authority => Ok(authority_target_len(&req.authority, req.scheme)),
        TargetForm::Absolute => Err(RejectReason::TargetFormInvalid),
    }
}

// ---------------------------------------------------------------------------
// Shared length helpers
// ---------------------------------------------------------------------------

/// The byte count needed for the framing line: `Content-Length: N\r\n` or
/// `Transfer-Encoding: chunked\r\n` or 0 for no body. Shares
/// [`CONTENT_LENGTH_PREFIX`] and [`TRANSFER_ENCODING_CHUNKED_LINE`] with
/// [`write_framing`] so the two cannot drift (#724 BLOCKING 4).
fn framing_len(body: BodySource) -> usize {
    match body {
        BodySource::None => 0,
        BodySource::Exact { len } => CONTENT_LENGTH_PREFIX
            .len()
            .saturating_add(u64_len(len))
            .saturating_add(CRLF.len()),
        BodySource::Streaming => TRANSFER_ENCODING_CHUNKED_LINE.len(),
    }
}

/// The byte count of the `Connection` header if it will be written. Shares
/// [`CONNECTION_CLOSE_LINE`] with [`write_connection`].
fn connection_field_len(mode: ConnectionMode) -> usize {
    match mode {
        ConnectionMode::KeepAlive => 0,
        ConnectionMode::Close => CONNECTION_CLOSE_LINE.len(),
    }
}

/// True when `headers` still carries `content-length` or
/// `transfer-encoding`.
///
/// Unreachable through `CanonicalRequestBuilder::build`, which enforces
/// invariant I2 before a `CanonicalRequest` can exist. This is the
/// release-mode backstop #37 step 3 requires: a filter or native extension
/// that runs after the build and reintroduces either field must not get a
/// second framing field written alongside `body`'s (#724 `SHOULD_FIX` 2).
fn framing_field_present(headers: &FieldSection) -> bool {
    headers.count_known(KnownHeader::ContentLength) > 0
        || headers.count_known(KnownHeader::TransferEncoding) > 0
}

/// True when `k` must be silently omitted from the end-to-end pass, neither
/// written to the wire nor treated as a hop-by-hop refusal.
///
/// `Host`: step 2 already wrote the authoritative `Host` field generated
/// from `req.authority`. `strip_ingress` deliberately leaves the inbound
/// `host` slot in the section (`canonicalize_request`'s `host_field` relies
/// on it still being there), so every ordinary request carries one; writing
/// it a second time would emit a duplicate `Host`, which the origin answers
/// with a 400 (#724 BLOCKING 1).
/// `Te`: not hop-by-hop (`te: trailers` survives the ingress strip by
/// design) but not forwarded by this pass either.
fn skip_field(k: KnownHeader) -> bool {
    matches!(k, KnownHeader::Te | KnownHeader::Host)
}

/// The byte count of every end-to-end field [`write_end_to_end_fields`]
/// will write for `headers`, walking the section with the exact same checks
/// so the two cannot drift (#724 BLOCKING 4).
///
/// `reserved_prefix` is the direction-specific reserved-prefix check:
/// [`is_reserved_prefix`] for a request, or the narrower response-only
/// check for a response (#724 `SHOULD_FIX` 4).
///
/// # Errors
/// `ConnectionSpecificField` when a hop-by-hop field is present (the
/// release-mode backstop; #724 `SHOULD_FIX` 2). `FieldNameInvalidByte` when a
/// slot cannot be read back. Whatever [`validate_name`] / [`validate_value`]
/// returns when a name or value fails validation.
fn end_to_end_fields_len(
    headers: &FieldSection,
    reserved_prefix: fn(&[u8]) -> bool,
) -> Result<usize, RejectReason> {
    let mut len = 0_usize;
    for (i, slot) in headers.slots().iter().enumerate() {
        if is_hop_by_hop(slot.known) {
            return Err(RejectReason::ConnectionSpecificField);
        }
        if skip_field(slot.known) {
            continue;
        }
        let (Some(name), Some(value)) = (headers.name_at(i), headers.value_at(i)) else {
            return Err(RejectReason::FieldNameInvalidByte);
        };
        if reserved_prefix(name) {
            continue;
        }
        validate_name(name, WireVersion::Http11)?;
        validate_value(value, WireVersion::Http11)?;
        len = len.saturating_add(name.len());
        len = len.saturating_add(2); // ": "
        len = len.saturating_add(value.len());
        len = len.saturating_add(2); // "\r\n"
    }
    Ok(len)
}

// ---------------------------------------------------------------------------
// Request serializer
// ---------------------------------------------------------------------------

/// The exact number of bytes [`serialize_request_head`] will write into
/// `out`, computed without writing anything. Every piece is derived from
/// the same literal or helper the writer uses (#724 BLOCKING 4), so this
/// function and the writer cannot silently disagree.
///
/// # Errors
/// As [`serialize_request_head`].
#[must_use = "the predicted length is useless if not compared against what was actually written"]
pub fn serialize_request_head_len(
    req: &CanonicalRequest,
    form: TargetForm,
    body: BodySource,
    keep_alive: ConnectionMode,
    emit: ForwardEmit,
    local: SocketAddr,
) -> Result<usize, RejectReason> {
    let mut len = 0_usize;

    // Request line: METHOD SP TARGET SP VERSION CRLF. Always "HTTP/1.1":
    // #37 says three times that the outbound version is never HTTP/1.0.
    len = len.saturating_add(req.method.as_bytes().len());
    len = len.saturating_add(1); // SP
    len = len.saturating_add(target_form_len(req, form)?);
    len = len.saturating_add(1); // SP
    len = len.saturating_add(8); // "HTTP/1.1"
    len = len.saturating_add(2); // CRLF

    // Host field
    len = len.saturating_add(HOST_PREFIX.len());
    len = len.saturating_add(req.authority.written_len());
    len = len.saturating_add(2); // CRLF

    // Framing field (step 3's guard, before ever looking at `body`)
    if framing_field_present(&req.headers) {
        return Err(RejectReason::ConnectionSpecificField);
    }
    len = len.saturating_add(framing_len(body));

    // Connection field
    len = len.saturating_add(connection_field_len(keep_alive));

    // Forwarded element
    if emit.emit_forwarded {
        len = len.saturating_add(FORWARDED_PREFIX.len());
        len = len.saturating_add(crate::peer::forwarded_element_len(
            &req.peer,
            local,
            req.scheme,
            &req.authority,
        ));
        len = len.saturating_add(2); // CRLF
    }

    // X-Forwarded-* fields
    if emit.emit_x_forwarded {
        len = len.saturating_add(X_FORWARDED_FOR_PREFIX.len());
        len = len.saturating_add(node_len(req.peer.client, None));
        len = len.saturating_add(2); // CRLF

        len = len.saturating_add(X_FORWARDED_PROTO_PREFIX.len());
        len = len.saturating_add(req.scheme.as_bytes().len());
        len = len.saturating_add(2); // CRLF

        len = len.saturating_add(X_FORWARDED_HOST_PREFIX.len());
        len = len.saturating_add(req.authority.written_len());
        len = len.saturating_add(2); // CRLF

        if let Some(port) = req.peer.client_port {
            len = len.saturating_add(X_FORWARDED_PORT_PREFIX.len());
            len = len.saturating_add(u64_len(u64::from(port)));
            len = len.saturating_add(2); // CRLF
        }
    }

    // End-to-end fields
    len = len.saturating_add(end_to_end_fields_len(&req.headers, is_reserved_prefix)?);

    // CRLF ending the head
    len = len.saturating_add(2);

    Ok(len)
}

/// Writes the full request head (request line + all header fields) into
/// `out`. Does NOT write the body. Callers write the body separately, using
/// `BodySource` to determine the format.
///
/// `Content-Length` and `Transfer-Encoding` come from `body` and from
/// nothing else. The inbound values were deleted at ingress and their
/// absence is an invariant of `CanonicalRequest`; this function refuses to
/// write a second framing field if one is somehow present.
///
/// Always writes `HTTP/1.1` and always writes origin-form (or asterisk or
/// authority form as `form` requires), never absolute-form.
///
/// # Errors
/// `TargetFormInvalid` for `TargetForm::Absolute`. `ConnectionSpecificField`
/// when the section still carries a framing field, or a hop-by-hop field
/// (the release-mode backstop against a filter that mutated the section
/// after `CanonicalRequestBuilder::build`). `FieldNameInvalidByte` or
/// `FieldValueInvalidByte` when a field fails validation on the way out. A
/// `host` slot in the section is NOT an error: it is expected, and it is
/// skipped because step 2 already wrote the authoritative `Host` from
/// `req.authority`.
///
/// On EVERY error path `out` is truncated back to the length it had on
/// entry, so the caller can never send a half-written head (#724 `SHOULD_FIX`
/// 3).
pub fn serialize_request_head(
    req: &CanonicalRequest,
    form: TargetForm,
    body: BodySource,
    keep_alive: ConnectionMode,
    emit: ForwardEmit,
    local: SocketAddr,
    out: &mut BytesMut,
) -> Result<usize, RejectReason> {
    let start = out.len();
    match write_request_head(req, form, body, keep_alive, emit, local, out) {
        Ok(()) => Ok(out.len().saturating_sub(start)),
        Err(e) => {
            out.truncate(start);
            Err(e)
        }
    }
}

/// The body of [`serialize_request_head`], with no truncate-on-error
/// bookkeeping of its own (the caller does that once, around the whole
/// call).
fn write_request_head(
    req: &CanonicalRequest,
    form: TargetForm,
    body: BodySource,
    keep_alive: ConnectionMode,
    emit: ForwardEmit,
    local: SocketAddr,
    out: &mut BytesMut,
) -> Result<(), RejectReason> {
    // Request line: METHOD SP TARGET SP VERSION CRLF
    out.extend_from_slice(req.method.as_bytes());
    out.put_u8(b' ');
    write_target_form(req, form, out)?;
    out.put_u8(b' ');
    out.extend_from_slice(b"HTTP/1.1\r\n");

    // Host field: generated from req.authority, replacing anything the
    // client sent (RFC 9113 Section 8.3.1).
    out.extend_from_slice(HOST_PREFIX);
    req.authority.write_to(out);
    out.extend_from_slice(CRLF);

    // Framing field (from BodySource, never from inbound fields). The
    // guard below is the release-mode backstop #37 step 3 requires: it
    // never fires through the builder (I2), only through a filter or
    // native extension that ran after it.
    if framing_field_present(&req.headers) {
        return Err(RejectReason::ConnectionSpecificField);
    }
    write_framing(body, out);

    // Connection field
    write_connection(keep_alive, out);

    // Forwarded element
    if emit.emit_forwarded {
        out.extend_from_slice(FORWARDED_PREFIX);
        write_forwarded_element(&req.peer, local, req.scheme, &req.authority, out);
        out.extend_from_slice(CRLF);
    }

    // X-Forwarded-* fields
    if emit.emit_x_forwarded {
        out.extend_from_slice(X_FORWARDED_FOR_PREFIX);
        write_node(req.peer.client, None, out);
        out.extend_from_slice(CRLF);

        out.extend_from_slice(X_FORWARDED_PROTO_PREFIX);
        out.extend_from_slice(req.scheme.as_bytes());
        out.extend_from_slice(CRLF);

        out.extend_from_slice(X_FORWARDED_HOST_PREFIX);
        req.authority.write_to(out);
        out.extend_from_slice(CRLF);

        if let Some(port) = req.peer.client_port {
            out.extend_from_slice(X_FORWARDED_PORT_PREFIX);
            write_u64(u64::from(port), out);
            out.extend_from_slice(CRLF);
        }
    }

    // End-to-end fields
    write_end_to_end_fields(&req.headers, is_reserved_prefix, out)?;

    // CRLF ending the head
    out.extend_from_slice(CRLF);

    Ok(())
}

// ---------------------------------------------------------------------------
// Response serializer
// ---------------------------------------------------------------------------

/// Response-side reserved-prefix check: `x-irontraffic-` only.
///
/// Deliberately narrower than [`is_reserved_prefix`] (the request-side
/// check, which additionally strips `x-envoy-` and `x-forwarded-`):
/// `x-envoy-*` on a response is interop information the resilience layer
/// reads, not something to strip, exactly as `strip::strip_response`'s own
/// `RESPONSE_RESERVED_PREFIXES` documents. Sharing the request-side check
/// here silently dropped `x-envoy-*` from every response (#724 `SHOULD_FIX`
/// 4); this mirrors `CanonicalResponse::new`'s own inline check for the
/// same reason.
fn is_response_reserved_prefix(name: &[u8]) -> bool {
    name.starts_with(b"x-irontraffic-")
}

/// True when RFC 9112 Section 6.3 fixes this response's framing regardless
/// of `body`: a `1xx`, `204` or `304` status, or a `2xx` response to
/// `CONNECT`. #37's response step 2 applies this rule before ever looking
/// at `body`, and before the `HEAD` exception (#724 BLOCKING 5).
fn is_bodyless_by_status(status: StatusCode, request_method: Method) -> bool {
    let code = status.as_u16();
    matches!(code, 100..=199)
        || code == 204
        || code == 304
        || (matches!(code, 200..=299) && request_method.is_connect())
}

/// The byte count [`write_response_framing`] will write.
fn response_framing_len(status: StatusCode, request_method: Method, body: BodySource) -> usize {
    if is_bodyless_by_status(status, request_method) {
        return 0;
    }
    if request_method.is_head() {
        return match body {
            BodySource::Exact { len } => CONTENT_LENGTH_PREFIX
                .len()
                .saturating_add(u64_len(len))
                .saturating_add(CRLF.len()),
            BodySource::None | BodySource::Streaming => 0,
        };
    }
    framing_len(body)
}

/// Writes the response framing field, applying the bodyless-by-status rule
/// and the `HEAD` exception before falling back to [`write_framing`] (#37
/// response step 2, #724 BLOCKING 5).
///
/// For a bodyless-by-status response (edge case 16) this writes nothing
/// and, in a debug build, asserts `body` is `BodySource::None`: a caller
/// passing anything else there is a caller bug, since the status alone
/// already fixes the framing. In release the debug assertion compiles to
/// nothing and the status silently wins instead of crashing a running
/// proxy over a caller's internal inconsistency.
///
/// For a response to `HEAD` (edge case 17) this writes `content-length: n`
/// only when `body` is `Exact { len: n }` -- the length the caller read
/// from the UPSTREAM's declared `Content-Length` before `strip_response`
/// deleted it, per `canonicalize_response`'s second return value -- and
/// never `transfer-encoding`. RFC 9112 Section 6.3 item 1 fixes the framing
/// of any response to `HEAD` at the first empty line regardless of header
/// fields present, so this cannot desync a client, and dropping the field
/// would silently break `curl -I` and every range-request client that
/// probes with `HEAD` first.
fn write_response_framing(
    status: StatusCode,
    request_method: Method,
    body: BodySource,
    out: &mut BytesMut,
) {
    if is_bodyless_by_status(status, request_method) {
        debug_assert!(
            matches!(body, BodySource::None),
            "a bodyless-by-status response must be called with BodySource::None; \
             the status fixes the framing regardless of body"
        );
        return;
    }
    if request_method.is_head() {
        if let BodySource::Exact { len } = body {
            out.extend_from_slice(CONTENT_LENGTH_PREFIX);
            write_u64(len, out);
            out.extend_from_slice(CRLF);
        }
        return;
    }
    write_framing(body, out);
}

/// The exact number of bytes [`serialize_response_head`] will write into
/// `out`, computed without writing anything.
///
/// # Errors
/// `ConnectionSpecificField` when a hop-by-hop field is present in
/// `res.headers`, or when a field cannot be read back. Whatever
/// [`validate_name`] / [`validate_value`] returns when a name or value
/// fails validation.
#[must_use = "the predicted length is useless if not compared against what was actually written"]
pub fn serialize_response_head_len(
    res: &CanonicalResponse,
    request_method: Method,
    body: BodySource,
    keep_alive: bool,
) -> Result<usize, RejectReason> {
    let mut len = 0_usize;

    // Status line: "HTTP/1.1 " (9) + 3-digit status + SP (always, RFC 9112
    // Section 4: the SP is part of the grammar even when the reason phrase
    // is empty) + optional reason + CRLF.
    len = len.saturating_add(9);
    len = len.saturating_add(3); // status code digits
    len = len.saturating_add(1); // SP
    let reason = canonical_reason(res.status.as_u16());
    len = len.saturating_add(reason.len());
    len = len.saturating_add(2); // CRLF

    // Framing field, bodyless-by-status and HEAD rules applied first.
    len = len.saturating_add(response_framing_len(res.status, request_method, body));

    // Connection field
    if !keep_alive {
        len = len.saturating_add(CONNECTION_CLOSE_LINE.len());
    } else if matches!(res.version, WireVersion::Http10) {
        len = len.saturating_add(CONNECTION_KEEPALIVE_LINE.len());
    }

    // End-to-end fields
    len = len.saturating_add(end_to_end_fields_len(
        &res.headers,
        is_response_reserved_prefix,
    )?);

    // CRLF ending the head
    len = len.saturating_add(2);

    Ok(len)
}

/// Writes the full response head (status line + all header fields) into
/// `out`. Does NOT write the body.
///
/// Applies the bodyless-by-status rule and the `HEAD` exception before ever
/// looking at `body` (#37 response step 2, #724 BLOCKING 5): see
/// [`write_response_framing`].
///
/// # Errors
/// `ConnectionSpecificField` when a header in `res.headers` is hop-by-hop
/// (the release-mode backstop, mirroring the request side) or cannot be
/// read back. `FieldNameInvalidByte` / `FieldValueInvalidByte` when a field
/// fails validation on the way out.
///
/// On EVERY error path `out` is truncated back to the length it had on
/// entry, exactly as `serialize_request_head`.
pub fn serialize_response_head(
    res: &CanonicalResponse,
    request_method: Method,
    body: BodySource,
    keep_alive: bool,
    out: &mut BytesMut,
) -> Result<usize, RejectReason> {
    let start = out.len();
    match write_response_head(res, request_method, body, keep_alive, out) {
        Ok(()) => Ok(out.len().saturating_sub(start)),
        Err(e) => {
            out.truncate(start);
            Err(e)
        }
    }
}

/// The body of [`serialize_response_head`], with no truncate-on-error
/// bookkeeping of its own (the caller does that once, around the whole
/// call).
fn write_response_head(
    res: &CanonicalResponse,
    request_method: Method,
    body: BodySource,
    keep_alive: bool,
    out: &mut BytesMut,
) -> Result<(), RejectReason> {
    // Status line: "HTTP/1.1 " + status code + SP + optional reason + CRLF.
    // The SP is unconditional: RFC 9112 Section 4 makes it part of the
    // grammar even when the reason phrase is zero length (#724 `SHOULD_FIX`
    // 5).
    out.extend_from_slice(b"HTTP/1.1 ");
    write_status_code(res.status.as_u16(), out);
    out.put_u8(b' ');
    let reason = canonical_reason(res.status.as_u16());
    if !reason.is_empty() {
        out.extend_from_slice(reason);
    }
    out.extend_from_slice(CRLF);

    // Framing field, bodyless-by-status and HEAD rules applied first.
    write_response_framing(res.status, request_method, body, out);

    // Connection field
    if !keep_alive {
        out.extend_from_slice(CONNECTION_CLOSE_LINE);
    } else if matches!(res.version, WireVersion::Http10) {
        out.extend_from_slice(CONNECTION_KEEPALIVE_LINE);
    }

    // End-to-end fields
    write_end_to_end_fields(&res.headers, is_response_reserved_prefix, out)?;

    // CRLF ending the head
    out.extend_from_slice(CRLF);

    Ok(())
}

// ---------------------------------------------------------------------------
// Reason phrases
// ---------------------------------------------------------------------------

/// The canonical reason phrase for `code`, or an empty slice for a code with
/// no entry in this table (RFC 9112 Section 4 permits a zero-length
/// `reason-phrase`, and the status line's SP separator is written
/// unconditionally either way -- see [`write_response_head`]).
///
/// Used only by [`serialize_response_head`] and
/// [`serialize_response_head_len`]: the phrase never comes from the
/// upstream, always from this fixed table, so a response we emit is
/// byte-identical for a given status regardless of what the origin said.
/// Exactly the 49 codes #37's Design section lists, including `103 Early
/// Hints` (RFC 8297); `418`, `510` and `599` are deliberately absent (an
/// empty phrase is correct for those here, even though some have phrases in
/// the wider registry).
#[must_use]
const fn canonical_reason(code: u16) -> &'static [u8] {
    match code {
        100 => b"Continue",
        101 => b"Switching Protocols",
        103 => b"Early Hints",
        200 => b"OK",
        201 => b"Created",
        202 => b"Accepted",
        203 => b"Non-Authoritative Information",
        204 => b"No Content",
        205 => b"Reset Content",
        206 => b"Partial Content",
        300 => b"Multiple Choices",
        301 => b"Moved Permanently",
        302 => b"Found",
        303 => b"See Other",
        304 => b"Not Modified",
        305 => b"Use Proxy",
        307 => b"Temporary Redirect",
        308 => b"Permanent Redirect",
        400 => b"Bad Request",
        401 => b"Unauthorized",
        402 => b"Payment Required",
        403 => b"Forbidden",
        404 => b"Not Found",
        405 => b"Method Not Allowed",
        406 => b"Not Acceptable",
        407 => b"Proxy Authentication Required",
        408 => b"Request Timeout",
        409 => b"Conflict",
        410 => b"Gone",
        411 => b"Length Required",
        412 => b"Precondition Failed",
        413 => b"Content Too Large",
        414 => b"URI Too Long",
        415 => b"Unsupported Media Type",
        416 => b"Range Not Satisfiable",
        417 => b"Expectation Failed",
        421 => b"Misdirected Request",
        422 => b"Unprocessable Content",
        426 => b"Upgrade Required",
        429 => b"Too Many Requests",
        431 => b"Request Header Fields Too Large",
        451 => b"Unavailable For Legal Reasons",
        500 => b"Internal Server Error",
        501 => b"Not Implemented",
        502 => b"Bad Gateway",
        503 => b"Service Unavailable",
        504 => b"Gateway Timeout",
        505 => b"HTTP Version Not Supported",
        511 => b"Network Authentication Required",
        _ => b"",
    }
}

// ---------------------------------------------------------------------------
// Shared writing helpers
// ---------------------------------------------------------------------------

/// Writes the three ASCII digits of a status code into `out`. `code` is
/// guaranteed by [`crate::scalar::StatusCode`] construction to be in
/// `100..=599`.
fn write_status_code(code: u16, out: &mut BytesMut) {
    let hundreds = code.checked_div(100).unwrap_or(0);
    let remaining = code.checked_rem(100).unwrap_or(0);
    let tens = remaining.checked_div(10).unwrap_or(0);
    let ones = remaining.checked_rem(10).unwrap_or(0);
    let h = u8::try_from(hundreds).unwrap_or(0).saturating_add(b'0');
    let t = u8::try_from(tens).unwrap_or(0).saturating_add(b'0');
    let o = u8::try_from(ones).unwrap_or(0).saturating_add(b'0');
    out.put_u8(h);
    out.put_u8(t);
    out.put_u8(o);
}

/// Writes the `Content-Length` or `Transfer-Encoding` header for `body`.
/// Never reads inbound framing fields. Shares [`CONTENT_LENGTH_PREFIX`] and
/// [`TRANSFER_ENCODING_CHUNKED_LINE`] with [`framing_len`].
fn write_framing(body: BodySource, out: &mut BytesMut) {
    match body {
        BodySource::None => {}
        BodySource::Exact { len } => {
            out.extend_from_slice(CONTENT_LENGTH_PREFIX);
            write_u64(len, out);
            out.extend_from_slice(CRLF);
        }
        BodySource::Streaming => out.extend_from_slice(TRANSFER_ENCODING_CHUNKED_LINE),
    }
}

/// Writes the `Connection` header for the request path according to
/// `mode`. The outbound version is always `HTTP/1.1` (#724 BLOCKING 6), so
/// there is no version parameter: `KeepAlive` always writes nothing, since
/// `HTTP/1.1` implies a persistent connection by default and forcing the
/// version is what makes the old `HTTP/1.0`-implies-`keep-alive` branch
/// dead code rather than a live bug.
fn write_connection(mode: ConnectionMode, out: &mut BytesMut) {
    if matches!(mode, ConnectionMode::Close) {
        out.extend_from_slice(CONNECTION_CLOSE_LINE);
    }
}

/// Writes every end-to-end field in `headers` that is not connection-specific
/// (`Host`, `Te`, see [`skip_field`]) and not reserved-prefix, in stable
/// slot order, validating every name and value with [`validate_name`] /
/// [`validate_value`] on the way out (#724 `SHOULD_FIX` 1: checked
/// construction on egress too, not merely a second look at bytes ingress
/// already checked).
///
/// `reserved_prefix` is the direction-specific check: [`is_reserved_prefix`]
/// for a request, [`is_response_reserved_prefix`] for a response (#724
/// `SHOULD_FIX` 4).
///
/// # Errors
/// `ConnectionSpecificField` when a hop-by-hop field survived to here: the
/// release-mode backstop against a filter or native extension that mutated
/// the section after `CanonicalRequestBuilder::build` / `CanonicalResponse::new`
/// ran (#724 `SHOULD_FIX` 2). This is the last code that touches the message,
/// and it holds in release, not only behind a `debug_assert`. `FieldNameInvalidByte`
/// when a slot cannot be read back -- substituting `b""` would write a field
/// with a silently emptied value, which is a different message from the one
/// routed and authorized. Whatever [`validate_name`] / [`validate_value`]
/// returns when a name or value fails validation.
fn write_end_to_end_fields(
    headers: &FieldSection,
    reserved_prefix: fn(&[u8]) -> bool,
    out: &mut BytesMut,
) -> Result<(), RejectReason> {
    for (i, slot) in headers.slots().iter().enumerate() {
        if is_hop_by_hop(slot.known) {
            return Err(RejectReason::ConnectionSpecificField);
        }
        if skip_field(slot.known) {
            continue;
        }
        let (Some(name), Some(value)) = (headers.name_at(i), headers.value_at(i)) else {
            return Err(RejectReason::FieldNameInvalidByte);
        };
        if reserved_prefix(name) {
            continue;
        }
        validate_name(name, WireVersion::Http11)?;
        validate_value(value, WireVersion::Http11)?;
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(CRLF);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalRequestBuilder;
    use crate::field::UnderscorePolicy;
    use crate::framing::{OtherCodings, RequestFraming};
    use crate::h1::H1Parser;
    use crate::h1::canonicalize::{H1Context, canonicalize_request};
    use crate::limits::{ClampedLimits, Limits};
    use crate::path::{NormalizedPath, PathPolicy, RawQuery};
    use crate::peer::{IdentitySource, PeerIdentity, TrustPolicy};
    use crate::response::ResponseFraming;
    use crate::scalar::ParseStatus;
    use crate::section::FieldSectionBuilder;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const DEFAULT_TRUST: TrustPolicy = TrustPolicy::None;

    fn clamped() -> ClampedLimits {
        Limits::DEFAULT.clamped()
    }

    fn authority(host: &[u8]) -> Authority {
        let limits = clamped();
        let mut out = BytesMut::new();
        Authority::parse_into(host, Scheme::Https, &limits, &mut out).expect("valid authority")
    }

    fn path_query(raw: &[u8]) -> (NormalizedPath, Option<RawQuery>) {
        let limits = clamped();
        let mut out = BytesMut::new();
        NormalizedPath::parse_into(raw, &PathPolicy::DEFAULT, &limits, &mut out)
            .expect("valid path")
    }

    fn peer_v4() -> PeerIdentity {
        PeerIdentity {
            client: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            client_port: Some(54321),
            source: IdentitySource::Socket,
            forwarded_proto: None,
            trusted_hops: 0,
            peer_trusted: false,
        }
    }

    fn peer_v6() -> PeerIdentity {
        PeerIdentity {
            client: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            client_port: Some(443),
            source: IdentitySource::Socket,
            forwarded_proto: None,
            trusted_hops: 0,
            peer_trusted: false,
        }
    }

    fn peer_no_port() -> PeerIdentity {
        PeerIdentity {
            client_port: None,
            ..peer_v4()
        }
    }

    fn local_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080)
    }

    fn fields_with(pairs: &[(&[u8], &[u8])]) -> FieldSection {
        let limits = clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        for (name, value) in pairs {
            builder.push(&mut arena, name, value).expect("valid field");
        }
        builder.finish(&mut arena)
    }

    fn no_emit() -> ForwardEmit {
        ForwardEmit {
            emit_forwarded: false,
            emit_x_forwarded: false,
        }
    }

    fn both_emit() -> ForwardEmit {
        ForwardEmit {
            emit_forwarded: true,
            emit_x_forwarded: true,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test helper mirroring CanonicalRequestBuilder's own eight required parts"
    )]
    fn request_with(
        method: Method,
        host: &[u8],
        raw_path: &[u8],
        headers: FieldSection,
        framing: RequestFraming,
        version: WireVersion,
        peer: PeerIdentity,
    ) -> CanonicalRequest {
        let (path, query) = path_query(raw_path);
        CanonicalRequestBuilder::new()
            .method(method)
            .scheme(Scheme::Https)
            .authority(authority(host))
            .path(path, query)
            .headers(headers)
            .framing(framing)
            .version(version)
            .peer(peer)
            .build()
            .expect("valid request")
    }

    fn get_request(headers: FieldSection) -> CanonicalRequest {
        request_with(
            Method::Get,
            b"example.com",
            b"/a",
            headers,
            RequestFraming::Empty,
            WireVersion::Http11,
            peer_v4(),
        )
    }

    /// Bypasses `CanonicalRequestBuilder::build`'s I2 invariant check,
    /// standing in for a filter or native extension that mutated the
    /// section AFTER the build ran. Every field of `CanonicalRequest` is
    /// `pub`, so a struct literal is the test-only helper #37 calls for at
    /// edge cases 5, 5b and 5c: I2 is enforced once, at construction, and
    /// this proves the serializer's OWN backstop still holds when that
    /// enforcement is skipped.
    fn request_with_raw_headers(headers: FieldSection) -> CanonicalRequest {
        let (path, query) = path_query(b"/a");
        CanonicalRequest {
            method: Method::Get,
            scheme: Scheme::Https,
            authority: authority(b"example.com"),
            path,
            query,
            headers,
            framing: RequestFraming::Empty,
            version: WireVersion::Http11,
            peer: peer_v4(),
        }
    }

    /// The response-side twin of [`request_with_raw_headers`]: bypasses
    /// `CanonicalResponse::new`'s invariant check the same way.
    fn response_with_raw_headers(status: StatusCode, headers: FieldSection) -> CanonicalResponse {
        CanonicalResponse {
            status,
            headers,
            framing: ResponseFraming::Empty,
            version: WireVersion::Http11,
        }
    }

    fn response_with(status: StatusCode, headers: FieldSection) -> CanonicalResponse {
        CanonicalResponse::new(status, headers, ResponseFraming::Empty, WireVersion::Http11)
            .expect("valid response")
    }

    fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
        if needle.is_empty() || haystack.len() < needle.len() {
            return 0;
        }
        haystack
            .windows(needle.len())
            .filter(|w| *w == needle)
            .count()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        occurrences(haystack, needle) > 0
    }

    /// Case-insensitive occurrence count. Field NAMES are case-insensitive
    /// on the wire (RFC 9110 Section 5.1), so a duplicate `Host` field is a
    /// duplicate whether the second copy is spelled `Host:` or `host:`; a
    /// case-sensitive count would miss the raw section slot (which keeps
    /// whatever case the test constructed it with) sitting next to the
    /// generated `Host:` (always title-case).
    fn occurrences_ci(haystack: &[u8], needle: &[u8]) -> usize {
        let lower_hay: Vec<u8> = haystack.iter().map(u8::to_ascii_lowercase).collect();
        let lower_needle: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
        occurrences(&lower_hay, &lower_needle)
    }

    /// Case-insensitive presence check. Field NAMES this module writes are
    /// title-case (`Content-Length`, `Transfer-Encoding`, `Host`) while the
    /// negative assertions below are written lowercase for readability; a
    /// plain byte-exact `contains` would never find the lowercase needle in
    /// the title-case haystack and so would ALWAYS report "absent" whether
    /// or not the field is really there, making the assertion vacuous.
    fn absent_ci(haystack: &[u8], needle: &[u8]) -> bool {
        occurrences_ci(haystack, needle) == 0
    }

    // -----------------------------------------------------------------
    // 1. corpus_table -- edge cases 1-15 (request-side; 16-18 are covered
    //    by response_bodyless_rules, 5b/5c by hop_by_hop_never_reaches_the_wire).
    // -----------------------------------------------------------------

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table of edge cases the issue names by number; splitting it would break \
                  the 1:1 mapping to that numbered list, mirroring h1::canonicalize::tests::corpus_table"
    )]
    fn corpus_table() {
        let req = get_request(fields_with(&[(b"accept", b"*/*")]));

        // Edge case 1: BodySource::None on a request.
        let mut out = BytesMut::new();
        serialize_request_head(
            &req,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(absent_ci(&out, b"content-length"));
        assert!(absent_ci(&out, b"transfer-encoding"));

        // Edge case 2: BodySource::Exact { len: 0 } writes content-length: 0.
        let mut out = BytesMut::new();
        serialize_request_head(
            &req,
            TargetForm::Origin,
            BodySource::Exact { len: 0 },
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(contains(&out, b"Content-Length: 0\r\n"));

        // Edge case 3: BodySource::Exact { len: u64::MAX } writes the
        // 20-digit decimal value correctly.
        let mut out = BytesMut::new();
        serialize_request_head(
            &req,
            TargetForm::Origin,
            BodySource::Exact { len: u64::MAX },
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(contains(
            &out,
            format!("Content-Length: {}\r\n", u64::MAX).as_bytes()
        ));

        // Edge case 4: BodySource::Streaming writes transfer-encoding:
        // chunked, never content-length.
        let mut out = BytesMut::new();
        serialize_request_head(
            &req,
            TargetForm::Origin,
            BodySource::Streaming,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(contains(&out, b"Transfer-Encoding: chunked\r\n"));
        assert!(absent_ci(&out, b"content-length"));

        // Edge case 5: a section still containing content-length is
        // refused, via the test-only bypass helper.
        let poisoned = request_with_raw_headers(fields_with(&[
            (b"content-length", b"5"),
            (b"accept", b"*/*"),
        ]));
        let mut out = BytesMut::new();
        let result = serialize_request_head(
            &poisoned,
            TargetForm::Origin,
            BodySource::Exact { len: 5 },
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        );
        assert!(matches!(result, Err(RejectReason::ConnectionSpecificField)));
        assert!(out.is_empty());

        // Edge case 6: a section containing host is the normal case; the
        // slot is skipped and exactly one Host field, generated from
        // req.authority, appears.
        let mut out = BytesMut::new();
        serialize_request_head(
            &req,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert_eq!(occurrences_ci(&out, b"host:"), 1, "out: {out:?}");

        // Edge case 7: TargetForm::Origin with no query writes /path.
        let no_query = get_request(fields_with(&[]));
        let mut out = BytesMut::new();
        serialize_request_head(
            &no_query,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(out.starts_with(b"GET /a HTTP/1.1\r\n"), "out: {out:?}");

        // Edge case 8: TargetForm::Origin with an empty query writes /path?.
        let empty_query = request_with(
            Method::Get,
            b"example.com",
            b"/a?",
            fields_with(&[]),
            RequestFraming::Empty,
            WireVersion::Http11,
            peer_v4(),
        );
        let mut out = BytesMut::new();
        serialize_request_head(
            &empty_query,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(out.starts_with(b"GET /a? HTTP/1.1\r\n"), "out: {out:?}");

        // Edge case 9: TargetForm::Asterisk writes a single *.
        let mut out = BytesMut::new();
        serialize_request_head(
            &req,
            TargetForm::Asterisk,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(out.starts_with(b"GET * HTTP/1.1\r\n"), "out: {out:?}");

        // Edge case 10: TargetForm::Authority with CONNECT and no explicit
        // port writes host:443 for https.
        let connect_req = request_with(
            Method::Connect,
            b"example.com",
            b"/",
            fields_with(&[]),
            RequestFraming::Empty,
            WireVersion::Http11,
            peer_v4(),
        );
        let mut out = BytesMut::new();
        serialize_request_head(
            &connect_req,
            TargetForm::Authority,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(
            out.starts_with(b"CONNECT example.com:443 HTTP/1.1\r\n"),
            "out: {out:?}"
        );

        // Edge case 11: TargetForm::Absolute is refused.
        let mut out = BytesMut::new();
        let result = serialize_request_head(
            &req,
            TargetForm::Absolute,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        );
        assert!(matches!(result, Err(RejectReason::TargetFormInvalid)));
        assert!(out.is_empty());

        // Edge case 12: an inbound HTTP/1.0 request is written as HTTP/1.1.
        let http10 = request_with(
            Method::Get,
            b"example.com",
            b"/a",
            fields_with(&[]),
            RequestFraming::Empty,
            WireVersion::Http10,
            peer_v4(),
        );
        let mut out = BytesMut::new();
        serialize_request_head(
            &http10,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::KeepAlive,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(out.starts_with(b"GET /a HTTP/1.1\r\n"), "out: {out:?}");
        assert!(!contains(&out, b"HTTP/1.0"));

        // Edge case 13: emit_forwarded and emit_x_forwarded both false
        // writes neither identity field.
        let mut out = BytesMut::new();
        serialize_request_head(
            &req,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(!contains(&out, b"orwarded"));

        // Edge case 14: emit_x_forwarded true with an unknown client port
        // omits x-forwarded-port entirely.
        let no_port_req = request_with(
            Method::Get,
            b"example.com",
            b"/a",
            fields_with(&[]),
            RequestFraming::Empty,
            WireVersion::Http11,
            peer_no_port(),
        );
        let mut out = BytesMut::new();
        serialize_request_head(
            &no_port_req,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            both_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(contains(&out, b"X-Forwarded-For:"));
        assert!(!contains(&out, b"X-Forwarded-Port:"));

        // Edge case 15 is covered directly by `out_is_truncated_on_error`:
        // a value that fails the egress validation tables refuses and
        // truncates `out` back to its entry length. Here we only pin the
        // companion positive case, that a well-formed custom field DOES
        // reach the wire unmodified.
        let req_ok = request_with_raw_headers(fields_with(&[(b"x-a", b"good")]));
        let mut out = BytesMut::new();
        serialize_request_head(
            &req_ok,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(contains(&out, b"x-a: good\r\n"));
    }

    // -----------------------------------------------------------------
    // 2. framing_comes_only_from_body
    // -----------------------------------------------------------------

    #[test]
    fn framing_comes_only_from_body() {
        // Inbound framing was Exact { len: 5 }; the OUTBOUND BodySource is
        // what decides what is written, and the inbound 5 must appear
        // nowhere (Envoy CVE-2026-48743: a stale inbound length reaching
        // the wire is exactly the request-smuggling bug this issue closes).
        let req = request_with(
            Method::Post,
            b"example.com",
            b"/a",
            fields_with(&[(b"accept", b"*/*")]),
            RequestFraming::Exact { len: 5 },
            WireVersion::Http11,
            peer_v4(),
        );

        let mut out = BytesMut::new();
        serialize_request_head(
            &req,
            TargetForm::Origin,
            BodySource::Streaming,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(contains(&out, b"Transfer-Encoding: chunked\r\n"));
        assert!(absent_ci(&out, b"content-length"));
        assert!(!contains(&out, b"Content-Length: 5"));

        let mut out = BytesMut::new();
        serialize_request_head(
            &req,
            TargetForm::Origin,
            BodySource::Exact { len: 9 },
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(contains(&out, b"Content-Length: 9\r\n"));
        assert!(absent_ci(&out, b"transfer-encoding"));
        assert!(!contains(&out, b": 5\r\n"), "the inbound value 5 leaked");
    }

    // -----------------------------------------------------------------
    // 3. at_most_one_framing_field
    // -----------------------------------------------------------------

    #[test]
    fn at_most_one_framing_field() {
        let req = get_request(fields_with(&[]));
        for body in [
            BodySource::None,
            BodySource::Exact { len: 3 },
            BodySource::Streaming,
        ] {
            let mut out = BytesMut::new();
            serialize_request_head(
                &req,
                TargetForm::Origin,
                body,
                ConnectionMode::Close,
                no_emit(),
                local_addr(),
                &mut out,
            )
            .unwrap();
            let cl = occurrences_ci(&out, b"content-length:");
            let te = occurrences_ci(&out, b"transfer-encoding:");
            assert!(
                cl <= 1,
                "{body:?}: content-length appeared {cl} times, out: {out:?}"
            );
            assert!(
                te <= 1,
                "{body:?}: transfer-encoding appeared {te} times, out: {out:?}"
            );
            // Never BOTH at once, whatever `body` is: exactly one framing
            // field is written, or none (#37's own invariant list).
            assert!(
                cl == 0 || te == 0,
                "{body:?}: both content-length and transfer-encoding present, out: {out:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // 4. host_is_generated
    // -----------------------------------------------------------------

    #[test]
    fn host_is_generated() {
        // With a host slot present -- the normal case: strip_ingress
        // deliberately leaves the inbound `host` field in the section
        // (canonicalize_request's host_field relies on it still being
        // there), so a real CanonicalRequest's headers carry one. Without
        // the fix, `write_end_to_end_fields` writes this raw slot on top of
        // the authoritative `Host` generated in step 2, producing two
        // `Host` fields (#724 BLOCKING 1).
        let with_host = get_request(fields_with(&[
            (b"host", b"example.com"),
            (b"accept", b"*/*"),
        ]));
        let mut out = BytesMut::new();
        serialize_request_head(
            &with_host,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert_eq!(occurrences_ci(&out, b"host:"), 1, "out: {out:?}");
        assert!(contains(&out, b"Host: example.com\r\n"), "out: {out:?}");

        // Without a host slot at all: still exactly one Host, generated.
        let without_host = get_request(fields_with(&[(b"accept", b"*/*")]));
        let mut out = BytesMut::new();
        serialize_request_head(
            &without_host,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert_eq!(occurrences_ci(&out, b"host:"), 1, "out: {out:?}");
    }

    // -----------------------------------------------------------------
    // 5. always_http_11_upstream
    // -----------------------------------------------------------------

    #[test]
    fn always_http_11_upstream() {
        let http10 = request_with(
            Method::Post,
            b"example.com",
            b"/a",
            fields_with(&[]),
            RequestFraming::Empty,
            WireVersion::Http10,
            peer_v4(),
        );
        let mut out = BytesMut::new();
        serialize_request_head(
            &http10,
            TargetForm::Origin,
            BodySource::Streaming,
            ConnectionMode::KeepAlive,
            no_emit(),
            local_addr(),
            &mut out,
        )
        .unwrap();
        assert!(out.starts_with(b"POST /a HTTP/1.1\r\n"), "out: {out:?}");
        assert!(!contains(&out, b"HTTP/1.0"));
        // Once the outbound version is forced to 1.1, KeepAlive on the
        // (formerly) HTTP/1.0 case must not still emit keep-alive (#724
        // BLOCKING 6).
        assert!(!contains(&out, b"Connection: keep-alive"));
    }

    // -----------------------------------------------------------------
    // 6. len_matches_written -- edge case 27: 36 combinations.
    // -----------------------------------------------------------------

    #[test]
    fn len_matches_written() {
        let bodies = [
            BodySource::None,
            BodySource::Exact { len: 7 },
            BodySource::Streaming,
        ];
        let forms = [
            TargetForm::Origin,
            TargetForm::Asterisk,
            TargetForm::Authority,
        ];
        let emits = [no_emit(), both_emit()];
        let peers = [peer_v4(), peer_v6()];

        let mut checked = 0_usize;
        let mut mismatches = Vec::new();
        for &body in &bodies {
            for &form in &forms {
                for &emit in &emits {
                    for peer in &peers {
                        let method = if matches!(form, TargetForm::Authority) {
                            Method::Connect
                        } else {
                            Method::Get
                        };
                        let req = request_with(
                            method,
                            b"example.com",
                            b"/a",
                            fields_with(&[(b"x-a", b"v")]),
                            RequestFraming::Empty,
                            WireVersion::Http11,
                            *peer,
                        );
                        let predicted = serialize_request_head_len(
                            &req,
                            form,
                            body,
                            ConnectionMode::KeepAlive,
                            emit,
                            local_addr(),
                        )
                        .unwrap();
                        let mut out = BytesMut::new();
                        let written = serialize_request_head(
                            &req,
                            form,
                            body,
                            ConnectionMode::KeepAlive,
                            emit,
                            local_addr(),
                            &mut out,
                        )
                        .unwrap();
                        checked += 1;
                        if predicted != written || written != out.len() {
                            mismatches.push(format!(
                                "body={body:?} form={form:?} emit={emit:?} peer={:?}: \
                                 predicted={predicted} written={written} out.len()={} \
                                 (delta {})",
                                peer.client,
                                out.len(),
                                i64::try_from(written).unwrap_or(i64::MAX)
                                    - i64::try_from(predicted).unwrap_or(i64::MAX)
                            ));
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 36, "expected exactly 36 combinations");
        assert!(
            mismatches.is_empty(),
            "{} of {checked} combinations disagree:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    // -----------------------------------------------------------------
    // 7. out_is_truncated_on_error -- edge case 15.
    // -----------------------------------------------------------------

    #[test]
    fn out_is_truncated_on_error() {
        // A hop-by-hop field reached deep enough into the walk that some
        // fields would already have been written by a version of this
        // function that did not truncate: put a normal field FIRST, then
        // the poison.
        let poisoned = request_with_raw_headers(fields_with(&[
            (b"accept", b"*/*"),
            (b"connection", b"upgrade"),
        ]));
        let mut out = BytesMut::new();
        out.extend_from_slice(b"prior data");
        let recorded_len = out.len();
        let result = serialize_request_head(
            &poisoned,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        );
        assert!(matches!(result, Err(RejectReason::ConnectionSpecificField)));
        assert_eq!(out.len(), recorded_len, "out must be truncated on error");
        assert_eq!(&out[..], b"prior data");
    }

    // -----------------------------------------------------------------
    // 7b. hop_by_hop_never_reaches_the_wire -- edge cases 5, 5b, 5c.
    // -----------------------------------------------------------------

    #[test]
    fn hop_by_hop_never_reaches_the_wire() {
        // All ten members of strip::STATIC_STRIP, named by literal (the
        // set is private to strip.rs; this list is the set is_hop_by_hop
        // answers true for -- see strip.rs's own doc comment on it).
        let static_strip: &[(&[u8], &[u8])] = &[
            (b"connection", b"close"),
            (b"proxy-connection", b"close"),
            (b"keep-alive", b"timeout=5"),
            (b"transfer-encoding", b"chunked"),
            (b"content-length", b"5"),
            (b"upgrade", b"h2c"),
            (b"http2-settings", b"AAMAAABkAAQAAP__"),
            (b"trailer", b"x-checksum"),
            (b"proxy-authenticate", b"Basic"),
            (b"proxy-authorization", b"Basic abc"),
        ];

        for (name, value) in static_strip {
            let req = request_with_raw_headers(fields_with(&[(b"accept", b"*/*"), (name, value)]));
            let mut out = BytesMut::new();
            let result = serialize_request_head(
                &req,
                TargetForm::Origin,
                BodySource::None,
                ConnectionMode::Close,
                no_emit(),
                local_addr(),
                &mut out,
            );
            assert!(
                matches!(result, Err(RejectReason::ConnectionSpecificField)),
                "{name:?} must be refused, got {result:?}"
            );
            assert!(out.is_empty(), "{name:?}: out must stay empty");
        }

        // A filter mutating the section to contain connection: upgrade +
        // upgrade: h2c: the h2c-smuggling-on-our-own-connection case.
        let h2c = request_with_raw_headers(fields_with(&[
            (b"connection", b"upgrade"),
            (b"upgrade", b"h2c"),
        ]));
        let mut out = BytesMut::new();
        let result = serialize_request_head(
            &h2c,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        );
        assert!(matches!(result, Err(RejectReason::ConnectionSpecificField)));
        assert!(out.is_empty());

        // te: trailers is NOT hop-by-hop and must serialize successfully.
        let te = request_with_raw_headers(fields_with(&[(b"te", b"trailers")]));
        let mut out = BytesMut::new();
        let result = serialize_request_head(
            &te,
            TargetForm::Origin,
            BodySource::None,
            ConnectionMode::Close,
            no_emit(),
            local_addr(),
            &mut out,
        );
        assert!(
            result.is_ok(),
            "te: trailers must serialize, got {result:?}"
        );
    }

    // -----------------------------------------------------------------
    // 8. chunked_encoder -- edge cases 19-26.
    // -----------------------------------------------------------------

    #[test]
    fn chunked_encoder() {
        // 19: empty data writes nothing, returns 0.
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        assert_eq!(enc.write_chunk(b"", &mut out), 0);
        assert!(out.is_empty());

        // 20: 1 byte.
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        let written = enc.write_chunk(b"X", &mut out);
        assert_eq!(written, 6);
        assert_eq!(&out[..], b"1\r\nX\r\n");

        // 21: 4096 bytes.
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        let data = vec![b'A'; 4096];
        enc.write_chunk(&data, &mut out);
        assert!(out.starts_with(b"1000\r\n"));
        assert!(out.ends_with(b"\r\n"));
        assert_eq!(&out[6..6 + 4096], &data[..]);

        // A zero-length write between two real chunks must not inject a
        // terminal chunk mid-body (#724 BLOCKING 2).
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        enc.write_chunk(b"AAAA", &mut out);
        enc.write_chunk(b"", &mut out);
        enc.write_chunk(b"BBBB", &mut out);
        assert_eq!(&out[..], b"4\r\nAAAA\r\n4\r\nBBBB\r\n");

        // 22: finish with no trailers.
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        let empty_trailers = fields_with(&[]);
        let written = enc.finish(&empty_trailers, &mut out).unwrap();
        assert_eq!(written, 5);
        assert_eq!(&out[..], b"0\r\n\r\n");

        // 23: finish with one allowed trailer.
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        let one_trailer = fields_with(&[(b"x-checksum", b"abc")]);
        enc.finish(&one_trailer, &mut out).unwrap();
        assert_eq!(&out[..], b"0\r\nx-checksum: abc\r\n\r\n");

        // 24: finish with a denied trailer.
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        let denied_trailer = fields_with(&[(b"content-length", b"5")]);
        let result = enc.finish(&denied_trailer, &mut out);
        assert!(matches!(result, Err(RejectReason::TrailerFieldForbidden)));
        assert!(out.is_empty());

        // 25: finish twice; the second call writes nothing, returns Ok(0).
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        let first = enc.finish(&empty_trailers, &mut out).unwrap();
        let after_first = out.len();
        let second = enc.finish(&empty_trailers, &mut out).unwrap();
        assert_eq!(first, 5);
        assert_eq!(second, 0);
        assert_eq!(
            out.len(),
            after_first,
            "finish must write nothing the second time"
        );
        assert!(enc.is_finished());

        // write_chunk after finish must also refuse (#724 BLOCKING 3):
        // "finish is not idempotent and write_chunk ignores `finished`".
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        enc.finish(&empty_trailers, &mut out).unwrap();
        let before = out.len();
        let n = enc.write_chunk(b"late", &mut out);
        assert_eq!(n, 0);
        assert_eq!(
            out.len(),
            before,
            "write_chunk after finish must write nothing"
        );

        // 26: 100 one-byte inbound chunks forwarded as one 100-byte write
        // produce exactly one outbound chunk (0x64 = 100).
        let mut enc = ChunkedEncoder::new();
        let mut out = BytesMut::new();
        let hundred = vec![b'z'; 100];
        enc.write_chunk(&hundred, &mut out);
        assert_eq!(
            occurrences(&out, b"\r\n"),
            2,
            "exactly one chunk boundary pair"
        );
        assert!(out.starts_with(b"64\r\n"));
    }

    // -----------------------------------------------------------------
    // 9. prop_roundtrip (proptest) -- property P-ROUNDTRIP.
    // -----------------------------------------------------------------

    fn ctx() -> H1Context<'static> {
        H1Context {
            limits: Limits::DEFAULT.clamped(),
            path_policy: PathPolicy::DEFAULT,
            codings: OtherCodings::Reject,
            underscores: UnderscorePolicy::Reject,
            scheme: Scheme::Https,
            socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            proxy_proto: None,
            trust: &DEFAULT_TRUST,
            default_authority: None,
            forward_proxy: false,
            will_buffer_body: false,
        }
    }

    fn method_strategy() -> impl Strategy<Value = Method> {
        prop_oneof![
            Just(Method::Get),
            Just(Method::Post),
            Just(Method::Put),
            Just(Method::Delete),
            Just(Method::Options),
        ]
    }

    fn authority_strategy() -> impl Strategy<Value = &'static [u8]> {
        prop_oneof![
            Just(&b"example.com"[..]),
            Just(&b"a.example.org"[..]),
            Just(&b"192.0.2.1"[..]),
            Just(&b"example.com:8080"[..]),
        ]
    }

    fn field_name_strategy() -> impl Strategy<Value = &'static [u8]> {
        prop_oneof![
            Just(&b"x-a"[..]),
            Just(&b"x-b"[..]),
            Just(&b"x-c"[..]),
            Just(&b"x-d"[..]),
            Just(&b"x-e"[..]),
            Just(&b"x-f"[..]),
            Just(&b"x-g"[..]),
            Just(&b"x-h"[..]),
            Just(&b"x-i"[..]),
            Just(&b"x-j"[..]),
        ]
    }

    fn field_value_strategy() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(0x21_u8..=0x7E, 0..=32)
    }

    #[derive(Clone, Copy, Debug)]
    enum FramingChoice {
        Empty,
        Exact(u16),
        Streaming,
    }

    fn framing_strategy() -> impl Strategy<Value = FramingChoice> {
        prop_oneof![
            Just(FramingChoice::Empty),
            (0_u16..=4096).prop_map(FramingChoice::Exact),
            Just(FramingChoice::Streaming),
        ]
    }

    fn path_strategy() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z]{1,6}", 0_usize..=3).prop_map(|segs| {
            if segs.is_empty() {
                "/".to_owned()
            } else {
                format!("/{}", segs.join("/"))
            }
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]
        #[test]
        fn prop_roundtrip(
            method in method_strategy(),
            host in authority_strategy(),
            raw_path in path_strategy(),
            query in proptest::option::of("[a-z]{1,6}"),
            fields in proptest::collection::vec((field_name_strategy(), field_value_strategy()), 0_usize..=12),
            framing_choice in framing_strategy(),
        ) {
            let limits = clamped();
            let mut arena = BytesMut::new();
            let mut builder = FieldSectionBuilder::new(&arena, &limits);
            // strip_ingress deliberately leaves the inbound `host` field in
            // the section (canonicalize_request's host_field relies on it
            // still being there), so a real CanonicalRequest's headers
            // always carry one. Without this, the property would never
            // reach the duplicate-Host defect (#724 BLOCKING 1) that
            // P-ROUNDTRIP exists to catch: the whole point of the property
            // is that this exact slot must be skipped, not re-emitted.
            let _ = builder.push(&mut arena, b"host", host);
            for (name, value) in &fields {
                // A generated (name, value) pair that fails field grammar
                // (should not happen given the strategies above, but the
                // property must not depend on it) is simply skipped rather
                // than poisoning the whole case.
                let _ = builder.push(&mut arena, name, value);
            }
            let headers = builder.finish(&mut arena);

            let full_path = match &query {
                Some(q) => format!("{raw_path}?{q}"),
                None => raw_path.clone(),
            };
            let (path, path_query_v) = {
                let limits = clamped();
                let mut out = BytesMut::new();
                match NormalizedPath::parse_into(full_path.as_bytes(), &PathPolicy::DEFAULT, &limits, &mut out) {
                    Ok(v) => v,
                    Err(_) => return Ok(()),
                }
            };

            let (req_framing, body) = match framing_choice {
                FramingChoice::Empty => (RequestFraming::Empty, BodySource::None),
                FramingChoice::Exact(n) => (
                    RequestFraming::Exact { len: u64::from(n) },
                    BodySource::Exact { len: u64::from(n) },
                ),
                FramingChoice::Streaming => (RequestFraming::Streamed, BodySource::Streaming),
            };

            let Ok(req) = CanonicalRequestBuilder::new()
                .method(method)
                .scheme(Scheme::Https)
                .authority(authority(host))
                .path(path, path_query_v)
                .headers(headers)
                .framing(req_framing)
                .version(WireVersion::Http11)
                .peer(peer_v4())
                .build()
            else {
                return Ok(());
            };

            let mut out = BytesMut::new();
            let Ok(written) = serialize_request_head(
                &req,
                TargetForm::Origin,
                body,
                ConnectionMode::Close,
                no_emit(),
                local_addr(),
                &mut out,
            ) else {
                return Ok(());
            };
            prop_assert_eq!(written, out.len());

            let parser = H1Parser::new(&limits, UnderscorePolicy::Reject);
            let raw = match parser.parse_request_head(&out) {
                Ok(ParseStatus::Complete { value, .. }) => value,
                other => panic!(
                    "RECANONICALIZE of our own head REFUSED at parse: {other:?} \
                     (framing_in={:?}) out={out:?}",
                    req.framing
                ),
            };
            let mut arena2 = BytesMut::new();
            let (req2, _, _) = match canonicalize_request(&raw, &ctx(), &mut arena2) {
                Ok(v) => v,
                Err(reason) => panic!(
                    "RECANONICALIZE of our own head REFUSED: {reason:?} (framing_in={:?})",
                    req.framing
                ),
            };

            prop_assert_eq!(req2.method.as_bytes(), req.method.as_bytes());
            prop_assert_eq!(req2.authority.host(), req.authority.host());
            prop_assert_eq!(req2.path.as_bytes(), req.path.as_bytes());
            prop_assert_eq!(
                req2.query.as_ref().map(crate::path::RawQuery::as_bytes),
                req.query.as_ref().map(crate::path::RawQuery::as_bytes)
            );
            prop_assert_eq!(req2.framing, req.framing);
        }
    }

    // -----------------------------------------------------------------
    // 10. response_bodyless_rules -- edge cases 16, 17, 18.
    // -----------------------------------------------------------------

    #[test]
    fn response_bodyless_rules() {
        // Edge case 16, correct usage: 204 with BodySource::None writes no
        // framing field.
        let no_content = response_with(StatusCode::NO_CONTENT, fields_with(&[]));
        let mut out = BytesMut::new();
        serialize_response_head(&no_content, Method::Get, BodySource::None, true, &mut out)
            .unwrap();
        assert!(absent_ci(&out, b"content-length"));
        assert!(absent_ci(&out, b"transfer-encoding"));

        // Edge case 16, mismatched usage: 204 with a non-None BodySource
        // debug_asserts (proving the status wins even when a caller passes
        // an inconsistent body, per #37's two-mode design). catch_unwind
        // keeps the panic from aborting the rest of this test.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut out = BytesMut::new();
            let _ = serialize_response_head(
                &no_content,
                Method::Get,
                BodySource::Exact { len: 5 },
                true,
                &mut out,
            );
        }));
        std::panic::set_hook(prev_hook);
        assert!(
            result.is_err(),
            "204 with a mismatched BodySource must debug_assert in this (debug) test build"
        );

        // 304 with BodySource::Streaming must not emit chunked framing.
        let not_modified = response_with(StatusCode::NOT_MODIFIED, fields_with(&[]));
        let mut out = BytesMut::new();
        serialize_response_head(&not_modified, Method::Get, BodySource::None, true, &mut out)
            .unwrap();
        assert!(absent_ci(&out, b"transfer-encoding"));
        assert!(absent_ci(&out, b"content-length"));

        // Edge case 17: a response to HEAD with BodySource::Exact { len:
        // 4096 } writes content-length: 4096 and no transfer-encoding.
        let ok = response_with(StatusCode::OK, fields_with(&[]));
        let mut out = BytesMut::new();
        serialize_response_head(
            &ok,
            Method::Head,
            BodySource::Exact { len: 4096 },
            true,
            &mut out,
        )
        .unwrap();
        assert!(contains(&out, b"Content-Length: 4096\r\n"));
        assert!(absent_ci(&out, b"transfer-encoding"));

        // Same response, BodySource::None: no framing field at all.
        let mut out = BytesMut::new();
        serialize_response_head(&ok, Method::Head, BodySource::None, true, &mut out).unwrap();
        assert!(absent_ci(&out, b"content-length"));
        assert!(absent_ci(&out, b"transfer-encoding"));

        // Edge case 18: an unknown status (599) gets an empty reason
        // phrase, but the SP after the status code is still written.
        let unknown = response_with(
            StatusCode::from_u16(599).expect("599 in range"),
            fields_with(&[]),
        );
        let mut out = BytesMut::new();
        serialize_response_head(&unknown, Method::Get, BodySource::None, true, &mut out).unwrap();
        // The SP after the status code is unconditional (RFC 9112 Section
        // 4): an empty reason phrase does not remove it (#724 `SHOULD_FIX` 5).
        assert!(out.starts_with(b"HTTP/1.1 599 \r\n"), "out: {out:?}");
    }

    /// Every arm of `canonical_reason` matches #37's Design section exactly:
    /// all 49 listed codes, row by row, and an empty phrase for 418, 510
    /// and 599, which are deliberately absent from the table. Kills
    /// mutation M8 (`canonical_reason` returning the empty phrase for
    /// every status), which the review found surviving because no test
    /// asserted the table's content at all.
    #[test]
    fn reason_phrase_table_matches_37() {
        let rows: &[(u16, &[u8])] = &[
            (100, b"Continue"),
            (101, b"Switching Protocols"),
            (103, b"Early Hints"),
            (200, b"OK"),
            (201, b"Created"),
            (202, b"Accepted"),
            (203, b"Non-Authoritative Information"),
            (204, b"No Content"),
            (205, b"Reset Content"),
            (206, b"Partial Content"),
            (300, b"Multiple Choices"),
            (301, b"Moved Permanently"),
            (302, b"Found"),
            (303, b"See Other"),
            (304, b"Not Modified"),
            (305, b"Use Proxy"),
            (307, b"Temporary Redirect"),
            (308, b"Permanent Redirect"),
            (400, b"Bad Request"),
            (401, b"Unauthorized"),
            (402, b"Payment Required"),
            (403, b"Forbidden"),
            (404, b"Not Found"),
            (405, b"Method Not Allowed"),
            (406, b"Not Acceptable"),
            (407, b"Proxy Authentication Required"),
            (408, b"Request Timeout"),
            (409, b"Conflict"),
            (410, b"Gone"),
            (411, b"Length Required"),
            (412, b"Precondition Failed"),
            (413, b"Content Too Large"),
            (414, b"URI Too Long"),
            (415, b"Unsupported Media Type"),
            (416, b"Range Not Satisfiable"),
            (417, b"Expectation Failed"),
            (421, b"Misdirected Request"),
            (422, b"Unprocessable Content"),
            (426, b"Upgrade Required"),
            (429, b"Too Many Requests"),
            (431, b"Request Header Fields Too Large"),
            (451, b"Unavailable For Legal Reasons"),
            (500, b"Internal Server Error"),
            (501, b"Not Implemented"),
            (502, b"Bad Gateway"),
            (503, b"Service Unavailable"),
            (504, b"Gateway Timeout"),
            (505, b"HTTP Version Not Supported"),
            (511, b"Network Authentication Required"),
        ];
        assert_eq!(rows.len(), 49, "#37 lists exactly 49 arms");
        for (code, phrase) in rows {
            assert_eq!(
                canonical_reason(*code),
                *phrase,
                "canonical_reason({code}) mismatch"
            );
        }
        for code in [418_u16, 510, 599] {
            assert_eq!(
                canonical_reason(code),
                b"",
                "canonical_reason({code}) must be empty"
            );
        }
    }

    // -----------------------------------------------------------------
    // response validation and reserved-prefix direction (SHOULD_FIX 1, 4).
    // -----------------------------------------------------------------

    #[test]
    fn response_egress_validates_and_keeps_x_envoy() {
        let res = response_with(
            StatusCode::OK,
            fields_with(&[(b"x-envoy-attempt-count", b"1"), (b"x-a", b"v")]),
        );
        let mut out = BytesMut::new();
        serialize_response_head(&res, Method::Get, BodySource::None, true, &mut out).unwrap();
        assert!(
            contains(&out, b"x-envoy-attempt-count: 1\r\n"),
            "x-envoy-* must survive on a response, out: {out:?}"
        );

        // A response-side hop-by-hop field left by a filter must still be
        // refused, mirroring the request-side backstop.
        let poisoned =
            response_with_raw_headers(StatusCode::OK, fields_with(&[(b"connection", b"close")]));
        let mut out = BytesMut::new();
        let result =
            serialize_response_head(&poisoned, Method::Get, BodySource::None, true, &mut out);
        assert!(matches!(result, Err(RejectReason::ConnectionSpecificField)));
        assert!(out.is_empty());
    }
}
