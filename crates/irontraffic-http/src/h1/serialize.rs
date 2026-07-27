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
//! The end-to-end pass skips every field that
//! [`crate::strip::is_hop_by_hop`] returns true for, plus `TE`
//! (`te` survives the ingress strip for the `trailers` value but must never
//! be forwarded) and any field whose name matches a reserved prefix.

use std::net::SocketAddr;

use bytes::{BufMut, BytesMut};

use crate::canonical::{CanonicalRequest, CanonicalResponse};
use crate::field::{name_byte_ok, value_byte_ok};
use crate::h1::chunked::trailer_denied;
use crate::known::KnownHeader;
use crate::peer::{ForwardEmit, write_forwarded_element};
use crate::scalar::{StatusCode, WireVersion};
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

/// Whether to emit `Connection: keep-alive` or `Connection: close`.
///
/// The default wiring (which lives outside this module, in the caller that
/// holds the listener configuration) is: HTTP/1.1 implies keep-alive, HTTP/1.0
/// implies close. The caller may override either by policy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Emit `Connection: keep-alive`, or nothing when the version already
    /// implies it.
    KeepAlive,
    /// Emit `Connection: close`.
    Close,
}

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
/// chunk-size line, the chunk data, and the trailing CRLF. The caller passes
/// the entire chunk at once. After all chunks are written,
/// [`finish`](ChunkedEncoder::finish) emits the terminal chunk and optional
/// trailer fields.
///
/// The encoder validates trailer field names and values through
/// [`name_byte_ok`] and [`value_byte_ok`] and refuses forbidden names via
/// [`trailer_denied`].
pub struct ChunkedEncoder {
    /// Scratch buffer for building the hex chunk-size line. Sized for the
    /// worst-case `usize` (16 hex digits on 64-bit).
    scratch: [u8; 16],
    /// True after `finish` has been called.
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

    /// Writes one chunk: hex-size line, data bytes, CRLF.
    ///
    /// # Panics
    ///
    /// Never. The method is infallible; the return type is `()` so that a
    /// future version that enforces a maximum chunk size can return a
    /// `Result` without changing the call site type.
    pub fn write_chunk(&mut self, chunk: &[u8], out: &mut BytesMut) {
        let count = hex_digits(chunk.len(), &mut self.scratch);
        let start = 16_usize.saturating_sub(count);
        if let Some(slice) = self.scratch.get(start..) {
            out.extend_from_slice(slice);
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }

    /// Writes the terminal chunk (`0\r\n`) and optional trailers, and marks
    /// the encoder as finished.
    ///
    /// When `trailers` is non-empty every trailer field is emitted as
    /// `Name: Value\r\n`, provided its name is validated and not in
    /// [`trailer_denied`]. The terminal CRLF (`\r\n`) ends the trailer
    /// section, or the head when no trailers are present.
    ///
    /// # Errors
    /// `TrailerFieldForbidden` when a trailer field uses a denied name.
    /// `FieldLineTooLong` for a trailer whose name or value contains a
    /// non-OK byte.
    pub fn finish(
        &mut self,
        trailers: &FieldSection,
        out: &mut BytesMut,
    ) -> Result<(), crate::error::RejectReason> {
        out.extend_from_slice(b"0\r\n");
        for (i, slot) in trailers.slots().iter().enumerate() {
            let Some(name) = trailers.name_at(i) else {
                return Err(crate::error::RejectReason::TrailerFieldForbidden);
            };
            if trailer_denied(slot.known) {
                return Err(crate::error::RejectReason::TrailerFieldForbidden);
            }
            let Some(value) = trailers.value_at(i) else {
                return Err(crate::error::RejectReason::TrailerFieldForbidden);
            };
            for &b in name {
                if !name_byte_ok(b) {
                    return Err(crate::error::RejectReason::FieldLineTooLong);
                }
            }
            for &b in value {
                if !value_byte_ok(b) {
                    return Err(crate::error::RejectReason::FieldLineTooLong);
                }
            }
            out.extend_from_slice(name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        self.finished = true;
        Ok(())
    }

    /// True after [`finish`](ChunkedEncoder::finish) has been called.
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
// Shared length helpers
// ---------------------------------------------------------------------------

/// The byte count needed for the framing line: `Content-Length: N\r\n` or
/// `Transfer-Encoding: chunked\r\n` or 0 for no body.
fn framing_len(body: BodySource) -> usize {
    match body {
        BodySource::None => 0,
        BodySource::Exact { len } => {
            // "Content-Length: " = 16 bytes + digits + "\r\n" = 2
            16_usize.saturating_add(u64_len(len)).saturating_add(2)
        }
        BodySource::Streaming => {
            // "Transfer-Encoding: chunked\r\n" = 31
            31
        }
    }
}

/// The byte count of the `Connection` header if it will be written.
fn connection_field_len(version: WireVersion, mode: ConnectionMode) -> usize {
    match mode {
        ConnectionMode::KeepAlive => {
            if matches!(version, WireVersion::Http10) {
                24 // "Connection: keep-alive\r\n"
            } else {
                0
            }
        }
        ConnectionMode::Close => {
            20 // "Connection: close\r\n"
        }
    }
}

/// True when `k` must never be written by the serializer.
fn skip_field(k: KnownHeader) -> bool {
    matches!(k, KnownHeader::Te) || is_hop_by_hop(k)
}

/// The byte count of all end-to-end fields from `headers`, excluding
/// connection-specific fields.
fn end_to_end_fields_len(headers: &FieldSection) -> usize {
    let mut len = 0_usize;
    for (i, slot) in headers.slots().iter().enumerate() {
        if skip_field(slot.known) {
            continue;
        }
        let Some(name) = headers.name_at(i) else {
            continue;
        };
        if is_reserved_prefix(name) {
            continue;
        }
        let Some(value) = headers.value_at(i) else {
            continue;
        };
        len = len.saturating_add(name.len());
        len = len.saturating_add(2); // ": "
        len = len.saturating_add(value.len());
        len = len.saturating_add(2); // "\r\n"
    }
    len
}

// ---------------------------------------------------------------------------
// Request serializer
// ---------------------------------------------------------------------------

/// The exact number of bytes [`serialize_request_head`] will write into
/// `out`, computed without writing anything.
#[must_use]
pub fn serialize_request_head_len(
    req: &CanonicalRequest,
    body: BodySource,
    keep_alive: ConnectionMode,
    emit: ForwardEmit,
    local: SocketAddr,
) -> usize {
    let mut len = 0_usize;

    // Request line: METHOD SP TARGET SP VERSION CRLF
    let method_bytes = req.method.as_bytes();
    len = len.saturating_add(method_bytes.len()); // METHOD
    len = len.saturating_add(1); // SP
    len = len.saturating_add(req.target_len()); // target
    len = len.saturating_add(1); // SP
    let version_bytes = match req.version {
        WireVersion::Http11 | WireVersion::H2 | WireVersion::H3 => b"HTTP/1.1",
        WireVersion::Http10 => b"HTTP/1.0",
    };
    len = len.saturating_add(version_bytes.len()); // VERSION
    len = len.saturating_add(2); // CRLF

    // Host field
    len = len.saturating_add(6); // "Host: "
    len = len.saturating_add(req.authority.written_len());
    len = len.saturating_add(2); // CRLF

    // Framing field
    len = len.saturating_add(framing_len(body));

    // Connection field
    len = len.saturating_add(connection_field_len(req.version, keep_alive));

    // Forwarded element
    if emit.emit_forwarded {
        len = len.saturating_add(10); // "Forwarded: "
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
        len = len.saturating_add(17); // "X-Forwarded-For: "
        len = len.saturating_add(node_len(req.peer.client, None));
        len = len.saturating_add(2); // CRLF

        len = len.saturating_add(19); // "X-Forwarded-Proto: "
        len = len.saturating_add(req.scheme.as_bytes().len());
        len = len.saturating_add(2); // CRLF

        len = len.saturating_add(17); // "X-Forwarded-Host: "
        len = len.saturating_add(req.authority.written_len());
        len = len.saturating_add(2); // CRLF

        if let Some(port) = req.peer.client_port {
            len = len.saturating_add(17); // "X-Forwarded-Port: "
            len = len.saturating_add(u64_len(u64::from(port)));
            len = len.saturating_add(2); // CRLF
        }
    }

    // End-to-end fields
    len = len.saturating_add(end_to_end_fields_len(&req.headers));

    // CRLF ending the head
    len = len.saturating_add(2);

    len
}

/// Writes the full request head (request line + all header fields) into `out`.
/// Does NOT write the body. Callers write the body separately, using
/// `BodySource` to determine the format.
///
/// # Errors
/// `ConnectionSpecificField` if a header in `req.headers` would produce an
/// invalid field line; this is the same invariant `CanonicalRequestBuilder::build`
/// already enforces at construction, so it should never fire in practice.
pub fn serialize_request_head(
    req: &CanonicalRequest,
    body: BodySource,
    keep_alive: ConnectionMode,
    emit: ForwardEmit,
    local: SocketAddr,
    out: &mut BytesMut,
) -> Result<(), crate::error::RejectReason> {
    // Request line: METHOD SP TARGET SP VERSION CRLF
    out.extend_from_slice(req.method.as_bytes());
    out.put_u8(b' ');
    req.write_target(out);
    out.put_u8(b' ');
    match req.version {
        WireVersion::Http11 | WireVersion::H2 | WireVersion::H3 => {
            out.extend_from_slice(b"HTTP/1.1\r\n");
        }
        WireVersion::Http10 => {
            out.extend_from_slice(b"HTTP/1.0\r\n");
        }
    }

    // Host field
    out.extend_from_slice(b"Host: ");
    req.authority.write_to(out);
    out.extend_from_slice(b"\r\n");

    // Framing field (from BodySource, never from inbound fields)
    write_framing(body, out);

    // Connection field
    write_connection(req.version, keep_alive, out);

    // Forwarded element
    if emit.emit_forwarded {
        out.extend_from_slice(b"Forwarded: ");
        write_forwarded_element(&req.peer, local, req.scheme, &req.authority, out);
        out.extend_from_slice(b"\r\n");
    }

    // X-Forwarded-* fields
    if emit.emit_x_forwarded {
        out.extend_from_slice(b"X-Forwarded-For: ");
        write_node(req.peer.client, None, out);
        out.extend_from_slice(b"\r\n");

        out.extend_from_slice(b"X-Forwarded-Proto: ");
        out.extend_from_slice(req.scheme.as_bytes());
        out.extend_from_slice(b"\r\n");

        out.extend_from_slice(b"X-Forwarded-Host: ");
        req.authority.write_to(out);
        out.extend_from_slice(b"\r\n");

        if let Some(port) = req.peer.client_port {
            out.extend_from_slice(b"X-Forwarded-Port: ");
            write_u64(u64::from(port), out);
            out.extend_from_slice(b"\r\n");
        }
    }

    // End-to-end fields
    write_end_to_end_fields(&req.headers, out)?;

    // CRLF ending the head
    out.extend_from_slice(b"\r\n");

    Ok(())
}

// ---------------------------------------------------------------------------
// Response serializer
// ---------------------------------------------------------------------------

/// The exact number of bytes [`serialize_response_head`] will write into
/// `out`, computed without writing anything.
#[must_use]
pub fn serialize_response_head_len(
    res: &CanonicalResponse,
    body: BodySource,
    keep_alive: bool,
) -> usize {
    let mut len = 0_usize;

    // Status line: "HTTP/1.1 " (9) + 3-digit status
    len = len.saturating_add(9);
    len = len.saturating_add(3); // status code digits
    let reason = StatusCode::canonical_reason(res.status);
    if !reason.is_empty() {
        len = len.saturating_add(1); // SP
        len = len.saturating_add(reason.len());
    }
    len = len.saturating_add(2); // CRLF

    // Framing field
    len = len.saturating_add(framing_len(body));

    // Connection field
    if !keep_alive {
        len = len.saturating_add(20);
    } else if matches!(res.version, WireVersion::Http10) {
        len = len.saturating_add(24);
    }

    // End-to-end fields
    len = len.saturating_add(end_to_end_fields_len(&res.headers));

    // CRLF ending the head
    len = len.saturating_add(2);

    len
}

/// Writes the full response head (status line + all header fields) into `out`.
/// Does NOT write the body.
///
/// # Errors
/// `ConnectionSpecificField` if a header in `res.headers` would produce an
/// invalid field line; this is the same invariant `CanonicalResponse::new`
/// already enforces at construction.
pub fn serialize_response_head(
    res: &CanonicalResponse,
    body: BodySource,
    keep_alive: bool,
    out: &mut BytesMut,
) -> Result<(), crate::error::RejectReason> {
    // Status line: "HTTP/1.1 " + status code + optional reason + CRLF
    out.extend_from_slice(b"HTTP/1.1 ");
    write_status_code(res.status.as_u16(), out);
    let reason = StatusCode::canonical_reason(res.status);
    if !reason.is_empty() {
        out.put_u8(b' ');
        out.extend_from_slice(reason);
    }
    out.extend_from_slice(b"\r\n");

    // Framing field
    write_framing(body, out);

    // Connection field
    if !keep_alive {
        out.extend_from_slice(b"Connection: close\r\n");
    } else if matches!(res.version, WireVersion::Http10) {
        out.extend_from_slice(b"Connection: keep-alive\r\n");
    }

    // End-to-end fields
    write_end_to_end_fields(&res.headers, out)?;

    // CRLF ending the head
    out.extend_from_slice(b"\r\n");

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared writing helpers
// ---------------------------------------------------------------------------

/// Writes the three ASCII digits of a status code into `out`. `code` is
/// guaranteed by [`StatusCode`] construction to be in `100..=599`.
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
/// Never reads inbound framing fields.
fn write_framing(body: BodySource, out: &mut BytesMut) {
    match body {
        BodySource::None => {}
        BodySource::Exact { len } => {
            out.extend_from_slice(b"Content-Length: ");
            write_u64(len, out);
            out.extend_from_slice(b"\r\n");
        }
        BodySource::Streaming => {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
    }
}

/// Writes the `Connection` header according to version and mode.
fn write_connection(version: WireVersion, mode: ConnectionMode, out: &mut BytesMut) {
    match mode {
        ConnectionMode::KeepAlive => {
            if matches!(version, WireVersion::Http10) {
                out.extend_from_slice(b"Connection: keep-alive\r\n");
            }
        }
        ConnectionMode::Close => {
            out.extend_from_slice(b"Connection: close\r\n");
        }
    }
}

/// Writes every end-to-end field in `headers` that is not connection-specific
/// and not a reserved-prefix field, in stable slot order.
///
/// # Errors
/// `ConnectionSpecificField` when a slot cannot be read back.
fn write_end_to_end_fields(
    headers: &FieldSection,
    out: &mut BytesMut,
) -> Result<(), crate::error::RejectReason> {
    for (i, slot) in headers.slots().iter().enumerate() {
        if skip_field(slot.known) {
            continue;
        }
        let Some(name) = headers.name_at(i) else {
            return Err(crate::error::RejectReason::ConnectionSpecificField);
        };
        if is_reserved_prefix(name) {
            continue;
        }
        let Some(value) = headers.value_at(i) else {
            return Err(crate::error::RejectReason::ConnectionSpecificField);
        };
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    Ok(())
}
