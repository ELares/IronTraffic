// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sans-IO gRPC health check codec (`grpc.health.v1.Health`).
//!
//! This module encodes the `HealthCheckRequest` frame, decodes the
//! `HealthCheckResponse` frame with a bounds-checked minimal protobuf reader, parses
//! the `grpc-status` trailer, and maps the two to a [`GrpcVerdict`]. It performs no
//! I/O, reads no clock, and never allocates in the decode or parse path: every
//! function below either reads bytes through bounds-checked slice accessors or
//! mutates a local primitive.
//!
//! The two messages this protocol defines have exactly one field each, so this is a
//! hand-written wire-type-dispatching reader rather than a general protobuf decoder:
//! see [`decode_health_response`]'s doc for why. [`GrpcCheckSpec`] is the
//! operator-facing configuration; [`GrpcCheckSpec::compile`] validates it and
//! serializes the request frame once, producing a [`CompiledGrpcCheck`] shared
//! (typically via `Arc`) across every check run against one endpoint. The
//! Watch-versus-Check policy machine lives in [`crate::health::grpc_mode`].
//!
//! See `docs/THREAT-MODEL.md`, "gRPC health checking".

use crate::config::{ConfigError, in_range_u32};
use crate::health::schedule::{CheckOutcome, FailKind};

/// Maximum protobuf message length this codec will decode.
///
/// A `HealthCheckResponse` is at most a handful of bytes; a server that sends more is
/// either broken or hostile, and 256 leaves generous room for unknown fields a future
/// version might add.
pub const MAX_MESSAGE_LEN: usize = 256;

/// Maximum simultaneously open `Watch` streams per process.
///
/// A `Watch` stream is a connection, a TLS session, and an HTTP/2 stream held open for
/// the endpoint's whole life, and nothing else in the health subsystem bounds that
/// count. Endpoints beyond the budget poll with unary `Check` instead: falling back to
/// polling is a cost, running out of file descriptors is an outage that also takes
/// down request serving.
pub const MAX_WATCH_STREAMS: usize = 4096;

/// Maximum `HealthCheckResponse` messages accepted on one `Watch` stream per check
/// interval.
///
/// Past this the runner stops reading, closes the stream, and reports
/// `Fail(Protocol)`. One legitimate server sends a message only when its status
/// changes; a compromised or broken backend can push messages as fast as the link
/// allows, and every one costs a decode and a mode-machine update.
pub const MAX_WATCH_MESSAGES_PER_INTERVAL: u32 = 100;

/// `grpc.health.v1.Health.ServingStatus`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum ServingStatus {
    /// The server has not determined the status.
    Unknown = 0,
    /// Healthy.
    Serving = 1,
    /// Unhealthy.
    NotServing = 2,
    /// The requested service name is not registered. Only sent by `Watch`.
    ServiceUnknown = 3,
}

impl ServingStatus {
    /// The status for a raw wire value, or `None` when it is not one of the four
    /// assigned values.
    #[must_use]
    pub fn from_raw(v: u32) -> Option<ServingStatus> {
        match v {
            0 => Some(ServingStatus::Unknown),
            1 => Some(ServingStatus::Serving),
            2 => Some(ServingStatus::NotServing),
            3 => Some(ServingStatus::ServiceUnknown),
            _ => None,
        }
    }
}

/// Why a gRPC health frame could not be decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GrpcDecodeError {
    /// Fewer than 5 bytes, or the declared length exceeds the bytes available.
    ShortFrame,
    /// The compressed flag was nonzero; we never advertise a compressor, so this is a
    /// protocol violation rather than something to decompress.
    Compressed,
    /// The declared message length exceeds [`MAX_MESSAGE_LEN`].
    TooLong,
    /// A varint ran past the end of the message or exceeded 10 bytes.
    BadVarint,
    /// A field used an unassigned or removed wire type (3, 4, 6, or 7). Named
    /// `GroupWireType` because 3 and 4 are the removed `start group`/`end group`
    /// encoding; 6 and 7 are simply never assigned and are rejected the same way.
    GroupWireType,
    /// A length-delimited field declared a length past the end of the message.
    BadLength,
}

impl core::fmt::Display for GrpcDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            GrpcDecodeError::ShortFrame => "frame shorter than its declared length",
            GrpcDecodeError::Compressed => "compressed flag was set",
            GrpcDecodeError::TooLong => "declared message length exceeds the cap",
            GrpcDecodeError::BadVarint => "varint ran past the message end or exceeded 10 bytes",
            GrpcDecodeError::GroupWireType => "field used an unassigned or removed wire type",
            GrpcDecodeError::BadLength => "length-delimited field length exceeds the message",
        };
        f.write_str(s)
    }
}

impl core::error::Error for GrpcDecodeError {}

/// The decision for one gRPC health exchange, with everything needed to log it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GrpcVerdict {
    /// Pass or the specific failure, for the scheduler's hysteresis.
    pub outcome: CheckOutcome,
    /// The raw `ServingStatus` value, retained even when unrecognized, so the log can
    /// name it.
    pub raw_serving_status: Option<u32>,
    /// The `grpc-status` code, when the response carried one.
    pub grpc_status: Option<u32>,
    /// True only for `grpc-status: 12` (`UNIMPLEMENTED`). Drives the Watch fallback.
    pub unimplemented: bool,
}

/// Configured gRPC health check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrpcCheckSpec {
    /// Service name to query. The empty string is the server's overall health, which
    /// is the default and the correct choice unless the upstream registers named
    /// services.
    pub service_name: String,
    /// Override for the `:authority` pseudo-header. `None` uses the endpoint
    /// authority.
    pub authority: Option<String>,
    /// Prefer the streaming `Watch` RPC. Default true.
    pub prefer_watch: bool,
    /// Liveness deadline for an open `Watch` stream, as a multiple of the check
    /// interval. Default 3.
    pub liveness_multiplier: u32,
    /// Unary checks to perform before retrying `Watch` after an `UNIMPLEMENTED`.
    /// Default 20.
    pub watch_retry_after_checks: u32,
}

impl Default for GrpcCheckSpec {
    fn default() -> Self {
        Self {
            service_name: String::new(),
            authority: None,
            prefer_watch: true,
            liveness_multiplier: 3,
            watch_retry_after_checks: 20,
        }
    }
}

impl GrpcCheckSpec {
    /// Validate against invariant 8: `service_name` at most 200 bytes and free of a
    /// NUL byte, `authority` (when set) holding only bytes in `0x21..=0x7E`,
    /// `liveness_multiplier` in `[2, 100]`, and `watch_retry_after_checks` in
    /// `[1, 10_000]`.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] naming the first rejected field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.service_name.len() > 200 {
            return Err(ConfigError::new(
                "health.grpc.service_name",
                &self.service_name,
                "must not exceed 200 bytes",
            ));
        }
        if self.service_name.bytes().any(|b| b == 0) {
            return Err(ConfigError::new(
                "health.grpc.service_name",
                &self.service_name,
                "must not contain a NUL byte",
            ));
        }
        if let Some(authority) = self.authority.as_deref()
            && !authority.bytes().all(|b| (0x21..=0x7E).contains(&b))
        {
            return Err(ConfigError::new(
                "health.grpc.authority",
                authority,
                "must contain only bytes in 0x21..=0x7E",
            ));
        }
        in_range_u32(
            "health.grpc.liveness_multiplier",
            self.liveness_multiplier,
            2,
            100,
        )?;
        in_range_u32(
            "health.grpc.watch_retry_after_checks",
            self.watch_retry_after_checks,
            1,
            10_000,
        )?;
        Ok(())
    }

    /// Validate and serialize the request frame once.
    ///
    /// # Errors
    /// Returns the same [`ConfigError`] as [`GrpcCheckSpec::validate`], or one from
    /// [`encode_health_request`] (unreachable once `validate` has passed, since it
    /// already bounds `service_name` well under the encoded-message cap, but the
    /// error is still propagated rather than assumed away).
    pub fn compile(self) -> Result<CompiledGrpcCheck, ConfigError> {
        self.validate()?;
        let mut request_frame = Vec::new();
        encode_health_request(&self.service_name, &mut request_frame)?;
        let authority = self
            .authority
            .as_deref()
            .map(|a| a.as_bytes().to_vec().into_boxed_slice());
        Ok(CompiledGrpcCheck {
            request_frame: request_frame.into_boxed_slice(),
            check_path: b"/grpc.health.v1.Health/Check",
            watch_path: b"/grpc.health.v1.Health/Watch",
            authority,
            prefer_watch: self.prefer_watch,
            liveness_multiplier: self.liveness_multiplier,
            watch_retry_after_checks: self.watch_retry_after_checks,
        })
    }
}

/// A `GrpcCheckSpec` with its request frame serialized. Shared by `Arc`, read-only.
pub struct CompiledGrpcCheck {
    /// The 5-byte-prefixed `HealthCheckRequest`, identical for Check and Watch.
    request_frame: Box<[u8]>,
    /// `/grpc.health.v1.Health/Check`.
    check_path: &'static [u8],
    /// `/grpc.health.v1.Health/Watch`.
    watch_path: &'static [u8],
    authority: Option<Box<[u8]>>,
    prefer_watch: bool,
    liveness_multiplier: u32,
    watch_retry_after_checks: u32,
}

impl CompiledGrpcCheck {
    /// The 5-byte-prefixed `HealthCheckRequest`. Identical for `Check` and `Watch`.
    #[must_use]
    pub fn request_frame(&self) -> &[u8] {
        &self.request_frame
    }

    /// `/grpc.health.v1.Health/Check`.
    #[must_use]
    pub fn check_path(&self) -> &[u8] {
        self.check_path
    }

    /// `/grpc.health.v1.Health/Watch`.
    #[must_use]
    pub fn watch_path(&self) -> &[u8] {
        self.watch_path
    }

    /// `:authority` override, if configured.
    #[must_use]
    pub fn authority(&self) -> Option<&[u8]> {
        self.authority.as_deref()
    }

    /// Whether `Watch` is preferred.
    #[must_use]
    pub fn prefer_watch(&self) -> bool {
        self.prefer_watch
    }

    /// Liveness deadline for an open `Watch` stream, as a multiple of the check
    /// interval. Read by [`crate::health::grpc_mode::GrpcModeMachine::on_check_due`].
    #[must_use]
    pub fn liveness_multiplier(&self) -> u32 {
        self.liveness_multiplier
    }

    /// Unary checks to perform before retrying `Watch`. Read by
    /// [`crate::health::grpc_mode::GrpcModeMachine::on_check_due`].
    #[must_use]
    pub fn watch_retry_after_checks(&self) -> u32 {
        self.watch_retry_after_checks
    }
}

/// Encoded length in bytes of `n` as a base-128 varint.
///
/// `encode_health_request` only ever calls this with `n` equal to a validated
/// `service_name`'s byte length, which [`GrpcCheckSpec::validate`] caps at 200, so
/// the three arms below are exhaustive for every value this function is actually
/// called with; the third arm exists only so the helper is total for any `usize`.
fn varint_len(n: usize) -> usize {
    if n < 128 {
        1
    } else if n < 16_384 {
        // `< 16_384` versus `<= 16_384` is unobservable from any caller of
        // this function: `encode_health_request` also rejects whenever
        // `1 + varint_len(n) + n > MAX_MESSAGE_LEN` (256), and even the
        // smallest possible `n` this branch could take under either
        // comparison, 16_384 itself, already makes `1 + 2 + 16_384` or
        // `1 + 3 + 16_384` far exceed 256. So the one value where `<` and
        // `<=` disagree (`n == 16_384` exactly) is always rejected before
        // this return value can affect an accepted frame. Confirmed by
        // mutating this comparison to `<=` and rerunning the suite, which
        // stayed green.
        2
    } else {
        3
    }
}

/// Push `n` as a base-128 varint into `out`: low 7 bits first, continuation bit
/// `0x80` set on every byte but the last.
fn push_varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let low7 = n & 0x7F;
        // `low7` is masked to the low 7 bits, so it is always in `0..128` and the
        // conversion to `u8` cannot lose data; `unwrap_or` is unreachable defense
        // rather than an expected failure path, matching the `usize -> u32`
        // conversions used throughout this module tree (see
        // `HttpCheckSpec::compile`).
        let byte = u8::try_from(low7).unwrap_or(0);
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        // `byte` is `low7`, masked to the low 7 bits above, so its bit 7 is
        // always 0; OR-ing and XOR-ing a fixed bit into a byte whose
        // corresponding bit is always clear are the same operation. `|` is
        // used because it is the conventional way to read "set this bit" in
        // varint-encoding code. Confirmed by mutating this to `^` and
        // rerunning the suite, which stayed green.
        out.push(byte | 0x80);
    }
}

/// Encode a `HealthCheckRequest` with its 5-byte gRPC prefix into `out`, which is
/// cleared first.
///
/// # Errors
/// Returns a [`ConfigError`] when the service name is too long for
/// [`MAX_MESSAGE_LEN`].
pub fn encode_health_request(service: &str, out: &mut Vec<u8>) -> Result<(), ConfigError> {
    out.clear();
    let body_len = if service.is_empty() {
        0
    } else {
        1 + varint_len(service.len()) + service.len()
    };
    if body_len > MAX_MESSAGE_LEN {
        return Err(ConfigError::new(
            "grpc_health.service_name",
            &service.len().to_string(),
            "encoded message must not exceed 256 bytes",
        ));
    }
    out.push(0u8);
    // `body_len <= MAX_MESSAGE_LEN` (256) was just checked above, so this fits in a
    // `u32` on every target this workspace supports; `try_from`/`unwrap_or` keeps
    // the conversion checked rather than a silent truncating `as` cast, matching
    // `HttpCheckSpec::compile`'s identical pattern.
    let body_len_u32 = u32::try_from(body_len).unwrap_or(u32::MAX);
    out.extend_from_slice(&body_len_u32.to_be_bytes());
    if !service.is_empty() {
        out.push(0x0A);
        push_varint(service.len(), out);
        out.extend_from_slice(service.as_bytes());
    }
    Ok(())
}

/// Validate a gRPC length-prefix and return the declared message length.
///
/// The runner MUST call this the moment it has five bytes and MUST NOT buffer a
/// sixth byte until it returns `Ok`. Returns [`GrpcDecodeError::Compressed`] when
/// the flag byte is nonzero and [`GrpcDecodeError::TooLong`] when the declared
/// length exceeds [`MAX_MESSAGE_LEN`]. Without this call the peer chooses how much
/// memory we allocate: a prefix of `00 FF FF FF FF` asks for 4 GiB. The reassembly
/// buffer is a fixed `[u8; 5 + MAX_MESSAGE_LEN]` and never grows.
///
/// # Errors
/// Returns [`GrpcDecodeError::Compressed`] when the flag byte is nonzero, or
/// [`GrpcDecodeError::TooLong`] when the declared length exceeds
/// [`MAX_MESSAGE_LEN`].
#[must_use = "ignoring this discards the one chance to bound the reassembly buffer before the runner buffers a peer-declared length"]
pub fn grpc_frame_admissible(prefix: &[u8; 5]) -> Result<usize, GrpcDecodeError> {
    let flag = prefix.first().copied().unwrap_or(0);
    if flag != 0 {
        return Err(GrpcDecodeError::Compressed);
    }
    let len = u32::from_be_bytes([
        prefix.get(1).copied().unwrap_or(0),
        prefix.get(2).copied().unwrap_or(0),
        prefix.get(3).copied().unwrap_or(0),
        prefix.get(4).copied().unwrap_or(0),
    ]);
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    if len > MAX_MESSAGE_LEN {
        return Err(GrpcDecodeError::TooLong);
    }
    Ok(len)
}

/// Read one base-128 varint from `msg` starting at `*i`, advancing `*i` past it.
///
/// Ten iterations is the maximum length of a `u64` varint; an eleventh
/// continuation byte is [`GrpcDecodeError::BadVarint`]. This function always
/// advances `*i` by at least one byte before it can return `Ok`, which is what
/// makes [`decode_health_response`]'s outer loop terminate.
fn read_varint(msg: &[u8], i: &mut usize) -> Result<u64, GrpcDecodeError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for _ in 0..10 {
        let b = *msg.get(*i).ok_or(GrpcDecodeError::BadVarint)?;
        *i += 1;
        result |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(GrpcDecodeError::BadVarint)
}

/// Truncate a decoded varint to the 32-bit `ServingStatus` wire value.
///
/// Wire type 0 always carries a varint (up to 64 bits); protobuf's own rule for a
/// 32-bit enum field read from it is to keep the low 32 bits, which is exactly
/// what this cast does. This is the wire format's rule, not unintended data loss:
/// see `decode_non_minimal_varint` for a legal, non-minimal encoding this must
/// still accept.
#[allow(
    clippy::cast_possible_truncation,
    reason = "protobuf's own rule for a 32-bit enum field read from a 64-bit varint is to keep the low 32 bits; this is the wire format's rule, not unintended data loss"
)]
fn truncate_varint_status(v: u64) -> u32 {
    // #747 NOTE: the escape below used to say "bounded per the doc comment
    // above", which was wrong: `v` is an arbitrary `u64` read straight off the
    // wire, and nothing bounds it. This narrowing conversion is a deliberate
    // truncation, not a proof that `v` fits in 32 bits without loss: protobuf's
    // own rule for a 32-bit enum field read from a 64-bit varint is to discard
    // the high 32 bits, which is exactly what happens below (`prost` and
    // `protobuf-go` do the same). A hostile `v` with nonzero high bits
    // truncates to whatever its low 32 bits say, which `ServingStatus::from_raw`
    // and `serving_status_verdict` then treat like any other value: `Some(1)`
    // truncated from is `Pass`, anything else is `Fail`. See
    // `decode_status_truncates_high_bits_of_the_varint`.
    v as u32 // it-allow: unchecked-cast reason: deliberate truncation per protobuf's own wire-format rule for a 32-bit field read from a 64-bit varint, not a bound on v (see the comment above); the high bits are intentionally discarded, not assumed zero
}

/// Decode a `HealthCheckResponse` frame, returning the raw `status` field value, or
/// `None` when the message contained no `status` field (which protobuf permits and
/// which means the default, 0, `UNKNOWN`).
///
/// Unknown fields are skipped by wire type: field 1 with wire type 2 (a
/// length-delimited value where an enum is expected) is skipped, not an error, per
/// protobuf's rule that a reader ignores fields it does not understand in the shape
/// it expects. A hostile server cannot make this function error out on that; it can
/// only make it see `None`.
///
/// Never reads outside `frame`: every index is a bounds-checked slice access, and
/// every length used to advance a position is `checked_add`-ed against the message
/// length before use. Never allocates: every step is a bounds-checked read of
/// `frame` or a mutation of a local primitive, with no `Vec`, `String`, or `Box`
/// ever constructed.
///
/// # Errors
/// Returns the specific [`GrpcDecodeError`] naming why the frame could not be
/// decoded.
pub fn decode_health_response(frame: &[u8]) -> Result<Option<u32>, GrpcDecodeError> {
    if frame.len() < 5 {
        return Err(GrpcDecodeError::ShortFrame);
    }
    let flag = frame.first().copied().unwrap_or(0);
    if flag != 0 {
        return Err(GrpcDecodeError::Compressed);
    }
    let len = u32::from_be_bytes([
        frame.get(1).copied().unwrap_or(0),
        frame.get(2).copied().unwrap_or(0),
        frame.get(3).copied().unwrap_or(0),
        frame.get(4).copied().unwrap_or(0),
    ]);
    // Checked before any arithmetic on `len`, so a declared length of `u32::MAX`
    // is rejected here rather than risking an overflow below (edge case 9).
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    if len > MAX_MESSAGE_LEN {
        return Err(GrpcDecodeError::TooLong);
    }
    let Some(frame_len) = 5usize.checked_add(len) else {
        return Err(GrpcDecodeError::ShortFrame);
    };
    // This check and the `frame.get(5..frame_len)` immediately below it both
    // reject a `frame` shorter than `frame_len`, with no panic either way, so
    // this is defense in depth (and follows the issue's own algorithm text
    // verbatim), not the sole enforcement of the bound.
    //
    // #747 SHOULD_FIX 4: this comment used to call `>` and `<` here
    // "confirmed equivalent" because mutating the comparison to `<` left the
    // suite green. The survival was real, but the two are NOT equivalent:
    // they disagree exactly when `frame.len() > frame_len` (a reassembly
    // buffer, such as the fixed 261-byte one `docs/THREAT-MODEL.md`
    // prescribes, holding a short message with trailing slack), where `>`
    // correctly accepts and `<` incorrectly rejects every such frame as
    // `ShortFrame`, which maps to `Fail(Protocol)` and would eject every
    // endpoint. The green suite only showed a coverage gap: no test decoded a
    // frame longer than its declared message.
    // `decode_ignores_trailing_bytes_past_declared_length` below closes it.
    if frame_len > frame.len() {
        return Err(GrpcDecodeError::ShortFrame);
    }
    let Some(msg) = frame.get(5..frame_len) else {
        return Err(GrpcDecodeError::ShortFrame);
    };

    let mut status: Option<u32> = None;
    let mut i = 0usize;
    while i < msg.len() {
        let tag = read_varint(msg, &mut i)?;
        let field = tag >> 3;
        let wire = tag & 7;
        match wire {
            0 => {
                let v = read_varint(msg, &mut i)?;
                if field == 1 {
                    status = Some(truncate_varint_status(v));
                }
            }
            1 => {
                i = i
                    .checked_add(8)
                    .filter(|n| *n <= msg.len())
                    .ok_or(GrpcDecodeError::BadLength)?;
            }
            2 => {
                let n = read_varint(msg, &mut i)?;
                let n = usize::try_from(n).map_err(|_| GrpcDecodeError::BadLength)?;
                i = i
                    .checked_add(n)
                    .filter(|k| *k <= msg.len())
                    .ok_or(GrpcDecodeError::BadLength)?;
            }
            5 => {
                i = i
                    .checked_add(4)
                    .filter(|n| *n <= msg.len())
                    .ok_or(GrpcDecodeError::BadLength)?;
            }
            // 3 and 4 are the removed `start group`/`end group` encoding; 6 and 7
            // are simply never assigned. All four, and any other value this
            // 3-bit field could never actually carry, are rejected identically.
            _ => return Err(GrpcDecodeError::GroupWireType),
        }
    }
    Ok(status)
}

/// Parse a `grpc-status` header or trailer value. ASCII decimal, at most 10
/// digits, no sign, no whitespace, `checked_mul`/`checked_add`.
///
/// Identical discipline to `crate::deadline::headers::parse_u32_ms`, and the two
/// are deliberately separate functions rather than one shared one, because a
/// future change to timeout parsing must not silently change status parsing.
#[must_use]
pub fn parse_grpc_status(v: &[u8]) -> Option<u32> {
    if v.is_empty() || v.len() > 10 {
        return None;
    }
    let mut value: u32 = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        let digit = u32::from(b - b'0');
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some(value)
}

/// Map a decoded status and an optional `grpc-status` to a verdict.
///
/// `grpc_status == Some(12)` (`UNIMPLEMENTED`) always wins, regardless of the
/// body. Any other nonzero `grpc_status` fails the check without setting
/// `unimplemented`. Otherwise the raw `ServingStatus` value decides: `Some(1)`
/// passes, everything else (`None`, `Some(0)`, `Some(2)`, `Some(3)`, or an
/// unrecognized value) fails.
#[must_use]
pub fn serving_status_verdict(raw: Option<u32>, grpc_status: Option<u32>) -> GrpcVerdict {
    if grpc_status == Some(12) {
        return GrpcVerdict {
            outcome: CheckOutcome::Fail(FailKind::Protocol),
            raw_serving_status: raw,
            grpc_status,
            unimplemented: true,
        };
    }
    if let Some(s) = grpc_status
        && s != 0
    {
        return GrpcVerdict {
            outcome: CheckOutcome::Fail(FailKind::Status),
            raw_serving_status: raw,
            grpc_status,
            unimplemented: false,
        };
    }
    let outcome = if raw == Some(1) {
        CheckOutcome::Pass
    } else {
        CheckOutcome::Fail(FailKind::Status)
    };
    GrpcVerdict {
        outcome,
        raw_serving_status: raw,
        grpc_status,
        unimplemented: false,
    }
}

/// Map a decode error to a verdict. Every error is `Fail(FailKind::Protocol)`: a
/// malformed frame is a protocol violation regardless of which specific bounds
/// check caught it, so `e` does not otherwise vary the result.
#[must_use]
pub fn decode_error_verdict(e: GrpcDecodeError) -> GrpcVerdict {
    let _ = e;
    GrpcVerdict {
        outcome: CheckOutcome::Fail(FailKind::Protocol),
        raw_serving_status: None,
        grpc_status: None,
        unimplemented: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The big-endian `u32` length declared in `frame`'s 5-byte prefix, read
    /// independently of `decode_health_response`/`grpc_frame_admissible` (both
    /// under test elsewhere) so the encode-side boundary tests below have their
    /// own oracle for "does the declared length match what was actually
    /// appended".
    fn declared_len(frame: &[u8]) -> u32 {
        u32::from_be_bytes([
            frame.get(1).copied().unwrap_or(0),
            frame.get(2).copied().unwrap_or(0),
            frame.get(3).copied().unwrap_or(0),
            frame.get(4).copied().unwrap_or(0),
        ])
    }

    #[test]
    fn default_spec_values() {
        let spec = GrpcCheckSpec::default();
        assert_eq!(spec.service_name, String::new());
        assert_eq!(spec.authority, None);
        assert!(spec.prefer_watch);
        assert_eq!(spec.liveness_multiplier, 3);
        assert_eq!(spec.watch_retry_after_checks, 20);
    }

    #[test]
    fn encode_empty_service() {
        let mut v = Vec::new();
        encode_health_request("", &mut v).expect("empty service is always valid");
        assert_eq!(v, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_named_service() {
        let mut v = Vec::new();
        encode_health_request("svc", &mut v).expect("short service name is valid");
        assert_eq!(v, vec![0, 0, 0, 0, 5, 0x0A, 0x03, b's', b'v', b'c']);
    }

    #[test]
    fn encode_rejects_long_service() {
        let long = "x".repeat(300);
        let mut v = Vec::new();
        let err =
            encode_health_request(&long, &mut v).expect_err("300-byte service name is too long");
        assert_eq!(err.field, "grpc_health.service_name");
    }

    /// Not one of the issue's 34 named tests. `cargo mutants` found this gap live:
    /// every other encode test uses a service name under 128 bytes, so
    /// `push_varint`'s multi-byte path (the continuation-bit-setting
    /// `byte | 0x80` line) and `varint_len`'s 1-byte/2-byte boundary at 128 were
    /// never exercised by a test that checks exact output bytes.
    /// `encode_rejects_long_service` above uses 300 bytes, which stays rejected
    /// under almost any off-by-a-few mutation of that arithmetic because
    /// `body_len` is already far past the cap either way. This checks the exact
    /// frame bytes on both sides of the 128-byte varint-length boundary, AND that
    /// the declared length prefix matches what was actually appended: `v.len()`
    /// alone cannot catch a broken `varint_len` feeding a wrong `body_len` into
    /// the prefix, because the bytes `push_varint` actually appends are computed
    /// independently of `varint_len` and would still total the right length.
    #[test]
    fn encode_varint_length_prefix_one_and_two_byte_boundary() {
        let name_127 = "x".repeat(127);
        let mut v = Vec::new();
        encode_health_request(&name_127, &mut v).expect("127-byte name is valid");
        assert_eq!(
            v.len(),
            5 + 1 + 1 + 127,
            "5 prefix + tag + 1-byte varint + name"
        );
        assert_eq!(v.get(5), Some(&0x0A), "field 1, wire type 2");
        assert_eq!(v.get(6), Some(&127), "127 < 128 fits in one varint byte");
        assert_eq!(
            declared_len(&v),
            u32::try_from(v.len() - 5).unwrap_or(u32::MAX),
            "declared prefix length must match the bytes actually appended"
        );

        let name_128 = "x".repeat(128);
        let mut v = Vec::new();
        encode_health_request(&name_128, &mut v).expect("128-byte name is valid");
        assert_eq!(
            v.len(),
            5 + 1 + 2 + 128,
            "5 prefix + tag + 2-byte varint + name"
        );
        assert_eq!(v.get(5), Some(&0x0A), "field 1, wire type 2");
        // varint(128): low 7 bits are 0 with the continuation bit set, then the
        // next 7 bits are 1.
        assert_eq!(
            v.get(6),
            Some(&0x80),
            "continuation bit set on the first byte"
        );
        assert_eq!(
            v.get(7),
            Some(&0x01),
            "no continuation bit on the last byte"
        );
        assert_eq!(
            declared_len(&v),
            u32::try_from(v.len() - 5).unwrap_or(u32::MAX),
            "declared prefix length must match the bytes actually appended"
        );
    }

    /// Not one of the issue's 34 named tests. The encode-side counterpart of
    /// `decode_accepts_message_at_max_len`: proves `MAX_MESSAGE_LEN` is a genuine
    /// boundary on the ENCODE path too, not merely something `encode_rejects_long_service`
    /// trips from far away. A 253-byte name is exactly the largest that fits: 5-byte
    /// prefix + 1 (field tag) + 2 (varint length of 253, which needs two bytes since
    /// 253 is at least 128) + 253 name bytes = 261 = 5 + `MAX_MESSAGE_LEN`. 254 bytes
    /// is one past it: a `varint_len` bug that undercounts by one (for example
    /// always returning 1) would compute `body_len` as exactly `MAX_MESSAGE_LEN`
    /// here instead of one over it, silently ACCEPTING a name that must be
    /// rejected, which is why this pairs the accept and reject sides in one test.
    #[test]
    fn encode_accepts_at_256_byte_cap_rejects_one_byte_over() {
        let name_253 = "x".repeat(253);
        let mut v = Vec::new();
        encode_health_request(&name_253, &mut v)
            .expect("253-byte name lands exactly on the encoded-message cap");
        assert_eq!(v.len(), 5 + MAX_MESSAGE_LEN);
        assert_eq!(
            declared_len(&v),
            u32::try_from(MAX_MESSAGE_LEN).unwrap_or(u32::MAX)
        );

        let name_254 = "x".repeat(254);
        let mut v = Vec::new();
        let err = encode_health_request(&name_254, &mut v)
            .expect_err("254 bytes is one byte past the encoded-message cap");
        assert_eq!(err.field, "grpc_health.service_name");
    }

    #[test]
    fn encode_clears_out() {
        let mut v = vec![0xFFu8; 64];
        encode_health_request("svc", &mut v).expect("valid service name");
        assert_eq!(v, vec![0, 0, 0, 0, 5, 0x0A, 0x03, b's', b'v', b'c']);
    }

    #[test]
    fn decode_serving() {
        assert_eq!(
            decode_health_response(&[0, 0, 0, 0, 2, 0x08, 0x01]),
            Ok(Some(1))
        );
    }

    #[test]
    fn decode_not_serving() {
        assert_eq!(
            decode_health_response(&[0, 0, 0, 0, 2, 0x08, 0x02]),
            Ok(Some(2))
        );
    }

    #[test]
    fn decode_service_unknown() {
        assert_eq!(
            decode_health_response(&[0, 0, 0, 0, 2, 0x08, 0x03]),
            Ok(Some(3))
        );
    }

    #[test]
    fn decode_empty_message() {
        assert_eq!(decode_health_response(&[0, 0, 0, 0, 0]), Ok(None));
    }

    #[test]
    fn decode_short_frame() {
        for frame in [
            Vec::<u8>::new(),
            vec![0u8],
            vec![0u8, 0, 0, 0],
            vec![0u8, 0, 0, 0, 2, 0x08],
        ] {
            assert_eq!(
                decode_health_response(&frame),
                Err(GrpcDecodeError::ShortFrame),
                "frame: {frame:?}"
            );
        }
    }

    #[test]
    fn decode_compressed() {
        assert_eq!(
            decode_health_response(&[1, 0, 0, 0, 2, 0x08, 0x01]),
            Err(GrpcDecodeError::Compressed)
        );
    }

    #[test]
    fn decode_too_long() {
        // Declared length 257: the 4-byte big-endian value 0x0000_0101.
        assert_eq!(
            decode_health_response(&[0, 0, 0, 1, 1]),
            Err(GrpcDecodeError::TooLong)
        );
        // Declared length u32::MAX.
        assert_eq!(
            decode_health_response(&[0, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(GrpcDecodeError::TooLong)
        );
    }

    #[test]
    fn decode_unknown_field_skipped() {
        // Declared length 4: field 15 (tag 0x78) varint 1, then field 1 (tag 0x08)
        // varint 1.
        assert_eq!(
            decode_health_response(&[0, 0, 0, 0, 4, 0x78, 0x01, 0x08, 0x01]),
            Ok(Some(1))
        );
    }

    #[test]
    fn decode_length_delimited_skip() {
        // Field 2 wire type 2 (tag 0x12), length 3, 3 payload bytes, then field 1
        // (tag 0x08) varint 1.
        let frame = [0u8, 0, 0, 0, 7, 0x12, 0x03, 0xAA, 0xBB, 0xCC, 0x08, 0x01];
        assert_eq!(decode_health_response(&frame), Ok(Some(1)));
    }

    #[test]
    fn decode_bad_length() {
        // Field 2 wire type 2 (tag 0x12), varint length 200 (0xC8, 0x01), padded
        // to a 10-byte message with 7 filler bytes.
        let frame = [0u8, 0, 0, 0, 10, 0x12, 0xC8, 0x01, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decode_health_response(&frame),
            Err(GrpcDecodeError::BadLength)
        );
    }

    /// Not one of the issue's 34 named tests. `cargo mutants` found this gap
    /// live: no test ever sent a wire type 1 (fixed64) field, so its whole match
    /// arm, its 8-byte skip amount, and its `BadLength` bound were all
    /// unexercised (a mutant could delete the arm entirely, or loosen its bound
    /// comparison, with the full suite green). Field 9 (arbitrary, unassigned)
    /// wire type 1 is tag `0x49`.
    #[test]
    fn decode_wire_type_one_skips_eight_bytes() {
        // 0x49 tag, 8 filler bytes, then field 1 (tag 0x08) varint 1.
        let frame = [
            0u8, 0, 0, 0, 11, 0x49, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x08, 0x01,
        ];
        assert_eq!(decode_health_response(&frame), Ok(Some(1)));

        // Same tag, but only 3 filler bytes present instead of the 8 required.
        let short_frame = [0u8, 0, 0, 0, 4, 0x49, 0xAA, 0xAA, 0xAA];
        assert_eq!(
            decode_health_response(&short_frame),
            Err(GrpcDecodeError::BadLength)
        );
    }

    /// Not one of the issue's 34 named tests. The wire-type-5 (fixed32)
    /// counterpart of `decode_wire_type_one_skips_eight_bytes` above, same gap:
    /// field 9 wire type 5 is tag `0x4D`.
    #[test]
    fn decode_wire_type_five_skips_four_bytes() {
        // 0x4D tag, 4 filler bytes, then field 1 (tag 0x08) varint 1.
        let frame = [0u8, 0, 0, 0, 7, 0x4D, 0xAA, 0xAA, 0xAA, 0xAA, 0x08, 0x01];
        assert_eq!(decode_health_response(&frame), Ok(Some(1)));

        // Same tag, but only 2 filler bytes present instead of the 4 required.
        let short_frame = [0u8, 0, 0, 0, 3, 0x4D, 0xAA, 0xAA];
        assert_eq!(
            decode_health_response(&short_frame),
            Err(GrpcDecodeError::BadLength)
        );
    }

    #[test]
    fn decode_group_wire_types() {
        for wire in [3u8, 4, 6, 7] {
            let tag = (1u8 << 3) | wire;
            let frame = [0u8, 0, 0, 0, 1, tag];
            assert_eq!(
                decode_health_response(&frame),
                Err(GrpcDecodeError::GroupWireType),
                "wire type {wire}"
            );
        }
    }

    #[test]
    fn decode_bad_varint() {
        // 11 continuation bytes: the tag varint never terminates within the
        // 10-iteration cap.
        let mut frame = vec![0u8, 0, 0, 0, 11];
        frame.extend(std::iter::repeat_n(0xFFu8, 11));
        assert_eq!(
            decode_health_response(&frame),
            Err(GrpcDecodeError::BadVarint)
        );

        // A value varint truncated at the message end: the tag is present but
        // its value byte is missing.
        let frame = [0u8, 0, 0, 0, 1, 0x08];
        assert_eq!(
            decode_health_response(&frame),
            Err(GrpcDecodeError::BadVarint)
        );
    }

    #[test]
    fn decode_non_minimal_varint() {
        // Field 1 (tag 0x08), value 1 encoded in 3 bytes: 0x81 0x80 0x00.
        let frame = [0u8, 0, 0, 0, 4, 0x08, 0x81, 0x80, 0x00];
        assert_eq!(decode_health_response(&frame), Ok(Some(1)));
    }

    /// Not one of the issue's 34 named tests. `cargo mutants` found this gap
    /// live: `decode_non_minimal_varint` above encodes 1 in 3 bytes, but every
    /// byte past the first contributes only zero bits (`0 << shift == 0 >> shift`
    /// for any shift, and `shift`'s own accumulation is likewise unobservable
    /// when every subsequent contribution is zero), so it cannot distinguish
    /// `read_varint`'s `<< shift` from `>> shift`, nor `shift += 7` from a
    /// broken accumulation. A value whose SECOND byte carries a nonzero bit
    /// can: 128 encodes as `[0x80, 0x01]`, and the second byte's `1` must land
    /// at bit 7 (`1 << 7 == 128`, reached only when `shift` correctly reached
    /// 7), not bit 0 (`1 << 0 == 1`, what a broken shift accumulation gives).
    #[test]
    fn decode_two_byte_varint_shifts_into_high_bits() {
        let frame = [0u8, 0, 0, 0, 3, 0x08, 0x80, 0x01];
        assert_eq!(decode_health_response(&frame), Ok(Some(128)));
    }

    /// #747 NOTE: `truncate_varint_status`'s cast had no test in either
    /// direction. Field 1 (tag `0x08`), varint `4_294_967_297` (`2^32 + 1`,
    /// encoded as `[0x81, 0x80, 0x80, 0x80, 0x10]`): a value with nonzero high
    /// 32 bits that low32-truncates to 1. Legal protobuf: an enum field is
    /// wire-encoded as a full varint, and a reader keeps only the low 32 bits
    /// (the wire format's own rule, not this decoder's invention, and what
    /// `prost`/`protobuf-go` do too).
    #[test]
    fn decode_status_truncates_high_bits_of_the_varint() {
        let frame = [0u8, 0, 0, 0, 6, 0x08, 0x81, 0x80, 0x80, 0x80, 0x10];
        assert_eq!(decode_health_response(&frame), Ok(Some(1)));
    }

    #[test]
    fn decode_field_one_wrong_wire_type() {
        // Field 1, wire type 2 (tag 0x0A), length 0.
        let frame = [0u8, 0, 0, 0, 2, 0x0A, 0x00];
        assert_eq!(decode_health_response(&frame), Ok(None));
    }

    #[test]
    fn decode_repeated_field_one_last_wins() {
        let frame = [0u8, 0, 0, 0, 4, 0x08, 0x02, 0x08, 0x01];
        assert_eq!(decode_health_response(&frame), Ok(Some(1)));
    }

    #[test]
    fn decode_field_zero_terminates() {
        let frame = [0u8, 0, 0, 0, 2, 0x00, 0x05];
        assert_eq!(decode_health_response(&frame), Ok(None));
    }

    #[test]
    fn parse_grpc_status_cases() {
        assert_eq!(parse_grpc_status(b"0"), Some(0));
        assert_eq!(parse_grpc_status(b"12"), Some(12));
        assert_eq!(parse_grpc_status(b""), None);
        assert_eq!(parse_grpc_status(b"-1"), None);
        assert_eq!(parse_grpc_status(b"1 "), None);
        assert_eq!(parse_grpc_status(b"99999999999"), None);
    }

    /// Not one of the issue's 34 named tests. `cargo mutants` found this gap
    /// live: every 11-digit decimal exceeds `u32::MAX` (10,000,000,000 is
    /// already past 4,294,967,295), so `99999999999` above is rejected by
    /// `checked_mul`/`checked_add` overflow regardless of whether the `> 10`
    /// length gate runs at all, which let a mutant change that gate to `== 10`
    /// or `>= 10` (silently rejecting the legal 10-digit case below) without
    /// failing anything. Mirrors `deadline::headers::parse_u32_ms_cases`'s
    /// identical boundary pair for the sibling function this one is
    /// deliberately not shared with.
    #[test]
    fn parse_grpc_status_ten_digit_boundary() {
        assert_eq!(parse_grpc_status(b"4294967295"), Some(u32::MAX));
        assert_eq!(parse_grpc_status(b"0000000000"), Some(0));
    }

    /// #747 `SHOULD_FIX` 2: the two cases above only prove the length gate and the
    /// checked arithmetic AGREE at the boundary (an 11-digit value is rejected
    /// either way, and a 10-digit value at `u32::MAX` is accepted either way), not
    /// that either one alone still does its job. `D18-parse-status-checked-to-wrapping`
    /// (`checked_mul`/`checked_add` weakened to `wrapping_mul`/`wrapping_add`) and
    /// `D20-del-parse-status-maxlen` (the `v.len() > 10` gate deleted) both survived
    /// the shipped suite. Two cases close both: a 10-digit value one past `u32::MAX`
    /// (still passes the length gate, so only the checked arithmetic can reject it),
    /// and a value longer than 10 bytes that never overflows arithmetically (all
    /// leading zeros, so only the length gate can reject it).
    #[test]
    fn parse_grpc_status_overflow_and_overlong_are_none() {
        // 4294967296 == u32::MAX + 1, still exactly 10 digits.
        assert_eq!(parse_grpc_status(b"4294967296"), None);
        // 14 bytes of leading zeros then "12": the value is 12, which never
        // overflows; only the length gate can reject this.
        assert_eq!(parse_grpc_status(b"00000000000012"), None);
    }

    #[test]
    fn verdict_matrix() {
        use CheckOutcome::{Fail, Pass};

        // (raw, grpc_status, expected_outcome, expected_unimplemented), one row
        // per one of the 24 combinations the issue's `serving_status_verdict`
        // table specifies. Every value here was hand-derived from the algorithm
        // text, not computed by calling `serving_status_verdict` or replicating
        // its branches, so a bug shared between this table and the
        // implementation cannot hide behind an identical mistake in both.
        let cases: [(Option<u32>, Option<u32>, CheckOutcome, bool); 24] = [
            // grpc_status: None
            (None, None, Fail(FailKind::Status), false),
            (Some(0), None, Fail(FailKind::Status), false),
            (Some(1), None, Pass, false),
            (Some(2), None, Fail(FailKind::Status), false),
            (Some(3), None, Fail(FailKind::Status), false),
            (Some(7), None, Fail(FailKind::Status), false),
            // grpc_status: Some(0)
            (None, Some(0), Fail(FailKind::Status), false),
            (Some(0), Some(0), Fail(FailKind::Status), false),
            (Some(1), Some(0), Pass, false),
            (Some(2), Some(0), Fail(FailKind::Status), false),
            (Some(3), Some(0), Fail(FailKind::Status), false),
            (Some(7), Some(0), Fail(FailKind::Status), false),
            // grpc_status: Some(5) (NOT_FOUND)
            (None, Some(5), Fail(FailKind::Status), false),
            (Some(0), Some(5), Fail(FailKind::Status), false),
            (Some(1), Some(5), Fail(FailKind::Status), false),
            (Some(2), Some(5), Fail(FailKind::Status), false),
            (Some(3), Some(5), Fail(FailKind::Status), false),
            (Some(7), Some(5), Fail(FailKind::Status), false),
            // grpc_status: Some(12) (UNIMPLEMENTED)
            (None, Some(12), Fail(FailKind::Protocol), true),
            (Some(0), Some(12), Fail(FailKind::Protocol), true),
            (Some(1), Some(12), Fail(FailKind::Protocol), true),
            (Some(2), Some(12), Fail(FailKind::Protocol), true),
            (Some(3), Some(12), Fail(FailKind::Protocol), true),
            (Some(7), Some(12), Fail(FailKind::Protocol), true),
        ];

        let mut pass_count = 0usize;
        for (raw, grpc_status, expected_outcome, expected_unimplemented) in cases {
            if expected_outcome == Pass {
                pass_count += 1;
            }
            let verdict = serving_status_verdict(raw, grpc_status);
            assert_eq!(
                verdict.outcome, expected_outcome,
                "raw={raw:?} grpc_status={grpc_status:?}"
            );
            assert_eq!(
                verdict.unimplemented, expected_unimplemented,
                "raw={raw:?} grpc_status={grpc_status:?}"
            );
            assert_eq!(
                verdict.raw_serving_status, raw,
                "raw={raw:?} grpc_status={grpc_status:?}"
            );
        }
        assert_eq!(pass_count, 2, "exactly two of the 24 cells must be Pass");
    }

    #[test]
    fn decode_error_verdict_is_protocol() {
        let variants = [
            GrpcDecodeError::ShortFrame,
            GrpcDecodeError::Compressed,
            GrpcDecodeError::TooLong,
            GrpcDecodeError::BadVarint,
            GrpcDecodeError::GroupWireType,
            GrpcDecodeError::BadLength,
        ];
        for e in variants {
            let verdict = decode_error_verdict(e);
            assert_eq!(verdict.outcome, CheckOutcome::Fail(FailKind::Protocol));
        }
    }

    /// Not one of the issue's 34 named tests. `cargo mutants` found this gap
    /// live: no test read `GrpcDecodeError`'s `Display` output, so a mutant that
    /// replaced the whole `fmt` body with `Ok(Default::default())` (an empty
    /// string, never an error) passed the whole suite.
    #[test]
    fn grpc_decode_error_display_is_non_empty_and_distinct() {
        let variants = [
            GrpcDecodeError::ShortFrame,
            GrpcDecodeError::Compressed,
            GrpcDecodeError::TooLong,
            GrpcDecodeError::BadVarint,
            GrpcDecodeError::GroupWireType,
            GrpcDecodeError::BadLength,
        ];
        let texts: Vec<String> = variants.iter().map(ToString::to_string).collect();
        for text in &texts {
            assert!(!text.is_empty(), "Display output must not be empty");
        }
        let mut unique = texts.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            texts.len(),
            "every variant must have a distinct Display message: {texts:?}"
        );
    }

    /// Not one of the issue's 34 named tests. `decode_too_long` above only proves
    /// the reject side of `decode_health_response`'s own `MAX_MESSAGE_LEN` check
    /// (257 and `u32::MAX`, both far past the cap); `frame_admissible_bounds`
    /// proves the accept-at-256 side for `grpc_frame_admissible`, but that is a
    /// different function with its own comparison. Without this, a mutant that
    /// tightens `decode_health_response`'s `len > MAX_MESSAGE_LEN` to `len >=
    /// MAX_MESSAGE_LEN` would leave every named test green while silently
    /// rejecting a legal 256-byte message.
    #[test]
    fn decode_accepts_message_at_max_len() {
        let mut frame = vec![0u8, 0, 0, 1, 0]; // prefix declaring length 256
        frame.extend(std::iter::repeat_n(0u8, MAX_MESSAGE_LEN));
        assert_eq!(frame.len(), 5 + MAX_MESSAGE_LEN);
        assert_eq!(decode_health_response(&frame), Ok(None));
    }

    /// #747 `SHOULD_FIX` 4: every decode test up to this one has `frame.len()`
    /// exactly `5 + declared_len`; none decodes a buffer LONGER than its
    /// declared message, which is exactly the shape `docs/THREAT-MODEL.md`
    /// prescribes: a fixed `[u8; 5 + MAX_MESSAGE_LEN]` (261-byte) reassembly
    /// buffer holding a short response with trailing slack. Declares length 2
    /// (the `SERVING` message) but supplies 3 extra bytes past it.
    #[test]
    fn decode_ignores_trailing_bytes_past_declared_length() {
        let frame = [0u8, 0, 0, 0, 2, 0x08, 0x01, 0xAA, 0xBB, 0xCC];
        assert_eq!(frame.len(), 10, "declared length 2 plus 3 trailing bytes");
        assert_eq!(decode_health_response(&frame), Ok(Some(1)));

        // The full 261-byte fixed reassembly buffer shape: a 2-byte SERVING
        // message followed by 254 bytes of untouched buffer slack.
        let mut buf = vec![0u8, 0, 0, 0, 2, 0x08, 0x01];
        buf.extend(std::iter::repeat_n(0u8, MAX_MESSAGE_LEN - 2));
        assert_eq!(buf.len(), 5 + MAX_MESSAGE_LEN);
        assert_eq!(decode_health_response(&buf), Ok(Some(1)));
    }

    #[test]
    fn frame_admissible_bounds() {
        assert_eq!(grpc_frame_admissible(&[0, 0, 0, 0, 0]), Ok(0));
        assert_eq!(grpc_frame_admissible(&[0, 0, 0, 1, 0]), Ok(256));
        assert_eq!(
            grpc_frame_admissible(&[0, 0, 0, 1, 1]),
            Err(GrpcDecodeError::TooLong)
        );
        assert_eq!(
            grpc_frame_admissible(&[0, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(GrpcDecodeError::TooLong)
        );
        assert_eq!(
            grpc_frame_admissible(&[1, 0, 0, 0, 2]),
            Err(GrpcDecodeError::Compressed)
        );
    }

    /// Not one of the issue's 34 named tests, but `ServingStatus::from_raw` is
    /// public API used nowhere else in this module (`decode_health_response`
    /// returns the raw `u32` directly, per its documented contract), so without
    /// this it would ship with zero direct coverage.
    #[test]
    fn serving_status_from_raw_cases() {
        assert_eq!(ServingStatus::from_raw(0), Some(ServingStatus::Unknown));
        assert_eq!(ServingStatus::from_raw(1), Some(ServingStatus::Serving));
        assert_eq!(ServingStatus::from_raw(2), Some(ServingStatus::NotServing));
        assert_eq!(
            ServingStatus::from_raw(3),
            Some(ServingStatus::ServiceUnknown)
        );
        assert_eq!(ServingStatus::from_raw(7), None);
    }

    /// Not one of the issue's 34 named tests. Invariant 8 names five rejection
    /// rules for `GrpcCheckSpec::validate`, and an untested `validate` is exactly
    /// the shape of gap this project's reviews keep finding, so this closes it
    /// with one row per rule, mirroring `http::tests::validate_rejects_table`.
    #[test]
    fn validate_rejects_invalid_fields() {
        let base = GrpcCheckSpec::default();
        assert!(base.validate().is_ok(), "fixture must itself be valid");

        let cases: Vec<(&str, GrpcCheckSpec)> = vec![
            (
                "health.grpc.service_name",
                GrpcCheckSpec {
                    service_name: "x".repeat(201),
                    ..base.clone()
                },
            ),
            (
                "health.grpc.service_name",
                GrpcCheckSpec {
                    service_name: "a\0b".into(),
                    ..base.clone()
                },
            ),
            (
                "health.grpc.authority",
                GrpcCheckSpec {
                    authority: Some("bad host\n".into()),
                    ..base.clone()
                },
            ),
            (
                "health.grpc.liveness_multiplier",
                GrpcCheckSpec {
                    liveness_multiplier: 1,
                    ..base.clone()
                },
            ),
            (
                "health.grpc.liveness_multiplier",
                GrpcCheckSpec {
                    liveness_multiplier: 101,
                    ..base.clone()
                },
            ),
            (
                "health.grpc.watch_retry_after_checks",
                GrpcCheckSpec {
                    watch_retry_after_checks: 0,
                    ..base.clone()
                },
            ),
            (
                "health.grpc.watch_retry_after_checks",
                GrpcCheckSpec {
                    watch_retry_after_checks: 10_001,
                    ..base.clone()
                },
            ),
        ];

        for (expected_field, spec) in cases {
            let err = spec.validate().expect_err("row must be rejected");
            assert_eq!(err.field, expected_field, "spec: {spec:?}");
        }
    }

    /// Not one of the issue's 34 named tests. Tests the ACCEPT side of every
    /// invariant-8 cap, not merely the reject side: a mutant that tightens a
    /// bound by one (`<= 200` to `<= 199`, `>= 2` to `>= 3`, and so on) would
    /// leave `validate_rejects_invalid_fields` above untouched but silently
    /// reject configs the docs call legal. Mirrors
    /// `http::tests::validate_accepts_every_cap_at_its_limit`.
    #[test]
    fn validate_accepts_every_cap_at_its_limit() {
        let base = GrpcCheckSpec::default();

        let cases: Vec<(&str, GrpcCheckSpec)> = vec![
            (
                "service_name length (200)",
                GrpcCheckSpec {
                    service_name: "x".repeat(200),
                    ..base.clone()
                },
            ),
            (
                "liveness_multiplier lo (2)",
                GrpcCheckSpec {
                    liveness_multiplier: 2,
                    ..base.clone()
                },
            ),
            (
                "liveness_multiplier hi (100)",
                GrpcCheckSpec {
                    liveness_multiplier: 100,
                    ..base.clone()
                },
            ),
            (
                "watch_retry_after_checks lo (1)",
                GrpcCheckSpec {
                    watch_retry_after_checks: 1,
                    ..base.clone()
                },
            ),
            (
                "watch_retry_after_checks hi (10_000)",
                GrpcCheckSpec {
                    watch_retry_after_checks: 10_000,
                    ..base.clone()
                },
            ),
            (
                "authority allowed bytes",
                GrpcCheckSpec {
                    authority: Some("svc.local:443".into()),
                    ..base.clone()
                },
            ),
        ];

        for (label, spec) in cases {
            assert!(
                spec.validate().is_ok(),
                "{label}: expected Ok at the exact limit, got {:?}",
                spec.validate()
            );
        }
    }

    #[test]
    fn compile_produces_expected_paths_and_frame() {
        let spec = GrpcCheckSpec {
            service_name: "svc".into(),
            authority: Some("upstream.local".into()),
            ..GrpcCheckSpec::default()
        };
        let compiled = spec.compile().expect("valid spec");
        assert_eq!(
            compiled.request_frame(),
            &[0, 0, 0, 0, 5, 0x0A, 0x03, b's', b'v', b'c']
        );
        assert_eq!(
            compiled.check_path(),
            b"/grpc.health.v1.Health/Check".as_slice()
        );
        assert_eq!(
            compiled.watch_path(),
            b"/grpc.health.v1.Health/Watch".as_slice()
        );
        assert_eq!(compiled.authority(), Some(b"upstream.local".as_slice()));
        assert!(compiled.prefer_watch());
        assert_eq!(compiled.liveness_multiplier(), 3);
        assert_eq!(compiled.watch_retry_after_checks(), 20);
    }

    /// Byte-vector generator for [`prop_decode_never_panics`]. Mirrors
    /// `crate::health::http::tests::response_strategy`'s fix for the #739
    /// BLOCKING 1 class of defect: fully arbitrary bytes reach
    /// `decode_health_response`'s prefix checks (`ShortFrame`, `Compressed`,
    /// `TooLong`) but essentially never carry a valid protobuf message behind a
    /// valid 5-byte prefix, so `vec(any::<u8>(), ..)` alone would leave the
    /// wire-type dispatch loop, the varint reader, and the field-1 status
    /// extraction completely unexercised. This strategy mixes fully arbitrary
    /// bytes (kept, so the prefix-rejection paths stay covered) with frames
    /// carrying a valid prefix around arbitrary payload bytes (reaches the
    /// dispatch loop even when the payload is not valid protobuf) and, weighted
    /// heaviest, fully well-formed frames encoding one arbitrary `u32` status
    /// value (reaches `Ok(Some(_))` reliably).
    fn frame_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            1 => proptest::collection::vec(any::<u8>(), 0..=512),
            1 => proptest::collection::vec(any::<u8>(), 0..=250).prop_map(|body| {
                let mut v = vec![0u8, 0, 0, 0, 0];
                let len_bytes = u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes();
                v[1..5].copy_from_slice(&len_bytes);
                v.extend(body);
                v
            }),
            3 => any::<u32>().prop_map(|status| {
                let mut body = vec![0x08u8];
                push_varint(usize::try_from(status).unwrap_or(usize::MAX), &mut body);
                let mut v = vec![0u8, 0, 0, 0, 0];
                let len_bytes = u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes();
                v[1..5].copy_from_slice(&len_bytes);
                v.extend(body);
                v
            }),
        ]
    }

    #[test]
    fn prop_decode_never_panics() {
        use proptest::test_runner::{Config, TestRunner};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // #739 BLOCKING 1's lesson applied here: a per-case `prop_assert!` cannot
        // express "a nonzero fraction of ALL cases", only a fact about one case.
        // `TestRunner::run` is called directly so these counters can be
        // inspected once every generated case has run.
        let total = Arc::new(AtomicUsize::new(0));
        let reached_status = Arc::new(AtomicUsize::new(0));
        let total_in = Arc::clone(&total);
        let reached_status_in = Arc::clone(&reached_status);

        let mut runner = TestRunner::new(Config::default());
        let run_result = runner.run(&frame_strategy(), move |bytes| {
            total_in.fetch_add(1, Ordering::Relaxed);
            let first = decode_health_response(&bytes);
            if let Ok(Some(v)) = first {
                reached_status_in.fetch_add(1, Ordering::Relaxed);
                let second = decode_health_response(&bytes);
                prop_assert_eq!(
                    second,
                    Ok(Some(v)),
                    "re-decoding the same bytes must be stable"
                );
            }
            Ok(())
        });
        run_result.unwrap();

        let total = total.load(Ordering::Relaxed);
        let reached = reached_status.load(Ordering::Relaxed);
        assert!(total > 0, "the property ran zero cases");
        assert!(
            reached > 0,
            "0 of {total} cases reached Ok(Some(_)); the frame generator is \
             seeding only unparseable byte strings again, so the wire-type loop, \
             the varint reader, and field-1 status extraction are going untested \
             (see #739 BLOCKING 1)"
        );
    }
}
