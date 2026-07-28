// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sans-IO HTTP/1.1 health check codec.
//!
//! [`HttpCheckSpec`] is the operator-facing configuration; [`HttpCheckSpec::compile`]
//! validates it and serializes the request bytes once, producing a
//! [`CompiledHttpCheck`] that is shared (typically via `Arc`) across every check run
//! against one endpoint. [`HttpCheckCodec`] is the per-in-flight-check parse state,
//! drawn from a pool bounded by `max_concurrent_checks` and reset before each use; it
//! is never allocated one per endpoint.
//!
//! The codec never resolves HTTP framing. It scans up to `max_head_bytes` for the
//! status line and headers, retains up to `response_buffer_size` body bytes, and
//! decides pass or fail from the status and the configured `receive` patterns. It
//! never reads `Content-Length` or `Transfer-Encoding`, never decodes chunked
//! transfer coding, and never forwards anything, which is what keeps a malicious or
//! broken upstream's response bounded at a fixed, small cost regardless of how much
//! it sends. See `docs/THREAT-MODEL.md`, "Health check response parsing".
//!
//! # `cfg(fuzzing)` on the test-only accessors
//!
//! `HttpCheckCodec`'s `*_for_test` accessors near the bottom of this file are
//! compiled under `cfg(any(test, fuzzing))`. `cfg(fuzzing)` is the flag
//! `cargo fuzz` sets for the whole crate graph it builds, including path
//! dependencies, which is what lets `fuzz_health_response_parser` (a separate
//! crate) observe the same invariants the in-crate property tests check.
//! `fuzzing` is not a `rustc`-known cfg name, so referencing it trips
//! `unexpected_cfgs`; the module-level allow below is the same pattern
//! `crate::health::bitmap` uses for `cfg(loom)`, for the same reason: this crate
//! may not touch the workspace `[lints]` table to register it, since
//! `irontraffic-resilience` must keep `[lints] workspace = true`.

#![allow(
    unexpected_cfgs,
    reason = "cfg(fuzzing) is the standard cargo-fuzz flag for exposing test-only introspection to a fuzz target without adding production API surface; this crate may not touch the workspace [lints] table to register it, since irontraffic-resilience must keep [lints] workspace = true"
)]

use crate::config::{ConfigError, in_range_u32};
use crate::health::schedule::{CheckOutcome, FailKind};
use crate::health::{CodecStep, ConnectionFate, StatusRange, patterns_match};

/// Method for an HTTP health check. Closed on purpose: a health check never needs an
/// arbitrary method, and allowing one invites a config that mutates the upstream.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum HttpCheckMethod {
    /// The default.
    #[default]
    Get,
    /// No body is read, so `receive` patterns are ignored and must be empty.
    Head,
    /// For upstreams that expose health on `OPTIONS`.
    Options,
}

impl HttpCheckMethod {
    /// The wire bytes for the request line's method token.
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Get => b"GET",
            Self::Head => b"HEAD",
            Self::Options => b"OPTIONS",
        }
    }
}

/// True when `b` is an RFC 9110 Section 5.6.2 `tchar`: an ASCII digit, an ASCII
/// letter, or one of `!`, `#`, `$`, `%`, `&`, `'`, `*`, `+`, `-`, `.`, `^`, `_`,
/// `` ` ``, `|`, or `~`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Configured HTTP health check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpCheckSpec {
    /// Request method. Default `Get`.
    pub method: HttpCheckMethod,
    /// Origin-form request target. Must start with `/`.
    pub path: String,
    /// Value for the `host` header. Required; the config layer fills it from the
    /// cluster's configured authority.
    pub host: Option<String>,
    /// Extra request headers. Names are lowercased; values must not contain CR or LF.
    pub headers: Vec<(String, String)>,
    /// Statuses that count as healthy. Default `[StatusRange { lo: 200, hi: 300 }]`.
    pub expected_statuses: Vec<StatusRange>,
    /// Statuses that fail the check but schedule a fast retry. Default empty. Checked
    /// BEFORE `expected_statuses`, so a status in both is retriable.
    pub retriable_statuses: Vec<StatusRange>,
    /// Byte patterns that must appear in the retained body, in this order, without
    /// overlapping. Default empty, meaning the status alone decides.
    pub receive: Vec<Vec<u8>>,
    /// Maximum body bytes retained. Default 1024, maximum 4096. Past this the codec
    /// decides and closes the connection.
    pub response_buffer_size: u32,
    /// Maximum status-line-plus-headers bytes scanned. Default 1024, maximum 8192.
    pub max_head_bytes: u32,
}

impl Default for HttpCheckSpec {
    fn default() -> Self {
        Self {
            method: HttpCheckMethod::default(),
            path: "/".into(),
            host: None,
            headers: Vec::new(),
            expected_statuses: vec![StatusRange { lo: 200, hi: 300 }],
            retriable_statuses: Vec::new(),
            receive: Vec::new(),
            response_buffer_size: 1024,
            max_head_bytes: 1024,
        }
    }
}

impl HttpCheckSpec {
    /// Validate every field against invariant 7.
    ///
    /// Checked in this order: `path`, `host`, `headers`, `expected_statuses`,
    /// `retriable_statuses`, `receive`, the method/receive combination,
    /// `response_buffer_size`, `max_head_bytes`, and finally the total serialized
    /// request size.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] naming the first rejected field.
    #[allow(
        clippy::too_many_lines,
        reason = "invariant 7 has ten independent clauses, each needing its own check and its own ConfigError message; splitting them into several private free functions would only move the line count, and the acceptance criterion for this module requires format!/to_string calls to stay textually inside validate and compile, not in helper functions"
    )]
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.path.is_empty() {
            return Err(ConfigError::new(
                "health.http.path",
                &self.path,
                "must not be empty",
            ));
        }
        if !self.path.starts_with('/') {
            return Err(ConfigError::new(
                "health.http.path",
                &self.path,
                "must start with '/'",
            ));
        }
        if !self.path.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
            return Err(ConfigError::new(
                "health.http.path",
                &self.path,
                "must contain only bytes in 0x21..=0x7E",
            ));
        }

        let Some(host) = self.host.as_deref() else {
            return Err(ConfigError::new("health.http.host", "", "must be set"));
        };
        if host.is_empty() {
            return Err(ConfigError::new(
                "health.http.host",
                host,
                "must not be empty",
            ));
        }
        if !host.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
            return Err(ConfigError::new(
                "health.http.host",
                host,
                "must contain only bytes in 0x21..=0x7E",
            ));
        }

        if self.headers.len() > 16 {
            return Err(ConfigError::new(
                "health.http.headers",
                &self.headers.len().to_string(),
                "must not configure more than 16 headers",
            ));
        }
        for (name, value) in &self.headers {
            if name.is_empty() || !name.bytes().all(is_tchar) {
                return Err(ConfigError::new(
                    "health.http.headers.name",
                    name,
                    "must be a non-empty sequence of RFC 9110 tchar bytes",
                ));
            }
            if value.bytes().any(|b| b == b'\r' || b == b'\n') {
                return Err(ConfigError::new(
                    "health.http.headers.value",
                    value,
                    "must not contain CR or LF",
                ));
            }
        }

        let check_ranges = |field: &'static str,
                            ranges: &[StatusRange],
                            must_be_nonempty: bool|
         -> Result<(), ConfigError> {
            if must_be_nonempty && ranges.is_empty() {
                return Err(ConfigError::new(field, "", "must not be empty"));
            }
            if ranges.len() > 8 {
                return Err(ConfigError::new(
                    field,
                    &ranges.len().to_string(),
                    "must not configure more than 8 ranges",
                ));
            }
            for r in ranges {
                if r.lo >= r.hi {
                    return Err(ConfigError::new(
                        field,
                        &r.lo.to_string(),
                        "range lo must be less than hi",
                    ));
                }
                if r.hi > 600 {
                    return Err(ConfigError::new(
                        field,
                        &r.hi.to_string(),
                        "range hi must not exceed 600",
                    ));
                }
            }
            Ok(())
        };
        check_ranges(
            "health.http.expected_statuses",
            &self.expected_statuses,
            true,
        )?;
        check_ranges(
            "health.http.retriable_statuses",
            &self.retriable_statuses,
            false,
        )?;

        if self.receive.len() > 8 {
            return Err(ConfigError::new(
                "health.http.receive",
                &self.receive.len().to_string(),
                "must not configure more than 8 patterns",
            ));
        }
        let mut pattern_bytes_total = 0usize;
        for pat in &self.receive {
            if pat.is_empty() {
                return Err(ConfigError::new(
                    "health.http.receive",
                    "",
                    "pattern must not be empty",
                ));
            }
            if pat.len() > 256 {
                return Err(ConfigError::new(
                    "health.http.receive",
                    &pat.len().to_string(),
                    "pattern must not exceed 256 bytes",
                ));
            }
            pattern_bytes_total = pattern_bytes_total.saturating_add(pat.len());
        }
        if pattern_bytes_total > 512 {
            return Err(ConfigError::new(
                "health.http.receive",
                &pattern_bytes_total.to_string(),
                "sum of pattern lengths must not exceed 512",
            ));
        }

        if self.method == HttpCheckMethod::Head && !self.receive.is_empty() {
            return Err(ConfigError::new(
                "health.http.receive",
                "non-empty",
                "must be empty when method is Head, which never has a body",
            ));
        }

        in_range_u32(
            "health.http.response_buffer_size",
            self.response_buffer_size,
            1,
            4096,
        )?;
        in_range_u32("health.http.max_head_bytes", self.max_head_bytes, 16, 8192)?;

        let request_size = serialize_request(self).len();
        if request_size > 8192 {
            return Err(ConfigError::new(
                "health.http.request_size",
                &request_size.to_string(),
                "serialized request must not exceed 8192 bytes",
            ));
        }

        Ok(())
    }

    /// Validate and serialize the request bytes once.
    ///
    /// # Errors
    /// Returns the same [`ConfigError`] as [`HttpCheckSpec::validate`].
    pub fn compile(self) -> Result<CompiledHttpCheck, ConfigError> {
        self.validate()?;
        let request = serialize_request(&self).into_boxed_slice();
        let expected = self.expected_statuses.into_boxed_slice();
        let retriable = self.retriable_statuses.into_boxed_slice();
        let receive: Box<[Box<[u8]>]> = self
            .receive
            .into_iter()
            .map(Vec::into_boxed_slice)
            .collect();
        // `validate()` above bounds `response_buffer_size` to [1, 4096] and
        // `max_head_bytes` to [16, 8192], both of which fit in a `usize` on every
        // target this workspace supports (all are 32-bit or 64-bit); `try_from`
        // with a `usize::MAX` fallback is used instead of `as` so the conversion
        // is checked rather than a silent truncating cast, per the widening/
        // narrowing conversion rule.
        let response_buffer_size = usize::try_from(self.response_buffer_size).unwrap_or(usize::MAX);
        let max_head_bytes = usize::try_from(self.max_head_bytes).unwrap_or(usize::MAX);
        let method_is_head = self.method == HttpCheckMethod::Head;
        Ok(CompiledHttpCheck {
            request,
            expected,
            retriable,
            receive,
            response_buffer_size,
            max_head_bytes,
            method_is_head,
        })
    }
}

/// Serialize `spec`'s wire request bytes. Called once at compile time by
/// [`HttpCheckSpec::compile`] and once more by [`HttpCheckSpec::validate`] to size
/// the total-request-bytes cap; never called from the parsing path.
fn serialize_request(spec: &HttpCheckSpec) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(spec.method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(spec.path.as_bytes());
    buf.extend_from_slice(b" HTTP/1.1\r\n");
    buf.extend_from_slice(b"host: ");
    buf.extend_from_slice(spec.host.as_deref().unwrap_or("").as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(b"user-agent: irontraffic-healthcheck\r\n");
    buf.extend_from_slice(b"accept: */*\r\n");
    buf.extend_from_slice(b"connection: keep-alive\r\n");
    for (name, value) in &spec.headers {
        buf.extend_from_slice(name.to_ascii_lowercase().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

/// An `HttpCheckSpec` with its request bytes serialized. Shared by `Arc`, read-only.
pub struct CompiledHttpCheck {
    request: Box<[u8]>,
    expected: Box<[StatusRange]>,
    retriable: Box<[StatusRange]>,
    receive: Box<[Box<[u8]>]>,
    response_buffer_size: usize,
    max_head_bytes: usize,
    method_is_head: bool,
}

impl CompiledHttpCheck {
    /// The exact bytes to write, including the terminating empty line.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }

    /// Maximum body bytes the codec will retain.
    #[must_use]
    pub fn response_buffer_size(&self) -> usize {
        self.response_buffer_size
    }
}

/// Byte offset threshold under which `HttpCheckCodec::consume_body_byte` defers
/// re-running `patterns_match`; see the Complexity section of the issue this
/// implements. Bounds the worst-case pattern-match cost to
/// `(response_buffer_size / MATCH_BATCH_BYTES) * response_buffer_size * S`.
const MATCH_BATCH_BYTES: usize = 64;

/// The four bytes `HttpCheckCodec::consume_head_byte`'s `crlf` matcher advances
/// through to find the end of the head.
const CRLF_SEQ: [u8; 4] = *b"\r\n\r\n";

/// Parse phase of one in-flight HTTP health check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    StatusLine,
    Head,
    Body,
    Finished,
}

/// HTTP response parse state for ONE IN-FLIGHT CHECK. The runner keeps a POOL of at
/// most `max_concurrent_checks` of these and calls [`HttpCheckCodec::reset`] before
/// handing one to a check. It is NOT allocated per endpoint.
///
/// This is a memory bound, not a style preference. The codec owns a
/// `response_buffer_size` byte buffer for its whole life. One codec per endpoint costs
/// `H * response_buffer_size`, which at the endpoint ceiling of `1_048_576` and the
/// maximum buffer of `4096` is 4 GB of idle buffers, and even at a routine `H = 50_000`
/// with the default `1024` it is 51 MB per cluster of memory that is in use for
/// microseconds per interval. One codec per IN-FLIGHT check costs
/// `max_concurrent_checks * response_buffer_size`, which at the default
/// `4 * num_cpus` and `1024` bytes is tens of kilobytes and does not grow with the
/// endpoint count at all.
pub struct HttpCheckCodec {
    phase: Phase,
    /// First bytes of the status line, buffered until we have 12 of them.
    status_buf: [u8; 12],
    /// Number of status-line bytes buffered so far, 0 to 12, then bumped to the
    /// sentinel 13 the instant the status line parses successfully. `status()`
    /// reads this sentinel: a value of 13 is the only way it returns `Some`, so a
    /// status line that failed its format checks (which finish the codec before
    /// reaching that assignment) correctly reports no parsed status.
    status_len: u8,
    status: u16,
    /// Bytes of `CRLF CRLF` matched so far, 0 to 4.
    crlf: u8,
    /// Every byte consumed while in `StatusLine` or `Head`, INCLUDING the 12 status-line
    /// bytes. The cap fires when this exceeds `max_head_bytes`, so its maximum value is
    /// `max_head_bytes + 1`.
    head_scanned: usize,
    body: Vec<u8>,
    /// `body.len()` the last time `patterns_match` ran, so the matcher runs at most once
    /// per `MATCH_BATCH_BYTES` appended bytes rather than once per `on_bytes` call.
    matched_at_len: usize,
    /// The verdict, stored the instant any `Done` is produced. `Phase::Finished` returns
    /// it verbatim, which is what makes `on_bytes` after `Done` idempotent.
    verdict_pending: Option<(CheckOutcome, ConnectionFate)>,
    /// Set once, the instant `phase` first becomes `Body` (see `consume_head_byte`).
    /// `Phase::Finished` loses the information of which phase preceded it, so this
    /// is what lets test and fuzz code confirm a case actually reached `Phase::Body`
    /// rather than only inferring it from a nonzero `body_len_for_test()`, which
    /// would miss a case where the peer closed with zero body bytes retained. Exists
    /// for `prop_never_exceeds_caps`'s nonzero-fraction guard; see #739 BLOCKING 1.
    entered_body: bool,
}

impl HttpCheckCodec {
    /// A codec whose body buffer is preallocated to `compiled.response_buffer_size()`.
    #[must_use]
    pub fn new(compiled: &CompiledHttpCheck) -> Self {
        Self {
            phase: Phase::StatusLine,
            status_buf: [0; 12],
            status_len: 0,
            status: 0,
            crlf: 0,
            head_scanned: 0,
            body: Vec::with_capacity(compiled.response_buffer_size),
            matched_at_len: 0,
            verdict_pending: None,
            entered_body: false,
        }
    }

    /// Clear the parse state, keeping the buffer's capacity. Allocation-free.
    pub fn reset(&mut self) {
        self.phase = Phase::StatusLine;
        self.status_buf = [0; 12];
        self.status_len = 0;
        self.status = 0;
        self.crlf = 0;
        self.head_scanned = 0;
        self.body.clear();
        self.matched_at_len = 0;
        self.verdict_pending = None;
        self.entered_body = false;
    }

    /// The parsed status, once the status line has been read.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        if self.status_len == 13 {
            Some(self.status)
        } else {
            None
        }
    }

    /// Store the verdict and move to `Finished` before returning `Done`, per the
    /// design rule that every `Done`-producing step does this in that order, which
    /// is what makes a later call idempotent.
    fn finish(&mut self, outcome: CheckOutcome, fate: ConnectionFate) -> CodecStep {
        self.verdict_pending = Some((outcome, fate));
        self.phase = Phase::Finished;
        CodecStep::Done { outcome, fate }
    }

    /// Consume response bytes. Allocation-free; never retains more than
    /// `response_buffer_size` body bytes or scans more than `max_head_bytes` head bytes.
    pub fn on_bytes(&mut self, chunk: &[u8], compiled: &CompiledHttpCheck) -> CodecStep {
        let mut idx = 0usize;
        loop {
            if self.phase == Phase::Finished {
                let (outcome, fate) = self.verdict_pending.unwrap_or((
                    CheckOutcome::Fail(FailKind::Protocol),
                    ConnectionFate::Close,
                ));
                return CodecStep::Done { outcome, fate };
            }
            let Some(&byte) = chunk.get(idx) else {
                return CodecStep::NeedMore;
            };
            idx = idx.saturating_add(1);

            let step = match self.phase {
                Phase::StatusLine => self.consume_status_line_byte(byte),
                Phase::Head => self.consume_head_byte(byte, compiled),
                Phase::Body => self.consume_body_byte(byte, compiled),
                Phase::Finished => {
                    // Not reachable: the check above already returned once
                    // `phase` is `Finished`. Kept as a safe no-op arm rather
                    // than a panicking macro, because this codec must never
                    // panic on any input.
                    None
                }
            };
            if let Some(step) = step {
                return step;
            }
        }
    }

    /// The peer closed. Decides the check.
    pub fn on_eof(&mut self, compiled: &CompiledHttpCheck) -> CodecStep {
        match self.phase {
            Phase::StatusLine | Phase::Head => self.finish(
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            ),
            Phase::Body => {
                if patterns_match(&self.body, &compiled.receive) {
                    self.finish(CheckOutcome::Pass, ConnectionFate::Close)
                } else {
                    self.finish(CheckOutcome::Fail(FailKind::Body), ConnectionFate::Close)
                }
            }
            Phase::Finished => {
                let (outcome, fate) = self.verdict_pending.unwrap_or((
                    CheckOutcome::Fail(FailKind::Protocol),
                    ConnectionFate::Close,
                ));
                CodecStep::Done { outcome, fate }
            }
        }
    }

    /// One byte of `Phase::StatusLine`. Returns `Some(step)` when the check is
    /// decided (always a protocol failure, from this phase) or when the status
    /// line has just parsed successfully and processing should continue with the
    /// next byte; returns `None` while fewer than 12 bytes have arrived.
    fn consume_status_line_byte(&mut self, byte: u8) -> Option<CodecStep> {
        let i = usize::from(self.status_len);
        if let Some(slot) = self.status_buf.get_mut(i) {
            *slot = byte;
        }
        self.status_len = self.status_len.saturating_add(1);
        self.head_scanned = self.head_scanned.saturating_add(1);
        if self.status_len < 12 {
            return None;
        }

        let buf = self.status_buf;
        if buf.get(0..5) != Some(b"HTTP/".as_slice()) {
            return Some(self.finish(
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            ));
        }
        let version_ok = buf.get(5) == Some(&b'1')
            && buf.get(6) == Some(&b'.')
            && matches!(buf.get(7), Some(&b'0' | &b'1'));
        if !version_ok {
            return Some(self.finish(
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            ));
        }
        if buf.get(8) != Some(&b' ') {
            return Some(self.finish(
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            ));
        }
        let Some(((&d0, &d1), &d2)) = buf.get(9).zip(buf.get(10)).zip(buf.get(11)) else {
            return Some(self.finish(
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            ));
        };
        if !(d0.is_ascii_digit() && d1.is_ascii_digit() && d2.is_ascii_digit()) {
            return Some(self.finish(
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            ));
        }
        let status = u16::from(d0 - b'0') * 100 + u16::from(d1 - b'0') * 10 + u16::from(d2 - b'0');
        self.status = status;
        self.status_len = 13;
        self.crlf = 0;
        self.phase = Phase::Head;
        None
    }

    /// One byte of `Phase::Head`. Returns `Some(step)` once the head is complete
    /// or the head-size cap is exceeded, `None` otherwise.
    fn consume_head_byte(&mut self, byte: u8, compiled: &CompiledHttpCheck) -> Option<CodecStep> {
        self.head_scanned = self.head_scanned.saturating_add(1);
        if self.head_scanned > compiled.max_head_bytes {
            return Some(self.finish(
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            ));
        }
        let expected = CRLF_SEQ.get(usize::from(self.crlf)).copied();
        if expected == Some(byte) {
            self.crlf = self.crlf.saturating_add(1);
        } else {
            self.crlf = u8::from(byte == b'\r');
        }
        if self.crlf < 4 {
            return None;
        }

        let retriable = compiled.retriable.iter().any(|r| r.contains(self.status));
        let outcome = if retriable {
            CheckOutcome::Fail(FailKind::RetriableStatus)
        } else if !compiled.expected.iter().any(|r| r.contains(self.status)) {
            CheckOutcome::Fail(FailKind::Status)
        } else {
            CheckOutcome::Pass
        };
        let fate = if compiled.method_is_head || self.status == 204 || self.status == 304 {
            ConnectionFate::Reusable
        } else {
            ConnectionFate::Close
        };
        if matches!(outcome, CheckOutcome::Fail(_)) {
            return Some(self.finish(outcome, fate));
        }
        if compiled.receive.is_empty() || compiled.method_is_head {
            return Some(self.finish(CheckOutcome::Pass, fate));
        }
        self.body.clear();
        self.matched_at_len = 0;
        self.phase = Phase::Body;
        self.entered_body = true;
        None
    }

    /// One byte of `Phase::Body`. Returns `Some(step)` once the configured
    /// `receive` patterns all matched or the buffer filled without a match,
    /// `None` otherwise.
    fn consume_body_byte(&mut self, byte: u8, compiled: &CompiledHttpCheck) -> Option<CodecStep> {
        // `<` here (rather than `<=`) is defense in depth, not the actual
        // enforcement: `full` below becomes true on the exact byte that takes
        // `body.len()` to `response_buffer_size`, and whenever `full` is true
        // this function unconditionally calls `finish`, which moves `phase` to
        // `Finished`. A `Finished` codec never reaches this function again (see
        // `on_bytes`'s phase check), so no later call can ever observe
        // `self.body.len() >= compiled.response_buffer_size` on entry, and
        // widening this guard to `<=` cannot be distinguished by any input: it
        // was confirmed equivalent by mutating it and rerunning the suite,
        // including `infinite_body_bounded` and `prop_never_exceeds_caps`,
        // which both stayed green.
        if self.body.len() < compiled.response_buffer_size {
            self.body.push(byte);
        }
        let full = self.body.len() == compiled.response_buffer_size;
        let grew_enough = self.body.len().saturating_sub(self.matched_at_len) >= MATCH_BATCH_BYTES;
        if !(full || grew_enough) {
            return None;
        }
        self.matched_at_len = self.body.len();
        if patterns_match(&self.body, &compiled.receive) {
            return Some(self.finish(CheckOutcome::Pass, ConnectionFate::Close));
        }
        if full {
            return Some(self.finish(CheckOutcome::Fail(FailKind::Body), ConnectionFate::Close));
        }
        None
    }
}

// Test-and-fuzz-only introspection. `cfg(fuzzing)` is the flag `cargo fuzz`
// passes for the whole crate graph it builds, including path dependencies, which
// is what lets `fuzz_health_response_parser` (a separate crate) observe the
// same invariants the property tests below check from inside this crate.
// `pub` rather than `pub(crate)` is required for that cross-crate visibility;
// under a normal (non-test, non-fuzz) build this whole block does not exist, so
// it adds no production API surface.
#[cfg(any(test, fuzzing))]
impl HttpCheckCodec {
    /// Retained body length. Test and fuzz introspection only.
    #[must_use]
    pub fn body_len_for_test(&self) -> usize {
        self.body.len()
    }

    /// Cumulative head-scan byte count. Test and fuzz introspection only.
    #[must_use]
    pub fn head_scanned_for_test(&self) -> usize {
        self.head_scanned
    }

    /// The body buffer's current capacity. Test and fuzz introspection only.
    #[must_use]
    pub fn body_capacity_for_test(&self) -> usize {
        self.body.capacity()
    }

    /// True once this codec ever reached `Phase::Body`, even if it later
    /// finished with an empty retained body. Test and fuzz introspection only;
    /// see the field doc on `entered_body`.
    #[must_use]
    pub fn entered_body_for_test(&self) -> bool {
        self.entered_body
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::too_many_lines,
        reason = "validate_rejects_table exercises one row per invariant-7 clause, and the length is the point: fewer rows means a mutation could hide behind an untested clause"
    )]

    use super::*;
    use proptest::prelude::*;

    fn valid_spec() -> HttpCheckSpec {
        HttpCheckSpec {
            host: Some("svc.local".into()),
            ..HttpCheckSpec::default()
        }
    }

    fn boxed_patterns(pats: &[&[u8]]) -> Box<[Box<[u8]>]> {
        pats.iter().map(|p| Box::from(*p)).collect()
    }

    #[test]
    fn default_spec_values() {
        let spec = HttpCheckSpec::default();
        assert_eq!(spec.method, HttpCheckMethod::Get);
        assert_eq!(
            spec.expected_statuses,
            vec![StatusRange { lo: 200, hi: 300 }]
        );
        assert_eq!(spec.retriable_statuses, Vec::<StatusRange>::new());
        assert_eq!(spec.receive, Vec::<Vec<u8>>::new());
        assert_eq!(spec.response_buffer_size, 1024);
        assert_eq!(spec.max_head_bytes, 1024);
    }

    #[test]
    fn validate_rejects_table() {
        let base = valid_spec();
        assert!(base.validate().is_ok(), "fixture must itself be valid");

        let cases: Vec<(&str, HttpCheckSpec)> = vec![
            (
                "health.http.path",
                HttpCheckSpec {
                    path: String::new(),
                    ..base.clone()
                },
            ),
            (
                "health.http.path",
                HttpCheckSpec {
                    path: "health".into(),
                    ..base.clone()
                },
            ),
            (
                "health.http.path",
                HttpCheckSpec {
                    path: "/a b".into(),
                    ..base.clone()
                },
            ),
            (
                "health.http.host",
                HttpCheckSpec {
                    host: None,
                    ..base.clone()
                },
            ),
            (
                "health.http.expected_statuses",
                HttpCheckSpec {
                    expected_statuses: Vec::new(),
                    ..base.clone()
                },
            ),
            (
                "health.http.expected_statuses",
                HttpCheckSpec {
                    expected_statuses: vec![StatusRange { lo: 300, hi: 300 }],
                    ..base.clone()
                },
            ),
            (
                "health.http.expected_statuses",
                HttpCheckSpec {
                    expected_statuses: vec![StatusRange { lo: 200, hi: 700 }],
                    ..base.clone()
                },
            ),
            (
                "health.http.receive",
                HttpCheckSpec {
                    receive: vec![Vec::new()],
                    ..base.clone()
                },
            ),
            (
                "health.http.receive",
                HttpCheckSpec {
                    receive: vec![vec![b'x'; 257]],
                    ..base.clone()
                },
            ),
            (
                "health.http.receive",
                HttpCheckSpec {
                    receive: (0..9).map(|_| vec![b'x']).collect(),
                    ..base.clone()
                },
            ),
            (
                "health.http.receive",
                HttpCheckSpec {
                    receive: (0..3).map(|_| vec![b'x'; 200]).collect(),
                    ..base.clone()
                },
            ),
            (
                "health.http.expected_statuses",
                HttpCheckSpec {
                    expected_statuses: (0..9)
                        .map(|i| StatusRange {
                            lo: i * 10,
                            hi: i * 10 + 1,
                        })
                        .collect(),
                    ..base.clone()
                },
            ),
            (
                "health.http.response_buffer_size",
                HttpCheckSpec {
                    response_buffer_size: 0,
                    ..base.clone()
                },
            ),
            (
                "health.http.response_buffer_size",
                HttpCheckSpec {
                    response_buffer_size: 4097,
                    ..base.clone()
                },
            ),
            (
                "health.http.max_head_bytes",
                HttpCheckSpec {
                    max_head_bytes: 15,
                    ..base.clone()
                },
            ),
            (
                "health.http.max_head_bytes",
                HttpCheckSpec {
                    max_head_bytes: 8193,
                    ..base.clone()
                },
            ),
            (
                "health.http.headers",
                HttpCheckSpec {
                    headers: (0..17).map(|i| (format!("x-{i}"), "v".into())).collect(),
                    ..base.clone()
                },
            ),
            (
                "health.http.headers.value",
                HttpCheckSpec {
                    headers: vec![("x-probe".into(), "a\rb".into())],
                    ..base.clone()
                },
            ),
            (
                "health.http.request_size",
                HttpCheckSpec {
                    headers: (0..16)
                        .map(|i| (format!("x-pad-{i}"), "v".repeat(600)))
                        .collect(),
                    ..base.clone()
                },
            ),
            (
                "health.http.receive",
                HttpCheckSpec {
                    method: HttpCheckMethod::Head,
                    receive: vec![vec![b'x']],
                    ..base.clone()
                },
            ),
        ];

        for (expected_field, spec) in cases {
            let err = spec.validate().expect_err("row must be rejected");
            assert_eq!(err.field, expected_field, "spec: {spec:?}");
        }
    }

    #[test]
    fn compiled_request_bytes_exact() {
        let spec = HttpCheckSpec {
            method: HttpCheckMethod::Get,
            path: "/healthz".into(),
            host: Some("svc.local".into()),
            headers: vec![("x-probe".into(), "1".into())],
            ..HttpCheckSpec::default()
        };
        let compiled = spec.compile().expect("valid spec");
        let expected: &[u8] = b"GET /healthz HTTP/1.1\r\n\
host: svc.local\r\n\
user-agent: irontraffic-healthcheck\r\n\
accept: */*\r\n\
connection: keep-alive\r\n\
x-probe: 1\r\n\
\r\n";
        assert_eq!(compiled.request_bytes(), expected);
    }

    #[test]
    fn pass_2xx_no_receive() {
        let compiled = valid_spec().compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        let step = codec.on_bytes(
            b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nok\n",
            &compiled,
        );
        assert_eq!(
            step,
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            }
        );
        assert_eq!(codec.status(), Some(200));
    }

    #[test]
    fn fail_status_out_of_range() {
        let compiled = valid_spec().compile().expect("valid spec");

        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 503 Service Unavailable\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Status),
                fate: ConnectionFate::Close,
            }
        );

        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 204 No Content\r\n\r\n", &compiled),
            CodecStep::Done {
                // 204 is inside the default `[200, 300)` expected range, so this
                // one passes; the fate-matrix point this row makes is that the
                // connection is still `Reusable`, independent of pass or fail.
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Reusable,
            }
        );

        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 304 Not Modified\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Status),
                fate: ConnectionFate::Reusable,
            }
        );

        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn retriable_checked_before_expected() {
        let spec = HttpCheckSpec {
            expected_statuses: vec![StatusRange { lo: 200, hi: 300 }],
            retriable_statuses: vec![StatusRange { lo: 200, hi: 201 }],
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::RetriableStatus),
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn byte_at_a_time_equals_one_chunk() {
        let spec = HttpCheckSpec {
            receive: vec![b"NEEDLE".to_vec()],
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut response = Vec::new();
        response.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        response.extend_from_slice(b"content-length: 30\r\n");
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(b"xxxxxxxxxxxxxxxxxxxxNEEDLExxxx");

        let mut whole = HttpCheckCodec::new(&compiled);
        let mut whole_step = whole.on_bytes(&response, &compiled);
        if whole_step == CodecStep::NeedMore {
            whole_step = whole.on_eof(&compiled);
        }

        let mut byte_at_a_time = HttpCheckCodec::new(&compiled);
        let mut byte_step = CodecStep::NeedMore;
        for &b in &response {
            byte_step = byte_at_a_time.on_bytes(&[b], &compiled);
            if matches!(byte_step, CodecStep::Done { .. }) {
                break;
            }
        }
        if byte_step == CodecStep::NeedMore {
            byte_step = byte_at_a_time.on_eof(&compiled);
        }

        assert_eq!(whole_step, byte_step);
        assert!(matches!(whole_step, CodecStep::Done { .. }));
    }

    #[test]
    fn status_line_split() {
        let compiled = valid_spec().compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(codec.on_bytes(b"HTTP/1.", &compiled), CodecStep::NeedMore);
        assert_eq!(
            codec.on_bytes(b"1 200 OK\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn not_http_rejected() {
        let compiled = valid_spec().compile().expect("valid spec");

        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"\x15\x03\x03\x00\x02\x02\x28", &compiled),
            CodecStep::NeedMore
        );
        assert_eq!(
            codec.on_eof(&compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Protocol),
                fate: ConnectionFate::Close,
            }
        );

        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"PRI * HTTP/2.0\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Protocol),
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn bad_version_rejected() {
        let compiled = valid_spec().compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.2 200 OK\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Protocol),
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn short_status_rejected() {
        let compiled = valid_spec().compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 20 OK\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Protocol),
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn four_digit_status_lenient() {
        let compiled = valid_spec().compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 2000 OK\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            }
        );
        assert_eq!(codec.status(), Some(200));
    }

    #[test]
    fn eof_before_head_fails() {
        let compiled = valid_spec().compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 200", &compiled),
            CodecStep::NeedMore
        );
        assert_eq!(
            codec.on_eof(&compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Protocol),
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn bare_lf_head_fails() {
        let spec = HttpCheckSpec {
            max_head_bytes: 64,
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        let mut input = b"HTTP/1.1 200 OK\n\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', 2000));
        assert_eq!(
            codec.on_bytes(&input, &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Protocol),
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn head_cap_boundary() {
        let spec = HttpCheckSpec {
            max_head_bytes: 20,
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");

        // 12 status-line bytes + 4 filler bytes + 4 CRLF-CRLF bytes = 20, exactly
        // the cap.
        let mut at_cap = b"HTTP/1.1 200".to_vec();
        at_cap.extend_from_slice(b"aaaa\r\n\r\n");
        assert_eq!(at_cap.len(), 20, "fixture must land exactly on the cap");

        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(&at_cap, &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            },
            "a head of exactly max_head_bytes must be accepted"
        );

        // One more filler byte pushes the CRLF-CRLF terminator one byte past the
        // cap, so the byte that would have completed it instead trips the cap.
        let mut over_cap = b"HTTP/1.1 200".to_vec();
        over_cap.extend_from_slice(b"aaaaa\r\n\r\n");
        assert_eq!(over_cap.len(), 21);
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(&over_cap, &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Protocol),
                fate: ConnectionFate::Close,
            },
            "one byte more than max_head_bytes must be rejected"
        );
    }

    #[test]
    fn crlf_matcher_extra_cr() {
        let compiled = valid_spec().compile().expect("valid spec");

        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 200 OK\r\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            },
            "the matcher must still terminate at the final LF"
        );

        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\r\n", &compiled),
            CodecStep::NeedMore,
            "this byte order must NOT terminate the head yet"
        );
    }

    #[test]
    fn receive_patterns_in_order() {
        // "alpha beta gamma" is exactly 16 bytes; response_buffer_size: 16 makes
        // the buffer fill on the last body byte of this one chunk, so the match
        // runs inside this same `on_bytes` call rather than needing `on_eof`.
        let spec = HttpCheckSpec {
            receive: vec![b"alpha".to_vec(), b"gamma".to_vec()],
            response_buffer_size: 16,
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\nalpha beta gamma", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            }
        );

        let spec = HttpCheckSpec {
            receive: vec![b"gamma".to_vec(), b"alpha".to_vec()],
            response_buffer_size: 16,
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\nalpha beta gamma", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Body),
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn receive_self_overlapping() {
        let spec = HttpCheckSpec {
            receive: vec![b"aab".to_vec()],
            response_buffer_size: 4,
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\naaab", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn receive_body_cap() {
        let spec = HttpCheckSpec {
            receive: vec![b"NEEDLE".to_vec()],
            response_buffer_size: 8,
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        let step = codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\nxxxxxxxxxxNEEDLE", &compiled);
        assert_eq!(
            step,
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Body),
                fate: ConnectionFate::Close,
            }
        );
        assert_eq!(codec.body_len_for_test(), 8);
    }

    #[test]
    fn receive_pass_closes() {
        // Body is exactly "ok" (2 bytes); response_buffer_size: 2 makes the
        // buffer fill on that last byte, so the match runs inside this call.
        let spec = HttpCheckSpec {
            receive: vec![b"ok".to_vec()],
            response_buffer_size: 2,
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        let step = codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\nok", &compiled);
        assert_eq!(
            step,
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn head_method_ignores_body() {
        let spec = HttpCheckSpec {
            method: HttpCheckMethod::Head,
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        assert_eq!(
            codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\n", &compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Reusable,
            }
        );
    }

    #[test]
    fn on_bytes_after_done_idempotent() {
        let compiled = valid_spec().compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        let done = codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\n", &compiled);
        assert!(matches!(done, CodecStep::Done { .. }));
        let before_len = codec.body_len_for_test();
        for _ in 0..3 {
            let step = codec.on_bytes(b"more garbage bytes", &compiled);
            assert_eq!(step, done);
        }
        assert_eq!(codec.body_len_for_test(), before_len);
    }

    #[test]
    fn reset_then_reuse() {
        let compiled = valid_spec().compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);

        let step4 = codec.on_bytes(
            b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nok\n",
            &compiled,
        );
        assert_eq!(
            step4,
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            }
        );

        codec.reset();

        let step5 = codec.on_bytes(b"HTTP/1.1 503 Service Unavailable\r\n\r\n", &compiled);
        assert_eq!(
            step5,
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Status),
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn infinite_body_bounded() {
        let spec = HttpCheckSpec {
            receive: vec![b"never".to_vec()],
            response_buffer_size: 1024,
            ..valid_spec()
        };
        let compiled = spec.compile().expect("valid spec");
        let mut codec = HttpCheckCodec::new(&compiled);
        let initial_capacity = codec.body_capacity_for_test();

        let head = codec.on_bytes(b"HTTP/1.1 200 OK\r\n\r\n", &compiled);
        assert_eq!(head, CodecStep::NeedMore);

        let big_x = vec![b'x'; 1024 * 1024];
        let step = codec.on_bytes(&big_x, &compiled);
        assert_eq!(
            step,
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Body),
                fate: ConnectionFate::Close,
            }
        );
        assert_eq!(codec.body_len_for_test(), 1024);
        assert_eq!(
            codec.body_capacity_for_test(),
            initial_capacity,
            "the body buffer must never reallocate"
        );
    }

    #[test]
    fn patterns_match_via_boxed_slices() {
        // Exercises `patterns_match` through boxed-slice construction, matching
        // the exact type `CompiledHttpCheck::receive` stores, complementing the
        // free-function tests in `health::mod`.
        let patterns = boxed_patterns(&[b"a", b"b"]);
        assert!(!patterns_match(b"ba", &patterns));
        assert!(patterns_match(b"ab", &patterns));
    }

    /// Response generator shared by [`prop_never_exceeds_caps`] and
    /// [`prop_chunking_invariant`].
    ///
    /// #739 BLOCKING 1: the original generator was
    /// `proptest::collection::vec(any::<u8>(), ..)`, uniformly random bytes. A
    /// uniformly random byte string begins with the 5-byte `HTTP/` magic with
    /// probability roughly `256^-5`, so every one of the 256-or-more generated
    /// cases died in `consume_status_line_byte` and returned `Fail(Protocol)`
    /// without ever reaching `Phase::Head`, `Phase::Body`,
    /// `response_buffer_size`, or `patterns_match`. This generator instead
    /// mixes three shapes: fully arbitrary bytes (kept, so the `StatusLine`
    /// rejection paths of edge cases 5, 6, 7, and 9 are not lost), a
    /// well-formed head with a fixed passing status (weighted heaviest, so
    /// `Phase::Body` is reached often enough that `prop_never_exceeds_caps`'s
    /// nonzero-fraction assertion is not a coin flip), and a well-formed head
    /// with a status drawn from the full range (so `Fail(Status)` and
    /// `Fail(RetriableStatus)` stay reachable too).
    fn response_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            1 => proptest::collection::vec(any::<u8>(), 0..=16 * 1024),
            3 => proptest::collection::vec(any::<u8>(), 0..=16 * 1024).prop_map(|tail| {
                let mut v = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
                v.extend(tail);
                v
            }),
            1 => (0u16..1000, proptest::collection::vec(any::<u8>(), 0..=16 * 1024)).prop_map(
                |(status, tail)| {
                    let mut v = format!("HTTP/1.1 {status:03} OK\r\n\r\n").into_bytes();
                    v.extend(tail);
                    v
                }
            ),
        ]
    }

    /// Independent, non-incremental reference for the head-parsing and status
    /// classification `HttpCheckCodec` computes incrementally, used only by
    /// [`prop_chunking_invariant`].
    ///
    /// #739 BLOCKING 1's second problem: comparing two chunkings of the SAME
    /// codec can never disagree, because `on_bytes` is a pure per-byte loop
    /// whose only per-call state is the local `idx` in `on_bytes` itself;
    /// chunking never enters any decision the codec makes, so a bug in the
    /// per-byte transition logic (for example the wrong HTTP version digit,
    /// or a `crlf` mismatch rule that resets to zero instead of
    /// `u8::from(byte == b'\r')`) reproduces identically under every
    /// chunking of the same byte sequence. That made the property
    /// unfalsifiable: it could pass on a codec that was simply wrong, as
    /// long as it was wrong the same way regardless of chunking. This oracle
    /// recomputes the verdict from the whole buffer at once with a different
    /// technique (`slice::windows` over the literal `\r\n\r\n`, proven
    /// equivalent to the codec's incremental matcher by the `head_cap_boundary`
    /// and `crlf_matcher_extra_cr` tests already tracing that equivalence by
    /// hand), so a divergence between the codec's incremental result and this
    /// batch recomputation is a real correctness signal, not just a
    /// chunk-boundary artifact. The two-chunking comparison is kept alongside
    /// it: cheap, and still a real regression guard against a future
    /// refactor that accidentally makes `on_bytes` depend on `chunk.len()`.
    fn oracle_verdict(
        spec: &HttpCheckSpec,
        response: &[u8],
        max_head_bytes: usize,
        response_buffer_size: usize,
    ) -> (CheckOutcome, ConnectionFate) {
        if response.len() < 12 || response[0..5] != *b"HTTP/" {
            return (
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            );
        }
        let version_ok =
            response[5] == b'1' && response[6] == b'.' && matches!(response[7], b'0' | b'1');
        if !version_ok || response[8] != b' ' {
            return (
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            );
        }
        let (d0, d1, d2) = (response[9], response[10], response[11]);
        if !(d0.is_ascii_digit() && d1.is_ascii_digit() && d2.is_ascii_digit()) {
            return (
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            );
        }
        let status = u16::from(d0 - b'0') * 100 + u16::from(d1 - b'0') * 10 + u16::from(d2 - b'0');

        let search_window = &response[..response.len().min(max_head_bytes)];
        let Some(term) = search_window.windows(4).position(|w| w == b"\r\n\r\n") else {
            return (
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            );
        };
        let head_len = term + 4;
        if head_len > max_head_bytes {
            return (
                CheckOutcome::Fail(FailKind::Protocol),
                ConnectionFate::Close,
            );
        }

        let retriable = spec.retriable_statuses.iter().any(|r| r.contains(status));
        let outcome = if retriable {
            CheckOutcome::Fail(FailKind::RetriableStatus)
        } else if !spec.expected_statuses.iter().any(|r| r.contains(status)) {
            CheckOutcome::Fail(FailKind::Status)
        } else {
            CheckOutcome::Pass
        };
        let method_is_head = spec.method == HttpCheckMethod::Head;
        let fate = if method_is_head || status == 204 || status == 304 {
            ConnectionFate::Reusable
        } else {
            ConnectionFate::Close
        };
        if matches!(outcome, CheckOutcome::Fail(_)) {
            return (outcome, fate);
        }
        if spec.receive.is_empty() || method_is_head {
            return (CheckOutcome::Pass, fate);
        }

        let body: Vec<u8> = response[head_len..]
            .iter()
            .copied()
            .take(response_buffer_size)
            .collect();
        let patterns: Box<[Box<[u8]>]> = spec
            .receive
            .iter()
            .map(|p| p.clone().into_boxed_slice())
            .collect();
        if patterns_match(&body, &patterns) {
            (CheckOutcome::Pass, ConnectionFate::Close)
        } else {
            (CheckOutcome::Fail(FailKind::Body), ConnectionFate::Close)
        }
    }

    #[test]
    fn prop_never_exceeds_caps() {
        use proptest::test_runner::{Config, TestRunner};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let strategy = (
            1u32..=4096u32,
            16u32..=8192u32,
            0usize..=3,
            1usize..=8,
            response_strategy(),
            proptest::collection::vec(1usize..=37, 0..=200),
        );

        // #739 BLOCKING 1: "add an assertion that a nonzero fraction of cases
        // reach Phase::Body, so this cannot silently go vacuous again." A
        // per-case `prop_assert!` cannot express "nonzero fraction of ALL
        // cases"; it can only express a fact about one case. `TestRunner::run`
        // is called directly (instead of going through the `proptest!` macro)
        // specifically so these counters can be inspected once every
        // generated case has run, which `Config::default()` still sizes from
        // `PROPTEST_CASES` exactly as the macro does (`contextualize_config`
        // reads the environment either way).
        let total = Arc::new(AtomicUsize::new(0));
        let reached_body = Arc::new(AtomicUsize::new(0));
        let total_in = Arc::clone(&total);
        let reached_body_in = Arc::clone(&reached_body);

        let mut runner = TestRunner::new(Config::default());
        let run_result = runner.run(&strategy, move |params| {
            let (
                response_buffer_size,
                max_head_bytes,
                pattern_count,
                pattern_len,
                response,
                chunk_sizes,
            ) = params;
            total_in.fetch_add(1, Ordering::Relaxed);
            let receive: Vec<Vec<u8>> = (0..pattern_count)
                .map(|i| {
                    let byte = b'a' + u8::try_from(i % 26).unwrap_or(0);
                    vec![byte; pattern_len]
                })
                .collect();
            let spec = HttpCheckSpec {
                host: Some("h".into()),
                receive,
                response_buffer_size,
                max_head_bytes,
                ..HttpCheckSpec::default()
            };
            let compiled = spec.compile().expect("constructed spec is always valid");
            let mut codec = HttpCheckCodec::new(&compiled);
            let initial_capacity = codec.body_capacity_for_test();

            let n = response.len();
            let mut offset = 0usize;
            let mut calls = 0usize;
            let mut done = false;
            let mut sizes = chunk_sizes.iter().cycle();
            while offset < n {
                let size = sizes.next().copied().unwrap_or(1).max(1);
                let end = (offset + size).min(n);
                let chunk = &response[offset..end];
                offset = end;
                let step = codec.on_bytes(chunk, &compiled);
                calls += 1;
                prop_assert!(codec.body_len_for_test() <= compiled.response_buffer_size());
                prop_assert!(
                    codec.head_scanned_for_test()
                        <= usize::try_from(max_head_bytes).unwrap_or(usize::MAX) + 1
                );
                prop_assert_eq!(codec.body_capacity_for_test(), initial_capacity);
                if matches!(step, CodecStep::Done { .. }) {
                    done = true;
                    break;
                }
            }
            if !done {
                let step = codec.on_eof(&compiled);
                calls += 1;
                let step_is_done = matches!(step, CodecStep::Done { .. });
                prop_assert!(step_is_done);
            }
            prop_assert!(calls <= n + 1);
            prop_assert!(codec.body_len_for_test() <= compiled.response_buffer_size());
            prop_assert!(
                codec.head_scanned_for_test()
                    <= usize::try_from(max_head_bytes).unwrap_or(usize::MAX) + 1
            );
            prop_assert_eq!(codec.body_capacity_for_test(), initial_capacity);
            if codec.entered_body_for_test() {
                reached_body_in.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        });
        run_result.unwrap();

        let total = total.load(Ordering::Relaxed);
        let reached = reached_body.load(Ordering::Relaxed);
        assert!(total > 0, "the property ran zero cases");
        assert!(
            reached > 0,
            "0 of {total} cases reached Phase::Body; the response generator is \
             seeding an unparseable stream again, so Phase::Body, \
             response_buffer_size, and patterns_match are going untested (see \
             #739 BLOCKING 1)"
        );
    }

    #[test]
    fn prop_chunking_invariant() {
        use proptest::test_runner::{Config, TestRunner};

        let strategy = (
            response_strategy(),
            proptest::collection::vec(1usize..=17, 0..=200),
            proptest::collection::vec(1usize..=31, 0..=200),
        );
        let spec = HttpCheckSpec {
            host: Some("h".into()),
            receive: vec![b"NEEDLE".to_vec()],
            response_buffer_size: 256,
            max_head_bytes: 256,
            ..HttpCheckSpec::default()
        };
        let compiled = spec
            .clone()
            .compile()
            .expect("constructed spec is always valid");

        let mut runner = TestRunner::new(Config::default());
        let run_result = runner.run(&strategy, move |params| {
            let (response, chunk_sizes_a, chunk_sizes_b): (Vec<u8>, Vec<usize>, Vec<usize>) =
                params;
            let drive = |chunk_sizes: &[usize]| -> (CheckOutcome, ConnectionFate) {
                let mut codec = HttpCheckCodec::new(&compiled);
                let n = response.len();
                let mut offset = 0usize;
                let mut sizes = chunk_sizes.iter().cycle();
                while offset < n {
                    let size = sizes.next().copied().unwrap_or(1).max(1);
                    let end = (offset + size).min(n);
                    let chunk = &response[offset..end];
                    offset = end;
                    if let CodecStep::Done { outcome, fate } = codec.on_bytes(chunk, &compiled) {
                        return (outcome, fate);
                    }
                }
                match codec.on_eof(&compiled) {
                    CodecStep::Done { outcome, fate } => (outcome, fate),
                    CodecStep::NeedMore => (
                        CheckOutcome::Fail(FailKind::Protocol),
                        ConnectionFate::Close,
                    ),
                }
            };

            let a = drive(&chunk_sizes_a);
            let b = drive(&chunk_sizes_b);
            prop_assert_eq!(a, b, "two chunkings of the same response disagreed");

            let oracle = oracle_verdict(&spec, &response, 256, 256);
            prop_assert_eq!(
                a,
                oracle,
                "codec verdict disagreed with the independent oracle"
            );
            Ok(())
        });
        run_result.unwrap();
    }
}
