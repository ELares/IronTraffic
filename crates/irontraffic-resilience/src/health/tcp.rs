// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sans-IO TCP health check codec.
//!
//! [`TcpCheckSpec`] configures an optional payload sent after connect and an
//! optional ordered set of byte patterns the response must contain. Unlike
//! [`crate::health::http`], this codec never resolves any framing at all, so every
//! [`crate::health::CodecStep::Done`] it produces carries
//! [`crate::health::ConnectionFate::Close`]: there is no protocol-level signal that
//! would let the runner prove the peer is at a message boundary.
//!
//! See `crate::health::http`'s module doc for why the `*_for_test` accessors near
//! the bottom of this file are gated `cfg(any(test, fuzzing))` and why the
//! `unexpected_cfgs` allow below is needed for it.

#![allow(
    unexpected_cfgs,
    reason = "cfg(fuzzing) is the standard cargo-fuzz flag for exposing test-only introspection to a fuzz target without adding production API surface; this crate may not touch the workspace [lints] table to register it, since irontraffic-resilience must keep [lints] workspace = true"
)]

use crate::config::{ConfigError, in_range_u32};
use crate::health::schedule::{CheckOutcome, FailKind};
use crate::health::{CodecStep, ConnectionFate, patterns_match};

/// Byte offset threshold under which `TcpCheckCodec::on_bytes` defers re-running
/// `patterns_match`, mirroring `crate::health::http`'s batching rule.
const MATCH_BATCH_BYTES: usize = 64;

/// Configured TCP health check.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TcpCheckSpec {
    /// Bytes to send after connecting. Empty means send nothing.
    pub send: Vec<u8>,
    /// Byte patterns that must appear in the response, in order. Empty means do not
    /// read a response.
    pub receive: Vec<Vec<u8>>,
    /// Maximum response bytes retained. Default 1024, maximum 4096.
    pub response_buffer_size: u32,
}

impl TcpCheckSpec {
    /// Validate against invariant 8.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] naming the first rejected field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.send.len() > 4096 {
            return Err(ConfigError::new(
                "health.tcp.send",
                &self.send.len().to_string(),
                "must not exceed 4096 bytes",
            ));
        }

        in_range_u32(
            "health.tcp.response_buffer_size",
            self.response_buffer_size,
            1,
            4096,
        )?;

        if self.receive.len() > 8 {
            return Err(ConfigError::new(
                "health.tcp.receive",
                &self.receive.len().to_string(),
                "must not configure more than 8 patterns",
            ));
        }
        let mut pattern_bytes_total = 0usize;
        for pat in &self.receive {
            if pat.is_empty() {
                return Err(ConfigError::new(
                    "health.tcp.receive",
                    "",
                    "pattern must not be empty",
                ));
            }
            if pat.len() > 256 {
                return Err(ConfigError::new(
                    "health.tcp.receive",
                    &pat.len().to_string(),
                    "pattern must not exceed 256 bytes",
                ));
            }
            pattern_bytes_total = pattern_bytes_total.saturating_add(pat.len());
        }
        if pattern_bytes_total > 512 {
            return Err(ConfigError::new(
                "health.tcp.receive",
                &pattern_bytes_total.to_string(),
                "sum of pattern lengths must not exceed 512",
            ));
        }

        Ok(())
    }

    /// Validate and box the patterns.
    ///
    /// # Errors
    /// Returns the same [`ConfigError`] as [`TcpCheckSpec::validate`].
    pub fn compile(self) -> Result<CompiledTcpCheck, ConfigError> {
        self.validate()?;
        let receive: Box<[Box<[u8]>]> = self
            .receive
            .into_iter()
            .map(Vec::into_boxed_slice)
            .collect();
        // Bounded to [1, 4096] by `validate()` above, which fits in `usize` on
        // every target this workspace supports; see the identical comment in
        // `HttpCheckSpec::compile`.
        let response_buffer_size =
            usize::try_from(self.response_buffer_size).unwrap_or(usize::MAX);
        Ok(CompiledTcpCheck {
            send: self.send.into_boxed_slice(),
            receive,
            response_buffer_size,
        })
    }
}

/// A compiled TCP check. Shared by `Arc`, read-only.
pub struct CompiledTcpCheck {
    send: Box<[u8]>,
    receive: Box<[Box<[u8]>]>,
    response_buffer_size: usize,
}

impl CompiledTcpCheck {
    /// Bytes to write after connecting; may be empty.
    #[must_use]
    pub fn send_bytes(&self) -> &[u8] {
        &self.send
    }

    /// True when nothing is sent and nothing is read: a successful connect is a pass.
    #[must_use]
    pub fn is_connect_only(&self) -> bool {
        self.send.is_empty() && self.receive.is_empty()
    }

    /// True when the runner must read a response and feed the codec.
    #[must_use]
    pub fn expects_response(&self) -> bool {
        !self.receive.is_empty()
    }

    /// Maximum response bytes the codec will retain.
    #[must_use]
    pub fn response_buffer_size(&self) -> usize {
        self.response_buffer_size
    }
}

/// TCP response state for ONE IN-FLIGHT CHECK, drawn from the same kind of pool as
/// [`crate::health::http::HttpCheckCodec`] and bounded by `max_concurrent_checks`,
/// never one per endpoint.
pub struct TcpCheckCodec {
    body: Vec<u8>,
    /// `body.len()` the last time `patterns_match` ran; see
    /// `crate::health::http::HttpCheckCodec`'s field of the same name.
    matched_at_len: usize,
    /// The verdict, stored the instant `Done` is produced, so a later call replays
    /// it verbatim instead of re-parsing.
    verdict_pending: Option<(CheckOutcome, ConnectionFate)>,
}

impl TcpCheckCodec {
    /// A codec whose buffer is preallocated.
    #[must_use]
    pub fn new(compiled: &CompiledTcpCheck) -> Self {
        Self {
            body: Vec::with_capacity(compiled.response_buffer_size),
            matched_at_len: 0,
            verdict_pending: None,
        }
    }

    /// Clear state, keep capacity.
    pub fn reset(&mut self) {
        self.body.clear();
        self.matched_at_len = 0;
        self.verdict_pending = None;
    }

    fn finish(&mut self, outcome: CheckOutcome, fate: ConnectionFate) -> CodecStep {
        self.verdict_pending = Some((outcome, fate));
        CodecStep::Done { outcome, fate }
    }

    /// Consume response bytes.
    pub fn on_bytes(&mut self, chunk: &[u8], compiled: &CompiledTcpCheck) -> CodecStep {
        let mut idx = 0usize;
        loop {
            if let Some((outcome, fate)) = self.verdict_pending {
                return CodecStep::Done { outcome, fate };
            }
            let Some(&byte) = chunk.get(idx) else {
                return CodecStep::NeedMore;
            };
            idx = idx.saturating_add(1);

            if self.body.len() < compiled.response_buffer_size {
                self.body.push(byte);
            }
            let full = self.body.len() == compiled.response_buffer_size;
            let grew_enough =
                self.body.len().saturating_sub(self.matched_at_len) >= MATCH_BATCH_BYTES;
            if !(full || grew_enough) {
                continue;
            }
            self.matched_at_len = self.body.len();
            if patterns_match(&self.body, &compiled.receive) {
                return self.finish(CheckOutcome::Pass, ConnectionFate::Close);
            }
            if full {
                return self.finish(CheckOutcome::Fail(FailKind::Body), ConnectionFate::Close);
            }
        }
    }

    /// The peer closed.
    pub fn on_eof(&mut self, compiled: &CompiledTcpCheck) -> CodecStep {
        if let Some((outcome, fate)) = self.verdict_pending {
            return CodecStep::Done { outcome, fate };
        }
        if patterns_match(&self.body, &compiled.receive) {
            self.finish(CheckOutcome::Pass, ConnectionFate::Close)
        } else {
            self.finish(CheckOutcome::Fail(FailKind::Body), ConnectionFate::Close)
        }
    }
}

// See the identical comment on `crate::health::http::HttpCheckCodec`'s matching
// block: this exists for both the in-crate property tests and
// `fuzz_health_response_parser`, a separate crate that needs `pub` (not
// `pub(crate)`) visibility and observes it only under `cfg(fuzzing)`.
#[cfg(any(test, fuzzing))]
impl TcpCheckCodec {
    /// Retained body length. Test and fuzz introspection only.
    #[must_use]
    pub fn body_len_for_test(&self) -> usize {
        self.body.len()
    }

    /// The body buffer's current capacity. Test and fuzz introspection only.
    #[must_use]
    pub fn body_capacity_for_test(&self) -> usize {
        self.body.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_only_flags() {
        let compiled = TcpCheckSpec {
            send: Vec::new(),
            receive: Vec::new(),
            response_buffer_size: 1024,
        }
        .compile()
        .expect("valid spec");
        assert!(compiled.is_connect_only());
        assert!(!compiled.expects_response());
    }

    #[test]
    fn send_only_flags() {
        let compiled = TcpCheckSpec {
            send: b"PING\r\n".to_vec(),
            receive: Vec::new(),
            response_buffer_size: 1024,
        }
        .compile()
        .expect("valid spec");
        assert!(!compiled.is_connect_only());
        assert!(!compiled.expects_response());
    }

    #[test]
    fn send_and_receive_pass() {
        let compiled = TcpCheckSpec {
            send: b"PING\r\n".to_vec(),
            receive: vec![b"PONG".to_vec()],
            response_buffer_size: 1024,
        }
        .compile()
        .expect("valid spec");
        assert!(compiled.expects_response());

        let mut codec = TcpCheckCodec::new(&compiled);
        let step = codec.on_bytes(b"+PONG\r\n", &compiled);
        let step = match step {
            CodecStep::Done { .. } => step,
            CodecStep::NeedMore => codec.on_eof(&compiled),
        };
        assert_eq!(
            step,
            CodecStep::Done {
                outcome: CheckOutcome::Pass,
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn tcp_eof_before_match_fails() {
        let compiled = TcpCheckSpec {
            send: b"PING\r\n".to_vec(),
            receive: vec![b"PONG".to_vec()],
            response_buffer_size: 1024,
        }
        .compile()
        .expect("valid spec");

        let mut codec = TcpCheckCodec::new(&compiled);
        assert_eq!(codec.on_bytes(b"+PO", &compiled), CodecStep::NeedMore);
        assert_eq!(
            codec.on_eof(&compiled),
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Body),
                fate: ConnectionFate::Close,
            }
        );
    }

    #[test]
    fn tcp_buffer_cap() {
        let compiled = TcpCheckSpec {
            send: Vec::new(),
            receive: vec![b"PONG".to_vec()],
            response_buffer_size: 4,
        }
        .compile()
        .expect("valid spec");

        let mut codec = TcpCheckCodec::new(&compiled);
        let step = codec.on_bytes(b"AAAAPONG", &compiled);
        assert_eq!(
            step,
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Body),
                fate: ConnectionFate::Close,
            }
        );
        assert_eq!(codec.body_len_for_test(), 4);
    }

    #[test]
    fn tcp_validate_rejects() {
        let err = TcpCheckSpec {
            send: vec![0u8; 4097],
            receive: Vec::new(),
            response_buffer_size: 1024,
        }
        .validate()
        .expect_err("send too long");
        assert_eq!(err.field, "health.tcp.send");

        let err = TcpCheckSpec {
            send: Vec::new(),
            receive: vec![vec![0u8; 257]],
            response_buffer_size: 1024,
        }
        .validate()
        .expect_err("pattern too long");
        assert_eq!(err.field, "health.tcp.receive");
    }

    #[test]
    fn tcp_codec_never_allocates_after_construction() {
        let compiled = TcpCheckSpec {
            send: Vec::new(),
            receive: vec![b"never".to_vec()],
            response_buffer_size: 16,
        }
        .compile()
        .expect("valid spec");
        let mut codec = TcpCheckCodec::new(&compiled);
        let initial_capacity = codec.body_capacity_for_test();
        let big = vec![b'x'; 10_000];
        let step = codec.on_bytes(&big, &compiled);
        assert_eq!(
            step,
            CodecStep::Done {
                outcome: CheckOutcome::Fail(FailKind::Body),
                fate: ConnectionFate::Close,
            }
        );
        assert_eq!(codec.body_len_for_test(), 16);
        assert_eq!(codec.body_capacity_for_test(), initial_capacity);
    }
}
