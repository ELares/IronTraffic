// SPDX-License-Identifier: MIT OR Apache-2.0
//! The preallocated response arena and the head writer.
//!
//! Exactly one [`ResponseArena`] is built at startup, from the configured
//! status, body size and sequence mode. Serving a request is one `write_all`
//! of a slice out of it: no formatting, no header map, no allocation.

use crate::config::OriginConfig;

/// The status codes this fixture can emit, paired with a fixed reason
/// phrase, so no formatting or lookup crate is needed. Any other accepted
/// `--status` value uses the literal reason phrase `Unassigned`: a client
/// that logs the status line should see a stable string, and an empty
/// reason phrase would be a framing difference between benchmark cells.
const REASONS: [(u16, &str); 8] = [
    (200, "OK"),
    (304, "Not Modified"),
    (400, "Bad Request"),
    (411, "Length Required"),
    (429, "Too Many Requests"),
    (431, "Request Header Fields Too Large"),
    (500, "Internal Server Error"),
    (503, "Service Unavailable"),
];

/// Looks up the reason phrase for `status` in [`REASONS`], or `"Unassigned"`.
fn reason_phrase(status: u16) -> &'static str {
    REASONS
        .iter()
        .find(|(code, _)| *code == status)
        .map_or("Unassigned", |(_, reason)| reason)
}

/// The number of ASCII digits reserved for `X-Origin-Seq`'s value: exactly
/// wide enough for `u64::MAX`, `18,446,744,073,709,551,615`.
const SEQ_DIGITS: usize = 20;

/// The ASCII digit for `n % 10`. `u8::try_from` never actually fails here
/// (the operand is always `0..=9`); the `unwrap_or` fallback keeps this
/// function itself free of `unwrap()`/`expect()`, which are denied outside
/// tests, rather than relying on that bound being obvious to the compiler.
fn digit_char(n: u64) -> u8 {
    let d = u8::try_from(n % 10).unwrap_or(0);
    b'0' + d
}

/// Renders `seq` as exactly [`SEQ_DIGITS`] zero-padded ASCII decimal digits.
fn seq_digits(seq: u64) -> [u8; SEQ_DIGITS] {
    let mut buf = [b'0'; SEQ_DIGITS];
    let mut remaining = seq;
    for slot in buf.iter_mut().rev() {
        *slot = digit_char(remaining);
        remaining /= 10;
    }
    buf
}

/// The preallocated response bytes, built once at startup.
#[derive(Debug)]
pub struct ResponseArena {
    /// The complete response: head followed by body.
    bytes: Box<[u8]>,
    /// Length of the head, `bytes[..head_len]`.
    head_len: usize,
    /// Byte offset of the reserved 20-digit `X-Origin-Seq` field within
    /// `bytes`, when sequence mode is on.
    seq_offset: Option<usize>,
}

impl ResponseArena {
    /// Builds the arena for the configured status, body size and sequence mode.
    #[must_use]
    pub fn new(config: &OriginConfig) -> Self {
        let status = config.status;
        let reason = reason_phrase(status);

        // Startup-only allocation: building the arena is `O(body_bytes)` once,
        // never on the request path. `Vec<u8>` is the right type here, unlike
        // everywhere in `serve.rs`, precisely because this function runs once.
        let mut head: Vec<u8> = Vec::new();
        head.extend_from_slice(b"HTTP/1.1 ");
        head.extend_from_slice(status.to_string().as_bytes());
        head.push(b' ');
        head.extend_from_slice(reason.as_bytes());
        head.extend_from_slice(b"\r\n");

        // RFC 9110 Section 8.6: `Content-Length` is never sent on a 204 (a
        // usage error at the config layer, so it cannot reach here) and a 304
        // carries no content, so this fixture omits the header entirely
        // rather than sending a misleading `Content-Length: 0`. Every other
        // status, including a zero-byte body, states the length explicitly.
        if status != 304 {
            head.extend_from_slice(b"Content-Length: ");
            head.extend_from_slice(config.body_bytes.to_string().as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        head.extend_from_slice(b"Connection: keep-alive\r\n");

        let seq_offset = if config.sequence {
            head.extend_from_slice(b"X-Origin-Seq: ");
            let offset = head.len();
            head.extend_from_slice(&[b'0'; SEQ_DIGITS]);
            head.extend_from_slice(b"\r\n");
            Some(offset)
        } else {
            None
        };
        head.extend_from_slice(b"\r\n");

        let head_len = head.len();
        let body_len = usize::try_from(config.body_bytes).unwrap_or(usize::MAX);

        let mut bytes = head;
        bytes.resize(head_len.saturating_add(body_len), 0x61u8);

        Self {
            bytes: bytes.into_boxed_slice(),
            head_len,
            seq_offset,
        }
    }

    /// The complete response bytes when sequence mode is off.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Writes the head with `seq` patched into the reserved 20-digit field.
    /// `out` must be at least `head_len()` bytes. Returns the head length.
    /// Panics never: an undersized `out` returns 0 and writes nothing.
    #[must_use]
    pub fn patched_head(&self, seq: u64, out: &mut [u8]) -> usize {
        if out.len() < self.head_len {
            return 0;
        }
        let Some(head_slice) = self.bytes.get(..self.head_len) else {
            return 0;
        };
        let Some(dest) = out.get_mut(..self.head_len) else {
            return 0;
        };
        dest.copy_from_slice(head_slice);

        if let Some(offset) = self.seq_offset {
            let digits = seq_digits(seq);
            if let Some(field) = out.get_mut(offset..offset + SEQ_DIGITS) {
                field.copy_from_slice(&digits);
            }
        }

        self.head_len
    }

    /// Length of the head in bytes.
    #[must_use]
    pub fn head_len(&self) -> usize {
        self.head_len
    }

    /// The body slice, shared by every response.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.bytes.get(self.head_len..).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DelayDist;
    use std::net::SocketAddr;

    fn base_config() -> OriginConfig {
        OriginConfig {
            listen: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
            body_bytes: 1024,
            status: 200,
            delay_us: 0,
            delay_dist: DelayDist::None,
            sequence: false,
            workers: 1,
            max_connections: 200_000,
            head_timeout_ms: 10_000,
            idle_timeout_ms: 60_000,
            stats_listen: None,
        }
    }

    #[test]
    fn body_matches_configured_size() {
        for size in [0u32, 1, 1024, 8192] {
            let mut config = base_config();
            config.body_bytes = size;
            let arena = ResponseArena::new(&config);
            assert_eq!(arena.body().len(), size as usize);
            assert!(arena.body().iter().all(|&b| b == 0x61));
        }
    }

    #[test]
    fn content_length_matches_body_bytes() {
        let mut config = base_config();
        config.body_bytes = 4096;
        let arena = ResponseArena::new(&config);
        let head = arena
            .bytes()
            .get(..arena.head_len())
            .expect("head fits in bytes");
        let head_text = std::str::from_utf8(head).expect("head is ASCII");
        assert!(head_text.contains("Content-Length: 4096\r\n"));
    }

    #[test]
    fn status_304_omits_content_length() {
        let mut config = base_config();
        config.status = 304;
        config.body_bytes = 0;
        let arena = ResponseArena::new(&config);
        let head = arena
            .bytes()
            .get(..arena.head_len())
            .expect("head fits in bytes");
        let head_text = std::str::from_utf8(head).expect("head is ASCII");
        assert!(!head_text.contains("Content-Length"));
        assert!(head_text.starts_with("HTTP/1.1 304 Not Modified\r\n"));
    }

    #[test]
    fn unassigned_reason_phrase_for_uncommon_status() {
        let mut config = base_config();
        config.status = 250;
        let arena = ResponseArena::new(&config);
        let head = arena
            .bytes()
            .get(..arena.head_len())
            .expect("head fits in bytes");
        let head_text = std::str::from_utf8(head).expect("head is ASCII");
        assert!(head_text.starts_with("HTTP/1.1 250 Unassigned\r\n"));
    }

    #[test]
    fn patched_head_writes_zero_padded_sequence() {
        let mut config = base_config();
        config.sequence = true;
        let arena = ResponseArena::new(&config);
        let mut out = vec![0u8; arena.head_len()];
        let written = arena.patched_head(42, &mut out);
        assert_eq!(written, arena.head_len());
        let text = std::str::from_utf8(&out).expect("head is ASCII");
        assert!(text.contains("X-Origin-Seq: 00000000000000000042\r\n"));
    }

    #[test]
    fn patched_head_rejects_undersized_out_without_panicking() {
        let mut config = base_config();
        config.sequence = true;
        let arena = ResponseArena::new(&config);
        let mut out = vec![0u8; arena.head_len() - 1];
        let written = arena.patched_head(7, &mut out);
        assert_eq!(written, 0);
        assert!(
            out.iter().all(|&b| b == 0),
            "an undersized out is never written to"
        );
    }
}
