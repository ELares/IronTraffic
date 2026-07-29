#![no_main]
//! Fuzz target for the gRPC health check codec's decoder and trailer parser.
//!
//! Input domain: `FuzzInput` derives `Arbitrary`. `decode_health_response` is driven
//! by `build_frame`, which picks per input among an unmodified arbitrary byte
//! stream, an arbitrary payload wrapped in a syntactically valid 5-byte prefix, and
//! a fully well-formed `HealthCheckResponse` carrying one arbitrary `u32` status
//! value. This mirrors `health::grpc::tests::frame_strategy`'s fix for the exact
//! defect `fuzz_health_response_parser` found in the HTTP codec's fuzz target
//! (#739 BLOCKING 2): 500,000 executions of an earlier version of that target,
//! seeded with nothing but uniformly random bytes, never got the HTTP codec past
//! byte 12, because a random byte string essentially never starts with a valid
//! magic prefix, let alone a valid message behind it. `parse_grpc_status` is
//! likewise driven by `build_status_text`, which either passes its seed through
//! unmodified (keeping the reject-non-digit and reject-too-long paths reachable)
//! or maps it byte-for-byte into ASCII digits (reaching the `checked_mul`/
//! `checked_add` accumulation path reliably, which a uniformly random byte string
//! reaches only with probability roughly `(10/256)^len`).
//!
//! Contract: neither function may panic, hang (the varint reader and the
//! wire-type dispatch loop both always advance their position by at least one
//! byte before looping), or read outside the input slice. `decode_health_response`
//! additionally must never allocate (verified statically: it constructs no `Vec`,
//! `String`, or `Box`, only reading through bounds-checked slice accessors and
//! mutating local primitives) and a successful decode must be stable under
//! re-decoding the same bytes.
//!
//! `assert_reachable`, mirroring `fuzz_health_response_parser`'s
//! `assert_http_half_is_reached`, fails the run outright if either decoder has
//! gone back to never completing a real parse after a meaningful number of
//! executions, which is the permanent fix for the #739 BLOCKING 2 class of defect:
//! a fuzz target that runs to completion many times while never reaching the code
//! under test is otherwise indistinguishable from one that is actually fuzzing it.

use arbitrary::Arbitrary;
use irontraffic_resilience::health::grpc::{
    MAX_MESSAGE_LEN, decode_health_response, parse_grpc_status,
};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Selects which of the three shapes `build_frame` produces.
    frame_shape: u8,
    /// The status value used when `frame_shape` selects the well-formed-frame
    /// shape.
    status_seed: u32,
    /// Raw bytes: used unmodified as one shape and as payload/filler for the
    /// others.
    frame_raw: Vec<u8>,
    /// Selects which of the two shapes `build_status_text` produces.
    status_shape: u8,
    /// Raw bytes handed to `build_status_text`.
    status_text_seed: Vec<u8>,
}

/// Wrap `body` in a syntactically valid 5-byte gRPC length prefix (uncompressed,
/// big-endian length).
fn frame_with_body(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + body.len());
    v.push(0u8);
    let len_u32 = u32::try_from(body.len()).unwrap_or(u32::MAX);
    v.extend_from_slice(&len_u32.to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// Push `n` as a base-128 varint: low 7 bits first, continuation bit `0x80` set
/// on every byte but the last. A local copy of `health::grpc`'s private
/// `push_varint`, since a fuzz target is a separate crate and cannot reach a
/// private item; this one only needs to build well-formed fixtures, not to
/// satisfy the production module's invariants.
fn push_varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let low7 = u8::try_from(n & 0x7F).unwrap_or(0);
        n >>= 7;
        if n == 0 {
            out.push(low7);
            return;
        }
        out.push(low7 | 0x80);
    }
}

/// Build the bytes handed to `decode_health_response`. See the module doc.
fn build_frame(shape: u8, status_seed: u32, raw: &[u8]) -> Vec<u8> {
    match shape % 3 {
        0 => raw.to_vec(),
        1 => {
            let capped = &raw[..raw.len().min(MAX_MESSAGE_LEN)];
            frame_with_body(capped)
        }
        _ => {
            let mut body = vec![0x08u8];
            push_varint(u64::from(status_seed), &mut body);
            frame_with_body(&body)
        }
    }
}

/// Build the bytes handed to `parse_grpc_status`. See the module doc.
fn build_status_text(shape: u8, seed: &[u8]) -> Vec<u8> {
    if shape.is_multiple_of(2) {
        seed.to_vec()
    } else {
        seed.iter().take(10).map(|b| b'0' + (b % 10)).collect()
    }
}

/// Process-lifetime counters for the reachability self-checks below.
static DECODE_RUNS: AtomicU64 = AtomicU64::new(0);
static DECODE_STATUS_PRESENT: AtomicU64 = AtomicU64::new(0);
static STATUS_PARSE_RUNS: AtomicU64 = AtomicU64::new(0);
static STATUS_PARSE_OK: AtomicU64 = AtomicU64::new(0);

/// Fails the run outright if `hits` has stayed at 0 for `total` executions past a
/// threshold small enough that CI's brief fuzz smoke run cannot trip it, but large
/// enough that a real fuzzing session must clear it. See the module doc.
fn assert_reachable(total: u64, hits: u64, what: &str) {
    assert!(
        total < 20_000 || hits > 0,
        "{what} stayed at 0 after {total} executions: this fuzz target has gone \
         unseeded again, see #739 BLOCKING 2"
    );
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|input: FuzzInput| {
    let frame = build_frame(input.frame_shape, input.status_seed, &input.frame_raw);
    let total = DECODE_RUNS.fetch_add(1, Ordering::Relaxed) + 1;
    if let Ok(Some(v)) = decode_health_response(&frame) {
        DECODE_STATUS_PRESENT.fetch_add(1, Ordering::Relaxed);
        // Stability: re-decoding the same bytes must give the same status.
        assert_eq!(
            decode_health_response(&frame),
            Ok(Some(v)),
            "re-decoding the same frame gave a different status"
        );
    }
    assert_reachable(
        total,
        DECODE_STATUS_PRESENT.load(Ordering::Relaxed),
        "decode_health_response Ok(Some(_))",
    );

    let status_text = build_status_text(input.status_shape, &input.status_text_seed);
    let status_total = STATUS_PARSE_RUNS.fetch_add(1, Ordering::Relaxed) + 1;
    if parse_grpc_status(&status_text).is_some() {
        STATUS_PARSE_OK.fetch_add(1, Ordering::Relaxed);
    }
    assert_reachable(
        status_total,
        STATUS_PARSE_OK.load(Ordering::Relaxed),
        "parse_grpc_status Some",
    );
});
