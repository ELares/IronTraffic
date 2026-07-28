#![no_main]
//! Fuzz target for `HttpCheckCodec` and `TcpCheckCodec`'s response parsing.
//!
//! Input domain: `FuzzInput` derives `Arbitrary`. `method_raw`, `status_ranges_raw`
//! and `pattern_seed` are mapped, not passed through: `method_raw % 3` selects one
//! of the three closed `HttpCheckMethod` variants, `status_ranges_raw` is clamped to
//! at most 4 half-open ranges each satisfying `lo < hi <= 600`, and `pattern_seed`
//! is split into at most 3 non-empty patterns of at most 8 bytes each. This mapping
//! is deliberate: an arbitrary `HttpCheckSpec` almost never satisfies
//! `HttpCheckSpec::validate`'s invariant-7 bounds, and a fuzz target that spends
//! its whole budget on inputs `compile()` rejects before `on_bytes` ever runs is
//! not fuzzing the response parser at all. `response_buffer_size_raw` and
//! `max_head_bytes_raw` are likewise reduced into `[1, 4096]` and `[16, 8192]` by
//! modulus, so `compile()` succeeds on every input this target generates; `path`
//! and `host` are fixed valid constants, since the codec's own outbound request
//! bytes are not the surface under fuzzing here (the untrusted input is the
//! response, per `docs/THREAT-MODEL.md`, "Health check response parsing").
//!
//! `response` and `chunk_sizes` are the actual fuzzed surface, but `response` alone
//! is not enough for the HTTP half: #739 BLOCKING 2 found that 500,000 runs of an
//! earlier version of this target never got the HTTP codec past byte 12, because a
//! uniformly random byte string essentially never starts with `HTTP/`. The same
//! bounding reasoning this doc comment already applies to the spec seed applies to
//! the response too. `response_shape` (via `build_http_response`) picks, per input,
//! among an unmodified arbitrary stream (keeping `Phase::StatusLine` rejection
//! coverage alive), a partial `HTTP/1.1 ` prefix, and a full well-formed head with
//! an `Arbitrary`-chosen status (`status_seed`), so both shapes described in #739
//! are explored within one corpus rather than by three separate hardcoded runs.
//! This reshaping is applied ONLY to the bytes handed to `drive_http`: `drive_tcp`
//! keeps consuming `input.response` unmodified, because `TcpCheckCodec` has no
//! phase machine to gate on an HTTP-shaped prefix and the reviewer's own counters
//! showed the TCP half was already meaningfully fuzzed; reshaping its input too
//! would only shrink the per-input entropy it explores for no coverage gain.
//!
//! Contract: neither codec's `on_bytes` or `on_eof` may panic or hang, neither may
//! allocate after construction (captured as `Vec::capacity` immediately after `new`
//! and compared again after driving the whole response through), and the retained
//! body length may never exceed `response_buffer_size`. Driving to completion means
//! either `on_bytes` returns `Done` directly, or every response byte was offered and
//! `on_eof` is then called and asserted to return `Done` (never `NeedMore`). A
//! process-lifetime self-check (`assert_http_half_is_reached`, below) additionally
//! fails the run outright if the HTTP half goes back to never parsing a status line,
//! which is what let the #739 regression run to completion 500,000 times unnoticed.

use arbitrary::Arbitrary;
use irontraffic_resilience::health::{
    CodecStep, CompiledHttpCheck, CompiledTcpCheck, HttpCheckCodec, HttpCheckMethod,
    HttpCheckSpec, StatusRange, TcpCheckCodec, TcpCheckSpec,
};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    method_raw: u8,
    status_ranges_raw: Vec<(u16, u16)>,
    pattern_seed: Vec<u8>,
    response_buffer_size_raw: u16,
    max_head_bytes_raw: u16,
    /// Selects which of the three head shapes `build_http_response` glues onto
    /// `response` before it is handed to `drive_http`. See the module doc.
    response_shape: u8,
    /// The status code used when `response_shape` selects the full-head shape.
    status_seed: u8,
    response: Vec<u8>,
    chunk_sizes: Vec<u8>,
}

/// Split `seed` into at most 3 non-empty patterns of at most 8 bytes each, which
/// always satisfies `HttpCheckSpec::validate`'s invariant-7 pattern bounds
/// (at most 8 patterns, each at most 256 bytes, sum at most 512).
fn clamp_patterns(seed: &[u8]) -> Vec<Vec<u8>> {
    seed.chunks(8)
        .take(3)
        .filter(|chunk| !chunk.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// Build the bytes handed to `drive_http`: `tail` unmodified, `tail` behind a
/// partial `HTTP/1.1 ` status-line prefix, or `tail` behind a full well-formed
/// head with an `Arbitrary`-chosen 3-digit status. #739 BLOCKING 2's fix: without
/// some shape carrying a real head, the HTTP codec never leaves
/// `consume_status_line_byte`.
fn build_http_response(shape: u8, status_seed: u8, tail: &[u8]) -> Vec<u8> {
    match shape % 3 {
        0 => tail.to_vec(),
        1 => {
            let mut v = b"HTTP/1.1 ".to_vec();
            v.extend_from_slice(tail);
            v
        }
        _ => {
            let status = u16::from(status_seed) % 1000;
            let mut v = format!("HTTP/1.1 {status:03} OK\r\n\r\n").into_bytes();
            v.extend_from_slice(tail);
            v
        }
    }
}

/// Process-lifetime counters for `assert_http_half_is_reached`'s self-check.
static HTTP_RUNS: AtomicU64 = AtomicU64::new(0);
static HTTP_PARSED_STATUS_LINE: AtomicU64 = AtomicU64::new(0);

/// Fails the fuzz run outright if the HTTP half has gone back to never parsing a
/// status line. #739 BLOCKING 2's actual defect was that 500,000 executions of
/// `drive_http` completed with `parsed_status_line=0` and nothing noticed, because
/// the only thing asserted was that `drive_http` was CALLED, not that it ever got
/// anywhere. This is the same "assert reachability, not just invocation" guard
/// `prop_never_exceeds_caps` now applies in-crate, applied here at the fuzz-target
/// level: it panics (which `cargo fuzz` treats as a crash) once enough executions
/// have accumulated that a zero count can no longer be attributed to bad luck on a
/// tiny run.
fn assert_http_half_is_reached(codec: &HttpCheckCodec) {
    let total = HTTP_RUNS.fetch_add(1, Ordering::Relaxed) + 1;
    if codec.status().is_some() {
        HTTP_PARSED_STATUS_LINE.fetch_add(1, Ordering::Relaxed);
    }
    let parsed = HTTP_PARSED_STATUS_LINE.load(Ordering::Relaxed);
    assert!(
        total < 20_000 || parsed > 0,
        "parsed_status_line stayed at 0 after {total} executions: the HTTP half \
         of this fuzz target has gone unseeded again, see #739 BLOCKING 2"
    );
}

/// Feed `response` to `codec` through `chunk_sizes`-shaped chunks until it
/// reaches `Done`, calling `on_eof` if bytes run out first. Asserts the shared
/// contract along the way: the retained body never exceeds `response_buffer_size`,
/// the buffer never reallocates, and `on_eof` always finalizes.
fn drive_http(codec: &mut HttpCheckCodec, compiled: &CompiledHttpCheck, response: &[u8], chunk_sizes: &[u8]) {
    let initial_capacity = codec.body_capacity_for_test();
    let n = response.len();
    let mut offset = 0usize;
    let mut sizes = chunk_sizes.iter().cycle();
    let mut done = false;
    while offset < n {
        let raw = sizes.next().copied().unwrap_or(1);
        let size = usize::from(raw).max(1);
        let end = (offset + size).min(n);
        let chunk = &response[offset..end];
        offset = end;
        let step = codec.on_bytes(chunk, compiled);
        assert!(codec.body_len_for_test() <= compiled.response_buffer_size());
        assert_eq!(codec.body_capacity_for_test(), initial_capacity);
        if matches!(step, CodecStep::Done { .. }) {
            done = true;
            break;
        }
    }
    if !done {
        let step = codec.on_eof(compiled);
        assert!(
            matches!(step, CodecStep::Done { .. }),
            "on_eof must always finalize"
        );
    }
    assert!(codec.body_len_for_test() <= compiled.response_buffer_size());
    assert_eq!(codec.body_capacity_for_test(), initial_capacity);
}

/// The `TcpCheckCodec` counterpart of `drive_http`.
fn drive_tcp(codec: &mut TcpCheckCodec, compiled: &CompiledTcpCheck, response: &[u8], chunk_sizes: &[u8]) {
    let initial_capacity = codec.body_capacity_for_test();
    let n = response.len();
    let mut offset = 0usize;
    let mut sizes = chunk_sizes.iter().cycle();
    let mut done = false;
    while offset < n {
        let raw = sizes.next().copied().unwrap_or(1);
        let size = usize::from(raw).max(1);
        let end = (offset + size).min(n);
        let chunk = &response[offset..end];
        offset = end;
        let step = codec.on_bytes(chunk, compiled);
        assert!(codec.body_len_for_test() <= compiled.response_buffer_size());
        assert_eq!(codec.body_capacity_for_test(), initial_capacity);
        if matches!(step, CodecStep::Done { .. }) {
            done = true;
            break;
        }
    }
    if !done {
        let step = codec.on_eof(compiled);
        assert!(
            matches!(step, CodecStep::Done { .. }),
            "on_eof must always finalize"
        );
    }
    assert!(codec.body_len_for_test() <= compiled.response_buffer_size());
    assert_eq!(codec.body_capacity_for_test(), initial_capacity);
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|input: FuzzInput| {
    let method = match input.method_raw % 3 {
        0 => HttpCheckMethod::Get,
        1 => HttpCheckMethod::Head,
        _ => HttpCheckMethod::Options,
    };
    // A Head check's receive patterns must be empty (validate() rejects the
    // combination), so the patterns are dropped rather than clamped away for
    // Head, keeping every generated spec valid regardless of method.
    let receive: Vec<Vec<u8>> = if method == HttpCheckMethod::Head {
        Vec::new()
    } else {
        clamp_patterns(&input.pattern_seed)
    };

    let mut expected_statuses: Vec<StatusRange> = input
        .status_ranges_raw
        .iter()
        .take(4)
        .map(|&(lo_raw, span_raw)| {
            let lo = lo_raw % 600;
            let span = 1 + (span_raw % (600 - lo));
            StatusRange { lo, hi: lo + span }
        })
        .collect();
    if expected_statuses.is_empty() {
        expected_statuses.push(StatusRange { lo: 200, hi: 300 });
    }

    let response_buffer_size = 1 + (u32::from(input.response_buffer_size_raw) % 4096);
    let max_head_bytes = 16 + (u32::from(input.max_head_bytes_raw) % (8192 - 16 + 1));

    let http_spec = HttpCheckSpec {
        method,
        path: "/healthz".into(),
        host: Some("svc.local".into()),
        headers: Vec::new(),
        expected_statuses,
        retriable_statuses: Vec::new(),
        receive: receive.clone(),
        response_buffer_size,
        max_head_bytes,
    };
    let Ok(http_compiled) = http_spec.compile() else {
        // The construction above is deliberately bounded to always be valid, so
        // this should not happen; fail closed rather than panic if it ever does.
        return;
    };
    let http_response = build_http_response(input.response_shape, input.status_seed, &input.response);
    let mut http_codec = HttpCheckCodec::new(&http_compiled);
    drive_http(&mut http_codec, &http_compiled, &http_response, &input.chunk_sizes);
    assert_http_half_is_reached(&http_codec);

    let tcp_receive = if receive.is_empty() {
        vec![vec![b'o', b'k']]
    } else {
        receive
    };
    let tcp_spec = TcpCheckSpec {
        send: Vec::new(),
        receive: tcp_receive,
        response_buffer_size,
    };
    let Ok(tcp_compiled) = tcp_spec.compile() else {
        return;
    };
    let mut tcp_codec = TcpCheckCodec::new(&tcp_compiled);
    drive_tcp(&mut tcp_codec, &tcp_compiled, &input.response, &input.chunk_sizes);
});
