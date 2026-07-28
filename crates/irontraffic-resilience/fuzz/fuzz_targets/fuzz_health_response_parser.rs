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
//! response, per `docs/THREAT-MODEL.md`, "Health check response parsing"). `response`
//! and `chunk_sizes` are the actual fuzzed surface: an arbitrary byte stream fed to
//! both codecs through arbitrary chunk boundaries.
//!
//! Contract: neither codec's `on_bytes` or `on_eof` may panic or hang, neither may
//! allocate after construction (captured as `Vec::capacity` immediately after `new`
//! and compared again after driving the whole response through), and the retained
//! body length may never exceed `response_buffer_size`. Driving to completion means
//! either `on_bytes` returns `Done` directly, or every response byte was offered and
//! `on_eof` is then called and asserted to return `Done` (never `NeedMore`).

use arbitrary::Arbitrary;
use irontraffic_resilience::health::{
    CodecStep, CompiledHttpCheck, CompiledTcpCheck, HttpCheckCodec, HttpCheckMethod,
    HttpCheckSpec, StatusRange, TcpCheckCodec, TcpCheckSpec,
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    method_raw: u8,
    status_ranges_raw: Vec<(u16, u16)>,
    pattern_seed: Vec<u8>,
    response_buffer_size_raw: u16,
    max_head_bytes_raw: u16,
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
    let mut http_codec = HttpCheckCodec::new(&http_compiled);
    drive_http(&mut http_codec, &http_compiled, &input.response, &input.chunk_sizes);

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
