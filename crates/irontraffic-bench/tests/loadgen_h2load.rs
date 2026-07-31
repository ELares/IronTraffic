// SPDX-License-Identifier: MIT OR Apache-2.0
//! Command-line and parser tests for the `H2Load` adapter (issue #413).
//!
//! # What this fixture is and is NOT
//!
//! `tests/fixtures/h2load-output.txt` is RECONSTRUCTED, not captured, exactly
//! like `tests/fixtures/nighthawk-output.json` and for the identical reason:
//! this implementation environment has no package manager and no
//! `autoconf`, and `h2load`'s own build additionally needs `libnghttp2`,
//! OpenSSL, `libev` and `c-ares`, none of which could be installed here.
//! `crates/irontraffic-bench/src/loadgen/h2load.rs`'s own module doc records
//! the evidence trail (the exact `nghttp2` tags whose `src/h2load.cc` this
//! adapter's parser was checked against) and the honestly-flagged gaps this
//! entails. `parse_fixture` below is an authority on this parser's OWN
//! reading of that shape, not evidence that the shape matches a real
//! `h2load 1.68.1` run.

use irontraffic_bench::{
    BenchCell, BenchError, CacheMode, CellId, H2Load, Invocation, KeepaliveMode, LoadGenerator,
    MAX_H2LOAD_OUTPUT_BYTES, ParseCtx, PathCorpus, Protocol, RateMode, RunParams, Scheme, Target,
    TlsMode, ToolStamp, Unsupported,
};

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

/// A reconstructed (not captured; see the module doc) h2load-shaped text
/// output.
const FIXTURE_BYTES: &[u8] = include_bytes!("fixtures/h2load-output.txt");

/// A minimal, individually valid `BenchCell`: saturate rate (the only mode
/// h2load supports), H2, TLS off, `SingleHot`, `Both` keepalive, 64
/// connections. Mirrors `tests/loadgen_nighthawk.rs`'s own `base_cell`,
/// changed only in `rate`.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: \"base\" is a literal already \
              covered by tests/cell_id.rs's own parses_single_segment"
)]
fn base_cell() -> BenchCell {
    BenchCell {
        id: CellId::parse("base").expect("\"base\" is a valid cell id"),
        protocol: Protocol::H2,
        tls: TlsMode::Off,
        payload_bytes: 1024,
        routes: 100,
        path_corpus: PathCorpus::SingleHot,
        connections: 64,
        upstreams: 1,
        filter_depth: 0,
        cache: CacheMode::Bypass,
        keepalive: KeepaliveMode::Both,
        rate: RateMode::Saturate,
    }
}

fn base_target() -> Target {
    Target {
        scheme: Scheme::Http,
        host: "example.test".to_owned(),
        connect: std::net::SocketAddr::from(([10, 0, 0, 5], 8080)),
        sni: None,
        path_expr: "/hot".to_owned(),
    }
}

/// Pairs with [`base_cell`] and [`base_target`]: 30 measured seconds, 5
/// warmup seconds.
fn base_run() -> RunParams {
    RunParams {
        duration_secs: 30,
        warmup_secs: 5,
        concurrency: None,
    }
}

fn base_h2load() -> H2Load {
    H2Load { threads: 4 }
}

fn base_tool_stamp() -> ToolStamp {
    ToolStamp {
        name: "h2load".to_owned(),
        version: "1.68.1".to_owned(),
        image_digest: None,
    }
}

#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: base_cell/base_target/base_run are \
              this file's own fixed, valid constants, so planning cannot fail"
)]
fn base_invocation() -> Invocation {
    base_h2load()
        .plan(&base_cell(), &base_target(), &base_run())
        .expect("the base cell, target and run are individually valid")
}

fn base_ctx<'a>(
    cell: &'a BenchCell,
    invocation: &'a Invocation,
    tool: &'a ToolStamp,
) -> ParseCtx<'a> {
    ParseCtx {
        cell,
        invocation,
        tool,
    }
}

/// Asserts `err` is `BenchError::Parse` naming the `"h2load"` tool and
/// returns its `detail` text, so every caller can assert on the SPECIFIC
/// reason rather than only the variant. Matches
/// `tests/loadgen_nighthawk.rs`'s own identically shaped helper.
#[allow(
    clippy::panic,
    reason = "test-support helper, not itself a #[test] fn: panicking here surfaces which \
              caller's assertion actually failed, with the real BenchError in the message"
)]
fn expect_parse_detail(err: &BenchError) -> String {
    match err {
        BenchError::Parse { tool, detail } => {
            assert_eq!(*tool, "h2load");
            detail.as_str().to_owned()
        }
        other => panic!("expected BenchError::Parse, got {other:?}"),
    }
}

/// `HdrHistogram`'s own stated precision guarantee is accuracy to within 3
/// significant decimal digits of the true value, never bit-for-bit
/// equality, matching `tests/hist.rs`'s own identically named helper
/// (private to that separate integration-test binary, so this file has its
/// own small copy rather than a cross-test-binary dependency).
fn assert_within_3sig(actual: u64, expected: u64, msg: &str) {
    #[allow(
        clippy::cast_precision_loss,
        reason = "expected is a nanosecond count well under 2^53 in every fixture this file \
                  builds, so this multiplication is exact enough for a tolerance check"
    )]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "expected as f64 * 0.001 is at most a few tens of millions in every fixture \
                  this file builds, and .ceil() of a non-negative number is never negative, so \
                  this cast back to u64 is always exact and always non-negative"
    )]
    let tolerance = (expected as f64 * 0.001).ceil() as u64 + 1;
    let diff = actual.abs_diff(expected);
    assert!(
        diff <= tolerance,
        "{msg}: actual={actual} expected={expected} diff={diff} tolerance={tolerance}"
    );
}

// ---------------------------------------------------------------------------
// 1. plan_pins_the_argument_vector
// ---------------------------------------------------------------------------

#[test]
fn plan_pins_the_argument_vector() {
    let invocation = base_invocation();
    assert_eq!(invocation.program, "h2load");
    assert_eq!(
        invocation.args,
        vec![
            "--duration".to_owned(),
            "30".to_owned(),
            "--warm-up-time".to_owned(),
            "5".to_owned(),
            "-c".to_owned(),
            "64".to_owned(),
            "-t".to_owned(),
            "4".to_owned(),
            "-m".to_owned(),
            "100".to_owned(),
            "--header".to_owned(),
            "host: example.test".to_owned(),
            "http://10.0.0.5:8080/hot".to_owned(),
        ]
    );
}

// ---------------------------------------------------------------------------
// 2. plan_never_emits_rate
// ---------------------------------------------------------------------------

#[test]
fn plan_never_emits_rate() {
    let h2load = base_h2load();
    let target = base_target();
    let run = base_run();
    for protocol in [Protocol::H1, Protocol::H2, Protocol::H3] {
        let mut cell = base_cell();
        cell.protocol = protocol;
        // Saturate is the only rate mode h2load's own `supports` accepts;
        // this loop covers every cell the adapter can plan at all.
        let invocation = h2load
            .plan(&cell, &target, &run)
            .unwrap_or_else(|e| panic!("{protocol:?} must plan: {e}"));
        assert!(
            !invocation.args.iter().any(|a| a == "--rate"),
            "{protocol:?}: --rate must never appear, args = {:?}",
            invocation.args
        );
    }
}

// ---------------------------------------------------------------------------
// 3. fixed_rate_is_unsupported
// ---------------------------------------------------------------------------

#[test]
fn fixed_rate_is_unsupported() {
    let mut cell = base_cell();
    cell.rate = RateMode::Fixed(50_000);
    let err = base_h2load()
        .supports(&cell)
        .expect_err("h2load never supports RateMode::Fixed");
    let Unsupported::RateMode { tool, detail } = err else {
        panic!("expected Unsupported::RateMode, got {err:?}");
    };
    assert_eq!(tool, "h2load");
    assert!(
        detail.contains("connections"),
        "the message must name the connections-per-period trap verbatim: {detail:?}"
    );

    // `plan` must refuse the same cell, mapping to `BenchError::Cell`.
    let plan_err = base_h2load()
        .plan(&cell, &base_target(), &base_run())
        .expect_err("plan must refuse a fixed-rate cell too");
    assert!(matches!(plan_err, BenchError::Cell(_)));
}

// ---------------------------------------------------------------------------
// 4. protocol_flags
// ---------------------------------------------------------------------------

#[test]
fn protocol_flags() {
    let h2load = base_h2load();
    let target = base_target();
    let run = base_run();

    let mut h1_cell = base_cell();
    h1_cell.protocol = Protocol::H1;
    let h1 = h2load.plan(&h1_cell, &target, &run).expect("valid cell");
    assert!(h1.args.iter().any(|a| a == "--h1"));
    assert!(!h1.args.iter().any(|a| a == "--h3"));

    let mut h2_cell = base_cell();
    h2_cell.protocol = Protocol::H2;
    let h2 = h2load.plan(&h2_cell, &target, &run).expect("valid cell");
    assert!(!h2.args.iter().any(|a| a == "--h1"));
    assert!(!h2.args.iter().any(|a| a == "--h3"));

    let mut h3_cell = base_cell();
    h3_cell.protocol = Protocol::H3;
    let h3 = h2load.plan(&h3_cell, &target, &run).expect("valid cell");
    assert!(!h3.args.iter().any(|a| a == "--h1"));
    assert!(h3.args.iter().any(|a| a == "--h3"));
}

// ---------------------------------------------------------------------------
// 5. streams_per_connection_mapping
// ---------------------------------------------------------------------------

/// Finds the value token immediately after `-m` in `args`.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: only called with args this file's \
              own H2Load::plan just built, which always includes -m"
)]
fn m_value(args: &[String]) -> &str {
    let pos = args
        .iter()
        .position(|a| a == "-m")
        .expect("-m must be present");
    args.get(pos + 1).expect("-m must have a value")
}

#[test]
fn streams_per_connection_mapping() {
    let h2load = base_h2load();
    let target = base_target();
    let run = base_run();

    let mut h1_cell = base_cell();
    h1_cell.protocol = Protocol::H1;
    let h1 = h2load.plan(&h1_cell, &target, &run).expect("valid cell");
    assert_eq!(m_value(&h1.args), "1");

    for protocol in [Protocol::H2, Protocol::H3] {
        let mut cell = base_cell();
        cell.protocol = protocol;
        let invocation = h2load.plan(&cell, &target, &run).expect("valid cell");
        assert_eq!(m_value(&invocation.args), "100", "{protocol:?}");
    }
}

// ---------------------------------------------------------------------------
// 6. warm_up_time_is_passed
// ---------------------------------------------------------------------------

#[test]
fn warm_up_time_is_passed() {
    let mut run = base_run();
    run.warmup_secs = 17;
    let invocation = base_h2load()
        .plan(&base_cell(), &base_target(), &run)
        .expect("valid cell");
    let pos = invocation
        .args
        .iter()
        .position(|a| a == "--warm-up-time")
        .expect("--warm-up-time must be present");
    assert_eq!(invocation.args.get(pos + 1), Some(&"17".to_owned()));
}

// ---------------------------------------------------------------------------
// 7. parse_fixture
// ---------------------------------------------------------------------------

#[test]
fn parse_fixture() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    let raw = base_h2load()
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("the fixture is well-formed");

    assert_eq!(raw.requests_sent, 100_000);
    assert_eq!(raw.responses_ok, 99_980);
    assert_eq!(raw.bytes_received, 11_905_000);
    assert!(
        !raw.latency_exact,
        "invariant 1: h2load never sets latency_exact"
    );
    assert!(raw.ttfb.is_some(), "invariant 2: ttfb must be present");
    assert!(raw.connect.is_some());
}

// ---------------------------------------------------------------------------
// 8. parse_missing_ttfb_row_is_error
// ---------------------------------------------------------------------------

#[test]
fn parse_missing_ttfb_row_is_error() {
    let text = std::str::from_utf8(FIXTURE_BYTES).expect("fixture is utf-8");
    let without_ttfb: String = text
        .lines()
        .filter(|line| !line.starts_with("time to 1st byte:"))
        .collect::<Vec<_>>()
        .join("\n");

    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    let err = base_h2load()
        .parse(&ctx, without_ttfb.as_bytes(), b"")
        .expect_err("a missing time to 1st byte row must be Err(Parse)");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("time to 1st byte"),
        "the error must name the missing row: {detail:?}"
    );
}

// ---------------------------------------------------------------------------
// 9. parse_rejects_non_second_duration
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_non_second_duration() {
    let text = std::str::from_utf8(FIXTURE_BYTES).expect("fixture is utf-8");
    let mutated = text.replace("finished in 35.00s,", "finished in 1.23m,");

    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    let err = base_h2load()
        .parse(&ctx, mutated.as_bytes(), b"")
        .expect_err("finished in 1.23m must be Err(Parse): only seconds are accepted");
    assert!(matches!(err, BenchError::Parse { .. }));
}

// ---------------------------------------------------------------------------
// 10. parse_rejects_line_bomb
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_line_bomb() {
    let mut bomb = String::new();
    for _ in 0..5_000 {
        bomb.push_str("x\n");
    }

    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    // `std::time::Instant` is used here, not through the `irontraffic-time`
    // seam: this file is an integration test under `tests/`, outside the
    // scope `scripts/invariant-lints.sh`'s determinism-seam rule scans, and
    // this measures the TEST's own wall-clock budget for a bound the
    // issue's own acceptance criteria ask for ("in under 1 second"), not a
    // request-path read.
    let start = std::time::Instant::now();
    let err = base_h2load()
        .parse(&ctx, bomb.as_bytes(), b"")
        .expect_err("5,000 lines exceeds MAX_H2LOAD_LINES (4,096)");
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "parsing a line bomb took {elapsed:?}, expected well under 1s"
    );
    assert!(matches!(err, BenchError::Parse { .. }));
}

// ---------------------------------------------------------------------------
// 11. parse_rejects_duplicate_label
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_duplicate_label() {
    let text = std::str::from_utf8(FIXTURE_BYTES).expect("fixture is utf-8");
    // Duplicate the entire "requests:" line right after itself.
    let requests_line = text
        .lines()
        .find(|l| l.starts_with("requests: "))
        .expect("fixture has a requests: line");
    let mutated = text.replacen(
        requests_line,
        &format!("{requests_line}\n{requests_line}"),
        1,
    );

    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    let err = base_h2load()
        .parse(&ctx, mutated.as_bytes(), b"")
        .expect_err("a duplicated requests: line must be Err(Parse)");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("requests:"),
        "the error must name the duplicated label: {detail:?}"
    );
}

// ---------------------------------------------------------------------------
// 11a. parse_handles_mixed_time_units
// ---------------------------------------------------------------------------

/// Proves each of the four `time for request:` columns carries its OWN unit
/// (`239us`, `11.85ms`, `602us`, `351us`), and that the `traffic:` line
/// parses the parenthesised exact byte count rather than the rounded
/// `11.35MB` prefix, THROUGH THE PUBLIC `H2Load::parse` API.
///
/// `min` (239,000 ns) and `sd` (351,000 ns) are proven correct by
/// `crates/irontraffic-bench/src/loadgen/h2load.rs`'s own co-located
/// `#[cfg(test)]` unit tests instead of here: `Percentiles` (added by issue
/// #405) has no field below the 50th percentile, and this adapter's own
/// reconstruction (see that module's doc) places the overwhelming majority
/// of the weight at `mean` for any `requests_sent` above 2, so `min` is
/// mathematically unrecoverable through `Percentiles` regardless of how the
/// weights are chosen; asserting it here would either be vacuous (an
/// assertion that could never fail) or would require inventing a
/// reconstruction that sacrifices the honest "poor histogram" framing this
/// adapter's own module doc argues for. `mean` and `max` ARE recoverable
/// here (`p50_ns` and `max_ns` respectively), and are asserted below against
/// the SAME literal integers this file's own row-level unit test pins.
#[test]
fn parse_handles_mixed_time_units() {
    let text = "finished in 35.00s, 2857.14 req/s, 340.14KB/s\n\
         requests: 1000 total, 1000 started, 1000 done, 1000 succeeded, 0 failed, 0 errored, 0 timeout\n\
         status codes: 1000 2xx, 0 3xx, 0 4xx, 0 5xx\n\
         traffic: 11.35MB (11905000) total, 285.16KB (292000) headers (space savings 12.34%), 10.49MB (11000000) data\n\
         time for request:  239us  11.85ms  602us  351us  89.35%\n\
         time for connect:  120us   980us   310us   95us   91.20%\n\
         time to 1st byte:  180us  9.40ms  450us  210us  88.10%\n";

    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    let raw = base_h2load()
        .parse(&ctx, text.as_bytes(), b"")
        .expect("well-formed mixed-unit fixture");

    // The parenthesised exact count, never the rounded 11.35MB prefix.
    assert_eq!(raw.bytes_received, 11_905_000);

    let percentiles = raw.latency.percentiles();
    // 602,000 ns: mean dominates the reconstructed weight (998 of 1000
    // samples), so it is what the median resolves to. Within `HdrHistogram`'s
    // 3-significant-digit bound, not bit-for-bit (see `assert_within_3sig`).
    assert_within_3sig(percentiles.p50_ns, 602_000, "p50_ns should recover mean");
    // 11,850,000 ns: `max_ns` always reflects the single largest recorded
    // value regardless of its weight, one sample at h2load's own reported
    // max.
    assert_within_3sig(percentiles.max_ns, 11_850_000, "max_ns should recover max");
}

// ---------------------------------------------------------------------------
// 20 and 21. Placement note.
//
// Issue #413's own Tests section lists both `h2load_parse_rejects_non_numeric_timing_columns`
// (test 20) and `h2load_parse_rejects_oversized_output` (test 21) under the
// "In `crates/irontraffic-bench/tests/loadgen_vegeta.rs`:" header, immediately
// after `plan_rejects_absurd_worker_cap` (test 19), with no comment marking a
// section break. Both names carry an explicit `h2load_` prefix, and both
// exercise `H2Load::parse` and `MAX_H2LOAD_OUTPUT_BYTES` exclusively; neither
// touches `Vegeta` or `cross_check` at all. This reads as a section-boundary
// slip while the issue was being written (the numbered list simply continues
// past the file-boundary comment), not a deliberate instruction to import
// `H2Load` into `loadgen_vegeta.rs`. Both tests are implemented HERE instead,
// where `FIXTURE_BYTES`, `base_h2load`, `base_ctx` and every other helper
// they need already live; the acceptance criterion
// (`cargo test --test loadgen_h2load --test loadgen_vegeta`) runs both test
// binaries together and does not require any specific test to live in one
// file over the other.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 20. h2load_parse_rejects_non_numeric_timing_columns
// ---------------------------------------------------------------------------

#[test]
fn h2load_parse_rejects_non_numeric_timing_columns() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);
    let h2load = base_h2load();

    let base_text = std::str::from_utf8(FIXTURE_BYTES).expect("fixture is utf-8");
    let original_row = base_text
        .lines()
        .find(|l| l.starts_with("time for request:"))
        .expect("fixture has a time for request: row");

    // `nanus`, `infms`, `-1us` and `1e309s` are all accepted by the standard
    // library's own floating-point string parser once a suffix is stripped;
    // this parser's integer-only columns must reject every one of them.
    let mutated = base_text.replace(
        original_row,
        "time for request:  nanus  infms  -1us  1e309s  89.35%",
    );
    let err = h2load
        .parse(&ctx, mutated.as_bytes(), b"")
        .expect_err("nanus/infms/-1us/1e309s must all be Err(Parse)");
    assert!(matches!(err, BenchError::Parse { .. }));

    // A bare number with no unit suffix at all.
    let mutated_bare = base_text.replace(
        original_row,
        "time for request:  239  11850  602  351  89.35%",
    );
    let err = h2load
        .parse(&ctx, mutated_bare.as_bytes(), b"")
        .expect_err("a bare number with no unit suffix must be Err(Parse)");
    assert!(matches!(err, BenchError::Parse { .. }));

    // 61 seconds: one second above HIGH_NS (60s). A summary statistic above
    // HIGH_NS is a misparse, not a slow request (edge case 4b): `Err(Parse)`,
    // never a recorded out-of-range sample.
    let mutated_high = base_text.replace(
        original_row,
        "time for request:  239us  61s  602us  351us  89.35%",
    );
    let err = h2load
        .parse(&ctx, mutated_high.as_bytes(), b"")
        .expect_err("a value above HIGH_NS must be Err(Parse)");
    assert!(matches!(err, BenchError::Parse { .. }));
}

// ---------------------------------------------------------------------------
// 21. h2load_parse_rejects_oversized_output
// ---------------------------------------------------------------------------

#[test]
fn h2load_parse_rejects_oversized_output() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);
    let h2load = base_h2load();

    // MAX_H2LOAD_OUTPUT_BYTES + 1 bytes, checked on the slice length before
    // any split, so this costs one comparison rather than a scan.
    let oversized = vec![b'x'; MAX_H2LOAD_OUTPUT_BYTES + 1];
    // `std::time::Instant` again, for the identical reason given on
    // `parse_rejects_line_bomb` above: this file is under `tests/`, outside
    // `scripts/invariant-lints.sh`'s determinism-seam scan, and this
    // measures the TEST's own wall-clock budget for the issue's own
    // acceptance bound ("under 10 milliseconds"), not a request-path read.
    let start = std::time::Instant::now();
    let err = h2load
        .parse(&ctx, &oversized, b"")
        .expect_err("MAX_H2LOAD_OUTPUT_BYTES + 1 must be Err(Parse)");
    let elapsed = start.elapsed();
    assert!(matches!(err, BenchError::Parse { .. }));
    assert!(
        elapsed < std::time::Duration::from_millis(10),
        "rejecting an oversized output took {elapsed:?}, expected well under 10ms"
    );

    // Exactly 1 MiB (MAX_H2LOAD_OUTPUT_BYTES itself, so the TOTAL-bytes cap
    // does not fire) in a single line with no newline at all: the per-line
    // cap (MAX_H2LOAD_LINE_BYTES, 1,024) is what must catch this, proving a
    // line-count cap alone would not have.
    let one_line = vec![b'x'; MAX_H2LOAD_OUTPUT_BYTES];
    assert_eq!(one_line.len(), MAX_H2LOAD_OUTPUT_BYTES);
    let err = h2load
        .parse(&ctx, &one_line, b"")
        .expect_err("a 1 MiB single line must be Err(Parse) from the per-line cap");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("MAX_H2LOAD_LINE_BYTES"),
        "must be rejected by the per-line cap specifically, not the total-bytes cap: {detail:?}"
    );
}
