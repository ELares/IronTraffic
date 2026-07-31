// SPDX-License-Identifier: MIT OR Apache-2.0
//! Command-line and parser tests for the `oha` adapter (issue #411).
//!
//! # What these tests do and do NOT prove
//!
//! `tests/fixtures/oha-1.15.0.json` is a REAL capture: `oha 1.15.0` (the
//! exact pinned version, installed with `cargo install oha --version 1.15.0
//! --locked`) run with `--no-tui --output-format json -c 8 -q 200
//! --latency-correction -z 3s` against a local Python `http.server` echoing a
//! 13 byte body, not hand-written. `parse_fixture` is the authority on the
//! exact field spellings (`summary.total`, `summary.totalData`,
//! `statusCodeDistribution`, `errorDistribution`, `latencyPercentiles`) this
//! parser assumes.
//!
//! Every other parser test (11 through 18) builds its own SYNTHETIC JSON
//! text rather than mutating the real fixture, because a hostile-input test
//! needs to isolate exactly one violated rule, and the real fixture's own
//! shape (an `"aborted due to deadline"` error entry, nine percentile
//! points) is not itself the thing under test in those cases.
//!
//! Two honestly-documented gaps, found while writing these tests:
//!
//! 1. `parse_rejects_non_finite_duration` (test 16) asks for `summary.total`
//!    of `nan` and `Infinity` to be rejected. Standard JSON has no literal
//!    for either, and `serde_json` (this crate's exact pinned version,
//!    1.0.151, confirmed by direct experiment) refuses `NaN`/`Infinity` as a
//!    TOKENIZER-level syntax error before a `Value` is ever built, and
//!    separately refuses any number literal whose magnitude would not fit a
//!    finite `f64` (`1e400` is "number out of range", not `Infinity`) for
//!    the same reason. Every sub-case in test 16 still returns
//!    `Err(BenchError::Parse)` as required, but the `nan`/`Infinity`
//!    sub-cases are caught by `serde_json`'s own JSON-syntax validation, NOT
//!    by this parser's `is_finite()` guard; only `-1.0`, `1e30` and `0.0`
//!    exercise that guard directly. Both are asserted on their OWN detail
//!    text below specifically so this distinction is pinned rather than
//!    hidden behind a shared `matches!(.., BenchError::Parse { .. })`.
//! 2. Edge case 10 in issue #411 asks that a stderr rate-warning line be
//!    "included in `RawRun`'s debug output". `RawRun`'s Public API, given
//!    verbatim by the issue, has no field to carry it; see the doc comment
//!    on `latency_trustworthy`'s computation in `src/loadgen/oha.rs`. This
//!    is treated as unsatisfiable as worded rather than silently narrowed:
//!    `stderr_rate_warning_marks_untrustworthy` below verifies the part that
//!    IS expressible (`latency_trustworthy` goes false), not the debug
//!    output claim.

use std::net::SocketAddr;

use irontraffic_bench::{
    BenchCell, BenchError, CacheMode, CellId, Invocation, KeepaliveMode, LoadGenerator,
    MAX_REPORTED_REQUESTS, MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_STDERR_BYTES, Oha, ParseCtx, PathCorpus,
    Protocol, RateMode, RunParams, Scheme, Target, TlsMode, ToolStamp, Unsupported,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

/// A real `oha 1.15.0` JSON capture. See the module doc for exactly how it
/// was produced.
const FIXTURE_BYTES: &[u8] = include_bytes!("fixtures/oha-1.15.0.json");

/// A minimal, individually valid `BenchCell`: fixed rate, H1, TLS off,
/// `SingleHot`, `Both` keepalive. Every field is inside its own valid range
/// so a test that overrides exactly one field exercises only that field's
/// behaviour, never an unrelated one. Mirrors `tests/cell_id.rs`'s own
/// `base_cell` convention, except `rate` is `Fixed`, not `Saturate`: a
/// `Saturate` base cell would make every plan-related test also exercise
/// `supports`'s refusal, which is not what those tests are about.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: \"base\" is a literal already \
              covered by tests/cell_id.rs's own parses_single_segment"
)]
fn base_cell() -> BenchCell {
    BenchCell {
        id: CellId::parse("base").expect("\"base\" is a valid cell id"),
        protocol: Protocol::H1,
        tls: TlsMode::Off,
        payload_bytes: 1024,
        routes: 100,
        path_corpus: PathCorpus::SingleHot,
        connections: 64,
        upstreams: 1,
        filter_depth: 0,
        cache: CacheMode::Bypass,
        keepalive: KeepaliveMode::Both,
        rate: RateMode::Fixed(50_000),
    }
}

/// A minimal, individually valid `Target` pairing with [`base_cell`].
fn base_target() -> Target {
    Target {
        scheme: Scheme::Http,
        host: "example.test".to_owned(),
        connect: SocketAddr::from(([10, 0, 0, 5], 8080)),
        sni: None,
        path_expr: "/hot".to_owned(),
    }
}

/// Pairs with [`base_cell`] and [`base_target`]: 30 measured seconds, 5
/// warmup seconds (never rendered; see `plan`'s own doc), no explicit
/// concurrency override.
fn base_run() -> RunParams {
    RunParams {
        duration_secs: 30,
        warmup_secs: 5,
        concurrency: None,
    }
}

fn base_tool_stamp() -> ToolStamp {
    ToolStamp {
        name: "oha".to_owned(),
        version: "1.15.0".to_owned(),
        image_digest: None,
    }
}

#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: base_cell/base_target/base_run are \
              this file's own fixed, valid constants, so planning cannot fail"
)]
fn base_invocation() -> Invocation {
    Oha.plan(&base_cell(), &base_target(), &base_run())
        .expect("the base cell, target and run are individually valid")
}

/// The exact expected argument vector for `plan(base_cell(), base_target(),
/// base_run())`, written out element by element so a reordering, an
/// insertion, or a dropped token in `Oha::plan` fails this test rather than
/// an assertion that only checks membership.
fn base_expected_args() -> Vec<String> {
    [
        "--no-tui",
        "--output-format",
        "json",
        "-c",
        "64",
        "-q",
        "50000",
        "--latency-correction",
        "-z",
        "30s",
        "--connect-to",
        "example.test:80:10.0.0.5:8080",
        "http://example.test/hot",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// The index of `seq` as a contiguous run inside `args`, or `None`.
fn find_subsequence(args: &[String], seq: &[&str]) -> Option<usize> {
    if seq.is_empty() || args.len() < seq.len() {
        return None;
    }
    args.windows(seq.len())
        .position(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
}

/// A synthetic, individually valid oha JSON document: real enough to exercise
/// every required field, but built directly in Rust (not from the real
/// fixture) so each hostile-input test below can mutate exactly one field.
fn valid_value() -> serde_json::Value {
    json!({
        "summary": { "total": 2.0, "totalData": 1000 },
        "statusCodeDistribution": { "200": 100 },
        "errorDistribution": {},
        "latencyPercentiles": {
            "p10": 0.0001,
            "p25": 0.0002,
            "p50": 0.0003,
            "p75": 0.0004,
            "p90": 0.0005,
            "p95": 0.0006,
            "p99": 0.0007,
            "p99.9": 0.0008,
            "p99.99": 0.0009
        }
    })
}

/// Asserts `err` is `BenchError::Parse` and returns its `detail` text, so
/// every caller can assert on the SPECIFIC reason rather than only the
/// variant, which any rejection would satisfy.
#[allow(
    clippy::panic,
    reason = "test-support helper, not itself a #[test] fn: panicking here surfaces which \
              caller's assertion actually failed, with the real BenchError in the message"
)]
fn expect_parse_detail(err: &BenchError) -> &str {
    match err {
        BenchError::Parse { tool, detail } => {
            assert_eq!(*tool, "oha");
            detail.as_str()
        }
        other => panic!("expected BenchError::Parse, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 1. plan_base_cell_pins_the_argument_vector
// ---------------------------------------------------------------------------

#[test]
fn plan_base_cell_pins_the_argument_vector() {
    let invocation = base_invocation();
    assert_eq!(invocation.program, "oha");
    assert_eq!(invocation.args, base_expected_args());
    assert!(invocation.env.is_empty());
}

// ---------------------------------------------------------------------------
// 2. plan_is_deterministic
// ---------------------------------------------------------------------------

#[test]
fn plan_is_deterministic() {
    let cell = base_cell();
    let target = base_target();
    let run = base_run();
    let first = Oha.plan(&cell, &target, &run).expect("base cell plans");
    let second = Oha.plan(&cell, &target, &run).expect("base cell plans");
    assert_eq!(first, second);
    assert_eq!(first.command_line(), second.command_line());
}

// ---------------------------------------------------------------------------
// 3. command_line_quoting
// ---------------------------------------------------------------------------

#[test]
fn command_line_quoting() {
    let quoted = Invocation {
        program: "oha".to_owned(),
        args: vec!["a b'c".to_owned()],
        env: Vec::new(),
    };
    assert_eq!(quoted.command_line(), "oha 'a b'\\''c'");

    let bare = Invocation {
        program: "oha".to_owned(),
        args: vec!["plain_token-1.2:3=4@5%6+7".to_owned()],
        env: Vec::new(),
    };
    assert_eq!(bare.command_line(), "oha plain_token-1.2:3=4@5%6+7");
}

// ---------------------------------------------------------------------------
// 4. keepalive_downstream_close_adds_flag
// ---------------------------------------------------------------------------

#[test]
fn keepalive_downstream_close_adds_flag() {
    let target = base_target();
    let run = base_run();

    let mut both = base_cell();
    both.keepalive = KeepaliveMode::Both;
    let both_args = Oha.plan(&both, &target, &run).expect("Both plans").args;
    assert!(!both_args.iter().any(|a| a == "--disable-keepalive"));

    let mut no_pool = base_cell();
    no_pool.keepalive = KeepaliveMode::NoUpstreamPool;
    let no_pool_args = Oha
        .plan(&no_pool, &target, &run)
        .expect("NoUpstreamPool plans")
        .args;
    assert!(!no_pool_args.iter().any(|a| a == "--disable-keepalive"));

    let mut downstream_close = base_cell();
    downstream_close.keepalive = KeepaliveMode::DownstreamClose;
    let downstream_close_args = Oha
        .plan(&downstream_close, &target, &run)
        .expect("DownstreamClose plans")
        .args;
    assert!(
        downstream_close_args
            .iter()
            .any(|a| a == "--disable-keepalive")
    );
}

// ---------------------------------------------------------------------------
// 5. fixed_rate_adds_latency_correction
// ---------------------------------------------------------------------------

#[test]
fn fixed_rate_adds_latency_correction() {
    let mut cell = base_cell();
    cell.rate = RateMode::Fixed(50_000);
    let args = Oha
        .plan(&cell, &base_target(), &base_run())
        .expect("fixed-rate cell plans")
        .args;
    let idx = find_subsequence(&args, &["-q", "50000", "--latency-correction"])
        .expect("-q, the rate, and --latency-correction must appear adjacently and in order");
    assert!(idx < args.len());
}

// ---------------------------------------------------------------------------
// 6. saturate_is_unsupported
// ---------------------------------------------------------------------------

#[test]
fn saturate_is_unsupported() {
    let mut cell = base_cell();
    cell.rate = RateMode::Saturate;
    let err = Oha.supports(&cell).expect_err("saturate must be refused");
    assert!(matches!(err, Unsupported::RateMode { tool: "oha" }));
}

// ---------------------------------------------------------------------------
// 7. h3_is_unsupported
// ---------------------------------------------------------------------------

#[test]
fn h3_is_unsupported() {
    let mut cell = base_cell();
    cell.protocol = Protocol::H3;
    let err = Oha.supports(&cell).expect_err("h3 must be refused");
    assert!(matches!(
        err,
        Unsupported::Protocol {
            tool: "oha",
            protocol: Protocol::H3
        }
    ));
}

// ---------------------------------------------------------------------------
// 8. too_many_connections_unsupported
// ---------------------------------------------------------------------------

#[test]
fn too_many_connections_unsupported() {
    let mut cell = base_cell();
    cell.connections = 100_000;
    let err = Oha
        .supports(&cell)
        .expect_err("100,000 connections must be refused");
    assert!(matches!(
        err,
        Unsupported::Connections {
            tool: "oha",
            connections: 100_000
        }
    ));
}

// ---------------------------------------------------------------------------
// 9. tls_uses_https_and_insecure
// ---------------------------------------------------------------------------

#[test]
fn tls_uses_https_and_insecure() {
    let mut cell = base_cell();
    cell.tls = TlsMode::EcdsaP256;
    let invocation = Oha
        .plan(&cell, &base_target(), &base_run())
        .expect("TLS cell plans");
    assert!(invocation.args.iter().any(|a| a == "--insecure"));
    let url = invocation
        .args
        .last()
        .expect("plan always emits a final URL argument");
    assert!(url.starts_with("https://"), "url was {url}");
}

// ---------------------------------------------------------------------------
// 10. parse_fixture
// ---------------------------------------------------------------------------

#[test]
fn parse_fixture() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let raw = Oha
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("the real oha 1.15.0 fixture must parse");

    // Ground truth, read directly out of tests/fixtures/oha-1.15.0.json:
    // statusCodeDistribution = {"200": 600}, errorDistribution =
    // {"aborted due to deadline": 1}, summary.totalData = 7800,
    // latencyPercentiles.p99 = 0.000459709 seconds.
    assert_eq!(raw.requests_sent, 601);
    assert_eq!(raw.responses_ok, 600);
    assert_eq!(raw.errors, 1);
    assert_eq!(raw.bytes_received, 7800);
    assert_eq!(raw.status_counts.len(), 1);
    assert_eq!(raw.status_counts.get(&200), Some(&600));
    assert!(!raw.latency_exact);
    assert!(raw.latency_trustworthy);

    // Acceptance criterion's own phrasing, made exact: the status map sums
    // to the reported request count net of errors (invariant 3's formula,
    // `sum(status_counts) == requests_sent - errors`), not to
    // `requests_sent` alone, which for this fixture also includes the one
    // "aborted due to deadline" entry that never got a status code at all.
    let status_sum: u64 = raw.status_counts.values().sum();
    assert_eq!(status_sum, raw.requests_sent - raw.errors);

    let expected_p99_ns = 459_709.0_f64;
    #[allow(
        clippy::cast_precision_loss,
        reason = "p99_ns is well under 2^53 for any run this fixture or this crate's own \
                  bounds can produce, so this comparison loses no precision that matters"
    )]
    let actual_p99_ns = raw.latency.percentiles().p99_ns as f64;
    let diff = (actual_p99_ns - expected_p99_ns).abs();
    assert!(
        diff <= expected_p99_ns * 0.01,
        "reconstructed p99_ns {actual_p99_ns} not within 1% of the fixture's own {expected_p99_ns}"
    );
}

// ---------------------------------------------------------------------------
// 11. parse_missing_summary_is_error
// ---------------------------------------------------------------------------

#[test]
fn parse_missing_summary_is_error() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let err = Oha
        .parse(&ctx, b"{}", b"")
        .expect_err("an empty object has no summary");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("summary"),
        "expected the detail to name summary, got: {detail}"
    );
}

// ---------------------------------------------------------------------------
// 12. parse_rejects_oversize
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_oversize() {
    // Content-based proof of check order, not a timing proxy: see
    // tests/hist.rs's `hgrm_rejects_oversized_input` for the identical
    // precedent and its own rationale (a plausible regression is often fast
    // enough to survive a timing bound anyway, which makes timing a weak
    // discriminator). Exactly one byte past MAX_TOOL_OUTPUT_BYTES is
    // rejected by the size guard specifically (its own detail names the
    // constant); exactly AT the bound is NOT rejected by that guard, which
    // pins the comparison as strictly `>`, not `>=` (the exactly-at /
    // exactly-one-past pair the size bound needs on both sides).
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let one_past = vec![0_u8; MAX_TOOL_OUTPUT_BYTES + 1];
    let err = Oha
        .parse(&ctx, &one_past, b"")
        .expect_err("must exceed MAX_TOOL_OUTPUT_BYTES");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("MAX_TOOL_OUTPUT_BYTES"),
        "expected the size guard to reject this input; got: {detail}"
    );

    let at_bound = vec![0_u8; MAX_TOOL_OUTPUT_BYTES];
    let err_at_bound = Oha
        .parse(&ctx, &at_bound, b"")
        .expect_err("all-zero bytes is not valid json, but must fail for a DIFFERENT reason");
    let detail_at_bound = expect_parse_detail(&err_at_bound);
    assert!(
        !detail_at_bound.contains("MAX_TOOL_OUTPUT_BYTES"),
        "exactly at the bound must not trip the size guard; got: {detail_at_bound}"
    );
}

// ---------------------------------------------------------------------------
// 13. parse_rejects_non_monotone_percentiles
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_non_monotone_percentiles() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // Watched-to-fail precondition: the UNMUTATED fixture must parse.
    let good = serde_json::to_vec(&valid_value()).expect("valid_value serialises");
    assert!(
        Oha.parse(&ctx, &good, b"").is_ok(),
        "fixture precondition: valid_value() must parse before it is mutated"
    );

    let mut mutated = valid_value();
    // p50 is 0.0003; setting p99 below it violates the monotone chain.
    mutated["latencyPercentiles"]["p99"] = json!(0.0001);
    let bytes = serde_json::to_vec(&mutated).expect("mutated value serialises");

    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("p99 below p50 must be rejected");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("monotone"),
        "expected the monotonicity guard to reject this input; got: {detail}"
    );
}

// ---------------------------------------------------------------------------
// 14. stderr_rate_warning_marks_untrustworthy
// ---------------------------------------------------------------------------

#[test]
fn stderr_rate_warning_marks_untrustworthy() {
    let cell = base_cell(); // Fixed rate.
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // Without a warning, a fixed-rate cell's latency is trustworthy.
    let clean = Oha
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("clean stderr parses");
    assert!(clean.latency_trustworthy);

    // With the pinned warning substring present anywhere in stderr, the
    // SAME fixed-rate cell's latency is marked untrustworthy: implication,
    // not equality (invariant 5), so a rate-mode check alone cannot decide
    // this.
    let warned = Oha
        .parse(
            &ctx,
            FIXTURE_BYTES,
            b"some preamble\nunable to keep up\ntrailer",
        )
        .expect("a rate warning does not itself make the run unparseable");
    assert!(!warned.latency_trustworthy);
}

// ---------------------------------------------------------------------------
// 15. parse_rejects_oversize_stderr
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_oversize_stderr() {
    // Primary, content-based proof (see parse_rejects_oversize's comment for
    // why this is preferred over a timing assertion): exactly one byte past
    // MAX_TOOL_STDERR_BYTES is rejected by the stderr size guard specifically,
    // even though stdout is the real, otherwise-valid fixture and even
    // though the oversized stderr itself CONTAINS a rate-warning substring
    // (proving the size guard fires rather than the run being silently
    // accepted with latency marked untrustworthy).
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut one_past = vec![b'x'; MAX_TOOL_STDERR_BYTES + 1 - "unable to keep up".len()];
    one_past.extend_from_slice(b"unable to keep up");
    assert_eq!(
        one_past.len(),
        MAX_TOOL_STDERR_BYTES + 1,
        "fixture precondition"
    );

    let err = Oha
        .parse(&ctx, FIXTURE_BYTES, &one_past)
        .expect_err("must exceed MAX_TOOL_STDERR_BYTES");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("MAX_TOOL_STDERR_BYTES"),
        "expected the stderr size guard to reject this input; got: {detail}"
    );

    // Secondary, best-effort proof of the issue's own literal framing ("in
    // under 100 milliseconds"): a MUCH larger oversized stderr (16x the
    // cap), so that a scan which incorrectly ran BEFORE the size check would
    // have measurably more work to do, must still be rejected quickly. This
    // is not the load-bearing assertion in this test (the content-based one
    // above is), because at this scale a linear byte scan is fast enough on
    // ordinary hardware that a real reordering regression might still
    // survive an even tighter bound; it is included because the issue asks
    // for it explicitly and a generous bound still catches a gross
    // regression (for example, an accidental quadratic rescan).
    let huge = vec![b'a'; MAX_TOOL_STDERR_BYTES * 16];
    let start = std::time::Instant::now();
    let huge_err = Oha
        .parse(&ctx, FIXTURE_BYTES, &huge)
        .expect_err("must exceed MAX_TOOL_STDERR_BYTES");
    let elapsed = start.elapsed();
    let huge_detail = expect_parse_detail(&huge_err);
    assert!(huge_detail.contains("MAX_TOOL_STDERR_BYTES"));
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "rejecting oversized stderr took {elapsed:?}, which suggests the size guard is not \
         running before an expensive scan"
    );
}

// ---------------------------------------------------------------------------
// 16. parse_rejects_non_finite_duration
// ---------------------------------------------------------------------------

fn duration_probe_text(total_literal: &str) -> String {
    format!(
        r#"{{"summary":{{"total":{total_literal},"totalData":1000}},"statusCodeDistribution":{{"200":100}},"errorDistribution":{{}},"latencyPercentiles":{{"p10":0.0001,"p25":0.0002,"p50":0.0003,"p75":0.0004,"p90":0.0005,"p95":0.0006,"p99":0.0007,"p99.9":0.0008,"p99.99":0.0009}}}}"#
    )
}

#[test]
fn parse_rejects_non_finite_duration() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // `NaN` and `Infinity` are not valid JSON number tokens: serde_json
    // 1.0.151 (confirmed by direct experiment while writing this test)
    // rejects both at the TOKENIZER level, before `Value` is ever built, so
    // these two sub-cases exercise serde_json's own syntax validation, NOT
    // this parser's `is_finite()` guard. They still return `Err(Parse)` as
    // required, asserted on their own ("invalid json") detail text so this
    // is pinned rather than hidden behind a shared variant-only check. See
    // the module doc's "honestly-documented gaps" section.
    for (label, literal) in [("nan", "NaN"), ("inf", "Infinity")] {
        let bytes = duration_probe_text(literal);
        let err = Oha.parse(&ctx, bytes.as_bytes(), b"").unwrap_err();
        let detail = expect_parse_detail(&err);
        assert!(
            detail.contains("invalid json"),
            "{label}: expected serde_json's own syntax rejection; got: {detail}"
        );
    }

    // `-1.0`, `1e30` and `0.0` ARE valid JSON number literals, and each
    // genuinely reaches and is rejected by this parser's own guard: `-1.0`
    // by the finite-and-non-negative check, `1e30` by the plausible-duration
    // ceiling, and `0.0` by the zero-duration check. `NaN as u64` is 0 in
    // Rust and every ordering comparison against `NaN` is false, so an
    // ordering-only check (`> 86_400.0` alone, with no `is_finite()` first)
    // would have silently accepted a non-finite value upstream of these
    // three and produced a zero-duration run.
    let neg = duration_probe_text("-1.0");
    let err_neg = Oha.parse(&ctx, neg.as_bytes(), b"").unwrap_err();
    assert!(expect_parse_detail(&err_neg).contains("not finite or is negative"));

    let huge = duration_probe_text("1e30");
    let err_huge = Oha.parse(&ctx, huge.as_bytes(), b"").unwrap_err();
    assert!(expect_parse_detail(&err_huge).contains("exceeds the maximum plausible run duration"));

    let zero = duration_probe_text("0.0");
    let err_zero = Oha.parse(&ctx, zero.as_bytes(), b"").unwrap_err();
    assert!(expect_parse_detail(&err_zero).contains("zero duration_ns"));
}

// ---------------------------------------------------------------------------
// 17. parse_rejects_absurd_counts
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_absurd_counts() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // Two status buckets each at u64::MAX. A u64 SUM of the two would
    // overflow: in a debug build (which `cargo test` uses) that panics
    // rather than wrapping, and in a release build it wraps into
    // u64::MAX - 1, still huge but silently wrong either way. Computing the
    // sum in u128 (this parser's actual implementation) avoids both: no
    // panic, and no wrap, just a correctly-huge value this parser then
    // rejects against MAX_REPORTED_REQUESTS.
    let mut two_max = valid_value();
    two_max["statusCodeDistribution"] = json!({
        "200": u64::MAX,
        "500": u64::MAX,
    });
    let bytes = serde_json::to_vec(&two_max).expect("serialises");
    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("two u64::MAX buckets must be rejected, not panic");
    assert!(
        expect_parse_detail(&err).contains("MAX_REPORTED_REQUESTS"),
        "expected the requests_sent bound to reject this input"
    );

    // A single bucket whose total exceeds MAX_REPORTED_REQUESTS, but does
    // not need u128 to avoid overflow on its own: a plain boundary check.
    let mut over_cap = valid_value();
    over_cap["statusCodeDistribution"] = json!({ "200": MAX_REPORTED_REQUESTS + 1 });
    let bytes_over = serde_json::to_vec(&over_cap).expect("serialises");
    let err_over = Oha
        .parse(&ctx, &bytes_over, b"")
        .expect_err("one bucket over MAX_REPORTED_REQUESTS must be rejected");
    assert!(expect_parse_detail(&err_over).contains("MAX_REPORTED_REQUESTS"));

    // Exactly AT MAX_REPORTED_REQUESTS is NOT rejected by this bound: the
    // exactly-at / exactly-one-past pair the boundary check needs on both
    // sides.
    let mut at_cap = valid_value();
    at_cap["statusCodeDistribution"] = json!({ "200": MAX_REPORTED_REQUESTS });
    let bytes_at = serde_json::to_vec(&at_cap).expect("serialises");
    let raw_at = Oha
        .parse(&ctx, &bytes_at, b"")
        .expect("exactly MAX_REPORTED_REQUESTS must be accepted");
    assert_eq!(raw_at.requests_sent, MAX_REPORTED_REQUESTS);
}

// ---------------------------------------------------------------------------
// 18. parse_rejects_deep_nesting
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_deep_nesting() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let bomb = "[".repeat(200_000);
    // Calling parse() and getting back a Result at all (rather than the
    // process aborting on a native stack overflow) IS the proof: an abort
    // would kill this whole test binary, not merely fail this assertion.
    let result = Oha.parse(&ctx, bomb.as_bytes(), b"");
    assert!(
        result.is_err(),
        "a 200,000-deep nesting bomb must be rejected, not accepted"
    );
}

// ---------------------------------------------------------------------------
// 19. plan_rejects_hostile_target_fields
// ---------------------------------------------------------------------------

#[test]
fn plan_rejects_hostile_target_fields() {
    let cell = base_cell();
    let run = base_run();

    let mut bad_host = base_target();
    bad_host.host = "exa mple.test".to_owned();
    let err = Oha
        .plan(&cell, &bad_host, &run)
        .expect_err("a host containing a space must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(
        msg.contains("host"),
        "expected the message to name host, got: {msg}"
    );

    let mut bad_sni = base_target();
    bad_sni.sni = Some("bad\nsni".to_owned());
    let err = Oha
        .plan(&cell, &bad_sni, &run)
        .expect_err("an sni containing a newline must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(
        msg.contains("sni"),
        "expected the message to name sni, got: {msg}"
    );

    let mut long_path = base_target();
    long_path.path_expr = format!("/{}", "a".repeat(4_999));
    assert_eq!(long_path.path_expr.len(), 5_000, "fixture precondition");
    let err = Oha
        .plan(&cell, &long_path, &run)
        .expect_err("a 5,000 byte path_expr must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(
        msg.contains("path_expr"),
        "expected the message to name path_expr, got: {msg}"
    );

    let mut control_byte_path = base_target();
    control_byte_path.path_expr = "/\u{1b}[2J".to_owned();
    let err = Oha
        .plan(&cell, &control_byte_path, &run)
        .expect_err("a path_expr containing an escape sequence must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(msg.contains("path_expr"));

    let mut no_leading_slash = base_target();
    no_leading_slash.path_expr = "no-leading-slash".to_owned();
    let err = Oha
        .plan(&cell, &no_leading_slash, &run)
        .expect_err("a path_expr with no leading slash must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(msg.contains("path_expr"));
    assert!(msg.contains("leading"));
}

// ---------------------------------------------------------------------------
// Property test: command_line_is_reparseable.
// ---------------------------------------------------------------------------

/// A small, checked-in POSIX-quoting splitter that inverts EXACTLY
/// `Invocation::command_line`'s own quoting rule: tokens are either bare
/// (any run of `is_bare_token_char` bytes, which by construction never
/// contains a space or a quote) or single-quoted with an embedded quote
/// spelled `'\''`. This is not a general shell parser; restricting the
/// property test's generator to printable ASCII (`0x20..=0x7E`) is what
/// makes that safe, matching invariant 8's own printable-ASCII requirement
/// on a recorded command line.
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: operates only on the printable-ASCII \
              bytes produced by Invocation::command_line and this file's own proptest \
              generator (never non-ASCII, so every from_utf8 here cannot fail), and every index \
              used is bounds-checked by the surrounding `i < n` / `i + 2 < n` loop condition \
              immediately before it is used"
)]
fn split_command_line(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let n = bytes.len();
    let mut tokens = Vec::new();
    while i < n {
        while i < n && bytes[i] == b' ' {
            i += 1;
        }
        if i >= n {
            break;
        }
        let mut tok = String::new();
        if bytes[i] == b'\'' {
            i += 1;
            loop {
                let start = i;
                while i < n && bytes[i] != b'\'' {
                    i += 1;
                }
                tok.push_str(std::str::from_utf8(&bytes[start..i]).expect("ascii input"));
                i += 1; // past the closing quote just found.
                if i + 2 < n && bytes[i] == b'\\' && bytes[i + 1] == b'\'' && bytes[i + 2] == b'\''
                {
                    tok.push('\'');
                    i += 3;
                    continue;
                }
                break;
            }
        } else {
            let start = i;
            while i < n && bytes[i] != b' ' {
                i += 1;
            }
            tok.push_str(std::str::from_utf8(&bytes[start..i]).expect("ascii input"));
        }
        tokens.push(tok);
    }
    tokens
}

/// A strategy for one printable-ASCII (`0x20..=0x7E`) token, 0 to 12 bytes.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: the regex literal is fixed and \
              valid, so this can never fail"
)]
fn printable_ascii_token() -> impl proptest::strategy::Strategy<Value = String> {
    proptest::string::string_regex("[ -~]{0,12}").expect("a fixed, valid regex")
}

proptest::proptest! {
    #[test]
    fn command_line_is_reparseable(
        program in printable_ascii_token(),
        args in proptest::collection::vec(printable_ascii_token(), 0..=6),
    ) {
        let invocation = Invocation { program: program.clone(), args: args.clone(), env: Vec::new() };
        let line = invocation.command_line();
        let split = split_command_line(&line);

        let mut expected = vec![program];
        expected.extend(args);
        proptest::prop_assert_eq!(split, expected);
    }
}

// ---------------------------------------------------------------------------
// Supplementary tests, beyond the 19 named above.
//
// Each of these closes a specific gap the 19 named tests do not reach: an
// edge case from the issue's own "Edge cases" list with no dedicated named
// test (statusCodeDistribution empty), the OTHER side of invariant 5 (a
// Saturate cell makes latency untrustworthy on its own, independent of
// stderr_rate_warning_marks_untrustworthy's stderr-side proof), and the
// exactly-at half of three boundaries the named tests only probe from the
// rejecting side (too_many_connections_unsupported, and 19's path_expr
// length and parse_rejects_absurd_counts's request count both test only
// one-past; the exactly-at case for the connections cap and the path_expr
// cap had no test at either edge at all before these).
// ---------------------------------------------------------------------------

/// Edge case 3: "statusCodeDistribution empty. Err(Parse); a run with no
/// responses is not a run." No test in the named 19 constructs this input;
/// this closes that gap.
#[test]
fn status_map_empty_is_rejected() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut empty_status = valid_value();
    empty_status["statusCodeDistribution"] = json!({});
    let bytes = serde_json::to_vec(&empty_status).expect("serialises");
    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("an empty statusCodeDistribution must be rejected");
    assert!(expect_parse_detail(&err).contains("statusCodeDistribution"));
}

/// Invariant 5's OTHER half: `latency_trustworthy` is false for a
/// `RateMode::Saturate` cell even with clean stderr. `supports` is the
/// PRIMARY gate (`saturate_is_unsupported`) and would normally stop a
/// runner from ever calling `parse` for such a cell at all, but `parse`'s
/// own formula must hold regardless of whether a caller checked `supports`
/// first: this is the second, independent line of defence its own doc
/// describes, and nothing in the named 19 constructs a Saturate `ParseCtx`
/// to prove it.
#[test]
fn saturate_ctx_sets_latency_untrustworthy_without_stderr_warning() {
    let mut cell = base_cell();
    cell.rate = RateMode::Saturate;
    let invocation = base_invocation(); // Invocation content is irrelevant here.
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let raw = Oha
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("parse itself does not consult supports");
    assert!(!raw.latency_trustworthy);
}

/// Exactly-at-cap / exactly-one-past for the connections bound
/// `too_many_connections_unsupported` only probes from 100,000 connections,
/// well past the 65,535 cap; this pins the boundary itself on both sides.
#[test]
fn connections_boundary_65535_ok_65536_unsupported() {
    let mut at_cap = base_cell();
    at_cap.connections = 65_535;
    assert!(Oha.supports(&at_cap).is_ok());

    let mut one_past = base_cell();
    one_past.connections = 65_536;
    let err = Oha
        .supports(&one_past)
        .expect_err("one past the connections cap must be refused");
    assert!(matches!(
        err,
        Unsupported::Connections {
            tool: "oha",
            connections: 65_536
        }
    ));
}

/// Exactly-at-cap for `path_expr`'s length bound. `plan_rejects_hostile_target_fields`
/// (test 19) only probes 5,000 bytes, one thousand past the 4,096 byte cap;
/// this pins that exactly 4,096 bytes is accepted.
#[test]
fn path_expr_boundary_exactly_at_cap_is_ok() {
    let cell = base_cell();
    let run = base_run();
    let mut target = base_target();
    target.path_expr = format!("/{}", "a".repeat(4_095));
    assert_eq!(target.path_expr.len(), 4_096, "fixture precondition");
    assert!(Oha.plan(&cell, &target, &run).is_ok());
}
