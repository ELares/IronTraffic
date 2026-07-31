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
//!
//! # Every relation `1.68.1`'s own `print_stats` guarantees, enforced here
//!
//! An earlier version of this fixture was not merely reconstructed, it was
//! arithmetically IMPOSSIBLE as any `h2load 1.68.1` output (PR 815 review,
//! issue #816 BLOCKING 3), which defeats the point of checking this parser
//! against it at all. Three relations `print_stats`
//! (`nghttp2/nghttp2`'s `src/h2load.cc`, the pinned tag) guarantees for every
//! real run are now enforced by construction in this fixture:
//!
//! 1. **`requests:`'s `total == succeeded + failed`, always, by
//!    construction.** `print_stats` computes `req_not_issued = req_todo -
//!    req_status_success - req_failed` and then does `req_failed +=
//!    req_not_issued` BEFORE printing, so the printed `failed` field is
//!    algebraically `total - succeeded` no matter what. This fixture's
//!    `99980 succeeded, 20 failed` sums to the `100000 total`; the previous
//!    `0 failed` could never come from a real run reporting `20 5xx` (a 5xx
//!    sets `status_success = 0`, which `on_stream_close` counts as
//!    `req_failed`, forcing `failed >= 20` on its own, independent of the
//!    `total`/`succeeded` identity).
//! 2. **`finished in`'s throughput is 1024-based, via `util::utos_funit`,
//!    never the SI 1000-based figure a human would compute by hand.** With
//!    `bytes_total = 11905000` and `duration = 35.00s`,
//!    `bps = 11905000 / 35 = 340142` (truncated to `int64_t`, matching
//!    `print_stats`'s own cast), and `340142 / 1024 = 332.17`, so this
//!    fixture reads `332.17KB/s`. The `traffic:` line's own `11.35MB`,
//!    `285.16KB` and `10.49MB` prefixes were ALREADY 1024-based correctly
//!    (confirmed by the same arithmetic against their own parenthesised
//!    exact counts) and are unchanged.
//!
//! **What was checked and left alone, because it is already correct.** The
//! `req/s` row's `min`/`max`/`mean`/`sd` columns (`2800.00   2900.00
//! 2857.14   25.30`) do NOT pass through `util::dtos` the way the three
//! timing rows' columns do (those go through `util::format_duration`, which
//! builds its own string via `dtos` internally, independent of `std::cout`'s
//! state); they are raw `double`s written straight to `std::cout` via
//! `operator<<`. The review that found the two relations above also flagged
//! this row as unable to "carry forced two decimal places," reading that as
//! a THIRD defect. Reading `print_stats` in full shows otherwise:
//! `std::cout << std::fixed << std::setprecision(2)` is set once, at the very
//! start of this same function (immediately before the `finished in` line),
//! and C++ `ostream` format flags and precision are STATE on the stream
//! object, persisting across every subsequent `std::cout <<` statement in
//! the function until something explicitly changes them again; nothing here
//! ever does. The `req/s` row's raw doubles are therefore printed with
//! exactly the same `fixed`, 2-decimal formatting already active from the
//! very first line, so `2800.00`/`2900.00`/`2857.14`/`25.30` is what a real
//! `1.68.1` run prints, not `2800`/`2900`/`2857.14`/`25.3`. This row is left
//! unchanged from what the review's own diff would have produced, because
//! changing it would make the fixture WRONG rather than right; see this
//! file's `req_s_row_min_max_mean_sd_are_fixed_two_decimal_by_construction`
//! test below, and `crates/irontraffic-bench/src/loadgen/h2load.rs`'s own
//! module doc, for the reasoning restated where the parser itself lives.
//!
//! This fixture remains a RECONSTRUCTION, not a capture: nothing in this
//! implementation environment can build or run a real `h2load`, so nobody
//! has confirmed these relations against an actual binary, only against
//! `1.68.1`'s own published source. Re-verify against a real run before this
//! parser is trusted for a real cell.

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

// Issue #413's own Design section spells the H3 branch as a literal `--h3`
// flag. That flag does not exist in the pinned h2load `1.68.1` at all (PR 815
// review, issue #816 BLOCKING 1): `--h3` first appears in `v1.69.0`, the same
// release that deletes the summary labels `H2Load::parse` reads, so no
// `nghttp2` release both accepts `--h3` and prints the shape this parser
// needs. `H2Load::plan` therefore emits `--alpn-list h3` for `Protocol::H3`
// instead (`Config::is_quic()` in `1.68.1` returns true only when
// `alpn_list[0]` is the h3 ALPN token); see `h2load.rs`'s own module doc,
// "HTTP/3 is selected through `--alpn-list`", for the full evidence trail.
// This test asserts the ACTUAL flag surface, a deliberate deviation from the
// issue's literal text, not the `--h3` spelling that would make a real
// `h2load 1.68.1` reject the command line outright.
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
    assert!(!h1.args.iter().any(|a| a == "--alpn-list"));

    let mut h2_cell = base_cell();
    h2_cell.protocol = Protocol::H2;
    let h2 = h2load.plan(&h2_cell, &target, &run).expect("valid cell");
    assert!(!h2.args.iter().any(|a| a == "--h1"));
    assert!(!h2.args.iter().any(|a| a == "--h3"));
    assert!(!h2.args.iter().any(|a| a == "--alpn-list"));

    let mut h3_cell = base_cell();
    h3_cell.protocol = Protocol::H3;
    let h3 = h2load.plan(&h3_cell, &target, &run).expect("valid cell");
    assert!(!h3.args.iter().any(|a| a == "--h1"));
    // NOT `--h3`: the pinned 1.68.1 has no such flag. HTTP/3 is selected
    // through `--alpn-list h3` instead.
    assert!(!h3.args.iter().any(|a| a == "--h3"));
    let alpn_pos = h3
        .args
        .iter()
        .position(|a| a == "--alpn-list")
        .expect("H3 must emit --alpn-list, the only way 1.68.1 selects HTTP/3");
    assert_eq!(h3.args.get(alpn_pos + 1), Some(&"h3".to_owned()));
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
        // `-m`'s value is fixed by protocol alone (see `plan`'s own comment),
        // independent of which flag selects H3: this holds whether H3 is
        // requested through `--h3` (h2load.cc's `getopt_long`, id 'm', is
        // parsed before the protocol match either way) or, as this adapter
        // now emits for the pinned 1.68.1 (see `protocol_flags` and
        // `h2load.rs`'s own module doc), `--alpn-list h3`. Confirmed here
        // rather than assumed: the H3 invocation never carries the
        // nonexistent `--h3` flag at all.
        if protocol == Protocol::H3 {
            assert!(!invocation.args.iter().any(|a| a == "--h3"));
        }
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
    // Pinned against the fixture's own literal `finished in 35.00s` (PR 815
    // review, issue #816 SHOULD_FIX 1): before this assertion existed, a
    // mutation of `parse_finished_in_token`'s scale factor from
    // 1_000_000_000 to 1_000_000 (reading "35.00s" as 35 MILLISECONDS, a
    // 1000x error in the denominator of every requests-per-second figure
    // this run would ever publish) left every test in every one of this
    // crate's 13 test binaries green. This is the identical hole
    // `tests/loadgen_oha.rs:977` records PR 799 closing for the `oha`
    // adapter, three files over.
    assert_eq!(raw.duration_ns, 35_000_000_000);
    // Pinned against the fixture's own literal `20 failed, 0 errored, 0
    // timeout` (same review, same SHOULD_FIX). NOTE what this alone does
    // and does not prove: this fixture's `errored` and `timeout` are
    // legitimately 0 (a real `1.68.1` run reporting the `20 5xx` this
    // fixture's own `status codes:` line carries has no transport-level
    // connection failures to report; see this file's own module doc, "Every
    // relation 1.68.1's own print_stats guarantees"), so this assertion
    // alone cannot distinguish `errors_u128 = failed + errored + timeout`
    // from `errors_u128 = failed` alone: both equal 20 here.
    // `parse_errors_sums_failed_errored_and_timeout` below, a deliberately
    // synthetic (not fixture-realistic) probe, is what actually exercises
    // the three-way sum with all three terms non-zero and distinct.
    assert_eq!(raw.errors, 20);
    assert!(
        !raw.latency_exact,
        "invariant 1: h2load never sets latency_exact"
    );
    assert!(raw.ttfb.is_some(), "invariant 2: ttfb must be present");
    assert!(raw.connect.is_some());
}

// ---------------------------------------------------------------------------
// Not one of the issue's own 24 named tests (PR 815 review, issue #816
// SHOULD_FIX 1). This document is a DELIBERATELY SYNTHETIC arithmetic probe,
// not a claim about what a real h2load run produces: `tests/fixtures/h2load-output.txt`
// itself cannot exercise `errors_u128`'s three-way sum with `failed`,
// `errored` and `timeout` all non-zero and distinct, because a real
// `1.68.1` run's own `print_stats` forces `total == succeeded + failed`
// exactly (see this file's own module doc), and this crate's Parsing table
// treats `errored`/`timeout` as ADDITIVE on top of `failed` rather than a
// breakdown within it, so a genuine capture with non-zero `errored` or
// `timeout` alongside a non-zero `failed` would need `succeeded + failed +
// errored + timeout` to exceed `total`, which `H2Load::parse`'s own
// "counters are inconsistent" check refuses. This synthetic document
// deliberately violates the realism `tests/fixtures/h2load-output.txt` was
// just fixed to honour (BLOCKING 3), on purpose, to isolate the ONE formula
// this test exists to pin.
// ---------------------------------------------------------------------------

#[test]
fn parse_errors_sums_failed_errored_and_timeout() {
    let text = "finished in 10.00s, 100.00 req/s, 12.50KB/s\n\
         requests: 1000 total, 1000 started, 1000 done, 800 succeeded, 100 failed, 50 errored, 25 timeout\n\
         status codes: 800 2xx, 0 3xx, 0 4xx, 100 5xx\n\
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
        .expect("well-formed synthetic fixture");

    // 100 + 50 + 25 = 175, distinct from `failed` alone (100): this is what
    // distinguishes the three-term sum the Design's own Parsing table
    // specifies ("failed, errored and timeout summed") from a mutation that
    // narrows it to `failed` alone, which the shipped fixture's own
    // legitimately-zero `errored`/`timeout` cannot (100 + 0 + 0 == 100
    // either way).
    assert_eq!(raw.errors, 175);
    assert_eq!(raw.responses_ok, 800);
    assert_eq!(raw.requests_sent, 1_000);
}

// ---------------------------------------------------------------------------
// Not one of the issue's own 24 named tests: pins the module doc's own claim
// (this file's "Every relation 1.68.1's own print_stats guarantees, enforced
// here" section) that a real 1.68.1 run's `req/s` row carries its
// `min`/`max`/`mean`/`sd` columns fixed to 2 decimal places, because
// `std::cout`'s `fixed`/`setprecision(2)` state (set once, at the very start
// of `print_stats`) persists across every later `std::cout <<` statement in
// that function, including this row's raw, unformatted `double`s. This is a
// LITERAL-TEXT check on the fixture file itself, not on `H2Load::parse`
// (which never reads this row at all: see the "Every other line ... is
// tolerated and skipped" comment in `h2load.rs`), so a future edit that
// silently regressed the fixture's own consistency with that claim would
// still be caught.
// ---------------------------------------------------------------------------

#[test]
fn req_s_row_min_max_mean_sd_are_fixed_two_decimal_by_construction() {
    let text = std::str::from_utf8(FIXTURE_BYTES).expect("fixture is utf-8");
    let row = text
        .lines()
        .find(|l| l.starts_with("req/s"))
        .expect("fixture has a req/s row");
    assert!(
        row.contains("2800.00")
            && row.contains("2900.00")
            && row.contains("2857.14")
            && row.contains("25.30"),
        "req/s row must carry two fixed decimal places on min/max/mean/sd, per this file's own \
         module doc: {row:?}"
    );
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
    // 332.17KB/s, not 340.14KB/s: `util::utos_funit` is 1024-based
    // (11,905,000 bytes / 35s = 340,142.857 B/s, / 1024 = 332.17KB/s), the
    // same correction `tests/fixtures/h2load-output.txt` needed (PR 815
    // review, issue #816 BLOCKING 3).
    let text = "finished in 35.00s, 2857.14 req/s, 332.17KB/s\n\
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
