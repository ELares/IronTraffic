// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parser and cross-check tests for the `Vegeta` adapter (issue #413).
//!
//! # What this fixture is
//!
//! `tests/fixtures/vegeta-report.json` is a REAL capture, unlike
//! `tests/fixtures/h2load-output.txt`: a genuine `vegeta v12.13.0`, built
//! locally with `go install github.com/tsenart/vegeta/v12@v12.13.0` (Go was
//! available in this environment; `docker`/`podman` and a full C++ toolchain
//! for `h2load` were not), attacked a local Python `http.server` echoing a
//! 128 byte body at 50 requests per second for 5 seconds
//! (`vegeta attack -rate 50/1s -duration 5s -connections 10 -max-workers 8
//! -targets targets.txt -output results.bin`, then
//! `vegeta report -type=json results.bin`), not hand-written.
//! `parse_fixture` is the authority on the exact field spellings
//! (`latencies`, `bytes_in`, `status_codes`) `src/loadgen/vegeta.rs`'s
//! parser assumes.
//!
//! # Test 20 and 21's placement
//!
//! `tests/loadgen_h2load.rs`'s own module doc explains why
//! `h2load_parse_rejects_non_numeric_timing_columns` and
//! `h2load_parse_rejects_oversized_output` (issue #413's own tests 20 and
//! 21, listed under THIS file's section header despite both exercising
//! `H2Load` exclusively) live there instead: this file has neither `H2Load`
//! nor its fixture, and the acceptance criterion runs both `--test`
//! binaries together regardless of which file a given test lives in.

use irontraffic_bench::{
    BenchCell, BenchError, CacheMode, CellId, CrossCheck, Invocation, KeepaliveMode, LoadGenerator,
    MAX_VEGETA_WORKERS, NotComparableReason, ParseCtx, PathCorpus, Percentiles, Protocol, RateMode,
    RunParams, Scheme, Target, TlsMode, ToolStamp, Vegeta, cross_check,
};

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

const FIXTURE_BYTES: &[u8] = include_bytes!("fixtures/vegeta-report.json");

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
        connections: 10,
        upstreams: 1,
        filter_depth: 0,
        cache: CacheMode::Bypass,
        keepalive: KeepaliveMode::Both,
        rate: RateMode::Fixed(50),
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

fn base_run() -> RunParams {
    RunParams {
        duration_secs: 5,
        warmup_secs: 0,
        concurrency: None,
    }
}

fn base_vegeta() -> Vegeta {
    Vegeta {
        max_workers: 8,
        targets_path: std::path::PathBuf::from("/tmp/bench/targets.txt"),
        output_path: std::path::PathBuf::from("/tmp/bench/results.bin"),
    }
}

fn base_tool_stamp() -> ToolStamp {
    ToolStamp {
        name: "vegeta".to_owned(),
        version: "12.13.0".to_owned(),
        image_digest: None,
    }
}

#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: base_cell/base_target/base_run/\
              base_vegeta are this file's own fixed, valid constants, so planning cannot fail"
)]
fn base_invocation() -> Invocation {
    base_vegeta()
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

/// A `Percentiles` with every field set explicitly, so a test reads exactly
/// what each one is; `cross_check` only ever reads `p99_ns` and `samples`,
/// so the others are filled with plausible, internally ordered values that
/// no test below depends on.
fn percentiles(p99_ns: u64, samples: u64) -> Percentiles {
    Percentiles {
        p50_ns: 0,
        p90_ns: p99_ns,
        p99_ns,
        p999_ns: p99_ns,
        p9999_ns: p99_ns,
        max_ns: p99_ns,
        samples,
    }
}

/// A percentile pair with ample samples (`Percentiles::required_samples(0.99)`
/// is 10,000; 100,000 clears it comfortably), for tests that are not
/// specifically about the sample-count gate.
fn healthy_percentiles(p99_ns: u64) -> Percentiles {
    percentiles(p99_ns, 100_000)
}

// ---------------------------------------------------------------------------
// 12. plan_always_bounds_workers
// ---------------------------------------------------------------------------

#[test]
fn plan_always_bounds_workers() {
    let invocation = base_vegeta()
        .plan(&base_cell(), &base_target(), &base_run())
        .expect("valid cell");
    let pos = invocation
        .args
        .iter()
        .position(|a| a == "-max-workers")
        .expect("-max-workers must always be present");
    assert_eq!(invocation.args.get(pos + 1), Some(&"8".to_owned()));

    let mut zero_workers = base_vegeta();
    zero_workers.max_workers = 0;
    let err = zero_workers
        .plan(&base_cell(), &base_target(), &base_run())
        .expect_err("a zero worker cap attacks at zero requests per second");
    assert!(matches!(err, BenchError::Cell(_)));
}

// ---------------------------------------------------------------------------
// 12a. report_invocation_is_the_second_command
// ---------------------------------------------------------------------------

#[test]
fn report_invocation_is_the_second_command() {
    let vegeta = base_vegeta();
    let attack = vegeta
        .plan(&base_cell(), &base_target(), &base_run())
        .expect("valid cell");
    assert_eq!(attack.program, "vegeta");
    assert_eq!(attack.args.first(), Some(&"attack".to_owned()));

    let report = vegeta.report_invocation();
    assert_eq!(report.program, "vegeta");
    assert_eq!(
        report.args,
        vec![
            "report".to_owned(),
            "-type=json".to_owned(),
            "/tmp/bench/results.bin".to_owned(),
        ]
    );
    // The pair is unambiguous: `attack` and `report` never share a first
    // argument.
    assert_ne!(attack.args.first(), report.args.first());
}

// ---------------------------------------------------------------------------
// 13. parse_fixture
// ---------------------------------------------------------------------------

#[test]
fn parse_fixture() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    let raw = Vegeta {
        max_workers: 8,
        targets_path: "targets.txt".into(),
        output_path: "results.bin".into(),
    }
    .parse(&ctx, FIXTURE_BYTES, b"")
    .expect("the fixture is well-formed");

    assert_eq!(raw.requests_sent, 250);
    assert_eq!(raw.responses_ok, 250);
    assert_eq!(raw.errors, 0);
    assert_eq!(raw.bytes_received, 32_000);
    assert_eq!(raw.duration_ns, 4_980_002_542);
    assert!(!raw.latency_exact, "vegeta never sets latency_exact");
    assert!(raw.latency.percentiles().samples > 0);

    // Pinned against the fixture's own literal `latencies."99th": 610834`
    // (PR 815 review, issue #816 BLOCKING 2), matching the precedent
    // `tests/loadgen_oha.rs`'s own `parse_real_oha_fixture` already sets for
    // the identical shape of gap: before this assertion existed, the only
    // check on the reconstructed p99 was `samples > 0`, so a mutation that
    // made the parser never read `latencies.99th` at all left every test in
    // every one of this crate's 13 test binaries green, and the independent
    // per-gap rounding bug this file's own module doc records (the
    // reconstructed p99 collapsing onto `latencies.max`, 1,669,119 against
    // this fixture's 610,834, a factor of 2.73) was invisible to the suite
    // entirely. `HdrHistogram`'s own stated precision guarantee is accuracy
    // to within 3 significant decimal digits of the true value, never
    // bit-for-bit equality, matching `tests/hist.rs`'s and
    // `tests/loadgen_h2load.rs`'s own identically reasoned tolerance.
    let expected_p99_ns = 610_834.0_f64;
    #[allow(
        clippy::cast_precision_loss,
        reason = "p99_ns is well under 2^53 for any run this fixture or this crate's own bounds \
                  can produce, so this comparison loses no precision that matters"
    )]
    let actual_p99_ns = raw.latency.percentiles().p99_ns as f64;
    let diff = (actual_p99_ns - expected_p99_ns).abs();
    assert!(
        diff <= expected_p99_ns * 0.01,
        "reconstructed p99_ns {actual_p99_ns} not within 1% of the fixture's own {expected_p99_ns}"
    );
}

// ---------------------------------------------------------------------------
// Not one of the issue's own 24 named tests (PR 815 review, issue #817
// BLOCKING 1's own regression guard). `parse_fixture` above pins the SAME
// property at `requests: 250`, but `250 mod 100 == 50`, the ONE residue
// where `round(0.99 * r) == ceil(0.99 * r)`: a regression that reverted the
// cumulative allocator's target from `ceil` back to `round` (the fix this
// module doc's "The percentile reconstruction" section records, PR 815
// review, issue #817 BLOCKING 1) would leave `parse_fixture` passing
// unchanged, exactly the "guard sits on the one value that cannot fail"
// shape that review named. `requests: 151` (`151 mod 100 == 51`, inside the
// `51..=99` collapsing band the review's own residue rule derives) is what
// actually exercises the reader/allocator mismatch: at `r = 151`,
// `round(0.99 * 151) == 149` but `ceil(0.99 * 151) == 150`, and
// `LatencyRecorder::percentiles`'s own `value_at_quantile(0.99)` reads rank
// `ceil(0.99 * 151) == 150`, which a `round`-based cumulative target places
// one rank INTO `latencies.max` (rank 150 falls in the max bucket's
// `150..=151`, since the `round`-based 99th bucket only reaches rank 149)
// rather than the 99th bucket. Watched to fail against the `round`-based
// form this replaces: the reconstructed p99 there collapses onto
// `latencies.max` (1,668,750), 2.73x this fixture's own declared 610,834,
// clearing the 1 percent tolerance below by two orders of magnitude.
// ---------------------------------------------------------------------------

#[test]
fn parse_reconstructs_p99_at_a_collapsing_residue() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    // The fixture's own percentile ladder, at `requests: 151` instead of
    // `250`: same values, a residue (51) inside the collapsing band instead
    // of the one residue (50) that cannot collapse.
    let doc = r#"{
        "latencies": {"50th": 404245, "90th": 522854, "95th": 564124, "99th": 610834, "max": 1668750},
        "bytes_in": {"total": 32000},
        "requests": 151,
        "duration": 4980002542,
        "status_codes": {"200": 151}
    }"#;

    let raw = Vegeta {
        max_workers: 8,
        targets_path: "targets.txt".into(),
        output_path: "results.bin".into(),
    }
    .parse(&ctx, doc.as_bytes(), b"")
    .expect("well-formed synthetic fixture");

    assert_eq!(raw.requests_sent, 151);
    // Total allocation stays exact: every one of the 151 samples lands
    // somewhere, which the rounded-cumulative fix already established and
    // this ceil-based one does not regress.
    assert_eq!(raw.latency.percentiles().samples, 151);

    let expected_p99_ns = 610_834.0_f64;
    #[allow(
        clippy::cast_precision_loss,
        reason = "p99_ns is well under 2^53 for any run this file's fixtures can produce, so this \
                  comparison loses no precision that matters"
    )]
    let actual_p99_ns = raw.latency.percentiles().p99_ns as f64;
    let diff = (actual_p99_ns - expected_p99_ns).abs();
    assert!(
        diff <= expected_p99_ns * 0.01,
        "reconstructed p99_ns {actual_p99_ns} not within 1% of the declared {expected_p99_ns}: a \
         round-based (rather than ceil-based) cumulative allocator collapses this exact residue \
         onto latencies.max (1,668,750)"
    );
}

// ---------------------------------------------------------------------------
// Not one of the issue's own 24 named tests: `src/loadgen/vegeta.rs`'s own
// module doc states that `status_codes` gets the SAME canonical-rendering
// check `oha.rs`'s `parse_rejects_status_code_key_aliasing` fix established
// (a real, previously shipped defect this milestone's own review caught), but
// no test in the issue's own Tests section exercises it for THIS adapter.
// Watched to fail: reverting `vegeta.rs`'s `code.to_string() != *key` check
// makes this pass with `responses_ok == 200` instead of failing, exactly the
// silent-aliasing shape the check exists to close.
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_status_code_key_aliasing() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    let doc = r#"{
        "latencies": {"50th": 100, "90th": 150, "95th": 180, "99th": 200, "max": 250},
        "bytes_in": {"total": 100},
        "requests": 2,
        "duration": 1000000000,
        "status_codes": {"200": 1, "0200": 1}
    }"#;

    let err = Vegeta {
        max_workers: 8,
        targets_path: "t".into(),
        output_path: "o".into(),
    }
    .parse(&ctx, doc.as_bytes(), b"")
    .expect_err("an aliased status code key (\"0200\" alongside \"200\") must be Err(Parse)");
    assert!(matches!(err, BenchError::Parse { .. }));
}

// ---------------------------------------------------------------------------
// Not one of the issue's own 24 named tests (PR 815 review, issue #816
// SHOULD_FIX 6): `latencies` is the object that produces the number
// `cross_check`'s 5 percent gate actually compares, and it had neither of
// the two defences `oha.rs` grew for the identical shape of object. Both are
// probed directly here rather than only asserted in prose.
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_non_monotone_latencies() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    // p50 above p90 above p95, then a p99/max drop back to 1: not a real
    // distribution. Matches `tests/loadgen_oha.rs`'s own
    // `parse_rejects_non_monotone_percentiles` probe shape for the
    // identical check on the identical shape of object.
    let doc = r#"{
        "latencies": {"50th": 900000, "90th": 800000, "95th": 700000, "99th": 1, "max": 1},
        "bytes_in": {"total": 100},
        "requests": 1000,
        "duration": 1000000000,
        "status_codes": {"200": 1000}
    }"#;

    let err = Vegeta {
        max_workers: 8,
        targets_path: "t".into(),
        output_path: "o".into(),
    }
    .parse(&ctx, doc.as_bytes(), b"")
    .expect_err("a non-monotone latencies ladder must be Err(Parse)");
    assert!(matches!(err, BenchError::Parse { .. }));
}

#[test]
fn parse_rejects_duplicate_latencies_key() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = base_ctx(&cell, &invocation, &tool);

    // A literally repeated "99th" key, deliberately chosen so the SECOND
    // (last-wins) value, 195000, is still monotone non-decreasing against
    // its neighbours (180000 <= 195000 <= 250000): this isolates the
    // duplicate-key defence from the monotonicity check immediately above
    // it. A document whose duplicated key collapses to a non-monotone
    // value (this file's own module doc example, "99th": 200000, "99th": 1)
    // would be caught by monotonicity alone even with the duplicate-key
    // check removed, which would not prove THIS defence is load-bearing.
    let doc = r#"{
        "latencies": {"50th": 100000, "90th": 150000, "95th": 180000, "99th": 190000, "99th": 195000, "max": 250000},
        "bytes_in": {"total": 100},
        "requests": 1000,
        "duration": 1000000000,
        "status_codes": {"200": 1000}
    }"#;

    let err = Vegeta {
        max_workers: 8,
        targets_path: "t".into(),
        output_path: "o".into(),
    }
    .parse(&ctx, doc.as_bytes(), b"")
    .expect_err(
        "a duplicated latencies.99th key must be Err(Parse), even when the collapsed \
                 value is itself monotone",
    );
    assert!(matches!(err, BenchError::Parse { .. }));
}

// ---------------------------------------------------------------------------
// 14. cross_check_agrees_within_tolerance
// ---------------------------------------------------------------------------

#[test]
fn cross_check_agrees_within_tolerance() {
    let arbiter = healthy_percentiles(1_000_000);
    let independent = healthy_percentiles(1_040_000);
    let verdict = cross_check(&arbiter, &independent, 10.0);
    assert_eq!(verdict, CrossCheck::Agree { delta_permille: 38 });
}

// ---------------------------------------------------------------------------
// 15. cross_check_disagrees_outside_tolerance
// ---------------------------------------------------------------------------

#[test]
fn cross_check_disagrees_outside_tolerance() {
    let arbiter = healthy_percentiles(1_000_000);
    let independent = healthy_percentiles(1_200_000);
    let verdict = cross_check(&arbiter, &independent, 10.0);
    assert!(
        matches!(verdict, CrossCheck::Disagree { .. }),
        "{verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// Not one of the issue's own 24 named tests, added on top of them: edge case
// 13 ("cross_check at exactly 50 permille. Agree. The rule is 'more than 5
// percent'.") is named in the issue's Edge cases section but not given its
// own entry in the Tests section, and a boundary tested only far from its
// edge (38 permille, ~166 permille above) can drift by a wide margin
// unnoticed. All three pin the LITERAL delta_permille, not just the Agree/
// Disagree variant, so an off-by-one at the boundary itself fails loudly.
// ---------------------------------------------------------------------------

#[test]
fn cross_check_boundary_is_pinned_exactly_at_the_edge() {
    let arbiter = healthy_percentiles(1_000_000);

    // 49,000 / 1,000,000 = 49 permille: just under the 50 permille edge.
    let just_under = healthy_percentiles(1_000_000 - 49_000);
    assert_eq!(
        cross_check(&arbiter, &just_under, 10.0),
        CrossCheck::Agree { delta_permille: 49 }
    );

    // 50,000 / 1,000,000 = 50 permille exactly: the rule is "more than 5
    // percent", so exactly 5 percent still Agrees.
    let exactly_at = healthy_percentiles(1_000_000 - 50_000);
    assert_eq!(
        cross_check(&arbiter, &exactly_at, 10.0),
        CrossCheck::Agree { delta_permille: 50 }
    );

    // 51,000 / 1,000,000 = 51 permille: just over the edge.
    let just_over = healthy_percentiles(1_000_000 - 51_000);
    assert_eq!(
        cross_check(&arbiter, &just_over, 10.0),
        CrossCheck::Disagree { delta_permille: 51 }
    );
}

// ---------------------------------------------------------------------------
// 16. cross_check_not_comparable
// ---------------------------------------------------------------------------

#[test]
fn cross_check_not_comparable() {
    // Client CPU 85 percent: ClientSaturated, even though the two
    // percentiles themselves are otherwise healthy and close.
    let arbiter = healthy_percentiles(1_000_000);
    let independent = healthy_percentiles(1_010_000);
    assert_eq!(
        cross_check(&arbiter, &independent, 85.0),
        CrossCheck::NotComparable {
            reason: NotComparableReason::ClientSaturated
        }
    );

    // 5,000 samples at quantile 0.99: below `required_samples(0.99)`
    // (10,000), so TooFewSamples, even with a healthy client CPU reading.
    let few_samples_a = percentiles(1_000_000, 5_000);
    let few_samples_b = percentiles(1_010_000, 100_000);
    assert_eq!(
        cross_check(&few_samples_a, &few_samples_b, 10.0),
        CrossCheck::NotComparable {
            reason: NotComparableReason::TooFewSamples
        }
    );

    // Two empty recorders: NoSamples, not a division by zero.
    let empty = percentiles(0, 0);
    assert_eq!(
        cross_check(&empty, &empty, 10.0),
        CrossCheck::NotComparable {
            reason: NotComparableReason::NoSamples
        }
    );

    // Issue #413's own edge case 12, `cross_check` where both p99 values are
    // 0, distinct from the "two empty recorders" case immediately above:
    // `samples` here is a healthy 100,000 on both sides, only `p99_ns` is
    // zero (PR 815 review, issue #816 SHOULD_FIX 2). Reachable through
    // `Vegeta::parse`: a report whose `latencies` object is all zeros
    // parses `Ok` with `samples > 0` and `p99 == 0` (nothing in that parser
    // rejects a zero-valued percentile ladder). The `p99_ns == 0` clauses in
    // `cross_check`'s step 1 are what catch this before step 4's division;
    // deleting them does not fail any OTHER test in this file (the
    // `samples == 0` clause alone already covers the empty-recorder case
    // above), but it does turn this exact input into a division-by-zero
    // panic at `max_p99 = 0`, since `arbiter.samples.min(independent.samples)`
    // (100,000) clears `Percentiles::required_samples(0.99)` and step 3
    // never fires either.
    let zero_p99_a = percentiles(0, 100_000);
    let zero_p99_b = percentiles(0, 100_000);
    assert_eq!(
        cross_check(&zero_p99_a, &zero_p99_b, 10.0),
        CrossCheck::NotComparable {
            reason: NotComparableReason::NoSamples
        }
    );
    // One side zero, one side healthy: still NoSamples, not a comparison
    // against a measurement that does not exist.
    let one_zero_p99 = percentiles(0, 100_000);
    let healthy = healthy_percentiles(1_000_000);
    assert_eq!(
        cross_check(&one_zero_p99, &healthy, 10.0),
        CrossCheck::NotComparable {
            reason: NotComparableReason::NoSamples
        }
    );
}

// ---------------------------------------------------------------------------
// 17. cross_check_rejects_non_finite_cpu
// ---------------------------------------------------------------------------

#[test]
fn cross_check_rejects_non_finite_cpu() {
    // Identical, healthy `Percentiles`: absent the CPU check, these would
    // Agree with delta_permille == 0.
    let p = healthy_percentiles(1_000_000);
    for cpu in [f64::NAN, f64::INFINITY, -1.0_f64] {
        let verdict = cross_check(&p, &p, cpu);
        assert_eq!(
            verdict,
            CrossCheck::NotComparable {
                reason: NotComparableReason::ClientSaturated
            },
            "cpu={cpu}: NaN >= 80.0 is false, so an ordering-only check would report agreement \
             on a measurement that does not exist"
        );
    }
}

// ---------------------------------------------------------------------------
// 18. cross_check_does_not_wrap_on_extreme_percentiles
// ---------------------------------------------------------------------------

#[test]
fn cross_check_does_not_wrap_on_extreme_percentiles() {
    // `Percentiles` are deserialised from result files a pull request author
    // can edit, so `p99_ns` can be `u64::MAX`; a `u64` multiply here (rather
    // than the u128 this parser actually uses) would wrap `u64::MAX * 1000`
    // into a small number that lands inside the tolerance and reports
    // `Agree`.
    let arbiter = healthy_percentiles(u64::MAX);
    let independent = healthy_percentiles(1);
    let verdict = cross_check(&arbiter, &independent, 10.0);
    let CrossCheck::Disagree { delta_permille } = verdict else {
        panic!("expected Disagree, got {verdict:?}");
    };
    assert!(delta_permille <= 1000, "delta_permille={delta_permille}");
}

// ---------------------------------------------------------------------------
// 19. plan_rejects_absurd_worker_cap
// ---------------------------------------------------------------------------

#[test]
fn plan_rejects_absurd_worker_cap() {
    for bad in [MAX_VEGETA_WORKERS + 1, u32::MAX] {
        let mut vegeta = base_vegeta();
        vegeta.max_workers = bad;
        let err = vegeta
            .plan(&base_cell(), &base_target(), &base_run())
            .expect_err(
                "a worker cap above MAX_VEGETA_WORKERS is the unbounded case spelled differently",
            );
        assert!(matches!(err, BenchError::Cell(_)), "max_workers={bad}");
    }

    let mut vegeta = base_vegeta();
    vegeta.max_workers = MAX_VEGETA_WORKERS;
    vegeta
        .plan(&base_cell(), &base_target(), &base_run())
        .expect("MAX_VEGETA_WORKERS exactly must be Ok");
}

// ---------------------------------------------------------------------------
// Property test: cross_check_is_symmetric_and_bounded
// ---------------------------------------------------------------------------

proptest::proptest! {
    // The issue's own acceptance criterion names 1,000 cases explicitly
    // ("cross_check is symmetric for 1,000 randomly generated pairs"),
    // above proptest's own default of 256.
    #![proptest_config(proptest::test_runner::Config {
        cases: 1_000,
        ..proptest::test_runner::Config::default()
    })]
    #[test]
    fn cross_check_is_symmetric_and_bounded(
        p99_a in proptest::num::u64::ANY,
        p99_b in proptest::num::u64::ANY,
        cpu in proptest::num::f64::ANY,
    ) {
        // `samples` is fixed at a large constant rather than generated: the
        // property this test states (symmetry, the 1,000 bound, and
        // non-finite-CPU-never-Agree) holds regardless of `samples`'
        // value, and `Percentiles::required_samples`/`NoSamples`/
        // `TooFewSamples` are already exercised directly, with literal
        // pinned values, by `cross_check_not_comparable` above; this
        // property test's own job is the full `0..=u64::MAX` sweep over
        // `p99_ns` and arbitrary `f64` (including `NaN` and the infinities)
        // for `cpu`, per the issue's own wording.
        let a = percentiles(p99_a, 1_000_000);
        let b = percentiles(p99_b, 1_000_000);

        let forward = cross_check(&a, &b, cpu);
        let backward = cross_check(&b, &a, cpu);
        proptest::prop_assert_eq!(forward, backward, "cross_check must be symmetric");

        match forward {
            CrossCheck::Agree { delta_permille } | CrossCheck::Disagree { delta_permille } => {
                proptest::prop_assert!(delta_permille <= 1000, "delta_permille={delta_permille}");
            }
            CrossCheck::NotComparable { .. } => {}
        }

        if !cpu.is_finite() {
            proptest::prop_assert!(
                !matches!(forward, CrossCheck::Agree { .. }),
                "a non-finite cpu must never yield Agree"
            );
        }
    }
}
