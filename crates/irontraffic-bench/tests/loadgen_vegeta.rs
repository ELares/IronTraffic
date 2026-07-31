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
