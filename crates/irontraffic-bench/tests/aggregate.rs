// SPDX-License-Identifier: MIT OR Apache-2.0
//! Aggregation tests, all with hand-computed answers, per this issue's own
//! Tests section.
//!
//! Every fixture `RunResult` below is built by [`base_result`] (the same
//! shape and convention as `tests/guards.rs`'s own `base_result`, a small
//! local copy rather than a shared dependency between two independent
//! integration test binaries) with exactly the fields a given test needs
//! changed, so a failure names what actually moved.

use std::collections::BTreeMap;

use irontraffic_bench::{
    BenchCell, Bottleneck, BuildStamp, CacheMode, CellAggregate, CellId, DeepestPercentile,
    InvariantId, KeepaliveMode, LatencyRecorder, PathCorpus, Percentiles, Protocol, Provenance,
    RateMode, RunResult, StampSource, TlsMode, ToolStamp, Validity, median, median_f64, quartiles,
};
use proptest::prelude::*;

/// `#[allow(clippy::expect_used)]`: test-support helper, not itself a
/// `#[test]` fn, so clippy's test exemption for `expect_used` does not
/// extend to it.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn"
)]
fn base_cell_def(id: &str) -> BenchCell {
    BenchCell {
        id: CellId::parse(id).expect("test cell id must be valid"),
        protocol: Protocol::H1,
        tls: TlsMode::Off,
        payload_bytes: 1024,
        routes: 1,
        path_corpus: PathCorpus::SingleHot,
        connections: 64,
        upstreams: 1,
        filter_depth: 0,
        cache: CacheMode::Bypass,
        keepalive: KeepaliveMode::Both,
        rate: RateMode::Fixed(1000),
    }
}

fn clean_stamp(name: &str) -> BuildStamp {
    BuildStamp {
        name: name.to_owned(),
        version: "0.1.0".to_owned(),
        git_sha: "0a1b2c3d4e5f".to_owned(),
        dirty: false,
        profile: "release".to_owned(),
        features: Vec::new(),
        stamp_source: StampSource::Embedded,
    }
}

fn base_provenance() -> Provenance {
    let mut provenance = Provenance {
        utc_date: "2026-07-24T00:00:00Z".to_owned(),
        hardware: "Example CPU, 8c/16t, 32 GiB".to_owned(),
        cpu_model: "Example CPU".to_owned(),
        cpu_arch: "aarch64".to_owned(),
        physical_cores: 8,
        physical_cores_assumed: false,
        logical_cores: 16,
        mem_bytes: 32 * 1024 * 1024 * 1024,
        instance_type: None,
        burstable: false,
        kernel: "6.1.0-generic".to_owned(),
        clocksource: "tsc".to_owned(),
        governor: Some("performance".to_owned()),
        thermal_throttle_count: Some(0),
        ulimit_nofile: 1_048_576,
        ip_local_port_range: Some((32_768, 60_999)),
        sut: clean_stamp("irontraffic"),
        origin: clean_stamp("it-origin"),
        loadgen: ToolStamp {
            name: "oha".to_owned(),
            version: "1.15.0".to_owned(),
            image_digest: None,
        },
        warmup_seconds: 5,
        measure_seconds: 60,
        repetitions: 5,
        publishable: true,
        unpublishable_reasons: Vec::new(),
    };
    provenance.recompute_publishable();
    provenance
}

fn zero_percentiles() -> Percentiles {
    Percentiles {
        p50_ns: 0,
        p90_ns: 0,
        p99_ns: 0,
        p999_ns: 0,
        p9999_ns: 0,
        max_ns: 0,
        samples: 0,
    }
}

/// Builds a `Percentiles` whose ONLY meaningful field is `p99_ns`; every
/// other quantile is set equal to it rather than computed as a fraction of
/// it, because the property test below feeds this arbitrary `u64` values up
/// to `u64::MAX`, and a fraction like `p99_ns * 9 / 10` would overflow for
/// no reason `CellAggregate::from_runs` (which reads only `p99_ns` and
/// `samples`) ever needs.
fn percentiles_with_p99(p99_ns: u64, samples: u64) -> Percentiles {
    Percentiles {
        p50_ns: p99_ns,
        p90_ns: p99_ns,
        p99_ns,
        p999_ns: p99_ns,
        p9999_ns: p99_ns,
        max_ns: p99_ns,
        samples,
    }
}

/// A `RunResult` fixture. Only the fields aggregation tests actually read
/// (`probe_latency.p99_ns`, `rps`, `validity`, `deepest_percentile`, `cell`)
/// vary between tests; everything else is a fixed, plausible filler value,
/// because `CellAggregate::from_runs` never runs `check_validity` itself.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn"
)]
fn base_result(id: &str, probe_p99_ns: u64, rps: f64, validity: Validity) -> RunResult {
    let mut status_counts = BTreeMap::new();
    status_counts.insert(200_u16, 1_000_u64);
    RunResult {
        cell: CellId::parse(id).expect("test cell id must be valid"),
        cell_def: base_cell_def(id),
        provenance: base_provenance(),
        rps,
        latency: percentiles_with_p99(probe_p99_ns, 10_000),
        probe_latency: percentiles_with_p99(probe_p99_ns, 6_000),
        ttfb: zero_percentiles(),
        connect: zero_percentiles(),
        stall: zero_percentiles(),
        cpu_seconds_per_request: None,
        rss_bytes: 0,
        pss_bytes: 0,
        bytes_received: 1024 * 1000,
        payload_bytes: 1024,
        total_requests: 1000,
        status_counts,
        origin_ceiling_rps: rps * 2.0,
        direct_rps: rps * 2.0,
        client_cpu_max_pct: 10.0,
        sut_cores: 4,
        catchup_burst_count: 0,
        out_of_range: 0,
        stall_out_of_range: 0,
        stall_backwards_count: 0,
        warmup_samples_discarded: 500,
        deepest_percentile: DeepestPercentile::P99,
        bottleneck: Bottleneck::Unknown,
        validity,
        command_line: "test-client --cell test".to_owned(),
    }
}

/// A `LatencyRecorder` with exactly `count` samples recorded at `value_ns`.
fn recorder_with_samples(value_ns: u64, count: u64) -> LatencyRecorder {
    #[allow(
        clippy::expect_used,
        reason = "test-support helper, not itself a #[test] fn"
    )]
    let mut recorder = LatencyRecorder::new().expect("LatencyRecorder::new must succeed");
    recorder.record_n_ns(value_ns, count);
    recorder
}

// ---------------------------------------------------------------------------
// 1-3: median.
// ---------------------------------------------------------------------------

#[test]
fn median_odd() {
    assert_eq!(median(&[10, 20, 30]), 20);
}

#[test]
fn median_even_takes_lower() {
    assert_eq!(median(&[10, 20, 30, 40]), 20);
}

#[test]
fn median_single() {
    assert_eq!(median(&[7]), 7);
}

// ---------------------------------------------------------------------------
// 4: quartiles.
// ---------------------------------------------------------------------------

#[test]
fn quartiles_five() {
    assert_eq!(quartiles(&[10, 20, 30, 40, 50]), (20, 40));
}

// ---------------------------------------------------------------------------
// 5 / 5a / 6: iqr_permille.
// ---------------------------------------------------------------------------

#[test]
fn iqr_permille_hand_computed() {
    // p99 values [100, 105, 140, 160, 400]: median v[2] = 140, q1 v[1] = 105,
    // q3 v[3] = 160, iqr_permille = (160 - 105) * 1000 / 140 = 392.
    let runs = vec![
        base_result("cell1", 100, 1000.0, Validity::Valid),
        base_result("cell1", 105, 1000.0, Validity::Valid),
        base_result("cell1", 140, 1000.0, Validity::Valid),
        base_result("cell1", 160, 1000.0, Validity::Valid),
        base_result("cell1", 400, 1000.0, Validity::Valid),
    ];
    let recorders: Vec<LatencyRecorder> = runs
        .iter()
        .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 10_000))
        .collect();
    #[allow(
        clippy::expect_used,
        reason = "test-support helper call, not itself a #[test] fn body proper"
    )]
    let cell_id = CellId::parse("cell1").expect("valid cell id");
    let aggregate =
        CellAggregate::from_runs(cell_id, runs, &recorders).expect("from_runs must succeed");
    assert_eq!(aggregate.median_p99_ns, 140);
    assert_eq!(aggregate.iqr_permille, 392);
    assert_eq!(aggregate.validity, Validity::Unstable { iqr_permille: 392 });
}

#[test]
fn single_outlier_does_not_flag_unstable() {
    // p99 values [100, 105, 110, 115, 400]: median 110, q1 105, q3 115,
    // iqr_permille = 10 * 1000 / 110 = 90. Valid, even though max_p99_ns is
    // 400: the interquartile range excludes the extremes by construction, so
    // one thermal event shows up in the published spread, not the flag.
    let runs = vec![
        base_result("cell2", 100, 1000.0, Validity::Valid),
        base_result("cell2", 105, 1000.0, Validity::Valid),
        base_result("cell2", 110, 1000.0, Validity::Valid),
        base_result("cell2", 115, 1000.0, Validity::Valid),
        base_result("cell2", 400, 1000.0, Validity::Valid),
    ];
    let recorders: Vec<LatencyRecorder> = runs
        .iter()
        .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 10_000))
        .collect();
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("cell2").expect("valid cell id");
    let aggregate =
        CellAggregate::from_runs(cell_id, runs, &recorders).expect("from_runs must succeed");
    assert_eq!(aggregate.iqr_permille, 90);
    assert_eq!(aggregate.max_p99_ns, 400);
    assert_eq!(aggregate.validity, Validity::Valid);
}

#[test]
fn iqr_within_tolerance_is_valid() {
    let runs = vec![
        base_result("cell3", 100, 1000.0, Validity::Valid),
        base_result("cell3", 102, 1000.0, Validity::Valid),
        base_result("cell3", 105, 1000.0, Validity::Valid),
        base_result("cell3", 108, 1000.0, Validity::Valid),
        base_result("cell3", 110, 1000.0, Validity::Valid),
    ];
    let recorders: Vec<LatencyRecorder> = runs
        .iter()
        .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 10_000))
        .collect();
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("cell3").expect("valid cell id");
    let aggregate =
        CellAggregate::from_runs(cell_id, runs, &recorders).expect("from_runs must succeed");
    assert_eq!(aggregate.iqr_permille, 57);
    assert_eq!(aggregate.validity, Validity::Valid);
}

#[test]
fn iqr_at_exactly_the_threshold_is_valid_not_unstable() {
    // Reviewed finding: flipping `iqr_permille > MAX_IQR_PERMILLE` to `>=`
    // survived every existing fixture, because none of them sits at exactly
    // 100. p99 values [90, 95, 100, 105, 110]: median v[2] = 100,
    // q1 v[1] = 95, q3 v[3] = 105, iqr_permille = (105 - 95) * 1000 / 100 =
    // 100 EXACTLY. The spec's own wording is "exceeds 10 percent" (a strict
    // `>`), so a cell sitting exactly at the threshold must still be Valid.
    let runs = vec![
        base_result("cell_threshold", 90, 1000.0, Validity::Valid),
        base_result("cell_threshold", 95, 1000.0, Validity::Valid),
        base_result("cell_threshold", 100, 1000.0, Validity::Valid),
        base_result("cell_threshold", 105, 1000.0, Validity::Valid),
        base_result("cell_threshold", 110, 1000.0, Validity::Valid),
    ];
    let recorders: Vec<LatencyRecorder> = runs
        .iter()
        .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 10_000))
        .collect();
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("cell_threshold").expect("valid cell id");
    let aggregate =
        CellAggregate::from_runs(cell_id, runs, &recorders).expect("from_runs must succeed");
    assert_eq!(aggregate.iqr_permille, 100);
    assert_eq!(
        aggregate.validity,
        Validity::Valid,
        "a cell whose iqr_permille sits at EXACTLY the 100 permille threshold must still be \
         Valid; the spec's own wording is \"exceeds 10 percent\", a strict >, and a mutation \
         that flips it to >= would flag this cell Unstable instead"
    );
}

// ---------------------------------------------------------------------------
// 7 / 8: a per-run Invalid or LoadgenSuspect dominates the spread.
// ---------------------------------------------------------------------------

#[test]
fn invalid_run_dominates_spread() {
    let mut runs = vec![
        base_result("cell4", 100, 1000.0, Validity::Valid),
        base_result("cell4", 101, 1000.0, Validity::Valid),
        base_result("cell4", 102, 1000.0, Validity::Valid),
        base_result("cell4", 103, 1000.0, Validity::Valid),
    ];
    runs.push(base_result(
        "cell4",
        104,
        1000.0,
        Validity::Invalid {
            violated: InvariantId::I7,
            detail: "test-fixture invalid run".into(),
        },
    ));
    let recorders: Vec<LatencyRecorder> = runs
        .iter()
        .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 10_000))
        .collect();
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("cell4").expect("valid cell id");
    let aggregate =
        CellAggregate::from_runs(cell_id, runs, &recorders).expect("from_runs must succeed");
    match aggregate.validity {
        Validity::Invalid { violated, .. } => assert_eq!(violated, InvariantId::I7),
        other => panic!("expected Invalid(I7, ..), got {other:?}"),
    }
}

#[test]
fn suspect_run_dominates_spread() {
    use irontraffic_bench::SuspectReason;
    let mut runs = vec![
        base_result("cell5", 100, 1000.0, Validity::Valid),
        base_result("cell5", 101, 1000.0, Validity::Valid),
        base_result("cell5", 102, 1000.0, Validity::Valid),
        base_result("cell5", 103, 1000.0, Validity::Valid),
    ];
    runs.push(base_result(
        "cell5",
        104,
        1000.0,
        Validity::LoadgenSuspect {
            reason: SuspectReason::StallRatio,
        },
    ));
    let recorders: Vec<LatencyRecorder> = runs
        .iter()
        .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 10_000))
        .collect();
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("cell5").expect("valid cell id");
    let aggregate =
        CellAggregate::from_runs(cell_id, runs, &recorders).expect("from_runs must succeed");
    assert_eq!(
        aggregate.validity,
        Validity::LoadgenSuspect {
            reason: SuspectReason::StallRatio
        }
    );
}

// ---------------------------------------------------------------------------
// 9: the merged histogram is published alongside the median, not instead.
// ---------------------------------------------------------------------------

#[test]
fn merged_is_published_alongside() {
    let runs = vec![
        base_result("cell6", 100, 1000.0, Validity::Valid),
        base_result("cell6", 105, 1000.0, Validity::Valid),
        base_result("cell6", 110, 1000.0, Validity::Valid),
        base_result("cell6", 115, 1000.0, Validity::Valid),
        base_result("cell6", 120, 1000.0, Validity::Valid),
    ];
    let recorders: Vec<LatencyRecorder> = runs
        .iter()
        .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 2_500))
        .collect();
    let total_samples: u64 = recorders.iter().map(LatencyRecorder::len).sum();
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("cell6").expect("valid cell id");
    let aggregate =
        CellAggregate::from_runs(cell_id, runs, &recorders).expect("from_runs must succeed");
    assert_eq!(aggregate.merged.samples, total_samples);
    assert_ne!(aggregate.merged.p99_ns, aggregate.median_p99_ns);
}

// ---------------------------------------------------------------------------
// 10: empty runs, mixed cells, recorder count mismatch.
// ---------------------------------------------------------------------------

#[test]
fn empty_runs_is_error() {
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("cell7").expect("valid cell id");
    let err = CellAggregate::from_runs(cell_id, Vec::new(), &[])
        .expect_err("from_runs must refuse an empty runs list");
    assert!(matches!(err, irontraffic_bench::BenchError::Cell(_)));
}

#[test]
fn mixed_cells_is_error() {
    let runs = vec![
        base_result("cell8", 100, 1000.0, Validity::Valid),
        base_result("cell8_other", 105, 1000.0, Validity::Valid),
    ];
    let recorders: Vec<LatencyRecorder> = runs
        .iter()
        .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 10_000))
        .collect();
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("cell8").expect("valid cell id");
    let err = CellAggregate::from_runs(cell_id, runs, &recorders)
        .expect_err("from_runs must refuse a mismatched cell id in runs");
    assert!(matches!(err, irontraffic_bench::BenchError::Cell(_)));
}

#[test]
fn recorder_count_mismatch_is_error() {
    let runs = vec![
        base_result("cell9", 100, 1000.0, Validity::Valid),
        base_result("cell9", 101, 1000.0, Validity::Valid),
        base_result("cell9", 102, 1000.0, Validity::Valid),
        base_result("cell9", 103, 1000.0, Validity::Valid),
        base_result("cell9", 104, 1000.0, Validity::Valid),
    ];
    // Four recorders for five runs.
    let recorders: Vec<LatencyRecorder> = runs
        .iter()
        .take(4)
        .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 10_000))
        .collect();
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("cell9").expect("valid cell id");
    let err = CellAggregate::from_runs(cell_id, runs, &recorders)
        .expect_err("from_runs must refuse a recorder/run count mismatch");
    match err {
        irontraffic_bench::BenchError::Parse { detail, .. } => {
            let text = detail.as_str();
            assert!(
                text.contains('4'),
                "detail {text:?} must name the recorder count 4"
            );
            assert!(
                text.contains('5'),
                "detail {text:?} must name the run count 5"
            );
        }
        other => panic!("expected BenchError::Parse naming both lengths, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 10a: median_rps is a member.
// ---------------------------------------------------------------------------

#[test]
fn median_rps_is_a_member() {
    assert!((median_f64(&[100.0, 102.0, 105.0, 108.0, 110.0]) - 105.0).abs() < f64::EPSILON);
    assert!((median_f64(&[100.0, 200.0]) - 100.0).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// Property test.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn aggregate_median_is_a_member(mut p99s in prop::collection::vec(any::<u64>(), 1..=9)) {
        #[allow(clippy::expect_used, reason = "proptest generator support, not the test body's own assertion")]
        let cell_id = CellId::parse("propcell").expect("valid cell id");
        let first = p99s.first().copied().unwrap_or(0);
        let all_equal = p99s.iter().all(|&v| v == first);
        let runs: Vec<RunResult> = p99s
            .iter()
            .map(|&p99| base_result("propcell", p99, 1000.0, Validity::Valid))
            .collect();
        let recorders: Vec<LatencyRecorder> = runs
            .iter()
            .map(|r| recorder_with_samples(r.probe_latency.p99_ns, 10_000))
            .collect();
        let aggregate = CellAggregate::from_runs(cell_id, runs, &recorders)
            .expect("from_runs must succeed for a non-empty, same-cell, matched-length input");

        p99s.sort_unstable();
        let min = *p99s.first().unwrap_or(&0);
        let max = *p99s.last().unwrap_or(&0);
        prop_assert!(p99s.contains(&aggregate.median_p99_ns));
        prop_assert!(aggregate.min_p99_ns <= aggregate.median_p99_ns);
        prop_assert!(aggregate.median_p99_ns <= aggregate.max_p99_ns);
        prop_assert_eq!(aggregate.min_p99_ns, min);
        prop_assert_eq!(aggregate.max_p99_ns, max);
        if all_equal {
            prop_assert_eq!(aggregate.iqr_permille, 0);
        }
    }
}
