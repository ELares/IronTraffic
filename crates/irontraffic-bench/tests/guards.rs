// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tests for `check_validity` and the thirteen validity invariants.
//!
//! Every test starts from [`base_result`] (the same shape as
//! `tests/fixtures/valid-run.json`) and mutates exactly one thing, so a test
//! failure names the field that broke. `base_result`'s own precondition
//! (asserted inside it) is that it is `Validity::Valid`, matching the
//! `base_cell` / `base_provenance` convention already used in
//! `tests/cell_id.rs` and `tests/provenance.rs`.

use std::collections::BTreeMap;

use irontraffic_bench::{
    BenchCell, Bottleneck, BuildStamp, CacheMode, CellId, DeepestPercentile, Detail, InvariantId,
    KeepaliveMode, MAX_COMMAND_LINE, PathCorpus, Percentiles, Protocol, Provenance, RateMode,
    RunResult, StampSource, SuspectReason, TlsMode, ToolStamp, Validity, check_validity,
};
use proptest::prelude::*;
use proptest::strategy::ValueTree;

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A `BuildStamp` that passes I10 on its own: `release`, clean, embedded.
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

/// A fully specified, fully publishable `Provenance`, the same shape as
/// `base_provenance` in `tests/provenance.rs`, with a nonzero warmup so I11
/// is exercised by every test that does not explicitly zero it out.
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
            name: "nighthawk".to_owned(),
            version: "1.0.0".to_owned(),
            image_digest: None,
        },
        warmup_seconds: 5,
        measure_seconds: 60,
        repetitions: 1,
        publishable: true,
        unpublishable_reasons: Vec::new(),
    };
    provenance.recompute_publishable();
    provenance
}

/// `#[allow(clippy::expect_used)]`: test-support helper, not itself a
/// `#[test]` fn, so clippy's test exemption for `expect_used` does not
/// extend to it. `"base"` is a literal already covered by `parses_single_segment`
/// in `tests/cell_id.rs`.
#[allow(clippy::expect_used, reason = "see the function doc comment above")]
fn base_cell_def() -> BenchCell {
    BenchCell {
        id: CellId::parse("base").expect("\"base\" is a valid cell id"),
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
        rate: RateMode::Saturate,
    }
}

fn percentiles(
    p50: u64,
    p90: u64,
    p99: u64,
    p999: u64,
    p9999: u64,
    max: u64,
    samples: u64,
) -> Percentiles {
    Percentiles {
        p50_ns: p50,
        p90_ns: p90,
        p99_ns: p99,
        p999_ns: p999,
        p9999_ns: p9999,
        max_ns: max,
        samples,
    }
}

/// A `RunResult` that passes all thirteen invariants. Every test in this
/// file starts here (`let mut r = base_result();`) and mutates exactly one
/// thing before asserting the resulting `Validity`.
///
/// The numbers below are deliberately round: `rps` and `origin_ceiling_rps`
/// are exact multiples of 1000 so the milli-rate conversion in step 0 is
/// exact rather than incidentally correct, matching the convention
/// `i2_boundary_passes` (test 3) itself calls for.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn"
)]
fn base_result() -> RunResult {
    let mut status_counts = BTreeMap::new();
    status_counts.insert(200_u16, 1_000_000_u64);

    let r = RunResult {
        cell: CellId::parse("base").expect("\"base\" is a valid cell id"),
        cell_def: base_cell_def(),
        provenance: base_provenance(),
        rps: 50_000.0,
        latency: percentiles(
            500_000, 1_000_000, 2_000_000, 3_000_000, 4_000_000, 5_000_000, 600_000,
        ),
        probe_latency: percentiles(
            300_000, 600_000, 1_200_000, 1_500_000, 1_800_000, 2_000_000, 60_000,
        ),
        ttfb: percentiles(
            100_000, 200_000, 400_000, 600_000, 800_000, 1_000_000, 600_000,
        ),
        connect: percentiles(50_000, 100_000, 200_000, 300_000, 400_000, 500_000, 64),
        stall: percentiles(0, 0, 50_000, 60_000, 70_000, 80_000, 600_000),
        cpu_seconds_per_request: None,
        rss_bytes: 200_000_000,
        pss_bytes: 180_000_000,
        bytes_received: 1024 * 1_000_000,
        payload_bytes: 1024,
        total_requests: 1_000_000,
        status_counts,
        origin_ceiling_rps: 100_000.0,
        direct_rps: 90_000.0,
        client_cpu_max_pct: 45.0,
        sut_cores: 8,
        catchup_burst_count: 0,
        out_of_range: 0,
        stall_out_of_range: 0,
        stall_backwards_count: 0,
        warmup_samples_discarded: 500,
        deepest_percentile: DeepestPercentile::P99,
        bottleneck: Bottleneck::Cpu,
        validity: Validity::Valid,
        command_line: "it-loadgen --cell base --rate saturate --duration 60 --warmup 5".to_owned(),
    };

    assert_eq!(
        check_validity(&r, None, None),
        Validity::Valid,
        "base_result's own fixture precondition: it must start Valid so each test can flip \
         exactly one thing and attribute the resulting verdict to it"
    );
    r
}

/// Asserts `$v` is `Validity::Invalid { violated: $want, .. }` and that its
/// `detail` respects the 256 byte bound (design invariant 9).
///
/// A `macro_rules!` rather than a plain function DELIBERATELY: this
/// project's `invariant-lints.sh` `no-test-without-assertion` rule looks for
/// an `assert*!`-shaped token textually inside each `#[test]` fn's own body,
/// and cannot see through a call to a helper FUNCTION that does the actual
/// asserting one level down. Expanding as a macro keeps the assertion
/// textually present at every call site, so the mechanical check (which is
/// exactly the same kind of mechanical, no-judgment-call guard this issue's
/// own `check_validity` is) can see it too, instead of taking this file's
/// word for it.
macro_rules! assert_invalid {
    ($v:expr, $want:expr $(,)?) => {{
        match $v {
            Validity::Invalid { violated, detail } => {
                assert_eq!(
                    *violated, $want,
                    "wrong invariant violated; detail was {detail}"
                );
                assert!(
                    detail.as_str().len() <= 256,
                    "Detail must never exceed 256 bytes, design invariant 9"
                );
            }
            other => panic!("expected Invalid({:?}, ..), got {:?}", $want, other),
        }
    }};
}

/// Asserts `$v` is `Validity::LoadgenSuspect { reason: $want }`. A macro for
/// the same reason as `assert_invalid!` above.
macro_rules! assert_suspect {
    ($v:expr, $want:expr $(,)?) => {
        assert_eq!(*$v, Validity::LoadgenSuspect { reason: $want });
    };
}

// ---------------------------------------------------------------------------
// 1: the pass case.
// ---------------------------------------------------------------------------

#[test]
fn fixture_is_valid() {
    let r = base_result();
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
    // Design invariant 8, pinned directly on the fixture that check_validity
    // just called Valid.
    assert!(r.command_line.len() <= MAX_COMMAND_LINE);
    assert!(r.command_line.bytes().all(|b| (0x20..=0x7E).contains(&b)));
    // Design invariant 4: the fixture itself respects the 64-entry bound.
    assert!(r.status_counts.len() <= 64);
    // Design invariant 5, restated directly: total_requests never undercounts
    // the sum of status_counts.
    let sum: u128 = r.status_counts.values().map(|&v| u128::from(v)).sum();
    assert!(u128::from(r.total_requests) >= sum);
}

/// The checked-in fixture file deserialises and is Valid: the acceptance
/// criterion "`tests/fixtures/valid-run.json` deserialises into a
/// `RunResult` whose `check_validity` is `Valid`", checked directly rather
/// than only through the Rust builder above.
#[test]
fn fixture_file_deserialises_and_is_valid() {
    let bytes = std::fs::read(fixture_path("valid-run.json"))
        .expect("the checked-in valid-run.json fixture must be present and readable");
    let r: RunResult =
        serde_json::from_slice(&bytes).expect("valid-run.json must deserialise into a RunResult");
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

// ---------------------------------------------------------------------------
// 2 / 3: I2.
// ---------------------------------------------------------------------------

#[test]
fn i2_origin_ceiling() {
    let mut r = base_result();
    r.origin_ceiling_rps = 100_000.0;
    r.rps = 71_000.0;
    assert_suspect!(
        &check_validity(&r, None, None),
        SuspectReason::OriginCeiling,
    );
}

#[test]
fn i2_boundary_passes() {
    let mut r = base_result();
    r.origin_ceiling_rps = 100_000.0;
    r.rps = 70_000.0;
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

// ---------------------------------------------------------------------------
// 4 / 5 / 6 / 6a / 6b / 6c / 7: I3.
// ---------------------------------------------------------------------------

#[test]
fn i3_status_distribution() {
    let mut r = base_result();
    r.total_requests = 1_000_000;
    r.status_counts = BTreeMap::from([(200_u16, 999_800_u64), (503_u16, 200_u64)]);
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I3);
}

#[test]
fn i3_boundary_passes() {
    let mut r = base_result();
    r.total_requests = 1_000_000;
    r.status_counts = BTreeMap::from([(200_u16, 999_900_u64), (503_u16, 100_u64)]);
    r.bytes_received = u64::from(r.payload_bytes) * 999_900;
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

#[test]
fn i3_empty_status_map() {
    let mut r = base_result();
    r.status_counts.clear();
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I3);
}

#[test]
fn i3_zero_total_requests() {
    let mut r = base_result();
    r.total_requests = 0;
    r.status_counts.clear();
    r.bytes_received = 0;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I3);
}

#[test]
fn i3_status_counts_exceed_total_requests() {
    let mut r = base_result();
    r.total_requests = 1_000_000;
    r.status_counts = BTreeMap::from([(200_u16, 2_000_000_u64)]);
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I3);
}

#[test]
fn i3_status_sum_does_not_wrap() {
    let mut r = base_result();
    r.status_counts = BTreeMap::from([(200_u16, u64::MAX), (500_u16, u64::MAX)]);
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I3);
}

#[test]
fn i3_too_many_codes() {
    let mut r = base_result();
    // 65 distinct codes, but constructed so every OTHER I3 sub-check still
    // passes (sum equals total_requests exactly, and the 200 bucket alone
    // already clears the 99.99 percent floor): 200 carries 999_936 and each
    // of the other 64 codes carries exactly 1, summing to 1_000_000. A test
    // that also broke the ratio or the sum check here would not uniquely
    // pin the entry-count bound; caught live by mutating the entry-count
    // check to a no-op and finding this test still passed for the WRONG
    // reason (the ratio check firing instead) before this fixture was
    // tightened.
    r.total_requests = 1_000_000;
    let mut status_counts: BTreeMap<u16, u64> =
        (201_u16..201 + 64).map(|code| (code, 1_u64)).collect();
    status_counts.insert(200_u16, 999_936_u64);
    assert_eq!(status_counts.len(), 65);
    assert_eq!(status_counts.values().sum::<u64>(), 1_000_000);
    r.status_counts = status_counts;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I3);
}

/// Acceptance criterion, checked directly rather than only through
/// `i3_zero_total_requests` (which also clears `status_counts`): "A
/// `RunResult` with `total_requests == 0` and every other field valid is NOT
/// `Valid`."
#[test]
fn total_requests_zero_alone_is_never_valid() {
    let mut r = base_result();
    r.total_requests = 0;
    assert_ne!(check_validity(&r, None, None), Validity::Valid);
}

// ---------------------------------------------------------------------------
// 8 / 9 / 10: I4.
// ---------------------------------------------------------------------------

#[test]
fn i4_bytes_mismatch() {
    let mut r = base_result();
    r.bytes_received += 1;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I4);
}

#[test]
fn i4_zero_payload() {
    let mut r = base_result();
    r.payload_bytes = 0;
    r.bytes_received = 0;
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

#[test]
#[allow(
    clippy::integer_division,
    reason = "an exact halving of u64::MAX to get a round, huge ok_count for the fixture; the \
              one bit of remainder integer division truncates is irrelevant to what this test \
              proves"
)]
fn i4_huge_product_is_invalid() {
    let mut r = base_result();
    let huge_ok_count = u64::MAX / 2;
    r.total_requests = huge_ok_count;
    r.status_counts = BTreeMap::from([(200_u16, huge_ok_count)]);
    r.payload_bytes = u32::MAX;
    // bytes_received is left at the base fixture's value, nowhere near the
    // ~3.96e28 product this now describes, so I4 must reject it.
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I4);
}

// ---------------------------------------------------------------------------
// 11 / 19b: I5.
// ---------------------------------------------------------------------------

#[test]
fn i5_sample_count() {
    let mut r = base_result();
    r.deepest_percentile = DeepestPercentile::P9999;
    r.latency.samples = 999_999;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I5);

    r.latency.samples = 1_000_000;
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

#[test]
fn i5_dead_probe() {
    let mut r = base_result();
    r.probe_latency.samples = 0;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I5);
}

// ---------------------------------------------------------------------------
// 12: I6.
// ---------------------------------------------------------------------------

#[test]
fn i6_client_cpu() {
    let mut r = base_result();
    r.client_cpu_max_pct = 80.0;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I6);

    r.client_cpu_max_pct = 79.9;
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

// ---------------------------------------------------------------------------
// 13 / 13a: I7.
// ---------------------------------------------------------------------------

#[test]
fn i7_out_of_range() {
    let mut r = base_result();
    r.out_of_range = 1;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I7);
}

#[test]
fn i7_covers_the_stall_histogram() {
    let mut r = base_result();
    r.out_of_range = 0;
    r.stall_out_of_range = 1;
    let v = check_validity(&r, None, None);
    assert_invalid!(&v, InvariantId::I7);
    if let Validity::Invalid { detail, .. } = v {
        assert!(
            detail.as_str().contains("stall"),
            "detail must name the stall histogram specifically, got {detail}"
        );
    }
}

// ---------------------------------------------------------------------------
// 14: I8.
// ---------------------------------------------------------------------------

#[test]
fn i8_stall_ratio() {
    let mut r = base_result();
    r.latency.p99_ns = 1_900_000;
    r.stall.p99_ns = 100_000;
    assert_suspect!(&check_validity(&r, None, None), SuspectReason::StallRatio);

    r.stall.p99_ns = 95_000;
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

// ---------------------------------------------------------------------------
// 15: I9.
// ---------------------------------------------------------------------------

#[test]
fn i9_probe_divergence() {
    let mut r = base_result();
    r.stall.p99_ns = 0;
    r.probe_latency.p99_ns = 1_000_000;
    r.latency.p99_ns = 2_000_001;
    assert_suspect!(
        &check_validity(&r, None, None),
        SuspectReason::ProbeDivergence,
    );
}

// ---------------------------------------------------------------------------
// 16 / 17: I10.
// ---------------------------------------------------------------------------

#[test]
fn i10_debug_profile() {
    let mut r = base_result();
    r.provenance.sut.profile = "debug".to_owned();
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I10);
}

#[test]
fn i10_dirty_worktree() {
    let mut r = base_result();
    r.provenance.sut.dirty = true;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I10);
}

// ---------------------------------------------------------------------------
// 18: I11.
// ---------------------------------------------------------------------------

#[test]
fn i11_warmup_not_discarded() {
    let mut r = base_result();
    r.provenance.warmup_seconds = 30;
    r.warmup_samples_discarded = 0;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I11);
}

// ---------------------------------------------------------------------------
// 19 / 19a: I12.
// ---------------------------------------------------------------------------

#[test]
fn i12_command_line_drift() {
    let r = base_result();
    assert_invalid!(
        &check_validity(&r, Some("different command"), None),
        InvariantId::I12,
    );
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

#[test]
fn i12_rejects_a_hostile_command_line() {
    let too_long = "a".repeat(MAX_COMMAND_LINE + 1);
    let ansi = "it-loadgen --cell base \x1b[2J\x1b[1;1H --rate saturate".to_owned();
    let newline = "it-loadgen --cell base\n--rate saturate".to_owned();

    for hostile in [too_long, ansi, newline] {
        let mut r = base_result();
        r.command_line = hostile;
        let v = check_validity(&r, None, None);
        assert_invalid!(&v, InvariantId::I12);
        if let Validity::Invalid { detail, .. } = v {
            assert!(detail.as_str().len() <= 256);
            assert!(detail.as_str().bytes().all(|b| (0x20..=0x7E).contains(&b)));
        }
    }
}

// ---------------------------------------------------------------------------
// 20 / 20a: I13.
// ---------------------------------------------------------------------------

#[test]
fn i13_unknown_bottleneck() {
    let mut r = base_result();
    r.cell_def.rate = RateMode::Saturate;
    r.bottleneck = Bottleneck::Unknown;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I13);
}

#[test]
fn i13_unknown_is_allowed_on_a_fixed_rate_cell() {
    let mut r = base_result();
    r.cell_def.rate = RateMode::Fixed(60_000);
    r.bottleneck = Bottleneck::Unknown;
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

// ---------------------------------------------------------------------------
// 20b: the catch-up burst ratio.
// ---------------------------------------------------------------------------

#[test]
fn catchup_burst_ratio_is_suspect() {
    let mut r = base_result();
    r.total_requests = 1_000_000;
    r.status_counts = BTreeMap::from([(200_u16, 1_000_000_u64)]);

    r.catchup_burst_count = 1_001;
    assert_suspect!(&check_validity(&r, None, None), SuspectReason::CatchupBurst);

    r.catchup_burst_count = 1_000;
    assert_eq!(check_validity(&r, None, None), Validity::Valid);

    r.catchup_burst_count = u64::MAX;
    assert_suspect!(&check_validity(&r, None, None), SuspectReason::CatchupBurst);
}

// ---------------------------------------------------------------------------
// 21: Unstable spread.
// ---------------------------------------------------------------------------

#[test]
fn unstable_spread() {
    let r = base_result();
    assert_eq!(
        check_validity(&r, None, Some(101)),
        Validity::Unstable { iqr_permille: 101 }
    );
    assert_eq!(check_validity(&r, None, Some(100)), Validity::Valid);
}

// ---------------------------------------------------------------------------
// 22: evaluation order.
// ---------------------------------------------------------------------------

#[test]
fn evaluation_order_is_stable() {
    let mut r = base_result();
    // I3: total_requests == 0.
    r.total_requests = 0;
    r.status_counts.clear();
    // I4: bytes_received now also mismatches whatever ok_count I3 would
    // have computed from an empty map (0), so leaving it nonzero violates
    // I4 too.
    r.bytes_received = 1;
    // I13: an unattributed ceiling on a saturate cell.
    r.cell_def.rate = RateMode::Saturate;
    r.bottleneck = Bottleneck::Unknown;

    // I3 precedes I4 and I13 in the fixed evaluation order, so it must be
    // the one reported, even though all three are violated at once.
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I3);
}

// ---------------------------------------------------------------------------
// 23: determinism.
// ---------------------------------------------------------------------------

#[test]
fn guard_is_deterministic() {
    let r = base_result();
    let first = check_validity(&r, None, None);
    for _ in 0..100 {
        assert_eq!(check_validity(&r, None, None), first);
    }

    // Also over an Invalid input, not only the Valid one, so this proves
    // determinism of a real failure path too.
    let mut invalid = base_result();
    invalid.out_of_range = 1;
    let first_invalid = check_validity(&invalid, None, None);
    for _ in 0..100 {
        assert_eq!(check_validity(&invalid, None, None), first_invalid);
    }
}

// ---------------------------------------------------------------------------
// 24: non-finite floats.
// ---------------------------------------------------------------------------

#[test]
fn non_finite_floats_are_rejected() {
    for bad_rps in [f64::NAN, f64::INFINITY, -1.0_f64] {
        let mut r = base_result();
        r.rps = bad_rps;
        assert_suspect!(
            &check_validity(&r, None, None),
            SuspectReason::OriginCeiling,
        );
        // `rps as u64` on `f64::NAN` is 0 in Rust; if step 0 used a bare
        // cast instead of `is_finite`/`< 0.0` checks, a NaN rps would
        // silently become 0 and pass every downstream `>=`/`<=` comparison
        // that reads it. This test's own name is the record of what field
        // (`rps`) and which three hostile values (NaN, +inf, -1.0) are
        // exercised here.
    }

    let mut r = base_result();
    r.client_cpu_max_pct = f64::NAN;
    assert_invalid!(&check_validity(&r, None, None), InvariantId::I6);
}

/// `origin_ceiling_rps` failing the finiteness check, isolated from
/// `rps`'s own: `f64::min`'s IEEE semantics return the NON-NaN operand
/// ("ignoring NaN"), so a `NaN` fed through the `.min(ceiling)` clamp in
/// `rate_milli_up`/`rate_milli_down` is silently laundered into
/// `u64::MAX`-ish rather than surfacing as an error at that point, which is
/// exactly the kind of accidental-safety-net case worth pinning on its own:
/// a `NaN` (or `+inf`) `rps` laundered this way still gets caught by I2's
/// ordinary ratio check afterward, purely because rate is multiplied by
/// 1000 there against the ceiling's 700, so a maxed-out numerator can never
/// pass regardless of the denominator (proven directly, not assumed, by
/// `rps_nan_would_still_be_caught_by_i2_even_without_the_finite_check`
/// below). A `NaN` `origin_ceiling_rps` has no such downstream safety net:
/// nothing else in `check_validity` reads it, so if step 0's explicit
/// finiteness check on the CEILING side were ever removed, this exact case
/// would silently become `Valid`. Caught live: mutating the finiteness
/// check out of `rate_milli_up` did NOT make this test's `rps` sub-cases
/// fail (I2's ratio still rejected them), which is what motivated adding
/// this ceiling-side case and the explicit note above; mutating the
/// finiteness check out of `rate_milli_down` DOES make this test fail (see
/// this issue's implementation report).
#[test]
fn origin_ceiling_non_finite_is_rejected() {
    for bad_ceiling in [f64::NAN, f64::INFINITY, -1.0_f64] {
        let mut r = base_result();
        r.origin_ceiling_rps = bad_ceiling;
        assert_suspect!(
            &check_validity(&r, None, None),
            SuspectReason::OriginCeiling,
        );
    }
}

/// Proves the claim in `origin_ceiling_non_finite_is_rejected`'s doc
/// comment directly, independently of `rate_milli_up`'s own internals
/// (which are private to `src/guards.rs` and unreachable from this
/// integration test): for ANY `u64` ceiling milli-rate (the largest
/// possible outcome of a "laundered" `NaN`/`+inf` `rps` after `.min()`
/// clamps it to `u64::MAX`), `rps_milli * 1000 > 700 * ceiling_milli`
/// always holds, because `700 * ceiling_milli <= 700 * u64::MAX <
/// 1000 * u64::MAX` unconditionally. This is exact `u128` arithmetic, not a
/// sampled check.
#[test]
fn rps_nan_would_still_be_caught_by_i2_even_without_the_finite_check() {
    let laundered_rps_milli = u128::from(u64::MAX);
    let ceiling_milli = u128::from(u64::MAX);
    assert!(
        laundered_rps_milli * 1000 > 700_u128 * ceiling_milli,
        "a u64::MAX-laundered rps must exceed 70 percent of even a u64::MAX ceiling"
    );
}

// ---------------------------------------------------------------------------
// 25: zero origin ceiling.
// ---------------------------------------------------------------------------

#[test]
fn zero_origin_ceiling_is_suspect() {
    let mut r = base_result();
    r.origin_ceiling_rps = 0.0;
    assert!(r.rps > 0.0, "fixture precondition: rps must be nonzero");
    assert_suspect!(
        &check_validity(&r, None, None),
        SuspectReason::OriginCeiling,
    );
}

// ---------------------------------------------------------------------------
// Acceptance criteria not already covered by a numbered test above.
// ---------------------------------------------------------------------------

/// Design invariant 1: `check_validity(&r, None, None) == Valid ||
/// !r.publishable()`. Exercised on both a Valid and an Invalid fixture, and
/// separately on `provenance.publishable == false`, which is the half of
/// `publishable()` that `check_validity` alone can never see.
#[test]
fn i1_publishable_agrees_with_check_validity_and_provenance() {
    let valid = base_result();
    assert_eq!(check_validity(&valid, None, None), Validity::Valid);
    assert!(valid.publishable());

    let mut invalid = base_result();
    invalid.out_of_range = 1;
    assert_ne!(check_validity(&invalid, None, None), Validity::Valid);
    assert!(!invalid.publishable());
    // Design invariant 1, restated directly rather than only implied by the
    // two assertions above.
    assert!(check_validity(&invalid, None, None) == Validity::Valid || !invalid.publishable());

    // check_validity alone is Valid, but provenance says the run is not
    // publishable (a dirty worktree the harness ran with --allow-dirty):
    // publishable() must still be false, since it ANDs both.
    let mut unpublishable_provenance = base_result();
    unpublishable_provenance.provenance.origin.dirty = true;
    unpublishable_provenance.provenance.recompute_publishable();
    assert_eq!(
        check_validity(&unpublishable_provenance, None, None),
        Validity::Valid,
        "check_validity itself only reads provenance.sut, not provenance.origin, so this \
         mutation must not trip I10"
    );
    assert!(!unpublishable_provenance.provenance.publishable);
    assert!(!unpublishable_provenance.publishable());
}

/// Acceptance criterion: "Every `u64` field of the fixture set to
/// `u64::MAX` in turn leaves `check_validity` panic-free, in a debug build,
/// and never returns `Valid`." Checked here for every DIRECT `u64` field of
/// `RunResult`, with the fields the guard never reads (`rss_bytes`,
/// `pss_bytes`, `stall_backwards_count`) and the one field the guard checks
/// only for a LOWER bound (`warmup_samples_discarded`, which I11 requires
/// to be nonzero, not any particular size) called out explicitly rather
/// than silently asserted into the same bucket as the rest: `RunResult`'s
/// own field docs already say `sut_cores` and `stall_backwards_count` are
/// "Recorded, never guarded", and the same is true of `rss_bytes` and
/// `pss_bytes` (no I2 through I13 check reads either). A test that claimed
/// otherwise would be asserting something false about this issue's own
/// design, not proving anything about a hostile input.
/// A named field mutator: `(field name, fn that sets it to u64::MAX)`. A
/// type alias rather than an inline `&[(&str, fn(&mut RunResult))]` slice
/// type at each call site, per `clippy::type_complexity`.
type FieldMutator = (&'static str, fn(&mut RunResult));

#[test]
fn u64_max_fields_are_panic_free() {
    let guarded_and_rejected: &[FieldMutator] = &[
        ("bytes_received", |r| r.bytes_received = u64::MAX),
        ("total_requests", |r| r.total_requests = u64::MAX),
        ("catchup_burst_count", |r| r.catchup_burst_count = u64::MAX),
        ("out_of_range", |r| r.out_of_range = u64::MAX),
        ("stall_out_of_range", |r| r.stall_out_of_range = u64::MAX),
    ];
    for (name, mutate) in guarded_and_rejected {
        let mut r = base_result();
        mutate(&mut r);
        let v = check_validity(&r, None, None);
        assert_ne!(
            v,
            Validity::Valid,
            "field {name} at u64::MAX must not be Valid, got {v:?}"
        );
    }

    // Not guarded by any of I2 through I13 by design; u64::MAX must still
    // not panic, and (honestly) the run STAYS Valid, because nothing reads
    // these fields.
    let unguarded: &[FieldMutator] = &[
        ("rss_bytes", |r| r.rss_bytes = u64::MAX),
        ("pss_bytes", |r| r.pss_bytes = u64::MAX),
        ("stall_backwards_count", |r| {
            r.stall_backwards_count = u64::MAX;
        }),
    ];
    for (name, mutate) in unguarded {
        let mut r = base_result();
        mutate(&mut r);
        let v = check_validity(&r, None, None);
        assert_eq!(
            v,
            Validity::Valid,
            "field {name} is documented as never guarded; if this now fails, either the guard \
             gained a check on it (update this test and the field's doc comment) or this \
             assertion is wrong"
        );
    }

    // warmup_samples_discarded: I11 only requires NONZERO, not any bound,
    // so u64::MAX legitimately still passes I11. Documented here rather
    // than silently grouped with the truly unguarded fields above, because
    // this one IS read by a guard, just not upper-bounded by it.
    let mut r = base_result();
    r.warmup_samples_discarded = u64::MAX;
    assert_eq!(check_validity(&r, None, None), Validity::Valid);
}

// ---------------------------------------------------------------------------
// Round trip and purity acceptance criteria.
// ---------------------------------------------------------------------------

#[test]
fn round_trip_serde_for_a_saturate_cell() {
    let r = base_result();
    assert_eq!(r.cell_def.rate, RateMode::Saturate);
    assert_eq!(r.cpu_seconds_per_request, None);

    let json = serde_json::to_string(&r).expect("a valid RunResult must serialise");
    assert!(
        !json.contains("NaN"),
        "no f64 field may ever serialise as NaN: serde_json writes it as null and then \
         refuses to read it back"
    );
    let back: RunResult = serde_json::from_str(&json).expect("the serialised form must parse");
    assert_eq!(r, back);
}

/// A second, `Invalid` result also round-trips, including its `Detail`:
/// this is the field whose deserialisation is hand-written (see
/// `src/result.rs`) rather than derived, so it is the one most likely to
/// silently stop round-tripping if that impl regresses.
#[test]
fn round_trip_serde_for_an_invalid_result() {
    let mut r = base_result();
    r.out_of_range = 7;
    r.validity = check_validity(&r, None, None);
    assert!(matches!(
        r.validity,
        Validity::Invalid {
            violated: InvariantId::I7,
            ..
        }
    ));

    let json = serde_json::to_string(&r).expect("an Invalid RunResult must serialise");
    let back: RunResult = serde_json::from_str(&json).expect("the serialised form must parse");
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// Hostile-detail security property (issue #796 finding 1).
// ---------------------------------------------------------------------------

/// The PR body justifies hand-writing `Serialize`/`Deserialize` for
/// `crate::error::Detail` in `result.rs` (rather than deriving them in
/// `error.rs`) entirely on the claim that a hand-edited `validity.detail`
/// field in a committed result file is routed through `Detail::new`, so it
/// gets clipped and sanitised rather than reconstructing the private
/// `String` field directly from hostile bytes. `round_trip_serde_for_an_invalid_result`
/// does NOT check this claim: it round-trips a `Detail` the guard itself
/// already produced, which is already clipped and sanitised, so it passes
/// identically whether or not deserialisation is routed through
/// `Detail::new`. This test attacks the field directly, the way a pull
/// request author hand-editing a committed result file would: it starts from
/// a real `RunResult`, serialises it, then splices a HOSTILE raw string
/// straight into the `validity.detail` JSON field (never through
/// `Detail::new`, never through the Rust type system) before deserialising,
/// and `assert_eq!`s the deserialised bytes against `Detail::new` called on
/// that same raw input.
///
/// The payload is deliberately both over `MAX_DETAIL_BYTES` (256) long AND
/// carries control bytes (an ANSI screen-clear/cursor-home, a bare `\r`
/// followed by a forged log line, a bare `\n`, NUL) plus non-ASCII UTF-8, so
/// this exercises both of `Detail::new`'s jobs, clip first and then
/// sanitise, not just one.
#[test]
fn hostile_detail_field_cannot_bypass_detail_new() {
    let mut r = base_result();
    r.validity = Validity::Invalid {
        violated: InvariantId::I12,
        detail: Detail::new("placeholder, overwritten below via raw JSON"),
    };

    let mut value: serde_json::Value =
        serde_json::to_value(&r).expect("a RunResult must serialise to a JSON value");

    let raw = format!(
        "\x1b[2J\x1b[1;1H\rFORGED LOG LINE: root shell opened\n\0{}caf\u{e9} \u{4e2d}\u{6587}{}",
        "x".repeat(50),
        "y".repeat(400)
    );
    assert!(
        raw.len() > 256,
        "the fixture must exceed MAX_DETAIL_BYTES to exercise the clip, not just the sanitise"
    );

    value["validity"]["detail"] = serde_json::Value::String(raw.clone());
    let hostile_json = serde_json::to_string(&value).expect("the mutated Value must serialise");

    let back: RunResult = serde_json::from_str(&hostile_json)
        .expect("a hostile but well-formed validity.detail must still deserialise");

    let Validity::Invalid { detail, .. } = back.validity else {
        panic!("validity must still be Invalid {{ violated: I12, .. }} after the round trip");
    };

    let expected = Detail::new(&raw);
    assert_eq!(
        detail.as_str().as_bytes(),
        expected.as_str().as_bytes(),
        "a hand-edited validity.detail in a committed result file must be clipped and sanitised \
         byte for byte identically to Detail::new(&raw), not reconstructed straight from the \
         hostile string; see issue #796 finding 1"
    );
    // Restates the two properties `Detail::new` guarantees, pinned directly
    // on the DESERIALISED value rather than only on a value the guard itself
    // produced (which is already known-good and proves nothing about the
    // deserialisation path).
    assert!(detail.as_str().len() <= 256);
    assert!(detail.as_str().bytes().all(|b| (0x20..=0x7E).contains(&b)));
}

// ---------------------------------------------------------------------------
// Property test.
// ---------------------------------------------------------------------------

/// The naive, freshly-transcribed (never calling into `crate::guards`,
/// which is private to the library crate and unreachable from here anyway)
/// counterpart to each of I2 through I13. Deliberately re-derived from the
/// one-line invariant statements in the issue rather than copied from
/// `src/guards.rs`, so a coding mistake in the real implementation has a
/// real chance of NOT being repeated here.
mod naive {
    use irontraffic_bench::{Bottleneck, RateMode, RunResult};

    fn milli(v: f64, round_up: bool) -> Option<u64> {
        if !v.is_finite() || v < 0.0 {
            return None;
        }
        let scaled = v * 1000.0;
        let rounded = if round_up {
            scaled.ceil()
        } else {
            scaled.floor()
        };
        #[allow(
            clippy::cast_precision_loss,
            reason = "u64::MAX as f64 is a fixed ceiling used only to bound rounded before the \
                      cast just below; this is test-only code checking a generated case against \
                      an independent naive predicate, not the guard itself"
        )]
        let ceiling = u64::MAX as f64;
        if rounded > ceiling {
            return Some(u64::MAX);
        }
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "rounded is finite (scaled is finite because v.is_finite() was checked \
                      above, and .ceil()/.floor() preserve finiteness) and, by the branch just \
                      above, at most u64::MAX, so this cast neither truncates an out-of-range \
                      value nor loses a sign"
        )]
        Some(rounded as u64)
    }

    pub(super) fn i10(r: &RunResult) -> bool {
        r.provenance.sut.profile == "release" && !r.provenance.sut.dirty
    }

    pub(super) fn i11(r: &RunResult) -> bool {
        r.provenance.warmup_seconds == 0 || r.warmup_samples_discarded > 0
    }

    pub(super) fn i7(r: &RunResult) -> bool {
        r.out_of_range == 0 && r.stall_out_of_range == 0
    }

    pub(super) fn i3(r: &RunResult) -> bool {
        if r.status_counts.len() > 64 || r.total_requests == 0 {
            return false;
        }
        let total = u128::from(r.total_requests);
        let sum: u128 = r.status_counts.values().map(|&v| u128::from(v)).sum();
        if sum > total {
            return false;
        }
        let ok = u128::from(r.status_counts.get(&200).copied().unwrap_or(0));
        ok * 10_000 >= total * 9_999
    }

    pub(super) fn i4(r: &RunResult) -> bool {
        let ok = u128::from(r.status_counts.get(&200).copied().unwrap_or(0));
        u128::from(r.payload_bytes) * ok == u128::from(r.bytes_received)
    }

    pub(super) fn i5(r: &RunResult) -> bool {
        r.latency.samples >= r.deepest_percentile.required_samples() && r.probe_latency.samples != 0
    }

    pub(super) fn i13(r: &RunResult) -> bool {
        !matches!(r.cell_def.rate, RateMode::Saturate)
            || !matches!(r.bottleneck, Bottleneck::Unknown)
    }

    pub(super) fn i2(r: &RunResult) -> bool {
        let (Some(rps_m), Some(ceil_m)) = (milli(r.rps, true), milli(r.origin_ceiling_rps, false))
        else {
            return false;
        };
        u128::from(rps_m) * 1000 <= 700_u128 * u128::from(ceil_m)
    }

    pub(super) fn i6(r: &RunResult) -> bool {
        r.client_cpu_max_pct.is_finite()
            && (0.0..=1000.0).contains(&r.client_cpu_max_pct)
            && r.client_cpu_max_pct < 80.0
    }

    pub(super) fn i8(r: &RunResult) -> bool {
        u128::from(r.stall.p99_ns) * 20 <= u128::from(r.latency.p99_ns)
    }

    pub(super) fn catchup(r: &RunResult) -> bool {
        u128::from(r.catchup_burst_count) * 1000 <= u128::from(r.total_requests)
    }

    pub(super) fn i9(r: &RunResult) -> bool {
        u128::from(r.probe_latency.p99_ns) * 2 >= u128::from(r.latency.p99_ns)
    }

    pub(super) fn spread(iqr: Option<u32>) -> bool {
        iqr.is_none_or(|v| v <= 100)
    }

    pub(super) fn all_hold(r: &RunResult, spread_value: Option<u32>) -> bool {
        i10(r)
            && i11(r)
            && i7(r)
            && i3(r)
            && i4(r)
            && i5(r)
            && i13(r)
            && i2(r)
            && i6(r)
            && i8(r)
            && catchup(r)
            && i9(r)
            && spread(spread_value)
    }
}

/// Which single invariant (if any) a generated case is built to violate.
/// `0` means "violate nothing": the case must be `Valid`. `1..=13` each name
/// exactly one of I10, I11, I7, I3, I4, I5, I13, I2, I6, I8, the catch-up
/// ratio, I9, and the spread check, matching `check_validity`'s own fixed
/// evaluation order, so every one of the fourteen buckets below gets equal,
/// guaranteed selection probability (`prop::sample::select` over a 14
/// element slice) rather than depending on many independent ranges
/// happening to land on the passing side at once, which is the shape that
/// silently collapses a generator's reachable branch to near zero (see this
/// module's own reachability measurement in `reachability_is_well_spread`
/// below).
fn which_strategy() -> impl Strategy<Value = u8> {
    (0_u8..=13).boxed()
}

/// Builds one case: `base_result()` with exactly the field(s) for `which`
/// pushed `margin` past its threshold on the failing side (or, for
/// `which == 0`, a harmless perturbation of a field no invariant reads, so
/// distinct concrete Valid cases are exercised too, not one repeated
/// literal). Returns the mutated result and the `spread` argument to pass
/// to `check_validity`.
fn build_case(which: u8, margin: u64, harmless: u64) -> (RunResult, Option<u32>) {
    let mut r = base_result();
    let mut spread = None;
    let bump = margin.max(1);

    match which {
        0 => {
            // A harmless perturbation: no invariant reads rss_bytes.
            r.rss_bytes = harmless;
        }
        1 => r.provenance.sut.dirty = true, // I10
        2 => {
            // I11: warmup_seconds > 0 but nothing discarded.
            r.provenance.warmup_seconds = 1;
            r.warmup_samples_discarded = 0;
        }
        3 => r.out_of_range = bump, // I7
        4 => {
            // I3: push the 200 ratio just under 99.99 percent.
            let ok = 999_900_u64.saturating_sub(bump % 50 + 1);
            r.status_counts = BTreeMap::from([(200_u16, ok), (503_u16, 1_000_000 - ok)]);
        }
        5 => r.bytes_received = r.bytes_received.saturating_add(bump % 1000 + 1), // I4
        6 => r.latency.samples = 10_000_u64.saturating_sub(bump % 9_999 + 1),     // I5
        7 => {
            r.cell_def.rate = RateMode::Saturate;
            r.bottleneck = Bottleneck::Unknown; // I13
        }
        8 => {
            // bump % 1000 + 1 is always in 1..=1000, which fits a u32
            // exactly, so widening through u32 first (rather than casting
            // the u64 straight to f64) keeps this conversion lossless.
            let over = u32::try_from(bump % 1000 + 1).unwrap_or(1000);
            r.rps = 70_000.0 + f64::from(over); // I2
        }
        9 => {
            let tenths = u32::try_from(bump % 100).unwrap_or(0);
            r.client_cpu_max_pct = 80.0 + f64::from(tenths) * 0.1; // I6
        }
        10 => r.stall.p99_ns = 100_000 + bump % 1000 + 1, // I8 (latency.p99_ns stays 2_000_000)
        11 => r.catchup_burst_count = 1_000 + bump % 1000 + 1, // catch-up ratio
        12 => r.probe_latency.p99_ns = 1_000_000_u64.saturating_sub(bump % 999_999 + 1), // I9
        13 => spread = Some(101 + (bump % 1000) as u32),  // spread
        _ => unreachable!("which_strategy only produces 0..=13"),
    }

    (r, spread)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    /// `check_validity` returns `Valid` if and only if every one of I2
    /// through I13, the catch-up ratio and the spread check independently
    /// evaluate to true. `which == 0` builds a case designed to satisfy
    /// every naive predicate; `which` in `1..=13` builds a case designed to
    /// violate exactly one. Both sides of the `==` below are computed from
    /// the SAME concrete `RunResult`, one by the real guard and one by the
    /// from-scratch `naive` module above, so an implementation bug in
    /// EITHER (not just a mismatch with the design's prose) has a strong
    /// chance of producing a disagreement here.
    #[test]
    fn valid_implies_every_check_passes(which in which_strategy(), margin in 0_u64..1_000_000, harmless in 0_u64..u64::MAX) {
        let (r, spread) = build_case(which, margin, harmless);
        let real_is_valid = check_validity(&r, None, spread) == Validity::Valid;
        let naive_is_valid = naive::all_hold(&r, spread);
        prop_assert_eq!(
            real_is_valid,
            naive_is_valid,
            "which={} margin={}: check_validity said valid={}, the naive independent predicates \
             said valid={}",
            which,
            margin,
            real_is_valid,
            naive_is_valid
        );
        if which == 0 {
            prop_assert!(real_is_valid, "which==0 must build a fully-passing case");
        } else {
            prop_assert!(!real_is_valid, "which={which} must build a case violating exactly one check");
        }
    }
}

/// Measures how often the property test's generator above actually reaches
/// each of the 14 buckets, over the same number of cases the property test
/// itself runs, and asserts every bucket is reached a nontrivial number of
/// times. A generator that silently never draws `which == 0` (or any other
/// bucket) would make `valid_implies_every_check_passes` pass by never
/// exercising the branch it claims to cover, exactly the failure shape this
/// project has shipped before; this test measures that directly rather than
/// assuming a uniform `Strategy` behaves as documented.
#[test]
fn reachability_is_well_spread() {
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 2048,
        ..ProptestConfig::default()
    });
    let strategy = (which_strategy(), 0_u64..1_000_000_u64, 0_u64..u64::MAX);
    let mut counts = [0_u32; 14];
    let total = 2048;
    for _ in 0..total {
        let tree = strategy
            .new_tree(&mut runner)
            .expect("a bounded integer strategy must always produce a value tree");
        let (which, _margin, _harmless) = tree.current();
        counts[usize::from(which)] += 1;
    }

    for (which, &count) in counts.iter().enumerate() {
        let fraction = f64::from(count) / f64::from(total);
        assert!(
            count > 0,
            "which={which} was never drawn in {total} cases (fraction 0.0000): the property \
             test's coverage claim for this bucket is vacuous"
        );
        // Uniform selection over 14 buckets targets ~7.14 percent each;
        // anything above 2 percent (a healthy margin below uniform) is
        // strong evidence the selection is not silently skewed to near
        // zero for this bucket.
        assert!(
            fraction > 0.02,
            "which={which} reached only {count}/{total} cases (fraction {fraction:.4}), below \
             the 2 percent reachability floor"
        );
    }
}
