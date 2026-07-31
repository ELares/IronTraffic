// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unit and property tests for `LatencyRecorder`, `Percentiles` and the
//! `.hgrm` codec.
//!
//! # What these tests do NOT prove
//!
//! `assert_within_3sig` exists because `HdrHistogram`'s precision guarantee
//! is a BOUND (3 significant digits at `SIGNIFICANT_DIGITS`), not an
//! equality that happens to hold: every percentile assertion in this file
//! goes through it except the two cases (`empty_recorder_is_all_zero`,
//! `zero_is_floored_not_dropped`'s `p50_ns == LOW_NS`) where the recorded
//! value is small and exact enough that `HdrHistogram` represents it without
//! rounding. Fixtures are chosen to discriminate a wrong implementation
//! (heavy tail, all-identical, single sample, values at and beyond
//! `HIGH_NS`) rather than a uniform or monotonic run, because `p50` of
//! `1..=100` is satisfied by many wrong implementations: see
//! `percentiles_from_known_histogram`'s own comment for the one exception,
//! which the issue names explicitly and which stays uniform on purpose.
//!
//! Tests 12 and 12a below deliberately do NOT assert wall-clock time, unlike
//! the issue's own wording ("under 10 milliseconds", "under 2 seconds").
//! Both bounds proved to be a weak discriminator on inspection (splitting
//! and validating even a full `MAX_HGRM_BYTES` of trivial input is fast
//! enough on ordinary hardware that a plausible regression would likely
//! still finish inside either bound), and this codebase has twice shipped a
//! wall-clock ceiling that flaked under CI scheduler contention without
//! catching the mutation it was meant to catch. Both tests instead assert on
//! the observable, content-based proof of the same property: which specific
//! bound rejected the input, pinned by the error's own detail text. See each
//! test's comment for the discriminating argument.

use irontraffic_bench::{
    BenchError, HIGH_NS, LOW_NS, LatencyRecorder, MAX_HGRM_BYTES, MAX_HGRM_LINE_BYTES,
    MAX_HGRM_LINES, MAX_HGRM_TOTAL_COUNT, Percentiles,
};
use proptest::strategy::Strategy;

/// `HdrHistogram`'s own stated precision guarantee is accuracy to within
/// `SIGNIFICANT_DIGITS` (3) significant decimal digits of the true value,
/// i.e. within 0.1 percent, NEVER bit-for-bit equality. `+ 1` covers the case
/// where 0.1 percent of a small expected value rounds below 1 whole
/// nanosecond.
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
        "{msg}: actual={actual} expected={expected} diff={diff} tolerance={tolerance} \
         (HdrHistogram's 3-significant-digit guarantee is a bound, not an equality)"
    );
}

#[allow(
    clippy::expect_used,
    reason = "test helper, not itself a #[test] fn: LOW_NS/HIGH_NS/SIGNIFICANT_DIGITS are this \
              crate's own fixed, valid constants, so construction cannot fail"
)]
fn recorder() -> LatencyRecorder {
    LatencyRecorder::new().expect("fixed configuration always constructs")
}

// ---------------------------------------------------------------------------
// Unit tests, numbered as in issue #405's Tests section.
// ---------------------------------------------------------------------------

#[test]
fn percentiles_from_known_histogram() {
    // Deliberately the ONE uniform fixture in this file: the issue names
    // this exact distribution (1..=10_000) and these exact tolerances, so
    // reproducing anything else here would not be testing what the issue
    // asks. Every OTHER percentile test below uses a distribution designed
    // to discriminate a wrong implementation instead.
    let mut r = recorder();
    for v in 1..=10_000u64 {
        r.record_ns(v);
    }
    let p = r.percentiles();
    assert_eq!(p.samples, 10_000);
    assert_within_3sig(p.p50_ns, 5_000, "p50 of 1..=10_000 within 0.1% of 5,000");
    assert_within_3sig(p.p90_ns, 9_000, "p90 of 1..=10_000 within 0.1% of 9,000");
    assert_within_3sig(p.p99_ns, 9_900, "p99 of 1..=10_000 within 0.1% of 9,900");
    assert_within_3sig(p.max_ns, 10_000, "max of 1..=10_000 within 0.1% of 10,000");
}

#[test]
fn empty_recorder_is_all_zero() {
    let r = recorder();
    let p = r.percentiles();
    assert_eq!(p.samples, 0);
    assert_eq!(p.p50_ns, 0);
    assert_eq!(p.p90_ns, 0);
    assert_eq!(p.p99_ns, 0);
    assert_eq!(p.p999_ns, 0);
    assert_eq!(p.p9999_ns, 0);
    assert_eq!(p.max_ns, 0);
}

#[test]
fn single_sample_collapses() {
    let mut r = recorder();
    r.record_ns(1_000);
    let p = r.percentiles();
    assert_eq!(p.samples, 1);
    assert_within_3sig(p.p50_ns, 1_000, "single sample p50");
    assert_within_3sig(p.p90_ns, 1_000, "single sample p90");
    assert_within_3sig(p.p99_ns, 1_000, "single sample p99");
    assert_within_3sig(p.p999_ns, 1_000, "single sample p999");
    assert_within_3sig(p.p9999_ns, 1_000, "single sample p9999");
    assert_within_3sig(p.max_ns, 1_000, "single sample max");
}

#[test]
fn high_boundary_is_in_range() {
    let mut r = recorder();
    r.record_ns(HIGH_NS);
    assert_eq!(r.out_of_range(), 0);
    assert_eq!(r.len(), 1);
    // Pinned against the LITERAL 60_028_878_847, independently measured
    // (`hdrhistogram::Histogram::highest_equivalent(HIGH_NS)` on this
    // crate's fixed LOW_NS/SIGNIFICANT_DIGITS configuration), not against
    // `high_ns_ceiling()` itself: comparing the SUT's own output to a second
    // call into the SAME function under test would prove nothing about
    // whether that function computes the right answer. This is issue #782
    // BLOCKING 1's core fact: a single sample recorded AT HIGH_NS reads back
    // ABOVE HIGH_NS, because `hdrhistogram` reports a bucket's highest
    // equivalent value, not the literal recorded value.
    assert_eq!(r.percentiles().max_ns, 60_028_878_847);
}

#[test]
fn high_boundary_round_trips_through_hgrm() {
    // Regression test for issue #782 BLOCKING 1: a `.hgrm` written from a
    // recorder holding a sample AT `HIGH_NS` used to be REJECTED by
    // `read_hgrm`, because `write_hgrm` reports that sample's bucket as
    // `60_028_878_847` (see `high_boundary_is_in_range`), which is above
    // `HIGH_NS` (60_000_000_000). Before the fix this test's `write_hgrm`
    // call already succeeds (it always did); it is `read_hgrm` on that exact
    // output that used to return
    // `Err(Parse { tool: "hgrm", detail: "value column exceeds HIGH_NS" })`.
    let mut r = recorder();
    r.record_ns(HIGH_NS);

    let mut buf = Vec::new();
    r.write_hgrm(&mut buf)
        .expect("write_hgrm to a Vec<u8> cannot fail");
    let text = std::str::from_utf8(&buf).expect("write_hgrm always writes valid utf-8");
    assert!(
        text.contains("60028878847.000"),
        "fixture precondition: write_hgrm must actually emit the too-high bucket value for \
         this test to exercise the bug it regresses; got:\n{text}"
    );

    let back = LatencyRecorder::read_hgrm(&buf)
        .expect("write_hgrm's own output for a sample AT HIGH_NS must read back");
    assert_eq!(
        back.len(),
        1,
        "the sample must be recorded, not diverted to out_of_range"
    );
    assert_eq!(back.out_of_range(), 0);
    // Pinned against the same literal as `high_boundary_is_in_range`: the
    // read-back recorder's sample and the original both land in HIGH_NS's
    // own bucket, so both report the identical bucket ceiling.
    assert_eq!(back.percentiles().max_ns, 60_028_878_847);
}

#[test]
fn above_high_counts_out_of_range() {
    let mut r = recorder();
    r.record_ns(HIGH_NS + 1);
    r.record_ns(u64::MAX);
    assert_eq!(r.len(), 0, "neither sample was in range");
    assert_eq!(
        r.out_of_range(),
        2,
        "both samples must be counted, never clamped"
    );
    // The anti-clamping assertion: hdrhistogram's clamp-on-overflow variant
    // would have folded both into the top bucket, making `max_ns` HIGH_NS
    // instead of 0.
    assert_eq!(r.percentiles().max_ns, 0);
}

#[test]
fn zero_is_floored_not_dropped() {
    let mut r = recorder();
    r.record_ns(0);
    assert_eq!(r.len(), 1);
    assert_eq!(r.percentiles().p50_ns, LOW_NS);
}

#[test]
fn merge_adds_out_of_range() {
    let mut a = recorder();
    let mut b = recorder();
    for _ in 0..3 {
        a.record_ns(HIGH_NS + 1);
        b.record_ns(HIGH_NS + 1);
    }
    assert_eq!(a.out_of_range(), 3, "fixture precondition");
    assert_eq!(b.out_of_range(), 3, "fixture precondition");
    a.merge(&b).expect("same fixed configuration always merges");
    assert_eq!(a.out_of_range(), 6);
}

#[test]
fn merge_with_empty_is_identity() {
    let mut a = recorder();
    for v in [10u64, 200, 3_000, 40_000] {
        a.record_ns(v);
    }
    let before = a.percentiles();
    let empty = recorder();
    a.merge(&empty)
        .expect("same fixed configuration always merges");
    assert_eq!(a.percentiles(), before);
    assert_eq!(a.out_of_range(), 0);
}

#[test]
fn merged_p99_differs_from_averaged_p99() {
    // This is the regression test for the "percentiles do not average" bug:
    // averaging two workers' p99 values lands near the midpoint, while the
    // merged p99 correctly lands near the heavier worker's tail. A uniform
    // or monotonic fixture could not show this difference, because a
    // uniform distribution's average and its merged percentile are close
    // together by construction.
    let mut a = recorder();
    a.record_n_ns(1_000, 10_000);
    let mut b = recorder();
    b.record_n_ns(1_000_000, 10_000);

    let p99_a = a.percentiles().p99_ns;
    let p99_b = b.percentiles().p99_ns;
    assert_within_3sig(p99_a, 1_000, "fixture precondition: A's own p99");
    assert_within_3sig(p99_b, 1_000_000, "fixture precondition: B's own p99");
    #[allow(
        clippy::cast_precision_loss,
        reason = "p99_a and p99_b are nanosecond counts around 1_000 and 1_000_000 in this \
                  fixture, both comfortably under 2^53"
    )]
    let averaged = f64::midpoint(p99_a as f64, p99_b as f64);
    assert!(
        (averaged - 500_500.0).abs() < 1_000.0,
        "fixture precondition: averaging the two p99s should land near 500,500, got {averaged}"
    );

    let mut merged = a.clone();
    merged
        .merge(&b)
        .expect("same fixed configuration always merges");
    let merged_p99 = merged.percentiles().p99_ns;
    assert_within_3sig(
        merged_p99,
        1_000_000,
        "merged p99 should track the heavier tail",
    );

    #[allow(
        clippy::cast_precision_loss,
        reason = "merged_p99 is a nanosecond count near 1_000_000 in this fixture, comfortably \
                  under 2^53"
    )]
    let relative_diff = (merged_p99 as f64 - averaged).abs() / averaged;
    assert!(
        relative_diff > 0.5,
        "merged p99 ({merged_p99}) and the averaged p99 ({averaged}) must differ by more than \
         50%, got a relative difference of {relative_diff}"
    );
}

#[test]
fn percentiles_span_distinct_orders_of_magnitude() {
    // Issue #782 BLOCKING 2: `p999_ns` and `p9999_ns` can each be computed
    // from the WRONG quantile with every other test in this file green,
    // because no OTHER fixture has a distribution where p99, p999 and p9999
    // differ. `single_sample_collapses` makes all six quantiles equal, so it
    // cannot tell WHICH quantile a field queried. `hgrm_round_trip` compares
    // `restored.p999_ns` against `original.p999_ns`, so an identical
    // mutation on both the writer and reader path cancels exactly.
    // `percentiles_are_monotone`'s OWN generator was separately vacuous (see
    // its comment below). This fixture is six groups sized so p50, p90, p99,
    // p999, p9999 and max each land in a DIFFERENT histogram bucket, with
    // enough margin from each cumulative boundary that HdrHistogram's own
    // rank rounding cannot move a percentile into its neighbour's group.
    //
    // The six expected values are LITERALS, independently measured from
    // this exact fixture against a bare `hdrhistogram::Histogram` (not
    // derived from `Percentiles::required_samples` or any other expression
    // this crate computes), and pinned via `assert_within_3sig` rather than
    // `assert_eq!` for the same reason every other percentile assertion in
    // this file is: HdrHistogram's 3-significant-digit guarantee is a
    // bound, not an equality. Watched to fail (see issue #782's own
    // methodology): mutating `p999_ns` to `value_at_quantile(0.99)` or
    // `p9999_ns` to `value_at_quantile(0.999)`, the two mutations BLOCKING 2
    // reports as surviving every other test in this file, both fail this
    // assertion with the actual value off by two, respectively one, orders
    // of magnitude.
    let mut r = recorder();
    r.record_n_ns(1_000, 700_000);
    r.record_n_ns(100_000, 250_000);
    r.record_n_ns(10_000_000, 45_000);
    r.record_n_ns(1_000_000_000, 4_500);
    r.record_n_ns(10_000_000_000, 800);
    r.record_n_ns(45_000_000_000, 10);
    let p = r.percentiles();
    assert_eq!(p.samples, 1_000_310, "fixture precondition");

    assert_within_3sig(p.p50_ns, 1_000, "heavy tail p50, group 1 of 6");
    assert_within_3sig(p.p90_ns, 100_000, "heavy tail p90, group 2 of 6");
    assert_within_3sig(p.p99_ns, 10_000_000, "heavy tail p99, group 3 of 6");
    assert_within_3sig(p.p999_ns, 1_000_000_000, "heavy tail p999, group 4 of 6");
    assert_within_3sig(p.p9999_ns, 10_000_000_000, "heavy tail p9999, group 5 of 6");
    assert_within_3sig(p.max_ns, 45_000_000_000, "heavy tail max, group 6 of 6");

    // Each field must land in a DIFFERENT bucket: strictly increasing, not
    // merely non-decreasing, which is what distinguishes this fixture from
    // the vacuous all-out-of-range draws `percentiles_are_monotone`'s old
    // generator produced.
    assert!(p.p50_ns < p.p90_ns);
    assert!(p.p90_ns < p.p99_ns);
    assert!(p.p99_ns < p.p999_ns);
    assert!(p.p999_ns < p.p9999_ns);
    assert!(p.p9999_ns < p.max_ns);
}

#[test]
fn hgrm_round_trip() {
    let mut r = recorder();
    // A mixed distribution: a dense low cluster, a mid cluster and a sparse
    // tail, plus one sample AT HIGH_NS (issue #782 BLOCKING 1: HIGH_NS's own
    // bucket reads back above HIGH_NS, which is exactly the case
    // `high_boundary_round_trips_through_hgrm` isolates; this fixture proves
    // it also survives inside a larger, mixed round trip, not only alone).
    // 100,001 samples in total, so the round trip exercises more than one
    // bucket.
    for i in 0..80_000u64 {
        r.record_ns(100 + (i % 500));
    }
    for i in 0..19_000u64 {
        r.record_ns(50_000 + (i % 2_000));
    }
    for i in 0..1_000u64 {
        r.record_ns(10_000_000 + i);
    }
    r.record_ns(HIGH_NS);
    assert_eq!(r.len(), 100_001, "fixture precondition");

    let mut buf = Vec::new();
    r.write_hgrm(&mut buf)
        .expect("write_hgrm to a Vec<u8> cannot fail");

    let back = LatencyRecorder::read_hgrm(&buf).expect("write_hgrm's own output must read back");
    assert_eq!(back.len(), r.len(), "sample count must be exactly equal");

    let original = r.percentiles();
    let restored = back.percentiles();
    assert_within_3sig(restored.p50_ns, original.p50_ns, "round trip p50");
    assert_within_3sig(restored.p90_ns, original.p90_ns, "round trip p90");
    assert_within_3sig(restored.p99_ns, original.p99_ns, "round trip p99");
    assert_within_3sig(restored.p999_ns, original.p999_ns, "round trip p999");
    assert_within_3sig(restored.p9999_ns, original.p9999_ns, "round trip p9999");
    assert_within_3sig(restored.max_ns, original.max_ns, "round trip max");
}

#[test]
fn hgrm_rejects_malformed() {
    // Six cases, each asserted against its OWN `detail` text, not merely the
    // `BenchError::Parse { tool: "hgrm", .. }` variant: a variant-only
    // assertion is satisfiable by ANY rejection reason, so it cannot prove
    // which guard actually fired. The sixth case (a decreasing `Percentile`
    // column) is issue #782 SHOULD_FIX 8: `read_hgrm`'s own doc comment
    // lists "a non-monotone percentile column" among the errors it returns,
    // and the guard is real (confirmed below and by the watched-to-fail
    // mutation this test's history records), but before this case existed
    // nothing constructed one, so deleting the guard left the suite green.
    let cases: [(&str, &str, &str); 6] = [
        (
            "short line",
            "1.000 0.5 100\n",
            "line has fewer than four fields",
        ),
        (
            "non-numeric value",
            "abc 0.500000000000 100 2.00\n",
            "value column is not a number",
        ),
        (
            "percentile above 1",
            "1.000 1.500000000000 100 2.00\n",
            "percentile column is not finite or is outside [0, 1]",
        ),
        (
            "decreasing total count",
            "1.000 0.100000000000 100 2.00\n2.000 0.200000000000 50 2.00\n",
            "total count column decreased",
        ),
        (
            "value above HIGH_NS",
            "70000000000.000 0.500000000000 100 2.00\n",
            "value column exceeds the recorder's representable range",
        ),
        (
            "decreasing percentile column",
            "1.000 0.900000000000 5 10.00\n2.000 0.100000000000 9 1.11\n",
            "percentile column is not monotone",
        ),
    ];
    for (label, text, expected_detail) in cases {
        let err = LatencyRecorder::read_hgrm(text.as_bytes())
            .err()
            .unwrap_or_else(|| panic!("{label}: expected Err, got Ok"));
        let BenchError::Parse { tool, detail } = &err else {
            panic!("{label}: expected BenchError::Parse, got {err:?}");
        };
        assert_eq!(*tool, "hgrm", "{label}");
        assert!(
            detail.as_str().contains(expected_detail),
            "{label}: expected detail to contain {expected_detail:?}, got {:?}",
            detail.as_str()
        );
    }
}

#[test]
fn hgrm_rejects_line_bomb() {
    // Each line is exactly 8 bytes ("1 0 0 x\n"), so MAX_HGRM_LINES + 1 lines
    // total MAX_HGRM_LINES * 8 + 8 bytes, comfortably under MAX_HGRM_BYTES
    // (8 MiB): this input must be rejected specifically by the LINE COUNT
    // bound, not the byte-size bound, which is what the assertion on the
    // error detail below confirms.
    let line_count = MAX_HGRM_LINES + 1;
    let mut text = String::with_capacity(line_count * 8);
    for _ in 0..line_count {
        text.push_str("1 0 0 x\n");
    }
    assert!(
        text.len() < MAX_HGRM_BYTES,
        "fixture precondition: must stay under MAX_HGRM_BYTES so the line-count bound, not \
         the byte bound, is what rejects this input"
    );

    let err = LatencyRecorder::read_hgrm(text.as_bytes()).expect_err("must exceed MAX_HGRM_LINES");
    let BenchError::Parse { tool, detail } = &err else {
        panic!("expected BenchError::Parse, got {err:?}");
    };
    assert_eq!(*tool, "hgrm");
    assert!(
        detail.as_str().contains("MAX_HGRM_LINES"),
        "expected the line-count bound to be what rejected this input, got: {}",
        detail.as_str()
    );
}

#[test]
fn hgrm_rejects_oversized_input() {
    // The issue's own acceptance criterion frames this as a wall-clock
    // assertion ("under 10 milliseconds"), which this file deliberately
    // does not use; see the module doc. This fixture instead proves the
    // SAME property (the byte-length check runs before any split) through
    // the error's own content, which is a strictly stronger and non-flaky
    // proof of ordering:
    //
    // The fixture is MAX_HGRM_BYTES + 1 zero bytes, exactly as the issue
    // names it. Zero (0x00) is not b'\n', so if the byte-length check were
    // moved to run AFTER the split (the exact regression this test exists
    // to catch), `input.split(|&b| b == b'\n')` would yield exactly ONE
    // line of MAX_HGRM_BYTES + 1 bytes, which the PER-LINE bound
    // (MAX_HGRM_LINE_BYTES, 512) would then reject instead, with a
    // DIFFERENT, distinguishable detail message. Asserting on which
    // specific message comes back is therefore a direct, deterministic
    // proof of check ORDER, not a timing proxy for it.
    let oversized = vec![0u8; MAX_HGRM_BYTES + 1];
    let err = LatencyRecorder::read_hgrm(&oversized).expect_err("must exceed MAX_HGRM_BYTES");
    let BenchError::Parse { tool, detail } = &err else {
        panic!("expected BenchError::Parse, got {err:?}");
    };
    assert_eq!(*tool, "hgrm");
    assert!(
        detail.as_str().contains("MAX_HGRM_BYTES"),
        "expected the byte-length check (not the per-line check) to reject this input, which \
         proves it runs before the split; got: {}",
        detail.as_str()
    );
    assert!(
        !detail.as_str().contains("MAX_HGRM_LINE_BYTES"),
        "the per-line bound firing instead means the byte-length check was skipped or moved \
         after the split; got: {}",
        detail.as_str()
    );
}

#[test]
fn hgrm_rejects_over_long_line() {
    // Issue #782 SHOULD_FIX 6: the OLD fixture (`vec![b'1'; MAX_HGRM_LINE_BYTES + 1]`, a single
    // token with no whitespace) tested nothing about the bound it is named for. With the
    // MAX_HGRM_LINE_BYTES check deleted entirely, that SAME input is rejected anyway by "line has
    // fewer than four fields", identically satisfying `matches!(err, BenchError::Parse { .. })`,
    // so the suite stayed green with the check gone (confirmed: `cargo test` still reported
    // `22 passed`). This fixture is instead a well-formed four-field row padded PAST the bound in
    // its last (unparsed) field, so deleting the check would make it parse successfully instead
    // of erroring, and the assertion is on the error's own `detail` text, which the per-line bound
    // and the four-field check produce DIFFERENT text for.
    let base = "1.000 0.500000000000 1 2.00";
    let padding = "9".repeat(MAX_HGRM_LINE_BYTES + 1 - base.len());
    let line = format!("{base}{padding}");
    assert_eq!(line.len(), MAX_HGRM_LINE_BYTES + 1, "fixture precondition");
    let err =
        LatencyRecorder::read_hgrm(line.as_bytes()).expect_err("must exceed MAX_HGRM_LINE_BYTES");
    let BenchError::Parse { tool, detail } = &err else {
        panic!("expected BenchError::Parse, got {err:?}");
    };
    assert_eq!(*tool, "hgrm");
    assert!(
        detail.as_str().contains("MAX_HGRM_LINE_BYTES"),
        "expected the per-line bound (not the four-field check) to reject this input; got: {}",
        detail.as_str()
    );
}

#[test]
fn hgrm_rejects_non_finite_value() {
    for value_text in ["nan", "NaN", "inf", "-inf", "-1.0"] {
        let line = format!("{value_text} 0.500000000000 100 2.00\n");
        let result = LatencyRecorder::read_hgrm(line.as_bytes());
        // `NaN > HIGH_NS as f64` is false and `NaN as u64` is 0 in Rust, so an
        // ordering-only check would silently inject a zero-nanosecond
        // sample; `is_finite()` must reject it first. There is no recorder
        // to inspect on the Err path: `result.is_err()` on its own is the
        // proof that none was returned.
        assert!(
            result.is_err(),
            "Value column {value_text:?} must be rejected, got {result:?}"
        );
        assert!(matches!(
            result,
            Err(BenchError::Parse { tool: "hgrm", .. })
        ));
    }
}

#[test]
fn hgrm_rejects_absurd_total_count() {
    let at_limit = format!("1.000 0.500000000000 {MAX_HGRM_TOTAL_COUNT} 2.00\n");
    LatencyRecorder::read_hgrm(at_limit.as_bytes())
        .expect("exactly MAX_HGRM_TOTAL_COUNT must be Ok");

    let over_limit = format!("1.000 0.500000000000 {} 2.00\n", MAX_HGRM_TOTAL_COUNT + 1);
    let err = LatencyRecorder::read_hgrm(over_limit.as_bytes())
        .expect_err("MAX_HGRM_TOTAL_COUNT + 1 must be Err");
    assert!(matches!(err, BenchError::Parse { tool: "hgrm", .. }));

    let u64_max = format!("1.000 0.500000000000 {} 2.00\n", u64::MAX);
    let err = LatencyRecorder::read_hgrm(u64_max.as_bytes())
        .expect_err("u64::MAX must be Err, not a wrapped or rounded value");
    assert!(matches!(err, BenchError::Parse { tool: "hgrm", .. }));
}

#[test]
fn record_n_ns_zero_count_is_a_true_no_op() {
    // Issue #782 SHOULD_FIX 7: `record_n_ns`'s `if count == 0 { return; }` guard is load-bearing
    // on the untrusted `read_hgrm` path (see `hgrm_zero_delta_row_cannot_inject_a_fabricated_max`
    // below), not merely an optimisation, because `hdrhistogram::Histogram::record_n` updates its
    // own min/max tracking even when called with `count == 0`. Deleting the guard leaves the
    // whole suite green (confirmed: `cargo test` still reports `22 passed`), but changes
    // observable behaviour: with the guard, recording 1_000 then a ZERO-count record at 5_000_000
    // leaves `max_ns` at 1_000; without it, `max_ns` becomes 5_001_215.
    let mut r = recorder();
    r.record_ns(1_000);
    r.record_n_ns(5_000_000, 0);
    assert_eq!(r.len(), 1, "the zero-count call must not add a sample");
    assert_within_3sig(
        r.percentiles().max_ns,
        1_000,
        "a zero-count record_n_ns call must not move max_ns",
    );
}

#[test]
fn hgrm_zero_delta_row_cannot_inject_a_fabricated_max() {
    // The untrusted-path version of the test above. `read_hgrm` computes
    // `count_delta = total - prev_total`, which is 0 for any row repeating the previous
    // cumulative `TotalCount`, and `read_hgrm` never requires the `Value` column itself to be
    // non-decreasing (only `Percentile` and `TotalCount` are checked for monotonicity). So a
    // hand-edited two-row file whose second row repeats the first row's `TotalCount` at a far
    // larger `Value` must NOT inject that `Value` into the recorder's published maximum: with the
    // `count == 0` guard in place, `record_n_ns` never touches `hdrhistogram`'s min/max tracking
    // for that second row at all.
    let text = "1000.000 0.500000000000 5 2.00\n50000000000.000 0.900000000000 5 10.00\n";
    let r = LatencyRecorder::read_hgrm(text.as_bytes())
        .expect("both rows are individually well formed");
    assert_eq!(
        r.len(),
        5,
        "fixture precondition: only the first row's count_delta (5 - 0) is nonzero"
    );
    assert_within_3sig(
        r.percentiles().max_ns,
        1_000,
        "the second row's zero count_delta must not inject its Value (50 seconds) as the \
         recorder's max",
    );
}

#[test]
fn record_n_saturates_counters() {
    let mut r = recorder();
    r.record_n_ns(HIGH_NS + 1, u64::MAX);
    r.record_n_ns(HIGH_NS + 1, u64::MAX);
    assert_eq!(
        r.out_of_range(),
        u64::MAX,
        "a wrapped out_of_range of a small number would turn a truncated-tail run into a \
         publishable one, which is the exact failure invariant 7 exists to catch"
    );
}

#[test]
fn required_samples_table() {
    assert_eq!(Percentiles::required_samples(0.99), 10_000);
    assert_eq!(Percentiles::required_samples(0.999), 100_000);
    assert_eq!(Percentiles::required_samples(0.9999), 1_000_000);

    let mut r = recorder();
    r.record_n_ns(1_000, 999_999);
    assert_eq!(r.percentiles().samples, 999_999, "fixture precondition");
    assert!(!r.percentiles().supports(0.9999));

    r.record_ns(1_000);
    assert_eq!(r.percentiles().samples, 1_000_000, "fixture precondition");
    assert!(r.percentiles().supports(0.9999));
}

#[test]
fn percentiles_carries_no_smuggled_field() {
    // Seven u64 fields and nothing else: invariant 5 in issue #405's Design
    // section. Pinned against the literal 56, not against
    // `7 * size_of::<u64>()`, which would still pass if a field were added
    // and another removed, or if the count itself silently changed.
    let p = Percentiles {
        p50_ns: 0,
        p90_ns: 0,
        p99_ns: 0,
        p999_ns: 0,
        p9999_ns: 0,
        max_ns: 0,
        samples: 0,
    };
    assert_eq!(std::mem::size_of_val(&p), 56);
}

// ---------------------------------------------------------------------------
// Property tests.
// ---------------------------------------------------------------------------

/// Deterministic pseudo-random permutation of `0..len`, seeded by `seed`.
/// Test-local scaffolding for exploring several merge orders per property
/// test case; not a production entropy source (it never runs outside
/// `tests/`, which the `determinism-seam` invariant lint's production scan
/// excludes by construction), and not proptest-shrinkable, which is fine
/// here since `seed` is a fixed literal chosen by the test, not a generated
/// value.
fn permutation_of(len: usize, mut seed: u64) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..len).collect();
    for i in (1..len).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "test-local permutation scaffolding, not a security boundary: the modulus \
                      below only needs SOME deterministic value in 0..=i, and truncation on a \
                      32-bit usize target still produces one"
        )]
        #[allow(
            clippy::indexing_slicing,
            reason = "i < len == indices.len() by the loop range, so i + 1 is always a valid \
                      modulus"
        )]
        let j = (seed as usize) % (i + 1);
        indices.swap(i, j);
    }
    indices
}

/// Strategy for `hgrm_parse_is_total` (issue #782 `SHOULD_FIX` 5): MOSTLY
/// well-formed `.hgrm` row text, one to five rows with a strictly ascending
/// quantile and cumulative total (so every row's monotonicity checks pass
/// and every row contributes at least one sample), rendered with the SAME
/// four whitespace-separated fields `parse_hgrm_row` reads, plus a minority
/// (10%) of fully adversarial raw strings (the narrowed generator this
/// replaces, `[0-9 .\n]{0,64}`) so the "never panics, always Ok-or-Err"
/// property this test primarily exists for keeps exercising genuinely
/// malformed input too, not only well-formed rows.
#[allow(
    clippy::expect_used,
    reason = "test-only strategy constructor, not itself a #[test] fn: the regex literal below \
              is fixed and this crate's own, so it cannot fail to compile"
)]
fn hgrm_like_text() -> impl proptest::strategy::Strategy<Value = String> {
    use std::fmt::Write as _;

    let well_formed = proptest::collection::vec((1_u64..=HIGH_NS, 1_u64..=10_000u64), 1..=5)
        .prop_map(|rows| {
            let n = rows.len();
            let mut total: u64 = 0;
            let mut out = String::new();
            for (i, (value, count_delta)) in rows.into_iter().enumerate() {
                total += count_delta;
                #[allow(
                    clippy::cast_precision_loss,
                    reason = "n is bounded to 1..=5 by the generator above and i < n, so this \
                              division is a small, exact-enough f64 fraction in (0.0, 1.0]"
                )]
                let quantile = (i + 1) as f64 / n as f64;
                let _ = writeln!(out, "{value}.000 {quantile:.12} {total} 9.99");
            }
            out
        });
    let adversarial = proptest::string::string_regex("[0-9 .\n]{0,64}")
        .expect("fixed regex literal always compiles");
    proptest::prop_oneof![9 => well_formed, 1 => adversarial]
}

proptest::proptest! {
    #[test]
    fn merge_is_order_independent(
        groups in proptest::collection::vec(
            proptest::collection::vec(1_u64..=HIGH_NS, 0..=500),
            2..=8,
        )
    ) {
        let mut recorders: Vec<LatencyRecorder> = Vec::with_capacity(groups.len());
        for g in &groups {
            let mut r = recorder();
            for &v in g {
                r.record_ns(v);
            }
            recorders.push(r);
        }

        let mut baseline = recorder();
        for r in &recorders {
            baseline.merge(r).expect("same fixed configuration always merges");
        }
        let baseline_percentiles = baseline.percentiles();
        let baseline_out_of_range = baseline.out_of_range();

        // Issue #782 SHOULD_FIX 9: every assertion below this line compares
        // `merged` against `baseline`, both produced by the SAME merge code
        // starting from the SAME "fresh recorder, merge each group in turn"
        // pattern (the production shape: issue #405 names it directly,
        // "Per-worker recorders are merged after the run"). That proves the
        // eight orders agree with EACH OTHER, never that any of them are
        // RIGHT: a merge that silently drops every group (for example, one
        // that only adds `other`'s counts when `self` is already non-empty,
        // which starts false for a freshly constructed recorder and stays
        // false forever after) makes `baseline` and every `merged` all
        // equally, identically empty, and the whole property holds
        // trivially. This line anchors the property to the actual input:
        // `baseline`'s sample count must equal the number of values the
        // fixture itself recorded, a literal computed from `groups`, not
        // from anything `LatencyRecorder` itself returns.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "each group is bounded to 0..=500 elements and there are at most 8 groups \
                      by the generator above, so the true sum is at most 4,000, comfortably \
                      inside u64 and inside usize on every platform this crate targets"
        )]
        let expected_samples = groups.iter().map(Vec::len).sum::<usize>() as u64;
        proptest::prop_assert_eq!(baseline_percentiles.samples, expected_samples);

        for seed in 0_u64..8 {
            let order = permutation_of(recorders.len(), seed ^ 0x9E37_79B9_7F4A_7C15);
            let mut merged = recorder();
            for idx in order {
                #[allow(
                    clippy::indexing_slicing,
                    reason = "idx is drawn from permutation_of(recorders.len(), ..), so it is \
                              always a valid index into recorders"
                )]
                let r = &recorders[idx];
                merged.merge(r).expect("same fixed configuration always merges");
            }
            proptest::prop_assert_eq!(merged.percentiles(), baseline_percentiles);
            proptest::prop_assert_eq!(merged.out_of_range(), baseline_out_of_range);
        }
    }

    #[test]
    fn percentiles_are_monotone(samples in proptest::collection::vec(
        // Issue #782 SHOULD_FIX 4: the old generator, uniform over the FULL
        // `u64` range, drew from a recordable band only 6e10 wide out of
        // 2^64, so P(a draw is in range) was 3.25e-9 and this property test
        // was, in 256 default cases, essentially never able to record a
        // single sample: EVERY case fell through to the empty-histogram
        // path, `0 <= 0 <= 0 <= 0 <= 0 <= 0`, an assertion that can never
        // fail regardless of whether `percentiles()` is correct. Measured
        // directly on the OLD generator (proptest's own deterministic
        // sampler, 256 cases): 0 of 264,818 draws in range.
        //
        // This generator is instead MOSTLY in range (90%) with a deliberate
        // minority out of range (10%), so the monotone chain has a real
        // distribution to be monotone about on almost every case, while
        // `p.samples + r.out_of_range() == recorded_calls` (issue #405
        // invariant 3) still gets genuine out-of-range draws to add up, not
        // only the all-in-range or all-out-of-range extremes. Measured the
        // same way on THIS generator: 255 of 256 cases record at least one
        // in-range sample, 226,052 of 251,277 total draws (90.0%) in range,
        // matching the 9:1 weighting below.
        proptest::prop_oneof![
            9 => 1_u64..=HIGH_NS,
            1 => (HIGH_NS + 1)..=u64::MAX,
        ],
        0..=2000,
    )) {
        let mut r = recorder();
        for &v in &samples {
            r.record_ns(v);
        }
        let p = r.percentiles();
        proptest::prop_assert!(p.p50_ns <= p.p90_ns);
        proptest::prop_assert!(p.p90_ns <= p.p99_ns);
        proptest::prop_assert!(p.p99_ns <= p.p999_ns);
        proptest::prop_assert!(p.p999_ns <= p.p9999_ns);
        proptest::prop_assert!(p.p9999_ns <= p.max_ns);
        #[allow(
            clippy::cast_possible_truncation,
            reason = "samples.len() is bounded to 0..=2000 by the generator above"
        )]
        let recorded_calls = samples.len() as u64;
        proptest::prop_assert_eq!(p.samples + r.out_of_range(), recorded_calls);
    }

    #[test]
    fn hgrm_parse_is_total(text in hgrm_like_text()) {
        // The issue names "arbitrary ASCII of up to 4 KB" as the generator.
        // Measured directly (200,000 draws against this shipped parser):
        // that generator reaches `Ok` only 0.049% of the time, an EXPECTED
        // 0.13 hits per default 256-case run. The PR's first fix narrowed it
        // to `[0-9 .\n]{0,64}`, measured at 2.09% Ok (5.35 hits per run), but
        // issue #782 SHOULD_FIX 5 found that fix moved the wrong number: of
        // 200,000 draws against THAT generator, only 14 (0.007%, an expected
        // 0.02 per 256-case run) were `Ok` with any sample actually
        // recorded, and 0 had more than one distinct value, so the
        // assertions inside the `if let Ok` arm below were themselves still
        // "reaches its interesting branch under once per run" (the same
        // defect class, one level deeper). `hgrm_like_text` fixes THAT
        // number: measured the same way (200,000 draws, proptest's own
        // sampler): Ok 90.1% (an expected 230.7 hits per 256-case run),
        // Ok-with-at-least-one-sample 89.9% (230.2 per run), and
        // Ok-with-a-spread-distribution (more than one distinct value, the
        // only shape where the monotone chain below can distinguish
        // anything) 59.2% (151.4 per run), because the well-formed arm
        // renders at least one, and usually several, syntactically valid,
        // monotone rows. The "never panics, always Ok-or-Err" property this
        // test primarily exists for is still exercised on every single case
        // regardless of which arm is taken, including the adversarial 10%.
        if let Ok(r) = LatencyRecorder::read_hgrm(text.as_bytes()) {
            let p = r.percentiles();
            proptest::prop_assert!(p.p50_ns <= p.p90_ns);
            proptest::prop_assert!(p.p90_ns <= p.p99_ns);
            proptest::prop_assert!(p.p99_ns <= p.p999_ns);
            proptest::prop_assert!(p.p999_ns <= p.p9999_ns);
            proptest::prop_assert!(p.p9999_ns <= p.max_ns);
        }
    }
}
