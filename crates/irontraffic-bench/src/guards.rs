// SPDX-License-Identifier: MIT OR Apache-2.0
//! `check_validity`: the thirteen invariants I2 through I13, evaluated in a
//! fixed order, that decide whether a `RunResult` may be published.
//!
//! I1 ("every published `RunResult` has `validity == Valid`") is the
//! conclusion this function's caller draws from its return value, not a
//! check this function itself performs; see [`crate::RunResult::publishable`].
//!
//! # Purity
//!
//! This module reads no clock, opens no file and spawns no process. That is
//! what lets `bench/run.sh --verify` re-check every invariant over a
//! committed results directory without running anything, so a hand-edited
//! result file cannot be merged. Grepping this file for the standard
//! library's wall clock and monotonic clock constructors, or for a file open
//! or a process spawn, returns nothing, which is one of this issue's
//! acceptance criteria, and stays true because nothing in this file ever
//! needs any of those four.
//!
//! # Hostile input
//!
//! A `RunResult` reaches [`check_validity`] by `serde_json::from_slice` over
//! a file any pull request author can edit, so every field is
//! attacker-chosen: `u64` counts at `u64::MAX`, `f64` fields at `NaN`, a
//! `status_counts` map with far more than the 64 entries a real run could
//! produce. Every product or sum computed here is widened to `u128` before
//! the arithmetic, never computed in the field's own narrower type, so a
//! hostile file cannot wrap a comparison into a false pass. Every `f64`
//! field this module reads is converted to a `u64` of thousandths exactly
//! once, at the top, through [`rate_milli_up`] or [`rate_milli_down`]; a
//! `NaN`, infinite, or negative float fails that conversion explicitly
//! rather than falling through `as u64`, which casts `f64::NAN` to `0` in
//! Rust and would otherwise silently pass every check that reads it.
//!
//! # Structure
//!
//! [`check_validity`] itself is a short, ordered ladder of calls into one
//! private function per step below, named `step_*` in the same order the
//! design's evaluation-order table lists them. Splitting the checks this way
//! (rather than one long function) is what keeps every individual check
//! short enough to read in one screen; the fixed ORDER, which is the part
//! that is actually load-bearing (see `evaluation_order_is_stable` in
//! `tests/guards.rs`), lives entirely in [`check_validity`]'s own body, not
//! scattered across the steps.

use crate::RateMode;
use crate::error::Detail;
use crate::result::{Bottleneck, InvariantId, RunResult, SuspectReason, Validity};

/// Parts per thousand of the median that the interquartile range may reach
/// before a cell is flagged `Unstable`. 100 permille is 10 percent.
pub const MAX_IQR_PERMILLE: u32 = 100;

/// Highest per-core client CPU utilisation a valid run may show.
pub const MAX_CLIENT_CPU_PCT: f64 = 80.0;

/// Fraction of the origin's own ceiling a valid run may reach, in permille.
pub const MAX_ORIGIN_UTILISATION_PERMILLE: u64 = 700;

/// A rate we measured. Round UP, so a rate just under the threshold cannot
/// round itself under it.
///
/// `None` when `v` is `NaN`, infinite or negative: a hand-edited or corrupt
/// result file can contain any of those, and a bare `as u64` cast of
/// `f64::NAN` is `0` in Rust, which would silently pass every check this
/// value feeds.
fn rate_milli_up(v: f64) -> Option<u64> {
    if !v.is_finite() || v < 0.0 {
        return None;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "u64::MAX as f64 is a fixed ceiling used only to clamp the multiplied rate \
                  before the final cast below; the precision lost by representing u64::MAX in \
                  f64 only ever makes that ceiling a few ULPs lower, which still comfortably \
                  exceeds any v * 1000.0 this function is ever called with in practice, and the \
                  final .min() and the possible-truncation expect below are what actually bound \
                  the result to u64 regardless"
    )]
    let ceiling = u64::MAX as f64;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "v is finite and non-negative by the guard above, and .min(ceiling) caps the \
                  product at u64::MAX before the cast, so this never truncates an out-of-range \
                  value or loses a sign"
    )]
    Some((v * 1000.0).ceil().min(ceiling) as u64)
}

/// A ceiling we are compared against. Round DOWN, so a generous ceiling
/// cannot round itself up.
///
/// `None` for the same three reasons as [`rate_milli_up`].
fn rate_milli_down(v: f64) -> Option<u64> {
    if !v.is_finite() || v < 0.0 {
        return None;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "see rate_milli_up's identical ceiling cast just above: the same fixed, \
                  slightly-lower-than-u64::MAX clamp value, used the same way"
    )]
    let ceiling = u64::MAX as f64;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "v is finite and non-negative by the guard above, and .min(ceiling) caps the \
                  product at u64::MAX before the cast, so this never truncates an out-of-range \
                  value or loses a sign"
    )]
    Some((v * 1000.0).floor().min(ceiling) as u64)
}

/// Builds an `Invalid` verdict, routing `detail` through [`Detail::new`] so
/// it is bounded and printable regardless of what the observed values
/// contained.
fn invalid(violated: InvariantId, detail: impl std::fmt::Display) -> Validity {
    Validity::Invalid {
        violated,
        detail: Detail::new(&detail.to_string()),
    }
}

/// Step 0: every `f64` this function reads, converted once, before any
/// comparison. `Err` short-circuits `check_validity` exactly as a named
/// invariant step would; `Ok` hands back `(rps_milli, ceiling_milli)` for
/// step 9 (I2) to use later, so the conversion never runs twice.
fn step_float_gate(result: &RunResult) -> Result<(u64, u64), Validity> {
    let Some(rps_milli) = rate_milli_up(result.rps) else {
        return Err(Validity::LoadgenSuspect {
            reason: SuspectReason::OriginCeiling,
        });
    };
    let Some(ceiling_milli) = rate_milli_down(result.origin_ceiling_rps) else {
        return Err(Validity::LoadgenSuspect {
            reason: SuspectReason::OriginCeiling,
        });
    };
    if !result.client_cpu_max_pct.is_finite()
        || !(0.0..=1000.0).contains(&result.client_cpu_max_pct)
    {
        return Err(invalid(
            InvariantId::I6,
            format!(
                "client_cpu_max_pct {} is not finite or is outside 0.0..=1000.0",
                result.client_cpu_max_pct
            ),
        ));
    }
    Ok((rps_milli, ceiling_milli))
}

/// Step 1: I10. The SUT binary's embedded build profile and worktree
/// cleanliness, checked on `provenance.sut`, matching the design's own "the
/// SUT binary's" phrasing.
fn step_i10(result: &RunResult) -> Option<Validity> {
    if result.provenance.sut.profile != "release" {
        return Some(invalid(
            InvariantId::I10,
            format!(
                "sut build profile is {:?}, not release",
                result.provenance.sut.profile
            ),
        ));
    }
    if result.provenance.sut.dirty {
        return Some(invalid(
            InvariantId::I10,
            "sut worktree was dirty at build time",
        ));
    }
    None
}

/// Step 2: I12. Shape first, unconditionally; the comparison against
/// `expected_command_line` second, only when it is `Some`. The shape check
/// comes first because the mismatch detail quotes the command line, so an
/// unchecked value must never reach that formatting step.
fn step_i12(result: &RunResult, expected_command_line: Option<&str>) -> Option<Validity> {
    if result.command_line.len() > crate::result::MAX_COMMAND_LINE
        || result
            .command_line
            .bytes()
            .any(|b| !(0x20..=0x7E).contains(&b))
    {
        return Some(invalid(
            InvariantId::I12,
            format!(
                "command_line is {} bytes; must be at most {} printable ascii bytes \
                 (0x20..=0x7E)",
                result.command_line.len(),
                crate::result::MAX_COMMAND_LINE
            ),
        ));
    }
    if let Some(expected) = expected_command_line
        && expected != result.command_line
    {
        return Some(invalid(
            InvariantId::I12,
            format!(
                "command_line for {} drifted from the registry: expected {:?}, got {:?}",
                result.cell.as_str(),
                expected,
                result.command_line
            ),
        ));
    }
    None
}

/// Step 3: I11. Warmup samples were merged into the published histogram
/// whenever there was a warmup to discard at all.
fn step_i11(result: &RunResult) -> Option<Validity> {
    if result.provenance.warmup_seconds > 0 && result.warmup_samples_discarded == 0 {
        return Some(invalid(
            InvariantId::I11,
            format!(
                "provenance.warmup_seconds is {} but warmup_samples_discarded is 0: warmup was \
                 never merged out of the published histogram",
                result.provenance.warmup_seconds
            ),
        ));
    }
    None
}

/// Step 4: I7. Both histograms: a lost sample in either one is a silently
/// truncated tail.
fn step_i7(result: &RunResult) -> Option<Validity> {
    if result.out_of_range == 0 && result.stall_out_of_range == 0 {
        return None;
    }
    let which = if result.out_of_range != 0 && result.stall_out_of_range != 0 {
        "the latency and stall histograms"
    } else if result.out_of_range != 0 {
        "the latency histogram"
    } else {
        "the stall histogram"
    };
    Some(invalid(
        InvariantId::I7,
        format!(
            "{which} lost samples above the 60 second maximum (out_of_range={}, \
             stall_out_of_range={})",
            result.out_of_range, result.stall_out_of_range
        ),
    ))
}

/// Step 5: I3, in the order the design fixes: the entry-count bound first
/// (so nothing below does unbounded work on a hostile map), then the
/// zero-request check (the ratio alone is vacuously true at 0 / 0), then the
/// sum-does-not-exceed-total check (in `u128`, so two `u64::MAX` buckets
/// cannot wrap into a false pass), then the ratio itself.
///
/// `Ok` hands back `(ok_count, total_requests)`, both already widened to
/// `u128`, for I4 and the catch-up burst check to reuse.
fn step_i3(result: &RunResult) -> Result<(u128, u128), Validity> {
    if result.status_counts.len() > 64 {
        return Err(invalid(
            InvariantId::I3,
            format!(
                "status_counts has {} distinct codes, more than the 64 the guard allows",
                result.status_counts.len()
            ),
        ));
    }
    if result.total_requests == 0 {
        return Err(invalid(
            InvariantId::I3,
            "total_requests is zero: the ratio check alone is vacuously true on an empty run",
        ));
    }
    let total_requests = u128::from(result.total_requests);
    let status_sum: u128 = result.status_counts.values().map(|&v| u128::from(v)).sum();
    if status_sum > total_requests {
        return Err(invalid(
            InvariantId::I3,
            format!(
                "status_counts sums to {status_sum}, which exceeds total_requests \
                 {total_requests}"
            ),
        ));
    }
    let ok_count = u128::from(result.status_counts.get(&200).copied().unwrap_or(0));
    if ok_count * 10_000 < total_requests * 9_999 {
        return Err(invalid(
            InvariantId::I3,
            format!(
                "only {ok_count} of {total_requests} requests were status 200, below the 99.99 \
                 percent floor"
            ),
        ));
    }
    Ok((ok_count, total_requests))
}

/// Step 6: I4.
fn step_i4(result: &RunResult, ok_count: u128) -> Option<Validity> {
    let expected_bytes = u128::from(result.payload_bytes) * ok_count;
    if expected_bytes == u128::from(result.bytes_received) {
        return None;
    }
    Some(invalid(
        InvariantId::I4,
        format!(
            "bytes_received {} does not equal payload_bytes {} * status_counts[200] {ok_count} \
             = {expected_bytes}",
            result.bytes_received, result.payload_bytes
        ),
    ))
}

/// Step 7: I5. The load client's histogram against the cell's declared
/// deepest percentile, then the dead-probe check: a probe that never
/// recorded a sample reports zeros, and zero is indistinguishable from an
/// extremely fast proxy in every `>=` comparison that reads it.
fn step_i5(result: &RunResult) -> Option<Validity> {
    let required = result.deepest_percentile.required_samples();
    if result.latency.samples < required {
        return Some(invalid(
            InvariantId::I5,
            format!(
                "latency.samples {} is below the {required} samples {:?} requires",
                result.latency.samples, result.deepest_percentile
            ),
        ));
    }
    if result.probe_latency.samples == 0 {
        return Some(invalid(
            InvariantId::I5,
            "probe_latency.samples is zero: the probe never recorded a sample",
        ));
    }
    None
}

/// Step 8: I13. Only a saturate cell makes a throughput claim; a fixed-rate
/// cell offers load well below saturation, so `Bottleneck::Unknown` is the
/// expected outcome there, not a fault.
fn step_i13(result: &RunResult) -> Option<Validity> {
    if matches!(result.cell_def.rate, RateMode::Saturate)
        && matches!(result.bottleneck, Bottleneck::Unknown)
    {
        return Some(invalid(
            InvariantId::I13,
            "bottleneck is unknown on a saturate cell: an unattributed ceiling makes the \
             throughput claim unpublishable",
        ));
    }
    None
}

/// Step 9: I2, using the milli-rate values [`step_float_gate`] already
/// validated.
fn step_i2(rps_milli: u64, ceiling_milli: u64) -> Option<Validity> {
    if u128::from(rps_milli) * 1000
        > u128::from(MAX_ORIGIN_UTILISATION_PERMILLE) * u128::from(ceiling_milli)
    {
        return Some(Validity::LoadgenSuspect {
            reason: SuspectReason::OriginCeiling,
        });
    }
    None
}

/// Step 10: I6, the threshold comparison. [`step_float_gate`] already
/// established `client_cpu_max_pct` is finite and in `0.0..=1000.0`.
fn step_i6_threshold(result: &RunResult) -> Option<Validity> {
    if result.client_cpu_max_pct >= MAX_CLIENT_CPU_PCT {
        return Some(invalid(
            InvariantId::I6,
            format!(
                "client_cpu_max_pct {} is not under {MAX_CLIENT_CPU_PCT}",
                result.client_cpu_max_pct
            ),
        ));
    }
    None
}

/// Step 11: I8.
fn step_i8(result: &RunResult) -> Option<Validity> {
    if u128::from(result.stall.p99_ns) * 20 > u128::from(result.latency.p99_ns) {
        return Some(Validity::LoadgenSuspect {
            reason: SuspectReason::StallRatio,
        });
    }
    None
}

/// Step 11a: the catch-up burst ratio. Not checked in the design sketch at
/// all; recording `catchup_burst_count` and consulting nothing is the same
/// fail-open shape as a boolean `valid` field written by the producer.
fn step_catchup_burst(result: &RunResult, total_requests: u128) -> Option<Validity> {
    if u128::from(result.catchup_burst_count) * 1000 > total_requests {
        return Some(Validity::LoadgenSuspect {
            reason: SuspectReason::CatchupBurst,
        });
    }
    None
}

/// Step 12: I9.
fn step_i9(result: &RunResult) -> Option<Validity> {
    if u128::from(result.probe_latency.p99_ns) * 2 < u128::from(result.latency.p99_ns) {
        return Some(Validity::LoadgenSuspect {
            reason: SuspectReason::ProbeDivergence,
        });
    }
    None
}

/// Step 13: spread, from the cell aggregate, when supplied.
fn step_spread(spread: Option<u32>) -> Option<Validity> {
    if let Some(iqr) = spread
        && iqr > MAX_IQR_PERMILLE
    {
        return Some(Validity::Unstable { iqr_permille: iqr });
    }
    None
}

/// Evaluates I2 through I13 in the fixed order and returns the first
/// failure.
///
/// Pure: no clock, no process, no file. This is what lets `--verify`
/// re-check a committed result without running anything.
///
/// `expected_command_line` is I12's cross-run input: `Some` when the cell
/// registry knows the canonical command line for this cell, `None` when it
/// does not yet. `spread` is the cell aggregate's interquartile range in
/// parts per thousand of the median per-run p99, or `None` for a single
/// run.
///
/// # Evaluation order
///
/// Structural faults (wrong build, wrong command line, warmup
/// contamination) are reported before measurement faults, because a run
/// with the wrong build has no measurement to discuss: float validity, I10,
/// I12, I11, I7, I3, I4, I5, I13 (saturate cells only), I2, I6, I8, the
/// catch-up burst ratio, I9, then the cell aggregate's spread. I2, I8, I9
/// and the catch-up burst ratio produce [`Validity::LoadgenSuspect`] rather
/// than [`Validity::Invalid`] because they say the number describes the
/// apparatus rather than the system under test, a different claim from
/// "this record is corrupt".
#[must_use]
pub fn check_validity(
    result: &RunResult,
    expected_command_line: Option<&str>,
    spread: Option<u32>,
) -> Validity {
    let (rps_milli, ceiling_milli) = match step_float_gate(result) {
        Ok(pair) => pair,
        Err(v) => return v,
    };
    if let Some(v) = step_i10(result) {
        return v;
    }
    if let Some(v) = step_i12(result, expected_command_line) {
        return v;
    }
    if let Some(v) = step_i11(result) {
        return v;
    }
    if let Some(v) = step_i7(result) {
        return v;
    }
    let (ok_count, total_requests) = match step_i3(result) {
        Ok(pair) => pair,
        Err(v) => return v,
    };
    if let Some(v) = step_i4(result, ok_count) {
        return v;
    }
    if let Some(v) = step_i5(result) {
        return v;
    }
    if let Some(v) = step_i13(result) {
        return v;
    }
    if let Some(v) = step_i2(rps_milli, ceiling_milli) {
        return v;
    }
    if let Some(v) = step_i6_threshold(result) {
        return v;
    }
    if let Some(v) = step_i8(result) {
        return v;
    }
    if let Some(v) = step_catchup_burst(result, total_requests) {
        return v;
    }
    if let Some(v) = step_i9(result) {
        return v;
    }
    if let Some(v) = step_spread(spread) {
        return v;
    }
    Validity::Valid
}
