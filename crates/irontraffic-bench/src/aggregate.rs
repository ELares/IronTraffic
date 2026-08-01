// SPDX-License-Identifier: MIT OR Apache-2.0
//! `CellAggregate`: five repetitions reduced to the one number the report
//! publishes, and the three nearest-rank statistics functions it is built
//! from.
//!
//! # Median, never mean
//!
//! The published headline is the MEDIAN of the per-run probe p99 values, not
//! their mean. A mean of percentiles is a value no run produced, and one
//! thermal event moves a mean while it barely moves a median. [`median`] and
//! [`median_f64`] both use the nearest-rank rule with the LOWER of the two
//! middle values on an even-length input, matching this crate's own
//! established convention: `median(&[1, 2, 3, 4])` is `2`, never `2.5` and
//! never `3`.
//!
//! # Two publishable numbers, not one
//!
//! [`CellAggregate::merged`] and [`CellAggregate::median_p99_ns`] answer
//! different questions and both are published, always, labelled. The merged
//! histogram is the full picture across every sample every repetition
//! recorded; the median of the five per-run p99 values is the headline
//! because it is robust to a single thermal event. Publishing one and
//! discarding the other would either hide the full picture or let one bad run
//! move the headline.

use crate::cell::CellId;
use crate::error::{BenchError, Detail};
use crate::guards::MAX_IQR_PERMILLE;
use crate::hist::{LatencyRecorder, Percentiles};
use crate::result::{InvariantId, RunResult, Validity};

/// Builds an `Invalid` verdict, routing `detail` through [`Detail::new`] so it
/// is bounded and printable regardless of what the observed values contained.
///
/// A small local copy of `crate::guards`'s own identically shaped private
/// helper: that function is not `pub(crate)` and `crate::guards` is not a
/// file this issue's own Files table lists as touched, so duplicating eight
/// lines here is cheaper and safer than widening that module's visibility for
/// a helper this small. `crate::loadgen::vegeta`'s own copy of `oha.rs`'s
/// duplicate-key detector is the established precedent for this exact
/// "small local copy, documented why" shape in this crate.
fn invalid(violated: InvariantId, detail: impl std::fmt::Display) -> Validity {
    Validity::Invalid {
        violated,
        detail: Detail::new(&detail.to_string()),
    }
}

/// Nearest-rank median of a NON-EMPTY ascending slice.
///
/// `sorted[len / 2]` for an odd length, `sorted[len / 2 - 1]` for an even one,
/// so an even-length input returns the LOWER of the two middle values, never
/// their mean: a mean of two measurements is a value no run produced.
/// `median(&[1, 2, 3, 4])` is `2`. Returns `0` for an empty slice rather than
/// panicking.
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "the nearest-rank index IS the floor of len / 2 by definition (this function's own \
              doc states the odd-length index as sorted[len / 2] verbatim); this is exact index \
              arithmetic, not a quantity where truncation loses precision"
)]
pub fn median(sorted: &[u64]) -> u64 {
    let len = sorted.len();
    if len == 0 {
        return 0;
    }
    let index = if len % 2 == 1 { len / 2 } else { len / 2 - 1 };
    sorted.get(index).copied().unwrap_or(0)
}

/// Nearest-rank quartiles of a NON-EMPTY ascending slice, as `(q1, q3)`.
///
/// `q1 = sorted[len / 4]` and `q3 = sorted[(3 * len / 4).min(len - 1)]`.
/// Plain indices with no lower-middle adjustment. `quartiles(&[10, 20, 30,
/// 40, 50])` is `(20, 40)`. Returns `(0, 0)` for an empty slice rather than
/// panicking.
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "q1 and q3 are nearest-rank indices (this function's own doc states them verbatim \
              as len / 4 and 3 * len / 4), exact index arithmetic where the floor IS the defined \
              answer, not a quantity where truncation loses precision"
)]
pub fn quartiles(sorted: &[u64]) -> (u64, u64) {
    let len = sorted.len();
    if len == 0 {
        return (0, 0);
    }
    let q1_index = len / 4;
    let q3_index = (3 * len / 4).min(len - 1);
    let q1 = sorted.get(q1_index).copied().unwrap_or(0);
    let q3 = sorted.get(q3_index).copied().unwrap_or(0);
    (q1, q3)
}

/// Nearest-rank median of a NON-EMPTY slice of finite `f64`, used for
/// `median_rps`. Sorts a copy with `f64::total_cmp` and applies the same
/// lower-middle rule as [`median`]. Returns `0.0` for an empty slice.
/// Non-finite values are an error at the call site, not something this
/// function repairs.
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "the nearest-rank index IS the floor of len / 2 by definition, matching median's \
              own identical reason; this is exact index arithmetic, not a quantity where \
              truncation loses precision"
)]
pub fn median_f64(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<f64> = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let len = sorted.len();
    let index = if len % 2 == 1 { len / 2 } else { len / 2 - 1 };
    sorted.get(index).copied().unwrap_or(0.0)
}

/// One cell's repetitions, reduced to what gets published.
///
/// Serialisable, because this is exactly what one `<cell-id>.json` file in a
/// results directory contains and what `--verify` parses back.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CellAggregate {
    /// Which cell.
    pub cell: CellId,
    /// Every repetition, in run order.
    pub runs: Vec<RunResult>,
    /// Median of the per-run probe p99. The headline number.
    pub median_p99_ns: u64,
    /// Smallest per-run probe p99.
    pub min_p99_ns: u64,
    /// Largest per-run probe p99.
    pub max_p99_ns: u64,
    /// Interquartile range of the per-run p99, in parts per thousand of the
    /// median.
    pub iqr_permille: u32,
    /// Percentiles of all repetitions' probe samples merged into one
    /// histogram. Published ALONGSIDE `median_p99_ns`, never instead of it:
    /// the two answer different questions.
    pub merged: Percentiles,
    /// Median of the per-run rps.
    pub median_rps: f64,
    /// The cell's verdict, which is the worst of the per-run verdicts plus
    /// the spread check.
    pub validity: Validity,
    /// True when at least one repetition failed and was retried. Recorded so
    /// a cell that only passes on retry is visible rather than clean.
    pub retried: bool,
}

impl CellAggregate {
    /// Reduces repetitions to a published aggregate.
    ///
    /// `probe_recorders` holds one probe latency recorder per repetition, in
    /// the same order as `runs`. They exist as a separate argument because
    /// `LatencyRecorder` is not serialisable and percentiles do not merge, so
    /// the merged histogram cannot be computed from `runs` alone.
    ///
    /// `retried` is always `false` on the returned value: this function has
    /// no way to know whether a repetition it was handed already replaced a
    /// failed one, because `RunResult` carries no such flag. `run_cell`,
    /// which runs the retry-at-most-once policy, sets the field on the value
    /// this returns before publishing it.
    ///
    /// # Errors
    /// `BenchError::Cell` when `runs` is empty, or when the runs are not all
    /// the same cell: neither names a value that varies per call, and
    /// `BenchError::Cell` carries only a `&'static str`.
    /// `BenchError::Parse` when `probe_recorders.len() != runs.len()`, naming
    /// both lengths: silently zipping the shorter of the two would publish a
    /// merged histogram missing a repetition, and the two lengths are runtime
    /// values `BenchError::Cell` cannot carry. Also `BenchError::Parse` when
    /// merging the recorders fails, which cannot happen for recorders built
    /// by this crate's own `LatencyRecorder::new` but is surfaced rather than
    /// unwrapped because that invariant is not `hdrhistogram`'s to promise
    /// forever.
    #[allow(
        clippy::too_many_lines,
        reason = "one cohesive, linearly ordered reduction (the Design section's own eight \
                  numbered steps); splitting it would scatter local state (the sorted p99 \
                  values, the merged recorder) that reads naturally kept in one place"
    )]
    pub fn from_runs(
        cell: CellId,
        runs: Vec<RunResult>,
        probe_recorders: &[LatencyRecorder],
    ) -> Result<Self, BenchError> {
        if runs.is_empty() {
            return Err(BenchError::Cell(
                "from_runs requires at least one repetition",
            ));
        }
        for run in &runs {
            if run.cell != cell {
                return Err(BenchError::Cell(
                    "every run passed to from_runs must measure the same cell",
                ));
            }
        }
        if probe_recorders.len() != runs.len() {
            return Err(BenchError::parse(
                "aggregate",
                &format!(
                    "probe_recorders has {} entries but runs has {}: every repetition needs \
                     exactly one recorder",
                    probe_recorders.len(),
                    runs.len()
                ),
            ));
        }

        // Step 1-4: the per-run probe p99 values, sorted, and their nearest-
        // rank statistics.
        let mut p99s: Vec<u64> = runs.iter().map(|run| run.probe_latency.p99_ns).collect();
        p99s.sort_unstable();
        let median_p99_ns = median(&p99s);
        let min_p99_ns = p99s.first().copied().unwrap_or(0);
        let max_p99_ns = p99s.last().copied().unwrap_or(0);
        let (q1, q3) = quartiles(&p99s);

        // Step 5: widened to u128 so a hand-edited result file carrying
        // u64::MAX cannot wrap (q3 - q1) * 1000 into a small, falsely stable
        // number. Zero when the median is zero, never a division by zero.
        let iqr_permille = if median_p99_ns == 0 {
            0
        } else {
            #[allow(
                clippy::integer_division,
                reason = "iqr_permille is defined as an integer parts-per-thousand ratio (this \
                          module's own doc states the formula verbatim); floor division is the \
                          specified answer, not a precision loss over a quantity that should be \
                          fractional"
            )]
            let scaled =
                u128::from(q3.saturating_sub(q1)).saturating_mul(1000) / u128::from(median_p99_ns);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "scaled is capped at u32::MAX by the .min() just above, so the cast \
                          below never truncates a value outside u32's range"
            )]
            let capped = scaled.min(u128::from(u32::MAX)) as u32; // it-allow: unchecked-cast reason: scaled is min()-capped at u32::MAX on this same line before the cast, so the cast can never truncate a value outside u32's range
            capped
        };

        // Step 6, first two clauses: a per-run Invalid or LoadgenSuspect
        // dominates the spread check entirely. The FIRST matching run's own
        // verdict is what the aggregate reports, in run order.
        let invalid_from_runs = runs
            .iter()
            .find(|run| matches!(run.validity, Validity::Invalid { .. }))
            .map(|run| run.validity.clone());
        let suspect_from_runs = runs
            .iter()
            .find(|run| matches!(run.validity, Validity::LoadgenSuspect { .. }))
            .map(|run| run.validity.clone());

        // Step 7: merge every probe recorder into one histogram. This is
        // published ALONGSIDE median_p99_ns, never instead of it: see the
        // module doc.
        let mut merged_recorder = LatencyRecorder::new()?;
        for recorder in probe_recorders {
            merged_recorder.merge(recorder)?;
        }

        // Step 7a: the merge is what the sample-count and lost-tail rules
        // actually check, because the published percentile comes from the
        // probe, not from the load client's own histogram (that one is what
        // check_validity's I5 step already checks, at the single-run level).
        // `runs` is non-empty (checked above), so `.first()` is always Some.
        let deepest = runs
            .first()
            .map_or(crate::result::DeepestPercentile::P99, |run| {
                run.deepest_percentile
            });
        let required = deepest.required_samples();
        let step_7a = if merged_recorder.len() < required {
            Some(invalid(
                InvariantId::I5,
                format!(
                    "merged probe recorder has {} samples, below the {required} \
                     {deepest:?} requires",
                    merged_recorder.len()
                ),
            ))
        } else if merged_recorder.out_of_range() != 0 {
            Some(invalid(
                InvariantId::I7,
                format!(
                    "merged probe recorder lost {} samples above the histogram maximum",
                    merged_recorder.out_of_range()
                ),
            ))
        } else {
            None
        };

        // Step 6, in full: the fixed cascade order.
        let validity = if let Some(v) = invalid_from_runs {
            v
        } else if let Some(v) = suspect_from_runs {
            v
        } else if let Some(v) = step_7a {
            v
        } else if iqr_permille > MAX_IQR_PERMILLE {
            Validity::Unstable { iqr_permille }
        } else {
            Validity::Valid
        };

        let merged = merged_recorder.percentiles();

        // Step 8: the same nearest-rank rule over the per-run rps values.
        let rps_values: Vec<f64> = runs.iter().map(|run| run.rps).collect();
        let median_rps = median_f64(&rps_values);

        Ok(Self {
            cell,
            runs,
            median_p99_ns,
            min_p99_ns,
            max_p99_ns,
            iqr_permille,
            merged,
            median_rps,
            validity,
            retried: false,
        })
    }
}
