// SPDX-License-Identifier: MIT OR Apache-2.0
//! `LatencyRecorder`, the recorder every latency number in this project passes
//! through, plus `Percentiles`, the six-quantile answer it produces, and the
//! `.hgrm` text codec that makes a raw histogram a committed, re-checkable run
//! artifact.
//!
//! # Why `HdrHistogram` and not a `Vec<Duration>`
//!
//! Storing every sample and sorting it costs about 960 MB per minute at
//! 1,000,000 requests per second and adds an O(N log N) sort on top; the
//! measurement apparatus becomes the dominant cost. `HdrHistogram` records in
//! roughly 5 to 10 nanoseconds instead: a leading-zero count, a shift, an add
//! to compute the bucket index, and one increment into a `Vec<u64>`. See
//! `science/benchmarking.md`, "Constant factors and cache behaviour", for the
//! full argument.
//!
//! # Percentiles do not average
//!
//! Merging per-worker results by averaging their p99 values is wrong and can
//! be wrong by a large factor: `merge` exists, and [`Percentiles`]
//! deliberately has no arithmetic operators, precisely so nobody writes that
//! bug. `merged_p99_differs_from_averaged_p99` in `tests/hist.rs` is the
//! regression test.
//!
//! # Out of range is counted, never clamped
//!
//! `hdrhistogram`'s `record` returns `Err` when a value exceeds the configured
//! maximum. `hdrhistogram` also offers a clamp-on-overflow recording variant
//! (one character shorter than the branch this module writes instead), which
//! would silently fold every tail sample above 60 seconds into the top
//! bucket, converting a broken run into a plausible-looking one. This module
//! counts out-of-range samples in [`LatencyRecorder::out_of_range`] instead,
//! and never calls that clamping variant, for either a single value or a
//! count, anywhere.
//!
//! # What the tests below do and do NOT prove
//!
//! The unit tests pin exact values only where `HdrHistogram`'s own precision
//! guarantee (3 significant digits, fixed by [`SIGNIFICANT_DIGITS`]) makes an
//! exact literal correct (a single sample, or a value at the lowest
//! discernible unit); every other percentile assertion goes through a
//! documented tolerance helper rather than `assert_eq!`, because the
//! guarantee is a BOUND, not an equality that happens to hold. The property
//! tests cover merge order-independence and the monotone percentile chain
//! over generated distributions chosen to discriminate a wrong implementation
//! (heavy tail, all-identical, single sample, boundary values), never a
//! uniform or monotonic sequence, because `p50` of `1..=100` is satisfied by
//! many wrong implementations. Neither the unit tests nor the property tests
//! measure `record_ns`'s cost; that is `benches/harness.rs`'s job, because a
//! correctness assertion and a performance budget fail for different reasons
//! and belong in different suites.

use crate::error::BenchError;

/// The `.hgrm` header line, written verbatim by [`LatencyRecorder::write_hgrm`]
/// and recognised verbatim (and skipped, like a blank or `#`-prefixed line) by
/// [`LatencyRecorder::read_hgrm`]. A single constant so the writer and the
/// reader can never drift apart on what the header looks like.
const HGRM_HEADER_LINE: &[u8] = b"       Value     Percentile TotalCount 1/(1-Percentile)";

/// Smallest value the recorder can distinguish, in nanoseconds.
///
/// Fixed, not configurable: see the "Do NOT" list in issue #405. A
/// configurable range is how a run ends up unable to see its own tail, and two
/// runs at different precision are not comparable.
pub const LOW_NS: u64 = 1;
/// Largest recordable value, in nanoseconds. 60 seconds.
pub const HIGH_NS: u64 = 60_000_000_000;
/// Significant decimal digits of precision. Fixed at 3.
pub const SIGNIFICANT_DIGITS: u8 = 3;

/// Largest `.hgrm` input [`LatencyRecorder::read_hgrm`] will look at, in
/// bytes. 8 MiB.
///
/// Checked on the input slice's length before a single byte is split or
/// parsed, so an oversized input is rejected in O(1) rather than after the
/// cost of tokenising it. See `hgrm_rejects_oversized_input` in
/// `tests/hist.rs`, which pins the specific error reason (the byte bound, not
/// the per-line bound) that firing first must produce.
pub const MAX_HGRM_BYTES: usize = 8 * 1024 * 1024;
/// Largest number of lines [`LatencyRecorder::read_hgrm`] will look at.
pub const MAX_HGRM_LINES: usize = 1_000_000;
/// Largest single line [`LatencyRecorder::read_hgrm`] will look at, in bytes.
pub const MAX_HGRM_LINE_BYTES: usize = 512;
/// Largest cumulative sample count a `.hgrm` file may claim.
///
/// `10^12`, a thousand times the largest run this harness can produce (a 60
/// second run at 50,000,000 requests per second is `3 * 10^9` samples), and
/// small enough that `count_delta` summed over a million lines cannot
/// approach `u64::MAX`.
pub const MAX_HGRM_TOTAL_COUNT: u64 = 1_000_000_000_000;

/// The largest value [`LatencyRecorder::percentiles`] or `write_hgrm` can ever
/// REPORT for an in-range sample, and therefore the largest `Value`
/// [`LatencyRecorder::read_hgrm`] accepts: the highest value in the SAME
/// histogram bucket [`HIGH_NS`] itself falls into,
/// `hdrhistogram::Histogram::highest_equivalent(HIGH_NS)`.
///
/// `hdrhistogram` reports `max()` and `value_at_quantile()` as a bucket's
/// highest equivalent value, never the literal recorded value. At
/// [`SIGNIFICANT_DIGITS`] the bucket containing `HIGH_NS` is `2^25`
/// nanoseconds wide, so a sample recorded anywhere in the last ~4.7 ms of the
/// in-range band, including `HIGH_NS` itself, is reported back somewhere in
/// `HIGH_NS..=high_ns_ceiling()`, ABOVE the published `HIGH_NS`. That is not a
/// bug in the recorder to fix by lying about the number: it is what a
/// bucketed histogram's precision guarantee means, and [`LatencyRecorder`] is
/// constructed with this wider value as its internal `high` specifically so
/// `hdrhistogram` always has room to report an in-range sample back, however
/// its own bucket rounding lands.
///
/// This does NOT move `record_ns`'s or `record_n_ns`'s own `> HIGH_NS`
/// out-of-range guard: recording is still governed by the published `HIGH_NS`
/// exactly as documented, unchanged. This constant only widens how far a
/// QUERY (`percentiles`, `write_hgrm`, `read_hgrm`) can read back, never what
/// counts as in range to record.
///
/// `high` never moves a bucket boundary, only how many buckets get
/// allocated: `low` and `SIGNIFICANT_DIGITS` alone determine where `HIGH_NS`
/// falls, so this is computed against a minimal, disposable scratch histogram
/// (`high = 2 * LOW_NS`, the smallest value `new_with_bounds` accepts) rather
/// than a full-size one. Computed once and cached: the inputs are fixed
/// constants, so the answer can never change within a process.
///
/// # Errors
/// `BenchError::Parse` only if the crate rejects the fixed scratch
/// configuration (`LOW_NS`, `2 * LOW_NS`, `SIGNIFICANT_DIGITS`), which cannot
/// happen for these constants and is surfaced rather than unwrapped for the
/// same reason [`LatencyRecorder::new`] surfaces its own construction error:
/// the constants might change, and `Histogram::new`'s own contract is not
/// this module's to assume forever. Never panics.
pub fn high_ns_ceiling() -> Result<u64, BenchError> {
    static CEILING: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    if let Some(&cached) = CEILING.get() {
        return Ok(cached);
    }
    let scratch =
        hdrhistogram::Histogram::<u64>::new_with_bounds(LOW_NS, 2 * LOW_NS, SIGNIFICANT_DIGITS)
            .map_err(|e| BenchError::parse("hdrhistogram", &e.to_string()))?;
    let ceiling = scratch.highest_equivalent(HIGH_NS);
    // `get_or_init` here, not a plain `set`, so a race that computed the
    // same `ceiling` concurrently (harmless, since this is a pure function
    // of fixed constants) never hits `set`'s "already initialized" error
    // path: the racing thread's redundant computation is simply discarded in
    // favour of whichever thread's `get_or_init` closure actually ran first.
    Ok(*CEILING.get_or_init(|| ceiling))
}

/// Latency percentiles in nanoseconds.
///
/// Deliberately carries no mean and no standard deviation. An average latency
/// for a proxy is dominated by the fast path and blind to the tail, and a
/// field that exists will eventually be published. There is also no
/// arithmetic operator on this type: percentiles do not average, and an
/// operator invites exactly that bug. Merge the [`LatencyRecorder`]s first,
/// then call [`LatencyRecorder::percentiles`] once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Percentiles {
    /// 50th percentile.
    pub p50_ns: u64,
    /// 90th percentile.
    pub p90_ns: u64,
    /// 99th percentile.
    pub p99_ns: u64,
    /// 99.9th percentile.
    pub p999_ns: u64,
    /// 99.99th percentile.
    pub p9999_ns: u64,
    /// Largest recorded value.
    pub max_ns: u64,
    /// Number of samples behind these percentiles.
    pub samples: u64,
}

impl Percentiles {
    /// The minimum sample count required to publish the given quantile,
    /// `ceil(100 / (1 - q))`. `required_samples(0.9999)` is `1_000_000`.
    ///
    /// Boundary behaviour, so no caller has to guess: a `quantile` at or below
    /// `0.0`, or one that is not finite, returns `100`; a `quantile` at or
    /// above `1.0` returns `u64::MAX`, which no run can meet, so an
    /// out-of-range quantile can never be published.
    ///
    /// `1.0 - quantile` loses precision for a quantile close to `1.0`: the
    /// literal `0.9999` is not exactly representable in `f64`, and
    /// `100.0 / (1.0 - 0.9999)` computes to a value a few parts in `10^13`
    /// ABOVE the true integer `1_000_000`, which a bare `.ceil()` rounds up
    /// to `1_000_001`. The nudge below cancels floating point noise at that
    /// scale (many orders of magnitude smaller than any fractional part a
    /// genuinely non-round quantile produces) without changing the ceiling
    /// of a real fraction, which is what keeps `required_samples(0.99)`,
    /// `(0.999)` and `(0.9999)` at the clean round numbers the sample-count
    /// rule in `science/benchmarking.md` D8 names.
    #[must_use]
    pub fn required_samples(quantile: f64) -> u64 {
        // Relative nudge applied before the ceiling below. Far larger than
        // the observed floating point noise from the `1.0 - quantile`
        // subtraction (around `10^-13` relative, measured for `0.9999`), and
        // far smaller than any fractional part a real, non-round quantile
        // produces, so a genuine fraction still ceils upward.
        const EPS: f64 = 1e-9;

        if !quantile.is_finite() || quantile <= 0.0 {
            return 100;
        }
        if quantile >= 1.0 {
            return u64::MAX;
        }

        let raw = 100.0 / (1.0 - quantile);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "raw is finite and non-negative (100.0 divided by a positive \
                      quantity), and the branches above already handled quantile >= 1.0, \
                      so raw * (1.0 - EPS) cannot exceed roughly 10^17, well inside u64"
        )]
        #[expect(
            clippy::cast_sign_loss,
            reason = "raw is always positive: 100.0 divided by (1.0 - quantile), and \
                      quantile < 1.0 is guaranteed by the branches above"
        )]
        let nudged = (raw * (1.0 - EPS)).ceil() as u64;
        nudged
    }

    /// True when `samples` meets `required_samples(quantile)`.
    #[must_use]
    pub fn supports(&self, quantile: f64) -> bool {
        self.samples >= Self::required_samples(quantile)
    }
}

/// Records latencies into an `HdrHistogram` with fixed, non-negotiable
/// precision.
///
/// Construction allocates once, for the counts array: `(bucket_count + 1) *
/// sub_bucket_count / 2` slots, which at [`SIGNIFICANT_DIGITS`] = 3 is `27 *
/// 1024 = 27,648` `u64` slots, about 216 KiB. Recording never allocates and
/// never panics: it always resolves to one of a `saturating_add` into
/// `out_of_range` or a call into `hdrhistogram::Histogram::record_n`, whose
/// `Result` is always inspected, never unwrapped.
#[derive(Debug, Clone)]
pub struct LatencyRecorder {
    inner: hdrhistogram::Histogram<u64>,
    out_of_range: u64,
}

impl LatencyRecorder {
    /// Allocates the counts array for `LOW_NS..=HIGH_NS` at
    /// `SIGNIFICANT_DIGITS`.
    ///
    /// The underlying `hdrhistogram::Histogram` is constructed with
    /// [`high_ns_ceiling`], not the bare `HIGH_NS`, so the histogram always
    /// has room to report an in-range sample back however its own bucket
    /// rounding lands (see that constant's doc). This does not change the
    /// counts-array size: `high_ns_ceiling()` is the top of the SAME bucket
    /// `HIGH_NS` already falls into, so both values need identically 26
    /// buckets (measured; `high` only decides how many buckets get
    /// allocated, never where one starts).
    ///
    /// # Errors
    /// `BenchError::Parse` only if the crate rejects the fixed configuration,
    /// which cannot happen for the constants above and is surfaced rather
    /// than unwrapped: the constants might change, and `Histogram::new`'s own
    /// contract is not this module's to assume forever.
    pub fn new() -> Result<Self, BenchError> {
        let inner = hdrhistogram::Histogram::new_with_bounds(
            LOW_NS,
            high_ns_ceiling()?,
            SIGNIFICANT_DIGITS,
        )
        .map_err(|e| BenchError::parse("hdrhistogram", &e.to_string()))?;
        Ok(Self {
            inner,
            out_of_range: 0,
        })
    }

    /// Records one sample. Values above `HIGH_NS` increment `out_of_range` and
    /// are NOT clamped. Values below `LOW_NS` are floored to `LOW_NS`.
    pub fn record_ns(&mut self, value_ns: u64) {
        self.record_n_ns(value_ns, 1);
    }

    /// Records `count` occurrences of `value_ns`. Used by the `.hgrm` reader
    /// and by the load-generator adapters that reconstruct a recorder from
    /// reported percentiles.
    ///
    /// Applies the same rules as [`Self::record_ns`]: a `value_ns` above
    /// `HIGH_NS` adds `count` to `out_of_range` and records nothing, and a
    /// `value_ns` below `LOW_NS` is floored to `LOW_NS`. A `count` of 0 is a
    /// no-op, checked FIRST and before either of the other two rules, because
    /// `hdrhistogram::Histogram::record_n` updates its own min/max tracking
    /// even when called with `count == 0`, which would make "no-op" false for
    /// the one field (`max_ns`) a caller is most likely to check.
    ///
    /// Every counter update here is a `saturating_add`, and the underlying
    /// `record_n` is called through its `Result`, never unwrapped: a `count`
    /// near `u64::MAX` must not wrap a counter into a smaller value, because a
    /// wrapped `out_of_range` of 0 turns an invalid run into a publishable
    /// one.
    pub fn record_n_ns(&mut self, value_ns: u64, count: u64) {
        if count == 0 {
            return;
        }
        if value_ns > HIGH_NS {
            self.out_of_range = self.out_of_range.saturating_add(count);
            return;
        }
        let floored = value_ns.max(LOW_NS);
        // `record_n` returning `Err` here is defence in depth: the branch
        // above already makes `floored` provably `LOW_NS..=HIGH_NS`, which is
        // representable by construction. See issue #405's Design section,
        // "Recording", step 3.
        if self.inner.record_n(floored, count).is_err() {
            self.out_of_range = self.out_of_range.saturating_add(count);
        }
    }

    /// Adds every count from `other` into `self`, including `out_of_range`,
    /// which is a `saturating_add`.
    ///
    /// Both recorders share the fixed configuration, so this is exact: no
    /// re-bucketing and no added error. `out_of_range` counters add, which is
    /// what makes merge order-independence hold as an equality rather than an
    /// approximation.
    ///
    /// # Errors
    /// `BenchError::Parse` if the underlying add fails. Both recorders always
    /// share the same fixed low, high and significant-digit configuration (
    /// there is no other constructor), so the underlying counts arrays always
    /// match and this cannot happen; it is surfaced rather than unwrapped
    /// because that invariant is not `hdrhistogram`'s to promise forever.
    pub fn merge(&mut self, other: &Self) -> Result<(), BenchError> {
        self.inner
            .add(&other.inner)
            .map_err(|e| BenchError::parse("hdrhistogram", &e.to_string()))?;
        self.out_of_range = self.out_of_range.saturating_add(other.out_of_range);
        Ok(())
    }

    /// Answers the six published percentiles and the sample count in one
    /// pass.
    ///
    /// `max_ns`, or any of the five quantile fields, MAY exceed `HIGH_NS` by
    /// up to `high_ns_ceiling() - HIGH_NS` (currently 28,878,847 ns) for a
    /// distribution whose tail sits in the last ~4.7 ms of the in-range
    /// band: `hdrhistogram` always reports a bucket's highest equivalent
    /// value, never the literal recorded value, and `HIGH_NS`'s own bucket
    /// top is above `HIGH_NS`. This is not out-of-range data leaking through:
    /// `out_of_range()` still counts only samples that were actually above
    /// `HIGH_NS` when recorded. See [`high_ns_ceiling`].
    #[must_use]
    pub fn percentiles(&self) -> Percentiles {
        Percentiles {
            p50_ns: self.inner.value_at_quantile(0.50),
            p90_ns: self.inner.value_at_quantile(0.90),
            p99_ns: self.inner.value_at_quantile(0.99),
            p999_ns: self.inner.value_at_quantile(0.999),
            p9999_ns: self.inner.value_at_quantile(0.9999),
            max_ns: self.inner.max(),
            samples: self.inner.len(),
        }
    }

    /// Samples that exceeded `HIGH_NS` and were therefore not recorded.
    #[must_use]
    pub fn out_of_range(&self) -> u64 {
        self.out_of_range
    }

    /// Number of recorded samples, excluding out-of-range ones.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.inner.len()
    }

    /// True when nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Writes the `.hgrm` percentile text format.
    ///
    /// One header line, one blank line, then one line per recorded percentile
    /// step from `hdrhistogram`'s own quantile iterator at 5 ticks per half
    /// distance, then a three-line footer. Two runs of the same histogram
    /// produce byte-identical output, because every row and every footer
    /// field is written with a fixed format string over the histogram's own
    /// values.
    ///
    /// `Mean` and `StdDeviation` are written as the literal `0.000`, never
    /// computed: this text is a committed artifact in version control, and a
    /// real mean would eventually be quoted as the number that matters, which
    /// is exactly the average-latency mistake this whole module corrects.
    /// `hdrhistogram::Histogram::mean` and `::stdev` are never called
    /// anywhere in this crate.
    ///
    /// # Errors
    /// Propagates the writer's error.
    pub fn write_hgrm(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        // `HGRM_HEADER_LINE` is `&[u8]`, not `&str` (`read_hgrm` matches it
        // against a raw line straight out of `input.split(|&b| b == b'\n')`,
        // before any UTF-8 check), so this writes it as bytes rather than
        // through `writeln!`'s string formatting.
        out.write_all(HGRM_HEADER_LINE)?;
        out.write_all(b"\n")?;
        writeln!(out)?;

        let mut running_total: u64 = 0;
        for v in self.inner.iter_quantiles(5) {
            running_total += v.count_since_last_iteration();
            let inverse = if v.quantile_iterated_to() >= 1.0 {
                f64::INFINITY
            } else {
                1.0 / (1.0 - v.quantile_iterated_to())
            };
            #[expect(
                clippy::cast_precision_loss,
                reason = "value_iterated_to is a histogram bucket boundary in \
                          nanoseconds; the .hgrm format is a human readable text \
                          artifact, and hdrhistogram's own reference format renders \
                          this column as a float"
            )]
            writeln!(
                out,
                "{:12.3} {:14.12} {:>10} {:>14.2}",
                v.value_iterated_to() as f64,
                v.quantile_iterated_to(),
                running_total,
                inverse,
            )?;
        }

        writeln!(
            out,
            "#[Mean    ={:>14.3}, StdDeviation   ={:>14.3}]",
            0.0_f64, 0.0_f64
        )?;
        #[expect(
            clippy::cast_precision_loss,
            reason = "max() is a histogram bucket boundary in nanoseconds; the .hgrm \
                      format is a human readable text artifact and renders it as a float, \
                      matching the per-row Value column above"
        )]
        writeln!(
            out,
            "#[Max     ={:>14.3}, Total count    ={:>15}]",
            self.inner.max() as f64,
            self.inner.len()
        )?;
        // `SubBuckets` is read from the histogram rather than hardcoded, per
        // issue #405's Design section: `distinct_values()` is the counts
        // array length, `(bucket_count + 1) * sub_bucket_count / 2`, so
        // `sub_bucket_count = distinct_values() * 2 / (bucket_count + 1)`.
        // For this crate's fixed configuration that is always 2048, but the
        // arithmetic derives it rather than asserting the literal.
        let buckets = self.inner.buckets();
        #[expect(
            clippy::integer_division,
            reason = "distinct_values() is exactly (bucket_count + 1) * sub_bucket_count / 2 \
                      for every configuration this crate constructs, so this division is \
                      always exact, never a truncating approximation"
        )]
        let sub_buckets = self.inner.distinct_values() * 2 / (usize::from(buckets) + 1);
        writeln!(
            out,
            "#[Buckets ={buckets:>14}, SubBuckets     ={sub_buckets:>15}]"
        )?;
        Ok(())
    }

    /// Parses the `.hgrm` percentile text format.
    ///
    /// This is a LOSSY inverse: bucket boundaries survive, sub-bucket-
    /// precision detail does not, because each row is replayed as
    /// `count_delta` occurrences of one value rather than of the original
    /// individual samples. It exists so `bench/run.sh --verify` can recompute
    /// percentiles from a committed artifact, not so a histogram can round-
    /// trip byte-identically.
    ///
    /// This parses a committed file that any pull request author can edit. It
    /// makes no assumption that the harness wrote it, and is bounded on four
    /// separate axes: total input bytes ([`MAX_HGRM_BYTES`]), line count
    /// ([`MAX_HGRM_LINES`]), bytes per line ([`MAX_HGRM_LINE_BYTES`]), and the
    /// cumulative sample count the file claims ([`MAX_HGRM_TOTAL_COUNT`]). The
    /// byte bound is checked on the input slice's length before any split, so
    /// an oversized input costs one comparison regardless of its content.
    ///
    /// # Errors
    /// `BenchError::Parse` on a malformed line, a non-finite or negative
    /// `Value`, a `Value` above [`high_ns_ceiling`] (the top of `HIGH_NS`'s
    /// own bucket: a genuinely in-range sample's `Value` can legitimately
    /// read back anywhere up to there, never above it), a non-monotone
    /// percentile column, a decreasing total count, a total count above
    /// `MAX_HGRM_TOTAL_COUNT`, an input longer than `MAX_HGRM_BYTES`, a line
    /// longer than `MAX_HGRM_LINE_BYTES`, or more than `MAX_HGRM_LINES`
    /// lines. Returns without mutating any caller state either way: a fresh
    /// recorder is built internally and only returned on full success.
    pub fn read_hgrm(input: &[u8]) -> Result<Self, BenchError> {
        // Checked on the slice length, before any split, so an oversized
        // input costs one comparison. See MAX_HGRM_BYTES's own doc comment
        // and the `hgrm_rejects_oversized_input` test.
        if input.len() > MAX_HGRM_BYTES {
            return Err(BenchError::parse("hgrm", "input exceeds MAX_HGRM_BYTES"));
        }

        let mut recorder = Self::new()?;
        let mut lines: usize = 0;
        let mut prev_quantile: f64 = 0.0;
        let mut prev_total: u64 = 0;

        for raw_line in input.split(|&b| b == b'\n') {
            lines += 1;
            if lines > MAX_HGRM_LINES {
                return Err(BenchError::parse("hgrm", "input exceeds MAX_HGRM_LINES"));
            }

            // A lone `\r` is not a terminator; a TRAILING `\r` (from a CRLF
            // file) is stripped here, before any other check, so a CRLF file
            // parses identically to an LF one.
            let line = match raw_line.split_last() {
                Some((b'\r', rest)) => rest,
                _ => raw_line,
            };
            if line.len() > MAX_HGRM_LINE_BYTES {
                return Err(BenchError::parse(
                    "hgrm",
                    "line exceeds MAX_HGRM_LINE_BYTES",
                ));
            }

            let Some((value_ns, quantile, total)) = parse_hgrm_row(line)? else {
                continue;
            };

            if quantile < prev_quantile {
                return Err(BenchError::parse(
                    "hgrm",
                    "percentile column is not monotone",
                ));
            }
            prev_quantile = quantile;

            if total < prev_total {
                return Err(BenchError::parse("hgrm", "total count column decreased"));
            }
            // `total >= prev_total` is established immediately above, so this
            // subtraction cannot underflow.
            let count_delta = total - prev_total;
            prev_total = total;

            // `value_ns` is validated above (in `parse_hgrm_row`) against
            // `high_ns_ceiling()`, not the bare `HIGH_NS`, so it can be as
            // large as HIGH_NS's own bucket top: `write_hgrm`'s own output
            // for a genuinely in-range sample can legitimately contain such
            // a row (see `high_ns_ceiling`'s doc). `record_n_ns`'s
            // `> HIGH_NS` out-of-range guard is deliberately UNCHANGED
            // (issue #782 BLOCKING 1's owner decision), so passing that
            // value straight through would make record_n_ns itself divert
            // it to `out_of_range`, silently losing a sample `write_hgrm`
            // wrote as recorded. `.min(HIGH_NS)` avoids that without
            // touching record_n_ns: `HIGH_NS` and anything up to
            // `high_ns_ceiling()` are PROVABLY the same histogram bucket
            // (both within `[lowest_equivalent(HIGH_NS),
            // highest_equivalent(HIGH_NS)]`), so this floor lands in the
            // identical counts-array slot the raw value would have, and is
            // a strict no-op for the overwhelming majority of rows whose
            // `value_ns` is already `<= HIGH_NS`.
            recorder.record_n_ns(value_ns.min(HIGH_NS), count_delta);
        }

        Ok(recorder)
    }
}

/// Parses one `.hgrm` line, already stripped of its trailing `\r` and already
/// checked against [`MAX_HGRM_LINE_BYTES`], into `(value_ns, quantile,
/// total)`.
///
/// Returns `Ok(None)` for a blank line or a `#`-prefixed comment line, which
/// [`LatencyRecorder::read_hgrm`] skips. Everything checkable from this one
/// line alone lives here; the cross-line monotonicity checks on `quantile`
/// and `total` need state from the previous row and stay in the caller.
fn parse_hgrm_row(line: &[u8]) -> Result<Option<(u64, f64, u64)>, BenchError> {
    // The header line is neither blank nor `#`-prefixed, so without this
    // check it would fall through to the field parser below and fail on its
    // very first, literal "Value" column: `write_hgrm`'s own output could
    // then never round-trip through `read_hgrm`, which `hgrm_round_trip`
    // requires. Recognised by an EXACT match against the one fixed literal
    // `write_hgrm` always writes, never by "does the value column fail to
    // parse as a number", which would also swallow a genuinely malformed
    // value row and defeat `hgrm_rejects_malformed`'s "non-numeric value"
    // case.
    if line == HGRM_HEADER_LINE || line.is_empty() || line.first() == Some(&b'#') {
        return Ok(None);
    }

    let s = std::str::from_utf8(line)
        .map_err(|_| BenchError::parse("hgrm", "line is not valid utf-8"))?;

    let mut fields = s.split_ascii_whitespace();
    let value_field = fields
        .next()
        .ok_or_else(|| BenchError::parse("hgrm", "line has fewer than four fields"))?;
    let quantile_field = fields
        .next()
        .ok_or_else(|| BenchError::parse("hgrm", "line has fewer than four fields"))?;
    let total_field = fields
        .next()
        .ok_or_else(|| BenchError::parse("hgrm", "line has fewer than four fields"))?;
    // The fourth field, `1/(1-Percentile)`, is derived from the second and
    // carries no information of its own: confirmed present and never parsed,
    // per issue #405's Design section.
    fields
        .next()
        .ok_or_else(|| BenchError::parse("hgrm", "line has fewer than four fields"))?;

    let value: f64 = value_field
        .parse()
        .map_err(|_| BenchError::parse("hgrm", "value column is not a number"))?;
    // `is_finite()` FIRST. Every comparison against `NaN` is false, so an
    // ordering check alone (`value > high_ns_ceiling() as f64`) accepts
    // `NaN`, and `NaN as u64` is `0` in Rust: an ordering-only check would
    // silently inject a zero-nanosecond sample. See context fact 8 of issue
    // #405 and the `hgrm_rejects_non_finite_value` test.
    if !value.is_finite() || value < 0.0 {
        return Err(BenchError::parse(
            "hgrm",
            "value column is not finite or is negative",
        ));
    }
    // The bound is `high_ns_ceiling()`, NOT the bare `HIGH_NS`: `percentiles`
    // and `write_hgrm` can legitimately report a bucket's highest equivalent
    // value for a genuinely in-range sample, which can read up to
    // `high_ns_ceiling()` (see that constant's doc for why). A `Value`
    // strictly above `high_ns_ceiling()` cannot come from ANY value
    // `record_ns`/`record_n_ns` would ever have accepted as in range, so it
    // is still rejected, exactly as `hgrm_rejects_malformed`'s "value above
    // HIGH_NS" case (`70000000000.000`, comfortably above the ceiling too)
    // continues to prove.
    #[expect(
        clippy::cast_precision_loss,
        reason = "high_ns_ceiling() is close to 6*10^10, comfortably inside f64's 2^53 exact \
                  integer range, so this comparison is exact"
    )]
    if value > high_ns_ceiling()? as f64 {
        return Err(BenchError::parse(
            "hgrm",
            "value column exceeds the recorder's representable range",
        ));
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "value is finite, >= 0.0 and <= high_ns_ceiling() as f64 by the two checks \
                  immediately above, so the truncation this cast performs is exactly the \
                  documented lossy value_ns conversion, not an unbounded one"
    )]
    #[expect(
        clippy::cast_sign_loss,
        reason = "value >= 0.0 is checked immediately above"
    )]
    let value_ns = value as u64;

    let quantile: f64 = quantile_field
        .parse()
        .map_err(|_| BenchError::parse("hgrm", "percentile column is not a number"))?;
    if !quantile.is_finite() || !(0.0..=1.0).contains(&quantile) {
        return Err(BenchError::parse(
            "hgrm",
            "percentile column is not finite or is outside [0, 1]",
        ));
    }

    let total: u64 = total_field
        .parse()
        .map_err(|_| BenchError::parse("hgrm", "total count column is not an integer"))?;
    if total > MAX_HGRM_TOTAL_COUNT {
        return Err(BenchError::parse(
            "hgrm",
            "total count column exceeds MAX_HGRM_TOTAL_COUNT",
        ));
    }

    Ok(Some((value_ns, quantile, total)))
}
