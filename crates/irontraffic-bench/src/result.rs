// SPDX-License-Identifier: MIT OR Apache-2.0
//! `RunResult`, the complete record of one benchmark cell run, and the closed
//! `Validity` verdict [`crate::guards::check_validity`] computes from it.
//!
//! A result that fails any of the thirteen invariants I1 through I13 (see
//! `crate::guards`) is not a slow result, it is not a result: the harness
//! records it, refuses to publish it, and names the invariant it violated.
//! This module defines the vocabulary that verdict is expressed in; the
//! guard that computes it lives in `crate::guards`.

use std::collections::BTreeMap;

use crate::error::Detail;
use crate::{BenchCell, CellId, Percentiles, Provenance};

/// Which invariant a result violated.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum InvariantId {
    /// Every published `RunResult` has `validity == Valid`.
    I1,
    /// `rps <= 0.7 * origin_ceiling_rps`: the origin, not the proxy, was the
    /// limit.
    I2,
    /// `status_counts[&200] >= (total_requests as f64 * 0.9999) as u64`: an
    /// accidental short circuit answered quickly.
    I3,
    /// `bytes_received == payload_bytes as u64 * status_counts[&200]`: an
    /// unintended cache hit, a truncated body, or a wrong payload size.
    I4,
    /// `latency.samples >= 100 / (1 - p)` for the deepest published
    /// percentile: a percentile computed from too few samples.
    I5,
    /// `client_cpu_max_pct < 80.0`: the load generator was the bottleneck.
    I6,
    /// `out_of_range == 0` AND `stall_out_of_range == 0`: a silently
    /// truncated tail, in either histogram.
    I7,
    /// `stall.p99_ns <= latency.p99_ns / 20`: the client materially
    /// contributed to the measurement.
    I8,
    /// `probe_latency.p99_ns * 2 >= latency.p99_ns`: the load client's own
    /// scheduling jitter dominates.
    I9,
    /// Build profile is `release`, features equal the declared list, and
    /// the worktree was clean: the wrong build was measured.
    ///
    /// The "features equal the declared list" clause is NOT implemented by
    /// [`crate::guards::step_i10`], which checks only
    /// `provenance.sut.profile == "release"` and `!provenance.sut.dirty`.
    /// No declared list exists anywhere in scope for this issue to compare
    /// against: neither issue #408's own Design, Tests or Public API
    /// sections (`check_validity`'s signature is given verbatim with no
    /// feature-list parameter analogous to I12's `expected_command_line`)
    /// nor `science/benchmarking.md`'s failure-mode-19 mitigation (which
    /// names profile, feature list and dirty as failure CAUSES, then
    /// describes only refusing a `dirty` or non-`release` build as the
    /// actual mitigation) nor `Provenance::recompute_publishable`'s six
    /// disqualifying conditions define what a "declared list" is or thread
    /// one in. A future issue that adds a declared feature list and threads
    /// it into `check_validity` must extend `step_i10` and this doc
    /// together; until then, do not read this variant's doc, or
    /// `step_i10`'s narrower scope, as claiming the third clause is
    /// checked.
    I10,
    /// Warmup samples were never merged into the published histogram: a
    /// warmup measurement published as steady state.
    I11,
    /// The same `CellId` always yields the same `command_line`, byte for
    /// byte: an undocumented parameter change between runs.
    I12,
    /// `bottleneck != Unknown` for any cell that makes a throughput claim:
    /// taking credit for a limit that was never identified.
    I13,
}

/// Why a run is suspected of measuring its own load generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspectReason {
    /// Measured rps exceeded 70 percent of the origin's own ceiling.
    OriginCeiling,
    /// The client's stall p99 was more than 5 percent of the latency p99.
    StallRatio,
    /// The load client's p99 was more than twice the probe client's p99.
    ProbeDivergence,
    /// The null-proxy control showed the client near its own ceiling.
    NullProxyControl,
    /// Doubling the client processes moved measured rps by more than 5
    /// percent.
    ClientScaling,
    /// The client repaid a schedule debt as capped bursts often enough that
    /// the spike it produced is its own, not the system under test's.
    CatchupBurst,
}

/// Whether a result may be published, and why not when it may not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Validity {
    /// Every invariant held.
    Valid,
    /// The number describes the measurement apparatus, not the system under
    /// test.
    ///
    /// Carries only `reason`, never a `Detail`, even though issue #408's own
    /// step-0 design prose and its tests 24 and 25 describe a failed float
    /// conversion as yielding "a detail naming the field and the value", "a
    /// detail naming `rps`", and (for a zero origin ceiling) "a detail
    /// saying the ceiling was never measured". That acceptance requirement
    /// is unsatisfiable as worded: the issue's own Public API gives this
    /// variant verbatim as `LoadgenSuspect { reason: SuspectReason }`, with
    /// no detail field, and its Do NOT list forbids collapsing
    /// `LoadgenSuspect` into `Invalid`, the only other variant that carries
    /// a `Detail`. The tests that reference a detail here
    /// (`non_finite_floats_are_rejected`, `origin_ceiling_non_finite_is_rejected`,
    /// `zero_origin_ceiling_is_suspect`) assert only `reason`, which is
    /// everything this variant can carry.
    LoadgenSuspect {
        /// Which apparatus check failed.
        reason: SuspectReason,
    },
    /// The cell's repetitions disagreed too much to be a headline number.
    Unstable {
        /// Interquartile range of the per-run p99, in parts per thousand of
        /// the median.
        iqr_permille: u32,
    },
    /// A structural or measurement invariant failed.
    Invalid {
        /// The first invariant that failed, in the fixed evaluation order.
        violated: InvariantId,
        /// The observed values, for a human reading the file. A `Detail`,
        /// not a `String`: it is rendered from fields of a file a stranger
        /// may have edited (I12's detail quotes a `command_line`), it is
        /// printed to a terminal, and it is written back into a committed
        /// artifact.
        detail: Detail,
    },
}

/// Where the ceiling was, established by kernel and process evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bottleneck {
    /// The system under test's own CPU.
    Cpu,
    /// The network interface.
    Nic,
    /// Kernel softirq processing.
    Softirq,
    /// The origin server, not the proxy.
    Origin,
    /// The load-generating client.
    Client,
    /// No component was identified as the limit.
    Unknown,
}

/// The deepest percentile this cell intends to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeepestPercentile {
    /// 99th percentile. Requires 10,000 samples.
    P99,
    /// 99.9th percentile. Requires 100,000 samples.
    P999,
    /// 99.99th percentile. Requires 1,000,000 samples.
    P9999,
}

impl DeepestPercentile {
    /// `100 / (1 - p)`: 10,000, 100,000, 1,000,000.
    #[must_use]
    pub fn required_samples(self) -> u64 {
        match self {
            Self::P99 => 10_000,
            Self::P999 => 100_000,
            Self::P9999 => 1_000_000,
        }
    }
}

/// Longest `command_line` a result may carry.
pub const MAX_COMMAND_LINE: usize = 4096;

/// The complete record of one benchmark cell run.
///
/// Everything a reader needs to judge the number, and everything the guard
/// needs to decide whether it may be published.
///
/// One later issue adds fields to this struct and no other does:
/// `bench-bottleneck-attribution` adds `scaling_rps`, `scaling_measured` and
/// `kernel`, because all three name types that do not exist until it lands.
/// Every field below is complete as written and none of them moves.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RunResult {
    /// Which cell this measures.
    pub cell: CellId,
    /// The full cell definition, so a result is self-describing.
    pub cell_def: BenchCell,
    /// Hardware, kernel, versions, limits, build stamps.
    pub provenance: Provenance,
    /// Achieved requests per second over the measurement window.
    pub rps: f64,
    /// Total latency from the load client. Secondary.
    pub latency: Percentiles,
    /// Total latency from the 100 rps probe client. THIS is what we
    /// publish.
    pub probe_latency: Percentiles,
    /// Time to first byte.
    pub ttfb: Percentiles,
    /// Connection establishment, measured separately from request service.
    pub connect: Percentiles,
    /// The coordinated-omission detector.
    pub stall: Percentiles,
    /// CPU seconds per request, measured at a FIXED rate. `None` for a
    /// saturate cell, where the quantity is definitionally 1 divided by
    /// throughput.
    ///
    /// An `Option`, NOT an `f64::NAN` sentinel. `serde_json` serialises
    /// `f64::NAN` as `null` and then REFUSES to deserialise `null` back into
    /// an `f64`, so a `NaN` sentinel produces a result file that writes
    /// successfully and can never be read again. Every saturate cell in the
    /// matrix would be write only, and `--verify` would discover it months
    /// later. `None` serialises as `null` and deserialises back to `None`.
    pub cpu_seconds_per_request: Option<f64>,
    /// Peak resident set size of the system under test, in bytes.
    pub rss_bytes: u64,
    /// Peak proportional set size from `smaps_rollup`, in bytes.
    pub pss_bytes: u64,
    /// Response body bytes the client received.
    pub bytes_received: u64,
    /// Configured response body size, repeated here so I4 is checkable
    /// alone.
    pub payload_bytes: u32,
    /// Requests the client issued in the measurement window.
    pub total_requests: u64,
    /// Response status distribution. At most 64 distinct codes.
    pub status_counts: BTreeMap<u16, u64>,
    /// Measured ceiling of `it-origin` on this hardware.
    pub origin_ceiling_rps: f64,
    /// Client rps against the origin with the proxy bypassed.
    pub direct_rps: f64,
    /// Highest per-core client CPU utilisation observed.
    pub client_cpu_max_pct: f64,
    /// Logical cores the system under test was pinned to, from the runner's
    /// `CoreAssignment`. Recorded, never guarded: no invariant reads it, so
    /// the evaluation order above is unchanged by its presence.
    ///
    /// It is here because two published quantities are per-core and cannot
    /// be derived from anything else in the file: the
    /// TLS-handshakes-per-second-per-core figure the connection-setup cells
    /// publish, and the utilisation denominator a later bottleneck
    /// attribution issue's `attribute` divides by.
    /// `provenance.logical_cores` is the whole machine and is the wrong
    /// denominator for both. Zero is treated as 1 by every consumer.
    pub sut_cores: u32,
    /// How many releases were capped because the client fell behind.
    pub catchup_burst_count: u64,
    /// Latency samples above the histogram's 60 second maximum. Must be
    /// zero.
    pub out_of_range: u64,
    /// STALL samples above the histogram's 60 second maximum, from
    /// `StallTracker::out_of_range()`. Must be zero, and for a different
    /// reason: a lost stall sample is a client that was blocked for over a
    /// minute and contributed nothing to the detector that exists to catch
    /// exactly that.
    pub stall_out_of_range: u64,
    /// `on_unblocked` calls whose instant preceded the matching
    /// `on_blocked`. Recorded so a non-monotone clock in the client is
    /// visible rather than showing up as an impossible stall distribution.
    pub stall_backwards_count: u64,
    /// Samples recorded during warmup and discarded.
    pub warmup_samples_discarded: u64,
    /// The deepest percentile this cell intends to publish.
    pub deepest_percentile: DeepestPercentile,
    /// Where the ceiling was.
    pub bottleneck: Bottleneck,
    /// The guard's verdict, recomputable from every other field.
    pub validity: Validity,
    /// Byte-for-byte reproducible invocation of the load generator.
    ///
    /// At most `MAX_COMMAND_LINE` bytes and printable ASCII only. Longer or
    /// otherwise is `Invalid(I12)`: this string is echoed into the run log,
    /// into the generated documentation table, and into an I12 mismatch
    /// detail, and it arrives from a file rather than from us.
    pub command_line: String,
}

impl RunResult {
    /// True when `check_validity(self, None, None) == Validity::Valid` AND
    /// `self.provenance.publishable` is true. The cross-run inputs are
    /// deliberately `None` here: a single result cannot check I12 or the
    /// spread, and this method answers only whether the result is
    /// publishable on its own terms.
    ///
    /// This is NOT sufficient authority to publish a number, and no caller
    /// may treat it as such. With `None` for `expected_command_line`, I12 is
    /// skipped entirely, so a result whose command line drifted from the
    /// registry answers `true` here. The publishing path elsewhere must call
    /// `check_validity` with the registry's entry for the cell, and must
    /// refuse a cell that has NO registry entry rather than treating a
    /// missing entry as permission. A skipped check is not a passed check.
    #[must_use]
    pub fn publishable(&self) -> bool {
        crate::guards::check_validity(self, None, None) == Validity::Valid
            && self.provenance.publishable
    }
}

// ---------------------------------------------------------------------------
// serde for `Detail`.
//
// `crate::error::Detail`'s inner `String` is private and `Detail::new` is
// its only constructor, on purpose: it is the type that keeps a hostile
// value from ever reaching a terminal or a committed artifact unclipped and
// unsanitised. `Validity::Invalid` carries one, and `Validity` is part of
// `RunResult`, which reaches `check_validity` by `serde_json::from_slice`
// over a file any pull request author can edit (see the module docs on
// `crate::guards`). A plain `#[derive(Deserialize)]` on `Detail` (which
// would need to live in `error.rs`, outside this issue's files) would
// reconstruct the private field directly from whatever string a hostile file
// supplied, bypassing the clip-and-sanitise step entirely and defeating "new
// is the only constructor" for exactly the file this crate cannot trust.
// These impls close that gap without touching `error.rs`: `Detail::new` and
// `Detail::as_str` are already public, or the orphan rule only requires ONE
// of {trait, type} to be local, so a foreign trait implemented for a local
// type from a different module of the same crate is ordinary, coherent
// Rust, and here it is what keeps the constructor promise true no matter
// where a `Detail` is built from.
impl serde::Serialize for Detail {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Detail {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Detail::new(&raw))
    }
}
