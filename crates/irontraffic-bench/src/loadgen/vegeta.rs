// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `vegeta` adapter: an independently written open-loop tool used once
//! per release as a cross-check, plus [`cross_check`], the function that
//! decides whether it and the arbiter agree.
//!
//! # Why vegeta is in the tree at all
//!
//! Two independent tools agreeing on p99 is worth more than one more percent
//! of throughput (issue #413's own Context). vegeta's Go `net/http` client
//! ceiling is well below this project's target rates, so it can never be the
//! primary load generator, but it is an HONEST open-loop design (`-rate`)
//! written by someone else, with a different loop model, and its own README
//! claims it avoids coordinated omission. A systematic error in this crate's
//! own harness would be invisible to a second run of the SAME harness;
//! [`cross_check`] is the cheap check against exactly that.
//!
//! # `-max-workers` is never left unbounded
//!
//! Left to grow, vegeta spawns workers until IT becomes the bottleneck,
//! which is the exact failure this milestone exists to detect. `plan`
//! therefore always emits `-max-workers` and refuses to plan at all
//! (`BenchError::Cell`) when [`Vegeta::max_workers`] is `0` (a zero cap
//! attacks at zero requests per second and reports a successful empty run)
//! or above [`MAX_VEGETA_WORKERS`] (a four-billion worker cap is the
//! unbounded case spelled differently). The field is a plain `u32`, never an
//! `Option`, and the documented value a caller sets is `min(cell.connections,
//! 4 * client_cores)`; this module does not compute it, per the Design's own
//! "never computed inside `plan`".
//!
//! # Two commands, because vegeta attacks and reports separately
//!
//! `LoadGenerator::plan` returns exactly one [`super::Invocation`]: the
//! `attack` command. [`Vegeta::report_invocation`] is the second command,
//! `vegeta report -type=json <output_path>`, which [`Vegeta::parse`]'s
//! stdout actually comes from. Feeding `parse` the attack command's own
//! stdout (a binary result file) produces an unhelpful UTF-8 error rather
//! than a clean "wrong command" message, which is why both doc comments
//! state the split directly. The targets file itself is written by
//! `{{bench-runner-and-repetition}}`, not this adapter (`Vegeta::targets_path`
//! only names where): this adapter is sans-IO, like every other adapter in
//! this crate.
//!
//! # The `status_codes` map's `"0"` key is vegeta's OWN transport-failure
//! # bucket, confirmed against real source and a real run
//!
//! `github.com/tsenart/vegeta/v12` `lib/metrics.go`'s `Metrics.Add` (the
//! function that builds this map) runs
//! `m.StatusCodes[strconv.Itoa(int(r.Code))]++` unconditionally for every
//! attempted request, and `r.Code` is the zero value for a request that
//! never got an HTTP response at all (a dial failure, a timeout). This was
//! independently confirmed empirically, not only read from source: attacking
//! one live target and one closed port with a genuine, locally built
//! `vegeta v12.13.0` (`go install
//! github.com/tsenart/vegeta/v12@v12.13.0`; no `docker` needed, unlike
//! Nighthawk) produced `"status_codes":{"0":20,"200":20}` for exactly the 20
//! requests that hit the closed port. `errors` (a JSON array of DISTINCT
//! error message strings, not a per-request count) is therefore never read
//! by this parser at all: using its length as a request count would be
//! wrong, since two failures with the same message collapse to one array
//! entry. `RawRun::errors` comes from `status_codes["0"]` instead, and every
//! other key is validated against the SAME canonical-decimal-rendering rule
//! `oha.rs`'s `parse_rejects_status_code_key_aliasing` fix established (a
//! key of `"0200"` or `"+200"` is rejected rather than silently aliased onto
//! `200`), because this map is exactly as untrusted as oha's own
//! `statusCodeDistribution`.
//!
//! **This module DOES now repeat oha's `duplicate_key_detail` whole-document
//! walk**, as a local copy matching this file's own established "small
//! local copies" convention (see the byte-class helpers immediately below):
//! an earlier version of this module declined it on the grounds that "the
//! canonical-rendering check alone already closes the aliasing class that
//! class of bug actually exploited." That reasoning does not extend to
//! `latencies` (PR 815 review, issue #816 `SHOULD_FIX` 6): the
//! canonical-rendering check runs only inside the `status_codes` loop, and a
//! LITERALLY duplicated key like `"99th"` appearing twice is a different
//! failure mode from a numerically-aliased key like `"0200"` in the first
//! place; `serde_json::Value`'s map silently keeps only the last value for a
//! repeated key with no trace of the one it discarded, on `latencies` exactly
//! as much as on `status_codes`. A repeated `"99th"` key that disagrees with
//! itself shifted this module's own reconstructed p99 by 7.7 percent on a
//! probe against this file's own fixture, larger than `cross_check`'s own 5
//! percent gate, with no error raised at all before this fix.
//!
//! # The percentile reconstruction, and what `latencies` is not used for
//!
//! `vegeta report -type=json`'s `latencies` object carries four percentiles
//! (`50th`, `90th`, `95th`, `99th`) plus `min`/`mean`/`max`/`total`, each
//! already an INTEGER nanosecond count (Go's `time.Duration` marshals as a
//! bare `int64`, never through a float), unlike oha's SECONDS-scaled
//! percentiles. [`Vegeta::parse`] reconstructs a [`crate::LatencyRecorder`]
//! from this ladder, and the top slice this covers (`1.0 - 0.99`, one
//! percent) is recorded at `latencies.max` instead of being silently
//! dropped the way oha's own top `1.0 - 0.9999` slice is documented to be:
//! vegeta gives this adapter a real `max` field to use for exactly that
//! slice, so there is no reason to throw it away. `latencies.total`,
//! `.mean` and `.min` are never read: nothing in this issue's own design
//! maps them onto a `RawRun` field, and `RawRun::latency_exact` is `false`
//! here regardless (this reconstruction is an approximation from four
//! points, not a histogram, exactly like h2load's and oha's).
//!
//! **Each key's weight is the difference of two CUMULATIVE counts, never an
//! independently rounded gap, and each cumulative count is a CEILING, never a
//! round-to-nearest.** An earlier version of this parser rounded each
//! `(quantile - prev_quantile) * requests_sent` gap on its own, the way
//! `oha.rs` rounds its own nine-point ladder's gaps; that is wrong here (PR
//! 815 review, issue #816 BLOCKING 2). Independent per-gap rounding lets the
//! SAME half-sample round down at one step and up at the next, so the errors
//! compound instead of cancelling: on this module's own committed fixture
//! (`requests: 250`), `(0.95 - 0.90) * 250` is `12.499999999999984` in f64,
//! which rounds to 12 rather than 13, leaving only 247 of the 248 samples
//! `round(0.99 * 250)` should place at or below the 99th percentile. The one
//! sample this dropped landed at `latencies.max` instead, so
//! `value_at_quantile(0.99)` fell into the `max` bucket rather than the 99th,
//! and the reconstructed p99 collapsed onto `max`, 2.73x vegeta's own
//! reported value, on 832 of a 2,602-point sweep of `requests`.
//!
//! A first fix took the DIFFERENCE of two cumulative, independently
//! ROUNDED running totals instead of rounding each gap; that made total
//! allocation exact (zero mismatches across a 2,602-point sweep and 4,000
//! random ladders) but left the collapse in place, and made it WORSE: 294 of
//! 602 gate-eligible run sizes instead of 192 (PR 815 review, issue #817
//! BLOCKING 1). The reason is that this ladder's own cumulative target and
//! [`crate::hist::LatencyRecorder::percentiles`]'s own READER disagreed on
//! which rank a quantile owns. `percentiles()` answers `p99_ns` through
//! `hdrhistogram::value_at_quantile(0.99)`, which reads the value at rank
//! `ceil(0.99 * N)` (confirmed directly against the `hdrhistogram` crate's
//! own source, `value_at_quantile`'s `fractional_count.ceil()`), but a
//! cumulative total of `round(0.99 * N)` places the LAST sample at the 99th
//! percentile's value only up to rank `round(0.99 * N)`. Whenever
//! `round(0.99 * N) < ceil(0.99 * N)`, the rank the reader actually asks for
//! falls one past that boundary, into the weight recorded at `latencies.max`
//! instead. `frac(0.99 * N)` takes only the values `0, 0.01, ..., 0.99`, and
//! `round` and `ceil` disagree on it whenever that fraction is strictly
//! between 0 and 0.5, which happens for 49 of every 100 values of `N`
//! (`N mod 100` in `51..=99`): confirmed empirically by sweeping, not only
//! derived.
//!
//! The actual fix is to make the cumulative target the SAME function the
//! reader uses: each cumulative count is `ceil(quantile * requests_sent)`,
//! never `round(quantile * requests_sent)`, so the rank the 99th bucket owns
//! (`ceil(0.99 * requests_sent)`, by construction) is exactly the rank
//! `value_at_quantile(0.99)` reads. This still allocates EXACTLY
//! `ceil(quantile * requests_sent)` samples at or below every quantile (each
//! cumulative count is non-decreasing and bounded by `requests_sent`, since
//! `quantile <= 0.99 < 1.0`), so total allocation stays exact, and it removes
//! the one-step-further-down-the-pipe mismatch the rounded-cumulative fix
//! left behind. `parse_fixture` (`tests/loadgen_vegeta.rs`) pins the
//! reconstructed p99 against this fixture's own literal `latencies.99th` at
//! `requests: 250` (`250 mod 100 == 50`, the one residue where `round` and
//! `ceil` already agreed, so this alone is not a regression guard against the
//! collapse); `parse_reconstructs_p99_at_a_collapsing_residue` in the same
//! file is the regression guard proper, built at a `requests` value whose
//! residue mod 100 falls in `51..=99` and watched to fail against the
//! rounded-cumulative form this replaces.
//!
//! # Untrusted input
//!
//! [`Vegeta::parse`]'s `stdout` is the captured output of a SEPARATE
//! process (`vegeta report`'s own stdout), the same untrusted-input
//! boundary this crate's `loadgen` module doc documents for every adapter;
//! [`super::MAX_TOOL_OUTPUT_BYTES`] is the caller-side capture-time bound
//! this parser's own `serde_json::from_slice` call is the second,
//! size-checked line of defence for.
//!
//! # `cross_check`: the release gate
//!
//! See this function's own doc for the full seven-step contract. The two
//! properties worth restating here because a naive implementation gets them
//! backwards: a `NaN` client-CPU reading must be checked with `is_finite()`
//! BEFORE any ordering comparison (`NaN >= 80.0` is `false`, so an
//! ordering-only saturation guard reports agreement on a measurement that
//! does not exist), and the tolerance ratio's denominator is
//! `max(arbiter.p99_ns, independent.p99_ns)`, never the arbiter's value
//! alone, specifically so the verdict does not depend on which tool is
//! passed first.

use std::collections::HashSet;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::cell::{BenchCell, Protocol, RateMode};
use crate::error::BenchError;
use crate::hist::{LatencyRecorder, Percentiles};
use crate::provenance::ToolStamp;

use super::{Invocation, MAX_HOST_BYTES, MAX_PATH_EXPR_BYTES, MAX_REPORTED_REQUESTS};
use super::{LoadGenerator, ParseCtx, RawRun, RunParams, Target, Unsupported};
use super::{MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_STDERR_BYTES, MAX_VERSION_OUTPUT_BYTES};

/// Relative p99 difference, in parts per thousand, above which two tools
/// disagree. 50 permille is the 5 percent threshold named throughout this
/// issue.
pub const CROSS_CHECK_TOLERANCE_PERMILLE: u32 = 50;

/// Largest `max_workers` the vegeta adapter will render. Above this, vegeta
/// is the bottleneck no matter what the target does: a four-billion worker
/// cap is not a bound, it is the unbounded case spelled differently.
pub const MAX_VEGETA_WORKERS: u32 = 65_536;

/// The four percentile keys `vegeta report -type=json`'s `latencies` object
/// carries, paired with the quantile each represents, in ascending order.
/// Fixed and exhaustive, matching `oha.rs`'s identical `PERCENTILE_KEYS`
/// shape: a MISSING entry is `Err(Parse)` naming it, never defaulted.
const PERCENTILE_KEYS: [(&str, f64); 4] = [
    ("50th", 0.50),
    ("90th", 0.90),
    ("95th", 0.95),
    ("99th", 0.99),
];

/// The vegeta adapter: an independently written open-loop tool used once per
/// release as a cross-check.
///
/// Go's `net/http` client ceiling is well below our target rates, so vegeta
/// is never the primary. Its role is confirmation at a moderate rate.
#[derive(Debug, Clone)]
pub struct Vegeta {
    /// Upper bound on vegeta's worker count. Never unbounded: left to grow,
    /// vegeta becomes the bottleneck, which is the failure this milestone
    /// exists to detect.
    pub max_workers: u32,
    /// Path the runner will write the targets file to.
    pub targets_path: std::path::PathBuf,
    /// Path the runner will write the binary result to.
    pub output_path: std::path::PathBuf,
}

// ---------------------------------------------------------------------------
// Duplicate-key detection: a local copy of `oha.rs`'s own
// `RejectDuplicateKeys`/`RejectDuplicateKeysVisitor`/`duplicate_key_detail`,
// matching this file's own "small local copies" convention (see the
// byte-class helpers immediately below), added because the module doc's
// earlier reasoning for declining it did not extend to `latencies` (PR 815
// review, issue #816 SHOULD_FIX 6).
// ---------------------------------------------------------------------------

/// A no-op [`DeserializeSeed`] that walks one JSON value (recursively, for an
/// array or object) purely to detect a duplicate key, without building
/// anything. See [`duplicate_key_detail`] for why this walk exists.
struct RejectDuplicateKeys;

impl<'de> DeserializeSeed<'de> for RejectDuplicateKeys {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(RejectDuplicateKeysVisitor)
    }
}

/// The [`Visitor`] half of [`RejectDuplicateKeys`]. Every scalar variant is a
/// plain `Ok(())`: only `visit_seq` and `visit_map` recurse, and only
/// `visit_map` can ever fail.
struct RejectDuplicateKeysVisitor;

impl<'de> Visitor<'de> for RejectDuplicateKeysVisitor {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _v: bool) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_i64<E>(self, _v: i64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u64<E>(self, _v: u64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_str<E>(self, _v: &str) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element_seed(RejectDuplicateKeys)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate key {key}")));
            }
            map.next_value_seed(RejectDuplicateKeys)?;
        }
        Ok(())
    }
}

/// Returns `Some(detail)` only when `bytes` is otherwise well-formed JSON
/// that contains a duplicate key in some object, at any nesting depth.
/// `serde_json::Value`'s own `Map` silently keeps only the LAST value for a
/// repeated key and reports nothing at all: a literal duplicated `"99th"`
/// entry in `latencies`, or two top-level `latencies` objects, both parse
/// `Ok` today using whichever entry happens to be spelled last, with no
/// trace of the one it discarded. This walk runs BEFORE the document ever
/// becomes a `Value`, so it sees every key exactly as `serde_json`'s own
/// tokenizer does, for exactly that reason. A local copy of `oha.rs`'s
/// identically named, identically implemented function.
///
/// A genuine JSON syntax error (mismatched brackets, an unterminated
/// string, and so on) is deliberately reported as `None` here rather than
/// surfaced from this pass: the caller's own `serde_json::from_slice::<Value>`
/// call reports it in this module's usual "invalid json: {e}" words, so one
/// malformed input gets one message, not two differently worded ones.
/// `serde_json::Error::is_data` is what tells the two apart, because
/// `serde::de::Error::custom` inside [`RejectDuplicateKeysVisitor`] is the
/// ONLY place this pass ever builds a Data-category error.
///
/// Uses `serde_json`'s own default recursion limit, exactly like the real
/// parse below: never widened, per this crate's Do NOT list.
fn duplicate_key_detail(bytes: &[u8]) -> Option<String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    match RejectDuplicateKeys.deserialize(&mut de) {
        Err(e) if e.is_data() => Some(format!("duplicate object key: {e}")),
        Ok(()) | Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Shared byte-class helpers, small local copies matching `nighthawk.rs`'s
// and `h2load.rs`'s own identical precedent.
// ---------------------------------------------------------------------------

fn is_host_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

fn is_path_expr_char(b: u8) -> bool {
    (0x21..=0x7E).contains(&b)
}

fn bounded(s: &str, cap: usize, allowed: fn(u8) -> bool) -> bool {
    s.len() <= cap && s.bytes().all(allowed)
}

fn validate_target(target: &Target) -> Result<(), BenchError> {
    if !bounded(&target.host, MAX_HOST_BYTES, is_host_char) {
        return Err(BenchError::Cell(
            "host exceeds its length or character class bound",
        ));
    }
    if let Some(sni) = &target.sni
        && !bounded(sni, MAX_HOST_BYTES, is_host_char)
    {
        return Err(BenchError::Cell(
            "sni exceeds its length or character class bound",
        ));
    }
    if !bounded(&target.path_expr, MAX_PATH_EXPR_BYTES, is_path_expr_char) {
        return Err(BenchError::Cell(
            "path_expr exceeds its length or character class bound",
        ));
    }
    if !target.path_expr.starts_with('/') {
        return Err(BenchError::Cell("path_expr must begin with a leading /"));
    }
    Ok(())
}

/// Maps a `supports` refusal to the `BenchError::Cell` `plan`'s own doc
/// promises, matching `oha.rs`'s identical `unsupported_to_cell_error`.
fn unsupported_to_cell_error(u: &Unsupported) -> BenchError {
    match u {
        Unsupported::Protocol { .. } => BenchError::Cell("protocol not supported by this adapter"),
        Unsupported::RateMode { .. } => {
            BenchError::Cell("saturate rate mode not supported by this adapter")
        }
        Unsupported::Connections { .. } => {
            BenchError::Cell("too many connections for this adapter")
        }
    }
}

/// Reads `obj[key]` as an object, naming `key` when absent or not an object.
fn require_object<'a>(
    obj: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a serde_json::Map<String, Value>, BenchError> {
    obj.get(key)
        .ok_or_else(|| BenchError::parse("vegeta", &format!("missing field {key}")))?
        .as_object()
        .ok_or_else(|| BenchError::parse("vegeta", &format!("{key} is not an object")))
}

impl Vegeta {
    /// The SECOND command of the pair: `vegeta report -type=json
    /// <output_path>`.
    ///
    /// `LoadGenerator::plan` returns the `attack` command; this returns the
    /// `report` command whose stdout `parse` consumes. The runner spawns
    /// both, in order, and treats a failure of either as a failure of the
    /// repetition (edge case 17).
    #[must_use]
    pub fn report_invocation(&self) -> Invocation {
        Invocation {
            program: "vegeta".to_owned(),
            args: vec![
                "report".to_owned(),
                "-type=json".to_owned(),
                self.output_path.to_string_lossy().into_owned(),
            ],
            env: Vec::new(),
        }
    }
}

impl LoadGenerator for Vegeta {
    fn name(&self) -> &'static str {
        "vegeta"
    }

    fn version_invocation(&self) -> Invocation {
        // `vegeta -version` prints `Version: <v>\nCommit: ...\nRuntime:
        // ...\nDate: ...\n` (confirmed against `tsenart/vegeta`'s own
        // `main.go`), so the version is the first line with the `Version:
        // ` label stripped.
        Invocation {
            program: "vegeta".to_owned(),
            args: vec!["-version".to_owned()],
            env: Vec::new(),
        }
    }

    fn parse_version(&self, stdout: &[u8]) -> Result<ToolStamp, BenchError> {
        if stdout.len() > MAX_VERSION_OUTPUT_BYTES {
            return Err(BenchError::parse(
                "vegeta",
                "version output exceeds MAX_VERSION_OUTPUT_BYTES",
            ));
        }
        let text = std::str::from_utf8(stdout)
            .map_err(|_| BenchError::parse("vegeta", "version output is not utf-8"))?;
        let first_line = text
            .trim()
            .lines()
            .next()
            .ok_or_else(|| BenchError::parse("vegeta", "version output is empty"))?;
        let version = first_line
            .strip_prefix("Version:")
            .map(str::trim)
            .ok_or_else(|| BenchError::parse("vegeta", "version output has no Version: label"))?;
        if version.is_empty() || !version.bytes().all(is_path_expr_char) {
            return Err(BenchError::parse(
                "vegeta",
                "version output is empty or contains a non-printable byte",
            ));
        }
        Ok(ToolStamp {
            name: self.name().to_owned(),
            version: version.to_owned(),
            image_digest: None,
        })
    }

    fn supports(&self, cell: &BenchCell) -> Result<(), Unsupported> {
        if cell.protocol == Protocol::H3 {
            return Err(Unsupported::Protocol {
                tool: self.name(),
                protocol: Protocol::H3,
            });
        }
        if matches!(cell.rate, RateMode::Saturate) {
            // vegeta's whole role is confirmation at a moderate FIXED rate
            // (this issue's own Summary); a saturate cell is not what the
            // cross-check exists to answer, and vegeta's own client ceiling
            // makes it a poor saturate-mode throughput tool anyway.
            return Err(Unsupported::RateMode {
                tool: self.name(),
                detail: "vegeta is the release cross-check at a moderate FIXED rate, not a \
                         saturate-mode throughput tool",
            });
        }
        Ok(())
    }

    fn plan(
        &self,
        cell: &BenchCell,
        target: &Target,
        run: &RunParams,
    ) -> Result<Invocation, BenchError> {
        self.supports(cell)
            .map_err(|e| unsupported_to_cell_error(&e))?;
        validate_target(target)?;

        if self.max_workers == 0 || self.max_workers > MAX_VEGETA_WORKERS {
            return Err(BenchError::Cell(
                "max_workers must be nonzero and at most MAX_VEGETA_WORKERS",
            ));
        }

        let RateMode::Fixed(rate) = cell.rate else {
            // `supports` above already refused `RateMode::Saturate`; this
            // is unreachable through any caller that consults `supports`
            // first, matching `plan`'s own contract, but a defensive `Err`
            // rather than a panic costs nothing here.
            return Err(BenchError::Cell(
                "vegeta only measures RateMode::Fixed cells",
            ));
        };
        if rate == 0 {
            return Err(BenchError::Cell("zero rate"));
        }

        let mut args: Vec<String> = Vec::with_capacity(12);
        args.push("attack".to_owned());
        args.push("-rate".to_owned());
        args.push(format!("{rate}/1s"));
        args.push("-duration".to_owned());
        args.push(format!("{}s", run.duration_secs));
        args.push("-connections".to_owned());
        args.push(cell.connections.to_string());
        args.push("-max-workers".to_owned());
        args.push(self.max_workers.to_string());
        args.push("-targets".to_owned());
        args.push(self.targets_path.to_string_lossy().into_owned());
        args.push("-output".to_owned());
        args.push(self.output_path.to_string_lossy().into_owned());

        Ok(Invocation {
            program: "vegeta".to_owned(),
            args,
            env: Vec::new(),
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one linear validate-then-extract pass over a single JSON document, matching \
                  this crate's own established parser shape (Oha::parse/Nighthawk::parse are the \
                  same length for the same reason)"
    )]
    fn parse(
        &self,
        ctx: &ParseCtx<'_>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<RawRun, BenchError> {
        if stdout.len() > MAX_TOOL_OUTPUT_BYTES {
            return Err(BenchError::parse(
                "vegeta",
                "stdout exceeds MAX_TOOL_OUTPUT_BYTES",
            ));
        }
        if stderr.len() > MAX_TOOL_STDERR_BYTES {
            return Err(BenchError::parse(
                "vegeta",
                "stderr exceeds MAX_TOOL_STDERR_BYTES",
            ));
        }

        // A literal duplicate key anywhere in stdout (a repeated `"99th"` in
        // `latencies`, or a second top-level `latencies` object) is rejected
        // here, before the document ever becomes a `Value`: see
        // `duplicate_key_detail`'s own doc for why `serde_json::Value`'s
        // silent last-wins behaviour is not good enough at this
        // untrusted-input boundary. Matches `oha.rs`'s identical check,
        // added here for the identical reason (PR 815 review, issue #816
        // SHOULD_FIX 6).
        if let Some(detail) = duplicate_key_detail(stdout) {
            return Err(BenchError::parse("vegeta", &detail));
        }

        let value: Value = serde_json::from_slice(stdout)
            .map_err(|e| BenchError::parse("vegeta", &format!("invalid json: {e}")))?;
        let obj = value
            .as_object()
            .ok_or_else(|| BenchError::parse("vegeta", "top level value is not an object"))?;

        let requests_sent = obj
            .get("requests")
            .and_then(Value::as_u64)
            .ok_or_else(|| BenchError::parse("vegeta", "missing field requests"))?;
        if requests_sent > MAX_REPORTED_REQUESTS {
            return Err(BenchError::parse(
                "vegeta",
                "requests exceeds MAX_REPORTED_REQUESTS",
            ));
        }
        if requests_sent == 0 {
            return Err(BenchError::parse("vegeta", "requests is zero: not a run"));
        }

        let duration_ns = obj
            .get("duration")
            .and_then(Value::as_u64)
            .ok_or_else(|| BenchError::parse("vegeta", "missing field duration"))?;
        if duration_ns == 0 {
            return Err(BenchError::parse(
                "vegeta",
                "duration yields a zero duration_ns",
            ));
        }

        let bytes_in = require_object(obj, "bytes_in")?;
        let bytes_received = bytes_in
            .get("total")
            .and_then(Value::as_u64)
            .ok_or_else(|| BenchError::parse("vegeta", "missing field bytes_in.total"))?;

        let status_codes = require_object(obj, "status_codes")?;
        if status_codes.is_empty() {
            return Err(BenchError::parse("vegeta", "status_codes is empty"));
        }

        let mut status_counts: std::collections::BTreeMap<u16, u64> =
            std::collections::BTreeMap::new();
        let mut errors: u64 = 0;
        let mut status_sum: u128 = 0;
        for (key, val) in status_codes {
            let count = val.as_u64().ok_or_else(|| {
                BenchError::parse("vegeta", &format!("status_codes[{key}] is not a u64"))
            })?;
            status_sum = status_sum.saturating_add(u128::from(count));
            if key == "0" {
                errors = count;
                continue;
            }
            // Same canonical-rendering rule `oha.rs`'s
            // `parse_rejects_status_code_key_aliasing` fix established: a
            // key of "0200" or "+200" parses to the same u16 as "200" while
            // remaining a DIFFERENT map key, which would otherwise let a
            // hostile document add its own count into `status_sum` while
            // colliding into a single `status_counts` entry.
            let code: u16 = key
                .parse::<u16>()
                .ok()
                .filter(|c| (100..=599).contains(c))
                .ok_or_else(|| {
                    BenchError::parse(
                        "vegeta",
                        &format!("status_codes key {key} is not a status code 100..=599"),
                    )
                })?;
            if code.to_string() != *key {
                return Err(BenchError::parse(
                    "vegeta",
                    &format!(
                        "status_codes key {key} is not the canonical rendering of its own code"
                    ),
                ));
            }
            status_counts.insert(code, count);
        }
        if status_sum != u128::from(requests_sent) {
            return Err(BenchError::parse(
                "vegeta",
                "status_codes total disagrees with requests",
            ));
        }
        let responses_ok = status_counts.get(&200).copied().unwrap_or(0);

        let latencies = require_object(obj, "latencies")?; // edge case 8

        let mut recorder = LatencyRecorder::new()?;
        #[expect(
            clippy::cast_precision_loss,
            reason = "requests_sent is <= MAX_REPORTED_REQUESTS (1e12), comfortably inside f64's \
                      2^53 exact-integer range, so this conversion loses no precision that \
                      matters for a reconstruction weight, matching oha.rs's identical cast"
        )]
        let requests_sent_f = requests_sent as f64;
        let mut allocated: u64 = 0;
        let mut prev_cumulative: u64 = 0;
        let mut prev_value_ns: Option<u64> = None;
        for (key, quantile) in PERCENTILE_KEYS {
            let value_ns = latencies.get(key).and_then(Value::as_u64).ok_or_else(|| {
                BenchError::parse("vegeta", &format!("missing field latencies.{key}"))
            })?;

            // Percentile values must be monotone non-decreasing as the
            // quantile increases (matching `oha.rs`'s identical
            // `latencyPercentiles` check, edge case 8 there): a tool bug or
            // a mangled fixture producing p99 below p50 would reconstruct a
            // histogram whose own p50 exceeds its p99, which is not a real
            // distribution. Not one of issue #413's own named edge cases
            // for `latencies` (PR 815 review, issue #816 SHOULD_FIX 6), but
            // the identical object this crate already guards on the sibling
            // adapter, and the object that produces the number
            // `cross_check`'s 5 percent gate actually compares.
            if let Some(prev) = prev_value_ns
                && value_ns < prev
            {
                return Err(BenchError::parse(
                    "vegeta",
                    "latencies values are not monotone non-decreasing",
                ));
            }
            prev_value_ns = Some(value_ns);

            // CUMULATIVE, not an independently-rounded-per-gap weight (PR
            // 815 review, issue #816 BLOCKING 2), and a CEILING, never a
            // round-to-nearest (PR 815 review, issue #817 BLOCKING 1).
            // Rounding each `(quantile - prev_quantile) * requests_sent_f`
            // gap on its own lets the SAME half-sample round down at one
            // step and up at the next, so the errors compound instead of
            // cancelling; taking the difference of two cumulative totals
            // fixes that, but a cumulative total of `round(quantile *
            // requests_sent)` still disagrees with the READER:
            // `LatencyRecorder::percentiles()` answers `p99_ns` through
            // `hdrhistogram::value_at_quantile(0.99)`, which reads the value
            // at rank `ceil(0.99 * N)`, not `round(0.99 * N)`. Whenever
            // `round(0.99 * N) < ceil(0.99 * N)` (49 of every 100 values of
            // `N`, exactly when `N mod 100` is in `51..=99`), the rank the
            // reader asks for falls one past the rounded cumulative total,
            // into the weight recorded at `latencies.max` instead, and the
            // reconstructed p99 collapses onto `max`. Using `ceil` here
            // instead of `round` makes the cumulative target the SAME
            // function the reader uses, so the 99th bucket's own cumulative
            // count (`ceil(0.99 * requests_sent)`) is exactly the rank
            // `value_at_quantile(0.99)` reads, at every `requests_sent`.
            // Total allocation stays exact: each cumulative count is
            // non-decreasing and bounded by `requests_sent_f` (`quantile <=
            // 0.99 < 1.0`), so `.clamp(...)` below never actually clamps
            // anything, and is kept only as defence in depth. `parse_fixture`
            // and `parse_reconstructs_p99_at_a_collapsing_residue` (both in
            // `tests/loadgen_vegeta.rs`) are the regression tests; the
            // latter is built at a `requests` value whose residue mod 100
            // falls in `51..=99`, the one case the former's fixture
            // (`requests: 250`, residue 50) cannot exercise, and fails
            // against the rounded-cumulative form this replaces.
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "quantile is in (0.0, 1.0] by construction (PERCENTILE_KEYS's quantiles \
                          are fixed, strictly increasing literals), and requests_sent_f is \
                          non-negative, so quantile * requests_sent_f is non-negative and at most \
                          requests_sent_f; .ceil().clamp(...) bounds it before this cast"
            )]
            let cumulative = (quantile * requests_sent_f)
                .ceil()
                .clamp(0.0, requests_sent_f) as u64;
            let weight = cumulative.saturating_sub(prev_cumulative);
            recorder.record_n_ns(value_ns, weight);
            allocated = allocated.saturating_add(weight);
            prev_cumulative = cumulative;
        }
        // The top slice this ladder does not cover (`1.0 - 0.99`, one
        // percent) goes to `latencies.max`, which vegeta reports directly:
        // unlike oha's nine-point ladder (whose own top slice has no
        // matching field to anchor it), vegeta gives this adapter a real
        // value for exactly this remainder, so it is used rather than
        // dropped.
        let max_ns = latencies
            .get("max")
            .and_then(Value::as_u64)
            .ok_or_else(|| BenchError::parse("vegeta", "missing field latencies.max"))?;
        let remaining = requests_sent.saturating_sub(allocated);
        recorder.record_n_ns(max_ns, remaining);

        let latency_trustworthy = matches!(ctx.cell.rate, RateMode::Fixed(_));

        Ok(RawRun {
            tool: ctx.tool.clone(),
            command_line: ctx.invocation.command_line(),
            requests_sent,
            responses_ok,
            errors,
            status_counts,
            bytes_received,
            duration_ns,
            out_of_range: recorder.out_of_range(),
            latency: recorder,
            ttfb: None,
            connect: None,
            stall: None,
            // Reconstructed from four percentile points, never a histogram:
            // the honest representation of "we only have four quantiles
            // plus max" is `latency_exact: false`, matching h2load's and
            // oha's identical choice. Never published (Do NOT list):
            // vegeta's value is the `cross_check` verdict, not its latency
            // number.
            latency_exact: false,
            latency_trustworthy,
        })
    }
}

/// Why a cross-check could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotComparableReason {
    /// The independent tool's own client CPU was at or above 80 percent.
    ClientSaturated,
    /// The independent tool recorded too few samples for a p99.
    TooFewSamples,
    /// One of the two recorders was empty.
    NoSamples,
}

/// Verdict of comparing the arbiter against an independent tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CrossCheck {
    /// The two tools' p99 values are within 5 percent.
    Agree {
        /// Relative difference in parts per thousand.
        delta_permille: u32,
    },
    /// The two tools disagree by more than 5 percent. Investigate before
    /// publishing.
    Disagree {
        /// Relative difference in parts per thousand.
        delta_permille: u32,
    },
    /// The comparison is not meaningful.
    NotComparable {
        /// Why.
        reason: NotComparableReason,
    },
}

/// Compares the arbiter's percentiles against an independent tool's.
///
/// Steps run in this fixed order and the FIRST match wins:
///
/// 0. A non-finite or negative `independent_client_cpu_pct` is
///    `NotComparable { ClientSaturated }`, checked BEFORE the ordering
///    comparison in step 2. `NaN >= 80.0` is `false`, so a saturation check
///    written only with `>=` would let a `NaN` CPU reading sail through as
///    agreement, on the strength of a measurement that does not exist; a
///    missing CPU sample is exactly how a `NaN` gets here.
/// 1. Either recorder having `samples == 0`, or either `p99_ns == 0`, is
///    `NotComparable { NoSamples }`.
/// 2. `independent_client_cpu_pct >= 80.0` is `NotComparable {
///    ClientSaturated }`.
/// 3. `min(arbiter.samples, independent.samples) < Percentiles::required_samples(0.99)`
///    is `NotComparable { TooFewSamples }`. The MINIMUM of the two, not only
///    the independent tool's, for the same symmetry reason step 4 widens to
///    `u128`: checking one side alone would make the verdict depend on
///    argument order.
/// 4. Otherwise, `delta_permille = |a.p99_ns - b.p99_ns| * 1000 /
///    max(a.p99_ns, b.p99_ns)`, computed in `u128` before narrowing:
///    `Percentiles` values are deserialised from result files a pull request
///    author can edit, so `p99_ns` can be `u64::MAX`, and `u64::MAX * 1000`
///    wraps to a small number in `u64` that would land inside the tolerance
///    and report `Agree`. The quotient is provably at most 1,000 (the
///    numerator can never exceed the denominator), so the narrowing cast at
///    the end cannot truncate.
/// 5. `delta_permille <= 50` (5 percent) is `Agree`.
/// 6. Otherwise `Disagree`.
///
/// Symmetric: swapping `arbiter` and `independent` never changes the
/// verdict, because the denominator is `max`, not the arbiter's own value,
/// and step 3 checks the minimum of the two sample counts. Only
/// `independent_client_cpu_pct` is one-sided, and it is a separate
/// parameter rather than a property of either `Percentiles`, so it never
/// swaps when the two recorders do.
#[must_use]
pub fn cross_check(
    arbiter: &Percentiles,
    independent: &Percentiles,
    independent_client_cpu_pct: f64,
) -> CrossCheck {
    if !independent_client_cpu_pct.is_finite() || independent_client_cpu_pct < 0.0 {
        return CrossCheck::NotComparable {
            reason: NotComparableReason::ClientSaturated,
        };
    }
    if arbiter.samples == 0
        || independent.samples == 0
        || arbiter.p99_ns == 0
        || independent.p99_ns == 0
    {
        return CrossCheck::NotComparable {
            reason: NotComparableReason::NoSamples,
        };
    }
    if independent_client_cpu_pct >= 80.0 {
        return CrossCheck::NotComparable {
            reason: NotComparableReason::ClientSaturated,
        };
    }
    if arbiter.samples.min(independent.samples) < Percentiles::required_samples(0.99) {
        return CrossCheck::NotComparable {
            reason: NotComparableReason::TooFewSamples,
        };
    }

    let max_p99 = arbiter.p99_ns.max(independent.p99_ns);
    let diff = arbiter.p99_ns.abs_diff(independent.p99_ns);
    // `diff <= max_p99` always (the difference between two non-negative
    // values can never exceed their maximum), so this quotient is provably
    // at most 1,000 regardless of the u128 numerator's magnitude; the u128
    // widening is what stops `diff * 1000` from wrapping in u64 when either
    // input is near `u64::MAX`. The division below is an intentional,
    // documented truncation (the permille figure IS the floor of the exact
    // ratio, per this function's own Design section), not a precision bug,
    // so `integer_division` is expected rather than routed through floats,
    // which would reintroduce exactly the NaN/rounding hazards this whole
    // module exists to avoid.
    #[expect(
        clippy::integer_division,
        reason = "delta_permille is defined as the FLOOR of the exact ratio (this function's own \
                  Design section, step 4); routing this through f64 would reintroduce the \
                  NaN/precision-loss hazards u128 integer arithmetic exists here specifically to \
                  avoid"
    )]
    let quotient = u128::from(diff) * 1000 / u128::from(max_p99);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "quotient <= 1000 always: diff <= max_p99 by construction (the difference \
                  between two u64 values cannot exceed their maximum), so diff * 1000 / max_p99 \
                  is bounded by 1000 regardless of how large diff or max_p99 are individually"
    )]
    let delta_permille = quotient as u32; // it-allow: unchecked-cast reason: quotient <= 1000 always, since diff <= max_p99 by construction (the difference between two u64 values cannot exceed their maximum), so diff * 1000 / max_p99 is bounded by 1000 regardless of how large diff or max_p99 are individually; not a value read off the wire without this proof.

    if delta_permille <= CROSS_CHECK_TOLERANCE_PERMILLE {
        CrossCheck::Agree { delta_permille }
    } else {
        CrossCheck::Disagree { delta_permille }
    }
}
