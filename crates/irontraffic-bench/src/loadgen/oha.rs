// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `oha` adapter: the sweep and developer-loop load generator.
//!
//! `oha` is closed-loop by default; `-q` sets a rate and `--latency-correction`
//! applies Gil Tene's correction so latency is measured from the intended send
//! time rather than the actual one. Both flags are always emitted together for
//! a fixed-rate cell, and [`Oha::supports`] refuses a `RateMode::Saturate`
//! cell outright: oha's saturate mode is a throughput measurement only, and
//! `supports` is the primary gate a runner consults before ever calling
//! [`Oha::plan`]. [`Oha::parse`]'s own `latency_trustworthy` computation is a
//! second, independent line of defence for exactly the same fact (see its own
//! doc), not a place that assumes `supports` was consulted first.
//!
//! `oha --output-format json` is a tool's debug output, not a stable public
//! schema: it changes between versions. [`Oha::parse`] therefore reads a
//! small, explicitly enumerated set of fields, tolerates unknown ones, and
//! names the missing field in the error rather than defaulting it to zero.
//! `crates/irontraffic-bench/tests/fixtures/oha-1.15.0.json` is a REAL,
//! captured `oha 1.15.0` run (captured against the pinned binary against a
//! local HTTP server, not hand-written), and `parse_fixture` in
//! `tests/loadgen_oha.rs` is the authority on the exact field spellings this
//! module assumes; if a future pinned version changes a key, fix this parser
//! against a freshly captured fixture, not the other way around.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::cell::{BenchCell, KeepaliveMode, PathCorpus, Protocol, RateMode, TlsMode};
use crate::error::BenchError;
use crate::hist::LatencyRecorder;
use crate::provenance::ToolStamp;

use super::{Invocation, MAX_HOST_BYTES, MAX_PATH_EXPR_BYTES, MAX_REPORTED_REQUESTS};
use super::{LoadGenerator, ParseCtx, RawRun, RunParams, Target, Unsupported};
use super::{MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_STDERR_BYTES, MAX_VERSION_OUTPUT_BYTES};

/// The oha adapter: sweeps and the developer loop.
#[derive(Debug, Default, Clone, Copy)]
pub struct Oha;

/// Largest connection count oha is asked to drive. Above this, oha's
/// per-connection cost makes the cell h2load's or Nighthawk's job.
const MAX_CONNECTIONS: u32 = 65_535;

/// Longest `summary.total` this parser accepts, in seconds. A run reporting a
/// longer duration than this is not a plausible sweep or developer-loop
/// measurement.
const MAX_DURATION_SECS: f64 = 86_400.0;

/// Largest number of distinct status codes `statusCodeDistribution` may
/// report. Matches invariant I3's own limit.
const MAX_STATUS_CODES: usize = 64;

/// Substrings that, if present anywhere in stderr, mark the run's latency as
/// untrustworthy regardless of `RateMode`.
///
/// SPECULATIVE, NOT OBSERVED: the pinned `oha 1.15.0` source
/// (`hatoo/oha` on crates.io) was inspected directly for this issue and
/// contains NO runtime warning message of any kind on this code path; its
/// only `eprintln!` calls are a `--dump-urls` debug print, a
/// `--db`/results-database status line, and a fatal top-level error printed
/// once before exit. There is no "unable to keep up" or rate-shortfall
/// warning to observe empirically at this pinned version. This array and the
/// scan that uses it are therefore a defensive, forward-looking check
/// (matching the general two-of-three-tools-warn-on-stderr rationale this
/// trait's own doc gives) rather than a behaviour reproduced from a real
/// run; if oha ever adds such a warning, re-verify these exact substrings
/// against its wording when the pinned version changes, as with every
/// version-specific string in this module.
const RATE_WARNING_SUBSTRINGS: [&str; 3] =
    ["unable to keep up", "could not achieve", "falling behind"];

/// The nine `latencyPercentiles` keys `oha 1.15.0` reports, paired with the
/// quantile each represents, in ascending quantile order. Fixed and
/// exhaustive: any key outside this list is an unknown field (tolerated,
/// per this module's own doc), and a MISSING entry from this list is
/// `Err(Parse)` naming it, per the "explicitly enumerated set of fields"
/// rule, never defaulted.
const PERCENTILE_KEYS: [(&str, f64); 9] = [
    ("p10", 0.10),
    ("p25", 0.25),
    ("p50", 0.50),
    ("p75", 0.75),
    ("p90", 0.90),
    ("p95", 0.95),
    ("p99", 0.99),
    ("p99.9", 0.999),
    ("p99.99", 0.9999),
];

/// True when `haystack` contains `needle` anywhere, scanned as raw bytes so
/// stderr never needs to be valid UTF-8 for this check to be safe. An empty
/// needle is defined as always present, matching `str::contains`'s own rule,
/// though every entry in [`RATE_WARNING_SUBSTRINGS`] is non-empty.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn is_host_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

/// Printable ASCII excluding space, matching the Bounds table's
/// `0x21..=0x7E` class for `path_expr`.
fn is_path_expr_char(b: u8) -> bool {
    (0x21..=0x7E).contains(&b)
}

fn bounded(s: &str, cap: usize, allowed: fn(u8) -> bool) -> bool {
    s.len() <= cap && s.bytes().all(allowed)
}

/// Validates `target`'s three string fields against the Bounds table. Every
/// one is rendered into a command argument or into `RunResult::command_line`
/// (compared byte for byte by invariant I12, echoed into the run log, and
/// published in the generated documentation table), so a `\n`, a control
/// byte, or an unbounded length is rejected here rather than laundered into
/// an argument vector that a shell never re-interprets (this is not a shell
/// injection concern: the runner spawns with an argument vector, never a
/// shell) but that a human reading the recorded command line, the run log,
/// or the generated table absolutely does.
///
/// `sni` is validated unconditionally when present even though the oha
/// adapter's own command line never renders it (oha has no explicit SNI
/// override flag distinct from the URL host; see `plan`'s own doc): the
/// bound exists for every `Target` field regardless of which adapter is
/// asked to plan it, so a value that could never be safely rendered is
/// refused before it can reach a future caller that does render it, or a
/// log line, rather than only when this particular adapter happens to use
/// it.
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
/// promises ("when the cell is unsupported or a field is out of range"). The
/// underlying `Unsupported` variant carries per-call detail (a protocol, a
/// connection count) that `BenchError::Cell`'s `&'static str` payload cannot
/// carry, so this maps to one fixed reason per variant rather than losing the
/// distinction: a caller that wants the detail calls `supports` itself, which
/// `plan` also does, first, so the two never disagree about WHICH cells are
/// refused, only about how much detail the refusal carries.
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

/// Reads `obj[key]` as an object, naming `path` (the dotted JSON path used
/// only in the error message) when the key is absent or is not itself a
/// JSON object.
fn require_object<'a>(
    obj: &'a serde_json::Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a serde_json::Map<String, Value>, BenchError> {
    obj.get(key)
        .ok_or_else(|| BenchError::parse("oha", &format!("missing field {path}")))?
        .as_object()
        .ok_or_else(|| BenchError::parse("oha", &format!("{path} is not an object")))
}

impl LoadGenerator for Oha {
    fn name(&self) -> &'static str {
        "oha"
    }

    fn version_invocation(&self) -> Invocation {
        Invocation {
            program: "oha".to_owned(),
            args: vec!["--version".to_owned()],
            env: Vec::new(),
        }
    }

    fn parse_version(&self, stdout: &[u8]) -> Result<ToolStamp, BenchError> {
        // Checked BEFORE any decoding, per this trait's own doc: a bound
        // checked only after the bytes are already in memory is not a
        // bound.
        if stdout.len() > MAX_VERSION_OUTPUT_BYTES {
            return Err(BenchError::parse(
                "oha",
                "version output exceeds MAX_VERSION_OUTPUT_BYTES",
            ));
        }
        let text = std::str::from_utf8(stdout)
            .map_err(|_| BenchError::parse("oha", "version output is not utf-8"))?;
        // `oha --version` prints exactly `oha <version>` (confirmed against
        // the pinned binary: `oha 1.15.0\n`). The LAST whitespace-separated
        // token is taken, matching `crate::provenance::capture_build_stamp`'s
        // identical fallback rule for the same reason: every conventional
        // CLI's plain `--version` output is `<name> <version>`, and the name
        // is chosen by this adapter's own `name()`, not read from the tool.
        let version = text
            .split_whitespace()
            .next_back()
            .ok_or_else(|| BenchError::parse("oha", "version output is empty"))?;
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
        if cell.connections > MAX_CONNECTIONS {
            return Err(Unsupported::Connections {
                tool: self.name(),
                connections: cell.connections,
            });
        }
        if matches!(cell.rate, RateMode::Saturate) {
            // oha's saturate mode offers as much load as the client can
            // generate; the latency it would report describes the client's
            // own queueing, not the system under test, and there is no
            // `BenchCell` field asking for "saturate, but only for
            // throughput" that would make this refusal conditional. This is
            // the PRIMARY gate; `parse`'s own `latency_trustworthy` formula
            // is a second, independent line of defence for the same fact.
            return Err(Unsupported::RateMode { tool: self.name() });
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

        // Argument order is fixed and is part of the contract: invariant I12
        // compares the rendered `command_line` byte for byte across runs.
        // The oha `--http2` and `--insecure` flags are not shown in the
        // design's own "fixed-rate H1 cell" skeleton (which is TLS-off,
        // H1), so their position here is this adapter's own choice, made
        // once and fixed: `--http2` sits with the other output-shape flags
        // before `-c`, and `--insecure` sits immediately after
        // `--connect-to`, the flag it is paired with. Every OTHER position
        // matches the design's skeleton exactly, including which lines are
        // omitted (never reordering the survivors) when a condition is
        // false.
        let mut args: Vec<String> = Vec::with_capacity(16);
        args.push("--no-tui".to_owned());
        args.push("--output-format".to_owned());
        args.push("json".to_owned());

        if cell.protocol == Protocol::H2 {
            args.push("--http2".to_owned());
        }

        args.push("-c".to_owned());
        args.push(cell.connections.to_string());

        if let RateMode::Fixed(rate) = cell.rate {
            // `-q` is NEVER emitted without `--latency-correction`: oha's
            // default loop is closed, and a rate limit on a closed loop is
            // still a closed loop.
            args.push("-q".to_owned());
            args.push(rate.to_string());
            args.push("--latency-correction".to_owned());
        }

        args.push("-z".to_owned());
        args.push(format!("{}s", run.duration_secs));

        if cell.keepalive == KeepaliveMode::DownstreamClose {
            args.push("--disable-keepalive".to_owned());
        }
        // `KeepaliveMode::NoUpstreamPool` maps to nothing here: it is a
        // proxy-side configuration, not a client flag.

        // `scheme` and `default_port` are derived from `cell.tls`, per the
        // design's own formula, NOT from `target.scheme`: `BenchCell`, not
        // `Target`, carries the `TlsMode` distinction (`EcdsaP256` versus
        // `Rsa2048`) that decides whether `--insecure` is needed, and the
        // design writes the URL scheme formula in terms of `TlsMode::Off`
        // "and otherwise", not in terms of `Target::scheme`. A caller
        // constructing `Target` is expected to keep `target.scheme`
        // consistent with the cell it was built for; this adapter does not
        // read it back out, so the two can never disagree from this code's
        // point of view.
        let (scheme_str, default_port): (&str, u16) = match cell.tls {
            TlsMode::Off => ("http", 80),
            TlsMode::EcdsaP256 | TlsMode::Rsa2048 => ("https", 443),
        };

        args.push("--connect-to".to_owned());
        args.push(format!(
            "{}:{default_port}:{}:{}",
            target.host,
            target.connect.ip(),
            target.connect.port()
        ));

        if cell.tls != TlsMode::Off {
            // The harness uses a self-signed fixture certificate.
            args.push("--insecure".to_owned());
        }

        if cell.path_corpus != PathCorpus::SingleHot {
            // `--max-repeat 4` is NEVER omitted when `--rand-regex-url` is
            // present: an unbounded repetition operator measures the
            // path-length limit rather than the router.
            args.push("--max-repeat".to_owned());
            args.push("4".to_owned());
            args.push("--rand-regex-url".to_owned());
        }

        args.push(format!(
            "{scheme_str}://{}{}",
            target.host, target.path_expr
        ));

        Ok(Invocation {
            program: "oha".to_owned(),
            args,
            env: Vec::new(),
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one linear validate-then-extract pass over a single JSON document, matching \
                  this crate's own established parser shape (LatencyRecorder::read_hgrm in \
                  hist.rs is the same length for the same reason); splitting it into several \
                  private functions each threading the same half dozen accumulator locals would \
                  not shorten the total code, only hide the fixed check order this parser's own \
                  correctness depends on"
    )]
    fn parse(
        &self,
        ctx: &ParseCtx<'_>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<RawRun, BenchError> {
        // Both byte caps are checked on the slice length BEFORE any
        // parsing or scanning, so a runaway tool costs one comparison
        // rather than a deserialisation, and (for stderr) before the
        // substring scan below, which is itself O(stderr length).
        if stdout.len() > MAX_TOOL_OUTPUT_BYTES {
            return Err(BenchError::parse(
                "oha",
                "stdout exceeds MAX_TOOL_OUTPUT_BYTES",
            ));
        }
        if stderr.len() > MAX_TOOL_STDERR_BYTES {
            return Err(BenchError::parse(
                "oha",
                "stderr exceeds MAX_TOOL_STDERR_BYTES",
            ));
        }

        let stderr_has_rate_warning = RATE_WARNING_SUBSTRINGS
            .iter()
            .any(|w| contains_bytes(stderr, w.as_bytes()));

        // `serde_json::from_slice` validates UTF-8 itself (edge case 7: no
        // lossy conversion, ever) and enforces its own built-in 128-level
        // recursion limit at its default settings (edge case 6a): this
        // crate never widens or disables that limit, anywhere, and it is
        // the only thing between a 100,000-bracket input and a stack
        // overflow, which aborts the process rather than returning an
        // error. See the "Do NOT" list in issue #411 for the two specific
        // serde_json knobs that must never be touched for exactly this
        // reason.
        let value: Value = serde_json::from_slice(stdout)
            .map_err(|e| BenchError::parse("oha", &format!("invalid json: {e}")))?;
        let obj = value
            .as_object()
            .ok_or_else(|| BenchError::parse("oha", "top level value is not an object"))?;

        let summary = require_object(obj, "summary", "summary")?;

        // `summary.total` is a DURATION in seconds, not a request count:
        // reading it as a count would produce a plausible-looking but wrong
        // run. `is_finite()` is checked FIRST: `NaN as u64` is 0 in Rust and
        // every ordering comparison against `NaN` is false, so a range check
        // written only with `>` would accept `NaN` and yield a zero
        // duration, which then divides into a requests-per-second figure.
        //
        // HONESTLY DOCUMENTED GAP (confirmed by direct experiment against
        // this crate's exact pinned serde_json, 1.0.151, and by a watched
        // mutation while writing tests/loadgen_oha.rs): standard JSON has no
        // literal for `NaN` or `Infinity`, and serde_json's tokenizer
        // rejects both, and separately rejects any number literal whose
        // magnitude would not fit a finite f64 ("number out of range"),
        // before a `Value` is ever built. That means NO input reachable
        // through `serde_json::from_slice::<Value>` can make `total_secs`
        // itself non-finite, so removing `!total_secs.is_finite() ||` here
        // leaves every test in tests/loadgen_oha.rs green (verified). This
        // check stays anyway, matching this crate's Do NOT list and its
        // own established pattern elsewhere (`crate::guards::rate_milli_up`
        // has the identical shape for the identical reason): it is
        // defence in depth against a future change to how this value is
        // obtained (a different JSON library, a hand-rolled parser, or a
        // value that arrives by a path other than JSON), not something a
        // hostile `oha --output-format json` payload can trigger today.
        let total_secs = summary
            .get("total")
            .and_then(Value::as_f64)
            .ok_or_else(|| BenchError::parse("oha", "missing field summary.total"))?;
        if !total_secs.is_finite() || total_secs < 0.0 {
            return Err(BenchError::parse(
                "oha",
                "summary.total is not finite or is negative",
            ));
        }
        if total_secs > MAX_DURATION_SECS {
            return Err(BenchError::parse(
                "oha",
                "summary.total exceeds the maximum plausible run duration",
            ));
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "total_secs is finite, in [0.0, MAX_DURATION_SECS] (86_400.0) by the two \
                      guards immediately above, so total_secs * 1e9 is at most 8.64e13, over five \
                      orders of magnitude below u64::MAX (~1.8e19): this can never truncate an \
                      out-of-range value or wrap a sign"
        )]
        let duration_ns = (total_secs * 1_000_000_000.0) as u64;
        if duration_ns == 0 {
            // A zero duration is not a fast run; it is an output no
            // downstream arithmetic (a requests-per-second figure) can use.
            return Err(BenchError::parse(
                "oha",
                "summary.total yields a zero duration_ns",
            ));
        }

        // Parsed as u64 directly, NEVER through f64: above 2^53 an f64
        // cannot represent consecutive integers, so a count round-tripped
        // through a float is silently wrong at exactly the magnitudes that
        // matter. `Value::as_u64` returns `None` for a JSON number stored
        // as a float (for example a literal with a decimal point), which is
        // exactly the rejection this rule requires, not merely an
        // optimisation.
        let bytes_received = summary
            .get("totalData")
            .and_then(Value::as_u64)
            .ok_or_else(|| BenchError::parse("oha", "missing field summary.totalData"))?;

        let status_map_raw =
            require_object(obj, "statusCodeDistribution", "statusCodeDistribution")?;
        if status_map_raw.is_empty() {
            // A run with no responses is not a run.
            return Err(BenchError::parse("oha", "statusCodeDistribution is empty"));
        }
        if status_map_raw.len() > MAX_STATUS_CODES {
            return Err(BenchError::parse(
                "oha",
                "statusCodeDistribution has more than 64 distinct status codes",
            ));
        }

        let mut status_counts: BTreeMap<u16, u64> = BTreeMap::new();
        let mut status_sum: u128 = 0;
        for (key, val) in status_map_raw {
            // oha emits STRING keys. A key that does not parse as a u16 in
            // 100..=599 fails the whole parse, naming the key: silently
            // skipping it would lose errors.
            let code: u16 = key
                .parse::<u16>()
                .ok()
                .filter(|c| (100..=599).contains(c))
                .ok_or_else(|| {
                    BenchError::parse(
                        "oha",
                        &format!("statusCodeDistribution key {key} is not a status code 100..=599"),
                    )
                })?;
            let count = val.as_u64().ok_or_else(|| {
                BenchError::parse(
                    "oha",
                    &format!("statusCodeDistribution[{key}] is not a u64"),
                )
            })?;
            status_sum = status_sum.saturating_add(u128::from(count));
            status_counts.insert(code, count);
        }
        let responses_ok = status_counts.get(&200).copied().unwrap_or(0);

        let error_map = require_object(obj, "errorDistribution", "errorDistribution")?;
        let mut error_sum: u128 = 0;
        for (key, val) in error_map {
            let count = val.as_u64().ok_or_else(|| {
                BenchError::parse("oha", &format!("errorDistribution[{key}] is not a u64"))
            })?;
            error_sum = error_sum.saturating_add(u128::from(count));
        }

        // `requests_sent` is `sum(status_counts) + errors`, computed in
        // u128 and checked against MAX_REPORTED_REQUESTS BEFORE narrowing.
        // A u64 sum of two hostile buckets (for example two entries at
        // u64::MAX) wraps into a small number that satisfies every later
        // comparison; u128 cannot wrap for any input this parser's own
        // 16 MiB stdout cap can encode.
        let requests_sent_u128 = status_sum.saturating_add(error_sum);
        if requests_sent_u128 > u128::from(MAX_REPORTED_REQUESTS) {
            return Err(BenchError::parse(
                "oha",
                "requests_sent exceeds MAX_REPORTED_REQUESTS",
            ));
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "requests_sent_u128 is checked <= MAX_REPORTED_REQUESTS (a u64 constant) \
                      immediately above, so this narrowing cannot truncate"
        )]
        let requests_sent = requests_sent_u128 as u64;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "error_sum <= requests_sent_u128 <= MAX_REPORTED_REQUESTS by construction \
                      (it is one of the two addends checked above), so this narrowing cannot \
                      truncate either"
        )]
        let errors = error_sum as u64;

        // Reconstructed from `latencyPercentiles`: oha reports percentiles,
        // not a histogram, so this is an APPROXIMATION. `latency_exact` is
        // false for oha, always, and this is never "improved" to claim
        // otherwise: the honest representation of "we only have nine
        // quantile points" is `latency_exact: false`.
        let percentiles_obj = require_object(obj, "latencyPercentiles", "latencyPercentiles")?;
        let mut recorder = LatencyRecorder::new()?;
        let mut prev_quantile = 0.0_f64;
        let mut prev_value_ns: Option<u64> = None;
        #[expect(
            clippy::cast_precision_loss,
            reason = "requests_sent is <= MAX_REPORTED_REQUESTS (1e12), comfortably inside f64's \
                      2^53 (~9.007e15) exact-integer range, so this conversion loses no precision \
                      that matters for a reconstruction weight"
        )]
        let requests_sent_f = requests_sent as f64;
        for (key, quantile) in PERCENTILE_KEYS {
            let value_secs = percentiles_obj
                .get(key)
                .and_then(Value::as_f64)
                .ok_or_else(|| {
                    BenchError::parse("oha", &format!("missing field latencyPercentiles.{key}"))
                })?;
            if !value_secs.is_finite() || value_secs < 0.0 {
                return Err(BenchError::parse(
                    "oha",
                    &format!("latencyPercentiles.{key} is not finite or is negative"),
                ));
            }
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "value_secs is finite and non-negative by the guard immediately above; \
                          a percentile value at all plausible for an HTTP benchmark is many \
                          orders of magnitude below u64::MAX / 1e9, and record_n_ns below floors \
                          or out-of-ranges whatever this cast produces, so no caller ever trusts \
                          this bit pattern without record_n_ns's own re-validation"
            )]
            let value_ns = (value_secs * 1_000_000_000.0) as u64;

            // Percentile values must be monotone non-decreasing as the
            // quantile increases (edge case 8): a tool bug or a mangled
            // fixture producing p99 below p50 would reconstruct a histogram
            // whose own p50 exceeds its p99, which is not a real
            // distribution.
            if let Some(prev) = prev_value_ns
                && value_ns < prev
            {
                return Err(BenchError::parse(
                    "oha",
                    "latencyPercentiles values are not monotone non-decreasing",
                ));
            }
            prev_value_ns = Some(value_ns);

            // Each reported percentile is recorded ONCE, weighted by the
            // gap to the previous percentile: the fraction of requests
            // between the previous quantile and this one is assumed to
            // land at this percentile's own reported value. This is a
            // documented, deliberate approximation (see the module doc):
            // the top `1.0 - 0.9999` of requests, above the highest
            // reported percentile, is not represented at all, which is
            // exactly what "reconstructed from percentiles, not a
            // histogram" means.
            let gap = quantile - prev_quantile;
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "gap is in (0.0, 1.0] by construction (PERCENTILE_KEYS's quantiles are \
                          fixed, strictly increasing literals), and requests_sent_f is \
                          non-negative, so gap * requests_sent_f is non-negative and at most \
                          requests_sent_f; .round().clamp(0.0, requests_sent_f) bounds it to a \
                          value representable in u64 before this cast"
            )]
            let weight = (gap * requests_sent_f).round().clamp(0.0, requests_sent_f) as u64;
            // Values above HIGH_NS are counted in `out_of_range` by
            // `record_n_ns` itself, never clamped into the top bucket: see
            // edge case 9, "a percentile above 60 seconds... fails
            // invariant I7 and invalidates the run rather than silently
            // truncating."
            recorder.record_n_ns(value_ns, weight);
            prev_quantile = quantile;
        }

        // ttfb, connect and stall are `None` for oha. The Parsing table
        // this module implements lists exactly seven `RawRun` fields to
        // reconstruct (duration_ns, status_counts, responses_ok, errors,
        // requests_sent, bytes_received, latency); ttfb and connect are not
        // among them even though oha's own JSON exposes `firstByte` and
        // `details.DNSDialup` data, and stall (the coordinated-omission
        // indicator) is explicitly Nighthawk-only per this trait's own
        // module doc (`sequencer.blocking`). Leaving all three unset matches
        // the issue's Parsing table as written rather than inventing a
        // reconstruction it does not specify.
        let latency_trustworthy =
            matches!(ctx.cell.rate, RateMode::Fixed(_)) && !stderr_has_rate_warning;

        // Edge case 10 (issue #411) also asks that a rate-warning stderr
        // line be included "in RawRun's debug output". `RawRun`'s Public
        // API, given verbatim by the issue, has no field for it: every
        // existing field has its own documented meaning (`command_line` in
        // particular is compared byte for byte by invariant I12 and must
        // stay an exact, printable-ASCII rendering of the `Invocation`), and
        // none is an appropriate place to fold in unrelated stderr text
        // without corrupting that meaning. This is the same shape of gap
        // `Validity::LoadgenSuspect` documents in `result.rs`: a clause
        // asking for something the given struct shape has no field to carry.
        // This adapter still performs the part of edge case 10 the struct
        // CAN express (`latency_trustworthy` above already goes false the
        // instant `stderr_has_rate_warning` is true, independent of
        // `RateMode`), it just does not surface the matched line itself.
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
            latency_exact: false,
            latency_trustworthy,
        })
    }
}
