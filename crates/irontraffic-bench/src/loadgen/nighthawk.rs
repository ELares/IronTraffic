// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `Nighthawk` adapter: the arbiter of every published latency number.
//!
//! Every other adapter in this crate measures a sweep or a developer loop;
//! this one is the only tool whose output may become a headline latency
//! figure, because it is the only one that (a) reports the full `HdrHistogram`
//! percentile ladder rather than nine fixed quantile points, (b) separates
//! `queue_to_connect` (connection establishment) from request latency, and
//! (c) treats coordinated omission as a first-class MEASURED quantity
//! (`sequencer.blocking`) rather than a footnote. It runs from an OCI image
//! referenced by digest, never by tag, and always in `--open-loop` mode for a
//! fixed-rate cell.
//!
//! # What this fixture is and is NOT
//!
//! Every other adapter fixture in this crate (`tests/fixtures/oha-1.15.0.json`)
//! is a REAL capture: the pinned binary, installed locally, run once against a
//! local server. This issue's own Design section asks for the same discipline
//! here ("Capture `fixtures/nighthawk-output.json` from the pinned image
//! FIRST and write the tables against it"), and that could not be done: this
//! implementation environment has neither `docker` nor `podman` installed, and
//! has no way to install either, so `envoyproxy/nighthawk-dev` could never be
//! pulled or run. `tests/fixtures/nighthawk-output.json` is therefore
//! RECONSTRUCTED, not captured, from three independent sources that do not
//! require running the image:
//!
//! 1. This issue's own Context and Design sections (the `results`/`statistics`/
//!    `counters`/`percentiles` shape, the four statistic ids, the counter
//!    names, the protobuf `Duration` string form).
//! 2. The real, public `envoyproxy/nighthawk` source at the `main` branch,
//!    fetched over HTTPS on 2026-07-31 (no `docker`/`git clone` involved,
//!    just reading published source files): `api/client/output.proto` (the
//!    `Output`/`Result`/`Statistic`/`Percentile`/`Counter` message shapes),
//!    `source/client/benchmark_client_impl.cc` (the `benchmark.` counter
//!    scope prefix and the four `benchmark_http_client.*` statistic ids),
//!    `source/client/output_collector_impl.cc` and
//!    `source/common/statistic_impl.cc` (which serialisation domain each
//!    statistic id uses, and that a `Percentile`'s `duration` field, not
//!    `raw_value`, is populated for every id this parser reads),
//!    `source/common/sequencer_impl.cc` (`sequencer.callback` and
//!    `sequencer.blocking`'s exact ids), and `docs/root/statistics.md` /
//!    `docs/root/terminology.md` (already quoted by this issue itself).
//! 3. The protobuf proto3 canonical JSON mapping
//!    (<https://protobuf.dev/programming-guides/proto3/#json>), which encodes
//!    every 64-bit integer field (`uint64 count`, `uint64 value`) as a JSON
//!    STRING rather than a JSON number, specifically because a JSON number
//!    cannot represent every `int64`/`uint64` value exactly. Envoy's own
//!    `MessageUtil::getJsonStringFromMessage` (which `JsonOutputFormatterImpl`
//!    calls) wraps the standard protobuf JSON printer with no override of
//!    this behaviour. [`read_u64`] below therefore reads a count or a value as
//!    EITHER a JSON string of decimal digits (the form source (3) predicts is
//!    the real one) or a bare JSON number (accepted defensively, since this
//!    reading could not be checked against the pinned image either).
//!
//! This is honestly weaker than a genuine capture, and the exact evidence
//! trail above is recorded so a reviewer can independently re-derive every
//! field name this parser reads. Two concrete discrepancies this cross-check
//! surfaced, both immaterial to correctness because neither field is ever
//! read by this parser:
//!
//! - This issue's own Context fact 5 describes each statistic as carrying
//!   `raw_mean`/`raw_pstdev`, and `tests/fixtures/nighthawk-output.json`'s
//!   `"global"` statistics carry exactly those two fields, per that fact,
//!   verbatim. Source (2) above shows `output_collector_impl.cc` selects the
//!   serialisation domain by whether the statistic id ends in `"_size"`;
//!   none of the four ids this parser reads do, so upstream would actually
//!   populate `mean`/`pstdev`/`min`/`max` (`google.protobuf.Duration` fields)
//!   rather than the `raw_*` doubles for those four. The fixture therefore
//!   follows the issue's own literal Context text rather than this module's
//!   own more precise source cross-check; both readings are recorded here so
//!   a reviewer can tell the fixture matched the ISSUE, not that it matched
//!   the real image. This parser reads neither shape, so the discrepancy
//!   does not change its behaviour either way.
//! - `RawRun::duration_ns` is not named by this issue's own Design or Context
//!   sections at all. The `Result` proto (source (2)) carries an
//!   `execution_duration` field of exactly the right type and purpose, so
//!   this parser reads that; this is this adapter's own choice where the
//!   issue is silent, not something stated in the issue.
//!
//! # A tension this issue's own text raised, now resolved: the floor is
//! # LATENCY-only
//!
//! An earlier reading of this module applied the [`MIN_PERCENTILE_ENTRIES`]
//! floor uniformly to every statistic, because the "Reconstructing the
//! recorder" design section states its seven assertions apply "for each
//! statistic". That reading was demonstrated wrong by execution, not by
//! argument: `sequencer.blocking` measures a fundamentally rarer event than
//! request latency (a healthy open-loop run is DEFINED by having little or
//! no blocking, per this issue's own epigraph), and an `HdrHistogram`
//! percentile iterator cannot emit more distinct rows than it recorded
//! samples. A run with 5, 20 or 63 stalls therefore cannot produce 64
//! percentile rows no matter how healthy it is, so the uniform floor made
//! `Nighthawk::parse` reject exactly the clean runs it exists to certify
//! while admitting badly blocked ones (which have many distinct stall
//! durations and so clear 64 rows easily): the arbiter's gate was inverted.
//! This is exactly the failure this issue's own Design section warns
//! against ("Do NOT keep a floor a real run cannot meet, because then every
//! run fails and the first fix anyone reaches for is setting
//! `latency_exact = true` unconditionally").
//!
//! The floor is therefore applied ONLY to `benchmark_http_client.request_to_response`,
//! the one statistic whose reconstruction decides [`RawRun::latency_exact`].
//! `benchmark_http_client.queue_to_connect` and `sequencer.blocking` are both
//! reconstructed with [`PercentileFloor::NotEnforced`]: every OTHER check
//! (max entries, strictly increasing percentiles, non-decreasing durations
//! and counts, the [`super::MAX_REPORTED_REQUESTS`] cap, and the
//! reconciliation against the statistic's own declared `count`) still
//! applies in full, and invariant 2 (`sequencer.blocking` must be PRESENT and
//! well-formed) is untouched; only the minimum ROW COUNT is no longer
//! required of these two. This narrows the issue's own "for each statistic"
//! wording for the two statistics that do not set `latency_exact`, on the
//! evidence above (a floor a real healthy run structurally cannot meet is
//! worse than no floor at all), not merely to make CI pass. See
//! `parse_low_blocking_run_is_ok` and `parse_low_connect_sample_run_is_ok` in
//! `tests/loadgen_nighthawk.rs`, each of which is watched to FAIL against the
//! old uniform floor and to PASS once it is scoped to latency alone.
//!
//! Whether the pinned image's `request_to_response` statistic itself always
//! clears 64 rows on a legitimate full-length run remains UNVERIFIED here,
//! for the same reason nothing else in this module was verified against a
//! live run: this could not be tested without `docker`/`podman`. Re-verify
//! against the pinned image before this adapter is trusted for a real run,
//! per the Design's own instruction to read the floor off a captured
//! full-length fixture and lower it if a legitimate run cannot clear it.
//!
//! # Two more honest gaps in the invocation
//!
//! This issue's own flag surface (context fact 3) and fixed argument order
//! (the Design's "The invocation" section) say nothing about how `TlsMode` or
//! `PathCorpus` map onto a Nighthawk invocation, unlike `Oha`'s own design,
//! which spells out both. Neither is exercised by any of this issue's 19
//! named tests or its acceptance criteria, so:
//!
//! - **TLS.** `plan` selects `https` for `TlsMode::EcdsaP256`/`Rsa2048` and
//!   `http` for `TlsMode::Off`, mirroring `Oha::plan`'s identical formula
//!   (the only precedent in this crate), but adds no certificate-validation
//!   override: this issue's flag surface has nothing resembling `Oha`'s own
//!   `--insecure`. A TLS cell measured against the harness's self-signed
//!   certificate may need a flag this issue does not name.
//! - **Path corpus.** `Oha` varies its request path via `--rand-regex-url`
//!   for `PathCorpus::UniformRandom`/`AdversarialWorstCase`; this issue's flag
//!   surface has no analogous mechanism, so `Nighthawk::plan` always renders
//!   `target.path_expr` as the URL's single literal path and `cell.path_corpus`
//!   has no effect on the invocation at all. This is not an omission of
//!   something asked for: the issue simply does not ask for it.
//!
//! # Untrusted input
//!
//! [`Nighthawk::parse`]'s `stdout` and `stderr` are the captured output of a
//! SEPARATE process (the containerised tool), exactly the untrusted-input
//! boundary this crate's `loadgen` module doc already documents for every
//! adapter; see that doc for the caller-side capture-time bound this parser's
//! own [`super::MAX_TOOL_OUTPUT_BYTES`]/[`super::MAX_TOOL_STDERR_BYTES`]
//! checks are the second, redundant line of defence for.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::cell::{BenchCell, KeepaliveMode, Protocol, RateMode, TlsMode};
use crate::error::BenchError;
use crate::hist::LatencyRecorder;
use crate::provenance::{SMALL_FILE_CAP, ToolStamp, read_bounded};

use super::{Invocation, MAX_HOST_BYTES, MAX_PATH_EXPR_BYTES, MAX_REPORTED_REQUESTS};
use super::{LoadGenerator, ParseCtx, RawRun, RunParams, Target, Unsupported};
use super::{MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_STDERR_BYTES, MAX_VERSION_OUTPUT_BYTES};

/// Minimum percentile entries a statistic must carry for `latency_exact` to
/// hold. See the module doc's "the floor is LATENCY-only" section: this
/// floor is enforced ONLY when reconstructing
/// `benchmark_http_client.request_to_response`, the statistic that decides
/// `latency_exact`. `queue_to_connect` and `sequencer.blocking` are
/// reconstructed with [`PercentileFloor::NotEnforced`]: an `HdrHistogram`
/// percentile iterator cannot emit more distinct rows than it recorded
/// samples, and near-zero blocking is the definition of a healthy open-loop
/// run, so this floor applied to either would reject exactly the clean runs
/// the arbiter exists to certify.
pub const MIN_PERCENTILE_ENTRIES: usize = 64;

/// Maximum percentile entries the parser will read from one statistic.
pub const MAX_PERCENTILE_ENTRIES: usize = 4096;

/// Maximum statistics the parser will read from one result entry.
pub const MAX_STATISTICS: usize = 32;

/// Maximum counters the parser will read from one result entry.
pub const MAX_COUNTERS: usize = 512;

/// Maximum result entries the parser will scan while looking for `"global"`.
pub const MAX_RESULT_ENTRIES: usize = 256;

/// Maximum seconds a parsed protobuf `Duration` may express.
pub const MAX_DURATION_SECONDS: u64 = 86_400;

/// Longest raw digest-file content [`Nighthawk::from_pin`] will read, before
/// trimming and matching against the exact 71 byte
/// `^sha256:[0-9a-f]{64}$` shape. Generous relative to that 71 byte target so
/// ordinary leading/trailing whitespace never trips this cap, while still
/// bounding a hostile or truncated file. Reuses `provenance::SMALL_FILE_CAP`
/// rather than inventing a new magic number for the same purpose.
const MAX_DIGEST_FILE_BYTES: usize = SMALL_FILE_CAP;

/// Exact byte length of a valid digest: `sha256:` (7 bytes) plus 64 lowercase
/// hex digits.
const DIGEST_BYTES: usize = 71;

/// Longest `image_repo` [`Nighthawk::from_pin`] will accept, in bytes.
const MAX_IMAGE_REPO_BYTES: usize = 255;

/// Longest `client_cores` [`Nighthawk::from_pin`] will accept, in bytes.
const MAX_CLIENT_CORES_BYTES: usize = 64;

/// Nighthawk statistic id this parser maps onto `RawRun::latency`. Version
/// specific and UNVERIFIED against a live run; see the module doc.
const STATISTIC_ID_LATENCY: &str = "benchmark_http_client.request_to_response";
/// Nighthawk statistic id this parser maps onto `RawRun::connect`.
const STATISTIC_ID_CONNECT: &str = "benchmark_http_client.queue_to_connect";
/// Nighthawk statistic id this parser maps onto `RawRun::stall`, the
/// coordinated-omission detector. Never `sequencer.callback`: that id
/// measures the OPPOSITE thing, the latency of requests that were NOT
/// blocked.
const STATISTIC_ID_STALL: &str = "sequencer.blocking";

/// Nighthawk counter name this parser maps onto `RawRun::requests_sent`.
const COUNTER_REQUESTS_SENT: &str = "upstream_rq_total";
/// Nighthawk counter name this parser maps onto `RawRun::responses_ok`.
const COUNTER_RESPONSES_OK: &str = "benchmark.http_2xx";
/// One of the two Nighthawk counters summed onto `RawRun::errors`.
const COUNTER_POOL_CONNECTION_FAILURE: &str = "benchmark.pool_connection_failure";
/// The other of the two Nighthawk counters summed onto `RawRun::errors`.
const COUNTER_STREAM_RESETS: &str = "benchmark.stream_resets";
/// Nighthawk counter name this parser maps onto `RawRun::bytes_received`.
const COUNTER_BYTES_RECEIVED: &str = "upstream_cx_rx_bytes_total";

/// Which container runtime to invoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerRuntime {
    /// `docker`.
    Docker,
    /// `podman`.
    Podman,
}

impl ContainerRuntime {
    /// The program name this variant renders as `Invocation::program`.
    fn program(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

/// The Nighthawk adapter. The arbiter of every published latency number.
///
/// Runs from an OCI image referenced by digest, always with `--open-loop` for
/// fixed-rate cells. It is the only tool that reports `sequencer.blocking`,
/// our coordinated-omission detector, and the only one that separates
/// `queue_to_connect` from request latency.
#[derive(Debug, Clone)]
pub struct Nighthawk {
    /// `docker` or `podman`.
    pub runtime: ContainerRuntime,
    /// Image reference including the `@sha256:` digest, read from
    /// `bench/tools/nighthawk.digest`.
    pub image: String,
    /// Cores the client container is confined to, rendered into
    /// `--cpuset-cpus`.
    pub client_cores: String,
}

/// True when `b` is `[a-z0-9._/-]`, `image_repo`'s allowed character class.
fn is_image_repo_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b"._/-".contains(&b)
}

/// True when `b` is `[0-9,-]`, `client_cores`'s allowed character class.
fn is_client_cores_char(b: u8) -> bool {
    b.is_ascii_digit() || b == b',' || b == b'-'
}

/// True when `b` is a lowercase hex digit, a digest's allowed character
/// class.
fn is_hex_lower(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// Validates `image_repo` against the Bounds table: at most
/// [`MAX_IMAGE_REPO_BYTES`], class `[a-z0-9._/-]`, must not begin with `-` or
/// `.`, must contain no `//`. `image_repo` is interpolated into the `docker
/// run` argument vector immediately before `nighthawk_client`, a position the
/// container runtime reads as a FLAG when the value begins with `-`: a value
/// equal to the runtime's own full-privilege-escalation flag would make the
/// runtime consume it as a flag and read the literal `nighthawk_client`
/// token as the image name instead, a real privilege escalation out of a
/// field that looks inert. The argument vector itself only prevents shell
/// injection; only this validation prevents argument injection.
///
/// # Errors
/// `BenchError::Parse` naming `image_repo`.
fn validate_image_repo(s: &str) -> Result<(), BenchError> {
    if s.is_empty()
        || s.len() > MAX_IMAGE_REPO_BYTES
        || !s.bytes().all(is_image_repo_char)
        || s.starts_with('-')
        || s.starts_with('.')
        || s.contains("//")
    {
        return Err(BenchError::parse(
            "nighthawk",
            "image_repo violates its length, character class, or shape bound",
        ));
    }
    Ok(())
}

/// Validates `client_cores` against the Bounds table: non-empty, at most
/// [`MAX_CLIENT_CORES_BYTES`], class `[0-9,-]`, must not begin with `-`.
/// `client_cores` is interpolated as `--cpuset-cpus`'s VALUE, so a value
/// beginning with `-` (for example the runtime's own full-privilege-escalation
/// flag) is read as the NEXT flag rather than as `--cpuset-cpus`'s argument,
/// whatever it looks like.
///
/// # Errors
/// `BenchError::Parse` naming `client_cores`.
fn validate_client_cores(s: &str) -> Result<(), BenchError> {
    if s.is_empty()
        || s.len() > MAX_CLIENT_CORES_BYTES
        || s.starts_with('-')
        || !s.bytes().all(is_client_cores_char)
    {
        return Err(BenchError::parse(
            "nighthawk",
            "client_cores violates its length, character class, or shape bound",
        ));
    }
    Ok(())
}

/// Validates a trimmed digest string matches `^sha256:[0-9a-f]{64}$` exactly:
/// exactly [`DIGEST_BYTES`] bytes, the literal `sha256:` prefix, and 64
/// lowercase hex digits after it. No indexing: `str::get` is used throughout
/// so a malformed, too-short input is a bounds-checked `None`, never a panic.
///
/// # Errors
/// `BenchError::Parse` when the shape does not match. A tag (for example
/// `latest`) or a two-line file both fail this check: neither is 71 bytes of
/// exactly `sha256:` plus 64 hex digits.
fn validate_digest(trimmed: &str) -> Result<(), BenchError> {
    const PREFIX: &str = "sha256:";
    let ok = trimmed.len() == DIGEST_BYTES
        && trimmed.starts_with(PREFIX)
        && trimmed
            .as_bytes()
            .get(PREFIX.len()..)
            .is_some_and(|rest| rest.iter().all(|&b| is_hex_lower(b)));
    if ok {
        Ok(())
    } else {
        Err(BenchError::parse(
            "nighthawk",
            "digest file does not match ^sha256:[0-9a-f]{64}$",
        ))
    }
}

impl Nighthawk {
    /// Builds the adapter, reading and validating the pinned digest.
    ///
    /// Reads `digest_path`, trims leading and trailing ASCII whitespace, and
    /// requires the remainder to be a single line matching
    /// `^sha256:[0-9a-f]{64}$`. `self.image` is then exactly
    /// `format!("{image_repo}@{digest}")`, for example
    /// `envoyproxy/nighthawk-dev@sha256:0a1b...`. There is no other way to
    /// build `image`, and no code path anywhere joins `image_repo` with a
    /// tag.
    ///
    /// `image_repo` and `client_cores` are validated here too, once, at
    /// construction, per the Design's own "checked once, at construction, so
    /// `plan` cannot be reached with an unvalidated field."
    ///
    /// # Errors
    /// `BenchError::Io` when the digest file is unreadable, `BenchError::Parse`
    /// when the trimmed content contains a newline or does not match
    /// `^sha256:[0-9a-f]{64}$`, or when `image_repo` or `client_cores`
    /// violates its own bound.
    pub fn from_pin(
        runtime: ContainerRuntime,
        digest_path: &std::path::Path,
        image_repo: &str,
        client_cores: &str,
    ) -> Result<Self, BenchError> {
        validate_image_repo(image_repo)?;
        validate_client_cores(client_cores)?;

        let raw = read_bounded(digest_path, MAX_DIGEST_FILE_BYTES)?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| BenchError::parse("nighthawk", "digest file is not utf-8"))?;
        let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
        validate_digest(trimmed)?;

        Ok(Self {
            runtime,
            image: format!("{image_repo}@{trimmed}"),
            client_cores: client_cores.to_owned(),
        })
    }
}

/// True when `s` is at most `cap` bytes and every byte satisfies `allowed`.
/// Mirrors `oha.rs`'s own identically named helper: that one is private to
/// its module and `oha.rs` is not one of this issue's declared files, so this
/// is a second, small copy rather than a cross-module dependency on a
/// sibling adapter's private code.
fn bounded(s: &str, cap: usize, allowed: fn(u8) -> bool) -> bool {
    s.len() <= cap && s.bytes().all(allowed)
}

/// `Target::host`/`Target::sni`'s allowed character class.
fn is_host_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

/// `Target::path_expr`'s allowed character class: printable ASCII excluding
/// space, matching the Bounds table's `0x21..=0x7E` class.
fn is_path_expr_char(b: u8) -> bool {
    (0x21..=0x7E).contains(&b)
}

/// Bounds-checks `target`'s three string fields. Every `Target` field is
/// validated regardless of whether THIS adapter's own command line renders
/// it (`sni` is checked even though `plan` below never emits it), matching
/// `oha.rs`'s own `validate_target` and its stated reasoning: a value that
/// could never be safely rendered is refused before it reaches a future
/// caller that does render it, or a log line.
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

/// Reads a protobuf-JSON-encoded `uint64` field. See the module doc's item
/// (3): the canonical protobuf JSON mapping encodes every 64-bit integer type
/// as a JSON STRING, so a string of decimal digits is the PRIMARY form this
/// reads; a bare JSON number is also accepted, defensively, since this crate
/// could not check the reading against a live run.
fn read_u64(value: &Value, field: &str) -> Result<u64, BenchError> {
    match value {
        Value::Number(n) => n.as_u64().ok_or_else(|| {
            BenchError::parse(
                "nighthawk",
                &format!("{field} is not a non-negative integer"),
            )
        }),
        Value::String(s) => s.parse::<u64>().map_err(|_| {
            BenchError::parse(
                "nighthawk",
                &format!("{field} is not a decimal integer string"),
            )
        }),
        _ => Err(BenchError::parse(
            "nighthawk",
            &format!("{field} is neither a number nor a string"),
        )),
    }
}

/// Parses a protobuf `Duration` string (`"0.000123s"`, `"1s"`) into
/// nanoseconds, entirely with integer arithmetic: strip the trailing `s`,
/// split once on `.`, parse the whole part as a `u64` bounded at
/// [`MAX_DURATION_SECONDS`], and parse the fraction by taking its first 9
/// digits (right-padded with zeros to exactly 9) as a `u64`.
///
/// Never routed through a floating-point conversion: `"nans"`, `"infs"`,
/// `"-1s"` and `"1e309s"` all strip to a string the standard library's own
/// floating-point string parser happily accepts (`"nan"`, `"inf"`, `"-1"`,
/// `"1e309"`), and casting a not-a-number floating value to an unsigned
/// integer yields `0` in Rust while an infinite one saturates, so that route
/// would turn a hostile or truncated duration into either a zero-nanosecond
/// sample or a 60 second one, silently. Every whole-part and fractional-part
/// check below is a byte-class scan (`is_ascii_digit`), which accepts none
/// of those four strings, so that route is never reached.
///
/// # Errors
/// `BenchError::Parse` naming the malformed string, for any input other than
/// `<digits>[.<digits>]s` with a whole part at most [`MAX_DURATION_SECONDS`].
fn parse_protobuf_duration(s: &str) -> Result<u64, BenchError> {
    let Some(body) = s.strip_suffix('s') else {
        return Err(BenchError::parse(
            "nighthawk",
            &format!("duration {s:?} does not end in 's'"),
        ));
    };

    let (whole_str, frac_str) = match body.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (body, None),
    };

    if whole_str.is_empty() || !whole_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BenchError::parse(
            "nighthawk",
            &format!("duration {s:?} has a non-digit or empty whole-seconds part"),
        ));
    }
    let whole: u64 = whole_str.parse().map_err(|_| {
        BenchError::parse(
            "nighthawk",
            &format!("duration {s:?} whole part does not fit u64"),
        )
    })?;
    if whole > MAX_DURATION_SECONDS {
        return Err(BenchError::parse(
            "nighthawk",
            &format!("duration {s:?} exceeds MAX_DURATION_SECONDS ({MAX_DURATION_SECONDS})"),
        ));
    }

    let frac_ns: u64 = match frac_str {
        None => 0,
        Some(f) => {
            if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                return Err(BenchError::parse(
                    "nighthawk",
                    &format!("duration {s:?} has a non-digit or empty fractional part"),
                ));
            }
            // Only the first 9 digits carry meaning (protobuf `Duration`'s
            // own nanosecond resolution); anything past that is truncated,
            // never an error (edge case 12b). A fraction shorter than 9
            // digits is right-padded with zeros so "000123" (6 digits) means
            // 123,000 nanoseconds, not 123.
            let mut nine = String::with_capacity(9);
            for c in f.chars().take(9) {
                nine.push(c);
            }
            while nine.len() < 9 {
                nine.push('0');
            }
            nine.parse().map_err(|_| {
                BenchError::parse(
                    "nighthawk",
                    &format!("duration {s:?} fractional part does not fit u64"),
                )
            })?
        }
    };

    // `whole` <= MAX_DURATION_SECONDS (86_400) and `frac_ns` < 1_000_000_000
    // (at most 9 decimal digits), so this product-plus-sum is at most
    // roughly 8.64e13, five orders of magnitude below u64::MAX (~1.8e19):
    // this cannot overflow.
    Ok(whole * 1_000_000_000 + frac_ns)
}

/// Finds the first `statistics` array entry whose `id` field equals `id`. A
/// malformed entry (not an object, or with a non-string `id`) is treated
/// like an entry with a DIFFERENT id: this parser reads by id from a fixed,
/// enumerated table (the `STATISTIC_ID_*` constants) and tolerates every
/// entry it does not need, exactly like [`find_counter`]'s identical
/// "linear scan, first match" shape.
fn find_statistic<'a>(
    statistics: &'a [Value],
    id: &str,
) -> Option<&'a serde_json::Map<String, Value>> {
    statistics.iter().find_map(|entry| {
        let obj = entry.as_object()?;
        let this_id = obj.get("id")?.as_str()?;
        (this_id == id).then_some(obj)
    })
}

/// Finds `name` in the `counters` array and reads its `value`, or fails
/// naming it. Per this issue's own Do NOT list: "Do NOT default a missing
/// statistic or counter to zero. Fail naming it." A malformed entry (not an
/// object, or with a non-string `name`) is skipped, exactly like
/// [`find_statistic`].
///
/// # Errors
/// `BenchError::Parse` naming `name` when no counter entry has that name, or
/// naming it when present but its `value` field is missing or malformed.
fn find_counter(counters: &[Value], name: &str) -> Result<u64, BenchError> {
    for entry in counters {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let Some(counter_name) = obj.get("name").and_then(Value::as_str) else {
            continue;
        };
        if counter_name == name {
            let value = obj.get("value").ok_or_else(|| {
                BenchError::parse("nighthawk", &format!("counter {name} has no value field"))
            })?;
            return read_u64(value, &format!("counter {name}"));
        }
    }
    Err(BenchError::parse(
        "nighthawk",
        &format!("missing counter {name}"),
    ))
}

/// Whether [`reconstruct_statistic`] enforces the [`MIN_PERCENTILE_ENTRIES`]
/// row-count floor for the statistic it is reconstructing. See the module
/// doc's "the floor is LATENCY-only" section for why this exists: the floor
/// protects `latency_exact`, a flag only the latency statistic sets, and an
/// `HdrHistogram` percentile iterator cannot emit more distinct rows than it
/// recorded samples, so applying it to a rare-event statistic like
/// `sequencer.blocking` would reject exactly the healthy runs the arbiter
/// exists to certify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PercentileFloor {
    /// Require at least [`MIN_PERCENTILE_ENTRIES`] rows. Used only for
    /// `benchmark_http_client.request_to_response`.
    Enforced,
    /// No row-count floor. Every other check (max entries, strictly
    /// increasing percentiles, non-decreasing durations and counts, the
    /// [`super::MAX_REPORTED_REQUESTS`] cap, and the reconciliation against
    /// the statistic's own declared `count`) still applies in full; only the
    /// minimum row count is not required. Used for `queue_to_connect` and
    /// `sequencer.blocking`.
    NotEnforced,
}

/// Reconstructs a `LatencyRecorder` from one Nighthawk `Statistic` JSON
/// object's `percentiles` array, per the Design's "Reconstructing the
/// recorder" section: for each ascending percentile entry, `count_i -
/// count_{i-1}` samples are recorded at `duration_i`. `stat_id` is used only
/// in error messages, so a failure names which statistic it came from.
///
/// `floor` decides whether [`MIN_PERCENTILE_ENTRIES`] is enforced; every
/// OTHER check below runs unconditionally for every statistic this adapter
/// reconstructs (latency, connect, stall), so there is exactly one
/// reconstruction routine here, never a separate one per statistic. See the
/// module doc's "the floor is LATENCY-only" section for why the row-count
/// floor alone is scoped to the statistic that sets `latency_exact`.
///
/// # Errors
/// `BenchError::Parse` on a missing or malformed `count`/`percentiles` field,
/// fewer than [`MIN_PERCENTILE_ENTRIES`] entries when `floor` is
/// [`PercentileFloor::Enforced`], more than [`MAX_PERCENTILE_ENTRIES`]
/// entries, a non-finite or non-strictly-increasing `percentile`, a
/// malformed or decreasing `duration`, a decreasing `count`, a `count` past
/// [`super::MAX_REPORTED_REQUESTS`], or a final reconstructed count that
/// disagrees with the statistic's own declared `count`.
#[expect(
    clippy::too_many_lines,
    reason = "one linear validate-then-extract pass over a single statistic's percentiles array, \
              matching this crate's own established parser shape (Oha::parse in oha.rs is the \
              same length for the same reason); splitting it into several private functions each \
              threading the same half dozen accumulator locals (prev_percentile, \
              prev_duration_ns, prev_count, recorder) would not shorten the total code, only hide \
              the fixed check order this function's own correctness depends on"
)]
fn reconstruct_statistic(
    stat: &serde_json::Map<String, Value>,
    stat_id: &str,
    floor: PercentileFloor,
) -> Result<LatencyRecorder, BenchError> {
    let declared_count = read_u64(
        stat.get("count").ok_or_else(|| {
            BenchError::parse("nighthawk", &format!("{stat_id}.count is missing"))
        })?,
        &format!("{stat_id}.count"),
    )?;

    let percentiles = stat
        .get("percentiles")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            BenchError::parse(
                "nighthawk",
                &format!("{stat_id}.percentiles is missing or not an array"),
            )
        })?;

    if floor == PercentileFloor::Enforced && percentiles.len() < MIN_PERCENTILE_ENTRIES {
        return Err(BenchError::parse(
            "nighthawk",
            &format!(
                "{stat_id}.percentiles has {} entries, fewer than MIN_PERCENTILE_ENTRIES ({MIN_PERCENTILE_ENTRIES})",
                percentiles.len()
            ),
        ));
    }
    if percentiles.len() > MAX_PERCENTILE_ENTRIES {
        return Err(BenchError::parse(
            "nighthawk",
            &format!(
                "{stat_id}.percentiles has {} entries, past MAX_PERCENTILE_ENTRIES ({MAX_PERCENTILE_ENTRIES})",
                percentiles.len()
            ),
        ));
    }

    let mut recorder = LatencyRecorder::new()?;
    let mut prev_percentile = f64::NEG_INFINITY;
    let mut prev_duration_ns: u64 = 0;
    let mut prev_count: u64 = 0;

    for entry in percentiles {
        let entry_obj = entry.as_object().ok_or_else(|| {
            BenchError::parse(
                "nighthawk",
                &format!("{stat_id}.percentiles entry is not an object"),
            )
        })?;

        // `is_finite()` first: every ordering comparison against `NaN` is
        // false, so `percentile <= prev_percentile` alone would let a `NaN`
        // slip through as "strictly increasing" on a technicality. Verified
        // by execution that this branch is UNREACHABLE via untrusted bytes
        // in this crate's current dependency configuration: JSON's grammar
        // has no `NaN` literal, and `serde_json::from_slice` itself rejects
        // an out-of-range magnitude such as `1e400` ("number out of range")
        // before ever constructing a `Value`, without the `arbitrary_precision`
        // feature this workspace does not enable. Kept as defence in depth
        // against a future dependency change that defers that bound to
        // `.as_f64()` instead of enforcing it at parse time; see
        // `tests/loadgen_nighthawk.rs`'s comment above
        // `parse_rejects_decreasing_percentile_durations` for the full
        // finding.
        let percentile = entry_obj
            .get("percentile")
            .and_then(Value::as_f64)
            .ok_or_else(|| {
                BenchError::parse(
                    "nighthawk",
                    &format!("{stat_id}.percentiles entry has no percentile field"),
                )
            })?;
        if !percentile.is_finite() || percentile <= prev_percentile {
            return Err(BenchError::parse(
                "nighthawk",
                &format!("{stat_id}.percentiles percentiles are not strictly increasing"),
            ));
        }
        prev_percentile = percentile;

        let duration_str = entry_obj
            .get("duration")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                BenchError::parse(
                    "nighthawk",
                    &format!("{stat_id}.percentiles entry has no duration field"),
                )
            })?;
        let duration_ns = parse_protobuf_duration(duration_str)?;
        if duration_ns < prev_duration_ns {
            return Err(BenchError::parse(
                "nighthawk",
                &format!("{stat_id}.percentiles durations are not non-decreasing"),
            ));
        }
        prev_duration_ns = duration_ns;

        let count = read_u64(
            entry_obj.get("count").ok_or_else(|| {
                BenchError::parse(
                    "nighthawk",
                    &format!("{stat_id}.percentiles entry has no count field"),
                )
            })?,
            &format!("{stat_id}.percentiles.count"),
        )?;
        // Checked BEFORE the subtraction below: a decreasing `count` would
        // otherwise wrap `count - prev_count` into an enormous weight handed
        // to `record_n_ns`.
        if count < prev_count {
            return Err(BenchError::parse(
                "nighthawk",
                &format!("{stat_id}.percentiles counts are not non-decreasing"),
            ));
        }
        if count > MAX_REPORTED_REQUESTS {
            return Err(BenchError::parse(
                "nighthawk",
                &format!("{stat_id}.percentiles count exceeds MAX_REPORTED_REQUESTS"),
            ));
        }
        // `count >= prev_count`, checked immediately above, so this cannot
        // underflow.
        let weight = count - prev_count;
        prev_count = count;

        recorder.record_n_ns(duration_ns, weight);
    }

    if prev_count != declared_count {
        return Err(BenchError::parse(
            "nighthawk",
            &format!(
                "{stat_id} reconstructed count {prev_count} does not equal the declared count {declared_count}"
            ),
        ));
    }

    Ok(recorder)
}

impl LoadGenerator for Nighthawk {
    fn name(&self) -> &'static str {
        "nighthawk"
    }

    fn version_invocation(&self) -> Invocation {
        // Carries the SAME five hardening flags `plan` does (`--cap-drop
        // ALL`, `--security-opt no-new-privileges`, `--read-only`, `--memory
        // 4g`, `--pids-limit 4096`): this is the FIRST invocation ever run
        // against a freshly pinned digest, which is precisely the moment a
        // compromised upstream image is most likely to be executed, so it
        // must not run with Docker's full default capability set and an
        // unbounded memory/PID budget just because it is "only a version
        // probe". See `version_invocation_carries_the_hardening_flags` in
        // `tests/loadgen_nighthawk.rs` and docs/THREAT-MODEL.md's
        // "Benchmark tool containers" section.
        //
        // Deliberately NOT carried, unlike `plan`: `--network host` (the
        // version probe makes no network call at all), `--tmpfs
        // /tmp:...`/`--read-only`'s scratch pairing (nothing here writes),
        // and `--cpuset-cpus` (no measurement to keep off other cores). Each
        // omission is an absence of a NEED, not a hardening gap; `plan`'s
        // own five safety flags above are carried regardless.
        Invocation {
            program: self.runtime.program().to_owned(),
            args: vec![
                "run".to_owned(),
                "--rm".to_owned(),
                "--cap-drop".to_owned(),
                "ALL".to_owned(),
                "--security-opt".to_owned(),
                "no-new-privileges".to_owned(),
                "--read-only".to_owned(),
                "--memory".to_owned(),
                "4g".to_owned(),
                "--pids-limit".to_owned(),
                "4096".to_owned(),
                self.image.clone(),
                "nighthawk_client".to_owned(),
                "--version".to_owned(),
            ],
            env: Vec::new(),
        }
    }

    fn parse_version(&self, stdout: &[u8]) -> Result<ToolStamp, BenchError> {
        // UNVERIFIED against a live run, per the module doc: this crate could
        // not check `nighthawk_client --version`'s real output shape. The
        // WHOLE trimmed first line is kept (not, as `Oha::parse_version`
        // does, only the last whitespace-separated token): `bench/tools.toml`
        // deliberately checks this string with `expect_version_contains`
        // rather than an exact match, specifically because it is a build
        // identifier expected to contain "nighthawk" somewhere in a longer
        // line, not a single bare version token.
        if stdout.len() > MAX_VERSION_OUTPUT_BYTES {
            return Err(BenchError::parse(
                "nighthawk",
                "version output exceeds MAX_VERSION_OUTPUT_BYTES",
            ));
        }
        let text = std::str::from_utf8(stdout)
            .map_err(|_| BenchError::parse("nighthawk", "version output is not utf-8"))?;
        let first_line = text
            .trim()
            .lines()
            .next()
            .ok_or_else(|| BenchError::parse("nighthawk", "version output is empty"))?;
        if first_line.is_empty() {
            return Err(BenchError::parse("nighthawk", "version output is empty"));
        }
        // This string becomes `ToolStamp::version`, echoed into the run log
        // and the published table exactly like `Oha::parse_version`'s
        // identical check exists for: a NUL byte, an ANSI escape, or any
        // other non-printable byte is rejected rather than laundered into
        // provenance.
        if !first_line.bytes().all(is_path_expr_char) {
            return Err(BenchError::parse(
                "nighthawk",
                "version output contains a non-printable byte",
            ));
        }
        Ok(ToolStamp {
            name: self.name().to_owned(),
            version: first_line.to_owned(),
            image_digest: self.image.split('@').next_back().map(str::to_owned),
        })
    }

    fn supports(&self, _cell: &BenchCell) -> Result<(), Unsupported> {
        // Nighthawk supports H1, H2 and H3 (context fact 3) and BOTH rate
        // modes. Unlike `Oha::supports` (which refuses `RateMode::Saturate`
        // outright as its PRIMARY gate), the Design's own text says a
        // saturate cell is invoked without `--open-loop`/`--rps` and simply
        // gets `latency_trustworthy = false` in `parse` below, "the same
        // reasoning as oha" for WHY the number is untrustworthy, not for
        // whether the tool may run the cell at all. Test 4
        // (`plan_saturate_omits_open_loop`) pins this directly: `supports`
        // must still return `Ok` for a saturate cell. There is therefore
        // nothing for this adapter to refuse.
        Ok(())
    }

    fn plan(
        &self,
        cell: &BenchCell,
        target: &Target,
        run: &RunParams,
    ) -> Result<Invocation, BenchError> {
        // `supports` is trivial for this adapter (see its own doc) and never
        // returns `Err`, but this call is kept so `plan` still consults it
        // first, matching every other adapter's contract: a FUTURE change
        // that gives `Nighthawk::supports` a real refusal is then enforced
        // here with no change to this function.
        self.supports(cell)
            .map_err(|_| BenchError::Cell("cell rejected by Nighthawk::supports"))?;
        validate_target(target)?;

        // Fixed order, matching the Design's own "The invocation" code block
        // exactly. Every hardening flag is part of this pinned vector (test
        // 16): removing one fails a test rather than passing review
        // unnoticed.
        let mut args: Vec<String> = Vec::with_capacity(28);
        args.push("run".to_owned());
        args.push("--rm".to_owned());
        args.push("--network".to_owned());
        args.push("host".to_owned());
        args.push("--cap-drop".to_owned());
        args.push("ALL".to_owned());
        args.push("--security-opt".to_owned());
        args.push("no-new-privileges".to_owned());
        args.push("--read-only".to_owned());
        args.push("--tmpfs".to_owned());
        args.push("/tmp:rw,noexec,nosuid,size=64m".to_owned());
        args.push("--cpuset-cpus".to_owned());
        args.push(self.client_cores.clone());
        args.push("--memory".to_owned());
        args.push("4g".to_owned());
        args.push("--pids-limit".to_owned());
        args.push("4096".to_owned());
        args.push(self.image.clone());
        args.push("nighthawk_client".to_owned());

        if let RateMode::Fixed(rate) = cell.rate {
            // NEVER emitted alone: `--open-loop`, `--max-pending-requests 0`
            // and `--rps <rate>` are always all three present together or
            // all three absent, matching test 3's own grouping.
            args.push("--open-loop".to_owned());
            args.push("--max-pending-requests".to_owned());
            args.push("0".to_owned());
            args.push("--rps".to_owned());
            args.push(rate.to_string());
        }
        // `RateMode::Saturate` omits all five tokens above: per the Design,
        // "Nighthawk is invoked without `--open-loop` and without `--rps`",
        // and a rate limiter on a saturate cell would contradict "offer as
        // much load as the client can generate". Test 4
        // (`plan_saturate_omits_open_loop`) pins that neither flag appears.

        args.push("--connections".to_owned());
        args.push(cell.connections.to_string());
        args.push("--concurrency".to_owned());
        args.push("auto".to_owned());
        args.push("--duration".to_owned());
        args.push(run.duration_secs.to_string());

        let protocol_str = match cell.protocol {
            Protocol::H1 => "http1",
            Protocol::H2 => "http2",
            Protocol::H3 => "http3",
        };
        args.push("--protocol".to_owned());
        args.push(protocol_str.to_owned());

        args.push("--output-format".to_owned());
        args.push("json".to_owned());

        args.push("--request-header".to_owned());
        args.push(format!("host: {}", target.host));

        // `cell.tls`, not `target.scheme`: mirrors `Oha::plan`'s identical
        // formula (`BenchCell` carries the `TlsMode` distinction, not
        // `Target`), the only precedent in this crate for this choice. See
        // the module doc's "Two more honest gaps" section: this issue names
        // no certificate-validation override for a TLS cell.
        let scheme_str = match cell.tls {
            TlsMode::Off => "http",
            TlsMode::EcdsaP256 | TlsMode::Rsa2048 => "https",
        };
        // Nighthawk's given flag surface has no `--connect-to` equivalent
        // (unlike oha), so the URL itself carries the actual connect
        // address, and `--request-header "host: <host>"` above carries the
        // logical Host header separately. See the module doc.
        args.push(format!(
            "{scheme_str}://{}:{}{}",
            target.connect.ip(),
            target.connect.port(),
            target.path_expr
        ));

        Ok(Invocation {
            program: self.runtime.program().to_owned(),
            args,
            env: Vec::new(),
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one linear validate-then-extract pass over a single JSON document, matching \
                  this crate's own established parser shape (`Oha::parse` in oha.rs is the same \
                  length for the same reason); splitting it into several private functions each \
                  threading the same half dozen accumulator locals would not shorten the total \
                  code, only hide the fixed check order this parser's own correctness depends on"
    )]
    fn parse(
        &self,
        ctx: &ParseCtx<'_>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Result<RawRun, BenchError> {
        // Both byte caps are checked on the slice length BEFORE any parsing,
        // so a runaway tool costs one comparison rather than a
        // deserialisation. Edge case 16.
        if stdout.len() > MAX_TOOL_OUTPUT_BYTES {
            return Err(BenchError::parse(
                "nighthawk",
                "stdout exceeds MAX_TOOL_OUTPUT_BYTES",
            ));
        }
        if stderr.len() > MAX_TOOL_STDERR_BYTES {
            return Err(BenchError::parse(
                "nighthawk",
                "stderr exceeds MAX_TOOL_STDERR_BYTES",
            ));
        }
        // Edge case 4.
        if stdout.is_empty() {
            return Err(BenchError::parse("nighthawk", "empty output"));
        }
        // Edge case 15: checked independently of `serde_json::from_slice`'s
        // own UTF-8 validation, so the error message can name the byte
        // offset `str::Utf8Error::valid_up_to` reports.
        if let Err(e) = std::str::from_utf8(stdout) {
            return Err(BenchError::parse(
                "nighthawk",
                &format!(
                    "stdout is not valid utf-8 at byte offset {}",
                    e.valid_up_to()
                ),
            ));
        }

        // `serde_json::from_slice` enforces its own built-in 128-level
        // recursion limit at its default settings, never widened or
        // disabled anywhere in this crate: see the `loadgen` module's own
        // "Do NOT" precedent in `oha.rs`.
        let value: Value = serde_json::from_slice(stdout)
            .map_err(|e| BenchError::parse("nighthawk", &format!("invalid json: {e}")))?;
        let obj = value
            .as_object()
            .ok_or_else(|| BenchError::parse("nighthawk", "top level value is not an object"))?;

        let results = obj
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| BenchError::parse("nighthawk", "missing field results"))?;
        // Edge case 12d, checked before any per-entry scanning.
        if results.len() > MAX_RESULT_ENTRIES {
            return Err(BenchError::parse(
                "nighthawk",
                "results exceeds MAX_RESULT_ENTRIES",
            ));
        }
        // Edge case 5.
        if results.is_empty() {
            return Err(BenchError::parse(
                "nighthawk",
                "results is empty: a run with no results is not a run",
            ));
        }

        // Edge case 6: select the entry named "global"; NEVER the first
        // entry, which for a multi-worker run would silently report one
        // worker's numbers.
        let mut names: Vec<String> = Vec::with_capacity(results.len());
        let mut global: Option<&serde_json::Map<String, Value>> = None;
        for entry in results {
            let entry_obj = entry.as_object().ok_or_else(|| {
                BenchError::parse("nighthawk", "a results entry is not an object")
            })?;
            let name = entry_obj
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    BenchError::parse("nighthawk", "a results entry has no name field")
                })?;
            names.push(name.to_owned());
            if name == "global" && global.is_none() {
                global = Some(entry_obj);
            }
        }
        let global = global.ok_or_else(|| {
            BenchError::parse(
                "nighthawk",
                &format!("no \"global\" result entry found; available names: {names:?}"),
            )
        })?;

        let statistics = global
            .get("statistics")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                BenchError::parse("nighthawk", "global result has no statistics field")
            })?;
        if statistics.len() > MAX_STATISTICS {
            return Err(BenchError::parse(
                "nighthawk",
                "statistics exceeds MAX_STATISTICS",
            ));
        }

        let counters = global
            .get("counters")
            .and_then(Value::as_array)
            .ok_or_else(|| BenchError::parse("nighthawk", "global result has no counters field"))?;
        if counters.len() > MAX_COUNTERS {
            return Err(BenchError::parse(
                "nighthawk",
                "counters exceeds MAX_COUNTERS",
            ));
        }

        // `RawRun::duration_ns`'s source: see the module doc's honest note
        // that this issue names no source for it.
        let duration_str = global
            .get("execution_duration")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                BenchError::parse("nighthawk", "global result has no execution_duration field")
            })?;
        let duration_ns = parse_protobuf_duration(duration_str)?;
        if duration_ns == 0 {
            return Err(BenchError::parse(
                "nighthawk",
                "execution_duration yields a zero duration_ns",
            ));
        }

        let requests_sent = find_counter(counters, COUNTER_REQUESTS_SENT)?;
        if requests_sent > MAX_REPORTED_REQUESTS {
            return Err(BenchError::parse(
                "nighthawk",
                "requests_sent exceeds MAX_REPORTED_REQUESTS",
            ));
        }
        let responses_ok = find_counter(counters, COUNTER_RESPONSES_OK)?;
        let pool_connection_failure = find_counter(counters, COUNTER_POOL_CONNECTION_FAILURE)?;
        let stream_resets = find_counter(counters, COUNTER_STREAM_RESETS)?;
        let bytes_received = find_counter(counters, COUNTER_BYTES_RECEIVED)?;

        // u128 throughout: two hostile u64 counters near `u64::MAX` must not
        // wrap a u64 sum into a small number that then satisfies the
        // consistency check below. Mirrors `Oha::parse`'s identical
        // `status_sum`/`error_sum` pattern.
        let errors_u128 =
            u128::from(pool_connection_failure).saturating_add(u128::from(stream_resets));
        let accounted = u128::from(responses_ok).saturating_add(errors_u128);
        if accounted > u128::from(requests_sent) {
            return Err(BenchError::parse(
                "nighthawk",
                "counters are inconsistent: responses_ok plus errors exceeds requests_sent",
            ));
        }
        // `accounted <= requests_sent`, checked immediately above, so this
        // cannot underflow.
        let remainder = u128::from(requests_sent) - accounted;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "remainder <= requests_sent (checked above), and requests_sent was itself \
                      just checked <= MAX_REPORTED_REQUESTS (1e12), five orders of magnitude \
                      below u64::MAX"
        )]
        let remainder_u64 = remainder as u64;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "errors_u128 <= accounted <= requests_sent <= MAX_REPORTED_REQUESTS (1e12), \
                      comfortably inside u64"
        )]
        let errors = errors_u128 as u64;

        // Nighthawk's own counter set (see the module doc) has no per-code
        // breakdown beyond the one 2xx count this issue's own Counter
        // mapping table names; it has only class-level buckets
        // (`benchmark.http_1xx`..`http_xxx`) this issue does NOT ask this
        // adapter to read. `200` carries the one code-level count Nighthawk
        // gives us; `0` (not a real HTTP status) carries the remainder this
        // adapter cannot attribute to a specific code. Chosen so that
        // `sum(status_counts) + errors == requests_sent` holds BY
        // CONSTRUCTION, which the shared fuzz harness in
        // `fuzz_loadgen_json.rs` (added by #411, inherited here once this
        // adapter joins its dispatch list) asserts for every adapter's `Ok`
        // parse.
        let mut status_counts: BTreeMap<u16, u64> = BTreeMap::new();
        status_counts.insert(200, responses_ok);
        status_counts.insert(0, remainder_u64);

        let latency_stat = find_statistic(statistics, STATISTIC_ID_LATENCY).ok_or_else(|| {
            BenchError::parse(
                "nighthawk",
                &format!("missing statistic {STATISTIC_ID_LATENCY}"),
            )
        })?;
        let latency = reconstruct_statistic(
            latency_stat,
            STATISTIC_ID_LATENCY,
            PercentileFloor::Enforced,
        )?;
        // A statistic cannot legitimately have recorded more samples than
        // the run sent requests at all. Not one of this issue's own nine
        // named invariants, but load-bearing anyway: `fuzz_loadgen_json.rs`
        // (added by #411, inherited here once this adapter joins its
        // dispatch list) asserts `raw.latency.len() <= raw.requests_sent + 4`
        // for every adapter's `Ok` parse, and `latency_stat.count` is read
        // from the SAME untrusted document as `requests_sent` with no other
        // cross-check tying the two together.
        if latency.len() > requests_sent.saturating_add(4) {
            return Err(BenchError::parse(
                "nighthawk",
                "reconstructed latency sample count exceeds requests_sent",
            ));
        }

        // Invariant 3 / edge case 8: required only for `DownstreamClose`;
        // `None` is allowed otherwise. The adapter learns the cell's
        // keepalive mode from `ctx.cell`, never from the tool's own output.
        let connect = if let Some(stat) = find_statistic(statistics, STATISTIC_ID_CONNECT) {
            // `PercentileFloor::NotEnforced`: see the module doc's "the floor
            // is LATENCY-only" section. `queue_to_connect` does not set
            // `latency_exact`, and a `Both`-keepalive cell that reuses
            // connections may legitimately establish very few of them.
            Some(reconstruct_statistic(
                stat,
                STATISTIC_ID_CONNECT,
                PercentileFloor::NotEnforced,
            )?)
        } else {
            if ctx.cell.keepalive == KeepaliveMode::DownstreamClose {
                return Err(BenchError::parse(
                    "nighthawk",
                    &format!(
                        "missing statistic {STATISTIC_ID_CONNECT}, required for \
                         KeepaliveMode::DownstreamClose"
                    ),
                ));
            }
            None
        };

        // Invariant 2 / edge case 7: ALWAYS required, never `None` on a
        // successful parse. `sequencer.blocking` is the coordinated-omission
        // detector this tool is the arbiter FOR; a Nighthawk run that cannot
        // produce it is not a trustworthy run. Never substituted with
        // `sequencer.callback`, which measures the opposite thing.
        let stall_stat = find_statistic(statistics, STATISTIC_ID_STALL).ok_or_else(|| {
            BenchError::parse(
                "nighthawk",
                &format!(
                    "missing statistic {STATISTIC_ID_STALL}: the coordinated-omission detector"
                ),
            )
        })?;
        // `PercentileFloor::NotEnforced`: see the module doc's "the floor is
        // LATENCY-only" section. `sequencer.blocking` does not set
        // `latency_exact`, and near-zero blocking is the DEFINITION of a
        // healthy open-loop run, so this statistic is required to be
        // present and well-formed (invariant 2, enforced by
        // `find_statistic` returning `None` above) but never to clear a row
        // count a healthy run cannot meet.
        let stall =
            reconstruct_statistic(stall_stat, STATISTIC_ID_STALL, PercentileFloor::NotEnforced)?;

        let out_of_range = latency.out_of_range();
        // Saturate mode carries no rate to hold open-loop, matching the
        // Design's own reasoning for why its latency is not trustworthy:
        // "saturate mode is a throughput measurement", identical to `Oha`.
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
            out_of_range,
            latency,
            // `ttfb` is `None` on purpose, per the Design's "Statistic
            // identifier mapping" table: Nighthawk reports no
            // time-to-first-byte statistic. Mapping `latency_2xx` (total
            // latency filtered by status) or `response_header_size` (a size
            // in bytes) onto `ttfb` would publish a TTFB column that is
            // really something else.
            ttfb: None,
            connect,
            stall: Some(stall),
            // Every run that reaches this point has already had its
            // `latency` statistic reconstructed by the SAME routine that
            // enforces the >= MIN_PERCENTILE_ENTRIES floor invariant 1's own
            // honest caveat requires for this flag to be true: there is no
            // path to `Ok` that skipped it, so this is unconditional rather
            // than a separately computed flag that could drift from the
            // check that actually gates it.
            latency_exact: true,
            latency_trustworthy,
        })
    }
}
