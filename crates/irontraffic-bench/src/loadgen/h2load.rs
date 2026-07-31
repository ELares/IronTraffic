// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `h2load` adapter: the protocol-level tool, used for saturate-mode
//! HTTP/2 and HTTP/3 cells and for the time-to-first-byte decomposition no
//! other adapter in this crate reports.
//!
//! # `--rate` means connections per period, never requests per period
//!
//! This is the single most dangerous fact about this tool (issue #413's own
//! Context, fact 1). An implementer who assumes `--rate` expresses a request
//! rate produces numbers wrong by the factor requests-per-connection. This
//! adapter therefore never emits `--rate`, for any reason, and
//! [`H2Load::supports`] refuses `RateMode::Fixed` outright with
//! [`Unsupported::RateMode`]: fixed-rate cells are Nighthawk's job, not
//! h2load's. h2load only ever measures a [`RateMode::Saturate`] cell here,
//! offering as much load as the client can generate, exactly like `Oha` does
//! for the same rate mode (see that module's own doc).
//!
//! # The pinned version's own output format, verified against real source
//!
//! `bench/tools.toml` pins h2load `1.68.1`, the last `nghttp2/nghttp2` tag
//! whose `h2load.cc` prints the human-readable summary this parser reads
//! (`finished in`, `requests:`, `status codes:`, `traffic:`, and the three
//! `time for request:`/`time for connect:`/`time to 1st byte:` rows, each
//! `min max mean sd +/- sd`). This was NOT assumed: `nghttp2/nghttp2`'s own
//! source was fetched directly over HTTPS on 2026-07-31 (`src/h2load.cc`,
//! `src/util.cc`) at several tags to find exactly where the format changes,
//! because the CURRENT `nghttp2` release at the time this adapter was
//! written, `v1.70.0` (published 2026-07-29, two days before this was
//! written), silently replaced this entire summary shape with a differently
//! laid out `title: min max median p95 p99 mean sd +/- sd%` table with NO
//! `time for request:`/`time to 1st byte:` labels at all (`output_sd_stat`
//! in that tag's `h2load.cc`). `v1.69.0` (2026-04-19) already carries the new
//! shape; `v1.68.1` (2026-03-18) is the newest tag that still prints the
//! shape this issue's own Design section, Parsing table and every numbered
//! test describe verbatim (`time for request:  239us  11.85ms  602us  351us
//! 89.35%`, the issue's own edge case 11a example, confirmed present
//! byte-for-byte in `v1.68.1`'s `h2load.cc`). Pinning `1.70.0` merely because
//! it is the newest release would make every test this issue names fail
//! against a real binary; pinning `1.68.1` is what makes the fixture, the
//! parser and a real capture agree, PROVIDED HTTP/3 is selected the way
//! `1.68.1` actually supports it, not the way the Design section spells it
//! (see the section immediately below: the two requirements are otherwise
//! mutually exclusive across the whole release history). **Nobody in this
//! environment could install and run either version to confirm this
//! directly (no package manager, no `autoconf`, and `h2load`'s own build
//! additionally needs `libnghttp2`, OpenSSL, `libev` and `c-ares`):
//! `tests/fixtures/h2load-output.txt` is therefore RECONSTRUCTED from
//! `v1.68.1`'s own published source, not captured, exactly like
//! `nighthawk.rs`'s fixture and for the identical reason. Re-verify against
//! a real `h2load 1.68.1` run before this parser is trusted for a real
//! cell.**
//!
//! # HTTP/3 is selected through `--alpn-list`, never `--h3`, on the pinned `1.68.1`
//!
//! **This is a deliberate, evidence-backed DEVIATION from issue #413's own
//! Design section**, which writes the H3 branch of the invocation as
//! `[--h1 | (default h2) | --h3]`. An earlier version of this adapter
//! emitted exactly that literal flag, and it does not work: `--h3` is
//! ABSENT from `v1.68.1`'s `getopt_long` table (`src/h2load.cc`, dumped in
//! full over HTTPS from the pinned tag on 2026-07-31; the only occurrence of
//! the string `"h3"` anywhere in the 3,408-line file is the ALPN comparison
//! at line 1137, `if ("h3"sv != proto && "h3-29"sv != proto)`). `--h3` first
//! appears in `v1.69.0` (`{"h3", no_argument, &flag, 24}`), which is the SAME
//! release that deletes the `time for request:`/`time to 1st byte:` labels
//! this parser reads. No `nghttp2` release both accepts `--h3` and prints
//! the summary shape this module needs: bumping the pin to get the flag
//! breaks the parser, and keeping the pin to keep the parser breaks the
//! flag. A real `h2load 1.68.1` given `--h3` rejects the whole command line
//! with an unrecognized-option error, so every H3 cell this adapter planned
//! before this fix was unrunnable. This was found by an adversarial review
//! of PR 815 (issue #816, BLOCKING 1), reading the pinned tag's own source
//! rather than assuming the Design section's flag spelling was still
//! current.
//!
//! `1.68.1` selects HTTP/3 a different way, and this adapter now uses it:
//! `Config::is_quic()` returns `true` only when `alpn_list[0]` is `"h3"` or
//! `"h3-29"` (`src/h2load.cc:162-165`), and `alpn_list` is populated from
//! `--alpn-list` (`getopt_long` id 19, `required_argument`; the handler is
//! `config.alpn_list = util::parse_config_str_list(std::string_view{optarg});`).
//! [`H2Load::plan`] therefore emits `--alpn-list` followed by [`H3_ALPN_TOKEN`]
//! (`"h3"`) for [`Protocol::H3`] instead of `--h3`. This is the ONLY
//! invocation this adapter's pinned version can actually run and still
//! produce the output shape this parser reads, so it is the resolution
//! chosen over moving the pin.
//!
//! # The fixture's own arithmetic now matches every relation `print_stats` guarantees
//!
//! The same PR 815 review (issue #816 BLOCKING 3) found
//! `tests/fixtures/h2load-output.txt` arithmetically IMPOSSIBLE as any real
//! `1.68.1` output: it read `0 failed` alongside `20 5xx`, which
//! `print_stats`'s own `req_not_issued` fold-in makes `total ==
//! succeeded + failed` an identity no real run can violate, and its
//! `340.14KB/s` was the SI 1000-based figure a human computes by hand, not
//! `util::utos_funit`'s own 1024-based one (`332.17KB/s`). Both are fixed;
//! see `tests/loadgen_h2load.rs`'s own module doc, "Every relation 1.68.1's
//! own `print_stats` guarantees, enforced here," for the arithmetic and for
//! the one review claim about this fixture (the `req/s` row's decimal
//! precision) that a full read of `print_stats` shows was already correct
//! and was therefore left unchanged, with the `std::cout` state-persistence
//! evidence for why.
//!
//! # `finished in` is parsed as seconds-only, a narrower rule than the tool's
//! # own duration formatter
//!
//! `util::format_duration(std::chrono::microseconds)` (the function that
//! renders `finished in`'s own duration, confirmed by reading `v1.68.1`'s
//! `src/util.cc`) is the SAME microsecond-scaled unit selector the three
//! timing rows use: it prints `us` under one millisecond, `ms` under one
//! second, and only `s` at or above one second. A sub-second h2load run
//! could therefore legitimately print `finished in 500ms, ...`. This parser
//! rejects any unit other than a bare `s` for `finished in` anyway (edge case
//! 3, "`finished in` with a unit other than seconds... Only `<digits>[.<digits>]s`
//! is accepted"), which is safe here specifically because every cell this
//! crate ever asks h2load to run supplies `RunParams::duration_secs` as a
//! whole, positive count of SECONDS with no caller in this milestone ever
//! passing a sub-second duration, so a genuine h2load invocation under this
//! harness always finishes at or above one second and always prints the `s`
//! form. A unit of `us` or `ms` reaching this parser is therefore either a
//! caller that broke that assumption or a corrupted/hostile output, and
//! `Err(Parse)` is the right answer to both.
//!
//! # The reconstruction is deliberately minimal, and `min` is not independently
//! # checkable through `Percentiles`
//!
//! h2load's summary gives five numbers per row (min, max, mean, sd, the `+/-
//! sd` within-one-deviation fraction) and no sample count of its own; the
//! request count that IS available (`requests:`'s own `total` field) is
//! shared across all three rows because h2load reports no separate count for
//! `time for connect:` or `time to 1st byte:`. [`reconstruct_row`] anchors
//! the two REPORTED extremes (one sample at `min`, one at `max`) and floods
//! everything else at `mean`. `sd` and the `+/- sd` fraction are still fully
//! parsed and bounds-checked (rejecting `nanus`, `infms`, a bare unsuffixed
//! number, and anything past [`crate::HIGH_NS`], per edge cases 4a/4b) but
//! deliberately are NOT used to place a sample: a four-number summary (min,
//! max, mean, and a count reduced by the two anchors) cannot support a fifth
//! independent degree of freedom without inventing a distributional shape
//! h2load never measured, and doing so would buy nothing, because
//! [`RawRun::latency_exact`] is unconditionally `false` here and this
//! histogram is never published (`Do NOT` list: "Do NOT publish an h2load or
//! vegeta latency number"). Its only real jobs are to exist, to be bounded,
//! and to carry `ttfb`.
//!
//! One consequence worth stating plainly: `Percentiles` (added by issue
//! #405) exposes `p50_ns` through `p9999_ns` and `max_ns`, with no field
//! below the 50th percentile. Because `mean` holds the overwhelming
//! majority of the reconstructed weight for any `requests_sent` above 2,
//! `percentiles().p50_ns` recovers `mean` and `percentiles().max_ns`
//! recovers `max` (both checked by `parse_handles_mixed_time_units` in
//! `tests/loadgen_h2load.rs`), but `min` is mathematically unrecoverable
//! through `Percentiles` no matter how this reconstruction weights its
//! anchors: it would need to hold at least half the total weight to reach
//! the lowest exposed quantile, which would make it dominate the median
//! instead of `mean`. `min` (and `sd`, which is never placed at all) are
//! instead verified directly against the row parser itself, in this
//! module's own `#[cfg(test)]` unit tests below, which is the level those
//! two numbers are actually meaningful at.
//!
//! # No certificate-validation override
//!
//! Unlike `curl`, `oha` (`--insecure`) or `wrk`, `h2load` has no flag that
//! skips certificate verification at all (confirmed directly against
//! `v1.68.1`'s own `--help` text and its `getopt_long` table in
//! `src/h2load.cc`: no `-k`, no `--insecure`, no `--cacert`). A TLS cell
//! measured against this harness's self-signed fixture certificate may
//! therefore fail for a reason this issue's own flag surface has no answer
//! to. This is the identical shape of gap `nighthawk.rs`'s own module doc
//! flags for the same reason: an honest absence, not an oversight this
//! adapter's code can paper over.
//!
//! # Untrusted input
//!
//! [`H2Load::parse`]'s `stdout` and `stderr` are the captured output of a
//! SEPARATE process, exactly the boundary this crate's `loadgen` module doc
//! already documents; see that doc for the caller-side capture-time bound
//! this parser's own [`MAX_H2LOAD_OUTPUT_BYTES`]/[`MAX_H2LOAD_LINES`]/
//! [`MAX_H2LOAD_LINE_BYTES`] checks are the second, redundant line of
//! defence for.

use crate::cell::{BenchCell, Protocol, RateMode};
use crate::error::BenchError;
use crate::hist::{HIGH_NS, LatencyRecorder};
use crate::provenance::ToolStamp;

use super::{Invocation, MAX_HOST_BYTES, MAX_PATH_EXPR_BYTES, MAX_REPORTED_REQUESTS};
use super::{LoadGenerator, ParseCtx, RawRun, RunParams, Target, Unsupported};
use super::{MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_STDERR_BYTES, MAX_VERSION_OUTPUT_BYTES};

/// Largest h2load stdout the parser will accept, in bytes. Checked on the
/// slice length before any split, so a runaway tool costs one comparison.
pub const MAX_H2LOAD_OUTPUT_BYTES: usize = 1024 * 1024;

/// Largest number of h2load output lines the parser will read.
pub const MAX_H2LOAD_LINES: usize = 4096;

/// Largest single h2load output line the parser will read, in bytes.
pub const MAX_H2LOAD_LINE_BYTES: usize = 1024;

/// The `--alpn-list` value this adapter emits to select HTTP/3 on the pinned
/// `1.68.1`, which has no `--h3` flag at all. `Config::is_quic()` in that
/// release (`src/h2load.cc:162-165`) returns `true` only when
/// `alpn_list[0]` is `"h3"` or `"h3-29"`; this adapter always names the
/// non-draft `"h3"` token. See this module's own doc, "HTTP/3 is selected
/// through `--alpn-list`", for the full evidence trail.
const H3_ALPN_TOKEN: &str = "h3";

/// The h2load adapter: protocol-level cells and the TTFB decomposition.
///
/// NEVER emits `--rate`. h2load's `--rate` is CONNECTIONS per rate period,
/// not requests per period; an implementer who assumes otherwise produces
/// numbers wrong by the factor requests-per-connection. Fixed-rate cells
/// belong to Nighthawk.
///
/// `latency_exact` is always false here: h2load reports min, mean, standard
/// deviation and max, which cannot reconstruct a tail. This adapter's value
/// is `ttfb`, which no other tool decomposes, and its H2 and H3 coverage.
#[derive(Debug, Clone, Copy)]
pub struct H2Load {
    /// Client threads, rendered into `-t`.
    pub threads: u16,
}

// ---------------------------------------------------------------------------
// Shared byte-class helpers. Small, local copies rather than a dependency on
// a sibling adapter's private code, matching `nighthawk.rs`'s own precedent
// and stated reasoning for the identically named helpers there.
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

/// Bounds-checks `target`'s three string fields, mirroring `oha.rs`'s and
/// `nighthawk.rs`'s own `validate_target` and their stated reasoning: a
/// value that could never be safely rendered is refused before it reaches a
/// future caller that does render it, or a log line, even though THIS
/// adapter's own command line never renders `sni` (h2load has no SNI
/// override distinct from the URL host; see `plan`'s own doc).
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

// ---------------------------------------------------------------------------
// Integer-only numeric column parsing.
//
// Every number below is parsed with pure integer arithmetic, NEVER through a
// floating-point conversion, for the reason issue #413's own Design section
// and Do NOT list give (matching the Nighthawk protobuf-duration parser's
// identical rationale): the standard library's own floating-point string
// parser happily accepts `nan`, `inf` and `1e309`, casting a not-a-number
// floating value to an unsigned integer yields `0` in Rust, every ordering
// comparison against it is false, and an infinite value saturates. A value
// column of `nanus` would otherwise become a zero-nanosecond latency sample
// in a published histogram.
// ---------------------------------------------------------------------------

/// Nanosecond scale factors for h2load's three duration suffixes, longest
/// first so `ms`/`us` are tried before the `s` they both also end in
/// (`"11.85ms".strip_suffix("s")` would otherwise spuriously succeed with a
/// leftover `"11.85m"`, which the digit check below then correctly refuses
/// anyway, but trying the more specific suffixes first avoids relying on
/// that fallthrough).
const DURATION_SUFFIXES: [(&str, u64); 3] =
    [("us", 1_000), ("ms", 1_000_000), ("s", 1_000_000_000)];

/// Parses `<digits>[.<digits>]` (no sign, no exponent) as nanoseconds once
/// `suffix` has already been stripped, taking at most 6 fractional digits
/// right-padded to 6, matching the Nighthawk protobuf-duration parser's own
/// rule. `factor` is nanoseconds per whole unit of `suffix` (for example
/// `1_000_000_000` for `s`).
fn parse_digits_as_ns(body: &str, factor: u64) -> Option<u64> {
    let (whole_str, frac_str) = match body.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (body, None),
    };
    if whole_str.is_empty() || !whole_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = whole_str.parse().ok()?;

    // `factor` is at most 1_000_000_000 (the "s" suffix); the fractional
    // contribution below is always strictly less than `factor` (at most 6
    // digits scaled down by 10^6), so `whole.checked_mul(factor)` is the
    // only place this can overflow, and it is checked explicitly.
    let whole_ns = whole.checked_mul(factor)?;

    let frac_ns: u64 = match frac_str {
        None => 0,
        Some(f) => {
            if f.is_empty() || f.len() > 9 || !f.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let mut six = String::with_capacity(6);
            for c in f.chars().take(6) {
                six.push(c);
            }
            while six.len() < 6 {
                six.push('0');
            }
            let frac_units: u64 = six.parse().ok()?;
            // `factor` is a multiple of 10^6 for every suffix this module
            // uses ("us" -> 1_000 is not, so this path is only exercised by
            // "ms"/"s"; see the dedicated `factor < 1_000_000` branch below
            // for "us", whose 6-digit fraction would otherwise be scaled by
            // a fraction of a nanosecond).
            if factor >= 1_000_000 {
                #[expect(
                    clippy::integer_division,
                    reason = "factor is always an exact multiple of 1_000_000 for the \"ms\" \
                              (1_000_000) and \"s\" (1_000_000_000) suffixes, the only two that \
                              reach this branch, so this division has no remainder to lose"
                )]
                let per_unit = factor / 1_000_000;
                frac_units.checked_mul(per_unit)?
            } else {
                // "us": a fractional MICROSECOND is sub-nanosecond and this
                // module has no need to represent it; six.parse() above
                // already rejected anything non-numeric, so simply drop the
                // sub-nanosecond remainder rather than reject a
                // legitimately formatted (if never emitted by h2load
                // itself) `<n>.<frac>us` value.
                0
            }
        }
    };

    whole_ns.checked_add(frac_ns)
}

/// Parses one duration token (for example `"239us"`, `"11.85ms"`) against
/// `allowed`, an ordered `(suffix, ns_per_unit)` table. Returns the first
/// suffix that both matches AND whose remaining digits parse cleanly;
/// `nanus`, `infms`, `-1us`, `1e309s` and a bare `239` all fail every
/// candidate and fall through to the final `Err`.
///
/// # Errors
/// `BenchError::Parse` naming `token` when no allowed suffix parses it.
fn parse_duration_token(token: &str, allowed: &[(&str, u64)]) -> Result<u64, BenchError> {
    for (suffix, factor) in allowed {
        if let Some(body) = token.strip_suffix(suffix)
            && let Some(ns) = parse_digits_as_ns(body, *factor)
        {
            return Ok(ns);
        }
    }
    Err(BenchError::parse(
        "h2load",
        &format!("{token:?} is not a valid duration"),
    ))
}

/// Parses a duration token against every suffix h2load's timing rows use
/// (`us`, `ms`, `s`), then rejects anything above [`HIGH_NS`]: for h2load the
/// value is a summary statistic rather than an observation, so a 90 second
/// mean is a misparse, not a slow request (edge case 4b), unlike the
/// tolerant `record_n_ns` out-of-range counting every OTHER adapter's raw
/// observations get.
///
/// # Errors
/// `BenchError::Parse` naming `token` when it is not a valid duration or
/// exceeds [`HIGH_NS`].
fn parse_bounded_duration_token(token: &str) -> Result<u64, BenchError> {
    let ns = parse_duration_token(token, &DURATION_SUFFIXES)?;
    if ns > HIGH_NS {
        return Err(BenchError::parse(
            "h2load",
            &format!("{token:?} exceeds HIGH_NS"),
        ));
    }
    Ok(ns)
}

/// Parses the `finished in <duration>` token, seconds-only. See the module
/// doc's "`finished in` is parsed as seconds-only" section for why a
/// narrower rule than the three timing rows is deliberate here.
///
/// # Errors
/// `BenchError::Parse` naming `token` when it does not end in a bare `s`
/// suffix or is otherwise malformed.
fn parse_finished_in_token(token: &str) -> Result<u64, BenchError> {
    parse_duration_token(token, &[("s", 1_000_000_000)])
}

/// Parses a `<digits>[.<digits>]%` percentage token as hundredths of a
/// percent (`"89.35%"` -> `8935`), taking at most 2 fractional digits
/// right-padded to 2 (h2load's own `dtos` always renders exactly 2), and
/// rejects anything above `10000` (100.00%): a `+/- sd` fraction can never
/// legitimately exceed 100 percent, and this bound is what lets the
/// reconstruction's own `within` weight never exceed `requests_sent`.
///
/// # Errors
/// `BenchError::Parse` naming `token` when it does not end in `%`, is not
/// `<digits>[.<digits>]`, or exceeds 100.00%.
fn parse_percentage_token(token: &str) -> Result<u32, BenchError> {
    let Some(body) = token.strip_suffix('%') else {
        return Err(BenchError::parse(
            "h2load",
            &format!("{token:?} is not a percentage (missing %)"),
        ));
    };
    let (whole_str, frac_str) = match body.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (body, None),
    };
    if whole_str.is_empty() || !whole_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BenchError::parse(
            "h2load",
            &format!("{token:?} is not a valid percentage"),
        ));
    }
    let whole: u32 = whole_str.parse().map_err(|_| {
        BenchError::parse("h2load", &format!("{token:?} whole part does not fit u32"))
    })?;
    let frac_hundredths: u32 = match frac_str {
        None => 0,
        Some(f) => {
            if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                return Err(BenchError::parse(
                    "h2load",
                    &format!("{token:?} is not a valid percentage"),
                ));
            }
            let mut two = String::with_capacity(2);
            for c in f.chars().take(2) {
                two.push(c);
            }
            while two.len() < 2 {
                two.push('0');
            }
            two.parse().map_err(|_| {
                BenchError::parse("h2load", &format!("{token:?} fractional part is malformed"))
            })?
        }
    };
    let hundredths = whole
        .checked_mul(100)
        .and_then(|w| w.checked_add(frac_hundredths))
        .ok_or_else(|| BenchError::parse("h2load", &format!("{token:?} overflows")))?;
    if hundredths > 10_000 {
        return Err(BenchError::parse(
            "h2load",
            &format!("{token:?} exceeds 100.00%"),
        ));
    }
    Ok(hundredths)
}

// ---------------------------------------------------------------------------
// Line-level parsing.
// ---------------------------------------------------------------------------

/// One reconstructed `min max mean sd +/- sd` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SdStatRow {
    min_ns: u64,
    max_ns: u64,
    mean_ns: u64,
    sd_ns: u64,
    within_hundredths: u32,
}

/// Parses the five whitespace-separated tokens after a `time for request:`
/// / `time for connect:` / `time to 1st byte:` label: `min max mean sd
/// +/-sd%`, for example `239us  11.85ms  602us  351us  89.35%`. Each of the
/// four duration columns carries its OWN unit suffix (edge case 11a: a row
/// may mix `us`, `ms` and `s` within itself), so a parser that assumes one
/// unit for the whole row silently reports milliseconds as microseconds.
///
/// # Errors
/// `BenchError::Parse` naming `label` when the row does not have exactly
/// five tokens, or naming the malformed token when any of the five fails its
/// own parse or exceeds [`HIGH_NS`].
fn parse_sd_stat_row(rest: &str, label: &str) -> Result<SdStatRow, BenchError> {
    let tokens: Vec<&str> = rest.split_ascii_whitespace().collect();
    let [min_tok, max_tok, mean_tok, sd_tok, pct_tok] = tokens.as_slice() else {
        return Err(BenchError::parse(
            "h2load",
            &format!("{label} row does not have exactly five columns"),
        ));
    };
    Ok(SdStatRow {
        min_ns: parse_bounded_duration_token(min_tok)?,
        max_ns: parse_bounded_duration_token(max_tok)?,
        mean_ns: parse_bounded_duration_token(mean_tok)?,
        sd_ns: parse_bounded_duration_token(sd_tok)?,
        within_hundredths: parse_percentage_token(pct_tok)?,
    })
}

/// The four counts this parser reads from the `requests:` line, in the
/// fixed order h2load always emits them: `<total> total, <started> started,
/// <done> done, <succeeded> succeeded, <failed> failed, <errored> errored,
/// <timeout> timeout`. `started`/`done`/`succeeded` are validated for shape
/// (each must be a plain digit run with the expected trailing label) but not
/// stored: this issue's own Parsing table maps only `total` (to
/// `requests_sent`) and the sum of `failed`+`errored`+`timeout` (to
/// `errors`) onto any `RawRun` field.
#[derive(Debug, Clone, Copy)]
struct RequestsFields {
    total: u64,
    failed: u64,
    errored: u64,
    timeout: u64,
}

/// Parses one `<n> <label>` segment (for example `"1000 total"`), checking
/// the count against [`MAX_REPORTED_REQUESTS`] and the trailing label
/// against `expected`.
///
/// # Errors
/// `BenchError::Parse` naming the segment when it is not `<digits> <label>`
/// or when the count exceeds [`MAX_REPORTED_REQUESTS`].
fn parse_count_field(segment: &str, expected: &str) -> Result<u64, BenchError> {
    let Some(count_str) = segment.strip_suffix(expected).map(str::trim_end) else {
        return Err(BenchError::parse(
            "h2load",
            &format!("{segment:?} does not end with {expected:?}"),
        ));
    };
    let count: u64 = count_str
        .parse()
        .map_err(|_| BenchError::parse("h2load", &format!("{segment:?} has no leading integer")))?;
    if count > MAX_REPORTED_REQUESTS {
        return Err(BenchError::parse(
            "h2load",
            &format!("{segment:?} exceeds MAX_REPORTED_REQUESTS"),
        ));
    }
    Ok(count)
}

/// Parses the `requests:` line's value part (everything after the label).
///
/// # Errors
/// `BenchError::Parse` when the line does not have exactly seven
/// comma-separated fields in h2load's own fixed order, or when any field's
/// count is malformed or exceeds [`MAX_REPORTED_REQUESTS`].
fn parse_requests_line(rest: &str) -> Result<RequestsFields, BenchError> {
    let fields: Vec<&str> = rest.split(", ").collect();
    let [
        total_f,
        started_f,
        done_f,
        succeeded_f,
        failed_f,
        errored_f,
        timeout_f,
    ] = fields.as_slice()
    else {
        return Err(BenchError::parse(
            "h2load",
            "requests: line does not have exactly seven fields",
        ));
    };
    let total = parse_count_field(total_f, " total")?;
    parse_count_field(started_f, " started")?;
    parse_count_field(done_f, " done")?;
    parse_count_field(succeeded_f, " succeeded")?;
    let failed = parse_count_field(failed_f, " failed")?;
    let errored = parse_count_field(errored_f, " errored")?;
    let timeout = parse_count_field(timeout_f, " timeout")?;
    Ok(RequestsFields {
        total,
        failed,
        errored,
        timeout,
    })
}

/// Parses the `status codes:` line's value part, returning only the `2xx`
/// field (the only one this issue's own Parsing table maps onto a `RawRun`
/// field, `responses_ok`); `3xx`/`4xx`/`5xx` are still validated for shape
/// so a malformed line is rejected rather than silently misread.
///
/// # Errors
/// `BenchError::Parse` when the line does not have exactly four
/// comma-separated fields in h2load's own fixed order, or when the `2xx`
/// count is malformed or exceeds [`MAX_REPORTED_REQUESTS`].
fn parse_status_codes_line(rest: &str) -> Result<u64, BenchError> {
    let fields: Vec<&str> = rest.split(", ").collect();
    let [twoxx_f, threexx_f, fourxx_f, fivexx_f] = fields.as_slice() else {
        return Err(BenchError::parse(
            "h2load",
            "status codes: line does not have exactly four fields",
        ));
    };
    let twoxx = parse_count_field(twoxx_f, " 2xx")?;
    parse_count_field(threexx_f, " 3xx")?;
    parse_count_field(fourxx_f, " 4xx")?;
    parse_count_field(fivexx_f, " 5xx")?;
    Ok(twoxx)
}

/// Parses the `traffic:` line's value part and returns the PARENTHESISED
/// integer byte count on the `total` field, never the rounded
/// human-readable prefix (`11.35MB`): edge case 11a's own example,
/// `traffic: 11.35MB (11905000) total, ...`, means the exact count is
/// `11905000`.
///
/// # Errors
/// `BenchError::Parse` when the line has no `total` field, that field has no
/// parenthesised integer, or the integer is malformed.
fn parse_traffic_line(rest: &str) -> Result<u64, BenchError> {
    let total_field = rest
        .split(", ")
        .find(|f| f.trim_end().ends_with("total"))
        .ok_or_else(|| BenchError::parse("h2load", "traffic: line has no total field"))?;
    let open = total_field
        .find('(')
        .ok_or_else(|| BenchError::parse("h2load", "traffic: total field has no ( count"))?;
    let close = total_field
        .get(open..)
        .and_then(|s| s.find(')'))
        .map(|i| i + open)
        .ok_or_else(|| BenchError::parse("h2load", "traffic: total field has no ) count"))?;
    let digits = total_field
        .get(open + 1..close)
        .ok_or_else(|| BenchError::parse("h2load", "traffic: total field parens are malformed"))?;
    digits.parse().map_err(|_| {
        BenchError::parse(
            "h2load",
            "traffic: total field's parenthesised value is not an integer",
        )
    })
}

/// Reconstructs a [`LatencyRecorder`] from one summary row. See the module
/// doc's "the reconstruction is deliberately minimal" section: one sample at
/// `min`, one at `max`, and everything else at `mean`. `sd` and
/// `within_hundredths` are already validated by [`parse_sd_stat_row`] but
/// intentionally unused here.
///
/// # Errors
/// Propagates [`LatencyRecorder::new`]'s construction error.
fn reconstruct_row(row: SdStatRow, requests_sent: u64) -> Result<LatencyRecorder, BenchError> {
    let mut recorder = LatencyRecorder::new()?;
    if requests_sent <= 1 {
        // The one case where anchoring both min and max separately from the
        // bulk would overcount a run this small: put everything at mean,
        // which for a genuine single-sample capture equals min and max
        // anyway.
        recorder.record_n_ns(row.mean_ns, requests_sent);
    } else {
        recorder.record_n_ns(row.min_ns, 1);
        recorder.record_n_ns(row.max_ns, 1);
        recorder.record_n_ns(row.mean_ns, requests_sent - 2);
    }
    Ok(recorder)
}

impl LoadGenerator for H2Load {
    fn name(&self) -> &'static str {
        "h2load"
    }

    fn version_invocation(&self) -> Invocation {
        Invocation {
            program: "h2load".to_owned(),
            args: vec!["--version".to_owned()],
            env: Vec::new(),
        }
    }

    fn parse_version(&self, stdout: &[u8]) -> Result<ToolStamp, BenchError> {
        // `h2load --version` prints exactly `h2load nghttp2/<version>`
        // (confirmed against `v1.68.1`'s own `print_version`: `std::println("h2load
        // nghttp2/" NGHTTP2_VERSION)`, a single line). The version substring
        // is taken after the LAST `/`, matching `bench/tools.toml`'s own
        // exact-match pin (`version = "1.68.1"`, not the whole line):
        // splitting on `/` rather than whitespace is this adapter's own
        // choice, made once, because the line has exactly one `/` and no
        // internal whitespace after it.
        if stdout.len() > MAX_VERSION_OUTPUT_BYTES {
            return Err(BenchError::parse(
                "h2load",
                "version output exceeds MAX_VERSION_OUTPUT_BYTES",
            ));
        }
        let text = std::str::from_utf8(stdout)
            .map_err(|_| BenchError::parse("h2load", "version output is not utf-8"))?;
        let first_line = text
            .trim()
            .lines()
            .next()
            .ok_or_else(|| BenchError::parse("h2load", "version output is empty"))?;
        if first_line.is_empty() || !first_line.bytes().all(is_path_expr_char) {
            return Err(BenchError::parse(
                "h2load",
                "version output is empty or contains a non-printable byte",
            ));
        }
        let version = first_line
            .rsplit('/')
            .next()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| BenchError::parse("h2load", "version output has no / separator"))?;
        Ok(ToolStamp {
            name: self.name().to_owned(),
            version: version.to_owned(),
            image_digest: None,
        })
    }

    fn supports(&self, cell: &BenchCell) -> Result<(), Unsupported> {
        // The ONLY refusal: h2load's `--rate` means connections per period,
        // not requests per period, so a fixed-rate cell is unexpressible.
        // Every protocol and every connection count is otherwise accepted;
        // this adapter's whole value is saturate-mode protocol coverage and
        // TTFB, per the module doc.
        if matches!(cell.rate, RateMode::Fixed(_)) {
            return Err(Unsupported::RateMode {
                tool: self.name(),
                detail: "--rate is connections per rate period, not requests per period; \
                         fixed-rate cells are Nighthawk's job",
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
        self.supports(cell).map_err(|_| {
            BenchError::Cell(
                "h2load's --rate is connections per period; RateMode::Fixed is unsupported",
            )
        })?;
        validate_target(target)?;

        // Fixed order, matching the Design's own invocation code block
        // exactly.
        let mut args: Vec<String> = Vec::with_capacity(16);
        args.push("--duration".to_owned());
        args.push(run.duration_secs.to_string());
        args.push("--warm-up-time".to_owned());
        args.push(run.warmup_secs.to_string());
        args.push("-c".to_owned());
        args.push(cell.connections.to_string());
        args.push("-t".to_owned());
        args.push(self.threads.to_string());

        // `-m` mapping: 1 for HTTP/1.1 (the pipelining depth; h2load cannot
        // multiplex H1 at all), 100 for H2 and H3 (the advertised
        // concurrent-stream default). Test 5's own wording names this rule
        // purely by protocol, with no keepalive qualifier.
        let streams = if cell.protocol == Protocol::H1 {
            1
        } else {
            100
        };
        args.push("-m".to_owned());
        args.push(streams.to_string());

        match cell.protocol {
            Protocol::H1 => args.push("--h1".to_owned()),
            Protocol::H2 => {} // h2load's default over plaintext; never relied on silently, but nothing to add.
            // NOT `--h3`: the pinned `1.68.1` has no such flag (see this
            // module's own doc, "HTTP/3 is selected through `--alpn-list`").
            // `--alpn-list h3` is what makes `Config::is_quic()` return
            // `true` in that release.
            Protocol::H3 => {
                args.push("--alpn-list".to_owned());
                args.push(H3_ALPN_TOKEN.to_owned());
            }
        }

        args.push("--header".to_owned());
        args.push(format!("host: {}", target.host));

        let scheme_str = match cell.tls {
            crate::cell::TlsMode::Off => "http",
            crate::cell::TlsMode::EcdsaP256 | crate::cell::TlsMode::Rsa2048 => "https",
        };
        args.push(format!(
            "{scheme_str}://{}:{}{}",
            target.connect.ip(),
            target.connect.port(),
            target.path_expr
        ));

        Ok(Invocation {
            program: "h2load".to_owned(),
            args,
            env: Vec::new(),
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one linear line-by-line scan over a single text document, matching this \
                  crate's own established parser shape (Oha::parse/Nighthawk::parse are the same \
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
        if stdout.len() > MAX_TOOL_OUTPUT_BYTES {
            return Err(BenchError::parse(
                "h2load",
                "stdout exceeds MAX_TOOL_OUTPUT_BYTES",
            ));
        }
        if stderr.len() > MAX_TOOL_STDERR_BYTES {
            return Err(BenchError::parse(
                "h2load",
                "stderr exceeds MAX_TOOL_STDERR_BYTES",
            ));
        }
        // This adapter's own tighter bound, checked on the slice length
        // before any split, so a runaway tool costs one comparison; a
        // per-line cap alone would still admit one 1 MiB line (edge case 4).
        if stdout.len() > MAX_H2LOAD_OUTPUT_BYTES {
            return Err(BenchError::parse(
                "h2load",
                "stdout exceeds MAX_H2LOAD_OUTPUT_BYTES",
            ));
        }

        let mut finished_in: Option<(u64, usize)> = None;
        let mut requests: Option<(RequestsFields, usize)> = None;
        let mut status_2xx: Option<(u64, usize)> = None;
        let mut bytes_received: Option<(u64, usize)> = None;
        let mut request_row: Option<(SdStatRow, usize)> = None;
        let mut connect_row: Option<(SdStatRow, usize)> = None;
        let mut ttfb_row: Option<(SdStatRow, usize)> = None;

        let mut line_no: usize = 0;
        for raw_line in stdout.split(|&b| b == b'\n') {
            line_no += 1;
            if line_no > MAX_H2LOAD_LINES {
                return Err(BenchError::parse(
                    "h2load",
                    "output exceeds MAX_H2LOAD_LINES",
                ));
            }
            if raw_line.len() > MAX_H2LOAD_LINE_BYTES {
                return Err(BenchError::parse(
                    "h2load",
                    &format!("line {line_no} exceeds MAX_H2LOAD_LINE_BYTES"),
                ));
            }
            // Edge case 14: parsed line by line with `str::from_utf8` per
            // line, naming the line number; no lossy conversion, ever.
            let line = std::str::from_utf8(raw_line).map_err(|_| {
                BenchError::parse("h2load", &format!("line {line_no} is not valid utf-8"))
            })?;

            if let Some(rest) = line.strip_prefix("finished in ") {
                if let Some((_, first)) = finished_in {
                    return Err(BenchError::parse(
                        "h2load",
                        &format!("duplicate label \"finished in\" at lines {first} and {line_no}"),
                    ));
                }
                // Only the duration token itself, up to the first comma.
                let duration_tok = rest
                    .split(',')
                    .next()
                    .ok_or_else(|| BenchError::parse("h2load", "finished in line is empty"))?;
                let ns = parse_finished_in_token(duration_tok)?;
                finished_in = Some((ns, line_no));
            } else if let Some(rest) = line.strip_prefix("requests: ") {
                if let Some((_, first)) = requests {
                    return Err(BenchError::parse(
                        "h2load",
                        &format!("duplicate label \"requests:\" at lines {first} and {line_no}"),
                    ));
                }
                requests = Some((parse_requests_line(rest)?, line_no));
            } else if let Some(rest) = line.strip_prefix("status codes: ") {
                if let Some((_, first)) = status_2xx {
                    return Err(BenchError::parse(
                        "h2load",
                        &format!(
                            "duplicate label \"status codes:\" at lines {first} and {line_no}"
                        ),
                    ));
                }
                status_2xx = Some((parse_status_codes_line(rest)?, line_no));
            } else if let Some(rest) = line.strip_prefix("traffic: ") {
                if let Some((_, first)) = bytes_received {
                    return Err(BenchError::parse(
                        "h2load",
                        &format!("duplicate label \"traffic:\" at lines {first} and {line_no}"),
                    ));
                }
                bytes_received = Some((parse_traffic_line(rest)?, line_no));
            } else if let Some(rest) = line.strip_prefix("time for request: ") {
                if let Some((_, first)) = request_row {
                    return Err(BenchError::parse(
                        "h2load",
                        &format!(
                            "duplicate label \"time for request:\" at lines {first} and {line_no}"
                        ),
                    ));
                }
                request_row = Some((parse_sd_stat_row(rest, "time for request:")?, line_no));
            } else if let Some(rest) = line.strip_prefix("time for connect: ") {
                if let Some((_, first)) = connect_row {
                    return Err(BenchError::parse(
                        "h2load",
                        &format!(
                            "duplicate label \"time for connect:\" at lines {first} and {line_no}"
                        ),
                    ));
                }
                connect_row = Some((parse_sd_stat_row(rest, "time for connect:")?, line_no));
            } else if let Some(rest) = line.strip_prefix("time to 1st byte: ") {
                if let Some((_, first)) = ttfb_row {
                    return Err(BenchError::parse(
                        "h2load",
                        &format!(
                            "duplicate label \"time to 1st byte:\" at lines {first} and {line_no}"
                        ),
                    ));
                }
                ttfb_row = Some((parse_sd_stat_row(rest, "time to 1st byte:")?, line_no));
            }
            // Every other line (the blank separator, the column header, the
            // `req/s` row) is tolerated and skipped: this parser reads a
            // fixed, enumerated set of labels and ignores everything else,
            // per the Do NOT list's "not a loose regex sweep" rule.
        }

        let (duration_ns, _) = finished_in
            .ok_or_else(|| BenchError::parse("h2load", "missing \"finished in\" line"))?;
        let (requests_fields, _) =
            requests.ok_or_else(|| BenchError::parse("h2load", "missing \"requests:\" line"))?;
        let (responses_ok, _) = status_2xx
            .ok_or_else(|| BenchError::parse("h2load", "missing \"status codes:\" line"))?;
        let (bytes_received, _) = bytes_received
            .ok_or_else(|| BenchError::parse("h2load", "missing \"traffic:\" line"))?;
        let (request_row, _) = request_row
            .ok_or_else(|| BenchError::parse("h2load", "missing \"time for request:\" row"))?;
        let (connect_row, _) = connect_row
            .ok_or_else(|| BenchError::parse("h2load", "missing \"time for connect:\" row"))?;
        let (ttfb_row, _) = ttfb_row
            .ok_or_else(|| BenchError::parse("h2load", "missing \"time to 1st byte:\" row"))?;

        if duration_ns == 0 {
            return Err(BenchError::parse(
                "h2load",
                "finished in yields a zero duration_ns",
            ));
        }

        let requests_sent = requests_fields.total;
        if requests_sent == 0 {
            return Err(BenchError::parse(
                "h2load",
                "requests: total is zero: not a run",
            ));
        }

        // `errors` per the Design's own Parsing table: failed + errored +
        // timeout, summed in u128 so three hostile near-u64::MAX counts
        // cannot wrap into a small number.
        let errors_u128 = u128::from(requests_fields.failed)
            .saturating_add(u128::from(requests_fields.errored))
            .saturating_add(u128::from(requests_fields.timeout));

        // `status_counts` mirrors Nighthawk's own scheme (see that module's
        // doc): h2load's own counter set gives only 2xx/3xx/4xx/5xx class
        // buckets, no per-code breakdown, so `200` carries the one
        // code-level count this parser reads, and `0` carries whatever
        // `requests_sent` does not attribute to either `responses_ok` or
        // `errors`. This is what makes `sum(status_counts) + errors ==
        // requests_sent` hold by construction, the invariant
        // `fuzz_loadgen_json.rs`'s shared `check_ok_raw_run` enforces for
        // every adapter.
        let accounted = u128::from(responses_ok).saturating_add(errors_u128);
        if accounted > u128::from(requests_sent) {
            return Err(BenchError::parse(
                "h2load",
                "counters are inconsistent: responses_ok plus errors exceeds requests_sent",
            ));
        }
        let remainder = u128::from(requests_sent) - accounted;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "remainder <= requests_sent <= MAX_REPORTED_REQUESTS (1e12), checked above, \
                      five orders of magnitude below u64::MAX"
        )]
        let remainder_u64 = remainder as u64;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "errors_u128 <= accounted <= requests_sent <= MAX_REPORTED_REQUESTS, \
                      comfortably inside u64"
        )]
        let errors = errors_u128 as u64;

        let mut status_counts = std::collections::BTreeMap::new();
        status_counts.insert(200, responses_ok);
        status_counts.insert(0, remainder_u64);

        let latency = reconstruct_row(request_row, requests_sent)?;
        let connect = reconstruct_row(connect_row, requests_sent)?;
        let ttfb = reconstruct_row(ttfb_row, requests_sent)?;

        // Invariant 8: every parsed timing column was already bounds-checked
        // against HIGH_NS by `parse_bounded_duration_token` before
        // `reconstruct_row` ever ran, so `max_ns` here can never exceed it;
        // this call proves that rather than assuming it.
        debug_assert!(latency.percentiles().max_ns <= HIGH_NS);

        Ok(RawRun {
            tool: ctx.tool.clone(),
            command_line: ctx.invocation.command_line(),
            requests_sent,
            responses_ok,
            errors,
            status_counts,
            bytes_received,
            duration_ns,
            out_of_range: latency.out_of_range(),
            latency,
            ttfb: Some(ttfb),
            connect: Some(connect),
            stall: None,
            // Invariant 1: always false. h2load's summary statistics cannot
            // reconstruct a tail.
            latency_exact: false,
            // h2load only ever measures a saturate cell (`supports` refuses
            // `RateMode::Fixed` above), and saturate mode is a throughput
            // measurement, not a latency one, matching `Oha`'s and
            // `Nighthawk`'s identical reasoning for the same rate mode.
            latency_trustworthy: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Row and column parsing: the exact numbers from issue #413's own
    // edge case 11a example, watched against a mutated unit table to
    // confirm they fail for the stated reason before being trusted here.
    // -----------------------------------------------------------------

    #[test]
    fn mixed_units_parse_to_exact_nanoseconds() {
        let row = parse_sd_stat_row("239us  11.85ms  602us  351us  89.35%", "time for request:")
            .expect("well-formed row");
        assert_eq!(row.min_ns, 239_000);
        assert_eq!(row.max_ns, 11_850_000);
        assert_eq!(row.mean_ns, 602_000);
        assert_eq!(row.sd_ns, 351_000);
        assert_eq!(row.within_hundredths, 8935);
    }

    #[test]
    fn traffic_line_prefers_parenthesised_integer() {
        let bytes = parse_traffic_line(
            "11.35MB (11905000) total, 285.16KB (292000) headers (space savings 96.20%), 10.49MB (11000000) data",
        )
        .expect("well-formed traffic line");
        assert_eq!(bytes, 11_905_000);
    }

    #[test]
    fn rejects_bare_number_with_no_unit() {
        assert!(parse_bounded_duration_token("239").is_err());
    }

    #[test]
    fn rejects_non_numeric_columns() {
        for bad in ["nanus", "infms", "-1us", "1e309s"] {
            assert!(
                parse_bounded_duration_token(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_value_above_high_ns() {
        // 61 seconds, one second above HIGH_NS (60s).
        assert!(parse_bounded_duration_token("61s").is_err());
    }

    /// The opposite direction of `rejects_value_above_high_ns`: a value AT
    /// the `HIGH_NS` boundary itself, and one microsecond below, must both
    /// still be accepted. A fix that rejects anything `>= HIGH_NS` instead
    /// of `> HIGH_NS` would reject this legitimate value silently.
    #[test]
    fn accepts_value_exactly_at_high_ns() {
        assert_eq!(
            parse_bounded_duration_token("60s").expect("60s == HIGH_NS exactly"),
            HIGH_NS
        );
        assert_eq!(
            parse_bounded_duration_token("59999999us").expect("one microsecond below HIGH_NS"),
            HIGH_NS - 1_000
        );
    }

    #[test]
    fn rejects_percentage_above_100() {
        assert!(parse_percentage_token("150.00%").is_err());
    }

    #[test]
    fn finished_in_rejects_non_second_unit() {
        assert!(parse_finished_in_token("500ms").is_err());
        assert!(parse_finished_in_token("35.00s").is_ok());
    }
}
