// SPDX-License-Identifier: MIT OR Apache-2.0
//! The corpus tests: the escape decoder, the line parser, and one `#[test]`
//! per corpus file in `corpus/` (`h1-heads.txt`, `paths.txt`, `chunked.txt`,
//! `mplex.txt`, and the `f:`/`x:` half of `forwarded.txt`), plus the reject
//! coverage test, the plain-ASCII check, the fuzz seed emitter, and the
//! threat-model freshness check.
//!
//! The `p:` half of `forwarded.txt` is `crates/irontraffic-conn/tests/corpus_proxy.rs`'s
//! job: `ProxyHeader::parse` lives in `irontraffic-conn`, which depends on
//! `irontraffic-http`, so a test inside `irontraffic-http` cannot name
//! `irontraffic_conn` without inverting the dependency. The escape decoder
//! and the line parser are duplicated there (about 70 lines) rather than
//! shared through a new crate, because the line format is frozen and two
//! consumers do not justify a shared test-support crate.
//!
//! All of this must complete in under 5 seconds: the corpus is about 120
//! entries total and every parser under test is O(entry length).

#![allow(
    clippy::panic,
    reason = "this whole file is corpus-parsing test-support code; clippy's own test detection \
              only exempts a function literally attributed #[test], not the ordinary helper \
              functions every #[test] here calls, and the issue's own instructions require a \
              rich panic message (file, line, offset) naming exactly what went wrong rather than \
              a bare unwrap, which is the same shape every #[test] fn in this crate already uses \
              freely under clippy.toml's allow-panic-in-tests"
)]

use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use bytes::BytesMut;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::forwarded::ForwardedChain;
use irontraffic_http::framing::{OtherCodings, RequestFraming};
use irontraffic_http::h1::H1Parser;
use irontraffic_http::h1::canonicalize::{H1Context, canonicalize_request};
use irontraffic_http::h1::chunked::{ChunkedDecoder, ChunkedEvent};
use irontraffic_http::mplex::body::BodyAccounting;
use irontraffic_http::mplex::{MplexContext, MplexHeadBuilder, MplexTrailerBuilder};
use irontraffic_http::path::{EncodedDot, EncodedSlash, NormalizedPath, PathPolicy, TargetForm};
use irontraffic_http::peer::TrustPolicy;
use irontraffic_http::{Limits, ParseStatus, RejectReason, Scheme, WireVersion};

/// The five corpus files this crate's tests read, in the order the issue
/// documents them.
const CORPUS_FILES: [&str; 5] = [
    "h1-heads.txt",
    "paths.txt",
    "chunked.txt",
    "mplex.txt",
    "forwarded.txt",
];

/// A fixed, never-consulted trust policy for the fixed `H1Context` and
/// `MplexContext` every corpus test drives its parser through.
const DEFAULT_TRUST: TrustPolicy = TrustPolicy::None;

// ---------------------------------------------------------------------------
// The escape decoder and the line parser.
// ---------------------------------------------------------------------------

/// Decodes the corpus escape syntax into bytes.
///
/// Exactly six escapes: `\r`, `\n`, `\t`, `\0`, `\\`, and `\xHH`. Anything
/// else after a backslash is an error, so a typo in the corpus fails the
/// test rather than silently producing different bytes.
fn unescape(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&byte) = bytes.get(i) {
        if byte != b'\\' {
            out.push(byte);
            i = i.saturating_add(1);
            continue;
        }
        let Some(&marker) = bytes.get(i.saturating_add(1)) else {
            return Err(format!("truncated escape at byte offset {i}"));
        };
        match marker {
            b'r' => {
                out.push(b'\r');
                i = i.saturating_add(2);
            }
            b'n' => {
                out.push(b'\n');
                i = i.saturating_add(2);
            }
            b't' => {
                out.push(b'\t');
                i = i.saturating_add(2);
            }
            b'0' => {
                out.push(0);
                i = i.saturating_add(2);
            }
            b'\\' => {
                out.push(b'\\');
                i = i.saturating_add(2);
            }
            b'x' => {
                let hi_raw = bytes.get(i.saturating_add(2));
                let lo_raw = bytes.get(i.saturating_add(3));
                let (Some(&hi_raw), Some(&lo_raw)) = (hi_raw, lo_raw) else {
                    return Err(format!("truncated \\x escape at byte offset {i}"));
                };
                let (Some(hi), Some(lo)) = (hex_digit(hi_raw), hex_digit(lo_raw)) else {
                    return Err(format!(
                        "invalid hex digits in \\x escape at byte offset {i}"
                    ));
                };
                out.push(hi.saturating_mul(16).saturating_add(lo));
                i = i.saturating_add(4);
            }
            other => {
                return Err(format!(
                    "unknown escape '\\{}' at byte offset {i}",
                    other as char
                ));
            }
        }
    }
    Ok(out)
}

/// The value of one ASCII hex digit, or `None` if `b` is not one.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// The exact expectation of one corpus entry: `ok`, `partial`, or a named
/// `RejectReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    Partial,
    Reject(RejectReason),
}

/// Parses an `<outcome>` field. Fails, naming the offending text, when it is
/// none of `ok`, `partial`, or a real `RejectReason` variant name.
fn parse_outcome(name: &str, line_no: usize, file: &str) -> Outcome {
    match name {
        "ok" => Outcome::Ok,
        "partial" => Outcome::Partial,
        other => RejectReason::ALL
            .into_iter()
            .find(|r| format!("{r:?}") == other)
            .map_or_else(
                || {
                    panic!(
                        "{file}:{line_no}: unknown outcome name {other:?}; valid names are \
                         `ok`, `partial`, or one of the 73 RejectReason variant names"
                    )
                },
                Outcome::Reject,
            ),
    }
}

/// One parsed corpus line: `<outcome><TAB><bytes>[<TAB><extra>][<TAB><extra2>]`.
struct Entry<'a> {
    line_no: usize,
    outcome_field: &'a str,
    bytes_field: &'a str,
    extra: Option<&'a str>,
    extra2: Option<&'a str>,
}

impl Entry<'_> {
    /// Decodes the byte field, panicking with the file, the line, and the
    /// escape's byte offset on a malformed escape: a corpus typo must never
    /// be diagnosed by a bare `unwrap`.
    fn decode_bytes(&self, file: &str) -> Vec<u8> {
        decode_field(self.bytes_field, self.line_no, file)
    }

    /// Parses the outcome field.
    fn outcome(&self, file: &str) -> Outcome {
        parse_outcome(self.outcome_field, self.line_no, file)
    }

    /// A locator string for an assertion failure message: the file, the
    /// line number, and the escaped bytes as written in the corpus.
    fn locator(&self, file: &str) -> String {
        format!("{file}:{}: {:?}", self.line_no, self.bytes_field)
    }
}

/// Decodes `s`, panicking with `file`, `line_no` and the escape's byte
/// offset on a malformed escape.
fn decode_field(s: &str, line_no: usize, file: &str) -> Vec<u8> {
    unescape(s).unwrap_or_else(|e| panic!("{file}:{line_no}: {e}"))
}

/// Parses `text` (one corpus file's content) into entries. Comment lines
/// (`#`) and empty lines are skipped. A line with no tab fails with the
/// line number and an explanatory message.
fn parse_entries<'a>(text: &'a str, file: &str) -> Vec<Entry<'a>> {
    let mut out = Vec::new();
    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx.saturating_add(1);
        if raw_line.is_empty() || raw_line.starts_with('#') {
            continue;
        }
        let mut parts = raw_line.split('\t');
        let outcome_field = parts
            .next()
            .unwrap_or_else(|| panic!("{file}:{line_no}: expected `<outcome><TAB><bytes>`"));
        let Some(bytes_field) = parts.next() else {
            panic!("{file}:{line_no}: expected `<outcome><TAB><bytes>`");
        };
        let extra = parts.next();
        let extra2 = parts.next();
        out.push(Entry {
            line_no,
            outcome_field,
            bytes_field,
            extra,
            extra2,
        });
    }
    out
}

/// The path to `corpus/<name>`, resolved from `CARGO_MANIFEST_DIR` so the
/// tests work under `cargo test` from anywhere in the workspace.
fn corpus_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join(name)
}

/// Reads `corpus/<name>` and leaks it to `'static`: every corpus test needs
/// its `Entry` values to outlive the function that parsed them, and leaking
/// a few kilobytes once per test run is cheaper than threading the owned
/// `String` through every caller.
fn read_corpus_text(name: &str) -> &'static str {
    let path = corpus_path(name);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    Box::leak(text.into_boxed_str())
}

/// Reads and parses `corpus/<name>`.
fn read_corpus_entries(name: &str) -> Vec<Entry<'static>> {
    parse_entries(read_corpus_text(name), name)
}

/// Every outcome-shaped string that appears in `corpus/<file>`: every
/// entry's primary outcome field, plus, for `mplex.txt` only, every entry's
/// post-head-operation outcome (`extra2`), because that is where
/// `ContentLengthMismatch` and `PseudoHeaderInTrailer` are actually
/// produced.
fn corpus_outcomes(file: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for entry in read_corpus_entries(file) {
        set.insert(entry.outcome_field.to_owned());
        if file == "mplex.txt"
            && let Some(e2) = entry.extra2
        {
            set.insert(e2.to_owned());
        }
    }
    set
}

// ---------------------------------------------------------------------------
// Test 1: h1_heads.
// ---------------------------------------------------------------------------

/// The fixed `H1Context` `h1_heads` drives every entry through: default
/// limits, default path policy, `OtherCodings::Reject`,
/// `UnderscorePolicy::Reject`, `Scheme::Https`, a fixed socket peer,
/// `TrustPolicy::None`, no default authority, `forward_proxy: false`,
/// `will_buffer_body: false`.
fn h1_context() -> H1Context<'static> {
    H1Context {
        limits: Limits::DEFAULT.clamped(),
        path_policy: PathPolicy::DEFAULT,
        codings: OtherCodings::Reject,
        underscores: UnderscorePolicy::Reject,
        scheme: Scheme::Https,
        socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 12345),
        proxy_proto: None,
        trust: &DEFAULT_TRUST,
        default_authority: None,
        forward_proxy: false,
        will_buffer_body: false,
    }
}

/// Iterates `corpus/h1-heads.txt`: `H1Parser::parse_request_head`, then on
/// `Complete`, `canonicalize_request`. Asserts the outcome and, where an
/// `<extra>` is present on an `ok` entry, `consumed`.
#[test]
fn h1_heads() {
    let file = "h1-heads.txt";
    let entries = read_corpus_entries(file);
    let ctx = h1_context();
    let parser = H1Parser::new(&ctx.limits, ctx.underscores);
    // Counts entries that pin `consumed`, so deleting the field from the
    // one row that carries it (the pipelining row) is a red build rather
    // than a silent, green relaxation of that row's contract.
    let mut consumed_pins = 0usize;

    for entry in &entries {
        let bytes = entry.decode_bytes(file);
        let outcome = entry.outcome(file);
        match parser.parse_request_head(&bytes) {
            Ok(ParseStatus::Partial) => {
                assert_eq!(
                    outcome,
                    Outcome::Partial,
                    "{}: parser returned Partial",
                    entry.locator(file)
                );
            }
            Err(reason) => {
                assert_eq!(
                    outcome,
                    Outcome::Reject(reason),
                    "{}: parser rejected",
                    entry.locator(file)
                );
            }
            Ok(ParseStatus::Complete { value, consumed }) => {
                let mut arena = BytesMut::new();
                match canonicalize_request(&value, &ctx, &mut arena) {
                    Ok(_) => {
                        assert_eq!(
                            outcome,
                            Outcome::Ok,
                            "{}: canonicalize_request succeeded",
                            entry.locator(file)
                        );
                        if let Some(extra) = entry.extra {
                            consumed_pins = consumed_pins.saturating_add(1);
                            let want: usize = extra.parse().unwrap_or_else(|e| {
                                panic!(
                                    "{}: extra field {extra:?} is not a usize: {e}",
                                    entry.locator(file)
                                )
                            });
                            assert_eq!(
                                consumed,
                                want,
                                "{}: consumed mismatch",
                                entry.locator(file)
                            );
                        }
                    }
                    Err(reason) => {
                        assert_eq!(
                            outcome,
                            Outcome::Reject(reason),
                            "{}: canonicalize_request rejected",
                            entry.locator(file)
                        );
                    }
                }
            }
        }
    }

    assert_eq!(
        consumed_pins, 1,
        "h1-heads.txt: expected exactly 1 entry pinning `consumed` (the pipelining row); \
         found {consumed_pins}. A count that dropped means a `consumed` field was deleted \
         rather than the row being removed outright"
    );
}

// ---------------------------------------------------------------------------
// Test 2: paths.
// ---------------------------------------------------------------------------

/// Iterates `corpus/paths.txt`: `NormalizedPath::parse_into` under the named
/// policy (default when absent). Asserts the outcome and, for `ok`, the
/// exact output bytes when the corpus carries them.
#[test]
fn paths() {
    let file = "paths.txt";
    let entries = read_corpus_entries(file);
    let limits = Limits::DEFAULT.clamped();

    for entry in &entries {
        let target = entry.decode_bytes(file);
        let outcome = entry.outcome(file);

        let (policy, expected_field) = match entry.extra {
            None => (PathPolicy::DEFAULT, None),
            Some(e) if e.starts_with('/') => (PathPolicy::DEFAULT, Some(e)),
            Some("default") => (PathPolicy::DEFAULT, entry.extra2),
            Some("keep-dot") => (
                PathPolicy {
                    encoded_dot: EncodedDot::Keep,
                    ..PathPolicy::DEFAULT
                },
                entry.extra2,
            ),
            Some("keep-slash") => (
                PathPolicy {
                    encoded_slash: EncodedSlash::Keep,
                    ..PathPolicy::DEFAULT
                },
                entry.extra2,
            ),
            Some("keep-both") => (
                PathPolicy {
                    encoded_dot: EncodedDot::Keep,
                    encoded_slash: EncodedSlash::Keep,
                    merge_slashes: false,
                },
                entry.extra2,
            ),
            Some("merge-slashes") => (
                PathPolicy {
                    merge_slashes: true,
                    ..PathPolicy::DEFAULT
                },
                entry.extra2,
            ),
            Some(other) => panic!(
                "{}: unknown path policy name {other:?}; valid names are `default`, \
                 `keep-dot`, `keep-slash`, `keep-both`, `merge-slashes`",
                entry.locator(file)
            ),
        };

        // Every `ok` entry must carry its expected output bytes (the
        // acceptance criteria say so explicitly): a corpus row that only
        // asserts acceptance, and not the normalized bytes it produced,
        // would pass unchanged if normalization started producing the
        // wrong output. Deleting the expected-output field is therefore
        // not a silent, green way to relax an entry.
        assert!(
            !(matches!(outcome, Outcome::Ok) && expected_field.is_none()),
            "{}: an `ok` entry must carry its expected output bytes",
            entry.locator(file)
        );

        let mut out = BytesMut::new();
        let result = NormalizedPath::parse_into(&target, &policy, &limits, &mut out);
        match (outcome, result) {
            (Outcome::Ok, Ok((path, _query))) => {
                if let Some(expected) = expected_field {
                    let expected_bytes = decode_field(expected, entry.line_no, file);
                    assert_eq!(
                        path.as_bytes(),
                        expected_bytes.as_slice(),
                        "{}: output mismatch",
                        entry.locator(file)
                    );
                }
            }
            (Outcome::Reject(want), Err(got)) => {
                assert_eq!(want, got, "{}", entry.locator(file));
            }
            (Outcome::Partial, _) => {
                panic!(
                    "{}: `partial` is not a valid outcome for paths.txt",
                    entry.locator(file)
                );
            }
            (expected, got) => {
                panic!(
                    "{}: expected {expected:?}, got {got:?}",
                    entry.locator(file)
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 3: chunked.
// ---------------------------------------------------------------------------

/// Feeds the whole entry to a fresh `ChunkedDecoder`, looping `decode`
/// calls until `Done`, an `Err`, or no further progress. Returns the final
/// cumulative `consumed` on `Done`.
fn drive_chunked(bytes: &[u8]) -> Option<Result<usize, RejectReason>> {
    let limits = Limits::DEFAULT.clamped();
    let mut decoder = ChunkedDecoder::new(&limits, UnderscorePolicy::Reject);
    let mut arena = BytesMut::new();
    let mut pos = 0usize;
    let max_iters = bytes.len().saturating_add(8);

    for _ in 0..max_iters {
        let buf = bytes.get(pos..).unwrap_or(&[]);
        match decoder.decode(buf, &mut arena) {
            Ok(ChunkedEvent::Data { .. }) => {
                pos = pos.saturating_add(decoder.consumed_this_call());
            }
            Ok(ChunkedEvent::NeedMore) => {
                let consumed = decoder.consumed_this_call();
                if consumed == 0 {
                    return None;
                }
                pos = pos.saturating_add(consumed);
            }
            Ok(ChunkedEvent::Done { consumed }) => {
                return Some(Ok(pos.saturating_add(consumed)));
            }
            Err(reason) => return Some(Err(reason)),
        }
    }
    None
}

/// Iterates `corpus/chunked.txt`: the whole entry fed to a fresh
/// `ChunkedDecoder`. Asserts the outcome and, where present, `Done { consumed }`.
#[test]
fn chunked() {
    let file = "chunked.txt";
    let entries = read_corpus_entries(file);
    // Counts entries that pin `Done { consumed }`, so deleting the field
    // from the one row that carries it (the trailing-garbage row) is a red
    // build rather than a silent, green relaxation of that row's contract.
    let mut consumed_pins = 0usize;

    for entry in &entries {
        let bytes = entry.decode_bytes(file);
        let outcome = entry.outcome(file);
        let result = drive_chunked(&bytes).unwrap_or_else(|| {
            panic!(
                "{}: decoder never resolved to Done or Err",
                entry.locator(file)
            )
        });
        match (outcome, result) {
            (Outcome::Ok, Ok(consumed)) => {
                if let Some(extra) = entry.extra {
                    consumed_pins = consumed_pins.saturating_add(1);
                    let want: usize = extra.parse().unwrap_or_else(|e| {
                        panic!(
                            "{}: extra field {extra:?} is not a usize: {e}",
                            entry.locator(file)
                        )
                    });
                    assert_eq!(consumed, want, "{}: consumed mismatch", entry.locator(file));
                }
            }
            (Outcome::Reject(want), Err(got)) => {
                assert_eq!(want, got, "{}", entry.locator(file));
            }
            (Outcome::Partial, _) => {
                panic!(
                    "{}: `partial` is not a valid outcome for chunked.txt",
                    entry.locator(file)
                );
            }
            (expected, got) => {
                panic!(
                    "{}: expected {expected:?}, got {got:?}",
                    entry.locator(file)
                );
            }
        }
    }

    assert_eq!(
        consumed_pins, 1,
        "chunked.txt: expected exactly 1 entry pinning `Done {{ consumed }}` (the \
         trailing-garbage row); found {consumed_pins}. A count that dropped means the field \
         was deleted rather than the row being removed outright"
    );
}

// ---------------------------------------------------------------------------
// Test 4: mplex.
// ---------------------------------------------------------------------------

/// Splits a decoded `mplex.txt` pair list on `|`, then each pair on its
/// first `=`.
fn split_mplex_pairs(bytes: &[u8]) -> Vec<(&[u8], &[u8])> {
    bytes
        .split(|&b| b == b'|')
        .map(|pair| {
            let eq = pair.iter().position(|&b| b == b'=').unwrap_or(pair.len());
            let name = pair.get(..eq).unwrap_or(pair);
            let value = pair.get(eq.saturating_add(1)..).unwrap_or(&[]);
            (name, value)
        })
        .collect()
}

/// The fixed `MplexContext` `mplex` drives every entry through: default
/// limits, default path policy, `OtherCodings::Reject`,
/// `UnderscorePolicy::Reject`, `Scheme::Https`, a fixed socket peer,
/// `TrustPolicy::None`, `will_buffer_body: false`.
fn mplex_context(limits: irontraffic_http::ClampedLimits) -> MplexContext<'static> {
    MplexContext {
        limits,
        path_policy: PathPolicy::DEFAULT,
        codings: OtherCodings::Reject,
        underscores: UnderscorePolicy::Reject,
        scheme: Scheme::Https,
        socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 12345),
        proxy_proto: None,
        trust: &DEFAULT_TRUST,
        will_buffer_body: false,
    }
}

/// Runs one `mplex.txt` entry: pushes every pair into a fresh
/// `MplexHeadBuilder` (H2), calls `finish`, then, when the entry names a
/// post-head operation, applies it and asserts its own expected outcome.
///
/// A closure defined inside `mplex`'s own body, not a free function:
/// `scripts/invariant-lints.sh`'s `no-test-without-assertion` rule scans a
/// test function's OWN body text for an assertion and cannot see through a
/// call to a separate top-level function that does the asserting, the same
/// reason `authority.rs`'s own `corpus_table` test inlines its `assert_case`
/// closure rather than factoring it out.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one linear per-entry driver over the head-level result plus the two post-head \
              operations (finish, trailer:<name>=<value>), inlined as a closure so the \
              assertions stay in this test's own body for no-test-without-assertion; splitting \
              it would scatter the step ordering the corpus format itself depends on"
)]
fn mplex() {
    let run_entry = |entry: &Entry<'_>| {
        let file = "mplex.txt";
        let pairs_raw = entry.decode_bytes(file);
        let pairs = split_mplex_pairs(&pairs_raw);

        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = MplexHeadBuilder::new(&arena, &limits, WireVersion::H2);
        let mut push_err = None;
        for &(name, value) in &pairs {
            if let Err(e) = builder.push(&mut arena, name, value) {
                push_err = Some(e);
                break;
            }
        }

        let ctx = mplex_context(limits);
        let head_result = match push_err {
            Some(e) => Err(e),
            None => builder.finish(&ctx, &mut arena),
        };
        let head_outcome = entry.outcome(file);

        let Some(post_op) = entry.extra else {
            match (head_outcome, head_result) {
                (Outcome::Ok, Ok((_request, form))) => {
                    let is_options_asterisk = pairs
                        .iter()
                        .any(|&(n, v)| n == b":method" && v == b"OPTIONS")
                        && pairs.iter().any(|&(n, v)| n == b":path" && v == b"*");
                    if is_options_asterisk {
                        assert_eq!(
                            form,
                            TargetForm::Asterisk,
                            "{}: OPTIONS * must resolve to TargetForm::Asterisk",
                            entry.locator(file)
                        );
                    }
                }
                (Outcome::Reject(want), Err(got)) => {
                    assert_eq!(want, got, "{}", entry.locator(file));
                }
                (Outcome::Partial, _) => {
                    panic!(
                        "{}: `partial` is not a valid outcome for mplex.txt",
                        entry.locator(file)
                    );
                }
                (expected, got) => {
                    panic!(
                        "{}: expected {expected:?}, got {got:?}",
                        entry.locator(file)
                    );
                }
            }
            return;
        };

        // A row with a post-head operation always has `ok` as its head-level
        // outcome: the operation only runs once the head itself finished
        // cleanly.
        assert_eq!(
            head_outcome,
            Outcome::Ok,
            "{}: a row with a post-head operation must have `ok` as its head-level outcome",
            entry.locator(file)
        );
        let (request, _form) = match head_result {
            Ok(pair) => pair,
            Err(e) => panic!(
                "{}: head finish failed ({e:?}) even though the head-level outcome is `ok`",
                entry.locator(file)
            ),
        };

        let post_outcome_field = entry.extra2.unwrap_or_else(|| {
            panic!(
                "{}: a post-head operation needs a fourth field naming its own expected outcome",
                entry.locator(file)
            )
        });
        let post_outcome = parse_outcome(post_outcome_field, entry.line_no, file);

        if post_op == "finish" {
            // The mplex test asserts the resolved framing for the row with
            // neither `content-length` nor `transfer-encoding`, not only
            // the `finish` outcome: if step 8 of `resolve_request_framing`
            // is ever changed back to answering `Empty` on a multiplexed
            // request, that maps to `declared: Some(0)`, and a `finish`
            // call with zero received octets is `Ok` either way, so the
            // outcome alone cannot tell `Streamed` (a real streaming
            // upload) from `Empty` (no body permitted at all) apart. See
            // `request-framing-resolution` (#27) step 8.
            let has_length_field = pairs.iter().any(|&(name, _)| {
                name.eq_ignore_ascii_case(b"content-length")
                    || name.eq_ignore_ascii_case(b"transfer-encoding")
            });
            if !has_length_field {
                assert_eq!(
                    request.framing,
                    RequestFraming::Streamed,
                    "{}: a multiplexed request with neither content-length nor \
                     transfer-encoding must resolve to RequestFraming::Streamed, not Empty",
                    entry.locator(file)
                );
            }
            let mut acc = BodyAccounting::new(request.framing);
            let result = acc.finish();
            match (post_outcome, result) {
                (Outcome::Ok, Ok(())) => {}
                (Outcome::Reject(want), Err(got)) => {
                    assert_eq!(want, got, "{}: finish operation", entry.locator(file));
                }
                (expected, got) => panic!(
                    "{}: finish operation expected {expected:?}, got {got:?}",
                    entry.locator(file)
                ),
            }
        } else if let Some(rest) = post_op.strip_prefix("trailer:") {
            let eq = rest.find('=').unwrap_or_else(|| {
                panic!(
                    "{}: trailer post-op {rest:?} has no `=`",
                    entry.locator(file)
                )
            });
            let name = rest.get(..eq).unwrap_or("").as_bytes();
            let value = rest.get(eq.saturating_add(1)..).unwrap_or("").as_bytes();
            let mut trailer_arena = BytesMut::new();
            let mut trailer_builder =
                MplexTrailerBuilder::new(&trailer_arena, &limits, WireVersion::H2);
            let result = trailer_builder.push(&mut trailer_arena, name, value);
            match (post_outcome, result) {
                (Outcome::Ok, Ok(())) => {
                    // Edge case 12: a `trailer:` operation that is
                    // expected to succeed asserts the finished trailer
                    // section actually contains the pushed field (proving
                    // `MplexTrailerBuilder::finish`, which no corpus
                    // assertion called before this row existed) and that
                    // it is a value separate from the request's own
                    // headers, never merged into the head builder.
                    let trailer_section = trailer_builder.finish(&mut trailer_arena);
                    let pushed = trailer_section.get_all(name).any(|v| v == value);
                    assert!(
                        pushed,
                        "{}: trailer operation succeeded but the finished trailer section \
                         does not contain the pushed field {:?}={:?}",
                        entry.locator(file),
                        String::from_utf8_lossy(name),
                        String::from_utf8_lossy(value)
                    );
                    let leaked_into_headers = request.headers.get_all(name).any(|v| v == value);
                    assert!(
                        !leaked_into_headers,
                        "{}: trailer field {:?}={:?} appears in request.headers; a trailer \
                         section must stay a separate value, never merged into the head \
                         builder's fields",
                        entry.locator(file),
                        String::from_utf8_lossy(name),
                        String::from_utf8_lossy(value)
                    );
                }
                (Outcome::Reject(want), Err(got)) => {
                    assert_eq!(want, got, "{}: trailer operation", entry.locator(file));
                }
                (expected, got) => panic!(
                    "{}: trailer operation expected {expected:?}, got {got:?}",
                    entry.locator(file)
                ),
            }
        } else {
            panic!(
                "{}: unknown mplex post-head operation {post_op:?}; valid operations are \
                 `finish` and `trailer:<name>=<value>`",
                entry.locator(file)
            );
        }
    };

    // Counts rows carrying a post-head operation (`finish` or `trailer:`),
    // so deleting one of the five (the `content-length: 100` finish row,
    // the no-length-field finish row, and the three `trailer:` rows) is a
    // red build rather than a silent, green relaxation of that row's
    // contract back to a head-level-only check.
    let mut post_op_rows = 0usize;
    for entry in &read_corpus_entries("mplex.txt") {
        if entry.extra.is_some() {
            post_op_rows = post_op_rows.saturating_add(1);
        }
        run_entry(entry);
    }

    assert_eq!(
        post_op_rows, 5,
        "mplex.txt: expected exactly 5 rows carrying a post-head operation (2 `finish`, 3 \
         `trailer:`); found {post_op_rows}. A count that dropped means a post-op field was \
         deleted rather than the row being removed outright"
    );
}

// ---------------------------------------------------------------------------
// Test 5: forwarded (the f:/x: half; p: is corpus_proxy.rs's `proxy`).
// ---------------------------------------------------------------------------

/// Turns the bytes AFTER a `f:`/`x:` marker's colon into the list of values
/// to feed to `ForwardedChain::parse_into`'s matching iterator: either the
/// one expansion of an `@repeat:<token>:<count>` generator directive, or
/// the `|`-separated `<FieldName>: <value>` segments' values in order.
fn forwarded_marker_values(payload: &[u8]) -> Vec<Vec<u8>> {
    const REPEAT_PREFIX: &[u8] = b"@repeat:";
    if let Some(rest) = payload.strip_prefix(REPEAT_PREFIX) {
        let text = std::str::from_utf8(rest)
            .unwrap_or_else(|e| panic!("@repeat directive is not valid UTF-8: {e}"));
        let Some(sep) = text.rfind(':') else {
            panic!("@repeat directive {text:?} has no `:<count>` suffix");
        };
        let token = text.get(..sep).unwrap_or("");
        let count_text = text.get(sep.saturating_add(1)..).unwrap_or("");
        let count: usize = count_text
            .parse()
            .unwrap_or_else(|e| panic!("@repeat directive {text:?} has a non-numeric count: {e}"));
        return vec![token.as_bytes().repeat(count)];
    }
    payload
        .split(|&b| b == b'|')
        .map(|segment| {
            let colon = segment.iter().position(|&b| b == b':').unwrap_or_else(|| {
                panic!("forwarded/xff segment {segment:?} has no `:` separating the field name")
            });
            let after = segment.get(colon.saturating_add(1)..).unwrap_or(&[]);
            let value = after.strip_prefix(b" ").unwrap_or(after);
            value.to_vec()
        })
        .collect()
}

/// Iterates `corpus/forwarded.txt`, handling `f:` and `x:` lines through
/// `ForwardedChain::parse_into` and skipping `p:` lines. Asserts it
/// processed at least one non-`p:` line.
#[test]
fn forwarded() {
    let file = "forwarded.txt";
    let entries = read_corpus_entries(file);
    let limits = Limits::DEFAULT.clamped();
    let mut saw_non_p = false;

    for entry in &entries {
        let decoded = entry.decode_bytes(file);
        let Some((&marker_byte, rest)) = decoded.split_first() else {
            panic!("{}: entry has no marker byte", entry.locator(file));
        };
        if marker_byte == b'p' {
            continue;
        }
        saw_non_p = true;

        let payload = rest.get(1..).unwrap_or(&[]); // rest[0] is the `:` after the marker letter.
        let values = forwarded_marker_values(payload);
        let value_refs: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();

        let mut out = BytesMut::new();
        let result = match marker_byte {
            b'f' => ForwardedChain::parse_into(
                value_refs.into_iter(),
                std::iter::empty(),
                std::iter::empty(),
                &limits,
                &mut out,
            ),
            b'x' => ForwardedChain::parse_into(
                std::iter::empty(),
                value_refs.into_iter(),
                std::iter::empty(),
                &limits,
                &mut out,
            ),
            other => panic!(
                "{}: unknown forwarded.txt marker '{}'",
                entry.locator(file),
                other as char
            ),
        };

        let outcome = entry.outcome(file);
        match (outcome, result) {
            (Outcome::Ok, Ok(_)) => {}
            (Outcome::Reject(want), Err(got)) => assert_eq!(want, got, "{}", entry.locator(file)),
            (Outcome::Partial, _) => panic!(
                "{}: `partial` is not a valid outcome for an f:/x: entry",
                entry.locator(file)
            ),
            (expected, got) => panic!(
                "{}: expected {expected:?}, got {got:?}",
                entry.locator(file)
            ),
        }
    }

    assert!(
        saw_non_p,
        "forwarded.txt has no f:/x: entries; marker handling may be broken"
    );
}

// ---------------------------------------------------------------------------
// Test 6: reject_table_coverage.
// ---------------------------------------------------------------------------

/// Every `RejectReason` variant a real corpus entry, in any of the five
/// files, produces as an outcome.
#[rustfmt::skip]
const REQUIRED: [RejectReason; 51] = [
    RejectReason::RequestLineMalformed,
    RejectReason::TargetFormInvalid,
    RejectReason::TargetFragment,
    RejectReason::FieldNameEmpty,
    RejectReason::FieldNameInvalidByte,
    RejectReason::FieldNameUppercase,
    RejectReason::FieldNameUnderscore,
    RejectReason::FieldValueInvalidByte,
    RejectReason::FieldValueLeadingWhitespace,
    RejectReason::WhitespaceBeforeColon,
    RejectReason::ObsFold,
    RejectReason::BareCr,
    RejectReason::BareLf,
    RejectReason::ContentLengthDuplicate,
    RejectReason::ContentLengthInvalid,
    RejectReason::ContentLengthOverflow,
    RejectReason::ContentLengthMismatch,
    RejectReason::TransferEncodingWithContentLength,
    RejectReason::TransferEncodingOnHttp10,
    RejectReason::TransferEncodingFinalNotChunked,
    RejectReason::TransferEncodingChunkedRepeated,
    RejectReason::TransferEncodingUnsupportedCoding,
    RejectReason::ChunkSizeInvalid,
    RejectReason::ChunkSizeOverflow,
    RejectReason::ChunkExtInvalid,
    RejectReason::ChunkTerminatorInvalid,
    RejectReason::TrailerFieldForbidden,
    RejectReason::HostMissing,
    RejectReason::HostDuplicate,
    RejectReason::AuthorityEmpty,
    RejectReason::AuthorityInvalidByte,
    RejectReason::AuthorityNonAscii,
    RejectReason::AuthorityPortInvalid,
    RejectReason::AuthorityMismatch,
    RejectReason::PathInvalidByte,
    RejectReason::PathPercentTruncated,
    RejectReason::PathPercentInvalidHex,
    RejectReason::PathEncodedNul,
    RejectReason::PathEncodedDot,
    RejectReason::PathEncodedSlash,
    RejectReason::PathTraversalAboveRoot,
    RejectReason::PseudoHeaderUnknown,
    RejectReason::PseudoHeaderDuplicate,
    RejectReason::PseudoHeaderMissing,
    RejectReason::PseudoHeaderAfterField,
    RejectReason::PseudoHeaderInTrailer,
    RejectReason::ConnectionSpecificField,
    RejectReason::TeValueNotTrailers,
    RejectReason::ForwardedElementLimit,
    RejectReason::ForwardedBytesLimit,
    RejectReason::ForwardedDuplicateParam,
];

/// The 22 `RejectReason` variants no corpus entry reaches at this
/// milestone, each with the one-line reason why, matching the Design
/// section's own table exactly. A variant may never move from `REQUIRED`
/// to here to make a build green: that is a statement that the product
/// stopped refusing something.
#[rustfmt::skip]
const EXCLUDED: [RejectReason; 22] = [
    RejectReason::RequestLineTooLong, // needs a generated input larger than the corpus carries
    RejectReason::MethodInvalid, // no row exercises a malformed method token
    RejectReason::MethodTooLong, // needs a generated 17-byte method
    RejectReason::VersionUnsupported, // no row carries a version other than HTTP/1.0 or HTTP/1.1
    RejectReason::FieldValueTrailingWhitespace, // HTTP/1 trims trailing OWS; no mplex.txt row carries a trailing-SP value
    RejectReason::FieldLineTooLong, // needs a generated oversized field line
    RejectReason::FieldCountExceeded, // needs more than 100 generated field lines
    RejectReason::HeaderListTooLarge, // needs a generated header list above 65536 bytes
    RejectReason::TransferEncodingEmptyToken, // no row carries an empty coding token
    RejectReason::BodyNotAllowedForMethod, // needs a method plus body combination no row carries
    RejectReason::ChunkExtTooLong, // needs a generated oversized chunk extension
    RejectReason::TrailingGarbage, // the 0\r\n\r\nGARBAGE row is ok with consumed: 5; the decoder stops rather than refusing
    RejectReason::AuthorityTooLong, // needs a generated 256-byte authority
    RejectReason::PathEmpty, // needs an empty target, refused earlier as RequestLineMalformed by the request-line rows
    RejectReason::PathTooLong, // needs a generated oversized path
    RejectReason::QueryInvalidByte, // no path row carries an invalid byte after the question mark
    RejectReason::ExpectUnsupported, // needs an Expect field, which belongs to the response path
    RejectReason::InterimResponseCountExceeded, // needs a forwarding loop
    RejectReason::InterimResponseBytesExceeded, // needs a forwarding loop
    RejectReason::PseudoProtocolUnsupported, // no mplex.txt row exercises a CONNECT request advertising an unsupported protocol
    RejectReason::ForwardedSyntax, // every malformed Forwarded row is refused earlier by a cap or the duplicate-parameter rule
    RejectReason::RewriteLimitExceeded, // needs the rewrite pipeline
];

/// Asserts `REQUIRED.len() + EXCLUDED.len() == 73`, that the two lists are
/// disjoint and together cover every `RejectReason` variant, and that
/// every `REQUIRED` variant is produced as an outcome somewhere across the
/// five corpus files.
#[test]
fn reject_table_coverage() {
    assert_eq!(REQUIRED.len(), 51);
    assert_eq!(EXCLUDED.len(), 22);
    assert_eq!(REQUIRED.len() + EXCLUDED.len(), 73);

    let mut seen = [false; 73];
    for r in REQUIRED {
        let idx = RejectReason::ALL
            .iter()
            .position(|&x| x == r)
            .unwrap_or_else(|| panic!("{r:?} in REQUIRED is not a real RejectReason variant"));
        assert!(
            !seen.get(idx).copied().unwrap_or(true),
            "{r:?} appears more than once in REQUIRED"
        );
        if let Some(slot) = seen.get_mut(idx) {
            *slot = true;
        }
    }
    for r in EXCLUDED {
        let idx = RejectReason::ALL
            .iter()
            .position(|&x| x == r)
            .unwrap_or_else(|| panic!("{r:?} in EXCLUDED is not a real RejectReason variant"));
        assert!(
            !seen.get(idx).copied().unwrap_or(true),
            "{r:?} appears in both REQUIRED and EXCLUDED"
        );
        if let Some(slot) = seen.get_mut(idx) {
            *slot = true;
        }
    }
    assert!(
        seen.iter().all(|&b| b),
        "REQUIRED and EXCLUDED together do not cover every RejectReason variant"
    );

    let mut all_outcomes: HashSet<String> = HashSet::new();
    for file in CORPUS_FILES {
        all_outcomes.extend(corpus_outcomes(file));
    }

    let missing: Vec<String> = REQUIRED
        .into_iter()
        .map(|r| format!("{r:?}"))
        .filter(|name| !all_outcomes.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "REQUIRED RejectReason variants absent from every corpus file: {missing:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 7: corpus_files_are_plain_ascii.
// ---------------------------------------------------------------------------

/// Every byte of every corpus file is `0x09`, `0x0A`, or `0x20..=0x7E`, so
/// the corpus stays reviewable as plain ASCII and the dash scan cannot be
/// tripped by an invisible byte.
#[test]
fn corpus_files_are_plain_ascii() {
    for file in CORPUS_FILES {
        let path = corpus_path(file);
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        for (i, &b) in bytes.iter().enumerate() {
            assert!(
                b == 0x09 || b == 0x0A || (0x20..=0x7E).contains(&b),
                "{file} byte {i} is {b:#04x}, outside 0x09, 0x0A, 0x20..=0x7E"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Test 8: emit_fuzz_seeds.
// ---------------------------------------------------------------------------

/// Writes `bytes` into `<root>/<dir>/<outcome>-<index:04>`, creating `<dir>`
/// as needed. Fails loudly, naming the path, rather than silently writing
/// nothing.
fn write_seed(root: &Path, dir: &str, outcome: &str, index: usize, bytes: &[u8]) {
    let dir_path = root.join(dir);
    fs::create_dir_all(&dir_path)
        .unwrap_or_else(|e| panic!("creating fuzz corpus directory {}: {e}", dir_path.display()));
    let file_path = dir_path.join(format!("{outcome}-{index:04}"));
    fs::write(&file_path, bytes)
        .unwrap_or_else(|e| panic!("writing fuzz seed {}: {e}", file_path.display()));
}

/// Transforms a decoded `mplex.txt` pair-list into `fuzz_mplex_head`'s own
/// two-level delimiter encoding: `|` becomes `0xFF`, and the first `=` of
/// each pair becomes `0xFE`.
fn mplex_seed_bytes(pairs_raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, pair) in pairs_raw.split(|&b| b == b'|').enumerate() {
        if i > 0 {
            out.push(0xFF);
        }
        if let Some(eq) = pair.iter().position(|&b| b == b'=') {
            out.extend_from_slice(pair.get(..eq).unwrap_or(pair));
            out.push(0xFE);
            out.extend_from_slice(pair.get(eq.saturating_add(1)..).unwrap_or(&[]));
        } else {
            out.extend_from_slice(pair);
        }
    }
    out
}

/// Builds a `fuzz_forwarded` seed: eight `0xFF`-delimited slots (up to four
/// `Forwarded` values, then up to four `X-Forwarded-For` values), with
/// `value` placed in slot 0 for an `f:` entry or slot 4 for an `x:` entry.
fn forwarded_seed_bytes(marker_byte: u8, value: &[u8]) -> Vec<u8> {
    let mut slots: [Vec<u8>; 8] = Default::default();
    let idx = if marker_byte == b'f' { 0 } else { 4 };
    if let Some(slot) = slots.get_mut(idx) {
        *slot = value.to_vec();
    }
    let mut out = Vec::new();
    for (i, slot) in slots.iter().enumerate() {
        if i > 0 {
            out.push(0xFF);
        }
        out.extend_from_slice(slot);
    }
    out
}

/// The guarded fuzz seed emitter: a no-op unless
/// `IRONTRAFFIC_EMIT_FUZZ_SEEDS` is set. Writes each decoded corpus entry
/// into the matching fuzz target's corpus directory, in that target's own
/// input encoding, and never deletes anything. Idempotent: running it twice
/// produces byte-identical files.
///
/// `fuzz_field_validate` (field-validation-tables, #23) and `fuzz_authority`
/// (authority-parsing-and-reconciliation, #30) are deliberately NOT seeded
/// from this corpus: the first takes a single field name or value and the
/// second a scheme-selector byte plus an authority, and neither input shape
/// appears as a corpus line here (the corpus stores whole heads, not
/// individual field or authority bytes). Both issues already ship their own
/// seeds from their unit tables.
#[allow(
    clippy::too_many_lines,
    reason = "one emitter over seven target directories, each with its own transformation; \
              splitting it would scatter the per-target encoding table this issue specifies \
              as one unit across several functions with no clearer seam"
)]
#[test]
fn emit_fuzz_seeds() {
    if env::var("IRONTRAFFIC_EMIT_FUZZ_SEEDS").is_err() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus");
    let mut written: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

    for (index, entry) in read_corpus_entries("h1-heads.txt").iter().enumerate() {
        let bytes = entry.decode_bytes("h1-heads.txt");
        for dir in ["fuzz_h1_head", "fuzz_h1_differential", "fuzz_h1_roundtrip"] {
            write_seed(&root, dir, entry.outcome_field, index, &bytes);
            *written.entry(dir).or_default() =
                written.get(dir).copied().unwrap_or(0).saturating_add(1);
        }
    }

    for (index, entry) in read_corpus_entries("paths.txt").iter().enumerate() {
        let target = entry.decode_bytes("paths.txt");
        let mut seed = vec![0x00u8];
        seed.extend_from_slice(&target);
        write_seed(&root, "fuzz_path", entry.outcome_field, index, &seed);
        *written.entry("fuzz_path").or_default() = written
            .get("fuzz_path")
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
    }

    for (index, entry) in read_corpus_entries("chunked.txt").iter().enumerate() {
        let body = entry.decode_bytes("chunked.txt");
        let mut seed = vec![0x01u8];
        seed.extend_from_slice(&body);
        write_seed(&root, "fuzz_chunked", entry.outcome_field, index, &seed);
        *written.entry("fuzz_chunked").or_default() = written
            .get("fuzz_chunked")
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
    }

    for (index, entry) in read_corpus_entries("forwarded.txt").iter().enumerate() {
        let decoded = entry.decode_bytes("forwarded.txt");
        let Some((&marker_byte, rest)) = decoded.split_first() else {
            continue;
        };
        if marker_byte != b'f' && marker_byte != b'x' {
            continue;
        }
        let payload = rest.get(1..).unwrap_or(&[]);
        // Skip the `@repeat:` generator rows: their expansion (the
        // 100,000-element row alone is 800,000 bytes) would seed
        // fuzz_forwarded with a near-megabyte unit, and libFuzzer with no
        // explicit `-max_len` sets MaxLen from the largest seed in the
        // corpus, so one row would switch every generated input in the
        // whole campaign from ~4 KiB to ~800 KB. A fuzzer also learns
        // nothing from a row whose only content is one byte string
        // repeated N times; the byte cap it exercises is already pinned
        // by name in the `forwarded` test above, from this same corpus
        // entry, every run.
        if payload.starts_with(b"@repeat:") {
            continue;
        }
        let values = forwarded_marker_values(payload);
        let value = values.first().map_or(&[][..], Vec::as_slice);
        let seed = forwarded_seed_bytes(marker_byte, value);
        write_seed(&root, "fuzz_forwarded", entry.outcome_field, index, &seed);
        *written.entry("fuzz_forwarded").or_default() = written
            .get("fuzz_forwarded")
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
    }

    for (index, entry) in read_corpus_entries("mplex.txt").iter().enumerate() {
        let pairs_raw = entry.decode_bytes("mplex.txt");
        let seed = mplex_seed_bytes(&pairs_raw);
        write_seed(&root, "fuzz_mplex_head", entry.outcome_field, index, &seed);
        *written.entry("fuzz_mplex_head").or_default() = written
            .get("fuzz_mplex_head")
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
    }

    for dir in [
        "fuzz_h1_head",
        "fuzz_h1_differential",
        "fuzz_h1_roundtrip",
        "fuzz_path",
        "fuzz_chunked",
        "fuzz_forwarded",
        "fuzz_mplex_head",
    ] {
        assert!(
            written.get(dir).copied().unwrap_or(0) > 0,
            "emit_fuzz_seeds wrote nothing into {dir}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 12: threat_model_is_covered.
// ---------------------------------------------------------------------------

/// Parses `docs/THREAT-MODEL.md`'s `## 6. Evidence` table and asserts every
/// row has either a corpus citation or a stated reason, and that every
/// cited `(file, outcome)` pair actually appears in that corpus file.
#[test]
fn threat_model_is_covered() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let doc_path = repo_root.join("docs").join("THREAT-MODEL.md");
    let text =
        fs::read_to_string(&doc_path).unwrap_or_else(|e| panic!("reading {doc_path:?}: {e}"));

    let section_start = text
        .find("## 6. Evidence")
        .unwrap_or_else(|| panic!("docs/THREAT-MODEL.md has no `## 6. Evidence` section"));
    let after = text.get(section_start..).unwrap_or("");
    let section_end = after.find("\n## ").unwrap_or(after.len());
    let section = after.get(..section_end).unwrap_or(after);

    let known_files = CORPUS_FILES;
    let mut rows_checked = 0usize;

    for (row_idx, line) in section.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        // A literal pipe inside a cell must be written `\|` (GFM's escape);
        // stand it aside on a sentinel byte that cannot otherwise appear in
        // this ASCII-only document before splitting on the column
        // separator, then restore it inside each cell. Without this, a row
        // like `| attack text \| more text | citation | |` splits into 4
        // cells instead of 3 and used to be silently skipped below rather
        // than checked or rejected.
        let escaped_pipe_sentinel = '\u{0}';
        let unescaped = trimmed.replace("\\|", &escaped_pipe_sentinel.to_string());
        let cells: Vec<String> = unescaped
            .trim_start_matches('|')
            .trim_end_matches('|')
            .split('|')
            .map(|c| c.trim().replace(escaped_pipe_sentinel, "|"))
            .collect();
        // A well-formed row always has exactly 3 columns (Attack, Corpus
        // citation, Reason). A row that does not is not skipped: skipping
        // it would let it pass with neither a citation nor a reason
        // checked, which is the coverage gap `threat_model_is_covered`
        // exists to close. Fail loudly and name the row instead.
        assert_eq!(
            cells.len(),
            3,
            "docs/THREAT-MODEL.md section 6, row {row_idx}: expected exactly 3 columns \
             (Attack, Corpus citation, Reason) after splitting on `|`, found {} in {trimmed:?}; \
             escape a literal pipe inside a cell as `\\|`",
            cells.len()
        );
        let is_header = cells.first().map(String::as_str) == Some("Attack");
        let is_separator = cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-'));
        if is_header || is_separator {
            continue;
        }

        let attack = cells.first().map_or("", String::as_str);
        let citation = cells.get(1).map_or("", String::as_str);
        let reason = cells.get(2).map_or("", String::as_str);

        assert!(
            !citation.is_empty() || !reason.is_empty(),
            "row {row_idx} ({attack:?}) has neither a corpus citation nor a stated reason"
        );

        if !citation.is_empty() {
            let tokens: Vec<&str> = citation.split('`').collect();
            let cited_file = tokens.get(1).copied().unwrap_or_else(|| {
                panic!(
                    "row {row_idx} ({attack:?}): citation {citation:?} is not \
                     `` `file`: `outcome` ``"
                )
            });
            let cited_outcome = tokens.get(3).copied().unwrap_or_else(|| {
                panic!(
                    "row {row_idx} ({attack:?}): citation {citation:?} is not \
                     `` `file`: `outcome` ``"
                )
            });
            assert!(
                known_files.contains(&cited_file),
                "row {row_idx} ({attack:?}): citation names unknown corpus file {cited_file:?}"
            );
            let outcomes = corpus_outcomes(cited_file);
            assert!(
                outcomes.contains(cited_outcome),
                "row {row_idx} ({attack:?}): cited outcome {cited_outcome:?} does not appear \
                 in corpus/{cited_file}"
            );
        }

        rows_checked = rows_checked.saturating_add(1);
    }

    // The floor tracks the table's actual row count (50 as of this test), not
    // an arbitrary low number: with the malformed-row panic above, the only
    // way for `rows_checked` to fall short is a row that stopped starting
    // with `|` at all (deleted, or turned into prose). Raise this floor
    // when rows are legitimately added; never lower it to make a build
    // green.
    assert!(
        rows_checked >= 50,
        "threat_model_is_covered parsed only {rows_checked} evidence rows, fewer than the \
         50 the table is expected to hold; a row may have been deleted or stopped starting \
         with `|` in docs/THREAT-MODEL.md"
    );
}
