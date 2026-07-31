// SPDX-License-Identifier: MIT OR Apache-2.0
//! Path corpora (committed regexes) and route corpora (deterministic
//! generators) for the published benchmark matrix.
//!
//! **The corpus regex and the route table must agree.** If a path-generating
//! client expands paths from a regex whose language is not covered by the
//! generated route table, every request 404s, which either invalidates the
//! run (invariant I3) or, worse, silently measures the 404 path. The route
//! count in every published cell is a power of ten, which makes exact
//! coverage easy: `w = log10(n)` digits, route `i` rendered with `i`
//! zero-padded to `w` digits, and the paired corpus regex carries the same
//! width in the same position. [`route_table`] and [`path_expr`] are the two
//! halves of that agreement; test 7a in `tests/matrix.rs` is what proves it
//! holds for the two committed files.
//!
//! **Reading the two committed corpus files.** Each file holds the `w = 3`
//! instance (the base cell's 1,000 routes) of a generated family, preceded by
//! a `#`-prefixed header comment for a human reading the file directly. Only
//! the FINAL non-comment, non-blank line is the pattern; [`path_expr`] strips
//! the header before validating and returning it, so the printable-ASCII
//! bound below applies to the pattern it hands back to a caller (which is
//! what becomes a command-line argument and a result file field), not to the
//! whole file's human-readable prose. The file READ itself is still capped at
//! [`MAX_CORPUS_FILE_BYTES`] before a single line is examined.

use crate::cell::PathCorpus;
use crate::error::BenchError;

/// Shape of a generated route table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteShape {
    /// Distinct static paths with no shared prefix beyond the first segment.
    Flat,
    /// All routes under `/repos/{owner}/{repo}/`: the adversarial shape for
    /// prefix-sharing routers.
    SharedPrefix,
    /// Routes differing only in the final segment.
    LastSegment,
    /// A mix of static and dynamic routes reproducing the shape of real
    /// public APIs at 36, 217 and 609 routes.
    RealWorldMix,
}

/// One generated route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    /// Path pattern in the neutral form the runner renders per system under
    /// test.
    pub path_pattern: String,
    /// Which upstream cluster index this route points at.
    pub cluster: u16,
}

/// Largest route table this module will generate.
///
/// The named form of the literal 1,000,000 that `BenchCell::validate`
/// enforces on `routes` in `bench-crate-and-cell-model`, which declares no
/// constant for it. This is the only declaration; test 13a asserts the two
/// numbers agree.
pub const MAX_ROUTES: u32 = 1_000_000;

/// Largest committed corpus file `path_expr` will read, in bytes.
pub const MAX_CORPUS_FILE_BYTES: usize = 4096;

/// Longest single expanded path `path_samples` will produce, in bytes.
pub const MAX_SAMPLE_PATH_BYTES: usize = 2048;

/// Bound passed to any tool expanding a corpus regex. Without it, an
/// unbounded repetition operator (`*`, `+`, `{n,}`) generates paths that
/// measure the path-length limit, not the router.
///
/// This bounds an EXTERNAL tool's own regex expander (oha's `--max-repeat`
/// flag, and the identical parameter `rand_regex::Regex::compile` takes in
/// test 7a). It is deliberately NOT the bound `path_samples`'s own four
/// construct grammar (below) applies to a counted repetition: that bound is
/// the private `MAX_COUNTED_REPEAT`, and the two are different numbers for a
/// reason documented on that constant.
pub const MAX_REGEX_REPEAT: u32 = 4;

/// Largest repeat count `path_samples`'s own grammar accepts for a counted
/// repetition (`{n}` or `{n,m}`), applied to `m`. Not part of this issue's
/// Public API section (which names only `MAX_REGEX_REPEAT`), so this stays
/// private; see that constant's own doc for why the two are different
/// numbers for a different purpose.
///
/// This is deliberately NOT [`MAX_REGEX_REPEAT`]. That constant bounds an
/// EXTERNAL tool's expansion of an UNBOUNDED operator (`*`, `+`, `{n,}`, none
/// of which this grammar even accepts as a construct). This constant bounds
/// `path_samples`'s own COUNTED, already-bounded repetition, and the two
/// committed corpus files need it to be at least 8 (`[0-9a-f]{8}`, the
/// SingleHot/UniformRandom id) and at least 6 (`[0-9]{1,6}`, the adversarial
/// issue number): 16 covers both with headroom while still refusing anything
/// that would let a hostile corpus expression buy an unbounded-looking amount
/// of output through a large counted repeat.
const MAX_COUNTED_REPEAT: u32 = 16;

/// Largest `path_samples` sample count in one call. Not part of this
/// issue's Public API section, which states the 1..=1,000,000 bound as a
/// literal in `path_samples`'s own doc rather than naming a constant for
/// it; kept as a private constant here so the check and the doc agree by
/// construction.
const MAX_SAMPLE_COUNT: u32 = 1_000_000;

/// Relative path from this crate's manifest directory to the uniform-random
/// path corpus file.
const PATHS_UNIFORM_REL: &str = "../../bench/corpora/paths-uniform.regex";
/// Relative path from this crate's manifest directory to the adversarial
/// path corpus file.
const PATHS_ADVERSARIAL_REL: &str = "../../bench/corpora/paths-adversarial.regex";
/// The portable name recorded in an error when a corpus file cannot be read,
/// deliberately not the full local build path (which would leak this
/// machine's checkout layout into a committed or printed error message).
const PATHS_UNIFORM_NAME: &str = "bench/corpora/paths-uniform.regex";
const PATHS_ADVERSARIAL_NAME: &str = "bench/corpora/paths-adversarial.regex";

/// The literal substring that carries the `w = 3` digit-count group in both
/// committed corpus files, replaced with the requested width by
/// [`path_expr`]. Both files are authored so this substring appears exactly
/// once, immediately after the route-index character class.
const WIDTH_MARKER: &str = "{3}";

/// Widest zero-padded index [`route_table`] and [`path_expr`] will ever
/// render, computed from `max_index` (`n - 1` for `n` routes). Returns 1 for
/// `max_index == 0` (a single route, index 0, still renders as `"0"`).
///
/// Uses `u32::ilog10`, exact integer arithmetic, deliberately not a
/// floating-point `log10`: an `f64` computation of `log10` on an exact power
/// of ten can round down by one ULP on some inputs, which would render one
/// digit short of the true width. `ilog10` cannot make that mistake because
/// it never leaves the integers.
fn digit_width(max_index: u32) -> u32 {
    if max_index == 0 {
        1
    } else {
        max_index.ilog10() + 1
    }
}

/// Returns `Some(w)` when `routes == 10^w` for some `w` reachable from
/// [`MAX_ROUTES`], `None` otherwise. `routes == 1` (`10^0`) is accepted.
fn power_of_ten_width(routes: u32) -> Option<u32> {
    let mut w: u32 = 0;
    let mut p: u32 = 1;
    loop {
        if p == routes {
            return Some(w);
        }
        if p > routes || w >= 9 {
            return None;
        }
        // 10^9 fits comfortably in u32 (10^9 < 4.3e9), so this never
        // overflows before the `w >= 9` check above stops the loop.
        p *= 10;
        w += 1;
    }
}

/// Narrower shape used inside [`route_table`]'s per-route loop, once
/// [`RouteShape::RealWorldMix`] has already been dispatched to
/// [`real_world_mix_table`] and returned. Exists so the loop's own `match`
/// is exhaustive without a `RealWorldMix` arm that can never run, which
/// would otherwise have to be an unreachable-macro arm this crate's
/// `no-panic` rule forbids in production code.
enum LinearShape {
    Flat,
    SharedPrefix,
    LastSegment,
}

/// Generates `n` routes of the given shape, deterministically.
///
/// The same `(shape, n, clusters)` always yields a byte-identical table, on
/// any machine, in any process. That is what makes two runs comparable.
///
/// # Errors
/// `BenchError::Cell("route table too large")` when `n > MAX_ROUTES`: this
/// allocates `n` strings, and an infallible signature over a `u32` is four
/// billion of them. `BenchError::Cell("zero clusters")` when
/// `clusters == 0`, because route `i` points at cluster `i % clusters` and
/// `i % 0` panics in Rust.
pub fn route_table(shape: RouteShape, n: u32, clusters: u16) -> Result<Vec<RouteSpec>, BenchError> {
    if n > MAX_ROUTES {
        return Err(BenchError::Cell(
            "route table too large: n exceeds MAX_ROUTES",
        ));
    }
    if clusters == 0 {
        return Err(BenchError::Cell("zero clusters"));
    }
    if shape == RouteShape::RealWorldMix {
        return Ok(real_world_mix_table(n, clusters));
    }
    if n == 0 {
        return Ok(Vec::new());
    }

    let linear = match shape {
        RouteShape::Flat => LinearShape::Flat,
        RouteShape::SharedPrefix => LinearShape::SharedPrefix,
        RouteShape::LastSegment => LinearShape::LastSegment,
        RouteShape::RealWorldMix => return Ok(real_world_mix_table(n, clusters)),
    };

    // Widening u32 -> usize: always exact on every platform this workspace
    // targets, so clippy does not flag it and no escape is needed (unlike
    // the narrowing u32 -> u16 casts below).
    let w = digit_width(n - 1) as usize;
    let clusters_u32 = u32::from(clusters);
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "i % clusters_u32 is strictly less than clusters_u32, which itself came \
                      from a u16, so the remainder always fits back into u16 regardless of i's \
                      own magnitude"
        )]
        let cluster = (i % clusters_u32) as u16; // it-allow: unchecked-cast reason: i % clusters_u32 is strictly less than clusters_u32, which came from a u16, so the remainder always fits back into u16
        let path_pattern = match linear {
            LinearShape::Flat => format!("/api/v1/r{i:0w$}/{{id}}"),
            LinearShape::SharedPrefix => {
                format!("/repos/acme/r{i:0w$}/issues/{{num}}/(comments|reviews|files)")
            }
            LinearShape::LastSegment => format!("/api/v1/items/s{i:0w$}"),
        };
        out.push(RouteSpec {
            path_pattern,
            cluster,
        });
    }
    Ok(out)
}

/// The three sizes `RealWorldMix` reproduces: the `OpenAI`, Okta and GitHub
/// API shapes' route counts (36, 217, 609 routes respectively), per
/// `science/benchmarking.md`'s account of `vm-001/gateways-routing-benchmark`.
const REAL_WORLD_SIZES: [u32; 3] = [36, 217, 609];

/// Nearest entry in [`REAL_WORLD_SIZES`] to `n`. On an exact tie the SMALLER
/// size wins (the loop below only replaces the running best on a STRICTLY
/// smaller distance), which is deterministic and stated here because the
/// three sizes are close enough that a tie is reachable (`n = 413` is
/// equidistant between 217 and 609).
fn nearest_real_world_size(n: u32) -> u32 {
    // Destructured rather than indexed: `REAL_WORLD_SIZES[0]` would be a
    // `clippy::indexing_slicing` violation (denied workspace wide) even
    // though the array's length is a compile-time constant.
    let [first, second, third] = REAL_WORLD_SIZES;
    let mut best = first;
    let mut best_diff = n.abs_diff(best);
    for candidate in [second, third] {
        let diff = n.abs_diff(candidate);
        if diff < best_diff {
            best = candidate;
            best_diff = diff;
        }
    }
    best
}

/// `RealWorldMix`: a synthetic, deterministic mix of static and dynamic
/// routes at the nearest of 36, 217 or 609 routes to the requested `n`.
///
/// Generated from a small, committed set of templates cycled by index,
/// never copied from any vendor's own API specification: the Do NOT list
/// forbids copying a vendor's specification file into this repository for
/// exactly this shape, because the specification is a moving external
/// dependency and copying it raises a licensing question this repository
/// does not need to have. The four templates below alternate static and
/// dynamic (one wildcard segment) paths, which is the shape that matters,
/// not any particular vendor's own path spelling.
fn real_world_mix_table(n: u32, clusters: u16) -> Vec<RouteSpec> {
    let resolved = nearest_real_world_size(n);
    let clusters_u32 = u32::from(clusters);
    let mut out = Vec::with_capacity(resolved as usize);
    for i in 0..resolved {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "i % clusters_u32 is strictly less than clusters_u32, which itself came \
                      from a u16, so the remainder always fits back into u16 regardless of i's \
                      own magnitude"
        )]
        let cluster = (i % clusters_u32) as u16; // it-allow: unchecked-cast reason: i % clusters_u32 is strictly less than clusters_u32, which came from a u16, so the remainder always fits back into u16
        let path_pattern = match i % 4 {
            0 => format!("/v1/resources/r{i}"),
            1 => format!("/v1/resources/r{i}/items/{{id}}"),
            2 => format!("/v1/accounts/a{i}/profile"),
            _ => format!("/v1/accounts/a{i}/items/{{id}}/detail"),
        };
        out.push(RouteSpec {
            path_pattern,
            cluster,
        });
    }
    out
}

/// Reads a committed corpus file and returns its pattern with the digit-count
/// group substituted for `w`.
///
/// `name` is the portable name recorded in an `Io` error (never the local
/// absolute path, which would leak this machine's checkout layout);
/// `rel_from_manifest_dir` locates the file relative to
/// `CARGO_MANIFEST_DIR`, resolved at compile time to this crate's own
/// directory, so the read works regardless of the caller's current working
/// directory. This assumes the tool is always built and run from within the
/// same repository checkout, true of every caller today (`cargo test`,
/// `xtask`, and `bench/run.sh`): this crate is `publish = false` and is
/// never shipped as a standalone artifact to a different machine.
fn read_corpus_pattern(
    rel_from_manifest_dir: &str,
    name: &'static str,
    w: u32,
) -> Result<String, BenchError> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel_from_manifest_dir);
    let content = std::fs::read_to_string(&path).map_err(|e| BenchError::io(name, e))?; // it-allow: no-blocking-in-async reason: irontraffic-bench is a synchronous benchmark harness crate with no async runtime anywhere in it (no tokio dependency at all); this reads one small, capped, committed corpus file, not a request-path operation with a worker thread to stall

    // The byte check precedes any split, matching this crate's own
    // established pattern (`SaturationTable::parse` does the identical
    // thing): a bound checked only after the bytes are already in memory is
    // not a bound.
    if content.len() > MAX_CORPUS_FILE_BYTES {
        return Err(BenchError::parse(
            "corpus",
            "committed corpus file exceeds MAX_CORPUS_FILE_BYTES",
        ));
    }

    let mut pattern: Option<&str> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if pattern.is_some() {
            return Err(BenchError::parse(
                "corpus",
                "committed corpus file has more than one non-comment line",
            ));
        }
        pattern = Some(trimmed);
    }
    let pattern = pattern
        .ok_or_else(|| BenchError::parse("corpus", "committed corpus file has no pattern line"))?;

    // The bound applies to the PATTERN this function hands back (what
    // becomes a command-line argument and a result file field), not to the
    // whole file's human-readable header comment: see the module doc.
    if !pattern.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(BenchError::parse(
            "corpus",
            "corpus pattern contains a byte outside 0x21..=0x7E",
        ));
    }
    if !pattern.contains(WIDTH_MARKER) {
        return Err(BenchError::parse(
            "corpus",
            "corpus pattern does not contain the expected width marker {3}",
        ));
    }

    let substituted = pattern.replacen(WIDTH_MARKER, &format!("{{{w}}}"), 1);
    if substituted.len() > MAX_CORPUS_FILE_BYTES {
        return Err(BenchError::parse(
            "corpus",
            "substituted corpus pattern exceeds MAX_CORPUS_FILE_BYTES",
        ));
    }
    Ok(substituted)
}

/// The regex a path-generating client expands for the given corpus at the
/// given route-table size.
///
/// The width of the index group is `log10(routes)`, so every expansion
/// names exactly one route in [`route_table`] for the paired shape: `Flat`
/// for `UniformRandom`, `SharedPrefix` for `AdversarialWorstCase`. `routes`
/// must be a power of ten.
///
/// # Errors
/// `BenchError::Io` when the committed corpus file cannot be read (a
/// truncated checkout is the only way this happens: the files are
/// committed). `BenchError::Cell` when `routes` is not a power of ten.
/// `BenchError::Parse` when a committed corpus file exists but is malformed
/// (oversized, has no pattern line, or a byte outside the printable-ASCII
/// bound): the two shipped files never trigger this, and it exists only as
/// defence in depth against a future hand edit.
pub fn path_expr(corpus: PathCorpus, routes: u32) -> Result<String, BenchError> {
    let w = power_of_ten_width(routes).ok_or(BenchError::Cell("routes must be a power of ten"))?;
    match corpus {
        PathCorpus::SingleHot => {
            // Widening u32 -> usize: always exact, so no escape is needed.
            let width = w as usize;
            Ok(format!("/api/v1/r{:0width$}/00000000", 0))
        }
        PathCorpus::UniformRandom => read_corpus_pattern(PATHS_UNIFORM_REL, PATHS_UNIFORM_NAME, w),
        PathCorpus::AdversarialWorstCase => {
            read_corpus_pattern(PATHS_ADVERSARIAL_REL, PATHS_ADVERSARIAL_NAME, w)
        }
    }
}

// ---------------------------------------------------------------------------
// The expansion grammar: four constructs, one left-to-right pass, no
// recursion. See the module doc and this issue's own Design section for why
// this is not a regex engine.
// ---------------------------------------------------------------------------

/// One parsed element of a corpus expression.
#[derive(Debug, Clone)]
enum Elem {
    /// Construct 1: a literal run, optionally repeated as a whole.
    Literal { bytes: Vec<u8>, min: u32, max: u32 },
    /// Construct 2: a character class, optionally repeated.
    Class {
        alphabet: Vec<u8>,
        min: u32,
        max: u32,
    },
    /// Construct 4: a single-level alternation of literal runs. Never
    /// repeated: the grammar does not attach a counted repetition to an
    /// alternation.
    Alt { choices: Vec<Vec<u8>> },
}

/// Bytes that end a literal run wherever they appear: the five grouping
/// metacharacters this grammar recognises, plus `*` and `+`, which this
/// grammar accepts as constructs from NO position (there is no unbounded
/// operator in this grammar at all) rather than silently as ordinary literal
/// bytes. Treating `*`/`+` as plain text would be surprising to anyone who
/// reads them as the regex quantifiers they conventionally are, and this
/// crate's own tests require both to be refused rather than accepted.
fn is_reserved(b: u8) -> bool {
    b"[](){}|*+".contains(&b)
}

fn is_literal_byte(b: u8) -> bool {
    (0x21..=0x7E).contains(&b) && !is_reserved(b)
}

/// Parses a counted repetition `{n}` or `{n,m}` starting at the `{` found at
/// `bytes[open]`. Returns `(min, max, index just past the closing '}')`.
///
/// Requires `n <= m <= MAX_COUNTED_REPEAT`. An empty upper bound after a
/// comma (`{n,}`) is the unbounded form this grammar does not accept and is
/// rejected here, naming `open`.
fn parse_repeat(bytes: &[u8], open: usize) -> Result<(u32, u32, usize), BenchError> {
    let close = bytes
        .iter()
        .skip(open)
        .position(|&b| b == b'}')
        .map(|rel| open + rel)
        .ok_or_else(|| offset_err(open, "unterminated repetition"))?;
    let body = bytes
        .get(open + 1..close)
        .ok_or_else(|| offset_err(open, "malformed repetition"))?;
    let body_str =
        std::str::from_utf8(body).map_err(|_| offset_err(open, "non-utf8 repetition"))?;
    let (min, max) = if let Some((n_str, m_str)) = body_str.split_once(',') {
        let n: u32 = n_str
            .parse()
            .map_err(|_| offset_err(open, "repetition lower bound is not an integer"))?;
        if m_str.is_empty() {
            return Err(offset_err(
                open,
                "unbounded repetition {n,} is not accepted by this grammar",
            ));
        }
        let m: u32 = m_str
            .parse()
            .map_err(|_| offset_err(open, "repetition upper bound is not an integer"))?;
        (n, m)
    } else {
        let n: u32 = body_str
            .parse()
            .map_err(|_| offset_err(open, "repetition count is not an integer"))?;
        (n, n)
    };
    if min > max || max > MAX_COUNTED_REPEAT {
        return Err(offset_err(
            open,
            "repetition bounds must satisfy n <= m <= MAX_COUNTED_REPEAT",
        ));
    }
    Ok((min, max, close + 1))
}

fn offset_err(offset: usize, reason: &str) -> BenchError {
    BenchError::parse("corpus_expr", &format!("byte offset {offset}: {reason}"))
}

/// Parses a character class body (the bytes strictly between `[` and its
/// matching `]`) into a flat alphabet of individual bytes.
///
/// Accepts literal members and `a-z` style ranges; rejects an empty class,
/// a nested `[`, and a leading `^` (no negation).
fn parse_class_body(body: &[u8], class_open: usize) -> Result<Vec<u8>, BenchError> {
    if body.first() == Some(&b'^') {
        return Err(offset_err(class_open, "negated class is not accepted"));
    }
    if body.is_empty() {
        return Err(offset_err(class_open, "empty character class"));
    }
    let mut alphabet = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let b = *body
            .get(i)
            .ok_or_else(|| offset_err(class_open, "malformed character class"))?;
        if b == b'[' {
            return Err(offset_err(class_open, "nested character class"));
        }
        if !(0x21..=0x7E).contains(&b) {
            return Err(offset_err(
                class_open,
                "non-printable byte in character class",
            ));
        }
        let is_range = body.get(i + 1) == Some(&b'-') && body.get(i + 2).is_some();
        if is_range {
            let hi = *body
                .get(i + 2)
                .ok_or_else(|| offset_err(class_open, "malformed range in character class"))?;
            if hi < b {
                return Err(offset_err(
                    class_open,
                    "descending range in character class",
                ));
            }
            let mut c = b;
            loop {
                alphabet.push(c);
                if c == hi {
                    break;
                }
                c += 1;
            }
            i += 3;
        } else {
            alphabet.push(b);
            i += 1;
        }
    }
    if alphabet.is_empty() {
        return Err(offset_err(class_open, "empty character class"));
    }
    Ok(alphabet)
}

/// Parses a `(a|b|c)` alternation body into its literal-run alternatives.
/// Each alternative must itself be a plain literal run: no nested groups, no
/// classes, no repetition.
fn parse_alt_body(body: &[u8], open: usize) -> Result<Vec<Vec<u8>>, BenchError> {
    let mut choices = Vec::new();
    for chunk in body.split(|&b| b == b'|') {
        if chunk.is_empty() {
            return Err(offset_err(open, "empty alternative"));
        }
        for &b in chunk {
            if !is_literal_byte(b) {
                return Err(offset_err(
                    open,
                    "alternation alternatives must be plain literal runs",
                ));
            }
        }
        choices.push(chunk.to_vec());
    }
    if choices.len() < 2 {
        return Err(offset_err(
            open,
            "alternation needs at least two alternatives",
        ));
    }
    Ok(choices)
}

/// Parses a corpus expression into elements, in one left-to-right pass with
/// an explicit `Vec` and no recursion, per the module doc.
///
/// # Errors
/// `BenchError::Parse` naming the offending byte offset, for anything
/// outside the four constructs this grammar accepts.
fn parse_elems(expr: &str) -> Result<Vec<Elem>, BenchError> {
    let bytes = expr.as_bytes();
    let mut elems = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = *bytes
            .get(i)
            .ok_or_else(|| offset_err(i, "internal cursor out of range"))?;
        match b {
            b'[' => {
                let close = bytes
                    .iter()
                    .skip(i)
                    .position(|&x| x == b']')
                    .map(|rel| i + rel)
                    .ok_or_else(|| offset_err(i, "unterminated character class"))?;
                let body = bytes
                    .get(i + 1..close)
                    .ok_or_else(|| offset_err(i, "malformed character class"))?;
                let alphabet = parse_class_body(body, i)?;
                let mut next = close + 1;
                let (min, max) = if bytes.get(next) == Some(&b'{') {
                    let (mn, mx, after) = parse_repeat(bytes, next)?;
                    next = after;
                    (mn, mx)
                } else {
                    (1, 1)
                };
                elems.push(Elem::Class { alphabet, min, max });
                i = next;
            }
            b'(' => {
                let close = bytes
                    .iter()
                    .skip(i)
                    .position(|&x| x == b')')
                    .map(|rel| i + rel)
                    .ok_or_else(|| offset_err(i, "unterminated alternation"))?;
                let body = bytes
                    .get(i + 1..close)
                    .ok_or_else(|| offset_err(i, "malformed alternation"))?;
                if body.contains(&b'(') || body.contains(&b'[') {
                    return Err(offset_err(i, "nested group in alternation"));
                }
                let choices = parse_alt_body(body, i)?;
                elems.push(Elem::Alt { choices });
                i = close + 1;
            }
            b')' | b']' => return Err(offset_err(i, "unmatched closing bracket")),
            b'{' | b'}' => {
                return Err(offset_err(
                    i,
                    "repetition with no preceding literal or class",
                ));
            }
            b'|' => return Err(offset_err(i, "alternation bar outside a group")),
            b'*' | b'+' => {
                return Err(offset_err(
                    i,
                    "unbounded repetition operator is not accepted",
                ));
            }
            _ if is_literal_byte(b) => {
                let start = i;
                let mut end = i;
                while end < bytes.len() && bytes.get(end).copied().is_some_and(is_literal_byte) {
                    end += 1;
                }
                let run = bytes
                    .get(start..end)
                    .ok_or_else(|| offset_err(start, "malformed literal run"))?
                    .to_vec();
                let mut next = end;
                let (min, max) = if bytes.get(next) == Some(&b'{') {
                    let (mn, mx, after) = parse_repeat(bytes, next)?;
                    next = after;
                    (mn, mx)
                } else {
                    (1, 1)
                };
                elems.push(Elem::Literal {
                    bytes: run,
                    min,
                    max,
                });
                i = next;
            }
            _ => {
                return Err(offset_err(
                    i,
                    "byte outside the accepted printable-ascii class",
                ));
            }
        }
    }
    Ok(elems)
}

/// The maximum number of bytes `elems` could ever expand to, computed with
/// `checked_mul`/`checked_add` in `u64` so the bound is known before a
/// single byte is generated, per edge case 8.
fn max_expansion(elems: &[Elem]) -> Result<u64, BenchError> {
    let mut total: u64 = 0;
    for elem in elems {
        let per_element_max: u64 = match elem {
            Elem::Literal { bytes, max, .. } => {
                let len = u64::try_from(bytes.len())
                    .map_err(|_| BenchError::Cell("literal run length overflowed u64"))?;
                len.checked_mul(u64::from(*max))
                    .ok_or(BenchError::Cell("expansion bound overflowed u64"))?
            }
            Elem::Class { max, .. } => u64::from(*max),
            Elem::Alt { choices } => choices
                .iter()
                .map(Vec::len)
                .max()
                .unwrap_or(0)
                .try_into()
                .map_err(|_| BenchError::Cell("alternative length overflowed u64"))?,
        };
        total = total
            .checked_add(per_element_max)
            .ok_or(BenchError::Cell("expansion bound overflowed u64"))?;
    }
    Ok(total)
}

/// Deterministically expands `corpus` into `count` concrete paths.
///
/// This is the only expansion primitive in the workspace. The runner calls
/// it to materialise vegeta's targets file (vegeta has no regex expansion of
/// its own), and tests call it for coverage assertions. The same `(corpus,
/// routes, count, seed)` always yields the same list, on any machine, so a
/// targets file is reproducible from the seed recorded in the result.
///
/// Draws from `irontraffic_rand::Rng`, never from the `rand` crate directly:
/// its types are banned outside `crates/irontraffic-rand` by the
/// `determinism-seam` rule.
///
/// # Errors
/// Propagates [`path_expr`], propagates a [`BenchError::Parse`] naming the
/// byte offset when the expression uses anything outside the four accepted
/// constructs or whose maximum expansion exceeds [`MAX_SAMPLE_PATH_BYTES`]
/// (computed and rejected BEFORE any path is generated), and returns
/// `BenchError::Cell` when `count` is 0 or above `MAX_SAMPLE_COUNT`
/// (1,000,000; private, see that constant's own doc).
pub fn path_samples(
    corpus: PathCorpus,
    routes: u32,
    count: u32,
    seed: u64,
) -> Result<Vec<String>, BenchError> {
    if count == 0 || count > MAX_SAMPLE_COUNT {
        return Err(BenchError::Cell("count must be 1..=MAX_SAMPLE_COUNT"));
    }
    let expr = path_expr(corpus, routes)?;
    let elems = parse_elems(&expr)?;
    let bound = max_expansion(&elems)?;
    if bound > MAX_SAMPLE_PATH_BYTES as u64 {
        return Err(BenchError::parse(
            "corpus_expr",
            "maximum expansion exceeds MAX_SAMPLE_PATH_BYTES",
        ));
    }

    let mut rng = irontraffic_rand::Rng::from_seed(seed);
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut sample = Vec::new();
        for elem in &elems {
            match elem {
                Elem::Literal { bytes, min, max } => {
                    let reps = draw_repeat(&mut rng, *min, *max);
                    for _ in 0..reps {
                        sample.extend_from_slice(bytes);
                    }
                }
                Elem::Class { alphabet, min, max } => {
                    let reps = draw_repeat(&mut rng, *min, *max);
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "alphabet is built from one committed corpus file capped at \
                                  MAX_CORPUS_FILE_BYTES (4,096), so its length is comfortably \
                                  below u32::MAX"
                    )]
                    let alphabet_len = alphabet.len() as u32; // it-allow: unchecked-cast reason: alphabet is built from a single committed corpus file capped at MAX_CORPUS_FILE_BYTES, comfortably below u32::MAX
                    for _ in 0..reps {
                        let idx = rng.bounded_u32(alphabet_len);
                        // Widening u32 -> usize below: always exact. `idx` is
                        // in 0..alphabet_len by bounded_u32's own contract,
                        // so the index is always in range.
                        let byte = alphabet.get(idx as usize).copied().ok_or_else(|| {
                            BenchError::parse("corpus_expr", "class alphabet index out of range")
                        })?;
                        sample.push(byte);
                    }
                }
                Elem::Alt { choices } => {
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "choices is built from one committed corpus file capped at \
                                  MAX_CORPUS_FILE_BYTES (4,096), so its length is comfortably \
                                  below u32::MAX"
                    )]
                    let choices_len = choices.len() as u32; // it-allow: unchecked-cast reason: choices comes from a single committed corpus file capped at MAX_CORPUS_FILE_BYTES, comfortably below u32::MAX
                    let idx = rng.bounded_u32(choices_len);
                    // Widening u32 -> usize below: always exact. `idx` is in
                    // 0..choices_len by bounded_u32's own contract, so the
                    // index is always in range.
                    let choice = choices.get(idx as usize).ok_or_else(|| {
                        BenchError::parse("corpus_expr", "alternation index out of range")
                    })?;
                    sample.extend_from_slice(choice);
                }
            }
        }
        if sample.len() > MAX_SAMPLE_PATH_BYTES {
            return Err(BenchError::parse(
                "corpus_expr",
                "generated sample exceeds MAX_SAMPLE_PATH_BYTES",
            ));
        }
        let text = String::from_utf8(sample)
            .map_err(|_| BenchError::parse("corpus_expr", "generated sample is not utf-8"))?;
        out.push(text);
    }
    Ok(out)
}

/// Draws a repeat count uniformly in `min..=max` using `rng`. `min == max`
/// (the common case: a plain `{n}`, or no repetition suffix at all, which
/// parses to `min = max = 1`) draws nothing and returns `min` directly.
fn draw_repeat(rng: &mut irontraffic_rand::Rng, min: u32, max: u32) -> u32 {
    if min >= max {
        return min;
    }
    let span = max - min + 1;
    min + rng.bounded_u32(span)
}

#[cfg(test)]
mod tests {
    use super::{
        Elem, digit_width, max_expansion, nearest_real_world_size, parse_elems, power_of_ten_width,
    };

    #[test]
    fn digit_width_matches_expected_powers_of_ten() {
        assert_eq!(digit_width(0), 1); // n = 1, index 0
        assert_eq!(digit_width(9), 1); // n = 10
        assert_eq!(digit_width(999), 3); // n = 1_000
        assert_eq!(digit_width(9_999), 4); // n = 10_000
        assert_eq!(digit_width(99_999), 5); // n = 100_000
        assert_eq!(digit_width(999_999), 6); // n = 1_000_000
    }

    #[test]
    fn power_of_ten_width_accepts_and_rejects() {
        assert_eq!(power_of_ten_width(1), Some(0));
        assert_eq!(power_of_ten_width(10), Some(1));
        assert_eq!(power_of_ten_width(1_000), Some(3));
        assert_eq!(power_of_ten_width(100_000), Some(5));
        assert_eq!(power_of_ten_width(999), None);
        assert_eq!(power_of_ten_width(0), None);
    }

    #[test]
    fn nearest_real_world_size_ties_favour_the_smaller() {
        assert_eq!(nearest_real_world_size(100), 36);
        assert_eq!(nearest_real_world_size(400), 217);
        assert_eq!(nearest_real_world_size(700), 609);
        // 413 is exactly equidistant between 217 and 609.
        assert_eq!(nearest_real_world_size(413), 217);
    }

    #[test]
    fn parse_elems_accepts_the_two_committed_shapes() {
        let uniform = parse_elems("/api/v1/r[0-9]{3}/[0-9a-f]{8}").expect("valid grammar");
        assert_eq!(uniform.len(), 4);
        let bound = max_expansion(&uniform).expect("bound computable");
        assert!(bound <= super::MAX_SAMPLE_PATH_BYTES as u64);

        let adversarial =
            parse_elems("/repos/acme/r[0-9]{3}/issues/[0-9]{1,6}/(comments|reviews|files)")
                .expect("valid grammar");
        let has_alt = adversarial.iter().any(|e| matches!(e, Elem::Alt { .. }));
        assert!(has_alt, "adversarial pattern must parse an alternation");
    }

    #[test]
    fn parse_elems_rejects_unbounded_and_unsafe_constructs() {
        assert!(parse_elems("a*").is_err());
        assert!(parse_elems("a+").is_err());
        assert!(parse_elems("a{4,}").is_err());
        assert!(parse_elems("((a|b)|c)").is_err());
        assert!(parse_elems("[^a]").is_err());
    }
}
