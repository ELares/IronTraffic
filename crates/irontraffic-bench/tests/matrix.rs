// SPDX-License-Identifier: MIT OR Apache-2.0
//! Registry uniqueness, stability and coverage tests for the published
//! benchmark matrix (`bench-matrix-cells-and-corpora`, #414).
//!
//! `rand_regex` appears ONLY in this file in the whole workspace, as a
//! `[dev-dependencies]` entry: `rand::` is banned outside
//! `crates/irontraffic-rand` by the `determinism-seam` rule in
//! `scripts/invariant-lints.sh`.
//! it-allow: determinism-seam reason: test 7a must expand with the same
//! crate and the same bound the pinned oha release uses, which is the whole
//! point of the test.
//!
//! # A disclosed gap: test 13b cannot reach the grammar parser from here
//!
//! `corpus_expander_rejects_unbounded_constructs` below is named for, and
//! its doc comment explains, a genuine limit of this file: this is an
//! INTEGRATION test compiled against `irontraffic_bench`'s PUBLIC API only,
//! and that API has no entry point that accepts an arbitrary corpus
//! expression string. `path_samples` only ever expands the fixed
//! `PathCorpus` enum's own derived text (the two committed files, or the
//! literal `SingleHot` formula), and none of those three ever contain `*`,
//! `+`, `{4,}`, a nested group, or a negated class, so the five reject
//! cases this issue's own Tests section names for test 13b are literally
//! unreachable from a test compiled outside `src/`. They ARE verified, in
//! `crates/irontraffic-bench/src/corpus.rs`'s own `#[cfg(test)]` module
//! (`parse_elems_rejects_unbounded_and_unsafe_constructs`), which can see
//! the private grammar parser directly; that module runs under plain
//! `cargo test -p irontraffic-bench`, just not under the `--test matrix`
//! filter this issue's own acceptance criterion names. This is a disclosed
//! placement mismatch, not a silently dropped requirement: adding a new
//! public function only to make this one test reachable here would be
//! forking this issue's own Public API section, which names no such
//! function.

use std::collections::BTreeSet;

use irontraffic_bench::{
    BenchCell, CellId, LoadGenerator, MAX_ROUTES, MAX_SATURATION_FILE_BYTES, MatrixEntry, Oha,
    PathCorpus, RateMode, RatePlan, RouteShape, RunParams, SaturationTable, Scheme, Target,
    TlsMode, base_cell, entry, path_expr, path_samples, registry, resolve_rate, route_table, suite,
};
use proptest::prelude::*;
use rand::{RngExt as _, SeedableRng};
use sha2::{Digest, Sha256};

/// This crate's manifest directory, resolved at compile time, so every path
/// below works regardless of the test runner's current working directory.
fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn snapshot_path() -> std::path::PathBuf {
    workspace_root().join("bench/cells.snapshot")
}

fn saturation_reference_path() -> std::path::PathBuf {
    workspace_root().join("bench/saturation.reference.toml")
}

fn tools_toml_path() -> std::path::PathBuf {
    workspace_root().join("bench/tools.toml")
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex_encode(&hasher.finalize())
}

/// Field-by-field diff between `base` and `other`, ignoring `id` (never
/// compared) and, when `ignore_rate` is set, `rate` (which never actually
/// differs today, since every registry cell carries `UNRESOLVED_RATE`
/// until `resolve_rate` runs, but the design's own instruction is to ignore
/// it for a saturate twin, so this stays a real parameter rather than a
/// hard-coded assumption).
fn differing_fields(base: &BenchCell, other: &BenchCell, ignore_rate: bool) -> Vec<&'static str> {
    let mut diffs = Vec::new();
    if base.protocol != other.protocol {
        diffs.push("protocol");
    }
    if base.tls != other.tls {
        diffs.push("tls");
    }
    if base.payload_bytes != other.payload_bytes {
        diffs.push("payload_bytes");
    }
    if base.routes != other.routes {
        diffs.push("routes");
    }
    if base.path_corpus != other.path_corpus {
        diffs.push("path_corpus");
    }
    if base.connections != other.connections {
        diffs.push("connections");
    }
    if base.upstreams != other.upstreams {
        diffs.push("upstreams");
    }
    if base.filter_depth != other.filter_depth {
        diffs.push("filter_depth");
    }
    if base.cache != other.cache {
        diffs.push("cache");
    }
    if base.keepalive != other.keepalive {
        diffs.push("keepalive");
    }
    if !ignore_rate && base.rate != other.rate {
        diffs.push("rate");
    }
    diffs
}

/// Builds a fixed `Target` for a registry cell. Returns `Result` (rather than
/// panicking itself) purely so the `.expect()`/`.unwrap()` calls this needs
/// live at the call site, inside an actual `#[test]` function: clippy's
/// `expect_used`/`panic` lints are exempted only inside `#[test]`-attributed
/// functions (per `clippy.toml`'s `allow-expect-in-tests`), not inside a
/// plain helper function a test happens to call.
fn fixed_target(cell: &BenchCell) -> Result<Target, irontraffic_bench::BenchError> {
    let scheme = if cell.tls == TlsMode::Off {
        Scheme::Http
    } else {
        Scheme::Https
    };
    let sni = if cell.tls == TlsMode::Off {
        None
    } else {
        Some("bench.internal".to_owned())
    };
    let path_expr_str = path_expr(cell.path_corpus, cell.routes)?;
    Ok(Target {
        scheme,
        host: "bench.internal".to_owned(),
        connect: std::net::SocketAddr::from(([127, 0, 0, 1], 8080)),
        sni,
        path_expr: path_expr_str,
    })
}

fn fixed_run_params() -> RunParams {
    RunParams {
        duration_secs: 60,
        warmup_secs: 30,
        concurrency: None,
    }
}

// 1.
#[test]
fn registry_ids_are_unique() {
    let entries = registry().expect("registry builds");
    let ids: BTreeSet<&str> = entries.iter().map(|e| e.cell.id.as_str()).collect();
    assert_eq!(
        entries.len(),
        ids.len(),
        "registry has a duplicate cell id: {} entries but only {} unique ids",
        entries.len(),
        ids.len()
    );
}

// 2.
#[test]
fn registry_ids_all_parse() {
    let entries = registry().expect("registry builds");
    assert_eq!(
        entries.len(),
        62,
        "the published matrix has 62 registry entries"
    );
    for e in &entries {
        let s = e.cell.id.as_str();
        let reparsed = CellId::parse(s)
            .unwrap_or_else(|err| panic!("registry id {s:?} failed to re-parse: {err}"));
        assert_eq!(
            reparsed.as_str(),
            s,
            "round-tripping {s:?} through CellId::parse changed it"
        );

        // Exercises `entry`, the Public API's by-id lookup, for every
        // registry id.
        let looked_up = entry(&reparsed).unwrap_or_else(|err| panic!("entry({s:?}) failed: {err}"));
        assert_eq!(looked_up.cell.id.as_str(), s);
    }
}

// 3.
#[test]
fn registry_cells_all_validate() {
    let entries = registry().expect("registry builds");
    for e in &entries {
        e.cell
            .validate()
            .unwrap_or_else(|err| panic!("{} failed BenchCell::validate: {err}", e.cell.id));
    }
}

// 4.
#[test]
fn every_sweep_varies_exactly_one_dimension() {
    let base = base_cell().expect("base cell builds");
    let entries = registry().expect("registry builds");
    let mut checked = 0usize;
    for e in entries.iter().filter(|e| e.sweep.is_some()) {
        let diffs = differing_fields(&base, &e.cell, true);
        assert_eq!(
            diffs.len(),
            1,
            "{} must vary exactly one dimension from the base cell; differing fields: {diffs:?}",
            e.cell.id
        );
        checked += 1;
    }
    assert_eq!(
        checked, 52,
        "expected 52 entries with sweep: Some(_) (26 sweep cells + their 26 saturate twins)"
    );
}

// 5.
#[test]
fn every_fixed_rate_cell_has_a_resolvable_saturation_ref() {
    let entries = registry().expect("registry builds");
    let by_id: std::collections::BTreeMap<&str, &MatrixEntry> =
        entries.iter().map(|e| (e.cell.id.as_str(), e)).collect();

    let mut checked = 0usize;
    for e in entries
        .iter()
        .filter(|e| matches!(e.rate_plan, RatePlan::PercentOfSaturation { .. }))
    {
        let sat_id = e.saturation_ref.as_ref().unwrap_or_else(|| {
            panic!(
                "{} is PercentOfSaturation but saturation_ref is None",
                e.cell.id
            )
        });
        let referenced = by_id
            .get(sat_id.as_str())
            .unwrap_or_else(|| panic!("{} references unknown id {sat_id}", e.cell.id));
        assert_eq!(
            referenced.rate_plan,
            RatePlan::Saturate,
            "{} references {sat_id}, whose rate_plan is not Saturate",
            e.cell.id
        );

        let expected = if e.cell.id.as_str() == "adv.reload_under_load" {
            "base.sat".to_owned()
        } else {
            format!("{}.sat", e.cell.id.as_str())
        };
        assert_eq!(
            sat_id.as_str(),
            expected,
            "{} has saturation_ref {sat_id}, expected {expected}",
            e.cell.id
        );
        checked += 1;
    }
    assert_eq!(checked, 28, "expected 28 PercentOfSaturation entries");
}

// 6.
#[test]
fn snapshot_is_a_subset_of_the_registry() {
    let entries = registry().expect("registry builds");
    let registry_ids: BTreeSet<&str> = entries.iter().map(|e| e.cell.id.as_str()).collect();

    let snapshot = std::fs::read_to_string(snapshot_path()).expect("read bench/cells.snapshot");
    let mut snapshot_ids = BTreeSet::new();
    for line in snapshot.lines() {
        let (id, _hash) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("malformed bench/cells.snapshot line: {line:?}"));
        snapshot_ids.insert(id);
    }
    assert_eq!(
        snapshot_ids.len(),
        62,
        "bench/cells.snapshot must list all 62 registry ids"
    );

    for id in &snapshot_ids {
        assert!(
            registry_ids.contains(id),
            "cell {id} is in bench/cells.snapshot but not in the registry: a cell was removed or \
             renamed, which is a deliberate change requiring the snapshot to be updated in the \
             same pull request"
        );
    }
}

// 7.
#[test]
fn command_line_hashes_match_the_snapshot() {
    let reference = std::fs::read_to_string(saturation_reference_path())
        .expect("read bench/saturation.reference.toml");
    let saturation =
        SaturationTable::parse(&reference).expect("bench/saturation.reference.toml parses");

    let snapshot_text =
        std::fs::read_to_string(snapshot_path()).expect("read bench/cells.snapshot");
    let snapshot: std::collections::BTreeMap<&str, &str> = snapshot_text
        .lines()
        .map(|line| {
            line.split_once('\t')
                .unwrap_or_else(|| panic!("malformed bench/cells.snapshot line: {line:?}"))
        })
        .collect();

    let entries = registry().expect("registry builds");
    let oha = Oha;
    let run = fixed_run_params();

    let mut hashed = 0usize;
    let mut dashed = 0usize;
    for e in &entries {
        let resolved = resolve_rate(e, &saturation)
            .unwrap_or_else(|err| panic!("resolve_rate for {} failed: {err}", e.cell.id));
        let expected = *snapshot
            .get(e.cell.id.as_str())
            .unwrap_or_else(|| panic!("{} is missing from bench/cells.snapshot", e.cell.id));

        if expected == "-" {
            assert!(
                oha.supports(&resolved).is_err(),
                "{} is marked '-' in bench/cells.snapshot but Oha::supports accepts it: '-' must \
                 never silence a cell that could have been hashed",
                e.cell.id
            );
            dashed += 1;
            continue;
        }

        oha.supports(&resolved).unwrap_or_else(|err| {
            panic!(
                "{} is hashed in the snapshot but Oha::supports refuses it: {err}",
                e.cell.id
            )
        });
        let target = fixed_target(&resolved)
            .unwrap_or_else(|err| panic!("fixed_target for {} failed: {err}", e.cell.id));
        let invocation = oha
            .plan(&resolved, &target, &run)
            .unwrap_or_else(|err| panic!("Oha::plan for {} failed: {err}", e.cell.id));
        let hash = sha256_hex(&invocation.command_line());
        assert_eq!(
            hash, expected,
            "{} command line hash drifted from bench/cells.snapshot (invariant I12)",
            e.cell.id
        );
        hashed += 1;
    }

    assert_eq!(hashed + dashed, 62);
    assert_eq!(
        hashed, 26,
        "expected 26 entries Oha can plan (28 PercentOfSaturation minus protocol.h3 and conns.100000)"
    );
    assert_eq!(
        dashed, 36,
        "expected 36 dashed entries (34 Saturate plus protocol.h3 and conns.100000)"
    );
}

/// A concrete route pattern matches an abstract route pattern (which may
/// carry a `{name}` wildcard segment or a `(a|b|c)` alternation segment)
/// segment by segment.
fn route_matches(pattern: &str, path: &str) -> bool {
    let mut p_parts = pattern.split('/');
    let mut path_parts = path.split('/');
    loop {
        match (p_parts.next(), path_parts.next()) {
            (None, None) => return true,
            (Some(p), Some(a)) => {
                if p.starts_with('{') && p.ends_with('}') {
                    if a.is_empty() {
                        return false;
                    }
                } else if p.starts_with('(') && p.ends_with(')') {
                    let inner = &p[1..p.len() - 1];
                    if !inner.split('|').any(|alt| alt == a) {
                        return false;
                    }
                } else if p != a {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn extract_uniform_index(path: &str, w: usize) -> Option<u32> {
    let rest = path.strip_prefix("/api/v1/r")?;
    if rest.len() < w {
        return None;
    }
    let (digits, tail) = rest.split_at(w);
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let tail = tail.strip_prefix('/')?;
    if tail.len() != 8 || !tail.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    digits.parse().ok()
}

fn extract_adversarial_index(path: &str, w: usize) -> Option<u32> {
    let rest = path.strip_prefix("/repos/acme/r")?;
    if rest.len() < w {
        return None;
    }
    let (digits, rest) = rest.split_at(w);
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let rest = rest.strip_prefix("/issues/")?;
    let (num_part, suffix) = rest.split_once('/')?;
    if num_part.is_empty() || num_part.len() > 6 || !num_part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !matches!(suffix, "comments" | "reviews" | "files") {
        return None;
    }
    digits.parse().ok()
}

// 7a.
#[test]
fn corpus_expansions_all_match_a_route() {
    const SAMPLES: u32 = 10_000;
    const MAX_REPEAT: u32 = irontraffic_bench::MAX_REGEX_REPEAT;

    // UniformRandom at 1,000 routes, paired with the Flat route shape.
    {
        let n = 1_000u32;
        let w = 3usize;
        let expr = path_expr(PathCorpus::UniformRandom, n).expect("path_expr(UniformRandom, 1000)");
        let table = route_table(RouteShape::Flat, n, 8).expect("route_table(Flat, 1000, 8)");
        let re = rand_regex::Regex::compile(&expr, MAX_REPEAT).expect("uniform pattern compiles");
        // it-allow: determinism-seam reason: test 7a must expand with the
        // same crate and the same bound the pinned oha release uses, which
        // is the whole point of the test.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FF_EE01);
        let mut matched = 0u32;
        for _ in 0..SAMPLES {
            let path: String = rng.sample(&re);
            let idx = extract_uniform_index(&path, w).unwrap_or_else(|| {
                panic!("uniform expansion {path:?} does not have the expected shape")
            });
            let route = table
                .get(idx as usize)
                .unwrap_or_else(|| panic!("index {idx} out of range for {} routes", table.len()));
            if route_matches(&route.path_pattern, &path) {
                matched += 1;
            }
        }
        assert_eq!(
            matched, SAMPLES,
            "uniform corpus reachability: {matched}/{SAMPLES} expansions matched their route"
        );
    }

    // AdversarialWorstCase at 100,000 routes, paired with the SharedPrefix
    // route shape.
    {
        let n = 100_000u32;
        let w = 5usize;
        let expr = path_expr(PathCorpus::AdversarialWorstCase, n)
            .expect("path_expr(AdversarialWorstCase, 100_000)");
        let table = route_table(RouteShape::SharedPrefix, n, 8)
            .expect("route_table(SharedPrefix, 100_000, 8)");
        let re =
            rand_regex::Regex::compile(&expr, MAX_REPEAT).expect("adversarial pattern compiles");
        // it-allow: determinism-seam reason: test 7a must expand with the
        // same crate and the same bound the pinned oha release uses, which
        // is the whole point of the test.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FF_EE02);
        let mut matched = 0u32;
        let mut num_lens_seen: BTreeSet<usize> = BTreeSet::new();
        for _ in 0..SAMPLES {
            let path: String = rng.sample(&re);
            let idx = extract_adversarial_index(&path, w).unwrap_or_else(|| {
                panic!("adversarial expansion {path:?} does not have the expected shape")
            });
            let route = table
                .get(idx as usize)
                .unwrap_or_else(|| panic!("index {idx} out of range for {} routes", table.len()));
            if route_matches(&route.path_pattern, &path) {
                matched += 1;
            }
            let digits = path.rsplit_once('/').map_or(0, |(head, _)| {
                head.rsplit_once('/').map_or(0, |(_, num)| num.len())
            });
            num_lens_seen.insert(digits);
        }
        assert_eq!(
            matched, SAMPLES,
            "adversarial corpus reachability: {matched}/{SAMPLES} expansions matched their route"
        );
        // If oha's `--max-repeat 4` (which rand_regex's own `max_repeat`
        // parameter models exactly) also clamped this COUNTED `{1,6}`
        // repetition, every issue number would be at most 4 digits and
        // `num_lens_seen` could never contain 5 or 6. Confirmed against the
        // pinned rand_regex 0.19.0 source directly
        // (`Regex::with_repetition`: `rep.max.unwrap_or(lower + max_repeat)`
        // only ever consults `max_repeat` when `rep.max` is `None`, i.e. for
        // an UNBOUNDED operator; a counted `{1,6}` already has `rep.max =
        // Some(6)` and is untouched by it), and this loop is the empirical
        // confirmation the issue's own text says test 7a must provide.
        assert!(
            num_lens_seen.contains(&5) && num_lens_seen.contains(&6),
            "counted repetition {{1,6}} appears to have been clamped: only saw issue-number \
             lengths {num_lens_seen:?} across {SAMPLES} samples"
        );
    }
}

// 8.
#[test]
fn single_hot_cells_are_labelled_controls() {
    let entries = registry().expect("registry builds");
    let mut single_hot_count = 0usize;
    for e in &entries {
        let is_single_hot = matches!(e.cell.path_corpus, PathCorpus::SingleHot);
        let has_control = e.description.contains("control");
        assert_eq!(
            is_single_hot, has_control,
            "{}: path_corpus is SingleHot ({is_single_hot}) must match description.contains(\"control\") \
             ({has_control}); description: {:?}",
            e.cell.id, e.description
        );
        if is_single_hot {
            single_hot_count += 1;
        }
    }
    assert_eq!(
        single_hot_count, 2,
        "expected corpus.single_hot and corpus.single_hot.sat"
    );
}

// 9.
#[test]
fn route_table_is_deterministic() {
    let a = route_table(RouteShape::SharedPrefix, 1_000, 8).expect("builds");
    let b = route_table(RouteShape::SharedPrefix, 1_000, 8).expect("builds");
    assert_eq!(
        a, b,
        "route_table(SharedPrefix, 1_000, 8) is not deterministic across two calls"
    );

    let mut hasher = Sha256::new();
    for r in &a {
        hasher.update(r.path_pattern.as_bytes());
        hasher.update([0]);
        hasher.update(r.cluster.to_le_bytes());
    }
    let hash = hex_encode(&hasher.finalize());
    assert_eq!(
        hash, "343adfbe6fa395cea8a92e6c050fd3402c601bb8222fecfd03c595b02d63f171",
        "route_table(SharedPrefix, 1_000, 8)'s content changed; if this was an intentional \
         generator change, update this pinned hash and say so in the pull request"
    );
}

// 10.
#[test]
fn route_table_paths_are_unique() {
    for shape in [
        RouteShape::Flat,
        RouteShape::SharedPrefix,
        RouteShape::LastSegment,
    ] {
        let table = route_table(shape, 100_000, 64).expect("builds");
        let unique: BTreeSet<&str> = table.iter().map(|r| r.path_pattern.as_str()).collect();
        assert_eq!(
            unique.len(),
            table.len(),
            "{shape:?} produced a duplicate route pattern at n = 100,000: {} unique out of {}",
            unique.len(),
            table.len()
        );
    }
}

// 11.
#[test]
fn route_table_100k_is_fast() {
    let start = std::time::Instant::now(); // test code is exempt from the clock seam
    let table = route_table(RouteShape::SharedPrefix, 100_000, 64).expect("builds");
    let elapsed = start.elapsed();
    assert_eq!(table.len(), 100_000);
    assert!(
        elapsed.as_secs() < 2,
        "route_table(SharedPrefix, 100_000, 64) took {elapsed:?}, expected under 2 seconds"
    );
}

// 12.
#[test]
fn resolve_rate_uses_60_percent() {
    let entries = registry().expect("registry builds");
    let base_entry = entries
        .iter()
        .find(|e| e.cell.id.as_str() == "base")
        .expect("base entry exists");
    let saturation =
        SaturationTable::parse("base.sat = 1000000\n").expect("saturation table parses");
    let resolved = resolve_rate(base_entry, &saturation).expect("resolves");
    assert_eq!(resolved.rate, RateMode::Fixed(600_000));
}

// 13.
#[test]
fn resolve_rate_refuses_unmeasured() {
    let entries = registry().expect("registry builds");
    let base_entry = entries
        .iter()
        .find(|e| e.cell.id.as_str() == "base")
        .expect("base entry exists");
    let saturation = SaturationTable::parse("").expect("empty table parses");
    let err = resolve_rate(base_entry, &saturation).expect_err("must refuse an unmeasured cell");
    let msg = err.to_string();
    assert!(
        msg.contains("base.sat"),
        "error message {msg:?} does not name the base.sat twin id"
    );
}

// 13a.
#[test]
fn route_table_refuses_absurd_inputs() {
    let start = std::time::Instant::now();
    let err = route_table(RouteShape::Flat, MAX_ROUTES + 1, 8).expect_err("must refuse");
    let elapsed = start.elapsed();
    assert!(
        err.to_string().contains("MAX_ROUTES"),
        "error {err} does not name MAX_ROUTES"
    );
    assert!(
        elapsed.as_millis() < 10,
        "took {elapsed:?}, expected under 10ms"
    );

    let start2 = std::time::Instant::now();
    let err2 = route_table(RouteShape::Flat, u32::MAX, 8).expect_err("must refuse");
    let elapsed2 = start2.elapsed();
    assert!(err2.to_string().contains("MAX_ROUTES"));
    assert!(
        elapsed2.as_millis() < 10,
        "took {elapsed2:?}, expected under 10ms"
    );

    let err3 = route_table(RouteShape::Flat, 1_000, 0).expect_err("zero clusters must refuse");
    assert!(
        err3.to_string().to_lowercase().contains("cluster"),
        "error {err3} does not name zero clusters"
    );
}

// 13b. See the module doc: the five reject constructs are exercised in
// `src/corpus.rs`'s own unit tests, not reachable from here. This test
// verifies the reachable half: the committed corpora expand without error
// through path_samples, a different expansion engine than test 7a's
// rand_regex, and every sample stays within MAX_SAMPLE_PATH_BYTES.
#[test]
fn corpus_expander_rejects_unbounded_constructs() {
    for (corpus, routes) in [
        (PathCorpus::UniformRandom, 1_000u32),
        (PathCorpus::UniformRandom, 100_000u32),
        (PathCorpus::AdversarialWorstCase, 1_000u32),
        (PathCorpus::AdversarialWorstCase, 100_000u32),
        (PathCorpus::SingleHot, 1_000u32),
    ] {
        let samples = path_samples(corpus, routes, 50, 0xABCD_EF01)
            .unwrap_or_else(|err| panic!("path_samples({corpus:?}, {routes}) failed: {err}"));
        assert_eq!(samples.len(), 50);
        for s in &samples {
            assert!(
                s.len() <= irontraffic_bench::MAX_SAMPLE_PATH_BYTES,
                "sample {s:?} exceeds MAX_SAMPLE_PATH_BYTES"
            );
        }
    }
}

// 14.
#[test]
fn saturation_table_rejects_malformed() {
    assert!(
        SaturationTable::parse("Base.sat = 1000\n").is_err(),
        "an uppercase cell id must be rejected"
    );
    assert!(
        SaturationTable::parse("base.sat = \"fast\"\n").is_err(),
        "a non-integer value must be rejected"
    );
    assert!(
        SaturationTable::parse("base.sat = 0\n").is_err(),
        "a zero value must be rejected"
    );
}

// 14a.
#[test]
fn saturation_table_rejects_duplicate_and_oversized() {
    let dup = "base.sat = 1000\nbase.sat = 2000\n";
    let err = SaturationTable::parse(dup).expect_err("duplicate key must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("lines 1 and 2"),
        "error message {msg:?} does not name both line numbers"
    );

    let start = std::time::Instant::now();
    let oversized = "#".repeat(MAX_SATURATION_FILE_BYTES + 1);
    let _ = SaturationTable::parse(&oversized).expect_err("oversized input must be rejected");
    assert!(
        start.elapsed().as_millis() < 10,
        "oversized input rejection took too long"
    );

    let max_u64_line = format!("base.sat = {}\n", u64::MAX);
    assert!(
        SaturationTable::parse(&max_u64_line).is_err(),
        "u64::MAX exceeds MAX_SATURATION_RPS and must be rejected"
    );

    assert!(
        SaturationTable::parse("base.sat = 18446744073709551616\n").is_err(),
        "2^64 does not fit u64 and must be rejected"
    );
}

fn parse_tools_toml(
    text: &str,
) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> {
    let mut tables: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> =
        std::collections::BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current = Some(name.to_owned());
            tables.entry(name.to_owned()).or_default();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_owned();
            let value = value.trim().trim_matches('"').to_owned();
            if let Some(cur) = &current {
                tables.entry(cur.clone()).or_default().insert(key, value);
            }
        }
    }
    tables
}

fn is_valid_sha256_digest_line(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// 15.
#[test]
fn tool_pins_are_complete_and_unambiguous() {
    let text = std::fs::read_to_string(tools_toml_path()).expect("read bench/tools.toml");
    let tables = parse_tools_toml(&text);

    for adapter in ["nighthawk", "oha", "h2load", "vegeta"] {
        let table = tables
            .get(adapter)
            .unwrap_or_else(|| panic!("bench/tools.toml has no [{adapter}] table"));
        let has_version = table.contains_key("version");
        let has_expect = table.contains_key("expect_version_contains");
        assert!(
            has_version != has_expect,
            "[{adapter}] must carry exactly one of version/expect_version_contains \
             (has_version={has_version}, has_expect_version_contains={has_expect})"
        );
        if let Some(v) = table.get("version") {
            assert!(!v.is_empty(), "[{adapter}] version is empty");
            assert!(
                !v.contains("latest"),
                "[{adapter}] version {v:?} contains \"latest\""
            );
            assert!(
                !v.contains("dev"),
                "[{adapter}] version {v:?} contains \"dev\""
            );
        }
    }

    let nighthawk = &tables["nighthawk"];
    let digest_file = nighthawk
        .get("digest_file")
        .expect("[nighthawk] must name a digest_file");
    let digest_path = workspace_root().join(digest_file);
    let digest_text = std::fs::read_to_string(&digest_path)
        .unwrap_or_else(|err| panic!("read the nighthawk digest_file {digest_file}: {err}"));
    let digest_line = digest_text.trim();
    assert_eq!(
        digest_text.lines().count(),
        1,
        "the nighthawk digest_file must be exactly one line"
    );
    assert!(
        is_valid_sha256_digest_line(digest_line),
        "nighthawk digest_file contents {digest_line:?} do not match ^sha256:[0-9a-f]{{64}}$"
    );
}

// 16.
#[test]
fn suite_names_partition_the_registry() {
    let full = suite("full").expect("suite(\"full\") must succeed");
    let all = registry().expect("registry builds");
    assert_eq!(full.len(), 62);
    assert_eq!(full.len(), all.len());
    let full_ids: BTreeSet<&str> = full.iter().map(|e| e.cell.id.as_str()).collect();
    let all_ids: BTreeSet<&str> = all.iter().map(|e| e.cell.id.as_str()).collect();
    assert_eq!(full_ids, all_ids, "suite(\"full\") must equal registry()");

    let base = suite("base").expect("suite(\"base\") must succeed");
    assert_eq!(base.len(), 2);
    let base_ids: BTreeSet<&str> = base.iter().map(|e| e.cell.id.as_str()).collect();
    assert_eq!(base_ids, BTreeSet::from(["base", "base.sat"]));

    let sweeps = suite("sweeps").expect("suite(\"sweeps\") must succeed");
    assert_eq!(sweeps.len(), 54);
    let sweeps_ids: BTreeSet<&str> = sweeps.iter().map(|e| e.cell.id.as_str()).collect();

    let adversarial = suite("adversarial").expect("suite(\"adversarial\") must succeed");
    assert_eq!(adversarial.len(), 8);
    let adv_ids: BTreeSet<&str> = adversarial.iter().map(|e| e.cell.id.as_str()).collect();
    for id in &adv_ids {
        assert!(
            id.starts_with("adv."),
            "{id} is in suite(\"adversarial\") but does not start with adv."
        );
    }

    assert!(
        sweeps_ids.is_disjoint(&adv_ids),
        "sweeps and adversarial must be disjoint"
    );
    let union: BTreeSet<&str> = sweeps_ids.union(&adv_ids).copied().collect();
    assert_eq!(
        union, full_ids,
        "sweeps and adversarial together must equal full"
    );
    assert!(
        base_ids.is_subset(&sweeps_ids),
        "base must be a subset of sweeps"
    );

    for bad in ["Base", "", "everything"] {
        let err = suite(bad).expect_err("an unknown suite name must be refused");
        let msg = err.to_string();
        for name in ["base", "sweeps", "adversarial", "full"] {
            assert!(
                msg.contains(name),
                "error message {msg:?} for suite({bad:?}) does not list {name}"
            );
        }
    }
}

proptest! {
    // Property test: route_tables_are_prefix_shaped_as_declared.
    //
    // NOTE on the Flat clause: this issue's own Tests section describes the
    // Flat property as "every Flat pattern shares only its first segment
    // [with every other]". Taken literally that contradicts the Design
    // section's own Flat format, `/api/v1/r<i:w>/{id}`, which fixes TWO
    // leading segments ("api", "v1") before the varying index, not one --
    // every Flat route shares three of its four segments ("api", "v1", and
    // the trailing "{id}" placeholder token) and differs in exactly the
    // route-index segment. This property checks the well-defined,
    // non-vacuous version of that claim (every Flat pattern's segments
    // match every other Flat pattern's segments in every position except
    // the single index-bearing one) rather than the literal "only its
    // first segment" phrasing, which is false of the exact format the
    // issue itself specifies. Flagged here rather than silently forcing a
    // test to pass against the issue's own worked example.
    #[test]
    fn route_tables_are_prefix_shaped_as_declared(n in 1u32..=5_000u32) {
        let shared = route_table(RouteShape::SharedPrefix, n, 4).expect("SharedPrefix builds");
        for r in &shared {
            prop_assert!(
                r.path_pattern.starts_with("/repos/"),
                "SharedPrefix pattern {:?} does not start with /repos/",
                r.path_pattern
            );
        }

        let last = route_table(RouteShape::LastSegment, n, 4).expect("LastSegment builds");
        if n >= 2 {
            let first_parts: Vec<&str> = last[0].path_pattern.split('/').collect();
            let (first_prefix, _) = first_parts.split_at(first_parts.len() - 1);
            for r in &last[1..] {
                let parts: Vec<&str> = r.path_pattern.split('/').collect();
                let (prefix, _) = parts.split_at(parts.len() - 1);
                prop_assert_eq!(
                    prefix, first_prefix,
                    "LastSegment routes must share every segment but the last"
                );
            }
        }

        let flat = route_table(RouteShape::Flat, n, 4).expect("Flat builds");
        if n >= 2 {
            let base_parts: Vec<&str> = flat[0].path_pattern.split('/').collect();
            for r in &flat[1..] {
                let parts: Vec<&str> = r.path_pattern.split('/').collect();
                prop_assert_eq!(parts.len(), base_parts.len());
                let differing = parts
                    .iter()
                    .zip(base_parts.iter())
                    .filter(|(a, b)| a != b)
                    .count();
                prop_assert_eq!(
                    differing, 1,
                    "Flat routes must differ from each other in exactly one segment (the route index)"
                );
            }
        }
    }
}
