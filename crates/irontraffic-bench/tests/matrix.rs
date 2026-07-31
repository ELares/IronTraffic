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

use std::collections::{BTreeSet, HashMap};

use irontraffic_bench::{
    BenchCell, CacheMode, CellId, KeepaliveMode, LoadGenerator, MAX_ROUTES,
    MAX_SATURATION_FILE_BYTES, MatrixEntry, Oha, PathCorpus, Protocol, RateMode, RatePlan,
    RouteShape, RunParams, SaturationTable, Scheme, Target, TlsMode, base_cell, entry, path_expr,
    path_samples, registry, resolve_rate, route_table, suite,
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

// Additional, not one of the issue's own numbered tests: `entry()`'s Err arm
// (NOTE on PR 819: "entry()'s documented 'naming the id' clause is unmet and
// undisclosed, and its error path is untested"). Test 2 above only ever
// exercises the success path, which is why the gap survived.
#[test]
fn entry_names_the_missing_id() {
    let bogus = CellId::parse("does_not_exist").expect("valid id shape");
    let err = entry(&bogus).expect_err("must refuse an id not in the registry");
    let msg = err.to_string();
    assert!(
        msg.contains("does_not_exist"),
        "error message {msg:?} for a missing id does not name it"
    );
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

/// Every one of the 26 sweep-family fixed-rate ids named in the issue's own
/// Sweeps table, mapped to a literal expected value for the ONE field its own
/// id names.
///
/// Additional, not one of the issue's own numbered tests: `BLOCKING` finding 1
/// on PR 819. `every_sweep_varies_exactly_one_dimension` above proves exactly
/// one field differs from the base cell; it never proves WHICH value that
/// field holds, and the pinned command-line snapshot
/// (`command_line_hashes_match_the_snapshot`) cannot fill the gap either,
/// because `Oha`'s argv only carries `protocol`, `connections`, `rate`,
/// `keepalive` (only as `DownstreamClose` vs anything else), whether `tls` is
/// off, and `path_expr` (a function of `path_corpus` and `routes` together,
/// not either alone) -- `payload_bytes`, `cache`, `filter_depth`,
/// `upstreams`, and specifically WHICH tls variant, are invisible to it. Six
/// of the ten swept dimensions could therefore carry a value contradicting
/// their own id with the whole suite green before this test existed. This is
/// what makes that unreachable: it is checked directly against the
/// `BenchCell` field, never through a rendered command line or a
/// human-written description.
const SWEEP_FIELD_PINS: &[(&str, SweepField)] = &[
    ("protocol.h2", SweepField::Protocol(Protocol::H2)),
    ("protocol.h3", SweepField::Protocol(Protocol::H3)),
    ("tls.ecdsa_p256", SweepField::Tls(TlsMode::EcdsaP256)),
    ("tls.rsa2048", SweepField::Tls(TlsMode::Rsa2048)),
    ("payload.0", SweepField::PayloadBytes(0)),
    ("payload.8192", SweepField::PayloadBytes(8192)),
    ("payload.65536", SweepField::PayloadBytes(65536)),
    ("payload.1048576", SweepField::PayloadBytes(1_048_576)),
    ("routes.10", SweepField::Routes(10)),
    ("routes.10000", SweepField::Routes(10_000)),
    ("routes.100000", SweepField::Routes(100_000)),
    (
        "corpus.single_hot",
        SweepField::PathCorpus(PathCorpus::SingleHot),
    ),
    (
        "corpus.adversarial",
        SweepField::PathCorpus(PathCorpus::AdversarialWorstCase),
    ),
    ("conns.16", SweepField::Connections(16)),
    ("conns.4096", SweepField::Connections(4096)),
    ("conns.100000", SweepField::Connections(100_000)),
    ("upstreams.1", SweepField::Upstreams(1)),
    ("upstreams.256", SweepField::Upstreams(256)),
    ("filters.0", SweepField::FilterDepth(0)),
    ("filters.4", SweepField::FilterDepth(4)),
    ("filters.16", SweepField::FilterDepth(16)),
    ("cache.all_hit", SweepField::Cache(CacheMode::AllHit)),
    ("cache.all_miss", SweepField::Cache(CacheMode::AllMiss)),
    ("cache.half_hit", SweepField::Cache(CacheMode::HalfHit)),
    (
        "keepalive.downstream_close",
        SweepField::Keepalive(KeepaliveMode::DownstreamClose),
    ),
    (
        "keepalive.no_upstream_pool",
        SweepField::Keepalive(KeepaliveMode::NoUpstreamPool),
    ),
];

/// One pinned expectation: the sweep's dimension and its literal value,
/// checked against the matching `BenchCell` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepField {
    Protocol(Protocol),
    Tls(TlsMode),
    PayloadBytes(u32),
    Routes(u32),
    PathCorpus(PathCorpus),
    Connections(u32),
    Upstreams(u32),
    FilterDepth(u8),
    Cache(CacheMode),
    Keepalive(KeepaliveMode),
}

impl SweepField {
    /// Asserts `cell` carries the pinned value on the exact field this
    /// variant names, and no other field is consulted: a mutation to any
    /// OTHER field is test 4's job (`every_sweep_varies_exactly_one_dimension`)
    /// to catch, not this function's.
    fn assert_matches(self, id: &str, cell: &BenchCell) {
        match self {
            Self::Protocol(want) => assert_eq!(cell.protocol, want, "{id}: protocol"),
            Self::Tls(want) => assert_eq!(cell.tls, want, "{id}: tls"),
            Self::PayloadBytes(want) => {
                assert_eq!(cell.payload_bytes, want, "{id}: payload_bytes");
            }
            Self::Routes(want) => assert_eq!(cell.routes, want, "{id}: routes"),
            Self::PathCorpus(want) => assert_eq!(cell.path_corpus, want, "{id}: path_corpus"),
            Self::Connections(want) => assert_eq!(cell.connections, want, "{id}: connections"),
            Self::Upstreams(want) => assert_eq!(cell.upstreams, want, "{id}: upstreams"),
            Self::FilterDepth(want) => assert_eq!(cell.filter_depth, want, "{id}: filter_depth"),
            Self::Cache(want) => assert_eq!(cell.cache, want, "{id}: cache"),
            Self::Keepalive(want) => assert_eq!(cell.keepalive, want, "{id}: keepalive"),
        }
    }
}

#[test]
fn sweep_values_match_their_ids() {
    let entries = registry().expect("registry builds");
    let by_id: std::collections::BTreeMap<&str, &MatrixEntry> =
        entries.iter().map(|e| (e.cell.id.as_str(), e)).collect();

    assert_eq!(
        SWEEP_FIELD_PINS.len(),
        26,
        "SWEEP_FIELD_PINS must cover every one of the issue's 26 sweep-family ids"
    );

    for (id, expected) in SWEEP_FIELD_PINS {
        let fixed = by_id
            .get(id)
            .unwrap_or_else(|| panic!("missing sweep entry {id}"));
        expected.assert_matches(id, &fixed.cell);

        // And its saturate twin, which must carry the identical value: the
        // whole point of a `.sat` twin is measuring the SAME cell's
        // saturation point, not a different one.
        let sat_id = format!("{id}.sat");
        let sat = by_id
            .get(sat_id.as_str())
            .unwrap_or_else(|| panic!("missing saturate twin {sat_id}"));
        expected.assert_matches(&sat_id, &sat.cell);
    }
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

/// A registry entry's measurable parameter set: every `BenchCell` field
/// except `id` (ids are always unique; that is test 1's job) plus
/// `rate_plan` (NOT `cell.rate`, which is always `UNRESOLVED_RATE` before
/// `resolve_rate` runs and so never distinguishes anything by itself; two
/// entries with otherwise-identical cells but different `rate_plan`s are
/// genuinely different measurements, one fixed-rate and one saturating, so
/// `rate_plan` must be part of the key or a base/`.sat` twin pair would
/// wrongly register as a duplicate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ParamKey {
    protocol: Protocol,
    tls: TlsMode,
    payload_bytes: u32,
    routes: u32,
    path_corpus: PathCorpus,
    connections: u32,
    upstreams: u32,
    filter_depth: u8,
    cache: CacheMode,
    keepalive: KeepaliveMode,
    rate_plan: (u8, u64),
}

impl ParamKey {
    fn from_entry(e: &MatrixEntry) -> Self {
        let rate_plan = match e.rate_plan {
            RatePlan::Saturate => (0u8, 0u64),
            RatePlan::PercentOfSaturation { permille } => (1u8, permille),
        };
        Self {
            protocol: e.cell.protocol,
            tls: e.cell.tls,
            payload_bytes: e.cell.payload_bytes,
            routes: e.cell.routes,
            path_corpus: e.cell.path_corpus,
            connections: e.cell.connections,
            upstreams: e.cell.upstreams,
            filter_depth: e.cell.filter_depth,
            cache: e.cell.cache,
            keepalive: e.cell.keepalive,
            rate_plan,
        }
    }
}

/// Additional, not one of the issue's own numbered tests: `BLOCKING` finding 2
/// on PR 819 ("the two adversarial cells are duplicates, not merely
/// unexpressible"). The issue's own Design section states the rule in
/// terms: "two ids for one set of parameters means running the same
/// measurement twice and publishing it as two points." This test makes that
/// rule mechanical rather than a matter of prose review: every group of two
/// or more ids sharing one parameter set must be in the explicit sanctioned
/// list below, or the test fails. A future accidental duplicate (for
/// example, a new sweep or adversarial cell copy-pasted without changing a
/// field) is caught here even though every OTHER test in this file is silent
/// about it, because none of them compares cells to EACH OTHER, only to the
/// base cell (test 4) or to a snapshot (test 6/7).
#[test]
fn registry_duplicate_parameter_sets_are_all_sanctioned() {
    let entries = registry().expect("registry builds");
    let mut groups: HashMap<ParamKey, Vec<&str>> = HashMap::new();
    for e in &entries {
        groups
            .entry(ParamKey::from_entry(e))
            .or_default()
            .push(e.cell.id.as_str());
    }

    // Every duplicate this registry knowingly ships, each with its own
    // reason documented in full on `adversarial_entries` in `src/matrix.rs`:
    //
    // - `base` / `adv.reload_under_load`: sanctioned by the issue's own
    //   Design section BY NAME. `adv.reload_under_load` IS the base cell
    //   plus periodic reloads, not a new shape to saturate separately.
    // - `routes.10000.sat` / `adv.last_segment_10k`: `BenchCell` has no
    //   route-shape field, so "10,000 routes differing only in the final
    //   segment" collapses onto the same eleven fields `routes.10000.sat`
    //   already occupies. Disclosed gap; wiring `RouteShape::LastSegment`
    //   into something `BenchCell` can express is left to
    //   `{{bench-runner-and-repetition}}`.
    // - `base.sat` / `adv.header_flood`: no `BenchCell` field represents
    //   header shape at all, so every field is the base cell's own value,
    //   which collapses onto `base.sat`. Same disclosed-gap shape.
    let sanctioned: BTreeSet<BTreeSet<&str>> = [
        BTreeSet::from(["base", "adv.reload_under_load"]),
        BTreeSet::from(["routes.10000.sat", "adv.last_segment_10k"]),
        BTreeSet::from(["base.sat", "adv.header_flood"]),
    ]
    .into_iter()
    .collect();

    let mut unexpected: Vec<BTreeSet<&str>> = Vec::new();
    for ids in groups.values() {
        if ids.len() < 2 {
            continue;
        }
        let set: BTreeSet<&str> = ids.iter().copied().collect();
        if !sanctioned.contains(&set) {
            unexpected.push(set);
        }
    }
    assert!(
        unexpected.is_empty(),
        "registry has UNDISCLOSED duplicate parameter sets (two ids for one set of parameters \
         means running the same measurement twice and publishing it as two points, which this \
         issue's own Design section forbids): {unexpected:?}; if this is a deliberate new \
         duplicate, add it to `sanctioned` above with the same reasoning `adversarial_entries` \
         documents, and if it is not, fix the entry instead"
    );

    // The converse: every sanctioned pair must actually occur, so this list
    // cannot rot into asserting a duplicate that no longer happens (for
    // example if a future field addition to `BenchCell` lets one of the two
    // disclosed gaps above express its own real shape and stop colliding).
    for pair in &sanctioned {
        let occurs = groups.values().any(|ids| {
            let set: BTreeSet<&str> = ids.iter().copied().collect();
            set == *pair
        });
        assert!(
            occurs,
            "sanctioned duplicate pair {pair:?} did not actually occur in the registry"
        );
    }
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

/// Additional, not one of the issue's own numbered tests: `BLOCKING` finding 3
/// on PR 819 ("`path_samples` has no route-agreement check"). Test 7a above
/// proves the corpus REGEX and the route table agree, but it expands that
/// regex with `rand_regex`, a different engine than `path_samples`'s own
/// hand-rolled four-construct expander; nothing anywhere previously fed
/// `path_samples`'s OWN output through a route-matching check. `path_samples`
/// is also the one primitive `{{bench-runner-and-repetition}}` will call to
/// materialise vegeta's real targets file, so an undetected regression here
/// is the single-hot-path pathology (or an all-404 corpus) landing directly
/// in a published run.
#[test]
fn path_samples_agrees_with_route_table_and_is_distributed() {
    const SAMPLES: u32 = 10_000;

    // UniformRandom, paired with Flat, at the base cell's own 1,000 routes.
    {
        let n = 1_000u32;
        let w = 3usize;
        let table = route_table(RouteShape::Flat, n, 8).expect("route_table(Flat, 1000, 8)");
        let samples = path_samples(PathCorpus::UniformRandom, n, SAMPLES, 0x5EED_0001)
            .expect("path_samples(UniformRandom, 1000, ..)");
        assert_eq!(samples.len(), SAMPLES as usize);
        let mut distinct: BTreeSet<&str> = BTreeSet::new();
        for path in &samples {
            let idx = extract_uniform_index(path, w).unwrap_or_else(|| {
                panic!("path_samples produced {path:?}, not the UniformRandom shape")
            });
            let route = table
                .get(idx as usize)
                .unwrap_or_else(|| panic!("index {idx} out of range for {} routes", table.len()));
            assert!(
                route_matches(&route.path_pattern, path),
                "path_samples produced {path:?}, which does not match route {:?}",
                route.path_pattern
            );
            distinct.insert(path.as_str());
        }
        assert!(
            distinct.len() * 2 > samples.len(),
            "UniformRandom path_samples produced only {} distinct paths out of {SAMPLES}: the \
             single-hot-path pathology this issue exists to prevent",
            distinct.len()
        );
    }

    // AdversarialWorstCase, paired with SharedPrefix, at 100,000 routes.
    {
        let n = 100_000u32;
        let w = 5usize;
        let table = route_table(RouteShape::SharedPrefix, n, 8)
            .expect("route_table(SharedPrefix, 100_000, 8)");
        let samples = path_samples(PathCorpus::AdversarialWorstCase, n, SAMPLES, 0x5EED_0002)
            .expect("path_samples(AdversarialWorstCase, 100_000, ..)");
        assert_eq!(samples.len(), SAMPLES as usize);
        let mut distinct: BTreeSet<&str> = BTreeSet::new();
        for path in &samples {
            let idx = extract_adversarial_index(path, w).unwrap_or_else(|| {
                panic!("path_samples produced {path:?}, not the AdversarialWorstCase shape")
            });
            let route = table
                .get(idx as usize)
                .unwrap_or_else(|| panic!("index {idx} out of range for {} routes", table.len()));
            assert!(
                route_matches(&route.path_pattern, path),
                "path_samples produced {path:?}, which does not match route {:?}",
                route.path_pattern
            );
            distinct.insert(path.as_str());
        }
        assert!(
            distinct.len() * 2 > samples.len(),
            "AdversarialWorstCase path_samples produced only {} distinct paths out of {SAMPLES}",
            distinct.len()
        );
    }

    // SingleHot: the labelled control. Every sample is, BY DESIGN, the same
    // single path (route 0); pinning that alongside the two distributed
    // corpora above is what turns "distinct count is high for the real
    // corpora" into an actual discriminating test rather than a coincidence
    // of a lenient threshold that would also pass for a single-hot bug.
    {
        let n = 1_000u32;
        let table = route_table(RouteShape::Flat, n, 8).expect("route_table(Flat, 1000, 8)");
        let samples = path_samples(PathCorpus::SingleHot, n, 50, 0x5EED_0003)
            .expect("path_samples(SingleHot, 1000, ..)");
        let distinct: BTreeSet<&str> = samples.iter().map(String::as_str).collect();
        assert_eq!(
            distinct.len(),
            1,
            "SingleHot must always produce the same single path, got {distinct:?}"
        );
        let only = samples.first().expect("50 samples requested");
        let route0 = table
            .first()
            .expect("route_table(Flat, 1000, 8) is non-empty");
        assert!(
            route_matches(&route0.path_pattern, only),
            "SingleHot path {only:?} does not match route 0 {:?}",
            route0.path_pattern
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

/// Additional, not one of the issue's own numbered tests: `SHOULD_FIX` finding
/// 6 on PR 819 ("the 'connection setup rate' acceptance criterion is
/// untested in both directions"). The issue's own acceptance criteria list
/// names exactly three ids whose description must contain the phrase
/// "connection setup rate", and says no other entry's may: that phrase is
/// how the renderer and a human reader agree which published rows carry the
/// D13 figure. Checking only the three positives (as a naive test would)
/// leaves the set free to silently grow; checking only "at least these
/// three" leaves it free to silently shrink to two. This test asserts the
/// SET is exactly these three, in both directions at once.
#[test]
fn connection_setup_rate_phrase_appears_on_exactly_three_entries() {
    let entries = registry().expect("registry builds");
    let expected: BTreeSet<&str> = BTreeSet::from([
        "keepalive.downstream_close.sat",
        "adv.setup_rate_tls_ecdsa",
        "adv.setup_rate_tls_rsa",
    ]);
    let actual: BTreeSet<&str> = entries
        .iter()
        .filter(|e| e.description.contains("connection setup rate"))
        .map(|e| e.cell.id.as_str())
        .collect();
    assert_eq!(
        actual, expected,
        "\"connection setup rate\" must appear in exactly these three entries' descriptions, no \
         fewer and no more"
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

/// Additional, not one of the issue's own numbered tests: `SHOULD_FIX` finding
/// 4 on PR 819 ("`RouteShape::RealWorldMix` ships with zero verification").
/// It is one of the four shapes the issue's own Files table requires and is
/// re-exported from `lib.rs`, but every OTHER test in this file (test 9's
/// determinism check, test 10's uniqueness check, and the
/// `route_tables_are_prefix_shaped_as_declared` property test) iterates only
/// `Flat`, `SharedPrefix` and `LastSegment`. Without this, the shipped shape
/// could be hundreds of copies of a single static route and nothing would
/// notice.
#[test]
fn real_world_mix_shapes_are_verified() {
    for n in [36u32, 217, 609] {
        let table = route_table(RouteShape::RealWorldMix, n, 8)
            .unwrap_or_else(|err| panic!("route_table(RealWorldMix, {n}, 8) failed: {err}"));
        assert_eq!(
            table.len(),
            n as usize,
            "RealWorldMix({n}) must return exactly {n} routes when n is one of its own defined \
             sizes"
        );

        let unique: BTreeSet<&str> = table.iter().map(|r| r.path_pattern.as_str()).collect();
        assert_eq!(
            unique.len(),
            table.len(),
            "RealWorldMix({n}) produced a duplicate route pattern: {} unique out of {}",
            unique.len(),
            table.len()
        );

        // "A mix of static and dynamic routes", per this shape's own doc
        // comment and the issue's Design section: at least one pattern must
        // carry a wildcard segment and at least one must not, so the shape
        // cannot collapse to "all static" or "all dynamic" (or to one
        // constant string, which is also both) without this test catching
        // it.
        let has_dynamic = table.iter().any(|r| r.path_pattern.contains('{'));
        let has_static = table.iter().any(|r| !r.path_pattern.contains('{'));
        assert!(
            has_dynamic,
            "RealWorldMix({n}) has no dynamic (wildcard) route"
        );
        assert!(has_static, "RealWorldMix({n}) has no static route");
    }

    // route_table's own determinism invariant (test 9's own reasoning)
    // applies here too: two calls must agree byte for byte.
    let a = route_table(RouteShape::RealWorldMix, 217, 8).expect("builds");
    let b = route_table(RouteShape::RealWorldMix, 217, 8).expect("builds");
    assert_eq!(
        a, b,
        "RealWorldMix(217, 8) is not deterministic across two calls"
    );
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

    // `MAX_ROUTES`'s own doc comment claims "test 13a asserts the two
    // numbers agree" against `BenchCell::validate`'s ceiling on `routes`
    // (`self.routes > 1_000_000`, a literal in `cell.rs` with no named
    // constant, so this is checked BEHAVIOURALLY rather than by comparing to
    // a second constant that does not exist). Before this, no assertion
    // anywhere backed that doc claim: `SHOULD_FIX` finding 5 on PR 819
    // ("MAX_ROUTES' doc comment claims a test 13a assertion that does not
    // exist"). A cell at exactly `MAX_ROUTES` routes must validate; one at
    // `MAX_ROUTES + 1` must not, which is exactly `route_table`'s own
    // ceiling above.
    let base = base_cell().expect("base cell builds");
    let mut at_max = base.clone();
    at_max.routes = MAX_ROUTES;
    at_max
        .validate()
        .unwrap_or_else(|err| panic!("a cell with routes == MAX_ROUTES must validate: {err}"));

    let mut over_max = base;
    over_max.routes = MAX_ROUTES + 1;
    assert!(
        over_max.validate().is_err(),
        "a cell with routes == MAX_ROUTES + 1 must fail BenchCell::validate, or MAX_ROUTES has \
         drifted from validate's own ceiling"
    );
}

/// Additional, not one of the issue's own numbered tests: `SHOULD_FIX` finding
/// 7 on PR 819 ("`path_expr` at `routes = 1` silently yields a degenerate
/// corpus that matches no route"). Before the fix this test pins,
/// `path_expr(_, 1)` returned `Ok` with a corpus regex that silently did NOT
/// name the sole generated route (a zero-width index class emits no digit at
/// all, while `route_table` always renders index 0's literal digit `"0"`,
/// Rust's integer formatting having no empty-string representation of `0`).
/// `routes == 1` is a valid `BenchCell` (`validate` rejects only `routes ==
/// 0`) and the issue's own Context adopts "a single static route" as one of
/// the real API corpus shapes, so a future cell can reach this even though
/// none currently does. The fix refuses `routes == 1` by name (see
/// `path_expr`'s own doc comment for why no width reconciles the two sides),
/// so this asserts the refusal end to end, through the public API, alongside
/// `path_expr_refuses_a_single_route` in `corpus.rs`'s own unit tests.
#[test]
fn path_expr_and_path_samples_refuse_routes_one() {
    let err = path_expr(PathCorpus::UniformRandom, 1).expect_err("must refuse routes == 1");
    assert!(
        err.to_string().to_lowercase().contains("routes == 1")
            || err.to_string().to_lowercase().contains("single-route"),
        "error {err} does not explain the routes == 1 refusal"
    );

    let err2 =
        path_samples(PathCorpus::UniformRandom, 1, 20, 0x5EED_0004).expect_err("must propagate");
    assert!(
        err2.to_string().to_lowercase().contains("routes == 1")
            || err2.to_string().to_lowercase().contains("single-route"),
        "path_samples's propagated error {err2} does not explain the routes == 1 refusal"
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
