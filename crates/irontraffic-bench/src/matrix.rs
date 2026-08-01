// SPDX-License-Identifier: MIT OR Apache-2.0
//! The published benchmark matrix: the base cell, the one-dimension-at-a-time
//! sweeps from it, the adversarial cells drawn from the failure-mode list,
//! and the registry that gives every cell a stable id.
//!
//! The full cross product of the eleven dimensions is `3*3*5*4*3*4*3*4*4*3*2
//! = 622,080` cells, far too many to run or to interpret. The published
//! matrix is therefore a fixed base cell plus one-dimension-at-a-time
//! sweeps: every published sweep varies exactly one dimension from the base,
//! which is what makes each chart honestly interpretable. See this issue's
//! own Design section, and `science/benchmarking.md` D14, for the full
//! argument; this module is the enforcement of it.

use crate::cell::{
    BenchCell, CacheMode, CellId, KeepaliveMode, PathCorpus, Protocol, RateMode, TlsMode,
};
use crate::error::BenchError;
use crate::result::DeepestPercentile;

/// Fraction of measured saturation a fixed-rate cell offers, in permille.
pub const FIXED_RATE_PERMILLE_OF_SATURATION: u64 = 600;

/// The rate a registry cell carries before `resolve_rate` runs.
///
/// Deliberately `RateMode::Saturate` and deliberately NOT `RateMode::Fixed(0)`:
/// a zero rate fails `BenchCell::validate`, and a placeholder that fails
/// validation would make the whole registry invalid. The intent (fixed rate
/// at some percent of saturation, versus deliberately saturating) is carried
/// by [`MatrixEntry::rate_plan`] instead; [`resolve_rate`] is what turns a
/// `PercentOfSaturation` entry into a real `RateMode::Fixed`.
pub const UNRESOLVED_RATE: RateMode = RateMode::Saturate;

/// Largest `bench/saturation.toml` the parser will read, in bytes.
pub const MAX_SATURATION_FILE_BYTES: usize = 65_536;
/// Largest number of lines the saturation parser will read.
pub const MAX_SATURATION_LINES: usize = 4096;
/// Largest single line the saturation parser will read, in bytes.
pub const MAX_SATURATION_LINE_BYTES: usize = 256;
/// Largest measured saturation rate the table may record, in requests per
/// second.
///
/// One order of magnitude above the `RateMode::Fixed` ceiling, so a
/// plausible mis-measurement is still readable while `u64::MAX` is not.
pub const MAX_SATURATION_RPS: u64 = 500_000_000;

/// Upper bound `resolve_rate` will accept for a computed fixed rate,
/// matching `BenchCell::validate`'s own ceiling on `RateMode::Fixed`.
const MAX_RESOLVED_RATE: u64 = 50_000_000;

/// What rate a registry entry intends to run at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatePlan {
    /// Offer as much load as the client can generate. Throughput only.
    Saturate,
    /// Offer this many parts per thousand of the cell's MEASURED saturation
    /// rate.
    PercentOfSaturation {
        /// Parts per thousand. 600 for every published fixed-rate cell.
        permille: u64,
    },
}

/// One published cell plus everything the report needs to describe it.
#[derive(Debug, Clone)]
pub struct MatrixEntry {
    /// The cell itself. Its `rate` field is `UNRESOLVED_RATE` until
    /// `resolve_rate` fills it, so the cell always passes
    /// `BenchCell::validate`.
    pub cell: BenchCell,
    /// What rate this cell intends to run at. This, not `cell.rate`, is the
    /// authority on whether the cell saturates or runs at a fraction of it.
    pub rate_plan: RatePlan,
    /// Deepest percentile this cell's sample count supports.
    pub deepest_percentile: DeepestPercentile,
    /// One line, rendered into the published table. A `SingleHot` cell's
    /// description MUST contain the word "control".
    pub description: &'static str,
    /// Which sweep this belongs to, or `None` for the base and the
    /// adversarial set.
    pub sweep: Option<&'static str>,
    /// Which saturate cell's measured saturation supplies this cell's rate.
    ///
    /// `Some(id)` exactly when `rate_plan` is `PercentOfSaturation`, and
    /// `None` exactly when it is `Saturate`.
    pub saturation_ref: Option<CellId>,
}

/// The fixed base cell every sweep varies exactly one dimension from.
///
/// > H1, TLS off, 1 KB payload, 1,000 routes, uniform random paths, 256
/// > connections, 8 upstreams, filter depth 1, cache bypass, keepalive Both,
/// > fixed rate at 60 percent of saturation.
///
/// Do NOT change this cell. Every sweep is defined relative to it, so a
/// change here silently invalidates every committed result; if the base
/// must change, every id changes with it.
///
/// # Errors
/// `BenchError::CellId` only if the static id fails to parse, which cannot
/// happen and is surfaced rather than unwrapped: this crate's lint
/// configuration allows an expect or unwrap call in test code but not in
/// library code, so this constructor returns a `Result` and callers
/// (including every test in `tests/matrix.rs`) unwrap it themselves.
pub fn base_cell() -> Result<BenchCell, BenchError> {
    Ok(BenchCell {
        id: CellId::parse("base")?,
        protocol: Protocol::H1,
        tls: TlsMode::Off,
        payload_bytes: 1024,
        routes: 1_000,
        path_corpus: PathCorpus::UniformRandom,
        connections: 256,
        upstreams: 8,
        filter_depth: 1,
        cache: CacheMode::Bypass,
        keepalive: KeepaliveMode::Both,
        rate: UNRESOLVED_RATE,
    })
}

/// One entry in the sweep table: a dimension name, the resulting cell's id,
/// its two descriptions (fixed-rate and saturate), and the field mutation
/// that turns the base cell into this sweep cell.
struct Sweep {
    /// The dimension this sweep varies, and the value of
    /// `MatrixEntry::sweep` for both the fixed-rate cell and its saturate
    /// twin.
    dimension: &'static str,
    /// The fixed-rate cell's id. Its saturate twin's id is this plus
    /// `.sat`.
    id: &'static str,
    /// Rendered for the fixed-rate cell.
    description: &'static str,
    /// Rendered for the saturate twin.
    sat_description: &'static str,
    /// Mutates a clone of the base cell into this sweep's cell. A plain
    /// non-capturing `fn` pointer, since every mutation here is a fixed,
    /// literal field assignment.
    mutate: fn(&mut BenchCell),
}

/// The 26 sweep cells, one row per value in the issue's own Sweeps table.
/// `base_cell()` plus these 26, each with a saturate twin, are the 54-entry
/// sweep family.
const SWEEPS: &[Sweep] = &[
    Sweep {
        dimension: "protocol",
        id: "protocol.h2",
        description: "Protocol sweep: HTTP/2 instead of the base cell's HTTP/1.1.",
        sat_description: "Protocol sweep at saturation: HTTP/2.",
        mutate: |c| c.protocol = Protocol::H2,
    },
    Sweep {
        dimension: "protocol",
        id: "protocol.h3",
        description: "Protocol sweep: HTTP/3 instead of the base cell's HTTP/1.1.",
        sat_description: "Protocol sweep at saturation: HTTP/3.",
        mutate: |c| c.protocol = Protocol::H3,
    },
    Sweep {
        dimension: "tls",
        id: "tls.ecdsa_p256",
        description: "TLS sweep: an ECDSA P-256 server certificate instead of plaintext.",
        sat_description: "TLS sweep at saturation: ECDSA P-256.",
        mutate: |c| c.tls = TlsMode::EcdsaP256,
    },
    Sweep {
        dimension: "tls",
        id: "tls.rsa2048",
        description: "TLS sweep: an RSA-2048 server certificate instead of plaintext.",
        sat_description: "TLS sweep at saturation: RSA-2048.",
        mutate: |c| c.tls = TlsMode::Rsa2048,
    },
    Sweep {
        dimension: "payload",
        id: "payload.0",
        description: "Payload sweep: a 0 byte response body instead of the base cell's 1 KB.",
        sat_description: "Payload sweep at saturation: 0 byte response body.",
        mutate: |c| c.payload_bytes = 0,
    },
    Sweep {
        dimension: "payload",
        id: "payload.8192",
        description: "Payload sweep: an 8 KB response body instead of the base cell's 1 KB.",
        sat_description: "Payload sweep at saturation: 8 KB response body.",
        mutate: |c| c.payload_bytes = 8192,
    },
    Sweep {
        dimension: "payload",
        id: "payload.65536",
        description: "Payload sweep: a 64 KB response body instead of the base cell's 1 KB.",
        sat_description: "Payload sweep at saturation: 64 KB response body.",
        mutate: |c| c.payload_bytes = 65536,
    },
    Sweep {
        dimension: "payload",
        id: "payload.1048576",
        description: "Payload sweep: a 1 MB response body instead of the base cell's 1 KB.",
        sat_description: "Payload sweep at saturation: 1 MB response body.",
        mutate: |c| c.payload_bytes = 1_048_576,
    },
    Sweep {
        dimension: "routes",
        id: "routes.10",
        description: "Route count sweep: 10 routes instead of the base cell's 1,000.",
        sat_description: "Route count sweep at saturation: 10 routes.",
        mutate: |c| c.routes = 10,
    },
    Sweep {
        dimension: "routes",
        id: "routes.10000",
        description: "Route count sweep: 10,000 routes instead of the base cell's 1,000.",
        sat_description: "Route count sweep at saturation: 10,000 routes.",
        mutate: |c| c.routes = 10_000,
    },
    Sweep {
        dimension: "routes",
        id: "routes.100000",
        description: "Route count sweep: 100,000 routes instead of the base cell's 1,000.",
        sat_description: "Route count sweep at saturation: 100,000 routes.",
        mutate: |c| c.routes = 100_000,
    },
    Sweep {
        dimension: "corpus",
        id: "corpus.single_hot",
        description: "Path corpus sweep: single hot path, a labelled control, instead of the \
                       base cell's uniform random paths.",
        sat_description: "Path corpus sweep at saturation: single hot path, a labelled control.",
        mutate: |c| c.path_corpus = PathCorpus::SingleHot,
    },
    Sweep {
        dimension: "corpus",
        id: "corpus.adversarial",
        description: "Path corpus sweep: the adversarial worst case path corpus instead of the \
                       base cell's uniform random paths.",
        sat_description: "Path corpus sweep at saturation: the adversarial worst case path \
                           corpus.",
        mutate: |c| c.path_corpus = PathCorpus::AdversarialWorstCase,
    },
    Sweep {
        dimension: "conns",
        id: "conns.16",
        description: "Connection count sweep: 16 concurrent connections instead of the base \
                       cell's 256.",
        sat_description: "Connection count sweep at saturation: 16 concurrent connections.",
        mutate: |c| c.connections = 16,
    },
    Sweep {
        dimension: "conns",
        id: "conns.4096",
        description: "Connection count sweep: 4,096 concurrent connections instead of the base \
                       cell's 256.",
        sat_description: "Connection count sweep at saturation: 4,096 concurrent connections.",
        mutate: |c| c.connections = 4096,
    },
    Sweep {
        dimension: "conns",
        id: "conns.100000",
        description: "Connection count sweep: 100,000 concurrent connections instead of the \
                       base cell's 256.",
        sat_description: "Connection count sweep at saturation: 100,000 concurrent connections.",
        mutate: |c| c.connections = 100_000,
    },
    Sweep {
        dimension: "upstreams",
        id: "upstreams.1",
        description: "Upstream count sweep: 1 upstream endpoint instead of the base cell's 8.",
        sat_description: "Upstream count sweep at saturation: 1 upstream endpoint.",
        mutate: |c| c.upstreams = 1,
    },
    Sweep {
        dimension: "upstreams",
        id: "upstreams.256",
        description: "Upstream count sweep: 256 upstream endpoints instead of the base cell's 8.",
        sat_description: "Upstream count sweep at saturation: 256 upstream endpoints.",
        mutate: |c| c.upstreams = 256,
    },
    Sweep {
        dimension: "filters",
        id: "filters.0",
        description: "Filter depth sweep: an empty filter chain instead of the base cell's \
                       depth of 1.",
        sat_description: "Filter depth sweep at saturation: an empty filter chain.",
        mutate: |c| c.filter_depth = 0,
    },
    Sweep {
        dimension: "filters",
        id: "filters.4",
        description: "Filter depth sweep: a filter chain of depth 4 instead of the base cell's \
                       depth of 1.",
        sat_description: "Filter depth sweep at saturation: a filter chain of depth 4.",
        mutate: |c| c.filter_depth = 4,
    },
    Sweep {
        dimension: "filters",
        id: "filters.16",
        description: "Filter depth sweep: a filter chain of depth 16 instead of the base cell's \
                       depth of 1.",
        sat_description: "Filter depth sweep at saturation: a filter chain of depth 16.",
        mutate: |c| c.filter_depth = 16,
    },
    Sweep {
        dimension: "cache",
        id: "cache.all_hit",
        description: "Cache sweep: every request a cache hit instead of the base cell's bypass.",
        sat_description: "Cache sweep at saturation: every request a cache hit.",
        mutate: |c| c.cache = CacheMode::AllHit,
    },
    Sweep {
        dimension: "cache",
        id: "cache.all_miss",
        description: "Cache sweep: every request a cache miss instead of the base cell's bypass.",
        sat_description: "Cache sweep at saturation: every request a cache miss.",
        mutate: |c| c.cache = CacheMode::AllMiss,
    },
    Sweep {
        dimension: "cache",
        id: "cache.half_hit",
        description: "Cache sweep: half of requests a cache hit instead of the base cell's \
                       bypass.",
        sat_description: "Cache sweep at saturation: half of requests a cache hit.",
        mutate: |c| c.cache = CacheMode::HalfHit,
    },
    Sweep {
        dimension: "keepalive",
        id: "keepalive.downstream_close",
        description: "Keepalive sweep: the downstream connection closed after every request \
                       instead of the base cell's Both.",
        sat_description: "Keepalive sweep at saturation: downstream connection closed after \
                           every request, so the measured rps is the connection setup rate.",
        mutate: |c| c.keepalive = KeepaliveMode::DownstreamClose,
    },
    Sweep {
        dimension: "keepalive",
        id: "keepalive.no_upstream_pool",
        description: "Keepalive sweep: the upstream connection not pooled instead of the base \
                       cell's Both.",
        sat_description: "Keepalive sweep at saturation: the upstream connection not pooled.",
        mutate: |c| c.keepalive = KeepaliveMode::NoUpstreamPool,
    },
];

/// Builds the base cell's two registry entries: the fixed-rate `base` and
/// its saturate twin `base.sat`.
fn base_entries(base: &BenchCell) -> Result<Vec<MatrixEntry>, BenchError> {
    let sat_id = CellId::parse("base.sat")?;
    let sat_cell = BenchCell {
        id: sat_id.clone(),
        ..base.clone()
    };
    Ok(vec![
        MatrixEntry {
            cell: base.clone(),
            rate_plan: RatePlan::PercentOfSaturation {
                permille: FIXED_RATE_PERMILLE_OF_SATURATION,
            },
            deepest_percentile: DeepestPercentile::P999,
            description: "The base cell: H1, TLS off, 1 KB payload, 1,000 routes, uniform \
                           random paths, 256 connections, 8 upstreams, filter depth 1, cache \
                           bypass, keepalive Both, fixed rate at 60 percent of saturation.",
            sweep: None,
            saturation_ref: Some(sat_id),
        },
        MatrixEntry {
            cell: sat_cell,
            rate_plan: RatePlan::Saturate,
            deepest_percentile: DeepestPercentile::P999,
            description: "The base cell at saturation, establishing the base cell's own 60 \
                           percent reference point.",
            sweep: None,
            saturation_ref: None,
        },
    ])
}

/// Builds the 52 sweep-family entries (26 fixed-rate cells plus their 26
/// saturate twins) from [`SWEEPS`].
fn sweep_entries(base: &BenchCell) -> Result<Vec<MatrixEntry>, BenchError> {
    let mut out = Vec::with_capacity(SWEEPS.len() * 2);
    for sweep in SWEEPS {
        let mut cell = base.clone();
        (sweep.mutate)(&mut cell);
        cell.id = CellId::parse(sweep.id)?;
        let sat_id = CellId::parse(&format!("{}.sat", sweep.id))?;
        let sat_cell = BenchCell {
            id: sat_id.clone(),
            ..cell.clone()
        };
        out.push(MatrixEntry {
            cell,
            rate_plan: RatePlan::PercentOfSaturation {
                permille: FIXED_RATE_PERMILLE_OF_SATURATION,
            },
            deepest_percentile: DeepestPercentile::P999,
            description: sweep.description,
            sweep: Some(sweep.dimension),
            saturation_ref: Some(sat_id),
        });
        out.push(MatrixEntry {
            cell: sat_cell,
            rate_plan: RatePlan::Saturate,
            deepest_percentile: DeepestPercentile::P999,
            description: sweep.sat_description,
            sweep: Some(sweep.dimension),
            saturation_ref: None,
        });
    }
    Ok(out)
}

/// Builds one adversarial entry from a clone of the base cell, applying
/// `mutate` and overriding the id, description, rate plan and saturation
/// reference. `sweep` is always `None`: no adversarial cell is a sweep.
fn adv_entry(
    base: &BenchCell,
    id: &str,
    description: &'static str,
    rate_plan: RatePlan,
    saturation_ref: Option<CellId>,
    mutate: impl FnOnce(&mut BenchCell),
) -> Result<MatrixEntry, BenchError> {
    let mut cell = base.clone();
    mutate(&mut cell);
    cell.id = CellId::parse(id)?;
    Ok(MatrixEntry {
        cell,
        rate_plan,
        deepest_percentile: DeepestPercentile::P999,
        description,
        sweep: None,
        saturation_ref,
    })
}

/// Builds the 8 adversarial entries, drawn directly from the failure-mode
/// list. None of these is a sweep from the base: each varies whatever
/// combination of dimensions its own shape needs, which is exactly why it
/// lives here and never on a sweep chart.
///
/// Two of `BenchCell`'s eleven dimensions cannot literally express every
/// adversarial shape's own prose (header shape, and the idle/active
/// connection split have no dedicated field), and `RouteShape::LastSegment`
/// has no corresponding `PathCorpus` variant at all. Where that happens, the
/// closest existing field value is used and the gap is documented on the
/// entry itself; wiring the exact runner-level shape (which literal route
/// table and request generator a cell id resolves to beyond what
/// `BenchCell` can express) is left to `{{bench-runner-and-repetition}}`,
/// which is the first issue that actually spawns a client against a real
/// route table.
///
/// **The stronger, previously undisclosed consequence:** for two of these
/// eight ids, "closest existing field value" does not merely approximate the
/// shape, it lands on a `BenchCell` that is BYTE IDENTICAL, across all
/// eleven fields and `rate_plan`, to a cell already elsewhere in this
/// registry: `adv.last_segment_10k` equals `routes.10000.sat`, and
/// `adv.header_flood` equals `base.sat`. Both are therefore a real
/// duplicate-measurement risk of exactly the shape this issue's own Design
/// section forbids ("two ids for one set of parameters means running the
/// same measurement twice and publishing it as two points"), on top of the
/// one pair the issue itself sanctions by name (`adv.reload_under_load`
/// equalling `base`, because it IS the base cell plus periodic reloads).
/// Accepted here, rather than deferring the two ids or adding a
/// `BenchCell` field neither this issue's Public API section nor its Files
/// table names, because a runner-level shape field is `{{bench-runner-and-repetition}}`'s
/// concern, not this issue's; `registry_duplicate_parameter_sets_are_all_sanctioned`
/// in `tests/matrix.rs` is what keeps this list closed and explicit rather
/// than open-ended: any FOURTH collision that appears without being added to
/// that test's sanctioned list fails the build. See the review finding on
/// PR 819 ("the two adversarial cells are duplicates, not merely
/// unexpressible").
fn adversarial_entries(base: &BenchCell) -> Result<Vec<MatrixEntry>, BenchError> {
    let base_sat = CellId::parse("base.sat")?;
    Ok(vec![
        // 100,000 routes with maximal shared prefixes (the GitHub
        // `/repos/{owner}/{repo}/` shape scaled up), paired with the
        // adversarial worst-case path corpus per this issue's own Design
        // ("AdversarialWorstCase, paired with the SharedPrefix route
        // shape").
        adv_entry(
            base,
            "adv.shared_prefix_100k",
            "Adversarial route table: 100,000 routes with maximal shared prefixes, worst case \
             path corpus.",
            RatePlan::Saturate,
            None,
            |c| {
                c.routes = 100_000;
                c.path_corpus = PathCorpus::AdversarialWorstCase;
            },
        )?,
        // 10,000 routes differing only in the final segment
        // (`RouteShape::LastSegment`). HONESTLY DOCUMENTED GAP: `PathCorpus`
        // has no variant paired with `LastSegment` the way `UniformRandom`
        // pairs with `Flat` and `AdversarialWorstCase` pairs with
        // `SharedPrefix`, so `UniformRandom` is used here as the closest
        // available label (uniform selection is what actually exercises
        // every distinct final segment); the runner that instantiates this
        // cell's real route table is what must actually generate
        // `LastSegment` routes and a corpus that visits them uniformly,
        // which this issue does not wire.
        adv_entry(
            base,
            "adv.last_segment_10k",
            "Adversarial route table: 10,000 routes differing only in the final segment.",
            RatePlan::Saturate,
            None,
            |c| c.routes = 10_000,
        )?,
        // 8 KB of headers across 100 header lines, with duplicate names.
        // HONESTLY DOCUMENTED GAP: none of `BenchCell`'s eleven dimensions
        // represent header shape at all, so every field here is the base
        // cell's own value; the adversarial request shape is a runner-level
        // concern (`{{bench-runner-and-repetition}}`), not a `BenchCell`
        // dimension.
        adv_entry(
            base,
            "adv.header_flood",
            "Adversarial request shape: 8 KB of headers across 100 header lines, with \
             duplicate names.",
            RatePlan::Saturate,
            None,
            |_c| {},
        )?,
        // 100,000 idle connections plus 10,000 active. `connections` is set
        // to the total (110,000): every one of them, idle or active, is a
        // concurrent downstream connection, which is what that field means.
        adv_entry(
            base,
            "adv.idle_100k_active_10k",
            "Adversarial connection shape: 100,000 idle connections plus 10,000 active.",
            RatePlan::Saturate,
            None,
            |c| c.connections = 110_000,
        )?,
        // DownstreamClose at maximum connection-setup rate, TLS ECDSA
        // P-256: the base cell plus TWO dimensions (keepalive and tls),
        // which the sweep family never does and the adversarial set
        // exists to allow. See "The connection-setup-rate cells" in this
        // issue's Design: this cell, its RSA twin, and
        // `keepalive.downstream_close.sat` are the only three cells that
        // publish a connection-setup rate.
        adv_entry(
            base,
            "adv.setup_rate_tls_ecdsa",
            "Adversarial connection setup rate: downstream connection closed after every \
             request at the maximum connection setup rate, TLS ECDSA P-256.",
            RatePlan::Saturate,
            None,
            |c| {
                c.keepalive = KeepaliveMode::DownstreamClose;
                c.tls = TlsMode::EcdsaP256;
            },
        )?,
        adv_entry(
            base,
            "adv.setup_rate_tls_rsa",
            "Adversarial connection setup rate: downstream connection closed after every \
             request at the maximum connection setup rate, TLS RSA-2048.",
            RatePlan::Saturate,
            None,
            |c| {
                c.keepalive = KeepaliveMode::DownstreamClose;
                c.tls = TlsMode::Rsa2048;
            },
        )?,
        // Partial-header concurrency at 50,000 connections.
        adv_entry(
            base,
            "adv.partial_headers_50k",
            "Adversarial connection shape: partial header concurrency at 50,000 connections.",
            RatePlan::Saturate,
            None,
            |c| c.connections = 50_000,
        )?,
        // Config reload every 5 seconds at 60 percent of saturation: the
        // base cell plus periodic reloads (a runner-level behaviour, not a
        // `BenchCell` dimension), so every field is the base cell's own
        // value and this borrows the BASE cell's saturation point rather
        // than getting its own `.sat` twin (it is the base cell plus
        // reloads, not a new shape to saturate separately).
        adv_entry(
            base,
            "adv.reload_under_load",
            "Adversarial operational load: the base cell plus a full route table reload every \
             5 seconds at 60 percent of saturation.",
            RatePlan::PercentOfSaturation {
                permille: FIXED_RATE_PERMILLE_OF_SATURATION,
            },
            Some(base_sat),
            |_c| {},
        )?,
    ])
}

/// The whole published matrix: base, sweeps, saturate twins, adversarial
/// cells. 62 entries: 54 in the sweep family (27 fixed-rate cells, each with
/// a saturate twin) plus 8 adversarial cells.
///
/// # Errors
/// `BenchError::CellId` or `BenchError::Cell` when a constructed cell is
/// invalid.
pub fn registry() -> Result<Vec<MatrixEntry>, BenchError> {
    let base = base_cell()?;
    let mut out = Vec::with_capacity(62);
    out.extend(base_entries(&base)?);
    out.extend(sweep_entries(&base)?);
    out.extend(adversarial_entries(&base)?);
    Ok(out)
}

/// Looks up one entry by id.
///
/// # Errors
/// `BenchError::Parse` naming the id when it is not in the registry, not
/// `BenchError::Cell`: `Cell`'s payload is a `&'static str` and cannot carry a
/// value that varies per call, the identical `&'static str` limitation
/// `resolve_rate`'s own doc comment already documents for the same reason.
/// This issue's own Public API section names `BenchError::Cell` here, which
/// this deliberately deviates from for the reason above; see the review
/// finding on PR 819 ("`entry()`'s documented 'naming the id' clause is
/// unmet and undisclosed").
pub fn entry(id: &CellId) -> Result<MatrixEntry, BenchError> {
    registry()?
        .into_iter()
        .find(|e| &e.cell.id == id)
        .ok_or_else(|| BenchError::parse("matrix", &format!("cell id {id} is not in the registry")))
}

/// The entries one `--suite <name>` selects, in registry order.
///
/// | Name | Entries | Count |
/// | --- | --- | --- |
/// | `base` | `base` and its `.sat` twin | 2 |
/// | `sweeps` | the `base` suite, every entry whose `sweep` is `Some`, and \
///   each of their `.sat` twins | 54 |
/// | `adversarial` | the eight `adv.*` entries | 8 |
/// | `full` | every registry entry | 62 |
///
/// `sweeps` and `adversarial` are disjoint and together are exactly `full`,
/// which is asserted rather than assumed (test 16). `base` is a subset of
/// `sweeps`.
///
/// # Errors
/// `BenchError::Cell` naming the four known suite names when `name` is none
/// of them.
pub fn suite(name: &str) -> Result<Vec<MatrixEntry>, BenchError> {
    let all = registry()?;
    match name {
        "base" => Ok(all
            .into_iter()
            .filter(|e| is_base_family(&e.cell.id))
            .collect()),
        "sweeps" => Ok(all
            .into_iter()
            .filter(|e| is_base_family(&e.cell.id) || e.sweep.is_some())
            .collect()),
        "adversarial" => Ok(all
            .into_iter()
            .filter(|e| e.cell.id.as_str().starts_with("adv."))
            .collect()),
        "full" => Ok(all),
        _ => Err(BenchError::Cell(
            "unknown suite name; the four known names are base, sweeps, adversarial, full",
        )),
    }
}

/// True for `base` and `base.sat`, the two entries the `base` suite selects.
fn is_base_family(id: &CellId) -> bool {
    matches!(id.as_str(), "base" | "base.sat")
}

/// Measured saturation rps per cell id, parsed from `bench/saturation.toml`.
#[derive(Debug, Clone, Default)]
pub struct SaturationTable {
    entries: std::collections::BTreeMap<CellId, u64>,
}

impl SaturationTable {
    /// Parses the TOML-flavoured line form `<cell-id> = <integer>`, with
    /// `#` comments and blank lines ignored.
    ///
    /// A LINE parser over `<cell-id> = <integer>` lines, not a `toml` crate
    /// deserialisation: `toml` is pinned nowhere in the workspace and this
    /// issue does not add it.
    ///
    /// Bounded like every other file parser in this crate: at most
    /// [`MAX_SATURATION_FILE_BYTES`] of input, checked on the slice length
    /// before any split; at most [`MAX_SATURATION_LINES`] lines; at most
    /// [`MAX_SATURATION_LINE_BYTES`] per line.
    ///
    /// A DUPLICATE key is an error, not a last-wins overwrite: this file
    /// decides the rate every fixed-rate cell runs at, and a file with two
    /// values for one cell has no single answer.
    ///
    /// # Errors
    /// `BenchError::Parse` on a malformed entry, a duplicate key (naming
    /// both line numbers), an id that does not parse, a value that is not a
    /// decimal integer, a value of 0, a value above [`MAX_SATURATION_RPS`],
    /// or an input past any of the three bounds.
    pub fn parse(input: &str) -> Result<Self, BenchError> {
        if input.len() > MAX_SATURATION_FILE_BYTES {
            return Err(BenchError::parse(
                "saturation",
                "input exceeds MAX_SATURATION_FILE_BYTES",
            ));
        }

        let mut entries = std::collections::BTreeMap::new();
        let mut first_line_of: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut line_no: usize = 0;

        for raw_line in input.lines() {
            line_no += 1;
            if line_no > MAX_SATURATION_LINES {
                return Err(BenchError::parse(
                    "saturation",
                    "input exceeds MAX_SATURATION_LINES",
                ));
            }
            if raw_line.len() > MAX_SATURATION_LINE_BYTES {
                return Err(BenchError::parse(
                    "saturation",
                    &format!("line {line_no} exceeds MAX_SATURATION_LINE_BYTES"),
                ));
            }
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key_raw, value_raw)) = line.split_once('=') else {
                return Err(BenchError::parse(
                    "saturation",
                    &format!("line {line_no} is not `<cell-id> = <integer>`"),
                ));
            };
            let key_str = key_raw.trim();
            let value_str = value_raw.trim();

            let id = CellId::parse(key_str).map_err(|_| {
                BenchError::parse(
                    "saturation",
                    &format!("line {line_no} has an invalid cell id {key_str:?}"),
                )
            })?;

            if let Some(&first) = first_line_of.get(key_str) {
                return Err(BenchError::parse(
                    "saturation",
                    &format!("cell id {key_str} is duplicated on lines {first} and {line_no}"),
                ));
            }
            first_line_of.insert(key_str.to_owned(), line_no);

            let value: u64 = value_str.parse().map_err(|_| {
                BenchError::parse(
                    "saturation",
                    &format!("line {line_no} has a non-integer value {value_str:?}"),
                )
            })?;
            if value == 0 {
                return Err(BenchError::parse(
                    "saturation",
                    &format!("line {line_no} has a saturation value of zero"),
                ));
            }
            if value > MAX_SATURATION_RPS {
                return Err(BenchError::parse(
                    "saturation",
                    &format!("line {line_no} exceeds MAX_SATURATION_RPS"),
                ));
            }
            entries.insert(id, value);
        }
        Ok(Self { entries })
    }

    /// Measured saturation rps for a cell, if known.
    #[must_use]
    pub fn get(&self, id: &CellId) -> Option<u64> {
        self.entries.get(id).copied()
    }
}

/// Reads measured saturation points and returns the cell with its
/// `RateMode::Fixed` filled to the entry's `PercentOfSaturation` fraction of
/// the measured value.
///
/// For a `RatePlan::Saturate` entry this returns `entry.cell` unchanged,
/// whose `rate` is already `RateMode::Saturate`.
///
/// For a `RatePlan::PercentOfSaturation { permille }` entry it looks up
/// `entry.saturation_ref` (never a string built by appending `.sat`) and
/// returns the cell with `rate = RateMode::Fixed(sat * permille / 1000)`,
/// computed in `u128` and rounded down (integer division already rounds
/// toward zero, which is down for the non-negative values here).
///
/// # Errors
/// `BenchError::Cell` when `saturation_ref` is `None` on a
/// `PercentOfSaturation` entry, when the measured value is 0, or when the
/// computed rate is 0 or above 50,000,000: a guessed rate is how a
/// fixed-rate cell silently ends up at 95 percent of saturation. When the
/// table has no entry for the referenced id, this returns
/// `BenchError::Parse`, not `BenchError::Cell`, because the message must
/// name the referenced id (so the runner knows which saturate cell to run
/// first) and `BenchError::Cell`'s payload is a `&'static str`, which cannot
/// carry a value that varies per call. This is the same shape of gap
/// `Validity::LoadgenSuspect` documents in `result.rs`: a clause asking for
/// something the given error shape has no field to carry.
pub fn resolve_rate(
    entry: &MatrixEntry,
    saturation: &SaturationTable,
) -> Result<BenchCell, BenchError> {
    match entry.rate_plan {
        RatePlan::Saturate => Ok(entry.cell.clone()),
        RatePlan::PercentOfSaturation { permille } => {
            let sat_id = entry.saturation_ref.as_ref().ok_or(BenchError::Cell(
                "a PercentOfSaturation entry must carry a saturation_ref",
            ))?;
            let Some(measured) = saturation.get(sat_id) else {
                return Err(BenchError::parse(
                    "resolve_rate",
                    &format!(
                        "no measured saturation for {sat_id}; run the saturate cell {sat_id} \
                         first"
                    ),
                ));
            };
            if measured == 0 {
                return Err(BenchError::Cell("measured saturation rps is zero"));
            }
            #[expect(
                clippy::integer_division,
                reason = "deliberate floor: rounding down is the design's own stated rule \
                          (\"computed in u128 and rounded DOWN\"), so a fixed-rate cell never \
                          rounds itself up past its intended percent of measured saturation"
            )]
            let computed: u128 = u128::from(measured) * u128::from(permille) / 1000;
            if computed == 0 {
                return Err(BenchError::Cell("computed fixed rate is zero"));
            }
            if computed > u128::from(MAX_RESOLVED_RATE) {
                return Err(BenchError::Cell("computed fixed rate exceeds 50,000,000"));
            }
            #[expect(
                clippy::cast_possible_truncation,
                reason = "computed is checked <= MAX_RESOLVED_RATE (50_000_000) immediately \
                          above, which fits comfortably in u64"
            )]
            let rate = computed as u64; // it-allow: unchecked-cast reason: computed is checked <= 50_000_000 immediately above
            let mut cell = entry.cell.clone();
            cell.rate = RateMode::Fixed(rate);
            Ok(cell)
        }
    }
}
