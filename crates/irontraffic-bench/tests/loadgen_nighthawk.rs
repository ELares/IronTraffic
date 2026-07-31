// SPDX-License-Identifier: MIT OR Apache-2.0
//! Command-line and parser tests for the `Nighthawk` adapter (issue #412).
//!
//! # What these tests do and do NOT prove
//!
//! `tests/fixtures/nighthawk-output.json` is NOT a genuine capture, unlike
//! `tests/fixtures/oha-1.15.0.json`. `crates/irontraffic-bench/src/loadgen/nighthawk.rs`'s
//! own module doc explains why (no `docker`/`podman` in this environment) and
//! names the three sources it was reconstructed from instead. `parse_fixture_is_exact`
//! below is therefore an authority on this parser's OWN reading of that
//! shape, not evidence that the shape matches a real `envoyproxy/nighthawk-dev`
//! run.
//!
//! `Nighthawk::reconstruct_statistic` (the function that actually enforces
//! the [`MIN_PERCENTILE_ENTRIES`]/[`MAX_PERCENTILE_ENTRIES`]/monotonicity/
//! reconciliation rules) is private to that module, so every test below that
//! exercises it does so THROUGH `Nighthawk::parse`, by embedding a hand-built
//! `percentiles` array into an otherwise-valid synthetic document: `make_percentiles_with_counts`,
//! `make_statistic_with_counts`, and the thin wrappers built on them
//! (`make_percentiles`, `make_statistic`, `count_ladder`) are this file's own
//! generator, not a captured tool output, exactly like `tests/loadgen_oha.rs`'s
//! `valid_value()` is for `Oha`.
//!
//! Every synthetic document built here keeps its counters internally
//! consistent with whatever `request_to_response` statistic it embeds
//! (`requests_sent`, `benchmark.http_2xx`, and the two error counters), so
//! that a test aimed at ONE violated rule does not incidentally trip the
//! separate "reconstructed latency sample count exceeds `requests_sent`"
//! cross-check `Nighthawk::parse`'s own doc explains is inherited from the
//! shared `fuzz_loadgen_json.rs` harness, rather than the rule the test
//! actually names.

use std::sync::atomic::{AtomicU64, Ordering};

use irontraffic_bench::{
    BenchCell, BenchError, CacheMode, CellId, ContainerRuntime, Invocation, KeepaliveMode,
    LoadGenerator, MAX_PERCENTILE_ENTRIES, MAX_REPORTED_REQUESTS, MAX_TOOL_OUTPUT_BYTES,
    MIN_PERCENTILE_ENTRIES, Nighthawk, ParseCtx, PathCorpus, Protocol, RateMode, RunParams, Scheme,
    Target, TlsMode, ToolStamp,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

/// A reconstructed (not captured; see the module doc) Nighthawk-shaped JSON
/// output.
const FIXTURE_BYTES: &[u8] = include_bytes!("fixtures/nighthawk-output.json");

/// A minimal, individually valid `BenchCell`: fixed rate, H1, TLS off,
/// `SingleHot`, `Both` keepalive, 64 connections. Mirrors
/// `tests/loadgen_oha.rs`'s own `base_cell` exactly, so a reader who knows
/// that convention already knows this one.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: \"base\" is a literal already \
              covered by tests/cell_id.rs's own parses_single_segment"
)]
fn base_cell() -> BenchCell {
    BenchCell {
        id: CellId::parse("base").expect("\"base\" is a valid cell id"),
        protocol: Protocol::H1,
        tls: TlsMode::Off,
        payload_bytes: 1024,
        routes: 100,
        path_corpus: PathCorpus::SingleHot,
        connections: 64,
        upstreams: 1,
        filter_depth: 0,
        cache: CacheMode::Bypass,
        keepalive: KeepaliveMode::Both,
        rate: RateMode::Fixed(50_000),
    }
}

/// A minimal, individually valid `Target` pairing with [`base_cell`].
fn base_target() -> Target {
    Target {
        scheme: Scheme::Http,
        host: "example.test".to_owned(),
        connect: std::net::SocketAddr::from(([10, 0, 0, 5], 8080)),
        sni: None,
        path_expr: "/hot".to_owned(),
    }
}

/// Pairs with [`base_cell`] and [`base_target`]: 30 measured seconds, 5
/// warmup seconds, no explicit concurrency override.
fn base_run() -> RunParams {
    RunParams {
        duration_secs: 30,
        warmup_secs: 5,
        concurrency: None,
    }
}

/// A valid, 64 character lowercase-hex digest body (no `sha256:` prefix).
fn valid_digest_body() -> String {
    "0123456789abcdef".repeat(4)
}

/// A `Nighthawk` built directly (bypassing `from_pin`, whose own validation
/// is exercised separately by tests 7 through 9 and 17): `runtime`, `image`
/// and `client_cores` are all `pub`, exactly like `Oha`'s own test file
/// builds a `ToolStamp` directly rather than through any validating
/// constructor.
fn base_nighthawk() -> Nighthawk {
    Nighthawk {
        runtime: ContainerRuntime::Docker,
        image: format!("envoyproxy/nighthawk-dev@sha256:{}", valid_digest_body()),
        client_cores: "0-3".to_owned(),
    }
}

fn base_tool_stamp() -> ToolStamp {
    ToolStamp {
        name: "nighthawk".to_owned(),
        version: "nighthawk_client version: deadbeef/1.29.0-dev/Clean/RELEASE/BoringSSL".to_owned(),
        image_digest: None,
    }
}

#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: base_cell/base_target/base_run/\
              base_nighthawk are this file's own fixed, valid constants, so planning cannot fail"
)]
fn base_invocation() -> Invocation {
    base_nighthawk()
        .plan(&base_cell(), &base_target(), &base_run())
        .expect("the base cell, target and run are individually valid")
}

/// The exact expected argument vector for
/// `base_nighthawk().plan(base_cell(), base_target(), base_run())`, written
/// out element by element so a reordering, an insertion, or a dropped token
/// fails this test rather than an assertion that only checks membership.
/// Matches the Design's own "The invocation" code block exactly.
fn base_expected_args() -> Vec<String> {
    [
        "run",
        "--rm",
        "--network",
        "host",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--cpuset-cpus",
        "0-3",
        "--memory",
        "4g",
        "--pids-limit",
        "4096",
        "envoyproxy/nighthawk-dev@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "nighthawk_client",
        "--open-loop",
        "--max-pending-requests",
        "0",
        "--rps",
        "50000",
        "--connections",
        "64",
        "--concurrency",
        "auto",
        "--duration",
        "30",
        "--protocol",
        "http1",
        "--output-format",
        "json",
        "--request-header",
        "host: example.test",
        "http://10.0.0.5:8080/hot",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// The index of `seq` as a contiguous run inside `args`, or `None`. Mirrors
/// `tests/loadgen_oha.rs`'s own identically named helper.
fn find_subsequence(args: &[String], seq: &[&str]) -> Option<usize> {
    if seq.is_empty() || args.len() < seq.len() {
        return None;
    }
    args.windows(seq.len())
        .position(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
}

/// Asserts `err` is `BenchError::Parse` naming the `"nighthawk"` tool and
/// returns its `detail` text, so every caller can assert on the SPECIFIC
/// reason rather than only the variant.
#[allow(
    clippy::panic,
    reason = "test-support helper, not itself a #[test] fn: panicking here surfaces which \
              caller's assertion actually failed, with the real BenchError in the message"
)]
fn expect_parse_detail(err: &BenchError) -> &str {
    match err {
        BenchError::Parse { tool, detail } => {
            assert_eq!(*tool, "nighthawk");
            detail.as_str()
        }
        other => panic!("expected BenchError::Parse, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// A private temporary directory for `from_pin`'s digest-file tests. Mirrors
// `tests/provenance.rs`'s own `ScriptDir` helper: this crate declares no
// `tempfile` dependency, so a hand-rolled `std::env::temp_dir()` join with a
// process id and a monotonic counter is what keeps concurrent test binaries
// (and repeated calls within one) from colliding.
// ---------------------------------------------------------------------------

static DIGEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct DigestDir {
    dir: std::path::PathBuf,
}

impl DigestDir {
    #[allow(
        clippy::expect_used,
        reason = "test-support helper, not itself a #[test] fn: mirrors tests/provenance.rs's \
                  ScriptDir::new"
    )]
    fn new() -> Self {
        let id = DIGEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "irontraffic-bench-nighthawk-test-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)
            .expect("a temp directory for a fixture digest file must be creatable");
        Self { dir }
    }

    /// Writes `content` to a `nighthawk.digest` file in this directory and
    /// returns its path.
    #[allow(
        clippy::expect_used,
        reason = "test-support helper, not itself a #[test] fn"
    )]
    fn write(&self, content: &str) -> std::path::PathBuf {
        let path = self.dir.join("nighthawk.digest");
        std::fs::write(&path, content).expect("the fixture digest file must be writable");
        path
    }
}

impl Drop for DigestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Synthetic Nighthawk JSON document builders. See the module doc: these
// stand in for a captured tool output, exactly like `tests/loadgen_oha.rs`'s
// `valid_value()` does for `Oha`.
// ---------------------------------------------------------------------------

/// A non-decreasing count ladder of `entries` values ending EXACTLY at
/// `total`: `count_ladder(entries, total)[i]` is `total * (i + 1) / entries`
/// for every entry but the last, which is `total` itself. Non-decreasing by
/// construction: integer floor division by a fixed positive divisor
/// preserves the `<=` ordering of its numerator, so no separate fix-up pass
/// is needed (and none is written, to avoid indexing into the vector this
/// function itself is building).
#[allow(
    clippy::integer_division,
    reason = "test-fixture generator: this is a deliberate floor-division ladder (see this \
              function's own doc), not a truncation bug"
)]
fn count_ladder(entries: usize, total: u64) -> Vec<u64> {
    let entries_u64 = entries as u64;
    let mut counts = Vec::with_capacity(entries);
    for i in 1..=entries {
        let i_u64 = i as u64;
        let count = if i == entries {
            total
        } else {
            total.saturating_mul(i_u64) / entries_u64.max(1)
        };
        counts.push(count);
    }
    counts
}

/// Builds one `percentiles` JSON array from an explicit, caller-supplied
/// non-decreasing `counts` ladder: strictly increasing `percentile`
/// fractions, non-decreasing `duration` strings, and each row's `count` taken
/// verbatim from `counts`. The one place this file's generators touch
/// floating point at all: `percentile` is intrinsically a fraction, and the
/// `#[expect]` below documents why the precision this cast could lose never
/// matters for a monotone test fraction over the small `counts.len()` this
/// file ever passes (at most a few thousand, comfortably inside f64's exact
/// integer range).
#[expect(
    clippy::cast_precision_loss,
    reason = "counts.len() is at most a few thousand in every call site this test file has \
              (the largest, test 14's oversized-list case, is 5,000), many orders of magnitude \
              below f64's 2^53 exact-integer range, so idx as f64 and entries_u64 as f64 lose no \
              precision that matters for a strictly increasing test fraction"
)]
#[allow(
    clippy::integer_division,
    reason = "splitting a nanosecond count into whole seconds and a fractional remainder by a \
              fixed constant is exact arithmetic, not a truncation bug"
)]
fn make_percentiles_with_counts(counts: &[u64]) -> Vec<Value> {
    let entries_u64 = counts.len() as u64;
    let mut rows = Vec::with_capacity(counts.len());
    for (i, &count) in counts.iter().enumerate() {
        let idx = (i + 1) as u64;
        let dur_ns: u64 = 50_000 + idx * 21_000;
        let whole = dur_ns / 1_000_000_000;
        let frac_ns = dur_ns % 1_000_000_000;
        let percentile = idx as f64 / entries_u64 as f64;
        rows.push(json!({
            "percentile": percentile,
            "count": count.to_string(),
            "duration": format!("{whole}.{frac_ns:09}s"),
        }));
    }
    rows
}

/// `make_percentiles_with_counts` over [`count_ladder`]'s own ladder: the
/// common case of "give me `entries` rows reconciling exactly to `total`".
fn make_percentiles(entries: usize, total: u64) -> Vec<Value> {
    make_percentiles_with_counts(&count_ladder(entries, total))
}

fn make_statistic_with_counts(id: &str, counts: &[u64], declared_count: u64) -> Value {
    json!({
        "id": id,
        "count": declared_count.to_string(),
        "percentiles": make_percentiles_with_counts(counts),
    })
}

fn make_statistic(id: &str, entries: usize, total: u64) -> Value {
    json!({
        "id": id,
        "count": total.to_string(),
        "percentiles": make_percentiles(entries, total),
    })
}

fn make_counter(name: &str, value: u64) -> Value {
    json!({ "name": name, "value": value.to_string() })
}

/// A fully valid `"global"` result entry: `request_to_response` (count
/// 1,000), `queue_to_connect` (count 64) and `sequencer.blocking` (count 12),
/// each with 70 percentile rows (above [`MIN_PERCENTILE_ENTRIES`]), and the
/// five counters `Nighthawk::parse` requires, chosen so
/// `sum(status_counts) + errors == requests_sent` and
/// `latency.len() <= requests_sent + 4` both hold: `responses_ok` (990) plus
/// the two error counters (5 and 5) accounts for all 1,000 of
/// `upstream_rq_total`, and `request_to_response`'s own declared count
/// (1,000) matches `upstream_rq_total` exactly.
fn make_global_result() -> Value {
    json!({
        "name": "global",
        "execution_duration": "30.000000000s",
        "statistics": [
            make_statistic("benchmark_http_client.request_to_response", 70, 1000),
            make_statistic("benchmark_http_client.queue_to_connect", 70, 64),
            make_statistic("sequencer.blocking", 70, 12),
        ],
        "counters": [
            make_counter("upstream_rq_total", 1000),
            make_counter("benchmark.http_2xx", 990),
            make_counter("benchmark.pool_connection_failure", 5),
            make_counter("benchmark.stream_resets", 5),
            make_counter("upstream_cx_rx_bytes_total", 130_000),
        ],
    })
}

/// A `results` entry carrying only a `name`: valid for every test that needs
/// an entry present but never SELECTED (a non-`"global"` worker, or a filler
/// entry past `MAX_RESULT_ENTRIES`), since `Nighthawk::parse` reads nothing
/// but `name` from an entry it does not choose.
fn make_minimal_result(name: &str) -> Value {
    json!({ "name": name })
}

/// Serialises `results` into a top-level Nighthawk `Output` document.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: serialising an already-valid \
              serde_json::Value tree this file itself built (no NaN/Infinity float anywhere in \
              it) cannot fail"
)]
fn make_document(results: &[Value]) -> Vec<u8> {
    serde_json::to_vec(&json!({ "results": results })).expect("a built Value always serialises")
}

/// Replaces the array entry whose `"statistics"` array carries `id` with
/// `replacement`, in place.
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test-support helper, not itself a #[test] fn: operates only on documents this \
              file's own generators built, whose shape is therefore known"
)]
fn replace_statistic(global: &mut Value, id: &str, replacement: Value) {
    let statistics = global
        .get_mut("statistics")
        .and_then(Value::as_array_mut)
        .expect("global result has a statistics array");
    for s in statistics.iter_mut() {
        if s.get("id").and_then(Value::as_str) == Some(id) {
            *s = replacement;
            return;
        }
    }
    panic!("no statistic {id} to replace");
}

/// Removes the array entry whose `"id"` field equals `id` from
/// `global`'s `"statistics"` array, in place.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: operates only on documents this \
              file's own generators built, whose shape is therefore known"
)]
fn remove_statistic(global: &mut Value, id: &str) {
    let statistics = global
        .get_mut("statistics")
        .and_then(Value::as_array_mut)
        .expect("global result has a statistics array");
    statistics.retain(|s| s.get("id").and_then(Value::as_str) != Some(id));
}

/// Overwrites `global`'s `key` field with `new_value`, in place.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: operates only on documents this \
              file's own generators built, whose shape is therefore known"
)]
fn set_field(global: &mut Value, key: &str, new_value: Value) {
    global
        .as_object_mut()
        .expect("global result is an object")
        .insert(key.to_owned(), new_value);
}

/// Builds one document whose `"global"` entry carries exactly `statistic` as
/// its `request_to_response` statistic, plus a fixed `queue_to_connect` and
/// `sequencer.blocking`, with counters rebuilt so `requests_sent` equals
/// `total_requests` exactly: this is what the property test uses so its own
/// `total` parameter never trips the separate `requests_sent` cross-check
/// documented at the top of this file.
fn make_document_with_latency_statistic(statistic: &Value, total_requests: u64) -> Vec<u8> {
    let global = json!({
        "name": "global",
        "execution_duration": "30.000000000s",
        "statistics": [
            statistic,

            make_statistic("benchmark_http_client.queue_to_connect", 64, 10),
            make_statistic("sequencer.blocking", 64, 5),
        ],
        "counters": [
            make_counter("upstream_rq_total", total_requests),
            make_counter("benchmark.http_2xx", total_requests),
            make_counter("benchmark.pool_connection_failure", 0),
            make_counter("benchmark.stream_resets", 0),
            make_counter("upstream_cx_rx_bytes_total", total_requests.saturating_mul(13)),
        ],
    });
    make_document(&[global])
}

// ---------------------------------------------------------------------------
// 1. plan_pins_the_argument_vector
// ---------------------------------------------------------------------------

#[test]
fn plan_pins_the_argument_vector() {
    let invocation = base_invocation();
    assert_eq!(invocation.program, "docker");
    assert_eq!(invocation.args, base_expected_args());
    assert!(invocation.env.is_empty());
}

// ---------------------------------------------------------------------------
// 2. plan_uses_host_network
// ---------------------------------------------------------------------------

#[test]
fn plan_uses_host_network() {
    // A bridge network's NAT adds a variable extra hop that would sit
    // INSIDE the latency measurement itself; `--network host` shares the
    // benchmark host's own network namespace with the container instead, so
    // the only hop the measurement ever sees is the one to the system under
    // test. See docs/THREAT-MODEL.md's "Benchmark tool containers" section
    // for the isolation this trades away in exchange.
    let invocation = base_invocation();
    assert!(find_subsequence(&invocation.args, &["--network", "host"]).is_some());
}

// ---------------------------------------------------------------------------
// 3. plan_open_loop_for_fixed_rate
// ---------------------------------------------------------------------------

#[test]
fn plan_open_loop_for_fixed_rate() {
    let mut cell = base_cell();
    cell.rate = RateMode::Fixed(50_000);
    let invocation = base_nighthawk()
        .plan(&cell, &base_target(), &base_run())
        .expect("a fixed-rate cell plans");
    assert!(invocation.args.iter().any(|a| a == "--open-loop"));
    assert!(find_subsequence(&invocation.args, &["--max-pending-requests", "0"]).is_some());
    assert!(find_subsequence(&invocation.args, &["--rps", "50000"]).is_some());
}

// ---------------------------------------------------------------------------
// 4. plan_saturate_omits_open_loop
// ---------------------------------------------------------------------------

#[test]
fn plan_saturate_omits_open_loop() {
    let mut cell = base_cell();
    cell.rate = RateMode::Saturate;
    let nh = base_nighthawk();
    assert!(
        nh.supports(&cell).is_ok(),
        "Nighthawk saturate mode is a legitimate throughput cell, unlike Oha's"
    );
    let invocation = nh
        .plan(&cell, &base_target(), &base_run())
        .expect("a saturate cell plans");
    assert!(!invocation.args.iter().any(|a| a == "--open-loop"));
    assert!(
        !invocation
            .args
            .iter()
            .any(|a| a == "--max-pending-requests")
    );
    assert!(!invocation.args.iter().any(|a| a == "--rps"));
}

// ---------------------------------------------------------------------------
// 5. plan_protocol_selector
// ---------------------------------------------------------------------------

#[test]
fn plan_protocol_selector() {
    let nh = base_nighthawk();
    let target = base_target();
    let run = base_run();
    for (protocol, expected) in [
        (Protocol::H1, "http1"),
        (Protocol::H2, "http2"),
        (Protocol::H3, "http3"),
    ] {
        let mut cell = base_cell();
        cell.protocol = protocol;
        let invocation = nh.plan(&cell, &target, &run).expect("every protocol plans");
        assert!(
            find_subsequence(&invocation.args, &["--protocol", expected]).is_some(),
            "{protocol:?} must render --protocol {expected}"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. plan_cpuset_is_passed
// ---------------------------------------------------------------------------

#[test]
fn plan_cpuset_is_passed() {
    let mut nh = base_nighthawk();
    nh.client_cores = "4-7,9".to_owned();
    let invocation = nh
        .plan(&base_cell(), &base_target(), &base_run())
        .expect("plans");
    assert!(find_subsequence(&invocation.args, &["--cpuset-cpus", "4-7,9"]).is_some());
}

// ---------------------------------------------------------------------------
// 7. from_pin_rejects_tag
// ---------------------------------------------------------------------------

#[test]
fn from_pin_rejects_tag() {
    let dir = DigestDir::new();
    let path = dir.write("latest\n");
    let err = Nighthawk::from_pin(
        ContainerRuntime::Docker,
        &path,
        "envoyproxy/nighthawk-dev",
        "0-3",
    )
    .expect_err("a mutable tag is not a digest");
    expect_parse_detail(&err);
}

// ---------------------------------------------------------------------------
// 8. from_pin_rejects_two_lines
// ---------------------------------------------------------------------------

#[test]
fn from_pin_rejects_two_lines() {
    let dir = DigestDir::new();
    let digest = valid_digest_body();
    let content = format!("sha256:{digest}\nsha256:{digest}\n");
    let path = dir.write(&content);
    let err = Nighthawk::from_pin(
        ContainerRuntime::Docker,
        &path,
        "envoyproxy/nighthawk-dev",
        "0-3",
    )
    .expect_err("two lines is not one digest");
    expect_parse_detail(&err);
}

// ---------------------------------------------------------------------------
// 9. from_pin_trims_whitespace
// ---------------------------------------------------------------------------

#[test]
fn from_pin_trims_whitespace() {
    let dir = DigestDir::new();
    let digest = valid_digest_body();
    let content = format!("  sha256:{digest}\n");
    let path = dir.write(&content);
    let nh = Nighthawk::from_pin(
        ContainerRuntime::Docker,
        &path,
        "envoyproxy/nighthawk-dev",
        "0-3",
    )
    .expect("leading spaces and a trailing newline must trim clean");
    assert_eq!(
        nh.image,
        format!("envoyproxy/nighthawk-dev@sha256:{digest}")
    );
}

// ---------------------------------------------------------------------------
// 10. parse_fixture_is_exact
// ---------------------------------------------------------------------------

#[test]
fn parse_fixture_is_exact() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let raw = nh
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("the checked-in fixture must parse");
    assert!(raw.latency_exact);
    assert!(raw.stall.is_some());
    assert!(raw.connect.is_some());
    // The fixture's "global" `benchmark_http_client.request_to_response`
    // declares `"count": "10000"`; see tests/fixtures/nighthawk-output.json.
    assert_eq!(raw.latency.len(), 10_000);
}

// ---------------------------------------------------------------------------
// 11. parse_selects_global_result
// ---------------------------------------------------------------------------

#[test]
fn parse_selects_global_result() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // Three result entries; "global" is neither first nor last, and picking
    // the first entry would silently report a worker's own numbers.
    let doc = make_document(&[
        make_minimal_result("worker_0"),
        make_global_result(),
        make_minimal_result("worker_1"),
    ]);
    let raw = nh
        .parse(&ctx, &doc, b"")
        .expect("a document with a \"global\" entry among three must parse");
    assert_eq!(raw.requests_sent, 1000);

    // No "global" entry at all: Err(Parse) listing the available names.
    let doc_no_global = make_document(&[
        make_minimal_result("worker_0"),
        make_minimal_result("worker_1"),
    ]);
    let err = nh
        .parse(&ctx, &doc_no_global, b"")
        .expect_err("no \"global\" entry cannot parse");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("worker_0"), "{detail}");
    assert!(detail.contains("worker_1"), "{detail}");
}

// ---------------------------------------------------------------------------
// 12. parse_requires_sequencer_blocking
// ---------------------------------------------------------------------------

#[test]
fn parse_requires_sequencer_blocking() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    remove_statistic(&mut global, "sequencer.blocking");
    let doc = make_document(&[global]);
    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("a Nighthawk run with no sequencer.blocking statistic must not parse");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("sequencer.blocking"), "{detail}");
}

// ---------------------------------------------------------------------------
// 13. parse_rejects_short_percentile_list
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_short_percentile_list() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    let short = make_statistic("benchmark_http_client.request_to_response", 63, 1000);
    replace_statistic(
        &mut global,
        "benchmark_http_client.request_to_response",
        short,
    );
    let doc = make_document(&[global]);
    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("63 entries is one short of MIN_PERCENTILE_ENTRIES (64)");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("63"), "{detail}");
    assert!(
        detail.contains(&MIN_PERCENTILE_ENTRIES.to_string()),
        "{detail}"
    );
}

// ---------------------------------------------------------------------------
// 14. parse_rejects_long_percentile_list
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_long_percentile_list() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    let long = make_statistic("benchmark_http_client.request_to_response", 5000, 1000);
    replace_statistic(
        &mut global,
        "benchmark_http_client.request_to_response",
        long,
    );
    let doc = make_document(&[global]);

    // `std::time::Instant` is used here, not through the `irontraffic-time`
    // seam: this file is an integration test under `tests/`, outside the
    // scope `scripts/invariant-lints.sh`'s determinism-seam rule scans
    // (`rust_non_test_files` excludes every path under `tests/`), and this
    // measures the TEST's own wall-clock budget for a bound the issue's own
    // acceptance criteria ask for, not a request-path read.
    let start = std::time::Instant::now();
    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("5,000 entries is past MAX_PERCENTILE_ENTRIES (4,096)");
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "parsing an oversized percentile list took {elapsed:?}, expected well under 1s"
    );
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("5000"), "{detail}");
    assert!(
        detail.contains(&MAX_PERCENTILE_ENTRIES.to_string()),
        "{detail}"
    );
}

// ---------------------------------------------------------------------------
// 15. parse_duration_forms
// ---------------------------------------------------------------------------

#[test]
fn parse_duration_forms() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // `execution_duration` is parsed by the exact same integer-only
    // `parse_protobuf_duration` routine every percentile `duration` string
    // is, and it is a single scalar field rather than a percentile array
    // entry, which is what lets this test observe the parsed nanosecond
    // value directly through `RawRun::duration_ns` without needing a
    // 64-row percentile list for every case.
    let valid_cases: [(&str, u64); 3] = [
        ("0.000123s", 123_000),
        ("1s", 1_000_000_000),
        ("0.1234567891s", 123_456_789),
    ];
    for (duration_str, expected_ns) in valid_cases {
        let mut global = make_global_result();
        set_field(&mut global, "execution_duration", json!(duration_str));
        let doc = make_document(&[global]);
        let raw = nh
            .parse(&ctx, &doc, b"")
            .unwrap_or_else(|e| panic!("{duration_str:?} must parse: {e}"));
        assert_eq!(raw.duration_ns, expected_ns, "duration {duration_str:?}");
    }

    // The four float-shaped inputs below ("nans", "infs", "-1s", "1e309s")
    // are ALL accepted by `str::parse::<f64>` once the trailing `s` is
    // stripped ("nan", "inf", "-1", "1e309" are all valid float literals),
    // and `NaN as u64` is 0 in Rust while `inf` saturates: exactly why this
    // parser never routes a duration through `f64`. "123ms" and "1m3s" are
    // not `<digits>[.<digits>]s` at all. "90000s" is a plain, well-formed
    // integer duration string that exceeds MAX_DURATION_SECONDS (86,400).
    let invalid_cases = ["123ms", "1m3s", "nans", "infs", "-1s", "1e309s", "90000s"];
    for duration_str in invalid_cases {
        let mut global = make_global_result();
        set_field(&mut global, "execution_duration", json!(duration_str));
        let doc = make_document(&[global]);
        match nh.parse(&ctx, &doc, b"") {
            Ok(_) => panic!("{duration_str:?} must not parse"),
            Err(e) => {
                let _ = expect_parse_detail(&e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 16. plan_carries_the_hardening_flags
// ---------------------------------------------------------------------------

#[test]
fn plan_carries_the_hardening_flags() {
    let invocation = base_invocation();
    assert!(find_subsequence(&invocation.args, &["--cap-drop", "ALL"]).is_some());
    assert!(find_subsequence(&invocation.args, &["--security-opt", "no-new-privileges"]).is_some());
    assert!(invocation.args.iter().any(|a| a == "--read-only"));
    assert!(find_subsequence(&invocation.args, &["--memory", "4g"]).is_some());
    assert!(find_subsequence(&invocation.args, &["--pids-limit", "4096"]).is_some());
    assert!(!invocation.args.iter().any(|a| a == "--privileged"));
    assert!(!invocation.args.iter().any(|a| a == "-v"));
    assert!(!invocation.args.iter().any(|a| a == "--volume"));
}

// ---------------------------------------------------------------------------
// 17. from_pin_rejects_flag_shaped_fields
// ---------------------------------------------------------------------------

#[test]
fn from_pin_rejects_flag_shaped_fields() {
    let dir = DigestDir::new();
    let digest = valid_digest_body();
    let path = dir.write(&format!("sha256:{digest}\n"));

    // The image name sits in the argument position where the container
    // runtime stops parsing flags: a value beginning with `-` is read as a
    // FLAG, and the next literal token (`nighthawk_client`) becomes the
    // image name instead.
    let oversized = "a".repeat(300);
    let bad_image_repos = ["--privileged", "-v", ".hidden", oversized.as_str()];
    for repo in bad_image_repos {
        match Nighthawk::from_pin(ContainerRuntime::Docker, &path, repo, "0-3") {
            Ok(_) => panic!("image_repo {repo:?} must be rejected"),
            Err(e) => {
                let detail = expect_parse_detail(&e);
                assert!(detail.contains("image_repo"), "{repo:?}: {detail}");
            }
        }
    }

    // `--cpuset-cpus`'s VALUE position: a leading `-` is read as the NEXT
    // flag rather than as `--cpuset-cpus`'s own argument.
    let bad_client_cores = ["--privileged", "0-3; rm -rf /", ""];
    for cores in bad_client_cores {
        match Nighthawk::from_pin(
            ContainerRuntime::Docker,
            &path,
            "envoyproxy/nighthawk-dev",
            cores,
        ) {
            Ok(_) => panic!("client_cores {cores:?} must be rejected"),
            Err(e) => {
                let detail = expect_parse_detail(&e);
                assert!(detail.contains("client_cores"), "{cores:?}: {detail}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 18. parse_rejects_absurd_statistic_count
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_absurd_statistic_count() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // A statistic whose final cumulative count exceeds MAX_REPORTED_REQUESTS.
    let mut absurd_counts: Vec<u64> = vec![10; 63];
    absurd_counts.push(MAX_REPORTED_REQUESTS + 1);
    let mut global = make_global_result();
    let absurd = make_statistic_with_counts(
        "benchmark_http_client.request_to_response",
        &absurd_counts,
        MAX_REPORTED_REQUESTS + 1,
    );
    replace_statistic(
        &mut global,
        "benchmark_http_client.request_to_response",
        absurd,
    );
    let doc = make_document(&[global]);
    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("a statistic count past MAX_REPORTED_REQUESTS must not parse");
    let _ = expect_parse_detail(&err);

    // A statistic whose percentile counts decrease partway through.
    let mut decreasing_counts: Vec<u64> = vec![200, 50];
    decreasing_counts.extend(std::iter::repeat_n(200, 62));
    let mut global2 = make_global_result();
    let decreasing = make_statistic_with_counts(
        "benchmark_http_client.request_to_response",
        &decreasing_counts,
        200,
    );
    replace_statistic(
        &mut global2,
        "benchmark_http_client.request_to_response",
        decreasing,
    );
    let doc2 = make_document(&[global2]);
    let err2 = nh
        .parse(&ctx, &doc2, b"")
        .expect_err("decreasing percentile counts must not parse");
    let _ = expect_parse_detail(&err2);
}

// ---------------------------------------------------------------------------
// 19. parse_rejects_oversized_lists
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_oversized_lists() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // 300 result entries: past MAX_RESULT_ENTRIES (256), checked before this
    // parser ever looks for a "global" name among them.
    let mut results = Vec::with_capacity(300);
    for i in 0..300 {
        results.push(make_minimal_result(&format!("worker_{i}")));
    }
    let doc = make_document(&results);
    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("300 result entries is past MAX_RESULT_ENTRIES");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("MAX_RESULT_ENTRIES"), "{detail}");

    // 40 statistics: past MAX_STATISTICS (32).
    let mut global = make_global_result();
    let mut extra_statistics: Vec<Value> = Vec::with_capacity(40);
    for i in 0..40 {
        extra_statistics.push(make_statistic(&format!("noise.{i}"), 64, 10));
    }
    set_field(&mut global, "statistics", Value::Array(extra_statistics));
    let doc = make_document(&[global]);
    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("40 statistics is past MAX_STATISTICS");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("MAX_STATISTICS"), "{detail}");

    // 600 counters: past MAX_COUNTERS (512).
    let mut global2 = make_global_result();
    let mut extra_counters: Vec<Value> = Vec::with_capacity(600);
    for i in 0..600 {
        extra_counters.push(make_counter(&format!("noise.{i}"), 1));
    }
    set_field(&mut global2, "counters", Value::Array(extra_counters));
    let doc2 = make_document(&[global2]);
    let err2 = nh
        .parse(&ctx, &doc2, b"")
        .expect_err("600 counters is past MAX_COUNTERS");
    let detail2 = expect_parse_detail(&err2);
    assert!(detail2.contains("MAX_COUNTERS"), "{detail2}");
}

// ---------------------------------------------------------------------------
// 20. parse_rejects_a_latency_count_inconsistent_with_requests_sent
//
// Not one of the issue's own 19 named tests: it pins the extra cross-check
// `Nighthawk::parse`'s own doc explains is needed so the reconstructed
// latency sample count can never exceed `requests_sent` by more than the
// shared fuzz harness's own slack. That harness (`fuzz_loadgen_json.rs`) was
// run for 200,000 iterations with this exact check REMOVED, from an empty
// corpus, and found no crash either way: a fixed, internally-consistent
// valid stdout on the stderr-path can never exhibit the mismatch (it is
// consistent by construction), and reconstructing a whole 64-plus-row valid
// document with a MISMATCHED counter from arbitrary mutated bytes, unseeded,
// is exactly the low-reachability shape this milestone's own review process
// has caught before. This test is the deterministic proof the fuzz run
// could not honestly provide: watched to fail with the check removed
// (confirmed directly, not inferred from fuzz silence), it demonstrates the
// check is reachable and load-bearing rather than dead code.
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_a_latency_count_inconsistent_with_requests_sent() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // A well-formed, internally reconciling `request_to_response` statistic
    // (64 rows, ending exactly at a declared count of 100) paired with
    // counters that report only 5 requests sent: every OTHER check this
    // parser performs is individually satisfied (the percentile ladder is
    // strictly increasing, non-decreasing, and reconciles to its own
    // declared count; the counters sum to themselves consistently), so only
    // the requests_sent cross-check can reject this document.
    let mut global = make_global_result();
    let mismatched = make_statistic("benchmark_http_client.request_to_response", 64, 100);
    replace_statistic(
        &mut global,
        "benchmark_http_client.request_to_response",
        mismatched,
    );
    set_field(
        &mut global,
        "counters",
        Value::Array(vec![
            make_counter("upstream_rq_total", 5),
            make_counter("benchmark.http_2xx", 5),
            make_counter("benchmark.pool_connection_failure", 0),
            make_counter("benchmark.stream_resets", 0),
            make_counter("upstream_cx_rx_bytes_total", 65),
        ]),
    );
    let doc = make_document(&[global]);
    let err = nh.parse(&ctx, &doc, b"").expect_err(
        "a reconstructed latency count of 100 against requests_sent of 5 must not parse",
    );
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("requests_sent"), "{detail}");
}

// ---------------------------------------------------------------------------
// Fix for PR 812's BLOCKING 1: the MIN_PERCENTILE_ENTRIES floor is now
// applied only to the statistic that sets latency_exact
// (request_to_response). These two tests are the direct demonstration: each
// is watched to FAIL against the OLD uniform floor (5 rows and 3 rows are
// both well short of MIN_PERCENTILE_ENTRIES's 64) and to PASS now that the
// floor is scoped to latency alone. See nighthawk.rs's module doc, "the
// floor is LATENCY-only" section.
// ---------------------------------------------------------------------------

#[test]
fn parse_low_blocking_run_is_ok() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // A healthy open-loop run is DEFINED by having little or no
    // coordinated-omission blocking, so sequencer.blocking legitimately
    // carries far fewer rows than a busy statistic: an HdrHistogram
    // percentile iterator cannot emit more distinct rows than it recorded
    // samples. 5 rows for 5 samples is the fully-saturated case (every
    // sample its own distinct duration).
    let mut global = make_global_result();
    let healthy_blocking = make_statistic("sequencer.blocking", 5, 5);
    replace_statistic(&mut global, "sequencer.blocking", healthy_blocking);
    let doc = make_document(&[global]);

    let raw = nh.parse(&ctx, &doc, b"").expect(
        "a healthy, low-blocking run must still parse: near-zero blocking is what a \
                 healthy open-loop run looks like, not a reason to discard the latency it \
                 measured",
    );
    assert!(raw.latency_exact);
    let stall = raw
        .stall
        .expect("sequencer.blocking must still be present and reconstructed");
    assert_eq!(stall.len(), 5);
}

#[test]
fn parse_low_connect_sample_run_is_ok() {
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // A `Both`-keepalive cell that reuses connections may legitimately open
    // very few of them relative to the request count; queue_to_connect does
    // not set latency_exact, so it carries the same NotEnforced floor as
    // sequencer.blocking, for the same reason.
    let mut global = make_global_result();
    let few_connects = make_statistic("benchmark_http_client.queue_to_connect", 3, 3);
    replace_statistic(
        &mut global,
        "benchmark_http_client.queue_to_connect",
        few_connects,
    );
    let doc = make_document(&[global]);

    let raw = nh
        .parse(&ctx, &doc, b"")
        .expect("a run that opened only 3 connections under connection reuse must still parse");
    let connect = raw
        .connect
        .expect("queue_to_connect must still be present and reconstructed");
    assert_eq!(connect.len(), 3);
}

// ---------------------------------------------------------------------------
// SHOULD_FIX: named invariants 3 and 4, and latency_trustworthy, had zero
// test coverage in either direction (PR 813 finding 5 / review item 5).
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_statistic_count_mismatch() {
    // Isolates invariant 4 (`assert_eq!(reconstructed.len(), statistic.count)`)
    // from the separate requests_sent cross-check
    // `parse_rejects_a_latency_count_inconsistent_with_requests_sent`
    // exercises: this uses sequencer.blocking, which has no requests_sent
    // cross-check at all, so ONLY the statistic's own internal reconciliation
    // can reject this document.
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    // Percentiles reconcile to 5, but the statistic declares "count": "999".
    let mismatched = make_statistic_with_counts("sequencer.blocking", &[1, 2, 3, 4, 5], 999);
    replace_statistic(&mut global, "sequencer.blocking", mismatched);
    let doc = make_document(&[global]);

    let err = nh.parse(&ctx, &doc, b"").expect_err(
        "a statistic whose declared count disagrees with its own reconstructed percentile \
         ladder must not parse",
    );
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("reconstructed count"), "{detail}");
    assert!(
        detail.contains("does not equal the declared count"),
        "{detail}"
    );
}

#[test]
fn parse_requires_connect_for_downstream_close() {
    // Invariant 3, the DownstreamClose-required direction. No existing test
    // mentioned KeepaliveMode::DownstreamClose at all before this one.
    let nh = base_nighthawk();
    let mut cell = base_cell();
    cell.keepalive = KeepaliveMode::DownstreamClose;
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    remove_statistic(&mut global, "benchmark_http_client.queue_to_connect");
    let doc = make_document(&[global]);

    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("a DownstreamClose cell with no queue_to_connect statistic must not parse");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("DownstreamClose"), "{detail}");
}

#[test]
fn parse_allows_missing_connect_for_both_keepalive() {
    // Invariant 3, the OTHER direction: `Both` keepalive must NOT require
    // queue_to_connect. `parse_fixture_is_exact` only ever exercises the
    // fixture, which always carries queue_to_connect, so this direction of
    // the invariant had no coverage either.
    let nh = base_nighthawk();
    let cell = base_cell(); // KeepaliveMode::Both
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    remove_statistic(&mut global, "benchmark_http_client.queue_to_connect");
    let doc = make_document(&[global]);

    let raw = nh
        .parse(&ctx, &doc, b"")
        .expect("Both keepalive must tolerate a missing queue_to_connect statistic");
    assert!(raw.connect.is_none());
}

#[test]
fn parse_latency_trustworthy_for_fixed_rate() {
    let nh = base_nighthawk();
    let mut cell = base_cell();
    cell.rate = RateMode::Fixed(50_000);
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let raw = nh
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("the checked-in fixture must parse");
    assert!(
        raw.latency_trustworthy,
        "a fixed-rate, open-loop run's latency must be trustworthy"
    );
}

#[test]
fn parse_latency_untrustworthy_for_saturate() {
    let nh = base_nighthawk();
    let mut cell = base_cell();
    cell.rate = RateMode::Saturate;
    // `ctx.invocation` is not consulted by `parse` for `latency_trustworthy`
    // (only `ctx.cell.rate` is), so reusing the fixed-rate `base_invocation`
    // here changes nothing about what this test proves.
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let raw = nh
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("the checked-in fixture must parse regardless of rate mode");
    assert!(
        !raw.latency_trustworthy,
        "saturate mode is a throughput measurement, not a trustworthy latency one"
    );
}

// ---------------------------------------------------------------------------
// SHOULD_FIX: only the sha256: prefix of the digest shape was tested; exact
// length, hex class and lowercase-only each survived mutation (PR 813
// finding 6 / review item 6).
// ---------------------------------------------------------------------------

#[test]
fn from_pin_rejects_malformed_digest_shapes() {
    let dir = DigestDir::new();
    let digest64 = valid_digest_body();

    let cases: [(&str, String); 4] = [
        (
            "63 hex digits: one short of the exact 64",
            digest64[..63].to_owned(),
        ),
        (
            "65 hex digits: one past the exact 64",
            format!("{digest64}a"),
        ),
        (
            "64 characters but the last is not a hex digit",
            format!("{}g", &digest64[..63]),
        ),
        ("64 hex digits but uppercase", digest64.to_uppercase()),
    ];
    for (label, body) in cases {
        let path = dir.write(&format!("sha256:{body}\n"));
        match Nighthawk::from_pin(
            ContainerRuntime::Docker,
            &path,
            "envoyproxy/nighthawk-dev",
            "0-3",
        ) {
            Ok(_) => panic!("{label}: must be rejected"),
            Err(e) => {
                let _ = expect_parse_detail(&e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SHOULD_FIX: version_invocation carried the digest but none of the five
// hardening flags plan carries (PR 813 finding 4 / review item 4).
// ---------------------------------------------------------------------------

#[test]
fn version_invocation_carries_the_hardening_flags() {
    let invocation = base_nighthawk().version_invocation();
    assert_eq!(invocation.program, "docker");
    assert!(find_subsequence(&invocation.args, &["--cap-drop", "ALL"]).is_some());
    assert!(find_subsequence(&invocation.args, &["--security-opt", "no-new-privileges"]).is_some());
    assert!(invocation.args.iter().any(|a| a == "--read-only"));
    assert!(find_subsequence(&invocation.args, &["--memory", "4g"]).is_some());
    assert!(find_subsequence(&invocation.args, &["--pids-limit", "4096"]).is_some());
    assert!(!invocation.args.iter().any(|a| a == "--privileged"));
    assert!(!invocation.args.iter().any(|a| a == "-v"));
    assert!(!invocation.args.iter().any(|a| a == "--volume"));
    // The digest is still carried on this path too.
    assert!(invocation.args.iter().any(|a| a.contains("@sha256:")));
}

// ---------------------------------------------------------------------------
// NOTE: eight further guards survived mutation with no test holding them
// (PR 813 finding 7 / review item 7). Each test below is the direct,
// isolated coverage for one of them.
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_non_monotone_percentiles() {
    // M23 (part 1): a repeated percentile value is not STRICTLY increasing.
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    let bad_stat = json!({
        "id": "sequencer.blocking",
        "count": "10",
        "percentiles": [
            {"percentile": 0.5, "count": "4", "duration": "0.000004000s"},
            {"percentile": 0.5, "count": "10", "duration": "0.000005000s"},
        ],
    });
    replace_statistic(&mut global, "sequencer.blocking", bad_stat);
    let doc = make_document(&[global]);

    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("a repeated percentile value must not parse");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("strictly increasing"), "{detail}");
}

// M23's `is_finite()` guard (documented in `nighthawk.rs` as protection
// against a NaN percentile) has NO dedicated test here, and deliberately so:
// I confirmed by execution that it cannot be reached through untrusted
// bytes at all in this crate's current configuration. JSON's own grammar has
// no NaN literal, and an out-of-range magnitude such as `1e400` (which, if
// silently converted, would be the one route to `f64::INFINITY`) is instead
// rejected by `serde_json::from_slice` itself, one layer before this parser
// ever runs (`serde_json::Error` "number out of range"), confirmed against
// this exact crate's dependency tree (`serde_json` without the
// `arbitrary_precision` feature, which is not enabled anywhere in this
// workspace's `Cargo.lock`). The check is retained as defence in depth
// against a future dependency change that defers that bound to `.as_f64()`
// instead of enforcing it at parse time, not because it is reachable today;
// `parse_rejects_non_monotone_percentiles` below is the real, reachable
// coverage for the comparison itself.

#[test]
fn parse_rejects_decreasing_percentile_durations() {
    // M24: a duration that decreases between two consecutive rows.
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    let bad_stat = json!({
        "id": "sequencer.blocking",
        "count": "10",
        "percentiles": [
            {"percentile": 0.5, "count": "4", "duration": "0.000005000s"},
            {"percentile": 0.9, "count": "10", "duration": "0.000004000s"},
        ],
    });
    replace_statistic(&mut global, "sequencer.blocking", bad_stat);
    let doc = make_document(&[global]);

    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("a decreasing duration must not parse");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("non-decreasing"), "{detail}");
}

#[test]
fn parse_rejects_per_entry_count_over_max_isolated() {
    // M21 / invariant 9, isolated from the separate requests_sent
    // cross-check `parse_rejects_absurd_statistic_count` actually triggers
    // (that test's own absurd count is compensated by the +4-slack
    // requests_sent check, so it does not isolate this one, per PR 813
    // finding 7). requests_sent is set to exactly MAX_REPORTED_REQUESTS (the
    // largest value the requests_sent check itself allows), and the
    // statistic's final count is MAX_REPORTED_REQUESTS + 1 (the smallest
    // value invariant 9 can catch): MAX_REPORTED_REQUESTS + 1 does not
    // exceed requests_sent (MAX_REPORTED_REQUESTS) + 4, so only invariant 9
    // itself can reject this document.
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let over_max = MAX_REPORTED_REQUESTS + 1;
    let counts = count_ladder(64, over_max);
    let mut global = make_global_result();
    let absurd = make_statistic_with_counts(
        "benchmark_http_client.request_to_response",
        &counts,
        over_max,
    );
    replace_statistic(
        &mut global,
        "benchmark_http_client.request_to_response",
        absurd,
    );
    set_field(
        &mut global,
        "counters",
        Value::Array(vec![
            make_counter("upstream_rq_total", MAX_REPORTED_REQUESTS),
            make_counter("benchmark.http_2xx", MAX_REPORTED_REQUESTS),
            make_counter("benchmark.pool_connection_failure", 0),
            make_counter("benchmark.stream_resets", 0),
            make_counter("upstream_cx_rx_bytes_total", 1),
        ]),
    );
    let doc = make_document(&[global]);

    let err = nh.parse(&ctx, &doc, b"").expect_err(
        "a percentile entry claiming more than MAX_REPORTED_REQUESTS samples must not parse, \
         even when requests_sent is large enough that the separate requests_sent cross-check \
         cannot catch it",
    );
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("MAX_REPORTED_REQUESTS"), "{detail}");
}

#[test]
fn parse_rejects_inconsistent_counters() {
    // M36: the u128 counter-consistency guard, which also prevents the
    // `requests_sent - accounted` subtraction from underflowing.
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    set_field(
        &mut global,
        "counters",
        Value::Array(vec![
            make_counter("upstream_rq_total", 1000),
            make_counter("benchmark.http_2xx", 1000),
            make_counter("benchmark.pool_connection_failure", 500),
            make_counter("benchmark.stream_resets", 0),
            make_counter("upstream_cx_rx_bytes_total", 130_000),
        ]),
    );
    let doc = make_document(&[global]);

    let err = nh.parse(&ctx, &doc, b"").expect_err(
        "responses_ok (1000) plus errors (500) exceeding requests_sent (1000) must not parse",
    );
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("counters are inconsistent"), "{detail}");
}

#[test]
fn parse_rejects_oversized_stdout() {
    // Edge case 16 / M40: the byte cap is checked on the slice length
    // BEFORE any deserialisation, so this is not valid JSON at all.
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let oversized = vec![b'a'; MAX_TOOL_OUTPUT_BYTES + 1];
    let err = nh
        .parse(&ctx, &oversized, b"")
        .expect_err("stdout past MAX_TOOL_OUTPUT_BYTES must not parse");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("MAX_TOOL_OUTPUT_BYTES"), "{detail}");
}

#[test]
fn parse_rejects_zero_execution_duration() {
    // M39: `"0s"` parses cleanly as a protobuf Duration (0 nanoseconds) but
    // is rejected by the SEPARATE zero-duration guard in `parse` itself.
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut global = make_global_result();
    set_field(&mut global, "execution_duration", json!("0s"));
    let doc = make_document(&[global]);

    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("a zero execution_duration must not parse");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("zero duration_ns"), "{detail}");
}

#[test]
fn parse_rejects_empty_output() {
    // Edge case 4 / M37.
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let err = nh
        .parse(&ctx, b"", b"")
        .expect_err("empty stdout must not parse");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("empty output"), "{detail}");
}

#[test]
fn parse_rejects_empty_results() {
    // Edge case 5 / M38.
    let nh = base_nighthawk();
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let doc = make_document(&[]);
    let err = nh
        .parse(&ctx, &doc, b"")
        .expect_err("a results array with no entries is not a run");
    let detail = expect_parse_detail(&err);
    assert!(detail.contains("results is empty"), "{detail}");
}

// ---------------------------------------------------------------------------
// Property test.
// ---------------------------------------------------------------------------

proptest::proptest! {
    #[test]
    fn reconstruction_preserves_count_and_monotonicity(
        entries in 64_usize..=512_usize,
        total in 1_u64..=1_000_000_u64,
    ) {
        let nh = base_nighthawk();
        let cell = base_cell();
        let invocation = base_invocation();
        let tool = base_tool_stamp();
        let ctx = ParseCtx {
            cell: &cell,
            invocation: &invocation,
            tool: &tool,
        };

        let counts = count_ladder(entries, total);
        let statistic = make_statistic_with_counts(
            "benchmark_http_client.request_to_response",
            &counts,
            total,
        );
        let doc = make_document_with_latency_statistic(&statistic, total);

        let raw = nh.parse(&ctx, &doc, b"").expect("a well-formed reconstruction must parse");
        proptest::prop_assert_eq!(raw.latency.len(), total);
        let p = raw.latency.percentiles();
        proptest::prop_assert!(p.p50_ns <= p.p90_ns);
        proptest::prop_assert!(p.p90_ns <= p.p99_ns);
        proptest::prop_assert!(p.p99_ns <= p.p999_ns);
        proptest::prop_assert!(p.p999_ns <= p.p9999_ns);
        proptest::prop_assert!(p.p9999_ns <= p.max_ns);
    }
}
