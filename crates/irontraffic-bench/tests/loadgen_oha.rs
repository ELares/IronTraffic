// SPDX-License-Identifier: MIT OR Apache-2.0
//! Command-line and parser tests for the `oha` adapter (issue #411).
//!
//! # What these tests do and do NOT prove
//!
//! `tests/fixtures/oha-1.15.0.json` is a REAL capture: `oha 1.15.0` (the
//! exact pinned version, installed with `cargo install oha --version 1.15.0
//! --locked`) run with `--no-tui --output-format json -c 8 -q 200
//! --latency-correction -z 3s` against a local Python `http.server` echoing a
//! 13 byte body, not hand-written. `parse_fixture` is the authority on the
//! exact field spellings (`summary.total`, `summary.totalData`,
//! `statusCodeDistribution`, `errorDistribution`, `latencyPercentiles`) this
//! parser assumes.
//!
//! Every other parser test (11 through 18) builds its own SYNTHETIC JSON
//! text rather than mutating the real fixture, because a hostile-input test
//! needs to isolate exactly one violated rule, and the real fixture's own
//! shape (an `"aborted due to deadline"` error entry, nine percentile
//! points) is not itself the thing under test in those cases.
//!
//! Two honestly-documented gaps, found while writing these tests:
//!
//! 1. `parse_rejects_non_finite_duration` (test 16) asks for `summary.total`
//!    of `nan` and `Infinity` to be rejected. Standard JSON has no literal
//!    for either, and `serde_json` (this crate's exact pinned version,
//!    1.0.151, confirmed by direct experiment) refuses `NaN`/`Infinity` as a
//!    TOKENIZER-level syntax error before a `Value` is ever built, and
//!    separately refuses any number literal whose magnitude would not fit a
//!    finite `f64` (`1e400` is "number out of range", not `Infinity`) for
//!    the same reason. Every sub-case in test 16 still returns
//!    `Err(BenchError::Parse)` as required, but the `nan`/`Infinity`
//!    sub-cases are caught by `serde_json`'s own JSON-syntax validation, NOT
//!    by this parser's `is_finite()` guard; only `-1.0`, `1e30` and `0.0`
//!    exercise that guard directly. Both are asserted on their OWN detail
//!    text below specifically so this distinction is pinned rather than
//!    hidden behind a shared `matches!(.., BenchError::Parse { .. })`.
//! 2. Edge case 10 in issue #411 asks that a stderr rate-warning line be
//!    "included in `RawRun`'s debug output". `RawRun`'s Public API, given
//!    verbatim by the issue, has no field to carry it; see the doc comment
//!    on `latency_trustworthy`'s computation in `src/loadgen/oha.rs`. This
//!    is treated as unsatisfiable as worded rather than silently narrowed:
//!    `stderr_rate_warning_marks_untrustworthy` below verifies the part that
//!    IS expressible (`latency_trustworthy` goes false), not the debug
//!    output claim.
//!
//! `FIXTURE_N1_BYTES` through `FIXTURE_N100_BYTES`, declared just below
//! `FIXTURE_BYTES`, are five more genuine `oha 1.15.0` captures (same
//! binary, same method: `--no-tui --output-format json -c 1 -n N` against a
//! local Python `http.server`), one per `-n` value, at the exact sizes PR
//! 799 round three's own review measured. They are embedded INLINE rather
//! than as separate files under `tests/fixtures/`, unlike `FIXTURE_BYTES`:
//! issue #411's own `## Files` table declares `tests/fixtures/oha-1.15.0.json`
//! as one exact path, not a directory, and `scripts/pr-scope-check.sh`
//! enforces that table literally, so a new file under `tests/fixtures/`
//! would fail the scope check this fix must still pass.
//! `parse_pins_sample_count_against_requests_sent_for_genuine_captures`
//! below is the regression test issue #804 asked for: it reads
//! `raw.latency.len()` and pins it against `raw.requests_sent` for each,
//! which no test before this one did.

use std::net::SocketAddr;

use irontraffic_bench::{
    BenchCell, BenchError, CacheMode, CellId, Invocation, KeepaliveMode, LoadGenerator,
    MAX_REPORTED_REQUESTS, MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_STDERR_BYTES, MAX_VERSION_OUTPUT_BYTES,
    Oha, ParseCtx, PathCorpus, Protocol, RateMode, RunParams, Scheme, Target, TlsMode, ToolStamp,
    Unsupported,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

/// A real `oha 1.15.0` JSON capture. See the module doc for exactly how it
/// was produced.
const FIXTURE_BYTES: &[u8] = include_bytes!("fixtures/oha-1.15.0.json");

/// Five more genuine `oha 1.15.0` captures, one per `-n` value, in ascending
/// order, embedded inline (rather than as separate files under
/// `tests/fixtures/`) because issue #411's own `## Files` table declares
/// `tests/fixtures/oha-1.15.0.json` as a single exact path, not a directory,
/// and `scripts/pr-scope-check.sh` enforces that table literally: a NEW file
/// under `tests/fixtures/` would fail the scope check this PR must still pass.
/// Each constant is the FULL document the pinned binary printed (every
/// top-level and summary key), captured the same way as `FIXTURE_BYTES`
/// above: `oha --no-tui --output-format json -c 1 -n N` against a local
/// Python `http.server`, not hand-written or hand-trimmed. See
/// `parse_accepts_a_genuine_single_request_oha_capture`'s own doc for why that
/// distinction matters.
const FIXTURE_N1_BYTES: &[u8] = br#"{
  "summary": {
    "successRate": 1.0,
    "total": 0.005214,
    "slowest": 0.002772958,
    "fastest": 0.002772958,
    "average": 0.002772958,
    "requestsPerSec": 191.79133103183736,
    "totalData": 13,
    "sizePerRequest": 13,
    "sizePerSec": 2493.2873034138856
  },
  "metrics": {
    "success_rate": 1.0,
    "requests_per_sec": 191.79133103183736,
    "latency_ms": {
      "min": 2.773,
      "mean": 2.773,
      "p50": 2.773,
      "p95": 2.773,
      "p99": 2.773,
      "max": 2.773
    }
  },
  "responseTimeHistogram": {
    "0.002772958": 0
  },
  "latencyPercentiles": {
    "p10": 0.002772958,
    "p25": 0.002772958,
    "p50": 0.002772958,
    "p75": 0.002772958,
    "p90": 0.002772958,
    "p95": 0.002772958,
    "p99": 0.002772958,
    "p99.9": 0.002772958,
    "p99.99": 0.002772958
  },
  "firstByteHistogram": {
    "0.002772541": 0
  },
  "firstBytePercentiles": {
    "p10": 0.002772541,
    "p25": 0.002772541,
    "p50": 0.002772541,
    "p75": 0.002772541,
    "p90": 0.002772541,
    "p95": 0.002772541,
    "p99": 0.002772541,
    "p99.9": 0.002772541,
    "p99.99": 0.002772541
  },
  "rps": {
    "mean": 203.22795083428122,
    "stddev": null,
    "max": 203.22795083428122,
    "min": 203.22795083428122,
    "percentiles": {
      "p10": 203.22795083428122,
      "p25": 203.22795083428122,
      "p50": 203.22795083428122,
      "p75": 203.22795083428122,
      "p90": 203.22795083428122,
      "p95": 203.22795083428122,
      "p99": 203.22795083428122,
      "p99.9": 203.22795083428122,
      "p99.99": 203.22795083428122
    }
  },
  "details": {
    "DNSDialup": {
      "average": 0.000757541,
      "fastest": 0.000757541,
      "slowest": 0.000757541
    },
    "DNSLookup": {
      "average": 0.000171125,
      "fastest": 0.000171125,
      "slowest": 0.000171125
    },
    "firstByte": {
      "average": 0.002772541,
      "fastest": 0.002772541,
      "slowest": 0.002772541
    }
  },
  "statusCodeDistribution": {
    "200": 1
  },
  "errorDistribution": {}
}"#;

const FIXTURE_N3_BYTES: &[u8] = br#"{
  "summary": {
    "successRate": 1.0,
    "total": 0.001508042,
    "slowest": 0.00066625,
    "fastest": 0.000259958,
    "average": 0.00042777766666666665,
    "requestsPerSec": 1989.3345145559606,
    "totalData": 39,
    "sizePerRequest": 13,
    "sizePerSec": 25861.34868922749
  },
  "metrics": {
    "success_rate": 1.0,
    "requests_per_sec": 1989.3345145559606,
    "latency_ms": {
      "min": 0.26,
      "mean": 0.428,
      "p50": 0.357,
      "p95": 0.666,
      "p99": 0.666,
      "max": 0.666
    }
  },
  "responseTimeHistogram": {
    "0.000259958": 1,
    "0.0003005872": 0,
    "0.0003412164": 0,
    "0.0003818456": 1,
    "0.0004224748": 0,
    "0.000463104": 0,
    "0.0005037332": 0,
    "0.0005443624": 0,
    "0.0005849916": 0,
    "0.0006256208": 0,
    "0.00066625": 1
  },
  "latencyPercentiles": {
    "p10": 0.000259958,
    "p25": 0.000259958,
    "p50": 0.000357125,
    "p75": 0.00066625,
    "p90": 0.00066625,
    "p95": 0.00066625,
    "p99": 0.00066625,
    "p99.9": 0.00066625,
    "p99.99": 0.00066625
  },
  "firstByteHistogram": {
    "0.000259875": 1,
    "0.0003004792": 0,
    "0.00034108340000000003": 0,
    "0.0003816876": 1,
    "0.00042229180000000004": 0,
    "0.000462896": 0,
    "0.0005035002": 0,
    "0.0005441044": 0,
    "0.0005847086": 0,
    "0.0006253128": 0,
    "0.000665917": 1
  },
  "firstBytePercentiles": {
    "p10": 0.000259875,
    "p25": 0.000259875,
    "p50": 0.000356958,
    "p75": 0.000665917,
    "p90": 0.000665917,
    "p95": 0.000665917,
    "p99": 0.000665917,
    "p99.9": 0.000665917,
    "p99.99": 0.000665917
  },
  "rps": {
    "mean": 2082.6102047900035,
    "stddev": null,
    "max": 2082.6102047900035,
    "min": 2082.6102047900035,
    "percentiles": {
      "p10": 2082.6102047900035,
      "p25": 2082.6102047900035,
      "p50": 2082.6102047900035,
      "p75": 2082.6102047900035,
      "p90": 2082.6102047900035,
      "p95": 2082.6102047900035,
      "p99": 2082.6102047900035,
      "p99.9": 2082.6102047900035,
      "p99.99": 2082.6102047900035
    }
  },
  "details": {
    "DNSDialup": {
      "average": 0.00015376366666666665,
      "fastest": 0.000088083,
      "slowest": 0.000237875
    },
    "DNSLookup": {
      "average": 5.7220000000000004e-6,
      "fastest": 1.833e-6,
      "slowest": 0.000013125
    },
    "firstByte": {
      "average": 0.0004275833333333333,
      "fastest": 0.000259875,
      "slowest": 0.000665917
    }
  },
  "statusCodeDistribution": {
    "200": 3
  },
  "errorDistribution": {}
}"#;

const FIXTURE_N5_BYTES: &[u8] = br#"{
  "summary": {
    "successRate": 1.0,
    "total": 0.00211675,
    "slowest": 0.0007535,
    "fastest": 0.000260334,
    "average": 0.0003767916,
    "requestsPerSec": 2362.1117278847287,
    "totalData": 65,
    "sizePerRequest": 13,
    "sizePerSec": 30707.452462501475
  },
  "metrics": {
    "success_rate": 1.0,
    "requests_per_sec": 2362.1117278847287,
    "latency_ms": {
      "min": 0.26,
      "mean": 0.377,
      "p50": 0.265,
      "p95": 0.754,
      "p99": 0.754,
      "max": 0.754
    }
  },
  "responseTimeHistogram": {
    "0.000260334": 1,
    "0.0003096506": 2,
    "0.0003589672": 1,
    "0.0004082838": 0,
    "0.0004576004": 0,
    "0.000506917": 0,
    "0.0005562336": 0,
    "0.0006055502": 0,
    "0.0006548668000000001": 0,
    "0.0007041834000000001": 0,
    "0.0007535": 1
  },
  "latencyPercentiles": {
    "p10": 0.000260334,
    "p25": 0.000262833,
    "p50": 0.000264916,
    "p75": 0.000342375,
    "p90": 0.0007535,
    "p95": 0.0007535,
    "p99": 0.0007535,
    "p99.9": 0.0007535,
    "p99.99": 0.0007535
  },
  "firstByteHistogram": {
    "0.00026025": 1,
    "0.00030953750000000004": 2,
    "0.000358825": 1,
    "0.00040811250000000003": 0,
    "0.00045740000000000006": 0,
    "0.0005066875": 0,
    "0.000555975": 0,
    "0.0006052625": 0,
    "0.00065455": 0,
    "0.0007038375000000001": 0,
    "0.0007531250000000001": 1
  },
  "firstBytePercentiles": {
    "p10": 0.00026025,
    "p25": 0.00026275,
    "p50": 0.000264833,
    "p75": 0.000342167,
    "p90": 0.000753125,
    "p95": 0.000753125,
    "p99": 0.000753125,
    "p99.9": 0.000753125,
    "p99.99": 0.000753125
  },
  "rps": {
    "mean": 2430.9713529473825,
    "stddev": null,
    "max": 2430.9713529473825,
    "min": 2430.9713529473825,
    "percentiles": {
      "p10": 2430.9713529473825,
      "p25": 2430.9713529473825,
      "p50": 2430.9713529473825,
      "p75": 2430.9713529473825,
      "p90": 2430.9713529473825,
      "p95": 2430.9713529473825,
      "p99": 2430.9713529473825,
      "p99.9": 2430.9713529473825,
      "p99.99": 2430.9713529473825
    }
  },
  "details": {
    "DNSDialup": {
      "average": 0.00011186659999999999,
      "fastest": 0.000074625,
      "slowest": 0.000217291
    },
    "DNSLookup": {
      "average": 3.8918e-6,
      "fastest": 9.58e-7,
      "slowest": 0.000013
    },
    "firstByte": {
      "average": 0.000376625,
      "fastest": 0.00026025,
      "slowest": 0.000753125
    }
  },
  "statusCodeDistribution": {
    "200": 5
  },
  "errorDistribution": {}
}"#;

const FIXTURE_N10_BYTES: &[u8] = br#"{
  "summary": {
    "successRate": 1.0,
    "total": 0.003659292,
    "slowest": 0.00071825,
    "fastest": 0.000238125,
    "average": 0.0003426999,
    "requestsPerSec": 2732.7690711755167,
    "totalData": 130,
    "sizePerRequest": 13,
    "sizePerSec": 35525.99792528172
  },
  "metrics": {
    "success_rate": 1.0,
    "requests_per_sec": 2732.7690711755167,
    "latency_ms": {
      "min": 0.238,
      "mean": 0.343,
      "p50": 0.294,
      "p95": 0.718,
      "p99": 0.718,
      "max": 0.718
    }
  },
  "responseTimeHistogram": {
    "0.000238125": 1,
    "0.0002861375": 3,
    "0.00033415": 3,
    "0.00038216249999999997": 1,
    "0.000430175": 0,
    "0.0004781875": 1,
    "0.0005262": 0,
    "0.0005742125": 0,
    "0.000622225": 0,
    "0.0006702375": 0,
    "0.00071825": 1
  },
  "latencyPercentiles": {
    "p10": 0.000247416,
    "p25": 0.000264917,
    "p50": 0.000294041,
    "p75": 0.000340709,
    "p90": 0.00071825,
    "p95": 0.00071825,
    "p99": 0.00071825,
    "p99.9": 0.00071825,
    "p99.99": 0.00071825
  },
  "firstByteHistogram": {
    "0.000237916": 1,
    "0.0002859328": 3,
    "0.0003339496": 3,
    "0.0003819664": 1,
    "0.00042998319999999995": 0,
    "0.000478": 1,
    "0.0005260168": 0,
    "0.0005740335999999999": 0,
    "0.0006220504": 0,
    "0.0006700672": 0,
    "0.000718084": 1
  },
  "firstBytePercentiles": {
    "p10": 0.000247375,
    "p25": 0.000264833,
    "p50": 0.000293916,
    "p75": 0.000340584,
    "p90": 0.000718084,
    "p95": 0.000718084,
    "p99": 0.000718084,
    "p99.9": 0.000718084,
    "p99.99": 0.000718084
  },
  "rps": {
    "mean": 2782.2858537179823,
    "stddev": null,
    "max": 2782.2858537179823,
    "min": 2782.2858537179823,
    "percentiles": {
      "p10": 2782.2858537179823,
      "p25": 2782.2858537179823,
      "p50": 2782.2858537179823,
      "p75": 2782.2858537179823,
      "p90": 2782.2858537179823,
      "p95": 2782.2858537179823,
      "p99": 2782.2858537179823,
      "p99.9": 2782.2858537179823,
      "p99.99": 2782.2858537179823
    }
  },
  "details": {
    "DNSDialup": {
      "average": 0.00009836219999999999,
      "fastest": 0.000060666,
      "slowest": 0.000241959
    },
    "DNSLookup": {
      "average": 2.3624999999999994e-6,
      "fastest": 8.33e-7,
      "slowest": 0.000011334
    },
    "firstByte": {
      "average": 0.0003425791,
      "fastest": 0.000237916,
      "slowest": 0.000718084
    }
  },
  "statusCodeDistribution": {
    "200": 10
  },
  "errorDistribution": {}
}"#;

const FIXTURE_N100_BYTES: &[u8] = br#"{
  "summary": {
    "successRate": 1.0,
    "total": 0.02318275,
    "slowest": 0.000599541,
    "fastest": 0.000179,
    "average": 0.00022863581000000003,
    "requestsPerSec": 4313.552102317456,
    "totalData": 1300,
    "sizePerRequest": 13,
    "sizePerSec": 56076.17733012693
  },
  "metrics": {
    "success_rate": 1.0,
    "requests_per_sec": 4313.552102317456,
    "latency_ms": {
      "min": 0.179,
      "mean": 0.229,
      "p50": 0.218,
      "p95": 0.302,
      "p99": 0.6,
      "max": 0.6
    }
  },
  "responseTimeHistogram": {
    "0.000179": 1,
    "0.00022105409999999997": 51,
    "0.0002631082": 31,
    "0.0003051623": 14,
    "0.00034721639999999994": 2,
    "0.0003892705": 0,
    "0.00043132459999999995": 0,
    "0.0004733786999999999": 0,
    "0.0005154328": 0,
    "0.0005574868999999999": 0,
    "0.000599541": 1
  },
  "latencyPercentiles": {
    "p10": 0.000186333,
    "p25": 0.000195,
    "p50": 0.000218042,
    "p75": 0.000250416,
    "p90": 0.000292833,
    "p95": 0.000302417,
    "p99": 0.000599541,
    "p99.9": 0.000599541,
    "p99.99": 0.000599541
  },
  "firstByteHistogram": {
    "0.000178917": 1,
    "0.0002209586": 51,
    "0.0002630002": 31,
    "0.0003050418": 14,
    "0.0003470834": 2,
    "0.000389125": 0,
    "0.00043116659999999996": 0,
    "0.0004732082": 0,
    "0.0005152498": 0,
    "0.0005572913999999999": 0,
    "0.000599333": 1
  },
  "firstBytePercentiles": {
    "p10": 0.000186291,
    "p25": 0.000195,
    "p50": 0.000217958,
    "p75": 0.000250375,
    "p90": 0.000292625,
    "p95": 0.000302334,
    "p99": 0.000599333,
    "p99.9": 0.000599333,
    "p99.99": 0.000599333
  },
  "rps": {
    "mean": 4540.661028312505,
    "stddev": 756.838594203171,
    "max": 5312.215114019317,
    "min": 3799.450619977922,
    "percentiles": {
      "p10": 3799.450619977922,
      "p25": 3799.450619977922,
      "p50": 4510.317350940276,
      "p75": 5312.215114019317,
      "p90": 5312.215114019317,
      "p95": 5312.215114019317,
      "p99": 5312.215114019317,
      "p99.9": 5312.215114019317,
      "p99.99": 5312.215114019317
    }
  },
  "details": {
    "DNSDialup": {
      "average": 0.00006917209000000001,
      "fastest": 0.000046375,
      "slowest": 0.000196166
    },
    "DNSLookup": {
      "average": 9.125100000000003e-7,
      "fastest": 5.83e-7,
      "slowest": 0.000011125
    },
    "firstByte": {
      "average": 0.00022855544000000008,
      "fastest": 0.000178917,
      "slowest": 0.000599333
    }
  },
  "statusCodeDistribution": {
    "200": 100
  },
  "errorDistribution": {}
}"#;

/// A minimal, individually valid `BenchCell`: fixed rate, H1, TLS off,
/// `SingleHot`, `Both` keepalive. Every field is inside its own valid range
/// so a test that overrides exactly one field exercises only that field's
/// behaviour, never an unrelated one. Mirrors `tests/cell_id.rs`'s own
/// `base_cell` convention, except `rate` is `Fixed`, not `Saturate`: a
/// `Saturate` base cell would make every plan-related test also exercise
/// `supports`'s refusal, which is not what those tests are about.
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
        connect: SocketAddr::from(([10, 0, 0, 5], 8080)),
        sni: None,
        path_expr: "/hot".to_owned(),
    }
}

/// Pairs with [`base_cell`] and [`base_target`]: 30 measured seconds, 5
/// warmup seconds (never rendered; see `plan`'s own doc), no explicit
/// concurrency override.
fn base_run() -> RunParams {
    RunParams {
        duration_secs: 30,
        warmup_secs: 5,
        concurrency: None,
    }
}

fn base_tool_stamp() -> ToolStamp {
    ToolStamp {
        name: "oha".to_owned(),
        version: "1.15.0".to_owned(),
        image_digest: None,
    }
}

#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: base_cell/base_target/base_run are \
              this file's own fixed, valid constants, so planning cannot fail"
)]
fn base_invocation() -> Invocation {
    Oha.plan(&base_cell(), &base_target(), &base_run())
        .expect("the base cell, target and run are individually valid")
}

/// The exact expected argument vector for `plan(base_cell(), base_target(),
/// base_run())`, written out element by element so a reordering, an
/// insertion, or a dropped token in `Oha::plan` fails this test rather than
/// an assertion that only checks membership.
fn base_expected_args() -> Vec<String> {
    [
        "--no-tui",
        "--output-format",
        "json",
        "-c",
        "64",
        "-q",
        "50000",
        "--latency-correction",
        "-z",
        "30s",
        "--connect-to",
        "example.test:80:10.0.0.5:8080",
        "http://example.test/hot",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// The index of `seq` as a contiguous run inside `args`, or `None`.
fn find_subsequence(args: &[String], seq: &[&str]) -> Option<usize> {
    if seq.is_empty() || args.len() < seq.len() {
        return None;
    }
    args.windows(seq.len())
        .position(|w| w.iter().map(String::as_str).eq(seq.iter().copied()))
}

/// A synthetic, individually valid oha JSON document: real enough to exercise
/// every required field, but built directly in Rust (not from the real
/// fixture) so each hostile-input test below can mutate exactly one field.
fn valid_value() -> serde_json::Value {
    json!({
        "summary": { "total": 2.0, "totalData": 1000 },
        "statusCodeDistribution": { "200": 100 },
        "errorDistribution": {},
        "latencyPercentiles": {
            "p10": 0.0001,
            "p25": 0.0002,
            "p50": 0.0003,
            "p75": 0.0004,
            "p90": 0.0005,
            "p95": 0.0006,
            "p99": 0.0007,
            "p99.9": 0.0008,
            "p99.99": 0.0009
        }
    })
}

/// Asserts `err` is `BenchError::Parse` and returns its `detail` text, so
/// every caller can assert on the SPECIFIC reason rather than only the
/// variant, which any rejection would satisfy.
#[allow(
    clippy::panic,
    reason = "test-support helper, not itself a #[test] fn: panicking here surfaces which \
              caller's assertion actually failed, with the real BenchError in the message"
)]
fn expect_parse_detail(err: &BenchError) -> &str {
    match err {
        BenchError::Parse { tool, detail } => {
            assert_eq!(*tool, "oha");
            detail.as_str()
        }
        other => panic!("expected BenchError::Parse, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 1. plan_base_cell_pins_the_argument_vector
// ---------------------------------------------------------------------------

#[test]
fn plan_base_cell_pins_the_argument_vector() {
    let invocation = base_invocation();
    assert_eq!(invocation.program, "oha");
    assert_eq!(invocation.args, base_expected_args());
    assert!(invocation.env.is_empty());
}

// ---------------------------------------------------------------------------
// 2. plan_is_deterministic
// ---------------------------------------------------------------------------

#[test]
fn plan_is_deterministic() {
    let cell = base_cell();
    let target = base_target();
    let run = base_run();
    let first = Oha.plan(&cell, &target, &run).expect("base cell plans");
    let second = Oha.plan(&cell, &target, &run).expect("base cell plans");
    assert_eq!(first, second);
    assert_eq!(first.command_line(), second.command_line());
}

// ---------------------------------------------------------------------------
// 3. command_line_quoting
// ---------------------------------------------------------------------------

#[test]
fn command_line_quoting() {
    let quoted = Invocation {
        program: "oha".to_owned(),
        args: vec!["a b'c".to_owned()],
        env: Vec::new(),
    };
    assert_eq!(quoted.command_line(), "oha 'a b'\\''c'");

    let bare = Invocation {
        program: "oha".to_owned(),
        args: vec!["plain_token-1.2:3=4@5%6+7".to_owned()],
        env: Vec::new(),
    };
    assert_eq!(bare.command_line(), "oha plain_token-1.2:3=4@5%6+7");
}

// ---------------------------------------------------------------------------
// 4. keepalive_downstream_close_adds_flag
// ---------------------------------------------------------------------------

#[test]
fn keepalive_downstream_close_adds_flag() {
    let target = base_target();
    let run = base_run();

    let mut both = base_cell();
    both.keepalive = KeepaliveMode::Both;
    let both_args = Oha.plan(&both, &target, &run).expect("Both plans").args;
    assert!(!both_args.iter().any(|a| a == "--disable-keepalive"));

    let mut no_pool = base_cell();
    no_pool.keepalive = KeepaliveMode::NoUpstreamPool;
    let no_pool_args = Oha
        .plan(&no_pool, &target, &run)
        .expect("NoUpstreamPool plans")
        .args;
    assert!(!no_pool_args.iter().any(|a| a == "--disable-keepalive"));

    let mut downstream_close = base_cell();
    downstream_close.keepalive = KeepaliveMode::DownstreamClose;
    let downstream_close_args = Oha
        .plan(&downstream_close, &target, &run)
        .expect("DownstreamClose plans")
        .args;
    assert!(
        downstream_close_args
            .iter()
            .any(|a| a == "--disable-keepalive")
    );
}

// ---------------------------------------------------------------------------
// 5. fixed_rate_adds_latency_correction
// ---------------------------------------------------------------------------

#[test]
fn fixed_rate_adds_latency_correction() {
    let mut cell = base_cell();
    cell.rate = RateMode::Fixed(50_000);
    let args = Oha
        .plan(&cell, &base_target(), &base_run())
        .expect("fixed-rate cell plans")
        .args;
    let idx = find_subsequence(&args, &["-q", "50000", "--latency-correction"])
        .expect("-q, the rate, and --latency-correction must appear adjacently and in order");
    assert!(idx < args.len());
}

// ---------------------------------------------------------------------------
// 6. saturate_is_unsupported
// ---------------------------------------------------------------------------

#[test]
fn saturate_is_unsupported() {
    let mut cell = base_cell();
    cell.rate = RateMode::Saturate;
    let err = Oha.supports(&cell).expect_err("saturate must be refused");
    assert!(matches!(err, Unsupported::RateMode { tool: "oha", .. }));
}

// ---------------------------------------------------------------------------
// 7. h3_is_unsupported
// ---------------------------------------------------------------------------

#[test]
fn h3_is_unsupported() {
    let mut cell = base_cell();
    cell.protocol = Protocol::H3;
    let err = Oha.supports(&cell).expect_err("h3 must be refused");
    assert!(matches!(
        err,
        Unsupported::Protocol {
            tool: "oha",
            protocol: Protocol::H3
        }
    ));
}

// ---------------------------------------------------------------------------
// 8. too_many_connections_unsupported
// ---------------------------------------------------------------------------

#[test]
fn too_many_connections_unsupported() {
    let mut cell = base_cell();
    cell.connections = 100_000;
    let err = Oha
        .supports(&cell)
        .expect_err("100,000 connections must be refused");
    assert!(matches!(
        err,
        Unsupported::Connections {
            tool: "oha",
            connections: 100_000
        }
    ));
}

// ---------------------------------------------------------------------------
// 9. tls_uses_https_and_insecure
// ---------------------------------------------------------------------------

#[test]
fn tls_uses_https_and_insecure() {
    let mut cell = base_cell();
    cell.tls = TlsMode::EcdsaP256;
    let invocation = Oha
        .plan(&cell, &base_target(), &base_run())
        .expect("TLS cell plans");
    assert!(invocation.args.iter().any(|a| a == "--insecure"));
    let url = invocation
        .args
        .last()
        .expect("plan always emits a final URL argument");
    assert!(url.starts_with("https://"), "url was {url}");
}

// ---------------------------------------------------------------------------
// 10. parse_fixture
// ---------------------------------------------------------------------------

#[test]
fn parse_fixture() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let raw = Oha
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("the real oha 1.15.0 fixture must parse");

    // Ground truth, read directly out of tests/fixtures/oha-1.15.0.json:
    // statusCodeDistribution = {"200": 600}, errorDistribution =
    // {"aborted due to deadline": 1}, summary.totalData = 7800,
    // latencyPercentiles.p99 = 0.000459709 seconds.
    assert_eq!(raw.requests_sent, 601);
    assert_eq!(raw.responses_ok, 600);
    assert_eq!(raw.errors, 1);
    assert_eq!(raw.bytes_received, 7800);
    // Pinned against the fixture's own literal `"total": 3.001554375`
    // seconds (PR 799 review finding 2): before this assertion existed,
    // mutating the SOURCE scale from 1e9 to 1e6 (a 1000x error in the
    // denominator of every published requests-per-second figure) and
    // mutating the FIXTURE's own `total` from 3.001554375 to 7.5 both left
    // every test in this file green. `duration_ns` is asserted nowhere
    // else in this suite.
    assert_eq!(raw.duration_ns, 3_001_554_375);
    assert_eq!(raw.status_counts.len(), 1);
    assert_eq!(raw.status_counts.get(&200), Some(&600));
    assert!(!raw.latency_exact);
    assert!(raw.latency_trustworthy);

    // Acceptance criterion's own phrasing, made exact: the status map sums
    // to the reported request count net of errors (invariant 3's formula,
    // `sum(status_counts) == requests_sent - errors`), not to
    // `requests_sent` alone, which for this fixture also includes the one
    // "aborted due to deadline" entry that never got a status code at all.
    let status_sum: u64 = raw.status_counts.values().sum();
    assert_eq!(status_sum, raw.requests_sent - raw.errors);

    let expected_p99_ns = 459_709.0_f64;
    #[allow(
        clippy::cast_precision_loss,
        reason = "p99_ns is well under 2^53 for any run this fixture or this crate's own \
                  bounds can produce, so this comparison loses no precision that matters"
    )]
    let actual_p99_ns = raw.latency.percentiles().p99_ns as f64;
    let diff = (actual_p99_ns - expected_p99_ns).abs();
    assert!(
        diff <= expected_p99_ns * 0.01,
        "reconstructed p99_ns {actual_p99_ns} not within 1% of the fixture's own {expected_p99_ns}"
    );
}

// ---------------------------------------------------------------------------
// 11. parse_missing_summary_is_error
// ---------------------------------------------------------------------------

#[test]
fn parse_missing_summary_is_error() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let err = Oha
        .parse(&ctx, b"{}", b"")
        .expect_err("an empty object has no summary");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("summary"),
        "expected the detail to name summary, got: {detail}"
    );
}

// ---------------------------------------------------------------------------
// 12. parse_rejects_oversize
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_oversize() {
    // Content-based proof of check order, not a timing proxy: see
    // tests/hist.rs's `hgrm_rejects_oversized_input` for the identical
    // precedent and its own rationale (a plausible regression is often fast
    // enough to survive a timing bound anyway, which makes timing a weak
    // discriminator). Exactly one byte past MAX_TOOL_OUTPUT_BYTES is
    // rejected by the size guard specifically (its own detail names the
    // constant); exactly AT the bound is NOT rejected by that guard, which
    // pins the comparison as strictly `>`, not `>=` (the exactly-at /
    // exactly-one-past pair the size bound needs on both sides).
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let one_past = vec![0_u8; MAX_TOOL_OUTPUT_BYTES + 1];
    let err = Oha
        .parse(&ctx, &one_past, b"")
        .expect_err("must exceed MAX_TOOL_OUTPUT_BYTES");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("MAX_TOOL_OUTPUT_BYTES"),
        "expected the size guard to reject this input; got: {detail}"
    );

    let at_bound = vec![0_u8; MAX_TOOL_OUTPUT_BYTES];
    let err_at_bound = Oha
        .parse(&ctx, &at_bound, b"")
        .expect_err("all-zero bytes is not valid json, but must fail for a DIFFERENT reason");
    let detail_at_bound = expect_parse_detail(&err_at_bound);
    assert!(
        !detail_at_bound.contains("MAX_TOOL_OUTPUT_BYTES"),
        "exactly at the bound must not trip the size guard; got: {detail_at_bound}"
    );
}

// ---------------------------------------------------------------------------
// 13. parse_rejects_non_monotone_percentiles
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_non_monotone_percentiles() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // Watched-to-fail precondition: the UNMUTATED fixture must parse.
    let good = serde_json::to_vec(&valid_value()).expect("valid_value serialises");
    assert!(
        Oha.parse(&ctx, &good, b"").is_ok(),
        "fixture precondition: valid_value() must parse before it is mutated"
    );

    let mut mutated = valid_value();
    // p50 is 0.0003; setting p99 below it violates the monotone chain.
    mutated["latencyPercentiles"]["p99"] = json!(0.0001);
    let bytes = serde_json::to_vec(&mutated).expect("mutated value serialises");

    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("p99 below p50 must be rejected");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("monotone"),
        "expected the monotonicity guard to reject this input; got: {detail}"
    );
}

// ---------------------------------------------------------------------------
// 14. stderr_rate_warning_marks_untrustworthy
// ---------------------------------------------------------------------------

#[test]
fn stderr_rate_warning_marks_untrustworthy() {
    let cell = base_cell(); // Fixed rate.
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // Without a warning, a fixed-rate cell's latency is trustworthy.
    let clean = Oha
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("clean stderr parses");
    assert!(clean.latency_trustworthy);

    // With the pinned warning substring present anywhere in stderr, the
    // SAME fixed-rate cell's latency is marked untrustworthy: implication,
    // not equality (invariant 5), so a rate-mode check alone cannot decide
    // this.
    let warned = Oha
        .parse(
            &ctx,
            FIXTURE_BYTES,
            b"some preamble\nunable to keep up\ntrailer",
        )
        .expect("a rate warning does not itself make the run unparseable");
    assert!(!warned.latency_trustworthy);
}

// ---------------------------------------------------------------------------
// 15. parse_rejects_oversize_stderr
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_oversize_stderr() {
    // Primary, content-based proof (see parse_rejects_oversize's comment for
    // why this is preferred over a timing assertion): exactly one byte past
    // MAX_TOOL_STDERR_BYTES is rejected by the stderr size guard specifically,
    // even though stdout is the real, otherwise-valid fixture and even
    // though the oversized stderr itself CONTAINS a rate-warning substring
    // (proving the size guard fires rather than the run being silently
    // accepted with latency marked untrustworthy).
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut one_past = vec![b'x'; MAX_TOOL_STDERR_BYTES + 1 - "unable to keep up".len()];
    one_past.extend_from_slice(b"unable to keep up");
    assert_eq!(
        one_past.len(),
        MAX_TOOL_STDERR_BYTES + 1,
        "fixture precondition"
    );

    let err = Oha
        .parse(&ctx, FIXTURE_BYTES, &one_past)
        .expect_err("must exceed MAX_TOOL_STDERR_BYTES");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("MAX_TOOL_STDERR_BYTES"),
        "expected the stderr size guard to reject this input; got: {detail}"
    );

    // Secondary, best-effort proof of the issue's own literal framing ("in
    // under 100 milliseconds"): a MUCH larger oversized stderr (16x the
    // cap), so that a scan which incorrectly ran BEFORE the size check would
    // have measurably more work to do, must still be rejected quickly. This
    // is not the load-bearing assertion in this test (the content-based one
    // above is), because at this scale a linear byte scan is fast enough on
    // ordinary hardware that a real reordering regression might still
    // survive an even tighter bound; it is included because the issue asks
    // for it explicitly and a generous bound still catches a gross
    // regression (for example, an accidental quadratic rescan).
    let huge = vec![b'a'; MAX_TOOL_STDERR_BYTES * 16];
    let start = std::time::Instant::now();
    let huge_err = Oha
        .parse(&ctx, FIXTURE_BYTES, &huge)
        .expect_err("must exceed MAX_TOOL_STDERR_BYTES");
    let elapsed = start.elapsed();
    let huge_detail = expect_parse_detail(&huge_err);
    assert!(huge_detail.contains("MAX_TOOL_STDERR_BYTES"));
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "rejecting oversized stderr took {elapsed:?}, which suggests the size guard is not \
         running before an expensive scan"
    );
}

// ---------------------------------------------------------------------------
// 16. parse_rejects_non_finite_duration
// ---------------------------------------------------------------------------

fn duration_probe_text(total_literal: &str) -> String {
    format!(
        r#"{{"summary":{{"total":{total_literal},"totalData":1000}},"statusCodeDistribution":{{"200":100}},"errorDistribution":{{}},"latencyPercentiles":{{"p10":0.0001,"p25":0.0002,"p50":0.0003,"p75":0.0004,"p90":0.0005,"p95":0.0006,"p99":0.0007,"p99.9":0.0008,"p99.99":0.0009}}}}"#
    )
}

#[test]
fn parse_rejects_non_finite_duration() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // `NaN` and `Infinity` are not valid JSON number tokens: serde_json
    // 1.0.151 (confirmed by direct experiment while writing this test)
    // rejects both at the TOKENIZER level, before `Value` is ever built, so
    // these two sub-cases exercise serde_json's own syntax validation, NOT
    // this parser's `is_finite()` guard. They still return `Err(Parse)` as
    // required, asserted on their own ("invalid json") detail text so this
    // is pinned rather than hidden behind a shared variant-only check. See
    // the module doc's "honestly-documented gaps" section.
    for (label, literal) in [("nan", "NaN"), ("inf", "Infinity")] {
        let bytes = duration_probe_text(literal);
        let err = Oha.parse(&ctx, bytes.as_bytes(), b"").unwrap_err();
        let detail = expect_parse_detail(&err);
        assert!(
            detail.contains("invalid json"),
            "{label}: expected serde_json's own syntax rejection; got: {detail}"
        );
    }

    // `-1.0`, `1e30` and `0.0` ARE valid JSON number literals, and each
    // genuinely reaches and is rejected by this parser's own guard: `-1.0`
    // by the finite-and-non-negative check, `1e30` by the plausible-duration
    // ceiling, and `0.0` by the zero-duration check. `NaN as u64` is 0 in
    // Rust and every ordering comparison against `NaN` is false, so an
    // ordering-only check (`> 86_400.0` alone, with no `is_finite()` first)
    // would have silently accepted a non-finite value upstream of these
    // three and produced a zero-duration run.
    let neg = duration_probe_text("-1.0");
    let err_neg = Oha.parse(&ctx, neg.as_bytes(), b"").unwrap_err();
    assert!(expect_parse_detail(&err_neg).contains("not finite or is negative"));

    let huge = duration_probe_text("1e30");
    let err_huge = Oha.parse(&ctx, huge.as_bytes(), b"").unwrap_err();
    assert!(expect_parse_detail(&err_huge).contains("exceeds the maximum plausible run duration"));

    let zero = duration_probe_text("0.0");
    let err_zero = Oha.parse(&ctx, zero.as_bytes(), b"").unwrap_err();
    assert!(expect_parse_detail(&err_zero).contains("zero duration_ns"));
}

// ---------------------------------------------------------------------------
// 17. parse_rejects_absurd_counts
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_absurd_counts() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // Two status buckets each at u64::MAX. A u64 SUM of the two would
    // overflow: in a debug build (which `cargo test` uses) that panics
    // rather than wrapping, and in a release build it wraps into
    // u64::MAX - 1, still huge but silently wrong either way. Computing the
    // sum in u128 (this parser's actual implementation) avoids both: no
    // panic, and no wrap, just a correctly-huge value this parser then
    // rejects against MAX_REPORTED_REQUESTS.
    let mut two_max = valid_value();
    two_max["statusCodeDistribution"] = json!({
        "200": u64::MAX,
        "500": u64::MAX,
    });
    let bytes = serde_json::to_vec(&two_max).expect("serialises");
    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("two u64::MAX buckets must be rejected, not panic");
    assert!(
        expect_parse_detail(&err).contains("MAX_REPORTED_REQUESTS"),
        "expected the requests_sent bound to reject this input"
    );

    // A single bucket whose total exceeds MAX_REPORTED_REQUESTS, but does
    // not need u128 to avoid overflow on its own: a plain boundary check.
    let mut over_cap = valid_value();
    over_cap["statusCodeDistribution"] = json!({ "200": MAX_REPORTED_REQUESTS + 1 });
    let bytes_over = serde_json::to_vec(&over_cap).expect("serialises");
    let err_over = Oha
        .parse(&ctx, &bytes_over, b"")
        .expect_err("one bucket over MAX_REPORTED_REQUESTS must be rejected");
    assert!(expect_parse_detail(&err_over).contains("MAX_REPORTED_REQUESTS"));

    // Exactly AT MAX_REPORTED_REQUESTS is NOT rejected by this bound: the
    // exactly-at / exactly-one-past pair the boundary check needs on both
    // sides.
    let mut at_cap = valid_value();
    at_cap["statusCodeDistribution"] = json!({ "200": MAX_REPORTED_REQUESTS });
    let bytes_at = serde_json::to_vec(&at_cap).expect("serialises");
    let raw_at = Oha
        .parse(&ctx, &bytes_at, b"")
        .expect("exactly MAX_REPORTED_REQUESTS must be accepted");
    assert_eq!(raw_at.requests_sent, MAX_REPORTED_REQUESTS);
}

// ---------------------------------------------------------------------------
// 18. parse_rejects_deep_nesting
// ---------------------------------------------------------------------------

#[test]
fn parse_rejects_deep_nesting() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let bomb = "[".repeat(200_000);
    // Calling parse() and getting back a Result at all (rather than the
    // process aborting on a native stack overflow) IS the proof: an abort
    // would kill this whole test binary, not merely fail this assertion.
    let result = Oha.parse(&ctx, bomb.as_bytes(), b"");
    assert!(
        result.is_err(),
        "a 200,000-deep nesting bomb must be rejected, not accepted"
    );
}

// ---------------------------------------------------------------------------
// 19. plan_rejects_hostile_target_fields
// ---------------------------------------------------------------------------

#[test]
fn plan_rejects_hostile_target_fields() {
    let cell = base_cell();
    let run = base_run();

    let mut bad_host = base_target();
    bad_host.host = "exa mple.test".to_owned();
    let err = Oha
        .plan(&cell, &bad_host, &run)
        .expect_err("a host containing a space must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(
        msg.contains("host"),
        "expected the message to name host, got: {msg}"
    );

    let mut bad_sni = base_target();
    bad_sni.sni = Some("bad\nsni".to_owned());
    let err = Oha
        .plan(&cell, &bad_sni, &run)
        .expect_err("an sni containing a newline must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(
        msg.contains("sni"),
        "expected the message to name sni, got: {msg}"
    );

    let mut long_path = base_target();
    long_path.path_expr = format!("/{}", "a".repeat(4_999));
    assert_eq!(long_path.path_expr.len(), 5_000, "fixture precondition");
    let err = Oha
        .plan(&cell, &long_path, &run)
        .expect_err("a 5,000 byte path_expr must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(
        msg.contains("path_expr"),
        "expected the message to name path_expr, got: {msg}"
    );

    let mut control_byte_path = base_target();
    control_byte_path.path_expr = "/\u{1b}[2J".to_owned();
    let err = Oha
        .plan(&cell, &control_byte_path, &run)
        .expect_err("a path_expr containing an escape sequence must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(msg.contains("path_expr"));

    let mut no_leading_slash = base_target();
    no_leading_slash.path_expr = "no-leading-slash".to_owned();
    let err = Oha
        .plan(&cell, &no_leading_slash, &run)
        .expect_err("a path_expr with no leading slash must be rejected");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(msg.contains("path_expr"));
    assert!(msg.contains("leading"));
}

// ---------------------------------------------------------------------------
// Property test: command_line_is_reparseable.
// ---------------------------------------------------------------------------

/// A small, checked-in POSIX-quoting splitter that inverts EXACTLY
/// `Invocation::command_line`'s own quoting rule: tokens are either bare
/// (any run of `is_bare_token_char` bytes, which by construction never
/// contains a space or a quote) or single-quoted with an embedded quote
/// spelled `'\''`. This is not a general shell parser; restricting the
/// property test's generator to printable ASCII (`0x20..=0x7E`) is what
/// makes that safe, matching invariant 8's own printable-ASCII requirement
/// on a recorded command line.
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: operates only on the printable-ASCII \
              bytes produced by Invocation::command_line and this file's own proptest \
              generator (never non-ASCII, so every from_utf8 here cannot fail), and every index \
              used is bounds-checked by the surrounding `i < n` / `i + 2 < n` loop condition \
              immediately before it is used"
)]
fn split_command_line(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let n = bytes.len();
    let mut tokens = Vec::new();
    while i < n {
        while i < n && bytes[i] == b' ' {
            i += 1;
        }
        if i >= n {
            break;
        }
        let mut tok = String::new();
        if bytes[i] == b'\'' {
            i += 1;
            loop {
                let start = i;
                while i < n && bytes[i] != b'\'' {
                    i += 1;
                }
                tok.push_str(std::str::from_utf8(&bytes[start..i]).expect("ascii input"));
                i += 1; // past the closing quote just found.
                if i + 2 < n && bytes[i] == b'\\' && bytes[i + 1] == b'\'' && bytes[i + 2] == b'\''
                {
                    tok.push('\'');
                    i += 3;
                    continue;
                }
                break;
            }
        } else {
            let start = i;
            while i < n && bytes[i] != b' ' {
                i += 1;
            }
            tok.push_str(std::str::from_utf8(&bytes[start..i]).expect("ascii input"));
        }
        tokens.push(tok);
    }
    tokens
}

/// A strategy for one printable-ASCII (`0x20..=0x7E`) token, 0 to 12 bytes.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn: the regex literal is fixed and \
              valid, so this can never fail"
)]
fn printable_ascii_token() -> impl proptest::strategy::Strategy<Value = String> {
    proptest::string::string_regex("[ -~]{0,12}").expect("a fixed, valid regex")
}

proptest::proptest! {
    #[test]
    fn command_line_is_reparseable(
        program in printable_ascii_token(),
        args in proptest::collection::vec(printable_ascii_token(), 0..=6),
    ) {
        let invocation = Invocation { program: program.clone(), args: args.clone(), env: Vec::new() };
        let line = invocation.command_line();
        let split = split_command_line(&line);

        let mut expected = vec![program];
        expected.extend(args);
        proptest::prop_assert_eq!(split, expected);
    }
}

// ---------------------------------------------------------------------------
// Supplementary tests, beyond the 19 named above.
//
// Each of these closes a specific gap the 19 named tests do not reach: an
// edge case from the issue's own "Edge cases" list with no dedicated named
// test (statusCodeDistribution empty), the OTHER side of invariant 5 (a
// Saturate cell makes latency untrustworthy on its own, independent of
// stderr_rate_warning_marks_untrustworthy's stderr-side proof), and the
// exactly-at half of three boundaries the named tests only probe from the
// rejecting side (too_many_connections_unsupported, and 19's path_expr
// length and parse_rejects_absurd_counts's request count both test only
// one-past; the exactly-at case for the connections cap and the path_expr
// cap had no test at either edge at all before these).
// ---------------------------------------------------------------------------

/// Edge case 3: "statusCodeDistribution empty. Err(Parse); a run with no
/// responses is not a run." No test in the named 19 constructs this input;
/// this closes that gap.
#[test]
fn status_map_empty_is_rejected() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut empty_status = valid_value();
    empty_status["statusCodeDistribution"] = json!({});
    let bytes = serde_json::to_vec(&empty_status).expect("serialises");
    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("an empty statusCodeDistribution must be rejected");
    assert!(expect_parse_detail(&err).contains("statusCodeDistribution"));
}

/// Invariant 5's OTHER half: `latency_trustworthy` is false for a
/// `RateMode::Saturate` cell even with clean stderr. `supports` is the
/// PRIMARY gate (`saturate_is_unsupported`) and would normally stop a
/// runner from ever calling `parse` for such a cell at all, but `parse`'s
/// own formula must hold regardless of whether a caller checked `supports`
/// first: this is the second, independent line of defence its own doc
/// describes, and nothing in the named 19 constructs a Saturate `ParseCtx`
/// to prove it.
#[test]
fn saturate_ctx_sets_latency_untrustworthy_without_stderr_warning() {
    let mut cell = base_cell();
    cell.rate = RateMode::Saturate;
    let invocation = base_invocation(); // Invocation content is irrelevant here.
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let raw = Oha
        .parse(&ctx, FIXTURE_BYTES, b"")
        .expect("parse itself does not consult supports");
    assert!(!raw.latency_trustworthy);
}

/// Exactly-at-cap / exactly-one-past for the connections bound
/// `too_many_connections_unsupported` only probes from 100,000 connections,
/// well past the 65,535 cap; this pins the boundary itself on both sides.
#[test]
fn connections_boundary_65535_ok_65536_unsupported() {
    let mut at_cap = base_cell();
    at_cap.connections = 65_535;
    assert!(Oha.supports(&at_cap).is_ok());

    let mut one_past = base_cell();
    one_past.connections = 65_536;
    let err = Oha
        .supports(&one_past)
        .expect_err("one past the connections cap must be refused");
    assert!(matches!(
        err,
        Unsupported::Connections {
            tool: "oha",
            connections: 65_536
        }
    ));
}

/// Exactly-at-cap for `path_expr`'s length bound. `plan_rejects_hostile_target_fields`
/// (test 19) only probes 5,000 bytes, one thousand past the 4,096 byte cap;
/// this pins that exactly 4,096 bytes is accepted.
#[test]
fn path_expr_boundary_exactly_at_cap_is_ok() {
    let cell = base_cell();
    let run = base_run();
    let mut target = base_target();
    target.path_expr = format!("/{}", "a".repeat(4_095));
    assert_eq!(target.path_expr.len(), 4_096, "fixture precondition");
    assert!(Oha.plan(&cell, &target, &run).is_ok());
}

// ---------------------------------------------------------------------------
// PR 799 review (issue #800) fixes, in the order the review's own findings
// are numbered. Each test's doc comment names the finding it closes.
// ---------------------------------------------------------------------------

/// BLOCKING finding 1: `u16::from_str` accepts a leading zero and a leading
/// `+`, so "0200" and "+200" both parse to the same code as an existing
/// canonical "200" key while remaining a DIFFERENT JSON key. Before the
/// fix, both aliased entries were summed into `requests_sent` while
/// colliding into a single `status_counts` entry, publishing a
/// self-inconsistent `RawRun` (`requests_sent=107` against a status map
/// summing to 100) that broke the issue's own invariants 3 and 9.
#[test]
fn parse_rejects_status_code_key_aliasing() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    for aliased_key in ["0200", "+200"] {
        let text = format!(
            r#"{{"summary":{{"total":2.0,"totalData":1000}},"statusCodeDistribution":{{"200":100,"{aliased_key}":7}},"errorDistribution":{{}},"latencyPercentiles":{{"p10":0.0001,"p25":0.0002,"p50":0.0003,"p75":0.0004,"p90":0.0005,"p95":0.0006,"p99":0.0007,"p99.9":0.0008,"p99.99":0.0009}}}}"#
        );
        let err = Oha
            .parse(&ctx, text.as_bytes(), b"")
            .expect_err("an aliased status-code key must be rejected, not silently collapsed");
        let detail = expect_parse_detail(&err);
        assert!(
            detail.contains(aliased_key),
            "expected the canonical-rendering guard to name {aliased_key}; got: {detail}"
        );
    }
}

/// `SHOULD_FIX` finding 3: a literal duplicate JSON key is accepted with
/// silent last-wins. `{"200":100,"200":7}` previously parsed as a 7-request
/// run, discarding the 100 responses under the first occurrence with no
/// error at all.
#[test]
fn parse_rejects_duplicate_status_code_key() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let text = concat!(
        r#"{"summary":{"total":2.0,"totalData":1000},"#,
        r#""statusCodeDistribution":{"200":100,"200":7},"#,
        r#""errorDistribution":{},"#,
        r#""latencyPercentiles":{"p10":0.0001,"p25":0.0002,"p50":0.0003,"p75":0.0004,"p90":0.0005,"p95":0.0006,"p99":0.0007,"p99.9":0.0008,"p99.99":0.0009}}"#,
    );
    let err = Oha
        .parse(&ctx, text.as_bytes(), b"")
        .expect_err("a literal duplicate statusCodeDistribution key must be rejected");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("duplicate"),
        "expected the duplicate-key guard to reject this input; got: {detail}"
    );
}

/// `SHOULD_FIX` finding 3, other half: two top-level `summary` objects
/// previously parsed `Ok` using the SECOND one's duration and byte count,
/// so an attacker or a corrupt tool could append a second summary and
/// rewrite the published duration and `bytes_received` while the first,
/// plausible-looking one is what a human reading the file sees.
#[test]
fn parse_rejects_duplicate_summary_object() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let text = concat!(
        r#"{"summary":{"total":2.0,"totalData":1000},"#,
        r#""summary":{"total":9.0,"totalData":5},"#,
        r#""statusCodeDistribution":{"200":100},"#,
        r#""errorDistribution":{},"#,
        r#""latencyPercentiles":{"p10":0.0001,"p25":0.0002,"p50":0.0003,"p75":0.0004,"p90":0.0005,"p95":0.0006,"p99":0.0007,"p99.9":0.0008,"p99.99":0.0009}}"#,
    );
    let err = Oha.parse(&ctx, text.as_bytes(), b"").expect_err(
        "two top-level summary objects must be rejected, not silently resolved to the second",
    );
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("duplicate"),
        "expected the duplicate-key guard to reject this input; got: {detail}"
    );
}

/// `SHOULD_FIX` finding 4, as corrected by round two review of PR 799.
/// Round one's original fix rejected any input whose latency reconstruction
/// recorded zero samples and had zero `out_of_range`, inferred from the
/// `LatencyRecorder`'s own post-reconstruction state. Round two's review ran
/// real `oha 1.15.0 --no-tui --output-format json -n 1 -c 1` against a local
/// server and showed that guard fires on a genuine single-request capture:
/// `requests_sent == 1` legitimately rounds every one of the nine percentile
/// gaps to a weight of 0 before a floor is applied, which round one's guard
/// could not tell apart from a document that never described a request at
/// all. The honest test for "did a run happen" is `requests_sent == 0`
/// itself, checked directly and before the latency reconstruction runs (see
/// `parse_accepts_a_genuine_single_request_oha_capture` below for the
/// n == 1 case this now correctly accepts). This closes the round-one gap a
/// different way: a status map whose only entry is present but reports `0`
/// occurrences, with an equally empty `errorDistribution`, sums to
/// `requests_sent == 0`, which genuinely is not a run.
#[test]
fn parse_rejects_a_reconstruction_with_zero_requests_sent() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut hostile = valid_value();
    hostile["statusCodeDistribution"] = json!({ "200": 0 });
    let bytes = serde_json::to_vec(&hostile).expect("serialises");
    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("a document whose requests_sent sums to 0 must be rejected");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("requests_sent") && detail.contains("zero"),
        "expected the requests_sent == 0 guard to reject this input; got: {detail}"
    );
}

/// `SHOULD_FIX` finding 4, round two's own blocking finding: a genuine
/// `oha 1.15.0` single-request capture must parse, not be rejected.
/// `FIXTURE_N1_BYTES` (declared above, next to `FIXTURE_BYTES`) is the real,
/// complete document the reviewer captured by running the real, pinned
/// `oha 1.15.0` binary against a local `python3 -m http.server`:
/// `oha --no-tui --output-format json -n 1 -c 1 http://127.0.0.1/index.html`,
/// 10 top-level keys and 9 summary keys, not a hand-trimmed subset. An
/// earlier version of this test built a 4-key object by hand instead
/// (`{"summary": {...}, "statusCodeDistribution": ..., "errorDistribution":
/// ..., "latencyPercentiles": ...}`); that exercised only the four fields
/// this parser reads and none of the unknown-field tolerance the real
/// fixture (`FIXTURE_BYTES`, above) exists to pin, so PR 799 round three's
/// review pointed this test at the genuine capture instead (NOTE 1).
///
/// Every `latencyPercentiles` value in the fixture is identical
/// (`0.002772958` seconds) because a single request has exactly one latency
/// value at every quantile; every one of the nine gaps (0.10 through
/// 0.0009) times `requests_sent` (1) is below 0.5 and rounds to a weight of
/// 0, which is exactly the state round one's guard rejected. Watched to
/// fail against that guard first: before round two's fix, this input
/// returned `Err("latency reconstruction produced zero recorded and zero
/// out-of-range samples")` instead of the `Ok` asserted below.
#[test]
fn parse_accepts_a_genuine_single_request_oha_capture() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let raw = Oha
        .parse(&ctx, FIXTURE_N1_BYTES, b"")
        .expect("a genuine single-request oha 1.15.0 capture must parse");

    assert_eq!(raw.requests_sent, 1);
    assert_eq!(raw.responses_ok, 1);
    assert_eq!(raw.errors, 0);
    assert_eq!(raw.out_of_range, 0);
    assert!(
        !raw.latency.is_empty(),
        "a genuine single-request run must record at least one latency sample, not publish an \
         all-zero histogram as fact"
    );

    let expected_ns = 2_772_958.0_f64;
    #[allow(
        clippy::cast_precision_loss,
        reason = "p50_ns is well under 2^53 for any run this crate's own bounds can produce, so \
                  this comparison loses no precision that matters"
    )]
    let actual_ns = raw.latency.percentiles().p50_ns as f64;
    let diff = (actual_ns - expected_ns).abs();
    assert!(
        diff <= expected_ns * 0.01,
        "reconstructed p50_ns {actual_ns} not within 1% of the capture's own {expected_ns}"
    );
}

/// `BLOCKING` finding 1 (issue #804, PR 799 round three), MEASURED against
/// five genuine `oha 1.15.0` captures at `-n 1`, `-n 3`, `-n 5`, `-n 10` and
/// `-n 100` (`FIXTURE_N1_BYTES` through `FIXTURE_N100_BYTES`). This is the
/// test the round three review asked for: no test before this one read
/// `raw.latency.len()` or related the reconstructed sample count to
/// `raw.requests_sent` at all, which is exactly why round two's symmetric
/// `weight.max(1)` (flooring both branches, forcing at least one sample per
/// reported percentile independent of `requests_sent`) shipped unnoticed.
///
/// Every expected count below was produced by running the fixed source
/// through this exact assertion and reading back what it printed (measured,
/// not reasoned about by hand): -n 1 gives 9 (the one legitimate exception:
/// `requests_sent == 1` floors every gap, see the test above), -n 3 gives
/// 2, -n 5 gives 5, -n 10 gives 11, -n 100 gives 100. Watched to fail
/// first: reverting the narrow floor in `oha.rs` back to round two's
/// unconditional `weight.max(1)` makes every one of -n 3, -n 5, -n 10 and
/// -n 100 assert here at 9, 9, 15 and 101 respectively instead, which is
/// the exact over-count the issue measured (and, for -n 3/-n 5/-n 10,
/// publishes the tool's own p75, p90 and p75 as `p50` instead of its real
/// p50; see the three `p50` assertions below, which fail identically under
/// that reversion).
#[test]
fn parse_pins_sample_count_against_requests_sent_for_genuine_captures() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    // (fixture bytes, requests_sent, expected raw.latency.len(), expected p50_ns, tolerance)
    let cases: [(&[u8], u64, u64, u64); 5] = [
        (FIXTURE_N1_BYTES, 1, 9, 2_772_958),
        (FIXTURE_N3_BYTES, 3, 2, 357_125),
        (FIXTURE_N5_BYTES, 5, 5, 264_916),
        (FIXTURE_N10_BYTES, 10, 11, 294_041),
        (FIXTURE_N100_BYTES, 100, 100, 218_042),
    ];

    for (bytes, expected_requests_sent, expected_samples, expected_p50_ns) in cases {
        let raw = Oha
            .parse(&ctx, bytes, b"")
            .expect("every genuine capture in this table must parse");
        assert_eq!(
            raw.requests_sent, expected_requests_sent,
            "fixture's own requests_sent must match the table"
        );
        assert_eq!(
            raw.latency.len(),
            expected_samples,
            "requests_sent {expected_requests_sent}: reconstructed sample count must track \
             requests_sent, not a fixed floor independent of it"
        );
        assert_eq!(
            raw.out_of_range, 0,
            "none of these captures report an out-of-range latency"
        );

        #[allow(
            clippy::cast_precision_loss,
            reason = "p50_ns is well under 2^53 for any run this crate's own bounds can produce, \
                      so this comparison loses no precision that matters"
        )]
        let actual_p50_ns = raw.latency.percentiles().p50_ns as f64;
        #[allow(
            clippy::cast_precision_loss,
            reason = "expected_p50_ns is a small literal constant, well under 2^53"
        )]
        let expected_p50_f = expected_p50_ns as f64;
        let diff = (actual_p50_ns - expected_p50_f).abs();
        assert!(
            diff <= expected_p50_f * 0.01,
            "requests_sent {expected_requests_sent}: published p50_ns {actual_p50_ns} not within \
             1% of the tool's own p50 {expected_p50_f}; the parser is publishing a DIFFERENT \
             percentile than the one it claims"
        );
    }
}

/// `NOTE` (issue #804): a document reporting every `latencyPercentiles`
/// value as `0.0` seconds parses (`requests_sent` is nonzero, so the
/// `requests_sent == 0` guard does not fire) and publishes `p50_ns ==
/// LOW_NS` (1 ns), a floor, not a measurement. This is a DELIBERATE,
/// DOCUMENTED floor, not a rejection: round two's review already
/// established that the honest test for "did a run happen" is
/// `requests_sent == 0` itself, checked once before the latency
/// reconstruction runs, not a property inferred from the reconstruction
/// (that was round one's rejected approach, and it is what misfired on a
/// genuine single-request capture, see the two tests above). Rejecting an
/// all-zero-latency document here would reintroduce exactly that inferred
/// check. `1 ns` is `hist::LOW_NS`, the same floor `LatencyRecorder::
/// record_n_ns` applies to any in-range value below it; nothing about the
/// oha adapter singles this case out.
#[test]
fn parse_accepts_all_zero_latency_percentiles_and_floors_to_low_ns() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut hostile = valid_value();
    for key in [
        "p10", "p25", "p50", "p75", "p90", "p95", "p99", "p99.9", "p99.99",
    ] {
        hostile["latencyPercentiles"][key] = json!(0.0);
    }
    let bytes = serde_json::to_vec(&hostile).expect("serialises");

    let raw = Oha
        .parse(&ctx, &bytes, b"")
        .expect("an all-zero-latency document with a nonzero requests_sent is not rejected");
    assert_eq!(raw.requests_sent, 100);
    assert_eq!(raw.out_of_range, 0);
    let p = raw.latency.percentiles();
    assert_eq!(
        p.p50_ns, 1,
        "an all-zero latency floors to LOW_NS (1 ns), not to 0"
    );
    assert_eq!(
        p.max_ns, 1,
        "every recorded sample is floored identically, so max matches p50"
    );
}

/// `SHOULD_FIX` finding 5: `record_n_ns` treats a `count` of 0 as a complete
/// no-op, so a percentile reading above `HIGH_NS` (60 seconds) whose own
/// reconstructed weight rounds to 0 previously vanished from
/// `out_of_range` with no trace, defeating the I7 tail-truncation signal
/// edge case 9 depends on. `p99.99`'s own gap (0.9999 - 0.999 = 0.0001)
/// times 100 responses is 0.01, which rounds to a weight of 0, yet its
/// reported value (1e30 seconds) is far above `HIGH_NS`.
#[test]
fn parse_marks_out_of_range_even_when_its_own_weight_rounds_to_zero() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut hostile = valid_value();
    hostile["statusCodeDistribution"] = json!({ "200": 100 });
    hostile["latencyPercentiles"]["p99.99"] = json!(1e30);
    let bytes = serde_json::to_vec(&hostile).expect("serialises");

    let raw = Oha
        .parse(&ctx, &bytes, b"")
        .expect("a hostile top percentile does not itself make the run unparseable");
    assert!(
        raw.out_of_range > 0,
        "an above-HIGH_NS percentile must be counted even when its own reconstructed weight \
         rounds to zero"
    );
}

/// `SHOULD_FIX` finding 6: `parse_version` had zero test coverage. This pins
/// the real `oha --version` shape: the LAST whitespace-separated token of
/// `oha 1.15.0\n` is `1.15.0`. Also closes the mutation that takes the
/// FIRST token instead (which would make every stamp read the literal
/// version "oha").
#[test]
fn parse_version_extracts_last_token() {
    let stamp = Oha
        .parse_version(b"oha 1.15.0\n")
        .expect("a well-formed version probe must parse");
    assert_eq!(stamp.name, "oha");
    assert_eq!(stamp.version, "1.15.0");
}

/// `SHOULD_FIX` finding 6: the extracted version token becomes
/// `ToolStamp::version`, which is later echoed into the run log and the
/// published table; a NUL byte or an ANSI escape sequence is rejected
/// rather than laundered into provenance, matching `validate_target`'s own
/// rationale for `Target`'s string fields.
#[test]
fn parse_version_rejects_non_printable_bytes() {
    let err = Oha
        .parse_version(b"oha 1.15.0\0evil")
        .expect_err("a NUL byte in the version token must be rejected");
    assert!(expect_parse_detail(&err).contains("non-printable"));

    let err = Oha
        .parse_version(b"\x1b[2K1.15.0")
        .expect_err("an ANSI escape sequence in the version token must be rejected");
    assert!(expect_parse_detail(&err).contains("non-printable"));
}

/// `SHOULD_FIX` finding 6: an empty probe output and non-UTF-8 bytes are each
/// rejected, naming a different reason.
#[test]
fn parse_version_rejects_empty_and_non_utf8() {
    let empty_err = Oha
        .parse_version(b"")
        .expect_err("empty version output must be rejected");
    assert!(expect_parse_detail(&empty_err).contains("empty"));

    let non_utf8_err = Oha
        .parse_version(&[0xFF, 0xFE])
        .expect_err("non-utf-8 version output must be rejected");
    assert!(expect_parse_detail(&non_utf8_err).contains("utf-8"));
}

/// `SHOULD_FIX` finding 6: closes the mutation that drops the
/// `MAX_VERSION_OUTPUT_BYTES` guard entirely, and pins the boundary on both
/// sides: exactly at the cap is accepted, one byte past it is rejected.
#[test]
fn parse_version_rejects_oversize() {
    let one_past = vec![b'1'; MAX_VERSION_OUTPUT_BYTES + 1];
    let err = Oha
        .parse_version(&one_past)
        .expect_err("must exceed MAX_VERSION_OUTPUT_BYTES");
    assert!(expect_parse_detail(&err).contains("MAX_VERSION_OUTPUT_BYTES"));

    let at_bound = vec![b'1'; MAX_VERSION_OUTPUT_BYTES];
    let stamp = Oha
        .parse_version(&at_bound)
        .expect("exactly at the cap must not trip the size guard");
    assert_eq!(stamp.version.len(), MAX_VERSION_OUTPUT_BYTES);
}

/// `SHOULD_FIX` finding 7 (1 of 4): the issue's own headline rule, "Do NOT
/// default a missing JSON field to zero. Name it in the error." Making
/// `errorDistribution` optional so a missing map silently means zero
/// errors was previously untested; this pins the rejection.
#[test]
fn parse_missing_error_distribution_is_error() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut missing_errors = valid_value();
    missing_errors
        .as_object_mut()
        .expect("valid_value is an object")
        .remove("errorDistribution");
    let bytes = serde_json::to_vec(&missing_errors).expect("serialises");
    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("a missing errorDistribution must never default to zero errors");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("errorDistribution"),
        "expected the detail to name errorDistribution, got: {detail}"
    );
}

/// `SHOULD_FIX` finding 7 (2 of 4): the 64-distinct-status-code cap (edge
/// case 5, Bounds table row 5) was previously untested; no test
/// constructed 65 distinct codes.
#[test]
fn parse_rejects_65_distinct_status_codes() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut codes = serde_json::Map::new();
    for c in 100..165_u32 {
        codes.insert(c.to_string(), json!(1));
    }
    assert_eq!(codes.len(), 65, "fixture precondition");
    let mut too_many = valid_value();
    too_many["statusCodeDistribution"] = serde_json::Value::Object(codes);
    let bytes = serde_json::to_vec(&too_many).expect("serialises");
    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("65 distinct status codes must exceed the 64 code cap");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("64"),
        "expected the status-code cap to reject this input; got: {detail}"
    );
}

/// `SHOULD_FIX` finding 7 (3 of 4): the status key range `100..=599` (edge
/// case 4) was previously exercised only by non-numeric hostile keys, never
/// by an in-range-format key that is numerically outside the range; this
/// pins both rejecting sides and both accepting boundaries.
#[test]
fn parse_rejects_status_key_outside_100_599_range() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    for bad_key in ["99", "600"] {
        let mut bad = valid_value();
        bad["statusCodeDistribution"] = json!({ bad_key: 100 });
        let bytes = serde_json::to_vec(&bad).expect("serialises");
        let err = Oha
            .parse(&ctx, &bytes, b"")
            .expect_err("a status key outside 100..=599 must be rejected");
        let detail = expect_parse_detail(&err);
        assert!(
            detail.contains("100..=599"),
            "expected the status-code range guard to reject key {bad_key}; got: {detail}"
        );
    }

    // Exactly-at-cap on both sides: 100 and 599 are both accepted. Count is
    // 100, not 1, so this does not also trip the unrelated
    // zero-recorded-samples guard.
    for good_key in ["100", "599"] {
        let mut good = valid_value();
        good["statusCodeDistribution"] = json!({ good_key: 100 });
        let bytes = serde_json::to_vec(&good).expect("serialises");
        assert!(
            Oha.parse(&ctx, &bytes, b"").is_ok(),
            "status key {good_key} is inside 100..=599 and must be accepted"
        );
    }
}

/// `SHOULD_FIX` finding 7 (4 of 4): the `is_finite`/non-negative guard on
/// each `latencyPercentiles` value is reachable (unlike `summary.total`'s
/// own `NaN`/`Infinity` sub-cases): `-1.0` is a valid JSON number literal,
/// and without this guard it would saturate to 0 ns and be silently
/// accepted rather than rejected.
#[test]
fn parse_rejects_non_finite_or_negative_percentile() {
    let cell = base_cell();
    let invocation = base_invocation();
    let tool = base_tool_stamp();
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    let mut negative = valid_value();
    negative["latencyPercentiles"]["p10"] = json!(-1.0);
    let bytes = serde_json::to_vec(&negative).expect("serialises");
    let err = Oha
        .parse(&ctx, &bytes, b"")
        .expect_err("a negative latencyPercentiles value must be rejected, not floored to 0 ns");
    let detail = expect_parse_detail(&err);
    assert!(
        detail.contains("not finite or is negative"),
        "expected the percentile finite/non-negative guard to reject this input; got: {detail}"
    );
}

/// `SHOULD_FIX` finding 8 (1 of 3): neither `PathCorpus::UniformRandom` nor
/// `PathCorpus::AdversarialWorstCase` was ever planned by any test, so
/// deleting `--max-repeat 4` (the issue's own explicit Do NOT: "Do NOT
/// omit --max-repeat 4 when --rand-regex-url is present") while keeping
/// `--rand-regex-url` left the previous suite green.
#[test]
fn plan_non_single_hot_path_corpus_adds_max_repeat_and_rand_regex_url() {
    let run = base_run();
    for corpus in [PathCorpus::UniformRandom, PathCorpus::AdversarialWorstCase] {
        let mut cell = base_cell();
        cell.path_corpus = corpus;
        let mut target = base_target();
        target.path_expr = "/[a-z]{1,10}".to_owned();
        let args = Oha
            .plan(&cell, &target, &run)
            .unwrap_or_else(|e| panic!("{corpus:?} cell must plan: {e}"))
            .args;
        find_subsequence(&args, &["--max-repeat", "4", "--rand-regex-url"]).unwrap_or_else(|| {
            panic!(
                "{corpus:?}: --max-repeat 4 and --rand-regex-url must appear adjacently and in \
                 order, got {args:?}"
            )
        });
    }

    let single_hot_args = Oha
        .plan(&base_cell(), &base_target(), &run)
        .expect("SingleHot plans")
        .args;
    assert!(
        !single_hot_args.iter().any(|a| a == "--rand-regex-url"),
        "SingleHot must never add --rand-regex-url"
    );
}

/// `SHOULD_FIX` finding 8 (2 of 3): the `Protocol::H2` mapping-table row
/// (`--http2`) was never planned by any test, so deleting it for an H2
/// cell would silently measure H1 while the cell claims H2, and the
/// previous suite would not have noticed.
#[test]
fn plan_h2_protocol_adds_http2_flag() {
    let mut cell = base_cell();
    cell.protocol = Protocol::H2;
    let args = Oha
        .plan(&cell, &base_target(), &base_run())
        .expect("H2 cell plans")
        .args;
    let idx = find_subsequence(&args, &["json", "--http2", "-c"])
        .expect("--http2 must sit between the output-format flags and -c for an H2 cell");
    assert!(idx < args.len());
}

/// `SHOULD_FIX` finding 8 (3 of 3): `saturate_is_unsupported` and
/// `h3_is_unsupported` call `supports` directly; no test called `plan`
/// itself with a cell `supports` refuses, so deleting `plan`'s own
/// `self.supports(cell)?` gate would have left the previous suite green.
#[test]
fn plan_refuses_a_cell_supports_rejects() {
    let mut cell = base_cell();
    cell.protocol = Protocol::H3;
    let err = Oha
        .plan(&cell, &base_target(), &base_run())
        .expect_err("plan must itself refuse a cell supports rejects, not only supports");
    let BenchError::Cell(msg) = err else {
        panic!("expected BenchError::Cell");
    };
    assert!(
        msg.contains("protocol"),
        "expected the message to name protocol, got: {msg}"
    );
}
