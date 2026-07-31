// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for every registered `LoadGenerator` adapter's `parse` and
//! `parse_version`.
//!
//! `parse` consumes the stdout and stderr of a SEPARATE process (a wrong
//! version, a crashed build, or a binary that is not the expected tool at
//! all), which makes it an untrusted-input parser exactly like
//! `CellId::parse` (`fuzz_cell_id.rs`) and `LatencyRecorder::read_hgrm`
//! (`fuzz_hgrm_parse.rs`), and gets the same treatment. Contract: no panic,
//! no hang, no unbounded allocation, for arbitrary bytes as EITHER stdout or
//! stderr. `data` is fed to `parse` twice per adapter: once as stdout with
//! empty stderr, so the stdout parser is fuzzed, and once as stderr with a
//! FIXED valid stdout, so the stderr-handling code path (the warning
//! substring scan and the stderr size guard) is fuzzed too, rather than only
//! the stdout one.
//!
//! `parse_version` is fuzzed on the same bytes: it is a second, much
//! smaller untrusted-input parser (a version probe's stdout) that shares
//! `parse`'s "external process output" property.
//!
//! One fixed `ParseCtx` is built ONCE, at the top of the body, from the base
//! cell, a fixed `Invocation` and a fixed `ToolStamp`: the CONTEXT never
//! varies, only the byte slice does, matching `ParseCtx`'s own doc
//! ("`&`-borrowed, so `parse` stays pure and stays fuzzable").
//!
//! ADDING AN ADAPTER: append one entry to `ADAPTERS` below. Everything else
//! (the stdout path, the stderr path, the shared assertions) is generic over
//! `&dyn LoadGenerator` already.
//!
//! # Known CI gap (#756)
//!
//! `crates/irontraffic-bench/fuzz/seed_corpus/fuzz_loadgen_json/` holds real
//! seeds (see that directory's own contents: a genuine oha capture, and one
//! input per rejection branch this parser has). CI's fuzz job invokes
//! `cargo fuzz run` with NO positional corpus argument, and `fuzz/corpus/`
//! is gitignored (`fuzz/.gitignore`), so on a fresh CI checkout this target
//! (like every other seeded target in this crate) starts from an EMPTY
//! corpus and the committed seeds above are never read automatically. A
//! LOCAL run that wants the seeds must pass the directory explicitly:
//! `cargo +nightly fuzz run fuzz_loadgen_json corpus/fuzz_loadgen_json seed_corpus/fuzz_loadgen_json -- -runs=200000`
//! (paths relative to `crates/irontraffic-bench/fuzz/`). This is not fixed
//! here: #756 tracks the CI invocation fix repo wide, and this crate's own
//! files list for this issue does not include `.github/workflows/ci.yml`.

use irontraffic_bench::{
    BenchCell, CacheMode, CellId, Invocation, KeepaliveMode, LoadGenerator, MAX_REPORTED_REQUESTS,
    Oha, ParseCtx, PathCorpus, Protocol, RateMode, RawRun, TlsMode, ToolStamp,
};
use libfuzzer_sys::fuzz_target;

/// A real, otherwise-valid oha capture, reused as the FIXED stdout when
/// fuzzing the stderr path. The same file `tests/loadgen_oha.rs` uses as its
/// own authority (`parse_fixture`), so this target and the unit tests agree
/// on what "a valid run" looks like.
const VALID_STDOUT: &[u8] = include_bytes!("../../tests/fixtures/oha-1.15.0.json");

#[allow(
    clippy::expect_used,
    reason = "fuzz-target setup, not the code under fuzzing: \"fuzz\" is a fixed, valid cell id \
              literal, so this cannot fail"
)]
fn base_cell() -> BenchCell {
    BenchCell {
        id: CellId::parse("fuzz").expect("\"fuzz\" is a valid cell id"), // it-allow: no-panic reason: "fuzz" is a fixed literal matching CellId::parse's own character class (lowercase ASCII, one segment, well under the length caps), never data derived from the fuzzer's input, so this can never fail for any `data` this target is given.
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

/// Every registered adapter's parser is fuzzed by this one target. Adding an
/// adapter in a later issue is exactly one more line here.
fn adapters() -> [&'static dyn LoadGenerator; 1] {
    [&Oha]
}

/// Shared, adapter-agnostic assertions on a successful parse. Matches the
/// issue's own fuzz contract: `duration_ns > 0`, `requests_sent` within
/// bound, and the reconstructed histogram's percentile chain is monotone.
///
/// Also asserts issue #411's invariants 3 and 9
/// (`sum(status_counts) + errors == requests_sent`, computed in `u128` so
/// two hostile buckets near `u64::MAX` cannot wrap the identity into
/// holding). Before PR 799 review finding 1 (status-code key aliasing,
/// "0200" and "+200" both parsing to 200) was fixed, an aliased key made
/// this parser return `Ok` with a `RawRun` whose status map summed to less
/// than `requests_sent - errors`, and this target's previous contract
/// (duration, request cap, percentile monotonicity only) could never catch
/// that: none of those three checks reads `status_counts` at all. This
/// assertion is a REGRESSION CONTRACT on that class, correct and worth
/// keeping, and NOT a discovery mechanism: round two's review handed the
/// reverted parser the aliasing input directly and confirmed this assertion
/// aborts on it, then ran three separate campaigns totalling 8,974,995
/// executions against the still-vulnerable parser (the shipped six seeds at
/// the PR's own `-runs=200000` extended to 25 minutes, those seeds plus a
/// full-size seed one `ChangeByte` from the bug, and a single 257-byte
/// minimal seed one byte from the bug at `-max_len=400`) and found zero
/// crashes. The reason is structural, not a budget shortfall: an aliased
/// key such as "0200" takes exactly the same parser branches as the
/// canonical "200", so libFuzzer has no coverage gradient to climb toward
/// the bug, and finding this class by fuzzing alone would require blind
/// luck on a specific byte. This assertion would catch a REGRESSION of the
/// fix (the parser check in `oha.rs` that actually closes the class), not
/// discover the class in the first place.
fn check_ok_raw_run(raw: &RawRun) {
    assert!(raw.duration_ns > 0, "an Ok parse must never yield a zero duration");
    assert!(
        raw.requests_sent <= MAX_REPORTED_REQUESTS,
        "an Ok parse must never exceed MAX_REPORTED_REQUESTS"
    );
    let status_sum: u128 = raw.status_counts.values().map(|v| u128::from(*v)).sum();
    assert_eq!(
        status_sum + u128::from(raw.errors),
        u128::from(raw.requests_sent),
        "invariants 3 and 9: sum(status_counts) + errors must equal requests_sent"
    );
    let p = raw.latency.percentiles();
    assert!(p.p50_ns <= p.p90_ns);
    assert!(p.p90_ns <= p.p99_ns);
    assert!(p.p99_ns <= p.p999_ns);
    assert!(p.p999_ns <= p.p9999_ns);
    assert!(p.p9999_ns <= p.max_ns);
}

fuzz_target!(|data: &[u8]| {
    let cell = base_cell();
    let invocation = Invocation {
        program: "oha".to_owned(),
        args: vec!["--version".to_owned()],
        env: Vec::new(),
    };
    let tool = ToolStamp {
        name: "oha".to_owned(),
        version: "1.15.0".to_owned(),
        image_digest: None,
    };
    let ctx = ParseCtx {
        cell: &cell,
        invocation: &invocation,
        tool: &tool,
    };

    for adapter in adapters() {
        // parse_version: a second, smaller untrusted-input parser.
        let _ = adapter.parse_version(data);

        // Stdout path: `data` varies, stderr is empty.
        if let Ok(raw) = adapter.parse(&ctx, data, b"") {
            check_ok_raw_run(&raw);
        }

        // Stderr path: stdout is FIXED and valid, `data` varies. This is
        // what actually exercises the stderr size guard and the
        // rate-warning substring scan under arbitrary bytes, rather than
        // only ever handing them a clean, empty stderr.
        if let Ok(raw) = adapter.parse(&ctx, VALID_STDOUT, data) {
            check_ok_raw_run(&raw);
        }
    }
});
