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
//! stderr. `data` is fed to `parse` twice per adapter, through the shared
//! [`fuzz_adapter`] helper: once as stdout with empty stderr, so the stdout
//! parser is fuzzed, and once as stderr with a FIXED valid stdout, so the
//! stderr-handling code path (the warning substring scan and the stderr size
//! guard) is fuzzed too, rather than only the stdout one. The fixed valid
//! stdout is now PER ADAPTER (`OHA_VALID_STDOUT`, `NIGHTHAWK_VALID_STDOUT`),
//! not one shared constant: a single shared fixture would only ever be
//! valid-shaped for the one adapter it was captured from, so every other
//! adapter's stderr-path half would reach `check_ok_raw_run` only on the rare
//! mutation that happens to reconstruct its own whole valid document out of
//! arbitrary bytes, an unmeasured and likely near-zero reachability exactly
//! like the generator defect this milestone's own review process has caught
//! before.
//!
//! `parse_version` is fuzzed on the same bytes: it is a second, much
//! smaller untrusted-input parser (a version probe's stdout) that shares
//! `parse`'s "external process output" property.
//!
//! One fixed `ParseCtx` is built ONCE, at the top of the body, from the base
//! cell, a fixed `Invocation` and a fixed `ToolStamp`: the CONTEXT never
//! varies, only the byte slice does, matching `ParseCtx`'s own doc
//! ("`&`-borrowed, so `parse` stays pure and stays fuzzable"). It is shared
//! across every adapter: `ctx.cell.keepalive == KeepaliveMode::Both` makes
//! `Nighthawk::parse`'s `connect` optional rather than required, and
//! `ctx.cell.rate` being `Fixed` makes every adapter's `latency_trustworthy`
//! true; nothing else in `ctx` is adapter specific.
//!
//! ADDING AN ADAPTER: add one `const <NAME>_VALID_STDOUT` fixture and one
//! `fuzz_adapter(&<Adapter>, &ctx, data, <NAME>_VALID_STDOUT)` call in the
//! `fuzz_target!` body below. `Nighthawk` could not use a `'static` array of
//! trait objects the way a future all-unit-struct adapter list could
//! (`Oha` is a zero-sized, `Copy` unit struct that Rust const-promotes to
//! `'static`; `Nighthawk` owns `String` fields built at runtime, which
//! cannot be), so each adapter is fuzzed by its own explicit call rather
//! than by iterating a shared array.
//!
//! # Known CI gap (#756)
//!
//! `crates/irontraffic-bench/fuzz/seed_corpus/fuzz_loadgen_json/` holds real
//! seeds (see that directory's own contents: a genuine oha capture, one
//! input per rejection branch this parser has, a genuine `-n 10` capture
//! that exercises the small-`requests_sent` regression bound in
//! `check_ok_raw_run`'s own doc below, and an aliased-status-key document
//! that makes this same function's aliasing regression contract fire on
//! its first execution, not on a mutation libFuzzer would have to find on
//! its own). CI's fuzz job invokes
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
    BenchCell, CacheMode, CellId, ContainerRuntime, H2Load, Invocation, KeepaliveMode,
    LoadGenerator, Nighthawk, Oha, ParseCtx, PathCorpus, Protocol, RateMode, RawRun, TlsMode,
    ToolStamp, Vegeta, MAX_REPORTED_REQUESTS,
};
use libfuzzer_sys::fuzz_target;

/// A real, otherwise-valid oha capture, reused as the FIXED stdout when
/// fuzzing the stderr path. The same file `tests/loadgen_oha.rs` uses as its
/// own authority (`parse_fixture`), so this target and the unit tests agree
/// on what "a valid run" looks like.
const OHA_VALID_STDOUT: &[u8] = include_bytes!("../../tests/fixtures/oha-1.15.0.json");

/// The Nighthawk fixture `tests/loadgen_nighthawk.rs` also uses as its own
/// authority, reused here for the identical reason `OHA_VALID_STDOUT` is: see
/// that constant's own doc. Unlike `OHA_VALID_STDOUT`, this is NOT a genuine
/// capture (see `src/loadgen/nighthawk.rs`'s own module doc for why one could
/// not be produced in this environment), only a reconstruction cross-checked
/// against the real upstream Nighthawk source; it is still the one input
/// that lets the stderr-path loop below reach `check_ok_raw_run` for
/// `Nighthawk` on every single execution, rather than only on the rare
/// mutation that happens to reconstruct a whole valid `results` document out
/// of the stdout-path's arbitrary bytes.
const NIGHTHAWK_VALID_STDOUT: &[u8] = include_bytes!("../../tests/fixtures/nighthawk-output.json");

/// The h2load fixture `tests/loadgen_h2load.rs` also uses as its own
/// authority, for the identical reason `NIGHTHAWK_VALID_STDOUT` is: also NOT
/// a genuine capture (see `src/loadgen/h2load.rs`'s own module doc for why),
/// only a reconstruction checked against the real `nghttp2` source at the
/// last tag whose `h2load.cc` still emits this text shape.
const H2LOAD_VALID_STDOUT: &[u8] = include_bytes!("../../tests/fixtures/h2load-output.txt");

/// The vegeta fixture `tests/loadgen_vegeta.rs` also uses as its own
/// authority. Unlike `H2LOAD_VALID_STDOUT`, this IS a genuine capture: a
/// real, locally built `vegeta v12.13.0` (`go install
/// github.com/tsenart/vegeta/v12@v12.13.0`; no `docker`/`podman` needed)
/// attacking a local HTTP server, per `tests/loadgen_vegeta.rs`'s own module
/// doc.
const VEGETA_VALID_STDOUT: &[u8] = include_bytes!("../../tests/fixtures/vegeta-report.json");

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

/// Runs both halves of this target's fuzz contract for one adapter: the
/// stdout path (`data` varies, stderr empty) and the stderr path (stdout
/// fixed to `valid_stdout`, `data` varies), plus `parse_version` on the same
/// bytes. Shared so every adapter this target ever gains gets the identical
/// treatment; see the module doc's "ADDING AN ADAPTER" note for why this is
/// a plain function call per adapter rather than a loop over a `'static`
/// array.
fn fuzz_adapter(adapter: &dyn LoadGenerator, ctx: &ParseCtx<'_>, data: &[u8], valid_stdout: &[u8]) {
    let _ = adapter.parse_version(data);

    if let Ok(raw) = adapter.parse(ctx, data, b"") {
        check_ok_raw_run(&raw);
    }

    if let Ok(raw) = adapter.parse(ctx, valid_stdout, data) {
        check_ok_raw_run(&raw);
    }
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
/// luck on a specific byte, which is exactly why
/// `seed_corpus/fuzz_loadgen_json/status_code_key_alias` now commits an
/// aliased-key document directly (a "200" and a "0200" bucket in the same
/// `statusCodeDistribution`): with that seed in place, this assertion DOES
/// catch a regression of the fix through the fuzz job itself, on the very
/// first execution of that seed, no mutation required, which was CONFIRMED
/// by reverting the canonical-rendering check in `oha.rs` and observing
/// this exact assertion abort on that one seed (`status_sum` 100 against
/// `requests_sent` 107). Before that seed existed, the honest statement was
/// the opposite: the assertion was correct but idle, because no committed
/// input reached it under an aliased key. What has caught a regression on
/// this class independent of the fuzz job, all along, is the unit test
/// `parse_rejects_status_code_key_aliasing` in `tests/loadgen_oha.rs`.
///
/// A second regression contract, added for PR 799 round three (issue
/// #804): round two's own fix floored the reconstruction weight to at
/// least 1 on BOTH branches unconditionally (`weight.max(1)` regardless of
/// `value_ns` or `requests_sent`), which forces every run to record at
/// least one sample per reported percentile (9) no matter how few requests
/// were actually sent, and MEASURABLY shifts the published percentile
/// (against genuine `oha 1.15.0` captures: the tool's own p75 published as
/// p50 at `-n 3`, its p90 at `-n 5`, its p75 again at `-n 100`; see
/// `tests/loadgen_oha.rs`'s `parse_pins_sample_count_against_requests_sent_for_genuine_captures`
/// for the exact numbers). The floor is legitimate only for an
/// out-of-range percentile (so the `out_of_range` tail-truncation signal
/// invariant I7 depends on is never silently dropped, edge case 9) or for
/// `requests_sent == 1` (the one case where all nine gaps legitimately
/// round to zero, see `oha.rs`'s own doc on the reconstruction loop). The
/// bound below is a LOOSE but mathematically safe upper bound on the
/// in-range sample count for any `requests_sent > 1`: each of the nine
/// fixed `PERCENTILE_KEYS` gaps sums to 0.9999, and rounding a single gap
/// to the nearest integer can move it by at most 0.5 from its exact value,
/// so summing all nine rounded gaps can exceed `requests_sent` by at most
/// `9 * 0.5 = 4.5` (an integer sample count, so at most 4) REGARDLESS of
/// `requests_sent`'s magnitude. The symmetric floor this bound is watching
/// for violates it at, for example, genuine `-n 3` (9 samples against a
/// bound of `3 + 4 = 7`) and `-n 10` (15 against `10 + 4 = 14`); it is
/// COARSER than `tests/loadgen_oha.rs`'s own exact pinning (which also
/// catches `-n 100`, 101 against an exact expected 100) because this
/// oracle, unlike that test, has no access to `oha.rs`'s own per-percentile
/// weights and so cannot recompute the exact expected count for an
/// arbitrary fuzzer-supplied `requests_sent`; it exists as a mechanical
/// backstop for whatever small `requests_sent` values the fuzzer happens to
/// explore, seeded by the genuine `-n 10` capture committed at
/// `seed_corpus/fuzz_loadgen_json/small_run_n10` so it is exercised on
/// every run, not left to mutation to rediscover.
fn check_ok_raw_run(raw: &RawRun) {
    assert!(
        raw.duration_ns > 0,
        "an Ok parse must never yield a zero duration"
    );
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
    if raw.requests_sent > 1 {
        // See this function's own doc for the derivation of the constant
        // 4 slack: it is a mathematical bound on independent per-key
        // rounding error, not an empirical guess, and it holds for every
        // `requests_sent > 1` regardless of magnitude.
        const ROUNDING_SLACK: u64 = 4;
        assert!(
            raw.latency.len() <= raw.requests_sent.saturating_add(ROUNDING_SLACK),
            "in-range sample count {} must track requests_sent {} (slack {ROUNDING_SLACK}), not \
             a floor independent of it: PR 799 round three's own regression (issue #804)",
            raw.latency.len(),
            raw.requests_sent,
        );
    }
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

    fuzz_adapter(&Oha, &ctx, data, OHA_VALID_STDOUT);

    // `Nighthawk`'s fields are `String`s built at runtime, never a `'static`
    // const-promoted value the way the zero-sized `Oha` unit struct is, so
    // it is constructed fresh here rather than added to a shared array.
    // Neither field's exact content matters to `parse`/`parse_version`
    // (`from_pin`'s own validation runs once, at construction, well before
    // this point, and is not itself under fuzz here): only `Nighthawk::name`
    // ("nighthawk", a `&'static str`) and the parsing logic in `parse`/
    // `parse_version` are exercised.
    let nighthawk = Nighthawk {
        runtime: ContainerRuntime::Docker,
        image: "envoyproxy/nighthawk-dev@sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_owned(),
        client_cores: "0-3".to_owned(),
    };
    fuzz_adapter(&nighthawk, &ctx, data, NIGHTHAWK_VALID_STDOUT);

    // `H2Load` is `Copy` (no owned heap data), like `Oha`, but is not
    // zero-sized (it carries a `threads: u16` field), so it is constructed
    // fresh here rather than `const`-promoted the way `Oha`'s own unit
    // struct is; see the module doc's "ADDING AN ADAPTER" note.
    let h2load = H2Load { threads: 4 };
    fuzz_adapter(&h2load, &ctx, data, H2LOAD_VALID_STDOUT);

    // `Vegeta`'s fields are owned (`PathBuf`), like `Nighthawk`'s `String`
    // fields, so it too is constructed fresh here.
    let vegeta = Vegeta {
        max_workers: 8,
        targets_path: "targets.txt".into(),
        output_path: "results.bin".into(),
    };
    fuzz_adapter(&vegeta, &ctx, data, VEGETA_VALID_STDOUT);
});
