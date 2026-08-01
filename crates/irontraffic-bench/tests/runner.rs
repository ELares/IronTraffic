// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests against `it-origin`, using a trivial pass-through stub
//! binary (compiled once, at test setup, from an embedded source string
//! rather than a second Cargo target this issue's own Files table does not
//! declare) as the system under test.
//!
//! # Why a compiled fixture and not a shell script
//!
//! The system under test needs to accept a real TCP connection, relay bytes
//! to `it-origin`, and (for `reconciliation_mismatch_fails`) misreport its
//! own request counter. A single small Rust source, compiled once with the
//! same pinned `rustc` this workspace already requires and cached for the
//! whole test binary via [`std::sync::OnceLock`], is simpler and more
//! portable than a shell/`nc` pipeline, and needs no new Cargo target (this
//! issue's own Files table lists none).
//!
//! # oha, not h2load or Nighthawk
//!
//! `h2load` needs `libnghttp2`/OpenSSL/`libev`/`c-ares` and `Nighthawk` needs
//! a container runtime; neither is installed on this development host. Tests
//! that need `run_repetition` to complete a full repetition therefore use
//! `oha` (installed here, pinned version confirmed) as `generator`, skipping
//! silently when it is absent, matching test 11's own wording. This project
//! denies `print_stdout`/`print_stderr` workspace wide with no test
//! exemption, so a skip cannot be announced; see `tests/probe.rs`'s own
//! identical note on `response_scan_is_total`.
//! The origin-ceiling measurement (Design step 2) still needs a
//! `RateMode::Saturate`-capable adapter in `adapters`; [`CeilingProbe`] is a
//! test-only `LoadGenerator` that drives the SAME installed `oha` binary in
//! its own default (no `-q`) unlimited-rate mode, which is a real saturate
//! measurement even though the shipped `Oha` adapter deliberately refuses to
//! model saturate cells at all (see `Oha::supports`'s own doc for why that
//! refusal is a judgment call about latency trustworthiness, not a hard tool
//! limitation).

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use irontraffic_bench::{
    BenchCell, BenchError, Bottleneck, CacheMode, CellAggregate, CellId, Child, CoreAssignment,
    CoreSet, DeepestPercentile, InvariantId, Invocation, KeepaliveMode, LatencyRecorder,
    LoadGenerator, ParseCtx, PathCorpus, Percentiles, Protocol, Provenance, RateMode, RawRun,
    RunParams, RunParamsFull, RunResult, TlsMode, ToolStamp, Unsupported, Validity,
    parse_stat_cpu_ticks, reconcile, run_cell, run_repetition,
};

// ---------------------------------------------------------------------------
// The compiled test fixture.
// ---------------------------------------------------------------------------

const FIXTURE_SOURCE: &str = r#"
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn flag_value(args: &[String], name: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == name)?;
    args.get(pos + 1).cloned()
}

fn respond_ok(mut s: TcpStream) {
    // Keep-alive, looping for as many requests as this connection sends:
    // the probe holds ONE persistent connection, and a one-shot,
    // Connection: close response here would force it to reconnect before
    // every single request, which starves it of the 5 second per-exchange
    // deadline budget it needs to also notice a recorder-reset request.
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
                if s.write_all(resp).is_err() {
                    break;
                }
            }
        }
    }
}

fn respond_stats(mut s: TcpStream) {
    let mut buf = [0u8; 4096];
    let _ = s.read(&mut buf);
    let body = b"{\"requests\":999999999,\"bytes\":0,\"rejects\":0,\"uptime_ms\":0}";
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
}

fn relay(client: TcpStream, upstream_addr: &str) {
    let upstream = match TcpStream::connect(upstream_addr) {
        Ok(u) => u,
        Err(_) => return,
    };
    let mut client_r = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut upstream_w = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };
    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_r, &mut upstream_w);
    });
    let mut upstream_r = upstream;
    let mut client_w = client;
    let _ = std::io::copy(&mut upstream_r, &mut client_w);
    let _ = t1.join();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") => {
            // Mimics `irontraffic run --config <path> --bind <addr> --upstream <addr>`:
            // a trivial pass-through TCP relay, ignoring the CONTENTS of
            // --config entirely (but see the retry-once trigger below,
            // which uses the --config PATH, not its contents).
            let bind = flag_value(&args, "--bind").expect("--bind required");
            let upstream = flag_value(&args, "--upstream").expect("--upstream required");
            // Retry-once test support (run_cell's own tests): a sibling
            // trigger file next to the rendered config, present only when a
            // test deliberately created it before calling run_cell. Every
            // OTHER test's config directory never has one (this checks
            // metadata, not contents), so this is a no-op for them.
            // run_repetition builds the SUT's argument list itself with no
            // room for a purpose-built CLI flag, and params.work_dir (and
            // therefore this rendered config path) is the ONE piece of
            // per-call state a test already controls that reaches the SUT's
            // own command line at all.
            if let Some(config) = flag_value(&args, "--config") {
                let trigger = std::path::Path::new(&config).with_file_name("force-first-sut-failure");
                if std::fs::metadata(&trigger).is_ok() {
                    let _ = std::fs::remove_file(&trigger);
                    eprintln!("fixture: deliberate first-attempt SUT failure (retry-once trigger)");
                    std::process::exit(7);
                }
            }
            let listener = TcpListener::bind(&bind).expect("bind failed");
            for stream in listener.incoming() {
                if let Ok(client) = stream {
                    let upstream = upstream.clone();
                    std::thread::spawn(move || relay(client, &upstream));
                }
            }
        }
        Some(s) if s.starts_with("--") => {
            // Mimics `it-origin --listen <addr> --stats-listen <addr>`, but
            // /stats always reports a fixed, deliberately wrong count, for
            // reconciliation_mismatch_fails.
            let listen = flag_value(&args, "--listen").expect("--listen required");
            let stats_listen = flag_value(&args, "--stats-listen").expect("--stats-listen required");
            let listener = TcpListener::bind(&listen).expect("bind failed");
            let stats_listener = TcpListener::bind(&stats_listen).expect("stats bind failed");
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if let Ok(s) = stream {
                        std::thread::spawn(move || respond_ok(s));
                    }
                }
            });
            for stream in stats_listener.incoming() {
                if let Ok(s) = stream {
                    std::thread::spawn(move || respond_stats(s));
                }
            }
        }
        Some("hang-stderr") => {
            let text = args.get(2).cloned().unwrap_or_default();
            eprint!("{text}");
            let _ = std::io::stderr().flush();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Some("ansi-stderr-exit") => {
            eprint!("\x1b[2J\x1b[1;1H\n");
            let _ = std::io::stderr().flush();
        }
        Some("listen-forever") => {
            let bind = flag_value(&args, "--bind").expect("--bind required");
            let listener = TcpListener::bind(&bind).expect("bind failed");
            for stream in listener.incoming() {
                if let Ok(mut s) = stream {
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 1024];
                        loop {
                            match s.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    });
                }
            }
        }
        Some("fork-listener") => {
            let bind = flag_value(&args, "--bind").expect("--bind required");
            let exe = std::env::current_exe().expect("current_exe");
            let _child = std::process::Command::new(exe)
                .arg("listen-forever")
                .arg("--bind")
                .arg(&bind)
                .spawn()
                .expect("spawn grandchild failed");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        other => {
            eprintln!("unknown fixture mode: {other:?}");
            std::process::exit(2);
        }
    }
}
"#;

/// Compiles [`FIXTURE_SOURCE`] once and returns the path to the resulting
/// binary, shared by every test in this process.
#[allow(
    clippy::expect_used,
    reason = "test setup helper, not itself a #[test] fn"
)]
fn fixture_binary() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("it-bench-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        let src_path = dir.join("fixture.rs");
        std::fs::write(&src_path, FIXTURE_SOURCE).expect("write fixture source");
        let out_path = dir.join("fixture_bin");
        let status = std::process::Command::new("rustc")
            .arg("--edition")
            .arg("2021")
            .arg("-O")
            .arg("-o")
            .arg(&out_path)
            .arg(&src_path)
            .status()
            .expect("spawn rustc to build the test fixture");
        assert!(status.success(), "rustc failed to build the test fixture");
        out_path
    })
    .as_path()
}

/// True when `oha` is installed and reachable on `PATH`.
fn oha_available() -> bool {
    std::process::Command::new("oha")
        .arg("--version")
        .output()
        .is_ok()
}

/// The absolute path to the `it-origin` executable, building it first if
/// necessary.
///
/// NOT `env!("CARGO_BIN_EXE_it-origin")`: `CARGO_BIN_EXE_<name>` is
/// populated only for binaries of the package whose own test is being
/// compiled, never for a dependency's binaries, even a path dependency in
/// the same workspace (confirmed empirically here, matching
/// `tests/probe.rs`'s own identical finding and identical fix: asking
/// `cargo` itself, once per test binary process, to build `it-origin` and
/// report its own artifact path via `--message-format=json`).
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test-support setup, not itself a #[test] fn: building an already-compiling sibling \
              crate's binary with cargo does not fail on a working test host, and a failure here \
              is reported as a failed test with a clear message rather than an inscrutable one \
              later"
)]
fn origin_binary() -> PathBuf {
    static BIN_PATH: OnceLock<String> = OnceLock::new();
    let path = BIN_PATH.get_or_init(|| {
        let output = std::process::Command::new("cargo")
            .args([
                "build",
                "--locked",
                "--package",
                "irontraffic-origin",
                "--bin",
                "it-origin",
                "--message-format=json",
            ])
            .output()
            .expect("origin_binary: run cargo build");
        assert!(
            output.status.success(),
            "cargo build -p irontraffic-origin --bin it-origin failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact")
            {
                continue;
            }
            let Some(executable) = value.get("executable").and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            if std::path::Path::new(executable).file_name()
                == Some(std::ffi::OsStr::new("it-origin"))
            {
                return executable.to_owned();
            }
        }
        panic!(
            "origin_binary: cargo build never reported an it-origin executable artifact:\n{stdout}"
        );
    });
    PathBuf::from(path)
}

fn fresh_work_dir(label: &str) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("it-bench-test-{label}-{}-{n}", std::process::id()))
}

// ---------------------------------------------------------------------------
// A test-only saturate-capable adapter for the origin-ceiling step. See the
// module doc.
// ---------------------------------------------------------------------------

struct CeilingProbe;

impl LoadGenerator for CeilingProbe {
    fn name(&self) -> &'static str {
        "test_ceiling_probe"
    }

    fn version_invocation(&self) -> Invocation {
        Invocation {
            program: "oha".to_owned(),
            args: vec!["--version".to_owned()],
            env: Vec::new(),
        }
    }

    fn parse_version(&self, _stdout: &[u8]) -> Result<ToolStamp, BenchError> {
        Ok(ToolStamp {
            name: self.name().to_owned(),
            version: "0.0.0-test".to_owned(),
            image_digest: None,
        })
    }

    fn supports(&self, cell: &BenchCell) -> Result<(), Unsupported> {
        if matches!(cell.rate, RateMode::Saturate) {
            Ok(())
        } else {
            Err(Unsupported::RateMode {
                tool: self.name(),
                detail: "test-only: this fixture adapter only models saturate cells",
            })
        }
    }

    fn plan(
        &self,
        cell: &BenchCell,
        target: &irontraffic_bench::Target,
        run: &RunParams,
    ) -> Result<Invocation, BenchError> {
        let scheme = match target.scheme {
            irontraffic_bench::Scheme::Http => "http",
            irontraffic_bench::Scheme::Https => "https",
        };
        let url = format!("{scheme}://{}{}", target.connect, target.path_expr);
        let args = vec![
            "--no-tui".to_owned(),
            "--output-format".to_owned(),
            "json".to_owned(),
            "-c".to_owned(),
            cell.connections.to_string(),
            "-z".to_owned(),
            format!("{}s", run.duration_secs),
            url,
        ];
        Ok(Invocation {
            program: "oha".to_owned(),
            args,
            env: Vec::new(),
        })
    }

    fn parse(
        &self,
        ctx: &ParseCtx<'_>,
        stdout: &[u8],
        _stderr: &[u8],
    ) -> Result<RawRun, BenchError> {
        let value: serde_json::Value = serde_json::from_slice(stdout)
            .map_err(|e| BenchError::parse("test_ceiling_probe", &e.to_string()))?;
        let summary = value
            .get("summary")
            .ok_or_else(|| BenchError::parse("test_ceiling_probe", "missing summary"))?;
        let total_secs = summary
            .get("total")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0);
        let mut status_counts: BTreeMap<u16, u64> = BTreeMap::new();
        let mut ok_sum: u64 = 0;
        if let Some(obj) = value
            .get("statusCodeDistribution")
            .and_then(serde_json::Value::as_object)
        {
            for (k, v) in obj {
                let code: u16 = k.parse().unwrap_or(0);
                let count = v.as_u64().unwrap_or(0);
                status_counts.insert(code, count);
                ok_sum = ok_sum.saturating_add(count);
            }
        }
        let mut error_sum: u64 = 0;
        if let Some(obj) = value
            .get("errorDistribution")
            .and_then(serde_json::Value::as_object)
        {
            for v in obj.values() {
                error_sum = error_sum.saturating_add(v.as_u64().unwrap_or(0));
            }
        }
        let bytes_received = summary
            .get("totalData")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        #[allow(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "total_secs is a small (at most tens of seconds), non-negative duration \
                      oha itself reported; this is test-support code converting it to nanoseconds \
                      for a synthetic RawRun, not a security or correctness boundary"
        )]
        let duration_ns = (total_secs * 1_000_000_000.0).max(0.0) as u64;
        Ok(RawRun {
            tool: ctx.tool.clone(),
            command_line: ctx.invocation.command_line(),
            requests_sent: ok_sum.saturating_add(error_sum),
            responses_ok: ok_sum,
            errors: error_sum,
            status_counts,
            bytes_received,
            duration_ns,
            latency: LatencyRecorder::new()?,
            ttfb: None,
            connect: None,
            stall: None,
            out_of_range: 0,
            latency_exact: false,
            latency_trustworthy: false,
        })
    }
}

// ---------------------------------------------------------------------------
// Shared cell and params fixtures.
// ---------------------------------------------------------------------------

#[allow(
    clippy::expect_used,
    reason = "test setup helper, not itself a #[test] fn"
)]
fn test_cell(id: &str) -> BenchCell {
    BenchCell {
        id: CellId::parse(id).expect("valid cell id"),
        protocol: Protocol::H1,
        tls: TlsMode::Off,
        payload_bytes: 0,
        routes: 1,
        path_corpus: PathCorpus::SingleHot,
        connections: 4,
        upstreams: 1,
        filter_depth: 0,
        cache: CacheMode::Bypass,
        keepalive: KeepaliveMode::Both,
        // A high enough rate that the 0.1 percent reconciliation tolerance
        // (RECONCILE_TOLERANCE_PERMILLE) is itself at least a handful of
        // requests wide: at a low rate the absolute tolerance rounds down to
        // 0 or 1, and a single connection still "in flight" at the exact
        // moment the client exits (the in_flight_at_end term reconcile's own
        // doc names as legitimately unaccounted for) would then fail a
        // perfectly healthy repetition.
        rate: RateMode::Fixed(2000),
    }
}

#[allow(
    clippy::expect_used,
    reason = "test setup helper, not itself a #[test] fn"
)]
fn test_provenance() -> Provenance {
    use irontraffic_bench::{BuildStamp, StampSource};
    let mut p = Provenance {
        utc_date: "2026-07-24T00:00:00Z".to_owned(),
        hardware: "Example CPU, 8c/16t, 32 GiB".to_owned(),
        cpu_model: "Example CPU".to_owned(),
        cpu_arch: "aarch64".to_owned(),
        physical_cores: 8,
        physical_cores_assumed: false,
        logical_cores: 16,
        mem_bytes: 32 * 1024 * 1024 * 1024,
        instance_type: None,
        burstable: false,
        kernel: "6.1.0-generic".to_owned(),
        clocksource: "tsc".to_owned(),
        governor: Some("performance".to_owned()),
        thermal_throttle_count: Some(0),
        ulimit_nofile: 1_048_576,
        ip_local_port_range: Some((32_768, 60_999)),
        sut: BuildStamp {
            name: "sut".to_owned(),
            version: "0.1.0".to_owned(),
            git_sha: "0a1b2c3d4e5f".to_owned(),
            dirty: false,
            profile: "release".to_owned(),
            features: Vec::new(),
            stamp_source: StampSource::Fallback,
        },
        origin: BuildStamp {
            name: "it-origin".to_owned(),
            version: "0.1.0".to_owned(),
            git_sha: "0a1b2c3d4e5f".to_owned(),
            dirty: false,
            profile: "release".to_owned(),
            features: Vec::new(),
            stamp_source: StampSource::Fallback,
        },
        loadgen: ToolStamp {
            name: "oha".to_owned(),
            version: "1.15.0".to_owned(),
            image_digest: None,
        },
        warmup_seconds: 2,
        measure_seconds: 3,
        repetitions: 1,
        publishable: false,
        unpublishable_reasons: vec!["test fixture provenance".to_owned()],
    };
    p.recompute_publishable();
    p
}

fn core_assignment() -> CoreAssignment {
    let logical = std::thread::available_parallelism().map_or(8, std::num::NonZero::get);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "available_parallelism on any real development or CI host is far below u32::MAX"
    )]
    let logical_u32 = logical as u32;
    #[allow(
        clippy::expect_used,
        reason = "test setup helper, not itself a #[test] fn"
    )]
    CoreSet::partition(logical_u32.max(8)).expect("at least 8 logical cores on the test host")
}

fn test_params(label: &str, warmup_secs: u32, measure_secs: u32) -> RunParamsFull {
    RunParamsFull {
        warmup_secs,
        measure_secs,
        cores: core_assignment(),
        sut_binary: fixture_binary().to_path_buf(),
        origin_binary: origin_binary(),
        work_dir: fresh_work_dir(label),
        target_host: "bench.test".to_owned(),
        deepest_percentile: DeepestPercentile::P99,
        probe_rate_hz: 100,
    }
}

// ---------------------------------------------------------------------------
// 11-13, 15: full run_repetition / run_cell tests.
//
// This project denies `print_stdout`/`print_stderr` workspace wide, with no
// test exemption (see `tests/probe.rs`'s own identical note on
// `response_scan_is_total`), so a test that must be skipped when `oha` is
// absent returns silently rather than printing a notice; the assertion
// itself, when it does run, is where the evidence lives.
// ---------------------------------------------------------------------------

#[test]
fn repetition_produces_a_result() {
    if !oha_available() {
        return;
    }
    let cell = test_cell("runner_t11");
    let oha = irontraffic_bench::Oha;
    let ceiling = CeilingProbe;
    let adapters: Vec<&dyn LoadGenerator> = vec![&oha, &ceiling];
    let params = test_params("t11", 2, 3);
    let provenance = test_provenance();

    let outcome = run_repetition(&cell, &oha, &adapters, &params, &provenance);
    let (result, _recorder) =
        outcome.expect("run_repetition must succeed for a healthy fixture proxy");
    assert!(result.rps > 0.0, "rps must be nonzero, got {}", result.rps);
    // Reviewed finding: the origin-ceiling step (Design step 2), the
    // correction this issue was reopened for, had no test that would fail
    // if it were skipped and origin_ceiling_rps left at 0.0, the exact trap
    // Design forbids by name twice ("Never skip the ceiling measurement and
    // leave origin_ceiling_rps at 0" / "Note the trap it declined to walk
    // into... Do not take it"). This assertion is unconditional (not nested
    // inside any one verdict arm below) because a healthy repetition must
    // have measured a real ceiling regardless of which verdict it lands on.
    assert!(
        result.origin_ceiling_rps > 0.0,
        "origin_ceiling_rps must be a real, positive measurement, never the skipped-step \
         placeholder of 0.0, got {}",
        result.origin_ceiling_rps
    );
    // Reviewed finding: sut_cores must be the SUT's OWN pinned core count
    // (Design step 11: "RunResult::sut_cores is params.cores.sut.len() as
    // u32 and nothing else"), never provenance.logical_cores (the whole
    // machine's count, which test_provenance() fixes at 16 regardless of
    // this host's real core count, giving this assertion real
    // discriminating power against that specific substitution).
    assert_eq!(
        result.sut_cores,
        u32::try_from(params.cores.sut.len()).unwrap_or(u32::MAX),
        "sut_cores must equal the SUT's own pinned core count, never the whole machine's \
         logical_cores"
    );
    // "a Valid or explicitly-named verdict" (test 11's own wording): every
    // arm is named explicitly, exhaustively, rather than defaulted through a
    // wildcard, and every arm asserts something concrete about it.
    match &result.validity {
        Validity::Valid => {}
        // Reviewed finding: this arm used to be merged with Valid's and had
        // an EMPTY body, silently accepting the exact mislabel a skipped
        // ceiling measurement produces: guards.rs's own step_i2 reads a zero
        // ceiling as LoadgenSuspect(OriginCeiling), so an empty arm here
        // could not tell a genuine loadgen-suspect verdict apart from that
        // mislabel. A healthy fixture run must never be OriginCeiling
        // specifically (the origin_ceiling_rps assertion above already
        // guards the underlying cause, but asserting on the verdict too
        // means a future refactor that reintroduces the mislabel some other
        // way still gets caught here).
        Validity::LoadgenSuspect { reason } => {
            assert!(
                !matches!(reason, irontraffic_bench::SuspectReason::OriginCeiling),
                "a healthy fixture run must not be mislabelled LoadgenSuspect(OriginCeiling); \
                 that is exactly the mislabel a zero or skipped origin_ceiling_rps produces"
            );
        }
        Validity::Invalid { detail, .. } => {
            assert!(
                detail.as_str().bytes().all(|b| (0x20..=0x7E).contains(&b)),
                "an Invalid verdict's detail must be printable ASCII, got {:?}",
                detail.as_str()
            );
        }
        Validity::Unstable { iqr_permille } => {
            assert!(
                *iqr_permille > 100,
                "an Unstable verdict must carry an iqr_permille above the 100 threshold, got \
                 {iqr_permille}"
            );
        }
    }
}

#[test]
fn warmup_samples_are_discarded() {
    if !oha_available() {
        return;
    }
    let cell = test_cell("runner_t12");
    let oha = irontraffic_bench::Oha;
    let ceiling = CeilingProbe;
    let adapters: Vec<&dyn LoadGenerator> = vec![&oha, &ceiling];
    let params = test_params("t12", 2, 3);
    let provenance = test_provenance();

    let (result, recorder) = run_repetition(&cell, &oha, &adapters, &params, &provenance)
        .expect("run_repetition must succeed for a healthy fixture proxy");
    assert!(
        result.warmup_samples_discarded > 0,
        "warmup_samples_discarded must be positive after a nonzero warmup"
    );
    // The probe runs at 100 requests per second; a 3 second measurement
    // therefore expects roughly 300 samples (measured directly on this host:
    // 286-289 across repeated runs). This assertion is inherently
    // timing-sensitive (the probe is a real thread racing the harness's own
    // wait loop on a host whose load this test does not control), so a wide
    // band is used and a failure here is EITHER host starvation or a real
    // defect, not distinguishable from inside this test; treat it as
    // inconclusive, not as confidently one or the other.
    //
    // Reviewed finding: the issue's own test 12 requires "the probe's final
    // sample count is close to measure_secs * 100", and the ORIGINAL
    // assertion here only checked `> 0`, satisfiable by a single sample.
    // That left the whole warmup-discard rule unverified: replacing the
    // real `probe.reset_recorders()?` call with a hardcoded constant (so
    // every warmup sample stays in the published histogram) measured
    // final_samples=500 on this host (all of warmup_secs + measure_secs,
    // 5s * 100/s), comfortably above the upper bound below; forcing
    // has_internal_warmup true unconditionally (skipping the separate
    // warmup invocation the Design mandates for every non-h2load tool)
    // measured final_samples=125, comfortably below the lower bound. The
    // correct code measured 286-289 across repeated runs, well inside
    // [180, 420].
    let final_samples = recorder.len();
    assert!(
        final_samples > 0,
        "the probe's final sample count must be positive, got {final_samples}"
    );
    assert!(
        (180..420).contains(&final_samples),
        "the probe's final published sample count ({final_samples}) should be close to \
         measure_secs * probe_rate_hz (3 * 100 = 300, measured at 286-289 on the development \
         host), not close to the full warmup-plus-measure lifetime total (500, the signature of \
         warmup samples never being discarded) or a fraction cut short by a skipped separate \
         warmup invocation (125, the signature of has_internal_warmup wrongly forced true); a \
         value outside [180, 420) is EITHER a real regression in the warmup-discard rule OR \
         extreme host starvation distorting the probe's own pacing, not distinguishable from \
         inside this test"
    );
}

#[test]
fn teardown_leaves_no_children() {
    let cell = test_cell("runner_t13");
    let oha = irontraffic_bench::Oha;
    let ceiling = CeilingProbe;
    let adapters: Vec<&dyn LoadGenerator> = vec![&oha, &ceiling];
    let mut params = test_params("t13", 1, 1);
    params.sut_binary = PathBuf::from("/nonexistent/binary/does-not-exist");
    let provenance = test_provenance();

    // No `oha_available()` guard: this test's own assertion is only that
    // the repetition fails, which holds whether it fails at step 0 (no
    // `oha` to probe a version from) or, when `oha` is installed, at step 3
    // (the SUT itself). Either way, nothing must survive the failure.
    let outcome = run_repetition(&cell, &oha, &adapters, &params, &provenance);
    assert!(
        outcome.is_err(),
        "pointing the SUT at a nonexistent binary must fail the repetition"
    );
    // Reviewed finding: this test's only assertion is the one above, which
    // says nothing about children (emptying Child's own Drop impl entirely
    // left this test green while leaking a live it-origin process). This
    // function cannot check that itself: run_repetition's own children are
    // fully encapsulated inside it and it returns no pid on any path, Err
    // included. `proc::tests::drop_without_an_explicit_stop_call_still_tears_down_the_child`
    // (crates/irontraffic-bench/src/proc.rs) is where the "no child
    // survives" invariant this test's own name promises is actually
    // asserted, against a real pid, with no explicit stop() call anywhere
    // in that test either: the same mechanism run_repetition's own Drop
    // guards rely on here.
}

#[test]
fn reconciliation_mismatch_fails() {
    if !oha_available() {
        return;
    }
    let cell = test_cell("runner_t15");
    let oha = irontraffic_bench::Oha;
    let ceiling = CeilingProbe;
    let adapters: Vec<&dyn LoadGenerator> = vec![&oha, &ceiling];
    let mut params = test_params("t15", 1, 2);
    // The origin role is played by the SAME fixture binary, in its
    // fake-origin mode (dispatched on a bare `--listen` flag with no
    // subcommand, mimicking it-origin's own CLI shape), whose `/stats`
    // endpoint always reports a fixed, deliberately wrong request count,
    // guaranteeing a reconciliation mismatch regardless of what the load
    // client actually sent. This is the one test in this file that does NOT
    // use the real it-origin binary, because the real one cannot be made to
    // misreport its own counter from outside.
    params.origin_binary = fixture_binary().to_path_buf();
    let provenance = test_provenance();

    let err = run_repetition(&cell, &oha, &adapters, &params, &provenance)
        .expect_err("a deliberately wrong origin counter must fail reconciliation");
    match err {
        BenchError::Parse { detail, .. } => {
            let text = detail.as_str();
            assert!(
                text.contains("origin_requests"),
                "reconciliation failure detail {text:?} must name origin_requests"
            );
            // Reviewed finding: "origin_requests" is a literal in reconcile's
            // own format string, so the assertion above is satisfied
            // regardless of what the actual values were; recorder_count_mismatch_is_error's
            // sibling test in tests/aggregate.rs asserts on the real numbers
            // instead, and this test should follow it. The fixture's fake
            // `/stats` handler returns the SAME hardcoded literal count on
            // every read, so the baseline-to-end DELTA reconcile() actually
            // computes is deterministically 0 (999999999 - 999999999), never
            // the fixture's own irrelevant literal: assert on that real,
            // computed number.
            assert!(
                text.contains("origin_requests 0"),
                "reconciliation failure detail {text:?} must show the origin side of the \
                 mismatch as the actual number reconcile() computed (0, the baseline-to-end \
                 delta of the fixture's own constant /stats counter), not merely mention the \
                 label"
            );
        }
        other => panic!("expected BenchError::Parse naming both counts, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Reviewed finding: run_cell is exported from lib.rs but was never called
// from any test in the workspace, leaving its own orchestration (the
// repetition loop, the retry-once policy, the `retried` flag) completely
// unexercised. These three tests drive run_cell itself, not just
// run_repetition or CellAggregate::from_runs in isolation.
// ---------------------------------------------------------------------------

#[test]
fn run_cell_aggregates_the_requested_repetition_count() {
    if !oha_available() {
        return;
    }
    let cell = test_cell("runner_run_cell_ok");
    let oha = irontraffic_bench::Oha;
    let ceiling = CeilingProbe;
    let adapters: Vec<&dyn LoadGenerator> = vec![&oha, &ceiling];
    let params = test_params("run_cell_ok", 1, 1);
    let provenance = test_provenance();

    // Each repetition reconciles a real load client's own request count
    // against the origin's, within a 0.1 percent tolerance: on a host under
    // heavy concurrent load (many repetitions' worth of oha, it-origin and
    // probe processes all competing for CPU at once), a repetition can fail
    // that reconciliation for real, causing run_cell to retry once and
    // (rarely) still fail if the retry lands under the same contention.
    // Either failure below is EITHER host starvation or a genuine defect in
    // run_cell's own orchestration, not distinguishable from inside this
    // test.
    let (aggregate, recorders) = run_cell(&cell, &oha, &adapters, &params, &provenance, 2)
        .unwrap_or_else(|e| {
            panic!(
                "run_cell must succeed for a healthy fixture proxy, got {e:?} (EITHER a genuine \
                 run_cell defect OR host contention causing a real reconciliation mismatch under \
                 concurrent load, not distinguishable from inside this test)"
            )
        });
    assert_eq!(
        aggregate.runs.len(),
        2,
        "run_cell must run exactly the requested repetition count, not a fixed number"
    );
    assert_eq!(
        recorders.len(),
        2,
        "run_cell must return one probe recorder per repetition"
    );
    assert!(
        !aggregate.retried,
        "an all-success run_cell call must report retried: false; if this repetition genuinely \
         needed a retry under real host contention (not a run_cell defect), that is itself an \
         honest signal this test cannot separate from a defect from inside itself"
    );
}

#[test]
fn run_cell_retries_once_then_propagates_a_persistent_failure() {
    if !oha_available() {
        return;
    }
    let cell = test_cell("runner_run_cell_retry_persist");
    let oha = irontraffic_bench::Oha;
    let ceiling = CeilingProbe;
    let adapters: Vec<&dyn LoadGenerator> = vec![&oha, &ceiling];
    let mut params = test_params("run_cell_retry_persist", 1, 1);
    params.sut_binary = PathBuf::from("/nonexistent/binary/does-not-exist");
    let provenance = test_provenance();

    let start = Instant::now();
    let outcome = run_cell(&cell, &oha, &adapters, &params, &provenance, 3);
    let elapsed = start.elapsed();

    assert!(
        outcome.is_err(),
        "a permanently broken SUT must fail run_cell even after the one retry edge case 15 \
         allows"
    );
    // Each attempt pays the full origin-ceiling measurement's own budget
    // (CEILING_RUN_SECONDS, 10s) before ever reaching the broken SUT spawn
    // in step 3, so two attempts (the initial one plus the one retry) cost
    // roughly twice one attempt's own time (measured directly on this host:
    // a single attempt is ~10-11s, two are ~20-22s). A floor comfortably
    // between those two, not a tight one: this is a real wall-clock signal
    // that the retry actually ran a second full repetition rather than
    // returning after the first failure, but on an EXTREMELY starved host a
    // single attempt could also be inflated past this floor, in which case
    // this assertion is inconclusive between host starvation and the
    // retry-once policy silently regressing to zero retries, not a
    // confident failure of the policy either way.
    assert!(
        elapsed >= Duration::from_secs(16),
        "run_cell took {elapsed:?} against a permanently broken SUT; the retry-once policy \
         (edge case 15) costs roughly two origin-ceiling runs (~20s measured on this host), and \
         a duration this short is the signature of a retry that silently stopped happening \
         (though on an extremely fast, unloaded host this could also be a false alarm from \
         tighter-than-expected timing, not distinguishable from inside this test)"
    );
}

#[test]
fn run_cell_retries_once_and_records_retried_true() {
    if !oha_available() {
        return;
    }
    let cell = test_cell("runner_run_cell_retry_ok");
    let oha = irontraffic_bench::Oha;
    let ceiling = CeilingProbe;
    let adapters: Vec<&dyn LoadGenerator> = vec![&oha, &ceiling];
    let params = test_params("run_cell_retry_ok", 1, 1);
    let provenance = test_provenance();

    // Arrange exactly ONE deliberate SUT failure: the fixture's own "run"
    // mode (see its own comment) checks for this exact trigger file, next
    // to the rendered sut.yaml, and consumes it on the first sight. Every
    // repetition and retry within one run_cell call shares the SAME
    // params.work_dir (run_cell never varies it), so this is stable across
    // exactly the calls this test needs it stable across, and unique to
    // this one test's own work_dir otherwise.
    std::fs::create_dir_all(&params.work_dir).expect("create work_dir for the trigger file");
    let trigger = params.work_dir.join("force-first-sut-failure");
    std::fs::write(&trigger, b"trigger").expect("write the retry-once trigger file");

    // The retry (the second attempt) is a real repetition against the SAME
    // real oha/it-origin/probe process tree as every other end-to-end test
    // here, so on a host under heavy concurrent load it can ALSO fail for a
    // genuine, unrelated reason (reconciliation timing), which run_cell has
    // no third attempt left to recover from. A failure here is EITHER that
    // host-contention case OR a real defect in the retry-once policy, not
    // distinguishable from inside this test.
    let (aggregate, recorders) = run_cell(&cell, &oha, &adapters, &params, &provenance, 1)
        .unwrap_or_else(|e| {
            panic!(
                "run_cell must succeed once the one retry clears the deliberate first failure, \
                 got {e:?} (EITHER the retry-once policy is broken OR the retry itself hit real \
                 host contention, not distinguishable from inside this test)"
            )
        });
    assert_eq!(aggregate.runs.len(), 1);
    assert_eq!(recorders.len(), 1);
    assert!(
        aggregate.retried,
        "a repetition that only passed on retry must set retried: true, not hide it"
    );
}

// ---------------------------------------------------------------------------
// 14, 20: Child::wait_ready directly.
// ---------------------------------------------------------------------------

#[test]
fn readiness_timeout_includes_stderr() {
    let invocation = Invocation {
        program: fixture_binary().display().to_string(),
        args: vec![
            "hang-stderr".to_owned(),
            "distinctive-marker-9f3e".to_owned(),
        ],
        env: Vec::new(),
    };
    let cores = CoreSet::partition(core_assignment_logical_cores())
        .map_or_else(|_| default_probe_core_set(), |assignment| assignment.probe);
    let mut child = Child::spawn(&invocation, &cores, "readiness_timeout_test")
        .expect("spawning the fixture must succeed");
    // A port nothing listens on: the fixture never binds anything.
    let never_listens: SocketAddr = "127.0.0.1:1"
        .parse()
        .unwrap_or_else(|_| panic!("127.0.0.1:1 must parse as a socket address"));
    // 3 seconds, not a tight bound: the fixture's stderr write is captured
    // by a background reader thread this call does not control the
    // scheduling of, and a short timeout here would race that thread on a
    // busy host. If this assertion ever fails, that is EITHER genuine host
    // starvation (the reader thread never got scheduled in time) OR a real
    // capture defect, and this test cannot tell the two apart from inside
    // itself; treat a failure as inconclusive, not as confidently one or
    // the other.
    let err = child
        .wait_ready(never_listens, Duration::from_secs(3))
        .expect_err("a child that never listens must time out");
    let text = err.to_string();
    assert!(
        text.contains("distinctive-marker-9f3e"),
        "readiness-timeout error {text:?} must include the child's own stderr text (this is \
         either genuine host starvation of the capture reader thread or a real capture defect, \
         not distinguishable from inside this test)"
    );
    child.stop();
}

#[test]
fn readiness_error_is_sanitised() {
    let invocation = Invocation {
        program: fixture_binary().display().to_string(),
        args: vec!["ansi-stderr-exit".to_owned()],
        env: Vec::new(),
    };
    let cores = default_probe_core_set();
    let mut child = Child::spawn(&invocation, &cores, "readiness_sanitised_test")
        .expect("spawning the fixture must succeed");
    let never_listens: SocketAddr = "127.0.0.1:1"
        .parse()
        .unwrap_or_else(|_| panic!("127.0.0.1:1 must parse as a socket address"));
    // 3 seconds: see readiness_timeout_includes_stderr's own comment on why
    // this is not a tight bound.
    let err = child
        .wait_ready(never_listens, Duration::from_secs(3))
        .expect_err("a child that exits without ever listening must be reported as a failure");
    let text = err.to_string();
    assert!(
        text.bytes().all(|b| (0x20..=0x7E).contains(&b)),
        "readiness error {text:?} must contain only printable ASCII"
    );
    assert!(
        !text.contains('\x1b'),
        "readiness error {text:?} must not contain a raw escape byte"
    );
    child.stop();
}

fn default_probe_core_set() -> CoreSet {
    core_assignment().probe
}

fn core_assignment_logical_cores() -> u32 {
    let logical = std::thread::available_parallelism().map_or(8, std::num::NonZero::get);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "available_parallelism on any real development or CI host is far below u32::MAX"
    )]
    let logical_u32 = logical as u32;
    logical_u32.max(8)
}

// ---------------------------------------------------------------------------
// 16, 17: CoreSet::partition.
// ---------------------------------------------------------------------------

#[test]
fn core_partition_requires_eight_cores() {
    let err = CoreSet::partition(4).expect_err("fewer than 8 logical cores must be refused");
    let text = err.to_string();
    assert!(text.contains('4'), "error {text:?} must name the count 4");
}

#[test]
fn core_partition_is_disjoint() {
    let assignment = CoreSet::partition(16).expect("16 logical cores must partition successfully");
    let sets = [
        &assignment.origin,
        &assignment.sut,
        &assignment.client,
        &assignment.probe,
    ];
    let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut total = 0usize;
    for set in sets {
        for &core in set.iter() {
            assert!(
                seen.insert(core),
                "core {core} appears in more than one role's set"
            );
            total += 1;
        }
    }
    assert!(
        total <= 16,
        "the four sets must cover at most 16 cores, covered {total}"
    );
}

// ---------------------------------------------------------------------------
// 18: saturate cells never publish cpu_seconds_per_request.
// ---------------------------------------------------------------------------

#[allow(
    clippy::expect_used,
    reason = "test setup helper, not itself a #[test] fn"
)]
fn round_trip_result(cpu_seconds_per_request: Option<f64>, rate: RateMode) -> RunResult {
    let mut status_counts = BTreeMap::new();
    status_counts.insert(200_u16, 1000_u64);
    let mut cell = test_cell("runner_t18");
    cell.rate = rate;
    RunResult {
        cell: cell.id.clone(),
        cell_def: cell,
        provenance: test_provenance(),
        rps: 5000.0,
        latency: zero_percentiles(),
        probe_latency: zero_percentiles(),
        ttfb: zero_percentiles(),
        connect: zero_percentiles(),
        stall: zero_percentiles(),
        cpu_seconds_per_request,
        rss_bytes: 0,
        pss_bytes: 0,
        bytes_received: 0,
        payload_bytes: 0,
        total_requests: 1000,
        status_counts,
        origin_ceiling_rps: 10_000.0,
        direct_rps: 10_000.0,
        client_cpu_max_pct: 10.0,
        sut_cores: 4,
        catchup_burst_count: 0,
        out_of_range: 0,
        stall_out_of_range: 0,
        stall_backwards_count: 0,
        warmup_samples_discarded: 100,
        deepest_percentile: DeepestPercentile::P99,
        bottleneck: Bottleneck::Unknown,
        validity: Validity::Valid,
        command_line: "test-client".to_owned(),
    }
}

fn zero_percentiles() -> Percentiles {
    Percentiles {
        p50_ns: 0,
        p90_ns: 0,
        p99_ns: 0,
        p999_ns: 0,
        p9999_ns: 0,
        max_ns: 0,
        samples: 0,
    }
}

#[test]
fn saturate_cell_has_no_cpu_per_request() {
    let saturate = round_trip_result(None, RateMode::Saturate);
    assert_eq!(saturate.cpu_seconds_per_request, None);
    #[allow(clippy::expect_used, reason = "the test's own assertion path")]
    let json = serde_json::to_string(&saturate).expect("serialise saturate result");
    #[allow(clippy::expect_used, reason = "the test's own assertion path")]
    let back: RunResult = serde_json::from_str(&json).expect("deserialise saturate result");
    assert_eq!(back, saturate);

    let fixed = round_trip_result(Some(0.000_123), RateMode::Fixed(1000));
    assert!(matches!(fixed.cpu_seconds_per_request, Some(v) if v.is_finite()));
    #[allow(clippy::expect_used, reason = "the test's own assertion path")]
    let json = serde_json::to_string(&fixed).expect("serialise fixed-rate result");
    #[allow(clippy::expect_used, reason = "the test's own assertion path")]
    let back: RunResult = serde_json::from_str(&json).expect("deserialise fixed-rate result");
    assert_eq!(back, fixed);
}

// ---------------------------------------------------------------------------
// 19: teardown kills the whole process group.
// ---------------------------------------------------------------------------

#[test]
fn teardown_kills_the_whole_process_group() {
    let port = {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a port");
        listener.local_addr().expect("read local_addr").port()
    };
    let bind_addr = format!("127.0.0.1:{port}");
    let invocation = Invocation {
        program: fixture_binary().display().to_string(),
        args: vec![
            "fork-listener".to_owned(),
            "--bind".to_owned(),
            bind_addr.clone(),
        ],
        env: Vec::new(),
    };
    let cores = default_probe_core_set();
    let mut child =
        Child::spawn(&invocation, &cores, "fork_listener_test").expect("spawn fork-listener");

    // Give the grandchild a moment to actually bind before tearing down.
    // Timing-sensitive: on a sufficiently starved host this wait might not
    // be enough for the grandchild to have bound yet, in which case the
    // port-free assertion below would pass for the wrong reason (nothing
    // ever bound) rather than the reason under test (teardown killed it);
    // that ambiguity, not a confident pass or fail either way, is the
    // correct reading of this test on a loaded host.
    std::thread::sleep(Duration::from_millis(500));

    // Reviewed finding: without this check, this test could pass for the
    // wrong reason on a starved host where the 500ms grace above was not
    // enough for the grandchild to have bound yet (nothing to kill means
    // the port-free assertion below trivially holds, proving nothing about
    // teardown at all). This turns that silent ambiguity into an explicit,
    // separately labelled signal: if THIS fails, the rest of the test is
    // inconclusive about teardown specifically and should be read as host
    // starvation, not a defect in Child::stop.
    assert!(
        TcpListener::bind(&bind_addr).is_err(),
        "the grandchild must already be bound to {bind_addr} before teardown is exercised; if \
         this fails, the 500ms grace period above was not enough on this host for the grandchild \
         to bind (host starvation), not evidence that teardown itself is broken"
    );

    child.stop();

    // Give the killed grandchild's socket a moment to actually release.
    std::thread::sleep(Duration::from_millis(200));

    let rebind = TcpListener::bind(&bind_addr);
    assert!(
        rebind.is_ok(),
        "the port must be free after teardown; the grandchild must be gone, not just the direct child"
    );
}

// ---------------------------------------------------------------------------
// 21: /proc/<pid>/stat parsing survives a spaced comm field.
// ---------------------------------------------------------------------------

#[test]
fn proc_stat_parsing_survives_a_spaced_comm() {
    let line = b"12345 (my proxy (v2)) S 1 12345 12345 0 -1 4194304 10 0 5 0 300 150 0 0 20 0 1 0";
    let (utime, stime) = parse_stat_cpu_ticks(line).expect("a well-formed line must parse");
    assert_eq!(utime, 300);
    assert_eq!(stime, 150);

    let no_paren = b"this line has no closing paren at all";
    assert!(parse_stat_cpu_ticks(no_paren).is_err());
}

// ---------------------------------------------------------------------------
// 22: merged sample count below the deepest percentile's requirement.
// ---------------------------------------------------------------------------

#[allow(
    clippy::expect_used,
    reason = "test setup helper, not itself a #[test] fn"
)]
fn aggregate_result(id: &str, p99_ns: u64) -> RunResult {
    let mut r = round_trip_result(None, RateMode::Fixed(1000));
    r.cell = CellId::parse(id).expect("valid cell id");
    r.cell_def.id = r.cell.clone();
    r.probe_latency = Percentiles {
        p50_ns: p99_ns,
        p90_ns: p99_ns,
        p99_ns,
        p999_ns: p99_ns,
        p9999_ns: p99_ns,
        max_ns: p99_ns,
        samples: 1,
    };
    r
}

fn recorder_with(value_ns: u64, count: u64) -> LatencyRecorder {
    #[allow(
        clippy::expect_used,
        reason = "test setup helper, not itself a #[test] fn"
    )]
    let mut recorder = LatencyRecorder::new().expect("LatencyRecorder::new must succeed");
    recorder.record_n_ns(value_ns, count);
    recorder
}

#[test]
fn merged_below_required_samples_is_invalid() {
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("runner_t22").expect("valid cell id");

    let runs: Vec<RunResult> = (0..5)
        .map(|i| aggregate_result("runner_t22", 100 + i))
        .collect();
    let short_recorders: Vec<LatencyRecorder> = vec![
        recorder_with(100, 2_000),
        recorder_with(100, 2_000),
        recorder_with(100, 2_000),
        recorder_with(100, 2_000),
        recorder_with(100, 1_999),
    ];
    let short_total: u64 = short_recorders.iter().map(LatencyRecorder::len).sum();
    assert_eq!(short_total, 9_999);
    let aggregate = CellAggregate::from_runs(cell_id.clone(), runs.clone(), &short_recorders)
        .expect("from_runs must succeed");
    match aggregate.validity {
        Validity::Invalid { violated, .. } => assert_eq!(violated, InvariantId::I5),
        other => panic!("expected Invalid(I5, ..) at 9,999 samples, got {other:?}"),
    }

    let full_recorders: Vec<LatencyRecorder> = vec![
        recorder_with(100, 2_000),
        recorder_with(100, 2_000),
        recorder_with(100, 2_000),
        recorder_with(100, 2_000),
        recorder_with(100, 2_000),
    ];
    let full_total: u64 = full_recorders.iter().map(LatencyRecorder::len).sum();
    assert_eq!(full_total, 10_000);
    let aggregate2 =
        CellAggregate::from_runs(cell_id, runs, &full_recorders).expect("from_runs must succeed");
    assert_eq!(aggregate2.validity, Validity::Valid);
}

// ---------------------------------------------------------------------------
// 23: iqr_permille does not wrap on extreme p99 values.
// ---------------------------------------------------------------------------

#[test]
fn iqr_does_not_wrap_on_extreme_p99_values() {
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("runner_t23").expect("valid cell id");
    // Includes u64::MAX: (q3 - q1) * 1000 in u64 would wrap into a small,
    // falsely stable number; the u128 widening in aggregate.rs's own
    // from_runs is what this test pins.
    let p99s = [u64::MAX, u64::MAX - 1, 100, 200, 300];
    let runs: Vec<RunResult> = p99s
        .iter()
        .map(|&p99| aggregate_result("runner_t23", p99))
        .collect();
    // The recorders' own recorded value is unrelated to the fake p99s above
    // (from_runs never reads a value back out of a recorder, only its
    // sample count for the step 7a check): a fixed, in-range value with
    // enough samples to clear the P99 threshold is all step 7a needs.
    let recorders: Vec<LatencyRecorder> = (0..5).map(|_| recorder_with(100, 2_000)).collect();
    let aggregate =
        CellAggregate::from_runs(cell_id, runs, &recorders).expect("from_runs must succeed");
    assert!(
        aggregate.iqr_permille > 0,
        "such widely spread p99 values must not report a wrapped, falsely small iqr_permille, got {}",
        aggregate.iqr_permille
    );
    // Reviewed finding: `> 0` alone does not pin the wrap this test is
    // named for, because replacing the u128 computation with
    // wrapping_mul(1000).wrapping_div(median) happened to ALSO produce a
    // nonzero value for this exact array. `iqr_permille` is min()-capped at
    // `u32::MAX` by construction (invariant 5b), and for THIS array the
    // ratio genuinely exceeds that cap, so the correct answer is exactly
    // u32::MAX; asserting that exact value, not just non-zero, is what a
    // wrapping u64 computation cannot coincidentally satisfy.
    assert_eq!(
        aggregate.iqr_permille,
        u32::MAX,
        "this array's true ratio (q3 - q1) * 1000 / median vastly exceeds u32::MAX, so the \
         correct, capped answer is exactly u32::MAX; anything else is evidence of a wrap"
    );
}

// ---------------------------------------------------------------------------
// 23 (reviewed finding, strengthened): the reviewer's own adversarial
// construction, which they confirmed empirically distinguishes the u128
// (capped) computation from a wrapping u64 one: p99 values
// [100, 100, 100, X, X] with X = 100 + 18_446_744_073_709_552 give
// iqr_permille = 4_294_967_295 (u32::MAX) under the correct, capped u128
// computation and iqr_permille = 3 under a wrapping u64 one (confirmed by
// landing that exact mutation against this exact input).
// ---------------------------------------------------------------------------

#[test]
fn iqr_caps_at_u32_max_on_the_reviewers_adversarial_input() {
    #[allow(clippy::expect_used, reason = "test-support helper call")]
    let cell_id = CellId::parse("runner_t23b").expect("valid cell id");
    let x: u64 = 100 + 18_446_744_073_709_552;
    let p99s = [100_u64, 100, 100, x, x];
    let runs: Vec<RunResult> = p99s
        .iter()
        .map(|&p99| aggregate_result("runner_t23b", p99))
        .collect();
    let recorders: Vec<LatencyRecorder> = (0..5).map(|_| recorder_with(100, 2_000)).collect();
    let aggregate =
        CellAggregate::from_runs(cell_id, runs, &recorders).expect("from_runs must succeed");
    assert_eq!(
        aggregate.iqr_permille,
        u32::MAX,
        "median = 100, q1 = 100, q3 = X: (X - 100) * 1000 / 100 vastly exceeds u32::MAX, so the \
         correct answer is exactly u32::MAX; a wrapping u64 computation on this exact input \
         produces 3, not this value"
    );
}

// ---------------------------------------------------------------------------
// 24: reconciliation uses integer arithmetic.
// ---------------------------------------------------------------------------

#[test]
fn reconciliation_uses_integer_arithmetic() {
    let err = reconcile(u64::MAX, 0, 0)
        .expect_err("u64::MAX client_requests against a 0 origin count must fail");
    let text = err.to_string();
    assert!(text.contains("18446744073709551615") || text.contains(&u64::MAX.to_string()));

    let err2 = reconcile(0, 1000, 0)
        .expect_err("0 client_requests against a nonzero origin count must fail");
    let text2 = err2.to_string();
    assert!(text2.contains('0'));
    assert!(text2.contains("1000"));
}
