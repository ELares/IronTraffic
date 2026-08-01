// SPDX-License-Identifier: MIT OR Apache-2.0
//! The runner: one repetition's full execution sequence, and running a cell
//! `k` times with a retry-once policy.
//!
//! # The full-matrix wall-time budget
//!
//! At `k = 5` repetitions, `W = 30` warmup seconds and `T = 60` measurement
//! seconds, one repetition costs the warmup plus the measurement plus a 10
//! second origin-ceiling run plus roughly 5 seconds of spawn, readiness and
//! teardown, so about `30 + 60 + 10 + 5 = 105` seconds. At `m = 62`
//! published cells, a full matrix costs `62 * 5 * 105 = 32,550` seconds,
//! which is about **9 hours** of wall time (`32,550 / 3600 ~= 9.04`). Cells
//! whose load generator needs a separate warmup invocation (every tool
//! except `h2load`) cost more, not less. An implementer who does not know
//! this number will design a CI job that tries to run the whole matrix on
//! every push.
//!
//! # Teardown is ordinary Rust drop order, not a bespoke stack
//!
//! `crate::proc::Child` already implements `Drop` (it calls `stop`, which
//! signals the whole process group). Declaring `origin_child`, then
//! `sut_child`, then `client_child` as plain local bindings, IN SPAWN ORDER,
//! is what makes Rust's own end-of-scope drop order (strictly the REVERSE of
//! declaration order) tear them down last-spawned-first on every exit path,
//! including an early `?` return or a panic, with no bespoke stack and no
//! match-and-cleanup repeated at each return. `ProbeHandle` has no `Drop` of
//! its own (its thread would otherwise run to its full `expected_requests`
//! count even after this function returns), so [`ProbeGuard`] exists to give
//! it one; every other resource here is already a `Child`.
//!
//! # Two adapter roles
//!
//! [`run_repetition`] takes `generator`, the adapter whose numbers get
//! published, and `adapters`, the full set of adapters the caller has
//! configured. The measurement (Design step 5) always uses `generator`. The
//! origin-ceiling measurement (Design step 2) is a `RateMode::Saturate` run
//! by construction, and `Oha::supports` refuses every `RateMode::Saturate`
//! cell unconditionally, so that step selects the FIRST adapter in
//! `adapters`, in order, whose `supports` accepts the cell with `rate`
//! replaced by `RateMode::Saturate`. If none does, the repetition fails
//! naming the cell and every refusal: leaving `origin_ceiling_rps` at 0
//! would make `check_validity`'s I2 step read the ceiling as
//! `LoadgenSuspect(OriginCeiling)`, mislabelling a harness gap as a
//! measurement problem, and this module never does that.
//!
//! # A disclosed gap: the rendered SUT configuration
//!
//! Design step 0a of this issue says the runner renders `<work_dir>/sut.yaml`
//! "in the source-document format `crates/irontraffic` already consumes",
//! with "one route per `RouteSpec`... plus `cell.filter_depth` no-op filters
//! and the cache mode". That format does not exist in this repository as of
//! this issue: `irontraffic_config::model::BootstrapDoc` (M1's own doc
//! comment reads "M1's process identity configuration") has no routing,
//! filter, or cache section at all, every one of its structs is
//! `#[serde(deny_unknown_fields)]`, `UpstreamSection`'s own doc comment reads
//! "The single upstream every connection is forwarded to in this version",
//! and `crates/irontraffic`'s own manifest does not depend on
//! `irontraffic-router` (the standalone crate that owns route-table types)
//! at all. This is a defect in the issue text, filed as a tracking issue
//! rather than blocking this one: none of this issue's own Tests exercise
//! the real `crates/irontraffic` binary as the system under test (they all
//! use a trivial pass-through stub instead, per the Tests section preamble),
//! so nothing here is checked against the real schema either way. Rendering
//! is therefore implemented against the fields the real schema DOES support
//! today (one listener, one upstream), with the cell's full routing
//! dimensions (`routes`, `upstreams`, `filter_depth`, `cache`) recorded as a
//! human-readable comment for a reader and left otherwise unexpressed: the
//! same disclosed-gap shape `crate::matrix`'s own `adversarial_entries` doc
//! already uses for `RouteShape::LastSegment`. A future issue that gives
//! `crates/irontraffic` a routing-capable configuration format must revisit
//! [`render_sut_yaml`].
//!
//! # A disclosed gap: `vegeta` as `generator`
//!
//! `Vegeta` needs a second process (`Vegeta::report_invocation()`, an
//! INHERENT method, not part of the `LoadGenerator` trait) after its first
//! exits successfully. `run_repetition` receives `generator: &dyn
//! LoadGenerator`, a trait object with no `downcast` available (the trait
//! does not extend `std::any::Any`, and `loadgen/mod.rs` is not a file this
//! issue's own Files table authorises touching), so there is no way to reach
//! `Vegeta::report_invocation` generically from here. `generator` is
//! therefore refused by name when it is `"vegeta"`, with a clear error
//! rather than a silently wrong single-process invocation. None of this
//! issue's own 24 named tests drives `run_repetition` with `vegeta` as
//! `generator`.
//!
//! # A disclosed gap: `direct_rps`
//!
//! [`RunResult::direct_rps`] documents itself, from `bench-runner-and-aggregation`'s
//! own earlier issue #408, as "Client rps against the origin with the proxy
//! bypassed": a run at the cell's OWN rate, not a saturate run. This issue's
//! own Design step 2 says of the origin-ceiling measurement, in so many
//! words, that conflating the two is wrong: "the null-proxy control in
//! `{{bench-bottleneck-attribution}}` is a different run at the cell's own
//! rate, and conflating the two is called out there." Design's own twelve
//! numbered steps, the ones this function actually implements, never define
//! or ask for that separate cell-rate, proxy-bypassed run at all; the
//! measurement `direct_rps` is supposed to hold belongs entirely to
//! `bench-bottleneck-attribution`, an issue that does not exist yet. Because
//! `RunResult::direct_rps` is a non-`Option<f64>` field and every produced
//! result must populate it, `run_repetition` sets `direct_rps` equal to
//! `origin_ceiling_rps`: the same saturate number Design step 2 warns
//! against treating as this one. This is exactly the conflation named above,
//! done anyway because there is no other value to put here without
//! inventing a whole new measurement run this issue's own Design section
//! never asks for (rule 1: do exactly what the issue says, nothing more).
//! `bench-bottleneck-attribution`, whenever it lands, must replace this
//! alias with its own null-proxy run; until then, every `RunResult` this
//! function produces carries the SAME number twice under two different
//! names, and a reader of `direct_rps` gets a saturate figure, not a
//! cell-rate one.
//!
//! # A disclosed gap: `run_cell`'s partial-cell context
//!
//! This issue's own Public API section says `run_cell`'s `# Errors` doc
//! should read "Propagates the first repetition error; completed repetitions
//! are returned in the error's context so a partial cell is still
//! inspectable." [`BenchError`] (`crate::error`, not a file this issue's own
//! Files table authorises touching) has no variant that carries a
//! `Vec<RunResult>` or any other structured payload beyond a `&'static str`
//! or a bounded, printable [`crate::error::Detail`] string: there is nowhere
//! to put completed repetitions inside the error this function actually
//! returns. `run_cell`'s own body reflects that: `attempt?` on the second,
//! non-retried failure propagates `BenchError` alone, and every repetition
//! collected before that point (in the local `runs` and `recorders`
//! `Vec`s) is dropped along with the rest of this function's stack frame.
//! A partial cell is therefore NOT inspectable from the returned `Err`
//! today; this is disclosed here, in the same shape as the other gaps
//! above, rather than silently omitted from this function's own doc
//! comment.
//!
//! # A disclosed gap: no syscall-counting benchmark test
//!
//! This issue's own `## Benchmarks` section states: "Both bounds are
//! asserted by a test that counts syscalls with `strace` where available and
//! is skipped elsewhere, with the skip recorded so it is visible rather than
//! silent." No such test exists in this crate. It is not one of the 27 named
//! tests in this issue's own `## Tests` section (1 through 24 plus the
//! property test), `strace` does not exist on this crate's own macOS
//! development host at all (so any such test would run its "skipped
//! elsewhere" branch here every time, verifying nothing on the one host this
//! work was implemented and gated on), and building a portable,
//! `strace`-wrapping child-process harness is a meaningfully sized new piece
//! of test machinery on its own. Recorded here as an honest gap rather than
//! left silently absent, matching this module's own established practice
//! for the other disclosed gaps above.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::CellAggregate;
use crate::cell::{BenchCell, RateMode, TlsMode};
use crate::error::BenchError;
use crate::hist::{LatencyRecorder, Percentiles};
use crate::loadgen::{Invocation, LoadGenerator, ParseCtx, RawRun, RunParams, Scheme, Target};
use crate::probe::{ProbeConfig, ProbeHandle, ProbeOutcome};
use crate::proc::Child;
use crate::provenance::{Provenance, SMALL_FILE_CAP, read_bounded};
use crate::result::{Bottleneck, DeepestPercentile, RunResult, Validity};

/// Default repetitions per cell.
pub const DEFAULT_REPETITIONS: u32 = 5;
/// Default discarded warmup seconds.
pub const DEFAULT_WARMUP_SECS: u32 = 30;
/// Default measured seconds.
pub const DEFAULT_MEASURE_SECS: u32 = 60;
/// Reconciliation tolerance between client, origin and error counts, in
/// permille.
pub const RECONCILE_TOLERANCE_PERMILLE: u64 = 1;

/// Wall-clock budget the origin-ceiling measurement (Design step 2) runs
/// for.
const CEILING_RUN_SECONDS: u32 = 10;
/// Wall-clock budget `wait_ready` allows for a child's TCP listener to come
/// up.
const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll interval for the warmup wait's absolute-deadline loop, and for the
/// "wait for the load client to exit" loop, which also drives the client CPU
/// sampler's tick.
const POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Wall-clock budget the origin `/stats` read is allowed.
const STATS_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Everything one repetition needs beyond the cell itself.
#[derive(Debug, Clone)]
pub struct RunParamsFull {
    /// Discarded warmup seconds. 30 for published runs.
    pub warmup_secs: u32,
    /// Measured seconds. 60 minimum for published runs.
    pub measure_secs: u32,
    /// Core assignment.
    pub cores: crate::proc::CoreAssignment,
    /// Path to the system-under-test binary.
    pub sut_binary: std::path::PathBuf,
    /// Path to `it-origin`.
    pub origin_binary: std::path::PathBuf,
    /// Directory for rendered configuration and captured child output.
    pub work_dir: std::path::PathBuf,
    /// `Host` header value the client and the probe send. The connect
    /// address is chosen by the runner, so this is the only part of the
    /// `Target` a caller supplies.
    pub target_host: String,
    /// Deepest percentile this cell intends to publish, copied into
    /// `RunResult::deepest_percentile` and read by invariant I5. It comes
    /// from the cell's `MatrixEntry`, which `run_repetition` does not
    /// receive.
    pub deepest_percentile: DeepestPercentile,
    /// Probe rate in requests per second. 100 for every published run.
    pub probe_rate_hz: u64,
}

/// Reconciles the load client's own request count against the origin's and
/// the client's own reported error count, in integer arithmetic widened to
/// `u128`.
///
/// `client_requests == origin_requests + proxy_errors + in_flight_at_end`;
/// the in-flight term is not observable from outside and is bounded by the
/// connection count, which at every published cell is far inside the 0.1
/// percent tolerance this function enforces instead of trying to name it
/// directly.
///
/// Never `0.001 * client_requests` in floating point: these are counts read
/// from a tool's output and from the origin's `/stats` endpoint, so they can
/// be `u64::MAX`, and a `u64` product wraps while the `f64` form loses
/// integer precision above 2^53. A `client_requests` of 0 makes the
/// tolerance 0, so any nonzero origin count correctly fails.
///
/// # Errors
/// `BenchError::Parse` naming both counts when the difference exceeds
/// [`RECONCILE_TOLERANCE_PERMILLE`] parts per thousand of `client_requests`.
pub fn reconcile(
    client_requests: u64,
    origin_requests: u64,
    proxy_errors: u64,
) -> Result<(), BenchError> {
    let expected = origin_requests.saturating_add(proxy_errors);
    let diff = u128::from(client_requests.abs_diff(expected));
    let allowed =
        u128::from(client_requests).saturating_mul(u128::from(RECONCILE_TOLERANCE_PERMILLE));
    if diff.saturating_mul(1000) <= allowed {
        return Ok(());
    }
    Err(BenchError::parse(
        "reconcile",
        &format!(
            "client reported {client_requests} requests but origin_requests + proxy_errors is \
             {expected} (origin_requests {origin_requests}, proxy_errors {proxy_errors}), beyond \
             the {RECONCILE_TOLERANCE_PERMILLE} permille tolerance"
        ),
    ))
}

/// A `ProbeHandle` that finishes itself on drop.
///
/// `ProbeHandle` (`crate::probe`, issue #410) has no `Drop` impl: its thread
/// runs until `finish` is called, however long that takes. Wrapping it here
/// is what makes Design step 12's "always, including on every early return"
/// true for the probe specifically; every other spawned resource in this
/// module is already a [`Child`], which has its own `Drop`.
struct ProbeGuard(Option<ProbeHandle>);

impl ProbeGuard {
    fn new(handle: ProbeHandle) -> Self {
        Self(Some(handle))
    }

    fn reset_recorders(&self) -> Result<u64, BenchError> {
        match &self.0 {
            Some(probe) => probe.reset_recorders(),
            None => Ok(0),
        }
    }

    /// Finishes the probe on the happy path and returns its outcome. After
    /// this, `Drop` has nothing left to do.
    fn take_and_finish(&mut self) -> Result<ProbeOutcome, BenchError> {
        match self.0.take() {
            Some(probe) => probe.finish(),
            None => Err(BenchError::Cell(
                "the probe was already finished once; take_and_finish must be called at most once",
            )),
        }
    }
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        if let Some(probe) = self.0.take() {
            let _ = probe.finish(); // it-allow: no-swallowed-error reason: Drop::drop cannot return a Result, and a probe thread panic (finish's only failure mode) is already reported by the panicking thread itself; there is no further action this guard could take with the error
        }
    }
}

/// Runs one repetition of one cell and returns its result plus the probe's
/// raw latency recorder, valid or not.
///
/// TWO ADAPTER ROLES, and they are not interchangeable. `generator` drives
/// the MEASUREMENT run at the cell's own rate; it is the adapter whose
/// numbers get published. `adapters` is the set the ORIGIN-CEILING run
/// selects from, because that run is a `RateMode::Saturate` run by
/// construction and `Oha::supports` refuses saturate unconditionally. Pass
/// every adapter the caller has configured, including `generator` itself.
/// Callers that hold only one adapter pass a one-element slice and must
/// expect the ceiling step to fail for a cell that adapter refuses, which is
/// the correct, loud outcome rather than a silent zero.
///
/// An invalid repetition is RECORDED, never discarded: the failing result is
/// the diagnostic. Children are always torn down, including on every early
/// return: see the module doc on Rust's own drop order.
///
/// # Errors
/// `BenchError::Io` for a spawn, readiness or teardown failure,
/// `BenchError::Parse` for unparsable tool output, a reconciliation mismatch
/// beyond 0.1 percent, or when no adapter in `adapters` accepts the cell's
/// saturate variant (naming the cell and every refusal, which
/// `BenchError::Cell`'s `&'static str` payload cannot carry: see
/// `select_ceiling_adapter`'s own doc), and `BenchError::Cell` when
/// `generator` is `"vegeta"` (see the module doc's disclosed gap).
#[allow(
    clippy::too_many_lines,
    reason = "one cohesive, linearly ordered repetition sequence (the Design section's own \
              twelve numbered steps); splitting it would scatter state (the spawned children, \
              the probe guard, the rendered addresses) that reads naturally kept in one place, \
              mirroring irontraffic-origin's own handle_connection and this crate's own \
              probe::run_probe"
)]
pub fn run_repetition(
    cell: &BenchCell,
    generator: &dyn LoadGenerator,
    adapters: &[&dyn LoadGenerator],
    params: &RunParamsFull,
    provenance: &Provenance,
) -> Result<(RunResult, LatencyRecorder), BenchError> {
    if generator.name() == "vegeta" {
        return Err(BenchError::Cell(
            "vegeta cannot be run_repetition's measurement generator: its second `report` \
             process is only reachable through a concrete &Vegeta, which this function's own \
             &dyn LoadGenerator signature cannot downcast to; see this module's own doc",
        ));
    }

    // Step 0: probe the tool's version and compare against the pin. Only
    // `generator` is checked; the ceiling-run adapter selected in step 2 is
    // a harness-internal choice, not a published tool, so it carries no pin.
    check_tool_pin(generator)?;

    // Step 0a: render the cell's configuration. See the module doc's
    // disclosed gap on the SUT configuration format.
    let work_dir_result = std::fs::create_dir_all(&params.work_dir); // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; this creates the one work directory a repetition writes into, once, before any child is spawned
    work_dir_result.map_err(|e| BenchError::io(&params.work_dir.display().to_string(), e))?;
    let sut_listen_addr = reserve_ephemeral_port()?;
    let origin_listen_addr = reserve_ephemeral_port()?;
    let origin_stats_addr = reserve_ephemeral_port()?;
    let sut_yaml_path = params.work_dir.join("sut.yaml");
    let sut_yaml = render_sut_yaml(cell, sut_listen_addr, origin_listen_addr);
    let sut_yaml_write_result = std::fs::write(&sut_yaml_path, sut_yaml); // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; this writes the rendered SUT configuration once, before the SUT is spawned, never on the measurement path
    sut_yaml_write_result.map_err(|e| BenchError::io(&sut_yaml_path.display().to_string(), e))?;

    // Step 1: spawn it-origin, wait for readiness. A plain local binding:
    // its own Drop tears it down last, per the module doc.
    let origin_invocation = Invocation {
        program: params.origin_binary.display().to_string(),
        args: vec![
            "--listen".to_owned(),
            origin_listen_addr.to_string(),
            "--stats-listen".to_owned(),
            origin_stats_addr.to_string(),
        ],
        env: Vec::new(),
    };
    let mut origin_child = Child::spawn(&origin_invocation, &params.cores.origin, "it-origin")?;
    origin_child.wait_ready(origin_listen_addr, READY_TIMEOUT)?;

    // Step 2: measure origin_ceiling_rps with a SATURATE run of the same
    // cell, pointed at the origin instead of the SUT.
    let (ceiling_adapter, saturate_cell) = select_ceiling_adapter(cell, adapters)?;
    let ceiling_target = Target {
        scheme: Scheme::Http,
        host: params.target_host.clone(),
        connect: origin_listen_addr,
        sni: None,
        path_expr: crate::path_expr(saturate_cell.path_corpus, saturate_cell.routes)?,
    };
    let ceiling_run = RunParams {
        duration_secs: CEILING_RUN_SECONDS,
        warmup_secs: 0,
        concurrency: None,
    };
    let ceiling_invocation = ceiling_adapter.plan(&saturate_cell, &ceiling_target, &ceiling_run)?;
    let ceiling_raw = run_one_shot_client(
        ceiling_adapter,
        &saturate_cell,
        &ceiling_invocation,
        &params.cores.client,
    )?;
    let ceiling_seconds = nanos_to_seconds(ceiling_raw.duration_ns);
    let origin_ceiling_rps = if ceiling_seconds > 0.0 {
        requests_as_f64(ceiling_raw.requests_sent) / ceiling_seconds
    } else {
        0.0
    };
    // Disclosed gap: see the module doc's own "A disclosed gap: direct_rps"
    // section. This is the exact conflation Design step 2 warns against
    // (origin_ceiling_rps is a SATURATE run; direct_rps documents itself as
    // a cell-rate, proxy-bypassed run), done anyway because this issue's own
    // Design never defines the separate measurement direct_rps is supposed
    // to hold and RunResult::direct_rps has no Option to leave unset.
    let direct_rps = origin_ceiling_rps;

    // Step 3: spawn the SUT, wait for readiness.
    let sut_invocation = Invocation {
        program: params.sut_binary.display().to_string(),
        args: vec![
            "run".to_owned(),
            "--config".to_owned(),
            sut_yaml_path.display().to_string(),
            "--bind".to_owned(),
            sut_listen_addr.to_string(),
            "--upstream".to_owned(),
            origin_listen_addr.to_string(),
        ],
        env: Vec::new(),
    };
    let mut sut_child = Child::spawn(&sut_invocation, &params.cores.sut, "sut")?;
    sut_child.wait_ready(sut_listen_addr, READY_TIMEOUT)?;

    // Baselined here, before the probe (which also talks to the SUT and
    // therefore to the origin, continuously, for the rest of the
    // repetition) and before the warmup and measurement invocations are
    // even planned: the origin's own /stats counter is cumulative since it
    // was spawned at step 1, already carries the origin-ceiling run's
    // direct traffic (step 2), and is about to additionally carry the
    // probe's own steady traffic for as long as it runs. NONE of that is
    // the load client's own traffic, and the Design's reconciliation
    // identity (`client_requests == origin_requests + proxy_errors +
    // in_flight_at_end`) is only true of the origin counter's DELTA over
    // exactly the measurement client's own lifetime, net of every other
    // legitimate source sharing the same origin; see the two subtractions
    // this baseline feeds at step 8 for the accounting this issue's own
    // Design text does not spell out, because it does not appear to have
    // considered that the probe and the load client both terminate at the
    // same single origin instance. `_settled`: the ceiling run in
    // particular offers as much load as the client can generate, and a
    // client that abandons an in-flight request on its own `-z` deadline
    // (rather than awaiting it) can leave bytes already written to a
    // kernel socket buffer still travelling to the origin after the client
    // process has already exited and been waited on;
    // `read_origin_stats_settled` polls until the counter stops moving
    // rather than trusting the first read.
    let origin_stats_baseline = read_origin_stats_settled(origin_stats_addr, &params.target_host)?;

    // Step 4: spawn the probe against the SUT, on a single fixed path.
    let single_hot_path = crate::path_expr(crate::PathCorpus::SingleHot, cell.routes)?;
    let expected_requests = u64::from(params.warmup_secs.saturating_add(params.measure_secs))
        .saturating_mul(params.probe_rate_hz);
    let probe_config = ProbeConfig {
        target: sut_listen_addr,
        host: params.target_host.clone(),
        path: single_hot_path,
        core_id: params.cores.probe.first().copied(),
        rate_hz: params.probe_rate_hz,
        expected_requests,
    };
    let time: irontraffic_time::SharedTime = Arc::new(irontraffic_time::SystemTimeSource::new());
    let mut probe = ProbeGuard::new(ProbeHandle::spawn(probe_config, time)?);

    // Step 5: build the Target the measurement run points at the SUT, and
    // start the load client (plus, for a tool with no internal warmup flag,
    // a separate warmup invocation first, whose RawRun this function keeps
    // just long enough to subtract its own request count from the origin
    // counter at step 8; the published RunResult never carries it).
    let measurement_target = Target {
        scheme: if cell.tls == TlsMode::Off {
            Scheme::Http
        } else {
            Scheme::Https
        },
        host: params.target_host.clone(),
        connect: sut_listen_addr,
        sni: if cell.tls == TlsMode::Off {
            None
        } else {
            Some(params.target_host.clone())
        },
        path_expr: crate::path_expr(cell.path_corpus, cell.routes)?,
    };

    // Every tool but h2load has no internal warmup flag: run the warmup as
    // a separate invocation. h2load takes its own `--warm-up-time` inside
    // the single invocation below instead, in which case there is no
    // separate warmup traffic to account for.
    let has_internal_warmup = generator.name() == "h2load";
    let warmup_requests_sent: u64 = if has_internal_warmup {
        0
    } else {
        let warmup_run = RunParams {
            duration_secs: params.warmup_secs,
            warmup_secs: 0,
            concurrency: None,
        };
        let warmup_invocation = generator.plan(cell, &measurement_target, &warmup_run)?;
        let warmup_raw =
            run_one_shot_client(generator, cell, &warmup_invocation, &params.cores.client)?;
        warmup_raw.requests_sent
    };

    let measurement_run = RunParams {
        duration_secs: params.measure_secs,
        warmup_secs: params.warmup_secs,
        concurrency: None,
    };
    let measurement_invocation = generator.plan(cell, &measurement_target, &measurement_run)?;
    let command_line = measurement_invocation.command_line();
    let mut client_child = Child::spawn(&measurement_invocation, &params.cores.client, "client")?;

    // Step 6: wait out the warmup against an absolute deadline computed
    // once, then reset the probe's recorders and snapshot the SUT's
    // measurement-window CPU baseline. h2load's own warmup runs INSIDE the
    // single invocation above, so this harness-side wait is 0 for it.
    let warmup_wait_secs = if has_internal_warmup {
        params.warmup_secs
    } else {
        0
    };
    let warmup_start = Instant::now(); // it-allow: determinism-seam reason: this is the harness's own warmup wait budget, computed once as an absolute deadline and recomputed on every poll from this instant, never a request-path clock read
    let warmup_end = warmup_start + Duration::from_secs(u64::from(warmup_wait_secs));
    loop {
        let now = Instant::now(); // it-allow: determinism-seam reason: recomputed every iteration against the absolute warmup_end deadline set above, never accumulated
        if now >= warmup_end {
            break;
        }
        std::thread::sleep(POLL_INTERVAL.min(warmup_end.saturating_duration_since(now))); // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime anywhere in it; this is the warmup wait itself, the one thing this loop exists to do. it-allow: no-accumulated-sleep reason: the sleep duration is recomputed every iteration from the absolute warmup_end deadline above, never an accumulating relative sleep, so a spurious wakeup or overshoot cannot accumulate across iterations
    }
    let warmup_samples_discarded = probe.reset_recorders()?;
    let sut_cpu_at_warmup_end = sut_child.cpu_seconds().ok();

    // Step 7: wait for the load client to exit, with a hard timeout, while
    // sampling client CPU utilisation once per second.
    let hard_timeout = Duration::from_secs(
        2 * (u64::from(params.warmup_secs) + u64::from(params.measure_secs)) + 60,
    );
    let wait_start = Instant::now(); // it-allow: determinism-seam reason: bounds the hard timeout on the load client's own exit, recomputed every iteration from this absolute instant, never a request-path clock read
    let mut client_cpu_max_pct: f64 = 0.0;
    let mut prev_percore = read_percore_ticks(&params.cores.client);
    let mut last_sample = Instant::now(); // it-allow: determinism-seam reason: paces the once-per-second client CPU sample against this repetition's own wall clock, not a request-path read
    loop {
        match client_child.raw_mut().try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {}
            Err(_wait_failed) => break,
        }
        let now_waiting = Instant::now(); // it-allow: determinism-seam reason: checked every iteration against the absolute wait_start plus hard_timeout deadline, never accumulated
        if now_waiting.saturating_duration_since(wait_start) >= hard_timeout {
            client_child.stop();
            return Err(BenchError::io(
                "client",
                std::io::Error::other(format!(
                    "load client exceeded the {hard_timeout:?} hard timeout"
                )),
            ));
        }
        std::thread::park_timeout(POLL_INTERVAL); // it-allow: no-accumulated-sleep reason: a fixed poll tick bounded by the wait_start.elapsed() >= hard_timeout deadline check above on every iteration; a spurious wakeup only costs one extra tick and never accumulates
        let now = Instant::now(); // it-allow: determinism-seam reason: paces the once-per-second sample below against this repetition's own wall clock, not a request-path read
        if now.saturating_duration_since(last_sample) >= Duration::from_secs(1) {
            last_sample = now;
            let sample = read_percore_ticks(&params.cores.client);
            if let (Some(prev), Some(cur)) = (&prev_percore, &sample)
                && let Some(pct) = percore_utilisation_pct(prev, cur)
            {
                client_cpu_max_pct = client_cpu_max_pct.max(pct);
            }
            prev_percore = sample;
        }
    }

    // Step 8: stop the probe, read the origin's /stats, snapshot the SUT's
    // counters again. origin_requests is the baseline-to-end delta, with the
    // probe's own total issued count and the warmup invocation's own
    // request count both subtracted: both share the same origin as the
    // measurement client (see the baseline's own comment), and neither is
    // the load client's own traffic that reconciliation is checking.
    let probe_outcome = probe.take_and_finish()?;
    let origin_stats_end = read_origin_stats_settled(origin_stats_addr, &params.target_host)?;
    let origin_requests_total_delta = origin_stats_end
        .requests
        .saturating_sub(origin_stats_baseline.requests);
    let origin_requests = origin_requests_total_delta
        .saturating_sub(probe_outcome.issued)
        .saturating_sub(warmup_requests_sent);
    let sut_cpu_at_end = sut_child.cpu_seconds().ok();
    let (rss_bytes, pss_bytes) = sut_child.memory().unwrap_or((0, 0));

    // Step 9: parse the load client's output into a RawRun.
    let stdout = client_child.stdout_snapshot();
    let stderr = client_child.stderr_snapshot();
    let ctx = ParseCtx {
        cell,
        invocation: &measurement_invocation,
        tool: &crate::provenance::ToolStamp {
            name: generator.name().to_owned(),
            version: provenance.loadgen.version.clone(),
            image_digest: provenance.loadgen.image_digest.clone(),
        },
    };
    let raw = generator.parse(&ctx, &stdout, &stderr)?;

    // Step 10: reconcile in integer arithmetic.
    let reconciliation = reconcile(raw.requests_sent, origin_requests, raw.errors);

    // Step 11: assemble the RunResult and run check_validity. An invalid
    // repetition is recorded, not discarded; a reconciliation failure is
    // instead this function's own Err, per its Errors doc.
    let measured_requests = raw.requests_sent;
    let rps = if raw.duration_ns > 0 {
        requests_as_f64(raw.requests_sent) / nanos_to_seconds(raw.duration_ns)
    } else {
        0.0
    };
    let cpu_seconds_per_request = cpu_seconds_per_request(
        sut_cpu_at_warmup_end,
        sut_cpu_at_end,
        cell.rate,
        measured_requests,
    );

    let latency_percentiles = raw.latency.percentiles();
    let latency_out_of_range = raw.out_of_range;
    let (stall_percentiles, stall_out_of_range) = optional_percentiles(raw.stall.as_ref());
    let (ttfb_percentiles, _ttfb_out_of_range) = optional_percentiles(raw.ttfb.as_ref());
    let (connect_percentiles, _connect_out_of_range) = optional_percentiles(raw.connect.as_ref());
    let probe_latency = probe_outcome.latency.percentiles();
    let sut_cores = u32::try_from(params.cores.sut.len()).unwrap_or(u32::MAX);

    let result = RunResult {
        cell: cell.id.clone(),
        cell_def: cell.clone(),
        provenance: provenance.clone(),
        rps,
        latency: latency_percentiles,
        probe_latency,
        ttfb: ttfb_percentiles,
        connect: connect_percentiles,
        stall: stall_percentiles,
        cpu_seconds_per_request,
        rss_bytes,
        pss_bytes,
        bytes_received: raw.bytes_received,
        payload_bytes: cell.payload_bytes,
        total_requests: raw.requests_sent,
        status_counts: raw.status_counts,
        origin_ceiling_rps,
        direct_rps,
        client_cpu_max_pct,
        sut_cores,
        catchup_burst_count: 0,
        out_of_range: latency_out_of_range,
        stall_out_of_range,
        stall_backwards_count: 0,
        warmup_samples_discarded,
        deepest_percentile: params.deepest_percentile,
        bottleneck: Bottleneck::Unknown,
        validity: Validity::Valid,
        command_line,
    };

    reconciliation?;

    let mut result = result;
    result.validity = crate::guards::check_validity(&result, None, None);

    // Step 12: teardown. `origin_child`, `sut_child`, `client_child` and
    // `probe` all drop here, in the REVERSE of the order they were declared
    // (client, probe, sut, origin), per the module doc.
    Ok((result, probe_outcome.latency))
}

/// Runs a cell `repetitions` times with a fresh process tree each time.
///
/// Collects the `(RunResult, LatencyRecorder)` pairs `run_repetition`
/// returns, splits them, and calls `CellAggregate::from_runs(cell, runs,
/// &recorders)`. The recorders are also what the caller writes out as
/// `.hgrm` artifacts, so `run_cell` returns them alongside the aggregate.
///
/// A failed repetition is retried at most once (edge case 15); the retry is
/// recorded on the returned aggregate as `retried: true` rather than hidden.
///
/// # Errors
/// Propagates the first repetition error that does not clear on retry.
/// Disclosed gap: this issue's own Public API section describes this
/// doc as also saying completed repetitions are returned in the error's
/// context so a partial cell is still inspectable; see the module doc's own
/// "A disclosed gap: `run_cell`'s partial-cell context" section for why that
/// is not actually true today (`BenchError` has no payload variant that
/// could carry a `Vec<RunResult>`) and is stated honestly here rather than
/// silently dropped from this comment.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors run_repetition's own five parameters plus the repetition count, all of \
              which this function's own Public API doc says it forwards unchanged"
)]
pub fn run_cell(
    cell: &BenchCell,
    generator: &dyn LoadGenerator,
    adapters: &[&dyn LoadGenerator],
    params: &RunParamsFull,
    provenance: &Provenance,
    repetitions: u32,
) -> Result<(CellAggregate, Vec<LatencyRecorder>), BenchError> {
    let mut runs: Vec<RunResult> = Vec::new();
    let mut recorders: Vec<LatencyRecorder> = Vec::new();
    let mut retried = false;

    for _repetition in 0..repetitions {
        let mut attempt = run_repetition(cell, generator, adapters, params, provenance);
        if attempt.is_err() {
            // Retry at most once: a second failure is the one this function
            // propagates.
            attempt = run_repetition(cell, generator, adapters, params, provenance);
            retried = true;
        }
        let (result, recorder) = attempt?;
        runs.push(result);
        recorders.push(recorder);
    }

    let mut aggregate = CellAggregate::from_runs(cell.id.clone(), runs, &recorders)?;
    aggregate.retried = retried;
    Ok((aggregate, recorders))
}

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

/// Checks `generator`'s probed version against its pin in `bench/tools.toml`,
/// per that file's own header comment: a table carrying `version = "<x>"`
/// requires byte equality, a table carrying `expect_version_contains = "<s>"`
/// requires the probed string to contain `<s>` case-sensitively, and a table
/// with neither key or with both is `Err(BenchError::Parse)` naming the
/// table.
fn check_tool_pin(generator: &dyn LoadGenerator) -> Result<(), BenchError> {
    let version_invocation = generator.version_invocation();
    let stdout = spawn_and_capture(&version_invocation)?;
    let stamp = generator.parse_version(&stdout)?;
    let pin = read_tool_pin(generator.name())?;
    match pin {
        ToolPin::Exact(expected) if expected == stamp.version => Ok(()),
        ToolPin::Contains(needle) if stamp.version.contains(&needle) => Ok(()),
        ToolPin::Exact(expected) => Err(BenchError::parse(
            "tools_toml",
            &format!(
                "{} version mismatch: pinned {expected:?}, probed {:?}",
                generator.name(),
                stamp.version
            ),
        )),
        ToolPin::Contains(needle) => Err(BenchError::parse(
            "tools_toml",
            &format!(
                "{} version mismatch: pinned substring {needle:?}, probed {:?}",
                generator.name(),
                stamp.version
            ),
        )),
    }
}

/// One tool's pin, as `bench/tools.toml` states it.
enum ToolPin {
    Exact(String),
    Contains(String),
}

/// Reads and parses `bench/tools.toml`'s table for `tool`, by the rule the
/// file's own header comment states. A hand-written reader, not a `toml`
/// dependency this crate's manifest does not authorise: the grammar needed
/// (`[name]` headers, `key = "value"` lines) is a tiny, fixed subset.
fn read_tool_pin(tool: &str) -> Result<ToolPin, BenchError> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/tools.toml");
    let read_result = std::fs::read_to_string(&path); // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; this reads one small, committed pin file once per repetition, before any measurement begins
    let text = read_result.map_err(|e| BenchError::io(&path.display().to_string(), e))?;
    let header = format!("[{tool}]");
    let mut in_table = false;
    let mut exact: Option<String> = None;
    let mut contains: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            in_table = trimmed == header;
            continue;
        }
        if !in_table {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("version")
            && let Some(value) = quoted_value(rest)
        {
            exact = Some(value);
        } else if let Some(rest) = trimmed.strip_prefix("expect_version_contains")
            && let Some(value) = quoted_value(rest)
        {
            contains = Some(value);
        }
    }
    match (exact, contains) {
        (Some(v), None) => Ok(ToolPin::Exact(v)),
        (None, Some(v)) => Ok(ToolPin::Contains(v)),
        (None, None) => Err(BenchError::parse(
            "tools_toml",
            &format!("no [{tool}] table with a version key found in bench/tools.toml"),
        )),
        (Some(_), Some(_)) => Err(BenchError::parse(
            "tools_toml",
            &format!("[{tool}] table in bench/tools.toml carries both version keys"),
        )),
    }
}

/// Extracts a `"..."`-quoted value from `rest`, which is everything after a
/// `key` up to and including its `=`.
fn quoted_value(rest: &str) -> Option<String> {
    let after_eq = rest.trim_start().strip_prefix('=')?;
    let trimmed = after_eq.trim();
    let inner = trimmed.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_owned())
}

/// Spawns `invocation` with no core pinning, waits for it to exit, and
/// returns its captured stdout. Used for the version probe, which is short
/// and does not need a `Child`'s full lifecycle.
fn spawn_and_capture(invocation: &Invocation) -> Result<Vec<u8>, BenchError> {
    let mut command = std::process::Command::new(&invocation.program); // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime anywhere in it; building a Command is not itself blocking, and the actual blocking call below (.output()) already carries its own marker
    command.args(&invocation.args);
    for (key, value) in &invocation.env {
        command.env(key, value);
    }
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    let output = command
        .output() // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; this is a short, bounded version-probe invocation, not a request-path operation
        .map_err(|e| BenchError::io(&invocation.program, e))?;
    Ok(output.stdout)
}

/// Selects the first adapter in `adapters`, in order, whose `supports`
/// accepts `cell` with `rate` replaced by `RateMode::Saturate`. Returns that
/// adapter and the saturate-modified cell it was checked against.
///
/// # Errors
/// `BenchError::Parse` naming the cell and every refusal when none does.
fn select_ceiling_adapter<'a>(
    cell: &BenchCell,
    adapters: &[&'a dyn LoadGenerator],
) -> Result<(&'a dyn LoadGenerator, BenchCell), BenchError> {
    let mut saturate_cell = cell.clone();
    saturate_cell.rate = RateMode::Saturate;
    let mut refusals: Vec<String> = Vec::new();
    for adapter in adapters {
        match adapter.supports(&saturate_cell) {
            Ok(()) => return Ok((*adapter, saturate_cell)),
            Err(reason) => refusals.push(format!("{}: {reason}", adapter.name())),
        }
    }
    let refusal_text = if refusals.is_empty() {
        "the adapters slice is empty".to_owned()
    } else {
        refusals.join("; ")
    };
    Err(BenchError::parse(
        "runner",
        &format!(
            "no adapter in the given slice accepts a saturate run of cell {}: {refusal_text}",
            cell.id
        ),
    ))
}

/// Runs `invocation` to completion pinned to `cores` (used for the
/// origin-ceiling run and for a discarded warmup invocation) and parses its
/// output with `adapter`.
fn run_one_shot_client(
    adapter: &dyn LoadGenerator,
    cell: &BenchCell,
    invocation: &Invocation,
    cores: &crate::proc::CoreSet,
) -> Result<RawRun, BenchError> {
    let mut child = Child::spawn(invocation, cores, "client-oneshot")?;
    let _status = child
        .raw_mut()
        .wait() // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; this waits out a single bounded (10 second ceiling, or warmup-length) child invocation to completion, which is the whole point of this helper
        .map_err(|e| BenchError::io("client-oneshot", e))?;
    let stdout = child.stdout_snapshot();
    let stderr = child.stderr_snapshot();
    let stamp = adapter
        .parse_version(&spawn_and_capture(&adapter.version_invocation())?)
        .unwrap_or_else(|_unavailable| crate::provenance::ToolStamp {
            name: adapter.name().to_owned(),
            version: "unknown".to_owned(),
            image_digest: None,
        });
    let ctx = ParseCtx {
        cell,
        invocation,
        tool: &stamp,
    };
    adapter.parse(&ctx, &stdout, &stderr)
}

/// Binds an ephemeral port on loopback, reads back the address the kernel
/// assigned, and closes the listener, so the caller can hand that address to
/// a child as its own listen address. Mitigates edge case 9 (a leaked child
/// from a previous run bound to a fixed, well-known port).
fn reserve_ephemeral_port() -> Result<SocketAddr, BenchError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)) // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; this reserves one ephemeral port before spawning a child, never on the measurement path
        .map_err(|e| BenchError::io("reserve_ephemeral_port", e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| BenchError::io("reserve_ephemeral_port", e))?;
    drop(listener);
    Ok(addr)
}

/// Renders `<work_dir>/sut.yaml`. See the module doc's disclosed gap: only
/// the listener and upstream fields `irontraffic_config::model::BootstrapDoc`
/// actually supports today are emitted; the cell's routing dimensions are
/// recorded as a comment for a human reader.
fn render_sut_yaml(cell: &BenchCell, bind: SocketAddr, upstream: SocketAddr) -> String {
    format!(
        "# cell {}: routes={} upstreams={} filter_depth={} cache={:?}\n\
         # irontraffic-config's BootstrapDoc (M1) has no routing, filter or cache\n\
         # section; those four dimensions are not expressible in this document yet.\n\
         apiVersion: irontraffic.io/v1\n\
         listeners:\n\
         \x20\x20- name: bench\n\
         \x20\x20\x20\x20bind: \"{bind}\"\n\
         upstream:\n\
         \x20\x20address: \"{upstream}\"\n",
        cell.id, cell.routes, cell.upstreams, cell.filter_depth, cell.cache
    )
}

/// Computes `RunResult::cpu_seconds_per_request` for one repetition.
///
/// `Some(finite)` only for a `RateMode::Fixed` cell with both CPU snapshots
/// present and at least one measured request; `None` otherwise. This is a
/// small, pure, directly testable seam extracted from `run_repetition`'s own
/// body specifically so the "never compute this at saturation" rule (Design's
/// own "Do NOT" list) is exercised by a unit test that does not need a whole
/// live repetition (a `RateMode::Saturate` cell cannot reach `run_repetition`
/// in this crate's own test suite at all, because every `LoadGenerator` this
/// crate ships that accepts saturate is either untestable on this host
/// (Nighthawk, no container runtime) or is `Oha`, which `Oha::supports`
/// refuses for every saturate cell unconditionally).
///
/// - A saturate cell: `None`, always, per Design's own "CPU per request
///   measured at saturation is definitionally 1 divided by throughput" rule.
/// - Either CPU snapshot missing (`None`, off Linux or a read failure): the
///   only source of a value.
/// - `measured_requests == 0`: `None`, because the division would otherwise
///   produce an infinity, which `serde_json` cannot round-trip.
/// - Otherwise: `(end - start).max(0.0) / measured_requests`, `None` instead
///   of `Some(f64::NAN)` on the rare chance that division is non-finite (a
///   `NaN` sentinel would serialise as `null` and could never be read back).
fn cpu_seconds_per_request(
    sut_cpu_at_warmup_end: Option<f64>,
    sut_cpu_at_end: Option<f64>,
    rate: RateMode,
    measured_requests: u64,
) -> Option<f64> {
    match (sut_cpu_at_warmup_end, sut_cpu_at_end, rate) {
        (Some(start), Some(end), RateMode::Fixed(_)) if measured_requests > 0 => {
            let delta = (end - start).max(0.0);
            let value = delta / requests_as_f64(measured_requests);
            if value.is_finite() { Some(value) } else { None }
        }
        _ => None,
    }
}

/// A tool run's requests, widened to `f64` once, so callers never repeat the
/// precision-loss annotation.
#[expect(
    clippy::cast_precision_loss,
    reason = "a request count losing precision above 2^53 is not a realistic single-repetition \
              count (it would take centuries at any rate this harness offers); this is a \
              display and ratio computation, not a security or correctness boundary"
)]
fn requests_as_f64(requests: u64) -> f64 {
    requests as f64
}

/// Nanoseconds widened to seconds, once.
#[expect(
    clippy::cast_precision_loss,
    reason = "a duration losing precision above 2^53 nanoseconds (over a century) is not a \
              realistic repetition length; this is a display and ratio computation, not a \
              security or correctness boundary"
)]
fn nanos_to_seconds(nanos: u64) -> f64 {
    (nanos as f64) / 1_000_000_000.0
}

/// Reduces an optional `LatencyRecorder` (a tool that did not report this
/// dimension) to `(Percentiles, out_of_range)`, zeroed when absent.
fn optional_percentiles(recorder: Option<&LatencyRecorder>) -> (Percentiles, u64) {
    match recorder {
        Some(r) => (r.percentiles(), r.out_of_range()),
        None => (
            Percentiles {
                p50_ns: 0,
                p90_ns: 0,
                p99_ns: 0,
                p999_ns: 0,
                p9999_ns: 0,
                max_ns: 0,
                samples: 0,
            },
            0,
        ),
    }
}

/// The fixed shape `{{origin-known-cost-server}}` serves on `GET /stats`:
/// `{"requests":N,"bytes":N,"rejects":N,"uptime_ms":N}` and nothing else.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
struct OriginStats {
    requests: u64,
    #[allow(
        dead_code,
        reason = "part of the fixed /stats shape; reconciliation only reads `requests`, but a \
                  hand-written parser reading the whole object once is simpler and more robust \
                  than one that reads a single field out of an otherwise-unvalidated document"
    )]
    bytes: u64,
    #[allow(dead_code, reason = "see the `bytes` field's own reason above")]
    rejects: u64,
    #[allow(dead_code, reason = "see the `bytes` field's own reason above")]
    uptime_ms: u64,
}

/// Largest response this reader will accept from the stats endpoint.
const STATS_RESPONSE_BUF_BYTES: usize = 4096;

/// Poll interval for [`read_origin_stats_settled`].
const SETTLE_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Iterations [`read_origin_stats_settled`] polls before giving up and
/// returning whatever it last read: `40 * 50ms` is 2 seconds.
const SETTLE_MAX_ITERATIONS: u32 = 40;

/// Reads the origin's `/stats` endpoint repeatedly until two consecutive
/// reads agree, or [`SETTLE_MAX_ITERATIONS`] is reached, whichever comes
/// first.
///
/// A load client offering as much traffic as it can generate (the
/// origin-ceiling run) can abandon an in-flight request at its own deadline
/// rather than awaiting it: bytes it already wrote to a kernel socket
/// buffer keep travelling to the origin and get counted there even after
/// the client's own process has exited and been waited on. Reading `/stats`
/// exactly once, immediately after that wait, can therefore observe a
/// counter that is still rising. This is the ONE thing that makes a
/// baseline-then-delta reconciliation trustworthy at all; see the two call
/// sites' own comments.
///
/// # Errors
/// `BenchError::Io` when a read itself fails (propagated from
/// [`read_origin_stats`]), or when the counter has not settled (two
/// consecutive equal reads) within [`SETTLE_MAX_ITERATIONS`] tries. The
/// second case used to return the last unsettled read instead of an error:
/// a still-rising counter fed straight into reconciliation as if it were
/// final produces a mismatch that reads as a proxy defect when the real
/// cause is that the origin's own counter never finished moving within this
/// budget. Both call sites already propagate this function's `Result` with
/// `?`, so returning `Err` here surfaces as `run_repetition`'s own failure
/// (retried once by `run_cell`, per edge case 15) rather than silently
/// publishing a number this function itself does not trust.
fn read_origin_stats_settled(addr: SocketAddr, host: &str) -> Result<OriginStats, BenchError> {
    let mut previous = read_origin_stats(addr, host)?;
    for _ in 0..SETTLE_MAX_ITERATIONS {
        std::thread::park_timeout(SETTLE_POLL_INTERVAL); // it-allow: no-accumulated-sleep reason: a fixed poll tick bounded by SETTLE_MAX_ITERATIONS on every iteration, mirroring crate::provenance's identical poll_until_done pattern; not an open-loop request-pacing schedule that could accumulate drift
        let current = read_origin_stats(addr, host)?;
        if current.requests == previous.requests {
            return Ok(current);
        }
        previous = current;
    }
    Err(BenchError::io(
        &addr.to_string(),
        std::io::Error::other(format!(
            "the origin's /stats requests counter at {addr} never stopped moving across \
             {SETTLE_MAX_ITERATIONS} reads spaced {SETTLE_POLL_INTERVAL:?} apart; a still-rising \
             counter cannot be trusted as a reconciliation baseline or endpoint, and returning \
             the last unsettled read here would silently blame a reconciliation mismatch on the \
             proxy instead of on this"
        )),
    ))
}

/// Reads the origin's `/stats` endpoint over HTTP/1.1.
fn read_origin_stats(addr: SocketAddr, host: &str) -> Result<OriginStats, BenchError> {
    let mut request_buf = [0_u8; crate::probe::MAX_REQUEST_BYTES];
    let request_len = crate::build_request(&mut request_buf, host, "/stats")?;
    let mut stream = TcpStream::connect(addr).map_err(|e| BenchError::io(&addr.to_string(), e))?; // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; this is the one-shot read of the origin's own stats endpoint at the end of a repetition, never on the measurement path
    stream
        .set_read_timeout(Some(STATS_READ_TIMEOUT))
        .map_err(|e| BenchError::io(&addr.to_string(), e))?;
    stream
        .write_all(request_buf.get(..request_len).unwrap_or(&[]))
        .map_err(|e| BenchError::io(&addr.to_string(), e))?;

    let mut buf = [0_u8; STATS_RESPONSE_BUF_BYTES];
    let mut filled = 0_usize;
    let head = loop {
        let target = buf.get_mut(filled..).ok_or_else(|| {
            BenchError::parse("origin_stats", "response head exceeds the read buffer")
        })?;
        if target.is_empty() {
            return Err(BenchError::parse(
                "origin_stats",
                "response head exceeds the read buffer",
            ));
        }
        let n = stream
            .read(target)
            .map_err(|e| BenchError::io(&addr.to_string(), e))?;
        if n == 0 {
            return Err(BenchError::parse(
                "origin_stats",
                "connection closed before a complete response head was read",
            ));
        }
        filled = filled.saturating_add(n);
        match crate::probe::scan_response_head(buf.get(..filled).unwrap_or(&[])) {
            crate::probe::ScanOutcome::Complete(h) => break h,
            crate::probe::ScanOutcome::NeedMore => {}
            crate::probe::ScanOutcome::Bad(_reason) => {
                return Err(BenchError::parse("origin_stats", "malformed response head"));
            }
        }
    };

    let body_have = filled.saturating_sub(head.head_len);
    let mut body: Vec<u8> = buf.get(head.head_len..filled).unwrap_or(&[]).to_vec();
    let mut remaining = head
        .content_length
        .saturating_sub(u64::try_from(body_have).unwrap_or(u64::MAX));
    while remaining > 0 {
        let mut chunk = [0_u8; 512];
        let n = stream
            .read(&mut chunk)
            .map_err(|e| BenchError::io(&addr.to_string(), e))?;
        if n == 0 {
            return Err(BenchError::parse(
                "origin_stats",
                "connection closed before the full body was read",
            ));
        }
        body.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        remaining = remaining.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
    }

    serde_json::from_slice(&body).map_err(|e| BenchError::parse("origin_stats", &e.to_string()))
}

/// One core's `(idle_ticks, total_ticks)` from a `/proc/stat` `cpuN` line.
type CoreTicks = (u64, u64);

/// Reads `/proc/stat`'s per-core lines for the cores in `cores`. `None` off
/// Linux or on any read or parse failure: this is a best-effort sample for
/// `client_cpu_max_pct`, and a missing sample simply contributes nothing to
/// the running maximum rather than failing the whole repetition.
fn read_percore_ticks(cores: &crate::proc::CoreSet) -> Option<Vec<CoreTicks>> {
    read_percore_ticks_from(std::path::Path::new("/proc/stat"), cores)
}

/// The pure half of [`read_percore_ticks`], parameterised on the path so a
/// test can drive it with a fixture file instead of the real `/proc/stat`.
fn read_percore_ticks_from(
    path: &std::path::Path,
    cores: &crate::proc::CoreSet,
) -> Option<Vec<CoreTicks>> {
    let bytes = read_bounded(path, SMALL_FILE_CAP).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let mut out = Vec::with_capacity(cores.len());
    for &core in cores.iter() {
        let prefix = format!("cpu{core} ");
        let line = text.lines().find(|l| l.starts_with(&prefix))?;
        let fields: Vec<u64> = line
            .get(prefix.len()..)?
            .split_whitespace()
            .filter_map(|f| f.parse::<u64>().ok())
            .collect();
        let idle = fields.get(3).copied().unwrap_or(0) + fields.get(4).copied().unwrap_or(0);
        let total: u64 = fields.iter().copied().fold(0_u64, u64::saturating_add);
        out.push((idle, total));
    }
    Some(out)
}

/// Highest single-core utilisation, in percent, between two per-core tick
/// samples. Every delta is a `saturating_sub`: a counter that appears to go
/// backwards (a hot-unplugged core, a remounted `/proc`, a 32-bit wrap on an
/// old kernel) contributes 0, never a wrapped enormous delta.
fn percore_utilisation_pct(prev: &[CoreTicks], cur: &[CoreTicks]) -> Option<f64> {
    if prev.len() != cur.len() {
        return None;
    }
    let mut max_pct = 0.0_f64;
    for (&(prev_idle, prev_total), &(cur_idle, cur_total)) in prev.iter().zip(cur.iter()) {
        let idle_delta = cur_idle.saturating_sub(prev_idle);
        let total_delta = cur_total.saturating_sub(prev_total);
        if total_delta == 0 {
            continue;
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "a single-second /proc/stat tick delta losing precision above 2^53 is \
                      impossible (it would require an implausible clock tick rate over an \
                      implausible uptime); this is a percentage display, not a security or \
                      correctness boundary"
        )]
        let busy_fraction = 1.0 - (idle_delta as f64 / total_delta as f64);
        let pct = (busy_fraction * 100.0).clamp(0.0, 100.0);
        max_pct = max_pct.max(pct);
    }
    Some(max_pct)
}

#[cfg(test)]
mod tests {
    use super::{
        SETTLE_MAX_ITERATIONS, cpu_seconds_per_request, percore_utilisation_pct,
        read_origin_stats_settled, reconcile, select_ceiling_adapter,
    };
    use crate::cell::{
        BenchCell, CacheMode, CellId, KeepaliveMode, PathCorpus, Protocol, RateMode, TlsMode,
    };
    use crate::error::BenchError;
    use crate::loadgen::{
        Invocation, LoadGenerator, ParseCtx, RawRun, RunParams, Target, Unsupported,
    };
    use crate::provenance::ToolStamp;

    #[test]
    fn reconcile_accepts_an_exact_match() {
        assert!(reconcile(1000, 999, 1).is_ok());
    }

    #[test]
    fn percore_utilisation_backwards_counter_contributes_zero() {
        // The current sample's idle count appears LOWER than the previous
        // one, which a naive subtraction would wrap into an enormous delta;
        // saturating_sub floors it at 0. total also decreased, so
        // total_delta saturates to 0 and this core is skipped entirely
        // rather than reporting a wrapped, nonsense percentage.
        let prev = vec![(100_u64, 200_u64)];
        let cur = vec![(50_u64, 150_u64)];
        let pct = percore_utilisation_pct(&prev, &cur).unwrap_or(0.0);
        assert!(
            pct.is_finite(),
            "a backwards counter must never produce a non-finite percentage"
        );
        assert!(
            (0.0..=100.0).contains(&pct),
            "pct {pct} must stay in 0..=100 even for a backwards counter"
        );
    }

    // -----------------------------------------------------------------
    // select_ceiling_adapter: Design step 2's "choose the FIRST adapter in
    // the adapters slice, in order, whose supports accepts the saturate
    // variant; if none does, fail naming the cell and every refusal."
    // Reviewed finding: the whole origin-ceiling step had no test that
    // would fail if it were done wrong (M1 deleted it entirely and left
    // origin_ceiling_rps at 0.0, exactly the trap Design forbids by name),
    // and two narrower mutations on this specific function also survived
    // (M2a: last-accepting instead of first; M2b: silent fallback to
    // adapters[0] instead of failing and naming every refusal). These
    // three tests exercise select_ceiling_adapter directly, with no live
    // process and no dependency on oha being installed, specifically so
    // they cannot be skipped the way the end-to-end tests below can be.
    // -----------------------------------------------------------------

    fn ceiling_test_cell() -> BenchCell {
        BenchCell {
            id: CellId::parse("select_ceiling_unit_test").unwrap_or_else(|_| {
                panic!("select_ceiling_unit_test must be a valid cell id literal")
            }),
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
            rate: RateMode::Fixed(1000),
        }
    }

    /// A fake `LoadGenerator` whose `supports` always accepts. Every method
    /// besides `name` and `supports` is unreachable from
    /// `select_ceiling_adapter`'s own body, which never plans, parses or
    /// version-probes the adapters it is choosing between.
    struct AlwaysAccepts(&'static str);

    impl LoadGenerator for AlwaysAccepts {
        fn name(&self) -> &'static str {
            self.0
        }

        fn version_invocation(&self) -> Invocation {
            unreachable!("select_ceiling_adapter never probes a version")
        }

        fn parse_version(&self, _stdout: &[u8]) -> Result<ToolStamp, BenchError> {
            unreachable!("select_ceiling_adapter never probes a version")
        }

        fn supports(&self, _cell: &BenchCell) -> Result<(), Unsupported> {
            Ok(())
        }

        fn plan(
            &self,
            _cell: &BenchCell,
            _target: &Target,
            _run: &RunParams,
        ) -> Result<Invocation, BenchError> {
            unreachable!("select_ceiling_adapter never plans an invocation")
        }

        fn parse(
            &self,
            _ctx: &ParseCtx<'_>,
            _stdout: &[u8],
            _stderr: &[u8],
        ) -> Result<RawRun, BenchError> {
            unreachable!("select_ceiling_adapter never parses output")
        }
    }

    /// A fake `LoadGenerator` whose `supports` always refuses, naming
    /// itself in the refusal so a test can assert the caller saw it.
    struct AlwaysRefuses(&'static str);

    impl LoadGenerator for AlwaysRefuses {
        fn name(&self) -> &'static str {
            self.0
        }

        fn version_invocation(&self) -> Invocation {
            unreachable!("select_ceiling_adapter never probes a version")
        }

        fn parse_version(&self, _stdout: &[u8]) -> Result<ToolStamp, BenchError> {
            unreachable!("select_ceiling_adapter never probes a version")
        }

        fn supports(&self, _cell: &BenchCell) -> Result<(), Unsupported> {
            Err(Unsupported::RateMode {
                tool: self.0,
                detail: "test fixture refuses every cell unconditionally",
            })
        }

        fn plan(
            &self,
            _cell: &BenchCell,
            _target: &Target,
            _run: &RunParams,
        ) -> Result<Invocation, BenchError> {
            unreachable!("select_ceiling_adapter never plans an invocation")
        }

        fn parse(
            &self,
            _ctx: &ParseCtx<'_>,
            _stdout: &[u8],
            _stderr: &[u8],
        ) -> Result<RawRun, BenchError> {
            unreachable!("select_ceiling_adapter never parses output")
        }
    }

    #[test]
    fn select_ceiling_adapter_picks_the_first_accepting_adapter_in_order() {
        let cell = ceiling_test_cell();
        let first = AlwaysAccepts("first");
        let second = AlwaysAccepts("second");
        let adapters: Vec<&dyn LoadGenerator> = vec![&first, &second];
        let (chosen, saturate_cell) = select_ceiling_adapter(&cell, &adapters)
            .unwrap_or_else(|e| panic!("both adapters accept; must not error, got {e:?}"));
        assert_eq!(
            chosen.name(),
            "first",
            "when more than one adapter accepts, the FIRST in the slice must be chosen, not the \
             last: a mutation that reverses this ordering is otherwise indistinguishable whenever \
             the accepting set has exactly one member"
        );
        assert!(
            matches!(saturate_cell.rate, RateMode::Saturate),
            "the cell checked against (and returned for) the ceiling run must have its rate \
             replaced with Saturate"
        );
    }

    #[test]
    fn select_ceiling_adapter_skips_refusals_before_the_first_acceptance() {
        let cell = ceiling_test_cell();
        let refuser = AlwaysRefuses("refuser");
        let accepter = AlwaysAccepts("accepter");
        let adapters: Vec<&dyn LoadGenerator> = vec![&refuser, &accepter];
        let (chosen, _) = select_ceiling_adapter(&cell, &adapters)
            .unwrap_or_else(|e| panic!("the second adapter accepts; must not error, got {e:?}"));
        assert_eq!(
            chosen.name(),
            "accepter",
            "a refusing adapter earlier in the slice must be skipped, not treated as a match"
        );
    }

    #[test]
    fn select_ceiling_adapter_fails_naming_every_refusal_when_none_accept() {
        let cell = ceiling_test_cell();
        let first = AlwaysRefuses("refuser_one");
        let second = AlwaysRefuses("refuser_two");
        let adapters: Vec<&dyn LoadGenerator> = vec![&first, &second];
        let err = match select_ceiling_adapter(&cell, &adapters) {
            Err(e) => e,
            Ok((chosen, _)) => panic!(
                "no adapter in the slice accepts; this must fail, never silently pick one, but \
                 {} was chosen",
                chosen.name()
            ),
        };
        let text = err.to_string();
        assert!(
            text.contains("refuser_one"),
            "the failure {text:?} must name refuser_one's own refusal"
        );
        assert!(
            text.contains("refuser_two"),
            "the failure {text:?} must name refuser_two's own refusal"
        );
    }

    // -----------------------------------------------------------------
    // cpu_seconds_per_request: extracted specifically so the "never at
    // saturation" rule is directly testable. Reviewed finding: the
    // integration test that names this rule (saturate_cell_has_no_cpu_per_request)
    // only round-trips a hand-built RunResult through serde and never calls
    // the runner at all, and RateMode::Saturate cannot reach run_repetition
    // in this crate's own test suite (Oha::supports refuses it, and no
    // saturate-capable adapter is exercised end-to-end here), so a mutation
    // that computed and published a value at saturation survived. These
    // tests call the real function the runner calls.
    // -----------------------------------------------------------------

    #[test]
    fn cpu_seconds_per_request_is_none_for_saturate_even_with_valid_samples() {
        let value = cpu_seconds_per_request(Some(1.0), Some(2.0), RateMode::Saturate, 100);
        assert_eq!(
            value, None,
            "a saturate cell must never publish cpu_seconds_per_request, even when both CPU \
             samples are present and requests were measured"
        );
    }

    #[test]
    fn cpu_seconds_per_request_is_some_finite_for_a_fixed_rate_cell() {
        let value = cpu_seconds_per_request(Some(1.0), Some(1.5), RateMode::Fixed(1000), 100);
        match value {
            Some(v) => assert!(
                (v - 0.005).abs() < f64::EPSILON,
                "expected (1.5 - 1.0) / 100 = 0.005, got {v}"
            ),
            None => panic!("a fixed-rate cell with valid samples must publish Some(finite)"),
        }
    }

    #[test]
    fn cpu_seconds_per_request_is_none_when_no_requests_were_measured() {
        let value = cpu_seconds_per_request(Some(1.0), Some(2.0), RateMode::Fixed(1000), 0);
        assert_eq!(
            value, None,
            "zero measured requests must not be divided by, which would otherwise produce an \
             infinity serde_json cannot round-trip"
        );
    }

    #[test]
    fn cpu_seconds_per_request_is_none_when_a_cpu_sample_is_missing() {
        let value = cpu_seconds_per_request(None, Some(2.0), RateMode::Fixed(1000), 100);
        assert_eq!(
            value, None,
            "a missing CPU sample (off Linux, or a read failure) must not be silently treated as \
             zero"
        );
    }

    // -----------------------------------------------------------------
    // read_origin_stats_settled: Reviewed finding: giving up after
    // SETTLE_MAX_ITERATIONS used to return the last unsettled read with no
    // signal to the caller, and that value feeds reconciliation directly,
    // so a still-moving counter became a reconciliation failure blamed on
    // the proxy. This test drives a counter that increments on every
    // single read, so it can never settle, and asserts the function now
    // fails instead of returning a number it does not trust.
    // -----------------------------------------------------------------

    #[test]
    fn read_origin_stats_settled_errors_when_the_counter_never_stops_moving() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{Duration, Instant};

        let listener =
            TcpListener::bind(("127.0.0.1", 0)).unwrap_or_else(|e| panic!("bind failed: {e}"));
        // Reviewed finding: the accept loop below used to be a plain
        // `for _ in 0..accept_budget { listener.accept() ... }` with no
        // timeout. That is deterministic today only because
        // read_origin_stats_settled always makes exactly this many reads
        // when the counter never settles; if the function under test ever
        // returned early (a different give-up condition, an added early
        // `Ok` path), nothing would ever connect for the remaining
        // iterations and this thread would block in `accept()` forever,
        // wedging `thread::scope`'s own join with no timeout, the same
        // shape as the `Child::stop` defect this PR's earlier pass removed.
        // Non-blocking `accept()` polled against a wall-clock deadline
        // bounds this loop regardless of how many times the function under
        // test actually reads.
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|e| panic!("set_nonblocking failed: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr failed: {e}"));
        let counter = AtomicU64::new(0);
        // read_origin_stats_settled makes exactly one initial read plus
        // SETTLE_MAX_ITERATIONS more when the counter never settles (this
        // fake origin's own counter increments on every single read, so it
        // never does): the accept loop below services EXACTLY that many
        // connections and then returns on its own, which is what lets
        // `thread::scope` below join it without blocking on a connection
        // that will never arrive.
        let accept_budget = usize::try_from(SETTLE_MAX_ITERATIONS)
            .unwrap_or_else(|_| panic!("SETTLE_MAX_ITERATIONS must fit in usize"))
            .saturating_add(1);
        // Comfortably above the settle loop's own ~2 second budget
        // (SETTLE_MAX_ITERATIONS * SETTLE_POLL_INTERVAL), so a healthy run
        // never comes close to it; only a wedge (the scenario described
        // above) or extreme host starvation would ever reach it, and either
        // way this bound turns a silent hang into a clean, if slow, test
        // failure instead.
        let accept_deadline = Instant::now() + Duration::from_secs(10);

        let result = std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut served = 0_usize;
                while served < accept_budget {
                    let (mut stream, _addr) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= accept_deadline {
                                break;
                            }
                            std::thread::park_timeout(Duration::from_millis(5)); // it-allow: no-accumulated-sleep reason: bounded by accept_deadline on every iteration, a fixed total cap of 10 seconds; guards this test-only fake-origin accept loop against blocking in accept() forever if the function under test ever stopped reading before accept_budget connections arrived
                            continue;
                        }
                        Err(_other) => break,
                    };
                    served += 1;
                    // The listener's own non-blocking mode above is not
                    // inherited by an accepted connection on any platform
                    // this crate ships on, but stating that explicitly
                    // rather than relying on it removes any doubt: the
                    // blocking read/write calls below need a blocking
                    // stream to behave the same as before this fix.
                    stream
                        .set_nonblocking(false)
                        .unwrap_or_else(|e| panic!("stream set_nonblocking(false) failed: {e}"));
                    let mut buf = [0_u8; 512];
                    let _ = stream.read(&mut buf);
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    let body =
                        format!("{{\"requests\":{n},\"bytes\":0,\"rejects\":0,\"uptime_ms\":0}}");
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body.as_bytes());
                }
            });

            read_origin_stats_settled(addr, "bench.test")
        });

        assert!(
            result.is_err(),
            "a requests counter that increments on every single read must never be treated as \
             settled; silently returning the last unsettled read would feed a still-moving \
             counter straight into reconciliation and blame the proxy for what the origin never \
             finished reporting"
        );
        // Sanity: this really did exhaust the full settle budget, not stop
        // early for an uninteresting reason (like the accept loop dying).
        assert!(
            counter.load(Ordering::SeqCst) >= u64::from(SETTLE_MAX_ITERATIONS),
            "the fake origin must have been read enough times to exercise the full settle budget, \
             got {} reads",
            counter.load(Ordering::SeqCst)
        );
    }
}
