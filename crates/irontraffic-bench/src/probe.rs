// SPDX-License-Identifier: MIT OR Apache-2.0
//! `probe`: the in-tree 100 requests per second single-connection reference
//! client whose percentiles are the published latency.
//!
//! # Why this exists
//!
//! At saturation a high-rate load client's own scheduling jitter is
//! inseparable from the system under test's behaviour. A client issuing
//! exactly 100 requests per second over one connection cannot self-queue and
//! cannot be the bottleneck, so its percentiles are the system's percentiles
//! rather than the client's own noise. This is the method HAProxy's own
//! benchmark uses; see `science/benchmarking.md`, D5.
//!
//! # No async runtime
//!
//! At 100 requests per second over one connection there is nothing to
//! multiplex. This module names no runtime and defines no asynchronous
//! function: it is a dedicated OS thread driving a blocking
//! [`std::net::TcpStream`], so the
//! probe's own tail is never a function of a scheduler's wakeup latency or of
//! what else a runtime happens to be doing.
//!
//! # `wait_until` and `no-accumulated-sleep`
//!
//! [`wait_until`] parks until [`SPIN_THRESHOLD_NS`] before its absolute
//! deadline, then spins on the monotonic clock. Every `park_timeout` call
//! site in this module (here, and in [`ProbeHandle::reset_recorders`]'s own
//! bounded poll) recomputes its duration from an absolute deadline or a fixed
//! iteration budget on every call, so a spurious wakeup or an overshoot can
//! never accumulate: that is what the `no-accumulated-sleep` invariant lint
//! is checking for, and each call site says so on its own line.
//!
//! # Every subtraction of two instants is `saturating_sub`
//!
//! [`irontraffic_time::PreciseMono`] is monotone by construction, so an
//! underflow should be unreachable here. The cost of being wrong anyway is a
//! sample around `u64::MAX` nanoseconds, which [`crate::LatencyRecorder`]
//! counts in `out_of_range` and silently drops from the published
//! distribution: precisely the failure this whole milestone exists to
//! prevent. Every nanosecond subtraction in this module, with no exception,
//! goes through `.saturating_sub(..)`.
//!
//! # A documented gap against the issue's own Public API section
//!
//! `ProbeHandle::spawn`'s doc comment below reads `time.precise()` and then
//! calls [`irontraffic_time::PreciseMono::as_measurement_nanos`], not
//! `.as_nanos()`: [`irontraffic_time::PreciseMono`] (already on `main` from
//! `time-source-seam`, #5) has never had an `as_nanos` method. This module
//! uses the seam's real, existing method name throughout.

mod wire;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use irontraffic_time::SharedTime;

use crate::error::BenchError;
use crate::hist::{HIGH_NS, LatencyRecorder};
use crate::schedule::{Schedule, StallTracker};

pub use wire::{BadReason, ResponseHead, ScanOutcome, build_request, scan_response_head};

/// Nanoseconds before the deadline at which [`wait_until`] stops parking and
/// spins. 200 microseconds: parking alone leaves tens to hundreds of
/// microseconds of scheduler wakeup latency in every sample; spinning the
/// whole 10 millisecond inter-arrival gap at 100 requests per second burns a
/// whole core for nothing. `100 * 200us = 20ms` of spin per second is 2
/// percent of one core, two orders of magnitude cheaper than spinning the
/// full interval.
pub const SPIN_THRESHOLD_NS: u64 = 200_000;

/// Maximum assembled request size. A path plus host that would assemble to
/// more than this is a configuration error, rejected by
/// [`ProbeHandle::spawn`].
pub const MAX_REQUEST_BYTES: usize = 1024;

/// Reconnect count above which a run is reported as probe-degraded: the
/// probe measured connection setup, not steady-state service.
pub const MAX_HEALTHY_RECONNECTS: u64 = 10;

/// Largest `Content-Length` the probe will honour, matching `it-origin`'s own
/// body cap. A response declaring more than this counts as `bad` and forces
/// a reconnect; see [`wire::BadReason::ContentLengthTooLarge`].
pub const MAX_RESPONSE_BODY_BYTES: u64 = 16_777_216;

/// Absolute per-exchange deadline in nanoseconds, measured from the
/// request's DUE time, not from when it was actually sent. Five seconds.
///
/// This is a deadline, not a per-read timeout. A peer that sends one byte
/// every four seconds resets a per-read timeout forever, holds the probe for
/// the entire run, and leaves percentiles that describe a shorter window
/// than the run claims. The socket's read and write timeouts are both
/// recomputed from the REMAINING time to this deadline before every use.
pub const REQUEST_DEADLINE_NS: u64 = 5_000_000_000;

/// Consecutive failed exchanges after which the probe stops and reports
/// [`ProbeOutcome::aborted`]. A target that has failed this many exchanges in
/// a row is producing nothing; the run is invalid either way, and this makes
/// it invalid in bounded time instead of after the full duration.
pub const MAX_CONSECUTIVE_ERRORS: u64 = 100;

/// Size of the probe's one fixed, reused read buffer. Also the cap on how
/// large a response head [`wire::scan_response_head`] will scan for before
/// refusing it as [`wire::BadReason::HeadTooLarge`]: the buffer is fixed and
/// never grows, so this is the same 8 KiB in both places by construction.
const READ_BUFFER_BYTES: usize = 8192;

/// How often [`ProbeHandle::reset_recorders`] polls for the probe thread's
/// acknowledgement.
const RESET_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// How many [`RESET_POLL_INTERVAL`] ticks [`ProbeHandle::reset_recorders`]
/// polls before giving up: `2000 * 1ms = 2` seconds, matching the Design
/// section's stated bound. A tick count rather than a clock read: this
/// crate's `determinism-seam` invariant lint bans a direct monotonic clock
/// read outside `irontraffic-time`, and counting fixed-duration ticks needs
/// no clock read of its own to enforce a bound that is accurate to within
/// one tick's worth of scheduling noise.
const RESET_POLL_MAX_ITERATIONS: u32 = 2000;

/// How to run the probe.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Where to connect. One address; the probe holds one connection.
    pub target: SocketAddr,
    /// `Host` header value.
    pub host: String,
    /// Request path. Assembled request must fit in [`MAX_REQUEST_BYTES`].
    pub path: String,
    /// Core to pin to. `None` means do not pin, which makes the run
    /// unpublishable.
    pub core_id: Option<usize>,
    /// Requests per second. Fixed at 100 for published runs; configurable so
    /// the tests can run a short probe.
    pub rate_hz: u64,
    /// Total requests to issue before returning.
    pub expected_requests: u64,
}

/// What the probe measured.
///
/// Two later issues add fields to this struct and to [`ProbeConfig`], and no
/// others do: `{{bench-config-reload-under-load}}` adds `samples` and
/// `ring_wrapped`, and `{{bench-methodology-proof-tests}}` adds `loop_mode`
/// to both. Every field below is complete as written and none of them moves.
#[derive(Debug)]
pub struct ProbeOutcome {
    /// Total latency, measured from each request's DUE time.
    pub latency: LatencyRecorder,
    /// Time to first byte, measured from each request's DUE time.
    pub ttfb: LatencyRecorder,
    /// Connection establishment, measured separately.
    pub connect: LatencyRecorder,
    /// Intervals the probe was ready to send but could not.
    pub stall: LatencyRecorder,
    /// Requests issued.
    pub issued: u64,
    /// Responses with status 200 and the expected body length.
    pub ok: u64,
    /// Responses that were not 200, or whose body length disagreed.
    pub bad: u64,
    /// I/O errors, each of which forced a reconnect.
    pub errors: u64,
    /// Reconnects. More than [`MAX_HEALTHY_RECONNECTS`] in a run means the
    /// probe measured setup, not service.
    pub reconnects: u64,
    /// Whether the thread was successfully pinned.
    pub pinned: bool,
    /// Samples discarded by [`ProbeHandle::reset_recorders`].
    pub warmup_discarded: u64,
    /// True when the probe stopped early after [`MAX_CONSECUTIVE_ERRORS`]
    /// consecutive failed exchanges. The run is invalid; this says so in
    /// bounded time instead of after the full duration.
    pub aborted: bool,
}

impl ProbeOutcome {
    /// Builds an outcome for a probe that never got past its own startup
    /// (the initial connect failed): every counter zero, the caller-owned
    /// recorders returned untouched.
    fn startup_failed(
        pinned: bool,
        latency: LatencyRecorder,
        ttfb: LatencyRecorder,
        connect: LatencyRecorder,
        stall: LatencyRecorder,
    ) -> Self {
        Self {
            latency,
            ttfb,
            connect,
            stall,
            issued: 0,
            ok: 0,
            bad: 0,
            errors: 0,
            reconnects: 0,
            pinned,
            warmup_discarded: 0,
            aborted: false,
        }
    }
}

/// A running probe thread.
///
/// `Send`, trivially: every field is `Send` (a `JoinHandle`, and `Arc`s over
/// atomics), so a `ProbeHandle` may be created on one thread and driven
/// (`reset_recorders`, `finish`) from another. The four recorders live
/// entirely inside the probe thread until `finish` joins it; the three
/// atomics below are the only state ever shared with the request path, and
/// no lock is taken on it.
#[derive(Debug)]
pub struct ProbeHandle {
    join: std::thread::JoinHandle<ProbeOutcome>,
    reset_requested: Arc<AtomicU64>,
    reset_acked: Arc<AtomicU64>,
    discarded: Arc<AtomicU64>,
    stop_requested: Arc<AtomicBool>,
}

/// Everything [`run_probe`] needs, bundled into one value so the thread
/// closure captures a single argument rather than a long, easily
/// misordered parameter list.
struct RunArgs {
    config: ProbeConfig,
    time: SharedTime,
    request: [u8; MAX_REQUEST_BYTES],
    request_len: usize,
    latency: LatencyRecorder,
    ttfb: LatencyRecorder,
    connect: LatencyRecorder,
    stall: StallTracker,
    ready_tx: mpsc::Sender<Result<(), BenchError>>,
    reset_requested: Arc<AtomicU64>,
    reset_acked: Arc<AtomicU64>,
    discarded: Arc<AtomicU64>,
    stop_requested: Arc<AtomicBool>,
}

impl ProbeHandle {
    /// Spawns the probe thread and returns once the probe's very first
    /// connection attempt has settled.
    ///
    /// `time` is the workspace clock seam from `time-source-seam` (#5):
    /// [`SharedTime`] is `std::sync::Arc<dyn irontraffic_time::TimeSource>`,
    /// and the probe thread reads only `time.precise()` from it, never a raw
    /// standard library monotonic clock call directly.
    ///
    /// # Errors
    /// [`BenchError::Io`] when the initial connect fails, naming the
    /// address. [`BenchError::Cell`] when the assembled request exceeds
    /// [`MAX_REQUEST_BYTES`] or `rate_hz` is 0. Both checks that do not need
    /// a connection (size, rate) run before any thread or socket exists.
    pub fn spawn(config: ProbeConfig, time: SharedTime) -> Result<Self, BenchError> {
        if config.rate_hz == 0 {
            return Err(BenchError::Cell("probe rate_hz must be nonzero"));
        }

        let mut request = [0u8; MAX_REQUEST_BYTES];
        let request_len = wire::build_request(&mut request, &config.host, &config.path)?;

        let latency = LatencyRecorder::new()?;
        let ttfb = LatencyRecorder::new()?;
        let connect = LatencyRecorder::new()?;
        let stall = StallTracker::new()?;

        let reset_requested = Arc::new(AtomicU64::new(0));
        let reset_acked = Arc::new(AtomicU64::new(0));
        let discarded = Arc::new(AtomicU64::new(0));
        let stop_requested = Arc::new(AtomicBool::new(false));

        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), BenchError>>();

        // Captured before `config` moves into `args` below: both error
        // branches after the thread is spawned need the address for their
        // message, and this is what makes `config` itself fully consumed
        // (a move, not a borrow) rather than merely read through a
        // reference, which is what its by-value Public API signature calls
        // for.
        let target = config.target;

        let args = RunArgs {
            config,
            time,
            request,
            request_len,
            latency,
            ttfb,
            connect,
            stall,
            ready_tx,
            reset_requested: Arc::clone(&reset_requested),
            reset_acked: Arc::clone(&reset_acked),
            discarded: Arc::clone(&discarded),
            stop_requested: Arc::clone(&stop_requested),
        };

        let join = std::thread::Builder::new()
            .name("it-probe".to_owned())
            .spawn(move || run_probe(args))
            .map_err(|source| BenchError::io("it-probe thread spawn", source))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                join,
                reset_requested,
                reset_acked,
                discarded,
                stop_requested,
            }),
            Ok(Err(connect_error)) => {
                // The thread has already sent its definitive error and is
                // exiting on its own; this join only reclaims the OS thread.
                // it-allow: no-swallowed-error reason: connect_error (from the same channel send) is the error already being returned to the caller below; the joined outcome itself is a startup-failure placeholder no caller will ever see
                let _ = join.join();
                Err(connect_error)
            }
            Err(_disconnected) => {
                // The sender was dropped without ever sending: the thread
                // panicked before it could report anything.
                let panicked = join.join().is_err();
                let detail = if panicked {
                    "probe thread panicked before reporting readiness"
                } else {
                    "probe thread exited without reporting readiness"
                };
                Err(BenchError::io(
                    &target.to_string(),
                    std::io::Error::other(detail),
                ))
            }
        }
    }

    /// Swaps in fresh recorders and returns how many samples were discarded.
    ///
    /// Called by the harness at the end of warmup. Blocks until the probe
    /// thread acknowledges the swap, so the caller knows every sample
    /// recorded after this call returns belongs to the measurement window.
    ///
    /// # Errors
    /// [`BenchError::Io`] if the probe thread has already exited, or did not
    /// acknowledge the swap within 2 seconds.
    pub fn reset_recorders(&self) -> Result<u64, BenchError> {
        if self.join.is_finished() {
            return Err(BenchError::io(
                "it-probe reset",
                std::io::Error::other("the probe thread has already exited"),
            ));
        }

        let generation = self
            .reset_requested
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);

        for _ in 0..RESET_POLL_MAX_ITERATIONS {
            if self.reset_acked.load(Ordering::Acquire) >= generation {
                return Ok(self.discarded.load(Ordering::Acquire));
            }
            std::thread::park_timeout(RESET_POLL_INTERVAL); // it-allow: no-accumulated-sleep reason: a fixed 1ms poll tick bounded by RESET_POLL_MAX_ITERATIONS (2000 * 1ms = 2s), not a pacing loop that drives a published latency number; a spurious wakeup costs one extra tick and never accumulates
        }

        Err(BenchError::io(
            "it-probe reset",
            std::io::Error::other(
                "the probe thread did not acknowledge the reset within 2 seconds",
            ),
        ))
    }

    /// Signals the probe to stop after the current request and joins the
    /// thread.
    ///
    /// # Errors
    /// [`BenchError::Io`] when the thread panicked, which is reported rather
    /// than re-panicked so one bad probe does not abort a whole matrix.
    pub fn finish(self) -> Result<ProbeOutcome, BenchError> {
        self.stop_requested.store(true, Ordering::Release); // it-allow: single-snapshot-publish reason: plain AtomicBool stop flag, not an ArcSwap config snapshot publish
        self.join.join().map_err(|_panic| {
            BenchError::io(
                "it-probe thread",
                std::io::Error::other("probe thread panicked"),
            )
        })
    }
}

/// Pins the current thread to `core_id`, if given, and reports whether that
/// succeeded. `None` (the caller chose not to pin) and a failed pin both
/// report `false`: the run is unpublishable either way, and this module
/// never falls back to pinning core 0, which would collide with the load
/// client.
fn pin_to_core(core_id: Option<usize>) -> bool {
    match core_id {
        Some(id) => core_affinity::set_for_current(core_affinity::CoreId { id }),
        None => false,
    }
}

/// Connects to `target`, bounded by [`REQUEST_DEADLINE_NS`] so a firewall
/// silently dropping the handshake cannot hang the probe forever.
fn connect(target: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&target, Duration::from_nanos(REQUEST_DEADLINE_NS))?;
    // Nagle's algorithm batches small writes to save packets, at the cost
    // of latency: exactly the wrong trade for a client whose entire job is
    // measuring latency accurately. `write_all` here is a single small
    // request per exchange, so there is no throughput case for coalescing
    // it with anything else.
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// `wait_until`: parks to `deadline_ns` minus [`SPIN_THRESHOLD_NS`], then
/// spins on the monotonic clock for the remainder. See the module doc
/// comment for why this shape and not a plain relative sleep.
///
/// `pub`, beyond issue #410's own Files table line for `lib.rs`, for the
/// same reason [`scan_response_head`] is: the Benchmarks section's own
/// `probe/wait_until/1ms` criterion target measures this exact function's
/// overshoot from `benches/harness.rs`, a separate crate that can see only
/// this crate's public API.
pub fn wait_until(time: &SharedTime, deadline_ns: u64) {
    loop {
        let now = time.precise().as_measurement_nanos();
        if now >= deadline_ns {
            return;
        }
        let remaining = deadline_ns.saturating_sub(now);
        if remaining > SPIN_THRESHOLD_NS {
            // The duration is recomputed from the absolute `deadline_ns`
            // every iteration, so a spurious wakeup or an overshoot here
            // cannot accumulate: see the module doc comment.
            let park_for = remaining.saturating_sub(SPIN_THRESHOLD_NS);
            std::thread::park_timeout(Duration::from_nanos(park_for)); // it-allow: no-accumulated-sleep reason: duration is recomputed from the absolute deadline_ns on every loop iteration, so a spurious wakeup or overshoot cannot accumulate; see the module doc comment
        } else {
            std::hint::spin_loop();
        }
    }
}

/// One completed exchange: a response was read in full (however it was
/// classified), and the probe knows how long that took.
struct ExchangeOutcome {
    ttfb_ns: u64,
    completion_ns: u64,
    /// `true` for a 200 response with framing the probe trusted.
    ok: bool,
    /// `true` when the connection must be closed: the head was framing
    /// unsafe (see [`wire::BadReason`]), not merely a non-200 status.
    needs_reconnect: bool,
}

/// An exchange that never completed at all: no sample to record.
struct ExchangeFailed;

/// Reads exactly one response, from the write having already succeeded
/// through either a trusted, fully-consumed body or a framing refusal.
///
/// `deadline_ns` is the ABSOLUTE instant (from the request's due time, per
/// [`REQUEST_DEADLINE_NS`]) that bounds the whole exchange: every read's own
/// timeout is recomputed from the time REMAINING to this one deadline, so a
/// peer that keeps resetting a per-read timeout by dribbling one byte at a
/// time cannot hold the probe past it.
fn read_exchange(
    stream: &mut TcpStream,
    time: &SharedTime,
    buf: &mut [u8; READ_BUFFER_BYTES],
    deadline_ns: u64,
) -> Result<ExchangeOutcome, ExchangeFailed> {
    let mut filled = 0usize;
    let mut ttfb_ns: Option<u64> = None;

    let head = loop {
        let now = time.precise().as_measurement_nanos();
        if now >= deadline_ns {
            return Err(ExchangeFailed);
        }
        let remaining = deadline_ns.saturating_sub(now);
        if stream
            .set_read_timeout(Some(Duration::from_nanos(remaining)))
            .is_err()
        {
            return Err(ExchangeFailed);
        }

        let Some(target) = buf.get_mut(filled..) else {
            return Err(ExchangeFailed);
        };
        if target.is_empty() {
            // The buffer filled without scan_response_head ever reporting
            // HeadTooLarge, which cannot happen: it fires the moment
            // `filled >= READ_BUFFER_BYTES`, checked below every time this
            // loop appends bytes. Defensive only.
            return Err(ExchangeFailed);
        }

        let n = match stream.read(target) {
            Ok(0) => return Err(ExchangeFailed),
            Ok(n) => n,
            Err(_read_error) => return Err(ExchangeFailed),
        };
        filled = filled.saturating_add(n);

        if ttfb_ns.is_none() {
            let scanned = buf.get(..filled).unwrap_or(&[]);
            if scanned.windows(2).any(|w| w == b"\r\n") {
                ttfb_ns = Some(time.precise().as_measurement_nanos());
            }
        }

        let scanned = buf.get(..filled).unwrap_or(&[]);
        match scan_response_head(scanned) {
            ScanOutcome::NeedMore => {}
            ScanOutcome::Bad(_reason) => {
                let completion_ns = time.precise().as_measurement_nanos();
                let ttfb = ttfb_ns.unwrap_or(completion_ns);
                return Ok(ExchangeOutcome {
                    ttfb_ns: ttfb,
                    completion_ns,
                    ok: false,
                    needs_reconnect: true,
                });
            }
            ScanOutcome::Complete(head) => break head,
        }
    };

    // The status line always precedes the head terminator, so ttfb_ns is
    // always Some by the time a head is Complete; the fallback exists only
    // to avoid ever unwrapping it.
    let ttfb = ttfb_ns.unwrap_or_else(|| time.precise().as_measurement_nanos());

    let already_buffered = filled.saturating_sub(head.head_len);
    let body_in_buf = u64::try_from(already_buffered)
        .unwrap_or(u64::MAX)
        .min(head.content_length);
    let remaining_body = head.content_length.saturating_sub(body_in_buf);

    if remaining_body > 0 && discard_body(stream, time, buf, remaining_body, deadline_ns).is_err() {
        return Err(ExchangeFailed);
    }

    let completion_ns = time.precise().as_measurement_nanos();
    Ok(ExchangeOutcome {
        ttfb_ns: ttfb,
        completion_ns,
        ok: head.status == 200,
        needs_reconnect: false,
    })
}

/// Reads and discards exactly `remaining` declared body bytes, reusing `buf`
/// as scratch space: the probe never inspects a response body, and this is
/// what lets a body far larger than [`READ_BUFFER_BYTES`] (test 3's 64 KiB
/// body, or the largest a real run allows) be consumed with no allocation
/// and no buffer larger than the fixed one the thread already owns.
fn discard_body(
    stream: &mut TcpStream,
    time: &SharedTime,
    buf: &mut [u8; READ_BUFFER_BYTES],
    mut remaining: u64,
    deadline_ns: u64,
) -> Result<(), ExchangeFailed> {
    while remaining > 0 {
        let now = time.precise().as_measurement_nanos();
        if now >= deadline_ns {
            return Err(ExchangeFailed);
        }
        let time_remaining = deadline_ns.saturating_sub(now);
        if stream
            .set_read_timeout(Some(Duration::from_nanos(time_remaining)))
            .is_err()
        {
            return Err(ExchangeFailed);
        }

        #[expect(
            clippy::cast_possible_truncation,
            reason = "remaining.min(buf.len() as u64) is bounded above by buf.len() (a usize \
                      cast up to u64 immediately above), so the result fits back into usize on \
                      every platform this workspace targets"
        )]
        let want = remaining.min(buf.len() as u64) as usize;
        let Some(target) = buf.get_mut(..want) else {
            return Err(ExchangeFailed);
        };
        match stream.read(target) {
            Ok(0) => return Err(ExchangeFailed),
            Ok(n) => remaining = remaining.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX)),
            Err(_read_error) => return Err(ExchangeFailed),
        }
    }
    Ok(())
}

/// The probe thread's whole life: pin, connect, report readiness, then drive
/// the schedule until `expected_requests` is reached, a stop is requested, or
/// [`MAX_CONSECUTIVE_ERRORS`] consecutive exchanges fail.
#[allow(
    clippy::too_many_lines,
    reason = "one cohesive per-connection state machine (reset check, pace, send, read, \
              classify, reconnect); splitting it would scatter state that reads naturally \
              kept in one place, mirroring irontraffic-origin's own handle_connection"
)]
fn run_probe(mut args: RunArgs) -> ProbeOutcome {
    let pinned = pin_to_core(args.config.core_id);

    let connect_start = args.time.precise().as_measurement_nanos();
    let mut stream = match connect(args.config.target) {
        Ok(stream) => stream,
        Err(source) => {
            let error = BenchError::io(&args.config.target.to_string(), source);
            // it-allow: no-swallowed-error reason: this send's only possible failure is a disconnected receiver, which means spawn() already gave up waiting and there is nobody left to tell
            let _ = args.ready_tx.send(Err(error));
            return ProbeOutcome::startup_failed(
                pinned,
                args.latency,
                args.ttfb,
                args.connect,
                args.stall.recorder().clone(),
            );
        }
    };
    let connect_ns = args
        .time
        .precise()
        .as_measurement_nanos()
        .saturating_sub(connect_start);
    args.connect.record_ns(connect_ns);

    // it-allow: no-swallowed-error reason: a disconnected receiver here means the caller already gave up (spawn()'s own recv() timed out or the caller was dropped); the probe still runs, and there is nobody left to tell
    let _ = args.ready_tx.send(Ok(()));

    let origin_ns = args.time.precise().as_measurement_nanos();
    let schedule = match Schedule::new(origin_ns, args.config.rate_hz, 1) {
        Ok(schedule) => schedule,
        // rate_hz == 0 is already rejected in `ProbeHandle::spawn`; a rate
        // above Schedule's own ceiling is the only way to reach this, and
        // there is no established connection semantics for "half a run":
        // report exactly what happened, connect sample included.
        Err(_out_of_range_rate) => {
            return ProbeOutcome::startup_failed(
                pinned,
                args.latency,
                args.ttfb,
                args.connect,
                args.stall.recorder().clone(),
            );
        }
    };

    let mut buf = [0u8; READ_BUFFER_BYTES];
    let mut issued: u64 = 0;
    let mut ok: u64 = 0;
    let mut bad: u64 = 0;
    let mut errors: u64 = 0;
    let mut reconnects: u64 = 0;
    let mut consecutive_errors: u64 = 0;
    let mut aborted = false;
    let mut ack_generation: u64 = 0;
    let mut connected = true;

    // BEGIN steady-state request loop: allocation-free (test 10 measures
    // this exact window). Nothing between here and its closing brace below
    // may allocate; the acceptance criteria's own grep for
    // `format!`/`String::from`/`to_string`/`Vec::new`/`Box::new` in this
    // file is checked against everything OUTSIDE this delimited block.
    for i in 0..args.config.expected_requests {
        let requested_generation = args.reset_requested.load(Ordering::Acquire);
        if requested_generation != ack_generation {
            args.discarded.store(args.latency.len(), Ordering::Release); // it-allow: single-snapshot-publish reason: plain AtomicU64 counter reporting a discard count, not an ArcSwap config snapshot publish
            if let (Ok(fresh_latency), Ok(fresh_ttfb), Ok(fresh_connect), Ok(fresh_stall)) = (
                LatencyRecorder::new(),
                LatencyRecorder::new(),
                LatencyRecorder::new(),
                StallTracker::new(),
            ) {
                args.latency = fresh_latency;
                args.ttfb = fresh_ttfb;
                args.connect = fresh_connect;
                args.stall = fresh_stall;
                ack_generation = requested_generation;
                args.reset_acked
                    .store(requested_generation, Ordering::Release); // it-allow: single-snapshot-publish reason: plain AtomicU64 generation counter acknowledging a reset, not an ArcSwap config snapshot publish
            }
            // Construction failing here (allocator exhaustion) leaves the
            // old recorders and the old generation in place: the probe
            // keeps running rather than crashing, and `reset_recorders`
            // observes exactly what a hung reset looks like (a timeout)
            // rather than the process going down.
        }

        if args.stop_requested.load(Ordering::Acquire) {
            break;
        }

        let Some(due) = schedule.due_ns(i) else {
            break;
        };
        args.stall.on_blocked(due);
        wait_until(&args.time, due);
        issued = issued.saturating_add(1);

        if !connected {
            let reconnect_start = args.time.precise().as_measurement_nanos();
            match connect(args.config.target) {
                Ok(fresh) => {
                    let reconnect_ns = args
                        .time
                        .precise()
                        .as_measurement_nanos()
                        .saturating_sub(reconnect_start);
                    args.connect.record_ns(reconnect_ns);
                    stream = fresh;
                    connected = true;
                    reconnects = reconnects.saturating_add(1);
                }
                Err(_reconnect_error) => {
                    errors = errors.saturating_add(1);
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        aborted = true;
                        break;
                    }
                    continue;
                }
            }
        }

        let deadline_ns = due.saturating_add(REQUEST_DEADLINE_NS);
        let write_now = args.time.precise().as_measurement_nanos();
        if write_now >= deadline_ns {
            errors = errors.saturating_add(1);
            consecutive_errors = consecutive_errors.saturating_add(1);
            connected = false;
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                aborted = true;
                break;
            }
            continue;
        }
        let write_remaining = deadline_ns.saturating_sub(write_now);
        let write_ok = stream
            .set_write_timeout(Some(Duration::from_nanos(write_remaining)))
            .is_ok()
            && stream
                .write_all(
                    args.request
                        .get(..args.request_len)
                        .unwrap_or(&args.request[..]),
                )
                .is_ok();

        if !write_ok {
            errors = errors.saturating_add(1);
            consecutive_errors = consecutive_errors.saturating_add(1);
            connected = false;
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                aborted = true;
                break;
            }
            continue;
        }

        let send_now = args.time.precise().as_measurement_nanos();
        args.stall.on_unblocked(send_now);

        if let Ok(exchange) = read_exchange(&mut stream, &args.time, &mut buf, deadline_ns) {
            args.latency
                .record_ns(exchange.completion_ns.saturating_sub(due));
            args.ttfb.record_ns(exchange.ttfb_ns.saturating_sub(due));
            consecutive_errors = 0;
            if exchange.ok {
                ok = ok.saturating_add(1);
            } else {
                bad = bad.saturating_add(1);
            }
            if exchange.needs_reconnect {
                connected = false;
            }
        } else {
            errors = errors.saturating_add(1);
            consecutive_errors = consecutive_errors.saturating_add(1);
            connected = false;
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                aborted = true;
                break;
            }
        }
    }
    // END steady-state request loop.

    let mut stall_recorder = args.stall.recorder().clone();
    // Folds the tracker's own separately counted out-of-range stalls
    // (longer than HIGH_NS) into the extracted recorder's own
    // `out_of_range` counter, which is what `ProbeOutcome::stall` (a bare
    // `LatencyRecorder`) exposes. `record_n_ns` with a value above `HIGH_NS`
    // only ever touches `out_of_range`, never the histogram itself (see
    // `LatencyRecorder::record_n_ns`), and a count of 0 is a documented
    // no-op, so this is exact and safe to call unconditionally.
    stall_recorder.record_n_ns(HIGH_NS.saturating_add(1), args.stall.out_of_range());

    ProbeOutcome {
        latency: args.latency,
        ttfb: args.ttfb,
        connect: args.connect,
        stall: stall_recorder,
        issued,
        ok,
        bad,
        errors,
        reconnects,
        pinned,
        warmup_discarded: args.discarded.load(Ordering::Acquire),
        aborted,
    }
}
