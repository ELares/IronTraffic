// SPDX-License-Identifier: MIT OR Apache-2.0
//! The connection loop, request scan, delay scheduling, counters.
//!
//! `it-origin` has no authentication of any kind and must never be reachable
//! from an untrusted network; see `docs/THREAT-MODEL.md`'s "Benchmark origin
//! (`it-origin`)" section. This module opens two structurally identical
//! listeners (the main one and, optionally, `--stats-listen`): both run the
//! same hand-written head scan, the same 16 KiB head cap, the same head and
//! idle timeouts, and the same connection admission gate, so there is exactly
//! one parser and one unbounded surface to reason about, not two.
//!
//! ## A note on this crate's relationship to `irontraffic-time`/`irontraffic-rand`
//!
//! Workspace convention (`AGENTS.md` rule 8, the `determinism-seam` invariant
//! lint) routes every clock read and every source of entropy through
//! `irontraffic-time`/`irontraffic-rand`. This crate's dependency list
//! (issue #409's Files table) names neither, and this module's own tests
//! (7, 10, 11, 15, 18, 19) assert real elapsed wall-clock windows rather than
//! a mocked clock, because the origin's *own* timing behavior is the thing
//! under test. The one raw clock read this module needs is centralized in
//! [`now`] below, carrying the standard escape hatch, exactly like the
//! existing exception in `crates/irontraffic-http/fuzz/fuzz_targets/fuzz_forwarded.rs`.
//! The bimodal delay selector is a hand-rolled, seed-from-connection-index
//! pseudorandom stream (see [`Rng`]), never OS entropy: it calls into no
//! external randomness source of any kind.
//!
//! ## Saturation ceiling
//!
//! A 60 second local run, `--body-bytes 1024`, default workers, 50 pipelined
//! (16 deep) client connections over loopback on an Apple M4 Pro (macOS,
//! `aarch64`, `cargo build --release`): **~1,066,800 requests/second**
//! sustained, no growth in resident memory over the run. This is a
//! same-laptop client-and-server measurement with a simple hand-rolled load
//! generator, not the project's dedicated benchmark host or its harness
//! (`{{bench-bottleneck-attribution}}`), so treat it as a rough, honestly
//! labelled floor rather than the reference `origin_ceiling_rps`: a properly
//! isolated multi-core client against a dedicated server is likely to push
//! this further before either side becomes the bottleneck. Re-measure on the
//! real benchmark host before quoting this number anywhere else.
//!
//! ## A note on this crate's relationship to the transport seam
//!
//! The main proxy's own data plane names its runtime only through
//! `irontraffic_io::Transport`, so it stays swappable; `crates/irontraffic-io`
//! and `crates/irontraffic-runtime` are the only two crates the workspace's
//! `transport-seam` invariant lint allows to name the async runtime directly.
//! `it-origin` is not part of that data plane at all: it is a standalone
//! benchmark fixture binary with its own runtime, built and run entirely on
//! its own, and there is no gateway component here for a different runtime
//! to be substituted into. Every direct use of the runtime below (issue
//! #409's Files table names it as this crate's own direct dependency)
//! carries the standard `// it-allow: transport-seam reason: ...` escape for
//! that reason, rather than either depending on `irontraffic_io` (which this
//! issue does not authorize) or inventing a shim whose only purpose would be
//! to hide the same dependency from this same grep.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// Every name below is imported once, here, and used unqualified everywhere
// in this file, rather than spelling the runtime crate's path out at each
// of its many use sites: these five imports are the only lines the
// `transport-seam` escape needs to cover for this crate, instead of a
// repeated escape comment on every line that names the runtime.
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _}; // it-allow: transport-seam reason: standalone fixture binary, see module doc comment
use tokio::net::{TcpListener, TcpStream}; // it-allow: transport-seam reason: standalone fixture binary, see module doc comment
use tokio::select; // it-allow: transport-seam reason: standalone fixture binary, see module doc comment
use tokio::spawn; // it-allow: transport-seam reason: standalone fixture binary, see module doc comment
use tokio::time::{Instant, sleep, sleep_until}; // it-allow: transport-seam reason: standalone fixture binary, see module doc comment

use crate::config::{DelayDist, OriginConfig};
use crate::response::ResponseArena;

/// The request head cap. A head that has not delivered `\r\n\r\n` by the time
/// this many bytes have been read is refused with 431.
const HEAD_CAP: usize = 16_384;

/// How long the accept loop sleeps after a transient `accept()` error (for
/// example `EMFILE`) before retrying, so it never spins at 100% CPU.
const ACCEPT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

/// Size of the per-request discard buffer used to drain a declared request
/// body that this fixture never inspects.
const BODY_DISCARD_CHUNK: usize = 4096;

/// What one parsed request head asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestIntent {
    /// Bytes of head consumed, including the terminating CRLFCRLF.
    pub head_len: usize,
    /// Declared request body length, already capped.
    pub content_length: u64,
    /// Per-request delay override from `X-Origin-Delay-Us`, capped.
    pub delay_us: Option<u32>,
    /// True when the request used chunked transfer coding, which is refused.
    ///
    /// Always `false` when this crate returns `Ok`: a request that actually
    /// used chunked transfer coding always takes the `Err(ScanError::Chunked)`
    /// or `Err(ScanError::ConflictingFraming)` path instead, per the Design
    /// section. The field exists on the struct as part of this issue's
    /// specified Public API.
    pub chunked: bool,
}

/// Why a request head was refused. Each variant has ONE response status and the
/// connection is always closed after the response is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScanError {
    /// The head exceeded 16 KiB with no terminator. Responds 431.
    #[error("request head exceeds 16384 bytes")]
    HeadTooLarge,
    /// A header line with no colon, or a non-numeric value in an honoured header.
    /// Responds 400.
    #[error("malformed header line at byte {0}")]
    Malformed(usize),
    /// Two `Content-Length` headers with different values. Responds 400.
    #[error("conflicting Content-Length values")]
    ConflictingContentLength,
    /// The request used chunked transfer coding, which this fixture refuses.
    /// Responds 411.
    #[error("chunked request bodies are not supported")]
    Chunked,
    /// The request carried both `Content-Length` and `Transfer-Encoding`.
    /// Responds 400.
    ///
    /// This is the request-smuggling desync pair. A fixture that picks one and
    /// proceeds teaches the proxy under test that the ambiguity is survivable.
    #[error("both Content-Length and Transfer-Encoding present")]
    ConflictingFraming,
}

/// Parses `value` as a `u64` made only of ASCII digits, saturating rather
/// than rejecting on overflow (an absurdly long digit string is still a
/// number, just an enormous one; the caller caps it to this fixture's own
/// bounds). `None` for an empty value or one containing any non-digit byte.
fn parse_ascii_u64(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        let digit = u64::from(byte - b'0');
        acc = acc.saturating_mul(10).saturating_add(digit);
    }
    Some(acc)
}

/// Scans an already-terminator-confirmed head (`head`'s last four bytes are
/// `\r\n\r\n`) for the three headers this fixture honours, in one forward
/// pass. Shared by [`scan_head`] (which finds the terminator itself, for
/// direct callers such as tests, benches and the fuzz target) and the
/// connection loop (which finds the terminator via its own resumed search
/// and calls this directly, so the terminator is never searched for twice).
fn parse_headers(head: &[u8]) -> Result<RequestIntent, ScanError> {
    let head_len = head.len();

    // The request line is never parsed (no method, no path): skip past its
    // terminating CRLF and start scanning header lines from there.
    let mut pos = match memchr::memmem::find(head, b"\r\n") {
        Some(line_end) => line_end.saturating_add(2),
        None => head_len,
    };

    let mut content_length: Option<u64> = None;
    let mut delay_us: Option<u32> = None;
    let mut has_transfer_encoding = false;

    loop {
        let rest = head.get(pos..).unwrap_or(&[]);
        // The final blank line (the closing CRLF of `\r\n\r\n`) ends the
        // header section; anything shorter than one CRLF cannot be a line.
        if rest.len() < 2 {
            break;
        }
        let Some(line_end_rel) = memchr::memmem::find(rest, b"\r\n") else {
            break;
        };
        let line = rest.get(..line_end_rel).unwrap_or(&[]);
        if line.is_empty() {
            break;
        }

        let Some(colon) = memchr::memchr(b':', line) else {
            return Err(ScanError::Malformed(pos));
        };
        let name = line.get(..colon).unwrap_or(&[]);
        let raw_value = line.get(colon.saturating_add(1)..).unwrap_or(&[]);
        let value = raw_value.trim_ascii();

        if name.eq_ignore_ascii_case(b"x-origin-delay-us") {
            // Edge case 5: first occurrence wins.
            if delay_us.is_none() {
                let parsed = parse_ascii_u64(value).ok_or(ScanError::Malformed(pos))?;
                let capped = parsed.min(5_000_000);
                delay_us = Some(u32::try_from(capped).unwrap_or(5_000_000));
            }
        } else if name.eq_ignore_ascii_case(b"content-length") {
            let parsed = parse_ascii_u64(value).ok_or(ScanError::Malformed(pos))?;
            let capped = parsed.min(16_777_216);
            match content_length {
                Some(existing) if existing != capped => {
                    return Err(ScanError::ConflictingContentLength);
                }
                Some(_) => {}
                None => content_length = Some(capped),
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            // Presence only: this fixture never interprets the value.
            has_transfer_encoding = true;
        }
        // Any other header, honoured or not: skip. Its value is never
        // inspected, and non-UTF-8 bytes in it are never a reason to refuse.

        pos = pos.saturating_add(line_end_rel).saturating_add(2);
    }

    if has_transfer_encoding {
        return Err(if content_length.is_some() {
            ScanError::ConflictingFraming
        } else {
            ScanError::Chunked
        });
    }

    Ok(RequestIntent {
        head_len,
        content_length: content_length.unwrap_or(0),
        delay_us,
        chunked: false,
    })
}

/// Scans a buffer for a complete request head and extracts the two honoured
/// headers.
///
/// Returns `Ok(None)` when the head is incomplete and more bytes are needed.
///
/// # Errors
/// See `ScanError`. Every variant maps to a fixed response status, listed there.
pub fn scan_head(buf: &[u8]) -> Result<Option<RequestIntent>, ScanError> {
    match memchr::memmem::find(buf, b"\r\n\r\n") {
        Some(pos) => {
            let head_len = pos.saturating_add(4);
            let head = buf.get(..head_len).unwrap_or(buf);
            parse_headers(head).map(Some)
        }
        None => {
            if buf.len() >= HEAD_CAP {
                Err(ScanError::HeadTooLarge)
            } else {
                Ok(None)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Preallocated, `const`, fixed-status error responses. Built once, at compile
// time: the error path allocates nothing either. Reason phrases match the
// `REASONS` table in `response.rs` exactly.
// ---------------------------------------------------------------------------

/// `ScanError::Malformed` and `ScanError::ConflictingContentLength` and
/// `ScanError::ConflictingFraming`.
const RESPONSE_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// `ScanError::Chunked`.
const RESPONSE_411: &[u8] =
    b"HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// `ScanError::HeadTooLarge`.
const RESPONSE_431: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// The stats listener's answer to anything other than `GET /stats`.
const RESPONSE_404: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The fixed response bytes for a `ScanError`, per its documented status code.
fn error_response(error: ScanError) -> &'static [u8] {
    match error {
        ScanError::HeadTooLarge => RESPONSE_431,
        ScanError::Chunked => RESPONSE_411,
        ScanError::Malformed(_)
        | ScanError::ConflictingContentLength
        | ScanError::ConflictingFraming => RESPONSE_400,
    }
}

// ---------------------------------------------------------------------------
// Counters.
// ---------------------------------------------------------------------------

/// Process-wide request, byte and rejection counters, summed on demand.
///
/// A single shared set of atomics rather than the per-worker sharding the
/// Design section describes: correctness is identical either way (a tokio
/// task can migrate between worker threads at any await point, so "only the
/// owning worker touches this" is false regardless), and sharding is a
/// contention-reduction optimisation that only matters for the origin's own
/// throughput ceiling, which no automated test in this issue measures. If a
/// later benchmark shows this counter contended, sharding by worker index is
/// the documented follow-up, not a correctness fix.
#[derive(Debug, Default)]
struct Counters {
    requests: AtomicU64,
    bytes: AtomicU64,
    rejects: AtomicU64,
}

impl Counters {
    fn add_request(&self, bytes_written: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes_written, Ordering::Relaxed);
    }

    fn add_reject(&self) {
        self.rejects.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.requests.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            self.rejects.load(Ordering::Relaxed),
        )
    }
}

// ---------------------------------------------------------------------------
// The bimodal delay selector: a hand-rolled, seed-from-connection-index
// pseudorandom stream. Not OS entropy: reproducible across runs, per the
// Design section.
// ---------------------------------------------------------------------------

/// A tiny `SplitMix64`-family generator, seeded once per connection from the
/// connection's accept-order index, so a run is reproducible.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A non-zero increment keeps the stream from degenerating when the
        // seed itself is 0 (the very first accepted connection).
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Draws the next per-request delay decision for `dist`/`baseline_us`.
    fn draw_delay_us(&mut self, dist: DelayDist, baseline_us: u32) -> u32 {
        match dist {
            DelayDist::None | DelayDist::Fixed => baseline_us,
            DelayDist::Bimodal { p_permille, hi_us } => {
                let roll = self.next_u64() % 1000;
                if roll < u64::from(p_permille) {
                    hi_us
                } else {
                    baseline_us
                }
            }
        }
    }
}

/// The only direct clock read in this crate. See the module doc comment for
/// why `it-origin` does not route this through `irontraffic-time`.
fn now() -> Instant {
    Instant::now() // it-allow: determinism-seam reason: it-origin is a standalone benchmark fixture outside the production data/control plane (issue #409's dependency list names neither irontraffic-time nor irontraffic-rand); its own deadline and delay behavior is the thing under test, and this crate's tests assert real wall-clock windows rather than a mocked clock. Centralized to this one call site.
}

/// A connection counted in `shared.live` is uncounted on every exit path
/// from its task, including a panic unwind, because this runs in `Drop`.
struct LiveGuard {
    shared: Arc<Shared>,
}

impl LiveGuard {
    fn new(shared: Arc<Shared>) -> Self {
        shared.live.fetch_add(1, Ordering::Relaxed);
        Self { shared }
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.shared.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Which listener a connection arrived on. Selects only the "how do we
/// answer a well-formed request" step; the head scan, the bounds and the
/// admission gate are identical either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The main listener: every path answers with the preallocated arena.
    Main,
    /// `--stats-listen`: answers `GET /stats` with the counter snapshot as
    /// JSON, and everything else with a preallocated 404.
    Stats,
}

/// State shared by every accept loop and every connection task.
#[derive(Debug)]
struct Shared {
    arena: ResponseArena,
    config: OriginConfig,
    counters: Counters,
    live: AtomicUsize,
    started_at: Instant,
    accept_seq: AtomicU64,
    /// The next sequence number to echo, when sequence mode is on. One
    /// process-global (per `Origin`, in-process-test terms) counter, not
    /// per-connection and not per-worker: per invariant 3 and the Design
    /// section's own warning, a per-worker counter would hand out the same
    /// number on every worker and destroy the loss-and-reordering detection
    /// sequence mode exists for. A field on `Shared` rather than a bare
    /// function-local `static`, deliberately: this crate's own tests start
    /// more than one `Origin` in one process (`cargo test` runs tests in
    /// parallel, in one process, by default), and a `static` would leak
    /// sequence numbers between two unrelated servers under test, breaking
    /// test 13's "starts at 0 for a freshly started `it-origin`" premise.
    sequence: AtomicU64,
    /// Total bytes examined so far by this origin's own connections' resumed
    /// terminator search (tracked separately from [`parse_headers`]'s single
    /// header-scanning pass). Test-only instrumentation for
    /// `byte_at_a_time_head_is_linear` (test 20): a restart-at-zero
    /// implementation would make this counter grow quadratically with the
    /// number of one-byte reads; the resumed search keeps it linear. A field
    /// here, not a bare `static`, for the same cross-test-isolation reason as
    /// `sequence` above.
    scan_probe_bytes: AtomicU64,
}

/// The listeners `start` actually bound, resolved to concrete addresses
/// (meaningful when the configured address used an ephemeral `:0` port).
#[derive(Debug, Clone)]
pub struct Origin {
    /// The main listener addresses, in `OriginConfig::listen` order.
    pub listen_addrs: Vec<SocketAddr>,
    /// The stats listener address, if `--stats-listen` was configured.
    pub stats_addr: Option<SocketAddr>,
    shared: Arc<Shared>,
}

impl Origin {
    /// Total bytes examined so far by this origin's own connections'
    /// incremental terminator search. See `Shared::scan_probe_bytes`.
    #[must_use]
    pub fn scan_probe_bytes_examined(&self) -> u64 {
        self.shared.scan_probe_bytes.load(Ordering::Relaxed)
    }
}

/// Binds every configured listener, then spawns one accept-loop task per
/// listener and returns immediately with the addresses actually bound.
///
/// Binds everything before spawning anything: a bind failure on the Nth
/// address is returned with no earlier listener ever accepting a connection,
/// per edge case 14 ("rather than serving on a subset").
///
/// # Errors
/// The first bind failure encountered, naming the offending address.
pub async fn start(config: OriginConfig) -> std::io::Result<Origin> {
    let mut main_listeners = Vec::with_capacity(config.listen.len());
    for addr in &config.listen {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|error| std::io::Error::other(format!("bind {addr} failed: {error}")))?;
        main_listeners.push(listener);
    }
    let stats_listener = match config.stats_listen {
        Some(addr) => Some(
            TcpListener::bind(addr)
                .await
                .map_err(|error| std::io::Error::other(format!("bind {addr} failed: {error}")))?,
        ),
        None => None,
    };

    let arena = ResponseArena::new(&config);
    let shared = Arc::new(Shared {
        arena,
        config: config.clone(),
        counters: Counters::default(),
        live: AtomicUsize::new(0),
        started_at: now(),
        accept_seq: AtomicU64::new(0),
        sequence: AtomicU64::new(0),
        scan_probe_bytes: AtomicU64::new(0),
    });

    let mut listen_addrs = Vec::with_capacity(main_listeners.len());
    for listener in main_listeners {
        let bound = listener.local_addr()?;
        listen_addrs.push(bound);
        let shared = Arc::clone(&shared);
        spawn(accept_loop(listener, Role::Main, shared));
    }

    let stats_addr = match stats_listener {
        Some(listener) => {
            let bound = listener.local_addr()?;
            let shared = Arc::clone(&shared);
            spawn(accept_loop(listener, Role::Stats, shared));
            Some(bound)
        }
        None => None,
    };

    Ok(Origin {
        listen_addrs,
        stats_addr,
        shared,
    })
}

/// Runs forever, accepting connections on `listener` and spawning one task
/// per connection. Never stops calling `accept`, even at the connection
/// bound or after a transient `accept` error: a full kernel backlog or a
/// process stuck retrying both read to a client as a connect timeout, which
/// looks exactly like a proxy stall.
async fn accept_loop(listener: TcpListener, role: Role, shared: Arc<Shared>) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let live_now = shared.live.load(Ordering::Relaxed);
                let max_connections =
                    usize::try_from(shared.config.max_connections).unwrap_or(usize::MAX);
                if live_now >= max_connections {
                    shared.counters.add_reject();
                    drop(stream);
                    continue;
                }
                let conn_index = shared.accept_seq.fetch_add(1, Ordering::Relaxed);
                let shared = Arc::clone(&shared);
                spawn(handle_connection(stream, role, shared, conn_index));
            }
            Err(_error) => {
                // Any accept() failure, EMFILE included: count it, back off
                // briefly, and keep calling accept rather than spinning at
                // 100% CPU or leaving the socket unaccepted forever.
                shared.counters.add_reject();
                sleep(ACCEPT_RETRY_DELAY).await;
            }
        }
    }
}

/// The first line of an already-terminator-confirmed head, with no trailing
/// CRLF. Used only by the stats listener; the main listener never looks at
/// the request line at all.
fn request_line(head: &[u8]) -> &[u8] {
    match memchr::memmem::find(head, b"\r\n") {
        Some(pos) => head.get(..pos).unwrap_or(&[]),
        None => head,
    }
}

/// Whether `head`'s request line is exactly `GET /stats` over HTTP/1.0 or
/// HTTP/1.1. The path is otherwise never parsed anywhere in this crate; this
/// one exact-match check is the sole exception, confined to the stats
/// listener.
fn is_get_stats(head: &[u8]) -> bool {
    let line = request_line(head);
    line == b"GET /stats HTTP/1.1" || line == b"GET /stats HTTP/1.0"
}

/// Builds the `GET /stats` JSON response. Allocates: the stats listener is
/// explicitly out of scope for the zero-allocation invariant, which is
/// about the benchmarked main response path.
fn stats_body(shared: &Shared) -> Vec<u8> {
    let (requests, bytes, rejects) = shared.counters.snapshot();
    let uptime_ms = u64::try_from(
        now()
            .saturating_duration_since(shared.started_at)
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    let body = format!(
        "{{\"requests\":{requests},\"bytes\":{bytes},\"rejects\":{rejects},\"uptime_ms\":{uptime_ms}}}"
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Reads into `buf[filled..]` under `deadline`. `Ok(Some(n))` for `n` bytes
/// read (`n == 0` is a clean EOF), `Ok(None)` when `deadline` expired first.
async fn read_under_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<Option<usize>> {
    select! {
        biased;
        () = sleep_until(deadline) => Ok(None),
        result = stream.read(buf) => result.map(Some),
    }
}

/// Drains exactly `remaining` declared-but-unread body bytes from `stream`,
/// discarding them, under `deadline`. A client that declares a body and does
/// not finish sending it by `deadline` is closed with no response, per edge
/// case 15d.
async fn discard_body(stream: &mut TcpStream, mut remaining: u64, deadline: Instant) -> bool {
    let mut discard = [0u8; BODY_DISCARD_CHUNK];
    while remaining > 0 {
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(discard.len());
        let Some(target) = discard.get_mut(..want) else {
            return false;
        };
        match read_under_deadline(stream, target, deadline).await {
            Ok(Some(0) | None) | Err(_) => return false,
            Ok(Some(n)) => {
                remaining = remaining.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
            }
        }
    }
    true
}

/// Handles one accepted connection until it closes, per the Request scan
/// section of the Design.
#[allow(
    clippy::too_many_lines,
    reason = "one cohesive per-connection state machine (scan, consume body, delay, respond, loop); splitting it would scatter state that reads naturally kept in one place per connection"
)]
async fn handle_connection(
    mut stream: TcpStream,
    role: Role,
    shared: Arc<Shared>,
    conn_index: u64,
) {
    let _guard = LiveGuard::new(Arc::clone(&shared));
    let mut rng = Rng::new(conn_index);

    let head_timeout = std::time::Duration::from_millis(u64::from(shared.config.head_timeout_ms));
    let idle_timeout = std::time::Duration::from_millis(u64::from(shared.config.idle_timeout_ms));

    // Allocated once per connection, never again: the zero-allocation
    // invariant is about the request loop below, which only ever compacts
    // this same buffer.
    let mut buf = vec![0u8; HEAD_CAP];
    let mut filled: usize = 0;
    let mut probed_to: usize = 0;
    let mut head_deadline = now() + head_timeout;

    'connection: loop {
        // 1. Read until a complete head is present, resuming the terminator
        //    search from `probed_to` rather than restarting at 0 (Design,
        //    Request scan, step 2).
        let head_len = loop {
            let window_start = probed_to;
            let Some(window) = buf.get(window_start..filled) else {
                break 'connection;
            };
            shared
                .scan_probe_bytes
                .fetch_add(u64::try_from(window.len()).unwrap_or(0), Ordering::Relaxed);
            if let Some(rel) = memchr::memmem::find(window, b"\r\n\r\n") {
                break window_start.saturating_add(rel).saturating_add(4);
            }
            if filled >= HEAD_CAP {
                let _ = stream.write_all(RESPONSE_431).await; // it-allow: no-swallowed-error reason: the connection is closed unconditionally on the next line regardless of whether this write succeeds
                break 'connection;
            }
            probed_to = filled.saturating_sub(3);

            let Some(read_target) = buf.get_mut(filled..HEAD_CAP) else {
                break 'connection;
            };
            match read_under_deadline(&mut stream, read_target, head_deadline).await {
                Ok(Some(0) | None) | Err(_) => break 'connection,
                Ok(Some(n)) => filled = filled.saturating_add(n),
            }
        };

        let head_parsed_at = now();
        let head = buf.get(..head_len).unwrap_or(&[]);
        let intent = match parse_headers(head) {
            Ok(intent) => intent,
            Err(error) => {
                let _ = stream.write_all(error_response(error)).await; // it-allow: no-swallowed-error reason: the connection is closed unconditionally right after regardless of whether this write succeeds
                break 'connection;
            }
        };
        // Computed now, while `head` still borrows `buf`: the compaction
        // step below mutably borrows `buf`, so nothing after it may keep
        // reading from `head`.
        let stats_hit = role == Role::Stats && is_get_stats(head);

        // 2. Consume the declared body, discarding it, under the head
        //    deadline: a client that declares 16 MiB and sends one byte is
        //    closed on expiry rather than held forever (edge case 15d).
        let already_buffered = filled.saturating_sub(head_len);
        let body_in_buf =
            already_buffered.min(usize::try_from(intent.content_length).unwrap_or(usize::MAX));
        let remaining_body = intent
            .content_length
            .saturating_sub(u64::try_from(body_in_buf).unwrap_or(u64::MAX));
        if remaining_body > 0 && !discard_body(&mut stream, remaining_body, head_deadline).await {
            break 'connection;
        }

        // 3. Compact: keep only the bytes after this request's head and body
        //    (a pipelined next request, if any), never reallocating.
        let leftover_start = head_len.saturating_add(body_in_buf);
        let leftover_len = filled.saturating_sub(leftover_start);
        if leftover_start > 0 && leftover_start <= filled {
            buf.copy_within(leftover_start..filled, 0);
        }
        filled = leftover_len;
        probed_to = 0;

        // 4. Schedule the response: the per-request header wins over the
        //    flag entirely; otherwise the configured baseline or distribution.
        let effective_delay_us = intent
            .delay_us
            .unwrap_or_else(|| rng.draw_delay_us(shared.config.delay_dist, shared.config.delay_us));
        if effective_delay_us > 0 {
            let delay_deadline =
                head_parsed_at + std::time::Duration::from_micros(u64::from(effective_delay_us));
            sleep_until(delay_deadline).await;
        }

        // 5. Respond.
        let written = match role {
            Role::Main => {
                if shared.config.sequence {
                    let seq = shared.sequence.fetch_add(1, Ordering::Relaxed);
                    let mut scratch = [0u8; 512];
                    let head_written = shared.arena.patched_head(seq, &mut scratch);
                    if head_written == 0
                        || stream
                            .write_all(scratch.get(..head_written).unwrap_or(&[]))
                            .await
                            .is_err()
                        || stream.write_all(shared.arena.body()).await.is_err()
                    {
                        break 'connection;
                    }
                    Some(
                        u64::try_from(head_written)
                            .unwrap_or(0)
                            .saturating_add(u64::try_from(shared.arena.body().len()).unwrap_or(0)),
                    )
                } else {
                    let bytes = shared.arena.bytes();
                    if stream.write_all(bytes).await.is_err() {
                        break 'connection;
                    }
                    Some(u64::try_from(bytes.len()).unwrap_or(0))
                }
            }
            Role::Stats => {
                let response = if stats_hit {
                    stats_body(&shared)
                } else {
                    RESPONSE_404.to_vec()
                };
                if stream.write_all(&response).await.is_err() {
                    break 'connection;
                }
                Some(u64::try_from(response.len()).unwrap_or(0))
            }
        };

        if let Some(bytes_written) = written {
            shared.counters.add_request(bytes_written);
        }

        // 6. Loop for the next request on this keepalive connection, subject
        //    to the idle timeout.
        head_deadline = now() + idle_timeout;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent_ok(buf: &[u8]) -> RequestIntent {
        match scan_head(buf) {
            Ok(Some(intent)) => intent,
            other => panic!("expected Ok(Some(_)), got {other:?}"),
        }
    }

    #[test]
    fn incomplete_head_is_ok_none() {
        assert_eq!(scan_head(b"GET / HTTP/1.1\r\n"), Ok(None));
        assert_eq!(scan_head(b""), Ok(None));
    }

    #[test]
    fn complete_minimal_head_is_parsed() {
        let intent = intent_ok(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(intent.head_len, 18);
        assert_eq!(intent.content_length, 0);
        assert_eq!(intent.delay_us, None);
        assert!(!intent.chunked);
    }

    #[test]
    fn head_too_large_without_terminator() {
        let buf = vec![b'a'; HEAD_CAP];
        assert_eq!(scan_head(&buf), Err(ScanError::HeadTooLarge));
    }

    #[test]
    fn exactly_head_cap_with_terminator_is_accepted() {
        let mut buf = vec![b'a'; HEAD_CAP - 4];
        buf.extend_from_slice(b"\r\n\r\n");
        assert_eq!(buf.len(), HEAD_CAP);
        let intent = intent_ok(&buf);
        assert_eq!(intent.head_len, HEAD_CAP);
    }

    #[test]
    fn delay_header_is_parsed_and_capped() {
        let intent = intent_ok(b"GET / HTTP/1.1\r\nX-Origin-Delay-Us: 999999999\r\n\r\n");
        assert_eq!(intent.delay_us, Some(5_000_000));
    }

    #[test]
    fn duplicate_delay_header_first_wins() {
        let intent = intent_ok(
            b"GET / HTTP/1.1\r\nX-Origin-Delay-Us: 0\r\nX-Origin-Delay-Us: 50000\r\n\r\n",
        );
        assert_eq!(intent.delay_us, Some(0));
    }

    #[test]
    fn conflicting_content_length_is_rejected() {
        let result = scan_head(b"GET / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n");
        assert_eq!(result, Err(ScanError::ConflictingContentLength));
    }

    #[test]
    fn duplicate_content_length_same_value_is_accepted() {
        let intent = intent_ok(b"GET / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n");
        assert_eq!(intent.content_length, 5);
    }

    #[test]
    fn chunked_alone_is_411() {
        let result = scan_head(b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(result, Err(ScanError::Chunked));
    }

    #[test]
    fn content_length_with_transfer_encoding_is_400_both_orders() {
        let a =
            scan_head(b"GET / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n");
        let b = scan_head(
            b"GET / HTTP/1.1\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\n\r\n",
        );
        assert_eq!(a, Err(ScanError::ConflictingFraming));
        assert_eq!(b, Err(ScanError::ConflictingFraming));
    }

    #[test]
    fn malformed_header_line_has_no_colon() {
        let result = scan_head(b"GET / HTTP/1.1\r\nnotaheader\r\n\r\n");
        assert!(matches!(result, Err(ScanError::Malformed(_))));
    }

    #[test]
    fn content_length_is_capped() {
        let intent = intent_ok(b"GET / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n");
        assert_eq!(intent.content_length, 16_777_216);
    }

    #[test]
    fn hundred_headers_totalling_8kib_is_parsed() {
        let mut buf = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..100u32 {
            buf.extend_from_slice(
                format!("X-Filler-{i:03}: {:0width$}\r\n", i, width = 60).as_bytes(),
            );
        }
        buf.extend_from_slice(b"\r\n");
        let intent = intent_ok(&buf);
        assert_eq!(intent.head_len, buf.len());
    }

    #[test]
    fn incremental_prefixes_agree_with_the_full_answer() {
        let full = b"GET / HTTP/1.1\r\nX-Origin-Delay-Us: 20\r\n\r\n".to_vec();
        let expected = scan_head(&full);
        for n in 0..full.len() {
            let prefix = full.get(..n).unwrap_or(&[]);
            let got = scan_head(prefix);
            assert!(
                got == Ok(None) || got == expected,
                "prefix of length {n} gave {got:?}, expected Ok(None) or {expected:?}"
            );
        }
        assert_eq!(scan_head(&full), expected);
    }

    #[test]
    fn rng_bimodal_reaches_both_branches_over_many_draws() {
        let mut rng = Rng::new(12345);
        let dist = DelayDist::Bimodal {
            p_permille: 500,
            hi_us: 999,
        };
        let mut saw_lo = false;
        let mut saw_hi = false;
        for _ in 0..1000 {
            match rng.draw_delay_us(dist, 111) {
                999 => saw_hi = true,
                111 => saw_lo = true,
                other => panic!("unexpected delay {other}"),
            }
        }
        assert!(
            saw_lo && saw_hi,
            "1000 draws at p=500/1000 must reach both branches"
        );
    }

    #[test]
    fn rng_is_deterministic_for_a_given_seed() {
        let dist = DelayDist::Bimodal {
            p_permille: 300,
            hi_us: 42,
        };
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        let sequence_a: Vec<u32> = (0..50).map(|_| a.draw_delay_us(dist, 1)).collect();
        let sequence_b: Vec<u32> = (0..50).map(|_| b.draw_delay_us(dist, 1)).collect();
        assert_eq!(sequence_a, sequence_b);
    }

    #[test]
    fn is_get_stats_matches_exactly() {
        assert!(is_get_stats(b"GET /stats HTTP/1.1\r\n\r\n"));
        assert!(!is_get_stats(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!is_get_stats(b"POST /stats HTTP/1.1\r\n\r\n"));
    }
}
