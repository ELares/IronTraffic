// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared support for the end-to-end smoke tests: a minimal HTTP/1.1 origin server
//! and a helper that spawns the real `irontraffic` binary as a child process.
//!
//! `pub(crate)` throughout rather than `pub`: this module is pulled into the `smoke`
//! integration test binary through `mod support;`, which has no external consumer
//! (an integration test binary is exactly as unreachable from outside as the crate's
//! own binary target is), so a wider visibility trips `clippy::unreachable_pub`.

use std::io::Read as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The byte sequence that ends an HTTP head.
const END_OF_HEADERS: &[u8] = b"\r\n\r\n";

/// The most a single request head may be before the origin gives up looking for the
/// end of it.
const MAX_HEAD_BYTES: usize = 8192;

/// A minimal HTTP/1.1 origin: answers every request with a fixed body and
/// `Connection: close`, and counts how many it has served.
///
/// Deliberately not a dependency: it reads until the end-of-headers marker or
/// `MAX_HEAD_BYTES`, and writes a fixed response. A complicated origin would turn a
/// proxy test failure into an origin test failure.
pub(crate) struct Origin {
    /// The address it is listening on.
    pub(crate) addr: SocketAddr,
    /// The accept-loop task. Aborted by `stop`, which drops the listener with it.
    handle: tokio::task::JoinHandle<()>,
    /// Requests served so far.
    hits: Arc<AtomicU64>,
    /// The exact bytes of the most recently completed request's head.
    #[allow(dead_code, reason = "read by smoke.rs; not every test binary uses it")]
    last_request: Arc<Mutex<Vec<u8>>>,
}

impl Origin {
    /// Binds `127.0.0.1:0` and answers every request with `body`.
    ///
    /// Runs one always-live accept loop that spawns a detached task per accepted
    /// connection, so a client that never sends anything (an idle connection) never
    /// blocks the origin from accepting the next one.
    #[allow(
        clippy::expect_used,
        reason = "test-support setup, not itself a #[test] fn, so clippy's test exemption for \
                  expect_used does not extend to it (mirrors write_fixture's own precedent in \
                  tests/validate_cli.rs); binding a loopback port on 127.0.0.1:0 does not fail on \
                  a working test host, and there is nothing a caller could usefully do with a \
                  propagated error here beyond failing the same test"
    )]
    pub(crate) async fn start(body: &'static str) -> Origin {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin: bind a scratch listener");
        let addr = listener
            .local_addr()
            .expect("origin: read the bound address");
        let hits = Arc::new(AtomicU64::new(0));
        let last_request = Arc::new(Mutex::new(Vec::new()));

        let hits_for_task = Arc::clone(&hits);
        let last_request_for_task = Arc::clone(&last_request);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    // The listener was dropped (Origin::stop) or a transient accept
                    // error occurred; either way this accept loop is done.
                    return;
                };
                let hits = Arc::clone(&hits_for_task);
                let last_request = Arc::clone(&last_request_for_task);
                tokio::spawn(async move {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0_u8; 512];
                    loop {
                        if buf.len() >= MAX_HEAD_BYTES || contains(&buf, END_OF_HEADERS) {
                            break;
                        }
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => match chunk.get(..n) {
                                Some(slice) => buf.extend_from_slice(slice),
                                // `Read::read` never reports more bytes filled than the buffer
                                // it was given, so this is unreachable in practice; treat it as
                                // an anomalous read and stop rather than index out of bounds.
                                None => break,
                            },
                        }
                    }
                    if buf.is_empty() {
                        // No real request ever arrived: the proxy's connection handler dials
                        // upstream immediately on accept, before it has read a single byte from
                        // the downstream, so a bare connect-then-close probe (a readiness check
                        // in spawn_proxy_with_mode, or a test holding a connection open without
                        // sending anything) reaches this origin as an accepted connection with
                        // nothing to read. Counting it as a hit or answering it would inflate
                        // every test's hit count by however many such probes happened to land
                        // here, which is exactly the kind of off-by-one this comment exists to
                        // prevent silently reappearing.
                        return;
                    }
                    *last_request
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = buf;
                    hits.fetch_add(1, Ordering::Relaxed);

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await; // it-allow: no-swallowed-error reason: a write failure here just means the client sees a short or absent response, which the test's own assertion on the client side already catches
                    let _ = stream.shutdown().await; // it-allow: no-swallowed-error reason: the socket is closing either way; a failed shutdown changes nothing the test observes
                });
            }
        });

        Origin {
            addr,
            handle,
            hits,
            last_request,
        }
    }

    /// Requests served so far.
    pub(crate) fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// The exact bytes of the most recently completed request's head.
    #[allow(dead_code, reason = "read by smoke.rs; not every test binary uses it")]
    pub(crate) fn last_request(&self) -> Vec<u8> {
        self.last_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Stops the origin and waits for its accept loop to actually end.
    pub(crate) async fn stop(self) {
        self.handle.abort();
        let _ = self.handle.await; // it-allow: no-swallowed-error reason: the awaited result is always Err(Cancelled) after abort(); the point of awaiting is only to confirm the task has actually ended before returning
    }
}

/// True when `needle` occurs anywhere in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Binds a scratch listener on `127.0.0.1:0`, reads the port the kernel assigned, and
/// drops the listener so the port is free again.
///
/// **This function does not reserve its port.** The moment it returns, the port is
/// unbound again and anything else in the process (or on the machine) can take it,
/// including a just-freed ephemeral port being re-issued by `bind(0)` itself: on
/// Linux, measured on a 6.8 kernel with the default `32768 60999` ephemeral range,
/// 3000 sequential bind/close calls produced 264 repeated ports, the closest repeat
/// only 4 calls apart. That makes this function correct ONLY for a port a caller (or
/// a child process it is about to spawn) binds a real listener on immediately, and
/// wrong for a port that must stay unbound for anything longer than that, such as a
/// deliberately dead upstream held for a whole test body: use [`dead_local_port`] for
/// that instead. Of the two callers that bind a real listener on the returned port,
/// only `spawn_proxy_with_mode` retries with a freshly drawn port on failure rather
/// than treat this race as impossible; `spawn_proxy_under_nofile_limit` makes a single
/// attempt (see its own doc comment). The four `dataplane_build.rs` call sites never
/// bind the returned port at all (it is always the config's upstream address there,
/// see that file's own doc comments), so they do not need to retry either.
#[allow(
    clippy::expect_used,
    reason = "test-support setup, not itself a #[test] fn (see Origin::start's identical \
              reasoning); binding a loopback port on 127.0.0.1:0 does not fail on a working \
              test host"
)]
pub(crate) fn free_local_port() -> u16 {
    let scratch =
        std::net::TcpListener::bind("127.0.0.1:0").expect("free_local_port: bind a scratch port");
    scratch
        .local_addr()
        .expect("free_local_port: read the scratch port")
        .port()
}

/// A port that nothing will ever answer on, held for the returned guard's lifetime.
///
/// `free_local_port` deliberately releases its port, which is correct for a port a
/// child process is about to bind, and wrong for a port that must STAY dead: on Linux
/// `bind(0)` re-issues a just-freed ephemeral port (measured: repeats 4 calls apart),
/// so a released dead-upstream port can be handed to a concurrent test's proxy as its
/// listen port, and this test's proxy then dials that proxy. Holding the port bound
/// but never listened keeps it genuinely dead, on every platform this workspace
/// targets, though the exact `connect(2)` outcome is platform-dependent: on Linux the
/// kernel resets an inbound `SYN` against a bound-but-not-listening socket, giving an
/// immediate `ECONNREFUSED`; on a BSD-derived stack (macOS, confirmed empirically)
/// there is no listen queue to reset against, so the `SYN` is silently dropped and a
/// caller only sees a bounded timeout. Either way the port never accepts a
/// connection, and it is unavailable to any other bind in the process, for as long as
/// the returned guard is alive.
#[allow(
    dead_code,
    reason = "constructed only by smoke.rs's dead-upstream tests; dataplane_build.rs's own copy \
              of this shared support module never calls dead_local_port, so that test binary \
              alone would otherwise warn this type is never constructed"
)]
pub(crate) struct DeadPort {
    /// The bound-but-never-listened socket, kept alive only to hold the port. Never
    /// read from or written to; `std::net::TcpListener` is just the RAII type that
    /// owns the underlying file descriptor and closes it on drop. Converting a
    /// `socket2::Socket` into this type is a pure type change, not a syscall. In
    /// particular it does not call `listen(2)`: only `TcpListener::bind` does that,
    /// and this value is never built through `bind`.
    _held: std::net::TcpListener,
    /// The port `_held` is bound to.
    pub(crate) port: u16,
}

/// Binds `127.0.0.1:0` without listening and returns a [`DeadPort`] holding it.
///
/// See [`DeadPort`]'s doc comment for why this exists instead of [`free_local_port`].
#[allow(
    dead_code,
    reason = "called only by smoke.rs's dead-upstream tests; not every test binary that pulls \
              in this shared support module uses it (see DeadPort's identical reasoning)"
)]
#[allow(
    clippy::expect_used,
    reason = "test-support setup, not itself a #[test] fn (see Origin::start's identical \
              reasoning); binding a loopback port on 127.0.0.1:0 does not fail on a working \
              test host"
)]
pub(crate) fn dead_local_port() -> DeadPort {
    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
        .expect("dead_local_port: create a scratch socket");
    let addr: SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("dead_local_port: parse the scratch address");
    sock.bind(&addr.into())
        .expect("dead_local_port: bind a scratch port without listening");
    let port = sock
        .local_addr()
        .expect("dead_local_port: read the scratch socket's address")
        .as_socket()
        .expect("dead_local_port: scratch address has no socket representation")
        .port();
    DeadPort {
        _held: sock.into(),
        port,
    }
}

/// Polls `child` with [`std::process::Child::try_wait`] until it exits or `timeout`
/// passes. On timeout, kills it and returns whatever status that produced, so a
/// caller's own assertion on the exit code fails with a clear diff rather than this
/// helper hanging the whole test run indefinitely.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn (see Origin::start's identical \
              reasoning); polling and waiting on a std::process::Child this function itself \
              spawned and still owns does not fail on a working test host"
)]
pub(crate) fn wait_for_exit(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .expect("wait_for_exit: poll the child process")
        {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill(); // it-allow: no-swallowed-error reason: the child is already past its deadline; a failed kill (it already exited between the last poll and here) changes nothing the following wait does not already resolve
            return child
                .wait()
                .expect("wait_for_exit: wait on a killed child process");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Like [`wait_for_exit`], but also returns everything the child wrote to stderr
/// while waiting.
///
/// Reads stderr on its own thread, concurrently with the wait, for the same reason
/// [`StderrTap`]'s reader thread does (see that struct's own doc comment): the read
/// blocks until the pipe closes, normally at process exit, so running it concurrently
/// with the bounded wait means a child that never exits cannot block this function
/// forever, and a child whose stderr output fills the pipe buffer before it exits
/// cannot deadlock against a caller that only starts reading after the wait returns.
/// This function does not itself build a `StderrTap`: it operates on a bare `Child`
/// from [`spawn_binary`], which (unlike a `ProxyProcess`) is never first handed to a
/// readiness check that would need to read the same pipe before this function does.
#[allow(
    dead_code,
    reason = "used by the control-mode tests, which are gated on the control-plane feature; also \
              by two_children_on_one_port_collide_loudly's second (expected-to-fail) child, which \
              is not"
)]
pub(crate) fn wait_for_exit_capturing_stderr(
    child: &mut Child,
    timeout: Duration,
) -> (ExitStatus, String) {
    let mut pipe = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(p) = pipe.as_mut() {
            let _ = p.read_to_string(&mut buf); // it-allow: no-swallowed-error reason: a pipe read failure leaves buf short, which the caller's own assertion on its content then fails on
        }
        buf
    });
    let status = wait_for_exit(child, timeout);
    // A poisoned reader thread leaves this empty, exactly like
    // `ProxyProcess::shutdown_capturing_stderr`'s identical join; the caller's own
    // assertion on the returned text fails on that, rather than this function
    // panicking on a panic that already happened on another thread.
    let stderr_text = reader.join().unwrap_or_default();
    (status, stderr_text)
}

/// Continuously drains a byte stream into a shared, growable buffer, so more than one
/// piece of code can inspect what has arrived so far without racing each other for the
/// single read of a pipe.
///
/// [`wait_for_connect`] polls a live snapshot of a spawned child's stderr while the
/// child is still starting, looking for the `"listener bound"` line only a child that
/// actually bound its listener can have produced; [`ProxyProcess::shutdown_capturing_
/// stderr`] later reads the SAME accumulated bytes, complete by then, once the child
/// has exited. Generic over [`std::io::Read`] rather than tied to
/// `std::process::ChildStderr`: `wait_for_connect_rejects_a_foreign_listener` (in
/// `smoke.rs`) constructs one over a plain in-memory byte source to stand in for a
/// listener that produced no such line, without spawning a real child process to prove
/// it.
///
/// The reader thread's own lifetime needs no timeout of its own: it returns the moment
/// a read reports EOF (`Ok(0)`) or an error, which for a real child's pipe happens
/// exactly once, when the child exits or closes its stderr.
pub(crate) struct StderrTap {
    /// Everything read so far.
    buf: Arc<Mutex<Vec<u8>>>,
    /// The thread doing the reading. Not joined by [`Self::snapshot`], only by
    /// [`Self::finish`].
    reader: std::thread::JoinHandle<()>,
}

impl StderrTap {
    /// Spawns the draining thread over `pipe`.
    pub(crate) fn spawn<R: std::io::Read + Send + 'static>(mut pipe: R) -> Self {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let buf_for_reader = Arc::clone(&buf);
        let reader = std::thread::spawn(move || {
            let mut chunk = [0_u8; 4096];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => match chunk.get(..n) {
                        Some(slice) => buf_for_reader
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .extend_from_slice(slice),
                        // `Read::read` never reports more bytes filled than the buffer
                        // it was given, so this is unreachable in practice; treat it
                        // as an anomalous read and stop rather than index out of
                        // bounds, mirroring Origin::start's identical handling of the
                        // same situation.
                        None => return,
                    },
                }
            }
        });
        StderrTap { buf, reader }
    }

    /// Everything read so far, lossily decoded: a snapshot taken mid-write could in
    /// principle land on a split multi-byte UTF-8 sequence, and `tracing_subscriber`'s
    /// output is always UTF-8 in practice, so degrading that one boundary byte to
    /// U+FFFD is preferable to panicking or discarding the rest of the buffer.
    pub(crate) fn snapshot(&self) -> String {
        String::from_utf8_lossy(
            &self
                .buf
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned()
    }

    /// Waits for the source to close (EOF) and returns everything read, consuming the
    /// tap. The join is unbounded on its own, but every caller already waited for the
    /// child's exit (which is what closes the pipe the reader thread is blocked
    /// reading) before calling this, so in practice it returns immediately.
    pub(crate) fn finish(self) -> String {
        // Cloned before the join below, not read through `self.snapshot()` after it:
        // `JoinHandle::join` takes `self.reader` by value, and Rust will not let a
        // later call borrow `self` as a whole (which a `self.snapshot()` method call
        // would) once one of its fields has been partially moved out, even though
        // `snapshot` only ever touches the OTHER field, `buf`.
        let buf = Arc::clone(&self.buf);
        let _ = self.reader.join(); // it-allow: no-swallowed-error reason: the reader thread's own body never unwraps, expects, or panics, so a join Err (a panic) here is unreachable in practice; the buffer read below returns whatever was read regardless of how the join result reads
        String::from_utf8_lossy(
            &buf.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned()
    }
}

/// Polls a TCP connect to `addr` until it succeeds AND the child whose stderr `tap`
/// drains has itself logged binding that listener, or `timeout` passes.
///
/// A bare connect success is not enough on its own to prove `addr` is served by the
/// specific child `tap` belongs to. Every caller of this function reaches `addr`
/// through [`free_local_port`], which releases the port the instant it returns (see
/// that function's own doc comment: 264 of 3000 sequential bind/close pairs repeated a
/// port on a measured Linux host, the closest repeat 4 calls apart), so a concurrent
/// test's own listener can occupy the exact same address in the window between drawing
/// the port and this function's own child actually binding it. A plain connect-only
/// probe would then report "ready" against that unrelated listener; issue #894
/// measured the resulting flake directly: `ConnectionRefused` on a later, genuine
/// connect, once the OTHER test's listener had since gone away, even though this
/// function had already reported success for it.
///
/// The fix does not need to identify WHICH process owns the responding socket, only
/// whether THIS function's own child does. `irontraffic_conn::listener::
/// ShardedListener::bind` logs the literal line `"listener bound"` to stderr on
/// success, and nothing else in this workspace emits that exact phrase. `tap` is built
/// once per spawned child and never shared across children (see [`StderrTap`]'s own
/// doc comment), so a snapshot of it containing that phrase can only mean THIS
/// function's own child produced it. Checked as a plain substring on the raw,
/// un-stripped snapshot: `smoke.rs`'s `strip_ansi` exists because
/// `tracing_subscriber`'s ANSI colouring splits a `key=value` field across several
/// escape-delimited spans, not because it splits the literal message text itself, and
/// `shutdown_capturing_stderr`'s own established `"shutdown complete"` /
/// `"connection cap"` checks elsewhere in this file already rely on exactly that
/// (matching directly against raw, un-stripped stderr).
///
/// On a child that dies between binding and its first response, or that never binds at
/// all, this loop simply never observes both conditions and returns `false` once
/// `timeout` elapses: nothing here can hang past that bound.
pub(crate) fn wait_for_connect(addr: SocketAddr, tap: &StderrTap, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(addr).is_ok() && tap.snapshot().contains("listener bound") {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Unique fixture directory names across concurrently running tests.
static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A running `irontraffic` child process.
pub(crate) struct ProxyProcess {
    /// The child process.
    pub(crate) child: Child,
    /// The listener address the generated configuration resolved to.
    pub(crate) addr: SocketAddr,
    /// The fixture directory holding the generated configuration file, removed when
    /// this value is dropped.
    cfg_dir: PathBuf,
    /// Everything the child has written to stderr since [`spawn_proxy_with_mode`]
    /// spawned it, including whatever [`wait_for_connect`]'s readiness check already
    /// read: `child.stderr` is taken exactly once, into this tap, at spawn time, so no
    /// later reader (this struct's own `shutdown_capturing_stderr`) can take it a
    /// second time and find it already gone. See [`StderrTap`]'s own doc comment.
    ///
    /// `Option`, not a bare `StderrTap`, because `ProxyProcess` implements `Drop`:
    /// `shutdown_capturing_stderr` consumes `self` and needs to move this field's
    /// value out to call `StderrTap::finish` (which itself consumes `self`), and Rust
    /// does not allow moving a field out of a type that implements `Drop`, only
    /// taking it through `Option::take`. Always `Some` from construction until
    /// `shutdown_capturing_stderr` takes it; nothing else in this file ever sees it as
    /// `None`.
    stderr: Option<StderrTap>,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill(); // it-allow: no-swallowed-error reason: best-effort safety net for a test that panicked before calling shutdown(); killing an already-exited process is expected to fail and changes nothing
        let _ = self.child.wait(); // it-allow: no-swallowed-error reason: reaps the process so it does not become a zombie; a failure here means it was already reaped
        let _ = std::fs::remove_dir_all(&self.cfg_dir); // it-allow: no-swallowed-error reason: best-effort test fixture cleanup; a leftover temp directory does not affect any assertion
        // `self.stderr`'s reader thread is intentionally not joined here: `self.child`
        // has just been killed and waited on above, which is what closes the pipe it
        // is blocked reading, so it is seconds (in practice, microseconds) from
        // returning on its own; this path only runs when a test panicked or otherwise
        // never called shutdown(), so nothing is waiting on its final content the way
        // shutdown_capturing_stderr's caller is.
    }
}

impl ProxyProcess {
    /// Sends SIGTERM and waits (up to ten seconds) for exit, returning the exit
    /// status.
    pub(crate) fn shutdown(self) -> ExitStatus {
        self.shutdown_capturing_stderr().0
    }

    /// Sends SIGTERM, waits (up to ten seconds) for exit, and returns the exit status
    /// together with everything the child wrote to stderr, from the moment
    /// `spawn_proxy_with_mode` spawned it. Used by the tests that must inspect the
    /// shutdown log line rather than only the exit code.
    pub(crate) fn shutdown_capturing_stderr(mut self) -> (ExitStatus, String) {
        let pid = self.child.id();
        // `Child::kill()` only sends SIGKILL; SIGTERM (the graceful-drain trigger) has
        // no safe standard-library API, and this workspace denies `unsafe`
        // everywhere, so the signal is sent through the `kill` command rather than a
        // raw `libc::kill` FFI call.
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status(); // it-allow: no-swallowed-error reason: a failed signal send means the process will not drain in time, which the bounded wait below turns into a failed exit-status assertion rather than a silent hang

        let status = wait_for_exit(&mut self.child, Duration::from_secs(10));
        // `self.stderr` has been draining continuously since spawn time, not merely
        // since this wait started (unlike the read this replaced, which only began
        // once shutdown was called and could in principle have let the child's stderr
        // pipe fill up and block it before then). `finish` joins the reader thread,
        // which the wait above already made bounded: the child has exited, which is
        // what closes the pipe the thread is blocked reading. `.take()`, not a move
        // of `self.stderr` directly: see the field's own doc comment for why.
        let stderr_text = self
            .stderr
            .take()
            .map(StderrTap::finish)
            .unwrap_or_default();
        (status, stderr_text)
    }
}

/// The mode `spawn_proxy` starts: `run` in a full build, `proxy` in a data-plane-only
/// build. The two behave identically in M1 except that `run` also builds the
/// control-plane runtime, so every existing smoke test asserts the same thing in both.
pub(crate) const DEFAULT_SPAWN_MODE: &str = if cfg!(feature = "control-plane") {
    "run"
} else {
    "proxy"
};

/// Starts the binary in [`DEFAULT_SPAWN_MODE`] with a generated config and waits
/// until the listener answers a TCP connect, up to 5 seconds.
///
/// `cfg_yaml` must contain the literal bind placeholder `127.0.0.1:0`, which this
/// function replaces with a port it discovered is free before the child ever runs.
pub(crate) fn spawn_proxy(cfg_yaml: &str) -> ProxyProcess {
    spawn_proxy_with_mode(cfg_yaml, DEFAULT_SPAWN_MODE)
}

/// Same as [`spawn_proxy`], for an arbitrary mode (`run`, `proxy`, or `control`).
///
/// `control` never binds anything, so [`wait_for_connect`] would always fail; do not
/// call this with `"control"`. Use [`spawn_binary`] instead.
#[allow(
    clippy::panic,
    reason = "edge case 15: a startup failure here is reported as a failed test, with the \
              child's stderr included in the message, because a startup failure with no stderr \
              is undiagnosable; this is the designed failure mode after 3 retries, not a \
              production code path"
)]
#[allow(
    clippy::expect_used,
    reason = "test-support setup, not itself a #[test] fn (see Origin::start's identical \
              reasoning); a child spawned two lines above with .stderr(Stdio::piped()) always \
              has Some(ChildStderr) to take, exactly once, right here"
)]
pub(crate) fn spawn_proxy_with_mode(cfg_yaml: &str, mode: &str) -> ProxyProcess {
    let mut last_failure = String::new();
    for _ in 0..3 {
        let port = free_local_port();
        let cfg = cfg_yaml.replace("127.0.0.1:0", &format!("127.0.0.1:{port}"));
        let (cfg_path, dir) = write_fixture(&cfg);

        let mut child = match Command::new(env!("CARGO_BIN_EXE_irontraffic"))
            .arg(mode)
            .arg("--config")
            .arg(&cfg_path)
            .env_remove("IRONTRAFFIC_LOG")
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                last_failure = format!("failed to spawn the proxy: {e}");
                let _ = std::fs::remove_dir_all(&dir); // it-allow: no-swallowed-error reason: best-effort test fixture cleanup on a retried attempt; a leftover temp directory does not affect any assertion
                continue;
            }
        };

        // Taken exactly once, here: everything the child writes to stderr from this
        // point to its exit flows through this one tap, which both the readiness
        // check below and (on success) ProxyProcess::shutdown_capturing_stderr read
        // from, rather than each racing to take child.stderr for themselves. See
        // StderrTap's own doc comment.
        let tap = StderrTap::spawn(
            child
                .stderr
                .take()
                .expect("spawn_proxy_with_mode: child.stderr was piped"),
        );

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if wait_for_connect(addr, &tap, Duration::from_secs(5)) {
            return ProxyProcess {
                child,
                addr,
                cfg_dir: dir,
                stderr: Some(tap),
            };
        }

        let _ = child.kill(); // it-allow: no-swallowed-error reason: the attempt is being abandoned regardless; a failed kill means it already exited
        let _ = child.wait(); // it-allow: no-swallowed-error reason: reaps the abandoned attempt so it does not become a zombie
        let stderr_text = tap.finish();
        last_failure =
            format!("the proxy did not start listening within 5s; stderr: {stderr_text}");
        let _ = std::fs::remove_dir_all(&dir); // it-allow: no-swallowed-error reason: best-effort test fixture cleanup on a retried attempt; a leftover temp directory does not affect any assertion
    }
    panic!("spawn_proxy_with_mode: failed after 3 attempts: {last_failure}");
}

/// Starts the binary in `mode` with a generated config and returns the child
/// immediately, without waiting for a listener: for `control`, which binds nothing.
#[allow(
    clippy::expect_used,
    reason = "test-support setup, not itself a #[test] fn (see Origin::start's identical \
              reasoning); spawning the just-built binary from CARGO_BIN_EXE_irontraffic does \
              not fail on a working test host"
)]
#[allow(
    dead_code,
    reason = "used by the control-mode tests, which are gated on the control-plane feature; also \
              by two_children_on_one_port_collide_loudly, which is not"
)]
pub(crate) fn spawn_binary(cfg_yaml: &str, mode: &str) -> (Child, PathBuf) {
    let (cfg_path, dir) = write_fixture(cfg_yaml);
    let child = Command::new(env!("CARGO_BIN_EXE_irontraffic"))
        .arg(mode)
        .arg("--config")
        .arg(&cfg_path)
        .env_remove("IRONTRAFFIC_LOG")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn_binary: spawn the proxy");
    (child, dir)
}

/// Starts the binary in `run` mode wrapped in a shell that lowers `RLIMIT_NOFILE` to
/// `nofile` first via `ulimit -n`, and waits until the listener answers a TCP
/// connect, up to 5 seconds.
///
/// Returns `None` when `sh` or `ulimit` is unavailable, so the caller can skip rather
/// than fail; any OTHER startup failure (the shell and `ulimit` both work, but the
/// wrapped binary still does not start listening in time) is a real defect and
/// panics rather than being folded into the same `None`.
///
/// `cfg_yaml` must contain the literal bind placeholder `127.0.0.1:0`, exactly like
/// [`spawn_proxy`]. UNLIKE `spawn_proxy_with_mode`, this makes a single attempt: it
/// does not retry `free_local_port`'s unreserved-port race (issue #888), so a
/// concurrent bind winning that race here fails this function outright rather than
/// drawing a fresh port and trying again.
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "used only by the Linux-only descriptor-budget test"
)]
#[allow(
    clippy::expect_used,
    reason = "test-support setup, not itself a #[test] fn (see Origin::start's identical \
              reasoning); the shell/ulimit availability check above already ruled out the one \
              expected failure mode, so spawning here does not fail on a working test host"
)]
pub(crate) fn spawn_proxy_under_nofile_limit(cfg_yaml: &str, nofile: u32) -> Option<ProxyProcess> {
    let ulimit_works = Command::new("sh")
        .arg("-c")
        .arg("ulimit -n")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ulimit_works {
        return None;
    }

    let port = free_local_port();
    let cfg = cfg_yaml.replace("127.0.0.1:0", &format!("127.0.0.1:{port}"));
    let (cfg_path, dir) = write_fixture(&cfg);
    let shell_cmd = format!(
        "ulimit -n {nofile}; exec {} {DEFAULT_SPAWN_MODE} --config {}",
        env!("CARGO_BIN_EXE_irontraffic"),
        cfg_path.display()
    );
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&shell_cmd)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn_proxy_under_nofile_limit: spawn the ulimit-wrapped proxy");

    // See spawn_proxy_with_mode's identical comment: taken exactly once, here.
    let tap = StderrTap::spawn(
        child
            .stderr
            .take()
            .expect("spawn_proxy_under_nofile_limit: child.stderr was piped"),
    );

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(
        wait_for_connect(addr, &tap, Duration::from_secs(5)),
        "the ulimit-wrapped proxy did not start listening within 5s"
    );
    Some(ProxyProcess {
        child,
        addr,
        cfg_dir: dir,
        stderr: Some(tap),
    })
}

/// Writes `contents` to a freshly created fixture directory and returns the file's
/// path together with the directory, so a caller can remove the directory when done.
#[allow(
    clippy::expect_used,
    reason = "test-support setup, not itself a #[test] fn (see Origin::start's identical \
              reasoning); creating a directory and a file under std::env::temp_dir() does not \
              fail on a working test host"
)]
fn write_fixture(contents: &str) -> (PathBuf, PathBuf) {
    let pid = std::process::id();
    let counter = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("irontraffic-smoke-{pid}-{counter}"));
    std::fs::create_dir_all(&dir).expect("write_fixture: create the fixture directory");
    let path = dir.join("cfg.yaml");
    std::fs::write(&path, contents).expect("write_fixture: write the fixture config");
    (path, dir)
}
