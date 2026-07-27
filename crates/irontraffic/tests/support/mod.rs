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
/// A small, documented race: another process could take the port between this
/// function returning and the caller's own bind. Callers that bind a real listener on
/// the returned port retry on failure rather than treat the race as impossible.
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
/// `ProxyProcess::shutdown_capturing_stderr` does: the read blocks until the pipe
/// closes, normally at process exit, so running it concurrently with the bounded
/// wait means a child that never exits cannot block this function forever, and a
/// child whose stderr output fills the pipe buffer before it exits cannot deadlock
/// against a caller that only starts reading after the wait returns.
#[allow(
    dead_code,
    reason = "used by the control-mode tests, which are gated on the control-plane feature"
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

/// Polls a TCP connect to `addr` until it succeeds or `timeout` passes.
fn wait_for_connect(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(addr).is_ok() {
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
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill(); // it-allow: no-swallowed-error reason: best-effort safety net for a test that panicked before calling shutdown(); killing an already-exited process is expected to fail and changes nothing
        let _ = self.child.wait(); // it-allow: no-swallowed-error reason: reaps the process so it does not become a zombie; a failure here means it was already reaped
        let _ = std::fs::remove_dir_all(&self.cfg_dir); // it-allow: no-swallowed-error reason: best-effort test fixture cleanup; a leftover temp directory does not affect any assertion
    }
}

impl ProxyProcess {
    /// Sends SIGTERM and waits (up to ten seconds) for exit, returning the exit
    /// status.
    pub(crate) fn shutdown(self) -> ExitStatus {
        self.shutdown_capturing_stderr().0
    }

    /// Sends SIGTERM, waits (up to ten seconds) for exit, and returns the exit status
    /// together with everything the child wrote to stderr. Used by the tests that
    /// must inspect the shutdown log line rather than only the exit code.
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

        // Read stderr on its own thread: the read blocks until the pipe closes
        // (normally at process exit), and running it concurrently with the bounded
        // wait below means a hanging child cannot block this function forever.
        let mut pipe = self.child.stderr.take();
        let reader = std::thread::spawn(move || {
            let mut buf = String::new();
            if let Some(p) = pipe.as_mut() {
                let _ = p.read_to_string(&mut buf); // it-allow: no-swallowed-error reason: a pipe read failure leaves buf short, which the caller's own assertion on its content then fails on
            }
            buf
        });

        let status = wait_for_exit(&mut self.child, Duration::from_secs(10));
        let stderr_text = reader.join().unwrap_or_default();
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

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if wait_for_connect(addr, Duration::from_secs(5)) {
            return ProxyProcess {
                child,
                addr,
                cfg_dir: dir,
            };
        }

        let _ = child.kill(); // it-allow: no-swallowed-error reason: the attempt is being abandoned regardless; a failed kill means it already exited
        let mut stderr_text = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut stderr_text); // it-allow: no-swallowed-error reason: best-effort diagnostic capture for the panic message below; a failed read just leaves it empty
        }
        let _ = child.wait(); // it-allow: no-swallowed-error reason: reaps the abandoned attempt so it does not become a zombie
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
    reason = "used by the control-mode tests, which are gated on the control-plane feature"
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
/// [`spawn_proxy`].
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
    let child = Command::new("sh")
        .arg("-c")
        .arg(&shell_cmd)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn_proxy_under_nofile_limit: spawn the ulimit-wrapped proxy");

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    assert!(
        wait_for_connect(addr, Duration::from_secs(5)),
        "the ulimit-wrapped proxy did not start listening within 5s"
    );
    Some(ProxyProcess {
        child,
        addr,
        cfg_dir: dir,
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
