// SPDX-License-Identifier: MIT OR Apache-2.0
//! Process supervision: spawning a child pinned to a disjoint core set,
//! waiting for readiness without a fixed sleep, sampling its CPU and memory,
//! and tearing it down.
//!
//! # Readiness, not a fixed sleep
//!
//! A child that fails to start is distinguished from a child that started
//! and exited: [`Child::wait_ready`] polls a real TCP connect to the child's
//! listen address rather than sleeping a fixed duration, which is either too
//! short on a loaded machine or wasted time on an idle one.
//!
//! # Teardown reaches the whole process group
//!
//! Every child is spawned into its own process group
//! (`std::os::unix::process::CommandExt::process_group(0)`), and
//! [`Child::stop`] signals that whole group, SIGTERM then SIGKILL after five
//! seconds, then reaps. Signalling only the direct child is not enough: a
//! container-based adapter's direct child is a `docker run` CLI process, and
//! killing the CLI does not stop the container. This module cannot close
//! that second half on its own; see [`Child::stop`]'s own doc.
//!
//! # Captured output never reaches a terminal unsanitised
//!
//! Child stdout and stderr are captured into bounded, in-memory, oldest-
//! dropped buffers (1 MiB each), never streamed to disk during the
//! measurement window. A readiness failure writes the full captured bytes to
//! a file and quotes only a short, [`crate::error::Detail`]-sanitised excerpt
//! in the returned error, because the child chose every byte it wrote and a
//! `\x1b[` sequence or an embedded newline in it must never reach a terminal
//! or forge a surrounding log line.
//!
//! # Pinning
//!
//! [`Child::spawn`] pins with `taskset -c <cpuset> <program> <args...>` when
//! `cores` is non-empty. `taskset` is Linux-only and is not installed on this
//! crate's own macOS development host; a spawn failure whose `ErrorKind` is
//! `NotFound` falls back to spawning `<program> <args...>` unpinned rather
//! than failing the repetition, matching edge case 11 ("`taskset`
//! unavailable: pinning is skipped, `pinned` is recorded false, and
//! provenance is already unpublishable").
//!
//! # CPU accounting is Linux-only
//!
//! [`Child::cpu_seconds`] reads `/proc/<pid>/stat` and [`Child::memory`]
//! reads `/proc/<pid>/status` and `/proc/<pid>/smaps_rollup`. Off Linux,
//! `cpu_seconds` returns `Err` (its own doc states this) and `memory` returns
//! `(0, 0)` (its own doc states this too): the two functions disagree on
//! purpose, matching their Public API doc comments exactly. [`Provenance`]
//! already marks a non-Linux run unpublishable, so this module's job is only
//! to report honestly, not to make the run pass.

use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::error::{BenchError, Detail};
use crate::loadgen::Invocation;
#[cfg(target_os = "linux")]
use crate::provenance::{SMALL_FILE_CAP, read_bounded};

/// Largest stdout or stderr capture this module retains per child, in bytes.
/// The oldest bytes are dropped once a stream's buffer would exceed this;
/// see [`append_capped`].
pub const MAX_CAPTURED_BYTES: usize = 1024 * 1024;

/// How long [`Child::stop`] waits after SIGTERM before escalating to
/// SIGKILL.
pub const TEARDOWN_GRACE: Duration = Duration::from_secs(5);

/// How long [`Child::stop`] waits for a capture reader thread to see EOF and
/// exit, after the process itself has been signalled and reaped.
///
/// A descendant that escapes the process-group signal (this module's own
/// documented gap: see [`Child::stop`]'s own doc on the container-CLI case)
/// keeps its end of the captured pipe open, and `read` on that pipe blocks
/// forever once nothing else is writing to it. Without this bound, `stop`
/// (and therefore `Drop`, and therefore every one of `run_repetition`'s
/// eleven early returns) would wedge the whole harness with no timeout and
/// no diagnostic: this was observed directly during review, with a
/// surviving grandchild parking the calling thread in `pthread_join` for the
/// full length of a 300 second test run. `CapturedReader::join` polls
/// `JoinHandle::is_finished` against this bound rather than calling the
/// blocking `join` directly, because `std::thread::JoinHandle` has no
/// timeout-bearing join in `std`.
const READER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval for [`CapturedReader::join`]'s bounded wait.
const READER_JOIN_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Poll interval for [`Child::wait_ready`]'s TCP connect retry.
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Poll interval for [`Child::stop`]'s SIGTERM grace-period wait.
const TEARDOWN_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Raw bytes fed into [`Detail::new`] for a readiness-failure excerpt, kept
/// well under [`crate::error::MAX_DETAIL_BYTES`] so the surrounding template
/// text and the capture file's own path both still fit inside the outer 256
/// byte clip `BenchError::Io`'s `Display` impl re-applies to the whole
/// message at render time.
const READINESS_EXCERPT_RAW_BYTES: usize = 128;

/// `/proc/<pid>/stat`'s clock-tick unit, assumed rather than read via
/// `sysconf(_SC_CLK_TCK)`: this is 100 on every Linux target this workspace
/// ships or tests on (`x86_64` and `aarch64`), and reading the real value would
/// need a `libc`/`sysconf` call this crate's manifest does not authorise.
/// A wrong assumption here would scale every `cpu_seconds` figure by a fixed
/// constant factor, not corrupt it in a way that could pass a validity check
/// silently; re-verify against a real kernel before trusting this to more
/// than one significant figure on an exotic target.
#[cfg(target_os = "linux")]
const CLOCK_TICKS_PER_SEC: u64 = 100;

/// Appends `chunk` to `buf`, dropping the OLDEST bytes first whenever the
/// result would exceed `cap`. Used for a child's captured stdout and stderr,
/// which must retain the MOST RECENT output (the tail is what a readiness or
/// teardown failure needs), not the first bytes written.
fn append_capped(buf: &mut Vec<u8>, chunk: &[u8], cap: usize) {
    if chunk.len() >= cap {
        buf.clear();
        let start = chunk.len() - cap; // chunk.len() >= cap, checked just above
        buf.extend_from_slice(chunk.get(start..).unwrap_or(&[]));
        return;
    }
    let total = buf.len().saturating_add(chunk.len());
    if total > cap {
        let excess = total - cap; // total > cap, checked just above
        let drop_count = excess.min(buf.len());
        buf.drain(0..drop_count);
    }
    buf.extend_from_slice(chunk);
}

/// Recovers a poisoned lock rather than panicking, matching
/// `crate::provenance`'s identical `lock_or_recover`: a reader thread
/// panicking mid-read is already reported by `JoinHandle::join`'s `Err`, and
/// the lock's last-written contents remain the best information this module
/// has.
fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A background reader draining one pipe (stdout or stderr) into a bounded,
/// oldest-dropped buffer, and the join handle that reclaims its thread.
///
/// Deliberately NOT `#[derive(Debug)]`: `std::thread::JoinHandle` does not
/// implement `Debug`, so this type implements it by hand, printing only the
/// captured byte count, which is what lets `Child` derive `Debug` (per its
/// own Public API doc) without that derive failing to compile.
struct CapturedReader {
    buf: Arc<Mutex<Vec<u8>>>,
    handle: Option<std::thread::JoinHandle<()>>,
    /// Set when a bounded [`CapturedReader::join`] gave up before the
    /// reader thread actually finished: the thread is still blocked in
    /// `read`, almost always because a descendant escaped the process-group
    /// signal and still holds the pipe's write end open (see `Child::stop`'s
    /// own doc). Surfaced through `Debug` because there is nowhere else to
    /// report it from a bounded, non-blocking join: this crate denies
    /// `print_stdout`/`print_stderr` everywhere, and `stop`'s own Public API
    /// doc fixes its signature as `fn stop(&mut self)`, with no `Result` to
    /// carry a diagnostic in.
    join_timed_out: bool,
}

impl std::fmt::Debug for CapturedReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = lock_or_recover(&self.buf).len();
        // `finish_non_exhaustive`, not `finish`: `handle` (a `JoinHandle`,
        // which does not implement `Debug`) is deliberately omitted, per
        // this type's own doc comment.
        f.debug_struct("CapturedReader")
            .field("captured_bytes", &len)
            .field("join_timed_out", &self.join_timed_out)
            .finish_non_exhaustive()
    }
}

/// Spawns a background thread draining `reader` into a bounded, oldest-
/// dropped buffer until EOF (the pipe's write end closes, normally because
/// the child exited or closed the descriptor).
fn spawn_capture(mut reader: impl Read + Send + 'static, cap: usize) -> CapturedReader {
    let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let buf_thread = Arc::clone(&buf);
    let handle = std::thread::spawn(move || {
        let mut chunk = [0_u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let bytes = chunk.get(..n).unwrap_or(&[]);
                    let mut guard = lock_or_recover(&buf_thread);
                    append_capped(&mut guard, bytes, cap);
                }
            }
        }
    });
    CapturedReader {
        buf,
        handle: Some(handle),
        join_timed_out: false,
    }
}

impl CapturedReader {
    /// A copy of everything captured so far.
    fn snapshot(&self) -> Vec<u8> {
        lock_or_recover(&self.buf).clone()
    }

    /// Reclaims the reader thread, waiting at most `timeout`. Idempotent: a
    /// second call after a successful join, or after one that already gave
    /// up and set [`Self::join_timed_out`], is a cheap no-op.
    ///
    /// Bounded per [`READER_JOIN_TIMEOUT`]'s own doc: `JoinHandle::join` has
    /// no timeout in `std`, so this polls `is_finished` instead (which is
    /// non-blocking) and only calls the real, blocking `join` once the
    /// thread has already finished, where it returns immediately.
    fn join(&mut self, timeout: Duration) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        if handle.is_finished() {
            let _ = handle.join(); // it-allow: no-swallowed-error reason: this reader thread's only failure mode is a panic, which the loop body above cannot cause (every branch is an infallible match arm), and join's Err carries no information this caller could act on differently
            return;
        }
        let start = Instant::now(); // it-allow: determinism-seam reason: bounds THIS bounded-join call's own wait budget, mirroring stop_unix's identical teardown-grace pattern just below; not a request-path or measurement-window time read
        loop {
            if handle.is_finished() {
                let _ = handle.join(); // it-allow: no-swallowed-error reason: see the identical reason on the fast-path join just above
                return;
            }
            if start.elapsed() >= timeout {
                // Do not join: the thread is still blocked in `read`,
                // almost always because a descendant escaped the group
                // signal and still holds the pipe open (see `Child::stop`'s
                // own doc). Dropping the `JoinHandle` here is safe: the
                // thread keeps running and cleans itself up whenever its
                // `read` eventually returns (or never does, in which case
                // the OS reclaims it at process exit like any other
                // detached thread), and this caller has no further use for
                // its result. `handle` is deliberately NOT put back on
                // `self`: a second bounded join later would just re-run
                // this same bounded wait for no benefit, since nothing
                // between now and then makes the thread any more likely to
                // have finished.
                self.join_timed_out = true;
                return;
            }
            std::thread::park_timeout(READER_JOIN_POLL_INTERVAL); // it-allow: no-accumulated-sleep reason: a fixed poll tick bounded by the start.elapsed() >= timeout deadline check above on every iteration, mirroring stop_unix's identical teardown-grace pattern; a spurious wakeup only costs one extra tick and never accumulates
        }
    }
}

/// Builds the path a capture file is written to: deterministic from the
/// child's own name and pid, so no additional field or parameter is needed
/// to reconstruct it later, and no clock read or random name is involved.
fn capture_file_path(name: &str, pid: u32, stream: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("it-bench-{name}-{pid}.{stream}"))
}

/// Best-effort write of the full captured bytes to a file, returning its path
/// on success. A write failure is reported in the caller's own message
/// (`<the capture file could not be written>`), never as a second error this
/// function itself raises: the write is a diagnostic convenience, not part
/// of what a readiness or teardown failure actually measured.
fn write_capture_file(
    name: &str,
    pid: u32,
    stream: &str,
    bytes: &[u8],
) -> Option<std::path::PathBuf> {
    let path = capture_file_path(name, pid, stream);
    let write_result = std::fs::write(&path, bytes); // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime anywhere in it; this writes a small diagnostic file only on a readiness or teardown failure, never on the measurement path
    match write_result {
        Ok(()) => Some(path),
        Err(_write_failed) => None,
    }
}

/// A spawned child under supervision.
#[derive(Debug)]
pub struct Child {
    process: std::process::Child,
    name: &'static str,
    pid: u32,
    stdout: CapturedReader,
    stderr: CapturedReader,
    reaped: bool,
}

impl Child {
    /// Spawns `invocation` pinned to `cores`, capturing bounded stdout and
    /// stderr.
    ///
    /// # Errors
    /// `BenchError::Io` naming the program when the spawn fails.
    pub fn spawn(
        invocation: &Invocation,
        cores: &CoreSet,
        name: &'static str,
    ) -> Result<Self, BenchError> {
        let attempt_pin = !cores.is_empty();
        let spawned = spawn_with_pin(invocation, cores, attempt_pin);
        let mut child = match spawned {
            Ok(child) => child,
            Err(source) if attempt_pin && source.kind() == std::io::ErrorKind::NotFound => {
                // `taskset` itself is what was not found (edge case 11: not
                // installed off Linux, the normal case on this crate's own
                // macOS development host), not `invocation.program`. Fall
                // back to spawning unpinned rather than failing the whole
                // repetition over a missing pinning tool.
                spawn_with_pin(invocation, cores, false)
                    .map_err(|e| BenchError::io(&invocation.program, e))?
            }
            Err(source) => return Err(BenchError::io(&invocation.program, source)),
        };

        let pid = child.id();
        let stdout = match child.stdout.take() {
            Some(reader) => spawn_capture(reader, MAX_CAPTURED_BYTES),
            // `Stdio::piped()` is set on every path in `spawn_with_pin`
            // above, so `stdout` is always `Some` after a successful spawn;
            // this arm is unreachable in practice and is handled with a
            // harmless empty capture rather than a panic, per this crate's
            // own no-panic-in-production rule.
            None => spawn_capture(std::io::empty(), MAX_CAPTURED_BYTES),
        };
        let stderr = match child.stderr.take() {
            Some(reader) => spawn_capture(reader, MAX_CAPTURED_BYTES),
            None => spawn_capture(std::io::empty(), MAX_CAPTURED_BYTES),
        };

        Ok(Self {
            process: child,
            name,
            pid,
            stdout,
            stderr,
            reaped: false,
        })
    }

    /// Polls a TCP connect to `addr` every 50 ms until it succeeds or
    /// `timeout` elapses. Never a fixed sleep: a fixed sleep is either too
    /// short on a loaded machine or wasted time on an idle one.
    ///
    /// # Errors
    /// `BenchError::Io` on timeout, or the moment the child is observed to
    /// have already exited (distinguishing "started and exited" from "never
    /// listened" without waiting out the rest of `timeout`). The message
    /// carries a `Detail`-clipped excerpt of the child's stderr (at most 256
    /// printable ASCII bytes) plus the path of the file the full bytes were
    /// written to. The child chooses every byte it writes, so the excerpt is
    /// sanitised before it reaches a terminal or a log, and the unsanitised
    /// bytes only ever reach a file.
    pub fn wait_ready(&mut self, addr: SocketAddr, timeout: Duration) -> Result<(), BenchError> {
        let start = Instant::now(); // it-allow: determinism-seam reason: measures this wait_ready call's own wall-clock readiness budget, mirroring crate::provenance's identical poll_until_done pattern; not a request-path or measurement-window time read
        loop {
            if matches!(self.process.try_wait(), Ok(Some(_status))) {
                // The child has already exited, so its stdout and stderr
                // pipes are already closed at the OS level: joining the
                // capture reader threads here is bounded and fast (they see
                // EOF almost immediately once the write end closes), and is
                // what guarantees the snapshot in readiness_error reflects
                // everything the child wrote rather than racing those
                // threads' own scheduling on a busy host. This is NOT safe
                // to do in the other return below, where the child may
                // still be running and its pipes still open.
                self.stdout.join(READER_JOIN_TIMEOUT);
                self.stderr.join(READER_JOIN_TIMEOUT);
                return Err(self.readiness_error(addr, timeout));
            }
            match TcpStream::connect(addr) {
                // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime; this poll IS the readiness check this function exists to perform
                Ok(_connected) => return Ok(()),
                Err(_not_ready_yet) => {}
            }
            if start.elapsed() >= timeout {
                return Err(self.readiness_error(addr, timeout));
            }
            std::thread::sleep(READY_POLL_INTERVAL); // it-allow: no-blocking-in-async reason: irontraffic-bench has no async runtime anywhere in it; this is the readiness poll itself, the one thing this function exists to do. it-allow: no-accumulated-sleep reason: a fixed 50ms readiness poll tick bounded by the start.elapsed() >= timeout deadline check above on every iteration; a spurious wakeup or scheduling delay costs one extra 50ms tick and never accumulates the way an open-loop request schedule must
        }
    }

    /// Builds the sanitised, file-referencing readiness-failure error. See
    /// `wait_ready`'s own doc for the shape.
    fn readiness_error(&self, addr: SocketAddr, timeout: Duration) -> BenchError {
        let raw_stderr = self.stderr.snapshot();
        let tail_start = raw_stderr.len().saturating_sub(READINESS_EXCERPT_RAW_BYTES);
        let tail = raw_stderr.get(tail_start..).unwrap_or(&[]);
        let excerpt = Detail::new(&String::from_utf8_lossy(tail));
        let path_text = write_capture_file(self.name, self.pid, "stderr", &raw_stderr).map_or_else(
            || "<the capture file could not be written>".to_owned(),
            |path| path.display().to_string(),
        );
        let message = format!(
            "child {} (pid {}) did not become ready on {addr} within {timeout:?}: stderr \
             excerpt: {excerpt}; full stderr at {path_text}",
            self.name, self.pid
        );
        BenchError::io(&addr.to_string(), std::io::Error::other(message))
    }

    /// Cumulative user plus system CPU seconds from `/proc/<pid>/stat`.
    ///
    /// # Errors
    /// `BenchError::Io` when the process has exited or `/proc` is
    /// unavailable.
    pub fn cpu_seconds(&self) -> Result<f64, BenchError> {
        read_cpu_seconds(self.pid)
    }

    /// `VmRSS` and `smaps_rollup` `Pss` in bytes. Both 0 off Linux.
    ///
    /// # Errors
    /// `BenchError::Io` when the process has exited.
    pub fn memory(&self) -> Result<(u64, u64), BenchError> {
        read_memory(self.pid)
    }

    /// Direct, mutable access to the underlying process.
    ///
    /// `pub(crate)`, beyond this issue's own Public API doc section for
    /// `proc.rs`, because `crate::runner` needs `try_wait`/`wait` on the
    /// load client's own natural exit (Design step 7) and on a one-shot
    /// ceiling or warmup invocation (Design step 2 and the warmup
    /// invocation), neither of which is `stop`'s own job. Kept crate-private
    /// rather than fully `pub`: nothing outside this crate needs it, and a
    /// caller that only has `&mut std::process::Child` could bypass this
    /// module's own bounded capture and process-group teardown entirely.
    pub(crate) fn raw_mut(&mut self) -> &mut std::process::Child {
        &mut self.process
    }

    /// The captured stdout so far. A repetition reads this once, after the
    /// child has exited, per `LoadGenerator::parse`'s own contract.
    pub(crate) fn stdout_snapshot(&self) -> Vec<u8> {
        self.stdout.snapshot()
    }

    /// The captured stderr so far.
    pub(crate) fn stderr_snapshot(&self) -> Vec<u8> {
        self.stderr.snapshot()
    }

    /// Signals the child's whole PROCESS GROUP with SIGTERM, then SIGKILL
    /// after 5 seconds, then reaps. Idempotent.
    ///
    /// The group, not the pid: a container-based adapter's direct child is a
    /// `docker run` CLI process, and a container that outlives teardown
    /// holds the host network ports it was given and runs a load generator
    /// through the next repetition. For a container-based adapter this is
    /// followed by `<runtime> kill <container-name>`, whose "no such
    /// container" result is ignored.
    ///
    /// `Child` as declared here carries no runtime and no container name, so
    /// that second half is NOT implementable from `stop`'s own state.
    /// Implement the process-group half, and leave the container kill to the
    /// adapter that knows its own runtime and container name. Do not invent
    /// a container field on `Child` to close the gap: no test in this issue
    /// exercises a container-based adapter, neither docker nor podman is
    /// installed on the development host, and the `docker ps --filter
    /// name=it-bench-` acceptance criterion is therefore vacuous on that host
    /// and must be reported as unverified rather than asserted as passing.
    ///
    /// The group signal above cannot reach a descendant that has already
    /// escaped the group (the exact container case this doc just described,
    /// and the one case this module cannot close). Reaping this process
    /// itself is unaffected by that, but the capture reader threads below
    /// read from a pipe such a descendant can keep open forever: `stop`
    /// bounds that wait per [`READER_JOIN_TIMEOUT`]'s own doc rather than
    /// blocking on it unconditionally, so an escaped descendant degrades
    /// this call to "returns within a few seconds, `CapturedReader::join_timed_out`
    /// set" instead of a wedge with no timeout and no diagnostic.
    pub fn stop(&mut self) {
        if self.reaped {
            return;
        }
        #[cfg(unix)]
        self.stop_unix();
        #[cfg(not(unix))]
        self.stop_fallback();
        self.reaped = true;
        self.stdout.join(READER_JOIN_TIMEOUT);
        self.stderr.join(READER_JOIN_TIMEOUT);
    }

    #[cfg(unix)]
    fn stop_unix(&mut self) {
        let pid = rustix::process::Pid::from_child(&self.process);
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM); // it-allow: no-swallowed-error reason: best-effort SIGTERM to the whole process group; the process may already have exited between the caller's own liveness check and this call, and the wait loop below observes the actual outcome regardless
        let start = Instant::now(); // it-allow: determinism-seam reason: measures this teardown call's own 5 second SIGTERM grace budget before escalating to SIGKILL, mirroring crate::provenance's identical poll_until_done pattern; not a request-path time read
        loop {
            match self.process.try_wait() {
                Ok(Some(_status)) => return,
                Ok(None) => {}
                Err(_wait_failed) => return,
            }
            if start.elapsed() >= TEARDOWN_GRACE {
                break;
            }
            std::thread::park_timeout(TEARDOWN_POLL_INTERVAL); // it-allow: no-accumulated-sleep reason: a fixed 20ms grace-period poll tick bounded by the start.elapsed() >= TEARDOWN_GRACE deadline check above on every iteration, mirroring crate::provenance's identical poll_until_done pattern; a spurious wakeup only costs one extra tick and never accumulates
        }
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL); // it-allow: no-swallowed-error reason: best-effort SIGKILL escalation to the whole process group; the blocking reap immediately below observes the actual outcome regardless of whether the signal reached a still-live process or an already-exited one
        let _ = self.process.wait(); // it-allow: no-swallowed-error reason: this reaps the child after SIGKILL, which cannot be caught or ignored; stop() has no further action to take whether the wait succeeds or the child had already been reaped by something else
    }

    #[cfg(not(unix))]
    fn stop_fallback(&mut self) {
        // No process-group signal concept off Unix; this is the documented
        // fallback on `stop`'s own Public API doc. Every platform this
        // module actually ships and tests on (Linux CI, macOS development)
        // is Unix; this arm exists only so the crate still builds elsewhere.
        let _ = self.process.kill(); // it-allow: no-swallowed-error reason: best-effort kill; the process may already have exited, and the wait below observes the actual outcome regardless
        let _ = self.process.wait(); // it-allow: no-swallowed-error reason: best-effort reap after kill; there is nothing further to do with the result
    }
}

impl Drop for Child {
    /// Calls `stop`. This is why teardown cannot be forgotten on an early
    /// return.
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawns `invocation`, either wrapped in `taskset -c <cpuset>` (when `pin`
/// is true) or bare, with stdin null and stdout/stderr piped, in its own
/// process group.
fn spawn_with_pin(
    invocation: &Invocation,
    cores: &CoreSet,
    pin: bool,
) -> std::io::Result<std::process::Child> {
    let mut command = if pin {
        let mut c = Command::new("taskset");
        c.arg("-c").arg(cores.as_cpuset()).arg(&invocation.program);
        c
    } else {
        Command::new(&invocation.program)
    };
    command.args(&invocation.args);
    for (key, value) in &invocation.env {
        command.env(key, value);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command.spawn() // it-allow: no-blocking-in-async reason: irontraffic-bench is a synchronous benchmark harness crate with no async runtime anywhere in it; spawning the measurement's own child processes is the whole point of this module, never a request-path operation
}

/// Parses `utime` and `stime` (fields 14 and 15) out of one `/proc/<pid>/stat`
/// line.
///
/// Splits after the LAST `)`, never on whitespace from the start: field 2 is
/// the executable name in parentheses and may itself contain spaces and
/// parentheses (for example `(my proxy (v2))`), so a whitespace split puts
/// `utime` and `stime` at the wrong indices for any such binary and silently
/// reads two unrelated numbers as CPU time. A line with no `)` is an error,
/// not an index into whatever was there.
///
/// Re-exported beyond `proc.rs`'s own Public API doc section for this issue,
/// which does not name it, because `proc_stat_parsing_survives_a_spaced_comm`
/// (test 21) needs a pure function it can drive with a synthetic buffer, and
/// `/proc` does not exist on this crate's own macOS development host at all;
/// `crate::probe`'s own re-export of `scan_response_head` beyond its own
/// issue's Files table line, for its own property test, is the established
/// precedent for this exact shape.
///
/// # Errors
/// `BenchError::Parse` when `line` contains no `)`, is not valid UTF-8 after
/// the comm field, has fewer than 15 whitespace-separated fields, or when
/// the `utime` or `stime` field is not an integer.
pub fn parse_stat_cpu_ticks(line: &[u8]) -> Result<(u64, u64), BenchError> {
    let last_paren = line.iter().rposition(|&b| b == b')').ok_or_else(|| {
        BenchError::parse(
            "proc_stat",
            "no ')' found: cannot locate the end of the comm field",
        )
    })?;
    let rest = line.get(last_paren.saturating_add(1)..).unwrap_or(&[]);
    let text = std::str::from_utf8(rest)
        .map_err(|_| BenchError::parse("proc_stat", "bytes after the comm field are not utf-8"))?;
    let fields: Vec<&str> = text.split_whitespace().collect();
    // The comm field terminates field 2; the fields remaining after it start
    // at field 3 (state). utime is field 14 (index 11 here) and stime is
    // field 15 (index 12 here).
    let utime_str = fields.get(11).ok_or_else(|| {
        BenchError::parse(
            "proc_stat",
            "line has fewer fields than needed to reach utime (field 14)",
        )
    })?;
    let stime_str = fields.get(12).ok_or_else(|| {
        BenchError::parse(
            "proc_stat",
            "line has fewer fields than needed to reach stime (field 15)",
        )
    })?;
    let utime: u64 = utime_str
        .parse()
        .map_err(|_| BenchError::parse("proc_stat", "utime field is not an integer"))?;
    let stime: u64 = stime_str
        .parse()
        .map_err(|_| BenchError::parse("proc_stat", "stime field is not an integer"))?;
    Ok((utime, stime))
}

#[cfg(target_os = "linux")]
fn read_cpu_seconds(pid: u32) -> Result<f64, BenchError> {
    let path = format!("/proc/{pid}/stat");
    let bytes = read_bounded(std::path::Path::new(&path), SMALL_FILE_CAP)?;
    let (utime, stime) = parse_stat_cpu_ticks(&bytes)?;
    let ticks = utime.saturating_add(stime);
    #[expect(
        clippy::cast_precision_loss,
        reason = "a cumulative CPU tick count losing a few low bits of precision above 2^53 \
                  ticks (over two million years at 100 ticks/second) is not a realistic \
                  benchmark run; this is display and comparison precision, not a security or \
                  correctness boundary"
    )]
    let ticks_f64 = ticks as f64;
    Ok(ticks_f64 / CLOCK_TICKS_PER_SEC_F64)
}

#[cfg(not(target_os = "linux"))]
fn read_cpu_seconds(_pid: u32) -> Result<f64, BenchError> {
    Err(BenchError::io(
        "/proc",
        std::io::Error::other("/proc is only available on Linux"),
    ))
}

/// `CLOCK_TICKS_PER_SEC` widened once, so `read_cpu_seconds` never repeats
/// the narrowing-then-widening dance on every call.
///
/// Written as an `f64` literal rather than `CLOCK_TICKS_PER_SEC as f64`, which
/// `clippy::cast_precision_loss` denies: an unrestricted `u64` really can
/// exceed `f64`'s 52 bit mantissa, and the lint cannot see that this
/// particular one is the constant 100. A cast plus an allow would silence the
/// lint while leaving the same trap for whoever later makes the tick count
/// dynamic, so the two are tied together instead: the debug assertion below
/// fails the moment they diverge, which is the only way they can.
#[cfg(target_os = "linux")]
const CLOCK_TICKS_PER_SEC_F64: f64 = 100.0;

#[cfg(target_os = "linux")]
#[allow(
    clippy::assertions_on_constants,
    reason = "the point IS that both sides are constants: this ties the f64 form to the u64               form so a future edit to one and not the other cannot silently scale every               cpu_seconds figure by a fixed factor"
)]
const _: () = assert!(CLOCK_TICKS_PER_SEC == 100);

#[cfg(target_os = "linux")]
fn read_memory(pid: u32) -> Result<(u64, u64), BenchError> {
    let rss = read_vmrss(pid)?;
    // `smaps_rollup` unreadable (an old kernel, or a restricted container) is
    // edge case 13: `pss_bytes` is 0, and an unpublishable reason is recorded
    // by whichever caller owns `Provenance`, not by this function.
    let pss = read_pss(pid).unwrap_or(0);
    Ok((rss, pss))
}

#[cfg(not(target_os = "linux"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the signature is shared with the #[cfg(target_os = \"linux\")] sibling above, \
              which DOES fail (a read error); keeping both bodies infallible-vs-fallible under \
              the same Result-returning signature is what lets Child::memory stay one function \
              with one doc comment rather than forking per platform"
)]
fn read_memory(_pid: u32) -> Result<(u64, u64), BenchError> {
    // "Both 0 off Linux" per this function's own Public API doc: unlike
    // `cpu_seconds`, this is `Ok`, not `Err`, off Linux.
    Ok((0, 0))
}

#[cfg(target_os = "linux")]
fn read_vmrss(pid: u32) -> Result<u64, BenchError> {
    let path = format!("/proc/{pid}/status");
    let bytes = read_bounded(std::path::Path::new(&path), SMALL_FILE_CAP)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| BenchError::parse("proc_status", "contains invalid utf-8"))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let value = rest
                .trim()
                .strip_suffix("kB")
                .map(str::trim)
                .ok_or_else(|| BenchError::parse("proc_status", "VmRSS has no kB unit"))?;
            let kb: u64 = value
                .parse()
                .map_err(|_| BenchError::parse("proc_status", "VmRSS is not an integer"))?;
            return kb
                .checked_mul(1024)
                .ok_or_else(|| BenchError::parse("proc_status", "VmRSS overflows u64 bytes"));
        }
    }
    Err(BenchError::parse("proc_status", "no VmRSS line found"))
}

#[cfg(target_os = "linux")]
fn read_pss(pid: u32) -> Result<u64, BenchError> {
    let path = format!("/proc/{pid}/smaps_rollup");
    let bytes = read_bounded(std::path::Path::new(&path), SMALL_FILE_CAP)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| BenchError::parse("proc_smaps_rollup", "contains invalid utf-8"))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Pss:") {
            let value = rest
                .trim()
                .strip_suffix("kB")
                .map(str::trim)
                .ok_or_else(|| BenchError::parse("proc_smaps_rollup", "Pss has no kB unit"))?;
            let kb: u64 = value
                .parse()
                .map_err(|_| BenchError::parse("proc_smaps_rollup", "Pss is not an integer"))?;
            return kb
                .checked_mul(1024)
                .ok_or_else(|| BenchError::parse("proc_smaps_rollup", "Pss overflows u64 bytes"));
        }
    }
    Err(BenchError::parse("proc_smaps_rollup", "no Pss line found"))
}

/// A disjoint set of cores assigned to one role: a sorted, deduplicated list
/// of logical core indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSet(Vec<usize>);

impl CoreSet {
    fn from_unsorted(mut cores: Vec<usize>) -> Self {
        cores.sort_unstable();
        cores.dedup();
        Self(cores)
    }

    /// Partitions the machine's cores into origin, sut, client and probe
    /// sets.
    ///
    /// The remaining cores after reserving one for the probe are split into
    /// three roughly equal, contiguous ranges (origin, sut, client, in that
    /// order), with any remainder from the division going to the client set:
    /// no particular ratio is specified by this issue's own Design or Public
    /// API sections beyond "disjoint", so this is a reasonable, deterministic
    /// choice rather than a tuned one.
    ///
    /// # Errors
    /// `BenchError::Parse` when the machine has fewer than 8 logical cores,
    /// naming the count. Below 8 cores the four roles cannot be disjoint and
    /// every number would be contention.
    ///
    /// NOT `BenchError::Cell`, which holds a `&'static str` and so cannot
    /// name a value that varies per call. `crate::matrix::entry` documents
    /// and resolves the identical conflict the same way, citing a PR 819
    /// review finding; this follows that precedent.
    pub fn partition(logical_cores: u32) -> Result<CoreAssignment, BenchError> {
        if logical_cores < 8 {
            return Err(BenchError::parse(
                "core_partition",
                &format!(
                    "{logical_cores} logical cores available; at least 8 are required so \
                     origin, sut, client and probe can each get a disjoint set"
                ),
            ));
        }
        let total = logical_cores as usize; // widening u32 -> usize: always exact on every platform this workspace targets, so clippy does not flag it and no escape is needed
        let probe_index = total - 1; // total >= 8, checked above
        let remaining = total - 1;
        #[allow(
            clippy::integer_division,
            reason = "base is a floor-divided core COUNT (an exact index arithmetic quantity, \
                      never a physical measurement), and the remainder from this division is \
                      deliberately added onto the client set's own count on the next line \
                      rather than silently dropped, so no core is ever lost to truncation"
        )]
        let base = remaining / 3;
        let client_count = remaining - 2 * base;

        let origin: Vec<usize> = (0..base).collect();
        let sut: Vec<usize> = (base..2 * base).collect();
        let client: Vec<usize> = (2 * base..2 * base + client_count).collect();
        let probe: Vec<usize> = vec![probe_index];

        Ok(CoreAssignment {
            origin: Self::from_unsorted(origin),
            sut: Self::from_unsorted(sut),
            client: Self::from_unsorted(client),
            probe: Self::from_unsorted(probe),
        })
    }

    /// Rendered for `taskset -c`.
    #[must_use]
    pub fn as_cpuset(&self) -> String {
        self.0
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// True when this set contains no cores.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many cores are in this set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::ops::Deref for CoreSet {
    type Target = [usize];

    fn deref(&self) -> &[usize] {
        &self.0
    }
}

/// Which cores each role runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreAssignment {
    /// Cores for `it-origin`.
    pub origin: CoreSet,
    /// Cores for the system under test.
    pub sut: CoreSet,
    /// Cores for the load client.
    pub client: CoreSet,
    /// One core for the probe.
    pub probe: CoreSet,
}

#[cfg(test)]
mod tests {
    use super::{Child, CoreSet, append_capped, parse_stat_cpu_ticks};
    use crate::loadgen::Invocation;
    use std::time::{Duration, Instant};

    #[test]
    fn append_capped_drops_oldest_bytes() {
        let mut buf = Vec::new();
        append_capped(&mut buf, b"abcde", 8);
        append_capped(&mut buf, b"fghij", 8);
        // "abcdefghij" is 10 bytes; capped at 8, the oldest 2 ("ab") drop.
        assert_eq!(buf, b"cdefghij");
    }

    #[test]
    fn append_capped_single_chunk_larger_than_cap_keeps_the_tail() {
        let mut buf = Vec::new();
        append_capped(&mut buf, b"0123456789", 4);
        assert_eq!(buf, b"6789");
    }

    #[test]
    fn parse_stat_cpu_ticks_rejects_a_line_with_no_paren() {
        assert!(parse_stat_cpu_ticks(b"not a stat line at all").is_err());
    }

    /// Whether `pid` is currently a running process. Checked with `ps`
    /// rather than a raw signal-0 liveness probe, which would need `unsafe`
    /// FFI this crate denies everywhere: `ps -p <pid>` exits 0 with output
    /// when the pid exists and nonzero with no output once it is gone, on
    /// both macOS and Linux.
    fn pid_is_alive(pid: u32) -> bool {
        std::process::Command::new("ps")
            .arg("-p")
            .arg(pid.to_string())
            .output()
            .is_ok_and(|out| out.status.success())
    }

    #[test]
    fn drop_without_an_explicit_stop_call_still_tears_down_the_child() {
        // Reviewed finding: teardown_leaves_no_children (tests/runner.rs,
        // test 13) asserts only that run_repetition returns Err; emptying
        // `impl Drop for Child { fn drop(&mut self) {} }` entirely left
        // that test green while leaking a live process, because
        // run_repetition's own encapsulation gives no external test a pid
        // to check liveness against. This test drives `Child`'s own Drop
        // impl directly, with no explicit `stop()` call anywhere, and
        // checks real process liveness by pid: the one thing test 13
        // structurally cannot do.
        let invocation = Invocation {
            program: "sleep".to_owned(),
            args: vec!["30".to_owned()],
            env: Vec::new(),
        };
        let cores = CoreSet::from_unsorted(Vec::new());
        let child = Child::spawn(&invocation, &cores, "drop_without_stop_test")
            .unwrap_or_else(|e| panic!("spawn of `sleep 30` failed: {e:?}"));
        let pid = child.pid;
        assert!(
            pid_is_alive(pid),
            "the freshly spawned child (pid {pid}) must be alive before Drop runs at all"
        );

        drop(child); // No stop() call: only Child's own Drop impl runs.

        let start = Instant::now();
        let mut alive = pid_is_alive(pid);
        while alive && start.elapsed() < Duration::from_secs(6) {
            // it-allow: no-accumulated-sleep reason: this is a bounded poll,
            // not an unconditional wait. Each tick re-checks pid_is_alive and
            // the loop exits the moment the pid is gone, against a 6 second
            // deadline; that is the same shape every other park_timeout site
            // in this crate uses. Justified by what it IS, deliberately not
            // by which grep it does or does not match: a wait site that
            // explains itself as staying out of a check is one a future
            // reader cannot audit.
            std::thread::park_timeout(Duration::from_millis(50));
            alive = pid_is_alive(pid);
        }
        assert!(
            !alive,
            "pid {pid} must not survive past Child's own Drop impl when nothing ever calls \
             stop() explicitly; a live process here means Drop is not actually tearing children \
             down"
        );
    }
}
