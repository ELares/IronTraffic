// SPDX-License-Identifier: MIT OR Apache-2.0

//! The end-to-end proof that `run` and `proxy` actually serve traffic, and that
//! `control` actually does not.
//!
//! Every test starts an origin (except the ones that do not need one: a dead
//! upstream, and control mode, which never reaches one), starts the proxy pointed at
//! it, and uses a plain [`std::net::TcpStream`] client so the client side has no
//! async machinery to misattribute a failure to.

mod support;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// The request every test that does not care about its exact bytes sends.
const HELLO_REQUEST: &[u8] = b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n";

/// The response `cfg_yaml`'s origin produces for [`HELLO_REQUEST`], byte for byte.
const HELLO_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

/// A minimal valid configuration: one listener, one upstream, and short timeouts so
/// the tests that exercise deadlines and drains do not have to wait for the
/// production defaults (a five-minute graceful timeout, a one-minute idle deadline).
fn cfg_yaml(upstream_port: u16) -> String {
    format!(
        "apiVersion: irontraffic.io/v1\n\
         listeners:\n\
         \x20\x20- name: web\n\
         \x20\x20\x20\x20bind: \"127.0.0.1:0\"\n\
         upstream:\n\
         \x20\x20address: \"127.0.0.1:{upstream_port}\"\n\
         timeouts:\n\
         \x20\x20connect_ms: 2000\n\
         \x20\x20idle_ms: 5000\n\
         \x20\x20half_close_ms: 5000\n\
         shutdown:\n\
         \x20\x20graceful_timeout_ms: 2000\n\
         \x20\x20drain_jitter_ms: 10\n"
    )
}

/// [`cfg_yaml`] plus an explicit `limits.max_connections`.
fn cfg_yaml_with_max_connections(upstream_port: u16, max_connections: u32) -> String {
    format!(
        "{}limits:\n\x20\x20max_connections: {max_connections}\n",
        cfg_yaml(upstream_port)
    )
}

/// A configuration with a concrete (non-zero) bind port, for the tests that must
/// know the listener's address without going through [`support::spawn_proxy`]'s own
/// port discovery (`control` mode never binds it, so there is nothing to discover).
fn cfg_yaml_with_bind(bind_port: u16, upstream_port: u16) -> String {
    format!(
        "apiVersion: irontraffic.io/v1\n\
         listeners:\n\
         \x20\x20- name: web\n\
         \x20\x20\x20\x20bind: \"127.0.0.1:{bind_port}\"\n\
         upstream:\n\
         \x20\x20address: \"127.0.0.1:{upstream_port}\"\n"
    )
}

/// Connects to `addr` with a bounded read timeout, so a hung server produces a
/// prompt test failure instead of blocking the whole run.
///
/// `#[allow(clippy::expect_used)]`: test-support helper, not itself a `#[test]` fn,
/// so clippy's test exemption for `expect_used` does not extend to it (mirrors
/// `write_fixture`'s own precedent in `tests/validate_cli.rs`). Connecting to a
/// proxy this same test already confirmed is listening does not fail on a working
/// test host.
#[allow(clippy::expect_used, reason = "see the function doc comment above")]
fn connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set a bounded read timeout");
    stream
}

/// Sends [`HELLO_REQUEST`].
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn (see connect's doc comment); writing \
              a few dozen bytes to a socket this test just connected does not fail on a working \
              test host"
)]
fn send_hello(stream: &mut TcpStream) {
    stream.write_all(HELLO_REQUEST).expect("write the request");
}

/// Reads the response to EOF.
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn (see connect's doc comment); a real \
              failure here is exactly what every calling test exists to catch, and it fails \
              loudly either way"
)]
fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .expect("read the response to EOF");
    out
}

/// Removes ANSI SGR escape sequences (`ESC [ ... <letter>`) from `text`.
///
/// `tracing_subscriber`'s default formatter emits them around the message, the
/// level, the target, and every field name and value, even when stderr is a piped,
/// non-terminal file descriptor (confirmed by running the binary manually with
/// stderr redirected to a plain file), which splits an otherwise-contiguous
/// `key=value` field across several such sequences (`connections_accepted` is one
/// escape-delimited span, `=` another, the value a third). `logging.rs` is not a
/// file this issue's table allows touching, so the parsing here tolerates its output
/// instead of asking it to change.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break; // the final byte of the escape sequence
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses `<name>=<digits>` out of `line`, tolerant of whatever else the line
/// contains: a later field addition must not break this.
fn field_value(line: &str, name: &str) -> Option<u64> {
    let plain = strip_ansi(line);
    let needle = format!("{name}=");
    let start = plain.find(&needle)? + needle.len();
    let rest = &plain[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..end)?.parse().ok()
}

/// 1. `one_request_is_proxied_end_to_end`: the milestone's acceptance test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_request_is_proxied_end_to_end() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml(origin.addr.port()));

    let mut client = connect(proxy.addr);
    send_hello(&mut client);
    let response = read_all(&mut client);

    assert_eq!(response, HELLO_RESPONSE);
    assert_eq!(origin.hits(), 1);

    proxy.shutdown();
    origin.stop().await;
}

/// 2. `request_bytes_reach_the_origin_unchanged`: no header was added, removed, or
///    reordered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_bytes_reach_the_origin_unchanged() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml(origin.addr.port()));

    let mut client = connect(proxy.addr);
    send_hello(&mut client);
    let _response = read_all(&mut client);

    assert_eq!(origin.last_request(), HELLO_REQUEST);

    proxy.shutdown();
    origin.stop().await;
}

/// 3. `ten_sequential_connections_all_succeed`: the accept loop is not wedging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_sequential_connections_all_succeed() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml(origin.addr.port()));

    for i in 0..10 {
        let mut client = connect(proxy.addr);
        send_hello(&mut client);
        let response = read_all(&mut client);
        assert_eq!(response, HELLO_RESPONSE, "connection {i}");
    }
    assert_eq!(origin.hits(), 10);

    proxy.shutdown();
    origin.stop().await;
}

/// 4. `ten_concurrent_connections_all_succeed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_concurrent_connections_all_succeed() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml(origin.addr.port()));
    let addr = proxy.addr;

    let handles: Vec<std::thread::JoinHandle<Vec<u8>>> = (0..10)
        .map(|_| {
            std::thread::spawn(move || {
                let mut client = connect(addr);
                send_hello(&mut client);
                read_all(&mut client)
            })
        })
        .collect();

    for (i, h) in handles.into_iter().enumerate() {
        let response = h
            .join()
            .unwrap_or_else(|_| panic!("client thread {i} panicked"));
        assert_eq!(response, HELLO_RESPONSE, "connection {i}");
    }
    assert_eq!(origin.hits(), 10);

    proxy.shutdown();
    origin.stop().await;
}

/// 5. `sigterm_drains_cleanly_and_exits_zero`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_drains_cleanly_and_exits_zero() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml(origin.addr.port()));

    let mut client = connect(proxy.addr);
    send_hello(&mut client);
    let response = read_all(&mut client);
    assert_eq!(response, HELLO_RESPONSE);
    // Close our half explicitly: `Connection: close` and the read to EOF above already
    // proved the upstream-to-client direction finished, but the client-to-upstream
    // direction only reaches its own EOF once THIS socket closes too. Leaving it open
    // would make the connection still "live" from the proxy's perspective the instant
    // SIGTERM arrives below, so the drain would wait out its graceful deadline and
    // report a killed connection instead of a clean one.
    drop(client);

    let status = proxy.shutdown();
    assert_eq!(status.code(), Some(0));

    origin.stop().await;
}

/// True when a read observed a closed connection promptly: either a clean `Ok(0)`
/// or one of two errors, tolerant of which of those valid TCP shapes it takes.
///
/// A bare `drop` of a socket that still has the peer's own unread bytes queued in its
/// receive buffer makes the kernel send an RST rather than a graceful FIN, by
/// ordinary POSIX socket semantics; that is exactly the scenario `dead_upstream_
/// closes_the_connection_without_hanging` creates by writing a request before it
/// reads, since the connection handler drops the downstream transport without ever
/// reading it once the upstream connect has already failed. Both a clean `Ok(0)` and
/// a reset are the same wall-clock-bounded "closed promptly" fact that test exists to
/// prove; only a hang, or the read returning real bytes, is a genuine failure, and
/// this function returns `false` for the latter so the caller's own `assert!` names
/// what was actually observed.
fn closed_without_hanging(result: &std::io::Result<usize>) -> bool {
    match result {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        ),
    }
}

/// 6. `dead_upstream_closes_the_connection_without_hanging`: startup succeeds even
///    though the backend is down, and the failure is bounded, not a hang.
#[test]
fn dead_upstream_closes_the_connection_without_hanging() {
    let dead_port = support::free_local_port(); // nothing is listening here
    let proxy = support::spawn_proxy(&cfg_yaml(dead_port));

    let mut first = connect(proxy.addr);
    send_hello(&mut first);
    let mut buf = [0_u8; 16];
    let first_result = first.read(&mut buf);
    assert!(
        closed_without_hanging(&first_result),
        "first connection: expected EOF or a reset, got {first_result:?}"
    );

    // The process is still alive and still accepting: a second connection also gets EOF.
    let mut second = connect(proxy.addr);
    send_hello(&mut second);
    let second_result = second.read(&mut buf);
    assert!(
        closed_without_hanging(&second_result),
        "second connection: expected EOF or a reset, got {second_result:?}"
    );

    proxy.shutdown();
}

/// True when a bounded read observes neither data nor a close: a `WouldBlock` (most
/// platforms) or `TimedOut` (some platforms) error from a socket whose read timeout
/// expired with nothing to report. This is the "still open" counterpart to
/// [`closed_without_hanging`]: the two are never satisfied by the same outcome, so a
/// connection can be proven open or proven closed, but never both.
fn still_open(result: &std::io::Result<usize>) -> bool {
    matches!(
        result,
        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
    )
}

/// 7. `connection_cap_rejects_the_extra_connection`.
///
/// Both reads below use a bound far under `cfg_yaml`'s `half_close_ms: 5000`: with
/// the cap disabled, an over-cap connection is never rejected and instead sits
/// forwarded and idle until the half-close deadline, which a bound of 5 seconds (the
/// literal wording of #21 test 7) would not distinguish from a cap rejection, since
/// `connect`'s own 10-second read timeout comfortably outlasts a 5-second half-close.
/// A 1-second bound on the second connection's read turns that wait into a timeout
/// error instead of the `Ok(0)` this test asserts, which is what makes the cap doing
/// nothing an observed failure rather than a slow pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_cap_rejects_the_extra_connection() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml_with_max_connections(origin.addr.port(), 1));

    // `spawn_proxy`'s own readiness probe opens and immediately closes one
    // connection to confirm the listener answers; give the proxy a moment to finish
    // releasing that connection's slot before this test relies on the cap starting
    // from exactly zero.
    std::thread::sleep(Duration::from_millis(200));

    let mut first = connect(proxy.addr); // held open, sends nothing

    let mut second = connect(proxy.addr);
    second
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("bound the cap-rejection probe's read well under half_close_ms");
    let mut buf = [0_u8; 16];
    let n = second
        .read(&mut buf)
        .expect("the connection over max_connections must see EOF within 1s, not time out");
    assert_eq!(n, 0, "the connection over max_connections must see EOF");

    // The first connection, which fit under the cap, must still be open while the
    // second is being rejected. Without this, the assertion above would equally pass
    // if some other bug closed the FIRST connection (leaving room under the cap for
    // the second) instead of rejecting the second.
    first
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("bound the still-open probe");
    let mut first_buf = [0_u8; 16];
    let first_result = first.read(&mut first_buf);
    assert!(
        still_open(&first_result),
        "the first connection (under the cap) must still be open: got {first_result:?}"
    );

    drop(first);
    drop(second);
    proxy.shutdown();
    origin.stop().await;
}

/// 8. `control_mode_binds_nothing_and_exits_zero`.
///
/// The port is held BEFORE the child ever runs, not probed afterwards: a probe run
/// after the child has already exited finds nothing listening whether or not
/// `control` ever attempted the bind, which proves nothing. Holding the port first
/// means a `control` that (incorrectly) reached the bind loop would collide with
/// this listener and exit 5, so exit 0 while the port is held is only possible when
/// `control` truly binds nothing.
///
/// The stderr assertion additionally pins startup ORDER, not just the outcome:
/// `control` must never reach either `irontraffic_runtime::DataPlane::build` or
/// `ControlPlane::build`, both of which log a `"... runtime built"` line on success.
/// A mutation that moves the `Mode::Control` short-circuit past those two calls (but
/// still before the bind loop) would leave the port-held assertion above passing,
/// since nothing would bind, while still building two tokio runtimes control mode is
/// specified never to build; this assertion is what catches that case.
#[test]
fn control_mode_binds_nothing_and_exits_zero() {
    let bind_port = support::free_local_port();
    let upstream_port = support::free_local_port();
    let cfg = cfg_yaml_with_bind(bind_port, upstream_port);

    let held = std::net::TcpListener::bind(("127.0.0.1", bind_port))
        .expect("hold the configured listener port for the duration of the test");

    let (mut child, dir) = support::spawn_binary(&cfg, "control");

    let (status, stderr) =
        support::wait_for_exit_capturing_stderr(&mut child, Duration::from_secs(5));
    assert_eq!(
        status.code(),
        Some(0),
        "control mode must exit 0 even with its configured port already held, which is only \
         possible if it never attempted to bind it"
    );
    assert!(
        !stderr.contains("runtime built"),
        "control mode must not build either runtime, but stderr contains a runtime-built line:\n{stderr}"
    );

    drop(held);
    let _ = std::fs::remove_dir_all(&dir); // it-allow: no-swallowed-error reason: best-effort test fixture cleanup; a leftover temp directory does not affect any assertion
}

/// 9. `proxy_mode_serves_like_run`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_mode_serves_like_run() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy_with_mode(&cfg_yaml(origin.addr.port()), "proxy");

    let mut client = connect(proxy.addr);
    send_hello(&mut client);
    let response = read_all(&mut client);
    assert_eq!(response, HELLO_RESPONSE);
    assert_eq!(origin.hits(), 1);

    proxy.shutdown();
    origin.stop().await;
}

/// 10. `large_body_is_byte_identical`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_body_is_byte_identical() {
    const FOUR_MIB: usize = 4 * 1024 * 1024;
    #[allow(
        clippy::integer_division,
        reason = "FOUR_MIB is an exact multiple of the 16-byte pattern by construction, so this \
                  divides evenly with no truncation"
    )]
    let repeats = FOUR_MIB / 16;
    let pattern: String = "0123456789abcdef".repeat(repeats);
    assert_eq!(pattern.len(), FOUR_MIB);
    let body: &'static str = Box::leak(pattern.into_boxed_str());

    let origin = support::Origin::start(body).await;
    let proxy = support::spawn_proxy(&cfg_yaml(origin.addr.port()));

    let mut client = connect(proxy.addr);
    send_hello(&mut client);
    let response = read_all(&mut client);

    let mut expected = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    expected.extend_from_slice(body.as_bytes());
    assert_eq!(response, expected);
    drop(client); // see sigterm_drains_cleanly_and_exits_zero's identical comment

    let status = proxy.shutdown();
    assert_eq!(status.code(), Some(0));
    origin.stop().await;
}

/// 11. `thousand_idle_connections_stay_under_the_budget` (Linux only): the D9 target
///     is 2 KiB per idle plaintext connection measured with no upstream; M1 holds a
///     second socket and an upstream connection per downstream connection, so 4 KiB
///     is the M1 bound.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn thousand_idle_connections_stay_under_the_budget() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml_with_max_connections(origin.addr.port(), 2_000));

    // Let the readiness probe's own connection settle before the baseline reading.
    std::thread::sleep(Duration::from_millis(200));
    let rss_before_kib = read_rss_kib(proxy.child.id());

    let mut held = Vec::with_capacity(1_000);
    for _ in 0..1_000 {
        held.push(connect(proxy.addr));
    }
    // Give the accept loop time to actually admit every connection.
    std::thread::sleep(Duration::from_secs(1));

    let rss_after_kib = read_rss_kib(proxy.child.id());
    let delta_kib = rss_after_kib.saturating_sub(rss_before_kib);
    assert!(
        delta_kib < 4 * 1024,
        "RSS delta {delta_kib} KiB exceeds the 4 MiB M1 bound for 1000 idle connections"
    );

    drop(held);

    // The process is still serving afterwards.
    let mut client = connect(proxy.addr);
    send_hello(&mut client);
    let response = read_all(&mut client);
    assert_eq!(response, HELLO_RESPONSE);

    proxy.shutdown();
    origin.stop().await;
}

/// Reads `VmRSS` (via `statm`'s resident-page count) for `pid`, in KiB.
///
/// `resident_pages * 4096`: the page size is not read from the system because there
/// is no dependency-free way to do it (`sysconf` needs `libc`, which this manifest's
/// closed dependency list does not include), and 4096 bytes is universal on the
/// `x86_64` and `aarch64` Linux hosts this test runs on.
/// `#[allow(clippy::expect_used)]`: test-support helper, not itself a `#[test]`
/// fn, so `clippy.toml`'s `allow-expect-in-tests` does not reach it. A failure
/// to read `/proc` here means the test cannot make its measurement at all, so
/// panicking is the correct outcome and is what the equivalent helper above
/// already does.
#[cfg(target_os = "linux")]
#[allow(clippy::expect_used, reason = "see the function doc comment above")]
fn read_rss_kib(pid: u32) -> u64 {
    let text =
        std::fs::read_to_string(format!("/proc/{pid}/statm")).expect("read /proc/<pid>/statm");
    let resident_pages: u64 = text
        .split_whitespace()
        .nth(1)
        .expect("statm has a resident field")
        .parse()
        .expect("resident field is a number");
    resident_pages * 4 // 4096 bytes/page / 1024 bytes/KiB == 4 KiB/page
}

/// 12. `counters_are_reported_at_shutdown`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn counters_are_reported_at_shutdown() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml(origin.addr.port()));

    for _ in 0..10 {
        let mut client = connect(proxy.addr);
        send_hello(&mut client);
        let response = read_all(&mut client);
        assert_eq!(response, HELLO_RESPONSE);
    }

    let (status, stderr) = proxy.shutdown_capturing_stderr();
    assert_eq!(status.code(), Some(0));

    let line = stderr
        .lines()
        .find(|l| l.contains("shutdown complete"))
        .unwrap_or_else(|| panic!("no \"shutdown complete\" line in stderr:\n{stderr}"));
    let accepted =
        field_value(line, "connections_accepted").expect("connections_accepted field present");
    let closed = field_value(line, "connections_closed").expect("connections_closed field present");
    assert!(accepted >= 10, "connections_accepted={accepted}");
    assert!(closed >= 10, "connections_closed={closed}");

    origin.stop().await;
}

/// Portable counterpart to `connection_cap_is_clamped_to_the_descriptor_budget`
/// (Linux only, below). That test is the only one that exercises the descriptor
/// budget's arithmetic against a real, lowered `RLIMIT_NOFILE`, but on every other
/// platform `read_nofile_soft_limit` returns `None` (there is no `/proc`), so
/// `effective_max` always equals the configured `max_connections`, unclamped. That
/// equality is exactly what makes the WIRING, independent of the clamp arithmetic,
/// assertable everywhere: `serve.rs` now logs `registry.stats().max` on the
/// "connection cap" line rather than the `effective_max` local variable, so this
/// line can only report what `ConnRegistry::new` was actually constructed with, not
/// a separately computed copy of the same number. A mutation that passes
/// `ConnRegistry::new` some other value than `effective_max` (a fixed constant, or
/// `loaded.doc.limits.max_connections` unclamped and not equal to the configured
/// value below) changes what this line reports without touching anything else this
/// test asserts, including `parse_nofile_soft_table` and
/// `clamp_max_connections_table` in `serve.rs`, which are pure and never see a real
/// `ConnRegistry` at all.
///
/// No origin needed: startup succeeds even with nothing listening on the upstream
/// port (edge case 1, also exercised by `dead_upstream_closes_the_connection_
/// without_hanging`), and this test only inspects the startup log, not forwarding.
#[test]
fn connection_cap_line_reflects_the_registry() {
    // Distinctive: far below any real host's descriptor budget (so it is never
    // itself clamped, on Linux or elsewhere), and far from the design's own worked
    // example of 10000/480 (test 14, below), so a mutation that substitutes one of
    // those numbers for this one is also caught here.
    const MAX_CONNECTIONS: u32 = 3;
    let dead_upstream_port = support::free_local_port();
    let proxy = support::spawn_proxy(&cfg_yaml_with_max_connections(
        dead_upstream_port,
        MAX_CONNECTIONS,
    ));

    let (status, stderr) = proxy.shutdown_capturing_stderr();
    assert_eq!(status.code(), Some(0));

    let line = stderr
        .lines()
        .find(|l| l.contains("connection cap"))
        .unwrap_or_else(|| panic!("no \"connection cap\" line in stderr:\n{stderr}"));
    let max_connections =
        field_value(line, "max_connections").expect("max_connections field present");
    assert_eq!(
        max_connections,
        u64::from(MAX_CONNECTIONS),
        "the connection-cap line must report what ConnRegistry was actually \
         constructed with"
    );
}

/// 14. `connection_cap_is_clamped_to_the_descriptor_budget` (Linux only): the
///     FD-exhaustion case the design corpus names, exercising the same clamp
///     `read_nofile_soft_limit`/`parse_nofile_soft` compute, this time against a
///     real, lowered `RLIMIT_NOFILE`.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_cap_is_clamped_to_the_descriptor_budget() {
    let origin = support::Origin::start("hello").await;
    let cfg = cfg_yaml_with_max_connections(origin.addr.port(), 10_000);
    let Some(proxy) = support::spawn_proxy_under_nofile_limit(&cfg, 1024) else {
        return; // sh or ulimit unavailable; nothing to assert
    };

    let mut client = connect(proxy.addr);
    send_hello(&mut client);
    let response = read_all(&mut client);
    assert_eq!(response, HELLO_RESPONSE);
    drop(client); // see sigterm_drains_cleanly_and_exits_zero's identical comment

    let (status, stderr) = proxy.shutdown_capturing_stderr();
    assert_eq!(status.code(), Some(0));
    assert!(
        stderr
            .lines()
            .any(|l| l.contains("WARN") && l.contains("10000") && l.contains("480")),
        "expected a WARN line naming both 10000 and 480 in stderr:\n{stderr}"
    );

    origin.stop().await;
}
