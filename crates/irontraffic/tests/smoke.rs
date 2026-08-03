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
#[allow(
    dead_code,
    reason = "used only by the control-mode test, which is gated on the control-plane feature"
)]
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
///
/// Switching to `dead_local_port` changed WHICH bounded failure this test measures on
/// macOS, and that is worth being explicit about rather than leaving it to surprise the
/// next reader. `free_local_port`'s unheld port used to give an instant `ECONNREFUSED`
/// on every platform (nothing was listening). `dead_local_port`'s held,
/// bound-but-never-listened socket gives that same instant refusal on Linux, but on
/// macOS (a BSD-derived stack, no listen queue to reset a `SYN` against) it silently
/// drops the `SYN` instead, so the proxy's dial now runs its full `connect_ms: 2000`
/// budget and fails with a timeout rather than a refusal.
///
/// Measured directly on this host, 5 runs at `--test-threads=4`, all green: this test
/// alone went from sub-millisecond to 4.3 to 5.2 s per run. The static headroom against
/// `connect`'s own 10 s read timeout below also dropped, from roughly four orders of
/// magnitude (an instant refusal against a 10 s bound) to 5x (`connect_ms: 2000`'s own
/// worst case against the same 10 s bound): a slower macOS host, or a config that
/// raised `connect_ms`, could in principle close that gap in a way it never could
/// before this change.
///
/// ACCEPTED: nothing here fails (5/5 runs green, full smoke binary 3/3 green), the cost
/// is confined to macOS, and Linux, the platform issue #888 is actually about, is
/// unaffected (an unlistened bind still refuses instantly there). A future config that
/// pushes `connect_ms` close to 10 s would be the thing to revisit this decision for.
#[test]
fn dead_upstream_closes_the_connection_without_hanging() {
    // Held for the whole test body, not merely observed: `free_local_port` releases
    // its port immediately, and on Linux a released ephemeral port can be re-issued
    // to a concurrent test's proxy before this test's assertions run (issue #888).
    // On macOS this same hold is also why THIS particular connect attempt below now
    // takes up to `connect_ms: 2000` instead of failing instantly: see the doc comment
    // above.
    let dead = support::dead_local_port();
    let proxy = support::spawn_proxy(&cfg_yaml(dead.port));

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

/// `support::dead_local_port` proves both properties its own doc comment claims:
/// nothing ever answers a connect to the held port, and the port is unavailable to
/// any other bind for as long as the guard is alive.
///
/// The connect side is intentionally tolerant of which of two legitimate kernel
/// behaviors it observes, unlike the doc comment's Linux-specific `ECONNREFUSED`
/// claim: measured directly on this host (a bound-but-never-listened socket),
/// Linux's kernel resets an inbound `SYN` immediately, giving `ConnectionRefused`,
/// while a BSD-derived stack (macOS's, confirmed here) has no listen queue to reset
/// against and silently drops the `SYN`, giving `TimedOut` once the caller's own
/// bounded `connect_timeout` gives up. Both are the same "genuinely dead, not merely
/// slow" fact this function needs to prove; only a real accept, or a hang past the
/// bound, would be a genuine failure.
///
/// The reservation side is checked by attempting an explicit bind to the exact held
/// port rather than by repeatedly calling `bind(0)` and hoping never to observe it:
/// an explicit bind failing with `AddrInUse` is a direct, deterministic proof that
/// the port is occupied, which structurally implies an ephemeral `bind(0)` (which
/// only ever offers an unoccupied port) can never be handed it either, whereas a
/// bounded number of `bind(0)` probes could only ever raise confidence, never prove
/// it (issue #888).
#[test]
fn dead_local_port_refuses_connects_and_stays_reserved() {
    let dead = support::dead_local_port();

    let addr = SocketAddr::from(([127, 0, 0, 1], dead.port));
    let connect_result = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500));
    let connect_err =
        connect_result.expect_err("a bound-but-never-listened port must never accept a connect");
    assert!(
        matches!(
            connect_err.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
        ),
        "expected ECONNREFUSED (Linux) or a bounded TimedOut (BSD/macOS, no listen queue to \
         reset against) connecting to a held dead port, got {connect_err:?}"
    );

    let rebind_result = std::net::TcpListener::bind(("127.0.0.1", dead.port));
    let rebind_err =
        rebind_result.expect_err("a port held by dead_local_port must reject a second bind");
    assert_eq!(
        rebind_err.kind(),
        std::io::ErrorKind::AddrInUse,
        "expected EADDRINUSE re-binding a held dead port, got {rebind_err:?}"
    );
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
/// TWO COUNTS DECIDE THIS TEST, AND NEITHER DEPENDS ON WHICH CONNECTION WINS.
///
/// This test used to turn on a wall-clock bound: read the over-cap connection with a
/// 1 second timeout and treat `Ok(0)` as proof the cap rejected it. That was flaky
/// (see #710) and, worse, it was unsound for a reason the bound's own comment got
/// wrong. It justified 1 second as "far under `half_close_ms: 5000`", but the same
/// config also sets `connect_ms: 2000`, and an upstream dial failure drops the client
/// and closes the DOWNSTREAM connection (`serve.rs`, "client is dropped here"). So a
/// connection that was ADMITTED, never rejected, can produce exactly the same `Ok(0)`
/// in about 100 microseconds. The real ceiling was `min(connect_ms, idle_ms,
/// half_close_ms)`, not `half_close_ms`, and any bound is arguing about which of
/// three deadlines fires first.
///
/// `connections_rejected` removes the argument. `accept.rs` bumps that counter at the
/// single site that refuses an over-cap connection, and `serve.rs` prints it on the
/// "shutdown complete" line, so asserting it observes THE CAP ITSELF rather than how
/// fast a byte arrives. It cannot be satisfied by a different mechanism that happens
/// to close the socket, which a latency bound can. It is not unconditionally immune
/// either: a connection still queued when the drain begins is never accepted, so it is
/// never counted. That window is far longer than anything here, but the honest claim is
/// the narrow one, not "a counter cannot flake". It cannot be satisfied by a
/// different mechanism that happens to close the socket. The same file already does
/// this for `connections_accepted` and `connections_closed`.
///
/// What makes it discriminating: with `ConnRegistry::new` given some value other than
/// `effective_max` (say a fixed `10_000`), nothing is ever refused, so BOTH connections
/// are admitted. The open count is then 2 and the first assertion fails, deterministically
/// and for the right reason. The rejected count would also be 0, and it is asserted
/// second as an independent guard on the same property from the other side. Stating the
/// order plainly because earlier revisions of this test claimed an assertion decided
/// when it was never reached.
///
/// Reaching it is a real constraint, not a given. Every bound here must stay far under
/// `idle_ms: 5000`, because a broken cap admits BOTH connections and leaves them idle,
/// so any long wait lets the idle deadline close both and trip an earlier assertion
/// instead. There is a LOWER bound too, which an earlier draft of this comment denied:
/// `open_count` is computed from `still_open`, which reports a read that TIMED OUT, so
/// the bound must also exceed the time for the accept loop to refuse and drop the
/// over-cap socket. Measured at 0.00 to 0.29ms against a 200ms budget, so the headroom
/// is about three orders of magnitude, but the constraint is two-sided and saying only
/// "keep it small" would mislead the next person.
///
/// The other assertion is a COUNT for the same reason. Nothing orders the two
/// `try_admit` calls: `reuseport` gives one accept loop per worker racing a shared
/// registry, and the only tiebreak is a roughly 70 microsecond `connect(2)` head
/// start, which is precisely what load takes away. Asserting WHICH connection is
/// admitted asserts the outcome of that race. Asserting that exactly one of them
/// remains open does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_cap_rejects_the_extra_connection() {
    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml_with_max_connections(origin.addr.port(), 1));

    // `spawn_proxy`'s own readiness probe opens and immediately closes one
    // connection to confirm the listener answers; give the proxy a moment to finish
    // releasing that connection's slot before this test relies on the cap starting
    // from exactly zero.
    std::thread::sleep(Duration::from_millis(200));

    let mut a = connect(proxy.addr);
    let mut b = connect(proxy.addr);

    // WHICH connection the cap admits is NOT asserted, deliberately. `reuseport` is
    // on and the listener runs one accept loop per worker, so N threads race a single
    // shared registry and nothing orders the two `try_admit` calls except the head
    // start of one `connect(2)`, measured at a median of about 70 microseconds. Under
    // load that head start is exactly what gets lost, so a test that names one of them
    // as the admitted connection is asserting the outcome of a race.
    //
    // A previous revision did exactly that and simply relocated its own flake: when
    // the second connection won, the cap still refused exactly one, the counter still
    // read 1, and the identity assertion failed instead. Reproduced at 14 of 25 with
    // the two connects barrier-synchronised.
    //
    // The property that actually matters is a COUNT, not an identity: offered two
    // against `max_connections: 1`, the cap must admit exactly one and refuse exactly
    // one. Both assertions below are invariant under the race.
    let mut buf_a = [0_u8; 16];
    let mut buf_b = [0_u8; 16];
    a.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("bound the first probe");
    b.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("bound the second probe");
    let ra = a.read(&mut buf_a);
    let rb = b.read(&mut buf_b);

    // Exactly one of the two must still be open. `still_open` reports a read that
    // TIMED OUT, so "open" is the timeout case and "refused" is a real `Ok(0)`.
    let open_count = usize::from(still_open(&ra)) + usize::from(still_open(&rb));
    assert_eq!(
        open_count, 1,
        "exactly one of the two connections must remain admitted, got {open_count} \
         (first={ra:?}, second={rb:?})"
    );

    drop(a);
    drop(b);

    let (status, stderr) = proxy.shutdown_capturing_stderr();
    assert_eq!(status.code(), Some(0));
    let line = stderr
        .lines()
        .find(|l| l.contains("shutdown complete"))
        .unwrap_or_else(|| panic!("no \"shutdown complete\" line in stderr:\n{stderr}"));

    // THE SECOND, INDEPENDENT GUARD, not the one that fires under the cap mutation.
    // It is reached only when `open_count` is 1, which is precisely the vacuity case:
    // a broken cap whose admitted connection died of some unrelated cause. Verified to
    // catch exactly that. `accept.rs` bumps this at the single site that refuses
    // an over-cap connection, so it observes the cap itself rather than how fast a
    // byte arrives. `== 1` rather than `>= 1`: a cap that refuses EVERYTHING, including
    // the connection that fits, would satisfy `>= 1` while being just as broken as one
    // that refuses nothing.
    let rejected =
        field_value(line, "connections_rejected").expect("connections_rejected field present");
    assert_eq!(
        rejected, 1,
        "exactly one over-cap connection must be refused, got connections_rejected={rejected} in:\n{line}"
    );

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
#[cfg(feature = "control-plane")]
#[test]
fn control_mode_binds_nothing_and_exits_zero() {
    // Both ports must stay held for the whole test body, not merely observed:
    // `free_local_port` releases its port immediately, and a released port can be
    // re-issued elsewhere in the process while this test is still running (issue
    // #888). `bind` doubles as the "collide with control's own bind attempt" listener
    // the doc comment above describes, and the reason that works is narrower than an
    // earlier version of this comment claimed: listen state is NOT irrelevant to a
    // competing `bind(2)` in general, on Linux.
    //
    // Measured directly on Linux 6.8 (20 trials each, raw socket probes against the
    // real option sets involved): a challenger that sets `SO_REUSEADDR` and
    // `SO_REUSEPORT`, which is what `irontraffic-io/src/sys/mod.rs`'s `bind_listener`
    // always sets before binding, gets `EADDRINUSE` against `dead_local_port`'s socket
    // (which sets neither flag, see its own doc comment) whether or not that socket is
    // listening: bind only, 20/20 refused; bind and listen, 20/20 refused. So `bind`
    // above needs no separate re-bind call. But give that SAME incumbent socket
    // `SO_REUSEADDR` instead (still not listening) and the identical challenger bind
    // now SUCCEEDS 20/20; give it `SO_REUSEPORT` alone instead (still not listening)
    // and it succeeds 20/20 too. Listen state only stopped mattering above because
    // `dead_local_port` sets neither flag; it is not a general property of a bound
    // socket. Adding `SO_REUSEADDR` or `SO_REUSEPORT` to `dead_local_port` would
    // silently let a control-mode regression's bind through this exact test on Linux.
    // `upstream` is never dialed by control mode; it is held only so nothing else in
    // the process can be handed the port while this test's config still names it.
    let bind = support::dead_local_port();
    let upstream = support::dead_local_port();
    let cfg = cfg_yaml_with_bind(bind.port, upstream.port);

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

    drop(bind);
    drop(upstream);
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
///
/// On macOS specifically, holding the dead upstream with `dead_local_port` (see that
/// test's identical doc comment for the mechanism) means `spawn_proxy`'s own readiness
/// probe now leaves one dial to this dead upstream in flight when `shutdown_capturing_
/// stderr` sends SIGTERM immediately after. Measured directly on this host, 9 runs at
/// `--test-threads=4`, all green: this test alone went from sub-millisecond to
/// consistently just over 2 s per run (`elapsed_ms` 1994 to 2056, read from the
/// "shutdown complete" line itself, against this config's `graceful_timeout_ms: 2000`),
/// because the drain's own deadline and the dial's `connect_ms: 2000` timeout are
/// racing on the same clock. That race lands close enough to call either way: 2 of the
/// 9 runs logged `irontraffic-conn/src/drain.rs`'s "drain deadline reached" WARN, the
/// other 7 finished (`drain complete; no connections remained`) a handful of
/// milliseconds before that check next ran. `killed=0` and `escalated=false` in all 9
/// either way. ACCEPTED for the same reason as `dead_upstream_closes_the_connection_
/// without_hanging`: nothing here fails, because `drain.rs` grants a further
/// `poll_interval * 20` (50 ms * 20 = 1000 ms, read directly from that file, not
/// assumed) past the graceful deadline before reporting `killed`, which is comfortably
/// more than the handful of milliseconds the WARN runs overran by; and Linux, where
/// this test's failure mode (issue #888) actually lives, is unaffected (an unlistened
/// bind still refuses instantly there, so no dial is ever left in flight). This test
/// does not assert on timing or on the shutdown log's `killed`/`escalated` fields, only
/// on `max_connections`, so the added latency changes this test's wall-clock cost but
/// not what it proves.
#[test]
fn connection_cap_line_reflects_the_registry() {
    // Distinctive: far below any real host's descriptor budget (so it is never
    // itself clamped, on Linux or elsewhere), and far from the design's own worked
    // example of 10000/480 (test 14, below), so a mutation that substitutes one of
    // those numbers for this one is also caught here.
    const MAX_CONNECTIONS: u32 = 3;
    // Held for the whole test body, not merely observed: see
    // `dead_upstream_closes_the_connection_without_hanging`'s identical comment
    // (issue #888).
    let dead = support::dead_local_port();
    let proxy = support::spawn_proxy(&cfg_yaml_with_max_connections(dead.port, MAX_CONNECTIONS));

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
