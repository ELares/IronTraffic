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
use std::process::Child;
use std::time::Duration;

/// The request every test that does not care about its exact bytes sends.
const HELLO_REQUEST: &[u8] = b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n";

/// The response `cfg_yaml`'s origin produces for [`HELLO_REQUEST`], byte for byte.
const HELLO_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

/// A minimal valid configuration: one listener, one upstream, and short timeouts so
/// the tests that exercise deadlines and drains do not have to wait for the
/// production defaults (a five-minute graceful timeout, a one-minute idle deadline).
///
/// `reuseport: false`, unlike `listeners[].reuseport`'s own documented default of
/// `true`: issue #894 measured that the default lets a `free_local_port` collision (a
/// concurrent test's proxy drawing the exact same port before this one's child binds
/// it, issue #888's own measured 264-of-3000 repeat rate) succeed SILENTLY on both
/// sides, sharing one `SO_REUSEPORT` group with no `EADDRINUSE` for anything to
/// notice. `false` turns that same collision loud: the losing side's bind fails
/// outright, which `spawn_proxy_with_mode`'s own existing retry (draw a fresh port,
/// try again) already handles. See `two_children_on_one_port_collide_loudly` for a
/// direct demonstration of the mechanism this switches off.
fn cfg_yaml(upstream_port: u16) -> String {
    format!(
        "apiVersion: irontraffic.io/v1\n\
         listeners:\n\
         \x20\x20- name: web\n\
         \x20\x20\x20\x20bind: \"127.0.0.1:0\"\n\
         \x20\x20\x20\x20reuseport: false\n\
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
///
/// Deliberately does NOT set `reuseport: false` the way [`cfg_yaml`] now does: its
/// only caller, `control_mode_binds_nothing_and_exits_zero`, has its own doc comment
/// with a directly measured (20-of-20, both ways) claim about what flags a REGRESSED
/// bind attempt would carry if it incorrectly reached `ShardedListener::bind`, and
/// that measurement was made against THIS function's reuseport default (`true`).
/// Changing it here would leave that comment's specific numbers describing a
/// configuration this function no longer produces.
/// `two_children_on_one_port_collide_loudly`, the one test that wants
/// `reuseport: false` on an explicit bind port, does not go through this function:
/// it builds straight off [`cfg_yaml`] instead (see that test's own doc comment for
/// why), which both carries the real `reuseport: false` fixture line issue #894 item
/// 2 added and, unlike a third, parallel copy of this template would, actually breaks
/// if that line is ever removed.
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

/// Parses `<name>=<digits>` out of `line`, tolerant of whatever else the line
/// contains: a later field addition must not break this.
///
/// `support::strip_ansi` (see its own doc comment for why it exists) runs first:
/// `wait_for_bound_addr`, below, needs the same ANSI-tolerant field parsing to read
/// the `addr=` field out of a `"listener bound"` line, so that stripping now lives
/// once, in `support`, rather than as a second, drifting copy here.
fn field_value(line: &str, name: &str) -> Option<u64> {
    let plain = support::strip_ansi(line);
    let needle = format!("{name}=");
    let start = plain.find(&needle)? + needle.len();
    let rest = &plain[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..end)?.parse().ok()
}

/// Polls `tap`'s growing snapshot until a `"listener bound"` line names a concrete
/// address, up to `timeout`, and returns that address.
///
/// Exists so `two_children_on_one_port_collide_loudly` can point its second child at
/// exactly the port the kernel handed the first, discovered from the very log line
/// `support::wait_for_connect` already treats as this child's own proof of identity,
/// instead of drawing a second, independent port with `support::free_local_port` and
/// hoping the two coincide: on a host running other tests that are themselves
/// drawing and releasing ports concurrently, they can differ, and that mismatch would
/// be a false collision this test does not exist to prove. Returns `None`, never
/// panics, once `timeout` elapses with no such line: the caller states what was
/// actually missing.
fn wait_for_bound_addr(tap: &support::StderrTap, timeout: Duration) -> Option<SocketAddr> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let snapshot = tap.snapshot();
        if let Some(addr) = snapshot
            .lines()
            .find(|line| line.contains("listener bound"))
            .and_then(|line| support::field_str(line, "addr"))
            .and_then(|s| s.parse().ok())
        {
            return Some(addr);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Calls `attempt` until it returns anything other than a signal-interrupted read
/// (`ErrorKind::Interrupted`, `EINTR`), retrying immediately with no added delay.
///
/// `Read::read` on a raw `TcpStream` maps to one `recv(2)`: a signal delivered while
/// that call is blocked aborts it having transferred nothing at all, neither real
/// bytes nor an EOF determination, so the connection's true state is exactly what it
/// was the instant before the call, and retrying loses no information already
/// observed. This matters concretely in this suite: `connection_cap_rejects_the_
/// extra_connection` runs alongside other tests in the same process that fork and
/// reap child proxies (`spawn_binary`, `spawn_proxy_with_mode`), and a `SIGCHLD` from
/// any of them can land mid-`recv` on this test's own, unrelated read. A prior,
/// un-retried version of this test's read fed that `Interrupted` straight to
/// `still_open`, which does not match it, scoring a connection that was never
/// observed to close as "not open" instead: measured directly on Linux, every
/// failure of this test across a paired 120-run A/B took exactly this shape
/// (`first=Err(Interrupted)`), on both the pre- and post-#894 binary alike. A larger,
/// separate 1050-run repetition study reached the same conclusion from the other
/// direction: none of the three mechanisms issue #894's own Design section names
/// produced a single failure, while this one and one other, unrelated production
/// defect (a startup signal-handling gap, filed separately as issue #903 because it
/// is outside this file's reach) accounted for the entire 51-run residual. Retrying
/// asks the kernel again and reports whatever it actually says, rather than guessing
/// "open" or "closed" from a call that answered neither.
fn retry_on_eintr<T>(mut attempt: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    loop {
        match attempt() {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// Proves [`retry_on_eintr`]'s two claims deterministically, with no real socket or
/// signal involved: it retries exactly the leading run of `Interrupted` results, and
/// returns the first result that is not `Interrupted` verbatim, without retrying past
/// it.
///
/// This is the discriminating regression test for the fix: reverting
/// `retry_on_eintr`'s body to a single, un-retried `attempt()` call (the shape
/// `connection_cap_rejects_the_extra_connection`'s reads had before this issue) makes
/// `calls` read 1 instead of 3 and `outcome` read `Interrupted` instead of
/// `WouldBlock`, failing both assertions below.
#[test]
fn retry_on_eintr_retries_interrupted_and_returns_the_first_other_result() {
    let mut calls = 0_u32;
    let outcome = retry_on_eintr(|| -> std::io::Result<usize> {
        calls += 1;
        if calls <= 2 {
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }
    });
    assert_eq!(
        calls, 3,
        "must retry exactly the two Interrupted results, then stop"
    );
    assert!(
        matches!(&outcome, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "must return the first non-Interrupted result verbatim, got {outcome:?}"
    );
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
///
/// Deliberately does not also match `ErrorKind::Interrupted`: an `EINTR` proves
/// neither "open" nor "closed" (see [`retry_on_eintr`]'s doc comment for why), so
/// folding it into either classifier here would be a guess dressed as a fact. Every
/// caller of this function retries a read through `retry_on_eintr` first, which is
/// what actually keeps `Interrupted` from ever reaching it.
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
/// The other assertion is a COUNT for the same reason the test body itself does not
/// assert an identity (see its own comment on that below). Before issue #894,
/// `reuseport` defaulted to `true` and this listener ran one accept loop per worker,
/// racing a shared registry with only a `connect(2)` head start (then measured at a
/// median of about 70 microseconds) to order the two `try_admit` calls. Issue #894
/// turned `reuseport` off in `cfg_yaml` (see that function's own doc comment, for an
/// unrelated reason: a silent listen-port collision), which as a side effect also
/// collapsed this listener to a single accept loop. Whether that loop's own admission
/// order is now effectively deterministic has not been re-measured here, and this
/// test does not need an answer either way: asserting WHICH connection is admitted
/// would still assert something about admission order this test has no business
/// depending on. Asserting that exactly one of the two remains open does not.
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

    // WHICH connection the cap admits is NOT asserted, deliberately. See this test's
    // own module-level doc comment above for why: before issue #894 `reuseport`
    // defaulted to true, giving one accept loop per worker racing a shared registry;
    // #894 turned it off (an unrelated fix for a silent listen-port collision), which
    // collapsed this listener to a single accept loop. This test does not depend on
    // whether that single loop's admission order is now deterministic.
    //
    // A previous revision asserted identity anyway (under the old, reuseport-true
    // configuration) and simply relocated its own flake: when the second connection
    // won, the cap still refused exactly one, the counter still read 1, and the
    // identity assertion failed instead. Reproduced at 14 of 25 with the two connects
    // barrier-synchronised.
    //
    // The property that actually matters is a COUNT, not an identity: offered two
    // against `max_connections: 1`, the cap must admit exactly one and refuse exactly
    // one. Both assertions below are invariant either way.
    let mut buf_a = [0_u8; 16];
    let mut buf_b = [0_u8; 16];
    a.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("bound the first probe");
    b.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("bound the second probe");
    let ra = retry_on_eintr(|| a.read(&mut buf_a));
    let rb = retry_on_eintr(|| b.read(&mut buf_b));

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
    // sets before binding whenever the listener's own options and the platform's
    // capability probe both agree (`opts.reuse_port && caps.reuse_port`, and
    // separately `opts.reuse_addr && caps.reuse_addr`; true of THIS test's config,
    // `cfg_yaml_with_bind`, which leaves `reuseport` unset and so defaults to `true`,
    // unlike `cfg_yaml`'s explicit `false` since issue #894, on a Linux host, but not
    // universally, and specifically not for `cfg_yaml`'s own listener since #894),
    // gets `EADDRINUSE` against `dead_local_port`'s socket
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

/// 15. `wait_for_connect_rejects_a_foreign_listener`: issue #894, item 1.
///
/// `support::wait_for_connect` used to report ready the moment a bare TCP connect
/// succeeded, which is satisfied by ANY listener on that address, not only the child
/// it was polling for. This bound a real, measured flake: `free_local_port` releases
/// its port before the intended child ever binds it (issue #888's own measured
/// 264-of-3000 repeat rate on Linux), so a concurrent test's listener can occupy the
/// exact same address in that window, `wait_for_connect` reports ready against IT, and
/// a later, genuine connect then fails once that unrelated listener has gone away.
///
/// This test does not need a second real process to stand in for "some other test's
/// listener": a plain, in-process [`std::net::TcpListener`] is a real, working
/// listener that answers every connect, which is the only property `wait_for_connect`
/// used to check. Pairing it with an EMPTY source (never containing the `"listener
/// bound"` line the real production binary logs on a successful bind) proves the
/// connect succeeding is not enough on its own; pairing the SAME listener with a
/// source that DOES contain the line, naming this listener's OWN address, proves the
/// check is not simply, and uselessly, always false regardless of what it is given.
///
/// A third case, added alongside the address-scoping fix: a source whose `"listener
/// bound"` line names a DIFFERENT address must not satisfy this listener's check
/// either, even though the phrase itself is present. Before that fix,
/// `wait_for_connect` asked only whether the phrase occurred anywhere in the tap, so a
/// stale line left over from a since-exited child (a real shape: a config's other
/// listener, or a port later reused by an unrelated process, see `support::
/// wait_for_connect`'s own doc comment) could satisfy a caller polling for a
/// completely different address. This case is what actually catches that: reverting
/// the address match back to a bare `.contains("listener bound")` makes it pass
/// (wrongly) instead of failing.
#[test]
fn wait_for_connect_rejects_a_foreign_listener() {
    let foreign = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("wait_for_connect_rejects_a_foreign_listener: bind the foreign listener");
    let addr = foreign
        .local_addr()
        .expect("wait_for_connect_rejects_a_foreign_listener: read the foreign listener's address");

    // EOF on the very first read: its snapshot is always empty and can never contain
    // "listener bound". Stands in for a foreign listener's stderr, which never
    // contains this workspace's own log output at all.
    let silent = support::StderrTap::spawn(std::io::empty());
    let ready = support::wait_for_connect(addr, &silent, Duration::from_millis(300));
    assert!(
        !ready,
        "wait_for_connect must not report ready against a listener whose source never \
         logged \"listener bound\", even though a bare connect to it succeeds"
    );

    // The SAME listener, now paired with a source that DOES contain the line, naming
    // this exact address: this rules out the check being unconditionally false
    // regardless of what it is given, the failure mode a negative-only assertion could
    // otherwise hide.
    let talkative = support::StderrTap::spawn(std::io::Cursor::new(
        format!(
            "2026-01-01T00:00:00Z INFO irontraffic_conn::listener: listener bound listener=web \
             addr={addr} shards=1 reuseport=false"
        )
        .into_bytes(),
    ));
    let ready = support::wait_for_connect(addr, &talkative, Duration::from_millis(300));
    assert!(
        ready,
        "wait_for_connect must report ready once a connect succeeds and the given source's \
         snapshot contains a \"listener bound\" line naming this exact address"
    );

    // The SAME listener again, but this time the source's line names a DIFFERENT
    // address: the phrase is present, the connect still succeeds, but the address
    // does not match, so this must not report ready.
    let other_addr: SocketAddr = "127.0.0.1:1".parse().expect("parse a throwaway address");
    let wrong_address = support::StderrTap::spawn(std::io::Cursor::new(
        format!(
            "2026-01-01T00:00:00Z INFO irontraffic_conn::listener: listener bound listener=web \
             addr={other_addr} shards=1 reuseport=false"
        )
        .into_bytes(),
    ));
    let ready = support::wait_for_connect(addr, &wrong_address, Duration::from_millis(300));
    assert!(
        !ready,
        "wait_for_connect must not report ready when the source's \"listener bound\" line \
         names a different address ({other_addr}) than the one being polled ({addr})"
    );

    drop(foreign);
}

/// Kills and reaps the wrapped child on drop, including on an unwinding panic.
///
/// A raw [`std::process::Child`] from [`support::spawn_binary`] has no such
/// guarantee on its own: `Child`'s own `Drop` only closes its pipes, never sends a
/// signal. `two_children_on_one_port_collide_loudly` spawns two children outside
/// [`support::ProxyProcess`] (which does have exactly this guarantee, but only for a
/// child that reached it through `spawn_proxy_with_mode`'s own automatic port
/// discovery, incompatible with this test's need for two children pointed at the
/// identical, externally chosen port). Without this guard, a failing assertion in
/// that test would leak a live, listening `irontraffic` process holding a port open
/// indefinitely, which issue #894's own 300-consecutive-run acceptance loop would
/// hit on every single failure.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill(); // it-allow: no-swallowed-error reason: best-effort cleanup; a failed kill means the process already exited
        let _ = self.0.wait(); // it-allow: no-swallowed-error reason: reaps the process so it does not become a zombie
    }
}

/// 16. `two_children_on_one_port_collide_loudly`: issue #894, item 2.
///
/// With `reuseport: false` (see [`cfg_yaml`]'s own doc comment for why that fixture
/// line exists), a second child given the exact same listen port as a first,
/// already-serving child fails loudly with `EADDRINUSE` (`ExitCode::from(5)` in
/// `serve.rs`'s bind-failure path) rather than silently sharing the listener the way
/// the previous, `reuseport: true` default let it.
///
/// Builds its config from [`cfg_yaml`] itself, the same fixture every other test in
/// this file uses, rather than a third, parallel copy of the YAML template: a helper
/// that never reads `cfg_yaml`'s own `reuseport: false` line cannot notice if that
/// line is ever removed, which is exactly the gap an earlier revision of this test
/// had (deleting the line left the whole suite green, 15/15, because this test read a
/// different template). Child B's config is child A's own [`cfg_yaml`] output with
/// the bind placeholder substituted for child A's REAL, kernel-assigned port
/// (discovered from child A's own `"listener bound"` line via
/// [`wait_for_bound_addr`]), the identical substitution
/// `support::spawn_proxy_with_mode` performs for every other test.
///
/// Neither child draws a port with `support::free_local_port` first: child A binds
/// `127.0.0.1:0` directly, so there is no window between drawing a port and a real
/// listener holding it for a concurrent test to win. This closes a second,
/// independent flake this test used to have: with a drawn-and-released port, a
/// concurrent test's own listener could occupy it before child A bound, and this
/// test's un-retried spawn (unlike `spawn_proxy_with_mode`, which retries) would then
/// hard-fail on the very port race issue #894 exists to fix, rather than exercising
/// the collision this test is actually about.
///
/// No origin is needed: this test only proves the LISTEN side collides, never forwards
/// a real request, so a held [`support::dead_local_port`] stands in for the upstream
/// (same choice, and the same issue #888 reservation reasoning, as
/// `dead_upstream_closes_the_connection_without_hanging`).
#[test]
fn two_children_on_one_port_collide_loudly() {
    let upstream = support::dead_local_port();
    let cfg = cfg_yaml(upstream.port);

    let (raw_a, dir_a) = support::spawn_binary(&cfg, support::DEFAULT_SPAWN_MODE);
    let mut child_a = KillOnDrop(raw_a);
    let tap_a = support::StderrTap::spawn(
        child_a
            .0
            .stderr
            .take()
            .expect("two_children_on_one_port_collide_loudly: child A's stderr was piped"),
    );
    let addr = wait_for_bound_addr(&tap_a, Duration::from_secs(5)).unwrap_or_else(|| {
        panic!(
            "two_children_on_one_port_collide_loudly: child A never logged a \"listener \
             bound\" address within 5s"
        )
    });
    assert!(
        support::wait_for_connect(addr, &tap_a, Duration::from_secs(5)),
        "child A did not report itself listening on {addr} within 5s"
    );

    let cfg_b = cfg.replace("127.0.0.1:0", &format!("127.0.0.1:{}", addr.port()));
    let (raw_b, dir_b) = support::spawn_binary(&cfg_b, support::DEFAULT_SPAWN_MODE);
    let mut child_b = KillOnDrop(raw_b);
    let (status_b, stderr_b) =
        support::wait_for_exit_capturing_stderr(&mut child_b.0, Duration::from_secs(5));
    assert_eq!(
        status_b.code(),
        Some(5),
        "child B must exit with the bind-failure code (5) rather than serve; stderr:\n{stderr_b}"
    );
    assert!(
        stderr_b.to_lowercase().contains("already in use"),
        "expected an \"already in use\" bind failure in child B's stderr, got:\n{stderr_b}"
    );

    // Child A is unaffected by child B's failed attempt: a fresh connect to it still
    // succeeds, proving the FIRST child, not some shared or confused state, is what is
    // actually still listening.
    assert!(
        std::net::TcpStream::connect(addr).is_ok(),
        "child A must still be accepting connections after child B's failed bind"
    );

    drop(child_a);
    drop(child_b);
    let _ = std::fs::remove_dir_all(&dir_a); // it-allow: no-swallowed-error reason: best-effort test fixture cleanup; a leftover temp directory does not affect any assertion
    let _ = std::fs::remove_dir_all(&dir_b); // it-allow: no-swallowed-error reason: best-effort test fixture cleanup; a leftover temp directory does not affect any assertion
}
