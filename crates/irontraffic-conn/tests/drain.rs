// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for the drain supervisor and the jitter helper, over a real
//! `ConnRegistry` and a real `ShutdownController`.
//!
//! Every test drives `supervise_with_trigger` with a trigger future that resolves
//! immediately to `Some(ShutdownSignal::Term)`, so the production drain body runs
//! without delivering a real signal (that path is covered separately by
//! `irontraffic-io`'s own signal tests).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use irontraffic_conn::{
    AcceptConfig, BoxFut, ConnGuard, ConnHandler, ConnRegistry, DrainConfig, accept_loop,
    jitter_before_close, supervise_with_trigger,
};
use irontraffic_io::{
    Phase, ShutdownController, ShutdownSignal, ShutdownToken, Spawner, TcpAcceptor, TcpTransport,
    sleep, with_timeout,
};
use irontraffic_time::{SystemTimeSource, TestTimeSource, TimeSource};
use proptest::prelude::*;

/// The trigger every test below uses: resolves immediately, so the drain body starts
/// without waiting on anything signal-related.
fn immediate_term() -> impl Future<Output = Option<ShutdownSignal>> + Send {
    std::future::ready(Some(ShutdownSignal::Term))
}

/// A `DrainConfig` with a 1ms poll interval, so a test drives seconds of production
/// timeout logic in milliseconds of real wall time. `graceful_timeout` and `jitter`
/// keep their (large) defaults; individual tests override whichever field their
/// scenario needs.
fn test_cfg() -> DrainConfig {
    DrainConfig {
        poll_interval: Duration::from_millis(1),
        ..DrainConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_with_no_connections_is_immediate() {
    let registry = ConnRegistry::new(8);
    let (controller, token) = ShutdownController::new();
    let time: Arc<dyn TimeSource> = Arc::new(TestTimeSource::new());

    let report = with_timeout(
        Duration::from_secs(2),
        supervise_with_trigger(
            controller,
            Arc::clone(&registry),
            time,
            test_cfg(),
            immediate_term(),
        ),
    )
    .await
    .expect("a drain with no live connections must return promptly");

    assert_eq!(report.killed, 0);
    assert!(!report.escalated);
    assert_eq!(token.phase(), Phase::Closing);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_waits_for_a_live_connection() {
    let registry = ConnRegistry::new(8);
    let guard = ConnRegistry::try_admit(&registry).expect("admits one guard");
    let (controller, token) = ShutdownController::new();
    let time: Arc<dyn TimeSource> = Arc::new(TestTimeSource::new());
    let spawner = Spawner::current().expect("a runtime drives this test");

    let handle = spawner.spawn(supervise_with_trigger(
        controller,
        Arc::clone(&registry),
        time,
        test_cfg(),
        immediate_term(),
    ));

    with_timeout(Duration::from_secs(1), async {
        while !token.is_draining() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("phase must reach Draining");

    // `supervise_with_trigger` must still be waiting on the live guard: the phase is
    // monotone and `begin_closing()` (which the function calls right before it
    // returns) would have moved it past `Draining`, so observing it still exactly
    // `Draining` after a real pause proves the supervisor has not returned yet
    // without racing `TaskHandle::join`, which would abort the task if dropped
    // mid-poll.
    sleep(Duration::from_millis(20)).await;
    assert_eq!(
        token.phase(),
        Phase::Draining,
        "supervise_with_trigger must still be waiting on the live guard after 20ms"
    );

    drop(guard);

    let report = with_timeout(Duration::from_secs(1), handle.join())
        .await
        .expect("supervise_with_trigger must return once the guard is dropped")
        .expect("the supervisor task must not panic");

    assert_eq!(report.killed, 0);
    assert_eq!(token.phase(), Phase::Closing);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_deadline_advances_to_closing() {
    let registry = ConnRegistry::new(8);
    let guard = ConnRegistry::try_admit(&registry).expect("admits one guard");
    let (controller, token) = ShutdownController::new();
    let time = Arc::new(TestTimeSource::new());
    let time_dyn: Arc<dyn TimeSource> = time.clone();
    // A zero poll interval collapses the post-Closing grace window (20 * poll
    // interval) to zero real and mock milliseconds, so this test can hold its guard
    // forever (as the scenario requires, to prove `killed == 1`) without needing a
    // second, separately-timed advance of the mock clock for that window as well as
    // the graceful deadline itself: the mock clock only ever moves when this test
    // calls `advance_ms`, so a nonzero grace window would wait on a clock that never
    // reaches it and the test would hang until its own outer timeout.
    let spawner = Spawner::current().expect("a runtime drives this test");
    let cfg = DrainConfig {
        graceful_timeout: Duration::from_millis(100),
        poll_interval: Duration::ZERO,
        ..DrainConfig::default()
    };

    let handle = spawner.spawn(supervise_with_trigger(
        controller,
        Arc::clone(&registry),
        time_dyn,
        cfg,
        immediate_term(),
    ));

    with_timeout(Duration::from_secs(1), async {
        while !token.is_draining() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("phase must reach Draining");

    time.advance_ms(101);

    let report = with_timeout(Duration::from_secs(1), handle.join())
        .await
        .expect("supervise_with_trigger must advance to Closing once the deadline passes")
        .expect("the supervisor task must not panic");

    assert_eq!(report.killed, 1);
    assert_eq!(token.phase(), Phase::Closing);

    drop(guard);
}

/// A connection handler whose future never completes: it holds both the real socket
/// and the registry guard for as long as the task lives, and never even looks at
/// `shutdown`. Used by `drain_terminates_with_a_real_peer_that_never_closes` below to
/// prove the drain deadline is real against a connection that never observes the
/// drain at all, not merely one a test held open with a bookkeeping guard and no
/// actual I/O behind it.
struct NeverClosingHandler;

impl ConnHandler<TcpTransport> for NeverClosingHandler {
    fn handle(
        &self,
        io: TcpTransport,
        _peer: SocketAddr,
        guard: ConnGuard,
        _shutdown: ShutdownToken,
    ) -> BoxFut {
        Box::pin(async move {
            let _io = io;
            let _guard = guard;
            std::future::pending::<()>().await;
        })
    }
}

// Not one of the 13 tests the issue names by number, but directly proving the
// property the "DRAIN MUST TERMINATE" directive asks for: a connection that never
// closes must not prevent shutdown past the deadline, demonstrated with a genuine TCP
// peer accepted through the real `accept_loop` (#17) rather than a `ConnGuard` a test
// holds by hand with no socket behind it. Uses a real `SystemTimeSource` (not a
// `TestTimeSource`) so the 50ms graceful window is genuine wall-clock elapsed time,
// not a clock this test drives itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_terminates_with_a_real_peer_that_never_closes() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = TcpAcceptor::from_std(listener).expect("register with reactor");

    let registry = ConnRegistry::new(8);
    let (controller, token) = ShutdownController::new();
    let spawner = Spawner::current().expect("a runtime drives this test");
    let time: Arc<dyn TimeSource> = Arc::new(SystemTimeSource::new());
    let handler = Arc::new(NeverClosingHandler);

    let _accept_handle = spawner.spawn(accept_loop(
        acceptor,
        Arc::clone(&registry),
        token.clone(),
        spawner.clone(),
        handler,
        Arc::clone(&time),
        AcceptConfig::default(),
    ));

    // A genuine peer: a real TCP client that connects and then does nothing else,
    // holding its half of the connection open for the rest of the test. Nothing on
    // either end ever closes this socket or drops its guard.
    let client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("client connects");

    with_timeout(Duration::from_secs(2), async {
        while registry.stats().current == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the real connection must be admitted through the real accept path");

    let cfg = DrainConfig {
        graceful_timeout: Duration::from_millis(50),
        jitter: Duration::from_secs(5),
        poll_interval: Duration::from_millis(1),
    };

    let report = with_timeout(
        Duration::from_secs(5),
        supervise_with_trigger(
            controller,
            Arc::clone(&registry),
            time,
            cfg,
            immediate_term(),
        ),
    )
    .await
    .expect(
        "supervise must return well within 5 real seconds even though the real peer \
         never closes and its handler never observes shutdown",
    );

    assert_eq!(
        report.killed, 1,
        "the one real, never-closing connection must be counted killed, not silently \
         waited on forever"
    );
    assert_eq!(token.phase(), Phase::Closing);

    drop(client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_released_after_closing_reports_zero_killed() {
    let registry = ConnRegistry::new(8);
    let guard = ConnRegistry::try_admit(&registry).expect("admits one guard");
    let (controller, token) = ShutdownController::new();
    let time = Arc::new(TestTimeSource::new());
    let time_dyn: Arc<dyn TimeSource> = time.clone();
    let spawner = Spawner::current().expect("a runtime drives this test");
    let cfg = DrainConfig {
        graceful_timeout: Duration::from_millis(100),
        ..test_cfg()
    };

    // Releases the guard the instant the phase reaches Closing, driven by
    // `ShutdownToken::closing()` rather than a poll, so the release happens well
    // inside step 10's bounded post-Closing wait.
    let release_token = token.clone();
    let release_handle = spawner.spawn(async move {
        release_token.closing().await;
        drop(guard);
    });

    let handle = spawner.spawn(supervise_with_trigger(
        controller,
        Arc::clone(&registry),
        time_dyn,
        cfg,
        immediate_term(),
    ));

    with_timeout(Duration::from_secs(1), async {
        while !token.is_draining() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("phase must reach Draining");

    time.advance_ms(101);

    let report = with_timeout(Duration::from_secs(1), handle.join())
        .await
        .expect("supervise_with_trigger must return once the guard releases")
        .expect("the supervisor task must not panic");

    assert_eq!(
        report.killed, 0,
        "the guard released during step 10's bounded wait, so nothing should be counted killed"
    );

    with_timeout(Duration::from_secs(1), release_handle.join())
        .await
        .expect("the release task must finish")
        .expect("the release task must not panic");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_graceful_timeout_escalates_immediately() {
    let registry = ConnRegistry::new(8);
    let guard = ConnRegistry::try_admit(&registry).expect("admits one guard");
    let (controller, token) = ShutdownController::new();
    let time: Arc<dyn TimeSource> = Arc::new(TestTimeSource::new());
    // See `drain_deadline_advances_to_closing` for why the grace window at step 10
    // needs a zero poll interval when nothing ever drops the held guard: with a mock
    // clock that only moves when this test moves it, a nonzero grace window would
    // wait on a deadline the clock never reaches.
    let cfg = DrainConfig {
        graceful_timeout: Duration::ZERO,
        poll_interval: Duration::ZERO,
        ..DrainConfig::default()
    };

    let _report = with_timeout(
        Duration::from_secs(2),
        supervise_with_trigger(
            controller,
            Arc::clone(&registry),
            time,
            cfg,
            immediate_term(),
        ),
    )
    .await
    .expect("a zero graceful timeout must return promptly");

    assert_eq!(token.phase(), Phase::Closing);
    drop(guard);
}

// Edge case 8a, tested directly with an extreme value: mutation testing cannot
// substitute saturating arithmetic for plain arithmetic (a bare `+` and a
// `saturating_mul` both produce the exact same result on every value a mutation
// test's own suite happens to exercise, so a mutant swapping one for the other is
// either caught by some completely unrelated assertion or not caught at all,
// never because THIS property was checked). `poll_interval: Duration::MAX` makes
// `clamp_ms(cfg.poll_interval)` return `CoarseMono::MAX_INTERVAL_MS`
// (about 1.07e9), and `.saturating_mul(20)` on that value overflows `u32`
// (about 2.1e10 does not fit); a plain `*` would panic in a debug build (this one)
// and wrap in release. The registry is empty here specifically so step 10's loop
// body, which contains the actual `sleep(cfg.poll_interval)` call, is never
// entered (`current > 0` is false on its first check): this test proves the
// arithmetic that BUILDS the deadline from an extreme `poll_interval` cannot
// panic, without ever asking tokio's timer to accept a `Duration::MAX` sleep,
// which is a separate concern this issue does not own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_interval_max_does_not_overflow_the_grace_deadline() {
    let registry = ConnRegistry::new(8);
    let (controller, token) = ShutdownController::new();
    let time: Arc<dyn TimeSource> = Arc::new(TestTimeSource::new());
    let cfg = DrainConfig {
        graceful_timeout: Duration::ZERO,
        jitter: Duration::from_secs(5),
        poll_interval: Duration::MAX,
    };

    let report = with_timeout(
        Duration::from_secs(2),
        supervise_with_trigger(
            controller,
            Arc::clone(&registry),
            time,
            cfg,
            immediate_term(),
        ),
    )
    .await
    .expect(
        "an extreme poll_interval must not panic while building the grace deadline, \
         and must not hang: the empty registry means step 10's loop body, which is \
         the only place that duration would actually be slept, is never entered",
    );

    assert_eq!(report.killed, 0);
    assert_eq!(token.phase(), Phase::Closing);
}

#[tokio::test]
async fn jitter_returns_immediately_when_closing() {
    let (controller, token) = ShutdownController::new();
    controller.begin_closing();
    let cfg = DrainConfig {
        jitter: Duration::from_secs(10),
        ..DrainConfig::default()
    };

    let start = std::time::Instant::now();
    jitter_before_close(&token, &cfg).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(50),
        "jitter_before_close must return immediately once the phase is Closing, took {elapsed:?}"
    );
}

#[tokio::test]
async fn jitter_zero_returns_immediately() {
    let (controller, token) = ShutdownController::new();
    controller.begin_drain();
    let cfg = DrainConfig {
        jitter: Duration::ZERO,
        ..DrainConfig::default()
    };

    let start = std::time::Instant::now();
    jitter_before_close(&token, &cfg).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(50),
        "jitter_before_close must return immediately when jitter is zero, took {elapsed:?}"
    );
}

#[tokio::test]
async fn jitter_delays_within_the_window() {
    let (controller, token) = ShutdownController::new();
    controller.begin_drain();
    let cfg = DrainConfig {
        jitter: Duration::from_millis(40),
        ..DrainConfig::default()
    };

    let mut delays = Vec::with_capacity(20);
    for _ in 0..20 {
        let start = std::time::Instant::now();
        jitter_before_close(&token, &cfg).await;
        delays.push(start.elapsed());
    }

    for d in &delays {
        assert!(
            *d < Duration::from_millis(200),
            "delay {d:?} exceeded the 200ms bound for a 40ms jitter window"
        );
    }

    let distinct = delays
        .iter()
        .map(Duration::as_millis)
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert!(
        distinct >= 2,
        "expected at least two distinct delays across 20 draws (a per-connection, \
         per-call draw), saw only {distinct} distinct value(s): {delays:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_report_elapsed_is_recorded() {
    let registry = ConnRegistry::new(8);
    let guard = ConnRegistry::try_admit(&registry).expect("admits one guard");
    let (controller, token) = ShutdownController::new();
    let time = Arc::new(TestTimeSource::new());
    let time_dyn: Arc<dyn TimeSource> = time.clone();
    let spawner = Spawner::current().expect("a runtime drives this test");

    let handle = spawner.spawn(supervise_with_trigger(
        controller,
        Arc::clone(&registry),
        time_dyn,
        test_cfg(),
        immediate_term(),
    ));

    with_timeout(Duration::from_secs(1), async {
        while !token.is_draining() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("phase must reach Draining");

    time.advance_ms(1234);
    drop(guard);

    let report = with_timeout(Duration::from_secs(1), handle.join())
        .await
        .expect("supervise_with_trigger must return once the guard is released")
        .expect("the supervisor task must not panic");

    assert!(
        report.elapsed_ms >= 1234,
        "elapsed_ms should reflect the 1234ms the mock clock advanced during the \
         drain, got {}",
        report.elapsed_ms
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn prop_jitter_is_in_range(jitter_ms in 0..=1000u32, draws in 1..=64usize) {
        // The exact expression `jitter_before_close` evaluates once it has decided
        // to draw a delay at all, called directly here `draws` times so the bound
        // is exercised over many draws rather than just one.
        for _ in 0..draws {
            let delay = irontraffic_runtime::core::with(|c| c.rand_bounded_u32(jitter_ms));
            if jitter_ms > 0 {
                prop_assert!(delay < jitter_ms);
            } else {
                // `rand_bounded_u32(0)` is a total function returning 0, which is
                // the value that makes `jitter_before_close` return immediately
                // (its own `max_ms == 0` check, reached before any draw at all).
                prop_assert_eq!(delay, 0);
            }
        }
    }
}

// drain_deadline_with_live_connections_logs_a_warning and
// drain_with_no_live_connections_logs_no_warning used to live here, along with a
// capture_async helper that captured tracing output via tracing::subscriber::set_default.
// Both proved the `if live > 0 { warn!(..) } else { info!(..) }` branch right after the
// drain loop actually depends on `live`, since none of the 13 named tests observes which
// line was logged, only the returned DrainReport, which is identical either way.
//
// They now live in their own file, tests/drain_logging.rs: every file under tests/
// compiles to its own binary with its own process, and tracing's per-callsite interest
// cache is a single process-global value, not one scoped to a thread or a test. Every
// other test in THIS file calls supervise_with_trigger too, which unconditionally hits
// the shared "drain starting" callsite (and, depending on the scenario, "drain complete"
// or "drain deadline reached"), with no subscriber installed at all. Whichever test's
// poll reached one of those callsites FIRST in the process decided, for the rest of the
// process, whether tracing considered it worth calling a subscriber about at all: if that
// first hit landed on a worker thread with no subscriber active (the common case for
// every test here except the two capturing ones), the callsite cached "never interested"
// for good, and rebuild_interest_cache() cannot rescue a callsite that has not registered
// yet when it runs. This raced the two capturing tests against every other test in this
// file for 13 to 14 failures in 200 runs (issue #621), each one the captured events
// coming back empty or missing "drain starting". Moved to its own process, the only code
// that ever touches those callsites there is the two capturing tests, and both always
// install a real subscriber before doing so, so the callsite can never be cached "never
// interested" from a bare context in the first place.
//
// THE RULE FOR FUTURE TESTS: a test that asserts on tracing output emitted by
// supervise_with_trigger or jitter_before_close does not belong in this file, because
// every other test here calls those functions with no subscriber installed and can win
// the registration race for a shared callsite. Give it its own file under tests/, the way
// tests/drain_logging.rs does.
