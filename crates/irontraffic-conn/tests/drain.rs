// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for the drain supervisor and the jitter helper, over a real
//! `ConnRegistry` and a real `ShutdownController`.
//!
//! Every test drives `supervise_with_trigger` with a trigger future that resolves
//! immediately to `Some(ShutdownSignal::Term)`, so the production drain body runs
//! without delivering a real signal (that path is covered separately by
//! `irontraffic-io`'s own signal tests).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use irontraffic_conn::{ConnRegistry, DrainConfig, jitter_before_close, supervise_with_trigger};
use irontraffic_io::{Phase, ShutdownController, ShutdownSignal, Spawner, sleep, with_timeout};
use irontraffic_time::{TestTimeSource, TimeSource};
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

/// Captures `tracing` events emitted while `fut` runs and returns its output alongside
/// every captured event's formatted message. Not one of the 13 tests the issue names.
///
/// Mutation testing (`cargo mutants -j 1`) found that the `if live > 0 { warn!(..) }
/// else { info!(..) }` branch right after the drain loop can have its comparison
/// flipped to `==`, `<`, or `>=` without any of the 13 named tests failing: none of
/// them observes which line was actually logged, only the returned `DrainReport`,
/// which is identical either way. The two tests below reuse the exact `Subscriber`
/// capture technique already reviewed and merged in `irontraffic-runtime`'s
/// `startup_log_tests` (`crates/irontraffic-runtime/src/plane.rs`) and in this crate's
/// own `fallback_warning` module (`tests/sharded_bind.rs`) to pin which line depends
/// on which value of `live`.
///
/// Sets the subscriber with `tracing::subscriber::set_default` and holds the guard
/// across the `.await`, which is only sound because every test using this runs on a
/// single-threaded (default-flavor) `#[tokio::test]`: the default subscriber is
/// thread-local, and a current-thread runtime never migrates a task to another OS
/// thread between polls, so nothing here relies on the multi-thread flavor's
/// work-stealing behaviour.
async fn capture_async<T>(fut: impl std::future::Future<Output = T>) -> (T, Vec<String>) {
    use std::sync::Mutex;

    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    struct MessageVisitor<'a>(&'a mut String);

    impl Visit for MessageVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                *self.0 = format!("{value:?}");
            }
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "message" {
                value.clone_into(self.0);
            }
        }
    }

    struct Collector(Arc<Mutex<Vec<String>>>);

    impl Subscriber for Collector {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut message = String::new();
            event.record(&mut MessageVisitor(&mut message));
            if let Ok(mut events) = self.0.lock() {
                events.push(message);
            }
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let collector = Collector(Arc::clone(&events));
    let guard = tracing::subscriber::set_default(collector);
    // `tracing` caches, per callsite, whether any subscriber has ever been interested
    // in it, the first time that callsite fires. Another test in this same binary may
    // already have logged "drain starting" or "drain complete" with no subscriber
    // installed at all, caching "never interested" for that line for the rest of the
    // process; without this call the events below could be silently skipped
    // regardless of `Collector::enabled` always returning `true`. Rebuilding here,
    // with `collector` as the active default, forces every callsite this scope
    // reaches to be re-evaluated against it.
    tracing::callsite::rebuild_interest_cache();
    let result = fut.await;
    drop(guard);

    let messages = match events.lock() {
        Ok(g) => g.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    (result, messages)
}

#[tokio::test]
async fn drain_deadline_with_live_connections_logs_a_warning() {
    let registry = ConnRegistry::new(8);
    let guard = ConnRegistry::try_admit(&registry).expect("admits one guard");
    let (controller, _token) = ShutdownController::new();
    let time: Arc<dyn TimeSource> = Arc::new(TestTimeSource::new());
    // Both durations zero: the graceful deadline is reached on the very first check
    // (a deadline equal to `started` is already `reached`), and a zero poll interval
    // collapses step 10's post-Closing grace window to zero too, so this resolves
    // without spawning a task or advancing any clock, with the guard held throughout.
    let cfg = DrainConfig {
        graceful_timeout: Duration::ZERO,
        poll_interval: Duration::ZERO,
        ..DrainConfig::default()
    };

    let (report, messages) = with_timeout(
        Duration::from_secs(2),
        capture_async(supervise_with_trigger(
            controller,
            Arc::clone(&registry),
            time,
            cfg,
            immediate_term(),
        )),
    )
    .await
    .expect("a zero graceful timeout and a zero poll interval must return promptly");

    assert_eq!(report.killed, 1, "the guard was never dropped");
    assert!(
        messages
            .iter()
            .any(|m| m.contains("drain deadline reached")),
        "expected the deadline-reached warning when a connection was still live, got: {messages:?}"
    );
    assert!(
        !messages
            .iter()
            .any(|m| m.contains("drain complete; no connections remained")),
        "the clean-drain message must not fire when a connection was still live, got: {messages:?}"
    );

    drop(guard);
}

#[tokio::test]
async fn drain_with_no_live_connections_logs_no_warning() {
    let registry = ConnRegistry::new(8);
    let (controller, _token) = ShutdownController::new();
    let time: Arc<dyn TimeSource> = Arc::new(TestTimeSource::new());

    let (report, messages) = with_timeout(
        Duration::from_secs(2),
        capture_async(supervise_with_trigger(
            controller,
            Arc::clone(&registry),
            time,
            test_cfg(),
            immediate_term(),
        )),
    )
    .await
    .expect("a drain with no live connections must return promptly");

    assert_eq!(report.killed, 0);
    assert!(
        messages
            .iter()
            .any(|m| m.contains("drain complete; no connections remained")),
        "expected the clean-drain message when nothing was live, got: {messages:?}"
    );
    assert!(
        !messages
            .iter()
            .any(|m| m.contains("drain deadline reached")),
        "the deadline-reached warning must not fire when nothing was live, got: {messages:?}"
    );
}
