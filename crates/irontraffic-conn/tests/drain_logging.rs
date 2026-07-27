// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process-isolated tests of what `supervise_with_trigger` logs through `tracing`
//! (issue #621, a follow-up on #18).
//!
//! `drain_deadline_with_live_connections_logs_a_warning` and
//! `drain_with_no_live_connections_logs_no_warning`, below, each install their own
//! `tracing` subscriber and assert on the messages it captured. They used to live in
//! `tests/drain.rs` alongside every other drain test, which is exactly what made them
//! flaky: `tracing` caches, per callsite, whether any subscriber has ever been
//! interested in it, decided once, the first time that callsite fires anywhere in the
//! process, and left alone after that. The cache is a single value shared by every OS
//! thread in the binary, not one scoped to a thread or a test. Every other test in
//! `tests/drain.rs` calls `supervise_with_trigger` too, which unconditionally executes
//! `tracing::info!("drain starting")` and, depending on the scenario, either
//! `tracing::info!("drain complete; no connections remained")` or
//! `tracing::warn!(.., "drain deadline reached; closing remaining connections")`, and
//! none of those other tests installs a subscriber first. Whichever test's poll reached
//! one of those callsites FIRST in the process decided, for the rest of the process,
//! whether `tracing` would bother calling a subscriber about it at all: reached with no
//! subscriber active, a callsite's interest is cached "never", and the fast path a
//! caching layer exists for skips calling any subscriber's `event()` from then on,
//! including a subscriber a later test installs. `tracing::callsite::rebuild_interest_cache()`
//! can force a re-check, but only for a callsite already present in `tracing`'s global
//! registry: it cannot immunise a callsite whose first-ever hit in the process happens
//! later, on a worker thread with no subscriber installed, which is exactly the shape of
//! this race. Sharing a binary with tests that exercise the same callsites bare made this
//! two tests' outcome depend on scheduler interleaving: 13 to 14 failures in 200 runs
//! measured against the shared-binary version of this file, every one either an empty
//! captured-events list or one missing "drain starting".
//!
//! Every file under `tests/` compiles to its own binary with its own process, so moving
//! these two tests here removes the race at its root rather than papering over it: the
//! only code in THIS process that ever touches the "drain starting", "drain complete",
//! or "drain deadline reached" callsites is the two tests below, and both always install
//! a real subscriber, via `capture_async`, before doing anything that could reach them.
//! A callsite can only ever be cached "never interested" by a hit with no subscriber
//! active, and nothing in this process produces one, so the race this file exists to
//! avoid cannot occur here regardless of which of the two tests the harness happens to
//! run first or how their OS threads interleave.
//!
//! THE RULE FOR FUTURE TESTS: a test that asserts on `tracing` output emitted by
//! `supervise_with_trigger` or `jitter_before_close` belongs in this file, not in
//! `tests/drain.rs`, precisely because `tests/drain.rs` is full of tests that reach the
//! same callsites with no subscriber installed and would be free to win the
//! registration race for them.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use irontraffic_conn::{ConnRegistry, DrainConfig, supervise_with_trigger};
use irontraffic_io::{ShutdownController, ShutdownSignal, with_timeout};
use irontraffic_time::{TestTimeSource, TimeSource};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// The trigger every test below uses: resolves immediately, so the drain body starts
/// without waiting on anything signal-related. Identical to `tests/drain.rs`'s own
/// helper of the same name; duplicated rather than shared because this file is
/// deliberately its own compilation unit with no path back to `tests/drain.rs`.
fn immediate_term() -> impl Future<Output = Option<ShutdownSignal>> + Send {
    std::future::ready(Some(ShutdownSignal::Term))
}

/// A `DrainConfig` with a 1ms poll interval, so a test drives seconds of production
/// timeout logic in milliseconds of real wall time. Identical to `tests/drain.rs`'s own
/// helper of the same name, duplicated for the same reason as `immediate_term` above.
fn test_cfg() -> DrainConfig {
    DrainConfig {
        poll_interval: Duration::from_millis(1),
        ..DrainConfig::default()
    }
}

/// Captures `tracing` events emitted while `fut` runs and returns its output alongside
/// every captured event's formatted message.
///
/// Sets the subscriber with `tracing::subscriber::set_default` and holds the guard
/// across the `.await`, which is only sound because every test using this runs on a
/// single-threaded (default-flavor) `#[tokio::test]`: the default subscriber is
/// thread-local, and a current-thread runtime never migrates a task to another OS
/// thread between polls, so nothing here relies on the multi-thread flavor's
/// work-stealing behaviour.
async fn capture_async<T>(fut: impl std::future::Future<Output = T>) -> (T, Vec<String>) {
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
    // This is defense in depth, not the fix: see the module doc comment for why the
    // real guarantee is this file being its own process. `rebuild_interest_cache` can
    // only re-evaluate a callsite already present in tracing's global registry, so it
    // cannot protect a callsite whose first-ever hit in the process happens later on a
    // different thread with no subscriber installed (issue #621's diagnosis of why this
    // call alone, while these two tests still shared a binary with every other drain
    // test, was insufficient). Kept here in case a future test added to this file
    // forgets to install a subscriber before touching a shared callsite; it costs
    // nothing and narrows that mistake's blast radius rather than papering over it.
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
