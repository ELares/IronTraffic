// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process-isolated test that a second real shutdown signal genuinely escalates a
//! drain (issue #622, a follow-up review finding on #18).
//!
//! `DrainReport::escalated` was never asserted `true` by any test: the whole
//! second-signal escalation path could be deleted with the rest of the suite green.
//! Issue #18's own prescribed recipe for testing it ("hold one guard, let the drain
//! start, then call `controller.begin_closing()` from the test thread: step 6c reads
//! the phase and breaks with `escalated == true`") cannot actually be written, because
//! `ShutdownController` is deliberately not `Clone` (see the doc comment on it in
//! `crates/irontraffic-io/src/shutdown.rs`: "exactly one thing in the process may
//! advance the phase, and making that structurally true is cheaper than documenting
//! it") and is moved by value into `supervise`/`supervise_with_trigger`. A test cannot
//! hold a second handle able to call `begin_closing()` while the one and only
//! `ShutdownController` is owned by the running supervisor. That is a genuine
//! contradiction between the issue text and the API the same issue specifies, which per
//! `AGENTS.md` rule 1 should have been raised rather than resolved by silently dropping
//! the coverage; #622 is that report, filed after the fact by an independent review.
//!
//! Rather than the impossible step-6c recipe, this test drives the OTHER escalation
//! path: step 6d, a second real signal observed by `sleep_or_signal` while the drain
//! loop is polling. It calls `supervise` (the real production entry point, not
//! `supervise_with_trigger`), so `next_shutdown_signal` and `sleep_or_signal` are the
//! genuine implementations end to end, and sends two real `SIGTERM`s with `kill`,
//! exactly the pattern already reviewed and merged for `irontraffic-io`'s own
//! `next_shutdown_signal_observes_sigterm` and `sleep_or_signal_observes_a_real_signal`
//! (`crates/irontraffic-io/tests/signal.rs`).
//!
//! It lives in its own file for the same reason `tests/drain_logging.rs` does: a real
//! signal is delivered to the whole process, not to a single task, so nothing else
//! running concurrently in this binary may have a live `tokio::signal::unix::signal`
//! registration when either `kill` below runs, or it could observe (or steal) a
//! notification meant for this test. None of the other tests in `tests/drain.rs` or
//! `tests/drain_logging.rs` ever calls `supervise`, `next_shutdown_signal`, or
//! `sleep_or_signal` (they all drive `supervise_with_trigger` with a stub trigger that
//! never touches a real signal), so today nothing races this test either way; giving it
//! its own process makes that guaranteed by the OS instead of by an audit of every
//! other test whenever one is added.

use std::sync::Arc;
use std::time::Duration;

use irontraffic_conn::{ConnRegistry, DrainConfig, supervise};
use irontraffic_io::{Phase, ShutdownController, Spawner, with_timeout};
use irontraffic_time::{SystemTimeSource, TimeSource};

// `#[cfg(unix)]`: sends a real SIGTERM to this process, exactly like
// `irontraffic-io`'s own real-signal tests. macOS and Linux both count as unix for
// cfg purposes and both accept `kill -TERM`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_real_signal_escalates_the_drain() {
    let registry = ConnRegistry::new(8);
    // A live guard: without one, the loop's own `current == 0` check would break it
    // before a second signal has any chance to be observed, and the property under
    // test (does a second real signal reach and escalate the loop) would be untested
    // by construction, passing for the same reason a graceful, on-time drain would.
    // Held only until the first signal has demonstrably moved the loop past that
    // check (see the comment above the second `kill` below); it is then dropped
    // immediately, well before the second signal is sent, because nothing from here
    // on depends on a live connection and holding it longer would only make step
    // 10's post-`Closing` grace wait, sized off `poll_interval`, do real work for no
    // reason.
    let guard = ConnRegistry::try_admit(&registry).expect("admits one guard");
    let (controller, token) = ShutdownController::new();
    let time: Arc<dyn TimeSource> = Arc::new(SystemTimeSource::new());
    let spawner = Spawner::current().expect("a runtime drives this test");
    // A graceful deadline far longer than this test's own real time budget, so the
    // only way `supervise` can return quickly is escalation, not the deadline. A
    // poll interval of 300ms is wide enough that the two `kill`s below, spaced
    // 100ms+ apart, cannot land in the brief gap between one `sleep_or_signal` call
    // ending and the next beginning that `drain.rs`'s module documentation
    // describes as the one place a second signal can genuinely be missed, while
    // staying short enough that step 10's post-`Closing` grace wait (up to 20 *
    // `poll_interval`) cannot itself make a passing run slow.
    let cfg = DrainConfig {
        graceful_timeout: Duration::from_secs(120),
        jitter: Duration::from_secs(5),
        poll_interval: Duration::from_millis(300),
    };

    let handle = spawner.spawn(supervise(controller, Arc::clone(&registry), time, cfg));

    // Give the spawned task time to reach `next_shutdown_signal` and install its
    // handlers before the first signal is sent, the same convention already reviewed
    // and merged in `next_shutdown_signal_observes_sigterm`.
    tokio::time::sleep(Duration::from_millis(100)).await;

    if let Ok(status) = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(std::process::id().to_string())
        .status()
    {
        assert!(
            status.success(),
            "the first kill command itself must succeed for this test to mean anything"
        );

        with_timeout(Duration::from_secs(2), async {
            while !token.is_draining() {
                irontraffic_io::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the first signal must start the drain");

        // Give the loop time to run past its `current == 0` / deadline / phase
        // checks and re-enter `sleep_or_signal` with a fresh registration, after
        // the first `next_shutdown_signal` call (the one that received the first
        // signal) returns and drops its handlers, so the second `kill` below lands
        // inside the loop's listening window rather than the gap between the two
        // registrations. All of that is synchronous CPU work with no `.await`
        // between `begin_drain()` and the fresh `sleep_or_signal` call, so 100ms of
        // real time is generous margin, not a tight race.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Safe to drop now and not a moment before: the loop is already inside
        // `sleep_or_signal`, past the one `current == 0` check that could exit it
        // through the clean-drain path instead of escalation, and that check is
        // not reached again until `sleep_or_signal` itself returns. Dropping here
        // rather than after the assertions below means step 10's post-`Closing`
        // wait sees zero live connections on its very first check, so a passing
        // run never actually waits out a `poll_interval`.
        drop(guard);

        let status2 = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(std::process::id().to_string())
            .status()
            .expect(
                "the first kill succeeded above, so the same kill binary exists for \
                 this second call too",
            );
        assert!(
            status2.success(),
            "the second kill command itself must succeed for this test to mean anything"
        );

        let report = with_timeout(Duration::from_secs(5), handle.join())
            .await
            .expect("a second real signal must escalate the drain well within 5 seconds")
            .expect("the supervisor task must not panic");

        assert!(
            report.escalated,
            "a second real shutdown signal must set DrainReport::escalated; this is the \
             mechanism that lets an operator's second Ctrl-C shorten a graceful window \
             instead of it being silently ignored for the full 120 second deadline"
        );
        assert_eq!(token.phase(), Phase::Closing);
    } else {
        // A sandbox without a `kill` binary: assert the future is still pending
        // instead of failing the suite over an environment limitation, the same
        // fallback `next_shutdown_signal_observes_sigterm` uses.
        drop(guard);
        let outcome = with_timeout(Duration::from_millis(200), handle.join()).await;
        assert!(
            outcome.is_err(),
            "expected supervise to still be draining when no signal could be sent"
        );
    }
}
