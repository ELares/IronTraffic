// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for the signal wrapper.

use std::time::Duration;

use irontraffic_io::{ShutdownSignal, next_shutdown_signal, sleep_or_signal};

#[tokio::test]
async fn sleep_or_signal_returns_none_without_a_signal() {
    let result = sleep_or_signal(Duration::from_millis(10)).await;
    assert_eq!(result, None);
}

// `#[cfg(unix)]`: sends a real SIGTERM to this process. macOS and Linux both count as
// unix for cfg purposes, and both accept `kill -TERM`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn next_shutdown_signal_observes_sigterm() {
    let handle = tokio::spawn(next_shutdown_signal());

    // Give the spawned task time to install its signal handlers before the signal is
    // sent, so the kill below cannot race ahead of the registration.
    tokio::time::sleep(Duration::from_millis(100)).await;

    if let Ok(status) = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(std::process::id().to_string())
        .status()
    {
        assert!(
            status.success(),
            "the kill command itself must succeed for this test to mean anything"
        );

        let observed = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("next_shutdown_signal must observe SIGTERM within 2 seconds")
            .expect("the spawned task must not panic")
            .expect("next_shutdown_signal must not report an installation error here");

        assert_eq!(observed, ShutdownSignal::Term);
    } else {
        // A sandbox without a `kill` binary: assert the future is still pending
        // instead of failing the suite over an environment limitation.
        let outcome = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            outcome.is_err(),
            "expected next_shutdown_signal to still be pending when no signal was sent"
        );
    }
}

// Not one of the 2 tests the issue names. Mutation testing (`cargo mutants -j 1`)
// found that replacing the entire body of the `#[cfg(unix)]` `sleep_or_signal` with a
// bare `None` survives `sleep_or_signal_returns_none_without_a_signal`: that test only
// ever exercises the "no signal arrived" path, so a `sleep_or_signal` that can never
// report a signal passes it just as well as the real implementation. Sending a real
// SIGTERM into a long sleep and asserting the returned value is `Some(Term)`, not
// merely `.is_some()`, is what a stuck-at-`None` mutant cannot survive.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sleep_or_signal_observes_a_real_signal() {
    let handle = tokio::spawn(sleep_or_signal(Duration::from_secs(5)));

    // Give the spawned task time to install its signal handlers before the signal is
    // sent, so the kill below cannot race ahead of the registration.
    tokio::time::sleep(Duration::from_millis(100)).await;

    if let Ok(status) = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(std::process::id().to_string())
        .status()
    {
        assert!(
            status.success(),
            "the kill command itself must succeed for this test to mean anything"
        );

        let observed = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect(
                "sleep_or_signal must observe SIGTERM within 2 seconds, well inside the 5 \
                     second sleep it was given",
            )
            .expect("the spawned task must not panic");

        assert_eq!(
            observed,
            Some(ShutdownSignal::Term),
            "a real signal must interrupt the sleep and be reported, not be swallowed into None"
        );
    } else {
        // A sandbox without a `kill` binary: assert the future is still pending
        // instead of failing the suite over an environment limitation.
        let outcome = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            outcome.is_err(),
            "expected sleep_or_signal to still be pending when no signal was sent"
        );
    }
}
