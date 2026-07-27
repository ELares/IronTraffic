// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shutdown signal handling: SIGTERM, SIGINT, and SIGQUIT.
//!
//! This is the thin `tokio::signal` wrapper `conn-drain-jitter` (#18) needs so that
//! `irontraffic-conn`'s drain supervisor can wait for a shutdown signal without naming
//! `tokio` itself: `tokio::` is permitted only in this crate and `irontraffic-runtime`,
//! enforced by the `transport-seam` rule in `scripts/invariant-lints.sh`.
//!
//! Each call to [`next_shutdown_signal`] or [`sleep_or_signal`] installs its own signal
//! handlers and drops them on return, rather than holding them for the process
//! lifetime. That is deliberate: tokio keeps the underlying process-wide handler
//! installed after first use, but a [`tokio::signal::unix::Signal`] stream only
//! receives notifications delivered while it exists, so a signal that arrives in the
//! gap between one call returning and the next one starting is not observed by either
//! call. That gap is one atomic load and one branch wide (the caller re-entering its
//! wait), and the drain supervisor has a second way to notice a second signal: it also
//! reads the shutdown phase directly on every loop iteration. An operator whose second
//! SIGTERM lands in the gap simply needs to send it again; do not "fix" this by holding
//! handlers for the whole process lifetime without also owning their teardown.

use std::io;
use std::time::Duration;

/// A shutdown signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    /// SIGTERM: the orchestrator asked us to stop.
    Term,
    /// SIGINT: an operator pressed control-C.
    Int,
    /// SIGQUIT: reserved as the binary-upgrade drain signal. Nothing implements the
    /// upgrade handoff yet; this variant only fixes the mapping now so it does not
    /// have to change later.
    Quit,
}

/// Waits for the first of SIGTERM, SIGINT, or SIGQUIT.
///
/// Registers handlers for the duration of the call and drops them on return, so a
/// caller may call it again later (tokio's registration is idempotent). On a non-unix
/// target this future never completes: signal-driven shutdown is unix only in v1.
///
/// # Errors
/// Returns the operating system error when a handler cannot be installed.
#[cfg(unix)]
pub async fn next_shutdown_signal() -> io::Result<ShutdownSignal> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut quit = signal(SignalKind::quit())?;

    // No `biased;` here: the three signals are equivalent drain triggers, and which
    // one fires first, if more than one is already pending, does not change what the
    // caller does with the result.
    tokio::select! {
        _ = term.recv() => Ok(ShutdownSignal::Term),
        _ = int.recv() => Ok(ShutdownSignal::Int),
        _ = quit.recv() => Ok(ShutdownSignal::Quit),
    }
}

/// Waits for the first of SIGTERM, SIGINT, or SIGQUIT.
///
/// # Errors
/// Returns the operating system error when a handler cannot be installed.
///
/// `cargo mutants` run on a unix host, which every CI runner and every developer
/// machine for this project is, cannot compile this function's body at all: the
/// `#[cfg(not(unix))]` gate excludes it before rustc ever sees it, so a mutation
/// applied here produces a byte-identical binary to the unmutated one and is
/// reported "missed" by construction, not because a test is missing. Exercising it
/// for real needs a non-unix build target, which is out of scope for v1.
#[cfg(not(unix))]
pub async fn next_shutdown_signal() -> io::Result<ShutdownSignal> {
    // Unreachable by construction on a non-unix target: signal-driven shutdown is
    // unix only in v1. Written as a pending await followed by a value that is never
    // produced, rather than the panicking macro that names this situation, so the
    // function still type-checks without a call that could ever actually run.
    std::future::pending::<()>().await;
    Ok(ShutdownSignal::Term)
}

/// Sleeps for `dur`, returning early with the signal if one arrives first.
///
/// Returns `None` when the sleep completed without a signal. This is how the drain
/// supervisor notices a second signal without holding registered handlers for the
/// whole drain.
#[cfg(unix)]
pub async fn sleep_or_signal(dur: Duration) -> Option<ShutdownSignal> {
    // A signal-installation failure inside the sleep path yields `None`, i.e. "the
    // sleep completed", which keeps the supervisor polling rather than escalating on
    // an error: a caller already treats installation failure as fatal the one time it
    // matters, in `next_shutdown_signal`'s own top-level call from `supervise`.
    tokio::select! {
        () = tokio::time::sleep(dur) => None,
        r = next_shutdown_signal() => r.ok(),
    }
}

/// Sleeps for `dur`, returning early with the signal if one arrives first.
///
/// Returns `None` when the sleep completed without a signal.
///
/// Same platform note as the `#[cfg(not(unix))]` body of [`next_shutdown_signal`]:
/// unreachable from a mutation-testing run on this (unix) host by construction, not
/// for lack of a test.
#[cfg(not(unix))]
pub async fn sleep_or_signal(dur: Duration) -> Option<ShutdownSignal> {
    tokio::time::sleep(dur).await;
    None
}
