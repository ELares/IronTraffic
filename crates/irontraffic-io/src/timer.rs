// SPDX-License-Identifier: MIT OR Apache-2.0

//! Timer helpers. The crate that owns the runtime also owns its timer.

use std::future::Future;
use std::time::Duration;

use thiserror::Error;

/// Sleeps for `dur` on the current runtime's timer.
///
/// # Panics
/// Panics if there is no tokio runtime driving the current thread, or if the
/// runtime was built without `enable_time()`. This function's signature has no
/// `Result` to report either case (the issue's Public API specifies `pub async
/// fn sleep(dur: Duration)`), and tokio has no public API to detect a missing
/// timer driver without triggering the panic itself, so unlike
/// `TcpAcceptor::from_std` (whose `io::Result` return type gives the
/// no-runtime case somewhere to go) this is a documented precondition rather
/// than a guarded one. Call it only from a runtime built with `enable_time()`
/// (or `enable_all()`).
pub async fn sleep(dur: Duration) {
    tokio::time::sleep(dur).await;
}

/// Runs `fut` with a deadline.
///
/// # Errors
/// Returns [`TimedOut`] carrying the budget in milliseconds if `dur` elapses first.
///
/// # Panics
/// Panics if there is no tokio runtime driving the current thread, or if the
/// runtime was built without `enable_time()`, for the same reason documented
/// on [`sleep`]. The `Result` this function already returns is reserved for
/// [`TimedOut`], a deadline actually elapsing; folding a missing timer driver
/// into that error would misclassify a caller bug as a timeout, so this is
/// documented rather than mapped into the return type.
pub async fn with_timeout<F: Future>(dur: Duration, fut: F) -> Result<F::Output, TimedOut> {
    // `as_millis()` is u128; saturate rather than cast, so a Duration::MAX budget
    // reports u64::MAX instead of a wrapped small number.
    let millis = u64::try_from(dur.as_millis()).unwrap_or(u64::MAX);
    tokio::time::timeout(dur, fut)
        .await
        .map_err(|_| TimedOut { millis })
}

/// The deadline passed by [`with_timeout`] elapsed.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("operation timed out after {millis} ms")]
pub struct TimedOut {
    /// The budget that elapsed, in milliseconds.
    pub millis: u64,
}

/// The `hyper::rt::Timer` implementation backed by the current runtime.
pub type SystemTimer = hyper_util::rt::TokioTimer;
