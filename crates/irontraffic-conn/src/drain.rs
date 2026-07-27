// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signal-driven graceful drain: a bounded deadline, and jittered per-connection close.
//!
//! [`supervise`] maps SIGTERM, SIGINT, and SIGQUIT onto the shutdown phases (all three
//! begin a drain; a second signal of any of them escalates straight to `Closing`,
//! because an operator who sends SIGTERM twice means it), waits for the connection
//! balance to reach zero with a bounded deadline, and reports how many connections
//! were still alive when the deadline expired. [`jitter_before_close`] spreads
//! per-connection close delays across a window so a drain does not wake every
//! connection task in the same instant, which would be a scheduler stampede and a
//! burst of upstream closes.
//!
//! Both the deadline and the jitter are bounded through [`clamp_ms`], the one place in
//! this module a `Duration` becomes a `u32` millisecond count. That is deliberate:
//! `irontraffic_time::CoarseMono::saturating_add_ms` wraps a deadline into the past if
//! handed an interval past its contracted bound, which would turn a request for a long
//! graceful window into an immediate hard kill of every live connection, the opposite
//! of what was asked for. Every deadline computed here goes through `clamp_ms` first.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use irontraffic_io::{Phase, ShutdownController, ShutdownSignal, ShutdownToken};
use irontraffic_time::{CoarseMono, TimeSource};

use crate::ConnRegistry;

/// Drain timing.
#[derive(Debug, Clone, Copy)]
pub struct DrainConfig {
    /// How long existing connections may keep serving after a drain begins.
    /// From `shutdown.graceful_timeout_ms`, default 300 seconds.
    pub graceful_timeout: Duration,
    /// The window over which per-connection close delays are spread, so c connections
    /// do not all wake in the same instant. From `shutdown.drain_jitter_ms`, default 5
    /// seconds.
    pub jitter: Duration,
    /// How often the supervisor re-reads the connection balance. 50 ms in production;
    /// tests set 1 ms. Not exposed in the configuration document: an operator has no
    /// reason to tune it.
    pub poll_interval: Duration,
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            graceful_timeout: Duration::from_secs(300),
            jitter: Duration::from_secs(5),
            poll_interval: Duration::from_millis(50),
        }
    }
}

/// What a drain did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    /// Which signal started it, or `None` when signal installation failed.
    pub trigger: Option<ShutdownSignal>,
    /// Connections still live after being told to close. 0 is a clean drain.
    pub killed: u64,
    /// The drain was escalated before its deadline, either by a second signal or by
    /// the phase reaching `Closing` from somewhere else.
    pub escalated: bool,
    /// Wall time from the signal to the end of the drain, in milliseconds.
    pub elapsed_ms: u64,
}

/// Converts a duration to milliseconds, saturating at
/// [`CoarseMono::MAX_INTERVAL_MS`], the largest interval
/// [`CoarseMono::saturating_add_ms`] is contracted for.
///
/// Two total conversions, `try_from` plus `unwrap_or`, never a narrowing `as`: a
/// `Duration::from_secs(u64::MAX)` arriving from a configuration bug must not wrap a
/// deadline into the past, which is what an unclamped `saturating_add_ms` call would
/// do (the "saturating" in its name describes the addition, not the bound on `ms`; a
/// `ms` argument past `MAX_INTERVAL_MS` wraps the 32-bit deadline around instead). A
/// deadline in the past means the drain escalates immediately, silently turning
/// "graceful shutdown" into "kill every connection now".
fn clamp_ms(d: Duration) -> u32 {
    let millis = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    let millis = u32::try_from(millis).unwrap_or(u32::MAX);
    millis.min(CoarseMono::MAX_INTERVAL_MS)
}

/// Waits for a shutdown signal, drains, and returns what happened.
///
/// Sequence: wait for SIGTERM, SIGINT, or SIGQUIT; `begin_drain()`; poll the connection
/// balance every `poll_interval` until it is zero, the graceful deadline passes, or a
/// second signal arrives; `begin_closing()`; wait up to 20 poll intervals for tasks to
/// release their guards; report.
///
/// Returns only after the phase has reached [`Phase::Closing`], so a caller may treat
/// its return as permission to shut the runtime down.
///
/// A two-line wrapper over [`supervise_with_trigger`]: it builds the signal wait and
/// delegates, so every test drives the identical production path in
/// `supervise_with_trigger` without delivering a real signal.
pub async fn supervise(
    controller: ShutdownController,
    registry: Arc<ConnRegistry>,
    time: Arc<dyn TimeSource>,
    cfg: DrainConfig,
) -> DrainReport {
    let trigger = async {
        match irontraffic_io::signal::next_shutdown_signal().await {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!(error = %e, "cannot install signal handlers; shutting down now");
                None
            }
        }
    };
    supervise_with_trigger(controller, registry, time, cfg, trigger).await
}

/// The same drain as [`supervise`], with the signal wait replaced by an arbitrary
/// trigger future.
///
/// `supervise` is a two-line wrapper over this function. It exists so every drain test
/// drives the production code path without delivering a real signal: pass a trigger
/// that resolves immediately to exercise the drain body directly, or hold a real
/// signal wait to reproduce the exact production sequence.
pub async fn supervise_with_trigger(
    controller: ShutdownController,
    registry: Arc<ConnRegistry>,
    time: Arc<dyn TimeSource>,
    cfg: DrainConfig,
    trigger: impl Future<Output = Option<ShutdownSignal>> + Send,
) -> DrainReport {
    let sig = trigger.await;
    let started = time.coarse_mono();
    tracing::info!(signal = ?sig, live = registry.stats().current, "drain starting");
    controller.begin_drain();

    let deadline = started.saturating_add_ms(clamp_ms(cfg.graceful_timeout));
    let mut escalated = false;

    loop {
        if registry.stats().current == 0 {
            break;
        }
        if time.coarse_mono().reached(deadline) {
            break;
        }
        if controller.phase() == Phase::Closing {
            // Something outside this loop already escalated (for example a hard
            // shutdown triggered elsewhere). Without this check the loop would keep
            // waiting for the full graceful window even though the phase already
            // says terminate now, and the escalation path would be untestable
            // without delivering a second real signal.
            escalated = true;
            break;
        }
        if irontraffic_io::signal::sleep_or_signal(cfg.poll_interval)
            .await
            .is_some()
        {
            escalated = true;
            tracing::warn!("second shutdown signal received; escalating the drain");
            break;
        }
    }

    let live = registry.stats().current;
    if live > 0 {
        tracing::warn!(
            live,
            escalated,
            "drain deadline reached; closing remaining connections"
        );
    } else {
        tracing::info!("drain complete; no connections remained");
    }
    controller.begin_closing();

    // Give connection tasks a bounded window to observe Closing and release their
    // guards, so `killed` means "still alive after being told to close" rather than
    // "alive when the deadline passed": without this, every drain that hits the
    // deadline would report a non-zero `killed` even when connections terminated
    // correctly a millisecond later.
    //
    // `saturating_mul` then `.min(MAX_INTERVAL_MS)` again: `clamp_ms` alone returns a
    // value up to `MAX_INTERVAL_MS`, and multiplying that by 20 overflows `u32` for
    // any large configured poll interval, which would wrap the deadline computed
    // below into the past.
    let grace_ms = clamp_ms(cfg.poll_interval)
        .saturating_mul(20)
        .min(CoarseMono::MAX_INTERVAL_MS);
    let hard_deadline = time.coarse_mono().saturating_add_ms(grace_ms);
    while registry.stats().current > 0 && !time.coarse_mono().reached(hard_deadline) {
        irontraffic_io::sleep(cfg.poll_interval).await;
    }

    let killed = registry.stats().current;
    DrainReport {
        trigger: sig,
        killed,
        escalated,
        elapsed_ms: u64::from(time.coarse_mono().elapsed_ms_since(started)),
    }
}

/// Waits a per-connection random delay before closing during a drain.
///
/// Draws once from the per-core RNG, so the delay is seedable and reproducible.
/// Returns immediately when the phase has reached [`Phase::Closing`], so jitter can
/// never extend the graceful window.
///
/// Called by a connection task after it observes `is_draining()` at a request
/// boundary and before it closes. Inert until the connection handler calls it;
/// `serve-and-smoke-test` (#21) is the issue that wires it in from the connection
/// handler.
pub async fn jitter_before_close(shutdown: &ShutdownToken, cfg: &DrainConfig) {
    if shutdown.is_closing() {
        return;
    }
    let max_ms = clamp_ms(cfg.jitter);
    if max_ms == 0 {
        return;
    }
    let delay_ms = irontraffic_runtime::core::with(|c| c.rand_bounded_u32(max_ms));
    // Widened with `u64::from`, never a narrowing-cast operator: the u32-to-u64
    // widening has a total `From` impl, so that operator would buy nothing here.
    irontraffic_io::sleep(Duration::from_millis(u64::from(delay_ms))).await;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use irontraffic_time::CoarseMono;

    use super::clamp_ms;

    #[test]
    fn clamp_ms_table() {
        assert_eq!(clamp_ms(Duration::ZERO), 0);
        assert_eq!(clamp_ms(Duration::from_millis(1)), 1);
        assert_eq!(clamp_ms(Duration::from_secs(300)), 300_000);
        assert_eq!(
            clamp_ms(Duration::from_millis(u64::from(
                CoarseMono::MAX_INTERVAL_MS
            ))),
            CoarseMono::MAX_INTERVAL_MS
        );
        assert_eq!(
            clamp_ms(Duration::from_millis(
                u64::from(CoarseMono::MAX_INTERVAL_MS) + 1
            )),
            CoarseMono::MAX_INTERVAL_MS
        );
        assert_eq!(clamp_ms(Duration::MAX), CoarseMono::MAX_INTERVAL_MS);

        // The issue names this assertion against `CoarseMono::from_millis(0)`, which
        // is not a real public constructor: `CoarseMono`'s only millisecond
        // constructor, `from_millis_since_start`, is `pub(crate)` inside
        // `irontraffic-time`, so a crate outside it (this one) cannot call it
        // directly. `CoarseMono::default()` is the same zero value (`CoarseMono`
        // derives `Default` over its single `u32` field), so the property under
        // test, that a deadline built from `clamp_ms(Duration::MAX)` starting at
        // time zero is never immediately reached, is unchanged. Filed as issue 593
        // against this issue's own test text.
        let zero = CoarseMono::default();
        assert!(!zero.reached(zero.saturating_add_ms(clamp_ms(Duration::MAX))));
    }
}
