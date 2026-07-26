// SPDX-License-Identifier: MIT OR Apache-2.0

//! Graceful shutdown signalling.
//!
//! One [`ShutdownController`] per process advances a monotone phase. Every
//! accept task and every connection task holds a cloneable [`ShutdownToken`]:
//! checking it is one relaxed atomic load, and waiting on it is one `Notify`
//! registration.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::Acceptor;

/// The process lifecycle phase. Monotone: it never moves backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Phase {
    /// Accepting new connections and serving existing ones.
    Serving = 0,
    /// Not accepting new connections; existing ones are being served to completion.
    Draining = 1,
    /// The drain deadline passed; existing connections must terminate now.
    Closing = 2,
}

impl Phase {
    /// Maps a stored byte back to a phase. `0` and `1` map to their own
    /// variant; every other value, including `2`, maps to [`Phase::Closing`],
    /// the safe direction: an impossible value must not be read as "keep
    /// serving". A wrong answer toward `Closing` stops the proxy early,
    /// which is recoverable by restarting; a wrong answer toward `Serving`
    /// means the proxy keeps taking traffic after being told to stop.
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Phase::Serving,
            1 => Phase::Draining,
            _ => Phase::Closing, // 2 and every impossible value fail safe toward shutdown
        }
    }

    /// The stored byte. A total `match`, not a bare numeric cast of `self`:
    /// the `unchecked-cast` rule in `scripts/invariant-lints.sh` fires on a
    /// narrowing `as` conversion in production code, and writing the three
    /// discriminants out keeps `from_u8` and `to_u8` visibly inverse.
    const fn to_u8(self) -> u8 {
        match self {
            Phase::Serving => 0,
            Phase::Draining => 1,
            Phase::Closing => 2,
        }
    }
}

/// Shared state behind a [`ShutdownController`] and every [`ShutdownToken`]
/// cloned from it.
#[derive(Debug)]
struct Inner {
    phase: AtomicU8,
    notify: tokio::sync::Notify,
}

/// Advances the shutdown phase. Exactly one per process; deliberately not
/// [`Clone`]: exactly one thing in the process may advance the phase, and
/// making that structurally true is cheaper than documenting it.
///
/// The supervisor that owns this controller must advance the phase to at
/// least [`Phase::Closing`] before dropping it. A [`ShutdownToken`] holds its
/// own `Arc` to the shared state, so dropping the controller with tokens
/// still alive does not drop that state; it only gives up the one handle
/// able to move the phase forward. Any token parked in
/// [`ShutdownToken::drained`] or [`ShutdownToken::closing`] at that moment is
/// left waiting on a notification that can now never arrive: no error, no
/// log line, and no way to observe the hang from inside this module. This is
/// the same shape as dropping a [`TaskHandle`](crate::TaskHandle) mid-poll
/// out of a `select!` arm, that is, a resource silently orphaned by call
/// order rather than by anything this type can detect.
#[derive(Debug)]
pub struct ShutdownController {
    inner: Arc<Inner>,
}

impl ShutdownController {
    /// Creates the controller and its first token, both starting at
    /// [`Phase::Serving`].
    #[must_use]
    pub fn new() -> (Self, ShutdownToken) {
        let inner = Arc::new(Inner {
            phase: AtomicU8::new(Phase::Serving.to_u8()),
            notify: tokio::sync::Notify::new(),
        });
        let controller = Self {
            inner: Arc::clone(&inner),
        };
        let token = ShutdownToken { inner };
        (controller, token)
    }

    /// Issues another token for a task to hold.
    #[must_use]
    pub fn token(&self) -> ShutdownToken {
        ShutdownToken {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Advances to [`Phase::Draining`] and wakes every waiter. Idempotent: a
    /// second call does nothing and wakes nobody.
    pub fn begin_drain(&self) {
        self.advance(Phase::Draining);
    }

    /// Advances to [`Phase::Closing`] and wakes every waiter. Idempotent. May
    /// be called without a preceding `begin_drain`, which is what a hard
    /// shutdown does.
    pub fn begin_closing(&self) {
        self.advance(Phase::Closing);
    }

    /// The current phase.
    #[must_use]
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.inner.phase.load(Ordering::Relaxed))
    }

    /// Advances the stored phase to at least `to`, waking every current
    /// waiter exactly once if the phase actually moved. Never moves the
    /// phase backwards: if it is already at or past `to`, this returns
    /// without touching the atomic again and without notifying anybody.
    fn advance(&self, to: Phase) {
        let want = to.to_u8();
        loop {
            let cur = self.inner.phase.load(Ordering::Acquire);
            if cur >= want {
                return;
            }
            if self
                .inner
                .phase
                .compare_exchange(cur, want, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        self.inner.notify.notify_waiters();
    }
}

/// A cheap, cloneable view of the shutdown phase.
#[derive(Debug, Clone)]
pub struct ShutdownToken {
    inner: Arc<Inner>,
}

const _: () = assert!(std::mem::size_of::<ShutdownToken>() == 8);

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ShutdownToken>();
};

impl ShutdownToken {
    /// The current phase. One relaxed atomic load.
    #[must_use]
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.inner.phase.load(Ordering::Relaxed))
    }

    /// True once draining has begun. Check this at request boundaries.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.phase() >= Phase::Draining
    }

    /// True once the drain deadline has passed and connections must
    /// terminate.
    #[must_use]
    pub fn is_closing(&self) -> bool {
        self.phase() == Phase::Closing
    }

    /// Resolves as soon as the phase is [`Phase::Draining`] or later,
    /// including immediately if it already is.
    pub async fn drained(&self) {
        loop {
            if self.is_draining() {
                return;
            }
            // Register with the notifier BEFORE the recheck below: this
            // order is load bearing, not a style choice. `notify_waiters`
            // stores no permit, so it wakes only the waiters that exist at
            // the moment it runs; `Notify::notified()` records the
            // notifier's `notify_waiters` call count when the future is
            // CREATED, and a future whose recorded count no longer matches
            // the current one completes on its first poll. Creating the
            // future first and rechecking the phase second closes the
            // window in which an advance happens between the first check
            // and the registration. The opposite order (check, then
            // register only if still serving) would leave that window
            // open: an advance landing inside it would be missed entirely
            // and this future would never resolve.
            let notified = self.inner.notify.notified();
            if self.is_draining() {
                return;
            }
            notified.await;
        }
    }

    /// Resolves as soon as the phase is [`Phase::Closing`], including
    /// immediately if it already is.
    pub async fn closing(&self) {
        loop {
            if self.is_closing() {
                return;
            }
            // See the comment in `drained`: registering before the recheck
            // is what closes the lost-wakeup window.
            let notified = self.inner.notify.notified();
            if self.is_closing() {
                return;
            }
            notified.await;
        }
    }
}

/// Waits for one inbound connection, or for a drain to begin.
///
/// Returns `None` as soon as the phase reaches [`Phase::Draining`], and
/// `None` for every subsequent call: an accept loop that sees `None` exits
/// and never resumes. The drain branch is polled first, so a listener with a
/// full accept queue cannot keep accepting after a drain has started.
pub async fn accept_or_drain<A: Acceptor>(
    acceptor: &A,
    token: &ShutdownToken,
) -> Option<io::Result<(A::Io, SocketAddr)>> {
    if token.is_draining() {
        return None;
    }
    tokio::select! {
        biased;
        () = token.drained() => None,
        r = std::future::poll_fn(|cx| acceptor.poll_accept(cx)) => Some(r),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::Duration;

    use super::{Phase, ShutdownController};

    #[tokio::test]
    async fn phase_starts_serving() {
        let (controller, token) = ShutdownController::new();
        assert_eq!(controller.phase(), Phase::Serving);
        assert_eq!(token.phase(), Phase::Serving);
        assert!(!token.is_draining());
        assert!(!token.is_closing());
    }

    #[tokio::test]
    async fn begin_drain_advances_and_is_visible_to_a_clone() {
        let (controller, token) = ShutdownController::new();
        let clone = token.clone();

        controller.begin_drain();

        assert_eq!(token.phase(), Phase::Draining);
        assert_eq!(clone.phase(), Phase::Draining);
        assert!(token.is_draining());
        assert!(!token.is_closing());
    }

    #[tokio::test]
    async fn phase_never_goes_backwards() {
        let (controller, token) = ShutdownController::new();

        controller.begin_closing();
        controller.begin_drain();

        assert_eq!(token.phase(), Phase::Closing);
    }

    // Respecified: the original shape spawned a `drained()` waiter, joined
    // the task to completion after the FIRST `begin_drain()`, and only then
    // issued the second `begin_drain()`. By that point the waiter task had
    // already exited, so nothing was left alive to receive (or fail to
    // receive) a second wakeup; the counter could not move regardless of
    // what the second `begin_drain()` did, so a mutant that makes
    // `advance()` call `notify_waiters()` on its no-op path still passed
    // this test. It also could not have used a second `drained()` call to
    // detect the extra wakeup: once the phase is `Draining`, EVERY later
    // `drained()` returns immediately from its first phase check without
    // ever registering with the `Notify`, so it cannot distinguish "a
    // second notification fired" from "no notification fired at all".
    //
    // This version keeps a waiter alive across both calls by looping on the
    // shared `Notify` directly (accessible here because `mod tests` is a
    // descendant of this module) and counting every time it actually fires,
    // which is the level invariant 2 is stated at: "`notify_waiters` is
    // called at most once per distinct phase advance".
    #[tokio::test]
    async fn second_begin_drain_wakes_nobody() {
        let (controller, _token) = ShutdownController::new();
        let wakeups = Arc::new(AtomicU32::new(0));
        let waiter_wakeups = Arc::clone(&wakeups);
        let inner = Arc::clone(&controller.inner);

        let handle = tokio::spawn(async move {
            loop {
                inner.notify.notified().await;
                waiter_wakeups.fetch_add(1, Ordering::Relaxed);
            }
        });

        // Let the spawned task reach its first `notified()` registration
        // before the phase moves, so the first `begin_drain()` below is
        // guaranteed to be the event that wakes it (rather than the waiter
        // registering late and racing the wakeup).
        tokio::task::yield_now().await;

        controller.begin_drain();
        crate::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            wakeups.load(Ordering::Relaxed),
            1,
            "the first begin_drain() must wake the still-alive waiter exactly once"
        );

        controller.begin_drain();
        crate::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            wakeups.load(Ordering::Relaxed),
            1,
            "a second begin_drain() is a no-op and must not call notify_waiters() again, \
             which a live waiter would otherwise observe as a second wakeup"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn no_lost_wakeup_under_race() {
        for _ in 0..1000 {
            let (controller, token) = ShutdownController::new();
            let flag = Arc::new(AtomicBool::new(false));
            let waiter_flag = Arc::clone(&flag);
            let waiter_token = token.clone();

            let handle = tokio::spawn(async move {
                waiter_token.drained().await;
                waiter_flag.store(true, Ordering::Relaxed);
            });

            controller.begin_drain();

            let outcome = crate::with_timeout(Duration::from_secs(1), handle).await;
            let join_result =
                outcome.expect("drained() must not lose a wakeup under race (timed out)");
            join_result.expect("waiter task must not panic");
            assert!(
                flag.load(Ordering::Relaxed),
                "waiter completed without observing the drain"
            );
        }
    }

    #[tokio::test]
    async fn drained_returns_immediately_when_already_draining() {
        let (controller, token) = ShutdownController::new();
        controller.begin_drain();

        let result = crate::with_timeout(Duration::from_millis(1), token.drained()).await;
        assert_eq!(result, Ok(()));
    }

    // Edge case 2, the `is_draining()` half: a hard shutdown calls
    // `begin_closing()` with no preceding `begin_drain()`, so the phase
    // jumps straight from `Serving` to `Closing` and is never, even
    // momentarily, exactly `Draining`. `is_draining()` must still report
    // true, because it asks "at or past Draining", not "exactly Draining".
    // Mutating its `>=` to `==` compiles, and every other test in this file
    // still passes, because every other test that reaches `Closing` gets
    // there through `Draining` first.
    #[tokio::test]
    async fn begin_closing_without_a_prior_drain_reports_is_draining_true() {
        let (controller, token) = ShutdownController::new();

        controller.begin_closing();

        assert!(
            token.is_draining(),
            "Closing is at or past Draining in the phase order, so a hard shutdown \
             (begin_closing with no preceding begin_drain) must still satisfy is_draining()"
        );
        assert!(token.is_closing());
    }

    // Edge case 2, the `drained()` half: on the `is_draining() == Draining`
    // mutant, a task parked in `drained()` after a hard shutdown never sees
    // its recheck succeed (the phase is `Closing`, never `Draining`), and no
    // further notification is coming because `begin_closing()` already fired
    // the only one it will ever fire. `with_timeout` turns that hang into a
    // failing assertion instead of a wedged test run.
    #[tokio::test]
    async fn drained_resolves_on_a_hard_shutdown_with_no_preceding_drain() {
        let (controller, token) = ShutdownController::new();
        controller.begin_closing();

        let result = crate::with_timeout(Duration::from_millis(200), token.drained()).await;
        assert_eq!(
            result,
            Ok(()),
            "drained() must resolve once Closing is reached even without an intervening \
             Draining phase"
        );
    }

    // `closing()` has its own loop-vs-recheck hazard, distinct from
    // `drained()`'s: the shared `Notify` fires on EVERY advance, including a
    // plain `begin_drain()`, so a `closing()` waiter is woken at `Draining`
    // too and must go back to sleep rather than resolve. If the `loop` here
    // is flattened into a single check-register-await, the waiter resolves
    // on that first, spurious wakeup, which is design fact 1 reintroduced: a
    // task meant to run until `Closing` stops at `Draining` instead.
    #[tokio::test]
    async fn closing_ignores_a_drain_and_resolves_only_on_begin_closing() {
        let (controller, token) = ShutdownController::new();
        let resolved = Arc::new(AtomicBool::new(false));
        let waiter_resolved = Arc::clone(&resolved);
        let waiter_token = token.clone();

        let handle = tokio::spawn(async move {
            waiter_token.closing().await;
            waiter_resolved.store(true, Ordering::Relaxed);
        });

        // Let the spawned task reach `closing()`'s first `notified()`
        // registration before the phase moves, so the `begin_drain()` below
        // is guaranteed to be a real wakeup delivered to an already-waiting
        // task rather than a state the task only observes after the fact.
        tokio::task::yield_now().await;

        controller.begin_drain();
        crate::sleep(Duration::from_millis(20)).await;
        assert!(
            !resolved.load(Ordering::Relaxed),
            "closing() must not resolve on a drain alone; only Closing ends it"
        );

        controller.begin_closing();
        let outcome = crate::with_timeout(Duration::from_secs(1), handle).await;
        outcome
            .expect("closing() must resolve once Closing is reached (timed out)")
            .expect("waiter task must not panic");
        assert!(resolved.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn closing_returns_immediately_when_already_closing() {
        let (controller, token) = ShutdownController::new();
        controller.begin_closing();

        let result = crate::with_timeout(Duration::from_millis(1), token.closing()).await;
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn unknown_phase_byte_fails_closed() {
        assert_eq!(Phase::from_u8(0), Phase::Serving);
        assert_eq!(Phase::from_u8(1), Phase::Draining);
        assert_eq!(Phase::from_u8(2), Phase::Closing);
        for v in 3..=255u8 {
            assert_eq!(Phase::from_u8(v), Phase::Closing);
        }
    }
}
