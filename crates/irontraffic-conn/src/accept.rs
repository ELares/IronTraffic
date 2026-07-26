// SPDX-License-Identifier: MIT OR Apache-2.0

//! The accept loop: one task per shard, admitting through a [`crate::ConnRegistry`]
//! and classifying accept errors so descriptor exhaustion backs off instead of
//! spinning a core at 100% while serving nothing.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use irontraffic_io::{Acceptor, ShutdownToken, Spawner, Transport, accept_or_drain, sleep};
use irontraffic_runtime::core::{self, Counter};

use crate::registry::{ConnGuard, ConnRegistry};

/// The largest backoff step the accept loop will sleep for, 5 seconds.
///
/// A resource-limit backoff longer than this stops being a backoff and becomes an
/// outage: the listener is still readable and the shard is simply not accepting.
pub const MAX_BACKOFF_MS: u32 = 5_000;

/// What to do about an accept error: retry it, back off, or stop the shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptFault {
    /// The peer went away between SYN and accept, an interrupted syscall, or a
    /// spurious wakeup. Normal at any scale; retried with no log line, because
    /// logging it would hand an attacker a log-amplification vector.
    RetryNow,
    /// A resource limit. Transient, and a tight retry loop burns a core serving
    /// nothing, so this backs off with doubling instead.
    BackOff,
    /// Anything else. Loud and terminal for the one shard that hit it.
    Fatal,
}

#[cfg(target_os = "linux")]
const EMFILE: i32 = 24;
#[cfg(target_os = "linux")]
const ENFILE: i32 = 23;
#[cfg(target_os = "linux")]
const ENOBUFS: i32 = 105;

#[cfg(target_os = "macos")]
const EMFILE: i32 = 24;
#[cfg(target_os = "macos")]
const ENFILE: i32 = 23;
#[cfg(target_os = "macos")]
const ENOBUFS: i32 = 55;

// Any other target: sentinels that no real `raw_os_error()` can equal, so every
// resource-limit error classifies as Fatal. Loud and stopped beats silent and
// spinning.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const EMFILE: i32 = -1;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const ENFILE: i32 = -2;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const ENOBUFS: i32 = -3;

/// Classifies an accept error into a retry, a backoff, or a fatal end to the shard
/// that hit it.
///
/// `std::io::ErrorKind` has no stable variant for `EMFILE` on the pinned toolchain,
/// so the raw OS error is compared against the numeric constants above, declared as
/// `cfg`-gated constants rather than pulled from `libc`, which is not a dependency of
/// this crate.
///
/// Three arms, not two: without the fallback arm this fails to compile on any target
/// that is neither Linux nor macOS, which is worse than the degraded (but correct)
/// behaviour the fallback gives.
pub(crate) fn classify(e: &std::io::Error) -> AcceptFault {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionAborted | K::Interrupted | K::WouldBlock => AcceptFault::RetryNow,
        K::OutOfMemory => AcceptFault::BackOff,
        _ => match e.raw_os_error() {
            Some(n) if n == EMFILE || n == ENFILE || n == ENOBUFS => AcceptFault::BackOff,
            _ => AcceptFault::Fatal,
        },
    }
}

/// Resolves the two backoff bounds on [`AcceptConfig`] through one clamp, called
/// exactly once before the accept loop starts.
///
/// Takes `cfg` by value: [`AcceptConfig`] is `Copy` and small enough that pedantic
/// clippy (`trivially_copy_pass_by_ref`) prefers a value over a reference here.
///
/// Both fields are `pub`, so a caller can set the floor to 0 or set the ceiling below
/// the floor. Every use of them inside the loop goes through this function's return
/// value rather than the fields directly, because a floor of 0 would turn the
/// resource-limit arm into a sleep of 0 milliseconds in a tight loop, which is
/// precisely the CPU spin the error classification exists to prevent, reachable from
/// a plain configuration value rather than a bug in the loop itself.
pub(crate) fn resolve_backoff(cfg: AcceptConfig) -> (u32, u32) {
    let initial = cfg.backoff_initial_ms.clamp(1, MAX_BACKOFF_MS);
    let ceiling = cfg.backoff_max_ms.clamp(initial, MAX_BACKOFF_MS);
    (initial, ceiling)
}

/// A boxed connection future. One allocation per connection, never per request.
///
/// The accept loop is generic over the transport but takes the connection handler as
/// a trait object producing this, which keeps the loop itself from being generic over
/// a closure type that would otherwise have to be named in every signature between
/// here and the supervisor that owns it.
pub type BoxFut = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// What the accept loop does with an accepted connection.
pub trait ConnHandler<Io: Transport>: Send + Sync + 'static {
    /// Produces the future that serves this connection.
    ///
    /// The returned future MUST own `guard` for its whole life, so the connection
    /// balance is released exactly when the connection ends, and MUST observe
    /// `shutdown` so a drain can complete.
    fn handle(&self, io: Io, peer: SocketAddr, guard: ConnGuard, shutdown: ShutdownToken)
    -> BoxFut;
}

/// Accept loop tuning.
#[derive(Debug, Clone, Copy)]
pub struct AcceptConfig {
    /// Which shard this loop serves. Logged with every accept error.
    pub shard: usize,
    /// First backoff step after a resource-limit accept error. Default 5.
    ///
    /// Clamped to `1..=MAX_BACKOFF_MS` before use: a value of 0 would make the
    /// resource-limit arm `sleep(0)` in a tight loop, which is the 100% CPU spin
    /// the error classification exists to prevent.
    pub backoff_initial_ms: u32,
    /// Backoff ceiling. Default 500.
    ///
    /// Clamped to `backoff_initial_ms..=MAX_BACKOFF_MS` before use, so a ceiling
    /// below the floor cannot shrink the backoff back toward zero.
    pub backoff_max_ms: u32,
}

impl Default for AcceptConfig {
    fn default() -> Self {
        Self {
            shard: 0,
            backoff_initial_ms: 5,
            backoff_max_ms: 500,
        }
    }
}

/// Why an accept loop returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// Draining began, so this loop stopped accepting.
    Drained,
    /// A fatal accept error stopped this shard. Other shards keep serving.
    Fatal,
}

/// Accepts connections until a drain begins or a fatal error occurs.
///
/// Exactly one accept loop may ever run against a given acceptor. The reactor
/// registration behind a listener keeps a single waker slot per readiness interest,
/// so a second task polling the same acceptor overwrites the first task's waker, and
/// the first is never woken again once it has returned `Pending`; four tasks sharing
/// one acceptor have been measured accepting only on the last of them. Fan accept
/// load out across cores with one listener per shard instead (built with
/// `SO_REUSEPORT` through `crate::ShardedListener`), call this function once per
/// shard's own acceptor, and never wrap one acceptor in an `Arc` to let two callers
/// of this function share it.
///
/// Per iteration: ticks the per-core clocks and the buffer pool decay, waits for a
/// connection or a drain, admits through `registry`, and spawns exactly one task per
/// admitted connection. A connection that cannot be admitted is closed immediately and
/// the loop pauses 1 millisecond so a flood at the connection cap cannot spin it.
///
/// Accept errors are classified: a peer that went away between SYN and accept, an
/// interrupted syscall, or a spurious wakeup all retry immediately with no log line;
/// a descriptor or buffer resource limit backs off with doubling between the two
/// bounds `cfg` configures, resolved once through [`resolve_backoff`] before this
/// loop starts; anything else is fatal for this one shard. Without that
/// classification, a resource-limit accept error spins a core at 100% while serving
/// nothing, which is a denial of service an attacker reaches purely by opening
/// connections.
pub async fn accept_loop<A, H>(
    acceptor: A,
    registry: Arc<ConnRegistry>,
    shutdown: ShutdownToken,
    spawner: Spawner,
    handler: Arc<H>,
    time: Arc<dyn irontraffic_time::TimeSource>,
    cfg: AcceptConfig,
) -> AcceptOutcome
where
    A: Acceptor,
    H: ConnHandler<A::Io>,
{
    let mut backoff_ms: u32 = 0;
    let (backoff_initial, backoff_ceiling) = resolve_backoff(cfg);

    loop {
        core::turn_tick(&*time);

        match accept_or_drain(&acceptor, &shutdown).await {
            None => return AcceptOutcome::Drained,
            Some(Ok((io, peer))) => {
                backoff_ms = 0;
                core::with(|c| c.bump(Counter::ConnectionsAccepted, 1));
                match ConnRegistry::try_admit(&registry) {
                    None => {
                        core::with(|c| c.bump(Counter::ConnectionsRejected, 1));
                        drop(io); // closes the socket immediately: FIN, or RST if data queued
                        // Bounded pause so a flood at the cap cannot spin this loop.
                        sleep(Duration::from_millis(1)).await;
                    }
                    Some(guard) => {
                        // The one place a data-plane task is detached, and it is
                        // correct: the task's lifetime is the connection's lifetime,
                        // `guard` inside it accounts for the balance, and `shutdown`
                        // inside it ends the task when a drain completes. Retaining
                        // the handle here would mean this loop owns a growing vector
                        // of handles, which is a second connection registry with
                        // worse properties than the one it already has.
                        let fut = handler.handle(io, peer, guard, shutdown.clone());
                        spawner.spawn(fut).detach();
                    }
                }
            }
            Some(Err(e)) => match classify(&e) {
                AcceptFault::RetryNow => {
                    // No sleep, no log: this is normal.
                }
                AcceptFault::BackOff => {
                    backoff_ms = if backoff_ms == 0 {
                        backoff_initial
                    } else {
                        backoff_ms.saturating_mul(2).min(backoff_ceiling)
                    };
                    // `backoff_ms` is now at least 1 by construction: both bounds
                    // above came from `resolve_backoff`, which never returns 0, so
                    // this arm can never become `sleep(0)` in a tight loop however
                    // `AcceptConfig` was filled in.
                    tracing::warn!(
                        shard = cfg.shard,
                        backoff_ms,
                        error = %e,
                        "accept is failing on a resource limit; backing off"
                    );
                    sleep(Duration::from_millis(u64::from(backoff_ms))).await;
                }
                AcceptFault::Fatal => {
                    tracing::error!(
                        shard = cfg.shard,
                        error = %e,
                        "fatal accept error; this shard stops accepting"
                    );
                    return AcceptOutcome::Fatal;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AcceptConfig, AcceptFault, MAX_BACKOFF_MS, classify, resolve_backoff};

    #[test]
    fn classify_table() {
        use std::io::{Error, ErrorKind};

        assert_eq!(
            classify(&Error::from(ErrorKind::ConnectionAborted)),
            AcceptFault::RetryNow
        );
        assert_eq!(
            classify(&Error::from(ErrorKind::Interrupted)),
            AcceptFault::RetryNow
        );
        assert_eq!(
            classify(&Error::from(ErrorKind::WouldBlock)),
            AcceptFault::RetryNow
        );
        assert_eq!(
            classify(&Error::from(ErrorKind::OutOfMemory)),
            AcceptFault::BackOff
        );
        assert_eq!(
            classify(&Error::from(ErrorKind::PermissionDenied)),
            AcceptFault::Fatal
        );
        assert_eq!(
            classify(&Error::from(ErrorKind::InvalidInput)),
            AcceptFault::Fatal
        );

        // A raw OS error that is deliberately none of EMFILE, ENFILE, or ENOBUFS on
        // any target, including the `not(any(linux, macos))` sentinel values (-1, -2,
        // -3): mutation testing this table found that the match guard on the third
        // comparison (`n == ENOBUFS`) could be flipped to `!=`, or the whole guard
        // replaced with `true`, without either mutant failing this test, because
        // every row above either carries no raw OS error at all or matches one of
        // the two rows this table already asserted BackOff for. A row whose raw
        // error is unrelated to all three resource-limit numbers is the one input
        // that must still classify Fatal under both mutations and does not, which is
        // exactly what catches them.
        assert_eq!(classify(&Error::from_raw_os_error(2)), AcceptFault::Fatal);

        // The sentinel values on any target that is neither Linux nor macOS make
        // these three rows classify as Fatal there, so they only mean what they say
        // on the two platforms whose real errno values are wired in above.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert_eq!(
                classify(&Error::from_raw_os_error(super::EMFILE)),
                AcceptFault::BackOff
            );
            assert_eq!(
                classify(&Error::from_raw_os_error(super::ENFILE)),
                AcceptFault::BackOff
            );
            // Not one of the two rows the issue's own Tests section names for this
            // table (only EMFILE and ENFILE are listed there): added because
            // `classify`'s guard has three OR'd comparisons and a table exercising
            // only two of them cannot catch a mutation confined to the third. See
            // the filed follow-up on the issue corpus for the full argument.
            assert_eq!(
                classify(&Error::from_raw_os_error(super::ENOBUFS)),
                AcceptFault::BackOff
            );
        }
    }

    /// `(backoff_initial_ms, backoff_max_ms)` in, `(initial, ceiling)` out. Named so
    /// the table in `resolve_backoff_table` below reads as a table rather than a
    /// wall of nested tuples, and so pedantic clippy's `type_complexity` lint (which
    /// fires on the equivalent inline nested-tuple slice type) has nothing to flag.
    type BackoffRow = ((u32, u32), (u32, u32));

    #[test]
    fn resolve_backoff_table() {
        let rows: &[BackoffRow] = &[
            ((5, 500), (5, 500)),
            ((0, 500), (1, 500)),
            ((0, 0), (1, 1)),
            ((100, 5), (100, 100)),
            ((5, u32::MAX), (5, 5000)),
            ((u32::MAX, u32::MAX), (5000, 5000)),
        ];
        for &((initial, max), expected) in rows {
            let cfg = AcceptConfig {
                shard: 0,
                backoff_initial_ms: initial,
                backoff_max_ms: max,
            };
            assert_eq!(
                resolve_backoff(cfg),
                expected,
                "resolve_backoff(initial={initial}, max={max})"
            );
        }
        assert_eq!(MAX_BACKOFF_MS, 5_000);
    }
}
