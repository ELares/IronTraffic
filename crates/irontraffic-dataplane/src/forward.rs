// SPDX-License-Identifier: MIT OR Apache-2.0

//! The forwarding loop.
//!
//! # The rule
//!
//! Read at most one buffer, write it to completion, then read again. There is exactly
//! one buffer of data in flight per direction. Not a queue. Not a channel. If the write
//! side returns `Poll::Pending`, we do not poll the read side. Backpressure is therefore
//! structural: a client reading at 1 byte per second cannot make us buffer a 1 GiB
//! upstream response, because we cannot read from the upstream until the downstream
//! write has drained.
//!
//! An idle connection holds no pooled buffer: the chunk is acquired when a read is about
//! to happen and released as soon as a read returns `Pending` with nothing buffered.

use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use irontraffic_io::{Read, ShutdownToken, Sleep, Timer, Transport, Write};

/// How many pump rounds one poll may run before yielding to the runtime.
///
/// Without this bound a fast local pair lets one connection move gigabytes inside a
/// single poll and starve every other task on the worker.
pub const MAX_PUMP_ROUNDS: usize = 8;

/// Deadlines and caps for one forwarded connection.
#[derive(Debug, Clone, Copy)]
pub struct ForwardLimits {
    /// No bytes in either direction for this long ends the connection.
    /// From `timeouts.idle_ms`, default 60 seconds.
    pub idle: Duration,
    /// After one direction reaches end of file, the other has this long to finish.
    /// From `timeouts.half_close_ms`, default 60 seconds. Without this deadline a peer
    /// that closes one direction and stalls the other holds a connection forever.
    pub half_close: Duration,
    /// Optional cap on bytes forwarded in one direction.
    pub max_bytes_per_direction: Option<u64>,
    /// Optional absolute ceiling on the connection's whole life, regardless of
    /// progress. From `timeouts.max_lifetime_ms`, default `None` (unlimited).
    ///
    /// `idle` bounds a connection that goes silent. This bounds one that keeps
    /// making a byte of progress just often enough to reset the idle deadline,
    /// which is otherwise unbounded and is how a trickle of traffic occupies every
    /// connection slot. Armed once at the start of the connection and never
    /// re-armed; re-arming it on progress would make it a second `idle`.
    pub max_lifetime: Option<Duration>,
}

/// What one forwarded connection moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForwardStats {
    /// Bytes written to the upstream.
    pub client_to_upstream: u64,
    /// Bytes written to the client.
    pub upstream_to_client: u64,
    /// Read syscalls that returned data.
    pub reads: u64,
    /// Write syscalls that accepted data.
    pub writes: u64,
}

/// Why forwarding stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// Both directions reached end of file and both write sides were shut down. The
    /// normal ending.
    BothEof,
    /// No bytes moved in either direction within `idle`.
    IdleTimeout,
    /// One direction ended and the other did not finish within `half_close`.
    HalfCloseTimeout,
    /// The process shutdown phase reached `Closing`.
    Closing,
    /// `max_bytes_per_direction` was reached.
    ByteCap,
    /// `max_lifetime` elapsed. The connection was making progress and was ended
    /// anyway, because its absolute ceiling was reached.
    LifetimeCap,
}

/// Forwarding failed on one side.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    /// The client side reported an error.
    #[error("client side failed after {stats:?}: {source}")]
    Client {
        /// What had been forwarded when it failed.
        stats: ForwardStats,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The upstream side reported an error.
    #[error("upstream side failed after {stats:?}: {source}")]
    Upstream {
        /// What had been forwarded when it failed.
        stats: ForwardStats,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A write accepted zero bytes with data still pending, which is not progress and
    /// would otherwise spin.
    #[error("write returned zero with {remaining} bytes pending after {stats:?}")]
    WriteZero {
        /// What had been forwarded when it failed.
        stats: ForwardStats,
        /// Bytes still unwritten.
        remaining: usize,
    },
}

/// What went wrong inside one direction's pump. Private: it has no notion of which
/// physical side is which. [`map_half_error`] is what turns this into a
/// [`ForwardError`] naming the client or the upstream.
enum HalfError {
    /// The read side failed.
    Src(std::io::Error),
    /// The write side failed.
    Dst(std::io::Error),
    /// A write accepted zero bytes with data still pending.
    WriteZero {
        /// Bytes still unwritten.
        remaining: usize,
    },
}

/// Which direction a pump was moving, which is what turns `Src`/`Dst` into
/// `Client`/`Upstream`.
#[derive(Clone, Copy)]
enum Dir {
    /// client -> upstream: source is the client, destination is the upstream.
    ClientToUpstream,
    /// upstream -> client: source is the upstream, destination is the client.
    UpstreamToClient,
}

/// Maps a direction-agnostic [`HalfError`] to the [`ForwardError`] naming the
/// physical side that actually failed.
///
/// Read this twice before changing it. Getting it backwards produces a proxy that
/// blames the client for every upstream reset, which is the kind of defect that
/// survives for years because both branches "work".
fn map_half_error(dir: Dir, e: HalfError, stats: ForwardStats) -> ForwardError {
    match (dir, e) {
        (_, HalfError::WriteZero { remaining }) => ForwardError::WriteZero { stats, remaining },
        (Dir::ClientToUpstream, HalfError::Src(source))
        | (Dir::UpstreamToClient, HalfError::Dst(source)) => ForwardError::Client { stats, source },
        (Dir::ClientToUpstream, HalfError::Dst(source))
        | (Dir::UpstreamToClient, HalfError::Src(source)) => {
            ForwardError::Upstream { stats, source }
        }
    }
}

/// The per-direction state. Every field's default is the correct starting state: no
/// buffer, nothing filled, nothing written, no EOF, not shut down, not capped, zero
/// total. That is what lets the outer loop write `Half::default()`.
#[derive(Default)]
struct Half {
    /// The pooled chunk, held ONLY between a read that produced bytes and the
    /// completion of the write of those bytes. `None` when idle.
    buf: Option<irontraffic_io::buffer::PooledBuf>,
    /// Bytes in `buf` that are meaningful.
    filled: usize,
    /// Bytes of `filled` already written.
    written: usize,
    /// The source reached end of file, or the byte cap made it behave as if it had.
    src_eof: bool,
    /// The destination's write side has been shut down.
    dst_shutdown: bool,
    /// `max_bytes_per_direction` was reached, so the ending reason is `ByteCap`.
    capped: bool,
    /// Total bytes forwarded in this direction.
    total: u64,
}

// Two of these plus two transports plus the loop state is the per-connection memory
// the 2 KiB idle budget is measured against. The measured size is 80 bytes; the slack
// to 96 is there so a `bool` added later does not require re-deriving the bound.
const _: () = assert!(std::mem::size_of::<Half>() <= 96);

/// The outcome of one read attempt, isolated in its own enum so the borrow of
/// `half.buf` taken to build a [`irontraffic_io::ReadBuf`] ends before the match on
/// this value runs, letting the match arms freely reassign `half.buf`.
enum ReadOutcome {
    /// The read had no data ready.
    Pending,
    /// The read returned data, or 0 for end of file.
    Filled(usize),
    /// The read failed.
    Failed(std::io::Error),
}

/// Moves one direction forward as far as it can without blocking.
///
/// The write is always attempted before the read, which is what makes backpressure
/// structural. Returns `Poll::Ready(Ok(true))` once this direction is completely
/// finished (source EOF, or byte cap, and the destination's write side shut down).
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature is shared with forward_bidirectional's own &ForwardLimits parameter \
              and every caller and the borrow checker both depend on it; see the issue's \
              'Its exact signature' note on this function"
)]
fn pump<S, D>(
    cx: &mut Context<'_>,
    half: &mut Half,
    mut src: Pin<&mut S>,
    mut dst: Pin<&mut D>,
    limits: &ForwardLimits,
    stats: &mut ForwardStats,
    progress: &mut bool,
) -> Poll<Result<bool, HalfError>>
where
    S: Read + Unpin,
    D: Write + Unpin,
{
    // Step 1: WRITE FIRST. This ordering is what makes backpressure structural.
    while half.written < half.filled {
        let pending = half
            .buf
            .as_ref()
            .and_then(|b| b.filled().get(half.written..))
            .unwrap_or_default();
        match dst.as_mut().poll_write(cx, pending) {
            Poll::Pending => {
                // If the write side returns Poll::Pending, we do not poll the read side. This is the rule.
                return Poll::Pending;
            }
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(HalfError::WriteZero {
                    remaining: half.filled.saturating_sub(half.written),
                }));
            }
            Poll::Ready(Ok(n)) => {
                // Trusting the transport: a `poll_write` that reports more bytes
                // accepted than it was given would otherwise push `written` past
                // `filled`, underflowing the next `saturating_sub`. Clamping makes
                // the loop simply re-attempt the tail instead of panicking.
                let n = n.min(pending.len());
                half.written = half.written.saturating_add(n);
                half.total = half
                    .total
                    .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                stats.writes = stats.writes.saturating_add(1);
                *progress = true;
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(HalfError::Dst(e))),
        }
    }

    // Step 2: the buffer is fully written. Release it so an idle connection holds
    // nothing.
    //
    // MUTATION NOTE: replacing this `>` with `==`, `<`, or `>=` is a provably
    // equivalent mutant, not a test gap; a `cargo mutants` run against this
    // function reaches this line with all three and finds nothing to catch it
    // with, by construction, not by an accident of the suite:
    //   1. `half.buf = None` on the next line runs UNCONDITIONALLY regardless
    //      of which branch of this `if` ran, so the pool release is never at
    //      stake.
    //   2. The while loop above only exits when `half.written == half.filled`
    //      (its own condition is `written < filled`), so on every path that
    //      reaches this point the two fields already hold equal values,
    //      whatever that shared value is. Whether this block then leaves them
    //      at that shared value or resets both to `0`, they remain EQUAL to
    //      each other either way.
    //   3. The only place either field is read again is this same while
    //      loop's condition on the NEXT call, and an equality-preserving
    //      change to two already-equal values cannot change the answer to
    //      "are these two still equal". A later successful read overwrites
    //      both fields together (`half.filled = n; half.written = 0;`)
    //      regardless, erasing whatever this block did.
    // The reset to exactly `0` is kept because it is what the issue's own
    // design specifies and because leaving a stale nonzero pair here would be
    // a genuine landmine for a future change that reads `filled`/`written`
    // for a new purpose; the guard has no CURRENT observable effect, but
    // removing it would be a bet on every future reader of this function
    // rediscovering this exact proof.
    if half.filled > 0 {
        half.filled = 0;
        half.written = 0;
    }
    half.buf = None; // returns the chunk to the pool

    // Step 3: byte cap. Behave exactly as if the source had reached end of file, so
    // step 5 still shuts the destination's write side down and nothing is truncated.
    if let Some(cap) = limits.max_bytes_per_direction
        && half.total >= cap
    {
        half.src_eof = true;
        half.capped = true;
    }

    // Step 4: READ SECOND, and only because there is nowhere left to put anything.
    if !half.src_eof {
        if half.buf.is_none() {
            half.buf = Some(irontraffic_io::buffer::acquire());
        }
        let outcome = match half.buf.as_mut() {
            // Unreachable: the line above just made it Some. Written as a match arm
            // rather than an unwrap because unwrap_used is denied.
            None => ReadOutcome::Filled(0),
            Some(buf) => {
                let mut rb = irontraffic_io::ReadBuf::new(buf.as_mut_slice());
                match src.as_mut().poll_read(cx, rb.unfilled()) {
                    Poll::Pending => ReadOutcome::Pending,
                    Poll::Ready(Ok(())) => ReadOutcome::Filled(rb.filled().len()),
                    Poll::Ready(Err(e)) => ReadOutcome::Failed(e),
                }
            }
        };
        // `rb` and the `&mut half.buf` borrow both end here, so `half.buf` is
        // assignable again.
        match outcome {
            ReadOutcome::Pending => {
                half.buf = None; // release: nothing is buffered
                return Poll::Pending;
            }
            ReadOutcome::Failed(e) => {
                half.buf = None;
                return Poll::Ready(Err(HalfError::Src(e)));
            }
            ReadOutcome::Filled(0) => {
                // At end of file there is nothing to write, so holding a 32 KiB
                // chunk through the shutdown handshake would violate the
                // idle-holds-nothing rule for exactly the connections that are
                // closing.
                half.buf = None;
                half.src_eof = true; // fall through to step 5
            }
            ReadOutcome::Filled(n) => {
                if let Some(buf) = half.buf.as_mut() {
                    buf.set_filled(n);
                }
                half.filled = n;
                half.written = 0;
                stats.reads = stats.reads.saturating_add(1);
                *progress = true;
                return Poll::Ready(Ok(false)); // loop again to write it
            }
        }
    }

    // Step 5: src_eof is true and nothing is pending: shut the destination's write
    // side. This runs only after every byte read has been written, which is the
    // anti-truncation invariant.
    if !half.dst_shutdown {
        match dst.as_mut().poll_shutdown(cx) {
            Poll::Pending => return Poll::Pending,
            // A peer that already reset on the `Err` arm is not an error: there is
            // nothing left to shut down either way.
            Poll::Ready(Ok(()) | Err(_)) => half.dst_shutdown = true,
        }
    }

    // Step 6.
    Poll::Ready(Ok(true))
}

/// Forwards bytes between `client` and `upstream` until both directions end, a
/// deadline expires, or the process enters its closing phase.
///
/// One task, no channels, at most one 32 KiB buffer in flight per direction. The write
/// of a direction is always attempted before its read, which is what makes
/// backpressure structural rather than a watermark policy.
///
/// `timer` supplies the two deadlines; the loop reads no clock, so a test can drive it
/// with a controlled timer.
///
/// # Errors
/// [`ForwardError`], always carrying the [`ForwardStats`] accumulated before the
/// failure.
#[allow(
    clippy::too_many_lines,
    reason = "one poll_fn state machine coordinating two Half structs, three timers, and the \
              shutdown token; splitting it into helper functions would mean threading all of \
              that shared mutable state through extra parameter lists with no gain in clarity, \
              and every line here corresponds to one numbered step or timer rule documented on \
              this issue"
)]
pub async fn forward_bidirectional<C, U, T>(
    client: &mut C,
    upstream: &mut U,
    timer: &T,
    shutdown: &ShutdownToken,
    limits: &ForwardLimits,
) -> Result<(ForwardStats, EndReason), ForwardError>
where
    C: Transport,
    U: Transport,
    T: Timer,
{
    let mut c2u = Half::default();
    let mut u2c = Half::default();
    let mut stats = ForwardStats::default();

    let mut idle_sleep = timer.sleep(limits.idle);
    let mut progress_at_arm: u64 = 0;
    let mut progress_count: u64 = 0;
    let mut half_sleep: Option<Pin<Box<dyn Sleep>>> = None;
    // Armed ONCE, here, before the first poll, because it is an absolute ceiling on
    // the connection and must not be re-armed by progress. One allocation per
    // connection, and only when the ceiling is configured at all.
    let mut life_sleep: Option<Pin<Box<dyn Sleep>>> = limits.max_lifetime.map(|d| timer.sleep(d));

    let reason = poll_fn(
        |cx: &mut Context<'_>| -> Poll<Result<EndReason, ForwardError>> {
            let mut rounds = 0usize;
            loop {
                if rounds == MAX_PUMP_ROUNDS {
                    // We ran out of rounds while still making progress. Yield to the
                    // runtime and ask to be polled again immediately; the wakers of both
                    // halves may not be registered, so this self-wake is what keeps the
                    // connection alive.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                rounds += 1;
                let mut progress = false;

                let a = pump(
                    cx,
                    &mut c2u,
                    Pin::new(&mut *client),
                    Pin::new(&mut *upstream),
                    limits,
                    &mut stats,
                    &mut progress,
                );
                let b = pump(
                    cx,
                    &mut u2c,
                    Pin::new(&mut *upstream),
                    Pin::new(&mut *client),
                    limits,
                    &mut stats,
                    &mut progress,
                );

                if progress {
                    progress_count += 1;
                }

                // Consume each Poll exactly once, reducing it to a bool: the direction
                // decides which physical side an error names, and `stats` is brought up
                // to date first so the error carries what was forwarded, not zeros.
                let a_done = match a {
                    Poll::Ready(Err(e)) => {
                        stats.client_to_upstream = c2u.total;
                        stats.upstream_to_client = u2c.total;
                        return Poll::Ready(Err(map_half_error(Dir::ClientToUpstream, e, stats)));
                    }
                    Poll::Ready(Ok(done)) => done,
                    Poll::Pending => false,
                };
                let b_done = match b {
                    Poll::Ready(Err(e)) => {
                        stats.client_to_upstream = c2u.total;
                        stats.upstream_to_client = u2c.total;
                        return Poll::Ready(Err(map_half_error(Dir::UpstreamToClient, e, stats)));
                    }
                    Poll::Ready(Ok(done)) => done,
                    Poll::Pending => false,
                };

                if a_done && b_done {
                    let reason = if c2u.capped || u2c.capped {
                        EndReason::ByteCap
                    } else {
                        EndReason::BothEof
                    };
                    return Poll::Ready(Ok(reason));
                }

                // Arm the half-close timer the first time exactly one side is finished.
                if (c2u.src_eof != u2c.src_eof) && half_sleep.is_none() {
                    half_sleep = Some(timer.sleep(limits.half_close));
                }

                // Shutdown phase. `is_draining()` is deliberately NOT checked here: a
                // drain must not interrupt an in-flight byte stream, and the connection
                // handler applies the drain policy at the connection boundary.
                if shutdown.is_closing() {
                    return Poll::Ready(Ok(EndReason::Closing));
                }

                // The lifetime timer is polled before the half-close timer so that a
                // connection past its absolute ceiling reports `LifetimeCap` rather than
                // whichever deadline happens to fire in the same round.
                if life_sleep
                    .as_mut()
                    .is_some_and(|s| s.as_mut().poll(cx).is_ready())
                {
                    return Poll::Ready(Ok(EndReason::LifetimeCap));
                }

                if half_sleep
                    .as_mut()
                    .is_some_and(|s| s.as_mut().poll(cx).is_ready())
                {
                    return Poll::Ready(Ok(EndReason::HalfCloseTimeout));
                }

                if idle_sleep.as_mut().poll(cx).is_ready() {
                    if progress_count == progress_at_arm {
                        return Poll::Ready(Ok(EndReason::IdleTimeout));
                    }
                    progress_at_arm = progress_count;
                    idle_sleep = timer.sleep(limits.idle); // one allocation per idle period
                    // POLL THE NEW SLEEP IMMEDIATELY. A `Sleep` that has never been
                    // polled has registered no waker, so if the loop returns Pending
                    // before the next poll of it, the idle deadline never fires and the
                    // connection can live forever.
                    let _ = idle_sleep.as_mut().poll(cx);
                }

                if !progress {
                    // Nothing moved this round: both halves returned Pending, so both
                    // wakers are registered and there is nothing to self-wake for.
                    return Poll::Pending;
                }
            }
        },
    )
    .await?;

    stats.client_to_upstream = c2u.total;
    stats.upstream_to_client = u2c.total;

    irontraffic_runtime::with(|c| {
        c.bump(
            irontraffic_runtime::Counter::BytesToUpstream,
            stats.client_to_upstream,
        );
        c.bump(
            irontraffic_runtime::Counter::BytesToDownstream,
            stats.upstream_to_client,
        );
    });

    Ok((stats, reason))
}

#[cfg(test)]
mod tests {
    use super::{Dir, ForwardError, ForwardStats, HalfError, map_half_error};

    /// Four assertions on `map_half_error`, asserting on the variant rather than on
    /// `is_err()`: the whole point of this table is which of the two sides it names,
    /// and getting it backwards is silent because both branches still "work".
    #[test]
    fn half_errors_name_the_right_side() {
        let stats = ForwardStats::default();

        let e = map_half_error(
            Dir::ClientToUpstream,
            HalfError::Src(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            stats,
        );
        assert!(matches!(e, ForwardError::Client { .. }));

        let e = map_half_error(
            Dir::ClientToUpstream,
            HalfError::Dst(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            stats,
        );
        assert!(matches!(e, ForwardError::Upstream { .. }));

        let e = map_half_error(
            Dir::UpstreamToClient,
            HalfError::Src(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            stats,
        );
        assert!(matches!(e, ForwardError::Upstream { .. }));

        let e = map_half_error(
            Dir::UpstreamToClient,
            HalfError::Dst(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            stats,
        );
        assert!(matches!(e, ForwardError::Client { .. }));
    }
}
