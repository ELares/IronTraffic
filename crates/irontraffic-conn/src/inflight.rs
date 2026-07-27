// SPDX-License-Identifier: MIT OR Apache-2.0

//! The count of upstream exchanges in flight on one connection, and the RAII slot that
//! holds one unit of it.
//!
//! # RULE R2
//!
//! `inflight_work` is decremented when the upstream request completes or is actually
//! cancelled, not when the downstream stream closes. A `RST_STREAM` from the client
//! decrements [`crate::budget::ConnBudget::concurrent_proto`] (the protocol permits a new
//! stream) but **not** `inflight_work`. New streams are admitted only while
//! `inflight_work < max_inflight_work` (default 256).
//!
//! CERT/CC VU#767506 states the problem exactly: "the protocol is considering these reset
//! streams as closed, but the server will still be processing them."
//!
//! # The `MadeYouReset` mechanism (CVE-2025-8671)
//!
//! The attacker never sends `RST_STREAM`. Instead it sends frames that are protocol-valid
//! in isolation but force the peer to emit a stream error: a `WINDOW_UPDATE` with a zero
//! increment, a `WINDOW_UPDATE` that overflows the 2^31-1 window, a HEADERS or DATA frame
//! on a half-closed (remote) stream, a zero-length HEADERS with `END_STREAM` followed by
//! more data, a PRIORITY frame referencing itself. Each provokes an outbound `RST_STREAM`
//! while the request already dispatched upstream keeps running. Cost to the attacker: one
//! frame. Cost to the server: one full upstream request. [`crate::budget::ConnBudget`]'s
//! Rule R1 (the budget debit on a sent reset) bounds how often that can happen; this
//! module's Rule R2 bounds how much work can be in flight at once. Both are required.
//! Rate-limiting resets by count alone is the almost-right fix that leaves `MadeYouReset`
//! open.
//!
//! # A proxy's obligation on a downstream reset
//!
//! On a downstream reset a proxy MUST propagate cancellation upstream (`RST_STREAM(CANCEL)`
//! on HTTP/2, `STOP_SENDING` plus `RESET_STREAM` on HTTP/3, and on HTTP/1 either a
//! connection close or a read to completion) and only then release the work slot. So
//! [`StreamSlot`] is not merely a counter guard: it carries the cancellation state so that
//! "the slot is still held" and "cancellation is still in flight" are the same fact.
//!
//! # Why this counter is a shared atomic while `ConnBudget` is a plain field
//!
//! A monotone counter may be per-core and lossy; a BALANCE may not. A lost counter
//! increment is a rounding error. A lost balance decrement is capacity that silently
//! disappears forever, and a lost increment is over-admission. `inflight_work` is a
//! balance, so it is a cache-line-padded shared atomic behind an RAII guard with no public
//! decrement API, which is the same pattern as `InflightGuard`, `Permit`, `PooledBuf` and
//! `FlightGuard` elsewhere in the product.
//!
//! Be precise about what is shared: the gauge is shared, through an [`std::sync::Arc`], so
//! a [`StreamSlot`] can be moved to whichever task ends up finishing the exchange and
//! dropped there. The slot itself is owned by exactly one place at a time, which is why
//! [`CancelState`] is a plain field and [`StreamSlot::on_downstream_reset`] takes
//! `&mut self` rather than being an atomic. In the H2 and H3 wiring that one place is the
//! per-stream state inside the connection task, which is also where the inbound
//! `RST_STREAM` is handled, so the `&mut` is available where it is needed.
//!
//! The repository bans a manual atomic decrement outside a `Drop` impl in data-plane
//! crates (the `balance-drop-only` invariant lint), which is the mechanical enforcement
//! that there is no way to release a slot except by dropping it.
//!
//! # What holding the slot until settlement does and does not bound
//!
//! The gauge is per connection, so 256 slots is 256 upstream exchanges for THAT
//! connection: an attacker who fills it stalls only their own connection's admissions,
//! which is the fail-closed direction. Two limits live elsewhere and this type depends on
//! both:
//!
//! - An upstream exchange that never settles holds its slot forever. Nothing in this
//!   module times it out, on purpose (a timeout here would need a clock in a crate that
//!   reads none). The forwarding loop's upstream request timeout is what makes `Settled`
//!   eventually arrive, and without one a hostile or dead origin converts every reset
//!   stream into a permanently held slot. That is a bounded failure (the connection stops
//!   admitting) rather than an unbounded one, and it is why the timeout is a requirement of
//!   that later loop rather than an optional refinement.
//! - The aggregate across connections is bounded by the connection cap, not by this gauge.
//!   256 per connection times N connections is N * 256 upstream exchanges. The
//!   per-source-IP connection cap and the upstream pool's own limits are the other half,
//!   exactly as for `ConnBudget`.
//!
//! # The interaction with `ConnBudget`
//!
//! [`InflightGauge`] and [`crate::budget::ConnBudget`] are deliberately separate objects
//! and the caller wires them. Nothing in this crate calls the four steps below; they land
//! with the H2 and H3 connection tasks in a later milestone, and are documented here
//! because getting the order wrong is the part an implementer will get wrong:
//!
//! 1. On a HEADERS that opens a stream: `budget.on_frame(FrameEvent::HeadersOpen, now)?`,
//!    then `budget.open_stream()?`, then `gauge.admit()?`. Three refusals with three
//!    different responses (`GOAWAY(ENHANCE_YOUR_CALM)`, `REFUSED_STREAM`,
//!    `REFUSED_STREAM`), and the order matters: the cheapest check first.
//! 2. On a downstream `RST_STREAM`: `budget.on_frame(FrameEvent::RstStreamReceived, now)?`,
//!    then `budget.close_stream()`, then `slot.on_downstream_reset()` and, if it returned
//!    `true`, propagate cancellation upstream. The slot is not dropped.
//! 3. On a `RST_STREAM` generated locally: `budget.on_frame(FrameEvent::RstStreamSent,
//!    now)?` before sending, then the same slot handling as step 2.
//! 4. When the upstream exchange terminates: `slot.on_upstream_settled()`, then drop the
//!    slot.
//!
//! # Why this design and not the obvious alternative
//!
//! The obvious alternative is to decrement the in-flight count in the `RST_STREAM`
//! handler. It feels obviously correct, and it is `MadeYouReset`. The second alternative is
//! to give the gauge a public `release()` so the reset handler can call it "when
//! appropriate"; it loses because "when appropriate" is seven code paths and one of them
//! will forget, and because a public decrement makes the balance's correctness a matter of
//! review rather than of types. The third alternative is `Arc::strong_count` as the
//! in-flight count, which is linkerd's actual design; it loses because any incidental clone
//! permanently changes the count.

use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release};

/// The admission CAS in [`InflightGauge::admit`] retries at most this many times before
/// giving up. One connection's streams are admitted by one task in practice, so contention
/// is between the admitting task and the releasing tasks, and one retry is the realistic
/// worst case; this bound exists so a pathological contention pattern cannot spin forever.
const ADMIT_RETRY_LIMIT: u32 = 64;

/// The count of upstream exchanges in flight on one connection.
///
/// A BALANCE, not a counter: it is a cache-line-padded shared atomic with no public
/// decrement API, because a lost decrement is capacity that disappears forever. The only
/// way the count falls is by dropping a [`StreamSlot`].
#[repr(align(64))]
#[derive(Debug)]
pub struct InflightGauge {
    inflight: AtomicU32,
    max: u32,
    /// Slots dropped while their cancellation was still outstanding. An accounting
    /// observation, not a fault: the drop still decrements. See `Drop for StreamSlot`.
    unsettled_drops: AtomicU32,
}

/// Proof that one unit of upstream work is admitted.
///
/// Created at HEADERS, by [`InflightGauge::admit`]. Dropped ONLY when the upstream
/// exchange terminates or its cancellation completes. A downstream `RST_STREAM` MUST NOT
/// drop it: the reset triggers upstream cancellation, and the slot drops when that
/// finishes.
///
/// Not [`Clone`], not [`Copy`], and there is no `release` method: dropping is the only
/// release, which is what makes a missed release a compile error rather than a leak.
#[must_use = "dropping a StreamSlot releases the upstream work slot; hold it for the whole upstream exchange"]
#[derive(Debug)]
pub struct StreamSlot {
    gauge: Arc<InflightGauge>,
    cancel: CancelState,
}

/// Where a stream's cancellation stands.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CancelState {
    /// The exchange is running normally.
    Running,
    /// The downstream peer reset the stream. Cancellation has been requested upstream and
    /// has not yet completed. The slot is STILL HELD.
    CancelRequested,
    /// Upstream cancellation completed, or the upstream exchange finished on its own. The
    /// slot may now be dropped.
    Settled,
}

/// Admission was refused because too much work is already in flight.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Refuse {
    /// The limit that was hit.
    pub limit: u32,
    /// The count at the moment of refusal.
    pub inflight: u32,
}

impl InflightGauge {
    /// A gauge admitting at most `max` concurrent upstream exchanges. Default 256.
    ///
    /// `max` is not clamped: `InflightGauge::new(u32::MAX)` is legal and simply never
    /// refuses. A ceiling on the configured value belongs in the configuration layer, not
    /// here.
    #[must_use]
    pub fn new(max: u32) -> Arc<Self> {
        Arc::new(Self {
            inflight: AtomicU32::new(0),
            max,
            unsettled_drops: AtomicU32::new(0),
        })
    }

    /// Admits one unit of upstream work.
    ///
    /// 1. Load `inflight` with [`Acquire`].
    /// 2. If it is at or above `max`, return `Err(Refuse)`.
    /// 3. `compare_exchange_weak` the observed value to one more, with [`AcqRel`] on
    ///    success and [`Acquire`] on failure. On failure, retry from step 1, using the
    ///    value the failed CAS observed. Bounded at [`ADMIT_RETRY_LIMIT`] iterations.
    /// 4. Return the slot with `cancel: CancelState::Running`.
    ///
    /// A `fetch_add`-then-check-then-decrement implementation is wrong here: it briefly
    /// over-admits, and the compensating decrement would have to live outside a `Drop`
    /// impl, which the repository lint forbids for exactly this reason.
    ///
    /// # Errors
    /// `Refuse` when `max` is already reached, or when the admission CAS failed
    /// [`ADMIT_RETRY_LIMIT`] times. The caller answers `REFUSED_STREAM`.
    pub fn admit(self: &Arc<Self>) -> Result<StreamSlot, Refuse> {
        let mut cur = self.inflight.load(Acquire);
        for _ in 0..ADMIT_RETRY_LIMIT {
            if cur >= self.max {
                return Err(Refuse {
                    limit: self.max,
                    inflight: cur,
                });
            }
            // `cur < self.max` was just checked above, so `cur + 1` cannot overflow:
            // the largest value `cur` can hold here is `self.max - 1`.
            match self
                .inflight
                .compare_exchange_weak(cur, cur + 1, AcqRel, Acquire)
            {
                Ok(_) => {
                    return Ok(StreamSlot {
                        gauge: Arc::clone(self),
                        cancel: CancelState::Running,
                    });
                }
                Err(observed) => cur = observed,
            }
        }
        Err(Refuse {
            limit: self.max,
            inflight: cur,
        })
    }

    /// Current upstream exchanges in flight.
    ///
    /// [`Acquire`] so a reader after a release sees the decrement. This is a metrics
    /// accessor, never used to gate admission; `admit` re-reads under its own
    /// compare-exchange loop rather than trusting a snapshot from here.
    #[must_use]
    pub fn inflight(&self) -> u32 {
        self.inflight.load(Acquire)
    }

    /// The admission limit.
    #[must_use]
    pub const fn max(&self) -> u32 {
        self.max
    }

    /// Slots dropped while their cancellation was still outstanding. A diagnostic counter,
    /// not a balance: it only ever increases, and it is the observable form of a condition
    /// a debug-only assertion in `Drop` would have hidden from release builds and turned
    /// into an abort during an unwind.
    #[must_use]
    pub fn unsettled_drops(&self) -> u32 {
        self.unsettled_drops.load(Relaxed)
    }
}

impl StreamSlot {
    /// Records that the DOWNSTREAM peer reset this stream.
    ///
    /// Returns `true` the first time, meaning the caller MUST now propagate cancellation
    /// upstream (`RST_STREAM(CANCEL)` on HTTP/2, `STOP_SENDING` plus `RESET_STREAM` on
    /// HTTP/3, connection close or read-to-completion on HTTP/1). Returns `false` on a
    /// repeat: idempotent, so a duplicate reset does nothing.
    ///
    /// Does NOT release the slot and does not touch the gauge. That is the `MadeYouReset`
    /// fix: the work is still running upstream, so the capacity is still consumed.
    pub fn on_downstream_reset(&mut self) -> bool {
        if self.cancel == CancelState::Running {
            self.cancel = CancelState::CancelRequested;
            true
        } else {
            false
        }
    }

    /// Records that the upstream exchange terminated, or that the cancellation requested
    /// by [`StreamSlot::on_downstream_reset`] completed. After this the slot may be
    /// dropped. Call this whether termination is a normal completion, an upstream error, or
    /// the completion of a requested cancellation.
    pub fn on_upstream_settled(&mut self) {
        self.cancel = CancelState::Settled;
    }

    /// The cancellation state.
    #[must_use]
    pub const fn cancel_state(&self) -> CancelState {
        self.cancel
    }

    /// True when a downstream reset has been recorded and upstream cancellation has not yet
    /// settled.
    #[must_use]
    pub const fn cancellation_outstanding(&self) -> bool {
        matches!(self.cancel, CancelState::CancelRequested)
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        // The only decrement in this module. Release so a subsequent Acquire load (or a
        // later admit's Acquire-ordered CAS failure) observes the freed slot.
        self.gauge.inflight.fetch_sub(1, Release);
        // A diagnostic, not a balance: losing one increment here costs a metric tick, while
        // losing the `inflight` decrement above costs capacity forever, which is why only
        // one of the two uses a release ordering. No debug-only assertion here on purpose:
        // it would make the release-build behaviour this counter exists to observe
        // untestable under `cargo test`, and a panic during this drop, if it ran during an
        // unwind, would abort the process.
        if !matches!(self.cancel, CancelState::Settled) {
            self.gauge.unsettled_drops.fetch_add(1, Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::thread;

    use proptest::prelude::*;

    use super::{CancelState, InflightGauge, Refuse, StreamSlot};

    #[test]
    fn admit_and_drop() {
        // Edge case 1: a fresh gauge starts empty.
        let fresh = InflightGauge::new(256);
        assert_eq!(fresh.inflight(), 0);

        // Edge case 2: one admit brings the count to 1; dropping the slot returns it to 0.
        let gauge = InflightGauge::new(256);
        let slot = gauge
            .admit()
            .expect("a fresh gauge under its limit must admit");
        assert_eq!(gauge.inflight(), 1);
        drop(slot);
        assert_eq!(gauge.inflight(), 0);

        // Edge case 4: max: 0 refuses the very first admit.
        let zero = InflightGauge::new(0);
        assert_eq!(
            zero.admit().unwrap_err(),
            Refuse {
                limit: 0,
                inflight: 0
            }
        );

        // Edge case 5: max: 1 admits exactly one slot at a time.
        let one = InflightGauge::new(1);
        let first = one.admit().expect("the first admit under max 1 succeeds");
        assert_eq!(
            one.admit().unwrap_err(),
            Refuse {
                limit: 1,
                inflight: 1
            }
        );
        drop(first);
        let second = one
            .admit()
            .expect("after the first slot drops, a second admit under max 1 succeeds");
        drop(second);
        assert_eq!(one.inflight(), 0);

        // Edge case 11: 1000 admits and drops interleaved return the count to 0 on every
        // interleaving.
        let churn = InflightGauge::new(4);
        for _ in 0..1000 {
            let slot = churn
                .admit()
                .expect("max 4 is never exceeded by admitting one at a time");
            assert_eq!(churn.inflight(), 1);
            drop(slot);
            assert_eq!(churn.inflight(), 0);
        }

        // Edge cases 16 and 17: drop the caller's own Arc<InflightGauge> while a slot is
        // still held. `observer` stands in for a second holder of the gauge (what a real
        // connection's other state would be); the slot carries its own Arc clone, so the
        // gauge is not freed early, and the eventual decrement still lands where `observer`
        // can see it.
        let owning = InflightGauge::new(2);
        let observer = Arc::clone(&owning);
        let held = InflightGauge::admit(&owning).expect("admit under max 2 succeeds");
        drop(owning);
        assert_eq!(
            observer.inflight(),
            1,
            "the gauge must survive the caller's own Arc dropping while a slot holds a clone"
        );
        drop(held);
        assert_eq!(
            observer.inflight(),
            0,
            "the drop must still decrement after the caller's own handle is gone"
        );

        // Edge case 20: InflightGauge::new(u32::MAX) is legal and meaningless. This type
        // does not clamp its own max, and the admission check never fires in a run this
        // small.
        let unclamped = InflightGauge::new(u32::MAX);
        assert_eq!(
            unclamped.max(),
            u32::MAX,
            "InflightGauge::new must not clamp its own max"
        );
        for _ in 0..10_000 {
            let slot = unclamped
                .admit()
                .expect("a u32::MAX ceiling must never refuse in a run this small");
            drop(slot);
        }
    }

    #[test]
    fn limit_is_enforced() {
        // Edge case 3: the 256th admit succeeds and the 257th is refused with the exact
        // Refuse contents.
        let gauge = InflightGauge::new(256);
        let mut slots = Vec::new();
        for _ in 0..256 {
            slots.push(
                gauge
                    .admit()
                    .expect("each of the first 256 admits under max 256 must succeed"),
            );
        }
        assert_eq!(gauge.inflight(), 256);
        assert_eq!(
            gauge.admit().unwrap_err(),
            Refuse {
                limit: 256,
                inflight: 256
            }
        );

        // Edge case 19: an upstream that never settles holds its slot forever. Holding all
        // 256 slots without ever calling on_upstream_settled means every later admit keeps
        // failing. This is the intended fail-closed behaviour: it stalls only this
        // connection's own admissions, and the caller answers REFUSED_STREAM. The
        // forwarding loop's upstream request timeout, not anything in this module, is what
        // eventually calls on_upstream_settled; that timeout is a REQUIREMENT of that loop,
        // not an optional refinement.
        for _ in 0..10 {
            assert_eq!(
                gauge.admit().unwrap_err(),
                Refuse {
                    limit: 256,
                    inflight: 256
                }
            );
        }
        assert_eq!(slots.len(), 256);
    }

    #[test]
    fn downstream_reset_does_not_release_the_slot() {
        // CVE-2025-8671 (MadeYouReset) and CERT/CC VU#767506: "the protocol is considering
        // these reset streams as closed, but the server will still be processing them." A
        // downstream RST_STREAM must not free the in-flight slot while the upstream
        // exchange is still running. This is invariant I5.
        let gauge = InflightGauge::new(4);
        let mut slot = gauge.admit().expect("admit under max 4 succeeds");
        assert_eq!(gauge.inflight(), 1);
        assert!(
            !slot.cancellation_outstanding(),
            "a freshly admitted slot has no cancellation outstanding"
        );

        // Edge case 6: the first reset requests cancellation and leaves the slot held.
        assert!(
            slot.on_downstream_reset(),
            "the first downstream reset must request cancellation"
        );
        assert_eq!(slot.cancel_state(), CancelState::CancelRequested);
        assert!(
            slot.cancellation_outstanding(),
            "a requested cancellation must read as outstanding until it settles"
        );
        assert_eq!(
            gauge.inflight(),
            1,
            "I5: a downstream RST_STREAM must never release the slot"
        );

        // Edge case 7: a second reset on the same slot is idempotent.
        assert!(
            !slot.on_downstream_reset(),
            "a repeat downstream reset must not report a fresh cancellation request"
        );
        assert_eq!(slot.cancel_state(), CancelState::CancelRequested);
        assert!(slot.cancellation_outstanding());
        assert_eq!(gauge.inflight(), 1);

        // Edge case 8: the count falls only at the eventual drop, not at
        // on_upstream_settled.
        slot.on_upstream_settled();
        assert_eq!(slot.cancel_state(), CancelState::Settled);
        assert!(
            !slot.cancellation_outstanding(),
            "settling the cancellation must clear the outstanding flag"
        );
        assert_eq!(
            gauge.inflight(),
            1,
            "settling the cancellation does not itself release the slot"
        );
        drop(slot);
        assert_eq!(gauge.inflight(), 0, "only the drop releases the slot");
    }

    #[test]
    fn normal_completion() {
        // Edge case 9: on_upstream_settled without any prior reset marks the slot Settled,
        // and dropping it decrements without touching unsettled_drops.
        let gauge = InflightGauge::new(4);
        let mut slot = gauge.admit().expect("admit under max 4 succeeds");
        slot.on_upstream_settled();
        assert_eq!(slot.cancel_state(), CancelState::Settled);
        assert!(!slot.cancellation_outstanding());
        assert_eq!(gauge.inflight(), 1);
        drop(slot);
        assert_eq!(gauge.inflight(), 0);
        assert_eq!(
            gauge.unsettled_drops(),
            0,
            "a settled drop must not be counted as unsettled"
        );
    }

    #[test]
    fn drop_while_cancel_outstanding_still_decrements() {
        // Edge case 10: dropping a slot whose cancellation never settled must still
        // decrement (no build may leak a slot) and must bump unsettled_drops by exactly
        // one. No #[cfg] guard: this must run in the default debug profile, which is
        // exactly the case a debug-only assertion in Drop would have made untestable.
        let gauge = InflightGauge::new(4);
        let mut slot = gauge.admit().expect("admit under max 4 succeeds");
        assert!(slot.on_downstream_reset());
        assert_eq!(gauge.unsettled_drops(), 0);
        drop(slot);
        assert_eq!(
            gauge.inflight(),
            0,
            "the drop must always decrement, settled or not"
        );
        assert_eq!(
            gauge.unsettled_drops(),
            1,
            "an unsettled drop must be counted exactly once"
        );
    }

    // Edge case 18, strengthened per issue #659: the churn phase must run against a
    // gauge sized to the concurrency it actually generates, not against the `gauge:
    // 256` above, which two threads doing admit-then-immediate-drop never come close
    // to filling. `max_seen <= 256` there had 254 units of headroom and could not tell
    // the CAS loop this module requires apart from the fetch_add-then-check-then-
    // fetch_sub implementation the "## Do NOT" list forbids by name, which briefly
    // over-admits. Confirmed by execution: swapping in that forbidden implementation
    // left this whole test suite, including the old assertion, green.
    // `CHURN_THREADS` exceeds `CHURN_MAX` here, so a real over-admission is observable
    // (a bug of this shape peaks at `CHURN_THREADS`, not at `CHURN_MAX`).
    //
    // Each churner also drives `StreamSlot::on_downstream_reset` at a different point
    // in its own lifecycle, so a hostile downstream RST_STREAM landing at any point
    // relative to the admit/settle/drop sequence cannot corrupt the shared balance:
    //   thread 0: reset immediately after admit, before any other transition
    //             ("before any work");
    //   thread 1: reset after yielding a few times, still before its drop ("after work
    //             is credited but before it is debited");
    //   thread 2: reset twice in a row (on_downstream_reset is idempotent: the second
    //             call must return false and must not change the state or the gauge);
    //   threads 3.. : no reset at all, so those iterations complete and drop while
    //             threads 0-2 are resetting, which is "reset concurrent with
    //             completion": with `CHURN_THREADS` racing under one barrier, one
    //             thread's on_downstream_reset can land at the same instant as another
    //             thread's Drop.
    // Under this tight, contended max, some admits also fail outright with Refuse,
    // which is "a reset on a slot that was never opened": there is no StreamSlot to
    // call on_downstream_reset on, and the balance must be untouched by that attempt,
    // exactly like every other Refuse in this file.
    fn churn_with_interleaved_resets() {
        const CHURN_MAX: u32 = 3;
        const CHURN_THREADS: u32 = 8;
        let churn = InflightGauge::new(CHURN_MAX);
        let churn_start = Arc::new(Barrier::new(CHURN_THREADS as usize + 1));
        let stop = Arc::new(AtomicBool::new(false));
        let max_seen = Arc::new(AtomicU32::new(0));

        let reader = {
            let gauge = Arc::clone(&churn);
            let start = Arc::clone(&churn_start);
            let stop = Arc::clone(&stop);
            let max_seen = Arc::clone(&max_seen);
            thread::spawn(move || {
                start.wait();
                while !stop.load(Ordering::Relaxed) {
                    max_seen.fetch_max(gauge.inflight(), Ordering::Relaxed);
                }
            })
        };

        let churners: Vec<_> = (0..CHURN_THREADS)
            .map(|id| {
                let gauge = Arc::clone(&churn);
                let start = Arc::clone(&churn_start);
                thread::spawn(move || {
                    start.wait();
                    for _ in 0..2000 {
                        let Ok(mut slot) = gauge.admit() else {
                            // A slot never opened: nothing to reset, balance untouched.
                            continue;
                        };
                        match id {
                            0 => {
                                assert!(
                                    slot.on_downstream_reset(),
                                    "the first reset on a running slot must request cancellation"
                                );
                            }
                            1 => {
                                for _ in 0..4 {
                                    thread::yield_now();
                                }
                                assert!(
                                    slot.on_downstream_reset(),
                                    "the first reset on a running slot must request cancellation"
                                );
                            }
                            2 => {
                                assert!(slot.on_downstream_reset());
                                assert!(
                                    !slot.on_downstream_reset(),
                                    "a repeat downstream reset must be idempotent"
                                );
                            }
                            _ => {}
                        }
                        slot.on_upstream_settled();
                        drop(slot);
                    }
                })
            })
            .collect();

        for handle in churners {
            handle.join().expect("a churning thread must not panic");
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().expect("the reader thread must not panic");

        let seen = max_seen.load(Ordering::Relaxed);
        assert!(
            seen <= CHURN_MAX,
            "inflight() must never be observed above max ({CHURN_MAX}), even while \
             downstream resets race completion; a value here (especially one near \
             u32::MAX, which is what an unsigned underflow from an extra fetch_sub \
             would produce) means the balance was corrupted, but saw {seen}"
        );
        assert_eq!(
            churn.inflight(),
            0,
            "the balance must return to its starting value of 0 once every churned \
             slot is dropped, regardless of how many of them were reset first"
        );
    }

    #[test]
    fn concurrent_admission_respects_the_limit() {
        // Edge case 12: two threads race 300 admits each against max: 256, synchronised to
        // start together with a barrier. Exactly 256 must succeed in total, and the gauge
        // must show exactly 256 while every winning slot is still held.
        let gauge = InflightGauge::new(256);
        let start = Arc::new(Barrier::new(2));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let gauge = Arc::clone(&gauge);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    let mut won = Vec::new();
                    for _ in 0..300 {
                        if let Ok(slot) = gauge.admit() {
                            won.push(slot);
                        }
                    }
                    won
                })
            })
            .collect();

        let mut all_slots = Vec::new();
        for handle in handles {
            all_slots.extend(handle.join().expect("an admitting thread must not panic"));
        }
        assert_eq!(
            all_slots.len(),
            256,
            "exactly max admits must succeed across both racing threads"
        );
        assert_eq!(
            gauge.inflight(),
            256,
            "the gauge must show exactly max while every winning slot is held"
        );
        drop(all_slots);
        assert_eq!(gauge.inflight(), 0);

        // Edge case 18: while several threads race admit-then-drop cycles, a reader
        // thread repeatedly reads inflight() and must never observe a value above max.
        // See churn_with_interleaved_resets for why this runs against its own tightly
        // sized gauge rather than reusing `gauge` above (issue #659), and for how it
        // interleaves downstream resets at each transition point.
        churn_with_interleaved_resets();

        // The second half of edge case 18: a read taken strictly after a slot's drop has
        // completed (the drop call itself, not a racy poll) must see the decrement.
        let slot = gauge.admit().expect("admit after the churn phase succeeds");
        assert_eq!(gauge.inflight(), 1);
        drop(slot);
        assert_eq!(
            gauge.inflight(),
            0,
            "a read after the drop has completed must see the decrement"
        );
    }

    #[test]
    fn cross_thread_release() {
        // Edge case 13: a slot admitted on this thread and dropped on a different one still
        // decrements correctly.
        let gauge = InflightGauge::new(4);
        let slot = gauge.admit().expect("admit under max 4 succeeds");
        assert_eq!(gauge.inflight(), 1);

        let handle = thread::spawn(move || {
            drop(slot);
        });
        handle.join().expect("the releasing thread must not panic");

        assert_eq!(
            gauge.inflight(),
            0,
            "a cross-thread drop must still release the slot"
        );
    }

    #[test]
    fn panic_unwind_releases() {
        // Edge case 14: a slot dropped while unwinding through a panic still decrements.
        let gauge = InflightGauge::new(4);
        let panic_gauge = Arc::clone(&gauge);
        let result = panic::catch_unwind(move || {
            let _slot = panic_gauge.admit().expect("admit under max 4 succeeds");
            assert_eq!(panic_gauge.inflight(), 1);
            panic!("deliberate panic while a slot is held, to unwind through its Drop");
        });
        assert!(
            result.is_err(),
            "the closure must actually panic for this test to prove anything"
        );
        assert_eq!(
            gauge.inflight(),
            0,
            "the slot must release even when dropped during a panic unwind"
        );
    }

    /// One step of the `prop_returns_to_zero` state machine. `Admit` carries no index: it
    /// fills the first free handle in the fixed pool, if any. `Reset`, `Settle` and `Drop`
    /// carry an index into that pool; the property test below applies them only when the
    /// indexed handle currently holds a slot, exactly the runtime guard
    /// `prop_registry_conservation` already uses in `registry.rs` for the same "only a
    /// valid subset of generated operations has an effect" shape.
    #[derive(Debug, Clone, Copy)]
    enum InflightOp {
        Admit,
        Reset(usize),
        Settle(usize),
        DropOp(usize),
    }

    /// The fixed pool size the state machine below holds handles in.
    const POOL: usize = 32;

    fn inflight_op_strategy() -> impl Strategy<Value = InflightOp> {
        prop_oneof![
            4 => Just(InflightOp::Admit),
            1 => (0..POOL).prop_map(InflightOp::Reset),
            1 => (0..POOL).prop_map(InflightOp::Settle),
            1 => (0..POOL).prop_map(InflightOp::DropOp),
        ]
    }

    proptest! {
        #[test]
        fn prop_returns_to_zero(ops in prop::collection::vec(inflight_op_strategy(), 0..=500)) {
            // Property: for any generated sequence of Admit/Reset/Settle/Drop over up to 32
            // slot handles, with max: 8, the count never exceeds 8, a Reset never changes
            // the count, and after every remaining slot is dropped the count is exactly 0.
            let gauge = InflightGauge::new(8);
            let mut slots: [Option<StreamSlot>; POOL] = std::array::from_fn(|_| None);

            for op in ops {
                match op {
                    InflightOp::Admit => {
                        if let Some(free) = slots.iter_mut().find(|s| s.is_none())
                            && let Ok(slot) = gauge.admit()
                        {
                            *free = Some(slot);
                        }
                    }
                    InflightOp::Reset(i) => {
                        if let Some(Some(slot)) = slots.get_mut(i) {
                            let before = gauge.inflight();
                            slot.on_downstream_reset();
                            prop_assert_eq!(
                                gauge.inflight(),
                                before,
                                "a downstream reset must never change inflight()"
                            );
                        }
                    }
                    InflightOp::Settle(i) => {
                        if let Some(Some(slot)) = slots.get_mut(i) {
                            slot.on_upstream_settled();
                        }
                    }
                    InflightOp::DropOp(i) => {
                        if let Some(slot_ref) = slots.get_mut(i) {
                            slot_ref.take();
                        }
                    }
                }
                prop_assert!(gauge.inflight() <= 8, "inflight() must never exceed max");
            }

            for slot in &mut slots {
                slot.take();
            }
            prop_assert_eq!(gauge.inflight(), 0, "every slot dropped must return the gauge to zero");
        }
    }
}
