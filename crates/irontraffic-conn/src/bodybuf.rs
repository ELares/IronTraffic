// SPDX-License-Identifier: MIT OR Apache-2.0

//! The global body buffer semaphore: statically declared buffering ceilings and the
//! single process-wide byte budget every buffered body draws from.
//!
//! # Bodies stream by default
//!
//! Bytes move from the downstream reader to the upstream writer through a bounded
//! ring, with backpressure propagated by the protocol's own flow control. A feature
//! that needs to look at a body (a firewall, a body transform, a request validator)
//! declares how much of it that feature may hold as [`BodyInspection`], fixed at
//! route-compile time. A per-request buffering decision would let the attacker
//! choose the expensive path by setting a header, and it would mean the pipeline
//! could no longer be compiled ahead of time, so the declaration is a ceiling rather
//! than a runtime choice.
//!
//! # Why one global budget
//!
//! Buffering every body so a feature can always inspect it makes `c` concurrent slow
//! uploads times the per-body ceiling an immediate out-of-memory condition. Every
//! buffered body therefore draws from one process-wide byte budget, [`BufferPool`],
//! sized by the caller (typically a fraction of the cgroup memory limit; this module
//! reads no system limit itself). A per-worker pool would either waste memory when
//! traffic is skewed or, sized generously enough to never waste it, permit the same
//! unbounded total the single budget exists to prevent.
//!
//! # Why the default on overflow is 413
//!
//! Fail-open overflow is a security bypass an attacker triggers by choosing a body
//! size: send one byte past the inspecting feature's window and inspection stops.
//! [`OnExceed::Reject413`] is therefore the default; [`OnExceed::StreamThroughUninspected`]
//! is opt-in, and the caller MUST log it at WARN and count it every time it fires,
//! because an operator who accepted the fail-open trade for one legacy endpoint
//! needs to see when it is actually exercised.
//!
//! # Reserving the ceiling up front
//!
//! [`BodyInspection::lease_size`] reserves the WHOLE declared ceiling before the
//! first body byte arrives, so a route declaring `Whole(10 MiB)` reserves 10 MiB for
//! a request whose body turns out to be 100 bytes. That is deliberate: an admitted
//! request can always be completed, and the budget never over-commits. The cost is
//! that `total / ceiling` concurrent requests exhaust the pool regardless of their
//! real sizes; the complementary control is a per-route concurrency limit, which is
//! not delivered here.
//!
//! # What this module is not
//!
//! It never reads a socket, never reads a system limit (the caller computes and
//! passes `total`), never logs, and never reads a clock: the caller polls
//! [`BufferPool::try_acquire`] under its own deadline instead of this module running
//! a wait queue with a timer. Keeping the clock and the logger out of this file is
//! what keeps it free of I/O.
//!
//! # Enforcing against the running count, never the declared length
//!
//! [`BodyInspection::observe`] takes the running octet count the caller has actually
//! received, never the declared `Content-Length`: the declared value is attacker
//! controlled, so a check against it is not a check at all.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A byte count, in a newtype so a byte total is never confused with a count of
/// items.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// Bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// A size in kibibytes. Saturates rather than overflowing for an
    /// unreasonably large `n`.
    #[must_use]
    pub const fn kib(n: u64) -> ByteSize {
        ByteSize(n.saturating_mul(1024))
    }

    /// A size in mebibytes. Saturates rather than overflowing for an
    /// unreasonably large `n`.
    #[must_use]
    pub const fn mib(n: u64) -> ByteSize {
        ByteSize(n.saturating_mul(1024 * 1024))
    }
}

/// How much of a body a feature may hold. Declared at route-compile time and fixed
/// for the life of the compiled route: a per-request decision would let the
/// attacker choose the expensive path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Buffering {
    /// Stream through. Hold nothing. The default for every route with no
    /// body-inspecting feature.
    None,
    /// Hold at most `n` bytes at a time, a sliding window over the body.
    Window(ByteSize),
    /// Hold the whole body, up to `n` bytes.
    Whole(ByteSize),
}

/// What to do when a body exceeds the declared ceiling.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OnExceed {
    /// Answer 413 and close. The default.
    Reject413,
    /// Forward the body without inspecting it. Opt-in, and the caller MUST log it
    /// at WARN and count it, because it converts a security feature into a
    /// suggestion.
    StreamThroughUninspected,
}

impl Default for OnExceed {
    /// `Reject413`.
    fn default() -> Self {
        OnExceed::Reject413
    }
}

/// A body-inspecting feature's declaration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BodyInspection {
    /// The ceiling. `Buffering::None` means the feature does not inspect bodies.
    pub buffering: Buffering,
    /// What happens when a body exceeds the ceiling.
    pub on_exceed: OnExceed,
}

impl BodyInspection {
    /// No inspection: stream through, hold nothing.
    pub const NONE: BodyInspection = BodyInspection {
        buffering: Buffering::None,
        on_exceed: OnExceed::Reject413,
    };

    /// Whether the body has exceeded the declared ceiling, and what to do about it.
    ///
    /// `received` MUST be the RUNNING OCTET COUNT, never the declared
    /// `Content-Length`: the declared value is attacker controlled.
    #[must_use]
    pub fn observe(&self, received: ByteSize) -> Option<OverflowAction> {
        // Every arm below is written with its `Buffering::` prefix. A bare `None`
        // pattern would resolve to `Option::None` from the prelude rather than to
        // `Buffering::None`, so leaving the prefix off does not compile.
        let ceiling = match self.buffering {
            Buffering::None => return None,
            Buffering::Window(n) | Buffering::Whole(n) => n,
        };
        if received <= ceiling {
            // This `None` IS `Option::None`: nothing to do, the body is within
            // the declared ceiling.
            return None;
        }
        Some(match self.on_exceed {
            OnExceed::Reject413 => OverflowAction::Reject,
            OnExceed::StreamThroughUninspected => OverflowAction::StreamThrough,
        })
    }

    /// Bytes to reserve from the global budget for this declaration. 0 for `None`.
    #[must_use]
    pub const fn lease_size(&self) -> ByteSize {
        match self.buffering {
            Buffering::None => ByteSize(0),
            Buffering::Window(n) | Buffering::Whole(n) => n,
        }
    }

    /// Combines two declarations on one route: the maximum ceiling and the
    /// strictest `on_exceed`, with `Buffering::None` short circuiting to the other
    /// side so that `NONE` is a true identity. Associative and commutative.
    ///
    /// A `const fn`, which is why this compares `Buffering` and `OnExceed` with
    /// `matches!` rather than `==`, and compares ceilings as raw `u64`s rather
    /// than as `ByteSize`: the derived `PartialEq` and `PartialOrd` these types
    /// carry are ordinary trait methods, not `const fn`, and are not callable
    /// from inside a `const fn` on stable Rust.
    #[must_use]
    pub const fn combine(a: BodyInspection, b: BodyInspection) -> BodyInspection {
        // Step 1: a declaration that inspects nothing has no opinion about
        // overflow, so its `on_exceed` (`Reject413`, see `NONE` above) must
        // never be consulted. Without this short circuit, `combine(x, NONE)`
        // would run `NONE`'s `Reject413` through the strictest-wins rule below
        // and could change a `StreamThroughUninspected` `x` into a value that is
        // not `x`, which would make the identity property false.
        if matches!(a.buffering, Buffering::None) {
            return b;
        }
        if matches!(b.buffering, Buffering::None) {
            return a;
        }

        // Step 2: the larger ceiling wins, and its kind wins with it; on a tie,
        // `Whole` wins over `Window` because holding the whole body is the
        // stronger requirement. Neither side is `Buffering::None` here, so both
        // matches below always take their second arm; the first arm exists only
        // because the match must stay exhaustive over the whole enum.
        let a_bytes = match a.buffering {
            Buffering::None => 0,
            Buffering::Window(ByteSize(n)) | Buffering::Whole(ByteSize(n)) => n,
        };
        let b_bytes = match b.buffering {
            Buffering::None => 0,
            Buffering::Window(ByteSize(n)) | Buffering::Whole(ByteSize(n)) => n,
        };
        let buffering = if a_bytes > b_bytes {
            a.buffering
        } else if b_bytes > a_bytes {
            b.buffering
        } else if matches!(a.buffering, Buffering::Whole(_)) {
            a.buffering
        } else {
            b.buffering
        };

        // Step 3: computed independently of step 2. The strictest `on_exceed`
        // wins regardless of which side owns the winning ceiling: one feature
        // configured to fail closed must not be downgraded by a sibling
        // configured to fail open.
        let on_exceed = if matches!(a.on_exceed, OnExceed::Reject413)
            || matches!(b.on_exceed, OnExceed::Reject413)
        {
            OnExceed::Reject413
        } else {
            OnExceed::StreamThroughUninspected
        };

        BodyInspection {
            buffering,
            on_exceed,
        }
    }
}

/// The one process-wide byte budget every buffered body draws from.
///
/// One cache-line-aligned atomic for the whole process. The alignment matters
/// because every buffered body on every worker touches it, so it must not share a
/// line with anything else.
#[repr(align(64))]
#[derive(Debug)]
pub struct BufferPool {
    outstanding: AtomicU64,
    total: u64,
}

impl BufferPool {
    /// A pool of `total` bytes. The caller computes `total` (typically a fraction
    /// of the cgroup memory limit); this crate reads no system limits.
    #[must_use]
    pub fn new(total: ByteSize) -> Arc<Self> {
        Arc::new(Self {
            outstanding: AtomicU64::new(0),
            total: total.0,
        })
    }

    /// Reserves `bytes` of the global budget.
    ///
    /// A zero-byte request always succeeds without touching the counter, so a
    /// streaming route pays nothing.
    ///
    /// An associated function taking `&Arc<Self>` rather than a `&self` method,
    /// because the returned [`BufferLease`] must own its own `Arc` clone of the
    /// pool so it can release its bytes from `Drop` no matter where it ends up
    /// living. Call this as `BufferPool::try_acquire(&pool, bytes)`.
    ///
    /// # Errors
    /// [`BudgetExhausted`] when the budget cannot cover the request, or when the
    /// compare-and-swap lost 64 consecutive races with other callers. The caller
    /// then waits under its own deadline or sheds with 503, per policy.
    pub fn try_acquire(self: &Arc<Self>, bytes: ByteSize) -> Result<BufferLease, BudgetExhausted> {
        // Step 1: the free path. `Buffering::None`'s `lease_size()` is always
        // zero, so a streaming route never reaches the loop below at all.
        if bytes.0 == 0 {
            return Ok(BufferLease {
                pool: Arc::clone(self),
                bytes: 0,
            });
        }

        for _ in 0..64 {
            // Step 2.
            let outstanding = self.outstanding.load(Ordering::Acquire);
            // Step 3. `checked_add` rather than `saturating_add`: with a
            // saturating sum, a `total` of `u64::MAX` (the only spelling of
            // "unlimited" available, since `ByteSize::kib`/`mib` themselves
            // saturate onto exactly `u64::MAX` for a large enough caller
            // value) makes `outstanding + bytes.0` clamp to `u64::MAX` for
            // every request, so `after > self.total` can never be true and
            // the guard stops firing: the pool over-issues past its cap and
            // `outstanding` is later driven to a wrapped, unrecoverable
            // value by the leases' own releases on drop. `checked_add`
            // returning `None` means the true, unclamped sum overflowed
            // `u64`, which is itself proof the request cannot fit any finite
            // budget, so it is rejected the same as an over-budget request.
            let Some(after) = outstanding.checked_add(bytes.0) else {
                return Err(BudgetExhausted {
                    requested: bytes.0,
                    outstanding,
                    total: self.total,
                });
            };
            if after > self.total {
                return Err(BudgetExhausted {
                    requested: bytes.0,
                    outstanding,
                    total: self.total,
                });
            }
            // Step 4.
            let won = self
                .outstanding
                .compare_exchange_weak(outstanding, after, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
            if won {
                debug_assert!(
                    after <= self.total,
                    "outstanding must never exceed total after a successful acquire"
                );
                // Step 5.
                return Ok(BufferLease {
                    pool: Arc::clone(self),
                    bytes: bytes.0,
                });
            }
            // Another acquire or release won the race on the same word: loop
            // around, re-read, and retry from step 2.
        }

        let outstanding = self.outstanding.load(Ordering::Acquire);
        Err(BudgetExhausted {
            requested: bytes.0,
            outstanding,
            total: self.total,
        })
    }

    /// Bytes currently reserved.
    #[must_use]
    pub fn outstanding(&self) -> u64 {
        self.outstanding.load(Ordering::Acquire)
    }

    /// The total budget.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }
}

/// Proof that `bytes` of the global budget are reserved.
///
/// A BALANCE, so there is no public method that gives the bytes back: dropping
/// the lease is the only way to return them. This type deliberately implements
/// neither `Clone` nor `Copy`, because either would let a caller hold two handles
/// to the same reservation while only one of them is ever dropped, silently
/// under-releasing the budget.
#[must_use = "dropping a BufferLease returns its bytes to the global budget"]
#[derive(Debug)]
pub struct BufferLease {
    pool: Arc<BufferPool>,
    bytes: u64,
}

impl BufferLease {
    /// Bytes this lease reserves.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for BufferLease {
    /// Returns the leased bytes to the pool. This is the only atomic decrement
    /// anywhere in this file: the balance-drop-only invariant lint requires
    /// exactly that for a hot-path balance, because a decrement outside `Drop`
    /// is a release that some call site can forget.
    fn drop(&mut self) {
        // EQUIVALENT MUTANT, verified by hand rather than by a test:
        // `cargo mutants` reports replacing this `>` with `>=` as missed.
        // `self.bytes` is a `u64`, so `self.bytes >= 0` is true unconditionally
        // and the mutation removes this guard in effect, always performing the
        // atomic subtract below with a zero operand whenever `self.bytes` is
        // 0. Subtracting zero from an atomic changes no bit of its value for
        // any observer under any interleaving: it is the identity operation,
        // not merely a common case that happens to look unchanged. No
        // assertion on `outstanding()`, at any point from any thread, can
        // ever distinguish the two versions, so this is not a gap for a test
        // to close. The guard is kept anyway, and is what the benchmark's
        // zero-byte budget measures: it replaces a maybe-contended atomic
        // read-modify-write on the shared `outstanding` counter with a
        // predictable branch on the streaming path. That claim is scoped to
        // `outstanding` specifically, not to every atomic operation the
        // streaming path performs: `try_acquire`'s zero-byte return still
        // does `Arc::clone(self)`, and this drop still runs the matching
        // `Arc` decrement, each an uncontended atomic refcount update. The
        // fast path avoids the one atomic this module's own budget is
        // shared and contended on, not atomics in general.
        if self.bytes > 0 {
            self.pool
                .outstanding
                .fetch_sub(self.bytes, Ordering::Release);
        }
    }
}

/// What the caller must do when a body exceeds its declared ceiling.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OverflowAction {
    /// Answer 413 Content Too Large and close.
    Reject,
    /// Forward without inspecting. The caller MUST log at WARN and increment
    /// `body_inspection_bypassed_total`.
    StreamThrough,
}

/// The global budget is exhausted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BudgetExhausted {
    /// Bytes requested.
    pub requested: u64,
    /// Bytes currently outstanding.
    pub outstanding: u64,
    /// The total budget.
    pub total: u64,
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use proptest::prelude::*;

    use super::{
        BodyInspection, BudgetExhausted, BufferPool, Buffering, ByteSize, OnExceed, OverflowAction,
    };

    #[test]
    fn observe_ceilings() {
        // Edge case 1: `NONE` never inspects, no matter what it is shown.
        assert_eq!(BodyInspection::NONE.lease_size(), ByteSize(0));
        assert_eq!(BodyInspection::NONE.observe(ByteSize(0)), None);
        assert_eq!(BodyInspection::NONE.observe(ByteSize(u64::MAX)), None);

        let window_1kib_reject = BodyInspection {
            buffering: Buffering::Window(ByteSize::kib(1)),
            on_exceed: OnExceed::Reject413,
        };

        // `lease_size` for a `Window` ceiling reserves the whole window, the
        // same as it would for a `Whole` ceiling of the same size: the
        // window is resident all at once. Asserted here directly, on a
        // `Window` value specifically, because every other `lease_size`
        // assertion in this file exercises `NONE` or `Whole`; a mutation
        // that made `Window`'s arm return something other than `n` (for
        // example always 0, as if it behaved like `Buffering::None`) would
        // otherwise pass this whole test module undetected.
        assert_eq!(window_1kib_reject.lease_size(), ByteSize::kib(1));

        // Edge case 2: strictly under the ceiling.
        assert_eq!(window_1kib_reject.observe(ByteSize(1023)), None);

        // Edge case 3: exactly at the ceiling is inclusive, not an overflow.
        assert_eq!(window_1kib_reject.observe(ByteSize(1024)), None);

        // Edge case 4: one byte past the ceiling rejects under the default
        // on_exceed.
        assert_eq!(
            window_1kib_reject.observe(ByteSize(1025)),
            Some(OverflowAction::Reject)
        );

        // Edge case 5: the same overage streams through when the declaration
        // opted into that.
        let whole_1kib_stream = BodyInspection {
            buffering: Buffering::Whole(ByteSize::kib(1)),
            on_exceed: OnExceed::StreamThroughUninspected,
        };
        assert_eq!(
            whole_1kib_stream.observe(ByteSize(1025)),
            Some(OverflowAction::StreamThrough)
        );

        // Edge case 6: `Window(0)` accepts an empty body but rejects any
        // nonzero one immediately.
        let window_zero = BodyInspection {
            buffering: Buffering::Window(ByteSize(0)),
            on_exceed: OnExceed::Reject413,
        };
        assert_eq!(window_zero.observe(ByteSize(0)), None);
        assert_eq!(
            window_zero.observe(ByteSize(1)),
            Some(OverflowAction::Reject)
        );

        // Edge case 7: the running octet count is what is judged, never the
        // declared Content-Length. A request that declared Content-Length: 10
        // but actually sent 100 octets under Whole(50) is judged on the 100.
        let whole_50 = BodyInspection {
            buffering: Buffering::Whole(ByteSize(50)),
            on_exceed: OnExceed::Reject413,
        };
        let declared_content_length: u64 = 10;
        let actually_received = ByteSize(100);
        assert_eq!(
            whole_50.observe(actually_received),
            Some(OverflowAction::Reject)
        );
        // The declared value plays no role in the call above: it is not even
        // passed to `observe`. This asserts the two differ so the point of the
        // edge case (100 octets trips a 50-byte ceiling even though the
        // declaration named 10) cannot be satisfied by accident by a
        // declared-length value that happened to already exceed the ceiling.
        assert_ne!(declared_content_length, actually_received.bytes());
        assert!(declared_content_length <= whole_50.lease_size().bytes());
    }

    #[test]
    fn default_is_reject() {
        assert_eq!(OnExceed::default(), OnExceed::Reject413);
        assert_eq!(BodyInspection::NONE.on_exceed, OnExceed::Reject413);
    }

    #[test]
    fn combine_rules() {
        let window_1kib_reject = BodyInspection {
            buffering: Buffering::Window(ByteSize::kib(1)),
            on_exceed: OnExceed::Reject413,
        };
        // Edge case 8: NONE combined with an inspecting declaration yields that
        // declaration, unchanged, from either side.
        assert_eq!(
            BodyInspection::combine(BodyInspection::NONE, window_1kib_reject),
            window_1kib_reject
        );
        assert_eq!(
            BodyInspection::combine(window_1kib_reject, BodyInspection::NONE),
            window_1kib_reject
        );

        // Edge case 8b: the identity case that fails without the None short
        // circuit. NONE's own on_exceed is Reject413 (asserted in
        // default_is_reject above), so if it were consulted here it would drag
        // a StreamThroughUninspected sibling toward Reject413. It must not.
        let whole_1kib_stream = BodyInspection {
            buffering: Buffering::Whole(ByteSize::kib(1)),
            on_exceed: OnExceed::StreamThroughUninspected,
        };
        assert_eq!(
            BodyInspection::combine(BodyInspection::NONE, whole_1kib_stream),
            whole_1kib_stream
        );

        // Edge case 9: the larger ceiling wins, and its kind wins with it. 2
        // KiB beats 1 KiB here regardless of which side is Window and which is
        // Whole.
        let window_1kib = BodyInspection {
            buffering: Buffering::Window(ByteSize::kib(1)),
            on_exceed: OnExceed::Reject413,
        };
        let whole_2kib = BodyInspection {
            buffering: Buffering::Whole(ByteSize::kib(2)),
            on_exceed: OnExceed::Reject413,
        };
        assert_eq!(BodyInspection::combine(window_1kib, whole_2kib), whole_2kib);
        assert_eq!(BodyInspection::combine(whole_2kib, window_1kib), whole_2kib);

        // The equal-ceiling tie: Whole wins over Window, independent of
        // argument order.
        let whole_1kib_reject = BodyInspection {
            buffering: Buffering::Whole(ByteSize::kib(1)),
            on_exceed: OnExceed::Reject413,
        };
        assert_eq!(
            BodyInspection::combine(window_1kib_reject, whole_1kib_reject).buffering,
            Buffering::Whole(ByteSize::kib(1))
        );
        assert_eq!(
            BodyInspection::combine(whole_1kib_reject, window_1kib_reject).buffering,
            Buffering::Whole(ByteSize::kib(1))
        );

        // Edge case 10: the strictest on_exceed wins, independent of the
        // ceiling rule. `bigger_but_lax` has the larger ceiling AND the laxer
        // on_exceed; `smaller_but_strict` has the smaller ceiling and the
        // stricter on_exceed. If the two rules were not computed
        // independently, the winning ceiling's on_exceed might also win,
        // which would wrongly yield StreamThroughUninspected here.
        let bigger_but_lax = BodyInspection {
            buffering: Buffering::Window(ByteSize::kib(2)),
            on_exceed: OnExceed::StreamThroughUninspected,
        };
        let smaller_but_strict = BodyInspection {
            buffering: Buffering::Window(ByteSize::kib(1)),
            on_exceed: OnExceed::Reject413,
        };
        let combined = BodyInspection::combine(bigger_but_lax, smaller_but_strict);
        assert_eq!(combined.buffering, Buffering::Window(ByteSize::kib(2)));
        assert_eq!(combined.on_exceed, OnExceed::Reject413);
    }

    #[test]
    fn pool_boundaries() {
        // Edge case 12: a pool of 0 bytes accepts only the free zero-byte
        // lease; any nonzero request fails.
        let empty_pool = BufferPool::new(ByteSize(0));
        assert!(BufferPool::try_acquire(&empty_pool, ByteSize(0)).is_ok());
        // `BufferLease` deliberately has no PartialEq (see its doc comment), so
        // the error is unwrapped and compared on its own rather than
        // comparing the whole `Result`.
        assert_eq!(
            BufferPool::try_acquire(&empty_pool, ByteSize(1)).unwrap_err(),
            BudgetExhausted {
                requested: 1,
                outstanding: 0,
                total: 0,
            }
        );

        // Edge case 13: a 1 MiB pool admits exactly one full-size acquire, and
        // a second acquire of a single extra byte fails with the exact budget
        // contents.
        let pool = BufferPool::new(ByteSize::mib(1));
        let lease =
            BufferPool::try_acquire(&pool, ByteSize::mib(1)).expect("the whole pool fits once");
        assert_eq!(pool.outstanding(), 1_048_576);
        assert_eq!(
            BufferPool::try_acquire(&pool, ByteSize(1)).unwrap_err(),
            BudgetExhausted {
                requested: 1,
                outstanding: 1_048_576,
                total: 1_048_576,
            }
        );

        // Edge case 14: dropping the outstanding lease returns its bytes, and
        // the pool admits again.
        drop(lease);
        assert_eq!(pool.outstanding(), 0);
        let reacquired = BufferPool::try_acquire(&pool, ByteSize::mib(1))
            .expect("the pool must admit again once the only lease is dropped");
        assert_eq!(pool.outstanding(), 1_048_576);

        // Edge case 15: an acquire of u64::MAX must fail via checked,
        // overflow-detecting arithmetic rather than wrapping, and must leave
        // the counter exactly as it was.
        let before = pool.outstanding();
        assert!(BufferPool::try_acquire(&pool, ByteSize(u64::MAX)).is_err());
        assert_eq!(pool.outstanding(), before);

        // Regression for issue 661: with a `total` of `u64::MAX` (the only
        // available spelling of "unlimited", since `ByteSize::mib`/`kib`
        // themselves saturate onto exactly `u64::MAX`), a `saturating_add`
        // based guard can never fire because the clamped sum can never
        // exceed `u64::MAX`. A first acquire of the whole budget must still
        // leave no room for a second, non-zero acquire, and every dropped
        // lease must bring the counter back to exactly 0, not a wrapped
        // value.
        let unlimited_pool = BufferPool::new(ByteSize(u64::MAX));
        let whole_budget = BufferPool::try_acquire(&unlimited_pool, ByteSize(u64::MAX))
            .expect("a single acquire of the entire unlimited budget must fit exactly once");
        assert_eq!(unlimited_pool.outstanding(), u64::MAX);
        assert_eq!(
            BufferPool::try_acquire(&unlimited_pool, ByteSize(1)).unwrap_err(),
            BudgetExhausted {
                requested: 1,
                outstanding: u64::MAX,
                total: u64::MAX,
            },
            "the budget is fully committed; a saturating-add guard would wrongly admit this"
        );
        drop(whole_budget);
        assert_eq!(
            unlimited_pool.outstanding(),
            0,
            "outstanding must return to exactly 0, not a wrapped value, once the only lease is dropped"
        );
        drop(reacquired);

        // Edge case 22: reserving the whole declared ceiling up front means
        // the pool exhausts after exactly total / ceiling admissions,
        // regardless of how many body bytes any one request actually sent.
        // lease_size() below is called with no body bytes observed at all, on
        // purpose: the reservation never depends on them.
        let bulk_pool = BufferPool::new(ByteSize::mib(100));
        let whole_10mib = BodyInspection {
            buffering: Buffering::Whole(ByteSize::mib(10)),
            on_exceed: OnExceed::Reject413,
        };
        #[allow(
            clippy::integer_division,
            reason = "computing how many whole ceilings fit in the budget is an intentional \
                      truncating division: this is exactly the edge case 22 count this test \
                      exists to pin, not a value on the request path"
        )]
        let expected_admissions = bulk_pool.total() / whole_10mib.lease_size().bytes();
        assert_eq!(expected_admissions, 10);
        let mut held = Vec::new();
        for i in 0..expected_admissions {
            held.push(
                BufferPool::try_acquire(&bulk_pool, whole_10mib.lease_size()).unwrap_or_else(|e| {
                    panic!("admission {i} of {expected_admissions} must fit: {e:?}")
                }),
            );
        }
        assert!(
            BufferPool::try_acquire(&bulk_pool, whole_10mib.lease_size()).is_err(),
            "the (total / ceiling + 1)th admission must exhaust the budget"
        );
        drop(held);
    }

    #[test]
    fn lease_returns_bytes() {
        // Edge case 14 again, from a pool of its own: dropping a lease returns
        // its bytes and the pool admits again immediately afterward.
        let pool = BufferPool::new(ByteSize::mib(1));
        let lease = BufferPool::try_acquire(&pool, ByteSize::mib(1)).expect("fits exactly once");
        assert_eq!(pool.outstanding(), 1_048_576);
        drop(lease);
        assert_eq!(pool.outstanding(), 0);
        assert!(BufferPool::try_acquire(&pool, ByteSize::mib(1)).is_ok());

        // Edge case 16: 1000 acquires and drops interleaved must return the
        // counter to exactly zero every single time, not merely once at the
        // very end.
        let churn_pool = BufferPool::new(ByteSize::kib(4));
        for i in 0..1000u32 {
            let lease = BufferPool::try_acquire(&churn_pool, ByteSize(4096))
                .unwrap_or_else(|e| panic!("acquire {i} must fit a freshly drained pool: {e:?}"));
            assert_eq!(churn_pool.outstanding(), 4096);
            drop(lease);
            assert_eq!(churn_pool.outstanding(), 0);
        }

        // Edge case 20: a zero-byte lease never moves the counter. A real,
        // nonzero lease is acquired first so the counter is away from zero;
        // acquiring and dropping a zero-byte lease must leave it completely
        // undisturbed.
        let mixed_pool = BufferPool::new(ByteSize::mib(1));
        let real_lease = BufferPool::try_acquire(&mixed_pool, ByteSize(4096)).expect("fits");
        assert_eq!(mixed_pool.outstanding(), 4096);
        // `bytes()` must reflect what was actually reserved, not just report 0
        // for every lease: a real, nonzero lease is checked here so that
        // `zero_lease.bytes()` below (necessarily 0 for both a correct and a
        // broken implementation) is not the only call site exercising this
        // accessor.
        assert_eq!(real_lease.bytes(), 4096);
        let zero_lease = BufferPool::try_acquire(&mixed_pool, ByteSize(0)).expect("always free");
        assert_eq!(zero_lease.bytes(), 0);
        assert_eq!(mixed_pool.outstanding(), 4096);
        drop(zero_lease);
        assert_eq!(mixed_pool.outstanding(), 4096);
        drop(real_lease);
        assert_eq!(mixed_pool.outstanding(), 0);
    }

    #[test]
    fn concurrent_acquire_respects_total() {
        // Edge case 17: two threads, released together by a barrier, each try
        // 100 acquires of 16 KiB against a 1 MiB pool. 1 MiB / 16 KiB is
        // exactly 64, so exactly 64 of the combined 200 attempts must succeed
        // while every successful lease is still held.
        let pool = BufferPool::new(ByteSize::mib(1));
        let total = pool.total();
        let barrier = Arc::new(Barrier::new(2));

        // Edge case 21, first half: a third thread that only reads
        // outstanding() throughout the race must never observe a value above
        // total, no matter when it happens to sample.
        let keep_polling = Arc::new(AtomicBool::new(true));
        let max_seen = Arc::new(AtomicU64::new(0));
        let poller = {
            let pool = Arc::clone(&pool);
            let keep_polling = Arc::clone(&keep_polling);
            let max_seen = Arc::clone(&max_seen);
            thread::spawn(move || {
                while keep_polling.load(Ordering::Relaxed) {
                    max_seen.fetch_max(pool.outstanding(), Ordering::Relaxed);
                }
            })
        };

        let spawn_acquirer = || {
            let pool = Arc::clone(&pool);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let mut leases = Vec::new();
                for _ in 0..100 {
                    if let Ok(lease) = BufferPool::try_acquire(&pool, ByteSize::kib(16)) {
                        leases.push(lease);
                    }
                }
                leases
            })
        };
        let acquirer_a = spawn_acquirer();
        let acquirer_b = spawn_acquirer();

        let mut leases_a = acquirer_a.join().expect("acquirer thread must not panic");
        let leases_b = acquirer_b.join().expect("acquirer thread must not panic");

        keep_polling.store(false, Ordering::Relaxed);
        poller.join().expect("poller thread must not panic");

        let succeeded = leases_a.len() + leases_b.len();
        assert_eq!(
            succeeded, 64,
            "exactly total / 16 KiB leases must succeed while all are held"
        );
        assert_eq!(pool.outstanding(), 1_048_576);
        assert!(
            max_seen.load(Ordering::Relaxed) <= total,
            "a concurrent reader must never observe outstanding() above total"
        );

        // Edge case 21, second half: dropping one held lease must be visible
        // to a subsequent outstanding() read. The Drop implementation
        // releases with Ordering::Release and outstanding() loads with
        // Ordering::Acquire, so the decrement happens-before this read
        // observes it: a real ordering guarantee, not a race won by luck.
        leases_a.extend(leases_b);
        let one = leases_a.pop().expect("64 leases were held");
        drop(one);
        assert_eq!(pool.outstanding(), 1_048_576 - 16_384);

        drop(leases_a);
        assert_eq!(pool.outstanding(), 0);
    }

    #[test]
    fn cross_thread_and_panic_release() {
        // Edge case 18: acquiring on this thread and dropping on a spawned
        // thread must still return the bytes. BufferLease holds only an Arc
        // and a byte count, neither of which is thread-affine.
        let pool = BufferPool::new(ByteSize::mib(1));
        let lease = BufferPool::try_acquire(&pool, ByteSize::kib(64)).expect("fits");
        assert_eq!(pool.outstanding(), 65_536);
        thread::spawn(move || drop(lease))
            .join()
            .expect("dropping a lease on another thread must not panic");
        assert_eq!(pool.outstanding(), 0);

        // Edge case 19: a lease dropped while unwinding through a panic must
        // still return its bytes. catch_unwind stops the unwind at this frame
        // so the pool can be inspected afterward.
        let panic_lease = BufferPool::try_acquire(&pool, ByteSize::kib(64)).expect("fits");
        assert_eq!(pool.outstanding(), 65_536);
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let _dropped_by_unwind = panic_lease;
            panic!("deliberate panic to exercise BufferLease::drop during unwind");
        }));
        assert!(result.is_err(), "the closure must have actually panicked");
        assert_eq!(
            pool.outstanding(),
            0,
            "the lease must release its bytes even when dropped by an unwind"
        );
    }

    fn buffering_strategy() -> impl Strategy<Value = Buffering> {
        prop_oneof![
            Just(Buffering::None),
            (0..=65_536u64).prop_map(|n| Buffering::Window(ByteSize(n))),
            (0..=65_536u64).prop_map(|n| Buffering::Whole(ByteSize(n))),
        ]
    }

    fn on_exceed_strategy() -> impl Strategy<Value = OnExceed> {
        prop_oneof![
            Just(OnExceed::Reject413),
            Just(OnExceed::StreamThroughUninspected),
        ]
    }

    fn body_inspection_strategy() -> impl Strategy<Value = BodyInspection> {
        (buffering_strategy(), on_exceed_strategy()).prop_map(|(buffering, on_exceed)| {
            BodyInspection {
                buffering,
                on_exceed,
            }
        })
    }

    /// Whether `x` and `y` are equal for every purpose this module cares about.
    ///
    /// Structural equality is not the right tool for the lattice property below,
    /// because the generator required by the issue this module implements
    /// crosses `Buffering::None` with BOTH `OnExceed` values, producing
    /// non-inspecting declarations that differ only in an `on_exceed` field
    /// `combine`'s own short circuit deliberately never looks at (see its doc
    /// comment: "a declaration that inspects nothing has no opinion about
    /// overflow"). Two such values are observably identical everywhere else in
    /// this module: `observe` returns `None` unconditionally for both and
    /// `lease_size` returns 0 for both. This treats any two non-inspecting
    /// declarations as equal regardless of their `on_exceed`, and falls back to
    /// real structural equality otherwise. A defect against this issue records
    /// the underlying contradiction: `combine`'s documented short circuit
    /// (return the OTHER side's value whole, including its `on_exceed`) makes
    /// the literal, unqualified "combine(x, NONE) == x for every x" and
    /// "commutative" claims false under `==` for such values, discoverable only
    /// because the generator the issue itself specifies is exactly the one that
    /// produces them.
    fn behaviorally_eq(x: BodyInspection, y: BodyInspection) -> bool {
        x == y || (matches!(x.buffering, Buffering::None) && matches!(y.buffering, Buffering::None))
    }

    proptest! {
        #[test]
        fn prop_combine_is_a_lattice(
            a in body_inspection_strategy(),
            b in body_inspection_strategy(),
            c in body_inspection_strategy(),
        ) {
            // Edge case 11: commutative.
            prop_assert!(behaviorally_eq(
                BodyInspection::combine(a, b),
                BodyInspection::combine(b, a)
            ));

            // Edge case 11: associative.
            prop_assert!(behaviorally_eq(
                BodyInspection::combine(BodyInspection::combine(a, b), c),
                BodyInspection::combine(a, BodyInspection::combine(b, c))
            ));

            // NONE is the identity, from either side.
            prop_assert!(behaviorally_eq(
                BodyInspection::combine(a, BodyInspection::NONE),
                a
            ));
            prop_assert!(behaviorally_eq(
                BodyInspection::combine(BodyInspection::NONE, a),
                a
            ));

            // Never produces StreamThroughUninspected when either input was an
            // INSPECTING declaration (buffering is not None) with Reject413.
            // The qualifier matters: NONE itself carries Reject413 too, but it
            // must not drag a StreamThroughUninspected sibling up to it, which
            // is exactly what the NONE-short-circuit tests above exercise
            // concretely and this property checks over a whole generated set.
            let a_inspects_and_rejects =
                !matches!(a.buffering, Buffering::None) && matches!(a.on_exceed, OnExceed::Reject413);
            let b_inspects_and_rejects =
                !matches!(b.buffering, Buffering::None) && matches!(b.on_exceed, OnExceed::Reject413);
            if a_inspects_and_rejects || b_inspects_and_rejects {
                prop_assert_eq!(
                    BodyInspection::combine(a, b).on_exceed,
                    OnExceed::Reject413
                );
            }
        }
    }
}
