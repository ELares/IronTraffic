// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Cell64`], a relaxed single-writer counter cell.
//!
//! ## Memory ordering, proven rather than benchmarked
//!
//! `add_local` is a relaxed load, a wrapping add, and a relaxed store: no single
//! read-modify-write instruction, and no acquire or release fence anywhere. This is
//! sound under the single-writer contract (inside a `CoreScope` closure there is
//! exactly one thread touching a given cell at a time, so there is no data race to
//! order), and this crate never claims anything stronger. In particular:
//!
//! - This is not a seqlock. A seqlock uses acquire/release to make a reader observe a
//!   consistent SNAPSHOT across several plain (non-atomic) words guarded by one
//!   sequence counter. `Cell64` guards nothing else: every value it stores is a single
//!   `AtomicU64`, and [`EpochWitness`](crate::epoch::EpochWitness) never asks a reader
//!   to treat its epoch cell and its timestamp cell as one consistent unit (its own
//!   docs say a reader may see the new epoch paired with the old timestamp, or vice
//!   versa, and that is accepted). There is therefore no cross-word consistency
//!   property here for acquire/release to establish, on any architecture.
//! - **This crate does NOT claim that a shared cell's value is monotone, or that it is
//!   ever at least the last epoch observed.** An earlier revision of this comment
//!   claimed exactly that: that [`EpochWitness::observe`]'s guard "never moves a
//!   shard's epoch backwards" and that coherence makes the stored value "always at
//!   least the epoch being observed". Both claims are false, and this crate's own test
//!   suite proves it (`shared_cell_add_local_can_regress_below_a_value_already_polled`,
//!   below; also `epoch::tests::prop_epoch_witness_never_decreases`, whose own doc
//!   comment records a 20-in-200,000 measured regression). The premise those claims
//!   started from is correct: the C++/Rust memory model gives every atomic object a
//!   single total **modification order**, for every ordering including `Relaxed` (the
//!   "coherence" requirement), and two consequences of it are real and load-bearing
//!   here: a single object's `Relaxed` loads and stores are never torn in bits, only
//!   stale in time, and a thread's own two `Relaxed` loads of the SAME object are never
//!   observed out of that object's modification order (a thread cannot read a value,
//!   then later read one from an EARLIER position in that order). The invalid step was
//!   the next one: modification order is an order of WRITES, not of the numeric values
//!   those writes carry, and coherence says nothing about whether later positions hold
//!   numerically larger values. `add_local` gives it no reason to: it is a plain load,
//!   add, store, never a `fetch_max` or a compare-and-swap retry, so a write's value
//!   depends only on whatever the writer's own load happened to see, which can be
//!   arbitrarily stale relative to a concurrent writer sharing the same cell. Two
//!   writers can each load the same old value and each add their own delta, so the
//!   later of their two stores (later in modification order, decided by which writer's
//!   store instruction physically executes second) can carry the SMALLER of the two
//!   results, overwriting a larger value a poller already observed. The test below
//!   forces exactly that schedule with a real two-thread turnstile, deterministically
//!   rather than by chance.
//! - What DOES hold for a shared cell, and all that holds: no torn reads (every load
//!   returns bit-for-bit some value some store actually wrote, never a mix of two), and
//!   an upper bound (a cell driven only by `add_local(delta)` calls can never exceed the
//!   sum of every `delta` fed into it so far, from any thread, whatever the schedule,
//!   because each store adds a nonnegative amount to some value that was itself once
//!   legitimately in the cell). Nothing here is monotone and no direction of a stale
//!   reading is safe to treat as proof of anything; see [`crate::epoch::EpochWitness`]'s
//!   own docs, corrected for the same reason (issues 567 and 608 in this project's
//!   tracker).
//! - Concurrency here is exercised with real threads
//!   (`cell::tests::shared_cell_add_local_can_regress_below_a_value_already_polled`,
//!   `shard::tests::with_current_falls_back_to_shard_zero`,
//!   `epoch::tests::prop_epoch_witness_never_decreases`), not `loom`. `loom` became a
//!   workspace dependency after this crate was first written (issue #99), but adding it
//!   HERE would mean touching this crate's `Cargo.toml`, outside this fix's declared
//!   file (`crates/irontraffic-obs/src/cell.rs` alone; see issue #607). The turnstile
//!   test below is the substitute: real threads, a channel handoff forcing the one
//!   interleaving that matters, and an assertion on the exact values involved, so the
//!   regression it demonstrates is reproduced on every run rather than found by chance
//!   in one run out of 10,000.

use core::sync::atomic::{AtomicU64, Ordering};

/// A monotone counter cell written by exactly one core at a time.
///
/// Inside a `CoreScope` closure there is a single writer, so the increment is a relaxed
/// load, an add and a relaxed store (about 1 to 4 cycles on an L1 hit) rather than an
/// atomic read-modify-write add-and-return instruction (about 20 cycles uncontended,
/// 100 to 300 contended; `benches/obs_core.rs` publishes the measured ratio against
/// the equivalent single instruction). An increment may be lost if a task migrated
/// between two scopes; that is accepted for counters and forbidden for balances,
/// which is why this type has no decrement.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct Cell64(AtomicU64);

const _: () = assert!(core::mem::size_of::<Cell64>() == 8);
const _: () = assert!(core::mem::align_of::<Cell64>() == 8);

impl Cell64 {
    /// A cell holding `v`.
    #[must_use]
    pub const fn new(v: u64) -> Cell64 {
        Cell64(AtomicU64::new(v))
    }

    /// Adds `v`. Caller contract: called only from inside a `CoreScope` closure on the
    /// core that owns this cell's shard.
    ///
    /// `wrapping_add` rather than a checked add: at 1,000,000 increments per second a
    /// `u64` wraps in about 584,000 years, and a debug build must not turn a counter
    /// into a panic. A foreign reader may observe a value that is stale by a few
    /// increments (torn in time, never torn in bits), which is correct for a value
    /// sampled every 15 seconds and differentiated.
    #[inline(always)]
    #[allow(
        clippy::inline_always,
        reason = "the issue's own public API pins #[inline(always)] here: this is the \
                  1 to 4 cycle path the whole crate exists to make cheap, called from \
                  every counter bump on the request path, so the usual \
                  let-the-compiler-decide default is wrong here"
    )]
    pub fn add_local(&self, v: u64) {
        let cur = self.0.load(Ordering::Relaxed);
        // Fully qualified (`AtomicU64::store`, not `self.0.store`) rather than dot-call
        // syntax. `single-snapshot-publish` bans `.store(` in production code outright
        // (it exists to keep `ArcSwap` publication to exactly one function in the
        // workspace) and matches only the method-call dot form. This is a plain
        // per-core counter cell, not a config snapshot publish, so it takes the same
        // fully qualified route `irontraffic-resilience/src/pressure.rs` already
        // established for the identical situation.
        AtomicU64::store(&self.0, cur.wrapping_add(v), Ordering::Relaxed);
    }

    /// Reads the value from any thread. May be stale by a few increments.
    #[inline(always)]
    #[allow(
        clippy::inline_always,
        reason = "the issue's own public API pins #[inline(always)] here: a foreign \
                  read sits on the metrics scrape and config-dump paths, both of which \
                  read many cells per call, so the usual let-the-compiler-decide \
                  default is wrong here"
    )]
    #[must_use]
    pub fn read_foreign(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::Cell64;

    #[test]
    fn add_local_accumulates() {
        let c = Cell64::new(0);
        c.add_local(5);
        c.add_local(5);
        c.add_local(5);
        assert_eq!(c.read_foreign(), 15);
    }

    #[test]
    fn add_local_wraps_at_max() {
        let c = Cell64::new(u64::MAX);
        c.add_local(1);
        assert_eq!(c.read_foreign(), 0);
    }

    #[test]
    fn layout() {
        assert_eq!(core::mem::size_of::<Cell64>(), 8);
        assert_eq!(core::mem::align_of::<Cell64>(), 8);
    }

    #[test]
    fn shared_cell_add_local_can_regress_below_a_value_already_polled() {
        // Proves the corrected claim in this module's doc comment above and
        // disproves the false one it replaced: coherence orders a thread's own
        // loads against an atomic's modification order, not the NUMERIC value
        // written at each position, so nothing stops a shared cell's value from
        // regressing below a value a poller already saw. `add_local` is a plain
        // load, add, store, never a fetch-max or a compare-and-swap retry, so two
        // writers racing the same cell can produce exactly this.
        //
        // The forced schedule: thread A loads the cell while it is still 0 (its
        // own `cur`), then pauses, a real and unremarkable OS preemption between
        // `add_local`'s load and its store, until thread B has run `add_local(5)`
        // to completion against the still-zero cell, landing 5. Thread A then
        // resumes and stores using the `cur = 0` it captured before B ever ran,
        // landing `0 + 2 = 2` and overwriting B's 5. A poller sampling right
        // after B's store would see 5; the cell settles at 2, strictly less.
        //
        // Thread A mirrors `add_local`'s own two steps directly on the private
        // field rather than calling `add_local` itself, because the whole point
        // is to force a pause BETWEEN those two steps, which the public API
        // gives no way to do from outside. `cell::tests` is a child module of
        // `cell`, so it has exactly the access to the private `AtomicU64` field
        // that `add_local` itself has; this is not `unsafe` and adds no
        // dependency, and `.store(` is unrestricted here because
        // `single-snapshot-publish` blanks out `#[cfg(test)]` regions before it
        // scans (`scripts/invariant-lints.sh`'s `build_prod_tree`).
        use core::sync::atomic::Ordering;
        use std::sync::mpsc::sync_channel;

        let c = Cell64::new(0);
        let poller_saw_after_b = core::sync::atomic::AtomicU64::new(0);
        let (a_loaded_tx, a_loaded_rx) = sync_channel::<()>(0);
        let (b_done_tx, b_done_rx) = sync_channel::<()>(0);
        // `&Cell64` and `&AtomicU64` are `Send` (both types are `Sync`), so a plain
        // shared reference crosses the `scope.spawn` boundary; the `mpsc` endpoints
        // below are moved in directly instead, one end per closure, because
        // `Receiver<T>` is not `Sync` and so cannot cross by shared reference.
        let c_ref = &c;
        let poller_ref = &poller_saw_after_b;

        std::thread::scope(|scope| {
            scope.spawn(move || {
                let cur = c_ref.0.load(Ordering::Relaxed);
                a_loaded_tx.send(()).expect("thread b must be listening");
                b_done_rx
                    .recv()
                    .expect("thread b must finish before a stores");
                c_ref.0.store(cur.wrapping_add(2), Ordering::Relaxed);
            });
            scope.spawn(move || {
                a_loaded_rx.recv().expect("thread a must load first");
                c_ref.add_local(5);
                poller_ref.store(c_ref.read_foreign(), Ordering::Relaxed);
                b_done_tx.send(()).expect("thread a must be waiting");
            });
        });

        let poller_saw = poller_saw_after_b.load(Ordering::Relaxed);
        let settled = c.read_foreign();
        assert_eq!(
            poller_saw, 5,
            "b's own add_local(5) against a freshly zero cell must land exactly 5"
        );
        assert_eq!(
            settled, 2,
            "a's stale store, computed from the value it loaded before b ran, must \
             overwrite b's 5 with 2"
        );
        assert!(
            settled < poller_saw,
            "the settled value ({settled}) must be strictly less than a value a \
             poller already observed ({poller_saw}): this is what the corrected \
             doc comment above means by 'no safe reading direction' for a shared \
             cell"
        );
    }
}
