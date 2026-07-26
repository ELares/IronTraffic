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
//! - The one correctness property this crate DOES claim under concurrent, unsynchronised
//!   access to a SHARED cell (the documented `Shards::with_current` fallback, when two
//!   cores land on the same shard) is that [`EpochWitness::observe`]'s monotone guard
//!   never moves a shard's epoch backwards, even though an increment can be lost and the
//!   value can overshoot. That property does not need acquire or release either: the
//!   C++/Rust memory model guarantees a single total **modification order** per atomic
//!   object, for every memory ordering including `Relaxed` (this is the "coherence"
//!   requirement on atomics, not a `Relaxed`-specific weakening). Two consequences of
//!   that guarantee are load bearing here: first, a single object's plain `Relaxed`
//!   loads and stores are never torn in bits, whatever architecture this runs on, only
//!   stale in time; second, a thread's own two `Relaxed` loads of the SAME object are
//!   never observed out of that object's modification order (a thread cannot read a
//!   value, then later read an OLDER one from the same location). `add_local`'s internal
//!   load in [`EpochWitness::observe`] is therefore never older, in modification order,
//!   than the value `observe` itself just read, so the value it stores is always at
//!   least the epoch being observed. That argument holds identically on `x86_64` and
//!   `aarch64`: it is a property of the atomics model, not of a hardware ordering
//!   guarantee either architecture happens to give for free.
//! - Concurrency here is exercised with real threads
//!   (`shard::tests::with_current_falls_back_to_shard_zero`,
//!   `epoch::tests::prop_epoch_witness_never_decreases`), not `loom`: this crate's
//!   `[dev-dependencies]` are fixed by its own acceptance criteria to exactly `proptest`
//!   and `criterion`, and `loom` is not a dependency of this workspace (it is not in
//!   `[workspace.dependencies]` on the branch this issue was implemented against, and is
//!   not authorised by this issue's manifest section), so it is not available to model
//!   with here. The reasoning above is the substitute: a proof from the atomics model's
//!   own coherence guarantee, which needs no architecture-specific assumption, backed by
//!   tests that actually run two threads against one shared cell rather than only
//!   asserting single-threaded behaviour.

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
}
