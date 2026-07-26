// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Shards`], one separately allocated, 128 byte aligned block per core.
//!
//! Per core state is reachable only inside a closure with no await point. In `balanced`
//! runtime mode a tokio task migrates between worker threads at any await point, so
//! "only the owning worker touches this cell" is true only for the duration of a scope
//! containing no await. `irontraffic_runtime::core::with` provides that scope; its
//! `CoreCtx` is `!Send` and `!Sync`, so an `.await` inside the closure does not
//! compile. [`Shards::with_current`] is therefore the only per-core accessor: it never
//! hands out a storable handle, and there is no method here returning `&T` with a
//! lifetime tied to `&self` alone or returning `&mut T`.

/// Alignment of every shard block, in bytes.
///
/// 128 because the `crossbeam-utils` crate's own cache-line padding wrapper documents
/// 128 on `x86_64` (the spatial prefetcher pulls pairs of 64 byte lines) and on
/// `aarch64`. This crate hard codes 128 rather than depending on that crate for the
/// value, because the number must appear in the allocation layout and in the tests,
/// and this crate does not depend on `crossbeam-utils` at all (nothing here needs a
/// padded individual cell; padding lives at the shard allocation boundary, never
/// around a cell).
pub const SHARD_ALIGN: usize = 128;

/// Hard upper bound on the shard count of any [`Shards`], in shards.
///
/// [`Shards::new`] clamps into `1..=MAX_SHARDS`. The bound exists because `n` is a
/// `usize` and one shard costs `round_up(128 + size_of::<T>(), 128)` bytes: an `n` that
/// ever reaches this constructor from a configuration field, a cluster message or any
/// other externally influenced number would otherwise be an unbounded allocation with
/// no error path. 4096 is far above any real core count (the largest shipping `x86_64`
/// socket is 128 physical cores, the largest `aarch64` is 192) and at a 16 byte payload
/// costs 1 MiB, which is affordable to allocate even if it is reached by mistake.
pub const MAX_SHARDS: usize = 4096;

/// One core's payload, preceded by a 128 byte guard region.
///
/// `#[repr(C, align(128))]` with the guard as the first field means the payload of
/// block `i` cannot share a line with the tail of block `i - 1`, regardless of how `T`
/// is sized: the guard occupies the whole first cache line, and `align(128)` rounds the
/// struct's own size up to a multiple of 128, so a neighbouring block boundary can
/// never land inside this one's payload. Its size is therefore
/// `round_up(128 + size_of::<T>(), 128)`, which is 256 bytes for a 16 byte payload.
/// Each block is allocated by its own `Box::new` (see [`Shards::new`]), so blocks are
/// not contiguous either.
#[derive(Debug)]
#[repr(C, align(128))]
pub struct ShardBlock<T> {
    guard: [u8; SHARD_ALIGN],
    value: T,
}

const _: () = assert!(core::mem::align_of::<ShardBlock<u64>>() == 128);

impl<T> ShardBlock<T> {
    fn new(value: T) -> ShardBlock<T> {
        ShardBlock {
            guard: [0; SHARD_ALIGN],
            value,
        }
    }

    /// The payload.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }
}

/// One separately allocated, 128 byte aligned block per core.
///
/// Access is only through [`Shards::with_current`], which runs inside a `CoreScope`
/// closure, or through [`Shards::iter`] for aggregation off the request path.
#[derive(Debug)]
pub struct Shards<T> {
    blocks: Box<[ShardBlock<T>]>,
}

impl<T> Shards<T> {
    /// `n` shards, shard `i` initialised by `init(i)`.
    ///
    /// `n` is clamped into `1..=MAX_SHARDS`, so this never allocates nothing and never
    /// allocates without bound. When the clamp bites, cores above `MAX_SHARDS - 1`
    /// share shard 0 through [`Shards::with_current`] and their counters become lossy;
    /// that is accepted because the alternative is an allocation sized by the caller's
    /// arithmetic. The clamp runs BEFORE `init` is ever called, so `init` runs exactly
    /// `n.clamp(1, MAX_SHARDS)` times, never the raw (possibly huge) `n` a caller
    /// passed.
    #[must_use]
    pub fn new(n: usize, mut init: impl FnMut(usize) -> T) -> Shards<T> {
        let n = n.clamp(1, MAX_SHARDS);
        let blocks = (0..n)
            .map(|i| ShardBlock::new(init(i)))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Shards { blocks }
    }

    /// One shard per installed core.
    #[must_use]
    pub fn from_core_count(init: impl FnMut(usize) -> T) -> Shards<T> {
        Shards::new(irontraffic_runtime::core::core_count(), init)
    }

    /// Runs `f` on the calling core's shard.
    ///
    /// Falls back to shard 0 when the calling core's index exceeds the shard count,
    /// which can happen when this `Shards` was built before `core::install`. Two
    /// threads then run `load, add, store` against the same cell with no lock, so an
    /// increment can be lost; nothing in this crate may be used as the sole authority
    /// for a decision that fails open on a too high or too low reading (see
    /// [`crate::epoch::EpochWitness::oldest`]).
    #[inline]
    pub fn with_current<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        irontraffic_runtime::core::with(|c| {
            let i = c.index();
            // `Shards::new` clamps `n` into `1..=MAX_SHARDS` before allocating
            // `blocks` (above), so `blocks` is never empty and index 0 always exists.
            // This `debug_assert!` records that invariant so a future change that
            // broke it would fail every test and debug build immediately, rather than
            // surfacing later as a silently wrong fallback.
            debug_assert!(
                !self.blocks.is_empty(),
                "Shards<T> is never empty by construction"
            );
            #[allow(
                clippy::indexing_slicing,
                reason = "blocks is non-empty by construction: Shards::new clamps n into \
                          1..=MAX_SHARDS before allocating, so index 0 always exists; \
                          mirrors irontraffic_runtime::core::with's identical fallback \
                          (crates/irontraffic-runtime/src/core.rs)"
            )]
            let block = self.blocks.get(i).unwrap_or_else(|| &self.blocks[0]);
            f(block.value())
        })
    }

    /// Every shard, in shard order. For aggregation only, never the request path.
    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.blocks.iter().map(ShardBlock::value)
    }

    /// Shard `i`, or `None`.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&T> {
        self.blocks.get(i).map(ShardBlock::value)
    }

    /// Number of shards. Always at least 1.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Always false; present because clippy requires it beside `len`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Guarantees `irontraffic_runtime::core::core_count() > 1` before the calling test
/// touches anything in `irontraffic_runtime::core`.
///
/// `irontraffic_runtime::core` keeps its installed core count in a process-global
/// `OnceLock`, and `cargo test` runs every test in this crate concurrently in one
/// process. Any test that calls [`Shards::with_current`] or
/// [`Shards::from_core_count`] (directly, or indirectly through
/// [`crate::epoch::EpochWitness::observe`] or `EpochWitness::new`) lazily installs a
/// ONE-slot fallback the first time it runs, which is a race: whichever test's thread
/// happens to touch `irontraffic_runtime::core` first fixes the core count for the
/// rest of this test binary's lifetime. `shard::tests::with_current_falls_back_to_shard_zero`
/// needs a core count above 1 to observe the fallback it names; every test in this
/// crate that reaches `irontraffic_runtime::core` at all calls this helper as its
/// first action so that whichever of them wins the race installs a multi-core count,
/// not the single-shard default. `std::sync::Once::call_once` makes this
/// deterministic: every caller blocks until the winning call finishes, so no caller
/// can observe `irontraffic_runtime::core` before this attempt has run.
#[cfg(test)]
pub(crate) fn ensure_multi_core_for_tests() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = irontraffic_runtime::core::install(8, 424_242);
    });
}

#[cfg(test)]
mod tests {
    use super::{Shards, ensure_multi_core_for_tests};
    use crate::cell::Cell64;

    #[test]
    fn new_zero_becomes_one() {
        let s = Shards::<u8>::new(0, |_| 0);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn is_empty_is_always_false() {
        // Not named by the issue, added because mutation testing found it: nothing
        // else in this file calls `is_empty`, so a stub hardcoding `true` survived
        // every other test. `Shards<T>` is never empty by construction (`new`
        // clamps `n` into `1..=MAX_SHARDS`), so `is_empty` must always read `false`,
        // for the smallest, largest, and an ordinary shard count alike.
        assert!(!Shards::<u8>::new(0, |_| 0).is_empty());
        assert!(!Shards::<u8>::new(1, |_| 0).is_empty());
        assert!(!Shards::<u8>::new(8, |_| 0).is_empty());
    }

    #[test]
    #[allow(
        clippy::integer_division,
        reason = "checking whether two addresses fall in the same 128 byte cache line \
                  is exactly integer division by the line size, not an accidental \
                  precision loss"
    )]
    fn blocks_do_not_share_a_line() {
        let s = Shards::<Cell64>::new(8, |_| Cell64::new(0));
        let addrs: Vec<usize> = (0..8)
            .map(|i| {
                let block = s.get(i).expect("index within len");
                core::ptr::from_ref(block).addr()
            })
            .collect();
        for (i, &a) in addrs.iter().enumerate() {
            for (j, &b) in addrs.iter().enumerate() {
                if i != j {
                    assert_ne!(a / super::SHARD_ALIGN, b / super::SHARD_ALIGN);
                }
            }
        }
    }

    #[test]
    fn with_current_uses_one_shard() {
        ensure_multi_core_for_tests();
        let s: Shards<Cell64> = Shards::from_core_count(|_| Cell64::new(0));
        for _ in 0..100 {
            s.with_current(|c| c.add_local(1));
        }
        let mut hit = 0usize;
        let mut total = 0u64;
        for v in s.iter() {
            let r = v.read_foreign();
            total += r;
            if r == 100 {
                hit += 1;
            } else {
                assert_eq!(r, 0, "a shard that was not touched must read exactly 0");
            }
        }
        assert_eq!(
            hit, 1,
            "exactly one shard must have received all 100 increments"
        );
        assert_eq!(total, 100);
    }

    #[test]
    fn with_current_falls_back_to_shard_zero() {
        ensure_multi_core_for_tests();
        let s = Shards::<Cell64>::new(1, |_| Cell64::new(0));
        let mut seen_indices = std::collections::HashSet::new();
        let mut calls: u64 = 0;
        // Threads are spawned and joined ONE AT A TIME, never concurrently: this
        // shard's single Cell64 then has exactly one writer at a time, so the total
        // asserted below is exact rather than subject to the documented lost-update
        // race that concurrent writers to a shared shard accept (see
        // `Shards::with_current`'s own doc comment). 256 is far more than the 8 cores
        // `ensure_multi_core_for_tests` installs, so the round-robin core assignment
        // is overwhelmingly likely to have produced at least two distinct indices
        // long before this loop runs out.
        for _ in 0..256 {
            if seen_indices.len() >= 2 {
                break;
            }
            let idx = std::thread::scope(|scope| {
                let handle = scope.spawn(|| {
                    let idx =
                        irontraffic_runtime::core::with(irontraffic_runtime::core::CoreCtx::index);
                    s.with_current(|c| c.add_local(1));
                    idx
                });
                handle.join().expect("a probing thread must not panic")
            });
            seen_indices.insert(idx);
            calls += 1;
        }
        assert!(
            seen_indices.len() >= 2,
            "expected at least two distinct core indices across {calls} probing \
             threads, saw {seen_indices:?}; ensure_multi_core_for_tests should have \
             installed 8 cores before any sibling test could fix a smaller count"
        );
        let total: u64 = s.iter().map(Cell64::read_foreign).sum();
        assert_eq!(
            total, calls,
            "every increment must land in the one existing shard"
        );
        assert_eq!(
            s.get(0)
                .expect("Shards::new(1, ..) has exactly one shard")
                .read_foreign(),
            calls
        );
    }

    #[test]
    fn new_clamps_to_max_shards() {
        let mut calls = 0usize;
        let s = Shards::<u8>::new(usize::MAX, |_| {
            calls += 1;
            0
        });
        assert_eq!(s.len(), super::MAX_SHARDS);
        assert_eq!(calls, super::MAX_SHARDS);

        let mut calls2 = 0usize;
        let s2 = Shards::<u8>::new(super::MAX_SHARDS + 1, |_| {
            calls2 += 1;
            0
        });
        assert_eq!(s2.len(), super::MAX_SHARDS);
        assert_eq!(calls2, super::MAX_SHARDS);
    }
}
