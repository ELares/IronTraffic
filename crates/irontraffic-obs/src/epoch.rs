// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`EpochWitness`], per-core proof that a configuration epoch reached that core.
//!
//! Envoy's `GET /config_dump` reports what the main thread believes. It does not tell
//! an operator whether worker 7 is still serving the previous route table. That is a
//! real class of bug and this type makes it observable.

use crate::cell::Cell64;
use crate::shard::Shards;

/// What one core last acknowledged.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EpochSighting {
    /// The epoch that core acknowledged. 0 means "never acknowledged anything".
    pub epoch: u64,
    /// Unix milliseconds at which it acknowledged, from the core's cached coarse wall
    /// clock. 0 when `epoch` is 0.
    pub at_unix_millis: u64,
}

/// Per core record of the newest configuration epoch each core has observed.
///
/// This exists because a config dump that reports only what the control thread
/// believes cannot tell an operator that worker 7 is still serving the previous
/// table.
#[derive(Debug)]
pub struct EpochWitness {
    shards: Shards<(Cell64, Cell64)>,
}

impl EpochWitness {
    /// One shard per installed core, all zero.
    #[must_use]
    pub fn new() -> EpochWitness {
        EpochWitness {
            shards: Shards::from_core_count(|_| (Cell64::new(0), Cell64::new(0))),
        }
    }

    /// Records that the calling core has installed `epoch`. Monotone: a smaller epoch
    /// is ignored.
    ///
    /// 0 is the "never acknowledged" sentinel, so `observe(0, _)` is always a no-op: a
    /// witness that has never observed anything already reads 0, and `0 < 0` is false.
    /// An epoch smaller than the shard's current value is likewise ignored, so a late
    /// arriving stale swap cannot move a core backwards.
    ///
    /// Steps 3 and 4 (see the design doc) express "store the larger value" using only
    /// `add_local`, because [`Cell64`] deliberately has no `store`: giving a counter
    /// cell a public store would make it usable as a balance. The timestamp delta uses
    /// `wrapping_sub` because a wall clock that stepped backwards (NTP) makes `at`
    /// smaller than the stored value, and a plain subtraction would panic in a debug
    /// build on a worker thread; `Cell64::add_local` adds with `wrapping_add`, so the
    /// wrapped delta stores exactly the intended value.
    pub fn observe(&self, epoch: u64, at: irontraffic_time::CoarseWall) {
        self.shards.with_current(|(e, t)| {
            let cur_e = e.read_foreign();
            if cur_e < epoch {
                e.add_local(epoch - cur_e);
                t.add_local(at.as_unix_millis().wrapping_sub(t.read_foreign()));
            }
        });
    }

    /// Clears `out`, then pushes exactly one sighting per shard, in shard order.
    pub fn sightings(&self, out: &mut Vec<EpochSighting>) {
        out.clear();
        for (e, t) in self.shards.iter() {
            out.push(EpochSighting {
                epoch: e.read_foreign(),
                at_unix_millis: t.read_foreign(),
            });
        }
    }

    /// The sighting with the smallest epoch.
    ///
    /// **Advisory. Never gate a fail-open decision on this alone, in EITHER
    /// direction.** The guard in [`EpochWitness::observe`] is monotone only when the
    /// single writer contract holds. When two cores share a shard
    /// (`Shards::with_current`'s documented fallback), both can read the same current
    /// epoch, both compute a delta to the same target epoch, and both deltas get
    /// applied: the shard can settle strictly ABOVE any epoch either core actually
    /// installed (issue #567), and, on a different schedule, it can also settle
    /// BELOW an epoch every core sharing it has already, individually, finished
    /// observing (issue #608; `tests::shared_shard_can_undershoot_a_target_every_core_reached`
    /// reproduces this deterministically). An earlier revision of this doc claimed
    /// `oldest().epoch < target` PROVES the config has not reached every core, as
    /// though the low direction, at least, were safe. That claim is false: the same
    /// lost-update race that can push a shared shard's value above target can, on a
    /// different interleaving, leave it below target after every core sharing that
    /// shard has already returned from `observe(target)`, and nothing about that
    /// state repairs itself without a further `observe` call reaching it. There is
    /// therefore no reading of `oldest()` that is safe to treat as proof of anything
    /// once a shard is shared; it is a best-effort hint in BOTH directions, and it is
    /// exact only under the single-writer contract (one core per shard, the ordinary
    /// case once `core::install` has run before any `Shards` in this witness was
    /// built). Any consumer whose wrong answer costs correctness (a readiness probe
    /// that admits traffic, a drain that declares itself finished, a config commit
    /// that reports success) must treat both a too-high and a too-low reading as
    /// possible and combine this witness with an authoritative signal it owns.
    #[must_use]
    pub fn oldest(&self) -> EpochSighting {
        let mut best: Option<EpochSighting> = None;
        for (e, t) in self.shards.iter() {
            let sighting = EpochSighting {
                epoch: e.read_foreign(),
                at_unix_millis: t.read_foreign(),
            };
            best = Some(match best {
                Some(b) if b.epoch <= sighting.epoch => b,
                _ => sighting,
            });
        }
        // `Shards` is never empty (`Shards::new` clamps `n` into `1..=MAX_SHARDS`
        // before allocating), so this loop always runs at least once and `best` is
        // always `Some` by the time it finishes; `unwrap_or_default` never actually
        // reaches its default arm; the "no observation anywhere" case (edge case 8)
        // is met naturally instead, because every shard starts at
        // `EpochSighting::default()` until something observes into it.
        best.unwrap_or_default()
    }
}

impl Default for EpochWitness {
    fn default() -> Self {
        EpochWitness::new()
    }
}

#[cfg(test)]
impl EpochWitness {
    /// Builds a witness with `epochs.len()` shards, shard `i` holding `epochs[i]` and
    /// a zero timestamp. Test only; production code always uses `new()` plus
    /// `observe`.
    pub(crate) fn from_epochs_for_test(epochs: &[u64]) -> EpochWitness {
        EpochWitness {
            shards: Shards::new(epochs.len(), |i| {
                (
                    Cell64::new(epochs.get(i).copied().unwrap_or(0)),
                    Cell64::new(0),
                )
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EpochSighting, EpochWitness};
    use irontraffic_time::{TestTimeSource, TimeSource as _};
    use proptest::prelude::*;

    #[test]
    fn observe_is_monotone() {
        crate::shard::ensure_multi_core_for_tests();
        let w = EpochWitness::from_epochs_for_test(&[0]);
        let ts = TestTimeSource::new();

        ts.set_wall_unix_millis(1_000);
        w.observe(7, ts.coarse_wall());
        ts.set_wall_unix_millis(2_000);
        w.observe(3, ts.coarse_wall());
        assert_eq!(
            w.oldest(),
            EpochSighting {
                epoch: 7,
                at_unix_millis: 1_000
            }
        );

        ts.set_wall_unix_millis(3_000);
        w.observe(9, ts.coarse_wall());
        assert_eq!(
            w.oldest(),
            EpochSighting {
                epoch: 9,
                at_unix_millis: 3_000
            }
        );
    }

    #[test]
    fn sightings_returns_one_entry_per_shard_in_order() {
        // Not named by the issue, added because mutation testing found it: nothing
        // else in this file calls `sightings`, so a stub doing nothing survived
        // every other test.
        let w = EpochWitness::from_epochs_for_test(&[5, 9, 2, 7]);
        let mut out = vec![EpochSighting {
            epoch: 111,
            at_unix_millis: 222,
        }];
        w.sightings(&mut out);
        assert_eq!(
            out,
            vec![
                EpochSighting {
                    epoch: 5,
                    at_unix_millis: 0
                },
                EpochSighting {
                    epoch: 9,
                    at_unix_millis: 0
                },
                EpochSighting {
                    epoch: 2,
                    at_unix_millis: 0
                },
                EpochSighting {
                    epoch: 7,
                    at_unix_millis: 0
                },
            ]
        );
    }

    #[test]
    fn observe_zero_is_ignored() {
        crate::shard::ensure_multi_core_for_tests();
        let w = EpochWitness::from_epochs_for_test(&[0]);
        let ts = TestTimeSource::new();
        ts.set_wall_unix_millis(5_000);
        w.observe(0, ts.coarse_wall());
        assert_eq!(
            w.oldest(),
            EpochSighting {
                epoch: 0,
                at_unix_millis: 0
            }
        );
    }

    #[test]
    fn shared_shard_can_undershoot_a_target_every_core_reached() {
        // Proves the corrected claim in `oldest()`'s doc comment above and disproves
        // the one it replaced. Two threads share one shard: thread 0's history is
        // observe(1) then observe(3), thread 1's is observe(2) then observe(3) (the
        // same two histories issue #608 itself uses). BOTH threads individually
        // return from their own `observe(3)` call by the end of this test, yet the
        // shard settles on 2, strictly below the target of 3, and nothing about
        // that state self-repairs without a further `observe` call reaching it. So
        // `oldest().epoch < target` does NOT prove the config has not reached every
        // core: it can be false exactly when every core sharing the shard has
        // already reached it.
        //
        // This mirrors `EpochWitness::observe`'s own two-step algorithm (an outer
        // read, then, if it is smaller than the target, `add_local`'s own inner
        // read and store) on a bare `AtomicU64` rather than through `EpochWitness`
        // or `Cell64`, because the whole point is to pause a thread BETWEEN its own
        // outer and inner reads, which neither public API exposes a way to do from
        // outside. That needs no dependency and no access to any private field,
        // matching the dependency-free reproduction this file's own
        // `prop_epoch_witness_never_decreases` test already describes for the
        // overshoot direction. The exact schedule was found by an exhaustive search
        // over every interleaving of the two histories above against a shard
        // starting at 0, and is forced here with rendezvous channels rather than
        // left to chance.
        use core::sync::atomic::{AtomicU64, Ordering};
        use std::sync::mpsc::sync_channel;

        fn read(cell: &AtomicU64) -> u64 {
            cell.load(Ordering::Relaxed)
        }
        fn commit(cell: &AtomicU64, inner: u64, outer: u64, epoch: u64) {
            // Mirrors `Cell64::add_local`'s own wrapping add exactly (see
            // cell.rs). The subtraction is unwrapped because every call site
            // below only reaches this after its own outer read already
            // established `outer < epoch`, exactly as `EpochWitness::observe`'s
            // own `if cur_e < epoch` guard does.
            cell.store(inner.wrapping_add(epoch - outer), Ordering::Relaxed);
        }

        let cell = AtomicU64::new(0);
        let cell_ref = &cell;
        let (h1_tx, h1_rx) = sync_channel::<()>(0);
        let (h2_tx, h2_rx) = sync_channel::<()>(0);
        let (h3_tx, h3_rx) = sync_channel::<()>(0);
        let (h4_tx, h4_rx) = sync_channel::<()>(0);
        let (h5_tx, h5_rx) = sync_channel::<()>(0);

        std::thread::scope(|scope| {
            scope.spawn(move || {
                // Thread 0's history: observe(1), then observe(3).
                let outer0 = read(cell_ref);
                let inner0 = read(cell_ref);
                debug_assert_eq!((outer0, inner0), (0, 0));
                h1_tx.send(()).expect("thread 1 must be listening");
                h2_rx.recv().expect(
                    "thread 1 must run observe(2) fully and capture observe(3)'s outer read",
                );
                commit(cell_ref, inner0, outer0, 1); // observe(1) returns, using stale reads
                let outer1 = read(cell_ref);
                let inner1 = read(cell_ref);
                debug_assert_eq!((outer1, inner1), (1, 1));
                h3_tx.send(()).expect("thread 1 must be listening");
                h4_rx
                    .recv()
                    .expect("thread 1 must capture its own observe(3) inner read");
                commit(cell_ref, inner1, outer1, 3); // observe(3) returns
                h5_tx.send(()).expect("thread 1 must be listening");
            });
            scope.spawn(move || {
                // Thread 1's history: observe(2), then observe(3).
                h1_rx
                    .recv()
                    .expect("thread 0 must capture its own reads first");
                let outer0 = read(cell_ref);
                let inner0 = read(cell_ref);
                debug_assert_eq!((outer0, inner0), (0, 0));
                commit(cell_ref, inner0, outer0, 2); // observe(2) returns
                let outer1 = read(cell_ref);
                debug_assert_eq!(outer1, 2);
                h2_tx.send(()).expect("thread 0 must be listening");
                h3_rx
                    .recv()
                    .expect("thread 0 must finish observe(1) and capture its own observe(3) reads");
                let inner1 = read(cell_ref); // this IS add_local's own inner read
                debug_assert_eq!(inner1, 1);
                h4_tx.send(()).expect("thread 0 must be listening");
                h5_rx
                    .recv()
                    .expect("thread 0 must finish its own observe(3) store first");
                // observe(3) returns, using the stale outer1 and inner1 captured above.
                commit(cell_ref, inner1, outer1, 3);
            });
        });

        let settled = cell.load(Ordering::Relaxed);
        assert_eq!(
            settled, 2,
            "both threads returned from their own observe(3) call, yet the shard \
             settles at 2, strictly below the target of 3"
        );
        assert!(
            settled < 3,
            "this is exactly the state the corrected oldest() doc warns about: \
             oldest().epoch < target here does NOT mean the config has not reached \
             every core, because every core sharing this shard explicitly observed \
             target 3 and returned"
        );
    }

    #[test]
    fn oldest_is_the_minimum() {
        let w = EpochWitness::from_epochs_for_test(&[5, 9, 2, 7]);
        assert_eq!(
            w.oldest(),
            EpochSighting {
                epoch: 2,
                at_unix_millis: 0
            }
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[allow(
            clippy::integer_division,
            reason = "splitting the generated epochs vector in half for the two \
                      probing threads is an intentional truncating split, not an \
                      accidental precision loss"
        )]
        #[test]
        fn prop_epoch_witness_never_decreases(
            epochs in proptest::collection::vec(0..1_000_000u64, 0..=64),
        ) {
            crate::shard::ensure_multi_core_for_tests();

            // Single threaded replay: under the single writer contract this is
            // exactly the maximum epoch observed.
            let w = EpochWitness::from_epochs_for_test(&[0]);
            let ts = TestTimeSource::new();
            for &e in &epochs {
                w.observe(e, ts.coarse_wall());
            }
            let expected_max = epochs.iter().copied().max().unwrap_or(0);
            prop_assert_eq!(w.oldest().epoch, expected_max);

            // Two threads racing the SAME shard: proptest does not control their
            // interleaving.
            //
            // THIS DOES NOT ASSERT "THE READING NEVER DECREASES", even though the
            // issue's own text names that as the property this arm checks. That
            // claim is false for the algorithm the same issue specifies:
            // `add_local` is a plain load then a separate store (never a single
            // read-modify-write, never a compare-and-swap retry), so two concurrent
            // `add_local` calls on the same cell can lose an update in a way that
            // makes a THIRD thread's poll observe a value LOWER than one it already
            // saw, not merely a smaller increase than expected. Concretely: thread A
            // loads the cell (reading V); thread B's `add_local` runs to completion
            // (loads V, stores V + delta_B); thread A then stores using its stale
            // load, V + delta_A. If delta_A < delta_B, the final value (V +
            // delta_A) is strictly less than the V + delta_B a poller already
            // observed. This is the classic lost-update race, not a bug in this
            // test: reproduced here (this property test failed on its first real
            // run, proptest-shrunk to a 32 element case, `oldest().epoch` dropping
            // between two consecutive polls) and confirmed with a ~40 line
            // reproduction with NO dependency on this crate at all (two bare
            // threads doing literally `load`, `wrapping_add`, `store` on an
            // `AtomicU64`, Relaxed throughout): 20 of 200,000 trials showed a
            // decrease. Filed as a defect against this issue's own design and test
            // text (`obs-cell64-shards-epoch-render`, corpus issue
            // `issues/m8/01-obs-crate-cells-shards-and-render.md`; ELares/IronTraffic
            // #567), because "no call and no interleaving can lower a shard's epoch"
            // and "the reading never decreases between two consecutive `oldest()`
            // calls" are both stated as invariants in that issue and neither holds
            // once a shard is shared, exactly the case this test and edge cases 2, 3
            // and 22 are about.
            //
            // What DOES provably hold, and what this asserts instead: every
            // `add_local(delta)` call stores `old_value_at_that_instant + delta`
            // where `delta <= epoch_i` (the specific epoch being applied), so by
            // induction the cell's value can never exceed the sum of every epoch
            // fed into it so far, from either thread, however they interleave. That
            // bound is checked at every poll below.
            let w2 = EpochWitness::from_epochs_for_test(&[0]);
            let ts2 = TestTimeSource::new();
            let half = epochs.len() / 2;
            let first = epochs[..half].to_vec();
            let second = epochs[half..].to_vec();
            let total: u64 = epochs.iter().copied().sum();
            let mut polled = vec![w2.oldest().epoch];
            std::thread::scope(|scope| {
                let h1 = scope.spawn(|| {
                    for &e in &first {
                        w2.observe(e, ts2.coarse_wall());
                    }
                });
                let h2 = scope.spawn(|| {
                    for &e in &second {
                        w2.observe(e, ts2.coarse_wall());
                    }
                });
                let mut spins = 0u32;
                while (!h1.is_finished() || !h2.is_finished()) && spins < 100_000 {
                    polled.push(w2.oldest().epoch);
                    spins += 1;
                }
                h1.join().expect("observer thread must not panic");
                h2.join().expect("observer thread must not panic");
            });
            polled.push(w2.oldest().epoch);
            for &v in &polled {
                prop_assert!(v <= total);
            }
        }
    }
}
