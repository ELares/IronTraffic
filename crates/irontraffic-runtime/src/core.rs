// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-core state, reachable only inside a closure that cannot await.
//!
//! A tokio task migrates between workers at any await point, so "only the owning
//! worker touches this" is true ONLY for the duration of a synchronous scope.
//! [`with`] provides that scope: [`CoreCtx`] is `!Send + !Sync`, so an `.await`
//! inside the closure does not compile.
//!
//! This module holds COUNTERS, which may lose an increment when a task migrates
//! between two scopes. It holds no BALANCE: a balance is a cache-line-padded shared
//! atomic behind an RAII guard with no public decrement, because a lost decrement is
//! capacity that silently disappears.
//!
//! The cached clock is not two bare atomics. An earlier draft of this module stored
//! `mono_ms: AtomicU32` and `wall_ms: AtomicU64` directly in the per-core slot and
//! rebuilt a [`irontraffic_time::CoarseMono`] / [`irontraffic_time::CoarseWall`] from
//! those integers on read, which is impossible: both constructors are `pub(crate)` in
//! `irontraffic-time`, deliberately, because the only legitimate way to obtain one is
//! to read it from a clock. [`irontraffic_time::AtomicCoarseCache`] (issue #499) is
//! the sanctioned way to share a coarse clock reading across the scope boundary: it
//! stores the same bit patterns in atomics and reconstructs real values internally,
//! so no raw integer ever crosses the seam.

use std::marker::PhantomData;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crossbeam_utils::CachePadded;

/// The monotone counters kept per core. A closed enum: no request-derived label ever
/// becomes a counter key.
///
/// The explicit discriminants are load bearing: `counter as usize` indexes the per-core
/// array, and `snapshot()` is read back through that same index. A test may write
/// `snapshot()[Counter::X as usize]`; production code must write
/// `snapshot().get(Counter::X as usize).copied().unwrap_or(0)`, because
/// `indexing_slicing` is denied outside tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Counter {
    /// Connections accepted by an accept task.
    ConnectionsAccepted = 0,
    /// Connections closed immediately because the connection cap was reached.
    ConnectionsRejected = 1,
    /// Connections that finished, for any reason.
    ConnectionsClosed = 2,
    /// Bytes forwarded downstream to upstream.
    BytesToUpstream = 3,
    /// Bytes forwarded upstream to downstream.
    BytesToDownstream = 4,
    /// Forwarding attempts that ended in an I/O error.
    ForwardErrors = 5,
    /// Event loop turns observed by [`turn_tick`].
    TurnsPolled = 6,
}

/// Number of variants in [`Counter`].
pub const COUNTER_COUNT: usize = 7;

/// One core's private state, reached only through [`with`]. Never exposed publicly:
/// a caller reaches a field of this type only through [`CoreCtx`]'s methods.
struct CoreSlot {
    counters: [AtomicU64; COUNTER_COUNT],
    /// The cached coarse clocks, refreshed once per turn by [`turn_tick`] and read
    /// with no clock in hand by [`CoreCtx::now_mono`] and [`CoreCtx::now_wall`].
    clock: irontraffic_time::AtomicCoarseCache,
    rng_state: AtomicU64,
}

/// The installed per-core slot array. Never exposed publicly: a caller reaches a
/// slot only through [`with`], never this type or its contents.
struct Cores {
    slots: Box<[CachePadded<CoreSlot>]>,
    next_index: AtomicUsize,
}

static CORES: OnceLock<Cores> = OnceLock::new();

thread_local! {
    /// Assigned on first use, immutable thereafter. Deliberately not a `Cell`.
    static MY_CORE: usize = assign_core_index();
}

/// The odd constant `SplitMix64` uses as its own increment, reused here so distinct
/// core indices land far apart in the seed's state space and no two cores draw from
/// the same stream.
const GOLDEN: u64 = 0x9e37_79b9_7f4a_7c15;

/// The seed used only when [`with`] is reached before [`install`] ever ran.
///
/// Fixed and public on purpose: this path exists so a unit test in another crate
/// that touches `with` before any `install` gets a working, reproducible one-slot
/// array rather than a panic. The binary calls `install` first, so this constant is
/// unreachable in a production process; `serve-and-smoke-test` (#21) is required to
/// fail startup if it finds this path was reached instead.
const LAZY_SEED: u64 = 0;

/// The installed slot array, lazily building a one-slot fallback (seeded from
/// [`LAZY_SEED`]) if [`install`] was never called.
fn cores() -> &'static Cores {
    CORES.get_or_init(|| build_cores(1, LAZY_SEED))
}

/// Builds `n` cache-line-padded slots, each seeded independently from `seed` so
/// that no two cores share a `WyRand` stream.
fn build_cores(n: usize, seed: u64) -> Cores {
    let slots = (0..n)
        .map(|i| {
            // `i * GOLDEN` overflows by design; `wrapping_mul` is exact wrapping
            // arithmetic, not a hidden bug.
            let mut s = seed ^ (i as u64).wrapping_mul(GOLDEN);
            CachePadded::new(CoreSlot {
                // `[AtomicU64::new(0); COUNTER_COUNT]` does not compile because
                // `AtomicU64` is not `Copy`.
                counters: std::array::from_fn(|_| AtomicU64::new(0)),
                clock: irontraffic_time::AtomicCoarseCache::new(),
                rng_state: AtomicU64::new(irontraffic_rand::split_mix64(&mut s)),
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    Cores {
        slots,
        next_index: AtomicUsize::new(0),
    }
}

/// Round-robin core assignment by first touch. Not CPU affinity: with `W` worker
/// threads and `W` slots each worker gets a distinct slot, which is all the
/// sharding needs. A thread that is neither a data-plane worker nor the installer
/// also gets a slot and shares it with a worker; harmless, because every field in
/// [`CoreSlot`] is an atomic.
fn assign_core_index() -> usize {
    let cores = cores();
    let n = cores.slots.len();
    cores.next_index.fetch_add(1, Ordering::Relaxed) % n
}

/// Per-core state. Obtainable only as the argument of [`with`].
///
/// `!Send` and `!Sync` on purpose: holding this across an `.await` would be a data
/// race, so the compiler refuses. Never store it in a struct field; thread it
/// through as a parameter instead.
pub struct CoreCtx {
    slot: &'static CoreSlot,
    index: usize,
    _not_send: PhantomData<*const ()>,
}

const _: () = assert!(std::mem::size_of::<CoreCtx>() <= 24);

impl CoreCtx {
    /// Which slot this scope is using.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// Adds to a monotone counter with a relaxed load-add-store (about 1 to 4
    /// cycles on an L1 hit). An increment may be lost if a task migrated between
    /// scopes; that is accepted for counters and forbidden for balances.
    pub fn bump(&self, counter: Counter, by: u64) {
        let idx = counter as usize;
        if let Some(cell) = self.slot.counters.get(idx) {
            let cur = cell.load(Ordering::Relaxed);
            cell.store(cur.wrapping_add(by), Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain AtomicU64 per-core counter load-add-store, not an ArcSwap config snapshot publish; mirrors the AtomicU32/AtomicU64 cache field writes already allowed in irontraffic-time's cache.rs
        }
    }

    /// The cached coarse monotonic clock. No syscall, no atomic fence.
    #[must_use]
    pub fn now_mono(&self) -> irontraffic_time::CoarseMono {
        self.slot.clock.mono()
    }

    /// The cached coarse wall clock. No syscall, no atomic fence.
    #[must_use]
    pub fn now_wall(&self) -> irontraffic_time::CoarseWall {
        self.slot.clock.wall()
    }

    /// A per-core `WyRand` draw. Identical algorithm to
    /// `irontraffic_rand::Rng::next_u64`, with the state in a relaxed atomic so
    /// the scope needs no cell type.
    ///
    /// NOT cryptographic, and weaker than a private `Rng` in one extra way: two
    /// threads sharing a slot can read the same state and return the same value,
    /// because the load-step-store is not atomic as a whole. Use it for jitter,
    /// sampling, and endpoint selection. Never use it, or anything derived from
    /// it, for a token, a nonce, a key, a session identifier, or a cookie value;
    /// those come from `irontraffic_rand::SecureRng` and from nothing else.
    #[must_use]
    pub fn rand_u64(&self) -> u64 {
        let cur = self.slot.rng_state.load(Ordering::Relaxed);
        let (next, out) = irontraffic_rand::wyrand_step(cur);
        self.slot.rng_state.store(next, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain AtomicU64 per-core RNG state load-step-store, not an ArcSwap config snapshot publish; mirrors the AtomicU32/AtomicU64 cache field writes already allowed in irontraffic-time's cache.rs
        out
    }

    /// A per-core bounded draw, uniform in `0..n`, 0 when `n == 0`. Identical
    /// algorithm to `irontraffic_rand::Rng::bounded_u32`, including its bias bound
    /// of at most `n / 2^32`.
    #[must_use]
    pub fn rand_bounded_u32(&self, n: u32) -> u32 {
        if n == 0 {
            return 0; // total function, matching Rng::bounded_u32
        }
        // high half, as Rng::next_u32 does
        let x = u64::from((self.rand_u64() >> 32) as u32); // it-allow: unchecked-cast reason: a u64 shifted right by 32 has at most 32 significant bits
        // `m` is bound rather than inlined, and the multiply is `wrapping_mul`
        // rather than `*`, because `Rng::bounded_u32` in `rand-seam` (#6) is
        // written exactly that way and the second marker's reason text names
        // `m`. The two reductions must stay diffable line for line; the product
        // cannot overflow either way, since both factors are below 2^32.
        let m = x.wrapping_mul(u64::from(n));
        (m >> 32) as u32 // it-allow: unchecked-cast reason: m is u64 and the shift by 32 leaves at most 32 significant bits
    }
}

/// Runs `f` with the calling thread's per-core state.
///
/// Installs a one-slot array lazily if [`install`] was never called, so tests and
/// control-plane threads work without ceremony.
#[inline]
pub fn with<R>(f: impl FnOnce(&CoreCtx) -> R) -> R {
    let idx = MY_CORE.with(|i| *i);
    let cores = cores();
    // `cores.slots` is never empty: `build_cores` only ever runs with `n >= 1`,
    // from `install`'s `cores == 0` check and from the lazy one-slot path in
    // `cores()`, so index 0 always exists. `idx` alone can be out of range when
    // there are more threads than slots (round-robin assignment); `get` handles
    // that without panicking, and falling back to slot 0 rather than indexing
    // straight through keeps this function panic-free even if that invariant
    // were ever violated.
    #[allow(
        clippy::indexing_slicing,
        reason = "cores.slots is non-empty by construction: build_cores is only ever called with n >= 1, so index 0 always exists"
    )]
    let slot: &'static CoreSlot = cores.slots.get(idx).unwrap_or_else(|| &cores.slots[0]);
    let ctx = CoreCtx {
        slot,
        index: idx,
        _not_send: PhantomData,
    };
    f(&ctx)
}

/// Allocates one cache-line-padded slot per core and seeds each core's RNG from
/// `seed` so no two cores share a stream.
///
/// `seed` MUST come from `irontraffic_rand::SecureRng::seed()` in a production
/// process. It is the root of every per-core `WyRand` stream, and those streams
/// drive decisions an outside observer can see: drain jitter today, and endpoint
/// selection, hedge timing, and sampling in the next milestone. A hardcoded seed
/// gives every deployment of the binary the same stream, so anyone holding the
/// binary can predict them. A fixed seed is legitimate in exactly one place, a
/// deterministic simulation that wants to replay a scheduling decision, and it is
/// never legitimate as a fallback for an entropy failure: an entropy failure is a
/// fatal startup error.
///
/// A caller MUST treat both error variants as fatal at startup. In particular
/// [`CoreInitError::AlreadyInstalled`] means a lazy one-slot array is already in
/// place, so every worker thread will share a single slot: their counter
/// increments collide and, worse, they draw from one RNG stream, which turns
/// per-connection drain jitter into a synchronised stampede. Continuing past that
/// error leaves the process in a state no test covers.
///
/// # Errors
/// [`CoreInitError::ZeroCores`] when `cores` is 0, or
/// [`CoreInitError::AlreadyInstalled`] when called twice.
pub fn install(cores: usize, seed: u64) -> Result<(), CoreInitError> {
    if cores == 0 {
        return Err(CoreInitError::ZeroCores);
    }
    let built = build_cores(cores, seed);
    CORES
        .set(built)
        .map_err(|_| CoreInitError::AlreadyInstalled)
}

/// Refreshes this core's cached clocks and ticks the buffer pool's decay.
///
/// Call once per event loop turn, at the top of an accept or connection loop.
/// This is the only place a worker thread reads a real clock, which is what
/// makes the per-request clock cost zero.
///
/// The clock refresh and the counter bump happen inside one [`with`] scope, which
/// returns the freshly cached monotonic timestamp by value; the buffer pool decay
/// check runs afterward, outside that scope, so the two never nest. `CoarseMono`
/// is `Copy`, so returning it out of a `!Send` scope is fine: only the [`CoreCtx`]
/// reference is confined, not the plain timestamp value it produced.
pub fn turn_tick(ts: &dyn irontraffic_time::TimeSource) {
    let m = with(|c| {
        c.slot.clock.refresh(ts);
        c.bump(Counter::TurnsPolled, 1);
        c.slot.clock.mono()
    });
    irontraffic_io::buffer::BufPool::with_current(|p| p.maybe_decay(m));
}

/// Sums every counter across every core. Never call on the request path.
#[must_use]
pub fn snapshot() -> [u64; COUNTER_COUNT] {
    let cores = cores();
    let mut totals = [0u64; COUNTER_COUNT];
    for slot in &cores.slots {
        for (total, counter) in totals.iter_mut().zip(slot.counters.iter()) {
            *total = total.wrapping_add(counter.load(Ordering::Relaxed));
        }
    }
    totals
}

/// How many slots are installed.
#[must_use]
pub fn core_count() -> usize {
    cores().slots.len()
}

/// Per-core state could not be installed.
#[derive(Debug, thiserror::Error)]
pub enum CoreInitError {
    /// `install(0, _)` was called.
    #[error("core count must be at least 1")]
    ZeroCores,
    /// `install` was called twice.
    #[error("per-core state is already installed")]
    AlreadyInstalled,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{
        COUNTER_COUNT, CoreCtx, CoreInitError, Counter, core_count, install, snapshot, with,
    };

    /// `snapshot()`'s underlying counters are process-global and cargo runs the
    /// tests in this binary concurrently, so a test asserting an exact delta must
    /// not race a sibling test bumping the same counter. Every test below that
    /// needs an exact count takes this lock for its whole body, with
    /// `unwrap_or_else(std::sync::PoisonError::into_inner)` so a panicking
    /// sibling does not poison the suite for the rest.
    static COUNTER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Every discriminant in [`Counter`], in index order, so the property test
    /// below can pick one from a generated `0..COUNTER_COUNT` index.
    const ALL_COUNTERS: [Counter; COUNTER_COUNT] = [
        Counter::ConnectionsAccepted,
        Counter::ConnectionsRejected,
        Counter::ConnectionsClosed,
        Counter::BytesToUpstream,
        Counter::BytesToDownstream,
        Counter::ForwardErrors,
        Counter::TurnsPolled,
    ];

    #[test]
    fn with_works_before_install() {
        let idx = with(CoreCtx::index);
        assert!(idx < core_count());
        assert!(core_count() >= 1);
    }

    #[test]
    fn install_twice_is_an_error() {
        match install(4, 7) {
            Ok(()) => {
                let second = install(4, 7);
                assert!(matches!(second, Err(CoreInitError::AlreadyInstalled)));
            }
            Err(e) => {
                assert!(matches!(e, CoreInitError::AlreadyInstalled));
            }
        }
    }

    #[test]
    fn install_zero_is_an_error() {
        assert!(matches!(install(0, 1), Err(CoreInitError::ZeroCores)));
    }

    /// Mutation testing (not named by the issue, added because it found a real
    /// gap) found that `core_count` hardcoded to return `1` survives every
    /// named test: `with_works_before_install`'s `core_count() >= 1` check is
    /// deliberately order independent (see its own comment) and so is
    /// satisfied by any constant at least 1. `core_count` must report exactly
    /// what `install` set, not a stub, when this call is the one that
    /// actually wins the race to install first in this binary; if a sibling
    /// test already installed something else first, this at least keeps
    /// asserting the one thing that is always true.
    #[test]
    fn install_success_reports_the_exact_core_count() {
        match install(6, 999) {
            Ok(()) => assert_eq!(core_count(), 6),
            Err(CoreInitError::AlreadyInstalled) => assert!(core_count() >= 1),
            Err(e) => panic!("install(6, 999) failed unexpectedly: {e}"),
        }
    }

    #[test]
    fn bump_then_snapshot_sums() {
        let _g = COUNTER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = snapshot();
        for _ in 0..3 {
            with(|c| c.bump(Counter::BytesToUpstream, 5));
        }
        let after = snapshot();
        assert_eq!(
            after[Counter::BytesToUpstream as usize],
            before[Counter::BytesToUpstream as usize] + 15
        );
    }

    #[test]
    fn bump_zero_changes_nothing() {
        let _g = COUNTER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = snapshot();
        with(|c| c.bump(Counter::ForwardErrors, 0));
        let after = snapshot();
        assert_eq!(after, before);
    }

    #[test]
    fn rand_bounded_matches_the_rand_crate_definition() {
        for n in 1..=32u32 {
            for _ in 0..1000 {
                let v = with(|c| c.rand_bounded_u32(n));
                assert!(v < n);
            }
        }
        assert_eq!(with(|c| c.rand_bounded_u32(0)), 0);
    }

    /// Mutation testing (not named by the issue, added because it found a
    /// real gap) found that `v < n` alone is satisfied by an implementation
    /// that always returns 0: 0 is less than every `n >= 1`, so a
    /// `rand_bounded_u32` that never actually draws anything (an early
    /// `return 0` reached unconditionally, or a shift mutated so the mixed
    /// value is always 0) passes the test above without ever being random.
    /// This checks the spread instead: over many draws at a generous `n`, a
    /// real `WyRand`-backed draw visits far more than a handful of distinct
    /// values, where a stuck-at-zero implementation visits exactly one.
    #[test]
    fn rand_bounded_actually_varies() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            seen.insert(with(|c| c.rand_bounded_u32(1000)));
        }
        assert!(
            seen.len() > 100,
            "rand_bounded_u32(1000) over 2000 draws should visit well over \
             100 distinct values; saw only {}",
            seen.len()
        );
    }

    #[test]
    fn snapshot_is_monotone() {
        // This test's own assertion (`>=`) does not need protection from a
        // sibling bumping the same counter: monotonicity holds under any
        // interleaving. But `prop_counter_sum_is_at_most_the_bumps` below
        // asserts an EXACT delta across all seven counters, including the
        // two this test bumps (`ConnectionsAccepted`, `ConnectionsClosed`),
        // so this test's own unlocked bumps can corrupt THAT test's exact
        // accounting if the two run concurrently. Reproduced empirically
        // (not merely reasoned about) while implementing issue #13: this
        // test's bumps to `ConnectionsAccepted` landed inside the property
        // test's own before/after window and made its measured delta exceed
        // the sum of `by` values it had generated, failing an assertion the
        // property test's own code never got wrong. Taking the lock here
        // does not change what this test itself verifies; it only stops it
        // from being a source of interference for a sibling that needs full
        // exclusivity.
        let _g = COUNTER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = snapshot();
        let handles: Vec<_> = (0..2)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..1000 {
                        with(|c| {
                            c.bump(Counter::ConnectionsAccepted, 1);
                            c.bump(Counter::ConnectionsClosed, 1);
                        });
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("a bumping thread must not panic");
        }
        let after = snapshot();
        for (a, b) in after.iter().zip(before.iter()) {
            assert!(a >= b);
        }
    }

    /// The real enforcement that `CoreCtx` cannot be held across an `.await` is
    /// the `PhantomData<*const ()>` field (verified by the acceptance-criteria
    /// grep for `PhantomData` in this file) plus the `core-ctx-not-stored` CI
    /// rule, which fails the build if `CoreCtx` ever appears as a struct field
    /// type anywhere in the workspace. `trybuild` is not in the dependency
    /// table, so a real negative compile test is not available here; this
    /// instead asserts the positive design facts that make `CoreCtx` `!Send`:
    /// a zero-sized `PhantomData<*const ()>` field is present, and the whole
    /// type still stays small.
    #[test]
    fn core_ctx_is_not_send() {
        let _g = COUNTER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            std::mem::size_of::<std::marker::PhantomData<*const ()>>(),
            0
        );
        assert!(std::mem::size_of::<CoreCtx>() <= 24);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn prop_counter_sum_is_at_most_the_bumps(
            ops in proptest::collection::vec((0usize..COUNTER_COUNT, 0u64..1000), 0..=256),
        ) {
            let _g = COUNTER_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = snapshot();
            let mut expected = [0u64; COUNTER_COUNT];
            for &(idx, by) in &ops {
                expected[idx] += by;
                with(|c| c.bump(ALL_COUNTERS[idx], by));
            }
            let after = snapshot();
            for i in 0..COUNTER_COUNT {
                prop_assert_eq!(after[i] - before[i], expected[i]);
            }
        }
    }
}
