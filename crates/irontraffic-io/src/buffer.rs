// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-worker pooled read buffers.
//!
//! A buffer is acquired on the readable event and released at request completion, so
//! an idle keep-alive connection holds NO data buffer. That is the single biggest
//! memory lever this product has: HAProxy holds roughly 32 KiB per established
//! connection for the connection's life, and hyper holds roughly 16 KiB per idle
//! connection.
//!
//! # What is bounded by what
//!
//! [`DEFAULT_POOL_CHUNKS`] bounds the FREE list, so it bounds resident memory once
//! traffic subsides. It does NOT bound how many chunks are checked out at once:
//! [`acquire`] allocates on a pool miss rather than blocking, because a data plane
//! that blocks for a buffer is a data plane that deadlocks. The bound on checked-out
//! chunks is the connection cap: at most one chunk per direction per connection, so
//! peak pooled bytes are `2 * live_connections * CHUNK_SIZE`, and `live_connections`
//! is capped by the connection registry (`limits.max_connections`, default 10,000,
//! giving 640 MiB worst case against 0 for idle connections). Raising
//! `max_connections` raises that number linearly.
//!
//! # A recycled chunk still holds the previous connection's bytes
//!
//! Chunks are not zeroed on release. Only the prefix recorded by
//! [`PooledBuf::set_filled`] may be read back, and that rule is a confidentiality
//! boundary: recording a fill length larger than what was written reads one client's
//! plaintext and forwards it to another. In debug builds every recycled chunk is
//! filled with `0xDB` before it is handed out, so that mistake surfaces as an obvious
//! poison run in a test instead of as a data leak in production.

use std::cell::RefCell; // it-allow: interior-mutability reason: the M1 thread-local buffer pool; see scripts/allowlist-interior-mutability.txt
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use bytes::{Bytes, BytesMut};
use crossbeam_utils::CachePadded;
use irontraffic_time::CoarseMono;

/// Size of every pooled chunk.
pub const CHUNK_SIZE: usize = 32 * 1024;

/// Default per-worker pool capacity in chunks (8 MiB).
pub const DEFAULT_POOL_CHUNKS: usize = 256;

/// How long a pool must sit over half idle before [`BufPool::maybe_decay`] shrinks it.
const DECAY_INTERVAL_MS: u32 = 60_000;

/// Numerator of the idle fraction that triggers decay: decay when `free > cap/2`.
const DECAY_IDLE_FRACTION_NUM: usize = 1;

/// Denominator of the idle fraction that triggers decay.
const DECAY_IDLE_FRACTION_DEN: usize = 2;

/// Live `PooledBuf` values. A BALANCE: +1 in `acquire`, -1 only in `Drop for PooledBuf`.
static OUTSTANDING: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
/// Chunks taken from the allocator rather than the pool.
static ALLOCATIONS: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
/// Chunks freed rather than pooled because the pool was full or unavailable.
static OVER_CAP_RELEASES: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));

thread_local! {
    static POOL: RefCell<BufPool> = RefCell::new(BufPool::new(DEFAULT_POOL_CHUNKS));
}

/// A bounded per-worker pool of fixed-size chunks. Reached through
/// [`BufPool::with_current`]; never constructed or shared by callers.
pub struct BufPool {
    free: Vec<BytesMut>,
    cap: usize,
    last_decay: CoarseMono,
    /// High water mark of `free.len()` since the last decay.
    hwm_free: usize,
}

impl BufPool {
    /// `cap.max(1)`: a pool capacity of 0 would make every release an
    /// over-cap release, which is a degenerate configuration rather than a
    /// useful "no pooling" mode, so the minimum is 1.
    fn new(cap: usize) -> Self {
        Self {
            free: Vec::new(),
            cap: cap.max(1),
            last_decay: CoarseMono::default(),
            hwm_free: 0,
        }
    }

    /// Runs `f` with the calling thread's pool.
    ///
    /// The closure is synchronous by signature: nothing may await while the pool is
    /// borrowed. Do not return a future from `f`.
    pub fn with_current<R>(f: impl FnOnce(&mut BufPool) -> R) -> R {
        POOL.with(|cell| {
            let mut p = cell.borrow_mut();
            f(&mut p)
        })
    }

    /// Removes and returns one chunk, poisoning it if it came from the free list.
    ///
    /// Poisoning (`0xDB`, debug builds only) is applied here rather than at
    /// release time: a chunk sitting in the free list between releases is not
    /// observed by anyone, so poisoning on take is the point where a stale
    /// byte could actually be mistaken for this holder's own data.
    fn take(&mut self) -> BytesMut {
        if let Some(c) = self.free.pop() {
            // `mut` is rebound only under `debug_assertions`: the poison fill is the
            // sole reason this binding is ever mutated, so a release build (where the
            // cfg strips the fill entirely) must not declare it mutable either, or
            // rustc's `unused_mut` fires.
            #[cfg(debug_assertions)]
            let mut c = c;
            #[cfg(debug_assertions)]
            c.fill(0xDB);
            c
        } else {
            ALLOCATIONS.fetch_add(1, Relaxed);
            BytesMut::zeroed(CHUNK_SIZE)
        }
    }

    /// Returns a chunk to the free list, or frees it if the pool is already at
    /// capacity. Reachable only from `Drop for PooledBuf`.
    fn give(&mut self, chunk: BytesMut) {
        if self.free.len() >= self.cap {
            OVER_CAP_RELEASES.fetch_add(1, Relaxed);
            return;
        }
        debug_assert_eq!(chunk.len(), CHUNK_SIZE, "pooled chunk changed size");
        self.free.push(chunk);
        if self.free.len() > self.hwm_free {
            self.hwm_free = self.free.len();
        }
    }

    /// Shrinks the pool if it has been at least half idle for the last decay
    /// interval (60 seconds). Called once per event loop turn with the cached
    /// coarse clock; this type never reads a clock itself.
    pub fn maybe_decay(&mut self, now: CoarseMono) {
        if !now.reached(self.last_decay.saturating_add_ms(DECAY_INTERVAL_MS)) {
            return;
        }
        self.last_decay = now;
        #[allow(
            clippy::integer_division,
            reason = "cap/2 idle threshold; DECAY_IDLE_FRACTION_NUM/DEN are exact small constants"
        )]
        let threshold = self.cap * DECAY_IDLE_FRACTION_NUM / DECAY_IDLE_FRACTION_DEN;
        if self.hwm_free > threshold {
            #[allow(
                clippy::integer_division,
                reason = "halving the free list by design; the odd chunk stays in the kept half"
            )]
            let keep = self.free.len() / 2;
            self.free.truncate(keep);
        }
        self.hwm_free = self.free.len();
    }

    /// Free chunks currently held.
    #[must_use]
    pub fn free_chunks(&self) -> usize {
        self.free.len()
    }

    /// Capacity in chunks.
    #[must_use]
    pub fn cap_chunks(&self) -> usize {
        self.cap
    }
}

/// Acquires one 32 KiB chunk from the calling thread's pool.
///
/// Allocates a fresh zeroed chunk if the pool is empty. The returned guard returns
/// its chunk to whichever thread's pool is current when it is dropped, which is
/// correct and self-balancing when a task migrates between workers.
#[must_use = "dropping the returned PooledBuf immediately releases its chunk back to the pool"]
pub fn acquire() -> PooledBuf {
    let chunk = BufPool::with_current(BufPool::take);
    OUTSTANDING.fetch_add(1, Relaxed);
    PooledBuf {
        chunk: Some(chunk),
        filled: 0,
    }
}

/// Process-wide pool statistics, for the startup log, the admin surface, and tests.
#[must_use]
pub fn stats() -> PoolStats {
    let (free_chunks, cap_chunks) = BufPool::with_current(|p| (p.free_chunks(), p.cap_chunks()));
    PoolStats {
        outstanding: OUTSTANDING.load(Relaxed),
        free_chunks,
        cap_chunks,
        allocations: ALLOCATIONS.load(Relaxed),
        over_cap_releases: OVER_CAP_RELEASES.load(Relaxed),
    }
}

/// A snapshot of pool accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    /// Live `PooledBuf` values across the whole process. This is a balance: it is
    /// incremented on acquire and decremented only in `Drop`.
    pub outstanding: u64,
    /// Free chunks in the calling thread's pool.
    pub free_chunks: usize,
    /// The calling thread's pool capacity in chunks.
    pub cap_chunks: usize,
    /// Chunks allocated from the allocator since process start.
    pub allocations: u64,
    /// Chunks freed rather than pooled because the pool was full or unavailable.
    pub over_cap_releases: u64,
}

/// An owned 32 KiB chunk. Returns to a pool on drop.
///
/// The chunk is NOT zeroed on release, so it may contain a previous connection's
/// bytes. Only the prefix recorded by [`PooledBuf::set_filled`] may be read back;
/// reading beyond it is a cross-connection information disclosure. Debug builds
/// fill a recycled chunk with `0xDB` so that mistake is visible in a test.
#[must_use = "a PooledBuf returns its chunk to the pool on drop; dropping it early releases the buffer"]
pub struct PooledBuf {
    // The Option exists for exactly one reason: `Drop` needs to move the chunk out
    // through `&mut self`. It is `Some` for the entire observable life of the guard,
    // and no method other than `Drop` may take it, because the `OUTSTANDING`
    // decrement lives behind that take and a chunk removed any other way would lose
    // the decrement forever.
    chunk: Option<BytesMut>,
    filled: usize,
}

impl PooledBuf {
    /// The whole 32 KiB region, for a reader to fill.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.chunk.as_mut().map_or(&mut [][..], BytesMut::as_mut)
    }

    /// The prefix recorded by [`PooledBuf::set_filled`].
    #[must_use]
    pub fn filled(&self) -> &[u8] {
        self.chunk
            .as_ref()
            .and_then(|c| c.get(..self.filled))
            .unwrap_or_default()
    }

    /// Records how many bytes at the front of the chunk are meaningful.
    ///
    /// `n` MUST be a length a read into this chunk just returned. Passing a larger
    /// value makes [`PooledBuf::filled`] expose bytes this holder never wrote,
    /// which on a recycled chunk are a previous connection's bytes.
    ///
    /// # Panics
    /// Never. A value above `CHUNK_SIZE` is clamped to `CHUNK_SIZE` and a
    /// `debug_assert` fires in debug builds.
    pub fn set_filled(&mut self, n: usize) {
        debug_assert!(n <= CHUNK_SIZE, "set_filled above CHUNK_SIZE");
        self.filled = n.min(CHUNK_SIZE);
    }

    /// How many bytes are recorded as meaningful.
    #[must_use]
    pub fn filled_len(&self) -> usize {
        self.filled
    }

    /// Copies the filled prefix into an exactly sized allocation and returns it,
    /// leaving this buffer to be recycled. Use when the bytes must outlive the
    /// current request.
    ///
    /// Implemented as a copy followed by a normal drop of the guard, never by
    /// taking the chunk out: the outstanding balance is decremented inside `Drop`
    /// and only inside `Drop`.
    #[must_use]
    pub fn into_bytes_exact(self) -> Bytes {
        let out = compact_exact(self.filled());
        drop(self);
        out
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        let Some(chunk) = self.chunk.take() else {
            return;
        };
        OUTSTANDING.fetch_sub(1, Relaxed);
        let returned = POOL
            .try_with(|cell| match cell.try_borrow_mut() {
                Ok(mut p) => {
                    p.give(chunk);
                    true
                }
                Err(_) => false,
            })
            .unwrap_or(false);
        if !returned {
            OVER_CAP_RELEASES.fetch_add(1, Relaxed);
        }
    }
}

/// Copies `src` into an exactly sized allocation.
///
/// A `Bytes` slice pins its ENTIRE backing allocation, so a 20-byte value sliced out
/// of a 32 KiB pooled chunk pins 32 KiB, which at 100,000 connections is 3.2 GiB
/// instead of about 90 MB for the same headers copied to size. Anything retained
/// past the current request is compacted through this function. Call this "slice
/// retention amplification" in any comment that refers to it.
#[must_use]
pub fn compact_exact(src: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(src.len());
    out.extend_from_slice(src);
    out.freeze()
}

#[cfg(test)]
mod tests {
    use irontraffic_time::{TestTimeSource, TimeSource};
    use proptest::prelude::*;

    use super::{
        BufPool, CHUNK_SIZE, DEFAULT_POOL_CHUNKS, PooledBuf, acquire, compact_exact, stats,
    };

    /// See the module-level test isolation note in `tests/buffer_pool.rs`: the three
    /// process-wide counters race across concurrently running tests unless every
    /// test serializes on this lock and asserts on deltas from a captured baseline.
    static POOL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Acquires `n` buffers and drops them, returning all `n` chunks to the
    /// calling thread's pool. Used to set up the decay tests, which must run
    /// on the thread whose pool they inspect.
    fn fill_pool_to(n: usize) {
        let mut held = Vec::with_capacity(n);
        for _ in 0..n {
            held.push(acquire());
        }
        drop(held);
    }

    /// Every other test in this module refers to `CHUNK_SIZE` and
    /// `DEFAULT_POOL_CHUNKS` symbolically, which is the right way to write
    /// them, but it also means none of those tests would notice if the
    /// constants' own literal values drifted from what the module doc and
    /// `BufPool`'s doc comments quote (32 KiB chunks; an 8 MiB, 256-chunk
    /// default pool; the 640 MiB worst case at `max_connections=10_000`
    /// derived from it). Pin the literals here so a change to either constant
    /// is a deliberate, visible edit to this assertion, not a silent drift
    /// that every symbolic reference elsewhere keeps quiet about.
    #[test]
    fn ct6_documented_constants_have_their_documented_values() {
        assert_eq!(CHUNK_SIZE, 32 * 1024);
        assert_eq!(DEFAULT_POOL_CHUNKS, 256);
    }

    #[test]
    fn acquire_then_drop_returns_the_chunk() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = stats();
        let buf = acquire();
        assert_eq!(stats().outstanding, base.outstanding + 1);
        drop(buf);
        assert_eq!(stats().outstanding, base.outstanding);
        assert!(stats().free_chunks >= 1);
    }

    #[test]
    fn chunk_is_reused_not_reallocated() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(acquire());
        let base = stats();
        for _ in 0..100 {
            drop(acquire());
        }
        assert_eq!(stats().allocations, base.allocations);
    }

    #[test]
    fn pool_never_exceeds_cap() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = stats();
        let mut bufs = Vec::with_capacity(DEFAULT_POOL_CHUNKS + 10);
        for _ in 0..(DEFAULT_POOL_CHUNKS + 10) {
            bufs.push(acquire());
        }
        drop(bufs);
        assert_eq!(stats().free_chunks, DEFAULT_POOL_CHUNKS);
        assert!(stats().over_cap_releases >= base.over_cap_releases + 10);
    }

    /// `pool_never_exceeds_cap` above asserts `over_cap_releases` with `>=`,
    /// which an implementation that fires on EVERY release (not just the ones
    /// that overflow the cap) would also satisfy: 266 released chunks would
    /// pass a `>= base + 10` check just as easily as the correct 10 does.
    /// `over_cap_releases` is the operator-facing memory-pressure signal (the
    /// admin surface and the startup log both read it), so an implementation
    /// that inflates it on every release, not just the overflowing ones,
    /// would make that signal fire constantly and be worthless. Assert the
    /// exact count instead: of `DEFAULT_POOL_CHUNKS + 10` chunks acquired
    /// then released from an empty pool, exactly 10 overflow the cap.
    #[test]
    fn ct7_over_cap_releases_counts_exactly_the_overflow() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = stats();
        let mut bufs = Vec::with_capacity(DEFAULT_POOL_CHUNKS + 10);
        for _ in 0..(DEFAULT_POOL_CHUNKS + 10) {
            bufs.push(acquire());
        }
        drop(bufs);
        assert_eq!(stats().free_chunks, DEFAULT_POOL_CHUNKS);
        assert_eq!(stats().over_cap_releases, base.over_cap_releases + 10);
    }

    #[test]
    fn outstanding_is_exact_under_interleaving() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = stats();
        let mut live: Vec<PooledBuf> = Vec::new();

        for _ in 0..5 {
            live.push(acquire());
        }
        assert_eq!(stats().outstanding - base.outstanding, 5);

        for _ in 0..2 {
            live.pop();
        }
        assert_eq!(stats().outstanding - base.outstanding, 3);

        for _ in 0..3 {
            live.push(acquire());
        }
        assert_eq!(stats().outstanding - base.outstanding, 6);

        live.clear();
        assert_eq!(stats().outstanding - base.outstanding, 0);
    }

    /// Edge case: a `PooledBuf` dropped while THIS thread's pool is already
    /// borrowed, for example by code running inside a `BufPool::with_current`
    /// closure. `Drop for PooledBuf` is written defensively for exactly this
    /// (`POOL.try_with` and `try_borrow_mut`, not `with`/`borrow_mut`), unlike
    /// `BufPool::with_current` itself, which is not defensive (see the filed
    /// follow-up on that gap) and would panic with "already borrowed" if it
    /// were the one re-entering. This test exercises the already-correct
    /// `Drop` path: dropping inside a `with_current` closure must not panic,
    /// and since the pool cannot be reached to receive the chunk back, it
    /// must fall back to an over-cap release rather than silently losing the
    /// accounting.
    #[test]
    fn ct8_drop_inside_with_current_does_not_panic() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = stats();
        let buf = acquire();
        BufPool::with_current(move |p| {
            drop(buf);
            // The pool is still usable for its own borrower afterward: the
            // panic this test rules out would have unwound out of this
            // closure instead of reaching here.
            let _ = p.cap_chunks();
        });
        assert_eq!(stats().outstanding, base.outstanding);
        assert_eq!(stats().over_cap_releases, base.over_cap_releases + 1);
    }

    #[test]
    fn filled_reads_back_and_accepts_the_whole_chunk() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut buf = acquire();
        buf.as_mut_slice()[..4].copy_from_slice(b"abcd");
        buf.set_filled(4);
        assert_eq!(buf.filled(), b"abcd");
        assert_eq!(buf.filled_len(), 4);

        buf.set_filled(0);
        assert!(buf.filled().is_empty());

        buf.set_filled(CHUNK_SIZE);
        assert_eq!(buf.filled_len(), CHUNK_SIZE);
    }

    #[test]
    fn decay_shrinks_after_idle_interval() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fill_pool_to(200);

        let ts = TestTimeSource::new();
        BufPool::with_current(|p| p.maybe_decay(ts.coarse_mono()));
        assert_eq!(stats().free_chunks, 200);

        ts.advance_ms(60_001);
        BufPool::with_current(|p| p.maybe_decay(ts.coarse_mono()));
        assert_eq!(stats().free_chunks, 100);
    }

    #[test]
    fn decay_is_a_noop_before_the_interval() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fill_pool_to(200);

        let ts = TestTimeSource::new();
        ts.advance_ms(59_999);
        BufPool::with_current(|p| p.maybe_decay(ts.coarse_mono()));
        assert_eq!(stats().free_chunks, 200);
    }

    #[test]
    fn decay_uses_high_water_mark() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fill_pool_to(200);

        let mut held = Vec::with_capacity(150);
        for _ in 0..150 {
            held.push(acquire());
        }
        assert_eq!(stats().free_chunks, 50);

        let ts = TestTimeSource::new();
        ts.advance_ms(60_001);
        BufPool::with_current(|p| p.maybe_decay(ts.coarse_mono()));
        // threshold = cap / 2 == 128; hwm_free == 200 > 128, so keep = free.len() / 2
        // == 25. The instantaneous free count (50) alone would not have crossed 128,
        // which is exactly the case that distinguishes the high-water-mark rule from
        // an instantaneous one.
        assert_eq!(stats().free_chunks, 25);

        drop(held);
    }

    /// Catches `last_decay` being advanced unconditionally (hoisted above the
    /// due check) instead of only when a decay actually fires. All three
    /// tests above call `maybe_decay` exactly once, which cannot distinguish
    /// "advances only when due" from "advances every call": both leave
    /// `last_decay` at the same value after a single call. This test makes a
    /// NOT-due call first (which must leave `last_decay` untouched) and then
    /// a second call whose "due" verdict depends on the interval being
    /// measured from the ORIGINAL start rather than from the first call's
    /// timestamp. Under the hoisting defect, `maybe_decay` is called once per
    /// event loop turn (per issue #13), so `last_decay` would advance every
    /// turn and the 60-second interval would never elapse: a one-minute
    /// traffic spike would become permanent resident memory.
    #[test]
    fn ct3_decay_last_decay_only_advances_when_due() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fill_pool_to(200);

        let ts = TestTimeSource::new();
        ts.advance_ms(30_000);
        BufPool::with_current(|p| p.maybe_decay(ts.coarse_mono()));
        // Not due yet (30s < 60s): must be a no-op, including on `last_decay`.
        assert_eq!(stats().free_chunks, 200);

        ts.advance_ms(30_002); // total elapsed since start: 60_002ms
        BufPool::with_current(|p| p.maybe_decay(ts.coarse_mono()));
        // Correct: elapsed since the ORIGINAL start (not since the first,
        // not-due call) now exceeds 60s, so decay fires on this second call.
        // Under the hoisting defect, the first call would have already moved
        // `last_decay` to the 30s mark, so only 30_002ms would have elapsed
        // since `last_decay` here, still short of the 60s threshold, and this
        // assertion would fail.
        assert_eq!(stats().free_chunks, 100);
    }

    /// Catches the high-water gate being removed (truncating unconditionally
    /// on every due tick regardless of `hwm_free`). All three existing decay
    /// tests fill the pool far above the cap/2 threshold (200 against a
    /// threshold of 128), so none of them can tell "decays because it is
    /// over threshold" apart from "decays unconditionally". This test sits
    /// the pool EXACTLY AT the threshold (cap/2 == 128, via `fill_pool_to`),
    /// where the gate is a strict `>` and must NOT fire. A worker steady at a
    /// load below (or at) half its cap must never lose its warm pool: under
    /// the unconditional-truncate defect, it would be halved every 60
    /// seconds regardless, degrading every subsequent acquire on that thread
    /// to an allocate-and-zero.
    #[test]
    #[allow(
        clippy::integer_division,
        reason = "cap/2 is the exact threshold boundary under test, not a lossy approximation"
    )]
    fn ct4_decay_leaves_pool_alone_at_or_below_threshold() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let half_cap = DEFAULT_POOL_CHUNKS / 2;
        fill_pool_to(half_cap); // hwm_free == cap/2 exactly

        let ts = TestTimeSource::new();
        ts.advance_ms(60_001);
        BufPool::with_current(|p| p.maybe_decay(ts.coarse_mono()));
        assert_eq!(stats().free_chunks, half_cap);
    }

    /// Catches `hwm_free` never being reset after a decay fires. All three
    /// existing decay tests call `maybe_decay` exactly once, so none of them
    /// can observe a SECOND tick, which is the only place a stale high-water
    /// mark shows up. This test fires a real decay (pool spikes to 200, halves
    /// to 100) and then, a full interval later with the pool sitting quietly
    /// at 100 (below the cap/2 == 128 threshold), asserts the pool is left
    /// alone. Under the defect, `hwm_free` would still read 200 from the
    /// first spike, so the pool would be halved again on every subsequent
    /// tick regardless of load, decaying to zero over time no matter how
    /// busy the worker actually is.
    #[test]
    fn ct5_decay_resets_high_water_mark_after_firing() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fill_pool_to(200);

        let ts = TestTimeSource::new();
        ts.advance_ms(60_001);
        BufPool::with_current(|p| p.maybe_decay(ts.coarse_mono()));
        assert_eq!(stats().free_chunks, 100);

        ts.advance_ms(60_001); // a second full interval, pool untouched at 100
        BufPool::with_current(|p| p.maybe_decay(ts.coarse_mono()));
        // 100 <= threshold (128), so a correctly reset `hwm_free` must leave
        // this alone. A stale `hwm_free` of 200 would halve it again to 50.
        assert_eq!(stats().free_chunks, 100);
    }

    #[test]
    fn compact_exact_copies_and_is_independent() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = stats();
        let mut buf = acquire();
        buf.as_mut_slice()[..5].copy_from_slice(b"hello");
        let compacted = compact_exact(&buf.as_mut_slice()[..5]);
        drop(buf);
        assert_eq!(&compacted[..], b"hello");
        assert_eq!(stats().outstanding, base.outstanding);
    }

    #[test]
    fn compact_exact_empty_is_empty() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let out = compact_exact(&[]);
        assert!(out.is_empty());
    }

    /// The module's entire reason to exist: `compact_exact` must allocate
    /// EXACTLY `src.len()`, never `CHUNK_SIZE` (the source chunk's size),
    /// never a doubling growth strategy, and never an off-by-one. The two
    /// tests above only check content and length, and both stay green under
    /// `BytesMut::with_capacity(src.len())` mutated to `with_capacity(CHUNK_SIZE)`,
    /// to `src.len() * 2 + 64`, or to `src.len() + 1`: an over-sized backing
    /// allocation still holds the right bytes at the right length, it just
    /// also pins the rest of the allocation. That pinned tail is exactly the
    /// "slice retention amplification" the module doc quotes numbers for
    /// (3.2 GiB instead of about 90 MB at 100,000 connections for a 20-byte
    /// header value), so capacity, not content or length, is the assertion
    /// that actually proves the function does its job.
    #[test]
    fn ct1_compact_exact_allocates_exactly_src_len() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for n in [1_usize, 20, 900] {
            let data = vec![0xAB_u8; n];
            let out = compact_exact(&data);
            let back = out
                .try_into_mut()
                .unwrap_or_else(|_| panic!("compact_exact must return a uniquely owned Bytes"));
            assert_eq!(
                back.capacity(),
                n,
                "compact_exact(n={n}) must allocate exactly n bytes, not a larger \
                 (slice-retention-amplifying) or smaller backing allocation"
            );
        }
    }

    /// Same defect, reached through the public method callers actually use.
    /// `compact_exact` is a private free function; `into_bytes_exact` is what
    /// production code will call once a later issue wires it in, so the
    /// exactness guarantee has to hold at that call site too, not only at the
    /// free function `ct1` exercises directly.
    #[test]
    fn ct2_into_bytes_exact_allocates_exactly_filled_len() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut buf = acquire();
        buf.set_filled(20);
        let out = buf.into_bytes_exact();
        let back = out
            .try_into_mut()
            .unwrap_or_else(|_| panic!("into_bytes_exact must return a uniquely owned Bytes"));
        assert_eq!(back.capacity(), 20);
    }

    #[test]
    fn slice_retention_is_visible_without_compaction() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = stats();
        let mut buf = acquire();
        buf.set_filled(20);
        let out = buf.into_bytes_exact();
        assert_eq!(stats().outstanding, base.outstanding);
        assert_eq!(out.len(), 20);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn recycled_chunk_is_poisoned_in_debug_builds() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut buf = acquire();
        buf.as_mut_slice()[..14].copy_from_slice(b"SECRET-PAYLOAD");
        buf.set_filled(14);
        drop(buf);

        let mut buf2 = acquire();
        let recycled = &buf2.as_mut_slice()[..14];
        assert!(recycled.iter().all(|&b| b == 0xDB));
        assert_ne!(recycled, b"SECRET-PAYLOAD");
    }

    /// The test above inspects 14 of the chunk's 32,768 bytes, the exact
    /// length of the secret it wrote. An implementation that poisoned only a
    /// prefix (say, up to the previous holder's recorded `filled` length,
    /// which happens to be 14 here too) would still pass it. Poisoning is
    /// documented and implemented as filling the WHOLE chunk (`c.fill(0xDB)`
    /// over all `CHUNK_SIZE` bytes), because a future reader is trusted to
    /// respect `filled`, not the poison pattern; check the whole chunk here
    /// to actually pin that.
    #[cfg(debug_assertions)]
    #[test]
    fn ct9_recycled_chunk_is_poisoned_across_the_whole_chunk() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut buf = acquire();
        buf.as_mut_slice()[..14].copy_from_slice(b"SECRET-PAYLOAD");
        buf.set_filled(14);
        drop(buf);

        let mut buf2 = acquire();
        let whole = buf2.as_mut_slice();
        assert_eq!(whole.len(), CHUNK_SIZE);
        assert!(
            whole.iter().all(|&b| b == 0xDB),
            "every one of the chunk's {CHUNK_SIZE} bytes must be poisoned on take, not just \
             the prefix a previous holder happened to record as filled"
        );
    }

    /// The debug-build poison fill is behind `#[cfg(debug_assertions)]`
    /// precisely so a release build pays nothing for it (see `BufPool::take`).
    /// Nothing in this suite previously ran under a release build to confirm
    /// that side of the `cfg`: a poison fill that leaked into release builds
    /// would silently zero or scramble recycled chunks in production and
    /// nothing here would notice. `cargo test --release` compiles this arm
    /// instead of the one above.
    #[cfg(not(debug_assertions))]
    #[test]
    fn ct10_recycled_chunk_is_not_poisoned_in_release_builds() {
        let _g = POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut buf = acquire();
        buf.as_mut_slice()[..14].copy_from_slice(b"SECRET-PAYLOAD");
        buf.set_filled(14);
        drop(buf);

        let mut buf2 = acquire();
        assert_eq!(&buf2.as_mut_slice()[..14], b"SECRET-PAYLOAD");
    }

    #[derive(Debug, Clone, Copy)]
    enum PoolOp {
        Acquire,
        DropOldest,
        DropNewest,
    }

    fn pool_op_strategy() -> impl Strategy<Value = PoolOp> {
        prop_oneof![
            // Unweighted (1:1:1), this generator is a downward-biased random
            // walk: `live.len()` starts at 0 and can only be pulled back
            // down by two drop variants against one acquire variant, so it
            // rarely climbs. Weighted 4:1:1 toward Acquire, it actually
            // reaches the pool's cap, which is the only way a bound
            // asserted below (`free_chunks <= DEFAULT_POOL_CHUNKS`) is ever
            // exercised near its edge instead of staying decorative.
            4 => Just(PoolOp::Acquire),
            1 => Just(PoolOp::DropOldest),
            1 => Just(PoolOp::DropNewest),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn prop_pool_conservation(ops in prop::collection::vec(pool_op_strategy(), 0..=1024)) {
            let _g = POOL_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let baseline = stats().outstanding;
            let mut live: Vec<PooledBuf> = Vec::new();

            for op in ops {
                match op {
                    PoolOp::Acquire => live.push(acquire()),
                    PoolOp::DropOldest => {
                        if !live.is_empty() {
                            drop(live.remove(0));
                        }
                    }
                    PoolOp::DropNewest => {
                        drop(live.pop());
                    }
                }
                let s = stats();
                let expected = u64::try_from(live.len())
                    .expect("live guard count fits in u64 within a 1024-operation run");
                prop_assert_eq!(s.outstanding - baseline, expected);
                prop_assert!(s.free_chunks <= DEFAULT_POOL_CHUNKS);
            }
        }
    }
}
