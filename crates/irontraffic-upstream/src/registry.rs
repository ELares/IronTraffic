// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`EndpointId`], the stable process-global endpoint identifier, and the
//! interning slab that hands them out.
//!
//! [`EndpointRegistry`] is the read half: `Sync`, shared, allocated once at
//! startup, atomics and immutable arrays only. [`EndpointRegistryWriter`] is the
//! write half: exactly one exists, owned by the configuration plane, and mutual
//! exclusion is by ownership rather than a lock, because this is a hot-path crate
//! and CI forbids `Mutex`, `RwLock`, and `.lock()` here.
//!
//! Ids are dense `u32` indices into a fixed-capacity arena that is never resized:
//! resizing would move the arena and invalidate every `&EndpointStats` reference
//! the request path holds. A retired id is recycled only after the process-global
//! snapshot generation has advanced by at least [`RECYCLE_GRACE_GENERATIONS`] and
//! at least [`RECYCLE_GRACE_MS`] of coarse time has passed, which is what keeps a
//! worker's stale local index, an in-flight request accounted against the old
//! endpoint, or a sticky-affinity cookie in a client's browser from silently
//! pointing at a different endpoint after reuse.
//!
//! `intern` and `lookup` always render an identity with `use_hostname = false`:
//! the registry key is the network location, never the hostname, so two
//! `EndpointIdentity` values that share an `addr` intern to the same id and share
//! one statistics line. The writer's own lookup table (`index`) is deliberately
//! left on the standard library's `RandomState`: identity bytes are
//! control-plane-influenced (derived from pod IPs and `EndpointSlice` hostnames a
//! tenant can influence in a multi-tenant cluster), and `RandomState`'s
//! per-process random `SipHash` key is what makes offline collision grinding
//! against this map impossible. This is a different concern from the
//! consistent-hash table build in later issues, which needs a fixed, replica
//! stable ordering; both are correct, for different maps.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use crate::identity::EndpointIdentity;
use crate::stats::EndpointStats;
use crate::{CoarseMillis, MAX_IDENTITY_BYTES};

/// Number of coarse milliseconds a retired id must sit idle before it may be
/// reused.
pub const RECYCLE_GRACE_MS: u32 = 60_000;

/// Number of snapshot generations that must elapse before a retired id may be
/// reused.
pub const RECYCLE_GRACE_GENERATIONS: u64 = 2;

/// Default slab capacity, in endpoints, across all clusters. 128 bytes each, so
/// 2 MiB.
pub const DEFAULT_CAPACITY: u32 = 16_384;

/// Hard ceiling on slab capacity: 1,048,576 endpoints, 128 MiB of address space.
pub const MAX_CAPACITY: u32 = 1 << 20;

/// Maximum ids one `recycle` call may free. Bounds the pause a mass retirement
/// can impose on the rebuild thread.
pub const RECYCLE_BATCH: usize = 4096;

/// Stable, process-global identifier for one upstream endpoint. A dense index
/// into the registry's slab, valid until the id is retired and recycled.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct EndpointId(pub u32);

/// Read half of the endpoint slab: shared, `Sync`, allocated once, never
/// resized.
pub struct EndpointRegistry {
    capacity: u32,
    stats: Box<[EndpointStats]>,
    /// 0 = free, 1 = live, 2 = retired. Read by the writer only; separate from
    /// `stats` so the request path never touches this array.
    states: Box<[AtomicU8]>,
    /// Two monotone counters rather than one balance: `live_count()` is
    /// `interned - retired_total`. A decrementing counter would need
    /// `fetch_sub`, which CI bans outside a `Drop` impl in a hot-path crate, and
    /// the single-writer rule makes the difference of two monotone counters
    /// exact.
    interned: AtomicU32,
    retired_total: AtomicU32,
}

impl EndpointRegistry {
    /// Slab capacity in endpoints.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Live endpoint count.
    ///
    /// `interned.wrapping_sub(retired_total)`, not a plain `-`: both counters are
    /// monotone `u32`s that count operations rather than live objects, so after
    /// 2^32 interns the minuend wraps while the difference stays exact. A plain
    /// `-` would panic in a debug build at that point.
    #[must_use]
    pub fn live_count(&self) -> u32 {
        self.interned
            .load(Ordering::Relaxed)
            .wrapping_sub(self.retired_total.load(Ordering::Relaxed))
    }

    /// The whole stats arena. Index with `EndpointId::0`. The load-balancer hot
    /// path takes this slice once and indexes it directly.
    #[must_use]
    pub fn stats_slice(&self) -> &[EndpointStats] {
        &self.stats
    }

    /// Stats for one id, or `None` if the id is out of range.
    #[must_use]
    pub fn stats(&self, id: EndpointId) -> Option<&EndpointStats> {
        self.stats.get(id.0 as usize)
    }

    /// The slot generation for `id`, or `None` if out of range. A sticky
    /// affinity token is valid only if it carries this exact value.
    #[must_use]
    pub fn slot_generation(&self, id: EndpointId) -> Option<u32> {
        self.stats
            .get(id.0 as usize)
            .map(|s| s.generation.load(Ordering::Relaxed))
    }

    /// Allocates the slab and leaks it, returning the shared read half and the
    /// single write half. Call once per process at startup, before any worker
    /// starts.
    ///
    /// The leak is deliberate: the read half must be `&'static` so that an
    /// `InflightGuard` held across an await point does not need to carry a
    /// lifetime or an `Arc` clone.
    ///
    /// May be called more than once in one process: each call leaks its own
    /// independent arena of `128 * capacity` bytes and returns its own writer.
    /// There is no global singleton and no `OnceLock`.
    ///
    /// This method is placed last in this `impl` block, deliberately: it is the
    /// only one whose body carries a `cfg(test)`-conditional struct-literal
    /// field, and that form of conditional compilation is invisible to the one
    /// text-based tool in this tree that looks specifically for a `cfg(test)`
    /// module (`scripts/invariant-lints.sh`'s production-source shadow-tree
    /// builder, which every "-prod"-suffixed rule and every hot-path-crate rule
    /// reads instead of the real source). That tool finds this attribute, then
    /// searches forward for the next brace pair to blank out, on the reasonable
    /// but here-incorrect assumption that a `cfg(test)` attribute always
    /// introduces a module body. Placed last, the nearest brace pair after it
    /// belongs to [`RegistryError`] below, an inert enum with no logic to hide;
    /// placed anywhere earlier, the same search would swallow the next real
    /// method in this `impl` block instead, silently hiding it from those
    /// rules. See the implementation report for this issue for the general
    /// case, which is not specific to this one field.
    ///
    /// # Errors
    /// [`RegistryError::InvalidCapacity`] when `capacity` is zero or exceeds
    /// [`MAX_CAPACITY`]. `install` rejects rather than clamps: exceeding the
    /// ceiling is a configuration error the operator must consciously fix, never
    /// a silent reallocation.
    #[allow(
        clippy::disallowed_methods,
        reason = "control-plane construction, never the request path"
    )]
    pub fn install(
        capacity: u32,
    ) -> Result<(&'static EndpointRegistry, EndpointRegistryWriter), RegistryError> {
        if capacity == 0 || capacity > MAX_CAPACITY {
            return Err(RegistryError::InvalidCapacity { capacity });
        }
        let stats: Box<[EndpointStats]> = (0..capacity)
            .map(|_| EndpointStats::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let slot_states: Box<[AtomicU8]> = (0..capacity)
            .map(|_| AtomicU8::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let reg: &'static EndpointRegistry = Box::leak(Box::new(EndpointRegistry {
            capacity,
            stats,
            states: slot_states,
            interned: AtomicU32::new(0),
            retired_total: AtomicU32::new(0),
        }));
        let writer = EndpointRegistryWriter {
            reg,
            index: HashMap::new(),
            keys: (0..capacity).map(|_| None).collect(),
            retired: VecDeque::new(),
            next_free: 0,
            _not_sync: core::marker::PhantomData,
            #[cfg(test)]
            scan_steps: std::cell::Cell::new(0),
        };
        Ok((reg, writer))
    }
}

/// Why a registry operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The slab is full. Raise `upstream.max_endpoints`.
    #[error("endpoint slab is full at capacity {capacity}")]
    CapacityExhausted {
        /// The slab capacity that was exhausted.
        capacity: u32,
    },
    /// The identity does not fit in `MAX_IDENTITY_BYTES`.
    #[error("endpoint identity exceeds {MAX_IDENTITY_BYTES} bytes")]
    IdentityTooLong,
    /// `capacity` was zero or above `MAX_CAPACITY`.
    #[error("invalid slab capacity {capacity}, must be 1..={MAX_CAPACITY}")]
    InvalidCapacity {
        /// The capacity that was requested.
        capacity: u32,
    },
}

/// Write half: exactly one exists, owned by the configuration plane. Not
/// `Clone`, not `Sync`. Mutual exclusion is by ownership, because this crate may
/// not take a lock.
///
/// Every field is otherwise `Sync`, so `!Sync` must be requested explicitly with
/// a `PhantomData` marker over `Cell`. Without it the compiler auto-derives
/// `Sync` and the "exactly one writer" rule becomes prose rather than a
/// type-level guarantee.
pub struct EndpointRegistryWriter {
    reg: &'static EndpointRegistry,
    /// Identity bytes to id. Keyed on the rendered identity so lookup and the
    /// build-time sort agree by construction.
    ///
    /// No explicit hasher. The standard-library `RandomState` is load-bearing
    /// here: the keys are control-plane-influenced byte strings and a
    /// per-process random `SipHash` key is what makes collision grinding
    /// impossible.
    index: HashMap<Box<[u8]>, EndpointId>,
    /// Slot index to the identity bytes currently interned in that slot, or
    /// `None` when the slot is free or retired. Allocated once at `install` with
    /// one entry per slot.
    ///
    /// This array is what makes `retire(id)` cheap. `index` is keyed by identity
    /// bytes, so removing an entry given only an id would otherwise be an
    /// `O(C)` scan of the whole map. With it, `retire` is one array read plus
    /// one hash removal, which is `O(L)`.
    keys: Vec<Option<Box<[u8]>>>,
    /// Retired ids awaiting recycle, in retirement order.
    retired: VecDeque<Retired>,
    /// Scan cursor for the free-slot search, so the common case is O(1)
    /// amortised.
    next_free: u32,
    /// Makes the writer `!Sync` while leaving it `Send`. A `Cell` is `Send` and
    /// `!Sync`, which is exactly the pair of properties required.
    _not_sync: core::marker::PhantomData<core::cell::Cell<()>>, // it-allow: interior-mutability reason: zero-sized Send+!Sync marker, never constructed with a real value and never reaches or holds mutable state; it exists solely to suppress the auto-derived Sync impl documented on this struct, which is the opposite of the per-core migration hazard this rule guards against
    /// Test-only instrumentation: counts how many slot-scan iterations `intern`
    /// performed since the writer was created. Lets a test prove the saturated
    /// fast path (step 3a in the design this module implements) returns without
    /// ever entering the O(capacity) scan loop. Never compiled into a
    /// production build.
    #[cfg(test)]
    scan_steps: std::cell::Cell<u64>,
}

/// One retired id awaiting recycle, and the identity bytes it was interned
/// under: `retire` needs the bytes to remove the matching entry from `index`,
/// and holding them here (rather than looking them up again) is what makes
/// `recycle` not need to touch `index` at all.
struct Retired {
    id: EndpointId,
    #[allow(
        dead_code,
        reason = "kept alive only to be dropped when this entry is recycled: freeing this \
                  allocation is the O(L) cost `recycle` accounts for in the complexity table, \
                  and no algorithm in this issue reads the bytes again once retire() has \
                  already removed them from `index`; a non-test build therefore never reads \
                  this field, which is expected rather than a bug"
    )]
    key: Box<[u8]>,
    at_generation: u64,
    at_ms: CoarseMillis,
}

impl EndpointRegistryWriter {
    #[cfg(test)]
    fn record_scan_step(&self) {
        self.scan_steps.set(self.scan_steps.get().wrapping_add(1));
    }

    #[cfg(not(test))]
    #[allow(
        clippy::unused_self,
        reason = "mirrors the cfg(test) counterpart's signature so intern's call site needs \
                  no conditional syntax; the test build's version does use self"
    )]
    fn record_scan_step(&self) {}

    /// Returns the id for `identity`, allocating one if it is not already
    /// interned. Idempotent: interning the same identity twice returns the same
    /// id and does not bump the slot's generation.
    ///
    /// Always renders `identity` with `use_hostname = false`: the registry key
    /// is the network location, never the hostname, so two identities that
    /// share an `addr` intern to the same id.
    ///
    /// # Errors
    /// [`RegistryError::IdentityTooLong`] when the rendered identity exceeds
    /// [`MAX_IDENTITY_BYTES`]. [`RegistryError::CapacityExhausted`] when the
    /// slab has no free slot, including when a retired id exists but is not yet
    /// eligible for recycling, or is eligible but `recycle` has not yet been
    /// called: `intern` takes neither a clock nor a snapshot generation, so it
    /// cannot evaluate the recycle grace itself.
    #[allow(
        clippy::disallowed_methods,
        reason = "control-plane construction, never the request path"
    )]
    pub fn intern(&mut self, identity: &EndpointIdentity) -> Result<EndpointId, RegistryError> {
        let mut buf = [0u8; MAX_IDENTITY_BYTES];
        let Some(len) = identity.identity_bytes(false, &mut buf) else {
            return Err(RegistryError::IdentityTooLong);
        };
        let Some(bytes) = buf.get(..len) else {
            // Cannot happen: identity_bytes never returns a length past its own
            // buffer's size. Treated as too-long rather than indexed directly
            // with `[..len]`, because this crate denies
            // `clippy::indexing_slicing`.
            return Err(RegistryError::IdentityTooLong);
        };
        if let Some(id) = self.index.get(bytes) {
            return Ok(*id);
        }

        let capacity = self.reg.capacity;

        // Full-slab fast path, before any scan. `index.len()` counts state-1
        // slots (I-R2) and `retired.len()` counts state-2 slots (I-R3), so
        // their sum equals the number of non-free slots exactly. When it
        // equals `capacity` there is provably no state-0 slot, and the scan
        // below cannot find one; skipping straight to the error keeps a
        // saturated slab from turning every subsequent rejected `intern` into
        // an O(capacity) scan, which would let a churning control plane stall
        // the rebuild thread.
        if self.index.len().saturating_add(self.retired.len()) == capacity as usize {
            return Err(RegistryError::CapacityExhausted { capacity });
        }

        // Scan upward from next_free, wrapping exactly once back to it: the
        // first free slot in that rotated order, not the numerically lowest
        // free slot, so the common case is O(1) amortised.
        let start = self.next_free;
        let mut found: Option<u32> = None;
        let mut offset: u32 = 0;
        while offset < capacity {
            self.record_scan_step();
            let slot = start.wrapping_add(offset) % capacity;
            let is_free = self
                .reg
                .states
                .get(slot as usize)
                .is_some_and(|s| s.load(Ordering::Relaxed) == 0);
            if is_free {
                found = Some(slot);
                break;
            }
            offset += 1;
        }

        // Unreachable given the fast path above, which already proved a free
        // slot exists; kept as the belt to that fast path's braces, and it
        // returns the error rather than panicking or looping if that
        // invariant were ever violated.
        let Some(slot) = found else {
            return Err(RegistryError::CapacityExhausted { capacity });
        };

        let Some(state) = self.reg.states.get(slot as usize) else {
            return Err(RegistryError::CapacityExhausted { capacity });
        };
        state.store(1, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic per-slot state transition, not an ArcSwap config snapshot publish; this crate defines no ArcSwap, and every write here is already exclusive because exactly one EndpointRegistryWriter exists (see its own Send+!Sync marker above)

        let Some(slot_stats) = self.reg.stats.get(slot as usize) else {
            return Err(RegistryError::CapacityExhausted { capacity });
        };
        // Reset the slot's statistics field by field with relaxed atomic
        // stores, preserving the generation counter, then bump it. The writer
        // holds a SHARED `&'static EndpointRegistry`, so
        // `stats[slot] = EndpointStats::default()` is not expressible without
        // `unsafe`; every field is an atomic precisely so the reset is a
        // sequence of stores instead.
        let generation = slot_stats.generation.load(Ordering::Relaxed);
        slot_stats.inflight.store(0, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic per-slot counter reset, not an ArcSwap config snapshot publish; see the state store above
        slot_stats.active_conns.store(0, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic per-slot counter reset, not an ArcSwap config snapshot publish; see the state store above
        slot_stats.cost.store(0, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic per-slot counter reset, not an ArcSwap config snapshot publish; see the state store above
        slot_stats.healthy_since_ms.store(0, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic per-slot counter reset, not an ArcSwap config snapshot publish; see the state store above
        slot_stats.left_healthy_ms.store(0, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic per-slot counter reset, not an ArcSwap config snapshot publish; see the state store above
        slot_stats
            .generation
            .store(generation.wrapping_add(1), Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic per-slot generation bump, not an ArcSwap config snapshot publish; see the state store above

        let key: Box<[u8]> = bytes.into();
        if let Some(slot_key) = self.keys.get_mut(slot as usize) {
            *slot_key = Some(key.clone());
        }
        self.index.insert(key, EndpointId(slot));
        self.reg.interned.fetch_add(1, Ordering::Relaxed);
        self.next_free = slot.wrapping_add(1) % capacity;
        Ok(EndpointId(slot))
    }

    /// Looks up an existing id without allocating one. Always renders
    /// `identity` with `use_hostname = false`, matching `intern`.
    #[must_use]
    pub fn lookup(&self, identity: &EndpointIdentity) -> Option<EndpointId> {
        let mut buf = [0u8; MAX_IDENTITY_BYTES];
        let len = identity.identity_bytes(false, &mut buf)?;
        let bytes = buf.get(..len)?;
        self.index.get(bytes).copied()
    }

    /// Marks `id` retired as of `snapshot_generation` and `now_ms`. Idempotent;
    /// retiring a free or already-retired id does nothing and never panics.
    ///
    /// `snapshot_generation` MUST be the process-global monotone generation,
    /// that is the maximum published generation across every cluster, and NOT
    /// one cluster's own generation. The registry is process-global while
    /// generations are per cluster, so comparing a value produced by cluster A
    /// against a value produced by cluster B is comparing two unrelated
    /// counters, and `RECYCLE_GRACE_GENERATIONS` would then mean nothing.
    /// `retire` and `recycle` must both be given the same quantity, which is
    /// what `UpstreamTable::max_generation()` returns.
    pub fn retire(&mut self, id: EndpointId, now_ms: CoarseMillis, snapshot_generation: u64) {
        let Some(state) = self.reg.states.get(id.0 as usize) else {
            return;
        };
        if state.load(Ordering::Relaxed) != 1 {
            return;
        }
        state.store(2, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic per-slot state transition, not an ArcSwap config snapshot publish; see the reason on the state store in intern above
        let Some(slot_key) = self.keys.get_mut(id.0 as usize) else {
            return;
        };
        let Some(key) = slot_key.take() else {
            return;
        };
        self.index.remove(&key);
        self.retired.push_back(Retired {
            id,
            key,
            at_generation: snapshot_generation,
            at_ms: now_ms,
        });
        self.reg.retired_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Frees every retired id whose grace conditions have both been met.
    /// Returns the number freed. Cheap to call on every snapshot publish.
    ///
    /// The queue is strictly FIFO in retirement order and both grace
    /// conditions are monotone in that order, so stopping at the first entry
    /// that is not yet eligible is correct: this is O(freed), not
    /// `O(retired_len())`. At most [`RECYCLE_BATCH`] ids are freed per call, so a
    /// mass retirement (a control plane deleting a 100,000-pod Deployment)
    /// cannot make one call arbitrarily long; a caller that wants the queue
    /// fully drained calls in a loop. Freeing an id late is harmless, which is
    /// why the grace conditions have no batch-related exception.
    ///
    /// `snapshot_generation` is the same process-global monotone value
    /// `retire` takes; see its documentation.
    pub fn recycle(&mut self, now_ms: CoarseMillis, snapshot_generation: u64) -> usize {
        let mut freed = 0usize;
        while freed < RECYCLE_BATCH {
            let Some(front) = self.retired.front() else {
                break;
            };
            if snapshot_generation
                < front
                    .at_generation
                    .saturating_add(RECYCLE_GRACE_GENERATIONS)
            {
                break;
            }
            if now_ms.wrapping_sub(front.at_ms) < RECYCLE_GRACE_MS {
                break;
            }
            let Some(popped) = self.retired.pop_front() else {
                // Cannot happen: `front()` above just proved the queue is
                // non-empty, and this writer is the only mutator (see its own
                // Send+!Sync marker), so nothing could have emptied it between
                // the two calls.
                break;
            };
            if let Some(state) = self.reg.states.get(popped.id.0 as usize) {
                state.store(0, Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic per-slot state transition, not an ArcSwap config snapshot publish; see the reason on the state store in intern above
            }
            freed += 1;
        }
        freed
    }

    /// Number of ids currently retired and not yet recycled.
    #[must_use]
    pub fn retired_len(&self) -> usize {
        self.retired.len()
    }
}

/// Compile-fail proof that [`EndpointRegistryWriter`] does not implement `Sync`.
///
/// If this ever compiles, the `PhantomData`-over-`Cell` marker on
/// `EndpointRegistryWriter` stopped suppressing the compiler's auto-derived
/// `Sync` impl, and the single-writer invariant this module's design depends on
/// (I-R2 through I-R4) is no longer enforced by the type system rather than by
/// prose.
///
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<irontraffic_upstream::EndpointRegistryWriter>();
/// ```
#[doc(hidden)]
pub const fn writer_not_sync_proof() {}

/// `T` implements `Send`. Called only from the `const _: () = ...` blocks
/// below: a failed bound is a compile error at that call site, which is the
/// actual proof: the boolean return exists only so `assert!` has something
/// to name.
const fn assert_send<T: Send>() -> bool {
    let _ = core::marker::PhantomData::<T>;
    true
}

/// `T` implements `Sync`. See [`assert_send`].
const fn assert_sync<T: Sync>() -> bool {
    let _ = core::marker::PhantomData::<T>;
    true
}

// EndpointRegistryWriter must be Send (so the configuration plane can move it
// between threads at startup) and, separately, must NOT be Sync (enforced by
// the compile_fail doctest above). This is the same `const _: () = { assert!(
// assert_send::<T>()); }` idiom `irontraffic-rand`'s `Rng` and
// `irontraffic-io`'s `ShutdownToken` already use for exactly this kind of
// property: it runs at compile time on every build, not only under `cargo
// test`, and a failed bound is a compile error rather than a test failure
// with no assertion in its body.
const _: () = assert!(assert_send::<EndpointRegistryWriter>());

// EndpointRegistry must be both Send and Sync: it is the shared, `&'static`
// read half every worker thread reads from concurrently.
const _: () = assert!(assert_send::<EndpointRegistry>());
const _: () = assert!(assert_sync::<EndpointRegistry>());

#[cfg(test)]
mod tests {
    use super::{EndpointId, EndpointRegistry, EndpointRegistryWriter, Ordering, RegistryError};
    use crate::identity::{EndpointAddr, EndpointIdentity};

    fn identity(port: u16) -> EndpointIdentity {
        EndpointIdentity {
            addr: EndpointAddr::Socket(std::net::SocketAddr::from(([10, 0, 0, 1], port))),
            hostname: None,
        }
    }

    /// Capacity 4. Intern 4 identities, retire two of them without recycling,
    /// then intern two further distinct identities. Every one of the last two
    /// must return `Err(CapacityExhausted { capacity: 4 })` WITHOUT the slot
    /// scan advancing, proving the step 3a fast path fired rather than an
    /// O(capacity) walk.
    ///
    /// This lives here, as a unit test over `EndpointRegistryWriter`'s private
    /// `scan_steps` field, rather than in `tests/registry.rs`. `scan_steps` is
    /// gated on `cfg(test)` on the writer, and items gated that way in a
    /// library are never visible to that library's own integration tests: an
    /// integration test binary links against the library built WITHOUT
    /// `--cfg test`, so `scan_steps` would not exist there at all. See the
    /// implementation report for this issue.
    #[test]
    fn intern_when_saturated_does_not_scan() {
        let (_reg, mut writer) =
            EndpointRegistry::install(4).expect("capacity 4 is valid and under the ceiling");
        for port in 1..=4u16 {
            writer
                .intern(&identity(port))
                .expect("interning within capacity must succeed");
        }
        writer.retire(EndpointId(0), 0, 0);
        writer.retire(EndpointId(1), 0, 0);

        let before = writer.scan_steps.get();

        let err1 = writer
            .intern(&identity(5))
            .expect_err("the slab is saturated: 2 live + 2 retired == capacity");
        assert_eq!(err1, RegistryError::CapacityExhausted { capacity: 4 });
        assert_eq!(
            writer.scan_steps.get(),
            before,
            "the saturated fast path must not enter the scan loop"
        );

        let err2 = writer
            .intern(&identity(6))
            .expect_err("the slab is still saturated");
        assert_eq!(err2, RegistryError::CapacityExhausted { capacity: 4 });
        assert_eq!(
            writer.scan_steps.get(),
            before,
            "the saturated fast path must not enter the scan loop"
        );
    }

    /// Interning `N` identities into an otherwise-empty, non-saturated slab
    /// must cost exactly `N` scan steps in total: `next_free` is supposed to
    /// advance to the slot right after the one just assigned, so every call
    /// finds a free slot on its very first probe. Added after mutation
    /// testing found that replacing the `%` in `next_free`'s update
    /// (`slot.wrapping_add(1) % capacity`) with `/` survived every other test
    /// in this suite: the wrong `next_free` still produced the correct
    /// DENSE ASCENDING ids (matching `intern_assigns_dense_ascending_ids` in
    /// `tests/registry.rs`), just via an O(n) rescan every time instead of
    /// O(1) amortised, which only a step count can distinguish.
    #[test]
    fn intern_advances_next_free_so_each_call_costs_one_scan_step() {
        let (_reg, mut writer) =
            EndpointRegistry::install(100).expect("capacity 100 is valid and under the ceiling");
        let before = writer.scan_steps.get();
        for port in 1..=10u16 {
            writer
                .intern(&identity(port))
                .expect("interning within capacity must succeed");
        }
        assert_eq!(
            writer.scan_steps.get().wrapping_sub(before),
            10,
            "each of the 10 interns above should find a free slot on its first probe"
        );
    }

    /// One operation in the arbitrary sequence the property test below replays.
    #[derive(Debug, Clone, Copy)]
    enum Op {
        Intern(usize),
        Retire(u32, u32, u64),
        Recycle(u32, u64),
    }

    fn op_strategy() -> impl proptest::strategy::Strategy<Value = Op> {
        use proptest::prelude::*;
        prop_oneof![
            (0..8usize).prop_map(Op::Intern),
            (0..8u32, 0..=120_000u32, 0..=3u64).prop_map(|(id, dt, dgen)| Op::Retire(id, dt, dgen)),
            (0..=120_000u32, 0..=3u64).prop_map(|(dt, dgen)| Op::Recycle(dt, dgen)),
        ]
    }

    /// Walks every private array reachable from `reg` and `writer` and checks
    /// I-R1 through I-R5 (I-R6 is exercised by the targeted grace-period tests
    /// in `tests/registry.rs`, since it is a property of one retire/recycle
    /// pair rather than of an arbitrary snapshot). `last_gen` is the
    /// per-slot generation observed after the previous operation, threaded
    /// through so I-R5 (strictly non-decreasing generations) can be checked
    /// across steps rather than within one.
    ///
    /// Returns the number of state-1 slots counted while walking, so the
    /// caller can independently re-check I-R4 (the invariant the issue calls
    /// out as the one that matters most) against `live_count()` at the call
    /// site, rather than only inside this helper.
    fn assert_invariants(
        reg: &EndpointRegistry,
        writer: &EndpointRegistryWriter,
        last_gen: &mut [u32],
    ) -> u32 {
        let capacity = reg.capacity as usize;
        // I-R1.
        assert_eq!(
            reg.stats.len(),
            capacity,
            "I-R1: stats.len() must equal capacity"
        );
        assert_eq!(
            reg.states.len(),
            capacity,
            "I-R1: states.len() must equal capacity"
        );

        let mut state1_count: u32 = 0;
        for i in 0..capacity {
            let state = reg.states.get(i).map(|s| s.load(Ordering::Relaxed));
            if state == Some(1) {
                state1_count += 1;
            }
            let has_key = writer.keys.get(i).is_some_and(std::option::Option::is_some);
            // I-R2: a slot has a key if and only if it is state 1.
            assert_eq!(
                has_key,
                state == Some(1),
                "I-R2: slot {i} key presence must match state == 1"
            );
            if let Some(g) = reg
                .stats
                .get(i)
                .map(|s| s.generation.load(Ordering::Relaxed))
                && let Some(prev) = last_gen.get_mut(i)
            {
                // I-R5: a slot's generation is strictly increasing (with
                // wrapping_add) across allocations, and is never reset. Over a
                // bounded 200-operation run starting at generation 0 the
                // counter never nears its wrap point, so a plain `>=` is
                // exactly the non-decrease this invariant states.
                assert!(g >= *prev, "I-R5: slot {i} generation must never decrease");
                *prev = g;
            }
        }

        // I-R2: index.len() equals the number of Some entries in keys, and
        // every id in index names a state-1 slot whose keys entry holds
        // exactly those bytes.
        let live_keys = writer.keys.iter().filter(|k| k.is_some()).count();
        assert_eq!(
            writer.index.len(),
            live_keys,
            "I-R2: index.len() must equal live key count"
        );
        for (bytes, id) in &writer.index {
            let state = reg
                .states
                .get(id.0 as usize)
                .map(|s| s.load(Ordering::Relaxed));
            assert_eq!(state, Some(1), "I-R2: every id in index must be state 1");
            let stored = writer.keys.get(id.0 as usize).and_then(|k| k.as_deref());
            assert_eq!(
                stored,
                Some(bytes.as_ref()),
                "I-R2: keys[id] must hold exactly the bytes id is interned under"
            );
        }

        // I-R3: every retired entry is state 2, and retired holds no duplicate
        // id. No id may be simultaneously in index and in retired.
        let mut seen_retired = std::collections::HashSet::new();
        for r in &writer.retired {
            let state = reg
                .states
                .get(r.id.0 as usize)
                .map(|s| s.load(Ordering::Relaxed));
            assert_eq!(state, Some(2), "I-R3: a retired id must be state 2");
            assert!(
                seen_retired.insert(r.id),
                "I-R3: retired must contain no duplicate id"
            );
            assert!(
                !r.key.is_empty() && r.key.len() <= crate::MAX_IDENTITY_BYTES,
                "a retired entry must carry the validly bounded key it was interned under"
            );
            assert!(
                !writer.index.values().any(|live| *live == r.id),
                "an id must never be simultaneously live and retired"
            );
        }

        // I-R4: live_count() equals the number of state-1 slots. This is the
        // property the issue calls out as the one that matters most.
        assert_eq!(
            reg.live_count(),
            state1_count,
            "I-R4: live_count() must equal the number of state-1 slots"
        );

        state1_count
    }

    proptest::proptest! {
        #[test]
        fn registry_invariants_hold_under_arbitrary_operation_sequences(
            ops in proptest::collection::vec(op_strategy(), 0..=200)
        ) {
            let (reg, mut writer) =
                EndpointRegistry::install(4).expect("capacity 4 is valid and under the ceiling");
            let identities: Vec<EndpointIdentity> = (0..8u16).map(identity).collect();
            let mut last_gen = vec![0u32; 4];

            for op in ops {
                match op {
                    Op::Intern(i) => {
                        let _ = writer.intern(&identities[i]);
                    }
                    Op::Retire(id, dt, dgen) => {
                        writer.retire(EndpointId(id), dt, dgen);
                    }
                    Op::Recycle(dt, dgen) => {
                        let _ = writer.recycle(dt, dgen);
                    }
                }
                let state1_count = assert_invariants(reg, &writer, &mut last_gen);
                // Restated here, at the property test's own top level, not
                // only inside the helper: the property the issue calls out as
                // the one that matters most is that the number of state-1
                // slots always equals live_count().
                proptest::prop_assert_eq!(
                    state1_count,
                    reg.live_count(),
                    "I-R4: live_count() must equal the number of state-1 slots"
                );
            }
        }
    }
}
