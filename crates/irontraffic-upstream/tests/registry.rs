// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for `EndpointRegistry` / `EndpointRegistryWriter`:
//! interning, retirement, recycling, and capacity, driven entirely through the
//! crate's public API.
//!
//! Two of the tests named in the issue this file implements,
//! `intern_when_saturated_does_not_scan` (18a) and
//! `registry_invariants_hold_under_arbitrary_operation_sequences` (the property
//! test), are NOT here. Both need to inspect `EndpointRegistryWriter`'s private
//! fields (`scan_steps`, `index`, `keys`, `retired`), and an integration test
//! cannot: this file is compiled as a separate crate that links against
//! `irontraffic-upstream` built WITHOUT `--cfg test`, so even the
//! `#[cfg(test)]`-gated `scan_steps` field the issue specifies does not exist in
//! the library this file sees. Both tests live as unit tests in
//! `crates/irontraffic-upstream/src/registry.rs` instead, with the same names
//! and the same assertions the issue specifies. See the implementation report
//! for this issue.

use std::sync::atomic::Ordering;

use irontraffic_upstream::{
    EndpointAddr, EndpointId, EndpointIdentity, EndpointRegistry, MAX_CAPACITY, RECYCLE_BATCH,
    RECYCLE_GRACE_MS, RegistryError,
};

/// A distinct identity for each `port`, all on the same IPv4 host.
fn identity(port: u16) -> EndpointIdentity {
    EndpointIdentity {
        addr: EndpointAddr::Socket(std::net::SocketAddr::from(([10, 0, 0, 1], port))),
        hostname: None,
    }
}

/// A distinct identity for each `index` in `0..65_536`, spread across two IPv4
/// octets. Used where a test needs more identities than a `u16` port range
/// sensibly represents on its own (`recycle_is_batched` needs 8,192).
///
/// Built with shifts and masks, not `/` or `%`: `clippy::integer_division` is a
/// workspace-wide warning promoted to an error under `-D warnings`, and this
/// avoids it rather than relying on a per-line allow.
fn identity_from_index(index: u32) -> EndpointIdentity {
    let hi = u8::try_from((index >> 8) & 0xff).unwrap_or(0);
    let lo = u8::try_from(index & 0xff).unwrap_or(0);
    EndpointIdentity {
        addr: EndpointAddr::Socket(std::net::SocketAddr::from(([10, 0, hi, lo], 9000))),
        hostname: None,
    }
}

#[test]
fn intern_is_idempotent() {
    let (reg, mut writer) = EndpointRegistry::install(4).expect("capacity 4 is valid");
    let id1 = writer.intern(&identity(1)).expect("first intern succeeds");
    let id2 = writer.intern(&identity(1)).expect("second intern succeeds");
    let id3 = writer.intern(&identity(1)).expect("third intern succeeds");
    assert_eq!(id1, id2);
    assert_eq!(id2, id3);
    assert_eq!(reg.live_count(), 1);
}

#[test]
fn intern_assigns_dense_ascending_ids() {
    let (_reg, mut writer) = EndpointRegistry::install(8).expect("capacity 8 is valid");
    let ids: Vec<EndpointId> = (1..=5u16)
        .map(|port| {
            writer
                .intern(&identity(port))
                .expect("interning within capacity must succeed")
        })
        .collect();
    assert_eq!(
        ids,
        vec![
            EndpointId(0),
            EndpointId(1),
            EndpointId(2),
            EndpointId(3),
            EndpointId(4),
        ]
    );
}

#[test]
fn capacity_exhausted_is_an_error_not_a_panic() {
    let (_reg, mut writer) = EndpointRegistry::install(2).expect("capacity 2 is valid");
    writer.intern(&identity(1)).expect("first intern succeeds");
    writer.intern(&identity(2)).expect("second intern succeeds");
    let err = writer.intern(&identity(3));
    assert_eq!(err, Err(RegistryError::CapacityExhausted { capacity: 2 }));
}

#[test]
fn retire_then_recycle_requires_two_generations() {
    let (_reg, mut writer) = EndpointRegistry::install(4).expect("capacity 4 is valid");
    let id = writer.intern(&identity(1)).expect("intern succeeds");
    writer.retire(id, 1_000, 7);

    let freed_at_gen_8 = writer.recycle(1_000 + 10 * RECYCLE_GRACE_MS, 8);
    assert_eq!(
        freed_at_gen_8, 0,
        "generation 8 is only one past the retire generation"
    );

    let freed_at_gen_9 = writer.recycle(1_000 + 10 * RECYCLE_GRACE_MS, 9);
    assert_eq!(
        freed_at_gen_9, 1,
        "generation 9 is two past the retire generation"
    );
}

#[test]
fn retire_then_recycle_requires_the_grace_period() {
    let (_reg, mut writer) = EndpointRegistry::install(4).expect("capacity 4 is valid");
    let id = writer.intern(&identity(1)).expect("intern succeeds");
    writer.retire(id, 1_000, 7);

    let freed_before_grace = writer.recycle(1_000 + RECYCLE_GRACE_MS - 1, 99);
    assert_eq!(
        freed_before_grace, 0,
        "one millisecond short of the grace period"
    );

    let freed_at_grace = writer.recycle(1_000 + RECYCLE_GRACE_MS, 99);
    assert_eq!(freed_at_grace, 1, "exactly the grace period");
}

#[test]
fn recycled_slot_bumps_generation() {
    // Capacity 1, not 4: with room for more than one live endpoint, the scan
    // starts at `next_free` (which has already advanced past slot 0) and
    // finds the next NEVER-used slot before it ever revisits the one just
    // recycled, which is correct amortised-O(1) behaviour, not a bug. Capacity
    // 1 is the smallest registry where "the only free slot" is unambiguous:
    // there is only one slot to find.
    let (reg, mut writer) = EndpointRegistry::install(1).expect("capacity 1 is valid");
    let id_a = writer.intern(&identity(1)).expect("intern a succeeds");
    let generation_a = reg
        .slot_generation(id_a)
        .expect("a freshly interned id is in range");

    writer.retire(id_a, 0, 0);
    writer.recycle(RECYCLE_GRACE_MS, 2);

    let id_b = writer.intern(&identity(2)).expect("intern b succeeds");
    assert_eq!(id_b, id_a, "the only free slot must be reused");
    assert_eq!(
        reg.slot_generation(id_b),
        Some(generation_a.wrapping_add(1)),
        "reuse must bump the slot generation by exactly one"
    );
}

#[test]
fn recycled_slot_resets_stats() {
    // Capacity 1: see the comment in recycled_slot_bumps_generation above for
    // why a larger capacity would let intern land on a different,
    // never-yet-used slot instead of the one just recycled.
    let (reg, mut writer) = EndpointRegistry::install(1).expect("capacity 1 is valid");
    let id = writer.intern(&identity(1)).expect("intern succeeds");
    let generation = reg
        .slot_generation(id)
        .expect("a freshly interned id is in range");

    reg.stats(id)
        .expect("a freshly interned id is in range")
        .inflight
        .store(5, Ordering::Relaxed);
    reg.stats(id)
        .expect("a freshly interned id is in range")
        .cost
        .store(123, Ordering::Relaxed);

    writer.retire(id, 0, 0);
    writer.recycle(RECYCLE_GRACE_MS, 2);
    let id2 = writer.intern(&identity(2)).expect("re-intern succeeds");
    assert_eq!(id2, id, "the only free slot must be reused");

    let stats = reg.stats(id2).expect("a freshly interned id is in range");
    assert_eq!(stats.inflight.load(Ordering::Relaxed), 0);
    assert_eq!(stats.cost.load(Ordering::Relaxed), 0);
    assert_eq!(
        stats.generation.load(Ordering::Relaxed),
        generation.wrapping_add(1)
    );
}

#[test]
fn retire_of_unknown_id_is_noop() {
    let (reg, mut writer) = EndpointRegistry::install(4).expect("capacity 4 is valid");
    writer.intern(&identity(1)).expect("intern succeeds");
    let before = reg.live_count();

    writer.retire(EndpointId(9999), 0, 0);

    assert_eq!(
        reg.live_count(),
        before,
        "retiring an out-of-range id must be a no-op"
    );
}

#[test]
fn recycle_is_batched() {
    let (_reg, mut writer) = EndpointRegistry::install(8192).expect("capacity 8192 is valid");
    let ids: Vec<EndpointId> = (0..8192u32)
        .map(|i| {
            writer
                .intern(&identity_from_index(i))
                .expect("interning within capacity must succeed")
        })
        .collect();
    for id in ids {
        writer.retire(id, 0, 1);
    }

    let freed_first = writer.recycle(RECYCLE_GRACE_MS, 3);
    assert_eq!(
        freed_first, RECYCLE_BATCH,
        "one call must free at most RECYCLE_BATCH ids"
    );
    assert_eq!(writer.retired_len(), 8192 - RECYCLE_BATCH);

    let freed_second = writer.recycle(RECYCLE_GRACE_MS, 3);
    assert_eq!(
        freed_second,
        8192 - RECYCLE_BATCH,
        "the second call drains the remainder"
    );
    assert_eq!(writer.retired_len(), 0);
}

#[test]
fn retired_queue_is_bounded_by_capacity() {
    let (_reg, mut writer) = EndpointRegistry::install(4).expect("capacity 4 is valid");

    for cycle in 0..10u16 {
        let base_port = cycle * 4;
        let ids: Vec<EndpointId> = (0..4u16)
            .map(|slot| {
                writer
                    .intern(&identity(base_port + slot + 1))
                    .expect("interning within capacity must succeed")
            })
            .collect();
        assert!(
            writer.retired_len() <= 4,
            "retired_len must never exceed capacity"
        );

        let generation = u64::from(cycle);
        for &id in &ids {
            writer.retire(id, 0, generation);
            assert!(
                writer.retired_len() <= 4,
                "retired_len must never exceed capacity"
            );
        }
        // Retiring an already-retired id ten more times must be a no-op that
        // never grows the queue past capacity.
        for _ in 0..10 {
            for &id in &ids {
                writer.retire(id, 0, generation);
                assert!(
                    writer.retired_len() <= 4,
                    "retired_len must never exceed capacity"
                );
            }
        }

        let now_ms = RECYCLE_GRACE_MS * u32::from(cycle + 1);
        writer.recycle(now_ms, generation + 2);
        assert!(
            writer.retired_len() <= 4,
            "retired_len must never exceed capacity"
        );
    }
}

#[test]
fn grace_wrap_is_handled() {
    let (_reg, mut writer) = EndpointRegistry::install(4).expect("capacity 4 is valid");
    let id = writer.intern(&identity(1)).expect("intern succeeds");

    // 11 milliseconds before the CoarseMillis counter wraps to 0.
    let at_ms = u32::MAX - 10;
    let retire_generation = 1u64;
    writer.retire(id, at_ms, retire_generation);

    let snapshot_generation = retire_generation + 2;
    let freed_before = writer.recycle(RECYCLE_GRACE_MS - 12, snapshot_generation);
    assert_eq!(
        freed_before, 0,
        "elapsed is RECYCLE_GRACE_MS - 1, one short of the grace period"
    );

    let freed_at = writer.recycle(RECYCLE_GRACE_MS - 11, snapshot_generation);
    assert_eq!(freed_at, 1, "elapsed is exactly RECYCLE_GRACE_MS");
}

// The tests below were added after mutation testing (`cargo mutants -j 1`,
// scoped to this issue's four files) found that `capacity()`, `stats_slice()`,
// and `lookup()` were never exercised by any test, and that `install`'s
// boundary conditions (`capacity == 0`, `capacity == MAX_CAPACITY`, and
// `capacity == MAX_CAPACITY + 1`) were untested even though they are edge
// case 1 in the issue this file implements. Each of these closes a mutant
// that a prior run of this suite left standing.

#[test]
fn capacity_and_stats_slice_report_construction_values() {
    let (reg, _writer) = EndpointRegistry::install(4).expect("capacity 4 is valid");
    assert_eq!(reg.capacity(), 4);
    assert_eq!(reg.stats_slice().len(), 4);
}

#[test]
fn lookup_finds_interned_identity_and_not_absent_ones() {
    let (_reg, mut writer) = EndpointRegistry::install(4).expect("capacity 4 is valid");
    let present = identity(1);
    let absent = identity(2);

    let id = writer.intern(&present).expect("intern succeeds");

    assert_eq!(writer.lookup(&present), Some(id));
    assert_eq!(writer.lookup(&absent), None);
}

#[test]
fn install_rejects_zero_capacity() {
    let err = EndpointRegistry::install(0);
    assert_eq!(
        err.err(),
        Some(RegistryError::InvalidCapacity { capacity: 0 })
    );
}

#[test]
fn install_rejects_capacity_above_the_ceiling() {
    let err = EndpointRegistry::install(MAX_CAPACITY + 1);
    assert_eq!(
        err.err(),
        Some(RegistryError::InvalidCapacity {
            capacity: MAX_CAPACITY + 1
        })
    );
}

#[test]
fn install_accepts_capacity_exactly_at_the_ceiling() {
    // MAX_CAPACITY itself must succeed: install rejects ABOVE the ceiling,
    // never AT it. This allocates a real ~145 MiB arena (128 MiB of stats
    // plus a 1 MiB state byte per slot plus 16 MiB of writer key headers),
    // which is why this is the only test in this file that uses a capacity
    // anywhere near MAX_CAPACITY.
    let (reg, _writer) =
        EndpointRegistry::install(MAX_CAPACITY).expect("the ceiling itself is valid");
    assert_eq!(reg.capacity(), MAX_CAPACITY);
}
