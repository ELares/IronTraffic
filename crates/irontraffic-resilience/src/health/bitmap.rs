// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two-bit-per-endpoint health bitmap and the `ClusterHealth` publication record.
//!
//! The bitmap packs two bits per endpoint into `AtomicU32` words, so reading one
//! endpoint's health is one relaxed load, one shift, and one mask. The
//! `ClusterHealth` record adds a per-endpoint slow-start weight multiplier and a
//! membership generation.
//!
//! # `words` under `loom`
//!
//! `loom_tests`, at the bottom of this file, models the one property this
//! module cannot prove single threaded: that two writers setting different
//! endpoints in the same word never clobber each other. That model needs
//! loom's instrumented atomic in place of `core`'s for exactly the field the
//! model exercises, `HealthBitmap::words`, so `AtomicU32` is aliased below.
//! `weights` and `CLUSTER_ENDPOINTS_TRUNCATED` deliberately keep
//! `core::sync::atomic`'s own types unaliased: neither is part of the
//! concurrency property the model checks, so aliasing them would only make
//! loom explore interleavings that cannot affect anything this module
//! guarantees.

#![allow(
    unexpected_cfgs,
    reason = "cfg(loom) is a deliberate custom cfg for the loom concurrency-model tests, the same #[cfg(loom)] convention loom's own downstream users (tokio, crossbeam) rely on; registering it via a package-level [lints.rust] check-cfg table would conflict with this crate's required [lints] workspace = true, and this crate may not touch the workspace lints table to add it there instead"
)]

#[cfg(not(loom))]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};
#[cfg(loom)]
use loom::sync::atomic::AtomicU32;

use crate::ids::EndpointIdx;

/// Health state of one endpoint. Two bits. `Healthy` is 0 so that a zeroed bitmap
/// means "all healthy", which is the correct state for an unchecked cluster.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum EndpointHealth {
    /// Passing checks, not ejected, taking full traffic.
    Healthy = 0,
    /// Selectable but ranked after `Healthy`: ramping after an unejection, or flagged
    /// by a relative detector without being ejected.
    Degraded = 1,
    /// Failing checks or ejected by outlier detection. Not selectable except through
    /// the panic path or a half-open probe.
    Unhealthy = 2,
    /// Graceful removal in progress. Finish existing streams, accept no new ones.
    Draining = 3,
}

impl EndpointHealth {
    /// True for `Healthy` and `Degraded`: the endpoint may be selected normally.
    #[inline]
    #[must_use]
    pub fn is_selectable(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }

    /// The state for a two-bit value.
    ///
    /// TOTAL over every `u8`: the implementation matches on `bits & 0b11`, so 0 is
    /// `Healthy`, 1 is `Degraded`, 2 is `Unhealthy`, 3 is `Draining`, and any larger
    /// input is reduced modulo 4 rather than returning `Option` or panicking. Callers in
    /// this crate always pass a value already masked to two bits.
    #[inline]
    #[must_use]
    pub fn from_bits(bits: u8) -> EndpointHealth {
        match bits & 0b11 {
            1 => Self::Degraded,
            2 => Self::Unhealthy,
            3 => Self::Draining,
            // 0 is `Healthy`, and the mask makes every other value reduce modulo 4
            // back to 0 as well, so the wildcard is the total, non-panicking fallback.
            _ => Self::Healthy,
        }
    }
}

/// Ceiling on the endpoint count of one cluster: `1_048_576`, matching the timer
/// wheel's `DEFAULT_MAX_IDS`. A larger `len` is clamped to this by the constructors,
/// because the endpoint count comes from discovery data and an unclamped one is a
/// multi-gigabyte allocation from one control-plane message.
pub const MAX_ENDPOINTS: usize = 1 << 20;

/// Counter for clusters whose endpoint count was truncated to [`MAX_ENDPOINTS`].
/// Incremented once per construction that clamps the supplied length.
pub static CLUSTER_ENDPOINTS_TRUNCATED: AtomicU64 = AtomicU64::new(0);

const ENDPOINTS_PER_WORD: usize = 16;

/// Two bits per endpoint, packed 16 per `AtomicU32`.
///
/// Written ONLY by the control task; read on the request path. Reads are one relaxed
/// load, one shift, and one mask, and are flat in the endpoint count.
pub struct HealthBitmap {
    words: Box<[AtomicU32]>,
    len: usize,
}

impl HealthBitmap {
    /// A bitmap for `len` endpoints, all set to `initial`.
    ///
    /// `len` is clamped to [`MAX_ENDPOINTS`]; [`HealthBitmap::len`] reports the clamped
    /// value, and every index at or above it reads [`EndpointHealth::Unhealthy`], so
    /// truncated endpoints are never selected.
    #[must_use]
    pub fn new(len: usize, initial: EndpointHealth) -> Self {
        let raw_len = len;
        let len = raw_len.min(MAX_ENDPOINTS);
        if len < raw_len {
            let _ = CLUSTER_ENDPOINTS_TRUNCATED.fetch_add(1, Ordering::Relaxed);
        }

        let words = len.div_ceil(ENDPOINTS_PER_WORD);
        let fill = (initial as u32) * 0x5555_5555; // it-allow: unchecked-cast reason: EndpointHealth is #[repr(u8)] with discriminants 0..=3; u8 to u32 is a widening cast and cannot truncate
        let storage = (0..words)
            .map(|_| AtomicU32::new(fill))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            words: storage,
            len,
        }
    }

    /// Number of endpoints.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when the bitmap covers no endpoints.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Health of endpoint `idx`.
    ///
    /// Returns [`EndpointHealth::Unhealthy`] when `idx` is out of range, so a stale
    /// index from a snapshot race fails safe rather than selecting a missing endpoint.
    #[inline]
    #[must_use]
    pub fn get(&self, idx: EndpointIdx) -> EndpointHealth {
        let idx = usize::try_from(idx.0).unwrap_or(usize::MAX);
        if idx >= self.len {
            return EndpointHealth::Unhealthy;
        }
        self.state_at(idx)
    }

    /// Set the health of endpoint `idx`. Returns false when `idx` is out of range.
    ///
    /// CONTROL TASK ONLY. Two atomic read-modify-writes on one word, so a concurrent
    /// write to a different endpoint in the same word cannot clobber this one.
    #[must_use]
    pub fn set(&self, idx: EndpointIdx, h: EndpointHealth) -> bool {
        let idx = usize::try_from(idx.0).unwrap_or(usize::MAX);
        if idx >= self.len {
            return false;
        }
        let shift = (idx & 0xF) * 2;
        let word = idx >> 4;
        let Some(w) = self.words.get(word) else {
            return false;
        };
        w.fetch_and(!(0b11u32 << shift), Ordering::Relaxed);
        w.fetch_or((h as u32) << shift, Ordering::Relaxed); // it-allow: unchecked-cast reason: EndpointHealth is #[repr(u8)] with discriminants 0..=3; u8 to u32 is a widening cast and cannot truncate
        true
    }

    /// Number of endpoints in state `h`. O(len); control tick only.
    #[must_use]
    pub fn count_state(&self, h: EndpointHealth) -> usize {
        let mut n = 0usize;
        for i in 0..self.len {
            if self.state_at(i) == h {
                n += 1;
            }
        }
        n
    }

    /// Decode the two-bit state for a raw endpoint index.
    ///
    /// Callers must ensure `idx < self.len`. A missing word (unreachable today,
    /// since every caller guarantees `idx < self.len`) falls back to the bit
    /// pattern for `Unhealthy`, not `Healthy`: every other out of range path in
    /// this module fails safe, and a fail open fallback here would be a latent
    /// trap for a future caller that loses that guarantee.
    #[inline]
    fn state_at(&self, idx: usize) -> EndpointHealth {
        let unhealthy_fallback = (EndpointHealth::Unhealthy as u32) * 0x5555_5555; // it-allow: unchecked-cast reason: EndpointHealth is #[repr(u8)] with discriminants 0..=3; u8 to u32 is a widening cast and cannot truncate
        let w = self
            .words
            .get(idx >> 4)
            .map_or(unhealthy_fallback, |w| w.load(Ordering::Relaxed));
        let shift = (idx & 0xF) * 2;
        EndpointHealth::from_bits(((w >> shift) & 0b11) as u8) // it-allow: unchecked-cast reason: the mask `& 0b11` produces a value in 0..=3, which always fits in u8
    }
}

/// Everything the request path needs to know about one cluster's endpoint health.
///
/// Held in an `Arc` that hangs off the configuration snapshot. A membership change
/// builds a new `ClusterHealth` and swaps the `Arc`; a health flip is a relaxed store
/// inside the existing one, so it never invalidates the load balancer's structures.
pub struct ClusterHealth {
    /// Per-endpoint health, indexed by `EndpointIdx`.
    pub bitmap: HealthBitmap,
    /// Per-endpoint weight multiplier in basis points, `0..=10_000`.
    pub weights: Box<[AtomicU16]>,
    /// Membership generation. Bumped when the endpoint set changes, never when a health bit flips.
    pub generation: u64,
}

impl ClusterHealth {
    /// A record for `len` endpoints, all `Healthy` with weight multiplier `10_000`.
    ///
    /// `len` is clamped to [`MAX_ENDPOINTS`], exactly as in [`HealthBitmap::new`].
    #[must_use]
    pub fn new(len: usize, generation: u64) -> Self {
        Self::with_initial(len, generation, EndpointHealth::Healthy)
    }

    /// A record for `len` endpoints all set to `initial`, with weight multiplier
    /// `10_000`. Used when rebuilding after a membership change.
    ///
    /// This constructor does NOT carry anything forward by itself: every weight is
    /// `10_000` and every state is `initial`. The rebuilder MUST re-apply, per endpoint
    /// identity (socket address, not [`EndpointIdx`], which is not stable across
    /// snapshots), the previous health state, the previous slow-start weight, and the
    /// previous ejection deadline, before publishing the new `Arc`. Skipping that makes
    /// membership churn a laundering mechanism: an ejected endpoint returns to
    /// `Healthy` at full weight the instant anything changes the endpoint set, so a
    /// backend that can flap its own registration (a crash-looping pod re-registering,
    /// or a workload that can write `EndpointSlices`) never stays ejected and never rides
    /// the unejection ramp. The rebuild path in `outlier-ejection-and-safety-valves` (#98)
    /// owns that carry-forward and its test 12 asserts it.
    #[must_use]
    pub fn with_initial(len: usize, generation: u64, initial: EndpointHealth) -> Self {
        let bitmap = HealthBitmap::new(len, initial);
        let weights = (0..bitmap.len)
            .map(|_| AtomicU16::new(10_000))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        debug_assert!(
            weights.len() == bitmap.len(),
            "invariant 3: weights and bitmap must cover the same endpoint count"
        );
        Self {
            bitmap,
            weights,
            generation,
        }
    }

    /// Number of endpoints.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.bitmap.len()
    }

    /// True when the cluster has no endpoints.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bitmap.is_empty()
    }

    /// Weight multiplier of endpoint `idx` in basis points. Returns 0 when `idx` is
    /// out of range, so a stale index contributes no weight.
    #[inline]
    #[must_use]
    pub fn weight_bp(&self, idx: EndpointIdx) -> u16 {
        let idx = usize::try_from(idx.0).unwrap_or(usize::MAX);
        if idx >= self.weights.len() {
            return 0;
        }
        self.weights
            .get(idx)
            .map_or(0, |w| w.load(Ordering::Relaxed))
    }

    /// Publish a weight multiplier, clamped to `0..=10_000`. Returns false when `idx`
    /// is out of range. CONTROL TASK ONLY.
    #[must_use]
    pub fn set_weight_bp(&self, idx: EndpointIdx, bp: u16) -> bool {
        let idx = usize::try_from(idx.0).unwrap_or(usize::MAX);
        if idx >= self.weights.len() {
            return false;
        }
        let Some(w) = self.weights.get(idx) else {
            return false;
        };
        AtomicU16::store(w, bp.min(10_000), Ordering::Relaxed);
        true
    }

    /// Fraction of endpoints that are selectable (`Healthy` or `Degraded`), in basis
    /// points. Returns `10_000` for an empty cluster. O(len); control tick only.
    ///
    /// This is the input to the 50% panic threshold.
    #[must_use]
    #[allow(
        clippy::integer_division,
        reason = "basis-points fraction of a finite cluster; exact truncation is required and bounded by construction"
    )]
    pub fn healthy_fraction_bp(&self) -> u16 {
        let len = self.bitmap.len();
        if len == 0 {
            return 10_000;
        }
        let mut n = 0usize;
        for i in 0..len {
            if self.bitmap.state_at(i).is_selectable() {
                n += 1;
            }
        }
        let bp = (n as u64 * 10_000) / len as u64;
        debug_assert!(bp <= 10_000);
        u16::try_from(bp).unwrap_or(10_000)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn all_states() -> [EndpointHealth; 4] {
        [
            EndpointHealth::Healthy,
            EndpointHealth::Degraded,
            EndpointHealth::Unhealthy,
            EndpointHealth::Draining,
        ]
    }

    fn endpoint_health_strategy() -> impl Strategy<Value = EndpointHealth> {
        prop_oneof![
            Just(EndpointHealth::Healthy),
            Just(EndpointHealth::Degraded),
            Just(EndpointHealth::Unhealthy),
            Just(EndpointHealth::Draining),
        ]
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "test indices are bounded by MAX_ENDPOINTS, which is far below u32::MAX"
    )]
    fn mkidx(i: usize) -> EndpointIdx {
        EndpointIdx(i as u32)
    }

    #[test]
    fn new_all_healthy() {
        let b = HealthBitmap::new(100, EndpointHealth::Healthy);
        assert!(!b.is_empty());
        for i in 0..100 {
            assert_eq!(b.get(mkidx(i)), EndpointHealth::Healthy);
        }
        assert_eq!(b.count_state(EndpointHealth::Healthy), 100);
        assert_eq!(b.count_state(EndpointHealth::Degraded), 0);
        assert_eq!(b.count_state(EndpointHealth::Unhealthy), 0);
        assert_eq!(b.count_state(EndpointHealth::Draining), 0);
    }

    #[test]
    fn new_all_unhealthy() {
        let b = HealthBitmap::new(100, EndpointHealth::Unhealthy);
        for i in 0..100 {
            assert_eq!(b.get(mkidx(i)), EndpointHealth::Unhealthy);
        }
        assert_eq!(b.count_state(EndpointHealth::Unhealthy), 100);
        assert_eq!(b.count_state(EndpointHealth::Healthy), 0);
    }

    #[test]
    fn set_get_roundtrip_all_states() {
        let b = HealthBitmap::new(40, EndpointHealth::Healthy);
        for i in 0..40 {
            for state in all_states() {
                assert!(b.set(mkidx(i), state));
                assert_eq!(b.get(mkidx(i)), state);
            }
        }
    }

    #[test]
    fn set_does_not_disturb_neighbours() {
        let b = HealthBitmap::new(32, EndpointHealth::Healthy);
        for state in [
            EndpointHealth::Healthy,
            EndpointHealth::Degraded,
            EndpointHealth::Unhealthy,
            EndpointHealth::Draining,
        ] {
            for idx in [0, 5, 15, 16, 31] {
                assert!(b.set(mkidx(idx), state));
                for other in 0..32 {
                    let expected = if other == idx {
                        state
                    } else {
                        EndpointHealth::Healthy
                    };
                    assert_eq!(b.get(mkidx(other)), expected);
                }
                assert!(b.set(mkidx(idx), EndpointHealth::Healthy));
            }
        }
    }

    #[test]
    fn four_states_in_one_word() {
        let b = HealthBitmap::new(16, EndpointHealth::Healthy);
        for (i, state) in all_states().into_iter().enumerate() {
            assert!(b.set(mkidx(i), state));
        }
        for i in 0..4 {
            assert_eq!(b.get(mkidx(i)), all_states()[i]);
        }
        for i in 4..16 {
            assert_eq!(b.get(mkidx(i)), EndpointHealth::Healthy);
        }
    }

    #[test]
    fn len_zero() {
        let b = HealthBitmap::new(0, EndpointHealth::Healthy);
        assert!(b.is_empty());
        assert_eq!(b.get(EndpointIdx(0)), EndpointHealth::Unhealthy);
        assert_eq!(b.count_state(EndpointHealth::Healthy), 0);
        assert!(!b.set(EndpointIdx(0), EndpointHealth::Draining));
    }

    #[test]
    fn len_one_partial_word_masking() {
        let b = HealthBitmap::new(1, EndpointHealth::Healthy);
        assert_eq!(b.count_state(EndpointHealth::Healthy), 1);
    }

    #[test]
    fn len_seventeen_partial_word_masking() {
        let b = HealthBitmap::new(17, EndpointHealth::Healthy);
        assert_eq!(b.count_state(EndpointHealth::Healthy), 17);
        assert!(b.set(EndpointIdx(16), EndpointHealth::Unhealthy));
        assert_eq!(b.count_state(EndpointHealth::Healthy), 16);
        assert_eq!(b.count_state(EndpointHealth::Unhealthy), 1);
    }

    #[test]
    fn out_of_range_reads_unhealthy() {
        let b = HealthBitmap::new(10, EndpointHealth::Healthy);
        assert_eq!(b.get(EndpointIdx(10)), EndpointHealth::Unhealthy);
        assert_eq!(b.get(EndpointIdx(11)), EndpointHealth::Unhealthy);
        assert_eq!(b.get(EndpointIdx(u32::MAX)), EndpointHealth::Unhealthy);
    }

    #[test]
    fn out_of_range_set_returns_false() {
        let b = HealthBitmap::new(10, EndpointHealth::Healthy);
        assert!(!b.set(EndpointIdx(10), EndpointHealth::Healthy));
    }

    /// `state_at`'s documented contract is `idx < self.len`; every caller in this
    /// crate upholds it, which makes the missing-word branch of its fallback
    /// unreachable through the public API. This test calls the private helper
    /// directly, deliberately violating that contract, to prove the fallback
    /// itself fails safe (decodes to `Unhealthy`) rather than fails open
    /// (decodes to `Healthy`), matching the rule `get` enforces for every other
    /// out of range path in this module.
    #[test]
    fn state_at_missing_word_fails_unhealthy() {
        let b = HealthBitmap::new(1, EndpointHealth::Healthy);
        assert_eq!(b.state_at(1_000), EndpointHealth::Unhealthy);
    }

    #[test]
    fn is_selectable_matrix() {
        assert!(EndpointHealth::Healthy.is_selectable());
        assert!(EndpointHealth::Degraded.is_selectable());
        assert!(!EndpointHealth::Unhealthy.is_selectable());
        assert!(!EndpointHealth::Draining.is_selectable());
    }

    #[test]
    fn from_bits_total() {
        let states = all_states();
        for i in 0..4 {
            assert_eq!(EndpointHealth::from_bits(i), states[i as usize]);
        }
        assert_eq!(EndpointHealth::from_bits(4), EndpointHealth::Healthy);
        assert_eq!(EndpointHealth::from_bits(7), EndpointHealth::Draining);
        assert_eq!(EndpointHealth::from_bits(255), EndpointHealth::Draining);
    }

    #[test]
    fn cluster_health_new_defaults() {
        let ch = ClusterHealth::new(8, 3);
        assert!(!ch.is_empty());
        assert_eq!(ch.len(), 8);
        assert_eq!(ch.generation, 3);
        for i in 0..8 {
            assert_eq!(ch.weight_bp(mkidx(i)), 10_000);
            assert_eq!(ch.bitmap.get(mkidx(i)), EndpointHealth::Healthy);
        }
    }

    #[test]
    fn weight_clamped_and_zero() {
        let ch = ClusterHealth::new(1, 0);
        assert!(ch.set_weight_bp(EndpointIdx(0), 65_535));
        assert_eq!(ch.weight_bp(EndpointIdx(0)), 10_000);
        assert!(ch.set_weight_bp(EndpointIdx(0), 0));
        assert_eq!(ch.weight_bp(EndpointIdx(0)), 0);
    }

    #[test]
    fn weight_out_of_range() {
        let ch = ClusterHealth::new(8, 0);
        assert!(!ch.set_weight_bp(EndpointIdx(8), 5_000));
        assert_eq!(ch.weight_bp(EndpointIdx(8)), 0);
    }

    #[test]
    fn healthy_fraction_cases() {
        let ch = ClusterHealth::new(4, 0);
        assert_eq!(ch.healthy_fraction_bp(), 10_000);

        assert!(ch.bitmap.set(EndpointIdx(0), EndpointHealth::Unhealthy));
        assert!(ch.bitmap.set(EndpointIdx(1), EndpointHealth::Unhealthy));
        assert_eq!(ch.healthy_fraction_bp(), 5_000);

        for i in 0..4 {
            assert!(ch.bitmap.set(mkidx(i), EndpointHealth::Unhealthy));
        }
        assert_eq!(ch.healthy_fraction_bp(), 0);

        let ch = ClusterHealth::new(4, 0);
        assert!(ch.bitmap.set(EndpointIdx(0), EndpointHealth::Degraded));
        for i in 1..4 {
            assert!(ch.bitmap.set(mkidx(i), EndpointHealth::Unhealthy));
        }
        assert_eq!(ch.healthy_fraction_bp(), 2_500);

        assert_eq!(ClusterHealth::new(0, 0).healthy_fraction_bp(), 10_000);
        assert!(ClusterHealth::new(0, 0).is_empty());

        let ch = ClusterHealth::new(3, 0);
        assert_eq!(ch.healthy_fraction_bp(), 10_000);
        assert!(ch.bitmap.set(EndpointIdx(0), EndpointHealth::Unhealthy));
        assert_eq!(ch.healthy_fraction_bp(), 6_666);
    }

    #[test]
    fn set_transient_is_fail_open() {
        let b = HealthBitmap::new(16, EndpointHealth::Healthy);
        for i in 0..16 {
            assert!(b.set(mkidx(i), EndpointHealth::Draining));
        }
        for idx in 0..16 {
            assert!(b.set(mkidx(idx), EndpointHealth::Healthy));
            assert!(b.set(mkidx(idx), EndpointHealth::Draining));
            for other in 0..16 {
                assert_eq!(b.get(mkidx(other)), EndpointHealth::Draining);
            }
        }
    }

    /// #91's Do NOT list forbids implementing `set` as a load, a full-word
    /// recompute, and a store: it requires `fetch_and` then `fetch_or` so that a
    /// concurrent write to a DIFFERENT endpoint in the SAME word survives. A
    /// single threaded test cannot observe the difference, because a single
    /// threaded load-then-store is bit-identical to two RMWs. This test uses two
    /// real OS threads, each hammering its own endpoint in word 0 (index 3 and
    /// index 4, sixteen endpoints per word) for many iterations with no
    /// synchronization between them, so the two writers actually race.
    ///
    /// Each thread cycles through a fixed sequence of states and remembers the
    /// last one it wrote. Nothing but that thread ever writes its own index, so
    /// if the final read does not match the last value that thread wrote, the
    /// only possible explanation is that the OTHER thread's concurrent write to
    /// the same word clobbered it, which is exactly the bug a load, recompute,
    /// store implementation has and two RMWs do not. Running many independent
    /// rounds, each with a fresh bitmap and thousands of iterations per thread,
    /// keeps this from being a one-shot coin flip: the forbidden implementation
    /// fails it on close to every run, the required one never does.
    #[test]
    fn concurrent_set_on_different_endpoints_in_one_word_survives() {
        use std::sync::Arc;
        use std::thread;

        const ROUNDS: usize = 50;
        const ITERS_PER_ROUND: usize = 4_000;

        let states = [
            EndpointHealth::Degraded,
            EndpointHealth::Unhealthy,
            EndpointHealth::Draining,
            EndpointHealth::Healthy,
        ];

        for _round in 0..ROUNDS {
            let b = Arc::new(HealthBitmap::new(16, EndpointHealth::Healthy));

            let b3 = Arc::clone(&b);
            let t3 = thread::spawn(move || {
                let mut last = EndpointHealth::Healthy;
                for i in 0..ITERS_PER_ROUND {
                    let s = states[i % states.len()];
                    assert!(b3.set(EndpointIdx(3), s));
                    last = s;
                }
                last
            });

            let b4 = Arc::clone(&b);
            let t4 = thread::spawn(move || {
                let mut last = EndpointHealth::Healthy;
                for i in 0..ITERS_PER_ROUND {
                    let s = states[(i + 2) % states.len()];
                    assert!(b4.set(EndpointIdx(4), s));
                    last = s;
                }
                last
            });

            let last3 = t3.join().expect("writer thread for index 3 must not panic");
            let last4 = t4.join().expect("writer thread for index 4 must not panic");

            assert_eq!(
                b.get(EndpointIdx(3)),
                last3,
                "index 3's final state must be exactly what its own writer thread \
                 last set, never a value clobbered by index 4's concurrent writer \
                 in the same word"
            );
            assert_eq!(
                b.get(EndpointIdx(4)),
                last4,
                "index 4's final state must be exactly what its own writer thread \
                 last set, never a value clobbered by index 3's concurrent writer \
                 in the same word"
            );
        }
    }

    /// `CLUSTER_ENDPOINTS_TRUNCATED` is a process-global static, and every test
    /// below that constructs a bitmap above `MAX_ENDPOINTS` increments it. The
    /// default test harness runs tests concurrently, so a delta computed from
    /// two loads of the counter (snapshot, construct, snapshot) can still be
    /// corrupted by an unrelated test's increment landing inside that window;
    /// a plain delta is not enough on its own. Every test that touches the
    /// counter takes this lock first, which serializes exactly the handful of
    /// tests that share the static and nothing else, so the delta check below
    /// is deterministic rather than merely unlikely to flake.
    static TRUNCATION_COUNTER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn len_clamped_to_max_endpoints() {
        let _guard = TRUNCATION_COUNTER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let b = HealthBitmap::new(MAX_ENDPOINTS + 1_000, EndpointHealth::Healthy);
        assert_eq!(b.len(), MAX_ENDPOINTS);
        assert_eq!(b.get(mkidx(MAX_ENDPOINTS)), EndpointHealth::Unhealthy);
        let ch = ClusterHealth::new(MAX_ENDPOINTS + 1_000, 0);
        assert_eq!(ch.weights.len(), MAX_ENDPOINTS);
    }

    #[test]
    fn len_usize_max_does_not_overflow() {
        let _guard = TRUNCATION_COUNTER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let b = HealthBitmap::new(usize::MAX, EndpointHealth::Healthy);
        assert_eq!(b.len(), MAX_ENDPOINTS);
    }

    /// `cluster_endpoints_truncated` is process global and other tests in this
    /// binary construct clamped bitmaps concurrently, so this asserts a DELTA
    /// against a snapshot rather than an absolute value; an absolute assertion
    /// would be flaky under parallel test execution. The shared lock above
    /// keeps that delta from being corrupted by those other tests' own
    /// increments landing inside this test's snapshot window.
    ///
    /// The second half, the non clamping construction, is load bearing: it is
    /// what catches a mutant that fires the counter on every construction
    /// rather than only on a construction that actually truncates.
    #[test]
    fn truncation_counter_fires_exactly_on_clamp() {
        let _guard = TRUNCATION_COUNTER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let before = CLUSTER_ENDPOINTS_TRUNCATED.load(Ordering::Relaxed);
        let b = HealthBitmap::new(MAX_ENDPOINTS + 1, EndpointHealth::Healthy);
        assert_eq!(b.len(), MAX_ENDPOINTS);
        let after_clamp = CLUSTER_ENDPOINTS_TRUNCATED.load(Ordering::Relaxed);
        assert_eq!(
            after_clamp - before,
            1,
            "constructing above MAX_ENDPOINTS must advance the counter by exactly one"
        );

        let b = HealthBitmap::new(MAX_ENDPOINTS, EndpointHealth::Healthy);
        assert_eq!(b.len(), MAX_ENDPOINTS);
        let after_exact = CLUSTER_ENDPOINTS_TRUNCATED.load(Ordering::Relaxed);
        assert_eq!(
            after_exact, after_clamp,
            "constructing at exactly MAX_ENDPOINTS must not advance the counter"
        );
    }

    proptest! {
        #[test]
        fn prop_set_get_roundtrip(len in 0..=300usize, ops in prop::collection::vec((0..=500u32, endpoint_health_strategy()), 0..=200)) {
            let b = HealthBitmap::new(len, EndpointHealth::Healthy);
            let mut model = vec![EndpointHealth::Healthy; len];
            for (idx, state) in ops {
                if let Some(i) = usize::try_from(idx).ok().filter(|i| *i < len) {
                    model[i] = state;
                    let _ = b.set(EndpointIdx(idx), state);
                }
            }
            for (i, expected) in model.iter().enumerate() {
                assert_eq!(b.get(mkidx(i)), *expected);
            }
            for i in len..len.saturating_add(8) {
                assert_eq!(b.get(mkidx(i)), EndpointHealth::Unhealthy);
            }
        }

        #[test]
        fn prop_count_state_matches_model(len in 0..=300usize, ops in prop::collection::vec((0..=500u32, endpoint_health_strategy()), 0..=200)) {
            let b = HealthBitmap::new(len, EndpointHealth::Healthy);
            let mut model = vec![EndpointHealth::Healthy; len];
            for (idx, state) in ops {
                if let Some(i) = usize::try_from(idx).ok().filter(|i| *i < len) {
                    model[i] = state;
                    let _ = b.set(EndpointIdx(idx), state);
                }
            }
            for state in all_states() {
                let expected = model.iter().filter(|&&s| s == state).count();
                assert_eq!(b.count_state(state), expected);
            }
        }

        #[test]
        fn prop_weights_roundtrip_and_clamp(len in 1..=300usize, ops in prop::collection::vec((0..=500u32, 0..=u16::MAX), 0..=200)) {
            let ch = ClusterHealth::new(len, 0);
            let mut model = vec![None; len];
            for (idx, bp) in ops {
                if let Some(i) = usize::try_from(idx).ok().filter(|i| *i < len) {
                    model[i] = Some(bp.min(10_000));
                    let _ = ch.set_weight_bp(EndpointIdx(idx), bp);
                }
            }
            for (i, expected) in model.iter().enumerate() {
                assert_eq!(ch.weight_bp(mkidx(i)), expected.unwrap_or(10_000));
            }
        }
    }
}

/// Exhaustive loom model of the property
/// `concurrent_set_on_different_endpoints_in_one_word_survives` above checks
/// by sampling: that two writers setting DIFFERENT endpoints in the SAME word
/// never clobber each other. `loom::model` explores every legal interleaving
/// of the two threads' atomic operations rather than a bounded number of real
/// scheduler outcomes, so a defect here is a proof of absence, not a sample
/// that happened not to catch it.
///
/// Not part of the default test run: nothing in `scripts/gate-fast.sh` builds
/// with `--cfg loom`, so this module is inert under a normal `cargo test`.
/// Run it directly with `RUSTFLAGS="--cfg loom" cargo test -p
/// irontraffic-resilience --lib health::bitmap::loom_tests::`. Do not add
/// `--release`: `health::wheel`'s own debug-only structural check is
/// `#[cfg(debug_assertions)]` and a release build drops it, which fails the
/// crate's unrelated wheel tests before this model ever runs.
#[cfg(loom)]
mod loom_tests {
    use loom::sync::Arc;
    use loom::thread;

    use super::{EndpointHealth, EndpointIdx, HealthBitmap};

    #[test]
    fn loom_two_writers_in_one_word_both_land() {
        loom::model(|| {
            let b = Arc::new(HealthBitmap::new(16, EndpointHealth::Healthy));

            let b3 = Arc::clone(&b);
            let t3 = thread::spawn(move || {
                assert!(b3.set(EndpointIdx(3), EndpointHealth::Unhealthy));
            });

            let b4 = Arc::clone(&b);
            let t4 = thread::spawn(move || {
                assert!(b4.set(EndpointIdx(4), EndpointHealth::Draining));
            });

            assert!(
                t3.join().is_ok(),
                "writer thread for index 3 must not panic"
            );
            assert!(
                t4.join().is_ok(),
                "writer thread for index 4 must not panic"
            );

            assert_eq!(b.get(EndpointIdx(3)), EndpointHealth::Unhealthy);
            assert_eq!(b.get(EndpointIdx(4)), EndpointHealth::Draining);
        });
    }
}
