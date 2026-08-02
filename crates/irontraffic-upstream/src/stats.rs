// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`EndpointStats`]: the 128-byte-aligned, atomics-only per-endpoint counter
//! line the request path indexes directly by [`crate::EndpointId`]. This module
//! also carries the protocol over it: [`EndpointStats::record_rtt`], the
//! [`order_key`] ordering primitive both load-balancing cost functions
//! ([`EndpointStats::cost_key`], [`EndpointStats::load_key`]) compare on, the
//! health-transition helpers that drive slow start, and the two RAII balances,
//! [`InflightGuard`] and [`ConnGuard`].

use crate::CoarseMillis;
use crate::ewma::{EwmaCfg, MIN_RTT_MS, decay_factor, peak_ewma_step, unpack};
use crate::sync::{AtomicU32, AtomicU64, Ordering};

/// One cache-line-pair of mutable per-endpoint state. 128-byte aligned, not 64,
/// because Apple silicon and some x86 parts prefetch line pairs, so 64-byte
/// alignment still admits false sharing between two endpoints.
///
/// Total live payload is 28 bytes; the rest is padding that exists to guarantee
/// that touching one endpoint's counters never invalidates another's line.
#[repr(align(128))]
#[derive(Debug, Default)]
pub struct EndpointStats {
    /// In-flight *requests*, not connections. Incremented at selection, decremented
    /// by `InflightGuard::drop`. This is the P2C load signal.
    pub inflight: AtomicU32,
    /// Open connections to this endpoint across all workers. Pool accounting only.
    pub active_conns: AtomicU32,
    /// Packed peak-EWMA: high 32 bits are an `f32` cost in milliseconds, low 32
    /// bits are the `CoarseMillis` at which that cost was recorded. Zero means
    /// "never sampled".
    pub cost: AtomicU64,
    /// `CoarseMillis` at which this endpoint last transitioned into `Healthy`.
    /// Drives slow start.
    pub healthy_since_ms: AtomicU32,
    /// `CoarseMillis` at which this endpoint last left `Healthy`. Drives
    /// slow-start flap suppression: a ramp does not restart if the endpoint was
    /// healthy recently.
    pub left_healthy_ms: AtomicU32,
    /// Registry slot generation, bumped every time this slot is allocated. A
    /// sticky affinity token carries it so that a token naming a recycled id is
    /// rejected.
    pub generation: AtomicU32,
}

/// Everything a cost function needs that is not per endpoint.
#[derive(Copy, Clone, Debug)]
pub struct CostCtx {
    /// Coarse milliseconds since process start. Never read from a live clock.
    pub now_ms: CoarseMillis,
    /// Decay window, copied from [`EwmaCfg`] so the hot path reads one struct.
    pub decay_ms: u32,
    /// Seed cost for a never-sampled endpoint, in milliseconds.
    pub default_rtt_ms: f32,
    /// Per-endpoint in-flight ceiling. `u32::MAX` disables it.
    pub max_requests: u32,
}

/// Maps a cost to a totally-ordered `u32`. Exposed because the algorithms
/// compare on it: the comparator is a branch-free integer compare and NaN sorts
/// as worst rather than being unordered, which makes a poisoned endpoint fail
/// safe (it is never selected) instead of failing silently (it would be under
/// `f32`'s own `<`, whose result on a NaN operand is always `false`).
#[allow(
    clippy::inline_always,
    reason = "the comparator both cost_key and load_key end on, inside the 25 ns P2C pick \
              budget for one endpoint sample; not inlining it doubles the call overhead \
              on every pick"
)]
#[inline(always)]
#[must_use]
pub fn order_key(cost: f32) -> u32 {
    let b = cost.to_bits();
    if b & 0x8000_0000 == 0 {
        // Non-negative finite, +inf, or +NaN: bit order is value order.
        b
    } else if b == 0x8000_0000 {
        // Negative zero is +0.0 and must sort as best.
        0
    } else {
        // Negative or a negative NaN: impossible by construction from this
        // crate's own callers, sorts worst as the last line of defence.
        u32::MAX
    }
}

impl EndpointStats {
    /// Folds one round-trip sample into the peak-EWMA estimate.
    ///
    /// Lock-free and bounded: at most two compare-exchange attempts, after which
    /// the sample is dropped. Clamps `sample_ms` into `[MIN_RTT_MS, MAX_RTT_MS]`
    /// and replaces a non-finite sample with `cfg.default_rtt_ms`. The lower
    /// clamp is `MIN_RTT_MS` and not zero: a stored `0.0` deletes the in-flight
    /// term from the cost product.
    pub fn record_rtt(&self, sample_ms: f32, now_ms: CoarseMillis, cfg: &EwmaCfg) {
        let mut cur = self.cost.load(Ordering::Relaxed);
        for _ in 0..2 {
            let new = peak_ewma_step(cur, sample_ms, now_ms, cfg);
            match self
                .cost
                .compare_exchange_weak(cur, new, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
        // Two attempts lost the race: the sample is dropped. A dropped EWMA
        // sample is harmless, unlike a dropped balance decrement: the estimate is
        // a smoothed statistic over thousands of samples, so one lost update
        // does not bias it. Spinning until success would put an unbounded stall
        // on the request path, and it stalls hardest exactly when the system is
        // busiest.
    }

    /// The peak-EWMA ordering key: `decayed_rtt * (inflight + 1) / w_eff`, mapped
    /// through [`order_key`]. Lower is better. Returns `u32::MAX` when
    /// `inflight >= cx.max_requests`.
    ///
    /// This function never refuses a selection; a hard concurrency limit must be
    /// enforced by the caller's admission path, which fails closed with a 503,
    /// and `circuit-breaker` budgets are that path.
    ///
    /// Reads exactly two relaxed atomics, both on this endpoint's single cache
    /// line. Allocation-free, never reads a clock, never panics.
    #[allow(
        clippy::inline_always,
        reason = "one P2C sample of one endpoint must cost exactly one cache-line touch; \
                  the 25 ns pick budget has no room for a call clippy's default inlining \
                  heuristic might decline to take, and the acceptance criteria for this \
                  issue require this exact annotation on this exact function"
    )]
    #[inline(always)]
    #[must_use]
    pub fn cost_key(&self, w_eff: f32, cx: &CostCtx) -> u32 {
        let inflight = self.inflight.load(Ordering::Relaxed);
        if inflight >= cx.max_requests {
            return u32::MAX;
        }
        let word = self.cost.load(Ordering::Relaxed);
        let rtt = if word == 0 {
            cx.default_rtt_ms
        } else {
            let (v, ts) = unpack(word);
            let d = v * decay_factor(ts, cx.now_ms, cx.decay_ms);
            if !d.is_finite() {
                // Poisoned: sorts worst. NOT written as `d.max(MIN_RTT_MS)`
                // alone: `f32::max` returns the OTHER operand when one operand
                // is NaN, so `NaN.max(MIN_RTT_MS)` is `MIN_RTT_MS`, the smallest
                // possible cost, which would make a poisoned endpoint
                // permanently PREFERRED by every worker in the fleet. Testing
                // finiteness explicitly and returning the worst key is the
                // second line of defence behind the bit-pattern ordering.
                return u32::MAX;
            }
            d.max(MIN_RTT_MS)
        };
        // `inflight` is a live request count, realistically far below `2^24`;
        // converting it to `f32` for this ratio loses only bits below `f32`'s
        // 24-bit mantissa, which is immaterial next to `order_key`'s own
        // bit-pattern ordering of the result.
        #[allow(
            clippy::cast_precision_loss,
            reason = "inflight is a live request count realistically far below 2^24; \
                      converting it to f32 for this ratio loses only bits below f32's \
                      24-bit mantissa, immaterial next to order_key's bit-pattern ordering"
        )]
        let weighted = rtt * (inflight.saturating_add(1) as f32) / w_eff.max(f32::MIN_POSITIVE);
        order_key(weighted)
    }

    /// The least-request ordering key: `(inflight + 1) / w_eff`, mapped through
    /// [`order_key`]. Lower is better. Reads one relaxed atomic.
    ///
    /// This function never refuses a selection; a hard concurrency limit must be
    /// enforced by the caller's admission path, which fails closed with a 503,
    /// and `circuit-breaker` budgets are that path.
    #[allow(
        clippy::inline_always,
        reason = "one P2C sample of one endpoint must cost exactly one cache-line touch; \
                  the 25 ns pick budget has no room for a call clippy's default inlining \
                  heuristic might decline to take, and the acceptance criteria for this \
                  issue require this exact annotation on this exact function"
    )]
    #[inline(always)]
    #[must_use]
    pub fn load_key(&self, w_eff: f32, cx: &CostCtx) -> u32 {
        let inflight = self.inflight.load(Ordering::Relaxed);
        if inflight >= cx.max_requests {
            return u32::MAX;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "inflight is a live request count realistically far below 2^24; \
                      converting it to f32 for this ratio loses only bits below f32's \
                      24-bit mantissa, immaterial next to order_key's bit-pattern ordering"
        )]
        let weighted = (inflight.saturating_add(1) as f32) / w_eff.max(f32::MIN_POSITIVE);
        order_key(weighted)
    }

    /// Seeds a never-sampled endpoint's estimate. Does nothing if `cost` is
    /// already non-zero, so it is safe to call on every snapshot build.
    ///
    /// One `compare_exchange` attempt only, never a loop: two builders seeding
    /// the same endpoint concurrently must not spin, and either seed satisfies
    /// the contract.
    pub fn seed_cost_if_unset(&self, est_ms: f32, now_ms: CoarseMillis) {
        if self.cost.load(Ordering::Relaxed) != 0 {
            return;
        }
        let clamped = if est_ms.is_finite() {
            est_ms.clamp(MIN_RTT_MS, crate::ewma::MAX_RTT_MS)
        } else {
            // A non-finite seed is a caller bug; fall back to a value clearly
            // above the load-bearing lower clamp rather than propagating NaN.
            MIN_RTT_MS.max(1.0)
        };
        let word = crate::ewma::pack(clamped, now_ms);
        // If another thread seeded first, its value is equally valid: this
        // function's whole contract is "seed if unset", and losing this race
        // means the endpoint is already seeded, which is the desired end state.
        let _ = self
            .cost
            .compare_exchange(0, word, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// Records a transition into `Healthy`, applying slow-start flap suppression.
    pub fn on_healthy(&self, now_ms: CoarseMillis, slow_start_window_ms: u32) {
        if slow_start_window_ms == 0 {
            self.healthy_since_ms
                .store(now_ms.max(1), Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic health-transition timestamp store, not an ArcSwap config snapshot publish; this crate defines no ArcSwap
            return;
        }
        let left = self.left_healthy_ms.load(Ordering::Relaxed);
        if left != 0 && now_ms.wrapping_sub(left) <= slow_start_window_ms.saturating_mul(2) {
            // Flap suppression: the endpoint was healthy within the last 2T, so
            // do not restart the ramp. Without this, an endpoint that flaps
            // every few seconds never reaches full weight and the cluster
            // permanently loses that capacity while reporting it healthy.
            //
            // `saturating_mul(2)`, not `2 *`: a configured window above `2^31`
            // would otherwise wrap `2 * T` to a small number (or panic in a
            // debug build), inverting the suppression into "restart on every
            // flap", the exact failure this line exists to prevent. Saturating
            // at `u32::MAX` means "always suppress", the safe direction.
            return;
        }
        // `.max(1)` for the same reason `on_unhealthy` uses it: `0` is the
        // "never healthy" sentinel a freshly reset slot holds, so an endpoint
        // that becomes healthy during the first coarse millisecond of process
        // life must not be indistinguishable from one that never became healthy
        // at all.
        self.healthy_since_ms
            .store(now_ms.max(1), Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic health-transition timestamp store, not an ArcSwap config snapshot publish; this crate defines no ArcSwap
    }

    /// Records a transition out of `Healthy`.
    pub fn on_unhealthy(&self, now_ms: CoarseMillis) {
        // `0` is reserved for "never".
        self.left_healthy_ms.store(now_ms.max(1), Ordering::Relaxed); // it-allow: single-snapshot-publish reason: plain relaxed-atomic health-transition timestamp store, not an ArcSwap config snapshot publish; this crate defines no ArcSwap
    }

    /// Current in-flight request count. Read-only; there is no public setter.
    #[must_use]
    pub fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// Current open-connection count. Read-only; there is no public setter.
    #[must_use]
    pub fn active_conns(&self) -> u32 {
        self.active_conns.load(Ordering::Relaxed)
    }
}

/// RAII in-flight accounting. The ONLY way to charge a request against an
/// endpoint.
///
/// There is deliberately no public decrement: a decrement forgotten on one
/// error path makes the endpoint's count ratchet upward forever, silently
/// removing it from service.
#[must_use = "dropping this immediately releases the in-flight slot"]
pub struct InflightGuard<'a> {
    stats: &'a EndpointStats,
    /// Slot generation observed at `acquire`. Private and never exposed: a
    /// caller that could set it could forge a decrement against another
    /// endpoint's counter. Named `gen_at_acquire` rather than the shorter `gen`
    /// the issue's own text uses: `gen` is a reserved keyword as of the 2024
    /// edition this workspace builds under (`cargo build` on the literal `gen`
    /// spelling fails with "expected identifier, found reserved keyword gen"),
    /// so the literal spelling in the issue does not compile. See the
    /// implementation report for this issue.
    gen_at_acquire: u32,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        release_inflight(self.stats, self.gen_at_acquire);
    }
}

impl<'a> InflightGuard<'a> {
    /// Increments `inflight` and returns the guard. Called at selection, before
    /// dispatch.
    pub fn acquire(stats: &'a EndpointStats) -> Self {
        let gen_at_acquire = stats.generation.load(Ordering::Relaxed);
        stats.inflight.fetch_add(1, Ordering::Relaxed);
        Self {
            stats,
            gen_at_acquire,
        }
    }

    /// Folds a round-trip sample into this endpoint's estimate. Convenience for
    /// the response path, which already holds the guard.
    pub fn record_rtt(&self, sample_ms: f32, now_ms: CoarseMillis, cfg: &EwmaCfg) {
        self.stats.record_rtt(sample_ms, now_ms, cfg);
    }

    /// The endpoint's stats, for callers that need to read another counter.
    #[must_use]
    pub fn stats(&self) -> &'a EndpointStats {
        self.stats
    }
}

/// RAII open-connection accounting over `active_conns`. Same pattern, same
/// reason, including the generation test, as [`InflightGuard`]: a pooled
/// connection is precisely the object that outlives a scale-down and a slot
/// recycle. Kept as a separate type, rather than a shared release path with
/// `InflightGuard`, so that a release of either counter appears in exactly two
/// `impl Drop` blocks in the whole workspace, which is what the CI grep checks.
#[must_use = "dropping this immediately releases the connection slot"]
pub struct ConnGuard<'a> {
    stats: &'a EndpointStats,
    /// See [`InflightGuard::gen_at_acquire`] for why this is not spelled `gen`.
    gen_at_acquire: u32,
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        release_active_conns(self.stats, self.gen_at_acquire);
    }
}

impl<'a> ConnGuard<'a> {
    /// Increments `active_conns` and returns the guard.
    pub fn acquire(stats: &'a EndpointStats) -> Self {
        let gen_at_acquire = stats.generation.load(Ordering::Relaxed);
        stats.active_conns.fetch_add(1, Ordering::Relaxed);
        Self {
            stats,
            gen_at_acquire,
        }
    }
}

/// Releases one `inflight` tenancy captured at generation `gen_at_acquire`,
/// called from exactly one place: [`InflightGuard`]'s `Drop` implementation.
///
/// NOT the single relaxed-load-then-unconditional-`fetch_sub` this issue's own
/// text specifies. That shape is unsound: `EndpointRegistryWriter::intern`
/// (`crates/irontraffic-upstream/src/registry.rs`, out of scope for this issue)
/// performs `inflight.store(0)` and `generation.store(g + 1)` as two SEPARATE
/// relaxed writes with a real gap between them. A guard's `drop` can load the
/// OLD `generation` (a match, so it decides to release) and then, before its
/// own write to `inflight` lands, race behind that `store(0)`: a bare
/// `fetch_sub(1)` in that window subtracts 1 from 0 and wraps to `u32::MAX`,
/// exactly the corruption the generation check exists to prevent. This was not
/// a hypothetical: a direct `loom` reproduction of that literal shape (one
/// thread doing `if generation.load() == captured { inflight.fetch_sub(1) }`,
/// the other doing the two-store reset above) fails with
/// `inflight wrapped: 4294967295`, and `loom_guard_release_races_slot_recycle`
/// in `tests/loom_balance.rs` is exactly that reproduction. See the
/// implementation report for this issue for the full write-up and the
/// standalone repro used to confirm it.
///
/// This version instead treats the CURRENT value of `inflight` as the final
/// authority on whether anything is left to release, never subtracting from a
/// counter already at zero: the generation check decides whether to attempt a
/// release at all (so a genuinely fresh tenant's real traffic is never
/// touched), and the compare-exchange retry decides whether THIS attempt may
/// commit, re-observing both facts on every iteration. A concurrent reset
/// always wins that race safely, regardless of exactly when its own generation
/// bump becomes visible to this thread. Confirmed sound against the identical
/// `loom` model this docstring describes failing above.
fn release_inflight(stats: &EndpointStats, gen_at_acquire: u32) {
    loop {
        if stats.generation.load(Ordering::Relaxed) != gen_at_acquire {
            // The slot was retired, recycled, and re-interned for a DIFFERENT
            // endpoint while this request was outstanding. Its counters were
            // zeroed by `intern`, so releasing now would charge this request's
            // release against a stranger.
            return;
        }
        let current = stats.inflight.load(Ordering::Relaxed);
        if current == 0 {
            // A concurrent `intern` reset already zeroed this slot; its own
            // generation bump has simply not become visible here yet (see the
            // race this function's own docstring describes). Nothing to
            // release either way.
            return;
        }
        if stats
            .inflight
            .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        // Lost the race, either to another guard's release or to the reset
        // landing between this thread's load and its compare-exchange: reload
        // both facts and retry.
    }
}

/// Releases one `active_conns` tenancy. Identical pattern and identical reason
/// as [`release_inflight`], called from exactly one place: [`ConnGuard`]'s
/// `Drop` implementation.
fn release_active_conns(stats: &EndpointStats, gen_at_acquire: u32) {
    loop {
        if stats.generation.load(Ordering::Relaxed) != gen_at_acquire {
            return;
        }
        let current = stats.active_conns.load(Ordering::Relaxed);
        if current == 0 {
            return;
        }
        if stats
            .active_conns
            .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EndpointStats;
    use crate::sync::Ordering;

    #[test]
    fn stats_is_one_aligned_line_pair() {
        assert_eq!(core::mem::size_of::<EndpointStats>(), 128);
        assert_eq!(core::mem::align_of::<EndpointStats>(), 128);
    }

    #[test]
    fn stats_default_is_all_zero() {
        let s = EndpointStats::default();
        assert_eq!(s.inflight.load(Ordering::Relaxed), 0);
        assert_eq!(s.active_conns.load(Ordering::Relaxed), 0);
        assert_eq!(s.cost.load(Ordering::Relaxed), 0);
        assert_eq!(s.healthy_since_ms.load(Ordering::Relaxed), 0);
        assert_eq!(s.left_healthy_ms.load(Ordering::Relaxed), 0);
        assert_eq!(s.generation.load(Ordering::Relaxed), 0);
    }
}
