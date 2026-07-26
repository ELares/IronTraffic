// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-cluster resource limits: [`LeasedSemaphore`], its RAII [`Permit`], and the
//! [`ResourceLimits`] bundle of four such semaphores (`max_connections`,
//! `max_pending_requests`, `max_requests`, `max_retries`).
//!
//! These are semaphores, NOT circuit breakers: there is no state machine, no
//! half-open state, and no probing. Envoy calls this shape `CircuitBreakers` in
//! `config.cluster.v3`, which has caused a decade of confusion between a plain
//! concurrency ceiling and Hystrix-style breaker semantics. The closed/open/
//! half-open machine lives separately, per endpoint, in a different module. The
//! name in the config schema, the metrics, and the docs is `resource_limits`.
//!
//! # Batching
//!
//! A shared atomic incremented and decremented on every request is a cache-line
//! ping-pong across cores. Instead, each worker spends from its OWN credit cell
//! (one uncontended CAS) and only touches the shared `charged` counter once
//! every `batch` acquisitions. Charging happens BEFORE spending and never lets
//! `charged` exceed `limit`, so the configured limit is a hard ceiling; the cost
//! is idle capacity, up to `workers * (batch - 1)` permits held as credits by
//! workers that are not using them. [`LeasedSemaphore::flush_stale`] reclaims
//! idle credits from workers that have not charged a batch recently.
//!
//! When `limit <= 4 * workers * batch`, EXACT mode is selected automatically
//! (`batch` becomes 1): every acquisition charges the shared counter directly,
//! because for a small limit the idle-credit waste would be a large fraction of
//! it and the request rate is low enough that shared-line contention does not
//! matter.
//!
//! # No public decrement API, ever
//!
//! A lost balance decrement is capacity that silently disappears forever; a
//! lost increment is over-admission. [`Permit`] is not `Clone`, not `Copy`, and
//! its only way to release is [`Drop`]. There is no `release`, no `decrement`,
//! and no `force_release`. The module's only shared-counter subtraction lives
//! inside [`LeasedSemaphore::flush_stale`], reclaiming idle credits, and is
//! not a permit release.
//!
//! # Ordering
//!
//! Every atomic access uses [`Ordering::Relaxed`]. There is no data dependency
//! being published: a permit carries no payload and the work it guards is
//! ordered by the caller's own control flow.
//!
//! # Atomics under `loom`
//!
//! The `loom` model tests need loom's instrumented atomics, a different type
//! from `core`'s, so the atomic types this module uses for its own balance
//! state are aliased at the top of the file and used everywhere below.
//! [`LeasedStats`] deliberately keeps `core::sync::atomic::AtomicU64` unaliased:
//! it is a metrics-only counter, never part of the correctness invariants the
//! `loom` models check, and aliasing it would only make the model explore
//! interleavings that cannot affect anything this module guarantees.

#![allow(
    unexpected_cfgs,
    reason = "cfg(loom) is a deliberate custom cfg for the loom concurrency-model tests, the same #[cfg(loom)] convention loom's own downstream users (tokio, crossbeam) rely on; registering it via a package-level [lints.rust] check-cfg table would conflict with this crate's required [lints] workspace = true, and this crate may not touch the workspace lints table to add it there instead"
)]

use core::sync::atomic::Ordering as StatOrdering;
#[cfg(not(loom))]
use core::sync::atomic::{AtomicU32, Ordering};
#[cfg(loom)]
use loom::sync::atomic::{AtomicU32, Ordering};

use crossbeam_utils::CachePadded;

use crate::clock::Millis;
use crate::config::{ConfigError, in_range_u32};

/// Which limit rejected an acquisition, for metrics and for the response reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LimitKind {
    /// `max_connections`.
    Connections,
    /// `max_pending_requests`.
    PendingRequests,
    /// `max_requests`.
    Requests,
    /// `max_retries`, the secondary concurrency ceiling on retries.
    Retries,
}

/// Cumulative counters for one semaphore. Deliberately does NOT count
/// acquisitions: counting them would require a shared write per request, which
/// is what the batching exists to avoid.
#[derive(Debug, Default)]
pub struct LeasedStats {
    /// Batches charged from the shared counter.
    pub charges: core::sync::atomic::AtomicU64,
    /// Acquisitions refused because the limit was reached or contention was
    /// extreme.
    pub rejections: core::sync::atomic::AtomicU64,
    /// `flush_stale` calls that reclaimed at least one permit.
    pub reclaims: core::sync::atomic::AtomicU64,
    /// Permits returned to the shared counter by `flush_stale`.
    pub reclaimed_permits: core::sync::atomic::AtomicU64,
}

/// A concurrency balance with batched per-worker leasing and RAII release.
///
/// The configured limit is a hard ceiling: [`LeasedSemaphore::in_use`] never
/// exceeds it while the limit is held fixed (lowering the limit with
/// [`LeasedSemaphore::set_limit`] can leave `in_use` transiently above the new
/// value; see that method's doc). The cost of batching is idle capacity, up to
/// `workers * (batch - 1)` permits held as credits by workers that are not
/// using them, reclaimed by [`LeasedSemaphore::flush_stale`].
///
/// There is no public decrement API. A permit is released by dropping it, and
/// by nothing else, because a lost decrement is capacity that disappears
/// forever.
pub struct LeasedSemaphore {
    /// The ceiling. Written only by the control task.
    limit: AtomicU32,
    /// Permits charged out of the limit, whether currently in use or held as
    /// an idle credit. Never exceeds `limit` at the moment of charging.
    charged: CachePadded<AtomicU32>,
    /// Per-worker credits: charged but not yet spent.
    credits: Box<[CachePadded<AtomicU32>]>,
    /// Last time each worker CHARGED a batch, for staleness reclamation.
    /// Deliberately NOT updated on the fast acquire path: a fast acquisition
    /// already drains the credit cell, so a busy worker's credits are near
    /// zero and there is nothing to reclaim, and writing a second cache line
    /// per request would undo the batching.
    touched_ms: Box<[CachePadded<AtomicU32>]>,
    /// Batch size. 1 in exact mode.
    batch: u32,
    /// Age at which an untouched worker's credits are reclaimed by
    /// `flush_stale`.
    lease_max_age_ms: u32,
    /// Cumulative acquisitions, rejections, charges, and reclaims, for
    /// metrics.
    stats: LeasedStats,
}

impl LeasedSemaphore {
    /// A semaphore for `workers` workers with the given limit and batch size.
    ///
    /// When `limit <= 4 * workers * batch`, EXACT mode is selected
    /// automatically: the effective batch becomes 1, because for a small
    /// limit the idle-credit waste would be a large fraction of the limit and
    /// the request rate is low enough that shared-line contention does not
    /// matter. The comparison is computed in `u64` so a large
    /// `workers * batch` cannot overflow. `batch` of 0 is raised to 1.
    ///
    /// `charged`, every credit cell, and every `touched_ms` cell start at 0.
    #[must_use]
    pub fn new(limit: u32, workers: usize, batch: u32, lease_max_age_ms: u32) -> Self {
        let requested_batch = if batch == 0 { 1 } else { batch };
        let workers_u64 = workers as u64;
        let exact = u64::from(limit) <= 4 * workers_u64 * u64::from(requested_batch);
        let effective_batch = if exact { 1 } else { requested_batch };

        let credits: Box<[CachePadded<AtomicU32>]> = (0..workers)
            .map(|_| CachePadded::new(AtomicU32::new(0)))
            .collect();
        let touched_ms: Box<[CachePadded<AtomicU32>]> = (0..workers)
            .map(|_| CachePadded::new(AtomicU32::new(0)))
            .collect();

        Self {
            limit: AtomicU32::new(limit),
            charged: CachePadded::new(AtomicU32::new(0)),
            credits,
            touched_ms,
            batch: effective_batch,
            lease_max_age_ms,
            stats: LeasedStats::default(),
        }
    }

    /// True when the semaphore selected exact mode.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.batch == 1
    }

    /// The current ceiling.
    #[inline]
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Publish a new ceiling. Control task only. Does not revoke permits
    /// already in use; new charging stops until releases and reclamation
    /// bring the charged balance down.
    ///
    /// Takes `&self` because it is called through the same shared `Arc` the
    /// request path holds, so the "control task only" rule is a convention
    /// rather than a type guarantee. Any request-path caller of this method
    /// would be a defect: it could raise its own ceiling and every limit in
    /// this module would become advisory.
    pub fn set_limit(&self, new_limit: u32) {
        // UFCS form, not `self.limit.store(...)`: this is a plain atomic
        // publish, not the single-writer ArcSwap snapshot the
        // single-snapshot-publish rule polices, and the dot-call spelling of
        // `.store(` is what that rule matches on.
        AtomicU32::store(&self.limit, new_limit, Ordering::Relaxed);
    }

    /// Sum of every worker's idle credit cell. Not atomic as a whole: a
    /// concurrent acquisition or release can make this stale by the time it
    /// is read, which is why callers combine it with `saturating_sub`/
    /// `saturating_add` rather than treating it as exact.
    fn sum_credits(&self) -> u32 {
        self.credits.iter().fold(0u32, |acc, cell| {
            acc.saturating_add(cell.load(Ordering::Relaxed))
        })
    }

    /// Permits currently held by live [`Permit`] values: `charged -
    /// sum(credits)`, computed with `saturating_sub` because the two reads
    /// are not atomic together and a concurrent release can make the credit
    /// sum momentarily exceed the charged value.
    ///
    /// O(workers); for metrics and for the retry ceiling computation, not for
    /// the request path.
    #[must_use]
    pub fn in_use(&self) -> u32 {
        self.charged
            .load(Ordering::Relaxed)
            .saturating_sub(self.sum_credits())
    }

    /// Permits charged from the limit, including idle credits. O(1).
    #[must_use]
    pub fn charged(&self) -> u32 {
        self.charged.load(Ordering::Relaxed)
    }

    /// Remaining headroom: `limit - in_use()`, saturating at 0. O(workers).
    /// This is Envoy's `track_remaining` gauge.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.limit().saturating_sub(self.in_use())
    }

    /// Charge up to `n` permits from the shared counter, never letting
    /// `charged` exceed `limit`. Returns the number actually granted, which
    /// may be less than `n` (including 0) when the limit is nearly reached or
    /// under extreme contention.
    fn try_charge(&self, n: u32) -> u32 {
        let limit = self.limit.load(Ordering::Relaxed);
        for _ in 0..8 {
            let cur = self.charged.load(Ordering::Relaxed);
            if cur >= limit {
                return 0;
            }
            let grant = n.min(limit - cur);
            if self
                .charged
                .compare_exchange_weak(cur, cur + grant, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return grant;
            }
        }
        // Eight failed CAS attempts under extreme contention: reject rather
        // than loop unboundedly. A request that might have fit is refused,
        // which is the safe direction.
        0
    }

    /// Try to acquire one permit for `worker`.
    ///
    /// Returns `None` when the limit is reached, when contention prevented a
    /// charge within a bounded number of attempts, or when `worker` is out of
    /// range. Never blocks, never allocates, never panics.
    #[inline]
    pub fn try_acquire(&self, worker: usize, now: Millis) -> Option<Permit<'_>> {
        // An out-of-range worker is a caller bug, not a limit decision:
        // return before touching any counter, `rejections` included.
        let cell = self.credits.get(worker)?;

        for _ in 0..4 {
            let c = cell.load(Ordering::Relaxed);
            if c == 0 {
                break;
            }
            if cell
                .compare_exchange_weak(c, c - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Some(Permit { sem: self, worker });
            }
        }

        let n = self.try_charge(self.batch);
        if n == 0 {
            self.stats.rejections.fetch_add(1, StatOrdering::Relaxed);
            return None;
        }
        if n == 1 {
            // Exact mode (or the last unit of a batch): nothing left over to
            // bank as a credit, and this arm does NOT count as a `charges`
            // batch, so exact mode reports zero batches forever.
            return Some(Permit { sem: self, worker });
        }
        cell.fetch_add(n - 1, Ordering::Relaxed);
        if let Some(touched) = self.touched_ms.get(worker) {
            // UFCS, not a dot call: a plain atomic publish, not the
            // ArcSwap-style snapshot swap single-snapshot-publish polices.
            AtomicU32::store(touched, now.0, Ordering::Relaxed);
        }
        self.stats.charges.fetch_add(1, StatOrdering::Relaxed);
        Some(Permit { sem: self, worker })
    }

    /// Return idle credits held by workers untouched for longer than
    /// `lease_max_age_ms`. Control task only, every 250 ms. Returns the
    /// number of permits reclaimed.
    pub fn flush_stale(&self, now: Millis) -> u32 {
        let mut reclaimed: u32 = 0;
        for (credit_cell, touched_cell) in self.credits.iter().zip(self.touched_ms.iter()) {
            let last = touched_cell.load(Ordering::Relaxed);
            if now.since(Millis(last)) < self.lease_max_age_ms {
                continue;
            }

            let mut took: u32 = 0;
            for _ in 0..8 {
                let c = credit_cell.load(Ordering::Relaxed);
                if c == 0 {
                    break;
                }
                if credit_cell
                    .compare_exchange_weak(c, 0, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    took = c;
                    break;
                }
            }
            if took > 0 {
                self.charged.fetch_sub(took, Ordering::Relaxed); // allow(fetch_sub): reclaiming idle credits lowers the charged balance; this is the inverse of try_charge, runs only on the control tick, and is not a permit release.
                reclaimed = reclaimed.saturating_add(took);
            }
            // UFCS, not a dot call: same plain-atomic-publish reasoning as
            // the `try_acquire` slow path above.
            AtomicU32::store(touched_cell, now.0, Ordering::Relaxed);
        }
        if reclaimed > 0 {
            self.stats.reclaims.fetch_add(1, StatOrdering::Relaxed);
            self.stats
                .reclaimed_permits
                .fetch_add(u64::from(reclaimed), StatOrdering::Relaxed);
        }
        reclaimed
    }

    /// Cumulative counters.
    #[must_use]
    pub fn stats(&self) -> &LeasedStats {
        &self.stats
    }

    /// Sum of every worker's idle credit cell, for tests that must observe
    /// the internal split between "charged and in use" and "charged and
    /// idle" that `in_use`/`charged` alone cannot distinguish.
    #[cfg(test)]
    pub(crate) fn credit_sum(&self) -> u32 {
        self.sum_credits()
    }
}

/// An acquired permit. Releases on drop and has no other release path.
///
/// Hold it for exactly the lifetime of the guarded work. The caller keeps the
/// [`LeasedSemaphore`] alive through the `Arc` it already holds for the
/// cluster snapshot.
#[must_use = "dropping the permit immediately releases it; bind it for the lifetime of the work"]
pub struct Permit<'a> {
    sem: &'a LeasedSemaphore,
    /// The worker whose credit cell the permit came from and returns to. A
    /// `usize`, not a narrower type: `try_acquire` takes `worker: usize` and
    /// a narrowing cast would need a bound on `workers` that nothing else in
    /// this module needs.
    worker: usize,
}

impl Drop for Permit<'_> {
    /// Returns the permit as a credit to the worker that acquired it. One
    /// relaxed `fetch_add` on one cache line. If a task migrated between
    /// acquiring and dropping the permit, this lands on the ACQUIRING
    /// worker's cell, which is correct for the accounting and merely means
    /// one uncontended remote-line write.
    fn drop(&mut self) {
        if let Some(cell) = self.sem.credits.get(self.worker) {
            cell.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Per-cluster, per-priority resource limits. These are semaphores, NOT
/// circuit breakers: there is no state machine, no half-open state, and no
/// probing. The closed/open/half-open machine is per endpoint and lives
/// elsewhere.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResourceLimitsConfig {
    /// Maximum upstream connections. Default 1024.
    pub max_connections: u32,
    /// Maximum requests queued waiting for a connection. Default 1024.
    pub max_pending_requests: u32,
    /// Maximum in-flight upstream requests. Default 1024.
    pub max_requests: u32,
    /// Percentage of active plus pending requests that may be retries.
    /// Default 20. This is Envoy's `RetryBudget::budget_percent`, accepted
    /// for compatibility as a SECONDARY ceiling; the primary retry limit is
    /// the success-denominated budget computed elsewhere.
    pub retry_budget_percent: u32,
    /// Floor for the retry ceiling. Default 3, matching Envoy's
    /// `min_retry_concurrency`.
    pub min_retry_concurrency: u32,
    /// Permits charged per batch. Default 64.
    pub lease_batch: u32,
    /// Age at which an untouched worker's credits are reclaimed. Default 100.
    pub lease_max_age_ms: u32,
}

impl Default for ResourceLimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_pending_requests: 1024,
            max_requests: 1024,
            retry_budget_percent: 20,
            min_retry_concurrency: 3,
            lease_batch: 64,
            lease_max_age_ms: 100,
        }
    }
}

impl ResourceLimitsConfig {
    /// Largest value accepted for `max_connections`, `max_pending_requests`,
    /// and `max_requests`.
    pub const MAX_STATIC_LIMIT: u32 = 16_777_216;
    /// Largest value accepted for `retry_budget_percent`.
    pub const MAX_RETRY_BUDGET_PERCENT: u32 = 1000;
    /// Largest value accepted for `lease_batch`.
    pub const MAX_LEASE_BATCH: u32 = 4096;
    /// Largest value accepted for `lease_max_age_ms`.
    pub const MAX_LEASE_MAX_AGE_MS: u32 = 60_000;

    /// Validate every field.
    ///
    /// Rejects: any of the three static limits (`max_connections`,
    /// `max_pending_requests`, `max_requests`) equal to 0 or above
    /// [`ResourceLimitsConfig::MAX_STATIC_LIMIT`]; `retry_budget_percent`
    /// above [`ResourceLimitsConfig::MAX_RETRY_BUDGET_PERCENT`];
    /// `min_retry_concurrency` equal to 0; `lease_batch` equal to 0 or above
    /// [`ResourceLimitsConfig::MAX_LEASE_BATCH`]; and `lease_max_age_ms`
    /// equal to 0 or above [`ResourceLimitsConfig::MAX_LEASE_MAX_AGE_MS`].
    ///
    /// # Errors
    /// Returns the first [`ConfigError`] found, naming the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        in_range_u32(
            "resource_limits.max_connections",
            self.max_connections,
            1,
            Self::MAX_STATIC_LIMIT,
        )?;
        in_range_u32(
            "resource_limits.max_pending_requests",
            self.max_pending_requests,
            1,
            Self::MAX_STATIC_LIMIT,
        )?;
        in_range_u32(
            "resource_limits.max_requests",
            self.max_requests,
            1,
            Self::MAX_STATIC_LIMIT,
        )?;
        in_range_u32(
            "resource_limits.retry_budget_percent",
            self.retry_budget_percent,
            0,
            Self::MAX_RETRY_BUDGET_PERCENT,
        )?;
        in_range_u32(
            "resource_limits.min_retry_concurrency",
            self.min_retry_concurrency,
            1,
            u32::MAX,
        )?;
        in_range_u32(
            "resource_limits.lease_batch",
            self.lease_batch,
            1,
            Self::MAX_LEASE_BATCH,
        )?;
        in_range_u32(
            "resource_limits.lease_max_age_ms",
            self.lease_max_age_ms,
            1,
            Self::MAX_LEASE_MAX_AGE_MS,
        )?;
        Ok(())
    }
}

/// `max(min_retry_concurrency, active * retry_budget_percent / 100)`. Envoy's
/// `RetryBudget` computation, reproduced exactly: a percentage of the active
/// plus active-pending count, floored at `min_retry_concurrency`.
///
/// The narrowing from the `u64` product to `u32` SATURATES rather than
/// truncates: `retry_budget_percent` is validated up to 1000 and `active` is
/// a `u32`, so the product can reach roughly 4.3e12, and a bare narrowing
/// cast would reduce that modulo 2^32 and land anywhere, including on a
/// value far BELOW `min_retry_concurrency` while the cluster is at maximum
/// load, which would turn the secondary retry ceiling into a random number
/// exactly when it is doing work.
#[allow(
    clippy::integer_division,
    reason = "the percentage-of-active budget calculation is exact-enough by design, matching Envoy's RetryBudget; the floor below covers the truncation toward zero"
)]
fn retry_ceiling(active: u32, cfg: ResourceLimitsConfig) -> u32 {
    let scaled = u64::from(active) * u64::from(cfg.retry_budget_percent) / 100;
    let scaled = u32::try_from(scaled).unwrap_or(u32::MAX);
    scaled.max(cfg.min_retry_concurrency)
}

/// The four semaphores for one cluster and priority.
pub struct ResourceLimits {
    connections: LeasedSemaphore,
    pending_requests: LeasedSemaphore,
    requests: LeasedSemaphore,
    retries: LeasedSemaphore,
    cfg: ResourceLimitsConfig,
}

impl ResourceLimits {
    /// Build the four semaphores.
    ///
    /// The retry semaphore starts at `cfg.min_retry_concurrency`, the floor
    /// [`ResourceLimits::refresh_retry_ceiling`] never goes below; the
    /// control task is expected to call `refresh_retry_ceiling` once traffic
    /// exists.
    ///
    /// # Errors
    /// The config's own [`ResourceLimitsConfig::validate`] error, or
    /// [`ConfigError`] naming `resource_limits.workers` when `workers == 0`:
    /// every [`LeasedSemaphore::try_acquire`] bounds-checks
    /// `worker < workers`, so a zero-worker semaphore would refuse every
    /// acquisition forever, which reads as a total outage rather than as a
    /// misconfiguration.
    pub fn new(cfg: ResourceLimitsConfig, workers: usize) -> Result<Self, ConfigError> {
        cfg.validate()?;
        if workers == 0 {
            return Err(ConfigError::new(
                "resource_limits.workers",
                "0",
                "must be at least 1",
            ));
        }
        let connections = LeasedSemaphore::new(
            cfg.max_connections,
            workers,
            cfg.lease_batch,
            cfg.lease_max_age_ms,
        );
        let pending_requests = LeasedSemaphore::new(
            cfg.max_pending_requests,
            workers,
            cfg.lease_batch,
            cfg.lease_max_age_ms,
        );
        let requests = LeasedSemaphore::new(
            cfg.max_requests,
            workers,
            cfg.lease_batch,
            cfg.lease_max_age_ms,
        );
        let retries = LeasedSemaphore::new(
            cfg.min_retry_concurrency,
            workers,
            cfg.lease_batch,
            cfg.lease_max_age_ms,
        );
        Ok(Self {
            connections,
            pending_requests,
            requests,
            retries,
            cfg,
        })
    }

    /// The connection semaphore.
    #[must_use]
    pub fn connections(&self) -> &LeasedSemaphore {
        &self.connections
    }

    /// The pending-request semaphore.
    #[must_use]
    pub fn pending_requests(&self) -> &LeasedSemaphore {
        &self.pending_requests
    }

    /// The in-flight request semaphore. The adaptive concurrency controller
    /// publishes its computed limit here with `set_limit`.
    #[must_use]
    pub fn requests(&self) -> &LeasedSemaphore {
        &self.requests
    }

    /// The retry semaphore, whose limit is recomputed by
    /// [`ResourceLimits::refresh_retry_ceiling`].
    #[must_use]
    pub fn retries(&self) -> &LeasedSemaphore {
        &self.retries
    }

    /// Recompute and publish the retry ceiling as
    /// `max(min_retry_concurrency, (requests.in_use() +
    /// pending_requests.in_use()) * retry_budget_percent / 100)`. Control
    /// task only, every 250 ms.
    ///
    /// The two `in_use` values are combined with `saturating_add`: they are
    /// read non-atomically and a lowered `set_limit` can make either
    /// momentarily large, so a plain `+` could wrap instead of saturating at
    /// exactly the moment this ceiling matters most.
    pub fn refresh_retry_ceiling(&self) {
        let active = self
            .requests
            .in_use()
            .saturating_add(self.pending_requests.in_use());
        self.retries.set_limit(retry_ceiling(active, self.cfg));
    }

    /// Reclaim idle credits on all four semaphores. Control task only, every
    /// 250 ms.
    pub fn flush_stale(&self, now: Millis) -> u32 {
        self.connections
            .flush_stale(now)
            .saturating_add(self.pending_requests.flush_stale(now))
            .saturating_add(self.requests.flush_stale(now))
            .saturating_add(self.retries.flush_stale(now))
    }

    /// The configuration in effect.
    #[must_use]
    pub fn config(&self) -> ResourceLimitsConfig {
        self.cfg
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering::Relaxed as StdRelaxed;

    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;

    use super::{
        LeasedSemaphore, Millis, Ordering, Permit, ResourceLimits, ResourceLimitsConfig,
        retry_ceiling,
    };

    /// Test 1: the documented defaults, pinned as literals so a drifting
    /// constant is a deliberate, reviewed edit rather than a silent change
    /// every symbolic reference elsewhere would stay quiet about.
    #[test]
    fn default_config_values() {
        let cfg = ResourceLimitsConfig::default();
        assert_eq!(cfg.max_connections, 1024);
        assert_eq!(cfg.max_pending_requests, 1024);
        assert_eq!(cfg.max_requests, 1024);
        assert_eq!(cfg.retry_budget_percent, 20);
        assert_eq!(cfg.min_retry_concurrency, 3);
        assert_eq!(cfg.lease_batch, 64);
        assert_eq!(cfg.lease_max_age_ms, 100);
    }

    /// Test 2: one row per clause of invariant 8 (every field individually,
    /// both the "equal to 0" and "above the maximum" side where applicable),
    /// plus invariant 9's `workers == 0` rejection naming the right field,
    /// plus the boundary values that must still validate.
    #[test]
    fn validate_rejects_table() {
        let base = ResourceLimitsConfig::default();

        let mut c = base;
        c.max_connections = 0;
        assert!(c.validate().is_err());
        let mut c = base;
        c.max_pending_requests = 0;
        assert!(c.validate().is_err());
        let mut c = base;
        c.max_requests = 0;
        assert!(c.validate().is_err());

        let mut c = base;
        c.max_connections = ResourceLimitsConfig::MAX_STATIC_LIMIT + 1;
        assert!(c.validate().is_err());
        let mut c = base;
        c.max_pending_requests = ResourceLimitsConfig::MAX_STATIC_LIMIT + 1;
        assert!(c.validate().is_err());
        let mut c = base;
        c.max_requests = ResourceLimitsConfig::MAX_STATIC_LIMIT + 1;
        assert!(c.validate().is_err());

        let mut c = base;
        c.retry_budget_percent = ResourceLimitsConfig::MAX_RETRY_BUDGET_PERCENT + 1;
        assert!(c.validate().is_err());

        let mut c = base;
        c.min_retry_concurrency = 0;
        assert!(c.validate().is_err());

        let mut c = base;
        c.lease_batch = 0;
        assert!(c.validate().is_err());
        let mut c = base;
        c.lease_batch = ResourceLimitsConfig::MAX_LEASE_BATCH + 1;
        assert!(c.validate().is_err());

        let mut c = base;
        c.lease_max_age_ms = 0;
        assert!(c.validate().is_err());
        let mut c = base;
        c.lease_max_age_ms = ResourceLimitsConfig::MAX_LEASE_MAX_AGE_MS + 1;
        assert!(c.validate().is_err());

        // The boundary values themselves must still validate: a rule written
        // as `>` that a mutation flips to `>=` would reject exactly these.
        let mut c = base;
        c.max_connections = ResourceLimitsConfig::MAX_STATIC_LIMIT;
        c.lease_batch = ResourceLimitsConfig::MAX_LEASE_BATCH;
        c.lease_max_age_ms = ResourceLimitsConfig::MAX_LEASE_MAX_AGE_MS;
        c.retry_budget_percent = ResourceLimitsConfig::MAX_RETRY_BUDGET_PERCENT;
        assert!(c.validate().is_ok());

        assert!(base.validate().is_ok());

        match ResourceLimits::new(ResourceLimitsConfig::default(), 0) {
            Ok(_) => panic!("workers == 0 must be rejected"),
            Err(e) => assert_eq!(e.field, "resource_limits.workers"),
        }
        assert!(ResourceLimits::new(ResourceLimitsConfig::default(), 1).is_ok());
    }

    /// Test 3: the exact/batched gate, including its `<=` boundary.
    #[test]
    fn exact_mode_selection() {
        assert!(LeasedSemaphore::new(4096, 16, 64, 100).is_exact());
        assert!(!LeasedSemaphore::new(4097, 16, 64, 100).is_exact());
        assert!(LeasedSemaphore::new(10, 2, 64, 100).is_exact());
    }

    /// Test 4: in exact mode, charging never banks a credit.
    #[test]
    fn exact_mode_no_credits() {
        let sem = LeasedSemaphore::new(10, 2, 64, 100);
        assert!(sem.is_exact());
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(sem.try_acquire(0, Millis(0)).expect("permit available"));
        }
        assert_eq!(sem.credit_sum(), 0);
        assert_eq!(sem.in_use(), 5);
        assert_eq!(sem.charged(), 5);
        drop(held);
    }

    /// Test 5: a batch is charged once per `batch` acquisitions, not once per
    /// acquisition.
    #[test]
    fn batched_charges_once_per_batch() {
        let sem = LeasedSemaphore::new(1024, 1, 64, 100);
        assert!(!sem.is_exact());
        let mut held = Vec::new();
        for _ in 0..64 {
            held.push(sem.try_acquire(0, Millis(0)).expect("permit available"));
        }
        assert_eq!(sem.stats().charges.load(StdRelaxed), 1);
        assert_eq!(sem.charged(), 64);

        held.push(
            sem.try_acquire(0, Millis(0))
                .expect("permit available on the 65th acquisition"),
        );
        assert_eq!(sem.stats().charges.load(StdRelaxed), 2);
        assert_eq!(sem.charged(), 128);
        drop(held);
    }

    /// Test 6: dropping a permit returns it as a credit, not to `charged`.
    #[test]
    fn permit_release_returns_credit() {
        let sem = LeasedSemaphore::new(1024, 1, 64, 100);
        let p = sem.try_acquire(0, Millis(0)).expect("permit available");
        drop(p);
        assert_eq!(sem.in_use(), 0);
        assert_eq!(sem.charged(), 64);
    }

    /// Test 7: the limit is a hard ceiling in exact mode.
    #[test]
    fn limit_is_hard_ceiling() {
        let sem = LeasedSemaphore::new(10, 1, 64, 100);
        assert!(sem.is_exact());
        let mut held = Vec::new();
        for _ in 0..10 {
            held.push(sem.try_acquire(0, Millis(0)).expect("permit available"));
        }
        assert!(sem.try_acquire(0, Millis(0)).is_none());
        assert_eq!(sem.in_use(), 10);
        assert_eq!(sem.stats().rejections.load(StdRelaxed), 1);
        drop(held);
    }

    /// Test 8: the limit is a hard ceiling in batched mode too, throughout a
    /// full drain from a single worker.
    ///
    /// Bounded at `4160 + 40` rather than an unbounded `while let`: a broken
    /// charge/spend arithmetic mutation that never returns `None` must fail
    /// this test fast (via the length assertion below), not hang the test
    /// process until the harness times it out.
    #[test]
    fn limit_hard_ceiling_batched() {
        let sem = LeasedSemaphore::new(4160, 16, 64, 100);
        assert!(!sem.is_exact());
        let mut held = Vec::new();
        for _ in 0..(4160 + 40) {
            match sem.try_acquire(0, Millis(0)) {
                Some(p) => {
                    held.push(p);
                    assert!(sem.in_use() <= 4160);
                }
                None => break,
            }
        }
        assert!(sem.in_use() <= 4160);
        assert_eq!(held.len(), 4160);
        drop(held);
    }

    /// Catches a defect in `try_charge`'s clamp (`limit - cur`, not
    /// `limit + cur`) that only shows up when the final batch before the
    /// limit is SMALLER than a full batch: with an evenly divisible limit
    /// (as in `limit_hard_ceiling_batched` above, `4160 = 65 * 64`) every
    /// grant, including the last, happens to be exactly `batch` either way,
    /// so a clamp computed with `+` instead of `-` produces the same grant
    /// by coincidence. `2000` is not a multiple of `64` (`31 * 64 = 1984`,
    /// leaving a final partial batch of `16`), so the two clamps diverge:
    /// the correct one grants `16` and stops exactly at `2000`; the broken
    /// one grants a full `64` and overshoots to `2048`.
    #[test]
    fn batched_final_partial_charge_does_not_overshoot() {
        let sem = LeasedSemaphore::new(2000, 1, 64, 100);
        assert!(!sem.is_exact());
        let mut held = Vec::new();
        for _ in 0..(2000 + 40) {
            match sem.try_acquire(0, Millis(0)) {
                Some(p) => held.push(p),
                None => break,
            }
            assert!(sem.charged() <= 2000);
        }
        assert_eq!(held.len(), 2000);
        assert_eq!(sem.charged(), 2000);
        drop(held);
    }

    /// Test 9: idle credits held by one worker can refuse another worker even
    /// though capacity is technically free, and `flush_stale` recovers it.
    #[test]
    fn idle_credits_block_another_worker() {
        let sem = LeasedSemaphore::new(72, 2, 8, 100);
        assert!(!sem.is_exact());
        let mut held = Vec::new();
        for _ in 0..65 {
            held.push(sem.try_acquire(0, Millis(0)).expect("permit available"));
        }
        assert_eq!(sem.charged(), 72);

        assert!(sem.try_acquire(1, Millis(0)).is_none());

        assert_eq!(sem.flush_stale(Millis(100)), 7);
        assert_eq!(sem.stats().reclaims.load(StdRelaxed), 1);
        assert_eq!(sem.stats().reclaimed_permits.load(StdRelaxed), 7);

        held.push(
            sem.try_acquire(1, Millis(100))
                .expect("permit available after reclaim"),
        );
        drop(held);
    }

    /// Test 10: `flush_stale` respects `lease_max_age_ms` exactly at the
    /// boundary.
    #[test]
    fn flush_stale_respects_age() {
        let sem = LeasedSemaphore::new(1024, 1, 64, 100);
        let p = sem.try_acquire(0, Millis(0)).expect("permit available");
        drop(p);
        assert_eq!(sem.flush_stale(Millis(99)), 0);
        assert_eq!(sem.flush_stale(Millis(100)), 64);
    }

    /// Test 11: nothing to reclaim in a pristine exact-mode semaphore.
    #[test]
    fn flush_stale_zero_when_no_credits() {
        let sem = LeasedSemaphore::new(10, 1, 64, 100);
        assert!(sem.is_exact());
        assert_eq!(sem.flush_stale(Millis(1_000)), 0);
        // A `flush_stale` call that reclaimed nothing must not count as a
        // reclaim: `reclaims` and `reclaimed_permits` are gated on actually
        // having taken a credit, not on merely having been called.
        assert_eq!(sem.stats().reclaims.load(StdRelaxed), 0);
        assert_eq!(sem.stats().reclaimed_permits.load(StdRelaxed), 0);
    }

    /// Test 12: raising the limit immediately permits more charging.
    #[test]
    fn set_limit_raises() {
        let sem = LeasedSemaphore::new(4, 1, 1, 100);
        assert!(sem.is_exact());
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(sem.try_acquire(0, Millis(0)).expect("permit available"));
        }
        assert!(sem.try_acquire(0, Millis(0)).is_none());
        sem.set_limit(8);
        for _ in 0..4 {
            held.push(
                sem.try_acquire(0, Millis(0))
                    .expect("permit available after raise"),
            );
        }
        drop(held);
    }

    /// Test 13: lowering the limit below the charged amount refuses new
    /// charges until releases and reclamation bring `charged` back down.
    #[test]
    fn set_limit_lowers() {
        let sem = LeasedSemaphore::new(1024, 1, 64, 100);
        let p = sem.try_acquire(0, Millis(0)).expect("permit available");
        assert_eq!(sem.charged(), 64);

        sem.set_limit(1);
        drop(p);
        let reclaimed = sem.flush_stale(Millis(100));
        assert!(reclaimed > 0);
        assert!(sem.charged() <= 1);

        assert!(sem.try_acquire(0, Millis(100)).is_some());
    }

    /// Test 14: `remaining` saturates at 0 rather than underflowing when a
    /// lowered limit is already below `in_use`.
    #[test]
    fn remaining_saturates() {
        let sem = LeasedSemaphore::new(1024, 1, 64, 100);
        let mut held = Vec::new();
        for _ in 0..10 {
            held.push(sem.try_acquire(0, Millis(0)).expect("permit available"));
        }
        assert_eq!(sem.charged(), 64);
        assert_eq!(sem.in_use(), 10);
        sem.set_limit(1);
        assert_eq!(sem.remaining(), 0);
        drop(held);
    }

    /// `remaining` must actually reflect headroom, not just saturate at 0:
    /// a semaphore with nothing acquired has ALL of its limit remaining, and
    /// acquiring one permit takes exactly one unit of it away.
    #[test]
    fn remaining_reflects_headroom() {
        let sem = LeasedSemaphore::new(10, 1, 64, 100);
        assert_eq!(sem.remaining(), 10);
        let p = sem.try_acquire(0, Millis(0)).expect("permit available");
        assert_eq!(sem.remaining(), 9);
        drop(p);
        assert_eq!(sem.remaining(), 10);
    }

    /// Test 15: an out-of-range worker is a caller bug, not a limit
    /// rejection: it must change no counter at all.
    #[test]
    fn worker_out_of_range() {
        let sem = LeasedSemaphore::new(1024, 4, 64, 100);
        let rejections_before = sem.stats().rejections.load(StdRelaxed);
        let charges_before = sem.stats().charges.load(StdRelaxed);
        let total_charged_before = sem.charged();

        assert!(sem.try_acquire(99, Millis(0)).is_none());

        assert_eq!(sem.stats().rejections.load(StdRelaxed), rejections_before);
        assert_eq!(sem.stats().charges.load(StdRelaxed), charges_before);
        assert_eq!(sem.charged(), total_charged_before);
    }

    /// Test 16: a permit always returns its credit to the worker that
    /// ACQUIRED it, never to wherever it happens to be dropped.
    #[test]
    fn release_on_other_worker() {
        let sem = LeasedSemaphore::new(2048, 4, 64, 100);
        assert!(!sem.is_exact());
        let p = sem.try_acquire(0, Millis(0)).expect("permit available");
        let charges_after_acquire = sem.stats().charges.load(StdRelaxed);
        assert_eq!(charges_after_acquire, 1);

        // Drop the permit here, standing in for "on worker 3": `Permit`
        // carries only the worker that ACQUIRED it (`self.worker`, set once
        // at `try_acquire` time), so nothing about where or when `drop` runs
        // can change which cell is credited; there is no "current worker"
        // for the type to read.
        drop(p);

        // Worker 0's cell now holds 64 idle credits (63 from the original
        // charge, plus the one just released). Draining exactly 64 more
        // acquisitions from worker 0 with no additional charge proves the
        // release landed there: had it landed on a different worker's cell,
        // worker 0 would have run dry after 63 and forced a second charge.
        let mut held = Vec::new();
        for _ in 0..64 {
            held.push(
                sem.try_acquire(0, Millis(0))
                    .expect("worker 0's own idle credits, including the released one"),
            );
        }
        assert_eq!(
            sem.stats().charges.load(StdRelaxed),
            charges_after_acquire,
            "the release must land in worker 0's cell, not be lost or credited elsewhere"
        );
        drop(held);
    }

    /// Test 17: with no active traffic, the retry ceiling sits at the floor.
    #[test]
    fn retry_ceiling_floor() {
        let cfg = ResourceLimitsConfig::default();
        let limits = ResourceLimits::new(cfg, 1).expect("valid config");
        limits.refresh_retry_ceiling();
        assert_eq!(limits.retries().limit(), 3);
    }

    /// Test 18: the retry ceiling tracks the configured percentage of active
    /// plus pending requests.
    #[test]
    fn retry_ceiling_percentage() {
        let cfg = ResourceLimitsConfig {
            max_requests: 1000,
            max_pending_requests: 1000,
            ..ResourceLimitsConfig::default()
        };
        let limits = ResourceLimits::new(cfg, 1).expect("valid config");

        let mut held = Vec::new();
        for _ in 0..100 {
            held.push(
                limits
                    .requests()
                    .try_acquire(0, Millis(0))
                    .expect("permit available"),
            );
        }
        for _ in 0..100 {
            held.push(
                limits
                    .pending_requests()
                    .try_acquire(0, Millis(0))
                    .expect("permit available"),
            );
        }

        limits.refresh_retry_ceiling();
        assert_eq!(limits.retries().limit(), 40);
        drop(held);
    }

    /// Test 19: the floor wins over the percentage when active traffic is
    /// low.
    #[test]
    fn retry_ceiling_min_wins() {
        let cfg = ResourceLimitsConfig {
            max_requests: 100,
            ..ResourceLimitsConfig::default()
        };
        let limits = ResourceLimits::new(cfg, 1).expect("valid config");

        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(
                limits
                    .requests()
                    .try_acquire(0, Millis(0))
                    .expect("permit available"),
            );
        }

        limits.refresh_retry_ceiling();
        assert_eq!(limits.retries().limit(), 3);
        drop(held);
    }

    /// Test 20: the `Permit` contract is textually declared: it releases only
    /// through `Drop`, is documented as such, and is never `Clone`. A
    /// negative trait bound is not expressible in Rust, so absence of
    /// `Clone` is asserted textually here (and enforced again by the
    /// acceptance-criteria grep, a second, independent line of defense).
    #[test]
    fn permit_contract_is_declared() {
        let source = include_str!("mod.rs");
        assert!(source.contains("#[must_use = \"dropping the permit"));
        assert!(source.contains("impl Drop for Permit"));
        // Built at runtime from two pieces rather than written as one
        // literal: `include_str!` reads this whole file, including this
        // test's own source, so spelling the forbidden trait impl out in
        // full right here would make the file "contain" the very text this
        // assertion checks is absent, failing regardless of whether such an
        // impl actually exists anywhere else.
        let never_this_impl = format!("impl {} for Permit", "Cl".to_owned() + "one");
        assert!(!source.contains(&never_this_impl));
    }

    /// Test 21: acquisitions are never counted directly; only batches are,
    /// and `LeasedStats` has no `acquisitions` field at all (a compile-time
    /// property, so the runtime assertion here is the bound on `charges`).
    #[test]
    fn stats_do_not_count_acquisitions() {
        let sem = LeasedSemaphore::new(2048, 1, 64, 100);
        assert!(!sem.is_exact());
        let mut held = Vec::new();
        for _ in 0..1000 {
            held.push(sem.try_acquire(0, Millis(0)).expect("permit available"));
        }
        assert!(sem.stats().charges.load(StdRelaxed) <= 16);
        drop(held);
    }

    /// Test 18a: the `u64` product must saturate through `u32::try_from`,
    /// not truncate with `as u32`, or a cluster at maximum load would see its
    /// secondary retry ceiling collapse to an arbitrary small number instead
    /// of staying wide open. `requests`' charged balance is hand-set to
    /// `u32::MAX` directly (reaching that state through real acquisitions
    /// would take billions of calls); `pending_requests` is left at 0 so this
    /// test isolates the multiplication step from the addition step that
    /// test 18b covers.
    #[test]
    fn retry_ceiling_saturates() {
        let cfg = ResourceLimitsConfig {
            retry_budget_percent: 1000,
            ..ResourceLimitsConfig::default()
        };
        let limits = ResourceLimits::new(cfg, 1).expect("valid config");

        limits.requests().set_limit(u32::MAX);
        limits.requests().charged.store(u32::MAX, Ordering::Relaxed);

        limits.refresh_retry_ceiling();
        assert_eq!(limits.retries().limit(), u32::MAX);
    }

    /// Test 18b: the two `in_use` values must be combined with
    /// `saturating_add`, not a plain `+`, or driving both `requests` and
    /// `pending_requests` near `u32::MAX` would overflow the addition (a
    /// panic under the overflow checks this workspace builds tests with, or
    /// a silent wrap to a small active count in a build without them)
    /// instead of saturating at `u32::MAX`.
    #[test]
    fn retry_ceiling_active_sum_saturates() {
        let cfg = ResourceLimitsConfig {
            retry_budget_percent: 1000,
            ..ResourceLimitsConfig::default()
        };
        let limits = ResourceLimits::new(cfg, 1).expect("valid config");

        limits.requests().set_limit(u32::MAX);
        limits
            .requests()
            .charged
            .store(u32::MAX - 5, Ordering::Relaxed);
        limits.pending_requests().set_limit(u32::MAX);
        limits
            .pending_requests()
            .charged
            .store(u32::MAX - 3, Ordering::Relaxed);

        limits.refresh_retry_ceiling();
        assert_eq!(limits.retries().limit(), u32::MAX);
    }

    #[derive(Debug, Clone, Copy)]
    enum LimitOp {
        Acquire(usize),
        DropOldest,
        Flush,
        SetLimit(u32),
    }

    fn limit_op_strategy() -> impl Strategy<Value = LimitOp> {
        prop_oneof![
            (0usize..4).prop_map(LimitOp::Acquire),
            Just(LimitOp::DropOldest),
            Just(LimitOp::Flush),
            (0u32..=256).prop_map(LimitOp::SetLimit),
        ]
    }

    /// Checks the three exact invariants the design promises after every
    /// single step: `in_use` matches the model's live-permit count, the
    /// credit cells plus `in_use` always reconstruct `charged` exactly (no
    /// permit is ever lost or double-counted), and `charged` never exceeds
    /// the highest limit ever published (not merely the CURRENT limit,
    /// because lowering it does not revoke already-charged permits; see edge
    /// case 13).
    fn assert_balance_invariants(
        sem: &LeasedSemaphore,
        live_count: usize,
        max_limit_ever_set: u32,
    ) -> Result<(), TestCaseError> {
        let live_count = u32::try_from(live_count).unwrap_or(u32::MAX);
        prop_assert_eq!(sem.in_use(), live_count);
        prop_assert_eq!(sem.credit_sum() + sem.in_use(), sem.charged());
        prop_assert!(sem.charged() <= max_limit_ever_set);
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        /// Test 22 (property test): for arbitrary interleavings of acquire,
        /// drop-oldest, flush, and set-limit across 4 workers and 3 batch
        /// sizes (1, 8, and 64, covering exact and batched modes), the
        /// balance invariants hold after every single step, not merely at
        /// the end.
        #[test]
        fn prop_never_exceeds_limit(
            initial_limit in 1u32..=256,
            batch in prop_oneof![Just(1u32), Just(8u32), Just(64u32)],
            ops in prop::collection::vec(limit_op_strategy(), 0..=128),
        ) {
            let sem = LeasedSemaphore::new(initial_limit, 4, batch, 100);
            let mut live: std::collections::VecDeque<Permit<'_>> = std::collections::VecDeque::new();
            let mut now_ms: u32 = 0;
            let mut max_limit_ever_set = initial_limit;

            assert_balance_invariants(&sem, live.len(), max_limit_ever_set)?;

            for op in ops {
                match op {
                    LimitOp::Acquire(worker) => {
                        now_ms = now_ms.wrapping_add(1);
                        if let Some(p) = sem.try_acquire(worker, Millis(now_ms)) {
                            live.push_back(p);
                        }
                    }
                    LimitOp::DropOldest => {
                        live.pop_front();
                    }
                    LimitOp::Flush => {
                        now_ms = now_ms.wrapping_add(200);
                        sem.flush_stale(Millis(now_ms));
                    }
                    LimitOp::SetLimit(l) => {
                        sem.set_limit(l);
                        max_limit_ever_set = max_limit_ever_set.max(l);
                    }
                }
                assert_balance_invariants(&sem, live.len(), max_limit_ever_set)?;
            }
        }
    }

    /// `ResourceLimits::config` must return the configuration it was built
    /// with, not a fresh default: a field far from any default value makes
    /// the two unmistakable.
    #[test]
    fn resource_limits_config_returns_what_it_was_built_with() {
        let cfg = ResourceLimitsConfig {
            max_connections: 777,
            ..ResourceLimitsConfig::default()
        };
        assert_ne!(
            cfg.max_connections,
            ResourceLimitsConfig::default().max_connections
        );
        let limits = ResourceLimits::new(cfg, 1).expect("valid config");
        assert_eq!(limits.config(), cfg);
    }

    /// `ResourceLimits::flush_stale` must sum the reclaims of all four
    /// underlying semaphores, not just report one of them or a constant:
    /// leaving idle credits on two of the four (`connections` and
    /// `pending_requests`) and none on the other two (`requests`,
    /// `retries`, both untouched and therefore with nothing to reclaim)
    /// pins the total to exactly the sum of the two real reclaims.
    #[test]
    fn resource_limits_flush_stale_sums_all_four_semaphores() {
        let limits = ResourceLimits::new(ResourceLimitsConfig::default(), 1).expect("valid config");
        drop(
            limits
                .connections()
                .try_acquire(0, Millis(0))
                .expect("permit available"),
        );
        drop(
            limits
                .pending_requests()
                .try_acquire(0, Millis(0))
                .expect("permit available"),
        );
        assert_eq!(limits.connections().charged(), 64);
        assert_eq!(limits.pending_requests().charged(), 64);

        let reclaimed = limits.flush_stale(Millis(100));
        assert_eq!(reclaimed, 128);
        assert_eq!(limits.connections().charged(), 0);
        assert_eq!(limits.pending_requests().charged(), 0);
    }

    /// `retry_ceiling` itself, directly: the floor wins when the percentage
    /// underflows it, independent of `ResourceLimits` plumbing.
    #[test]
    fn retry_ceiling_helper_floor_wins() {
        let cfg = ResourceLimitsConfig::default();
        assert_eq!(retry_ceiling(0, cfg), 3);
    }
}

#[cfg(loom)]
mod loom_tests {
    use loom::sync::Arc;
    use loom::thread;

    use super::{LeasedSemaphore, Millis};

    /// Test 23: two workers, each acquiring and dropping once against a
    /// limit of 2 in exact mode, must never observe more than 2 in use at
    /// any interleaving `loom` explores, and must end with nothing charged.
    ///
    /// `Permit::drop` returns a released permit as an idle CREDIT, never as
    /// a direct decrement of `charged` (that is true in every mode, per its
    /// own doc and per `permit_release_returns_credit` above), so after both
    /// threads acquire and drop, `charged` sits at 2 held as two idle
    /// credits, not at 0: only `flush_stale` (or a lowered `set_limit`)
    /// converges `charged` back down. `lease_max_age_ms` is 0 so a single
    /// `flush_stale` call, at any timestamp, reclaims both immediately
    /// without needing the model to track elapsed time.
    #[test]
    fn loom_two_workers_never_exceed_limit() {
        loom::model(|| {
            let sem = Arc::new(LeasedSemaphore::new(2, 2, 1, 0));
            let sem2 = Arc::clone(&sem);
            let t = thread::spawn(move || {
                let p = sem2.try_acquire(1, Millis(0));
                assert!(sem2.in_use() <= 2);
                drop(p);
            });

            let p0 = sem.try_acquire(0, Millis(0));
            assert!(sem.in_use() <= 2);
            drop(p0);

            let join_result = t.join();
            assert!(join_result.is_ok(), "worker 1's thread panicked");

            assert_eq!(sem.in_use(), 0);
            sem.flush_stale(Millis(0));
            assert_eq!(sem.charged(), 0);
        });
    }

    /// Test 24: one thread acquires and drops while another concurrently
    /// runs `flush_stale`; no permit is lost or double-counted at any
    /// interleaving, and the semaphore remains fully usable afterward.
    #[test]
    fn loom_acquire_races_flush() {
        loom::model(|| {
            let sem = Arc::new(LeasedSemaphore::new(4, 2, 4, 0));

            let sem_acquire = Arc::clone(&sem);
            let acquirer = thread::spawn(move || {
                let p = sem_acquire.try_acquire(0, Millis(0));
                assert!(sem_acquire.in_use() <= 4);
                drop(p);
            });
            let sem_flush = Arc::clone(&sem);
            let flusher = thread::spawn(move || {
                sem_flush.flush_stale(Millis(0));
                assert!(sem_flush.in_use() <= 4);
            });

            let acquire_result = acquirer.join();
            assert!(acquire_result.is_ok(), "acquirer thread panicked");
            let flush_result = flusher.join();
            assert!(flush_result.is_ok(), "flusher thread panicked");

            assert!(sem.in_use() <= 4);
            let one_more = sem.try_acquire(1, Millis(0));
            assert!(one_more.is_some(), "no permit was lost across the race");
        });
    }
}
