// SPDX-License-Identifier: MIT OR Apache-2.0

//! `HealthScheduler`: the one active health checker per process.
//!
//! A sans-IO state machine that drives the timer wheel, emits [`CheckOrder`] values
//! when endpoints are due, accepts [`CheckReport`] values, applies hysteresis, and
//! publishes the result into [`ClusterHealth`]. It enforces both the global
//! in-flight check cap (`max_concurrent`) and the per-endpoint probe rate cap by
//! DEFERRING a due endpoint in the wheel rather than starting more work than the
//! cap allows: an excess check is rescheduled to the tail of a monotonically
//! increasing cursor, not a fixed few milliseconds out (the retry distance grows
//! with the size of the deferred backlog; see the "Deferral, not queueing" section
//! below), never held in an unbounded queue. It exists because per-worker health
//! checking multiplies the aggregate probe rate by the worker count, and because a
//! serial sweep and a fully concurrent sweep are both wrong: one starves at scale,
//! the other creates a connection storm against the very upstream being probed.
//!
//! This file performs no I/O, creates no background task of its own, and reads no
//! clock: every function that needs the current time takes it as a [`Millis`]
//! parameter, and every function that needs randomness takes `&mut Rng`. The runner
//! that owns the sockets and calls [`HealthScheduler::poll_due`] and
//! [`HealthScheduler::record`] lives outside this crate.
//!
//! # Published health precedence
//!
//! Four independent signals can make an endpoint unavailable: active checking (the
//! hysteresis state in [`crate::health::schedule::EndpointSchedule`]), outlier
//! ejection, the unejection slow-start ramp, and graceful drain. `Self::publish` is
//! the only place that resolves them into one [`EndpointHealth`] and the only
//! caller of [`crate::health::bitmap::HealthBitmap::set`] in this crate: `Draining`
//! if draining, else `Unhealthy` if ejected or actively unhealthy, else `Degraded`
//! if ramping, else `Healthy`.
//!
//! # Deferral, not queueing
//!
//! When `max_concurrent` is reached, a due endpoint is rescheduled via
//! `defer_cursor`, a single monotonically increasing cursor that hands out
//! strictly increasing millisecond deadlines to the deferred backlog, and
//! `SchedulerStats::checks_deferred` is incremented. This is NOT "a few
//! milliseconds later": under sustained overload the cursor trails `now` by
//! roughly the size of the backlog deferred within one busy stretch (measured
//! lead up to 193ms at 200 endpoints, up to ~1994ms at 2000, bounded around
//! `2H` ms for `H` endpoints deferred close together), and decays back toward
//! zero once the backlog drains, because a vacated cursor range shrinks at 1ms
//! per ms of real time. It is never pushed into a pending list: a list under
//! sustained overload grows without bound and delivers checks in an order
//! unrelated to their deadlines, while the wheel already is the queue, and
//! rescheduling via the cursor keeps the endpoint's place in time -- this is
//! now genuinely true (issue #862 fixed it): before the monotonic cursor,
//! every endpoint deferred within one poll shared the SAME `now + defer_ms`
//! deadline, which erased their relative order and collapsed the whole
//! backlog onto a single wheel slot that came due, and re-collapsed, forever.
//!
//! At low `max_concurrent` (notably 1), a freshly-reporting endpoint's own
//! plain (not-yet-deferred) dispatch can keep winning the concurrency slot
//! ahead of the deferred backlog for longer than it would starve for under
//! main, even though total wasted work is far lower with the cursor: this is
//! a separate, unrelated starvation route through the plain dispatch branch,
//! tracked in issue #896, and out of scope for the cursor described above.
//! Measured at `max_concurrent = 1`, 100 endpoints, a fully dead upstream,
//! 600 simulated seconds: this scheduler reaches 100/100 coverage at roughly
//! 400s with 600,054 deferred operations, versus main reaching 100/100 at
//! roughly 200s with 11,658,454 deferred -- slower to full coverage by about
//! 2x, but doing about 19x less work to get there. At the scales issue #862
//! itself measures (`max_concurrent` in the tens, thousands of endpoints)
//! this scheduler wins on BOTH axes: at 2000 endpoints / cap 32, 1228 versus
//! 403 covered by 60s and 601,889 versus 231,728,312 deferred over 600s. The
//! cap=1 inversion is therefore recorded here, not treated as a regression to
//! fix: it is the same #896 route, it does not worsen with scale, and fixing
//! it would mean giving the plain dispatch branch cursor-aware ordering too,
//! which issue #862 explicitly scoped out.

use crate::clock::Millis;
use crate::config::ConfigError;
use crate::health::bitmap::{ClusterHealth, EndpointHealth, MAX_ENDPOINTS};
use crate::health::schedule::{
    CheckOutcome, EndpointSchedule, HealthCheckConfig, IntervalState, Transition, phase_ms,
};
use crate::health::wheel::TimerWheel;
use crate::ids::EndpointIdx;
use irontraffic_rand::Rng;

/// Hard ceiling on `max_concurrent`: the number of [`CheckOrder`] values one
/// [`HealthScheduler::poll_due`] call may append to the caller's vector, and
/// therefore the number of simultaneous connections the runner may open. Far past
/// any real deployment; the recommended default is `4 * num_cpus`.
const MAX_CONCURRENT_CHECKS: u32 = 65_536;

/// One check the runner must perform. Carries everything the runner needs; the
/// runner never reads scheduler state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckOrder {
    /// Dense index, used to route the report back.
    pub endpoint: EndpointIdx,
    /// Stable identity. The runner returns it unchanged so a stale report can be
    /// discarded after a membership change.
    pub endpoint_id: u64,
    /// The runner must open a fresh connection rather than reusing a pooled one.
    pub force_reconnect: bool,
    /// Per-check timeout in milliseconds.
    pub timeout_ms: u32,
    /// Absolute time at which the runner must abandon the check and report
    /// `CheckOutcome::Fail(FailKind::Timeout)`.
    pub deadline: Millis,
}

/// The result of one [`CheckOrder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckReport {
    /// Copied from the order.
    pub endpoint: EndpointIdx,
    /// Copied from the order, unchanged.
    pub endpoint_id: u64,
    /// What happened.
    pub outcome: CheckOutcome,
    /// True when this check opened a fresh connection.
    pub reconnected: bool,
}

/// Cumulative scheduler counters. Export every field as a metric.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedulerStats {
    /// Orders emitted.
    pub checks_dispatched: u64,
    /// Reports accepted.
    pub checks_reported: u64,
    /// Times a due endpoint was rescheduled because the concurrency cap was reached.
    pub checks_deferred: u64,
    /// Hysteresis transitions to healthy.
    pub transitions_to_healthy: u64,
    /// Hysteresis transitions to unhealthy.
    pub transitions_to_unhealthy: u64,
    /// Reports discarded because the endpoint id did not match.
    pub reports_for_unknown_endpoint: u64,
    /// Reports discarded because no check was in flight for that endpoint.
    pub reports_without_inflight: u64,
    /// Orders that carried `force_reconnect`.
    pub reconnects_forced: u64,
    /// Wheel sweeps caused by a clock jump.
    pub timer_catchup_clamped: u64,
    /// Endpoints whose dispatched check has been outstanding for longer than
    /// `10 * timeout_ms`. A gauge, not a counter: it rises when a runner loses an
    /// order and falls when the report finally arrives. Above 0 means the runner is
    /// violating its contract to report every order exactly once.
    pub stuck_inflight: u32,
}

/// What one [`HealthScheduler::poll_due`] call did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollStats {
    /// Orders appended to the output vector.
    pub dispatched: u32,
    /// Due endpoints rescheduled because of the concurrency cap or an in-flight
    /// check.
    pub deferred: u32,
    /// True when the wheel performed a catch-up sweep.
    pub swept: bool,
}

/// The one active health checker for one cluster. Owned by the control task; not
/// `Sync`, contains no interior mutability, performs no I/O, reads no clock.
pub struct HealthScheduler {
    /// Wheel keyed by endpoint index.
    wheel: TimerWheel,
    /// Per-endpoint scheduling and hysteresis state, indexed by `EndpointIdx`.
    sched: Vec<EndpointSchedule>,
    /// Stable per-endpoint identity used for the deterministic phase and for
    /// carrying state across a membership change. Indexed by `EndpointIdx`.
    endpoint_ids: Vec<u64>,
    /// Bit per endpoint: a check is dispatched and not yet reported.
    inflight: Vec<bool>,
    /// When each in-flight check was dispatched, for the stuck-check gauge.
    dispatched_at: Vec<Millis>,
    /// Bit per endpoint: already counted in `stuck_inflight`, so the gauge does not
    /// double-count an endpoint that keeps coming due.
    stuck: Vec<bool>,
    /// Bit per endpoint: ejected by outlier detection.
    ejected: Vec<bool>,
    /// Bit per endpoint: ramping after an unejection.
    ramping: Vec<bool>,
    /// Bit per endpoint: graceful drain in progress.
    draining: Vec<bool>,
    cfg: HealthCheckConfig,
    effective_interval_ms: u32,
    max_concurrent: u32,
    inflight_count: u32,
    defer_ms: u32,
    /// Next deadline `poll_due`'s concurrency-cap branch will hand out to a
    /// deferred endpoint. A single scalar, not per-endpoint state: it is what
    /// keeps a whole overloaded backlog from collapsing onto one shared
    /// instant. See `poll_due`'s concurrency-cap branch for how it advances
    /// and resyncs, and `rebuild`'s reset of it to `now` for why a scalar
    /// still needs deliberate handling across a membership change even
    /// though it is not carried per-endpoint.
    defer_cursor: Millis,
    instance_id: u64,
    has_traffic: bool,
    /// Reused between `poll_due` calls so the hot loop allocates nothing.
    due_scratch: Vec<u32>,
    stats: SchedulerStats,
}

/// Returns `Err` naming `cluster.endpoints` when `ids` contains a duplicate, else
/// `Ok(())`. Shared by [`HealthScheduler::new`] and [`HealthScheduler::rebuild`],
/// which must apply the identical admission check.
///
/// Sorts a scratch copy rather than hashing: `O(u log u)`, run once on the control
/// task, and immune to the hash-flooding concern a fast unkeyed hasher would carry
/// for ids derived from discovery-supplied addresses.
fn reject_duplicate_ids(ids: &[u64]) -> Result<(), ConfigError> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    let duplicate = sorted.windows(2).find_map(|w| {
        let (a, b) = (w.first()?, w.get(1)?);
        (a == b).then_some(*a)
    });
    if let Some(d) = duplicate {
        return Err(ConfigError::new(
            "cluster.endpoints",
            &d.to_string(),
            "endpoint ids must be unique",
        ));
    }
    Ok(())
}

/// What [`HealthScheduler::rebuild`] carries forward for one surviving endpoint
/// whose old index was `j` and whose new index is `i`.
struct CarriedEndpointState {
    /// The new `inflight` bit.
    inflight: bool,
    /// The new `dispatched_at` value.
    dispatched_at: Millis,
    /// The new `stuck` bit.
    stuck: bool,
    /// If `true`, the caller must pay back one count of
    /// `SchedulerStats::stuck_inflight`: the bit being reset here had already
    /// raised the gauge and, since `record` will never run for the abandoned
    /// check, nothing else ever will.
    release_stuck_gauge: bool,
    /// The instant at which to arm this endpoint's wheel entry.
    rearm_at: Millis,
}

/// Release `stats.stuck_inflight` for every OLD index whose endpoint was NOT
/// carried into the new membership (removed outright, `old_carried[j] ==
/// false`) but was marked `stuck`.
///
/// An endpoint absent from the new membership is never visited by
/// [`HealthScheduler::rebuild`]'s carry loop at all. If it was `stuck`, that
/// already raised the gauge in `poll_due`, and `record` can never run for an
/// endpoint that no longer exists to pay it back: same leak as the
/// index-move case [`carry_endpoint_state`] closes, reached through the
/// other exit from the loop instead.
fn release_stuck_gauge_for_removed(
    stats: &mut SchedulerStats,
    stuck: &[bool],
    old_carried: &[bool],
) {
    for (j, carried) in old_carried.iter().enumerate() {
        if !carried && stuck.get(j).copied().unwrap_or(false) {
            stats.stuck_inflight = stats.stuck_inflight.saturating_sub(1);
        }
    }
}

/// Compute the carried state for one endpoint surviving a [`HealthScheduler::rebuild`].
///
/// An outstanding `CheckOrder` the runner is holding still names the endpoint's
/// OLD index `j`. When the index has not moved (`index_moved` is `false`), the
/// runner's eventual report still arrives addressed to the right slot and the
/// existing id guard in `record` accepts it normally, so `inflight`,
/// `dispatched_at`, and `stuck` are safe to carry unchanged. When the index HAS
/// moved, that report will be addressed to `j`, which after the rebuild names a
/// different endpoint (or is out of range), so `record` will discard it as
/// `reports_for_unknown_endpoint` and nothing would ever clear an in-flight bit
/// carried forward to `i`: the endpoint would be permanently stuck as "already
/// in flight" and never dispatched again. Reset instead: the endpoint loses at
/// most that one outstanding check.
///
/// Caveat NOT closed by this reset, and tracked in issue #876, not fixed
/// here: the id guard in `record` only rejects a report whose index now
/// names a DIFFERENT endpoint. If a LATER rebuild moves this endpoint back
/// to index `j` before the abandoned report finally arrives, that ancient
/// report is indistinguishable from an honest one addressed to the fresh
/// check now occupying `j`, and `record` will apply it: clearing the fresh
/// check's in-flight bit, feeding a stale outcome into hysteresis, and in
/// the worst case publishing the endpoint unhealthy on the strength of an
/// abandoned check while every real probe passed. Closing that properly
/// needs a generation counter carried alongside `endpoint_id` in
/// `CheckOrder`/`CheckReport`, which is a larger change than this fix should
/// carry.
///
/// The endpoint becomes dispatchable again either on its own normal schedule
/// (`nominal`, already correct when no check was abandoned) or, when the index
/// moved while a check was outstanding, one probe interval from `now`.
/// `advance_nominal` runs only from `record`, which will never run for the
/// check just abandoned, so `nominal` in that case is still the PAST instant
/// the endpoint was last due. Arming the wheel with that stale value would let
/// `TimerWheel::schedule` clamp the negative delta to `now + 1ms`,
/// re-dispatching on the very next tick and bypassing
/// `max_checks_per_endpoint_per_sec` by orders of magnitude against the very
/// upstream a churn-heavy cluster is already stressing.
///
/// `rearm_interval_ms` is the caller's `cfg.interval_for(carried.interval_state)`,
/// i.e. THIS endpoint's own current-state interval (`Down` while unhealthy,
/// `NoTraffic` on a cluster that has never seen a request, and so on), not the
/// flat steady-state interval: a rearm is a substitute for one ordinary probe
/// on this endpoint's own schedule, so it must use the same interval that
/// schedule would have used. Every branch of `HealthCheckConfig::interval_for`
/// is already floored by the per-endpoint rate cap, so this can never breach
/// `max_checks_per_endpoint_per_sec` regardless of which state the endpoint
/// carries.
///
/// This function only computes `rearm_at`, the instant the CALLER must arm the
/// WHEEL entry at; it returns a `CarriedEndpointState` and does not touch
/// `EndpointSchedule` at all. That is deliberate but easy to get half right:
/// [`HealthScheduler::rebuild`] must ALSO copy `rearm_at` into the carried
/// endpoint's `nominal` field before pushing it into the new schedule vector,
/// or the fix only holds for one rebuild. Left unsynced, the very next
/// `rebuild` (even one that does not move this endpoint again, since the
/// `!index_moved` arm above reads the same `nominal`) recomputes `rearm_at`
/// from the still-stale past `nominal`, reproducing the exact clamp-to-`now +
/// 1ms` violation this reset exists to close.
fn carry_endpoint_state(
    index_moved: bool,
    was_inflight: bool,
    was_stuck: bool,
    was_dispatched_at: Millis,
    nominal: Millis,
    rearm_interval_ms: u32,
    now: Millis,
) -> CarriedEndpointState {
    let inflight = !index_moved && was_inflight;
    let dispatched_at = if index_moved {
        Millis(0)
    } else {
        was_dispatched_at
    };
    let rearm_at = if index_moved && was_inflight {
        now.add_ms(rearm_interval_ms)
    } else {
        nominal
    };
    CarriedEndpointState {
        inflight,
        dispatched_at,
        stuck: !index_moved && was_stuck,
        release_stuck_gauge: index_moved && was_stuck,
        rearm_at,
    }
}

impl HealthScheduler {
    /// Build a scheduler for `endpoint_ids`, which are stable per-endpoint
    /// identities (in practice a hash of the endpoint's socket address and
    /// cluster).
    ///
    /// `instance_id` is this process's stable identity, which enters the phase hash
    /// so that two proxies de-synchronize with no coordination.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when `cfg.validate()` fails, when `max_concurrent`
    /// is not in `1..=65536`, when `endpoint_ids` has more than
    /// [`MAX_ENDPOINTS`] entries, or when `endpoint_ids` contains a duplicate.
    pub fn new(
        now: Millis,
        instance_id: u64,
        endpoint_ids: &[u64],
        cfg: HealthCheckConfig,
        max_concurrent: u32,
        has_traffic: bool,
    ) -> Result<Self, ConfigError> {
        cfg.validate()?;
        if max_concurrent == 0 || max_concurrent > MAX_CONCURRENT_CHECKS {
            return Err(ConfigError::new(
                "health_check.max_concurrent_checks",
                &max_concurrent.to_string(),
                "must be in 1..=65536",
            ));
        }
        if endpoint_ids.len() > MAX_ENDPOINTS {
            return Err(ConfigError::new(
                "cluster.endpoints",
                &endpoint_ids.len().to_string(),
                "at most 1048576 endpoints per cluster",
            ));
        }
        reject_duplicate_ids(endpoint_ids)?;

        let (effective_interval_ms, _stretched) = cfg.effective_interval_ms();
        let len = endpoint_ids.len();

        let mut wheel = TimerWheel::new(now, len);
        wheel.set_max_catchup_ms(5_000);

        let mut sched = Vec::with_capacity(len);
        for (i, &id) in endpoint_ids.iter().enumerate() {
            let s = EndpointSchedule::init_with_effective_interval(
                now,
                instance_id,
                id,
                effective_interval_ms,
                has_traffic,
            );
            let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
            if wheel.schedule(i_u32, s.nominal).is_err() {
                // Unreachable given the length check above (`len <=
                // MAX_ENDPOINTS`, which never exceeds the wheel's own
                // ceiling), and `i_u32` is always `< len` so it is never
                // `u32::MAX`. Mapped to a configuration error rather than an
                // `unwrap`, which the workspace lints deny, so a future
                // change to either ceiling fails as a rejected configuration
                // instead of an endpoint that is silently never checked.
                return Err(ConfigError::new(
                    "cluster.endpoints",
                    &endpoint_ids.len().to_string(),
                    "at most 1048576 endpoints per cluster",
                ));
            }
            sched.push(s);
        }

        Ok(Self {
            wheel,
            sched,
            endpoint_ids: endpoint_ids.to_vec(),
            inflight: vec![false; len],
            dispatched_at: vec![Millis(0); len],
            stuck: vec![false; len],
            ejected: vec![false; len],
            ramping: vec![false; len],
            draining: vec![false; len],
            cfg,
            effective_interval_ms,
            max_concurrent,
            inflight_count: 0,
            defer_ms: 5,
            defer_cursor: now,
            instance_id,
            has_traffic,
            due_scratch: Vec::with_capacity(len),
            stats: SchedulerStats::default(),
        })
    }

    /// Advance the wheel to `now` and append every check that must run to `out`.
    ///
    /// `out` is not cleared. Never emits two orders for one endpoint concurrently
    /// from this scheduler's own bookkeeping, and `inflight_count` (see
    /// [`HealthScheduler::inflight`]) never exceeds `max_concurrent`: both are
    /// checked by `debug_assert_consistent`. This is a guarantee about the
    /// scheduler's belief, not about sockets the runner may still be holding: a
    /// [`HealthScheduler::rebuild`] that abandons an in-flight check (its index
    /// moved) frees that check's slot immediately so the endpoint can be
    /// re-dispatched, while the runner may still be holding the abandoned
    /// check's connection open. Real concurrent connections to one endpoint can
    /// therefore briefly reach twice `max_concurrent` across a rebuild; see the
    /// comment in `rebuild` at the `index_moved` reset for why this trade is
    /// accepted over leaving the endpoint permanently stranded.
    pub fn poll_due(
        &mut self,
        now: Millis,
        _rng: &mut Rng,
        out: &mut Vec<CheckOrder>,
    ) -> PollStats {
        self.due_scratch.clear();
        let advance_stats = self.wheel.advance(now, &mut self.due_scratch);
        self.stats.timer_catchup_clamped = self
            .stats
            .timer_catchup_clamped
            .saturating_add(u64::from(advance_stats.swept));

        let cfg = self.cfg;
        let mut dispatched: u32 = 0;
        let mut deferred: u32 = 0;
        let due_len = self.due_scratch.len();

        for i in 0..due_len {
            let Some(id) = self.due_scratch.get(i).copied() else {
                continue;
            };
            let idx = usize::try_from(id).unwrap_or(usize::MAX);
            if idx >= self.sched.len() {
                // A stale wheel entry after a shrink. `rebuild` cancels every
                // out-of-range entry, so this cannot happen; the bound check
                // is free insurance against a future change.
                continue;
            }

            let already_inflight = self.inflight.get(idx).copied().unwrap_or(false);
            if already_inflight {
                let dispatched_at = self.dispatched_at.get(idx).copied().unwrap_or(now);
                let already_stuck = self.stuck.get(idx).copied().unwrap_or(false);
                let stuck_threshold = cfg.timeout_ms.saturating_mul(10);
                if now.since(dispatched_at) > stuck_threshold && !already_stuck {
                    if let Some(s) = self.stuck.get_mut(idx) {
                        *s = true;
                    }
                    self.stats.stuck_inflight = self.stats.stuck_inflight.saturating_add(1);
                }
                let at = now.add_ms(self.defer_ms);
                let _ = self.wheel.schedule(id, at); // it-allow: no-swallowed-error reason: `id` was a live wheel entry the instant before this call (it just fired out of `advance`), so it already names a node below `max_ids`; rescheduling that same id cannot fail.
                deferred = deferred.saturating_add(1);
                continue;
            }

            if self.inflight_count >= self.max_concurrent {
                // A monotonically increasing cursor, not the fixed `now +
                // defer_ms` every concurrency-cap-deferred endpoint used to
                // share: giving the whole backlog one instant collapses it
                // onto a single wheel slot, which then reports as due
                // together on the very next tick and repeats forever (issue
                // #862). Resync when the cursor has fallen behind `now`
                // (idle gap, or the very first deferral ever), then hand out
                // strictly increasing millisecond deadlines so the backlog
                // drains in close to arrival order and can never re-collapse.
                if self.defer_cursor.is_at_or_before(now) {
                    self.defer_cursor = now.add_ms(self.defer_ms);
                }
                let at = self.defer_cursor;
                self.defer_cursor = self.defer_cursor.add_ms(1);
                let _ = self.wheel.schedule(id, at); // it-allow: no-swallowed-error reason: see the identical justification above: `id` is a wheel-native id that just fired, so rescheduling it cannot fail.
                self.stats.checks_deferred = self.stats.checks_deferred.saturating_add(1);
                deferred = deferred.saturating_add(1);
                continue;
            }

            let force = self
                .sched
                .get(idx)
                .is_some_and(|s| s.should_reconnect(&cfg));
            if force {
                self.stats.reconnects_forced = self.stats.reconnects_forced.saturating_add(1);
            }
            if let Some(s) = self.sched.get_mut(idx) {
                s.note_dispatched();
            }
            if let Some(b) = self.inflight.get_mut(idx) {
                *b = true;
            }
            if let Some(d) = self.dispatched_at.get_mut(idx) {
                *d = now;
            }
            if let Some(s) = self.stuck.get_mut(idx) {
                *s = false;
            }
            self.inflight_count = self.inflight_count.saturating_add(1);
            self.stats.checks_dispatched = self.stats.checks_dispatched.saturating_add(1);

            let endpoint_id = self.endpoint_ids.get(idx).copied().unwrap_or(0);
            let timeout_ms = cfg.timeout_ms;
            out.push(CheckOrder {
                endpoint: EndpointIdx(id),
                endpoint_id,
                force_reconnect: force,
                timeout_ms,
                deadline: now.add_ms(timeout_ms),
            });

            // The watchdog, not the next real check: `record` arms the real
            // next deadline, measured from completion. Without this, an
            // endpoint whose report never arrives would be absent from the
            // wheel forever and never checked again.
            let watchdog_at = now.add_ms(timeout_ms).add_ms(self.defer_ms);
            let _ = self.wheel.schedule(id, watchdog_at); // it-allow: no-swallowed-error reason: `id` is the wheel entry that just fired out of `advance` above, so it already names a node below `max_ids`; scheduling it again cannot fail.

            dispatched = dispatched.saturating_add(1);
        }

        PollStats {
            dispatched,
            deferred,
            swept: advance_stats.swept,
        }
    }

    /// Apply one report: update hysteresis, reschedule, and publish.
    ///
    /// Returns `None` when the report is discarded (unknown endpoint id, or no
    /// check in flight), else the hysteresis transition.
    pub fn record(
        &mut self,
        now: Millis,
        report: CheckReport,
        rng: &mut Rng,
        health: &ClusterHealth,
    ) -> Option<Transition> {
        let idx = usize::try_from(report.endpoint.0).unwrap_or(usize::MAX);
        let id_matches = self.endpoint_ids.get(idx).copied() == Some(report.endpoint_id);
        if idx >= self.sched.len() || !id_matches {
            self.stats.reports_for_unknown_endpoint =
                self.stats.reports_for_unknown_endpoint.saturating_add(1);
            return None;
        }
        if !self.inflight.get(idx).copied().unwrap_or(false) {
            self.stats.reports_without_inflight =
                self.stats.reports_without_inflight.saturating_add(1);
            return None;
        }

        if let Some(f) = self.inflight.get_mut(idx) {
            *f = false;
        }
        self.inflight_count = self.inflight_count.saturating_sub(1);
        self.stats.checks_reported = self.stats.checks_reported.saturating_add(1);
        if self.stuck.get(idx).copied().unwrap_or(false) {
            if let Some(s) = self.stuck.get_mut(idx) {
                *s = false;
            }
            self.stats.stuck_inflight = self.stats.stuck_inflight.saturating_sub(1);
        }

        let cfg = self.cfg;
        if report.reconnected
            && let Some(s) = self.sched.get_mut(idx)
        {
            s.note_reconnected();
        }
        let transition = self
            .sched
            .get_mut(idx)
            .map_or(Transition::None, |s| s.apply_outcome(report.outcome, &cfg));
        match transition {
            Transition::ToHealthy => {
                self.stats.transitions_to_healthy =
                    self.stats.transitions_to_healthy.saturating_add(1);
            }
            Transition::ToUnhealthy => {
                self.stats.transitions_to_unhealthy =
                    self.stats.transitions_to_unhealthy.saturating_add(1);
            }
            Transition::None => {}
        }
        if let Some(s) = self.sched.get_mut(idx) {
            s.advance_nominal(now, &cfg);
        }
        let at = self.sched.get(idx).map_or_else(
            || now.add_ms(self.effective_interval_ms),
            |s| s.fire_at(now, &cfg, rng),
        );
        let idx_u32 = u32::try_from(idx).unwrap_or(u32::MAX);
        if self.wheel.schedule(idx_u32, at).is_err() {
            // `WheelError::IdTooLarge` requires `idx_u32 == u32::MAX`, which
            // cannot happen for an `idx` bounded by `self.sched.len()` above;
            // `WheelError::IdOutOfRange` requires the wheel's `max_ids` to
            // have been lowered below `idx`, which this crate never does.
            // Both are therefore unreachable, but a fallback reschedule is
            // cheap insurance: an endpoint that is neither in flight nor in
            // the wheel would otherwise never be checked again.
            let eff = self.effective_interval_ms;
            let _ = self.wheel.schedule(idx_u32, now.add_ms(eff)); // it-allow: no-swallowed-error reason: idx_u32 is bounded by self.sched.len(), which never exceeds the wheel's fixed max_ids ceiling, so this fallback call cannot itself fail either; it exists only so a future change to that ceiling fails safe.
        }

        self.publish(report.endpoint, health);
        Some(transition)
    }

    /// Resolve the four independent health signals into one published state and
    /// write it through `health.bitmap`. The only call site of
    /// `HealthBitmap::set` in this crate.
    fn publish(&self, idx: EndpointIdx, health: &ClusterHealth) {
        let i = usize::try_from(idx.0).unwrap_or(usize::MAX);
        let Some(sched) = self.sched.get(i) else {
            return;
        };
        let draining = self.draining.get(i).copied().unwrap_or(false);
        let ejected = self.ejected.get(i).copied().unwrap_or(false);
        let ramping = self.ramping.get(i).copied().unwrap_or(false);
        let state = if draining {
            EndpointHealth::Draining
        } else if ejected || sched.active_health == EndpointHealth::Unhealthy {
            EndpointHealth::Unhealthy
        } else if ramping {
            EndpointHealth::Degraded
        } else {
            EndpointHealth::Healthy
        };
        let _ = health.bitmap.set(idx, state); // it-allow: no-swallowed-error reason: a false return only means `idx` is out of range for `health`, which is a caller bug (edge case 20); `publish` deliberately does not panic on it, and `publish_all`'s debug assertion is what catches a length mismatch in tests.
    }

    /// Set or clear the outlier-ejection flag and republish.
    ///
    /// Called by `outlier-ejection-and-safety-valves` (#98), never by the runner.
    pub fn set_ejected(&mut self, idx: EndpointIdx, ejected: bool, health: &ClusterHealth) {
        let i = usize::try_from(idx.0).unwrap_or(usize::MAX);
        if let Some(e) = self.ejected.get_mut(i) {
            *e = ejected;
        }
        self.publish(idx, health);
    }

    /// Set or clear the unejection-ramp flag and republish. A ramping endpoint
    /// publishes as `Degraded`.
    pub fn set_ramping(&mut self, idx: EndpointIdx, ramping: bool, health: &ClusterHealth) {
        let i = usize::try_from(idx.0).unwrap_or(usize::MAX);
        if let Some(r) = self.ramping.get_mut(i) {
            *r = ramping;
        }
        self.publish(idx, health);
    }

    /// Set or clear the graceful-drain flag and republish. Draining outranks every
    /// other signal.
    pub fn set_draining(&mut self, idx: EndpointIdx, draining: bool, health: &ClusterHealth) {
        let i = usize::try_from(idx.0).unwrap_or(usize::MAX);
        if let Some(d) = self.draining.get_mut(i) {
            *d = draining;
        }
        self.publish(idx, health);
    }

    /// Switch the whole cluster between the traffic and no-traffic schedules.
    ///
    /// A no-op when `has_traffic` already matches the scheduler's own flag.
    /// Otherwise every endpoint that is not in flight is re-based on `now` plus its
    /// own phase and rescheduled, so the new interval takes effect immediately
    /// without collapsing the whole cluster onto one instant.
    pub fn set_has_traffic(&mut self, has_traffic: bool, now: Millis, rng: &mut Rng) {
        if has_traffic == self.has_traffic {
            return;
        }
        self.has_traffic = has_traffic;

        let new_state = if has_traffic {
            IntervalState::Edge
        } else {
            IntervalState::NoTraffic
        };
        let cfg = self.cfg;
        let iv = cfg.interval_for(new_state);
        let instance_id = self.instance_id;

        for i in 0..self.sched.len() {
            if let Some(s) = self.sched.get_mut(i) {
                s.set_has_traffic(has_traffic);
            }
            if self.inflight.get(i).copied().unwrap_or(false) {
                // A watchdog is armed; `record` will apply the new interval
                // when the outstanding check completes.
                continue;
            }
            let endpoint_id = self.endpoint_ids.get(i).copied().unwrap_or(0);
            let phase = phase_ms(instance_id, endpoint_id, iv);
            let nominal = now.add_ms(phase);
            if let Some(s) = self.sched.get_mut(i) {
                s.nominal = nominal;
            }
            let fire_at = self
                .sched
                .get(i)
                .map_or_else(|| now.add_ms(iv), |s| s.fire_at(now, &cfg, rng));
            let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
            let _ = self.wheel.schedule(i_u32, fire_at); // it-allow: no-swallowed-error reason: i is a valid, already-scheduled index bounded by self.sched.len(), which never exceeds the wheel's fixed max_ids ceiling, so neither WheelError variant is reachable here.
        }
    }

    /// Milliseconds a due-but-undispatchable endpoint is pushed out by, for the
    /// already-in-flight branch and for the first entry into the
    /// concurrency-cap deferred backlog after `defer_cursor` resyncs (an idle
    /// gap, or the very first deferral ever). Default 5. CLAMPED to
    /// `1..=60_000`. Control task only.
    ///
    /// This is NOT the retry distance for most concurrency-cap deferrals:
    /// `poll_due`'s monotonic `defer_cursor` hands out one strictly
    /// increasing millisecond deadline per endpoint deferred, so under a
    /// sustained backlog the LAST endpoint deferred in a busy stretch trails
    /// `now` by roughly the backlog size in milliseconds, not by `defer_ms`
    /// (measured up to ~193ms at 200 endpoints, ~1994ms at 2000). See the
    /// module doc's "Deferral, not queueing" section.
    ///
    /// The lower clamp stops a value of 0 from making deferral a busy loop that
    /// re-examines every deferred endpoint on every poll. The upper clamp stops a
    /// mistaken or hostile configuration from pushing a deferred endpoint 49 days
    /// into the future, which would silently stop checking every endpoint that was
    /// ever deferred while leaving the scheduler looking healthy.
    pub fn set_defer_ms(&mut self, ms: u32) {
        self.defer_ms = ms.clamp(1, 60_000);
    }

    /// Forward to `TimerWheel::set_max_catchup_ms` on the scheduler's wheel.
    /// Default 5000. CLAMPED to `1..=60_000` before forwarding. Control task only.
    ///
    /// The clamp is the whole reason this wrapper exists rather than exposing the
    /// wheel's setter directly: the wheel ticks once per millisecond of gap up to
    /// this value, so an unclamped value turns the next VM migration or suspend
    /// into a loop of that many iterations on the control task.
    pub fn set_max_catchup_ms(&mut self, ms: u32) {
        self.wheel.set_max_catchup_ms(ms.clamp(1, 60_000));
    }

    /// Republish every endpoint into `health`. Call after constructing a new
    /// `ClusterHealth` following a membership change.
    pub fn publish_all(&self, health: &ClusterHealth) {
        debug_assert_eq!(
            health.len(),
            self.sched.len(),
            "ClusterHealth length must match the scheduler's endpoint count"
        );
        for i in 0..self.sched.len() {
            let id = u32::try_from(i).unwrap_or(u32::MAX);
            self.publish(EndpointIdx(id), health);
        }
    }

    /// Apply a membership change, carrying scheduling, ejection, ramp, drain, and
    /// in-flight state for endpoints whose id is unchanged.
    ///
    /// Rebuilding `ClusterHealth` is NOT this function's job: the caller
    /// constructs a new `ClusterHealth` sized to `endpoint_ids.len()` and calls
    /// [`HealthScheduler::publish_all`] on it afterward, which keeps the ordering
    /// explicit and prevents publishing into a stale bitmap.
    ///
    /// An endpoint whose index moves while it has a check outstanding has that
    /// check abandoned, not carried: see [`carry_endpoint_state`]'s doc comment
    /// for why, and for the ABA caveat (tracked in issue #876) that reset does
    /// NOT close.
    ///
    /// # Errors
    /// Returns [`ConfigError`] naming `cluster.endpoints` when `endpoint_ids` has
    /// more than [`MAX_ENDPOINTS`] entries, or contains a duplicate. Applies the
    /// same two checks [`HealthScheduler::new`] applies, in the same order,
    /// because a membership update arrives from discovery on every pod churn and
    /// must not be the lenient path.
    #[allow(
        clippy::too_many_lines,
        reason = "one loop admitting every new endpoint, carried or fresh, into seven parallel \
                  vectors that must stay in lockstep by construction; splitting the carried and \
                  fresh arms into separate functions would let a future edit push into those \
                  vectors out of order across two call sites instead of one, which is a sharper \
                  hazard than the line count for a function three consecutive review rounds have \
                  already found defects in"
    )]
    pub fn rebuild(
        &mut self,
        now: Millis,
        endpoint_ids: &[u64],
        _rng: &mut Rng,
    ) -> Result<(), ConfigError> {
        if endpoint_ids.len() > MAX_ENDPOINTS {
            return Err(ConfigError::new(
                "cluster.endpoints",
                &endpoint_ids.len().to_string(),
                "at most 1048576 endpoints per cluster",
            ));
        }
        reject_duplicate_ids(endpoint_ids)?;

        let old_len = self.sched.len();
        let mut old: std::collections::HashMap<u64, usize> =
            std::collections::HashMap::with_capacity(old_len);
        for (j, &id) in self.endpoint_ids.iter().enumerate() {
            old.insert(id, j);
        }

        let new_len = endpoint_ids.len();
        let mut new_sched = Vec::with_capacity(new_len);
        let mut new_ids = Vec::with_capacity(new_len);
        let mut new_ejected = Vec::with_capacity(new_len);
        let mut new_ramping = Vec::with_capacity(new_len);
        let mut new_draining = Vec::with_capacity(new_len);
        let mut new_inflight = Vec::with_capacity(new_len);
        let mut new_dispatched_at = Vec::with_capacity(new_len);
        let mut new_stuck = Vec::with_capacity(new_len);
        let mut inflight_count: u32 = 0;

        let instance_id = self.instance_id;
        let effective_interval_ms = self.effective_interval_ms;
        let has_traffic = self.has_traffic;
        let mut old_carried = vec![false; old_len];

        for (i, &id) in endpoint_ids.iter().enumerate() {
            new_ids.push(id);
            let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
            if let Some(&j) = old.get(&id) {
                if let Some(c) = old_carried.get_mut(j) {
                    *c = true;
                }
                let mut carried = self.sched.get(j).copied().unwrap_or_else(|| {
                    EndpointSchedule::init_with_effective_interval(
                        now,
                        instance_id,
                        id,
                        effective_interval_ms,
                        has_traffic,
                    )
                });
                new_ejected.push(self.ejected.get(j).copied().unwrap_or(false));
                new_ramping.push(self.ramping.get(j).copied().unwrap_or(false));
                new_draining.push(self.draining.get(j).copied().unwrap_or(false));
                // See `carry_endpoint_state`'s doc comment: why the check is
                // abandoned, the ABA caveat (#876) left open, and why the
                // rearm interval is the endpoint's OWN `interval_state`.
                let state = carry_endpoint_state(
                    i != j,
                    self.inflight.get(j).copied().unwrap_or(false),
                    self.stuck.get(j).copied().unwrap_or(false),
                    self.dispatched_at.get(j).copied().unwrap_or(Millis(0)),
                    carried.nominal,
                    self.cfg.interval_for(carried.interval_state),
                    now,
                );
                new_inflight.push(state.inflight);
                new_dispatched_at.push(state.dispatched_at);
                new_stuck.push(state.stuck);
                if state.release_stuck_gauge {
                    self.stats.stuck_inflight = self.stats.stuck_inflight.saturating_sub(1);
                }
                if state.inflight {
                    inflight_count = inflight_count.saturating_add(1);
                }
                let _ = self.wheel.schedule(i_u32, state.rearm_at); // it-allow: no-swallowed-error reason: i is bounded by new_len <= MAX_ENDPOINTS, which never exceeds the wheel's fixed max_ids ceiling, so neither WheelError variant is reachable here.
                // Keep `nominal` in step with the wheel entry just armed
                // (a no-op when it already matches), or the NEXT rebuild
                // re-derives `rearm_at` from a stale past `nominal`.
                carried.nominal = state.rearm_at;
                new_sched.push(carried);
            } else {
                let fresh = EndpointSchedule::init_with_effective_interval(
                    now,
                    instance_id,
                    id,
                    effective_interval_ms,
                    has_traffic,
                );
                new_ejected.push(false);
                new_ramping.push(false);
                new_draining.push(false);
                new_inflight.push(false);
                new_dispatched_at.push(Millis(0));
                new_stuck.push(false);
                let _ = self.wheel.schedule(i_u32, fresh.nominal); // it-allow: no-swallowed-error reason: identical justification to the carried-endpoint branch above.
                new_sched.push(fresh);
            }
        }

        for i in new_len..old_len {
            let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
            self.wheel.cancel(i_u32);
        }

        // See `release_stuck_gauge_for_removed`'s doc comment: an endpoint
        // removed outright is never visited by the loop above.
        release_stuck_gauge_for_removed(&mut self.stats, &self.stuck, &old_carried);

        self.sched = new_sched;
        self.endpoint_ids = new_ids;
        self.ejected = new_ejected;
        self.ramping = new_ramping;
        self.draining = new_draining;
        self.inflight = new_inflight;
        self.dispatched_at = new_dispatched_at;
        self.stuck = new_stuck;
        self.inflight_count = inflight_count;

        // `defer_cursor` is a scalar, not per-endpoint state, so it is not
        // carried above with the rest of a surviving endpoint's row: it is
        // reset to `now` here instead. Without this, a membership shrink
        // leaves survivors that were over the concurrency cap anchored to
        // the departed backlog's cursor lead (measured now+1994/now+1995ms
        // after a 2000-endpoint shrink to 4, versus now+5/now+5 with this
        // reset) even though the new, smaller membership may no longer be
        // anywhere near the cap. The reset cannot collide with a live
        // cursor-allocated deadline: every carried endpoint was just
        // re-armed in the wheel above via `state.rearm_at` (or, for a fresh
        // endpoint, its own `nominal`), and `TimerWheel::schedule` clamps
        // any deadline at or before `now` forward to `now + 1`, so no
        // cursor-derived deadline from before this call can still be
        // pending when `poll_due` next reads `defer_cursor`.
        self.defer_cursor = now;

        Ok(())
    }

    /// Number of endpoints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sched.len()
    }

    /// True when the cluster has no endpoints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sched.is_empty()
    }

    /// Checks currently dispatched and not yet reported.
    #[must_use]
    pub fn inflight(&self) -> u32 {
        self.inflight_count
    }

    /// Cumulative counters.
    #[must_use]
    pub fn stats(&self) -> SchedulerStats {
        self.stats
    }

    /// What active checking currently believes about one endpoint.
    #[must_use]
    pub fn active_health(&self, idx: EndpointIdx) -> Option<EndpointHealth> {
        let i = usize::try_from(idx.0).unwrap_or(usize::MAX);
        self.sched.get(i).map(|s| s.active_health)
    }

    /// Debug-only check of invariants 1, 2, 4, and 7. Compiled out in release.
    #[cfg(debug_assertions)]
    pub fn debug_assert_consistent(&self) {
        let counted = self.inflight.iter().filter(|b| **b).count();
        let counted_u32 = u32::try_from(counted).unwrap_or(u32::MAX);
        debug_assert_eq!(
            self.inflight_count, counted_u32,
            "invariant 1: inflight_count must equal the number of true entries in `inflight`"
        );
        debug_assert!(
            self.inflight_count <= self.max_concurrent,
            "invariant 2: inflight_count must never exceed max_concurrent"
        );
        let len = self.sched.len();
        debug_assert_eq!(
            len,
            self.endpoint_ids.len(),
            "invariant 7: endpoint_ids length mismatch"
        );
        debug_assert_eq!(
            len,
            self.inflight.len(),
            "invariant 7: inflight length mismatch"
        );
        debug_assert_eq!(
            len,
            self.dispatched_at.len(),
            "invariant 7: dispatched_at length mismatch"
        );
        debug_assert_eq!(len, self.stuck.len(), "invariant 7: stuck length mismatch");
        debug_assert_eq!(
            len,
            self.ejected.len(),
            "invariant 7: ejected length mismatch"
        );
        debug_assert_eq!(
            len,
            self.ramping.len(),
            "invariant 7: ramping length mismatch"
        );
        debug_assert_eq!(
            len,
            self.draining.len(),
            "invariant 7: draining length mismatch"
        );
        for i in 0..len {
            let id = u32::try_from(i).unwrap_or(u32::MAX);
            debug_assert!(
                self.wheel.deadline_of(id).is_some(),
                "invariant 4: every endpoint must always be scheduled in the wheel"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::health::schedule::FailKind;

    fn idx_of(e: EndpointIdx) -> usize {
        usize::try_from(e.0).unwrap_or(usize::MAX)
    }

    /// Like `Result::unwrap_err`, but usable on `Result<HealthScheduler, _>`:
    /// `HealthScheduler` deliberately does not implement `Debug` (it holds a
    /// `TimerWheel`, which does not either, per the wheel's own "owned by one
    /// control task" design), so the standard `unwrap_err` cannot be called on
    /// it. This only ever inspects the `Err` side.
    fn expect_config_err(r: Result<HealthScheduler, ConfigError>) -> ConfigError {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected an error, got a valid HealthScheduler"),
        }
    }

    /// All-zero-phase config from the issue: with `max_checks_per_endpoint_per_sec
    /// = 1000` the effective interval floors to 1 ms for every state, and
    /// `phase_ms(.., .., 1)` is 0 for every endpoint, so with `jitter_bp = 0`
    /// every endpoint's nominal AND fire time equal `t0` exactly. Reused by tests
    /// 5, 6, and 20.
    fn all_due_cfg() -> HealthCheckConfig {
        HealthCheckConfig {
            interval_ms: 1,
            edge_interval_ms: 1,
            unhealthy_interval_ms: 1,
            no_traffic_interval_ms: 1,
            timeout_ms: 1,
            jitter_bp: 0,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            reconnect_every: 0,
            max_checks_per_endpoint_per_sec: 1000,
        }
    }

    #[test]
    fn new_schedules_every_endpoint() {
        let cfg = HealthCheckConfig::default();
        let (eff, _) = cfg.effective_interval_ms();
        let now = Millis(1_000);
        let ids: Vec<u64> = (0..10).collect();
        let sched = HealthScheduler::new(now, 1, &ids, cfg, 4, true).expect("valid config");
        for i in 0..10u32 {
            let deadline = sched
                .wheel
                .deadline_of(i)
                .expect("every endpoint scheduled");
            let delta = deadline.since(now);
            assert!(
                delta < eff,
                "endpoint {i} deadline delta {delta} not within [0, {eff})"
            );
        }
        assert_eq!(sched.inflight(), 0);
        sched.debug_assert_consistent();
    }

    #[test]
    fn new_rejects_zero_concurrency() {
        let cfg = HealthCheckConfig::default();
        let ids = vec![1u64, 2u64, 3u64];
        let err = expect_config_err(HealthScheduler::new(Millis(0), 1, &ids, cfg, 0, true));
        assert_eq!(err.field, "health_check.max_concurrent_checks");
    }

    #[test]
    fn new_rejects_duplicate_ids() {
        let cfg = HealthCheckConfig::default();
        let ids = vec![7u64, 7u64];
        let err = expect_config_err(HealthScheduler::new(Millis(0), 1, &ids, cfg, 4, true));
        assert_eq!(err.field, "cluster.endpoints");
    }

    #[test]
    fn poll_due_dispatches_at_deadline() {
        let cfg = HealthCheckConfig::default();
        let now = Millis(0);
        let ids = vec![42u64];
        let mut sched = HealthScheduler::new(now, 1, &ids, cfg, 4, true).expect("valid");
        let deadline = sched.wheel.deadline_of(0).expect("scheduled");
        let mut rng = Rng::from_seed(1);
        let mut out = Vec::new();

        let delta = deadline.since(now);
        let just_before = now.add_ms(delta - 1);
        let stats1 = sched.poll_due(just_before, &mut rng, &mut out);
        assert!(out.is_empty());
        assert_eq!(stats1.dispatched, 0);

        let stats2 = sched.poll_due(deadline, &mut rng, &mut out);
        assert_eq!(out.len(), 1);
        let order = out.first().copied().expect("one order");
        assert_eq!(order.endpoint_id, 42);
        assert_eq!(order.timeout_ms, cfg.timeout_ms);
        assert_eq!(order.deadline, deadline.add_ms(cfg.timeout_ms));
        assert_eq!(stats2.dispatched, 1);
        sched.debug_assert_consistent();
    }

    #[test]
    fn poll_due_respects_concurrency_cap() {
        let cfg = all_due_cfg();
        let t0 = Millis(0);
        let ids: Vec<u64> = (0..100).collect();
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 8, true).expect("valid");
        sched.debug_assert_consistent();
        let mut rng = Rng::from_seed(2);
        let mut out = Vec::new();
        let poll_stats = sched.poll_due(t0.add_ms(1), &mut rng, &mut out);
        sched.debug_assert_consistent();
        assert_eq!(out.len(), 8);
        assert_eq!(poll_stats.dispatched, 8);
        assert_eq!(poll_stats.deferred, 92);
        assert_eq!(sched.stats().checks_deferred, 92);
    }

    #[test]
    fn deferred_endpoints_come_back() {
        let cfg = all_due_cfg();
        let t0 = Millis(0);
        let ids: Vec<u64> = (0..100).collect();
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 8, true).expect("valid");
        let mut rng = Rng::from_seed(3);
        let health = ClusterHealth::new(100, 0);
        let mut out = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();

        // Phase 1: the issue's literal recipe, reproducing test 5 and then
        // reporting the whole first batch synchronously before advancing by
        // exactly `defer_ms` (5), which proves the immediate "another 8 (or
        // more, as reports free slots)" claim.
        let mut now = t0.add_ms(1);
        let first = sched.poll_due(now, &mut rng, &mut out);
        assert_eq!(
            first.dispatched, 8,
            "first poll must dispatch exactly max_concurrent"
        );
        sched.debug_assert_consistent();
        for order in out.drain(..) {
            seen.insert(order.endpoint_id);
            let report = CheckReport {
                endpoint: order.endpoint,
                endpoint_id: order.endpoint_id,
                outcome: CheckOutcome::Pass,
                reconnected: false,
            };
            sched.record(now, report, &mut rng, &health);
        }
        sched.debug_assert_consistent();
        now = now.add_ms(5);
        let second = sched.poll_due(now, &mut rng, &mut out);
        assert!(
            second.dispatched >= 8,
            "expected the freed slots plus the deferred backlog to dispatch at least 8, got {}",
            second.dispatched
        );
        sched.debug_assert_consistent();

        // Phase 2: the no-starvation property. Continuing in perfect lockstep
        // (every batch reported at the same instant, with the same latency
        // for every member) locks a large batch into a stable cycle between
        // two fixed 8-endpoint groups forever, because the wheel's
        // LIFO-per-slot linking exactly reproduces the same partition every
        // round: a batch deferred together keeps its relative order, and a
        // fixed report cadence keeps recreating the identical split (see the
        // filed defect against this issue for the full trace, which also
        // found that even independently-drawn per-order latencies converge
        // far slower than the issue's "over 20 rounds" framing implies,
        // needing on the order of 3000 simulated ms rather than a few dozen).
        // A real runner's checks do not complete in lockstep, so from here on
        // each dispatched order is given its own, independently drawn
        // completion latency and the simulation runs long enough (with wide
        // margin above the measured convergence point) for every endpoint to
        // surface at least once, which is the property this test actually
        // needs to prove.
        let mut pending: Vec<(Millis, CheckReport)> = Vec::new();
        for order in out.drain(..) {
            seen.insert(order.endpoint_id);
            let latency = 1 + rng.bounded_u32(8);
            pending.push((
                now.add_ms(latency),
                CheckReport {
                    endpoint: order.endpoint,
                    endpoint_id: order.endpoint_id,
                    outcome: CheckOutcome::Pass,
                    reconnected: false,
                },
            ));
        }
        for step in 1..8_000u32 {
            let step_now = now.add_ms(step);
            let mut still_pending = Vec::new();
            for (fire_at, report) in pending.drain(..) {
                if fire_at.is_at_or_before(step_now) {
                    sched.record(step_now, report, &mut rng, &health);
                } else {
                    still_pending.push((fire_at, report));
                }
            }
            pending = still_pending;
            sched.debug_assert_consistent();

            sched.poll_due(step_now, &mut rng, &mut out);
            for order in out.drain(..) {
                seen.insert(order.endpoint_id);
                let latency = 1 + rng.bounded_u32(8);
                pending.push((
                    step_now.add_ms(latency),
                    CheckReport {
                        endpoint: order.endpoint,
                        endpoint_id: order.endpoint_id,
                        outcome: CheckOutcome::Pass,
                        reconnected: false,
                    },
                ));
            }
            sched.debug_assert_consistent();
        }

        assert_eq!(
            seen.len(),
            100,
            "every endpoint must be dispatched at least once as the backlog drains"
        );
    }

    #[test]
    fn no_two_checks_in_flight_per_endpoint() {
        let cfg = HealthCheckConfig::default();
        let (eff, _) = cfg.effective_interval_ms();
        let t0 = Millis(0);
        let ids = vec![9u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let mut rng = Rng::from_seed(4);
        let mut out = Vec::new();
        let deadline = sched.wheel.deadline_of(0).expect("scheduled");
        let stats1 = sched.poll_due(deadline, &mut rng, &mut out);
        assert_eq!(stats1.dispatched, 1);
        assert_eq!(sched.inflight(), 1);
        out.clear();

        let later = deadline.add_ms(eff);
        let stats2 = sched.poll_due(later, &mut rng, &mut out);
        assert!(
            out.is_empty(),
            "an in-flight endpoint must not get a second order"
        );
        assert!(stats2.deferred >= 1);
        sched.debug_assert_consistent();
    }

    // Not one of the 23 named tests, but the property the design's edge case
    // 6 depends on: added because `cargo mutants` (see the report for the
    // `-j 1` table) found that no test in this file actually exercised
    // `poll_due`'s stuck-check branch, so five independent mutations of its
    // condition all survived.
    #[test]
    fn stuck_inflight_gauge_rises_and_does_not_double_count() {
        let cfg = HealthCheckConfig {
            timeout_ms: 100,
            ..HealthCheckConfig::default()
        };
        let t0 = Millis(0);
        let ids = vec![1u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        sched.debug_assert_consistent();
        let mut rng = Rng::from_seed(20);
        let mut out = Vec::new();

        let dispatch_deadline = sched.wheel.deadline_of(0).expect("scheduled");
        let stats = sched.poll_due(dispatch_deadline, &mut rng, &mut out);
        assert_eq!(stats.dispatched, 1);
        sched.debug_assert_consistent();
        assert_eq!(sched.stats().stuck_inflight, 0);
        out.clear();

        // The report never arrives. The endpoint keeps coming due (rescheduled
        // `defer_ms` = 5 ms later each time by the in-flight branch, far
        // finer than this loop's 50 ms polling step, so every step re-examines
        // it) without a second order. The stuck threshold is
        // `10 * timeout_ms` = 1000 ms here, and the loop's step size (50)
        // divides it exactly, landing one step exactly ON the boundary
        // (since == 1000) and the next exactly past it (since == 1050): this
        // is what actually distinguishes the correct `since > threshold` from
        // an off-by-one `==` or `>=` (which would flip a step early, at
        // since == 1000), and separately distinguishes it from an eager `<`
        // or `||` (which would flip on the very first examination, long
        // before the threshold). Asserting "eventually 1" alone cannot tell
        // any of those apart from the correct behaviour; asserting the exact
        // step of the flip can.
        for step in 1..=25u32 {
            let now = dispatch_deadline.add_ms(step * 50);
            out.clear();
            let poll_stats = sched.poll_due(now, &mut rng, &mut out);
            assert!(
                out.is_empty(),
                "an in-flight endpoint must never get a second order"
            );
            assert_eq!(poll_stats.dispatched, 0);
            sched.debug_assert_consistent();
            let since = now.since(dispatch_deadline);
            if since <= 1000 {
                assert_eq!(
                    sched.stats().stuck_inflight,
                    0,
                    "must not be stuck yet at since={since} (<= 10 * timeout_ms)"
                );
            } else {
                assert_eq!(
                    sched.stats().stuck_inflight,
                    1,
                    "must be stuck once since={since} exceeds 10 * timeout_ms"
                );
            }
        }

        // Does not double count on a further poll while still stuck.
        let now = dispatch_deadline.add_ms(26 * 50);
        out.clear();
        sched.poll_due(now, &mut rng, &mut out);
        assert_eq!(
            sched.stats().stuck_inflight,
            1,
            "the gauge must not double count an endpoint that keeps coming due"
        );
        sched.debug_assert_consistent();
    }

    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        reason = "test arithmetic mirrors bounded production formulas"
    )]
    #[test]
    fn record_reschedules_from_completion() {
        let cfg = HealthCheckConfig {
            interval_ms: 2000,
            ..HealthCheckConfig::default()
        };
        let t0 = Millis(0);
        let ids = vec![5u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let mut rng = Rng::from_seed(5);
        let mut out = Vec::new();
        let dispatch_deadline = sched.wheel.deadline_of(0).expect("scheduled");
        sched.poll_due(dispatch_deadline, &mut rng, &mut out);
        let order = out.first().copied().expect("one order");

        let report_time = dispatch_deadline.add_ms(300);
        let health = ClusterHealth::new(1, 0);
        let report = CheckReport {
            endpoint: order.endpoint,
            endpoint_id: order.endpoint_id,
            outcome: CheckOutcome::Pass,
            reconnected: false,
        };
        sched.record(report_time, report, &mut rng, &health);

        let new_deadline = sched.wheel.deadline_of(0).expect("rescheduled");
        let (eff, _) = cfg.effective_interval_ms();
        let span = (u64::from(eff) * u64::from(cfg.jitter_bp) / 10_000) as u32;
        // See the filed defect against this issue's own description of this
        // test, which asserts a window around `report_time + eff`
        // (`t + 2300`). `EndpointSchedule::advance_nominal`
        // (health-check-scheduling-policy, #92, unchanged by this issue)
        // advances the endpoint's fixed periodic `nominal` by one interval and
        // re-bases onto `now` only when the schedule has fallen more than a
        // full interval behind (`nominal + iv <= now`); a 300 ms latency
        // against a 2000 ms interval never satisfies that, so the correct,
        // provable result is `dispatch_deadline + eff`, deterministically 300
        // ms earlier than the issue's stated window, for any dispatch time.
        let expected = dispatch_deadline.add_ms(eff);
        let diff = new_deadline.0.abs_diff(expected.0);
        assert!(
            diff <= span,
            "deadline {new_deadline:?} not within jitter span {span} of {expected:?}"
        );
        // The property this test's name actually promises, still verified:
        // `record`, not the watchdog armed at dispatch, is what produced this
        // deadline. The watchdog would have landed at
        // `dispatch_deadline + timeout_ms + defer_ms`, far short of a full
        // interval away.
        let watchdog_would_be = dispatch_deadline.add_ms(cfg.timeout_ms).add_ms(5);
        assert_ne!(
            new_deadline, watchdog_would_be,
            "the wheel entry must be the real reschedule from record, not the leftover watchdog"
        );
        sched.debug_assert_consistent();
    }

    #[test]
    fn record_applies_hysteresis() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let mut rng = Rng::from_seed(6);
        let health = ClusterHealth::new(1, 0);
        let mut out = Vec::new();

        let mut results = Vec::new();
        for _ in 0..3 {
            let deadline = sched.wheel.deadline_of(0).expect("scheduled");
            sched.poll_due(deadline, &mut rng, &mut out);
            let order = out.drain(..).next().expect("one order");
            let report = CheckReport {
                endpoint: order.endpoint,
                endpoint_id: order.endpoint_id,
                outcome: CheckOutcome::Fail(FailKind::Status),
                reconnected: false,
            };
            let t = sched.record(deadline, report, &mut rng, &health);
            results.push(t);
            if results.len() < 3 {
                assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Healthy);
            }
        }
        assert_eq!(
            results,
            vec![
                Some(Transition::None),
                Some(Transition::None),
                Some(Transition::ToUnhealthy),
            ]
        );
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Unhealthy);
        sched.debug_assert_consistent();
    }

    #[test]
    fn record_publishes_healthy_again() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![2u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        if let Some(s) = sched.sched.get_mut(0) {
            s.active_health = EndpointHealth::Unhealthy;
            s.interval_state = IntervalState::Down;
        }
        // The bitmap's PRIOR value does not matter here: `record` always
        // calls `publish`, which recomputes the state from `sched` and the
        // flag vectors and overwrites it regardless. Leaving `health` at its
        // freshly-constructed default keeps this test from adding a second
        // call site to `HealthBitmap::set` outside `publish`.
        let health = ClusterHealth::new(1, 0);
        let mut rng = Rng::from_seed(7);
        let mut out = Vec::new();

        let mut results = Vec::new();
        for _ in 0..2 {
            let deadline = sched.wheel.deadline_of(0).expect("scheduled");
            sched.poll_due(deadline, &mut rng, &mut out);
            let order = out.drain(..).next().expect("one order");
            let report = CheckReport {
                endpoint: order.endpoint,
                endpoint_id: order.endpoint_id,
                outcome: CheckOutcome::Pass,
                reconnected: false,
            };
            let t = sched.record(deadline, report, &mut rng, &health);
            results.push(t);
        }
        assert_eq!(
            results,
            vec![Some(Transition::None), Some(Transition::ToHealthy)]
        );
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Healthy);
        sched.debug_assert_consistent();
    }

    #[test]
    fn record_discards_stale_id() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![100u64, 200u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let mut rng = Rng::from_seed(8);
        let health = ClusterHealth::new(2, 0);
        let mut out = Vec::new();

        let d0 = sched.wheel.deadline_of(0).expect("scheduled");
        let d1 = sched.wheel.deadline_of(1).expect("scheduled");
        let poll_at = if d0.since(t0) >= d1.since(t0) { d0 } else { d1 };
        sched.poll_due(poll_at, &mut rng, &mut out);
        sched.debug_assert_consistent();
        let order = out
            .iter()
            .find(|o| o.endpoint == EndpointIdx(0))
            .copied()
            .expect("endpoint 0 must have been dispatched by its own deadline");

        let new_ids = vec![300u64, 200u64];
        sched
            .rebuild(poll_at, &new_ids, &mut rng)
            .expect("rebuild must accept a valid, duplicate-free id set");
        sched.debug_assert_consistent();

        let before = sched.stats().reports_for_unknown_endpoint;
        let report = CheckReport {
            endpoint: order.endpoint,
            endpoint_id: order.endpoint_id,
            outcome: CheckOutcome::Fail(FailKind::Status),
            reconnected: false,
        };
        let result = sched.record(poll_at, report, &mut rng, &health);
        sched.debug_assert_consistent();
        assert_eq!(result, None);
        assert_eq!(sched.stats().reports_for_unknown_endpoint, before + 1);
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Healthy);
    }

    #[test]
    fn record_discards_duplicate() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![11u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let mut rng = Rng::from_seed(9);
        let health = ClusterHealth::new(1, 0);
        let mut out = Vec::new();
        let deadline = sched.wheel.deadline_of(0).expect("scheduled");
        sched.poll_due(deadline, &mut rng, &mut out);
        let order = out.first().copied().expect("one order");
        let report = CheckReport {
            endpoint: order.endpoint,
            endpoint_id: order.endpoint_id,
            outcome: CheckOutcome::Pass,
            reconnected: false,
        };
        let first = sched.record(deadline, report, &mut rng, &health);
        assert!(first.is_some());
        assert_eq!(sched.inflight(), 0);

        let second = sched.record(deadline, report, &mut rng, &health);
        assert_eq!(second, None);
        assert_eq!(sched.stats().reports_without_inflight, 1);
        assert_eq!(
            sched.inflight(),
            0,
            "duplicate report must not underflow inflight count"
        );
        sched.debug_assert_consistent();
    }

    #[test]
    fn record_out_of_range() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64, 2u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let mut rng = Rng::from_seed(10);
        let health = ClusterHealth::new(2, 0);
        let report = CheckReport {
            endpoint: EndpointIdx(999),
            endpoint_id: 42,
            outcome: CheckOutcome::Pass,
            reconnected: false,
        };
        let result = sched.record(t0, report, &mut rng, &health);
        assert_eq!(result, None);
        assert_eq!(sched.stats().reports_for_unknown_endpoint, 1);
        assert_eq!(sched.inflight(), 0);
        sched.debug_assert_consistent();
    }

    #[test]
    fn publish_precedence() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64];
        let health = ClusterHealth::new(1, 0);
        for bits in 0u8..16 {
            let draining = bits & 0b0001 != 0;
            let ejected = bits & 0b0010 != 0;
            let active_unhealthy = bits & 0b0100 != 0;
            let ramping = bits & 0b1000 != 0;

            let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
            sched.debug_assert_consistent();
            if let Some(s) = sched.sched.get_mut(0) {
                s.active_health = if active_unhealthy {
                    EndpointHealth::Unhealthy
                } else {
                    EndpointHealth::Healthy
                };
            }
            if let Some(d) = sched.draining.get_mut(0) {
                *d = draining;
            }
            if let Some(e) = sched.ejected.get_mut(0) {
                *e = ejected;
            }
            if let Some(r) = sched.ramping.get_mut(0) {
                *r = ramping;
            }
            sched.publish(EndpointIdx(0), &health);

            let expected = if draining {
                EndpointHealth::Draining
            } else if ejected || active_unhealthy {
                EndpointHealth::Unhealthy
            } else if ramping {
                EndpointHealth::Degraded
            } else {
                EndpointHealth::Healthy
            };
            assert_eq!(
                health.bitmap.get(EndpointIdx(0)),
                expected,
                "bits={bits:04b} draining={draining} ejected={ejected} \
                 active_unhealthy={active_unhealthy} ramping={ramping}"
            );
        }
    }

    #[test]
    fn set_ejected_publishes_immediately() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        sched.debug_assert_consistent();
        let health = ClusterHealth::new(1, 0);
        sched.set_ejected(EndpointIdx(0), true, &health);
        sched.debug_assert_consistent();
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Unhealthy);
        sched.set_ejected(EndpointIdx(0), false, &health);
        sched.debug_assert_consistent();
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Healthy);
    }

    // Not one of the 23 named tests. `cargo mutants` found that replacing
    // `set_ramping`'s and `set_draining`'s entire bodies with `()` survived:
    // `publish_precedence` (test 14) exercises the precedence logic by
    // writing the `ramping`/`draining` flag vectors directly and calling the
    // private `publish` helper, never the public setters themselves, so
    // nothing in this file actually called them.
    #[test]
    fn set_ramping_publishes_degraded_then_healthy() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        sched.debug_assert_consistent();
        let health = ClusterHealth::new(1, 0);
        sched.set_ramping(EndpointIdx(0), true, &health);
        sched.debug_assert_consistent();
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Degraded);
        sched.set_ramping(EndpointIdx(0), false, &health);
        sched.debug_assert_consistent();
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Healthy);
    }

    #[test]
    fn set_draining_publishes_draining_then_healthy() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        sched.debug_assert_consistent();
        let health = ClusterHealth::new(1, 0);
        sched.set_draining(EndpointIdx(0), true, &health);
        sched.debug_assert_consistent();
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Draining);
        sched.set_draining(EndpointIdx(0), false, &health);
        sched.debug_assert_consistent();
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Healthy);
    }

    #[test]
    fn rebuild_carries_state() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![10u64, 20u64, 30u64, 40u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        if let Some(s) = sched.sched.get_mut(2) {
            s.active_health = EndpointHealth::Unhealthy;
        }
        let deadline_before = sched.wheel.deadline_of(2).expect("scheduled");

        let mut rng = Rng::from_seed(11);
        let reordered = vec![30u64, 10u64, 20u64, 40u64];
        sched
            .rebuild(t0, &reordered, &mut rng)
            .expect("rebuild must succeed on a reordered, duplicate-free set");

        assert_eq!(
            sched.active_health(EndpointIdx(0)),
            Some(EndpointHealth::Unhealthy)
        );
        let deadline_after = sched
            .wheel
            .deadline_of(0)
            .expect("carried entry must remain scheduled");
        assert_eq!(
            deadline_after, deadline_before,
            "the wheel deadline must be carried, not reset"
        );
        sched.debug_assert_consistent();
    }

    #[test]
    fn rebuild_adds_and_removes() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64, 2u64, 3u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let deadline_2_before = sched
            .wheel
            .deadline_of(1)
            .expect("id 2 scheduled at index 1");
        let deadline_3_before = sched
            .wheel
            .deadline_of(2)
            .expect("id 3 scheduled at index 2");

        let mut rng = Rng::from_seed(12);
        let new_ids = vec![2u64, 3u64, 4u64];
        sched
            .rebuild(t0, &new_ids, &mut rng)
            .expect("rebuild must succeed");

        assert_eq!(sched.len(), 3);
        assert_eq!(
            sched.wheel.deadline_of(0),
            Some(deadline_2_before),
            "id 2 must carry its old deadline into its new index"
        );
        assert_eq!(
            sched.wheel.deadline_of(1),
            Some(deadline_3_before),
            "id 3 must carry its old deadline into its new index"
        );
        assert!(
            sched.wheel.deadline_of(2).is_some(),
            "the fresh endpoint (id 4) must still be scheduled"
        );
        sched.debug_assert_consistent();
    }

    #[test]
    fn rebuild_preserves_inflight_accounting() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64, 2u64, 3u64, 4u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let mut deadlines: Vec<u32> = (0..4u32)
            .map(|i| sched.wheel.deadline_of(i).expect("scheduled").since(t0))
            .collect();
        deadlines.sort_unstable();
        let second = *deadlines.get(1).expect("four deadlines");

        let mut rng = Rng::from_seed(13);
        let health = ClusterHealth::new(4, 0);
        let mut out = Vec::new();
        sched.poll_due(t0.add_ms(second), &mut rng, &mut out);
        assert_eq!(
            out.len(),
            2,
            "exactly the two earliest-due endpoints must dispatch"
        );
        assert_eq!(sched.inflight(), 2);

        sched
            .rebuild(t0.add_ms(second), &ids, &mut rng)
            .expect("rebuild with the same ids must succeed");
        assert_eq!(
            sched.inflight(),
            2,
            "in-flight accounting must survive a rebuild that keeps every id"
        );

        for order in out.drain(..) {
            let report = CheckReport {
                endpoint: order.endpoint,
                endpoint_id: order.endpoint_id,
                outcome: CheckOutcome::Pass,
                reconnected: false,
            };
            sched.record(t0.add_ms(second), report, &mut rng, &health);
        }
        assert_eq!(sched.inflight(), 0);
        sched.debug_assert_consistent();
    }

    // Not one of the 23 named tests. `cargo mutants` found that replacing
    // `publish_all`'s body with `()` survived: no test called it and then
    // checked the resulting bitmap.
    #[test]
    fn publish_all_writes_every_endpoint() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64, 2u64, 3u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        sched.debug_assert_consistent();
        if let Some(s) = sched.sched.get_mut(1) {
            s.active_health = EndpointHealth::Unhealthy;
        }
        let health = ClusterHealth::new(3, 0);
        sched.publish_all(&health);
        assert_eq!(health.bitmap.get(EndpointIdx(0)), EndpointHealth::Healthy);
        assert_eq!(
            health.bitmap.get(EndpointIdx(1)),
            EndpointHealth::Unhealthy,
            "publish_all must have written endpoint 1's schedule-derived state, \
             which ClusterHealth::new's own Healthy default cannot explain on its own"
        );
        assert_eq!(health.bitmap.get(EndpointIdx(2)), EndpointHealth::Healthy);
    }

    // Not one of the 23 named tests. `cargo mutants` found that `rebuild`'s
    // own endpoint-count ceiling check (a separate call site from `new`'s,
    // per the design's step 0) survived both a `>` to `==` and a `>` to `>=`
    // mutation, because no test drove `rebuild` itself past or exactly to the
    // ceiling.
    #[test]
    fn rebuild_enforces_the_same_endpoint_ceiling_as_new() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64, 2u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let mut rng = Rng::from_seed(22);

        let too_many: Vec<u64> = (0..=(MAX_ENDPOINTS as u64)).collect();
        let err = sched.rebuild(t0, &too_many, &mut rng).unwrap_err();
        assert_eq!(err.field, "cluster.endpoints");
        assert_eq!(
            sched.len(),
            2,
            "a rejected rebuild must not have touched the scheduler's state"
        );
        sched.debug_assert_consistent();

        let exactly_at_ceiling: Vec<u64> = (0..(MAX_ENDPOINTS as u64)).collect();
        sched
            .rebuild(t0, &exactly_at_ceiling, &mut rng)
            .expect("rebuild must accept exactly MAX_ENDPOINTS unique endpoints");
        assert_eq!(sched.len(), MAX_ENDPOINTS);
        sched.debug_assert_consistent();
    }

    // Not one of the 23 named tests, but edge case 16's explicit requirement
    // that `rebuild` reject a duplicate exactly as `new` does.
    #[test]
    fn rebuild_rejects_duplicate_ids() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64, 2u64, 3u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        let mut rng = Rng::from_seed(23);
        let dup_ids = vec![5u64, 5u64];
        let err = sched.rebuild(t0, &dup_ids, &mut rng).unwrap_err();
        assert_eq!(err.field, "cluster.endpoints");
        assert_eq!(
            sched.len(),
            3,
            "a rejected rebuild must not have touched the scheduler's state"
        );
        sched.debug_assert_consistent();
    }

    // Regression test for the live defect described in issue 861: `rebuild`
    // carried a surviving endpoint's in-flight bit forward unconditionally,
    // even when the endpoint's index moved. The runner's outstanding
    // `CheckOrder` for that endpoint still names the OLD index, so its
    // eventual honest report gets discarded by `record`'s id guard and the
    // in-flight bit at the endpoint's NEW index can never clear: the
    // endpoint is never dispatched again for the rest of the process's
    // life. Reproduces the measured scenario verbatim: deleting pod 20 from
    // the middle of `[10, 20, 30]` moves id 30 from index 2 to index 1.
    #[test]
    fn rebuild_index_move_does_not_strand_inflight() {
        let cfg = all_due_cfg();
        let t0 = Millis(0);
        // The wheel bumps a deadline scheduled exactly at the current cursor
        // forward by one millisecond (`schedule`'s `raw == 0` case), and
        // `HealthScheduler::new` starts the cursor at `t0` with every
        // endpoint's nominal also at `t0` (`all_due_cfg`'s zero phase), so
        // the very first due instant is `t0 + 1`, not `t0` itself. Every
        // existing test that uses `all_due_cfg` polls at `t0.add_ms(1)` for
        // the same reason (see `poll_due_respects_concurrency_cap`).
        let t1 = t0.add_ms(1);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 3, true).expect("valid");
        let mut rng = Rng::from_seed(861);
        let mut out = Vec::new();
        sched.poll_due(t1, &mut rng, &mut out);
        assert_eq!(
            out.len(),
            3,
            "all three endpoints must dispatch at t0 + 1ms"
        );
        assert_eq!(sched.inflight(), 3);

        let order_10 = out
            .iter()
            .copied()
            .find(|o| o.endpoint_id == 10)
            .expect("order for id 10");
        let order_30 = out
            .iter()
            .copied()
            .find(|o| o.endpoint_id == 30)
            .expect("order for id 30");

        sched
            .rebuild(t1, &[10u64, 30u64], &mut rng)
            .expect("rebuild must succeed");
        assert_eq!(
            sched.inflight(),
            1,
            "only the unmoved endpoint's in-flight bit may survive the rebuild, not 2"
        );
        sched.debug_assert_consistent();

        let health = ClusterHealth::new(2, 0);
        let before_unknown = sched.stats().reports_for_unknown_endpoint;

        let report_10 = CheckReport {
            endpoint: order_10.endpoint,
            endpoint_id: order_10.endpoint_id,
            outcome: CheckOutcome::Pass,
            reconnected: false,
        };
        assert!(
            sched.record(t1, report_10, &mut rng, &health).is_some(),
            "the report for the endpoint whose index did not move must be accepted"
        );

        let report_30 = CheckReport {
            endpoint: order_30.endpoint,
            endpoint_id: order_30.endpoint_id,
            outcome: CheckOutcome::Pass,
            reconnected: false,
        };
        assert!(
            sched.record(t1, report_30, &mut rng, &health).is_none(),
            "the stale report addressed to the endpoint's OLD index must be discarded"
        );
        assert_eq!(
            sched.stats().reports_for_unknown_endpoint,
            before_unknown + 1,
            "the discard must be counted exactly once"
        );
        sched.debug_assert_consistent();

        let mut dispatch_count_30: u32 = 0;
        let mut now = t1;
        for _ in 0..5000u32 {
            now = now.add_ms(1);
            out.clear();
            sched.poll_due(now, &mut rng, &mut out);
            for order in out.drain(..) {
                if order.endpoint_id == 30 {
                    dispatch_count_30 = dispatch_count_30.saturating_add(1);
                }
                let report = CheckReport {
                    endpoint: order.endpoint,
                    endpoint_id: order.endpoint_id,
                    outcome: CheckOutcome::Pass,
                    reconnected: false,
                };
                sched.record(now, report, &mut rng, &health);
            }
        }
        assert!(
            dispatch_count_30 > 0,
            "endpoint 30 must recover and be dispatched again over the 5-second window \
             (observed {dispatch_count_30} dispatches), not permanently stranded at 0"
        );
        sched.debug_assert_consistent();
    }

    // Regression test for issue 861, edge case 1: a rebuild that changes
    // nothing about ordering must still carry the in-flight bit and
    // `dispatched_at` for a surviving endpoint whose index did not move.
    // Guards against a future edit making the `index_moved` check too
    // aggressive (for example comparing endpoint ids instead of positions).
    #[test]
    fn rebuild_same_index_still_carries_inflight() {
        let cfg = all_due_cfg();
        let t0 = Millis(0);
        // See `rebuild_index_move_does_not_strand_inflight` for why the
        // first due instant is `t0 + 1`, not `t0`.
        let t1 = t0.add_ms(1);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 3, true).expect("valid");
        let mut rng = Rng::from_seed(862);
        let mut out = Vec::new();
        sched.poll_due(t1, &mut rng, &mut out);
        assert_eq!(
            out.len(),
            3,
            "all three endpoints must dispatch at t0 + 1ms"
        );

        let order_30 = out
            .iter()
            .copied()
            .find(|o| o.endpoint_id == 30)
            .expect("order for id 30");
        let health = ClusterHealth::new(3, 0);
        let report_30 = CheckReport {
            endpoint: order_30.endpoint,
            endpoint_id: order_30.endpoint_id,
            outcome: CheckOutcome::Pass,
            reconnected: false,
        };
        assert!(sched.record(t1, report_30, &mut rng, &health).is_some());
        let pre_rebuild_inflight = sched.inflight();
        assert_eq!(
            pre_rebuild_inflight, 2,
            "ids 10 and 20 must still be in flight after id 30's report is recorded"
        );
        let dispatched_at_10_before = sched.dispatched_at.first().copied();

        // Removing only the LAST endpoint leaves every surviving index
        // unchanged: id 10 stays at index 0, id 20 stays at index 1.
        sched
            .rebuild(t1, &[10u64, 20u64], &mut rng)
            .expect("rebuild must succeed");

        assert_eq!(
            sched.inflight(),
            pre_rebuild_inflight,
            "removing an endpoint that is not itself in flight, and that shifts no \
             survivor's index, must not disturb the survivors' in-flight bits"
        );
        assert_eq!(
            sched.dispatched_at.first().copied(),
            dispatched_at_10_before,
            "dispatched_at must still be carried for an endpoint whose index did not move"
        );
        sched.debug_assert_consistent();
    }

    // Regression test for issue 861, edge case 7: an endpoint that is both
    // in flight AND already marked stuck must come out of a rebuild that
    // moves its index with `stuck == false` and `inflight == false`, and
    // must not immediately re-trip the stuck detector from a stale
    // `dispatched_at` once it is dispatched fresh.
    #[test]
    fn rebuild_index_move_resets_stuck_and_dispatched_at() {
        // `all_due_cfg` unmodified: `timeout_ms` (1) must not exceed
        // `interval_ms` (1) per `HealthCheckConfig::validate`'s
        // `ordered_u32` check, so the stuck threshold here is
        // `10 * timeout_ms` = 10 ms, not the 1000 ms a larger `timeout_ms`
        // would give, but the property under test does not depend on the
        // threshold's absolute size.
        let cfg = all_due_cfg();
        let t0 = Millis(0);
        // See `rebuild_index_move_does_not_strand_inflight` for why the
        // first due instant is `t0 + 1`, not `t0`.
        let t1 = t0.add_ms(1);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 3, true).expect("valid");
        let mut rng = Rng::from_seed(863);
        let mut out = Vec::new();

        sched.poll_due(t1, &mut rng, &mut out);
        assert_eq!(
            out.len(),
            3,
            "all three endpoints must dispatch at t0 + 1ms"
        );

        // Never respond to id 30 (index 2). Advance past the stuck
        // threshold (10 * timeout_ms = 10 ms), exactly as
        // `stuck_inflight_gauge_rises_and_does_not_double_count` drives a
        // single endpoint stuck, so `poll_due`'s already-inflight branch
        // marks it stuck before the rebuild.
        let past_threshold = t1.add_ms(11);
        out.clear();
        let stuck_poll = sched.poll_due(past_threshold, &mut rng, &mut out);
        assert!(
            out.is_empty(),
            "an already in-flight endpoint must never get a second order"
        );
        assert_eq!(stuck_poll.dispatched, 0);
        assert_eq!(
            sched.stuck.get(2).copied(),
            Some(true),
            "id 30 must be marked stuck before the rebuild"
        );
        assert_eq!(sched.inflight.get(2).copied(), Some(true));
        // None of the three checks dispatched at t1 has ever been
        // responded to, so all three cross the same stuck threshold in
        // this one poll, not just id 30: the gauge counts every stuck
        // endpoint, and this rebuild is about to exercise both ways it can
        // be released (removed outright, and reset by an index move) in
        // the same call.
        assert_eq!(sched.stuck.first().copied(), Some(true));
        assert_eq!(sched.stuck.get(1).copied(), Some(true));
        assert_eq!(
            sched.stats().stuck_inflight,
            3,
            "the gauge must rise once per stuck endpoint; all three are outstanding here"
        );
        sched.debug_assert_consistent();

        // Remove id 20 from the middle: id 30 moves from index 2 to index 1
        // while its check is still in flight and marked stuck. Id 20 was
        // also stuck and is now removed outright; id 10's index does not
        // move, so its stuck bit is neither reset nor released here.
        sched
            .rebuild(past_threshold, &[10u64, 30u64], &mut rng)
            .expect("rebuild must succeed");

        assert_eq!(
            sched.inflight.get(1).copied(),
            Some(false),
            "the moved endpoint's in-flight bit must be reset, not stranded stuck-and-inflight"
        );
        assert_eq!(
            sched.stuck.get(1).copied(),
            Some(false),
            "the moved endpoint's stuck bit must be reset, not carried across the index change"
        );
        assert_eq!(
            sched.dispatched_at.get(1).copied(),
            Some(Millis(0)),
            "the moved endpoint's dispatched_at must reset to the fresh value, not a stale timestamp"
        );
        assert_eq!(
            sched.stats().stuck_inflight,
            1,
            "id 20's removal and id 30's index-move reset must each pay back the gauge \
             immediately (3 -> 1), leaving only id 10's still-genuinely-stuck bit counted, \
             not leak either release and strand the gauge at 2 or 3"
        );
        sched.debug_assert_consistent();

        // A subsequent dispatch must behave exactly like a freshly
        // scheduled endpoint: it becomes due on its own schedule and
        // dispatches a fresh order.
        out.clear();
        let fresh_dispatch_at = past_threshold.add_ms(1);
        let redispatch = sched.poll_due(fresh_dispatch_at, &mut rng, &mut out);
        assert_eq!(
            redispatch.dispatched, 1,
            "the moved endpoint must dispatch a fresh order once due again"
        );
        let fresh_order = out.first().copied().expect("one fresh order");
        assert_eq!(fresh_order.endpoint, EndpointIdx(1));
        assert_eq!(fresh_order.endpoint_id, 30);
        sched.debug_assert_consistent();

        // The endpoint's watchdog (armed by `poll_due` at dispatch time +
        // `timeout_ms` + `defer_ms`, see the comment on the watchdog
        // schedule call above) is the next instant the wheel actually
        // examines this endpoint again while its fresh check is still
        // outstanding. Polling any earlier is vacuous: the wheel simply
        // does not fire, nothing looks at index 1, and no assertion here
        // could detect a reintroduced bug. At the watchdog instant the
        // stuck detector must not immediately re-trip: `dispatched_at` must
        // be the fresh timestamp set by the dispatch above (so
        // `now.since(dispatched_at)` is small), not the pre-rebuild stale
        // one (which would make it huge and false-positive stuck on the
        // very first watchdog after a churn).
        out.clear();
        let watchdog_at = fresh_dispatch_at
            .add_ms(cfg.timeout_ms)
            .add_ms(sched.defer_ms);
        let watchdog_repoll = sched.poll_due(watchdog_at, &mut rng, &mut out);
        assert!(
            out.is_empty(),
            "the watchdog firing while the fresh check is still outstanding must not emit a \
             second order"
        );
        assert_eq!(watchdog_repoll.dispatched, 0);
        assert_eq!(
            watchdog_repoll.deferred, 2,
            "the watchdog must defer the still-outstanding fresh check for id 30 (index 1); \
             id 10 (index 0) is also deferred here because it was never responded to either \
             and has been re-checking every `defer_ms` since it was marked stuck, which is \
             incidental to this test's own scenario, not something id 30's fix must avoid"
        );
        assert_eq!(
            sched.stuck.get(1).copied(),
            Some(false),
            "the watchdog firing well under the stuck threshold after a fresh dispatch must \
             never re-trip the stuck detector from a stale dispatched_at"
        );
        sched.debug_assert_consistent();
    }

    // Regression test for the review of issue 861's fix: a moved endpoint
    // whose in-flight check is abandoned must become dispatchable again on
    // its own probe interval, not on the very next millisecond. Uses a
    // realistic (non-`all_due_cfg`) interval so the two behaviors are
    // actually distinguishable: with `interval_ms == 1`, arming the wheel
    // at either the stale past `nominal` (the bug) or at `now +
    // effective_interval_ms` (the fix) both clamp to "the next tick", so a
    // 1ms config can never catch a regression here.
    #[test]
    fn rebuild_index_move_reschedules_at_the_probe_interval_not_immediately() {
        let cfg = HealthCheckConfig {
            interval_ms: 1000,
            edge_interval_ms: 250,
            unhealthy_interval_ms: 1000,
            no_traffic_interval_ms: 60_000,
            timeout_ms: 200,
            jitter_bp: 0,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            reconnect_every: 0,
            max_checks_per_endpoint_per_sec: 10,
        };
        let (effective_interval_ms, _) = cfg.effective_interval_ms();
        assert_eq!(
            effective_interval_ms, 1000,
            "sanity: the probe-rate floor must not be tighter than interval_ms here"
        );
        let t0 = Millis(0);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 8, true).expect("valid");
        let mut rng = Rng::from_seed(8611);
        let mut out = Vec::new();

        // Dispatch id 30 (index 2) at its own scheduled deadline and leave
        // it outstanding, simulating the runner losing the check.
        let deadline_30 = sched.wheel.deadline_of(2).expect("scheduled");
        sched.poll_due(deadline_30, &mut rng, &mut out);
        let order_30 = out
            .iter()
            .copied()
            .find(|o| o.endpoint_id == 30)
            .expect("id 30 dispatched at its own deadline");
        assert_eq!(order_30.endpoint, EndpointIdx(2));

        // Discovery churns one millisecond later: prepend a pod, moving id
        // 30 from index 2 to index 3 while its check is still outstanding.
        // The no-op poll first keeps the wheel's cursor in sync with `now`,
        // matching how every other test in this file sequences poll_due
        // and rebuild at the same instant.
        let churn_at = deadline_30.add_ms(1);
        out.clear();
        sched.poll_due(churn_at, &mut rng, &mut out);
        sched
            .rebuild(churn_at, &[99u64, 10u64, 20u64, 30u64], &mut rng)
            .expect("rebuild must succeed");

        // It must NOT be re-probed on the very next millisecond: that
        // bypasses `max_checks_per_endpoint_per_sec` by orders of
        // magnitude and opens a second connection to an endpoint whose
        // first check may still be outstanding at the transport level.
        out.clear();
        sched.poll_due(churn_at.add_ms(1), &mut rng, &mut out);
        assert!(
            out.iter().all(|o| o.endpoint_id != 30),
            "a moved endpoint whose check was abandoned must not be re-probed one \
             millisecond later"
        );

        // It must not become dispatchable any EARLIER than a full probe
        // interval either: this pins the rearm to the interval itself,
        // rather than merely to "somewhere after the next millisecond",
        // which the assertion above alone cannot distinguish from a rearm
        // that fires at half, or a quarter, of `effective_interval_ms`.
        out.clear();
        sched.poll_due(
            churn_at.add_ms(effective_interval_ms - 1),
            &mut rng,
            &mut out,
        );
        assert!(
            out.iter().all(|o| o.endpoint_id != 30),
            "the moved endpoint must not be dispatchable one millisecond before its full \
             probe interval elapses"
        );

        // It must become dispatchable again once a full probe interval has
        // elapsed from the rebuild (the rearm instant is computed from
        // `now` at rebuild time, i.e. `churn_at`, not from the original
        // abandoned dispatch).
        out.clear();
        sched.poll_due(churn_at.add_ms(effective_interval_ms), &mut rng, &mut out);
        assert!(
            out.iter().any(|o| o.endpoint_id == 30),
            "the moved endpoint must be dispatchable again once its probe interval elapses"
        );
        sched.debug_assert_consistent();
    }

    // Regression test for the SECOND review round of issue 861's fix: the
    // rearm above only holds until the NEXT rebuild unless
    // `EndpointSchedule::nominal` is kept in step with the wheel entry.
    // Without that sync, a second rebuild arriving before the abandoned
    // endpoint could ever be redispatched re-derives the arming instant from
    // the still-stale past `nominal` and reproduces the exact
    // clamp-to-`now + 1ms` violation the first rebuild's fix exists to
    // close. This is the shape of a rolling deploy: several membership
    // updates land within one probe interval of each other.
    #[test]
    fn rebuild_a_second_rebuild_does_not_recompute_the_rearm_from_a_stale_nominal() {
        let cfg = HealthCheckConfig {
            interval_ms: 1000,
            edge_interval_ms: 250,
            unhealthy_interval_ms: 1000,
            no_traffic_interval_ms: 60_000,
            timeout_ms: 200,
            jitter_bp: 0,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            reconnect_every: 0,
            max_checks_per_endpoint_per_sec: 10,
        };
        let (effective_interval_ms, _) = cfg.effective_interval_ms();
        let t0 = Millis(0);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 8, true).expect("valid");
        let mut rng = Rng::from_seed(8612);
        let mut out = Vec::new();

        // Dispatch id 30 (index 2) at its own deadline and leave it
        // outstanding, exactly as the single-rebuild test above does.
        let deadline_30 = sched.wheel.deadline_of(2).expect("scheduled");
        sched.poll_due(deadline_30, &mut rng, &mut out);
        assert!(out.iter().any(|o| o.endpoint_id == 30));

        // Rebuild #1, 2ms later: prepend a pod, moving id 30 (2 -> 3) while
        // its check is still outstanding. `carry_endpoint_state` resets
        // `inflight` to false and arms the wheel a full interval out.
        let churn1_at = deadline_30.add_ms(2);
        out.clear();
        sched.poll_due(churn1_at, &mut rng, &mut out);
        sched
            .rebuild(churn1_at, &[99u64, 10u64, 20u64, 30u64], &mut rng)
            .expect("rebuild 1 must succeed");

        // Rebuild #2, 2ms after that, well before id 30 could ever be
        // redispatched (its rearm is ~1000ms out): prepend again, moving id
        // 30 (3 -> 4). `was_inflight` is now false, since rebuild #1 already
        // reset it and nothing has redispatched it since: this is exactly
        // the condition under which `carry_endpoint_state` falls through to
        // reading `nominal`.
        let churn2_at = churn1_at.add_ms(2);
        out.clear();
        sched.poll_due(churn2_at, &mut rng, &mut out);
        sched
            .rebuild(churn2_at, &[98u64, 99u64, 10u64, 20u64, 30u64], &mut rng)
            .expect("rebuild 2 must succeed");

        // It must NOT be re-probed on the next millisecond: that is the
        // 500x violation this fix exists to close, reappearing one rebuild
        // later.
        out.clear();
        sched.poll_due(churn2_at.add_ms(1), &mut rng, &mut out);
        assert!(
            out.iter().all(|o| o.endpoint_id != 30),
            "a second rebuild must not re-derive the rearm from a stale nominal and re-probe \
             one millisecond later"
        );

        // It must become dispatchable a full probe interval from rebuild #1,
        // the rebuild that actually abandoned the check: rebuild #2 read the
        // already-correct future `nominal` rebuild #1 left behind (with the
        // fix) and must not have re-derived a fresh interval from itself,
        // since `was_inflight` was false by the time rebuild #2 ran.
        out.clear();
        sched.poll_due(
            churn1_at.add_ms(effective_interval_ms - 1),
            &mut rng,
            &mut out,
        );
        assert!(
            out.iter().all(|o| o.endpoint_id != 30),
            "must not be dispatchable one millisecond before a full probe interval from \
             rebuild 1 elapses"
        );
        out.clear();
        sched.poll_due(churn1_at.add_ms(effective_interval_ms), &mut rng, &mut out);
        assert!(
            out.iter().any(|o| o.endpoint_id == 30),
            "must become dispatchable once a full probe interval from rebuild 1 elapses"
        );
        sched.debug_assert_consistent();
    }

    // Companion to the test above: the second rebuild does not even need to
    // move the endpoint again for the stale-`nominal` fallback to fire,
    // because the `!index_moved` arm of `carry_endpoint_state` reads the
    // same `nominal` field the `index_moved` arm would have left stale.
    #[test]
    fn rebuild_a_second_rebuild_that_does_not_move_the_endpoint_still_reads_a_fresh_nominal() {
        let cfg = HealthCheckConfig {
            interval_ms: 1000,
            edge_interval_ms: 250,
            unhealthy_interval_ms: 1000,
            no_traffic_interval_ms: 60_000,
            timeout_ms: 200,
            jitter_bp: 0,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            reconnect_every: 0,
            max_checks_per_endpoint_per_sec: 10,
        };
        let (effective_interval_ms, _) = cfg.effective_interval_ms();
        let t0 = Millis(0);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 8, true).expect("valid");
        let mut rng = Rng::from_seed(8613);
        let mut out = Vec::new();

        let deadline_30 = sched.wheel.deadline_of(2).expect("scheduled");
        sched.poll_due(deadline_30, &mut rng, &mut out);
        assert!(out.iter().any(|o| o.endpoint_id == 30));

        let churn1_at = deadline_30.add_ms(2);
        out.clear();
        sched.poll_due(churn1_at, &mut rng, &mut out);
        sched
            .rebuild(churn1_at, &[99u64, 10u64, 20u64, 30u64], &mut rng)
            .expect("rebuild 1 must succeed");

        // Rebuild #2 APPENDS instead of prepending: id 30 stays at index 3,
        // so `index_moved` is false this time and `carry_endpoint_state`
        // takes the `!index_moved` arm, which reads `nominal` directly.
        let churn2_at = churn1_at.add_ms(2);
        out.clear();
        sched.poll_due(churn2_at, &mut rng, &mut out);
        sched
            .rebuild(churn2_at, &[99u64, 10u64, 20u64, 30u64, 77u64], &mut rng)
            .expect("rebuild 2 (append, no move) must succeed");

        out.clear();
        sched.poll_due(churn2_at.add_ms(1), &mut rng, &mut out);
        assert!(
            out.iter().all(|o| o.endpoint_id != 30),
            "an unmoved endpoint on a second rebuild must not be re-probed one millisecond \
             later just because an earlier rebuild left `nominal` stale"
        );

        // Rebuild #2 did not move it and must not have re-armed it either:
        // it must become dispatchable exactly when rebuild #1 armed it, one
        // probe interval from rebuild #1, not from rebuild #2.
        out.clear();
        sched.poll_due(churn1_at.add_ms(effective_interval_ms), &mut rng, &mut out);
        assert!(
            out.iter().any(|o| o.endpoint_id == 30),
            "must become dispatchable once the interval armed by rebuild 1 elapses"
        );
        sched.debug_assert_consistent();
    }

    // Regression test for the review of issue 861's fix, minor 4: the rearm
    // interval must be the endpoint's OWN current interval state
    // (`cfg.interval_for(carried.interval_state)`), not the flat
    // steady-state interval. An endpoint parked `Down` after failing must
    // rearm at its unhealthy cadence when its check is abandoned by an
    // index move, not wait out the full steady interval.
    #[test]
    fn rebuild_index_move_rearms_at_the_endpoints_own_interval_state_not_steady() {
        let cfg = HealthCheckConfig {
            interval_ms: 30_000,
            edge_interval_ms: 500,
            unhealthy_interval_ms: 500,
            no_traffic_interval_ms: 60_000,
            timeout_ms: 200,
            jitter_bp: 0,
            healthy_threshold: 2,
            unhealthy_threshold: 1,
            reconnect_every: 0,
            max_checks_per_endpoint_per_sec: 10,
        };
        let t0 = Millis(0);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 8, true).expect("valid");
        let mut rng = Rng::from_seed(8614);
        let mut out = Vec::new();
        let health = ClusterHealth::new(3, 0);

        // First check fails: `unhealthy_threshold = 1` means one failure is
        // enough to transition Healthy -> Unhealthy, which parks the
        // endpoint in `Edge`.
        let deadline1 = sched.wheel.deadline_of(2).expect("scheduled");
        sched.poll_due(deadline1, &mut rng, &mut out);
        let order1 = out
            .iter()
            .copied()
            .find(|o| o.endpoint_id == 30)
            .expect("id 30 dispatched at its own deadline");
        let transition1 = sched
            .record(
                deadline1,
                CheckReport {
                    endpoint: order1.endpoint,
                    endpoint_id: 30,
                    outcome: CheckOutcome::Fail(FailKind::Connect),
                    reconnected: false,
                },
                &mut rng,
                &health,
            )
            .expect("id 30 was inflight");
        assert_eq!(transition1, Transition::ToUnhealthy);
        assert_eq!(sched.sched[2].interval_state, IntervalState::Edge);
        out.clear();

        // Second check also fails: `Edge` resolves to `Down`, since the
        // endpoint is still `Unhealthy`.
        let deadline2 = sched.wheel.deadline_of(2).expect("scheduled");
        sched.poll_due(deadline2, &mut rng, &mut out);
        let order2 = out
            .iter()
            .copied()
            .find(|o| o.endpoint_id == 30)
            .expect("id 30 dispatched again");
        sched.record(
            deadline2,
            CheckReport {
                endpoint: order2.endpoint,
                endpoint_id: 30,
                outcome: CheckOutcome::Fail(FailKind::Connect),
                reconnected: false,
            },
            &mut rng,
            &health,
        );
        assert_eq!(sched.sched[2].interval_state, IntervalState::Down);
        out.clear();

        // Third check is dispatched, then abandoned by an index-moving
        // rebuild while `interval_state` is `Down`.
        let deadline3 = sched.wheel.deadline_of(2).expect("scheduled");
        sched.poll_due(deadline3, &mut rng, &mut out);
        assert!(out.iter().any(|o| o.endpoint_id == 30));
        out.clear();
        let churn_at = deadline3.add_ms(1);
        sched.poll_due(churn_at, &mut rng, &mut out);
        out.clear();
        sched
            .rebuild(churn_at, &[99u64, 10u64, 20u64, 30u64], &mut rng)
            .expect("rebuild must succeed");

        // It must not wait out the full 30-second steady interval: the
        // unhealthy interval (500ms) is the endpoint's own schedule.
        out.clear();
        sched.poll_due(churn_at.add_ms(499), &mut rng, &mut out);
        assert!(
            out.iter().all(|o| o.endpoint_id != 30),
            "must not be dispatchable one millisecond before its own unhealthy interval elapses"
        );
        out.clear();
        sched.poll_due(churn_at.add_ms(500), &mut rng, &mut out);
        assert!(
            out.iter().any(|o| o.endpoint_id == 30),
            "an unhealthy endpoint's abandoned check must rearm at its OWN unhealthy interval \
             (500ms), not the flat steady interval (30_000ms)"
        );
        sched.debug_assert_consistent();
    }

    // Regression test for the review of issue 861's fix: resetting a
    // carried `stuck` bit across an index move must pay back
    // `stats.stuck_inflight`, or the gauge ratchets upward forever on every
    // churn, even when nothing is actually stuck. Mirrors the reviewer's
    // measured scenario: discovery never REMOVES anything, it only
    // prepends a new pod, which still shifts every survivor's index by one
    // and exercises the same `index_moved` reset path.
    #[test]
    fn rebuild_index_move_does_not_leak_stuck_gauge_across_repeated_churns() {
        let cfg = all_due_cfg();
        let t0 = Millis(0);
        let t1 = t0.add_ms(1);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 3, true).expect("valid");
        let mut rng = Rng::from_seed(864);
        let mut out = Vec::new();

        sched.poll_due(t1, &mut rng, &mut out);
        assert_eq!(
            out.len(),
            3,
            "all three endpoints must dispatch at t0 + 1ms"
        );

        // Respond to ids 10 and 20 immediately so only id 30 is ever left
        // outstanding; otherwise all three would cross the stuck threshold
        // together below, muddying the single-endpoint scenario this test
        // is about.
        let health0 = ClusterHealth::new(3, 0);
        for order in out.drain(..) {
            if order.endpoint_id != 30 {
                let report = CheckReport {
                    endpoint: order.endpoint,
                    endpoint_id: order.endpoint_id,
                    outcome: CheckOutcome::Pass,
                    reconnected: false,
                };
                sched.record(t1, report, &mut rng, &health0);
            }
        }

        // Never respond to id 30 (index 2); push it past the stuck
        // threshold exactly once. Ids 10 and 20 come due again under
        // `all_due_cfg` and dispatch fresh in this same poll; that is
        // expected and does not disturb id 30's stuck detection.
        let past_threshold = t1.add_ms(11);
        out.clear();
        sched.poll_due(past_threshold, &mut rng, &mut out);
        assert_eq!(sched.stuck.get(2).copied(), Some(true));
        assert_eq!(sched.stats().stuck_inflight, 1);

        // First churn: prepend a pod. Nothing is removed, but every
        // survivor's index shifts by one, so id 30 moves from index 2 to
        // index 3 while still marked stuck and in flight.
        sched
            .rebuild(past_threshold, &[99u64, 10u64, 20u64, 30u64], &mut rng)
            .expect("rebuild must succeed");
        assert_eq!(
            sched.stats().stuck_inflight,
            0,
            "the reset carried stuck bit must pay back the gauge immediately"
        );

        // 60 simulated seconds in which every subsequent order is answered
        // immediately by a well-behaved runner: nothing should ever be
        // stuck again, so the gauge must stay at 0 throughout.
        let health = ClusterHealth::new(4, 0);
        let mut now = past_threshold;
        for _ in 0..60_000u32 {
            now = now.add_ms(1);
            out.clear();
            sched.poll_due(now, &mut rng, &mut out);
            for order in out.drain(..) {
                let report = CheckReport {
                    endpoint: order.endpoint,
                    endpoint_id: order.endpoint_id,
                    outcome: CheckOutcome::Pass,
                    reconnected: false,
                };
                sched.record(now, report, &mut rng, &health);
            }
            assert_eq!(
                sched.stats().stuck_inflight,
                0,
                "a healthy runner answering every order must never leave the gauge above 0"
            );
        }

        // Five more churns, each prepending another pod and shifting every
        // survivor's index again, must not ratchet the gauge upward: there
        // is nothing stuck left to reset.
        let mut current_ids = vec![99u64, 10u64, 20u64, 30u64];
        for churn in 0..5u64 {
            current_ids.insert(0, 1000 + churn);
            sched
                .rebuild(now, &current_ids, &mut rng)
                .expect("rebuild must succeed");
            assert_eq!(
                sched.stats().stuck_inflight,
                0,
                "repeated index-moving churns with nothing stuck must never raise the gauge \
                 (churn {churn})"
            );
        }
        sched.debug_assert_consistent();
    }

    // Companion to the two tests above: the SAME gauge leak (a `stuck` bit
    // that raised `stats.stuck_inflight` and is never paid back) also
    // reaches through the OTHER exit from `rebuild`'s carry loop, removing
    // an endpoint outright instead of moving its index. Pre-existing on
    // main, folded into this fix because it is the identical counter in
    // the identical function.
    #[test]
    fn rebuild_removing_a_stuck_endpoint_does_not_leak_the_gauge() {
        let cfg = all_due_cfg();
        let t0 = Millis(0);
        let t1 = t0.add_ms(1);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 3, true).expect("valid");
        let mut rng = Rng::from_seed(865);
        let mut out = Vec::new();

        sched.poll_due(t1, &mut rng, &mut out);
        assert_eq!(
            out.len(),
            3,
            "all three endpoints must dispatch at t0 + 1ms"
        );

        // Respond to ids 10 and 20 immediately so only id 30 is ever left
        // outstanding; otherwise all three would cross the stuck threshold
        // together below, muddying the single-endpoint scenario this test
        // is about.
        let health0 = ClusterHealth::new(3, 0);
        for order in out.drain(..) {
            if order.endpoint_id != 30 {
                let report = CheckReport {
                    endpoint: order.endpoint,
                    endpoint_id: order.endpoint_id,
                    outcome: CheckOutcome::Pass,
                    reconnected: false,
                };
                sched.record(t1, report, &mut rng, &health0);
            }
        }

        // Never respond to id 30 (index 2); push it past the stuck
        // threshold. Ids 10 and 20 come due again under `all_due_cfg` and
        // dispatch fresh in this same poll; that is expected and does not
        // disturb id 30's stuck detection.
        let past_threshold = t1.add_ms(11);
        out.clear();
        sched.poll_due(past_threshold, &mut rng, &mut out);
        assert_eq!(sched.stuck.get(2).copied(), Some(true));
        assert_eq!(sched.stats().stuck_inflight, 1);

        // Remove id 30 entirely: it is gone for good, so its stuck bit
        // must be released, not silently dropped along with the rest of
        // its state while the gauge that counted it stays raised.
        sched
            .rebuild(past_threshold, &[10u64, 20u64], &mut rng)
            .expect("rebuild must succeed");
        assert_eq!(
            sched.stats().stuck_inflight,
            0,
            "removing a stuck endpoint outright must release its gauge contribution, not leak it"
        );
        sched.debug_assert_consistent();
    }

    // Regression test for the review of issue 861's fix: `release_stuck_gauge`
    // must require BOTH `index_moved` AND `was_stuck`. An index move alone
    // must never pay back a gauge count that move's own endpoint never
    // raised, even while a DIFFERENT, still genuinely stuck, endpoint sits at
    // an index that does not move. Without the `was_stuck` conjunct this
    // would zero the gauge for id 10, which is still genuinely stuck, while
    // its check keeps being lost forever.
    #[test]
    fn rebuild_index_move_of_a_never_stuck_endpoint_does_not_release_a_gauge_it_never_raised() {
        let cfg = all_due_cfg();
        let t0 = Millis(0);
        let t1 = t0.add_ms(1);
        let ids = vec![10u64, 20u64, 30u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 3, true).expect("valid");
        let mut rng = Rng::from_seed(866);
        let mut out = Vec::new();

        sched.poll_due(t1, &mut rng, &mut out);
        assert_eq!(
            out.len(),
            3,
            "all three endpoints must dispatch at t0 + 1ms"
        );

        // Respond to ids 20 and 30 immediately so only id 10 is ever left
        // outstanding; it alone crosses the stuck threshold below, and its
        // index never moves in the rebuild that follows.
        let health0 = ClusterHealth::new(3, 0);
        for order in out.drain(..) {
            if order.endpoint_id != 10 {
                let report = CheckReport {
                    endpoint: order.endpoint,
                    endpoint_id: order.endpoint_id,
                    outcome: CheckOutcome::Pass,
                    reconnected: false,
                };
                sched.record(t1, report, &mut rng, &health0);
            }
        }

        // Never respond to id 10 (index 0); push it past the stuck
        // threshold. Ids 20 and 30 come due again under `all_due_cfg` and
        // dispatch fresh in this same poll; that is expected (see the
        // sibling gauge tests above) and leaves them neither inflight nor
        // stuck.
        let past_threshold = t1.add_ms(11);
        out.clear();
        sched.poll_due(past_threshold, &mut rng, &mut out);
        assert_eq!(
            sched.stuck.first().copied(),
            Some(true),
            "id 10 must be stuck"
        );
        assert_eq!(
            sched.stuck.get(2).copied(),
            Some(false),
            "id 30 must not be stuck"
        );
        assert_eq!(sched.stats().stuck_inflight, 1);

        // Insert a fresh endpoint between id 20 and id 30: id 10 stays at
        // index 0 (never visited by the index-move reset at all), id 20
        // stays at index 1, and id 30 moves from index 2 to index 3 despite
        // never having been stuck.
        sched
            .rebuild(past_threshold, &[10u64, 20u64, 99u64, 30u64], &mut rng)
            .expect("rebuild must succeed");

        assert_eq!(
            sched.stuck.first().copied(),
            Some(true),
            "id 10's stuck bit is untouched by an index move that is not its own"
        );
        assert_eq!(
            sched.stats().stuck_inflight,
            1,
            "id 30's index move must not pay back a gauge count it never raised; id 10's \
             still-genuinely-stuck bit must remain counted"
        );
        sched.debug_assert_consistent();
    }

    // Not one of the 23 named tests. `cargo mutants` found that both
    // `is_empty -> true` and `is_empty -> false` survived: nothing in this
    // file called it.
    #[test]
    fn is_empty_reflects_endpoint_count() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let empty_ids: Vec<u64> = Vec::new();
        let empty_sched = HealthScheduler::new(t0, 1, &empty_ids, cfg, 4, true).expect("valid");
        assert!(empty_sched.is_empty());
        assert_eq!(empty_sched.len(), 0);
        empty_sched.debug_assert_consistent();
        // Edge case 1: publish_all on an empty scheduler is a no-op that must
        // not panic.
        empty_sched.publish_all(&ClusterHealth::new(0, 0));

        let ids = vec![1u64];
        let sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        assert!(!sched.is_empty());
        assert_eq!(sched.len(), 1);
        sched.debug_assert_consistent();
    }

    // Not one of the 23 named tests. `cargo mutants` found that replacing
    // `debug_assert_consistent`'s body with `()` survived, because every
    // other test only calls it on states the implementation itself keeps
    // consistent. Mirrors the precedent in `health::wheel`'s own
    // `debug_assert_structure_catches_*` tests: deliberately corrupt a
    // private field into a genuine violation and prove the check fires.
    #[test]
    #[should_panic(expected = "invariant 1")]
    fn debug_assert_consistent_catches_inflight_count_mismatch() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        sched.inflight_count = 5;
        sched.debug_assert_consistent();
    }

    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        reason = "test arithmetic mirrors bounded production formulas"
    )]
    #[test]
    fn no_traffic_interval_used() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64, 2u64, 3u64];
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, false).expect("valid");
        for i in 0..3u32 {
            let d = sched.wheel.deadline_of(i).expect("scheduled");
            assert!(
                d.since(t0) < 60_000,
                "endpoint {i} deadline {d:?} not within the no-traffic window"
            );
        }

        let mut rng = Rng::from_seed(14);
        sched.set_has_traffic(true, t0, &mut rng);

        let edge_iv = cfg.interval_for(IntervalState::Edge);
        let span = (u64::from(edge_iv) * u64::from(cfg.jitter_bp) / 10_000) as u32;
        for i in 0..3u32 {
            let d = sched.wheel.deadline_of(i).expect("scheduled");
            let delta = d.since(t0);
            assert!(
                delta <= edge_iv.saturating_add(span),
                "endpoint {i} deadline delta {delta} exceeds the edge-interval window \
                 {edge_iv} plus jitter {span}"
            );
        }
        sched.debug_assert_consistent();
    }

    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        reason = "test arithmetic mirrors bounded production formulas and bucket indices \
                  are far below usize::MAX"
    )]
    #[test]
    fn set_has_traffic_does_not_herd() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids: Vec<u64> = (0..1000).collect();
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, false).expect("valid");
        sched.debug_assert_consistent();
        let mut rng = Rng::from_seed(15);
        sched.set_has_traffic(true, t0, &mut rng);
        sched.debug_assert_consistent();

        let edge_iv = cfg.interval_for(IntervalState::Edge);
        let span = (u64::from(edge_iv) * u64::from(cfg.jitter_bp) / 10_000) as u32;
        let window = edge_iv.saturating_add(span).saturating_add(10);
        let bucket_count = (window / 10) as usize;
        let mut buckets = vec![0usize; bucket_count.max(1)];
        for i in 0..1000u32 {
            let d = sched.wheel.deadline_of(i).expect("scheduled");
            let delta = d.since(t0);
            let bucket = (delta / 10) as usize;
            if let Some(b) = buckets.get_mut(bucket) {
                *b += 1;
            }
        }
        let max_bucket = buckets.iter().copied().max().unwrap_or(0);
        assert!(
            max_bucket <= 80,
            "bucket holds {max_bucket} endpoints of 1000, exceeding the 8 percent herd threshold"
        );
    }

    #[test]
    fn caps_are_bounded() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let ids = vec![1u64, 2u64];

        let err = expect_config_err(HealthScheduler::new(t0, 1, &ids, cfg, 0, true));
        assert_eq!(err.field, "health_check.max_concurrent_checks");

        let err = expect_config_err(HealthScheduler::new(t0, 1, &ids, cfg, 65_537, true));
        assert_eq!(err.field, "health_check.max_concurrent_checks");

        let too_many: Vec<u64> = (0..=(MAX_ENDPOINTS as u64)).collect();
        let err = expect_config_err(HealthScheduler::new(t0, 1, &too_many, cfg, 4, true));
        assert_eq!(err.field, "cluster.endpoints");

        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        sched.debug_assert_consistent();
        sched.set_defer_ms(0);
        assert_eq!(sched.defer_ms, 1);
        sched.set_defer_ms(u32::MAX);
        assert_eq!(sched.defer_ms, 60_000);
        sched.debug_assert_consistent();

        let mut at_ceiling = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        at_ceiling.debug_assert_consistent();
        at_ceiling.set_max_catchup_ms(u32::MAX);
        at_ceiling.debug_assert_consistent();
        let mut out = Vec::new();
        let stats_at = at_ceiling.wheel.advance(t0.add_ms(60_000), &mut out);
        assert!(
            !stats_at.swept,
            "a gap exactly at the clamped ceiling (60_000) must tick, not sweep"
        );

        let mut past_ceiling = HealthScheduler::new(t0, 1, &ids, cfg, 4, true).expect("valid");
        past_ceiling.debug_assert_consistent();
        past_ceiling.set_max_catchup_ms(u32::MAX);
        past_ceiling.debug_assert_consistent();
        out.clear();
        let stats_past = past_ceiling.wheel.advance(t0.add_ms(60_001), &mut out);
        assert!(
            stats_past.swept,
            "a gap one ms past the clamped ceiling must sweep, proving set_max_catchup_ms \
             forwarded 60_000, not u32::MAX"
        );
    }

    #[test]
    fn clock_jump_bounded_burst() {
        let cfg = all_due_cfg();
        let t0 = Millis(0);
        let ids: Vec<u64> = (0..500).collect();
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 8, true).expect("valid");
        sched.set_max_catchup_ms(100);
        let mut rng = Rng::from_seed(16);
        let mut out = Vec::new();
        let poll_stats = sched.poll_due(t0.add_ms(60_000), &mut rng, &mut out);
        assert!(poll_stats.swept);
        assert_eq!(poll_stats.dispatched, 8);
        assert_eq!(out.len(), 8);
        assert!(poll_stats.deferred >= 1);
        assert_eq!(sched.stats().timer_catchup_clamped, 1);
        sched.debug_assert_consistent();
    }

    #[test]
    fn sweep_rate_matches_interval() {
        let cfg = HealthCheckConfig {
            interval_ms: 2000,
            ..HealthCheckConfig::default()
        };
        let t0 = Millis(0);
        let n: u64 = 1000;
        let ids: Vec<u64> = (0..n).collect();
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 64, true).expect("valid");
        sched.debug_assert_consistent();
        let health = ClusterHealth::new(usize::try_from(n).unwrap_or(0), 0);
        let mut rng = Rng::from_seed(17);

        let mut pending: Vec<(Millis, CheckReport)> = Vec::new();
        let mut checks_per_endpoint = vec![0u32; usize::try_from(n).unwrap_or(0)];
        let mut total_dispatched: u64 = 0;
        let mut max_inflight: u32 = 0;
        let mut out = Vec::new();

        for step in 0..10_000u32 {
            let now = t0.add_ms(step);
            out.clear();
            sched.poll_due(now, &mut rng, &mut out);
            sched.debug_assert_consistent();
            for order in &out {
                total_dispatched += 1;
                if let Some(c) = checks_per_endpoint.get_mut(idx_of(order.endpoint)) {
                    *c += 1;
                }
                pending.push((
                    now.add_ms(5),
                    CheckReport {
                        endpoint: order.endpoint,
                        endpoint_id: order.endpoint_id,
                        outcome: CheckOutcome::Pass,
                        reconnected: false,
                    },
                ));
            }
            max_inflight = max_inflight.max(sched.inflight());

            let mut still_pending = Vec::new();
            for (fire_at, report) in pending.drain(..) {
                if fire_at.is_at_or_before(now) {
                    sched.record(now, report, &mut rng, &health);
                } else {
                    still_pending.push((fire_at, report));
                }
            }
            pending = still_pending;
            sched.debug_assert_consistent();
        }

        // 1000 endpoints over 10 simulated seconds at a 2-second interval:
        // each endpoint is checked 10 / 2 = 5 times, for 5000 total.
        let expected: u64 = 5000;
        assert!(
            total_dispatched * 100 >= expected * 95 && total_dispatched * 100 <= expected * 105,
            "total dispatched {total_dispatched} not within 5% of {expected}"
        );
        for (i, &c) in checks_per_endpoint.iter().enumerate() {
            assert!(
                (4..=6).contains(&c),
                "endpoint {i} checked {c} times, expected 4..=6"
            );
        }
        assert!(max_inflight <= 64);
    }

    /// Reproduces, at a scale the normal test suite can run quickly, the
    /// central defect measured for issue #862: with a fully unresponsive
    /// upstream and a backlog well past `max_concurrent`, the unfixed
    /// concurrency-cap branch collapses the whole backlog onto one shared
    /// deadline every cycle and burns work proportional to the backlog size
    /// on every single poll, instead of the `O(1) + O(dispatched)` average
    /// the module's own design commits to.
    ///
    /// # Why this only asserts the deferred-sum bound
    ///
    /// An earlier version of this test also asserted `seen.len() == 200`
    /// ("every endpoint dispatched at least once by t=125s"). That clause
    /// was withdrawn: it does not test the fix. Measured directly, varying
    /// only `t0` with the fix fully in place (same 200 ids, same cap 8,
    /// same seed, same `125_000` one-millisecond steps): t0=0 -> 200 covered,
    /// t0=1 -> 199, t0=7 -> 200, t0=1000 -> 199, t0=65536 -> 200,
    /// t0=`u32::MAX`-1000 -> 199 and *still* 199 after `200_000` steps. The
    /// residual gap is the known starvation route in issue #896 (a
    /// freshly-reporting endpoint's plain dispatch can keep winning the
    /// concurrency slot ahead of the deferred backlog), which this fix
    /// deliberately does not touch, so 200/200-by-125s is not a property
    /// the fixed scheduler has at every phase: asserting it made the test
    /// pass or fail on a millisecond of `t0`, not on whether the storm was
    /// fixed. Worse, the clause was decorative in the direction that
    /// matters: measured against UNMODIFIED main at `t0 = Millis(0)`,
    /// coverage was also 200/200, so it detected nothing about the defect
    /// this test exists for. (Coverage does vary more on unfixed code
    /// across phase -- as low as 169/200 at some `t0` values -- but that
    /// variation comes from the SAME `t0`-dependent scheduling accident,
    /// not from anything this fix changes, so building an assertion on it
    /// would still be measuring phase, not the storm.)
    ///
    /// The deferred-sum bound is the one clause that actually discriminates,
    /// at every phase: looping `t0` over 0, 1, 7, 137, `1_000`, `65_536` and
    /// `u32::MAX - 1_000` (the last one crosses the `u32` wraparound
    /// partway through the run), fixed code's `total_deferred` over the
    /// 125s window is stable at 125,122-125,125 regardless of phase, while
    /// unmodified main's is 4,495,153-4,512,041 -- roughly 36x higher at
    /// every phase tested, not just the one this test used to hardcode.
    ///
    /// # Why `250_000`, not `1_000_000`
    ///
    /// The original `1_000_000` bound is not vacuous -- it fails on main
    /// (~4.5M, above) and killed every hand-built mutation that restores
    /// the collapse -- but it has a measured dead zone: a plausible future
    /// "cap the cursor lead" guard (`|| self.defer_cursor.since(now) >
    /// 100` added to the resync condition) gives 415,205 deferred with
    /// full coverage, and the same at `> 50` gives 809,210; both are
    /// 3.3x/6.5x regressions in the exact quantity this test bounds, and
    /// both stayed under `1_000_000`. `250_000` sits at 2x the fixed
    /// value's stable ceiling (comfortable headroom against ordinary
    /// variance) while sitting below both dead-zone mutants, so it closes
    /// that window without asserting a number tighter than what was
    /// actually measured to be stable.
    #[test]
    fn deferral_does_not_storm_under_overload() {
        // Looped over several phases, including one that straddles the
        // `u32` millisecond wraparound, because the property below is only
        // a genuine regression guard if it holds regardless of `t0`; see
        // this test's doc comment for why a single hardcoded `t0 =
        // Millis(0)` previously let a phase-dependent coverage clause ship
        // as if it discriminated the fix when it did not.
        for &t0 in &[
            Millis(0),
            Millis(1),
            Millis(7),
            Millis(137),
            Millis(1_000),
            Millis(65_536),
            Millis(u32::MAX - 1_000),
        ] {
            let cfg = HealthCheckConfig::default();
            let ids: Vec<u64> = (0..200).collect();
            let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 8, true).expect("valid");
            let mut rng = Rng::from_seed(862);
            let health = ClusterHealth::new(200, 0);
            let mut out = Vec::new();
            let mut pending: Vec<(Millis, CheckReport)> = Vec::new();
            let mut total_deferred: u64 = 0;

            for step in 1..=125_000u32 {
                let now = t0.add_ms(step);

                // The fully unresponsive upstream: every dispatched check
                // reports `Fail(Timeout)` exactly `timeout_ms` after dispatch,
                // which is precisely `order.deadline`.
                let mut still_pending = Vec::new();
                for (fire_at, report) in pending.drain(..) {
                    if fire_at.is_at_or_before(now) {
                        sched.record(now, report, &mut rng, &health);
                    } else {
                        still_pending.push((fire_at, report));
                    }
                }
                pending = still_pending;

                out.clear();
                let stats = sched.poll_due(now, &mut rng, &mut out);
                total_deferred += u64::from(stats.deferred);
                for order in out.drain(..) {
                    pending.push((
                        order.deadline,
                        CheckReport {
                            endpoint: order.endpoint,
                            endpoint_id: order.endpoint_id,
                            outcome: CheckOutcome::Fail(FailKind::Timeout),
                            reconnected: false,
                        },
                    ));
                }
            }

            assert!(
                total_deferred < 250_000,
                "t0={t0:?}: deferred sum {total_deferred} over 125s is not within a \
                 controlled multiple of the endpoint count: unmodified main produces \
                 4,495,153-4,512,041 over an identical scenario across the same phases \
                 (measured on this same clone), and a plausible future \"cap the cursor \
                 lead\" guard produces 415,205 (at 100ms) or 809,210 (at 50ms) with full \
                 coverage, so this bound rules out both the O(backlog)-per-poll storm and \
                 that dead zone while the fixed value (125,122-125,125, stable across every \
                 phase tested) still clears it with 2x headroom"
            );
        }
    }

    /// Edge case 2: a long idle gap where nothing is ever deferred, followed
    /// by a new bout of overload, must resync `defer_cursor` to the NEW
    /// `now` rather than continuing to hand out deadlines anchored to
    /// whatever `now` was in effect the last time anything was deferred.
    ///
    /// Uses `all_due_cfg()` with `max_checks_per_endpoint_per_sec` raised
    /// only enough (1, from its default 1000) to floor every interval at
    /// 1000 ms instead of 1 ms: comfortably above `defer_ms` (5), so a
    /// just-reported endpoint's own next check cannot race a near-term
    /// deferred backlog the way `all_due_cfg()`'s bare 1 ms floor would. See
    /// issue #896, which hits exactly that unrelated interaction: with the
    /// bare 1 ms floor, a freshly-reporting endpoint's own plain dispatch
    /// keeps winning `max_concurrent`'s single slot ahead of the
    /// concurrency-cap-deferred backlog every time, which is why the
    /// strict-FIFO test issue #862's edge case 1 originally named
    /// (`deferred_backlog_is_fair_under_single_concurrency`) was withdrawn
    /// as unsatisfiable rather than implemented, and why this test raises
    /// the rate cap instead of using the bare floor.
    #[test]
    fn defer_cursor_resyncs_after_idle_gap() {
        let mut cfg = all_due_cfg();
        cfg.max_checks_per_endpoint_per_sec = 1;
        let t0 = Millis(0);
        let ids: Vec<u64> = (0..4).collect();
        let mut sched = HealthScheduler::new(t0, 1, &ids, cfg, 1, true).expect("valid");
        let mut rng = Rng::from_seed(862);
        let health = ClusterHealth::new(4, 0);
        let mut out = Vec::new();

        // Every endpoint's phase falls inside [0, 1000); push them all due
        // at once and force the other three through the concurrency-cap
        // deferral path with `max_concurrent = 1`. This is the last poll
        // that touches `defer_cursor` until the post-gap poll below.
        let mut now = t0.add_ms(1_500);
        let stats1 = sched.poll_due(now, &mut rng, &mut out);
        assert_eq!(
            stats1.dispatched, 1,
            "exactly one endpoint fits the concurrency cap"
        );
        assert_eq!(
            stats1.deferred, 3,
            "the other three must be deferred, not dropped"
        );

        // Report every outstanding check and keep polling forward one
        // millisecond at a time until a poll produces neither a dispatch nor
        // a deferral with nothing in flight: the genuinely idle state edge
        // case 2 requires before the gap. The three endpoints deferred above
        // are not yet due (their cursor deadlines are a few ms ahead) and
        // the just-reported endpoint's own next check is ~1000 ms out, so
        // this reaches quiescence almost immediately; the loop bound is
        // generous headroom, not an expectation of many iterations.
        let mut pending_orders: Vec<CheckOrder> = std::mem::take(&mut out);
        let mut quiescent = false;
        for _ in 0..2_100u32 {
            for order in pending_orders.drain(..) {
                let report = CheckReport {
                    endpoint: order.endpoint,
                    endpoint_id: order.endpoint_id,
                    outcome: CheckOutcome::Pass,
                    reconnected: false,
                };
                sched.record(now, report, &mut rng, &health);
            }
            now = now.add_ms(1);
            out.clear();
            let stats = sched.poll_due(now, &mut rng, &mut out);
            pending_orders = std::mem::take(&mut out);
            if stats.dispatched == 0 && stats.deferred == 0 && sched.inflight() == 0 {
                quiescent = true;
                break;
            }
        }
        assert!(
            quiescent,
            "the scheduler must reach a genuinely idle poll (nothing dispatched, nothing \
             deferred, nothing in flight) before the gap"
        );

        // A long idle gap: 10 simulated minutes with `defer_cursor` never
        // touched, since nothing becomes due or deferred during it.
        now = now.add_ms(10 * 60 * 1000);
        out.clear();
        let post_gap_stats = sched.poll_due(now, &mut rng, &mut out);

        // Every endpoint's own schedule (the just-reported one's ~1000 ms
        // reschedule, and the three original deferred deadlines a handful
        // of ms past `now1`) is now far in the past relative to `now`, so
        // all four come due together: with `max_concurrent = 1`, one
        // dispatches and three are deferred fresh, right after the gap.
        assert_eq!(post_gap_stats.dispatched, 1);
        assert_eq!(post_gap_stats.deferred, 3);

        // Every one of the four endpoints' wheel deadlines, dispatched or
        // deferred, must land close to the NEW `now`: `TimerWheel::schedule`
        // collapses ANY deadline at or before its current time to `now + 1`
        // on its own (see its doc comment), which alone would make a merely
        // "close to now" check pass even for a cursor that was left
        // completely untouched through the gap, so it is not by itself
        // proof the cursor resynced. `defer_ms` is 5 by default; the
        // dispatched endpoint's own watchdog lands at `now + timeout_ms(1) +
        // defer_ms(5) = now + 6`, so every deadline must land within
        // `defer_ms` plus the endpoint count (4) of `now`.
        let dispatched_id = out.first().map(|o| o.endpoint_id);
        let mut deferred_deadlines: Vec<Millis> = Vec::new();
        for (i, &id) in ids.iter().enumerate() {
            let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
            let deadline = sched
                .wheel
                .deadline_of(i_u32)
                .expect("every endpoint must always be scheduled in the wheel");
            let delta = deadline.since(now);
            assert!(
                delta <= 5 + 4,
                "endpoint {i} deadline is {delta} ms after the post-gap `now`, more than \
                 defer_ms (5) plus the endpoint count (4): it looks anchored to the stale \
                 pre-gap cursor instead of resyncing to the new `now`"
            );
            if Some(id) != dispatched_id {
                deferred_deadlines.push(deadline);
            }
        }

        // The property a "close to now" check alone cannot catch: a cursor
        // left stale through the gap (never resynced) still produces
        // deadlines close to `now`, because `TimerWheel::schedule`'s own
        // past-deadline clamp independently collapses each of the three
        // stale, pre-gap cursor values to `now + 1`, reproducing the exact
        // shared-deadline storm this whole issue is about through a
        // different door. Verified directly against a scheduler with the
        // resync check (`is_at_or_before`) removed but the cursor's
        // increment kept: run against this exact scenario, it deferred all
        // three to the SAME instant (601505 for every one of them), not
        // three distinct ones. A correctly resyncing cursor cannot produce
        // that: three endpoints deferred in the same `poll_due` call always
        // get three distinct, strictly increasing cursor values.
        deferred_deadlines.sort_unstable_by_key(|m| m.0);
        deferred_deadlines.dedup();
        assert_eq!(
            deferred_deadlines.len(),
            3,
            "the three newly deferred endpoints must receive three DISTINCT deadlines; fewer \
             than three means at least two collapsed onto the same instant, which is the \
             pre-#862 storm reproduced through a stale, unresynced cursor"
        );
        sched.debug_assert_consistent();
    }
}
