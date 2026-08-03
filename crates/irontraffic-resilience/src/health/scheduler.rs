// SPDX-License-Identifier: MIT OR Apache-2.0

//! `HealthScheduler`: the one active health checker per process.
//!
//! A sans-IO state machine that drives the timer wheel, emits [`CheckOrder`] values
//! when endpoints are due, accepts [`CheckReport`] values, applies hysteresis, and
//! publishes the result into [`ClusterHealth`]. It enforces both the global
//! in-flight check cap (`max_concurrent`) and the per-endpoint probe rate cap by
//! DEFERRING a due endpoint in the wheel rather than starting more work than the
//! cap allows: an excess check is rescheduled a few milliseconds later, never held
//! in an unbounded queue. It exists because per-worker health checking multiplies
//! the aggregate probe rate by the worker count, and because a serial sweep and a
//! fully concurrent sweep are both wrong: one starves at scale, the other creates a
//! connection storm against the very upstream being probed.
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
//! When `max_concurrent` is reached, a due endpoint is rescheduled a few
//! milliseconds later and `SchedulerStats::checks_deferred` is incremented. It is
//! never pushed into a pending list: a list under sustained overload grows without
//! bound and delivers checks in an order unrelated to their deadlines, while the
//! wheel already is the queue and rescheduling keeps the endpoint's place in time.

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
            instance_id,
            has_traffic,
            due_scratch: Vec::with_capacity(len),
            stats: SchedulerStats::default(),
        })
    }

    /// Advance the wheel to `now` and append every check that must run to `out`.
    ///
    /// `out` is not cleared. Never emits two orders for one endpoint concurrently,
    /// and never exceeds `max_concurrent` in flight.
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
                let at = now.add_ms(self.defer_ms);
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

    /// Milliseconds a due-but-undispatchable endpoint is pushed out by. Default 5.
    /// CLAMPED to `1..=60_000`. Control task only.
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
    /// # Errors
    /// Returns [`ConfigError`] naming `cluster.endpoints` when `endpoint_ids` has
    /// more than [`MAX_ENDPOINTS`] entries, or contains a duplicate. Applies the
    /// same two checks [`HealthScheduler::new`] applies, in the same order,
    /// because a membership update arrives from discovery on every pod churn and
    /// must not be the lenient path.
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

        for (i, &id) in endpoint_ids.iter().enumerate() {
            new_ids.push(id);
            let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
            if let Some(&j) = old.get(&id) {
                let carried = self.sched.get(j).copied().unwrap_or_else(|| {
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
                // An outstanding `CheckOrder` the runner is holding still
                // names the endpoint's OLD index `j`. When the index has not
                // moved (`i == j`), the runner's eventual report still
                // arrives addressed to the right slot and the existing id
                // guard in `record` accepts it normally, so the in-flight
                // bit, `dispatched_at`, and `stuck` are safe to carry. When
                // the index HAS moved, that report will be addressed to `j`,
                // which after this rebuild names a different endpoint (or is
                // out of range), so `record` will discard it as
                // `reports_for_unknown_endpoint` and nothing would ever
                // clear an in-flight bit carried forward to `i`: the
                // endpoint would be permanently stuck as "already in
                // flight" and never dispatched again. Reset instead: the
                // endpoint loses at most that one outstanding check and
                // becomes dispatchable again on its own normal schedule via
                // the wheel entry armed at `carried.nominal` below.
                let index_moved = i != j;
                let carried_inflight =
                    !index_moved && self.inflight.get(j).copied().unwrap_or(false);
                new_inflight.push(carried_inflight);
                new_dispatched_at.push(if index_moved {
                    Millis(0)
                } else {
                    self.dispatched_at.get(j).copied().unwrap_or(Millis(0))
                });
                new_stuck.push(if index_moved {
                    false
                } else {
                    self.stuck.get(j).copied().unwrap_or(false)
                });
                if carried_inflight {
                    inflight_count = inflight_count.saturating_add(1);
                }
                let _ = self.wheel.schedule(i_u32, carried.nominal); // it-allow: no-swallowed-error reason: i is bounded by new_len <= MAX_ENDPOINTS, which never exceeds the wheel's fixed max_ids ceiling, so neither WheelError variant is reachable here.
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

        self.sched = new_sched;
        self.endpoint_ids = new_ids;
        self.ejected = new_ejected;
        self.ramping = new_ramping;
        self.draining = new_draining;
        self.inflight = new_inflight;
        self.dispatched_at = new_dispatched_at;
        self.stuck = new_stuck;
        self.inflight_count = inflight_count;

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
        sched.debug_assert_consistent();

        // Remove id 20 from the middle: id 30 moves from index 2 to index 1
        // while its check is still in flight and marked stuck.
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
        sched.debug_assert_consistent();

        // A subsequent dispatch must behave exactly like a freshly
        // scheduled endpoint: it becomes due on its own schedule and
        // dispatches a fresh order.
        out.clear();
        let redispatch = sched.poll_due(past_threshold.add_ms(1), &mut rng, &mut out);
        assert_eq!(
            redispatch.dispatched, 1,
            "the moved endpoint must dispatch a fresh order once due again"
        );
        let fresh_order = out.first().copied().expect("one fresh order");
        assert_eq!(fresh_order.endpoint, EndpointIdx(1));
        assert_eq!(fresh_order.endpoint_id, 30);
        sched.debug_assert_consistent();

        // One millisecond after the fresh dispatch, the stuck detector must
        // not immediately re-trip: `dispatched_at` must be the fresh
        // timestamp, not the pre-rebuild stale one.
        out.clear();
        let immediate_repoll = sched.poll_due(past_threshold.add_ms(2), &mut rng, &mut out);
        assert!(
            out.is_empty(),
            "the freshly dispatched endpoint must not get a second order one millisecond later"
        );
        assert_eq!(immediate_repoll.dispatched, 0);
        assert_eq!(
            sched.stuck.get(1).copied(),
            Some(false),
            "one millisecond after a fresh dispatch must never re-trip the stuck detector"
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
}
