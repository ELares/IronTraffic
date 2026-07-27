// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure active health-check scheduling policy.
//!
//! This module contains no I/O, no clock read, and no allocation on any per-check
//! path. It is owned and called by the single control task in
//! `health-check-scheduler-core` (#93).
//!
//! The design is deliberately different from the obvious `next = now + interval +
//! rand(0, jitter)`: the per-endpoint phase is a deterministic function of
//! `(instance_id, endpoint_id)`, which spreads probes uniformly by construction,
//! while a small symmetric jitter only blurs fire times and is never accumulated
//! into the nominal schedule.
//!
//! # Security note
//!
//! The phase function and the jitter generator are public algorithms. The jitter
//! is not a defense against a dishonest backend; it exists only to break ties from
//! hash collisions and to blur, not hide, the probe schedule. Active health
//! checking detects a broken backend, not a lying one. Passive outlier detection
//! (#97) handles a backend that answers probes selectively.
//!
//! `instance_id` must be seeded from the OS CSPRNG at process startup. It must not
//! be derived from a hostname, pod name, `StatefulSet` ordinal, IP address, or any
//! other public low-entropy value. Tests pass fixed values on purpose; production
//! must not.

use crate::clock::Millis;
use crate::config::{ConfigError, in_range_u32, ordered_u32};
use crate::health::bitmap::EndpointHealth;
use crate::rng::symmetric_jitter_ms;
use irontraffic_rand::{Rng, split_mix64};

/// Active health-check policy for one cluster.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HealthCheckConfig {
    /// Steady-state interval. Default 2000, matching HAProxy's `inter`.
    pub interval_ms: u32,
    /// Interval for the single check after any state transition. Default `interval/4`.
    pub edge_interval_ms: u32,
    /// Interval while the endpoint is failing. Default `interval`.
    pub unhealthy_interval_ms: u32,
    /// Interval for a cluster that has never received a request. Default `60_000`.
    pub no_traffic_interval_ms: u32,
    /// Per-check timeout. Default `1000`. Must not exceed `interval_ms`.
    pub timeout_ms: u32,
    /// Symmetric jitter as a fraction of the interval, in basis points. Default `500`
    /// (5%). Capped at `5_000` (50%) by validation.
    pub jitter_bp: u16,
    /// Consecutive passes required to mark an endpoint healthy. Default 2 (HAProxy `rise`).
    pub healthy_threshold: u32,
    /// Consecutive failures required to mark an endpoint unhealthy. Default 3 (HAProxy `fall`).
    pub unhealthy_threshold: u32,
    /// Force a fresh connection every N checks. Default 10. Zero means never, which is
    /// the Envoy behaviour and is documented as unsafe.
    pub reconnect_every: u32,
    /// Hard ceiling on probes per endpoint per second. Default 4. A configured
    /// interval that would exceed it is stretched, not obeyed.
    pub max_checks_per_endpoint_per_sec: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval_ms: 2000,
            edge_interval_ms: 500,
            unhealthy_interval_ms: 2000,
            no_traffic_interval_ms: 60_000,
            timeout_ms: 1000,
            jitter_bp: 500,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            reconnect_every: 10,
            max_checks_per_endpoint_per_sec: 4,
        }
    }
}

impl HealthCheckConfig {
    /// Validate every field against invariant 10. Returns the first violation.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] naming the first rejected field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        in_range_u32(
            "health.interval_ms",
            self.interval_ms,
            1,
            Millis::HORIZON_MS,
        )?;
        in_range_u32(
            "health.edge_interval_ms",
            self.edge_interval_ms,
            1,
            Millis::HORIZON_MS,
        )?;
        in_range_u32(
            "health.unhealthy_interval_ms",
            self.unhealthy_interval_ms,
            1,
            Millis::HORIZON_MS,
        )?;
        in_range_u32(
            "health.no_traffic_interval_ms",
            self.no_traffic_interval_ms,
            1,
            Millis::HORIZON_MS,
        )?;
        in_range_u32("health.timeout_ms", self.timeout_ms, 1, Millis::HORIZON_MS)?;
        ordered_u32(
            "health.timeout_ms",
            self.timeout_ms,
            "health.interval_ms",
            self.interval_ms,
        )?;
        in_range_u32("health.jitter_bp", u32::from(self.jitter_bp), 0, 5_000)?;
        in_range_u32("health.healthy_threshold", self.healthy_threshold, 1, 254)?;
        in_range_u32(
            "health.unhealthy_threshold",
            self.unhealthy_threshold,
            1,
            254,
        )?;
        in_range_u32(
            "health.max_checks_per_endpoint_per_sec",
            self.max_checks_per_endpoint_per_sec,
            1,
            1000,
        )?;
        Ok(())
    }

    /// The steady interval after the per-endpoint rate cap is applied, and whether the
    /// configured interval was stretched. Log the stretch once per cluster at WARN.
    #[must_use]
    pub fn effective_interval_ms(&self) -> (u32, bool) {
        let steady = self.interval_for(IntervalState::Steady);
        (steady, self.interval_ms < steady)
    }

    /// The interval for one scheduling state, floored by the per-endpoint rate cap.
    #[must_use]
    pub fn interval_for(&self, state: IntervalState) -> u32 {
        let cap = self.max_checks_per_endpoint_per_sec.max(1);
        let sustained_floor = 1000u32.div_ceil(cap);
        let edge_floor = 500u32.div_ceil(cap);
        match state {
            IntervalState::Steady => self.interval_ms.max(sustained_floor),
            IntervalState::Down => self.unhealthy_interval_ms.max(1).max(sustained_floor),
            IntervalState::NoTraffic => self.no_traffic_interval_ms.max(1).max(sustained_floor),
            IntervalState::Edge => self.edge_interval_ms.max(1).max(edge_floor),
        }
    }
}

/// Which of the four intervals applies to an endpoint right now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum IntervalState {
    /// Healthy and stable.
    Steady = 0,
    /// The single check after any state transition.
    Edge = 1,
    /// Currently failing.
    Down = 2,
    /// The cluster has never received a request.
    NoTraffic = 3,
}

/// Why a check failed. Only `RetriableStatus` changes scheduling behaviour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FailKind {
    /// TCP connect failed or timed out.
    Connect,
    /// The check exceeded `timeout_ms`.
    Timeout,
    /// The TLS handshake failed.
    Tls,
    /// The response status was outside `expected_statuses`.
    Status,
    /// The response body did not match the configured `receive` patterns.
    Body,
    /// The response was not parseable, or the stream ended early.
    Protocol,
    /// The status was in `retriable_statuses`: counts toward the threshold, and the
    /// next check runs at the edge interval.
    RetriableStatus,
}

/// The result of one check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckOutcome {
    /// The endpoint answered as configured.
    Pass,
    /// The endpoint did not.
    Fail(FailKind),
}

/// Whether applying an outcome crossed a hysteresis threshold.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transition {
    /// No threshold crossed.
    None,
    /// The endpoint became healthy.
    ToHealthy,
    /// The endpoint became unhealthy.
    ToUnhealthy,
}

/// Per-endpoint active-check scheduling and hysteresis state. 32 bytes, `Copy`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EndpointSchedule {
    /// `t0 + k*interval + phase`, with no jitter accumulated. Jitter is applied to the
    /// fire time only, so this never drifts.
    pub nominal: Millis,
    /// Which interval applies next.
    pub interval_state: IntervalState,
    /// What ACTIVE checking believes about this endpoint. The published bitmap value is
    /// the more severe of this and the outlier-ejection state.
    pub active_health: EndpointHealth,
    /// Consecutive passes since the last failure.
    pub consecutive_ok: u32,
    /// Consecutive failures since the last pass.
    pub consecutive_fail: u32,
    /// Checks performed on the current connection.
    pub checks_since_reconnect: u32,
    /// Total checks dispatched, for metrics and for tests.
    pub checks_started: u64,
}

impl EndpointSchedule {
    /// Initial state for an endpoint, with its deterministic phase applied.
    ///
    /// Starts `Healthy`: starting unhealthy would black-hole a freshly scaled endpoint
    /// for `healthy_threshold * interval` milliseconds.
    #[must_use]
    pub fn init(
        t0: Millis,
        instance_id: u64,
        endpoint_id: u64,
        cfg: &HealthCheckConfig,
        has_traffic: bool,
    ) -> Self {
        let (eff, _) = cfg.effective_interval_ms();
        let phase = phase_ms(instance_id, endpoint_id, eff);
        let interval_state = if has_traffic {
            IntervalState::Steady
        } else {
            IntervalState::NoTraffic
        };
        Self {
            nominal: t0.add_ms(phase),
            interval_state,
            active_health: EndpointHealth::Healthy,
            consecutive_ok: 0,
            consecutive_fail: 0,
            checks_since_reconnect: 0,
            checks_started: 0,
        }
    }

    /// Absolute time to dispatch the next check: `nominal` plus symmetric jitter,
    /// clamped to at least `now + 1`.
    #[must_use]
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "validated bounds keep span and positive delta in range; division by 10_000 is the policy-defined basis-point conversion"
    )]
    pub fn fire_at(&self, now: Millis, cfg: &HealthCheckConfig, rng: &mut Rng) -> Millis {
        let interval = cfg.interval_for(self.interval_state);
        let span = (u64::from(interval) * u64::from(cfg.jitter_bp) / 10_000) as u32; // it-allow: unchecked-cast reason: interval and jitter_bp are validated so the quotient is at most (HORIZON_MS * 5000) / 10000, which fits in u32
        let delta = symmetric_jitter_ms(rng, span);
        let at = if delta >= 0 {
            self.nominal.add_ms(delta as u32) // it-allow: unchecked-cast reason: delta is non-negative here and at most span, which fits in u32
        } else {
            Millis(self.nominal.0.wrapping_sub(delta.unsigned_abs()))
        };
        if at.is_at_or_before(now) {
            now.add_ms(1)
        } else {
            at
        }
    }

    /// Move `nominal` forward by one interval of the current state, re-basing on `now`
    /// when the control task fell behind so that a starved checker does not burst.
    pub fn advance_nominal(&mut self, now: Millis, cfg: &HealthCheckConfig) {
        let iv = cfg.interval_for(self.interval_state);
        self.nominal = self.nominal.add_ms(iv);
        if self.nominal.is_at_or_before(now) {
            self.nominal = now.add_ms(iv);
        }
    }

    /// Apply one outcome, updating the counters and possibly crossing a threshold.
    pub fn apply_outcome(&mut self, outcome: CheckOutcome, cfg: &HealthCheckConfig) -> Transition {
        self.checks_since_reconnect = self.checks_since_reconnect.saturating_add(1);
        match outcome {
            CheckOutcome::Pass => {
                self.consecutive_fail = 0;
                self.consecutive_ok = self.consecutive_ok.saturating_add(1);
                if self.active_health != EndpointHealth::Healthy
                    && self.consecutive_ok >= cfg.healthy_threshold
                {
                    self.active_health = EndpointHealth::Healthy;
                    self.consecutive_ok = 0;
                    self.interval_state = IntervalState::Edge;
                    return Transition::ToHealthy;
                }
                if self.interval_state == IntervalState::Edge {
                    self.interval_state = if self.active_health == EndpointHealth::Healthy {
                        IntervalState::Steady
                    } else {
                        IntervalState::Down
                    };
                }
                Transition::None
            }
            CheckOutcome::Fail(kind) => {
                self.consecutive_ok = 0;
                self.consecutive_fail = self.consecutive_fail.saturating_add(1);
                if self.active_health == EndpointHealth::Healthy
                    && self.consecutive_fail >= cfg.unhealthy_threshold
                {
                    self.active_health = EndpointHealth::Unhealthy;
                    self.consecutive_fail = 0;
                    self.interval_state = IntervalState::Edge;
                    return Transition::ToUnhealthy;
                }
                if kind == FailKind::RetriableStatus {
                    self.interval_state = IntervalState::Edge;
                    return Transition::None;
                }
                if self.interval_state == IntervalState::Edge {
                    self.interval_state = if self.active_health == EndpointHealth::Healthy {
                        IntervalState::Steady
                    } else {
                        IntervalState::Down
                    };
                }
                Transition::None
            }
        }
    }

    /// True when the next check must open a fresh connection.
    #[must_use]
    pub fn should_reconnect(&self, cfg: &HealthCheckConfig) -> bool {
        cfg.reconnect_every != 0 && self.checks_since_reconnect >= cfg.reconnect_every
    }

    /// Reset the reconnect counter. Call only when a fresh connection was actually
    /// opened.
    pub fn note_reconnected(&mut self) {
        self.checks_since_reconnect = 0;
    }

    /// Increment `checks_started`. Call when a check is dispatched, not when it
    /// completes.
    pub fn note_dispatched(&mut self) {
        self.checks_started = self.checks_started.saturating_add(1);
    }

    /// Switch between the traffic and no-traffic schedules. Called when a cluster
    /// receives its first request or goes idle.
    ///
    /// `has_traffic = true` moves `NoTraffic` to `Edge` and leaves any other state
    /// alone; `has_traffic = false` moves ANY state to `NoTraffic`. `nominal` is never
    /// touched; the caller reschedules with [`EndpointSchedule::fire_at`].
    pub fn set_has_traffic(&mut self, has_traffic: bool) {
        if has_traffic {
            if self.interval_state == IntervalState::NoTraffic {
                self.interval_state = IntervalState::Edge;
            }
        } else {
            self.interval_state = IntervalState::NoTraffic;
        }
    }
}

/// The deterministic phase offset for one endpoint, uniform on `[0, interval_ms)`.
///
/// `instance_id` is this process's identity, so two proxies checking the same endpoint
/// choose different phases with no coordination. Deterministic: no clock and no RNG,
/// which is what makes the schedule reproducible in tests.
///
/// `instance_id` MUST be seeded from the OS CSPRNG once at process start, never from a
/// hostname, a pod name, a `StatefulSet` ordinal, an IP address, or any other public
/// low-entropy value. This function and the plus-or-minus 5% jitter are public
/// algorithms; if `instance_id` is guessable then every probe time in the fleet is
/// computable by anyone, including by the backend being probed, and it survives
/// restarts. Even with a random `instance_id` this is defense in depth and not a
/// guarantee: a backend can observe its own probe arrivals and learn the phase
/// empirically within a few intervals. Active checking detects a broken backend, not a
/// lying one; that is passive outlier detection's job.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    reason = "the multiply-shift reduction guarantees the result fits in u32"
)]
pub fn phase_ms(instance_id: u64, endpoint_id: u64, interval_ms: u32) -> u32 {
    let mut s = instance_id ^ endpoint_id;
    let h = split_mix64(&mut s);
    let hi = h >> 32;
    ((hi * u64::from(interval_ms)) >> 32) as u32 // it-allow: unchecked-cast reason: multiply-shift reduction of the high 32 bits times a u32 interval produces a value in [0, interval_ms), which fits in u32
}

// Size invariant from the design: 32 bytes per endpoint so 50,000 endpoints is 1.6 MB.
const _: () = assert!(core::mem::size_of::<EndpointSchedule>() == 32);

#[cfg(test)]
mod tests {
    #![allow(
        clippy::field_reassign_with_default,
        clippy::integer_division,
        clippy::manual_abs_diff,
        clippy::manual_range_contains,
        clippy::maybe_infinite_iter,
        reason = "tests use straightforward fixture construction and bounded arithmetic"
    )]

    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = HealthCheckConfig::default();
        assert_eq!(cfg.interval_ms, 2000);
        assert_eq!(cfg.edge_interval_ms, 500);
        assert_eq!(cfg.unhealthy_interval_ms, 2000);
        assert_eq!(cfg.no_traffic_interval_ms, 60_000);
        assert_eq!(cfg.timeout_ms, 1000);
        assert_eq!(cfg.jitter_bp, 500);
        assert_eq!(cfg.healthy_threshold, 2);
        assert_eq!(cfg.unhealthy_threshold, 3);
        assert_eq!(cfg.reconnect_every, 10);
        assert_eq!(cfg.max_checks_per_endpoint_per_sec, 4);
    }

    #[test]
    fn validate_accepts_defaults() {
        assert!(HealthCheckConfig::default().validate().is_ok());
    }

    #[test]
    fn validate_rejects_each_violation() {
        let base = HealthCheckConfig::default();

        let mut c = base;
        c.interval_ms = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.interval_ms");

        let mut c = base;
        c.edge_interval_ms = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.edge_interval_ms");

        let mut c = base;
        c.unhealthy_interval_ms = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.unhealthy_interval_ms");

        let mut c = base;
        c.no_traffic_interval_ms = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.no_traffic_interval_ms");

        let mut c = base;
        c.timeout_ms = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.timeout_ms");

        let mut c = base;
        c.timeout_ms = 3000;
        c.interval_ms = 2000;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.timeout_ms");

        let mut c = base;
        c.jitter_bp = 5001;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.jitter_bp");

        let mut c = base;
        c.healthy_threshold = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.healthy_threshold");

        let mut c = base;
        c.healthy_threshold = 255;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.healthy_threshold");

        let mut c = base;
        c.unhealthy_threshold = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.unhealthy_threshold");

        let mut c = base;
        c.unhealthy_threshold = 255;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.unhealthy_threshold");

        let mut c = base;
        c.max_checks_per_endpoint_per_sec = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.max_checks_per_endpoint_per_sec");

        let mut c = base;
        c.interval_ms = Millis::HORIZON_MS + 1;
        let err = c.validate().unwrap_err();
        assert_eq!(err.field, "health.interval_ms");
    }

    #[test]
    fn validate_rejects_absurd_cap() {
        let mut c = HealthCheckConfig::default();
        c.max_checks_per_endpoint_per_sec = 1001;
        assert!(c.validate().is_err());

        let mut c = HealthCheckConfig::default();
        c.max_checks_per_endpoint_per_sec = u32::MAX;
        assert!(c.validate().is_err());
    }

    #[test]
    fn effective_interval_stretches() {
        let mut c = HealthCheckConfig::default();
        c.interval_ms = 100;
        assert_eq!(c.effective_interval_ms(), (250, true));

        c.interval_ms = 2000;
        assert_eq!(c.effective_interval_ms(), (2000, false));

        c.interval_ms = 250;
        assert_eq!(c.effective_interval_ms(), (250, false));
    }

    #[test]
    fn rate_cap_floors_every_state() {
        let mut c = HealthCheckConfig::default();
        c.interval_ms = 1;
        c.edge_interval_ms = 1;
        c.unhealthy_interval_ms = 1;
        c.no_traffic_interval_ms = 1;
        assert_eq!(c.interval_for(IntervalState::Steady), 250);
        assert_eq!(c.interval_for(IntervalState::Down), 250);
        assert_eq!(c.interval_for(IntervalState::NoTraffic), 250);
        assert_eq!(c.interval_for(IntervalState::Edge), 125);

        c.max_checks_per_endpoint_per_sec = 1;
        assert_eq!(c.interval_for(IntervalState::Steady), 1000);
        assert_eq!(c.interval_for(IntervalState::Down), 1000);
        assert_eq!(c.interval_for(IntervalState::NoTraffic), 1000);
        assert_eq!(c.interval_for(IntervalState::Edge), 500);
    }

    #[test]
    fn phase_in_range_and_deterministic() {
        for e in 0..10_000 {
            let p = phase_ms(1, e, 2000);
            assert!(p < 2000);
            assert_eq!(phase_ms(1, e, 2000), p);
        }
    }

    #[test]
    fn phase_pins_known_value() {
        // Value produced by the implementation and reviewed, not derived by hand.
        assert_eq!(phase_ms(0, 0, 2000), 1766);
    }

    #[test]
    fn phase_spread_is_uniform() {
        let mut buckets = [0usize; 10];
        for e in 0..10_000 {
            let p = phase_ms(1, e, 1000);
            buckets[(p / 100) as usize] += 1;
        }
        for &count in &buckets {
            assert!(
                count >= 800 && count <= 1200,
                "bucket count {count} out of range"
            );
        }
    }

    #[test]
    fn phase_differs_across_instances() {
        let mut collisions = 0usize;
        for e in 0..1000 {
            let a = phase_ms(1, e, 2000);
            let b = phase_ms(2, e, 2000);
            if a == b {
                collisions += 1;
            }
        }
        assert!(collisions < 5, "{collisions} collisions");
    }

    #[test]
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        reason = "test arithmetic mirrors bounded production formulas"
    )]
    fn fire_at_within_jitter_span() {
        let cfg = HealthCheckConfig::default();
        let sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        let mut rng = Rng::from_seed(0x5eed);
        let interval = cfg.interval_for(IntervalState::Steady);
        let span = (u64::from(interval) * u64::from(cfg.jitter_bp) / 10_000) as u32;
        for _ in 0..1000 {
            let at = sched.fire_at(Millis(0), &cfg, &mut rng);
            let diff = if at.0 >= sched.nominal.0 {
                at.0 - sched.nominal.0
            } else {
                sched.nominal.0 - at.0
            };
            assert!(diff <= span, "fire time {diff} ms outside span {span}");
            assert!(at.since(Millis(0)) >= 1);
        }
    }

    #[test]
    fn fire_at_zero_jitter_is_nominal() {
        let mut cfg = HealthCheckConfig::default();
        cfg.jitter_bp = 0;
        let sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        let mut rng = Rng::from_seed(0x5eed);
        let at = sched.fire_at(Millis(0), &cfg, &mut rng);
        assert_eq!(at, sched.nominal);
    }

    #[test]
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        reason = "test arithmetic mirrors bounded production formulas"
    )]
    fn fire_at_clamps_to_future() {
        let mut cfg = HealthCheckConfig::default();
        cfg.jitter_bp = 5000;
        let now = Millis(1000);
        let sched = EndpointSchedule {
            nominal: now,
            interval_state: IntervalState::Steady,
            active_health: EndpointHealth::Healthy,
            consecutive_ok: 0,
            consecutive_fail: 0,
            checks_since_reconnect: 0,
            checks_started: 0,
        };
        let span = (u64::from(cfg.interval_for(IntervalState::Steady)) * u64::from(cfg.jitter_bp)
            / 10_000) as u32;
        // Find a seed that produces a negative jitter for this span.
        let seed = (0u64..)
            .find(|&s| {
                let mut probe = Rng::from_seed(s);
                symmetric_jitter_ms(&mut probe, span) < 0
            })
            .expect("a negative jitter exists for span 1000");
        let mut rng = Rng::from_seed(seed);
        let at = sched.fire_at(now, &cfg, &mut rng);
        assert_eq!(at, now.add_ms(1));
    }

    #[test]
    fn note_dispatched_increments() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        assert_eq!(sched.checks_started, 0);
        sched.note_dispatched();
        assert_eq!(sched.checks_started, 1);
        sched.note_dispatched();
        assert_eq!(sched.checks_started, 2);
    }

    #[test]
    fn fire_at_basis_point_span() {
        let mut cfg = HealthCheckConfig::default();
        cfg.jitter_bp = 500;
        let now = Millis(0);
        let nominal = Millis(10_000);
        for interval_ms in [250, 500, 1000, 2000] {
            cfg.interval_ms = interval_ms;
            let sched = EndpointSchedule {
                nominal,
                interval_state: IntervalState::Steady,
                active_health: EndpointHealth::Healthy,
                consecutive_ok: 0,
                consecutive_fail: 0,
                checks_since_reconnect: 0,
                checks_started: 0,
            };
            let expected_span =
                (cfg.interval_for(IntervalState::Steady) * u32::from(cfg.jitter_bp)) / 10_000;
            let mut rng = Rng::from_seed(0x5eed);
            let mut any_nonzero = false;
            for _ in 0..500 {
                let at = sched.fire_at(now, &cfg, &mut rng);
                let diff = at.0.abs_diff(sched.nominal.0);
                assert!(
                    diff <= expected_span,
                    "interval {interval_ms}: diff {diff} exceeds expected span {expected_span}"
                );
                assert!(at.since(now) >= 1);
                if diff > 0 {
                    any_nonzero = true;
                }
            }
            assert!(
                any_nonzero,
                "interval {interval_ms}: expected span {expected_span} but fire_at never deviated"
            );
        }
    }

    #[test]
    fn fire_at_adds_positive_jitter() {
        let mut cfg = HealthCheckConfig::default();
        cfg.jitter_bp = 500;
        let nominal = Millis(10_000);
        let sched = EndpointSchedule {
            nominal,
            interval_state: IntervalState::Steady,
            active_health: EndpointHealth::Healthy,
            consecutive_ok: 0,
            consecutive_fail: 0,
            checks_since_reconnect: 0,
            checks_started: 0,
        };
        let span = (cfg.interval_for(IntervalState::Steady) * u32::from(cfg.jitter_bp)) / 10_000;
        let seed = (0u64..)
            .find(|&s| {
                let mut probe = Rng::from_seed(s);
                symmetric_jitter_ms(&mut probe, span) > 0
            })
            .expect("a positive jitter exists for span 100");
        let mut rng = Rng::from_seed(seed);
        let at = sched.fire_at(Millis(0), &cfg, &mut rng);
        assert!(
            at.since(nominal) > 0,
            "positive jitter should move fire time after nominal"
        );
    }

    #[test]
    fn fire_at_subtracts_negative_jitter() {
        let mut cfg = HealthCheckConfig::default();
        cfg.jitter_bp = 500;
        let nominal = Millis(10_000);
        let sched = EndpointSchedule {
            nominal,
            interval_state: IntervalState::Steady,
            active_health: EndpointHealth::Healthy,
            consecutive_ok: 0,
            consecutive_fail: 0,
            checks_since_reconnect: 0,
            checks_started: 0,
        };
        let span = (cfg.interval_for(IntervalState::Steady) * u32::from(cfg.jitter_bp)) / 10_000;
        let seed = (0u64..)
            .find(|&s| {
                let mut probe = Rng::from_seed(s);
                symmetric_jitter_ms(&mut probe, span) < 0
            })
            .expect("a negative jitter exists for span 100");
        let mut rng = Rng::from_seed(seed);
        let at = sched.fire_at(Millis(0), &cfg, &mut rng);
        assert!(
            nominal.since(at) > 0,
            "negative jitter should move fire time before nominal"
        );
        assert!(at.since(Millis(0)) >= 1);
    }

    #[test]
    fn advance_nominal_no_drift() {
        let cfg = HealthCheckConfig::default();
        let mut now = Millis(0);
        let mut sched = EndpointSchedule::init(now, 1, 1, &cfg, true);
        sched.nominal = now;
        let iv = cfg.interval_for(IntervalState::Steady);
        for _ in 0..20 {
            sched.advance_nominal(now, &cfg);
            now = now.add_ms(iv);
        }
        assert_eq!(sched.nominal, Millis(20 * iv));
    }

    #[test]
    fn advance_nominal_rebases_when_starved() {
        let cfg = HealthCheckConfig::default();
        let t0 = Millis(0);
        let mut sched = EndpointSchedule::init(t0, 1, 1, &cfg, true);
        sched.nominal = t0;
        let now = Millis(30_000);
        sched.advance_nominal(now, &cfg);
        let iv = cfg.interval_for(IntervalState::Steady);
        assert_eq!(sched.nominal, now.add_ms(iv));
    }

    #[test]
    fn hysteresis_three_down() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        assert_eq!(
            sched.apply_outcome(CheckOutcome::Fail(FailKind::Status), &cfg),
            Transition::None
        );
        assert_eq!(sched.active_health, EndpointHealth::Healthy);
        assert_eq!(
            sched.apply_outcome(CheckOutcome::Fail(FailKind::Status), &cfg),
            Transition::None
        );
        assert_eq!(sched.active_health, EndpointHealth::Healthy);
        assert_eq!(
            sched.apply_outcome(CheckOutcome::Fail(FailKind::Status), &cfg),
            Transition::ToUnhealthy
        );
        assert_eq!(sched.active_health, EndpointHealth::Unhealthy);
        assert_eq!(sched.consecutive_fail, 0);
        assert_eq!(sched.interval_state, IntervalState::Edge);
    }

    #[test]
    fn hysteresis_two_up() {
        let mut cfg = HealthCheckConfig::default();
        cfg.healthy_threshold = 2;
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        sched.active_health = EndpointHealth::Unhealthy;
        sched.interval_state = IntervalState::Down;
        assert_eq!(
            sched.apply_outcome(CheckOutcome::Pass, &cfg),
            Transition::None
        );
        assert_eq!(sched.active_health, EndpointHealth::Unhealthy);
        assert_eq!(
            sched.apply_outcome(CheckOutcome::Pass, &cfg),
            Transition::ToHealthy
        );
        assert_eq!(sched.active_health, EndpointHealth::Healthy);
        assert_eq!(sched.consecutive_ok, 0);
        assert_eq!(sched.interval_state, IntervalState::Edge);
    }

    #[test]
    fn hysteresis_interleaved_resets() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        let seq = [
            CheckOutcome::Fail(FailKind::Status),
            CheckOutcome::Fail(FailKind::Status),
            CheckOutcome::Pass,
            CheckOutcome::Fail(FailKind::Status),
            CheckOutcome::Fail(FailKind::Status),
        ];
        for outcome in seq {
            assert_eq!(sched.apply_outcome(outcome, &cfg), Transition::None);
        }
        assert_eq!(sched.active_health, EndpointHealth::Healthy);
    }

    #[test]
    fn retriable_status_sets_edge_but_counts() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        assert_eq!(
            sched.apply_outcome(CheckOutcome::Fail(FailKind::RetriableStatus), &cfg),
            Transition::None
        );
        assert_eq!(sched.interval_state, IntervalState::Edge);
        assert_eq!(sched.consecutive_fail, 1);
        assert_eq!(
            sched.apply_outcome(CheckOutcome::Fail(FailKind::RetriableStatus), &cfg),
            Transition::None
        );
        assert_eq!(
            sched.apply_outcome(CheckOutcome::Fail(FailKind::RetriableStatus), &cfg),
            Transition::ToUnhealthy
        );
    }

    #[test]
    fn edge_falls_back_to_steady_or_down() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        // Force ToUnhealthy, then a Fail should fall back to Down.
        sched.apply_outcome(CheckOutcome::Fail(FailKind::Status), &cfg);
        sched.apply_outcome(CheckOutcome::Fail(FailKind::Status), &cfg);
        sched.apply_outcome(CheckOutcome::Fail(FailKind::Status), &cfg);
        assert_eq!(sched.active_health, EndpointHealth::Unhealthy);
        assert_eq!(sched.interval_state, IntervalState::Edge);
        sched.apply_outcome(CheckOutcome::Fail(FailKind::Status), &cfg);
        assert_eq!(sched.interval_state, IntervalState::Down);

        // Force ToHealthy, then a Pass should fall back to Steady.
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        sched.active_health = EndpointHealth::Unhealthy;
        sched.interval_state = IntervalState::Down;
        sched.apply_outcome(CheckOutcome::Pass, &cfg);
        sched.apply_outcome(CheckOutcome::Pass, &cfg);
        assert_eq!(sched.active_health, EndpointHealth::Healthy);
        assert_eq!(sched.interval_state, IntervalState::Edge);
        sched.apply_outcome(CheckOutcome::Pass, &cfg);
        assert_eq!(sched.interval_state, IntervalState::Steady);
    }

    #[test]
    fn reconnect_counter() {
        let mut cfg = HealthCheckConfig::default();
        cfg.reconnect_every = 3;
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        sched.apply_outcome(CheckOutcome::Pass, &cfg);
        assert!(!sched.should_reconnect(&cfg));
        sched.apply_outcome(CheckOutcome::Pass, &cfg);
        assert!(!sched.should_reconnect(&cfg));
        sched.apply_outcome(CheckOutcome::Pass, &cfg);
        assert!(sched.should_reconnect(&cfg));
        sched.note_reconnected();
        assert_eq!(sched.checks_since_reconnect, 0);
        assert!(!sched.should_reconnect(&cfg));

        cfg.reconnect_every = 0;
        sched.checks_since_reconnect = 100;
        assert!(!sched.should_reconnect(&cfg));
    }

    #[test]
    fn no_traffic_switch() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, false);
        assert_eq!(sched.interval_state, IntervalState::NoTraffic);
        assert_eq!(cfg.interval_for(IntervalState::NoTraffic), 60_000);
        sched.set_has_traffic(true);
        assert_eq!(sched.interval_state, IntervalState::Edge);
    }

    #[test]
    fn counters_saturate() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        sched.consecutive_ok = u32::MAX;
        sched.apply_outcome(CheckOutcome::Pass, &cfg);
        assert_eq!(sched.consecutive_ok, u32::MAX);
    }

    #[test]
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "test arithmetic mirrors bounded production formulas"
    )]
    fn herd_hash_phase_beats_random_jitter() {
        const P: usize = 200;
        const U: usize = 500;
        const INTERVAL_MS: u32 = 1000;
        const WINDOW_MS: u32 = 10_000;
        const JITTER_BP: u16 = 500;
        const BUCKET_MS: u32 = 10;
        const PERIODS: usize = (WINDOW_MS / INTERVAL_MS) as usize;

        let span = (u64::from(INTERVAL_MS) * u64::from(JITTER_BP) / 10_000) as u32;

        let mut max_a = 0usize;
        let mut max_b = 0usize;
        let mut total_a = 0usize;
        let mut total_b = 0usize;

        for endpoint in 0..U {
            let endpoint_id = endpoint as u64;
            let mut buckets_a = [0usize; (WINDOW_MS / BUCKET_MS) as usize];
            let mut buckets_b = [0usize; (WINDOW_MS / BUCKET_MS) as usize];

            for instance in 0..P {
                let instance_id = instance as u64;
                let seed = instance_id;
                let mut rng_a = Rng::from_seed(seed);
                let mut rng_b = Rng::from_seed(seed);
                let phase = phase_ms(instance_id, endpoint_id, INTERVAL_MS);

                for k in 0..PERIODS {
                    let base = k as u32 * INTERVAL_MS;
                    let jitter_a = symmetric_jitter_ms(&mut rng_a, span);
                    let fire_a = if jitter_a >= 0 {
                        base.saturating_add(phase).saturating_add(jitter_a as u32)
                    } else {
                        base.saturating_add(phase)
                            .saturating_sub(jitter_a.unsigned_abs())
                    };
                    let jitter_b = symmetric_jitter_ms(&mut rng_b, span);
                    let fire_b = if jitter_b >= 0 {
                        base.saturating_add(jitter_b as u32)
                    } else {
                        base.saturating_sub(jitter_b.unsigned_abs())
                    };

                    let idx_a = (fire_a / BUCKET_MS) as usize % buckets_a.len();
                    let idx_b = (fire_b / BUCKET_MS) as usize % buckets_b.len();
                    buckets_a[idx_a] += 1;
                    buckets_b[idx_b] += 1;
                    total_a += 1;
                    total_b += 1;
                }
            }

            max_a = max_a.max(buckets_a.iter().copied().max().unwrap_or(0));
            max_b = max_b.max(buckets_b.iter().copied().max().unwrap_or(0));
        }

        assert_eq!(total_a, total_b);
        assert!(
            max_a <= 16,
            "hash-phase max {max_a} exceeds 16 at jitter 5% over 200 instances"
        );
        assert!(
            max_b >= 20,
            "random-jitter max {max_b} below 20; the control arm did not bunch"
        );
        assert!(
            max_a < max_b,
            "hash-phase max {max_a} not less than random {max_b}"
        );
    }
}
