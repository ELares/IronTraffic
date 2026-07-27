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
    #[allow(
        clippy::integer_division,
        reason = "the horizon-with-jitter check divides by the policy-defined 10_000 basis-point denominator; both operands are already bounded by the range checks above, so this only loses fractional precision the same way the rest of this module's basis-point arithmetic does"
    )]
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
        // `fire_at` computes its jitter span as `interval_for(state) * jitter_bp /
        // 10_000` and adds it to `nominal`. `Millis::since` (clock.rs, outside this
        // issue's Files table) reads a wrapping difference greater than
        // `Millis::HORIZON_MS` as "in the past", so a fire time that is legitimately
        // MORE than `HORIZON_MS` beyond the reference instant is misread as past and
        // clamped to `now + 1`, defeating the rate cap entirely (issue #709,
        // SHOULD_FIX 6). Each of the four interval fields is checked, not only
        // `interval_ms`, because `fire_at` reads whichever field `interval_for`
        // selects for the endpoint's current state, and the same overflow is
        // reachable through `Edge`, `Down`, or `NoTraffic` exactly as it is through
        // `Steady`. `u64` keeps the product from overflowing `u32` before the
        // division; both operands are already bounded (interval by the range check
        // just above, jitter_bp by the one before it), so this can only reject, never
        // panic.
        for (field, interval) in [
            ("health.interval_ms", self.interval_ms),
            ("health.edge_interval_ms", self.edge_interval_ms),
            ("health.unhealthy_interval_ms", self.unhealthy_interval_ms),
            ("health.no_traffic_interval_ms", self.no_traffic_interval_ms),
        ] {
            let horizon_with_jitter =
                u64::from(interval) * (10_000 + u64::from(self.jitter_bp)) / 10_000;
            if horizon_with_jitter > u64::from(Millis::HORIZON_MS) {
                return Err(ConfigError::new(
                    field,
                    &interval.to_string(),
                    "combined with jitter_bp must not be able to schedule a fire time beyond Millis::HORIZON_MS from nominal",
                ));
            }
        }
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

    // Issue #709 BLOCKING 2. `rate_cap_floors_every_state` sets all four interval
    // fields to 1, so under the rate cap every arm collapses to the same floored
    // value and no arm's raw field is distinguishable from any other. This test
    // keeps `rate_cap_floors_every_state` exactly as it is (it tests the floor, a
    // different property) and instead uses `max_checks_per_endpoint_per_sec =
    // 1000`, whose 1 ms floor cannot mask four pairwise-distinct field values, to
    // prove each arm of `interval_for` reads its OWN config field rather than
    // `interval_ms`. Without this, `Edge => self.interval_ms...` (dropping
    // HAProxy's `fastinter`) and `Down => self.interval_ms...` (dropping
    // `downinter`) both leave the full 28-test suite green.
    #[test]
    fn interval_for_reads_its_own_field() {
        let mut cfg = HealthCheckConfig::default();
        cfg.max_checks_per_endpoint_per_sec = 1000;
        cfg.interval_ms = 2000;
        cfg.edge_interval_ms = 501;
        cfg.unhealthy_interval_ms = 4001;
        cfg.no_traffic_interval_ms = 60001;

        assert_eq!(cfg.interval_for(IntervalState::Steady), cfg.interval_ms);
        assert_eq!(cfg.interval_for(IntervalState::Edge), cfg.edge_interval_ms);
        assert_eq!(
            cfg.interval_for(IntervalState::Down),
            cfg.unhealthy_interval_ms
        );
        assert_eq!(
            cfg.interval_for(IntervalState::NoTraffic),
            cfg.no_traffic_interval_ms
        );
    }

    // Issue #709 SHOULD_FIX 6. `fire_at` reads whichever field `interval_for`
    // selects for `self.interval_state`, but at interval_ms = HORIZON_MS the raw
    // per-field range check alone (interval <= HORIZON_MS) still accepts a
    // config whose jitter span pushes a legitimate fire time more than
    // HORIZON_MS beyond the reference instant, which `Millis::since` (clock.rs,
    // outside this issue) then misreads as being in the past. Chosen fix:
    // tighten `validate()` rather than touch `clock.rs`, which is not in this
    // issue's Files table. Applied to all four interval fields, not only
    // `interval_ms`, because `fire_at` can select any of them depending on
    // `interval_state`.
    #[test]
    fn validate_rejects_interval_overflowing_horizon_with_jitter() {
        // ~17.4 days: within the plain per-field bound (<= HORIZON_MS) on its
        // own, but at the maximum legal jitter_bp of 5_000 (50%), interval *
        // 1.5 exceeds HORIZON_MS. Checked at compile time, not with a runtime
        // assert, so this fixture invariant cannot itself be reported as an
        // assertion on constants.
        const OVERFLOWING_INTERVAL_MS: u32 = 1_500_000_000;
        const _: () = assert!(
            OVERFLOWING_INTERVAL_MS <= Millis::HORIZON_MS,
            "fixture must stay inside the plain per-field bound to prove the new check, not the pre-existing one"
        );

        let mut c = HealthCheckConfig::default();
        c.jitter_bp = 5_000;
        c.interval_ms = OVERFLOWING_INTERVAL_MS;
        assert_eq!(c.validate().unwrap_err().field, "health.interval_ms");

        let mut c = HealthCheckConfig::default();
        c.jitter_bp = 5_000;
        c.edge_interval_ms = OVERFLOWING_INTERVAL_MS;
        assert_eq!(c.validate().unwrap_err().field, "health.edge_interval_ms");

        let mut c = HealthCheckConfig::default();
        c.jitter_bp = 5_000;
        c.unhealthy_interval_ms = OVERFLOWING_INTERVAL_MS;
        assert_eq!(
            c.validate().unwrap_err().field,
            "health.unhealthy_interval_ms"
        );

        let mut c = HealthCheckConfig::default();
        c.jitter_bp = 5_000;
        c.no_traffic_interval_ms = OVERFLOWING_INTERVAL_MS;
        assert_eq!(
            c.validate().unwrap_err().field,
            "health.no_traffic_interval_ms"
        );
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

    // Issue #709 BLOCKING 3, #92 edge case 1. Computing the phase from
    // `cfg.interval_ms` instead of the rate-cap-stretched effective interval
    // leaves every other test green, because the existing herd simulation
    // (`herd_hash_phase_beats_random_jitter`) calls the free function `phase_ms`
    // directly and never goes through `EndpointSchedule::init`, so it cannot see
    // which interval `init` actually fed it. This test goes through `init` for
    // several thousand endpoint ids with `interval_ms = 1`: under the mutant,
    // `phase_ms(_, _, 1)` returns 0 for every endpoint (the only value in
    // `[0, 1)`), so every `nominal` lands exactly on `t0` and the fleet fires in
    // the same millisecond, which is precisely the self-inflicted denial of
    // service #92's Context section exists to prevent. Under the fix, the phase
    // is computed against the stretched effective interval (250 ms at the
    // default cap of 4) and spreads.
    #[test]
    fn init_computes_phase_from_stretched_interval() {
        let mut cfg = HealthCheckConfig::default();
        cfg.interval_ms = 1;
        let t0 = Millis(0);

        let mut max_offset = 0u32;
        let mut first_offset = None;
        let mut saw_different = false;
        for endpoint_id in 0..5_000u64 {
            let sched = EndpointSchedule::init(t0, 1, endpoint_id, &cfg, true);
            let offset = sched.nominal.since(t0);
            assert!(
                offset < 250,
                "offset {offset} should be in 0..250, the stretched effective \
                 interval, not 0..1, the raw configured interval_ms"
            );
            max_offset = max_offset.max(offset);
            match first_offset {
                None => first_offset = Some(offset),
                Some(f) if f != offset => saw_different = true,
                Some(_) => {}
            }
        }
        assert!(
            saw_different,
            "every endpoint got the same phase; the herd is not spread"
        );
        assert!(
            max_offset >= 200,
            "max offset {max_offset} too small for a spread over 0..250"
        );
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

    // Issue #709 SHOULD_FIX 8. Every existing `fire_at` test constructs its
    // schedule in `Steady`, so a mutant that computes the jitter span from
    // `cfg.interval_for(IntervalState::Steady)` unconditionally, instead of
    // `cfg.interval_for(self.interval_state)`, agrees with the correct
    // implementation on all of them. This test fires from `Down`, with
    // `unhealthy_interval_ms` deliberately far smaller than `interval_ms` so the
    // two spans are distinguishable, and a fixed seed so the run cannot flake.
    #[test]
    #[allow(
        clippy::integer_division,
        clippy::cast_possible_truncation,
        reason = "test arithmetic mirrors bounded production formulas"
    )]
    fn fire_at_uses_current_state_interval_for_jitter_span() {
        let mut cfg = HealthCheckConfig::default();
        cfg.jitter_bp = 5_000;
        cfg.interval_ms = 2000;
        cfg.unhealthy_interval_ms = 200;
        let now = Millis(0);
        let nominal = Millis(10_000);
        let sched = EndpointSchedule {
            nominal,
            interval_state: IntervalState::Down,
            active_health: EndpointHealth::Unhealthy,
            consecutive_ok: 0,
            consecutive_fail: 0,
            checks_since_reconnect: 0,
            checks_started: 0,
        };
        let down_span = (cfg.interval_for(IntervalState::Down) * u32::from(cfg.jitter_bp)) / 10_000;
        let steady_span =
            (cfg.interval_for(IntervalState::Steady) * u32::from(cfg.jitter_bp)) / 10_000;
        assert!(
            down_span < steady_span,
            "fixture must make the two spans distinguishable"
        );

        let mut rng = Rng::from_seed(0x5eed);
        for _ in 0..500 {
            let at = sched.fire_at(now, &cfg, &mut rng);
            let diff = at.0.abs_diff(sched.nominal.0);
            assert!(
                diff <= down_span,
                "Down-state fire_at diff {diff} exceeds its own span {down_span} \
                 (would be allowed under the Steady span {steady_span})"
            );
        }
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

    // Issue #709 BLOCKING 1. Both existing `advance_nominal` tests run in
    // `Steady`, so `cfg.interval_for(self.interval_state)` replaced with the
    // constant `cfg.interval_for(IntervalState::Steady)` agrees with the
    // correct implementation on both and leaves the whole suite green: a
    // `NoTraffic` cluster would then be probed at the `Steady` interval instead
    // of `no_traffic_interval_ms`, a 30x amplification at the defaults. Uses
    // `max_checks_per_endpoint_per_sec = 1000` so the rate-cap floor is 1 ms and
    // cannot mask four pairwise-distinct interval values.
    #[test]
    fn advance_nominal_uses_state_interval() {
        let mut cfg = HealthCheckConfig::default();
        cfg.max_checks_per_endpoint_per_sec = 1000;
        cfg.interval_ms = 2000;
        cfg.edge_interval_ms = 501;
        cfg.unhealthy_interval_ms = 4001;
        cfg.no_traffic_interval_ms = 60001;

        let cases = [
            (IntervalState::Steady, cfg.interval_ms),
            (IntervalState::Edge, cfg.edge_interval_ms),
            (IntervalState::Down, cfg.unhealthy_interval_ms),
            (IntervalState::NoTraffic, cfg.no_traffic_interval_ms),
        ];
        for (state, expected_iv) in cases {
            let t0 = Millis(0);
            let mut sched = EndpointSchedule::init(t0, 1, 1, &cfg, true);
            sched.nominal = t0;
            sched.interval_state = state;
            sched.advance_nominal(t0, &cfg);
            assert_eq!(
                sched.nominal,
                t0.add_ms(expected_iv),
                "state {state:?} should advance by its own interval {expected_iv}, \
                 not Steady's"
            );
        }
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

    // Issue #709 BLOCKING 5. The Fail-direction counterpart of
    // `hysteresis_interleaved_resets` above: deleting `self.consecutive_ok = 0;`
    // from the Fail branch turns a consecutive-pass counter into a lifetime
    // count, so an `Unhealthy` endpoint flapping Pass, Fail, Pass would be marked
    // `ToHealthy` on the second, non-consecutive pass at the default
    // `healthy_threshold` of 2, restoring full traffic to a backend that is still
    // failing half its probes.
    #[test]
    fn hysteresis_interleaved_resets_fail_direction() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        sched.active_health = EndpointHealth::Unhealthy;
        sched.interval_state = IntervalState::Down;

        let seq = [
            CheckOutcome::Pass,
            CheckOutcome::Fail(FailKind::Status),
            CheckOutcome::Pass,
        ];
        for outcome in seq {
            assert_eq!(
                sched.apply_outcome(outcome, &cfg),
                Transition::None,
                "a single non-consecutive pass must not cross healthy_threshold"
            );
        }
        assert_eq!(sched.active_health, EndpointHealth::Unhealthy);
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

    // Issue #709 BLOCKING 4. Deleting the `self.active_health ==
    // EndpointHealth::Healthy` conjunct from the Fail branch's threshold check
    // lets an already-`Unhealthy` endpoint re-cross `unhealthy_threshold` on
    // every further run of consecutive failures, emitting a spurious
    // `ToUnhealthy` on a loop and resetting `interval_state` to `Edge` each time:
    // a 4x sustained probe amplifier aimed at a backend already too broken to
    // answer. This asserts neither happens as failures keep accumulating past
    // the threshold.
    #[test]
    fn unhealthy_endpoint_does_not_retransition_on_further_fails() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        sched.active_health = EndpointHealth::Unhealthy;
        sched.interval_state = IntervalState::Down;
        sched.consecutive_fail = 0;

        for _ in 0..(cfg.unhealthy_threshold * 2) {
            let transition = sched.apply_outcome(CheckOutcome::Fail(FailKind::Status), &cfg);
            assert_eq!(
                transition,
                Transition::None,
                "an already-Unhealthy endpoint must not re-fire ToUnhealthy"
            );
            assert_eq!(sched.active_health, EndpointHealth::Unhealthy);
            assert_eq!(
                sched.interval_state,
                IntervalState::Down,
                "interval_state must not reset to Edge while already Unhealthy"
            );
        }
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

    // Issue #709 SHOULD_FIX 7, Design step 1b. `set_has_traffic(true)` must move
    // ONLY a `NoTraffic` endpoint to `Edge`; an endpoint already on a traffic
    // schedule must be left alone. Making the guard unconditional (the mutant
    // that deletes the `if self.interval_state == IntervalState::NoTraffic`
    // check) would force every endpoint to `Edge` on every traffic signal,
    // which this catches.
    #[test]
    fn set_has_traffic_true_leaves_non_no_traffic_state_unchanged() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);

        sched.interval_state = IntervalState::Steady;
        sched.set_has_traffic(true);
        assert_eq!(
            sched.interval_state,
            IntervalState::Steady,
            "an already-scheduled endpoint must not be forced to Edge"
        );

        sched.interval_state = IntervalState::Down;
        sched.set_has_traffic(true);
        assert_eq!(sched.interval_state, IntervalState::Down);
    }

    // Issue #709 SHOULD_FIX 7, Design step 2. `set_has_traffic(false)` moves ANY
    // state to `NoTraffic` unconditionally, including from `Edge`. Deleting the
    // `else { NoTraffic }` branch would leave `set_has_traffic(false)` a no-op,
    // which this catches: an idle cluster would never drop off the edge or
    // steady schedule onto the 60_000 ms no-traffic interval.
    #[test]
    fn set_has_traffic_false_forces_no_traffic_from_any_state() {
        let cfg = HealthCheckConfig::default();
        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);

        sched.interval_state = IntervalState::Edge;
        sched.set_has_traffic(false);
        assert_eq!(
            sched.interval_state,
            IntervalState::NoTraffic,
            "going idle must apply immediately even from Edge"
        );

        sched.interval_state = IntervalState::Steady;
        sched.set_has_traffic(false);
        assert_eq!(sched.interval_state, IntervalState::NoTraffic);
    }

    // Issue #709 SHOULD_FIX 9. Originally covered only `consecutive_ok`. Extended
    // to `consecutive_fail` (guarding it with `active_health = Unhealthy` so the
    // ToUnhealthy branch, which legitimately resets the counter to 0, does not
    // fire and mask the saturation) and `checks_since_reconnect`, whose
    // saturating_add runs unconditionally on every outcome. The interesting
    // survivor is `checks_since_reconnect.wrapping_add`, which would silently
    // disable the forced periodic reconnect.
    #[test]
    fn counters_saturate() {
        let cfg = HealthCheckConfig::default();

        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        sched.consecutive_ok = u32::MAX;
        sched.apply_outcome(CheckOutcome::Pass, &cfg);
        assert_eq!(sched.consecutive_ok, u32::MAX);

        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        sched.active_health = EndpointHealth::Unhealthy;
        sched.consecutive_fail = u32::MAX;
        sched.apply_outcome(CheckOutcome::Fail(FailKind::Connect), &cfg);
        assert_eq!(sched.consecutive_fail, u32::MAX);

        let mut sched = EndpointSchedule::init(Millis(0), 1, 1, &cfg, true);
        sched.checks_since_reconnect = u32::MAX;
        sched.apply_outcome(CheckOutcome::Pass, &cfg);
        assert_eq!(sched.checks_since_reconnect, u32::MAX);
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
