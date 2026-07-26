// SPDX-License-Identifier: MIT OR Apache-2.0
//! One absolute monotonic deadline per request, established at ingress and carried
//! across every retry and every hedge attempt without ever being extended.
//!
//! Propagated across a hop as a REMAINING DURATION, never as an absolute timestamp:
//! NTP skew between two hosts is routinely tens of milliseconds and can be
//! unbounded, so an absolute timestamp handed to a skewed peer gives it either too
//! much or too little budget. This module performs no I/O and reads no clock; every
//! function that needs the current time takes it as a [`crate::clock::Millis`]
//! parameter.

pub mod headers;

use crate::clock::Millis;
use crate::config::{ConfigError, in_range_u32, ordered_u32};

/// One absolute monotonic deadline for a whole request, including every retry and
/// every hedge attempt.
///
/// Deliberately `Copy` and deliberately without any mutating method: a retry attempt
/// carries the ORIGINAL request's deadline, and there is no API by which it could be
/// extended. Propagated across a hop as a remaining duration, never as an absolute
/// timestamp, because NTP skew between hosts is unbounded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Deadline {
    /// Absolute coarse-monotonic instant at which the request's budget is exhausted.
    at: Millis,
}

impl Deadline {
    /// A deadline `budget_ms` milliseconds after `now`.
    ///
    /// `budget_ms` is clamped to `Millis::HORIZON_MS` first, because a larger offset is
    /// indistinguishable from an instant in the PAST on the wrapping `Millis` timeline
    /// and would make `remaining_ms` return 0 immediately. Config validation already
    /// bounds `max_timeout_ms` by `HORIZON_MS`; this clamp makes the constructor total
    /// for callers that do not go through `establish`.
    #[must_use]
    pub fn from_now(now: Millis, budget_ms: u32) -> Self {
        let budget_ms = budget_ms.min(Millis::HORIZON_MS);
        Self {
            at: now.add_ms(budget_ms),
        }
    }

    /// Milliseconds left, saturating at 0. Monotonically non-increasing in `now`.
    #[inline]
    #[must_use]
    pub fn remaining_ms(self, now: Millis) -> u32 {
        self.at.since(now)
    }

    /// True when no budget remains.
    #[inline]
    #[must_use]
    pub fn expired(self, now: Millis) -> bool {
        self.remaining_ms(now) == 0
    }

    /// True when at least `need_ms` of budget remains.
    ///
    /// This is the retry gate: call it with `backoff_ms + min_attempt_estimate_ms`.
    #[inline]
    #[must_use]
    pub fn permits(self, now: Millis, need_ms: u32) -> bool {
        self.remaining_ms(now) >= need_ms
    }
}

/// Which inbound signal established the deadline. Emitted as a metric label so an
/// operator can see whether clients are actually sending deadlines.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimeoutSource {
    /// Inbound `grpc-timeout`.
    GrpcTimeout,
    /// Inbound `x-envoy-expected-rq-timeout-ms`, honoured only when configured.
    ExpectedRqTimeout,
    /// Inbound `x-envoy-upstream-rq-timeout-ms`, honoured only on trusted-internal connections.
    UpstreamRqTimeout,
    /// The route's configured timeout.
    RouteDefault,
}

/// Raw inbound timeout header values, borrowed from the parsed request head.
#[derive(Clone, Copy, Default, Debug)]
pub struct InboundTimeouts<'a> {
    /// Value of `grpc-timeout`, if present.
    pub grpc_timeout: Option<&'a [u8]>,
    /// Value of `x-envoy-expected-rq-timeout-ms`, if present.
    pub expected_rq_timeout_ms: Option<&'a [u8]>,
    /// Value of `x-envoy-upstream-rq-timeout-ms`, if present.
    pub upstream_rq_timeout_ms: Option<&'a [u8]>,
}

/// Deadline policy for one route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeadlineConfig {
    /// Lower clamp for any established timeout. Default 1.
    pub min_timeout_ms: u32,
    /// Upper clamp for any established timeout. Default `60_000`.
    pub max_timeout_ms: u32,
    /// Below this much remaining budget, refuse to start an upstream attempt. Default 10.
    pub floor_ms: u32,
    /// Subtracted from the propagated budget to account for network transit.
    /// Default 0; the recommended setting is the observed p50 RTT to the upstream.
    pub hop_offset_ms: u32,
    /// Honour inbound `x-envoy-expected-rq-timeout-ms`. Default false.
    pub respect_expected_rq_timeout: bool,
}

impl Default for DeadlineConfig {
    fn default() -> Self {
        Self {
            min_timeout_ms: 1,
            max_timeout_ms: 60_000,
            floor_ms: 10,
            hop_offset_ms: 0,
            respect_expected_rq_timeout: false,
        }
    }
}

impl DeadlineConfig {
    /// Rejects `min_timeout_ms == 0`, `min > max`, `max_timeout_ms > Millis::HORIZON_MS`,
    /// `floor_ms > max_timeout_ms`, and `hop_offset_ms > max_timeout_ms`.
    ///
    /// The last two exist because a `floor_ms` or `hop_offset_ms` above `max_timeout_ms`
    /// makes every request fail the pre-attempt gate, or propagates a 1 ms budget to
    /// every upstream, which is a configuration-driven total outage that no runtime
    /// code path can recover from.
    ///
    /// # Errors
    /// Returns the first [`ConfigError`] found, naming the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        in_range_u32("min_timeout_ms", self.min_timeout_ms, 1, u32::MAX)?;
        ordered_u32(
            "min_timeout_ms",
            self.min_timeout_ms,
            "max_timeout_ms",
            self.max_timeout_ms,
        )?;
        in_range_u32("max_timeout_ms", self.max_timeout_ms, 0, Millis::HORIZON_MS)?;
        ordered_u32(
            "floor_ms",
            self.floor_ms,
            "max_timeout_ms",
            self.max_timeout_ms,
        )?;
        ordered_u32(
            "hop_offset_ms",
            self.hop_offset_ms,
            "max_timeout_ms",
            self.max_timeout_ms,
        )?;
        Ok(())
    }
}

/// Establish the request deadline at ingress.
///
/// Returns the deadline, which signal established it, and the clamped budget in
/// milliseconds. An unparseable inbound header falls through to the next clause and
/// never fails the request.
///
/// When `trusted_internal` is false and the budget came from an inbound header, the
/// result is additionally capped at `route_timeout_ms`: an untrusted peer may shorten
/// its own budget and may never lengthen it. Callers MUST pass `trusted_internal =
/// false` whenever the forwarding trust policy has not positively classified the
/// downstream connection as one of our own hops; the parameter is fail-closed by
/// construction, so "unknown" is "untrusted".
#[must_use]
pub fn establish(
    now: Millis,
    inbound: InboundTimeouts<'_>,
    route_timeout_ms: u32,
    trusted_internal: bool,
    cfg: &DeadlineConfig,
) -> (Deadline, TimeoutSource, u32) {
    let grpc_ms = inbound.grpc_timeout.and_then(headers::parse_grpc_timeout);
    let expected_ms = if cfg.respect_expected_rq_timeout {
        inbound
            .expected_rq_timeout_ms
            .and_then(headers::parse_u32_ms)
    } else {
        None
    };
    let upstream_ms = if trusted_internal {
        inbound
            .upstream_rq_timeout_ms
            .and_then(headers::parse_u32_ms)
    } else {
        None
    };

    // In order, first match wins: grpc-timeout, then expected-rq-timeout (if
    // enabled), then upstream-rq-timeout (if trusted), then the route default.
    let (chosen_ms, source): (u64, TimeoutSource) = match (grpc_ms, expected_ms, upstream_ms) {
        (Some(ms), _, _) => (ms, TimeoutSource::GrpcTimeout),
        (None, Some(ms), _) => (u64::from(ms), TimeoutSource::ExpectedRqTimeout),
        (None, None, Some(ms)) => (u64::from(ms), TimeoutSource::UpstreamRqTimeout),
        (None, None, None) => (u64::from(route_timeout_ms), TimeoutSource::RouteDefault),
    };

    // Saturating, not wrapping: a legal grpc-timeout can be far larger than
    // `u32::MAX` milliseconds, and a wrapping cast would reduce it modulo 2^32,
    // landing anywhere in the u32 range including below `max_timeout_ms`.
    let narrowed = u32::try_from(chosen_ms).unwrap_or(u32::MAX);

    // An untrusted peer may only shorten its budget, never lengthen it past what
    // the route configures. A trusted-internal peer is exempt: it is forwarding
    // some other client's original deadline, which may legitimately exceed this
    // route's local default, and it remains bounded by `max_timeout_ms` below.
    let narrowed = if source != TimeoutSource::RouteDefault && !trusted_internal {
        narrowed.min(route_timeout_ms)
    } else {
        narrowed
    };

    let ms = narrowed.clamp(cfg.min_timeout_ms, cfg.max_timeout_ms);
    (Deadline::from_now(now, ms), source, ms)
}

/// The result of the pre-attempt gate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttemptAdmission {
    /// Proceed; this many milliseconds of budget remain.
    Proceed(u32),
    /// Refuse with 504 and increment `deadline_exceeded_before_attempt`.
    RefuseDeadlineExceeded,
}

/// Gate an upstream attempt on remaining budget.
#[inline]
#[must_use]
pub fn admit_attempt(d: Deadline, now: Millis, cfg: &DeadlineConfig) -> AttemptAdmission {
    let remaining = d.remaining_ms(now);
    if remaining < cfg.floor_ms {
        AttemptAdmission::RefuseDeadlineExceeded
    } else {
        AttemptAdmission::Proceed(remaining)
    }
}

/// Budget to propagate to the upstream on this hop: `remaining - hop_offset`.
#[inline]
#[must_use]
pub fn propagated_budget_ms(d: Deadline, now: Millis, cfg: &DeadlineConfig) -> u32 {
    d.remaining_ms(now).saturating_sub(cfg.hop_offset_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::{ProptestConfig, any, proptest};

    #[test]
    fn establish_prefers_grpc_timeout() {
        let cfg = DeadlineConfig {
            respect_expected_rq_timeout: true,
            ..DeadlineConfig::default()
        };
        let inbound = InboundTimeouts {
            grpc_timeout: Some(b"500m"),
            expected_rq_timeout_ms: Some(b"250"),
            upstream_rq_timeout_ms: Some(b"9000"),
        };
        let (deadline, source, ms) = establish(Millis(0), inbound, 1_000, true, &cfg);
        assert_eq!(source, TimeoutSource::GrpcTimeout);
        assert_eq!(ms, 500);
        assert_eq!(deadline.remaining_ms(Millis(0)), 500);
    }

    #[test]
    fn establish_falls_through_on_malformed() {
        let cfg = DeadlineConfig {
            respect_expected_rq_timeout: true,
            ..DeadlineConfig::default()
        };
        let inbound = InboundTimeouts {
            grpc_timeout: Some(b"garbage"),
            expected_rq_timeout_ms: Some(b"250"),
            upstream_rq_timeout_ms: None,
        };
        let (_, source, ms) = establish(Millis(0), inbound, 1_000, true, &cfg);
        assert_eq!(source, TimeoutSource::ExpectedRqTimeout);
        assert_eq!(ms, 250);
    }

    #[test]
    fn establish_ignores_expected_when_disabled() {
        let cfg = DeadlineConfig::default();
        let inbound = InboundTimeouts {
            grpc_timeout: Some(b"garbage"),
            expected_rq_timeout_ms: Some(b"250"),
            upstream_rq_timeout_ms: None,
        };
        let (_, source, ms) = establish(Millis(0), inbound, 777, true, &cfg);
        assert_eq!(source, TimeoutSource::RouteDefault);
        assert_eq!(ms, 777);
    }

    #[test]
    fn establish_ignores_upstream_when_untrusted() {
        let cfg = DeadlineConfig::default();
        let inbound = InboundTimeouts {
            grpc_timeout: None,
            expected_rq_timeout_ms: None,
            upstream_rq_timeout_ms: Some(b"5000"),
        };
        let (_, source, ms) = establish(Millis(0), inbound, 300, false, &cfg);
        assert_eq!(source, TimeoutSource::RouteDefault);
        assert_eq!(ms, 300);
    }

    #[test]
    fn establish_clamps_low() {
        let cfg = DeadlineConfig {
            min_timeout_ms: 10,
            ..DeadlineConfig::default()
        };
        let inbound = InboundTimeouts {
            grpc_timeout: Some(b"1u"),
            ..InboundTimeouts::default()
        };
        let (_, _, ms) = establish(Millis(0), inbound, 5_000, true, &cfg);
        assert_eq!(ms, 10);
    }

    #[test]
    fn establish_clamps_high() {
        let cfg = DeadlineConfig::default();
        let inbound = InboundTimeouts {
            upstream_rq_timeout_ms: Some(b"4294967295"),
            ..InboundTimeouts::default()
        };
        let (_, _, ms) = establish(Millis(0), inbound, 5_000, true, &cfg);
        assert_eq!(ms, 60_000);
    }

    #[test]
    fn establish_all_absent() {
        let cfg = DeadlineConfig::default();
        let (_, source, ms) = establish(Millis(0), InboundTimeouts::default(), 42_000, true, &cfg);
        assert_eq!(source, TimeoutSource::RouteDefault);
        assert_eq!(ms, 42_000);
    }

    #[test]
    fn remaining_is_monotone_and_saturates() {
        let now = Millis(1_000);
        let d = Deadline::from_now(now, 100);
        assert_eq!(d.remaining_ms(now), 100);
        assert_eq!(d.remaining_ms(now.add_ms(50)), 50);
        assert_eq!(d.remaining_ms(now.add_ms(100)), 0);
        assert_eq!(d.remaining_ms(now.add_ms(5_000)), 0);
    }

    #[test]
    fn expired_boundary() {
        let now = Millis(0);
        let d = Deadline::from_now(now, 100);
        assert!(!d.expired(now.add_ms(99)));
        assert!(d.expired(now.add_ms(100)));
    }

    #[test]
    fn permits_boundary() {
        let now = Millis(0);
        let d = Deadline::from_now(now, 100);
        assert!(d.permits(now, 100));
        assert!(!d.permits(now, 101));
    }

    #[test]
    fn admit_attempt_floor() {
        let cfg = DeadlineConfig {
            floor_ms: 10,
            ..DeadlineConfig::default()
        };
        let now = Millis(0);
        let d10 = Deadline::from_now(now, 10);
        assert_eq!(admit_attempt(d10, now, &cfg), AttemptAdmission::Proceed(10));
        let d9 = Deadline::from_now(now, 9);
        assert_eq!(
            admit_attempt(d9, now, &cfg),
            AttemptAdmission::RefuseDeadlineExceeded
        );
    }

    #[test]
    fn propagated_subtracts_hop_offset() {
        let cfg = DeadlineConfig {
            hop_offset_ms: 5,
            ..DeadlineConfig::default()
        };
        let now = Millis(0);
        let d100 = Deadline::from_now(now, 100);
        assert_eq!(propagated_budget_ms(d100, now, &cfg), 95);
        let d3 = Deadline::from_now(now, 3);
        assert_eq!(propagated_budget_ms(d3, now, &cfg), 0);
    }

    #[test]
    fn config_validate_rejects() {
        let base = DeadlineConfig::default();

        let err = DeadlineConfig {
            min_timeout_ms: 0,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "min_timeout_ms");

        let err = DeadlineConfig {
            min_timeout_ms: 100,
            max_timeout_ms: 50,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "min_timeout_ms");

        let err = DeadlineConfig {
            max_timeout_ms: u32::MAX,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "max_timeout_ms");

        let err = DeadlineConfig {
            floor_ms: 60_001,
            max_timeout_ms: 60_000,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "floor_ms");

        let err = DeadlineConfig {
            hop_offset_ms: 60_001,
            max_timeout_ms: 60_000,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "hop_offset_ms");
    }

    #[test]
    fn untrusted_inbound_cannot_exceed_route() {
        let cfg = DeadlineConfig {
            respect_expected_rq_timeout: true,
            ..DeadlineConfig::default()
        };

        let inbound = InboundTimeouts {
            grpc_timeout: Some(b"60S"),
            ..InboundTimeouts::default()
        };
        let (_, source, ms) = establish(Millis(0), inbound, 1_000, false, &cfg);
        assert_eq!(source, TimeoutSource::GrpcTimeout);
        assert_eq!(ms, 1_000);

        let inbound = InboundTimeouts {
            expected_rq_timeout_ms: Some(b"60000"),
            ..InboundTimeouts::default()
        };
        let (_, source, ms) = establish(Millis(0), inbound, 1_000, false, &cfg);
        assert_eq!(source, TimeoutSource::ExpectedRqTimeout);
        assert_eq!(ms, 1_000);
    }

    #[test]
    fn untrusted_inbound_may_shorten() {
        let cfg = DeadlineConfig::default();
        let inbound = InboundTimeouts {
            grpc_timeout: Some(b"200m"),
            ..InboundTimeouts::default()
        };
        let (_, _, ms) = establish(Millis(0), inbound, 1_000, false, &cfg);
        assert_eq!(ms, 200);
    }

    #[test]
    fn trusted_inbound_may_exceed_route() {
        let cfg = DeadlineConfig::default();
        let inbound = InboundTimeouts {
            grpc_timeout: Some(b"60S"),
            ..InboundTimeouts::default()
        };
        let (_, _, ms) = establish(Millis(0), inbound, 1_000, true, &cfg);
        assert_eq!(ms, 60_000);
    }

    #[test]
    fn prop_remaining_non_increasing() {
        proptest!(
            ProptestConfig::default(),
            |(
                start: u32,
                budget in 1u32..=60_000,
                offsets in proptest::collection::vec(0u32..=200_000, 0..16),
            )| {
                let mut offsets = offsets;
                offsets.sort_unstable();
                let d = Deadline::from_now(Millis(start), budget);
                let mut prev = d.remaining_ms(Millis(start));
                assert!(prev <= budget);
                for off in offsets {
                    let now = Millis(start.wrapping_add(off));
                    let rem = d.remaining_ms(now);
                    assert!(rem <= budget);
                    assert!(rem <= prev);
                    prev = rem;
                }
            }
        );
    }

    #[test]
    fn prop_established_within_clamp() {
        proptest!(
            ProptestConfig::default(),
            |(
                min_timeout_ms in 1u32..=60_000,
                span in 0u32..=200_000,
                floor_ms in 0u32..=260_000,
                hop_offset_ms in 0u32..=260_000,
                respect_expected_rq_timeout: bool,
                route_timeout_ms: u32,
                trusted_internal: bool,
                grpc in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..=16)),
                expected in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..=16)),
                upstream in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..=16)),
                now: u32,
            )| {
                let max_timeout_ms = min_timeout_ms.saturating_add(span);
                let cfg = DeadlineConfig {
                    min_timeout_ms,
                    max_timeout_ms,
                    floor_ms: floor_ms.min(max_timeout_ms),
                    hop_offset_ms: hop_offset_ms.min(max_timeout_ms),
                    respect_expected_rq_timeout,
                };
                cfg.validate().expect("generated config must be valid");

                let inbound = InboundTimeouts {
                    grpc_timeout: grpc.as_deref(),
                    expected_rq_timeout_ms: expected.as_deref(),
                    upstream_rq_timeout_ms: upstream.as_deref(),
                };
                let (_, source, budget) =
                    establish(Millis(now), inbound, route_timeout_ms, trusted_internal, &cfg);

                assert!(budget >= cfg.min_timeout_ms);
                assert!(budget <= cfg.max_timeout_ms);
                if !trusted_internal && source != TimeoutSource::RouteDefault {
                    assert!(budget <= route_timeout_ms.max(cfg.min_timeout_ms));
                }
            }
        );
    }

    #[test]
    fn prop_emitted_expected_never_zero() {
        proptest!(
            ProptestConfig::default(),
            |(per_try: u32, propagate: u32)| {
                let mut buf = [0u8; 10];
                let n = headers::emit_expected_rq_timeout_ms(per_try, propagate, &mut buf);
                let bytes = &buf[..n];
                assert_ne!(bytes, b"0");
                let expected = per_try.min(propagate).max(1);
                assert_eq!(headers::parse_u32_ms(bytes), Some(expected));
            }
        );
    }

    #[test]
    fn prop_grpc_timeout_roundtrip() {
        proptest!(
            ProptestConfig::default(),
            |(ms in 1u32..=60_000)| {
                let mut buf = [0u8; 12];
                let n = headers::emit_grpc_timeout(ms, &mut buf);
                assert_eq!(headers::parse_grpc_timeout(&buf[..n]), Some(u64::from(ms)));
            }
        );
    }
}
