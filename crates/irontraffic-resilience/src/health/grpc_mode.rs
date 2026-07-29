// SPDX-License-Identifier: MIT OR Apache-2.0

//! Watch-versus-Check policy for one gRPC health check endpoint.
//!
//! [`GrpcModeMachine`] decides, at each scheduled check time, whether the runner
//! should open a `Watch` stream, send an HTTP/2 PING on one already open, close a
//! silently dead stream, perform a unary `Check`, or do nothing. It reads no clock
//! (every method takes `now` as a [`Millis`] parameter) and speaks no HTTP/2: the
//! runner that owns the connection interprets [`GrpcAction`] and calls back into
//! this machine as the corresponding event happens.
//!
//! The policy: prefer `Watch`. Treat a stream that goes silent past its liveness
//! deadline (`interval_ms * liveness_multiplier`) as a signal to retry `Watch`
//! immediately, not to fall back, because a network blip must not permanently
//! downgrade an endpoint to polling. Only an explicit `UNIMPLEMENTED` answer moves
//! the endpoint to sticky unary `Check` polling, and even then only for
//! `watch_retry_after_checks` checks before `Watch` is tried again. See the issue
//! this module implements and `docs/THREAT-MODEL.md`, "gRPC health checking".

use crate::clock::Millis;
use crate::health::grpc::{CompiledGrpcCheck, GrpcVerdict};
use crate::health::schedule::{CheckOutcome, FailKind};

/// Which transport the endpoint's health is currently observed through.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GrpcMode {
    /// A `Watch` stream should be opened at the next opportunity.
    WatchDesired,
    /// A `Watch` stream is open.
    WatchOpen,
    /// The server answered `UNIMPLEMENTED`; poll with unary `Check`.
    UnaryFallback,
}

/// What the runner must do at this check time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GrpcAction {
    /// Open a `Watch` stream now.
    OpenWatch,
    /// Send an HTTP/2 PING on the endpoint's connection.
    SendPing,
    /// The stream is silent past the liveness deadline: close it and go to unary.
    CloseStreamAndFallback,
    /// Perform one unary `Check`.
    SendUnaryCheck,
    /// Nothing to do before the next scheduled event.
    Idle,
}

/// Per-endpoint Watch-versus-Check policy. 24 bytes: one mode byte, three `u32`
/// timestamps and counters, and an `Option<u32>`. Owned by the control task, one
/// per endpoint, and not `Sync`; [`CompiledGrpcCheck`] is immutable and shared.
pub struct GrpcModeMachine {
    mode: GrpcMode,
    last_message_at: Millis,
    next_ping_at: Millis,
    unary_checks_since_fallback: u32,
    last_serving: Option<u32>,
}

impl GrpcModeMachine {
    /// A machine in `WatchDesired` when `prefer_watch`, else `UnaryFallback`.
    #[must_use]
    pub fn new(now: Millis, prefer_watch: bool) -> Self {
        Self {
            mode: if prefer_watch {
                GrpcMode::WatchDesired
            } else {
                GrpcMode::UnaryFallback
            },
            last_message_at: now,
            next_ping_at: now,
            unary_checks_since_fallback: 0,
            last_serving: None,
        }
    }

    /// The current mode.
    #[must_use]
    pub fn mode(&self) -> GrpcMode {
        self.mode
    }

    /// Decide what to do at a scheduled check time.
    pub fn on_check_due(
        &mut self,
        now: Millis,
        interval_ms: u32,
        compiled: &CompiledGrpcCheck,
    ) -> GrpcAction {
        match self.mode {
            GrpcMode::WatchDesired => GrpcAction::OpenWatch,
            GrpcMode::WatchOpen => {
                // `saturating_mul`, because `interval_ms` may be as large as
                // `Millis::HORIZON_MS` and the multiplier as large as 100, so the
                // product overflows `u32`.
                let liveness_deadline_ms =
                    interval_ms.saturating_mul(compiled.liveness_multiplier());
                if now.since(self.last_message_at) > liveness_deadline_ms {
                    // The name says fallback; the mode goes to `WatchDesired`
                    // because a dead stream is retried as a stream once, and
                    // only an `UNIMPLEMENTED` answer moves to `UnaryFallback`.
                    self.mode = GrpcMode::WatchDesired;
                    GrpcAction::CloseStreamAndFallback
                } else if !now.is_at_or_before(self.next_ping_at) {
                    self.next_ping_at = now.add_ms(interval_ms);
                    GrpcAction::SendPing
                } else {
                    GrpcAction::Idle
                }
            }
            GrpcMode::UnaryFallback => {
                // The `prefer_watch` guard is what makes `prefer_watch: false`
                // mean "never use Watch": without it this clause would open a
                // stream after `watch_retry_after_checks` unary checks even
                // though `Watch` was never wanted.
                if compiled.prefer_watch()
                    && self.unary_checks_since_fallback >= compiled.watch_retry_after_checks()
                {
                    self.mode = GrpcMode::WatchDesired;
                    self.unary_checks_since_fallback = 0;
                    GrpcAction::OpenWatch
                } else {
                    self.unary_checks_since_fallback =
                        self.unary_checks_since_fallback.saturating_add(1);
                    GrpcAction::SendUnaryCheck
                }
            }
        }
    }

    /// A `Watch` stream was accepted.
    pub fn on_watch_open(&mut self, now: Millis, interval_ms: u32) {
        self.mode = GrpcMode::WatchOpen;
        self.last_message_at = now;
        self.next_ping_at = now.add_ms(interval_ms);
    }

    /// A `HealthCheckResponse` arrived on the open stream.
    pub fn on_watch_message(&mut self, now: Millis, raw: Option<u32>) {
        self.last_message_at = now;
        self.last_serving = raw;
    }

    /// The `Watch` stream ended. `verdict.unimplemented` decides whether this
    /// becomes a sticky unary fallback or a stream retry.
    pub fn on_watch_closed(&mut self, now: Millis, verdict: GrpcVerdict) {
        // `now` is not consulted: neither transition below updates a timestamp,
        // only `mode` and `unary_checks_since_fallback` (and, in both cases,
        // `last_serving`). It is kept in the signature for symmetry with the
        // machine's other event methods and for the runner's own bookkeeping.
        let _ = now;
        if verdict.unimplemented {
            self.mode = GrpcMode::UnaryFallback;
            self.unary_checks_since_fallback = 0;
        } else {
            self.mode = GrpcMode::WatchDesired;
        }
        self.last_serving = None;
    }

    /// A PING was acknowledged; the connection is alive.
    pub fn on_ping_ack(&mut self, now: Millis) {
        self.last_message_at = now;
    }

    /// The outcome to report when no RPC was sent this interval, which is the
    /// steady state in `WatchOpen`. `None` in the other modes, where an explicit
    /// report follows a sent RPC instead.
    #[must_use]
    pub fn current_outcome(&self) -> Option<CheckOutcome> {
        match self.mode {
            GrpcMode::WatchOpen => Some(if self.last_serving == Some(1) {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail(FailKind::Status)
            }),
            GrpcMode::WatchDesired | GrpcMode::UnaryFallback => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::grpc::GrpcCheckSpec;

    fn valid_spec(prefer_watch: bool) -> GrpcCheckSpec {
        GrpcCheckSpec {
            prefer_watch,
            ..GrpcCheckSpec::default()
        }
    }

    #[test]
    fn starts_watch_desired() {
        let now = Millis(0);
        let compiled = valid_spec(true).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(now, true);
        assert_eq!(machine.mode(), GrpcMode::WatchDesired);
        assert_eq!(
            machine.on_check_due(now, 1000, &compiled),
            GrpcAction::OpenWatch
        );
    }

    #[test]
    fn prefer_watch_false_never_opens() {
        let now = Millis(0);
        let compiled = valid_spec(false).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(now, false);
        let mut t = now;
        for i in 0..100 {
            assert_eq!(
                machine.on_check_due(t, 1000, &compiled),
                GrpcAction::SendUnaryCheck,
                "check {i}"
            );
            t = t.add_ms(1000);
        }
    }

    #[test]
    fn watch_open_pings_then_idles() {
        let now = Millis(0);
        let compiled = valid_spec(true).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(now, true);
        machine.on_watch_open(now, 1000);

        // `next_ping_at` is `now + 1000`. A check exactly at that instant is
        // still "at or before" it (`is_at_or_before` uses `<=`), so it must not
        // fire yet; one millisecond past it must.
        let t_ping = now.add_ms(1001);
        assert_eq!(
            machine.on_check_due(t_ping, 1000, &compiled),
            GrpcAction::SendPing
        );
        assert_eq!(
            machine.on_check_due(t_ping, 1000, &compiled),
            GrpcAction::Idle
        );
    }

    #[test]
    fn watch_liveness_fires() {
        let t0 = Millis(5_000);
        let compiled = valid_spec(true).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(t0, true);
        machine.on_watch_open(t0, 1000);

        let later = t0.add_ms(3_001);
        assert_eq!(
            machine.on_check_due(later, 1000, &compiled),
            GrpcAction::CloseStreamAndFallback
        );
        assert_eq!(machine.mode(), GrpcMode::WatchDesired);
    }

    /// The ACCEPT side of the liveness boundary: `watch_liveness_fires` above only
    /// proves one millisecond past the `interval_ms * liveness_multiplier`
    /// deadline (3001 against a deadline of 3000) fires. That alone cannot
    /// distinguish `since > deadline` from `since >= deadline`, since 3001
    /// satisfies both; a mutant that widens the comparison to `>=` fires one
    /// millisecond early and would leave that test green. This checks exactly at
    /// the deadline (3000), where the two comparisons disagree, and asserts the
    /// stream is NOT yet closed.
    #[test]
    fn watch_liveness_does_not_fire_at_exact_deadline() {
        let t0 = Millis(5_000);
        let compiled = valid_spec(true).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(t0, true);
        machine.on_watch_open(t0, 1000);

        let at_deadline = t0.add_ms(3_000);
        let action = machine.on_check_due(at_deadline, 1000, &compiled);
        assert!(
            matches!(action, GrpcAction::SendPing | GrpcAction::Idle),
            "expected SendPing or Idle exactly at the deadline, got {action:?}"
        );
        assert_eq!(machine.mode(), GrpcMode::WatchOpen);
    }

    #[test]
    fn ping_ack_defers_liveness() {
        let t0 = Millis(1_000);
        let compiled = valid_spec(true).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(t0, true);
        machine.on_watch_open(t0, 1000);
        machine.on_ping_ack(t0.add_ms(2_000));

        let later = t0.add_ms(3_001);
        let action = machine.on_check_due(later, 1000, &compiled);
        assert!(
            matches!(action, GrpcAction::SendPing | GrpcAction::Idle),
            "expected SendPing or Idle, got {action:?}"
        );
    }

    #[test]
    fn unimplemented_is_sticky() {
        let t0 = Millis(0);
        let compiled = valid_spec(true).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(t0, true);

        let verdict = GrpcVerdict {
            outcome: CheckOutcome::Fail(FailKind::Protocol),
            raw_serving_status: None,
            grpc_status: Some(12),
            unimplemented: true,
        };
        machine.on_watch_closed(t0, verdict);
        assert_eq!(machine.mode(), GrpcMode::UnaryFallback);

        let mut t = t0;
        for i in 0..20 {
            assert_eq!(
                machine.on_check_due(t, 1000, &compiled),
                GrpcAction::SendUnaryCheck,
                "check {i}"
            );
            t = t.add_ms(1000);
        }
        assert_eq!(
            machine.on_check_due(t, 1000, &compiled),
            GrpcAction::OpenWatch
        );
        assert_eq!(machine.mode(), GrpcMode::WatchDesired);
    }

    #[test]
    fn network_close_retries_watch() {
        let t0 = Millis(0);
        let compiled = valid_spec(true).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(t0, true);
        machine.on_watch_open(t0, 1000);

        let verdict = GrpcVerdict {
            outcome: CheckOutcome::Fail(FailKind::Protocol),
            raw_serving_status: None,
            grpc_status: None,
            unimplemented: false,
        };
        machine.on_watch_closed(t0, verdict);
        assert_eq!(machine.mode(), GrpcMode::WatchDesired);
        assert_eq!(
            machine.on_check_due(t0, 1000, &compiled),
            GrpcAction::OpenWatch
        );
    }

    #[test]
    fn current_outcome_tracks_last_message() {
        let t0 = Millis(0);
        let mut machine = GrpcModeMachine::new(t0, true);
        assert_eq!(machine.current_outcome(), None, "WatchDesired reports None");

        machine.on_watch_open(t0, 1000);
        machine.on_watch_message(t0, Some(1));
        assert_eq!(machine.current_outcome(), Some(CheckOutcome::Pass));

        machine.on_watch_message(t0, Some(2));
        assert_eq!(
            machine.current_outcome(),
            Some(CheckOutcome::Fail(FailKind::Status))
        );

        let verdict = GrpcVerdict {
            outcome: CheckOutcome::Fail(FailKind::Protocol),
            raw_serving_status: None,
            grpc_status: Some(12),
            unimplemented: true,
        };
        machine.on_watch_closed(t0, verdict);
        assert_eq!(machine.mode(), GrpcMode::UnaryFallback);
        assert_eq!(
            machine.current_outcome(),
            None,
            "UnaryFallback reports None"
        );
    }
}
