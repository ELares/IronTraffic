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
                    // #747 BLOCKING: this exit from `WatchOpen` never calls
                    // `on_watch_closed` (there is no `GrpcVerdict`: nothing
                    // was received to decode, and the mode transition above
                    // is already this method's own decision), so the reset
                    // that method performs on every other exit does not run
                    // here on its own. Without this line the next stream
                    // opened for this endpoint inherits a dead stream's
                    // `last_serving` and `current_outcome()` reports `Pass`
                    // before that stream has received a single message: a
                    // backend that accepts every stream and then sends
                    // nothing is never ejected.
                    self.last_serving = None;
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
    ///
    /// A no-op unless the mode is `WatchOpen`. #747 BLOCKING (second path): this
    /// machine carries no stream identity, so a frame drained from a stream that
    /// has already closed (the runner is draining a socket buffer, or the frame
    /// was already in flight when the liveness timer or `on_watch_closed` fired)
    /// would otherwise be recorded as evidence about whatever stream opens next.
    /// Gating on the mode means such a frame lands strictly between a close and
    /// the following `on_watch_open`, when the mode is `WatchDesired` or
    /// `UnaryFallback`, not `WatchOpen`, so it is dropped rather than
    /// misattributed.
    pub fn on_watch_message(&mut self, now: Millis, raw: Option<u32>) {
        if self.mode == GrpcMode::WatchOpen {
            self.last_message_at = now;
            self.last_serving = raw;
        }
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

    /// #747 BLOCKING, path 1: the liveness-timeout exit from `WatchOpen` never
    /// calls `on_watch_closed` (there is no `GrpcVerdict` for a silent stream),
    /// so it must clear `last_serving` itself. Reproduces the reviewer's
    /// end-to-end shape at the unit level: a stream reports `Pass`, goes
    /// silent, is closed by the liveness timer, and the freshly reopened
    /// stream must report `Fail`, not inherit the dead stream's `Pass`, even
    /// though it too has received zero messages.
    #[test]
    fn watch_reopen_after_liveness_timeout_reports_fail_with_zero_messages() {
        let t0 = Millis(0);
        let compiled = valid_spec(true).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(t0, true);
        machine.on_watch_open(t0, 1000);
        machine.on_watch_message(t0, Some(1));
        assert_eq!(machine.current_outcome(), Some(CheckOutcome::Pass));

        let later = t0.add_ms(3_001);
        assert_eq!(
            machine.on_check_due(later, 1000, &compiled),
            GrpcAction::CloseStreamAndFallback
        );
        assert_eq!(machine.mode(), GrpcMode::WatchDesired);
        assert_eq!(
            machine.on_check_due(later, 1000, &compiled),
            GrpcAction::OpenWatch
        );

        // The runner reopens a stream. Zero messages have arrived on it.
        machine.on_watch_open(later, 1000);
        assert_eq!(
            machine.current_outcome(),
            Some(CheckOutcome::Fail(FailKind::Status)),
            "a freshly opened stream with zero messages must not inherit the dead stream's Pass"
        );
    }

    /// #747: kills `M7-del-last-serving-reset-on-close`, which survives against
    /// the shipped suite because nothing reopens Watch after a normal
    /// (`on_watch_closed`) exit and checks `current_outcome()` again. This is
    /// the network-failure sibling of
    /// `watch_reopen_after_liveness_timeout_reports_fail_with_zero_messages`
    /// above: same stale-`Pass` shape, but reached through the exit that DOES
    /// call `on_watch_closed`, to pin the reset that method already performs
    /// (deleting `self.last_serving = None;` there is otherwise unobserved by
    /// any test).
    #[test]
    fn watch_reopen_after_close_reports_fail_with_zero_messages() {
        let t0 = Millis(0);
        let mut machine = GrpcModeMachine::new(t0, true);
        machine.on_watch_open(t0, 1000);
        machine.on_watch_message(t0, Some(1));
        assert_eq!(machine.current_outcome(), Some(CheckOutcome::Pass));

        let verdict = GrpcVerdict {
            outcome: CheckOutcome::Fail(FailKind::Protocol),
            raw_serving_status: None,
            grpc_status: None,
            unimplemented: false,
        };
        machine.on_watch_closed(t0, verdict);
        assert_eq!(machine.mode(), GrpcMode::WatchDesired);

        machine.on_watch_open(t0, 1000);
        assert_eq!(
            machine.current_outcome(),
            Some(CheckOutcome::Fail(FailKind::Status)),
            "on_watch_closed's last_serving reset must survive into the next stream"
        );
    }

    /// #747 BLOCKING, path 2: `on_watch_message` carries no stream identity, so
    /// a frame drained from a stream that already closed must not be
    /// attributed to whatever stream opens next. Simulates a frame from stream
    /// A that was already in flight when A closed, draining after
    /// `on_watch_closed` has already moved the mode off `WatchOpen` but before
    /// stream B's `on_watch_open` runs.
    #[test]
    fn late_watch_message_after_close_is_ignored() {
        let t0 = Millis(0);
        let compiled = valid_spec(true).compile().expect("valid spec");
        let mut machine = GrpcModeMachine::new(t0, true);
        machine.on_watch_open(t0, 1000);
        machine.on_watch_message(t0, Some(1));
        assert_eq!(machine.current_outcome(), Some(CheckOutcome::Pass));

        let verdict = GrpcVerdict {
            outcome: CheckOutcome::Fail(FailKind::Protocol),
            raw_serving_status: None,
            grpc_status: None,
            unimplemented: false,
        };
        machine.on_watch_closed(t0, verdict);
        assert_eq!(machine.mode(), GrpcMode::WatchDesired);

        // A frame from the just-closed stream A, already in flight, drains
        // after the close but before B's `on_watch_open`. Without the mode
        // gate this would set `last_serving` back to `Some(1)`.
        machine.on_watch_message(t0, Some(1));

        assert_eq!(
            machine.on_check_due(t0, 1000, &compiled),
            GrpcAction::OpenWatch
        );
        machine.on_watch_open(t0, 1000);
        assert_eq!(
            machine.current_outcome(),
            Some(CheckOutcome::Fail(FailKind::Status)),
            "a message drained from the closed stream must not be attributed to the next one"
        );
    }

    /// #747 VERIFICATION: the reviewer's end-to-end probe, driven through the
    /// shipped `EndpointSchedule` with `HealthCheckConfig::default()` for 200
    /// intervals. The backend accepts every stream and sends exactly one real
    /// `SERVING` message ever, on the very first stream, then black-holes
    /// every reopened stream after it (accepts the stream, sends nothing, and
    /// -- this is a true black hole, not merely a quiet server -- never acks
    /// a PING either, since a middlebox that silently drops a connection
    /// drops everything on it): the canonical "was healthy, then
    /// black-holed" case the BLOCKING finding's title names. Before the fix
    /// this stayed `Healthy` forever with zero `ToUnhealthy` transitions,
    /// because every reopened stream inherited the one real `Pass` verdict;
    /// the fixed machine must eject it.
    #[test]
    fn endpoint_schedule_ejects_a_black_holing_watch_backend() {
        use crate::health::bitmap::EndpointHealth;
        use crate::health::schedule::{EndpointSchedule, HealthCheckConfig, Transition};

        let cfg = HealthCheckConfig::default();
        let compiled = valid_spec(true).compile().expect("valid spec");
        let t0 = Millis(0);
        let mut schedule = EndpointSchedule::init(t0, 1, 1, &cfg, true);
        let mut machine = GrpcModeMachine::new(t0, true);

        let mut t = t0;
        let mut sent_first_message = false;
        let mut to_unhealthy = 0u32;
        let mut passes = 0u32;
        let mut fails = 0u32;

        for _ in 0..200 {
            let action = machine.on_check_due(t, cfg.interval_ms, &compiled);
            if let GrpcAction::OpenWatch = action {
                machine.on_watch_open(t, cfg.interval_ms);
                if !sent_first_message {
                    machine.on_watch_message(t, Some(1));
                    sent_first_message = true;
                }
            }
            // `SendPing`, `CloseStreamAndFallback`, `SendUnaryCheck`, and
            // `Idle` all need no reaction from this probe: a true black hole
            // never acks the PING the runner would send, never answers the
            // unary `Check` the runner would dispatch after falling back
            // (both would time out, which this probe does not need to model
            // since the mode machine already treats a stream it has not
            // heard from as the failure it is), and closing or idling needs
            // no event call at all.
            if let Some(outcome) = machine.current_outcome() {
                match outcome {
                    CheckOutcome::Pass => passes += 1,
                    CheckOutcome::Fail(_) => fails += 1,
                }
                if schedule.apply_outcome(outcome, &cfg) == Transition::ToUnhealthy {
                    to_unhealthy += 1;
                }
            }
            t = t.add_ms(cfg.interval_ms);
        }

        assert!(
            to_unhealthy >= 1,
            "a backend that black-holes after one real message must eventually be ejected \
             (passes={passes} fails={fails} to_unhealthy={to_unhealthy})"
        );
        assert_eq!(
            schedule.active_health,
            EndpointHealth::Unhealthy,
            "passes={passes} fails={fails} to_unhealthy={to_unhealthy}"
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
