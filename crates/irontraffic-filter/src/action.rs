// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a filter decides at one phase: `Action`, the short-circuit descriptor
//! `DirectResponse` it may carry, the transport-level `ResetCode`, why a chain
//! short-circuited (`ShortCircuitReason`), and the separate per-chunk
//! backpressure decision `BodyDisposition`.
//!
//! `Action` and `DirectResponse` are returned by value on the request path, so
//! both stay small and neither owns heap memory. See `DirectResponse`'s docs
//! for why a short-circuit response is a descriptor rather than an owned
//! response.

const _: () = assert!(core::mem::size_of::<Action>() <= 12);

/// What a filter decided at one phase.
///
/// Four variants, deliberately not five: Envoy's `FilterHeadersStatus`
/// conflates iteration control with flow control, which is why
/// `StopAllIterationAndBuffer` versus `StopAllIterationAndWatermark` is a
/// common Envoy filter bug. Here, `Action` says only whether iteration
/// proceeds; `BodyDisposition` carries the separate, revisable buffering
/// decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Proceed to the next filter in this phase.
    Continue,
    /// This filter is not done. The chain records the filter index, stops the phase,
    /// and polls this filter again through `Filter::poll_resume`.
    Pause,
    /// Stop the chain and send this response downstream. Filters before this one in
    /// the chain still see the response path, in reverse order.
    Respond(DirectResponse),
    /// Abort the stream at the transport level.
    Reset(ResetCode),
}

impl Action {
    /// True for `Continue` only. The chain's hot branch.
    #[inline]
    #[must_use]
    pub const fn is_continue(self) -> bool {
        matches!(self, Action::Continue)
    }

    /// True for `Respond` and `Reset`: the phase is over and the stream is finishing.
    #[inline]
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Action::Respond(_) | Action::Reset(_))
    }
}

/// A short-circuit response descriptor, `Copy` and eight bytes: a status, an
/// index into the configuration snapshot's interned response-template table,
/// and why.
///
/// Templates (their header set and their static body) are owned by the
/// immutable configuration snapshot, interned once at config-commit time.
/// Building an owned response per rejection, the way Envoy's `local_reply`
/// does, is an allocation on the path an attacker controls.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DirectResponse {
    /// Status to send, in `200..=599`. A short-circuit response is a *final*
    /// response, so the informational range `100..=199` is rejected: a 1xx does not
    /// terminate the exchange, so a filter-generated 1xx leaves the downstream peer
    /// waiting for a final response that never comes (an HTTP/1 connection that is
    /// never reusable, an HTTP/2 stream that is never closed) until a timeout fires.
    /// Every layer that can produce a `Respond` is reachable from a peer or from
    /// partly trusted code, so this is a stream-hang primitive and is rejected at the
    /// one constructor rather than at each of the four call sites.
    pub status: u16,
    /// Index into the configuration snapshot's interned response-template table, or
    /// `DirectResponse::NO_TEMPLATE` for a bare status line with no body.
    ///
    /// This type cannot validate the index: it does not know the snapshot. It is
    /// therefore an untrusted value whenever it originates outside this process (a
    /// WASM guest, an `ext_proc` processor) or outside the current snapshot (an action
    /// value that outlived a config commit). Every consumer resolves it with
    /// `templates.get(dr.template as usize)`, never with `[]`.
    pub template: u16,
    /// Why the chain short-circuited. Recorded in the access log and the response flag.
    pub reason: ShortCircuitReason,
}

impl DirectResponse {
    /// Template index meaning "status line only, no configured headers, empty body".
    pub const NO_TEMPLATE: u16 = u16::MAX;

    /// A direct response, or `None` when `status` is outside `200..=599`.
    ///
    /// The informational range is rejected on purpose; see the field documentation.
    /// Returning `Option` rather than clamping is deliberate: a filter that computes
    /// a status of 0 has a bug, and clamping to 500 hides it inside a response an
    /// operator will misread as an upstream failure.
    #[must_use]
    pub const fn new(
        status: u16,
        template: u16,
        reason: ShortCircuitReason,
    ) -> Option<DirectResponse> {
        if status < 200 || status > 599 {
            None
        } else {
            Some(DirectResponse {
                status,
                template,
                reason,
            })
        }
    }

    /// A bare status-line response with no template. Exactly
    /// `DirectResponse::new(status, DirectResponse::NO_TEMPLATE, reason)`.
    #[must_use]
    pub const fn status_only(status: u16, reason: ShortCircuitReason) -> Option<DirectResponse> {
        DirectResponse::new(status, DirectResponse::NO_TEMPLATE, reason)
    }
}

/// The HTTP/2 error code a stream reset maps to, and the reason IronTraffic
/// itself is aborting the stream at the transport level.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum ResetCode {
    /// Deliberate rejection. HTTP/2 CANCEL, HTTP/1 connection close.
    Cancel = 0,
    /// The peer violated a rule this filter enforces. HTTP/2 `PROTOCOL_ERROR`.
    ProtocolError = 1,
    /// The filter itself failed and the stream cannot continue. HTTP/2 `INTERNAL_ERROR`.
    InternalError = 2,
    /// A limit this filter enforces was exceeded. HTTP/2 `ENHANCE_YOUR_CALM`.
    Overload = 3,
}

impl ResetCode {
    /// The HTTP/2 error code (RFC 9113 Section 7) this reset maps to.
    #[must_use]
    pub const fn h2_error_code(self) -> u32 {
        match self {
            ResetCode::Cancel => 0x8,
            ResetCode::ProtocolError => 0x1,
            ResetCode::InternalError => 0x2,
            ResetCode::Overload => 0xb,
        }
    }

    /// The reset code for a stored or wire discriminant, or `None` when `i >= 4`.
    ///
    /// The one conversion from a number to a `ResetCode`, for the same reason
    /// `Arena::from_index` and `Phase::from_index` are: the WASM ABI and the `ext_proc`
    /// decoder both receive a reset code as an integer from outside this process and
    /// must have exactly one place to reject an undefined one.
    #[must_use]
    pub const fn from_index(i: u8) -> Option<ResetCode> {
        match i {
            0 => Some(ResetCode::Cancel),
            1 => Some(ResetCode::ProtocolError),
            2 => Some(ResetCode::InternalError),
            3 => Some(ResetCode::Overload),
            _ => None,
        }
    }
}

/// Why the chain short-circuited a stream.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum ShortCircuitReason {
    /// An authorization filter denied the request.
    AuthzDenied = 0,
    /// A policy expression selected a deny action.
    PolicyDenied = 1,
    /// A rate, quota or concurrency filter denied the request.
    LimitExceeded = 2,
    /// A body filter exceeded its per-stream buffer budget.
    BodyBudgetExceeded = 3,
    /// A filter paused and did not resume within its deadline.
    PauseDeadlineExceeded = 4,
    /// A filter failed and its effective failure mode is fail closed.
    FilterFailedClosed = 5,
    /// The filter produced this response as its normal output: a mock, a redirect,
    /// a CORS preflight answer.
    FilterGenerated = 6,
}

impl ShortCircuitReason {
    /// The stable `snake_case` name emitted as the access-log field, and as the
    /// `x-irontraffic-response-flag` response header **only when the listener enables
    /// `emit_response_flag_header` (default `false`)**.
    ///
    /// The default is off because the flag distinguishes "you failed authorization"
    /// from "you were rate limited" from "a policy denied you", which is exactly the
    /// oracle an attacker uses to map a policy set from outside. The access log
    /// always records it; the wire does not, unless an operator asks.
    ///
    /// The exact table, which no other issue may re-invent:
    /// `AuthzDenied` -> `"authz_denied"`, `PolicyDenied` -> `"policy_denied"`,
    /// `LimitExceeded` -> `"limit_exceeded"`, `BodyBudgetExceeded` ->
    /// `"body_budget_exceeded"`, `PauseDeadlineExceeded` -> `"pause_deadline_exceeded"`,
    /// `FilterFailedClosed` -> `"filter_failed_closed"`, `FilterGenerated` ->
    /// `"filter_generated"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ShortCircuitReason::AuthzDenied => "authz_denied",
            ShortCircuitReason::PolicyDenied => "policy_denied",
            ShortCircuitReason::LimitExceeded => "limit_exceeded",
            ShortCircuitReason::BodyBudgetExceeded => "body_budget_exceeded",
            ShortCircuitReason::PauseDeadlineExceeded => "pause_deadline_exceeded",
            ShortCircuitReason::FilterFailedClosed => "filter_failed_closed",
            ShortCircuitReason::FilterGenerated => "filter_generated",
        }
    }
}

/// The per-chunk backpressure decision for a streaming body phase.
///
/// Split out of `Action` on purpose: whether bytes are retained and whether
/// the peer is throttled can be revised on every chunk without changing
/// whether iteration itself proceeds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum BodyDisposition {
    /// Forward this chunk now. Zero buffering.
    Forward = 0,
    /// Retain this chunk. The chain charges its bytes against the per-stream budget.
    Hold = 1,
    /// Retain this chunk and stop reading from the peer until bytes are released.
    HoldAndPause = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_REASONS: [ShortCircuitReason; 7] = [
        ShortCircuitReason::AuthzDenied,
        ShortCircuitReason::PolicyDenied,
        ShortCircuitReason::LimitExceeded,
        ShortCircuitReason::BodyBudgetExceeded,
        ShortCircuitReason::PauseDeadlineExceeded,
        ShortCircuitReason::FilterFailedClosed,
        ShortCircuitReason::FilterGenerated,
    ];

    #[test]
    fn direct_response_range() {
        let r = ShortCircuitReason::PolicyDenied;
        assert!(DirectResponse::new(0, 0, r).is_none());
        assert!(DirectResponse::new(99, 0, r).is_none());
        assert!(DirectResponse::new(600, 0, r).is_none());
        assert!(DirectResponse::new(65535, 0, r).is_none());
        assert!(DirectResponse::new(200, 0, r).is_some());
        assert!(DirectResponse::new(404, 0, r).is_some());
        assert!(DirectResponse::new(599, 0, r).is_some());
    }

    #[test]
    fn direct_response_rejects_informational() {
        // Exhaustive over the whole 1xx range. This is the test that fails if
        // someone "restores" the 100 lower bound: a short-circuit response is
        // a *final* response, and accepting a 1xx here would let any layer
        // that can return `Action::Respond` (a policy `deny`, a WASM guest, an
        // ext_proc `ImmediateResponse`) manufacture a downstream peer that
        // waits for a final response that never arrives.
        for status in 100..=199u16 {
            let r = ShortCircuitReason::PolicyDenied;
            assert!(DirectResponse::new(status, 0, r).is_none());
            assert!(DirectResponse::status_only(status, r).is_none());
        }
    }

    #[test]
    fn action_size_and_copy() {
        fn takes_by_value(a: Action) -> Action {
            a
        }

        assert!(core::mem::size_of::<Action>() <= 12);

        let a = Action::Continue;
        let b = takes_by_value(a);
        // `a` is still usable after being passed by value: compile-time proof
        // that `Action` is `Copy`, not merely `Clone`.
        assert_eq!(a, Action::Continue);
        assert_eq!(b, Action::Continue);
    }

    #[test]
    fn reset_code_h2_mapping() {
        assert_eq!(ResetCode::Cancel.h2_error_code(), 0x8);
        assert_eq!(ResetCode::ProtocolError.h2_error_code(), 0x1);
        assert_eq!(ResetCode::InternalError.h2_error_code(), 0x2);
        assert_eq!(ResetCode::Overload.h2_error_code(), 0xb);
    }

    #[test]
    fn reset_code_from_index_roundtrip() {
        assert_eq!(ResetCode::from_index(0), Some(ResetCode::Cancel));
        assert_eq!(ResetCode::from_index(1), Some(ResetCode::ProtocolError));
        assert_eq!(ResetCode::from_index(2), Some(ResetCode::InternalError));
        assert_eq!(ResetCode::from_index(3), Some(ResetCode::Overload));
        assert!(ResetCode::from_index(4).is_none());
        assert!(ResetCode::from_index(255).is_none());
    }

    #[test]
    fn reason_names_are_unique() {
        let mut names: Vec<&str> = ALL_REASONS.iter().map(|r| r.as_str()).collect();
        names.sort_unstable();
        for w in names.windows(2) {
            assert_ne!(w[0], w[1]);
        }
        assert!(names.iter().all(|n| !n.is_empty()));
    }

    #[test]
    fn reason_names_exact() {
        let names: Vec<&str> = ALL_REASONS.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "authz_denied",
                "policy_denied",
                "limit_exceeded",
                "body_budget_exceeded",
                "pause_deadline_exceeded",
                "filter_failed_closed",
                "filter_generated",
            ]
        );
    }
}
