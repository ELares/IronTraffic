// SPDX-License-Identifier: MIT OR Apache-2.0
//! The retryability conjunction: proof-of-non-processing and the commit point.
//!
//! [`retryable`] decides whether one failed attempt may be retried. It is a
//! CONJUNCTION, evaluated in a fixed order, and it must not be simplified:
//!
//! ```text
//! retryable(req, failure) =
//!       matches_configured_retry_on(failure)
//!   AND ( idempotent(req.method) OR proves_not_processed(failure) )
//!   AND NOT committed(req)
//!   AND attempts_remaining(req)
//!   AND deadline_permits(req)
//!   AND budget.withdraw()          -- NOT part of this function; see [`retryable`]'s doc
//! ```
//!
//! The second clause is the one that matters: without it, retrying a POST the origin
//! already applied double-charges a credit card. Retrying a non-idempotent request the
//! origin may have processed is a CORRECTNESS bug, not a performance bug, and no amount
//! of throughput pays for it.
//!
//! The default for an unknown or uncertain state is NOT RETRYABLE. Every classification
//! function here ([`FailureKind::proves_not_processed`], [`FailureKind::matches`]) is an
//! exhaustive match with no wildcard arm, so a new [`FailureKind`] variant that nobody
//! has classified yet is a compile error, never a silent grant of retryability. A
//! [`PerTryTimeout`](FailureKind::PerTryTimeout) is the clearest instance of the
//! principle: a timeout means we do not know what happened, and "we do not know" is not
//! "it did not happen", so it does not prove non-processing.
//!
//! This module is pure, allocation-free, and performs no I/O. It never reads a clock;
//! every function that needs the current time takes it as a [`Millis`] parameter.

use crate::clock::Millis;
use crate::config::{ConfigError, in_range_u32};
use crate::deadline::Deadline;

/// Why an attempt failed.
///
/// Closed and exhaustively matched everywhere, so adding a variant forces every
/// classification function ([`FailureKind::proves_not_processed`],
/// [`FailureKind::matches`]) to be updated rather than silently defaulting.
///
/// NOT the same type as a health check's own failure classification, which has
/// different variants and a different purpose: a health check's timeout says nothing
/// about whether an upstream processed a real request, and the two must never be
/// converted into one another.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FailureKind {
    /// TCP connect failed or timed out. No bytes reached the application.
    ConnectFailure,
    /// The TLS handshake failed. No bytes reached the application.
    TlsHandshakeFailure,
    /// HTTP/2 `RST_STREAM` with error code `REFUSED_STREAM`. This is the UPSTREAM's
    /// assertion that it did not process the request, believed on the strength of
    /// RFC 9113 Section 8.7's "MUST NOT indicate ... unless it can guarantee that fact".
    /// A dishonest upstream can use it to make us double-apply a POST.
    RefusedStream,
    /// HTTP/2 `GOAWAY` whose `last_stream_id` is STRICTLY below our stream id. Equal
    /// means our stream may have been processed; `<=` here is a double-application bug.
    /// Also an upstream assertion.
    GoAwayUnprocessed,
    /// HTTP/3 `H3_REQUEST_REJECTED`. Also an upstream assertion.
    H3RequestRejected,
    /// Our connection was reset before any request byte for this stream was accepted by
    /// a write syscall. Derived from the transport's actual write accounting, never from
    /// what the proxy intended to write; a partial write of unknown length is
    /// [`ResetAfterRequest`](FailureKind::ResetAfterRequest). This is OUR OWN
    /// observation and holds against a hostile upstream.
    ResetBeforeRequest,
    /// The connection or stream was reset after we wrote request bytes. Does NOT prove
    /// non-processing.
    ResetAfterRequest,
    /// The per-try timeout fired. Does NOT prove non-processing: "we do not know what
    /// happened" is not "it did not happen".
    PerTryTimeout,
    /// The upstream returned this HTTP status.
    UpstreamStatus(u16),
    /// The upstream returned this gRPC status code.
    GrpcStatus(u16),
    /// We refused the attempt ourselves because of local overload.
    LocalOverload,
}

impl FailureKind {
    /// TRUE ONLY when the protocol GUARANTEES the origin did not process the request.
    ///
    /// RFC 9113 Section 8.7. Getting this wrong is a correctness bug, not a performance
    /// bug: a retry permitted by a false positive here double-applies a mutation.
    /// Implemented as an exhaustive match with no wildcard arm: a new variant that
    /// nobody has classified is a compile error here, never a silent `true`.
    #[inline]
    #[must_use]
    pub fn proves_not_processed(self) -> bool {
        match self {
            FailureKind::ConnectFailure
            | FailureKind::TlsHandshakeFailure
            | FailureKind::RefusedStream
            | FailureKind::GoAwayUnprocessed
            | FailureKind::H3RequestRejected
            | FailureKind::ResetBeforeRequest => true,
            FailureKind::ResetAfterRequest
            | FailureKind::PerTryTimeout
            | FailureKind::UpstreamStatus(_)
            | FailureKind::GrpcStatus(_)
            | FailureKind::LocalOverload => false,
        }
    }

    /// Whether this failure is in the configured retry-on set.
    ///
    /// Returns false for every HTTP status below 500, including 409 and 429: there is no
    /// `retriable-4xx` and there never will be, because a 409 is proof the server DID
    /// process the request. Implemented as an exhaustive match with no wildcard arm over
    /// [`FailureKind`].
    #[inline]
    #[must_use]
    pub fn matches(self, retry_on: RetryOn) -> bool {
        match self {
            FailureKind::ConnectFailure | FailureKind::TlsHandshakeFailure => {
                retry_on.contains(RetryOn::CONNECT_FAILURE)
            }
            // A GOAWAY below our stream id is the same guarantee as REFUSED_STREAM;
            // Envoy groups them under the same bit.
            FailureKind::RefusedStream | FailureKind::GoAwayUnprocessed => {
                retry_on.contains(RetryOn::REFUSED_STREAM)
            }
            FailureKind::H3RequestRejected => {
                retry_on.contains(RetryOn::HTTP3_POST_CONNECT_FAILURE)
            }
            FailureKind::ResetBeforeRequest => retry_on.contains(RetryOn::RESET_BEFORE_REQUEST),
            FailureKind::ResetAfterRequest => retry_on.contains(RetryOn::RESET),
            FailureKind::PerTryTimeout => retry_on.contains(RetryOn::PER_TRY_TIMEOUT),
            FailureKind::LocalOverload => retry_on.contains(RetryOn::LOCAL_OVERLOAD),
            // Exhaustive over every u16 status with no wildcard arm: 502/503/504 are
            // GATEWAY_ERROR, the rest of 500..=599 is FIVE_XX, and every status outside
            // 500..=599 (including every 4xx, 409 and 429 among them) matches nothing.
            FailureKind::UpstreamStatus(status) => match status {
                502..=504 => retry_on.contains(RetryOn::GATEWAY_ERROR),
                500..=501 | 505..=599 => retry_on.contains(RetryOn::FIVE_XX),
                0..=499 | 600..=u16::MAX => false,
            },
            // Exhaustive over every u16 gRPC code with no wildcard arm: 14 is
            // UNAVAILABLE, 4 is DEADLINE_EXCEEDED, 8 is RESOURCE_EXHAUSTED, and every
            // other code, including 0 (OK), matches nothing.
            FailureKind::GrpcStatus(code) => match code {
                14 => retry_on.contains(RetryOn::GRPC_UNAVAILABLE),
                4 => retry_on.contains(RetryOn::GRPC_DEADLINE_EXCEEDED),
                8 => retry_on.contains(RetryOn::GRPC_RESOURCE_EXHAUSTED),
                0..=3 | 5..=7 | 9..=13 | 15..=u16::MAX => false,
            },
        }
    }
}

/// The configured retry-on set, as bitflags.
///
/// The inner bit field is private on purpose: the only way to build a value is the
/// twelve named associated constants below, [`RetryOn::union`], and
/// [`RetryOn::parse_token`], none of which can ever set a bit outside 0..=11. An
/// operator who wants every class lists them, so the config stays auditable; see
/// [`RetryOn::default`] for the one bundled set this type does provide.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RetryOn(u16);

impl RetryOn {
    /// `connect-failure`, which also covers a TLS handshake failure sharing this bit.
    ///
    /// EQUIVALENT-MUTANT NOTE: `1 << 0` and `1 >> 0` are both `1`, since shifting by
    /// zero positions is the identity regardless of direction. Mutation testing flags
    /// `<<` to `>>` here; no test can distinguish the two spellings because they always
    /// produce the same value, unlike every other bit constant below where the shift
    /// amount is nonzero and the two operators diverge.
    pub const CONNECT_FAILURE: RetryOn = RetryOn(1 << 0);
    /// `refused-stream`, which also covers `GOAWAY` below our stream id.
    pub const REFUSED_STREAM: RetryOn = RetryOn(1 << 1);
    /// `reset-before-request`.
    pub const RESET_BEFORE_REQUEST: RetryOn = RetryOn(1 << 2);
    /// `http3-post-connect-failure`.
    pub const HTTP3_POST_CONNECT_FAILURE: RetryOn = RetryOn(1 << 3);
    /// `5xx`, excluding 502, 503, and 504, which are [`RetryOn::GATEWAY_ERROR`].
    pub const FIVE_XX: RetryOn = RetryOn(1 << 4);
    /// `gateway-error`: 502, 503, 504.
    pub const GATEWAY_ERROR: RetryOn = RetryOn(1 << 5);
    /// `reset`: a reset after request bytes were written.
    pub const RESET: RetryOn = RetryOn(1 << 6);
    /// `per-try-timeout`.
    pub const PER_TRY_TIMEOUT: RetryOn = RetryOn(1 << 7);
    /// `grpc-unavailable`: gRPC status 14.
    pub const GRPC_UNAVAILABLE: RetryOn = RetryOn(1 << 8);
    /// `grpc-deadline-exceeded`: gRPC status 4.
    pub const GRPC_DEADLINE_EXCEEDED: RetryOn = RetryOn(1 << 9);
    /// `grpc-resource-exhausted`: gRPC status 8.
    pub const GRPC_RESOURCE_EXHAUSTED: RetryOn = RetryOn(1 << 10);
    /// `local-overload`.
    pub const LOCAL_OVERLOAD: RetryOn = RetryOn(1 << 11);

    /// The union of two sets.
    #[must_use]
    pub const fn union(self, other: RetryOn) -> RetryOn {
        RetryOn(self.0 | other.0)
    }

    /// True when every bit of `other` is set in `self`.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: RetryOn) -> bool {
        self.0 & other.0 == other.0
    }

    /// The empty set.
    #[must_use]
    pub const fn none() -> RetryOn {
        RetryOn(0)
    }

    /// Parse one config token. `Err` for an unknown token, including `retriable-4xx`,
    /// whose error message says it is deliberately not implemented and why.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] when `token` is not one of the recognized retry-on
    /// tokens, naming the field `retry_on`.
    pub fn parse_token(token: &str) -> Result<RetryOn, ConfigError> {
        match token {
            "connect-failure" => Ok(RetryOn::CONNECT_FAILURE),
            "refused-stream" => Ok(RetryOn::REFUSED_STREAM),
            "reset-before-request" => Ok(RetryOn::RESET_BEFORE_REQUEST),
            "http3-post-connect-failure" => Ok(RetryOn::HTTP3_POST_CONNECT_FAILURE),
            "5xx" => Ok(RetryOn::FIVE_XX),
            "gateway-error" => Ok(RetryOn::GATEWAY_ERROR),
            "reset" => Ok(RetryOn::RESET),
            "per-try-timeout" => Ok(RetryOn::PER_TRY_TIMEOUT),
            "grpc-unavailable" => Ok(RetryOn::GRPC_UNAVAILABLE),
            "grpc-deadline-exceeded" => Ok(RetryOn::GRPC_DEADLINE_EXCEEDED),
            "grpc-resource-exhausted" => Ok(RetryOn::GRPC_RESOURCE_EXHAUSTED),
            "local-overload" => Ok(RetryOn::LOCAL_OVERLOAD),
            "retriable-4xx" => Err(ConfigError::new(
                "retry_on",
                token,
                "retriable-4xx is deliberately not implemented: a 409 is proof the \
                 server processed the request, and a 4xx never proves non-processing",
            )),
            _ => Err(ConfigError::new(
                "retry_on",
                token,
                "unknown retry_on token",
            )),
        }
    }
}

impl Default for RetryOn {
    /// The conservative proof-of-non-processing set: [`RetryOn::CONNECT_FAILURE`],
    /// [`RetryOn::REFUSED_STREAM`], [`RetryOn::RESET_BEFORE_REQUEST`],
    /// [`RetryOn::HTTP3_POST_CONNECT_FAILURE`]. Safe for every method, including POST.
    fn default() -> Self {
        RetryOn::CONNECT_FAILURE
            .union(RetryOn::REFUSED_STREAM)
            .union(RetryOn::RESET_BEFORE_REQUEST)
            .union(RetryOn::HTTP3_POST_CONNECT_FAILURE)
    }
}

/// Why a request can no longer be retried. Once set it is never cleared.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitReason {
    /// One or more response bytes were forwarded downstream, headers or body. This is
    /// gRFC A6's "client receives Response-Headers" rule, generalized to HTTP.
    ResponseBytesForwarded,
    /// The request body exceeded `retry_buffer_limit`, so the replay buffer was
    /// released. Buffering never stalls the upload and never spills to disk.
    ReplayBufferOverflow,
    /// The request used `Expect: 100-continue` and the upstream already sent the
    /// interim response.
    InterimResponseSeen,
    /// The request is a WebSocket or CONNECT upgrade, or any bidirectional stream.
    BidirectionalUpgrade,
}

/// Idempotency of the request method, per RFC 9110 Section 9.2.2.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MethodIdempotence {
    /// GET, HEAD, OPTIONS, TRACE, PUT, DELETE.
    Idempotent,
    /// Everything else, including POST, PATCH, CONNECT, and any unknown method.
    NonIdempotent,
}

/// Classify a request method. Case-SENSITIVE per RFC 9110 Section 9.1: `get` is not
/// `GET`. Fails closed: an unknown method, an empty slice, a non-ASCII slice, and a
/// method with trailing whitespace are all [`MethodIdempotence::NonIdempotent`].
/// Compares bytes directly and never allocates or calls `from_utf8`.
#[inline]
#[must_use]
pub fn method_idempotence(method: &[u8]) -> MethodIdempotence {
    match method {
        b"GET" | b"HEAD" | b"OPTIONS" | b"TRACE" | b"PUT" | b"DELETE" => {
            MethodIdempotence::Idempotent
        }
        _ => MethodIdempotence::NonIdempotent,
    }
}

/// Everything the predicate needs. `Copy` and allocation-free.
#[derive(Clone, Copy, Debug)]
pub struct RetryContext {
    /// The route's configured retry-on set.
    pub retry_on: RetryOn,
    /// Classification of the request method.
    pub idempotence: MethodIdempotence,
    /// The per-route escape hatch. Defaults false. Turning it on for an endpoint that is
    /// not actually idempotent is a correctness bug that will double-charge customers.
    pub treat_as_idempotent: bool,
    /// `Some` once the request is committed.
    pub committed: Option<CommitReason>,
    /// Attempts already made, including the original.
    pub attempts_so_far: u32,
    /// Secondary ceiling on total attempts, including the original. Default 3.
    pub max_attempts: u32,
    /// The ORIGINAL request's deadline. Never a fresh one.
    pub deadline: Deadline,
    /// Current time.
    pub now: Millis,
    /// The backoff this retry would sleep for.
    pub backoff_ms: u32,
    /// The route's observed p50 attempt duration, used to refuse a retry that cannot
    /// finish.
    pub min_attempt_estimate_ms: u32,
}

/// The decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RetryDecision {
    /// The caller may now call `budget.withdraw()` and, if it succeeds, retry.
    Retry,
    /// Do not retry, for this reason.
    No(RetryVeto),
}

/// Which clause refused, in the fixed evaluation order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RetryVeto {
    /// The failure class is not in the configured retry-on set.
    NotInRetryOn,
    /// The method is not idempotent and the failure does not prove non-processing.
    NonIdempotent,
    /// The request is committed.
    Committed(CommitReason),
    /// `max_attempts` reached.
    AttemptsExhausted,
    /// The remaining deadline cannot fit the backoff plus one more attempt.
    DeadlineExhausted,
    /// Produced by `retry-attempt-machine` (#105), not by [`retryable`]: the
    /// success-denominated budget refused the withdrawal.
    BudgetExhausted,
}

/// Decide whether a failed attempt may be retried.
///
/// A pure function with no side effects: it does not touch the retry budget, which is
/// why it is safe to call speculatively, for example to compute the
/// `candidate_is_retryable` argument the endpoint breaker's `admit` takes. The caller
/// calls `budget.withdraw()` only after this returns [`RetryDecision::Retry`], because
/// consuming a token for a retry that is then refused silently drains the budget and
/// breaks the amplification bound.
///
/// Evaluated in exactly this order, returning immediately on the first refusal, because
/// the order is part of the contract: the reported veto is a metric an operator reads to
/// debug "why did this not retry", and the cheap, specific clauses come first.
#[inline]
#[must_use]
pub fn retryable(ctx: &RetryContext, failure: FailureKind) -> RetryDecision {
    if !failure.matches(ctx.retry_on) {
        return RetryDecision::No(RetryVeto::NotInRetryOn);
    }
    if ctx.idempotence == MethodIdempotence::NonIdempotent
        && !ctx.treat_as_idempotent
        && !failure.proves_not_processed()
    {
        return RetryDecision::No(RetryVeto::NonIdempotent);
    }
    if let Some(reason) = ctx.committed {
        return RetryDecision::No(RetryVeto::Committed(reason));
    }
    if ctx.attempts_so_far >= ctx.max_attempts {
        return RetryDecision::No(RetryVeto::AttemptsExhausted);
    }
    let need_ms = ctx.backoff_ms.saturating_add(ctx.min_attempt_estimate_ms);
    if !ctx.deadline.permits(ctx.now, need_ms) {
        return RetryDecision::No(RetryVeto::DeadlineExhausted);
    }
    RetryDecision::Retry
}

/// Per-route retry policy as configured.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RetryPolicyConfig {
    /// Which failure classes to retry. Default [`RetryOn::default`].
    pub retry_on: RetryOn,
    /// Total attempts including the original. Default 3, so two retries.
    pub max_attempts: u32,
    /// The documented, dangerous escape hatch. Default false.
    pub treat_as_idempotent: bool,
    /// Refuse to retry a request that arrived with `x-envoy-attempt-count` above 1,
    /// because someone upstream is already retrying it. Default false.
    ///
    /// `retryable` does NOT read this field: the predicate sees no inbound headers. It
    /// is enforced as the FIRST clause of `AttemptMachine::on_failure` in
    /// `retry-attempt-machine` (#105), which is the layer that holds the inbound
    /// attempt count. It lives here because it is part of the route's retry policy and
    /// the config plane loads it as one struct.
    ///
    /// The inbound attempt count is `x-envoy-attempt-count`, which is in the
    /// `x-envoy-*` family stripped at ingress on any connection the forwarding trust
    /// policy has not classified as trusted-internal. The attempt machine MUST
    /// therefore treat the inbound count as 1 on an untrusted connection rather than
    /// reading a header value. Both directions matter: a client that sets a HIGH count
    /// would disable our retries for its own request (self-harm, but also a way to make
    /// one tenant's traffic behave differently from another's), and a client that sets
    /// a LOW count on a request that really has been retried five times upstream
    /// defeats the only mechanism that bounds cross-layer amplification.
    pub retry_only_first_hop: bool,
    /// Endpoint-selection attempts a retry may make before it is permitted to reuse an
    /// already-tried endpoint. Default 3, matching Envoy's
    /// `host_selection_retry_max_attempts`. Read by `retry-attempt-machine` (#105);
    /// `retryable` does not use it. Validation rejects 0 and any value above 10.
    pub host_selection_retry_max_attempts: u32,
    /// Per-ATTEMPT timeout in milliseconds, or 0 for "none". Default 0.
    ///
    /// `retryable` does NOT read this field. It exists here because the per-try
    /// timeout is part of a route's retry policy (this is where Envoy puts it too) and
    /// because two other layers need a single, named source for it:
    ///
    /// - `deadline-core` (#89) emits `min(per_try_budget, propagate).max(1)` into
    ///   `x-envoy-expected-rq-timeout-ms`, where `per_try_budget` is exactly this value
    ///   when it is nonzero and the propagated remaining budget when it is 0.
    /// - The attempt runner arms the per-attempt timer from it and reports
    ///   [`FailureKind::PerTryTimeout`] when it fires.
    ///
    /// Neither of those two consumers lives in this milestone: the emitter takes the
    /// resolved number as a parameter and the runner is a data-plane assembly issue
    /// that is not yet filed. This field is the definition and the validation, so that
    /// when they arrive there is one spelling and one bound rather than three. It is
    /// NEVER a substitute for the request deadline: a per-try timeout bounds one
    /// attempt and the deadline bounds the whole attempt tree, and an attempt is still
    /// refused by `retryable` clause 5 when the deadline cannot fit it however large
    /// this value is.
    pub per_try_timeout_ms: u32,
}

impl Default for RetryPolicyConfig {
    fn default() -> Self {
        RetryPolicyConfig {
            retry_on: RetryOn::default(),
            max_attempts: 3,
            treat_as_idempotent: false,
            retry_only_first_hop: false,
            host_selection_retry_max_attempts: 3,
            per_try_timeout_ms: 0,
        }
    }
}

impl RetryPolicyConfig {
    /// Validate against invariant 9 of `retryability-conjunction-and-commit-point`
    /// (#101): rejects `max_attempts == 0`, `max_attempts > 10`,
    /// `host_selection_retry_max_attempts == 0`, `host_selection_retry_max_attempts >
    /// 10`, and `per_try_timeout_ms > 600_000`. `per_try_timeout_ms == 0` is ACCEPTED
    /// and means "no per-try timeout".
    ///
    /// # Errors
    /// Returns the first [`ConfigError`] found, naming the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        in_range_u32("max_attempts", self.max_attempts, 1, 10)?;
        in_range_u32(
            "host_selection_retry_max_attempts",
            self.host_selection_retry_max_attempts,
            1,
            10,
        )?;
        in_range_u32("per_try_timeout_ms", self.per_try_timeout_ms, 0, 600_000)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::{Just, ProptestConfig, Strategy, any, proptest};

    /// A POST-shaped context with the default retry-on set, plenty of deadline budget,
    /// and one attempt already made. Individual tests override the fields they care
    /// about with struct-update syntax.
    fn base_ctx() -> RetryContext {
        RetryContext {
            retry_on: RetryOn::default(),
            idempotence: MethodIdempotence::NonIdempotent,
            treat_as_idempotent: false,
            committed: None,
            attempts_so_far: 1,
            max_attempts: 3,
            deadline: Deadline::from_now(Millis(0), 1_000),
            now: Millis(0),
            backoff_ms: 0,
            min_attempt_estimate_ms: 0,
        }
    }

    fn every_bit() -> RetryOn {
        RetryOn::CONNECT_FAILURE
            .union(RetryOn::REFUSED_STREAM)
            .union(RetryOn::RESET_BEFORE_REQUEST)
            .union(RetryOn::HTTP3_POST_CONNECT_FAILURE)
            .union(RetryOn::FIVE_XX)
            .union(RetryOn::GATEWAY_ERROR)
            .union(RetryOn::RESET)
            .union(RetryOn::PER_TRY_TIMEOUT)
            .union(RetryOn::GRPC_UNAVAILABLE)
            .union(RetryOn::GRPC_DEADLINE_EXCEEDED)
            .union(RetryOn::GRPC_RESOURCE_EXHAUSTED)
            .union(RetryOn::LOCAL_OVERLOAD)
    }

    fn failure_kind_strategy() -> impl Strategy<Value = FailureKind> {
        proptest::prop_oneof![
            Just(FailureKind::ConnectFailure),
            Just(FailureKind::TlsHandshakeFailure),
            Just(FailureKind::RefusedStream),
            Just(FailureKind::GoAwayUnprocessed),
            Just(FailureKind::H3RequestRejected),
            Just(FailureKind::ResetBeforeRequest),
            Just(FailureKind::ResetAfterRequest),
            Just(FailureKind::PerTryTimeout),
            any::<u16>().prop_map(FailureKind::UpstreamStatus),
            any::<u16>().prop_map(FailureKind::GrpcStatus),
            Just(FailureKind::LocalOverload),
        ]
    }

    fn commit_reason_strategy() -> impl Strategy<Value = CommitReason> {
        proptest::prop_oneof![
            Just(CommitReason::ResponseBytesForwarded),
            Just(CommitReason::ReplayBufferOverflow),
            Just(CommitReason::InterimResponseSeen),
            Just(CommitReason::BidirectionalUpgrade),
        ]
    }

    #[test]
    fn proves_not_processed_exhaustive() {
        let cases: [(FailureKind, bool); 11] = [
            (FailureKind::ConnectFailure, true),
            (FailureKind::TlsHandshakeFailure, true),
            (FailureKind::RefusedStream, true),
            (FailureKind::GoAwayUnprocessed, true),
            (FailureKind::H3RequestRejected, true),
            (FailureKind::ResetBeforeRequest, true),
            (FailureKind::ResetAfterRequest, false),
            (FailureKind::PerTryTimeout, false),
            (FailureKind::UpstreamStatus(503), false),
            (FailureKind::GrpcStatus(14), false),
            (FailureKind::LocalOverload, false),
        ];
        for (failure, expected) in cases {
            assert_eq!(failure.proves_not_processed(), expected, "{failure:?}");
        }
    }

    #[test]
    fn default_retry_on_bits() {
        assert_eq!(RetryOn::default().0, 0b1111);
    }

    #[test]
    fn union_is_bitwise_or_not_xor() {
        // `union` must be OR, not XOR: every union used elsewhere in this file combines
        // DISJOINT single bits, where OR and XOR agree (1 | 2 == 1 ^ 2 == 3), so this is
        // the only test that would notice `|` mutated to `^`. Unioning a set with a bit
        // it already contains is the case where they diverge: OR is idempotent and
        // leaves the bit set, XOR of a bit with itself clears it back to empty.
        assert_eq!(
            RetryOn::CONNECT_FAILURE.union(RetryOn::CONNECT_FAILURE),
            RetryOn::CONNECT_FAILURE
        );
        let combined = RetryOn::CONNECT_FAILURE.union(RetryOn::REFUSED_STREAM);
        assert_eq!(combined.union(RetryOn::REFUSED_STREAM), combined);
    }

    #[test]
    fn default_policy_values() {
        assert_eq!(
            RetryPolicyConfig::default(),
            RetryPolicyConfig {
                retry_on: RetryOn::default(),
                max_attempts: 3,
                treat_as_idempotent: false,
                retry_only_first_hop: false,
                host_selection_retry_max_attempts: 3,
                per_try_timeout_ms: 0,
            }
        );
    }

    #[test]
    fn parse_token_all_names() {
        let cases = [
            ("connect-failure", RetryOn::CONNECT_FAILURE),
            ("refused-stream", RetryOn::REFUSED_STREAM),
            ("reset-before-request", RetryOn::RESET_BEFORE_REQUEST),
            (
                "http3-post-connect-failure",
                RetryOn::HTTP3_POST_CONNECT_FAILURE,
            ),
            ("5xx", RetryOn::FIVE_XX),
            ("gateway-error", RetryOn::GATEWAY_ERROR),
            ("reset", RetryOn::RESET),
            ("per-try-timeout", RetryOn::PER_TRY_TIMEOUT),
            ("grpc-unavailable", RetryOn::GRPC_UNAVAILABLE),
            ("grpc-deadline-exceeded", RetryOn::GRPC_DEADLINE_EXCEEDED),
            ("grpc-resource-exhausted", RetryOn::GRPC_RESOURCE_EXHAUSTED),
            ("local-overload", RetryOn::LOCAL_OVERLOAD),
        ];
        for (token, expected) in cases {
            assert_eq!(RetryOn::parse_token(token).unwrap(), expected, "{token}");
        }
        let err = RetryOn::parse_token("retriable-4xx").unwrap_err();
        assert!(err.to_string().contains("409"), "{err}");
    }

    #[test]
    fn parse_token_unknown() {
        assert!(RetryOn::parse_token("nope").is_err());
    }

    #[test]
    fn matches_table() {
        let none = RetryOn::none();
        let cases = [
            (FailureKind::ConnectFailure, RetryOn::CONNECT_FAILURE, true),
            (FailureKind::ConnectFailure, none, false),
            (
                FailureKind::TlsHandshakeFailure,
                RetryOn::CONNECT_FAILURE,
                true,
            ),
            (FailureKind::TlsHandshakeFailure, none, false),
            (FailureKind::RefusedStream, RetryOn::REFUSED_STREAM, true),
            (FailureKind::RefusedStream, none, false),
            (
                FailureKind::GoAwayUnprocessed,
                RetryOn::REFUSED_STREAM,
                true,
            ),
            (FailureKind::GoAwayUnprocessed, none, false),
            (
                FailureKind::H3RequestRejected,
                RetryOn::HTTP3_POST_CONNECT_FAILURE,
                true,
            ),
            (FailureKind::H3RequestRejected, none, false),
            (
                FailureKind::ResetBeforeRequest,
                RetryOn::RESET_BEFORE_REQUEST,
                true,
            ),
            (FailureKind::ResetBeforeRequest, none, false),
            (FailureKind::ResetAfterRequest, RetryOn::RESET, true),
            (FailureKind::ResetAfterRequest, none, false),
            (FailureKind::PerTryTimeout, RetryOn::PER_TRY_TIMEOUT, true),
            (FailureKind::PerTryTimeout, none, false),
            (FailureKind::LocalOverload, RetryOn::LOCAL_OVERLOAD, true),
            (FailureKind::LocalOverload, none, false),
            (FailureKind::UpstreamStatus(500), RetryOn::FIVE_XX, true),
            (FailureKind::UpstreamStatus(500), none, false),
            (FailureKind::GrpcStatus(14), RetryOn::GRPC_UNAVAILABLE, true),
            (FailureKind::GrpcStatus(14), none, false),
        ];
        for (failure, bits, expected) in cases {
            assert_eq!(
                failure.matches(bits),
                expected,
                "{failure:?} against {bits:?}"
            );
        }
    }

    #[test]
    fn matches_status_split() {
        let five_xx = RetryOn::FIVE_XX;
        for status in [500u16, 501, 505] {
            assert!(
                FailureKind::UpstreamStatus(status).matches(five_xx),
                "{status}"
            );
        }
        for status in [502u16, 503, 504] {
            assert!(
                !FailureKind::UpstreamStatus(status).matches(five_xx),
                "{status}"
            );
        }
        let gateway = RetryOn::GATEWAY_ERROR;
        for status in [502u16, 503, 504] {
            assert!(
                FailureKind::UpstreamStatus(status).matches(gateway),
                "{status}"
            );
        }
        for status in [500u16, 501, 505] {
            assert!(
                !FailureKind::UpstreamStatus(status).matches(gateway),
                "{status}"
            );
        }
    }

    #[test]
    fn matches_no_4xx() {
        let all = every_bit();
        for status in [400u16, 404, 409, 429, 499] {
            assert!(
                !FailureKind::UpstreamStatus(status).matches(all),
                "{status}"
            );
        }
    }

    #[test]
    fn matches_grpc_codes() {
        assert!(FailureKind::GrpcStatus(14).matches(RetryOn::GRPC_UNAVAILABLE));
        assert!(FailureKind::GrpcStatus(4).matches(RetryOn::GRPC_DEADLINE_EXCEEDED));
        assert!(FailureKind::GrpcStatus(8).matches(RetryOn::GRPC_RESOURCE_EXHAUSTED));
        // Checked against RetryOn::none(), an independently defined empty set, rather
        // than only against the very constant each arm returns: a bit constant that
        // collapsed to 0 (for example a `<<` mutated to `>>`) would otherwise pass the
        // three asserts above unnoticed, because both sides of `contains` would then be
        // the same mutated zero. `none()` has no such blind spot.
        for code in [4u16, 8, 14] {
            assert!(
                !FailureKind::GrpcStatus(code).matches(RetryOn::none()),
                "{code}"
            );
        }
        let all = RetryOn::GRPC_UNAVAILABLE
            .union(RetryOn::GRPC_DEADLINE_EXCEEDED)
            .union(RetryOn::GRPC_RESOURCE_EXHAUSTED);
        for code in [0u16, 5, 12, 16] {
            assert!(!FailureKind::GrpcStatus(code).matches(all), "{code}");
        }
    }

    #[test]
    fn method_idempotence_table() {
        let idempotent: [&[u8]; 6] = [b"GET", b"HEAD", b"OPTIONS", b"TRACE", b"PUT", b"DELETE"];
        for m in idempotent {
            assert_eq!(
                method_idempotence(m),
                MethodIdempotence::Idempotent,
                "{m:?}"
            );
        }
        let two_hundred = vec![b'X'; 200];
        let non_idempotent: [&[u8]; 9] = [
            b"POST",
            b"PATCH",
            b"CONNECT",
            b"get",
            b"Get",
            b"PUT ",
            b"",
            b"\xff\xfe",
            two_hundred.as_slice(),
        ];
        for m in non_idempotent {
            assert_eq!(
                method_idempotence(m),
                MethodIdempotence::NonIdempotent,
                "{m:?}"
            );
        }
    }

    #[test]
    fn post_connect_failure_retries() {
        let ctx = base_ctx();
        assert_eq!(
            retryable(&ctx, FailureKind::ConnectFailure),
            RetryDecision::Retry
        );
    }

    #[test]
    fn post_503_refused() {
        let ctx = RetryContext {
            retry_on: RetryOn::default().union(RetryOn::GATEWAY_ERROR),
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, FailureKind::UpstreamStatus(503)),
            RetryDecision::No(RetryVeto::NonIdempotent)
        );
    }

    #[test]
    fn post_503_with_escape_hatch_retries() {
        let ctx = RetryContext {
            retry_on: RetryOn::default().union(RetryOn::GATEWAY_ERROR),
            treat_as_idempotent: true,
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, FailureKind::UpstreamStatus(503)),
            RetryDecision::Retry
        );
    }

    #[test]
    fn get_503_default_set_refused() {
        let ctx = RetryContext {
            idempotence: MethodIdempotence::Idempotent,
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, FailureKind::UpstreamStatus(503)),
            RetryDecision::No(RetryVeto::NotInRetryOn)
        );
    }

    #[test]
    fn post_timeout_refused() {
        let ctx = RetryContext {
            retry_on: RetryOn::default().union(RetryOn::PER_TRY_TIMEOUT),
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, FailureKind::PerTryTimeout),
            RetryDecision::No(RetryVeto::NonIdempotent)
        );
    }

    /// A tiny fixed-capacity sink standing in for a real socket's write syscall, used
    /// only to prove the reset-before/after-request classification against an ACTUAL
    /// partial write rather than a hand-set flag. A real write syscall on a congested
    /// socket can accept fewer bytes than requested; this does the same thing for real,
    /// by genuinely refusing to copy more than `capacity` bytes.
    struct BoundedSink {
        capacity: usize,
        written: Vec<u8>,
    }

    impl BoundedSink {
        fn new(capacity: usize) -> Self {
            BoundedSink {
                capacity,
                written: Vec::new(),
            }
        }

        /// Accepts as many bytes of `buf` as fit in the remaining capacity and returns
        /// the number ACTUALLY accepted, never the number requested.
        fn write_some(&mut self, buf: &[u8]) -> usize {
            let remaining = self.capacity.saturating_sub(self.written.len());
            let n = buf.len().min(remaining);
            self.written.extend_from_slice(&buf[..n]);
            n
        }
    }

    /// The classification a real transport would report, derived only from bytes
    /// ACTUALLY accepted by the write, mirroring this module's own rule: zero bytes
    /// accepted is `ResetBeforeRequest`, and any uncertainty, including a partial write
    /// of any nonzero length, resolves to `ResetAfterRequest`.
    fn classify_from_accepted_bytes(accepted: usize) -> FailureKind {
        if accepted == 0 {
            FailureKind::ResetBeforeRequest
        } else {
            FailureKind::ResetAfterRequest
        }
    }

    #[test]
    fn partial_write_resolves_to_reset_after_request_not_before() {
        // The commit point is the whole property: once any byte of the request body has
        // reached the transport, proof-of-non-processing is gone. This proves it with a
        // GENUINE partial write, not a boolean set by hand: a 10 byte body written into
        // a sink with capacity for only 3 bytes, exactly the way a real, congested
        // socket write can accept fewer bytes than requested.
        let body = b"0123456789";
        let mut sink = BoundedSink::new(3);
        let accepted = sink.write_some(body);
        assert_eq!(
            accepted, 3,
            "the sink must have genuinely accepted a partial write"
        );
        assert!(
            accepted < body.len(),
            "must be a PARTIAL write, not the whole body"
        );

        let failure = classify_from_accepted_bytes(accepted);
        assert_eq!(failure, FailureKind::ResetAfterRequest);
        assert!(!failure.proves_not_processed());

        // End to end: retryable must refuse a non-idempotent method after this ACTUAL
        // partial write. If the classification feeding the conjunction could ever be
        // observed as "unprocessed" once real bytes reached the transport, this would
        // wrongly return Retry and a POST would be replayed against an origin that may
        // already have seen part of it.
        let ctx = RetryContext {
            retry_on: every_bit(),
            idempotence: MethodIdempotence::NonIdempotent,
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, failure),
            RetryDecision::No(RetryVeto::NonIdempotent)
        );

        // Contrast, using the SAME sink type and the SAME derivation function: zero
        // bytes accepted (a sink with no capacity at all) DOES prove non-processing and
        // DOES permit a retry. This shows the classification genuinely tracks the
        // number of bytes accepted rather than always refusing regardless of input,
        // which would make the test above pass for the wrong reason.
        let mut empty_sink = BoundedSink::new(0);
        let accepted_none = empty_sink.write_some(body);
        assert_eq!(accepted_none, 0);
        let failure_none = classify_from_accepted_bytes(accepted_none);
        assert_eq!(failure_none, FailureKind::ResetBeforeRequest);
        assert_eq!(retryable(&ctx, failure_none), RetryDecision::Retry);
    }

    #[test]
    fn committed_outranks_idempotency() {
        let ctx = RetryContext {
            committed: Some(CommitReason::ResponseBytesForwarded),
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, FailureKind::ConnectFailure),
            RetryDecision::No(RetryVeto::Committed(CommitReason::ResponseBytesForwarded))
        );
    }

    #[test]
    fn commit_reasons_all_veto() {
        for reason in [
            CommitReason::ResponseBytesForwarded,
            CommitReason::ReplayBufferOverflow,
            CommitReason::InterimResponseSeen,
            CommitReason::BidirectionalUpgrade,
        ] {
            let ctx = RetryContext {
                committed: Some(reason),
                ..base_ctx()
            };
            assert_eq!(
                retryable(&ctx, FailureKind::ConnectFailure),
                RetryDecision::No(RetryVeto::Committed(reason))
            );
        }
    }

    #[test]
    fn attempts_boundary() {
        let ctx = RetryContext {
            max_attempts: 3,
            attempts_so_far: 2,
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, FailureKind::ConnectFailure),
            RetryDecision::Retry
        );

        let ctx = RetryContext {
            attempts_so_far: 3,
            ..ctx
        };
        assert_eq!(
            retryable(&ctx, FailureKind::ConnectFailure),
            RetryDecision::No(RetryVeto::AttemptsExhausted)
        );
    }

    #[test]
    fn max_attempts_one_never_retries() {
        let ctx = RetryContext {
            retry_on: every_bit(),
            idempotence: MethodIdempotence::Idempotent,
            max_attempts: 1,
            attempts_so_far: 1,
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, FailureKind::ConnectFailure),
            RetryDecision::No(RetryVeto::AttemptsExhausted)
        );
    }

    #[test]
    fn deadline_boundary() {
        let ctx = RetryContext {
            deadline: Deadline::from_now(Millis(0), 100),
            now: Millis(0),
            backoff_ms: 60,
            min_attempt_estimate_ms: 40,
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, FailureKind::ConnectFailure),
            RetryDecision::Retry
        );

        let ctx = RetryContext {
            backoff_ms: 61,
            ..ctx
        };
        assert_eq!(
            retryable(&ctx, FailureKind::ConnectFailure),
            RetryDecision::No(RetryVeto::DeadlineExhausted)
        );
    }

    #[test]
    fn deadline_saturating() {
        let ctx = RetryContext {
            deadline: Deadline::from_now(Millis(0), 100),
            now: Millis(0),
            backoff_ms: u32::MAX,
            min_attempt_estimate_ms: 10,
            ..base_ctx()
        };
        assert_eq!(
            retryable(&ctx, FailureKind::ConnectFailure),
            RetryDecision::No(RetryVeto::DeadlineExhausted)
        );
    }

    #[test]
    fn retryable_is_pure() {
        let ctx = base_ctx();
        let before = ctx;
        let mut last = None;
        for _ in 0..1_000 {
            let decision = retryable(&ctx, FailureKind::ConnectFailure);
            if let Some(prev) = last {
                assert_eq!(decision, prev);
            }
            last = Some(decision);
        }
        assert_eq!(format!("{ctx:?}"), format!("{before:?}"));
    }

    #[test]
    fn validate_rejects_table() {
        let base = RetryPolicyConfig::default();

        let err = RetryPolicyConfig {
            max_attempts: 0,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "max_attempts");

        let err = RetryPolicyConfig {
            max_attempts: 11,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "max_attempts");

        let err = RetryPolicyConfig {
            host_selection_retry_max_attempts: 0,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "host_selection_retry_max_attempts");

        let err = RetryPolicyConfig {
            host_selection_retry_max_attempts: 11,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "host_selection_retry_max_attempts");

        let err = RetryPolicyConfig {
            per_try_timeout_ms: 600_001,
            ..base
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.field, "per_try_timeout_ms");

        assert!(
            RetryPolicyConfig {
                per_try_timeout_ms: 0,
                ..base
            }
            .validate()
            .is_ok()
        );
        assert!(
            RetryPolicyConfig {
                per_try_timeout_ms: 600_000,
                ..base
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn prop_never_retries_non_idempotent_without_proof() {
        proptest!(
            ProptestConfig::default(),
            |(
                bits: u16,
                idempotent: bool,
                treat_as_idempotent: bool,
                attempts_so_far: u32,
                max_attempts in 1u32..=10,
                now: u32,
                budget in 0u32..=100_000,
                backoff_ms: u32,
                min_attempt_estimate_ms: u32,
                committed in proptest::option::of(commit_reason_strategy()),
                failure in failure_kind_strategy(),
            )| {
                let ctx = RetryContext {
                    retry_on: RetryOn(bits),
                    idempotence: if idempotent {
                        MethodIdempotence::Idempotent
                    } else {
                        MethodIdempotence::NonIdempotent
                    },
                    treat_as_idempotent,
                    committed,
                    attempts_so_far,
                    max_attempts,
                    deadline: Deadline::from_now(Millis(now), budget),
                    now: Millis(now),
                    backoff_ms,
                    min_attempt_estimate_ms,
                };
                let decision = retryable(&ctx, failure);
                if decision == RetryDecision::Retry {
                    assert!(
                        ctx.idempotence == MethodIdempotence::Idempotent
                            || ctx.treat_as_idempotent
                            || failure.proves_not_processed()
                    );
                }
            }
        );
    }

    #[test]
    fn prop_never_retries_after_commit() {
        proptest!(
            ProptestConfig::default(),
            |(
                bits: u16,
                idempotent: bool,
                treat_as_idempotent: bool,
                attempts_so_far: u32,
                max_attempts in 1u32..=10,
                now: u32,
                budget in 0u32..=100_000,
                backoff_ms: u32,
                min_attempt_estimate_ms: u32,
                committed in proptest::option::of(commit_reason_strategy()),
                failure in failure_kind_strategy(),
            )| {
                let ctx = RetryContext {
                    retry_on: RetryOn(bits),
                    idempotence: if idempotent {
                        MethodIdempotence::Idempotent
                    } else {
                        MethodIdempotence::NonIdempotent
                    },
                    treat_as_idempotent,
                    committed,
                    attempts_so_far,
                    max_attempts,
                    deadline: Deadline::from_now(Millis(now), budget),
                    now: Millis(now),
                    backoff_ms,
                    min_attempt_estimate_ms,
                };
                let decision = retryable(&ctx, failure);
                if ctx.committed.is_some() {
                    assert_ne!(decision, RetryDecision::Retry);
                }
            }
        );
    }

    #[test]
    fn prop_veto_order_is_stable() {
        proptest!(
            ProptestConfig::default(),
            |(
                bits: u16,
                idempotent: bool,
                treat_as_idempotent: bool,
                attempts_so_far: u32,
                max_attempts in 1u32..=10,
                now: u32,
                budget in 0u32..=100_000,
                backoff_ms: u32,
                min_attempt_estimate_ms: u32,
                committed in proptest::option::of(commit_reason_strategy()),
                failure in failure_kind_strategy(),
            )| {
                let ctx = RetryContext {
                    retry_on: RetryOn(bits),
                    idempotence: if idempotent {
                        MethodIdempotence::Idempotent
                    } else {
                        MethodIdempotence::NonIdempotent
                    },
                    treat_as_idempotent,
                    committed,
                    attempts_so_far,
                    max_attempts,
                    deadline: Deadline::from_now(Millis(now), budget),
                    now: Millis(now),
                    backoff_ms,
                    min_attempt_estimate_ms,
                };
                let decision = retryable(&ctx, failure);
                let idempotent_or_proven = ctx.idempotence == MethodIdempotence::Idempotent
                    || ctx.treat_as_idempotent
                    || failure.proves_not_processed();
                let need_ms = ctx.backoff_ms.saturating_add(ctx.min_attempt_estimate_ms);

                if let RetryDecision::No(veto) = decision {
                    match veto {
                        RetryVeto::NotInRetryOn => {}
                        RetryVeto::NonIdempotent => {
                            assert!(failure.matches(ctx.retry_on));
                        }
                        RetryVeto::Committed(_) => {
                            assert!(failure.matches(ctx.retry_on));
                            assert!(idempotent_or_proven);
                        }
                        RetryVeto::AttemptsExhausted => {
                            assert!(failure.matches(ctx.retry_on));
                            assert!(idempotent_or_proven);
                            assert!(ctx.committed.is_none());
                        }
                        RetryVeto::DeadlineExhausted => {
                            assert!(failure.matches(ctx.retry_on));
                            assert!(idempotent_or_proven);
                            assert!(ctx.committed.is_none());
                            assert!(ctx.attempts_so_far < ctx.max_attempts);
                        }
                        RetryVeto::BudgetExhausted => {
                            panic!("retryable never produces BudgetExhausted; {ctx:?} / {failure:?} / {need_ms}");
                        }
                    }
                }
            }
        );
    }
}
