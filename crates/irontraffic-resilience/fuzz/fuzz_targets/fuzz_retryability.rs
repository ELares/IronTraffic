#![no_main]
//! Fuzz target for `retry::predicate::retryable`, the retryability conjunction.
//!
//! This is the highest-value fuzz target in the project: `retryable` decides whether a
//! failed attempt is safe to retry, and a false `Retry` on a non-idempotent, unproven
//! failure double-applies a mutation (a double charge, a double order). The target
//! exists to make a regression in that conjunction a fuzz CRASH rather than a silent
//! behaviour change.
//!
//! Input domain: `(RetryContextSeed, FailureKindSeed)` derives `Arbitrary` and maps onto
//! the real `RetryContext` and `FailureKind`, including arbitrary `u16` HTTP statuses and
//! gRPC codes, arbitrary `u32` attempt counts, arbitrary `u32` millisecond values for the
//! deadline budget/backoff/estimate, and an arbitrary `retry_on` set.
//!
//! `RetryOn`'s inner bit field is private by design (see its own doc comment): the only
//! bit patterns any caller, including this fuzz target, can ever build are unions of its
//! twelve named associated constants (bits 0 through 11). `RetryOnSeed`'s twelve
//! independent bools already cover that type's ENTIRE representable domain, 4096
//! distinct values, through the public API alone; bits 12 through 15 of the underlying
//! `u16` are unreachable from outside the crate and so can never affect `retryable` for
//! any real caller. That is the property this target is checking, not a gap in it.
//!
//! Contract: `retryable` must not panic, must not hang, and must not allocate. The
//! target additionally ASSERTS the two properties that matter most:
//!
//! - never `Retry` for a non-idempotent method unless `treat_as_idempotent` is set or
//!   the failure proves non-processing (the single most important property in the
//!   milestone);
//! - never `Retry` once the context is committed.
//!
//! so a regression in either one is a fuzz crash rather than a silent behaviour change.

use arbitrary::Arbitrary;
use irontraffic_resilience::clock::Millis;
use irontraffic_resilience::deadline::Deadline;
use irontraffic_resilience::retry::{
    CommitReason, FailureKind, MethodIdempotence, RetryContext, RetryDecision, RetryOn, retryable,
};
use libfuzzer_sys::fuzz_target;

/// Seed for [`CommitReason`].
#[derive(Debug, Arbitrary)]
enum CommitReasonSeed {
    ResponseBytesForwarded,
    ReplayBufferOverflow,
    InterimResponseSeen,
    BidirectionalUpgrade,
}

impl From<CommitReasonSeed> for CommitReason {
    fn from(seed: CommitReasonSeed) -> CommitReason {
        match seed {
            CommitReasonSeed::ResponseBytesForwarded => CommitReason::ResponseBytesForwarded,
            CommitReasonSeed::ReplayBufferOverflow => CommitReason::ReplayBufferOverflow,
            CommitReasonSeed::InterimResponseSeen => CommitReason::InterimResponseSeen,
            CommitReasonSeed::BidirectionalUpgrade => CommitReason::BidirectionalUpgrade,
        }
    }
}

/// Seed for [`FailureKind`], including arbitrary `u16` HTTP statuses and gRPC codes.
#[derive(Debug, Arbitrary)]
enum FailureKindSeed {
    ConnectFailure,
    TlsHandshakeFailure,
    RefusedStream,
    GoAwayUnprocessed,
    H3RequestRejected,
    ResetBeforeRequest,
    ResetAfterRequest,
    PerTryTimeout,
    UpstreamStatus(u16),
    GrpcStatus(u16),
    LocalOverload,
}

impl From<FailureKindSeed> for FailureKind {
    fn from(seed: FailureKindSeed) -> FailureKind {
        match seed {
            FailureKindSeed::ConnectFailure => FailureKind::ConnectFailure,
            FailureKindSeed::TlsHandshakeFailure => FailureKind::TlsHandshakeFailure,
            FailureKindSeed::RefusedStream => FailureKind::RefusedStream,
            FailureKindSeed::GoAwayUnprocessed => FailureKind::GoAwayUnprocessed,
            FailureKindSeed::H3RequestRejected => FailureKind::H3RequestRejected,
            FailureKindSeed::ResetBeforeRequest => FailureKind::ResetBeforeRequest,
            FailureKindSeed::ResetAfterRequest => FailureKind::ResetAfterRequest,
            FailureKindSeed::PerTryTimeout => FailureKind::PerTryTimeout,
            FailureKindSeed::UpstreamStatus(status) => FailureKind::UpstreamStatus(status),
            FailureKindSeed::GrpcStatus(code) => FailureKind::GrpcStatus(code),
            FailureKindSeed::LocalOverload => FailureKind::LocalOverload,
        }
    }
}

/// Seed for [`RetryOn`]. See this module's own doc comment for why twelve independent
/// bools already cover the type's entire representable domain.
#[derive(Debug, Arbitrary)]
struct RetryOnSeed {
    connect_failure: bool,
    refused_stream: bool,
    reset_before_request: bool,
    http3_post_connect_failure: bool,
    five_xx: bool,
    gateway_error: bool,
    reset: bool,
    per_try_timeout: bool,
    grpc_unavailable: bool,
    grpc_deadline_exceeded: bool,
    grpc_resource_exhausted: bool,
    local_overload: bool,
}

impl From<RetryOnSeed> for RetryOn {
    fn from(seed: RetryOnSeed) -> RetryOn {
        let mut bits = RetryOn::none();
        if seed.connect_failure {
            bits = bits.union(RetryOn::CONNECT_FAILURE);
        }
        if seed.refused_stream {
            bits = bits.union(RetryOn::REFUSED_STREAM);
        }
        if seed.reset_before_request {
            bits = bits.union(RetryOn::RESET_BEFORE_REQUEST);
        }
        if seed.http3_post_connect_failure {
            bits = bits.union(RetryOn::HTTP3_POST_CONNECT_FAILURE);
        }
        if seed.five_xx {
            bits = bits.union(RetryOn::FIVE_XX);
        }
        if seed.gateway_error {
            bits = bits.union(RetryOn::GATEWAY_ERROR);
        }
        if seed.reset {
            bits = bits.union(RetryOn::RESET);
        }
        if seed.per_try_timeout {
            bits = bits.union(RetryOn::PER_TRY_TIMEOUT);
        }
        if seed.grpc_unavailable {
            bits = bits.union(RetryOn::GRPC_UNAVAILABLE);
        }
        if seed.grpc_deadline_exceeded {
            bits = bits.union(RetryOn::GRPC_DEADLINE_EXCEEDED);
        }
        if seed.grpc_resource_exhausted {
            bits = bits.union(RetryOn::GRPC_RESOURCE_EXHAUSTED);
        }
        if seed.local_overload {
            bits = bits.union(RetryOn::LOCAL_OVERLOAD);
        }
        bits
    }
}

/// Seed for [`RetryContext`].
#[derive(Debug, Arbitrary)]
struct RetryContextSeed {
    retry_on: RetryOnSeed,
    idempotent: bool,
    treat_as_idempotent: bool,
    committed: Option<CommitReasonSeed>,
    attempts_so_far: u32,
    max_attempts: u32,
    deadline_budget_ms: u32,
    now: u32,
    backoff_ms: u32,
    min_attempt_estimate_ms: u32,
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|input: (RetryContextSeed, FailureKindSeed)| {
    let (ctx_seed, failure_seed) = input;
    let now = Millis(ctx_seed.now);
    let ctx = RetryContext {
        retry_on: ctx_seed.retry_on.into(),
        idempotence: if ctx_seed.idempotent {
            MethodIdempotence::Idempotent
        } else {
            MethodIdempotence::NonIdempotent
        },
        treat_as_idempotent: ctx_seed.treat_as_idempotent,
        committed: ctx_seed.committed.map(CommitReason::from),
        attempts_so_far: ctx_seed.attempts_so_far,
        max_attempts: ctx_seed.max_attempts,
        deadline: Deadline::from_now(now, ctx_seed.deadline_budget_ms),
        now,
        backoff_ms: ctx_seed.backoff_ms,
        min_attempt_estimate_ms: ctx_seed.min_attempt_estimate_ms,
    };
    let failure: FailureKind = failure_seed.into();

    let decision = retryable(&ctx, failure);

    // Property 24: never Retry for a non-idempotent method unless treat_as_idempotent
    // is set or the failure proves non-processing.
    if decision == RetryDecision::Retry {
        assert!(
            ctx.idempotence == MethodIdempotence::Idempotent
                || ctx.treat_as_idempotent
                || failure.proves_not_processed()
        );
    }

    // Property 25: never Retry once the context is committed.
    if ctx.committed.is_some() {
        assert_ne!(decision, RetryDecision::Retry);
    }
});
