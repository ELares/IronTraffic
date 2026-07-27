// SPDX-License-Identifier: MIT OR Apache-2.0
//! Retry eligibility, backoff, and server pushback parsing.
//!
//! [`predicate::retryable`] is the whole decision: the retryability conjunction with
//! proof-of-non-processing and the commit point. [`backoff::FullJitterBackoff`]
//! computes the sleep before the next attempt. [`pushback::resolve_backoff`] parses
//! server pushback and decides whether to sleep, and for how long. See each module's
//! documentation for the full design. This module performs no I/O and reads no clock.

pub mod backoff;
pub mod predicate;
pub mod pushback;

pub use backoff::{BackoffConfig, FullJitterBackoff, GrpcBackoffParams, grpc_backoff_ms};
pub use predicate::{
    CommitReason, FailureKind, MethodIdempotence, RetryContext, RetryDecision, RetryOn,
    RetryPolicyConfig, RetryVeto, method_idempotence, retryable,
};
pub use pushback::{
    BackoffDecision, BackoffInputs, HDR_GRPC_RETRY_PUSHBACK_MS, HDR_RETRY_AFTER, NoRetryReason,
    PushbackResult, days_from_civil, parse_grpc_pushback, parse_http_date_ms, parse_retry_after,
    resolve_backoff,
};
