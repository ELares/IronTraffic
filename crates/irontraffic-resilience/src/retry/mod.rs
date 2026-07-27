// SPDX-License-Identifier: MIT OR Apache-2.0
//! Retry eligibility.
//!
//! [`predicate::retryable`] is the whole decision: the retryability conjunction with
//! proof-of-non-processing and the commit point. See [`predicate`]'s module
//! documentation for the full design. This module performs no I/O and reads no clock.

pub mod predicate;

pub use predicate::{
    CommitReason, FailureKind, MethodIdempotence, RetryContext, RetryDecision, RetryOn,
    RetryPolicyConfig, RetryVeto, method_idempotence, retryable,
};
