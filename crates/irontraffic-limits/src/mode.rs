// SPDX-License-Identifier: MIT OR Apache-2.0

//! The seven configuration mode enums: [`LimitMode`], [`OnExceed`],
//! [`OnUnavailable`], [`ExposeTo`], [`HeaderFamily`], [`Tier`], and
//! [`QuotaStatus`].

use crate::config::{ConfigError, at_least, at_most};

/// Whether a policy enforces or only observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LimitMode {
    /// Deny requests that exceed the policy.
    #[default]
    Enforce,
    /// Update state, emit metrics and logs, and let the request proceed.
    Shadow,
}

/// What to do with a request a policy would deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnExceed {
    /// Answer immediately. The default: queueing excess requests converts a rate
    /// problem into an unbounded-memory problem.
    #[default]
    Reject,
    /// Delay up to `max_wait_nanos`, then reject.
    ///
    /// Requires a bounded parked-request queue, which no issue in this milestone
    /// builds. Until one does, a consumer that reads this variant MUST behave as if
    /// it read [`OnExceed::Reject`]: a parked request holds a connection and its
    /// buffers, so an unbounded or unimplemented park is a memory denial of service.
    Delay {
        /// Hard ceiling on the delay, in nanoseconds. Range checked by
        /// [`OnExceed::validate`] against [`OnExceed::MIN_WAIT_NANOS`] and
        /// [`OnExceed::MAX_WAIT_NANOS`].
        max_wait_nanos: u64,
    },
}

impl OnExceed {
    /// Smallest legal delay, 1 ms. Below this the park costs more than it saves.
    pub const MIN_WAIT_NANOS: u64 = 1_000_000;

    /// Largest legal delay, 30 s. A constant and not a knob: a larger value only
    /// buys a way to pin connections until memory runs out.
    pub const MAX_WAIT_NANOS: u64 = 30_000_000_000;

    /// Range checks the delay ceiling.
    ///
    /// # Errors
    /// [`ConfigError::TooSmall`] or [`ConfigError::TooLarge`] naming
    /// `on_exceed.max_wait_nanos`. Always `Ok` for [`OnExceed::Reject`].
    pub const fn validate(self) -> Result<(), ConfigError> {
        match self {
            Self::Reject => Ok(()),
            Self::Delay { max_wait_nanos } => {
                if let Err(e) = at_least(
                    "on_exceed.max_wait_nanos",
                    max_wait_nanos,
                    Self::MIN_WAIT_NANOS,
                ) {
                    return Err(e);
                }
                at_most(
                    "on_exceed.max_wait_nanos",
                    max_wait_nanos,
                    Self::MAX_WAIT_NANOS,
                )
            }
        }
    }
}

/// What a node enforces when it cannot reach the share allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnUnavailable {
    /// Enforce `rate / last_known_node_count`. Never overshoots; may under-admit by
    /// up to a factor of the node count under perfect skew. The default because it is
    /// the only variant that cannot be catastrophically wrong in either direction.
    #[default]
    FairShare,
    /// Keep enforcing the last held share.
    LastShare,
    /// Enforce nothing. Correct for a paid API that must not deny during a partition.
    Allow,
    /// Deny everything. Correct for an abuse shield that must not let a flood through.
    Deny,
    /// Enforce the full configured rate locally, so up to node-count times the rate
    /// cluster-wide. Correct only for advisory limits.
    LocalFull,
}

/// To whom `RateLimit` response headers are disclosed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExposeTo {
    /// Only to requests that carried an authenticated identity. The default, because
    /// capacity information lets an unauthenticated party size an attack.
    #[default]
    Authenticated,
    /// To every request.
    Always,
    /// To no request.
    Never,
}

/// Which `RateLimit` header syntax to emit. Never two at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeaderFamily {
    /// `RateLimit` and `RateLimit-Policy` structured fields.
    #[default]
    Draft11,
    /// `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`.
    Draft03Legacy,
    /// `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
    XPrefixed,
    /// Emit nothing.
    None,
}

/// How a key's rate is enforced across a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tier {
    /// Local enforcement at the full configured rate, zero coordination.
    #[default]
    Tier0Full,
    /// Local enforcement at `rate / node_count`, zero coordination.
    FairShare,
    /// A lease from the allocator, so the cluster arrival curve equals one process's.
    Leased,
}

/// Status code used when a quota is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuotaStatus {
    /// 429.
    #[default]
    TooManyRequests,
    /// 402, for a plan whose remedy is payment.
    PaymentRequired,
    /// 403, for a plan whose remedy is a different subscription.
    Forbidden,
}

impl QuotaStatus {
    /// The numeric status.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::TooManyRequests => 429,
            Self::PaymentRequired => 402,
            Self::Forbidden => 403,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_exceed_default_is_reject() {
        assert_eq!(OnExceed::default(), OnExceed::Reject);
    }

    #[test]
    fn on_exceed_delay_bounds_are_enforced() {
        assert_eq!(
            OnExceed::Delay { max_wait_nanos: 0 }.validate(),
            Err(ConfigError::TooSmall {
                field: "on_exceed.max_wait_nanos",
                min: 1_000_000,
                value: 0
            })
        );
        assert_eq!(
            OnExceed::Delay {
                max_wait_nanos: u64::MAX
            }
            .validate(),
            Err(ConfigError::TooLarge {
                field: "on_exceed.max_wait_nanos",
                max: 30_000_000_000,
                value: u64::MAX
            })
        );
        assert_eq!(
            OnExceed::Delay {
                max_wait_nanos: 1_000_000
            }
            .validate(),
            Ok(())
        );
        assert_eq!(
            OnExceed::Delay {
                max_wait_nanos: 30_000_000_000
            }
            .validate(),
            Ok(())
        );
    }

    #[test]
    fn on_exceed_reject_always_validates() {
        assert_eq!(OnExceed::Reject.validate(), Ok(()));
    }
}
