// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`DenyReason`], the closed set of reasons a request may be denied.

use core::mem::size_of;

const _: () = assert!(size_of::<DenyReason>() == 1);

/// Why a request was denied. A closed set with stable dense indices, because every
/// metric, log field, and problem-type URI in this subsystem is derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DenyReason {
    /// A rate policy denied: the client sent faster than its configured rate.
    RateExceeded = 0,
    /// The request's cost exceeds the policy's burst, so it can never conform.
    /// A response for this reason MUST NOT carry `Retry-After`.
    CostExceedsBurst = 1,
    /// No table entry was available and the overflow limiter also denied.
    TableFull = 2,
    /// A per-key in-flight concurrency limit denied.
    ConcurrencyExceeded = 3,
    /// A long-window quota is spent for the current period.
    QuotaExhausted = 4,
    /// A distributed policy holds no share and `on_unavailable` is `deny`.
    LimiterUnavailable = 5,
    /// This key exhausted its deny budget, so we stop generating responses for it.
    DenyBudgetExhausted = 6,
}

impl DenyReason {
    /// Number of variants. Fixed at 7.
    pub const COUNT: usize = 7;

    /// Dense index, for metric label slots.
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Stable `snake_case` name. Never change an existing string: dashboards key on it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateExceeded => "rate_exceeded",
            Self::CostExceedsBurst => "cost_exceeds_burst",
            Self::TableFull => "table_full",
            Self::ConcurrencyExceeded => "concurrency_exceeded",
            Self::QuotaExhausted => "quota_exhausted",
            Self::LimiterUnavailable => "limiter_unavailable",
            Self::DenyBudgetExhausted => "deny_budget_exhausted",
        }
    }

    /// True when the client caused the denial.
    ///
    /// This is the single fact the status-code mapping derives from: 429 means "you
    /// sent too much" and 503 means "I cannot serve right now". The mapping is not
    /// one-to-one; [`DenyReason::TableFull`] is our fault and is still answered with
    /// 429, and the issue that owns status codes documents why.
    #[must_use]
    pub const fn is_client_fault(self) -> bool {
        match self {
            Self::TableFull | Self::LimiterUnavailable => false,
            Self::RateExceeded
            | Self::CostExceedsBurst
            | Self::ConcurrencyExceeded
            | Self::QuotaExhausted
            | Self::DenyBudgetExhausted => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn deny_reason_indices_are_dense() {
        let ordered = [
            DenyReason::RateExceeded,
            DenyReason::CostExceedsBurst,
            DenyReason::TableFull,
            DenyReason::ConcurrencyExceeded,
            DenyReason::QuotaExhausted,
            DenyReason::LimiterUnavailable,
            DenyReason::DenyBudgetExhausted,
        ];
        for (position, reason) in ordered.iter().enumerate() {
            assert_eq!(reason.index(), position);
        }
        let max_index = ordered.iter().map(|r| r.index()).max().unwrap();
        assert_eq!(max_index, DenyReason::COUNT - 1);
    }

    #[test]
    fn deny_reason_strings_are_exact() {
        assert_eq!(DenyReason::RateExceeded.as_str(), "rate_exceeded");
        assert_eq!(DenyReason::CostExceedsBurst.as_str(), "cost_exceeds_burst");
        assert_eq!(DenyReason::TableFull.as_str(), "table_full");
        assert_eq!(
            DenyReason::ConcurrencyExceeded.as_str(),
            "concurrency_exceeded"
        );
        assert_eq!(DenyReason::QuotaExhausted.as_str(), "quota_exhausted");
        assert_eq!(
            DenyReason::LimiterUnavailable.as_str(),
            "limiter_unavailable"
        );
        assert_eq!(
            DenyReason::DenyBudgetExhausted.as_str(),
            "deny_budget_exhausted"
        );
    }

    #[test]
    fn deny_reason_strings_are_unique() {
        let all = [
            DenyReason::RateExceeded,
            DenyReason::CostExceedsBurst,
            DenyReason::TableFull,
            DenyReason::ConcurrencyExceeded,
            DenyReason::QuotaExhausted,
            DenyReason::LimiterUnavailable,
            DenyReason::DenyBudgetExhausted,
        ];
        let set: BTreeSet<&'static str> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(set.len(), 7);
    }

    #[test]
    fn deny_reason_client_fault_partition() {
        assert!(!DenyReason::TableFull.is_client_fault());
        assert!(!DenyReason::LimiterUnavailable.is_client_fault());
        assert!(DenyReason::RateExceeded.is_client_fault());
        assert!(DenyReason::CostExceedsBurst.is_client_fault());
        assert!(DenyReason::ConcurrencyExceeded.is_client_fault());
        assert!(DenyReason::QuotaExhausted.is_client_fault());
        assert!(DenyReason::DenyBudgetExhausted.is_client_fault());
    }
}
