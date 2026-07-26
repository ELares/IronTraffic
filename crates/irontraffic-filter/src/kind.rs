// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a filter is for (`FilterKind`), and what happens to the stream when
//! one of that kind fails (`FailureMode`).
//!
//! A single global failure-mode default is wrong in both directions:
//! fail-open on an authorization filter is a security hole, and fail-closed
//! on a logging filter is an outage. Each `FilterKind` states its own default.

/// The category of work a filter performs.
///
/// Configuration and metrics key on this to pick a default failure mode and a
/// default fail-closed status, and an operator dashboard groups filters by it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum FilterKind {
    /// Decides whether the request may proceed at all.
    Authorization = 0,
    /// Enforces a rate, quota or concurrency limit.
    Limit = 1,
    /// Mutates headers, query, body or the routing decision.
    Transformation = 2,
    /// Reads only: logs, metrics, traces, sampling decisions.
    Observability = 3,
    /// Produces the response itself: mock, redirect, static response.
    Terminal = 4,
}

impl FilterKind {
    /// Number of kinds. Fixed at 5.
    pub const COUNT: usize = 5;

    /// The failure mode used when configuration does not state one.
    ///
    /// `Authorization`, `Limit` and `Terminal` default to `FailClosed`;
    /// `Transformation` and `Observability` default to `FailOpen`. A single global
    /// default is wrong in both directions: fail-open on an authz filter is a
    /// security hole, and fail-closed on a logging filter is an outage.
    #[must_use]
    pub const fn default_failure_mode(self) -> FailureMode {
        match self {
            FilterKind::Authorization | FilterKind::Limit | FilterKind::Terminal => {
                FailureMode::FailClosed
            }
            FilterKind::Transformation | FilterKind::Observability => FailureMode::FailOpen,
        }
    }

    /// The status a fail-closed failure of this kind produces: 403 for
    /// `Authorization`, 429 for `Limit`, 500 for the rest.
    #[must_use]
    pub const fn fail_closed_status(self) -> u16 {
        match self {
            FilterKind::Authorization => 403,
            FilterKind::Limit => 429,
            FilterKind::Transformation | FilterKind::Observability | FilterKind::Terminal => 500,
        }
    }

    /// The stable `snake_case` name used in configuration and metrics.
    ///
    /// The exact table, which no other issue may re-invent: `Authorization` ->
    /// `"authorization"`, `Limit` -> `"limit"`, `Transformation` -> `"transformation"`,
    /// `Observability` -> `"observability"`, `Terminal` -> `"terminal"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            FilterKind::Authorization => "authorization",
            FilterKind::Limit => "limit",
            FilterKind::Transformation => "transformation",
            FilterKind::Observability => "observability",
            FilterKind::Terminal => "terminal",
        }
    }
}

/// What happens to the stream when a filter fails (panics are never an
/// option; this is for an explicit, returned failure).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum FailureMode {
    /// The stream continues as if the filter had returned `Action::Continue`.
    FailOpen = 0,
    /// The stream is short-circuited with the kind's configured status.
    FailClosed = 1,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KINDS: [FilterKind; FilterKind::COUNT] = [
        FilterKind::Authorization,
        FilterKind::Limit,
        FilterKind::Transformation,
        FilterKind::Observability,
        FilterKind::Terminal,
    ];

    #[test]
    fn failure_defaults_by_kind() {
        // This is the test that fails if someone "simplifies" the table to
        // one global default.
        assert_eq!(
            FilterKind::Authorization.default_failure_mode(),
            FailureMode::FailClosed
        );
        assert_eq!(
            FilterKind::Limit.default_failure_mode(),
            FailureMode::FailClosed
        );
        assert_eq!(
            FilterKind::Terminal.default_failure_mode(),
            FailureMode::FailClosed
        );
        assert_eq!(
            FilterKind::Transformation.default_failure_mode(),
            FailureMode::FailOpen
        );
        assert_eq!(
            FilterKind::Observability.default_failure_mode(),
            FailureMode::FailOpen
        );
    }

    #[test]
    fn fail_closed_status_by_kind() {
        assert_eq!(FilterKind::Authorization.fail_closed_status(), 403);
        assert_eq!(FilterKind::Limit.fail_closed_status(), 429);
        assert_eq!(FilterKind::Transformation.fail_closed_status(), 500);
        assert_eq!(FilterKind::Observability.fail_closed_status(), 500);
        assert_eq!(FilterKind::Terminal.fail_closed_status(), 500);
    }

    #[test]
    fn kind_names_exact() {
        let names: Vec<&str> = ALL_KINDS.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "authorization",
                "limit",
                "transformation",
                "observability",
                "terminal",
            ]
        );
    }
}
