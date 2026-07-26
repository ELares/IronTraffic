// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rate limits, concurrency limits, and admission control for IronTraffic.
//!
//! This crate holds the GCRA rate primitive, the sharded limiter key table, the
//! striped hot-key representation, per-key concurrency permits, and `RateLimit`
//! response-header emission. Long-window quotas live in `irontraffic-quota` and
//! cluster leases live in `irontraffic-limits-cluster`.
//!
//! The only clock this crate reads is [`irontraffic_time::Boot`]. Durations are
//! plain `u64` nanoseconds in fields named `*_nanos`; there is deliberately no
//! `Duration` type, because a domain-free duration is how a wall-clock interval
//! ends up added to a monotonic instant.
//!
//! This issue (`limits-crate-and-vocabulary`) defines the vocabulary only: the
//! dense identifier newtypes, the denial reason enum, the seven configuration
//! mode enums, and the configuration error type with its range-check helpers.
//! No policy struct, table, or GCRA primitive lives here yet.

pub mod config;
pub mod ids;
pub mod mode;
pub mod reason;

pub use config::{ConfigError, at_least, at_most, power_of_two};
pub use ids::{PolicyId, ShardIdx};
pub use mode::{ExposeTo, HeaderFamily, LimitMode, OnExceed, OnUnavailable, QuotaStatus, Tier};
pub use reason::DenyReason;
