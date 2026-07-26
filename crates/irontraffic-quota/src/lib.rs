// SPDX-License-Identifier: MIT OR Apache-2.0

//! Long-window quotas for IronTraffic.
//!
//! A quota is not a rate. It runs on the wall clock and a real calendar, it is
//! durable, it is billing grade, and it is never evicted inside its period.
//! Rate limiting lives in `irontraffic-limits` and runs on `CLOCK_BOOTTIME`.
//!
//! This crate reads [`irontraffic_time::CoarseWall`] and never
//! `irontraffic_time::Boot`. The two do not interconvert, which is what stops a
//! wall interval being added to a monotonic instant.

#![deny(missing_docs)]

pub mod period;

pub use period::{
    Anchor, CalendarAnchor, CalendarUnit, MAX_SUBJECT_BYTES, Period, PeriodError, PeriodId,
    PeriodResolver, PeriodWindow, QuotaSeed, SPREAD_MODULUS_DAY_MS, SPREAD_MODULUS_MS, SubjectHash,
    spread_modulus_ms,
};
