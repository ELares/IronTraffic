// SPDX-License-Identifier: MIT OR Apache-2.0

//! Active health checking: scheduling substrate for endpoint checks.
//!
//! [`wheel`] is the four-level hierarchical timing wheel that schedules and
//! reschedules up to hundreds of thousands of endpoint checks without spawning
//! one tokio timer per endpoint. [`http`] and [`tcp`] are the sans-IO response
//! codecs that decide pass or fail for one in-flight check: they perform no I/O,
//! read no clock, and share the [`StatusRange`], [`CodecStep`],
//! [`ConnectionFate`], and [`patterns_match`] items defined in this module. A
//! later issue in this milestone (the gRPC checker) builds directly on those
//! same shared items.

pub mod bitmap;
pub mod http;
pub mod schedule;
pub mod tcp;
pub mod wheel;

pub use bitmap::{ClusterHealth, EndpointHealth, HealthBitmap};
pub use http::{CompiledHttpCheck, HttpCheckCodec, HttpCheckMethod, HttpCheckSpec};
pub use schedule::{
    CheckOutcome, EndpointSchedule, FailKind, HealthCheckConfig, IntervalState, Transition,
    phase_ms,
};
pub use tcp::{CompiledTcpCheck, TcpCheckCodec, TcpCheckSpec};
pub use wheel::TimerWheel;

/// Half-open status range `[lo, hi)`. `StatusRange { lo: 200, hi: 300 }` is "any 2xx".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StatusRange {
    /// Inclusive lower bound.
    pub lo: u16,
    /// Exclusive upper bound.
    pub hi: u16,
}

impl StatusRange {
    /// True when `status` is in `[lo, hi)`.
    #[inline]
    #[must_use]
    pub fn contains(self, status: u16) -> bool {
        status >= self.lo && status < self.hi
    }
}

/// What the runner should do next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CodecStep {
    /// Read more bytes and call `on_bytes` again.
    NeedMore,
    /// The check is decided.
    Done {
        /// Pass, or the specific failure.
        outcome: CheckOutcome,
        /// Whether the connection may go back in the check's connection slot.
        fate: ConnectionFate,
    },
}

/// Whether the connection survives this check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionFate {
    /// The response provably had no body (a `HEAD` request, or a 204 or 304 status),
    /// so the socket is at a message boundary and the connection may be reused.
    Reusable,
    /// Anything else: the response may have carried body bytes we did not read, or it
    /// was malformed. Close it.
    Close,
}

/// True when every pattern in `patterns` appears in `body`, in order, without
/// overlap.
///
/// An exact, non-incremental search: for each pattern, `slice::windows` scans the
/// remaining tail of `body` starting after the previous match. This is correct for
/// self-overlapping patterns such as `aab` inside `aaab`, which an incremental
/// matcher that resets to zero on mismatch is not. Shared by
/// [`crate::health::http::HttpCheckCodec`] and
/// [`crate::health::tcp::TcpCheckCodec`]; there is exactly one copy.
pub(crate) fn patterns_match(body: &[u8], patterns: &[Box<[u8]>]) -> bool {
    let mut pos = 0usize;
    for pat in patterns {
        if pat.is_empty() {
            // Validation rejects an empty pattern before it can reach here. The
            // branch exists so a validation gap cannot turn into an infinite
            // loop: an empty needle would otherwise "match" at `pos` on every
            // iteration without ever advancing it.
            continue;
        }
        let Some(hay) = body.get(pos..) else {
            return false;
        };
        let Some(found) = hay.windows(pat.len()).position(|w| w == pat.as_ref()) else {
            return false;
        };
        pos = pos.saturating_add(found).saturating_add(pat.len());
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_range_contains_half_open() {
        let r = StatusRange { lo: 200, hi: 300 };
        assert!(!r.contains(199));
        assert!(r.contains(200));
        assert!(r.contains(299));
        assert!(!r.contains(300));
    }

    #[test]
    fn patterns_match_in_order_no_overlap() {
        let alpha: Box<[u8]> = Box::from(*b"alpha");
        let gamma: Box<[u8]> = Box::from(*b"gamma");
        assert!(patterns_match(
            b"alpha beta gamma",
            &[alpha.clone(), gamma.clone()]
        ));
        let a: Box<[u8]> = Box::from(*b"a");
        let b: Box<[u8]> = Box::from(*b"b");
        assert!(!patterns_match(b"ab", &[b, a]));
    }

    #[test]
    fn patterns_match_self_overlapping() {
        let aab: Box<[u8]> = Box::from(*b"aab");
        assert!(patterns_match(b"aaab", &[aab]));
    }

    // Edge case 26 from the issue: a repeated pattern needs a SECOND, disjoint
    // occurrence, not the same one counted twice. `pos` must advance past the
    // whole match (`found + pat.len()`), not just to the match start
    // (`found`): advancing only to the start lets the second search re-find
    // the identical occurrence the first search already consumed. This is
    // exactly what a mutant that drops `.saturating_add(pat.len())` from
    // `patterns_match`'s `pos` update produces, and it is NOT caught by
    // `patterns_match_in_order_no_overlap` above, whose negative case
    // ("b", "a" against "ab") happens to still fail correctly under that
    // mutant by coincidence.
    #[test]
    fn patterns_match_duplicate_pattern_needs_two_occurrences() {
        let a1: Box<[u8]> = Box::from(*b"a");
        let a2: Box<[u8]> = Box::from(*b"a");
        assert!(patterns_match(b"aa", &[a1.clone(), a2.clone()]));
        assert!(!patterns_match(b"a", &[a1, a2]));
    }

    #[test]
    fn patterns_match_empty_pattern_list_is_vacuously_true() {
        assert!(patterns_match(b"anything", &[]));
    }
}
