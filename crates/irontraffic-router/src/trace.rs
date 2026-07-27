// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`RouteTrace`], the sink `match_request` observes a route match through, plus
//! the production ([`NoTrace`]) and explain ([`RecordTrace`]) implementations.
//!
//! Three separate surfaces need to answer "why did this request match this
//! route, and why did these near misses not match": the admin `/explain`
//! endpoint, the config dry-run response, and the dashboard's near-miss view.
//! If any of them were a second matcher, it would diverge from the real one,
//! and the divergence would be discovered during an incident. So
//! `match_request` (added by `match-request-core` (#60)) is generic over a
//! [`RouteTrace`] sink from its very first signature, with [`NoTrace`] as the
//! production argument:
//!
//! ```text
//! pub fn match_request<T: RouteTrace>(
//!     &self,
//!     req: &RequestView<'_>,
//!     scratch: &mut MatchScratch,
//!     trace: &mut T,
//! ) -> Option<MatchOutcome>;
//! ```
//!
//! [`NoTrace`] is a zero sized type, every method body is empty, and every
//! method is `#[inline(always)]`, so monomorphization erases the sink
//! entirely: `match_request::<NoTrace>` compiles to the same machine code as a
//! version of the function with no trace parameter at all.
//!
//! THAT IDENTITY IS NOT CHECKED ANYWHERE TODAY, and this comment used to say it
//! was. `match-request-core` (#60) is open, `match_request` does not exist yet,
//! and #60 explicitly DEFERS the instruction-count proof ("deferred to the
//! milestone-7 benchmark harness issue"); its `## Files` table contains no path
//! under `.github/` or `scripts/`, so it could not add the check even when it
//! lands. The owner is #423, open, milestone M17. `git grep -ri gungraun`
//! returns nothing. This module's obligation is only to make the check
//! ACHIEVABLE, which is why every method below takes only `Copy` scalar
//! arguments and nothing borrowed. A method that took a `&[u8]` or built a
//! struct would leave a trace of itself in the optimized code even with an
//! empty body, because computing the argument is work the caller would still
//! pay for.
//!
//! This module is INERT: nothing calls these methods until `match-request-core`
//! (#60).

use crate::ids::{GroupId, NodeId, RouteId};
use crate::precedence::Precedence;

/// A sink that observes the route match as it happens.
///
/// `match_request` is generic over this from its first signature. The
/// production implementation is [`NoTrace`], a zero-sized type whose methods
/// are empty, so the whole mechanism costs nothing:
/// `match_request::<NoTrace>` compiles to the same machine code as a version
/// with no trace parameter.
///
/// Implementations MUST NOT panic, MUST NOT allocate unboundedly, and MUST
/// tolerate being called in any order and any number of times. The matcher
/// makes no promise about how many times it will report a step; it reports
/// what it actually did.
pub trait RouteTrace {
    /// The host trie resolved to this chain head, or `GroupId::NONE` on no match.
    fn on_host(&mut self, chain: GroupId, cert_mask: u64);
    /// The matcher entered this group in the fallthrough chain.
    fn on_group(&mut self, group: GroupId);
    /// The path descent ended at this node, whose full key is `key_len` bytes.
    fn on_descent(&mut self, node: NodeId, key_len: u16);
    /// The `up` walk visited this node, which owns `cand_n` candidates.
    fn on_node(&mut self, node: NodeId, key_len: u16, cand_n: u16);
    /// A candidate was evaluated and rejected.
    fn on_reject(&mut self, cand: u32, route: RouteId, prec: Precedence, why: RejectReason);
    /// A candidate passed every check and won.
    fn on_accept(&mut self, cand: u32, route: RouteId, prec: Precedence);
    /// The visit budget was exhausted; the match returns no route.
    fn on_budget_exhausted(&mut self, spent: u32);
}

/// Why one candidate did not match. Every variant is produced by exactly one
/// check in the matcher, so an explain output names the precise reason rather
/// than "no match".
///
/// This is the routing crate's own reject vocabulary. `irontraffic-http` and
/// the TLS listener each have their own, unrelated `RejectReason`-shaped enum
/// for their own layer; the three are deliberately separate types and none of
/// them is reused across crates.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// An `Exact` path candidate whose node key length differs from the path length.
    ExactLengthMismatch,
    /// A `SegmentPrefix` candidate where the path continues with a byte other
    /// than `/`. This is the `/admin` versus `/admind` check.
    PrefixNotAtSegmentBoundary,
    /// The method mask did not intersect the request method.
    Method,
    /// A required header was absent.
    HeaderMissing,
    /// A header was present with a different value.
    HeaderValue,
    /// A header required to be absent was present.
    HeaderPresentButForbidden,
    /// A required query parameter was absent.
    QueryMissing,
    /// A query parameter was present with a different value.
    QueryValue,
    /// A path regex candidate whose pattern did not match. Produced only once
    /// `path-regex-multipattern` (#61) has landed.
    Regex,
    /// The predicate arena was inconsistent (an unknown op, an unterminated
    /// run, or an out-of-range literal). The candidate fails closed and the
    /// table is invalid.
    MalformedPredicate,
}

impl RejectReason {
    /// A stable, `snake_case` label for this reason.
    ///
    /// The explain output and the `route_reject_total` metric are both keyed
    /// on this label, so it is part of the contract: every variant maps to a
    /// distinct, non-empty label matching `[a-z0-9_]+`, and this `match` has
    /// no wildcard arm, so adding a variant without adding its label is a
    /// compile error rather than a silently mislabeled reject.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            RejectReason::ExactLengthMismatch => "exact_length_mismatch",
            RejectReason::PrefixNotAtSegmentBoundary => "prefix_not_at_segment_boundary",
            RejectReason::Method => "method",
            RejectReason::HeaderMissing => "header_missing",
            RejectReason::HeaderValue => "header_value",
            RejectReason::HeaderPresentButForbidden => "header_present_but_forbidden",
            RejectReason::QueryMissing => "query_missing",
            RejectReason::QueryValue => "query_value",
            RejectReason::Regex => "regex",
            RejectReason::MalformedPredicate => "malformed_predicate",
        }
    }
}

/// The production sink: records nothing, costs nothing.
///
/// A ZST with every method `#[inline(always)]` and empty. See the module
/// documentation for why this is the shape that makes the production path
/// pay literally nothing rather than a `dyn` vtable call or a runtime flag.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NoTrace;

const _: () = assert!(core::mem::size_of::<NoTrace>() == 0);

impl RouteTrace for NoTrace {
    #[inline(always)]
    fn on_host(&mut self, _chain: GroupId, _cert_mask: u64) {}
    #[inline(always)]
    fn on_group(&mut self, _group: GroupId) {}
    #[inline(always)]
    fn on_descent(&mut self, _node: NodeId, _key_len: u16) {}
    #[inline(always)]
    fn on_node(&mut self, _node: NodeId, _key_len: u16, _cand_n: u16) {}
    #[inline(always)]
    fn on_reject(&mut self, _cand: u32, _route: RouteId, _prec: Precedence, _why: RejectReason) {}
    #[inline(always)]
    fn on_accept(&mut self, _cand: u32, _route: RouteId, _prec: Precedence) {}
    #[inline(always)]
    fn on_budget_exhausted(&mut self, _spent: u32) {}
}

/// Maximum steps [`RecordTrace`] retains. 256 steps at up to 32 bytes is at
/// most 8 KiB, which is fine for an admin request and far too much for a
/// request-path structure, which is why [`RecordTrace`] is never used on the
/// request path.
pub const MAX_EXPLAIN_STEPS: usize = 256;

/// One recorded step. `Copy` and at most 32 bytes so the array is a plain
/// block of memory.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExplainStep {
    /// The host trie resolved.
    Host {
        /// Chain head.
        chain: GroupId,
        /// Certificate mask at the matched authority.
        cert_mask: u64,
    },
    /// A group was entered.
    Group {
        /// The group.
        group: GroupId,
    },
    /// The path descent ended.
    Descent {
        /// Deepest node whose key is a prefix of the path.
        node: NodeId,
        /// That node's key length.
        key_len: u16,
    },
    /// A node was visited on the `up` walk.
    Node {
        /// The node.
        node: NodeId,
        /// Its key length.
        key_len: u16,
        /// How many candidates it owns.
        cand_n: u16,
    },
    /// A candidate was rejected.
    Reject {
        /// Candidate index within its group.
        cand: u32,
        /// The route it came from.
        route: RouteId,
        /// Its precedence.
        prec: Precedence,
        /// Why it failed.
        why: RejectReason,
    },
    /// A candidate won.
    Accept {
        /// Candidate index within its group.
        cand: u32,
        /// The route it came from.
        route: RouteId,
        /// Its precedence.
        prec: Precedence,
    },
    /// The budget ran out.
    BudgetExhausted {
        /// How much budget was spent.
        spent: u32,
    },
}

// `Reject` is the widest variant at 4 + 4 + 8 + 1 bytes plus the discriminant,
// which with 8-byte alignment lays out at 24 bytes on the compilers this was
// checked against. `<=` rather than `==` because the exact size depends on the
// enum layout the compiler chooses; the bound is what matters, since
// `MAX_EXPLAIN_STEPS * size_of::<ExplainStep>()` is then at most 8 KiB
// (256 * 32) and is 6 KiB at the expected 24-byte layout.
const _: () = assert!(core::mem::size_of::<ExplainStep>() <= 32);

/// A sink that records a bounded step list, for the `/explain` surface.
///
/// The step array is fixed size and the recorder stops recording once it is
/// full, incrementing `dropped` instead of growing. That bound is deliberate:
/// `/explain` runs against attacker-influenced route tables and an unbounded
/// step list would be a memory amplifier reachable from an admin request.
///
/// `ExplainStep` needs no `Default` impl for the array initializer below:
/// deriving one would force choosing a meaningless default variant, so `new`
/// instead initializes every slot to `Group { group: GroupId::NONE }` and
/// relies on `n` to bound the valid prefix. Entries past `n` are meaningless.
#[derive(Clone, Debug)]
pub struct RecordTrace {
    steps: [ExplainStep; MAX_EXPLAIN_STEPS],
    n: u16,
    dropped: u32,
}

impl RecordTrace {
    /// A new, empty recorder.
    #[must_use]
    pub fn new() -> RecordTrace {
        RecordTrace {
            steps: [ExplainStep::Group {
                group: GroupId::NONE,
            }; MAX_EXPLAIN_STEPS],
            n: 0,
            dropped: 0,
        }
    }

    /// The recorded steps, oldest first.
    #[must_use]
    pub fn steps(&self) -> &[ExplainStep] {
        self.steps.get(..usize::from(self.n)).unwrap_or(&[])
    }

    /// How many steps were dropped because the array was full.
    #[must_use]
    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    /// The winning route, if any step was an `Accept`. This is the value the
    /// `explain(req).winning_route_id == route(req).id` property test
    /// compares.
    ///
    /// An `Accept` step that was itself dropped because the array was full
    /// means this returns `None` even though the match succeeded: an explain
    /// output with `dropped() > 0` is truncated and the caller must say so.
    #[must_use]
    pub fn winner(&self) -> Option<RouteId> {
        self.steps().iter().find_map(|step| match step {
            ExplainStep::Accept { route, .. } => Some(*route),
            _ => None,
        })
    }

    /// Clears the recorder for reuse without reallocating.
    pub fn reset(&mut self) {
        self.n = 0;
        self.dropped = 0;
    }

    /// Records one step, or counts it as dropped once the array is full.
    /// `get_mut` rather than an index because `clippy::indexing_slicing` is
    /// denied crate-wide, and `saturating_add` so that a caller looping
    /// forever cannot overflow `dropped`. Overflow on entry only when the
    /// array is already full, so this always drops the NEWEST step past
    /// capacity, never the oldest: keeping the beginning is what makes an
    /// explain output readable, because the interesting decisions happen
    /// first.
    fn push(&mut self, step: ExplainStep) {
        match self.steps.get_mut(usize::from(self.n)) {
            Some(slot) => {
                *slot = step;
                self.n += 1;
            }
            None => {
                self.dropped = self.dropped.saturating_add(1);
            }
        }
    }
}

impl Default for RecordTrace {
    fn default() -> Self {
        RecordTrace::new()
    }
}

impl RouteTrace for RecordTrace {
    fn on_host(&mut self, chain: GroupId, cert_mask: u64) {
        self.push(ExplainStep::Host { chain, cert_mask });
    }

    fn on_group(&mut self, group: GroupId) {
        self.push(ExplainStep::Group { group });
    }

    fn on_descent(&mut self, node: NodeId, key_len: u16) {
        self.push(ExplainStep::Descent { node, key_len });
    }

    fn on_node(&mut self, node: NodeId, key_len: u16, cand_n: u16) {
        self.push(ExplainStep::Node {
            node,
            key_len,
            cand_n,
        });
    }

    fn on_reject(&mut self, cand: u32, route: RouteId, prec: Precedence, why: RejectReason) {
        self.push(ExplainStep::Reject {
            cand,
            route,
            prec,
            why,
        });
    }

    fn on_accept(&mut self, cand: u32, route: RouteId, prec: Precedence) {
        self.push(ExplainStep::Accept { cand, route, prec });
    }

    fn on_budget_exhausted(&mut self, spent: u32) {
        self.push(ExplainStep::BudgetExhausted { spent });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{ExplainStep, MAX_EXPLAIN_STEPS, NoTrace, RecordTrace, RejectReason, RouteTrace};
    use crate::ids::{GroupId, NodeId, RouteId};
    use crate::precedence::{PathKind, Precedence};

    /// Touches every `RouteTrace` method once, generic over the sink, which is
    /// what proves `NoTrace` satisfies the trait through the generic bound.
    /// `notrace_is_zero_sized` calls it once; there is no tight loop here, and
    /// this comment claimed one because it was written for a wall-clock test
    /// that has since been deleted (#650).
    fn touch_all<T: RouteTrace>(trace: &mut T) {
        trace.on_host(GroupId(1), 0xdead_beef);
        trace.on_group(GroupId(2));
        trace.on_descent(NodeId(3), 4);
        trace.on_node(NodeId(5), 6, 7);
        trace.on_reject(
            8,
            RouteId(9),
            Precedence::pack(PathKind::Exact, false, 0, 0, 0),
            RejectReason::Method,
        );
        trace.on_accept(
            10,
            RouteId(11),
            Precedence::pack(PathKind::Exact, true, 1, 1, 1),
        );
        trace.on_budget_exhausted(12);
    }

    #[test]
    fn notrace_is_zero_sized() {
        assert_eq!(core::mem::size_of::<NoTrace>(), 0);
        let mut nt = NoTrace;
        touch_all(&mut nt);
    }

    #[test]
    fn step_size_bound() {
        assert!(core::mem::size_of::<ExplainStep>() <= 32);
        assert!(core::mem::size_of::<RecordTrace>() <= 8 * 1024 + 16);
    }

    #[test]
    fn record_all_step_kinds() {
        let mut trace = RecordTrace::new();
        touch_all(&mut trace);

        let steps = trace.steps();
        assert_eq!(steps.len(), 7);
        assert_eq!(
            steps[0],
            ExplainStep::Host {
                chain: GroupId(1),
                cert_mask: 0xdead_beef
            }
        );
        assert_eq!(steps[1], ExplainStep::Group { group: GroupId(2) });
        assert_eq!(
            steps[2],
            ExplainStep::Descent {
                node: NodeId(3),
                key_len: 4
            }
        );
        assert_eq!(
            steps[3],
            ExplainStep::Node {
                node: NodeId(5),
                key_len: 6,
                cand_n: 7
            }
        );
        assert_eq!(
            steps[4],
            ExplainStep::Reject {
                cand: 8,
                route: RouteId(9),
                prec: Precedence::pack(PathKind::Exact, false, 0, 0, 0),
                why: RejectReason::Method,
            }
        );
        assert_eq!(
            steps[5],
            ExplainStep::Accept {
                cand: 10,
                route: RouteId(11),
                prec: Precedence::pack(PathKind::Exact, true, 1, 1, 1),
            }
        );
        assert_eq!(steps[6], ExplainStep::BudgetExhausted { spent: 12 });
    }

    #[test]
    fn record_caps_and_counts_dropped() {
        let mut trace = RecordTrace::new();
        for i in 0..300u32 {
            trace.on_group(GroupId(i));
        }
        assert_eq!(trace.steps().len(), MAX_EXPLAIN_STEPS);
        assert_eq!(trace.dropped(), 44);
        assert_eq!(
            trace.steps().first(),
            Some(&ExplainStep::Group { group: GroupId(0) }),
            "the FIRST call's step must be retained, not the most recent"
        );
    }

    #[test]
    fn winner_finds_accept() {
        let mut trace = RecordTrace::new();
        trace.on_reject(
            0,
            RouteId(1),
            Precedence::pack(PathKind::Exact, false, 0, 0, 0),
            RejectReason::HeaderMissing,
        );
        trace.on_accept(
            2,
            RouteId(7),
            Precedence::pack(PathKind::Exact, true, 0, 0, 1),
        );
        assert_eq!(trace.winner(), Some(RouteId(7)));

        let mut overflowed = RecordTrace::new();
        for i in 0..300u32 {
            overflowed.on_group(GroupId(i));
        }
        overflowed.on_accept(
            0,
            RouteId(42),
            Precedence::pack(PathKind::Exact, true, 0, 0, 0),
        );
        assert_eq!(
            overflowed.winner(),
            None,
            "an Accept dropped for capacity must not be reported as the winner"
        );
        assert!(overflowed.dropped() > 0);
    }

    #[test]
    fn reset_clears() {
        let mut trace = RecordTrace::new();
        for i in 0..300u32 {
            trace.on_group(GroupId(i));
        }
        assert!(!trace.steps().is_empty());
        assert!(trace.dropped() > 0);

        trace.reset();
        assert!(trace.steps().is_empty());
        assert_eq!(trace.dropped(), 0);

        trace.on_group(GroupId(99));
        assert_eq!(trace.steps(), [ExplainStep::Group { group: GroupId(99) }]);
    }

    #[test]
    fn reject_reason_labels_are_distinct() {
        // No wildcard arm: adding a `RejectReason` variant without adding it
        // here makes this match non-exhaustive and fails to compile, so this
        // test cannot go silently stale the way a `_ => ...` fallback would
        // let it.
        fn all_reasons() -> [RejectReason; 10] {
            let sample = RejectReason::ExactLengthMismatch;
            match sample {
                RejectReason::ExactLengthMismatch
                | RejectReason::PrefixNotAtSegmentBoundary
                | RejectReason::Method
                | RejectReason::HeaderMissing
                | RejectReason::HeaderValue
                | RejectReason::HeaderPresentButForbidden
                | RejectReason::QueryMissing
                | RejectReason::QueryValue
                | RejectReason::Regex
                | RejectReason::MalformedPredicate => [
                    RejectReason::ExactLengthMismatch,
                    RejectReason::PrefixNotAtSegmentBoundary,
                    RejectReason::Method,
                    RejectReason::HeaderMissing,
                    RejectReason::HeaderValue,
                    RejectReason::HeaderPresentButForbidden,
                    RejectReason::QueryMissing,
                    RejectReason::QueryValue,
                    RejectReason::Regex,
                    RejectReason::MalformedPredicate,
                ],
            }
        }

        let labels: Vec<&'static str> = all_reasons()
            .into_iter()
            .map(RejectReason::metric_label)
            .collect();

        for label in &labels {
            assert!(!label.is_empty(), "label must not be empty");
            assert!(
                label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "label {label} must match [a-z0-9_]+"
            );
        }

        let unique: HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(
            unique.len(),
            labels.len(),
            "labels must be pairwise distinct"
        );
    }
}
