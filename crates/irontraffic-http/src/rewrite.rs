// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`RewriteLedger`], which makes every path rewrite re-run the full
//! normalization pipeline under a bounded number of re-route cycles.
//!
//! **Invariant P2.** Any rewrite produces a new [`crate::path::NormalizedPath`] by
//! re-running the FULL normalization pipeline on its output, and the request is
//! re-routed and re-authorized against that new value before it is forwarded. This is
//! the direct fix for Traefik CVE-2026-48020: `PathPrefix` matched a public router,
//! `StripPrefix` removed the prefix, and the *post-rewrite* path was normalized
//! afterwards, resolving `..` into a path owned by a different, authenticated router.
//! Route-level authorization bypass with one `..`.
//!
//! P2 needs a loop bound, because two filters can each rewrite. The bound: rewrites
//! are collected and the chain performs at most `max_rewrites` re-route cycles
//! (default 1, hard cap 3), each re-running normalization and authorization. Exceeding
//! the cap is a 500 with a dedicated metric ([`crate::error::RejectReason::RewriteLimitExceeded`]),
//! not a silent stop and not an unbounded loop. [`RewriteLedger`] is the type that
//! counts.
//!
//! **What this module does not deliver.** It does not route and it does not
//! authorize; no router exists yet. [`RewriteLedger::apply`] re-normalizes and
//! returns a [`RewriteOutcome`] telling the caller that a re-route cycle is required.
//! The routing milestone consumes that outcome, and this module is inert until it is
//! wired in: no request path calls it yet.

use bytes::{Bytes, BytesMut};

use crate::canonical::CanonicalRequest;
use crate::error::RejectReason;
use crate::limits::ClampedLimits;
use crate::path::{NormalizedPath, PathPolicy};

/// Counts and bounds path rewrites for one request.
///
/// INVARIANT P2: any rewrite produces a new `NormalizedPath` by re-running the FULL
/// normalization pipeline on its output, and the request is re-routed and re-authorized
/// against that new value before it is forwarded. The bound exists because two filters
/// can each rewrite.
///
/// Deliberately NOT `Copy`, for the same reason as `HeaderListBudget` in
/// `uncompressed-header-list-budget` (#25) and `InterimBudget` in
/// `response-framing-expect-and-interim` (#28): a filter chain written
/// `fn run(mut ledger: RewriteLedger, ..)` spends a copy, the caller's `applied` never
/// moves, and the P2 loop bound is gone with no compile error. The filter chain holds
/// one ledger and passes `&mut`.
#[derive(Clone, Debug)]
pub struct RewriteLedger {
    applied: u8,
    max: u8,
}

/// A requested path change, expressed as bytes rather than as an operation, so the
/// ledger does not need to know what kind of rewrite produced it.
#[derive(Clone, Debug)]
pub struct PathRewrite {
    /// The new path bytes, BEFORE normalization. May be anything; it is validated.
    pub new_path: Bytes,
    /// The new query, or `None` to keep the existing one. `Some(empty)` sets an empty query.
    pub new_query: Option<Bytes>,
}

/// What the caller must do after a rewrite.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RewriteOutcome {
    /// The path or the query changed. The caller MUST re-route and re-authorize before
    /// forwarding.
    RerouteRequired,
    /// The normalized result was byte-identical to the previous path AND the query was
    /// byte-identical too. No re-route is needed, and the rewrite still counted against
    /// the ledger.
    Unchanged,
}

impl RewriteLedger {
    /// A ledger allowing `limits.clamp_rewrites()` rewrites.
    ///
    /// Not a `const fn`, unlike the issue's own Public API section, which cannot
    /// compile: `ClampedLimits` exposes its fields (and `clamp_rewrites`, which reads
    /// one) only through a non-`const` `Deref` impl, and calling through that `Deref`
    /// is not permitted inside a `const fn` (`error[E0015]: cannot perform non-const
    /// deref coercion`). `HeaderListBudget::new` in `hlist.rs` and `InterimBudget::new`
    /// in `expect.rs` hit the identical constraint on the identical type first and
    /// both document it exactly this way; this follows that established precedent
    /// rather than inventing a workaround. Filed as a defect against this issue.
    #[must_use]
    pub fn new(limits: &ClampedLimits) -> Self {
        RewriteLedger {
            applied: 0,
            max: limits.clamp_rewrites(),
        }
    }

    /// Applies one rewrite: re-runs the FULL normalization pipeline on the new bytes and
    /// replaces the request's path.
    ///
    /// Algorithm:
    /// 1. If `self.applied >= self.max`, return `Err(RewriteLimitExceeded)` and perform
    ///    no normalization. Otherwise increment `self.applied` before doing any other
    ///    work: checking before incrementing keeps `applied <= max` true at every
    ///    instant, including on every later error return in this function, none of
    ///    which un-spends the slot.
    /// 2. Resolve the query source. `rewrite.new_path` may itself contain a `?`; if it
    ///    does and `rewrite.new_query` is also `Some`, the query would be expressed
    ///    twice, which is `Err(RequestLineMalformed)`. Otherwise run
    ///    `NormalizedPath::parse_into` over exactly one input: `rewrite.new_path` alone
    ///    when it already carries a query or when `rewrite.new_query` is absent, or
    ///    `rewrite.new_path` with `rewrite.new_query`'s bytes appended behind a
    ///    synthetic `?` when only `rewrite.new_query` is `Some`. The full nine-step
    ///    pipeline runs either way, over both sources when both are used: the
    ///    rewrite's output is untrusted input exactly like the original target,
    ///    because a filter can be driven by attacker-controlled bytes, and that
    ///    applies to a query supplied through `new_query` exactly as much as it does
    ///    to one embedded in `new_path`. A `RawQuery` has no public constructor
    ///    outside this crate's path module precisely so that every one in existence
    ///    has been through that check; resolving `new_query` any other way would
    ///    create one that had not, and `write_target` later writes it straight onto
    ///    the wire.
    /// 3. If neither source carried a query, the request's existing query is kept.
    /// 4. Compare the normalized path and the resolved query, both by bytes, against
    ///    the request's current values. Replace both unconditionally (assigning the
    ///    same bytes back is harmless) and return `Unchanged` only when both compared
    ///    equal; otherwise return `RerouteRequired`. The query is part of the
    ///    comparison because routing predicates can match on query parameters.
    ///
    /// The caller MUST re-route and re-authorize when the outcome is `RerouteRequired`.
    ///
    /// # Errors
    /// `RewriteLimitExceeded` when the ledger is exhausted; `RequestLineMalformed` when
    /// the new query is expressed both inside `new_path` and via `new_query`; plus
    /// every error `NormalizedPath::parse_into` can return.
    pub fn apply(
        &mut self,
        req: &mut CanonicalRequest,
        rewrite: &PathRewrite,
        policy: &PathPolicy,
        limits: &ClampedLimits,
        out: &mut BytesMut,
    ) -> Result<RewriteOutcome, RejectReason> {
        if self.applied >= self.max {
            return Err(RejectReason::RewriteLimitExceeded);
        }
        self.applied = self.applied.saturating_add(1);

        let new_path_has_query = rewrite.new_path.contains(&b'?');
        if new_path_has_query && rewrite.new_query.is_some() {
            return Err(RejectReason::RequestLineMalformed);
        }
        let query_source_present = new_path_has_query || rewrite.new_query.is_some();

        // The synthetic buffer below is built ONLY when `new_query` supplies a query
        // separately from `new_path` (the rare shape): the common case, a bare path
        // rewrite with no query change at all, borrows `rewrite.new_path` directly and
        // pays exactly one `parse_into` call and no extra allocation, matching this
        // function's documented cost of "bench_path_normalize plus two integer
        // operations".
        let mut synthetic_scratch = Vec::new();
        let input: &[u8] = if new_path_has_query {
            &rewrite.new_path
        } else if let Some(q) = &rewrite.new_query {
            synthetic_scratch.reserve(
                rewrite
                    .new_path
                    .len()
                    .saturating_add(1)
                    .saturating_add(q.len()),
            );
            synthetic_scratch.extend_from_slice(&rewrite.new_path);
            synthetic_scratch.push(b'?');
            synthetic_scratch.extend_from_slice(q);
            &synthetic_scratch
        } else {
            &rewrite.new_path
        };

        let (new_path, parsed_query) = NormalizedPath::parse_into(input, policy, limits, out)?;
        let new_query = if query_source_present {
            parsed_query
        } else {
            req.query.clone()
        };

        let path_unchanged = new_path.as_bytes() == req.path.as_bytes();
        let query_unchanged = match (&new_query, &req.query) {
            (None, None) => true,
            (Some(a), Some(b)) => a.as_bytes() == b.as_bytes(),
            _ => false,
        };

        req.path = new_path;
        req.query = new_query;

        if path_unchanged && query_unchanged {
            Ok(RewriteOutcome::Unchanged)
        } else {
            Ok(RewriteOutcome::RerouteRequired)
        }
    }

    /// Rewrites applied so far.
    #[must_use]
    pub const fn applied(&self) -> u8 {
        self.applied
    }

    /// Rewrites still permitted: `max.saturating_sub(applied)`, which is exact because
    /// `apply` checks before incrementing and therefore never lets `applied` exceed `max`.
    #[must_use]
    pub const fn remaining(&self) -> u8 {
        self.max.saturating_sub(self.applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Authority;
    use crate::canonical::CanonicalRequestBuilder;
    use crate::framing::RequestFraming;
    use crate::limits::Limits;
    use crate::path::{EncodedDot, EncodedSlash, RawQuery};
    use crate::peer::{IdentitySource, PeerIdentity};
    use crate::scalar::{Method, Scheme, WireVersion};
    use crate::section::FieldSectionBuilder;
    use std::net::{IpAddr, Ipv4Addr};

    fn base_request_with_query(path_raw: &[u8], query: Option<&[u8]>) -> CanonicalRequest {
        let limits = Limits::DEFAULT.clamped();
        let mut synthetic = Vec::from(path_raw);
        if let Some(q) = query {
            synthetic.push(b'?');
            synthetic.extend_from_slice(q);
        }
        let mut path_out = BytesMut::new();
        let (path, parsed_query) =
            NormalizedPath::parse_into(&synthetic, &PathPolicy::DEFAULT, &limits, &mut path_out)
                .expect("test fixture path must be well formed");

        let mut authority_out = BytesMut::new();
        let authority =
            Authority::parse_into(b"example.com", Scheme::Https, &limits, &mut authority_out)
                .expect("test fixture authority must be well formed");

        let mut arena = BytesMut::new();
        let builder = FieldSectionBuilder::new(&arena, &limits);
        let headers = builder.finish(&mut arena);

        CanonicalRequestBuilder::new()
            .method(Method::Get)
            .scheme(Scheme::Https)
            .authority(authority)
            .path(path, parsed_query)
            .headers(headers)
            .framing(RequestFraming::Empty)
            .version(WireVersion::Http11)
            .peer(PeerIdentity {
                client: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                client_port: Some(1234),
                source: IdentitySource::Socket,
                forwarded_proto: None,
                trusted_hops: 0,
                peer_trusted: false,
            })
            .build()
            .expect("test fixture request must build")
    }

    fn base_request(path_raw: &[u8]) -> CanonicalRequest {
        base_request_with_query(path_raw, None)
    }

    /// Applies one rewrite through a fresh `BytesMut`, so every call site below is
    /// one line instead of a five-field struct literal plus a scratch buffer.
    /// Takes `policy` and `limits` BY VALUE (both are small `Copy` types) rather than
    /// by reference: this is a private test helper, not the production `apply`
    /// signature the issue itself specifies as `&PathPolicy`/`&ClampedLimits`.
    fn apply_rewrite(
        ledger: &mut RewriteLedger,
        req: &mut CanonicalRequest,
        new_path: &'static [u8],
        new_query: Option<&'static [u8]>,
        policy: PathPolicy,
        limits: ClampedLimits,
    ) -> Result<RewriteOutcome, RejectReason> {
        let rewrite = PathRewrite {
            new_path: Bytes::from_static(new_path),
            new_query: new_query.map(Bytes::from_static),
        };
        ledger.apply(req, &rewrite, &policy, &limits, &mut BytesMut::new())
    }

    /// Applies two rewrites in sequence against one ledger held by the caller.
    /// Exists to prove that spending the ledger through a `&mut` borrow is visible
    /// to the owner: `ledger_bounds` asserts `ledger_spend.remaining() == 0`
    /// after both calls land on the one ledger it holds.
    ///
    /// That is a real property of `&mut`, but it is NOT a guard against
    /// `RewriteLedger` ever becoming `Copy`: this function's signature is `&mut
    /// RewriteLedger` either way, and `&mut` mutates the caller's one ledger
    /// identically whether or not the type also derives `Copy`, so the assertion
    /// in `ledger_bounds` passes unchanged if `Copy` is added. The real guard
    /// against that is `ledger_is_not_copy_at_compile_time`, below, which is a
    /// compile-time assertion rather than a runtime one.
    fn spend(
        ledger: &mut RewriteLedger,
        req: &mut CanonicalRequest,
        policy: PathPolicy,
        limits: ClampedLimits,
    ) {
        let _ = apply_rewrite(ledger, req, b"/one", None, policy, limits);
        let _ = apply_rewrite(ledger, req, b"/two", None, policy, limits);
    }

    #[test]
    fn ledger_bounds() {
        let policy = PathPolicy::DEFAULT;

        // Edge case 14: max = 1. The first apply succeeds; the second gives
        // `RewriteLimitExceeded` and performs no normalization, proven by giving the
        // second call a rewrite whose path would otherwise error a DIFFERENT way
        // (`/..` is `PathTraversalAboveRoot` on its own) and observing
        // `RewriteLimitExceeded` instead.
        let limits_one = Limits {
            max_rewrites: 1,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut ledger_one = RewriteLedger::new(&limits_one);
        assert_eq!(ledger_one.applied(), 0);
        let mut req_one = base_request(b"/public/x");
        let first = apply_rewrite(
            &mut ledger_one,
            &mut req_one,
            b"/public/y",
            None,
            policy,
            limits_one,
        );
        assert_eq!(first, Ok(RewriteOutcome::RerouteRequired));
        let second = apply_rewrite(
            &mut ledger_one,
            &mut req_one,
            b"/..",
            None,
            policy,
            limits_one,
        );
        assert_eq!(second, Err(RejectReason::RewriteLimitExceeded));

        // Edge case 15: max = 0. The first apply is already refused.
        let limits_zero = Limits {
            max_rewrites: 0,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut ledger_zero = RewriteLedger::new(&limits_zero);
        let mut req_zero = base_request(b"/public/x");
        let refused = apply_rewrite(
            &mut ledger_zero,
            &mut req_zero,
            b"/public/y",
            None,
            policy,
            limits_zero,
        );
        assert_eq!(refused, Err(RejectReason::RewriteLimitExceeded));

        // Edge case 16: `max_rewrites: 200` clamps to the hard cap of 3.
        let limits_over_cap = Limits {
            max_rewrites: 200,
            ..Limits::DEFAULT
        }
        .clamped();
        assert_eq!(RewriteLedger::new(&limits_over_cap).remaining(), 3);

        // Edge case 17: a rewrite producing the same bytes still consumes a slot.
        let limits_three = Limits {
            max_rewrites: 3,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut ledger_three = RewriteLedger::new(&limits_three);
        let mut req_three = base_request(b"/public/x");
        let same = apply_rewrite(
            &mut ledger_three,
            &mut req_three,
            b"/public/x",
            None,
            policy,
            limits_three,
        );
        assert_eq!(same, Ok(RewriteOutcome::Unchanged));
        assert_eq!(ledger_three.applied(), 1);

        let limits_spend = Limits {
            max_rewrites: 1,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut ledger_spend = RewriteLedger::new(&limits_spend);
        let mut req_spend = base_request(b"/start");
        spend(&mut ledger_spend, &mut req_spend, policy, limits_spend);
        assert_eq!(ledger_spend.remaining(), 0);
    }

    #[test]
    fn ledger_is_not_copy_at_compile_time() {
        // The real guard `spend`'s doc comment above points to, the same probe
        // `budget_is_not_copy_at_compile_time` in `hlist.rs` established for
        // `HeaderListBudget` (and the identical check in `expect.rs` for
        // `InterimBudget`): the inherent const is selected over the trait const
        // only when `T: Copy` holds, so `Probe<T>::IS_COPY` answers the question.
        // The `const` blocks turn a regression into a COMPILE error, not a test
        // failure that could be skipped or ignored.
        struct Probe<T>(core::marker::PhantomData<T>);
        trait NotCopy {
            const IS_COPY: bool = false;
        }
        impl<T> NotCopy for Probe<T> {}
        impl<T: Copy> Probe<T> {
            const IS_COPY: bool = true;
        }
        // `PathPolicy` is the positive control and proves the probe can still
        // say "yes": unlike `RewriteLedger`, it is `Copy`.
        const { assert!(!<Probe<RewriteLedger>>::IS_COPY) }
        const { assert!(<Probe<PathPolicy>>::IS_COPY) }
    }

    #[test]
    fn query_sources_and_outcome() {
        let limits = Limits::DEFAULT.clamped();
        let policy = PathPolicy::DEFAULT;

        // Edge case 22: `new_query: None` and no `?` in `new_path`: the existing
        // query is preserved.
        let mut req_query_preserved = base_request_with_query(b"/p", Some(b"a=1"));
        let mut ledger_query_preserved = RewriteLedger::new(&limits);
        let outcome_query_preserved = apply_rewrite(
            &mut ledger_query_preserved,
            &mut req_query_preserved,
            b"/q",
            None,
            policy,
            limits,
        )
        .expect("well formed rewrite");
        assert_eq!(outcome_query_preserved, RewriteOutcome::RerouteRequired);
        assert_eq!(
            req_query_preserved.query.as_ref().map(RawQuery::as_bytes),
            Some(&b"a=1"[..])
        );

        // Edge case 23: `new_query: Some(empty)` makes the query present and empty;
        // `RerouteRequired` because it differs from the previous (absent) query.
        let mut req_query_becomes_empty = base_request(b"/p");
        let mut ledger_query_becomes_empty = RewriteLedger::new(&limits);
        let outcome_query_becomes_empty = apply_rewrite(
            &mut ledger_query_becomes_empty,
            &mut req_query_becomes_empty,
            b"/p",
            Some(b""),
            policy,
            limits,
        )
        .expect("well formed rewrite");
        assert_eq!(outcome_query_becomes_empty, RewriteOutcome::RerouteRequired);
        assert_eq!(
            req_query_becomes_empty
                .query
                .as_ref()
                .map(RawQuery::as_bytes),
            Some(&b""[..])
        );

        // Edge case 23b: `new_path` is `/a?b=1` with `new_query: None`: the query
        // becomes `b=1`.
        let mut req_query_from_embedded_path = base_request(b"/a");
        let mut ledger_query_from_embedded_path = RewriteLedger::new(&limits);
        let outcome_embedded = apply_rewrite(
            &mut ledger_query_from_embedded_path,
            &mut req_query_from_embedded_path,
            b"/a?b=1",
            None,
            policy,
            limits,
        )
        .expect("well formed rewrite");
        assert_eq!(outcome_embedded, RewriteOutcome::RerouteRequired);
        assert_eq!(
            req_query_from_embedded_path
                .query
                .as_ref()
                .map(RawQuery::as_bytes),
            Some(&b"b=1"[..])
        );

        // Edge case 23c: `new_path` is `/a?b=1` with `new_query: Some(b"c=2")`: the
        // query is expressed twice.
        let mut req_double_query = base_request(b"/a");
        let mut ledger_double_query = RewriteLedger::new(&limits);
        let result_double_query = apply_rewrite(
            &mut ledger_double_query,
            &mut req_double_query,
            b"/a?b=1",
            Some(b"c=2"),
            policy,
            limits,
        );
        assert_eq!(result_double_query, Err(RejectReason::RequestLineMalformed));

        // Edge case 23d: the normalized path equals the current path but the query
        // differs: `RerouteRequired`, not `Unchanged`, because routing predicates can
        // match on the query.
        let mut req_query_only_changes = base_request_with_query(b"/a", Some(b"x=1"));
        let mut ledger_query_only_changes = RewriteLedger::new(&limits);
        let outcome_query_only_changes = apply_rewrite(
            &mut ledger_query_only_changes,
            &mut req_query_only_changes,
            b"/a",
            Some(b"x=2"),
            policy,
            limits,
        )
        .expect("well formed rewrite");
        assert_eq!(outcome_query_only_changes, RewriteOutcome::RerouteRequired);

        // Both the path and an existing, non-empty query stay byte-identical:
        // `Unchanged`, and specifically through the `(Some, Some)` comparison arm
        // (edge case 17 in `ledger_bounds` exercises only the `(None, None)` arm,
        // since that fixture carries no query at all).
        let mut req_same_query = base_request_with_query(b"/same", Some(b"k=v"));
        let mut ledger_same_query = RewriteLedger::new(&limits);
        let outcome_same_query = apply_rewrite(
            &mut ledger_same_query,
            &mut req_same_query,
            b"/same",
            Some(b"k=v"),
            policy,
            limits,
        )
        .expect("well formed rewrite");
        assert_eq!(outcome_same_query, RewriteOutcome::Unchanged);
    }

    #[test]
    fn strip_prefix_then_traversal_is_renormalized() {
        // Traefik CVE-2026-48020: `PathPrefix` matched a public router, `StripPrefix`
        // rewrote, and the post-rewrite path was normalized afterwards, resolving
        // `..` into a protected router's namespace. Re-running the FULL
        // normalization pipeline here, before the caller re-routes, is the fix.
        let limits = Limits::DEFAULT.clamped();
        let policy = PathPolicy::DEFAULT;
        let mut req = base_request(b"/public/x");
        let mut ledger = RewriteLedger::new(&limits);
        let outcome = apply_rewrite(
            &mut ledger,
            &mut req,
            b"/public/../admin",
            None,
            policy,
            limits,
        )
        .expect("well formed rewrite");
        assert_eq!(outcome, RewriteOutcome::RerouteRequired);
        assert_eq!(req.path.as_bytes(), b"/admin");
    }

    #[test]
    fn rewrite_output_uses_the_same_policy() {
        // Traefik CVE-2025-66490: an encoded restricted character in the path let a
        // request reach the backend while bypassing the middleware chain. `apply`
        // must run the rewrite's output through the SAME `PathPolicy` the original
        // parse used, never a laxer one; there is no policy override parameter.
        let limits = Limits::DEFAULT.clamped();
        let reject_policy = PathPolicy::DEFAULT;

        let mut req_reject = base_request(b"/a/b");
        let mut ledger_reject = RewriteLedger::new(&limits);
        let result_reject = apply_rewrite(
            &mut ledger_reject,
            &mut req_reject,
            b"/a/..%2fb",
            None,
            reject_policy,
            limits,
        );
        assert_eq!(result_reject, Err(RejectReason::PathEncodedSlash));

        let keep_policy = PathPolicy {
            encoded_slash: EncodedSlash::Keep,
            ..PathPolicy::DEFAULT
        };
        let mut req_keep = base_request(b"/a/b");
        let mut ledger_keep = RewriteLedger::new(&limits);
        let outcome_keep = apply_rewrite(
            &mut ledger_keep,
            &mut req_keep,
            b"/a/..%2fb",
            None,
            keep_policy,
            limits,
        )
        .expect("Keep policy accepts the encoded slash");
        assert_eq!(outcome_keep, RewriteOutcome::RerouteRequired);
        assert_eq!(req_keep.path.as_bytes(), b"/a/..%2Fb");

        // `PathPolicy` has three knobs, not one: a laxer policy that preserves
        // `encoded_slash` but relaxes `encoded_dot` or `merge_slashes` must be
        // just as detectable, or `apply` could silently select it and reopen the
        // same CVE shape through a different knob.

        // encoded_dot Reject vs Keep, same shape as encoded_slash above.
        let mut req_dot_reject = base_request(b"/a/b");
        let mut ledger_dot_reject = RewriteLedger::new(&limits);
        let result_dot_reject = apply_rewrite(
            &mut ledger_dot_reject,
            &mut req_dot_reject,
            b"/a/%2E%2E/b",
            None,
            reject_policy,
            limits,
        );
        assert_eq!(result_dot_reject, Err(RejectReason::PathEncodedDot));

        let dot_keep_policy = PathPolicy {
            encoded_dot: EncodedDot::Keep,
            ..PathPolicy::DEFAULT
        };
        let mut req_dot_keep = base_request(b"/a/b");
        let mut ledger_dot_keep = RewriteLedger::new(&limits);
        let outcome_dot_keep = apply_rewrite(
            &mut ledger_dot_keep,
            &mut req_dot_keep,
            b"/a/%2E%2E/b",
            None,
            dot_keep_policy,
            limits,
        )
        .expect("Keep policy accepts the encoded dot segment");
        assert_eq!(outcome_dot_keep, RewriteOutcome::RerouteRequired);
        assert_eq!(req_dot_keep.path.as_bytes(), b"/a/%2E%2E/b");

        // merge_slashes false vs true: `/x//y` is left alone under the default and
        // collapsed to `/x/y` only when the caller's policy asks for it.
        let mut req_slashes_false = base_request(b"/a/b");
        let mut ledger_slashes_false = RewriteLedger::new(&limits);
        let outcome_slashes_false = apply_rewrite(
            &mut ledger_slashes_false,
            &mut req_slashes_false,
            b"/x//y",
            None,
            reject_policy,
            limits,
        )
        .expect("merge_slashes: false leaves the run of slashes as sent");
        assert_eq!(outcome_slashes_false, RewriteOutcome::RerouteRequired);
        assert_eq!(req_slashes_false.path.as_bytes(), b"/x//y");

        let merge_slashes_policy = PathPolicy {
            merge_slashes: true,
            ..PathPolicy::DEFAULT
        };
        let mut req_slashes_true = base_request(b"/a/b");
        let mut ledger_slashes_true = RewriteLedger::new(&limits);
        let outcome_slashes_true = apply_rewrite(
            &mut ledger_slashes_true,
            &mut req_slashes_true,
            b"/x//y",
            None,
            merge_slashes_policy,
            limits,
        )
        .expect("merge_slashes: true collapses the run");
        assert_eq!(outcome_slashes_true, RewriteOutcome::RerouteRequired);
        assert_eq!(req_slashes_true.path.as_bytes(), b"/x/y");
    }

    fn rewrite_path_strategy() -> impl proptest::strategy::Strategy<Value = Bytes> {
        use proptest::prelude::*;
        prop_oneof![
            proptest::collection::vec(proptest::sample::select(&b"abc/.%2Ef5C?&="[..]), 0..=64)
                .prop_map(Bytes::from),
            proptest::collection::vec(any::<u8>(), 0..=64).prop_map(Bytes::from),
        ]
    }

    proptest::proptest! {
        #[test]
        fn prop_ledger_never_exceeds_max(
            rewrites in proptest::collection::vec(rewrite_path_strategy(), 0..=10),
            max in 0_u8..=3,
        ) {
            let limits = Limits { max_rewrites: max, ..Limits::DEFAULT }.clamped();
            let policy = PathPolicy::DEFAULT;
            let mut req = base_request(b"/start");
            let mut ledger = RewriteLedger::new(&limits);
            let mut ok_count: u32 = 0;
            let mut saw_limit_exceeded = false;

            for new_path in rewrites {
                let rewrite = PathRewrite { new_path, new_query: None };
                let mut out = BytesMut::new();
                let result = ledger.apply(&mut req, &rewrite, &policy, &limits, &mut out);

                if saw_limit_exceeded {
                    proptest::prop_assert!(
                        matches!(result, Err(RejectReason::RewriteLimitExceeded)),
                        "a result after RewriteLimitExceeded was not itself RewriteLimitExceeded: {:?}",
                        result
                    );
                    continue;
                }

                match result {
                    Ok(_) => {
                        ok_count = ok_count.saturating_add(1);
                        proptest::prop_assert_eq!(req.path.as_bytes().first(), Some(&b'/'));
                        for seg in req.path.segments() {
                            proptest::prop_assert_ne!(seg, b"..");
                            proptest::prop_assert_ne!(seg, b".");
                        }
                    }
                    Err(RejectReason::RewriteLimitExceeded) => {
                        saw_limit_exceeded = true;
                    }
                    Err(_) => {}
                }
            }

            proptest::prop_assert!(ok_count <= u32::from(max));
        }
    }
}
