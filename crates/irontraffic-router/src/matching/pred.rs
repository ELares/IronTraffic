// SPDX-License-Identifier: MIT OR Apache-2.0

//! HOT PATH
//!
//! [`eval_preds`], which walks one candidate's contiguous [`Pred`] run and
//! decides whether every predicate holds, returning the [`RejectReason`] of
//! the FIRST failure in run order for the trace sink.
//!
//! Predicate evaluation is where a naive router spends most of its time,
//! because the naive shape is "for each candidate, for each predicate, look
//! the header up in a map". Our predicates are a flat structure-of-arrays
//! bytecode over ALREADY INTERNED names: the header lookup happened once,
//! during parsing, and the predicate here reads a slot indexed by a `NameId`
//! instead. Traefik, Kong and Envoy all do a header lookup per predicate per
//! candidate; this evaluator does zero.
//!
//! A candidate's predicates are contiguous in `Group::preds` starting at
//! `Cand::preds`, and the run is terminated by the `PRED_LAST` flag rather
//! than a length, which saves four bytes per candidate. Predicates are
//! emitted cheapest and most selective first by the builder: the method
//! mask (one AND), then header absence and presence (two loads, no
//! comparison), then header equality (two loads and a comparison), then
//! query predicates (which may force the lazy query parse). [`eval_preds`]
//! does not reorder; it trusts the build order, because reordering at
//! request time would be work per candidate for a decision that is
//! identical for every request.
//!
//! Case rules, which are a security property and not a style choice: header
//! NAMES are case insensitive (already handled: the name was lowercased
//! before interning). Header VALUES are case sensitive. Query parameter
//! names and values are both case sensitive. Getting any of those backwards
//! is a security bug, not a cosmetic one.
//!
//! The `HOT PATH` marker above puts this whole file under
//! `scripts/invariant-lints.sh`'s `hot-path-allocation` and `hot-path-lock`
//! rules, the same mechanism `src/normalize.rs`, `src/scratch.rs` and
//! `src/matching/path.rs` already use; `tests/no_alloc.rs`'s
//! `eval_preds_allocates_nothing` guards the marker line itself. This
//! module does not instead build a counting `#[global_allocator]`: this
//! crate is `#![forbid(unsafe_code)]` and `GlobalAlloc` is an `unsafe
//! trait`, so a process-wide counting allocator cannot compile here, and it
//! would be unsound even if it could, since it would count every other
//! test's allocations too, whichever happen to run in the same binary at the
//! same time.
//!
//! This module is INERT: [`eval_preds`] is called by `match-request-core`
//! (#60) and, later, by `discriminator-synthesis` (#62)'s merged scan.

use crate::ids::{MethodMask, SENTINEL};
use crate::request::RequestView;
use crate::scratch::MatchScratch;
use crate::table::{Group, Pred, PredOp, RouteTable};
use crate::trace::RejectReason;

/// The result of evaluating one candidate's predicate run.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PredOutcome {
    /// Every predicate held.
    Pass,
    /// A predicate failed. The reason is the FIRST failure in run order,
    /// which is what the explain surface reports.
    Fail(RejectReason),
}

/// Evaluates one candidate's predicate run.
///
/// Returns [`PredOutcome::Pass`] when every predicate holds, or
/// [`PredOutcome::Fail`] with the reason of the FIRST failure in run order.
/// A `start` of `SENTINEL` means the candidate is unconditional and always
/// passes; that is the overwhelmingly common case and it never touches the
/// arena.
///
/// Allocation-free and panic-free, for any arena content: a malformed op, an
/// unterminated run, an out-of-range literal offset and an out-of-range
/// `NameId` all fail closed rather than panicking. Decrements `budget` once
/// per predicate examined, before evaluating it, and stops the moment it
/// reaches zero; the caller distinguishes budget exhaustion from a genuine
/// predicate failure by checking `*budget == 0` afterwards.
///
/// `budget` is the CANDIDATE-evaluation budget, the one `match-request-core`
/// (#60) initializes to `MAX_CAND_EVALS`. It is NOT `visit_budget(path.len())`.
/// The two budgets are separate on purpose: node visits are driven by the
/// request's path length, while predicate evaluations are driven by how many
/// candidates the CONFIGURATION put on a node. Charging predicates against
/// the path-derived budget would mean a request to `/` (budget 68) could not
/// finish scanning even 34 single-predicate candidates, so a table with 100
/// header-differentiated rules on `/` would 404 the most common request
/// there is.
///
/// Header names are compared case-insensitively (already handled: the name
/// was lowercased before interning). Header VALUES, query names and query
/// values are all compared as raw bytes, case sensitively.
#[must_use]
pub fn eval_preds(
    group: &Group,
    table: &RouteTable,
    start: u32,
    req: &RequestView<'_>,
    scratch: &mut MatchScratch,
    budget: &mut u32,
) -> PredOutcome {
    if start == SENTINEL {
        return PredOutcome::Pass;
    }
    let run = group.preds_from(start);
    if run.is_empty() {
        return PredOutcome::Fail(RejectReason::MalformedPredicate);
    }

    for p in run {
        if *budget == 0 {
            return PredOutcome::Fail(RejectReason::MalformedPredicate);
        }
        *budget -= 1;

        let Some(op) = PredOp::from_u8(p.op) else {
            return PredOutcome::Fail(RejectReason::MalformedPredicate);
        };

        // A predicate that names a slot this scratch does not have is a
        // corrupted or mismatched table, NOT an absent header. Failing
        // closed here is what stops `HeaderAbsent` from silently PASSING in
        // that case: without this check, an unusable `NameId` would read as
        // "absent" and a route gated on a header's absence would match a
        // request that does carry it.
        if matches!(
            op,
            PredOp::HeaderExact | PredOp::HeaderPresent | PredOp::HeaderAbsent
        ) && (p.a.is_none() || p.a.idx() >= scratch.header_slot_count())
        {
            return PredOutcome::Fail(RejectReason::MalformedPredicate);
        }
        if matches!(op, PredOp::QueryExact | PredOp::QueryPresent)
            && (p.a.is_none() || p.a.idx() >= table.query_names().count())
        {
            return PredOutcome::Fail(RejectReason::MalformedPredicate);
        }

        let ok = match op {
            PredOp::Method => req.method.intersects(MethodMask(p.d)),
            PredOp::HeaderPresent => scratch.header_present(p.a),
            PredOp::HeaderAbsent => !scratch.header_present(p.a),
            PredOp::HeaderExact => match scratch.header_value(p.a, req.head) {
                Some(v) => v == group.literal(p),
                None => false,
            },
            PredOp::QueryPresent => {
                scratch.index_query(table, req.query);
                scratch.query_present(p.a)
            }
            PredOp::QueryExact => {
                scratch.index_query(table, req.query);
                match scratch.query_value(p.a, req.query) {
                    Some(v) => v == group.literal(p),
                    None => false,
                }
            }
        };

        if !ok {
            return PredOutcome::Fail(reason_for(op, *p, scratch));
        }
    }

    PredOutcome::Pass
}

/// Maps a failing predicate to the reason the explain surface reports. Takes
/// the scratch by shared reference because two of the six ops distinguish
/// "absent" from "present with a different value" and that distinction is a
/// slot read.
///
/// Takes `p` BY VALUE rather than `&Pred` as the issue's snippet shows: `Pred`
/// is 16 bytes and `Copy`, so `clippy::trivially_copy_pass_by_ref` (pedantic,
/// denied under `-D warnings`) rejects the reference form. This helper is
/// private and file-local, unlike `eval_preds`, whose signature the issue
/// says is quoted exactly because three later issues call it; nothing outside
/// this file depends on `reason_for`'s exact shape.
fn reason_for(op: PredOp, p: Pred, scratch: &MatchScratch) -> RejectReason {
    match op {
        PredOp::Method => RejectReason::Method,
        PredOp::HeaderPresent => RejectReason::HeaderMissing,
        PredOp::HeaderAbsent => RejectReason::HeaderPresentButForbidden,
        PredOp::HeaderExact => {
            if scratch.header_present(p.a) {
                RejectReason::HeaderValue
            } else {
                RejectReason::HeaderMissing
            }
        }
        PredOp::QueryPresent => RejectReason::QueryMissing,
        PredOp::QueryExact => {
            if scratch.query_present(p.a) {
                RejectReason::QueryValue
            } else {
                RejectReason::QueryMissing
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::ids::{CertId, GroupId, ListenerId, MethodMask, NameId, SENTINEL};
    use crate::intern::NameSetBuilder;
    use crate::request::RequestView;
    use crate::scratch::MatchScratch;
    use crate::table::{
        Group, MAX_PREDS_PER_CAND, Pred, PredOp, RouteTable, TableParts, pred_flags,
    };
    use crate::trace::RejectReason;

    use super::{PredOutcome, eval_preds};

    /// Builds a table with the requested header and query names, sharing the
    /// helper shape `scratch::tests::build_table` already uses.
    fn build_table(
        header_names: &[&[u8]],
        query_names: &[&[u8]],
        needs_query: bool,
    ) -> (RouteTable, Vec<NameId>, Vec<NameId>) {
        let mut hb = NameSetBuilder::new();
        let mut hids = Vec::new();
        for name in header_names {
            hids.push(hb.insert(name).unwrap());
        }
        let mut qb = NameSetBuilder::new();
        let mut qids = Vec::new();
        for name in query_names {
            qids.push(qb.insert(name).unwrap());
        }
        let table = RouteTable::from_parts(TableParts {
            header_names: hb.finish(),
            query_names: qb.finish(),
            needs_query,
            ..Default::default()
        });
        (table, hids, qids)
    }

    /// A `Group` holding only a predicate arena: no trie nodes and no
    /// candidates, since `eval_preds` reads `start` directly as an index
    /// into `preds` and never touches the trie.
    fn group_with_preds(preds: Vec<Pred>, blob: Vec<u8>) -> Group {
        crate::table::tests::tiny_group(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            preds,
            blob,
            GroupId::NONE,
        )
    }

    /// Appends `bytes` to `blob` and returns its `(offset, length)`.
    fn push_literal(blob: &mut Vec<u8>, bytes: &[u8]) -> (u32, u32) {
        let off = u32::try_from(blob.len()).unwrap();
        blob.extend_from_slice(bytes);
        let len = u32::try_from(bytes.len()).unwrap();
        (off, len)
    }

    /// A minimal `RequestView`. `authority` and `path` are irrelevant to
    /// `eval_preds`, which never reads them.
    fn mk_request<'a>(method: MethodMask, head: &'a [u8], query: &'a [u8]) -> RequestView<'a> {
        RequestView {
            authority: b"",
            path: b"/",
            query,
            method,
            head,
            listener: ListenerId(0),
            sni: None,
            cert: CertId::NONE,
        }
    }

    /// Builds a contiguous head buffer from `(name, value)` pairs, observing
    /// each into `scratch` in order, so a repeated name overwrites the
    /// earlier slot exactly as `MatchScratch::observe_header` documents.
    fn observe_all(
        table: &RouteTable,
        scratch: &mut MatchScratch,
        headers: &[(&[u8], &[u8])],
    ) -> Vec<u8> {
        let mut head = Vec::new();
        for &(name, value) in headers {
            let off = u32::try_from(head.len()).unwrap();
            head.extend_from_slice(value);
            let len = u32::try_from(value.len()).unwrap();
            scratch.observe_header(table, name, off, len);
        }
        head
    }

    #[test]
    fn sentinel_passes() {
        let (table, _, _) = build_table(&[], &[], false);
        let group = group_with_preds(Vec::new(), Vec::new());
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        let req = mk_request(MethodMask::GET, &[], &[]);
        let mut budget = 5u32;
        assert_eq!(
            eval_preds(&group, &table, SENTINEL, &req, &mut scratch, &mut budget),
            PredOutcome::Pass
        );
        assert_eq!(budget, 5, "SENTINEL must not spend any budget");
    }

    #[test]
    fn method_mask() {
        let (table, _, _) = build_table(&[], &[], false);
        let mask = MethodMask::GET.union(MethodMask::POST);
        let preds = vec![Pred {
            tag: pred_flags::PRED_LAST,
            op: PredOp::Method as u8,
            a: NameId::NONE,
            b: 0,
            c: 0,
            d: mask.0,
        }];
        let group = group_with_preds(preds, Vec::new());
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);

        let mut budget = 10u32;
        let req_get = mk_request(MethodMask::GET, &[], &[]);
        assert_eq!(
            eval_preds(&group, &table, 0, &req_get, &mut scratch, &mut budget),
            PredOutcome::Pass
        );

        let mut budget = 10u32;
        let req_post = mk_request(MethodMask::POST, &[], &[]);
        assert_eq!(
            eval_preds(&group, &table, 0, &req_post, &mut scratch, &mut budget),
            PredOutcome::Pass
        );

        let mut budget = 10u32;
        let req_put = mk_request(MethodMask::PUT, &[], &[]);
        assert_eq!(
            eval_preds(&group, &table, 0, &req_put, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::Method)
        );

        let mut budget = 10u32;
        let req_none = mk_request(MethodMask::NONE, &[], &[]);
        assert_eq!(
            eval_preds(&group, &table, 0, &req_none, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::Method)
        );

        // ANY must also match OTHER: every named method plus OTHER is what
        // "any single-bit request method" means.
        let preds_any = vec![Pred {
            tag: pred_flags::PRED_LAST,
            op: PredOp::Method as u8,
            a: NameId::NONE,
            b: 0,
            c: 0,
            d: MethodMask::ANY.0,
        }];
        let group_any = group_with_preds(preds_any, Vec::new());
        let mut budget = 10u32;
        let req_other = mk_request(MethodMask::OTHER, &[], &[]);
        assert_eq!(
            eval_preds(&group_any, &table, 0, &req_other, &mut scratch, &mut budget),
            PredOutcome::Pass
        );
    }

    #[test]
    fn header_present_and_absent() {
        let (table, hids, _) = build_table(&[b"x"], &[], false);
        let x = hids[0];
        let present_pred = vec![Pred {
            tag: pred_flags::PRED_LAST,
            op: PredOp::HeaderPresent as u8,
            a: x,
            b: 0,
            c: 0,
            d: 0,
        }];
        let absent_pred = vec![Pred {
            tag: pred_flags::PRED_LAST,
            op: PredOp::HeaderAbsent as u8,
            a: x,
            b: 0,
            c: 0,
            d: 0,
        }];
        let present_group = group_with_preds(present_pred, Vec::new());
        let absent_group = group_with_preds(absent_pred, Vec::new());

        // Combination 1: header present with a non-empty value.
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        let head = observe_all(&table, &mut scratch, &[(b"x", b"abc")]);
        let req = mk_request(MethodMask::GET, &head, &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(&present_group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Pass
        );
        let mut budget = 5;
        assert_eq!(
            eval_preds(&absent_group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::HeaderPresentButForbidden)
        );

        // Combination 2: header present with an EMPTY value still counts as
        // present.
        let mut scratch_empty = MatchScratch::new();
        scratch_empty.begin_request(&table);
        let head_empty = observe_all(&table, &mut scratch_empty, &[(b"x", b"")]);
        let req_empty = mk_request(MethodMask::GET, &head_empty, &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(
                &present_group,
                &table,
                0,
                &req_empty,
                &mut scratch_empty,
                &mut budget
            ),
            PredOutcome::Pass
        );
        let mut budget = 5;
        assert_eq!(
            eval_preds(
                &absent_group,
                &table,
                0,
                &req_empty,
                &mut scratch_empty,
                &mut budget
            ),
            PredOutcome::Fail(RejectReason::HeaderPresentButForbidden)
        );

        // Combination 3: header genuinely absent.
        let mut scratch_absent = MatchScratch::new();
        scratch_absent.begin_request(&table);
        let req_absent = mk_request(MethodMask::GET, &[], &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(
                &present_group,
                &table,
                0,
                &req_absent,
                &mut scratch_absent,
                &mut budget
            ),
            PredOutcome::Fail(RejectReason::HeaderMissing)
        );
        let mut budget = 5;
        assert_eq!(
            eval_preds(
                &absent_group,
                &table,
                0,
                &req_absent,
                &mut scratch_absent,
                &mut budget
            ),
            PredOutcome::Pass
        );
    }

    #[test]
    fn header_exact_matches() {
        let (table, hids, _) = build_table(&[b"x"], &[], false);
        let x = hids[0];
        let mut blob = Vec::new();
        let (off, len) = push_literal(&mut blob, b"abc");
        let preds = vec![Pred {
            tag: pred_flags::PRED_LAST,
            op: PredOp::HeaderExact as u8,
            a: x,
            b: off,
            c: len,
            d: 0,
        }];
        let group = group_with_preds(preds, blob);

        let mut scratch_match = MatchScratch::new();
        scratch_match.begin_request(&table);
        let head_match = observe_all(&table, &mut scratch_match, &[(b"x", b"abc")]);
        let req_match = mk_request(MethodMask::GET, &head_match, &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(
                &group,
                &table,
                0,
                &req_match,
                &mut scratch_match,
                &mut budget
            ),
            PredOutcome::Pass
        );

        let mut scratch_diff = MatchScratch::new();
        scratch_diff.begin_request(&table);
        let head_diff = observe_all(&table, &mut scratch_diff, &[(b"x", b"xyz")]);
        let req_diff = mk_request(MethodMask::GET, &head_diff, &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 0, &req_diff, &mut scratch_diff, &mut budget),
            PredOutcome::Fail(RejectReason::HeaderValue)
        );

        let mut scratch_absent = MatchScratch::new();
        scratch_absent.begin_request(&table);
        let req_absent = mk_request(MethodMask::GET, &[], &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(
                &group,
                &table,
                0,
                &req_absent,
                &mut scratch_absent,
                &mut budget
            ),
            PredOutcome::Fail(RejectReason::HeaderMissing)
        );
    }

    #[test]
    fn header_value_is_case_sensitive() {
        // Header VALUES are case sensitive. Getting this backwards is a
        // security bug: a request carrying `bearer abc` must NOT satisfy a
        // route gated on the literal `Bearer abc`.
        let (table, hids, _) = build_table(&[b"authorization"], &[], false);
        let auth = hids[0];
        let mut blob = Vec::new();
        let (off, len) = push_literal(&mut blob, b"Bearer abc");
        let preds = vec![Pred {
            tag: pred_flags::PRED_LAST,
            op: PredOp::HeaderExact as u8,
            a: auth,
            b: off,
            c: len,
            d: 0,
        }];
        let group = group_with_preds(preds, blob);

        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        let head = observe_all(&table, &mut scratch, &[(b"authorization", b"bearer abc")]);
        let req = mk_request(MethodMask::GET, &head, &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::HeaderValue)
        );
    }

    #[test]
    fn empty_literal_semantics() {
        let (table, hids, _) = build_table(&[b"x"], &[], false);
        let x = hids[0];
        let preds = vec![Pred {
            tag: pred_flags::PRED_LAST,
            op: PredOp::HeaderExact as u8,
            a: x,
            b: 0,
            c: 0,
            d: 0,
        }];
        let group = group_with_preds(preds, Vec::new());

        // Edge case 9: present with an empty value matches an empty literal.
        let mut scratch_present = MatchScratch::new();
        scratch_present.begin_request(&table);
        let head = observe_all(&table, &mut scratch_present, &[(b"x", b"")]);
        let req_present = mk_request(MethodMask::GET, &head, &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(
                &group,
                &table,
                0,
                &req_present,
                &mut scratch_present,
                &mut budget
            ),
            PredOutcome::Pass
        );

        // Edge case 10: absent never matches an empty literal either.
        let mut scratch_absent = MatchScratch::new();
        scratch_absent.begin_request(&table);
        let req_absent = mk_request(MethodMask::GET, &[], &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(
                &group,
                &table,
                0,
                &req_absent,
                &mut scratch_absent,
                &mut budget
            ),
            PredOutcome::Fail(RejectReason::HeaderMissing)
        );
    }

    #[test]
    fn query_predicates() {
        let (table, _, qids) = build_table(&[], &[b"a", b"b", b"c"], true);
        let qa = qids[0];
        let qb = qids[1];
        let qc = qids[2];
        let mut blob = Vec::new();
        let (off_one, len_one) = push_literal(&mut blob, b"1");
        let (off_empty, len_empty) = push_literal(&mut blob, b"");
        let (off_two, len_two) = push_literal(&mut blob, b"2");
        let preds = vec![
            Pred {
                tag: pred_flags::PRED_LAST,
                op: PredOp::QueryPresent as u8,
                a: qa,
                b: 0,
                c: 0,
                d: 0,
            }, // idx 0: a present
            Pred {
                tag: pred_flags::PRED_LAST,
                op: PredOp::QueryExact as u8,
                a: qa,
                b: off_one,
                c: len_one,
                d: 0,
            }, // idx 1: a == "1"
            Pred {
                tag: pred_flags::PRED_LAST,
                op: PredOp::QueryPresent as u8,
                a: qb,
                b: 0,
                c: 0,
                d: 0,
            }, // idx 2: b present (empty value)
            Pred {
                tag: pred_flags::PRED_LAST,
                op: PredOp::QueryExact as u8,
                a: qb,
                b: off_empty,
                c: len_empty,
                d: 0,
            }, // idx 3: b == ""
            Pred {
                tag: pred_flags::PRED_LAST,
                op: PredOp::QueryPresent as u8,
                a: qc,
                b: 0,
                c: 0,
                d: 0,
            }, // idx 4: c present (it is not, in the query below)
            Pred {
                tag: pred_flags::PRED_LAST,
                op: PredOp::QueryExact as u8,
                a: qa,
                b: off_two,
                c: len_two,
                d: 0,
            }, // idx 5: a == "2" (it is "1")
        ];
        let group = group_with_preds(preds, blob);

        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        let req = mk_request(MethodMask::GET, &[], b"a=1&b=");

        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Pass,
            "a is present"
        );
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 1, &req, &mut scratch, &mut budget),
            PredOutcome::Pass,
            "a equals 1"
        );
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 2, &req, &mut scratch, &mut budget),
            PredOutcome::Pass,
            "b is present with an empty value"
        );
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 3, &req, &mut scratch, &mut budget),
            PredOutcome::Pass,
            "b equals the empty string"
        );
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 4, &req, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::QueryMissing),
            "c is absent"
        );
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 5, &req, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::QueryValue),
            "a is present but does not equal 2"
        );
    }

    #[test]
    fn query_leftmost_wins() {
        let (table, _, qids) = build_table(&[], &[b"a"], true);
        let qa = qids[0];
        let mut blob = Vec::new();
        let (off, len) = push_literal(&mut blob, b"2");
        let preds = vec![Pred {
            tag: pred_flags::PRED_LAST,
            op: PredOp::QueryExact as u8,
            a: qa,
            b: off,
            c: len,
            d: 0,
        }];
        let group = group_with_preds(preds, blob);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        let req = mk_request(MethodMask::GET, &[], b"a=1&a=2");
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::QueryValue),
            "query_value returns the leftmost occurrence, \"1\", which does not equal \"2\""
        );
    }

    #[test]
    fn run_order_reports_first_failure() {
        let (table, hids, _) = build_table(&[b"x", b"y"], &[], false);
        let x = hids[0];
        let y = hids[1];
        let mut blob = Vec::new();
        let (off, len) = push_literal(&mut blob, b"v");
        let preds = vec![
            Pred {
                tag: 0,
                op: PredOp::Method as u8,
                a: NameId::NONE,
                b: 0,
                c: 0,
                d: MethodMask::GET.0,
            },
            Pred {
                tag: 0,
                op: PredOp::HeaderPresent as u8,
                a: x,
                b: 0,
                c: 0,
                d: 0,
            },
            Pred {
                tag: pred_flags::PRED_LAST,
                op: PredOp::HeaderExact as u8,
                a: y,
                b: off,
                c: len,
                d: 0,
            },
        ];
        let group = group_with_preds(preds, blob);
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        // Method fails (PUT != GET) AND header x is also absent, which would
        // ALSO fail if it were reached; the run must report the FIRST
        // failure only.
        let req = mk_request(MethodMask::PUT, &[], &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::Method)
        );
    }

    /// A one-field-per-argument `Pred` builder, so the malformed-arena cases
    /// in `malformed_arena_fails_closed` fit one record per line.
    fn single_pred(last: bool, op: u8, a: NameId, b: u32, c: u32) -> Pred {
        Pred {
            tag: if last { pred_flags::PRED_LAST } else { 0 },
            op,
            a,
            b,
            c,
            d: 0,
        }
    }

    /// Asserts that a single-predicate run built from `preds` fails with
    /// `MalformedPredicate` against a fresh table, scratch and request; used
    /// by every sub-case of `malformed_arena_fails_closed` except the two
    /// that need their own request or table state.
    fn assert_malformed(table: &RouteTable, scratch: &mut MatchScratch, preds: Vec<Pred>) {
        let group = group_with_preds(preds, Vec::new());
        let req = mk_request(MethodMask::GET, &[], &[]);
        let mut budget = 5;
        assert_eq!(
            eval_preds(&group, table, 0, &req, scratch, &mut budget),
            PredOutcome::Fail(RejectReason::MalformedPredicate)
        );
    }

    #[test]
    fn malformed_arena_fails_closed() {
        let (table, hids, _) = build_table(&[b"x", b"y"], &[], false);
        let x = hids[0];
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        assert_eq!(scratch.header_slot_count(), 2);

        // (a) An unterminated run: two records, neither carrying PRED_LAST.
        let hp = PredOp::HeaderPresent as u8;
        assert_malformed(
            &table,
            &mut scratch,
            vec![
                single_pred(false, hp, x, 0, 0),
                single_pred(false, hp, x, 0, 0),
            ],
        );
        // (b) op == 200, not a valid PredOp discriminant.
        assert_malformed(&table, &mut scratch, vec![single_pred(true, 200, x, 0, 0)]);
        // (c) NameId::NONE on a HeaderPresent.
        assert_malformed(
            &table,
            &mut scratch,
            vec![single_pred(true, hp, NameId::NONE, 0, 0)],
        );
        // (d) NameId::NONE on a HeaderAbsent: the point of the test. Without
        // the explicit check this negative predicate would read an unusable
        // NameId as "absent" and PASS, a fail-open bypass.
        let ha = PredOp::HeaderAbsent as u8;
        assert_malformed(
            &table,
            &mut scratch,
            vec![single_pred(true, ha, NameId::NONE, 0, 0)],
        );
        // (e) A NameId AT scratch.header_slot_count() (2, one past the last
        // valid slot) on a HeaderAbsent: the boundary the ">=" comparison
        // exists to catch, as opposed to only ">".
        assert_malformed(
            &table,
            &mut scratch,
            vec![single_pred(true, ha, NameId(2), 0, 0)],
        );

        // (g) and (h): the query-op counterpart of (c) and (e). Edge case 14
        // states the same rule applies "for the query ops against
        // table.query_names().count()". This table interns zero query
        // names, so table.query_names().count() == 0 and NameId(0) is
        // already one past the last valid slot (there is no valid slot at
        // all), which is the same boundary case (e) drives for headers.
        // Found by `cargo mutants -j 1` scoped to this file: replacing the
        // `||` on the query-side check with `&&` survived every case above,
        // because none of them exercises an out-of-range, non-NONE query
        // NameId.
        let qp = PredOp::QueryPresent as u8;
        assert_malformed(
            &table,
            &mut scratch,
            vec![single_pred(true, qp, NameId::NONE, 0, 0)],
        );
        assert_malformed(
            &table,
            &mut scratch,
            vec![single_pred(true, PredOp::QueryExact as u8, NameId(0), 0, 0)],
        );

        // (f) A literal whose b + c extends past the blob. group.literal
        // returns an empty slice for it, so it compares equal only to an
        // empty value; a present, NON-empty header value must therefore
        // still fail, and above all must not panic.
        let oob_literal = vec![single_pred(true, PredOp::HeaderExact as u8, x, 100, 10)];
        let group_f = group_with_preds(oob_literal, vec![0u8; 4]);
        let mut scratch_f = MatchScratch::new();
        scratch_f.begin_request(&table);
        let head_f = observe_all(&table, &mut scratch_f, &[(b"x", b"abc")]);
        let req_f = mk_request(MethodMask::GET, &head_f, &[]);
        let mut budget = 5;
        let outcome = eval_preds(&group_f, &table, 0, &req_f, &mut scratch_f, &mut budget);
        assert!(
            matches!(outcome, PredOutcome::Fail(_)),
            "an out-of-range literal must fail, not panic: {outcome:?}"
        );
    }

    #[test]
    fn budget_accounting() {
        let (table, hids, _) = build_table(&[b"x", b"y", b"z"], &[], false);
        let x = hids[0];
        let y = hids[1];
        let z = hids[2];
        let preds = vec![
            Pred {
                tag: 0,
                op: PredOp::HeaderPresent as u8,
                a: x,
                b: 0,
                c: 0,
                d: 0,
            },
            Pred {
                tag: 0,
                op: PredOp::HeaderPresent as u8,
                a: y,
                b: 0,
                c: 0,
                d: 0,
            },
            Pred {
                tag: pred_flags::PRED_LAST,
                op: PredOp::HeaderPresent as u8,
                a: z,
                b: 0,
                c: 0,
                d: 0,
            },
        ];
        let group = group_with_preds(preds, Vec::new());
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        let head = observe_all(
            &table,
            &mut scratch,
            &[(b"x", b"1"), (b"y", b"1"), (b"z", b"1")],
        );
        let req = mk_request(MethodMask::GET, &head, &[]);

        let mut budget = 10u32;
        assert_eq!(
            eval_preds(&group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Pass
        );
        assert_eq!(
            budget, 7,
            "a 3-predicate passing run spends exactly 3 budget"
        );

        let mut budget = 1u32;
        assert_eq!(
            eval_preds(&group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::MalformedPredicate)
        );
        assert_eq!(
            budget, 0,
            "the first predicate is evaluated, the second sees budget 0"
        );

        let mut budget = 0u32;
        assert_eq!(
            eval_preds(&group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Fail(RejectReason::MalformedPredicate)
        );
        assert_eq!(
            budget, 0,
            "budget 0 on entry fails immediately without evaluating anything"
        );
    }

    #[test]
    fn sixty_four_predicates() {
        assert_eq!(MAX_PREDS_PER_CAND, 64);
        let (table, hids, _) = build_table(&[b"x"], &[], false);
        let x = hids[0];
        let mut preds = Vec::new();
        for i in 0..MAX_PREDS_PER_CAND {
            let last = i + 1 == MAX_PREDS_PER_CAND;
            preds.push(Pred {
                tag: if last { pred_flags::PRED_LAST } else { 0 },
                op: PredOp::HeaderPresent as u8,
                a: x,
                b: 0,
                c: 0,
                d: 0,
            });
        }
        let group = group_with_preds(preds, Vec::new());
        let mut scratch = MatchScratch::new();
        scratch.begin_request(&table);
        let head = observe_all(&table, &mut scratch, &[(b"x", b"1")]);
        let req = mk_request(MethodMask::GET, &head, &[]);
        let mut budget = 100u32;
        assert_eq!(
            eval_preds(&group, &table, 0, &req, &mut scratch, &mut budget),
            PredOutcome::Pass
        );
        assert_eq!(budget, 100 - u32::try_from(MAX_PREDS_PER_CAND).unwrap());
    }

    // ------------------------------------------------------------------
    // Property tests 14 and 15: a shared generator over a 4-name table
    // (the same 4 names interned into both the header and the query name
    // space, as two independent `NameId` spaces), random ops from all six
    // `PredOp` variants, literals from `["", "a", "abc"]`, and requests
    // built from a random subset of the 4 names with possible duplicates.
    // ------------------------------------------------------------------

    /// The 4 names shared by the property-test generators, interned once
    /// into the header name space and once into the query name space.
    const NAMES: [&[u8]; 4] = [b"n0", b"n1", b"n2", b"n3"];

    /// The 3 literal values the property-test generators draw from.
    const LITERALS: [&[u8]; 3] = [b"", b"a", b"abc"];

    /// One generated predicate, before it is laid out into a `Pred` record.
    #[derive(Copy, Clone, Debug)]
    enum PropOp {
        Method(u32),
        HeaderPresent(usize),
        HeaderAbsent(usize),
        HeaderExact(usize, usize),
        QueryPresent(usize),
        QueryExact(usize, usize),
    }

    fn arb_op() -> impl Strategy<Value = PropOp> {
        prop_oneof![
            (0u32..0x400).prop_map(PropOp::Method),
            (0usize..4).prop_map(PropOp::HeaderPresent),
            (0usize..4).prop_map(PropOp::HeaderAbsent),
            (0usize..4, 0usize..3).prop_map(|(n, l)| PropOp::HeaderExact(n, l)),
            (0usize..4).prop_map(PropOp::QueryPresent),
            (0usize..4, 0usize..3).prop_map(|(n, l)| PropOp::QueryExact(n, l)),
        ]
    }

    /// One of the 10 legal single-bit request methods, per `RequestView`'s
    /// "exactly one bit" contract.
    fn arb_method() -> impl Strategy<Value = MethodMask> {
        prop::sample::select(vec![
            MethodMask::GET,
            MethodMask::HEAD,
            MethodMask::POST,
            MethodMask::PUT,
            MethodMask::DELETE,
            MethodMask::CONNECT,
            MethodMask::OPTIONS,
            MethodMask::TRACE,
            MethodMask::PATCH,
            MethodMask::OTHER,
        ])
    }

    /// Lays `ops` out into a `Pred` run, using `hids`/`qids` for the header
    /// and query `NameId` spaces respectively.
    fn build_prop_run(ops: &[PropOp], hids: &[NameId], qids: &[NameId]) -> (Vec<Pred>, Vec<u8>) {
        let mut blob = Vec::new();
        let mut preds = Vec::new();
        let n = ops.len();
        for (i, op) in ops.iter().enumerate() {
            let tag = if i + 1 == n { pred_flags::PRED_LAST } else { 0 };
            let rec = match *op {
                PropOp::Method(mask) => Pred {
                    tag,
                    op: PredOp::Method as u8,
                    a: NameId::NONE,
                    b: 0,
                    c: 0,
                    d: mask,
                },
                PropOp::HeaderPresent(idx) => Pred {
                    tag,
                    op: PredOp::HeaderPresent as u8,
                    a: hids[idx],
                    b: 0,
                    c: 0,
                    d: 0,
                },
                PropOp::HeaderAbsent(idx) => Pred {
                    tag,
                    op: PredOp::HeaderAbsent as u8,
                    a: hids[idx],
                    b: 0,
                    c: 0,
                    d: 0,
                },
                PropOp::HeaderExact(idx, lit) => {
                    let (off, len) = push_literal(&mut blob, LITERALS[lit]);
                    Pred {
                        tag,
                        op: PredOp::HeaderExact as u8,
                        a: hids[idx],
                        b: off,
                        c: len,
                        d: 0,
                    }
                }
                PropOp::QueryPresent(idx) => Pred {
                    tag,
                    op: PredOp::QueryPresent as u8,
                    a: qids[idx],
                    b: 0,
                    c: 0,
                    d: 0,
                },
                PropOp::QueryExact(idx, lit) => {
                    let (off, len) = push_literal(&mut blob, LITERALS[lit]);
                    Pred {
                        tag,
                        op: PredOp::QueryExact as u8,
                        a: qids[idx],
                        b: off,
                        c: len,
                        d: 0,
                    }
                }
            };
            preds.push(rec);
        }
        (preds, blob)
    }

    /// Joins `(name_idx, literal_idx)` pairs into a raw `name=value&...`
    /// query string over `NAMES`/`LITERALS`.
    fn build_query_string(pairs: &[(usize, usize)]) -> Vec<u8> {
        let mut q = Vec::new();
        for (i, &(name_idx, lit_idx)) in pairs.iter().enumerate() {
            if i > 0 {
                q.push(b'&');
            }
            q.extend_from_slice(NAMES[name_idx]);
            q.push(b'=');
            q.extend_from_slice(LITERALS[lit_idx]);
        }
        q
    }

    /// An independent, fresh split-based query parse: no code shared with
    /// `MatchScratch::index_query`. Returns `(name, value)` pairs in the
    /// order they appear, so "leftmost wins" falls out of a plain `find`.
    fn reference_query_pairs(query: &[u8]) -> Vec<(&[u8], &[u8])> {
        if query.is_empty() {
            return Vec::new();
        }
        query
            .split(|&b| b == b'&')
            .filter_map(|pair| {
                if pair.is_empty() {
                    return None;
                }
                match pair.iter().position(|&b| b == b'=') {
                    Some(i) => {
                        let name = &pair[..i];
                        let value = &pair[i + 1..];
                        if name.is_empty() {
                            None
                        } else {
                            Some((name, value))
                        }
                    }
                    None => Some((pair, &[][..])),
                }
            })
            .collect()
    }

    /// An independent linear scan for the LAST occurrence of `name`,
    /// matched case-insensitively, mirroring `MatchScratch`'s documented
    /// "last occurrence wins" without sharing its code.
    fn reference_header_value<'a>(headers: &'a [(&[u8], &[u8])], name: &[u8]) -> Option<&'a [u8]> {
        let mut found = None;
        for &(n, v) in headers {
            if n.eq_ignore_ascii_case(name) {
                found = Some(v);
            }
        }
        found
    }

    fn reference_header_present(headers: &[(&[u8], &[u8])], name: &[u8]) -> bool {
        headers.iter().any(|&(n, _)| n.eq_ignore_ascii_case(name))
    }

    /// The naive reference oracle: for each op, a linear scan of the
    /// request's header list with `eq_ignore_ascii_case` on the name and a
    /// byte comparison on the value, and a fresh split-based query parse.
    fn reference_eval(
        ops: &[PropOp],
        headers: &[(&[u8], &[u8])],
        query_pairs: &[(usize, usize)],
        method: MethodMask,
    ) -> PredOutcome {
        let query = build_query_string(query_pairs);
        let parsed_query = reference_query_pairs(&query);

        for op in ops {
            let ok = match *op {
                PropOp::Method(mask) => method.intersects(MethodMask(mask)),
                PropOp::HeaderPresent(idx) => reference_header_present(headers, NAMES[idx]),
                PropOp::HeaderAbsent(idx) => !reference_header_present(headers, NAMES[idx]),
                PropOp::HeaderExact(idx, lit) => {
                    reference_header_value(headers, NAMES[idx]) == Some(LITERALS[lit])
                }
                PropOp::QueryPresent(idx) => parsed_query.iter().any(|&(n, _)| n == NAMES[idx]),
                PropOp::QueryExact(idx, lit) => {
                    let value = parsed_query
                        .iter()
                        .find(|&&(n, _)| n == NAMES[idx])
                        .map(|&(_, v)| v);
                    value == Some(LITERALS[lit])
                }
            };
            if !ok {
                let reason = match *op {
                    PropOp::Method(_) => RejectReason::Method,
                    PropOp::HeaderPresent(_) => RejectReason::HeaderMissing,
                    PropOp::HeaderAbsent(_) => RejectReason::HeaderPresentButForbidden,
                    PropOp::HeaderExact(idx, _) => {
                        if reference_header_present(headers, NAMES[idx]) {
                            RejectReason::HeaderValue
                        } else {
                            RejectReason::HeaderMissing
                        }
                    }
                    PropOp::QueryPresent(_) => RejectReason::QueryMissing,
                    PropOp::QueryExact(idx, _) => {
                        if parsed_query.iter().any(|&(n, _)| n == NAMES[idx]) {
                            RejectReason::QueryValue
                        } else {
                            RejectReason::QueryMissing
                        }
                    }
                };
                return PredOutcome::Fail(reason);
            }
        }
        PredOutcome::Pass
    }

    proptest! {
        #[test]
        fn eval_is_deterministic(
            ops in prop::collection::vec(arb_op(), 1..=6),
            headers in prop::collection::vec((0usize..4, 0usize..3), 0..=6),
            query_pairs in prop::collection::vec((0usize..4, 0usize..3), 0..=6),
            method in arb_method(),
        ) {
            let (table, hids, qids) = build_table(&NAMES, &NAMES, true);
            let (preds, blob) = build_prop_run(&ops, &hids, &qids);
            let group = group_with_preds(preds, blob);
            let observed: Vec<(&[u8], &[u8])> = headers.iter().map(|&(n, l)| (NAMES[n], LITERALS[l])).collect();
            let query = build_query_string(&query_pairs);

            let mut scratch1 = MatchScratch::new();
            scratch1.begin_request(&table);
            let head1 = observe_all(&table, &mut scratch1, &observed);
            let req1 = mk_request(method, &head1, &query);
            let mut budget1 = 1000u32;
            let outcome1 = eval_preds(&group, &table, 0, &req1, &mut scratch1, &mut budget1);

            let mut scratch2 = MatchScratch::new();
            scratch2.begin_request(&table);
            let head2 = observe_all(&table, &mut scratch2, &observed);
            let req2 = mk_request(method, &head2, &query);
            let mut budget2 = 1000u32;
            let outcome2 = eval_preds(&group, &table, 0, &req2, &mut scratch2, &mut budget2);

            prop_assert_eq!(outcome1, outcome2);
            prop_assert_eq!(budget1, budget2);
        }
    }

    proptest! {
        #[test]
        fn eval_matches_reference(
            ops in prop::collection::vec(arb_op(), 1..=6),
            headers in prop::collection::vec((0usize..4, 0usize..3), 0..=8),
            query_pairs in prop::collection::vec((0usize..4, 0usize..3), 0..=8),
            method in arb_method(),
        ) {
            let (table, hids, qids) = build_table(&NAMES, &NAMES, true);
            let (preds, blob) = build_prop_run(&ops, &hids, &qids);
            let group = group_with_preds(preds, blob);
            let observed: Vec<(&[u8], &[u8])> = headers.iter().map(|&(n, l)| (NAMES[n], LITERALS[l])).collect();
            let query = build_query_string(&query_pairs);

            let mut scratch = MatchScratch::new();
            scratch.begin_request(&table);
            let head = observe_all(&table, &mut scratch, &observed);
            let req = mk_request(method, &head, &query);
            let mut budget = 1000u32;
            let outcome = eval_preds(&group, &table, 0, &req, &mut scratch, &mut budget);

            let expected = reference_eval(&ops, &observed, &query_pairs, method);
            prop_assert_eq!(outcome, expected);
        }
    }
}
