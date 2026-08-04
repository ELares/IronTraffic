#![no_main]
//! Fuzz target for `irontraffic_http::mplex::head::MplexHeadBuilder`.
//!
//! Input domain: arbitrary bytes, split into `(name, value)` pairs by a
//! two-level delimiter (`0xFF` between pairs, `0xFE` between a name and its
//! value), pushed in order into an `MplexHeadBuilder` built with
//! `WireVersion::H2` and `&Limits::DEFAULT.clamped()`, followed by `finish`
//! with a fixed `MplexContext`.
//!
//! Contract: must not panic, must not hang, and the work must be bounded by
//! the budget rather than by the input. `MplexHeadBuilder::push` is the
//! HTTP/2 and HTTP/3 parse boundary, so the milestone rule that every parser
//! ships a fuzz target in its own issue applies to it. This is the
//! milestone's stand-in for the science document's `fuzz_hpack` and
//! `fuzz_qpack` targets, whose decoder halves are out of scope here: what
//! this crate owns is the sink, and the sink is what the budget assertions
//! below are about.
//!
//! Asserted on every run:
//! - `charged()` is bounded by `Limits::DEFAULT.max_header_list_bytes + one
//!   entry's worth` up to and including the charge that FIRST crosses the
//!   byte limit, not for the rest of the sequence: `HeaderListBudget::charge`
//!   keeps accumulating `used` on every later call once `count` is still
//!   within `max_field_count`, so `used` is not capped at `limit + one
//!   entry`, it merely stays above `limit` forever once crossed. Charges
//!   after the crossing point are therefore not bounded by this assertion,
//!   though they are provably inert: nothing further is stored, because
//!   every subsequent charge also fails (see the OTHER assertion below).
//!   Checked by [`irontraffic_http::mplex::head::guarded_charged_bound`],
//!   shared with this crate's own regression test so the two copies of this
//!   arithmetic cannot drift apart.
//! - Once a `push` fails with `HeaderListTooLarge`, or with
//!   `FieldCountExceeded` that the header-list budget's OWN field-count
//!   ceiling raised, every later `push` in the same sequence also fails.
//!   This is narrower than "the first `Err` is terminal" (a claim this
//!   target's own first draft disproved in under a second of fuzzing: a
//!   `push` that fails for a per-pair reason unrelated to the budget, such as
//!   `FieldNameInvalidByte`, has no bearing on a later, unrelated,
//!   well-formed pair) AND narrower than "every `FieldCountExceeded` is
//!   terminal" (a second, independently false claim an earlier draft of this
//!   comment made: `FieldCountExceeded` also comes from
//!   `CookieAccumulator`'s own, independent `MAX_COOKIE_CRUMBS` (256)
//!   ceiling, reached only once the budget's own charge for that same push
//!   already succeeded, and that refusal leaves the budget's `used` and
//!   `count` untouched, so a later, non-cookie push can still be charged and
//!   stored). The narrower claim IS provably true: `HeaderListBudget::charge`
//!   runs first, unconditionally, on every `push` call, and `used` and
//!   `count` are both monotonic in that budget's own internal state (see
//!   `hlist.rs`'s `saturated_budget_stays_failed_forever` and
//!   `count_check_runs_before_any_byte_accounting`), so once the BUDGET's own
//!   check fires it fires on every subsequent charge regardless of the pair
//!   being charged, while the accumulator's own ceiling firing says nothing
//!   about the budget at all. Checked by
//!   [`irontraffic_http::mplex::head::push_poisons_budget`], shared with this
//!   crate's own regression test for the same reason.
//! - On an `Ok` from `finish`, the built request satisfies invariant I2 (no
//!   hop-by-hop field remains) and its `TargetForm` is one of the three legal
//!   values.

use bytes::BytesMut;
use irontraffic_http::Limits;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::framing::OtherCodings;
use irontraffic_http::known::classify;
use irontraffic_http::mplex::head::{guarded_charged_bound, push_poisons_budget};
use irontraffic_http::mplex::{MplexContext, MplexHeadBuilder};
use irontraffic_http::path::{PathPolicy, TargetForm};
use irontraffic_http::peer::TrustPolicy;
use irontraffic_http::scalar::{Scheme, WireVersion};
use irontraffic_http::strip::is_hop_by_hop;
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Splits `data` into `(name, value)` pairs on the two-level delimiter:
/// `0xFF` separates pairs, `0xFE` separates a name from its value within one
/// pair. A pair with no `0xFE` is treated as a name with an empty value.
fn split_pairs(data: &[u8]) -> Vec<(&[u8], &[u8])> {
    data.split(|&b| b == 0xFF)
        .map(|pair| match pair.iter().position(|&b| b == 0xFE) {
            Some(i) => (
                pair.get(..i).unwrap_or(&[]),
                pair.get(i.saturating_add(1)..).unwrap_or(&[]),
            ),
            None => (pair, &[][..]),
        })
        .collect()
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT.clamped();
    let pairs = split_pairs(data);

    let mut arena = BytesMut::new();
    let mut builder = MplexHeadBuilder::new(&arena, &limits, WireVersion::H2);

    let mut budget_poisoned = false;
    for (name, value) in &pairs {
        // FIXED semantics: capture charged() BEFORE this push. The tight
        // bound only holds up to and including the charge that first
        // crosses the byte limit; once already over, `used` keeps growing
        // on every later charge (`HeaderListBudget::charge` never stops
        // accumulating once `count` is still within `max_field_count`), so
        // the bound is not re-checked past that point. The OTHER assertion
        // below (once poisoned, every later push also fails) is what
        // proves nothing further gets stored; this one is only about the
        // `used` counter's own growth up to the crossing charge.
        let charged_before = builder.charged();
        let result = builder.push(&mut arena, name, value);
        let charged_after = builder.charged();
        if budget_poisoned {
            assert!(
                result.is_err(),
                "a push after the budget itself failed returned Ok for {data:?}"
            );
        }
        // `push_poisons_budget` tells apart the budget's OWN
        // `FieldCountExceeded` (terminal) from `CookieAccumulator`'s
        // independent one (not terminal): see the module doc above.
        if push_poisons_budget(&result, charged_before, charged_after) {
            budget_poisoned = true;
        }

        if let Some(bound) = guarded_charged_bound(
            charged_before,
            u64::from(limits.max_header_list_bytes),
            name.len(),
            value.len(),
        ) {
            assert!(
                charged_after <= bound,
                "charged() exceeded the budget by more than one entry's worth for {data:?}"
            );
        }
    }

    let trust = TrustPolicy::None;
    let ctx = MplexContext {
        limits,
        path_policy: PathPolicy::DEFAULT,
        codings: OtherCodings::Reject,
        underscores: UnderscorePolicy::Reject,
        scheme: Scheme::Https,
        socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        proxy_proto: None,
        trust: &trust,
        will_buffer_body: false,
    };

    if let Ok((request, form)) = builder.finish(&ctx, &mut arena) {
        for (name, _, _) in request.headers.iter() {
            assert!(
                !is_hop_by_hop(classify(name)),
                "a hop-by-hop field survived into a built request for {data:?}: {name:?}"
            );
        }
        assert!(
            matches!(
                form,
                TargetForm::Origin | TargetForm::Asterisk | TargetForm::Authority
            ),
            "finish returned an illegal TargetForm {form:?} for {data:?}"
        );
    }
});
