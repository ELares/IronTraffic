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
//! - `charged()` never exceeds `Limits::DEFAULT.max_header_list_bytes` by more
//!   than one entry's worth: the charge that crosses the limit is recorded and
//!   then refused, so the bound is `limit + name.len() + value.len() + 32` and
//!   never more.
//! - Once a `push` fails with `HeaderListTooLarge` or `FieldCountExceeded`,
//!   every later `push` in the same sequence also fails. This is narrower
//!   than "the first `Err` is terminal" (a claim this target's own first
//!   draft disproved in under a second of fuzzing: a `push` that fails for a
//!   per-pair reason unrelated to the budget, such as `FieldNameInvalidByte`,
//!   has no bearing on a later, unrelated, well-formed pair, and nothing in
//!   `MplexHeadBuilder::push`'s own algorithm says it should). The narrower
//!   claim IS provably true: `HeaderListBudget::charge` runs first,
//!   unconditionally, on every `push` call, and both `HeaderListTooLarge` and
//!   `FieldCountExceeded` are monotonic in that budget's own internal
//!   counters (see `hlist.rs`'s `saturated_budget_stays_failed_forever` and
//!   `count_check_runs_before_any_byte_accounting`), so once either fires it
//!   fires on every subsequent charge regardless of the pair being charged.
//!   Filed as a defect against this issue's own `## Tests` section, which
//!   states the broader, false claim.
//! - On an `Ok` from `finish`, the built request satisfies invariant I2 (no
//!   hop-by-hop field remains) and its `TargetForm` is one of the three legal
//!   values.

use bytes::BytesMut;
use irontraffic_http::Limits;
use irontraffic_http::RejectReason;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::framing::OtherCodings;
use irontraffic_http::known::classify;
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
        let result = builder.push(&mut arena, name, value);
        if budget_poisoned {
            assert!(
                result.is_err(),
                "a push after the budget itself failed returned Ok for {data:?}"
            );
        }
        if matches!(
            result,
            Err(RejectReason::HeaderListTooLarge | RejectReason::FieldCountExceeded)
        ) {
            budget_poisoned = true;
        }

        // Bounded by the limit, not by the input: the charge that crosses the
        // limit is recorded and then refused, so the running total is never
        // more than one entry's worth (name + value + the 32-byte per-entry
        // overhead) past the limit.
        let max_overshoot = u64::try_from(name.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
            .saturating_add(32);
        assert!(
            builder.charged()
                <= u64::from(limits.max_header_list_bytes).saturating_add(max_overshoot),
            "charged() exceeded the budget by more than one entry's worth for {data:?}"
        );
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
