// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per handshake zero allocation gate for `UpgradeRequest::parse`, `accept_key` and
//! `UpgradeResponse::verify`.
//!
//! **Why this file exists.** `handshake_round_trip_is_within_the_per_handshake_budget` asserted a
//! 20 microsecond wall clock ceiling and called it "the sign that something is allocating per
//! handshake" (#203). Measured, it was not that sign: injecting a per handshake heap allocation of
//! 4 KiB, 64 KiB and 1 MiB left the assertion PASSING every time, against a 15.3 microsecond
//! baseline. What it did detect reliably was scheduler noise, which is why it failed CI at
//! 20.051 microseconds and blocked three unrelated PRs (#762). This file asserts the property that
//! ceiling was standing in for, deterministically, so the allocation claim is backed by something
//! that can actually fail when it is violated.
//!
//! **Why a text scan and not a counting allocator, stated accurately.** A counting
//! `#[global_allocator]` DOES compile in this workspace. `unsafe_code = "deny"` is the overridable
//! lint level, not `forbid`, and `crates/irontraffic-tls/tests/alloc_gate.rs` records that issue
//! #719 already corrected the opposite claim. What actually blocks it is
//! `scripts/invariant-lints.sh` rule 15, `no-unsafe`, whose failure text grants no exception:
//! "There is no exception an implementer is authorized to make; raise it on the issue instead."
//! That escalation has not happened for this crate, so this file adds neither the `unsafe` keyword
//! nor a crate level attribute re-enabling it, and does not suppress the rule with an `it-allow`
//! marker either. Writing that marker would be an implementer self granting an exception to a rule
//! that says no implementer may, which is a different thing from the mechanism being impossible.
//!
//! **What this proves and what it does not.** It catches an allocating call that appears,
//! textually, in a scanned function body. It CANNOT distinguish a function that allocates zero
//! times from one that allocates on every call through a spelling nobody added to the list, a call
//! taken by function pointer (`let f = str::to_lowercase; f(s)` matches nothing), or a call reached
//! through a fully qualified path (`ToOwned::to_owned(x)` rather than `x.to_owned()`). A review on
//! this repo exploited exactly that last blind spot to hide an allocation past a sibling gate, so
//! it is named here rather than left for the next reader to discover. This is a best effort net,
//! not a proof, which is the same framing `crates/irontraffic-http/tests/alloc_gate_common/mod.rs`
//! uses for the identical pattern.

/// Call spellings that can allocate.
///
/// Kept in step with `crates/irontraffic-http/tests/alloc_gate_common/mod.rs`, which owns the
/// canonical copy. This file keeps its own because that module lives under a different crate's
/// `tests/` directory.
const ALLOCATING_CALLS: [&str; 14] = [
    "format!",
    ".to_string()",
    ".to_owned()",
    ".to_vec()",
    "vec![",
    "Vec::new()",
    "String::new()",
    "String::from(",
    "Box::new(",
    "HashMap::new()",
    ".collect::<Vec",
    ".collect::<String",
    ".collect::<HashMap",
    ".clone()",
];

/// Returns the source text of the function whose signature contains `signature`, from its opening
/// brace through the matching closing brace.
fn extract_fn_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let start = source.find(signature)?;
    let open = source[start..].find('{').map(|offset| start + offset)?;
    let mut depth = 0usize;
    let mut end = open;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + offset + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if end > open {
        Some(&source[open..end])
    } else {
        None
    }
}

#[test]
fn handshake_round_trip_allocates_nothing() {
    let source = include_str!("../src/handshake.rs");

    // The three entry points the per handshake budget covers, plus the in crate helpers they
    // call. A function that moves or is renamed fails loudly below rather than silently dropping
    // out of the scan, which is the failure mode that makes a gate like this decorative.
    let checked: [&str; 3] = ["pub fn parse(", "pub fn accept_key(", "pub fn verify("];

    let mut scanned = 0u32;
    for anchor in checked {
        let body = extract_fn_body(source, anchor)
            .unwrap_or_else(|| panic!("`{anchor}` not found; has it moved or been renamed?"));
        for call in ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "the body anchored at `{anchor}` contains `{call}`, which can allocate. The \
                 handshake path is documented to allocate nothing per handshake (#203)"
            );
        }
        scanned += 1;
    }

    // Pinned to a LITERAL, not to `checked.len()`, so emptying the table fails this test rather
    // than scanning nothing and passing.
    assert_eq!(
        scanned, 3,
        "every anchored function must be scanned; emptying the table must FAIL this test"
    );
}
