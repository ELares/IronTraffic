// SPDX-License-Identifier: MIT OR Apache-2.0
//! The shared vocabulary and the source-extraction helper every
//! `alloc_gate_*.rs` file in this directory uses.
//!
//! WHY THIS IS A DIRECTORY MODULE AND NOT A SEVENTH TEST FILE. Cargo turns
//! every `tests/*.rs` into its own test binary, so a helper written as
//! `tests/alloc_gate_common.rs` would compile as a test target of its own with
//! no tests in it. `tests/<name>/mod.rs` is not auto-discovered, so this file
//! is compiled only through the `mod alloc_gate_common;` declaration each gate
//! file carries.
//!
//! WHY THE GATES ARE TEXT SCANS AND NOT A COUNTING ALLOCATOR. Several issues
//! specify their allocation-freedom proof as a process-wide counting
//! `#[global_allocator]` wrapped around 1000 calls. That does not compile
//! here: `GlobalAlloc` is declared as an `unsafe trait`, so every
//! implementation, including a pure counter that forwards straight to
//! `std::alloc::System`, needs the keyword this repository denies with no
//! exception an implementer may grant (AGENTS.md, and the `no-unsafe` rule in
//! `scripts/invariant-lints.sh`). `#![forbid(unsafe_code)]` in `lib.rs` is a
//! crate-root attribute and does not reach a separate crate under `tests/`,
//! but this package's `[lints] workspace = true` in `Cargo.toml` does: it
//! applies the workspace's `unsafe_code = "deny"` to every target of the
//! package, integration tests included, which is confirmed by trying it. A
//! process-wide global allocator is also unsound independent of that ban: it
//! counts allocations made by every other test running in parallel in the
//! same binary. There is no `count_allocs` helper anywhere in this crate to
//! call.
//!
//! Instead these gates prove the same property the way the rest of this
//! workspace's allocation-freedom claims are enforced when the call graph is
//! concrete and non-dispatching (see `crates/irontraffic-k8s/tests/identity_sizes.rs`,
//! the reference implementation for this pattern): `scripts/invariant-lints.sh`'s
//! `hot-path-allocation` rule polices "does this code allocate" by scanning
//! source text for the calls that can allocate, not by instrumenting the
//! allocator. A text scan of a closed call graph is exhaustive over every
//! possible input, not just the ones a particular run happens to generate,
//! which is strictly stronger than a counting allocator sampled over any
//! finite number of calls. It remains a DENY LIST, not a proof: it catches
//! every call named in `ALLOCATING_CALLS`, textually, and nothing else, and it
//! cannot see that the runtime CONDITION governing when a call fires has
//! changed.

/// Calls that can allocate on the heap. Originally documented as "the exact
/// vocabulary" of `scripts/invariant-lints.sh`'s `hot-path-allocation` rule;
/// that claim was false (`.clone()` was missing). See
/// `tests/alloc_gate_h1.rs`'s module doc comment for how the gap was found.
/// This list is still a deny list, not a proof: it catches every call named
/// here, textually, and nothing else. Used by every `alloc_gate_*.rs` file in
/// this directory; every body they scan was grepped first to confirm none
/// already contains `.clone()` legitimately.
pub(crate) const ALLOCATING_CALLS: [&str; 14] = [
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

/// Returns the source text of the function whose signature contains
/// `signature`, from that function's opening brace through its matching
/// closing brace, or `None` if `signature` is not found or has no matching
/// closing brace.
///
/// A plain brace-depth text scan, not a Rust parser: correct as long as the
/// scanned body contains no string or char literal holding an unmatched `{`
/// or `}`, which every function scanned by these files satisfies today. If a
/// future edit to one of them ever needs such a literal, this test will need
/// a smarter scanner, not a workaround here.
///
/// Returns `Option` rather than panicking so this plain helper function,
/// which is not itself a `#[test]`, stays outside the escape clippy.toml
/// grants to test code; the callers unwrap it inside the `#[test]`
/// functions where that escape applies.
pub(crate) fn extract_fn_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
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
