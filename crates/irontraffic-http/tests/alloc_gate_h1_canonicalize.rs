// SPDX-License-Identifier: MIT OR Apache-2.0
//! The allocation gate for the `h1::canonicalize_request` and
//! `h1::canonicalize_response` surface.
//!
//! ONE ALLOCATION-GATE FILE PER SURFACE (issue #630). Do not append a gate for
//! another surface here: add `tests/alloc_gate_<surface>.rs`, which is what
//! stops two issues from ever conflicting in one shared gate file.
//!
//! WHY THIS IS A TEXT SCAN AND NOT A COUNTING ALLOCATOR. `GlobalAlloc` is an
//! `unsafe trait` and this package's `[lints] workspace = true` applies the
//! workspace's `unsafe_code = "deny"` to every target including this one, so a
//! counting `#[global_allocator]` cannot live anywhere in this repository; a
//! process-wide one would in any case count allocations made by every other
//! test running in parallel in the same binary. The full argument is in
//! `tests/alloc_gate_common/mod.rs`.
//!
//! This proves the checkable half of the same claim statically:
//! `canonicalize_request`'s own body contains no call from the allocating-call
//! vocabulary, so it cannot itself touch the allocator; every allocating
//! operation it invokes (`split_off` on the arena) is inside a callee that has
//! its own allocation gate.

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
fn canonicalize_request_allocates_only_in_callees() {
    let source = include_str!("../src/h1/canonicalize.rs");

    let checked: [(&str, &str); 2] = [
        ("canonicalize_request", "pub fn canonicalize_request("),
        ("canonicalize_response", "pub fn canonicalize_response("),
    ];

    for (name, signature) in checked {
        let body = extract_fn_body(source, signature).unwrap_or_else(|| {
            panic!(
                "`{signature}` not found in src/h1/canonicalize.rs; \
                 has {name} moved, been renamed, or been reformatted?"
            )
        });
        for call in ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "{name}'s body contains `{call}`, which can allocate; the callees \
                 (FieldSectionBuilder, NormalizedPath, Authority, etc.) have their \
                 own allocation gates and this function must not introduce additional \
                 heap allocations"
            );
        }
    }
}
