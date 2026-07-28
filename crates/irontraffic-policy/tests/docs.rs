// SPDX-License-Identifier: MIT OR Apache-2.0

//! Documentation consistency tests.
#![allow(
    clippy::expect_used,
    reason = "integration test code: a test that cannot panic cannot fail, and pushing Results through test helpers adds no safety"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "integration test code: the slices are bounded by prior position() calls on the same vector"
)]

use std::fs;
use std::path::Path;

/// Returns `line` with a leading `//!` doc-comment prefix removed.
fn strip_doc_prefix(line: &str) -> &str {
    match line.strip_prefix("//!") {
        Some(after_bang) => after_bang.strip_prefix(' ').unwrap_or(after_bang),
        None => line,
    }
}

/// Extracts the first fenced EBNF block from `path`.
///
/// Strips a leading `//!` prefix from each line so the same block can be read
/// from the Rust module docs and from the markdown file.
fn extract_ebnf(path: &str) -> String {
    let text = fs::read_to_string(path).expect("file must be readable");
    let lines: Vec<&str> = text.lines().collect();
    let open = lines
        .iter()
        .position(|line| strip_doc_prefix(line).trim_end().eq("```ebnf"))
        .expect("EBNF block must open with ```ebnf");
    let close = lines
        .get(open + 1..)
        .and_then(|rest| {
            rest.iter()
                .position(|line| strip_doc_prefix(line).trim_end().eq("```"))
        })
        .map(|pos| pos + open + 1)
        .expect("EBNF block must close with ```");
    lines
        .get(open + 1..close)
        .map(|block| {
            block
                .iter()
                .map(|line| strip_doc_prefix(line))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .expect("EBNF block slice is in range")
}

#[test]
fn docs_grammar_matches_module_docs() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs_path = crate_dir.join("../../docs/ITPL.md");
    let from_docs = extract_ebnf(docs_path.to_str().expect("path is valid utf-8"));
    let from_lib = extract_ebnf(
        crate_dir
            .join("src/lib.rs")
            .to_str()
            .expect("path is valid utf-8"),
    );
    assert_eq!(
        from_docs, from_lib,
        "the EBNF block in docs/ITPL.md must match the one in src/lib.rs"
    );
}
