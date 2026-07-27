// SPDX-License-Identifier: MIT OR Apache-2.0

//! Documentation consistency tests.

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
    let close = lines[open + 1..]
        .iter()
        .position(|line| strip_doc_prefix(line).trim_end().eq("```"))
        .expect("EBNF block must close with ```")
        + open
        + 1;
    lines[open + 1..close]
        .iter()
        .map(|line| strip_doc_prefix(line))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn docs_grammar_matches_module_docs() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs_path = crate_dir.join("../../docs/ITPL.md");
    eprintln!("docs path: {:?}", docs_path);
    eprintln!("canonical: {:?}", docs_path.canonicalize());
    eprintln!("exists: {:?}", std::fs::metadata(&docs_path).is_ok());
    let raw = fs::read_to_string(&docs_path).unwrap();
    eprintln!("raw line 38 bytes: {:?}", raw.lines().nth(37));
    let from_docs = extract_ebnf(docs_path.to_str().unwrap());
    let from_lib = extract_ebnf(crate_dir.join("src/lib.rs").to_str().unwrap());
    eprintln!("from_docs: {:?}", from_docs);
    eprintln!("from_lib:  {:?}", from_lib);
    assert_eq!(
        from_docs, from_lib,
        "the EBNF block in docs/ITPL.md must match the one in src/lib.rs"
    );
}
