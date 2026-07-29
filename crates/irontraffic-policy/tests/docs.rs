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
#![allow(
    clippy::panic,
    reason = "integration test code: these panics are the designed failure mode for a table that \
              has been renamed, deleted or given an unrecognised cell value. Failing loudly is the \
              whole point: the previous version of these tests silently iterated an empty set when \
              the documentation drifted, which is the defect being fixed"
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

/// Splits a markdown table row into its cells, trimming each.
///
/// `| a | b |` yields `["a", "b"]`. Leading and trailing empties from the outer
/// pipes are dropped; interior empties (an unset matrix cell) are kept.
fn table_cells(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    let inner = trimmed
        .strip_prefix('|')
        .and_then(|rest| rest.strip_suffix('|'))
        .unwrap_or(trimmed);
    inner
        .split('|')
        .map(|cell| cell.trim().to_owned())
        .collect()
}

/// Returns the data rows of the markdown table whose header cells equal `header`.
///
/// Panics if no such table exists, which is the point: renaming a column or
/// deleting a table fails the build here rather than silently emptying the loop
/// that would otherwise iterate over it.
fn table_rows(text: &str, header: &[&str]) -> Vec<Vec<String>> {
    let lines: Vec<&str> = text.lines().collect();
    let head = lines
        .iter()
        .position(|line| table_cells(line) == header)
        .unwrap_or_else(|| panic!("docs/ITPL.md has no table with header {header:?}"));
    // The row after the header is the `| --- |` separator; data starts after it.
    let mut rows = Vec::new();
    for line in lines.iter().skip(head + 2) {
        if !line.trim_start().starts_with('|') {
            break;
        }
        rows.push(table_cells(line));
    }
    assert!(
        !rows.is_empty(),
        "the table with header {header:?} has no data rows"
    );
    rows
}

/// Strips the surrounding backticks from a markdown code span.
fn unticked(cell: &str) -> &str {
    cell.trim_matches('`')
}

/// The published name for a scalar type, as the docs spell it.
fn ty_name(ty: irontraffic_policy::Ty) -> &'static str {
    match ty {
        irontraffic_policy::Ty::Str => "string",
        irontraffic_policy::Ty::Int => "int",
        irontraffic_policy::Ty::Bool => "bool",
        other => panic!("no published name for {other:?}"),
    }
}

#[test]
fn docs_scalar_table_matches_the_schema() {
    // Test 28: every column of the published scalar table is checked against the
    // running code, in BOTH directions, cell by cell.
    //
    // This replaces a `docs_text.contains(path)` substring search that pinned
    // almost nothing. Eight mutations of this file used to survive the whole
    // suite, including deleting rows and inverting the availability column. The
    // substring form could not even pin the 28 paths: `request.query` is a
    // prefix of `request.query_params`, so its row could be deleted from every
    // table and the assertion still passed, and `request.path` could be deleted
    // from this table because it still appeared in the availability matrix,
    // which is exactly the distinction the acceptance criterion asks for.
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs_path = crate_dir.join("../../docs/ITPL.md");
    let docs_text = fs::read_to_string(&docs_path).expect("docs/ITPL.md must be readable");

    let rows = table_rows(&docs_text, &["path", "type", "available from"]);

    let scalars: Vec<&irontraffic_policy::AttrEntry> = irontraffic_policy::ATTRS
        .iter()
        .filter(|entry| entry.attr.is_some())
        .collect();
    assert_eq!(
        rows.len(),
        scalars.len(),
        "the published scalar table has {} rows, the schema has {} scalar attributes",
        rows.len(),
        scalars.len()
    );

    for row in &rows {
        assert_eq!(row.len(), 3, "malformed scalar row: {row:?}");
        let path = unticked(&row[0]);
        let entry = irontraffic_policy::resolve_path(path.as_bytes()).unwrap_or_else(|| {
            panic!("docs/ITPL.md documents `{path}`, which is not an attribute")
        });
        let attr = entry
            .attr
            .unwrap_or_else(|| panic!("`{path}` is in the scalar table but is a map"));

        assert_eq!(
            row[1],
            ty_name(attr.ty()),
            "`{path}`: published type is `{}`, the schema says `{}`",
            row[1],
            ty_name(attr.ty())
        );
        assert_eq!(
            unticked(&row[2]),
            attr.from_phase().as_str(),
            "`{path}`: published availability is `{}`, the schema says `{}`",
            unticked(&row[2]),
            attr.from_phase().as_str()
        );
    }

    // The other direction: no scalar attribute may be missing from the table.
    for entry in scalars {
        let path = core::str::from_utf8(entry.path).expect("paths are ascii");
        assert!(
            rows.iter().any(|row| unticked(&row[0]) == path),
            "docs/ITPL.md's scalar table is missing `{path}`"
        );
    }
}

#[test]
fn docs_map_table_matches_the_schema() {
    // Test 28c: the map table's `key casing` column is a SECURITY rule, not a
    // note. Inverting it (telling an operator to write `X-Api-Key` when lookups
    // are lowercased, or to expect query parameters to be case insensitive when
    // they are not) silently breaks every policy an operator writes from the
    // documentation. It used to be pinned by nothing.
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs_path = crate_dir.join("../../docs/ITPL.md");
    let docs_text = fs::read_to_string(&docs_path).expect("docs/ITPL.md must be readable");

    let rows = table_rows(
        &docs_text,
        &["path", "element type", "available from", "key casing"],
    );

    let maps: Vec<&irontraffic_policy::AttrEntry> = irontraffic_policy::ATTRS
        .iter()
        .filter(|entry| entry.map.is_some())
        .collect();
    assert_eq!(
        rows.len(),
        maps.len(),
        "the published map table is the wrong size"
    );

    for row in &rows {
        assert_eq!(row.len(), 4, "malformed map row: {row:?}");
        let path = unticked(&row[0]);
        let entry = irontraffic_policy::resolve_path(path.as_bytes()).unwrap_or_else(|| {
            panic!("docs/ITPL.md documents `{path}`, which is not an attribute")
        });
        let map = entry
            .map
            .unwrap_or_else(|| panic!("`{path}` is in the map table but is a scalar"));

        assert_eq!(
            unticked(&row[2]),
            map.from_phase().as_str(),
            "`{path}`: published availability disagrees with the schema"
        );
        let published_lowercased = match row[3].as_str() {
            "lowercased" => true,
            "case sensitive" => false,
            other => panic!("`{path}`: unrecognised key casing `{other}`"),
        };
        assert_eq!(
            published_lowercased,
            map.lowercase_keys(),
            "`{path}`: published key casing is `{}`, which is backwards",
            row[3]
        );
    }

    for entry in maps {
        let path = core::str::from_utf8(entry.path).expect("paths are ascii");
        assert!(
            rows.iter().any(|row| unticked(&row[0]) == path),
            "docs/ITPL.md's map table is missing `{path}`"
        );
    }
}

#[test]
fn docs_availability_matrix_matches_the_schema() {
    // Test 28d: all 28 rows by all 10 phases, 280 published cells, each checked
    // against `available_in`. Whole matrix rows used to be invertible without
    // failing anything.
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs_path = crate_dir.join("../../docs/ITPL.md");
    let docs_text = fs::read_to_string(&docs_path).expect("docs/ITPL.md must be readable");

    let phases: Vec<irontraffic_filter::Phase> = (0..irontraffic_filter::Phase::COUNT)
        .map(|i| {
            let index = u8::try_from(i).expect("COUNT is 10");
            irontraffic_filter::Phase::from_index(index).expect("index is in range")
        })
        .collect();

    let mut header = vec!["attribute".to_owned()];
    header.extend(phases.iter().map(|p| (*p).as_str().to_owned()));
    let header_refs: Vec<&str> = header.iter().map(String::as_str).collect();
    let rows = table_rows(&docs_text, &header_refs);

    assert_eq!(
        rows.len(),
        irontraffic_policy::ATTRS.len(),
        "the availability matrix has {} rows, the schema has {}",
        rows.len(),
        irontraffic_policy::ATTRS.len()
    );

    let mut checked_cells = 0u32;
    for row in &rows {
        assert_eq!(
            row.len(),
            phases.len() + 1,
            "malformed matrix row (wrong number of columns): {row:?}"
        );
        let path = unticked(&row[0]);
        let entry = irontraffic_policy::resolve_path(path.as_bytes())
            .unwrap_or_else(|| panic!("the matrix documents `{path}`, which is not an attribute"));
        let from = match (entry.attr, entry.map) {
            (Some(attr), None) => attr.from_phase(),
            (None, Some(map)) => map.from_phase(),
            _ => panic!("`{path}`: exactly one of attr and map must be set"),
        };

        for (col, phase) in phases.iter().enumerate() {
            let cell = row
                .get(col + 1)
                .unwrap_or_else(|| panic!("`{path}`: missing cell for {}", (*phase).as_str()));
            let published = match cell.as_str() {
                "x" => true,
                "" => false,
                other => panic!("`{path}`: unrecognised matrix cell `{other}`"),
            };
            let actual = phase.index() >= from.index();
            assert_eq!(
                published,
                actual,
                "`{path}` at `{}`: published {}, the schema says {actual}",
                (*phase).as_str(),
                published
            );
            checked_cells += 1;
        }
    }

    // Pinned against a literal, deliberately, not against `rows.len() *
    // phases.len()`: emptying either loop must FAIL this test rather than
    // silently checking nothing.
    assert_eq!(checked_cells, 280, "expected 28 attributes by 10 phases");
}

#[test]
fn docs_carries_the_two_trust_warnings() {
    // Test 28b: substring search, so deleting either warning fails the build
    // rather than quietly shipping.
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs_path = crate_dir.join("../../docs/ITPL.md");
    let docs_text = fs::read_to_string(&docs_path).expect("docs/ITPL.md must be readable");

    assert!(
        docs_text.contains("connection.remote_addr") && docs_text.contains("peer"),
        "docs/ITPL.md must state that connection.remote_addr is the peer, not the client"
    );
    assert!(
        docs_text.contains("constant time")
            && docs_text.contains("api-key-mint-and-constant-time-verify"),
        "docs/ITPL.md must warn that == on strings is not constant time and name \
         api-key-mint-and-constant-time-verify (#351)"
    );
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
