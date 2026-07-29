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
fn docs_attribute_table_is_complete() {
    // Test 28: every AttrId::path() and MapId::path() appears in docs/ITPL.md. This
    // checks the running code against documentation, not documentation against
    // itself: deleting a row from `ATTRS`, or from the doc table, fails this test.
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs_path = crate_dir.join("../../docs/ITPL.md");
    let docs_text = fs::read_to_string(&docs_path).expect("docs/ITPL.md must be readable");

    let all_attr_ids = [
        irontraffic_policy::AttrId::RequestMethod,
        irontraffic_policy::AttrId::RequestPath,
        irontraffic_policy::AttrId::RequestQuery,
        irontraffic_policy::AttrId::RequestScheme,
        irontraffic_policy::AttrId::RequestAuthority,
        irontraffic_policy::AttrId::RequestHost,
        irontraffic_policy::AttrId::RequestPort,
        irontraffic_policy::AttrId::RequestProtocol,
        irontraffic_policy::AttrId::RequestSize,
        irontraffic_policy::AttrId::RequestId,
        irontraffic_policy::AttrId::RequestHeaderCount,
        irontraffic_policy::AttrId::ConnectionRemoteAddr,
        irontraffic_policy::AttrId::ConnectionRemotePort,
        irontraffic_policy::AttrId::ConnectionLocalAddr,
        irontraffic_policy::AttrId::ConnectionTls,
        irontraffic_policy::AttrId::ConnectionSni,
        irontraffic_policy::AttrId::ConnectionAlpn,
        irontraffic_policy::AttrId::ConnectionMtlsVerified,
        irontraffic_policy::AttrId::ConnectionListener,
        irontraffic_policy::AttrId::RouteId,
        irontraffic_policy::AttrId::RouteCluster,
        irontraffic_policy::AttrId::ResponseStatus,
        irontraffic_policy::AttrId::ResponseSize,
        irontraffic_policy::AttrId::StreamId,
        irontraffic_policy::AttrId::StreamDurationMs,
    ];
    assert_eq!(all_attr_ids.len(), irontraffic_policy::AttrId::COUNT);
    for id in all_attr_ids {
        let path = id.path();
        assert!(
            docs_text.contains(path),
            "docs/ITPL.md is missing the attribute path `{path}` ({id:?})"
        );
    }

    let all_map_ids = [
        irontraffic_policy::MapId::RequestHeaders,
        irontraffic_policy::MapId::RequestQuery,
        irontraffic_policy::MapId::ResponseHeaders,
    ];
    for id in all_map_ids {
        let path = id.path();
        assert!(
            docs_text.contains(path),
            "docs/ITPL.md is missing the map path `{path}` ({id:?})"
        );
    }
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
