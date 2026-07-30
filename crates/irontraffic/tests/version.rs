// SPDX-License-Identifier: MIT OR Apache-2.0
//! Two tests: the `--version --json` shape (the Public API contract in
//! `src/main.rs`), and the `FEATURES`-against-`[features]` freshness check
//! from the release issue's edge case on ambiguous feature-name reversal.

use std::process::Command;

// Beside `build.rs`, not under `src/`, so this relative path and
// `build.rs`'s own `include!("features.rs")` both resolve. See the doc
// comment on `features.rs` itself.
include!("../features.rs");

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_irontraffic"))
}

#[test]
fn version_json_is_the_exact_six_key_sorted_object() {
    let output = bin()
        .arg("--version")
        .arg("--json")
        .output()
        .expect("the irontraffic binary starts");
    assert_eq!(output.status.code(), Some(0));

    // These are read from the SAME build-script-produced environment
    // `src/main.rs` reads, so this is an oracle for whether
    // `print_version_json` faithfully SERIALIZES the baked-in stamp (correct
    // key set, correct quoting, correct placement), not a re-derivation of
    // what the stamp's own VALUE should be. The independent, non-tautological
    // check on the value itself is `git_sha_has_a_valid_shape` below.
    let git_sha = env!("IT_GIT_SHA");
    let dirty = env!("IT_GIT_DIRTY") == "true";
    let profile = env!("IT_PROFILE");
    let mut features: Vec<&str> = env!("IT_FEATURES")
        .split(',')
        .filter(|feature| !feature.is_empty())
        .collect();
    features.sort_unstable();

    let features_json = features
        .iter()
        .map(|feature| format!("\"{feature}\""))
        .collect::<Vec<_>>()
        .join(",");

    // Six keys, alphabetically sorted (dirty, features, git_sha, name,
    // profile, version), exactly one trailing newline: pinned against a
    // literal template rather than reconstructed field by field, so a key
    // dropped, renamed, or reordered by `print_version_json` fails this
    // assertion even though every individual field's VALUE would still be
    // present somewhere in the output.
    let expected = format!(
        "{{\"dirty\":{dirty},\"features\":[{features_json}],\"git_sha\":\"{git_sha}\",\"name\":\"irontraffic\",\"profile\":\"{profile}\",\"version\":\"{}\"}}\n",
        env!("CARGO_PKG_VERSION"),
    );

    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        expected
    );
}

#[test]
fn git_sha_has_a_valid_shape() {
    // Independent of `print_version_json`'s serialization: this checks the
    // VALUE `build.rs` produced, not whether `main.rs` copied it faithfully.
    // Twelve lowercase hex characters, or the literal `unknown`; never
    // anything else, per edge case 1 (no `.git` directory) and the
    // environment-variable validation in `build.rs`.
    let git_sha = env!("IT_GIT_SHA");
    let is_valid = git_sha == "unknown"
        || (git_sha.len() == 12
            && git_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert!(
        is_valid,
        "IT_GIT_SHA={git_sha:?} is neither 12 lowercase hex characters nor \"unknown\""
    );
}

#[test]
fn plain_version_flag_is_unaffected_by_the_json_interception() {
    // `main.rs` intercepts the exact pair `--version --json` ahead of
    // `cli::run`; a bare `--version` must still take `cli::run`'s existing
    // path and print its existing single-line form (already covered for the
    // flag's own behavior by `tests/cli_basics.rs`; this test exists only to
    // pin that the NEW interception in `main.rs` does not widen and swallow
    // this case too).
    let output = bin()
        .arg("--version")
        .output()
        .expect("the irontraffic binary starts");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        format!("irontraffic {}\n", env!("CARGO_PKG_VERSION")).into_bytes()
    );
}

#[test]
fn features_const_matches_the_cargo_toml_features_table() {
    let manifest = include_str!("../Cargo.toml");
    let declared = parse_feature_names(manifest);

    // Fixture precondition: a manifest with an empty or absent `[features]`
    // table would make the equality assertion below pass trivially against
    // an equally empty `FEATURES`, proving nothing about whether the parser
    // or the freshness check actually work. `crates/irontraffic/Cargo.toml`
    // declares `control-plane` and `dataplane` as of this file, so this
    // fixture precondition is real, not aspirational.
    assert!(
        !declared.is_empty(),
        "fixture precondition failed: crates/irontraffic/Cargo.toml's [features] \
         table must declare at least one feature (besides `default`) for this test \
         to exercise the freshness check at all"
    );

    assert_eq!(
        declared,
        FEATURES.to_vec(),
        "crates/irontraffic/features.rs's FEATURES must list exactly the \
         [features] table entries in crates/irontraffic/Cargo.toml (excluding \
         `default`, which names other features rather than being one), in the \
         same order. Update features.rs when Cargo.toml's [features] table \
         changes."
    );
}

/// Extracts the feature names declared in `manifest`'s `[features]` table, in
/// the order they appear, excluding the `default` key.
///
/// Deliberately not a general TOML parser: it recognizes exactly the shape
/// every `[features]` table in this workspace uses (one `name = ...` per
/// line), which is enough to keep this file and `features.rs` from drifting
/// without adding a TOML-parsing dependency to a crate the Files table of
/// the release issue does not authorize adding one to.
fn parse_feature_names(manifest: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut in_features = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(section) = trimmed.strip_prefix('[') {
            in_features = section.trim_end_matches(']') == "features";
            continue;
        }
        if !in_features || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, _value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key != "default" {
            names.push(key);
        }
    }
    names
}
