// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The canonical feature-name list for this crate, declared exactly once so
// `build.rs` and `tests/version.rs` cannot drift from each other or from
// `Cargo.toml`.
//
// This file is `include!`d, never `mod`-declared: `build.rs` does
// `include!("features.rs")` and `tests/version.rs` does
// `include!("../features.rs")`. It sits at the crate root, beside `build.rs`
// and `Cargo.toml`, rather than under `src/`, precisely so both of those
// relative paths resolve. A `mod features;` declared from `lib.rs` would put
// this behind the library target's own module tree, which `build.rs` (a
// wholly separate, free standing binary Cargo compiles on its own) cannot
// see at all.
//
// Reversing `CARGO_FEATURE_<NAME>` back into a feature name is ambiguous: a
// feature name containing an underscore and one containing a hyphen produce
// the identical environment variable, because Cargo uppercases the name and
// replaces both separators with `_`. The forward direction has no such
// collision, so this list is the single source of truth and `build.rs` only
// ever tests `CARGO_FEATURE_<NAME>` for a name already known here; it never
// enumerates `CARGO_FEATURE_*` and maps backwards.

/// Every feature declared in this crate's `Cargo.toml` `[features]` table, in
/// manifest order (excluding the `default` key itself, which names other
/// features rather than being one), spelled exactly as it is there.
///
/// `tests/version.rs` parses `Cargo.toml` at test time and fails if this list
/// and that table ever disagree, in either direction: a feature added to
/// `Cargo.toml` and not here, or a name kept here after its feature was
/// removed there.
const FEATURES: [&str; 2] = ["control-plane", "dataplane"];
