// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::print_stdout,
    reason = "a build script's only channel back to cargo is stdout `cargo:` directives; every print in this file is one of those, never a diagnostic"
)]

//! Derives the six-key `--version --json` build stamp and hands it to
//! `crates/irontraffic/src/main.rs` as compile-time environment variables.
//!
//! # Preference order
//!
//! - `IT_GIT_SHA`: from the environment, else `git rev-parse --short=12 HEAD`,
//!   else the literal `unknown`.
//! - `IT_GIT_DIRTY`: from the environment, else `git status --porcelain`
//!   emptiness, else the literal `true`.
//! - `IT_PROFILE`: from cargo's own `PROFILE` environment variable.
//! - `IT_FEATURES`: the entries of `FEATURES` (`include!`d from
//!   `features.rs`, beside this file) for which
//!   `CARGO_FEATURE_<NAME uppercased, '-' replaced by '_'>` is set, joined
//!   with `,` in manifest order.
//!
//! Environment first is what makes a build from a source tarball with no
//! `.git` directory reproducible: the release recipe
//! (`scripts/release/build.sh`) sets `IT_GIT_SHA` and `IT_GIT_DIRTY`
//! explicitly, so the resulting binary never depends on a `.git` directory
//! being present at build time. Defaulting `dirty` to `true` when nothing is
//! known is the safe direction: unknown provenance is treated as
//! unreleasable, never as clean.
//!
//! `IT_GIT_SHA` taken from the environment is validated (12 lowercase hex
//! characters or the literal `unknown`) because an unvalidated environment
//! variable would land verbatim in a published artifact's version output.
//! `IT_GIT_DIRTY` taken from the environment is validated the same way (the
//! literal `true` or `false`), for the identical reason. Either failing is a
//! build failure naming the variable, not a silent fallback: a value that
//! fails validation is not "unset", it is wrong, and falling back to a
//! default would hide that.
//!
//! `cargo:rerun-if-env-changed` is emitted for `IT_GIT_SHA` and `IT_GIT_DIRTY`
//! and `cargo:rerun-if-changed` for `features.rs`, which is what makes
//! Cargo's own environment-variable-override path (the one the release
//! recipe actually uses) and a feature-list edit reliable. Emitting any
//! `rerun-if-*` at all replaces Cargo's default fingerprint (rerun when a
//! file anywhere in this package changes) with exactly the listed triggers,
//! so the known, accepted trade here is the git-derived path: a purely
//! local, iterative `cargo build` across two commits that touch no file in
//! this package can show a stale commit SHA until something else invalidates
//! the fingerprint (editing a file in the package, or `cargo clean`). That
//! staleness is immaterial to the release recipe this issue actually cares
//! about, because `scripts/release/build.sh` always sets `IT_GIT_SHA` and
//! `IT_GIT_DIRTY` explicitly and `scripts/release/verify-repro.sh` always
//! builds into a wiped target directory, so this script always reruns there
//! regardless.

use std::env;
use std::process::Command; // it-allow: no-blocking-in-async reason: build.rs runs once at compile time, in its own short-lived process, before the async runtime this lint protects exists at all; there is no worker thread here to stall.

include!("features.rs");

fn main() {
    let git_sha = resolve_git_sha();
    let git_dirty = resolve_git_dirty();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned()); // it-allow: no-swallowed-error reason: PROFILE is set by cargo for every build script invocation with no documented failure mode; a missing value here would mean cargo itself changed contract, not a case this build should abort over.
    let features = resolve_features();

    println!("cargo:rustc-env=IT_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=IT_GIT_DIRTY={git_dirty}");
    println!("cargo:rustc-env=IT_PROFILE={profile}");
    println!("cargo:rustc-env=IT_FEATURES={features}");

    println!("cargo:rerun-if-env-changed=IT_GIT_SHA");
    println!("cargo:rerun-if-env-changed=IT_GIT_DIRTY");
    println!("cargo:rerun-if-changed=features.rs");
}

/// Twelve lowercase hex characters, or the literal `unknown`.
fn is_valid_git_sha(candidate: &str) -> bool {
    candidate == "unknown"
        || (candidate.len() == 12
            && candidate
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// `IT_GIT_SHA` from the environment (validated), else `git rev-parse
/// --short=12 HEAD` (validated the same way, since a corrupt or unusual repo
/// could hand back something that is not 12 hex characters), else
/// `"unknown"`.
fn resolve_git_sha() -> String {
    if let Ok(from_env) = env::var("IT_GIT_SHA") {
        if !is_valid_git_sha(&from_env) {
            fail_with(&format!(
                "IT_GIT_SHA={from_env:?} is not 12 lowercase hex characters or the literal \"unknown\""
            ));
        }
        return from_env;
    }

    if let Some(output) = run_git(&["rev-parse", "--short=12", "HEAD"]) {
        let candidate = output.trim();
        if is_valid_git_sha(candidate) {
            return candidate.to_owned();
        }
    }

    "unknown".to_owned()
}

/// `IT_GIT_DIRTY` from the environment (validated as exactly `true` or
/// `false`), else `git status --porcelain` emptiness, else `"true"`: unknown
/// provenance is treated as unreleasable, the safe direction.
fn resolve_git_dirty() -> String {
    if let Ok(from_env) = env::var("IT_GIT_DIRTY") {
        if from_env != "true" && from_env != "false" {
            fail_with(&format!(
                "IT_GIT_DIRTY={from_env:?} is not the literal \"true\" or \"false\""
            ));
        }
        return from_env;
    }

    match run_git(&["status", "--porcelain"]) {
        Some(output) => {
            if output.trim().is_empty() {
                "false".to_owned()
            } else {
                "true".to_owned()
            }
        }
        None => "true".to_owned(),
    }
}

/// The enabled entries of `FEATURES`, in manifest order, joined with `,`.
/// Empty (not absent) when none are enabled, so `IT_FEATURES=` is a valid,
/// meaningful value rather than a missing variable.
fn resolve_features() -> String {
    FEATURES
        .iter()
        .filter(|name| {
            let var = format!("CARGO_FEATURE_{}", name.to_uppercase().replace('-', "_"));
            env::var(var).is_ok()
        })
        .copied()
        .collect::<Vec<&str>>()
        .join(",")
}

/// Runs `git <args>` from the crate root (Cargo sets the build script's
/// working directory there) and returns trimmed stdout on success, or `None`
/// if `git` is not installed, this is not a repository, or the command
/// otherwise failed. `None` is a normal, expected outcome (a source tarball
/// has no `.git` directory) and is never itself a build failure; only a
/// validated-and-wrong environment variable is.
fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?; // it-allow: no-blocking-in-async reason: same as the import above; build.rs has no async runtime to block.
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// Fails the build, naming the offending variable. Not a `panic!`: this
/// crate's lints deny `panic`, `unwrap_used`, and `expect_used` uniformly
/// across every target including this build script, and a build script's
/// contract with Cargo is a nonzero exit and a message on stderr, which
/// `panic!` also produces but with an unrelated backtrace and location that
/// only obscures the actual problem.
fn fail_with(message: &str) -> ! {
    #[allow(
        clippy::print_stderr,
        reason = "a build script has no telemetry seam; stderr is cargo's own documented channel for a build script failure message"
    )]
    {
        eprintln!("error: {message}");
    }
    std::process::exit(1);
}
