// SPDX-License-Identifier: MIT OR Apache-2.0
//! Emits the `IT_GIT_SHA` and `IT_GIT_DIRTY` compile-time constants that
//! `main.rs` `include!`s to build the `--version --json` `BuildStamp` object.
//!
//! Shells out to `git rev-parse --short HEAD` and `git status --porcelain`.
//! Either command missing, failing, or this not being a git checkout at all
//! (a vendored or offline source tree) falls back to `"unknown"` and `true`
//! rather than failing the build: a benchmark fixture must still compile with
//! no network and no `.git` directory present.
//!
//! No `cargo:rerun-if-changed` directive is emitted, so Cargo falls back to
//! its default: rerun this script whenever any file in this package changes.
//! That already reruns it on every ordinary edit-and-rebuild cycle; the one
//! case it misses is a commit made elsewhere in the repository advancing
//! `HEAD` with no file in this crate touched, in which case the stamped SHA
//! can lag by one commit until this crate is next touched. That is an
//! acceptable staleness window for a diagnostic field, not a correctness
//! requirement, so it is not worth tracking `.git/HEAD` (which is a symlink
//! or a `gitdir:` pointer file, not a fixed path, under a worktree checkout
//! like this one).

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command; // it-allow: no-blocking-in-async reason: build.rs is a synchronous, non-async build-time script; there is no async runtime here to stall, and shelling out to git is exactly how a compile-time commit stamp is meant to be read

/// The short commit hash `HEAD` points at, or `"unknown"` when `git` is
/// unavailable, this is not a repository, or the command otherwise fails.
fn git_short_sha() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|sha| sha.trim().to_owned())
        .filter(|sha| !sha.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Whether the working tree has uncommitted changes. Defaults to `true`
/// (dirty) when `git` is unavailable: an unknown state is reported as dirty
/// rather than silently claiming a clean build that was never verified.
fn git_is_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_none_or(|output| !output.stdout.is_empty())
}

fn main() -> Result<(), Box<dyn Error>> {
    let sha = git_short_sha();
    let dirty = git_is_dirty();

    let out_dir = env::var("OUT_DIR")?;
    let dest = Path::new(&out_dir).join("it_origin_git.rs");
    let generated =
        format!("const IT_GIT_SHA: &str = {sha:?};\nconst IT_GIT_DIRTY: bool = {dirty};\n");
    fs::write(dest, generated)?;

    Ok(())
}
