#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The deterministic release build recipe for one target. See docs/RELEASE.md.
#
# Usage: scripts/release/build.sh <target>
#
# Sets exactly the environment the reproducibility recipe needs and nothing
# else, then runs one `cargo build --locked --release`. Every source of
# nondeterminism this controls is named in docs/RELEASE.md; this script is
# the one place that actually sets them, so a local build and a CI build
# take the identical path.
#
# Refuses to run on a dirty worktree unless IT_ALLOW_DIRTY=1, because a
# release built from uncommitted changes cannot be reproduced by anyone
# checking out the tagged commit. Set IT_ALLOW_DIRTY=1 for a local
# experiment; the result is stamped dirty: true, which every downstream
# consumer (scripts/release/build-matrix.sh, scripts/install.sh) treats as
# unreleasable.
set -eu

usage() {
    cat <<'EOF' >&2
usage: scripts/release/build.sh <target>

  targets:
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
    x86_64-unknown-linux-musl
    aarch64-unknown-linux-musl

  environment:
    IT_ALLOW_DIRTY=1   build from a dirty worktree anyway (stamps dirty: true)
EOF
}

# Runs `git <args>` and prints trimmed stdout on success, nothing on any
# failure (git absent, not a repository, or a nonzero exit). Never aborts the
# script: every caller treats "nothing printed" as "unknown", the same
# fallback crates/irontraffic/build.rs itself falls back to when it derives
# these values directly (a source tarball with no environment override and
# no .git directory).
git_or_nothing() {
    git "$@" 2>/dev/null || true
}

main() {
    if [ "$#" -ne 1 ]; then
        usage
        exit 2
    fi
    target="$1"

    repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
    cd "$repo_root"

    # "Unknown" is treated as dirty (the safe direction), never as clean: a
    # `git status` that fails to run at all (git absent) tells us nothing,
    # and nothing is not the same as "no changes".
    status_output="$(git_or_nothing status --porcelain)"
    if git status --porcelain >/dev/null 2>&1; then
        if [ -n "$status_output" ]; then
            dirty=true
        else
            dirty=false
        fi
    else
        dirty=true
    fi

    if [ "$dirty" = "true" ] && [ "${IT_ALLOW_DIRTY:-0}" != "1" ]; then
        echo "error: the worktree is dirty (or its status could not be determined)." >&2
        echo "  A release build from a dirty tree cannot be reproduced from the tagged" >&2
        echo "  commit alone. Set IT_ALLOW_DIRTY=1 to build anyway; the result is" >&2
        echo "  stamped dirty: true, which every downstream consumer treats as" >&2
        echo "  unreleasable." >&2
        exit 1
    fi

    # Edge case 3: SOURCE_DATE_EPOCH unset because git is unavailable (no
    # .git directory, or no git binary). A fixed wrong timestamp (0, the Unix
    # epoch) is still reproducible; a sampled one (the wall clock) is not, so
    # 0 is the correct fallback, not an error.
    commit_epoch="$(git_or_nothing log -1 --pretty=%ct)"
    if [ -n "$commit_epoch" ]; then
        SOURCE_DATE_EPOCH="$commit_epoch"
    else
        echo "warning: git is unavailable; SOURCE_DATE_EPOCH falls back to 0" >&2
        echo "  (the Unix epoch), a fixed value, not the commit date." >&2
        SOURCE_DATE_EPOCH=0
    fi
    export SOURCE_DATE_EPOCH

    # Left UNSET on failure, deliberately, rather than defaulted to
    # "unknown" here: crates/irontraffic/build.rs applies the identical
    # git-rev-parse-then-unknown fallback itself, and setting it to a
    # specific value here would just be this script re-deriving what
    # build.rs already derives, with two places to keep in agreement instead
    # of one.
    sha="$(git_or_nothing rev-parse --short=12 HEAD)"
    if [ -n "$sha" ]; then
        IT_GIT_SHA="$sha"
        export IT_GIT_SHA
    fi

    IT_GIT_DIRTY="$dirty"
    export IT_GIT_DIRTY

    export CARGO_PROFILE_RELEASE_DEBUG=0
    export CARGO_PROFILE_RELEASE_STRIP=symbols
    export CARGO_PROFILE_RELEASE_LTO=thin
    export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
    # ${CARGO_HOME:-$HOME/.cargo}, not $CARGO_HOME: this script runs under
    # `set -eu`, and CARGO_HOME is frequently unset on a developer machine,
    # where an unset variable would abort the build with a message about the
    # wrong thing.
    export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"

    echo "building irontraffic for $target"
    echo "  dirty:             $IT_GIT_DIRTY"
    echo "  git_sha:           ${IT_GIT_SHA:-<unset, build.rs falls back to \"unknown\">}"
    echo "  source_date_epoch: $SOURCE_DATE_EPOCH"
    cargo build --locked --release --target "$target" -p irontraffic
    echo "built: target/$target/release/irontraffic"
}

main "$@"
