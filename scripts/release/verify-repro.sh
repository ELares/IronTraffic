#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Builds one target TWICE, from two different absolute paths, and asserts
# the resulting binaries are byte for byte identical. Reproducibility is a
# checked property here, not an intention: a verification that builds twice
# in the SAME directory would prove almost nothing about
# --remap-path-prefix, so this script always copies the tree to a second,
# different absolute path before the second build.
#
# Usage: scripts/release/verify-repro.sh <target>
#
# The three usual causes of a mismatch, in order, are a path leak, a
# toolchain difference, and a sampled timestamp; this script checks the
# toolchain difference itself (comparing `rustc -vV` between the two builds)
# and prints diagnostics aimed at the other two on a mismatch.
set -eu

usage() {
    echo "usage: scripts/release/verify-repro.sh <target>" >&2
}

main() {
    if [ "$#" -ne 1 ]; then
        usage
        exit 2
    fi
    target="$1"

    repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT INT TERM

    copy_a="$work/copy-a/src"
    copy_b="$work/copy-b/src"
    out_dir="$work/out"
    mkdir -p "$copy_a" "$copy_b" "$out_dir/a" "$out_dir/b"

    # A real copy of the tracked tree at a DIFFERENT absolute path, including
    # `.git`, so `git`-derived values (SOURCE_DATE_EPOCH, IT_GIT_SHA, the
    # dirty check) come out the SAME at both copies, the way they would for
    # two independent checkouts of the identical commit. `target/` and any
    # existing `dist/` are excluded: they are this script's own or a
    # previous run's build output, never an input.
    ( cd "$repo_root" && tar --exclude='./target' --exclude='./dist' -cf - . ) \
        | ( cd "$copy_a" && tar -xf - )
    ( cd "$repo_root" && tar --exclude='./target' --exclude='./dist' -cf - . ) \
        | ( cd "$copy_b" && tar -xf - )

    echo "== build A: $copy_a =="
    ( cd "$copy_a" && sh scripts/release/build.sh "$target" )
    cp "$copy_a/target/$target/release/irontraffic" "$out_dir/a/irontraffic"
    rustc_a="$( (cd "$copy_a" && rustc -vV) )"

    # Wipe copy_a's own target directory now that its binary has been copied
    # out: build B runs in copy_b, its own independent checkout with its own
    # target directory, so this cannot affect build B's inputs at all (copy_b
    # was never built into yet). It exists so this script does not leave a
    # multi-gigabyte target directory behind for copy_a once that build is no
    # longer needed, not to make build B "cannot pass by reusing" anything.
    rm -rf "$copy_a/target"

    echo "== build B: $copy_b (a DIFFERENT absolute path) =="
    ( cd "$copy_b" && sh scripts/release/build.sh "$target" )
    cp "$copy_b/target/$target/release/irontraffic" "$out_dir/b/irontraffic"
    rustc_b="$( (cd "$copy_b" && rustc -vV) )"

    if [ "$rustc_a" != "$rustc_b" ]; then
        echo "FAIL: the two builds used different toolchains (rustc -vV differs)," >&2
        echo "  which is the second most common cause of a reproducibility mismatch," >&2
        echo "  after a path leak. rust-toolchain.toml pins an exact version for" >&2
        echo "  exactly this reason; something bypassed it." >&2
        echo "--- build A: rustc -vV ---" >&2
        echo "$rustc_a" >&2
        echo "--- build B: rustc -vV ---" >&2
        echo "$rustc_b" >&2
        exit 1
    fi

    digest_a="$(sha256_of "$out_dir/a/irontraffic")"
    digest_b="$(sha256_of "$out_dir/b/irontraffic")"

    echo "toolchain: $(echo "$rustc_a" | head -1)"
    echo "build A digest: $digest_a"
    echo "build B digest: $digest_b"

    if [ "$digest_a" = "$digest_b" ]; then
        echo "reproducible: ok ($target)"
        return 0
    fi

    echo "FAIL: $target is NOT reproducible. Two builds of the identical commit," >&2
    echo "  at two different absolute paths, produced different bytes." >&2
    echo >&2
    echo "-- first 32 differing bytes (cmp -l) --" >&2
    cmp -l "$out_dir/a/irontraffic" "$out_dir/b/irontraffic" 2>/dev/null | head -32 >&2 || true
    echo >&2
    if command -v readelf >/dev/null 2>&1; then
        echo "-- build A .comment section --" >&2
        readelf --string-dump=.comment "$out_dir/a/irontraffic" >&2 || true
        echo "-- build B .comment section --" >&2
        readelf --string-dump=.comment "$out_dir/b/irontraffic" >&2 || true
    else
        echo "(readelf not available on this machine; skipping the .comment dump." >&2
        echo " It is present on the Ubuntu CI runner this script also runs on.)" >&2
    fi
    exit 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

main "$@"
