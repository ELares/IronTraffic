#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Drives scripts/release/build.sh across the four shipped targets and
# assembles a tarball and a SHA256SUMS manifest for each. See docs/RELEASE.md
# for the target matrix and docs/THREAT-MODEL.md for what the checksum does
# and does not prove.
#
# Usage: scripts/release/build-matrix.sh [output-directory]
#   output-directory defaults to dist/ at the repository root.
#
# Every retry is idempotent: re-running overwrites this run's own output,
# per edge case 16.
set -eu

TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl"

# Assembles one target's tarball with a fixed member order (sorted), fixed
# ownership (0/0), fixed permissions (0755 for the binary, 0644 for
# everything else), and SOURCE_DATE_EPOCH as every member's mtime, including
# the gzip container's own timestamp header, which is a second, easily
# missed place a build timestamp leaks: `tar czf` alone lets gzip stamp the
# wall clock into the `.gz` header even when every tar member's own mtime is
# fixed. Written in Python rather than shelled out to `tar`, because `tar`'s
# owner/mtime/sort flags are not portably spelled the same way across GNU
# tar (the CI runner) and other implementations, and this way the exact same
# code produces the exact same member metadata regardless of which `tar`
# happens to be installed.
assemble_tarball() {
    stage_dir="$1"
    member_name="$2"
    tarball_path="$3"
    epoch="$4"

    python3 - "$stage_dir" "$member_name" "$tarball_path" "$epoch" <<'PYEOF'
import gzip
import os
import sys
import tarfile

stage_dir, member_name, tarball_path, epoch = sys.argv[1:5]
epoch = int(epoch)
member_root = os.path.join(stage_dir, member_name)

paths = []
for dirpath, dirnames, filenames in os.walk(member_root):
    dirnames.sort()
    for filename in sorted(filenames):
        paths.append(os.path.relpath(os.path.join(dirpath, filename), stage_dir))
paths.sort()

def fixed_info(tarinfo):
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = ""
    tarinfo.gname = ""
    tarinfo.mtime = epoch
    is_binary = tarinfo.name == os.path.join(member_name, "irontraffic")
    tarinfo.mode = 0o755 if is_binary else 0o644
    return tarinfo

# mtime set explicitly on the GzipFile itself: without it, gzip stamps the
# wall clock into the .gz header's own timestamp field even though every
# member inside the tar stream carries the fixed epoch above. filename=""
# is equally deliberate and was NOT in the first version of this script: left
# unset, GzipFile derives the embedded FNAME field from fileobj.name (the
# output path), so a tarball built as out.tar.gz and an identical one built
# as out2.tar.gz (or into a differently named output directory) compressed
# to DIFFERENT bytes even though the underlying tar member content was
# proven byte-identical, which is the exact class of leak (an incidental
# path turning up inside a build artifact) this whole issue exists to close,
# just one layer further out than --remap-path-prefix reaches. An empty
# filename is falsy to gzip's own header writer, which omits the FNAME
# field entirely rather than writing a zero-length one.
with open(tarball_path, "wb") as raw:
    with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as gz:
        with tarfile.open(fileobj=gz, mode="w|") as tar:
            for path in paths:
                tar.add(
                    os.path.join(stage_dir, path),
                    arcname=path,
                    recursive=False,
                    filter=fixed_info,
                )
PYEOF
}

main() {
    repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
    cd "$repo_root"

    out_dir="${1:-$repo_root/dist}"
    mkdir -p "$out_dir"

    version="$(cargo metadata --no-deps --format-version=1 | python3 -c '
import json, sys
meta = json.load(sys.stdin)
for pkg in meta["packages"]:
    if pkg["name"] == "irontraffic":
        print(pkg["version"])
        sys.exit(0)
sys.exit("irontraffic package not found in cargo metadata")
')"

    epoch="$(git log -1 --pretty=%ct 2>/dev/null || echo 0)"

    checksums_file="$out_dir/SHA256SUMS"
    : > "$checksums_file"

    for target in $TARGETS; do
        echo "== building $target =="
        sh "$repo_root/scripts/release/build.sh" "$target"

        name="irontraffic-$version-$target"
        stage_dir="$(mktemp -d)"
        member_dir="$stage_dir/$name"
        mkdir -p "$member_dir/docs"
        cp "$repo_root/target/$target/release/irontraffic" "$member_dir/irontraffic"
        cp "$repo_root/LICENSE" "$member_dir/LICENSE"
        cp "$repo_root/README.md" "$member_dir/README.md"
        cp "$repo_root/docs/QUICKSTART.md" "$member_dir/docs/QUICKSTART.md"

        tarball_path="$out_dir/$name.tar.gz"
        assemble_tarball "$stage_dir" "$name" "$tarball_path" "$epoch"
        rm -rf "$stage_dir"

        ( cd "$out_dir" && sha256sum "$(basename "$tarball_path")" >> "SHA256SUMS" )
        echo "wrote $tarball_path"
    done

    echo "wrote $checksums_file"
    ( cd "$out_dir" && sha256sum -c SHA256SUMS )
}

main "$@"
