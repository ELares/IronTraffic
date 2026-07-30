#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Downloads, verifies, and installs an irontraffic release binary with no
# package manager:
#
#   curl -fsSL https://github.com/ELares/IronTraffic/releases/latest/download/install.sh | sh
#
# That shape (`curl | sh`) has failure modes a script run from a file does
# not, and this file is written the way it is entirely because of them. Read
# docs/RELEASE.md and docs/THREAT-MODEL.md's "Installation and release
# artifacts" section for what the checksum verification below does and does
# not prove: it is integrity of the transfer, not authenticity of the
# artifact.
#
# Environment:
#   IT_VERSION      pin a version (e.g. "0.4.1" or "v0.4.1"); default: latest
#   IT_ALLOW_ROOT   "1" to allow running as root (default: refuse)
#   --prefix DIR    install under DIR/bin instead of $HOME/.local/bin
#
# umask is set before anything is written, so the installed binary is 0755
# regardless of the invoking shell's umask: a group-writable binary left on
# PATH is a local privilege-escalation primitive on a shared machine.
umask 022

# The four targets this project ships prebuilt binaries for. Anything else
# is refused by name (edge case 8): never download a mismatched binary.
SUPPORTED_TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl"

# Overridable only for this script's own test suite, which cannot reach the
# real GitHub host: a real invocation never sets this, so it always resolves
# to the one line below.
: "${IT_RELEASE_BASE_URL:=https://github.com/ELares/IronTraffic/releases}"

usage() {
    cat <<'EOF'
usage: install.sh [--prefix DIR]

Downloads, verifies, and installs the irontraffic binary for this machine.

  --prefix DIR   install under DIR/bin instead of $HOME/.local/bin

environment:
  IT_VERSION      pin a version (e.g. "0.4.1"); default: the latest release
  IT_ALLOW_ROOT   set to "1" to allow running as root (default: refuse)
EOF
}

# Every fetch uses `--proto '=https' --tlsv1.2 -fsSL` (or the wget
# equivalent): a redirect to `http://` cannot be followed (a downgrade), and
# a connection cannot negotiate below TLS 1.2, regardless of where a
# redirect (GitHub's own release assets always redirect once, to
# object storage, which IS expected and IS still followed) ends up
# pointing. `-L` alone, with no `--proto` restriction, follows a redirect
# anywhere, including to plain HTTP.
fetch_to_file() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -qO "$dest" "$url"
    else
        echo "error: neither curl nor wget is installed; cannot download anything" >&2
        return 1
    fi
}

# Edge case 8: an unsupported OS/architecture is refused by name, listing
# the four supported targets, and nothing is downloaded.
detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux) : ;;
        *)
            echo "error: unsupported OS \"$os\". Supported targets:" >&2
            for t in $SUPPORTED_TARGETS; do echo "  $t" >&2; done
            return 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *)
            echo "error: unsupported architecture \"$arch\" on Linux. Supported targets:" >&2
            for t in $SUPPORTED_TARGETS; do echo "  $t" >&2; done
            return 1
            ;;
    esac
}

# `ldd` on a fully static musl binary is not something this script decides;
# it always installs the `gnu` (dynamically linked) target for the detected
# architecture, which is the default for most distributions and is what
# `detect_target` returns. A reader who specifically wants the static musl
# artifact downloads it directly; this script's job is the common case.

# Edge case 13c / the interpolated-version hazard: IT_VERSION is
# substituted into a download URL, so it is validated against this pattern
# BEFORE use. Without this check, `IT_VERSION=../../evil` would fetch an
# arbitrary path on the host, and a value containing `://` could leave the
# host entirely.
is_valid_version() {
    printf '%s' "$1" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
}

# Strips an optional leading "v": release tags conventionally carry one
# (`v0.1.0`) and asset filenames never do (`irontraffic-0.1.0-<target>...`,
# built from Cargo's own version field). The TAG in the URL path and the
# FILENAME's embedded version are validated identically but are not
# required to be spelled identically.
strip_v_prefix() {
    printf '%s' "$1" | sed 's/^v//'
}

# Resolves "latest" to a concrete, validated tag. A HEAD request against
# GitHub's own `.../releases/latest` alias 302s to `.../releases/tag/<TAG>`;
# reading the `Location` header this way (rather than blindly following an
# open-ended redirect chain with `-L` and hoping) is what makes the
# resolved value a known, single string this script can validate before it
# is ever interpolated into another URL, exactly like a user-supplied
# IT_VERSION is.
resolve_latest_version() {
    location=""
    if command -v curl >/dev/null 2>&1; then
        location="$(curl --proto '=https' --tlsv1.2 -fsSI "$IT_RELEASE_BASE_URL/latest" 2>/dev/null \
            | tr -d '\r' | grep -i '^location:' | tail -1 | sed 's/^[Ll]ocation:[[:space:]]*//')"
    elif command -v wget >/dev/null 2>&1; then
        location="$(wget --https-only -q --max-redirect=0 "$IT_RELEASE_BASE_URL/latest" 2>&1 \
            | grep -i 'Location:' | tail -1 | sed 's/.*Location:[[:space:]]*//')"
    fi

    if [ -z "$location" ]; then
        echo "error: could not resolve the latest release (no redirect Location found)" >&2
        return 1
    fi

    tag="${location##*/}"
    if ! is_valid_version "$tag"; then
        echo "error: the resolved latest version \"$tag\" does not match the expected" >&2
        echo "  version pattern; refusing to use it in a download URL" >&2
        return 1
    fi
    printf '%s' "$tag"
}

# Edge case 9: neither checker present. Refuses rather than installing
# unverified.
checksum_checker() {
    if command -v sha256sum >/dev/null 2>&1; then
        echo "sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        echo "shasum"
    else
        echo "error: neither sha256sum nor shasum is installed; refusing to install" >&2
        echo "  an unverified binary. Install one of them and try again." >&2
        return 1
    fi
}

verify_checksums() {
    checker="$1"
    dir="$2"
    sums_file="$3"

    # Edge case 14: the platform checker's own verdict is used verbatim
    # rather than parsed by this script; anything other than every line
    # reporting OK is a refusal.
    if [ "$checker" = "sha256sum" ]; then
        ( cd "$dir" && sha256sum -c "$sums_file" )
    else
        ( cd "$dir" && shasum -a 256 -c "$sums_file" )
    fi
}

main() {
    prefix="$HOME/.local"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --prefix)
                [ "$#" -ge 2 ] || { echo "error: --prefix requires a value" >&2; exit 2; }
                prefix="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "error: unrecognised argument \"$1\"" >&2
                usage
                exit 2
                ;;
        esac
    done

    # Edge case 12: a piped shell script running as root is the
    # highest-consequence version of the pattern this file's whole design
    # defends against.
    if [ "$(id -u)" = "0" ] && [ "${IT_ALLOW_ROOT:-0}" != "1" ]; then
        echo "error: refusing to install as root. Set IT_ALLOW_ROOT=1 to override." >&2
        exit 1
    fi

    target="$(detect_target)" || exit 1

    version="${IT_VERSION:-}"
    if [ -z "$version" ]; then
        version="$(resolve_latest_version)" || exit 1
    fi
    if ! is_valid_version "$version"; then
        echo "error: IT_VERSION=\"$version\" does not match the expected version" >&2
        echo "  pattern (e.g. \"0.4.1\" or \"v0.4.1\"); refusing to build a download" >&2
        echo "  URL from it." >&2
        exit 1
    fi
    echo "resolved version: $version"

    checker="$(checksum_checker)" || exit 1

    asset_version="$(strip_v_prefix "$version")"
    asset_name="irontraffic-$asset_version-$target.tar.gz"
    tarball_url="$IT_RELEASE_BASE_URL/download/$version/$asset_name"
    sums_url="$IT_RELEASE_BASE_URL/download/$version/SHA256SUMS"

    # Edge case 4 / 13a: everything from here on lives inside `main`, and
    # `main "$@"` is the LAST line of this file. `sh` executes what it has
    # received so far, so a connection cut mid-download of THIS SCRIPT
    # itself runs a prefix of it: with the body in functions and the call at
    # the very end, a truncated download defines some functions and calls
    # none of them, rather than running "download and extract" without
    # "verify". This is the single most important line in the file.
    work_dir="$(mktemp -d)"
    # staged_path is declared here, empty, so the trap below can reference it
    # unconditionally from the moment it is registered: it is only ever given
    # a real value right before the final install (edge case 15), and the
    # trap removes it on every exit path from that point on, including one
    # interrupted between staging the new binary under $bin_dir and renaming
    # it into place.
    staged_path=""
    trap 'rm -rf "$work_dir"; [ -n "$staged_path" ] && rm -f "$staged_path"' EXIT INT TERM

    echo "downloading $asset_name"
    fetch_to_file "$tarball_url" "$work_dir/$asset_name" || {
        echo "error: download failed: $tarball_url" >&2
        exit 1
    }
    fetch_to_file "$sums_url" "$work_dir/SHA256SUMS" || {
        echo "error: download failed: $sums_url" >&2
        exit 1
    }

    # Only the one line matching this asset is checked: SHA256SUMS lists
    # every target's tarball, and this script has downloaded exactly one of
    # them.
    grep -F "$asset_name" "$work_dir/SHA256SUMS" > "$work_dir/SHA256SUMS.this-asset" || {
        echo "error: $asset_name is not listed in SHA256SUMS" >&2
        exit 1
    }

    if ! verify_checksums "$checker" "$work_dir" "$work_dir/SHA256SUMS.this-asset"; then
        echo "error: checksum verification FAILED for $asset_name. Refusing to install" >&2
        echo "  an artifact that does not match its published checksum." >&2
        exit 1
    fi
    # Edge case 13e, said out loud rather than merely implied by exit code
    # 0: SHA256SUMS comes from the same origin as the tarball, so this
    # proves the transfer was not corrupted and proves nothing about who
    # produced the artifact. Signature verification is added by a later
    # release issue and becomes the default there.
    echo "checksum verified (integrity only; signature verification lands in the next release)"

    extract_dir="$work_dir/extracted"
    mkdir -p "$extract_dir"
    tar -xzf "$work_dir/$asset_name" -C "$extract_dir"

    member_dir="$extract_dir/irontraffic-$asset_version-$target"
    extracted_bin="$member_dir/irontraffic"
    if [ ! -f "$extracted_bin" ]; then
        echo "error: $asset_name did not contain $member_dir/irontraffic" >&2
        exit 1
    fi
    chmod 0755 "$extracted_bin"

    # Runs the freshly extracted binary before it is ever moved into place:
    # a binary that cannot even print its own version is not installed.
    if ! "$extracted_bin" --version >/dev/null 2>&1; then
        echo "error: the downloaded binary failed to run \"--version\"; refusing to install it" >&2
        exit 1
    fi

    bin_dir="$prefix/bin"
    mkdir -p "$bin_dir"
    if [ ! -w "$bin_dir" ]; then
        echo "error: $bin_dir is not writable. Pass --prefix to install somewhere else." >&2
        exit 1
    fi

    installed_path="$bin_dir/irontraffic"
    # Staged under $bin_dir itself, NOT left under $work_dir (a `mktemp -d`
    # under $TMPDIR, which on a typical Linux desktop is tmpfs `/tmp`) before
    # the rename: `mv` is only atomic when its source and destination are on
    # the SAME filesystem, and $bin_dir (e.g. $HOME/.local/bin) is ordinarily
    # on the root filesystem, a different one from tmpfs. A cross-filesystem
    # `mv` silently degrades to copy-then-unlink, which is not atomic and can
    # leave a truncated executable on PATH if interrupted mid-copy, exactly
    # what this design is supposed to make impossible. Staging the copy
    # inside $bin_dir guarantees the final `mv` below renames within one
    # filesystem, so it is a real atomic rename regardless of where $TMPDIR
    # happens to live.
    staged_path="$bin_dir/.irontraffic.tmp.$$"
    if ! cp "$extracted_bin" "$staged_path"; then
        echo "error: failed to stage the new binary under $bin_dir" >&2
        rm -f "$staged_path"
        exit 1
    fi
    # `cp` alone does not guarantee the executable bit survives umask, unlike
    # a rename of the already-`chmod`ed extracted_bin would: chmod again,
    # explicitly, so invariant 11 (0755 regardless of umask) holds for the
    # staged copy too, not just the extracted one.
    chmod 0755 "$staged_path"

    # Edge case 11: an existing binary is kept as `<name>.previous` rather
    # than overwritten outright, so a bad upgrade is one `mv` from recovery.
    # Both `mv`s below are checked: a failed rename here must not be reported
    # as a successful install, unlike the unchecked version of this script
    # that printed "installed:" and exited 0 regardless of whether either
    # `mv` actually succeeded.
    if [ -e "$installed_path" ]; then
        if ! mv -f "$installed_path" "$installed_path.previous"; then
            echo "error: failed to back up the existing $installed_path" >&2
            rm -f "$staged_path"
            exit 1
        fi
    fi
    if ! mv "$staged_path" "$installed_path"; then
        echo "error: failed to move the new binary into place at $installed_path" >&2
        exit 1
    fi

    echo "installed: $installed_path"
    case ":$PATH:" in
        *":$bin_dir:"*) : ;;
        *)
            echo "note: $bin_dir is not on your PATH. Add it with:"
            echo "  export PATH=\"$bin_dir:\$PATH\""
            ;;
    esac
}

main "$@"
