#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Generates a CycloneDX 1.6 software bill of materials for one release
# artifact, from the exact locked dependency graph that artifact's build
# actually resolves. See docs/SUPPLY-CHAIN.md and docs/RELEASE.md.
#
# Usage: scripts/release/sbom.sh <target> <features> [output-file]
#   target        a Rust target triple, e.g. x86_64-unknown-linux-musl
#   features      a comma-separated feature list, activated with
#                 --no-default-features so the SBOM always describes an
#                 EXPLICIT feature set rather than whatever "default" happens
#                 to mean; the real release recipe's default build is
#                 therefore always spelled out here too (see build.sh /
#                 docs/RELEASE.md's "What this table does not yet say").
#   output-file   defaults to stdout
#
# WHY THE FEATURE FLAGS BELONG ON THE cargo metadata INVOCATION, not applied
# after the fact: they change the resolve. Filtering an already-resolved,
# default-features dependency list cannot remove a crate that only the
# default features pulled in in the first place; the closure below is
# computed from a metadata run scoped to exactly this artifact's own build.
#
# WHY THE CLOSURE IS RESTRICTED, not the raw `cargo metadata` package list:
# `cargo metadata` reports every workspace dependency, including the
# dev-dependencies of the root package and of every OTHER workspace member.
# `--filter-platform` narrows the platform, never the dependency kind, so the
# closure below is walked from the built package's own resolve node,
# following only edges whose `dep_kinds` include `normal` or `build`, never
# `dev`. Shipping dev-only dependencies (this workspace's own `proptest`, for
# one) in a released artifact's SBOM overstates its content.
#
# WHAT IT_SBOM_ROOT_PACKAGE IS AND WHY IT IS AN ENVIRONMENT VARIABLE, NOT A
# THIRD POSITIONAL ARGUMENT: every real invocation (this repository's own
# sign.sh, attest.sh, .github/workflows/ci.yml) builds the irontraffic binary
# and never sets this, so the CLI real users and real CI ever see is exactly
# the two-argument form above. crates/irontraffic does not yet depend on
# crates/irontraffic-tls at all (see docs/RELEASE.md's "What this table does
# not yet say"), so no feature string passed here can make the
# vendored-crypto-provider overlay below apply to the actual release binary
# today; scripts/release/supply-chain-selftest.sh sets this variable to
# irontraffic-tls, a workspace member whose three crypto-* features
# genuinely do select between aws-lc-rs and ring today, so the
# closure-restriction and vendored-library mechanisms are exercised against a
# real dependency graph rather than an invented one. The mechanism does not
# change when a future issue wires TLS into irontraffic itself; only the
# real <features> argument does.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

usage() {
    cat <<'EOF' >&2
usage: scripts/release/sbom.sh <target> <features> [output-file]

  target       a Rust target triple, e.g. x86_64-unknown-linux-musl
  features     comma-separated feature list (activated with
               --no-default-features)
  output-file  defaults to stdout
EOF
}

preflight() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "error: jq is required to generate a CycloneDX SBOM (cargo metadata's" >&2
        echo "  JSON is turned into CycloneDX JSON with jq; this issue adds no Rust" >&2
        echo "  code to do it instead). Install: https://jqlang.org/download/" >&2
        echo "  (e.g. 'apt-get install jq' or 'brew install jq')." >&2
        exit 1
    fi
    if ! command -v iconv >/dev/null 2>&1; then
        echo "error: iconv is required to validate crate metadata as UTF-8 (edge" >&2
        echo "  case: a non-UTF-8 licence or description field). Install: it ships" >&2
        echo "  with glibc on Linux and with macOS by default." >&2
        exit 1
    fi
}

# Mirrors build.sh's own fallback: a fixed wrong timestamp (the Unix epoch)
# is still reproducible; a sampled one (the wall clock) is not. Two SBOMs of
# the same artifact must be byte-identical (invariant 1), so this must derive
# the same way build.sh derives it, from the same commit, not be sampled here.
source_date_epoch() {
    if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
        printf '%s' "$SOURCE_DATE_EPOCH"
        return 0
    fi
    epoch="$(git log -1 --pretty=%ct 2>/dev/null || true)"
    if [ -n "$epoch" ]; then
        printf '%s' "$epoch"
    else
        printf '0'
    fi
}

# A one-line rustc identification string, recorded in metadata.properties so
# a reader can tell which compiler produced the artifact this SBOM describes,
# without embedding the full multi-line `rustc -vV` block.
rustc_version_line() {
    rustc -vV 2>/dev/null | head -1 || echo "unknown"
}

# ---------------------------------------------------------------------------
# Shared jq definitions, held as shell variables rather than duplicated in
# every jq invocation below (there are four: the closure-name listing, the
# two vendored-overlay component builders, and the final document build).
# ---------------------------------------------------------------------------

# Walks resolve.nodes from one root id, following only edges whose
# `dep_kinds` include `normal` (kind == null) or `build`, never `dev`, with
# an explicit visited set so a diamond-shaped graph (almost every graph of
# this size) is walked once per node rather than reprocessed once per
# incoming path.
JQ_CLOSURE='
  def dep_index:
    [ .resolve.nodes[]
      | { key: .id,
          value: [ .deps[]
                   | select(.dep_kinds | any(.kind == null or .kind == "build"))
                   | .pkg ]
        }
    ] | from_entries;

  def closure_ids(root_id; idx):
    { visited: ({} | .[root_id] = true), frontier: [root_id] }
    | until(.frontier | length == 0;
        . as $state
        | ( $state.frontier | map(idx[.] // []) | add // [] | unique) as $candidates
        | ($candidates - ($state.visited | keys)) as $new
        | { visited: ($state.visited + ($new | map({(.): true}) | add // {})), frontier: $new }
      )
    | .visited | keys;
'

# A minority of crates (14, as of this writing, in this workspace's own
# closure: bitflags, fnv, siphasher, walkdir and others) still declare the
# pre-SPDX-expression Cargo convention "MIT/Apache-2.0" rather than
# "MIT OR Apache-2.0". The issue this script implements names only OR, AND
# and parentheses as the lexical split points; "/" is a real, necessary
# fourth one, found by validating real output against the committed
# CycloneDX schema (a bare "/"-joined string is not a valid single SPDX
# licence id, which the schema rejects, and sbom-licence-check.sh applies
# the identical normalisation for the same reason). Treating "/" as OR is
# the safe direction the same edge case already argues for: every legacy
# slash in this ecosystem separates alternatives, never a conjunction, and a
# crate offering EITHER licence still needs every alternative allowlisted.
JQ_LICENSES='
  def normalize_license_expr($lic): $lic | gsub("/"; " OR ");

  def licenses_of($lic):
    if $lic == null or $lic == "" then []
    else
      (normalize_license_expr($lic)) as $norm
      | if ($norm | test(" OR | AND ")) then [ { expression: $norm } ]
        else [ { license: { id: $norm } } ]
        end
    end;
'

# Finds a package's own extracted source directory from cargo metadata's
# `manifest_path` (the directory Cargo actually fetched or vendored it into,
# whether the registry cache or a `[patch]`/path override), rather than
# guessing the registry cache's own directory layout, which is not a stable
# public interface.
manifest_dir_of() {
    meta_file="$1"
    crate_name="$2"
    jq -r --arg name "$crate_name" \
        '[.packages[] | select(.name == $name)] | first | .manifest_path | if . then (. | sub("/Cargo\\.toml$"; "")) else empty end' \
        "$meta_file"
}

license_of_crate() {
    meta_file="$1"
    crate_name="$2"
    jq -r --arg name "$crate_name" '[.packages[] | select(.name == $name)] | first | .license // ""' "$meta_file"
}

# The vendored-C-library overlay (Design, step 4). A Rust-only SBOM for a
# binary containing aws-lc or zstd is wrong in the way that matters most to a
# vulnerability scanner, which tracks CVEs against the UPSTREAM C project's
# own version, not the wrapping `*-sys` crate's independent crates.io
# version. Emits one CycloneDX component per vendored library actually
# present in the closure, using a `pkg:generic/` purl (there is no `cargo`
# purl for a C project that never ships on crates.io under its own name) and
# reusing the wrapping crate's own `license` field, which cargo already reads
# from its Cargo.toml and which correctly reflects the vendored source's
# mixed licensing (verified against aws-lc-sys 0.43.0: cargo metadata reports
# "ISC AND (Apache-2.0 OR ISC) AND ...", every disjunct of which is on this
# project's allowlist).
vendored_overlay() {
    meta_file="$1"
    closure_names_file="$2"
    overlay="[]"

    for sys_crate in aws-lc-sys aws-lc-fips-sys; do
        if ! grep -qxF "$sys_crate" "$closure_names_file"; then
            continue
        fi
        src_dir="$(manifest_dir_of "$meta_file" "$sys_crate")"
        header="$src_dir/aws-lc/include/openssl/base.h"
        if [ ! -f "$header" ]; then
            echo "warning: $sys_crate is in the closure but $header was not found;" >&2
            echo "  omitting the vendored aws-lc overlay component. This means the" >&2
            echo "  vendored library's own layout changed since this script was written." >&2
            continue
        fi
        awslc_version="$(grep -oE 'AWSLC_VERSION_NUMBER_STRING "[0-9]+\.[0-9]+\.[0-9]+"' "$header" \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
        if [ -z "$awslc_version" ]; then
            echo "warning: could not read AWSLC_VERSION_NUMBER_STRING from $header;" >&2
            echo "  omitting the vendored aws-lc overlay component." >&2
            continue
        fi
        lic="$(license_of_crate "$meta_file" "$sys_crate")"
        overlay="$(printf '%s' "$overlay" | jq -c --arg v "$awslc_version" --arg lic "$lic" --arg via "$sys_crate" \
            "$JQ_LICENSES"'
            . + [{type: "library", name: "aws-lc", version: $v,
                    purl: ("pkg:generic/aws-lc@" + $v),
                    licenses: licenses_of($lic),
                    description: ("vendored C library bundled via " + $via)}]')"
        # Only one aws-lc overlay entry regardless of how many *-sys crates
        # vendoring it are in the closure (aws-lc-sys and aws-lc-fips-sys
        # never appear together: deny.toml's crypto-fips exception is
        # scoped to a feature the default build never enables).
        break
    done

    if grep -qxF "zstd-sys" "$closure_names_file"; then
        zstd_version_field="$(jq -r '[.packages[] | select(.name == "zstd-sys")] | first | .version' "$meta_file")"
        # zstd-sys's own crates.io version carries the vendored library's
        # version as SemVer build metadata (e.g. "2.0.16+zstd.1.5.7"),
        # verified against every published zstd-sys release as of this
        # writing. If a future release drops that convention, the split
        # below finds no "+zstd." marker and the overlay is omitted rather
        # than emitting a fabricated version.
        case "$zstd_version_field" in
            *+zstd.*)
                zstd_version="${zstd_version_field##*+zstd.}"
                lic="$(license_of_crate "$meta_file" "zstd-sys")"
                overlay="$(printf '%s' "$overlay" | jq -c --arg v "$zstd_version" --arg lic "$lic" \
                    "$JQ_LICENSES"'
                    . + [{type: "library", name: "zstd", version: $v,
                            purl: ("pkg:generic/zstd@" + $v),
                            licenses: licenses_of($lic),
                            description: "vendored C library bundled via zstd-sys"}]')"
                ;;
            *)
                echo "warning: zstd-sys $zstd_version_field carries no '+zstd.X.Y.Z' build" >&2
                echo "  metadata; omitting the vendored zstd overlay component." >&2
                ;;
        esac
    fi

    printf '%s' "$overlay"
}

# Rejects a field that is not valid UTF-8 (edge case 13). `cargo metadata`'s
# own output is JSON, which is UTF-8 by construction, so a real invocation of
# this script cannot reach this branch; it exists as defence in depth against
# a hand-edited or corrupted intermediate file, and is exercised directly
# (not through a real `cargo metadata` run) in
# scripts/release/supply-chain-selftest.sh.
assert_field_is_utf8() {
    field_name="$1"
    crate_name="$2"
    value="$3"
    if ! printf '%s' "$value" | iconv -f UTF-8 -t UTF-8 >/dev/null 2>&1; then
        echo "error: $crate_name's $field_name is not valid UTF-8; refusing to emit an" >&2
        echo "  SBOM that would silently mangle it." >&2
        exit 1
    fi
}

main() {
    if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
        usage
        exit 2
    fi
    preflight

    target="$1"
    features="$2"
    out="${3:-}"
    root_package="${IT_SBOM_ROOT_PACKAGE:-irontraffic}"

    epoch="$(source_date_epoch)"
    rustc_ver="$(rustc_version_line)"

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT INT TERM
    doc_file="$work/bom.json"

    meta_file="$work/metadata.json"
    cargo metadata --locked --format-version 1 --filter-platform "$target" \
        --no-default-features --features "$features" > "$meta_file"

    # A 16 MiB cap on the raw cargo metadata document, the same cap edge case
    # 12 puts on the emitted SBOM, applied here too before any per-field
    # check below runs over it.
    meta_size="$(wc -c < "$meta_file" | tr -d ' ')"
    if [ "$meta_size" -gt 16777216 ]; then
        echo "error: cargo metadata output is ${meta_size} bytes, over the 16 MiB cap." >&2
        exit 1
    fi

    # Compute the closure once, as a plain newline-separated, sorted name
    # list, both for the vendored-overlay lookup and for the per-field UTF-8
    # check below, rather than re-walking the graph twice.
    closure_names_file="$work/closure-names.txt"
    jq -r --arg root_name "$root_package" \
        "$JQ_CLOSURE"'
      . as $meta
      | ($meta | dep_index) as $idx
      | ($meta.packages | map(select(.name == $root_name)) | first) as $root_pkg
      | if $root_pkg == null then
          "error: no package named \($root_name) in cargo metadata output" | halt_error(1)
        else . end
      | ($meta.packages | map({(.id): .}) | add) as $by_id
      | (closure_ids($root_pkg.id; $idx)) as $ids
      | ($ids | map($by_id[.].name)) | sort[]
    ' "$meta_file" > "$closure_names_file"

    while IFS= read -r crate_name; do
        [ -n "$crate_name" ] || continue
        lic="$(license_of_crate "$meta_file" "$crate_name")"
        desc="$(jq -r --arg name "$crate_name" '[.packages[] | select(.name == $name)] | first | .description // ""' "$meta_file")"
        assert_field_is_utf8 "license" "$crate_name" "$lic"
        assert_field_is_utf8 "description" "$crate_name" "$desc"
    done < "$closure_names_file"

    overlay="$(vendored_overlay "$meta_file" "$closure_names_file")"

    jq --arg root_name "$root_package" \
       --arg target "$target" \
       --arg features "$features" \
       --arg rustc_ver "$rustc_ver" \
       --arg epoch "$epoch" \
       --argjson overlay "$overlay" \
       "$JQ_CLOSURE$JQ_LICENSES"'
      def purl_of($name; $version): "pkg:cargo/\($name)@\($version)";

      def ext_refs_of($repo):
        if $repo == null or $repo == "" then {}
        else { externalReferences: [ { type: "vcs", url: $repo } ] }
        end;

      . as $meta
      | ($meta | dep_index) as $idx
      | ($meta.packages | map(select(.name == $root_name)) | first) as $root_pkg
      | (closure_ids($root_pkg.id; $idx) | unique | sort) as $ids
      | ($meta.packages | map({(.id): .}) | add) as $by_id
      | ($ids | map($by_id[.])) as $members
      | {
          "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
          bomFormat: "CycloneDX",
          specVersion: "1.6",
          version: 1,
          metadata: {
            timestamp: ($epoch | tonumber | todateiso8601),
            component: {
              type: "application",
              name: $root_pkg.name,
              version: $root_pkg.version,
              purl: purl_of($root_pkg.name; $root_pkg.version)
            },
            properties: [
              { name: "irontraffic:target", value: $target },
              { name: "irontraffic:features", value: $features },
              { name: "irontraffic:rustc_version", value: $rustc_ver },
              { name: "irontraffic:source_date_epoch", value: ($epoch | tostring) }
            ]
          },
          components: (
            (
              [ $members[]
                | select(.name != $root_pkg.name)
                | { type: "library", name: .name, version: .version, purl: purl_of(.name; .version) }
                  + { licenses: licenses_of(.license) }
                  + ext_refs_of(.repository)
              ]
              + $overlay
            )
            | sort_by(.purl)
          )
        }
    ' "$meta_file" > "$doc_file"

    if [ -n "$out" ]; then
        cp "$doc_file" "$out"
    else
        cat "$doc_file"
    fi
}

main "$@"
