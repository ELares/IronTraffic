#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Asserts a CycloneDX SBOM's licence set is a subset of deny.toml's
# allowlist. This is a SECOND, independent check over the same allowlist
# `cargo deny check` already gates the build with, not a redundant one: one
# gates the build, one describes the artifact, and a divergence between them
# (this check reads deny.toml itself, never a copy of its list) is a finding
# in its own right, per this issue's own "Do NOT" section.
#
# Usage: scripts/release/sbom-licence-check.sh <sbom-file> [deny-toml] [exceptions-file]
#   deny-toml        defaults to deny.toml at the repository root
#   exceptions-file  defaults to scripts/release/licence-exceptions.txt
#
# Splitting is purely lexical (edge case 2): split on the words OR and AND,
# on parentheses, and on "/" (see sbom.sh's own comment on the same
# normalisation: a real, necessary fourth split point this workspace's own
# dependency tree demonstrates, e.g. "MIT/Apache-2.0"), trim, and require
# every resulting token to be in the allowlist unless the component's purl
# (unversioned) has a committed exception with a written reason.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

usage() {
    cat <<'EOF' >&2
usage: scripts/release/sbom-licence-check.sh <sbom-file> [deny-toml] [exceptions-file]
EOF
}

preflight() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "error: jq is required to read a CycloneDX SBOM's component list." >&2
        echo "  Install: https://jqlang.org/download/ (e.g. 'apt-get install jq')." >&2
        exit 1
    fi
}

# See deny.toml's own [licenses] allow = [ ... ] array. Purely lexical: a
# quoted string per line between "allow = [" and the closing "]", inside the
# [licenses] table. deny.toml is TOML, not JSON, so this reads it directly
# rather than inventing a TOML parser or a second, driftable copy of the
# list.
extract_allowlist() {
    deny_file="$1"
    awk '
        /^\[licenses\]/ { in_section = 1; next }
        /^\[/ { in_section = 0 }
        in_section && /^allow[[:space:]]*=[[:space:]]*\[/ { in_list = 1; next }
        in_list && /^\]/ { in_list = 0; next }
        in_list {
            line = $0
            gsub(/^[[:space:]]*"/, "", line)
            gsub(/",?[[:space:]]*$/, "", line)
            if (line != "") print line
        }
    ' "$deny_file"
}

# Reads the exceptions file into two parallel, newline-separated files under
# $work: one of unversioned purls, one of their reasons (same line number in
# both). Fails naming the line number if a reason is missing or under 20
# characters (edge case 2's own stated minimum).
load_exceptions() {
    exceptions_file="$1"
    purls_out="$2"
    reasons_out="$3"
    : > "$purls_out"
    : > "$reasons_out"
    line_no=0
    while IFS= read -r raw_line || [ -n "$raw_line" ]; do
        line_no=$((line_no + 1))
        case "$raw_line" in
            ''|'#'*) continue ;;
        esac
        purl="$(printf '%s' "$raw_line" | cut -f1)"
        reason="$(printf '%s' "$raw_line" | cut -f2-)"
        if [ "$purl" = "$reason" ]; then
            # `cut -f2-` on a line with no tab at all returns the WHOLE
            # line unchanged rather than empty, which would otherwise let a
            # tab-less line slip through with its full text
            # misinterpreted as a purl AND a reason simultaneously.
            reason=""
        fi
        if [ -z "$purl" ] || [ -z "$reason" ]; then
            echo "error: $exceptions_file line $line_no is not '<purl><TAB><reason>'" >&2
            exit 1
        fi
        reason_len=$(printf '%s' "$reason" | wc -c | tr -d ' ')
        if [ "$reason_len" -lt 20 ]; then
            echo "error: $exceptions_file line $line_no's reason is $reason_len characters," >&2
            echo "  under the required 20: \"$reason\"" >&2
            exit 1
        fi
        printf '%s\n' "$purl" >> "$purls_out"
        printf '%s\n' "$reason" >> "$reasons_out"
    done < "$exceptions_file"
}

has_exception() {
    unversioned_purl="$1"
    purls_file="$2"
    grep -qxF "$unversioned_purl" "$purls_file"
}

# "MIT/Apache-2.0" -> "MIT OR Apache-2.0" (see sbom.sh's identical
# normalisation and comment; kept in agreement deliberately, since a
# licence string that reads as compound to one script and atomic to the
# other would make the SBOM and this check disagree about the same crate).
normalize_expr() {
    printf '%s' "$1" | sed 's,/, OR ,g'
}

# Splits a (already slash-normalised) SPDX-ish expression on the words OR
# and AND and on parentheses, trims, drops empties. No SPDX expression
# evaluator: this is intentionally lexical, per edge case 2.
#
# The split points become NEWLINES, never a bare space: a naive
# `tr ' ' '\n'` after blanking out "OR"/"AND" would also cut a multi-word
# licence identifier like "Apache-2.0 WITH LLVM-exception" (itself one of
# deny.toml's own allowlist entries, verbatim) into three separate,
# individually-unallowlisted tokens ("Apache-2.0", "WITH",
# "LLVM-exception"), turning an allowed licence into a false failure. Found
# by running this check against this workspace's own real SBOM: `rustix`
# and `linux-raw-sys` both declare
# "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT", and only replacing
# the exact " OR "/" AND " separators (never a lone space) keeps "WITH" and
# the identifier it belongs to on the same token.
disjuncts_of() {
    expr="$1"
    printf '%s' "$expr" \
        | sed -E 's/\(/\n/g; s/\)/\n/g; s/ OR /\n/g; s/ AND /\n/g' \
        | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
        | grep -v '^$' || true
}

main() {
    if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
        usage
        exit 2
    fi
    preflight

    sbom_file="$1"
    deny_file="${2:-$REPO_ROOT/deny.toml}"
    exceptions_file="${3:-$REPO_ROOT/scripts/release/licence-exceptions.txt}"

    if [ ! -f "$sbom_file" ]; then
        echo "error: no such SBOM file: $sbom_file" >&2
        exit 1
    fi
    if [ ! -f "$deny_file" ]; then
        echo "error: no such deny.toml: $deny_file" >&2
        exit 1
    fi

    # Edge case 12, applied here too: a licence check that parses an
    # over-large document before this cap would be exactly the unbounded
    # work the cap on sbom.sh's own output exists to prevent.
    sbom_size="$(wc -c < "$sbom_file" | tr -d ' ')"
    if [ "$sbom_size" -gt 16777216 ]; then
        echo "error: $sbom_file is ${sbom_size} bytes, over the 16 MiB cap." >&2
        exit 1
    fi

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT INT TERM

    allow_file="$work/allow.txt"
    extract_allowlist "$deny_file" > "$allow_file"
    if [ ! -s "$allow_file" ]; then
        echo "error: found no [licenses] allow = [ ... ] entries in $deny_file;" >&2
        echo "  refusing to check against an empty allowlist." >&2
        exit 1
    fi

    exc_purls="$work/exc-purls.txt"
    exc_reasons="$work/exc-reasons.txt"
    if [ -f "$exceptions_file" ]; then
        load_exceptions "$exceptions_file" "$exc_purls" "$exc_reasons"
    else
        : > "$exc_purls"
        : > "$exc_reasons"
    fi

    components_file="$work/components.ndjson"
    if ! jq -c '.components[]' "$sbom_file" > "$components_file" 2>"$work/jq.err"; then
        echo "error: could not parse $sbom_file as a CycloneDX document:" >&2
        cat "$work/jq.err" >&2
        exit 1
    fi

    total=0
    failed=0
    while IFS= read -r component_json; do
        total=$((total + 1))
        name="$(printf '%s' "$component_json" | jq -r '.name')"
        purl="$(printf '%s' "$component_json" | jq -r '.purl // ""')"
        unversioned_purl="${purl%@*}"
        licenses_len="$(printf '%s' "$component_json" | jq '.licenses | length')"

        if [ "$licenses_len" -eq 0 ]; then
            echo "FAIL: $name ($purl) declares no licence" >&2
            failed=$((failed + 1))
            continue
        fi

        # Reassemble the expression this component actually carries: either
        # a single `{expression: "..."}` entry, or one-or-more
        # `{license: {id: "..."}}` entries joined with AND (CycloneDX's own
        # reading of a multi-entry licenses array: every listed licence
        # applies).
        expr="$(printf '%s' "$component_json" | jq -r '
            if (.licenses[0] | has("expression")) then .licenses[0].expression
            else [.licenses[] | .license.id] | join(" AND ")
            end
        ')"

        # Read disjuncts_of's output one LINE at a time, never
        # `for x in $(...)`: unquoted word-splitting uses $IFS (space,
        # tab, newline), which would re-cut a multi-word token like
        # "Apache-2.0 WITH LLVM-exception" right back into pieces after
        # disjuncts_of took care to keep it on one line.
        bad_tokens=""
        while IFS= read -r token; do
            [ -n "$token" ] || continue
            if ! grep -qxF "$token" "$allow_file"; then
                bad_tokens="$bad_tokens|$token"
            fi
        done <<TOKENS
$(disjuncts_of "$(normalize_expr "$expr")")
TOKENS

        if [ -z "$bad_tokens" ]; then
            continue
        fi

        if has_exception "$unversioned_purl" "$exc_purls"; then
            continue
        fi

        echo "FAIL: $name ($purl): licence \"$expr\" has disjunct(s) not on the" >&2
        echo "  allowlist and no exception in $exceptions_file:$bad_tokens" >&2
        failed=$((failed + 1))
    done < "$components_file"

    echo "sbom-licence-check: $((total - failed))/$total components pass"
    if [ "$failed" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
