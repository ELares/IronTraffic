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
#   deny-toml        when omitted, tried in order: beside THIS script (the
#                     documented standalone layout, once deny.toml is
#                     published as a release asset; see #788), then at the
#                     repository root (a checkout, including the tag-only
#                     CI step below); if NEITHER exists, this exits 3, a
#                     distinct "no allowlist to check against" SKIP, never
#                     a licence-violation FAILURE (#788: a missing
#                     allowlist says nothing about the SBOM it was supposed
#                     to be checked against, and must never be reported
#                     with wording that blames the artifact)
#   exceptions-file  same two-tier default as deny-toml; when a deny_file
#                     was found (by either means) but no exceptions_file
#                     exists by DEFAULT anywhere this script knows to
#                     look, that ALSO exits 3 as the same honest SKIP
#                     (#791: deny.toml alone is not enough, and checking
#                     against an incomplete allowlist would falsely accuse
#                     a component that only passes via a committed
#                     exception). An EXPLICIT, missing exceptions_file
#                     argument is the one case that stays non-fatal (see
#                     main(), below): a caller who named a path themselves
#                     is treated as deliberately opting out of exceptions,
#                     not as "nothing was published here"
#
# Exit codes: 0 pass, 1 a real check ran and found a violation (or a real
# misconfiguration, e.g. an explicit path that does not exist), 2 bad
# usage, 3 no allowlist was found to check against (#788, widened by #791
# to cover deny.toml-found-but-no-exceptions-file), 4 an allowlist WAS
# found and applied but the SBOM itself declares zero components, so there
# is nothing in it to check (#791 NOTE). 3 and 4 are both honest SKIPs,
# never a licence-violation FAILURE, but are kept distinct because they
# name different facts: 3 means this script found no allowlist, 4 means it
# found one and had nothing to point it at.
#
# Splitting is purely lexical (edge case 2): split on the words OR and AND,
# on parentheses, and on "/" (see sbom.sh's own comment on the same
# normalisation: a real, necessary fourth split point this workspace's own
# dependency tree demonstrates, e.g. "MIT/Apache-2.0"), trim, and require
# every resulting token to be in the allowlist unless the component's purl
# (unversioned) has a committed exception with a written reason.
set -eu

# SCRIPT_DIR is where this script itself lives. docs/SUPPLY-CHAIN.md
# section 3's documented standalone flow curls verify.sh,
# sbom-licence-check.sh, deny.toml and licence-exceptions.txt into ONE flat
# directory beside the tarball and its SBOM (no repository checkout
# anywhere on the machine), so a deny.toml living next to THIS script is
# checked FIRST, below.
#
# REPO_ROOT is a second, fallback default only: two directories above this
# script, which is where deny.toml actually lives in a checkout, including
# the tag-only step in ci.yml that runs this script against dist/*.sbom.json
# from inside one. Neither of these `cd`s the running process; both are
# used only to build candidate default file PATHS below. This script is
# invoked by verify.sh's `--sbom` path with an <sbom-file> argument that may
# be relative to the CALLER's working directory, and a `cd` here, same as
# verify.sh's own former bug, would resolve that relative sbom_file against
# the WRONG directory once this script's own `$0` is not sitting inside a
# repository checkout.
#
# A previous version of this comment argued the REPO_ROOT-derived defaults
# were safe because they are "already absolute". That reasoning was
# backwards, and is exactly what issue #788 was filed over: being absolute
# is what made `$REPO_ROOT/deny.toml` resolve, confidently and silently, to
# a real path TWO LEVELS ABOVE wherever this script was actually downloaded
# to when run standalone, outside a checkout, rather than failing loudly.
# Absolute was never what made it correct; the two-tier lookup above, and
# the honest SKIP (never a FAIL) when even that finds nothing, are what fix
# it.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

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
    deny_file="${2:-}"
    exceptions_file="${3:-}"

    if [ ! -f "$sbom_file" ]; then
        echo "error: no such SBOM file: $sbom_file" >&2
        exit 1
    fi

    # Two-tier default, only when the caller did not name one explicitly
    # (an explicit, missing deny_file below is still a hard error: that is
    # a real misconfiguration, not "no allowlist was ever published here").
    if [ -z "$deny_file" ]; then
        if [ -f "$SCRIPT_DIR/deny.toml" ]; then
            deny_file="$SCRIPT_DIR/deny.toml"
        elif [ -f "$REPO_ROOT/deny.toml" ]; then
            deny_file="$REPO_ROOT/deny.toml"
        fi
    fi
    # #791: this two-tier default used to assign the REPO_ROOT-derived
    # fallback UNCONDITIONALLY, with no [ -f ] test, the exact "two
    # directories above me is the repository" assumption #788 was filed
    # over and fixed for deny_file above but never carried over here. An
    # explicit, missing exceptions_file argument is still deliberately
    # left for main()'s own [ -f "$exceptions_file" ] check below to treat
    # as "no exceptions" rather than a hard error (see this function's own
    # usage comment, above): only the DEFAULT lookup gets the guard, so a
    # still-empty $exceptions_file here means neither candidate exists,
    # not merely that one was checked and rejected.
    if [ -z "$exceptions_file" ]; then
        if [ -f "$SCRIPT_DIR/licence-exceptions.txt" ]; then
            exceptions_file="$SCRIPT_DIR/licence-exceptions.txt"
        elif [ -f "$REPO_ROOT/scripts/release/licence-exceptions.txt" ]; then
            exceptions_file="$REPO_ROOT/scripts/release/licence-exceptions.txt"
        fi
    fi

    if [ -z "$deny_file" ]; then
        # #788: no allowlist anywhere this script knows to look. This is an
        # HONEST SKIP, not a failure -- a missing deny.toml says nothing
        # about the SBOM or the artifact it describes. The former behaviour
        # here (falling through to the "no such deny.toml" error below,
        # against a path nobody outside a checkout could ever have
        # populated) is exactly what turned a perfectly good standalone
        # artifact into "FAILED: sbom licence: not a subset of the
        # allowlist", a false tamper alarm from the security tool itself.
        # Exit code 3 is this script's own distinct SKIPPED signal (2 is
        # already "bad usage", 1 is "a real check ran and failed");
        # verify.sh's --sbom step reads it and reports a named skip, never
        # a FAILED line, so a --allow-skipped run still succeeds and a
        # strict run still surfaces it by name rather than silently passing.
        echo "skipped: sbom-licence-check: no deny.toml found beside this script" >&2
        echo "  ($SCRIPT_DIR) or at the repository root ($REPO_ROOT); nothing to" >&2
        echo "  check the SBOM's licences against. See docs/SUPPLY-CHAIN.md section 3" >&2
        echo "  for how to fetch deny.toml alongside this script." >&2
        exit 3
    fi
    if [ ! -f "$deny_file" ]; then
        # Only reachable with an EXPLICIT, missing deny_file argument: the
        # two-tier default above already confirmed each candidate it set
        # exists before assigning it, so a still-empty $deny_file already
        # exited 3 above, and a still-missing FILE here can only mean
        # whoever called this script named a path themselves. A real
        # misconfiguration, not the "nothing published" case above.
        echo "error: no such deny.toml: $deny_file" >&2
        exit 1
    fi

    if [ -z "$exceptions_file" ]; then
        # #791: deny.toml WAS found (both checks above already returned or
        # exited otherwise) but no licence-exceptions.txt anywhere this
        # script knows to look by default, either beside this script or at
        # the repository root. This PR's own body already says the two
        # files "are also necessary together, not deny.toml alone" (#788),
        # and the three committed exceptions are "load bearing for the
        # real closure to pass at all": proceeding past this point with an
        # EMPTY exception set would silently accuse a genuinely compliant
        # component that only passes via a committed exception (e.g.
        # aho-corasick, memchr, ryu; see docs/SUPPLY-CHAIN.md section 7) of
        # a licence violation, by name. That is strictly WORSE than
        # finding no deny.toml at all, so it gets the identical honest
        # SKIP, and the identical exit code 3, rather than a FAILURE that
        # blames the artifact for this script's own incomplete allowlist.
        echo "skipped: sbom-licence-check: deny.toml was found, but no" >&2
        echo "  licence-exceptions.txt beside this script ($SCRIPT_DIR) or at the" >&2
        echo "  repository root ($REPO_ROOT/scripts/release); deny.toml alone is not" >&2
        echo "  enough to check the SBOM's licences against without risking a false" >&2
        echo "  accusation against a component that only passes via a committed" >&2
        echo "  exception. See docs/SUPPLY-CHAIN.md section 3 for how to fetch" >&2
        echo "  licence-exceptions.txt alongside deny.toml." >&2
        exit 3
    fi

    # #791 SHOULD_FIX: name which allowlist was actually applied. Both
    # deny_file and exceptions_file are resolved via a two-tier lookup
    # (beside this script, then the repository root) that a shadowed or
    # substituted file elsewhere on the machine could silently win over
    # the real one; before this line, neither a passing nor a failing run
    # ever printed a path, so that substitution was invisible in the one
    # screen a user reads. Printed to STDOUT (verify.sh's --sbom step
    # captures this script's combined stdout+stderr and echoes it back on
    # a pass), not merely a code comment.
    echo "applied: deny.toml=$deny_file, licence-exceptions.txt=$exceptions_file"

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

    # #791 NOTE: a component-less SBOM (an empty `.components` array, e.g.
    # a truncated download or a malformed generator run) used to fall
    # straight through the loop below with total=0, failed=0, and print
    # "0/0 components pass" followed by a genuine exit 0 -- a security
    # tool reading an EMPTY input as a PASS, indistinguishable from a real
    # SBOM that was actually checked. This is deliberately its OWN exit
    # code (4), distinct from exit 3's "no allowlist to check against":
    # here an allowlist WAS found and applied (see the "applied:" line
    # above), there is simply nothing in THIS SBOM to check it against,
    # which is a different fact and would be misreported by exit 3's own
    # "no deny.toml allowlist or licence-exceptions.txt found" wording.
    if [ ! -s "$components_file" ]; then
        echo "skipped: sbom-licence-check: $sbom_file declares zero components;" >&2
        echo "  nothing to check its licence set against. If this artifact" >&2
        echo "  genuinely has no dependencies, that is itself worth confirming" >&2
        echo "  by hand, not by this check's silent, vacuous success." >&2
        exit 4
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
