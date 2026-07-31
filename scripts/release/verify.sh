#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The user-facing verification: a user runs this to check a downloaded
# release artifact with no account and no trust in this project beyond a
# public transparency log. See docs/SUPPLY-CHAIN.md.
#
# Usage: scripts/release/verify.sh --artifact <file> [--sbom <file>]
#            [--strict] [--allow-skipped]
#
#   --artifact FILE   the downloaded tarball to check (required)
#   --sbom FILE       also verify this SBOM's signature and licence subset
#   --strict          additionally require the provenance's commit be
#                     reachable from a release tag, and fail on a dirty
#                     artifact; scripts/install.sh always passes this
#   --allow-skipped   the explicit downgrade: a check that could not be
#                     performed (typically, no network) is printed and
#                     counted, but does not turn the exit code nonzero
#
# THE ONE FAIL-OPEN IN THIS DESIGN, AND WHY IT IS THE OPPOSITE OF FAIL-OPEN:
# this script exits NONZERO whenever a check it was asked to perform could
# not be performed (no network, missing signature file, and so on), unless
# --allow-skipped was passed. The obvious shape, "verify what you can,
# report the rest as skipped, exit 0", is wrong here: the party best placed
# to serve a modified artifact is usually also placed to make the
# transparency log unreachable, so "the log was unreachable, continuing"
# hands them exactly the outcome they wanted. --allow-skipped exists for a
# genuinely air-gapped user who has only the checksum; it prints one named
# line per skipped check so that user still sees exactly what was not
# checked, rather than a bare "ok".
set -eu

# The directory verify.sh itself lives in: this script is a release asset a
# user downloads standalone (see docs/SUPPLY-CHAIN.md), with no repository
# checkout around it, and sbom-licence-check.sh below is looked up next to
# THIS file for exactly that reason.
#
# THIS SCRIPT DOES NOT chdir ANYWHERE. It used to `cd` to a computed
# "repository root" two directories above itself
# (`$(dirname "$0")/../..`), which is correct only when the script still
# sits inside a checkout at scripts/release/verify.sh. Run the way
# docs/SUPPLY-CHAIN.md documents standalone use ("curl the script beside the
# tarball, then `sh verify.sh --artifact <tarball>`"), `dirname "$0"` is
# `.`, so that computed root landed TWO LEVELS ABOVE the download directory,
# and a relative `--artifact` (or `--sbom`) path no longer resolved from
# there: "error: no such file: irontraffic-<version>-<target>.tar.gz" even
# though the file was sitting right next to this script. Nothing else in
# this file needs a changed working directory; every path this script reads
# is either $SCRIPT_DIR-relative (sbom-licence-check.sh) or taken from
# --artifact/--sbom/SHA256SUMS exactly as the caller's own shell resolves
# them, which is only correct if this script leaves that resolution alone.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Overridable only for this script's own test suite, which cannot reach the
# real GitHub host, mirroring scripts/install.sh's identical IT_RELEASE_BASE_URL
# seam: a real invocation never sets this.
: "${IT_RELEASE_BASE_URL:=https://github.com/ELares/IronTraffic/releases}"

CERT_IDENTITY_REGEXP='^https://github\.com/ELares/IronTraffic/\.github/workflows/ci\.yml@refs/tags/v'
CERT_OIDC_ISSUER='https://token.actions.githubusercontent.com'

usage() {
    cat <<'EOF' >&2
usage: scripts/release/verify.sh --artifact FILE [--sbom FILE] [--strict] [--allow-skipped]
EOF
}

preflight() {
    missing=0
    if ! command -v cosign >/dev/null 2>&1; then
        echo "error: cosign is required to verify a signature or an attestation." >&2
        echo "  Install: https://docs.sigstore.dev/cosign/system_config/installation/" >&2
        missing=1
    fi
    if ! command -v jq >/dev/null 2>&1; then
        echo "error: jq is required to read the provenance attestation and, with" >&2
        echo "  --sbom, the SBOM's licence set. Install: https://jqlang.org/download/" >&2
        missing=1
    fi
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        echo "error: neither sha256sum nor shasum is installed; refusing to verify" >&2
        echo "  an artifact whose checksum cannot even be checked." >&2
        missing=1
    fi
    if [ "$missing" -ne 0 ]; then
        exit 1
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Same transport rule as scripts/install.sh, applied to every fetch this
# script makes too (edge case 7b): a redirect cannot downgrade to plaintext
# or leave the release host.
fetch_to_file() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 60 -o "$dest" "$url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -q -O "$dest" "$url" 2>/dev/null
    else
        return 1
    fi
}

# Finds a companion file (SHA256SUMS, <artifact>.bundle,
# <artifact>.intoto.bundle) next to the artifact locally first, then falls
# back to downloading it from the same release the artifact's own filename
# names, mirroring scripts/install.sh's URL construction.
locate_or_fetch() {
    local_candidate="$1"
    remote_name="$2"
    dest="$3"
    version="$4"
    if [ -f "$local_candidate" ]; then
        cp "$local_candidate" "$dest"
        return 0
    fi
    url="$IT_RELEASE_BASE_URL/download/v$version/$remote_name"
    fetch_to_file "$url" "$dest"
}

main() {
    artifact=""
    sbom=""
    strict=0
    allow_skipped=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --artifact)
                [ "$#" -ge 2 ] || { echo "error: --artifact requires a value" >&2; exit 2; }
                artifact="$2"; shift 2 ;;
            --sbom)
                [ "$#" -ge 2 ] || { echo "error: --sbom requires a value" >&2; exit 2; }
                sbom="$2"; shift 2 ;;
            --strict) strict=1; shift ;;
            --allow-skipped) allow_skipped=1; shift ;;
            --help|-h) usage; exit 0 ;;
            *) echo "error: unrecognised argument \"$1\"" >&2; usage; exit 2 ;;
        esac
    done

    if [ -z "$artifact" ]; then
        usage
        exit 2
    fi
    if [ ! -f "$artifact" ]; then
        echo "error: no such file: $artifact" >&2
        exit 1
    fi

    preflight

    # Edge case 12: a malformed or oversized companion file is refused
    # before it is parsed at all.
    max_bytes=16777216

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT INT TERM

    checked=0
    skipped=0
    failed=0
    skip_lines=""
    fail_lines=""

    note_skip() {
        skipped=$((skipped + 1))
        skip_lines="$skip_lines
  skipped: $1 ($2)"
        echo "skipped: $1 ($2)"
    }
    note_fail() {
        failed=$((failed + 1))
        fail_lines="$fail_lines
  FAILED: $1"
        echo "FAILED: $1" >&2
    }

    artifact_basename="$(basename "$artifact")"
    # irontraffic-<version>-<target>.tar.gz. The version is between the
    # first and the (target-triple-starting) second hyphen group; mirrors
    # scripts/install.sh's own construction of this same filename in
    # reverse, so both derive identically from the one Cargo version stamp.
    #
    # The optional prerelease group is anchored to require the FOLLOWING
    # hyphen segment to start a known target triple (x86_64 or aarch64),
    # not merely "the next `-<word>` after the version". Without that
    # anchor, `[0-9A-Za-z.]+` (needed for a real prerelease like "rc.1")
    # also matches "aarch64" itself, and the greedy optional group consumes
    # it: "irontraffic-0.1.0-aarch64-unknown-linux-gnu.tar.gz" parsed as
    # version "0.1.0-aarch64" (confirmed with BSD sed, GNU sed and Python
    # `re`, so this is not an engine quirk). x86_64 escaped only because
    # `_` is not in that character class; aarch64 has no such accident.
    # Every downstream URL is built from this value, so a wrong version
    # 404s and silently skips signature and provenance on both aarch64
    # targets, half the shipped matrix.
    version="$(printf '%s' "$artifact_basename" | sed -E 's/^irontraffic-([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?)-(x86_64|aarch64)-.*/\1/')"
    # Everything after "irontraffic-<version>-" and before the ".tar.gz"
    # suffix, e.g. "x86_64-unknown-linux-musl". Plain parameter expansion,
    # not another sed pattern: $version is inserted as a glob pattern here,
    # and a version string ("0.1.0", "0.1.0-rc.1") contains none of glob's
    # metacharacters, so this is exact and needs no escaping. Used below to
    # bind a --sbom argument to the artifact it claims to describe
    # (invariant 8's other half): without this, an SBOM built for a
    # DIFFERENT target still passes every other check in this script.
    target_from_artifact="${artifact_basename#irontraffic-"$version"-}"
    target_from_artifact="${target_from_artifact%.tar.gz}"

    # -------------------------------------------------------------------
    # 1. Checksum. Fails LOUDLY and before anything else runs (test:
    #    verify_fails_on_tampered_artifact asserts this ordering directly).
    # -------------------------------------------------------------------
    sums_file="$work/SHA256SUMS"
    sums_dir="$(dirname "$artifact")"
    if locate_or_fetch "$sums_dir/SHA256SUMS" "SHA256SUMS" "$sums_file" "$version"; then
        this_line="$work/SHA256SUMS.this"
        # A release SHA256SUMS lists every target's tarball AND every
        # target's SBOM (`sha256sum *.tar.gz *.sbom.json > SHA256SUMS`), and
        # "irontraffic-<v>-<target>.tar.gz" is a byte-for-byte PREFIX of
        # "irontraffic-<v>-<target>.tar.gz.sbom.json". A substring match
        # (the previous `grep -F`) therefore returns BOTH lines for a
        # tarball whose SBOM was never downloaded, and `sha256sum -c` fails
        # naming the SBOM's own line as missing: a false tamper alarm on a
        # perfectly good artifact. awk's field comparison requires the
        # WHOLE second (whitespace-delimited) field to equal
        # $artifact_basename, which a mere prefix cannot satisfy.
        #
        # No `sed "s#$sums_dir/##"` here (there used to be one): a real
        # release SHA256SUMS is always generated from INSIDE its own
        # directory (`cd dist && sha256sum *.tar.gz *.sbom.json`), so its
        # second field is already a bare basename, and awk's exact `$2 ==
        # name` match above can only ever succeed against a line whose
        # field already equals $artifact_basename verbatim; a substitution
        # meant to strip a directory prefix that is never there is a
        # no-op on every real input. It was not, however, a no-op on
        # $sums_dir itself: interpolating an unescaped download directory
        # into a `sed` program that also uses `#` as its own delimiter
        # broke the substitution (and, with it, the checksum check) for
        # any directory whose name happens to contain a literal `#`.
        if awk -v name="$artifact_basename" '$2 == name' "$sums_file" > "$this_line" 2>/dev/null \
            && [ -s "$this_line" ]; then
            checksum_ok=0
            if command -v sha256sum >/dev/null 2>&1; then
                ( cd "$(cd "$sums_dir" && pwd)" && sha256sum -c "$this_line" ) >"$work/checksum.log" 2>&1 || checksum_ok=1
            else
                ( cd "$(cd "$sums_dir" && pwd)" && shasum -a 256 -c "$this_line" ) >"$work/checksum.log" 2>&1 || checksum_ok=1
            fi
            if [ "$checksum_ok" -eq 0 ]; then
                checked=$((checked + 1))
                echo "checksum: done"
            else
                cat "$work/checksum.log" >&2
                note_fail "checksum: $artifact_basename does not match SHA256SUMS"
            fi
        else
            note_fail "checksum: $artifact_basename is not listed in SHA256SUMS"
        fi
    else
        note_skip "checksum" "SHA256SUMS could not be located or downloaded"
    fi

    # A tampered artifact is a hard stop before any network call runs: no
    # signature, provenance or SBOM check below executes once the checksum
    # itself has failed.
    if [ "$failed" -gt 0 ]; then
        print_summary_and_exit "$checked" "$skipped" "$failed" "$skip_lines" "$fail_lines" "$allow_skipped"
    fi

    # -------------------------------------------------------------------
    # 2. Signature. Pins BOTH the certificate identity and the OIDC
    #    issuer: a verification that omits either accepts a signature from
    #    anyone, the single most common mistake with this tooling.
    # -------------------------------------------------------------------
    sig_file="$work/artifact.bundle"
    have_sig="$(locate_or_fetch "$artifact.bundle" "$artifact_basename.bundle" "$sig_file" "$version" && echo yes || echo no)"
    if [ "$have_sig" = "yes" ] \
        && [ "$(wc -c < "$sig_file" | tr -d ' ')" -le "$max_bytes" ]; then
        if cosign verify-blob \
            --bundle "$sig_file" \
            --new-bundle-format \
            --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
            --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
            "$artifact" >"$work/sig-verify.log" 2>&1; then
            checked=$((checked + 1))
            echo "signature: verified (identity matches $CERT_IDENTITY_REGEXP, issuer $CERT_OIDC_ISSUER)"
        else
            if grep -qi "certificate identity\|does not match" "$work/sig-verify.log"; then
                note_fail "signature: certificate identity did not match $CERT_IDENTITY_REGEXP (see log below)"
            else
                note_fail "signature: cosign verify-blob failed (see log below)"
            fi
            cat "$work/sig-verify.log" >&2
        fi
    else
        note_skip "signature" "could not locate or download $artifact_basename.bundle"
    fi

    # -------------------------------------------------------------------
    # 3. Provenance. The subject digest cosign embedded when the
    #    attestation was produced must equal this artifact's own sha256
    #    (invariant 7); this script recomputes the artifact's digest
    #    independently rather than trusting the attestation's own claim.
    #
    # Verified from a Sigstore bundle (--bundle), not a bare DSSE envelope
    # plus a separate `cosign verify-blob-attestation` Rekor SEARCH call:
    # the search path was tried first and failed against this project's own
    # real signing identity with a Rekor API error this project does not
    # control ("proposedContent.proposedContent.verifiers in body is
    # required"); the bundle embeds the same inclusion proof the search
    # would have looked up, so verification needs no live search at all.
    # -------------------------------------------------------------------
    intoto_file="$work/artifact.intoto.bundle"
    if locate_or_fetch "$artifact.intoto.bundle" "$artifact_basename.intoto.bundle" "$intoto_file" "$version" \
        && [ "$(wc -c < "$intoto_file" | tr -d ' ')" -le "$max_bytes" ]; then
        if cosign verify-blob-attestation \
            --bundle "$intoto_file" \
            --new-bundle-format \
            --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
            --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
            --type slsaprovenance \
            "$artifact" >"$work/attest-verify.log" 2>&1; then
            payload="$(jq -r '.dsseEnvelope.payload' "$intoto_file" 2>/dev/null | base64 -d 2>/dev/null || true)"
            subject_sha256="$(printf '%s' "$payload" | jq -r '.subject[0].digest.sha256 // empty' 2>/dev/null || true)"
            actual_sha256="$(sha256_of "$artifact")"
            commit="$(printf '%s' "$payload" | jq -r '.predicate.invocation.configSource.digest.sha1 // empty' 2>/dev/null || true)"
            builder="$(printf '%s' "$payload" | jq -r '.predicate.builder.id // empty' 2>/dev/null || true)"
            # The ref this build actually ran from, e.g.
            # "git+https://github.com/ELares/IronTraffic@refs/tags/v1.2.3"
            # -> "refs/tags/v1.2.3". Used by --strict below; extracted here,
            # once, rather than re-parsing the payload again down there.
            source_ref="$(printf '%s' "$payload" | jq -r '.predicate.invocation.configSource.uri // empty' 2>/dev/null | sed 's/^.*@//' || true)"
            # sha256(Cargo.lock) as attest.sh recorded it for THIS artifact's
            # own build. Used below (SBOM step) to bind a --sbom argument to
            # this exact artifact's dependency graph, invariant 8's other
            # half: a subject-digest match alone (above) proves the SBOM
            # bundle format loads and the artifact's own signature is real,
            # but says nothing about whether a GIVEN --sbom file describes
            # the SAME build.
            provenance_cargo_lock_sha256="$(printf '%s' "$payload" | jq -r '.predicate.invocation.parameters.cargoLockSha256 // empty' 2>/dev/null || true)"
            if [ -n "$subject_sha256" ] && [ "$subject_sha256" = "$actual_sha256" ]; then
                checked=$((checked + 1))
                echo "provenance: verified"
                echo "  source commit: ${commit:-<unknown>}"
                echo "  workflow:      ${builder:-<unknown>}"
            else
                note_fail "provenance: subject digest ($subject_sha256) does not match the artifact's own sha256 ($actual_sha256)"
            fi
            # Edge case 9, the non-strict half: a dirty artifact should
            # never have been published, and a plain (non-strict) run warns
            # rather than failing so a check specifically aimed at exactly
            # this cannot be silently missed; --strict escalates it to a
            # failure below.
            dirty_flag="$(printf '%s' "$payload" | jq -r '.predicate.invocation.parameters.dirty // empty' 2>/dev/null || true)"
            if [ "$dirty_flag" = "true" ]; then
                echo "warning: this artifact's dirty flag is true (built from an uncommitted" >&2
                echo "  worktree); it should never have been published. Pass --strict to" >&2
                echo "  make this a hard failure." >&2
            fi
        else
            note_fail "provenance: cosign verify-blob-attestation failed (see log below)"
            cat "$work/attest-verify.log" >&2
        fi
    else
        note_skip "provenance" "could not locate or download $artifact_basename.intoto.bundle"
    fi

    # -------------------------------------------------------------------
    # 4. SBOM, only if --sbom was given.
    # -------------------------------------------------------------------
    if [ -n "$sbom" ]; then
        if [ ! -f "$sbom" ]; then
            note_fail "sbom: no such file: $sbom"
        else
            sbom_sig="$work/sbom.bundle"
            sbom_basename="$(basename "$sbom")"
            if locate_or_fetch "$sbom.bundle" "$sbom_basename.bundle" "$sbom_sig" "$version"; then
                if cosign verify-blob \
                    --bundle "$sbom_sig" \
                    --new-bundle-format \
                    --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
                    --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
                    "$sbom" >"$work/sbom-sig-verify.log" 2>&1; then
                    checked=$((checked + 1))
                    echo "sbom signature: verified"
                else
                    note_fail "sbom signature: cosign verify-blob failed (see log below)"
                    cat "$work/sbom-sig-verify.log" >&2
                fi
            else
                note_skip "sbom signature" "could not locate or download $sbom_basename.bundle"
            fi

            # sbom-licence-check.sh's own exit 3 is a distinct SKIPPED
            # signal (#788, widened by #791): either no deny.toml
            # allowlist was found anywhere it knows to look, OR deny.toml
            # was found but licence-exceptions.txt was not (deny.toml
            # alone is not enough; see its own header comment), and either
            # way this says nothing about the SBOM's own licence set and
            # must not be reported as though it does. This script cannot
            # tell the two apart without re-parsing sbom-licence-check.sh's
            # own stderr, so the reason names both files rather than
            # guessing which one was missing. Only exit 1 ("a real check
            # ran and failed") becomes a FAILED line here; exit 3 and exit
            # 4 each become their own named skip, same as every other
            # check in this script that could not be performed. Exit 4
            # (#791 NOTE) is the SBOM's own fault, not the allowlist's: an
            # allowlist WAS found, but the SBOM declares zero components,
            # so a security tool reporting a vacuous "pass" over nothing
            # would be worse than naming the gap.
            sbom_licence_status=0
            sh "$SCRIPT_DIR/sbom-licence-check.sh" "$sbom" >"$work/sbom-licence.log" 2>&1 || sbom_licence_status=$?
            if [ "$sbom_licence_status" -eq 0 ]; then
                checked=$((checked + 1))
                allowlist_applied="$(grep -m1 '^applied: ' "$work/sbom-licence.log" | sed 's/^applied: //')"
                echo "sbom licence: subset of the allowlist ($allowlist_applied)"
            elif [ "$sbom_licence_status" -eq 3 ]; then
                note_skip "sbom licence" "no deny.toml allowlist or licence-exceptions.txt found; see docs/SUPPLY-CHAIN.md section 3"
            elif [ "$sbom_licence_status" -eq 4 ]; then
                note_skip "sbom licence" "SBOM declares zero components; nothing to check its licence set against"
            else
                note_fail "sbom licence: not a subset of the allowlist (see below)"
                cat "$work/sbom-licence.log" >&2
            fi

            # -----------------------------------------------------------
            # Bind the SBOM to THIS artifact (invariant 8). A signed SBOM
            # signature (above) proves this project produced SOME SBOM; it
            # does not prove this SBOM describes this artifact's own
            # dependency graph. Without this check, any signed SBOM from
            # any target or any release verifies correctly beside any
            # tarball: a wrong-target or stale SBOM would pass silently,
            # naming a licence set that never described the file the user
            # actually downloaded.
            #
            # Two independent comparisons, both against data already
            # cryptographically verified above (never against the SBOM's
            # own unverified self-description alone):
            #   - target: the SBOM's irontraffic:target property must equal
            #     the target embedded in the artifact's own filename.
            #   - cargo_lock_sha256: the SBOM's irontraffic:cargo_lock_sha256
            #     property must equal the artifact's OWN provenance
            #     attestation's cargoLockSha256 (extracted in step 3), so
            #     this compares two values the artifact's build itself
            #     produced, not the SBOM's claim checked against itself.
            # The second comparison only runs when provenance was actually
            # verified: with no verified provenance there is nothing
            # authoritative to bind against, and the target comparison
            # alone still runs unconditionally, since it needs only the
            # artifact's own (locally known) filename.
            #
            # Each comparison reports ONLY what it itself verified, on its
            # own line, with its own `checked`/`skipped` accounting. A
            # single joint success line used to be printed from the
            # cargo_lock_sha256 branch alone, claiming "target and
            # cargo_lock_sha256 match" even on a run where the target
            # comparison immediately above had just reported a FAILED
            # mismatch: a security tool contradicting itself on the one
            # screen a user reads. Splitting them also means a target-only
            # pass (no verified provenance to compare cargo_lock_sha256
            # against at all) is no longer silently invisible: it gets its
            # own success line and its own `checked` tick instead of being
            # folded into a sentence about a comparison that never ran.
            # -----------------------------------------------------------
            sbom_target="$(jq -r '(.metadata.properties[]? | select(.name == "irontraffic:target") | .value) // empty' "$sbom" 2>/dev/null || true)"
            if [ -z "$sbom_target" ]; then
                note_fail "sbom binding: sbom has no irontraffic:target property to bind it to the artifact"
            elif [ "$sbom_target" != "$target_from_artifact" ]; then
                note_fail "sbom binding: sbom's target ($sbom_target) does not match the artifact's own target ($target_from_artifact)"
            else
                checked=$((checked + 1))
                echo "sbom binding: target matches the artifact's own filename ($target_from_artifact)"
            fi

            if [ -z "${provenance_cargo_lock_sha256:-}" ]; then
                # verify.sh's own header promise: --allow-skipped prints
                # one named line per skipped check so the user still sees
                # exactly what was not checked, rather than a bare "ok".
                # Without this branch, a run with no verified provenance
                # (unreachable network, or --sbom given without a
                # reachable .intoto.bundle) silently omitted the
                # cargo_lock_sha256 comparison from BOTH the summary
                # counts and the skip list, which is indistinguishable
                # from "there was nothing else to check" at a glance.
                note_skip "sbom binding: cargo_lock_sha256" "no verified provenance to bind the sbom's cargo_lock_sha256 against"
            else
                sbom_cargo_lock_sha256="$(jq -r '(.metadata.properties[]? | select(.name == "irontraffic:cargo_lock_sha256") | .value) // empty' "$sbom" 2>/dev/null || true)"
                if [ -z "$sbom_cargo_lock_sha256" ]; then
                    note_fail "sbom binding: sbom has no irontraffic:cargo_lock_sha256 property to bind it to the artifact's provenance"
                elif [ "$sbom_cargo_lock_sha256" != "$provenance_cargo_lock_sha256" ]; then
                    note_fail "sbom binding: sbom's cargo_lock_sha256 ($sbom_cargo_lock_sha256) does not match the artifact's own provenance ($provenance_cargo_lock_sha256)"
                else
                    checked=$((checked + 1))
                    echo "sbom binding: cargo_lock_sha256 matches the artifact's own provenance"
                fi
            fi
        fi
    fi

    # -------------------------------------------------------------------
    # 5. --strict extras: dirty flag, and reachability from a release tag.
    #
    # WHY THIS DOES NOT WALK LOCAL GIT HISTORY, though "reachable from a
    # signed tag" reads like it should: `verify.sh` runs from wherever
    # `install.sh` downloaded it to (edge case: the documented
    # `curl | sh` install has no `.git` directory anywhere on the machine
    # at all), so a check that required one would make `--strict`, which
    # `install.sh` always passes, fail every real install. This project
    # also does not GPG- or gitsign-sign its git tag objects (only the
    # ARTIFACTS are signed, keylessly, by cosign); a check that required
    # that would fail every real install for a DIFFERENT, also-currently-
    # true reason. What this checks instead needs neither: the provenance's
    # own `invocation.configSource.uri` already names the ref the build ran
    # from (extracted above as $source_ref), and that ref is exactly what
    # the certificate-identity-regexp pin in step 2 already bound the
    # signature to. Requiring `refs/tags/v*` here is therefore not a new,
    # separate trust decision; it restates, from data already fetched and
    # already cryptographically verified, that this build ran from an
    # actual tagged release rather than a branch or pull-request ref. See
    # docs/SUPPLY-CHAIN.md for the full reasoning and the literal
    # GPG-tag-signing alternative this project deliberately does not build.
    # -------------------------------------------------------------------
    if [ "$strict" -eq 1 ]; then
        if [ "${dirty_flag:-}" = "true" ]; then
            note_fail "strict: the artifact's dirty flag is true; it should never have been published"
        fi

        case "${source_ref:-}" in
            refs/tags/v*) : ;;
            "")
                note_fail "strict: no source ref was recovered from the provenance to check" ;;
            *)
                note_fail "strict: provenance's source ref is \"$source_ref\", naming the tag: not a refs/tags/v* release ref" ;;
        esac
    fi

    print_summary_and_exit "$checked" "$skipped" "$failed" "$skip_lines" "$fail_lines" "$allow_skipped"
}

print_summary_and_exit() {
    checked="$1"; skipped="$2"; failed="$3"; skip_lines="$4"; fail_lines="$5"; allow_skipped="$6"
    echo
    echo "verify.sh summary: $checked checked, $skipped skipped, $failed failed"
    if [ -n "$skip_lines" ]; then
        printf '%s\n' "$skip_lines"
    fi
    if [ -n "$fail_lines" ]; then
        printf '%s\n' "$fail_lines"
    fi
    echo "to independently reproduce: check out the commit printed above, then run"
    echo "  scripts/release/verify-repro.sh <target>"
    echo "verification proves this project produced the artifact from that commit;"
    echo "reproducing it proves that commit produces the artifact. Both matter."

    if [ "$failed" -gt 0 ]; then
        exit 1
    fi
    if [ "$skipped" -gt 0 ] && [ "$allow_skipped" -ne 1 ]; then
        echo "error: $skipped check(s) were skipped and --allow-skipped was not given;" >&2
        echo "  a skipped check is treated as a failure. Pass --allow-skipped only if" >&2
        echo "  you understand what that check would otherwise have caught." >&2
        exit 1
    fi
    exit 0
}

main "$@"
