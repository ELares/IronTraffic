#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Signs one or more files keylessly with cosign (sigstore). Every published
# release file is signed this way: the four tarballs, the four SBOMs, and
# SHA256SUMS. See docs/SUPPLY-CHAIN.md.
#
# Usage: scripts/release/sign.sh <file> [<file> ...]
#
# Produces, per file: <file>.bundle, a Sigstore "new bundle format" object
# (cosign's --new-bundle-format) holding the signature, the short-lived
# Fulcio certificate, and the Rekor inclusion proof together, so
# verification is self-contained and does not need a live Rekor SEARCH call
# by artifact digest. That search-based path is what this script used
# before: `cosign verify-blob-attestation` without --bundle, verified
# against this project's own real signing identity on a real pull request,
# failed with a Rekor API error ("proposedContent.proposedContent.verifiers
# in body is required") this project does not control and cannot fix;
# --bundle sidesteps it by embedding the same proof the search would have
# looked up. Signing SHA256SUMS in addition to each individual tarball and
# SBOM means a user who only wants to make one check has one to make.
#
# WHY THIS SCRIPT REFUSES TO RUN OUTSIDE THE RELEASE WORKFLOW: keyless
# signing binds a short-lived certificate to WHATEVER identity requests it.
# A signature produced from a developer's laptop is a real, verifiable
# signature, just not one that means what a release signature is supposed to
# mean (that ci.yml itself, running as this repository, produced the file).
# The check below is a real environment check, not a courtesy prompt: this
# script exits 1 unless GITHUB_ACTIONS is set, GITHUB_REPOSITORY is exactly
# this project, and GITHUB_WORKFLOW_REF names ci.yml, so a local run cannot
# accidentally produce a signature that looks like a release signature. It
# deliberately allows a pull-request run, not only a tag: cosign's ambient
# GitHub Actions OIDC detection issues a real, distinctly-identified
# certificate for ANY workflow run with `id-token: write` permission
# (subject ".../ci.yml@refs/pull/N/merge" on a pull request,
# ".../ci.yml@refs/tags/vX.Y.Z" on a tag), and verify.sh's pinned
# certificate-identity-regexp only matches the tag form; exercising the
# mechanism on every pull request (not merely tag-gated) is what this
# project's CI learned the hard way while extending this exact job (see
# .github/workflows/ci.yml's own comment on release-artifacts).
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

usage() {
    cat <<'EOF' >&2
usage: scripts/release/sign.sh <file> [<file> ...]
EOF
}

preflight() {
    if ! command -v cosign >/dev/null 2>&1; then
        echo "error: cosign is required to sign a release artifact. Install:" >&2
        echo "  https://docs.sigstore.dev/cosign/system_config/installation/" >&2
        exit 1
    fi
}

# See the header comment above. GITHUB_REPOSITORY is compared to a literal,
# not derived from `git remote`, so a fork cannot satisfy this check by
# renaming its own remote.
assert_release_identity() {
    if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
        echo "error: refusing to sign outside a GitHub Actions run. Keyless signing" >&2
        echo "  binds a certificate to the identity requesting it, and a local run's" >&2
        echo "  identity is not this project's release workflow." >&2
        exit 1
    fi
    if [ "${GITHUB_REPOSITORY:-}" != "ELares/IronTraffic" ]; then
        echo "error: refusing to sign: GITHUB_REPOSITORY is \"${GITHUB_REPOSITORY:-<unset>}\"," >&2
        echo "  not ELares/IronTraffic." >&2
        exit 1
    fi
    case "${GITHUB_WORKFLOW_REF:-}" in
        */.github/workflows/ci.yml@*) : ;;
        *)
            echo "error: refusing to sign: GITHUB_WORKFLOW_REF is" >&2
            echo "  \"${GITHUB_WORKFLOW_REF:-<unset>}\", which does not name" >&2
            echo "  .github/workflows/ci.yml." >&2
            exit 1
            ;;
    esac
    # Confirmed directly (not assumed): without this check, cosign does NOT
    # fail fast when the ambient GitHub Actions OIDC token is unavailable
    # (a job missing `permissions: id-token: write`, or this exact script
    # run anywhere outside Actions). It falls back to an interactive device
    # flow, prints a one-time URL and code, and only fails after a ~5
    # minute wait per attempt, so a misconfigured job would burn roughly 15
    # minutes across sign_one_with_retry's three attempts before reporting
    # anything actionable. GitHub Actions sets both of these whenever
    # `id-token: write` is granted, regardless of pull_request vs. tag, so
    # checking for them here fails in seconds with a message that actually
    # names the missing permission.
    if [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
        echo "error: refusing to sign: no ambient GitHub Actions OIDC token is" >&2
        echo "  available (ACTIONS_ID_TOKEN_REQUEST_TOKEN / _URL are unset). This" >&2
        echo "  job needs \`permissions: id-token: write\`; without it, cosign would" >&2
        echo "  otherwise fall back to a slow interactive device-flow prompt and" >&2
        echo "  fail anyway." >&2
        exit 1
    fi
}

# Edge case 6: the transparency log is unreachable. Retried three times with
# backoff, then the release fails; never falls back to an unsigned publish
# and never falls back to a local key.
sign_one_with_retry() {
    file="$1"
    attempt=1
    delay=2
    while [ "$attempt" -le 3 ]; do
        # --oidc-provider=github-actions pins cosign to the ambient GitHub
        # Actions OIDC provider specifically. Without it, cosign tries every
        # ambient provider in turn and then falls back to an interactive
        # browser OAuth flow, which this project confirmed hangs
        # indefinitely (until cosign's own --timeout) when run anywhere
        # that is not actually GitHub Actions with `id-token: write`
        # granted; pinning the provider turns that hang into a fast,
        # explicit failure instead, both here and in a misconfigured CI job
        # that forgot to grant the permission.
        if cosign sign-blob --yes \
            --oidc-provider=github-actions \
            --bundle "$file.bundle" \
            --new-bundle-format \
            "$file" >"$file.sign.log" 2>&1; then
            rm -f "$file.sign.log"
            return 0
        fi
        echo "warning: signing $file failed on attempt $attempt/3:" >&2
        cat "$file.sign.log" >&2
        rm -f "$file.sign.log"
        if [ "$attempt" -lt 3 ]; then
            sleep "$delay"
            delay=$((delay * 2))
        fi
        attempt=$((attempt + 1))
    done
    return 1
}

main() {
    if [ "$#" -lt 1 ]; then
        usage
        exit 2
    fi
    preflight
    assert_release_identity

    failed=0
    for file in "$@"; do
        if [ ! -f "$file" ]; then
            echo "error: no such file: $file" >&2
            failed=1
            continue
        fi
        echo "signing $file"
        if ! sign_one_with_retry "$file"; then
            echo "error: signing $file failed after 3 attempts; refusing to publish" >&2
            echo "  an unsigned artifact." >&2
            failed=1
            continue
        fi
        echo "signed: $file.bundle"
    done

    if [ "$failed" -ne 0 ]; then
        exit 1
    fi
}

main "$@"
