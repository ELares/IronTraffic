#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Produces an in-toto build provenance attestation for one release artifact.
# A signature says "we produced this"; this attestation says which commit,
# which workflow, which builder and which inputs produced it. See
# docs/SUPPLY-CHAIN.md.
#
# Usage: scripts/release/attest.sh <artifact-file> <target> <features>
#
# Produces <artifact-file>.intoto.jsonl (cosign's own DSSE-enveloped
# in-toto statement). The statement's subject is {name, digest: {sha256}},
# computed by cosign itself from <artifact-file>; this script only supplies
# the PREDICATE, whose fields are:
#   builder.id            this workflow's identity (matches the identity
#                          verify.sh's certificate-identity-regexp pins)
#   buildType              the workflow file's own URL
#   invocation.configSource.uri/digest   the source repository and commit
#   invocation.parameters  target, features, SOURCE_DATE_EPOCH, dirty (from
#                          IT_GIT_DIRTY, the same flag build.sh stamps;
#                          edge case 9 is what reads this back)
#   materials[0].digest.sha1              the same commit, restated as a
#                          SLSA "material", for tooling that reads materials
#                          rather than configSource
#   metadata.workflowFileSha256           the sha256 of the workflow file
#                          itself, so a change to ci.yml is independently
#                          checkable against the commit named above
#   metadata.cargoLockSha256              the resolved dependency digest:
#                          sha256(Cargo.lock), which is what lets a verifier
#                          check that the SBOM and this artifact describe
#                          the same dependency graph (invariant 8)
#
# This uses the standard SLSA v0.2 provenance field names (builder,
# buildType, invocation, materials, metadata) where they exist, so a
# SLSA-aware consumer reads a familiar shape, and adds two fields neither
# name has a slot for (metadata.workflowFileSha256,
# metadata.cargoLockSha256) rather than overloading an existing one.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

usage() {
    cat <<'EOF' >&2
usage: scripts/release/attest.sh <artifact-file> <target> <features>
EOF
}

preflight() {
    missing=0
    if ! command -v cosign >/dev/null 2>&1; then
        echo "error: cosign is required to produce a provenance attestation." >&2
        echo "  Install: https://docs.sigstore.dev/cosign/system_config/installation/" >&2
        missing=1
    fi
    if ! command -v jq >/dev/null 2>&1; then
        echo "error: jq is required to build the provenance predicate JSON." >&2
        echo "  Install: https://jqlang.org/download/" >&2
        missing=1
    fi
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        echo "error: neither sha256sum nor shasum is installed; this script needs" >&2
        echo "  one to compute the artifact and Cargo.lock digests." >&2
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

# See sign.sh's identical check and its own comment: this project confirmed
# directly that cosign does not fail fast without it, falling back instead
# to a slow interactive device-flow prompt.
assert_release_identity() {
    if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
        echo "error: refusing to attest outside a GitHub Actions run." >&2
        exit 1
    fi
    if [ "${GITHUB_REPOSITORY:-}" != "ELares/IronTraffic" ]; then
        echo "error: refusing to attest: GITHUB_REPOSITORY is \"${GITHUB_REPOSITORY:-<unset>}\"," >&2
        echo "  not ELares/IronTraffic." >&2
        exit 1
    fi
    case "${GITHUB_WORKFLOW_REF:-}" in
        */.github/workflows/ci.yml@*) : ;;
        *)
            echo "error: refusing to attest: GITHUB_WORKFLOW_REF is" >&2
            echo "  \"${GITHUB_WORKFLOW_REF:-<unset>}\", which does not name" >&2
            echo "  .github/workflows/ci.yml." >&2
            exit 1
            ;;
    esac
    if [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
        echo "error: refusing to attest: no ambient GitHub Actions OIDC token is" >&2
        echo "  available. This job needs \`permissions: id-token: write\`." >&2
        exit 1
    fi
}

main() {
    if [ "$#" -ne 3 ]; then
        usage
        exit 2
    fi
    preflight

    artifact="$1"
    target="$2"
    features="$3"

    if [ ! -f "$artifact" ]; then
        echo "error: no such file: $artifact" >&2
        exit 1
    fi

    assert_release_identity

    commit_sha="$(git rev-parse HEAD 2>/dev/null || echo "${GITHUB_SHA:-unknown}")"
    epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct 2>/dev/null || echo 0)}"
    cargo_lock_sha256="$(sha256_of "$REPO_ROOT/Cargo.lock")"
    workflow_file="$REPO_ROOT/.github/workflows/ci.yml"
    if [ ! -f "$workflow_file" ]; then
        echo "error: $workflow_file does not exist; cannot record its digest." >&2
        exit 1
    fi
    workflow_sha256="$(sha256_of "$workflow_file")"
    dirty="${IT_GIT_DIRTY:-unknown}"

    # https://github.com/<owner>/<repo>/<GITHUB_WORKFLOW_REF>, e.g.
    # "https://github.com/ELares/IronTraffic/.github/workflows/ci.yml@refs/tags/v1.2.3".
    # This is deliberately the SAME shape verify.sh's
    # --certificate-identity-regexp pins, because it names the identity the
    # certificate Fulcio issues for this exact workflow run actually binds
    # to; constructing it independently here (rather than copying it) is
    # what lets a verifier cross-check the attestation's claimed builder
    # against the certificate's own subject.
    builder_id="https://github.com/${GITHUB_WORKFLOW_REF:-${GITHUB_REPOSITORY:-unknown}/.github/workflows/ci.yml@unknown}"
    build_type="https://github.com/${GITHUB_REPOSITORY:-unknown}/.github/workflows/ci.yml"
    config_uri="git+https://github.com/${GITHUB_REPOSITORY:-unknown}@${GITHUB_REF:-unknown}"

    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT INT TERM
    predicate_file="$work/predicate.json"

    jq -n \
        --arg builder_id "$builder_id" \
        --arg build_type "$build_type" \
        --arg config_uri "$config_uri" \
        --arg commit_sha "$commit_sha" \
        --arg target "$target" \
        --arg features "$features" \
        --arg epoch "$epoch" \
        --arg workflow_sha256 "$workflow_sha256" \
        --arg cargo_lock_sha256 "$cargo_lock_sha256" \
        --arg dirty "$dirty" \
        --arg run_id "${GITHUB_RUN_ID:-unknown}" \
        '{
          builder: { id: $builder_id },
          buildType: $build_type,
          invocation: {
            configSource: { uri: $config_uri, digest: { sha1: $commit_sha } },
            parameters: { target: $target, features: $features, SOURCE_DATE_EPOCH: $epoch, dirty: $dirty }
          },
          materials: [ { uri: $config_uri, digest: { sha1: $commit_sha } } ],
          metadata: {
            buildInvocationId: $run_id,
            workflowFileSha256: $workflow_sha256,
            cargoLockSha256: $cargo_lock_sha256,
            completeness: { parameters: true, environment: false, materials: true }
          }
        }' > "$predicate_file"

    attestation_out="$artifact.intoto.jsonl"
    if ! cosign attest-blob --yes \
        --oidc-provider=github-actions \
        --predicate "$predicate_file" \
        --type slsaprovenance \
        --output-attestation "$attestation_out" \
        "$artifact"; then
        echo "error: producing the provenance attestation for $artifact failed." >&2
        exit 1
    fi

    echo "attested: $attestation_out"
}

main "$@"
