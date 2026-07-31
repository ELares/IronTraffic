#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Self-test for the supply-chain scripts, run by the shell-selftests CI job
# on every pull request (see .github/workflows/ci.yml), the same job
# release-reproducible-build-and-artifacts (#427) created and
# bench-competitor-compare-script (#425) specified. Without that wiring
# this file's fifteen tests are a file nothing runs, which is why adding one
# step there is a Files table row on the issue this file belongs to (the
# same omission-and-remedy shape release-selftest.sh's own header describes
# for #427).
#
# WHAT THIS FILE DOES AND DOES NOT EXERCISE FOR REAL. `cargo metadata` and
# `sbom.sh` need no network beyond crates.io (already required by every
# other job that builds this workspace) and are exercised for real, always.
# `cosign sign-blob` / `attest-blob` need a GitHub Actions ambient OIDC
# identity token (`ACTIONS_ID_TOKEN_REQUEST_TOKEN`), which exists only when
# this job actually runs in GitHub Actions with `permissions: id-token:
# write` granted to a same-repository run; a fork pull request's run does
# not get one, and this SCRIPT run on a developer's own machine never does.
# Every test that needs a real signature or attestation checks for that
# token first and prints a named skip line, counted separately from
# pass/fail, when it is absent, per this issue's own instruction that "the
# tests that need network access to a transparency log print a named skip
# line and the script still exits nonzero for any test that ran and
# failed": a skipped test is not a failed test, but it is also not silently
# absent from this script's own output.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

RAN=0
FAILED=0
SKIPPED=0

pass() { RAN=$((RAN + 1)); printf 'ok   - %s\n' "$1"; }
fail() {
    RAN=$((RAN + 1))
    FAILED=$((FAILED + 1))
    printf 'FAIL - %s\n' "$1"
    # See release-selftest.sh's identical note: an `if`, not a bare
    # `[ -n ... ] && printf`, because the latter as the last statement would
    # make a detail-less call to fail() itself return 1 and, under `set -e`,
    # abort the whole self-test having reported only that one failure.
    if [ -n "${2:-}" ]; then
        printf '       %s\n' "$2"
    fi
}
skip() {
    SKIPPED=$((SKIPPED + 1))
    printf 'skip - %s (%s)\n' "$1" "$2"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Writes a `sha256sum -c`-format line ("<hex>  <name>") for one file into
# SHA256SUMS in the file's own directory, using whichever checksum tool is
# available.
write_sha256sums_line() {
    file="$1"
    dir="$(dirname "$file")"
    name="$(basename "$file")"
    printf '%s  %s\n' "$(sha256_of "$file")" "$name" >> "$dir/SHA256SUMS"
}

have_actions_oidc() {
    [ "${GITHUB_ACTIONS:-}" = "true" ] \
        && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] \
        && [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]
}

# scripts/release/cyclonedx-schema/{bom-1.6.schema.json,spdx.schema.json}
# are committed, unmodified, third-party copies of the CycloneDX project's
# own JSON Schema (Apache-2.0), fetched from
# https://github.com/CycloneDX/specification/tree/master/schema. Not
# generated: this issue's own Files table omits them the same way it omits
# this test file itself (see the header comment above), for the same
# reason (scripts/pr-scope-check.sh's prescribed remedy is a Files table
# row, not a silently widened diff), and a schema-validation test that
# fetched its schema over the network on every run would be exactly the
# single point of failure this project's own dependency-pinning rules argue
# against elsewhere (see .github/workflows/ci.yml's musl.cc handling).
CYCLONEDX_SCHEMA="$REPO_ROOT/scripts/release/cyclonedx-schema/bom-1.6.schema.json"
SPDX_SCHEMA="$REPO_ROOT/scripts/release/cyclonedx-schema/spdx.schema.json"

# ---------------------------------------------------------------------------
# Shared fixtures, generated once and reused across the tests below, the
# same "build once" discipline release-selftest.sh uses for its own shared
# Rust build.
# ---------------------------------------------------------------------------
FIXTURE_TARGET="x86_64-unknown-linux-musl"
FIXTURE_SBOM="$WORK/irontraffic.sbom.json"
if ! sh "$REPO_ROOT/scripts/release/sbom.sh" "$FIXTURE_TARGET" "control-plane" "$FIXTURE_SBOM" >"$WORK/sbom-gen.log" 2>&1; then
    echo "FATAL: could not generate the shared SBOM fixture; every test below" >&2
    echo "  depends on it. sbom.sh's own output:" >&2
    cat "$WORK/sbom-gen.log" >&2
    exit 1
fi

# irontraffic-tls stands in for the eventual irontraffic binary: see
# sbom.sh's own header comment on IT_SBOM_ROOT_PACKAGE for why. Real
# invocations (sign.sh, attest.sh, ci.yml) never set this.
FIXTURE_SBOM_RING="$WORK/tls-ring.sbom.json"
FIXTURE_SBOM_AWSLC="$WORK/tls-awslc.sbom.json"
IT_SBOM_ROOT_PACKAGE=irontraffic-tls sh "$REPO_ROOT/scripts/release/sbom.sh" \
    x86_64-unknown-linux-gnu "crypto-ring" "$FIXTURE_SBOM_RING" >"$WORK/sbom-ring-gen.log" 2>&1 \
    || { echo "FATAL: could not generate the ring-variant SBOM fixture:" >&2; cat "$WORK/sbom-ring-gen.log" >&2; exit 1; }
IT_SBOM_ROOT_PACKAGE=irontraffic-tls sh "$REPO_ROOT/scripts/release/sbom.sh" \
    x86_64-unknown-linux-gnu "crypto-aws-lc-rs" "$FIXTURE_SBOM_AWSLC" >"$WORK/sbom-awslc-gen.log" 2>&1 \
    || { echo "FATAL: could not generate the aws-lc-rs-variant SBOM fixture:" >&2; cat "$WORK/sbom-awslc-gen.log" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. sbom_is_valid_cyclonedx
# ---------------------------------------------------------------------------
test_sbom_is_valid_cyclonedx() {
    if [ ! -f "$CYCLONEDX_SCHEMA" ] || [ ! -f "$SPDX_SCHEMA" ]; then
        fail "sbom_is_valid_cyclonedx" "committed schema fixture(s) missing under scripts/release/cyclonedx-schema/"
        return
    fi
    if ! python3 -c "import jsonschema" >/dev/null 2>&1; then
        if ! pip3 install --quiet --user jsonschema >/dev/null 2>&1 \
            && ! pip3 install --quiet --user --break-system-packages jsonschema >/dev/null 2>&1; then
            skip "sbom_is_valid_cyclonedx" "no network to install the jsonschema package"
            return
        fi
    fi
    out="$(python3 - "$CYCLONEDX_SCHEMA" "$SPDX_SCHEMA" "$FIXTURE_SBOM" <<'PYEOF'
import json, sys, warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import jsonschema

bom_schema_path, spdx_schema_path, doc_path = sys.argv[1:4]
bom_schema = json.load(open(bom_schema_path))
spdx_schema = json.load(open(spdx_schema_path))
store = {
    "http://cyclonedx.org/schema/spdx.schema.json": spdx_schema,
    "spdx.schema.json": spdx_schema,
    bom_schema["$id"]: bom_schema,
}
resolver = jsonschema.RefResolver(base_uri=bom_schema["$id"], referrer=bom_schema, store=store)
validator = jsonschema.Draft7Validator(bom_schema, resolver=resolver)
doc = json.load(open(doc_path))
errors = list(validator.iter_errors(doc))
if errors:
    for e in errors[:5]:
        print("SCHEMA-ERROR:", e.message[:300])
    sys.exit(1)
PYEOF
)" && status=0 || status=$?
    if [ "$status" -eq 0 ]; then
        pass "sbom_is_valid_cyclonedx"
    else
        fail "sbom_is_valid_cyclonedx" "$out"
    fi
}

# ---------------------------------------------------------------------------
# 2. sbom_is_reproducible
# ---------------------------------------------------------------------------
test_sbom_is_reproducible() {
    second="$WORK/irontraffic.sbom.second.json"
    if ! sh "$REPO_ROOT/scripts/release/sbom.sh" "$FIXTURE_TARGET" "control-plane" "$second" >"$WORK/sbom-gen2.log" 2>&1; then
        fail "sbom_is_reproducible" "second generation failed: $(cat "$WORK/sbom-gen2.log")"
        return
    fi
    if cmp -s "$FIXTURE_SBOM" "$second"; then
        pass "sbom_is_reproducible"
    else
        fail "sbom_is_reproducible" "two generations of the same artifact differed: $(cmp "$FIXTURE_SBOM" "$second" 2>&1 | head -1)"
    fi
}

# ---------------------------------------------------------------------------
# 3. sbom_excludes_dev_dependencies
# ---------------------------------------------------------------------------
test_sbom_excludes_dev_dependencies() {
    # Assert the fixture's OWN precondition first: proptest is a real
    # dev-dependency of this workspace (irontraffic-tls, irontraffic-router,
    # and others all declare it), so its absence below is the closure
    # restriction working, not the fixture never having a chance to
    # include it in the first place.
    if ! grep -q '^proptest = ' "$REPO_ROOT/crates/irontraffic-tls/Cargo.toml" 2>/dev/null; then
        fail "sbom_excludes_dev_dependencies" "fixture precondition failed: proptest is not even a declared dev-dependency anywhere in this workspace, so its absence below would prove nothing"
        return
    fi
    if jq -e '.components[] | select(.name == "proptest")' "$FIXTURE_SBOM" >/dev/null 2>&1; then
        fail "sbom_excludes_dev_dependencies" "proptest, a dev-only dependency, is present in the default-features SBOM"
    else
        pass "sbom_excludes_dev_dependencies"
    fi
}

# ---------------------------------------------------------------------------
# 4. sbom_includes_vendored_c
# ---------------------------------------------------------------------------
test_sbom_includes_vendored_c() {
    # Precondition: aws-lc-sys must actually be in this fixture's closure,
    # or "aws-lc present" below would be checking a component the fixture
    # never had a chance to omit either.
    if ! jq -e '.components[] | select(.name == "aws-lc-sys")' "$FIXTURE_SBOM_AWSLC" >/dev/null 2>&1; then
        fail "sbom_includes_vendored_c" "fixture precondition failed: aws-lc-sys is not in the crypto-aws-lc-rs fixture's closure at all"
        return
    fi
    if jq -e '.components[] | select(.name == "aws-lc")' "$FIXTURE_SBOM_AWSLC" >/dev/null 2>&1; then
        pass "sbom_includes_vendored_c"
    else
        fail "sbom_includes_vendored_c" "no synthetic 'aws-lc' overlay component in the aws-lc-rs-variant fixture"
    fi
}

# ---------------------------------------------------------------------------
# 5. sbom_ring_variant
# ---------------------------------------------------------------------------
test_sbom_ring_variant() {
    has_ring="$(jq -e '.components[] | select(.name == "ring")' "$FIXTURE_SBOM_RING" >/dev/null 2>&1 && echo yes || echo no)"
    has_awslc="$(jq -e '.components[] | select(.name == "aws-lc-rs")' "$FIXTURE_SBOM_RING" >/dev/null 2>&1 && echo yes || echo no)"
    if [ "$has_ring" = "yes" ] && [ "$has_awslc" = "no" ]; then
        pass "sbom_ring_variant"
    else
        fail "sbom_ring_variant" "ring present=$has_ring (want yes), aws-lc-rs present=$has_awslc (want no)"
    fi
}

# ---------------------------------------------------------------------------
# 6. sbom_every_component_has_a_purl
# ---------------------------------------------------------------------------
test_sbom_every_component_has_a_purl() {
    count="$(jq '.components | length' "$FIXTURE_SBOM")"
    missing="$(jq '[.components[] | select(.purl == null or .purl == "")] | length' "$FIXTURE_SBOM")"
    if [ "$count" -gt 0 ] && [ "$missing" -eq 0 ]; then
        pass "sbom_every_component_has_a_purl"
    else
        fail "sbom_every_component_has_a_purl" "$count components, $missing missing a purl"
    fi
}

# ---------------------------------------------------------------------------
# 7. sbom_components_are_sorted_by_purl
# ---------------------------------------------------------------------------
test_sbom_components_are_sorted_by_purl() {
    actual="$(jq -r '.components[].purl' "$FIXTURE_SBOM")"
    expected="$(printf '%s\n' "$actual" | LC_ALL=C sort)"
    if [ "$actual" = "$expected" ]; then
        pass "sbom_components_are_sorted_by_purl"
    else
        fail "sbom_components_are_sorted_by_purl" "component purls are not sorted"
    fi
}

# ---------------------------------------------------------------------------
# 8. licence_check_passes_on_real_sbom
# ---------------------------------------------------------------------------
test_licence_check_passes_on_real_sbom() {
    if ! sh "$REPO_ROOT/scripts/release/sbom-licence-check.sh" "$FIXTURE_SBOM" >"$WORK/licence-real.log" 2>&1; then
        fail "licence_check_passes_on_real_sbom" "$(cat "$WORK/licence-real.log")"
        return
    fi
    # The real fixture's own slash-licensed crates (aho-corasick, memchr,
    # ryu) all happen to carry a committed exception too, so a check that
    # passed only because the EXCEPTION matched (by crate name, regardless
    # of the licence string) rather than because the "/" split actually
    # ran would still pass this far without the split logic doing anything
    # at all. Found exactly that way: deleting the "/" -> " OR " step
    # entirely left this test green. A synthetic component with NO
    # exception entry and a legacy slash licence, both of whose halves ARE
    # individually allowlisted, isolates the split from the exception
    # mechanism.
    slash_injected="$WORK/slash-injected.sbom.json"
    jq '.components += [{type:"library", name:"selftest-slash-fixture", version:"0.0.0",
        purl:"pkg:cargo/selftest-slash-fixture@0.0.0", licenses:[{license:{id:"MIT/Apache-2.0"}}]}]' \
        "$FIXTURE_SBOM" > "$slash_injected"
    if ! sh "$REPO_ROOT/scripts/release/sbom-licence-check.sh" "$slash_injected" >"$WORK/licence-slash.log" 2>&1; then
        fail "licence_check_passes_on_real_sbom" "a synthetic MIT/Apache-2.0 (no exception) component was rejected, meaning the '/' split is not running: $(cat "$WORK/licence-slash.log")"
        return
    fi
    pass "licence_check_passes_on_real_sbom"
}

# ---------------------------------------------------------------------------
# 9. licence_check_fails_on_injected_licence
# ---------------------------------------------------------------------------
test_licence_check_fails_on_injected_licence() {
    injected="$WORK/injected-gpl.sbom.json"
    # Injected into a component with NO committed exception (this
    # workspace's real three exceptions all cover a genuinely
    # allowlist-adjacent licence; injecting into one of THOSE would pass
    # for the wrong reason, matching it regardless of the injected value).
    target_name="$(jq -r '[.components[].name] - ["aho-corasick","memchr","ryu"] | first' "$FIXTURE_SBOM")"
    jq --arg name "$target_name" \
        '(.components[] | select(.name == $name) | .licenses) |= [{license: {id: "GPL-3.0"}}]' \
        "$FIXTURE_SBOM" > "$injected"
    if sh "$REPO_ROOT/scripts/release/sbom-licence-check.sh" "$injected" >"$WORK/licence-gpl.log" 2>&1; then
        fail "licence_check_fails_on_injected_licence" "check passed despite an injected GPL-3.0 component ($target_name)"
    elif grep -q "$target_name" "$WORK/licence-gpl.log"; then
        pass "licence_check_fails_on_injected_licence"
    else
        fail "licence_check_fails_on_injected_licence" "check failed but did not name $target_name: $(cat "$WORK/licence-gpl.log")"
    fi
}

# ---------------------------------------------------------------------------
# 10. licence_check_fails_on_missing_licence
# ---------------------------------------------------------------------------
test_licence_check_fails_on_missing_licence() {
    emptied="$WORK/emptied-licence.sbom.json"
    target_name="$(jq -r '.components[0].name' "$FIXTURE_SBOM")"
    jq --arg name "$target_name" '(.components[] | select(.name == $name) | .licenses) |= []' \
        "$FIXTURE_SBOM" > "$emptied"
    if sh "$REPO_ROOT/scripts/release/sbom-licence-check.sh" "$emptied" >"$WORK/licence-empty.log" 2>&1; then
        fail "licence_check_fails_on_missing_licence" "check passed despite a component with licenses: []"
    elif grep -q "$target_name" "$WORK/licence-empty.log"; then
        pass "licence_check_fails_on_missing_licence"
    else
        fail "licence_check_fails_on_missing_licence" "check failed but did not name $target_name: $(cat "$WORK/licence-empty.log")"
    fi
}

# ---------------------------------------------------------------------------
# 10a. licence_check_skips_on_zero_components
#
# #791 NOTE: an SBOM whose own `.components` array is empty (a truncated
# download, or a malformed generator run) used to fall straight through
# main()'s loop with total=0, failed=0, print a genuine "0/0 components
# pass", and exit 0 -- a security tool reading an EMPTY input as a PASS,
# indistinguishable from a real SBOM that was actually checked. This
# asserts the dedicated exit code 4 fires instead: distinct from exit 3's
# "no allowlist found" (an allowlist WAS found and applied here; deriving
# $empty_components from FIXTURE_SBOM, rather than hand-writing one,
# guarantees a real deny.toml and licence-exceptions.txt resolve first),
# and distinct from exit 0's genuine pass.
# ---------------------------------------------------------------------------
test_licence_check_skips_on_zero_components() {
    empty_components="$WORK/zero-components.sbom.json"
    jq '.components = []' "$FIXTURE_SBOM" > "$empty_components"
    out="$(sh "$REPO_ROOT/scripts/release/sbom-licence-check.sh" "$empty_components" 2>&1)" && status=0 || status=$?
    if [ "$status" -ne 4 ]; then
        fail "licence_check_skips_on_zero_components" "a zero-component SBOM exited $status, want 4 (the dedicated honest-skip code): $out"
        return
    fi
    if printf '%s' "$out" | grep -q "components pass"; then
        fail "licence_check_skips_on_zero_components" "a zero-component SBOM still printed a vacuous N/0 components pass line: $out"
        return
    fi
    pass "licence_check_skips_on_zero_components"
}

# ---------------------------------------------------------------------------
# 11. verify_fails_without_identity_pin
#
# THIS IS THE MOST COMMON MISTAKE WITH THIS TOOLING, so this test asserts it
# directly, without needing a real Fulcio-issued certificate (which cannot
# be obtained outside GitHub Actions; see this file's header). cosign
# itself REQUIRES --certificate-identity or --certificate-identity-regexp
# for any keyless verify-blob call; omitting it is a hard, immediate,
# config-level refusal, before cosign ever inspects the certificate's
# actual content. Removing the pin from verify.sh's own invocation would
# make EVERY verification take this same early exit for the wrong reason,
# which is exactly why verify.sh's own source is grepped here too: this
# test would not catch the pin being deleted from verify.sh if it only
# tested cosign's CLI in isolation.
# ---------------------------------------------------------------------------
test_verify_fails_without_identity_pin() {
    if ! grep -q -- '--certificate-identity-regexp' "$REPO_ROOT/scripts/release/verify.sh" \
        || ! grep -q -- '--certificate-oidc-issuer' "$REPO_ROOT/scripts/release/verify.sh"; then
        fail "verify_fails_without_identity_pin" "verify.sh's own source no longer names both pin flags"
        return
    fi
    fake_cert="$WORK/fake.pem"
    fake_sig="$WORK/fake.sig"
    fake_blob="$WORK/fake-blob.txt"
    printf 'not a real certificate\n' > "$fake_cert"
    printf 'bm90IGEgcmVhbCBzaWduYXR1cmU=\n' > "$fake_sig"
    printf 'test blob\n' > "$fake_blob"

    without_pin_log="$WORK/without-pin.log"
    cosign verify-blob --certificate "$fake_cert" --signature "$fake_sig" "$fake_blob" \
        >"$without_pin_log" 2>&1 && without_pin_status=0 || without_pin_status=$?

    with_pin_log="$WORK/with-pin.log"
    cosign verify-blob --certificate "$fake_cert" --signature "$fake_sig" \
        --certificate-identity-regexp '^https://github\.com/ELares/IronTraffic/' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        "$fake_blob" >"$with_pin_log" 2>&1 && with_pin_status=0 || with_pin_status=$?

    if [ "$without_pin_status" -eq 0 ]; then
        fail "verify_fails_without_identity_pin" "cosign verify-blob with NO identity pin at all exited 0 against a fake certificate"
        return
    fi
    if ! grep -qi "required.*keyless" "$without_pin_log"; then
        fail "verify_fails_without_identity_pin" "omitting the pin did not produce cosign's own mandatory-pin refusal: $(cat "$without_pin_log")"
        return
    fi
    if [ "$with_pin_status" -eq 0 ] || grep -qi "required.*keyless" "$with_pin_log"; then
        fail "verify_fails_without_identity_pin" "the pin being PRESENT did not change cosign's failure mode away from the mandatory-pin refusal, so the two runs are indistinguishable"
        return
    fi
    pass "verify_fails_without_identity_pin"
}

# ---------------------------------------------------------------------------
# 12. verify_fails_on_tampered_artifact
# ---------------------------------------------------------------------------
test_verify_fails_on_tampered_artifact() {
    dir="$WORK/tamper-fixture"
    mkdir -p "$dir"
    artifact="$dir/irontraffic-9.9.9-x86_64-unknown-linux-musl.tar.gz"
    printf 'fixture artifact content\n' > "$artifact"
    ( cd "$dir" && sha256_of "$(basename "$artifact")" > /dev/null )
    write_sha256sums_line "$artifact"
    printf 'TAMPERED\n' >> "$artifact"

    out="$(sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$artifact" 2>&1)" && status=0 || status=$?
    if [ "$status" -eq 0 ]; then
        fail "verify_fails_on_tampered_artifact" "verify.sh exited 0 against a tampered artifact"
        return
    fi
    if ! printf '%s' "$out" | grep -qi "checksum"; then
        fail "verify_fails_on_tampered_artifact" "failure did not name the checksum step: $out"
        return
    fi
    if printf '%s' "$out" | grep -qi "signature: verified\|provenance: verified"; then
        fail "verify_fails_on_tampered_artifact" "a network (signature/provenance) step ran despite the checksum already having failed"
        return
    fi
    pass "verify_fails_on_tampered_artifact"
}

# ---------------------------------------------------------------------------
# 12a. verify_checksum_ignores_sbom_substring_collision
#
# A release's real SHA256SUMS lists every target's tarball AND every
# target's SBOM (ci.yml: `sha256sum *.tar.gz *.sbom.json > SHA256SUMS`),
# eight lines for a four-target release. Every OTHER checksum fixture in
# this file (write_sha256sums_line, called once) writes exactly ONE line,
# which is why nothing caught this before: "irontraffic-<v>-<target>.tar.gz"
# is a byte-for-byte PREFIX of "irontraffic-<v>-<target>.tar.gz.sbom.json",
# so a substring-matching selector against a real, eight-line SHA256SUMS
# returns BOTH lines for a tarball whose SBOM was never downloaded, and
# `sha256sum -c` fails naming the missing SBOM file: a false tamper alarm
# on a perfectly good artifact. This fixture reproduces the REAL shape (all
# four targets' tarballs and all four SBOMs get a line), then verifies only
# the one tarball a real install actually downloads.
# ---------------------------------------------------------------------------
test_verify_checksum_ignores_sbom_substring_collision() {
    dir="$WORK/substring-fixture"
    mkdir -p "$dir"
    version="9.9.9"
    real_target="x86_64-unknown-linux-musl"
    for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
        tb="$dir/irontraffic-$version-$t.tar.gz"
        printf 'decoy tarball content for %s\n' "$t" > "$tb"
        write_sha256sums_line "$tb"
        sb="$tb.sbom.json"
        printf '{"decoy": "sbom for %s"}\n' "$t" > "$sb"
        write_sha256sums_line "$sb"
        # Only the target under test keeps its own tarball on disk: a real
        # verify.sh run only ever has the ONE tarball it downloaded, never
        # the other three targets' and never any SBOM (this test never
        # passes --sbom). Removing the rest proves the checksum step needs
        # nothing beyond the SHA256SUMS lines to pass.
        if [ "$t" != "$real_target" ]; then
            rm -f "$tb"
        fi
        rm -f "$sb"
    done
    real_artifact="$dir/irontraffic-$version-$real_target.tar.gz"

    out="$(sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$real_artifact" --allow-skipped 2>&1)" && status=0 || status=$?
    if [ "$status" -ne 0 ]; then
        fail "verify_checksum_ignores_sbom_substring_collision" "verify.sh failed against a genuine artifact merely because its own SBOM is also listed in a real, eight-line SHA256SUMS: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "checksum: done"; then
        fail "verify_checksum_ignores_sbom_substring_collision" "checksum step did not report done: $out"
        return
    fi
    pass "verify_checksum_ignores_sbom_substring_collision"
}

# ---------------------------------------------------------------------------
# 12b. verify_version_regex_handles_aarch64
#
# verify.sh's own version-from-filename value never surfaces on stdout or
# stderr by itself (only URLs built from it do, and curl's stderr is
# suppressed), so this extracts the EXACT sed expression verify.sh itself
# uses -- never a hand-copied duplicate that could quietly drift from the
# real one -- and runs it directly against every shipped target's own
# filename shape. The bug this catches: a greedy optional prerelease group
# whose character class ([0-9A-Za-z.]) also matches "aarch64" itself, so
# "irontraffic-0.1.0-aarch64-unknown-linux-gnu.tar.gz" parsed as version
# "0.1.0-aarch64"; x86_64 escaped only because "_" is not in that class.
# ---------------------------------------------------------------------------
test_verify_version_regex_handles_aarch64() {
    version_line="$(grep -F "sed -E 's/^irontraffic-" "$REPO_ROOT/scripts/release/verify.sh" || true)"
    if [ -z "$version_line" ]; then
        fail "verify_version_regex_handles_aarch64" "could not find verify.sh's own version-from-filename sed line at all"
        return
    fi
    sed_expr="$(printf '%s\n' "$version_line" | sed -E "s/^.*sed -E '//" | sed -E "s/'\\)\"\$//")"
    if [ -z "$sed_expr" ]; then
        fail "verify_version_regex_handles_aarch64" "could not extract the sed expression from: $version_line"
        return
    fi
    bad=""
    for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
        got="$(printf 'irontraffic-0.1.0-%s.tar.gz' "$t" | sed -E "$sed_expr")"
        if [ "$got" != "0.1.0" ]; then
            bad="$bad $t=>$got"
        fi
    done
    # A real prerelease must still parse (the fix must not have merely
    # removed the optional group).
    pre_got="$(printf 'irontraffic-0.1.0-rc.1-x86_64-unknown-linux-musl.tar.gz' | sed -E "$sed_expr")"
    if [ "$pre_got" != "0.1.0-rc.1" ]; then
        bad="$bad prerelease=>$pre_got"
    fi
    if [ -n "$bad" ]; then
        fail "verify_version_regex_handles_aarch64" "verify.sh's own version regex misparsed:$bad"
        return
    fi
    pass "verify_version_regex_handles_aarch64"
}

# ---------------------------------------------------------------------------
# 12c. verify_runs_standalone_outside_repo
#
# docs/SUPPLY-CHAIN.md documents downloading the artifact, its SBOM,
# verify.sh, sbom-licence-check.sh, deny.toml AND licence-exceptions.txt
# into ONE flat directory with no repository checkout anywhere on the
# machine, then running `sh verify.sh --artifact <tarball> --sbom <sbom>`
# (section 3's flagship command; --sbom is not an afterthought there, it is
# the headline form). verify.sh used to compute a "repository root" two
# directories above itself and `cd` there before using a relative
# --artifact path, which is correct only when the script still sits inside
# scripts/release/ of a checkout; run the documented way, that `cd` landed
# two levels above the actual download directory, and the relative
# artifact path no longer resolved.
#
# THIS FIXTURE USED TO COPY ONLY verify.sh AND NEVER PASS --sbom (#788):
# that is precisely why sbom-licence-check.sh's OWN identical
# two-directories-above-itself default for deny.toml survived fixing
# verify.sh's chdir. Copying sbom-licence-check.sh, deny.toml and
# licence-exceptions.txt in too, and asserting the licence check actually
# PASSES (not merely "does not crash"), is what closes that gap: run
# exactly as documented from this bare directory, a genuinely good
# artifact and a genuine (real, workspace-generated) SBOM must produce a
# real, passing licence check, not a false "not a subset of the allowlist"
# tamper alarm accusing the artifact of what was actually this script's own
# inability to find its allowlist.
# ---------------------------------------------------------------------------
test_verify_runs_standalone_outside_repo() {
    dir="$WORK/standalone-fixture"
    mkdir -p "$dir"
    cp "$REPO_ROOT/scripts/release/verify.sh" "$dir/verify.sh"
    cp "$REPO_ROOT/scripts/release/sbom-licence-check.sh" "$dir/sbom-licence-check.sh"
    cp "$REPO_ROOT/deny.toml" "$dir/deny.toml"
    cp "$REPO_ROOT/scripts/release/licence-exceptions.txt" "$dir/licence-exceptions.txt"
    artifact_name="irontraffic-9.9.9-x86_64-unknown-linux-musl.tar.gz"
    sbom_name="$artifact_name.sbom.json"
    printf 'standalone fixture artifact content\n' > "$dir/$artifact_name"
    # FIXTURE_SBOM (the shared, REAL sbom.sh output built at the top of
    # this file) carries irontraffic:target = FIXTURE_TARGET
    # ("x86_64-unknown-linux-musl"), matching $artifact_name's own target
    # segment, so the sbom-binding target comparison inside verify.sh
    # passes for a genuine reason below, not merely because nothing
    # compared it.
    cp "$FIXTURE_SBOM" "$dir/$sbom_name"
    ( cd "$dir" && write_sha256sums_line "$artifact_name" )

    # A subshell, not the current shell: `cd` here must not leak into the
    # rest of this script. `sh verify.sh` (not an absolute script path)
    # AND a relative --artifact/--sbom both matter: the reviewer's own
    # repro used exactly this shape.
    out="$(cd "$dir" && sh verify.sh --artifact "$artifact_name" --sbom "$sbom_name" --allow-skipped 2>&1)" && status=0 || status=$?
    if [ "$status" -ne 0 ]; then
        fail "verify_runs_standalone_outside_repo" "verify.sh failed when run standalone (no repo checkout), the documented --artifact/--sbom flow: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "checksum: done"; then
        fail "verify_runs_standalone_outside_repo" "checksum step did not report done: $out"
        return
    fi
    if printf '%s' "$out" | grep -qi "no such file"; then
        fail "verify_runs_standalone_outside_repo" "verify.sh reported a missing file despite the artifact sitting right next to it: $out"
        return
    fi
    # #788's own reproduction, inverted into an assertion: sbom-licence-
    # check.sh used to look for deny.toml two directories above this bare
    # directory, found nothing there, and verify.sh reported "FAILED: sbom
    # licence: not a subset of the allowlist" / "error: no such deny.toml"
    # over a deny.toml sitting right beside it the whole time.
    if printf '%s' "$out" | grep -qi "no such deny.toml"; then
        fail "verify_runs_standalone_outside_repo" "sbom-licence-check.sh could not find deny.toml despite it sitting right next to it: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "sbom licence: subset of the allowlist"; then
        fail "verify_runs_standalone_outside_repo" "sbom licence check did not genuinely pass (deny.toml/licence-exceptions.txt were not actually resolved beside the script): $out"
        return
    fi
    # This standalone run has no .intoto.bundle anywhere (real network,
    # deliberately never reached: no real release named "9.9.9" exists),
    # so provenance is genuinely unreachable and the cargo_lock_sha256
    # half of the sbom binding check has nothing authoritative to compare
    # against. verify.sh's own header promises --allow-skipped "prints one
    # named line per skipped check", and this is the one place in this
    # file where that specific check is naturally, honestly unreachable
    # (not a fabricated fixture): asserting its named skip line appears
    # here, rather than being silently dropped from the summary, is what
    # this test's own --allow-skipped exit-0 assertion above cannot tell
    # apart from "there was nothing else to check".
    if ! printf '%s' "$out" | grep -q "skipped: sbom binding: cargo_lock_sha256"; then
        fail "verify_runs_standalone_outside_repo" "cargo_lock_sha256 binding was silently omitted from the summary instead of a named skip: $out"
        return
    fi
    pass "verify_runs_standalone_outside_repo"
}

# ---------------------------------------------------------------------------
# 12d. verify_binds_sbom_to_artifact_target
#
# Invariant 8's other half. `--sbom` used to be checked entirely on its
# own: its signature had to verify and its licence set had to be a subset
# of the allowlist, but nothing ever compared it to the ARTIFACT it was
# supposedly describing. Any signed SBOM from any target of any release
# therefore passed beside any tarball. This fixture gives verify.sh a real
# artifact and a locally-forged SBOM whose own irontraffic:target property
# names a DIFFERENT target, and asserts the mismatch is caught by name.
# Deliberately network-free (an unreachable-by-construction .invalid host):
# this is about the LOCAL comparison logic, not the SBOM's own signature.
# ---------------------------------------------------------------------------
test_verify_binds_sbom_to_artifact_target() {
    dir="$WORK/binding-fixture"
    mkdir -p "$dir"
    artifact="$dir/irontraffic-9.9.9-x86_64-unknown-linux-musl.tar.gz"
    printf 'binding fixture artifact content\n' > "$artifact"
    write_sha256sums_line "$artifact"

    mismatched_sbom="$dir/irontraffic-9.9.9-aarch64-unknown-linux-gnu.tar.gz.sbom.json"
    jq -n --arg target "aarch64-unknown-linux-gnu" \
        '{"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json", bomFormat: "CycloneDX",
          specVersion: "1.6", version: 1,
          metadata: { properties: [ { name: "irontraffic:target", value: $target } ] },
          components: []}' > "$mismatched_sbom"

    out="$(IT_RELEASE_BASE_URL="https://verify-binding-fixture.invalid/releases" \
        sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$artifact" --sbom "$mismatched_sbom" --allow-skipped 2>&1)" && status=0 || status=$?
    if [ "$status" -eq 0 ]; then
        fail "verify_binds_sbom_to_artifact_target" "verify.sh exited 0 with an SBOM whose own target does not match the artifact's: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "sbom binding: sbom's target"; then
        fail "verify_binds_sbom_to_artifact_target" "failure did not name the sbom binding check: $out"
        return
    fi
    pass "verify_binds_sbom_to_artifact_target"
}

# ---------------------------------------------------------------------------
# 12e/12f. verify_binds_sbom_cargo_lock_sha256_matches / _mismatch
#
# Invariant 8's OTHER other half. The only binding fixture above (12d)
# points IT_RELEASE_BASE_URL at an unreachable .invalid host so that the
# whole run stays network-free, which also means verify.sh's own
# provenance step never verifies there: provenance_cargo_lock_sha256 stays
# unset, and verify.sh's second, independent binding comparison (the
# cargo_lock_sha256 block) is never reached by ANY test. If sbom.sh
# silently stopped emitting irontraffic:cargo_lock_sha256, or verify.sh's
# own comparison were simply deleted, every test in this file would stay
# green.
#
# Reaching it needs a verified provenance, which needs `cosign
# verify-blob-attestation` to succeed. A REAL Fulcio-issued signature is
# only obtainable inside GitHub Actions with an ambient OIDC token (see
# build_real_signed_fixture's own header, below), and even there,
# verify.sh's own --certificate-identity-regexp is pinned to refs/tags/v*
# only, which a same-repository pull request's own identity can never
# match (test 17's own subject) -- so a fixture built that way could never
# reach this comparison EITHER, on any pull request, ever. Neither
# obstacle has anything to do with what this pair of tests is actually
# checking: verify.sh's own LOCAL string comparison between two values it
# has already decoded, not cosign's cryptography. A `cosign` stub on PATH
# that unconditionally exits 0 for verify-blob-attestation takes the
# cryptography out of the way (the same technique used to probe this bug
# in the first place, and the same shape as this file's own `iuname` stub
# for install.sh's end-to-end test, above), while a hand-built,
# well-formed `<artifact>.intoto.bundle` supplies the DSSE payload
# verify.sh decodes and compares FOR REAL, straight from the local file --
# so this reaches the comparison for real, is free of network, and is free
# of any ambient GitHub Actions identity, unlike tests 14/15/17.
#
# build_cargo_lock_binding_fixture writes an artifact, a matching
# SHA256SUMS line, and a genuinely well-formed .intoto.bundle whose
# subject digest is the REAL sha256 of the artifact it just wrote (so
# verify.sh's own, un-stubbed digest comparison at step 3 passes for a
# genuine reason) and whose cargoLockSha256 is whatever the caller passed
# in; it does not build or place the SBOM itself, since the two tests below
# need different (matching vs. mismatching) SBOM-side values.
# ---------------------------------------------------------------------------
build_cargo_lock_binding_fixture() {
    dir="$1"
    provenance_cargo_lock_sha256="$2"
    mkdir -p "$dir/stub-bin"
    cat > "$dir/stub-bin/cosign" <<'EOF'
#!/bin/sh
# Stands in for a real cosign, for these two tests only (PATH-scoped):
# unconditionally accepts any verify-blob-attestation/verify-blob call.
# verify.sh decodes the actual binding data itself, straight out of the
# local .intoto.bundle's own DSSE payload, so this stub controls nothing
# about what is being compared -- only whether cosign's OWN cryptographic
# check (deliberately out of scope for these tests; see their header) is
# treated as having passed.
case "$1" in
    verify-blob-attestation|verify-blob) exit 0 ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$dir/stub-bin/cosign"

    artifact="$dir/irontraffic-9.9.9-x86_64-unknown-linux-musl.tar.gz"
    printf 'cargo-lock-binding fixture artifact content\n' > "$artifact"
    write_sha256sums_line "$artifact"

    artifact_sha256="$(sha256_of "$artifact")"
    payload_json="$(jq -n --arg sha "$artifact_sha256" --arg cl "$provenance_cargo_lock_sha256" '
        {
            subject: [ { digest: { sha256: $sha } } ],
            predicate: {
                invocation: {
                    configSource: {
                        digest: { sha1: "0000000000000000000000000000000000000000" },
                        uri: "git+https://github.com/ELares/IronTraffic@refs/heads/selftest-fixture"
                    },
                    parameters: { cargoLockSha256: $cl, dirty: "false" }
                },
                builder: { id: "https://github.com/ELares/IronTraffic/.github/workflows/ci.yml@refs/heads/selftest-fixture" }
            }
        }')"
    payload_b64="$(printf '%s' "$payload_json" | base64 | tr -d '\n')"
    jq -n --arg payload "$payload_b64" '{dsseEnvelope: {payload: $payload}}' > "$artifact.intoto.bundle"

    printf '%s' "$artifact" > "$dir/artifact-path.txt"
}

test_verify_binds_sbom_cargo_lock_sha256_matches() {
    dir="$WORK/cargo-lock-match-fixture"
    mkdir -p "$dir"
    printf 'selftest cargo lock fixture value (match)\n' > "$dir/lockval"
    cargo_lock_sha256="$(sha256_of "$dir/lockval")"
    build_cargo_lock_binding_fixture "$dir" "$cargo_lock_sha256"
    artifact="$(cat "$dir/artifact-path.txt")"

    sbom="$dir/irontraffic-9.9.9-x86_64-unknown-linux-musl.tar.gz.sbom.json"
    jq -n --arg target "x86_64-unknown-linux-musl" --arg cl "$cargo_lock_sha256" \
        '{"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json", bomFormat: "CycloneDX",
          specVersion: "1.6", version: 1,
          metadata: { properties: [ { name: "irontraffic:target", value: $target },
                                     { name: "irontraffic:cargo_lock_sha256", value: $cl } ] },
          components: []}' > "$sbom"

    out="$(PATH="$dir/stub-bin:$PATH" IT_RELEASE_BASE_URL="https://verify-cargo-lock-fixture.invalid/releases" \
        sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$artifact" --sbom "$sbom" --allow-skipped 2>&1)" && status=0 || status=$?
    if [ "$status" -ne 0 ]; then
        fail "verify_binds_sbom_cargo_lock_sha256_matches" "verify.sh failed despite a genuinely matching cargo_lock_sha256: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "provenance: verified"; then
        fail "verify_binds_sbom_cargo_lock_sha256_matches" "provenance did not verify, so the cargo_lock_sha256 comparison this test exists to reach was never even attempted: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "sbom binding: cargo_lock_sha256 matches the artifact's own provenance"; then
        fail "verify_binds_sbom_cargo_lock_sha256_matches" "cargo_lock_sha256 binding success line did not print: $out"
        return
    fi
    pass "verify_binds_sbom_cargo_lock_sha256_matches"
}

test_verify_binds_sbom_cargo_lock_sha256_mismatch() {
    dir="$WORK/cargo-lock-mismatch-fixture"
    mkdir -p "$dir"
    printf 'selftest cargo lock fixture value (provenance side)\n' > "$dir/lockval"
    provenance_cargo_lock_sha256="$(sha256_of "$dir/lockval")"
    build_cargo_lock_binding_fixture "$dir" "$provenance_cargo_lock_sha256"
    artifact="$(cat "$dir/artifact-path.txt")"

    printf 'selftest cargo lock fixture value (sbom side, DIFFERENT)\n' > "$dir/lockval-sbom"
    sbom_cargo_lock_sha256="$(sha256_of "$dir/lockval-sbom")"

    sbom="$dir/irontraffic-9.9.9-x86_64-unknown-linux-musl.tar.gz.sbom.json"
    jq -n --arg target "x86_64-unknown-linux-musl" --arg cl "$sbom_cargo_lock_sha256" \
        '{"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json", bomFormat: "CycloneDX",
          specVersion: "1.6", version: 1,
          metadata: { properties: [ { name: "irontraffic:target", value: $target },
                                     { name: "irontraffic:cargo_lock_sha256", value: $cl } ] },
          components: []}' > "$sbom"

    out="$(PATH="$dir/stub-bin:$PATH" IT_RELEASE_BASE_URL="https://verify-cargo-lock-fixture.invalid/releases" \
        sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$artifact" --sbom "$sbom" --allow-skipped 2>&1)" && status=0 || status=$?
    if [ "$status" -eq 0 ]; then
        fail "verify_binds_sbom_cargo_lock_sha256_mismatch" "verify.sh exited 0 despite a genuinely mismatching cargo_lock_sha256: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "sbom binding: sbom's cargo_lock_sha256"; then
        fail "verify_binds_sbom_cargo_lock_sha256_mismatch" "failure did not name the cargo_lock_sha256 binding check: $out"
        return
    fi
    pass "verify_binds_sbom_cargo_lock_sha256_mismatch"
}

# ---------------------------------------------------------------------------
# 12g. verify_checksum_tolerates_hash_in_directory_name
#
# verify.sh's checksum step used to pipe the awk selector's matched line
# through `sed "s#$sums_dir/##"` to strip a directory prefix that, per 12a's
# own header, a real SHA256SUMS line never actually carries: awk's exact
# `$2 == name` match can only ever succeed against a line whose second
# field ALREADY equals the bare basename. That `sed` used `#` as its own
# program delimiter while also interpolating $sums_dir, UNESCAPED, into
# that same program: a download directory whose own name contains a
# literal `#` broke the substitution, sed's own error was swallowed by
# `2>/dev/null`, $this_line came out empty, and a perfectly good artifact
# was reported "not listed in SHA256SUMS". Removing the (provably
# redundant; see 12a) sed entirely, rather than escaping it, is what this
# fixture guards: its own directory name is chosen specifically to contain
# `#`.
# ---------------------------------------------------------------------------
test_verify_checksum_tolerates_hash_in_directory_name() {
    dir="$WORK/hash#in#dirname"
    mkdir -p "$dir"
    artifact="$dir/irontraffic-9.9.9-x86_64-unknown-linux-musl.tar.gz"
    printf 'hash-in-dirname fixture artifact content\n' > "$artifact"
    write_sha256sums_line "$artifact"

    out="$(sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$artifact" --allow-skipped 2>&1)" && status=0 || status=$?
    if [ "$status" -ne 0 ]; then
        fail "verify_checksum_tolerates_hash_in_directory_name" "verify.sh failed against a genuine artifact merely because its own directory name contains '#': $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "checksum: done"; then
        fail "verify_checksum_tolerates_hash_in_directory_name" "checksum step did not report done: $out"
        return
    fi
    pass "verify_checksum_tolerates_hash_in_directory_name"
}

# ---------------------------------------------------------------------------
# 12h. verify_sbom_licence_check_skips_when_no_allowlist_found
#
# #788's own honest-degrade half, exercised on its own (12c above always
# has a deny.toml to find, so it never reaches sbom-licence-check.sh's
# exit-3 branch or verify.sh's handling of it). This fixture copies
# verify.sh and sbom-licence-check.sh into a bare directory but
# deliberately WITHOUT deny.toml or licence-exceptions.txt anywhere either
# beside them or two directories above (a fresh mktemp tree has neither):
# a good artifact and a well-formed SBOM must produce a named SKIP, never
# a FAILED line that reads as though the SBOM's own licence set was
# checked and found wanting.
# ---------------------------------------------------------------------------
test_verify_sbom_licence_check_skips_when_no_allowlist_found() {
    dir="$WORK/no-allowlist-fixture"
    mkdir -p "$dir"
    cp "$REPO_ROOT/scripts/release/verify.sh" "$dir/verify.sh"
    cp "$REPO_ROOT/scripts/release/sbom-licence-check.sh" "$dir/sbom-licence-check.sh"
    artifact_name="irontraffic-9.9.9-x86_64-unknown-linux-musl.tar.gz"
    sbom_name="$artifact_name.sbom.json"
    printf 'no-allowlist fixture artifact content\n' > "$dir/$artifact_name"
    jq -n --arg target "x86_64-unknown-linux-musl" \
        '{"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json", bomFormat: "CycloneDX",
          specVersion: "1.6", version: 1,
          metadata: { properties: [ { name: "irontraffic:target", value: $target } ] },
          components: []}' > "$dir/$sbom_name"
    ( cd "$dir" && write_sha256sums_line "$artifact_name" )

    out="$(cd "$dir" && sh verify.sh --artifact "$artifact_name" --sbom "$sbom_name" --allow-skipped 2>&1)" && status=0 || status=$?
    if [ "$status" -ne 0 ]; then
        fail "verify_sbom_licence_check_skips_when_no_allowlist_found" "verify.sh exited nonzero with --allow-skipped despite a missing allowlist being a SKIP, not a FAIL: $out"
        return
    fi
    if printf '%s' "$out" | grep -qi "FAILED: sbom licence"; then
        fail "verify_sbom_licence_check_skips_when_no_allowlist_found" "a missing allowlist was reported as a FAILED licence check (blaming the artifact) rather than a named skip: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "skipped: sbom licence"; then
        fail "verify_sbom_licence_check_skips_when_no_allowlist_found" "the missing allowlist produced no named skip line at all: $out"
        return
    fi
    pass "verify_sbom_licence_check_skips_when_no_allowlist_found"
}

# ---------------------------------------------------------------------------
# 12i. verify_sbom_licence_check_skips_when_exceptions_missing
#
# #791: 12c's own fixture always copies BOTH deny.toml and
# licence-exceptions.txt together, so it never reaches the specific case
# this test exists for -- deny.toml present, licence-exceptions.txt
# ABSENT -- and 12h's fixture copies NEITHER, so it never reaches it
# either. Before this fix, sbom-licence-check.sh's exceptions_file default
# fell through to a REPO_ROOT-derived path assigned UNCONDITIONALLY, with
# no [ -f ] test (the exact "two directories above me is the repository"
# assumption #788 fixed for deny_file but never carried over to
# exceptions_file), so main() proceeded past the missing-file check with
# an EMPTY exception set and accused this workspace's own aho-corasick,
# memchr and ryu -- real components of FIXTURE_SBOM, each allowlisted only
# via a committed exception; see docs/SUPPLY-CHAIN.md section 7 -- of a
# licence violation, by name: a false tamper alarm on a genuinely
# compliant artifact. Fetching deny.toml WITHOUT its co-required
# exceptions file is strictly WORSE than fetching neither, so it must
# degrade to the identical honest SKIP 12h asserts for the both-absent
# case, never silently check against an incomplete allowlist.
#
# FIXTURE_SBOM (the shared, REAL sbom.sh output generated once at the top
# of this file) is what makes this fixture genuine, unlike 12h's synthetic
# components:[] SBOM: it carries the three real dependencies that need
# the committed exception to pass, so this test can only pass for the
# right reason.
# ---------------------------------------------------------------------------
test_verify_sbom_licence_check_skips_when_exceptions_missing() {
    dir="$WORK/no-exceptions-fixture"
    mkdir -p "$dir"
    cp "$REPO_ROOT/scripts/release/verify.sh" "$dir/verify.sh"
    cp "$REPO_ROOT/scripts/release/sbom-licence-check.sh" "$dir/sbom-licence-check.sh"
    cp "$REPO_ROOT/deny.toml" "$dir/deny.toml"
    # Deliberately NOT copied here: licence-exceptions.txt. That is the
    # one difference from 12c's fixture, above, and the whole point of
    # this test.
    artifact_name="irontraffic-9.9.9-x86_64-unknown-linux-musl.tar.gz"
    sbom_name="$artifact_name.sbom.json"
    printf 'no-exceptions fixture artifact content\n' > "$dir/$artifact_name"
    cp "$FIXTURE_SBOM" "$dir/$sbom_name"
    ( cd "$dir" && write_sha256sums_line "$artifact_name" )

    out="$(cd "$dir" && sh verify.sh --artifact "$artifact_name" --sbom "$sbom_name" --allow-skipped 2>&1)" && status=0 || status=$?
    if [ "$status" -ne 0 ]; then
        fail "verify_sbom_licence_check_skips_when_exceptions_missing" "verify.sh exited nonzero with --allow-skipped despite deny.toml-found/exceptions-missing being a SKIP, not a FAIL: $out"
        return
    fi
    if printf '%s' "$out" | grep -qi "FAILED: sbom licence"; then
        fail "verify_sbom_licence_check_skips_when_exceptions_missing" "a missing licence-exceptions.txt was reported as a FAILED licence check (accusing a genuinely compliant component) rather than a named skip: $out"
        return
    fi
    if printf '%s' "$out" | grep -qE "aho-corasick|memchr|ryu"; then
        fail "verify_sbom_licence_check_skips_when_exceptions_missing" "a genuinely compliant component was named in the output at all, meaning the empty exception set was still checked against: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "skipped: sbom licence"; then
        fail "verify_sbom_licence_check_skips_when_exceptions_missing" "the missing exceptions file produced no named skip line at all: $out"
        return
    fi
    pass "verify_sbom_licence_check_skips_when_exceptions_missing"
}

# ---------------------------------------------------------------------------
# 13. verify_fails_when_a_check_is_skipped
#
# WHY THE DEFAULT IS A FAILURE, not a pass: the party able to serve a
# modified artifact is usually the party able to make the transparency log
# unreachable too, so "skipped, continuing" hands them exactly the outcome
# they were working towards. This fixture cannot literally cut this
# machine's network; it points verify.sh at a fabricated version number no
# real release has, so the signature and provenance companion files are
# genuinely unreachable (a 404 from the real release host), which exercises
# the identical "could not locate or download" code path a real network
# outage would.
# ---------------------------------------------------------------------------
test_verify_fails_when_a_check_is_skipped() {
    dir="$WORK/skip-fixture"
    mkdir -p "$dir"
    artifact="$dir/irontraffic-0.0.0-nonexistent-x86_64-unknown-linux-musl.tar.gz"
    printf 'fixture artifact content\n' > "$artifact"
    write_sha256sums_line "$artifact"

    default_out="$(sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$artifact" 2>&1)" && default_status=0 || default_status=$?
    if [ "$default_status" -eq 0 ]; then
        fail "verify_fails_when_a_check_is_skipped" "default invocation exited 0 with unreachable companion files"
        return
    fi
    if ! printf '%s' "$default_out" | grep -q "checksum: done"; then
        fail "verify_fails_when_a_check_is_skipped" "checksum was not reported done: $default_out"
        return
    fi
    if ! printf '%s' "$default_out" | grep -q "skipped: signature"; then
        fail "verify_fails_when_a_check_is_skipped" "signature was not reported skipped with a reason: $default_out"
        return
    fi

    allow_out="$(sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$artifact" --allow-skipped 2>&1)" && allow_status=0 || allow_status=$?
    if [ "$allow_status" -ne 0 ]; then
        fail "verify_fails_when_a_check_is_skipped" "--allow-skipped did not exit 0: $allow_out"
        return
    fi
    skip_line_count="$(printf '%s' "$allow_out" | grep -c '^skipped:')"
    if [ "$skip_line_count" -lt 2 ]; then
        fail "verify_fails_when_a_check_is_skipped" "--allow-skipped printed $skip_line_count skip line(s), want at least 2 (signature, provenance)"
        return
    fi

    sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$artifact" --strict >/dev/null 2>&1 && strict_status=0 || strict_status=$?
    if [ "$strict_status" -eq 0 ]; then
        fail "verify_fails_when_a_check_is_skipped" "--strict exited 0 with unreachable companion files"
        return
    fi
    pass "verify_fails_when_a_check_is_skipped"
}

# ---------------------------------------------------------------------------
# 13a. install_verifies_by_default
# ---------------------------------------------------------------------------
test_install_verifies_by_default() {
    if ! grep -Eq 'sh "\$verify_script".*--strict|verify\.sh.*--strict' "$REPO_ROOT/scripts/install.sh"; then
        fail "install_verifies_by_default" "install.sh no longer invokes verify.sh with --strict"
        return
    fi
    negative_grep="$(grep -n "verify-signature" "$REPO_ROOT/scripts/install.sh" || true)"
    if [ -z "$negative_grep" ]; then
        fail "install_verifies_by_default" "install.sh has no --no-verify-signature opt-out at all"
        return
    fi
    if printf '%s' "$negative_grep" | grep -qv "no-verify-signature"; then
        fail "install_verifies_by_default" "grep -n \"verify-signature\" install.sh shows more than the negative form:$negative_grep"
        return
    fi
    if grep -q "available once signing lands" "$REPO_ROOT/scripts/install.sh"; then
        fail "install_verifies_by_default" "install.sh still prints release-reproducible-build-and-artifacts's placeholder line"
        return
    fi

    # The real, end-to-end half: a local HTTPS fixture (install.sh refuses
    # anything that is not https, so the fixture must genuinely speak TLS,
    # the same reason release-selftest.sh's own install.sh fixture does)
    # serves a tarball with a CORRECT checksum and a REAL copy of
    # verify.sh, but no .bundle at all: this stands in for "the
    # signature does not check out" (the closest this offline test gets to
    # a literally tampered signature, since a real Fulcio-issued
    # certificate cannot be forged here; see this file's header) and
    # exercises the actual wiring, not just install.sh's own source text.
    if ! command -v openssl >/dev/null 2>&1; then
        skip "install_verifies_by_default (end-to-end)" "no openssl to run a local HTTPS fixture"
        return
    fi
    idir="$WORK/install-e2e"
    mkdir -p "$idir/certs" "$idir/releases"
    openssl req -x509 -newkey rsa:2048 -keyout "$idir/certs/key.pem" -out "$idir/certs/cert.pem" \
        -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1
    # install.sh refuses any non-Linux host by name before ever reaching a
    # network call (edge case 8), so on a macOS development machine (this
    # job's own CI runner is Linux, where this stub is a harmless no-op:
    # `uname` on ubuntu-latest already answers Linux/x86_64) this test would
    # otherwise fail for a reason that has nothing to do with what it is
    # actually checking. Same technique release-selftest.sh's own test 7
    # uses, in the opposite direction (there, to force an unsupported
    # answer; here, to force a supported one).
    iuname_dir="$idir/fake-uname"
    mkdir -p "$iuname_dir"
    cat > "$iuname_dir/uname" <<'EOF'
#!/bin/sh
case "$1" in
    -s) echo "Linux" ;;
    -m) echo "x86_64" ;;
    *) echo "unknown" ;;
esac
EOF
    chmod +x "$iuname_dir/uname"
    iversion="9.9.9"
    itarget="x86_64-unknown-linux-gnu"
    iasset="irontraffic-$iversion-$itarget.tar.gz"
    mkdir -p "$idir/stage/irontraffic-$iversion-$itarget"
    cat > "$idir/stage/irontraffic-$iversion-$itarget/irontraffic" <<'EOF'
#!/bin/sh
[ "$1" = "--version" ] && { echo "irontraffic 9.9.9 (selftest fixture)"; exit 0; }
exit 1
EOF
    chmod +x "$idir/stage/irontraffic-$iversion-$itarget/irontraffic"
    ( cd "$idir/stage" && tar -czf "$idir/releases/$iasset" "irontraffic-$iversion-$itarget" )
    ( cd "$idir/releases" && write_sha256sums_line "$iasset" )
    # A REAL release's SHA256SUMS also lists the SBOM
    # (ci.yml: `sha256sum *.tar.gz *.sbom.json > SHA256SUMS`), and
    # "$iasset" is a byte-for-byte PREFIX of "$iasset.sbom.json"; add that
    # second line (never served: install.sh never requests an SBOM on its
    # own, mirroring what a real default install actually downloads) so
    # this fixture exercises install.sh's own checksum-line selector
    # against the real, colliding shape, not an idealised one-line file.
    ( cd "$idir/releases" \
        && printf '{"decoy": "sbom, never served or downloaded by this test"}\n' > "$iasset.sbom.json" \
        && write_sha256sums_line "$iasset.sbom.json" \
        && rm -f "$iasset.sbom.json" )
    cp "$REPO_ROOT/scripts/release/verify.sh" "$idir/releases/verify.sh"

    iport=$((21000 + ($$ % 9000)))
    cat > "$idir/server.py" <<PYEOF
import http.server, ssl, os
RELEASES_DIR = "$idir/releases"
VERSION = "$iversion"
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/releases/latest":
            self.send_response(302)
            self.send_header("Location", "/releases/tag/v" + VERSION)
            self.end_headers()
            return
        prefix = "/releases/download/v" + VERSION + "/"
        if self.path.startswith(prefix):
            full = os.path.join(RELEASES_DIR, self.path[len(prefix):])
            if os.path.isfile(full):
                data = open(full, "rb").read()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
        self.send_response(404)
        self.end_headers()
    def log_message(self, fmt, *args):
        pass
server = http.server.HTTPServer(("127.0.0.1", $iport), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile="$idir/certs/cert.pem", keyfile="$idir/certs/key.pem")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PYEOF
    python3 "$idir/server.py" >"$idir/server.log" 2>&1 &
    iserver_pid=$!
    i=0
    ready=0
    while [ "$i" -lt 50 ]; do
        if CURL_CA_BUNDLE="$idir/certs/cert.pem" curl --proto '=https' --tlsv1.2 -fsS \
            "https://localhost:$iport/releases/latest" -o /dev/null 2>/dev/null; then
            ready=1
            break
        fi
        i=$((i + 1))
        sleep 0.1
    done
    if [ "$ready" -ne 1 ]; then
        kill "$iserver_pid" 2>/dev/null || true
        fail "install_verifies_by_default (end-to-end)" "local HTTPS fixture never became ready"
        return
    fi

    prefix_default="$idir/prefix-default"
    prefix_novrfy="$idir/prefix-noverify"
    # IT_VERSION carries the "v" prefix here (unlike the tests above that
    # never set it at all) because install.sh interpolates $version, not
    # the "v"-stripped asset_version, directly into the download URL path;
    # the fixture server's own routing expects that same "v9.9.9" segment,
    # matching the real release host's own /download/vX.Y.Z/ layout.
    default_out="$(PATH="$iuname_dir:$PATH" IT_VERSION="v$iversion" \
        CURL_CA_BUNDLE="$idir/certs/cert.pem" IT_RELEASE_BASE_URL="https://localhost:$iport/releases" \
        sh "$REPO_ROOT/scripts/install.sh" --prefix "$prefix_default" 2>&1)" && default_status=0 || default_status=$?
    novrfy_stderr="$idir/novrfy.stderr"
    novrfy_out="$(PATH="$iuname_dir:$PATH" IT_VERSION="v$iversion" \
        CURL_CA_BUNDLE="$idir/certs/cert.pem" IT_RELEASE_BASE_URL="https://localhost:$iport/releases" \
        sh "$REPO_ROOT/scripts/install.sh" --prefix "$prefix_novrfy" --no-verify-signature 2>"$novrfy_stderr")" && novrfy_status=0 || novrfy_status=$?
    kill "$iserver_pid" 2>/dev/null || true

    if [ "$default_status" -eq 0 ] || [ -e "$prefix_default/bin/irontraffic" ]; then
        fail "install_verifies_by_default (end-to-end)" "default (no flag) install succeeded despite no signature: $default_out"
        return
    fi
    if [ "$novrfy_status" -ne 0 ] || [ ! -e "$prefix_novrfy/bin/irontraffic" ]; then
        fail "install_verifies_by_default (end-to-end)" "--no-verify-signature install did not succeed: $novrfy_out"
        return
    fi
    if ! grep -qi "WARNING.*no-verify-signature" "$novrfy_stderr"; then
        fail "install_verifies_by_default (end-to-end)" "--no-verify-signature printed no warning on stderr naming what was skipped: $(cat "$novrfy_stderr")"
        return
    fi
    pass "install_verifies_by_default"
}

# ---------------------------------------------------------------------------
# 14 / 15: a real signed, attested fixture, produced only when this run
# actually has an ambient GitHub Actions OIDC identity (see this file's
# header). Built at most ONCE (cached in $WORK) and shared by both tests:
# `sign.sh`/`attest.sh` are real, slow, network round trips against the
# public Sigstore instance, and calling them twice bought nothing but risk.
#
# WHY THESE TWO TESTS DO NOT CALL verify.sh: verify.sh's own
# --certificate-identity-regexp is deliberately pinned to `refs/tags/v*`
# ONLY (see verify.sh's own header and docs/SUPPLY-CHAIN.md); a fixture
# signed by THIS test run, which is a pull-request run
# (".../ci.yml@refs/pull/N/merge"), can never match that pin, by design,
# the identical reason a real release signature could never be produced
# from a pull request either. Using verify.sh here would make this test
# either permanently fail on every pull request (the identity check is
# supposed to refuse it) or require weakening verify.sh's own pin, which is
# precisely the mistake this issue's whole design exists to prevent. These
# two tests instead verify with cosign directly, using a
# --certificate-identity-regexp built from THIS run's own
# GITHUB_WORKFLOW_REF, which proves the sign -> attest round trip itself
# works for real; verify_fails_without_identity_pin (test 11) is what
# proves the pin mechanism itself is load-bearing.
# State crosses into two FILES under $WORK, never shell variables: both
# tests below call this function as a plain statement (never inside
# `$(...)`), because command substitution forks a subshell, and a variable
# assigned INSIDE a function called that way never reaches the caller. Found
# exactly that way, on this issue's own real pull-request CI run: an
# artifact path and an identity regexp were both assigned as plain
# variables inside build_real_signed_fixture, called as
# `artifact="$(build_real_signed_fixture)"`, and the regexp variable read
# back empty in the caller, which made cosign refuse with "certificate
# identity ... is required for verification in keyless mode" against a
# perfectly valid, freshly-signed fixture.
REAL_FIXTURE_PATH_FILE="$WORK/real-fixture-path.txt"
REAL_FIXTURE_REGEXP_FILE="$WORK/real-fixture-regexp.txt"
REAL_FIXTURE_BUILT=0
REAL_FIXTURE_OK=1

build_real_signed_fixture() {
    if [ "$REAL_FIXTURE_BUILT" -eq 1 ]; then
        return "$REAL_FIXTURE_OK"
    fi
    REAL_FIXTURE_BUILT=1
    if ! have_actions_oidc; then
        REAL_FIXTURE_OK=1
        return 1
    fi
    fixture_dir="$WORK/real-signed"
    mkdir -p "$fixture_dir"
    # A real-shaped filename (not an arbitrary name): verify.sh's own
    # version-from-filename regex, exercised indirectly by other tests, is
    # part of what this fixture stands in for being a genuine release
    # artifact.
    artifact="$fixture_dir/irontraffic-0.0.0-selftest-fixture.tar.gz"
    printf 'supply-chain-selftest fixture, %s\n' "$(date -u +%s 2>/dev/null || echo 0)" > "$artifact"
    write_sha256sums_line "$artifact"
    if ! sh "$REPO_ROOT/scripts/release/sign.sh" "$artifact" >"$WORK/real-sign.log" 2>&1; then
        cat "$WORK/real-sign.log" >&2
        REAL_FIXTURE_OK=1
        return 1
    fi
    if ! sh "$REPO_ROOT/scripts/release/attest.sh" "$artifact" "$FIXTURE_TARGET" "control-plane" >"$WORK/real-attest.log" 2>&1; then
        cat "$WORK/real-attest.log" >&2
        REAL_FIXTURE_OK=1
        return 1
    fi
    # https://github.com/<GITHUB_WORKFLOW_REF> -> the certificate-identity
    # this run's own signature actually carries, mirroring attest.sh's own
    # builder_id construction. GITHUB_WORKFLOW_REF's only regex metachar is
    # ".", escaped before this is used as a --certificate-identity-regexp.
    escaped_workflow_ref="$(printf '%s' "$GITHUB_WORKFLOW_REF" | sed 's/\./\\./g')"
    printf '%s' "$artifact" > "$REAL_FIXTURE_PATH_FILE"
    printf '^https://github\\.com/%s$' "$escaped_workflow_ref" > "$REAL_FIXTURE_REGEXP_FILE"
    REAL_FIXTURE_OK=0
    return 0
}

test_verify_prints_source_commit() {
    if ! build_real_signed_fixture; then
        skip "verify_prints_source_commit" "no ambient GitHub Actions OIDC identity in this run"
        return
    fi
    artifact="$(cat "$REAL_FIXTURE_PATH_FILE")"
    identity_regexp="$(cat "$REAL_FIXTURE_REGEXP_FILE")"
    expected_commit="$(git rev-parse HEAD)"
    if ! cosign verify-blob-attestation \
        --bundle "$artifact.intoto.bundle" \
        --new-bundle-format \
        --certificate-identity-regexp "$identity_regexp" \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        --type slsaprovenance \
        "$artifact" >"$WORK/real-verify-attest.log" 2>&1; then
        fail "verify_prints_source_commit" "cosign verify-blob-attestation against this run's own real signature failed: $(cat "$WORK/real-verify-attest.log")"
        return
    fi
    payload="$(jq -r '.dsseEnvelope.payload' "$artifact.intoto.bundle" 2>/dev/null | base64 -d 2>/dev/null || true)"
    commit="$(printf '%s' "$payload" | jq -r '.predicate.invocation.configSource.digest.sha1 // empty' 2>/dev/null || true)"
    if [ "$commit" = "$expected_commit" ]; then
        pass "verify_prints_source_commit"
    else
        fail "verify_prints_source_commit" "provenance names commit \"$commit\", expected \"$expected_commit\""
    fi
}

test_provenance_subject_matches_digest() {
    if ! build_real_signed_fixture; then
        skip "provenance_subject_matches_digest" "no ambient GitHub Actions OIDC identity in this run"
        return
    fi
    artifact="$(cat "$REAL_FIXTURE_PATH_FILE")"
    actual_sha256="$(sha256_of "$artifact")"
    intoto_file="$artifact.intoto.bundle"
    if [ ! -s "$intoto_file" ]; then
        fail "provenance_subject_matches_digest" "no (or empty) .intoto.bundle produced alongside $artifact"
        return
    fi
    payload="$(jq -r '.dsseEnvelope.payload' "$intoto_file" 2>/dev/null | base64 -d 2>/dev/null || true)"
    if [ -z "$payload" ]; then
        fail "provenance_subject_matches_digest" "could not decode the DSSE payload in $intoto_file"
        return
    fi
    subject_sha256="$(printf '%s' "$payload" | jq -r '.subject[0].digest.sha256 // empty' 2>/dev/null || true)"
    if [ -n "$subject_sha256" ] && [ "$subject_sha256" = "$actual_sha256" ]; then
        pass "provenance_subject_matches_digest"
    else
        fail "provenance_subject_matches_digest" "subject digest ($subject_sha256) != artifact sha256 ($actual_sha256)"
    fi
}

# ---------------------------------------------------------------------------
# 17. verify_sh_fails_on_pr_identity_mismatch
#
# THE ROOT CAUSE this issue's own review named: verify.sh, the actual
# script a user runs, was never once invoked against a real Sigstore
# bundle by anything. Tests 14/15 above deliberately verify this run's own
# real signature with `cosign` directly, using an identity regexp read
# back from THIS run's own $GITHUB_WORKFLOW_REF, because a pull request's
# identity (".../ci.yml@refs/pull/N/merge") can never match verify.sh's own
# release pin (refs/tags/v*) -- see build_real_signed_fixture's header for
# why calling verify.sh there would either always fail for the right
# reason on every PR or require weakening the pin. This test is the
# resolution: it calls verify.sh itself, on purpose, expecting that exact,
# specific refusal, which is the only way available on a pull-request run
# to exercise verify.sh's real fetch (local, from this fixture's own
# directory), parse and cosign-bundle-loading code against a genuine
# signature at all. `.github/workflows/ci.yml`'s tag-only
# "Verify signature and provenance over the freshly signed dist/" step is
# the complementary SUCCESS-path exercise, over a real release identity,
# which only a tagged run can ever produce.
# ---------------------------------------------------------------------------
test_verify_sh_fails_on_pr_identity_mismatch() {
    if ! build_real_signed_fixture; then
        skip "verify_sh_fails_on_pr_identity_mismatch" "no ambient GitHub Actions OIDC identity in this run"
        return
    fi
    artifact="$(cat "$REAL_FIXTURE_PATH_FILE")"
    out="$(sh "$REPO_ROOT/scripts/release/verify.sh" --artifact "$artifact" --allow-skipped 2>&1)" && status=0 || status=$?
    if [ "$status" -eq 0 ]; then
        fail "verify_sh_fails_on_pr_identity_mismatch" "verify.sh exited 0 against this run's own real signature, whose certificate identity is a pull-request ref, not verify.sh's own refs/tags/v* pin: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "checksum: done"; then
        fail "verify_sh_fails_on_pr_identity_mismatch" "checksum did not pass first, so a later failure would not isolate the identity mismatch specifically: $out"
        return
    fi
    if ! printf '%s' "$out" | grep -q "signature: certificate identity did not match"; then
        fail "verify_sh_fails_on_pr_identity_mismatch" "failure did not name the certificate identity mismatch specifically (this is the one message that proves verify.sh's own cosign invocation, and its own pin, actually ran against a real bundle): $out"
        return
    fi
    pass "verify_sh_fails_on_pr_identity_mismatch"
}

test_sbom_is_valid_cyclonedx
test_sbom_is_reproducible
test_sbom_excludes_dev_dependencies
test_sbom_includes_vendored_c
test_sbom_ring_variant
test_sbom_every_component_has_a_purl
test_sbom_components_are_sorted_by_purl
test_licence_check_passes_on_real_sbom
test_licence_check_fails_on_injected_licence
test_licence_check_fails_on_missing_licence
test_licence_check_skips_on_zero_components
test_verify_fails_without_identity_pin
test_verify_fails_on_tampered_artifact
test_verify_checksum_ignores_sbom_substring_collision
test_verify_version_regex_handles_aarch64
test_verify_runs_standalone_outside_repo
test_verify_binds_sbom_to_artifact_target
test_verify_binds_sbom_cargo_lock_sha256_matches
test_verify_binds_sbom_cargo_lock_sha256_mismatch
test_verify_checksum_tolerates_hash_in_directory_name
test_verify_sbom_licence_check_skips_when_no_allowlist_found
test_verify_sbom_licence_check_skips_when_exceptions_missing
test_verify_fails_when_a_check_is_skipped
test_install_verifies_by_default
test_verify_prints_source_commit
test_provenance_subject_matches_digest
test_verify_sh_fails_on_pr_identity_mismatch

echo
echo "supply-chain-selftest: $((RAN - FAILED))/$RAN passed, $SKIPPED skipped"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
