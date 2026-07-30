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
)"
    status=$?
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
    # verify.sh, but no .sig / .pem at all: this stands in for "the
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
REAL_FIXTURE_ARTIFACT=""
REAL_FIXTURE_IDENTITY_REGEXP=""

build_real_signed_fixture() {
    if [ -n "$REAL_FIXTURE_ARTIFACT" ]; then
        printf '%s' "$REAL_FIXTURE_ARTIFACT"
        return 0
    fi
    if ! have_actions_oidc; then
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
        return 1
    fi
    if ! sh "$REPO_ROOT/scripts/release/attest.sh" "$artifact" "$FIXTURE_TARGET" "control-plane" >"$WORK/real-attest.log" 2>&1; then
        cat "$WORK/real-attest.log" >&2
        return 1
    fi
    # https://github.com/<GITHUB_WORKFLOW_REF> -> the certificate-identity
    # this run's own signature actually carries, mirroring attest.sh's own
    # builder_id construction. GITHUB_WORKFLOW_REF's only regex metachar is
    # ".", escaped before this is used as a --certificate-identity-regexp.
    escaped_workflow_ref="$(printf '%s' "$GITHUB_WORKFLOW_REF" | sed 's/\./\\./g')"
    REAL_FIXTURE_IDENTITY_REGEXP="^https://github\\.com/${escaped_workflow_ref}\$"
    REAL_FIXTURE_ARTIFACT="$artifact"
    printf '%s' "$artifact"
}

test_verify_prints_source_commit() {
    artifact="$(build_real_signed_fixture)" || {
        skip "verify_prints_source_commit" "no ambient GitHub Actions OIDC identity in this run"
        return
    }
    expected_commit="$(git rev-parse HEAD)"
    if ! cosign verify-blob-attestation \
        --certificate "$artifact.pem" \
        --signature "$artifact.intoto.jsonl" \
        --certificate-identity-regexp "$REAL_FIXTURE_IDENTITY_REGEXP" \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        --type slsaprovenance \
        "$artifact" >"$WORK/real-verify-attest.log" 2>&1; then
        fail "verify_prints_source_commit" "cosign verify-blob-attestation against this run's own real signature failed: $(cat "$WORK/real-verify-attest.log")"
        return
    fi
    payload="$(jq -r '.payload' "$artifact.intoto.jsonl" 2>/dev/null | base64 -d 2>/dev/null || true)"
    commit="$(printf '%s' "$payload" | jq -r '.predicate.invocation.configSource.digest.sha1 // empty' 2>/dev/null || true)"
    if [ "$commit" = "$expected_commit" ]; then
        pass "verify_prints_source_commit"
    else
        fail "verify_prints_source_commit" "provenance names commit \"$commit\", expected \"$expected_commit\""
    fi
}

test_provenance_subject_matches_digest() {
    artifact="$(build_real_signed_fixture)" || {
        skip "provenance_subject_matches_digest" "no ambient GitHub Actions OIDC identity in this run"
        return
    }
    actual_sha256="$(sha256_of "$artifact")"
    intoto_file="$artifact.intoto.jsonl"
    if [ ! -s "$intoto_file" ]; then
        fail "provenance_subject_matches_digest" "no (or empty) .intoto.jsonl produced alongside $artifact"
        return
    fi
    payload="$(jq -r '.payload' "$intoto_file" 2>/dev/null | base64 -d 2>/dev/null || true)"
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
test_verify_fails_without_identity_pin
test_verify_fails_on_tampered_artifact
test_verify_fails_when_a_check_is_skipped
test_install_verifies_by_default
test_verify_prints_source_commit
test_provenance_subject_matches_digest

echo
echo "supply-chain-selftest: $((RAN - FAILED))/$RAN passed, $SKIPPED skipped"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
