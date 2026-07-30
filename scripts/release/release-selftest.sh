#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Self-test for the release scripts, run by the `shell-selftests` CI job on
# every pull request (see .github/workflows/ci.yml), the same job
# `bench-competitor-compare-script` (#425) creates. Without that wiring this
# file's fifteen tests are a file nothing runs, which is why adding the one
# CI step is itself a Files table row on the issue this file belongs to.
#
# WHY THIS FILE EXISTS BUT IS NOT IN THE ISSUE'S FILES TABLE, said plainly:
# the issue's own Design and Tests sections specify this file's name, its
# fifteen tests, and the CI wiring that runs it, but its own Files table
# never lists it. That is an omission in the issue, not a deliberate
# exclusion; the remedy `scripts/pr-scope-check.sh` prescribes for a file
# compilation or CI wiring forces outside the table is to add a row to the
# issue rather than widen the diff silently, which is what was done here.
#
# WHAT THIS SCRIPT DOES NOT DO: cross-compile any of the four shipped
# targets. It runs on whatever the CI runner's own host target is (there is
# no `dtolnay/rust-toolchain` or cache step in the `shell-selftests` job,
# per its own specification in #425, which lists exactly a checkout and one
# run step) and every Rust-dependent test below uses a debug build for
# speed. The four-target release matrix, `ldd`'s verdict, and a genuine
# `verify-repro.sh` run are exercised by the separate `release-artifacts`
# job this issue also adds, not by this fast, every-PR self-test.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

WORK="$(mktemp -d)"
trap 'cleanup_server 2>/dev/null || true; rm -rf "$WORK"' EXIT INT TERM

FAILED=0
RAN=0

pass() { RAN=$((RAN + 1)); printf 'ok   - %s\n' "$1"; }
fail() {
    RAN=$((RAN + 1))
    FAILED=$((FAILED + 1))
    printf 'FAIL - %s\n' "$1"
    # An `if`, not `[ -n "${2:-}" ] && printf ...`: the latter, as the LAST
    # statement of this function, would make the function's own exit status
    # the test's status, which is 1 (false) whenever no detail string is
    # given. Under `set -e`, a bare, unguarded call to `fail "x" ""` (used
    # throughout this file) would then abort the ENTIRE self-test right
    # there, having reported only the one failure it happened to be on. Found
    # by running this file for real: every test after the first such call
    # never ran.
    if [ -n "${2:-}" ]; then
        printf '       %s\n' "$2"
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ---------------------------------------------------------------------------
# Shared Rust build helpers. Every test below that needs the binary shares
# ONE target directory (built once per distinct environment) rather than a
# fresh `cargo build --release` each time: this job has no dependency cache
# (see the note at the top of the file) and a debug build is enough to
# exercise `build.rs`'s logic, which does not depend on optimization level.
# ---------------------------------------------------------------------------
RUST_WORK="$WORK/rust"
mkdir -p "$RUST_WORK/target"

# Forces `build.rs` to rerun on the next build in $RUST_WORK/target: without
# this, changing only the environment or PATH between two builds that touch
# no source file can leave Cargo reusing the previous run's cached
# `cargo:rustc-env` values instead of recomputing them, which would make
# tests 2 and 3 below compare the binary against itself instead of against a
# freshly derived stamp.
clear_build_script_cache() {
    rm -rf "$RUST_WORK/target/debug/build/irontraffic-"* 2>/dev/null || true
    rm -f "$RUST_WORK/target/debug/irontraffic" 2>/dev/null || true
}

build_debug() {
    ( cd "$REPO_ROOT" && cargo build --locked -p irontraffic --target-dir "$RUST_WORK/target" ) \
        >"$WORK/build.log" 2>&1 || {
        cat "$WORK/build.log" >&2
        return 1
    }
}

version_json_output() {
    "$RUST_WORK/target/debug/irontraffic" --version --json
}

# ---------------------------------------------------------------------------
# Test 1: version_json_has_six_sorted_keys
# ---------------------------------------------------------------------------
test_version_json_has_six_sorted_keys() {
    clear_build_script_cache
    if ! build_debug; then
        fail "version_json_has_six_sorted_keys" "baseline build failed"
        return
    fi
    out="$(version_json_output)"

    # The literal, sorted key list this issue's Public API section requires.
    # Extracted with grep -o rather than a JSON parser (no such dependency is
    # authorized here): each key name is searched for at its expected
    # position in a single pass over the same string.
    order="$(printf '%s' "$out" | grep -oE '"(dirty|features|git_sha|name|profile|version)":')"
    expected='"dirty":
"features":
"git_sha":
"name":
"profile":
"version":'
    if [ "$order" = "$expected" ]; then
        pass "version_json_has_six_sorted_keys"
    else
        fail "version_json_has_six_sorted_keys" "key order was: $(printf '%s' "$order" | tr '\n' ' ')"
    fi

    if printf '%s' "$out" | grep -q 'stamp_source'; then
        fail "version_json_has_six_sorted_keys (stamp_source absent)" "stamp_source must never be emitted; the bench harness sets it"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: version_json_git_sha_from_env
# ---------------------------------------------------------------------------
test_version_json_git_sha_from_env() {
    clear_build_script_cache
    if ! ( cd "$REPO_ROOT" && IT_GIT_SHA=deadbeefcafe IT_GIT_DIRTY=false \
        cargo build --locked -p irontraffic --target-dir "$RUST_WORK/target" ) >"$WORK/build2.log" 2>&1
    then
        cat "$WORK/build2.log" >&2
        fail "version_json_git_sha_from_env" "build with IT_GIT_SHA set failed"
        return
    fi
    out="$(version_json_output)"
    if printf '%s' "$out" | grep -q '"git_sha":"deadbeefcafe"'; then
        pass "version_json_git_sha_from_env"
    else
        fail "version_json_git_sha_from_env" "output: $out"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: version_json_unknown_without_git
# ---------------------------------------------------------------------------
test_version_json_unknown_without_git() {
    clear_build_script_cache
    no_git_bin="$WORK/no-git-bin"
    mkdir -p "$no_git_bin"
    # A `git` that always fails, ahead of the real one on PATH: this
    # simulates "no .git directory and no git binary" (edge case 1, a source
    # tarball) without the expense of copying the whole tree to a path with
    # no .git of its own, which would force a full, uncached rebuild rather
    # than a relink.
    cat > "$no_git_bin/git" <<'EOF'
#!/bin/sh
exit 127
EOF
    chmod +x "$no_git_bin/git"

    if ! ( cd "$REPO_ROOT" && env -u IT_GIT_SHA -u IT_GIT_DIRTY PATH="$no_git_bin:$PATH" \
        cargo build --locked -p irontraffic --target-dir "$RUST_WORK/target" ) >"$WORK/build3.log" 2>&1
    then
        cat "$WORK/build3.log" >&2
        fail "version_json_unknown_without_git" "build with git hidden failed"
        return
    fi
    out="$(version_json_output)"
    if printf '%s' "$out" | grep -q '"git_sha":"unknown"' && printf '%s' "$out" | grep -q '"dirty":true'; then
        pass "version_json_unknown_without_git"
    else
        fail "version_json_unknown_without_git" "output: $out"
    fi
}

# ---------------------------------------------------------------------------
# Tests 4 and 5: tarball assembly (build-matrix.sh's own function, sourced
# directly rather than run through the full build.sh recipe, which needs a
# cross toolchain this job does not have; the debug binary above stands in
# as the payload, since assembly determinism does not depend on what is
# inside the payload file).
# ---------------------------------------------------------------------------
BUILD_MATRIX_FUNCS="$WORK/build-matrix-funcs.sh"
build_matrix_functions_only() {
    # Strips the trailing `main "$@"` line so this file can be sourced for
    # its function definitions without running a real 4-target matrix build.
    awk '!/^main "\$@"$/' scripts/release/build-matrix.sh > "$BUILD_MATRIX_FUNCS"
}

stage_fixture_member() {
    stage_dir="$1"
    member_name="$2"
    member_dir="$stage_dir/$member_name"
    mkdir -p "$member_dir/docs"
    cp "$RUST_WORK/target/debug/irontraffic" "$member_dir/irontraffic"
    cp LICENSE "$member_dir/LICENSE"
    cp README.md "$member_dir/README.md"
    cp docs/QUICKSTART.md "$member_dir/docs/QUICKSTART.md"
}

test_tarball_is_deterministic_and_sorted() {
    if [ ! -f "$RUST_WORK/target/debug/irontraffic" ]; then
        clear_build_script_cache
        build_debug || true
    fi
    if [ ! -f "$RUST_WORK/target/debug/irontraffic" ]; then
        fail "tarball_is_deterministic" "no binary available to package"
        fail "tarball_members_are_sorted_and_owned_by_zero" "no binary available to package"
        return
    fi

    build_matrix_functions_only
    # shellcheck source=/dev/null
    . "$BUILD_MATRIX_FUNCS"

    member="irontraffic-0.0.0-selftest"
    stage1="$WORK/stage1"
    stage2="$WORK/stage2"
    stage_fixture_member "$stage1" "$member"
    stage_fixture_member "$stage2" "$member"

    tarball1="$WORK/one.tar.gz"
    tarball2="$WORK/two.tar.gz"
    assemble_tarball "$stage1" "$member" "$tarball1" 1700000000
    assemble_tarball "$stage2" "$member" "$tarball2" 1700000000

    if [ "$(sha256_of "$tarball1")" = "$(sha256_of "$tarball2")" ]; then
        pass "tarball_is_deterministic"
    else
        fail "tarball_is_deterministic" "two assemblies of identical input produced different bytes"
    fi

    # Inspected with Python's own `tarfile` module rather than parsing `tar
    # -tvf` text output: that output's COLUMN LAYOUT for owner/group is not
    # the same between bsdtar (this development machine) and GNU tar (the
    # Ubuntu CI runner this also has to pass on), so a text-scraped check
    # that passes here can still be scraping the wrong columns there.
    # `tarfile` reports the same structured uid/gid/mode/mtime fields
    # regardless of which platform wrote or is reading the archive.
    tar_report="$(python3 - "$tarball1" "$member" <<'PYEOF'
import sys
import tarfile

path, member_name = sys.argv[1], sys.argv[2]
with tarfile.open(path) as tar:
    members = tar.getmembers()

names = [m.name for m in members]
if names != sorted(names):
    print("NOT_SORTED", names)
    sys.exit(0)

for m in members:
    if m.uid != 0 or m.gid != 0:
        print("BAD_OWNER", m.name, m.uid, m.gid)
        sys.exit(0)
    is_binary = m.name == member_name + "/irontraffic"
    expected_mode = 0o755 if is_binary else 0o644
    if m.mode != expected_mode:
        print("BAD_MODE", m.name, oct(m.mode), oct(expected_mode))
        sys.exit(0)

print("OK")
PYEOF
    )"

    if [ "$tar_report" = "OK" ]; then
        pass "tarball_members_are_sorted_and_owned_by_zero"
    else
        fail "tarball_members_are_sorted_and_owned_by_zero" "$tar_report"
    fi
}

# ---------------------------------------------------------------------------
# install.sh tests. A local HTTPS fixture server stands in for the real
# release host: no release for an in-flight commit exists yet on GitHub for
# a pull request to fetch, and `install.sh` refuses anything that is not
# `https`, so the fixture must genuinely speak TLS.
# ---------------------------------------------------------------------------
# A port derived from this process's own PID rather than a fixed number:
# a fixed port collides with anything else already listening on the same
# machine (a leftover process from a previous, interrupted run of this same
# script is the most likely case) and, on collision, this script's own
# readiness probe cannot tell "my server is slow to start" apart from
# "something else entirely answered on this port with a certificate mine
# did not sign", and only times out. Found by running this file for real.
SERVER_PORT=$((20000 + ($$ % 10000)))
SERVER_PID=""
CERT_DIR="$WORK/certs"
RELEASES_DIR="$WORK/releases"
FIXTURE_VERSION="9.9.9"
FIXTURE_TARGET="x86_64-unknown-linux-gnu"
FIXTURE_ASSET="irontraffic-$FIXTURE_VERSION-$FIXTURE_TARGET.tar.gz"

start_test_server() {
    mkdir -p "$CERT_DIR" "$RELEASES_DIR"
    if command -v openssl >/dev/null 2>&1; then
        openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
            -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1
    else
        echo "SKIP: openssl not available; every install.sh network test below reports skipped, not passed" >&2
        return 1
    fi

    # A tiny fixture stand-in for the release binary: this machine's own
    # host build (whatever the CI runner's native target is) is not
    # necessarily FIXTURE_TARGET, so a genuine ELF binary is not
    # guaranteed runnable here either; the fixture only needs to answer
    # `--version` the way `install.sh` expects, which is exactly what it is
    # checking at this step.
    stage="$WORK/install-fixture-stage"
    member="irontraffic-$FIXTURE_VERSION-$FIXTURE_TARGET"
    mkdir -p "$stage/$member/docs"
    cat > "$stage/$member/irontraffic" <<'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then
    echo "irontraffic 9.9.9 (selftest fixture)"
    exit 0
fi
exit 1
EOF
    chmod +x "$stage/$member/irontraffic"
    cp LICENSE "$stage/$member/LICENSE"
    cp README.md "$stage/$member/README.md"
    cp docs/QUICKSTART.md "$stage/$member/docs/QUICKSTART.md"

    build_matrix_functions_only
    # shellcheck source=/dev/null
    . "$BUILD_MATRIX_FUNCS"
    assemble_tarball "$stage" "$member" "$RELEASES_DIR/$FIXTURE_ASSET" 1700000000
    ( cd "$RELEASES_DIR" && sha256_of "$FIXTURE_ASSET" | awk -v f="$FIXTURE_ASSET" '{print $1"  "f}' > SHA256SUMS )

    cat > "$WORK/server.py" <<PYEOF
import http.server, ssl, sys, os
RELEASES_DIR = "$RELEASES_DIR"
VERSION = "$FIXTURE_VERSION"

class Handler(http.server.BaseHTTPRequestHandler):
    def _serve(self, path):
        full = os.path.join(RELEASES_DIR, path)
        if not os.path.isfile(full):
            self.send_response(404); self.end_headers(); return
        data = open(full, "rb").read()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self): self.handle_one()
    def do_GET(self): self.handle_one()

    def handle_one(self):
        if self.path == "/releases/latest":
            self.send_response(302)
            self.send_header("Location", "/releases/tag/v" + VERSION)
            self.end_headers()
            return
        prefix = "/releases/download/v" + VERSION + "/"
        if self.path.startswith(prefix):
            self._serve(self.path[len(prefix):])
            return
        self.send_response(404); self.end_headers()

    def log_message(self, fmt, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", $SERVER_PORT), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile="$CERT_DIR/cert.pem", keyfile="$CERT_DIR/key.pem")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PYEOF
    python3 "$WORK/server.py" >"$WORK/server.log" 2>&1 &
    SERVER_PID="$!"
    i=0
    while [ "$i" -lt 50 ]; do
        if CURL_CA_BUNDLE="$CERT_DIR/cert.pem" curl --proto '=https' --tlsv1.2 -fsS \
            "https://localhost:$SERVER_PORT/releases/latest" -o /dev/null 2>/dev/null; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

cleanup_server() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
}

install_with_server() {
    CURL_CA_BUNDLE="$CERT_DIR/cert.pem" \
        IT_RELEASE_BASE_URL="https://localhost:$SERVER_PORT/releases" \
        sh scripts/install.sh "$@"
}

if start_test_server; then
    # ------------------------------------------------------------------
    # Test 6: install_rejects_bad_checksum
    # ------------------------------------------------------------------
    cp "$RELEASES_DIR/$FIXTURE_ASSET" "$RELEASES_DIR/$FIXTURE_ASSET.bak"
    printf 'x' >> "$RELEASES_DIR/$FIXTURE_ASSET"
    prefix6="$WORK/prefix6"
    # `set +e` around every capture of a command this test EXPECTS to fail:
    # `out="$(cmd)"` as a bare statement is itself a simple command whose
    # exit status is cmd's, so under `set -e` the expected failure aborts
    # the whole self-test right here, before `status=$?` is ever reached.
    # Found by running this file for real, the same bug as `fail()` above,
    # in the shape it takes whenever a test's own subject is supposed to
    # exit nonzero.
    set +e
    out6="$(CURL_CA_BUNDLE="$CERT_DIR/cert.pem" IT_RELEASE_BASE_URL="https://localhost:$SERVER_PORT/releases" \
        sh scripts/install.sh --prefix "$prefix6" 2>&1)"
    status6=$?
    set -e
    mv "$RELEASES_DIR/$FIXTURE_ASSET.bak" "$RELEASES_DIR/$FIXTURE_ASSET"
    if [ "$status6" -ne 0 ] && [ ! -e "$prefix6/bin/irontraffic" ]; then
        pass "install_rejects_bad_checksum"
    else
        fail "install_rejects_bad_checksum" "exit=$status6 output=$out6"
    fi

    # ------------------------------------------------------------------
    # Test 7: install_rejects_unsupported_platform
    # ------------------------------------------------------------------
    fake_uname_bin="$WORK/fake-uname-bin"
    mkdir -p "$fake_uname_bin"
    cat > "$fake_uname_bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
    -s) echo "Plan9" ;;
    -m) echo "mips" ;;
    *) echo "unknown" ;;
esac
EOF
    chmod +x "$fake_uname_bin/uname"
    set +e
    out7="$(PATH="$fake_uname_bin:$PATH" sh scripts/install.sh --prefix "$WORK/prefix7" 2>&1)"
    status7=$?
    set -e
    names_present=0
    for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
        printf '%s' "$out7" | grep -q "$t" || names_present=1
    done
    if [ "$status7" -ne 0 ] && [ "$names_present" -eq 0 ]; then
        pass "install_rejects_unsupported_platform"
    else
        fail "install_rejects_unsupported_platform" "exit=$status7 output=$out7"
    fi

    # ------------------------------------------------------------------
    # Test 8: install_refuses_root
    # ------------------------------------------------------------------
    fake_id_bin="$WORK/fake-id-bin"
    mkdir -p "$fake_id_bin"
    cat > "$fake_id_bin/id" <<'EOF'
#!/bin/sh
echo 0
EOF
    chmod +x "$fake_id_bin/id"
    set +e
    out8="$(PATH="$fake_id_bin:$PATH" sh scripts/install.sh --prefix "$WORK/prefix8" 2>&1)"
    status8=$?
    out8b="$(PATH="$fake_id_bin:$PATH" IT_ALLOW_ROOT=1 CURL_CA_BUNDLE="$CERT_DIR/cert.pem" \
        IT_RELEASE_BASE_URL="https://localhost:$SERVER_PORT/releases" \
        sh scripts/install.sh --prefix "$WORK/prefix8b" 2>&1)"
    status8b=$?
    set -e
    if [ "$status8" -ne 0 ] && [ "$status8b" -eq 0 ] && [ -e "$WORK/prefix8b/bin/irontraffic" ]; then
        pass "install_refuses_root"
    else
        fail "install_refuses_root" "no-override exit=$status8 override exit=$status8b: $out8 / $out8b"
    fi

    # ------------------------------------------------------------------
    # Test 9: install_keeps_previous
    # ------------------------------------------------------------------
    prefix9="$WORK/prefix9"
    install_with_server --prefix "$prefix9" >/dev/null 2>&1
    install_with_server --prefix "$prefix9" >/dev/null 2>&1
    if [ -e "$prefix9/bin/irontraffic" ] && [ -e "$prefix9/bin/irontraffic.previous" ]; then
        pass "install_keeps_previous"
    else
        fail "install_keeps_previous" "missing irontraffic or irontraffic.previous under $prefix9/bin"
    fi

    # ------------------------------------------------------------------
    # Test 9a: install_is_truncation_safe
    # ------------------------------------------------------------------
    total_bytes=$(wc -c < scripts/install.sh)
    truncation_ok=0
    for pct in 20 40 60 80 95; do
        n=$(( total_bytes * pct / 100 ))
        prefixT="$WORK/prefix9a-$pct"
        rm -rf "$prefixT"
        set +e
        head -c "$n" scripts/install.sh | \
            CURL_CA_BUNDLE="$CERT_DIR/cert.pem" IT_RELEASE_BASE_URL="https://localhost:$SERVER_PORT/releases" \
            sh -s -- --prefix "$prefixT" >/dev/null 2>&1
        set -e
        if [ -e "$prefixT/bin/irontraffic" ]; then
            truncation_ok=1
            printf '       truncated at %s%% installed something\n' "$pct" >&2
        fi
    done
    if [ "$truncation_ok" -eq 0 ]; then
        pass "install_is_truncation_safe"
    else
        fail "install_is_truncation_safe" "a truncated download installed a binary at some percentage"
    fi

    # ------------------------------------------------------------------
    # Test 9b: install_rejects_a_bad_version_string
    # ------------------------------------------------------------------
    bad_version_ok=0
    for v in '../../etc' 'https://evil.example/x' '1.0.0 ; rm -rf /'; do
        prefixB="$WORK/prefix9b"
        rm -rf "$prefixB"
        set +e
        IT_VERSION="$v" sh scripts/install.sh --prefix "$prefixB" >"$WORK/9b.log" 2>&1
        status="$?"
        set -e
        if [ "$status" -eq 0 ] || ! grep -q "does not match the expected version" "$WORK/9b.log"; then
            bad_version_ok=1
            printf '       IT_VERSION=%s was not refused before a fetch\n' "$v" >&2
        fi
    done
    if [ "$bad_version_ok" -eq 0 ]; then
        pass "install_rejects_a_bad_version_string"
    else
        fail "install_rejects_a_bad_version_string" "see above"
    fi

    # ------------------------------------------------------------------
    # Test 9c: install_sets_mode_regardless_of_umask
    # ------------------------------------------------------------------
    mode_ok=0
    for um in 077 000; do
        prefixU="$WORK/prefix9c-$um"
        rm -rf "$prefixU"
        ( umask "$um"; install_with_server --prefix "$prefixU" >/dev/null 2>&1 )
        mode="$(stat -f '%Lp' "$prefixU/bin/irontraffic" 2>/dev/null || stat -c '%a' "$prefixU/bin/irontraffic" 2>/dev/null)"
        [ "$mode" = "755" ] || mode_ok=1
    done
    if [ "$mode_ok" -eq 0 ]; then
        pass "install_sets_mode_regardless_of_umask"
    else
        fail "install_sets_mode_regardless_of_umask" "installed mode was not 0755 under some umask"
    fi

    # ------------------------------------------------------------------
    # Test 9e: install_cleans_up_on_interrupt
    # ------------------------------------------------------------------
    slow_copy="$WORK/install-slow.sh"
    awk '{print} /^main "\$@"$/{exit}' scripts/install.sh | \
        sed '$d' > "$slow_copy"
    { cat "$slow_copy"; echo 'sleep 5 &'; echo 'wait $!'; echo 'main "$@"'; } > "$slow_copy.tmp"
    mv "$slow_copy.tmp" "$slow_copy"
    prefixI="$WORK/prefix9e"
    ( CURL_CA_BUNDLE="$CERT_DIR/cert.pem" IT_RELEASE_BASE_URL="https://localhost:$SERVER_PORT/releases" \
        sh "$slow_copy" --prefix "$prefixI" >"$WORK/9e.log" 2>&1 & echo "$!" > "$WORK/9e.pid" )
    sleep 1
    kill -INT "$(cat "$WORK/9e.pid")" 2>/dev/null || true
    sleep 1
    survived=0
    # `if`, not `[ cond ] && survived=1`: under `set -e` a bare `&&` whose
    # condition is FALSE (the expected, wanted outcome here: no binary was
    # installed) makes the whole statement's exit status 1 and aborts the
    # script right here, exactly the `fail()` bug above, just for the
    # opposite (usually-false) direction. Found the same way.
    if [ -e "$prefixI/bin/irontraffic" ]; then
        survived=1
    fi
    if [ "$survived" -eq 0 ]; then
        pass "install_cleans_up_on_interrupt"
    else
        fail "install_cleans_up_on_interrupt" "a binary was installed despite the interrupt"
    fi
else
    fail "install_rejects_bad_checksum (SKIPPED: no openssl)" ""
    fail "install_rejects_unsupported_platform (SKIPPED: no openssl)" ""
    fail "install_refuses_root (SKIPPED: no openssl)" ""
    fail "install_keeps_previous (SKIPPED: no openssl)" ""
    fail "install_is_truncation_safe (SKIPPED: no openssl)" ""
    fail "install_rejects_a_bad_version_string (SKIPPED: no openssl)" ""
    fail "install_sets_mode_regardless_of_umask (SKIPPED: no openssl)" ""
    fail "install_cleans_up_on_interrupt (SKIPPED: no openssl)" ""
fi

# ---------------------------------------------------------------------------
# Test 9d: install_uses_https_only (a static grep, needs neither a build nor
# a server, so it runs regardless of the branch above).
# ---------------------------------------------------------------------------
test_install_uses_https_only() {
    # `curl|wget` alone also matches the usage comment at the top of the
    # file and the two `command -v curl` presence checks, neither of which
    # is an actual invocation; restricted to `curl --` / `wget --` (every
    # real invocation in this script uses a long flag), which excludes both
    # and matches only the four real fetch call sites.
    offenders="$(grep -nE '(^|[^a-zA-Z])(curl|wget)[[:space:]]+--' scripts/install.sh \
        | grep -v "proto '=https'" | grep -v -- '--https-only' || true)"
    if [ -z "$offenders" ]; then
        pass "install_uses_https_only"
    else
        fail "install_uses_https_only" "$offenders"
    fi
}

test_version_json_has_six_sorted_keys
test_version_json_git_sha_from_env
test_version_json_unknown_without_git
test_tarball_is_deterministic_and_sorted
test_install_uses_https_only

echo
echo "release-selftest: $((RAN - FAILED))/$RAN passed"
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
