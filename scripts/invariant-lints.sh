#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The invariant lints.
#
# These are the structural rules that the type system and clippy cannot express,
# and that a less experienced implementer will otherwise violate. Every lint here
# exists because it closes a specific, observed failure mode. Each one prints the
# offending file and line and explains the rule, so a failing run tells the
# implementer exactly what to do rather than just saying no.
#
# ESCAPE HATCH. A few rules have legitimate exceptions. The escape is always the
# same shape: the marker below on the SAME LINE, followed by a written reason.
# A bare marker with no reason does not suppress anything, so the escape can
# never be used to silently disable a rule, and it shows up in the diff as prose
# a reviewer must accept.
#
#   // it-allow: <rule-name> reason: <why this specific line is correct>
#
# Rules whose name ends in `-prod` run against copies of the sources with every
# `#[cfg(test)]` module body blanked out, so unit tests living beside the code
# they test do not trip production-only rules. Line numbers are preserved.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

FAILED=0
ESCAPE='it-allow:'
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
  local rule="$1" explain="$2" hits="$3"
  printf '\n%s\n' "FAIL [$rule]"
  printf '%s\n' "$explain" | sed 's/^/  /'
  printf '%s\n' "$hits" | sed 's/^/  /'
  FAILED=1
}

# All tracked Rust sources, excluding generated and vendored trees.
rust_files() {
  git ls-files -z -- '*.rs' | tr '\0' '\n' | grep -v -E '^(target|fuzz/target)/' || true
}

# Rust sources that are not wholly test code.
rust_non_test_files() {
  rust_files | grep -v -E '(^|/)(tests|benches|examples)/' | grep -v -E '_test\.rs$' || true
}

# Build, once, a shadow tree of the non-test sources with `#[cfg(test)]` module
# bodies replaced by blank lines. Same relative paths, same line numbers.
PROD_TREE=""
build_prod_tree() {
  [ -n "$PROD_TREE" ] && return 0
  PROD_TREE="$WORK/prod"
  mkdir -p "$PROD_TREE"
  rust_non_test_files | python3 -c '
import os, re, sys

OUT = sys.argv[1]
CFG = re.compile(r"#\[cfg\(\s*test\s*\)\]")

for rel in sys.stdin.read().split("\n"):
    if not rel:
        continue
    try:
        text = open(rel, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    chars = list(text)
    for m in CFG.finditer(text):
        # Find the module body that follows the attribute and blank it out,
        # preserving newlines so reported line numbers stay correct.
        i = text.find("{", m.end())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        for k in range(m.start(), min(j + 1, len(chars))):
            if chars[k] != "\n":
                chars[k] = " "
    dest = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write("".join(chars))
' "$PROD_TREE"
}

# Drop hits carrying a justified escape marker for this rule.
drop_escaped() {
  grep -v -E "${ESCAPE}[[:space:]]*$1[[:space:]]+reason:[[:space:]]*[^[:space:]]" || true
}

# scan <rule> <regex> <file-list-fn>   -- greps the real tree.
# `-H` is mandatory: without it grep omits the filename when given one file.
scan() {
  local rule="$1" pattern="$2"
  shift 2
  "$@" | tr '\n' '\0' | xargs -0 -r grep -HnE "$pattern" 2>/dev/null \
    | drop_escaped "$rule" || true
}

# scan_prod <rule> <regex>   -- greps the test-stripped shadow tree.
scan_prod() {
  local rule="$1" pattern="$2"
  build_prod_tree
  ( cd "$PROD_TREE" && find . -name '*.rs' -print0 | xargs -0 -r grep -HnE "$pattern" 2>/dev/null ) \
    | sed 's|^\./||' | drop_escaped "$rule" || true
}

# ---------------------------------------------------------------------------
# 1. no-stub: a stub that compiles is not a deliverable.
# ---------------------------------------------------------------------------
hits="$(scan no-stub '\b(todo!|unimplemented!)\s*\(' rust_files)"
[ -n "$hits" ] && fail no-stub \
"Every issue must ship a complete deliverable. todo!() and unimplemented!()
mean the work is not done. If you cannot finish, say so on the issue instead
of landing a placeholder that makes CI green." "$hits"

# ---------------------------------------------------------------------------
# 2. no-panic: the request path must not be able to kill the process.
#    Runs against the test-stripped tree so unit tests may assert freely.
# ---------------------------------------------------------------------------
hits="$(scan_prod no-panic '(\.unwrap\(\)|\.expect\(|\bpanic!\s*\(|\bunreachable!\s*\()')"
[ -n "$hits" ] && fail no-panic \
"Non-test code must not panic. A malformed request is a 4xx, an upstream
failure is a 5xx, a resource limit is a 429 or 503. Return an error instead.
If a case is genuinely unreachable, prove it in a comment and use the escape:
  // it-allow: no-panic reason: <proof that this cannot happen>" "$hits"

# ---------------------------------------------------------------------------
# 3. determinism-seam: one source of time and entropy, so tests are reproducible.
# ---------------------------------------------------------------------------
hits="$(scan_prod determinism-seam '(SystemTime::now|Instant::now|UNIX_EPOCH|\brand::|thread_rng|getrandom|OsRng|Utc::now|Local::now)' \
  | grep -vE '^crates/irontraffic-(time|rand)/' || true)"
[ -n "$hits" ] && fail determinism-seam \
"All wall-clock time, monotonic time, and entropy flows through the
irontraffic-time and irontraffic-rand seams. Direct access makes tests non-deterministic and makes
time-dependent bugs unreproducible. Take a Clock or Entropy handle instead." "$hits"

# ---------------------------------------------------------------------------
# 4. allow-needs-reason: a silenced lint must say why it was silenced.
# ---------------------------------------------------------------------------
hits="$(scan allow-needs-reason '#!?\[allow\(' rust_files | grep -v 'reason[[:space:]]*=' || true)"
[ -n "$hits" ] && fail allow-needs-reason \
"Every #[allow(...)] carries reason = \"...\" explaining why the lint is wrong
here. Silencing a lint without a reason is how real defects get hidden.
  #[allow(clippy::too_many_lines, reason = \"one cohesive dispatch loop\")]" "$hits"

# ---------------------------------------------------------------------------
# 5. no-ignored-tests: a skipped test proves nothing.
# ---------------------------------------------------------------------------
hits="$(scan no-ignored-tests '#\[ignore' rust_files)"
[ -n "$hits" ] && fail no-ignored-tests \
"A test marked #[ignore] does not run in CI, so it guarantees nothing. Either
make it run, or delete it and file an issue for the gap." "$hits"

# ---------------------------------------------------------------------------
# 6. no-vacuous-assert: an assertion that cannot fail is not a test.
# ---------------------------------------------------------------------------
hits="$(scan no-vacuous-assert '(assert!\s*\(\s*true\s*\)|assert!\s*\(\s*matches!\s*\([^,]+,\s*_\s*\))' rust_files)"
[ -n "$hits" ] && fail no-vacuous-assert \
"This assertion cannot fail, so the test asserts nothing. Assert on the actual
value the code under test produced." "$hits"

# ---------------------------------------------------------------------------
# 7. no-test-without-assertion: a test body that never asserts.
# ---------------------------------------------------------------------------
cat > "$WORK/no_assert.py" <<'PY'
import re, sys

FN = re.compile(r'#\[(?:tokio::)?test[^\]]*\]\s*(?:async\s+)?fn\s+(\w+)')
ASSERT = re.compile(
    r'(assert\w*!|should_panic|expect_err|unwrap_err|\.is_err\(\)|\.is_ok\(\)'
    r'|insta::|proptest!|panic!|\?;)'
)
out = []
for path in sys.argv[1:]:
    try:
        text = open(path, encoding='utf-8').read()
    except (OSError, UnicodeDecodeError):
        continue
    for m in FN.finditer(text):
        head = text[max(0, m.start() - 200):m.start()]
        if 'should_panic' in head:
            continue
        i = text.find('{', m.end())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(text):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if not ASSERT.search(text[i:j]):
            line = text[:m.start()].count('\n') + 1
            out.append(f'{path}:{line}: test `{m.group(1)}` contains no assertion')
print('\n'.join(out))
PY
hits="$(rust_files | tr '\n' '\0' | xargs -0 -r python3 "$WORK/no_assert.py" | grep -v '^$' || true)"
[ -n "$hits" ] && fail no-test-without-assertion \
"A test that runs code but never asserts on the result only proves the code did
not panic. State the expected value and assert it." "$hits"

# ---------------------------------------------------------------------------
# 8. no-swallowed-error: discarding a Result hides failures.
# ---------------------------------------------------------------------------
hits="$(scan_prod no-swallowed-error 'let\s+_\s*(:\s*[^=]+)?=\s*[a-zA-Z_][a-zA-Z0-9_:]*\s*\(')"
[ -n "$hits" ] && fail no-swallowed-error \
"Discarding a call result with \`let _ =\` hides errors. Handle it, propagate it
with ?, or log it with context. If discarding is genuinely correct, say why:
  // it-allow: no-swallowed-error reason: <why the failure is safe to drop>" "$hits"

# ---------------------------------------------------------------------------
# 9. no-blocking-in-async: a blocking call stalls a whole worker thread.
# ---------------------------------------------------------------------------
hits="$(scan_prod no-blocking-in-async '(std::thread::sleep|std::fs::(read|write|File|create|remove|copy|rename)|std::net::TcpStream::connect|to_socket_addrs|reqwest::blocking|std::io::stdin)')"
[ -n "$hits" ] && fail no-blocking-in-async \
"Blocking calls stall an entire async worker thread and every connection it
serves. Use the async equivalent, or move the work to spawn_blocking and say
so in a comment." "$hits"

# ---------------------------------------------------------------------------
# 10. unchecked-cast: length fields are attacker controlled.
#     Only clearly narrowing targets are flagged, to keep the signal high.
# ---------------------------------------------------------------------------
hits="$(scan_prod unchecked-cast '\bas\s+(u8|u16|u32|i8|i16|i32)\b')"
[ -n "$hits" ] && fail unchecked-cast \
"A narrowing \`as\` cast truncates silently, and values derived from network
input are attacker controlled. Use try_from with an explicit error, or prove
the bound:
  // it-allow: unchecked-cast reason: <proof of the bound>" "$hits"

# ---------------------------------------------------------------------------
# 11. constant-time-secrets: comparing a secret with == is a timing oracle.
# ---------------------------------------------------------------------------
hits="$(scan_prod constant-time-secrets '(secret|api_key|apikey|token|signature|hmac|password|credential)[a-z_]*\s*==')"
[ -n "$hits" ] && fail constant-time-secrets \
"Comparing a secret with == is a timing oracle. Use the constant-time
comparison helper (subtle::ConstantTimeEq) for every credential comparison." "$hits"

# ---------------------------------------------------------------------------
# 12/13. Hot path purity. A module whose header contains `//! HOT PATH` runs
#        once per request: no allocation, no locks.
# ---------------------------------------------------------------------------
hot_files() {
  build_prod_tree
  ( cd "$PROD_TREE" && find . -name '*.rs' -print0 \
      | xargs -0 -r grep -l '^//! HOT PATH' 2>/dev/null ) || true
}
hot_scan() {
  local rule="$1" pattern="$2"
  build_prod_tree
  ( cd "$PROD_TREE" && hot_files_inner() { :; }; find . -name '*.rs' -print0 \
      | xargs -0 -r grep -l '^//! HOT PATH' 2>/dev/null \
      | tr '\n' '\0' | xargs -0 -r grep -HnE "$pattern" 2>/dev/null ) \
    | sed 's|^\./||' | drop_escaped "$rule" || true
}

hits="$(hot_scan hot-path-allocation '(\bformat!\s*\(|\.to_string\(\)|\.to_owned\(\)|\.to_vec\(\)|\bvec!\s*\[|Vec::new\(\)|String::new\(\)|String::from\(|Box::new\(|HashMap::new\(|\.collect::<(Vec|String|HashMap)|\.clone\(\))')"
[ -n "$hits" ] && fail hot-path-allocation \
"This module is marked //! HOT PATH, so it runs once per request and must not
allocate. Borrow instead of cloning, use bytes::Bytes for shared buffers, write
into a reused buffer instead of formatting a new String, and take slices rather
than owned collections." "$hits"

hits="$(hot_scan hot-path-lock '(Mutex|RwLock|\.lock\(\)|\.read\(\)\.|\.write\(\)\.)')"
[ -n "$hits" ] && fail hot-path-lock \
"This module is marked //! HOT PATH. Locks on the request path serialize every
core. Read configuration from the arc_swap snapshot, shard mutable state per
core, or use an atomic." "$hits"

# ---------------------------------------------------------------------------
# 14. dependency-justification: every direct dependency explains itself.
# ---------------------------------------------------------------------------
hits="$(python3 - <<'PY' || true
import re, sys
try:
    lines = open('Cargo.toml', encoding='utf-8').read().splitlines()
except OSError:
    sys.exit(0)
in_deps, out = False, []
for i, line in enumerate(lines):
    s = line.strip()
    if s.startswith('['):
        in_deps = (s == '[workspace.dependencies]')
        continue
    if not in_deps or not s or s.startswith('#'):
        continue
    if not re.match(r'^[A-Za-z0-9_-]+\s*=', s):
        continue
    j = i - 1
    while j >= 0 and (not lines[j].strip() or lines[j].strip().startswith(']')):
        j -= 1
    if j < 0 or not lines[j].strip().startswith('#'):
        out.append(f'Cargo.toml:{i+1}: dependency `{s.split("=")[0].strip()}` has no justifying comment')
print('\n'.join(out))
PY
)"
hits="$(printf '%s' "$hits" | grep -v '^$' || true)"
[ -n "$hits" ] && fail dependency-justification \
"Every entry in [workspace.dependencies] carries a comment above it explaining
why the crate is in the tree, its license, and whether it keeps the musl static
build clean. The dependency tree is a security boundary and is reviewed." "$hits"

# ---------------------------------------------------------------------------
# 15. no-unsafe: denied workspace wide; checked here so a crate-level attribute
#     cannot quietly re-enable it.
# ---------------------------------------------------------------------------
hits="$(scan no-unsafe '(unsafe\s+(fn|impl|\{)|allow\(unsafe_code\))' rust_files)"
[ -n "$hits" ] && fail no-unsafe \
"unsafe is denied workspace wide. There is no exception an implementer is
authorized to make; raise it on the issue instead." "$hits"

# ---------------------------------------------------------------------------
if [ "$FAILED" -ne 0 ]; then
  printf '\ninvariant-lints: FAILED. Each block above names the rule, explains why it\n'
  printf 'exists, and lists the offending lines. Fix the code; do not silence a lint\n'
  printf 'unless you can write a reason a reviewer will accept.\n'
  exit 1
fi

echo "invariant-lints: clean"
