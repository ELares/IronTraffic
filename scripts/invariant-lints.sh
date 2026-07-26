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
# Allowlist files: one repository-relative path per line, blank lines and `#`
# comments ignored. Matching is EXACT path equality only, never a prefix, a
# suffix, a glob, or a directory: an entry that names a directory or a stale
# path matches nothing and is reported by allowlist_stale_hits, because an
# exemption nobody re-reads is worse than no exemption.
# ---------------------------------------------------------------------------

# allowlist_entries <file> -- trimmed, non-blank, non-comment lines.
allowlist_entries() {
  local f="$1"
  [ -f "$f" ] || return 0
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$f" 2>/dev/null | grep -v -E '^(#|$)' || true
}

# allowlisted <file> <path> -- true if <path> exactly matches a listed entry.
allowlisted() {
  allowlist_entries "$1" | grep -qxF "$2"
}

# drop_allowlisted <file> -- reads "path:line:..." hits on stdin, drops any
# whose path (the text before the first colon) exactly matches an entry.
drop_allowlisted() {
  local allow="$1" line path
  while IFS= read -r line; do
    path="${line%%:*}"
    allowlisted "$allow" "$path" || printf '%s\n' "$line"
  done
}

# allowlist_stale_hits <file> -- one "file:line: message" per entry that is
# not the exact repository-relative path of a tracked Rust source file. A
# directory, a prefix, a deleted file, or a path with stray whitespace all
# fail this the same way: they match nothing, so they are reported rather
# than silently treated as exemptions.
allowlist_stale_hits() {
  local allow="$1"
  [ -f "$allow" ] || return 0
  local valid lineno=0 raw trimmed
  valid="$(rust_files)"
  while IFS= read -r raw; do
    lineno=$((lineno + 1))
    trimmed="$(printf '%s' "$raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -z "$trimmed" ] && continue
    case "$trimmed" in '#'*) continue ;; esac
    if ! printf '%s\n' "$valid" | grep -qxF "$trimmed"; then
      printf '%s:%d: stale allowlist entry %s does not name a tracked file\n' "$allow" "$lineno" "$trimmed"
    fi
  done < "$allow"
}

# ---------------------------------------------------------------------------
# Hot-path CRATE scope, used by balance-drop-only and interior-mutability.
# This is NOT hot_scan and the `//! HOT PATH` header above: a balance or a
# cell can live in a file nobody remembered to mark, so this is a path
# predicate over a fixed list of crate directories rather than a per-file
# opt-in. Do not fold this into hot_scan and do not change the two rules that
# use hot_scan. The directory list is a literal here, matched as a path
# prefix, because it names a crate directory rather than an exemption; later
# milestones add their own crates to it in their own issues.
# ---------------------------------------------------------------------------
hotpath_crate_files() {
  build_prod_tree
  ( cd "$PROD_TREE" && find . -name '*.rs' -print0 ) | tr '\0' '\n' | sed 's|^\./||' \
    | while IFS= read -r rel; do
        case "$rel" in
          crates/irontraffic-io/*|crates/irontraffic-runtime/*|crates/irontraffic-conn/*|crates/irontraffic-upstream/*|crates/irontraffic-dataplane/*)
            printf '%s\n' "$rel" ;;
        esac
      done
}

# hotpath_crate_scan <rule> <pattern> -- like scan_prod, restricted to the
# hot-path crate scope above.
hotpath_crate_scan() {
  local rule="$1" pattern="$2"
  build_prod_tree
  hotpath_crate_files | tr '\n' '\0' \
    | ( cd "$PROD_TREE" && xargs -0 -r grep -HnE "$pattern" 2>/dev/null ) \
    | drop_escaped "$rule" || true
}

# balance_drop_only_hits -- the balance-drop-only rule's file-level scan. A
# monotone counter may lose an increment; a balance may not, so this checks a
# whole file rather than trying to prove a given fetch_sub sits inside a Drop
# body, which grep cannot express.
#
# BALANCE_PATTERN also catches fetch_add(TYPE::MAX, ...): adding a type's
# maximum value wraps an unsigned integer by exactly -1, so `fetch_add(u32::
# MAX, ...)` IS a decrement spelled to dodge a fetch_sub grep. An ordinary
# incrementing fetch_add (no ::MAX operand) is left alone on purpose: treating
# every fetch_add like fetch_sub would demand a Drop impl on every plain
# monotone counter in a hot-path crate, which is not what this rule guards.
#
# ::MAX must be the WHOLE first argument (identifier(s), "::MAX", then a
# comma), not merely present somewhere before the first close-paren. A naive
# `[^)]*::MAX` matches straight through a nested call, so a genuine saturating
# increment like `fetch_add(n.min(usize::MAX - current), Ordering::Relaxed)`
# would falsely fire: its first argument is `n.min(...)`, and the `::MAX`
# sits inside that nested call's own argument, not as the top-level operand
# fetch_add receives. Requiring the identifier-then-"::MAX"-then-comma shape
# to start immediately after the open paren rules that out, because the
# nested call's dot and parenthesis break the shape before "::MAX" is ever
# reached.
#
# ACCEPTED GAP (documented, not fixed): this is a file-level, five-crate-
# scoped grep. Known evasions out of reach of a text search:
#   1. A decrement wrapped some OTHER way (wrapping_sub, a hand-rolled
#      negative-cast fetch_add, a MAX literal wrapped in its own cast or
#      parenthesised expression) that does not spell a bare TYPE::MAX first
#      argument.
#   2. The decrement moved into a helper or extension-trait method defined in
#      a crate OUTSIDE the five scanned directories, so the balance-owning
#      struct's file never contains the text `fetch_add` or `fetch_sub` at
#      all. Seeing through that requires tracking which crate defines a
#      "balance type" and where its release method is called, which is a
#      cross-crate type-flow question, not a grep. Review is the second line
#      of defense here, exactly as it already is for the Drop-body-membership
#      question this rule was always coarse about.
BALANCE_PATTERN='fetch_sub|fetch_add\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*::MAX[[:space:]]*,'
balance_drop_only_hits() {
  build_prod_tree
  hotpath_crate_files | while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    grep -qE "$BALANCE_PATTERN" "$PROD_TREE/$rel" 2>/dev/null || continue
    grep -q 'impl Drop for' "$PROD_TREE/$rel" 2>/dev/null && continue
    allowlisted scripts/allowlist-balance.txt "$rel" && continue
    grep -nE "$BALANCE_PATTERN" "$PROD_TREE/$rel" 2>/dev/null | sed "s|^|$rel:|"
  done
  allowlist_stale_hits scripts/allowlist-balance.txt
}

# ---------------------------------------------------------------------------
# 16. transport-seam: the data plane is generic over hyper::rt::Read/Write, so
#     tokio may be named directly only in the two crates that implement the
#     seam. Without this rule the runtime is theoretically swappable rather
#     than actually swappable, and the seam rots in about three months.
# ---------------------------------------------------------------------------
hits="$(scan_prod transport-seam '(^|[^A-Za-z_])tokio::|^[[:space:]]*use tokio' \
  | grep -vE '^crates/irontraffic-(io|runtime)/' || true)"
[ -n "$hits" ] && fail transport-seam \
"tokio:: and \`use tokio\` are permitted only in crates/irontraffic-io and
crates/irontraffic-runtime, the two crates that implement the transport seam.
Everywhere else, reach the runtime through irontraffic_io::Transport
(hyper::rt::Read + hyper::rt::Write) instead of naming tokio directly, so the
runtime stays actually swappable rather than theoretically so:
  // it-allow: transport-seam reason: <why this file is the seam itself>" "$hits"

# ---------------------------------------------------------------------------
# 17. no-unbounded-channel: an unbounded queue between the read half and the
#     write half of a proxied connection is precisely the out-of-memory
#     failure the forwarding design exists to prevent, and it is the single
#     most likely thing an inexperienced implementer writes because it makes
#     the borrow checker happy.
#
#     The bare-constructor alternative tolerates an optional turbofish
#     (::<T>) between the identifier and the paren, because all three channel
#     crates named in the design (flume, async-channel, crossbeam-channel)
#     spell their unbounded constructor as a generic function, and
#     `unbounded::<u8>()` is unremarkable, ordinary call syntax, not evasion.
# ---------------------------------------------------------------------------
hits="$(scan_prod no-unbounded-channel 'unbounded_channel|channel::unbounded|(^|[^A-Za-z_.])unbounded(::<[^)]*>)?\(')"
[ -n "$hits" ] && fail no-unbounded-channel \
"An unbounded channel compiles and satisfies the borrow checker, and it is an
out-of-memory bug: nothing bounds how far the fast half of a connection can
outrun the slow half. Read one buffer, write it to completion, then read
again; backpressure must be structural, never a queue with no ceiling." "$hits"

# ---------------------------------------------------------------------------
# 18. balance-drop-only: a monotone counter may lose an increment; a balance
#     (in-flight connections, permits, pooled buffers outstanding) may not.
#     A lost decrement is capacity that silently disappears for the life of
#     the process, so a fetch_sub in a hot-path crate is a violation unless
#     that file also releases the balance in a Drop impl.
# ---------------------------------------------------------------------------
hits="$(balance_drop_only_hits | drop_escaped balance-drop-only || true)"
[ -n "$hits" ] && fail balance-drop-only \
"fetch_sub, or fetch_add whose first argument is exactly TYPE::MAX (that
wraps an unsigned integer by exactly -1, i.e. a decrement spelled to dodge a
fetch_sub grep), on an atomic in irontraffic-io, -runtime, -conn, -upstream,
or -dataplane must live in a file that also defines impl Drop for something:
that is where a balance release belongs. Move the release into the Drop
impl, or if this file is a documented, reviewed exception, add it to
scripts/allowlist-balance.txt with a reason in the same PR." "$hits"

# ---------------------------------------------------------------------------
# 19. interior-mutability: Cell<, RefCell<, and UnsafeCell< are banned in
#     hot-path crates. A tokio task migrates between workers at any await
#     point, so per-core state reached through a Cell is a data race; use a
#     relaxed atomic instead. std::cell::OnceCell is unaffected: it is a
#     legitimate one-shot initialiser, not a per-core mutable cell.
# ---------------------------------------------------------------------------
hits="$(hotpath_crate_scan interior-mutability '(^|[^A-Za-z_])(Cell|RefCell|UnsafeCell)<' \
  | drop_allowlisted scripts/allowlist-interior-mutability.txt; \
  allowlist_stale_hits scripts/allowlist-interior-mutability.txt)"
[ -n "$hits" ] && fail interior-mutability \
"Cell<, RefCell<, and UnsafeCell< are banned in irontraffic-io, -runtime,
-conn, -upstream, and -dataplane. A tokio task migrates between worker
threads at any await point, so per-core state reached through a Cell is a
data race; use a relaxed atomic instead. std::cell::OnceCell is not banned:
it is a one-shot initialiser, not a per-core mutable cell. If this use is a
documented, reviewed exception (the M1 thread-local buffer pool, whose
borrow is confined to a synchronous closure), add the file to
scripts/allowlist-interior-mutability.txt with a reason in the same PR." "$hits"

# ---------------------------------------------------------------------------
# 20. single-snapshot-publish: ArcSwap::store may be called in exactly one
#     function in the whole workspace, because a second publication site
#     reintroduces torn configuration: a request could see a route from
#     generation N and a filter chain from N+1.
#
#     INVERTED, not detected: this used to require ArcSwap|arc_swap and
#     .store( on the SAME line, which is close to vacuous, because real code
#     almost never writes it that way. The type name lives on the field
#     declaration; the store call lives in a method, lines or files away:
#
#       struct Holder { table: ArcSwap<RouteSnapshot> }
#       fn publish(h: &Holder, next: Arc<RouteSnapshot>) { h.table.store(next); }
#
#     That is ordinary, idiomatic Rust, and the old same-line pattern never
#     saw it: no alias, no evasion needed, the co-occurrence requirement was
#     simply never true for real code. So this rule no longer tries to prove
#     a store call touches specifically an ArcSwap. It bans `.store(` outright
#     in production code and allowlists the legitimate call sites, the same
#     shape balance-drop-only and interior-mutability already use. This is
#     deliberately over-broad: it also catches a `.store(` on something that
#     is not an ArcSwap. That is the intended trade, not a defect. An
#     over-broad rule fails LOUDLY on a real file and costs one allowlist
#     entry with a reason; a rule narrow enough to name only ArcSwap can be
#     silently blind to the exact call it exists to guard, which is a torn-
#     config bug waiting to ship. No ArcSwap exists in M1, so the allowlist
#     ships empty and every current `.store(` (there are none yet) would
#     need one; this rule is in place before the config plane lands rather
#     than retrofitted after.
# ---------------------------------------------------------------------------
hits="$(
  {
    scan_prod single-snapshot-publish '\.store\(' | drop_allowlisted scripts/allowlist-arcswap-store.txt
    allowlist_stale_hits scripts/allowlist-arcswap-store.txt
  } || true
)"
[ -n "$hits" ] && fail single-snapshot-publish \
".store( in production code is a violation unless the file is listed in
scripts/allowlist-arcswap-store.txt. This rule exists to keep ArcSwap::store
called from exactly one function in the whole workspace: a second
publication site reintroduces torn configuration, where a request could see
a route from generation N and a filter chain from N+1. It fires on any
.store( call, not only ArcSwap's, because a same-line ArcSwap-plus-store
pattern misses ordinary multi-line code and would report a guarantee it does
not provide. If this file is not an ArcSwap publisher (for example a plain
Atomic::store), or if it is the one designated publisher, add it to
scripts/allowlist-arcswap-store.txt with a reason in the same PR." "$hits"

# ---------------------------------------------------------------------------
# 21. core-ctx-not-stored: a CoreCtx (or CoreHandle, the name design
#     documents used for the same idea) may be borrowed as a synchronous
#     closure argument, never stored: a struct field of this type makes its
#     container !Send, which either fails to compile far from the mistake or
#     is worked around with an unsafe impl Send that reintroduces the data
#     race the seam exists to remove. The type system cannot express "may be
#     borrowed, never stored", so this is a grep.
#
#     The trailing `(//.*)?` tolerates an end-of-line comment after the field
#     (`ctx: CoreCtx, // per-core context`), which would otherwise defeat the
#     `$` anchor with a single keystroke. It only matches a comment that
#     starts immediately after the allowed punctuation/whitespace, so it does
#     not open the door to matching CoreCtx text that appears earlier in an
#     unrelated trailing comment on a line that is not itself a field.
# ---------------------------------------------------------------------------
hits="$(scan_prod core-ctx-not-stored 'Core(Ctx|Handle)[,;>[:space:]]*(//.*)?$')"
[ -n "$hits" ] && fail core-ctx-not-stored \
"CoreCtx and CoreHandle may be borrowed as the argument of a synchronous
closure, never stored. A struct field of this type makes its container
!Send, which either fails to compile far from the mistake or gets worked
around with an unsafe impl Send that reintroduces the data race
runtime-core-scope exists to remove. Thread the context through as a
parameter instead of holding it:
  // it-allow: core-ctx-not-stored reason: <why storing it here is safe>" "$hits"

# ---------------------------------------------------------------------------
# 22. no-guarded-alias: a grep matches a name, not a meaning, so it cannot see
#     through `use ... as X`, a re-export, or a `type X = ...` alias. It does
#     not need to: creating that alias is itself one greppable line, and
#     forbidding the alias makes every rename attempt visible at the moment
#     it is written, rather than hoping no one ever renames a guarded symbol.
#
#     Two shapes per guarded group, `as` and `type`, plus one crate-scoped
#     re-export shape:
#       - `RefCell`/`Cell`/`UnsafeCell` renamed via `as`, OR named on the
#         right-hand side of a `type X = ...;` alias (defeats
#         interior-mutability: the alias no longer contains the guarded
#         token anywhere it is used at the call site). The `type` form is
#         the worse of the two, because it can live in ANY crate, including
#         one of the four that are not among the five interior-mutability
#         scans, so `pub type SharedCache<T> = std::cell::RefCell<T>;` in an
#         unrelated crate is invisible to interior-mutability no matter what
#         its own pattern does.
#       - `ArcSwap` renamed via `as`, or aliased via `type` (defeats
#         single-snapshot-publish's allowlist the same way: `type Snap =
#         ArcSwap<u8>;` then `.store(` on a `Snap` never mentions ArcSwap at
#         the call site).
#       - `CoreCtx`/`CoreHandle` renamed via `as`, aliased via `type`, OR
#         named in a `pub use` (aliased or bare/braced). core-ctx-not-stored
#         anchors on the END of a line, so `pub use inner::{Helper,
#         CoreCtx};` never reaches that anchor; the pub-use alternative does
#         not anchor at all, so it catches CoreCtx anywhere on a pub-use
#         line regardless of position.
#       - `pub use tokio...` (anything) from inside irontraffic-io or
#         irontraffic-runtime. Naming tokio there is legitimate and exempted
#         by transport-seam, but PUBLICLY re-exporting it hands the seam's
#         escape hatch to every downstream crate: code outside the seam can
#         then write `irontraffic_io::RawListener` and never type `tokio::`
#         at all. The re-export marker is matched as `pub`, `pub(crate)`, or
#         `pub(super)`, with an optional leading `::` before `tokio`, because
#         `pub(crate) use tokio::net::TcpListener;` inside a private module
#         followed by `pub use that_module::TcpListener as Listener;`
#         one level up is the same laundering trick with the crate-visible
#         re-export doing the actual work: blocking the first hop (which
#         still names tokio) closes the sequence even though the second hop's
#         own line never mentions tokio at all and could not be matched by
#         any text search. This is the only one of the four scoped to
#         specific crates; the other three are banned everywhere, because
#         aliasing a guarded symbol anywhere hides it from a rule that has no
#         crate restriction to begin with.
#
#     ACCEPTED GAP: a re-export chain three or more hops deep, where the
#     FINAL hop that actually crosses the crate boundary re-exports a local
#     alias whose own line never names tokio (or any other guarded token),
#     is not reachable by this or any text search once the first hop is
#     itself only crate-local and unblocked by a different rule. Blocking the
#     first hop closes the two-hop case the review demonstrated; a longer
#     chain is a control-flow question (what does this name eventually
#     resolve to), not a text-search one.
#
#     No allowlist: an alias of a guarded symbol has no legitimate case the
#     way a lone Drop-releasing file or a lone ArcSwap publisher does. The
#     escape hatch is the same `// it-allow: no-guarded-alias reason: ...`
#     every other rule uses.
# ---------------------------------------------------------------------------
GUARDED_TYPE_ALIAS_HEAD='^[[:space:]]*(pub[[:space:]]+)?type[[:space:]]+[A-Za-z_][A-Za-z0-9_]*.*=.*'
hits="$(
  {
    scan_prod no-guarded-alias '(^|[^A-Za-z_])(Cell|RefCell|UnsafeCell)[[:space:]]+as[[:space:]]+[A-Za-z_]'
    scan_prod no-guarded-alias '(^|[^A-Za-z_])ArcSwap[[:space:]]+as[[:space:]]+[A-Za-z_]'
    scan_prod no-guarded-alias '(^|[^A-Za-z_])Core(Ctx|Handle)[[:space:]]+as[[:space:]]+[A-Za-z_]|^[[:space:]]*pub[[:space:]]+use[[:space:]].*Core(Ctx|Handle)'
    scan_prod no-guarded-alias "${GUARDED_TYPE_ALIAS_HEAD}[^A-Za-z_](Cell|RefCell|UnsafeCell)<"
    scan_prod no-guarded-alias "${GUARDED_TYPE_ALIAS_HEAD}[^A-Za-z_]ArcSwap"
    scan_prod no-guarded-alias "${GUARDED_TYPE_ALIAS_HEAD}[^A-Za-z_]Core(Ctx|Handle)"
    scan_prod no-guarded-alias '^[[:space:]]*pub(\(crate\)|\(super\))?[[:space:]]+use[[:space:]]+(::)?tokio' \
      | grep -E '^crates/irontraffic-(io|runtime)/'
  } || true
)"
[ -n "$hits" ] && fail no-guarded-alias \
"Renaming or re-exporting a guarded symbol, including through a \`type X =
...;\` alias, removes the text every other rule greps for, without removing
the hazard the rule guards against. Cell, RefCell, and UnsafeCell may not be
imported \`as\` another name or aliased via \`type\`; neither may ArcSwap;
neither may CoreCtx or CoreHandle, which also may not appear in a pub use
(aliased or bare) since that anchors nowhere a rename can hide.
irontraffic-io and irontraffic-runtime may name tokio directly, but may not
publicly re-export it (pub, pub(crate), or pub(super), with or without a
leading ::): that hands the transport seam's escape hatch to every
downstream crate. Keep the guarded name in scope under its own name, or
route the value through a function instead of a re-exported type:
  // it-allow: no-guarded-alias reason: <why this alias cannot hide anything>" "$hits"

# ---------------------------------------------------------------------------
if [ "$FAILED" -ne 0 ]; then
  printf '\ninvariant-lints: FAILED. Each block above names the rule, explains why it\n'
  printf 'exists, and lists the offending lines. Fix the code; do not silence a lint\n'
  printf 'unless you can write a reason a reviewer will accept.\n'
  exit 1
fi

echo "invariant-lints: clean"
