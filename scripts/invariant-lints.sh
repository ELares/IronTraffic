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
export WORK

# rslex.py: a minimal, literal- and comment-aware lexical scanner for Rust
# source, shared by every python helper below that needs to find a matching
# bracket, split call arguments, or locate a statement boundary.
#
# WHY THIS EXISTS. A rule that counts `{`/`(` characters (or searches for the
# first one, or splits on top-level commas) to find where a Rust construct
# ends is wrong the moment the source contains a string, char literal, raw
# string, or comment with an unbalanced brace or paren inside it: a char
# literal for the brace character itself (`'{'`), a `{0,20}` regex
# repetition inside a string, a unicode escape, a `// comment with a stray
# }`, and a block comment (which nests in Rust) can all desynchronize a
# naive counter. This happened for real: a proptest generator string
# containing `{0,20}` and a parameter list containing a `\u{...}` escape both
# made a plain brace-depth scan locate the WRONG opening brace as a
# function's body (the first `{` it found textually, inside the decoy
# string, rather than the real one after the parameter list), read a bogus
# near-empty "body", and report two genuine property tests as having no
# assertion. Every function below treats literal and comment regions as
# opaque: their contents can never contribute to a depth count or be
# mistaken for a real bracket.
cat > "$WORK/rslex.py" <<'PYLEX'
import re


def skip_trivia(text, i):
    """If a string/char/byte literal, raw string, or comment starts at
    position i, return the index just past its end. Otherwise return i
    unchanged (never less than i). Line comments consume through, but not
    including, a trailing newline. Block comments nest, matching rustc."""
    n = len(text)
    if i >= n:
        return i
    c = text[i]

    if c == '/' and i + 1 < n and text[i + 1] == '/':
        j = text.find('\n', i)
        return n if j < 0 else j

    if c == '/' and i + 1 < n and text[i + 1] == '*':
        depth = 1
        j = i + 2
        while j < n and depth > 0:
            if text[j:j + 2] == '/*':
                depth += 1
                j += 2
            elif text[j:j + 2] == '*/':
                depth -= 1
                j += 2
            else:
                j += 1
        return j

    # (Raw) (byte) string: an optional leading `b`, then `r`, then zero or
    # more `#`, then a `"`. Anything short of the `"` is not a raw string at
    # all (it might be a raw identifier like `r#type`, or just the letters
    # `r`/`b` used as ordinary identifier characters elsewhere), so on a
    # failed match this falls through to the plain string/char checks below,
    # which is exactly right: `r` and `b` alone carry no special meaning.
    j = i
    if text[j] == 'b':
        j += 1
    if j < n and text[j] == 'r':
        k = j + 1
        hashes = 0
        while k < n and text[k] == '#':
            hashes += 1
            k += 1
        if k < n and text[k] == '"':
            k += 1
            closer = '"' + ('#' * hashes)
            end = text.find(closer, k)
            return n if end < 0 else end + len(closer)

    if c == 'b' and i + 1 < n and text[i + 1] == '"':
        return _skip_quoted(text, i + 1)

    if c == 'b' and i + 1 < n and text[i + 1] == "'":
        end = _skip_char_literal(text, i + 1)
        if end is not None:
            return end
        return i  # `b` on its own is not special; let the caller advance.

    if c == '"':
        return _skip_quoted(text, i)

    if c == "'":
        end = _skip_char_literal(text, i)
        if end is not None:
            return end
        # A lifetime (`'a`, `'static`) or a bare tick: not a literal, but the
        # tick itself must not be re-examined as if it could start one.
        # Consuming just the tick is correct either way, since a lifetime's
        # identifier characters are not brackets and need no special
        # handling.
        return i + 1

    return i


def _skip_quoted(text, i):
    """text[i] == '"'. Return the index just past the matching unescaped
    closing quote."""
    n = len(text)
    j = i + 1
    while j < n:
        if text[j] == '\\' and j + 1 < n:
            j += 2
            continue
        if text[j] == '"':
            return j + 1
        j += 1
    return n


def _skip_char_literal(text, i):
    """text[i] == "'". Try to parse a char literal starting here (including
    a unicode escape, whose own brace must never leak into a caller's depth
    count). Returns the index just past the closing quote, or None if this
    is not a char literal (most commonly a lifetime)."""
    n = len(text)
    j = i + 1
    if j >= n:
        return None
    if text[j] == '\\':
        if text[j:j + 2] == '\\u' and j + 2 < n and text[j + 2] == '{':
            close = text.find('}', j + 3)
            if close < 0:
                return None
            k = close + 1
        elif text[j:j + 2] == '\\x':
            k = j + 4
        else:
            k = j + 2
        if k < n and text[k] == "'":
            return k + 1
        return None
    if j + 1 < n and text[j + 1] == "'":
        return j + 2
    return None


_OPEN_TO_CLOSE = {'(': ')', '[': ']', '{': '}'}


def find_matching(text, open_idx):
    """text[open_idx] is one of ( [ {. Returns the index of its matching
    close bracket, treating literals and comments as opaque, or -1 if the
    text ends before it is found."""
    open_ch = text[open_idx]
    close_ch = _OPEN_TO_CLOSE[open_ch]
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        skipped = skip_trivia(text, i)
        if skipped != i:
            i = skipped
            continue
        c = text[i]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
            if c == close_ch and depth == 0:
                return i
        i += 1
    return -1


def find_first_real(text, start, chars, stop=None):
    """The index of the first character in `chars` at or after `start` that
    is not inside a literal or comment, or -1. Stops (returning -1) at or
    after `stop` if given, so a caller can bound the search to one
    statement's span without accidentally reading into the next one."""
    i = start
    n = stop if stop is not None else len(text)
    while i < n:
        skipped = skip_trivia(text, i)
        if skipped != i:
            i = skipped
            continue
        if text[i] in chars:
            return i
        i += 1
    return -1


def top_level_split(text, open_idx, close_idx):
    """The comma-separated top-level arguments between open_idx+1 and
    close_idx (exclusive), as trimmed strings, ignoring commas nested inside
    another bracket pair or a literal/comment. Always returns at least one
    element (possibly empty, for an empty argument list, OR as a trailing
    element after a rustfmt-style trailing comma: callers that count
    arguments must drop empty/whitespace-only elements first)."""
    depth = 0
    parts = []
    start = open_idx + 1
    i = start
    while i < close_idx:
        skipped = skip_trivia(text, i)
        if skipped != i:
            i = min(skipped, close_idx)
            continue
        c = text[i]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:close_idx])
    return [p.strip() for p in parts]


def line_of(text, idx):
    """1-based line number of a character offset."""
    return text.count('\n', 0, idx) + 1


def blank_region(chars, start, end):
    """Overwrite chars[start:end] with spaces, except newlines, which are
    kept so line numbers computed against the result stay correct. `chars`
    is a mutable list of one-character strings (list(text)), modified in
    place."""
    for k in range(start, min(end, len(chars))):
        if chars[k] != '\n':
            chars[k] = ' '


def blanked_span(text, start, end):
    """text[start:end] with every literal and comment region replaced by
    spaces (newlines kept). For a caller checking whether a span CONTAINS a
    real token (not just its spelling inside a decoy string or a comment
    that mentions it), so that a test body reading `// see assert! above`
    with no real assertion is not mistaken for one that has it."""
    sub = text[start:end]
    chars = list(sub)
    i = 0
    n = len(sub)
    while i < n:
        skipped = skip_trivia(sub, i)
        if skipped != i:
            blank_region(chars, i, skipped)
            i = skipped
            continue
        i += 1
    return ''.join(chars)


def finditer_real(pattern, text):
    """Like pattern.finditer(text), but skips any match that would start
    inside a string, char literal, or comment. A plain regex has no notion
    of those regions, so without this a doc comment that merely MENTIONS a
    construct in prose (`/// #[allow(...)] is how ...` while explaining
    what one looks like, or `/// ... precisely because .store( was
    rejected`) reads exactly like the construct itself: prose about a rule
    can otherwise trip the rule it is describing."""
    i, n = 0, len(text)
    while i < n:
        skipped = skip_trivia(text, i)
        if skipped != i:
            i = skipped
            continue
        m = pattern.match(text, i)
        if m:
            yield m
            i = m.end() if m.end() > i else i + 1
        else:
            i += 1


NAME = re.compile(r'[A-Za-z_]\w*')
PYLEX

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

sys.path.insert(0, os.environ["WORK"])
import rslex

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
        # find_first_real (not a plain str.find) so a decoy brace inside a
        # string or comment between the attribute and the module cannot be
        # mistaken for the module body opening early, and find_matching (not
        # a plain depth counter) so a brace inside a string, char literal, or
        # comment ANYWHERE in the test module cannot end the blank region
        # early, which would leak un-blanked #[cfg(test)] code (unwrap(),
        # direct clock reads, and the rest) into the shadow tree that every
        # scan_prod-based rule runs against.
        i = rslex.find_first_real(text, m.end(), "{")
        if i < 0:
            continue
        j = rslex.find_matching(text, i)
        if j < 0:
            j = len(text) - 1
        rslex.blank_region(chars, m.start(), j + 1)
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
# 0. untracked-source: a file this gate cannot see is a file it did not
#    check, no matter what every rule below reports.
#
#    WHY THIS EXISTS (issue #513). Every rule below discovers what to scan
#    through git, never through the filesystem: rust_files() is `git ls-files
#    -z -- '*.rs' | ...`, and crate-inherits-workspace reads `git ls-files --
#    'crates/*/Cargo.toml'` directly. `git ls-files` lists only what git is
#    already tracking. A file created on disk and not yet `git add`ed is
#    therefore invisible to every one of them: a todo!(), a bare .store( with
#    no allowlist entry, a CoreCtx stored as a struct field, or a test with no
#    assertion, in a brand-new file, all sail through a gate that reports
#    clean because nothing below ever reads a byte of it. This happened for
#    real: three new files created for issue #13 produced an identical clean
#    invariant-lints run and an identical clean test-census run before and
#    after `git add`, even though one of the files held two un-marked
#    .store( calls that single-snapshot-publish correctly rejected the moment
#    staging made them visible.
#
#    THE FIX IS A REFUSAL, NOT A QUIET WIDENING. rust_files() could instead
#    read the filesystem directly and quietly include untracked files, and
#    every rule above would then see them without anyone having to do
#    anything. That is precisely the wrong fix: it would make the gate
#    correct by accident, for a reason nobody had to notice, understand, or
#    keep true. The next rewrite of a scan that goes back to a plain git
#    enumeration, or a rule added later that reads git directly instead of
#    going through rust_files(), silently reopens the exact same hole with
#    nothing here left to catch it. Refusing outright makes "stage it" a step
#    the gate itself enforces rather than a convention an implementer has to
#    remember, and it matches every other rule in this file: named, explained,
#    with the offending lines listed, not silently patched around.
#
#    SCOPE. `git ls-files --others --exclude-standard` is the honest
#    enumeration: "others" means untracked, and `--exclude-standard` applies
#    .gitignore, .git/info/exclude, and git's own always-on excludes, so a
#    build artifact under target/, an editor swap file, or anything else
#    .gitignore already knows about is never reported by it. This is
#    restricted to the same two patterns a rule below actually scans (`*.rs`,
#    exactly rust_files()'s own pathspec, and `crates/*/Cargo.toml`, exactly
#    crate-inherits-workspace's own pathspec): a file outside both is not
#    silently unchecked by anything below, so flagging it here would be noise
#    with no rule behind it, which is exactly the failure mode that gets a
#    rule disabled by the first person it annoys.
# ---------------------------------------------------------------------------
hits="$(git ls-files --others --exclude-standard -- '*.rs' 'crates/*/Cargo.toml' \
  | grep -v -E '^(target|fuzz/target)/' \
  | sed 's/$/: untracked; git add it before this gate can see it/' \
  || true)"
[ -n "$hits" ] && fail untracked-source \
"This file exists on disk but git is not tracking it, so no rule in this
script, and no rule in test-census.sh, has scanned a single byte of it: every
one of them discovers what to check through git, not through the filesystem.
Stage it with git add (along with every other new file this diff introduces)
before trusting a green result here; an untracked file is not a smaller
version of a tracked one, it is one this script never opened." "$hits"

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
#
# ONE SPELLING IS NOT THE OPERATION: `irontraffic-time`'s own system source
# (time-source-seam, #5/#449) reads the boot clock via
# `rustix::time::clock_gettime`, because that is the only way to reach
# `CLOCK_BOOTTIME` without a C build or `unsafe`. `rustix` is an ordinary
# workspace dependency, available to every crate, not only the seam. A crate
# outside irontraffic-time that wanted a direct, un-seamed clock read could
# call `rustix::time::clock_gettime` itself and this rule's original pattern
# would never see it: none of SystemTime/Instant/Utc/Local name it, and it
# is exactly the same hazard (non-deterministic tests, unreproducible
# time-dependent bugs) as the six forms already covered. Added scoped by the
# same crates/irontraffic-(time|rand)/ exemption as everything else here.
# ---------------------------------------------------------------------------
hits="$(scan_prod determinism-seam '(SystemTime::now|Instant::now|UNIX_EPOCH|\brand::|thread_rng|getrandom|OsRng|Utc::now|Local::now|rustix::time|clock_gettime)' \
  | grep -vE '^crates/irontraffic-(time|rand)/' || true)"
[ -n "$hits" ] && fail determinism-seam \
"All wall-clock time, monotonic time, and entropy flows through the
irontraffic-time and irontraffic-rand seams. Direct access makes tests non-deterministic and makes
time-dependent bugs unreproducible. Take a Clock or Entropy handle instead." "$hits"

# ---------------------------------------------------------------------------
# 4. allow-needs-reason: a silenced lint must say why it was silenced.
#
# NOT a same-line grep. rustfmt force-wraps an #[allow(...)] attribute onto
# multiple lines once its contents exceed roughly 70 characters (driven by
# attr_fn_like_width, not max_width), which is routine the moment the lint
# path plus a real explanation is long:
#
#   #[allow(
#       clippy::too_many_arguments,
#       reason = "one cohesive dispatch loop that threads every per-\
#                 connection parameter through by design"
#   )]
#
# A same-line grep for `reason[[:space:]]*=` sees only the FIRST line of
# that attribute, which never contains the word "reason", and fails the very
# form cargo fmt produces: cargo fmt --check and this rule then demand
# opposite things for every allow long enough to wrap, and there is no
# spelling that satisfies both. So this scans the WHOLE #[allow(...)] /
# #![allow(...)] span (open paren to its matching close, via rslex, which
# tolerates the reason string itself being force-wrapped mid-sentence with a
# backslash-newline continuation as above) for `reason[[:space:]]*=`
# anywhere inside it, matching what rustfmt actually produces instead of
# what a single line can show.
# ---------------------------------------------------------------------------
cat > "$WORK/allow_reason.py" <<'PY'
import os, re, sys

sys.path.insert(0, os.environ['WORK'])
import rslex

ATTR = re.compile(r'#!?\[allow\(')
REASON = re.compile(r'reason\s*=')
ESCAPE = re.compile(r'it-allow:\s*allow-needs-reason\s+reason:\s*\S')

out = []
for path in sys.argv[1:]:
    try:
        text = open(path, encoding='utf-8').read()
    except (OSError, UnicodeDecodeError):
        continue
    lines = text.splitlines()
    for m in rslex.finditer_real(ATTR, text):
        open_idx = m.end() - 1
        close_idx = rslex.find_matching(text, open_idx)
        if close_idx < 0:
            close_idx = len(text) - 1
        span = text[m.start():close_idx + 1]
        if REASON.search(span):
            continue
        start_line = rslex.line_of(text, m.start())
        # The escape marker gets the same tolerance as the reason check
        # above: anywhere in the attribute's own span, which for a
        # single-line attribute is exactly "the same line", matching the
        # escape hatch's documented shape everywhere else in this file.
        if ESCAPE.search(span):
            continue
        content = lines[start_line - 1] if start_line - 1 < len(lines) else ''
        out.append(f'{path}:{start_line}:{content}')

print('\n'.join(out))
PY
hits="$(rust_files | tr '\n' '\0' | xargs -0 -r python3 "$WORK/allow_reason.py" | grep -v '^$' || true)"
[ -n "$hits" ] && fail allow-needs-reason \
"Every #[allow(...)] carries reason = \"...\" explaining why the lint is wrong
here, anywhere in the attribute (rustfmt is free to wrap it onto multiple
lines once it is long, and this check follows that wrap rather than fighting
it). Silencing a lint without a reason is how real defects get hidden.
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
#
# NOT a same-line grep for the matches! form. `assert!(matches!(x, _))` is
# short and rustfmt leaves it alone, but a REAL x is often a long expression
# (the value under test, not a placeholder), and once the whole call exceeds
# max_width rustfmt wraps it:
#
#   assert!(matches!(
#       parse_the_thing_under_test(&input_that_forced_this_wide_call),
#       _
#   ));
#
# A same-line grep for `matches!\s*\([^,]+,\s*_\s*\)` never sees the `, _`
# once it has moved to its own line, so the exact vacuous shape this rule
# exists to catch survives untouched the moment the expression being matched
# is realistic instead of a placeholder variable. This scans with rslex
# instead, which finds matches!'s argument list wherever its parens close
# and is therefore indifferent to how rustfmt chose to wrap it.
# ---------------------------------------------------------------------------
cat > "$WORK/vacuous_assert.py" <<'PY'
import os, re, sys

sys.path.insert(0, os.environ['WORK'])
import rslex

ASSERT = re.compile(r'\bassert!\s*\(')
MATCHES = re.compile(r'\bmatches!\s*\(')

out = []
for path in sys.argv[1:]:
    try:
        text = open(path, encoding='utf-8').read()
    except (OSError, UnicodeDecodeError):
        continue
    lines = text.splitlines()
    for m in rslex.finditer_real(ASSERT, text):
        a_open = m.end() - 1
        a_close = rslex.find_matching(text, a_open)
        if a_close < 0:
            continue
        inner = text[a_open + 1:a_close]
        line = rslex.line_of(text, m.start())
        content = lines[line - 1] if line - 1 < len(lines) else ''
        if inner.strip() == 'true':
            out.append(f'{path}:{line}:{content}')
            continue
        mm = MATCHES.search(text, a_open + 1, a_close)
        if not mm:
            continue
        mm_open = mm.end() - 1
        mm_close = rslex.find_matching(text, mm_open)
        if mm_close < 0 or mm_close > a_close:
            continue
        parts = [p for p in rslex.top_level_split(text, mm_open, mm_close) if p.strip()]
        if len(parts) == 2 and parts[1] == '_':
            out.append(f'{path}:{line}:{content}')

print('\n'.join(out))
PY
hits="$(rust_files | tr '\n' '\0' | xargs -0 -r python3 "$WORK/vacuous_assert.py" | drop_escaped no-vacuous-assert || true)"
[ -n "$hits" ] && fail no-vacuous-assert \
"This assertion cannot fail, so the test asserts nothing. Assert on the actual
value the code under test produced." "$hits"

# ---------------------------------------------------------------------------
# 7. no-test-without-assertion: a test body that never asserts.
#
# TWO independent line/text-oriented assumptions used to live here, both now
# fixed with rslex:
#
#  1. The old regex required `fn` to come IMMEDIATELY after `#[test]` (or
#     `#[tokio::test]`), with nothing in between. Any attribute placed
#     between them, most commonly `#[allow(..., reason = "...")]` on a
#     property test whose generator needs one, made the whole function
#     invisible to this rule (and to test-census.sh, which shares the exact
#     same assumption; see the fix there). This now walks past any number of
#     `#[...]` attributes between the test marker and `fn`, using rslex's
#     bracket matching (not a `[^\]]*` guess) so an attribute containing its
#     own nested `[...]` cannot cut the walk short.
#  2. The body was extracted with a plain `{`/`}` depth counter, which is
#     wrong the moment the body (or, worse, a proptest generator string in
#     the parameter list BEFORE the body) contains a literal or comment with
#     an unbalanced brace: a char literal for the brace character itself, a
#     `{0,20}` regex repetition inside a string, a unicode escape, or a
#     brace inside a comment. This is not hypothetical: it broke two real
#     property tests, whose generator strings contained exactly the first
#     two forms, reading a near-empty body from a decoy `{` and reporting
#     "no assertion" on tests that plainly had one. rslex.find_first_real /
#     find_matching treat those regions as opaque, and the ASSERT search now
#     runs against a copy of the body with literals and comments blanked
#     (rslex.blanked_span), so a comment that merely MENTIONS an assertion
#     macro cannot stand in for having one either.
# ---------------------------------------------------------------------------
cat > "$WORK/no_assert.py" <<'PY'
import os, re, sys

sys.path.insert(0, os.environ['WORK'])
import rslex

TEST_ATTR = re.compile(r'#\[\s*(?:tokio::)?test\b')
ASSERT = re.compile(
    r'(assert\w*!|should_panic|expect_err|unwrap_err|\.is_err\(\)|\.is_ok\(\)'
    r'|insta::|proptest!|panic!|\?;)'
)


def skip_attributes(text, start):
    """From just past a test-marking attribute's closing `]`, skip
    whitespace/comments and any further `#[...]` attributes (via bracket
    matching, so a nested `[...]` or a `]` inside a string cannot cut this
    short), then require `fn` (optionally `async fn`). Returns
    (index_of_fn_keyword, name) or None."""
    i, n = start, len(text)
    while True:
        while i < n:
            skipped = rslex.skip_trivia(text, i)
            if skipped != i:
                i = skipped
                continue
            if text[i].isspace():
                i += 1
                continue
            break
        if i < n and text[i] == '#' and i + 1 < n and text[i + 1] == '[':
            close = rslex.find_matching(text, i + 1)
            if close < 0:
                return None
            i = close + 1
            continue
        break
    m = re.match(r'(?:async\s+)?fn\s+(\w+)', text[i:])
    if not m:
        return None
    return i, m.group(1)


out = []
for path in sys.argv[1:]:
    try:
        text = open(path, encoding='utf-8').read()
    except (OSError, UnicodeDecodeError):
        continue
    for m in rslex.finditer_real(TEST_ATTR, text):
        attr_open = text.index('[', m.start())
        attr_close = rslex.find_matching(text, attr_open)
        if attr_close < 0:
            continue
        found = skip_attributes(text, attr_close + 1)
        if not found:
            continue
        fn_pos, name = found
        # should_panic may appear as its own attribute either before or
        # after the test marker; check the whole span so both orders count.
        span_start = max(0, m.start() - 200)
        if 'should_panic' in text[span_start:fn_pos]:
            continue
        i = rslex.find_first_real(text, fn_pos, '{')
        if i < 0:
            continue
        j = rslex.find_matching(text, i)
        if j < 0:
            continue
        if not ASSERT.search(rslex.blanked_span(text, i, j)):
            line = rslex.line_of(text, fn_pos)
            out.append(f'{path}:{line}: test `{name}` contains no assertion')
print('\n'.join(out))
PY
hits="$(rust_files | tr '\n' '\0' | xargs -0 -r python3 "$WORK/no_assert.py" | grep -v '^$' || true)"
[ -n "$hits" ] && fail no-test-without-assertion \
"A test that runs code but never asserts on the result only proves the code did
not panic. State the expected value and assert it." "$hits"

# ---------------------------------------------------------------------------
# 8. no-swallowed-error: discarding a Result hides failures.
#
# KNOWN GAP, NOT FIXED HERE (documented rather than silently left, per the
# audit in #453 step 5): this is still a same-line pattern, and it can be
# defeated the same way allow-needs-reason and the others were. rustfmt
# breaks a `let` statement after `=` when the left-hand side (an explicit
# `let _: SomeVerboseType =`) plus the right-hand side does not fit:
#
#   let _: SomeVerboseResultTypeAnnotationThatForcesAWrapHere<WithGenerics> =
#       some_function_call();
#
# `some_function_call(` then sits alone on the second line with no `let _`
# on it, and the regex, which requires the whole shape on one line, misses
# it. Confirmed with rustfmt during this audit. NOT fixed in this PR: a
# correct multi-line version has to walk past the type annotation to find
# the statement's own top-level `=` without being fooled by an
# associated-type binding inside it (`Box<dyn Iterator<Item = u8>>`), which
# needs angle-bracket-aware depth tracking that Rust's grammar does not
# make safe to fake with a text scanner (`<`/`>` are also comparison and
# shift operators). Shipping that without real confidence it is right
# everywhere would be the same mistake this audit exists to stop repeating.
# Left for a follow-up with its own review, not bundled into this one.
# ---------------------------------------------------------------------------
hits="$(scan_prod no-swallowed-error 'let\s+_\s*(:\s*[^=]+)?=\s*[a-zA-Z_][a-zA-Z0-9_:]*\s*\(')"
[ -n "$hits" ] && fail no-swallowed-error \
"Discarding a call result with \`let _ =\` hides errors. Handle it, propagate it
with ?, or log it with context. If discarding is genuinely correct, say why:
  // it-allow: no-swallowed-error reason: <why the failure is safe to drop>" "$hits"

# ---------------------------------------------------------------------------
# 9. no-blocking-in-async: a blocking call stalls a whole worker thread.
#
# ONE SPELLING IS NOT THE OPERATION: the std::fs alternatives originally
# listed here are the common ones, not the complete blocking-syscall surface
# std::fs exposes. metadata, canonicalize, symlink_metadata, hard_link,
# read_link, and set_permissions are all synchronous filesystem syscalls
# with exactly the same hazard as read/write/create, and none of them start
# with those six words, so none were reachable by "starts with
# read/write/File/create/remove/copy/rename". Spawning a child process is
# the same class of hazard again -- Command::spawn/output/status block the
# calling thread for the lifetime of the child -- and had no representation
# here at all. This still is not a claim of completeness for std::fs or
# std::process; it adds the highest-value misses in the same spirit the
# existing list was written in, not an exhaustive enumeration.
# ---------------------------------------------------------------------------
hits="$(scan_prod no-blocking-in-async '(std::thread::sleep|std::fs::(read|write|File|create|remove|copy|rename|metadata|canonicalize|symlink_metadata|hard_link|read_link|set_permissions)|std::net::TcpStream::connect|to_socket_addrs|reqwest::blocking|std::io::stdin|std::process::Command)')"
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
#
# NOT a same-line grep. rustfmt's default `binop_separator = "Front"` breaks
# a boolean expression BEFORE the operator when a comparison does not fit,
# the same way it already does for `&&`/`||` chains:
#
#   if some_api_key_variable_used_for_probing_purposes_here
#       == expected_value_variable_name_used_here
#   {
#
# A same-line grep for `<secret-ish name>\s*==` never sees the operator once
# it has moved to the next line by itself, so a long enough identifier name
# (routine once a variable is named descriptively rather than `key`) removes
# the comparison from this rule's view entirely while leaving the timing
# oracle intact. Matched with a plain whole-file regex instead of per-line
# grep, since Python's `\s` already spans newlines, which is all the
# robustness this one needs: no nested brackets to balance, just "these two
# tokens with only whitespace between them, however that whitespace wraps".
# ---------------------------------------------------------------------------
cat > "$WORK/secrets_eq.py" <<'PY'
import os, re, sys

sys.path.insert(0, os.environ['WORK'])
import rslex

PATTERN = re.compile(r'(secret|api_key|apikey|token|signature|hmac|password|credential)[a-z_]*\s*==')

for path in sys.argv[1:]:
    try:
        text = open(path, encoding='utf-8').read()
    except (OSError, UnicodeDecodeError):
        continue
    lines = text.splitlines()
    for m in rslex.finditer_real(PATTERN, text):
        line = text.count('\n', 0, m.start()) + 1
        content = lines[line - 1] if line - 1 < len(lines) else ''
        print(f'{path}:{line}:{content}')
PY
hits="$(build_prod_tree; ( cd "$PROD_TREE" && find . -name '*.rs' -print0 \
    | xargs -0 -r python3 "$WORK/secrets_eq.py" ) | sed 's|^\./||' \
    | drop_escaped constant-time-secrets || true)"
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
# scoped scan. Known evasions out of reach of a text search:
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
#
# NOT line-oriented any more: the first-argument check used to be a single
# regex requiring `fetch_add(`, whitespace, and a bare `TYPE::MAX,` all on
# ONE line. rustfmt wraps a call's arguments onto their own lines once the
# receiver plus call does not fit (routine for a long field name, which
# `//! HOT PATH` code tends to have, since a short name is itself a small
# allocation-adjacent readability trade this codebase does not make), which
# splits `fetch_add(` from `u32::MAX,` across two lines and let the same
# spelling this rule exists to catch through. This scans with rslex instead:
# it finds fetch_add's actual argument list via bracket matching (correct
# regardless of how it is wrapped) and checks whether ITS FIRST TOP-LEVEL
# ARGUMENT, exactly, matches a `...::MAX` path -- which is also a strictly
# more precise rendering of the "whole first argument, not merely present
# before the first close-paren" requirement the old comment above described
# a regex trick for, without needing the trick.
cat > "$WORK/balance_scan.py" <<'PY'
import os, re, sys

sys.path.insert(0, os.environ['WORK'])
import rslex

FETCH_SUB = re.compile(r'\bfetch_sub\s*\(')
FETCH_ADD = re.compile(r'\bfetch_add\s*\(')
MAX_ARG = re.compile(r'^([A-Za-z_]\w*::)*[A-Za-z_]\w*::MAX$')

rel, path = sys.argv[1], sys.argv[2]
try:
    text = open(path, encoding='utf-8').read()
except (OSError, UnicodeDecodeError):
    sys.exit(0)
lines = text.splitlines()

hit_lines = set()
for m in rslex.finditer_real(FETCH_SUB, text):
    hit_lines.add(rslex.line_of(text, m.start()))
for m in rslex.finditer_real(FETCH_ADD, text):
    open_idx = m.end() - 1
    close_idx = rslex.find_matching(text, open_idx)
    if close_idx < 0:
        continue
    parts = rslex.top_level_split(text, open_idx, close_idx)
    if parts and MAX_ARG.match(parts[0].strip()):
        hit_lines.add(rslex.line_of(text, m.start()))

for line in sorted(hit_lines):
    content = lines[line - 1] if line - 1 < len(lines) else ''
    print(f'{rel}:{line}:{content}')
PY
balance_drop_only_hits() {
  build_prod_tree
  hotpath_crate_files | while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    lines="$(python3 "$WORK/balance_scan.py" "$rel" "$PROD_TREE/$rel" 2>/dev/null)"
    [ -n "$lines" ] || continue
    grep -q 'impl Drop for' "$PROD_TREE/$rel" 2>/dev/null && continue
    allowlisted scripts/allowlist-balance.txt "$rel" && continue
    printf '%s\n' "$lines"
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
#
#     ONE SPELLING IS NOT THE OPERATION: `.store(` is one of FOUR ways
# arc_swap's `ArcSwapAny` (what `ArcSwap<T>` is a type alias for) publishes a
# new generation, enumerated from the crate's own `src/lib.rs`
# (`store`/`swap`/`compare_and_swap`/`rcu`, https://docs.rs/arc-swap):
#   - `store(&self, val: T)` -- the spelling already covered above. Its own
#     doc comment says "Uses swap internally": store is defined as
#     `drop(self.swap(val))`, so swap is not a lesser cousin of store, it IS
#     the primitive store is built from.
#   - `swap(&self, new: T) -> T` -- exchanges the value and returns the old
#     one. Caught in the wild during review of #449, where a plain
#     std::sync::atomic swap (see the discrimination note below; that
#     specific case was NOT an ArcSwap) was substituted for a store the
#     over-broad rule above had rejected, with a comment explaining the
#     substitution was made BECAUSE the invariant lint forbade `.store(`.
#     That is now in-tree precedent: the next implementer who needs a real
#     ArcSwap publish and reads it would write `snapshot.swap(next)`, and
#     the rule as it stood would match nothing.
#   - `compare_and_swap<C>(&self, current: C, new: T) -> Guard<T, S>` -- a
#     conditional publish; still a publish when the comparison succeeds.
#   - `rcu<R, F>(&self, f: F) -> T` -- read-copy-update: retries `f` and
#     `compare_and_swap`s the result in a loop. A caller of `.rcu(` never
#     types `store`, `swap`, or `compare_and_swap` themselves, so it needs
#     its own spelling in this rule, not just coverage of what it calls
#     internally.
#   - Reassigning an existing ArcSwap-typed place with a freshly built
#     `ArcSwap::from_pointee(...)` or `ArcSwap::new(...)`, as opposed to
#     binding a NEW `let`/`static`/`const` to one, replaces what every
#     reader through the old place sees without calling any of the four
#     methods above at all.
#
#     THE DISCRIMINATION PROBLEM, and why it is not solved by matching every
# `.swap(` in the tree: `swap` and `compare_and_swap` are not unique to
# arc_swap. `std::sync::atomic::AtomicU64::swap(&self, val, order:
# Ordering) -> u64` and `<[T]>::swap(&mut self, a: usize, b: usize)`
# (slices and therefore Vec) both spell `.swap(`, and both are common and
# harmless; `std::sync::atomic::AtomicX::compare_and_swap` (deprecated but
# not removed) spells `.compare_and_swap(`. A rule that fired on every
# `.swap(` in the tree would trip on `std::mem::swap` age-old idiom code
# (actually a free function, `mem::swap(a, b)`, never `.swap(`, so that one
# was never a risk) and on the very file that reported this bug,
# `irontraffic-time/src/source.rs`, which legitimately calls `.swap(` on a
# plain `AtomicU64` field to simulate an NTP step. Firing on that call is
# exactly the failure this file's own header warns about: a rule annoying
# enough gets disabled by the first person it bothers, and then it guards
# nothing.
#
#     The fix is not a heuristic: it is `ArcSwapAny::swap`'s actual arity.
# `swap` takes exactly ONE argument (the new value); `AtomicX::swap` and
# `<[T]>::swap` both ALWAYS take exactly two (the Ordering argument is
# mandatory on every atomic method, and a slice swap is always two
# indices). So "exactly one top-level argument" is not a guess at which
# `.swap(` call is which, it is the one shape only ArcSwap's swap has among
# the three. The same reasoning separates ArcSwap's two-argument
# `compare_and_swap` from the deprecated atomic three-argument one (current,
# new, Ordering). Argument counting is done with rslex.top_level_split,
# which is multi-line-safe by construction (see the allow-needs-reason and
# balance-drop-only notes above for why that matters) rather than assuming
# a call's arguments stay on one line.
#
#     ACCEPTED GAP: `std::cell::Cell::swap(&self, other: &Cell<T>)` also
# takes exactly one argument, so a `.swap(` call on a `Cell` outside the
# five interior-mutability-scanned crates (where Cell is banned outright
# already) reads as an ArcSwap publish to this rule. Cell::swap is rare in
# practice (`.replace`/`.set` are the idiomatic ways to mutate a Cell), and
# an over-broad match here costs one allowlist entry with a reason, which is
# the same trade the rest of this rule already makes on purpose.
# ---------------------------------------------------------------------------
cat > "$WORK/arcswap_scan.py" <<'PY'
import os, re, sys

sys.path.insert(0, os.environ['WORK'])
import rslex

STORE = re.compile(r'\.store\s*\(')
SWAP = re.compile(r'\.swap\s*\(')
CAS = re.compile(r'\.compare_and_swap\s*\(')
RCU = re.compile(r'\.rcu\s*\(')
REASSIGN = re.compile(r'ArcSwap(?:Any)?(?:::<[^>]*>)?::(from_pointee|new)\s*\(')
BINDING = re.compile(r'^\s*(let\s+(mut\s+)?|static\s+(mut\s+)?|const\s+)')


def arg_count(text, open_idx, close_idx):
    return len([p for p in rslex.top_level_split(text, open_idx, close_idx) if p.strip()])


for path in sys.argv[1:]:
    try:
        text = open(path, encoding='utf-8').read()
    except (OSError, UnicodeDecodeError):
        continue
    lines = text.splitlines()
    hit_lines = set()

    for m in rslex.finditer_real(STORE, text):
        hit_lines.add(rslex.line_of(text, m.start()))

    for m in rslex.finditer_real(SWAP, text):
        o = m.end() - 1
        c = rslex.find_matching(text, o)
        if c < 0:
            continue
        # ArcSwapAny::swap takes exactly one argument; AtomicX::swap and
        # <[T]>::swap both always take exactly two. See the header note.
        if arg_count(text, o, c) == 1:
            hit_lines.add(rslex.line_of(text, m.start()))

    for m in rslex.finditer_real(CAS, text):
        o = m.end() - 1
        c = rslex.find_matching(text, o)
        if c < 0:
            continue
        # ArcSwapAny::compare_and_swap takes two arguments (current, new);
        # the deprecated AtomicX::compare_and_swap always takes three
        # (current, new, Ordering). See the header note.
        if arg_count(text, o, c) == 2:
            hit_lines.add(rslex.line_of(text, m.start()))

    for m in rslex.finditer_real(RCU, text):
        hit_lines.add(rslex.line_of(text, m.start()))

    for m in rslex.finditer_real(REASSIGN, text):
        i = m.start() - 1
        while i >= 0 and text[i] in ' \t\r\n':
            i -= 1
        if i < 0 or text[i] != '=':
            continue
        prev_c = text[i - 1] if i > 0 else ''
        next_c = text[i + 1] if i + 1 < len(text) else ''
        if prev_c in '=!<>' or next_c in '=>':
            continue  # ==, !=, <=, >=, => : not a plain assignment.
        j = i - 1
        while j >= 0 and text[j] not in ';{}':
            j -= 1
        stmt = text[j + 1:i]
        if BINDING.match(stmt):
            continue  # a fresh let/static/const binding, not a republish.
        hit_lines.add(rslex.line_of(text, m.start()))

    for line in sorted(hit_lines):
        content = lines[line - 1] if line - 1 < len(lines) else ''
        print(f'{path}:{line}:{content}')
PY
hits="$(
  {
    build_prod_tree
    ( cd "$PROD_TREE" && find . -name '*.rs' -print0 | xargs -0 -r python3 "$WORK/arcswap_scan.py" ) \
      | sed 's|^\./||' | drop_escaped single-snapshot-publish \
      | drop_allowlisted scripts/allowlist-arcswap-store.txt
    allowlist_stale_hits scripts/allowlist-arcswap-store.txt
  } || true
)"
[ -n "$hits" ] && fail single-snapshot-publish \
".store(, .swap(, .compare_and_swap(, .rcu(, or reassigning an existing
ArcSwap-typed place with a fresh ArcSwap::new/from_pointee, in production
code, is a violation unless the file is listed in
scripts/allowlist-arcswap-store.txt. This rule exists to keep ArcSwap
publication called from exactly one function in the whole workspace: a second
publication site reintroduces torn configuration, where a request could see
a route from generation N and a filter chain from N+1. .store( and .rcu( fire
on every call by that name, deliberately over-broad, because a same-line
ArcSwap-plus-store pattern misses ordinary multi-line code and would report a
guarantee it does not provide. .swap( and .compare_and_swap( fire only when
the argument count matches ArcSwap's own methods (one argument, and two
respectively), which is what tells them apart from a plain atomic integer's
same-named methods rather than a guess. If this file is not an ArcSwap
publisher (for example a plain Atomic::store or Atomic::swap), or if it is
the one designated publisher, add it to scripts/allowlist-arcswap-store.txt
with a reason in the same PR." "$hits"

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
#
#     TWO of the seven shapes below are NOT same-line greps, because the two
#     statement forms they match can each be split across lines by rustfmt
#     in a way that removes the co-occurrence a single-line regex needs:
#       - `pub use inner::{Helper, CoreCtx};` wraps its braced list onto
#         multiple lines once it has enough names, which is routine for a
#         re-export module. CoreCtx then sits on its own line with neither
#         "pub" nor "use" anywhere on it, so the same-line alternative that
#         requires both never matches either line.
#       - `type Alias = std::cell::RefCell<T>;` (or ArcSwap, or CoreCtx)
#         wraps immediately after `=` once the left-hand side plus `=` does
#         not leave room for the right-hand side, which is routine for a
#         long alias name describing a long guarded type. The guarded name
#         then sits on a line with no `type`/`=` on it at all.
#     Both are scanned with rslex instead: find the whole statement's span
#     (from `type`/`pub use` to its terminating `;`, wherever that lands) and
#     search WITHIN that span, rather than within one line of it.
# ---------------------------------------------------------------------------
cat > "$WORK/guarded_alias_multiline.py" <<'PY'
import os, re, sys

sys.path.insert(0, os.environ['WORK'])
import rslex

TYPE_HEAD = re.compile(r'^[ \t]*(pub[ \t]+)?type[ \t]+[A-Za-z_]\w*', re.MULTILINE)
PUB_USE = re.compile(r'^[ \t]*pub[ \t]+use\b', re.MULTILINE)
CORE = re.compile(r'\bCore(Ctx|Handle)\b')
CELL_ANGLE = re.compile(r'(^|[^A-Za-z_])(Cell|RefCell|UnsafeCell)<')
ARCSWAP = re.compile(r'(^|[^A-Za-z_])ArcSwap\b')

for path in sys.argv[1:]:
    try:
        text = open(path, encoding='utf-8').read()
    except (OSError, UnicodeDecodeError):
        continue
    lines = text.splitlines()
    hit_lines = set()

    for m in rslex.finditer_real(TYPE_HEAD, text):
        eq = rslex.find_first_real(text, m.end(), '=')
        if eq < 0:
            continue
        semi = rslex.find_first_real(text, eq, ';')
        end = semi if semi >= 0 else len(text)
        rhs = text[eq + 1:end]
        if CELL_ANGLE.search(rhs) or ARCSWAP.search(rhs) or CORE.search(rhs):
            hit_lines.add(rslex.line_of(text, m.start()))

    for m in rslex.finditer_real(PUB_USE, text):
        semi = rslex.find_first_real(text, m.end(), ';')
        end = semi if semi >= 0 else len(text)
        if CORE.search(text[m.end():end]):
            hit_lines.add(rslex.line_of(text, m.start()))

    for line in sorted(hit_lines):
        content = lines[line - 1] if line - 1 < len(lines) else ''
        print(f'{path}:{line}:{content}')
PY
hits="$(
  {
    scan_prod no-guarded-alias '(^|[^A-Za-z_])(Cell|RefCell|UnsafeCell)[[:space:]]+as[[:space:]]+[A-Za-z_]'
    scan_prod no-guarded-alias '(^|[^A-Za-z_])ArcSwap[[:space:]]+as[[:space:]]+[A-Za-z_]'
    scan_prod no-guarded-alias '(^|[^A-Za-z_])Core(Ctx|Handle)[[:space:]]+as[[:space:]]+[A-Za-z_]'
    build_prod_tree
    ( cd "$PROD_TREE" && find . -name '*.rs' -print0 | xargs -0 -r python3 "$WORK/guarded_alias_multiline.py" ) \
      | sed 's|^\./||' | drop_escaped no-guarded-alias
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
# 23. crate-inherits-workspace: a crate manifest that never opts into the
#     workspace lints compiles clean under a gate that looks identical to
#     the one every other crate passes, while checking almost nothing.
#
#     `scripts/gate-fast.sh` and CI invoke clippy per crate
#     (`-p <crate> --all-features`, or now per feature-matrix combination),
#     never `--workspace`. The `[workspace.lints]` table in the root
#     Cargo.toml (pedantic, unwrap_used, expect_used, indexing_slicing,
#     cast_possible_truncation, and the rest) therefore reaches a crate ONLY
#     if that crate's own manifest carries:
#
#       [lints]
#       workspace = true
#
#     A crate manifest missing that stanza is not a smaller violation of the
#     same kind every other rule here catches; it is the gate reporting
#     success while having checked almost nothing, which is the exact
#     failure class this whole file exists to close.
#
#     Also rejects a per-crate `edition` or `version` key: [workspace.package]
#     already provides both, and a crate that hardcodes its own silently
#     drifts from the floor the rest of the tree is held to -- edition 2021
#     against a workspace on 2024, or a version nobody remembers to bump. The
#     correct spelling is `edition.workspace = true` / `version.workspace =
#     true`, which this rule does not (and structurally cannot) flag: it
#     matches only a literal `edition = "..."` / `version = "..."` key,
#     never the `.workspace = true` form, because that form's key is
#     literally spelled `edition.workspace`, not `edition`.
#
#     Cargo.toml is TOML, not Rust, and cargo fmt never touches it, so none
#     of the line-wrapping concerns that motivate rslex elsewhere in this
#     file apply here: a manifest's `[section]` headers and `key = value`
#     lines are reliably one statement per line by TOML's own grammar.
#
#     NO ESCAPE HATCH: there is no legitimate case for a workspace crate to
#     opt out of the workspace lints or to hardcode a metadata field the
#     workspace already provides, the same way there is none for no-unsafe
#     above. Raise it on the issue instead of adding an it-allow marker here.
# ---------------------------------------------------------------------------
cat > "$WORK/crate_manifest.py" <<'PY'
import re, sys

def sections(lines):
    out, name, start = [], None, 0
    header = re.compile(r'^\s*\[([^\]]+)\]\s*$')
    for i, line in enumerate(lines):
        m = header.match(line)
        if m:
            if name is not None:
                out.append((name, start, i))
            name, start = m.group(1).strip(), i + 1
    if name is not None:
        out.append((name, start, len(lines)))
    return out

out = []
for path in sys.argv[1:]:
    try:
        text = open(path, encoding='utf-8').read()
    except OSError:
        continue
    lines = text.splitlines()
    secs = sections(lines)

    # A manifest that declares its own [workspace] table IS a workspace root, so
    # by definition it has no outer workspace to inherit from and `.workspace =
    # true` would not even parse. cargo-fuzz generates exactly this shape: a
    # nested crate under crates/<name>/fuzz/ carrying an empty [workspace] table
    # precisely so it is excluded from the parent workspace.
    #
    # This rule matched them because `git ls-files -- 'crates/*/Cargo.toml'` uses
    # git pathspec globbing, where `*` DOES cross a slash, so the pattern reaches
    # crates/<name>/fuzz/Cargo.toml as well as the direct children it was written
    # for. Filtering on the declaration rather than on directory depth is the
    # right fix: it also covers any future nested workspace, and it cannot be
    # defeated by moving a crate one level deeper.
    if any(name == 'workspace' for name, _s, _e in secs):
        continue

    lints_ok = False
    for name, s, e in secs:
        if name == 'lints':
            for j in range(s, e):
                if re.match(r'^\s*workspace\s*=\s*true\s*(#.*)?$', lines[j]):
                    lints_ok = True
    if not lints_ok:
        out.append(
            f'{path}:1: crate manifest has no `[lints]` section with '
            '`workspace = true`, so pedantic, unwrap_used, expect_used, '
            'indexing_slicing, and every other workspace lint never reach '
            'this crate under the per-crate gate'
        )

    for name, s, e in secs:
        if name != 'package':
            continue
        for j in range(s, e):
            line = lines[j]
            if line.strip().startswith('#'):
                continue
            m = re.match(r'^\s*(edition|version)\s*=\s*["\']', line)
            if m:
                key = m.group(1)
                out.append(
                    f'{path}:{j + 1}: hardcodes `{key} = ...` instead of '
                    f'`{key}.workspace = true`, so this crate can silently drift '
                    'from the value [workspace.package] sets for every other crate'
                )

print('\n'.join(out))
PY
hits="$(git ls-files -- 'crates/*/Cargo.toml' | tr '\n' '\0' | xargs -0 -r python3 "$WORK/crate_manifest.py" | grep -v '^$' || true)"
[ -n "$hits" ] && fail crate-inherits-workspace \
"Every crates/*/Cargo.toml must carry
  [lints]
  workspace = true
so the workspace's pedantic clippy lints, unwrap_used, expect_used,
indexing_slicing, and the rest actually reach this crate: the per-crate gate
invocation has no other way to apply them. It must also use
edition.workspace = true and version.workspace = true rather than
hardcoding either, so this crate cannot silently drift from what
[workspace.package] sets for the rest of the tree. There is no exception an
implementer is authorized to make; raise it on the issue instead." "$hits"

# ---------------------------------------------------------------------------
# 24. framing-fields-confined: KnownHeader::ContentLength and
#     KnownHeader::TransferEncoding decide where a message's body ends.
#     `request-framing-resolution` (#27) is the ONE place permitted to turn
#     that decision into a RequestFraming, and a second, unreviewed reader of
#     either variant is a second framing decision that can disagree with it,
#     which is exactly the shape of a request-smuggling bug.
#
#     The allowlist is exactly six files, named literally rather than
#     derived, because a grep with the wrong allowlist either passes
#     vacuously (too wide) or fails on correct code (too narrow):
#       known.rs      declares the variants and their canonical spellings.
#       framing.rs    resolves request framing (#27, this rule's own issue).
#       response.rs   resolves response framing (#28); applies the identical
#                      rules on the response side.
#       strip.rs      removes both fields from the section after framing has
#                      been resolved.
#       h1/serialize.rs regenerates them from the body actually being sent.
#       h1/chunked.rs (#36) never reads either variant, but its
#                      TRAILER_DENIED array must name both so a trailer can
#                      never introduce framing; a deny-list has to spell the
#                      names it denies, so it earns the sixth allowlist slot
#                      even though it never reads them.
#     Four of the six (response.rs, strip.rs, h1/serialize.rs, h1/chunked.rs)
#     do not exist on `main` yet. The allowlist names them now so this rule
#     does not need to widen again the moment each one merges.
# ---------------------------------------------------------------------------
hits="$(scan framing-fields-confined 'KnownHeader::(ContentLength|TransferEncoding)' rust_files \
  | grep -vE '^crates/irontraffic-http/src/(known|framing|response|strip|h1/serialize|h1/chunked)\.rs:' || true)"
[ -n "$hits" ] && fail framing-fields-confined \
"KnownHeader::ContentLength and KnownHeader::TransferEncoding may be read only
in known.rs, framing.rs, response.rs, strip.rs, h1/serialize.rs and
h1/chunked.rs. Reading either variant anywhere else is a second, unreviewed
framing decision that can disagree with resolve_request_framing, which is the
exact shape of a request-smuggling bug:
  // it-allow: framing-fields-confined reason: <why this file must read it>" "$hits"

# ---------------------------------------------------------------------------
if [ "$FAILED" -ne 0 ]; then
  printf '\ninvariant-lints: FAILED. Each block above names the rule, explains why it\n'
  printf 'exists, and lists the offending lines. Fix the code; do not silence a lint\n'
  printf 'unless you can write a reason a reviewer will accept.\n'
  exit 1
fi

echo "invariant-lints: clean"
