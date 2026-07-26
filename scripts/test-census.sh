#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The test census: tests may be ADDED freely, but never silently removed or
# weakened.
#
# WHY THIS EXISTS. The fifteen invariant lints are all present-tense greps over
# the working tree, which makes them structurally blind to deletion: removing a
# test leaves a CLEANER tree and passes every one of them. They are equally
# blind to weakening, because `no-vacuous-assert` and `no-test-without-assertion`
# check that an assertion is PRESENT, not that it is STRONG. So
#
#     -    assert_eq!(parse("42").unwrap(), 42);
#     +    assert!(parse("42").is_ok());
#
# passes the entire gate today while destroying what the test proved.
#
# For an autonomous implementer facing a red build, deleting or loosening the
# failing test is the cheapest path to green. It is not malice, it is the
# gradient, and no amount of prose in a prompt removes a gradient. This is the
# mechanical answer.
#
# The check is deliberately one-directional: adding tests and adding assertions
# is always allowed. Only removal and weakening are refused, and only with a
# written justification in the pull request body can they land at all.
#
# Environment: BASE_REF (defaults to origin/main).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

BASE="${BASE_REF:-main}"
if git rev-parse --verify --quiet "origin/$BASE" >/dev/null; then
  BASE_REV="origin/$BASE"
elif git rev-parse --verify --quiet "$BASE" >/dev/null; then
  BASE_REV="$BASE"
elif git rev-parse --verify --quiet FETCH_HEAD >/dev/null; then
  BASE_REV=FETCH_HEAD
else
  echo "test-census: cannot resolve a base revision from BASE_REF='$BASE'; refusing to pass vacuously" >&2
  exit 1
fi

# The merge base, not the base tip. Using the tip would attribute every test
# that landed on the base branch after this work started to this diff.
MERGE_BASE="$(git merge-base "$BASE_REV" HEAD)" || {
  echo "test-census: no merge base with $BASE_REV" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export WORK

# rslex.py: the same literal- and comment-aware Rust scanner
# scripts/invariant-lints.sh uses, with two census-specific helpers added at
# the bottom. Kept as an independent copy (not a shared file read via a
# relative path) because this script, like invariant-lints.sh, must remain
# fully self-contained: nothing here may assume the current directory still
# has a scripts/ next to it.
#
# WHY THE TEST-NAME REGEX CHANGED. `#\[(?:tokio::)?test[^\]]*\]\s*
# (?:async\s+)?fn\s+(\w+)` required `fn` to follow the test marker with
# nothing but whitespace in between. Any further attribute placed there --
# most commonly `#[allow(..., reason = "...")]` on a property test whose
# generator needs one -- made the whole function invisible to this census.
# The census is the ONE mechanism that catches a test being deleted,
# renamed away, or emptied of assertions to reach a green gate; a test it
# cannot see can be deleted with the census reporting clean. This is fixed
# the same way as the equivalent bug in invariant-lints.sh's
# no-test-without-assertion rule: walk past any number of `#[...]`
# attributes (matched by bracket depth, not a `[^\]]*` guess that a nested
# `[...]` or a `]` inside a string could defeat) before requiring `fn`.
#
# WHY THE ASSERTION COUNT ALSO CHANGED. `len(re.findall(r"\bassert\w*!",
# text))` counted a match anywhere in the file, including inside a doc
# comment or a string literal that merely MENTIONS an assertion macro
# (`/// see assert_eq! above`, or a message string quoting one). That can
# inflate a file's count independently of its real tests, which is a false
# NEGATIVE waiting to happen: a real assertion removed on the same diff that
# also removes an unrelated comment mentioning one would net out to "no
# change" and pass silently. Counting only occurrences rslex confirms are
# not inside a literal or comment closes that.
cat > "$WORK/rslex.py" <<'PYLEX'
import re


def skip_trivia(text, i):
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
        return i
    if c == '"':
        return _skip_quoted(text, i)
    if c == "'":
        end = _skip_char_literal(text, i)
        if end is not None:
            return end
        return i + 1
    return i


def _skip_quoted(text, i):
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


def finditer_real(pattern, text):
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


TEST_ATTR = re.compile(r'#\[\s*(?:tokio::)?test\b')
ASSERT = re.compile(r'\bassert\w*!')
ASSERT_STRICT = re.compile(r'\bassert_(?:eq|ne)!')


def find_test_names(text):
    """Yields function names for every #[test] / #[tokio::test] in `text`,
    tolerant of any number of further #[...] attributes between the test
    marker and `fn` (bracket-matched, not `[^\\]]*`-guessed, so a nested
    `[...]` or a `]` inside a string cannot cut the walk short)."""
    n = len(text)
    for m in finditer_real(TEST_ATTR, text):
        attr_open = text.index('[', m.start())
        attr_close = find_matching(text, attr_open)
        if attr_close < 0:
            continue
        i = attr_close + 1
        while True:
            while i < n:
                skipped = skip_trivia(text, i)
                if skipped != i:
                    i = skipped
                    continue
                if text[i].isspace():
                    i += 1
                    continue
                break
            if i < n and text[i] == '#' and i + 1 < n and text[i + 1] == '[':
                close = find_matching(text, i + 1)
                if close < 0:
                    break
                i = close + 1
                continue
            break
        fm = re.match(r'(?:async\s+)?fn\s+(\w+)', text[i:])
        if fm:
            yield fm.group(1)


def count_real_asserts(text):
    """Counts assert*! occurrences that are not inside a string, char
    literal, or comment."""
    return sum(1 for _ in finditer_real(ASSERT, text))


def count_real_strict_asserts(text):
    """Counts assert_eq!/assert_ne! occurrences that are not inside a
    string, char literal, or comment. Same literal- and comment-aware
    scanner as count_real_asserts, restricted to the two comparison-style
    macros: a doc comment or string that merely MENTIONS assert_eq! must
    not inflate this count any more than it inflates the total one."""
    return sum(1 for _ in finditer_real(ASSERT_STRICT, text))
PYLEX

# Census a whole tree at a revision: one line per test, "path\tname", plus a
# per-file TOTAL assertion count and a per-file STRICT assertion count.
#
# The strict count exists because the total count alone misses a real
# weakening: `assert_eq!(x, 42)` becoming `assert!(x.is_ok())` is a straight
# one-for-one swap of one assert-family macro invocation for another, so the
# total per file is unchanged before and after. `assert_eq!`/`assert_ne!`
# compare two concrete values; a bare `assert!` can be satisfied by almost
# anything, including a check that proves far less than the one it replaced.
# Tracking the count of the comparison-style macros separately, and failing on
# a drop in EITHER metric, catches the same-count substitution the total alone
# is blind to. This was found by actually running the probe described in
# issue #454, not by inspection: the total-only version of this script passed
# a real assert_eq-to-assert weakening silently.
#
# The strict count goes through the same rslex scanner as the total count,
# not a second, plainer regex: a doc comment or string that merely mentions
# assert_eq! must not inflate the strict count any more than it inflates the
# total one, for the same false-negative reason explained above.
census() {
  local rev="$1" out="$2" counts="$3" strict="$4"
  : > "$out"; : > "$counts"; : > "$strict"
  # No pathspec: `git ls-tree -r --name-only <rev> -- '*.rs'` matches NOTHING,
  # because ls-tree pathspecs are anchored and a bare *.rs never matches a
  # nested path. That silently produced a census of zero tests, which is a
  # vacuous check that would have passed every deletion. Filter instead.
  git ls-tree -r --name-only "$rev" | grep -E '\.rs$' | while read -r f; do
    local body
    body="$(git show "$rev:$f" 2>/dev/null)" || continue
    printf '%s' "$body" | python3 -c '
import os, sys
sys.path.insert(0, os.environ["WORK"])
import rslex
path = sys.argv[1]
text = sys.stdin.read()
for name in rslex.find_test_names(text):
    print(f"{path}\t{name}")
' "$f" >> "$out"
    printf '%s' "$body" | python3 -c '
import os, sys
sys.path.insert(0, os.environ["WORK"])
import rslex
path = sys.argv[1]
text = sys.stdin.read()
n = rslex.count_real_asserts(text)
# Printed UNCONDITIONALLY, even when n is 0: the comparison below treats a
# path missing from this file as "the whole file is gone" (rule 1 already
# reports the tests it held) and skips it, rather than as "this file now
# has zero assertions". If a file that used to hold one assertion has it
# deleted while the file itself survives, omitting the zero line here would
# make that reduction indistinguishable from a deleted file and it would
# never be reported: assertions-weakened exists specifically to catch an
# assertion being removed or loosened, and "removed all the way to zero" is
# the most complete form of removal there is.
print(f"{path}\t{n}")
' "$f" >> "$counts"
    printf '%s' "$body" | python3 -c '
import os, sys
sys.path.insert(0, os.environ["WORK"])
import rslex
path = sys.argv[1]
text = sys.stdin.read()
n = rslex.count_real_strict_asserts(text)
# Printed UNCONDITIONALLY, same reasoning as the total count above: a file
# whose last assert_eq!/assert_ne! was swapped for a bare assert! must read
# as "0 strict assertions" rather than vanish from this file and read as
# "file gone".
print(f"{path}\t{n}")
' "$f" >> "$strict"
  done
}

# Census the WORKING TREE for the head side, not the HEAD commit.
#
# gate.sh runs this BEFORE the implementer commits, which is the moment it has
# to be useful: an agent that just deleted a failing test needs to be told now,
# not after it has pushed. Reading `git show HEAD:<file>` would compare the last
# commit against itself and pass every uncommitted deletion. In CI the checkout
# and the commit agree, so reading the filesystem is correct in both settings.
census_worktree() {
  local out="$1" counts="$2" strict="$3"
  : > "$out"; : > "$counts"; : > "$strict"
  git ls-files -- '*.rs' | while read -r f; do
    [ -f "$f" ] || continue
    python3 -c '
import os, sys
sys.path.insert(0, os.environ["WORK"])
import rslex
path = sys.argv[1]
text = open(path, encoding="utf-8", errors="replace").read()
for name in rslex.find_test_names(text):
    print(f"{path}\t{name}")
' "$f" >> "$out"
    python3 -c '
import os, sys
sys.path.insert(0, os.environ["WORK"])
import rslex
path = sys.argv[1]
text = open(path, encoding="utf-8", errors="replace").read()
n = rslex.count_real_asserts(text)
# Printed UNCONDITIONALLY, even when n is 0: the comparison below treats a
# path missing from this file as "the whole file is gone" (rule 1 already
# reports the tests it held) and skips it, rather than as "this file now
# has zero assertions". If a file that used to hold one assertion has it
# deleted while the file itself survives, omitting the zero line here would
# make that reduction indistinguishable from a deleted file and it would
# never be reported: assertions-weakened exists specifically to catch an
# assertion being removed or loosened, and "removed all the way to zero" is
# the most complete form of removal there is.
print(f"{path}\t{n}")
' "$f" >> "$counts"
    python3 -c '
import os, sys
sys.path.insert(0, os.environ["WORK"])
import rslex
path = sys.argv[1]
text = open(path, encoding="utf-8", errors="replace").read()
n = rslex.count_real_strict_asserts(text)
# Printed UNCONDITIONALLY, same reasoning as the total count above: a file
# whose last assert_eq!/assert_ne! was swapped for a bare assert! must read
# as "0 strict assertions" rather than vanish from this file and read as
# "file gone".
print(f"{path}\t{n}")
' "$f" >> "$strict"
  done
}

census "$MERGE_BASE" "$WORK/base.tests" "$WORK/base.asserts" "$WORK/base.strict"
census_worktree      "$WORK/head.tests" "$WORK/head.asserts" "$WORK/head.strict"

LC_ALL=C sort -o "$WORK/base.tests" "$WORK/base.tests"
LC_ALL=C sort -o "$WORK/head.tests" "$WORK/head.tests"

FAILED=0

# ---------------------------------------------------------------------------
# 1. No test may disappear.
#
# A test that MOVED (same name, different file) is fine and common: modules get
# split. So compare by NAME, not by path, and only complain when a name is gone
# from the tree entirely.
# ---------------------------------------------------------------------------
cut -f2 "$WORK/base.tests" | LC_ALL=C sort -u > "$WORK/base.names"
cut -f2 "$WORK/head.tests" | LC_ALL=C sort -u > "$WORK/head.names"
GONE="$(LC_ALL=C comm -23 "$WORK/base.names" "$WORK/head.names")"

if [ -n "$GONE" ]; then
  echo
  echo "FAIL [test-removed]"
  cat <<'EOF' | sed 's/^/  /'
These tests existed on the base branch and are absent from this branch. Tests
may be added freely; removing one is a reduction in what the repository proves,
and it is the cheapest way to turn a red build green.

If a removal is genuinely correct (the behavior it covered was deleted, or it
was replaced by a strictly stronger test), say so explicitly in the pull request
body on a line beginning:

    test-census-allow: <test_name> reason: <why removing it loses nothing>

one line per test. A reviewer then has to accept that sentence, which is the
point: the removal becomes a decision somebody made rather than a side effect.
EOF
  printf '%s\n' "$GONE" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 2. No file may lose assertions, by TOTAL count or by STRICT count.
#
# The total catches assertions deleted outright. It does NOT catch the subtle
# form: `assert_eq!(x, 42)` becoming `assert!(x.is_ok())` is one assert-family
# macro invocation replaced by another, so the total per file is unchanged.
# The strict count (assert_eq!/assert_ne! only) catches exactly that swap,
# because it drops from 1 to 0 even while the total holds steady. Both are
# compared per file so that moving tests between files does not trip either
# one as long as the total in a surviving file does not drop.
# ---------------------------------------------------------------------------
WEAKENED="$(python3 - "$WORK/base.asserts" "$WORK/head.asserts" "$WORK/base.strict" "$WORK/head.strict" <<'PY'
import sys
def load(p):
    d = {}
    try:
        for line in open(p, encoding="utf-8"):
            if "\t" not in line: continue
            path, n = line.rstrip("\n").split("\t", 1)
            d[path] = int(n)
    except OSError:
        pass
    return d
base, head = load(sys.argv[1]), load(sys.argv[2])
base_strict, head_strict = load(sys.argv[3]), load(sys.argv[4])
for path, n in sorted(base.items()):
    m = head.get(path)
    if m is None:      # whole file gone; rule 1 reports the tests it held
        continue
    if m < n:
        print(f"{path}: {n} -> {m} assertions ({n - m} fewer)")
for path, n in sorted(base_strict.items()):
    m = head_strict.get(path)
    if m is None:      # whole file gone; rule 1 reports the tests it held
        continue
    if m < n:
        print(f"{path}: {n} -> {m} assert_eq!/assert_ne! ({n - m} fewer, even if the total assertion count held steady)")
PY
)"

if [ -n "$WEAKENED" ]; then
  echo
  echo "FAIL [assertions-weakened]"
  cat <<'EOF' | sed 's/^/  /'
These files assert less than they did on the base branch. The usual cause is an
assertion loosened to make a failing test pass, for example changing
`assert_eq!(x, 42)` into `assert!(x.is_ok())`. Both forms satisfy every existing
lint, and only one of them proves anything.

Strengthen the assertion instead, or justify the reduction in the pull request
body on a line beginning:

    test-census-allow: <path> reason: <why the file needs fewer assertions>
EOF
  printf '%s\n' "$WEAKENED" | sed 's/^/    /'
  FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
  echo
  echo "test-census: FAILED. Tests are the only thing standing between a"
  echo "plausible implementation and a correct one; they are not an obstacle to"
  echo "route around."
  exit 1
fi

BASE_N=$(wc -l < "$WORK/base.names" | tr -d ' ')
HEAD_N=$(wc -l < "$WORK/head.names" | tr -d ' ')
echo "test-census: clean ($BASE_N tests on base, $HEAD_N here, none removed, none weakened)"
