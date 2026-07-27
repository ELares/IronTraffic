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

# ---------------------------------------------------------------------------
# untracked-source (issue #513): census_worktree, below, enumerates the head
# side with `git ls-files -- '*.rs'`, tracked files only. A test file created
# on disk and not yet `git add`ed is invisible to it: its tests never enter
# head.tests or head.asserts, so this comparison has nothing to weigh them
# against.
#
# THE CONSEQUENCE DIFFERS FROM invariant-lints.sh's identical blind spot
# there, an untracked file with a real violation sails through because
# nothing scans it at all. Here the failure is quieter: an untracked test
# file is simply absent from both sides of the comparison, which is not
# itself a false pass on anything the base branch already proved. But it
# means a coder can add tests, watch the gate pass, and delete that same
# file again before ever staging it, and this census will have had no record
# that it ever existed to report its removal. Silence about presence becomes
# silence about disappearance the moment the file is gone.
#
# THE FIX IS THE SAME REFUSAL, APPLIED INDEPENDENTLY, NOT BY RELYING ON
# invariant-lints.sh HAVING ALREADY RUN. scripts/gate-fast.sh and scripts/
# gate.sh both run invariant-lints.sh, which carries the identical guard,
# before this script, so a properly gated run never reaches here with an
# untracked .rs file on disk: invariant-lints.sh already exited 1 first. But
# this script's own header says it "must remain fully self-contained" and
# assume nothing about what ran before it, precisely so it keeps working
# when invoked on its own (BASE_REF=main scripts/test-census.sh, exactly how
# an implementer debugging a census-only failure would run it) or from any
# future caller that composes the gate differently. A guard that only holds
# because of a sibling script's ordering is not a guard, it is a coincidence.
# ---------------------------------------------------------------------------
UNTRACKED_RS="$(git ls-files --others --exclude-standard -- '*.rs' \
  | grep -v -E '^(target|fuzz/target)/' || true)"
if [ -n "$UNTRACKED_RS" ]; then
  echo
  echo "FAIL [untracked-source]"
  cat <<'EOF' | sed 's/^/  /'
These files exist on disk but git is not tracking them, so the head side of
this census, which is built from git ls-files, has not read a single byte of
any of them. A brand-new test file added here would be invisible to both the
"removed" and the "weakened" comparisons below: adding it looks like nothing
happened, and deleting it again before staging looks like nothing happened
either. Stage every new file with git add before trusting this census.
EOF
  printf '%s\n' "$UNTRACKED_RS" | sed 's/^/    /'
  echo
  echo "test-census: FAILED. Tests are the only thing standing between a"
  echo "plausible implementation and a correct one; they are not an obstacle to"
  echo "route around."
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export WORK

# ---------------------------------------------------------------------------
# test-census-allow (issue #556 follow-up): the two FAIL messages below have
# told a reviewer to write "test-census-allow: <name> reason: <text>" in the
# pull request body since this script existed, and nothing anywhere ever read
# that line back. It was an escape hatch that could not be opened: every
# legitimate removal or per-file assertion drop this script's own comments
# already admit are "genuinely correct" (a test replaced by a strictly
# stronger one, or moved into a brand-new `tests/*.rs` binary, which rule 2
# below cannot treat as a wash the way it does a move between two EXISTING
# files, because the destination file has no "before" count to net against)
# had no path to a green build except a human bypassing this check entirely
# with --admin, which is a worse outcome than the check not existing: the
# badge claims a guarantee a bypass just proved it is not providing. Found
# implementing #556: moving `provider_lifecycle` to its own test binary, the
# correct fix for a real, confirmed test race, dropped
# crates/irontraffic-tls/src/provider.rs's own assertion count with no way to
# say so that this script would ever read.
#
# Reads the PR body live via the GitHub API, exactly the way
# scripts/pr-scope-check.sh already does, and only when PR_NUMBER is set: a
# push event (this script also runs on push, see the BASE_REF fallback above)
# has no pull request to read, and this must not treat "could not check" as
# "everything is allowed" by silently proceeding as if every removal were
# pre-approved. ALLOWED_NAMES and ALLOWED_PATHS are the two id-spaces the FAIL
# messages already promised, kept in separate files because a test name and a
# file path can collide as strings with no relation to each other.
ALLOWED_NAMES="$WORK/allowed.names"
ALLOWED_PATHS="$WORK/allowed.paths"
: > "$ALLOWED_NAMES"
: > "$ALLOWED_PATHS"
if [ -n "${PR_NUMBER:-}" ]; then
  REPO="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null)}"
  if PR_BODY="$(gh api "repos/$REPO/pulls/$PR_NUMBER" --jq '.body // ""' 2>/dev/null)"; then
    # One capture per line: the token right after "test-census-allow:" and
    # before " reason:". Requires the reason keyword to be present at all
    # (not that it says anything in particular) so a bare
    # "test-census-allow: foo" typo without a reason does not silently match;
    # the reviewer-facing point of this line is that a human wrote a sentence,
    # not that the sentence passes any content check.
    printf '%s\n' "$PR_BODY" \
      | grep -oE '^test-census-allow:[[:space:]]*[^[:space:]]+[[:space:]]+reason:.+$' \
      | sed -E 's/^test-census-allow:[[:space:]]*([^[:space:]]+)[[:space:]]+reason:.*/\1/' \
      > "$WORK/allow.tokens" || true
    # A token is a test NAME if it names something in base.tests' name column
    # (computed below, after this point runs, so this file is written but not
    # yet split here); simplest and least surprising: put every token in BOTH
    # lists. A test name and a real file path are different enough in shape
    # (a path contains '/', a Rust identifier never does) that a token
    # matching neither list on its actual check does nothing, so listing a
    # token in the list it does not apply to is inert, not a false allow.
    cp "$WORK/allow.tokens" "$ALLOWED_NAMES" 2>/dev/null || true
    cp "$WORK/allow.tokens" "$ALLOWED_PATHS" 2>/dev/null || true
  else
    echo "test-census: could not read PR #$PR_NUMBER's body (continuing with no allow-list; a genuine removal or weakening still fails below)" >&2
  fi
fi

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
GONE_ALL="$(LC_ALL=C comm -23 "$WORK/base.names" "$WORK/head.names")"

# Split GONE_ALL against the allow-list read above: a name present there was
# a reviewed, explicit decision, not a silent disappearance. Reported either
# way, because "allowed" is not the same thing as "invisible".
GONE="" GONE_ALLOWED=""
while IFS= read -r name; do
  [ -n "$name" ] || continue
  if LC_ALL=C grep -qxF "$name" "$ALLOWED_NAMES" 2>/dev/null; then
    GONE_ALLOWED="$GONE_ALLOWED$name
"
  else
    GONE="$GONE$name
"
  fi
done <<< "$GONE_ALL"
if [ -n "$GONE_ALLOWED" ]; then
  echo
  echo "test-census-allow honored (test-removed):"
  printf '%s' "$GONE_ALLOWED" | sed 's/^/    /'
fi

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
WEAKENED_ALL="$(python3 - "$WORK/base.asserts" "$WORK/head.asserts" "$WORK/base.strict" "$WORK/head.strict" <<'PY'
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

# Split WEAKENED_ALL against the allow-list the same way: each line is
# "<path>: ..."; the path is everything before the first ": ", which is safe
# because a Rust source path never itself contains ": ".
WEAKENED="" WEAKENED_ALLOWED=""
while IFS= read -r line; do
  [ -n "$line" ] || continue
  path="${line%%: *}"
  if LC_ALL=C grep -qxF "$path" "$ALLOWED_PATHS" 2>/dev/null; then
    WEAKENED_ALLOWED="$WEAKENED_ALLOWED$line
"
  else
    WEAKENED="$WEAKENED$line
"
  fi
done <<< "$WEAKENED_ALL"
if [ -n "$WEAKENED_ALLOWED" ]; then
  echo
  echo "test-census-allow honored (assertions-weakened):"
  printf '%s' "$WEAKENED_ALLOWED" | sed 's/^/    /'
fi

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
