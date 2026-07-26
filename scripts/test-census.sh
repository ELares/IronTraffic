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
import re, sys
path = sys.argv[1]
text = sys.stdin.read()
for m in re.finditer(r"#\[(?:tokio::)?test[^\]]*\]\s*(?:async\s+)?fn\s+(\w+)", text):
    print(f"{path}\t{m.group(1)}")
' "$f" >> "$out"
    printf '%s' "$body" | python3 -c '
import re, sys
path = sys.argv[1]
text = sys.stdin.read()
n = len(re.findall(r"\bassert\w*!", text))
if n:
    print(f"{path}\t{n}")
' "$f" >> "$counts"
    printf '%s' "$body" | python3 -c '
import re, sys
path = sys.argv[1]
text = sys.stdin.read()
n = len(re.findall(r"\bassert_(?:eq|ne)!", text))
if n:
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
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8", errors="replace").read()
for m in re.finditer(r"#\[(?:tokio::)?test[^\]]*\]\s*(?:async\s+)?fn\s+(\w+)", text):
    print(f"{path}\t{m.group(1)}")
' "$f" >> "$out"
    python3 -c '
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8", errors="replace").read()
n = len(re.findall(r"\bassert\w*!", text))
if n:
    print(f"{path}\t{n}")
' "$f" >> "$counts"
    python3 -c '
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8", errors="replace").read()
n = len(re.findall(r"\bassert_(?:eq|ne)!", text))
if n:
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
    if head.get(path) is None:
        continue      # whole file gone, or now has zero assertions of any
                       # kind; rule 1 and the no-vacuous-assert invariant lint
                       # cover those cases respectively
    m = head_strict.get(path, 0)
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
