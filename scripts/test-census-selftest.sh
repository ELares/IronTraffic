#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Self-test for scripts/test-census.sh.
#
# WHY THIS EXISTS. test-census.sh is the one mechanism that catches a test
# being deleted, renamed away, or emptied of assertions to turn a red build
# green. It used to be blind to any test with an attribute (most commonly
# #[allow(..., reason = "...")]) between #[test] and fn: such a test was
# invisible to the census entirely, so deleting it left the census reporting
# clean. It was also blind to an assertion count that a decorative comment or
# string literal inflated or hid, and separately blind to a same-total swap
# (assert_eq!(x, 42) becoming assert!(x > 0), one assert-family macro
# invocation for another, leaving the total count per file unchanged). A
# census that cannot see what it is meant to guard is worse than no census:
# it reports success while proving nothing. This builds two small throwaway
# git histories (a base commit and
# a head state) and runs the real script against them, so it tests the
# shipped script, not a description of it.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
CENSUS="$PWD/scripts/test-census.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILED=0
note() { printf '  %s\n' "$1"; }

# base_commit <dir> <lib.rs content> -- a throwaway repo with one commit.
base_commit() {
  local dir="$1" content="$2"
  mkdir -p "$dir/src"
  printf '%s' "$content" > "$dir/src/lib.rs"
  ( cd "$dir" && git init -q . && git config user.email t@t && git config user.name t \
      && git add -A >/dev/null && git commit -qm base >/dev/null )
}

# run_census <dir> -- runs the real script with BASE_REF=HEAD (the commit
# just made), against whatever the working tree currently holds.
run_census() {
  ( cd "$1" && BASE_REF=HEAD bash "$CENSUS" 2>&1 || true )
}

# run_census_with_pr <dir> <pr_body> -- runs the real script as if invoked
# from a pull request whose body is exactly <pr_body>, WITHOUT any real
# network or GitHub API access: a fake `gh` shadowing the real one on PATH
# answers the one call scripts/test-census.sh makes (`gh api
# repos/<repo>/pulls/<n>`) by echoing <pr_body> back, and `gh repo view` with
# a fixed fake slug. This keeps the selftest fully offline and deterministic,
# the same property every other corpus in this file already has; it does not
# depend on this repository, this PR, or any real GitHub state.
run_census_with_pr() {
  local dir="$1" body="$2"
  local fakebin="$WORK/fakebin"
  mkdir -p "$fakebin"
  printf '%s' "$body" > "$WORK/pr-body.txt"
  cat > "$fakebin/gh" <<FAKEGH
#!/usr/bin/env bash
if [ "\$1" = "repo" ] && [ "\$2" = "view" ]; then
  echo "test-org/test-repo"
  exit 0
fi
if [ "\$1" = "api" ]; then
  cat "$WORK/pr-body.txt"
  exit 0
fi
echo "fake gh: unhandled args: \$*" >&2
exit 1
FAKEGH
  chmod +x "$fakebin/gh"
  ( cd "$dir" && PATH="$fakebin:$PATH" PR_NUMBER=1 GITHUB_REPOSITORY=test-org/test-repo \
      BASE_REF=HEAD bash "$CENSUS" 2>&1 || true )
}

BASE_LIB='//! Base revision: one attributed test with a real assertion.
pub fn add(a: u8, b: u8) -> u8 { a + b }

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    #[allow(clippy::assertions_on_constants, reason = "documented invariant")]
    fn adds_two_numbers() {
        assert_eq!(add(2, 3), 5);
    }
}
'

# ---------------------------------------------------------------------------
# 1. Unchanged: the attributed test must be COUNTED (not merely "not
#    flagged"), so the head census total matches the base total exactly and
#    reports clean.
# ---------------------------------------------------------------------------
D1="$WORK/unchanged"
base_commit "$D1" "$BASE_LIB"
echo "== unchanged: an attribute between #[test] and fn must be counted =="
OUT1="$(run_census "$D1")"
if echo "$OUT1" | grep -q '^test-census: clean (1 tests on base, 1 here, none removed, none weakened)$'; then
  note "counted correctly on both sides (1 test, unchanged)"
else
  echo "FAIL: expected a clean census counting exactly 1 test on each side. Got:"
  echo "$OUT1" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 2. Deleted: removing the attributed test must be CAUGHT. Before the fix,
#    the test was invisible to the census (0 counted on base too), so its
#    deletion passed silently; this is the direct regression test for that.
# ---------------------------------------------------------------------------
D2="$WORK/deleted"
base_commit "$D2" "$BASE_LIB"
printf '%s' '//! Head: the attributed test is gone.
pub fn add(a: u8, b: u8) -> u8 { a + b }
' > "$D2/src/lib.rs"
echo "== deleted: removing an attributed test must be reported =="
OUT2="$(run_census "$D2")"
if echo "$OUT2" | grep -q 'FAIL \[test-removed\]' && echo "$OUT2" | grep -q 'adds_two_numbers'; then
  note "deletion of the attributed test is caught and named"
else
  echo "FAIL: deleting the attributed test did not trip test-removed. Got:"
  echo "$OUT2" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 3. Weakened: removing a file's ONLY assertion, without touching the test's
#    name, must be caught. This is also the direct regression test for a
#    SECOND, independent bug this self-test caught while it was being
#    written: the per-file assertion count used to be printed only `if n:`
#    (n truthy), so a file whose count dropped to EXACTLY ZERO vanished from
#    the head-side count file entirely. The comparison then read "path
#    missing from head" as "the whole file is gone" (which rule 1 already
#    covers) and skipped it, so reducing a file's real assertions all the
#    way to zero -- the most complete form of weakening there is -- passed
#    silently. Confirmed present in the script BEFORE this fix by running it
#    against this exact fixture and getting a clean report.
# ---------------------------------------------------------------------------
D3="$WORK/weakened"
base_commit "$D3" "$BASE_LIB"
printf '%s' '//! Head: the assertion is loosened from assert_eq! to a vacuous-looking
//! assert!, reducing this file'"'"'s real assertion count from one to zero
//! genuinely-informative checks -- here, simply removing it, which is the
//! plain "fewer asserts in this file" case the count exists to catch.
pub fn add(a: u8, b: u8) -> u8 { a + b }

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    #[allow(clippy::assertions_on_constants, reason = "documented invariant")]
    fn adds_two_numbers() {
        let _ = add(2, 3);
    }
}
' > "$D3/src/lib.rs"
echo "== weakened: fewer real assertions in the same file must be reported =="
OUT3="$(run_census "$D3")"
if echo "$OUT3" | grep -q 'FAIL \[assertions-weakened\]'; then
  note "the reduced assertion count is caught"
else
  echo "FAIL: removing the assertion from the attributed test did not trip"
  echo "      assertions-weakened. Got:"
  echo "$OUT3" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 4. A decoy #[allow(...)] carrying no test at all (an ordinary attributed
#    function) must NOT be counted as a test: proves the walk stops at a
#    real `fn` and does not just count every `#[...]`-decorated function in
#    the file once it has learned to tolerate attributes.
# ---------------------------------------------------------------------------
D4="$WORK/no-false-test"
base_commit "$D4" '//! An attributed function that is not a test must not be counted as one.
#[allow(dead_code, reason = "corpus-only")]
pub fn helper() -> u8 { 1 }
'
echo "== an attributed non-test function must not be counted as a test =="
OUT4="$(run_census "$D4")"
if echo "$OUT4" | grep -q '^test-census: clean (0 tests on base, 0 here, none removed, none weakened)$'; then
  note "an attributed non-test function is correctly not counted"
else
  echo "FAIL: an ordinary attributed function was miscounted as a test. Got:"
  echo "$OUT4" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 5. A doc comment that merely MENTIONS assert_eq! in prose must not inflate
#    the real assertion count, and a #[test] appearing only inside a string
#    or comment must not be counted as a real test.
# ---------------------------------------------------------------------------
D5="$WORK/prose-decoys"
base_commit "$D5" '//! Example: `assert_eq!(add(2, 3), 5)` demonstrates the invariant.
//! A #[test] mentioned here in prose is not a real test either.
pub fn add(a: u8, b: u8) -> u8 { a + b }

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn adds_two_numbers() {
        assert_eq!(add(2, 3), 5);
    }
}
'
echo "== prose mentioning assert_eq!/#[test] must not inflate the counts =="
OUT5="$(run_census "$D5")"
if echo "$OUT5" | grep -q '^test-census: clean (1 tests on base, 1 here, none removed, none weakened)$'; then
  note "prose mentions did not inflate the test or assertion count"
else
  echo "FAIL: a doc comment mentioning assert_eq!/#[test] as prose changed the"
  echo "      counted totals for an otherwise-unchanged file. Got:"
  echo "$OUT5" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 6. Same-total swap: assert_eq!(x, 42) becoming assert!(x > 0) is one
#    assert-family macro invocation replaced by another, so the TOTAL count
#    for this file is unchanged (1 -> 1) and case 3 above would not catch it.
#    This is issue #454's bug, independent of case 3's drop-to-zero bug: the
#    strict assert_eq!/assert_ne!-only count must still drop (1 -> 0) and be
#    reported, even though the total holds steady. Confirmed present in the
#    total-only version of this script by running it against this exact
#    fixture and getting a clean report.
# ---------------------------------------------------------------------------
D6="$WORK/same-total-swap"
base_commit "$D6" '//! Base revision: one comparison-style assertion.
pub fn add(a: u8, b: u8) -> u8 { a + b }

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn adds_two_numbers() {
        assert_eq!(add(2, 3), 5);
    }
}
'
printf '%s' '//! Head: assert_eq! swapped for a bare assert!, one-for-one. The total
//! assert-family count for this file is unchanged; only the strict
//! assert_eq!/assert_ne! count drops.
pub fn add(a: u8, b: u8) -> u8 { a + b }

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn adds_two_numbers() {
        assert!(add(2, 3) > 0);
    }
}
' > "$D6/src/lib.rs"
echo "== same-total swap: assert_eq! -> assert! must be reported even though the total holds steady =="
OUT6="$(run_census "$D6")"
if echo "$OUT6" | grep -q 'FAIL \[assertions-weakened\]' && echo "$OUT6" | grep -q 'assert_eq!/assert_ne!'; then
  note "the same-total assert_eq!-to-assert! swap is caught by the strict count"
else
  echo "FAIL: swapping assert_eq! for assert! one-for-one did not trip"
  echo "      assertions-weakened via the strict count. Got:"
  echo "$OUT6" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 7. untracked-source (issue #513). census_worktree builds the head side from
#    `git ls-files -- '*.rs'`, tracked files only, so a brand-new .rs file
#    that has not been `git add`ed must make the census refuse outright
#    rather than silently compare a head side that never read it. Proven in
#    the same three directions as the identical guard in
#    invariant-lints.sh: a fully tracked tree passes, a .gitignore-excluded
#    file does not trip it, and a genuine untracked file does and is named.
# ---------------------------------------------------------------------------
D7="$WORK/untracked"
base_commit "$D7" '//! A clean, tracked baseline for the untracked-source corpus.
pub fn add(a: u8, b: u8) -> u8 { a + b }
'
echo "== untracked-source, stage 1: a fully tracked tree must not trip it =="
OUT7A="$(run_census "$D7")"
if printf '%s\n' "$OUT7A" | grep -q '^FAIL \[untracked-source\]$'; then
  echo "FAIL: untracked-source fired on a fully tracked tree. Got:"
  echo "$OUT7A" | sed 's/^/    /'
  FAILED=1
else
  note "fully tracked tree does not trip untracked-source"
fi

printf 'ignored.rs\n' > "$D7/.gitignore"
cat > "$D7/src/ignored.rs" <<'RS'
//! Excluded by .gitignore; must not surface even though it is untracked.
pub fn stub() {}
RS
echo "== untracked-source, stage 2: a .gitignore-excluded file must not trip it =="
OUT7B="$(run_census "$D7")"
if printf '%s\n' "$OUT7B" | grep -q '^FAIL \[untracked-source\]$'; then
  echo "FAIL: untracked-source fired on a file .gitignore already excludes. Got:"
  echo "$OUT7B" | sed 's/^/    /'
  FAILED=1
else
  note "gitignored file does not trip untracked-source"
fi

cat > "$D7/src/new_untracked.rs" <<'RS'
//! Untracked on purpose: never `git add`ed in this corpus step.
pub fn double(a: u8) -> u8 { a * 2 }
RS
echo "== untracked-source, stage 3: an untracked .rs file must trip it and be named =="
OUT7C="$(run_census "$D7")"
if printf '%s\n' "$OUT7C" | grep -q '^FAIL \[untracked-source\]$' \
    && printf '%s\n' "$OUT7C" | grep -qF 'src/new_untracked.rs'; then
  note "untracked .rs file trips untracked-source and is named"
else
  echo "FAIL: an untracked .rs file did not trip untracked-source, or did not name it. Got:"
  echo "$OUT7C" | sed 's/^/    /'
  FAILED=1
fi
if printf '%s\n' "$OUT7C" | grep -qF 'ignored.rs'; then
  echo "FAIL: the gitignored file was named as an untracked-source offender."
  FAILED=1
else
  note "the gitignored file is never named, even in a failing run"
fi

# ---------------------------------------------------------------------------
# 8. test-census-allow (issue #589): the FAIL messages for both rules have
#    always told a reviewer to write this line in the pull request body; nothing
#    ever read it back until this. Proven in four directions: a matching path
#    allowance clears rule 2, a matching name allowance clears rule 1
#    independently of rule 2, a non-matching allowance still fails, and no
#    PR_NUMBER at all (a push event) behaves exactly as if the feature did not
#    exist, because "could not check the body" must never read as "everything
#    is allowed".
# ---------------------------------------------------------------------------
D8="$WORK/census-allow"
base_commit "$D8" '//! Base revision: one file with a real assertion.
pub fn add(a: u8, b: u8) -> u8 { a + b }

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn adds_two_numbers() {
        assert_eq!(add(2, 3), 5);
        assert_eq!(add(0, 0), 0);
    }
}
'
# head: drop one assertion from the same file, with no PR context at all.
cat > "$D8/src/lib.rs" <<'RS'
//! Head revision: one assertion removed from the surviving test.
pub fn add(a: u8, b: u8) -> u8 { a + b }

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn adds_two_numbers() {
        assert_eq!(add(2, 3), 5);
    }
}
RS

echo "== test-census-allow, stage 1: no PR_NUMBER at all must still fail =="
OUT8A="$(run_census "$D8")"
if printf '%s\n' "$OUT8A" | grep -q '^FAIL \[assertions-weakened\]$'; then
  note "with no PR context, a real weakening still fails"
else
  echo "FAIL: a genuine weakening passed with no PR_NUMBER set. Got:"
  echo "$OUT8A" | sed 's/^/    /'
  FAILED=1
fi

echo "== test-census-allow, stage 2: a non-matching allow line must still fail =="
OUT8B="$(run_census_with_pr "$D8" 'test-census-allow: src/unrelated.rs reason: does not name the file that actually changed')"
if printf '%s\n' "$OUT8B" | grep -q '^FAIL \[assertions-weakened\]$'; then
  note "a non-matching allow line does not excuse a real weakening"
else
  echo "FAIL: a non-matching allow line excused a weakening it does not name. Got:"
  echo "$OUT8B" | sed 's/^/    /'
  FAILED=1
fi

echo "== test-census-allow, stage 3: a matching PATH allow line clears rule 2 =="
OUT8C="$(run_census_with_pr "$D8" 'test-census-allow: src/lib.rs reason: intentionally trimmed a redundant assertion in this selftest fixture')"
if printf '%s\n' "$OUT8C" | grep -q '^FAIL \[assertions-weakened\]$'; then
  echo "FAIL: a matching test-census-allow path line did not clear the weakening. Got:"
  echo "$OUT8C" | sed 's/^/    /'
  FAILED=1
elif ! printf '%s\n' "$OUT8C" | grep -qF 'test-census-allow honored'; then
  echo "FAIL: the census passed but never said the allowance was honored. Got:"
  echo "$OUT8C" | sed 's/^/    /'
  FAILED=1
else
  note "a matching path allow line clears assertions-weakened and says so"
fi

# A genuine test REMOVAL (not a same-file edit), to prove rule 1's own
# allow-by-name is independent of rule 2's allow-by-path: naming only the
# test must not also silence a real per-file assertion drop.
D8B="$WORK/census-allow-removed"
base_commit "$D8B" '//! Base revision: two tests.
pub fn add(a: u8, b: u8) -> u8 { a + b }

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn removed_test() {
        assert_eq!(add(1, 1), 2);
        assert_eq!(add(2, 2), 4);
    }

    #[test]
    fn surviving_test() {
        assert_eq!(add(0, 0), 0);
    }
}
'
cat > "$D8B/src/lib.rs" <<'RS'
//! Head revision: removed_test is gone entirely, taking its assertions with it.
pub fn add(a: u8, b: u8) -> u8 { a + b }

#[cfg(test)]
mod tests {
    use super::add;

    #[test]
    fn surviving_test() {
        assert_eq!(add(0, 0), 0);
    }
}
RS

echo "== test-census-allow, stage 4: naming only the TEST does not also excuse the file's own drop =="
OUT8D="$(run_census_with_pr "$D8B" 'test-census-allow: removed_test reason: superseded, but this line does not mention the path')"
if printf '%s\n' "$OUT8D" | grep -q '^FAIL \[test-removed\]$'; then
  echo "FAIL: naming the removed test by name did not clear rule 1. Got:"
  echo "$OUT8D" | sed 's/^/    /'
  FAILED=1
fi
if ! printf '%s\n' "$OUT8D" | grep -q '^FAIL \[assertions-weakened\]$'; then
  echo "FAIL: rule 1's name-only allowance incorrectly also silenced rule 2's" \
       "independent per-file check. Got:"
  echo "$OUT8D" | sed 's/^/    /'
  FAILED=1
else
  note "an allow line naming only the test clears rule 1 but rule 2 still fires independently"
fi

echo "== test-census-allow, stage 5: naming BOTH the test and the path clears both rules =="
OUT8E="$(run_census_with_pr "$D8B" 'test-census-allow: removed_test reason: superseded by a stronger test elsewhere
test-census-allow: src/lib.rs reason: the removed test'"'"'s assertions went with it, reviewed and accepted')"
if printf '%s\n' "$OUT8E" | grep -qE '^FAIL \['; then
  echo "FAIL: naming both the test and the path still left a rule failing. Got:"
  echo "$OUT8E" | sed 's/^/    /'
  FAILED=1
else
  note "naming both the test and the path clears both rules"
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "test-census-selftest: FAILED. The census no longer enforces what it claims."
  exit 1
fi
echo "test-census-selftest: clean"
