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
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
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
# orphan branch) passes them explicitly. Never lets a non-zero exit escape
# and trip this self-test's own `set -e`; every case below reads the OUTPUT
# text, the same convention test-census-selftest.sh uses for the identical
# reason.
run_scope() {
  local dir="$1" base="${2:-}" head="${3:-}"
  ( cd "$dir"
    [ -z "$base" ] && base="$(git rev-parse main)"
    [ -z "$head" ] && head="$(git rev-parse HEAD)"
    PATH="$FAKEBIN:$PATH" GITHUB_REPOSITORY=test-org/test-repo PR_NUMBER=1 \
      BASE_SHA="$base" HEAD_SHA="$head" bash "$SCOPE" 2>&1 || true
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
OUT1="$(run_scope "$D1")"
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
OUT2="$(run_scope "$D2")"
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
OUT3="$(run_scope "$D3")"
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
# ---------------------------------------------------------------------------
D4="$WORK/nested-crate"
new_repo "$D4"
mkdir -p "$D4/crates/a/b"
printf '[workspace]\nmembers=["crates/a/b"]\n' > "$D4/Cargo.toml"
printf '[package]\nname="b"\nversion="0.1.0"\n' > "$D4/crates/a/b/Cargo.toml"
commit_all "$D4" base
git -C "$D4" checkout -qb pr
printf '[package]\nname="b"\nversion="0.2.0"\n' > "$D4/crates/a/b/Cargo.toml"
commit_all "$D4" attack
fake_gh 'dependabot[bot]' ''
echo "== crates/a/b/Cargo.toml (nested) must be refused =="
OUT4="$(run_scope "$D4")"
if echo "$OUT4" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: a nested crate manifest was reported EXEMPT. Got:"
  echo "$OUT4" | sed 's/^/    /'
  FAILED=1
else
  note "crates/a/b/Cargo.toml is refused"
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
OUT5="$(run_scope "$D5")"
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
OUT6="$(run_scope "$D6")"
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
OUT7="$(run_scope "$D7")"
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
# ---------------------------------------------------------------------------
D8="$WORK/empty-diff"
new_repo "$D8"
printf '[workspace]\nmembers=[]\n' > "$D8/Cargo.toml"
commit_all "$D8" base
fake_gh 'dependabot[bot]' ''
echo "== an empty diff must not be reported EXEMPT =="
SHA8="$(git -C "$D8" rev-parse main)"
OUT8="$(run_scope "$D8" "$SHA8" "$SHA8")"
if echo "$OUT8" | grep -qF 'pr-scope-check: EXEMPT'; then
  echo "FAIL: an empty diff was reported EXEMPT. Got:"
  echo "$OUT8" | sed 's/^/    /'
  FAILED=1
else
  note "an empty diff is refused rather than vacuously EXEMPT"
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
OUT9="$(run_scope "$D9" "$BASE9" "$HEAD9")"
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
OUT10="$(run_scope "$D10")"
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
OUT11="$(run_scope "$D11")"
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
OUT12="$(run_scope "$D12")"
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
OUT13="$(run_scope "$D13")"
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
OUT14="$(run_scope "$D14")"
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
OUT15="$(run_scope "$D15")"
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
OUT16="$(run_scope "$D16")"
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
OUT17="$(run_scope "$D17")"
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
OUT18="$(run_scope "$D18")"
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
OUT19="$(run_scope "$D19")"
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
OUT20="$(run_scope "$D20")"
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
OUT21="$(run_scope "$D21")"
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
OUT22="$(run_scope "$D22")"
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
OUT23="$(run_scope "$D23")"
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
OUT24="$(run_scope "$D24")"
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
OUT25="$(run_scope "$D25")"
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
OUT26="$(run_scope "$D26")"
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
OUT27="$(run_scope "$D27")"
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
OUT28="$(run_scope "$D28")"
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
OUT29="$(run_scope "$D29")"
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
OUT30="$(run_scope "$D30")"
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
OUT31="$(run_scope "$D31")"
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
OUT32="$(run_scope "$D32")"
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
OUT33="$(run_scope "$D33")"
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
OUT34="$(run_scope "$D34")"
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
OUT35="$(run_scope "$D35")"
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
OUT36="$(run_scope "$D36")"
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
OUT36b="$(run_scope "$D36b")"
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
OUT37="$(run_scope "$D37")"
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
OUT38="$(run_scope "$D38")"
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
OUT39="$(run_scope "$D39")"
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
OUT40="$(run_scope "$D40")"
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
OUT41="$(run_scope "$D41")"
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
OUT42="$(run_scope "$D42")"
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

echo
if [ "$FAILED" -ne 0 ]; then
  echo "pr-scope-check-selftest: FAILED. The scope check no longer enforces what it claims."
  exit 1
fi
echo "pr-scope-check-selftest: clean"
