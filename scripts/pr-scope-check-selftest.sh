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
SCOPE="$PWD/scripts/pr-scope-check.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAKEBIN="$WORK/fakebin"

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

echo
if [ "$FAILED" -ne 0 ]; then
  echo "pr-scope-check-selftest: FAILED. The scope check no longer enforces what it claims."
  exit 1
fi
echo "pr-scope-check-selftest: clean"
