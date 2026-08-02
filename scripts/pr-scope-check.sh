#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The PR scope check.
#
# WHY THIS EXISTS. The most consistent failure mode of a small model asked to
# change four files is that it changes eleven: it "helpfully" refactors an
# adjacent module, renames a field it did not like, or fixes an unrelated
# warning it noticed on the way past. Each of those edits is individually
# plausible and collectively makes the diff unreviewable, and the reviewer is
# the only remaining defence in this project.
#
# Every issue in this repository carries a `## Files` table declaring exactly
# which files the implementer will create or modify. This check compares the
# pull request's actual diff against that table and fails on anything extra.
# The fix for a legitimate overrun is to EDIT THE ISSUE, which is a reviewable
# act, rather than to quietly widen the diff.
#
# Environment: GH_TOKEN, PR_NUMBER, BASE_SHA, HEAD_SHA.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

: "${PR_NUMBER:?PR_NUMBER is required}"
: "${BASE_SHA:?BASE_SHA is required}"
: "${HEAD_SHA:?HEAD_SHA is required}"

REPO="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"

# Files every PR may touch without declaring them, because they are process
# artifacts rather than implementation.
#
# Cargo.lock is DELIBERATELY NOT here. A lockfile pins exact versions of every
# transitive dependency, and `cargo update` can rewrite it with no manifest
# change at all, silently repinning an existing dependency to a different
# build. That is precisely the kind of undeclared change this check exists to
# catch, so it is not safe to blanket-allow. See the narrower rule below,
# applied inside the main loop, that allows Cargo.lock only alongside a
# Cargo.toml the issue actually declared.
ALWAYS_ALLOWED='^(CHANGELOG\.md)$'

pr_json="$(gh api "repos/$REPO/pulls/$PR_NUMBER")"
body="$(printf '%s' "$pr_json" | jq -r '.body // ""')"
author="$(printf '%s' "$pr_json" | jq -r '.user.login // ""')"

# Automated dependency and workflow bumps have no issue and never will. They are
# exempt ONLY when the author is a known bot AND every file they touch is a
# dependency manifest or a workflow. A bot PR that touches source code is NOT
# exempt, which is the case that would actually matter if a token were misused.
# This is a positive check in the script rather than a skipped job, because
# GitHub reports a skipped job to branch protection as SUCCESS.
#
# The crate-level manifests are here for a reason found the hard way: the first
# version anchored only the ROOT Cargo.toml and Cargo.lock, so a bump to a
# dependency declared in a single crate, which is most of them, produced
# "dependabot[bot] is a bot but this PR touches files outside the dependency
# allowlist: crates/irontraffic-policy/Cargo.toml". The gate refused exactly the
# class of PR this exemption exists to permit, and it said so in the wording of
# a security refusal, which reads as the bot having done something suspicious
# rather than as a hole in this list. PR 832 (logos) hit it.
#
# Widening to crate manifests does NOT widen the threat model. The comment above
# is still the rule that matters: a bot PR touching SOURCE is not exempt. A
# crate manifest can add a dependency, but so can the root manifest that was
# always allowed, so this admits nothing the previous list did not. Note the
# [^/]+ segments are deliberate: crates/<name>/Cargo.toml matches,
# crates/<name>/src/anything does not.
BOT_ALLOWED='^(Cargo\.toml|Cargo\.lock|crates/[^/]+/Cargo\.toml|crates/[^/]+/Cargo\.lock|crates/[^/]+/fuzz/Cargo\.toml|crates/[^/]+/fuzz/Cargo\.lock|\.github/workflows/[^/]+\.ya?ml|\.github/dependabot\.yml|packages/[^/]+/package(-lock)?\.json)$'
case "$author" in
  dependabot\[bot\]|renovate\[bot\]|github-actions\[bot\])
    changed_now="$(git diff --name-only "$(git merge-base "$BASE_SHA" "$HEAD_SHA" || echo "$BASE_SHA")" "$HEAD_SHA")"
    offending=""
    for f in $changed_now; do
      printf '%s' "$f" | grep -qE "$BOT_ALLOWED" || offending="$offending$f
"
    done
    if [ -z "$offending" ]; then
      echo "pr-scope-check: EXEMPT. Automated dependency bump by $author touching only manifests and workflows:"
      printf '%s\n' $changed_now | sed 's/^/    /'
      exit 0
    fi
    echo "FAIL: $author is a bot but this PR touches files outside the dependency allowlist:" >&2
    printf '%s' "$offending" | sed 's/^/    /' >&2
    exit 1
    ;;
esac

# Accept the GitHub closing keywords, case insensitively.
issues="$(printf '%s' "$body" \
  | grep -oiE '(close[sd]?|fixe?[sd]?|resolve[sd]?)[[:space:]]+#[0-9]+' \
  | grep -oE '[0-9]+' | sort -un || true)"

if [ -z "$issues" ]; then
  cat >&2 <<'EOF'
FAIL: this pull request does not close an issue.

Every PR implements exactly one issue and says so in its body:

    Closes #123

The issue is the specification: it carries the file list this check enforces,
the acceptance criteria, and the do-not-do list. A PR without one has no
agreed scope and cannot be reviewed against anything.
EOF
  exit 1
fi

count="$(printf '%s\n' "$issues" | wc -l | tr -d ' ')"
if [ "$count" -ne 1 ]; then
  echo "FAIL: this PR closes $count issues:" >&2
  printf '  #%s\n' $issues >&2
  echo "One issue per PR. Split it." >&2
  exit 1
fi

issue="$issues"
echo "PR #$PR_NUMBER implements issue #$issue"

issue_body="$(gh api "repos/$REPO/issues/$issue" --jq '.body // ""')"

# Extract the first column of the markdown table under `## Files`. Rows look
# like:  | `crates/irontraffic-router/src/matcher.rs` | create | ... |
declared="$(printf '%s' "$issue_body" | python3 -c '
import re, sys

text = sys.stdin.read()
lines = text.splitlines()
out, in_files = [], False
for line in lines:
    s = line.strip()
    # Reset on ANY heading. An issue may put an `### ` subsection inside
    # `## Files` with its own backticked table; those rows are not file rows.
    if s.startswith("#"):
        in_files = s.lower().startswith("## files")
        continue
    if not in_files or not s.startswith("|"):
        continue
    cells = [c.strip() for c in s.strip("|").split("|")]
    if not cells:
        continue
    # A row may annotate the path, e.g. `Cargo.toml` (workspace root). Take the
    # FIRST backticked span when present, else the bare cell. The corpus
    # validator uses the identical rule; if these two ever disagree, CI rejects
    # a diff the author was told was in scope.
    m = re.search(r"`([^`]+)`", cells[0])
    # Every legitimate Files row backticks its path. An unbackticked first cell
    # means this row belongs to some OTHER table nested in the Files section, so
    # skip it rather than declaring a bogus path in scope.
    if not m:
        continue
    path = m.group(1).strip()
    # Skip the header row and the --- separator row.
    if not path or path.lower() == "path" or set(path) <= set("-: "):
        continue
    out.append(path)
print("\n".join(out))
')"

if [ -z "$declared" ]; then
  cat >&2 <<EOF
FAIL: issue #$issue has no '## Files' table, so this PR's scope is undefined.

Every issue declares the files it touches:

    ## Files

    | Path | Action | Purpose |
    | --- | --- | --- |
    | \`crates/irontraffic-router/src/matcher.rs\` | create | the compiled matcher |

Add the table to the issue, then re-run this check.
EOF
  exit 1
fi

# THREE dots, not two. `git diff A B` is a two-dot diff and shows everything
# that differs between the tips, so once other pull requests merge into main the
# base sha advances and THEIR files appear in THIS diff, producing a false scope
# violation the author cannot act on. The three-dot form diffs against the merge
# base, which is what "the files this branch changed" actually means.
#
# A FAILED merge-base is a FAILURE, not a two-dot diff wearing a fallback
# (issue #535). This used to be `|| MERGE_BASE="$BASE_SHA"`, which silently
# turned exactly the failure the paragraph above describes into the very
# comparison it exists to avoid: if `git merge-base` cannot find a shared
# ancestor, that almost always means this checkout never actually fetched the
# commit `BASE_SHA` names (its own fetch step raced a later commit landing on
# the base branch), not that no common ancestor exists. Substituting `BASE_SHA`
# then diffs against a commit this branch may never have descended from at
# all, and reports every file whatever else landed on the base branch in that
# window as an undeclared change in THIS pull request, exactly what happened
# to PR #512 (blamed for issue #113's already merged SNI normalization files).
# `scripts/test-census.sh` already gets this right for its own merge base:
# fail loudly and let the run be investigated or re-tried, never guess.
if ! MERGE_BASE="$(git merge-base "$BASE_SHA" "$HEAD_SHA")"; then
  cat >&2 <<EOF
FAIL: could not compute a merge base between BASE_SHA ($BASE_SHA) and HEAD_SHA
($HEAD_SHA). This almost always means the checkout does not actually have the
commit BASE_SHA names, not that the two commits share no history. Falling back
to a two-dot diff against BASE_SHA would compare against a commit this branch
may not descend from at all once other pull requests have merged into the base
branch since this branch's last rebase, and would misreport every file those
merges touched as an undeclared change in THIS pull request. Re-run this check
rather than trust a result computed without a real merge base.
EOF
  exit 1
fi
changed="$(git diff --name-only "$MERGE_BASE" "$HEAD_SHA")"

echo "declared in issue #$issue:"; printf '  %s\n' $declared
echo "changed by this PR:"; printf '  %s\n' $changed

# Cargo.lock exemption: allowed WITHOUT its own Files row, but only when this
# same diff also touches a Cargo.toml that the issue DID declare. That ties
# the lockfile change to a manifest edit a human already reviewed, rather than
# exempting Cargo.lock outright, which would also wave through a bare
# `cargo update` that repins an existing dependency with no manifest change at
# all. This does not prove every entry that moved in Cargo.lock belongs to the
# declared manifest edit, only that the diff has a plausible legitimate
# trigger; `cargo deny check` runs separately over the resulting tree and
# would catch a banned licence, source, or known advisory pulled in this way.
# It would NOT catch a quiet repin to an older, merely undesirable version, so
# this is a narrowing of the false-positive, not a claim that Cargo.lock
# content is fully verified here.
cargo_lock_exempt=0
for f in $changed; do
  case "$f" in
    Cargo.toml|*/Cargo.toml) : ;;
    *) continue ;;
  esac
  for d in $declared; do
    case "$d" in
      */) case "$f" in "$d"*) cargo_lock_exempt=1;; esac ;;
      *)  [ "$f" = "$d" ] && cargo_lock_exempt=1 ;;
    esac
    [ "$cargo_lock_exempt" -eq 1 ] && break
  done
  [ "$cargo_lock_exempt" -eq 1 ] && break
done

# A declared entry may name a directory (trailing slash) to cover a tree.
undeclared=""
for f in $changed; do
  if printf '%s' "$f" | grep -qE "$ALWAYS_ALLOWED"; then continue; fi
  if [ "$f" = "Cargo.lock" ] && [ "$cargo_lock_exempt" -eq 1 ]; then continue; fi
  # A NESTED lockfile, crates/<name>/fuzz/Cargo.lock, is generated by cargo-fuzz
  # because a fuzz crate is its own workspace root. Unlike the root lockfile it
  # belongs to exactly ONE manifest, its sibling, so the tie here is STRICTER
  # than the root rule above: exempt it only when that sibling manifest is
  # itself declared by the issue. A declared manifest elsewhere in the tree does
  # not qualify it. The reason for refusing a blanket lockfile exemption is
  # unchanged, since `cargo update` can still repin a dependency with no
  # manifest change, and that case is still caught.
  case "$f" in
    */Cargo.lock)
      sibling="${f%/Cargo.lock}/Cargo.toml"
      sib_declared=0
      for d in $declared; do
        [ "$d" = "$sibling" ] && sib_declared=1 && break
      done
      [ "$sib_declared" -eq 1 ] && continue
      ;;
  esac
  ok=0
  for d in $declared; do
    case "$d" in
      */) case "$f" in "$d"*) ok=1;; esac ;;
      *)  [ "$f" = "$d" ] && ok=1 ;;
    esac
    [ "$ok" -eq 1 ] && break
  done
  [ "$ok" -eq 0 ] && undeclared="$undeclared$f
"
done

if [ -n "$undeclared" ]; then
  cat >&2 <<EOF

FAIL: this PR changes files that issue #$issue does not declare:

$(printf '%s' "$undeclared" | sed 's/^/    /')

Do ONE of the following:

  1. Revert the undeclared changes. This is almost always the right answer.
     An unrelated cleanup noticed along the way belongs in its own issue, so
     that it can be reviewed on its own merits.

  2. If the change genuinely belongs to this issue, EDIT THE ISSUE's '## Files'
     table to declare it, and say in the PR why the scope grew. Widening the
     scope is allowed; widening it silently is not.
EOF
  exit 1
fi

# A declared file that was never touched is a signal, not a failure: the issue
# may have over-declared, or the implementer may have missed a required edit.
untouched=""
for d in $declared; do
  case "$d" in */) continue;; esac
  printf '%s\n' $changed | grep -qxF "$d" || untouched="$untouched$d
"
done
if [ -n "$untouched" ]; then
  echo
  echo "NOTE: declared but not modified (verify this is intentional):"
  printf '%s' "$untouched" | sed 's/^/    /'
fi

echo
echo "pr-scope-check: the diff matches issue #$issue"
