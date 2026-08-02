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
# Belt and suspenders alongside the NUL-delimited reads below: this script
# never intentionally relies on pathname expansion, so turn it off entirely.
# `case` patterns are unaffected by this (they are not filename globbing), so
# nothing below changes behaviour; it only removes a footgun for the next
# edit.
#
# DO NOT DELETE THIS THINKING THE QUOTING BELOW MAKES IT REDUNDANT, OR
# VICE VERSA. PR 837's own self-test mutation battery proved the two are
# load-bearing ONLY JOINTLY for the bot-path glob vector: reverting the bot
# loop below to `for f in ${changed[*]}` (unquoted) is caught by the
# self-test's WHITESPACE case regardless of `set -f`, because word-splitting
# alone already breaks it, but it is caught by the GLOB case ONLY when
# `set -f` is present, because `set -f` is the only thing stopping
# `Cargo.tom[l]` from pathname-expanding once the quoting that would
# otherwise have prevented it is gone. Delete either one and the glob half
# of that regression silently stops being tested.
#
# HONEST NOTE ON THIS MUTATION (PR 837's third review round, re-verified
# directly): with every loop below already a properly quoted array
# expansion, deleting THIS line by itself, with nothing else changed, is
# currently an EQUIVALENT mutation. No input distinguishes the two states of
# the script, because `set -f` only ever mattered to an UNQUOTED expansion,
# and there is not one left. Re-landed and run through the self-test to
# confirm: exit 0, zero failures, both before and after deleting this line
# alone. That is not a reason to remove it: it is why deleting it is
# invisible today and would only become dangerous the day some future edit
# reintroduces an unquoted expansion elsewhere, at which point this line is
# the only thing standing between that regression and the glob vector above.
# A test cannot be written to force this line red in isolation without
# ALSO reintroducing the very unquoted expansion this line exists to guard
# against, which would defeat the point of testing it separately.
set -f
cd "$(git rev-parse --show-toplevel)"

# Working directory for the manifest capability check below (bot path only).
# One trap for the whole script: every exit, including an early `exit 1`
# from any check above or below this line, must still clean this up.
MANIFEST_TMP="$(mktemp -d)"
trap 'rm -rf "$MANIFEST_TMP"' EXIT

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

# THREE dots, not two. `git diff A B` is a two-dot diff and shows everything
# that differs between the tips, so once other pull requests merge into main the
# base sha advances and THEIR files appear in THIS diff, producing a false scope
# violation the author cannot act on. The three-dot form diffs against the merge
# base, which is what "the files this branch changed" actually means.
#
# A FAILED merge-base is a FAILURE, not a two-dot diff wearing a fallback
# (issue #535). This used to be `|| MERGE_BASE="$BASE_SHA"` on the issue path,
# and separately `|| echo "$BASE_SHA"` inline on the bot path below it, an
# inconsistency PR 837's review caught: two spellings of the identical wrong
# idea, one fixed and one not. If `git merge-base` cannot find a shared
# ancestor, that almost always means this checkout never actually fetched the
# commit `BASE_SHA` names (its own fetch step raced a later commit landing on
# the base branch), not that no common ancestor exists. Substituting `BASE_SHA`
# then diffs against a commit this branch may never have descended from at
# all, and reports every file whatever else landed on the base branch in that
# window as an undeclared change in THIS pull request, exactly what happened
# to PR #512 (blamed for issue #113's already merged SNI normalization files).
# `scripts/test-census.sh` already gets this right for its own merge base:
# fail loudly and let the run be investigated or re-tried, never guess. There
# is exactly one merge base and exactly one "files this PR changed" for the
# whole script, computed once here and used by both the bot path and the
# issue path below, rather than twice with two chances to disagree.
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

# Read the diff NUL delimited and compare each path LITERALLY. This script
# used to compute this list with `git diff --name-only` (newline separated)
# and then consume it as `for f in $changed`, an UNQUOTED expansion. Bash
# word-splits AND pathname-expands an unquoted expansion, so what actually got
# tested was never the path that changed; it was that expansion. PR 837's
# review proved two independent ways to abuse this, both against the real
# script with real cargo:
#
#   1. GLOB. A file literally named `crates/pol/Cargo.tom[l]` is a valid
#      glob pattern. Expanded against the checkout, `Cargo.tom[l]` matches
#      `Cargo.toml` whenever that file also exists alongside it, which an
#      attacker controls by simply committing both. The loop then tests
#      `crates/pol/Cargo.toml`, not the path that changed, and a payload
#      planted at `crates/pol/Cargo.tom[l]` is never tested at all. Paired
#      with a sibling `crates/pol/Cargo.toml` carrying `build =
#      "Cargo.tom[l]"`, this made the bot path print EXEMPT while cargo
#      compiled and ran the payload during `cargo build`.
#   2. WHITESPACE. `git diff --name-only` does not quote a space, so a path
#      containing one is a single diff line that word-splits into TWO
#      allowlisted fragments with no existing file required:
#      `crates/pol/Cargo.toml Cargo.toml` becomes `crates/pol/Cargo.toml` and
#      `Cargo.toml`, and the real, space-containing path is again never
#      tested.
#
# `git diff --name-only -z` NUL-terminates every entry instead of newline
# separating them, and `read -r -d ''` reads exactly one NUL-terminated
# record into `f` with no word-splitting and no globbing, whatever bytes the
# path contains. That is the only correct way to consume this output, and it
# is why this is fixed in the loop, not in the allowlist regex: the regex was
# never wrong, it was simply never shown the path that changed.
#
# --no-renames (PR 837's third review round). Rename detection is on by
# default from git 2.9 onward, down to 50 percent similarity, and
# `--name-only` on a detected rename prints ONLY the post-image path. So
# `git mv crates/pol/src/lib.rs crates/pol/Cargo.lock` showed this script
# exactly one line, `crates/pol/Cargo.lock`, an allowlisted path, and the
# fact that a SOURCE FILE WAS DELETED never appeared in the diff this check
# (or a human reviewing its EXEMPT listing) ever sees. Combined with the
# manifest capability check below, that made a rename-and-replace of a real
# crate's `src/lib.rs` into a `build`-carrying payload indistinguishable from
# an ordinary two-file bot bump: git reported it as one rename plus one
# modify, both allowlisted, verdict EXEMPT. `--no-renames` makes git report
# a rename as a plain delete plus a plain add instead, two separate paths,
# so the deleted source file is never invisible. There is no legitimate
# reason for a bot-authored dependency bump to rename anything, and a
# non-bot PR is compared against the issue's Files table regardless, so
# nothing here needs rename detection to pass.
changed=()
while IFS= read -r -d '' f; do
  changed+=("$f")
done < <(git diff --no-renames --name-only -z "$MERGE_BASE" "$HEAD_SHA")

# A path containing a literal embedded newline is rejected outright, rather
# than trusted to any particular grep flavour's handling of one. Every match
# below is done with `grep -qE` against a single value, which is safe for an
# ordinary one-line path; but a value that itself contains a newline reads to
# a line-oriented tool as MULTIPLE lines, and `grep -q` succeeds if ANY line
# matches, so a two-line value with one allowlisted line and one payload line
# could otherwise pass. It also defeats the directory-prefix `case "$f" in
# "$d"*)` matches further down in the same way, since a glob-style prefix
# match does not stop at an embedded newline either. NUL-delimited reading
# cannot itself produce this (a NUL cannot appear in a POSIX path), but a
# real newline can, and this is the one remaining metacharacter worth
# checking for by hand rather than by trusting `grep -z` semantics, which
# this repository's own local tooling was observed to implement differently
# from GNU grep.
for f in "${changed[@]}"; do
  case "$f" in
    *$'\n'*)
      echo "FAIL: a changed path contains an embedded newline, which this" >&2
      echo "check will not compare against a line-oriented allowlist. The" >&2
      echo "raw bytes, one apparent line per embedded fragment:" >&2
      printf '%s\n' "$f" | sed 's/^/    /' >&2
      exit 1
      ;;
  esac
done

# An empty diff must never read as "nothing to enforce, so EXEMPT" or
# "nothing to enforce, so it matches". Every other lane in this workflow
# fails closed when its inputs are missing rather than reporting success for
# having found nothing; this script was the one exception, on the bot path
# only, where an empty diff printed EXEMPT with a blank file list and exited
# 0. A `pull_request` event always has at least one changed file in practice;
# if this ever fires, something upstream (a bad BASE_SHA/HEAD_SHA pair, most
# likely) is broken and deserves investigation, not a silent pass.
if [ "${#changed[@]}" -eq 0 ]; then
  cat >&2 <<EOF
FAIL: no files changed between the merge base and HEAD_SHA ($HEAD_SHA). A pull
request with no diff has nothing for this check to enforce, and reporting a
pass here would be exactly the vacuous pass this workflow refuses everywhere
else. Investigate rather than trust it.
EOF
  exit 1
fi

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
# CORRECTED CLAIM, TWICE OVER (PR 837's review caught both). This comment and
# issue #836 originally said the widening below "admits nothing the previous
# list did not", on the theory that a crate manifest can add a dependency but
# so can the root manifest that was already allowed. That equivalence does
# NOT hold in this repository: the root `Cargo.toml` is a VIRTUAL workspace
# manifest (`[workspace]`, no `[package]`), so Cargo refuses `build =`,
# `[[bin]] path =`, `[lib] path =` and `[[test]] path =` there entirely. A
# crate manifest accepts all of them. So a crate manifest carries a
# capability the root manifest never had: it can retarget what Cargo COMPILES
# AND RUNS at an arbitrary path already in the tree.
#
# The FIRST correction (PR 837 round two) said reading every path literally
# was enough, because "an allowlisted crate manifest can only point Cargo at
# a file that is ALSO part of this same reviewed diff, never at a payload
# smuggled under a different name via a glob or a space". That is true and
# it does not follow that the diff is safe: a file at an allowlisted path IS
# the payload. `crates/[^/]+/Cargo\.lock` used to be on this allowlist. A
# per-crate `Cargo.lock` is never read by Cargo for a workspace member (only
# the WORKSPACE ROOT lockfile is), so its content is completely
# unconstrained, and the repository tracks zero of them outside `fuzz/`
# (verified against `git ls-files`; the fuzz ones are real and stay
# allowlisted below, each its own workspace root's genuine lockfile). PR
# 837's third review round proved, with real cargo, that
# `crates/pol/Cargo.toml` declaring `build = "Cargo.lock"` alongside a
# `crates/pol/Cargo.lock` containing `fn main(){ ... }` is EXEMPT under the
# literal-path fix and then compiles and runs during `cargo build`. Removing
# the crate-lockfile alternative below closes that specific container.
#
# But the container was never the actual capability, only the cheapest
# example of it. The capability is: a crate manifest can point `build`,
# `[[bin]] path`, `[lib] path`, `[[test]] path`, or `[[bench]] path` at ANY
# path already present in the same diff, allowlisted or not (an attacker
# controls both halves of a bot PR). A dependency bump never needs to do
# that; it only ever edits a version string inside a `[dependencies]`,
# `[dev-dependencies]`, or `[build-dependencies]` table. So the second, real
# fix is `manifest_capability_offense` below: refuse a bot PR outright if any
# `Cargo.toml` it touches introduces or changes one of those five keys,
# comparing the manifest at MERGE_BASE against HEAD_SHA, regardless of which
# allowlisted (or non-allowlisted, already-offending) path the payload itself
# would live at. That is what actually makes the allowlist widening below
# safe, not the literal-path reading by itself and not the lockfile removal
# by itself; per the review, either alone leaves the class open. Note the
# [^/]+ segments are still deliberate: crates/<name>/Cargo.toml matches,
# crates/<name>/src/anything does not.
BOT_ALLOWED='^(Cargo\.toml|Cargo\.lock|crates/[^/]+/Cargo\.toml|crates/[^/]+/fuzz/Cargo\.toml|crates/[^/]+/fuzz/Cargo\.lock|\.github/workflows/[^/]+\.ya?ml|\.github/dependabot\.yml|packages/[^/]+/package(-lock)?\.json)$'

# manifest_capability_offense <path> -- prints one line per capability key
# (`package.build`, `lib.path`, `[[bin]] path`, `[[test]] path`,
# `[[bench]] path`) that HEAD_SHA's version of <path> introduces or changes
# relative to MERGE_BASE's version, or nothing if none did. Used only on the
# bot path, and only to decide whether a bot PR that touches a `Cargo.toml`
# may be exempted: a real dependency bump changes version strings, never
# these keys, so this refuses nothing #836 needs and refuses exactly the
# capability PR 837's third round demonstrated.
#
# Parsed with Python's stdlib `tomllib` (3.11+, already relied on elsewhere
# in this repository's CI: see the fuzz `[[bin]]` path cross-check in
# ci.yml) rather than a regex, specifically so a legitimate internal
# dependency such as `irontraffic-time = { path = "../irontraffic-time" }`
# is never confused with the `[lib]`/`[[bin]]`/`[[test]]`/`[[bench]]` `path`
# this check actually cares about: tomllib knows which table a key belongs
# to, a regex would have to guess.
#
# FAIL CLOSED, both directions PR 837's third round named:
#   - A manifest that exists at MERGE_BASE but cannot be read there (`git
#     show` fails despite `git cat-file -e` confirming it exists) is reported
#     as an offense, never silently treated as having no prior keys.
#   - A HEAD_SHA version that does not parse as valid TOML at all is reported
#     as an offense too, since a check that cannot verify safety must not
#     report safety.
#   - A manifest with NO base version at all (a brand new file; `git
#     cat-file -e` says it does not exist at MERGE_BASE) is treated as an
#     empty base, i.e. any of these five keys in it counts as introduced. A
#     bot never legitimately authors a brand new manifest, so this is not a
#     new restriction on any real dependency bump.
#   - A manifest deleted at HEAD_SHA is not checked at all: nothing is left
#     for Cargo to compile from that path, so there is no capability to
#     introduce.
manifest_capability_offense() {
  local f="$1" base_file="$MANIFEST_TMP/base.toml" head_file="$MANIFEST_TMP/head.toml"
  : > "$base_file"
  if git cat-file -e "$MERGE_BASE:$f" 2>/dev/null; then
    if ! git show "$MERGE_BASE:$f" > "$base_file" 2>/dev/null; then
      echo "could not read the base ($MERGE_BASE) version of $f to compare it against; failing closed"
      return 0
    fi
  fi
  if ! git show "$HEAD_SHA:$f" > "$head_file" 2>/dev/null; then
    return 0
  fi
  python3 - "$base_file" "$head_file" <<'PYEOF'
import sys
import tomllib


def load(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.strip():
        return {}
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return None


def capability_keys(doc):
    # None means "did not parse", which the caller must treat as
    # unverifiable, and therefore an offense, rather than as safe.
    if doc is None:
        return None
    out = {}
    build = doc.get("package", {}).get("build")
    if build is not None:
        out["package.build"] = repr(build)
    lib_path = doc.get("lib", {}).get("path")
    if lib_path is not None:
        out["lib.path"] = repr(lib_path)
    for kind in ("bin", "test", "bench"):
        entries = doc.get(kind, [])
        if isinstance(entries, list):
            for i, entry in enumerate(entries):
                if isinstance(entry, dict) and entry.get("path") is not None:
                    out["[[%s]][%d].path" % (kind, i)] = repr(entry["path"])
    return out


base_keys = capability_keys(load(sys.argv[1]))
head_keys = capability_keys(load(sys.argv[2]))

if head_keys is None:
    print("the proposed version does not parse as TOML; cannot verify it introduces no build/path key")
    sys.exit(0)
if base_keys is None:
    print("the base version exists but does not parse as TOML; cannot verify what it already declared")
    sys.exit(0)

for key, value in head_keys.items():
    if key not in base_keys:
        print("introduces %s = %s" % (key, value))
    elif base_keys[key] != value:
        print("changes %s from %s to %s" % (key, base_keys[key], value))
PYEOF
}

case "$author" in
  dependabot\[bot\]|renovate\[bot\]|github-actions\[bot\])
    offending=""
    for f in "${changed[@]}"; do
      printf '%s' "$f" | grep -qE "$BOT_ALLOWED" || offending="$offending$f
"
    done
    # The capability check runs over every Cargo.toml this PR touches, not
    # only ones BOT_ALLOWED accepts: an offending path already fails below
    # regardless, and a manifest at an allowlisted path is exactly the case
    # this check exists for.
    for f in "${changed[@]}"; do
      case "$f" in
        Cargo.toml|*/Cargo.toml) : ;;
        *) continue ;;
      esac
      cap="$(manifest_capability_offense "$f")"
      if [ -n "$cap" ]; then
        offending="$offending$f: $(printf '%s' "$cap" | tr '\n' ' ')
"
      fi
    done
    if [ -z "$offending" ]; then
      echo "pr-scope-check: EXEMPT. Automated dependency bump by $author touching only manifests and workflows:"
      for f in "${changed[@]}"; do
        printf '    %s\n' "$f"
      done
      exit 0
    fi
    echo "FAIL: $author is a bot but this PR touches files outside the dependency allowlist, or a manifest that introduces or changes a build/path key a dependency bump never needs:" >&2
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
  while IFS= read -r n; do
    printf '  #%s\n' "$n" >&2
  done <<< "$issues"
  echo "One issue per PR. Split it." >&2
  exit 1
fi

issue="$issues"
echo "PR #$PR_NUMBER implements issue #$issue"

issue_body="$(gh api "repos/$REPO/issues/$issue" --jq '.body // ""')"

# Extract the first column of the markdown table under `## Files`. Rows look
# like:  | `crates/irontraffic-router/src/matcher.rs` | create | ... |
declared_raw="$(printf '%s' "$issue_body" | python3 -c '
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

if [ -z "$declared_raw" ]; then
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

# Read line by line rather than `for d in $declared_raw`, the same unquoted
# shape fixed above for the diff: a declared path is author-controlled prose
# (the issue's own Files table) and deserves the identical literal treatment,
# not a second, differently-shaped trust boundary.
declared=()
while IFS= read -r d; do
  [ -n "$d" ] && declared+=("$d")
done <<< "$declared_raw"

echo "declared in issue #$issue:"
for d in "${declared[@]}"; do
  printf '  %s\n' "$d"
done
echo "changed by this PR:"
for f in "${changed[@]}"; do
  printf '  %s\n' "$f"
done

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
for f in "${changed[@]}"; do
  case "$f" in
    Cargo.toml|*/Cargo.toml) : ;;
    *) continue ;;
  esac
  for d in "${declared[@]}"; do
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
for f in "${changed[@]}"; do
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
      for d in "${declared[@]}"; do
        [ "$d" = "$sibling" ] && sib_declared=1 && break
      done
      [ "$sib_declared" -eq 1 ] && continue
      ;;
  esac
  ok=0
  for d in "${declared[@]}"; do
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
#
# EQUIVALENT MUTATION, DOCUMENTED RATHER THAN FAKED (PR 837's third review
# round, re-verified directly). Rewriting this as
# `printf '%s\n' "${changed[@]}" | grep -qxF "$d" || untouched="$untouched$d\n"`
# is behaviorally IDENTICAL to the explicit loop below, given the invariants
# this script already establishes by this point: `changed` is guaranteed
# non-empty (the empty-diff guard above exits before this line is reached),
# both forms quote `"${changed[@]}"` correctly, and `-F -x` performs the same
# whole-element, literal comparison the loop performs by hand. No declared
# path can contain an embedded newline either (every `declared` entry comes
# from a single line of the issue body via splitlines(), so the "embedded
# newline turns one grep pattern into several alternatives" concern that
# motivated hand-rolling the newline guard for `changed` earlier in this
# script does not apply here). Re-landed this exact substitution and ran the
# self-test: exit 0, zero failures, both forms agree on every case in this
# file. It is written as an explicit loop for uniformity with the other
# loops below doing the identical shape of comparison, not because the
# pipeline form is unsafe.
untouched=""
for d in "${declared[@]}"; do
  case "$d" in */) continue;; esac
  found=0
  for f in "${changed[@]}"; do
    [ "$f" = "$d" ] && { found=1; break; }
  done
  [ "$found" -eq 0 ] && untouched="$untouched$d
"
done
if [ -n "$untouched" ]; then
  echo
  echo "NOTE: declared but not modified (verify this is intentional):"
  printf '%s' "$untouched" | sed 's/^/    /'
fi

echo
echo "pr-scope-check: the diff matches issue #$issue"
