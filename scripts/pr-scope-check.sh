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

# Required-input guards, checked explicitly rather than with `: "${VAR:?...}"`.
#
# PR 837's own fourth review round found that the `:?` form is NOT safe to
# rely on here, and that this very script had already regressed on it. A
# `${VAR:?msg}` failure is neither a `set -e`-triggered false nor an explicit
# `exit`; it is bash's own fatal "parameter null or unset" abort, and on at
# least bash 3.2 that abort does not carry its exit status through an EXIT
# trap installed earlier in the script: the trap's own command runs and
# succeeds, and the shell then exits 0, silently. The round's own commit
# (ab1a295) had put exactly such a trap above these guards for an unrelated
# reason (cleaning up the manifest-diff temp directory below), so a required
# variable being unset went from failing the job (base script, before that
# commit: rc=1) to passing it in total silence (rc=0), which is precisely the
# "GitHub reports a skipped job as SUCCESS" failure mode this whole file
# exists to refuse, just reached by a different mechanism than a skipped job.
# Measured directly, all three variables, same command: base 8cb2482 rc=1,
# this file before this fix rc=0.
#
# An explicit `[ -z ... ]` test followed by an explicit `exit 1` does not have
# this problem: `set -e` and an explicit `exit` both propagate their status
# through an EXIT trap correctly (verified directly: `false` under `set -e`
# gives rc=1 through the same trap, `exit 7` gives rc=7), it is only the
# implicit fatal-expansion abort that does not. Do not revert this to the
# `:?` form, with or without a trap present: the trap is moved below (see the
# comment at MANIFEST_TMP) specifically so nothing between here and there can
# ever again share this failure mode with a trap that has not been installed
# yet, but a `:?` guard here would still be one fatal-expansion abort away
# from losing its exit status the day some earlier line needs a trap of its
# own again.
if [ -z "${PR_NUMBER:-}" ]; then
  echo "FAIL: PR_NUMBER is required" >&2
  exit 1
fi
if [ -z "${BASE_SHA:-}" ]; then
  echo "FAIL: BASE_SHA is required" >&2
  exit 1
fi
if [ -z "${HEAD_SHA:-}" ]; then
  echo "FAIL: HEAD_SHA is required" >&2
  exit 1
fi

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

# An empty diff must never read as "nothing to enforce, so EXEMPT" or
# "nothing to enforce, so it matches". Every other lane in this workflow
# fails closed when its inputs are missing rather than reporting success for
# having found nothing; this script was the one exception, on the bot path
# only, where an empty diff printed EXEMPT with a blank file list and exited
# 0. A `pull_request` event always has at least one changed file in practice;
# if this ever fires, something upstream (a bad BASE_SHA/HEAD_SHA pair, most
# likely) is broken and deserves investigation, not a silent pass.
#
# THIS GUARD RUNS BEFORE ANYTHING ELSE TOUCHES `changed`, DELIBERATELY (PR
# 837's third review round, re-verified directly). `"${changed[@]}"` element
# expansion on a still-empty array is an "unbound variable" error under
# `set -u` on bash below 4.4 (fixed upstream in 4.4, but this workflow does
# not pin the runner's bash minor version); `${#changed[@]}` length expansion
# is not, on any bash version, because the array itself is declared even when
# it holds nothing. Checking the length FIRST and exiting before any
# `"${changed[@]}"` expansion is reached means this script's own behaviour on
# an empty diff no longer depends on which bash is running it: previously the
# newline guard below expanded `"${changed[@]}"` first, so whether an empty
# diff produced this script's own FAIL message or bash's "unbound variable"
# depended on the runner's bash version, and a self-test mutation that
# deleted this guard could pass locally (bash 3.2) for a reason that would
# not hold in CI (bash 5.x).
if [ "${#changed[@]}" -eq 0 ]; then
  cat >&2 <<EOF
FAIL: no files changed between the merge base and HEAD_SHA ($HEAD_SHA). A pull
request with no diff has nothing for this check to enforce, and reporting a
pass here would be exactly the vacuous pass this workflow refuses everywhere
else. Investigate rather than trust it.
EOF
  exit 1
fi

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
# ROUND TWO CORRECTIONS. This comment and issue #836 originally said the
# widening below "admits nothing the previous list did not", on the theory that
# a crate manifest can add a dependency but so can the root manifest that was
# already allowed. That equivalence does NOT hold: the root `Cargo.toml` is a
# VIRTUAL workspace manifest (`[workspace]`, no `[package]`), so Cargo refuses
# `build =`, `[[bin]] path =`, `[lib] path =` and `[[test]] path =` there
# entirely. A crate manifest accepts all of them: it can retarget what Cargo
# COMPILES AND RUNS at an arbitrary path already in the tree. Reading every
# changed path literally (fixed elsewhere in this script, see the NUL-delimited
# loop above) is necessary but not sufficient, because a file AT an allowlisted
# path can simply BE the payload: a per-crate `Cargo.lock`, never read by Cargo
# for a workspace member, is completely unconstrained content sitting at a path
# this list used to allow outright. Round two's fix dropped `crates/[^/]+/Cargo\.lock`
# from BOT_ALLOWED for exactly that reason.
#
# ROUND THREE CORRECTION. Dropping that one container was still not the fix,
# because the container was never the actual capability, only the cheapest
# example of it. Round three added `manifest_capability_offense`: refuse a bot
# PR outright if any `Cargo.toml` it touches introduces or changes `package.build`,
# `[lib] path`, `[[bin]] path`, `[[test]] path`, or `[[bench]] path`, comparing
# MERGE_BASE against HEAD_SHA regardless of which path the payload itself lives
# at. That closed the three vectors known at the time.
#
# ROUND FOUR CORRECTION, AND THE LAST TIME THIS SHOULD NEED SAYING. Five keys is
# still a DENYLIST over a manifest format that keeps gaining keys, and the round
# three review proved it: `[[example]]` is a sixth Cargo target kind, absent from
# that list, and a target setting the Cargo book documents, `test = true`, makes
# `cargo test` build AND RUN an example. A two-file bot PR (a crate manifest
# gaining `[[example]] path = "fuzz/Cargo.lock" test = true`, plus that fuzz
# lockfile now holding Rust) was EXEMPT, and `cargo test --workspace` ran the
# payload. Proven on a clone of the real repository, with real cargo. Two more
# doors were found in the same shape: `[[example]]` inside a fuzz crate's OWN
# manifest, and `[workspace] members` or `[patch.crates-io]` in the ROOT
# manifest (never inspected by the five-key check at all, since none of those
# five keys are even legal there).
#
# The denylist chases containers one at a time forever, because Cargo defines
# the containers, not this script. A dependency bump never needs the manifest to
# gain a NEW capability of any kind; it only ever moves a version string that was
# already there. So `manifest_disallowed_diff` below inverts the check: instead
# of naming what to refuse, it names EXACTLY what to allow, and refuses every
# other structural difference between the manifest at MERGE_BASE and at HEAD_SHA
# by default, whatever key it is under, printing the key path that differs so a
# human can see what happened. This is a smaller, closed statement of what a bot
# bump IS ("a version string moved inside a dependency table") rather than an
# ever-growing statement of what it must not be.
#
# THE ALLOWLIST, STATED EXPLICITLY, because the next reader needs to know the
# rule is "only version strings move", not a list of banned keys:
#
#   - Inside `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`,
#     `[workspace.dependencies]`, or any `[target.'cfg(...)'.dependencies]` /
#     `.dev-dependencies` / `.build-dependencies` table: an EXISTING entry's
#     value may change, and ONLY in the following ways.
#       * If the value is a bare string (`serde = "1.0"`), any new string is
#         allowed. A bare string in a dependency table position IS the version
#         requirement; the TOML/Cargo format gives it no other meaning, so
#         there is nothing else for a change here to be.
#       * If the value is a detailed table (`serde = { version = "1.0",
#         features = [...] }`), only its `version` sub-key may change. Every
#         OTHER sub-key (`path`, `features`, `optional`, `default-features`,
#         `workspace`, `git`, `branch`, `rev`, `tag`, `package`, `registry`,
#         anything else) must be byte-for-byte identical to the base version,
#         or it is refused and named. A real bump never touches these; #832,
#         #831, #833, #834 and #835 (this repo's own real Dependabot PRs) only
#         ever moved a bare version string, never a table sub-key.
#   - A dependency entry may NOT be newly introduced or removed. Dependabot
#     bumps an EXISTING declared dependency; it does not add or delete one.
#     Adding a dependency is exactly the kind of scope growth issue #836 never
#     asked for and this check still refuses it, named.
#   - EVERYTHING ELSE is refused unconditionally: `package.*` (including a
#     version bump of the crate's own version, which is a release action, not
#     a dependency bump), `[lib]`, every `[[bin]]` / `[[test]]` / `[[bench]]` /
#     `[[example]]` entry whether introduced, removed, or merely edited,
#     `[workspace]` (members, exclude, resolver, the workspace's own
#     `[workspace.package]`), `[patch.*]`, `[profile.*]`, `[features]`, and any
#     key this comment does not name, because the check does not enumerate
#     what to refuse: it enumerates what to allow, above, and refuses the
#     complement. A manifest with no base version at all (a brand new file) is
#     compared against an empty document, so every key in it is "introduced"
#     and the whole file is refused: a bot never legitimately authors a new
#     manifest, so this is not a new restriction on any real bump.
#
# Validated both directions on the real repository at the commit this change
# was proposed on: all 49 tracked Cargo/npm manifests and lockfiles stay exempt
# for a real per-file bump, a single combined bump, and the real shapes of PRs
# #829, #830, #832, #835 plus a constructed fuzz-crate dependency bump; and the
# four known vectors plus `[[example]] test = true`, the fuzz-manifest
# `[[example]]` variant, and root `[patch.crates-io]` are all refused. See
# `scripts/pr-scope-check-selftest.sh` for the executable form of both claims.
#
# `crates/[^/]+/fuzz/Cargo\.lock` STAYS on BOT_ALLOWED below, after
# consideration: it is a real, cargo-fuzz-required lockfile (10 of them are
# tracked) and a real fuzz-dependency bump touches its content the same way a
# root bump touches the root `Cargo.lock`. Round three's finding was never that
# this file's content is safe to read as a lockfile; it is that nothing stops
# some OTHER part of the same diff from pointing a Cargo target at it as
# something else entirely (source, in vector 4). What makes that safe now is
# not this file's presence on the allowlist, it is that `manifest_disallowed_diff`
# refuses ANY manifest change that could create such a pointer, in ANY
# Cargo.toml this PR touches, not just the five kinds round three checked for.
# Verified against `git ls-files`: no manifest in this repository, at the
# commit this change was proposed on, has any `build`, `[lib] path`,
# `[[bin]]`/`[[test]]`/`[[bench]]`/`[[example]] path` already pointing at any
# `Cargo.lock` anywhere in the tree, so there is also no PRE-EXISTING pointer a
# lockfile-content-only bot diff could ride, the way #21's fixture rides an
# already-declared `build =` for the single-level case.
#
# `.github/workflows/[^/]+\.ya?ml` and `packages/[^/]+/package(-lock)?\.json`
# also stay on BOT_ALLOWED, and this check does NOT validate their content.
# Said plainly, because a prior draft of this comment implied otherwise: a
# `run:` step added to a workflow, or a lifecycle script (`postinstall` and
# friends) added to `packages/dashboard/package.json`, is NOT caught by
# anything in this file. That gap predates this change, `manifest_disallowed_diff`
# only ever runs over `Cargo.toml`, and closing it is a different, larger check
# (workflow diff semantics, npm lifecycle scripts) that does not belong folded
# into a manifest-diff function. Tracked separately in issue #840 rather than
# asserted as covered here.
BOT_ALLOWED='^(Cargo\.toml|Cargo\.lock|crates/[^/]+/Cargo\.toml|crates/[^/]+/fuzz/Cargo\.toml|crates/[^/]+/fuzz/Cargo\.lock|\.github/workflows/[^/]+\.ya?ml|\.github/dependabot\.yml|packages/[^/]+/package(-lock)?\.json)$'

# manifest_disallowed_diff <path> -- prints one line per way HEAD_SHA's version
# of <path> differs from MERGE_BASE's version that is NOT a dependency-table
# version string moving, or nothing if the only differences are that. Used only
# on the bot path, to decide whether a bot PR that touches a `Cargo.toml` may be
# exempted. See the long comment above BOT_ALLOWED for exactly what is allowed
# and why; this function is the executable form of that rule, not a second,
# separate one.
#
# Parsed with Python's stdlib `tomllib` (3.11+, already relied on elsewhere in
# this repository's CI: see the fuzz `[[bin]]` path cross-check in ci.yml)
# rather than a regex, specifically so table structure (which key belongs to
# which parent) is known rather than guessed.
#
# FAIL CLOSED, every direction:
#   - A manifest that exists at MERGE_BASE but cannot be read there (`git show`
#     fails despite `git cat-file -e` confirming it exists) is reported as an
#     offense, never silently treated as having no prior content.
#   - A HEAD_SHA version that does not parse as valid TOML at all is reported
#     as an offense: a check that cannot verify safety must not report safety.
#   - A BASE version that exists but does not parse as valid TOML is reported
#     as an offense too, for the same reason: there is nothing to diff against.
#   - A manifest with NO base version at all (a brand new file; `git cat-file
#     -e` says it does not exist at MERGE_BASE) is diffed against an empty
#     document, so every key in it counts as introduced. A bot never
#     legitimately authors a brand new manifest, so this is not a new
#     restriction on any real dependency bump.
#   - A manifest deleted at HEAD_SHA is not checked at all: nothing is left for
#     Cargo to compile from that path, so there is no capability to introduce.
#   - A dependency table, or a dependency entry's value, that is present but is
#     not the TOML shape expected (a table where a dependency value should be a
#     string or a detailed table, say) is refused rather than guessed at: an
#     unrecognized shape is treated the same as "cannot verify", not as safe.
manifest_disallowed_diff() {
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

# The exact and only shape a dependency-version bump takes. Everything this
# script allows through the bot path lives entirely in this tuple and the
# "workspace.dependencies" / "target.*.<name>" special cases just below; every
# other key in the document is refused by the generic recursive diff at the
# bottom, by default, with no separate enumeration to keep in sync.
DEP_TABLE_NAMES = ("dependencies", "dev-dependencies", "build-dependencies")
_MISSING = object()


def load(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.strip():
        return {}
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return None


def fmt(path):
    out = ""
    for part in path:
        if isinstance(part, int):
            out += "[%d]" % part
        elif out:
            out += ".%s" % part
        else:
            out = str(part)
    return out or "(the whole manifest)"


def short(value, limit=120):
    r = repr(value)
    if len(r) > limit:
        r = r[: limit - 3] + "..."
    return r


def is_dep_table_path(path):
    # The three package-level tables, the one workspace-level table, and each
    # of the three again inside every [target.'cfg(...)'] section. Nothing
    # else is ever treated as "a table whose entries may move version only".
    if path in (
        ("dependencies",),
        ("dev-dependencies",),
        ("build-dependencies",),
        ("workspace", "dependencies"),
    ):
        return True
    return len(path) == 3 and path[0] == "target" and path[2] in DEP_TABLE_NAMES


def dep_entry_offenses(path, base_entry, head_entry):
    # A bare string dependency value IS the version requirement; the format
    # gives it no other meaning, so any string-to-string change here is
    # exactly what a bump does, whatever the new string says.
    if isinstance(base_entry, str) and isinstance(head_entry, str):
        return []
    if not (isinstance(base_entry, dict) and isinstance(head_entry, dict)):
        return [
            "changes %s from %s to %s: not a version-string move"
            % (fmt(path), short(base_entry), short(head_entry))
        ]
    offenses = []
    for key in sorted(set(base_entry) | set(head_entry)):
        if key == "version":
            continue
        b = base_entry.get(key, _MISSING)
        h = head_entry.get(key, _MISSING)
        if b == h:
            continue
        sub = path + (key,)
        if b is _MISSING:
            offenses.append("introduces %s = %s" % (fmt(sub), short(h)))
        elif h is _MISSING:
            offenses.append("removes %s (was %s)" % (fmt(sub), short(b)))
        else:
            offenses.append("changes %s from %s to %s" % (fmt(sub), short(b), short(h)))
    return offenses


def diff(base, head, path=()):
    if is_dep_table_path(path):
        if isinstance(base, dict) and isinstance(head, dict):
            offenses = []
            for name in sorted(set(base) | set(head)):
                b = base.get(name, _MISSING)
                h = head.get(name, _MISSING)
                if b == h:
                    continue
                entry_path = path + (name,)
                if b is _MISSING:
                    offenses.append("introduces %s" % fmt(entry_path))
                elif h is _MISSING:
                    offenses.append("removes %s (was %s)" % (fmt(entry_path), short(b)))
                else:
                    offenses.extend(dep_entry_offenses(entry_path, b, h))
            return offenses
        if base == head:
            return []
        return ["changes %s: no longer a table (%s to %s)" % (fmt(path), short(base), short(head))]

    if base == head:
        return []

    if isinstance(base, dict) and isinstance(head, dict):
        offenses = []
        for key in sorted(set(base) | set(head)):
            b = base.get(key, _MISSING)
            h = head.get(key, _MISSING)
            if b == h:
                continue
            sub = path + (key,)
            if b is _MISSING:
                offenses.append("introduces %s = %s" % (fmt(sub), short(h)))
            elif h is _MISSING:
                offenses.append("removes %s (was %s)" % (fmt(sub), short(b)))
            else:
                offenses.extend(diff(b, h, sub))
        return offenses

    if isinstance(base, list) and isinstance(head, list):
        offenses = []
        for i in range(max(len(base), len(head))):
            sub = path + (i,)
            if i >= len(base):
                offenses.append("introduces %s = %s" % (fmt(sub), short(head[i])))
            elif i >= len(head):
                offenses.append("removes %s (was %s)" % (fmt(sub), short(base[i])))
            elif base[i] != head[i]:
                offenses.extend(diff(base[i], head[i], sub))
        return offenses

    return ["changes %s from %s to %s" % (fmt(path), short(base), short(head))]


base_doc = load(sys.argv[1])
head_doc = load(sys.argv[2])

if head_doc is None:
    print("the proposed version does not parse as TOML; cannot verify it changes only a dependency version")
    sys.exit(0)
if base_doc is None:
    print("the base version exists but does not parse as TOML; cannot verify what it already declared")
    sys.exit(0)

for offense in diff(base_doc, head_doc):
    print(offense)
PYEOF
}

case "$author" in
  dependabot\[bot\]|renovate\[bot\]|github-actions\[bot\])
    # Working directory for the manifest diff check below, created here,
    # inside the one case arm that ever reads it, rather than at the top of
    # the script.
    #
    # `manifest_disallowed_diff` is the only thing that reads `$MANIFEST_TMP`,
    # and it is only ever called from inside THIS arm, so nothing before this
    # line, and nothing on the non-bot path below the whole `case`, needs it.
    # Installing the trap this late, immediately before the first (and only)
    # code that needs the directory it protects, means every line above this
    # one, including the required-variable guards near the top of the script
    # and the `"${changed[@]}"` expansions in the empty-diff guard and the
    # embedded-newline check, runs with NO EXIT trap installed at all. That
    # matters for exactly the failure mode PR 837's fourth review round found:
    # an implicit fatal-expansion abort (`${VAR:?}`, or `"${changed[@]}"` on a
    # still-empty array under `set -u` on bash below 4.4) does not carry its
    # exit status through an EXIT trap, so a trap installed too early silently
    # turns that abort into rc=0. A trap that is not installed yet cannot do
    # that; bash is left to its own default behaviour on the abort, which is a
    # plain nonzero exit (verified directly, both with and without a trap in
    # place, same command: no trap rc=1, trap already installed rc=0). Every
    # exit reachable from this point on, for the rest of this arm, is either
    # this function's own `return 0` (a normal function return, not a fatal
    # abort) or this arm's two explicit `exit 0` / `exit 1` statements, both of
    # which propagate their status through an EXIT trap correctly regardless
    # of where the trap sits, so there is no similar reason to install this
    # any later than here, and no reason to install it at all for a PR whose
    # author never matches this case.
    MANIFEST_TMP="$(mktemp -d)"
    trap 'rm -rf "$MANIFEST_TMP"' EXIT

    offending=""
    for f in "${changed[@]}"; do
      grep -qE "$BOT_ALLOWED" <<<"$f" || offending="$offending$f
"
    done
    # The manifest diff check runs over every Cargo.toml this PR touches, not
    # only ones BOT_ALLOWED accepts: an offending path already fails below
    # regardless, and a manifest at an allowlisted path is exactly the case
    # this check exists for.
    for f in "${changed[@]}"; do
      case "$f" in
        Cargo.toml|*/Cargo.toml) : ;;
        *) continue ;;
      esac
      cap="$(manifest_disallowed_diff "$f")"
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
    echo "FAIL: $author is a bot but this PR touches files outside the dependency allowlist, or a manifest that changes something other than a dependency-table version string:" >&2
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
  if grep -qE "$ALWAYS_ALLOWED" <<<"$f"; then continue; fi
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
