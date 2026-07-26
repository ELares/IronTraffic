#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The feature matrix: shared by scripts/gate-fast.sh, scripts/gate.sh, and
# .github/workflows/ci.yml, so the three can never disagree about which
# feature combinations a crate gets checked with.
#
# WHY THIS EXISTS. `--all-features` activates EVERY feature of a crate at
# once. A crate whose features are mutually exclusive by design (irontraffic-
# tls's three crypto-* providers, enforced with a compile_error!, because
# rustls cannot link two crypto backends as the process default at the same
# time) cannot compile under `--all-features` at all: the property the crate
# is REQUIRED to have is exactly what makes the blanket flag unsatisfiable.
# Cargo has no flag to subtract features from `--all-features`, so the answer
# has to live here: a crate declares its mutually exclusive feature group
# once, in its own manifest, and every one of the three callers above expands
# that into every valid combination and checks ALL of them, INSTEAD OF the
# single `--all-features` run that could never have compiled.
#
# THE DECLARATION lives in the crate's own Cargo.toml, not in a separate list
# in this file, because a separate list drifts out of sync with reality and
# nothing notices:
#
#   [package.metadata.gate]
#   exclusive-features = ["crypto-aws-lc-rs", "crypto-ring", "crypto-fips"]
#
# `[package.metadata.*]` is Cargo's own sanctioned extension point: cargo
# itself ignores it, so declaring it costs nothing, it cannot desync from
# what the crate actually builds the way a copy living in a script could, and
# it sits right next to the `[features]` table it describes.
#
# v1 supports exactly ONE exclusive group per crate, because that is the only
# shape any crate in the tree needs. A crate that ever needed two independent
# exclusive groups (say, a crypto provider AND an allocator choice) would need
# this format extended to a list of groups and the run computation changed to
# a cartesian product; nothing below assumes that can never happen, but
# nothing builds it ahead of a need either.
#
# THE ONE INVARIANT THIS FILE MUST NEVER VIOLATE: the number of runs for a
# crate that exists is never zero. An absent, empty, or malformed
# exclusive-features declaration is defined to mean "one run: the plain
# --all-features run", which is exactly today's behavior, never "zero runs".
# `runs_for` is the ONE function every caller goes through to learn what to
# run for a crate, and it always prints at least one line: read it end to end
# and there is no branch that emits nothing. That is what makes "this crate
# is exempt from the gate" impossible to express through this file
# structurally, rather than by a convention someone could forget: there is no
# separate skip flag to add, and shrinking the declared list only ever grows
# back to the one guaranteed run, never past it to none.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

# crate_manifests -- every crates/*/Cargo.toml, one per line, deterministically
# ordered so repeated runs (and the two callers comparing notes) agree.
crate_manifests() {
  git ls-files -- 'crates/*/Cargo.toml' | LC_ALL=C sort
}

# crate_name_of <manifest> -- the `name = "..."` value from [package].
crate_name_of() {
  awk -F'"' '
    /^\[package\]/ { in_pkg = 1; next }
    /^\[/          { in_pkg = 0 }
    in_pkg && /^name[[:space:]]*=/ { print $2; exit }
  ' "$1"
}

# declared_features <manifest> -- one feature name per line from this crate's
# [package.metadata.gate] exclusive-features array, or NOTHING (zero lines)
# if there is no declaration, or a malformed one. Zero lines here is fine and
# expected for most crates: turning "zero declared" into "one guaranteed run"
# is `runs_for`'s job below, not this function's, so a bug in extraction can
# under-report a group but can never by itself make a crate invisible to the
# gate.
declared_features() {
  python3 - "$1" <<'PY'
import re, sys

try:
    text = open(sys.argv[1], encoding='utf-8').read()
except OSError:
    sys.exit(0)

m = re.search(r'^\[package\.metadata\.gate\]\s*$', text, re.MULTILINE)
if not m:
    sys.exit(0)
rest = text[m.end():]
nxt = re.search(r'^\[', rest, re.MULTILINE)
section = rest[:nxt.start()] if nxt else rest

fm = re.search(r'exclusive-features\s*=\s*\[(.*?)\]', section, re.DOTALL)
if not fm:
    sys.exit(0)
for feat in re.findall(r'"([^"]+)"', fm.group(1)):
    print(feat)
PY
}

# has_matrix <manifest> -- exit 0 iff this crate declares a non-empty
# exclusive-features group.
has_matrix() {
  [ -n "$(declared_features "$1")" ]
}

# runs_for <manifest> -- one run per line. Each line is either the literal
# token "--all-features" (no group declared: run exactly as every crate
# always has) or a single feature name, meaning "run this crate with
# --no-default-features --features <name>". ALWAYS at least one line.
runs_for() {
  local manifest="$1" feats
  feats="$(declared_features "$manifest")"
  if [ -z "$feats" ]; then
    printf -- '--all-features\n'
    return 0
  fi
  printf '%s\n' "$feats"
}

# matrixed_names -- crate names (bare, one per line) that declare a group.
# This is the exclude list for the workspace-wide --all-features run: those
# crates are checked below instead, via matrix_runs, never in addition to.
matrixed_names() {
  local manifest
  while IFS= read -r manifest; do
    [ -n "$manifest" ] || continue
    has_matrix "$manifest" && crate_name_of "$manifest"
  done < <(crate_manifests)
  # Explicit, unconditional success: without this, the function's exit status
  # is whatever the LAST manifest's `has_matrix && crate_name_of` happened to
  # return, so a tree where the last crate (alphabetically) has no matrix
  # would make this "fail" even though enumeration completed correctly. A
  # caller that ever checked this exit status (rather than only reading
  # stdout, as gate.sh and ci.yml do today) would misread "nothing more to
  # report" as an error.
  return 0
}

# matrix_runs -- "<crate-name><TAB><feature>" one per line, for every
# matrixed crate's every declared feature. Crates with no declaration are
# absent on purpose: the workspace-wide run already checks them with
# --all-features exactly as before, and listing them here would check them
# twice under two different mechanisms.
matrix_runs() {
  local manifest name feat
  while IFS= read -r manifest; do
    [ -n "$manifest" ] || continue
    has_matrix "$manifest" || continue
    name="$(crate_name_of "$manifest")"
    while IFS= read -r feat; do
      [ -n "$feat" ] && printf '%s\t%s\n' "$name" "$feat"
    done < <(declared_features "$manifest")
  done < <(crate_manifests)
}

# json -- matrix_runs, reshaped into the JSON array
# `[{"crate":"...","features":"..."}, ...]` that a GitHub Actions dynamic
# `strategy.matrix` consumes via `fromJson`. `[]` when nothing is matrixed.
json() {
  python3 - <<'PY'
import json, sys

rows = []
for line in sys.stdin:
    line = line.rstrip('\n')
    if not line:
        continue
    crate, feat = line.split('\t', 1)
    rows.append({"crate": crate, "features": feat})
print(json.dumps(rows))
PY
}

# selftest -- proves the one invariant this file exists to guarantee: no
# input produces zero runs for a crate that exists, and a declared group is
# fully expanded rather than collapsed to one run. Exercised by
# scripts/gate.sh; not part of the fast inner loop.
selftest() {
  local work ok=1
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN

  mkdir -p "$work/none" "$work/empty" "$work/three" "$work/malformed"

  cat > "$work/none/Cargo.toml" <<'TOML'
[package]
name = "no-declaration"
version = "0.1.0"
TOML

  cat > "$work/empty/Cargo.toml" <<'TOML'
[package]
name = "empty-declaration"
version = "0.1.0"

[package.metadata.gate]
exclusive-features = []
TOML

  cat > "$work/three/Cargo.toml" <<'TOML'
[package]
name = "three-way"
version = "0.1.0"

[package.metadata.gate]
exclusive-features = ["crypto-a", "crypto-b", "crypto-c"]
TOML

  # No [package.metadata.gate] table at all, but the crate DOES have an
  # unrelated metadata table above it: proves the section-boundary regex
  # does not spill into or out of a neighboring table.
  cat > "$work/malformed/Cargo.toml" <<'TOML'
[package]
name = "unrelated-metadata"
version = "0.1.0"

[package.metadata.something-else]
exclusive-features = ["should-not-be-seen"]
TOML

  check_count() {
    local label="$1" manifest="$2" want="$3" got
    got="$(runs_for "$manifest" | grep -c .)"
    if [ "$got" -eq "$want" ]; then
      printf '  ok: %s -> %d run(s)\n' "$label" "$got"
    else
      printf '  FAIL: %s -> %d run(s), wanted %d\n' "$label" "$got" "$want"
      ok=0
    fi
  }

  echo "== feature-matrix selftest =="
  check_count "no declaration"                  "$work/none/Cargo.toml"      1
  check_count "empty declaration"                "$work/empty/Cargo.toml"    1
  check_count "three-way declaration"            "$work/three/Cargo.toml"    3
  check_count "declaration on an unrelated table" "$work/malformed/Cargo.toml" 1

  if ! runs_for "$work/none/Cargo.toml" | grep -qxF -- '--all-features'; then
    echo "  FAIL: no declaration must run exactly --all-features"
    ok=0
  fi
  if runs_for "$work/three/Cargo.toml" | grep -qxF -- '--all-features'; then
    echo "  FAIL: a declared group must never fall back to --all-features"
    ok=0
  fi
  for f in crypto-a crypto-b crypto-c; do
    if ! runs_for "$work/three/Cargo.toml" | grep -qxF "$f"; then
      echo "  FAIL: three-way declaration lost feature $f"
      ok=0
    fi
  done

  if has_matrix "$work/none/Cargo.toml"; then
    echo "  FAIL: no declaration must not read as having a matrix"
    ok=0
  fi
  if has_matrix "$work/empty/Cargo.toml"; then
    echo "  FAIL: an empty declaration must not read as having a matrix"
    ok=0
  fi
  if ! has_matrix "$work/three/Cargo.toml"; then
    echo "  FAIL: a three-way declaration must read as having a matrix"
    ok=0
  fi

  # Every real crate manifest in THIS workspace, right now, resolves to at
  # least one run. This is the same claim proven synthetically above, checked
  # against the tree the gate actually runs on.
  while IFS= read -r manifest; do
    [ -n "$manifest" ] || continue
    n="$(runs_for "$manifest" | grep -c .)"
    if [ "$n" -lt 1 ]; then
      echo "  FAIL: $manifest resolved to zero runs"
      ok=0
    fi
  done < <(crate_manifests)

  if [ "$ok" -eq 1 ]; then
    echo "feature-matrix selftest: clean"
    return 0
  fi
  echo "feature-matrix selftest: FAILED"
  return 1
}

# Dispatch only when executed directly; sourcing (gate.sh, gate-fast.sh) must
# only define the functions above and must not run any of them as a side
# effect of `source scripts/feature-matrix.sh`.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    runs)           [ $# -eq 2 ] || { echo "usage: $0 runs <crate-manifest>" >&2; exit 2; }; runs_for "$2" ;;
    has-matrix)     [ $# -eq 2 ] || { echo "usage: $0 has-matrix <crate-manifest>" >&2; exit 2; }; has_matrix "$2" ;;
    matrixed-names) matrixed_names ;;
    matrix-runs)    matrix_runs ;;
    json)           matrix_runs | json ;;
    selftest)       selftest ;;
    *)
      echo "usage: $0 {runs <manifest>|has-matrix <manifest>|matrixed-names|matrix-runs|json|selftest}" >&2
      exit 2
      ;;
  esac
fi
