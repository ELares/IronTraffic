#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The FAST gate: the inner loop for an implementer working on one issue.
#
# WHY THIS EXISTS. scripts/gate.sh is the full merge gate and it is slow,
# because it is workspace wide and includes MSRV, musl, cargo-deny and the
# no-default-features build. Rust compiles slowly, and an implementer that has
# to pay six minutes per iteration will take hours to converge on a change that
# touches one crate. That cost is multiplied by every retry of every runner, so
# it is the single largest lever on delivery speed.
#
# This script runs the checks that can actually FAIL for a single-crate change,
# scoped to the crates that change touches. Everything it omits is deliberate
# and is covered by the milestone sweep (scripts/gate.sh in CI at the end of
# each milestone), never dropped:
#
#   omitted here            covered by
#   ----------------------  ---------------------------------------------
#   MSRV 1.85               milestone sweep
#   musl static build       milestone sweep
#   cargo-deny              milestone sweep (and deny.toml rarely moves)
#   --no-default-features   milestone sweep
#   workspace-wide tests    milestone sweep
#   fuzz smoke              milestone sweep
#
# The checks that stay are the ones that catch a defect IN THIS DIFF: format,
# lints at pedantic, the touched crates' tests, and every structural check,
# which are greps and cost nothing.
#
# Usage:  scripts/gate-fast.sh            (derive crates from the git diff)
#         scripts/gate-fast.sh -p irontraffic-router [-p ...]
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

BASE="${BASE_REF:-main}"
PKGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -p) PKGS+=("$2"); shift 2 ;;
    *) echo "usage: $0 [-p <crate>]..." >&2; exit 2 ;;
  esac
done

# Derive the touched crates from the diff when none were named.
if [ ${#PKGS[@]} -eq 0 ]; then
  base_rev="$(git rev-parse --verify --quiet "origin/$BASE" || git rev-parse --verify --quiet "$BASE" || echo "")"
  merge_base=""
  [ -n "$base_rev" ] && merge_base="$(git merge-base "$base_rev" HEAD 2>/dev/null || true)"
  changed="$( { [ -n "$merge_base" ] && git diff --name-only "$merge_base"; git diff --name-only; git diff --name-only --cached; } 2>/dev/null | sort -u )"
  while read -r c; do
    [ -n "$c" ] && PKGS+=("$c")
  done < <(printf '%s\n' "$changed" | sed -n 's|^crates/\([^/]*\)/.*|\1|p' | sort -u)
fi

if [ ${#PKGS[@]} -eq 0 ]; then
  echo "gate-fast: no crate touched; running the structural checks only"
fi

SEL=()
for p in "${PKGS[@]:-}"; do
  [ -n "$p" ] && SEL+=(-p "$p")
done

fail() { echo; echo "GATE-FAST FAILED at: $1"; exit 1; }

echo "==> crates in scope: ${PKGS[*]:-none}"

echo "==> fmt"
cargo fmt --all --check || fail "cargo fmt --all --check"

if [ ${#SEL[@]} -gt 0 ]; then
  echo "==> clippy (pedantic, -D warnings) on the touched crates"
  cargo clippy --locked "${SEL[@]}" --all-targets --all-features -- -D warnings \
    || fail "cargo clippy on ${PKGS[*]}"

  echo "==> test (touched crates)"
  cargo test --locked "${SEL[@]}" --all-features || fail "cargo test on ${PKGS[*]}"

  echo "==> doctests (touched crates)"
  cargo test --locked "${SEL[@]}" --all-features --doc || fail "doctests on ${PKGS[*]}"
fi

# The structural checks are greps and cost milliseconds. They are the ones that
# catch the failure modes an implementer under pressure actually reaches for, so
# they run every time regardless of what changed.
echo "==> invariant lints"
scripts/invariant-lints.sh || fail "scripts/invariant-lints.sh"

echo "==> dash scan"
scripts/dash-scan.sh || fail "scripts/dash-scan.sh"

echo "==> test census (no test removed, no assertion weakened)"
BASE_REF="$BASE" scripts/test-census.sh || fail "scripts/test-census.sh"

echo
echo "gate-fast: green for ${PKGS[*]:-<no crate>}"
echo "NOTE: this is the fast inner loop. The full workspace gate (MSRV, musl,"
echo "cargo-deny, no-default-features, workspace tests, fuzz) runs in the"
echo "milestone sweep. Do not treat this as proof the whole workspace is green."
