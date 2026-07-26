#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The local merge gate. Runs everything CI runs that can run locally, in the
# same order. Green here means green in CI for every lane except musl, MSRV,
# and cargo-deny, which need extra toolchains (install them and this script
# runs those too).
#
# Run this BEFORE opening a pull request. Do not open a PR hoping CI is more
# forgiving than this script; it is not, it is the same checks.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "==> fmt"
cargo fmt --all --check

# shellcheck source=scripts/feature-matrix.sh
source scripts/feature-matrix.sh

# A crate with mutually exclusive features (irontraffic-tls's three crypto-*
# providers, enforced with a compile_error!) cannot compile under
# --all-features at all, so it is excluded from the workspace-wide runs below
# and checked separately, once per valid combination, further down. Every
# other crate is completely unaffected: with nothing matrixed, EXCLUDE_ARGS
# is empty and these three lines are exactly what they always were.
EXCLUDE_ARGS=()
while IFS= read -r name; do
  [ -n "$name" ] && EXCLUDE_ARGS+=(--exclude "$name")
done < <(matrixed_names)

echo "==> clippy (pedantic, -D warnings)"
cargo clippy --workspace "${EXCLUDE_ARGS[@]+"${EXCLUDE_ARGS[@]}"}" --all-targets --all-features -- -D warnings

echo "==> test"
cargo test --workspace "${EXCLUDE_ARGS[@]+"${EXCLUDE_ARGS[@]}"}" --all-features

echo "==> doctests"
cargo test --workspace "${EXCLUDE_ARGS[@]+"${EXCLUDE_ARGS[@]}"}" --all-features --doc

echo "==> data-plane-only build (the edge and k3s profile must not rot)"
cargo check --workspace --no-default-features

# The crates excluded above, checked once per valid feature combination
# instead of the single --all-features run that cannot compile them. This is
# STRICTLY MORE coverage than --all-features ever gave a crate like this: three
# runs instead of the zero a single unsatisfiable run was worth.
while IFS= read -r manifest; do
  [ -n "$manifest" ] || continue
  has_matrix "$manifest" || continue
  name="$(crate_name_of "$manifest")"
  while IFS= read -r feat; do
    [ -n "$feat" ] || continue
    echo "==> clippy ($name, --no-default-features --features $feat)"
    cargo clippy --locked -p "$name" --all-targets --no-default-features --features "$feat" -- -D warnings
    echo "==> test ($name, --no-default-features --features $feat)"
    cargo test --locked -p "$name" --no-default-features --features "$feat"
    echo "==> doctests ($name, --no-default-features --features $feat)"
    cargo test --locked -p "$name" --no-default-features --features "$feat" --doc
  done < <(declared_features "$manifest")
done < <(crate_manifests)

echo "==> feature matrix self-test (the matrix cannot silently collapse to zero runs)"
scripts/feature-matrix.sh selftest

echo "==> invariant lints"
scripts/invariant-lints.sh

echo "==> invariant lint self-test (the lints still enforce what they claim)"
scripts/invariant-lints-selftest.sh

echo "==> dash scan"
scripts/dash-scan.sh

echo "==> test census (no test removed, no assertion weakened)"
scripts/test-census.sh

echo "==> test census self-test (the census still enforces what it claims)"
scripts/test-census-selftest.sh

echo "==> governance files present"
for f in LICENSE LICENSE-APACHE LICENSE-MIT COVENANTS.md SECURITY.md \
         CONTRIBUTING.md AGENTS.md ARCHITECTURE.md \
         docs/WILL-NOT-IMPLEMENT.md docs/THREAT-MODEL.md; do
  test -s "$f" || { echo "missing or empty governance file: $f"; exit 1; }
done

if command -v cargo-deny >/dev/null 2>&1; then
  echo "==> cargo deny"
  cargo deny check
else
  echo "==> cargo deny SKIPPED (not installed; CI enforces it)"
  echo "    install with: cargo install cargo-deny --locked"
fi

# The musl lane cross-links a Linux binary. That only works on a Linux host (or
# with a musl cross toolchain installed), so attempting it from macOS produces a
# linker error that says nothing about the code. CI runs this lane on Linux and
# is the authority.
if [ "$(uname -s)" = "Linux" ] && rustup target list --installed | grep -q x86_64-unknown-linux-musl; then
  echo "==> musl static build"
  cargo build --release --target x86_64-unknown-linux-musl -p irontraffic
else
  echo "==> musl static build SKIPPED (needs a Linux host; CI enforces it)"
fi

echo
echo "gate: all local checks green"
