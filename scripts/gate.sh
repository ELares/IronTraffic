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

echo "==> clippy (pedantic, -D warnings)"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> test"
cargo test --workspace --all-features

echo "==> doctests"
cargo test --workspace --all-features --doc

echo "==> data-plane-only build (the edge and k3s profile must not rot)"
cargo check --workspace --no-default-features

echo "==> invariant lints"
scripts/invariant-lints.sh

echo "==> invariant lint self-test (the lints still enforce what they claim)"
scripts/invariant-lints-selftest.sh

echo "==> dash scan"
scripts/dash-scan.sh

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
