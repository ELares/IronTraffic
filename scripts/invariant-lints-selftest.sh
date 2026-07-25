#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Self-test for scripts/invariant-lints.sh.
#
# WHY THIS EXISTS. The invariant lints are the main structural defence against
# the mistakes a small model makes, and they are implemented as greps. A grep
# that silently stops matching is strictly worse than no lint at all: it reports
# success forever and nobody notices, so the rule quietly stops existing while
# the badge stays green. This script proves, on every CI run, that:
#
#   1. every rule still FIRES on a corpus of deliberate violations, and
#   2. no rule fires on a clean corpus (no false positives), and
#   3. the escape hatch suppresses a rule ONLY when it carries a written
#      reason, so it cannot be used to silently disable a rule.
#
# It builds throwaway git repositories in a temp directory and runs the real
# lint script against them, so it tests the shipped script, not a copy.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
LINTS="$PWD/scripts/invariant-lints.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILED=0
note() { printf '  %s\n' "$1"; }

# Build a throwaway repo at $1 and run the lints in it, printing which rules fired.
run_lints_in() {
  ( cd "$1" && git init -q . && git config user.email t@t && git config user.name t \
      && git add -A >/dev/null && git commit -qm t >/dev/null \
      && bash "$LINTS" 2>&1 || true )
}
fired_rules() { run_lints_in "$1" | sed -n 's/^FAIL \[\(.*\)\]$/\1/p' | LC_ALL=C sort -u; }

# ---------------------------------------------------------------------------
# Corpus A: deliberate violations. Every rule listed must fire.
# ---------------------------------------------------------------------------
A="$WORK/bad"
mkdir -p "$A/crates/irontraffic-router/src" "$A/crates/irontraffic-time/src"

cat > "$A/crates/irontraffic-router/src/hot.rs" <<'RS'
//! HOT PATH
//! Deliberately violates the hot-path rules.
/// Handles a request.
pub fn handle(n: usize) -> usize {
    let v: Vec<u8> = Vec::new();
    let key = format!("{n}");
    let m = std::sync::Mutex::new(0u32);
    let g = m.lock();
    drop(g);
    v.len() + key.len()
}
RS

cat > "$A/crates/irontraffic-router/src/bad.rs" <<'RS'
//! Deliberately violates the production-code rules.
use std::time::Instant;
/// Parses a value.
pub fn parse(s: &str) -> usize {
    let started = Instant::now();
    let narrowed = s.len() as u16;
    let api_key = "k";
    if api_key == "other" { return 0; }
    let _ = compute();
    std::thread::sleep(std::time::Duration::from_millis(1));
    let parsed: usize = s.parse().unwrap();
    parsed + narrowed as usize + started.elapsed().as_millis() as usize
}
fn compute() -> Result<(), ()> { Ok(()) }
/// Not finished.
pub fn later() { todo!() }
#[allow(dead_code)]
fn hidden() {}
#[cfg(test)]
mod tests {
    #[test]
    fn asserts_nothing() { let _x = 1 + 1; }
    #[test]
    fn vacuous() { assert!(true); }
    #[test]
    #[ignore]
    fn skipped() { assert_eq!(1, 2); }
}
RS

cat > "$A/crates/irontraffic-router/src/unsafe_use.rs" <<'RS'
//! Deliberately uses unsafe.
/// Reads a byte.
pub unsafe fn peek(p: *const u8) -> u8 { *p }
RS

printf '[workspace.dependencies]\nserde = "1"\n' > "$A/Cargo.toml"

EXPECTED='allow-needs-reason
constant-time-secrets
determinism-seam
dependency-justification
hot-path-allocation
hot-path-lock
no-blocking-in-async
no-ignored-tests
no-panic
no-stub
no-swallowed-error
no-test-without-assertion
no-unsafe
no-vacuous-assert
unchecked-cast'

echo "== corpus A: every rule must fire =="
ACTUAL="$(fired_rules "$A")"
# comm requires both inputs sorted under the SAME collation, so sort both here
# rather than trusting the literal above to stay in order.
EXPECTED_SORTED="$(echo "$EXPECTED" | LC_ALL=C sort -u)"
MISSING="$(comm -23 <(echo "$EXPECTED_SORTED") <(echo "$ACTUAL") || true)"
EXTRA="$(comm -13 <(echo "$EXPECTED_SORTED") <(echo "$ACTUAL") || true)"
if [ -n "$MISSING" ]; then
  echo "FAIL: these rules STOPPED FIRING on known violations:"
  echo "$MISSING" | sed 's/^/    /'
  FAILED=1
fi
if [ -n "$EXTRA" ]; then
  echo "NOTE: rules fired that this corpus did not expect (update the corpus):"
  echo "$EXTRA" | sed 's/^/    /'
fi
[ -z "$MISSING" ] && note "all $(echo "$EXPECTED" | wc -l | tr -d ' ') expected rules fired"

# ---------------------------------------------------------------------------
# Corpus B: clean code. No rule may fire.
# ---------------------------------------------------------------------------
B="$WORK/clean"
mkdir -p "$B/crates/irontraffic-router/src" "$B/crates/irontraffic-time/src"

cat > "$B/crates/irontraffic-time/src/lib.rs" <<'RS'
//! The time seam. Direct clock access is legal HERE and nowhere else.
use std::time::Instant;
/// Returns a monotonic instant.
#[must_use]
pub fn now() -> Instant { Instant::now() }
RS

cat > "$B/crates/irontraffic-router/src/lib.rs" <<'RS'
//! Clean production code that must not trip any rule.
/// Parses a value, returning an error rather than panicking.
///
/// # Errors
/// Returns `Err` when the input is not a decimal integer.
pub fn parse(s: &str) -> Result<usize, std::num::ParseIntError> { s.parse() }

/// Compares two credentials in constant time.
#[must_use]
pub fn creds_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{creds_match, parse};
    #[test]
    fn parses_a_decimal() { assert_eq!(parse("42").unwrap(), 42); }
    #[test]
    fn rejects_a_non_decimal() { assert!(parse("x").is_err()); }
    #[test]
    fn credentials_compare_by_value() {
        assert!(creds_match(b"abc", b"abc"));
        assert!(!creds_match(b"abc", b"abd"));
    }
}
RS

cat > "$B/Cargo.toml" <<'TOML'
[workspace.dependencies]
# serde: configuration deserialization. MIT OR Apache-2.0, pure Rust, musl clean.
serde = "1"
TOML

echo "== corpus B: no rule may fire =="
CLEAN_FIRED="$(fired_rules "$B")"
if [ -n "$CLEAN_FIRED" ]; then
  echo "FAIL: these rules produced FALSE POSITIVES on clean code:"
  echo "$CLEAN_FIRED" | sed 's/^/    /'
  run_lints_in "$B" | sed 's/^/    /'
  FAILED=1
else
  note "clean corpus is clean"
fi

# ---------------------------------------------------------------------------
# Corpus C: the escape hatch. A reason suppresses; a bare marker does not.
# ---------------------------------------------------------------------------
C="$WORK/escape"
mkdir -p "$C/crates/irontraffic-router/src"
cp "$B/Cargo.toml" "$C/Cargo.toml"
cat > "$C/crates/irontraffic-router/src/lib.rs" <<'RS'
//! Uses the escape hatch correctly.
/// Parses a value that the caller guarantees is a decimal.
#[must_use]
pub fn parse(s: &str) -> usize { s.parse().unwrap() } // it-allow: no-panic reason: caller proved the input is decimal
RS
echo "== corpus C: a justified escape suppresses the rule =="
if [ -n "$(fired_rules "$C")" ]; then
  echo "FAIL: a justified escape did not suppress its rule."
  run_lints_in "$C" | sed 's/^/    /'
  FAILED=1
else
  note "justified escape suppresses"
fi

# Same file, marker stripped of its reason. The rule MUST fire again.
sed -i.bak 's| reason: caller proved the input is decimal||' "$C/crates/irontraffic-router/src/lib.rs"
rm -f "$C/crates/irontraffic-router/src/lib.rs.bak"
rm -rf "$C/.git"
echo "== corpus D: a bare marker with no reason must NOT suppress =="
if fired_rules "$C" | grep -q '^no-panic$'; then
  note "bare marker does not suppress"
else
  echo "FAIL: a bare escape marker with no written reason suppressed the rule."
  echo "      The escape hatch would then be a silent off switch."
  FAILED=1
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "invariant-lints-selftest: FAILED. The lint script no longer enforces what it claims."
  exit 1
fi
echo "invariant-lints-selftest: clean"
