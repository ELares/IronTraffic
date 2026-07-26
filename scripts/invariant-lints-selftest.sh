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

# Run the lints against a repo AS IT ALREADY STANDS, with no add/commit step
# of its own. Used only by the untracked-source corpus below, which has to
# control exactly what is staged, untracked, and ignored at each step; the
# blanket `git add -A` in run_lints_in would defeat the very thing being
# tested.
run_lints_raw() { ( cd "$1" && bash "$LINTS" 2>&1 || true ) }
fired_rules_raw() { run_lints_raw "$1" | sed -n 's/^FAIL \[\(.*\)\]$/\1/p' | LC_ALL=C sort -u; }

# ---------------------------------------------------------------------------
# Corpus A: deliberate violations. Every rule listed must fire.
# ---------------------------------------------------------------------------
A="$WORK/bad"
mkdir -p "$A/crates/irontraffic-router/src" "$A/crates/irontraffic-time/src" \
  "$A/crates/irontraffic-io/src"

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
/// Deliberately names tokio directly outside the transport seam.
pub fn current_runtime_handle() {
    let h = tokio::runtime::Handle::current();
    drop(h);
}
/// Deliberately wires two connection halves with no backpressure.
pub fn wire_up() {
    let (tx, rx) = mpsc::unbounded_channel();
    let (tx2, rx2) = unbounded();
    let (tx3, rx3) = unbounded::<u8>();
    drop((tx, rx, tx2, rx2, tx3, rx3));
}
/// Deliberately stores per-core state in a struct field.
pub struct Worker {
    ctx: CoreCtx,
    handle: Option<CoreHandle>,
}
/// Deliberately stores per-core state behind a trailing comment, which used
/// to defeat the end-of-line anchor with a single keystroke.
pub struct CommentedWorker {
    ctx: CoreCtx, // per-core context
}
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

cat > "$A/crates/irontraffic-router/src/publish.rs" <<'RS'
//! Deliberately violates single-snapshot-publish: an un-allowlisted .store(.
use std::sync::Arc;
/// Publishes a configuration snapshot from a site that is not listed in
/// scripts/allowlist-arcswap-store.txt.
pub fn publish(snapshot: u8) {
    CELL.store(Arc::new(snapshot));
}
RS

cat > "$A/crates/irontraffic-router/src/publish_realistic.rs" <<'RS'
//! Deliberately violates single-snapshot-publish with the REALISTIC shape
//! that the old same-line ArcSwap-plus-.store( pattern missed entirely: the
//! type name and the store call are never on the same line, so no alias and
//! no evasion is needed to slip past a same-line co-occurrence check. This
//! file is NOT listed in scripts/allowlist-arcswap-store.txt.
use arc_swap::ArcSwap;
use std::sync::Arc;

/// Holds the current route snapshot behind a lock-free swap.
pub struct Holder {
    table: ArcSwap<u8>,
}

impl Holder {
    /// Publishes a new snapshot from a site that is not the allowlisted one.
    pub fn publish(&self, next: Arc<u8>) {
        self.table.store(next);
    }
}
RS

cat > "$A/crates/irontraffic-router/src/alias.rs" <<'RS'
//! Deliberately violates no-guarded-alias: renaming a guarded symbol, or
//! aliasing it through `type`, removes the text every other rule greps for,
//! without removing the hazard.
use std::cell::RefCell as PerCoreCell;
use arc_swap::ArcSwap as Snap;
use inner::CoreCtx as MyCtx;
pub use inner::{Helper, CoreCtx};

/// A `type` alias is a second way to hide a guarded cell type: the alias
/// name carries no trace of RefCell at any of its use sites.
type AliasedCell = std::cell::RefCell<u8>;

/// Same evasion, for the ArcSwap guard.
type AliasedSwap = arc_swap::ArcSwap<u8>;

/// Same evasion, for the CoreCtx guard.
type AliasedCtx = inner::CoreCtx;

mod inner {
    pub struct CoreCtx;
    pub struct Helper;
}
RS

cat > "$A/crates/irontraffic-io/src/reexport.rs" <<'RS'
//! Deliberately violates no-guarded-alias: a public re-export of tokio from
//! inside the seam crate hands the escape hatch to every downstream crate,
//! which can then use raw tokio with no `tokio::` text outside this file.
//! Three spellings of the re-export marker, all of which must fire.
pub use tokio::net::TcpListener as RawListener;
pub use ::tokio::net::TcpStream as RawStream;

mod raw {
    pub(crate) use tokio::net::UdpSocket;
}
RS

cat > "$A/crates/irontraffic-io/src/balance.rs" <<'RS'
//! Deliberately violates balance-drop-only and interior-mutability. This
//! path is exempt from transport-seam, so a fetch_sub and a RefCell here
//! isolate those two rules from the transport-seam violation in bad.rs.
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
/// Tracks outstanding permits without releasing them through Drop.
pub struct Permits {
    count: AtomicUsize,
}
impl Permits {
    /// Releases one permit inline, not inside a Drop impl.
    pub fn release(&self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}
/// Builds a per-core cell that a migrating task could race on.
pub fn make_cell() -> RefCell<u8> {
    let c: RefCell<u8> = RefCell::new(0);
    c
}
RS

cat > "$A/crates/irontraffic-io/src/balance_wrap.rs" <<'RS'
//! Deliberately violates balance-drop-only via a wrapping fetch_add: adding
//! a type's MAX value decrements an unsigned integer by exactly one, with
//! the decrement operation spelled a way that never names the sibling
//! subtracting operation anywhere in this file.
use std::sync::atomic::{AtomicU32, Ordering};
/// Tracks outstanding leases without releasing them through Drop.
pub struct Leases {
    count: AtomicU32,
}
impl Leases {
    /// Releases one lease by wrapping the counter down by one, with no Drop
    /// impl anywhere in this file.
    pub fn release(&self) {
        self.count.fetch_add(u32::MAX, Ordering::Relaxed);
    }
}
RS

# Deliberately missing [lints] workspace = true, and hardcoding edition
# instead of edition.workspace = true: crate-inherits-workspace (#452).
cat > "$A/crates/irontraffic-router/Cargo.toml" <<'TOML'
[package]
name = "irontraffic-router"
edition = "2021"
version.workspace = true
license.workspace = true

[dependencies]
TOML

# Deliberately violates the NOT-line-oriented forms added under #453/#456:
# a multi-line #[allow(...)] with no reason anywhere in it, a wrapped
# assert!(matches!(..., _)), a wrapped secret == comparison, a wrapped
# fetch_add(TYPE::MAX, ...) with no Drop impl, every new ArcSwap-publish
# spelling, and a wrapped pub-use / type alias hiding a guarded symbol.
# Each of these previously either failed to fire (a bypass) or, for the
# rustfmt-forced #[allow(...)] wrap, fired on code that had a reason and
# simply could not spell it on one line (a false positive cargo fmt and this
# rule disagreed about, which is its own kind of bug).
cat > "$A/crates/irontraffic-router/src/multiline_bad.rs" <<'RS'
//! Deliberately violates every NOT-line-oriented rule added under #453/#456.
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use arc_swap::ArcSwap;

/// A multi-line #[allow(...)] whose reason never made it onto any line:
/// deliberately missing, not merely wrapped.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub fn many_lints_no_reason(
    a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8,
) -> u8 {
    a + b + c + d + e + f + g + h + i
}

/// A wrapped vacuous assert!(matches!(..., _)): the exact shape
/// no-vacuous-assert exists to catch, spread across lines by rustfmt
/// because the expression under test is realistically long rather than a
/// placeholder.
pub fn check_shape(some_moderately_long_expression_result_value_here: u8) {
    assert!(matches!(
        some_moderately_long_expression_result_value_here,
        _
    ));
}

/// A wrapped secret == comparison: constant-time-secrets must still see it
/// once rustfmt has moved `==` onto its own line.
pub fn compare(
    some_api_key_variable_name_used_for_probing_purposes_here: u64,
    expected_value_variable_name_used_here: u64,
) -> bool {
    if some_api_key_variable_name_used_for_probing_purposes_here
        == expected_value_variable_name_used_here
    {
        return true;
    }
    false
}

/// A wrapped fetch_add(TYPE::MAX, ...) decrement with no Drop impl anywhere
/// in this file: balance-drop-only must still see it once the call's own
/// arguments, not just the receiver, have wrapped onto their own lines.
pub struct Permits {
    count: AtomicU32,
}
impl Permits {
    pub fn release_wrapped(&self) {
        self.count.fetch_add(
            u32::MAX,
            Ordering::Relaxed,
        );
    }
}

/// Every new single-snapshot-publish spelling: swap, compare_and_swap, and
/// rcu, none of which mention `.store(`.
pub struct Holder {
    table: ArcSwap<u8>,
}
impl Holder {
    pub fn publish_via_swap(&self, next: Arc<u8>) {
        self.table.swap(next);
    }
    pub fn publish_via_cas(&self, current: &Arc<u8>, next: Arc<u8>) {
        self.table.compare_and_swap(current, next);
    }
    pub fn publish_via_rcu(&self, add: u8) {
        self.table.rcu(|old| **old + add);
    }
}

/// Reassigning an existing ArcSwap-typed place with a fresh
/// ArcSwap::from_pointee, rather than binding a new let: also a republish.
pub struct Reinit {
    pub table: ArcSwap<u8>,
}
impl Reinit {
    pub fn reinit(&mut self, v: u8) {
        self.table = ArcSwap::from_pointee(v);
    }
}
RS

# Deliberately violates no-guarded-alias via the two multi-line statement
# forms: a wrapped pub-use braced list and a wrapped type alias, neither of
# which puts the guarded name on the same line as `pub use` or `type ... =`.
cat > "$A/crates/irontraffic-router/src/guarded_alias_multiline_bad.rs" <<'RS'
//! Deliberately violates no-guarded-alias via wrapped multi-line statements.
pub use inner::{
    AndOneMoreForGoodMeasureToForceWrap, CoreCtx, Helper, OtherThing, YetAnotherThing,
};

pub type AliasedCellWithAVeryLongNameIndeedToPushThisOverTheEdgeOfMaxWidth =
    std::cell::RefCell<SomeVeryLongGenericParameterNameToForceARustfmtWrapHereForSure>;

mod inner {
    pub struct Helper;
    pub struct CoreCtx;
    pub struct OtherThing;
    pub struct YetAnotherThing;
    pub struct AndOneMoreForGoodMeasureToForceWrap;
}
RS

# Deliberately uses a direct clock read (rustix::time) outside the seam
# crate, and blocking std::fs / std::process calls the original
# no-blocking-in-async list did not name.
cat > "$A/crates/irontraffic-router/src/axis_two_bad.rs" <<'RS'
//! Deliberately uses spellings the ORIGINAL patterns for determinism-seam
//! and no-blocking-in-async did not cover, outside the crates that are
//! allowed to.
/// Reads the boot clock directly instead of through irontraffic-time.
pub fn read_boot_time() -> u64 {
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    ts.tv_sec as u64
}
/// Reads filesystem metadata synchronously, a blocking syscall none of the
/// original read/write/File/create/remove/copy/rename prefixes named.
pub fn stat_it(p: &std::path::Path) -> bool {
    std::fs::metadata(p).is_ok()
}
/// Spawns a child process synchronously, blocking the calling thread for
/// its lifetime; the original list had no representation for this at all.
pub fn run_it() {
    let _ = std::process::Command::new("true").status();
}
RS

# Deliberately places a real attribute (not a literal decoy) between #[test]
# and fn, on a test with NO assertion: this must still be caught, proving
# the fix does not overcorrect into never firing once such tests are finally
# visible to it.
cat > "$A/crates/irontraffic-router/src/attributed_test_bad.rs" <<'RS'
//! Deliberately places an attribute between #[test] and fn on an
//! assertion-free test.
#[cfg(test)]
mod tests {
    #[test]
    #[allow(clippy::assertions_on_constants, reason = "no assertion at all here on purpose")]
    fn attributed_and_empty() {
        let _x = 1 + 1;
    }
}
RS

# Deliberately reproduces the exact #286 brace-in-literal false NEGATIVE
# shape, but with genuinely NO assertion, so the fix must still catch a real
# violation rather than merely stop false-positiving on a good one.
cat > "$A/crates/irontraffic-router/src/literal_braces_bad.rs" <<'RS'
//! Deliberately assertion-free tests, each with a decoy brace in a literal
//! or comment between the test marker and the real body, or inside it.
use proptest::prelude::*;

proptest! {
    #[test]
    fn regex_repetition_decoy(s in "[a-z][a-z0-9-]{0,20}") {
        let _ = s;
    }

    #[test]
    fn unicode_escape_decoy(c in prop_oneof![Just('\u{e9}'), Just('\u{65e5}')]) {
        let _ = c;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn raw_string_decoy() {
        let pattern = r"{not a real brace} { still not }";
        let _ = pattern;
    }

    #[test]
    fn comment_decoy() {
        // a stray brace in a comment: { should not affect depth counting
        let _ = 1;
    }
}
RS

# Deliberately reads a framing-confined field from a file that is NOT one of
# the six allowed by framing-fields-confined, to exercise that rule.
mkdir -p "$A/crates/irontraffic-http/src"
cat > "$A/crates/irontraffic-http/src/rogue_reader.rs" <<'RS'
//! Deliberately violates framing-fields-confined: reads a framing-confined
//! field outside the six-file allowlist.
use crate::known::KnownHeader;

/// Not one of the six files permitted to read a framing-confined field.
pub fn is_content_length(k: KnownHeader) -> bool {
    k == KnownHeader::ContentLength
}
RS

printf '[workspace.dependencies]\nserde = "1"\n' > "$A/Cargo.toml"

EXPECTED='allow-needs-reason
balance-drop-only
constant-time-secrets
core-ctx-not-stored
crate-inherits-workspace
determinism-seam
dependency-justification
framing-fields-confined
hot-path-allocation
hot-path-lock
interior-mutability
no-blocking-in-async
no-guarded-alias
no-ignored-tests
no-panic
no-stub
no-swallowed-error
no-test-without-assertion
no-unbounded-channel
no-unsafe
no-vacuous-assert
single-snapshot-publish
transport-seam
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
mkdir -p "$B/crates/irontraffic-router/src" "$B/crates/irontraffic-time/src" \
  "$B/crates/irontraffic-io/src"

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

/// A stand-in for a bounded resource pool, used only to exercise the
/// no-unbounded-channel lint's false-positive guards: a method call named
/// is_unbounded and a field access named unbounded must both be left alone,
/// since neither one is the banned constructor.
pub struct Limits {
    /// Configured ceiling; a name, not a constructor call.
    pub unbounded: usize,
}

impl Limits {
    /// Corpus-only helper proving that a call to is_unbounded is not the
    /// banned constructor.
    #[must_use]
    pub fn is_unbounded(&self) -> bool {
        false
    }

    /// Corpus-only helper proving that reading the unbounded field is not
    /// the banned constructor either.
    #[must_use]
    pub fn describe(&self, limits: &Limits) -> bool {
        if self.is_unbounded() {
            return true;
        }
        let n = limits.unbounded;
        n == 0
    }

    /// Corpus-only helper proving that a turbofish on the GUARDED method
    /// name still does not match: the boundary guard looks at what precedes
    /// the word unbounded, and a dot or an underscore there excludes it
    /// regardless of what comes between the identifier and the paren.
    #[must_use]
    pub fn is_unbounded_typed<T>(&self) -> bool {
        self.is_unbounded::<T>()
    }
}

/// A stand-in `CoreCtx` used only to exercise core-ctx-not-stored's three
/// documented false positives: a single-line function signature, a typed
/// closure parameter, and the type's own definition.
pub struct CoreCtx {
    index: u64,
}

impl CoreCtx {
    fn index(&self) -> u64 { self.index }
}

/// A single-line function signature must not match: it ends with `{`.
fn helper(c: &CoreCtx) -> u64 { c.index() }

/// A single-line function signature with a trailing comment must not match
/// either: the comment starts right after `{`, not right after `CoreCtx`, so
/// the new `(//.*)?` alternative added to survive a trailing comment on a
/// field never gets a chance to engage here.
fn helper_commented(c: &CoreCtx) -> u64 { c.index() } // borrowed only, never stored

/// A typed closure parameter must not match: it ends with `|`.
fn uses_closure() -> u64 {
    let n = core::with(|c: &CoreCtx| c.index());
    n
}

mod core {
    // Deliberately no `use super::CoreCtx;` here: a bare `use ...::CoreCtx;`
    // import is a documented false positive (it DOES match), so the clean
    // corpus must not contain one. The fully qualified path below avoids it.
    pub fn with<F: FnOnce(&super::CoreCtx) -> u64>(f: F) -> u64 {
        f(&super::CoreCtx { index: 0 })
    }
}

/// A stand-in unguarded type, aliased via `as`. Renaming an UNGUARDED symbol
/// is ordinary Rust and must not trip no-guarded-alias.
use std::collections::HashMap as Map;

/// `OnceCell` is not a guarded cell type, so aliasing it must not trip
/// no-guarded-alias either.
use std::cell::OnceCell as InitCell;

/// A `pub use` of something that is not a guarded symbol must not trip the
/// CoreCtx/tokio re-export alternatives.
pub use std::num::ParseIntError as ReExportedError;

/// An ordinary numeric cast must not trip the alias rule: the guarded-name
/// alternatives all require the guarded name to appear BEFORE `as`, and no
/// guarded name appears on this line at all.
#[must_use]
pub fn widen(count: u8) -> usize {
    count as usize
}

#[must_use]
pub fn build_map() -> Map<u8, InitCell> {
    Map::new()
}

/// A `type` alias of an UNGUARDED type must not trip the alias rule: no
/// Cell/RefCell/UnsafeCell/ArcSwap/CoreCtx name appears anywhere on this
/// line.
pub type ParseResult = Result<usize, std::num::ParseIntError>;

/// A `type` alias whose right-hand side is an unrelated generic container
/// must not trip it either.
pub type Registry = std::collections::HashMap<u8, u8>;

/// A `type` alias of `OnceCell` must not trip the Cell-group alternative:
/// `OnceCell` is not a guarded cell type, exactly as the bare `use ... as`
/// form already leaves it alone.
pub type InitOnce = std::cell::OnceCell<u8>;

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

cat > "$B/crates/irontraffic-io/src/lib.rs" <<'RS'
//! The transport seam. Direct tokio use is legal HERE and nowhere else.
use std::cell::OnceCell;
use std::sync::atomic::{AtomicUsize, Ordering};
// A PRIVATE, unaliased tokio import is the legitimate case no-guarded-alias
// must leave alone: it is neither `pub` nor renamed, so it hands nothing to
// a downstream crate.
use tokio::net::TcpListener;
// A pub(crate) re-export of something that is NOT tokio must not trip the
// widened tokio alternative: only the literal word tokio after use may
// match, regardless of the pub/pub(crate)/pub(super) tolerance added to
// survive the crate-visible laundering step.
pub(crate) use std::net::TcpListener as StdListener;

/// Spawns a background task on the current tokio runtime. This crate is one
/// of the two places outside which naming tokio directly is banned.
pub fn spawn_background<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(fut);
}

/// Binds a listener using the private import above, so it is not flagged as
/// unused; the import itself is what corpus B is proving is legitimate.
#[must_use]
pub fn listener_type_name() -> &'static str {
    std::any::type_name::<TcpListener>()
}

/// A one-shot initialised value. `OnceCell` is not banned: it is a
/// legitimate single-initialisation cell, not a per-core mutable one.
pub struct Once {
    value: OnceCell<u8>,
}

thread_local! {
    /// Confined to a synchronous closure; never migrates across an await,
    /// and declares no cell type at all.
    static COUNT: usize = 0;
}

/// A permit balance that releases correctly through `Drop`, so the
/// decrement can never be forgotten on an early return.
pub struct MyGuard {
    count: AtomicUsize,
}

impl Drop for MyGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}
RS

cat > "$B/crates/irontraffic-io/src/counter.rs" <<'RS'
//! An ordinary monotone counter, in its own file with no Drop impl anywhere
//! in it, proving that a plain increment with no wrapping-MAX operand is
//! still left alone: a monotone counter may lose an increment, and does not
//! need to balance in Drop.
use std::sync::atomic::{AtomicUsize, Ordering};
/// Counts requests handled; only ever goes up.
pub struct Hits {
    count: AtomicUsize,
}
impl Hits {
    /// Records one more hit. This is an increment, not a balance release,
    /// so it must not require a Drop impl in this file.
    pub fn record(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}
RS

cat > "$B/crates/irontraffic-io/src/saturating.rs" <<'RS'
//! A saturating monotone counter, in its own file with no Drop impl, proving
//! that ::MAX buried inside a NESTED call's argument does not trip
//! balance-drop-only: the widened pattern requires ::MAX to be the whole
//! first argument fetch_add receives, and here the first argument is the
//! call `n.min(...)`, not a bare TYPE::MAX literal.
use std::sync::atomic::{AtomicUsize, Ordering};
/// Counts bytes forwarded, saturating instead of wrapping on overflow.
pub struct Forwarded {
    total: AtomicUsize,
}
impl Forwarded {
    /// Adds n, clamped so the counter never wraps past usize::MAX.
    pub fn add(&self, n: usize) {
        let current = self.total.load(Ordering::Relaxed);
        self.total
            .fetch_add(n.min(usize::MAX - current), Ordering::Relaxed);
    }
}
RS

cat > "$B/crates/irontraffic-router/src/holder.rs" <<'RS'
//! A REALISTIC, multi-line ArcSwap publication site: the type name and the
//! store call are never on the same line, which is exactly why the old
//! same-line co-occurrence pattern was close to vacuous. This file is
//! listed in scripts/allowlist-arcswap-store.txt as the one designated
//! publisher, so its .store( call must not fire single-snapshot-publish.
use arc_swap::ArcSwap;
use std::sync::Arc;

/// Holds the current route snapshot behind a lock-free swap.
pub struct Holder {
    table: ArcSwap<u8>,
}

impl Holder {
    /// Publishes a new snapshot. This is the single call site the
    /// single-snapshot-publish rule exists to keep unique.
    pub fn publish(&self, next: Arc<u8>) {
        self.table.store(next);
    }
}
RS

# A crate manifest that correctly inherits the workspace: [lints] workspace
# = true, and edition/version spelled as .workspace = true rather than
# hardcoded. crate-inherits-workspace (#452) must not fire on this.
cat > "$B/crates/irontraffic-router/Cargo.toml" <<'TOML'
[package]
name = "irontraffic-router"
version.workspace = true
edition.workspace = true

[lints]
workspace = true

[dependencies]
TOML

# A cargo-fuzz crate. It sits at crates/<name>/fuzz/Cargo.toml and carries its
# OWN empty [workspace] table, which is exactly how cargo-fuzz excludes it from
# the parent workspace. Being a workspace root, it has nothing to inherit FROM
# and `.workspace = true` would not parse, so crate-inherits-workspace must skip
# it entirely.
#
# This fixture exists because the rule DID fire on one. Its selector is
# `git ls-files -- 'crates/*/Cargo.toml'`, and git pathspec globbing lets `*`
# cross a slash, so the pattern reached one directory deeper than it was written
# for. The fix filters on the [workspace] declaration rather than on directory
# depth, so it also covers any future nested workspace and cannot be defeated by
# moving a crate a level down.
mkdir -p "$B/crates/irontraffic-router/fuzz"
cat > "$B/crates/irontraffic-router/fuzz/Cargo.toml" <<'TOML'
[package]
name = "irontraffic-router-fuzz"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[dependencies]
libfuzzer-sys = "0.4"
TOML

# The NOT-line-oriented forms added under #453/#456, each written the way
# rustfmt actually produces them (or the way legitimate code uses the
# construct), proving none of the fixes above turned into new false
# positives on real, correct code.
cat > "$B/crates/irontraffic-router/src/multiline_ok.rs" <<'RS'
//! The correct, rustfmt-produced shape of every construct
//! crates/irontraffic-router/src/multiline_bad.rs in the bad corpus
//! violates, proving the fixes do not false-positive on legitimate code.
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use arc_swap::ArcSwap;

/// A multi-line #[allow(...)] IS how rustfmt renders a long lint path plus
/// a real reason once the attribute exceeds roughly 70 characters. The
/// reason is present, just not on the attribute's own first line.
#[allow(
    clippy::too_many_arguments,
    reason = "one cohesive dispatch loop that threads every per-connection parameter through by design"
)]
pub fn many_lints_with_reason(
    a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8, i: u8,
) -> u8 {
    a + b + c + d + e + f + g + h + i
}

/// A wrapped assert!(matches!(...)) whose second argument is a REAL pattern,
/// not `_`: this can fail, so it is not vacuous, and must not be flagged
/// merely for having wrapped onto multiple lines.
pub fn check_shape(some_moderately_long_expression_result_value_here: Option<u8>) {
    assert!(matches!(
        some_moderately_long_expression_result_value_here,
        Some(_)
    ));
}

/// A wrapped fetch_add(TYPE::MAX, ...) decrement that DOES release through
/// Drop in this same file: balance-drop-only must not fire just because the
/// call's arguments wrapped onto their own lines.
pub struct Permits {
    count: AtomicU32,
}
impl Permits {
    pub fn acquire(&self) {
        self.count.fetch_add(
            1,
            Ordering::Relaxed,
        );
    }
}
impl Drop for Permits {
    fn drop(&mut self) {
        self.count.fetch_add(u32::MAX, Ordering::Relaxed);
    }
}

/// False-positive guard: mem::swap is a free function, never a method call,
/// and must not be mistaken for an ArcSwap publish.
pub fn uses_mem_swap(a: &mut u64, b: &mut u64) {
    std::mem::swap(a, b);
}

/// False-positive guard: slice::swap always takes two plain index
/// arguments, never one, so it must not be mistaken for ArcSwap::swap.
pub fn uses_slice_swap(v: &mut [u64]) {
    v.swap(0, 1);
}

/// False-positive guard: a plain atomic integer's swap always takes an
/// Ordering as its second argument (the very call PR #449 substituted for a
/// store precisely because this rule, before this fix, banned .store(
/// outright with no way to spell a plain atomic swap either); it must not
/// be mistaken for ArcSwap::swap, which takes exactly one argument.
pub struct Counter {
    value: AtomicU64,
}
impl Counter {
    pub fn set(&self, v: u64) -> u64 {
        self.value.swap(v, Ordering::Relaxed)
    }
}

/// False-positive guard: the deprecated atomic compare_and_swap always
/// takes three arguments (current, new, Ordering), never two, so it must
/// not be mistaken for ArcSwap::compare_and_swap.
pub fn uses_atomic_cas(a: &AtomicU64) -> u64 {
    a.compare_and_swap(0, 1, Ordering::Relaxed)
}

/// False-positive guard: binding a brand new ArcSwap with `let` is ordinary
/// construction, not a republish of an existing place.
pub fn build_fresh() -> ArcSwap<u64> {
    let fresh = ArcSwap::from_pointee(0);
    fresh
}
RS

# no-guarded-alias's two multi-line forms, applied to names that are NOT
# guarded, proving the new statement-span scan does not turn "this name
# appears somewhere in a wrapped pub-use or type alias" into a false
# positive on an ordinary one.
cat > "$B/crates/irontraffic-router/src/guarded_alias_multiline_ok.rs" <<'RS'
//! Wrapped multi-line pub-use and type-alias statements naming NOTHING
//! guarded, proving the new statement-span scan is not simply "any name in
//! a wrapped statement".
pub use inner::{
    AndOneMoreForGoodMeasureToForceWrap, Helper, NotGuardedEither, OtherThing, YetAnotherThing,
};

pub type AliasedRegistryWithAVeryLongNameIndeedToPushThisOverTheEdgeOfMaxWidth =
    std::collections::HashMap<SomeVeryLongGenericParameterNameToForceARustfmtWrapHereOk, u8>;

mod inner {
    pub struct Helper;
    pub struct OtherThing;
    pub struct YetAnotherThing;
    pub struct AndOneMoreForGoodMeasureToForceWrap;
    pub struct NotGuardedEither;
}
RS

# An attribute between #[test] and fn on a test that DOES assert, proving
# such a test is now correctly recognized as passing (not merely "not
# flagged"), matching what test-census.sh must also now count.
cat > "$B/crates/irontraffic-router/src/attributed_test_ok.rs" <<'RS'
//! An attribute between #[test] and fn on a test that genuinely asserts.
#[cfg(test)]
mod tests {
    #[test]
    #[allow(clippy::assertions_on_constants, reason = "tests a documented constant")]
    fn attributed_and_asserting() {
        assert_eq!(1 + 1, 2);
    }
}
RS

# The exact #286 brace-in-literal shapes, each WITH a genuine assertion:
# proves each of the four forms is counted correctly rather than read as an
# empty body from a decoy brace.
cat > "$B/crates/irontraffic-router/src/literal_braces_ok.rs" <<'RS'
//! The four #286 brace-in-literal shapes, each with a real assertion.
use proptest::prelude::*;

fn intern(s: &str) -> String {
    s.to_string()
}

proptest! {
    #[test]
    fn regex_repetition_present(s in "[a-z][a-z0-9-]{0,20}") {
        let interned = intern(&s);
        assert_eq!(interned, s);
    }

    #[test]
    fn unicode_escape_present(c in prop_oneof![Just('\u{e9}'), Just('\u{65e5}')]) {
        assert!(c == '\u{e9}' || c == '\u{65e5}');
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn raw_string_present() {
        let pattern = r"{not a real brace} { still not }";
        assert_eq!(pattern.len(), 33);
    }

    #[test]
    fn comment_present() {
        // a stray brace in a comment: { should not affect depth counting
        assert_eq!(1 + 1, 2);
    }
}
RS

# A legitimate reader, confined to the allowlist, proving framing-fields-confined
# does not false-positive on the one file this whole rule exists to permit.
mkdir -p "$B/crates/irontraffic-http/src"
cat > "$B/crates/irontraffic-http/src/framing.rs" <<'RS'
//! The one legitimate reader: framing.rs is on the framing-fields-confined
//! allowlist.
use crate::known::KnownHeader;

/// Confined to the allowlist; must not trip framing-fields-confined.
pub fn is_transfer_encoding(k: KnownHeader) -> bool {
    k == KnownHeader::TransferEncoding
}
RS

mkdir -p "$B/scripts"
cat > "$B/scripts/allowlist-arcswap-store.txt" <<'TXT'
# Corpus-only allowlist: the one designated ArcSwap publisher in this
# synthetic clean tree.
crates/irontraffic-router/src/holder.rs
TXT

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

# ---------------------------------------------------------------------------
# Corpus E/F: the same escape-hatch proof, repeated for transport-seam rather
# than trusting that drop_escaped's generic behaviour, proven above only for
# no-panic, generalises to every rule that calls it.
# ---------------------------------------------------------------------------
E="$WORK/escape-transport"
mkdir -p "$E/crates/irontraffic-router/src"
cp "$B/Cargo.toml" "$E/Cargo.toml"
cat > "$E/crates/irontraffic-router/src/lib.rs" <<'RS'
//! Uses the escape hatch correctly for transport-seam.
/// Returns a handle to the current tokio runtime.
#[must_use]
pub fn handle() -> tokio::runtime::Handle { tokio::runtime::Handle::current() } // it-allow: transport-seam reason: this is the seam crate
RS
echo "== corpus E: a justified transport-seam escape suppresses the rule =="
if fired_rules "$E" | grep -q '^transport-seam$'; then
  echo "FAIL: a justified transport-seam escape did not suppress its rule."
  run_lints_in "$E" | sed 's/^/    /'
  FAILED=1
else
  note "justified transport-seam escape suppresses"
fi

# Same file, marker stripped of its reason. The rule MUST fire again.
sed -i.bak 's| reason: this is the seam crate||' "$E/crates/irontraffic-router/src/lib.rs"
rm -f "$E/crates/irontraffic-router/src/lib.rs.bak"
rm -rf "$E/.git"
echo "== corpus F: a bare transport-seam marker with no reason must NOT suppress =="
if fired_rules "$E" | grep -q '^transport-seam$'; then
  note "bare transport-seam marker does not suppress"
else
  echo "FAIL: a bare transport-seam escape marker with no written reason suppressed the rule."
  echo "      The escape hatch would then be a silent off switch."
  FAILED=1
fi

# ---------------------------------------------------------------------------
# Corpus G: untracked-source (issue #513). Proven in both directions, per the
# standing rule that an untested rule is a rule nobody knows works: a fully
# staged tree passes, a file .gitignore already excludes still does not trip
# it even though it commits a real violation, and a genuine untracked .rs
# file does trip it and is named in the failure. One directory, mutated in
# sequence, the same progressive-fixture style corpus C/D and E/F above use.
# ---------------------------------------------------------------------------
G="$WORK/untracked"
mkdir -p "$G/crates/irontraffic-router/src"
cat > "$G/crates/irontraffic-router/src/lib.rs" <<'RS'
//! A clean, tracked baseline for the untracked-source corpus.
/// Adds two numbers.
#[must_use]
pub fn add(a: u8, b: u8) -> u8 { a + b }
RS
cat > "$G/Cargo.toml" <<'TOML'
[workspace.dependencies]
# serde: baseline dependency for this corpus; no rule scans this file.
serde = "1"
TOML
cat > "$G/.gitignore" <<'TXT'
ignored.rs
TXT
( cd "$G" && git init -q . && git config user.email t@t && git config user.name t \
    && git add -A >/dev/null && git commit -qm baseline >/dev/null )

echo "== corpus G, stage 1: a fully staged tree must not trip untracked-source =="
if fired_rules_raw "$G" | grep -q '^untracked-source$'; then
  echo "FAIL: untracked-source fired on a fully staged tree with nothing untracked."
  run_lints_raw "$G" | sed 's/^/    /'
  FAILED=1
else
  note "fully staged tree does not trip untracked-source"
fi

# A file .gitignore already excludes, committing a real violation (todo!())
# to prove the point precisely: even a genuine defect in an ignored file must
# stay invisible, matching the accepted design that a build artifact or an
# editor swap file is never scanned by anything in this file.
cat > "$G/crates/irontraffic-router/src/ignored.rs" <<'RS'
//! Excluded by .gitignore; even a real violation here must not surface,
//! the same way a build artifact or an editor swap file never does.
pub fn stub() { todo!() }
RS
echo "== corpus G, stage 2: a .gitignore-excluded file must not trip untracked-source =="
if fired_rules_raw "$G" | grep -q '^untracked-source$'; then
  echo "FAIL: untracked-source fired on a file .gitignore already excludes."
  run_lints_raw "$G" | sed 's/^/    /'
  FAILED=1
else
  note "gitignored file does not trip untracked-source"
fi

# A genuinely untracked, non-ignored .rs file, added on top of the state
# above without staging it.
cat > "$G/crates/irontraffic-router/src/new_untracked.rs" <<'RS'
//! Untracked on purpose: never `git add`ed in this corpus step.
/// Doubles a value.
#[must_use]
pub fn double(a: u8) -> u8 { a * 2 }
RS
echo "== corpus G, stage 3: an untracked .rs file must trip untracked-source and be named =="
OUT_G="$(run_lints_raw "$G")"
if printf '%s\n' "$OUT_G" | grep -q '^FAIL \[untracked-source\]$' \
    && printf '%s\n' "$OUT_G" | grep -qF 'crates/irontraffic-router/src/new_untracked.rs'; then
  note "untracked .rs file trips untracked-source and is named in the output"
else
  echo "FAIL: an untracked .rs file did not trip untracked-source, or did not name it. Got:"
  printf '%s\n' "$OUT_G" | sed 's/^/    /'
  FAILED=1
fi
# The ignored file must never be named as an offender, even in a run that
# does fail for the unrelated untracked file: naming it would mean the scope
# guard is not actually filtering by .gitignore.
if printf '%s\n' "$OUT_G" | grep -qF 'ignored.rs: untracked'; then
  echo "FAIL: the gitignored file was named as an untracked-source offender."
  FAILED=1
else
  note "the gitignored file is never named, even in a failing run"
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "invariant-lints-selftest: FAILED. The lint script no longer enforces what it claims."
  exit 1
fi
echo "invariant-lints-selftest: clean"
