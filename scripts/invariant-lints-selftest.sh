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

# One deliberate hot-path allocation per line, one line per call spelling the
# hot-path-allocation rule claims to cover.
#
# WHY THIS FILE EXISTS (issue #539). Corpus A above only proves that the RULE
# fired somewhere in the corpus, which is satisfied by a single `format!` and
# says nothing about the other thirty-odd spellings in the token list. That is
# exactly how the list shipped for months without `to_lowercase`,
# `String::with_capacity` or `push_str` in it: a reviewer proved by injection
# that `raw.to_lowercase()` in a `//! HOT PATH` module left the gate CLEAN,
# while `raw.to_owned()` correctly failed it. The stage below asserts that the
# rule reports EVERY line in this file, by line, so a token can never again be
# added to the rule and quietly match nothing.
#
# Each binding is named `tok_<spelling>` so the assertion can key on a string
# that appears nowhere else, in particular nowhere in the rule's own explain
# text, which names several of these calls in prose and would otherwise make
# the assertion pass vacuously.
cat > "$A/crates/irontraffic-router/src/hot_alloc.rs" <<'RS'
//! HOT PATH
//! Deliberately allocates once per line, one call spelling per line.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, LinkedList, VecDeque};
use std::rc::Rc;
use std::sync::Arc;

/// Every statement in here is a deliberate violation.
pub fn allocates(n: usize, raw: &str, parts: &[&str], cow: Cow<'_, str>) -> usize {
    let tok_format = format!("{n}");
    let tok_to_string = n.to_string();
    let tok_to_owned = raw.to_owned();
    let tok_into_owned = cow.into_owned();
    let tok_to_vec = raw.as_bytes().to_vec();
    let tok_vec_macro = vec![0u8; 4];
    let tok_vec_new: Vec<u8> = Vec::new();
    let tok_string_new = String::new();
    let tok_hash_map_new: HashMap<u8, u8> = HashMap::new();
    let tok_hash_set_new: HashSet<u8> = HashSet::new();
    let tok_btree_map_new: BTreeMap<u8, u8> = BTreeMap::new();
    let tok_btree_set_new: BTreeSet<u8> = BTreeSet::new();
    let tok_vec_deque_new: VecDeque<u8> = VecDeque::new();
    let tok_binary_heap_new: BinaryHeap<u8> = BinaryHeap::new();
    let tok_linked_list_new: LinkedList<u8> = LinkedList::new();
    let tok_string_with_capacity = String::with_capacity(n);
    let tok_turbofish_with_capacity = Vec::<u8>::with_capacity(n);
    let tok_string_from = String::from(raw);
    let tok_vec_from = Vec::from(raw.as_bytes());
    let tok_box_from: Box<str> = Box::from(raw);
    // Turbofish evasion (issue #610): a type parameter written explicitly
    // between the type name and `::` used to remove the `Type::` prefix
    // these rules require, so `Vec::<u8>::new()` and `Box::<str>::from(raw)`
    // matched nothing even though `Vec::new()` and `Box::from(raw)` did.
    let tok_turbofish_from: Box<str> = Box::<str>::from(raw);
    let tok_box_new = Box::new(n);
    let tok_arc_new = Arc::new(n);
    let tok_rc_new = Rc::new(n);
    let tok_turbofish_new: Vec<u8> = Vec::<u8>::new();
    let tok_box_pin = Box::pin(n);
    let tok_collect_turbofish = raw.bytes().collect::<Vec<u8>>();
    let tok_collect_bare: Vec<u8> = raw.bytes().collect();
    let tok_clone = tok_string_new.clone();
    let tok_to_lowercase = raw.to_lowercase();
    let tok_to_uppercase = raw.to_uppercase();
    let mut tok_push_str = tok_string_from;
    tok_push_str.push_str(raw);
    let tok_repeat = raw.repeat(2);
    let tok_join = parts.join(".");
    // Wrapped by rustfmt so the separator is not on the same line as the
    // call: the rule must still see it, which is why the separator test
    // accepts end of line as well as a non-`)` character.
    let tok_join_wrapped = parts.join(
        ".",
    );
    let tok_into_boxed_slice = tok_vec_from.into_boxed_slice();
    let tok_into_boxed_str = tok_push_str.into_boxed_str();
    n + tok_into_boxed_slice.len() + tok_into_boxed_str.len()
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

# Deliberately reproduces issue #628's two failure modes plus the third real
# instance found on `main` itself, all in build_prod_tree's #[cfg(test)]
# detection: each file's unwrap() must be visible to no-panic once the fix
# stops build_prod_tree from assuming the attribute always introduces a
# `mod { ... }` body and from matching the attribute inside prose.

# Failure mode 1: a #[cfg(test)]-gated struct field (ends in `,`, not `{`)
# immediately followed by a real function with a genuine unwrap(). The old
# build_prod_tree searched forward past the field for the next real `{` (this
# function's own opening brace) and blanked the function's entire body,
# hiding the unwrap() from no-panic.
cat > "$A/crates/irontraffic-router/src/cfg_test_field_bad.rs" <<'RS'
//! Deliberately reproduces issue #628 failure mode 1: a #[cfg(test)]-gated
//! struct field, ended by `,` rather than `{`.
pub struct ScanState {
    #[cfg(test)]
    scan_steps: std::cell::Cell<u64>,
}

/// Not test-only: always compiled. The unwrap() here must be visible to
/// no-panic once build_prod_tree confines the field attribute's blanking to
/// just the field.
pub fn parse_len(s: &str) -> usize {
    s.parse::<usize>().unwrap()
}
RS

# Failure mode 2: a doc comment that merely MENTIONS `#[cfg(test)]` in prose
# (the same way irontraffic-router/src/intern.rs's real comment does),
# immediately followed by a real function with a genuine unwrap(). The old
# trivia-blind regex matched the prose exactly like a real attribute and
# blanked forward to the next real `{`: this function's own opening brace.
cat > "$A/crates/irontraffic-router/src/cfg_test_prose_bad.rs" <<'RS'
//! Deliberately reproduces issue #628 failure mode 2: prose that mentions
//! the attribute without being it.
///
/// This helper's counting is enabled only under `#[cfg(test)]`; the text
/// `#[cfg(test)]` appears here purely as prose describing that fact, not as
/// a real attribute.
pub fn compute_len(s: &str) -> usize {
    s.parse::<usize>().unwrap()
}
RS

# The third real instance measured on `main` itself while diagnosing #628: a
# genuine #[cfg(test)] on a body-less `mod name;` file declaration (ends in
# `;`, not `{`), the exact shape of irontraffic-router/src/lib.rs's real
# `#[cfg(test)] pub mod testutil;`. The old build_prod_tree searched forward
# past the semicolon for the next real `{` and blanked everything up to and
# including it: the unrelated `pub mod real_thing;` declaration and this
# always-compiled function's unwrap().
cat > "$A/crates/irontraffic-router/src/cfg_test_modsemi_bad.rs" <<'RS'
//! Deliberately reproduces the third real #628 instance found on `main`:
//! #[cfg(test)] on a body-less `mod name;` declaration.
#[cfg(test)]
pub mod test_only_helpers;
pub mod real_thing;

/// Always compiled. The unwrap() here must be visible to no-panic.
pub fn compute_thing(s: &str) -> usize {
    s.parse::<usize>().unwrap()
}
RS

# The other failure-mode-1 shape the GH issue's acceptance criteria name
# explicitly, alongside a struct field: a #[cfg(test)] on a STRUCT-LITERAL
# field entry (inside an expression, not a struct definition), immediately
# followed by a real function with a genuine panic!().
cat > "$A/crates/irontraffic-router/src/cfg_test_struct_literal_bad.rs" <<'RS'
//! Deliberately reproduces the struct-LITERAL-field-entry shape issue #628's
//! acceptance criteria name alongside a struct definition field.
pub struct SomeConfig {
    pub retries: u8,
    pub timeout: u8,
}

/// Builds a config with a test-only field override.
pub fn build() -> SomeConfig {
    SomeConfig {
        #[cfg(test)]
        retries: 3,
        timeout: 10,
    }
}

/// Always compiled. The panic!() here must be visible to no-panic.
pub fn triggers_panic(n: u8) -> u8 {
    if n == 0 {
        panic!("n must not be zero")
    }
    n
}
RS

# ---------------------------------------------------------------------------
# bench-registration (issue #630): deliberately defines a criterion benchmark
# that no criterion_group! in this file registers, registers one this file
# does not define, and defines a second criterion_group! that this file's
# criterion_main! never names, exercising all three failure shapes a merge of
# two issues appending to one shared bench file (or a hand-edited
# criterion_main! group list) produces. Every one of these is valid Rust: it
# compiles, passes clippy, and passes every test, which is exactly why nothing
# else in the pipeline can see it.
# ---------------------------------------------------------------------------
mkdir -p "$A/crates/irontraffic-http/benches"
cat > "$A/crates/irontraffic-http/benches/rogue_bench.rs" <<'RS'
//! Deliberately violates bench-registration in all three directions.
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_registered(c: &mut Criterion) {
    c.bench_function("registered", |b| b.iter(|| 1 + 1));
}

fn bench_never_registered(c: &mut Criterion) {
    c.bench_function("dropped", |b| b.iter(|| 2 + 2));
}

fn bench_orphan_group(c: &mut Criterion) {
    c.bench_function("orphan", |b| b.iter(|| 3 + 3));
}

criterion_group!(benches, bench_registered, bench_moved_to_another_file);
criterion_group!(orphan_group, bench_orphan_group);
criterion_main!(benches);
RS

# ---------------------------------------------------------------------------
# no-accumulated-sleep (issue #406): a relative sleep in the harness path,
# exactly the accumulating-drift construct the rule exists to ban. Placed
# under crates/irontraffic-bench/src, which is in scope (unlike benches/,
# tests/ or examples/, which scan_prod never sees at all).
# ---------------------------------------------------------------------------
mkdir -p "$A/crates/irontraffic-bench/src"
cat > "$A/crates/irontraffic-bench/src/rogue_pace.rs" <<'RS'
//! Deliberately violates no-accumulated-sleep: a relative sleep in a pacing
//! loop, which overshoots on every call and accumulates without bound.
use std::time::Duration;

/// Paces requests with a relative sleep instead of an absolute deadline.
pub async fn bad_pace(interval: Duration) {
    tokio::time::sleep(interval).await;
}
RS

# ---------------------------------------------------------------------------
# hkdf-zeroize-not-fill (review of PR 839): the two banned shapes, a plain
# .fill(0) call and a bare `= [0u8; N]` reassignment, on the two local names
# (`full`, `t`) the real crates/irontraffic-tls/src/hkdf.rs wipes with a real
# zeroize::Zeroize call. This is the exact regression a disassembly-level
# review reconstructed from the pre-fix tree: it compiled, passed every test,
# and emitted no wipe instructions at all.
# ---------------------------------------------------------------------------
mkdir -p "$A/crates/irontraffic-tls/src"
cat > "$A/crates/irontraffic-tls/src/hkdf.rs" <<'RS'
//! Deliberately violates hkdf-zeroize-not-fill: reverts both HMAC output
//! wipes to a plain, non-volatile store the compiler is free to remove
//! instead of a real zeroize::Zeroize call.
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha384;

/// The `.fill(0)` shape: exactly the regression a real review caught by
/// disassembly, which emitted zero wipe instructions in release object code.
pub(crate) fn extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let Ok(mut mac) = Hmac::<Sha384>::new_from_slice(salt) else {
        return [0u8; 48];
    };
    mac.update(ikm);
    let mut full = mac.finalize().into_bytes();
    let mut prk = [0u8; 48];
    if let Some(head) = full.get(..48) {
        prk.copy_from_slice(head);
    }
    full.fill(0);
    prk
}

/// The other banned shape: reassigning the buffer to a fresh zero array
/// instead of calling fill or zeroize. Just as non-volatile, and just as
/// dead the moment the compiler can see nothing reads `t` again.
pub(crate) fn expand_sha384(prk: &[u8; 48], info: &[u8]) -> [u8; 32] {
    let Ok(mut mac) = Hmac::<Sha384>::new_from_slice(prk) else {
        return [0u8; 32];
    };
    mac.update(info);
    let mut t = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    if let Some(head) = t.get(..32) {
        out.copy_from_slice(head);
    }
    t = [0u8; 48];
    out
}
RS

printf '[workspace.dependencies]\nserde = "1"\n' > "$A/Cargo.toml"

EXPECTED='allow-needs-reason
balance-drop-only
bench-registration
constant-time-secrets
core-ctx-not-stored
crate-inherits-workspace
determinism-seam
dependency-justification
framing-fields-confined
hkdf-zeroize-not-fill
hot-path-allocation
hot-path-lock
interior-mutability
no-accumulated-sleep
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
# Captured ONCE: run_lints_in commits whatever is new in $A and then runs the
# real script, so a second call on the same tree with nothing left to commit
# would fail its own `git commit` step and silently return empty output. The
# rule-name set below (ACTUAL), the specific file:line check further down
# (issue #641), and the hot-path-allocation per-spelling check further down
# still (issue #539) all read this same capture rather than re-running the
# corpus.
RAW_A="$(run_lints_in "$A")"
ACTUAL="$(printf '%s\n' "$RAW_A" | sed -n 's/^FAIL \[\(.*\)\]$/\1/p' | LC_ALL=C sort -u)"
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
# issue #641: the SET-OF-RULE-NAMES check above is blind to whether the four
# #628 regression files below are actually reaching no-panic, because
# `no-panic` is ALREADY in EXPECTED from the unrelated bad.rs file in this
# same corpus: reverting build_prod_tree's entire #628 fix (item_extent back
# to "search forward for the next real `{`") still leaves `no-panic` in
# ACTUAL, so MISSING stays empty and this whole check reports success on a
# gate that no longer does what it claims. Grep the RAW per-line output
# instead, for the specific file:line hits each of the four regression files
# is known to produce once build_prod_tree correctly confines a
# `#[cfg(test)]` attribute's blanking to just the attributed item, rather
# than the set of rule NAMES that fired.
#
# The four lines below are the genuine violation lines in each file, verified
# by running the corpus directly (not transcribed by hand): a doc comment on
# an EARLIER line in three of the four files also mentions the word
# `unwrap()`/`panic!()` in prose, but `.unwrap()`/`.expect(` require a
# literal preceding dot that comment prose does not have, so only the real
# code line actually fires for those three. `panic!(` has no such anchor, so
# cfg_test_struct_literal_bad.rs's doc comment on line 17 fires too (it
# literally contains the word `panic!(`), alongside the real `panic!()` call
# on line 20; line 17 is used below since it is sufficient on its own to
# prove this file's content is visible.
# ---------------------------------------------------------------------------
echo "== corpus A: the four #628 regression files must be individually visible to no-panic =="
NEEDED_LINES=(
  "crates/irontraffic-router/src/cfg_test_field_bad.rs:12:"
  "crates/irontraffic-router/src/cfg_test_prose_bad.rs:8:"
  "crates/irontraffic-router/src/cfg_test_modsemi_bad.rs:9:"
  "crates/irontraffic-router/src/cfg_test_struct_literal_bad.rs:17:"
)
MISSING_LINES=""
for needle in "${NEEDED_LINES[@]}"; do
  printf '%s\n' "$RAW_A" | grep -qF "$needle" || MISSING_LINES="$MISSING_LINES$needle
"
done
if [ -n "$MISSING_LINES" ]; then
  echo "FAIL: corpus A's raw output is missing these expected no-panic hits."
  echo "      The set-of-rule-names check above cannot tell these four #628"
  echo "      regression files apart from the unrelated no-panic hit already"
  echo "      firing on bad.rs in this same corpus (issue #641); a full"
  echo "      revert of the item_extent fix leaves it green anyway. Missing:"
  printf '%s' "$MISSING_LINES" | sed 's/^/    /'
  FAILED=1
else
  note "all four #628 regression files are individually visible to no-panic"
fi

# ---------------------------------------------------------------------------
# issue #673 (independent review of PR 636): the SET-OF-RULE-NAMES check above
# is just as blind here as it is for no-panic above, and in a way that matters
# more, because rogue_bench.rs carries three INDEPENDENT bench-registration
# violations (a dropped fn-level registration, a stale fn-level registration,
# and a criterion_group! never named by criterion_main!). A regression that
# silently disables only the THIRD check (the one #673 found missing entirely)
# would still leave `bench-registration` in ACTUAL, because the first two
# violations still fire on their own, so the coarse rule-name check would
# report success on a gate that no longer guards the criterion_main! link at
# all. Grep the RAW per-line output for each violation's specific file:line,
# verified by running the corpus directly (not transcribed by hand), so each
# of the three failure shapes is individually proven to still be visible.
# ---------------------------------------------------------------------------
echo "== corpus A: all three bench-registration violations must be individually visible =="
NEEDED_BENCH_LINES=(
  "crates/irontraffic-http/benches/rogue_bench.rs:8:"
  "crates/irontraffic-http/benches/rogue_bench.rs:16:"
  "crates/irontraffic-http/benches/rogue_bench.rs:17:"
)
MISSING_BENCH_LINES=""
for needle in "${NEEDED_BENCH_LINES[@]}"; do
  printf '%s\n' "$RAW_A" | grep -qF "$needle" || MISSING_BENCH_LINES="$MISSING_BENCH_LINES$needle
"
done
if [ -n "$MISSING_BENCH_LINES" ]; then
  echo "FAIL: corpus A's raw output is missing these expected bench-registration hits."
  echo "      The set-of-rule-names check above cannot tell a regression in one"
  echo "      of the three checks (dropped fn registration, stale fn"
  echo "      registration, criterion_group! not named by criterion_main!) apart"
  echo "      from the other two still firing in this same file. Missing:"
  printf '%s' "$MISSING_BENCH_LINES" | sed 's/^/    /'
  FAILED=1
else
  note "all three bench-registration violations (dropped fn, stale fn, ungoverned group) are individually visible"
fi

# ---------------------------------------------------------------------------
# Corpus A, per call spelling: hot-path-allocation must name EVERY covered
# call, by line.
#
# WHY THIS IS NOT REDUNDANT WITH THE CHECK ABOVE (issue #539). The check above
# asks only whether the rule fired anywhere in corpus A, which one `format!`
# satisfies. hot-path-allocation is a deny list of more than thirty call
# spellings, and a deny list is only worth the entries that actually match: a
# token added to the pattern with a typo, an unescaped metacharacter, or an
# alternation the shell mangled matches nothing and costs nothing to nobody,
# forever, while this file keeps reporting that the rule fired. That is
# precisely how `to_lowercase`, `String::with_capacity` and `push_str` came to
# be absent from a rule whose own documentation said it caught every call that
# can allocate.
#
# So every spelling gets its own line in hot_alloc.rs and its own needle here.
# Add a token to the rule, add its needle here, and watch it fail before you
# trust it. The hits are filtered to lines naming hot_alloc.rs first, because
# the rule's explain text discusses several of these calls in prose and a
# needle matching that prose would pass while matching no source line at all.
# ---------------------------------------------------------------------------
echo "== corpus A: hot-path-allocation must report every covered call by line =="
ALLOC_HITS="$(printf '%s\n' "$RAW_A" \
  | awk '/^FAIL \[hot-path-allocation\]$/ { on = 1; next } /^FAIL \[/ { on = 0 } on' \
  | grep -F 'crates/irontraffic-router/src/hot_alloc.rs:' || true)"
MISSED_SPELLINGS=""
while IFS= read -r needle; do
  [ -n "$needle" ] || continue
  printf '%s\n' "$ALLOC_HITS" | grep -qF -- "$needle" \
    || MISSED_SPELLINGS="$MISSED_SPELLINGS  $needle"$'\n'
done <<'NEEDLES'
tok_format = format!(
tok_to_string = n.to_string()
tok_to_owned = raw.to_owned()
tok_into_owned = cow.into_owned()
tok_to_vec = raw.as_bytes().to_vec()
tok_vec_macro = vec![
tok_vec_new: Vec<u8> = Vec::new()
tok_string_new = String::new()
tok_hash_map_new: HashMap<u8, u8> = HashMap::new()
tok_hash_set_new: HashSet<u8> = HashSet::new()
tok_btree_map_new: BTreeMap<u8, u8> = BTreeMap::new()
tok_btree_set_new: BTreeSet<u8> = BTreeSet::new()
tok_vec_deque_new: VecDeque<u8> = VecDeque::new()
tok_binary_heap_new: BinaryHeap<u8> = BinaryHeap::new()
tok_linked_list_new: LinkedList<u8> = LinkedList::new()
tok_string_with_capacity = String::with_capacity(
tok_turbofish_with_capacity = Vec::<u8>::with_capacity(
tok_string_from = String::from(
tok_vec_from = Vec::from(
tok_box_from: Box<str> = Box::from(
tok_turbofish_from: Box<str> = Box::<str>::from(
tok_box_new = Box::new(
tok_arc_new = Arc::new(
tok_rc_new = Rc::new(
tok_turbofish_new: Vec<u8> = Vec::<u8>::new(
tok_box_pin = Box::pin(
tok_collect_turbofish = raw.bytes().collect::<Vec<u8>>()
tok_collect_bare: Vec<u8> = raw.bytes().collect()
tok_clone = tok_string_new.clone()
tok_to_lowercase = raw.to_lowercase()
tok_to_uppercase = raw.to_uppercase()
tok_push_str.push_str(
tok_repeat = raw.repeat(
tok_join = parts.join(
tok_join_wrapped = parts.join(
tok_into_boxed_slice = tok_vec_from.into_boxed_slice()
tok_into_boxed_str = tok_push_str.into_boxed_str()
NEEDLES
if [ -n "$MISSED_SPELLINGS" ]; then
  echo "FAIL: hot-path-allocation did not report these deliberate allocations:"
  printf '%s' "$MISSED_SPELLINGS"
  echo "      Each one is a call the rule's token list claims to cover. A token"
  echo "      that matches nothing is a rule that enforces nothing."
  FAILED=1
else
  note "hot-path-allocation reported every covered call spelling"
fi

# ---------------------------------------------------------------------------
# Corpus A, the OTHER direction: the pattern must not outrun NEEDLES.
#
# WHY THIS EXISTS (issue #610). The check just above only walks NEEDLES ->
# hits: it proves every line this file claims is covered really fires, and it
# says nothing at all about a token that was added to the live pattern in
# scripts/invariant-lints.sh with no needle here to match it. That is not a
# hypothetical gap, it is a proven one: appending a brand new top-level
# alternative to the end of the hot-path-allocation pattern, with nothing
# added to NEEDLES, left this whole script exiting 0 and printing "hot-path-
# allocation reported every covered call spelling" for every one of these:
#   - `|\.to_lowercasee\(\)`      (a typo)
#   - `|\.to_pathbuf\(\)`         (a real call, just never added as a needle)
#   - `|\.into_bytes\(\)`         (same)
# The needles-to-hits check above cannot see any of these, because it never
# reads the pattern; it only reads what the rule reported. The one case it
# happens to catch, an unbalanced group, is caught for the wrong reason: an
# invalid ERE makes grep reject the whole pattern, so every PRE-EXISTING hit
# vanishes at once, which trips the needles-to-hits check on tokens that were
# already there, not because the new token itself was noticed.
#
# THE CHECK. Extract the live hot-path-allocation pattern from scripts/
# invariant-lints.sh and count its top-level `|` alternatives: an alternation
# nested inside a group, such as the type list on the `::new\(` line
# (`(Vec|String|...)`), is ONE top-level alternative, not many, because
# touching only the type list is a separate, narrower change this check does
# not claim to police (see the limits below). Compare that count to the
# number pinned immediately below, right beside NEEDLES. Add, remove, or
# otherwise change a top-level alternative in the pattern without updating
# both this number and the matching NEEDLES line(s), in either direction, and
# this fails here.
#
# WHAT THIS STILL DOES NOT PROVE, STATED HONESTLY. Two independent edits can
# cancel out and still leave the counts agreeing (add one alternative, remove
# a different one, forget both needles). It also cannot see a change made
# INSIDE an existing alternative's own inner list: folding a tenth collection
# type into the `(Vec|String|HashMap|...)::new\(` group changes nothing at
# the top level and this check would not notice. It closes the specific,
# demonstrated hole (a bare token appended to the pattern with nothing else
# touched), not every hole shaped like it.
echo "== corpus A: hot-path-allocation pattern alternatives must match NEEDLES =="
# Keep this number in the same commit as any change to the top-level shape of
# hot_scan's hot-path-allocation pattern in scripts/invariant-lints.sh, and add
# or remove the matching NEEDLES line(s) at the same time.
EXPECTED_ALLOC_ALTERNATIVES=19
ACTUAL_ALLOC_ALTERNATIVES="$(python3 - <<'PY'
import re

try:
    text = open("scripts/invariant-lints.sh", encoding="utf-8").read()
except OSError:
    print("ERROR: could not read scripts/invariant-lints.sh")
    raise SystemExit(0)

m = re.search(r"hot_scan hot-path-allocation '([^']*)'", text)
if not m:
    print("ERROR: could not find the hot-path-allocation pattern")
    raise SystemExit(0)
pattern = m.group(1)


def strip_outer_group(pat):
    """If pat is wrapped in one group spanning the whole string, return its
    contents; otherwise return pat unchanged. Depth-aware and character-class
    aware, exactly like count_top_level below, so it does not mistake a `(`
    inside `[...]` for a real group, or an escaped `\\(` for one either."""
    if not (pat.startswith("(") and pat.endswith(")")):
        return pat
    depth = 0
    escaped = False
    in_class = False
    for idx, c in enumerate(pat):
        if escaped:
            escaped = False
            continue
        if c == "\\":
            escaped = True
            continue
        if in_class:
            if c == "]":
                in_class = False
            continue
        if c == "[":
            in_class = True
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and idx != len(pat) - 1:
                # Closes before the end: this is not a single wrapping group,
                # e.g. "(a)|(b)". Leave pat exactly as given.
                return pat
    return pat[1:-1]


def count_top_level_alternatives(pat):
    """Count `|` at depth 0, outside any [...] character class, and outside
    any escaped \\| or \\( or \\). An unescaped `(` opens a real group
    (depth += 1) and an unescaped `)` closes one (depth -= 1); a `|` only
    separates top-level alternatives when depth is 0. `(Vec|String)::new\\(`
    is therefore ONE alternative: its inner `|` sits at depth 1."""
    depth = 0
    escaped = False
    in_class = False
    count = 1
    for c in pat:
        if escaped:
            escaped = False
            continue
        if c == "\\":
            escaped = True
            continue
        if in_class:
            if c == "]":
                in_class = False
            continue
        if c == "[":
            in_class = True
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            count += 1
    return count


print(count_top_level_alternatives(strip_outer_group(pattern)))
PY
)"
if [ "$ACTUAL_ALLOC_ALTERNATIVES" != "$EXPECTED_ALLOC_ALTERNATIVES" ]; then
  echo "FAIL: scripts/invariant-lints.sh's hot-path-allocation pattern now has"
  echo "      $ACTUAL_ALLOC_ALTERNATIVES top-level alternatives, but this file still expects"
  echo "      $EXPECTED_ALLOC_ALTERNATIVES (EXPECTED_ALLOC_ALTERNATIVES above). A top-level"
  echo "      alternative was added to or removed from the pattern without updating"
  echo "      EXPECTED_ALLOC_ALTERNATIVES and the matching NEEDLES line(s) here."
  FAILED=1
else
  note "hot-path-allocation pattern has exactly $EXPECTED_ALLOC_ALTERNATIVES top-level alternatives, matching NEEDLES"
fi

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

# Issue #628: proving the fix does not OVER-reach. Every shape below has a
# genuine unwrap()/violation inside a genuinely test-only construct, and
# every one of them must still be blanked out of the -prod tree exactly as
# before, so none of them may fire any rule.

# A normal #[cfg(test)] mod tests { ... } containing a real unwrap(): the
# baseline shape build_prod_tree has always had to get right. Must still be
# blanked in full.
cat > "$B/crates/irontraffic-router/src/cfg_test_mod_ok.rs" <<'RS'
//! Issue #628 no-over-reach proof: a normal #[cfg(test)] mod tests { ... }
//! containing a genuine unwrap() must still be blanked in full.
/// Adds one.
#[must_use]
pub fn add_one(n: usize) -> usize {
    n + 1
}

#[cfg(test)]
mod tests {
    use super::add_one;
    #[test]
    fn adds_one() {
        assert_eq!(add_one(1).checked_add(0).unwrap(), 2);
    }
}
RS

# A #[cfg(test)]-gated helper FUNCTION (not a mod, the irontraffic-resilience
# limits/mod.rs shape found while measuring #628) whose own body contains an
# unwrap(): proves a brace-bodied `fn` is recognized the same as a
# brace-bodied `mod`, not just the literal keyword `mod`.
cat > "$B/crates/irontraffic-router/src/cfg_test_fn_ok.rs" <<'RS'
//! Issue #628 no-over-reach proof: a #[cfg(test)]-gated fn (not mod) whose
//! body contains a genuine unwrap() must still be blanked in full.
/// Tracks hits.
pub struct Counter {
    hits: std::sync::atomic::AtomicU64,
}

impl Counter {
    #[cfg(test)]
    pub(crate) fn hits_unwrapped(&self) -> u64 {
        self.hits
            .load(std::sync::atomic::Ordering::Relaxed)
            .checked_add(0)
            .unwrap()
    }
}
RS

# A #[cfg(test)]-gated thread_local! block (the irontraffic-router/src/
# intern.rs shape) whose initializer contains an unwrap(): proves a
# macro-invocation brace body is recognized too, not just `mod`/`fn`.
cat > "$B/crates/irontraffic-router/src/cfg_test_threadlocal_ok.rs" <<'RS'
//! Issue #628 no-over-reach proof: a #[cfg(test)]-gated thread_local! block
//! whose initializer contains a genuine unwrap() must still be blanked.
#[cfg(test)]
thread_local! {
    static SEEDED: std::cell::Cell<u64> =
        std::cell::Cell::new(1u64.checked_add(1).unwrap());
}

/// Always compiled, deliberately trivial.
pub fn noop() {}
RS

# The real irontraffic-router/src/lib.rs shape (#[cfg(test)] on a body-less
# `mod name;`) but with genuinely clean code around and after it: proves the
# fix's narrower blanking does not itself introduce a false positive merely
# by leaving the sibling `pub mod` declaration visible.
cat > "$B/crates/irontraffic-router/src/cfg_test_modsemi_ok.rs" <<'RS'
//! Issue #628 no-over-reach proof: #[cfg(test)] on a body-less `mod name;`
//! declaration, with clean code around it, must not fire anything.
#[cfg(test)]
pub mod test_only_helpers;
pub mod real_thing;

/// Always compiled and clean.
pub fn compute_thing(s: &str) -> Result<usize, std::num::ParseIntError> {
    s.parse::<usize>()
}
RS

# Issue #628's other named acceptance criterion: a reason = "..." string
# that merely MENTIONS the literal text #[cfg(test)] in prose must cause no
# blanking at all, so it can neither hide a real violation near it nor be
# mistaken for something that needs hiding.
cat > "$B/crates/irontraffic-router/src/cfg_test_reason_string_ok.rs" <<'RS'
//! Issue #628 acceptance criterion: a reason = "..." string mentioning the
//! literal text #[cfg(test)] must cause no blanking at all.
#[allow(dead_code, reason = "mirrors the #[cfg(test)] hazard this string only mentions, not a real attribute")]
pub fn helper() {}

/// Always compiled and clean.
#[must_use]
pub fn safe(n: u8) -> u8 {
    n.saturating_add(1)
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

# The genuine hkdf-zeroize-not-fill shape: a real zeroize::Zeroize call on
# both locals, plus a `let`-initialized zero buffer with a DIFFERENT name
# (`prk`), proving the rule does not flag ordinary zero-initialization, only
# a reassignment or .fill( on the two wipe-site locals themselves.
mkdir -p "$B/crates/irontraffic-tls/src"
cat > "$B/crates/irontraffic-tls/src/hkdf.rs" <<'RS'
//! The correct hkdf-zeroize-not-fill shape: a real zeroize::Zeroize call on
//! both HMAC output locals, must not trip the rule.
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha384;
use zeroize::Zeroize;

/// Wipes the HMAC output buffer for real.
pub(crate) fn extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let Ok(mut mac) = Hmac::<Sha384>::new_from_slice(salt) else {
        return [0u8; 48];
    };
    mac.update(ikm);
    let mut full = mac.finalize().into_bytes();
    // An ordinary `let`-initialized zero buffer under a DIFFERENT name: not
    // a reassignment of `full` or `t`, and must not trip the rule either.
    let mut prk = [0u8; 48];
    if let Some(head) = full.get(..48) {
        prk.copy_from_slice(head);
    }
    full.zeroize();
    prk
}

/// Wipes the second HMAC output buffer for real.
pub(crate) fn expand_sha384(prk: &[u8; 48], info: &[u8]) -> [u8; 32] {
    let Ok(mut mac) = Hmac::<Sha384>::new_from_slice(prk) else {
        return [0u8; 32];
    };
    mac.update(info);
    let mut t = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    if let Some(head) = t.get(..32) {
        out.copy_from_slice(head);
    }
    t.zeroize();
    out
}
RS

# Legitimate, NON-allocating hot-path code that a naive widening of the
# hot-path-allocation token list would have rejected.
#
# WHY THIS FILE EXISTS (issue #539). Widening a deny list is the easy half; not
# over-widening it is the half that costs people time. This repository already
# carries two rules that reach too far: single-snapshot-publish is broad enough
# that two implementers wrote `AtomicU32::store(&cell, ...)` in fully qualified
# form purely to route around it, and constant-time-secrets fires on any
# identifier matching token[a-z_]*\s*==. A rule people have learned to evade
# stops being a rule. Every function below is correct, allocation-free code
# that the obvious version of each newly added token would have flagged, so the
# clean-corpus check is what keeps the widened rule honest in the other
# direction.
cat > "$B/crates/irontraffic-router/src/hot_ok.rs" <<'RS'
//! HOT PATH
//! Correct, allocation-free hot-path code. Every call here is one a naive
//! version of the hot-path-allocation token list would have rejected.
use std::sync::Arc;

/// Lowercases ASCII into a buffer the caller already owns, allocating
/// nothing. This is the exact idiom `crates/irontraffic-router/src/
/// normalize.rs` uses on the real request path: on a byte receiver the ASCII
/// case conversions return a byte and touch no heap, while on a str receiver
/// the identical spelling returns an owned string. A receiver-blind text scan
/// cannot separate the two, which is why neither is in the token list.
pub fn lowercase_into(src: &[u8], buf: &mut [u8; 64]) -> usize {
    let mut written = 0usize;
    for (i, &b) in src.iter().enumerate() {
        let out = match b {
            b'A'..=b'Z' => b.to_ascii_lowercase(),
            _ => b,
        };
        if let Some(slot) = buf.get_mut(i) {
            *slot = out;
            written += 1;
        }
    }
    written
}

/// The char form of the same conversion, which also allocates nothing.
#[must_use]
pub fn upper_char(c: char) -> char {
    c.to_ascii_uppercase()
}

/// Comparing two names case-insensitively without building an owned copy of
/// either: the call a hot path should reach for, and one a rule keyed on the
/// word "lowercase" rather than on the call spelling would have flagged.
#[must_use]
pub fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Classifying a byte. Same reasoning as above.
#[must_use]
pub fn is_lower(b: u8) -> bool {
    b.is_ascii_lowercase()
}

/// Appending into a buffer the CALLER owns and has already sized: the idiom
/// the rule's own failure message recommends, which is why extend and
/// extend_from_slice are deliberately not tokens.
pub fn append(buf: &mut Vec<u8>, src: &[u8]) {
    buf.extend_from_slice(src);
}

/// Reading how much room a buffer already has is not reserving any. The token
/// for the capacity constructor is spelled as a double-colon path, so an
/// ordinary method call on a receiver cannot match it.
///
/// Note the shape of this comment: it describes the token rather than
/// quoting it. hot-path-allocation is a plain text scan with no idea what a
/// comment is, so quoting a covered call in prose inside a HOT PATH module
/// fires the rule on the documentation. This corpus hit that twice while it
/// was being written.
#[must_use]
pub fn headroom(buf: &Vec<u8>) -> usize {
    buf.capacity()
}

/// Waiting for a worker takes no separator, so it is not the allocating slice
/// join: the token requires join to receive an argument.
pub fn wait(handle: std::thread::JoinHandle<()>) -> bool {
    handle.join().is_ok()
}

/// Repeating through the free function allocates nothing and is not the
/// allocating slice method: the token requires a receiver and a dot.
pub fn filler(n: usize) -> impl Iterator<Item = u8> {
    std::iter::repeat_n(b'a', n)
}

/// Bumping a reference count is not an allocation. Constructing a fresh
/// counted pointer is a covered call; the fully qualified clone of an
/// existing one is not, and must stay legal on the request path.
#[must_use]
pub fn share(v: &Arc<u8>) -> Arc<u8> {
    Arc::clone(v)
}

/// Pinning to the stack allocates nothing, unlike the boxed form.
pub fn pin_local(v: &mut u8) -> std::pin::Pin<&mut u8> {
    std::pin::Pin::new(v)
}

/// Setting an Option in place never allocates, which is one reason insert is
/// not a token.
pub fn fill(slot: &mut Option<u8>, v: u8) -> u8 {
    *slot.insert(v)
}

/// A crate type's own constructor. The token list names the standard
/// collection types explicitly rather than matching any `::new()`, so an
/// ordinary constructor call on the request path stays legal.
pub struct Cursor {
    at: usize,
}

impl Cursor {
    /// Builds a cursor over nothing. Allocates nothing.
    #[must_use]
    pub fn new() -> Self {
        Self { at: 0 }
    }

    /// A field named for collecting is not a call to collect.
    #[must_use]
    pub fn collect_count(&self) -> usize {
        self.at
    }
}

/// Constructing a crate type is not constructing a collection.
#[must_use]
pub fn make() -> Cursor {
    Cursor::new()
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

# ---------------------------------------------------------------------------
# bench-registration (issue #630): a correctly wired criterion bench target,
# in both spellings criterion accepts, plus a file with two groups both named
# by a single criterion_main!, must never fire bench-registration. The
# criterion_group! mentioned in each doc comment above must not be mistaken
# for a real invocation either.
# ---------------------------------------------------------------------------
mkdir -p "$B/crates/irontraffic-router/benches"
cat > "$B/crates/irontraffic-router/benches/clean_bench.rs" <<'RS'
//! A correctly wired criterion bench target. Every fn bench_* below appears in
//! the criterion_group! at the bottom, and that group is named by
//! criterion_main!, so bench-registration must stay silent.
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_one(c: &mut Criterion) {
    c.bench_function("one", |b| b.iter(|| 1 + 1));
}

fn bench_two(c: &mut Criterion) {
    c.bench_function("two", |b| b.iter(|| 2 + 2));
}

criterion_group!(benches, bench_one, bench_two);
criterion_main!(benches);
RS

cat > "$B/crates/irontraffic-router/benches/clean_bench_configured.rs" <<'RS'
//! The same, in criterion's `name = ...; config = ...; targets = ...` form,
//! where the group name is a named field rather than the first positional
//! argument, and that name is what criterion_main! must be seen to name.
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_configured(c: &mut Criterion) {
    c.bench_function("configured", |b| b.iter(|| 3 + 3));
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_configured
}
criterion_main!(benches);
RS

cat > "$B/crates/irontraffic-router/benches/clean_bench_multi_group.rs" <<'RS'
//! Two criterion_group! groups in one file, both named by a single
//! criterion_main!, proving the group-coverage direction of
//! bench-registration accepts a file that names every group it defines.
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_alpha(c: &mut Criterion) {
    c.bench_function("alpha", |b| b.iter(|| 1 + 1));
}

fn bench_beta(c: &mut Criterion) {
    c.bench_function("beta", |b| b.iter(|| 2 + 2));
}

criterion_group!(alpha_group, bench_alpha);
criterion_group!(beta_group, bench_beta);
criterion_main!(alpha_group, beta_group);
RS

echo "== corpus B: no rule may fire =="
# Captured once and reused for the same reason corpus A is: running the lints
# a second time to print the detail would find nothing to commit, short
# circuit before the lint script, and print an empty diagnostic for the
# failure it was called to explain.
OUT_B="$(run_lints_in "$B")"
CLEAN_FIRED="$(printf '%s\n' "$OUT_B" | sed -n 's/^FAIL \[\(.*\)\]$/\1/p' | LC_ALL=C sort -u)"
if [ -n "$CLEAN_FIRED" ]; then
  echo "FAIL: these rules produced FALSE POSITIVES on clean code:"
  echo "$CLEAN_FIRED" | sed 's/^/    /'
  printf '%s\n' "$OUT_B" | sed 's/^/    /'
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

# ---------------------------------------------------------------------------
# Corpus H: build_prod_tree refuses rather than guesses (issue #628). A
# #[cfg(test)] attribute whose extent cannot be resolved (no brace body, `;`,
# or `,` found before end of file) must stop the WHOLE gate with a clear
# diagnostic naming the file and line, not silently continue as if nothing
# happened. Checked two ways: the diagnostic text, and the actual exit code
# of the whole script. build_prod_tree runs inside a command-substitution
# subshell from almost every call site, so a plain `exit 1` there would only
# kill that one subshell and let the run silently carry on to print
# "invariant-lints: clean" -- this proves the fix actually reaches the
# top-level script, not just its immediate caller.
# ---------------------------------------------------------------------------
H="$WORK/refuse"
mkdir -p "$H/crates/irontraffic-router/src"
cat > "$H/crates/irontraffic-router/src/truncated.rs" <<'RS'
//! Deliberately truncated: a real #[cfg(test)] attribute with nothing
//! recognizable after it anywhere before end of file.
pub fn noop() {}
#[cfg(test)]
RS
# Deliberately NO Cargo.toml, and in particular no unjustified
# `[workspace.dependencies]\nserde = "1"` entry (issue #642): that entry
# trips dependency-justification and supplies a nonzero exit ALL ON ITS OWN,
# which let this corpus pass even with `kill -TERM "$$"` deleted from
# build_prod_tree. dependency-justification's own Python reads Cargo.toml
# with `except OSError: sys.exit(0)`, so a missing manifest is a silent no-op
# for it, and no other rule here depends on one existing at all: this corpus
# now has exactly one way to produce a nonzero exit, the refusal itself.
( cd "$H" && git init -q . && git config user.email t@t && git config user.name t \
    && git add -A >/dev/null && git commit -qm t >/dev/null )

echo "== corpus H: an unresolvable #[cfg(test)] refuses rather than guesses =="
H_RC=0
( cd "$H" && bash "$LINTS" ) > "$WORK/h_output.txt" 2>&1 || H_RC=$?
# DIAG_COUNT, not just presence: build_prod_tree runs inside a command-
# substitution subshell from almost every call site, so a plain `exit 1`
# there kills only that one subshell and lets the run silently carry on to
# the NEXT rule's own build_prod_tree call, printing the same diagnostic
# again from scratch, once per remaining call site (measured at 15 on this
# corpus, issue #642). Exactly once is what proves `kill -TERM "$$"` reached
# the top-level script and stopped it at the FIRST refusal, which is the
# property this corpus exists to prove; more than once means the kill did
# not fire and the run only happened to still end nonzero for an unrelated
# reason.
DIAG_COUNT="$(grep -c 'FAIL \[build-prod-tree\]' "$WORK/h_output.txt" || true)"
if [ "$H_RC" -le 128 ]; then
  echo "FAIL: an unresolvable #[cfg(test)] did not die BY SIGNAL (exit $H_RC;"
  echo "      143 is SIGTERM, so anything at or below 128 is an ordinary"
  echo "      nonzero exit from some OTHER rule, not proof that kill -TERM"
  echo "      \"\$\$\" in build_prod_tree actually fired):"
  sed 's/^/    /' "$WORK/h_output.txt"
  FAILED=1
elif [ "$DIAG_COUNT" -ne 1 ]; then
  echo "FAIL: the build-prod-tree diagnostic appeared $DIAG_COUNT time(s), not"
  echo "      exactly once. Exactly once is what proves the run STOPPED at the"
  echo "      first refusal rather than continuing through every later"
  echo "      scan_prod call site:"
  sed 's/^/    /' "$WORK/h_output.txt"
  FAILED=1
elif grep -q '^invariant-lints: clean$' "$WORK/h_output.txt"; then
  echo "FAIL: the gate printed \"invariant-lints: clean\" even though a"
  echo "      #[cfg(test)] attribute could not be resolved; the refusal did"
  echo "      not actually stop the run:"
  sed 's/^/    /' "$WORK/h_output.txt"
  FAILED=1
elif grep -qF 'truncated.rs' "$WORK/h_output.txt"; then
  note "unresolvable #[cfg(test)] refuses by signal (exit $H_RC), names the file, prints the diagnostic exactly once, and never reaches \"clean\""
else
  echo "FAIL: the gate stopped (exit $H_RC), but not with the expected"
  echo "      build-prod-tree diagnostic naming the offending file:"
  sed 's/^/    /' "$WORK/h_output.txt"
  FAILED=1
fi

echo
if [ "$FAILED" -ne 0 ]; then
  echo "invariant-lints-selftest: FAILED. The lint script no longer enforces what it claims."
  exit 1
fi
echo "invariant-lints-selftest: clean"
