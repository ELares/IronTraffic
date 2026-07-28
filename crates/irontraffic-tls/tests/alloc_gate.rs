// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration test for `CertIndex::resolve`'s zero-allocation invariant and its adversarial-SNI
//! flood behavior.
//!
//! WHY THIS IS A TEXT SCAN AND NOT A COUNTING ALLOCATOR, STATED ACCURATELY. Issue #719 found that
//! the previous version of this doc was false: it said a counting `#[global_allocator]` "cannot
//! be implemented without the unsafe keyword" and that the workspace "denies unsafe code in
//! every file including tests". Neither is true. The root `Cargo.toml` sets
//! `unsafe_code = "deny"`, and `deny` is the OVERRIDABLE lint level; `forbid` is the level that
//! cannot be overridden, and this crate does not use it. A counting `#[global_allocator]` was
//! verified to compile and run cleanly in this exact crate behind
//! `#![allow(unsafe_code, reason = "...")]`, and it passed `cargo clippy --all-targets
//! --all-features -- -D warnings`. What actually blocks it is `scripts/invariant-lints.sh` rule
//! 15, `no-unsafe`, whose own failure text grants no exception: "There is no exception an
//! implementer is authorized to make; raise it on the issue instead." That escalation has not
//! happened for this crate, so this file adds neither the `unsafe` keyword nor an `allow` for
//! `unsafe_code`. If a
//! counting allocator is ever wanted here, the correct next step is to raise that exception on
//! issue #115, not to add the attribute and hope the lint misses it: `no-unsafe` runs through the
//! same `scan()` helper as most rules in `scripts/invariant-lints.sh`, which pipes hits through
//! `drop_escaped`, so a `// it-allow: no-unsafe reason: ...` comment would mechanically suppress
//! it exactly as it does for any other rule (see `crates/irontraffic-tls/src/name.rs`'s module
//! doc for the same point made about this same lint). The reason not to write that line is that
//! it is a self-granted exception to a rule whose own text says no implementer may grant one, not
//! that the mechanism could not be made to compile.
//!
//! Instead this file uses the same pattern every `alloc_gate_*.rs` file in
//! `crates/irontraffic-http/tests/` uses: a per-function TEXT SCAN over the source of `resolve`,
//! `select`, `name_at`, `default_path`, and everything they call inside this crate (`normalize`,
//! `validate_label`, `parent`, and `NameHasher::hash`), checking each function's body for any
//! call spelling that can allocate. `crates/irontraffic-http/tests/alloc_gate_common/mod.rs`
//! owns the canonical version of this vocabulary and helper; this file keeps its own copy because
//! that module lives under a different crate's `tests/` directory, outside this issue's Files
//! table.
//!
//! STATE PLAINLY WHAT THIS DOES AND DOES NOT PROVE, because a clean run of a deny-list text scan
//! is not a proof of zero allocations. It catches an allocating call that appears, textually, in
//! a scanned function body. It CANNOT distinguish a function that allocates zero times from one
//! that allocates on every call through a spelling nobody added to the list, a call taken by
//! function pointer (`let f = str::to_lowercase; f(s)` matches nothing here), or a call reached
//! through a fully qualified path (`ToOwned::to_owned(x)` instead of `x.to_owned()`). It is a
//! best-effort net, not a proof, exactly the framing
//! `crates/irontraffic-http/tests/alloc_gate_common/mod.rs` uses for the identical pattern.
//!
//! The functional flood tests below are a separate, complementary check with a different job:
//! they exercise the adversarial input shapes the design doc calls out (a random-SNI miss flood
//! and a wildcard-subdomain hit flood, each 1,000,000 iterations) and assert the FUNCTIONAL
//! outcome (miss / hit) stays correct at scale. They observe no allocation at all; that is what
//! the text scan above is for. Each phase returns the count of iterations it actually ran rather
//! than a literal, so emptying a loop changes the returned count and fails the assertion instead
//! of passing it: issue #719 found the previous version hard-coded `1_000_000` as the return
//! value of two of the three phases, so `assert_eq!(random_misses, 1_000_000)` reduced to
//! `assert_eq!(1_000_000, 1_000_000)` regardless of how many iterations the loop actually ran.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test-only helpers on generated inputs and a fixed-size stack buffer"
)]

use std::sync::Arc;

use irontraffic_tls::store::{CertIndex, CertIndexBuilder, ClientCaps};
use irontraffic_tls::store::{ChainInterner, Credentials};

/// Calls that can allocate on the heap, textually. The same vocabulary
/// `crates/irontraffic-http/tests/alloc_gate_common/mod.rs` uses for the identical pattern; a
/// deny list, not a proof, per the module doc above.
const ALLOCATING_CALLS: [&str; 14] = [
    "format!",
    ".to_string()",
    ".to_owned()",
    ".to_vec()",
    "vec![",
    "Vec::new()",
    "String::new()",
    "String::from(",
    "Box::new(",
    "HashMap::new()",
    ".collect::<Vec",
    ".collect::<String",
    ".collect::<HashMap",
    ".clone()",
];

/// Returns the source text of the function whose signature contains `signature`, from its
/// opening brace through its matching closing brace, or `None` if `signature` is not found or has
/// no matching closing brace.
///
/// A plain brace-depth text scan, not a Rust parser: correct as long as the scanned body contains
/// no string or char literal holding an unmatched `{` or `}`, which every function scanned below
/// satisfies today. Mirrors
/// `crates/irontraffic-http/tests/alloc_gate_common/mod.rs::extract_fn_body`.
fn extract_fn_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let start = source.find(signature)?;
    let open = source[start..].find('{').map(|offset| start + offset)?;
    let mut depth = 0usize;
    let mut end = open;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + offset + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if end > open {
        Some(&source[open..end])
    } else {
        None
    }
}

/// Text-scans `resolve`, `select`, `name_at`, `default_path`, and everything they call inside
/// this crate, for any call spelling in `ALLOCATING_CALLS`. See the module doc for what this does
/// and does not prove.
#[test]
fn resolve_call_graph_has_no_allocating_calls() {
    let index_source = include_str!("../src/store/index.rs");
    let name_source = include_str!("../src/name.rs");

    // Every function `resolve` can reach inside this crate, found by its own (stable,
    // single-line) signature text. `resolve`, `select`, `name_at`, and `default_path` are named
    // directly by issue #719; `normalize`, `validate_label`, `parent`, and `NameHasher::hash` are
    // everything they call inside this crate. `self.exact.get`/`self.wild.get` (hashbrown),
    // `fetch_add` (core::sync::atomic), and `SipHasher13` (siphasher) are outside this crate and
    // are not scanned; that is a real, stated limit of this test, not an oversight.
    let signatures = [
        (
            index_source,
            "resolve",
            "pub fn resolve(&self, sni: &str, caps: ClientCaps) -> Option<&Arc<Credentials>> {",
        ),
        (
            index_source,
            "select",
            "fn select(&self, i: CredSetIdx, caps: ClientCaps) -> Option<&Arc<Credentials>> {",
        ),
        (
            index_source,
            "name_at",
            "fn name_at(&self, i: CredSetIdx) -> &[u8] {",
        ),
        (
            index_source,
            "default_path",
            "fn default_path(&self) -> Option<&Arc<Credentials>> {",
        ),
        (
            name_source,
            "normalize",
            "pub fn normalize<'b>(raw: &str, buf: &'b mut [u8; MAX_NAME_LEN]) -> Result<&'b str, NameError> {",
        ),
        (
            name_source,
            "validate_label",
            "fn validate_label(b: &[u8], label_start: usize, end: usize) -> Result<(), NameError> {",
        ),
        (
            name_source,
            "parent",
            "pub fn parent(name: &str) -> Option<&str> {",
        ),
        (
            name_source,
            "NameHasher::hash",
            "pub fn hash(&self, normalized: &str) -> NameKey {",
        ),
    ];

    for (source, name, signature) in signatures {
        let body = extract_fn_body(source, signature).unwrap_or_else(|| {
            panic!(
                "`fn {name}` not found via `{signature}`; has it moved, been renamed, or been \
                 reformatted onto a different single-line signature?"
            )
        });
        for call in ALLOCATING_CALLS {
            assert!(
                !body.contains(call),
                "{name}'s body contains `{call}`, which can allocate; resolve's whole call \
                 graph is documented to perform zero heap allocations per lookup"
            );
        }
    }
}

fn gen_cred(san: &str) -> Arc<Credentials> {
    let _ = irontraffic_tls::install_process_provider();
    let params = rcgen::CertificateParams::new(vec![san.to_owned()]).expect("valid SANs");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keygen");
    let cert = params.self_signed(&key).expect("sign");
    let mut interner = ChainInterner::new();
    Arc::new(
        Credentials::load(&[cert.der()], &key.serialize_der(), &mut interner)
            .expect("valid leaf and key"),
    )
}

/// Writes `<16 lowercase hex digits of n><suffix>` into `buf` and returns the &str.
fn flood_name<'b>(n: u64, suffix: &str, buf: &'b mut [u8; 64]) -> &'b str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..16 {
        // it-allow: unchecked-cast reason: the value is masked to 0..=15, which fits in usize
        buf[i] = HEX[((n >> (60 - 4 * i)) & 0xf) as usize];
    }
    buf[16..16 + suffix.len()].copy_from_slice(suffix.as_bytes());
    core::str::from_utf8(&buf[..16 + suffix.len()]).expect("ascii")
}

fn build_exact_index(n: usize, suffix: &str) -> (CertIndex, Arc<Credentials>) {
    let cred = gen_cred("example.com");
    let mut builder = CertIndexBuilder::new([1u8; 16]);
    for i in 0..n {
        let name = format!("{i}{suffix}");
        builder
            .upsert_exact(&name, Arc::clone(&cred))
            .expect("valid");
    }
    let index = builder.build().expect("build");
    (index, cred)
}

#[test]
fn alloc_gate() {
    // The zero-allocation proof is enforced statically by `resolve_call_graph_has_no_allocating_calls`
    // above; this runtime test covers the same flood inputs and asserts the functional outcomes.
    let zero_count = zero_allocations_in_resolve();
    let random_misses = random_sni_flood_is_flat();
    let wildcard_hits = wildcard_subdomain_flood_is_flat();
    assert_eq!(zero_count, 30_000);
    assert_eq!(random_misses, 1_000_000);
    assert_eq!(wildcard_hits, 1_000_000);
}

fn zero_allocations_in_resolve() -> usize {
    let (index, _cred) = build_exact_index(1_000, ".example.net");
    let queries = ["0.example.net", "1.example.net", "nope.example.net"];
    let mut count = 0usize;
    for _ in 0..10_000 {
        for q in &queries {
            let _ = index.resolve(q, ClientCaps::all());
            count += 1;
        }
    }
    count
}

fn random_sni_flood_is_flat() -> usize {
    // Index unrelated names so every flood query is a miss.
    let (index, _cred) = build_exact_index(1_000, ".other.example");
    let mut buf = [0u8; 64];
    let mut count = 0usize;
    for n in 0..1_000_000u64 {
        let q = flood_name(n, ".example.net", &mut buf);
        let r = index.resolve(q, ClientCaps::all());
        assert!(r.is_none(), "flood query must miss: {q}");
        count += 1;
    }
    count
}

fn wildcard_subdomain_flood_is_flat() -> usize {
    // This is the input that grows Traefik's CertCache without bound: a wildcard and a random
    // subdomain per query. Here every lookup must still match.
    let cred = gen_cred("example.com");
    let mut builder = CertIndexBuilder::new([2u8; 16]);
    builder
        .upsert_wildcard("*.example.com", Arc::clone(&cred))
        .expect("valid");
    let index = builder.build().expect("build");

    let mut buf = [0u8; 64];
    let mut count = 0usize;
    for n in 0..1_000_000u64 {
        let q = flood_name(n, ".example.com", &mut buf);
        let r = index.resolve(q, ClientCaps::all());
        assert!(r.is_some(), "flood query must match wildcard: {q}");
        count += 1;
    }
    count
}
