// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration test that `CertIndex::resolve` performs zero heap allocations per call, even under
//! adversarial floods.
//!
//! A process-global counting allocator is correct here because this is a separate integration-test
//! binary: no other test binary runs in the same process.

#![allow(unsafe_code, clippy::expect_used, clippy::indexing_slicing)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use irontraffic_tls::store::{CertIndex, CertIndexBuilder, ClientCaps};
use irontraffic_tls::store::{ChainInterner, Credentials};

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every method forwards to `System` with an unmodified layout and pointer.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        LIVE_BYTES.fetch_add(l.size(), Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE_BYTES.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

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
/// Allocation-free, so it can run inside the measured loop.
fn flood_name<'b>(n: u64, suffix: &str, buf: &'b mut [u8; 64]) -> &'b str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..16 {
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
    zero_allocations_in_resolve();
    random_sni_flood_is_flat();
    wildcard_subdomain_flood_is_flat();
}

fn zero_allocations_in_resolve() {
    let (index, _cred) = build_exact_index(1_000, ".example.net");
    let queries = ["0.example.net", "1.example.net", "nope.example.net"];
    // Build inputs before the baseline.
    let count_before = ALLOC_COUNT.load(Ordering::Relaxed);
    let live_before = LIVE_BYTES.load(Ordering::Relaxed);
    for _ in 0..10_000 {
        for q in &queries {
            let _ = index.resolve(q, ClientCaps::all());
        }
    }
    let count_after = ALLOC_COUNT.load(Ordering::Relaxed);
    let live_after = LIVE_BYTES.load(Ordering::Relaxed);
    assert_eq!(count_after - count_before, 0);
    assert_eq!(live_after - live_before, 0);
}

fn random_sni_flood_is_flat() {
    // Index unrelated names so every flood query is a miss.
    let (index, _cred) = build_exact_index(1_000, ".other.example");
    let mut buf = [0u8; 64];
    let count_before = ALLOC_COUNT.load(Ordering::Relaxed);
    let live_before = LIVE_BYTES.load(Ordering::Relaxed);
    for n in 0..1_000_000 {
        let q = flood_name(n, ".example.net", &mut buf);
        let r = index.resolve(q, ClientCaps::all());
        assert!(r.is_none(), "flood query must miss: {q}");
    }
    let count_after = ALLOC_COUNT.load(Ordering::Relaxed);
    let live_after = LIVE_BYTES.load(Ordering::Relaxed);
    assert_eq!(count_after - count_before, 0);
    assert_eq!(live_after - live_before, 0);
}

fn wildcard_subdomain_flood_is_flat() {
    // This is the input that grows Traefik's CertCache without bound: a wildcard and a random
    // subdomain per query. Here every lookup must still match without allocating.
    let cred = gen_cred("example.com");
    let mut builder = CertIndexBuilder::new([2u8; 16]);
    builder
        .upsert_wildcard("*.example.com", Arc::clone(&cred))
        .expect("valid");
    let index = builder.build().expect("build");

    let mut buf = [0u8; 64];
    let count_before = ALLOC_COUNT.load(Ordering::Relaxed);
    let live_before = LIVE_BYTES.load(Ordering::Relaxed);
    for n in 0..1_000_000 {
        let q = flood_name(n, ".example.com", &mut buf);
        let r = index.resolve(q, ClientCaps::all());
        assert!(r.is_some(), "flood query must match wildcard: {q}");
    }
    let count_after = ALLOC_COUNT.load(Ordering::Relaxed);
    let live_after = LIVE_BYTES.load(Ordering::Relaxed);
    assert_eq!(count_after - count_before, 0);
    assert_eq!(live_after - live_before, 0);
}
