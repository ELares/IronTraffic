// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]

//! Fuzz target for `ClusterTicketer::decrypt`: arbitrary bytes into decryption, per the issue
//! that specifies this module. `cipher` is fully attacker controlled, the same shape of input a
//! client hands the server in a TLS 1.3 `pre_shared_key` extension, so the contract is: never
//! panic, never hang, never allocate more than `MAX_TICKET_LEN` per call.
//!
//! **Two paths, exercised per input, honestly reported as such.** A random 16-byte prefix
//! matches a real derived key name with probability 2^-128, so a target that only ever calls
//! `decrypt(data)` directly would spend essentially its entire run inside the length check and
//! the unknown-key arm, never reaching the AEAD-open branch or the framing property below it.
//! That is a REAL fact about this fuzz target's own coverage, stated rather than hidden behind a
//! metric that only counts calls:
//!
//! - **Path A**: `data` itself, unmodified, straight into `decrypt`. Its realistic ceiling for
//!   reaching a successful decrypt is zero: nothing in this corpus can carry a name matching
//!   this target's fixed root without already having seen a real ticket from it.
//! - **Path B**: a real ticket this target itself builds by encrypting `data` (capped to
//!   `MAX_TICKET_LEN - 56` bytes of plaintext) under the same fixed `ClusterTicketer` used to
//!   decrypt it, then decrypted straight back. This reliably reaches the matched-key and AEAD-
//!   open branches that path A almost never does, and is what makes the framing assertion below
//!   meaningful rather than dead code.
//! - **Path C**: path B's ciphertext with one fuzzer-chosen byte flipped, exploring the
//!   almost-valid manifold around a real ticket the same way `ticket.rs`'s own
//!   `decrypt_corrupted_ciphertext` and `decrypt_corrupted_nonce` unit tests flip one byte by
//!   hand.
//!
//! Every path runs through the SAME `exercise` function and its SAME framing assertion: a
//! returned `Some(plaintext)` must have `plaintext.len() == cipher.len() - 56`, which catches a
//! framing error (a wrong split point, an off-by-one in the name or nonce length) that a bare
//! "AEAD open succeeded" check would not, because the AEAD tag only authenticates the bytes it
//! was given; it says nothing about whether the split that produced those bytes was correct.
//!
//! **What this target does not independently measure.** The "must not allocate more than
//! `MAX_TICKET_LEN` per call" contract is argued from the code, not measured with an allocator
//! here: `ticket.rs`'s own `unknown_key_path_allocates_nothing` unit test uses the crate-internal
//! `alloc_probe` counter for that, which is `pub(crate)` and not reachable from this separate
//! fuzz crate. This target's own assurance is the framing assertion above plus whatever a
//! sanitizer-backed `cargo fuzz` run reports for peak memory.
//!
//! Contract: must not panic, must not hang.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use irontraffic_tls::store::TimeView;
use irontraffic_tls::ticket::{ClusterTicketer, MAX_TICKET_LEN, NonceSource, TicketRoot};
use irontraffic_tls::time::UnixSeconds;
use libfuzzer_sys::fuzz_target;
use rustls::server::ProducesTickets;

/// Fixed clock: 2025-01-01T00:00:00Z, unix seconds. Never a live read; see
/// `irontraffic_tls::time`'s own module doc on why a fuzz target's inputs must be reproducible.
const FIXED_NOW: u64 = 1_735_689_600;

struct FixedClock;

impl TimeView for FixedClock {
    fn unix_seconds(&self) -> UnixSeconds {
        UnixSeconds::new(FIXED_NOW)
    }
}

/// Deterministic, non-repeating nonces: fast and reproducible, never the OS CSPRNG a fuzz
/// target has no business calling.
#[derive(Default)]
struct DeterministicNonceSource(AtomicU64);

impl NonceSource for DeterministicNonceSource {
    fn fill(&self, out: &mut [u8; 24]) -> bool {
        let n = self.0.fetch_add(1, Ordering::Relaxed);
        if let Some(head) = out.get_mut(..8) {
            head.copy_from_slice(&n.to_be_bytes());
        }
        true
    }
}

fn ticketer() -> &'static ClusterTicketer {
    static TICKETER: OnceLock<ClusterTicketer> = OnceLock::new();
    TICKETER.get_or_init(|| {
        ClusterTicketer::new(
            TicketRoot::new([0x42; 32]),
            [0u8; 16],
            21_600,
            Arc::new(FixedClock),
            Arc::new(DeterministicNonceSource::default()),
        )
    })
}

static TOTAL: AtomicU64 = AtomicU64::new(0);
static PATH_A_CALLS: AtomicU64 = AtomicU64::new(0);
static PATH_A_OK: AtomicU64 = AtomicU64::new(0);
static PATH_B_CALLS: AtomicU64 = AtomicU64::new(0);
static PATH_B_OK: AtomicU64 = AtomicU64::new(0);
static PATH_C_CALLS: AtomicU64 = AtomicU64::new(0);
static PATH_C_OK: AtomicU64 = AtomicU64::new(0);

fn report_progress() {
    let total = TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    if total.is_multiple_of(5_000) {
        eprintln!(
            "fuzz_ticket_decrypt: total={total} || PATH-A calls={} ok={} | PATH-B calls={} \
             ok={} | PATH-C calls={} ok={}",
            PATH_A_CALLS.load(Ordering::Relaxed),
            PATH_A_OK.load(Ordering::Relaxed),
            PATH_B_CALLS.load(Ordering::Relaxed),
            PATH_B_OK.load(Ordering::Relaxed),
            PATH_C_CALLS.load(Ordering::Relaxed),
            PATH_C_OK.load(Ordering::Relaxed),
        );
    }
}

/// Runs `cipher` through `decrypt` once, asserting the panic-free and framing contract. Returns
/// whether it decrypted, so callers can track their own path's hit rate.
fn exercise(cipher: &[u8]) -> bool {
    match ticketer().decrypt(cipher) {
        Some(plain) => {
            assert_eq!(
                plain.len(),
                cipher.len() - 56,
                "decrypted plaintext length must be exactly cipher.len() - 56 (16-byte name + \
                 24-byte nonce + 16-byte AEAD tag), catching a framing error AEAD success alone \
                 would not"
            );
            true
        }
        None => false,
    }
}

fuzz_target!(|data: &[u8]| {
    report_progress();

    // Path A: the raw fuzz bytes, unmodified, straight into decrypt.
    PATH_A_CALLS.fetch_add(1, Ordering::Relaxed);
    if exercise(data) {
        PATH_A_OK.fetch_add(1, Ordering::Relaxed);
    }

    // Path B: a real ticket built from `data` as plaintext (capped so the resulting ciphertext
    // never exceeds MAX_TICKET_LEN), decrypted straight back.
    let cap = MAX_TICKET_LEN - 56;
    let plain = data.get(..data.len().min(cap)).unwrap_or(data);
    if let Some(ct) = ticketer().encrypt(plain) {
        PATH_B_CALLS.fetch_add(1, Ordering::Relaxed);
        if exercise(&ct) {
            PATH_B_OK.fetch_add(1, Ordering::Relaxed);
        }

        // Path C: the same valid ticket with one fuzzer-chosen byte flipped, exploring the
        // almost-valid manifold around a real ticket.
        if let [b0, b1, ..] = *data {
            if let Some(max) = ct.len().checked_sub(1) {
                let offset = (usize::from(b0) | (usize::from(b1) << 8)) % (max + 1);
                let mut mutated = ct;
                if let Some(byte) = mutated.get_mut(offset) {
                    *byte ^= 0xff;
                }
                PATH_C_CALLS.fetch_add(1, Ordering::Relaxed);
                if exercise(&mutated) {
                    PATH_C_OK.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
});
