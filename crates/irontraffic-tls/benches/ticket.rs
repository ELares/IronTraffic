// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for `ClusterTicketer::encrypt` and `ClusterTicketer::decrypt`.
//!
//! Budgets are recorded here, not gated: `perf-budgets-file-and-raise-lint` (#418) wires up
//! enforcement once its budget file exists. See `cluster-derived-session-ticketer`'s own
//! Benchmarks section for the budget each id below is checked against; the PR that lands this
//! file records the measured medians and a pass or fail note against every budget in its own
//! body, including the ratio between `ticket/decrypt_unknown_key_near_miss` and
//! `ticket/decrypt_unknown_key`.

#![allow(missing_docs, reason = "criterion_group! generates this pub item")]
#![allow(
    clippy::expect_used,
    reason = "bench harness fixture setup, not request-path code: every expect() below is on a \
              fixed, well formed input this file constructs itself"
)]

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
use irontraffic_tls::store::TimeView;
use irontraffic_tls::ticket::{ClusterTicketer, NonceSource, TicketRoot};
use irontraffic_tls::time::UnixSeconds;
use rustls::server::ProducesTickets;

/// A movable clock: `set` lets a benchmark build a ticket at one epoch and measure decryption
/// at another, mirroring `ticket.rs`'s own `TestClock`.
struct BenchClock(AtomicU64);

impl BenchClock {
    fn new(secs: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(secs)))
    }

    fn set(&self, secs: u64) {
        self.0.store(secs, Ordering::SeqCst);
    }
}

impl TimeView for BenchClock {
    fn unix_seconds(&self) -> UnixSeconds {
        UnixSeconds::new(self.0.load(Ordering::SeqCst))
    }
}

/// Deterministic, non-repeating nonces, mirroring `ticket.rs`'s own `CountingNonceSource`: fast
/// and reproducible, never the OS CSPRNG a benchmark has no business calling.
#[derive(Default)]
struct BenchNonceSource(AtomicU64);

impl NonceSource for BenchNonceSource {
    fn fill(&self, out: &mut [u8; 24]) -> bool {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        if let Some(head) = out.get_mut(..8) {
            head.copy_from_slice(&n.to_be_bytes());
        }
        true
    }
}

const ROTATION_SECS: u32 = 21_600;

fn ticketer(clock: &Arc<BenchClock>) -> ClusterTicketer {
    let time: Arc<dyn TimeView> = clock.clone();
    ClusterTicketer::new(
        TicketRoot::new([0x42; 32]),
        [0u8; 16],
        ROTATION_SECS,
        time,
        Arc::new(BenchNonceSource::default()),
    )
}

/// 130 bytes, matching the design's own budget note for a realistic rustls TLS 1.3 ticket
/// plaintext.
const PLAINTEXT_130: [u8; 130] = [0xAA; 130];

fn bench_encrypt(c: &mut Criterion) {
    let clock = BenchClock::new(1_700_000_000);
    let t = ticketer(&clock);
    // Warm the slot before measuring: this id is the steady-state cost, not the cold derive
    // (that is `ticket/epoch_key_cold`, below).
    let _ = t.encrypt(&PLAINTEXT_130);

    c.bench_function("ticket/encrypt", |b| {
        b.iter(|| black_box(t.encrypt(black_box(&PLAINTEXT_130))));
    });
}

fn bench_decrypt_current_epoch(c: &mut Criterion) {
    let clock = BenchClock::new(1_700_000_000);
    let t = ticketer(&clock);
    let ct = t
        .encrypt(&PLAINTEXT_130)
        .expect("fixture ticket must encrypt");

    c.bench_function("ticket/decrypt_current_epoch", |b| {
        b.iter(|| black_box(t.decrypt(black_box(&ct))));
    });
}

fn bench_decrypt_oldest_epoch(c: &mut Criterion) {
    let clock = BenchClock::new(1_700_000_000);
    let t = ticketer(&clock);
    let ct = t
        .encrypt(&PLAINTEXT_130)
        .expect("fixture ticket must encrypt");
    // Move two rotation periods forward: decrypting now must compare against all three
    // accepted epochs (e, e-1, e-2) before it finds the match at e-2.
    clock.set(1_700_000_000 + 2 * u64::from(ROTATION_SECS));
    // Warm the current and middle epoch's slots too, so this id measures the three-epoch
    // comparison cost, not a cold derive at the other two candidates.
    let _ = t.decrypt(&ct);

    c.bench_function("ticket/decrypt_oldest_epoch", |b| {
        b.iter(|| black_box(t.decrypt(black_box(&ct))));
    });
}

fn bench_decrypt_unknown_key(c: &mut Criterion) {
    let clock = BenchClock::new(1_700_000_000);
    let t = ticketer(&clock);
    let _ = t.encrypt(&PLAINTEXT_130);
    let garbage = vec![0x5A_u8; 200];

    c.bench_function("ticket/decrypt_unknown_key", |b| {
        b.iter(|| black_box(t.decrypt(black_box(&garbage))));
    });
}

fn bench_decrypt_unknown_key_near_miss(c: &mut Criterion) {
    let clock = BenchClock::new(1_700_000_000);
    let t = ticketer(&clock);
    let ct = t
        .encrypt(&PLAINTEXT_130)
        .expect("fixture ticket must encrypt");

    // A 200-byte ticket whose first 15 name bytes match a live key name and whose 16th does
    // not: the near-miss case the constant-time comparison exists for. `ct`'s own name is a
    // live one; corrupt only its last byte and pad/truncate the rest to 200 bytes.
    let mut near_miss = vec![0x5A_u8; 200];
    if let Some(name) = ct.get(..16)
        && let Some(dst) = near_miss.get_mut(..15)
        && let Some(src) = name.get(..15)
    {
        dst.copy_from_slice(src);
    }

    c.bench_function("ticket/decrypt_unknown_key_near_miss", |b| {
        b.iter(|| black_box(t.decrypt(black_box(&near_miss))));
    });
}

fn bench_epoch_key_cold(c: &mut Criterion) {
    // A fresh ticketer per iteration, via iter_batched: only the encrypt call (which forces
    // the first, cold epoch-key derivation on an uninitialized slot) is measured, not the
    // ticketer's own construction. `epoch_key` itself is private, so this exercises it through
    // `encrypt`, the same way every other caller reaches it.
    c.bench_function("ticket/epoch_key_cold", |b| {
        b.iter_batched(
            || {
                let clock = BenchClock::new(1_700_000_000);
                ticketer(&clock)
            },
            |t| black_box(t.encrypt(black_box(&PLAINTEXT_130))),
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt_current_epoch,
    bench_decrypt_oldest_epoch,
    bench_decrypt_unknown_key,
    bench_decrypt_unknown_key_near_miss,
    bench_epoch_key_cold,
);
criterion_main!(benches);
