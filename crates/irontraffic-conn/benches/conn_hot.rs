// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    missing_docs,
    reason = "this bench binary's crate root: criterion_group! and criterion_main! \
              below expand to undocumented items (a group function, a static, fn \
              main), none of which are part of this crate's public API"
)]
//! Criterion benchmark for `ConnBudget::on_frame`, the per-frame hot path
//! debited before any per-stream state is allocated. `harness = false` in
//! `Cargo.toml`: criterion supplies its own `main`, and a `[[bench]]` entry
//! without that flag runs under libtest instead and fails at startup.
//!
//! Budget (reference runner: GitHub Actions `ubuntu-latest`, 4 vCPU, release
//! profile with `lto = "thin"`, see `[profile.bench]` in the workspace
//! `Cargo.toml`): `on_frame` itself must complete in under 6 nanoseconds per
//! frame, and the overhead the accounting adds over a no-op comparison loop
//! must be under 2 percent of a 300 nanosecond frame-dispatch cost, that is,
//! under 6 nanoseconds. Criterion does not enforce either budget itself;
//! compare the reported time against them by hand.
//!
//! `ConnBudget` is a plain-integer-field struct with no heap-owning member,
//! so the zero-allocation property is structural rather than measured here:
//! it is checked by
//! `grep -nE "Vec::|String::|Box::|to_vec\(|format!" crates/irontraffic-conn/src/budget.rs`
//! returning nothing.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use irontraffic_conn::bodybuf::{BufferPool, ByteSize};
use irontraffic_conn::inflight::InflightGauge;
use irontraffic_conn::proxyproto::ProxyHeader;
use irontraffic_conn::{ConnBudget, FrameEvent};
use std::hint::black_box;
use std::thread;
use std::time::Instant;

/// A fixed rotation of frame events representative of ordinary multiplexed
/// traffic: mostly `Ordinary` frames with an occasional `HeadersOpen`,
/// `RstStreamReceived` and `Ping`, so the loop exercises every arm of
/// `cost_of`'s match rather than always taking the cheapest one.
const EVENTS: [FrameEvent; 8] = [
    FrameEvent::Ordinary,
    FrameEvent::Ordinary,
    FrameEvent::HeadersOpen,
    FrameEvent::Ordinary,
    FrameEvent::Ordinary,
    FrameEvent::RstStreamReceived,
    FrameEvent::Ordinary,
    FrameEvent::Ping,
];

/// A no-op stand-in with the same call shape as [`ConnBudget::on_frame`]: a
/// plain saturating subtraction on a bare counter, with no cost table and no
/// refill. The comparison loop built from this measures dispatch overhead
/// alone, so the DIFFERENCE between `budget_on` and `budget_off` below is the
/// accounting's true added cost.
fn no_budget_on_frame(counter: &mut i64, ev: FrameEvent) {
    let cost = if matches!(ev, FrameEvent::Ordinary) {
        1
    } else {
        2
    };
    *counter = counter.saturating_sub(cost);
}

fn bench_frame_debit(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_frame_debit");
    group.throughput(Throughput::Elements(1_000));

    group.bench_function("budget_on", |b| {
        b.iter(|| {
            let mut budget = ConnBudget::new(0);
            let mut now_ms = 0u32;
            for (i, &ev) in EVENTS.iter().cycle().take(1_000).enumerate() {
                if i % 64 == 0 {
                    now_ms = now_ms.wrapping_add(1);
                }
                let _ = black_box(budget.on_frame(black_box(ev), black_box(now_ms)));
            }
            black_box(budget.tokens())
        });
    });

    group.bench_function("budget_off", |b| {
        b.iter(|| {
            let mut counter = 10_000_i64;
            for (i, &ev) in EVENTS.iter().cycle().take(1_000).enumerate() {
                // `now_ms` plays no role in the no-op path; the branch below
                // mirrors the real loop's shape so both loops do the same
                // number of comparisons and branches, leaving only the
                // accounting itself as the measured difference.
                let _ = black_box(i % 64 == 0);
                no_budget_on_frame(&mut counter, black_box(ev));
            }
            black_box(counter)
        });
    });

    group.finish();
}

// Benchmarks `BufferPool::try_acquire` paired with the resulting
// `BufferLease`'s drop: the zero-byte streaming path (what `Buffering::None`'s
// `lease_size()` always requests) and the nonzero buffering path.
//
// Budget (reference runner: see the module doc comment above): under 2
// nanoseconds for the zero-byte case, because it must touch the shared,
// process-wide `outstanding` counter with a branch rather than an atomic
// read-modify-write, and under 25 nanoseconds for the nonzero case, which
// pays one load, one compare-and-swap on the uncontended path, and one atomic
// subtract on drop. The zero-byte case is not free of atomics altogether:
// `Arc::clone`/drop on the pool handle still perform an uncontended atomic
// refcount update either way, which is a fixed, unavoidable cost this budget
// does not attempt to eliminate. Criterion does not enforce either budget
// itself; compare the reported time against them by hand.
fn bench_buffer_lease(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_buffer_lease");

    // Both closures below discard the `Result` with `let _ =`, exactly the
    // convention `bench_frame_debit` above uses for `on_frame`'s `Result`:
    // production code must never `unwrap` or `expect`, and that rule applies
    // to this bench binary too (it is a real compiled target, not test code,
    // so clippy.toml's test-only allowance for `expect` does not cover it).
    // The discarded `Ok` lease still drops at the end of the `let _ =`
    // statement, so one measured iteration covers exactly one acquire paired
    // with its release.
    let zero_pool = BufferPool::new(ByteSize::mib(64));
    group.bench_function("zero_byte_acquire_release", |b| {
        b.iter(|| {
            let _ = black_box(BufferPool::try_acquire(
                black_box(&zero_pool),
                black_box(ByteSize(0)),
            ));
        });
    });

    let nonzero_pool = BufferPool::new(ByteSize::mib(64));
    group.bench_function("nonzero_acquire_release", |b| {
        b.iter(|| {
            let _ = black_box(BufferPool::try_acquire(
                black_box(&nonzero_pool),
                black_box(ByteSize::kib(4)),
            ));
        });
    });

    group.finish();

    // A two-thread contended variant, recorded but deliberately not gated: a
    // contended figure on a shared CI runner is not a stable number to assert
    // a budget against, because it depends on how many other processes land
    // on the same physical cores at the moment the benchmark happens to run.
    // Criterion's own `Bencher::iter` does the timing here, exactly as it
    // does for every other benchmark in this file, so this closure never
    // reads a clock itself; only the two spawned threads' combined completion
    // time per iteration is measured.
    let mut contended_group = c.benchmark_group("bench_buffer_lease_contended");
    let contended_pool = BufferPool::new(ByteSize::mib(64));
    contended_group.bench_function("two_thread_contended_acquire_release", |b| {
        b.iter(|| {
            std::thread::scope(|scope| {
                for _ in 0..2 {
                    let pool = &contended_pool;
                    scope.spawn(move || {
                        let _ = black_box(BufferPool::try_acquire(pool, ByteSize::kib(4)));
                    });
                }
            });
        });
    });
    contended_group.finish();
}

/// `InflightGauge::admit` immediately followed by dropping the returned `StreamSlot`,
/// single threaded.
///
/// Budget (reference runner, see the module doc above): under 25 nanoseconds per
/// admit-release pair, two lock-prefixed operations (the CAS in `admit`, the `fetch_sub`
/// in `Drop for StreamSlot`) on a cache line that stays Modified locally because nothing
/// else touches this gauge between the two calls.
fn bench_admit_release(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_admit_release");
    group.throughput(Throughput::Elements(1));

    group.bench_function("single_threaded", |b| {
        let gauge = InflightGauge::new(256);
        b.iter(|| {
            if let Ok(slot) = black_box(gauge.admit()) {
                drop(black_box(slot));
            }
        });
    });

    // Contended two-thread variant, reported WITHOUT a gate: a contended figure on a
    // shared CI runner is not a stable gate, only a data point. Expectation: 100 to 200
    // cycles same-socket, because the gauge's cache line now bounces between the two
    // threads' cores on every admit and every release instead of staying Modified
    // locally the way the single-threaded variant above does.
    group.bench_function("two_thread_contended", |b| {
        let gauge = InflightGauge::new(256);
        b.iter_custom(|iters| {
            #[allow(
                clippy::integer_division,
                reason = "splitting the reported iteration count evenly between the two \
                          contended threads below; at most one iteration is lost to \
                          truncation, which is immaterial to a contended figure this \
                          benchmark reports without a gate"
            )]
            let per_thread = iters / 2;
            let start = Instant::now();
            thread::scope(|scope| {
                for _ in 0..2 {
                    let gauge = &gauge;
                    scope.spawn(move || {
                        for _ in 0..per_thread {
                            if let Ok(slot) = black_box(gauge.admit()) {
                                drop(black_box(slot));
                            }
                        }
                    });
                }
            });
            start.elapsed()
        });
    });

    group.finish();
}

/// The 12-byte v2 signature, duplicated here (rather than made `pub` from the crate) since
/// this benchmark binary is the only place outside `proxyproto::v2` itself that needs the
/// raw bytes to build an input; `ProxyHeader::parse` takes no way to construct one directly.
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// 1 KiB (1024), rounded down to a whole number of 3-byte TLVs (1 type byte, 2 length
/// bytes, 0 value bytes each): `341 * 3 = 1023`. The declared v2 length and the bytes
/// actually written must match exactly, or the header is short of its own declaration and
/// `ProxyHeader::parse` takes the cheap `Partial` path instead of walking the TLVs this
/// benchmark exists to measure.
const ONE_KIB_OF_TLVS: u16 = 1023;

/// A v2 IPv4 PROXY header (`ver_cmd = 0x21`, `family = 0x11`) with `tlv_bytes` bytes of
/// well-formed, zero-value TLVs appended after the 12-byte address block. `tlv_bytes` MUST
/// be a multiple of 3; any remainder is simply not written, which callers avoid by only
/// ever passing 0 or [`ONE_KIB_OF_TLVS`].
fn v2_ipv4_header(tlv_bytes: u16) -> Vec<u8> {
    let len = 12u16.saturating_add(tlv_bytes);
    let mut buf = V2_SIGNATURE.to_vec();
    buf.push(0x21);
    buf.push(0x11);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0, 2]);
    let mut remaining = tlv_bytes;
    while remaining >= 3 {
        buf.push(0x01);
        buf.extend_from_slice(&0u16.to_be_bytes());
        remaining = remaining.saturating_sub(3);
    }
    buf
}

fn bench_proxyproto_parse(c: &mut Criterion) {
    let v1_line = b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n".to_vec();
    let v2_no_tlv = v2_ipv4_header(0);
    let v2_1kib_tlv = v2_ipv4_header(ONE_KIB_OF_TLVS);

    let mut group = c.benchmark_group("bench_proxyproto_parse");
    group.throughput(Throughput::Elements(1));

    group.bench_function("v1_tcp4", |b| {
        b.iter(|| black_box(ProxyHeader::parse(black_box(&v1_line))));
    });
    group.bench_function("v2_no_tlv", |b| {
        b.iter(|| black_box(ProxyHeader::parse(black_box(&v2_no_tlv))));
    });
    group.bench_function("v2_1kib_tlv", |b| {
        b.iter(|| black_box(ProxyHeader::parse(black_box(&v2_1kib_tlv))));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_frame_debit,
    bench_buffer_lease,
    bench_admit_release,
    bench_proxyproto_parse
);
criterion_main!(benches);
