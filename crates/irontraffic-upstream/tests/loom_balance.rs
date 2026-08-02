// SPDX-License-Identifier: MIT OR Apache-2.0

//! `loom` model-checked tests for [`InflightGuard`] and the bounded `record_rtt`
//! CAS. Gated entirely behind `#![cfg(loom)]`: under an ordinary `cargo test`
//! this whole file compiles to an empty crate (zero tests, exit 0), and it is
//! model-checked only via:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p irontraffic-upstream --test loom_balance
//! ```
//!
//! `loom` model-checks only the atomics it provides, so this exercises anything
//! reachable through [`irontraffic_upstream::stats`]'s atomics only because that
//! module imports them from `crate::sync`, which resolves to `loom`'s
//! instrumented types under this same `--cfg loom` build (see `src/sync.rs`).
//! `EndpointStats` is constructed directly with `EndpointStats::default()` in
//! every test below, never through `EndpointRegistry::install`: `loom`'s
//! atomics cannot be created outside a `loom::model` closure, and `install`
//! allocates its arena outside one.
#![allow(
    unexpected_cfgs,
    reason = "cfg(loom) is a deliberate custom cfg for the loom concurrency-model tests, the same #[cfg(loom)] convention loom's own downstream users (tokio, crossbeam) rely on; registering it via a package-level [lints.rust] check-cfg table would conflict with this crate's required [lints] workspace = true, and this crate may not touch the workspace lints table to add it there instead"
)]
#![cfg(loom)]
#![allow(missing_docs, reason = "test binary, not a public library surface")]

use loom::sync::Arc;
use loom::sync::atomic::Ordering;
use loom::thread;

use irontraffic_upstream::{EndpointStats, EwmaCfg, InflightGuard, unpack};

/// Two threads each acquire and drop a guard against one [`EndpointStats`]:
/// the final count must be `0` on every interleaving `loom` explores. A second
/// `loom::model` run in this same test is the "third variant" the issue's own
/// test description calls for: one thread's guard is dropped while a panic
/// unwinds through its scope (inside a `catch_unwind`, so the panic does not
/// escape the test process), and the balance must still return to `0`.
#[test]
fn loom_inflight_guard_returns_to_zero() {
    loom::model(|| {
        let stats = Arc::new(EndpointStats::default());

        let s1 = Arc::clone(&stats);
        let t1 = thread::spawn(move || {
            let g = InflightGuard::acquire(&s1);
            drop(g);
        });

        let s2 = Arc::clone(&stats);
        let t2 = thread::spawn(move || {
            let g = InflightGuard::acquire(&s2);
            drop(g);
        });

        assert!(t1.join().is_ok(), "writer thread 1 must not panic");
        assert!(t2.join().is_ok(), "writer thread 2 must not panic");

        assert_eq!(stats.inflight(), 0);
    });

    loom::model(|| {
        let stats = Arc::new(EndpointStats::default());

        let s1 = Arc::clone(&stats);
        let t1 = thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = InflightGuard::acquire(&s1);
                panic!("deliberate panic while a guard is in scope");
                // `_guard`'s `Drop` runs here, during unwinding, before
                // `catch_unwind` regains control below.
            }));
            assert!(outcome.is_err(), "the deliberate panic must have fired");
        });

        let s2 = Arc::clone(&stats);
        let t2 = thread::spawn(move || {
            let g = InflightGuard::acquire(&s2);
            drop(g);
        });

        assert!(t1.join().is_ok(), "catch_unwind must contain the panic");
        assert!(t2.join().is_ok(), "writer thread 2 must not panic");

        assert_eq!(
            stats.inflight(),
            0,
            "a guard dropped during a panic unwind must still release its balance"
        );
    });
}

/// Two threads call `record_rtt` concurrently with samples `10.0` and `20.0` at
/// the same `now_ms`: every interleaving must terminate (the bounded, at-most-
/// two-attempt CAS cannot spin forever) and the final unpacked estimate must
/// lie in `[10.0, 20.0]`, the range spanned by the two samples actually
/// recorded.
#[test]
fn loom_ewma_cas_terminates_and_stays_in_range() {
    loom::model(|| {
        let stats = Arc::new(EndpointStats::default());
        let cfg = EwmaCfg::default();

        let s1 = Arc::clone(&stats);
        let t1 = thread::spawn(move || {
            s1.record_rtt(10.0, 1_000, &cfg);
        });

        let s2 = Arc::clone(&stats);
        let t2 = thread::spawn(move || {
            s2.record_rtt(20.0, 1_000, &cfg);
        });

        t1.join().expect("record_rtt must not panic");
        t2.join().expect("record_rtt must not panic");

        let (est, _) = unpack(stats.cost.load(Ordering::Relaxed));
        assert!(
            (10.0..=20.0).contains(&est),
            "final estimate {est} must lie within the sampled range [10, 20]"
        );
    });
}

/// One thread holds an [`InflightGuard`] and drops it; the other performs the
/// slot reset `EndpointRegistryWriter::intern` performs
/// (`crates/irontraffic-upstream/src/registry.rs`, out of scope for this
/// issue): `inflight.store(0)` then `generation.store(g + 1)`, in that exact
/// order, as two SEPARATE relaxed writes.
///
/// This is I-S5 under the model checker, and it is the only place the ordering
/// of `intern`'s two stores is exercised concurrently against a release.
///
/// The literal Drop body this issue's own text specifies -- one relaxed load of
/// `generation`, then, if it matches, one unconditional `fetch_sub` -- FAILS
/// this exact test: a direct `loom` reproduction of that shape reports
/// `inflight wrapped: 4294967295`, because the generation check and the
/// `fetch_sub` are two separate operations with a real gap between them, and
/// `intern`'s `inflight.store(0)` can land in that gap. `InflightGuard::drop`
/// in this crate instead loops, treating the CURRENT value of `inflight` (not
/// `generation` alone) as the final authority on whether anything is left to
/// release: it never subtracts from a counter already at `0`. See
/// `crate::stats::release_inflight`'s doc comment and the implementation report
/// for this issue for the full write-up.
///
/// With only one guard and one reset, the final value this crate's
/// implementation produces is always exactly `0`, in EVERY interleaving `loom`
/// explores, which is a strictly stronger result than the issue's own "either 0
/// or 1" (a hedge that is not reachable from a single guard and a single
/// reset: `inflight` starts at `1`, `intern`'s `store(0)` unconditionally lands
/// at some point, and after it lands the drop can only either release nothing,
/// because it observes `current == 0`, or the mismatched generation, both of
/// which leave the value at `0`; nothing here can ever increment it back
/// toward `1`). Asserting the exact value rather than the looser `0 || 1` is
/// deliberate: it is the stronger claim, and it still trivially satisfies "when
/// the drop is fully ordered before the reset the final value is 0", since `0`
/// is the only value this test ever produces.
#[test]
fn loom_guard_release_races_slot_recycle() {
    loom::model(|| {
        // A genuine `&'static EndpointStats`, not an `Arc`: the guard is
        // constructed here, BEFORE either thread is spawned, so that its drop
        // (not its acquire) is what races the simulated reset below, matching
        // this test's own description. `InflightGuard<'a>` borrows `&'a
        // EndpointStats`, and `loom::thread::spawn` requires `F: 'static`, so
        // moving a guard built from a stack-local `Arc<EndpointStats>` into a
        // spawned closure does not compile: `Arc::clone`s a thread receives
        // are fine on their own, but the GUARD itself, if built before
        // spawning from `&stats` rather than from a clone a thread owns, is
        // not. Leaking instead gives an actually-`'static` reference, which is
        // also exactly how production uses `InflightGuard`: see
        // `EndpointRegistry::install`'s own doc comment on why the arena is
        // leaked to `&'static` in the first place.
        let stats: &'static EndpointStats = Box::leak(Box::new(EndpointStats::default()));
        let guard = InflightGuard::acquire(stats);
        let gen_before = stats.generation.load(Ordering::Relaxed);

        let t1 = thread::spawn(move || {
            drop(guard);
        });

        let t2 = thread::spawn(move || {
            // The exact two-store sequence EndpointRegistryWriter::intern
            // performs on a recycled slot, `inflight` then `generation`.
            stats.inflight.store(0, Ordering::Relaxed);
            stats
                .generation
                .store(gen_before.wrapping_add(1), Ordering::Relaxed);
        });

        assert!(t1.join().is_ok(), "guard drop must not panic");
        assert!(t2.join().is_ok(), "the simulated reset must not panic");

        let final_inflight = stats.inflight();
        assert_ne!(
            final_inflight,
            u32::MAX,
            "a guard outstanding across a recycle must never wrap the new tenant's counter"
        );
        assert!(
            final_inflight == 0 || final_inflight == 1,
            "final inflight must be 0 or 1, got {final_inflight}"
        );
        assert_eq!(
            final_inflight, 0,
            "with exactly one guard and one reset, 0 is the only reachable final value"
        );
    });
}
