// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process-isolated regression guard for issue #624, proving the fix rather than merely
//! describing it.
//!
//! `install_process_provider` makes two separate publications: rustls's own process-default
//! slot via `install_default`, and this crate's own `INSTALLED` record. Before `INSTALL_LOCK`
//! (see `src/provider.rs`), a concurrent second caller, released the instant `install_default`
//! failed for it, could return a well-formed outcome (`Ok` or `Err(AlreadyInstalled)`) while
//! the winner still sat between those two publications, and observe `provider_kind() == None`
//! for a provider that was, in fact, already the process default.
//!
//! This spawns several threads, barrier-synced so they all call `install_process_provider`
//! at once, and has each one read `provider_kind()` immediately after its own call returns.
//! Every one of those reads must already agree with the call's own outcome: whichever thread
//! is the true winner set `INSTALLED` before `INSTALL_LOCK` let ANY other thread's call
//! through, so by the time a thread's own call has returned at all, `provider_kind()` is
//! already settled, not merely "eventually consistent" once every thread has joined.
//!
//! This lives in its own file under `tests/`, per `src/provider.rs`'s "THE RULE FOR FUTURE
//! TESTS": a test that needs `install_process_provider` to actually run cannot share a process
//! with any other provider-touching test.
//!
//! Measured on the unfixed function (`cargo test`, this exact shape, 8 threads): 418 of 3000
//! process launches produced at least one thread whose well-formed outcome was paired with
//! `provider_kind() == None`. After the `INSTALL_LOCK` fix: 0 of 3000. This single run cannot
//! reproduce that rate by itself (each process gets only one race, since the provider slot is
//! installable once per process), but with the fix in place the outcome is no longer
//! probabilistic at all: `INSTALL_LOCK` makes every call observe a fully-settled state, so this
//! assertion holds on every run, not merely on most of them.

use std::sync::{Arc, Barrier};
use std::thread;

use irontraffic_tls::{ProviderError, install_process_provider, provider_kind};

#[test]
fn concurrent_installers_never_observe_kind_none_after_a_well_formed_outcome() {
    const THREADS: usize = 8;
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let outcome = install_process_provider();
                let kind_immediately_after = provider_kind();
                (outcome, kind_immediately_after)
            })
        })
        .collect();

    let mut saw_a_winner = false;
    for handle in handles {
        let (outcome, kind_immediately_after) = handle.join().expect("installer thread panicked");
        match outcome {
            Ok(kind) => {
                saw_a_winner = true;
                // The winner's own call cannot return Ok before INSTALLED.set has run: it is
                // the last statement before the Ok return, under the same INSTALL_LOCK guard.
                assert_eq!(kind_immediately_after, Some(kind));
            }
            Err(ProviderError::AlreadyInstalled) => {
                // This is the property issue #624 was about: a loser must not observe
                // provider_kind() == None. Something DID win (either a sibling thread here,
                // or nothing yet if every thread in this run happened to lose to an external
                // caller, which cannot happen in this test binary), so this must be Some.
                assert!(
                    kind_immediately_after.is_some(),
                    "a losing install observed provider_kind() == None: the exact issue #624 race"
                );
            }
            // Any other error (today only `FipsNotActive`, reachable on a crypto-fips build
            // whose provider fails its own FIPS check, plus whatever variant `ProviderError`
            // gains later: it is `#[non_exhaustive]`) is unrelated to the race under test;
            // INSTALLED correctly stays unset either way.
            Err(_) => {}
        }
    }
    assert!(
        saw_a_winner,
        "no thread reported Ok: at least one of these racers must be the process's first installer"
    );
}
