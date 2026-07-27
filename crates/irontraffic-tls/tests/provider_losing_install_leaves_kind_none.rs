// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process-isolated test that a LOSING install does not mutate `provider_kind()` (issue #623).
//!
//! This occupies the process-wide rustls crypto provider slot from OUTSIDE
//! `install_process_provider` before ever calling it, which guarantees that call can only
//! lose. No other test in the workspace may share this process's crypto provider slot (it
//! is a global, installable-once-per-process resource), so this lives in its own file under
//! `tests/`, exactly as `src/provider.rs`'s own "THE RULE FOR FUTURE TESTS" comment
//! prescribes for any test whose expected answer depends on winning or losing that race.
//!
//! This replaces the decorative `assert_eq!(provider_kind(), Some(THIS_KIND))` that PR 612
//! added to the shared `--lib` test binary under a comment claiming it proved "a losing
//! install must not mutate the installed kind" (issue #623). That assertion could not prove
//! it: `provider_kind()` reads a `OnceLock<ProviderKind>` whose only value ever written by
//! this crate is the compile-time constant `THIS_KIND`, so comparing it to `Some(THIS_KIND)`
//! cannot distinguish "the loser wrote it" from "the winner wrote it, and this call lost". In
//! the shared binary there is no sibling installer, so the call under test always wins, and
//! the assertion only ever detects "no install happened at all", which the adjacent
//! `assert!(provider().is_some())` and an identical `assert_eq!` two lines below already
//! detect; `cargo mutants` confirmed it killed zero mutants.
//!
//! This test forces the losing path for real (a foreign install occupies the slot first,
//! regardless of which `crypto-*` feature this crate was built with) and checks the one
//! thing that matters: that losing leaves `provider_kind()` at `None` rather than the
//! compiled-in kind. Under a `crypto-fips` build this also pins the consequence the
//! reviewer called out: a losing install that wrongly set `INSTALLED` would make
//! `fips_active()` report `true` while a non-FIPS provider is the real process default, a
//! FIPS fail-open silent to every other test in the suite.

use irontraffic_tls::{ProviderError, fips_active, install_process_provider, provider_kind};

#[test]
fn losing_install_leaves_provider_kind_none() {
    assert_eq!(provider_kind(), None);
    assert!(!fips_active());

    // Occupy the process-wide rustls default from OUTSIDE `install_process_provider`
    // before it ever runs, so its call below is guaranteed to lose. It does not need to
    // be a different crypto backend from this build's own `THIS_KIND`; which constructor
    // is reachable depends on which single `crypto-*` feature this crate was built with
    // (they are mutually exclusive, see the compile_error!s in src/provider.rs), so this
    // mirrors install_process_provider's own cfg-gated selection rather than hardcoding
    // one backend that would fail to compile under the other two features. Inlined here
    // (not a helper fn) so clippy's `allow-expect-in-tests` recognizes the `.expect()`
    // below as test code: that recognition keys off the enclosing function actually being
    // `#[test]`-attributed, not merely living in a file under `tests/`.
    #[cfg(any(feature = "crypto-aws-lc-rs", feature = "crypto-fips"))]
    let foreign_provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "crypto-ring")]
    let foreign_provider = rustls::crypto::ring::default_provider();
    rustls::crypto::CryptoProvider::install_default(foreign_provider)
        .expect("this process's rustls default is uninstalled: no other test shares this binary");

    // The rustls process default is already claimed, so this call can only lose.
    assert_eq!(
        install_process_provider(),
        Err(ProviderError::AlreadyInstalled)
    );
    // The property PR 612's decorative assertion could not check: a LOSING install must
    // not mutate the installed kind. A `install_process_provider` that reported
    // `AlreadyInstalled` while still writing `THIS_KIND` into `INSTALLED` would pass every
    // other assertion in the suite and fail only this one.
    assert_eq!(provider_kind(), None);
    // Consequence for a crypto-fips build: fips_active() must stay false too. The foreign
    // provider installed above is not this build's FIPS-checked provider, so a
    // fips_active() that returned true here would report FIPS mode active while the real
    // process default is not a FIPS provider at all, a fail-open a fips-marketed
    // deployment has no other way to detect.
    assert!(!fips_active());
}
