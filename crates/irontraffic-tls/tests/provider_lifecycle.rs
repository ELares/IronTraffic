// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process-isolated test of the crypto provider install lifecycle (issue #556).
//!
//! `provider_lifecycle`, below, asserts PRE-INSTALL process state before calling
//! `install_process_provider`, which is process-global and installable at most once per
//! process. It used to be a `--lib` unit test inside `irontraffic-tls`'s own `src/provider.rs`,
//! where `cargo test` runs every unit test of the crate, across every module, in ONE process:
//! any sibling test anywhere in the crate that also needed `irontraffic_tls::provider::provider`
//! to return `Some` (cert-credentials-and-der-interning, #114, and policy-and-protocol-versions,
//! #116, both do) raced this test for the one process-wide provider slot and broke its
//! precondition assertions on almost every run.
//!
//! It lives here instead because every file under `tests/` compiles to its own binary with its
//! own process: nothing else in the workspace can touch this process's crypto provider slot
//! before these assertions run, guaranteed by the OS rather than by convention across every
//! current and future unit test module in the crate's `--lib` binary.

use irontraffic_tls::provider::provider;
use irontraffic_tls::{
    ProviderError, ProviderKind, fips_active, install_process_provider, post_quantum_available,
    provider_kind,
};

// Provider installation is process-global, and this file is its own process: no other test in
// the workspace can run in it. Exactly one test function in this file may call
// `install_process_provider`, and every assertion whose answer depends on installation lives
// inside that function, in order. Do not split them and do not rely on test execution order.
#[test]
fn provider_lifecycle() {
    assert_eq!(provider_kind(), None);
    // Invariant 3 / edge case 7: fips_active() must be false before installation,
    // not merely equal to cfg!(feature = "crypto-fips"). A fips_active()
    // implemented as bare cfg!(feature = "crypto-fips") (explicitly forbidden)
    // would return true here on a crypto-fips build, before anything is
    // installed, and this assertion is the only place that shape is checked.
    assert!(!fips_active());
    // The crate's one job is putting a provider in place process-wide. Assert
    // the pre-state directly against rustls, not just against this crate's own
    // provider_kind() bookkeeping, so a install_process_provider() that never
    // calls install_default cannot pass by only touching its own OnceLock.
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let expected = if cfg!(feature = "crypto-ring") {
        ProviderKind::Ring
    } else if cfg!(feature = "crypto-fips") {
        ProviderKind::AwsLcRsFips
    } else {
        ProviderKind::AwsLcRs
    };
    assert_eq!(install_process_provider(), Ok(expected));
    assert_eq!(provider_kind(), Some(expected));
    assert_eq!(fips_active(), cfg!(feature = "crypto-fips"));
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    // provider() must actually expose what was installed above, and must still
    // require provider_kind() to be Some to get there (checked in isolation:
    // this cannot observe the fail-open case where SOME OTHER provider was
    // installed before ours, which needs a separate test binary; see #112).
    assert!(provider().is_some());
    let installed = rustls::crypto::CryptoProvider::get_default().expect("installed above");
    let first_is_hybrid = installed.kx_groups[0].name() == rustls::NamedGroup::X25519MLKEM768;
    assert_eq!(first_is_hybrid, post_quantum_available());
    assert_eq!(
        install_process_provider(),
        Err(ProviderError::AlreadyInstalled)
    );
    assert_eq!(provider_kind(), Some(expected));
}
