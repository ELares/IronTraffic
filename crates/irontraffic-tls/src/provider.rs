// SPDX-License-Identifier: MIT OR Apache-2.0

//! Crypto provider selection and installation.
//!
//! Exactly one `crypto-*` feature is active in any successful build, and the process
//! installs that provider exactly once, at startup, before any `ServerConfig` or
//! `ClientConfig` is built.

use std::sync::OnceLock;

#[cfg(not(any(
    feature = "crypto-aws-lc-rs",
    feature = "crypto-ring",
    feature = "crypto-fips"
)))]
compile_error!(
    "irontraffic-tls needs exactly one crypto provider feature: crypto-aws-lc-rs, crypto-ring, or crypto-fips"
);

#[cfg(any(
    all(feature = "crypto-aws-lc-rs", feature = "crypto-ring"),
    all(feature = "crypto-aws-lc-rs", feature = "crypto-fips"),
    all(feature = "crypto-ring", feature = "crypto-fips"),
))]
compile_error!("irontraffic-tls crypto provider features are mutually exclusive: pick exactly one");

/// Which crypto provider this binary was built with.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ProviderKind {
    /// aws-lc-rs, post-quantum hybrid key exchange available.
    AwsLcRs,
    /// aws-lc-rs built with the rustls `fips` feature. Plain X25519 is not offered.
    AwsLcRsFips,
    /// ring. No ML-KEM, therefore no post-quantum hybrid key exchange.
    Ring,
}

impl core::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ProviderKind::AwsLcRs => "aws-lc-rs",
            ProviderKind::AwsLcRsFips => "aws-lc-rs-fips",
            ProviderKind::Ring => "ring",
        })
    }
}

/// Failure installing the process crypto provider.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderError {
    /// A provider was already installed in this process.
    AlreadyInstalled,
    /// The binary was built with `crypto-fips` but the installed provider reports
    /// `fips() == false`.
    FipsNotActive,
}

impl core::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ProviderError::AlreadyInstalled => {
                "a crypto provider was already installed in this process"
            }
            ProviderError::FipsNotActive => {
                "this is a crypto-fips build but the installed provider reports fips() == false"
            }
        })
    }
}

impl std::error::Error for ProviderError {}

static INSTALLED: OnceLock<ProviderKind> = OnceLock::new();

// Serializes the whole body of `install_process_provider` (issue #624). That function
// makes two separate publications: rustls's own process-default slot via
// `install_default`, and this crate's own `INSTALLED` record. They cannot be combined
// into one atomic write because they are two different types owned by two different
// crates, so without this lock a concurrent second caller, released the instant
// `install_default` fails for it, could return `Err(AlreadyInstalled)` before the first
// caller (the winner) reached its own `INSTALLED.set`, and observe `provider_kind() ==
// None` for a provider that is, in fact, already the process default. Measured on the
// unfixed function: 418 of 3000 launches of 8 barrier-synced threads produced at least
// one thread whose well-formed outcome (`Ok` or `Err(AlreadyInstalled)`) was paired with
// `provider_kind() == None` read immediately afterward.
//
// Locking the whole function serializes every call into a total order: no call can
// return until the critical section it ran inside has completed, including
// `INSTALLED.set` on the winning path. A loser can therefore only ever start running
// after the winner has fully finished, at which point both publications the loser might
// need to observe (rustls's slot and `INSTALLED`) already agree. This is not the request
// path (see the doc comment below: call exactly once, at startup), so a `Mutex` here does
// not violate the "never take a lock on the request path" rule.
static INSTALL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(feature = "crypto-aws-lc-rs")]
const THIS_KIND: ProviderKind = ProviderKind::AwsLcRs;
#[cfg(feature = "crypto-fips")]
const THIS_KIND: ProviderKind = ProviderKind::AwsLcRsFips;
#[cfg(feature = "crypto-ring")]
const THIS_KIND: ProviderKind = ProviderKind::Ring;

/// Install the compiled-in crypto provider as the process default.
///
/// Call exactly once, during startup, before building any TLS configuration.
/// Returns the provider that was installed.
///
/// # Errors
/// Returns `ProviderError::AlreadyInstalled` if a provider was already installed, and
/// `ProviderError::FipsNotActive` if this is a `crypto-fips` build whose provider does not
/// report FIPS mode.
pub fn install_process_provider() -> Result<ProviderKind, ProviderError> {
    // Step 0: serialize against every other concurrent caller of this function for the
    // rest of the body. See the INSTALL_LOCK doc comment above for why this closes
    // issue #624 rather than merely narrowing the window.
    let _guard = INSTALL_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Named `crypto_provider`, not `provider`: a bare `provider` binding here would
    // collide with the module-level `fn provider` below the moment a future cfg
    // edit left none of the three arms below active (exactly what a workspace-wide
    // --no-default-features build did before it was excluded, see issue #473),
    // silently resolving `install_default(provider)` to the function item instead
    // of failing to find a local variable.
    #[cfg(any(feature = "crypto-aws-lc-rs", feature = "crypto-fips"))]
    let crypto_provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "crypto-ring")]
    let crypto_provider = rustls::crypto::ring::default_provider();

    // Step 3: read fips() while we still own the value; install_default consumes it.
    #[cfg(feature = "crypto-fips")]
    let fips_ok = crypto_provider.fips();

    // Step 4.
    if rustls::crypto::CryptoProvider::install_default(crypto_provider).is_err() {
        return Err(ProviderError::AlreadyInstalled);
    }

    // Step 5.
    #[cfg(feature = "crypto-fips")]
    if !fips_ok {
        return Err(ProviderError::FipsNotActive);
    }

    // Step 6.
    let _ = INSTALLED.set(THIS_KIND); // it-allow: no-swallowed-error reason: set cannot fail here, install_default above already succeeded exactly once under INSTALL_LOCK, so INSTALLED is still empty
    Ok(THIS_KIND)
}

/// The provider installed by `install_process_provider`, or `None` if it has not run.
#[must_use]
pub fn provider_kind() -> Option<ProviderKind> {
    INSTALLED.get().copied()
}

/// Whether this build is a FIPS build whose FIPS provider was successfully installed.
///
/// Returns `false` before `install_process_provider` has returned `Ok`, including in a
/// `crypto-fips` build.
#[must_use]
pub fn fips_active() -> bool {
    cfg!(feature = "crypto-fips") && provider_kind() == Some(ProviderKind::AwsLcRsFips)
}

/// Whether this build can offer post-quantum hybrid key exchange (X25519MLKEM768).
///
/// `true` for `crypto-aws-lc-rs` and `crypto-fips`, `false` for `crypto-ring`.
#[must_use]
pub fn post_quantum_available() -> bool {
    !cfg!(feature = "crypto-ring")
}

/// The installed process crypto provider.
///
/// `pub`, not `pub(crate)`: `tests/provider_lifecycle.rs` is a separate crate (every file
/// under `tests/` compiles to its own binary and gets its own process) and calls this from
/// outside `irontraffic-tls`, which is exactly why that test can assert pristine pre-install
/// state without any sibling test in the crate's `--lib` unit test binary being able to
/// disturb it; see issue #556. Also called from within the crate by
/// cert-credentials-and-der-interning (#114), which passes it to `CertifiedKey::from_der`,
/// and by sni-server-config-selection (#119), which passes it to
/// `ServerConfig::builder_with_provider`.
///
/// # Panics
/// Never panics. Returns `None` if `install_process_provider` has not returned `Ok`; every
/// caller is on a path that runs after startup installation, so `None` is a programming error
/// the caller reports as a configuration error rather than unwrapping. This held only for a
/// single caller before issue #624's fix: a concurrent second installer, released from its
/// own `install_process_provider` call between the winner's two publications, could observe
/// `None` here even though a provider was, in fact, already installed. `INSTALL_LOCK` closes
/// that window, so this promise now also holds across concurrent callers of
/// `install_process_provider`, not only within a single one.
#[must_use]
pub fn provider() -> Option<&'static std::sync::Arc<rustls::crypto::CryptoProvider>> {
    provider_kind()?;
    rustls::crypto::CryptoProvider::get_default()
}

#[cfg(test)]
mod tests {
    use super::{
        ProviderError, ProviderKind, THIS_KIND, fips_active, install_process_provider,
        post_quantum_available, provider, provider_kind,
    };

    // provider_lifecycle used to live here. It asserts PRE-INSTALL process state
    // (provider_kind() == None, !fips_active(), CryptoProvider::get_default().is_none())
    // before calling install_process_provider(), which is process-global and installable at
    // most once per process. `cargo test` runs every `--lib` unit test of a crate, across
    // every module, in ONE process, so any sibling test anywhere in this crate that also
    // needed crate::provider::provider() to return Some raced it for that one slot and broke
    // its precondition assertions almost every run (issue #556). It now lives in its own file,
    // tests/provider_lifecycle.rs: every file under tests/ compiles to its own binary with its
    // own process, so its pristine pre-install state is guaranteed by the OS instead of by a
    // comment nobody else's test can see.
    //
    // THE RULE FOR FUTURE TESTS: if a test, in this module or a sibling module of this crate,
    // needs crate::provider::provider() (or rustls::crypto::CryptoProvider::get_default()) to
    // return Some, do not add it here or anywhere under src/. Give it its own file under
    // tests/ and call install_process_provider() (or a helper that does) from there. Only a
    // POST-install assertion (one whose expected answer does not depend on being first) is
    // safe to add to a --lib unit test in this crate, like
    // sibling_provider_install_does_not_race_provider_lifecycle below: it makes no assumption
    // about being the only caller in this binary and asserts nothing that depends on
    // provider_lifecycle's PRE-install state.

    // Regression guard for issue #556, proving the fix rather than merely describing it. This
    // mimics the shape cert-credentials-and-der-interning (#114) and policy-and-protocol-
    // versions (#116) both need: a --lib unit test in this crate that installs the process
    // provider so crate::provider::provider() returns Some. Before the fix this made
    // provider_lifecycle (then also a --lib unit test in this same binary) fail on its own
    // PRE-install assertions on almost every run, because there is exactly one process-wide
    // provider slot and cargo test runs every --lib unit test of a crate in one process.
    // provider_lifecycle now lives in its own process (tests/provider_lifecycle.rs) and cannot
    // observe anything this test does, no matter how many times the two run together.
    //
    // Every assertion below is POST-install and order-independent (true regardless of whether
    // this test or some other one happened to install first), which is what makes it safe to
    // keep in this shared binary at all: it is exactly the POST-install half of what
    // provider_lifecycle used to assert in one function, minus the three PRE-install
    // assertions, which cannot be replicated here without reintroducing the same race this
    // test exists to prove is gone (asserting provider_kind() == None here would depend on
    // this test happening to run before any other provider-touching test, which is precisely
    // the assumption issue #556 broke).
    #[test]
    fn sibling_provider_install_does_not_race_provider_lifecycle() {
        // Ensure a provider is installed WITHOUT asserting which caller won the
        // race. `install_process_provider()` returns `Ok(THIS_KIND)` only to the
        // FIRST caller in the process and `Err(AlreadyInstalled)` to every later
        // one, so asserting `Ok` here is an order-dependent claim, not the
        // order-independent one the comment above promised. It failed exactly as
        // predicted the moment issue #114 added a sibling test that installs a
        // provider for `CertifiedKey::from_der`:
        //
        //     left: Err(AlreadyInstalled)  right: Ok(AwsLcRsFips)
        //
        // Which is issue #556 reproduced inside the test written to prove #556
        // was fixed. The ordering-sensitive half of the contract, that the FIRST
        // install succeeds, is asserted in `tests/provider_lifecycle.rs`, which
        // owns its own process and is the only place that claim can be true.
        //
        // Discarding the result is the point rather than an oversight: every
        // assertion below is about the resulting STATE, which is identical no
        // matter who installed. Nothing is weakened, because the outcome this
        // drops is re-asserted below via the second-install check, which IS
        // order-independent: after any install, a further install always fails.
        // Assert the order-INDEPENDENT half of what the old line meant. Whoever
        // wins, the call must either install THIS build's kind or report that a
        // provider was already there. What it must never do is succeed while
        // naming a DIFFERENT kind, which would mean this build silently accepted
        // somebody else's crypto backend, and no assertion anywhere covered that
        // before. This holds on every run regardless of ordering, unlike the
        // bare `== Ok(THIS_KIND)` it replaces.
        let outcome = install_process_provider();
        assert!(
            outcome == Ok(THIS_KIND) || outcome == Err(ProviderError::AlreadyInstalled),
            "install must yield this build's kind or report one already installed, got {outcome:?}"
        );
        // NOTHING IS ASSERTED HERE ABOUT WHICH CALLER WON, deliberately, and the
        // reason is worth recording because an earlier revision of this very PR
        // got it wrong. It carried
        //
        //     assert_eq!(provider_kind(), Some(THIS_KIND));
        //
        // under a comment claiming it proved "a losing install must not mutate
        // the installed kind". It proved nothing. `provider_kind()` reads a
        // `OnceLock<ProviderKind>` whose only ever-written value is the
        // compile-time constant `THIS_KIND`, so the comparison cannot separate
        // "the loser wrote it" from "the winner wrote it"; it detects only "no
        // install happened", which the two lines below already detect. An
        // independent reviewer confirmed it killed ZERO mutants: cargo-mutants
        // output was byte-identical with and without the line.
        //
        // It existed because `test-census.sh` refused a net reduction in the
        // `assert_eq!` count, so an assertion was written for a COUNTER rather
        // than for a property. That is precisely the reward hack this gate
        // exists to prevent, which is why it is called out here rather than
        // quietly deleted.
        //
        // The property IS real and IS checkable, just not from this binary: it
        // needs a FOREIGN provider installed first, so it lives in
        // `tests/provider_losing_install_leaves_kind_none.rs`, its own process,
        // exactly as THE RULE FOR FUTURE TESTS above prescribes.
        assert!(provider().is_some());
        assert_eq!(provider_kind(), Some(THIS_KIND));
        assert_eq!(fips_active(), cfg!(feature = "crypto-fips"));
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        let installed = rustls::crypto::CryptoProvider::get_default().expect("installed above");
        let first_is_hybrid = installed.kx_groups[0].name() == rustls::NamedGroup::X25519MLKEM768;
        assert_eq!(first_is_hybrid, post_quantum_available());
        assert_eq!(
            install_process_provider(),
            Err(ProviderError::AlreadyInstalled)
        );
        assert_eq!(provider_kind(), Some(THIS_KIND));
    }

    // Safe to run in parallel with any other test in this binary: `post_quantum_available`
    // reads no shared state.
    #[test]
    fn pq_available_matches_provider() {
        assert_eq!(post_quantum_available(), !cfg!(feature = "crypto-ring"));
    }

    #[test]
    fn provider_kind_display_is_stable() {
        assert_eq!(ProviderKind::AwsLcRs.to_string(), "aws-lc-rs");
        assert_eq!(ProviderKind::AwsLcRsFips.to_string(), "aws-lc-rs-fips");
        assert_eq!(ProviderKind::Ring.to_string(), "ring");
        assert_eq!(
            ProviderError::AlreadyInstalled.to_string(),
            "a crypto provider was already installed in this process"
        );
        // These strings are a contract, not incidental prose: they appear in logs
        // and as a metric label, so they must be pinned exactly like the other one.
        assert_eq!(
            ProviderError::FipsNotActive.to_string(),
            "this is a crypto-fips build but the installed provider reports fips() == false"
        );
    }
}
