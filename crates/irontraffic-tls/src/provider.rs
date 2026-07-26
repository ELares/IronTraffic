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
    let _ = INSTALLED.set(THIS_KIND); // it-allow: no-swallowed-error reason: set cannot fail here, install_default above already succeeded exactly once, so INSTALLED is still empty
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
/// # Panics
/// Never panics. Returns `None` if `install_process_provider` has not returned `Ok`; every
/// caller is on a path that runs after startup installation, so `None` is a programming error
/// the caller reports as a configuration error rather than unwrapping.
#[allow(
    dead_code,
    reason = "called by cert-credentials-and-der-interning (#114), which passes it to \
              CertifiedKey::from_der, and by sni-server-config-selection (#119), which passes it \
              to ServerConfig::builder_with_provider; neither sibling issue is in the tree yet, \
              so this accessor has no caller until they land"
)]
pub(crate) fn provider() -> Option<&'static std::sync::Arc<rustls::crypto::CryptoProvider>> {
    provider_kind()?;
    rustls::crypto::CryptoProvider::get_default()
}

#[cfg(test)]
mod tests {
    use super::{ProviderError, ProviderKind, fips_active, install_process_provider};
    use super::{post_quantum_available, provider, provider_kind};

    // Provider installation is process-global and `cargo test` runs the tests of one binary
    // in parallel threads of one process. Exactly one test function may call
    // `install_process_provider`, and every assertion whose answer depends on installation
    // lives inside that function, in order. Do not split them and do not rely on test
    // execution order.
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

    // Safe to run in parallel with `provider_lifecycle`: `post_quantum_available` reads no
    // shared state.
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
