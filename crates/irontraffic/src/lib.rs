// SPDX-License-Identifier: MIT OR Apache-2.0
//! IronTraffic: a traffic and API manager.
//!
//! This crate is the single entry point for every server mode. `main.rs` is a
//! thin shell over this library so that everything it does is testable; that
//! split is deliberate and must be preserved as the modes are implemented.
//!
//! # Modes
//!
//! Which product IronTraffic acts as is a runtime mode and a compile-time
//! feature set, never a different binary. The modes are:
//!
//! - [`Mode::Run`], the default: data plane, control plane, and dashboard in
//!   one process. This is what a standalone or k3s user gets, and it must work
//!   from one configuration file with no external dependency of any kind.
//! - [`Mode::Proxy`]: data plane only, for the hardened horizontally scaled
//!   tier, with no Kubernetes client, no consensus, and no admin write path in
//!   its address space.
//! - [`Mode::Control`]: control plane only, owning the configuration store,
//!   cluster membership, the admin API, the dashboard, and the Kubernetes
//!   controller.
//! - [`Mode::Validate`]: parse, validate, and diff a configuration without
//!   serving. The exit code is the answer, so continuous integration can gate
//!   on a configuration change before it is applied.
//!
//! See `ARCHITECTURE.md` for why this is one binary rather than a family.

/// The crate version, as reported by `irontraffic --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The server mode selected on the command line.
///
/// ```
/// use irontraffic::Mode;
/// assert_eq!(Mode::parse("run"), Some(Mode::Run));
/// assert_eq!(Mode::parse("validate"), Some(Mode::Validate));
/// assert_eq!(Mode::parse("nonsense"), None);
/// // The default is the batteries-included single-process mode.
/// assert_eq!(Mode::default(), Mode::Run);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Data plane, control plane, and dashboard in one process.
    #[default]
    Run,
    /// Data plane only.
    Proxy,
    /// Control plane only.
    Control,
    /// Validate a configuration and exit.
    Validate,
}

impl Mode {
    /// Parses a mode name, returning `None` for anything unrecognized.
    ///
    /// Unknown modes are rejected rather than defaulted, because silently
    /// falling back to `Run` would let a typo in a systemd unit or a container
    /// command turn a hardened data-plane deployment into one that also
    /// exposes an admin write path.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "run" => Some(Self::Run),
            "proxy" => Some(Self::Proxy),
            "control" => Some(Self::Control),
            "validate" => Some(Self::Validate),
            _ => None,
        }
    }

    /// The mode name as it appears on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Proxy => "proxy",
            Self::Control => "control",
            Self::Validate => "validate",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mode, VERSION};

    #[test]
    fn version_is_populated_from_cargo() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert!(!VERSION.is_empty(), "version string must not be empty");
    }

    #[test]
    fn every_mode_round_trips_through_its_name() {
        for mode in [Mode::Run, Mode::Proxy, Mode::Control, Mode::Validate] {
            assert_eq!(
                Mode::parse(mode.as_str()),
                Some(mode),
                "{mode:?} did not round trip through {:?}",
                mode.as_str()
            );
        }
    }

    #[test]
    fn an_unknown_mode_is_rejected_rather_than_defaulted() {
        // A typo must not silently select the mode with the largest surface.
        assert_eq!(Mode::parse("Run"), None);
        assert_eq!(Mode::parse(""), None);
        assert_eq!(Mode::parse("serve"), None);
    }

    #[test]
    fn the_default_mode_is_run() {
        assert_eq!(Mode::default(), Mode::Run);
    }
}
