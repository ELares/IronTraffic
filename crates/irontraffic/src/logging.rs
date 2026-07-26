// SPDX-License-Identifier: MIT OR Apache-2.0
//! Subscriber initialisation for the IronTraffic binary.

/// Result of installing the subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitOutcome {
    /// The subscriber was installed with the filter taken from the environment.
    Installed,
    /// The environment filter was unparsable and `info` was installed instead.
    InstalledWithFallback,
    /// A subscriber was already installed; this call did nothing.
    AlreadyInstalled,
}

/// Installs the process-wide `tracing` subscriber.
///
/// The filter is read from `IRONTRAFFIC_LOG` and defaults to `info`. An unparsable
/// filter is reported at WARN and replaced with `info`. Calling this more than once
/// is a no-op after the first success; the return value says which happened.
pub(crate) fn init() -> InitOutcome {
    let raw = std::env::var("IRONTRAFFIC_LOG").unwrap_or_default();
    let spec = if raw.trim().is_empty() {
        "info"
    } else {
        raw.as_str()
    };

    let (filter, fell_back) = match tracing_subscriber::EnvFilter::try_new(spec) {
        Ok(f) => (f, false),
        Err(_) => (tracing_subscriber::EnvFilter::new("info"), true),
    };

    let installed = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init()
        .is_ok();

    if !installed {
        return InitOutcome::AlreadyInstalled;
    }

    if fell_back {
        tracing::warn!(filter = %spec, "IRONTRAFFIC_LOG is not a valid filter; using info");
        return InitOutcome::InstalledWithFallback;
    }

    InitOutcome::Installed
}
