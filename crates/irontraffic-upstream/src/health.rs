// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`EndpointHealth`]: health state as decided by the health checker and the
//! outlier detector.

/// Health state of one endpoint, as decided by the health checker and the
/// outlier detector. Written by the control plane, consumed by the snapshot
/// builder.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum EndpointHealth {
    /// Passing health checks and not ejected.
    #[default]
    Healthy,
    /// Passing but marked degraded; eligible only when degraded routing is
    /// enabled.
    Degraded,
    /// Failing health checks.
    Unhealthy,
    /// Ejected by passive outlier detection.
    Ejected,
    /// Administratively draining: keeps existing connections and affinity, takes
    /// no new traffic (this is what `weight == 0` means and it is expressed here
    /// as well).
    Draining,
}
