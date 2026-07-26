// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared shed-pressure primitive for the resilience subsystems.

use core::sync::atomic::{AtomicU16, Ordering};
use crossbeam_utils::CachePadded;

/// A published shed-pressure level in basis points: 0 means no pressure, `10_000`
/// means shed everything.
///
/// Written by the overload manager and by outlier detection's panic-mode check, read
/// on the request path by the shed stack and the hedge policy. Cache-line padded so
/// that a request-path read never false-shares with an unrelated counter. This is a
/// published level, not a balance, so the setter is public and idempotent.
pub struct SharedPressure(CachePadded<AtomicU16>);

impl SharedPressure {
    /// A new cell at zero pressure. Equivalent to `SharedPressure::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self(CachePadded::new(AtomicU16::new(0)))
    }

    /// The current pressure in basis points, always in `0..=10_000`.
    #[inline]
    #[must_use]
    pub fn get_bp(&self) -> u16 {
        self.0.load(Ordering::Relaxed)
    }

    /// Publish `bp`, clamped to `0..=10_000`.
    #[inline]
    pub fn set_bp(&self, bp: u16) {
        AtomicU16::store(&self.0, bp.min(10_000), Ordering::Relaxed);
    }

    /// Publish `max(current, bp)`, clamped. Used when two independent sources both
    /// raise pressure and the higher must win.
    #[inline]
    pub fn raise_to_bp(&self, bp: u16) {
        let clamped = bp.min(10_000);
        let _ = self.0.fetch_max(clamped, Ordering::Relaxed);
    }
}

impl Default for SharedPressure {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for SharedPressure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedPressure")
            .field("bp", &self.get_bp())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_clamps_high() {
        let p = SharedPressure::new();
        p.set_bp(20_000);
        assert_eq!(p.get_bp(), 10_000);
    }

    #[test]
    fn pressure_raise_keeps_max() {
        let p = SharedPressure::new();
        p.set_bp(3_000);
        p.raise_to_bp(1_000);
        assert_eq!(p.get_bp(), 3_000);
        p.raise_to_bp(9_000);
        assert_eq!(p.get_bp(), 9_000);
    }

    #[test]
    fn pressure_default_is_zero() {
        assert_eq!(SharedPressure::new().get_bp(), 0);
    }
}
