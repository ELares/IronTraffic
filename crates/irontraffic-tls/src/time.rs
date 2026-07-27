// SPDX-License-Identifier: MIT OR Apache-2.0

//! A wall-clock instant expressed as whole seconds since the Unix epoch.
//!
//! [`UnixSeconds`] is a pure value type: it is parsed out of a certificate's ASN.1 `Time`
//! field, never read from a live clock, and every arithmetic operation on it saturates
//! instead of overflowing or panicking. Reading the process's actual notion of "now" still
//! flows through the `irontraffic-time` seam, exactly as everywhere else in the workspace;
//! this type only represents a point in time that arrived over the wire, inside a
//! certificate, not one this process measured itself.

/// A wall-clock instant as whole seconds since the Unix epoch.
///
/// This is a value type, parsed from DER or converted from `irontraffic_time::CoarseWall`.
/// Reading the current time still goes through the `irontraffic-time` seam; constructing a
/// `UnixSeconds` does not read any clock.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct UnixSeconds(u64);

impl UnixSeconds {
    /// Wrap a raw seconds value.
    #[must_use]
    pub const fn new(secs: u64) -> Self {
        Self(secs)
    }

    /// The raw seconds value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// `self + secs`, saturating at `u64::MAX`.
    #[must_use]
    pub const fn saturating_add_secs(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }

    /// `self - other` in seconds, saturating at 0.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> u64 {
        self.0.saturating_sub(other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::UnixSeconds;

    #[test]
    fn new_and_get_roundtrip() {
        assert_eq!(UnixSeconds::new(42).get(), 42);
        assert_eq!(UnixSeconds::new(0).get(), 0);
    }

    #[test]
    fn ordering_matches_raw_value() {
        assert!(UnixSeconds::new(5) < UnixSeconds::new(6));
        assert_eq!(UnixSeconds::new(5), UnixSeconds::new(5));
        assert!(UnixSeconds::new(7) > UnixSeconds::new(6));
    }

    #[test]
    fn saturating_add_secs_saturates_at_max() {
        assert_eq!(UnixSeconds::new(10).saturating_add_secs(5).get(), 15);
        assert_eq!(
            UnixSeconds::new(u64::MAX - 1).saturating_add_secs(10).get(),
            u64::MAX
        );
    }

    #[test]
    fn saturating_sub_saturates_at_zero() {
        assert_eq!(UnixSeconds::new(10).saturating_sub(UnixSeconds::new(3)), 7);
        assert_eq!(UnixSeconds::new(3).saturating_sub(UnixSeconds::new(10)), 0);
        assert_eq!(UnixSeconds::new(5).saturating_sub(UnixSeconds::new(5)), 0);
    }
}
