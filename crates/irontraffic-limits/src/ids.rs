// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dense array-index identifiers: [`PolicyId`] and [`ShardIdx`].
//!
//! Both carry their bound in the constructor so a downstream array index is
//! provably in range without a runtime check on the request path.

use core::mem::size_of;

use crate::config::ConfigError;

const _: () = assert!(size_of::<PolicyId>() == 2);
const _: () = assert!(size_of::<ShardIdx>() == 2);

/// Dense index of a configured limit policy.
///
/// Bounded at 63 because the policy matcher is a linear scan over a packed
/// struct-of-arrays sized for 64 policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyId(u16);

impl PolicyId {
    /// Largest valid raw value.
    pub const MAX_INDEX: u16 = 63;

    /// Builds a policy id.
    ///
    /// # Errors
    /// [`ConfigError::TooLarge`] when `raw` exceeds [`PolicyId::MAX_INDEX`].
    #[rustfmt::skip]
    #[allow(clippy::cast_lossless, reason = "u16 to u64 is a lossless widening; From is not yet callable in a const fn")]
    pub const fn new(raw: u16) -> Result<Self, ConfigError> {
        if raw > Self::MAX_INDEX {
            Err(ConfigError::TooLarge {
                field: "policy_id",
                max: Self::MAX_INDEX as u64,
                value: raw as u64,
            })
        } else {
            Ok(Self(raw))
        }
    }

    /// The raw value, for array indexing.
    #[must_use]
    #[rustfmt::skip]
    #[allow(clippy::cast_lossless, reason = "u16 to usize is a lossless widening; From is not yet callable in a const fn")]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Dense index of a shard in the limiter key table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardIdx(u16);

impl ShardIdx {
    /// Largest valid raw value.
    pub const MAX_INDEX: u16 = 4095;

    /// Builds a shard index.
    ///
    /// # Errors
    /// [`ConfigError::TooLarge`] when `raw` exceeds [`ShardIdx::MAX_INDEX`].
    #[rustfmt::skip]
    #[allow(clippy::cast_lossless, reason = "u16 to u64 is a lossless widening; From is not yet callable in a const fn")]
    pub const fn new(raw: u16) -> Result<Self, ConfigError> {
        if raw > Self::MAX_INDEX {
            Err(ConfigError::TooLarge {
                field: "shard_idx",
                max: Self::MAX_INDEX as u64,
                value: raw as u64,
            })
        } else {
            Ok(Self(raw))
        }
    }

    /// The raw value, for array indexing.
    #[must_use]
    #[rustfmt::skip]
    #[allow(clippy::cast_lossless, reason = "u16 to usize is a lossless widening; From is not yet callable in a const fn")]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_id_accepts_zero_and_max() {
        assert_eq!(PolicyId::new(0).unwrap().index(), 0);
        assert_eq!(PolicyId::new(63).unwrap().index(), 63);
    }

    #[test]
    fn policy_id_rejects_out_of_range() {
        assert_eq!(
            PolicyId::new(64),
            Err(ConfigError::TooLarge {
                field: "policy_id",
                max: 63,
                value: 64
            })
        );
    }

    #[test]
    fn shard_idx_rejects_out_of_range() {
        assert_eq!(
            ShardIdx::new(4096),
            Err(ConfigError::TooLarge {
                field: "shard_idx",
                max: 4095,
                value: 4096
            })
        );
    }
}
