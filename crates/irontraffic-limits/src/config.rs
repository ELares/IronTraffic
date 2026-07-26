// SPDX-License-Identifier: MIT OR Apache-2.0

//! Configuration errors and the range-check helpers every mode enum and
//! identifier newtype in this crate validates through.

/// A configured value is out of range or self-inconsistent.
///
/// Every variant names the offending field as a `&'static str`, so an
/// operator sees which knob is wrong without reading code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A value is below its minimum.
    #[error("{field} must be at least {min}, got {value}")]
    TooSmall {
        /// The offending field.
        field: &'static str,
        /// The minimum.
        min: u64,
        /// What was configured.
        value: u64,
    },
    /// A value is above its maximum.
    #[error("{field} must be at most {max}, got {value}")]
    TooLarge {
        /// The offending field.
        field: &'static str,
        /// The maximum.
        max: u64,
        /// What was configured.
        value: u64,
    },
    /// A value that must be a power of two is not one.
    #[error("{field} must be a power of two, got {value}")]
    NotPowerOfTwo {
        /// The offending field.
        field: &'static str,
        /// What was configured.
        value: u64,
    },
    /// Two values are individually valid but inconsistent with each other.
    #[error("{field} is invalid: {why}")]
    Invalid {
        /// The offending field.
        field: &'static str,
        /// A fixed explanation.
        why: &'static str,
    },
}

/// Checks `value >= min`.
///
/// Comparisons are inclusive at both ends and no arithmetic is performed, so
/// there is no overflow path.
///
/// # Errors
/// [`ConfigError::TooSmall`] when `value < min`.
pub const fn at_least(field: &'static str, value: u64, min: u64) -> Result<(), ConfigError> {
    if value >= min {
        Ok(())
    } else {
        Err(ConfigError::TooSmall { field, min, value })
    }
}

/// Checks `value <= max`.
///
/// Comparisons are inclusive at both ends and no arithmetic is performed, so
/// there is no overflow path.
///
/// # Errors
/// [`ConfigError::TooLarge`] when `value > max`.
pub const fn at_most(field: &'static str, value: u64, max: u64) -> Result<(), ConfigError> {
    if value <= max {
        Ok(())
    } else {
        Err(ConfigError::TooLarge { field, max, value })
    }
}

/// Checks `value` is a nonzero power of two.
///
/// `u64::is_power_of_two` already returns `false` for zero, so no separate
/// zero check is needed, but the doc states it because a shard count of zero
/// would make a shard mask degenerate.
///
/// # Errors
/// [`ConfigError::NotPowerOfTwo`], including when `value` is 0.
pub const fn power_of_two(field: &'static str, value: u64) -> Result<(), ConfigError> {
    if value.is_power_of_two() {
        Ok(())
    } else {
        Err(ConfigError::NotPowerOfTwo { field, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn range_helpers_are_inclusive() {
        assert_eq!(at_least("f", 5, 5), Ok(()));
        assert_eq!(at_most("f", 5, 5), Ok(()));
        assert_eq!(
            at_least("f", 4, 5),
            Err(ConfigError::TooSmall {
                field: "f",
                min: 5,
                value: 4
            })
        );
        assert_eq!(
            at_most("f", 6, 5),
            Err(ConfigError::TooLarge {
                field: "f",
                max: 5,
                value: 6
            })
        );
    }

    #[test]
    fn power_of_two_rejects_zero_and_three() {
        assert_eq!(
            power_of_two("s", 0),
            Err(ConfigError::NotPowerOfTwo {
                field: "s",
                value: 0
            })
        );
        assert_eq!(
            power_of_two("s", 3),
            Err(ConfigError::NotPowerOfTwo {
                field: "s",
                value: 3
            })
        );
        assert_eq!(power_of_two("s", 1), Ok(()));
        assert_eq!(power_of_two("s", 4096), Ok(()));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]
        #[test]
        fn prop_at_least_agrees_with_comparison(value: u64, min: u64) {
            assert_eq!(at_least("f", value, min).is_ok(), value >= min);
        }
    }
}
