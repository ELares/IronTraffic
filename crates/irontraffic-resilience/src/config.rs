// SPDX-License-Identifier: MIT OR Apache-2.0
//! Configuration validation error type and range helpers.

/// A configuration value that cannot be accepted, naming the field, the offending
/// value, and the constraint. Every subsystem in this crate returns this from its
/// `validate` method, and the config plane surfaces it verbatim.
///
/// `field` and `constraint` are `&'static str` on purpose: they are authored in this
/// codebase and can never carry attacker data. `value` is the only attacker-influenced
/// member (a configuration document may be authored by a lower-privilege tenant and is
/// echoed back by the admin dry-run endpoint and into structured logs), so it is
/// constructed only through [`ConfigError::new`], which sanitizes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// Dotted path of the field, for example `outlier.base_ejection_time_ms`.
    pub field: &'static str,
    /// The rejected value, sanitized and truncated by [`ConfigError::new`]: at most
    /// [`ConfigError::MAX_VALUE_LEN`] bytes, with every byte outside printable ASCII
    /// (`0x20..=0x7E`) replaced by `?`.
    pub value: String,
    /// The constraint in words, for example `must be in (0, 1]`.
    pub constraint: &'static str,
}

impl ConfigError {
    /// Maximum retained length of [`ConfigError::value`], in bytes. 64.
    pub const MAX_VALUE_LEN: usize = 64;

    /// Build a `ConfigError`, sanitizing `value`.
    ///
    /// `value` is first filtered so that every byte outside printable ASCII
    /// (`0x20..=0x7E`) becomes `?`, which makes a newline, a carriage return, or an
    /// ANSI escape in a configuration string unable to forge a second log line or move
    /// a terminal cursor. It is then truncated to [`ConfigError::MAX_VALUE_LEN`] bytes
    /// with a trailing `...` when truncation occurred, so a multi-megabyte string in a
    /// configuration document cannot be amplified into a multi-megabyte error, log
    /// record, or admin response body.
    #[must_use]
    pub fn new(field: &'static str, value: &str, constraint: &'static str) -> ConfigError {
        let mut sanitized: String = value
            .bytes()
            .map(|b| {
                if (0x20..=0x7E).contains(&b) {
                    char::from(b)
                } else {
                    '?'
                }
            })
            .collect();
        if sanitized.len() > Self::MAX_VALUE_LEN {
            sanitized.truncate(Self::MAX_VALUE_LEN);
            sanitized.push_str("...");
        }
        ConfigError {
            field,
            value: sanitized,
            constraint,
        }
    }
}

impl core::fmt::Display for ConfigError {
    /// Exactly `"{field} = {value}: {constraint}"`, for example
    /// `outlier.base_ejection_time_ms = 0: must be greater than 0`. Written with one
    /// `write!` and no allocation.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} = {}: {}", self.field, self.value, self.constraint)
    }
}

impl core::error::Error for ConfigError {}

/// `Ok(())` when `v` is in `[lo, hi]`, else a [`ConfigError`] naming `field`.
///
/// # Errors
/// Returns a [`ConfigError`] when `v` is outside the inclusive range.
pub fn in_range_u32(field: &'static str, v: u32, lo: u32, hi: u32) -> Result<(), ConfigError> {
    if (lo..=hi).contains(&v) {
        Ok(())
    } else {
        Err(ConfigError::new(
            field,
            &v.to_string(),
            "must be in the allowed range",
        ))
    }
}

/// `Ok(())` when `v` is finite and in `[lo, hi]`, else a [`ConfigError`].
/// A non-finite `v` is always rejected, so no NaN can reach a denominator.
///
/// # Errors
/// Returns a [`ConfigError`] when `v` is not finite or is outside the inclusive range.
pub fn in_range_f64(field: &'static str, v: f64, lo: f64, hi: f64) -> Result<(), ConfigError> {
    if v.is_finite() && v >= lo && v <= hi {
        Ok(())
    } else {
        Err(ConfigError::new(
            field,
            &v.to_string(),
            "must be in the allowed range",
        ))
    }
}

/// `Ok(())` when `v` is finite and in `(lo, hi]`, else a [`ConfigError`].
///
/// # Errors
/// Returns a [`ConfigError`] when `v` is not finite or is outside the half-open range.
pub fn in_half_open_f64(field: &'static str, v: f64, lo: f64, hi: f64) -> Result<(), ConfigError> {
    if v.is_finite() && v > lo && v <= hi {
        Ok(())
    } else {
        Err(ConfigError::new(
            field,
            &v.to_string(),
            "must be in the allowed half-open range",
        ))
    }
}

/// `Ok(())` when `a <= b`, else a [`ConfigError`] naming `field_a`.
///
/// # Errors
/// Returns a [`ConfigError`] when `a` is greater than `b`.
pub fn ordered_u32(
    field_a: &'static str,
    a: u32,
    field_b: &'static str,
    b: u32,
) -> Result<(), ConfigError> {
    let _ = field_b;
    if a <= b {
        Ok(())
    } else {
        Err(ConfigError::new(
            field_a,
            &a.to_string(),
            "must be less than or equal to the other value",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_range_f64_rejects_nan_and_inf() {
        for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let err = in_range_f64("x", v, 0.0, 1.0).unwrap_err();
            assert_eq!(err.field, "x");
        }
    }

    #[test]
    fn in_half_open_rejects_lower_bound() {
        assert!(in_half_open_f64("alpha", 0.0, 0.0, 1.0).is_err());
        assert!(in_half_open_f64("alpha", 1.0, 0.0, 1.0).is_ok());
    }

    #[test]
    fn ordered_u32_allows_equal() {
        assert!(ordered_u32("a", 5, "b", 5).is_ok());
        assert!(ordered_u32("a", 6, "b", 5).is_err());
    }

    #[test]
    fn config_error_display_format() {
        let err = ConfigError {
            field: "outlier.k",
            value: String::from("7"),
            constraint: "must be in (0, 1]",
        };
        assert_eq!(err.to_string(), "outlier.k = 7: must be in (0, 1]");
    }

    #[test]
    fn config_error_truncates_long_value() {
        let long = "a".repeat(1_000_000);
        let err = ConfigError::new("x", &long, "c");
        assert_eq!(err.value.len(), ConfigError::MAX_VALUE_LEN + 3);
        assert!(err.value.ends_with("..."));
    }

    #[test]
    fn config_error_strips_control_bytes() {
        let err = ConfigError::new("x", "1\nlevel=error\r\x1b[2J", "c");
        assert!(err.value.bytes().all(|b| (0x20..=0x7E).contains(&b)));
        assert_eq!(err.value, "1?level=error??[2J");
    }
}
