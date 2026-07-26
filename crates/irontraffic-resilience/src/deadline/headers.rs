// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parse and emit the deadline propagation headers: `grpc-timeout`,
//! `x-envoy-expected-rq-timeout-ms`, and `x-envoy-upstream-rq-timeout-ms`.
//!
//! Every parser and emitter here operates on raw bytes and never allocates. A header
//! value is arbitrary attacker-controlled bytes, and forcing UTF-8 validation on it
//! before parsing digits is both wasted work and a place to get the error path wrong.

/// The three header names this module reads and writes, as lowercase ASCII.
pub const HDR_GRPC_TIMEOUT: &[u8] = b"grpc-timeout";
/// See [`HDR_GRPC_TIMEOUT`].
pub const HDR_EXPECTED_RQ_TIMEOUT_MS: &[u8] = b"x-envoy-expected-rq-timeout-ms";
/// See [`HDR_GRPC_TIMEOUT`].
pub const HDR_UPSTREAM_RQ_TIMEOUT_MS: &[u8] = b"x-envoy-upstream-rq-timeout-ms";

/// Number of ASCII decimal digits `value` prints as. Always at least 1, since `0`
/// itself prints as one digit.
fn decimal_digit_count(value: u32) -> usize {
    if value == 0 {
        1
    } else {
        // `ilog10` is the zero-based power of ten at or below `value`: a one-digit
        // value (1..=9) gives 0, a three-digit value (100..=999) gives 2. Adding 1
        // turns that into the digit count.
        usize::try_from(value.ilog10())
            .unwrap_or(0)
            .saturating_add(1)
    }
}

/// Writes `value` as ASCII decimal digits, most significant first, into the first
/// `decimal_digit_count(value)` bytes of `out`, and returns that count.
///
/// If `out` is shorter than the digit count, nothing is written and 0 is returned;
/// every call site in this file sizes its buffer so that never happens. For a `u32`
/// the digit count is never above 10, so a 10-byte or larger `out` is always enough.
fn write_decimal(out: &mut [u8], value: u32) -> usize {
    let count = decimal_digit_count(value);
    let Some(dst) = out.get_mut(..count) else {
        return 0;
    };
    let mut remaining = value;
    for i in (0..count).rev() {
        if let Some(slot) = dst.get_mut(i) {
            let n = u8::try_from(remaining % 10).unwrap_or(0);
            *slot = b'0'.wrapping_add(n);
        }
        remaining /= 10;
    }
    count
}

/// Parse a `grpc-timeout` value into milliseconds, rounding up.
///
/// Returns `None` for an empty value, more than 8 digits, a non-digit, an unknown
/// unit, or any arithmetic overflow. Units are case-significant: `H` is hours,
/// `M` is minutes, `S` is seconds, `m` is milliseconds, `u` is microseconds,
/// `n` is nanoseconds.
#[must_use]
pub fn parse_grpc_timeout(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 9 {
        return None;
    }
    // At most 8 digits plus one unit byte: split the unit off the end.
    let (digits, unit_byte) = v.split_at(v.len() - 1);
    let unit = *unit_byte.first()?;
    if digits.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        let n = u64::from(b - b'0');
        value = value.checked_mul(10)?.checked_add(n)?;
    }
    match unit {
        b'H' => value.checked_mul(3_600_000),
        b'M' => value.checked_mul(60_000),
        b'S' => value.checked_mul(1_000),
        b'm' => Some(value),
        b'u' => Some(value.div_ceil(1_000)),
        b'n' => Some(value.div_ceil(1_000_000)),
        _ => None,
    }
}

/// Parse an unsigned ASCII decimal millisecond count. No sign, no whitespace, at
/// most 10 digits, `None` on overflow.
#[must_use]
pub fn parse_u32_ms(v: &[u8]) -> Option<u32> {
    if v.is_empty() || v.len() > 10 {
        return None;
    }
    let mut value: u32 = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        let n = u32::from(b - b'0');
        value = value.checked_mul(10)?.checked_add(n)?;
    }
    Some(value)
}

/// Format `ms` as a `grpc-timeout` value into `out`, returning the used length.
///
/// Picks the largest unit that represents `ms` exactly, so 2000 becomes `2S` and
/// 1500 becomes `1500m`. Never emits a value below `1m`.
#[allow(
    clippy::integer_division,
    reason = "converting a millisecond count into whole hours, minutes, or seconds is exact \
              division by a fixed unit width guarded by is_multiple_of, not lossy arithmetic"
)]
pub fn emit_grpc_timeout(ms: u32, out: &mut [u8; 12]) -> usize {
    // Without this, the branch below fires for `ms == 0` (`0 % 3_600_000 == 0`
    // and `0 / 3_600_000 == 0`) and the emitted value is `0H`, a zero-duration
    // timeout the peer would treat as already expired.
    let ms = ms.max(1);
    let (value, unit) = if ms.is_multiple_of(3_600_000) && ms / 3_600_000 <= 99_999_999 {
        (ms / 3_600_000, b'H')
    } else if ms.is_multiple_of(60_000) && ms / 60_000 <= 99_999_999 {
        (ms / 60_000, b'M')
    } else if ms.is_multiple_of(1_000) && ms / 1_000 <= 99_999_999 {
        (ms / 1_000, b'S')
    } else if ms <= 99_999_999 {
        (ms, b'm')
    } else {
        // Unreachable given the 60_000 ms default clamp upstream; written rather
        // than asserted so there is no panic path.
        (99_999_999, b'm')
    };
    let n = write_decimal(out, value);
    match out.get_mut(n) {
        Some(slot) => {
            *slot = unit;
            n.saturating_add(1)
        }
        None => n,
    }
}

/// Format the `x-envoy-expected-rq-timeout-ms` value into `out`, returning the used
/// length. The emitted value is never 0, because 0 means infinity in that header.
pub fn emit_expected_rq_timeout_ms(
    per_try_budget_ms: u32,
    propagate_ms: u32,
    out: &mut [u8; 10],
) -> usize {
    // The `max(1)` is the whole point: 0 means infinity in this header, so an
    // exhausted budget must be propagated as 1.
    let v = per_try_budget_ms.min(propagate_ms).max(1);
    write_decimal(out, v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_timeout_units() {
        assert_eq!(parse_grpc_timeout(b"1H"), Some(3_600_000));
        assert_eq!(parse_grpc_timeout(b"1M"), Some(60_000));
        assert_eq!(parse_grpc_timeout(b"1S"), Some(1_000));
        assert_eq!(parse_grpc_timeout(b"1m"), Some(1));
        assert_eq!(parse_grpc_timeout(b"1u"), Some(1));
        assert_eq!(parse_grpc_timeout(b"1n"), Some(1));
        assert_eq!(parse_grpc_timeout(b"2500u"), Some(3));
        assert_eq!(parse_grpc_timeout(b"1500000n"), Some(2));
    }

    #[test]
    fn grpc_timeout_rejects() {
        let cases: [&[u8]; 10] = [
            b"",
            b"S",
            b"100",
            b"123456789m",
            b"1x",
            b" 1m",
            b"1m ",
            b"+1m",
            b"-1m",
            b"\xff m",
        ];
        for v in cases {
            assert_eq!(parse_grpc_timeout(v), None, "expected None for {v:?}");
        }
    }

    #[test]
    fn grpc_timeout_max_hours_saturates() {
        assert_eq!(parse_grpc_timeout(b"99999999H"), Some(359_999_996_400_000));

        // The `establish` half of this regression: the huge value above must
        // saturate to `u32::MAX` on narrowing, not wrap, and then clamp down to
        // the default `max_timeout_ms` (60_000). A wrapping `as u32` cast would
        // land somewhere else in the u32 range instead.
        let cfg = super::super::DeadlineConfig::default();
        let inbound = super::super::InboundTimeouts {
            grpc_timeout: Some(b"99999999H"),
            ..super::super::InboundTimeouts::default()
        };
        let (_, source, ms) =
            super::super::establish(crate::clock::Millis(0), inbound, 1_000, true, &cfg);
        assert_eq!(source, super::super::TimeoutSource::GrpcTimeout);
        assert_eq!(ms, 60_000);
    }

    #[test]
    fn grpc_timeout_zero() {
        assert_eq!(parse_grpc_timeout(b"0S"), Some(0));
    }

    #[test]
    fn parse_u32_ms_cases() {
        assert_eq!(parse_u32_ms(b"0"), Some(0));
        assert_eq!(parse_u32_ms(b"007"), Some(7));
        assert_eq!(parse_u32_ms(b"4294967295"), Some(u32::MAX));
        assert_eq!(parse_u32_ms(b"4294967296"), None);
        assert_eq!(parse_u32_ms(b""), None);
        assert_eq!(parse_u32_ms(b"1 "), None);
        assert_eq!(parse_u32_ms(b"1a"), None);
    }

    #[test]
    fn emit_grpc_timeout_largest_exact_unit() {
        let cases: [(u32, &[u8]); 6] = [
            (2_000, b"2S"),
            (60_000, b"1M"),
            (3_600_000, b"1H"),
            (1_500, b"1500m"),
            (1, b"1m"),
            (0, b"1m"),
        ];
        for (ms, expected) in cases {
            let mut buf = [0u8; 12];
            let n = emit_grpc_timeout(ms, &mut buf);
            assert_eq!(&buf[..n], expected, "ms={ms}");
        }
    }

    #[test]
    fn emit_expected_never_zero() {
        let mut buf = [0u8; 10];
        let n = emit_expected_rq_timeout_ms(0, 0, &mut buf);
        assert_eq!(&buf[..n], b"1");
    }

    #[test]
    fn emit_expected_takes_min() {
        let mut buf = [0u8; 10];
        let n = emit_expected_rq_timeout_ms(50, 200, &mut buf);
        assert_eq!(&buf[..n], b"50");

        let mut buf = [0u8; 10];
        let n = emit_expected_rq_timeout_ms(200, 50, &mut buf);
        assert_eq!(&buf[..n], b"50");
    }

    #[test]
    fn emit_lengths() {
        for ms in [0u32, 1, 9, 10, 99, 100, 60_000] {
            let mut buf = [0xAAu8; 12];
            let n = emit_grpc_timeout(ms, &mut buf);
            assert!(
                buf[n..].iter().all(|&b| b == 0xAA),
                "ms={ms} wrote past the returned length"
            );
            let (unit, digits) = buf[..n].split_last().expect("at least a unit byte");
            assert!(
                digits.iter().all(u8::is_ascii_digit),
                "ms={ms} digits={digits:?}"
            );
            assert!(
                matches!(unit, b'H' | b'M' | b'S' | b'm'),
                "ms={ms} unit={unit}"
            );

            let mut ebuf = [0xAAu8; 10];
            let en = emit_expected_rq_timeout_ms(ms, ms, &mut ebuf);
            assert!(
                ebuf[en..].iter().all(|&b| b == 0xAA),
                "ms={ms} wrote past the returned length"
            );
            assert!(
                ebuf[..en].iter().all(u8::is_ascii_digit),
                "ms={ms} expected={:?}",
                &ebuf[..en]
            );
        }
    }
}
