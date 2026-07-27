// SPDX-License-Identifier: MIT OR Apache-2.0
//! Server pushback parsing and backoff resolution.
//!
//! `Retry-After` (delta-seconds or HTTP-date) and `grpc-retry-pushback-ms`
//! override our computed backoff when present and parseable. Both headers are
//! chosen by the upstream, so every byte is treated as attacker-controlled:
//! parsing is total, allocation-free, and length-bounded.
//!
//! This module is pure, allocation-free, and performs no I/O. It never reads a
//! clock; `now_wall_ms` is supplied by the caller.

use crate::clock::Millis;
use crate::deadline::Deadline;
use crate::retry::backoff::FullJitterBackoff;
use irontraffic_rand::Rng;

/// Maximum bytes scanned from a single header value.
const MAX_HEADER_VALUE_LEN: usize = 64;

/// The header names this module reads, as lowercase ASCII.
pub const HDR_RETRY_AFTER: &[u8] = b"retry-after";
/// See [`HDR_RETRY_AFTER`].
pub const HDR_GRPC_RETRY_PUSHBACK_MS: &[u8] = b"grpc-retry-pushback-ms";

/// The result of parsing `grpc-retry-pushback-ms`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PushbackResult {
    /// Wait this many milliseconds.
    Ms(u32),
    /// Do not retry at all. Produced by a negative or unparseable value, per
    /// gRFC A6.
    Forbid,
}

/// What the caller must do about the delay before the next attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackoffDecision {
    /// Sleep this many milliseconds, then retry.
    Sleep(u32),
    /// Do not retry.
    DoNotRetry(NoRetryReason),
}

/// Why no retry will happen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoRetryReason {
    /// `grpc-retry-pushback-ms` was negative or unparseable.
    GrpcPushbackForbids,
    /// The server's pushback does not fit the remaining deadline.
    PushbackExceedsDeadline,
    /// Our computed backoff plus one attempt does not fit the remaining deadline.
    BackoffExceedsDeadline,
}

/// Inputs to [`resolve_backoff`]. All borrowed or `Copy`.
#[derive(Clone, Copy, Debug)]
pub struct BackoffInputs<'a> {
    /// Raw `grpc-retry-pushback-ms` value, if the response carried one. Takes
    /// precedence over `retry_after`.
    pub grpc_pushback: Option<&'a [u8]>,
    /// Raw `Retry-After` value, if the response carried one.
    pub retry_after: Option<&'a [u8]>,
    /// The ORIGINAL request's deadline.
    pub deadline: Deadline,
    /// Current coarse monotonic time.
    pub now: Millis,
    /// Current unix milliseconds, for the HTTP-date form only.
    pub now_wall_ms: u64,
    /// The route's observed p50 attempt duration.
    pub min_attempt_estimate_ms: u32,
}

/// Parse `Retry-After`, returning milliseconds to wait, or `None` when the value
/// is unparseable (in which case it is IGNORED and our own backoff applies).
///
/// Accepts delta-seconds and all three HTTP-date formats required by RFC 9110
/// Section 5.6.7: IMF-fixdate, obsolete RFC 850, and asctime. A date in the
/// past returns `Some(0)`. `now_wall_ms` is unix milliseconds, supplied by the
/// caller so this stays pure.
#[must_use]
pub fn parse_retry_after(v: &[u8], now_wall_ms: u64) -> Option<u32> {
    if v.is_empty() || v.len() > MAX_HEADER_VALUE_LEN {
        return None;
    }

    if is_all_digits(v) && v.len() <= 10 {
        let secs = parse_u64_digits(v)?;
        let ms = secs.saturating_mul(1000);
        return Some(u32::try_from(ms).unwrap_or(u32::MAX));
    }

    let target_ms = parse_http_date_ms(v, now_wall_ms)?;
    let ms = target_ms.saturating_sub(now_wall_ms);
    Some(u32::try_from(ms).unwrap_or(u32::MAX))
}

/// Parse `grpc-retry-pushback-ms`. A negative or unparseable value is
/// [`PushbackResult::Forbid`], which means do not retry at all, per gRFC A6.
/// Note the asymmetry with `Retry-After`, which is merely ignored when
/// unparseable.
#[must_use]
pub fn parse_grpc_pushback(v: &[u8]) -> PushbackResult {
    if v.is_empty() || v.len() > MAX_HEADER_VALUE_LEN {
        return PushbackResult::Forbid;
    }

    if v.first() == Some(&b'-') {
        return PushbackResult::Forbid;
    }

    if is_all_digits(v) && v.len() <= 10 {
        let value = parse_u64_digits(v).unwrap_or(0);
        return match u32::try_from(value) {
            Ok(ms) => PushbackResult::Ms(ms),
            Err(_) => PushbackResult::Forbid,
        };
    }

    PushbackResult::Forbid
}

/// Parse an HTTP-date into unix milliseconds. Accepts IMF-fixdate, RFC 850,
/// and asctime. Allocation-free and dependency-free.
#[must_use]
pub fn parse_http_date_ms(v: &[u8], now_wall_ms: u64) -> Option<u64> {
    if v.len() > MAX_HEADER_VALUE_LEN {
        return None;
    }

    parse_imf_fixdate(v)
        .or_else(|| parse_rfc850(v, now_wall_ms))
        .or_else(|| parse_asctime(v))
        .and_then(|(y, m, d, hh, mm, ss)| {
            let days = days_from_civil(y, m, d);
            let secs = days.checked_mul(86_400)?.checked_add(i64::from(
                hh.checked_mul(3600)?
                    .checked_add(mm.checked_mul(60)?)?
                    .checked_add(ss)?,
            ))?;
            let ms = secs.checked_mul(1000)?;
            u64::try_from(ms).ok()
        })
}

/// Days from the unix epoch to `(y, m, d)` in the proleptic Gregorian calendar.
/// Howard Hinnant's `days_from_civil`. Exact for all representable dates.
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "exact integer arithmetic from Hinnant's days_from_civil"
)]
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let m = i64::from(m);
    let d = i64::from(d);
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Decide the delay before the next attempt.
///
/// Server pushback, when present and parseable, is used VERBATIM: it is never
/// averaged, maxed, or minned with our computed backoff, because the server
/// knows when it will be ready and second-guessing it is how a herd returns. It
/// is capped only by the deadline.
///
/// Call exactly once per retry decision: it advances `backoff`.
#[must_use]
pub fn resolve_backoff(
    inputs: BackoffInputs<'_>,
    backoff: &mut FullJitterBackoff,
    rng: &mut Rng,
) -> BackoffDecision {
    let pushback = if let Some(raw) = inputs.grpc_pushback {
        match parse_grpc_pushback(raw) {
            PushbackResult::Forbid => {
                return BackoffDecision::DoNotRetry(NoRetryReason::GrpcPushbackForbids);
            }
            PushbackResult::Ms(v) => Some(v),
        }
    } else if let Some(raw) = inputs.retry_after {
        parse_retry_after(raw, inputs.now_wall_ms)
    } else {
        None
    };

    if let Some(p) = pushback {
        let need_ms = p.saturating_add(inputs.min_attempt_estimate_ms);
        if !inputs.deadline.permits(inputs.now, need_ms) {
            return BackoffDecision::DoNotRetry(NoRetryReason::PushbackExceedsDeadline);
        }
        if p == 0 {
            // Zero pushback is floored with jitter to break a synchronized herd.
            let jittered = rng.bounded_u32(backoff.base_interval_ms().saturating_add(1));
            return BackoffDecision::Sleep(jittered);
        }
        return BackoffDecision::Sleep(p);
    }

    let own = backoff.next(rng);
    let need_ms = own.saturating_add(inputs.min_attempt_estimate_ms);
    if !inputs.deadline.permits(inputs.now, need_ms) {
        return BackoffDecision::DoNotRetry(NoRetryReason::BackoffExceedsDeadline);
    }
    BackoffDecision::Sleep(own)
}

/// True when `v` is non-empty and every byte is an ASCII digit.
#[inline]
#[must_use]
fn is_all_digits(v: &[u8]) -> bool {
    !v.is_empty() && v.iter().all(|&b| b.is_ascii_digit())
}

/// Parse a decimal integer from all-ASCII-digit bytes. Returns `None` on empty
/// input for safety, though callers already guard against it.
#[inline]
#[must_use]
fn parse_u64_digits(v: &[u8]) -> Option<u64> {
    let mut out: u64 = 0;
    for &b in v {
        out = out.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(out)
}

/// Month from its three-letter English abbreviation. Case-sensitive per ABNF.
#[inline]
#[must_use]
fn month_from_name(name: &[u8]) -> Option<u32> {
    if name.len() != 3 {
        return None;
    }
    Some(match name {
        b"Jan" => 1,
        b"Feb" => 2,
        b"Mar" => 3,
        b"Apr" => 4,
        b"May" => 5,
        b"Jun" => 6,
        b"Jul" => 7,
        b"Aug" => 8,
        b"Sep" => 9,
        b"Oct" => 10,
        b"Nov" => 11,
        b"Dec" => 12,
        _ => return None,
    })
}

/// True when `year` is a leap year in the proleptic Gregorian calendar.
#[inline]
#[must_use]
const fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Maximum day-of-month for `(year, month)`.
#[inline]
#[must_use]
fn max_day_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Validate and convert calendar fields. Returns `(year, month, day, hour,
/// minute, second)` with second 60 treated as 59.
#[inline]
#[must_use]
fn validate_datetime(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<(i64, u32, u32, u32, u32, u32)> {
    if !(1..=12).contains(&month) || !(1..=max_day_in_month(year, month)).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let second = if second == 60 { 59 } else { second };
    Some((year, month, day, hour, minute, second))
}

/// Parse `Wkd, DD Mon YYYY HH:MM:SS GMT` (IMF-fixdate, exactly 29 bytes).
#[must_use]
fn parse_imf_fixdate(v: &[u8]) -> Option<(i64, u32, u32, u32, u32, u32)> {
    if v.len() != 29 {
        return None;
    }
    if *v.get(3)? != b','
        || *v.get(4)? != b' '
        || *v.get(7)? != b' '
        || *v.get(11)? != b' '
        || *v.get(16)? != b' '
        || *v.get(19)? != b':'
        || *v.get(22)? != b':'
        || *v.get(25)? != b' '
    {
        return None;
    }
    if v.get(26..29)? != b"GMT" {
        return None;
    }

    let day = parse_two_digits(v.get(5..7)?)?;
    let month = month_from_name(v.get(8..11)?)?;
    let year = parse_four_digits(v.get(12..16)?)?;
    let hour = parse_two_digits(v.get(17..19)?)?;
    let minute = parse_two_digits(v.get(20..22)?)?;
    let second = parse_two_digits(v.get(23..25)?)?;

    validate_datetime(i64::from(year), month, day, hour, minute, second)
}

/// Parse `Weekday, DD-Mon-YY HH:MM:SS GMT` (RFC 850, variable weekday).
#[must_use]
fn parse_rfc850(v: &[u8], now_wall_ms: u64) -> Option<(i64, u32, u32, u32, u32, u32)> {
    let comma = v.iter().position(|&b| b == b',')?;
    if comma == 0 {
        return None;
    }
    let rest = v.get(comma + 1..)?;
    // rest must be ` DD-Mon-YY HH:MM:SS GMT` = 23 bytes.
    if rest.len() != 23
        || *rest.first()? != b' '
        || *rest.get(3)? != b'-'
        || *rest.get(7)? != b'-'
        || *rest.get(10)? != b' '
        || *rest.get(13)? != b':'
        || *rest.get(16)? != b':'
        || *rest.get(19)? != b' '
    {
        return None;
    }
    if rest.get(20..23)? != b"GMT" {
        return None;
    }

    let day = parse_two_digits(rest.get(1..3)?)?;
    let month = month_from_name(rest.get(4..7)?)?;
    let yy = parse_two_digits(rest.get(8..10)?)?;
    let year = expand_two_digit_year(yy, now_wall_ms);
    let hour = parse_two_digits(rest.get(11..13)?)?;
    let minute = parse_two_digits(rest.get(14..16)?)?;
    let second = parse_two_digits(rest.get(17..19)?)?;

    validate_datetime(year, month, day, hour, minute, second)
}

/// Parse `Wkd Mon [D]D HH:MM:SS YYYY` (asctime, exactly 24 bytes).
#[must_use]
fn parse_asctime(v: &[u8]) -> Option<(i64, u32, u32, u32, u32, u32)> {
    if v.len() != 24 {
        return None;
    }
    if *v.get(3)? != b' '
        || *v.get(7)? != b' '
        || *v.get(10)? != b' '
        || *v.get(13)? != b':'
        || *v.get(16)? != b':'
        || *v.get(19)? != b' '
    {
        return None;
    }

    let month = month_from_name(v.get(4..7)?)?;
    let day = if *v.get(8)? == b' ' {
        parse_one_digit(*v.get(9)?)?
    } else {
        parse_two_digits(v.get(8..10)?)?
    };
    let hour = parse_two_digits(v.get(11..13)?)?;
    let minute = parse_two_digits(v.get(14..16)?)?;
    let second = parse_two_digits(v.get(17..19)?)?;
    let year = parse_four_digits(v.get(20..24)?)?;

    validate_datetime(i64::from(year), month, day, hour, minute, second)
}

/// Expand a two-digit year using RFC 9110's 50-year rule.
#[must_use]
fn expand_two_digit_year(yy: u32, now_wall_ms: u64) -> i64 {
    let current_year = approximate_year_from_unix_millis(now_wall_ms);
    let candidate = current_year - (current_year % 100) + i64::from(yy);
    if candidate > current_year + 50 {
        candidate - 100
    } else if candidate < current_year - 49 {
        candidate + 100
    } else {
        candidate
    }
}

/// Approximate current year from unix milliseconds. Good enough for the 50-year
/// rule because the rule's window is far wider than the approximation error.
#[inline]
#[must_use]
#[allow(
    clippy::integer_division,
    reason = "approximating the year from a whole millisecond count"
)]
fn approximate_year_from_unix_millis(now_wall_ms: u64) -> i64 {
    const MS_PER_YEAR: i64 = 31_557_600_000; // 365.25 days * 86400 * 1000
    let now_ms = i64::try_from(now_wall_ms).unwrap_or(i64::MAX);
    1970i64
        .checked_add(now_ms / MS_PER_YEAR)
        .unwrap_or(i64::MAX)
}

/// Parse two ASCII digits into a `u32`.
#[inline]
#[must_use]
fn parse_two_digits(v: &[u8]) -> Option<u32> {
    if v.len() != 2 {
        return None;
    }
    let a = v.first()?.checked_sub(b'0')?;
    let b = v.get(1)?.checked_sub(b'0')?;
    if a > 9 || b > 9 {
        return None;
    }
    Some(u32::from(a) * 10 + u32::from(b))
}

/// Parse one ASCII digit into a `u32`.
#[inline]
#[must_use]
fn parse_one_digit(b: u8) -> Option<u32> {
    let d = b.checked_sub(b'0')?;
    if d > 9 {
        return None;
    }
    Some(u32::from(d))
}

/// Parse four ASCII digits into a `u32`.
#[inline]
#[must_use]
fn parse_four_digits(v: &[u8]) -> Option<u32> {
    if v.len() != 4 {
        return None;
    }
    let thousands = parse_one_digit(*v.first()?)?;
    let hundreds = parse_one_digit(*v.get(1)?)?;
    let tens = parse_one_digit(*v.get(2)?)?;
    let ones = parse_one_digit(*v.get(3)?)?;
    Some(thousands * 1000 + hundreds * 100 + tens * 10 + ones)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::BackoffConfig;
    use proptest::prelude::{ProptestConfig, any, proptest};

    const NOV_1994_MS: u64 = 784_111_777_000;

    fn base_inputs() -> BackoffInputs<'static> {
        BackoffInputs {
            grpc_pushback: None,
            retry_after: None,
            deadline: Deadline::from_now(Millis(0), 10_000),
            now: Millis(0),
            now_wall_ms: NOV_1994_MS,
            min_attempt_estimate_ms: 0,
        }
    }

    #[test]
    fn retry_after_delta_cases() {
        let cases: [(&[u8], Option<u32>); 8] = [
            (b"0", Some(0)),
            (b"120", Some(120_000)),
            (b"4294967", Some(4_294_967_000)),
            (b"4294968", Some(u32::MAX)),
            (b"", None),
            (b"-5", None),
            (b"1.5", None),
            (b"99999999999", None),
        ];
        for (v, expected) in cases {
            assert_eq!(parse_retry_after(v, NOV_1994_MS), expected, "{v:?}");
        }
    }

    #[test]
    fn retry_after_imf_fixdate() {
        assert_eq!(
            parse_http_date_ms(b"Sun, 06 Nov 1994 08:49:37 GMT", NOV_1994_MS),
            Some(NOV_1994_MS)
        );
        assert_eq!(
            parse_retry_after(b"Sun, 06 Nov 1994 08:49:37 GMT", NOV_1994_MS - 5000),
            Some(5000)
        );
    }

    #[test]
    fn retry_after_imf_past() {
        assert_eq!(
            parse_retry_after(b"Sun, 06 Nov 1994 08:49:37 GMT", NOV_1994_MS + 5000),
            Some(0)
        );
    }

    #[test]
    fn retry_after_rfc850() {
        assert_eq!(
            parse_http_date_ms(b"Sunday, 06-Nov-94 08:49:37 GMT", NOV_1994_MS),
            Some(NOV_1994_MS)
        );
    }

    #[test]
    fn retry_after_asctime() {
        assert_eq!(
            parse_http_date_ms(b"Sun Nov  6 08:49:37 1994", NOV_1994_MS),
            Some(NOV_1994_MS)
        );
    }

    #[test]
    fn retry_after_asctime_two_digit_day() {
        assert_eq!(
            parse_http_date_ms(b"Sun Nov 06 08:49:37 1994", NOV_1994_MS),
            Some(NOV_1994_MS)
        );
    }

    #[test]
    fn retry_after_wrong_weekday_accepted() {
        assert_eq!(
            parse_http_date_ms(b"Mon, 06 Nov 1994 08:49:37 GMT", NOV_1994_MS),
            Some(NOV_1994_MS)
        );
    }

    #[test]
    fn retry_after_rejects_table() {
        let cases: [&[u8]; 7] = [
            b"Sun, 29 Feb 1995 00:00:00 GMT",
            b"Sun, 06 Nov 1994 24:00:00 GMT",
            b"Sun, 06 Nov 1994 08:49:37 UTC",
            b"Sun, 06 Nov 1994 08:49:37 GMT ",
            b"Sun, 32 Nov 1994 08:49:37 GMT",
            b"Sun, 06 Xxx 1994 08:49:37 GMT",
            &[b'X'; 1000],
        ];
        for v in cases {
            assert_eq!(parse_retry_after(v, NOV_1994_MS), None, "{v:?}");
        }
    }

    #[test]
    fn retry_after_leap_second() {
        // :60 is treated as :59, so the instant is one second before :00 and the
        // seconds field is 59 rather than 60.
        let expected_ms = NOV_1994_MS + (59 - 37) * 1000;
        assert_eq!(
            parse_http_date_ms(b"Sun, 06 Nov 1994 08:49:60 GMT", NOV_1994_MS),
            Some(expected_ms)
        );
    }

    #[test]
    fn retry_after_leap_day_valid() {
        assert!(parse_http_date_ms(b"Thu, 29 Feb 1996 00:00:00 GMT", NOV_1994_MS).is_some());
    }

    #[test]
    fn days_from_civil_known_values() {
        let cases: [(i64, u32, u32, i64); 5] = [
            (1970, 1, 1, 0),
            (1969, 12, 31, -1),
            (2000, 3, 1, 11_017),
            (1994, 11, 6, 9075),
            (2026, 7, 24, 20_658),
        ];
        for (y, m, d, expected) in cases {
            assert_eq!(days_from_civil(y, m, d), expected, "({y}, {m}, {d})");
        }
    }

    #[test]
    fn rfc850_two_digit_year_rule() {
        let now_2026_ms: u64 = u64::try_from(days_from_civil(2026, 7, 24)).unwrap() * 86_400_000;
        assert_eq!(
            parse_http_date_ms(b"Sunday, 06-Nov-94 08:49:37 GMT", now_2026_ms),
            Some(NOV_1994_MS)
        );
        // 2030-11-06 08:49:37 GMT.
        let target_2030_ms = u64::try_from(days_from_civil(2030, 11, 6)).unwrap() * 86_400_000
            + 8 * 3_600_000
            + 49 * 60_000
            + 37_000;
        assert_eq!(
            parse_http_date_ms(b"Sunday, 06-Nov-30 08:49:37 GMT", now_2026_ms),
            Some(target_2030_ms)
        );
        // A year more than 50 years in the future resolves to the past century.
        let now_2026_approx = approximate_year_from_unix_millis(now_2026_ms);
        let future_yy = u32::try_from((now_2026_approx + 51).rem_euclid(100)).unwrap();
        let expanded = expand_two_digit_year(future_yy, now_2026_ms);
        assert!(expanded < now_2026_approx + 50);
    }

    #[test]
    fn grpc_pushback_cases() {
        let cases: [(&[u8], PushbackResult); 6] = [
            (b"0", PushbackResult::Ms(0)),
            (b"250", PushbackResult::Ms(250)),
            (b"-1", PushbackResult::Forbid),
            (b"abc", PushbackResult::Forbid),
            (b"", PushbackResult::Forbid),
            (b"99999999999", PushbackResult::Forbid),
        ];
        for (v, expected) in cases {
            assert_eq!(parse_grpc_pushback(v), expected, "{v:?}");
        }
    }

    #[test]
    fn resolve_prefers_grpc_over_retry_after() {
        let mut inputs = base_inputs();
        inputs.grpc_pushback = Some(b"250");
        inputs.retry_after = Some(b"120");
        let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
        let mut rng = Rng::from_seed(0xabc);
        assert_eq!(
            resolve_backoff(inputs, &mut backoff, &mut rng),
            BackoffDecision::Sleep(250)
        );
    }

    #[test]
    fn resolve_grpc_forbid_wins() {
        let mut inputs = base_inputs();
        inputs.grpc_pushback = Some(b"-1");
        inputs.retry_after = Some(b"1");
        let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
        let mut rng = Rng::from_seed(0xabc);
        assert_eq!(
            resolve_backoff(inputs, &mut backoff, &mut rng),
            BackoffDecision::DoNotRetry(NoRetryReason::GrpcPushbackForbids)
        );
    }

    #[test]
    fn resolve_pushback_verbatim() {
        let mut inputs = base_inputs();
        inputs.retry_after = Some(b"1");
        let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
        let mut rng = Rng::from_seed(0xabc);
        assert_eq!(
            resolve_backoff(inputs, &mut backoff, &mut rng),
            BackoffDecision::Sleep(1000)
        );
    }

    #[test]
    fn resolve_pushback_exceeds_deadline() {
        let mut inputs = base_inputs();
        inputs.deadline = Deadline::from_now(Millis(0), 200);
        inputs.retry_after = Some(b"3600");
        let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
        let mut rng = Rng::from_seed(0xabc);
        assert_eq!(
            resolve_backoff(inputs, &mut backoff, &mut rng),
            BackoffDecision::DoNotRetry(NoRetryReason::PushbackExceedsDeadline)
        );
    }

    #[test]
    fn resolve_unparseable_retry_after_falls_through() {
        let mut inputs = base_inputs();
        inputs.retry_after = Some(b"garbage");
        let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
        let mut rng = Rng::from_seed(0xabc);
        let decision = resolve_backoff(inputs, &mut backoff, &mut rng);
        match decision {
            BackoffDecision::Sleep(v) => {
                assert!(v <= 25, "first draw {v} exceeds base window");
            }
            BackoffDecision::DoNotRetry(_) => {
                panic!("expected Sleep from fallback backoff, got {decision:?}")
            }
        }
    }

    #[test]
    fn resolve_own_backoff_exceeds_deadline() {
        let mut inputs = base_inputs();
        inputs.deadline = Deadline::from_now(Millis(0), 5);
        let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
        let mut rng = Rng::from_seed(0xabc);
        let decision = resolve_backoff(inputs, &mut backoff, &mut rng);
        assert_eq!(
            decision,
            BackoffDecision::DoNotRetry(NoRetryReason::BackoffExceedsDeadline)
        );
        assert_eq!(backoff.attempt(), 1);
    }

    #[test]
    fn resolve_zero_pushback_is_jittered() {
        for raw in [b"0".as_slice(), b"Sun, 06 Nov 1994 08:49:37 GMT"] {
            let mut inputs = base_inputs();
            inputs.retry_after = Some(raw);
            inputs.now_wall_ms = NOV_1994_MS;

            let mut saw_nonzero = false;
            for _ in 0..1000 {
                let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
                let mut rng = Rng::from_seed(0xabc);
                let decision = resolve_backoff(inputs, &mut backoff, &mut rng);
                match decision {
                    BackoffDecision::Sleep(v) => {
                        assert!(v <= 25, "zero pushback jittered {v} exceeds base");
                        if v != 0 {
                            saw_nonzero = true;
                        }
                        assert_eq!(backoff.attempt(), 0, "zero pushback advanced backoff");
                    }
                    BackoffDecision::DoNotRetry(_) => {
                        panic!("expected Sleep for zero pushback, got {decision:?}")
                    }
                }
            }
            assert!(saw_nonzero, "zero pushback never jittered to nonzero");
        }

        // gRPC pushback of zero is also jittered.
        let mut inputs = base_inputs();
        inputs.grpc_pushback = Some(b"0");
        let mut saw_nonzero = false;
        for _ in 0..1000 {
            let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
            let mut rng = Rng::from_seed(0xabc);
            let decision = resolve_backoff(inputs, &mut backoff, &mut rng);
            match decision {
                BackoffDecision::Sleep(v) => {
                    assert!(v <= 25);
                    if v != 0 {
                        saw_nonzero = true;
                    }
                    assert_eq!(backoff.attempt(), 0);
                }
                BackoffDecision::DoNotRetry(_) => {
                    panic!("expected Sleep for grpc zero pushback, got {decision:?}")
                }
            }
        }
        assert!(saw_nonzero);
    }

    #[test]
    fn parse_length_capped() {
        // A value whose first 64 bytes are a valid `Retry-After: 120` followed
        // by padding. If the parser scanned past 64 bytes it could produce a
        // different result; the length check must precede the scan.
        let mut long = [b' '; 10_000];
        long[..3].copy_from_slice(b"120");
        assert_eq!(parse_retry_after(&long, NOV_1994_MS), None);

        let long_grpc = [b'0'; 10_000];
        assert_eq!(parse_grpc_pushback(&long_grpc), PushbackResult::Forbid);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]
        #[test]
        fn prop_parse_retry_after_never_panics(
            v in proptest::collection::vec(any::<u8>(), 0..=64),
            now_wall_ms: u64,
        ) {
            let result = parse_retry_after(&v, now_wall_ms);
        // Purity: the same input must always produce the same output.
        assert_eq!(result, parse_retry_after(&v, now_wall_ms));
        // Any returned duration is a u32 by construction, so it is bounded;
        // the parser clamps overflow to u32::MAX rather than wrapping.
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]
        #[test]
        fn prop_resolve_respects_deadline(
            grpc in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..=64)),
            retry in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..=64)),
            now: u32,
            deadline_budget: u32,
            now_wall_ms: u64,
            min_attempt_estimate_ms: u32,
            seed: u64,
        ) {
            let inputs = BackoffInputs {
                grpc_pushback: grpc.as_deref(),
                retry_after: retry.as_deref(),
                deadline: Deadline::from_now(Millis(now), deadline_budget.min(Millis::HORIZON_MS)),
                now: Millis(now),
                now_wall_ms,
                min_attempt_estimate_ms,
            };
            let mut backoff = FullJitterBackoff::new(BackoffConfig::default());
            let mut rng = Rng::from_seed(seed);
            let decision = resolve_backoff(inputs, &mut backoff, &mut rng);
            if let BackoffDecision::Sleep(v) = decision {
                let need_ms = v.saturating_add(min_attempt_estimate_ms);
                assert!(
                    inputs.deadline.permits(inputs.now, need_ms),
                    "sleep {v} + estimate {min_attempt_estimate_ms} exceeds deadline"
                );
            }
        }
    }
}
