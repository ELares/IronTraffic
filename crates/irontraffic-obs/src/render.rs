// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::integer_division,
    reason = "this module's whole purpose is truncating integer-only rendering: \
              nanoseconds to milliseconds, digit extraction, and the civil calendar \
              algorithm below are all built from intentional truncating division, \
              never an accidental one. Gating each of the dozens of individual sites \
              in this file would just repeat this same justification endlessly."
)]

//! Integer and hex byte rendering, plus [`CachedWall`], a per-writer pre-rendered
//! timestamp.
//!
//! Every `render_*` function writes into a caller supplied `&mut Vec<u8>` and returns
//! the number of bytes written. None allocates beyond the caller's own `reserve`, none
//! uses `format!`/`write!`/`to_string`, and none can panic on any input.

/// Lowercase hex digits, indexed by nibble value.
const HEX: [u8; 16] = *b"0123456789abcdef";

/// Appends `v` as ASCII decimal. Returns bytes written.
///
/// `v == 0` is handled separately because the general loop below writes nothing for
/// it. `wrapping_add`/plain integer arithmetic only; no `format!`, no `to_string`.
pub fn render_u64(mut v: u64, out: &mut Vec<u8>) -> usize {
    if v == 0 {
        out.push(b'0');
        return 1;
    }
    let mut buf = [0u8; 20];
    let mut i = 20usize;
    while v > 0 {
        i -= 1;
        let digit = u8::try_from(v % 10).unwrap_or(0);
        if let Some(slot) = buf.get_mut(i) {
            *slot = b'0' + digit;
        }
        v /= 10;
    }
    buf.get(i..).map_or(0, |written| {
        out.extend_from_slice(written);
        written.len()
    })
}

/// Appends `v` as ASCII decimal. Returns bytes written.
pub fn render_u32(v: u32, out: &mut Vec<u8>) -> usize {
    render_u64(u64::from(v), out)
}

/// Appends `v` as ASCII decimal with a leading `-` when negative.
///
/// Widens to `i64` FIRST: negating `i32::MIN` directly overflows `i32`.
pub fn render_i32(v: i32, out: &mut Vec<u8>) -> usize {
    let w = i64::from(v);
    if w < 0 {
        out.push(b'-');
        1 + render_u64(w.unsigned_abs(), out)
    } else {
        render_u64(w.unsigned_abs(), out)
    }
}

/// Appends `bytes` as lowercase hex, two characters per byte.
///
/// Writes exactly `2 * bytes.len()` bytes and imposes no cap of its own, so it is the
/// one render function whose output an unbounded caller could make unbounded. Pass a
/// fixed size array or an already capped slice; never pass a request body, a header
/// value or any other length the peer chooses.
pub fn render_hex_lower(bytes: &[u8], out: &mut Vec<u8>) -> usize {
    for &b in bytes {
        let hi = usize::from(b >> 4);
        let lo = usize::from(b & 0x0f);
        out.push(HEX.get(hi).copied().unwrap_or(b'0'));
        out.push(HEX.get(lo).copied().unwrap_or(b'0'));
    }
    2 * bytes.len()
}

/// Appends `ns` as milliseconds with `decimals` (clamped to `0..=3`) fractional
/// digits, truncating toward zero. Integer arithmetic only.
///
/// Splits `ns` into whole milliseconds and a fractional nanosecond remainder BEFORE
/// scaling, so no intermediate value exceeds `u64`: a plain `ns * scale` overflows for
/// `ns` above about 1.8e16, well inside `u64`'s own range.
pub fn render_millis_fixed(ns: u64, decimals: u8, out: &mut Vec<u8>) -> usize {
    let decimals = decimals.min(3);
    // A `match`, deliberately not a lookup table indexed by `decimals`: `decimals`
    // reaches this function from a compiled log format directive, so indexing by it
    // is a panic in a writer thread the day someone reorders the clamp out of step 1,
    // and the crate root denies `clippy::indexing_slicing` anyway.
    // Mutation testing note: the `0 => 1` arm's specific value is unobservable. When
    // `decimals == 0`, `scale` still feeds into `frac` below, but `frac` is itself
    // discarded by the `return n` a few lines down before it is ever used, exactly
    // as the issue's own step-by-step algorithm orders these statements. No test can
    // distinguish `0 => 1` from a mutant that deletes it (falling through to
    // `_ => 1_000`) without reordering this function's control flow away from the
    // given algorithm, which would be answering a different question than the one
    // mutation testing is meant to check here.
    let scale: u64 = match decimals {
        0 => 1,
        1 => 10,
        2 => 100,
        _ => 1_000,
    };
    let whole_ms = ns / 1_000_000;
    let frac_ns = ns % 1_000_000;
    let frac = frac_ns * scale / 1_000_000;
    let n = render_u64(whole_ms, out);
    if decimals == 0 {
        return n;
    }
    out.push(b'.');
    // Zero padded to exactly `decimals` digits, most significant first.
    let mut d = scale / 10;
    let mut v = frac;
    while d > 0 {
        let digit = u8::try_from(v / d).unwrap_or(0);
        out.push(b'0' + digit);
        v %= d;
        // Mutation testing note: mutating this `/=` to `%=` does not survive as a
        // silent pass. For `decimals == 1` (`d` starts at 1), `d %= 10` leaves `d`
        // at 1 forever (`1 % 10 == 1`), so the loop condition `d > 0` never becomes
        // false and the writer thread this runs on hangs. `millis_fixed_no_overflow`
        // exercises exactly that `decimals == 1` case, so the mutant is caught by
        // timing out rather than by a failed assertion; cargo-mutants reports it as
        // a distinct TIMEOUT outcome rather than MISSED.
        d /= 10;
    }
    n + 1 + usize::from(decimals)
}

/// (year, month `1..=12`, day `1..=31`, hour, minute, second) for a Unix second.
/// Howard Hinnant's `civil_from_days`, proleptic Gregorian, UTC.
///
/// Every division here is truncating by design (see the module level `#[allow]`), and
/// every narrowing step uses `try_from` with an unreachable-but-safe fallback rather
/// than an `as` cast, because a raw `as` between these types is exactly what
/// `clippy::cast_possible_truncation`/`cast_possible_wrap`/`cast_sign_loss` (all
/// `deny` at the workspace level) exist to catch: this function's own bounds comments
/// (`0..=146_096`, `0..=399`, `1..=31`, `1..=12`) are the proof that every fallback
/// below is unreachable, not merely convenient.
#[allow(
    clippy::many_single_char_names,
    reason = "s/y/m/d plus the derived z/era/doe/yoe/doy/mp names are Howard Hinnant's \
              own names for this exact algorithm, transcribed so a reader can check \
              this against the reference rather than against a renaming of it"
)]
fn civil_from_unix_secs(s: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = i64::try_from(s / 86_400).unwrap_or(0);
    let secs_of_day = u32::try_from(s % 86_400).unwrap_or(0);
    // Shift the era so day 0 is 0000-03-01.
    let z = days + 719_468;
    // Mutation testing note: the `else` arm (`z - 146_096`) is unreachable for any
    // `s: u64`, and so is any mutation of the `-` inside it. `days` comes from
    // `s / 86_400` with `s` unsigned, so `days >= 0` always, and `z = days +
    // 719_468` is therefore always at least 719_468, never negative. Howard
    // Hinnant's original algorithm needs this branch for a signed day count that
    // can be negative (a date before the shifted epoch); this function's `u64`
    // input makes that case impossible to construct, so no test can reach the
    // branch to tell a correct `-` from a mutated one. The branch is kept, rather
    // than simplified to `z / 146_097`, so this stays checkable line for line
    // against the published reference algorithm.
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe_signed = z - era * 146_097; // 0..=146_096
    let doe = u64::try_from(doe_signed).unwrap_or(0);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // 0..=399
    let y = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365
    let mp = (5 * doy + 2) / 153; // 0..=11, March = 0
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1); // 1..=31
    let m_raw: u64 = if mp < 10 { mp + 3 } else { mp - 9 }; // 1..=12
    let m = u32::try_from(m_raw).unwrap_or(1);
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        m,
        d,
        secs_of_day / 3600,
        (secs_of_day / 60) % 60,
        secs_of_day % 60,
    )
}

/// The three letter English month abbreviations, index 0 is January.
const MONTHS: [[u8; 3]; 12] = [
    *b"Jan", *b"Feb", *b"Mar", *b"Apr", *b"May", *b"Jun", *b"Jul", *b"Aug", *b"Sep", *b"Oct",
    *b"Nov", *b"Dec",
];

/// Writes `byte` at `buf[at]`, silently doing nothing if `at` is out of range (never
/// happens for any call in this file; every caller's offsets are fixed and within the
/// buffer's own fixed size, checked by `render::tests::cached_wall_epoch` and friends
/// exercising every field).
fn put(buf: &mut [u8], at: usize, byte: u8) {
    if let Some(slot) = buf.get_mut(at) {
        *slot = byte;
    }
}

/// Writes `v` as exactly two zero padded ASCII digits at `buf[at]` and `buf[at + 1]`.
fn put2(buf: &mut [u8], at: usize, v: u32) {
    let tens = u8::try_from((v / 10) % 10).unwrap_or(0);
    let ones = u8::try_from(v % 10).unwrap_or(0);
    put(buf, at, b'0' + tens);
    put(buf, at + 1, b'0' + ones);
}

/// Writes `y` as exactly four zero padded ASCII digits starting at `buf[at]`.
///
/// `civil_from_unix_secs` is only ever fed `s: u64 >= 0`, so `y` here is always
/// non-negative; a year at or beyond 10000 renders its low four digits, which is
/// documented and not a case any log line reaches.
fn put4_year(buf: &mut [u8], at: usize, y: i64) {
    let y4 = u32::try_from(y % 10_000).unwrap_or(0);
    put(buf, at, b'0' + u8::try_from((y4 / 1000) % 10).unwrap_or(0));
    put(
        buf,
        at + 1,
        b'0' + u8::try_from((y4 / 100) % 10).unwrap_or(0),
    );
    put(
        buf,
        at + 2,
        b'0' + u8::try_from((y4 / 10) % 10).unwrap_or(0),
    );
    put(buf, at + 3, b'0' + u8::try_from(y4 % 10).unwrap_or(0));
}

/// `YYYY-MM-DDTHH:MM:SSZ`, exactly 20 bytes.
fn render_rfc3339(buf: &mut [u8; 20], y: i64, m: u32, d: u32, hh: u32, mm: u32, ss: u32) {
    put4_year(buf, 0, y);
    put(buf, 4, b'-');
    put2(buf, 5, m);
    put(buf, 7, b'-');
    put2(buf, 8, d);
    put(buf, 10, b'T');
    put2(buf, 11, hh);
    put(buf, 13, b':');
    put2(buf, 14, mm);
    put(buf, 16, b':');
    put2(buf, 17, ss);
    put(buf, 19, b'Z');
}

/// `DD/Mon/YYYY:HH:MM:SS +0000`, exactly 26 bytes. The zone is the literal `+0000`:
/// UTC only.
fn render_clf(buf: &mut [u8; 26], y: i64, m: u32, d: u32, hh: u32, mm: u32, ss: u32) {
    put2(buf, 0, d);
    put(buf, 2, b'/');
    let month_idx = usize::try_from(m.saturating_sub(1)).unwrap_or(0);
    let [b0, b1, b2] = MONTHS.get(month_idx).copied().unwrap_or(*b"Jan");
    put(buf, 3, b0);
    put(buf, 4, b1);
    put(buf, 5, b2);
    put(buf, 6, b'/');
    put4_year(buf, 7, y);
    put(buf, 11, b':');
    put2(buf, 12, hh);
    put(buf, 14, b':');
    put2(buf, 15, mm);
    put(buf, 17, b':');
    put2(buf, 18, ss);
    put(buf, 20, b' ');
    for (i, &byte) in b"+0000".iter().enumerate() {
        put(buf, 21 + i, byte);
    }
}

/// A pre rendered wall clock timestamp, refreshed at most once per whole second.
///
/// Copied from NGINX's `ngx_cached_http_log_time` and `ngx_cached_http_log_iso8601`,
/// which are cached in `src/core/ngx_times.h`, refreshed in `ngx_time_update()`, and
/// copied into a log line with `ngx_cpymem`. UTC only; the zone in the CLF form is the
/// literal `+0000`.
#[derive(Debug)]
pub struct CachedWall {
    secs: u64,
    rfc3339: [u8; 20],
    clf: [u8; 26],
}

impl CachedWall {
    /// A cache holding no valid timestamp yet.
    #[must_use]
    pub fn new() -> CachedWall {
        CachedWall {
            secs: u64::MAX,
            rfc3339: [b'0'; 20],
            clf: [b'0'; 26],
        }
    }

    /// Re renders if the whole second changed. Returns true when it re rendered.
    ///
    /// Follows the wall clock in both directions, including backwards (an NTP step):
    /// a log timestamp must report what the wall clock says, not what it said last.
    #[allow(
        clippy::many_single_char_names,
        reason = "w/s plus the y/m/d/hh/mm/ss tuple civil_from_unix_secs returns are \
                  the calendar field names every caller of that function uses; \
                  renaming them here would just require a comment mapping them back"
    )]
    pub fn refresh(&mut self, w: irontraffic_time::CoarseWall) -> bool {
        let ms = w.as_unix_millis();
        let s = ms / 1000;
        if s == self.secs {
            return false;
        }
        self.secs = s;
        let (y, m, d, hh, mm, ss) = civil_from_unix_secs(s);
        render_rfc3339(&mut self.rfc3339, y, m, d, hh, mm, ss);
        render_clf(&mut self.clf, y, m, d, hh, mm, ss);
        true
    }

    /// `YYYY-MM-DDTHH:MM:SSZ`, 20 bytes.
    #[must_use]
    pub fn rfc3339(&self) -> &[u8; 20] {
        &self.rfc3339
    }

    /// `DD/Mon/YYYY:HH:MM:SS +0000`, 26 bytes.
    #[must_use]
    pub fn clf(&self) -> &[u8; 26] {
        &self.clf
    }

    /// The whole second this cache currently holds.
    #[must_use]
    pub fn unix_secs(&self) -> u64 {
        self.secs
    }
}

impl Default for CachedWall {
    fn default() -> Self {
        CachedWall::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CachedWall, render_hex_lower, render_i32, render_millis_fixed, render_u32, render_u64,
    };
    use irontraffic_time::{TestTimeSource, TimeSource as _};
    use proptest::prelude::*;

    fn wall(ms: u64) -> irontraffic_time::CoarseWall {
        let ts = TestTimeSource::new();
        ts.set_wall_unix_millis(ms);
        ts.coarse_wall()
    }

    #[test]
    fn u64_boundaries() {
        for &(v, expected) in &[
            (0u64, "0"),
            (1, "1"),
            (9, "9"),
            (10, "10"),
            (99, "99"),
            (100, "100"),
            (12345, "12345"),
            (u64::MAX, "18446744073709551615"),
        ] {
            let mut out = Vec::new();
            let n = render_u64(v, &mut out);
            assert_eq!(out, expected.as_bytes());
            assert_eq!(n, expected.len());
            assert_eq!(n, out.len());
        }
    }

    #[test]
    fn millis_fixed_no_overflow() {
        // Every case checks the RETURNED length against `out.len()` as well as the
        // bytes: mutation testing found that the final `n + 1 + usize::from(decimals)`
        // return expression can have either `+` mutated to `*` or `-` without any
        // named test noticing, because none of them checked the returned count on the
        // fractional-digit path, only the bytes written.
        let mut out = Vec::new();
        let n = render_millis_fixed(u64::MAX, 3, &mut out);
        assert_eq!(out, b"18446744073709.551");
        assert_eq!(n, out.len());

        let mut out = Vec::new();
        let n = render_millis_fixed(999_999, 3, &mut out);
        assert_eq!(out, b"0.999");
        assert_eq!(n, out.len());

        let mut out = Vec::new();
        let n = render_millis_fixed(1_500_000, 1, &mut out);
        assert_eq!(out, b"1.5");
        assert_eq!(n, out.len());

        let mut out = Vec::new();
        let n = render_millis_fixed(1_500_000, 0, &mut out);
        assert_eq!(out, b"1");
        assert_eq!(n, out.len());

        // `decimals == 2` specifically: not named by the issue, added because
        // mutation testing found that deleting the `2 => 100` arm of the scale
        // `match` (falling through to the `_ => 1_000` arm instead) survived every
        // other test, none of which ever passed `decimals == 2`.
        let mut out = Vec::new();
        let n = render_millis_fixed(1_255_000, 2, &mut out);
        assert_eq!(out, b"1.25");
        assert_eq!(n, out.len());
    }

    #[test]
    fn cached_wall_epoch() {
        let mut cw = CachedWall::new();
        assert!(cw.refresh(wall(0)));
        assert_eq!(cw.rfc3339(), b"1970-01-01T00:00:00Z");
        assert_eq!(cw.clf(), b"01/Jan/1970:00:00:00 +0000");
    }

    #[test]
    fn cached_wall_refresh_is_per_second() {
        let mut cw = CachedWall::new();
        assert!(cw.refresh(wall(1_600_000_000_123)));
        assert_eq!(cw.rfc3339(), b"2020-09-13T12:26:40Z");
        assert!(!cw.refresh(wall(1_600_000_000_999)));
        assert_eq!(cw.rfc3339(), b"2020-09-13T12:26:40Z");
        assert!(cw.refresh(wall(1_600_000_001_000)));
        assert_eq!(cw.rfc3339(), b"2020-09-13T12:26:41Z");
    }

    #[test]
    fn cached_wall_leap_day() {
        // 2024-02-29T12:34:56Z is 1_709_210_096 unix seconds: 19_782 days since the
        // epoch (2024-01-01 is day 19_723, and Feb 29 is 59 days into a leap year)
        // times 86_400, plus 12:34:56 = 45_296 seconds of day.
        let mut cw = CachedWall::new();
        assert!(cw.refresh(wall(1_709_210_096_000)));
        assert_eq!(cw.rfc3339(), b"2024-02-29T12:34:56Z");
    }

    #[test]
    fn cached_wall_century_leap_year_boundary() {
        // Not named by the issue, added because mutation testing found it. 2000 is
        // divisible by 400, so `civil_from_unix_secs`'s `doe` (day of era) reaches
        // its maximum, 146_096, at 2000-02-29: the one day in every 400 years where
        // the `- doe / 146_096` term of the `yoe` formula is actually nonzero (it is
        // 0 for every other day in the era). Every other date this file tests keeps
        // that term at 0, so a `-` to `+` (or `/`) mutation there survived. 2000 is
        // also the classic leap-year-RULE boundary in the other direction from a
        // plain "divisible by 4" bug (1900 is divisible by 4 but NOT a leap year;
        // 2000 is divisible by 100 too, but IS one because it is also divisible by
        // 400), so this is independently a meaningful date to pin regardless of the
        // mutation it happens to catch.
        //
        // 2000-02-29T00:00:00Z is 951_782_400 unix seconds: 1970-01-01 to
        // 2000-01-01 is 10_957 days (30 years with 7 leap years, 1972..=1996 step
        // 4), plus 59 days to Feb 29 (31 in January, 28 more into February),
        // times 86_400.
        let mut cw = CachedWall::new();
        assert!(cw.refresh(wall(951_782_400_000)));
        assert_eq!(cw.rfc3339(), b"2000-02-29T00:00:00Z");
    }

    #[test]
    fn cached_wall_ordinary_century_year_is_not_a_leap_year() {
        // Not named by the issue, added because mutation testing found it: the
        // 2000-02-29 date above alone does not catch every mutation of the `yoe`
        // formula. cargo-mutants performs a token level operator swap, not an
        // AST-preserving one, so `- doe / 146_096` mutated to `/ doe / 146_096`
        // parses (by ordinary left to right precedence) as chained division,
        // collapsing that whole term to 0 for every `doe` except the single value
        // 146_096 itself, where the chain happens to numerically coincide with the
        // correct answer. 2100-03-01 lands at `doe == 36_524` in
        // `civil_from_unix_secs`'s internal era arithmetic, one of the many other
        // points (found by brute-force search over `0..146_097`) where the
        // mutant's collapsed term of `0` and the correct term of `doe / 36_524 -
        // doe / 146_096 == 1` land the `/ 365` division on opposite sides of a
        // multiple of 365, giving a different year outright (verified against
        // Python's independent `datetime` before writing this test). 2100 is also
        // independently meaningful: divisible by 100 but not by 400, so it is an
        // ORDINARY (non-leap) year, the opposite century-boundary case from
        // 2000's leap year above.
        let mut cw = CachedWall::new();
        assert!(cw.refresh(wall(4_107_542_400_000)));
        assert_eq!(cw.rfc3339(), b"2100-03-01T00:00:00Z");
    }

    #[test]
    fn put4_year_stays_correct_for_a_year_beyond_u32_max() {
        // Not named by the issue, added because mutation testing found it.
        // `put4_year`'s `y % 10_000` bound is what keeps `u32::try_from` succeeding
        // no matter how large `y` is (the result is always in `0..=9999`). A `%` to
        // `+` mutation computes `y + 10_000` instead, which for every year this
        // file otherwise tests (all comfortably under `u32::MAX`) still fits in a
        // `u32` and, because the `/1000 %10`, `/100 %10`, `/10 %10`, `%10` digit
        // extraction that follows only ever depends on the value modulo 10_000, it
        // renders the EXACT SAME four digits either way. Only a year that pushes
        // `y + 10_000` past `u32::MAX` (while `y % 10_000` stays trivially in
        // range) can tell the two apart: the mutant's `u32::try_from` then fails
        // and silently falls back to 0, rendering "0000" instead of the year's
        // real low four digits.
        let mut buf = [0u8; 4];
        super::put4_year(&mut buf, 0, 5_000_000_007);
        assert_eq!(&buf, b"0007");
    }

    #[test]
    fn hex_lower_all_bytes() {
        use std::fmt::Write as _;

        let bytes: Vec<u8> = (0..=255u16).map(|b| u8::try_from(b).unwrap_or(0)).collect();
        let mut out = Vec::new();
        render_hex_lower(&bytes, &mut out);
        let mut expected = String::new();
        for b in &bytes {
            let _ = write!(expected, "{b:02x}");
        }
        assert_eq!(out, expected.as_bytes());
        assert!(out.iter().all(|b| !b.is_ascii_uppercase()));
    }

    #[test]
    fn millis_fixed_rejects_no_decimals() {
        let mut reference = Vec::new();
        render_millis_fixed(1_500_000, 3, &mut reference);
        for d in 0..=255u8 {
            let mut out = Vec::new();
            let n = render_millis_fixed(1_500_000, d, &mut out);
            assert!(n <= 24);
            assert!(out.len() <= 24);
            if d >= 3 {
                assert_eq!(out, reference);
            }
        }
    }

    #[test]
    fn u32_and_i32_render() {
        // Every case checks the RETURNED length against `out.len()`, not just the
        // bytes: mutation testing found that `render_i32`'s negative branch
        // (`1 + render_u64(...)`) can have its `+` mutated to `*` (`1 * x == x`)
        // without changing a single byte written to `out`, only the length it
        // reports back, which no test here previously checked.
        let mut out = Vec::new();
        let n = render_u32(u32::MAX, &mut out);
        assert_eq!(out, b"4294967295");
        assert_eq!(n, out.len());

        let mut out = Vec::new();
        let n = render_i32(i32::MIN, &mut out);
        assert_eq!(out, b"-2147483648");
        assert_eq!(n, out.len());

        let mut out = Vec::new();
        let n = render_i32(-1, &mut out);
        assert_eq!(out, b"-1");
        assert_eq!(n, out.len());

        let mut out = Vec::new();
        let n = render_i32(0, &mut out);
        assert_eq!(out, b"0");
        assert_eq!(n, out.len());
    }

    #[test]
    fn hex_lower_empty_writes_nothing() {
        let mut out = Vec::new();
        let n = render_hex_lower(&[], &mut out);
        assert_eq!(n, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn cached_wall_before_refresh_is_all_zero_bytes() {
        let cw = CachedWall::new();
        assert_eq!(cw.rfc3339(), &[b'0'; 20]);
        assert_eq!(cw.clf(), &[b'0'; 26]);
        assert_eq!(cw.unix_secs(), u64::MAX);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]
        #[test]
        fn prop_render_u64_matches_std(v: u64) {
            let mut out = Vec::new();
            render_u64(v, &mut out);
            prop_assert_eq!(out, v.to_string().into_bytes());
        }
    }

    /// Inverse of `civil_from_unix_secs`, written independently (days-from-civil, the
    /// other half of Howard Hinnant's pair) so this property test does not compare the
    /// code under test against itself.
    fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = u64::try_from(y - era * 400).unwrap_or(0);
        let mp = u64::from(if m > 2 { m - 3 } else { m + 9 });
        let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + i64::try_from(doe).unwrap_or(0) - 719_468
    }

    /// Whether `y` is a leap year, by the ordinary Gregorian rule: written
    /// independently of `civil_from_unix_secs`, which never computes this predicate
    /// explicitly at all (its era/century split handles leap years implicitly).
    fn is_leap(y: i64) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }

    /// Days in Gregorian month `m` of year `y`. Used only to keep the brute force
    /// search below from ever trying an impossible date such as June 31st, which
    /// `days_from_civil` would otherwise happily accept (it computes a day count for
    /// any (y, m, d) algebraically, valid calendar date or not) and which can collide
    /// numerically with the following month's 1st.
    fn days_in_month(y: i64, m: u32) -> u32 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            _ if is_leap(y) => 29,
            _ => 28,
        }
    }

    fn reference_rfc3339(ms: u64) -> Vec<u8> {
        let s = ms / 1000;
        let days = i64::try_from(s / 86_400).unwrap_or(0);
        let secs_of_day = s % 86_400;
        let hh = secs_of_day / 3600;
        let mm = (secs_of_day / 60) % 60;
        let ss = secs_of_day % 60;
        // A cheap estimate (366 days/year, deliberately a slight overestimate of the
        // true 365.2425 average so the window below leans early rather than late)
        // narrows the search to a handful of candidate years around the true one:
        // `days_from_civil` is monotone in the (year, month, day) triple taken as a
        // day count, so scanning a small window around the estimate and taking the
        // unique VALID calendar date that matches is exact, not approximate.
        let year_estimate = 1970 + days / 366 - 2;
        let mut found: Option<(i64, u32, u32)> = None;
        'outer: for cand_y in year_estimate..=year_estimate + 5 {
            for cand_m in 1..=12u32 {
                for cand_d in 1..=days_in_month(cand_y, cand_m) {
                    if days_from_civil(cand_y, cand_m, cand_d) == days {
                        found = Some((cand_y, cand_m, cand_d));
                        break 'outer;
                    }
                }
            }
        }
        let (y, m, d) = found.unwrap_or((1970, 1, 1));
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z").into_bytes()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn prop_cached_wall_matches_reference(ms in 0..=4_102_444_800_000u64) {
            let mut cw = CachedWall::new();
            cw.refresh(wall(ms));
            prop_assert_eq!(cw.rfc3339().to_vec(), reference_rfc3339(ms));
            prop_assert_eq!(cw.unix_secs(), ms / 1000);
        }
    }
}
