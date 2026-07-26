// SPDX-License-Identifier: MIT OR Apache-2.0

//! Quota period arithmetic.

use core::hash::Hasher;

use jiff::Span;
use jiff::Timestamp;
use jiff::civil::{Date, DateTime};
use jiff::tz::TimeZone;

use irontraffic_time::CoarseWall;

/// A period, identified by its start in unix milliseconds.
///
/// Totally ordered, so it compares directly against a persisted watermark, and
/// identical on every node because every input is configuration or the subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeriodId(pub u64);

/// A 128-bit keyed hash of a quota subject.
///
/// Ordered as well as hashable, because `QuotaKey` in
/// `{{quota-store-wal-and-checkpoints}}` derives `Ord` and a derived `Ord`
/// requires every field to have one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectHash {
    /// Upper 64 bits. Storage sharding.
    pub hi: u64,
    /// Lower 64 bits. Boundary anchoring.
    pub lo: u64,
}

/// Largest quota subject, in bytes.
///
/// A subject is derived from request-supplied material, so hashing it and
/// storing it are both linear in a length a client influences. 256 bytes is
/// generous for an API key, a consumer id or a plan identifier, and it bounds
/// both the hash cost and the durable record size.
/// `{{quota-store-wal-and-checkpoints}}` enforces it; this crate states it.
pub const MAX_SUBJECT_BYTES: usize = 256;

/// The configured seed for subject hashing.
///
/// Derived from configuration, NOT from process entropy. A quota subject hash
/// decides a durable period boundary and must agree across restarts and across
/// every node, or a customer's period would move when they reconnected
/// elsewhere. This is deliberately the opposite of the rate limiter's key seed.
#[derive(Debug, Clone, Copy)]
pub struct QuotaSeed([u8; 16]);

impl QuotaSeed {
    /// Derives the seed from a configured secret with a fixed label.
    #[must_use]
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let mut key = [0u8; 16];
        for (dst, src) in key.iter_mut().zip(secret.iter()) {
            *dst = *src;
        }
        let mut h = siphasher::sip128::SipHasher13::new_with_key(&key);
        h.write(b"irontraffic/quota/subject/v1");
        let out = siphasher::sip128::Hasher128::finish128(&h);
        let mut seed = [0u8; 16];
        seed[..8].copy_from_slice(&out.h1.to_le_bytes());
        seed[8..].copy_from_slice(&out.h2.to_le_bytes());
        Self(seed)
    }

    /// A fixed seed, for tests and for a single-node deployment with no cluster
    /// secret.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Hashes a subject.
    ///
    /// Cost is linear in `subject.len()`, and a subject is derived from
    /// request-supplied material such as an API key or a consumer id, so the
    /// caller MUST bound it. [`MAX_SUBJECT_BYTES`] is the bound
    /// `{{quota-store-wal-and-checkpoints}}` enforces, and it is defined here so
    /// there is one number rather than one per call site. This function does not
    /// truncate: truncating would silently merge two subjects into one quota,
    /// and rejecting an over-long subject at the store is the correct place.
    #[must_use]
    pub fn hash(&self, subject: &[u8]) -> SubjectHash {
        let mut h = siphasher::sip128::SipHasher13::new_with_key(&self.0);
        h.write(subject);
        let out = siphasher::sip128::Hasher128::finish128(&h);
        SubjectHash {
            hi: out.h1,
            lo: out.h2,
        }
    }
}

/// Where a rolling period's boundary sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Anchor {
    /// Aligned to the unix epoch. Every subject's period starts at the same
    /// instant, which is a synchronised traffic step at every boundary.
    Epoch,
    /// Offset deterministically by a hash of the subject, spreading the step
    /// across the whole period. The default.
    #[default]
    Subject,
}

/// A calendar period's unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarUnit {
    /// One calendar day in the configured zone.
    Day,
    /// Seven days from the anchored weekday.
    Week,
    /// One calendar month. Not 30 days.
    Month,
    /// One calendar year. Not 365 days.
    Year,
}

/// Where a calendar period starts. Unused fields must be left at their defaults
/// or construction fails, so a misconfigured field is an error rather than a
/// silently ignored value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalendarAnchor {
    /// 1 to 12. Used by [`CalendarUnit::Year`] only.
    pub month_of_year: u8,
    /// 1 to 31, clamped down to the month's last day. Used by
    /// [`CalendarUnit::Month`] and [`CalendarUnit::Year`].
    pub day_of_month: u8,
    /// 1 (Monday) to 7 (Sunday). Used by [`CalendarUnit::Week`] only.
    pub weekday: u8,
    /// 0 to 23, in the configured zone. Used by every unit.
    pub hour: u8,
}

impl CalendarAnchor {
    /// Midnight on the first, Monday, January.
    #[must_use]
    pub const fn default_anchor() -> Self {
        Self {
            month_of_year: 1,
            day_of_month: 1,
            weekday: 1,
            hour: 0,
        }
    }
}

/// Subject spread modulus for [`CalendarUnit::Week`], [`CalendarUnit::Month`]
/// and [`CalendarUnit::Year`], in milliseconds.
///
/// One day, and a CONSTANT: a modulus derived from the resolved window length
/// would differ between a 23-hour daylight-saving day and its 24-hour neighbour,
/// so adjacent periods would receive different spreads and would no longer tile.
pub const SPREAD_MODULUS_MS: u64 = 86_400_000;

/// Subject spread modulus for [`CalendarUnit::Day`], in milliseconds.
///
/// One hour, not one day. The recomputation in `calendar_window` step 7 walks
/// back exactly one period, so the spread must be strictly smaller than the
/// shortest possible preceding period, and the shortest `Day` period is 23
/// hours on a spring-forward day. A one-day modulus would put an instant two
/// periods back for some subjects on two days a year, and the returned window
/// would not contain it.
pub const SPREAD_MODULUS_DAY_MS: u64 = 3_600_000;

/// The spread modulus for a unit. Constant per unit, so tiling is preserved,
/// and strictly below that unit's shortest possible period, so one step back in
/// `calendar_window` step 7 is always enough.
#[must_use]
pub const fn spread_modulus_ms(unit: CalendarUnit) -> u64 {
    match unit {
        CalendarUnit::Day => SPREAD_MODULUS_DAY_MS,
        CalendarUnit::Week | CalendarUnit::Month | CalendarUnit::Year => SPREAD_MODULUS_MS,
    }
}

/// A quota period definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Period {
    /// A fixed-length window.
    Rolling {
        /// Length in seconds, 1 to `31_536_000`.
        length_secs: u64,
        /// Boundary anchoring.
        anchor: Anchor,
    },
    /// A real calendar period in an IANA timezone.
    ///
    /// This is what Envoy's reference rate limit service cannot express: its
    /// `UnitToDivider()` defines MONTH as `60*60*24*30` and YEAR as
    /// `60*60*24*365`, so a plan billed on calendar months drifts by 5 to 6 days
    /// per year and ignores leap years.
    Calendar {
        /// Day, week, month or year.
        unit: CalendarUnit,
        /// An IANA timezone identifier, for example `Europe/Berlin`.
        tz: Box<str>,
        /// Where the period starts.
        anchor: CalendarAnchor,
        /// Offset each subject's boundary by up to one day, to spread the reset
        /// step. Opt-in, because some billing arrangements require a true
        /// calendar boundary.
        subject_spread: bool,
    },
}

/// One resolved period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodWindow {
    /// The period's identity, equal to `start_unix_ms`.
    pub id: PeriodId,
    /// Inclusive start.
    pub start_unix_ms: u64,
    /// Exclusive end.
    pub end_unix_ms: u64,
}

impl PeriodWindow {
    /// Milliseconds until the period ends, saturating at 0.
    #[must_use]
    pub const fn remaining_ms(&self, now_unix_ms: u64) -> u64 {
        self.end_unix_ms.saturating_sub(now_unix_ms)
    }

    /// True when `now` is inside this window.
    #[must_use]
    pub const fn contains(&self, now_unix_ms: u64) -> bool {
        self.start_unix_ms <= now_unix_ms && now_unix_ms < self.end_unix_ms
    }
}

impl From<jiff::Error> for PeriodError {
    fn from(_: jiff::Error) -> Self {
        PeriodError::OutOfRange { unix_ms: 0 }
    }
}

/// Period arithmetic could not be performed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeriodError {
    /// The IANA identifier is not in the bundled database.
    #[error("unknown timezone {name}")]
    UnknownTimeZone {
        /// What was configured.
        name: Box<str>,
    },
    /// An anchor field is out of range or set for a unit that does not use it.
    #[error("invalid calendar anchor: {why}")]
    InvalidAnchor {
        /// A fixed explanation naming the field.
        why: &'static str,
    },
    /// The rolling length is 0 or above one year.
    #[error("rolling period length must be 1 to 31_536_000 seconds, got {secs}")]
    InvalidLength {
        /// What was configured.
        secs: u64,
    },
    /// The instant is outside the range calendar arithmetic can represent.
    #[error("instant {unix_ms} is outside the representable range")]
    OutOfRange {
        /// What was passed.
        unix_ms: u64,
    },
}

/// A compiled period definition with its timezone resolved once.
#[derive(Debug, Clone)]
pub struct PeriodResolver {
    period: Period,
    tz: Option<TimeZone>,
}

/// Minimum unix millisecond for calendar resolution.
///
/// One day of slack over the largest possible zone offset.
const MIN_RESOLVABLE_UNIX_MS: u64 = 86_400_000;

/// Maximum unix millisecond for calendar resolution.
const MAX_RESOLVABLE_UNIX_MS: u64 = 4_102_444_800_000;

/// Maximum rolling length in seconds.
const MAX_ROLLING_LENGTH_SECS: u64 = 31_536_000;

impl PeriodResolver {
    /// Compiles a period, resolving the timezone against the bundled database.
    ///
    /// Do this at configuration time. A timezone lookup allocates and touches
    /// the database; the resolved handle is then reused for every request.
    ///
    /// # Errors
    /// [`PeriodError::UnknownTimeZone`], [`PeriodError::InvalidAnchor`] and
    /// [`PeriodError::InvalidLength`].
    pub fn new(period: Period) -> Result<Self, PeriodError> {
        let tz = match &period {
            Period::Rolling {
                length_secs,
                anchor: _,
            } => {
                if *length_secs == 0 || *length_secs > MAX_ROLLING_LENGTH_SECS {
                    return Err(PeriodError::InvalidLength { secs: *length_secs });
                }
                None
            }
            Period::Calendar {
                unit,
                tz,
                anchor,
                subject_spread: _,
            } => {
                validate_anchor(*unit, *anchor)?;
                Some(
                    TimeZone::get(tz.as_ref())
                        .map_err(|_| PeriodError::UnknownTimeZone { name: tz.clone() })?,
                )
            }
        };
        Ok(Self { period, tz })
    }

    /// The period containing `now` for `subject`.
    ///
    /// Pure: identical inputs give identical outputs on any machine.
    ///
    /// # Errors
    /// [`PeriodError::OutOfRange`] for an instant calendar arithmetic cannot
    /// represent.
    pub fn period_of(
        &self,
        subject: SubjectHash,
        now: CoarseWall,
    ) -> Result<PeriodWindow, PeriodError> {
        let now_ms = now.as_unix_millis();
        match &self.period {
            Period::Rolling {
                length_secs,
                anchor,
            } => Ok(rolling_window(*length_secs, *anchor, subject, now_ms)),
            Period::Calendar {
                unit,
                tz: _,
                anchor,
                subject_spread,
            } => {
                let tz = self
                    .tz
                    .as_ref()
                    .ok_or(PeriodError::OutOfRange { unix_ms: now_ms })?;
                calendar_window(*unit, tz, *anchor, *subject_spread, subject, now_ms)
            }
        }
    }

    /// The configured definition, for the admin config dump.
    #[must_use]
    pub fn period(&self) -> &Period {
        &self.period
    }
}

#[allow(
    clippy::integer_division,
    reason = "exact period boundary per the specification"
)]
fn rolling_window(
    length_secs: u64,
    anchor: Anchor,
    subject: SubjectHash,
    now_ms: u64,
) -> PeriodWindow {
    let len_ms = length_secs * 1_000;
    let offset = match anchor {
        Anchor::Epoch => 0,
        Anchor::Subject => subject.lo % len_ms,
    };
    if now_ms < offset {
        return PeriodWindow {
            id: PeriodId(0),
            start_unix_ms: 0,
            end_unix_ms: offset,
        };
    }
    let start = ((now_ms - offset) / len_ms) * len_ms + offset;
    PeriodWindow {
        id: PeriodId(start),
        start_unix_ms: start,
        end_unix_ms: start.saturating_add(len_ms),
    }
}

fn validate_anchor(unit: CalendarUnit, a: CalendarAnchor) -> Result<(), PeriodError> {
    if !(1..=12).contains(&a.month_of_year) {
        return Err(PeriodError::InvalidAnchor {
            why: "month_of_year must be 1 to 12",
        });
    }
    if !(1..=31).contains(&a.day_of_month) {
        return Err(PeriodError::InvalidAnchor {
            why: "day_of_month must be 1 to 31",
        });
    }
    if !(1..=7).contains(&a.weekday) {
        return Err(PeriodError::InvalidAnchor {
            why: "weekday must be 1 (Monday) to 7 (Sunday)",
        });
    }
    if a.hour > 23 {
        return Err(PeriodError::InvalidAnchor {
            why: "hour must be 0 to 23",
        });
    }
    match unit {
        CalendarUnit::Day => {
            if a.month_of_year != 1 {
                return Err(PeriodError::InvalidAnchor {
                    why: "month_of_year must be 1 for a daily period",
                });
            }
            if a.day_of_month != 1 {
                return Err(PeriodError::InvalidAnchor {
                    why: "day_of_month must be 1 for a daily period",
                });
            }
            if a.weekday != 1 {
                return Err(PeriodError::InvalidAnchor {
                    why: "weekday must be 1 for a daily period",
                });
            }
        }
        CalendarUnit::Week => {
            if a.month_of_year != 1 {
                return Err(PeriodError::InvalidAnchor {
                    why: "month_of_year must be 1 for a weekly period",
                });
            }
            if a.day_of_month != 1 {
                return Err(PeriodError::InvalidAnchor {
                    why: "day_of_month must be 1 for a weekly period",
                });
            }
        }
        CalendarUnit::Month => {
            if a.month_of_year != 1 {
                return Err(PeriodError::InvalidAnchor {
                    why: "month_of_year must be 1 for a monthly period",
                });
            }
            if a.weekday != 1 {
                return Err(PeriodError::InvalidAnchor {
                    why: "weekday must be 1 for a monthly period",
                });
            }
        }
        CalendarUnit::Year => {
            if a.weekday != 1 {
                return Err(PeriodError::InvalidAnchor {
                    why: "weekday must be 1 for a yearly period",
                });
            }
        }
    }
    Ok(())
}

fn calendar_window(
    unit: CalendarUnit,
    tz: &TimeZone,
    anchor: CalendarAnchor,
    subject_spread: bool,
    subject: SubjectHash,
    now_ms: u64,
) -> Result<PeriodWindow, PeriodError> {
    if !(MIN_RESOLVABLE_UNIX_MS..MAX_RESOLVABLE_UNIX_MS).contains(&now_ms) {
        return Err(PeriodError::OutOfRange { unix_ms: now_ms });
    }

    let now_i64 = i64::try_from(now_ms).map_err(|_| PeriodError::OutOfRange { unix_ms: now_ms })?;
    let now_zoned = Timestamp::from_millisecond(now_i64)
        .map_err(|_| PeriodError::OutOfRange { unix_ms: now_ms })?
        .to_zoned(tz.clone());
    let now_civil = now_zoned.datetime();
    let hour = i8::try_from(anchor.hour).map_err(|_| PeriodError::InvalidAnchor {
        why: "hour must be 0 to 23",
    })?;

    let civil_start = calendar_civil_start(unit, hour, anchor, now_civil, tz)?;
    let (mut start_ms, mut end_ms) = window_ms_for_civil(unit, anchor, civil_start, tz)?;

    if subject_spread {
        let spread = i64::try_from(subject.lo % spread_modulus_ms(unit))
            .map_err(|_| PeriodError::OutOfRange { unix_ms: now_ms })?;
        start_ms += spread;
        end_ms += spread;
        let now_i64 =
            i64::try_from(now_ms).map_err(|_| PeriodError::OutOfRange { unix_ms: now_ms })?;
        if now_i64 < start_ms {
            let prev = civil_add_unit(unit, anchor, civil_start, -1)?;
            let (prev_start_ms, prev_end_ms) = window_ms_for_civil(unit, anchor, prev, tz)?;
            start_ms = prev_start_ms + spread;
            end_ms = prev_end_ms + spread;
        }
    }

    let start = u64::try_from(start_ms).map_err(|_| PeriodError::OutOfRange { unix_ms: now_ms })?;
    let end = u64::try_from(end_ms).map_err(|_| PeriodError::OutOfRange { unix_ms: now_ms })?;
    Ok(PeriodWindow {
        id: PeriodId(start),
        start_unix_ms: start,
        end_unix_ms: end,
    })
}

fn calendar_civil_start(
    unit: CalendarUnit,
    hour: i8,
    anchor: CalendarAnchor,
    now: DateTime,
    tz: &TimeZone,
) -> Result<DateTime, PeriodError> {
    let candidate = candidate_for_unit(unit, hour, anchor, now)?;
    let candidate_zoned = resolve_civil(tz, candidate)?;
    if candidate_zoned.datetime() > now {
        civil_add_unit(unit, anchor, candidate, -1)
    } else {
        Ok(candidate)
    }
}

fn candidate_for_unit(
    unit: CalendarUnit,
    hour: i8,
    anchor: CalendarAnchor,
    now: DateTime,
) -> Result<DateTime, PeriodError> {
    let year = now.year();
    let month = now.month();
    let day = now.day();
    match unit {
        CalendarUnit::Day => Ok(DateTime::new(year, month, day, hour, 0, 0, 0)?),
        CalendarUnit::Week => {
            let today_weekday = now.weekday().to_monday_one_offset();
            let target_weekday =
                i8::try_from(anchor.weekday).map_err(|_| PeriodError::InvalidAnchor {
                    why: "weekday must be 1 to 7",
                })?;
            let days_back = (today_weekday - target_weekday + 7) % 7;
            let date = Date::new(year, month, day)?
                .checked_add(Span::new().days(-i64::from(days_back)))?;
            Ok(DateTime::new(
                date.year(),
                date.month(),
                date.day(),
                hour,
                0,
                0,
                0,
            )?)
        }
        CalendarUnit::Month => {
            let clamped = clamped_day(year, month, anchor.day_of_month)?;
            Ok(DateTime::new(year, month, clamped, hour, 0, 0, 0)?)
        }
        CalendarUnit::Year => {
            let month =
                i8::try_from(anchor.month_of_year).map_err(|_| PeriodError::InvalidAnchor {
                    why: "month_of_year must be 1 to 12",
                })?;
            let clamped = clamped_day(year, month, anchor.day_of_month)?;
            Ok(DateTime::new(year, month, clamped, hour, 0, 0, 0)?)
        }
    }
}

fn clamped_day(year: i16, month: i8, day_of_month: u8) -> Result<i8, PeriodError> {
    let dim = Date::new(year, month, 1)?.days_in_month();
    let requested = i8::try_from(day_of_month).map_err(|_| PeriodError::InvalidAnchor {
        why: "day_of_month must be 1 to 31",
    })?;
    Ok(if requested > dim { dim } else { requested })
}

fn civil_add_unit(
    unit: CalendarUnit,
    anchor: CalendarAnchor,
    dt: DateTime,
    sign: i64,
) -> Result<DateTime, PeriodError> {
    let year = dt.year();
    let month = dt.month();
    let day = dt.day();
    let hour = dt.hour();
    let (y, m, d) = match unit {
        CalendarUnit::Day => {
            let date = Date::new(year, month, day)?.checked_add(Span::new().days(sign))?;
            (date.year(), date.month(), date.day())
        }
        CalendarUnit::Week => {
            let date = Date::new(year, month, day)?.checked_add(Span::new().days(sign * 7))?;
            (date.year(), date.month(), date.day())
        }
        CalendarUnit::Month => {
            let (y, m) = if sign > 0 {
                if month == 12 {
                    (year + 1, 1)
                } else {
                    (year, month + 1)
                }
            } else if month == 1 {
                (year - 1, 12)
            } else {
                (year, month - 1)
            };
            let dim = Date::new(y, m, 1)?.days_in_month();
            let requested =
                i8::try_from(anchor.day_of_month).map_err(|_| PeriodError::InvalidAnchor {
                    why: "day_of_month must be 1 to 31",
                })?;
            let d = if requested > dim { dim } else { requested };
            (y, m, d)
        }
        CalendarUnit::Year => {
            let y =
                year + i16::try_from(sign).map_err(|_| PeriodError::OutOfRange { unix_ms: 0 })?;
            let m = i8::try_from(anchor.month_of_year).map_err(|_| PeriodError::InvalidAnchor {
                why: "month_of_year must be 1 to 12",
            })?;
            let dim = Date::new(y, m, 1)?.days_in_month();
            let requested =
                i8::try_from(anchor.day_of_month).map_err(|_| PeriodError::InvalidAnchor {
                    why: "day_of_month must be 1 to 31",
                })?;
            let d = if requested > dim { dim } else { requested };
            (y, m, d)
        }
    };
    Ok(DateTime::new(y, m, d, hour, 0, 0, 0)?)
}

fn window_ms_for_civil(
    unit: CalendarUnit,
    anchor: CalendarAnchor,
    civil_start: DateTime,
    tz: &TimeZone,
) -> Result<(i64, i64), PeriodError> {
    let start_zoned = resolve_civil(tz, civil_start)?;
    let next_civil = civil_add_unit(unit, anchor, civil_start, 1)?;
    let end_zoned = resolve_civil(tz, next_civil)?;
    let start_ms = start_zoned.timestamp().as_millisecond();
    let end_ms = end_zoned.timestamp().as_millisecond();
    Ok((start_ms, end_ms))
}

fn resolve_civil(tz: &TimeZone, dt: DateTime) -> Result<jiff::Zoned, PeriodError> {
    Ok(tz.to_ambiguous_zoned(dt).compatible()?)
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PeriodResolver>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use irontraffic_time::TimeSource;

    #[test]
    fn rolling_contains_and_tiles() {
        let p = Period::Rolling {
            length_secs: 60,
            anchor: Anchor::Epoch,
        };
        let r = PeriodResolver::new(p).unwrap();
        let source = irontraffic_time::TestTimeSource::new();
        source.set_wall_unix_millis(0);
        let w0 = r
            .period_of(SubjectHash { hi: 0, lo: 0 }, source.coarse_wall())
            .unwrap();
        assert_eq!(w0.start_unix_ms, 0);
        assert_eq!(w0.end_unix_ms, 60_000);
        assert!(w0.contains(0));
        assert!(w0.contains(59_999));
        assert!(!w0.contains(60_000));
    }
}
