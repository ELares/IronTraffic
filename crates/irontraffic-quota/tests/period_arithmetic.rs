// SPDX-License-Identifier: MIT OR Apache-2.0

//! Quota period arithmetic tests.

#![allow(
    clippy::cast_sign_loss,
    clippy::unwrap_used,
    reason = "test helpers only use post-epoch instants and fixed valid civil dates"
)]

use std::collections::HashSet;

use proptest::prelude::*;

use irontraffic_quota::{
    Anchor, CalendarAnchor, CalendarUnit, Period, PeriodError, PeriodResolver, PeriodWindow,
    QuotaSeed, SubjectHash, spread_modulus_ms,
};
use irontraffic_time::{TestTimeSource, TimeSource};

fn seed() -> QuotaSeed {
    QuotaSeed::from_bytes([0x77; 16])
}

fn wall(ms: u64) -> irontraffic_time::CoarseWall {
    let source = TestTimeSource::new();
    source.set_wall_unix_millis(ms);
    source.coarse_wall()
}

fn utc_ms(year: i16, month: i8, day: i8, hour: i8, minute: i8, second: i8) -> i64 {
    let dt = jiff::civil::DateTime::new(year, month, day, hour, minute, second, 0).unwrap();
    let tz = jiff::tz::TimeZone::get("UTC").unwrap();
    dt.to_zoned(tz).unwrap().timestamp().as_millisecond()
}

fn local_ms(tz_name: &str, year: i16, month: i8, day: i8, hour: i8, minute: i8) -> i64 {
    let dt = jiff::civil::DateTime::new(year, month, day, hour, minute, 0, 0).unwrap();
    let tz = jiff::tz::TimeZone::get(tz_name).unwrap();
    dt.to_zoned(tz).unwrap().timestamp().as_millisecond()
}

fn zoned_day_of_month(tz_name: &str, unix_ms: u64) -> i8 {
    let tz = jiff::tz::TimeZone::get(tz_name).unwrap();
    let z = jiff::Timestamp::from_millisecond(i64::try_from(unix_ms).unwrap())
        .unwrap()
        .to_zoned(tz);
    z.day()
}

fn window_ms(w: PeriodWindow) -> u64 {
    w.end_unix_ms - w.start_unix_ms
}

fn subject_for(i: usize) -> SubjectHash {
    seed().hash(&i.to_le_bytes())
}

#[test]
fn rolling_periods_tile_without_gaps() {
    let period = Period::Rolling {
        length_secs: 3600,
        anchor: Anchor::Epoch,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let subject = subject_for(0);
    let mut windows = Vec::new();
    for i in 0..1_000 {
        let now_ms = u64::try_from(i).unwrap() * 60_000;
        let w = resolver.period_of(subject, wall(now_ms)).unwrap();
        assert!(w.contains(now_ms), "window {w:?} does not contain {now_ms}");
        windows.push(w);
    }
    let unique: Vec<_> = windows.iter().copied().fold(Vec::new(), |mut acc, w| {
        if acc.last() != Some(&w) {
            acc.push(w);
        }
        acc
    });
    for pair in unique.windows(2) {
        assert_eq!(pair[0].end_unix_ms, pair[1].start_unix_ms);
    }
}

#[test]
fn subject_anchoring_spreads_boundaries() {
    let period = Period::Rolling {
        length_secs: 86_400,
        anchor: Anchor::Subject,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let mut offsets = HashSet::new();
    for i in 0..10_000 {
        let w = resolver
            .period_of(subject_for(i), wall(86_400_000 * 5))
            .unwrap();
        offsets.insert(w.start_unix_ms % 86_400_000);
    }
    assert!(
        offsets.len() >= 9_000,
        "only {} distinct offsets",
        offsets.len()
    );

    let period = Period::Rolling {
        length_secs: 86_400,
        anchor: Anchor::Epoch,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let mut offsets = HashSet::new();
    for i in 0..10_000 {
        let w = resolver
            .period_of(subject_for(i), wall(86_400_000 * 5))
            .unwrap();
        offsets.insert(w.start_unix_ms % 86_400_000);
    }
    assert_eq!(offsets.len(), 1);
}

#[test]
fn calendar_month_is_not_thirty_days() {
    let period = Period::Calendar {
        unit: CalendarUnit::Month,
        tz: Box::from("UTC"),
        anchor: CalendarAnchor::default_anchor(),
        subject_spread: false,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let subject = subject_for(0);

    let jan_ms = utc_ms(2026, 1, 15, 0, 0, 0) as u64;
    let jan = resolver.period_of(subject, wall(jan_ms)).unwrap();
    assert_eq!(jan.start_unix_ms, utc_ms(2026, 1, 1, 0, 0, 0) as u64);
    assert_eq!(jan.end_unix_ms, utc_ms(2026, 2, 1, 0, 0, 0) as u64);
    assert_eq!(window_ms(jan), 86_400_000 * 31);

    let feb_ms = utc_ms(2026, 2, 15, 0, 0, 0) as u64;
    let feb = resolver.period_of(subject, wall(feb_ms)).unwrap();
    assert_eq!(feb.start_unix_ms, utc_ms(2026, 2, 1, 0, 0, 0) as u64);
    assert_eq!(feb.end_unix_ms, utc_ms(2026, 3, 1, 0, 0, 0) as u64);
    assert_eq!(window_ms(feb), 86_400_000 * 28);

    assert_ne!(
        window_ms(jan),
        86_400_000 * 30,
        "Envoy UnitToDivider defines a month as 30 days"
    );
    assert_ne!(
        window_ms(feb),
        86_400_000 * 30,
        "Envoy UnitToDivider defines a month as 30 days"
    );
}

#[test]
fn calendar_year_handles_leap_years() {
    let period = Period::Calendar {
        unit: CalendarUnit::Year,
        tz: Box::from("UTC"),
        anchor: CalendarAnchor {
            month_of_year: 1,
            ..CalendarAnchor::default_anchor()
        },
        subject_spread: false,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let subject = subject_for(0);

    let y2024 = resolver
        .period_of(subject, wall(utc_ms(2024, 7, 1, 12, 0, 0) as u64))
        .unwrap();
    assert_eq!(y2024.start_unix_ms, utc_ms(2024, 1, 1, 0, 0, 0) as u64);
    assert_eq!(y2024.end_unix_ms, utc_ms(2025, 1, 1, 0, 0, 0) as u64);
    assert_eq!(window_ms(y2024), 86_400_000 * 366);

    let y2025 = resolver
        .period_of(subject, wall(utc_ms(2025, 7, 1, 12, 0, 0) as u64))
        .unwrap();
    assert_eq!(y2025.start_unix_ms, utc_ms(2025, 1, 1, 0, 0, 0) as u64);
    assert_eq!(y2025.end_unix_ms, utc_ms(2026, 1, 1, 0, 0, 0) as u64);
    assert_eq!(window_ms(y2025), 86_400_000 * 365);
}

#[test]
fn day_of_month_clamps_in_short_months() {
    let period = Period::Calendar {
        unit: CalendarUnit::Month,
        tz: Box::from("UTC"),
        anchor: CalendarAnchor {
            day_of_month: 31,
            ..CalendarAnchor::default_anchor()
        },
        subject_spread: false,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let subject = subject_for(0);

    let cases = &[
        (2026, 4, 30),
        (2026, 5, 31),
        (2026, 6, 30),
        (2026, 9, 30),
        (2026, 11, 30),
    ];
    for &(year, month, expected_day) in cases {
        let next_month = month + 1;
        let now_ms = utc_ms(year, next_month, 15, 12, 0, 0) as u64;
        let w = resolver.period_of(subject, wall(now_ms)).unwrap();
        assert_eq!(zoned_day_of_month("UTC", w.start_unix_ms), expected_day);
    }
}

#[test]
fn february_twenty_nine_clamps_outside_leap_years() {
    let period = Period::Calendar {
        unit: CalendarUnit::Year,
        tz: Box::from("UTC"),
        anchor: CalendarAnchor {
            month_of_year: 2,
            day_of_month: 29,
            ..CalendarAnchor::default_anchor()
        },
        subject_spread: false,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let subject = subject_for(0);

    let leap = resolver
        .period_of(subject, wall(utc_ms(2024, 7, 1, 12, 0, 0) as u64))
        .unwrap();
    assert_eq!(zoned_day_of_month("UTC", leap.start_unix_ms), 29);

    let non_leap = resolver
        .period_of(subject, wall(utc_ms(2025, 7, 1, 12, 0, 0) as u64))
        .unwrap();
    assert_eq!(zoned_day_of_month("UTC", non_leap.start_unix_ms), 28);
}

#[test]
fn spring_forward_gap_resolves_later() {
    let period = Period::Calendar {
        unit: CalendarUnit::Day,
        tz: Box::from("America/New_York"),
        anchor: CalendarAnchor {
            hour: 2,
            ..CalendarAnchor::default_anchor()
        },
        subject_spread: false,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let subject = subject_for(0);

    let now_ms = local_ms("America/New_York", 2026, 3, 8, 12, 0) as u64;
    let w = resolver.period_of(subject, wall(now_ms)).unwrap();
    assert_eq!(
        w.start_unix_ms,
        local_ms("America/New_York", 2026, 3, 8, 3, 0) as u64
    );
    assert_eq!(window_ms(w), 86_400_000 - 3_600_000);
    assert!(w.contains(local_ms("America/New_York", 2026, 3, 8, 12, 0) as u64));
    assert!(!w.contains(utc_ms(2026, 3, 8, 6, 0, 0) as u64));
}

#[test]
fn autumn_fold_resolves_to_the_first_occurrence() {
    let period = Period::Calendar {
        unit: CalendarUnit::Day,
        tz: Box::from("America/New_York"),
        anchor: CalendarAnchor {
            hour: 1,
            ..CalendarAnchor::default_anchor()
        },
        subject_spread: false,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let subject = subject_for(0);

    let now_ms = local_ms("America/New_York", 2026, 11, 1, 15, 0) as u64;
    let w = resolver.period_of(subject, wall(now_ms)).unwrap();
    assert_eq!(w.start_unix_ms, utc_ms(2026, 11, 1, 5, 0, 0) as u64);
    assert_eq!(window_ms(w), 86_400_000 + 3_600_000);
}

#[test]
fn timezone_changes_the_boundary() {
    let anchor = CalendarAnchor::default_anchor();
    let period_utc = Period::Calendar {
        unit: CalendarUnit::Month,
        tz: Box::from("UTC"),
        anchor,
        subject_spread: false,
    };
    let period_auckland = Period::Calendar {
        unit: CalendarUnit::Month,
        tz: Box::from("Pacific/Auckland"),
        anchor,
        subject_spread: false,
    };
    let resolver_utc = PeriodResolver::new(period_utc).unwrap();
    let resolver_auckland = PeriodResolver::new(period_auckland).unwrap();
    let subject = subject_for(0);

    let now_ms = utc_ms(2026, 1, 15, 12, 0, 0) as u64;
    let utc_window = resolver_utc.period_of(subject, wall(now_ms)).unwrap();
    let auckland_window = resolver_auckland.period_of(subject, wall(now_ms)).unwrap();
    assert_eq!(
        utc_window.start_unix_ms - auckland_window.start_unix_ms,
        46_800_000
    );
    assert_ne!(window_ms(utc_window), 86_400_000 * 30);
    assert_ne!(window_ms(auckland_window), 86_400_000 * 30);
}

#[test]
fn unknown_timezone_and_invalid_anchors_are_errors() {
    assert!(matches!(
        PeriodResolver::new(Period::Calendar {
            unit: CalendarUnit::Day,
            tz: Box::from(""),
            anchor: CalendarAnchor::default_anchor(),
            subject_spread: false,
        }),
        Err(PeriodError::UnknownTimeZone { .. })
    ));
    assert!(matches!(
        PeriodResolver::new(Period::Calendar {
            unit: CalendarUnit::Day,
            tz: Box::from("Not/AZone"),
            anchor: CalendarAnchor::default_anchor(),
            subject_spread: false,
        }),
        Err(PeriodError::UnknownTimeZone { .. })
    ));
    assert!(matches!(
        PeriodResolver::new(Period::Calendar {
            unit: CalendarUnit::Day,
            tz: Box::from("UTC"),
            anchor: CalendarAnchor {
                hour: 24,
                ..CalendarAnchor::default_anchor()
            },
            subject_spread: false,
        }),
        Err(PeriodError::InvalidAnchor { .. })
    ));
    assert!(matches!(
        PeriodResolver::new(Period::Calendar {
            unit: CalendarUnit::Day,
            tz: Box::from("UTC"),
            anchor: CalendarAnchor {
                weekday: 0,
                ..CalendarAnchor::default_anchor()
            },
            subject_spread: false,
        }),
        Err(PeriodError::InvalidAnchor { .. })
    ));
    assert!(matches!(
        PeriodResolver::new(Period::Calendar {
            unit: CalendarUnit::Day,
            tz: Box::from("UTC"),
            anchor: CalendarAnchor {
                weekday: 8,
                ..CalendarAnchor::default_anchor()
            },
            subject_spread: false,
        }),
        Err(PeriodError::InvalidAnchor { .. })
    ));
    assert!(matches!(
        PeriodResolver::new(Period::Calendar {
            unit: CalendarUnit::Day,
            tz: Box::from("UTC"),
            anchor: CalendarAnchor {
                day_of_month: 0,
                ..CalendarAnchor::default_anchor()
            },
            subject_spread: false,
        }),
        Err(PeriodError::InvalidAnchor { .. })
    ));
    assert!(matches!(
        PeriodResolver::new(Period::Calendar {
            unit: CalendarUnit::Day,
            tz: Box::from("UTC"),
            anchor: CalendarAnchor {
                month_of_year: 13,
                ..CalendarAnchor::default_anchor()
            },
            subject_spread: false,
        }),
        Err(PeriodError::InvalidAnchor { .. })
    ));
    assert!(matches!(
        PeriodResolver::new(Period::Calendar {
            unit: CalendarUnit::Month,
            tz: Box::from("UTC"),
            anchor: CalendarAnchor {
                weekday: 3,
                ..CalendarAnchor::default_anchor()
            },
            subject_spread: false,
        }),
        Err(PeriodError::InvalidAnchor { .. })
    ));
}

#[test]
fn subject_spread_keeps_the_instant_inside_its_window() {
    let period = Period::Calendar {
        unit: CalendarUnit::Month,
        tz: Box::from("UTC"),
        anchor: CalendarAnchor::default_anchor(),
        subject_spread: true,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let start_ms = utc_ms(2026, 1, 1, 0, 0, 0) as u64;
    for i in 0..10_000 {
        let subject = subject_for(i);
        for j in 0..200 {
            let now_ms = start_ms + j * 3_600_000;
            let w = resolver.period_of(subject, wall(now_ms)).unwrap();
            assert!(w.contains(now_ms));
        }
    }
}

#[test]
fn daily_spread_survives_a_short_daylight_saving_day() {
    assert!(spread_modulus_ms(CalendarUnit::Day) < 23 * 3_600_000);
    let period = Period::Calendar {
        unit: CalendarUnit::Day,
        tz: Box::from("America/New_York"),
        anchor: CalendarAnchor {
            hour: 0,
            ..CalendarAnchor::default_anchor()
        },
        subject_spread: true,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let base_ms = local_ms("America/New_York", 2026, 3, 7, 0, 0) as u64;
    for i in 0..10_000 {
        let subject = subject_for(i);
        let mut previous: Option<PeriodWindow> = None;
        for j in 0..200 {
            let now_ms = base_ms + j * 600_000;
            let w = resolver.period_of(subject, wall(now_ms)).unwrap();
            assert!(w.contains(now_ms));
            if let Some(p) = previous
                && p.start_unix_ms != w.start_unix_ms
            {
                assert_eq!(p.end_unix_ms, w.start_unix_ms);
            }
            previous = Some(w);
        }
    }
}

fn timezones() -> Vec<&'static str> {
    vec![
        "UTC",
        "America/New_York",
        "Europe/Berlin",
        "Asia/Kolkata",
        "Pacific/Chatham",
    ]
}

fn calendar_anchor_strategy(unit: CalendarUnit) -> BoxedStrategy<CalendarAnchor> {
    match unit {
        CalendarUnit::Day => (0u8..=23)
            .prop_map(|hour| CalendarAnchor {
                month_of_year: 1,
                day_of_month: 1,
                weekday: 1,
                hour,
            })
            .boxed(),
        CalendarUnit::Week => (0u8..=23, 1u8..=7)
            .prop_map(|(hour, weekday)| CalendarAnchor {
                month_of_year: 1,
                day_of_month: 1,
                weekday,
                hour,
            })
            .boxed(),
        CalendarUnit::Month => (0u8..=23, 1u8..=31)
            .prop_map(|(hour, day_of_month)| CalendarAnchor {
                month_of_year: 1,
                day_of_month,
                weekday: 1,
                hour,
            })
            .boxed(),
        CalendarUnit::Year => (0u8..=23, 1u8..=12, 1u8..=31)
            .prop_map(|(hour, month_of_year, day_of_month)| CalendarAnchor {
                month_of_year,
                day_of_month,
                weekday: 1,
                hour,
            })
            .boxed(),
    }
}

fn calendar_unit_strategy() -> BoxedStrategy<CalendarUnit> {
    prop::sample::select(&[
        CalendarUnit::Day,
        CalendarUnit::Week,
        CalendarUnit::Month,
        CalendarUnit::Year,
    ])
    .boxed()
}

fn period_strategy() -> BoxedStrategy<Period> {
    let calendar = (
        prop::sample::select(timezones()),
        calendar_unit_strategy(),
        any::<bool>(),
    )
        .prop_flat_map(|(tz, unit, subject_spread)| {
            calendar_anchor_strategy(unit).prop_map(move |anchor| Period::Calendar {
                unit,
                tz: Box::from(tz),
                anchor,
                subject_spread,
            })
        })
        .boxed();
    let rolling = (
        1u64..=31_536_000,
        prop::sample::select(&[Anchor::Epoch, Anchor::Subject]),
    )
        .prop_map(|(length_secs, anchor)| Period::Rolling {
            length_secs,
            anchor,
        });
    prop_oneof![rolling.prop_map(|p| p), calendar.prop_map(|p| p),].boxed()
}

fn subject_strategy() -> BoxedStrategy<SubjectHash> {
    prop::collection::vec(any::<u8>(), 0..256)
        .prop_map(|v| seed().hash(&v))
        .boxed()
}

const MAX_RESOLVABLE_UNIX_MS: u64 = 4_102_444_800_000;

fn instant_strategy() -> BoxedStrategy<u64> {
    // 1971-01-01T00:00:00Z. Using MIN_RESOLVABLE directly allows generated
    // year/month anchors whose start falls before the epoch, which is
    // OutOfRange; 1971 guarantees the previous year is representable for all
    // valid anchors.
    const MIN: u64 = 31_536_000_000;
    (MIN..MAX_RESOLVABLE_UNIX_MS).boxed()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_every_instant_is_in_exactly_one_period(
        period in period_strategy(),
        subject in subject_strategy(),
        now_ms in instant_strategy(),
    ) {
        let resolver = PeriodResolver::new(period).unwrap();
        let w = resolver.period_of(subject, wall(now_ms)).unwrap();
        assert!(w.contains(now_ms));
        if resolver.period_of(subject, wall(w.start_unix_ms - 1)).is_ok() {
            let before = resolver.period_of(subject, wall(w.start_unix_ms - 1)).unwrap();
            assert_eq!(before.end_unix_ms, w.start_unix_ms);
        }
        if resolver.period_of(subject, wall(w.end_unix_ms)).is_ok() {
            let after = resolver.period_of(subject, wall(w.end_unix_ms)).unwrap();
            assert_eq!(after.start_unix_ms, w.end_unix_ms);
        }
    }

    #[test]
    fn prop_period_id_is_monotone(
        period in period_strategy(),
        subject in subject_strategy(),
        (now1, now2) in (instant_strategy(), instant_strategy()).prop_filter("ordered", |v| v.0 <= v.1),
    ) {
        let resolver = PeriodResolver::new(period).unwrap();
        let id1 = resolver.period_of(subject, wall(now1)).unwrap().id;
        let id2 = resolver.period_of(subject, wall(now2)).unwrap().id;
        assert!(id1 <= id2);
    }
}

/// Regression for issue #665: `Calendar { Day, "Pacific/Chatham" }` with
/// `subject_spread: true` and an anchor hour of 3, at the exact inputs
/// reported. `Pacific/Chatham` is UTC+12:45 standard and UTC+13:45 in
/// daylight saving, one of the few zones with a 45 minute offset and a DST
/// transition, and its autumn fold repeats the local wall clock range
/// [02:45, 03:45). The anchor hour of 3 falls inside that range, and this
/// subject's constant one-hour-bounded spread pushes the unspread window
/// boundary past the fold's transition instant, so `now` and the window's
/// end land in different occurrences of the same repeated wall-clock hour.
///
/// Before the fix, `calendar_civil_start` compared the bare civil (offset
/// naive) datetime of the candidate boundary against the bare civil datetime
/// of `now`. During the second occurrence of a fold, a wall clock reading
/// can look "earlier" than a first-occurrence candidate while actually being
/// later in absolute time, so the comparison picked the wrong day and
/// `period_of` queried exactly at a window's exclusive end returned a window
/// starting a full nominal day earlier, putting that instant in two periods.
#[test]
fn calendar_day_tiles_across_the_chatham_autumn_fold_with_subject_spread() {
    let period = Period::Calendar {
        unit: CalendarUnit::Day,
        tz: Box::from("Pacific/Chatham"),
        anchor: CalendarAnchor {
            month_of_year: 1,
            day_of_month: 1,
            weekday: 1,
            hour: 3,
        },
        subject_spread: true,
    };
    let resolver = PeriodResolver::new(period).unwrap();
    let subject = SubjectHash {
        hi: 1_746_374_178_425_565_603,
        lo: 13_586_956_261_155_929_603,
    };
    let now_ms = 541_517_132_388u64;

    let w = resolver.period_of(subject, wall(now_ms)).unwrap();
    assert!(w.contains(now_ms), "window {w:?} does not contain {now_ms}");

    let after = resolver.period_of(subject, wall(w.end_unix_ms)).unwrap();
    assert_eq!(
        after.start_unix_ms, w.end_unix_ms,
        "the period starting at w's exclusive end must start exactly there; \
         got {after:?} for w = {w:?}"
    );
}

/// Walks `hops` consecutive periods forward from `start_ms` for one subject,
/// asserting at every step both that the resolved window contains the
/// instant it was resolved for, and that the next period's start is exactly
/// the previous period's exclusive end. This is Invariant 1 (containment)
/// and Invariant 3 (tiling) from issue #227, checked together the same way
/// `prop_every_instant_is_in_exactly_one_period` checks them, but walked
/// deterministically rather than drawn at random.
/// Returns the number of hops it actually verified, which the caller asserts
/// against the number it asked for. That return value is not decoration: a
/// helper that returns early, or that is handed `hops: 0`, otherwise reports
/// success having checked nothing, and the caller cannot tell the difference.
/// It also gives the caller a real assertion of its own, which
/// `invariant-lints.sh`'s `no-test-without-assertion` rule requires and cannot
/// otherwise see, because that rule looks for an assertion lexically inside the
/// test body and cannot follow a call into a helper (see #562, #563). The
/// honest fix for that blind spot is an assertion the test genuinely needs, not
/// a decorative one added to quiet the lint.
fn assert_calendar_periods_tile(
    resolver: &PeriodResolver,
    subject: SubjectHash,
    start_ms: u64,
    hops: usize,
) -> Result<usize, PeriodError> {
    let mut verified = 0_usize;
    let mut now_ms = start_ms;
    for hop in 0..hops {
        let w = resolver.period_of(subject, wall(now_ms))?;
        assert!(
            w.contains(now_ms),
            "hop {hop}: window {w:?} does not contain {now_ms}"
        );
        let after = resolver.period_of(subject, wall(w.end_unix_ms))?;
        assert_eq!(
            after.start_unix_ms, w.end_unix_ms,
            "hop {hop}: periods do not tile: window {w:?} followed by {after:?}"
        );
        now_ms = w.end_unix_ms;
        verified += 1;
    }
    Ok(verified)
}

/// Companion guard for issue #665's fix: the fix in `calendar_civil_start`
/// touches the shared code path for every `CalendarUnit`, not only `Day`, so
/// this checks Week, Month and Year still tile exactly, including with
/// `subject_spread: true`, across five zones.
///
/// WHAT THIS DOES NOT DO, stated because an earlier version of this comment
/// claimed it did. This is a "still works" guard, NOT a discriminating test: it
/// passes identically on the pre-fix and post-fix source, so it cannot detect
/// the bug and does not rule out the fix having been narrowly tied to the case
/// it was found through. Measured, twice, by reverting the one-line fix in
/// `calendar_civil_start` and re-running: still green.
///
/// The reason is structural. It starts at 2026-01-01 and walks six periods, so
/// for Week and Month it never reaches a DST transition at all, and the changed
/// branch is only reachable when `now` falls in the second occurrence of an
/// ambiguous local hour with the anchor hour strictly inside the repeated
/// range. Adding zones alone does not fix that; the start instant has to sit on
/// a transition too.
///
/// A recipe that WOULD discriminate is recorded in the follow-up issue, with
/// the configuration measured to fail pre-fix (`Antarctica/Troll`, a two-hour
/// shift, anchor hour 2, weekday 7, around the 2023-10-29 transition). Making
/// that work is more than a zone-list edit and is deliberately not attempted
/// here rather than shipped as a guess.
///
/// The discriminating coverage that DOES exist is
/// `calendar_day_tiles_across_the_chatham_autumn_fold_with_subject_spread` and
/// `prop_every_instant_is_in_exactly_one_period` with the committed seed; both
/// fail on the pre-fix source.
#[test]
fn calendar_week_month_year_tile_with_subject_spread_across_zones() {
    let cases = [
        (
            CalendarUnit::Week,
            CalendarAnchor {
                month_of_year: 1,
                day_of_month: 1,
                weekday: 3,
                hour: 3,
            },
        ),
        (
            CalendarUnit::Month,
            CalendarAnchor {
                month_of_year: 1,
                day_of_month: 15,
                weekday: 1,
                hour: 3,
            },
        ),
        (
            CalendarUnit::Year,
            CalendarAnchor {
                month_of_year: 3,
                day_of_month: 10,
                weekday: 1,
                hour: 3,
            },
        ),
    ];
    let start_ms = utc_ms(2026, 1, 1, 0, 0, 0) as u64;
    let subjects: Vec<SubjectHash> = (0..25).map(subject_for).collect();

    for (unit, anchor) in cases {
        for tz in [
            "Antarctica/Troll",
            "Pacific/Chatham",
            "America/New_York",
            "UTC",
            "Australia/Eucla",
        ] {
            let period = Period::Calendar {
                unit,
                tz: Box::from(tz),
                anchor,
                subject_spread: true,
            };
            let resolver = PeriodResolver::new(period).unwrap();
            for &subject in &subjects {
                let verified =
                    assert_calendar_periods_tile(&resolver, subject, start_ms, 6).unwrap();
                assert_eq!(
                    verified, 6,
                    "{unit:?} in {tz}: only {verified} of 6 hops were checked, \
                     so this case proved less than it claims"
                );
            }
        }
    }
}
