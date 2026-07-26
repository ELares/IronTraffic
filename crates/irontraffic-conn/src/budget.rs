// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-connection frame budget: a lazily refilled token bucket, debited at
//! frame-parse time, BEFORE any per-stream state is allocated.
//!
//! HTTP/2 and HTTP/3 multiplex, so a single TCP or QUIC connection can conjure
//! unbounded server-side work. Rapid Reset (CVE-2023-44487), the CONTINUATION
//! flood (2024) and `MadeYouReset` (CVE-2025-8671) are all the same bug: an
//! accounting mismatch between what the protocol considers live and what the
//! implementation is actually working on. [`ConnBudget`] is the accounting.
//!
//! Debiting at frame-parse time, before per-stream allocation, is the whole
//! point: a budget checked after the stream state is created has already paid
//! for the attack.
//!
//! # RULE R1
//!
//! `RST_STREAM` debits the budget. It never credits it. A reset is not a
//! refund. Rapid Reset works precisely because implementations treated a
//! reset as freeing capacity. There is no `credit`, `refund`, `reset`, or
//! `set_tokens` method anywhere in this module, and there never should be.
//!
//! # Why plain integer fields and not atomics
//!
//! [`ConnBudget`] is per-connection state owned by the task that owns the
//! connection, and it moves with the task. It is reached through `&mut self`
//! and never shared, so an atomic read-modify-write would pay a locked
//! instruction's cost for nothing. An async runtime's task can migrate
//! between worker threads at any await point, and that is fine here
//! precisely because the budget travels inside the connection's own state
//! rather than living in a per-core array.
//!
//! # Why the caller supplies `now_ms`
//!
//! The bucket refills lazily on debit, with no timer wheel. Reading a
//! high-resolution clock on every frame is too expensive, so the caller
//! passes a coarse millisecond counter it already has, refreshed once per
//! event-loop iteration. This module reads no clock at all, which is also
//! what keeps it inside the repository rule that time flows through one
//! seam: `irontraffic-time`.
//!
//! # What this budget does not bound
//!
//! It is per connection, so an attacker who can open `N` connections gets `N`
//! buckets. The complementary bound is a per-source-IP connection cap and an
//! accept-time deadline, both outside this crate; an unbounded number of
//! bounded buckets is still unbounded.

/// Per-connection frame budget for a multiplexed protocol.
///
/// Debited at frame-parse time, BEFORE any per-stream state is allocated. Plain integer
/// fields, not atomics: this is per-connection state owned by the task that owns the
/// connection and reached through `&mut self`, so it moves with the task and is never
/// shared.
///
/// Deliberately NOT `Copy`. A frame loop written `fn handle(mut budget: ConnBudget, ..)`
/// debits a copy, the connection's own `tokens` never moves, and the entire Rapid Reset,
/// CONTINUATION-flood and `MadeYouReset` defense is off with no compile error, no failing
/// test and no metric. Metrics read the accessors (`tokens`, `concurrent_proto`); they do
/// not need a snapshot of the whole struct.
#[derive(Clone, Debug)]
pub struct ConnBudget {
    tokens: i64,
    capacity: i64,
    refill_per_sec: i64,
    last_refill_ms: u32,
    concurrent_proto: u32,
    max_concurrent_proto: u32,
    costs: FrameCosts,
}

/// What kind of frame arrived, for pricing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameEvent {
    /// Any frame not covered by a more specific variant (DATA with payload, HEADERS on an
    /// existing stream, SETTINGS ACK, PING ACK, `WINDOW_UPDATE` of 1024 or more).
    Ordinary,
    /// HEADERS that opens a new stream.
    HeadersOpen,
    /// CONTINUATION.
    Continuation,
    /// DATA with a zero-length payload and no `END_STREAM`.
    EmptyDataNoEndStream,
    /// `RST_STREAM` received from the peer.
    RstStreamReceived,
    /// `RST_STREAM` we are about to send. Debit BEFORE sending.
    RstStreamSent,
    /// PING without the ACK flag.
    Ping,
    /// SETTINGS without the ACK flag.
    Settings,
    /// `WINDOW_UPDATE` whose increment is under 1024.
    SmallWindowUpdate,
    /// PRIORITY or `PRIORITY_UPDATE`.
    Priority,
    /// GOAWAY received while streams are live.
    GoawayReceived,
}

/// The cost table. Every field is the EXTRA cost on top of `base`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FrameCosts {
    /// Cost applied to every frame, regardless of type, before any
    /// event-specific extra below. Default 1.
    pub base: i64,
    /// Extra cost for a HEADERS frame that opens a new stream: real work.
    /// Default 10.
    pub headers_open: i64,
    /// Extra cost for a CONTINUATION frame: the 2024 CONTINUATION flood.
    /// Default 2.
    pub continuation: i64,
    /// Extra cost for a DATA frame with a zero-length payload and no
    /// `END_STREAM`: the empty-frame flood, CVE-2019-9518. Default 20.
    pub empty_data: i64,
    /// Extra cost for a `RST_STREAM` received from the peer: Rapid Reset,
    /// CVE-2023-44487. Default 40.
    pub rst_received: i64,
    /// Extra cost for a `RST_STREAM` we send ourselves: `MadeYouReset`,
    /// CVE-2025-8671. Default 40.
    pub rst_sent: i64,
    /// Extra cost for a PING without the ACK flag: the ping flood,
    /// CVE-2019-9512. Default 10.
    pub ping: i64,
    /// Extra cost for a SETTINGS frame without the ACK flag: the settings
    /// flood, CVE-2019-9515. Default 20.
    pub settings: i64,
    /// Extra cost for a `WINDOW_UPDATE` whose increment is under 1024: the
    /// data dribble and window abuse, CVE-2019-9511. Default 10.
    pub small_window_update: i64,
    /// Extra cost for a PRIORITY or `PRIORITY_UPDATE` frame: the resource
    /// loop, CVE-2019-9513. Default 5.
    pub priority: i64,
    /// Extra cost for a GOAWAY received while streams are live. Default 0:
    /// legitimate, but the base cost still applies, so it is never free.
    pub goaway: i64,
}

/// The budget is exhausted. The caller MUST send `GOAWAY(ENHANCE_YOUR_CALM)` and close
/// after a short drain. It MUST NOT silently drop frames.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EnhanceYourCalm {
    /// How far below zero the bucket went, for the metric.
    pub deficit: i64,
}

/// The protocol-level concurrent stream limit was exceeded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TooManyStreams {
    /// The limit that was hit.
    pub limit: u32,
}

impl ConnBudget {
    /// The clamp step 1 of [`ConnBudget::on_frame`] applies to `elapsed`
    /// before computing the refill gain: the backwards-clock guard. A caller
    /// that passes a stale or wildly future `now_ms` can credit at most 60
    /// seconds' worth of tokens from a single call, which
    /// [`ConnBudget::on_frame`]'s own `min(capacity, ..)` then caps a second
    /// time.
    const MAX_ELAPSED_MS: u32 = 60_000;

    /// A budget with the default capacity (10000), refill (1000 per second),
    /// concurrency limit (128) and cost table.
    #[must_use]
    pub const fn new(now_ms: u32) -> Self {
        Self::with_params(10_000, 1_000, 128, FrameCosts::DEFAULT, now_ms)
    }

    /// A budget with explicit parameters.
    #[must_use]
    pub const fn with_params(
        capacity: i64,
        refill_per_sec: i64,
        max_concurrent_proto: u32,
        costs: FrameCosts,
        now_ms: u32,
    ) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last_refill_ms: now_ms,
            concurrent_proto: 0,
            max_concurrent_proto,
            costs,
        }
    }

    /// Debits one frame. Call this at frame-parse time, BEFORE allocating any per-stream
    /// state, and before SENDING a `RST_STREAM` we generate ourselves.
    ///
    /// `now_ms` is a coarse millisecond counter the caller already has, refreshed once per
    /// event-loop iteration. This crate never reads a clock.
    ///
    /// # Errors
    /// `EnhanceYourCalm` when the bucket goes negative. The caller MUST then send
    /// `GOAWAY(ENHANCE_YOUR_CALM)` and close after a short drain, and MUST NOT silently
    /// drop frames.
    pub fn on_frame(&mut self, ev: FrameEvent, now_ms: u32) -> Result<(), EnhanceYourCalm> {
        // 1. Refill. `wrapping_sub` is exactly correct for any interval
        // shorter than 49.7 days, and every interval computed here is
        // bounded by a connection lifetime. The clamp below is the
        // backwards-clock guard: it also bounds a forward jump, which is
        // harmless because the `min(capacity, ..)` two lines down caps the
        // result again regardless.
        let elapsed = now_ms
            .wrapping_sub(self.last_refill_ms)
            .min(Self::MAX_ELAPSED_MS);
        #[allow(
            clippy::integer_division,
            reason = "converting a millisecond gain to whole tokens is an intentional \
                      truncation toward zero; a fractional token is not a token, and the \
                      dropped remainder is preserved by NOT advancing last_refill_ms below \
                      when gain is zero, so it accumulates rather than being lost"
        )]
        let gain = i64::from(elapsed).saturating_mul(self.refill_per_sec) / 1000;
        if gain > 0 {
            self.tokens = self.capacity.min(self.tokens.saturating_add(gain));
            self.last_refill_ms = now_ms;
        }

        // 2. Debit.
        self.tokens = self.tokens.saturating_sub(self.cost_of(ev));

        debug_assert!(
            self.tokens <= self.capacity,
            "tokens must never exceed capacity after a refill"
        );

        // 3. Check.
        if self.tokens < 0 {
            return Err(EnhanceYourCalm {
                deficit: self.tokens.saturating_neg(),
            });
        }

        // 4.
        Ok(())
    }

    /// Admits a new protocol stream against the RFC 9113 Section 5.1.2 concurrency limit.
    ///
    /// This counter is a PROTOCOL-CONFORMANCE counter, not a resource counter: a
    /// `RST_STREAM` from the peer decrements it. Bounding actual work needs `StreamSlot`
    /// as well, which is a separate type for exactly that reason.
    ///
    /// # Errors
    /// `TooManyStreams` when the limit is reached.
    pub fn open_stream(&mut self) -> Result<(), TooManyStreams> {
        if self.concurrent_proto < self.max_concurrent_proto {
            self.concurrent_proto = self.concurrent_proto.saturating_add(1);
            Ok(())
        } else {
            Err(TooManyStreams {
                limit: self.max_concurrent_proto,
            })
        }
    }

    /// Releases a protocol stream slot. Saturates at zero.
    pub fn close_stream(&mut self) {
        self.concurrent_proto = self.concurrent_proto.saturating_sub(1);
    }

    /// Tokens currently available. May be negative after an exhausting debit.
    #[must_use]
    pub const fn tokens(&self) -> i64 {
        self.tokens
    }

    /// Open plus half-closed streams, in the RFC 9113 Section 5.1.2 sense.
    #[must_use]
    pub const fn concurrent_proto(&self) -> u32 {
        self.concurrent_proto
    }

    /// The cost this budget charges for `ev`, including the base.
    #[must_use]
    pub const fn cost_of(&self, ev: FrameEvent) -> i64 {
        let specific = match ev {
            FrameEvent::Ordinary => 0,
            FrameEvent::HeadersOpen => self.costs.headers_open,
            FrameEvent::Continuation => self.costs.continuation,
            FrameEvent::EmptyDataNoEndStream => self.costs.empty_data,
            FrameEvent::RstStreamReceived => self.costs.rst_received,
            FrameEvent::RstStreamSent => self.costs.rst_sent,
            FrameEvent::Ping => self.costs.ping,
            FrameEvent::Settings => self.costs.settings,
            FrameEvent::SmallWindowUpdate => self.costs.small_window_update,
            FrameEvent::Priority => self.costs.priority,
            FrameEvent::GoawayReceived => self.costs.goaway,
        };
        self.costs.base.saturating_add(specific)
    }
}

impl FrameCosts {
    /// The shipped defaults.
    pub const DEFAULT: FrameCosts = FrameCosts {
        base: 1,
        headers_open: 10,
        continuation: 2,
        empty_data: 20,
        rst_received: 40,
        rst_sent: 40,
        ping: 10,
        settings: 20,
        small_window_update: 10,
        priority: 5,
        goaway: 0,
    };
}

#[cfg(test)]
mod tests {
    use super::{ConnBudget, FrameCosts, FrameEvent, TooManyStreams};
    use proptest::prelude::*;

    /// Every `FrameEvent` variant, built through a match that is exhaustive
    /// on purpose: adding a new variant without updating this list is a
    /// compile error, not a silently under-tested cost table.
    fn all_events() -> [FrameEvent; 11] {
        let sample = FrameEvent::Ordinary;
        match sample {
            FrameEvent::Ordinary
            | FrameEvent::HeadersOpen
            | FrameEvent::Continuation
            | FrameEvent::EmptyDataNoEndStream
            | FrameEvent::RstStreamReceived
            | FrameEvent::RstStreamSent
            | FrameEvent::Ping
            | FrameEvent::Settings
            | FrameEvent::SmallWindowUpdate
            | FrameEvent::Priority
            | FrameEvent::GoawayReceived => {}
        }
        [
            FrameEvent::Ordinary,
            FrameEvent::HeadersOpen,
            FrameEvent::Continuation,
            FrameEvent::EmptyDataNoEndStream,
            FrameEvent::RstStreamReceived,
            FrameEvent::RstStreamSent,
            FrameEvent::Ping,
            FrameEvent::Settings,
            FrameEvent::SmallWindowUpdate,
            FrameEvent::Priority,
            FrameEvent::GoawayReceived,
        ]
    }

    fn event_strategy() -> impl Strategy<Value = FrameEvent> {
        prop_oneof![
            Just(FrameEvent::Ordinary),
            Just(FrameEvent::HeadersOpen),
            Just(FrameEvent::Continuation),
            Just(FrameEvent::EmptyDataNoEndStream),
            Just(FrameEvent::RstStreamReceived),
            Just(FrameEvent::RstStreamSent),
            Just(FrameEvent::Ping),
            Just(FrameEvent::Settings),
            Just(FrameEvent::SmallWindowUpdate),
            Just(FrameEvent::Priority),
            Just(FrameEvent::GoawayReceived),
        ]
    }

    #[test]
    fn cost_table_is_exact() {
        // Edge case 19: every `FrameEvent` costs at least 1 (the base), and
        // the specific extra matches the documented table exactly.
        let budget = ConnBudget::new(0);
        let expected: [(FrameEvent, i64); 11] = [
            (FrameEvent::Ordinary, 1),
            (FrameEvent::HeadersOpen, 11),
            (FrameEvent::Continuation, 3),
            (FrameEvent::EmptyDataNoEndStream, 21),
            (FrameEvent::RstStreamReceived, 41),
            (FrameEvent::RstStreamSent, 41),
            (FrameEvent::Ping, 11),
            (FrameEvent::Settings, 21),
            (FrameEvent::SmallWindowUpdate, 11),
            (FrameEvent::Priority, 6),
            (FrameEvent::GoawayReceived, 1),
        ];
        for (ev, want) in expected {
            let got = budget.cost_of(ev);
            assert_eq!(got, want, "{ev:?} should cost {want}, got {got}");
            assert!(got >= 1, "{ev:?} must cost at least the base of 1");
        }
        // Every variant returned by the exhaustive helper is covered above.
        assert_eq!(all_events().len(), expected.len());
    }

    #[test]
    fn single_debits() {
        // Edge case 1: a fresh budget starts full.
        let fresh = ConnBudget::new(0);
        assert_eq!(fresh.tokens(), 10_000);

        // Edge case 2: one Ordinary frame costs the base 1.
        let mut ordinary = ConnBudget::new(0);
        assert_eq!(ordinary.on_frame(FrameEvent::Ordinary, 0), Ok(()));
        assert_eq!(ordinary.tokens(), 9_999);

        // Edge case 3: one HeadersOpen costs base 1 plus 10.
        let mut headers = ConnBudget::new(0);
        assert_eq!(headers.on_frame(FrameEvent::HeadersOpen, 0), Ok(()));
        assert_eq!(headers.tokens(), 9_989);

        // Edge case 4: one RstStreamReceived costs base 1 plus 40.
        let mut rst_received = ConnBudget::new(0);
        assert_eq!(
            rst_received.on_frame(FrameEvent::RstStreamReceived, 0),
            Ok(())
        );
        assert_eq!(rst_received.tokens(), 9_959);

        // Edge case 5: one RstStreamSent costs the same as RstStreamReceived,
        // on purpose: both directions of a reset are priced identically.
        let mut rst_sent = ConnBudget::new(0);
        assert_eq!(rst_sent.on_frame(FrameEvent::RstStreamSent, 0), Ok(()));
        assert_eq!(rst_sent.tokens(), 9_959);
    }

    #[test]
    fn rapid_reset_exhausts_the_bucket() {
        // CVE-2023-44487, HTTP/2 Rapid Reset: an attacker opens a stream and
        // immediately resets it, over and over. Each HEADERS+RST_STREAM pair
        // costs 52 tokens at the default cost table (1 + 10 for HEADERS,
        // 1 + 40 for RST_STREAM), so the 10,000-token bucket runs out after
        // roughly capacity / 52 pairs instead of admitting unbounded resets.
        // Edge case 6.
        let mut budget = ConnBudget::new(0);
        let mut failing_pair = None;
        for pair in 1..=500u32 {
            if let Err(e) = budget.on_frame(FrameEvent::HeadersOpen, 0) {
                assert!(e.deficit > 0);
                failing_pair = Some(pair);
                break;
            }
            if let Err(e) = budget.on_frame(FrameEvent::RstStreamReceived, 0) {
                assert!(e.deficit > 0);
                failing_pair = Some(pair);
                break;
            }
        }
        let failing_pair = failing_pair.expect("the bucket must exhaust within 500 pairs");
        assert!(
            (190..=195).contains(&failing_pair),
            "expected the bucket to exhaust between pair 190 and 195, got {failing_pair}"
        );
    }

    #[test]
    fn reset_never_credits() {
        // RULE R1: a `RST_STREAM` must debit, never credit, in either
        // direction. This module defines no method that gives tokens back,
        // by inspection of the `impl ConnBudget` block above.
        let mut received = ConnBudget::new(0);
        let before = received.tokens();
        assert_eq!(received.on_frame(FrameEvent::RstStreamReceived, 0), Ok(()));
        assert!(received.tokens() < before);

        let mut sent = ConnBudget::new(0);
        let before = sent.tokens();
        assert_eq!(sent.on_frame(FrameEvent::RstStreamSent, 0), Ok(()));
        assert!(sent.tokens() < before);

        // A frame loop that took `ConnBudget` by value would debit a copy
        // and leave the connection's own bucket untouched; that failure mode
        // can only be caught by going through `&mut` the way a real caller
        // must, which is exactly what `spend_ten_rst_received` does here.
        let mut b = ConnBudget::new(0);
        spend_ten_rst_received(&mut b);
        assert_eq!(b.tokens(), 10_000 - 410);
    }

    /// Debits `RstStreamReceived` ten times through a `&mut` borrow, so the
    /// caller can observe the debit landing on its own, non-`Copy` budget
    /// rather than on a value that was taken by copy and discarded.
    fn spend_ten_rst_received(b: &mut ConnBudget) {
        for _ in 0..10 {
            assert_eq!(b.on_frame(FrameEvent::RstStreamReceived, 0), Ok(()));
        }
    }

    #[test]
    fn refill_behaviour() {
        // Edge case 7: `now_ms` unchanged across 10,000 frames. No refill at
        // all; the budget empties exactly on schedule, at frame 10,000, and
        // the very next frame is refused.
        let mut fixed_clock = ConnBudget::new(0);
        for _ in 0..10_000 {
            assert_eq!(fixed_clock.on_frame(FrameEvent::Ordinary, 0), Ok(()));
        }
        assert_eq!(fixed_clock.tokens(), 0);
        assert!(fixed_clock.on_frame(FrameEvent::Ordinary, 0).is_err());

        // Edge case 8: advancing `now_ms` by 1000 with an empty bucket adds
        // exactly 1000 tokens (the default refill is 1000 per second), then
        // the Ordinary frame itself debits 1.
        let mut refill_1s = ConnBudget::new(0);
        for _ in 0..10_000 {
            assert_eq!(refill_1s.on_frame(FrameEvent::Ordinary, 0), Ok(()));
        }
        assert_eq!(refill_1s.tokens(), 0);
        assert_eq!(refill_1s.on_frame(FrameEvent::Ordinary, 1_000), Ok(()));
        assert_eq!(refill_1s.tokens(), 999);

        // Edge case 9: advancing `now_ms` by 1,000,000 with an empty bucket
        // still caps at `capacity`, not at the much larger raw product of
        // elapsed and rate.
        let mut refill_huge = ConnBudget::new(0);
        for _ in 0..10_000 {
            assert_eq!(refill_huge.on_frame(FrameEvent::Ordinary, 0), Ok(()));
        }
        assert_eq!(refill_huge.tokens(), 0);
        assert_eq!(
            refill_huge.on_frame(FrameEvent::Ordinary, 1_000_000),
            Ok(())
        );
        assert_eq!(refill_huge.tokens(), 10_000 - 1);

        // Edge case 10: `now_ms` advanced by 0 means no refill at all, just
        // the plain per-frame debit.
        let mut same_ms = ConnBudget::new(500);
        assert_eq!(same_ms.on_frame(FrameEvent::Ordinary, 500), Ok(()));
        assert_eq!(same_ms.tokens(), 9_999);
        assert_eq!(same_ms.on_frame(FrameEvent::Ordinary, 500), Ok(()));
        assert_eq!(same_ms.tokens(), 9_998);

        // Edge case 11: a backwards `now_ms` (the caller passed a stale
        // value) makes `wrapping_sub` compute a huge `elapsed`. The 60_000 ms
        // clamp bounds the resulting gain to at most 60 seconds' worth: with
        // `refill_per_sec = 1` that is 60 tokens. Capacity here is 10_000,
        // far above what the clamped gain could ever reach, so if the clamp
        // were missing this would instead read 9_999 (capacity minus the one
        // debited frame) rather than 59.
        let mut clock_jump = ConnBudget::with_params(10_000, 1, 128, FrameCosts::DEFAULT, 100);
        for _ in 0..10_000 {
            assert_eq!(clock_jump.on_frame(FrameEvent::Ordinary, 100), Ok(()));
        }
        assert_eq!(clock_jump.tokens(), 0);
        assert_eq!(clock_jump.on_frame(FrameEvent::Ordinary, 0), Ok(()));
        assert_eq!(clock_jump.tokens(), 59);

        // Edge case 12: `now_ms` wrapping at `u32::MAX`. 10 ticks reach
        // `u32::MAX`, one more wraps to 0, and 5 more reach 5, so the elapsed
        // interval `wrapping_sub` computes is 16 ms, not 15.
        let mut wrap = ConnBudget::new(u32::MAX - 10);
        for _ in 0..10_000 {
            assert_eq!(wrap.on_frame(FrameEvent::Ordinary, u32::MAX - 10), Ok(()));
        }
        assert_eq!(wrap.tokens(), 0);
        assert_eq!(wrap.on_frame(FrameEvent::Ordinary, 5), Ok(()));
        assert_eq!(wrap.tokens(), 15);

        // Edge case 13: `saturating_mul` and `saturating_add` in the refill
        // prevent overflow when the configured rate is extreme. `capacity`
        // still wins the `min`, and nothing panics or wraps even though
        // `elapsed.saturating_mul(refill_per_sec)` alone would overflow
        // `i64` many times over.
        let mut extreme = ConnBudget::with_params(10_000, i64::MAX, 128, FrameCosts::DEFAULT, 0);
        for _ in 0..10_000 {
            assert_eq!(extreme.on_frame(FrameEvent::Ordinary, 0), Ok(()));
        }
        assert_eq!(extreme.tokens(), 0);
        assert_eq!(extreme.on_frame(FrameEvent::Ordinary, 60_000), Ok(()));
        assert_eq!(extreme.tokens(), 10_000 - 1);

        // The fractional-credit rule: `last_refill_ms` must only advance
        // when `gain` is actually positive. With `refill_per_sec = 100`,
        // each 1 ms tick alone computes `1 * 100 / 1000 == 0`, so 10
        // successive calls one millisecond apart must still add up to
        // exactly 1 token overall (at the tick where the accumulated
        // elapsed time finally reaches 10 ms), never 0. A buggy
        // implementation that advances `last_refill_ms` on every call,
        // discarding the fractional millisecond each time, would instead
        // land on 10_000 - 10 = 9_990 here (10 debits, 0 total credit).
        let mut fractional = ConnBudget::with_params(10_000, 100, 128, FrameCosts::DEFAULT, 0);
        for ms in 1..=10u32 {
            assert_eq!(fractional.on_frame(FrameEvent::Ordinary, ms), Ok(()));
        }
        assert_eq!(fractional.tokens(), 10_000 - 9);
    }

    #[test]
    fn degenerate_configs() {
        // Edge case 14: a zero capacity is a legal, if hostile,
        // configuration: the very first frame already exceeds it.
        let mut zero_capacity = ConnBudget::with_params(0, 1_000, 128, FrameCosts::DEFAULT, 0);
        match zero_capacity.on_frame(FrameEvent::Ordinary, 0) {
            Err(e) => assert_eq!(e.deficit, 1),
            Ok(()) => panic!("a zero-capacity budget must refuse its first frame"),
        }

        // Edge case 15: a zero refill rate is also legal. The bucket never
        // refills, so once it is empty every subsequent frame errors even as
        // `now_ms` advances arbitrarily far.
        let mut zero_refill = ConnBudget::with_params(10, 0, 128, FrameCosts::DEFAULT, 0);
        for _ in 0..10 {
            assert_eq!(zero_refill.on_frame(FrameEvent::Ordinary, 0), Ok(()));
        }
        assert_eq!(zero_refill.tokens(), 0);
        assert!(
            zero_refill
                .on_frame(FrameEvent::Ordinary, 1_000_000)
                .is_err()
        );
        assert_eq!(zero_refill.tokens(), -1);
    }

    #[test]
    fn stream_admission() {
        // Edge case 16: the 128th `open_stream` succeeds (matching the
        // default `max_concurrent_proto`), and the 129th is refused with the
        // limit that was hit.
        let mut b = ConnBudget::new(0);
        for _ in 0..128 {
            assert_eq!(b.open_stream(), Ok(()));
        }
        assert_eq!(b.concurrent_proto(), 128);
        assert_eq!(b.open_stream(), Err(TooManyStreams { limit: 128 }));

        // Edge case 17: `close_stream` saturates at zero rather than
        // underflowing. First prove `close_stream` actually decrements (a
        // no-op body would also leave an already-zero counter at zero, so
        // that call alone cannot tell a real decrement apart from nothing
        // happening at all).
        let mut one_open = ConnBudget::new(0);
        assert_eq!(one_open.open_stream(), Ok(()));
        assert_eq!(one_open.concurrent_proto(), 1);
        one_open.close_stream();
        assert_eq!(one_open.concurrent_proto(), 0);

        // Now the saturation itself: closing an already-empty budget must
        // not underflow.
        let mut fresh = ConnBudget::new(0);
        fresh.close_stream();
        assert_eq!(fresh.concurrent_proto(), 0);
    }

    proptest! {
        #[test]
        fn prop_budget_monotone(
            events in proptest::collection::vec((event_strategy(), 0u32..=100), 0..=500)
        ) {
            // P-BUDGET-MONOTONE, part 1, first half: for any sequence of
            // frame events, `tokens()` never exceeds `capacity` (10_000, the
            // default used here), no matter what mix of credits and debits
            // it sees.
            let mut budget = ConnBudget::new(0);
            let mut now_ms = 0u32;
            for (event, delta) in events {
                now_ms = now_ms.wrapping_add(delta);
                // The outcome itself is not the property under test here
                // (both `Ok` and `Err` are legal depending on the sequence);
                // only the invariant checked below is.
                let _ = budget.on_frame(event, now_ms);
                prop_assert!(budget.tokens() <= 10_000);
            }

            // P-BUDGET-MONOTONE, part 1, second half: a pure Rapid Reset
            // stream (HEADERS plus RST_STREAM pairs, no time passing between
            // them) must drive the bucket negative within `capacity / 52 + 2`
            // pairs; at the defaults that bound is 194.
            let mut rapid_reset = ConnBudget::new(0);
            let mut failed = false;
            for _ in 0..194 {
                if rapid_reset.on_frame(FrameEvent::HeadersOpen, 0).is_err() {
                    failed = true;
                    break;
                }
                if rapid_reset.on_frame(FrameEvent::RstStreamReceived, 0).is_err() {
                    failed = true;
                    break;
                }
            }
            prop_assert!(failed);
        }
    }
}
