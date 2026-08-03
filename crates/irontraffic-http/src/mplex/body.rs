// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`BodyAccounting`], the counter that reconciles received DATA or QUIC
//! STREAM octets against a declared `content-length` for one multiplexed
//! (H2 or H3) stream, and refuses the message before end-of-stream reaches
//! the router if the two disagree.
//!
//! **Why this exists.** Envoy CVE-2026-48743 (GHSA-8phg-2h2q-jgxf) and
//! HAProxy CVE-2026-33555 are the same defect in two codebases: a
//! headers-only or zero-payload end-of-stream signal reached the router
//! before Content-Length accounting ran, so a declared length that was
//! never actually received was forwarded anyway. Envoy's own advisory
//! states the invariant this type enforces, verbatim: "semantic request
//! completion must not cross a protocol boundary until Content-Length
//! accounting has been reconciled with received DATA bytes." RFC 9113
//! Section 8.1.1 and RFC 9114 Section 4.1.2 both require the same thing: "A
//! request or response is also malformed if the value of a content-length
//! header field does not equal the sum of the DATA frame payload lengths
//! that form the content," and an intermediary "MUST NOT forward a
//! malformed request or response."
//!
//! **The call-order contract.** [`BodyAccounting::finish`] is the only
//! function that can answer whether a stream reconciled, and its return
//! value MUST be observed as `Ok` before the codec propagates end-of-stream
//! to the router: not after, and not skipped because another code path
//! already recorded end-of-stream. That ordering requirement is what became
//! a bug in both advisories, and turning it into an API shape (a codec
//! cannot report a clean end-of-stream without calling the function that
//! validates it) is why this type exists as a separate value instead of an
//! inline check in the codec's end-of-stream handler.
//!
//! **This type takes lengths, not frames.** It knows nothing about H2 or H3
//! framing, and it never reads `content-length` itself: the declared value
//! comes from the already-resolved [`crate::framing::RequestFraming`] or
//! [`crate::response::ResponseFraming`], which are the only places those
//! fields are read (see `scripts/invariant-lints.sh`'s
//! `framing-fields-confined` rule).

use crate::error::RejectReason;
use crate::framing::RequestFraming;
use crate::response::ResponseFraming;

/// Counts received body octets against a declared `content-length` for one
/// multiplexed stream.
///
/// The declared value comes from the resolved [`RequestFraming`] (or
/// [`ResponseFraming`]), not from a header lookup, so there is exactly one
/// source for it.
///
/// **INVARIANT I4:** for every H2 or H3 message where the peer signalled
/// end-of-stream, if a length was declared then `received == declared`.
/// [`BodyAccounting::finish`] is the only place that can be answered, and it
/// MUST be called before end-of-stream is propagated to the router.
///
/// Deliberately NOT `Copy`. This is the counter the whole smuggling defense
/// rests on, and a `Copy` counter is silently bypassable: a frame loop
/// written `let mut acc = stream.accounting; acc.observe_data(..)` counts
/// into a temporary, the stream's own `received` stays at 0, and a
/// 100-byte declaration reconciles against a zero-byte body with no compile
/// error and no failing test. That is Envoy's link 1 with a different
/// mechanism. The codec holds one instance per stream and passes `&mut`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyAccounting {
    /// The declared body length, from the resolved framing. `None` when the
    /// peer declared nothing at all.
    declared: Option<u64>,
    /// Octets observed so far via `observe_data`.
    received: u64,
    /// Set once an end-of-stream signal has been recorded, by
    /// `observe_data` with `EndOfStream::Yes` or by `finish`.
    ended: bool,
}

/// Whether the peer signalled end-of-stream with this frame.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EndOfStream {
    /// More body may follow.
    No,
    /// This is the last body octet group; `END_STREAM` (H2) or FIN (H3) was
    /// set.
    Yes,
}

impl BodyAccounting {
    /// Accounting for a request whose framing has already been resolved.
    ///
    /// Maps [`RequestFraming::Empty`] to a declared length of `0`,
    /// [`RequestFraming::Exact`] to its `len`, and [`RequestFraming::Streamed`]
    /// to no declared length at all: on H2 and H3, `Streamed` arises only
    /// when the peer sent no `content-length`, because `transfer-encoding`
    /// is refused outright, so `None` here means "the peer declared
    /// nothing" and no reconciliation is possible or required.
    ///
    /// # Panics
    /// In debug builds, panics if `framing` is `RequestFraming::Exact { len:
    /// 0 }`. [`crate::framing::resolve_request_framing`] never produces that
    /// value (a zero `content-length` resolves to [`RequestFraming::Empty`]
    /// instead), so this can only happen by constructing the enum directly.
    /// Release builds skip the check and behave identically to `Empty`:
    /// both map to a declared length of `0`.
    #[must_use]
    pub const fn new(framing: RequestFraming) -> Self {
        if let RequestFraming::Exact { len } = framing {
            debug_assert!(
                len != 0,
                "RequestFraming::Exact {{ len: 0 }} is unreachable: \
                 resolve_request_framing maps a zero content-length to Empty"
            );
        }
        let declared = match framing {
            RequestFraming::Empty => Some(0),
            RequestFraming::Exact { len } => Some(len),
            RequestFraming::Streamed => None,
        };
        Self {
            declared,
            received: 0,
            ended: false,
        }
    }

    /// Accounting for a response whose framing has already been resolved.
    ///
    /// Maps [`ResponseFraming::Empty`] to a declared length of `0`,
    /// [`ResponseFraming::Exact`] to its `len`, and both
    /// [`ResponseFraming::Streamed`] and [`ResponseFraming::UntilClose`] to
    /// no declared length.
    ///
    /// # Panics
    /// In debug builds, panics if `framing` is
    /// [`ResponseFraming::UntilClose`], which cannot occur on a multiplexed
    /// protocol: H2 and H3 always end a body at `END_STREAM` or FIN, never
    /// at a connection close. Release builds skip the check and treat it
    /// the same as `Streamed`: no declared length.
    #[must_use]
    pub const fn for_response(framing: ResponseFraming) -> Self {
        debug_assert!(
            !matches!(framing, ResponseFraming::UntilClose),
            "ResponseFraming::UntilClose cannot occur on a multiplexed protocol"
        );
        let declared = match framing {
            ResponseFraming::Empty => Some(0),
            ResponseFraming::Exact { len } => Some(len),
            ResponseFraming::Streamed | ResponseFraming::UntilClose => None,
        };
        Self {
            declared,
            received: 0,
            ended: false,
        }
    }

    /// Records `len` received body octets and whether the peer signalled
    /// end-of-stream.
    ///
    /// Refuses immediately when the running count exceeds the declared
    /// length, without waiting for end-of-stream, and refuses at
    /// end-of-stream when the count is short. Uses `saturating_add`, so a
    /// 64-bit octet count cannot wrap under the declared value.
    ///
    /// # Errors
    /// [`RejectReason::ContentLengthMismatch`] when the running count
    /// exceeds the declared length, when end-of-stream arrives with a short
    /// count, or when data arrives after end-of-stream was already
    /// recorded.
    pub fn observe_data(&mut self, len: u64, eos: EndOfStream) -> Result<(), RejectReason> {
        if self.ended {
            // A DATA frame after end-of-stream is a stream error. The codec
            // sees the frame first and will also refuse it as a protocol
            // error; both are correct, and reporting it here too means the
            // refusal is counted alongside every other one.
            return Err(RejectReason::ContentLengthMismatch);
        }
        self.received = self.received.saturating_add(len);
        if let Some(declared) = self.declared
            && self.received > declared
        {
            return Err(RejectReason::ContentLengthMismatch);
        }
        if matches!(eos, EndOfStream::Yes) {
            self.ended = true;
            return self.check_final();
        }
        Ok(())
    }

    /// Records an end-of-stream signal that carries no data.
    ///
    /// This is the entry point for the headers-only-with-`END_STREAM` case
    /// (Envoy CVE-2026-48743) and the standalone zero-length STREAM frame
    /// with FIN case (HAProxy CVE-2026-33555). The codec MUST call this,
    /// and MUST see `Ok`, BEFORE it propagates end-of-stream to the router.
    ///
    /// Idempotent, and idempotent in both directions: calling it again after
    /// it already returned `Ok` returns `Ok` again, and calling it again
    /// after it already returned `Err` returns `Err` again. It does NOT
    /// short-circuit when `self.ended` is already set: `check_final` is
    /// pure, so re-running it is what keeps a second `finish` on a stream
    /// that already failed reconciliation refusing. A guard shaped like `if
    /// self.ended { return Ok(()) }` would turn "this stream already failed
    /// reconciliation" into "this stream ended cleanly" on the second call,
    /// which is the same skip-the-check-because-a-flag-is-set shape as
    /// Envoy's link 1.
    ///
    /// # Errors
    /// [`RejectReason::ContentLengthMismatch`] when a length was declared
    /// and the received count differs from it.
    pub fn finish(&mut self) -> Result<(), RejectReason> {
        self.ended = true;
        self.check_final()
    }

    /// The reconciliation check shared by `observe_data`'s end-of-stream
    /// path and `finish`: both end here, so a standalone FIN and a FIN on a
    /// data-bearing frame go through the identical check. HAProxy
    /// CVE-2026-33555's bug was treating the standalone case differently.
    const fn check_final(&self) -> Result<(), RejectReason> {
        if let Some(declared) = self.declared
            && self.received != declared
        {
            return Err(RejectReason::ContentLengthMismatch);
        }
        Ok(())
    }

    /// Octets received so far.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }

    /// The declared length, when the peer declared one.
    #[must_use]
    pub const fn declared(&self) -> Option<u64> {
        self.declared
    }

    /// True once end-of-stream has been recorded.
    #[must_use]
    pub const fn is_ended(&self) -> bool {
        self.ended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Selects between `BodyAccounting::new` and `BodyAccounting::for_response`.
    /// Edge cases 18 and 19 are `for_response` cases and cannot be expressed
    /// by a column that only holds a `RequestFraming`.
    #[derive(Clone, Copy, Debug)]
    enum Construction {
        Req(RequestFraming),
        Resp(ResponseFraming),
    }

    impl Construction {
        fn build(self) -> BodyAccounting {
            match self {
                Construction::Req(framing) => BodyAccounting::new(framing),
                Construction::Resp(framing) => BodyAccounting::for_response(framing),
            }
        }
    }

    /// One step of a call sequence exercised against a `BodyAccounting`.
    #[derive(Clone, Copy, Debug)]
    enum Op {
        Observe(u64, EndOfStream),
        Finish,
    }

    /// Runs `ops` against `acc` in order, collecting every call's result.
    fn run_ops(acc: &mut BodyAccounting, ops: &[Op]) -> Vec<Result<(), RejectReason>> {
        ops.iter()
            .map(|op| match *op {
                Op::Observe(len, eos) => acc.observe_data(len, eos),
                Op::Finish => acc.finish(),
            })
            .collect()
    }

    /// One `corpus_table` row: a label for failure messages, which
    /// constructor to use, the call sequence to run, and the expected
    /// result of each call in order. Named so `clippy::type_complexity`
    /// does not ask this one-off test table to factor out a type it uses
    /// exactly once.
    type Case = (
        &'static str,
        Construction,
        Vec<Op>,
        Vec<Result<(), RejectReason>>,
    );

    #[allow(
        clippy::too_many_lines,
        reason = "one table of edge cases 1 through 19 the issue names by number, plus the \
                  loop that runs each row (inlined so the assertions stay in this test's own \
                  body for no-test-without-assertion) and the two case-10 and case-18 checks \
                  the table format cannot express; splitting the table would break the 1:1 \
                  mapping to that numbered list"
    )]
    #[test]
    fn corpus_table() {
        use EndOfStream::{No, Yes};
        use Op::{Finish, Observe};
        use RejectReason::ContentLengthMismatch as Mismatch;

        let cases: Vec<Case> = vec![
            (
                "case 1: Empty framing, finish with no data",
                Construction::Req(RequestFraming::Empty),
                vec![Finish],
                vec![Ok(())],
            ),
            (
                "case 2: Empty framing, one DATA octet",
                Construction::Req(RequestFraming::Empty),
                vec![Observe(1, No)],
                vec![Err(Mismatch)],
            ),
            (
                "case 3: Exact { len: 100 }, finish with no data (Envoy CVE-2026-48743)",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Finish],
                vec![Err(Mismatch)],
            ),
            (
                "case 4: Exact { len: 100 }, zero-length observation with EndOfStream::Yes \
                 (HAProxy CVE-2026-33555)",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(0, Yes)],
                vec![Err(Mismatch)],
            ),
            (
                "case 5: Exact { len: 100 }, 100 octets then finish",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(100, No), Finish],
                vec![Ok(()), Ok(())],
            ),
            (
                "case 6: Exact { len: 100 }, 100 octets with EndOfStream::Yes in one call",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(100, Yes)],
                vec![Ok(())],
            ),
            (
                "case 7: Exact { len: 100 }, 60 octets then 40 octets with EndOfStream::Yes",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(60, No), Observe(40, Yes)],
                vec![Ok(()), Ok(())],
            ),
            (
                "case 8: Exact { len: 100 }, 101 octets refused on the crossing call, before EOS",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(101, No)],
                vec![Err(Mismatch)],
            ),
            (
                "case 9: Exact { len: 100 }, 99 octets then finish",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(99, No), Finish],
                vec![Ok(()), Err(Mismatch)],
            ),
            (
                "case 11: Streamed framing, octets then finish",
                Construction::Req(RequestFraming::Streamed),
                vec![Observe(999_999, No), Finish],
                vec![Ok(()), Ok(())],
            ),
            (
                "case 12: Streamed framing, finish with no data",
                Construction::Req(RequestFraming::Streamed),
                vec![Finish],
                vec![Ok(())],
            ),
            (
                "case 13a: finish called twice on a reconciled stream",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(100, No), Finish, Finish],
                vec![Ok(()), Ok(()), Ok(())],
            ),
            (
                "case 13b: finish called twice on a stream that already refused",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(99, No), Finish, Finish],
                vec![Ok(()), Err(Mismatch), Err(Mismatch)],
            ),
            (
                "case 14a: finish after an observe_data(EndOfStream::Yes) that reconciled",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(100, Yes), Finish],
                vec![Ok(()), Ok(())],
            ),
            (
                "case 14b: finish after an observe_data(EndOfStream::Yes) that did not reconcile",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Observe(50, Yes), Finish],
                vec![Err(Mismatch), Err(Mismatch)],
            ),
            (
                "case 15: observe_data after finish",
                Construction::Req(RequestFraming::Exact { len: 100 }),
                vec![Finish, Observe(1, No)],
                vec![Err(Mismatch), Err(Mismatch)],
            ),
            (
                "case 16: observe_data after a previous Err stays terminal",
                Construction::Req(RequestFraming::Exact { len: 1 }),
                vec![Observe(5, No), Observe(1, No)],
                vec![Err(Mismatch), Err(Mismatch)],
            ),
            (
                "case 17: observe_data(u64::MAX, No) twice saturates rather than wraps",
                Construction::Req(RequestFraming::Exact { len: 1 }),
                vec![Observe(u64::MAX, No), Observe(u64::MAX, No)],
                vec![Err(Mismatch), Err(Mismatch)],
            ),
            (
                "case 19: for_response(Empty) stands in for a HEAD response, which \
                 resolve_response_framing already maps to Empty before this type ever sees it",
                Construction::Resp(ResponseFraming::Empty),
                vec![Finish],
                vec![Ok(())],
            ),
        ];

        for (label, construction, ops, expected) in cases {
            let mut acc = construction.build();
            let got = run_ops(&mut acc, &ops);
            assert_eq!(got, expected, "{label}");
        }

        // Silences the panic hook noise for the two catch_unwind checks
        // below, restored immediately after both run.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        // Case 10: `Exact { len: 0 }` is unreachable through
        // `resolve_request_framing` (a zero content-length resolves to
        // `Empty` instead), and `new` documents that with a debug
        // assertion, which fires unconditionally the moment `Exact { len: 0
        // }` is constructed at all: there is no way to reach a returned
        // value to inspect in this (debug) test build. Proven here with
        // catch_unwind, which confirms the assertion fires; the
        // release-mode equivalence to `Empty` (both arms produce `declared:
        // Some(0)`) is a static property of the code that a debug build
        // cannot observe directly, because debug_assert compiles out
        // entirely in release.
        let case_10 = std::panic::catch_unwind(|| {
            let _ = BodyAccounting::new(RequestFraming::Exact { len: 0 });
        });
        assert!(
            case_10.is_err(),
            "case 10: BodyAccounting::new(Exact {{ len: 0 }}) must debug_assert in this \
             (debug) test build"
        );

        // Case 18: `for_response(UntilClose)` cannot occur on a multiplexed
        // protocol, and the debug assertion documenting that fires
        // unconditionally too, for the same reason as case 10: there is no
        // returned value to inspect `declared()` on in this (debug) test
        // build. The release-mode fact the edge case names, `declared:
        // None`, is likewise a static property of the code (the `Streamed
        // | UntilClose => None` arm) rather than something this build can
        // assert at run time.
        let case_18 = std::panic::catch_unwind(|| {
            let _ = BodyAccounting::for_response(ResponseFraming::UntilClose);
        });
        assert!(
            case_18.is_err(),
            "case 18: BodyAccounting::for_response(UntilClose) must debug_assert in this \
             (debug) test build"
        );

        std::panic::set_hook(prev_hook);
    }

    #[test]
    fn headers_only_with_declared_length_is_malformed() {
        // Envoy CVE-2026-48743 (GHSA-8phg-2h2q-jgxf): a headers-only
        // request with a nonzero Content-Length was promoted to
        // `end_stream = true` by `EnvoyQuicServerStream::OnInitialHeadersComplete()`
        // before body accounting ran, because `updateReceivedContentBytes()`
        // is skipped once `end_stream_decoded_` is already set. The
        // advisory's own invariant: "semantic request completion must not
        // cross a protocol boundary until Content-Length accounting has
        // been reconciled with received DATA bytes." `finish` is that
        // reconciliation, and calling it on a headers-only request that
        // declared a body reproduces exactly the case Envoy shipped without
        // it. Affected Envoy >= 1.35 and < 1.39; fixed in 1.35.13, 1.36.9,
        // 1.37.5 and 1.38.3.
        let mut acc = BodyAccounting::new(RequestFraming::Exact { len: 100 });
        assert_eq!(acc.finish(), Err(RejectReason::ContentLengthMismatch));
    }

    #[test]
    fn standalone_fin_goes_through_the_same_path() {
        // HAProxy CVE-2026-33555: the HTTP/3 parser did not verify the
        // received body length against the declared Content-Length when the
        // stream was closed by a zero-payload STREAM frame with FIN, so a
        // headers-only close slipped through a route `finish` never saw.
        // Here both paths, `observe_data(0, EndOfStream::Yes)` and
        // `finish()`, must produce the identical error for the same
        // declared length, because both end in `check_final`. Reported
        // fixed in HAProxy 3.3.6, 3.2.15, 3.0.19, 2.8.20 and 2.6.25.
        let declared = RequestFraming::Exact { len: 100 };

        let mut via_observe = BodyAccounting::new(declared);
        let observe_result = via_observe.observe_data(0, EndOfStream::Yes);

        let mut via_finish = BodyAccounting::new(declared);
        let finish_result = via_finish.finish();

        assert_eq!(observe_result, finish_result);
        assert_eq!(observe_result, Err(RejectReason::ContentLengthMismatch));
    }

    #[test]
    fn over_long_body_refused_before_eos() {
        // `declared()` reports exactly what each constructor documented:
        // `Empty` as `Some(0)`, `Exact { len }` as `Some(len)`, `Streamed`
        // as `None`. Checked before either accounting below observes
        // anything, so this is `declared()` alone, not entangled with the
        // reject behaviour the rest of this test exercises.
        let empty_declared = BodyAccounting::new(RequestFraming::Empty);
        assert_eq!(empty_declared.declared(), Some(0));
        let exact_declared = BodyAccounting::new(RequestFraming::Exact { len: 100 });
        assert_eq!(exact_declared.declared(), Some(100));
        let streamed_declared = BodyAccounting::new(RequestFraming::Streamed);
        assert_eq!(streamed_declared.declared(), None);

        // Edge cases 2 and 8: the reject fires on the call that crosses the
        // declared length, before end-of-stream, never waiting for EOS the
        // way a naive "check only at finish" implementation would.
        let mut empty = BodyAccounting::new(RequestFraming::Empty);
        assert_eq!(
            empty.observe_data(1, EndOfStream::No),
            Err(RejectReason::ContentLengthMismatch)
        );
        assert!(
            !empty.is_ended(),
            "the reject arrived with EndOfStream::No; nothing signalled end-of-stream"
        );

        let mut exact = BodyAccounting::new(RequestFraming::Exact { len: 100 });
        assert_eq!(
            exact.observe_data(101, EndOfStream::No),
            Err(RejectReason::ContentLengthMismatch)
        );
        assert!(
            !exact.is_ended(),
            "the reject arrived with EndOfStream::No; nothing signalled end-of-stream"
        );

        // The positive case for `is_ended()`, so a mutant that always
        // returns `false` from `is_ended` cannot hide behind the two
        // `!is_ended()` checks above: EndOfStream::Yes must flip it to
        // `true` even though this call also refuses (declared 100, only 50
        // received).
        let mut short_with_eos = BodyAccounting::new(RequestFraming::Exact { len: 100 });
        assert_eq!(
            short_with_eos.observe_data(50, EndOfStream::Yes),
            Err(RejectReason::ContentLengthMismatch)
        );
        assert!(
            short_with_eos.is_ended(),
            "EndOfStream::Yes must record end-of-stream even when reconciliation fails"
        );
    }

    #[test]
    fn terminal_after_error() {
        // Edge case 21: a frame loop that observes through a `&mut` borrow
        // is visible to the owner, which is only guaranteed because
        // `BodyAccounting` is not `Copy`. `feed` takes `&mut BodyAccounting`
        // (never by value), observes 60 then 40 octets, and the owner's
        // `finish()` sees the combined total. If `BodyAccounting` were ever
        // made `Copy` and a frame loop took it by value instead, `feed`
        // would mutate a copy and the owner's `finish()` would see 0
        // received against 100 declared. Used at the end of this test, but
        // declared first: clippy's `items_after_statements` wants every
        // item before the first statement in its scope.
        fn feed(acc: &mut BodyAccounting) {
            acc.observe_data(60, EndOfStream::No)
                .expect("60 of a 100-octet declaration must not fail");
            acc.observe_data(40, EndOfStream::No)
                .expect("the combined 100 octets must not fail");
        }

        // Edge case 15: observe_data after finish.
        let mut after_finish = BodyAccounting::new(RequestFraming::Exact { len: 100 });
        assert_eq!(
            after_finish.finish(),
            Err(RejectReason::ContentLengthMismatch)
        );
        assert_eq!(
            after_finish.observe_data(1, EndOfStream::No),
            Err(RejectReason::ContentLengthMismatch)
        );

        // Edge case 16: observe_data after a previous Err stays terminal;
        // once received exceeds declared, received only grows.
        let mut after_overrun = BodyAccounting::new(RequestFraming::Exact { len: 1 });
        assert_eq!(
            after_overrun.observe_data(5, EndOfStream::No),
            Err(RejectReason::ContentLengthMismatch)
        );
        assert_eq!(
            after_overrun.observe_data(1, EndOfStream::No),
            Err(RejectReason::ContentLengthMismatch)
        );

        // Edge case 17: observe_data(u64::MAX, No) twice against
        // Exact { len: 1 }. The first call already exceeds and returns Err;
        // saturating_add means the second call cannot wrap the count back
        // toward a small value.
        let mut saturating = BodyAccounting::new(RequestFraming::Exact { len: 1 });
        assert_eq!(
            saturating.observe_data(u64::MAX, EndOfStream::No),
            Err(RejectReason::ContentLengthMismatch)
        );
        assert_eq!(
            saturating.observe_data(u64::MAX, EndOfStream::No),
            Err(RejectReason::ContentLengthMismatch)
        );
        assert_eq!(
            saturating.received(),
            u64::MAX,
            "received must saturate at u64::MAX, not wrap to a small value"
        );

        // Edge case 21, continued: `feed` (declared above) mutates through
        // a `&mut` borrow, and the owner's own `finish()` observes it.
        let mut owned = BodyAccounting::new(RequestFraming::Exact { len: 100 });
        feed(&mut owned);
        assert_eq!(owned.finish(), Ok(()));
    }

    proptest::proptest! {
        #[test]
        fn prop_reconciliation_is_exact(
            declared in 0u64..=4096,
            chunks in proptest::collection::vec(0u64..=512, 0..=32),
        ) {
            let sum: u64 = chunks.iter().copied().sum();
            let framing = if declared == 0 {
                RequestFraming::Empty
            } else {
                RequestFraming::Exact { len: declared }
            };

            // Feed every chunk with EndOfStream::No, then a separate finish.
            let mut via_finish = BodyAccounting::new(framing);
            for &chunk in &chunks {
                let _ = via_finish.observe_data(chunk, EndOfStream::No);
            }
            let finish_result = via_finish.finish();
            assert_eq!(finish_result.is_ok(), sum == declared);

            // Feed the same chunks, the last one (if any) carrying
            // EndOfStream::Yes instead of a trailing finish call.
            let mut via_eos = BodyAccounting::new(framing);
            let mut eos_result = Ok(());
            let last_index = chunks.len().saturating_sub(1);
            for (i, &chunk) in chunks.iter().enumerate() {
                let eos = if i == last_index { EndOfStream::Yes } else { EndOfStream::No };
                eos_result = via_eos.observe_data(chunk, eos);
            }
            if chunks.is_empty() {
                eos_result = via_eos.finish();
            }
            assert_eq!(eos_result.is_ok(), sum == declared);
        }
    }
}
