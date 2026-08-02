// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Purity`, `PoisonReason` and `ExchangeLedger`: one-request-one-response accounting for
//! one pooled upstream connection, and the structural defense against response queue
//! poisoning.
//!
//! # The seven anomalies
//!
//! A pooled upstream connection is marked `Poisoned` and closed rather than returned to
//! the pool when any of the following happens:
//!
//! 1. the response's framing did not resolve cleanly (`ResponseFramingRefused`);
//! 2. the upstream sent a final response before we finished sending the request body
//!    (`EarlyFinalResponse`);
//! 3. the response body's octet count did not match its declared `Content-Length`
//!    (`BodyLengthMismatch`);
//! 4. we sent N requests and received a number other than N responses
//!    (`ExchangeCountMismatch`);
//! 5. bytes remain unread on the socket after the response is complete (`TrailingBytes`);
//! 6. the upstream closed while a request was in flight (`ClosedInFlight`);
//! 7. the response was framed `UntilClose`, which by definition cannot be followed by
//!    another response on the same connection (`CloseDelimitedResponse`).
//!
//! # Why this is the defense
//!
//! Response queue poisoning is desync causing response N to be delivered to request
//! N plus 1. Strict one-request-one-response accounting per upstream connection makes
//! that a detected condition rather than a silent one: any surplus or deficit poisons the
//! connection. The "double desync" weaponization, which is how a single `0.CL` becomes
//! cross-user contamination, requires reusing a connection after an anomaly. Refusing to
//! reuse costs one TCP handshake and removes the mechanism.
//!
//! # The easiest way to misuse this type
//!
//! The caller MUST call [`ExchangeLedger::request_body_written`] for EVERY request,
//! including one with no body at all. For a bodyless request (a plain `GET`) the call
//! comes immediately after [`ExchangeLedger::begin_request`], because the body is
//! trivially complete. Omitting it means [`ExchangeLedger::response_head`] sees the
//! request body as incomplete and poisons the connection with `EarlyFinalResponse` on
//! every bodyless request, which is every `GET`: the connection pool would then be a
//! one-shot connection pool with a perfect-looking metric explaining why.
//!
//! # What this delivers and what it does not
//!
//! This is the sans-IO ledger: a type that is told what happened and answers "may this
//! connection be pooled". It does not implement the pool, does not touch a socket, and
//! does not decide when to open a new connection. The forwarding loop drives it, in a
//! later milestone.
//!
//! # Why this design and not the obvious alternative
//!
//! The obvious alternative is to return the connection to the pool after an anomaly
//! because "it is probably fine", possibly after draining. It loses: that is the
//! mechanism that turns a single `0.CL` into the double desync that poisons other users'
//! requests, and draining is exactly what an attacker who controls the response body can
//! control. The second alternative is to make the ledger part of the pool; it loses
//! because then the seven anomalies can only be tested through the pool, which needs
//! sockets, and the seven anomalies are the whole value.
//!
//! # `PoolScope`
//!
//! For clusters explicitly marked `untrusted_origin`, the pool scope defaults to
//! [`PoolScope::PerDownstreamConnection`], which fully removes cross-user contamination
//! at the cost of connection churn. That enum lives here so the pool implementation in a
//! later milestone cannot invent its own; the pool itself is not implemented in this
//! issue.
//!
//! # Complexity
//!
//! Every method is `O(1)` time and space. An [`ExchangeLedger`] is 40 bytes; at 10,000
//! upstream connections that is 400 KB.

use irontraffic_http::RejectReason;
use irontraffic_http::response::ResponseFraming;

/// Whether a pooled upstream connection may be reused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Purity {
    /// Every exchange on this connection completed cleanly. It may return to the pool.
    Clean,
    /// Something anomalous happened. The connection MUST be closed, not pooled.
    Poisoned(PoisonReason),
}

/// Why a connection was poisoned. Every variant has a distinct metric label, because an
/// operator who cannot see which anomaly is happening cannot diagnose a desyncing origin.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PoisonReason {
    /// The response framing did not resolve cleanly.
    ResponseFramingRefused,
    /// The upstream sent a final response before we finished sending the request body.
    EarlyFinalResponse,
    /// The response body octet count did not match the declared `Content-Length`.
    BodyLengthMismatch,
    /// We sent N requests and received a different number of responses.
    ExchangeCountMismatch,
    /// Bytes remained unread on the socket after the response completed.
    TrailingBytes,
    /// The upstream closed while a request was in flight.
    ClosedInFlight,
    /// The response was framed by the connection close, so there can be no next response.
    CloseDelimitedResponse,
    /// A protocol-level anomaly the forwarding loop detected and named generically.
    ProtocolAnomaly,
}

/// One-request-one-response accounting for one upstream connection.
///
/// Deliberately NOT `Copy`. The whole value of this type is that a poison sticks to the
/// connection: a forwarding loop written `fn relay(mut ledger: ExchangeLedger, ..)`
/// poisons a temporary, the connection's own ledger stays `Clean`, `may_pool()` answers
/// true, and the anomalous connection goes straight back into the pool. That is the
/// double-desync mechanism this issue exists to remove, reintroduced by a derive. The
/// connection owns one ledger and every call takes `&mut`.
#[derive(Clone, Debug)]
pub struct ExchangeLedger {
    requests_sent: u32,
    responses_received: u32,
    /// Set while a request head has been written and its response has not completed.
    in_flight: bool,
    /// Set once the request body is fully written for the in-flight exchange.
    request_body_complete: bool,
    /// Declared length of the in-flight response, when it declared one.
    declared_body: Option<u64>,
    /// Body octets received for the in-flight response.
    received_body: u64,
    purity: Purity,
}

/// How widely an upstream HTTP/1 connection may be shared.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PoolScope {
    /// Shared across every downstream connection. Fast, and relies on the poisoning rules.
    Shared,
    /// One upstream connection per downstream connection. Slower, structurally removes
    /// cross-user contamination. The default for a cluster marked `untrusted_origin`.
    PerDownstreamConnection,
}

impl ExchangeLedger {
    /// A clean ledger for a new upstream connection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            requests_sent: 0,
            responses_received: 0,
            in_flight: false,
            request_body_complete: false,
            declared_body: None,
            received_body: 0,
            purity: Purity::Clean,
        }
    }

    /// Sets the purity to `Poisoned(reason)` when it is still `Clean`, leaving an
    /// existing poison's reason untouched either way, and returns the purity that
    /// results. This is what makes "the first reason wins" one line rather than a rule
    /// every call site has to remember.
    fn poison(&mut self, reason: PoisonReason) -> Purity {
        if self.purity == Purity::Clean {
            self.purity = Purity::Poisoned(reason);
        }
        self.purity
    }

    /// Records that a request head has been written.
    ///
    /// # Errors
    /// The current `Purity` when the connection is already poisoned, or when an exchange
    /// is already in flight (we never pipeline upstream, and doing so is what makes
    /// response queue poisoning possible).
    pub fn begin_request(&mut self) -> Result<(), Purity> {
        if self.purity != Purity::Clean {
            return Err(self.purity);
        }
        if self.in_flight {
            return Err(self.poison(PoisonReason::ProtocolAnomaly));
        }
        self.requests_sent = self.requests_sent.saturating_add(1);
        self.in_flight = true;
        self.request_body_complete = false;
        self.declared_body = None;
        self.received_body = 0;
        Ok(())
    }

    /// Records that the request body has been fully written.
    pub fn request_body_written(&mut self) {
        self.request_body_complete = true;
    }

    /// Records the response head and its resolved framing.
    ///
    /// Poisons with `EarlyFinalResponse` when the request body is not yet fully written,
    /// and with `CloseDelimitedResponse` for `UntilClose` framing (returning `Ok`,
    /// because that response is valid and must still be relayed).
    ///
    /// # Errors
    /// The current `Purity` on an early final response or when already poisoned.
    pub fn response_head(&mut self, framing: ResponseFraming) -> Result<(), Purity> {
        if self.purity != Purity::Clean {
            return Err(self.purity);
        }
        if !self.request_body_complete {
            return Err(self.poison(PoisonReason::EarlyFinalResponse));
        }
        if framing.forbids_reuse() {
            self.poison(PoisonReason::CloseDelimitedResponse);
        }
        self.declared_body = framing.known_len();
        Ok(())
    }

    /// Records that response framing resolution refused the response.
    ///
    /// The `RejectReason` is not stored: the metric that counts it is emitted by the
    /// caller with its own label. The parameter exists so the call site reads correctly
    /// and so a future version can store it without an API change.
    pub fn response_framing_refused(&mut self, _reason: RejectReason) {
        self.poison(PoisonReason::ResponseFramingRefused);
    }

    /// Records `n` response body octets.
    ///
    /// # Errors
    /// The current `Purity` when the count exceeds the declared length, or when already
    /// poisoned.
    pub fn response_body_bytes(&mut self, n: u64) -> Result<(), Purity> {
        if self.purity != Purity::Clean {
            return Err(self.purity);
        }
        self.received_body = self.received_body.saturating_add(n);
        if let Some(declared) = self.declared_body
            && self.received_body > declared
        {
            return Err(self.poison(PoisonReason::BodyLengthMismatch));
        }
        Ok(())
    }

    /// Records that the response completed, checking the body length and the exchange
    /// count.
    ///
    /// # Errors
    /// The current `Purity` on a short body, on an exchange count mismatch, or when
    /// already poisoned.
    pub fn response_complete(&mut self) -> Result<(), Purity> {
        if self.purity != Purity::Clean {
            return Err(self.purity);
        }
        if let Some(declared) = self.declared_body
            && self.received_body != declared
        {
            return Err(self.poison(PoisonReason::BodyLengthMismatch));
        }
        self.responses_received = self.responses_received.saturating_add(1);
        self.in_flight = false;
        if self.responses_received != self.requests_sent {
            return Err(self.poison(PoisonReason::ExchangeCountMismatch));
        }
        Ok(())
    }

    /// Records that bytes remained unread on the socket after the response completed.
    pub fn socket_had_trailing_bytes(&mut self) {
        self.poison(PoisonReason::TrailingBytes);
    }

    /// Records that the upstream closed. Poisons only when an exchange was in flight.
    pub fn upstream_closed(&mut self) {
        if self.in_flight {
            self.poison(PoisonReason::ClosedInFlight);
        }
    }

    /// True when this connection may return to the pool.
    #[must_use]
    pub const fn may_pool(&self) -> bool {
        matches!(self.purity, Purity::Clean) && !self.in_flight
    }

    /// The current purity.
    #[must_use]
    pub const fn purity(&self) -> Purity {
        self.purity
    }

    /// Requests sent on this connection.
    #[must_use]
    pub const fn requests_sent(&self) -> u32 {
        self.requests_sent
    }

    /// Responses received on this connection.
    #[must_use]
    pub const fn responses_received(&self) -> u32 {
        self.responses_received
    }
}

impl Default for ExchangeLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl PoisonReason {
    /// The stable, `snake_case` metric label.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            PoisonReason::ResponseFramingRefused => "response_framing_refused",
            PoisonReason::EarlyFinalResponse => "early_final_response",
            PoisonReason::BodyLengthMismatch => "body_length_mismatch",
            PoisonReason::ExchangeCountMismatch => "exchange_count_mismatch",
            PoisonReason::TrailingBytes => "trailing_bytes",
            PoisonReason::ClosedInFlight => "closed_in_flight",
            PoisonReason::CloseDelimitedResponse => "close_delimited_response",
            PoisonReason::ProtocolAnomaly => "protocol_anomaly",
        }
    }

    /// Every variant.
    pub const ALL: [PoisonReason; 8] = [
        PoisonReason::ResponseFramingRefused,
        PoisonReason::EarlyFinalResponse,
        PoisonReason::BodyLengthMismatch,
        PoisonReason::ExchangeCountMismatch,
        PoisonReason::TrailingBytes,
        PoisonReason::ClosedInFlight,
        PoisonReason::CloseDelimitedResponse,
        PoisonReason::ProtocolAnomaly,
    ];
}

impl Default for PoolScope {
    /// `Shared`. A cluster marked `untrusted_origin` overrides this to
    /// `PerDownstreamConnection` at configuration compile time.
    fn default() -> Self {
        PoolScope::Shared
    }
}

#[cfg(test)]
mod tests {
    use super::{ExchangeLedger, PoisonReason, PoolScope, Purity, RejectReason, ResponseFraming};
    use proptest::prelude::*;

    #[test]
    fn clean_exchanges() {
        // Edge case 1: a fresh ledger.
        let mut ledger = ExchangeLedger::new();
        assert!(ledger.may_pool());
        assert_eq!(ledger.purity(), Purity::Clean);
        assert_eq!(ledger.requests_sent(), 0);
        assert_eq!(ledger.responses_received(), 0);

        // Edge case 17: may_pool() is false the moment an exchange opens, even though
        // the purity stays Clean throughout what will be a clean exchange. This is what
        // stops a half-finished exchange being handed to the next user.
        assert_eq!(ledger.begin_request(), Ok(()));
        assert!(
            !ledger.may_pool(),
            "in flight but no reply yet must not be poolable"
        );
        assert_eq!(ledger.purity(), Purity::Clean);
        ledger.request_body_written();
        assert!(!ledger.may_pool());

        // Edge case 2: one clean exchange with Exact framing.
        assert_eq!(
            ledger.response_head(ResponseFraming::Exact { len: 5 }),
            Ok(())
        );
        assert!(!ledger.may_pool());
        assert_eq!(ledger.response_body_bytes(5), Ok(()));
        assert_eq!(ledger.response_complete(), Ok(()));
        assert!(ledger.may_pool());
        assert_eq!(ledger.purity(), Purity::Clean);
        assert_eq!(ledger.requests_sent(), 1);
        assert_eq!(ledger.responses_received(), 1);

        // Edge case 3: a clean exchange with Empty framing declares a body of exactly
        // zero octets, not "no declared length" (which would be Streamed's None). The
        // very next octet must exceed it: if response_head instead mapped Empty to
        // known_len() == None, this call would return Ok, and this assertion would
        // catch it.
        assert_eq!(ledger.begin_request(), Ok(()));
        ledger.request_body_written();
        assert_eq!(ledger.response_head(ResponseFraming::Empty), Ok(()));
        assert_eq!(
            ledger.response_body_bytes(1),
            Err(Purity::Poisoned(PoisonReason::BodyLengthMismatch))
        );

        // Edge case 3b: a bodyless request (a plain GET) completes cleanly when the
        // caller calls request_body_written immediately after begin_request; skipping
        // that call instead poisons with EarlyFinalResponse. Both directions, on fresh
        // ledgers.
        let mut clean_get = ExchangeLedger::new();
        assert_eq!(clean_get.begin_request(), Ok(()));
        clean_get.request_body_written();
        assert_eq!(clean_get.response_head(ResponseFraming::Empty), Ok(()));
        assert_eq!(clean_get.response_complete(), Ok(()));
        assert!(clean_get.may_pool());

        let mut missed_call = ExchangeLedger::new();
        assert_eq!(missed_call.begin_request(), Ok(()));
        // request_body_written is never called.
        assert_eq!(
            missed_call.response_head(ResponseFraming::Empty),
            Err(Purity::Poisoned(PoisonReason::EarlyFinalResponse))
        );
        assert!(!missed_call.may_pool());

        // Edge case 4: a clean exchange with Streamed framing accepts any number of
        // body bytes across any number of calls.
        let mut streamed = ExchangeLedger::new();
        assert_eq!(streamed.begin_request(), Ok(()));
        streamed.request_body_written();
        assert_eq!(streamed.response_head(ResponseFraming::Streamed), Ok(()));
        assert_eq!(streamed.response_body_bytes(1_000_000), Ok(()));
        assert_eq!(streamed.response_body_bytes(1), Ok(()));
        assert_eq!(streamed.response_complete(), Ok(()));
        assert!(streamed.may_pool());

        // Edge case 20: PoolScope::default() is Shared.
        assert_eq!(PoolScope::default(), PoolScope::Shared);
    }

    #[test]
    fn until_close_poisons_but_relays() {
        // Edge case 5: UntilClose framing. The response is still valid and must be
        // relayed, so response_head returns Ok even though it poisons the connection.
        let mut ledger = ExchangeLedger::new();
        assert_eq!(ledger.begin_request(), Ok(()));
        ledger.request_body_written();
        assert_eq!(ledger.response_head(ResponseFraming::UntilClose), Ok(()));
        assert_eq!(
            ledger.purity(),
            Purity::Poisoned(PoisonReason::CloseDelimitedResponse)
        );
        assert!(!ledger.may_pool());
    }

    #[test]
    fn early_final_response() {
        // Edge case 6: an early final response is the 0.CL escape hatch that turns a
        // deadlock into a working exploit. The upstream answering before it has read
        // the request body we are still sending is exactly what lets a smuggled second
        // request ride the rest of that same body onto the origin.
        let mut ledger = ExchangeLedger::new();
        assert_eq!(ledger.begin_request(), Ok(()));
        // request_body_written is never called.
        assert_eq!(
            ledger.response_head(ResponseFraming::Exact { len: 0 }),
            Err(Purity::Poisoned(PoisonReason::EarlyFinalResponse))
        );

        // Edge case 7: the ledger never receives a status code at all (response_head's
        // only input besides self is the resolved framing), so a "2xx" early response
        // poisons identically to any other. The absence of a status parameter on
        // response_head is itself the enforcement; this asserts the resulting
        // behaviour explicitly rather than leaving it implied.
        let mut ledger_would_be_2xx = ExchangeLedger::new();
        assert_eq!(ledger_would_be_2xx.begin_request(), Ok(()));
        assert_eq!(
            ledger_would_be_2xx.response_head(ResponseFraming::Empty),
            Err(Purity::Poisoned(PoisonReason::EarlyFinalResponse))
        );
    }

    #[test]
    fn body_length_mismatch_both_directions() {
        // Edge case 8: one octet over the declared length poisons on the exact call
        // that crosses it.
        let mut over = ExchangeLedger::new();
        assert_eq!(over.begin_request(), Ok(()));
        over.request_body_written();
        assert_eq!(
            over.response_head(ResponseFraming::Exact { len: 5 }),
            Ok(())
        );
        assert_eq!(over.response_body_bytes(5), Ok(()));
        assert_eq!(
            over.response_body_bytes(1),
            Err(Purity::Poisoned(PoisonReason::BodyLengthMismatch))
        );

        // Edge case 9: one octet short can only be caught at response_complete,
        // because response_body_bytes has no way to know the response is over.
        let mut short = ExchangeLedger::new();
        assert_eq!(short.begin_request(), Ok(()));
        short.request_body_written();
        assert_eq!(
            short.response_head(ResponseFraming::Exact { len: 5 }),
            Ok(())
        );
        assert_eq!(short.response_body_bytes(4), Ok(()));
        assert_eq!(
            short.response_complete(),
            Err(Purity::Poisoned(PoisonReason::BodyLengthMismatch))
        );

        // Edge case 18: response_body_bytes(u64::MAX) twice against a declared length
        // poisons on the first call, because it already exceeds any finite declared
        // length, and the second call (already poisoned) reports the identical reason.
        let mut declared = ExchangeLedger::new();
        assert_eq!(declared.begin_request(), Ok(()));
        declared.request_body_written();
        assert_eq!(
            declared.response_head(ResponseFraming::Exact { len: 5 }),
            Ok(())
        );
        assert_eq!(
            declared.response_body_bytes(u64::MAX),
            Err(Purity::Poisoned(PoisonReason::BodyLengthMismatch))
        );
        assert_eq!(
            declared.response_body_bytes(u64::MAX),
            Err(Purity::Poisoned(PoisonReason::BodyLengthMismatch))
        );

        // With Streamed framing (no declared length) the identical two calls never
        // poison. If the internal counter used a plain `+` instead of saturating_add,
        // the second call (u64::MAX + u64::MAX) would overflow and panic under the
        // debug overflow checks this workspace runs its tests with, so this also
        // pins the saturating behaviour even though received_body has no accessor.
        let mut streamed = ExchangeLedger::new();
        assert_eq!(streamed.begin_request(), Ok(()));
        streamed.request_body_written();
        assert_eq!(streamed.response_head(ResponseFraming::Streamed), Ok(()));
        assert_eq!(streamed.response_body_bytes(u64::MAX), Ok(()));
        assert_eq!(streamed.response_body_bytes(u64::MAX), Ok(()));
        assert_eq!(streamed.response_complete(), Ok(()));
    }

    #[test]
    fn exchange_count_mismatch() {
        // Edge case 10: two response_complete calls for one begin_request. The second
        // makes responses_received == 2 against requests_sent == 1.
        let mut double_complete = ExchangeLedger::new();
        assert_eq!(double_complete.begin_request(), Ok(()));
        double_complete.request_body_written();
        assert_eq!(
            double_complete.response_head(ResponseFraming::Empty),
            Ok(())
        );
        assert_eq!(double_complete.response_complete(), Ok(()));
        assert_eq!(
            double_complete.response_complete(),
            Err(Purity::Poisoned(PoisonReason::ExchangeCountMismatch))
        );

        // Edge case 11: begin_request twice without a response in between is
        // pipelining upstream, which this ledger treats as a programming error.
        let mut double_begin = ExchangeLedger::new();
        assert_eq!(double_begin.begin_request(), Ok(()));
        assert_eq!(
            double_begin.begin_request(),
            Err(Purity::Poisoned(PoisonReason::ProtocolAnomaly))
        );

        // Edge case 19: requests_sent saturates at u32::MAX instead of wrapping to 0,
        // which would otherwise read as a fresh, clean connection sitting next to a
        // stale nonzero responses_received: a live mismatch hidden by wraparound.
        // Constructed already at the ceiling (looping there would take 4 billion
        // calls) so the next begin_request exercises the real saturating_add path.
        let mut at_ceiling = ExchangeLedger {
            requests_sent: u32::MAX,
            responses_received: u32::MAX,
            in_flight: false,
            request_body_complete: false,
            declared_body: None,
            received_body: 0,
            purity: Purity::Clean,
        };
        assert_eq!(at_ceiling.begin_request(), Ok(()));
        assert_eq!(
            at_ceiling.requests_sent(),
            u32::MAX,
            "requests_sent must saturate at u32::MAX rather than wrap to 0"
        );

        // Review finding 4 on PR 843: this is the consequence of saturating at
        // the ceiling, measured rather than changed. Once both counters have
        // saturated at u32::MAX, response_complete's own saturating_add(1) on
        // responses_received is *also* a no-op, so the mismatch comparison two
        // lines later can never observe a surplus response again: the
        // one-request-one-response accounting this module's own doc header
        // calls "the structural defense against response queue poisoning" goes
        // permanently vacuous on a connection that has served u32::MAX
        // requests. `## Design` mandates saturating_add and `## Do NOT`
        // forbids `+` on these counters, so the counters must not wrap
        // either; this is not a defect this test is asking to be fixed.
        assert_eq!(at_ceiling.response_complete(), Ok(()));
        assert_eq!(at_ceiling.responses_received(), u32::MAX);
        assert!(
            at_ceiling.may_pool(),
            "at the counter ceiling the exchange completes as Clean"
        );

        // A genuine surplus response -- one more response than was ever
        // requested -- is exactly what saturating_add(1) can no longer
        // distinguish from a real match: a second response_complete with
        // nothing in flight also returns Ok and leaves the connection
        // poolable.
        assert_eq!(at_ceiling.response_complete(), Ok(()));
        assert_eq!(at_ceiling.responses_received(), u32::MAX);
        assert!(
            at_ceiling.may_pool(),
            "a surplus response at the counter ceiling still pools cleanly"
        );
    }

    #[test]
    fn close_and_trailing_bytes() {
        // Edge case 12: trailing bytes after an otherwise clean exchange.
        let mut trailing = ExchangeLedger::new();
        assert_eq!(trailing.begin_request(), Ok(()));
        trailing.request_body_written();
        assert_eq!(trailing.response_head(ResponseFraming::Empty), Ok(()));
        assert_eq!(trailing.response_complete(), Ok(()));
        assert!(trailing.may_pool());
        trailing.socket_had_trailing_bytes();
        assert_eq!(
            trailing.purity(),
            Purity::Poisoned(PoisonReason::TrailingBytes)
        );
        assert!(!trailing.may_pool());

        // Edge case 13: a clean close with nothing in flight is normal, not a poison.
        // The connection is simply gone; the metric would be useless if every close
        // counted as an anomaly.
        let mut clean_close = ExchangeLedger::new();
        assert_eq!(clean_close.begin_request(), Ok(()));
        clean_close.request_body_written();
        assert_eq!(clean_close.response_head(ResponseFraming::Empty), Ok(()));
        assert_eq!(clean_close.response_complete(), Ok(()));
        clean_close.upstream_closed();
        assert_eq!(clean_close.purity(), Purity::Clean);
        assert!(clean_close.may_pool());

        let mut never_used = ExchangeLedger::new();
        never_used.upstream_closed();
        assert_eq!(never_used.purity(), Purity::Clean);
        assert!(never_used.may_pool());

        // Edge case 14: closed while a request is in flight poisons: the response to
        // that request will never arrive.
        let mut in_flight = ExchangeLedger::new();
        assert_eq!(in_flight.begin_request(), Ok(()));
        in_flight.upstream_closed();
        assert_eq!(
            in_flight.purity(),
            Purity::Poisoned(PoisonReason::ClosedInFlight)
        );
        assert!(!in_flight.may_pool());
    }

    // The three tests below (review finding 1 on PR 843) each drive a SECOND exchange
    // on a ledger that has already completed a first one, which is the exact
    // reuse-after-anomaly scenario this module exists to defend: every other test in
    // this file starts from a virgin `ExchangeLedger::new()`, where `begin_request`'s
    // resets of `request_body_complete`, `declared_body` and `received_body` (step 3
    // of the state machine) are already sitting at their reset values, so dropping any
    // one of those three resets left every prior test green. One test per reset, so a
    // dropped reset points at exactly the field that regressed.

    #[test]
    fn second_exchange_resets_request_body_complete() {
        // The concrete hole this pins: exchange 1 runs a clean GET and pools.
        // Exchange 2 is checked out and its POST body is still being written when
        // the origin emits its final response early (the 0.CL escape hatch). If
        // begin_request's reset of `request_body_complete` were dropped, exchange
        // 2's `response_head` would see it still `true` from exchange 1's finished
        // request body, return `Ok`, and hand a desynced connection back to the
        // pool.
        let mut ledger = ExchangeLedger::new();

        // Exchange 1 completes cleanly, leaving request_body_complete == true.
        assert_eq!(ledger.begin_request(), Ok(()));
        ledger.request_body_written();
        assert_eq!(ledger.response_head(ResponseFraming::Empty), Ok(()));
        assert_eq!(ledger.response_complete(), Ok(()));
        assert!(ledger.may_pool());

        // Exchange 2: begin_request must reset request_body_complete to false.
        // request_body_written is deliberately never called for exchange 2, so
        // this is exchange 2's request body still in flight when its response
        // head arrives.
        assert_eq!(ledger.begin_request(), Ok(()));
        assert_eq!(
            ledger.response_head(ResponseFraming::Empty),
            Err(Purity::Poisoned(PoisonReason::EarlyFinalResponse)),
            "a reused ledger must not inherit exchange 1's completed request body"
        );
        assert!(!ledger.may_pool());
    }

    #[test]
    fn second_exchange_resets_declared_body() {
        // Pins begin_request's reset of `declared_body` to `None`. `response_head`
        // always overwrites `declared_body` before a normal `response_body_bytes`
        // call sees it, so the only way to observe a dropped reset is to call
        // `response_body_bytes` for exchange 2 before exchange 2's own
        // `response_head`: the value it sees can then only be whatever
        // begin_request left there.
        let mut ledger = ExchangeLedger::new();

        // Exchange 1 declares a body of Some(3) and completes cleanly.
        assert_eq!(ledger.begin_request(), Ok(()));
        ledger.request_body_written();
        assert_eq!(
            ledger.response_head(ResponseFraming::Exact { len: 3 }),
            Ok(())
        );
        assert_eq!(ledger.response_body_bytes(3), Ok(()));
        assert_eq!(ledger.response_complete(), Ok(()));
        assert!(ledger.may_pool());

        // Exchange 2: begin_request must reset declared_body to None. 4 octets,
        // arriving before exchange 2's own response_head has declared a length,
        // must be accepted: there is nothing to check them against yet. If the
        // reset were dropped, declared_body would still be Some(3) from exchange
        // 1, and 4 > 3 would poison a connection whose exchange 2 has not even
        // received a response head.
        assert_eq!(ledger.begin_request(), Ok(()));
        assert_eq!(
            ledger.response_body_bytes(4),
            Ok(()),
            "a reused ledger must not inherit exchange 1's declared body length"
        );
    }

    #[test]
    fn second_exchange_resets_received_body() {
        // Pins begin_request's reset of `received_body` to 0. Both exchanges
        // declare the same length, so a stale, un-reset count from exchange 1
        // pushes exchange 2 over its own freshly declared length on exchange 2's
        // very first body chunk.
        let mut ledger = ExchangeLedger::new();

        assert_eq!(ledger.begin_request(), Ok(()));
        ledger.request_body_written();
        assert_eq!(
            ledger.response_head(ResponseFraming::Exact { len: 5 }),
            Ok(())
        );
        assert_eq!(ledger.response_body_bytes(5), Ok(()));
        assert_eq!(ledger.response_complete(), Ok(()));
        assert!(ledger.may_pool());

        assert_eq!(ledger.begin_request(), Ok(()));
        ledger.request_body_written();
        assert_eq!(
            ledger.response_head(ResponseFraming::Exact { len: 5 }),
            Ok(())
        );
        assert_eq!(
            ledger.response_body_bytes(5),
            Ok(()),
            "a reused ledger must not inherit exchange 1's received body count"
        );
        assert_eq!(ledger.response_complete(), Ok(()));
        assert!(ledger.may_pool());
        assert_eq!(ledger.requests_sent(), 2);
        assert_eq!(ledger.responses_received(), 2);
    }

    /// Drives a fresh ledger, through the public API only, to exactly `Poisoned(reason)`
    /// for each `reason`. Used by `poison_is_terminal_and_first_reason_wins` to check
    /// `may_pool()` exhaustively over `PoisonReason::ALL` without special-casing the
    /// private `poison` helper.
    fn poisoned_with(reason: PoisonReason) -> ExchangeLedger {
        let mut ledger = ExchangeLedger::new();
        match reason {
            PoisonReason::ResponseFramingRefused => {
                ledger.response_framing_refused(RejectReason::ContentLengthDuplicate);
            }
            PoisonReason::EarlyFinalResponse => {
                assert_eq!(ledger.begin_request(), Ok(()));
                let _: Result<(), Purity> = ledger.response_head(ResponseFraming::Empty);
            }
            PoisonReason::BodyLengthMismatch => {
                assert_eq!(ledger.begin_request(), Ok(()));
                ledger.request_body_written();
                assert_eq!(
                    ledger.response_head(ResponseFraming::Exact { len: 1 }),
                    Ok(())
                );
                let _: Result<(), Purity> = ledger.response_body_bytes(2);
            }
            PoisonReason::ExchangeCountMismatch => {
                assert_eq!(ledger.begin_request(), Ok(()));
                ledger.request_body_written();
                assert_eq!(ledger.response_head(ResponseFraming::Empty), Ok(()));
                assert_eq!(ledger.response_complete(), Ok(()));
                let _: Result<(), Purity> = ledger.response_complete();
            }
            PoisonReason::TrailingBytes => {
                ledger.socket_had_trailing_bytes();
            }
            PoisonReason::ClosedInFlight => {
                assert_eq!(ledger.begin_request(), Ok(()));
                ledger.upstream_closed();
            }
            PoisonReason::CloseDelimitedResponse => {
                assert_eq!(ledger.begin_request(), Ok(()));
                ledger.request_body_written();
                let _: Result<(), Purity> = ledger.response_head(ResponseFraming::UntilClose);
            }
            PoisonReason::ProtocolAnomaly => {
                assert_eq!(ledger.begin_request(), Ok(()));
                let _: Result<(), Purity> = ledger.begin_request();
            }
        }
        ledger
    }

    #[test]
    fn poison_is_terminal_and_first_reason_wins() {
        // Edge case 21 helper, declared first so it reads as a top-level fixture rather
        // than an item wedged between statements. A poison recorded through a &mut
        // borrow is visible to the owner: mutating through `&mut ExchangeLedger`
        // always mutates the caller's own value, regardless of whether the type is
        // `Copy`, since `Copy` only governs what happens at a MOVE (whether the
        // bits are duplicated or the original becomes unusable), and this helper
        // never moves its argument at all.
        //
        // A previous version of this comment claimed that if `ExchangeLedger` ever
        // became `Copy` and `anomaly` started operating on a temporary copy, "the
        // assertion at the end of this test is what would notice". That was wrong,
        // and review finding 2 on PR 843 caught it empirically: adding `Copy` to
        // the derive above leaves this test, and every other test in this file,
        // green, because `anomaly`'s signature is `&mut ExchangeLedger` either way
        // and a reference cannot silently turn into a by-value copy without the
        // call site changing. What `Copy` actually breaks is a forwarding loop
        // that takes `ExchangeLedger` BY VALUE (`fn relay(mut ledger:
        // ExchangeLedger, ..)`, see the type's own doc comment above): such code
        // compiles today only because the value is moved out of the caller, so
        // mutating the callee's copy is a compile-visible bug (the caller's ledger
        // is gone, so it cannot be read again by mistake); the moment the type is
        // `Copy`, the same code compiles AND silently mutates an implicit
        // duplicate while the caller's original, still readable, stays untouched.
        // No test that only ever takes `&mut ExchangeLedger` can observe that
        // failure mode, because it depends on a call site the ledger's own tests
        // do not contain. `exchange_ledger_is_not_copy`, below, is the actual
        // regression test for the `Copy` prohibition: it probes the trait itself
        // rather than trying to infer it from `&mut` behavior.
        fn anomaly(l: &mut ExchangeLedger) {
            assert_eq!(l.begin_request(), Ok(()));
            // request_body_written is never called: EarlyFinalResponse.
            let _: Result<(), Purity> = l.response_head(ResponseFraming::Empty);
        }

        // Edge case 15: a second, different anomaly does not change the reported
        // reason.
        let mut ledger = ExchangeLedger::new();
        assert_eq!(ledger.begin_request(), Ok(()));
        // request_body_written is never called: EarlyFinalResponse lands first.
        assert_eq!(
            ledger.response_head(ResponseFraming::Empty),
            Err(Purity::Poisoned(PoisonReason::EarlyFinalResponse))
        );
        ledger.socket_had_trailing_bytes();
        assert_eq!(
            ledger.purity(),
            Purity::Poisoned(PoisonReason::EarlyFinalResponse),
            "the first anomaly must stick even after a second, different one"
        );

        // Edge case 16: any method on an already-poisoned ledger returns Err with the
        // original purity and changes nothing.
        let before = ledger.purity();
        assert_eq!(ledger.begin_request(), Err(before));
        assert_eq!(ledger.purity(), before);
        assert_eq!(ledger.response_head(ResponseFraming::Empty), Err(before));
        assert_eq!(ledger.purity(), before);
        assert_eq!(ledger.response_body_bytes(1), Err(before));
        assert_eq!(ledger.purity(), before);
        assert_eq!(ledger.response_complete(), Err(before));
        assert_eq!(ledger.purity(), before);

        // Edge case 22: bytes arriving after response_complete are measured against
        // the finished exchange's declared length and received count, which are not
        // reset until the next begin_request, so they poison with BodyLengthMismatch:
        // the same family as TrailingBytes under a different name.
        let mut after_complete = ExchangeLedger::new();
        assert_eq!(after_complete.begin_request(), Ok(()));
        after_complete.request_body_written();
        assert_eq!(
            after_complete.response_head(ResponseFraming::Exact { len: 3 }),
            Ok(())
        );
        assert_eq!(after_complete.response_body_bytes(3), Ok(()));
        assert_eq!(after_complete.response_complete(), Ok(()));
        assert_eq!(
            after_complete.response_body_bytes(1),
            Err(Purity::Poisoned(PoisonReason::BodyLengthMismatch))
        );

        // may_pool() is false for every one of the eight PoisonReason variants,
        // each reached through the public API rather than a shortcut.
        for reason in PoisonReason::ALL {
            let poisoned = poisoned_with(reason);
            assert_eq!(poisoned.purity(), Purity::Poisoned(reason));
            assert!(
                !poisoned.may_pool(),
                "{reason:?} must make may_pool() false"
            );
        }

        // Edge case 21, continued: run the fixture above against a fresh ledger.
        let mut owner = ExchangeLedger::new();
        anomaly(&mut owner);
        assert!(!owner.may_pool());
        assert_eq!(
            owner.purity(),
            Purity::Poisoned(PoisonReason::EarlyFinalResponse)
        );
    }

    /// Whether `ExchangeLedger` implements `Copy`, checked at compile time via
    /// method resolution rather than at run time.
    ///
    /// Review finding 2 on PR 843: acceptance criterion 2 and the first `## Do NOT`
    /// entry both require that `ExchangeLedger` never derive `Copy`, but stable
    /// Rust has no negative trait bound, so there is no `where ExchangeLedger:
    /// !Copy` to write and no way to make `#[derive(Copy)]` on the struct itself
    /// fail to compile from inside this crate without a proc-macro dependency.
    ///
    /// This is the closest available substitute: the same specialization-by-method-
    /// priority idiom the `impls` crate uses internally (written out here rather
    /// than taken as a dependency). `Wrapper<T>` gets an INHERENT `is_copy()` from
    /// `impl<T: Copy> Wrapper<T>`, and a fallback trait-default `is_copy()` from
    /// `ViaClone`, blanket-implemented for every `Wrapper<T>`. Inherent methods
    /// always win over trait methods of the same name, unconditionally, so
    /// `Wrapper::<ExchangeLedger>::is_copy()` resolves to the inherent one when
    /// `ExchangeLedger: Copy` holds and falls back to the trait default otherwise.
    ///
    /// The type MUST be named directly at the call site, not threaded through an
    /// unconstrained generic function. An earlier version of this probe did exactly
    /// that (`fn is_copy<T>(value: T) -> bool`), and it was silently useless: Rust
    /// type-checks a generic function body once, generically, before any concrete
    /// type is known, so with no `T: Copy` bound in scope the compiler could never
    /// select the `T: Copy` impl for ANY `T` and the probe always returned `false`,
    /// Copy or not, with no error to reveal that it was checking nothing. Naming
    /// `ExchangeLedger` explicitly here (`Wrapper::<ExchangeLedger>::is_copy()`)
    /// forces resolution against the one, fully concrete type, which is what makes
    /// the bound decidable at all. This distinction was verified empirically in an
    /// isolated scratch crate before landing here, in both directions: the
    /// generic-function form returns `false` unconditionally regardless of `Copy`;
    /// this form returns `false` today and flips to `true` the moment `Copy` is
    /// added to the derive above.
    mod copy_probe {
        use std::marker::PhantomData;

        use super::ExchangeLedger;

        pub(super) struct Wrapper<T>(PhantomData<T>);

        pub(super) trait ViaClone {
            fn is_copy() -> bool {
                false
            }
        }
        impl<T> ViaClone for Wrapper<T> {}

        impl<T: Copy> Wrapper<T> {
            // Dead by design in the current, correct state: `ExchangeLedger` is
            // not `Copy`, so this inherent method is never the one selected and
            // rustc's dead-code lint sees that. It exists to become LIVE, and
            // this test to start failing, the moment `Copy` is added to the
            // derive above.
            #[allow(
                dead_code,
                reason = "dead only while ExchangeLedger correctly stays non-Copy; \
                          becomes the selected method, and this probe's test starts \
                          failing, the moment Copy is added to its derive"
            )]
            pub(super) fn is_copy() -> bool {
                true
            }
        }

        pub(super) type ExchangeLedgerWrapper = Wrapper<ExchangeLedger>;
    }

    #[test]
    fn exchange_ledger_is_not_copy() {
        // This is the actual regression test for acceptance criterion 2 and the
        // first `## Do NOT` entry. It replaces the reasoning the (now corrected)
        // comment on `anomaly` above used to rely on: a poison recorded through
        // `&mut ExchangeLedger` mutates the caller's own value whether or not the
        // type is `Copy`, so no test built only out of `&mut` calls can tell the
        // difference. This test asks the type system the question directly instead.
        //
        // Proven to catch the regression it exists for: adding `Copy` to
        // `ExchangeLedger`'s derive list flips this to `true`, failing the
        // assertion below, while every other test in this file (including
        // `poison_is_terminal_and_first_reason_wins`'s `anomaly` helper) stays
        // green, exactly as both PR 843 reviewers measured.
        use copy_probe::ViaClone as _;

        assert!(
            !copy_probe::ExchangeLedgerWrapper::is_copy(),
            "ExchangeLedger must not be Copy: a poison recorded on an implicit \
             copy leaves the connection's own ledger Clean, and may_pool() \
             answers true for a connection that should be closed and is not"
        );
    }

    #[test]
    fn poison_reason_all_has_eight_unique_snake_case_labels() {
        // Review finding 3 on PR 843: `assert_eq!(PoisonReason::ALL.len(), 8)` is a
        // type-level tautology, since `ALL` is declared `[PoisonReason; 8]`, and it
        // cannot enforce that `ALL` covers every variant. The non-emptiness,
        // charset and uniqueness checks below are all invariant under permuting
        // labels among variants, so swapping two labels (a real hazard: whoever is
        // debugging a desyncing origin then chases the wrong condition) leaves them
        // all passing.
        //
        // The two checks added here are the same device
        // `proxyproto::mod::error_labels_are_unique` uses for `ProxyError`, which
        // its own comment records caught a real `PathEncodedDot`/`PathEncodedSlash`
        // label swap: an exhaustive match from variant to position, so `ALL`
        // omitting or duplicating a variant is a compile error rather than a
        // silent gap, and an independent oracle for the label itself, derived from
        // the variant's own `Debug` name rather than comparing `metric_label` to
        // itself.
        fn position_of(reason: PoisonReason) -> usize {
            match reason {
                PoisonReason::ResponseFramingRefused => 0,
                PoisonReason::EarlyFinalResponse => 1,
                PoisonReason::BodyLengthMismatch => 2,
                PoisonReason::ExchangeCountMismatch => 3,
                PoisonReason::TrailingBytes => 4,
                PoisonReason::ClosedInFlight => 5,
                PoisonReason::CloseDelimitedResponse => 6,
                PoisonReason::ProtocolAnomaly => 7,
            }
        }

        fn snake_case_of_debug_name(name: &str) -> String {
            let mut out = String::new();
            for (i, c) in name.chars().enumerate() {
                if c.is_ascii_uppercase() {
                    if i != 0 {
                        out.push('_');
                    }
                    out.push(c.to_ascii_lowercase());
                } else {
                    out.push(c);
                }
            }
            out
        }

        assert_eq!(PoisonReason::ALL.len(), 8);

        let positions: Vec<usize> = PoisonReason::ALL.iter().copied().map(position_of).collect();
        assert_eq!(
            positions,
            (0..8).collect::<Vec<usize>>(),
            "PoisonReason::ALL must list every variant exactly once"
        );

        for reason in PoisonReason::ALL {
            let want = snake_case_of_debug_name(&format!("{reason:?}"));
            assert_eq!(
                reason.metric_label(),
                want,
                "{reason:?}'s metric label diverges from its own Debug name"
            );
        }

        let mut labels: Vec<&'static str> =
            PoisonReason::ALL.iter().map(|r| r.metric_label()).collect();
        for label in &labels {
            assert!(!label.is_empty(), "metric label must not be empty");
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{label} is not snake_case"
            );
        }
        let before = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), before, "metric labels must be unique");
    }

    proptest::proptest! {
        #[test]
        fn prop_counters_never_diverge_silently(
            ops in proptest::collection::vec(op_strategy(), 0..=40),
        ) {
            let mut ledger = ExchangeLedger::new();
            for op in ops {
                match op {
                    Op::BeginRequest => {
                        let _: Result<(), Purity> = ledger.begin_request();
                    }
                    Op::BodyWritten => ledger.request_body_written(),
                    Op::ResponseHead(framing) => {
                        let _: Result<(), Purity> = ledger.response_head(framing);
                    }
                    Op::BodyBytes(n) => {
                        let _: Result<(), Purity> = ledger.response_body_bytes(n);
                    }
                    Op::ResponseComplete => {
                        let _: Result<(), Purity> = ledger.response_complete();
                    }
                    Op::TrailingBytes => ledger.socket_had_trailing_bytes(),
                    Op::Closed => ledger.upstream_closed(),
                }

                // The property: a Clean ledger with no exchange in flight always has
                // matching counters. There is no state in which it is Clean, idle, and
                // the counters differ; every path that could produce that instead
                // poisons in the same call that would otherwise have created it.
                if ledger.purity() == Purity::Clean && !ledger.in_flight {
                    prop_assert_eq!(ledger.responses_received(), ledger.requests_sent());
                }
            }
        }
    }

    /// One step of the sequence `prop_counters_never_diverge_silently` fuzzes.
    #[derive(Clone, Debug)]
    enum Op {
        BeginRequest,
        BodyWritten,
        ResponseHead(ResponseFraming),
        BodyBytes(u64),
        ResponseComplete,
        TrailingBytes,
        Closed,
    }

    fn framing_strategy() -> impl Strategy<Value = ResponseFraming> {
        prop_oneof![
            Just(ResponseFraming::Empty),
            (1_u64..=64).prop_map(|len| ResponseFraming::Exact { len }),
            Just(ResponseFraming::Streamed),
            Just(ResponseFraming::UntilClose),
        ]
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            Just(Op::BeginRequest),
            Just(Op::BodyWritten),
            framing_strategy().prop_map(Op::ResponseHead),
            (0_u64..=64).prop_map(Op::BodyBytes),
            Just(Op::ResponseComplete),
            Just(Op::TrailingBytes),
            Just(Op::Closed),
        ]
    }
}
