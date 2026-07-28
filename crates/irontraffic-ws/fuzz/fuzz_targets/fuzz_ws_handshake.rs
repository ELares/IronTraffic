// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz target for `irontraffic_ws::handshake::{UpgradeRequest::parse, UpgradeResponse::verify}`.
//!
//! Input domain: `data`'s first byte selects a split point; the bytes before it drive
//! the REQUEST side (parsed as a full HTTP/1.1 head with [`H1Parser`], exactly the
//! pipeline `crates/irontraffic-ws/tests/handshake.rs`'s own `upgrade()` helper uses,
//! so `UpgradeTokens` is built from evidence that provably still exists), and the
//! bytes after it drive the RESPONSE side (an arbitrary [`FieldSection`] built
//! directly with [`FieldSectionBuilder`], verified against a FIXED, always-valid
//! `UpgradeRequest`: `UpgradeResponse::verify`'s `req` argument is a value only a real
//! upgrade parse can produce, and fuzzing that argument itself would mean fuzzing the
//! request side twice rather than exercising `verify`'s own logic).
//!
//! Contract, per the module's own issue: no panic, no allocation (established
//! statically, exactly as `crates/irontraffic-ws/tests/handshake.rs`'s
//! `no_allocation_in_the_handshake` does: `handshake.rs`'s own production source
//! contains none of the allocating-call vocabulary, and the volume half is what this
//! target's run count provides), and every error's `status(side)` is 400 or 426 on
//! [`HandshakeSide::Request`] and always exactly 502 on [`HandshakeSide::Response`].
//!
//! Coverage is REPORTED, not assumed: `REACHED`/`REQUEST_PARSED`/`REQUEST_CANONICALIZED`
//! and the response-side counters below are printed periodically to stderr, the same
//! technique `fuzz_h1_roundtrip.rs` uses, so a `cargo fuzz run` session gives direct
//! evidence of what fraction of the corpus reaches past the first parse into the
//! handshake logic this target exists to exercise, rather than being rejected as not
//! a request (or not a well-formed field) at the first hurdle.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::BytesMut;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::framing::OtherCodings;
use irontraffic_http::h1::H1Parser;
use irontraffic_http::h1::canonicalize::{H1Context, canonicalize_request};
use irontraffic_http::known::KnownHeader;
use irontraffic_http::path::PathPolicy;
use irontraffic_http::peer::TrustPolicy;
use irontraffic_http::scalar::ParseStatus;
use irontraffic_http::section::{FieldSection, FieldSectionBuilder};
use irontraffic_http::strip::connection_has_token;
use irontraffic_http::{Limits, Scheme};
use irontraffic_ws::{HandshakeSide, UpgradeRequest, UpgradeResponse, UpgradeTokens};
use libfuzzer_sys::fuzz_target;

static REACHED: AtomicU64 = AtomicU64::new(0);
static REQUEST_PARSED: AtomicU64 = AtomicU64::new(0);
static REQUEST_CANONICALIZED: AtomicU64 = AtomicU64::new(0);
static REQUEST_PARSE_CALLED: AtomicU64 = AtomicU64::new(0);
static REQUEST_IS_UPGRADE: AtomicU64 = AtomicU64::new(0);
static RESPONSE_VERIFY_CALLED: AtomicU64 = AtomicU64::new(0);
static RESPONSE_ACCEPTED: AtomicU64 = AtomicU64::new(0);

fn report(n: u64) {
    if n.is_multiple_of(200_000) {
        let parsed = REQUEST_PARSED.load(Ordering::Relaxed);
        let canon = REQUEST_CANONICALIZED.load(Ordering::Relaxed);
        let req_parse_called = REQUEST_PARSE_CALLED.load(Ordering::Relaxed);
        let req_is_upgrade = REQUEST_IS_UPGRADE.load(Ordering::Relaxed);
        let resp_called = RESPONSE_VERIFY_CALLED.load(Ordering::Relaxed);
        let resp_accepted = RESPONSE_ACCEPTED.load(Ordering::Relaxed);
        eprintln!(
            "fuzz_ws_handshake: {n} reached, {parsed} request heads parsed ({:.1}%), \
             {canon} canonicalized ({:.1}%), UpgradeRequest::parse called {req_parse_called} \
             times, returned Some (a real upgrade) {req_is_upgrade} times ({:.1}%); \
             UpgradeResponse::verify called {resp_called} times, accepted {resp_accepted} \
             times ({:.1}%)",
            100.0 * parsed as f64 / n as f64,
            100.0 * canon as f64 / n as f64,
            100.0 * req_is_upgrade as f64 / req_parse_called.max(1) as f64,
            100.0 * resp_accepted as f64 / resp_called.max(1) as f64,
        );
    }
}

const TRUST: TrustPolicy = TrustPolicy::None;

fn ctx() -> H1Context<'static> {
    H1Context {
        limits: Limits::DEFAULT.clamped(),
        path_policy: PathPolicy::DEFAULT,
        codings: OtherCodings::Reject,
        underscores: UnderscorePolicy::Reject,
        scheme: Scheme::Http,
        socket_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
        proxy_proto: None,
        trust: &TRUST,
        default_authority: None,
        forward_proxy: false,
        will_buffer_body: false,
    }
}

/// A fixed, hand-verified valid upgrade request, canonicalized once per run through
/// the real pipeline (not from fuzz bytes: `UpgradeResponse::verify`'s `req` argument
/// must be a value only a real upgrade parse can build, and this target's job is to
/// fuzz `verify`'s OWN logic, not to also fuzz-generate the value it is checked
/// against).
const BASELINE_HEAD: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

/// Builds `UpgradeTokens` from `section`, reading `Upgrade`/`Connection` the same way
/// on both the request and the response side: the caller MUST have built `section`
/// from evidence read BEFORE any hop-by-hop strip, exactly as the module's own doc
/// comment requires.
fn tokens_from(section: &FieldSection) -> UpgradeTokens<'_> {
    let duplicate_upgrade = section.get_unique_known(KnownHeader::Upgrade).is_err();
    let upgrade = section.get_unique_known(KnownHeader::Upgrade).ok().flatten();
    let connection_has_upgrade = connection_has_token(section, b"upgrade");
    UpgradeTokens {
        upgrade,
        connection_has_upgrade,
        duplicate_upgrade,
    }
}

fn baseline_request() -> Option<UpgradeRequest> {
    let limits = Limits::DEFAULT.clamped();
    let parser = H1Parser::new(&limits, UnderscorePolicy::Reject);
    let ParseStatus::Complete { value: head, .. } = parser.parse_request_head(BASELINE_HEAD).ok()?
    else {
        return None;
    };

    let mut pre_arena = BytesMut::new();
    let mut pre_builder = FieldSectionBuilder::new(&pre_arena, &limits);
    for i in 0..head.field_count() {
        let name = head.field_name(i)?;
        let value = head.field_value(i)?;
        pre_builder
            .push_normalized(&mut pre_arena, name, UnderscorePolicy::Reject, value, head.version)
            .ok()?;
    }
    let pre = pre_builder.finish(&mut pre_arena);
    let tokens = tokens_from(&pre);

    let mut arena = BytesMut::new();
    let (req, _, _) = canonicalize_request(&head, &ctx(), &mut arena).ok()?;
    UpgradeRequest::parse(&req, tokens).ok().flatten()
}

/// Builds a [`FieldSection`] directly out of `data`, splitting on NUL (a byte that
/// can never appear in a well-formed field name or an already OWS-trimmed value, so
/// it is a safe, simple delimiter) into up to 16 `(name, value)` candidate pairs,
/// each capped at 256 bytes. [`FieldSectionBuilder::push`] rejects anything that is
/// not itself a well-formed name/value pair, so a rejected pair simply contributes
/// nothing to the section rather than aborting the run: this is what lets the target
/// explore the full range from an empty section (every field missing) to one dense
/// with attacker-controlled `Sec-WebSocket-*` values.
fn build_fuzzed_section(data: &[u8]) -> FieldSection {
    let limits = Limits::DEFAULT.clamped();
    let mut arena = BytesMut::new();
    let mut builder = FieldSectionBuilder::new(&arena, &limits);
    let parts: Vec<&[u8]> = data.split(|&b| b == 0).take(32).collect();
    let mut i: usize = 0;
    while i.saturating_add(1) < parts.len() {
        let Some(name) = parts.get(i) else { break };
        let Some(value) = parts.get(i.saturating_add(1)) else {
            break;
        };
        let name = name.get(..name.len().min(256)).unwrap_or(&[]);
        let value = value.get(..value.len().min(256)).unwrap_or(&[]);
        let _ = builder.push(&mut arena, name, value);
        i = i.saturating_add(2);
    }
    builder.finish(&mut arena)
}

fuzz_target!(|data: &[u8]| {
    // `Limits::DEFAULT` already bounds every individual piece; this just keeps
    // libFuzzer from spending cycles on pathologically huge inputs whose rejection
    // reason is uninteresting well before reaching any logic this target exists to
    // exercise.
    if data.len() > 65536 {
        return;
    }

    let n = REACHED.fetch_add(1, Ordering::Relaxed) + 1;
    report(n);

    let Some((&split_byte, rest)) = data.split_first() else {
        return;
    };
    let split = if rest.is_empty() {
        0
    } else {
        usize::from(split_byte) % rest.len()
    };
    let Some((request_bytes, response_bytes)) = (|| {
        let a = rest.get(..split)?;
        let b = rest.get(split..)?;
        Some((a, b))
    })() else {
        return;
    };

    // --- Request side: the real H1 parse pipeline. ---
    let limits = Limits::DEFAULT.clamped();
    let parser = H1Parser::new(&limits, UnderscorePolicy::Reject);
    if let Ok(ParseStatus::Complete { value: head, .. }) = parser.parse_request_head(request_bytes)
    {
        REQUEST_PARSED.fetch_add(1, Ordering::Relaxed);

        let mut pre_arena = BytesMut::new();
        let mut pre_builder = FieldSectionBuilder::new(&pre_arena, &limits);
        let mut fields_ok = true;
        for i in 0..head.field_count() {
            let (Some(name), Some(value)) = (head.field_name(i), head.field_value(i)) else {
                fields_ok = false;
                break;
            };
            if pre_builder
                .push_normalized(&mut pre_arena, name, UnderscorePolicy::Reject, value, head.version)
                .is_err()
            {
                fields_ok = false;
                break;
            }
        }

        if fields_ok {
            let pre = pre_builder.finish(&mut pre_arena);
            let tokens = tokens_from(&pre);

            let mut arena = BytesMut::new();
            if let Ok((req, _, _)) = canonicalize_request(&head, &ctx(), &mut arena) {
                REQUEST_CANONICALIZED.fetch_add(1, Ordering::Relaxed);
                REQUEST_PARSE_CALLED.fetch_add(1, Ordering::Relaxed);

                match UpgradeRequest::parse(&req, tokens) {
                    Ok(Some(_)) => {
                        REQUEST_IS_UPGRADE.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        let status = e.status(HandshakeSide::Request);
                        assert!(
                            status == 400 || status == 426,
                            "UpgradeRequest::parse error {e:?} answered status {status}, \
                             expected 400 or 426 on HandshakeSide::Request"
                        );
                    }
                }
            }
        }
    }

    // --- Response side: an arbitrary FieldSection against a FIXED baseline request. ---
    // Computed once and cached: `BASELINE_HEAD` never changes across the run, so
    // re-parsing it on every single one of millions of iterations would be pure
    // waste. `UpgradeRequest` is `Clone` and holds only fixed-size inline arrays, so
    // the clone below is cheap and allocation-free.
    static BASELINE: std::sync::OnceLock<Option<UpgradeRequest>> = std::sync::OnceLock::new();
    if let Some(baseline) = BASELINE.get_or_init(baseline_request).clone() {
        let Some((&status_byte, response_rest)) = response_bytes.split_first() else {
            return;
        };
        // 101 is folded in at a much higher weight than any other status: the
        // interesting behaviour (accept/extension/subprotocol checks) is all GATED
        // behind `status == 101`, so a uniform random byte would spend the vast
        // majority of runs on the (already fully covered by
        // `response_wrong_status`) early `NotSwitchingProtocols` return.
        let status: u16 = if status_byte < 250 { 101 } else { u16::from(status_byte) };

        let headers = build_fuzzed_section(response_rest);
        let tokens = tokens_from(&headers);

        RESPONSE_VERIFY_CALLED.fetch_add(1, Ordering::Relaxed);
        match UpgradeResponse::verify(&baseline, status, &headers, tokens) {
            Ok(_) => {
                RESPONSE_ACCEPTED.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                assert_eq!(
                    e.status(HandshakeSide::Response),
                    502,
                    "UpgradeResponse::verify error {e:?} answered a status other than 502 \
                     on HandshakeSide::Response"
                );
            }
        }
    }
});
