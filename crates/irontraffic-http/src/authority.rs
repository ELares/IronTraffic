// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`Authority`], the validated ASCII-only host-and-optional-port value, and
//! [`reconcile_authority`], which refuses a request whose `Host` field
//! disagrees with its `:authority` pseudo-header after scheme-based
//! normalization.
//!
//! The authority decides which virtual host, which route table and which TLS
//! policy a request belongs to, and it is attacker chosen. Two rules make it
//! safe, both load bearing enough to restate here rather than only in
//! `docs/THREAT-MODEL.md`:
//!
//! **No internationalized-domain-name mapping, ever, and no Unicode text
//! normalization of any kind.** Any byte at or above `0x80` in `Host` or
//! `:authority` is refused. This module never maps a Unicode hostname label
//! to its ASCII form, under any of the several competing standards for doing
//! so, and never applies any Unicode canonical or compatibility
//! (de)composition to an authority. The reason is concrete: the several
//! competing standards for that mapping disagree with each other on which
//! ASCII form a given label produces, sometimes by more than a handful of
//! characters. A proxy that maps
//! `\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}` to
//! `xn--e1afmkfd.xn--p1ai` sitting in front of an origin that does not map,
//! or maps with a different table version, is a virtual-host confusion
//! primitive: two different requests reach two different vhosts depending on
//! which library version each side compiled against. Clients send the
//! already-mapped ASCII form. We route on that ASCII form:
//! `xn--e1afmkfd.xn--p1ai` is accepted because it is ASCII, and the Cyrillic
//! form above is refused because it is not. This module never decodes a
//! byte to `char` or `str` for comparison purposes, so no code path exists
//! through which any such mapping or text normalization could run; the rule
//! is enforced by what the parser is structurally unable to do, not only by
//! what it happens not to call.
//!
//! **One authority per request.** RFC 9113 Section 8.3.1 says a server
//! *SHOULD* treat a request as malformed if `Host` differs from
//! `:authority`. [`reconcile_authority`] makes it a MUST: when both are
//! present and disagree after scheme-based normalization (RFC 3986 Section
//! 6.2.3: drop the scheme's default port), it refuses with
//! `RejectReason::AuthorityMismatch` rather than picking one.
//!
//! **What this type canonicalizes, and what it does not.** [`Authority`]
//! canonicalizes BYTES, not ADDRESSES. `[::1]` and `[0:0:0:0:0:0:0:1]` are
//! the same address and two different `Authority` values. `127.0.0.1`,
//! `127.1`, `0177.0.0.1` and `2130706433` all resolve to loopback and are
//! four different `Authority` values, and three of them are `reg-name`s to
//! this parser, not IPv4 literals. Any policy that means to match an IP
//! address MUST parse the host into an `IpAddr` and compare addresses;
//! comparing [`Authority::host`] bytes against `b"127.0.0.1"` is a bypass
//! waiting to be written.

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::RejectReason;
use crate::limits::ClampedLimits;
use crate::scalar::{Scheme, WireVersion};

/// True for bytes legal in a `reg-name`, an IPv4 literal, or an IPv6 literal
/// inside brackets, as `HOST_OK[b]`.
///
/// `:`, `[` and `]` are true here because they are structurally significant
/// and are handled by [`Authority::parse_into`]'s own algorithm, not by this
/// table: a byte class alone cannot express "at most one unbracketed `:`" or
/// "brackets must be balanced and non-empty".
static HOST_OK: [bool; 256] = build_host_ok();

/// The 81 bytes legal in an authority, as a literal, so the table builder and
/// the test that counts entries cannot drift apart.
const HOST_BYTES: [u8; 81] =
    *b"!$%&'()*+,-.0123456789:;=ABCDEFGHIJKLMNOPQRSTUVWXYZ[]_abcdefghijklmnopqrstuvwxyz~";
const _: () = assert!(HOST_BYTES.len() == 81);

// The `#[allow]` below is the standing exception defined in
// `field-validation-tables` (#23): a `const fn` cannot call `<[T]>::get`, and
// a `u8` index into a 256-element array is total by the type. Scoped to
// exactly this construct (a `[T; 256]` table indexed by a `u8`, its builder,
// and its accessor) and to no other site, matching `field.rs`'s own
// `build_name_ok` and `build_value_ok` exactly.
#[allow(
    clippy::indexing_slicing,
    reason = "total by construction, u8 index into a [_; 256]"
)]
const fn build_host_ok() -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0usize;
    while i < HOST_BYTES.len() {
        t[HOST_BYTES[i] as usize] = true;
        // Not `i += 1`: this crate carries `#![deny(clippy::arithmetic_side_effects)]`
        // because it parses attacker-controlled bytes. `i` is a bounded loop
        // counter (i < HOST_BYTES.len() == 81), so this never actually
        // saturates; the method form is what keeps the lint from firing on an
        // ordinary `+=`, matching `field.rs`'s identical loops.
        i = i.saturating_add(1);
    }
    t
}

/// True when `b` may appear in an authority.
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "total by construction, u8 index into a [_; 256]"
)]
pub const fn host_byte_ok(b: u8) -> bool {
    HOST_OK[b as usize]
}

/// A validated authority: an ASCII host with an optional port.
///
/// The host is stored ASCII-lowercased. An IPv6 literal keeps its brackets,
/// so [`Authority::write_to`] round-trips to a legal `Host` value. Never the
/// result of a Unicode-to-ASCII hostname mapping: a byte at or above `0x80`
/// is refused at parse time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Authority {
    buf: Bytes,
    host_len: u16,
    port: Option<u16>,
}

/// Renders `port`'s decimal digits least-significant-digit first into a
/// fixed 5-byte buffer, returning the buffer and how many of its leading
/// slots hold a digit (1 to 5). Shared by [`Authority::write_to`] and
/// [`Authority::written_len`] so the two can never disagree about how many
/// bytes a port renders to, which is exactly the property
/// `write_to_round_trips` pins.
///
/// Uses `checked_rem`/`checked_div` rather than `%`/`/`, because this crate
/// denies `clippy::arithmetic_side_effects` on the bare operator forms; the
/// `unwrap_or` fallbacks are never reached (`10` is never zero) and exist so
/// this stays free of any escape-hatch `#[allow]`.
fn port_digits(port: u16) -> ([u8; 5], usize) {
    let mut digits = [0_u8; 5];
    let mut count = 0_usize;
    let mut remaining = port;
    loop {
        let digit = remaining.checked_rem(10).unwrap_or(0);
        let digit_byte = u8::try_from(digit).unwrap_or(0);
        if let Some(slot) = digits.get_mut(count) {
            *slot = b'0'.saturating_add(digit_byte);
        }
        count = count.saturating_add(1);
        remaining = remaining.checked_div(10).unwrap_or(0);
        if remaining == 0 {
            break;
        }
    }
    (digits, count)
}

impl Authority {
    /// Parses and validates an authority, writing its canonical host bytes
    /// into `out`.
    ///
    /// The host is ASCII-lowercased. A port equal to the scheme's default is
    /// normalized away (RFC 3986 Section 6.2.3). No hostname mapping and no
    /// Unicode text processing of any kind is performed, and a byte at or
    /// above `0x80` is refused.
    ///
    /// `out` receives exactly the lowercased host bytes at its current
    /// length; a caller building several values from one buffer must call
    /// `out.reserve(n)` between them, the same contract
    /// `NormalizedPath::parse_into` uses elsewhere in this crate's design.
    ///
    /// # Errors
    /// `AuthorityEmpty`, `AuthorityTooLong`, `AuthorityNonAscii`,
    /// `AuthorityInvalidByte`, `AuthorityPortInvalid`.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear ten-step parse over one input, not a dispatcher; splitting it would scatter the step ordering the design and its edge-case table both depend on across several functions with no clearer seam"
    )]
    pub fn parse_into(
        raw: &[u8],
        scheme: Scheme,
        limits: &ClampedLimits,
        out: &mut BytesMut,
    ) -> Result<Authority, RejectReason> {
        // Step 1.
        if raw.is_empty() {
            return Err(RejectReason::AuthorityEmpty);
        }
        // Step 2. Structural cap first and unconditionally, before the
        // per-byte scan below, so a hostile over-length authority rejects in
        // O(1) rather than paying for the scan first.
        if raw.len() > limits.max_authority_bytes as usize {
            return Err(RejectReason::AuthorityTooLong);
        }
        // Step 3. Non-ASCII is checked before the table, so a U-label gets
        // the specific `AuthorityNonAscii` reason rather than the generic
        // `AuthorityInvalidByte`.
        for &b in raw {
            if b >= 0x80 {
                return Err(RejectReason::AuthorityNonAscii);
            }
            if !host_byte_ok(b) {
                return Err(RejectReason::AuthorityInvalidByte);
            }
        }

        // Step 4: split host and port.
        let bracketed = raw.first() == Some(&b'[');
        let (host_span, port_text): (&[u8], Option<&[u8]>) = if bracketed {
            let close = raw
                .iter()
                .position(|&b| b == b']')
                .ok_or(RejectReason::AuthorityInvalidByte)?;
            let host_span = raw
                .get(..=close)
                .ok_or(RejectReason::AuthorityInvalidByte)?;
            let after = raw
                .get(close.saturating_add(1)..)
                .ok_or(RejectReason::AuthorityInvalidByte)?;
            if after.is_empty() {
                (host_span, None)
            } else {
                if after.first() != Some(&b':') {
                    return Err(RejectReason::AuthorityInvalidByte);
                }
                let port_text = after.get(1..).ok_or(RejectReason::AuthorityInvalidByte)?;
                (host_span, Some(port_text))
            }
        } else {
            match raw.iter().rposition(|&b| b == b':') {
                Some(idx) => {
                    let host_span = raw.get(..idx).ok_or(RejectReason::AuthorityInvalidByte)?;
                    // A `reg-name` and an IPv4 literal contain no `:`; a bare
                    // (unbracketed) IPv6 literal is not a legal authority. A
                    // second colon in the host portion, found by splitting on
                    // the LAST colon, is `a:8080:9090`'s shape.
                    if host_span.contains(&b':') {
                        return Err(RejectReason::AuthorityInvalidByte);
                    }
                    let port_text = raw
                        .get(idx.saturating_add(1)..)
                        .ok_or(RejectReason::AuthorityInvalidByte)?;
                    (host_span, Some(port_text))
                }
                None => (raw, None),
            }
        };

        // Step 5: validate the host.
        if host_span.is_empty() {
            return Err(RejectReason::AuthorityEmpty);
        }
        if bracketed {
            // `host_span` is `raw[..=close]`, so it starts with `[` and ends
            // with `]` by construction; `len() >= 2` always holds here.
            let inner = host_span
                .get(1..host_span.len().saturating_sub(1))
                .ok_or(RejectReason::AuthorityInvalidByte)?;
            // Non-empty and at-least-one-colon are what refuse `[]` and
            // `[1.2.3.4]`, neither of which is a legal IP-literal: a bare
            // "every byte is in this set" test over `inner` would accept
            // both vacuously.
            if inner.is_empty() || !inner.contains(&b':') {
                return Err(RejectReason::AuthorityInvalidByte);
            }
            for &b in inner {
                if !(b.is_ascii_hexdigit() || b == b':' || b == b'.') {
                    return Err(RejectReason::AuthorityInvalidByte);
                }
            }
        } else {
            // A `%` in a `reg-name` is legal per RFC 3986 and is refused
            // anyway, including the well-formed `%XX` case, because a
            // percent-encoded host is another two-interpretations problem.
            // `[` and `]` outside the bracket form belong to no legal host.
            if host_span.contains(&b'[') || host_span.contains(&b']') || host_span.contains(&b'%') {
                return Err(RejectReason::AuthorityInvalidByte);
            }
            // A trailing `.` (the DNS root label) is accepted and preserved;
            // a lone `.` is not a host.
            if host_span == b"." {
                return Err(RejectReason::AuthorityInvalidByte);
            }
        }

        // Step 6: parse the port.
        let parsed_port: Option<u16> = match port_text {
            Some(text) => {
                if text.is_empty() || text.len() > 5 || !text.iter().all(u8::is_ascii_digit) {
                    return Err(RejectReason::AuthorityPortInvalid);
                }
                let text_str =
                    core::str::from_utf8(text).map_err(|_| RejectReason::AuthorityPortInvalid)?;
                let value: u32 = text_str
                    .parse()
                    .map_err(|_| RejectReason::AuthorityPortInvalid)?;
                if value == 0 || value > u32::from(u16::MAX) {
                    return Err(RejectReason::AuthorityPortInvalid);
                }
                let value_u16 =
                    u16::try_from(value).map_err(|_| RejectReason::AuthorityPortInvalid)?;
                Some(value_u16)
            }
            None => None,
        };

        // Step 7: scheme-based normalization (RFC 3986 Section 6.2.3).
        let port = if parsed_port == Some(scheme.default_port()) {
            None
        } else {
            parsed_port
        };

        // Step 8: write the canonical (lowercased) host bytes and take the
        // `Bytes` view the same way `NormalizedPath::parse_into` does.
        let base = out.len();
        for &b in host_span {
            out.put_u8(b.to_ascii_lowercase());
        }
        let buf = out.split_off(base).freeze();
        // `host_len` fits `u16` because step 2 already refused anything
        // longer than `limits.max_authority_bytes`, whose hard ceiling
        // (`Limits::CEILING.max_authority_bytes`) is well under `u16::MAX`;
        // `try_from` is used rather than an `as` cast regardless, so a
        // future ceiling change fails closed with `AuthorityTooLong` instead
        // of silently truncating.
        let host_len = u16::try_from(buf.len()).map_err(|_| RejectReason::AuthorityTooLong)?;

        Ok(Authority {
            buf,
            host_len,
            port,
        })
    }

    /// The canonical host: lowercase ASCII, brackets retained for an IPv6
    /// literal.
    #[must_use]
    pub fn host(&self) -> &[u8] {
        self.buf.get(..usize::from(self.host_len)).unwrap_or(&[])
    }

    /// The port, or `None` when absent or equal to the scheme default.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// The port, resolving `None` to the scheme default.
    #[must_use]
    pub const fn effective_port(&self, scheme: Scheme) -> u16 {
        match self.port {
            Some(p) => p,
            None => scheme.default_port(),
        }
    }

    /// True when the host is a bracketed IPv6 literal.
    #[must_use]
    pub fn is_ipv6_literal(&self) -> bool {
        self.host().first() == Some(&b'[')
    }

    /// Writes the canonical `host` or `host:port` form into `out` and
    /// returns the byte count written. This is the value used for the
    /// `Host` field generated on egress.
    pub fn write_to(&self, out: &mut BytesMut) -> usize {
        let host = self.host();
        out.extend_from_slice(host);
        let mut written = host.len();
        if let Some(p) = self.port {
            out.put_u8(b':');
            written = written.saturating_add(1);
            let (digits, count) = port_digits(p);
            for i in (0..count).rev() {
                if let Some(&b) = digits.get(i) {
                    out.put_u8(b);
                }
            }
            written = written.saturating_add(count);
        }
        written
    }

    /// Number of bytes [`Authority::write_to`] will write.
    #[must_use]
    pub fn written_len(&self) -> usize {
        let mut n = self.host().len();
        if let Some(p) = self.port {
            let (_, count) = port_digits(p);
            n = n.saturating_add(1).saturating_add(count);
        }
        n
    }
}

/// Produces the single [`Authority`] for a request from whichever of `Host`
/// and `:authority` are present, refusing a mismatch.
///
/// RFC 9113 Section 8.3.1 makes this a SHOULD; IronTraffic makes it a MUST.
/// On HTTP/2 and HTTP/3 the pseudo-header wins, so the `Host` field
/// synthesized when downgrading to HTTP/1 replaces whatever the client sent,
/// matching RFC 9113 Section 8.3.1's own wording: "This replaces any
/// existing Host field to avoid potential vulnerabilities in HTTP routing."
///
/// The "zero or more than one `Host` field line" rule lives in the caller
/// (`h1-head-to-canonical-request`, #35), because it is a property of the
/// field section, not of the authority value.
///
/// # Errors
/// `HostMissing`, `PseudoHeaderMissing`, `AuthorityMismatch`, plus every
/// error [`Authority::parse_into`] can return.
pub fn reconcile_authority(
    host_field: Option<&[u8]>,
    pseudo_authority: Option<&[u8]>,
    scheme: Scheme,
    version: WireVersion,
    limits: &ClampedLimits,
    out: &mut BytesMut,
) -> Result<Authority, RejectReason> {
    match version {
        WireVersion::Http10 | WireVersion::Http11 => {
            // `:authority` is always `None` on HTTP/1; a caller that hands
            // one in has a bug, not a client with a mismatched authority, so
            // this is `AuthorityMismatch` rather than being silently
            // ignored.
            if pseudo_authority.is_some() {
                return Err(RejectReason::AuthorityMismatch);
            }
            // On HTTP/1.0 a missing `Host` is permitted by the wire format;
            // the caller substitutes the listener's default authority as
            // `host_field` in that case. This function does not invent one:
            // `host_field` being `None` here, on either version, is
            // `HostMissing`.
            let host = host_field.ok_or(RejectReason::HostMissing)?;
            Authority::parse_into(host, scheme, limits, out)
        }
        WireVersion::H2 | WireVersion::H3 => match (host_field, pseudo_authority) {
            (None, None) => Err(RejectReason::PseudoHeaderMissing),
            (Some(host), None) => Authority::parse_into(host, scheme, limits, out),
            (None, Some(authority)) => Authority::parse_into(authority, scheme, limits, out),
            (Some(host), Some(authority)) => {
                let from_host = Authority::parse_into(host, scheme, limits, out)?;
                let from_pseudo = Authority::parse_into(authority, scheme, limits, out)?;
                if from_host != from_pseudo {
                    return Err(RejectReason::AuthorityMismatch);
                }
                // The pseudo-header wins when both parse and agree: this is
                // what makes the `Host` field synthesized on an H2/H3 to H1
                // downgrade correct.
                Ok(from_pseudo)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    /// The exact expectation of one `parse_into` call in [`corpus_table`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Expected {
        /// The canonical host bytes and the normalized port.
        Ok(&'static [u8], Option<u16>),
        /// The exact reject reason.
        Err(RejectReason),
    }

    fn parse(raw: &[u8], scheme: Scheme) -> Result<Authority, RejectReason> {
        let mut out = BytesMut::new();
        Authority::parse_into(raw, scheme, &Limits::DEFAULT.clamped(), &mut out)
    }

    #[test]
    fn authority_none_is_never_equal_to_authority_some() {
        // Not one of the ten named tests: a sanity check on `Expected`
        // itself before it is trusted below, and the PAIR the parent
        // instructions ask for: one input that must parse and one that must
        // not, so a mutation collapsing `Result` handling cannot pass both.
        assert_ne!(parse(b"a", Scheme::Http), parse(b"", Scheme::Http));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table of edge cases 1 through 29 the issue names by number, plus the \
                  closure that checks each row (inlined rather than a free function so the \
                  assertions stay in this test's own body for no-test-without-assertion); \
                  splitting the table would break the 1:1 mapping to that numbered list"
    )]
    #[test]
    fn corpus_table() {
        use RejectReason::{
            AuthorityEmpty, AuthorityInvalidByte, AuthorityNonAscii, AuthorityPortInvalid,
            AuthorityTooLong,
        };

        // A closure, not a free function: `scripts/invariant-lints.sh`'s
        // `no-test-without-assertion` rule scans a test function's OWN body
        // text for an assertion and cannot see through a call to a separate
        // top-level function that does the asserting (the same reason
        // `validate_allocates_nothing` above inlines its loops rather than
        // factoring them out). A closure defined inside this test's own body
        // keeps the assertions textually inside it.
        let assert_case = |raw: &[u8], scheme: Scheme, expected: &Expected| {
            let got = parse(raw, scheme);
            match (expected, got) {
                (Expected::Ok(host, port), Ok(authority)) => {
                    assert_eq!(authority.host(), *host, "host mismatch for {raw:?}");
                    assert_eq!(authority.port(), *port, "port mismatch for {raw:?}");
                }
                (Expected::Err(reason), Err(got_reason)) => {
                    assert_eq!(*reason, got_reason, "reject reason mismatch for {raw:?}");
                }
                (expected, got) => {
                    panic!("for {raw:?}: expected {expected:?}, got {got:?}");
                }
            }
        };

        let cases: &[(&[u8], Scheme, Expected)] = &[
            // 1
            (b"a", Scheme::Http, Expected::Ok(b"a", None)),
            // 2
            (b"", Scheme::Http, Expected::Err(AuthorityEmpty)),
            // 3
            (
                b"A.EXAMPLE.com",
                Scheme::Http,
                Expected::Ok(b"a.example.com", None),
            ),
            // 4
            (
                b"example.com.",
                Scheme::Http,
                Expected::Ok(b"example.com.", None),
            ),
            // 5
            (b".", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            // 6
            (b"a:80", Scheme::Http, Expected::Ok(b"a", None)),
            // 7
            (b"a:80", Scheme::Https, Expected::Ok(b"a", Some(80))),
            // 8
            (b"a:443", Scheme::Https, Expected::Ok(b"a", None)),
            // 9
            (b"a:8080", Scheme::Http, Expected::Ok(b"a", Some(8080))),
            // 10
            (b"a:0", Scheme::Http, Expected::Err(AuthorityPortInvalid)),
            // 11
            (
                b"a:99999",
                Scheme::Http,
                Expected::Err(AuthorityPortInvalid),
            ),
            // 12
            (b"a:65535", Scheme::Http, Expected::Ok(b"a", Some(65535))),
            (
                b"a:65536",
                Scheme::Http,
                Expected::Err(AuthorityPortInvalid),
            ),
            // 13
            (b"a:-1", Scheme::Http, Expected::Err(AuthorityPortInvalid)),
            // 14
            (b"a:", Scheme::Http, Expected::Err(AuthorityPortInvalid)),
            // 15
            (
                b"a:8080:9090",
                Scheme::Http,
                Expected::Err(AuthorityInvalidByte),
            ),
            // 16
            (b"a b", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            // 17
            (b"a\tb", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            (b"a\rb", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            (b"a\nb", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            (b"a\0b", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            // 18
            (b"a/b", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            (b"a@b", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            (b"a?b", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            (b"a#b", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            // 19
            (
                b"xn--e1afmkfd.xn--p1ai",
                Scheme::Http,
                Expected::Ok(b"xn--e1afmkfd.xn--p1ai", None),
            ),
            // 20
            (
                "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}".as_bytes(),
                Scheme::Http,
                Expected::Err(AuthorityNonAscii),
            ),
            // 21
            (b"[::1]", Scheme::Http, Expected::Ok(b"[::1]", None)),
            // 22
            (
                b"[::1]:8080",
                Scheme::Http,
                Expected::Ok(b"[::1]", Some(8080)),
            ),
            // 23
            (b"[::1", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            // 24
            (b"[::1]x", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            // 25
            (
                b"[::ffff:192.0.2.1]",
                Scheme::Http,
                Expected::Ok(b"[::ffff:192.0.2.1]", None),
            ),
            // 26
            (
                b"[zz::1]",
                Scheme::Http,
                Expected::Err(AuthorityInvalidByte),
            ),
            // 27
            (b"[]", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            // 28
            (b"a%2fb", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            // Not one of the 29 numbered cases: a non-bracketed host with a
            // STRAY `[` and no `]` or `%`, and one with a stray `]` and no
            // `[` or `%`, isolating each of the three OR'd conditions in the
            // non-bracket branch of step 5 from the other two. Both bytes
            // are legal in HOST_OK (structurally significant, handled here
            // rather than by the table), so only this check can refuse them.
            (b"a[b", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            (b"a]b", Scheme::Http, Expected::Err(AuthorityInvalidByte)),
            // 29: the 255/256 byte boundary is its own assertion below,
            // because it needs a generated input rather than a literal.
        ];

        for (raw, scheme, expected) in cases {
            assert_case(raw, *scheme, expected);
        }

        // 29: a 255-byte authority is accepted; 256 bytes is refused. Pins
        // the tradeoff (max_authority_bytes defaults to 255, shorter than
        // the longest legal DNS name) so it is visible rather than
        // accidental.
        let ok_255 = vec![b'a'; 255];
        assert_case(&ok_255, Scheme::Http, &Expected::Ok(&[b'a'; 255], None));
        let too_long_256 = vec![b'a'; 256];
        assert_case(
            &too_long_256,
            Scheme::Http,
            &Expected::Err(AuthorityTooLong),
        );
    }

    #[test]
    fn lowercased_and_idempotent() {
        let authority = parse(b"A.EXAMPLE.com", Scheme::Http).expect("well formed");
        assert_eq!(authority.host(), b"a.example.com");

        let mut out = BytesMut::new();
        let written = authority.write_to(&mut out);
        assert_eq!(written, out.len());
        let bytes = out.freeze();

        let mut reparse_buf = BytesMut::new();
        let reparsed = Authority::parse_into(
            &bytes,
            Scheme::Http,
            &Limits::DEFAULT.clamped(),
            &mut reparse_buf,
        )
        .expect("round trip must reparse");
        assert_eq!(reparsed, authority);

        // The distinguishing pair: a DIFFERENT host must not come out equal.
        // A mutation that ignored the input entirely (always returning
        // "a.example.com") would still pass every assertion above.
        let other = parse(b"b.example.com", Scheme::Http).expect("well formed");
        assert_ne!(other, authority);
    }

    #[test]
    fn default_port_normalized_per_scheme() {
        let cases: [(&[u8], Scheme, Option<u16>); 6] = [
            (b"a", Scheme::Http, None),
            (b"a:80", Scheme::Http, None),
            (b"a:443", Scheme::Http, Some(443)),
            (b"a", Scheme::Https, None),
            (b"a:80", Scheme::Https, Some(80)),
            (b"a:443", Scheme::Https, None),
        ];
        for (raw, scheme, expected_port) in cases {
            let authority = parse(raw, scheme)
                .unwrap_or_else(|e| panic!("expected {raw:?} on {scheme:?} to parse, got {e:?}"));
            assert_eq!(authority.port(), expected_port, "{raw:?} on {scheme:?}");
            // effective_port resolves None to the scheme default; every case
            // here has a distinct, non-zero, non-one expected value, so a
            // mutation collapsing effective_port to a constant cannot pass.
            let expected_effective = expected_port.unwrap_or_else(|| scheme.default_port());
            assert_eq!(
                authority.effective_port(scheme),
                expected_effective,
                "{raw:?} on {scheme:?}"
            );
        }
    }

    #[test]
    fn ipv6_literals() {
        let accepted: [&[u8]; 3] = [b"[::1]", b"[::1]:8080", b"[::ffff:192.0.2.1]"];
        for raw in accepted {
            let authority =
                parse(raw, Scheme::Http).unwrap_or_else(|e| panic!("{raw:?} rejected: {e:?}"));
            assert!(
                authority.is_ipv6_literal(),
                "{raw:?} must be recognized as an IPv6 literal"
            );
        }

        let refused: [&[u8]; 7] = [
            b"[::1",
            b"[::1]x",
            b"[zz::1]",
            b"[]",
            b"[1.2.3.4]",
            b"[fe80::1%25eth0]",
            b"[fe80::1%eth0]",
        ];
        for raw in refused {
            assert_eq!(
                parse(raw, Scheme::Http),
                Err(RejectReason::AuthorityInvalidByte),
                "{raw:?}"
            );
        }

        // A host that is NOT bracketed must never report as an IPv6 literal:
        // the distinguishing pair for `is_ipv6_literal` itself.
        let plain = parse(b"example.com", Scheme::Http).expect("well formed");
        assert!(!plain.is_ipv6_literal());
    }

    #[test]
    fn bytes_not_addresses() {
        let loopback_spellings: [&[u8]; 4] = [b"127.0.0.1", b"127.1", b"0177.0.0.1", b"2130706433"];
        let mut parsed = Vec::with_capacity(loopback_spellings.len());
        for raw in loopback_spellings {
            parsed.push(
                parse(raw, Scheme::Http)
                    .unwrap_or_else(|e| panic!("{raw:?} must parse as a reg-name, got {e:?}")),
            );
        }
        for i in 0..parsed.len() {
            for j in (i.saturating_add(1))..parsed.len() {
                assert_ne!(
                    parsed.get(i),
                    parsed.get(j),
                    "loopback spellings {:?} and {:?} must be distinct Authority values: \
                     this type canonicalizes bytes, not addresses",
                    loopback_spellings.get(i),
                    loopback_spellings.get(j),
                );
            }
        }

        let long_form = parse(b"[::1]", Scheme::Http).expect("well formed");
        let short_form = parse(b"[0:0:0:0:0:0:0:1]", Scheme::Http).expect("well formed");
        assert_ne!(
            long_form, short_form,
            "[::1] and [0:0:0:0:0:0:0:1] denote the same address and must still be two \
             distinct Authority values: address-matching policy parses an IpAddr, it does \
             not compare host() bytes"
        );
    }

    #[test]
    fn non_ascii_is_refused_not_mapped() {
        let cyrillic = "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}";
        assert_eq!(
            parse(cyrillic.as_bytes(), Scheme::Http),
            Err(RejectReason::AuthorityNonAscii)
        );

        // The exact two-byte case a required acceptance check names by its
        // literal bytes: the UTF-8 encoding of the first letter of the
        // Cyrillic word above, standing alone as a complete authority.
        let mut out = BytesMut::new();
        assert_eq!(
            Authority::parse_into(
                b"\xd0\xbf",
                Scheme::Http,
                &Limits::DEFAULT.clamped(),
                &mut out
            ),
            Err(RejectReason::AuthorityNonAscii)
        );

        let a_label = parse(b"xn--e1afmkfd.xn--p1ai", Scheme::Http).expect("A-label must parse");
        assert_eq!(a_label.host(), b"xn--e1afmkfd.xn--p1ai");

        // The audit's own concern, made concrete: a single precomposed
        // accented letter (U+00E9) and the canonically equivalent spelling
        // of the same character as a plain letter plus a combining accent
        // are two different byte sequences that a Unicode text canonicalizer
        // would fold together. Both must be refused, and refused
        // independently: neither may be canonicalized into the other or
        // into anything else. This is the rule the ban exists to enforce,
        // not merely a check on which four-letter standard names appear in
        // this file's own text.
        let precomposed = "caf\u{e9}"; // "café" with a single precomposed e-acute codepoint
        let decomposed = "cafe\u{301}"; // "cafe" plus a separate combining acute accent codepoint
        assert_ne!(precomposed.as_bytes(), decomposed.as_bytes());
        assert_eq!(
            parse(precomposed.as_bytes(), Scheme::Http),
            Err(RejectReason::AuthorityNonAscii)
        );
        assert_eq!(
            parse(decomposed.as_bytes(), Scheme::Http),
            Err(RejectReason::AuthorityNonAscii)
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table of the nine reconcile_authority scenarios the issue names as edge \
                  cases 30 through 38 plus the HTTP/1 caller-bug case; splitting it would break \
                  the 1:1 mapping between this test and that numbered list"
    )]
    #[test]
    fn reconcile_matrix() {
        let mut out = BytesMut::new();

        // 30
        out.clear();
        let a = reconcile_authority(
            Some(b"a"),
            None,
            Scheme::Http,
            WireVersion::Http11,
            &Limits::DEFAULT.clamped(),
            &mut out,
        )
        .expect("Host alone on HTTP/1.1 must reconcile");
        assert_eq!(a.host(), b"a");

        // 31
        out.clear();
        assert_eq!(
            reconcile_authority(
                None,
                None,
                Scheme::Http,
                WireVersion::Http11,
                &Limits::DEFAULT.clamped(),
                &mut out,
            ),
            Err(RejectReason::HostMissing)
        );

        // 32
        out.clear();
        assert_eq!(
            reconcile_authority(
                None,
                None,
                Scheme::Http,
                WireVersion::Http10,
                &Limits::DEFAULT.clamped(),
                &mut out,
            ),
            Err(RejectReason::HostMissing)
        );

        // 33
        out.clear();
        let a = reconcile_authority(
            None,
            Some(b"a"),
            Scheme::Https,
            WireVersion::H2,
            &Limits::DEFAULT.clamped(),
            &mut out,
        )
        .expect(":authority alone on H2 must reconcile");
        assert_eq!(a.host(), b"a");

        // 34
        out.clear();
        let a = reconcile_authority(
            Some(b"a"),
            None,
            Scheme::Https,
            WireVersion::H2,
            &Limits::DEFAULT.clamped(),
            &mut out,
        )
        .expect("Host alone on H2 (no :authority) must reconcile");
        assert_eq!(a.host(), b"a");
        out.clear();
        assert_eq!(
            reconcile_authority(
                None,
                None,
                Scheme::Https,
                WireVersion::H2,
                &Limits::DEFAULT.clamped(),
                &mut out,
            ),
            Err(RejectReason::PseudoHeaderMissing)
        );

        // 35
        out.clear();
        assert_eq!(
            reconcile_authority(
                Some(b"evil.com"),
                Some(b"good.com"),
                Scheme::Https,
                WireVersion::H2,
                &Limits::DEFAULT.clamped(),
                &mut out,
            ),
            Err(RejectReason::AuthorityMismatch)
        );

        // 36
        out.clear();
        let a = reconcile_authority(
            Some(b"a:443"),
            Some(b"a"),
            Scheme::Https,
            WireVersion::H2,
            &Limits::DEFAULT.clamped(),
            &mut out,
        )
        .expect("a:443 and a must agree on https after default-port normalization");
        assert_eq!(a.host(), b"a");

        // 37
        out.clear();
        assert_eq!(
            reconcile_authority(
                Some(b"a:80"),
                Some(b"a"),
                Scheme::Https,
                WireVersion::H2,
                &Limits::DEFAULT.clamped(),
                &mut out,
            ),
            Err(RejectReason::AuthorityMismatch)
        );

        // 38
        out.clear();
        let a = reconcile_authority(
            Some(b"A"),
            Some(b"a"),
            Scheme::Https,
            WireVersion::H2,
            &Limits::DEFAULT.clamped(),
            &mut out,
        )
        .expect("A and a must agree after lowercasing");
        assert_eq!(a.host(), b"a");

        // Caller-bug case named in the algorithm text but outside the
        // numbered edge cases: `:authority` is always None on HTTP/1, so a
        // caller that hands one in anyway gets AuthorityMismatch rather than
        // having it silently ignored.
        out.clear();
        assert_eq!(
            reconcile_authority(
                Some(b"a"),
                Some(b"a"),
                Scheme::Http,
                WireVersion::Http11,
                &Limits::DEFAULT.clamped(),
                &mut out,
            ),
            Err(RejectReason::AuthorityMismatch)
        );
    }

    #[test]
    fn write_to_round_trips() {
        let inputs: [&[u8]; 4] = [b"a", b"a:8080", b"[::1]", b"[::1]:8080"];
        for raw in inputs {
            let authority = parse(raw, Scheme::Http).unwrap_or_else(|e| {
                panic!("{raw:?} must parse for this test's purpose, got {e:?}")
            });

            let mut out = BytesMut::new();
            let written = authority.write_to(&mut out);
            assert_eq!(
                written,
                authority.written_len(),
                "write_to's return value must match written_len() for {raw:?}"
            );
            assert_eq!(
                out.len(),
                written,
                "write_to must write exactly the bytes it reports for {raw:?}"
            );

            let mut reparse_buf = BytesMut::new();
            let reparsed = Authority::parse_into(
                &out,
                Scheme::Http,
                &Limits::DEFAULT.clamped(),
                &mut reparse_buf,
            )
            .unwrap_or_else(|e| {
                panic!("re-parsing write_to's own output for {raw:?} failed: {e:?}")
            });
            assert_eq!(reparsed, authority);
        }
    }

    #[test]
    fn limits() {
        let ok_255 = vec![b'a'; 255];
        assert!(parse(&ok_255, Scheme::Http).is_ok());

        let too_long_256 = vec![b'a'; 256];
        assert_eq!(
            parse(&too_long_256, Scheme::Http),
            Err(RejectReason::AuthorityTooLong)
        );

        // The tighter limit a configuration might set is honored, not just
        // the default: a mutation that read `Limits::DEFAULT` instead of the
        // passed-in `limits` argument would still pass every assertion above.
        let tight = Limits {
            max_authority_bytes: 4,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut out = BytesMut::new();
        assert_eq!(
            Authority::parse_into(b"abcd", Scheme::Http, &tight, &mut out),
            Ok(Authority {
                buf: Bytes::from_static(b"abcd"),
                host_len: 4,
                port: None,
            })
        );
        let mut out2 = BytesMut::new();
        assert_eq!(
            Authority::parse_into(b"abcde", Scheme::Http, &tight, &mut out2),
            Err(RejectReason::AuthorityTooLong)
        );
    }

    proptest::proptest! {
        #[test]
        fn prop_parse_never_panics(
            v in proptest::collection::vec(
                proptest::prop_oneof![
                    b'a'..=b'z',
                    proptest::prelude::Just(b'.'),
                    proptest::prelude::Just(b':'),
                    proptest::prelude::Just(b'['),
                    proptest::prelude::Just(b']'),
                    proptest::prelude::any::<u8>(),
                ],
                0..=300,
            ),
            scheme_is_https: bool,
        ) {
            let scheme = if scheme_is_https { Scheme::Https } else { Scheme::Http };
            let mut out = BytesMut::new();
            let result = Authority::parse_into(&v, scheme, &Limits::DEFAULT.clamped(), &mut out);
            if let Ok(authority) = result {
                assert!(!authority.host().is_empty());
                assert!(authority.host().iter().all(|b| *b < 0x80));
                assert!(authority.host().iter().all(|b| !b.is_ascii_uppercase()));
                assert_ne!(authority.port(), Some(scheme.default_port()));
            }
        }
    }
}
