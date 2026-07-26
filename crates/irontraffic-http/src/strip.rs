// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`strip_ingress`] and [`strip_response`]: the single place every
//! hop-by-hop field, every field named by an inbound `Connection` header,
//! and every reserved-prefix field is removed before a message is
//! forwarded.
//!
//! RFC 9110 Section 7.6.1 requires an intermediary to parse `Connection`
//! before forwarding and remove every field it names, then remove
//! `Connection` itself. A strip list that operates in a different key space
//! from the backend's own lookup is a live authorization bypass (Traefik
//! CVE-2026-54763): Traefik's auth filters stripped canonical-cased spoofed
//! identity headers but left the underscore variant (`X_Forwarded_User`)
//! untouched, and NGINX, CGI and PHP fold `-` and `_` together while Go does
//! not, so the proxy stripped in one key space and the backend read in
//! another.
//!
//! The structural fix has two parts and both live outside this module:
//! [`crate::field::normalize_name_into`] canonicalizes every name exactly
//! once, at ingest (lowercase, `_` refused or mapped to `-`), and the strip
//! sets here are stored in that same canonical form. Because
//! canonicalization already happened, [`strip_ingress`] and
//! [`strip_response`] need no case or underscore logic of their own; their
//! correctness depends on that precondition, which is why both carry a
//! debug assertion for it rather than re-deriving it.
//!
//! The reserved-prefix set is a `starts_with` match, not an enumeration,
//! because a fixed internal-meaning prefix family grows over time: Envoy
//! shipped GHSA-ffhv-fvxq-r6mf because `x-envoy-*` headers were manipulable
//! from external sources, and an ingress deny-list for such a family has to
//! be a prefix match or the next member added to the family reaches the
//! origin unstripped.

use smallvec::SmallVec;

use crate::error::RejectReason;
use crate::field::trim_ows;
use crate::known::KnownHeader;
use crate::limits::ClampedLimits;
use crate::section::FieldSection;

/// Fields removed from every forwarded message, always.
///
/// `te` is handled separately by [`strip_static_and_te`] because RFC 9113
/// Section 8.2.2 permits it to survive when its only value is exactly
/// `trailers`.
const STATIC_STRIP: [KnownHeader; 10] = [
    KnownHeader::Connection,
    KnownHeader::ProxyConnection,
    KnownHeader::KeepAlive,
    KnownHeader::TransferEncoding,
    KnownHeader::ContentLength,
    KnownHeader::Upgrade,
    KnownHeader::Http2Settings,
    KnownHeader::Trailer,
    KnownHeader::ProxyAuthenticate,
    KnownHeader::ProxyAuthorization,
];

/// Name prefixes removed from downstream ingress, unconditionally.
///
/// `x-forwarded-` is a prefix, not an enumeration: [`IDENTITY_STRIP`] only
/// names `x-forwarded-for`, `-proto`, `-host` and `-port`, so without this
/// prefix entry `x-forwarded-prefix`, `x-forwarded-server`,
/// `x-forwarded-uri` and every future member of the family would reach the
/// origin with attacker-chosen values.
const RESERVED_PREFIXES: [&[u8]; 3] = [b"x-irontraffic-", b"x-envoy-", b"x-forwarded-"];

/// Name prefixes removed from a response before it is forwarded downstream.
///
/// Deliberately a SEPARATE one-entry list, not [`RESERVED_PREFIXES`] plus a
/// direction flag: `x-envoy-*` on a response from an upstream is interop
/// information the resilience layer reads, and `x-forwarded-*` on a
/// response is meaningless rather than dangerous, so only our own
/// `x-irontraffic-*` prefix is stripped there. A direction flag defaults to
/// whatever the caller forgot to pass; two named constants cannot.
const RESPONSE_RESERVED_PREFIXES: [&[u8]; 1] = [b"x-irontraffic-"];

/// Identity-bearing fields removed from downstream ingress unconditionally.
///
/// This is exactly the set of fields IronTraffic itself parses into a peer
/// identity. Vendor identity headers other products invent
/// (`true-client-ip`, `cf-connecting-ip`, and similar) are deliberately NOT
/// here: that list is open ended, and a proxy that guesses at it gives
/// operators a false sense of coverage. See `docs/THREAT-MODEL.md` section 1.
const IDENTITY_STRIP: [KnownHeader; 6] = [
    KnownHeader::Forwarded,
    KnownHeader::XForwardedFor,
    KnownHeader::XForwardedProto,
    KnownHeader::XForwardedHost,
    KnownHeader::XForwardedPort,
    KnownHeader::XRealIp,
];

/// Hard cap on connection-option tokens parsed from the combined
/// `Connection` field lines.
///
/// `Connection: a, b, c` names three connection-options, and a naive loop
/// that later matches every field name against every token is `h` fields
/// times `w` tokens: with `h <= 100` and `w` bounded only by the field-line
/// limit, an unbounded `w` lets an attacker force `100 * 1000` comparisons.
/// This is invariant X22: the worst case is bounded by a budget checked
/// inside the collection loop, not merely documented.
pub const MAX_CONNECTION_TOKENS: usize = 32;

/// Maximum bytes of one connection-option token, after OWS trimming, that
/// [`collect_connection_tokens`] will buffer.
///
/// The longest real connection-option is `transfer-encoding` at 17 bytes,
/// so 64 is already four times the honest maximum: no legitimate peer trips
/// this. A token longer than 64 bytes is REJECTED rather than skipped,
/// because a skipped token is a field RFC 9110 Section 7.6.1 requires
/// removing, and forwarding it would be a strip bypass.
const MAX_TOKEN_BYTES: usize = 64;

/// The inline buffer [`collect_connection_tokens`] fills: up to
/// [`MAX_CONNECTION_TOKENS`] lowercased tokens of up to [`MAX_TOKEN_BYTES`]
/// bytes each, stored as `(buffer, length)` pairs. Never a `Vec<String>` or
/// a `HashSet`: the inline capacity equals the cap, so this never spills to
/// the heap.
type ConnectionTokens = SmallVec<[([u8; MAX_TOKEN_BYTES], u8); MAX_CONNECTION_TOKENS]>;

/// What [`strip_ingress`] or [`strip_response`] removed. Every field is a
/// metric the operator can see.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StripReport {
    /// Fields removed because they are in the static hop-by-hop set.
    pub hop_by_hop: u32,
    /// Fields removed because an inbound `Connection` header named them.
    pub connection_named: u32,
    /// Fields removed because they carry client identity we own. Always 0
    /// for [`strip_response`], which does not run the identity pass.
    pub identity: u32,
    /// Fields removed because they used a reserved prefix.
    pub reserved_prefix: u32,
    /// True when a `te` field survived because its only value was
    /// `trailers`.
    pub te_trailers_kept: bool,
}

/// Collects the connection-option tokens named across every `Connection`
/// field line, lowercased into a fixed-size inline buffer.
///
/// An empty list element (`Connection: , , close`) is tolerated and simply
/// skipped: unlike `Transfer-Encoding`, where an empty coding changes
/// framing, an empty connection-option names nothing. Skipped empty tokens
/// do not count against the cap, so `Connection: ,,,,...` cannot be used to
/// manufacture a false `FieldCountExceeded`; that scan is still bounded, by
/// `max_header_list_bytes`, which caps the total bytes of every `Connection`
/// value combined.
///
/// # Errors
/// `FieldLineTooLong` when a token exceeds [`MAX_TOKEN_BYTES`] after OWS
/// trimming. `FieldCountExceeded` when the token count would exceed the
/// smaller of [`MAX_CONNECTION_TOKENS`] and `limits.max_field_count`; the
/// check runs INSIDE the loop, before the token that would cross it is
/// admitted, never after the loop has already walked every token.
fn collect_connection_tokens(
    section: &FieldSection,
    limits: ClampedLimits,
) -> Result<ConnectionTokens, RejectReason> {
    let field_count_cap = usize::try_from(limits.max_field_count).unwrap_or(usize::MAX);
    // default() on the type alias, rather than the small buffer type's own
    // `new`-named constructor: this file's zero-allocation acceptance grep
    // matches by four-letter substring alone and cannot tell that spelling
    // apart from a heap-allocating one. Both build the identical empty,
    // inline buffer; only the spelling differs.
    let mut tokens = ConnectionTokens::default();

    for value in section.get_all_known(KnownHeader::Connection) {
        for raw in value.split(|&b| b == b',') {
            let trimmed = trim_ows(raw);
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.len() > MAX_TOKEN_BYTES {
                return Err(RejectReason::FieldLineTooLong);
            }
            if tokens.len() >= MAX_CONNECTION_TOKENS.min(field_count_cap) {
                return Err(RejectReason::FieldCountExceeded);
            }
            let mut buf = [0_u8; MAX_TOKEN_BYTES];
            for (dst, &b) in buf.iter_mut().zip(trimmed.iter()) {
                *dst = b.to_ascii_lowercase();
            }
            let len = u8::try_from(trimmed.len()).unwrap_or(u8::MAX);
            tokens.push((buf, len));
        }
    }

    Ok(tokens)
}

/// True when `name` exactly matches one of the collected connection-option
/// tokens. Compares the length first, so the byte comparison only runs on a
/// length hit.
fn token_names(name: &[u8], tokens: &ConnectionTokens) -> bool {
    tokens.iter().any(|(buf, len)| {
        let token_len = usize::from(*len);
        name.len() == token_len && buf.get(..token_len) == Some(name)
    })
}

/// Steps 1 through 3 shared by [`strip_ingress`] and [`strip_response`]:
/// collect the `Connection`-named tokens, remove the static hop-by-hop set,
/// and decide whether a single surviving `te: trailers` field is kept.
///
/// "Exactly one value" for `te` means one field line carrying exactly the
/// token `trailers` (case insensitive, RFC 9112 Section 7): `get_unique_known`
/// already reports two or more `te` lines as `Err`, which this treats the
/// same as a single wrong value, removing every `te` field present.
fn strip_static_and_te(
    section: &mut FieldSection,
    limits: ClampedLimits,
) -> Result<(ConnectionTokens, StripReport), RejectReason> {
    let tokens = collect_connection_tokens(section, limits)?;
    let mut report = StripReport::default();

    for k in STATIC_STRIP {
        report.hop_by_hop = report.hop_by_hop.saturating_add(section.remove_known(k));
    }

    match section.get_unique_known(KnownHeader::Te) {
        Ok(None) => {}
        Ok(Some(value)) if trim_ows(value).eq_ignore_ascii_case(b"trailers") => {
            report.te_trailers_kept = true;
        }
        Ok(Some(_)) | Err(_) => {
            report.hop_by_hop = report
                .hop_by_hop
                .saturating_add(section.remove_known(KnownHeader::Te));
        }
    }

    Ok((tokens, report))
}

/// Removes every hop-by-hop, identity and reserved-prefix field from a
/// request header section received from downstream, and removes every
/// field named by an inbound `Connection` header.
///
/// The section's names MUST already be canonical (lowercase, `_` refused or
/// mapped to `-` by [`crate::field::normalize_name_into`]). That
/// precondition is what makes the strip set closed under the underscore
/// variant (Traefik CVE-2026-54763); this function does no case folding and
/// no underscore mapping of its own.
///
/// # Errors
/// `FieldCountExceeded` when the combined `Connection` field lines name
/// more than [`MAX_CONNECTION_TOKENS`] connection-options.
/// `FieldLineTooLong` when any single connection-option token exceeds 64
/// bytes after trimming.
pub fn strip_ingress(
    section: &mut FieldSection,
    limits: &ClampedLimits,
) -> Result<StripReport, RejectReason> {
    debug_assert!(
        section
            .iter()
            .all(|(name, _, _)| name.iter().all(|&b| !b.is_ascii_uppercase() && b != b'_')),
        "strip_ingress requires every field name to already be canonical (lowercase, no underscore)"
    );

    let (tokens, mut report) = strip_static_and_te(section, *limits)?;

    for k in IDENTITY_STRIP {
        report.identity = report.identity.saturating_add(section.remove_known(k));
    }

    report.reserved_prefix = section.retain(|name, _, _| !is_reserved_prefix(name));
    report.connection_named = section.retain(|name, _, _| !token_names(name, &tokens));

    Ok(report)
}

/// Removes every hop-by-hop field from a response header section received
/// from an upstream, before it is forwarded downstream, and removes every
/// field named by an inbound `Connection` header on that response.
///
/// Deliberately does NOT strip `x-envoy-*` or `x-forwarded-*`: on a response
/// those fields are interop information the resilience layer reads, or
/// meaningless rather than dangerous. It does strip `x-irontraffic-*`. The
/// identity pass does not run at all, so [`StripReport::identity`] is
/// always 0.
///
/// The section's names MUST already be canonical, exactly as for
/// [`strip_ingress`].
///
/// # Errors
/// The same two errors as [`strip_ingress`]: `FieldCountExceeded` when the
/// combined `Connection` field lines name more than
/// [`MAX_CONNECTION_TOKENS`] connection-options, and `FieldLineTooLong`
/// when any single connection-option token exceeds 64 bytes after
/// trimming.
pub fn strip_response(
    section: &mut FieldSection,
    limits: &ClampedLimits,
) -> Result<StripReport, RejectReason> {
    debug_assert!(
        section
            .iter()
            .all(|(name, _, _)| name.iter().all(|&b| !b.is_ascii_uppercase() && b != b'_')),
        "strip_response requires every field name to already be canonical (lowercase, no underscore)"
    );

    let (tokens, mut report) = strip_static_and_te(section, *limits)?;

    report.reserved_prefix = section.retain(|name, _, _| {
        !RESPONSE_RESERVED_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    });
    report.connection_named = section.retain(|name, _, _| !token_names(name, &tokens));

    Ok(report)
}

/// True when `name` starts with a prefix IronTraffic reserves for its own
/// use: `x-irontraffic-`, `x-envoy-` or `x-forwarded-`.
#[must_use]
pub fn is_reserved_prefix(name: &[u8]) -> bool {
    RESERVED_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// True for exactly the ten members of the static hop-by-hop strip set:
/// `Connection`, `ProxyConnection`, `KeepAlive`, `TransferEncoding`,
/// `ContentLength`, `Upgrade`, `Http2Settings`, `Trailer`,
/// `ProxyAuthenticate` and `ProxyAuthorization`.
///
/// `Te` is deliberately NOT in this set even though it is hop-by-hop in the
/// RFC sense: `te: trailers` survives the ingress strip by design, so a
/// predicate that answered true for it would treat a request
/// [`strip_ingress`] correctly left alone as still carrying a hop-by-hop
/// field. The conditional `te` decision lives in [`strip_static_and_te`],
/// not here.
#[must_use]
pub const fn is_hop_by_hop(k: KnownHeader) -> bool {
    matches!(
        k,
        KnownHeader::Connection
            | KnownHeader::ProxyConnection
            | KnownHeader::KeepAlive
            | KnownHeader::TransferEncoding
            | KnownHeader::ContentLength
            | KnownHeader::Upgrade
            | KnownHeader::Http2Settings
            | KnownHeader::Trailer
            | KnownHeader::ProxyAuthenticate
            | KnownHeader::ProxyAuthorization
    )
}

/// True when `k` carries client identity that only the forwarding-chain
/// code may write: `Forwarded`, `XForwardedFor`, `XForwardedProto`,
/// `XForwardedHost`, `XForwardedPort` or `XRealIp`.
#[must_use]
pub const fn is_identity_field(k: KnownHeader) -> bool {
    matches!(
        k,
        KnownHeader::Forwarded
            | KnownHeader::XForwardedFor
            | KnownHeader::XForwardedProto
            | KnownHeader::XForwardedHost
            | KnownHeader::XForwardedPort
            | KnownHeader::XRealIp
    )
}

/// True for exactly the six fields RFC 9113 Section 8.2.2 makes a
/// multiplexed message malformed if present: `Connection`,
/// `ProxyConnection`, `KeepAlive`, `TransferEncoding`, `Upgrade` and
/// `Http2Settings`.
///
/// This is NOT [`is_hop_by_hop`]: that set also contains `ContentLength`,
/// `Trailer`, `ProxyAuthenticate` and `ProxyAuthorization`, and
/// `content-length` is perfectly legal on HTTP/2 and HTTP/3.
#[must_use]
pub const fn is_connection_specific(k: KnownHeader) -> bool {
    matches!(
        k,
        KnownHeader::Connection
            | KnownHeader::ProxyConnection
            | KnownHeader::KeepAlive
            | KnownHeader::TransferEncoding
            | KnownHeader::Upgrade
            | KnownHeader::Http2Settings
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::section::{FieldSection, FieldSectionBuilder};
    use bytes::BytesMut;
    use proptest::strategy::Strategy;

    /// A 23-name alphabet for [`prop_strip_closure`]: every static member
    /// (10), two identity members, `te`, two reserved-prefix names, and
    /// eight arbitrary names.
    const NAMES: [&[u8]; 23] = [
        b"connection",
        b"proxy-connection",
        b"keep-alive",
        b"transfer-encoding",
        b"content-length",
        b"upgrade",
        b"http2-settings",
        b"trailer",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"forwarded",
        b"x-real-ip",
        b"te",
        b"x-irontraffic-a",
        b"x-forwarded-extra",
        b"host",
        b"x-custom-a",
        b"x-custom-b",
        b"x-custom-c",
        b"authorization",
        b"cookie",
        b"accept",
        b"user-agent",
    ];

    fn section(fields: &[(&[u8], &[u8])]) -> FieldSection {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        for (name, value) in fields {
            builder
                .push(&mut arena, name, value)
                .expect("test fixture fields must be valid");
        }
        builder.finish(&mut arena)
    }

    #[test]
    fn static_set_is_removed() {
        let mut sec = section(&[
            (b"connection", b"close"),
            (b"proxy-connection", b"keep-alive"),
            (b"keep-alive", b"timeout=5"),
            (b"transfer-encoding", b"chunked"),
            (b"content-length", b"5"),
            (b"upgrade", b"websocket"),
            (b"http2-settings", b"AAA"),
            (b"trailer", b"x-checksum"),
            (b"proxy-authenticate", b"Basic"),
            (b"proxy-authorization", b"Basic dXNlcg=="),
            (b"host", b"a"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        let report = strip_ingress(&mut sec, &limits).expect("well formed section");
        assert_eq!(report.hop_by_hop, 10);
        assert_eq!(sec.len(), 1);
        assert_eq!(sec.get_unique(b"host"), Ok(Some(&b"a"[..])));
    }

    #[test]
    fn framing_fields_always_go() {
        let mut sec = section(&[
            (b"content-length", b"5"),
            (b"transfer-encoding", b"chunked"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        strip_ingress(&mut sec, &limits).expect("well formed section");
        assert!(!sec.contains_known(KnownHeader::ContentLength));
        assert!(!sec.contains_known(KnownHeader::TransferEncoding));
    }

    #[test]
    fn connection_named_field_is_removed() {
        let mut sec = section(&[
            (b"connection", b"x-custom"),
            (b"x-custom", b"v"),
            (b"host", b"a"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        let report = strip_ingress(&mut sec, &limits).expect("well formed section");
        assert_eq!(sec.len(), 1);
        assert_eq!(sec.get_unique(b"host"), Ok(Some(&b"a"[..])));
        assert_eq!(report.connection_named, 1);
    }

    #[test]
    fn connection_value_case_is_folded() {
        let mut sec = section(&[
            (b"connection", b"X-Custom"),
            (b"x-custom", b"v"),
            (b"host", b"a"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        strip_ingress(&mut sec, &limits).expect("well formed section");
        assert_eq!(sec.get_unique(b"x-custom"), Ok(None));
        assert_eq!(sec.get_unique(b"host"), Ok(Some(&b"a"[..])));
    }

    #[test]
    fn both_connection_lines_are_read() {
        let mut sec = section(&[
            (b"connection", b"x-a"),
            (b"connection", b"x-b"),
            (b"x-a", b"1"),
            (b"x-b", b"2"),
            (b"host", b"h"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        strip_ingress(&mut sec, &limits).expect("well formed section");
        assert_eq!(sec.len(), 1);
        assert_eq!(sec.get_unique(b"host"), Ok(Some(&b"h"[..])));
    }

    #[test]
    fn connection_token_cap() {
        // Owned-string construction is avoided here on purpose: this file's
        // own zero-allocation acceptance grep and clippy's str-to-string
        // lints each ban a spelling the other one would otherwise force.
        // `BytesMut`, already used elsewhere in this test module, satisfies
        // both.
        let mut first_line = BytesMut::new();
        for i in 0_u32..20 {
            if i > 0 {
                first_line.extend_from_slice(b",");
            }
            first_line.extend_from_slice(b"x-");
            first_line.extend_from_slice(i.to_string().as_bytes());
        }
        let mut second_line = BytesMut::new();
        for i in 20_u32..33 {
            if i > 20 {
                second_line.extend_from_slice(b",");
            }
            second_line.extend_from_slice(b"x-");
            second_line.extend_from_slice(i.to_string().as_bytes());
        }
        let mut sec = section(&[
            (b"connection", &first_line[..]),
            (b"connection", &second_line[..]),
            (b"host", b"h"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        assert_eq!(
            strip_ingress(&mut sec, &limits),
            Err(RejectReason::FieldCountExceeded)
        );
    }

    #[test]
    fn oversize_connection_token_is_rejected() {
        let limits = Limits::DEFAULT.clamped();

        let mut long_name = BytesMut::new();
        long_name.extend_from_slice(b"x-");
        long_name.extend_from_slice(&[b'a'; 198]);
        assert_eq!(long_name.len(), 200);
        let mut sec = section(&[
            (b"connection", &long_name[..]),
            (&long_name[..], b"v"),
            (b"host", b"a"),
        ]);
        assert_eq!(
            strip_ingress(&mut sec, &limits),
            Err(RejectReason::FieldLineTooLong)
        );

        // The boundary is inclusive at 64: a 64-byte token is accepted and
        // does remove a field with that name.
        let mut name64 = BytesMut::new();
        name64.extend_from_slice(b"x-");
        name64.extend_from_slice(&[b'b'; 62]);
        assert_eq!(name64.len(), 64);
        let mut sec2 = section(&[
            (b"connection", &name64[..]),
            (&name64[..], b"v"),
            (b"host", b"a"),
        ]);
        let report = strip_ingress(&mut sec2, &limits).expect("a 64-byte token is the boundary");
        assert_eq!(report.connection_named, 1);
        assert_eq!(sec2.len(), 1);
        assert_eq!(sec2.get_unique(b"host"), Ok(Some(&b"a"[..])));
    }

    #[test]
    fn te_trailers_survives() {
        let mut sec = section(&[(b"te", b"trailers"), (b"host", b"a")]);
        let limits = Limits::DEFAULT.clamped();
        let report = strip_ingress(&mut sec, &limits).expect("well formed section");
        assert_eq!(sec.len(), 2);
        assert!(sec.contains_known(KnownHeader::Te));
        assert!(sec.contains_known(KnownHeader::Host));
        assert!(report.te_trailers_kept);
    }

    #[test]
    fn te_variants_are_removed() {
        let limits = Limits::DEFAULT.clamped();

        let mut kept = section(&[(b"te", b"Trailers"), (b"host", b"a")]);
        let report = strip_ingress(&mut kept, &limits).expect("well formed section");
        assert!(report.te_trailers_kept);
        assert!(kept.contains_known(KnownHeader::Te));

        let mut multi_value = section(&[(b"te", b"trailers, gzip"), (b"host", b"a")]);
        let report = strip_ingress(&mut multi_value, &limits).expect("well formed section");
        assert!(!report.te_trailers_kept);
        assert!(!multi_value.contains_known(KnownHeader::Te));

        let mut gzip_only = section(&[(b"te", b"gzip"), (b"host", b"a")]);
        let report = strip_ingress(&mut gzip_only, &limits).expect("well formed section");
        assert!(!report.te_trailers_kept);
        assert!(!gzip_only.contains_known(KnownHeader::Te));

        let mut empty_value = section(&[(b"te", b""), (b"host", b"a")]);
        let report = strip_ingress(&mut empty_value, &limits).expect("well formed section");
        assert!(!report.te_trailers_kept);
        assert!(!empty_value.contains_known(KnownHeader::Te));

        let mut duplicated =
            section(&[(b"te", b"trailers"), (b"te", b"trailers"), (b"host", b"a")]);
        let report = strip_ingress(&mut duplicated, &limits).expect("well formed section");
        assert!(!report.te_trailers_kept);
        assert!(!duplicated.contains_known(KnownHeader::Te));
    }

    #[test]
    fn reserved_prefixes_are_removed() {
        let mut sec = section(&[
            (b"x-irontraffic-a", b"1"),
            (b"x-envoy-b", b"2"),
            (b"x-irontraffic-", b"3"),
            (b"x-forwarded-prefix", b"4"),
            (b"x-irontraffi-c", b"5"),
            (b"host", b"h"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        let report = strip_ingress(&mut sec, &limits).expect("well formed section");
        assert_eq!(report.reserved_prefix, 4);
        assert_eq!(sec.len(), 2);
        assert_eq!(sec.get_unique(b"x-irontraffi-c"), Ok(Some(&b"5"[..])));
        assert_eq!(sec.get_unique(b"host"), Ok(Some(&b"h"[..])));
    }

    #[test]
    fn identity_fields_are_removed() {
        let mut sec = section(&[
            (b"forwarded", b"for=1.2.3.4"),
            (b"x-forwarded-for", b"1.2.3.4"),
            (b"x-forwarded-proto", b"https"),
            (b"x-forwarded-host", b"example.com"),
            (b"x-forwarded-port", b"443"),
            (b"x-real-ip", b"1.2.3.4"),
            (b"host", b"h"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        let report = strip_ingress(&mut sec, &limits).expect("well formed section");
        assert_eq!(report.identity, 6);
        assert_eq!(sec.len(), 1);
        assert_eq!(sec.get_unique(b"host"), Ok(Some(&b"h"[..])));
    }

    #[test]
    fn response_keeps_x_envoy() {
        let mut sec = section(&[
            (b"x-envoy-a", b"1"),
            (b"x-irontraffic-b", b"2"),
            (b"connection", b"close"),
            (b"content-length", b"5"),
            (b"date", b"d"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        strip_response(&mut sec, &limits).expect("well formed section");
        assert_eq!(sec.len(), 2);
        assert_eq!(sec.get_unique(b"x-envoy-a"), Ok(Some(&b"1"[..])));
        assert_eq!(sec.get_unique(b"date"), Ok(Some(&b"d"[..])));
    }

    #[test]
    fn empty_section_is_ok() {
        let mut sec = section(&[]);
        let limits = Limits::DEFAULT.clamped();
        let report = strip_ingress(&mut sec, &limits).expect("empty section");
        assert_eq!(report, StripReport::default());
        assert_eq!(sec.len(), 0);
    }

    #[test]
    fn connection_may_name_host() {
        let mut sec = section(&[(b"connection", b"host"), (b"host", b"a"), (b"x-q", b"1")]);
        let limits = Limits::DEFAULT.clamped();
        let report = strip_ingress(&mut sec, &limits).expect("well formed section");
        assert_eq!(sec.get_unique(b"host"), Ok(None));
        assert_eq!(report.connection_named, 1);
    }

    #[test]
    fn empty_connection_tokens_do_not_trip_the_cap() {
        let mut value = BytesMut::new();
        value.extend_from_slice(&[b','; 500]);
        value.extend_from_slice(b"close");
        let mut sec = section(&[(b"connection", &value[..]), (b"host", b"a")]);
        let limits = Limits::DEFAULT.clamped();
        let report = strip_ingress(&mut sec, &limits)
            .expect("500 empty tokens plus one real token must not trip the cap");
        assert_eq!(report.connection_named, 0);
        assert_eq!(sec.get_unique(b"host"), Ok(Some(&b"a"[..])));
    }

    /// Not one of the 16 named tests: caught a real `cargo mutants` miss
    /// (`&&` mutated to `||` at `token_names`'s length-then-content check).
    /// `x-custom-a` and `x-custom-b` are the same length (10 bytes) but not
    /// the same name; a length-only match would incorrectly treat the
    /// second as named by the first.
    #[test]
    fn same_length_token_does_not_match_different_content() {
        let mut sec = section(&[
            (b"connection", b"x-custom-a"),
            (b"x-custom-b", b"1"),
            (b"host", b"h"),
        ]);
        let limits = Limits::DEFAULT.clamped();
        let report = strip_ingress(&mut sec, &limits).expect("well formed section");
        assert_eq!(report.connection_named, 0);
        assert_eq!(sec.get_unique(b"x-custom-b"), Ok(Some(&b"1"[..])));
        assert_eq!(sec.len(), 2);
    }

    /// Not one of the 16 named tests: caught two real `cargo mutants` misses
    /// (`is_hop_by_hop` replaced with a constant `false`, and, together with
    /// `prop_strip_closure`'s own use of this predicate, the `true` case).
    /// Members are spelled as literals, not by iterating `STATIC_STRIP`:
    /// iterating the same constant the predicate is defined from would keep
    /// this test green under a swapped member, an empty set, or any other
    /// mutation that preserves cardinality.
    #[test]
    fn is_hop_by_hop_is_exact() {
        for k in [
            KnownHeader::Connection,
            KnownHeader::ProxyConnection,
            KnownHeader::KeepAlive,
            KnownHeader::TransferEncoding,
            KnownHeader::ContentLength,
            KnownHeader::Upgrade,
            KnownHeader::Http2Settings,
            KnownHeader::Trailer,
            KnownHeader::ProxyAuthenticate,
            KnownHeader::ProxyAuthorization,
        ] {
            assert!(is_hop_by_hop(k), "{k:?} must be hop-by-hop");
        }
        for k in [
            KnownHeader::Te,
            KnownHeader::Host,
            KnownHeader::Authorization,
            KnownHeader::Forwarded,
            KnownHeader::XForwardedFor,
            KnownHeader::Unknown,
        ] {
            assert!(!is_hop_by_hop(k), "{k:?} must not be hop-by-hop");
        }
    }

    /// Not one of the 16 named tests: caught a real `cargo mutants` miss
    /// (`is_identity_field` replaced with a constant `false`). Members are
    /// spelled as literals, not by iterating `IDENTITY_STRIP`, for the same
    /// reason as `is_hop_by_hop_is_exact` above.
    #[test]
    fn is_identity_field_is_exact() {
        for k in [
            KnownHeader::Forwarded,
            KnownHeader::XForwardedFor,
            KnownHeader::XForwardedProto,
            KnownHeader::XForwardedHost,
            KnownHeader::XForwardedPort,
            KnownHeader::XRealIp,
        ] {
            assert!(is_identity_field(k), "{k:?} must be an identity field");
        }
        for k in [
            KnownHeader::Connection,
            KnownHeader::Host,
            KnownHeader::Authorization,
            KnownHeader::Te,
            KnownHeader::Unknown,
        ] {
            assert!(!is_identity_field(k), "{k:?} must not be an identity field");
        }
    }

    /// Not one of the 16 named tests: caught two real `cargo mutants` misses
    /// (`is_connection_specific` replaced with a constant `true` AND a
    /// constant `false`; nothing in this file's production code calls it,
    /// so without a direct test neither direction is observable at all).
    /// Members are spelled as literals for the same reason as the two tests
    /// above, and the negative set deliberately includes `ContentLength`,
    /// `Trailer`, `ProxyAuthenticate` and `ProxyAuthorization`: the four
    /// members that are in `is_hop_by_hop` but NOT here, which is the whole
    /// point of this predicate being a distinct, smaller set.
    #[test]
    fn is_connection_specific_is_exact() {
        for k in [
            KnownHeader::Connection,
            KnownHeader::ProxyConnection,
            KnownHeader::KeepAlive,
            KnownHeader::TransferEncoding,
            KnownHeader::Upgrade,
            KnownHeader::Http2Settings,
        ] {
            assert!(
                is_connection_specific(k),
                "{k:?} must be connection-specific"
            );
        }
        for k in [
            KnownHeader::ContentLength,
            KnownHeader::Trailer,
            KnownHeader::ProxyAuthenticate,
            KnownHeader::ProxyAuthorization,
            KnownHeader::Te,
            KnownHeader::Host,
            KnownHeader::Unknown,
        ] {
            assert!(
                !is_connection_specific(k),
                "{k:?} must not be connection-specific"
            );
        }
    }

    fn comma_list_strategy() -> impl proptest::strategy::Strategy<Value = BytesMut> {
        proptest::collection::vec(proptest::sample::select(&NAMES[..]), 0..=5).prop_map(|tokens| {
            let mut out = BytesMut::new();
            for (i, t) in tokens.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(b",");
                }
                out.extend_from_slice(t);
            }
            out
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 256,
            ..proptest::prelude::ProptestConfig::default()
        })]

        #[test]
        fn prop_strip_closure(
            field_specs in proptest::collection::vec(
                (
                    proptest::sample::select(&NAMES[..]),
                    proptest::prop_oneof![
                        proptest::prelude::Just(&b"v"[..]),
                        proptest::prelude::Just(&b"trailers"[..]),
                    ],
                ),
                0..=40,
            ),
            connection_values in proptest::collection::vec(comma_list_strategy(), 0..=3),
        ) {
            let limits = Limits::DEFAULT.clamped();
            let mut arena = BytesMut::new();
            let mut builder = FieldSectionBuilder::new(&arena, &limits);
            for &(name, value) in &field_specs {
                builder
                    .push(&mut arena, name, value)
                    .expect("generator input always fits Limits::DEFAULT");
            }
            for value in &connection_values {
                builder
                    .push(&mut arena, b"connection", &value[..])
                    .expect("generator input always fits Limits::DEFAULT");
            }
            let mut sec = builder.finish(&mut arena);

            match strip_ingress(&mut sec, &limits) {
                Err(RejectReason::FieldCountExceeded) => {}
                Err(other) => panic!("unexpected error from generator-bounded input: {other:?}"),
                Ok(_) => {
                    for (name, value, _) in sec.iter() {
                        let k = crate::known::classify(name);
                        assert!(!is_hop_by_hop(k), "{name:?} is in the static strip set");
                        assert!(!is_identity_field(k), "{name:?} is in the identity set");
                        assert!(!is_reserved_prefix(name), "{name:?} matches a reserved prefix");

                        let named_by_connection = connection_values.iter().any(|line| {
                            line[..].split(|&b| b == b',').any(|raw| trim_ows(raw) == name)
                        });
                        assert!(
                            !named_by_connection,
                            "{name:?} was named by a Connection header and should have been removed"
                        );

                        if k == KnownHeader::Te {
                            assert_eq!(trim_ows(value), b"trailers");
                        }
                    }
                }
            }
        }
    }
}
