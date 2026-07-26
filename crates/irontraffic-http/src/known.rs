// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`KnownHeader`], the closed set of the 51 header names IronTraffic itself
//! makes decisions about, and [`classify`], the constant-time classifier
//! from an already-canonical field name to it.
//!
//! Classifying a name once, at parse time, into a `u8` tag turns every later
//! "is this the `authorization` header" question into a one-byte comparison
//! instead of a case-insensitive string comparison, and it is what lets
//! [`crate::section::FieldSection`]'s `known_mask` answer "is this header
//! absent" with one `AND` against a register instead of a scan.
//!
//! [`classify`] is a nested `match` on length and then on the first byte,
//! never a `HashMap` and never a hand-built perfect-hash table: the nested
//! match is a jump table the compiler verifies, and a perfect-hash table
//! would have to be proven collision free by hand and would silently break
//! under a small change to the name list.

/// The header names IronTraffic itself makes decisions about. Everything
/// else is `Unknown` and is carried opaquely.
///
/// The discriminants are stable: they appear in
/// [`crate::section::FieldSlot`] and in [`crate::section::FieldSection`]'s
/// `known_mask` bitmask, so the count must stay at or below 63.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KnownHeader {
    /// Not one of the 51 names this crate itself interprets. Carried opaquely.
    Unknown = 0,
    /// `host`.
    Host,
    /// `content-length`.
    ContentLength,
    /// `transfer-encoding`.
    TransferEncoding,
    /// `connection`.
    Connection,
    /// `proxy-connection`.
    ProxyConnection,
    /// `keep-alive`.
    KeepAlive,
    /// `upgrade`.
    Upgrade,
    /// `http2-settings`.
    Http2Settings,
    /// `trailer`.
    Trailer,
    /// `te`.
    Te,
    /// `proxy-authenticate`.
    ProxyAuthenticate,
    /// `proxy-authorization`.
    ProxyAuthorization,
    /// `expect`.
    Expect,
    /// `content-type`.
    ContentType,
    /// `content-encoding`.
    ContentEncoding,
    /// `accept`.
    Accept,
    /// `accept-encoding`.
    AcceptEncoding,
    /// `accept-language`.
    AcceptLanguage,
    /// `authorization`.
    Authorization,
    /// `cookie`.
    Cookie,
    /// `set-cookie`.
    SetCookie,
    /// `user-agent`.
    UserAgent,
    /// `referer`.
    Referer,
    /// `origin`.
    Origin,
    /// `date`.
    Date,
    /// `server`.
    Server,
    /// `location`.
    Location,
    /// `cache-control`.
    CacheControl,
    /// `pragma`.
    Pragma,
    /// `vary`.
    Vary,
    /// `age`.
    Age,
    /// `etag`.
    Etag,
    /// `if-none-match`.
    IfNoneMatch,
    /// `if-modified-since`.
    IfModifiedSince,
    /// `if-match`.
    IfMatch,
    /// `if-unmodified-since`.
    IfUnmodifiedSince,
    /// `range`.
    Range,
    /// `if-range`.
    IfRange,
    /// `max-forwards`.
    MaxForwards,
    /// `forwarded`.
    Forwarded,
    /// `x-forwarded-for`.
    XForwardedFor,
    /// `x-forwarded-proto`.
    XForwardedProto,
    /// `x-forwarded-host`.
    XForwardedHost,
    /// `x-forwarded-port`.
    XForwardedPort,
    /// `x-real-ip`.
    XRealIp,
    /// `priority`.
    Priority,
    /// `via`.
    Via,
    /// `warning`.
    Warning,
    /// `allow`.
    Allow,
    /// `retry-after`.
    RetryAfter,
    /// `www-authenticate`.
    WwwAuthenticate,
}

/// Number of `KnownHeader` variants including `Unknown`. Exactly 52.
pub const KNOWN_HEADER_COUNT: usize = 52;

impl KnownHeader {
    /// The canonical lowercase spelling. `Unknown` returns an empty slice.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            KnownHeader::Unknown => b"",
            KnownHeader::Host => b"host",
            KnownHeader::ContentLength => b"content-length",
            KnownHeader::TransferEncoding => b"transfer-encoding",
            KnownHeader::Connection => b"connection",
            KnownHeader::ProxyConnection => b"proxy-connection",
            KnownHeader::KeepAlive => b"keep-alive",
            KnownHeader::Upgrade => b"upgrade",
            KnownHeader::Http2Settings => b"http2-settings",
            KnownHeader::Trailer => b"trailer",
            KnownHeader::Te => b"te",
            KnownHeader::ProxyAuthenticate => b"proxy-authenticate",
            KnownHeader::ProxyAuthorization => b"proxy-authorization",
            KnownHeader::Expect => b"expect",
            KnownHeader::ContentType => b"content-type",
            KnownHeader::ContentEncoding => b"content-encoding",
            KnownHeader::Accept => b"accept",
            KnownHeader::AcceptEncoding => b"accept-encoding",
            KnownHeader::AcceptLanguage => b"accept-language",
            KnownHeader::Authorization => b"authorization",
            KnownHeader::Cookie => b"cookie",
            KnownHeader::SetCookie => b"set-cookie",
            KnownHeader::UserAgent => b"user-agent",
            KnownHeader::Referer => b"referer",
            KnownHeader::Origin => b"origin",
            KnownHeader::Date => b"date",
            KnownHeader::Server => b"server",
            KnownHeader::Location => b"location",
            KnownHeader::CacheControl => b"cache-control",
            KnownHeader::Pragma => b"pragma",
            KnownHeader::Vary => b"vary",
            KnownHeader::Age => b"age",
            KnownHeader::Etag => b"etag",
            KnownHeader::IfNoneMatch => b"if-none-match",
            KnownHeader::IfModifiedSince => b"if-modified-since",
            KnownHeader::IfMatch => b"if-match",
            KnownHeader::IfUnmodifiedSince => b"if-unmodified-since",
            KnownHeader::Range => b"range",
            KnownHeader::IfRange => b"if-range",
            KnownHeader::MaxForwards => b"max-forwards",
            KnownHeader::Forwarded => b"forwarded",
            KnownHeader::XForwardedFor => b"x-forwarded-for",
            KnownHeader::XForwardedProto => b"x-forwarded-proto",
            KnownHeader::XForwardedHost => b"x-forwarded-host",
            KnownHeader::XForwardedPort => b"x-forwarded-port",
            KnownHeader::XRealIp => b"x-real-ip",
            KnownHeader::Priority => b"priority",
            KnownHeader::Via => b"via",
            KnownHeader::Warning => b"warning",
            KnownHeader::Allow => b"allow",
            KnownHeader::RetryAfter => b"retry-after",
            KnownHeader::WwwAuthenticate => b"www-authenticate",
        }
    }
}

/// Classifies an already canonical (lowercase, `-` separated) field name.
///
/// Returns `KnownHeader::Unknown` for anything IronTraffic does not itself
/// interpret. The caller MUST have canonicalized the name first with
/// `field::normalize_name_into`; this function does no case folding, so an
/// uppercase name always classifies as `Unknown` even when it names a known
/// header.
///
/// A nested `match` on length and then on the first byte: at most two
/// candidates ever share a (length, first byte) pair over the 51 spellings,
/// so the inner comparison is a byte-slice equality against one or two
/// literals, never a scan.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "one flat classification table over 51 fixed spellings, grouped by length then \
              first byte; splitting it across functions would not shrink it, only hide that \
              it is one table"
)]
pub fn classify(name: &[u8]) -> KnownHeader {
    match name.len() {
        2 => match name.first() {
            Some(b't') => match name {
                b"te" => KnownHeader::Te,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        3 => match name.first() {
            Some(b'a') => match name {
                b"age" => KnownHeader::Age,
                _ => KnownHeader::Unknown,
            },
            Some(b'v') => match name {
                b"via" => KnownHeader::Via,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        4 => match name.first() {
            Some(b'h') => match name {
                b"host" => KnownHeader::Host,
                _ => KnownHeader::Unknown,
            },
            Some(b'd') => match name {
                b"date" => KnownHeader::Date,
                _ => KnownHeader::Unknown,
            },
            Some(b'v') => match name {
                b"vary" => KnownHeader::Vary,
                _ => KnownHeader::Unknown,
            },
            Some(b'e') => match name {
                b"etag" => KnownHeader::Etag,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        5 => match name.first() {
            Some(b'r') => match name {
                b"range" => KnownHeader::Range,
                _ => KnownHeader::Unknown,
            },
            Some(b'a') => match name {
                b"allow" => KnownHeader::Allow,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        6 => match name.first() {
            Some(b'e') => match name {
                b"expect" => KnownHeader::Expect,
                _ => KnownHeader::Unknown,
            },
            Some(b'a') => match name {
                b"accept" => KnownHeader::Accept,
                _ => KnownHeader::Unknown,
            },
            Some(b'c') => match name {
                b"cookie" => KnownHeader::Cookie,
                _ => KnownHeader::Unknown,
            },
            Some(b'o') => match name {
                b"origin" => KnownHeader::Origin,
                _ => KnownHeader::Unknown,
            },
            Some(b's') => match name {
                b"server" => KnownHeader::Server,
                _ => KnownHeader::Unknown,
            },
            Some(b'p') => match name {
                b"pragma" => KnownHeader::Pragma,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        7 => match name.first() {
            Some(b'u') => match name {
                b"upgrade" => KnownHeader::Upgrade,
                _ => KnownHeader::Unknown,
            },
            Some(b't') => match name {
                b"trailer" => KnownHeader::Trailer,
                _ => KnownHeader::Unknown,
            },
            Some(b'r') => match name {
                b"referer" => KnownHeader::Referer,
                _ => KnownHeader::Unknown,
            },
            Some(b'w') => match name {
                b"warning" => KnownHeader::Warning,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        8 => match name.first() {
            Some(b'l') => match name {
                b"location" => KnownHeader::Location,
                _ => KnownHeader::Unknown,
            },
            Some(b'i') => match name {
                b"if-match" => KnownHeader::IfMatch,
                b"if-range" => KnownHeader::IfRange,
                _ => KnownHeader::Unknown,
            },
            Some(b'p') => match name {
                b"priority" => KnownHeader::Priority,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        9 => match name.first() {
            Some(b'f') => match name {
                b"forwarded" => KnownHeader::Forwarded,
                _ => KnownHeader::Unknown,
            },
            Some(b'x') => match name {
                b"x-real-ip" => KnownHeader::XRealIp,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        10 => match name.first() {
            Some(b'c') => match name {
                b"connection" => KnownHeader::Connection,
                _ => KnownHeader::Unknown,
            },
            Some(b'k') => match name {
                b"keep-alive" => KnownHeader::KeepAlive,
                _ => KnownHeader::Unknown,
            },
            Some(b's') => match name {
                b"set-cookie" => KnownHeader::SetCookie,
                _ => KnownHeader::Unknown,
            },
            Some(b'u') => match name {
                b"user-agent" => KnownHeader::UserAgent,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        11 => match name.first() {
            Some(b'r') => match name {
                b"retry-after" => KnownHeader::RetryAfter,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        12 => match name.first() {
            Some(b'c') => match name {
                b"content-type" => KnownHeader::ContentType,
                _ => KnownHeader::Unknown,
            },
            Some(b'm') => match name {
                b"max-forwards" => KnownHeader::MaxForwards,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        13 => match name.first() {
            Some(b'a') => match name {
                b"authorization" => KnownHeader::Authorization,
                _ => KnownHeader::Unknown,
            },
            Some(b'c') => match name {
                b"cache-control" => KnownHeader::CacheControl,
                _ => KnownHeader::Unknown,
            },
            Some(b'i') => match name {
                b"if-none-match" => KnownHeader::IfNoneMatch,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        14 => match name.first() {
            Some(b'c') => match name {
                b"content-length" => KnownHeader::ContentLength,
                _ => KnownHeader::Unknown,
            },
            Some(b'h') => match name {
                b"http2-settings" => KnownHeader::Http2Settings,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        15 => match name.first() {
            Some(b'a') => match name {
                b"accept-encoding" => KnownHeader::AcceptEncoding,
                b"accept-language" => KnownHeader::AcceptLanguage,
                _ => KnownHeader::Unknown,
            },
            Some(b'x') => match name {
                b"x-forwarded-for" => KnownHeader::XForwardedFor,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        16 => match name.first() {
            Some(b'p') => match name {
                b"proxy-connection" => KnownHeader::ProxyConnection,
                _ => KnownHeader::Unknown,
            },
            Some(b'c') => match name {
                b"content-encoding" => KnownHeader::ContentEncoding,
                _ => KnownHeader::Unknown,
            },
            Some(b'x') => match name {
                b"x-forwarded-host" => KnownHeader::XForwardedHost,
                b"x-forwarded-port" => KnownHeader::XForwardedPort,
                _ => KnownHeader::Unknown,
            },
            Some(b'w') => match name {
                b"www-authenticate" => KnownHeader::WwwAuthenticate,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        17 => match name.first() {
            Some(b't') => match name {
                b"transfer-encoding" => KnownHeader::TransferEncoding,
                _ => KnownHeader::Unknown,
            },
            Some(b'i') => match name {
                b"if-modified-since" => KnownHeader::IfModifiedSince,
                _ => KnownHeader::Unknown,
            },
            Some(b'x') => match name {
                b"x-forwarded-proto" => KnownHeader::XForwardedProto,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        // Do not omit 18: dropping it silently declassifies
        // `proxy-authenticate`, which is in the hop-by-hop strip set.
        18 => match name.first() {
            Some(b'p') => match name {
                b"proxy-authenticate" => KnownHeader::ProxyAuthenticate,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        19 => match name.first() {
            Some(b'p') => match name {
                b"proxy-authorization" => KnownHeader::ProxyAuthorization,
                _ => KnownHeader::Unknown,
            },
            Some(b'i') => match name {
                b"if-unmodified-since" => KnownHeader::IfUnmodifiedSince,
                _ => KnownHeader::Unknown,
            },
            _ => KnownHeader::Unknown,
        },
        _ => KnownHeader::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `KnownHeader` variant, `Unknown` first, in declaration order.
    const ALL_HEADERS: [KnownHeader; KNOWN_HEADER_COUNT] = [
        KnownHeader::Unknown,
        KnownHeader::Host,
        KnownHeader::ContentLength,
        KnownHeader::TransferEncoding,
        KnownHeader::Connection,
        KnownHeader::ProxyConnection,
        KnownHeader::KeepAlive,
        KnownHeader::Upgrade,
        KnownHeader::Http2Settings,
        KnownHeader::Trailer,
        KnownHeader::Te,
        KnownHeader::ProxyAuthenticate,
        KnownHeader::ProxyAuthorization,
        KnownHeader::Expect,
        KnownHeader::ContentType,
        KnownHeader::ContentEncoding,
        KnownHeader::Accept,
        KnownHeader::AcceptEncoding,
        KnownHeader::AcceptLanguage,
        KnownHeader::Authorization,
        KnownHeader::Cookie,
        KnownHeader::SetCookie,
        KnownHeader::UserAgent,
        KnownHeader::Referer,
        KnownHeader::Origin,
        KnownHeader::Date,
        KnownHeader::Server,
        KnownHeader::Location,
        KnownHeader::CacheControl,
        KnownHeader::Pragma,
        KnownHeader::Vary,
        KnownHeader::Age,
        KnownHeader::Etag,
        KnownHeader::IfNoneMatch,
        KnownHeader::IfModifiedSince,
        KnownHeader::IfMatch,
        KnownHeader::IfUnmodifiedSince,
        KnownHeader::Range,
        KnownHeader::IfRange,
        KnownHeader::MaxForwards,
        KnownHeader::Forwarded,
        KnownHeader::XForwardedFor,
        KnownHeader::XForwardedProto,
        KnownHeader::XForwardedHost,
        KnownHeader::XForwardedPort,
        KnownHeader::XRealIp,
        KnownHeader::Priority,
        KnownHeader::Via,
        KnownHeader::Warning,
        KnownHeader::Allow,
        KnownHeader::RetryAfter,
        KnownHeader::WwwAuthenticate,
    ];

    #[test]
    fn every_variant_classifies_to_itself() {
        // Exhaustive match: adding a variant to `KnownHeader` without adding
        // an arm here is a compile error, which is what forces this test (and
        // `ALL_HEADERS` above) to be revisited the moment the enum grows,
        // rather than silently continuing to pass over a subset of variants.
        fn ordinal(h: KnownHeader) -> usize {
            match h {
                KnownHeader::Unknown => 0,
                KnownHeader::Host => 1,
                KnownHeader::ContentLength => 2,
                KnownHeader::TransferEncoding => 3,
                KnownHeader::Connection => 4,
                KnownHeader::ProxyConnection => 5,
                KnownHeader::KeepAlive => 6,
                KnownHeader::Upgrade => 7,
                KnownHeader::Http2Settings => 8,
                KnownHeader::Trailer => 9,
                KnownHeader::Te => 10,
                KnownHeader::ProxyAuthenticate => 11,
                KnownHeader::ProxyAuthorization => 12,
                KnownHeader::Expect => 13,
                KnownHeader::ContentType => 14,
                KnownHeader::ContentEncoding => 15,
                KnownHeader::Accept => 16,
                KnownHeader::AcceptEncoding => 17,
                KnownHeader::AcceptLanguage => 18,
                KnownHeader::Authorization => 19,
                KnownHeader::Cookie => 20,
                KnownHeader::SetCookie => 21,
                KnownHeader::UserAgent => 22,
                KnownHeader::Referer => 23,
                KnownHeader::Origin => 24,
                KnownHeader::Date => 25,
                KnownHeader::Server => 26,
                KnownHeader::Location => 27,
                KnownHeader::CacheControl => 28,
                KnownHeader::Pragma => 29,
                KnownHeader::Vary => 30,
                KnownHeader::Age => 31,
                KnownHeader::Etag => 32,
                KnownHeader::IfNoneMatch => 33,
                KnownHeader::IfModifiedSince => 34,
                KnownHeader::IfMatch => 35,
                KnownHeader::IfUnmodifiedSince => 36,
                KnownHeader::Range => 37,
                KnownHeader::IfRange => 38,
                KnownHeader::MaxForwards => 39,
                KnownHeader::Forwarded => 40,
                KnownHeader::XForwardedFor => 41,
                KnownHeader::XForwardedProto => 42,
                KnownHeader::XForwardedHost => 43,
                KnownHeader::XForwardedPort => 44,
                KnownHeader::XRealIp => 45,
                KnownHeader::Priority => 46,
                KnownHeader::Via => 47,
                KnownHeader::Warning => 48,
                KnownHeader::Allow => 49,
                KnownHeader::RetryAfter => 50,
                KnownHeader::WwwAuthenticate => 51,
            }
        }

        for (i, h) in ALL_HEADERS.iter().enumerate() {
            assert_eq!(
                ordinal(*h),
                i,
                "{h:?} sits at position {i} in ALL_HEADERS but has ordinal {}",
                ordinal(*h)
            );
        }

        for h in ALL_HEADERS.iter().filter(|h| **h != KnownHeader::Unknown) {
            assert_eq!(
                classify(h.as_bytes()),
                *h,
                "{h:?} does not classify to itself"
            );
        }
    }

    #[test]
    fn canonical_spellings_are_lowercase_tokens() {
        let mut seen: Vec<&[u8]> = Vec::new();
        for h in ALL_HEADERS.iter().filter(|h| **h != KnownHeader::Unknown) {
            let bytes = h.as_bytes();
            assert!(!bytes.is_empty(), "{h:?} has an empty spelling");
            for &b in bytes {
                assert!(
                    crate::field::name_byte_ok(b),
                    "{h:?}'s spelling contains byte {b:#04x}, not a valid name byte"
                );
                assert!(
                    !b.is_ascii_uppercase(),
                    "{h:?}'s spelling contains an uppercase byte"
                );
            }
            assert!(
                !seen.contains(&bytes),
                "{h:?}'s spelling {bytes:?} is shared with an earlier variant"
            );
            seen.push(bytes);
        }
    }

    #[test]
    fn unknown_cases() {
        for name in [
            &b""[..],
            b"Host",
            b"hos",
            b"hostx",
            b"x-custom-thing",
            b"cookid",
        ] {
            assert_eq!(classify(name), KnownHeader::Unknown, "{name:?}");
        }
    }

    #[test]
    fn count_is_52() {
        assert_eq!(KNOWN_HEADER_COUNT, 52);
        // Both sides are compile-time constants, so a bare `assert!` here is
        // constant-folded and clippy flags it; wrapping it in a `const` block
        // is how you keep the same check without that warning while still
        // pinning the bound this test's name promises.
        const { assert!(KNOWN_HEADER_COUNT <= 63) };
    }

    proptest::proptest! {
        #[test]
        fn prop_classify_is_exact(
            v in proptest::collection::vec(
                proptest::prop_oneof![
                    b'a'..=b'z',
                    proptest::prelude::Just(b'-'),
                    proptest::prelude::any::<u8>(),
                ],
                0..=32,
            )
        ) {
            let k = classify(&v);
            if k != KnownHeader::Unknown {
                assert_eq!(v.as_slice(), k.as_bytes());
            }
        }
    }
}
