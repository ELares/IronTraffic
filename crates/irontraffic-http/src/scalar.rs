// SPDX-License-Identifier: MIT OR Apache-2.0
//! The wire scalar types every parser in this crate speaks in:
//! [`Method`], [`StatusCode`], [`WireVersion`], [`Scheme`], and the
//! sans-IO parse result shape [`ParseStatus`].

use crate::error::RejectReason;
use crate::limits::ClampedLimits;

/// Returns whether `b` is an RFC 9110 Section 5.6.2 `tchar` (a `token`
/// character): one of fifteen punctuation bytes, an ASCII digit, or an
/// ASCII letter.
///
/// `pub(crate)`, not private: issue #23's field-name grammar (`field.rs`,
/// `NAME_OK`) is drawn from this same RFC 9110 Section 5.6.2 `tchar` set,
/// and it derives its table from this function rather than restating the
/// fifteen punctuation bytes a second time. This crate's whole thesis is
/// that there is one parse policy; two independent encodings of one grammar
/// is how they drift.
pub(crate) const fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    ) || b.is_ascii_alphanumeric()
}

/// A request method. The nine methods RFC 9110 defines get a variant;
/// anything else is an `Other` token of at most `Limits::max_method_bytes`
/// bytes, stored inline. Methods are case sensitive (RFC 9110 Section 9.1):
/// `get` is not `GET`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
    /// `CONNECT`.
    Connect,
    /// `OPTIONS`.
    Options,
    /// `TRACE`.
    Trace,
    /// `PATCH`.
    Patch,
    /// Any other syntactically valid method token.
    Other(MethodToken),
}

impl Method {
    /// Parses a method token. Case sensitive per RFC 9110 Section 9.1.
    ///
    /// Order matters here and is deliberate (see D5 in the crate's decision
    /// record): the structural length cap runs first and unconditionally,
    /// before anything else, because a 17-byte worst case rejects in under
    /// 1 ns that way versus paying for an O(n) `tchar` scan on
    /// attacker-chosen input if the scan ran first. `limits.max_method_bytes`
    /// is then consulted ONLY for an extension token, matching its own doc
    /// ("maximum bytes of an extension method token"): the nine known
    /// methods are never subject to it.
    ///
    /// # Errors
    /// `MethodInvalid` if empty or containing a non-`tchar` byte;
    /// `MethodTooLong` if longer than `MethodToken::CAP` (16) bytes, or, for
    /// an extension token specifically, longer than `limits.max_method_bytes`.
    pub fn parse(raw: &[u8], limits: &ClampedLimits) -> Result<Method, RejectReason> {
        if raw.is_empty() {
            return Err(RejectReason::MethodInvalid);
        }

        // Step 1: the structural cap, unconditional and first. Load bearing
        // for the DoS defense; see the doc comment above and D5.
        if raw.len() > MethodToken::CAP {
            return Err(RejectReason::MethodTooLong);
        }

        // Step 2: the nine known methods, matched before any scan.
        match raw {
            b"GET" => Ok(Method::Get),
            b"HEAD" => Ok(Method::Head),
            b"POST" => Ok(Method::Post),
            b"PUT" => Ok(Method::Put),
            b"DELETE" => Ok(Method::Delete),
            b"CONNECT" => Ok(Method::Connect),
            b"OPTIONS" => Ok(Method::Options),
            b"TRACE" => Ok(Method::Trace),
            b"PATCH" => Ok(Method::Patch),
            _ => {
                // Step 3: the extension-token-only operator limit. This is
                // the ONLY place `max_method_bytes` is read; the known
                // methods above never see it.
                if raw.len() > limits.max_method_bytes as usize {
                    return Err(RejectReason::MethodTooLong);
                }

                // Step 4: the `tchar` scan, always bounded to `CAP` (16)
                // bytes by step 1.
                for &b in raw {
                    if !is_tchar(b) {
                        return Err(RejectReason::MethodInvalid);
                    }
                }

                // `raw.len() <= MethodToken::CAP`, proven by step 1, so this
                // copy always fits and never touches an uninitialized slot.
                let mut bytes = [0_u8; MethodToken::CAP];
                for (dst, &src) in bytes.iter_mut().zip(raw.iter()) {
                    *dst = src;
                }
                // D8: computed once from the already-bounded length instead
                // of accumulated one `saturating_add` per byte inside the
                // copy loop above, which LLVM could not fold away even under
                // `lto = "fat"`.
                let len = u8::try_from(raw.len()).unwrap_or(0); // <= CAP == 16, proven above
                Ok(Method::Other(MethodToken { bytes, len }))
            }
        }
    }

    /// The method as ASCII bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Method::Get => b"GET",
            Method::Head => b"HEAD",
            Method::Post => b"POST",
            Method::Put => b"PUT",
            Method::Delete => b"DELETE",
            Method::Connect => b"CONNECT",
            Method::Options => b"OPTIONS",
            Method::Trace => b"TRACE",
            Method::Patch => b"PATCH",
            Method::Other(token) => token.as_bytes(),
        }
    }

    /// True for `CONNECT`. Framing rules differ for it, so callers ask by
    /// name.
    #[must_use]
    pub const fn is_connect(&self) -> bool {
        matches!(self, Method::Connect)
    }

    /// True for `HEAD`. Response framing rules differ for it.
    #[must_use]
    pub const fn is_head(&self) -> bool {
        matches!(self, Method::Head)
    }
}

/// An extension method token: at most `MethodToken::CAP` (16) bytes of
/// RFC 9110 `tchar`, stored inline, never heap allocated.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct MethodToken {
    bytes: [u8; MethodToken::CAP],
    len: u8,
}

impl MethodToken {
    /// The inline capacity of a method token, in bytes. Every effective
    /// `Limits::max_method_bytes` is clamped to this value.
    pub const CAP: usize = 16;

    /// The token as ASCII bytes. Never longer than `CAP`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// A status code in the range 100 to 599 inclusive.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusCode(u16);

impl StatusCode {
    /// Constructs a status code, or `None` outside 100 to 599 inclusive.
    #[must_use]
    pub const fn from_u16(v: u16) -> Option<StatusCode> {
        if matches!(v, 100..=599) {
            Some(StatusCode(v))
        } else {
            None
        }
    }

    /// The numeric value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// True for 100 to 199 inclusive.
    #[must_use]
    pub const fn is_interim(self) -> bool {
        matches!(self.0, 100..=199)
    }

    /// `100 Continue`.
    pub const CONTINUE: StatusCode = StatusCode(100);
    /// `200 OK`.
    pub const OK: StatusCode = StatusCode(200);
    /// `204 No Content`.
    pub const NO_CONTENT: StatusCode = StatusCode(204);
    /// `304 Not Modified`.
    pub const NOT_MODIFIED: StatusCode = StatusCode(304);
    /// `400 Bad Request`.
    pub const BAD_REQUEST: StatusCode = StatusCode(400);
    /// `414 URI Too Long`.
    pub const URI_TOO_LONG: StatusCode = StatusCode(414);
    /// `417 Expectation Failed`.
    pub const EXPECTATION_FAILED: StatusCode = StatusCode(417);
    /// `431 Request Header Fields Too Large`.
    pub const HEADERS_TOO_LARGE: StatusCode = StatusCode(431);
    /// `500 Internal Server Error`.
    pub const INTERNAL_ERROR: StatusCode = StatusCode(500);
    /// `501 Not Implemented`.
    pub const NOT_IMPLEMENTED: StatusCode = StatusCode(501);
    /// `502 Bad Gateway`.
    pub const BAD_GATEWAY: StatusCode = StatusCode(502);
    /// `505 HTTP Version Not Supported`.
    pub const VERSION_NOT_SUPPORTED: StatusCode = StatusCode(505);

    /// The canonical reason phrase for this status code, or an empty slice
    /// when the code has no standard reason (RFC 9110 Section 15).
    ///
    /// Every code in the 100-to-599 range has a defined phrase in the
    /// registry; the empty slice is returned only for codes outside that
    /// range, which this type's constructor already refuses to build.
    #[must_use]
    pub const fn canonical_reason(self) -> &'static [u8] {
        match self.0 {
            100 => b"Continue",
            101 => b"Switching Protocols",
            200 => b"OK",
            201 => b"Created",
            202 => b"Accepted",
            203 => b"Non-Authoritative Information",
            204 => b"No Content",
            205 => b"Reset Content",
            206 => b"Partial Content",
            300 => b"Multiple Choices",
            301 => b"Moved Permanently",
            302 => b"Found",
            303 => b"See Other",
            304 => b"Not Modified",
            305 => b"Use Proxy",
            307 => b"Temporary Redirect",
            308 => b"Permanent Redirect",
            400 => b"Bad Request",
            401 => b"Unauthorized",
            402 => b"Payment Required",
            403 => b"Forbidden",
            404 => b"Not Found",
            405 => b"Method Not Allowed",
            406 => b"Not Acceptable",
            407 => b"Proxy Authentication Required",
            408 => b"Request Timeout",
            409 => b"Conflict",
            410 => b"Gone",
            411 => b"Length Required",
            412 => b"Precondition Failed",
            413 => b"Content Too Large",
            414 => b"URI Too Long",
            415 => b"Unsupported Media Type",
            416 => b"Range Not Satisfiable",
            417 => b"Expectation Failed",
            421 => b"Misdirected Request",
            422 => b"Unprocessable Content",
            425 => b"Too Early",
            426 => b"Upgrade Required",
            429 => b"Too Many Requests",
            431 => b"Request Header Fields Too Large",
            451 => b"Unavailable For Legal Reasons",
            500 => b"Internal Server Error",
            501 => b"Not Implemented",
            502 => b"Bad Gateway",
            503 => b"Service Unavailable",
            504 => b"Gateway Timeout",
            505 => b"HTTP Version Not Supported",
            506 => b"Variant Also Negotiates",
            507 => b"Insufficient Storage",
            508 => b"Loop Detected",
            510 => b"Not Extended",
            511 => b"Network Authentication Required",
            _ => b"",
        }
    }
}

/// The wire protocol a message arrived on. Observability and framing rules
/// only; it never selects a code path that changes what a request *means*.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WireVersion {
    /// HTTP/1.0.
    Http10,
    /// HTTP/1.1.
    Http11,
    /// HTTP/2.
    H2,
    /// HTTP/3.
    H3,
}

impl WireVersion {
    /// True for `H2` and `H3`: the protocols where a header section is a
    /// decoded field list rather than a text block, and where uppercase
    /// names are malformed.
    #[must_use]
    pub const fn is_multiplexed(self) -> bool {
        matches!(self, WireVersion::H2 | WireVersion::H3)
    }
}

/// The scheme a request was made under.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http`.
    Http,
    /// `https`.
    Https,
}

impl Scheme {
    /// The default port for the scheme: 80 for http, 443 for https.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }

    /// The scheme as lowercase ASCII bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Scheme::Http => b"http",
            Scheme::Https => b"https",
        }
    }
}

/// The result of a sans-IO parse over a possibly incomplete buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ParseStatus<T> {
    /// A complete item was parsed and occupies the first `consumed` bytes of
    /// the input. Construct this ONLY through [`ParseStatus::complete`];
    /// the fields are private so that an invalid `consumed` (zero, or past
    /// the end of the input) cannot be expressed, matching D4 in the crate's
    /// decision record.
    Complete {
        /// The parsed value.
        value: T,
        /// The number of leading bytes of the input the value occupies.
        consumed: usize,
    },
    /// Not enough bytes yet: the input did not contain a complete item. The
    /// caller MUST call again from offset zero of the SAME buffer once more
    /// bytes have been appended to it.
    ///
    /// Parsers in this crate hold NO position state across calls (issue #34
    /// is explicit: no cursor, no partial-state enum, nothing that survives
    /// between one `Partial` and the next call). `Partial` is a unit
    /// variant precisely because there is nothing to carry. Re-running from
    /// offset zero is therefore not free in the general case, but total scan
    /// work across all re-runs of one message is bounded by a scan budget
    /// the CALLER owns, not by any hint riding on this value. `h1-head-parser`
    /// (#34) owns that budget and its tests.
    Partial,
}

impl<T> ParseStatus<T> {
    /// Constructs `Complete`, the only way to do so from outside this
    /// module. Checks, in debug builds (which includes every fuzz build, so
    /// this is exercised at millions of cases per minute rather than only in
    /// prose) that `consumed` occupies a non-empty prefix of `input_len`
    /// bytes: `Complete { value, consumed: usize::MAX }` and
    /// `Complete { value, consumed: 0 }` both used to compile and pass with
    /// public fields; neither can be built through this constructor without
    /// panicking in debug.
    #[must_use]
    pub fn complete(value: T, consumed: usize, input_len: usize) -> ParseStatus<T> {
        debug_assert!(
            consumed > 0 && consumed <= input_len,
            "ParseStatus::complete: consumed ({consumed}) must be in 1..=input_len ({input_len})"
        );
        ParseStatus::Complete { value, consumed }
    }

    /// The number of leading input bytes consumed, or `None` for `Partial`.
    #[must_use]
    pub const fn consumed(&self) -> Option<usize> {
        match self {
            ParseStatus::Complete { consumed, .. } => Some(*consumed),
            ParseStatus::Partial => None,
        }
    }

    /// Unwraps `Complete` into its parsed value and consumed-byte count, or
    /// `None` for `Partial`.
    #[must_use]
    pub fn into_complete(self) -> Option<(T, usize)> {
        match self {
            ParseStatus::Complete { value, consumed } => Some((value, consumed)),
            ParseStatus::Partial => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use proptest::strategy::Strategy;

    const TCHARS: [u8; 77] = *b"!#$%&'*+-.^_`|~0123456789\
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const _: () = assert!(TCHARS.len() == 77);

    #[test]
    fn parse_known_methods() {
        let known: [(&[u8], Method); 9] = [
            (b"GET", Method::Get),
            (b"HEAD", Method::Head),
            (b"POST", Method::Post),
            (b"PUT", Method::Put),
            (b"DELETE", Method::Delete),
            (b"CONNECT", Method::Connect),
            (b"OPTIONS", Method::Options),
            (b"TRACE", Method::Trace),
            (b"PATCH", Method::Patch),
        ];
        for (raw, expected) in known {
            assert_eq!(Method::parse(raw, &Limits::DEFAULT.clamped()), Ok(expected));
        }

        match Method::parse(b"get", &Limits::DEFAULT.clamped()) {
            Ok(Method::Other(token)) => assert_eq!(token.as_bytes(), b"get"),
            other => panic!("expected Method::Other(\"get\"), got {other:?}"),
        }
    }

    #[test]
    fn method_parse_is_case_sensitive_for_post_too() {
        // D9: case sensitivity was pinned for `GET` only; `b"post"` parsing
        // to `Method::Post` survived every mutation the tests lens tried.
        match Method::parse(b"post", &Limits::DEFAULT.clamped()) {
            Ok(Method::Other(token)) => assert_eq!(token.as_bytes(), b"post"),
            other => panic!("expected Method::Other(\"post\"), got {other:?}"),
        }
    }

    #[test]
    fn reject_bad_methods() {
        assert_eq!(
            Method::parse(b"", &Limits::DEFAULT.clamped()),
            Err(RejectReason::MethodInvalid)
        );
        assert_eq!(
            Method::parse(b"GET ", &Limits::DEFAULT.clamped()),
            Err(RejectReason::MethodInvalid)
        );
        assert_eq!(
            Method::parse(b"G\xffT", &Limits::DEFAULT.clamped()),
            Err(RejectReason::MethodInvalid)
        );
        assert_eq!(
            Method::parse(b"GE:T", &Limits::DEFAULT.clamped()),
            Err(RejectReason::MethodInvalid)
        );
        assert_eq!(
            Method::parse(b"AAAAAAAAAAAAAAAAA", &Limits::DEFAULT.clamped()),
            Err(RejectReason::MethodTooLong)
        );

        let widened = Limits {
            max_method_bytes: 64,
            ..Limits::DEFAULT
        }
        .clamped();
        assert_eq!(
            Method::parse(b"AAAAAAAAAAAAAAAAA", &widened),
            Err(RejectReason::MethodTooLong)
        );
    }

    #[test]
    fn method_too_long_takes_priority_over_tchar_scan() {
        // D9: parse-step ordering was unobservable, because the only
        // 17-byte input the old test used (`b"AAAAAAAAAAAAAAAAA"`) is all
        // valid `tchar`, so a mutation that ran the `tchar` scan BEFORE the
        // structural length cap still produced `MethodTooLong` and passed.
        // 16 valid bytes plus one invalid byte distinguishes the two
        // orders: the correct order (cap first, unconditional) rejects this
        // as `MethodTooLong` without the scan ever running; a swapped order
        // would see the invalid byte first and report `MethodInvalid`
        // instead.
        let raw = b"AAAAAAAAAAAAAAAA\xff";
        assert_eq!(raw.len(), 17);
        assert_eq!(
            Method::parse(raw, &Limits::DEFAULT.clamped()),
            Err(RejectReason::MethodTooLong)
        );
    }

    #[test]
    fn max_method_bytes_zero_forbids_extension_tokens_but_not_known_methods() {
        // D9: `max_method_bytes: 0` treated as unlimited survived every
        // mutation. `Limits`'s own doc forbids any field ever meaning
        // "unlimited" via a sentinel; `0` must mean exactly zero.
        let no_extensions = Limits {
            max_method_bytes: 0,
            ..Limits::DEFAULT
        }
        .clamped();
        assert_eq!(
            Method::parse(b"X", &no_extensions),
            Err(RejectReason::MethodTooLong)
        );
        // The nine known methods are matched before `max_method_bytes` is
        // consulted at all (D5, step 2 before step 3), so they are
        // unaffected by this limit.
        assert_eq!(Method::parse(b"GET", &no_extensions), Ok(Method::Get));
    }

    #[test]
    fn method_predicates() {
        // D9: `is_connect` and `is_head` were untested entirely.
        assert!(Method::Connect.is_connect());
        assert!(!Method::Get.is_connect());
        assert!(Method::Head.is_head());
        assert!(!Method::Get.is_head());
    }

    #[test]
    fn status_code_boundaries() {
        assert!(StatusCode::from_u16(99).is_none());
        assert!(StatusCode::from_u16(100).is_some());
        assert!(StatusCode::from_u16(599).is_some());
        assert!(StatusCode::from_u16(600).is_none());
        assert!(StatusCode::from_u16(0).is_none());
        assert!(StatusCode::from_u16(u16::MAX).is_none());
        assert!(StatusCode::CONTINUE.is_interim());
        assert!(!StatusCode::OK.is_interim());
    }

    #[test]
    fn status_code_named_constants() {
        // D9: `NO_CONTENT`, `NOT_MODIFIED`, `CONTINUE` and `OK` were
        // untested entirely.
        assert_eq!(StatusCode::CONTINUE.as_u16(), 100);
        assert_eq!(StatusCode::OK.as_u16(), 200);
        assert_eq!(StatusCode::NO_CONTENT.as_u16(), 204);
        assert_eq!(StatusCode::NOT_MODIFIED.as_u16(), 304);
    }

    #[test]
    fn wire_version_is_multiplexed() {
        // D9: `is_multiplexed` was untested entirely.
        assert!(WireVersion::H2.is_multiplexed());
        assert!(WireVersion::H3.is_multiplexed());
        assert!(!WireVersion::Http10.is_multiplexed());
        assert!(!WireVersion::Http11.is_multiplexed());
    }

    #[test]
    fn scheme_default_port_and_as_bytes() {
        // D9: `default_port` and `Scheme::as_bytes` were untested entirely.
        assert_eq!(Scheme::Http.default_port(), 80);
        assert_eq!(Scheme::Https.default_port(), 443);
        assert_eq!(Scheme::Http.as_bytes(), b"http");
        assert_eq!(Scheme::Https.as_bytes(), b"https");
    }

    #[test]
    fn parse_status_complete_checked_construction() {
        let status = ParseStatus::complete(7_i32, 3, 5);
        assert_eq!(status.consumed(), Some(3));
        assert_eq!(status.into_complete(), Some((7, 3)));
        let partial: ParseStatus<i32> = ParseStatus::Partial;
        assert_eq!(partial.consumed(), None);
        assert_eq!(partial.into_complete(), None);
    }

    #[test]
    #[should_panic(expected = "consumed")]
    fn parse_status_complete_rejects_zero_consumed() {
        let _ = ParseStatus::<i32>::complete(0, 0, 5);
    }

    #[test]
    #[should_panic(expected = "consumed")]
    fn parse_status_complete_rejects_consumed_past_input_len() {
        let _ = ParseStatus::<i32>::complete(0, 6, 5);
    }

    proptest::proptest! {
        #[test]
        fn method_token_roundtrip(
            v in proptest::collection::vec(proptest::sample::select(&TCHARS[..]), 1..=16)
        ) {
            match Method::parse(&v, &Limits::DEFAULT.clamped()) {
                Ok(m) => assert_eq!(m.as_bytes(), &v[..]),
                Err(e) => panic!("rejected {v:?}: {e:?}"),
            }
        }

        #[test]
        fn is_tchar_rejects_every_non_tchar_byte(
            b in proptest::prelude::any::<u8>().prop_filter(
                "must not be a tchar byte",
                |b| !TCHARS.contains(b),
            )
        ) {
            // D9: `is_tchar` was pinned by four positive bytes only; adding
            // CR, LF or NUL to the accepted set survived every mutation.
            // This is the negative side: every byte outside the 77-byte
            // `TCHARS` set must be rejected.
            assert!(!is_tchar(b));
        }
    }
}
