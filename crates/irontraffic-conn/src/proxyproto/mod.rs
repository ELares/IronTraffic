// SPDX-License-Identifier: MIT OR Apache-2.0

//! The PROXY protocol v1 and v2 parser.
//!
//! **This parser never sniffs and never falls back.** The PROXY protocol specification is
//! explicit: "The receiver MUST be configured to only receive the protocol described in this
//! specification and MUST not try to guess whether the protocol header is present or not."
//! [`ProxyHeader::parse`] is used ONLY on a listener explicitly configured for PROXY
//! protocol, and ONLY after the caller has checked the socket's peer address against that
//! listener's `trusted_cidrs`. If the first bytes are not a valid v1 or v2 header, the
//! caller MUST close the connection; there is no fallback to raw HTTP. A listener that
//! sniffs lets an attacker who can reach it choose whether to be trusted.
//!
//! Conversely, a listener NOT configured for PROXY protocol never calls this parser, so a
//! header sent to it is just the first bytes of a malformed HTTP request, refused by the
//! HTTP parser. There is no auto-detection anywhere in this module.
//!
//! **Bounded allocation is the security property.** A v2 header can declare a length of
//! 65535. This parser never allocates a buffer of that size on seeing the declaration; it
//! returns [`ParseStatus::Partial`] until that many bytes have actually arrived in the
//! caller's own buffer, and it never reads past what has arrived. Every function in this
//! module and its two submodules allocates nothing: parsing happens entirely in place over
//! the caller's borrowed `&[u8]`.
//!
//! **Two caller obligations this parser cannot enforce.** [`ProxyHeader::parse`] takes no
//! clock and no size policy; it is the caller's job to:
//! 1. Apply `accept_to_first_byte` to the first byte and `header_read_timeout` (10 s) to the
//!    completion of the header, closing the connection on expiry. A peer that declares 65535
//!    bytes and sends one byte per minute holds a connection indefinitely otherwise, and
//!    `Partial` will keep saying "more could complete it" forever. Being inside
//!    `trusted_cidrs` is not a reason to skip this: a trusted network position is exactly
//!    what a compromised sidecar has.
//! 2. Bound the read buffer for this phase at 65551 bytes (16 + 65535, the v2 worst case;
//!    107 bytes suffices for v1) and stop growing it once `parse` has said `Partial` at that
//!    size, because at that point the bytes cannot be a valid header either.
//!
//! See the "PROXY protocol" subsection of `docs/THREAT-MODEL.md` section 5 for the full
//! trust-plane accounting.

use std::net::SocketAddr;

use irontraffic_http::ParseStatus;

mod v1;
mod v2;

pub mod encode;

/// The 12-byte v2 signature (haproxy.org PROXY protocol specification section 2.2):
/// `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`.
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// The literal v1 prefix, 6 bytes including the trailing space.
const V1_PREFIX: [u8; 6] = *b"PROXY ";

/// A parsed PROXY protocol header.
///
/// Reports what the header CLAIMED. Whether the sender was allowed to claim it is the
/// caller's decision, made from the socket peer address against the listener's
/// `trusted_cidrs` BEFORE this parser is called. This type deliberately takes no address
/// argument so that the trust check cannot be mistaken for something the parser does.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProxyHeader {
    /// v1 or v2.
    pub version: ProxyVersion,
    /// The addresses, or `Unspec` for `UNKNOWN` (v1) and the LOCAL command (v2).
    pub addrs: ProxyAddrs,
    /// Total bytes of the header, so the caller can advance its buffer.
    ///
    /// This is ALWAYS equal to the `consumed` of the enclosing `Complete` inside the
    /// `ParseStatus::Complete` this parser returns. Both exist because this field makes the
    /// value self-describing once it has been moved out of the `ParseStatus`, and
    /// `ParseStatus` is the shape every other parser in the product returns. Every
    /// construction site in `v1.rs` and `v2.rs` carries a `debug_assert_eq!` checking the
    /// equality, and [`consumed_points_at_the_next_byte`] checks it at the boundary too.
    pub consumed: usize,
}

/// Which wire format the header used.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProxyVersion {
    /// The human readable v1 text format.
    V1,
    /// The binary v2 format.
    V2,
}

/// The address information a header carried.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProxyAddrs {
    /// No usable address: v1 `UNKNOWN`, a v2 LOCAL command, or a v2 `AF_UNSPEC`/UDP/`AF_UNIX`
    /// family. The caller uses the socket peer address instead.
    Unspec,
    /// A source and destination address pair.
    Tcp {
        /// The claimed source address.
        src: SocketAddr,
        /// The claimed destination address.
        dst: SocketAddr,
    },
}

/// Why a PROXY protocol header was refused.
///
/// Distinct from `RejectReason` because these faults happen before any HTTP message
/// exists, and every one of them closes the connection with no response at all: there is
/// nobody to answer in a protocol we have not established. Never send this, its label, or
/// any diagnostic to the peer: the connection closes with no bytes written.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// The bytes are neither a v1 prefix nor a v2 signature.
    NotAProxyHeader,
    /// v1: no CRLF within 107 bytes.
    V1LineTooLong,
    /// v1: the protocol token is not `TCP4`, `TCP6` or `UNKNOWN`.
    V1BadProtocol,
    /// v1: an address, a port, or the field layout is malformed.
    V1BadField,
    /// v1: the line ended with a bare LF rather than CRLF.
    V1BareLf,
    /// v2: the version nibble is not 0x2.
    V2BadVersion,
    /// v2: the command nibble is neither LOCAL (0x0) nor PROXY (0x1).
    V2BadCommand,
    /// v2: the family and protocol byte is not one we support.
    V2BadFamily,
    /// v2: the declared length is too small for the declared family's address block.
    V2LengthTooSmall,
    /// v2: a TLV's declared length runs past the end of the address block.
    V2BadTlv,
}

impl ProxyHeader {
    /// Parses a v1 or v2 header from the front of `buf`.
    ///
    /// PRECONDITION: the caller has already verified that the socket peer address is in
    /// the listener's `trusted_cidrs`, and the listener is explicitly configured for PROXY
    /// protocol. This function performs NO trust check and takes no address, so it cannot
    /// be mistaken for one.
    ///
    /// Returns `Partial` only when more bytes could complete a valid header. A first byte
    /// that can never begin one gives `NotAProxyHeader` immediately, and the caller MUST
    /// close the connection: there is no fallback to raw HTTP.
    ///
    /// Allocates nothing. Never reads past `buf.len()`, whatever a v2 header declares.
    ///
    /// # Errors
    /// Every `ProxyError` variant.
    pub fn parse(buf: &[u8]) -> Result<ParseStatus<ProxyHeader>, ProxyError> {
        // Dispatch commits to a format the moment `buf` has enough bytes to prove it,
        // regardless of how much MORE `buf` already holds: a 50-byte buffer whose first 6
        // bytes are `PROXY ` is unambiguously v1 even though it is far short of v2's
        // 12-byte signature length, so it must not be re-tested against the shorter-only
        // "is buf a prefix of the target" rule below.
        //
        // A literal reading of the specification's own step-by-step dispatch ("if
        // buf.len() < 12, check whether the available bytes are a PREFIX of either
        // signature") has a gap here: once `buf` is longer than 6 bytes, it can never
        // again be "a prefix of" the 6-byte string `PROXY `, even when its first 6 bytes
        // match it exactly and the rest is simply not enough yet to reach a CRLF. Taken
        // literally, a v1 header delivered as a 7 to 11 byte first segment (impossible to
        // avoid on a small MTU or an immediate partial write, and always true early in any
        // v1 header, since the shortest complete one is 15 bytes) would be refused as
        // `NotAProxyHeader` instead of reported `Partial`, closing a legitimate connection.
        // That contradicts this module's own invariant that `Partial` is returned whenever
        // more bytes could still complete a valid header (see the module doc comment and
        // `ProxyHeader::parse`'s own doc above). The dispatch below fixes that: it commits
        // to v1 as soon as the 6-byte prefix matches, at any total length, and only falls
        // back to the prefix-of-either check for buffers too short to have committed to
        // either format yet. Filed as a foundation issue against the specification text
        // (this module cannot edit its own issue); see the implementation report.
        if buf.get(..V2_SIGNATURE.len()) == Some(&V2_SIGNATURE[..]) {
            return v2::parse(buf);
        }
        if buf.get(..V1_PREFIX.len()) == Some(&V1_PREFIX[..]) {
            return v1::parse(buf);
        }
        if V2_SIGNATURE[..].starts_with(buf) || V1_PREFIX[..].starts_with(buf) {
            return Ok(ParseStatus::Partial);
        }
        Err(ProxyError::NotAProxyHeader)
    }

    /// The source address when the header carried one.
    #[must_use]
    pub const fn src(&self) -> Option<SocketAddr> {
        match self.addrs {
            ProxyAddrs::Tcp { src, .. } => Some(src),
            ProxyAddrs::Unspec => None,
        }
    }

    /// The destination address when the header carried one.
    #[must_use]
    pub const fn dst(&self) -> Option<SocketAddr> {
        match self.addrs {
            ProxyAddrs::Tcp { dst, .. } => Some(dst),
            ProxyAddrs::Unspec => None,
        }
    }
}

impl ProxyError {
    /// The stable, `snake_case` metric label for this failure.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            ProxyError::NotAProxyHeader => "not_a_proxy_header",
            ProxyError::V1LineTooLong => "v1_line_too_long",
            ProxyError::V1BadProtocol => "v1_bad_protocol",
            ProxyError::V1BadField => "v1_bad_field",
            ProxyError::V1BareLf => "v1_bare_lf",
            ProxyError::V2BadVersion => "v2_bad_version",
            ProxyError::V2BadCommand => "v2_bad_command",
            ProxyError::V2BadFamily => "v2_bad_family",
            ProxyError::V2LengthTooSmall => "v2_length_too_small",
            ProxyError::V2BadTlv => "v2_bad_tlv",
        }
    }

    /// Every variant, for the label-uniqueness test.
    pub const ALL: [ProxyError; 10] = [
        ProxyError::NotAProxyHeader,
        ProxyError::V1LineTooLong,
        ProxyError::V1BadProtocol,
        ProxyError::V1BadField,
        ProxyError::V1BareLf,
        ProxyError::V2BadVersion,
        ProxyError::V2BadCommand,
        ProxyError::V2BadFamily,
        ProxyError::V2LengthTooSmall,
        ProxyError::V2BadTlv,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::Strategy;

    /// Edge cases 1 through 4: dispatch on too-short input and on input that can never be
    /// either format.
    #[test]
    fn dispatch_and_partial() {
        // Edge 1.
        assert_eq!(ProxyHeader::parse(b""), Ok(ParseStatus::Partial));
        // Edge 2.
        assert_eq!(ProxyHeader::parse(b"P"), Ok(ParseStatus::Partial));
        assert_eq!(ProxyHeader::parse(b"PRO"), Ok(ParseStatus::Partial));
        assert_eq!(ProxyHeader::parse(b"PROXY "), Ok(ParseStatus::Partial));
        // Edge 3: a v2 signature prefix.
        assert_eq!(
            ProxyHeader::parse(b"\x0d\x0a\x0d"),
            Ok(ParseStatus::Partial)
        );
        // Edge 4: raw HTTP on a PROXY-protocol listener refuses immediately, never Partial.
        assert_eq!(
            ProxyHeader::parse(b"GET / HTTP/1.1"),
            Err(ProxyError::NotAProxyHeader)
        );

        // The fix described above the dispatch: a v1 header whose first segment is longer
        // than the 6-byte `PROXY ` prefix but still short of a complete line must be
        // `Partial`, not `NotAProxyHeader`, because more bytes could still complete it.
        for len in 7..=11 {
            let partial = &b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"[..len];
            assert_eq!(
                ProxyHeader::parse(partial),
                Ok(ParseStatus::Partial),
                "a {len}-byte prefix of a valid v1 header must be Partial"
            );
        }
    }

    /// Edge case 36, for both versions: two headers back to back, `parse` consumes only the
    /// first and `consumed` points at the second.
    #[test]
    fn consumed_points_at_the_next_byte() {
        let mut buf = b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n".to_vec();
        let first_len = buf.len();
        let second = b"PROXY UNKNOWN\r\n";
        buf.extend_from_slice(second);

        match ProxyHeader::parse(&buf) {
            Ok(ParseStatus::Complete { value, consumed }) => {
                assert_eq!(consumed, first_len);
                assert_eq!(value.consumed, consumed);
                assert_eq!(buf.get(consumed..), Some(&second[..]));
            }
            other => panic!("expected Complete for the first v1 header, got {other:?}"),
        }

        let one: [u8; 16] = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x20, 0x00,
            0x00, 0x00,
        ];
        let mut buf2 = one.to_vec();
        buf2.extend_from_slice(&one);

        match ProxyHeader::parse(&buf2) {
            Ok(ParseStatus::Complete { value, consumed }) => {
                assert_eq!(consumed, 16);
                assert_eq!(value.consumed, consumed);
                assert_eq!(buf2.get(consumed..), Some(&one[..]));
            }
            other => panic!("expected Complete for the first v2 header, got {other:?}"),
        }
    }

    /// `ProxyError::ALL` has 10 entries with unique, non-empty, `snake_case` labels, and
    /// `ALL` is exhaustive over every variant.
    #[test]
    fn error_labels_are_unique() {
        // An exhaustive match: adding a variant to `ProxyError` without adding an arm here
        // is a compile error, which is what keeps this test honest as the enum grows (the
        // same device `irontraffic-http`'s `RejectReason::all_contains_every_variant` uses).
        fn position_of(e: ProxyError) -> usize {
            match e {
                ProxyError::NotAProxyHeader => 0,
                ProxyError::V1LineTooLong => 1,
                ProxyError::V1BadProtocol => 2,
                ProxyError::V1BadField => 3,
                ProxyError::V1BareLf => 4,
                ProxyError::V2BadVersion => 5,
                ProxyError::V2BadCommand => 6,
                ProxyError::V2BadFamily => 7,
                ProxyError::V2LengthTooSmall => 8,
                ProxyError::V2BadTlv => 9,
            }
        }

        // Independent oracle: derive the expected label from the `Debug` name rather than
        // comparing `metric_label` to itself, so a swap between two variants' labels (which
        // a plain uniqueness check cannot see, since the SET of labels is unchanged by a
        // swap) shows up as a mismatch. This is the same device that caught a real
        // `PathEncodedDot`/`PathEncodedSlash` label swap in `RejectReason`'s own tests.
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

        assert_eq!(ProxyError::ALL.len(), 10);

        let positions: Vec<usize> = ProxyError::ALL.iter().copied().map(position_of).collect();
        assert_eq!(positions, (0..10).collect::<Vec<usize>>());

        for reason in ProxyError::ALL {
            let want = snake_case_of_debug_name(&format!("{reason:?}"));
            assert_eq!(
                reason.metric_label(),
                want,
                "{reason:?}'s metric label diverges from its own Debug name"
            );
        }

        let mut labels: Vec<&str> = ProxyError::ALL.iter().map(|e| e.metric_label()).collect();
        labels.sort_unstable();
        for pair in labels.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate metric label: {}", pair[0]);
        }
        for label in ProxyError::ALL.iter().map(|e| e.metric_label()) {
            assert!(!label.is_empty());
            assert!(
                label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{label} has a byte outside a-z, 0-9, _"
            );
            assert!(
                !label.starts_with('_') && !label.ends_with('_'),
                "{label} starts or ends with _"
            );
        }
    }

    // Edge case 38 ("concurrent access: the parser is a free function over a borrowed
    // slice") is a property of `ProxyHeader::parse`'s signature, not of any call sequence:
    // it takes `buf: &[u8]` and touches no shared, mutable state anywhere in its call
    // graph (this module, `v1.rs` and `v2.rs` contain no `static`, no interior mutability,
    // and no I/O), so there is nothing a concurrent call could race with. There is
    // deliberately no test for it, matching the acceptance criteria's own accounting.

    fn valid_v1_header() -> Vec<u8> {
        b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n".to_vec()
    }

    fn valid_v2_header() -> Vec<u8> {
        let mut v = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11,
            0x00, 0x0C,
        ];
        v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0, 2]);
        v
    }

    /// Builds a valid v1 or v2 header (chosen by `use_v1`) and mutates one byte of it,
    /// selected by `idx_seed` modulo the header's length. Factored out of the `proptest!`
    /// invocation below, whose `in <strategy>` clause is parsed for its OWN, non-Rust `in`
    /// syntax before the real test body: a closure literal (with its own `{ ... }`) inlined
    /// there would give a brace-depth scanner a decoy body to find before the genuine one,
    /// which is exactly the failure mode `scripts/invariant-lints.sh`'s own module doc
    /// warns about for other constructs. Every existing `prop_oneof!`/`prop_map` use
    /// elsewhere in this workspace (for example `irontraffic-config`'s `model.rs`) keeps
    /// its strategy-building closures in named functions for the same reason.
    fn mutated_header(use_v1: bool, idx_seed: usize, byte: u8) -> Vec<u8> {
        let mut header = if use_v1 {
            valid_v1_header()
        } else {
            valid_v2_header()
        };
        let len = header.len();
        if let Some(slot) = header.get_mut(idx_seed % len) {
            *slot = byte;
        }
        header
    }

    fn prop_input_strategy() -> impl Strategy<Value = Vec<u8>> {
        proptest::prop_oneof![
            proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=1024),
            (
                proptest::prelude::any::<bool>(),
                proptest::prelude::any::<usize>(),
                proptest::prelude::any::<u8>()
            )
                .prop_map(|(use_v1, idx_seed, byte)| mutated_header(use_v1, idx_seed, byte)),
        ]
    }

    proptest::proptest! {
        /// Property: for any `Vec<u8>` of length 0..=1024, `parse` returns without
        /// panicking (a panic fails the proptest run itself), and on `Complete`,
        /// `consumed <= buf.len()`. Generator: a mix of arbitrary bytes and a structured
        /// generator that emits a valid v1 or v2 header with one byte mutated.
        #[test]
        fn prop_never_over_reads(buf in prop_input_strategy()) {
            match ProxyHeader::parse(&buf) {
                Ok(ParseStatus::Complete { consumed, value }) => {
                    assert!(consumed <= buf.len());
                    assert_eq!(value.consumed, consumed);
                }
                Ok(ParseStatus::Partial) | Err(_) => {}
            }
        }
    }
}
