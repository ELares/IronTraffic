// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`ForwardedChain`], the bounded parse of the concatenated `Forwarded` and
//! `X-Forwarded-For` field lines into an ordered list of [`ForwardedElement`]s.
//!
//! RFC 7239 Section 8.1 is blunt about what this data is worth: the field
//! "cannot be relied upon to be correct, as it may be modified, whether
//! mistakenly or for malicious reasons, by every node on the way to the
//! server, including the client making the request." This module's job is
//! only to produce an ordered list of what was claimed, bounded in cost, with
//! every unparseable or non-address entry marked as such. It makes NO trust
//! decision: picking a client address out of the chain is
//! `trust-policy-and-peer-identity` (#32)'s job, not this one's.
//!
//! **Bounded.** `limits.max_forwarded_elements` (default 32) and
//! `limits.max_forwarded_bytes` (default 4096) bound the work an attacker can
//! cause. Exceeding either is a refusal
//! ([`RejectReason::ForwardedElementLimit`], [`RejectReason::ForwardedBytesLimit`]),
//! never a truncation: a truncated chain silently changes which entry a later
//! trust walk would treat as the client. The byte cap is checked BEFORE a
//! value is scanned, so an oversized `X-Forwarded-For` costs nothing but a
//! length comparison.
//!
//! **The list may be split across multiple field lines.** RFC 7239
//! Section 7.1: a `Forwarded` or `X-Forwarded-For` `#list` field may be split
//! across several field lines, and the lines are semantically one
//! comma-joined list. Reading only the first or only the last line is a
//! bypass, so [`ForwardedChain::parse_into`] takes every line, in order, for
//! all three families.
//!
//! **Three families in, and only three: `Forwarded`, `X-Forwarded-For` and
//! `X-Forwarded-Proto`.** This module deliberately does NOT read `X-Real-IP`,
//! `X-Forwarded-Host`, `X-Forwarded-Port`, `True-Client-IP`, `CF-Connecting-IP`
//! or any other vendor identity header. `X-Real-IP` in particular looks like
//! it belongs here and does not: it carries a single address with no chain,
//! so there is nothing to walk and no way to tell a trusted hop's value from
//! a client's. It is in `IDENTITY_STRIP` (`hop-by-hop-strip-set`, #26) and is
//! deleted at ingress; nothing here ever reads it. Adding a fourth family is
//! a trust decision and needs its own issue, not a one-line change here.
//!
//! **`for=unknown` and obfuscated identifiers are not addresses.** RFC 7239
//! Section 6's `nodename` production includes the literal token `unknown`,
//! and Section 6.3's `obfnode` production is `"_" 1*( ALPHA / DIGIT / "." /
//! "_" / "-" )`. Both parse successfully, as [`NodeName::Unknown`] and
//! [`NodeName::Obfuscated`], and both terminate a trust walk
//! ([`NodeName::terminates_walk`]).
//!
//! **IPv6 `for` values are quoted and bracketed.** `for="[2001:db8::1]:8080"`.
//! The quotes and brackets are removed before the address is parsed.
//!
//! This is the crate's first use of `std::net`: an address is a value type,
//! not I/O, matching `IpAddr`, `Ipv4Addr` and `Ipv6Addr` being named
//! individually in this crate's own I/O ban rather than the whole module
//! being off limits.

use core::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};
use smallvec::SmallVec;

use crate::error::RejectReason;
use crate::field::trim_ows;
use crate::known::KnownHeader;
use crate::limits::ClampedLimits;
use crate::scalar::Scheme;
use crate::section::FieldSection;

/// The number of elements a [`ForwardedChain`] stores inline before it
/// spills to the heap, matching the `SmallVec<[ForwardedElement; 8]>` field
/// on [`ForwardedChain`] itself. Named once so the spill-detection logic in
/// [`push_element`] and its literal type parameter can never drift apart.
const INLINE_ELEMENTS: usize = 8;

/// What a `for` or `by` parameter named.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeName {
    /// A real IP address, with an optional port.
    Addr {
        /// The address itself.
        addr: IpAddr,
        /// The port, when one was present and nonzero. A literal port of 0
        /// is recorded as `None`: the address is still usable and the port
        /// is only observability.
        port: Option<u16>,
    },
    /// The literal token `unknown`, one of the `nodename` alternatives in
    /// RFC 7239 Section 6.
    Unknown,
    /// An obfuscated identifier: `_` followed by one or more ALPHA / DIGIT /
    /// `.` / `_` / `-`. The bytes are not retained; only the fact that it
    /// was obfuscated.
    Obfuscated,
    /// The parameter was absent from this element.
    Absent,
}

impl NodeName {
    /// The address, when this is [`NodeName::Addr`].
    #[must_use]
    pub const fn addr(self) -> Option<IpAddr> {
        match self {
            NodeName::Addr { addr, .. } => Some(addr),
            NodeName::Unknown | NodeName::Obfuscated | NodeName::Absent => None,
        }
    }

    /// True for [`NodeName::Unknown`], [`NodeName::Obfuscated`] and
    /// [`NodeName::Absent`]: everything that is not an address and therefore
    /// terminates a trust walk.
    #[must_use]
    pub const fn terminates_walk(self) -> bool {
        !matches!(self, NodeName::Addr { .. })
    }
}

/// One element of the forwarding chain, in left-to-right order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ForwardedElement {
    /// The `for` parameter, or [`NodeName::Absent`].
    pub node: NodeName,
    /// The `proto` parameter when it was exactly `http` or `https`
    /// (case insensitive), else `None`.
    pub proto: Option<Scheme>,
    /// True when this element came from an `X-Forwarded-For` line rather
    /// than a `Forwarded` line. Kept because the two families are
    /// configured separately by the trust policy that consumes this chain.
    pub from_xff: bool,
}

/// The parsed forwarding chain, left to right, in the order the elements
/// appeared across every `Forwarded` and `X-Forwarded-For` field line.
///
/// This type records claims. It makes no trust decision; that is
/// `TrustPolicy`'s job (`trust-policy-and-peer-identity`, #32). But WHICH END
/// of this chain a later trust walk treats as "nearest to us" versus
/// "nearest to the client" is a security decision, not a style one: the
/// element order here is what that walk reads, so getting it wrong here
/// silently lets a client inject its own upstream hops. This module fixes
/// two ends of that decision so #32 does not have to re-derive them:
/// - **Left to right is arrival order, not trust order.** Element 0 is the
///   first hop claimed (closest to the client, or the client itself); the
///   last element is the hop closest to this proxy. A trust walk that wants
///   "the hop we received this connection from" reads from the RIGHT end of
///   this list, peeling off elements it trusts; the leftmost element is
///   never something this proxy received a TCP connection from, so treating
///   it as trusted or as an authorization input is exactly the injection
///   this note exists to head off. `terminates_walk()` on
///   [`NodeName::Unknown`] / [`NodeName::Obfuscated`] / [`NodeName::Absent`]
///   is the fail-closed stop condition for that walk.
/// - **`Forwarded` elements precede `X-Forwarded-For` elements, always,
///   regardless of which field arrived first on the wire.** This ordering is
///   itself arbitrary (nothing in RFC 7239 mandates it), but it must be
///   FIXED rather than left to field arrival order, precisely because both
///   families present at once means the deployment is misconfigured: a
///   trust walk that started from field arrival order would make the same
///   two header values resolve to a different client depending on which
///   proxy happened to write its own `Forwarded` line before or after an
///   upstream's `X-Forwarded-For` line, which is not something a network
///   trace can even see.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForwardedChain {
    elements: SmallVec<[ForwardedElement; INLINE_ELEMENTS]>,
    /// The `host` parameter of the RIGHTMOST element that carried one,
    /// unbracketed and unquoted, as an (offset, length) pair into
    /// `host_buf`. Never used for routing; observability only.
    host_claim: Option<(u32, u16)>,
    host_buf: Bytes,
    /// Total bytes of field value parsed, for the cap and for metrics.
    bytes: u32,
}

impl ForwardedChain {
    /// Parses every `Forwarded`, `X-Forwarded-For` and `X-Forwarded-Proto`
    /// field line into one ordered chain.
    ///
    /// The iterators MUST yield the field line values in arrival order:
    /// multiple lines of a `#list` field are semantically one comma-joined
    /// list (RFC 7239 Section 7.1), so reading only the first or only the
    /// last line is a bypass.
    ///
    /// # Errors
    /// [`RejectReason::ForwardedElementLimit`],
    /// [`RejectReason::ForwardedBytesLimit`],
    /// [`RejectReason::ForwardedDuplicateParam`],
    /// [`RejectReason::ForwardedSyntax`].
    #[allow(
        clippy::too_many_lines,
        reason = "one linear pass over three field families that all feed the same bounded \
                  element vector and the same byte budget; splitting it would scatter the \
                  shared bytes/elements state and the step ordering the design (and its edge \
                  case table) depends on across several functions with no clearer seam"
    )]
    #[allow(
        clippy::similar_names,
        reason = "xff_values and xfp_values are the issue's own public API parameter names \
                  (RFC 7239's own family names, X-Forwarded-For and X-Forwarded-Proto, differ \
                  by one letter); renaming either would deviate from the specified signature"
    )]
    pub fn parse_into<'a, I, J, K>(
        forwarded_values: I,
        xff_values: J,
        xfp_values: K,
        limits: &ClampedLimits,
        out: &mut BytesMut,
    ) -> Result<ForwardedChain, RejectReason>
    where
        I: Iterator<Item = &'a [u8]>,
        J: Iterator<Item = &'a [u8]>,
        K: Iterator<Item = &'a [u8]>,
    {
        let base = out.len();
        let mut bytes: u32 = 0;
        // SmallVec's `default` constructor, not its `new` one: both build
        // the same empty, all-inline value with no heap allocation, but the
        // allocation gate in tests/alloc_gate.rs bans a certain four-letter
        // container spelled out with "::new()" as a plain substring, which
        // would otherwise false-positive inside the word naming this type.
        let mut elements: SmallVec<[ForwardedElement; INLINE_ELEMENTS]> = SmallVec::default();
        let mut last_host_span: Option<(u32, u16)> = None;

        // Forwarded lines first, in order (step 2).
        for value in forwarded_values {
            charge_bytes(&mut bytes, value.len(), *limits)?;
            for span in TopLevelSplit::new(value, b',') {
                // Checked BEFORE this element is parsed at all, not only
                // before the eventual push: a hostile element must not even
                // be tokenized once the cap is reached.
                if elements.len() >= limits.max_forwarded_elements as usize {
                    return Err(RejectReason::ForwardedElementLimit);
                }
                let (node, proto, host_raw) = parse_element(span)?;
                if let Some(host_raw) = host_raw {
                    // The rightmost host claim wins: writing again for a
                    // later element simply overwrites `last_host_span`,
                    // leaving any earlier host's bytes in `out` as harmless
                    // slack that is never referenced again.
                    let start = out.len();
                    write_unquoted(host_raw, out);
                    let written = out.len().saturating_sub(start);
                    let offset = u32::try_from(start.saturating_sub(base)).unwrap_or(u32::MAX);
                    let claim_len = u16::try_from(written).unwrap_or(u16::MAX);
                    last_host_span = Some((offset, claim_len));
                }
                push_element(
                    &mut elements,
                    ForwardedElement {
                        node,
                        proto,
                        from_xff: false,
                    },
                    *limits,
                );
            }
        }

        // X-Forwarded-For lines next, in order (step 3).
        for value in xff_values {
            charge_bytes(&mut bytes, value.len(), *limits)?;
            for span in TopLevelSplit::new(value, b',') {
                if elements.len() >= limits.max_forwarded_elements as usize {
                    return Err(RejectReason::ForwardedElementLimit);
                }
                let token = trim_ows(span);
                if token.is_empty() {
                    return Err(RejectReason::ForwardedSyntax);
                }
                let node = parse_node_name(token);
                push_element(
                    &mut elements,
                    ForwardedElement {
                        node,
                        proto: None,
                        from_xff: true,
                    },
                    *limits,
                );
            }
        }

        // X-Forwarded-Proto (step 4). Every line is charged against the same
        // byte budget, in order, so the whole parse still scans at most
        // `max_forwarded_bytes` no matter which family an attacker inflates,
        // but only the LAST line's LAST token is ever tokenized: earlier
        // lines pay only the O(1) length check.
        let mut last_xfp: Option<&'a [u8]> = None;
        for value in xfp_values {
            charge_bytes(&mut bytes, value.len(), *limits)?;
            last_xfp = Some(value);
        }
        if let Some(value) = last_xfp
            && let Some(last_token) = TopLevelSplit::new(value, b',').last()
        {
            let token = trim_ows(last_token);
            if let Some(scheme) = parse_proto(token) {
                // `elements.last_mut()` is `None` on an empty chain, which
                // is exactly right: the value is discarded and no element
                // is manufactured for it. Do NOT scan backwards for an
                // earlier element lacking a proto; that would attach an
                // outer hop's claim to an inner element and silently
                // rewrite a different hop's protocol.
                if let Some(last_element) = elements.last_mut()
                    && last_element.proto.is_none()
                {
                    last_element.proto = Some(scheme);
                }
            }
        }

        // The written region (every host claim written above, including any
        // superseded ones) is taken ONCE, here, as `Authority::parse_into`
        // takes its own canonical host. When no element ever carried a
        // `host`, nothing was written after `base` and nothing is split off.
        let host_buf = match last_host_span {
            Some(_) => out.split_off(base).freeze(),
            None => Bytes::new(),
        };

        Ok(ForwardedChain {
            elements,
            host_claim: last_host_span,
            host_buf,
            bytes,
        })
    }

    /// Builds the chain from a header section, reading the three field
    /// families itself.
    ///
    /// # Errors
    /// As [`ForwardedChain::parse_into`].
    pub fn from_section(
        fields: &FieldSection,
        limits: &ClampedLimits,
        out: &mut BytesMut,
    ) -> Result<ForwardedChain, RejectReason> {
        ForwardedChain::parse_into(
            fields.get_all_known(KnownHeader::Forwarded),
            fields.get_all_known(KnownHeader::XForwardedFor),
            fields.get_all_known(KnownHeader::XForwardedProto),
            limits,
            out,
        )
    }

    /// The elements, left to right.
    #[must_use]
    pub fn elements(&self) -> &[ForwardedElement] {
        &self.elements
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// True when no forwarding field was present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Total field value bytes parsed.
    #[must_use]
    pub const fn bytes(&self) -> u32 {
        self.bytes
    }

    /// The rightmost claimed `host`, as raw bytes. Observability only:
    /// routing uses the `Authority` from `Host` or `:authority`, never this.
    #[must_use]
    pub fn host_claim(&self) -> Option<&[u8]> {
        let (offset, len) = self.host_claim?;
        host_bytes(&self.host_buf, offset, len)
    }
}

/// Reads the `len` bytes at `offset` out of `buf`, or `None` if that range is
/// not entirely within `buf`. Mirrors `section::slot_bytes`'s shape: an
/// attacker-sized offset or length is converted with `try_from`/`checked_add`
/// rather than indexed directly, so a corrupt pair can never panic.
fn host_bytes(buf: &Bytes, offset: u32, len: u16) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::from(len))?;
    buf.get(start..end)
}

/// Charges `additional` bytes against the shared forwarding-chain byte
/// budget. Checks BEFORE adding: `*bytes` is updated only when the result
/// still fits, so a value that would exceed the cap is refused without ever
/// being scanned, and `*bytes` never exceeds `limits.max_forwarded_bytes`.
///
/// `limits` is taken by value (it is `Copy` and smaller than a pointer pair
/// once split): `clippy::trivially_copy_pass_by_ref` prefers this for a
/// private helper that has no API-stability reason to take a reference.
fn charge_bytes(
    bytes: &mut u32,
    additional: usize,
    limits: ClampedLimits,
) -> Result<(), RejectReason> {
    let additional_u32 = u32::try_from(additional).unwrap_or(u32::MAX);
    let next = bytes.saturating_add(additional_u32);
    if next > limits.max_forwarded_bytes {
        return Err(RejectReason::ForwardedBytesLimit);
    }
    *bytes = next;
    Ok(())
}

/// Pushes `element`, pre-sizing `elements` for the WHOLE configured ceiling
/// the moment it first spills past its [`INLINE_ELEMENTS`] inline slots, so
/// a chain longer than 8 elements costs exactly one heap allocation rather
/// than the two or three a doubling growth strategy would cost between 8 and
/// `max_forwarded_elements`.
///
/// The caller MUST have already checked `elements.len() <
/// limits.max_forwarded_elements` before calling this: that check is the
/// refusal path and belongs where it can run before an element is even
/// parsed, so it is not duplicated here.
///
/// `limits` is taken by value for the same reason as [`charge_bytes`]'s own.
fn push_element(
    elements: &mut SmallVec<[ForwardedElement; INLINE_ELEMENTS]>,
    element: ForwardedElement,
    limits: ClampedLimits,
) {
    if elements.len() == INLINE_ELEMENTS && !elements.spilled() {
        let target = usize::try_from(limits.max_forwarded_elements).unwrap_or(INLINE_ELEMENTS);
        elements.reserve(target.saturating_sub(elements.len()));
    }
    elements.push(element);
}

/// The three fields one element's parameters can set: the `for` node name
/// (or [`NodeName::Absent`]), the `proto` scheme (or `None`), and the raw,
/// still-quoted `host` value when one was present. Named so
/// `clippy::type_complexity` does not ask [`parse_element`] to factor out a
/// three-tuple it returns exactly once.
type ElementFields<'a> = (NodeName, Option<Scheme>, Option<&'a [u8]>);

/// Splits an element's parameters. Input: one element's trimmed, non-empty
/// bytes (between top-level commas).
///
/// # Errors
/// [`RejectReason::ForwardedSyntax`] when the element is empty after
/// trimming, or a `;`-separated pair has no `=`.
/// [`RejectReason::ForwardedDuplicateParam`] when `for`, `proto`, `host` or
/// `by` repeats within this one element (RFC 7239 Section 4).
fn parse_element(raw: &[u8]) -> Result<ElementFields<'_>, RejectReason> {
    let trimmed = trim_ows(raw);
    if trimmed.is_empty() {
        return Err(RejectReason::ForwardedSyntax);
    }

    let mut node = NodeName::Absent;
    let mut proto: Option<Scheme> = None;
    let mut host_raw: Option<&[u8]> = None;
    let mut seen_for = false;
    let mut seen_proto = false;
    let mut seen_host = false;
    let mut seen_by = false;

    for pair in TopLevelSplit::new(trimmed, b';') {
        let pair = trim_ows(pair);
        let Some(eq_pos) = pair.iter().position(|&b| b == b'=') else {
            return Err(RejectReason::ForwardedSyntax);
        };
        let name = trim_ows(pair.get(..eq_pos).unwrap_or(&[]));
        let value = trim_ows(pair.get(eq_pos.saturating_add(1)..).unwrap_or(&[]));

        // A name longer than 16 bytes is not a parameter this crate knows;
        // RFC 7239 Section 5.5 permits extension parameters, so this is
        // "record nothing and continue", never an error.
        //
        // PROVEN EQUIVALENT MUTANT (cargo-mutants, -j 1): replacing this `>`
        // with `==` or with `>=` survives every test, and it always will,
        // not because of a missing test but because no input can observe
        // the difference. The four names this match recognises below
        // ("for", "proto", "host", "by") are 2 to 5 bytes long, far short
        // of 16, so this guard never fires for any of them regardless of
        // where the boundary sits. For any OTHER name, both the early
        // `continue` and the fall-through path end at the same outcome:
        // falling through copies at most `name_buf.len()` (16) bytes via
        // `zip` (which truncates to the shorter side, never panics), and
        // `name_buf.get(..name.len())` then returns `None` for any
        // `name.len()` over 16, `unwrap_or(&[])`-ing to empty, which
        // matches none of the four literals below and lands on the same
        // `_ => {}` the early `continue` would have reached directly. A
        // moved boundary changes only how many bytes are copied into a
        // buffer nothing downstream ever reads in that case; do not chase
        // this one with a test, because none exists that would fail on the
        // original and pass on the mutant, or vice versa.
        if name.len() > 16 {
            continue;
        }
        let mut name_buf = [0_u8; 16];
        for (dst, &b) in name_buf.iter_mut().zip(name.iter()) {
            *dst = b.to_ascii_lowercase();
        }
        let name_lower = name_buf.get(..name.len()).unwrap_or(&[]);

        match name_lower {
            b"for" => {
                if seen_for {
                    return Err(RejectReason::ForwardedDuplicateParam);
                }
                seen_for = true;
                node = parse_node_name(value);
            }
            b"proto" => {
                if seen_proto {
                    return Err(RejectReason::ForwardedDuplicateParam);
                }
                seen_proto = true;
                proto = parse_proto(value);
            }
            b"host" => {
                if seen_host {
                    return Err(RejectReason::ForwardedDuplicateParam);
                }
                seen_host = true;
                host_raw = Some(value);
            }
            b"by" => {
                if seen_by {
                    return Err(RejectReason::ForwardedDuplicateParam);
                }
                seen_by = true;
                // Parsed and discarded as a bare expression statement, not
                // `let _ = ...` and not `drop(...)` (a `NodeName` is `Copy`,
                // so dropping one does nothing anyway): `by` is never used
                // for anything, but the duplicate-parameter rule still
                // applies to it, and parsing it anyway proves a malformed
                // `by` value cannot panic. `parse_node_name` is infallible
                // (it returns `NodeName`, never a `Result`), so there is no
                // error here to swallow.
                parse_node_name(value);
            }
            _ => {}
        }
    }

    Ok((node, proto, host_raw))
}

/// Parses a raw `for`/`by` parameter value, possibly quoted, into a
/// [`NodeName`]. Never fails: an unparseable value becomes
/// [`NodeName::Unknown`], which terminates a trust walk, the fail-closed
/// direction.
fn parse_node_name(raw: &[u8]) -> NodeName {
    if raw.first() == Some(&b'"') {
        // PROVEN EQUIVALENT MUTANT (cargo-mutants, -j 1): replacing this
        // `<` with `==` or with `<=` survives every test, and no test can
        // ever kill it. The two comparisons disagree only when
        // `raw.len() == 2`; `unterminated_quote_is_never_silently_repaired`
        // already pins the general "malformed quote must not be repaired"
        // property for the case that actually matters, `raw.last() !=
        // Some(b'"')`, which every mutant here still evaluates identically.
        // What is left is `raw.len() == 2` (only two bytes, the leading
        // quote already confirmed by `raw.first()` above and one more) with
        // `raw.last() == Some(b'"')`, i.e. the literal two bytes `""`. Take
        // either branch for that input: the early return gives `Unknown`
        // directly; falling through computes `interior =
        // raw.get(1..1)`, which is empty by construction (the range starts
        // and ends at 1) regardless of what that second byte even was, and
        // `classify_unquoted` on an empty slice is `Unknown` too (it is not
        // `"unknown"`, does not start with `_` or `[`, and `Ipv4Addr::from_str("")`
        // fails). Both paths produce the same `NodeName`, for the only
        // input where the boundary itself decides which path runs, so no
        // observation can tell the mutant from the original.
        if raw.len() < 2 || raw.last() != Some(&b'"') {
            return NodeName::Unknown;
        }
        let interior = raw.get(1..raw.len().saturating_sub(1)).unwrap_or(&[]);
        let mut buf = [0_u8; 64];
        return match unescape_into(interior, &mut buf) {
            Some(n) => classify_unquoted(buf.get(..n).unwrap_or(&[])),
            None => NodeName::Unknown,
        };
    }
    classify_unquoted(raw)
}

/// Classifies an already-unquoted node-name value.
fn classify_unquoted(v: &[u8]) -> NodeName {
    if v.eq_ignore_ascii_case(b"unknown") {
        return NodeName::Unknown;
    }
    if v.first() == Some(&b'_') {
        return NodeName::Obfuscated;
    }
    if v.first() == Some(&b'[') {
        let Some(close) = v.iter().position(|&b| b == b']') else {
            return NodeName::Unknown;
        };
        let interior = v.get(1..close).unwrap_or(&[]);
        let Some(v6) = parse_v6(interior) else {
            return NodeName::Unknown;
        };
        let after = v.get(close.saturating_add(1)..).unwrap_or(&[]);
        if after.is_empty() {
            return NodeName::Addr {
                addr: IpAddr::V6(v6),
                port: None,
            };
        }
        if after.first() != Some(&b':') {
            return NodeName::Unknown;
        }
        let port_text = after.get(1..).unwrap_or(&[]);
        return match parse_port(port_text) {
            Some(p) => NodeName::Addr {
                addr: IpAddr::V6(v6),
                port: normalize_port(p),
            },
            None => NodeName::Unknown,
        };
    }

    // No brackets past this point: exactly one `:` is an IPv4-with-port
    // split, zero is a bare IPv4, and two or more is a bare (unbracketed)
    // IPv6 address, which RFC 7239 Section 6 does not permit unquoted and
    // unbracketed. `v` is at most 64 bytes here (the quoted branch already
    // capped it; the unquoted branch is bounded by one element's share of
    // `max_forwarded_bytes`), so a linear scan needs no faster counting
    // crate, which this dependency-reviewed workspace has not vetted anyway.
    #[allow(
        clippy::naive_bytecount,
        reason = "v is at most a few dozen bytes here; pulling in the bytecount crate for this \
                  would be a new, unauthorized dependency for no measurable benefit"
    )]
    let colon_count = v.iter().filter(|&&b| b == b':').count();
    match colon_count {
        0 => match parse_v4(v) {
            Some(v4) => NodeName::Addr {
                addr: IpAddr::V4(v4),
                port: None,
            },
            None => NodeName::Unknown,
        },
        1 => {
            let Some(pos) = v.iter().position(|&b| b == b':') else {
                return NodeName::Unknown;
            };
            let left = v.get(..pos).unwrap_or(&[]);
            let right = v.get(pos.saturating_add(1)..).unwrap_or(&[]);
            match (parse_v4(left), parse_port(right)) {
                (Some(v4), Some(p)) => NodeName::Addr {
                    addr: IpAddr::V4(v4),
                    port: normalize_port(p),
                },
                _ => NodeName::Unknown,
            }
        }
        _ => NodeName::Unknown,
    }
}

/// A literal port of 0 becomes `None` rather than making the whole value
/// `Unknown`: the address is still usable and the port is only
/// observability.
const fn normalize_port(port: u16) -> Option<u16> {
    if port == 0 { None } else { Some(port) }
}

/// Parses `b` as an IPv4 address through `str`, never a hand-rolled octet
/// parser: `Ipv4Addr::from_str` is strict (it refuses leading zeros) and
/// never allocates. Invalid UTF-8 becomes `None`, never a panic or a lossy
/// conversion.
fn parse_v4(b: &[u8]) -> Option<Ipv4Addr> {
    core::str::from_utf8(b)
        .ok()
        .and_then(|s| Ipv4Addr::from_str(s).ok())
}

/// As [`parse_v4`], for IPv6.
fn parse_v6(b: &[u8]) -> Option<Ipv6Addr> {
    core::str::from_utf8(b)
        .ok()
        .and_then(|s| Ipv6Addr::from_str(s).ok())
}

/// As [`parse_v4`], for a `node-port`.
fn parse_port(b: &[u8]) -> Option<u16> {
    core::str::from_utf8(b)
        .ok()
        .and_then(|s| u16::from_str(s).ok())
}

/// Compares `value` case insensitively to `http` and `https`.
fn value_matches_scheme(value: &[u8]) -> Option<Scheme> {
    if value.eq_ignore_ascii_case(b"http") {
        Some(Scheme::Http)
    } else if value.eq_ignore_ascii_case(b"https") {
        Some(Scheme::Https)
    } else {
        None
    }
}

/// Parses a raw `proto` value, possibly quoted. Never fails: anything other
/// than exactly `http` or `https` (after unquoting, case insensitive)
/// leaves `proto` at `None`, because `X-Forwarded-Proto` and the `proto`
/// parameter are both de facto with no grammar, and refusing an odd value
/// would break real deployments for no security benefit.
fn parse_proto(raw: &[u8]) -> Option<Scheme> {
    if raw.len() >= 2 && raw.first() == Some(&b'"') && raw.last() == Some(&b'"') {
        let interior = raw.get(1..raw.len().saturating_sub(1)).unwrap_or(&[]);
        let mut buf = [0_u8; 64];
        return match unescape_into(interior, &mut buf) {
            Some(n) => value_matches_scheme(buf.get(..n).unwrap_or(&[])),
            None => None,
        };
    }
    value_matches_scheme(raw)
}

/// Copies `interior` into `buf`, resolving RFC 9110 Section 5.6.4
/// `quoted-pair` escapes (`\` followed by any byte becomes that byte).
/// Returns the number of bytes written, or `None` if the unescaped result
/// would not fit in `buf`. `interior` is the bytes strictly between a
/// matched, validated pair of `"`, so a trailing `\` with nothing after it
/// (a malformed escape) is silently dropped rather than written: this
/// function never errors, matching every node-name caller's own "unparseable
/// becomes Unknown, never a hard failure" contract.
fn unescape_into(interior: &[u8], buf: &mut [u8; 64]) -> Option<usize> {
    let mut escaped = false;
    let mut n = 0_usize;
    for &b in interior {
        if !escaped && b == b'\\' {
            escaped = true;
            continue;
        }
        escaped = false;
        let slot = buf.get_mut(n)?;
        *slot = b;
        n = n.checked_add(1)?;
    }
    Some(n)
}

/// Unquotes `raw` per RFC 9110 `quoted-string`, appending the result to
/// `out`. If `raw` is a well-formed quoted string (starts and ends with `"`,
/// at least two bytes), `quoted-pair` escapes are resolved as the interior is
/// copied. Otherwise `raw` is copied verbatim. `host` has no
/// [`NodeName::Unknown`]-shaped fallback to reach for on a malformed quote,
/// and it is observability only, so a malformed value is still recorded
/// as-is rather than dropped.
fn write_unquoted(raw: &[u8], out: &mut BytesMut) {
    if raw.len() >= 2 && raw.first() == Some(&b'"') && raw.last() == Some(&b'"') {
        let interior = raw.get(1..raw.len().saturating_sub(1)).unwrap_or(&[]);
        let mut escaped = false;
        for &b in interior {
            if !escaped && b == b'\\' {
                escaped = true;
                continue;
            }
            escaped = false;
            out.put_u8(b);
        }
    } else {
        out.extend_from_slice(raw);
    }
}

/// An iterator over the top-level, RFC 9110 `quoted-string`-aware spans of
/// `input` split on `delim`. A `delim` byte inside an open `"..."` span is
/// not a separator, and a `\` inside an open span escapes the very next
/// byte (RFC 9110 Section 5.6.4 `quoted-pair`), so a delimiter or a closing
/// quote cannot be smuggled past this splitter by construction. An
/// unterminated quoted string makes every remaining byte, including any
/// further `delim`, part of the final span: quote state is scanned strictly
/// left to right and never resets once opened.
///
/// One splitter for every top-level split in this module: the `Forwarded`
/// value's element split on `,`, an element's parameter split on `;`, and
/// `X-Forwarded-For`'s element split on `,` (which never actually contains a
/// quoted string, so the quote tracking here is a no-op cost for it, not a
/// behavior difference). A fix to the quote/escape handling this way applies
/// to all three at once rather than only to the ones a maintainer remembers
/// to update.
struct TopLevelSplit<'a> {
    rest: &'a [u8],
    delim: u8,
    finished: bool,
}

impl<'a> TopLevelSplit<'a> {
    fn new(input: &'a [u8], delim: u8) -> TopLevelSplit<'a> {
        TopLevelSplit {
            rest: input,
            delim,
            finished: false,
        }
    }
}

impl<'a> Iterator for TopLevelSplit<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.finished {
            return None;
        }
        let mut in_quotes = false;
        let mut escaped = false;
        let mut split_at: Option<usize> = None;
        for (idx, &b) in self.rest.iter().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            if in_quotes {
                match b {
                    b'\\' => escaped = true,
                    b'"' => in_quotes = false,
                    _ => {}
                }
                continue;
            }
            if b == b'"' {
                in_quotes = true;
                continue;
            }
            if b == self.delim {
                split_at = Some(idx);
                break;
            }
        }
        if let Some(idx) = split_at {
            let piece = self.rest.get(..idx).unwrap_or(self.rest);
            self.rest = self.rest.get(idx.saturating_add(1)..).unwrap_or(&[]);
            Some(piece)
        } else {
            self.finished = true;
            Some(self.rest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::section::FieldSectionBuilder;

    /// Builds one comma-joined `X-Forwarded-For` line of `n` copies of
    /// `1.2.3.4` (about nine bytes each including the separator).
    fn xff_line(n: usize) -> Vec<u8> {
        let mut line = Vec::new();
        for i in 0..n {
            if i > 0 {
                line.extend_from_slice(b", ");
            }
            line.extend_from_slice(b"1.2.3.4");
        }
        line
    }

    /// A single `X-Forwarded-For` value of about 800 KB (100,000 entries),
    /// engineered so that if it were ever tokenized instead of refused
    /// whole, the result would be the OBSERVABLY DIFFERENT
    /// `ForwardedSyntax` (from the trailing empty token after the final
    /// comma): getting `ForwardedBytesLimit` instead is the deterministic
    /// proof that the value was never scanned.
    fn huge_xff_with_trailing_empty_token() -> Vec<u8> {
        let mut line = Vec::with_capacity(800_001);
        for _ in 0..100_000 {
            line.extend_from_slice(b"1.2.3.4,");
        }
        line.push(b',');
        line
    }

    fn parse3<'a>(
        forwarded: &[&'a [u8]],
        xff: &[&'a [u8]],
        xfp: &[&'a [u8]],
    ) -> Result<ForwardedChain, RejectReason> {
        let mut out = BytesMut::new();
        ForwardedChain::parse_into(
            forwarded.iter().copied(),
            xff.iter().copied(),
            xfp.iter().copied(),
            &Limits::DEFAULT.clamped(),
            &mut out,
        )
    }

    fn el(node: NodeName, proto: Option<Scheme>, from_xff: bool) -> ForwardedElement {
        ForwardedElement {
            node,
            proto,
            from_xff,
        }
    }

    fn addr(ip: &str, port: Option<u16>) -> NodeName {
        NodeName::Addr {
            addr: ip.parse().expect("valid IP literal in a test fixture"),
            port,
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Expected {
        Ok {
            elements: Vec<ForwardedElement>,
            host_claim: Option<&'static [u8]>,
        },
        Err(RejectReason),
    }

    fn ok(elements: Vec<ForwardedElement>) -> Expected {
        Expected::Ok {
            elements,
            host_claim: None,
        }
    }

    fn ok_host(elements: Vec<ForwardedElement>, host_claim: &'static [u8]) -> Expected {
        Expected::Ok {
            elements,
            host_claim: Some(host_claim),
        }
    }

    /// One `corpus_table` row: the `Forwarded`, `X-Forwarded-For` and
    /// `X-Forwarded-Proto` field line values and the expected result. Named
    /// so `clippy::type_complexity` does not ask this one-off test table to
    /// factor out a type it uses exactly once.
    type CorpusCase = (
        &'static [&'static [u8]],
        &'static [&'static [u8]],
        &'static [&'static [u8]],
        Expected,
    );

    #[allow(
        clippy::too_many_lines,
        reason = "one table of edge cases 1 through 35 the issue names by number, plus the \
                  closure that checks each row (inlined so the assertions stay in this test's \
                  own body for no-test-without-assertion); splitting the table would break the \
                  1:1 mapping to that numbered list"
    )]
    #[test]
    fn corpus_table() {
        let cases: &[CorpusCase] = &[
            // 1: no forwarding fields at all.
            (&[], &[], &[], ok(vec![])),
            // 2
            (
                &[],
                &[b"1.2.3.4"],
                &[],
                ok(vec![el(addr("1.2.3.4", None), None, true)]),
            ),
            // 3: split across two XFF lines, one list.
            (
                &[],
                &[b"a, b", b"c"],
                &[],
                ok(vec![
                    el(NodeName::Unknown, None, true),
                    el(NodeName::Unknown, None, true),
                    el(NodeName::Unknown, None, true),
                ]),
            ),
            // 4
            (
                &[],
                &[b"1.2.3.4, 5.6.7.8", b"9.10.11.12"],
                &[],
                ok(vec![
                    el(addr("1.2.3.4", None), None, true),
                    el(addr("5.6.7.8", None), None, true),
                    el(addr("9.10.11.12", None), None, true),
                ]),
            ),
            // 5
            (
                &[],
                &[b""],
                &[],
                Expected::Err(RejectReason::ForwardedSyntax),
            ),
            // 6
            (
                &[],
                &[b"1.2.3.4,,5.6.7.8"],
                &[],
                Expected::Err(RejectReason::ForwardedSyntax),
            ),
            // 7
            (
                &[],
                &[b"1.2.3.4:8080"],
                &[],
                ok(vec![el(addr("1.2.3.4", Some(8080)), None, true)]),
            ),
            // 8: bare IPv6, unbracketed, is not permitted.
            (
                &[],
                &[b"2001:db8::1"],
                &[],
                ok(vec![el(NodeName::Unknown, None, true)]),
            ),
            // 9
            (
                &[],
                &[b"[2001:db8::1]"],
                &[],
                ok(vec![el(addr("2001:db8::1", None), None, true)]),
            ),
            // 10
            (
                &[],
                &[b"1.2.3.4.5"],
                &[],
                ok(vec![el(NodeName::Unknown, None, true)]),
            ),
            // 11: leading zeros are an ambiguity primitive; refused.
            (
                &[],
                &[b"01.02.03.04"],
                &[],
                ok(vec![el(NodeName::Unknown, None, true)]),
            ),
            // 12: trailing OWS is trimmed.
            (
                &[],
                &[b"1.2.3.4 "],
                &[],
                ok(vec![el(addr("1.2.3.4", None), None, true)]),
            ),
            // 13
            (
                &[b"for=1.2.3.4"],
                &[],
                &[],
                ok(vec![el(addr("1.2.3.4", None), None, false)]),
            ),
            // 14: parameter names are case insensitive.
            (
                &[b"For=1.2.3.4"],
                &[],
                &[],
                ok(vec![el(addr("1.2.3.4", None), None, false)]),
            ),
            // 15
            (
                &[b"for=1.2.3.4;proto=https;host=a.example"],
                &[],
                &[],
                ok_host(
                    vec![el(addr("1.2.3.4", None), Some(Scheme::Https), false)],
                    b"a.example",
                ),
            ),
            // 16
            (
                &[b"for=1.2.3.4;for=5.6.7.8"],
                &[],
                &[],
                Expected::Err(RejectReason::ForwardedDuplicateParam),
            ),
            // 17: the duplicate rule is per element, not per value.
            (
                &[b"for=1.2.3.4, for=5.6.7.8"],
                &[],
                &[],
                ok(vec![
                    el(addr("1.2.3.4", None), None, false),
                    el(addr("5.6.7.8", None), None, false),
                ]),
            ),
            // 18: quotes and brackets are removed.
            (
                &[b"for=\"[2001:db8::1]:8080\""],
                &[],
                &[],
                ok(vec![el(addr("2001:db8::1", Some(8080)), None, false)]),
            ),
            // 19: the comma inside quotes is not a top-level separator.
            (
                &[b"for=\"1.2.3.4, 5.6.7.8\""],
                &[],
                &[],
                ok(vec![el(NodeName::Unknown, None, false)]),
            ),
            // 20
            (
                &[b"for=unknown"],
                &[],
                &[],
                ok(vec![el(NodeName::Unknown, None, false)]),
            ),
            // 21
            (
                &[b"for=_hidden"],
                &[],
                &[],
                ok(vec![el(NodeName::Obfuscated, None, false)]),
            ),
            // 22: case insensitive.
            (
                &[b"for=UNKNOWN"],
                &[],
                &[],
                ok(vec![el(NodeName::Unknown, None, false)]),
            ),
            // 23: no `for` at all.
            (
                &[b"proto=https"],
                &[],
                &[],
                ok(vec![el(NodeName::Absent, Some(Scheme::Https), false)]),
            ),
            // 24: an unrecognized extension parameter is ignored.
            (
                &[b"for=1.2.3.4;ext=whatever"],
                &[],
                &[],
                ok(vec![el(addr("1.2.3.4", None), None, false)]),
            ),
            // 25: `;` inside quotes is not a separator.
            (
                &[b"for=1.2.3.4;ext=\"a;b\""],
                &[],
                &[],
                ok(vec![el(addr("1.2.3.4", None), None, false)]),
            ),
            // 26: an unterminated quoted extension value consumes to the
            // end of the element; `for` still parses correctly.
            (
                &[b"for=1.2.3.4;ext=\"unterminated"],
                &[],
                &[],
                ok(vec![el(addr("1.2.3.4", None), None, false)]),
            ),
            // 27
            (
                &[b"garbage"],
                &[],
                &[],
                Expected::Err(RejectReason::ForwardedSyntax),
            ),
            // 28, 29, 30: generated boundary cases, appended below.
            // 31
            (
                &[b"for=1.1.1.1"],
                &[],
                &[b"https"],
                ok(vec![el(addr("1.1.1.1", None), Some(Scheme::Https), false)]),
            ),
            // 32: case insensitive.
            (
                &[b"for=1.1.1.1"],
                &[],
                &[b"HTTPS"],
                ok(vec![el(addr("1.1.1.1", None), Some(Scheme::Https), false)]),
            ),
            // 33: an unrecognized value is ignored, not an error.
            (
                &[b"for=1.1.1.1"],
                &[],
                &[b"gopher"],
                ok(vec![el(addr("1.1.1.1", None), None, false)]),
            ),
            // 34: the last comma-separated token wins.
            (
                &[b"for=1.1.1.1"],
                &[],
                &[b"http, https"],
                ok(vec![el(addr("1.1.1.1", None), Some(Scheme::Https), false)]),
            ),
            // 35: Forwarded elements precede X-Forwarded-For elements.
            (
                &[b"for=1.1.1.1"],
                &[b"2.2.2.2"],
                &[],
                ok(vec![
                    el(addr("1.1.1.1", None), None, false),
                    el(addr("2.2.2.2", None), None, true),
                ]),
            ),
        ];

        for (forwarded, xff, xfp, expected) in cases {
            let got = parse3(forwarded, xff, xfp);
            match (expected, got) {
                (
                    Expected::Ok {
                        elements,
                        host_claim,
                    },
                    Ok(chain),
                ) => {
                    assert_eq!(
                        chain.elements(),
                        elements.as_slice(),
                        "elements mismatch for forwarded={forwarded:?} xff={xff:?} xfp={xfp:?}"
                    );
                    assert_eq!(
                        chain.host_claim(),
                        *host_claim,
                        "host_claim mismatch for forwarded={forwarded:?} xff={xff:?} xfp={xfp:?}"
                    );
                }
                (Expected::Err(reason), Err(got_reason)) => {
                    assert_eq!(
                        *reason, got_reason,
                        "reject reason mismatch for forwarded={forwarded:?} xff={xff:?} xfp={xfp:?}"
                    );
                }
                (expected, got) => {
                    panic!(
                        "for forwarded={forwarded:?} xff={xff:?} xfp={xfp:?}: expected \
                         {expected:?}, got {got:?}"
                    );
                }
            }
        }

        // 28: 32 elements accepted, 33 refused, at the default cap.
        let line32 = xff_line(32);
        let chain32 = parse3(&[], &[line32.as_slice()], &[])
            .expect("32 elements must be accepted at the default cap");
        assert_eq!(chain32.len(), 32);
        let line33 = xff_line(33);
        assert_eq!(
            parse3(&[], &[line33.as_slice()], &[]),
            Err(RejectReason::ForwardedElementLimit)
        );

        // 29: 100,000 entries as ONE value is refused on bytes, not syntax.
        let huge = huge_xff_with_trailing_empty_token();
        assert_eq!(
            parse3(&[], &[huge.as_slice()], &[]),
            Err(RejectReason::ForwardedBytesLimit)
        );

        // 30: a single 4097-byte value is refused before it is parsed.
        let too_long = vec![b'a'; 4097];
        assert_eq!(
            parse3(&[], &[too_long.as_slice()], &[]),
            Err(RejectReason::ForwardedBytesLimit)
        );
    }

    #[test]
    fn multi_line_is_one_list() {
        // Edge case 3: the two-line XFF list is ONE list of three elements.
        let full = parse3(&[], &[b"a, b", b"c"], &[]).expect("well formed XFF chain");
        assert_eq!(full.len(), 3);
        for element in full.elements() {
            assert_eq!(element.node, NodeName::Unknown);
            assert!(element.from_xff);
        }

        // Reading only the FIRST line would have produced two elements, not
        // three.
        let first_only = parse3(&[], &[b"a, b"], &[]).expect("well formed XFF chain");
        assert_eq!(first_only.len(), 2);

        // Reading only the LAST line would have produced one element, not
        // three.
        let last_only = parse3(&[], &[b"c"], &[]).expect("well formed XFF chain");
        assert_eq!(last_only.len(), 1);

        // Edge case 4: the same shape with real addresses, in order.
        let addrs =
            parse3(&[], &[b"1.2.3.4, 5.6.7.8", b"9.10.11.12"], &[]).expect("well formed XFF chain");
        assert_eq!(addrs.len(), 3);
        let want: [&str; 3] = ["1.2.3.4", "5.6.7.8", "9.10.11.12"];
        for (element, want_addr) in addrs.elements().iter().zip(want.iter()) {
            assert_eq!(
                element.node.addr(),
                Some(want_addr.parse().expect("valid ip"))
            );
        }
    }

    #[test]
    fn quoted_comma_is_not_a_separator() {
        // Edge case 19.
        let chain =
            parse3(&[b"for=\"1.2.3.4, 5.6.7.8\""], &[], &[]).expect("well formed, one element");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.elements()[0].node, NodeName::Unknown);

        // Edge case 26b: an unterminated quoted string INSIDE one element's
        // extension parameter swallows what looks like a second element
        // after a top-level comma, because that comma sits inside the still
        // open quote.
        let chain2 = parse3(&[b"for=1.1.1.1;x=\", for=9.9.9.9"], &[], &[])
            .expect("well formed, one element");
        assert_eq!(chain2.len(), 1);
        assert_eq!(
            chain2.elements()[0].node.addr(),
            Some("1.1.1.1".parse().expect("valid ip"))
        );
    }

    #[test]
    fn x_real_ip_is_never_read() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder
            .push(&mut arena, b"x-real-ip", b"1.2.3.4")
            .expect("well formed field");
        let section = builder.finish(&mut arena);

        let mut out = BytesMut::new();
        let chain = ForwardedChain::from_section(&section, &limits, &mut out)
            .expect("a section with no Forwarded/XFF/XFP field parses to an empty chain");
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn ipv6_unquoting() {
        // Edge case 18.
        let chain = parse3(&[b"for=\"[2001:db8::1]:8080\""], &[], &[]).expect("well formed");
        assert_eq!(chain.len(), 1);
        match chain.elements()[0].node {
            NodeName::Addr { addr, port } => {
                assert_eq!(addr, "2001:db8::1".parse::<IpAddr>().expect("valid ip"));
                assert_eq!(port, Some(8080));
            }
            other => panic!("expected an address, got {other:?}"),
        }

        // The unbracketed, unquoted form of the same address is not
        // permitted (edge case 8 restated in the Forwarded family).
        let bare = parse3(&[b"for=2001:db8::1"], &[], &[]).expect("well formed");
        assert_eq!(bare.elements()[0].node, NodeName::Unknown);
    }

    #[test]
    fn duplicate_param_per_element() {
        // Edge case 16.
        assert_eq!(
            parse3(&[b"for=1.2.3.4;for=5.6.7.8"], &[], &[]),
            Err(RejectReason::ForwardedDuplicateParam)
        );
        // Edge case 17: the duplicate rule is per element, not per value.
        let chain =
            parse3(&[b"for=1.2.3.4, for=5.6.7.8"], &[], &[]).expect("two distinct elements");
        assert_eq!(chain.len(), 2);

        // The same rule applies to proto, host and by.
        assert_eq!(
            parse3(&[b"proto=http;proto=https"], &[], &[]),
            Err(RejectReason::ForwardedDuplicateParam)
        );
        assert_eq!(
            parse3(&[b"host=a;host=b"], &[], &[]),
            Err(RejectReason::ForwardedDuplicateParam)
        );
        assert_eq!(
            parse3(&[b"by=1.2.3.4;by=5.6.7.8"], &[], &[]),
            Err(RejectReason::ForwardedDuplicateParam)
        );
    }

    #[test]
    fn non_addresses_terminate_the_walk() {
        let samples: [&[u8]; 5] = [
            b"for=unknown",
            b"for=_hidden",
            b"for=UNKNOWN",
            b"for=1.2.3.4.5",
            b"for=01.02.03.04",
        ];
        for raw in samples {
            let chain = parse3(&[raw], &[], &[])
                .unwrap_or_else(|e| panic!("{raw:?} should parse, got {e:?}"));
            let node = chain.elements()[0].node;
            assert!(
                node.terminates_walk(),
                "{raw:?} produced {node:?}, expected terminates_walk() == true"
            );
            assert_eq!(
                node.addr(),
                None,
                "{raw:?} produced {node:?}, expected no address"
            );
        }

        // An absent `for` also terminates the walk.
        let absent = parse3(&[b"proto=https"], &[], &[]).expect("well formed");
        assert!(absent.elements()[0].node.terminates_walk());

        // The positive control: a real address must NOT terminate the walk.
        // Without this, a mutation that made terminates_walk() always
        // return true would still pass every assertion above.
        let real = parse3(&[b"for=1.2.3.4"], &[], &[]).expect("well formed");
        assert!(!real.elements()[0].node.terminates_walk());
        assert_eq!(
            real.elements()[0].node.addr(),
            Some("1.2.3.4".parse().expect("valid ip"))
        );
    }

    #[test]
    fn caps_are_enforced_inside_the_loop() {
        let line32 = xff_line(32);
        let chain32 = parse3(&[], &[line32.as_slice()], &[])
            .expect("32 elements must be accepted at the default cap");
        assert_eq!(chain32.len(), 32);
        assert!(chain32.bytes() <= 4096);

        let line33 = xff_line(33);
        assert_eq!(
            parse3(&[], &[line33.as_slice()], &[]),
            Err(RejectReason::ForwardedElementLimit)
        );

        // A single 4097-byte value is refused on bytes before it is parsed.
        let too_long = vec![b'a'; 4097];
        assert_eq!(
            parse3(&[], &[too_long.as_slice()], &[]),
            Err(RejectReason::ForwardedBytesLimit)
        );

        // 100,000 entries in ONE value, engineered so a scan would have
        // produced a DIFFERENT error (ForwardedSyntax, from the trailing
        // empty token): getting ForwardedBytesLimit instead is the
        // deterministic proof the value was never tokenized.
        let huge = huge_xff_with_trailing_empty_token();
        assert_eq!(
            parse3(&[], &[huge.as_slice()], &[]),
            Err(RejectReason::ForwardedBytesLimit)
        );

        // The same shape of entries, spread across several short lines each
        // far under the byte cap, instead hits the ELEMENT cap: 4 lines of
        // 10 entries is 40 elements, well past the 32-element cap, while the
        // total bytes (well under 400) stay far under 4096.
        let short_lines = [xff_line(10), xff_line(10), xff_line(10), xff_line(10)];
        let short_refs: Vec<&[u8]> = short_lines.iter().map(Vec::as_slice).collect();
        assert_eq!(
            parse3(&[], &short_refs, &[]),
            Err(RejectReason::ForwardedElementLimit)
        );
    }

    #[test]
    fn xfp_last_token_wins() {
        // Edge case 31.
        let plain_https = parse3(&[b"for=1.1.1.1"], &[], &[b"https"]).expect("well formed");
        assert_eq!(plain_https.elements()[0].proto, Some(Scheme::Https));

        // Edge case 32: case insensitive.
        let upper_https = parse3(&[b"for=1.1.1.1"], &[], &[b"HTTPS"]).expect("well formed");
        assert_eq!(upper_https.elements()[0].proto, Some(Scheme::Https));

        // Edge case 33: an unrecognized value is ignored, not an error.
        let unknown_proto = parse3(&[b"for=1.1.1.1"], &[], &[b"gopher"]).expect("well formed");
        assert_eq!(unknown_proto.elements()[0].proto, None);

        // Edge case 34: the last comma-separated token on the line wins.
        let last_token = parse3(&[b"for=1.1.1.1"], &[], &[b"http, https"]).expect("well formed");
        assert_eq!(last_token.elements()[0].proto, Some(Scheme::Https));

        // A Forwarded-carried proto is never overwritten by
        // X-Forwarded-Proto: the Forwarded value wins.
        let forwarded_wins =
            parse3(&[b"for=1.1.1.1;proto=http"], &[], &[b"https"]).expect("well formed");
        assert_eq!(forwarded_wins.elements()[0].proto, Some(Scheme::Http));

        // An empty chain discards the XFP value instead of manufacturing an
        // element for it.
        let still_empty = parse3(&[], &[], &[b"https"]).expect("well formed, still empty");
        assert!(still_empty.is_empty());
    }

    #[test]
    fn forwarded_elements_precede_xff() {
        // Edge case 35.
        let chain = parse3(&[b"for=1.1.1.1"], &[b"2.2.2.2"], &[]).expect("well formed");
        assert_eq!(chain.len(), 2);
        assert!(!chain.elements()[0].from_xff);
        assert!(chain.elements()[1].from_xff);
        assert_eq!(
            chain.elements()[0].node.addr(),
            Some("1.1.1.1".parse().expect("valid ip"))
        );
        assert_eq!(
            chain.elements()[1].node.addr(),
            Some("2.2.2.2".parse().expect("valid ip"))
        );
    }

    #[test]
    fn chain_accessors_reflect_the_parse() {
        // `is_empty()` must actually read the parsed elements, not return a
        // constant: the positive case (empty) is already covered by
        // `x_real_ip_is_never_read` and by corpus_table case 1, so this pins
        // the NEGATIVE case, which a mutation collapsing `is_empty` to
        // `true` would otherwise still pass.
        let chain = parse3(&[b"for=1.2.3.4"], &[], &[]).expect("well formed");
        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 1);

        // `bytes()` must report the ACTUAL parsed byte count, not a
        // constant: "for=1.2.3.4" is exactly 11 bytes, a value distinct
        // enough that a mutation collapsing `bytes()` to 0 or to 1 cannot
        // pass this assertion.
        assert_eq!(chain.bytes(), 11);
    }

    #[test]
    fn from_section_parses_the_real_fields() {
        // `x_real_ip_is_never_read` only ever exercises `from_section` on a
        // section that must parse to an EMPTY chain, which cannot
        // distinguish a correct implementation from one that always returns
        // `Ok(ForwardedChain::default())` regardless of input. This is the
        // positive control: a section that DOES carry a real
        // `x-forwarded-for` field must parse to a matching non-empty chain.
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder
            .push(&mut arena, b"x-forwarded-for", b"203.0.113.7")
            .expect("well formed field");
        let section = builder.finish(&mut arena);

        let mut out = BytesMut::new();
        let chain = ForwardedChain::from_section(&section, &limits, &mut out)
            .expect("a section carrying a real X-Forwarded-For field must parse");
        assert_eq!(chain.len(), 1);
        assert!(chain.elements()[0].from_xff);
        assert_eq!(
            chain.elements()[0].node.addr(),
            Some("203.0.113.7".parse().expect("valid ip"))
        );
    }

    #[test]
    fn push_element_reserves_exactly_once_on_first_spill() {
        // White box, on `push_element` directly: whether and when the
        // element vector reserves capacity for the whole configured
        // ceiling is not observable through `ForwardedChain`'s public API
        // (`elements()` returns a slice with no capacity information), so
        // the only way to pin this behaviour is to call the private
        // function from inside its own module, as this test does.
        let limits = Limits::DEFAULT.clamped();
        let sample = ForwardedElement {
            node: NodeName::Absent,
            proto: None,
            from_xff: false,
        };

        let mut elements: SmallVec<[ForwardedElement; INLINE_ELEMENTS]> = SmallVec::default();
        for i in 0..INLINE_ELEMENTS {
            push_element(&mut elements, sample, limits);
            assert!(!elements.spilled(), "element {i} must still be inline");
        }
        assert_eq!(elements.len(), INLINE_ELEMENTS);
        assert_eq!(elements.capacity(), INLINE_ELEMENTS);

        // The 9th push is the first spill: capacity must jump straight to
        // the configured ceiling (32 by default), not merely to 9 or to
        // some doubled-from-8 value.
        push_element(&mut elements, sample, limits);
        assert!(
            elements.spilled(),
            "the 9th element must have spilled to the heap"
        );
        assert_eq!(elements.len(), 9);
        assert!(
            elements.capacity() >= usize::try_from(limits.max_forwarded_elements).unwrap_or(0),
            "the first spill must reserve for the whole configured ceiling in one call, got \
             capacity {}",
            elements.capacity()
        );
    }

    #[test]
    fn byte_budget_boundary_is_exact() {
        // A value landing EXACTLY on `max_forwarded_bytes` must be
        // accepted; one byte more must not. Both sides of the boundary are
        // asserted, not only the over side, so a `>` to `>=` mutation in
        // `charge_bytes` (which would reject the exact boundary) cannot
        // pass alongside a `>` to `<` style mutation (which would accept
        // past it).
        let tight = Limits {
            max_forwarded_bytes: 8,
            ..Limits::DEFAULT
        }
        .clamped();

        let exactly_eight = vec![b'a'; 8];
        let mut out = BytesMut::new();
        let chain = ForwardedChain::parse_into(
            core::iter::empty(),
            core::iter::once(exactly_eight.as_slice()),
            core::iter::empty(),
            &tight,
            &mut out,
        )
        .expect("a value landing exactly on the byte cap must be accepted");
        assert_eq!(chain.bytes(), 8);

        let nine = vec![b'a'; 9];
        let mut out2 = BytesMut::new();
        assert_eq!(
            ForwardedChain::parse_into(
                core::iter::empty(),
                core::iter::once(nine.as_slice()),
                core::iter::empty(),
                &tight,
                &mut out2,
            ),
            Err(RejectReason::ForwardedBytesLimit)
        );
    }

    #[test]
    fn unterminated_quote_is_never_silently_repaired() {
        // `parse_node_name`'s quote guard is `raw.len() < 2 || raw.last() !=
        // Some(b'"')`; an unterminated quote must be refused as `Unknown`
        // even when blindly stripping a trailing byte (as if it were a
        // closing quote that is not actually there) would happen to leave
        // behind text that parses as a real, but WRONG, address. `for=` here
        // carries `"1.2.3.45` (nine bytes: a leading quote, then the digits,
        // with no closing quote at all): naively dropping what LOOKS like a
        // final delimiter byte leaves "1.2.3.4", a valid, different address
        // this value never actually claimed.
        let chain = parse3(&[br#"for="1.2.3.45"#], &[], &[]).expect("well formed, one element");
        assert_eq!(chain.len(), 1);
        assert_eq!(
            chain.elements()[0].node,
            NodeName::Unknown,
            "an unterminated quote must never be repaired into a shorter, different address"
        );
    }

    #[test]
    fn quoted_proto_value_is_unquoted_and_compared() {
        // RFC 7239's `proto` value may be a `token` or a `quoted-string`;
        // none of the numbered edge cases exercise the quoted form, so it
        // was entirely untested until this test.
        let quoted_https =
            parse3(&[br#"for=1.1.1.1;proto="https""#], &[], &[]).expect("well formed");
        assert_eq!(quoted_https.elements()[0].proto, Some(Scheme::Https));

        let quoted_upper =
            parse3(&[br#"for=1.1.1.1;proto="HTTP""#], &[], &[]).expect("well formed");
        assert_eq!(quoted_upper.elements()[0].proto, Some(Scheme::Http));

        let quoted_unknown =
            parse3(&[br#"for=1.1.1.1;proto="gopher""#], &[], &[]).expect("well formed");
        assert_eq!(quoted_unknown.elements()[0].proto, None);

        // A quoted value with NO closing quote is malformed; `parse_proto`
        // must not strip a leading quote it cannot pair with a trailing one
        // and then match the leftover text anyway.
        let unterminated =
            parse3(&[br#"for=1.1.1.1;proto="https"#], &[], &[]).expect("well formed");
        assert_eq!(unterminated.elements()[0].proto, None);
    }

    #[test]
    fn unescape_resolves_quoted_pair_escapes_in_for_value() {
        // A `quoted-pair` escape (`\` followed by any byte becomes that
        // byte) inside a `for` value must actually be resolved, not merely
        // copied verbatim. `for="1.2.3.\4"` unescapes to the 7-byte address
        // "1.2.3.4"; left un-unescaped, the literal 8-byte text
        // "1.2.3.\4" (with the backslash still present) is not a valid IPv4
        // address at all and would parse as `Unknown` instead.
        let chain = parse3(&[br#"for="1.2.3.\4""#], &[], &[]).expect("well formed");
        assert_eq!(
            chain.elements()[0].node.addr(),
            Some("1.2.3.4".parse().expect("valid ip"))
        );
    }

    #[test]
    fn quoted_host_value_is_unquoted() {
        // The plain quoted case: a `host` value wrapped in `"..."` with no
        // escapes records the unquoted interior, not the raw bytes
        // including the quote marks.
        let chain = parse3(&[br#"for=1.2.3.4;host="a.example""#], &[], &[]).expect("well formed");
        assert_eq!(chain.host_claim(), Some(&b"a.example"[..]));

        // An UNTERMINATED quoted host value has no `NodeName::Unknown`
        // fallback to reach for; it is recorded verbatim, quote and all,
        // rather than silently stripped or dropped. This pins
        // `write_unquoted`'s own quote/no-quote boundary independently of
        // its inner escape loop.
        let unterminated =
            parse3(&[br#"for=1.2.3.4;host="unterminated"#], &[], &[]).expect("well formed");
        assert_eq!(unterminated.host_claim(), Some(&br#""unterminated"#[..]));
    }

    #[test]
    fn quoted_host_value_resolves_escapes() {
        // As `unescape_resolves_quoted_pair_escapes_in_for_value`, but for
        // `write_unquoted`'s own, separate escape loop: a `quoted-pair`
        // inside a `host` value must be resolved, not copied verbatim.
        let chain = parse3(&[br#"for=1.2.3.4;host="a\.example""#], &[], &[]).expect("well formed");
        assert_eq!(chain.host_claim(), Some(&b"a.example"[..]));
    }

    #[test]
    fn top_level_split_quote_state_is_exact() {
        // Kills a mutation deleting either match arm of `TopLevelSplit`'s
        // own in-quotes state machine, which `quoted_comma_is_not_a_separator`
        // and the corpus table do not reach because none of their cases
        // combine an ESCAPED quote with a LATER, real top-level delimiter.
        //
        // An escaped quote must not close the quoted span early: the comma
        // here sits between the escaped `"` and the real closing `"`, so
        // deleting the backslash-recognition arm would incorrectly treat it
        // as a live top-level separator and split this into two elements,
        // the second of which has no `=` and would turn `Ok` into `Err`.
        let escaped_quote_does_not_close =
            parse3(&[br#"for="a\"b, c""#], &[], &[]).expect("well formed, one element");
        assert_eq!(escaped_quote_does_not_close.len(), 1);
        assert_eq!(
            escaped_quote_does_not_close.elements()[0].node,
            NodeName::Unknown
        );

        // A real (unescaped) closing quote MUST close the span: deleting
        // the quote-recognition arm would leave `in_quotes` stuck true
        // forever, swallowing the `;proto=https` that follows a quoted
        // `host` value into the host text instead of splitting it out as
        // its own parameter.
        let real_quote_closes_and_lets_the_next_param_through =
            parse3(&[br#"for=1.2.3.4;host="a.example";proto=https"#], &[], &[])
                .expect("well formed");
        assert_eq!(
            real_quote_closes_and_lets_the_next_param_through.host_claim(),
            Some(&b"a.example"[..])
        );
        assert_eq!(
            real_quote_closes_and_lets_the_next_param_through.elements()[0].proto,
            Some(Scheme::Https)
        );
    }

    const FUZZ_ALPHABET: [u8; 23] = *b"0123456789.:,;=\"[]_for ";
    const _: () = assert!(FUZZ_ALPHABET.len() == 23);

    proptest::proptest! {
        #[test]
        fn prop_bounded_and_total(
            forwarded_lines in proptest::collection::vec(
                proptest::collection::vec(proptest::sample::select(&FUZZ_ALPHABET[..]), 0..=200),
                0..=4,
            ),
            xff_lines in proptest::collection::vec(
                proptest::collection::vec(proptest::sample::select(&FUZZ_ALPHABET[..]), 0..=200),
                0..=4,
            ),
        ) {
            let limits = Limits::DEFAULT.clamped();
            let mut out = BytesMut::new();
            let result = ForwardedChain::parse_into(
                forwarded_lines.iter().map(Vec::as_slice),
                xff_lines.iter().map(Vec::as_slice),
                core::iter::empty(),
                &limits,
                &mut out,
            );
            if let Ok(chain) = result {
                assert!(chain.len() <= 32);
                assert!(chain.bytes() <= 4096);
            }
        }
    }
}
