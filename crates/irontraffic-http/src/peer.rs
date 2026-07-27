// SPDX-License-Identifier: MIT OR Apache-2.0
//! The fail-closed right-to-left trust walk: [`TrustPolicy`], [`PeerIdentity`]
//! and [`resolve_identity`], plus the egress side that emits exactly one
//! `Forwarded` element and, optionally, the matching `X-Forwarded-*` fields.
//!
//! **Client identity has exactly one source.** [`resolve_identity`] is the
//! only function in this crate that decides who the client is; nothing
//! downstream re-derives it from a header. The default, [`TrustPolicy::None`],
//! never reads a forwarding header at all: every request's client is its
//! socket peer. An operator who fronts this proxy with a load balancer or a
//! CDN opts into reading the chain by choosing [`TrustPolicy::HopCount`] or
//! [`TrustPolicy::TrustedCidrs`], and both are fail-closed: a chain shorter
//! than the policy expects, a non-address entry where an address was needed,
//! or an untrusted socket peer all resolve to the socket peer, never to a
//! guess.
//!
//! **The rejected alternative.** Trusting the leftmost `X-Forwarded-For`
//! entry is the single most common mistake here, because it looks like the
//! obvious reading of "the client is the first one in the list". The
//! leftmost entry is 100% attacker controlled: it is whatever the client
//! typed. This module always walks from the RIGHT, peeling off hops it
//! trusts, because a client can only ever pad the LEFT end of the chain; a
//! walk that starts from the right is invariant under that padding.
//!
//! **`peer_trusted` is a separate, narrower claim.** It answers "was the
//! immediate socket peer's address checked against a configured prefix list
//! and found inside it", which only [`TrustPolicy::TrustedCidrs`] can ever
//! answer yes to: [`TrustPolicy::HopCount`] carries no address list, so
//! granting the trusted-internal capability under it would mean trusting
//! whoever opened the socket, including an attacker who reached the listener
//! directly. [`PeerIdentity::trusted_internal`] is the ONE place this answer
//! is read from; the `x-envoy-*` metadata family is honoured only on a
//! connection this same value marks trusted, and nowhere else computes it.
//!
//! **Egress never passes through what we received.** [`write_forwarded_element`]
//! synthesizes exactly one `Forwarded` element from a [`PeerIdentity`] and the
//! listener's own address; it never appends to an inbound value, because
//! there is no inbound value left to append to by the time this runs
//! (`strip_ingress`, `hop-by-hop-and-reserved-prefix-strip`, #26, deletes
//! every inbound `Forwarded`/`X-Forwarded-*`/`X-Real-IP` field before a
//! request is forwarded). That is what makes the upstream's view of identity
//! a function of this proxy's configuration, never of the client's input.

use std::net::{IpAddr, SocketAddr};

use bytes::{BufMut, BytesMut};

use crate::authority::Authority;
use crate::cidr::IpCidr;
use crate::forwarded::{ForwardedChain, ForwardedElement, NodeName};
use crate::scalar::Scheme;

/// How much of an inbound forwarding chain to believe.
///
/// This is the ONLY trust decision this product makes about who a client is:
/// see the module documentation for why the leftmost entry is never the
/// answer and why a short chain fails closed instead of falling back to
/// whatever is present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustPolicy {
    /// Trust exactly N hops from the right. If fewer entries exist than N,
    /// FAIL CLOSED: use the socket peer address, with
    /// [`IdentitySource::Socket`].
    HopCount(u8),
    /// Pop entries from the right while their address is in `cidrs`. Stop at
    /// the first address that is not. That address is the client. If ALL
    /// entries are trusted, the leftmost entry is the client.
    TrustedCidrs(Vec<IpCidr>),
    /// No proxy in front. Ignore every forwarding header. Client = socket
    /// peer. DEFAULT.
    None,
}

impl Default for TrustPolicy {
    /// [`TrustPolicy::None`].
    fn default() -> Self {
        TrustPolicy::None
    }
}

/// The single client identity for a request. Built once, at ingress.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The address policy, logging, rate limiting and the emitted
    /// `Forwarded` element all use. Never attacker chosen unless the
    /// operator configured it to be.
    pub client: IpAddr,
    /// The client's source port when we know it, which is only when
    /// `source` is `Socket` or `ProxyProtocol`, or when a forwarding element
    /// carried one.
    pub client_port: Option<u16>,
    /// How `client` was determined.
    pub source: IdentitySource,
    /// The scheme the client used to reach the outermost trusted proxy, when
    /// it told us.
    pub forwarded_proto: Option<Scheme>,
    /// How many forwarding elements the walk consumed from the right.
    pub trusted_hops: u8,
    /// True when the immediate socket peer's address was CHECKED against a
    /// configured prefix list and matched. This is the ONE answer to "is
    /// this connection trusted-internal", used by the `x-envoy-*` honouring
    /// rule and by nothing else.
    ///
    /// Only [`TrustPolicy::TrustedCidrs`] can make this true, because it is
    /// the only policy that has an address list to check. Under
    /// [`TrustPolicy::HopCount`] and [`TrustPolicy::None`] it is always
    /// false: an unverified operator assertion must not grant a capability
    /// an external client would otherwise not have.
    pub peer_trusted: bool,
}

/// Where [`PeerIdentity::client`] came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IdentitySource {
    /// The TCP or QUIC peer address. The default and the fail-closed answer.
    Socket,
    /// A PROXY protocol header from a listener configured to expect one.
    ProxyProtocol,
    /// A trusted forwarding element.
    ForwardedChain,
}

impl PeerIdentity {
    /// True when the immediate socket peer is inside the policy's trusted
    /// set. The one answer to "is this connection trusted-internal"; the
    /// `x-envoy-*` honouring rule consults this and nothing else.
    #[must_use]
    pub const fn trusted_internal(&self) -> bool {
        self.peer_trusted
    }
}

/// The nearest `proto` at or to the right of `elements[start..]`: the client
/// element's own claim when it has one, otherwise the first one found
/// scanning towards the proxy end of the chain. Shared by the `HopCount` and
/// `TrustedCidrs` arms of [`resolve_identity`] below (design step 4c and
/// step 5e both read this the same way).
fn nearest_proto(elements: &[ForwardedElement], start: usize) -> Option<Scheme> {
    elements
        .get(start..)?
        .iter()
        .find_map(|element| element.proto)
}

/// Narrows a hop count that can never exceed
/// `Limits::CEILING.max_forwarded_elements` (255) in practice, but is
/// saturated defensively rather than assumed, matching the design's own
/// "saturating at 255" wording for step 5d.
fn saturate_hops(value: u32) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

/// The outcome of walking a non-empty [`ForwardedChain`] from the right
/// under [`TrustPolicy::TrustedCidrs`] (design step 5b/5c).
enum WalkOutcome {
    /// A non-address element stopped the walk (design step 5b's "otherwise
    /// stop... fail closed to the base, `trusted_hops`: 0"): the caller
    /// discards any hops already counted and returns the base identity.
    FailClosed,
    /// The client element: its index (for the rightward `proto` scan), its
    /// address and port, and how many elements the walk consumed as trusted
    /// hops. When every element was trusted this is the leftmost element
    /// (index 0) and `trusted_hops` counts it too (design step 5c/5d).
    Client {
        index: usize,
        addr: IpAddr,
        port: Option<u16>,
        trusted_hops: u8,
    },
}

/// Walks `elements` right to left under `TrustedCidrs(cidrs)`. The caller
/// (`resolve_identity`) MUST have already checked that `elements` is
/// non-empty and that the base address is itself trusted (design steps 5a
/// and 5a2); this function does not repeat either check.
fn walk_trusted_cidrs(elements: &[ForwardedElement], cidrs: &[IpCidr]) -> WalkOutcome {
    let len = elements.len();
    let mut trusted_hops: u32 = 0;
    for offset in 0..len {
        let idx = len.saturating_sub(1).saturating_sub(offset);
        let Some(element) = elements.get(idx) else {
            return WalkOutcome::FailClosed;
        };
        match element.node {
            NodeName::Addr { addr, port } if cidrs.iter().any(|cidr| cidr.contains(addr)) => {
                trusted_hops = trusted_hops.saturating_add(1);
                if idx == 0 {
                    // Every element, including this leftmost one, was
                    // trusted: it becomes the client AND counts among
                    // `trusted_hops` (design step 5c/5d).
                    return WalkOutcome::Client {
                        index: 0,
                        addr,
                        port,
                        trusted_hops: saturate_hops(trusted_hops),
                    };
                }
            }
            NodeName::Addr { addr, port } => {
                // The first untrusted address, walking from the right: it is
                // the client, and it is NOT itself counted as a trusted hop.
                return WalkOutcome::Client {
                    index: idx,
                    addr,
                    port,
                    trusted_hops: saturate_hops(trusted_hops),
                };
            }
            NodeName::Unknown | NodeName::Obfuscated | NodeName::Absent => {
                return WalkOutcome::FailClosed;
            }
        }
    }
    // Unreachable given the caller's non-empty precondition (the loop above
    // always returns for a non-empty slice), but written out rather than
    // assumed: an empty slice falls through to the same fail-closed answer
    // the caller would have produced itself via design step 5a2.
    WalkOutcome::FailClosed
}

/// Resolves the one client identity for a request.
///
/// Total: every degenerate input has a defined, fail-closed answer, so there
/// is no error type. A chain shorter than the policy expects, a non-address
/// entry where an address was needed, or an untrusted socket peer all
/// resolve to the socket peer with [`IdentitySource::Socket`].
#[must_use]
pub fn resolve_identity(
    socket_peer: SocketAddr,
    proxy_proto: Option<SocketAddr>,
    chain: &ForwardedChain,
    policy: &TrustPolicy,
) -> PeerIdentity {
    // Step 1: the base. The PROXY protocol address describes the same hop as
    // the socket, more accurately, so it is preferred when present.
    let (base_ip, base_port, base_source) = match proxy_proto {
        Some(declared) => (
            declared.ip(),
            Some(declared.port()),
            IdentitySource::ProxyProtocol,
        ),
        None => (
            socket_peer.ip(),
            Some(socket_peer.port()),
            IdentitySource::Socket,
        ),
    };

    // Step 2: `peer_trusted`. Only `TrustedCidrs` has an address list to
    // check; every other policy, `HopCount(n)` included for every `n`,
    // leaves this false. This is an OUTPUT of the base address alone: it
    // never depends on how the walk below resolves the client, and the walk
    // below never reads it either.
    let peer_trusted = match policy {
        TrustPolicy::TrustedCidrs(cidrs) => cidrs.iter().any(|cidr| cidr.contains(base_ip)),
        TrustPolicy::HopCount(_) | TrustPolicy::None => false,
    };

    let fail_closed = PeerIdentity {
        client: base_ip,
        client_port: base_port,
        source: base_source,
        forwarded_proto: None,
        trusted_hops: 0,
        peer_trusted,
    };

    match policy {
        // Step 3: the chain is not consulted at all.
        TrustPolicy::None => fail_closed,

        // Step 4: HopCount(n). `n == 0` needs no special case: the computed
        // index `chain.len() - 0 == chain.len()` is always one past the end
        // of any slice, so `elements.get(idx)` always misses and this falls
        // through to `fail_closed` exactly as `None` would, without ever
        // reading an element.
        TrustPolicy::HopCount(n) => {
            let elements = chain.elements();
            let n_usize = usize::from(*n);
            // `checked_sub` returning `None` here IS "chain.len() < n"
            // (design step 4b): the two conditions are the same fact.
            let Some(idx) = elements.len().checked_sub(n_usize) else {
                return fail_closed;
            };
            let Some(element) = elements.get(idx) else {
                return fail_closed;
            };
            let NodeName::Addr { addr, port } = element.node else {
                // Not an address: fail closed exactly as a short chain would
                // (design step 4c).
                return fail_closed;
            };
            PeerIdentity {
                client: addr,
                client_port: port,
                source: IdentitySource::ForwardedChain,
                forwarded_proto: nearest_proto(elements, idx),
                trusted_hops: *n,
                peer_trusted,
            }
        }

        // Step 5: TrustedCidrs(cidrs).
        TrustPolicy::TrustedCidrs(cidrs) => {
            // 5a: an untrusted base is worth nothing. 5a2: an empty chain
            // has no leftmost element to fall back to; both share the exact
            // same fail-closed answer as every other short-chain case.
            if !peer_trusted || chain.is_empty() {
                return fail_closed;
            }
            match walk_trusted_cidrs(chain.elements(), cidrs) {
                WalkOutcome::FailClosed => fail_closed,
                WalkOutcome::Client {
                    index,
                    addr,
                    port,
                    trusted_hops,
                } => PeerIdentity {
                    client: addr,
                    client_port: port,
                    source: IdentitySource::ForwardedChain,
                    forwarded_proto: nearest_proto(chain.elements(), index),
                    trusted_hops,
                    peer_trusted,
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Egress: exactly one synthesized `Forwarded` element, and the matching
// `X-Forwarded-*` field values.
// ---------------------------------------------------------------------------

/// Renders `v`'s decimal digits least-significant-digit first into a fixed
/// 10-byte buffer (wide enough for any `u32`, so this serves both a `u16`
/// port and a `u8` address octet promoted to `u32`), returning the buffer and
/// how many of its leading slots hold a digit. Mirrors
/// `authority::port_digits`'s own contract: every writer below and its
/// matching length computation call this SAME function for the same value,
/// so the two can never disagree about how many bytes it takes.
fn decimal_digits(v: u32) -> ([u8; 10], usize) {
    let mut digits = [0_u8; 10];
    let mut count = 0_usize;
    let mut remaining = v;
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

/// Writes `v`'s decimal digits into `out` and returns how many bytes were
/// written; always agrees with `decimal_digits(v).1`, since it is the same
/// computation.
fn write_decimal(v: u32, out: &mut BytesMut) -> usize {
    let (digits, count) = decimal_digits(v);
    for i in (0..count).rev() {
        if let Some(&b) = digits.get(i) {
            out.put_u8(b);
        }
    }
    count
}

/// The fixed byte length of the uncompressed, zero-padded 8-group hex form
/// this module writes for an IPv6 address: 8 groups of 4 hex digits plus 7
/// colon separators (8 * 4 + 7). This module deliberately does not replicate
/// `Display`'s RFC 5952 `::` run-length compression: any well-formed hex
/// rendering of the same 128 bits re-parses to the same `Ipv6Addr` through
/// `Ipv6Addr::from_str`, which is all `forwarded_element_len_is_exact` (test
/// 9) requires, and a fixed length free of a compression decision is simpler
/// to keep provably in agreement between the writer and the length
/// computation than a variable one would be.
const IPV6_ADDR_LEN: usize = 39;

const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// Writes `addr`'s 8-group hex form (see [`IPV6_ADDR_LEN`]) into `out`.
/// Always writes exactly `IPV6_ADDR_LEN` bytes: the loop below is
/// unconditional (no branch can make it write more or fewer), so returning
/// the same constant [`forwarded_element_len`] and its callees use is not a
/// second, divergent calculation, it is the same fact stated twice.
fn write_ipv6_hex(addr: std::net::Ipv6Addr, out: &mut BytesMut) -> usize {
    for (i, group) in addr.segments().iter().enumerate() {
        if i > 0 {
            out.put_u8(b':');
        }
        for shift in [12_u32, 8, 4, 0] {
            let nibble = (u32::from(*group) >> shift) & 0xF;
            let index = usize::try_from(nibble).unwrap_or(0);
            let ch = HEX_DIGITS.get(index).copied().unwrap_or(b'0');
            out.put_u8(ch);
        }
    }
    IPV6_ADDR_LEN
}

/// The byte length [`write_addr_text`] will write for `addr`.
fn addr_text_len(addr: IpAddr) -> usize {
    match addr {
        IpAddr::V4(v4) => {
            let mut len = 3_usize; // three '.' separators
            for octet in v4.octets() {
                len = len.saturating_add(decimal_digits(u32::from(octet)).1);
            }
            len
        }
        IpAddr::V6(_) => IPV6_ADDR_LEN,
    }
}

/// Writes `addr`'s text form (dotted-decimal for IPv4, the 8-group hex form
/// for IPv6, neither bracketed nor quoted) into `out`.
fn write_addr_text(addr: IpAddr, out: &mut BytesMut) -> usize {
    match addr {
        IpAddr::V4(v4) => {
            let mut written = 0_usize;
            for (i, octet) in v4.octets().iter().enumerate() {
                if i > 0 {
                    out.put_u8(b'.');
                    written = written.saturating_add(1);
                }
                written = written.saturating_add(write_decimal(u32::from(*octet), out));
            }
            written
        }
        IpAddr::V6(v6) => write_ipv6_hex(v6, out),
    }
}

/// The unquoted length of a `node` value (RFC 7239 Section 6): the address
/// text, bracketed when IPv6, with `:port` appended when `port` is `Some`.
fn node_raw_len(addr: IpAddr, port: Option<u16>) -> usize {
    let mut len = addr_text_len(addr);
    if addr.is_ipv6() {
        len = len.saturating_add(2); // '[' and ']'
    }
    if let Some(p) = port {
        len = len
            .saturating_add(1)
            .saturating_add(decimal_digits(u32::from(p)).1);
    }
    len
}

/// Writes a `node` value (unquoted): bracketed address text, then `:port`
/// when `port` is `Some`.
fn write_node(addr: IpAddr, port: Option<u16>, out: &mut BytesMut) -> usize {
    let mut written = 0_usize;
    if addr.is_ipv6() {
        out.put_u8(b'[');
        written = written.saturating_add(1);
    }
    written = written.saturating_add(write_addr_text(addr, out));
    if addr.is_ipv6() {
        out.put_u8(b']');
        written = written.saturating_add(1);
    }
    if let Some(p) = port {
        out.put_u8(b':');
        written = written.saturating_add(1);
        written = written.saturating_add(write_decimal(u32::from(p), out));
    }
    written
}

/// RFC 7239 Section 4 (`value = token / quoted-string`) plus RFC 9110
/// Section 5.6.2 (`:`, `[` and `]` are not `tchar`): a `for` value must be
/// quoted exactly when it contains one of those three bytes, which is
/// exactly when the address is IPv6 (always bracketed) or the client's port
/// is known (always adds a `:`).
fn client_needs_quote(identity: PeerIdentity) -> bool {
    identity.client.is_ipv6() || identity.client_port.is_some()
}

/// As [`client_needs_quote`], for the `host` parameter: an authority needs
/// quoting exactly when it is a bracketed IPv6 literal or carries a
/// non-default port (the only way `Authority::write_to` ever emits a `:`).
fn authority_needs_quote(authority: &Authority) -> bool {
    authority.is_ipv6_literal() || authority.port().is_some()
}

/// The `for=` value's length, quoted when [`client_needs_quote`] says so.
fn for_value_len(identity: PeerIdentity) -> usize {
    let raw = node_raw_len(identity.client, identity.client_port);
    if client_needs_quote(identity) {
        raw.saturating_add(2)
    } else {
        raw
    }
}

/// Writes the `for=` value (without the `for=` prefix itself).
fn write_for_value(identity: PeerIdentity, out: &mut BytesMut) -> usize {
    let quote = client_needs_quote(identity);
    let mut written = 0_usize;
    if quote {
        out.put_u8(b'"');
        written = written.saturating_add(1);
    }
    written = written.saturating_add(write_node(identity.client, identity.client_port, out));
    if quote {
        out.put_u8(b'"');
        written = written.saturating_add(1);
    }
    written
}

/// The `by=` value's length. `local` is a `SocketAddr`, which always carries
/// a port, so `by` is always quoted (it always contains a `:`).
fn by_value_len(local: SocketAddr) -> usize {
    node_raw_len(local.ip(), Some(local.port())).saturating_add(2)
}

/// Writes the `by=` value (without the `by=` prefix itself), always quoted.
fn write_by_value(local: SocketAddr, out: &mut BytesMut) -> usize {
    out.put_u8(b'"');
    let mut written = 1_usize;
    written = written.saturating_add(write_node(local.ip(), Some(local.port()), out));
    out.put_u8(b'"');
    written.saturating_add(1)
}

/// The `host=` value's length, quoted when [`authority_needs_quote`] says
/// so.
fn host_value_len(authority: &Authority) -> usize {
    let raw = authority.written_len();
    if authority_needs_quote(authority) {
        raw.saturating_add(2)
    } else {
        raw
    }
}

/// Writes the `host=` value (without the `host=` prefix itself).
fn write_host_value(authority: &Authority, out: &mut BytesMut) -> usize {
    let quote = authority_needs_quote(authority);
    let mut written = 0_usize;
    if quote {
        out.put_u8(b'"');
        written = written.saturating_add(1);
    }
    written = written.saturating_add(authority.write_to(out));
    if quote {
        out.put_u8(b'"');
        written = written.saturating_add(1);
    }
    written
}

/// Writes the single RFC 7239 element we emit upstream into `out`, returning
/// the byte count written, which always equals
/// [`forwarded_element_len`]`(..)`.
pub fn write_forwarded_element(
    identity: &PeerIdentity,
    local: SocketAddr,
    scheme: Scheme,
    authority: &Authority,
    out: &mut BytesMut,
) -> usize {
    let mut written = 0_usize;

    out.extend_from_slice(b"for=");
    written = written.saturating_add(4);
    written = written.saturating_add(write_for_value(*identity, out));

    out.extend_from_slice(b";by=");
    written = written.saturating_add(4);
    written = written.saturating_add(write_by_value(local, out));

    out.extend_from_slice(b";proto=");
    written = written.saturating_add(7);
    out.extend_from_slice(scheme.as_bytes());
    written = written.saturating_add(scheme.as_bytes().len());

    out.extend_from_slice(b";host=");
    written = written.saturating_add(6);
    written = written.saturating_add(write_host_value(authority, out));

    written
}

/// The number of bytes [`write_forwarded_element`] will write.
#[must_use]
pub fn forwarded_element_len(
    identity: &PeerIdentity,
    local: SocketAddr,
    scheme: Scheme,
    authority: &Authority,
) -> usize {
    let mut len = 4_usize; // "for="
    len = len.saturating_add(for_value_len(*identity));
    len = len.saturating_add(4); // ";by="
    len = len.saturating_add(by_value_len(local));
    len = len.saturating_add(7); // ";proto="
    len = len.saturating_add(scheme.as_bytes().len());
    len = len.saturating_add(6); // ";host="
    len = len.saturating_add(host_value_len(authority));
    len
}

/// The four `X-Forwarded-*` values, written into `out` back to back with no
/// separators, with the returned ranges giving, in this order, `(for, proto,
/// host, port)`.
///
/// The ranges are ABSOLUTE indices into `out` after the call, so
/// `&out[r.start..r.end]` is the value. They are not relative to the region
/// this call wrote. When `identity.client_port` is `None` the `port` range
/// is empty (`start == end`), and the caller MUST omit the
/// `x-forwarded-port` field entirely rather than emit an empty value;
/// `Range::is_empty` is the check.
///
/// Unlike [`write_forwarded_element`] these values are never quoted: the
/// `X-Forwarded-*` family has no `quoted-string` production, and an IPv6
/// client is written bracketed but bare.
pub fn write_x_forwarded(
    identity: &PeerIdentity,
    scheme: Scheme,
    authority: &Authority,
    out: &mut BytesMut,
) -> [core::ops::Range<usize>; 4] {
    let for_start = out.len();
    write_node(identity.client, None, out);
    let for_end = out.len();

    let proto_start = out.len();
    out.extend_from_slice(scheme.as_bytes());
    let proto_end = out.len();

    let host_start = out.len();
    authority.write_to(out);
    let host_end = out.len();

    let port_start = out.len();
    if let Some(p) = identity.client_port {
        write_decimal(u32::from(p), out);
    }
    let port_end = out.len();

    [
        for_start..for_end,
        proto_start..proto_end,
        host_start..host_end,
        port_start..port_end,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    fn empty_chain() -> ForwardedChain {
        ForwardedChain::default()
    }

    fn xff_chain(entries: &[&str]) -> ForwardedChain {
        let joined = entries.join(", ");
        let mut out = BytesMut::new();
        ForwardedChain::parse_into(
            core::iter::empty(),
            core::iter::once(joined.as_bytes()),
            core::iter::empty(),
            &Limits::DEFAULT.clamped(),
            &mut out,
        )
        .expect("well formed XFF chain fixture")
    }

    fn forwarded_chain(entries: &[&str]) -> ForwardedChain {
        let joined = entries.join(", ");
        let mut out = BytesMut::new();
        ForwardedChain::parse_into(
            core::iter::once(joined.as_bytes()),
            core::iter::empty(),
            core::iter::empty(),
            &Limits::DEFAULT.clamped(),
            &mut out,
        )
        .expect("well formed Forwarded chain fixture")
    }

    fn attacker_32_chain() -> ForwardedChain {
        let entries: Vec<String> = (0..32_u32).map(|i| format!("203.0.113.{i}")).collect();
        let refs: Vec<&str> = entries.iter().map(String::as_str).collect();
        xff_chain(&refs)
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().expect("valid IP literal in a test fixture")
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse()
            .expect("valid socket address literal in a test fixture")
    }

    fn cidr(s: &str, len: u8) -> IpCidr {
        IpCidr::new(addr(s), len).expect("valid prefix in a test fixture")
    }

    fn identity(client: IpAddr, client_port: Option<u16>) -> PeerIdentity {
        PeerIdentity {
            client,
            client_port,
            source: IdentitySource::ForwardedChain,
            forwarded_proto: None,
            trusted_hops: 0,
            peer_trusted: false,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table of edge cases 1 through 19 (case 20 is IpCidr::new's own bound and \
                  is covered by cidr::tests::prefix_bounds instead, since it has no \
                  socket_peer/chain/policy shape to fit this table), plus the loop that checks \
                  each row; splitting the table would break the 1:1 mapping to that numbered list"
    )]
    #[test]
    fn walk_table() {
        struct Case {
            label: &'static str,
            socket_peer: SocketAddr,
            proxy_proto: Option<SocketAddr>,
            chain: ForwardedChain,
            policy: TrustPolicy,
            client: IpAddr,
            source: IdentitySource,
            hops: u8,
            peer_trusted: bool,
        }

        let cases: Vec<Case> = vec![
            // 1: empty chain, None.
            Case {
                label: "1",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: empty_chain(),
                policy: TrustPolicy::None,
                client: addr("198.51.100.1"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 2: 32-element attacker chain, None. The chain is not read.
            Case {
                label: "2",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: attacker_32_chain(),
                policy: TrustPolicy::None,
                client: addr("198.51.100.1"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 3: empty chain, HopCount(1).
            Case {
                label: "3",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: empty_chain(),
                policy: TrustPolicy::HopCount(1),
                client: addr("198.51.100.1"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 4: one-element chain, HopCount(1).
            Case {
                label: "4",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: xff_chain(&["1.2.3.4"]),
                policy: TrustPolicy::HopCount(1),
                client: addr("1.2.3.4"),
                source: IdentitySource::ForwardedChain,
                hops: 1,
                peer_trusted: false,
            },
            // 5: two-element chain, HopCount(1): index 2 - 1 = 1.
            Case {
                label: "5",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: xff_chain(&["9.9.9.9", "1.2.3.4"]),
                policy: TrustPolicy::HopCount(1),
                client: addr("1.2.3.4"),
                source: IdentitySource::ForwardedChain,
                hops: 1,
                peer_trusted: false,
            },
            // 6: same chain, HopCount(2): index 0.
            Case {
                label: "6",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: xff_chain(&["9.9.9.9", "1.2.3.4"]),
                policy: TrustPolicy::HopCount(2),
                client: addr("9.9.9.9"),
                source: IdentitySource::ForwardedChain,
                hops: 2,
                peer_trusted: false,
            },
            // 7: two-element chain, HopCount(3): fail closed.
            Case {
                label: "7",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: xff_chain(&["9.9.9.9", "1.2.3.4"]),
                policy: TrustPolicy::HopCount(3),
                client: addr("198.51.100.1"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 8: HopCount(0) behaves as None; a non-empty chain proves it is
            // not consulted.
            Case {
                label: "8",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: xff_chain(&["1.2.3.4"]),
                policy: TrustPolicy::HopCount(0),
                client: addr("198.51.100.1"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 9: HopCount(255) with a 32-element chain: fail closed.
            Case {
                label: "9",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: attacker_32_chain(),
                policy: TrustPolicy::HopCount(255),
                client: addr("198.51.100.1"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 10: chain [unknown, 1.2.3.4], HopCount(2): index 0 is not an
            // address.
            Case {
                label: "10",
                socket_peer: sock("198.51.100.1:9000"),
                proxy_proto: None,
                chain: xff_chain(&["unknown", "1.2.3.4"]),
                policy: TrustPolicy::HopCount(2),
                client: addr("198.51.100.1"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 11: TrustedCidrs([10.0.0.0/8]), untrusted socket peer.
            Case {
                label: "11",
                socket_peer: sock("203.0.113.5:1111"),
                proxy_proto: None,
                chain: empty_chain(),
                policy: TrustPolicy::TrustedCidrs(vec![cidr("10.0.0.0", 8)]),
                client: addr("203.0.113.5"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 12: trusted base, rightmost trusted and consumed, next
            // untrusted becomes the client.
            Case {
                label: "12",
                socket_peer: sock("10.1.2.3:2222"),
                proxy_proto: None,
                chain: xff_chain(&["1.2.3.4", "10.9.9.9"]),
                policy: TrustPolicy::TrustedCidrs(vec![cidr("10.0.0.0", 8)]),
                client: addr("1.2.3.4"),
                source: IdentitySource::ForwardedChain,
                hops: 1,
                peer_trusted: true,
            },
            // 13: every element trusted; the leftmost is the client.
            Case {
                label: "13",
                socket_peer: sock("10.1.2.3:2222"),
                proxy_proto: None,
                chain: xff_chain(&["10.0.0.1", "10.0.0.2"]),
                policy: TrustPolicy::TrustedCidrs(vec![cidr("10.0.0.0", 8)]),
                client: addr("10.0.0.1"),
                source: IdentitySource::ForwardedChain,
                hops: 2,
                peer_trusted: true,
            },
            // 14: a non-address stops the walk entirely; peer_trusted stays
            // true because the base itself was trusted, but the client falls
            // back to the base.
            Case {
                label: "14",
                socket_peer: sock("10.1.2.3:2222"),
                proxy_proto: None,
                chain: xff_chain(&["unknown", "10.0.0.2"]),
                policy: TrustPolicy::TrustedCidrs(vec![cidr("10.0.0.0", 8)]),
                client: addr("10.1.2.3"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: true,
            },
            // 15: empty chain, trusted base: client is the base itself.
            Case {
                label: "15",
                socket_peer: sock("10.1.2.3:2222"),
                proxy_proto: None,
                chain: empty_chain(),
                policy: TrustPolicy::TrustedCidrs(vec![cidr("10.0.0.0", 8)]),
                client: addr("10.1.2.3"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: true,
            },
            // 16: TrustedCidrs([]): nothing is ever trusted.
            Case {
                label: "16",
                socket_peer: sock("10.1.2.3:2222"),
                proxy_proto: None,
                chain: xff_chain(&["1.2.3.4"]),
                policy: TrustPolicy::TrustedCidrs(Vec::new()),
                client: addr("10.1.2.3"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 17: TrustedCidrs([::/0]) with an IPv4 socket peer: families
            // never mix.
            Case {
                label: "17",
                socket_peer: sock("203.0.113.5:1111"),
                proxy_proto: None,
                chain: empty_chain(),
                policy: TrustPolicy::TrustedCidrs(vec![cidr("::", 0)]),
                client: addr("203.0.113.5"),
                source: IdentitySource::Socket,
                hops: 0,
                peer_trusted: false,
            },
            // 18: TrustedCidrs([0.0.0.0/0]): every IPv4 address is trusted,
            // so the leftmost element wins, attacker chosen by operator
            // choice.
            Case {
                label: "18",
                socket_peer: sock("10.1.2.3:2222"),
                proxy_proto: None,
                chain: xff_chain(&["6.6.6.6", "7.7.7.7"]),
                policy: TrustPolicy::TrustedCidrs(vec![cidr("0.0.0.0", 0)]),
                client: addr("6.6.6.6"),
                source: IdentitySource::ForwardedChain,
                hops: 2,
                peer_trusted: true,
            },
            // 19: PROXY protocol present and TrustedCidrs: the PROXY-declared
            // address is the base the chain is walked from.
            Case {
                label: "19",
                socket_peer: sock("192.0.2.1:3333"),
                proxy_proto: Some(sock("10.0.0.7:4444")),
                chain: xff_chain(&["1.2.3.4"]),
                policy: TrustPolicy::TrustedCidrs(vec![cidr("10.0.0.0", 8)]),
                client: addr("1.2.3.4"),
                source: IdentitySource::ForwardedChain,
                hops: 0,
                peer_trusted: true,
            },
        ];

        for case in &cases {
            let got = resolve_identity(
                case.socket_peer,
                case.proxy_proto,
                &case.chain,
                &case.policy,
            );
            assert_eq!(
                got.client, case.client,
                "case {}: client mismatch",
                case.label
            );
            assert_eq!(
                got.source, case.source,
                "case {}: source mismatch",
                case.label
            );
            assert_eq!(
                got.trusted_hops, case.hops,
                "case {}: trusted_hops mismatch",
                case.label
            );
            assert_eq!(
                got.peer_trusted, case.peer_trusted,
                "case {}: peer_trusted mismatch",
                case.label
            );
        }
    }

    #[test]
    fn fail_closed_on_short_chain() {
        let socket_peer = sock("198.51.100.1:9000");

        // Edge case 3.
        let got = resolve_identity(socket_peer, None, &empty_chain(), &TrustPolicy::HopCount(1));
        assert_eq!(got.source, IdentitySource::Socket);
        assert_eq!(got.client, socket_peer.ip());

        // Edge case 7.
        let two = xff_chain(&["9.9.9.9", "1.2.3.4"]);
        let got = resolve_identity(socket_peer, None, &two, &TrustPolicy::HopCount(3));
        assert_eq!(got.source, IdentitySource::Socket);
        assert_eq!(got.client, socket_peer.ip());

        // Edge case 9.
        let got = resolve_identity(
            socket_peer,
            None,
            &attacker_32_chain(),
            &TrustPolicy::HopCount(255),
        );
        assert_eq!(got.source, IdentitySource::Socket);
        assert_eq!(got.client, socket_peer.ip());

        // Edge case 10.
        let mixed = xff_chain(&["unknown", "1.2.3.4"]);
        let got = resolve_identity(socket_peer, None, &mixed, &TrustPolicy::HopCount(2));
        assert_eq!(got.source, IdentitySource::Socket);
        assert_eq!(got.client, socket_peer.ip());
    }

    #[test]
    fn none_never_reads_the_chain() {
        let socket_peer = sock("198.51.100.1:9000");
        let chain = attacker_32_chain();
        assert_eq!(chain.len(), 32);
        let got = resolve_identity(socket_peer, None, &chain, &TrustPolicy::None);
        assert_eq!(got.client, socket_peer.ip());
        assert_eq!(got.trusted_hops, 0);
    }

    #[test]
    fn proxy_protocol_is_the_base() {
        let socket_peer = sock("192.0.2.1:1111");
        let proxy_proto = Some(sock("10.0.0.7:2222"));
        let policy = TrustPolicy::TrustedCidrs(vec![cidr("10.0.0.0", 8)]);
        let chain = xff_chain(&["1.2.3.4", "10.9.9.9"]);

        let got = resolve_identity(socket_peer, proxy_proto, &chain, &policy);
        assert!(
            got.peer_trusted,
            "the PROXY-declared address must be checked, not the socket address"
        );
        assert_eq!(
            got.client,
            addr("1.2.3.4"),
            "the chain must still be walked from the PROXY-declared base"
        );
        assert_eq!(got.trusted_hops, 1);
        assert_eq!(got.source, IdentitySource::ForwardedChain);

        // The distinguishing pair: using the socket address (no PROXY
        // declaration) must fail closed, because 192.0.2.1 is not in
        // 10.0.0.0/8.
        let without_proxy = resolve_identity(socket_peer, None, &chain, &policy);
        assert!(!without_proxy.peer_trusted);
        assert_eq!(without_proxy.client, socket_peer.ip());
    }

    #[test]
    fn proto_falls_back_rightwards() {
        // Edge case 25: only the middle of three elements carries `proto`.
        let chain = forwarded_chain(&["for=1.1.1.1", "for=2.2.2.2;proto=https", "for=3.3.3.3"]);
        let socket_peer = sock("198.51.100.1:9000");
        let got = resolve_identity(socket_peer, None, &chain, &TrustPolicy::HopCount(3));
        assert_eq!(got.client, addr("1.1.1.1"));
        assert_eq!(got.forwarded_proto, Some(Scheme::Https));
    }

    #[test]
    fn forwarded_element_len_is_exact() {
        let clients: [(IpAddr, &str); 2] =
            [(addr("203.0.113.5"), "v4"), (addr("2001:db8::1"), "v6")];
        let client_ports: [Option<u16>; 2] = [None, Some(5555)];
        let locals: [SocketAddr; 2] = [sock("198.51.100.1:443"), sock("[2001:db8::2]:443")];
        let schemes: [Scheme; 2] = [Scheme::Http, Scheme::Https];

        let limits = Limits::DEFAULT.clamped();
        let mut out1 = BytesMut::new();
        let authority_no_port =
            Authority::parse_into(b"a.example", Scheme::Http, &limits, &mut out1)
                .expect("a.example must parse");
        let mut out2 = BytesMut::new();
        let authority_with_port =
            Authority::parse_into(b"a.example:8443", Scheme::Http, &limits, &mut out2)
                .expect("a.example:8443 must parse");
        let authorities: [(&Authority, &str); 2] = [
            (&authority_no_port, "no_port"),
            (&authority_with_port, "with_port"),
        ];

        let mut combinations = 0_usize;
        for (client, client_label) in clients {
            for client_port in client_ports {
                for local in locals {
                    for scheme in schemes {
                        for (authority, authority_label) in authorities {
                            combinations = combinations.saturating_add(1);
                            let peer = identity(client, client_port);
                            let expected_len =
                                forwarded_element_len(&peer, local, scheme, authority);
                            let mut buf = BytesMut::new();
                            let written =
                                write_forwarded_element(&peer, local, scheme, authority, &mut buf);
                            assert_eq!(
                                written, expected_len,
                                "client={client_label} port={client_port:?} local={local} \
                                 scheme={scheme:?} authority={authority_label}: \
                                 write_forwarded_element must return exactly forwarded_element_len"
                            );
                            assert_eq!(
                                buf.len(),
                                written,
                                "write_forwarded_element must write exactly the bytes it reports"
                            );

                            // The written bytes must re-parse to one element
                            // naming the same client address.
                            let mut reparse_out = BytesMut::new();
                            let field = buf.freeze();
                            let reparsed = ForwardedChain::parse_into(
                                core::iter::once(field.as_ref()),
                                core::iter::empty(),
                                core::iter::empty(),
                                &limits,
                                &mut reparse_out,
                            )
                            .unwrap_or_else(|e| {
                                panic!(
                                    "write_forwarded_element's own output failed to re-parse: {e:?}"
                                )
                            });
                            assert_eq!(reparsed.len(), 1);
                            assert_eq!(
                                reparsed.elements().first().and_then(|el| el.node.addr()),
                                Some(client)
                            );

                            // Every parameter value containing a `:` or a
                            // bracket must be quoted; every bare token must
                            // not be.
                            let text = core::str::from_utf8(field.as_ref())
                                .expect("this writer only ever emits ASCII");
                            for part in text.split(';') {
                                let Some(eq) = part.find('=') else {
                                    panic!("every parameter must have a value: {part}");
                                };
                                let value = &part[eq.saturating_add(1)..];
                                let raw_needs_quote = value.contains(':')
                                    || value.contains('[')
                                    || value.contains(']');
                                let is_quoted = value.starts_with('"') && value.ends_with('"');
                                if raw_needs_quote && !is_quoted {
                                    // A quoted value's OWN interior must not
                                    // itself be mistaken for unquoted: check
                                    // the interior instead.
                                    assert!(
                                        is_quoted,
                                        "{part} contains ':' or a bracket and must be quoted"
                                    );
                                }
                                if is_quoted {
                                    let interior = &value[1..value.len().saturating_sub(1)];
                                    assert!(
                                        interior.contains(':')
                                            || interior.contains('[')
                                            || interior.contains(']'),
                                        "{part} is quoted but its content needs no quoting"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(
            combinations, 32,
            "this test must enumerate exactly the 32 shape combinations edge case 24 names"
        );
    }

    #[test]
    fn x_forwarded_values() {
        let limits = Limits::DEFAULT.clamped();
        let mut out1 = BytesMut::new();
        let authority = Authority::parse_into(b"a.example:8443", Scheme::Http, &limits, &mut out1)
            .expect("a.example:8443 must parse");

        let peer = identity(addr("203.0.113.5"), Some(5555));
        let mut buf = BytesMut::new();
        let ranges = write_x_forwarded(&peer, Scheme::Https, &authority, &mut buf);
        let bytes = buf.freeze();
        let raw: &[u8] = bytes.as_ref();

        assert_eq!(raw.get(ranges[0].clone()), Some(&b"203.0.113.5"[..]));
        assert_eq!(raw.get(ranges[1].clone()), Some(&b"https"[..]));
        assert_eq!(raw.get(ranges[2].clone()), Some(&b"a.example:8443"[..]));
        assert_eq!(raw.get(ranges[3].clone()), Some(&b"5555"[..]));

        // The port range must be empty when the port is unknown.
        let peer_no_port = identity(addr("203.0.113.5"), None);
        let mut buf2 = BytesMut::new();
        let ranges2 = write_x_forwarded(&peer_no_port, Scheme::Https, &authority, &mut buf2);
        assert!(ranges2[3].is_empty());
    }

    #[test]
    fn peer_trusted_requires_a_checked_address() {
        let peers = ["10.0.0.1", "127.0.0.1", "203.0.113.5"];
        let policies_never_trusted = [
            TrustPolicy::None,
            TrustPolicy::HopCount(0),
            TrustPolicy::HopCount(1),
            TrustPolicy::HopCount(255),
        ];
        for peer_str in peers {
            for policy in &policies_never_trusted {
                let socket_peer = SocketAddr::new(addr(peer_str), 12345);
                let got = resolve_identity(socket_peer, None, &empty_chain(), policy);
                assert!(
                    !got.peer_trusted,
                    "peer_trusted must be false for {peer_str} under {policy:?}"
                );
                // `trusted_internal()` must report the SAME answer as the
                // field, not a constant: this is the distinguishing negative
                // half of that pair.
                assert!(
                    !got.trusted_internal(),
                    "trusted_internal() must be false for {peer_str} under {policy:?}"
                );
            }
        }

        let trusted_cidrs = TrustPolicy::TrustedCidrs(vec![cidr("10.0.0.0", 8)]);
        for peer_str in peers {
            let socket_peer = SocketAddr::new(addr(peer_str), 12345);
            let got = resolve_identity(socket_peer, None, &empty_chain(), &trusted_cidrs);
            let expect_trusted = peer_str == "10.0.0.1";
            assert_eq!(
                got.peer_trusted, expect_trusted,
                "peer_trusted mismatch for {peer_str} under TrustedCidrs([10.0.0.0/8])"
            );
            // The distinguishing positive half: for 10.0.0.1 this must be
            // true, so `trusted_internal` cannot be a constant `false`
            // either.
            assert_eq!(
                got.trusted_internal(),
                expect_trusted,
                "trusted_internal() mismatch for {peer_str} under TrustedCidrs([10.0.0.0/8])"
            );
        }

        // Edge case 28: the PROXY-declared address is the base, and it is
        // checked, not the socket address it arrived on.
        let socket_peer = SocketAddr::new(addr("10.0.0.1"), 12345);
        let proxy_proto = Some(SocketAddr::new(addr("203.0.113.5"), 54321));
        let got = resolve_identity(socket_peer, proxy_proto, &empty_chain(), &trusted_cidrs);
        assert!(
            !got.peer_trusted,
            "edge case 28: the PROXY-declared address is outside the trusted prefix"
        );
        assert!(
            !got.trusted_internal(),
            "edge case 28: trusted_internal() must agree"
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum NodeKind {
        TenSlash8(u8),
        Attacker(u8),
        Unknown,
        Obfuscated,
    }

    fn render_node_kind(kind: NodeKind) -> String {
        match kind {
            NodeKind::TenSlash8(n) => format!("10.0.0.{n}"),
            NodeKind::Attacker(n) => format!("203.0.113.{n}"),
            NodeKind::Unknown => "unknown".to_owned(),
            NodeKind::Obfuscated => "_abc".to_owned(),
        }
    }

    fn node_kind_strategy() -> impl proptest::strategy::Strategy<Value = NodeKind> {
        use proptest::strategy::Strategy;
        proptest::prop_oneof![
            proptest::prelude::any::<u8>().prop_map(NodeKind::TenSlash8),
            proptest::prelude::any::<u8>().prop_map(NodeKind::Attacker),
            proptest::prelude::Just(NodeKind::Unknown),
            proptest::prelude::Just(NodeKind::Obfuscated),
        ]
    }

    fn policy_strategy() -> impl proptest::strategy::Strategy<Value = TrustPolicy> {
        use proptest::strategy::Strategy;
        let trusted = TrustPolicy::TrustedCidrs(vec![cidr("10.0.0.0", 8)]);
        proptest::prop_oneof![
            proptest::prelude::Just(TrustPolicy::None),
            (0..=5_u8).prop_map(TrustPolicy::HopCount),
            proptest::prelude::Just(trusted),
        ]
    }

    proptest::proptest! {
        #[test]
        fn prop_xff_walk(
            kinds in proptest::collection::vec(node_kind_strategy(), 0..=32),
            policy in policy_strategy(),
        ) {
            // 198.51.100.1 (TEST-NET-2) never overlaps 10.0.0.0/8 or
            // 203.0.113.0/24 (TEST-NET-3), so a fail-closed answer can never
            // coincide with a genuine chain match by accident. TrustedCidrs
            // instead uses a base address INSIDE the trusted prefix, or the
            // whole policy would fail closed at step 5a on every case and
            // never exercise the walk at all.
            let socket_peer = match &policy {
                TrustPolicy::TrustedCidrs(_) => sock("10.255.255.255:9000"),
                TrustPolicy::None | TrustPolicy::HopCount(_) => sock("198.51.100.1:9000"),
            };

            let entries: Vec<String> = kinds.iter().copied().map(render_node_kind).collect();
            let chain = if entries.is_empty() {
                empty_chain()
            } else {
                let refs: Vec<&str> = entries.iter().map(String::as_str).collect();
                xff_chain(&refs)
            };
            let t = chain.len();

            let resolved = resolve_identity(socket_peer, None, &chain, &policy);
            let hops = usize::from(resolved.trusted_hops);

            assert!(hops <= t);

            if matches!(policy, TrustPolicy::None) {
                assert_eq!(resolved.source, IdentitySource::Socket);
            }

            if resolved.source != IdentitySource::Socket {
                match &policy {
                    TrustPolicy::HopCount(n) => {
                        assert_eq!(hops, usize::from(*n));
                        let index = t.saturating_sub(hops);
                        assert_eq!(
                            chain.elements().get(index).and_then(|e| e.node.addr()),
                            Some(resolved.client)
                        );
                    }
                    TrustPolicy::TrustedCidrs(cidrs) => {
                        let index = if hops == t {
                            0
                        } else {
                            t.saturating_sub(hops).saturating_sub(1)
                        };
                        assert_eq!(
                            chain.elements().get(index).and_then(|e| e.node.addr()),
                            Some(resolved.client)
                        );
                        let lower_bound = t.saturating_sub(hops).saturating_sub(1);
                        assert!(index >= lower_bound);
                        for element in chain.elements().get(index.saturating_add(1)..).unwrap_or(&[]) {
                            match element.node.addr() {
                                Some(a) => assert!(cidrs.iter().any(|c| c.contains(a))),
                                None => panic!("an element right of the client must be an address"),
                            }
                        }
                    }
                    TrustPolicy::None => {
                        panic!("TrustPolicy::None never resolves via the forwarded chain");
                    }
                }
            }
        }
    }
}
