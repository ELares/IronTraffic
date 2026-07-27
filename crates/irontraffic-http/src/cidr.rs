// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`IpCidr`], an IP address prefix.
//!
//! Defined here rather than taken from a crate because `contains` is twenty
//! lines and a dependency is not worth it: `ipnet`, `cidr` and `ipnetwork`
//! are all refused (AGENTS.md rule 7, `deny.toml`'s reviewed-dependency
//! policy). `trust-policy-and-peer-identity` (#32) is the one consumer:
//! [`crate::peer::TrustPolicy::TrustedCidrs`] holds a list of these to decide
//! which socket peers and forwarding-chain entries it believes.

use std::net::IpAddr;

/// An IP prefix. Defined here rather than taken from a crate because
/// `contains` is twenty lines and a dependency is not worth it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct IpCidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    /// A prefix, or `None` when `prefix_len` exceeds the family's width.
    #[must_use]
    pub const fn new(addr: IpAddr, prefix_len: u8) -> Option<IpCidr> {
        let width: u8 = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > width {
            None
        } else {
            Some(IpCidr { addr, prefix_len })
        }
    }

    /// True when `other` is in this prefix. Address families must match
    /// exactly: an IPv4-mapped IPv6 address is not unwrapped. An operator who
    /// wants to trust an IPv4 range must list it, and an operator who wants
    /// to trust the mapped form must list the mapped prefix; silently
    /// unwrapping one into the other is a trust-boundary surprise.
    #[must_use]
    pub fn contains(&self, other: IpAddr) -> bool {
        match (self.addr, other) {
            (IpAddr::V4(a), IpAddr::V4(b)) => bits_match(&a.octets(), &b.octets(), self.prefix_len),
            (IpAddr::V6(a), IpAddr::V6(b)) => bits_match(&a.octets(), &b.octets(), self.prefix_len),
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }

    /// The prefix length.
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

/// Compares the first `prefix_len` bits of two same-length octet arrays:
/// whole bytes with `==`, then the final partial byte under a mask of
/// `0xFFu8 << (8 - rem)` when `rem != 0`. `prefix_len == 0` compares zero
/// whole bytes and takes the `rem == 0` exit immediately, so it matches
/// every address of the family: the empty prefix.
///
/// `a` and `b` are always two same-length octet arrays (4 bytes for IPv4, 16
/// for IPv6) belonging to the same family; `prefix_len` never exceeds that
/// family's width, enforced by `IpCidr::new`.
fn bits_match(a: &[u8], b: &[u8], prefix_len: u8) -> bool {
    let full_bytes = usize::from(prefix_len.checked_div(8).unwrap_or(0));
    let rem = prefix_len.checked_rem(8).unwrap_or(0);

    match (a.get(..full_bytes), b.get(..full_bytes)) {
        (Some(a_head), Some(b_head)) => {
            if a_head != b_head {
                return false;
            }
        }
        _ => return false,
    }

    if rem == 0 {
        return true;
    }

    // `rem` is 1..=7 here (the `rem == 0` case already returned), so the
    // shift amount `8 - rem` is 1..=7: always in range for a `u8`, never
    // reached with `rem == 8` (which `checked_rem(8)` can never produce) or
    // `rem == 0` (handled above).
    let shift = 8_u8.saturating_sub(rem);
    let mask = 0xFF_u8.checked_shl(u32::from(shift)).unwrap_or(0);
    match (a.get(full_bytes), b.get(full_bytes)) {
        (Some(&a_byte), Some(&b_byte)) => (a_byte & mask) == (b_byte & mask),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_bounds() {
        let v4 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0));
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));

        for len in [0_u8, 1, 31, 32] {
            assert!(
                IpCidr::new(v4, len).is_some(),
                "IPv4 prefix length {len} must be accepted"
            );
        }
        assert!(
            IpCidr::new(v4, 33).is_none(),
            "IPv4 prefix length 33 must be refused"
        );

        for len in [0_u8, 1, 127, 128] {
            assert!(
                IpCidr::new(v6, len).is_some(),
                "IPv6 prefix length {len} must be accepted"
            );
        }
        assert!(
            IpCidr::new(v6, 129).is_none(),
            "IPv6 prefix length 129 must be refused"
        );

        // The distinguishing pair for `prefix_len()`: two different accepted
        // values must report back distinct lengths, not a constant.
        let narrow = IpCidr::new(v4, 8).expect("prefix length 8 must be accepted");
        let wide = IpCidr::new(v4, 24).expect("prefix length 24 must be accepted");
        assert_eq!(narrow.prefix_len(), 8);
        assert_eq!(wide.prefix_len(), 24);
    }

    #[test]
    fn contains_boundaries() {
        let ip = |a: u8, b: u8, c: u8, d: u8| IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
        let ten_slash_8 = IpCidr::new(ip(10, 0, 0, 0), 8).expect("10.0.0.0/8 must be valid");
        assert!(ten_slash_8.contains(ip(10, 0, 0, 0)));
        assert!(ten_slash_8.contains(ip(10, 255, 255, 255)));
        assert!(ten_slash_8.contains(ip(10, 1, 2, 3)));
        assert!(!ten_slash_8.contains(ip(9, 255, 255, 255)));
        assert!(!ten_slash_8.contains(ip(11, 0, 0, 0)));

        let ten_slash_32 = IpCidr::new(ip(10, 0, 0, 0), 32).expect("10.0.0.0/32 must be valid");
        assert!(ten_slash_32.contains(ip(10, 0, 0, 0)));
        assert!(!ten_slash_32.contains(ip(10, 0, 0, 1)));
        assert!(!ten_slash_32.contains(ip(10, 0, 0, 255)));

        let v6 = |s: &str| -> IpAddr { s.parse().expect("valid IPv6 literal in a test fixture") };
        let db8_slash_32 = IpCidr::new(v6("2001:db8::"), 32).expect("2001:db8::/32 must be valid");
        assert!(db8_slash_32.contains(v6("2001:db8::1")));
        assert!(!db8_slash_32.contains(v6("2001:db9::1")));

        // A /7 boundary: 10 (0b0000101_0) and 11 (0b0000101_1) share their
        // top 7 bits, so 10.0.0.0/7 contains 11.0.0.1.
        let ten_slash_7 = IpCidr::new(ip(10, 0, 0, 0), 7).expect("10.0.0.0/7 must be valid");
        assert!(ten_slash_7.contains(ip(11, 0, 0, 1)));
        // The distinguishing negative: 12 does not share those bits.
        assert!(!ten_slash_7.contains(ip(12, 0, 0, 1)));
    }

    #[test]
    fn families_do_not_mix() {
        let v4_any = IpCidr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            .expect("0.0.0.0/0 must be valid");
        let v6_any = IpCidr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            .expect("::/0 must be valid");

        let v4_addr = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        let v6_addr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);

        assert!(
            !v6_any.contains(v4_addr),
            "::/0 must not contain an IPv4 address"
        );
        assert!(
            !v4_any.contains(v6_addr),
            "0.0.0.0/0 must not contain an IPv6 address"
        );

        // The IPv4-mapped IPv6 form must NOT be silently unwrapped to its
        // IPv4 meaning.
        let mapped: IpAddr = "::ffff:1.2.3.4".parse().expect("valid mapped literal");
        let v4_slash_24 = IpCidr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 0)), 24)
            .expect("1.2.3.0/24 must be valid");
        assert!(
            !v4_slash_24.contains(mapped),
            "an IPv4-mapped IPv6 address must not be contained by an IPv4 prefix"
        );
    }
}
