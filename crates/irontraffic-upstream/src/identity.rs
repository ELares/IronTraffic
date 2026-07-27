// SPDX-License-Identifier: MIT OR Apache-2.0

//! Endpoint identity: [`EndpointAddr`], [`EndpointIdentity`], and the allocation-free
//! byte rendering both the consistent-hash table build and the endpoint registry key
//! on.
//!
//! Ordering is defined on the rendered bytes ([`EndpointIdentity::identity_cmp`]),
//! never derived from `SocketAddr`'s own `Ord`, so a consistent-hash table build
//! sorts identically on every replica: see Envoy's `maglev_lb.cc`, which carries a
//! comment about exactly this, and `science/load-balancing.md`.

use core::cmp::Ordering;
use core::fmt::Write as _;

/// Longest identity rendering we accept: a 253-byte DNS name, a colon, a 5-digit
/// port, and slack for the `unix:` prefix and IPv6 brackets.
pub const MAX_IDENTITY_BYTES: usize = 320;

/// Where an upstream endpoint lives on the network.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum EndpointAddr {
    /// A resolved TCP or UDP socket address.
    Socket(std::net::SocketAddr),
    /// A unix domain socket path.
    Unix(Box<std::path::Path>),
}

/// The stable name of one upstream endpoint.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct EndpointIdentity {
    /// Network location. Always present, even when `hostname` is set.
    pub addr: EndpointAddr,
    /// Optional configured hostname, used for hashing when the cluster sets
    /// `use_hostname_for_hashing`.
    pub hostname: Option<Box<str>>,
}

/// Fixed-capacity, allocation-free `core::fmt::Write` adaptor over a caller-owned
/// `[u8; MAX_IDENTITY_BYTES]` buffer.
///
/// `core::fmt::Write` alone cannot write non-UTF-8 bytes (a unix socket path is not
/// guaranteed to be valid UTF-8) and cannot report overflow without an early return
/// that would leave the buffer partially written with a plausible-looking length.
/// This records overflow as a flag instead, so [`finish`](Self::finish) is the only
/// place that observes it.
struct BufWriter<'a> {
    buf: &'a mut [u8; MAX_IDENTITY_BYTES],
    len: usize,
    overflow: bool,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8; MAX_IDENTITY_BYTES]) -> Self {
        Self {
            buf,
            len: 0,
            overflow: false,
        }
    }

    /// Appends raw bytes, or records overflow instead of returning an error, so no
    /// caller can early-return and leave a partially written buffer with a
    /// plausible length.
    ///
    /// The length check uses `checked_add`, not `+`. `b` can be a unix socket path
    /// of arbitrary length taken from configuration, and `self.len + b.len()` on a
    /// release build would wrap rather than trip the bound if `b.len()` were near
    /// `usize::MAX`. A wrapped sum would compare below `MAX_IDENTITY_BYTES` and let
    /// a subsequent copy run past the buffer, which is an availability bug
    /// reachable from configuration; `checked_add` makes the overflow branch
    /// identical to the too-long branch.
    fn write_bytes(&mut self, b: &[u8]) {
        let fits = self
            .len
            .checked_add(b.len())
            .is_some_and(|end| end <= MAX_IDENTITY_BYTES);
        if self.overflow || !fits {
            self.overflow = true;
            return;
        }
        let Some(dst) = self.buf.get_mut(self.len..self.len.wrapping_add(b.len())) else {
            // Cannot happen: `fits` just proved `self.len + b.len() <=
            // MAX_IDENTITY_BYTES == self.buf.len()`. Treated as overflow rather
            // than indexed directly with `[..]`, because this crate denies
            // `clippy::indexing_slicing`: a caller-owned buffer fed by a value
            // that can originate in configuration (an arbitrarily long unix
            // socket path) must not depend on the arithmetic above staying
            // correct to avoid a panic.
            self.overflow = true;
            return;
        };
        dst.copy_from_slice(b);
        self.len = self.len.wrapping_add(b.len());
    }

    /// Consumes the writer, returning the length written, or `None` if any
    /// `write_bytes` call overflowed the buffer.
    fn finish(self) -> Option<usize> {
        if self.overflow { None } else { Some(self.len) }
    }
}

impl core::fmt::Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

impl EndpointIdentity {
    /// Renders the identity into `out` and returns its length in bytes, or `None`
    /// if the rendering would exceed `MAX_IDENTITY_BYTES`.
    ///
    /// Allocation-free. The rendering is the stable name used for consistent
    /// hashing and for the build-time sort, so it must not change between
    /// releases without a documented migration: changing it remaps every
    /// consistent-hash key.
    ///
    /// When `use_hostname` is true and `hostname` is set, renders
    /// `<hostname>:<port>`. Otherwise renders the socket form: `<ipv4>:<port>`,
    /// `[<ipv6>]:<port>`, or `unix:<path>`. A `SocketAddrV6`'s scope id and flow
    /// info are never rendered: two endpoints differing only in scope id are the
    /// same upstream.
    #[must_use]
    pub fn identity_bytes(
        &self,
        use_hostname: bool,
        out: &mut [u8; MAX_IDENTITY_BYTES],
    ) -> Option<usize> {
        let mut w = BufWriter::new(out);
        if use_hostname
            && let Some(h) = self.hostname.as_deref()
            && let EndpointAddr::Socket(sa) = &self.addr
        {
            w.write_bytes(h.as_bytes());
            w.write_bytes(b":");
            // write! through core::fmt::Write::write_str, which never fails (see
            // write_str above), so the Result is discarded rather than propagated.
            let _ = write!(w, "{}", sa.port());
        } else {
            match &self.addr {
                EndpointAddr::Socket(std::net::SocketAddr::V4(sa)) => {
                    let _ = write!(w, "{}", sa.ip());
                    w.write_bytes(b":");
                    let _ = write!(w, "{}", sa.port());
                }
                EndpointAddr::Socket(std::net::SocketAddr::V6(sa)) => {
                    w.write_bytes(b"[");
                    let _ = write!(w, "{}", sa.ip());
                    w.write_bytes(b"]:");
                    let _ = write!(w, "{}", sa.port());
                }
                EndpointAddr::Unix(p) => {
                    w.write_bytes(b"unix:");
                    w.write_bytes(p.as_os_str().as_encoded_bytes());
                }
            }
        }
        w.finish()
    }

    /// Total byte order over identities, defined on the rendered bytes.
    ///
    /// Returns `Ordering::Equal` for two identities that render identically.
    /// Identities that fail to render sort last, deterministically.
    #[must_use]
    pub fn identity_cmp(&self, other: &Self, use_hostname: bool) -> Ordering {
        let mut ba = [0u8; MAX_IDENTITY_BYTES];
        let mut bb = [0u8; MAX_IDENTITY_BYTES];
        match (
            self.identity_bytes(use_hostname, &mut ba),
            other.identity_bytes(use_hostname, &mut bb),
        ) {
            (Some(na), Some(nb)) => {
                let a = ba.get(..na).unwrap_or(&[]);
                let b = bb.get(..nb).unwrap_or(&[]);
                a.cmp(b)
            }
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EndpointAddr, EndpointIdentity, MAX_IDENTITY_BYTES, Ordering};

    #[test]
    fn identity_v4_renders_ip_colon_port() {
        let identity = EndpointIdentity {
            addr: EndpointAddr::Socket("127.0.0.1:8080".parse().expect("valid literal")),
            hostname: None,
        };
        let mut buf = [0u8; MAX_IDENTITY_BYTES];
        let len = identity
            .identity_bytes(false, &mut buf)
            .expect("a socket address always renders");
        assert_eq!(buf.get(..len).unwrap_or(&[]), b"127.0.0.1:8080");
    }

    #[test]
    fn identity_v6_renders_bracketed() {
        let identity = EndpointIdentity {
            addr: EndpointAddr::Socket("[2001:db8::1]:443".parse().expect("valid literal")),
            hostname: None,
        };
        let mut buf = [0u8; MAX_IDENTITY_BYTES];
        let len = identity
            .identity_bytes(false, &mut buf)
            .expect("a socket address always renders");
        assert_eq!(buf.get(..len).unwrap_or(&[]), b"[2001:db8::1]:443");
    }

    #[test]
    fn identity_v6_ignores_scope_id() {
        use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let a = SocketAddrV6::new(ip, 443, 0, 7);
        let b = SocketAddrV6::new(ip, 443, 0, 99);
        let ia = EndpointIdentity {
            addr: EndpointAddr::Socket(SocketAddr::V6(a)),
            hostname: None,
        };
        let ib = EndpointIdentity {
            addr: EndpointAddr::Socket(SocketAddr::V6(b)),
            hostname: None,
        };

        let mut buf1 = [0u8; MAX_IDENTITY_BYTES];
        let mut buf2 = [0u8; MAX_IDENTITY_BYTES];
        let na = ia
            .identity_bytes(false, &mut buf1)
            .expect("a socket address always renders");
        let nb = ib
            .identity_bytes(false, &mut buf2)
            .expect("a socket address always renders");
        assert_eq!(buf1.get(..na).unwrap_or(&[]), buf2.get(..nb).unwrap_or(&[]));
    }

    #[test]
    fn identity_unix_renders_prefixed() {
        let identity = EndpointIdentity {
            addr: EndpointAddr::Unix(std::path::Path::new("/var/run/x.sock").into()),
            hostname: None,
        };
        let mut buf = [0u8; MAX_IDENTITY_BYTES];
        let len = identity
            .identity_bytes(false, &mut buf)
            .expect("a unix path always renders");
        assert_eq!(buf.get(..len).unwrap_or(&[]), b"unix:/var/run/x.sock");
    }

    #[test]
    fn identity_hostname_used_only_when_requested() {
        let identity = EndpointIdentity {
            addr: EndpointAddr::Socket("10.0.0.1:8080".parse().expect("valid literal")),
            hostname: Some("api.internal".into()),
        };

        let mut buf_host = [0u8; MAX_IDENTITY_BYTES];
        let len_host = identity
            .identity_bytes(true, &mut buf_host)
            .expect("renders with the hostname");
        assert_eq!(
            buf_host.get(..len_host).unwrap_or(&[]),
            b"api.internal:8080"
        );

        let mut buf_sock = [0u8; MAX_IDENTITY_BYTES];
        let len_sock = identity
            .identity_bytes(false, &mut buf_sock)
            .expect("renders with the socket");
        assert_eq!(buf_sock.get(..len_sock).unwrap_or(&[]), b"10.0.0.1:8080");
    }

    /// Interning keys on the socket rendering only: two identities that share an
    /// `addr` but carry different `hostname` values intern to the SAME id and
    /// leave `live_count() == 1`. See Context fact 9 in the issue this module
    /// implements: an `EndpointId` names a network peer, and the hostname
    /// rendering exists only for hashing, never for this registry's key.
    #[test]
    fn intern_ignores_hostname() {
        let (reg, mut writer) = crate::registry::EndpointRegistry::install(4)
            .expect("capacity 4 is a valid, non-zero, under-ceiling capacity");
        let a = EndpointIdentity {
            addr: EndpointAddr::Socket("10.0.0.1:8080".parse().expect("valid literal")),
            hostname: Some("a".into()),
        };
        let b = EndpointIdentity {
            addr: EndpointAddr::Socket("10.0.0.1:8080".parse().expect("valid literal")),
            hostname: Some("b".into()),
        };

        let id_a = writer.intern(&a).expect("the slab has room");
        let id_b = writer.intern(&b).expect("the slab has room");

        assert_eq!(id_a, id_b);
        assert_eq!(reg.live_count(), 1);
    }

    #[test]
    fn identity_too_long_returns_none() {
        let long_hostname = "a".repeat(400);
        let identity = EndpointIdentity {
            addr: EndpointAddr::Socket("10.0.0.1:8080".parse().expect("valid literal")),
            hostname: Some(long_hostname.into_boxed_str()),
        };
        let mut buf = [0u8; MAX_IDENTITY_BYTES];
        assert_eq!(identity.identity_bytes(true, &mut buf), None);
    }

    #[test]
    fn identity_cmp_is_byte_order_not_numeric_order() {
        let a = EndpointIdentity {
            addr: EndpointAddr::Socket("10.0.0.10:1".parse().expect("valid literal")),
            hostname: None,
        };
        let b = EndpointIdentity {
            addr: EndpointAddr::Socket("10.0.0.2:1".parse().expect("valid literal")),
            hostname: None,
        };

        let mut ba = [0u8; MAX_IDENTITY_BYTES];
        let mut bb = [0u8; MAX_IDENTITY_BYTES];
        let na = a
            .identity_bytes(false, &mut ba)
            .expect("a socket address always renders");
        let nb = b
            .identity_bytes(false, &mut bb)
            .expect("a socket address always renders");

        // The rendered bytes differ first at index 7, where b'1' (0x31)
        // precedes b'2' (0x32), so the byte order puts "...10:1" before
        // "...2:1" even though 10 > 2 numerically.
        assert_eq!(ba.get(..na).unwrap_or(&[]), b"10.0.0.10:1");
        assert_eq!(bb.get(..nb).unwrap_or(&[]), b"10.0.0.2:1");
        assert_eq!(a.identity_cmp(&b, false), Ordering::Less);
    }
}
