// SPDX-License-Identifier: MIT OR Apache-2.0

//! PROXY protocol v2 encoder.
//!
//! This module writes a v2 header into a single caller-owned [`BytesMut`]. The
//! 2-byte payload length is back-patched from the number of bytes actually
//! written, because a length field derived from a parallel computation is the
//! shape of Envoy CVE-2026-47692 / GHSA-wh36-hm39-mm3r.

use std::net::SocketAddr;

use bytes::BytesMut;

use super::V2_SIGNATURE;

/// The `PP2_TYPE_AUTHORITY` TLV type byte, per the PROXY protocol specification
/// Section 2.2.7.
pub const PP2_TYPE_AUTHORITY: u8 = 0x02;

/// The maximum v2 payload length, in bytes. Stored as `usize` so the ceiling
/// checks are checked against buffer lengths without repeated casts.
const MAX_PAYLOAD_LEN: usize = 65_535;

/// Why encoding failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A TLV value was longer than 65535 bytes.
    TlvValueTooLong,
    /// The address family of `src` and `dst` differ.
    AddressFamilyMismatch,
    /// A TLV was appended after `finish`.
    AlreadyFinished,
    /// The release-mode check that the declared length equals `written_total - 16`
    /// failed. Arithmetically impossible today; it exists so a future refactor that
    /// reintroduces a second length source is caught at runtime with its own metric
    /// label rather than in an advisory.
    LengthCheckFailed,
}

/// One TLV to append.
#[derive(Copy, Clone, Debug)]
pub struct Tlv<'v> {
    /// The TLV type byte.
    pub kind: u8,
    /// The value. Must be at most 65535 bytes; longer is refused.
    pub value: &'v [u8],
}

/// Writes a PROXY protocol v2 header into ONE buffer, back-patching the length field from
/// the bytes actually written.
///
/// There is deliberately no second vector and no parallel length computation: Envoy
/// CVE-2026-47692 was a filtered TLV vector built for the length calculation while the
/// unfiltered vector was emitted, spilling 65523 attacker-controlled bytes into the
/// upstream application stream.
#[derive(Debug)]
pub struct V2Encoder<'b> {
    buf: &'b mut BytesMut,
    /// Offset in `buf` at which this header began.
    start: usize,
    /// TLVs skipped because they would have exceeded the 65535 ceiling.
    skipped: u16,
    finished: bool,
}

impl<'b> V2Encoder<'b> {
    /// Starts a v2 header for a TCP connection, writing the signature, the command, the
    /// family, a placeholder length and the address block.
    ///
    /// # Errors
    /// `AddressFamilyMismatch` when `src` and `dst` are not both IPv4 or both IPv6.
    pub fn begin(
        buf: &'b mut BytesMut,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<V2Encoder<'b>, EncodeError> {
        let start = buf.len();

        match (src, dst) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                buf.extend_from_slice(&V2_SIGNATURE);
                buf.extend_from_slice(&[0x21]);
                buf.extend_from_slice(&[0x11]);
                buf.extend_from_slice(&[0x00, 0x00]);
                buf.extend_from_slice(&src.ip().octets());
                buf.extend_from_slice(&dst.ip().octets());
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                buf.extend_from_slice(&V2_SIGNATURE);
                buf.extend_from_slice(&[0x21]);
                buf.extend_from_slice(&[0x21]);
                buf.extend_from_slice(&[0x00, 0x00]);
                buf.extend_from_slice(&src.ip().octets());
                buf.extend_from_slice(&dst.ip().octets());
            }
            _ => return Err(EncodeError::AddressFamilyMismatch),
        }

        buf.extend_from_slice(&src.port().to_be_bytes());
        buf.extend_from_slice(&dst.port().to_be_bytes());

        Ok(Self {
            buf,
            start,
            skipped: 0,
            finished: false,
        })
    }

    /// Appends one TLV if it fits under the 65535-byte payload ceiling.
    ///
    /// Returns `Ok(true)` when written and `Ok(false)` when skipped for space. The check
    /// happens BEFORE any byte is written, so the buffer never contains a TLV the length
    /// field will not cover.
    ///
    /// # Errors
    /// `TlvValueTooLong` when the value exceeds 65535 bytes; `AlreadyFinished` after
    /// `finish`.
    pub fn append_tlv(&mut self, tlv: &Tlv<'_>) -> Result<bool, EncodeError> {
        if self.finished {
            return Err(EncodeError::AlreadyFinished);
        }
        if tlv.value.len() > MAX_PAYLOAD_LEN {
            return Err(EncodeError::TlvValueTooLong);
        }

        let tlv_total = 3usize.saturating_add(tlv.value.len());
        let current_payload = self.buf.len().saturating_sub(self.start).saturating_sub(16);
        if current_payload.saturating_add(tlv_total) > MAX_PAYLOAD_LEN {
            self.skipped = self.skipped.saturating_add(1);
            return Ok(false);
        }

        self.buf.extend_from_slice(&[tlv.kind]);
        let value_len =
            u16::try_from(tlv.value.len()).map_err(|_| EncodeError::LengthCheckFailed)?;
        self.buf.extend_from_slice(&value_len.to_be_bytes());
        self.buf.extend_from_slice(tlv.value);

        Ok(true)
    }

    /// Back-patches the length field from the bytes actually written and returns the total
    /// header length.
    ///
    /// Carries a RELEASE-mode check that the declared length equals `written_total - 16`.
    /// The check is arithmetically redundant today and is present so that a future change
    /// introducing a second length source fails at runtime rather than in an advisory
    /// (Envoy CVE-2026-47692).
    ///
    /// # Errors
    /// `LengthCheckFailed` when the release check fails, in which case the buffer is
    /// truncated back to the header's start. Calling `finish` twice is a compile error,
    /// not a runtime one, because it consumes `self`.
    pub fn finish(mut self) -> Result<usize, EncodeError> {
        let written_total = self.buf.len().saturating_sub(self.start);
        if written_total < 28 {
            self.buf.truncate(self.start);
            return Err(EncodeError::LengthCheckFailed);
        }
        let declared = written_total.saturating_sub(16);

        // Range check before the narrowing to `u16`. If the ceiling logic above is ever
        // broken, a bare cast of `declared` to `u16` would truncate 65536 to 16 and
        // reproduce CVE-2026-47692.
        if declared > usize::from(u16::MAX) {
            self.buf.truncate(self.start);
            return Err(EncodeError::LengthCheckFailed);
        }
        let declared_u16 = u16::try_from(declared).map_err(|_| {
            // Unreachable after the range check, but mapped to the same error so a future
            // refactor that removes the check still fails closed.
            EncodeError::LengthCheckFailed
        })?;

        let at = self.start + 14;
        let Some(slot) = self.buf.get_mut(at..at + 2) else {
            self.buf.truncate(self.start);
            return Err(EncodeError::LengthCheckFailed);
        };
        slot.copy_from_slice(&declared_u16.to_be_bytes());

        // Release check: read the length field back out of the buffer and compare it to
        // the bytes actually written. Comparing `written_total` to `16 + declared` would
        // be tautological; the bytes in the buffer are what the upstream will read.
        let read_back = {
            let Some(slot) = self.buf.get(at..at + 2) else {
                self.buf.truncate(self.start);
                return Err(EncodeError::LengthCheckFailed);
            };
            let Ok(bytes) = slot.try_into() else {
                self.buf.truncate(self.start);
                return Err(EncodeError::LengthCheckFailed);
            };
            u16::from_be_bytes(bytes)
        };
        if usize::from(read_back) != written_total - 16 {
            self.buf.truncate(self.start);
            return Err(EncodeError::LengthCheckFailed);
        }

        self.finished = true;
        Ok(written_total)
    }

    /// TLVs skipped for space so far.
    #[must_use]
    pub const fn skipped(&self) -> u16 {
        self.skipped
    }
}

impl Drop for V2Encoder<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.buf.truncate(self.start);
        }
    }
}

/// Encodes a complete v2 header in one call.
///
/// # Errors
/// As `V2Encoder::begin`, `append_tlv` and `finish`.
pub fn encode_v2(
    buf: &mut BytesMut,
    src: SocketAddr,
    dst: SocketAddr,
    tlvs: &[Tlv<'_>],
) -> Result<usize, EncodeError> {
    let mut enc = V2Encoder::begin(buf, src, dst)?;
    for tlv in tlvs {
        enc.append_tlv(tlv)?;
    }
    enc.finish()
}

#[cfg(test)]
impl<'b> V2Encoder<'b> {
    /// Test-only: creates an encoder at `start` with the given buffer, bypassing the
    /// `begin` header layout and the `append_tlv` ceiling check.
    pub(crate) fn for_test(buf: &'b mut BytesMut, start: usize) -> Self {
        Self {
            buf,
            start,
            skipped: 0,
            finished: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::proxyproto::ProxyHeader;
    use irontraffic_http::ParseStatus;

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn v6(segments: [u16; 8], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(segments)), port)
    }

    fn authority(value: &[u8]) -> Tlv<'_> {
        Tlv {
            kind: PP2_TYPE_AUTHORITY,
            value,
        }
    }

    fn assert_declared_length(buf: &BytesMut, start: usize, written_total: usize) {
        let at = start + 14;
        let len_bytes = &buf[at..at + 2];
        let declared = u16::from_be_bytes([len_bytes[0], len_bytes[1]]);
        assert_eq!(usize::from(declared), written_total - 16);
    }

    /// Edge cases 1, 2, 4 and 5: exact byte layouts for IPv4 and IPv6 headers, with and
    /// without TLVs.
    #[test]
    fn fixed_shapes() {
        let src = v4(1, 2, 3, 4, 1);
        let dst = v4(5, 6, 7, 8, 2);
        let mut buf = BytesMut::with_capacity(128);
        encode_v2(&mut buf, src, dst, &[]).unwrap();
        let expected: [u8; 28] = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11,
            0x00, 0x0C, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0, 2,
        ];
        assert_eq!(&buf[..], &expected[..]);

        let src = v6([0, 0, 0, 0, 0, 0, 0, 1], 1);
        let dst = v6([0, 0, 0, 0, 0, 0, 0, 2], 2);
        let mut buf = BytesMut::with_capacity(128);
        encode_v2(&mut buf, src, dst, &[]).unwrap();
        assert_eq!(buf.len(), 52);
        assert_eq!(buf[12], 0x21);
        assert_eq!(buf[13], 0x21);
        assert_eq!(&buf[14..16], &[0x00, 0x24]);

        let src = v4(1, 2, 3, 4, 1);
        let dst = v4(5, 6, 7, 8, 2);
        let mut buf = BytesMut::with_capacity(128);
        encode_v2(&mut buf, src, dst, &[authority(b"host")]).unwrap();
        let expected: [u8; 35] = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11,
            0x00, 0x13, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0, 2, 0x02, 0x00, 0x04, b'h', b'o', b's',
            b't',
        ];
        assert_eq!(&buf[..], &expected[..]);

        let mut buf = BytesMut::with_capacity(128);
        encode_v2(&mut buf, src, dst, &[authority(b"")]).unwrap();
        let expected: [u8; 31] = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11,
            0x00, 0x0F, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0, 2, 0x02, 0x00, 0x00,
        ];
        assert_eq!(&buf[..], &expected[..]);
    }

    /// For every header-producing case, reads the 2-byte length field back out of the
    /// buffer and asserts it equals `written_total - 16`. This is the exact check that
    /// would have caught Envoy CVE-2026-47692, where the advertised length was 38 bytes
    /// but 65561 bytes were written, spilling 65523 attacker-controlled bytes past the HTTP
    /// connection manager, RBAC, JWT and `ext_authz`.
    ///
    /// Also covers edge case 20: a payload that bypasses the `append_tlv` ceiling check is
    /// caught by the range check in `finish`, which truncates the buffer rather than write
    /// a truncated length field.
    #[allow(
        clippy::integer_division,
        reason = "floor division is the intended operation for counting whole TLVs that fit"
    )]
    #[test]
    fn declared_length_equals_bytes_written() {
        let v4_src = v4(1, 2, 3, 4, 1);
        let v4_dst = v4(5, 6, 7, 8, 2);
        let v6_src = v6([0, 0, 0, 0, 0, 0, 0, 1], 1);
        let v6_dst = v6([0, 0, 0, 0, 0, 0, 0, 2], 2);
        let big = vec![0u8; 65_535];
        let value_65520 = vec![0u8; 65_520];
        let value_65521 = vec![0u8; 65_521];
        let value_300: Vec<Vec<u8>> = (0..300)
            .map(|i| vec![u8::try_from(i % 256).unwrap(); 300])
            .collect();
        let cases: Vec<(&str, SocketAddr, SocketAddr, Vec<Tlv<'_>>, usize)> = vec![
            ("v4 no tlv", v4_src, v4_dst, vec![], 28),
            ("v6 no tlv", v6_src, v6_dst, vec![], 52),
            (
                "one 4-byte tlv",
                v4_src,
                v4_dst,
                vec![authority(b"host")],
                35,
            ),
            ("empty tlv", v4_src, v4_dst, vec![authority(b"")], 31),
            (
                "skipped too-long tlv",
                v4_src,
                v4_dst,
                vec![Tlv {
                    kind: 0x02,
                    value: &big,
                }],
                28,
            ),
            (
                "exactly fills ceiling",
                v4_src,
                v4_dst,
                vec![Tlv {
                    kind: 0x02,
                    value: &value_65520,
                }],
                65_551,
            ),
            (
                "one byte over exact fill",
                v4_src,
                v4_dst,
                vec![Tlv {
                    kind: 0x02,
                    value: &value_65521,
                }],
                28,
            ),
            (
                "300 300-byte tlvs",
                v4_src,
                v4_dst,
                value_300
                    .iter()
                    .map(|v| Tlv {
                        kind: 0x02,
                        value: v.as_slice(),
                    })
                    .collect(),
                0,
            ),
        ];

        for (name, src, dst, tlvs, expected_total) in cases {
            let mut buf = BytesMut::with_capacity(131_072);
            let start = buf.len();
            let written = encode_v2(&mut buf, src, dst, &tlvs).unwrap();
            let expected_total = if name == "300 300-byte tlvs" {
                let per_tlv = 3 + 300;
                let max_n = (MAX_PAYLOAD_LEN - 12) / per_tlv;
                16 + 12 + max_n * per_tlv
            } else {
                expected_total
            };
            assert_eq!(written, expected_total, "{name}");
            assert_declared_length(&buf, start, written);
            let parsed = ProxyHeader::parse(&buf[start..]).unwrap();
            match parsed {
                ParseStatus::Complete { value, consumed } => {
                    assert_eq!(consumed, written, "{name}");
                    assert_eq!(value.src(), Some(src), "{name}");
                    assert_eq!(value.dst(), Some(dst), "{name}");
                }
                ParseStatus::Partial => panic!("{name}: expected Complete, got {parsed:?}"),
            }
        }

        // Edge case 20: a payload that exceeds the ceiling is caught by the range check in
        // `finish`, not by writing a truncated length field.
        {
            let mut buf = BytesMut::with_capacity(65_552);
            let start = buf.len();
            buf.extend_from_slice(&[0x0D; 16]);
            buf.extend_from_slice(&vec![0u8; 65_536]);
            let enc = V2Encoder::for_test(&mut buf, start);
            assert_eq!(enc.finish(), Err(EncodeError::LengthCheckFailed));
            assert_eq!(buf.len(), start);
        }
    }

    /// Edge cases 6, 7, 8, 9, 10 and 21: the 65535-byte payload ceiling is enforced before
    /// any byte is written, and `skipped()` accounts for every TLV that did not fit.
    #[allow(
        clippy::too_many_lines,
        clippy::integer_division,
        reason = "one flat test covering the issue's numbered edge cases 6 through 10 and 21; \
                  floor division counts whole TLVs that fit under the ceiling"
    )]
    #[test]
    fn ceiling_is_enforced_before_writing() {
        let src = v4(1, 2, 3, 4, 1);
        let dst = v4(5, 6, 7, 8, 2);

        // Edge 6: a TLV whose value is exactly 65535 bytes is skipped because 12 + 3 + 65535
        // exceeds the ceiling. The header is still valid and parses.
        {
            let mut buf = BytesMut::with_capacity(65_552);
            let value = vec![0u8; 65_535];
            let mut enc = V2Encoder::begin(&mut buf, src, dst).unwrap();
            assert_eq!(
                enc.append_tlv(&Tlv {
                    kind: 0x02,
                    value: &value
                }),
                Ok(false)
            );
            assert_eq!(enc.skipped(), 1);
            let written = enc.finish().unwrap();
            assert_eq!(written, 28);
            assert_declared_length(&buf, 0, written);
            assert!(ProxyHeader::parse(&buf[..]).is_ok());
        }

        // Edge 7: a TLV whose value is 65536 bytes is refused before writing.
        {
            let mut buf = BytesMut::with_capacity(128);
            let value = vec![0u8; 65_536];
            let mut enc = V2Encoder::begin(&mut buf, src, dst).unwrap();
            assert_eq!(
                enc.append_tlv(&Tlv {
                    kind: 0x02,
                    value: &value
                }),
                Err(EncodeError::TlvValueTooLong)
            );
            drop(enc);
            assert_eq!(buf.len(), 0); // dropped unfinished
        }

        // Edge 8: a TLV that exactly fills the ceiling is written and round-trips.
        {
            let mut buf = BytesMut::with_capacity(65_552);
            let value = vec![0u8; 65_520];
            let written = encode_v2(
                &mut buf,
                src,
                dst,
                &[Tlv {
                    kind: 0x02,
                    value: &value,
                }],
            )
            .unwrap();
            assert_eq!(written, 65_551);
            assert_declared_length(&buf, 0, written);
            match ProxyHeader::parse(&buf[..]).unwrap() {
                ParseStatus::Complete { consumed, .. } => {
                    assert_eq!(consumed, written);
                }
                other @ ParseStatus::Partial => panic!("expected Complete, got {other:?}"),
            }
        }

        // Edge 9: a TLV one byte over the exact fill is skipped.
        {
            let mut buf = BytesMut::with_capacity(65_552);
            let value = vec![0u8; 65_521];
            let mut enc = V2Encoder::begin(&mut buf, src, dst).unwrap();
            assert_eq!(
                enc.append_tlv(&Tlv {
                    kind: 0x02,
                    value: &value
                }),
                Ok(false)
            );
            assert_eq!(enc.skipped(), 1);
            assert_eq!(enc.finish().unwrap(), 28);
        }

        // Edge 10: 300 TLVs with 300-byte values. The boundary is computed from the ceiling.
        {
            let values: Vec<Vec<u8>> = (0..300)
                .map(|i| vec![u8::try_from(i % 256).unwrap(); 300])
                .collect();
            let tlvs: Vec<Tlv<'_>> = values
                .iter()
                .map(|v| Tlv {
                    kind: 0x02,
                    value: v.as_slice(),
                })
                .collect();
            let mut buf = BytesMut::with_capacity(131_072);
            let written = encode_v2(&mut buf, src, dst, &tlvs).unwrap();
            assert!(written <= 65_551);
            let per_tlv = 3 + 300;
            let max_n = (MAX_PAYLOAD_LEN - 12) / per_tlv;
            assert_eq!(written, 16 + 12 + max_n * per_tlv);
            assert_declared_length(&buf, 0, written);
            match ProxyHeader::parse(&buf[..]).unwrap() {
                ParseStatus::Complete { consumed, .. } => {
                    assert_eq!(consumed, written);
                }
                other @ ParseStatus::Partial => panic!("expected Complete, got {other:?}"),
            }
        }

        // Edge 21: 70,000 one-byte TLVs appended to a full header. `skipped()` saturates at
        // `u16::MAX` rather than wrapping to a small number.
        {
            let mut buf = BytesMut::with_capacity(65_552);
            // First fill the header to the ceiling.
            let fill_value = vec![0u8; MAX_PAYLOAD_LEN - 12 - 3];
            let mut enc = V2Encoder::begin(&mut buf, src, dst).unwrap();
            assert!(
                enc.append_tlv(&Tlv {
                    kind: 0x02,
                    value: &fill_value
                })
                .unwrap()
            );
            assert_eq!(enc.skipped(), 0);
            let one_byte = [0u8];
            for _ in 0..70_000 {
                let _ = enc.append_tlv(&Tlv {
                    kind: 0x02,
                    value: &one_byte,
                });
            }
            assert_eq!(enc.skipped(), u16::MAX);
            let written = enc.finish().unwrap();
            assert_eq!(written, 65_551);
        }
    }

    /// Edge case 3: mismatched address families leave the buffer unchanged.
    #[test]
    fn family_mismatch() {
        let src = v4(1, 2, 3, 4, 1);
        let dst = v6([0, 0, 0, 0, 0, 0, 0, 1], 2);
        let mut buf = BytesMut::with_capacity(128);
        let start = buf.len();
        assert_eq!(
            encode_v2(&mut buf, src, dst, &[]),
            Err(EncodeError::AddressFamilyMismatch)
        );
        assert_eq!(buf.len(), start);
    }

    /// Edge cases 13 and 13b: an abandoned encoder truncates the buffer, and a finished one
    /// does NOT. The second half is the regression test for `finish` forgetting to set
    /// `finished`, which would silently delete every header while leaving the return value
    /// correct.
    #[test]
    fn abandoned_encoder_truncates() {
        let src = v4(1, 2, 3, 4, 1);
        let dst = v4(5, 6, 7, 8, 2);

        // Edge 13: abandoned encoder truncates.
        {
            let mut buf = BytesMut::with_capacity(128);
            let start = buf.len();
            {
                let mut enc = V2Encoder::begin(&mut buf, src, dst).unwrap();
                enc.append_tlv(&authority(b"x")).unwrap();
                // `enc` is dropped here without `finish`.
            }
            assert_eq!(buf.len(), start);
        }

        // Edge 13b: finished encoder keeps the header.
        {
            let mut buf = BytesMut::with_capacity(128);
            let written = {
                let mut enc = V2Encoder::begin(&mut buf, src, dst).unwrap();
                enc.append_tlv(&authority(b"x")).unwrap();
                enc.finish().unwrap()
            };
            assert_eq!(buf.len(), written);
            assert!(ProxyHeader::parse(&buf[..]).is_ok());
        }
    }

    /// Edge cases 14 and 15: encoding appends to a buffer that already holds bytes, and two
    /// headers can be encoded back to back.
    #[test]
    fn appends_to_a_nonempty_buffer() {
        let src = v4(1, 2, 3, 4, 1);
        let dst = v4(5, 6, 7, 8, 2);

        // Edge 14: pre-existing bytes are untouched.
        {
            let prefix = b"prefix";
            let mut buf = BytesMut::from(prefix.as_slice());
            let start = buf.len();
            let written = encode_v2(&mut buf, src, dst, &[]).unwrap();
            assert_eq!(&buf[..start], prefix);
            assert_declared_length(&buf, start, written);
            match ProxyHeader::parse(&buf[start..]).unwrap() {
                ParseStatus::Complete { value, consumed } => {
                    assert_eq!(consumed, written);
                    assert_eq!(value.src(), Some(src));
                    assert_eq!(value.dst(), Some(dst));
                }
                other @ ParseStatus::Partial => panic!("expected Complete, got {other:?}"),
            }
        }

        // Edge 15: two headers back to back.
        {
            let mut buf = BytesMut::with_capacity(128);
            let src2 = v4(9, 10, 11, 12, 3);
            let dst2 = v4(13, 14, 15, 16, 4);
            let n1 = encode_v2(&mut buf, src, dst, &[]).unwrap();
            let n2 = encode_v2(&mut buf, src2, dst2, &[authority(b"x")]).unwrap();
            match ProxyHeader::parse(&buf[..]).unwrap() {
                ParseStatus::Complete { value, consumed } => {
                    assert_eq!(consumed, n1);
                    assert_eq!(value.src(), Some(src));
                    assert_eq!(value.dst(), Some(dst));
                }
                other @ ParseStatus::Partial => panic!("expected first Complete, got {other:?}"),
            }
            match ProxyHeader::parse(&buf[n1..]).unwrap() {
                ParseStatus::Complete { value, consumed } => {
                    assert_eq!(consumed, n2);
                    assert_eq!(value.src(), Some(src2));
                    assert_eq!(value.dst(), Some(dst2));
                }
                other @ ParseStatus::Partial => panic!("expected second Complete, got {other:?}"),
            }
        }
    }

    /// Edge case 18: the 18 combinations of {IPv4, IPv6} x {0, 1, 8 TLVs} x {ports 0, 1,
    /// 65535} all round-trip through `ProxyHeader::parse`.
    #[test]
    fn roundtrip_matrix() {
        let ports: [u16; 3] = [0, 1, 65_535];
        let tlv_counts: [usize; 3] = [0, 1, 8];

        for is_v4 in [true, false] {
            for &sport in &ports {
                for &dport in &ports {
                    for &count in &tlv_counts {
                        let src = if is_v4 {
                            v4(1, 2, 3, 4, sport)
                        } else {
                            v6([0, 0, 0, 0, 0, 0, 0, 1], sport)
                        };
                        let dst = if is_v4 {
                            v4(5, 6, 7, 8, dport)
                        } else {
                            v6([0, 0, 0, 0, 0, 0, 0, 2], dport)
                        };
                        let values: Vec<Vec<u8>> =
                            (0..count).map(|i| vec![u8::try_from(i).unwrap()]).collect();
                        let tlvs: Vec<Tlv<'_>> = values
                            .iter()
                            .map(|v| Tlv {
                                kind: PP2_TYPE_AUTHORITY,
                                value: v.as_slice(),
                            })
                            .collect();
                        let mut buf = BytesMut::with_capacity(1024);
                        let written = encode_v2(&mut buf, src, dst, &tlvs).unwrap();
                        match ProxyHeader::parse(&buf[..]).unwrap() {
                            ParseStatus::Complete { value, consumed } => {
                                assert_eq!(consumed, written);
                                assert_eq!(value.src(), Some(src));
                                assert_eq!(value.dst(), Some(dst));
                            }
                            other @ ParseStatus::Partial => panic!(
                                "v4={is_v4} sport={sport} dport={dport} count={count}: expected Complete, got {other:?}"
                            ),
                        }
                    }
                }
            }
        }
    }

    fn ip_pair_strategy() -> impl Strategy<Value = (SocketAddr, SocketAddr)> {
        prop_oneof![
            (
                any::<[u8; 4]>(),
                any::<[u8; 4]>(),
                any::<u16>(),
                any::<u16>()
            )
                .prop_map(|(a, b, sp, dp)| {
                    (
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), sp),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(b)), dp),
                    )
                }),
            (
                any::<[u8; 16]>(),
                any::<[u8; 16]>(),
                any::<u16>(),
                any::<u16>()
            )
                .prop_map(|(a, b, sp, dp)| {
                    (
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), sp),
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(b)), dp),
                    )
                }),
        ]
    }

    fn tlv_strategy() -> impl Strategy<Value = Tlv<'static>> {
        (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..=512)).prop_map(|(kind, value)| {
            Tlv {
                kind,
                value: &*value.leak(),
            }
        })
    }

    proptest! {
        /// Property: for any generated source and destination (both IPv4 or both IPv6) and
        /// 0..=16 TLVs of 0..=512 bytes, `encode_v2` then `ProxyHeader::parse` yields the
        /// same addresses and ports, `consumed` equals the encode return value, and the
        /// length field equals `consumed - 16`.
        #[test]
        fn prop_roundtrip((pair, tlvs) in (ip_pair_strategy(), proptest::collection::vec(tlv_strategy(), 0..=16))) {
            let (src, dst) = pair;
            let mut buf = BytesMut::with_capacity(65_536);
            let written = encode_v2(&mut buf, src, dst, &tlvs).unwrap();
            assert!(written <= 65_551);
            let parsed = ProxyHeader::parse(&buf[..]).unwrap();
            match parsed {
                ParseStatus::Complete { value, consumed } => {
                    assert_eq!(consumed, written);
                    assert_eq!(value.src(), Some(src));
                    assert_eq!(value.dst(), Some(dst));
                }
                other @ ParseStatus::Partial => panic!("expected Complete, got {other:?}"),
            }
            let declared = u16::from_be_bytes([buf[14], buf[15]]);
            assert_eq!(usize::from(declared), written - 16);
        }
    }
}
