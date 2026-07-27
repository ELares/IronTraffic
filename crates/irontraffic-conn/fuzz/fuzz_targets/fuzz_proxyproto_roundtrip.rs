#![no_main]

//! Fuzz target for `irontraffic_conn::proxyproto::encode::encode_v2` paired with
//! `ProxyHeader::parse`.
//!
//! Input domain: arbitrary bytes. The first byte selects the address family (even means
//! IPv4, odd means IPv6). The required address and port bytes follow; the remainder is
//! consumed as a sequence of TLVs.
//!
//! Contract: encode MUST succeed, parse of the encoded bytes MUST succeed, the parsed
//! addresses and ports MUST equal the encoded ones, `consumed` MUST equal the encode
//! return value, the length field read from the buffer MUST equal `consumed - 16`, and
//! the total buffer length MUST never exceed 65551 bytes for one header.

use bytes::BytesMut;
use irontraffic_conn::proxyproto::ProxyHeader;
use irontraffic_conn::proxyproto::encode::{Tlv, encode_v2};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Parses the remainder of the fuzz input into a sequence of TLVs. Each TLV's value is
/// capped so that at least some TLVs fit even when the raw input is large, keeping the
/// encoder on the success path this target is meant to exercise.
fn tlvs_from_bytes(bytes: &[u8]) -> Vec<Tlv<'_>> {
    let mut tlvs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 > bytes.len() {
            tlvs.push(Tlv {
                kind: 0x02,
                value: &bytes[i..],
            });
            break;
        }
        let kind = bytes[i];
        let len = usize::from(u16::from_be_bytes([bytes[i + 1], bytes[i + 2]]));
        let value_start = i + 3;
        let value_end = value_start.saturating_add(len).min(bytes.len());
        tlvs.push(Tlv {
            kind,
            value: &bytes[value_start..value_end],
        });
        i = value_end;
    }
    tlvs
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let v4_block_len = 1 + 4 + 4 + 2 + 2;
    let v6_block_len = 1 + 16 + 16 + 2 + 2;
    let min_len = if data[0] % 2 == 0 {
        v4_block_len
    } else {
        v6_block_len
    };
    if data.len() < min_len {
        return;
    }

    let (src, dst, tlv_bytes) = if data[0] % 2 == 0 {
        let src_ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
        let dst_ip = Ipv4Addr::new(data[5], data[6], data[7], data[8]);
        let src_port = u16::from_be_bytes([data[9], data[10]]);
        let dst_port = u16::from_be_bytes([data[11], data[12]]);
        let src = SocketAddr::new(IpAddr::V4(src_ip), src_port);
        let dst = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
        (src, dst, &data[v4_block_len..])
    } else {
        let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[1..17]).unwrap()); // it-allow: no-panic reason: fuzz target reports a finding by panicking; data.len() >= v6_block_len guarantees 16 bytes
        let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[17..33]).unwrap()); // it-allow: no-panic reason: fuzz target reports a finding by panicking; data.len() >= v6_block_len guarantees 16 bytes
        let src_port = u16::from_be_bytes([data[33], data[34]]);
        let dst_port = u16::from_be_bytes([data[35], data[36]]);
        let src = SocketAddr::new(IpAddr::V6(src_ip), src_port);
        let dst = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);
        (src, dst, &data[v6_block_len..])
    };

    let tlvs = tlvs_from_bytes(tlv_bytes);
    let mut buf = BytesMut::with_capacity(65_536);
    let start = buf.len();
    let written = encode_v2(&mut buf, src, dst, &tlvs).unwrap(); // it-allow: no-panic reason: fuzz target reports a finding by panicking; encode_v2 succeeds by construction for these inputs
    assert!(written <= 65_551, "header exceeded 65551 bytes: {written}");
    assert_eq!(buf.len() - start, written);

    let parsed = ProxyHeader::parse(&buf[start..]).unwrap(); // it-allow: no-panic reason: fuzz target reports a finding by panicking; an encoder-generated header is always parseable
    if let Some((value, consumed)) = parsed.into_complete() {
        assert_eq!(consumed, written);
        assert_eq!(value.src(), Some(src));
        assert_eq!(value.dst(), Some(dst));
        let declared = u16::from_be_bytes([buf[start + 14], buf[start + 15]]);
        assert_eq!(usize::from(declared), consumed - 16);
    } else {
        panic!("parse of a valid encoded header returned Partial"); // it-allow: no-panic reason: fuzz target reports a finding by panicking; Partial means the round-trip contract was broken
    }
});
