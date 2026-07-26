// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests over real loopback listeners.

use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use irontraffic_config::UpstreamAddr;
use irontraffic_io::{Read as IoRead, ReadBuf, Transport, Write as IoWrite, with_timeout};
use irontraffic_upstream::{ConnectError, SingleUpstream};
use tokio::io::AsyncReadExt;

/// Converts a bound socket address into the configuration newtype this crate
/// accepts, the same shape an operator's configuration file produces.
///
/// Returns a `Result` rather than unwrapping internally: this plain helper
/// function is not itself a `#[test]`, so clippy's per-test unwrap/expect
/// exemption does not reach it, and every call site below is inside a real
/// `#[tokio::test]` body where `.expect(...)` is exempt.
fn upstream_addr(addr: SocketAddr) -> Result<UpstreamAddr, irontraffic_config::FieldError> {
    UpstreamAddr::try_from(addr.to_string())
}

/// Reads once into `dst`, returning the number of bytes filled (0 means end of file).
/// Copied from `io-transport-seam` (#7)'s test file
/// (`crates/irontraffic-io/tests/tcp_roundtrip.rs`), which this crate has no other
/// way to drive a `hyper::rt::Read` from outside the transport seam.
async fn read_once<T: Transport>(t: &mut T, dst: &mut [u8]) -> std::io::Result<usize> {
    std::future::poll_fn(|cx| {
        let mut rb = ReadBuf::new(dst);
        match IoRead::poll_read(Pin::new(&mut *t), cx, rb.unfilled()) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(rb.filled().len())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
        }
    })
    .await
}

/// Writes `buf` to completion by polling `poll_write` directly, the same shape as
/// `read_once` above: this crate has no other way to drive a `hyper::rt::Write`.
async fn write_all<T: Transport>(t: &mut T, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        let n = std::future::poll_fn(|cx| IoWrite::poll_write(Pin::new(&mut *t), cx, buf)).await?;
        buf = buf
            .get(n..)
            .ok_or_else(|| std::io::Error::other("poll_write reported writing past the buffer"))?;
    }
    Ok(())
}

#[tokio::test]
async fn connects_to_a_live_listener() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let accept = tokio::spawn(async move { listener.accept().await });

    let configured = upstream_addr(addr).expect("a SocketAddr always formats back");
    let upstream = SingleUpstream::new(configured, Duration::from_millis(500));
    let transport = upstream.connect().await.expect("connect should succeed");
    assert_eq!(transport.peer_addr().expect("peer_addr"), addr);

    accept
        .await
        .expect("accept task should not panic")
        .expect("listener should accept the connection");
}

#[tokio::test]
async fn refused_when_nothing_listens() {
    let mut outcome = None;
    for attempt in 1..=3 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let configured = upstream_addr(addr).expect("a SocketAddr always formats back");
        let upstream = SingleUpstream::new(configured, Duration::from_millis(500));
        let result = upstream.connect().await;
        let is_timeout = matches!(result, Err(ConnectError::TimedOut { .. }));
        outcome = Some((addr, result));
        if !is_timeout || attempt == 3 {
            break;
        }
    }

    let (addr, result) = outcome.expect("the loop always runs at least once");
    let err = result.expect_err("nothing listens on this address");
    assert!(
        matches!(err, ConnectError::Refused { .. }),
        "expected Refused, got {err:?}"
    );
    assert!(
        err.to_string().contains(&addr.port().to_string()),
        "display {err} should mention port {}",
        addr.port()
    );
    assert_eq!(err.reason(), "refused");
}

#[tokio::test]
async fn timeout_is_bounded_by_the_configured_deadline() {
    // RFC 5737 TEST-NET-1: reserved for documentation, never routed to a real host.
    let blackhole: SocketAddr = "192.0.2.1:1".parse().expect("RFC 5737 literal");
    let configured = upstream_addr(blackhole).expect("a SocketAddr always formats back");
    let upstream = SingleUpstream::new(configured, Duration::from_millis(200));

    let start = std::time::Instant::now();
    let result = upstream.connect().await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "connect took {elapsed:?}, expected under 2s"
    );
    match result {
        Err(ConnectError::TimedOut { millis, .. }) => assert_eq!(millis, 200),
        // Some CI networks report a routing failure for TEST-NET-1 immediately
        // instead of timing out; the property under test is boundedness, not
        // which of the two failure kinds is reported.
        Err(ConnectError::Unreachable { .. }) => {}
        other => panic!("expected TimedOut or Unreachable, got {other:?}"),
    }
}

#[tokio::test]
async fn connector_round_trips_a_byte() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let accept = tokio::spawn(async move { listener.accept().await.expect("accept") });

    let configured = upstream_addr(addr).expect("a SocketAddr always formats back");
    let upstream = SingleUpstream::new(configured, Duration::from_millis(500));
    let mut transport = upstream.connect().await.expect("connect should succeed");
    write_all(&mut transport, b"a")
        .await
        .expect("write should succeed");

    let (mut server, _peer) = accept.await.expect("accept task should not panic");
    let mut buf = [0u8; 1];
    with_timeout(Duration::from_millis(100), server.read_exact(&mut buf))
        .await
        .expect("listener should observe the byte within 100ms")
        .expect("read should succeed");
    assert_eq!(buf, [b'a']);
}

#[tokio::test]
async fn timed_out_connects_do_not_leak_descriptors() {
    // RFC 5737 TEST-NET-1: reserved for documentation, never routed to a real host.
    let blackhole: SocketAddr = "192.0.2.1:1".parse().expect("RFC 5737 literal");
    let configured = upstream_addr(blackhole).expect("a SocketAddr always formats back");
    let upstream = SingleUpstream::new(configured, Duration::from_millis(5));

    for _ in 0..200 {
        let result = upstream.connect().await;
        assert!(
            result.is_err(),
            "connect to the black hole should not succeed: {result:?}"
        );
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let accept = tokio::spawn(async move { listener.accept().await });

    let configured = upstream_addr(addr).expect("a SocketAddr always formats back");
    let live = SingleUpstream::new(configured, Duration::from_millis(500));
    let result = live.connect().await;
    assert!(
        result.is_ok(),
        "connect after 200 timed-out attempts should still succeed: {result:?}"
    );

    accept
        .await
        .expect("accept task should not panic")
        .expect("listener should accept the connection");
}

#[tokio::test]
async fn zero_deadline_times_out_immediately() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let configured = upstream_addr(addr).expect("a SocketAddr always formats back");
    let upstream = SingleUpstream::new(configured, Duration::ZERO);

    match upstream.connect().await {
        // The expected outcome, and (see
        // https://github.com/ELares/IronTraffic/issues/519) the ONLY outcome on a
        // platform where a loopback TCP connect always yields `Pending` on its
        // first poll. On some platforms (observed deterministically on
        // macOS/Darwin) a loopback connect can instead complete inside tokio's
        // very first poll, before with_timeout(Duration::ZERO, ..) ever gets a
        // chance to observe the already-elapsed deadline: with_timeout always
        // polls the inner future before the delay and prefers a Ready result
        // (the same behaviour with_timeout_prefers_ready_future in
        // irontraffic-io exercises directly), so a same-tick success
        // legitimately races a zero budget and wins. Millis::MIN is 1, so a
        // zero deadline is unreachable through real configuration in the
        // first place (see edge case 4); accepting a synchronous Ok(_) here
        // documents that platform behaviour rather than masking a bug in
        // SingleUpstream::connect or classify, neither of which this path
        // reaches.
        Err(ConnectError::TimedOut { millis: 0, .. }) | Ok(_) => {}
        other => {
            panic!("expected TimedOut {{ millis: 0 }} or a synchronous success, got {other:?}")
        }
    }
}

#[tokio::test]
async fn upstream_that_closes_immediately_still_connects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let accept = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        drop(stream);
    });

    let configured = upstream_addr(addr).expect("a SocketAddr always formats back");
    let upstream = SingleUpstream::new(configured, Duration::from_millis(500));
    let mut transport = upstream
        .connect()
        .await
        .expect("connect should succeed even though the peer closes immediately");

    accept.await.expect("accept task should not panic");

    let mut buf = [0u8; 16];
    let n = with_timeout(
        Duration::from_millis(500),
        read_once(&mut transport, &mut buf),
    )
    .await
    .expect("read should not hang")
    .expect("read should succeed");
    assert_eq!(n, 0, "an immediately closed peer must read back as EOF");
}
