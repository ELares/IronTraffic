// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests over real loopback socket pairs, plus the byte-identity
//! property test and (behind `test-support`) one test over the in-memory
//! [`irontraffic_dataplane::duplex::DuplexTransport`] double.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use irontraffic_dataplane::{
    EndReason, ForwardError, ForwardLimits, ForwardStats, forward_bidirectional,
};
use irontraffic_io::{
    Acceptor, Read as IoRead, ReadBuf, ShutdownController, SystemTimer, TcpAcceptor, TcpTransport,
    Transport, Write as IoWrite, with_timeout,
};
use proptest::prelude::*;

/// Every test in this file allocates from the SAME process-wide pooled-buffer
/// counters (`irontraffic_io::buffer::stats()`), and several assert exact or
/// bounded values against a captured baseline. Cargo runs the test functions in
/// this binary concurrently by default, so every test takes this lock for its
/// whole body to serialize against that shared, global state, mirroring the
/// same pattern in `irontraffic-io`'s own `buffer.rs` test suite. A
/// `tokio::sync::Mutex`, not a `std::sync::Mutex`: several tests hold this guard
/// across an `.await`, which `clippy::await_holding_lock` (denied
/// workspace-wide) rejects for a synchronous mutex but is exactly what an async
/// one is for.
static BUFFER_STATS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Generous limits for tests that are not themselves testing idle or
/// half-close timing: 60 seconds gives a wide margin under a loaded CI runner
/// where several tests race real sockets on their own `current_thread`
/// runtimes concurrently, without weakening any timing-specific test, which
/// all construct their own tight `ForwardLimits` instead of this one.
fn default_limits() -> ForwardLimits {
    ForwardLimits {
        idle: Duration::from_secs(60),
        half_close: Duration::from_secs(60),
        max_bytes_per_direction: None,
        max_lifetime: None,
    }
}

/// A deterministic, non-repeating byte pattern, distinguishable from any other
/// call with a different `seed` so a test can tell the two directions of a
/// connection apart in a failure message.
fn pattern_bytes(n: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let Ok(b) = u8::try_from(i % 251) else {
            unreachable!("i % 251 always fits in a u8")
        };
        out.push(b.wrapping_mul(31).wrapping_add(seed));
    }
    out
}

/// Connects a loopback TCP pair and returns both ends already wrapped as
/// [`TcpTransport`]: `.0` is the accepted (server) side, `.1` is the connecting
/// (client) side.
async fn tcp_pair() -> io::Result<(TcpTransport, TcpTransport)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let acceptor = TcpAcceptor::from_std(listener)?;

    let (accepted, connected) = tokio::join!(
        std::future::poll_fn(|cx| acceptor.poll_accept(cx)),
        tokio::net::TcpStream::connect(addr),
    );
    let (accepted, _peer) = accepted?;
    let connected = TcpTransport::from_tokio(connected?)?;
    Ok((accepted, connected))
}

/// Writes every byte of `data` to `t`, looping past partial writes.
async fn write_all_via<T: Transport>(t: &mut T, mut data: &[u8]) -> io::Result<()> {
    std::future::poll_fn(|cx| {
        while !data.is_empty() {
            match Pin::new(&mut *t).poll_write(cx, data) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => data = data.get(n..).unwrap_or_default(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    })
    .await
}

/// Shuts the write half of `t` down.
async fn shutdown_write<T: Transport>(t: &mut T) -> io::Result<()> {
    std::future::poll_fn(|cx| Pin::new(&mut *t).poll_shutdown(cx)).await
}

/// Reads `t` until end of file, returning everything received.
async fn read_to_end<T: Transport>(t: &mut T) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    std::future::poll_fn(|cx| {
        let mut chunk = [0_u8; 8192];
        loop {
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut *t).poll_read(cx, rb.unfilled()) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    out.extend_from_slice(rb.filled());
                }
            }
        }
    })
    .await?;
    Ok(out)
}

/// Reads exactly `n` bytes from `t`, failing with `UnexpectedEof` if `t` ends
/// first.
async fn read_exact_n<T: Transport>(t: &mut T, n: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    std::future::poll_fn(|cx| {
        let mut chunk = [0_u8; 8192];
        while out.len() < n {
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut *t).poll_read(cx, rb.unfilled()) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    out.extend_from_slice(rb.filled());
                }
            }
        }
        Poll::Ready(Ok(()))
    })
    .await?;
    out.truncate(n);
    Ok(out)
}

/// Concurrently writes a script of `(chunk, delay_ms)` pairs (sleeping
/// `delay_ms` before each chunk), shuts the write half down once every chunk
/// is sent, and reads whatever arrives until end of file, all interleaved on
/// the same transport rather than write-then-read sequentially.
///
/// This interleaving is load bearing, not a style choice. A peer that writes
/// its whole payload before ever reading can deadlock against another peer
/// doing the same: once both directions' payloads exceed the OS socket
/// buffers, each side blocks on `poll_write`, waiting for a receive buffer
/// the OTHER side has not started draining yet because it too is still
/// writing. `eight_mib_is_byte_identical` (both directions carry 8 MiB) hits
/// exactly this with a naive sequential helper; interleaving here is what a
/// real full-duplex peer does, and what `forward_bidirectional` itself does.
async fn drive_far_end_chunks(
    mut t: TcpTransport,
    chunks: Vec<(Vec<u8>, u64)>,
) -> io::Result<Vec<u8>> {
    let mut remaining: std::collections::VecDeque<(Vec<u8>, u64)> = chunks.into();
    let mut current: Vec<u8> = Vec::new();
    let mut current_pos = 0_usize;
    let mut sleeping: Option<Pin<Box<tokio::time::Sleep>>> = None;
    let mut write_done = false;
    let mut shutdown_done = false;
    let mut received = Vec::new();
    let mut read_done = false;

    std::future::poll_fn(|cx| {
        loop {
            let mut progressed = false;

            if !write_done {
                if current_pos < current.len() {
                    let pending = current.get(current_pos..).unwrap_or_default();
                    match Pin::new(&mut t).poll_write(cx, pending) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                        }
                        Poll::Ready(Ok(n)) => {
                            current_pos += n;
                            progressed = true;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {}
                    }
                } else if let Some(sleep) = sleeping.as_mut() {
                    if sleep.as_mut().poll(cx).is_ready() {
                        sleeping = None;
                        progressed = true;
                    }
                } else if let Some((chunk, delay_ms)) = remaining.pop_front() {
                    current = chunk;
                    current_pos = 0;
                    if delay_ms > 0 {
                        sleeping = Some(Box::pin(tokio::time::sleep(Duration::from_millis(
                            delay_ms,
                        ))));
                    }
                    progressed = true;
                } else {
                    write_done = true;
                    progressed = true;
                }
            } else if !shutdown_done {
                match Pin::new(&mut t).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => {
                        shutdown_done = true;
                        progressed = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }

            if !read_done {
                let mut chunk_buf = [0_u8; 8192];
                let mut rb = ReadBuf::new(&mut chunk_buf);
                match Pin::new(&mut t).poll_read(cx, rb.unfilled()) {
                    Poll::Ready(Ok(())) => {
                        let filled = rb.filled().len();
                        if filled == 0 {
                            read_done = true;
                        } else {
                            received.extend_from_slice(rb.filled());
                        }
                        progressed = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }

            if shutdown_done && read_done {
                return Poll::Ready(Ok(()));
            }
            if !progressed {
                return Poll::Pending;
            }
        }
    })
    .await?;

    Ok(received)
}

/// Writes `send`, shuts the write half down, then reads whatever comes back
/// until end of file, all interleaved with the write (see
/// [`drive_far_end_chunks`]). Used to drive the "fake peer" end of a pair
/// while `forward_bidirectional` drives the near end.
async fn drive_far_end(t: TcpTransport, send: Vec<u8>) -> io::Result<Vec<u8>> {
    drive_far_end_chunks(t, vec![(send, 0)]).await
}

/// Reads `t` until end of file, discarding the near end's write side entirely
/// (never writes back). Used for a far end that only needs to observe what
/// arrives.
async fn collect_all(mut t: TcpTransport) -> io::Result<Vec<u8>> {
    read_to_end(&mut t).await
}

/// Wraps a transport's write side with a byte cap per call and an optional
/// cooldown after each successful write, to prove the loop resumes a partial
/// write and never reads ahead of it. The read side and shutdown are passed
/// through unchanged.
struct ThrottledTransport<T> {
    inner: T,
    max_write: usize,
    /// Caps how many bytes one `poll_read` call delivers. `usize::MAX` (the
    /// default via [`ThrottledTransport::new`]) means unlimited: the inner
    /// transport's own read size decides.
    read_cap: usize,
    delay: Duration,
    cooldown: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<T> ThrottledTransport<T> {
    fn new(inner: T, max_write: usize, delay: Duration) -> Self {
        Self {
            inner,
            max_write,
            read_cap: usize::MAX,
            delay,
            cooldown: None,
        }
    }

    fn with_read_cap(mut self, read_cap: usize) -> Self {
        self.read_cap = read_cap;
        self
    }
}

impl<T: IoRead + Unpin> IoRead for ThrottledTransport<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: irontraffic_io::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let want = buf.remaining().min(this.read_cap);
        if want == buf.remaining() {
            // No cap in effect (or the caller's buffer is already smaller than the
            // cap): read straight into the caller's cursor, no extra copy.
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let mut capped = vec![0_u8; want];
        let mut rb = ReadBuf::new(&mut capped);
        match Pin::new(&mut this.inner).poll_read(cx, rb.unfilled()) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                buf.put_slice(rb.filled());
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<T: IoWrite + Unpin> IoWrite for ThrottledTransport<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(sleep) = this.cooldown.as_mut() {
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.cooldown = None;
        }
        let cap = this.max_write.min(buf.len());
        let capped = buf.get(..cap).unwrap_or(buf);
        let result = Pin::new(&mut this.inner).poll_write(cx, capped);
        if let Poll::Ready(Ok(_)) = result
            && !this.delay.is_zero()
        {
            this.cooldown = Some(Box::pin(tokio::time::sleep(this.delay)));
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<T: Transport> Transport for ThrottledTransport<T> {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    #[cfg(unix)]
    fn as_raw_fd_opt(&self) -> Option<std::os::fd::RawFd> {
        self.inner.as_raw_fd_opt()
    }
}

/// A transport whose write side always reports zero bytes accepted, to drive
/// the `WriteZero` path deterministically.
struct AlwaysZeroWrite<T> {
    inner: T,
}

impl<T> AlwaysZeroWrite<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: IoRead + Unpin> IoRead for AlwaysZeroWrite<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: irontraffic_io::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: IoWrite + Unpin> IoWrite for AlwaysZeroWrite<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<T: Transport> Transport for AlwaysZeroWrite<T> {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    #[cfg(unix)]
    fn as_raw_fd_opt(&self) -> Option<std::os::fd::RawFd> {
        self.inner.as_raw_fd_opt()
    }
}

#[tokio::test]
async fn zero_byte_connection_ends_both_eof() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let (mut client_near, client_far) = tcp_pair().await.unwrap();
    let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();
    drop(client_far);
    drop(upstream_far);

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = default_limits();

    let (stats, reason) = forward_bidirectional(
        &mut client_near,
        &mut upstream_near,
        &timer,
        &token,
        &limits,
    )
    .await
    .unwrap();
    assert_eq!(reason, EndReason::BothEof);
    assert_eq!(stats, ForwardStats::default());
}

#[tokio::test]
async fn single_byte_each_way() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let (mut client_near, client_far) = tcp_pair().await.unwrap();
    let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();

    let client_task = tokio::spawn(drive_far_end(client_far, b"c".to_vec()));
    let upstream_task = tokio::spawn(drive_far_end(upstream_far, b"u".to_vec()));

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = default_limits();

    let (stats, reason) = forward_bidirectional(
        &mut client_near,
        &mut upstream_near,
        &timer,
        &token,
        &limits,
    )
    .await
    .unwrap();
    assert_eq!(reason, EndReason::BothEof);
    assert_eq!(stats.client_to_upstream, 1);
    assert_eq!(stats.upstream_to_client, 1);

    let client_far_received = client_task.await.unwrap().unwrap();
    let upstream_far_received = upstream_task.await.unwrap().unwrap();
    assert_eq!(client_far_received, b"u");
    assert_eq!(upstream_far_received, b"c");
}

#[tokio::test]
async fn exact_chunk_boundary() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    for &n in &[32767_usize, 32768, 32769] {
        let (mut client_near, client_far) = tcp_pair().await.unwrap();
        let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();

        let c_payload = pattern_bytes(n, 0xC1);
        let u_payload = pattern_bytes(n, 0xE2);

        let client_task = tokio::spawn(drive_far_end(client_far, c_payload.clone()));
        let upstream_task = tokio::spawn(drive_far_end(upstream_far, u_payload.clone()));

        let (_controller, token) = ShutdownController::new();
        let timer = SystemTimer::new();
        let limits = default_limits();

        let (stats, reason) = forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        )
        .await
        .unwrap();

        assert_eq!(reason, EndReason::BothEof, "payload size {n}");
        let want = u64::try_from(n).unwrap();
        assert_eq!(stats.client_to_upstream, want, "payload size {n}");
        assert_eq!(stats.upstream_to_client, want, "payload size {n}");

        let client_far_received = client_task.await.unwrap().unwrap();
        let upstream_far_received = upstream_task.await.unwrap().unwrap();
        assert_eq!(client_far_received, u_payload, "payload size {n}");
        assert_eq!(upstream_far_received, c_payload, "payload size {n}");
    }
}

#[tokio::test]
async fn eight_mib_is_byte_identical() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let mut rng = irontraffic_rand::Rng::from_seed(42);
    let mut payload = vec![0_u8; 8 * 1024 * 1024];
    rng.fill_bytes(&mut payload);

    let (mut client_near, client_far) = tcp_pair().await.unwrap();
    let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();

    let client_task = tokio::spawn(drive_far_end(client_far, payload.clone()));
    let upstream_task = tokio::spawn(drive_far_end(upstream_far, payload.clone()));

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = default_limits();

    let (stats, reason) = forward_bidirectional(
        &mut client_near,
        &mut upstream_near,
        &timer,
        &token,
        &limits,
    )
    .await
    .unwrap();

    assert_eq!(reason, EndReason::BothEof);
    let want = u64::try_from(payload.len()).unwrap();
    assert_eq!(stats.client_to_upstream, want);
    assert_eq!(stats.upstream_to_client, want);

    let client_far_received = client_task.await.unwrap().unwrap();
    let upstream_far_received = upstream_task.await.unwrap().unwrap();
    assert_eq!(client_far_received, payload);
    assert_eq!(upstream_far_received, payload);
}

#[tokio::test]
async fn at_most_two_buffers_outstanding() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let mut rng = irontraffic_rand::Rng::from_seed(7);
    let mut payload = vec![0_u8; 8 * 1024 * 1024];
    rng.fill_bytes(&mut payload);

    let (mut client_near, client_far) = tcp_pair().await.unwrap();
    let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();

    let client_task = tokio::spawn(drive_far_end(client_far, payload.clone()));
    let upstream_task = tokio::spawn(drive_far_end(upstream_far, Vec::new()));

    let baseline = irontraffic_io::buffer::stats().outstanding;
    let max_seen = Arc::new(AtomicU64::new(baseline));
    let sampler_max = Arc::clone(&max_seen);
    let sampler = tokio::spawn(async move {
        loop {
            let cur = irontraffic_io::buffer::stats().outstanding;
            sampler_max.fetch_max(cur, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    });

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = default_limits();

    let (stats, reason) = forward_bidirectional(
        &mut client_near,
        &mut upstream_near,
        &timer,
        &token,
        &limits,
    )
    .await
    .unwrap();
    sampler.abort();

    assert_eq!(reason, EndReason::BothEof);
    assert_eq!(
        stats.client_to_upstream,
        u64::try_from(payload.len()).unwrap()
    );

    let observed_max = max_seen.load(Ordering::Relaxed);
    assert!(
        observed_max <= baseline + 2,
        "outstanding rose to {observed_max}, baseline {baseline}"
    );

    client_task.await.unwrap().unwrap();
    upstream_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn idle_connection_holds_no_buffer() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let (client_near, _client_far) = tcp_pair().await.unwrap();
    let (upstream_near, _upstream_far) = tcp_pair().await.unwrap();

    let baseline = irontraffic_io::buffer::stats().outstanding;

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_secs(30),
        half_close: Duration::from_secs(30),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    let handle = tokio::spawn(async move {
        let mut client_near = client_near;
        let mut upstream_near = upstream_near;
        let _ = forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        )
        .await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(irontraffic_io::buffer::stats().outstanding, baseline);

    handle.abort();
    let _ = handle.await;
}

#[tokio::test]
async fn slow_reader_does_not_grow_memory() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let mut rng = irontraffic_rand::Rng::from_seed(99);
    let mut payload = vec![0_u8; 4 * 1024 * 1024];
    rng.fill_bytes(&mut payload);

    let (client_near, client_far) = tcp_pair().await.unwrap();
    let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();
    let mut client_near = ThrottledTransport::new(client_near, 1024, Duration::from_millis(1));

    let client_task = tokio::spawn(collect_all(client_far));
    let upstream_task = tokio::spawn(drive_far_end(upstream_far, payload.clone()));

    let baseline = irontraffic_io::buffer::stats().outstanding;
    let max_seen = Arc::new(AtomicU64::new(baseline));
    let sampler_max = Arc::clone(&max_seen);
    let sampler = tokio::spawn(async move {
        loop {
            let cur = irontraffic_io::buffer::stats().outstanding;
            sampler_max.fetch_max(cur, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_micros(200)).await;
        }
    });

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_secs(60),
        half_close: Duration::from_secs(60),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    let (stats, reason) = forward_bidirectional(
        &mut client_near,
        &mut upstream_near,
        &timer,
        &token,
        &limits,
    )
    .await
    .unwrap();
    sampler.abort();

    assert_eq!(reason, EndReason::BothEof);
    assert_eq!(
        stats.upstream_to_client,
        u64::try_from(payload.len()).unwrap()
    );

    let observed_max = max_seen.load(Ordering::Relaxed);
    assert!(
        observed_max <= baseline + 2,
        "outstanding rose to {observed_max}, baseline {baseline}"
    );

    let received = client_task.await.unwrap().unwrap();
    assert_eq!(received, payload);
    upstream_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn partial_writes_are_resumed() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let payload = pattern_bytes(100_000, 0x5A);

    let (mut client_near, client_far) = tcp_pair().await.unwrap();
    let (upstream_near, upstream_far) = tcp_pair().await.unwrap();
    let mut upstream_near = ThrottledTransport::new(upstream_near, 7, Duration::ZERO);

    let client_task = tokio::spawn(drive_far_end(client_far, payload.clone()));
    let upstream_task = tokio::spawn(collect_all(upstream_far));

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_secs(60),
        half_close: Duration::from_secs(60),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    let (stats, reason) = forward_bidirectional(
        &mut client_near,
        &mut upstream_near,
        &timer,
        &token,
        &limits,
    )
    .await
    .unwrap();

    assert_eq!(reason, EndReason::BothEof);
    assert_eq!(
        stats.client_to_upstream,
        u64::try_from(payload.len()).unwrap()
    );
    assert!(stats.writes >= 14_285, "stats.writes = {}", stats.writes);

    let received = upstream_task.await.unwrap().unwrap();
    assert_eq!(received, payload);
    client_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn write_zero_is_an_error() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let (mut client_near, client_far) = tcp_pair().await.unwrap();
    let (upstream_near, upstream_far) = tcp_pair().await.unwrap();
    let mut upstream_near = AlwaysZeroWrite::new(upstream_near);
    drop(upstream_far);

    let client_task = tokio::spawn(async move {
        let mut client_far = client_far;
        write_all_via(&mut client_far, b"hello").await
    });

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_secs(10),
        half_close: Duration::from_secs(10),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    let result = with_timeout(
        Duration::from_secs(2),
        forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        ),
    )
    .await
    .expect("forward_bidirectional must return within 2 seconds, not spin");

    match result {
        Err(ForwardError::WriteZero { remaining, .. }) => assert!(remaining > 0),
        other => panic!("expected ForwardError::WriteZero, got {other:?}"),
    }

    client_task.abort();
}

#[tokio::test]
async fn client_fin_flushes_pending_upstream_bytes() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let payload = pattern_bytes(100_000, 0x11);

    let (mut client_near, mut client_far) = tcp_pair().await.unwrap();
    let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();

    shutdown_write(&mut client_far).await.unwrap();

    let upstream_payload = payload.clone();
    let upstream_task = tokio::spawn(async move {
        let mut upstream_far = upstream_far;
        write_all_via(&mut upstream_far, &upstream_payload)
            .await
            .unwrap();
        // Keep `upstream_far` alive (not shut down, not dropped) for the rest of
        // the test, proving the client side is not truncated by an early
        // upstream-side close.
        std::future::pending::<()>().await;
    });

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_secs(20),
        half_close: Duration::from_secs(20),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    let forward_task = tokio::spawn(async move {
        forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        )
        .await
    });

    let received = with_timeout(
        Duration::from_secs(5),
        read_exact_n(&mut client_far, payload.len()),
    )
    .await
    .expect("must receive the full payload within 5 seconds")
    .unwrap();
    assert_eq!(received, payload);

    forward_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn half_close_timeout_fires() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let (mut client_near, mut client_far) = tcp_pair().await.unwrap();
    let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();
    let _upstream_far = upstream_far;

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_secs(20),
        half_close: Duration::from_millis(50),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    let forward_task = tokio::spawn(async move {
        forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        )
        .await
    });

    // Neither direction has reached end of file yet: both `src_eof` flags are
    // false, which is EQUAL, not different. Holding here for longer than
    // `half_close` before the client ever sends FIN proves the half-close
    // timer is armed on the transition to exactly one side finishing, not
    // merely because the two `src_eof` flags happen to agree (which they also
    // do, the other way, from the moment the connection opens).
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !forward_task.is_finished(),
        "the half-close timer must not fire while neither side has reached end of file"
    );

    shutdown_write(&mut client_far).await.unwrap();

    let result = with_timeout(Duration::from_secs(2), forward_task)
        .await
        .expect("must resolve within 2 seconds")
        .expect("forward task must not panic or be aborted");

    let (_stats, reason) = result.unwrap();
    assert_eq!(reason, EndReason::HalfCloseTimeout);
}

#[tokio::test]
async fn idle_timeout_fires_and_is_rearmed_on_progress() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let (mut client_near, mut client_far) = tcp_pair().await.unwrap();
    let (upstream_near, upstream_far) = tcp_pair().await.unwrap();
    let _upstream_far = upstream_far;

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_millis(100),
        half_close: Duration::from_secs(20),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    let forward_task = tokio::spawn(async move {
        let mut upstream_near = upstream_near;
        forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        )
        .await
    });

    for _ in 0..10 {
        write_all_via(&mut client_far, b"x").await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    assert!(
        !forward_task.is_finished(),
        "the loop must still be running while progress keeps arriving"
    );

    let (_stats, reason) = with_timeout(Duration::from_secs(1), forward_task)
        .await
        .expect("must finish within 1 second once progress stops")
        .expect("forward task must not panic or be aborted")
        .unwrap();
    assert_eq!(reason, EndReason::IdleTimeout);
}

#[tokio::test]
async fn closing_phase_ends_the_loop() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let mut rng = irontraffic_rand::Rng::from_seed(123);
    let mut payload = vec![0_u8; 8 * 1024 * 1024];
    rng.fill_bytes(&mut payload);

    let (client_near, client_far) = tcp_pair().await.unwrap();
    let (upstream_near, upstream_far) = tcp_pair().await.unwrap();
    // Drain `upstream_far` in the background: nothing here inspects what
    // arrives, but it MUST be read or the OS receive buffer fills and
    // `upstream_near`'s writes (the c2u direction) block on real backpressure
    // forever, which would starve the loop of the very re-polls this test
    // depends on to ever notice `begin_closing()`.
    let _drain_upstream = tokio::spawn(collect_all(upstream_far));
    // Throttled so the 8 MiB transfer is still active well past the 10
    // millisecond mark below: an unthrottled in-process loopback transfer can
    // finish before `begin_closing()` is even called, which would prove
    // nothing about the closing phase interrupting an in-flight stream. This
    // is the c2u direction's DESTINATION, so throttling its write side is
    // what actually paces client-to-upstream delivery.
    let mut upstream_near = ThrottledTransport::new(upstream_near, 4096, Duration::from_millis(1));

    let client_task = tokio::spawn(drive_far_end(client_far, payload));

    let (controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_secs(20),
        half_close: Duration::from_secs(20),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    let forward_task = tokio::spawn(async move {
        let mut client_near = client_near;
        forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    controller.begin_closing();

    let (_stats, reason) = with_timeout(Duration::from_secs(2), forward_task)
        .await
        .expect("must finish within 2 seconds")
        .expect("forward task must not panic or be aborted")
        .unwrap();
    assert_eq!(reason, EndReason::Closing);

    client_task.abort();
}

#[tokio::test]
async fn byte_cap_ends_the_direction() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let payload = pattern_bytes(4096, 0x77);

    let (mut client_near, client_far) = tcp_pair().await.unwrap();
    let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();

    let client_task = tokio::spawn(drive_far_end(client_far, payload.clone()));
    let upstream_task = tokio::spawn(collect_all(upstream_far));

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_secs(10),
        half_close: Duration::from_secs(10),
        max_bytes_per_direction: Some(1000),
        max_lifetime: None,
    };

    let (stats, reason) = with_timeout(
        Duration::from_secs(5),
        forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        ),
    )
    .await
    .expect("must finish within 5 seconds")
    .unwrap();

    assert_eq!(reason, EndReason::ByteCap);
    assert!(stats.client_to_upstream >= 1000);
    assert_eq!(
        stats.client_to_upstream,
        u64::try_from(payload.len()).unwrap()
    );

    let received = with_timeout(Duration::from_secs(2), upstream_task)
        .await
        .expect("upstream side must observe a clean end, not hang")
        .unwrap()
        .unwrap();
    assert_eq!(
        received, payload,
        "upstream must receive the whole payload, not a truncated prefix, proving step 5 ran"
    );

    client_task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn loop_yields_to_other_tasks() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let mut rng = irontraffic_rand::Rng::from_seed(55);
    let mut payload = vec![0_u8; 8 * 1024 * 1024];
    rng.fill_bytes(&mut payload);

    let (client_near, client_far) = tcp_pair().await.unwrap();
    let (upstream_near, mut upstream_far) = tcp_pair().await.unwrap();
    shutdown_write(&mut upstream_far).await.unwrap();
    // Drain in the background: `upstream_far`'s write side is already shut
    // down (so u2c is trivial), but its READ side still receives every byte
    // the c2u direction forwards, and leaving that unread would fill the OS
    // receive buffer and block `upstream_near`'s writes on real backpressure
    // forever once the 8 MiB payload exceeds it.
    let _drain_upstream = tokio::spawn(collect_all(upstream_far));
    // `MAX_PUMP_ROUNDS` counts calls to `pump`, one per direction per outer
    // round; a successful read always returns control to the outer loop (step
    // 4's `Filled(n)` arm), but a partial write is resumed INSIDE `pump`'s own
    // while loop and never costs an extra round. So it is the READ side that
    // must be capped small to force many outer rounds: an unthrottled 32 KiB
    // read per chunk needs only 256 rounds for 8 MiB, which self-yields about
    // 32 times, short of the 100 this test requires, not because yielding is
    // broken but because a transfer this coarse barely needs to yield at all.
    let mut client_near =
        ThrottledTransport::new(client_near, usize::MAX, Duration::ZERO).with_read_cap(1024);
    let mut upstream_near = ThrottledTransport::new(upstream_near, 512, Duration::ZERO);

    let client_task = tokio::spawn(drive_far_end(client_far, payload.clone()));

    let counter = Arc::new(AtomicU64::new(0));
    let counter2 = Arc::clone(&counter);
    let yield_task = tokio::spawn(async move {
        loop {
            counter2.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
        }
    });

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_secs(60),
        half_close: Duration::from_secs(60),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    // Wrapped in `unconstrained`: tokio's OWN cooperative budget would otherwise
    // force a yield roughly every 128 polls on its own, which is enough on its
    // own to keep `yield_task` running and would make this test pass even if
    // `MAX_PUMP_ROUNDS` itself were broken. `unconstrained` disables that budget
    // for every poll inside this future, including the socket reads and writes
    // `forward_bidirectional` drives, so the only thing that can make this poll
    // return `Pending` mid-transfer is the loop's own self-wake.
    let (stats, reason) = tokio::task::coop::unconstrained(forward_bidirectional(
        &mut client_near,
        &mut upstream_near,
        &timer,
        &token,
        &limits,
    ))
    .await
    .unwrap();
    yield_task.abort();

    assert_eq!(reason, EndReason::BothEof);
    assert_eq!(
        stats.client_to_upstream,
        u64::try_from(payload.len()).unwrap()
    );
    let seen = counter.load(Ordering::Relaxed);
    assert!(seen >= 100, "yield counter only advanced {seen}");

    let received = client_task.await.unwrap().unwrap();
    assert!(received.is_empty());
}

#[tokio::test]
async fn lifetime_cap_ends_a_progressing_connection() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let (mut client_near, mut client_far) = tcp_pair().await.unwrap();
    let (mut upstream_near, upstream_far) = tcp_pair().await.unwrap();
    let upstream_task = tokio::spawn(collect_all(upstream_far));

    let writer_task = tokio::spawn(async move {
        loop {
            if write_all_via(&mut client_far, b"z").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    });

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_millis(500),
        half_close: Duration::from_secs(5),
        max_bytes_per_direction: None,
        max_lifetime: Some(Duration::from_millis(150)),
    };

    let (stats, reason) = with_timeout(
        Duration::from_secs(2),
        forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        ),
    )
    .await
    .expect("must finish within 2 seconds")
    .unwrap();

    assert_eq!(reason, EndReason::LifetimeCap);
    assert!(
        stats.client_to_upstream >= 3,
        "client_to_upstream = {}",
        stats.client_to_upstream
    );

    writer_task.abort();
    // Simulate the eventual caller closing the connection once
    // `forward_bidirectional` returns, so the upstream side observes the clean
    // end of the bytes already forwarded.
    drop(upstream_near);

    let received = with_timeout(Duration::from_secs(2), upstream_task)
        .await
        .expect("upstream side must observe a clean end")
        .unwrap()
        .unwrap();
    assert_eq!(
        u64::try_from(received.len()).unwrap(),
        stats.client_to_upstream,
        "upstream must receive every byte already forwarded, not a truncated stream"
    );
}

#[tokio::test]
async fn no_lifetime_cap_means_no_lifetime_bound() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let (mut client_near, mut client_far) = tcp_pair().await.unwrap();
    let (upstream_near, upstream_far) = tcp_pair().await.unwrap();
    let _upstream_far = upstream_far;

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let writer_task = tokio::spawn(async move {
        while !stop2.load(Ordering::Relaxed) {
            if write_all_via(&mut client_far, b"z").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    });

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = ForwardLimits {
        idle: Duration::from_millis(200),
        half_close: Duration::from_secs(5),
        max_bytes_per_direction: None,
        max_lifetime: None,
    };

    let forward_task = tokio::spawn(async move {
        let mut upstream_near = upstream_near;
        forward_bidirectional(
            &mut client_near,
            &mut upstream_near,
            &timer,
            &token,
            &limits,
        )
        .await
    });

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !forward_task.is_finished(),
        "with no max_lifetime, steady progress must keep the connection alive past 1 second"
    );

    stop.store(true, Ordering::Relaxed);

    let (_stats, reason) = with_timeout(Duration::from_secs(2), forward_task)
        .await
        .expect("must finish once progress stops")
        .expect("forward task must not panic or be aborted")
        .unwrap();
    assert_eq!(reason, EndReason::IdleTimeout);

    writer_task.abort();
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn oversized_write_return_is_clamped() {
    let _guard = BUFFER_STATS_LOCK.lock().await;
    let payload = pattern_bytes(5000, 0x9C);

    let mut client = irontraffic_dataplane::duplex::DuplexTransport::new(payload.clone());
    let mut upstream = irontraffic_dataplane::duplex::DuplexTransport::new(Vec::new())
        .with_overreport_on_first_write(1000);

    let (_controller, token) = ShutdownController::new();
    let timer = SystemTimer::new();
    let limits = default_limits();

    let result = with_timeout(
        Duration::from_secs(2),
        forward_bidirectional(&mut client, &mut upstream, &timer, &token, &limits),
    )
    .await
    .expect("must not hang");

    match result {
        Ok((stats, _reason)) => {
            assert_eq!(
                stats.client_to_upstream,
                u64::try_from(payload.len()).unwrap()
            );
            assert_eq!(
                upstream.written(),
                payload,
                "bytes delivered must equal bytes sent even when the destination lies about \
                 how many it accepted"
            );
        }
        Err(ForwardError::WriteZero { .. }) => {}
        Err(other) => panic!("expected Ok or WriteZero, got {other:?}"),
    }
}

fn chunk_script_strategy() -> impl Strategy<Value = Vec<(Vec<u8>, u64)>> {
    prop::collection::vec(
        (prop::collection::vec(any::<u8>(), 0..=4096), 0..=2_u64),
        0..=64,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn prop_forwarding_is_byte_identity(
        client_chunks in chunk_script_strategy(),
        upstream_chunks in chunk_script_strategy(),
        write_cap in 1_usize..=4096,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building a current-thread runtime must not fail");

        let client_sent: Vec<u8> = client_chunks.iter().flat_map(|(c, _)| c.iter().copied()).collect();
        let upstream_sent: Vec<u8> = upstream_chunks.iter().flat_map(|(c, _)| c.iter().copied()).collect();

        // The whole case is bounded so a mutation or a real regression that makes the
        // loop hang turns into a fast, shrinkable proptest failure instead of a run
        // that never returns.
        let outcome = rt.block_on(with_timeout(Duration::from_secs(30), async {
            let _guard = BUFFER_STATS_LOCK.lock().await;

            let (client_near, client_far) = tcp_pair().await.expect("tcp_pair");
            let (upstream_near, upstream_far) = tcp_pair().await.expect("tcp_pair");

            let mut client_near = ThrottledTransport::new(client_near, write_cap, Duration::ZERO);
            let mut upstream_near = ThrottledTransport::new(upstream_near, write_cap, Duration::ZERO);

            let client_task = tokio::spawn(drive_far_end_chunks(client_far, client_chunks));
            let upstream_task = tokio::spawn(drive_far_end_chunks(upstream_far, upstream_chunks));

            let (_controller, token) = ShutdownController::new();
            let timer = SystemTimer::new();
            let limits = ForwardLimits {
                idle: Duration::from_secs(10),
                half_close: Duration::from_secs(10),
                max_bytes_per_direction: None,
                max_lifetime: None,
            };

            let forward_result =
                forward_bidirectional(&mut client_near, &mut upstream_near, &timer, &token, &limits)
                    .await;
            let client_far_received = client_task.await;
            let upstream_far_received = upstream_task.await;
            (forward_result, client_far_received, upstream_far_received)
        }))
        .expect("one forwarding case must not hang past 30 seconds");

        let (forward_result, client_far_received, upstream_far_received) = outcome;
        let (stats, reason) = forward_result.expect("forwarding must not fail for a well-behaved pair");
        let client_far_received = client_far_received
            .expect("client task must not panic")
            .expect("client far end io");
        let upstream_far_received = upstream_far_received
            .expect("upstream task must not panic")
            .expect("upstream far end io");

        prop_assert_eq!(reason, EndReason::BothEof);
        prop_assert_eq!(stats.client_to_upstream, u64::try_from(client_sent.len()).unwrap());
        prop_assert_eq!(stats.upstream_to_client, u64::try_from(upstream_sent.len()).unwrap());
        prop_assert_eq!(client_far_received, upstream_sent);
        prop_assert_eq!(upstream_far_received, client_sent);
    }
}
