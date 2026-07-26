// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `Transport` trait and its TCP implementation.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper_util::rt::TokioIo;

/// A bidirectional byte stream with addressing, owned by exactly one task.
pub trait Transport: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static {
    /// The remote address, captured at construction.
    ///
    /// # Errors
    /// Returns the error the platform reported when the address was captured.
    fn peer_addr(&self) -> io::Result<SocketAddr>;

    /// The local address, captured at construction.
    ///
    /// # Errors
    /// Returns the error the platform reported when the address was captured.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// The raw file descriptor, when this transport has exactly one.
    ///
    /// Used ONLY by the future `splice(2)` L4 fast path and by socket option
    /// setters that `socket2` does not cover. Never read or write through it.
    /// Returns `None` for transports without a single descriptor, such as a
    /// TLS-wrapped stream.
    ///
    /// The returned number is valid only for as long as the `&self` borrow. Do
    /// NOT store it in a struct, send it to another task, or use it after the
    /// transport is dropped: the kernel reuses descriptor numbers immediately, so
    /// a stale descriptor names whichever connection was accepted next, and
    /// reading or writing through it moves one client's bytes onto another
    /// client's socket. Every use must be a syscall made inside the same
    /// expression that obtained the number.
    #[cfg(unix)]
    fn as_raw_fd_opt(&self) -> Option<std::os::fd::RawFd>;
}

/// A TCP stream with `TCP_NODELAY` set and its addresses captured.
#[derive(Debug)]
pub struct TcpTransport {
    io: TokioIo<tokio::net::TcpStream>,
    peer: SocketAddr,
    local: SocketAddr,
}

const _: () = assert!(std::mem::size_of::<TcpTransport>() <= 128);

impl TcpTransport {
    /// Wraps an accepted or connected stream, setting `TCP_NODELAY` and capturing
    /// both addresses.
    ///
    /// # Errors
    /// Returns an error if `TCP_NODELAY` cannot be set or either address cannot be
    /// read. A socket that cannot be configured is never served.
    pub fn from_tokio(stream: tokio::net::TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let peer = stream.peer_addr()?;
        let local = stream.local_addr()?;
        Ok(Self {
            io: TokioIo::new(stream),
            peer,
            local,
        })
    }
}

impl hyper::rt::Read for TcpTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for TcpTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl Transport for TcpTransport {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    #[cfg(unix)]
    fn as_raw_fd_opt(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        Some(self.io.inner().as_raw_fd())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn nodelay_is_set_by_from_tokio() {
        // Wrap the CONNECTING side with Nagle explicitly enabled first, so the
        // assertion proves `from_tokio` turned Nagle off rather than observing a
        // platform default that happens to agree. That is what the issue asks
        // for, and the distinction is not academic: on an ACCEPTED socket the
        // default differs between platforms, so the earlier version of this test
        // asserted the right thing for the wrong reason on Linux.
        //
        // It was also racy. The client ran on its own thread and wrote, then
        // shut down, while the main thread inspected the option and dropped the
        // transport. When the drop won the race the peer saw a reset, the
        // client's `shutdown` returned ENOTCONN, and the thread panicked, taking
        // `join().unwrap()` with it. Linux resets faster than macOS, which is
        // why this only ever failed in CI. There is no traffic here now: the
        // peer socket is accepted and simply held alive, so there is nothing
        // left to race.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepter = std::thread::spawn(move || listener.accept().unwrap());

        let client = std::net::TcpStream::connect(addr).unwrap();
        client.set_nodelay(false).unwrap();
        assert!(
            !client.nodelay().unwrap(),
            "precondition: Nagle must be ON before from_tokio, or this test proves nothing"
        );
        client.set_nonblocking(true).unwrap();

        let tokio_stream = tokio::net::TcpStream::from_std(client).unwrap();
        let transport = TcpTransport::from_tokio(tokio_stream).unwrap();
        assert!(transport.io.inner().nodelay().unwrap());

        // Hold the accepted peer until the assertion is done, then drop both.
        let _peer = accepter.join().unwrap();
    }
}
