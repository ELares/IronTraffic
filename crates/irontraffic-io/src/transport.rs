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
    use std::io::Write;

    use super::*;

    #[tokio::test]
    async fn nodelay_is_set_by_from_tokio() {
        // Bind a loopback listener and connect a plain std socket so we can
        // hand the accepted tokio stream to TcpTransport and inspect the option.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        let client = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            // A freshly connected std socket has Nagle enabled; from_tokio must turn it off.
            s.write_all(b"x").unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            // Keep the socket alive until the server has inspected the option.
            let _ = done_rx.recv();
        });

        let (stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let tokio_stream = tokio::net::TcpStream::from_std(stream).unwrap();
        let transport = TcpTransport::from_tokio(tokio_stream).unwrap();
        let nodelay = transport.io.inner().nodelay();
        assert!(nodelay.unwrap());
        drop(transport);
        done_tx.send(()).unwrap();
        client.join().unwrap();
    }
}
