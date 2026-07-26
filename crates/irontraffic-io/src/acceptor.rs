// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `Acceptor` trait and its TCP implementation.

use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};

use crate::transport::{TcpTransport, Transport};

/// A source of inbound connections.
pub trait Acceptor: Send + Sync + 'static {
    /// The transport this acceptor produces.
    type Io: Transport;

    /// Polls for one inbound connection.
    ///
    /// At most one task may poll a given acceptor at a time. The reactor
    /// registration behind a listener keeps a single waker slot per readiness
    /// interest: a second concurrent poller overwrites the first's waker, and
    /// the first is never woken again once it has returned `Pending`. Sharing
    /// one acceptor with a non-polling consumer (a status endpoint calling
    /// `local_addr`) is fine; sharing it between two accept tasks silently
    /// starves all but one of them. Fan accept load out across cores with one
    /// listener per shard (bound with `SO_REUSEPORT`), each wrapped in its own
    /// acceptor, never one acceptor `Arc`-cloned onto more than one polling
    /// task.
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Self::Io, SocketAddr)>>;

    /// The bound address, captured at construction.
    fn local_addr(&self) -> SocketAddr;
}

/// A TCP acceptor over an already-bound listener.
#[derive(Debug)]
pub struct TcpAcceptor {
    inner: tokio::net::TcpListener,
    local: SocketAddr,
}

impl TcpAcceptor {
    /// Takes ownership of a bound listener, sets it non-blocking, and registers it
    /// with the current reactor.
    ///
    /// # Errors
    /// Returns an error if the listener cannot be made non-blocking, its address
    /// cannot be read, or there is no reactor on the current thread.
    ///
    /// # Panics
    /// Panics if the current thread has a tokio runtime but that runtime was
    /// built without `enable_io()`. `tokio::runtime::Handle::try_current()` (used
    /// to detect the no-runtime-at-all case below) only reports whether a
    /// runtime is driving the thread, not which drivers it enabled, and tokio
    /// has no public API to ask that without triggering the same panic
    /// `tokio::net::TcpListener::from_std` would raise internally. Call this
    /// only from a runtime built with `enable_io()` (or `enable_all()`).
    pub fn from_std(listener: std::net::TcpListener) -> io::Result<Self> {
        // `tokio::net::TcpListener::from_std` PANICS, rather than returning an
        // error, when there is no reactor driving the current thread (verified
        // against tokio 1.53: `Handle::current()` inside its reactor
        // registration path calls `panic!`). That contradicts this function's
        // own `# Errors` doc above, so guard with the non-panicking
        // `Handle::try_current()` and map its `Err` to an `io::Error` before
        // ever reaching `tokio::net::TcpListener::from_std`.
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other(
                "TcpAcceptor::from_std requires a tokio runtime driving the current thread",
            ));
        }
        listener.set_nonblocking(true)?;
        let local = listener.local_addr()?;
        let inner = tokio::net::TcpListener::from_std(listener)?;
        Ok(Self { inner, local })
    }
}

/// The original error from configuring an accepted socket, exposed as a source so
/// operators can still see why a connection was aborted.
#[derive(Debug)]
struct ConnectionSetupError(io::Error);

impl std::fmt::Display for ConnectionSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "accepted connection setup failed: {}", self.0)
    }
}

impl std::error::Error for ConnectionSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Re-kinds a per-connection setup error to `ConnectionAborted`, preserving the
/// original as the `source`, so the accept loop treats it as one gone
/// connection rather than a fatal listener error. The single mapping site
/// tests assert against, so a future edit that weakens or removes the mapping
/// (for example passing the error through unchanged) fails the test named
/// after it rather than silently shipping.
fn map_setup_error(e: io::Error) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, ConnectionSetupError(e))
}

/// Applies [`map_setup_error`] to the `Err` arm of a `TcpTransport::from_tokio`
/// result, leaving `Ok` untouched. Split out of `wrap_accepted_stream` so a
/// test can drive the exact expression production code evaluates with a
/// synthetic `Err`, instead of needing a live socket to actually fail.
///
/// That split matters because a live socket essentially never does fail here:
/// `getpeername` / `setsockopt(TCP_NODELAY)` / `getsockname` read state cached
/// on the file descriptor and only error for a closed or never-connected fd,
/// not for "the peer is gone". A peer that shuts down cleanly, or is driven
/// all the way to a fully closed connection on both ends, still leaves those
/// three calls returning `Ok` for as long as our own fd stays open (checked
/// against this platform directly, not assumed). A test that waited for a
/// genuine failure from `TcpTransport::from_tokio` to prove the mapping would
/// therefore pass or fail by accident of platform and timing rather than by
/// asserting the mapping is wired up, which is the shape of test that let a
/// missing `.map_err` ship unnoticed in the first place.
fn map_setup_result(result: io::Result<TcpTransport>) -> io::Result<TcpTransport> {
    result.map_err(map_setup_error)
}

/// Wraps an accepted stream, mapping a per-connection setup failure into
/// `ConnectionAborted` so the accept loop cannot be driven to stop a shard by
/// a peer that resets immediately after the handshake.
fn wrap_accepted_stream(stream: tokio::net::TcpStream) -> io::Result<TcpTransport> {
    map_setup_result(TcpTransport::from_tokio(stream))
}

impl Acceptor for TcpAcceptor {
    type Io = TcpTransport;

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Self::Io, SocketAddr)>> {
        match self.inner.poll_accept(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok((stream, peer))) => match wrap_accepted_stream(stream) {
                Ok(t) => Poll::Ready(Ok((t, peer))),
                Err(e) => Poll::Ready(Err(e)),
            },
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::net::Shutdown;

    use super::*;

    #[test]
    fn from_std_outside_runtime_is_err_not_panic() {
        // `tokio::net::TcpListener::from_std` panics (not errors) when there is
        // no reactor on the current thread (tokio 1.53). Run on a fresh thread,
        // mirroring `spawner_current_outside_runtime_is_err` in `spawn.rs`, so
        // no other test's ambient tokio runtime can leak into this one and hide
        // a regression.
        let result = std::thread::spawn(|| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            TcpAcceptor::from_std(listener)
        })
        .join()
        .unwrap();
        assert!(
            result.is_err(),
            "from_std must return Err, not panic, with no runtime driving the thread"
        );
    }

    #[tokio::test]
    async fn per_connection_setup_failure_is_connection_aborted() {
        // Bind a listener and accept a std socket, then close the client side so
        // getpeername on the accepted stream may fail (or not, depending on the
        // platform). If it does fail, assert the mapping on that real error
        // below. Empirically (checked on this platform with the client
        // synchronised past shutdown-and-drop, and again with the accepted
        // side driven all the way to a fully closed connection) it does not
        // fail: getpeername/setsockopt/getsockname read state cached on the
        // fd and keep succeeding as long as our own fd is open, regardless of
        // peer state. That is why the second half of this test does not wait
        // on platform behaviour at all.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            let s = std::net::TcpStream::connect(addr).unwrap();
            // Close the socket immediately after connect to make the accepted
            // socket's peer state uncertain.
            s.shutdown(Shutdown::Both).unwrap();
            drop(s);
        });

        let (stream, _peer) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let tokio_stream = tokio::net::TcpStream::from_std(stream).unwrap();
        let result = wrap_accepted_stream(tokio_stream);
        client.join().unwrap();

        if let Err(e) = result {
            // The platform actually produced a per-connection setup failure on
            // this run; it must already carry the mapping.
            assert_eq!(e.kind(), io::ErrorKind::ConnectionAborted);
            assert!(e.source().is_some());
        }

        // Deterministic, platform-independent proof that the mapping is wired
        // up: `wrap_accepted_stream` is exactly
        // `map_setup_result(TcpTransport::from_tokio(stream))`, so drive
        // `map_setup_result`, the SAME expression production code evaluates,
        // with a synthetic `Err` of the shape `TcpTransport::from_tokio` would
        // produce if getpeername or set_nodelay ever failed. This is what
        // fails if `map_setup_result` (or the `.map_err(map_setup_error)`
        // inside it) is ever deleted or bypassed, whether or not a live
        // socket happens to fail on a given run: this is the test that keeps
        // a connect-and-reset storm from being able to stop a shard.
        let synthetic = io::Error::new(io::ErrorKind::NotConnected, "synthetic peer gone");
        let mapped = map_setup_result(Err(synthetic)).expect_err("Err must stay Err");
        assert_eq!(mapped.kind(), io::ErrorKind::ConnectionAborted);
        assert!(mapped.source().is_some());
    }
}
