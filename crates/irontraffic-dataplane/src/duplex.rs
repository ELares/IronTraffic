// SPDX-License-Identifier: MIT OR Apache-2.0

//! An in-memory [`irontraffic_io::Transport`] double, feature-gated behind
//! `test-support` and used only by the benchmarks, the fuzz target, and the
//! `oversized_write_return_is_clamped` integration test.
//!
//! The two `VecDeque<u8>` buffers below are NOT a data-plane accumulation: this type
//! is a test fixture, it is compiled out of every production build by the
//! `test-support` feature gate, and the `no-unbounded-channel` rule does not apply to
//! it. [`DuplexTransport`] performs no syscalls, so a benchmark over it measures the
//! forwarding loop rather than the kernel.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A scripted, in-memory transport half: preloaded bytes to read, a log of bytes
/// written, and a policy that can cap one write, alternate `Pending`, and lie about
/// how many bytes one write accepted.
pub struct DuplexTransport {
    /// Bytes waiting to be read, consumed from the front by `poll_read`.
    inbound: VecDeque<u8>,
    /// Bytes accepted by `poll_write`, in write order, for the caller to inspect.
    outbound: VecDeque<u8>,
    /// Bytes accepted per successful `poll_write` call.
    write_cap: usize,
    /// Bytes delivered per successful `poll_read` call.
    read_cap: usize,
    /// `poll_read` and `poll_write` share one counter and return `Pending` every this
    /// many calls. `0` means never.
    pending_every_n: usize,
    poll_count: usize,
    /// Bytes delivered so far by `poll_read`.
    delivered: usize,
    /// Once `inbound` is empty and `delivered` reaches this count, `poll_read`
    /// reports end of file. `None` means a peer that stalls rather than closing:
    /// `poll_read` returns `Pending` forever once `inbound` is empty.
    close_after: Option<usize>,
    /// Consumed by the next successful `poll_write`: that call reports this many
    /// more bytes accepted than it actually stored.
    overreport_next_write_by: usize,
    addr: SocketAddr,
}

impl DuplexTransport {
    /// A transport preloaded with `inbound`, reporting end of file as soon as it is
    /// exhausted. No write cap, no scripted `Pending`.
    #[must_use]
    pub fn new(inbound: Vec<u8>) -> Self {
        let close_after = Some(inbound.len());
        Self {
            inbound: VecDeque::from(inbound),
            outbound: VecDeque::new(),
            write_cap: usize::MAX,
            read_cap: usize::MAX,
            pending_every_n: 0,
            poll_count: 0,
            delivered: 0,
            close_after,
            overreport_next_write_by: 0,
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }

    /// Caps how many bytes one `poll_write` call accepts.
    #[must_use]
    pub fn with_write_cap(mut self, write_cap: usize) -> Self {
        self.write_cap = write_cap;
        self
    }

    /// Caps how many bytes one `poll_read` call delivers, for a benchmark or test
    /// that needs many small reads instead of one big one.
    #[must_use]
    pub fn with_read_cap(mut self, read_cap: usize) -> Self {
        self.read_cap = read_cap;
        self
    }

    /// Returns `Poll::Pending` every `n`th poll (read and write share one counter).
    /// `0` means never.
    #[must_use]
    pub fn with_pending_every_n(mut self, n: usize) -> Self {
        self.pending_every_n = n;
        self
    }

    /// Once `inbound` is exhausted, return `Pending` forever instead of reporting end
    /// of file: a peer that stalls rather than closing.
    #[must_use]
    pub fn never_closes(mut self) -> Self {
        self.close_after = None;
        self
    }

    /// On the first successful (non-`Pending`) `poll_write` only, reports `extra`
    /// more bytes accepted than were actually stored, to exercise the clamp on a
    /// lying `Write` implementation.
    #[must_use]
    pub fn with_overreport_on_first_write(mut self, extra: usize) -> Self {
        self.overreport_next_write_by = extra;
        self
    }

    /// Every byte accepted by `poll_write`, in order.
    #[must_use]
    pub fn written(&self) -> Vec<u8> {
        self.outbound.iter().copied().collect()
    }

    /// Whether the scripted policy forces this poll to `Pending`.
    fn is_throttled_pending(&mut self) -> bool {
        if self.pending_every_n == 0 {
            return false;
        }
        self.poll_count = self.poll_count.wrapping_add(1);
        self.poll_count.is_multiple_of(self.pending_every_n)
    }
}

impl irontraffic_io::Read for DuplexTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: irontraffic_io::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.is_throttled_pending() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if this.inbound.is_empty() {
            if this.close_after.is_some_and(|n| this.delivered >= n) {
                return Poll::Ready(Ok(())); // 0 bytes filled: end of file
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = this.inbound.len().min(buf.remaining()).min(this.read_cap);
        let slice = this.inbound.make_contiguous();
        if let Some(front) = slice.get(..n) {
            buf.put_slice(front);
        }
        this.inbound.drain(..n);
        this.delivered = this.delivered.saturating_add(n);
        Poll::Ready(Ok(()))
    }
}

impl irontraffic_io::Write for DuplexTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.is_throttled_pending() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let cap = this.write_cap.min(buf.len());
        this.outbound.extend(buf.iter().take(cap).copied());
        let lie = this.overreport_next_write_by;
        this.overreport_next_write_by = 0;
        Poll::Ready(Ok(cap.saturating_add(lie)))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl irontraffic_io::Transport for DuplexTransport {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }

    #[cfg(unix)]
    fn as_raw_fd_opt(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}
