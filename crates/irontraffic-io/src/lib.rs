// SPDX-License-Identifier: MIT OR Apache-2.0

//! The transport seam. This crate is the ONLY place in the workspace permitted to
//! name `tokio`, enforced by the `transport-seam` rule in `scripts/invariant-lints.sh`.

#![deny(missing_docs)]

pub mod acceptor;
pub mod buffer;
pub mod shutdown;
pub mod spawn;
pub mod timer;
pub mod transport;

pub use acceptor::{Acceptor, TcpAcceptor};
pub use buffer::{
    BufPool, CHUNK_SIZE, DEFAULT_POOL_CHUNKS, PoolStats, PooledBuf, acquire, compact_exact, stats,
};
pub use hyper::rt::{Read, ReadBuf, ReadBufCursor, Sleep, Timer, Write};
pub use shutdown::{Phase, ShutdownController, ShutdownToken, accept_or_drain};
pub use spawn::{NoRuntime, Spawner, TaskError, TaskHandle};
pub use timer::{SystemTimer, TimedOut, sleep, with_timeout};
pub use transport::{TcpTransport, Transport};
