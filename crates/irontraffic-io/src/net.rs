// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one dial primitive. `tokio::net::TcpStream::connect` may be named only
//! here; every caller in the workspace reaches it through [`connect_tcp`].

use std::io;
use std::net::SocketAddr;

use crate::transport::TcpTransport;

/// Dials `addr` and returns a transport with `TCP_NODELAY` set.
///
/// # Errors
/// Returns the operating system error unchanged; classification is the caller's job.
pub async fn connect_tcp(addr: SocketAddr) -> io::Result<TcpTransport> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    TcpTransport::from_tokio(stream)
}
