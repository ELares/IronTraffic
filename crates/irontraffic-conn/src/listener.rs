// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ShardedListener`, its bind report, and its error type.

use std::net::{SocketAddr, TcpListener};

use irontraffic_config::{Backlog, BindAddr, ListenerName};
use irontraffic_io::TcpAcceptor;
use irontraffic_io::sys::{BindError, Caps, SockOpts, bind_listener};

/// What a bind attempt actually produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerReport {
    /// Shards asked for, normally the worker count.
    pub shards_requested: usize,
    /// Shards actually bound: equal to `shards_requested` with `SO_REUSEPORT`, or 1
    /// without it.
    pub shards_bound: usize,
    /// Whether `SO_REUSEPORT` was applied.
    pub reuseport: bool,
    /// The backlog value `bind_listener` actually applied.
    pub backlog: u32,
    /// `net.core.somaxconn` is below the requested backlog, so the kernel clamped it.
    pub backlog_may_be_clamped: bool,
}

/// A listener could not be bound or registered.
#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    /// `bind` was asked for zero shards.
    #[error("listener {name}: shard count must be at least 1")]
    ZeroShards {
        /// The listener's configured name.
        name: String,
    },
    /// A shard's socket could not be bound.
    #[error("listener {name}: failed to bind shard {shard} of {total} on {addr}: {source}")]
    Bind {
        /// The listener's configured name.
        name: String,
        /// The zero-based index of the shard that failed.
        shard: usize,
        /// The total number of shards being bound.
        total: usize,
        /// The address the shard tried to bind.
        addr: SocketAddr,
        /// The underlying bind failure.
        #[source]
        source: BindError,
    },
    /// The first shard bound but its local address could not be read back.
    #[error("listener {name}: bound {addr} but could not read the resolved address: {source}")]
    Resolve {
        /// The listener's configured name.
        name: String,
        /// The address that was bound.
        addr: SocketAddr,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// A shard's socket could not be registered with the reactor.
    #[error("listener {name}: failed to register shard {shard} with the reactor: {source}")]
    Register {
        /// The listener's configured name.
        name: String,
        /// The zero-based index of the shard that failed to register.
        shard: usize,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
}

/// One configured endpoint, bound as one socket per worker.
///
/// Holds only `std::net::TcpListener` values, so it can be constructed before a runtime
/// exists (`bind` performs only blocking syscalls) and turned into reactor-registered
/// acceptors once one does (`into_acceptors`).
#[derive(Debug)]
pub struct ShardedListener {
    name: ListenerName,
    bind: BindAddr,
    /// The port every shard actually bound, which differs from `bind` when the
    /// configured port was 0.
    resolved: SocketAddr,
    socks: Vec<TcpListener>,
    report: ListenerReport,
}

impl ShardedListener {
    /// Binds one socket per shard, all on the same resolved address.
    ///
    /// The first shard resolves the address (which matters when the configured port is
    /// 0); every later shard binds that resolved address, so all shards share one port.
    /// When `SO_REUSEPORT` is unavailable this binds exactly one socket and reports it,
    /// and the caller runs every accept task against that one acceptor: that is legal
    /// because `Acceptor::poll_accept` takes `&self`.
    ///
    /// `shards` is not clamped here. It is bounded by its only caller, which passes the
    /// derived worker count, itself capped at `irontraffic_runtime::MAX_WORKERS`. A
    /// second clamp would hide a caller bug rather than fix one.
    ///
    /// When `SO_REUSEPORT` is applied, another local process may join the group and take
    /// a share of the connections; on Linux that requires a matching effective UID, and
    /// on other platforms it may not. See the crate documentation.
    ///
    /// An older instance of this same process that also set `SO_REUSEPORT` can bind the
    /// same address successfully, and both processes then receive connections. That is
    /// the intended mechanism for a future rolling upgrade, and a footgun during a
    /// botched restart: this function does not and cannot detect which case it is.
    ///
    /// Performs only blocking syscalls and does not touch a reactor, so it may be called
    /// before a runtime exists.
    ///
    /// # Errors
    /// [`ListenError::ZeroShards`] for `shards == 0`; [`ListenError::Bind`] naming the
    /// shard index, the total, and the address; [`ListenError::Resolve`] when the bound
    /// address cannot be read. A partial failure closes every socket already bound.
    pub fn bind(
        name: &ListenerName,
        bind: BindAddr,
        shards: usize,
        reuseport_requested: bool,
        ipv6_only: bool,
        backlog: Backlog,
        caps: &Caps,
    ) -> Result<Self, ListenError> {
        if shards == 0 {
            return Err(ListenError::ZeroShards {
                name: name.to_string(),
            });
        }

        let want_reuseport = reuseport_requested && caps.reuse_port;
        let effective_shards = if want_reuseport { shards } else { 1 };
        let opts = SockOpts {
            reuse_port: want_reuseport,
            reuse_addr: true,
            backlog: backlog.get(),
            ipv6_only,
        };

        let mut socks: Vec<TcpListener> = Vec::with_capacity(effective_shards);

        // The first shard resolves the port: with a configured port of 0 the kernel
        // assigns an ephemeral one, and that ephemeral port is what every later shard
        // must join.
        let (first_listener, first_outcome) = bind_listener(bind.socket_addr(), &opts, caps)
            .map_err(|source| ListenError::Bind {
                name: name.to_string(),
                shard: 0,
                total: effective_shards,
                addr: bind.socket_addr(),
                source,
            })?;
        let resolved = first_listener
            .local_addr()
            .map_err(|source| ListenError::Resolve {
                name: name.to_string(),
                addr: bind.socket_addr(),
                source,
            })?;
        socks.push(first_listener);

        // Every shard after the first binds `resolved`, not `bind`: binding shard 1 to
        // `bind` instead of `resolved` gives each shard a different ephemeral port when
        // the configured port is 0.
        for shard in 1..effective_shards {
            match bind_listener(resolved, &opts, caps) {
                Ok((sock, _out)) => socks.push(sock),
                Err(source) => {
                    drop(socks); // Vec::drop closes every socket already bound.
                    return Err(ListenError::Bind {
                        name: name.to_string(),
                        shard,
                        total: effective_shards,
                        addr: resolved,
                        source,
                    });
                }
            }
        }

        let report = ListenerReport {
            shards_requested: shards,
            shards_bound: effective_shards,
            reuseport: first_outcome.reuse_port_applied,
            backlog: first_outcome.backlog_requested,
            backlog_may_be_clamped: first_outcome.backlog_may_be_clamped,
        };

        if report.backlog_may_be_clamped {
            tracing::warn!(
                listener = %name,
                backlog = report.backlog,
                "requested backlog exceeds net.core.somaxconn and the kernel will clamp it"
            );
        }
        if reuseport_requested && !want_reuseport {
            tracing::warn!(
                listener = %name,
                "SO_REUSEPORT is unavailable; bound a single socket and will run all accept tasks against it"
            );
        }
        tracing::info!(
            listener = %name,
            addr = %resolved,
            shards = effective_shards,
            reuseport = report.reuseport,
            backlog = report.backlog,
            "listener bound"
        );

        Ok(Self {
            name: name.clone(),
            bind,
            resolved,
            socks,
            report,
        })
    }

    /// The configured name.
    #[must_use]
    pub fn name(&self) -> &ListenerName {
        &self.name
    }

    /// The address as configured, which may have port 0.
    #[must_use]
    pub fn configured_addr(&self) -> SocketAddr {
        self.bind.socket_addr()
    }

    /// The address actually bound, with the real port.
    #[must_use]
    pub fn resolved_addr(&self) -> SocketAddr {
        self.resolved
    }

    /// How many sockets are held.
    #[must_use]
    pub fn shards(&self) -> usize {
        self.socks.len()
    }

    /// What the bind produced.
    #[must_use]
    pub fn report(&self) -> ListenerReport {
        self.report
    }

    /// Registers every socket with the current reactor and returns one acceptor per
    /// shard, together with the report and the resolved address.
    ///
    /// Must be called from inside the data-plane runtime: registration needs a reactor.
    /// Calling this before a runtime exists (for example before `block_on`) produces
    /// [`ListenError::Register`] naming shard 0, rather than a panic.
    ///
    /// # Errors
    /// [`ListenError::Register`] naming the shard index. Sockets not yet converted are
    /// closed when the error returns.
    pub fn into_acceptors(
        self,
    ) -> Result<(Vec<TcpAcceptor>, ListenerReport, SocketAddr), ListenError> {
        let name = self.name.to_string();
        let mut out = Vec::with_capacity(self.socks.len());
        for (shard, sock) in self.socks.into_iter().enumerate() {
            match TcpAcceptor::from_std(sock) {
                Ok(acceptor) => out.push(acceptor),
                Err(source) => {
                    // `out` drops here, closing every acceptor already converted; the
                    // remainder of the `into_iter()` iterator drops too, closing every
                    // socket that was not yet reached.
                    return Err(ListenError::Register {
                        name,
                        shard,
                        source,
                    });
                }
            }
        }
        Ok((out, self.report, self.resolved))
    }
}

#[cfg(test)]
mod tests {
    use irontraffic_config::{Backlog, BindAddr, ListenerName};
    use irontraffic_io::sys::Caps;

    use super::{ListenError, ShardedListener};

    #[test]
    fn zero_shards_is_an_error() {
        let caps = Caps::probe();
        let name = ListenerName::try_from("zero-shards").expect("valid listener name");
        let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
        let backlog = Backlog::try_from(4096u32).expect("valid backlog");

        let result = ShardedListener::bind(&name, bind_addr, 0, true, false, backlog, &caps);
        match result {
            Err(ListenError::ZeroShards { name: found }) => {
                assert_eq!(found, "zero-shards");
                assert_eq!(
                    ListenError::ZeroShards { name: found }.to_string(),
                    "listener zero-shards: shard count must be at least 1"
                );
            }
            other => panic!("expected Err(ListenError::ZeroShards), got {other:?}"),
        }
    }
}
