// SPDX-License-Identifier: MIT OR Apache-2.0

//! `SingleUpstream`, the one connector M1 ships, and the typed error it returns.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

/// The single upstream every connection is forwarded to.
#[derive(Debug, Clone, Copy)]
pub struct SingleUpstream {
    addr: SocketAddr,
    connect_timeout: Duration,
}

// 48 bytes: a 32-byte `SocketAddr` plus a 16-byte `Duration`. Small enough that
// a connection handler holds one by value rather than behind an `Arc`; `<= 64`
// rather than a tighter bound because both component sizes are fixed by `std`
// and there is nothing left here to shave.
const _: () = assert!(std::mem::size_of::<SingleUpstream>() <= 64);

impl SingleUpstream {
    /// Builds a connector from the configured address and deadline.
    #[must_use]
    pub fn new(addr: irontraffic_config::UpstreamAddr, connect_timeout: Duration) -> Self {
        Self {
            addr: addr.socket_addr(),
            connect_timeout,
        }
    }

    /// The address this connector dials.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The connect deadline.
    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Dials the upstream, applying the deadline and setting `TCP_NODELAY`.
    ///
    /// Emits no log line and no metric: a log per connection attempt is a throughput
    /// ceiling, so the caller counts outcomes.
    ///
    /// # Errors
    /// [`ConnectError::TimedOut`] when the deadline expires, [`ConnectError::Refused`]
    /// when the upstream is not listening, [`ConnectError::Unreachable`] for a routing
    /// failure, and [`ConnectError::Io`] for anything else. Every variant names the
    /// address.
    pub async fn connect(&self) -> Result<irontraffic_io::TcpTransport, ConnectError> {
        let fut = irontraffic_io::net::connect_tcp(self.addr);
        // Saturate rather than cast, so a Duration::MAX budget reports u64::MAX
        // instead of wrapping to a small, misleading number.
        let budget_ms = u64::try_from(self.connect_timeout.as_millis()).unwrap_or(u64::MAX);
        match irontraffic_io::with_timeout(self.connect_timeout, fut).await {
            Err(timed_out) => Err(ConnectError::TimedOut {
                addr: self.addr,
                millis: timed_out.millis,
            }),
            Ok(Ok(transport)) => Ok(transport),
            Ok(Err(e)) => Err(classify(self.addr, budget_ms, e)),
        }
    }
}

/// Classifies a raw connect failure into a [`ConnectError`].
///
/// Takes `budget_ms` rather than inventing a value, because a kernel `ETIMEDOUT`
/// and our own deadline are reported identically and both must name the number the
/// operator configured.
fn classify(addr: SocketAddr, budget_ms: u64, e: io::Error) -> ConnectError {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => ConnectError::Refused { addr },
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
            ConnectError::Unreachable { addr, source: e }
        }
        io::ErrorKind::TimedOut => ConnectError::TimedOut {
            addr,
            millis: budget_ms,
        },
        _ => ConnectError::Io { addr, source: e },
    }
}

/// Why an upstream connection could not be established.
#[derive(Debug, Error)]
pub enum ConnectError {
    /// The deadline expired. The upstream may be overloaded or black-holed.
    #[error("upstream {addr} did not accept a connection within {millis} ms")]
    TimedOut {
        /// The address dialled.
        addr: SocketAddr,
        /// The budget that expired, in milliseconds.
        millis: u64,
    },
    /// The upstream actively refused: nothing is listening on that port.
    #[error("upstream {addr} refused the connection")]
    Refused {
        /// The address dialled.
        addr: SocketAddr,
    },
    /// The network or host is unreachable: a routing problem, not an upstream problem.
    #[error("upstream {addr} is unreachable: {source}")]
    Unreachable {
        /// The address dialled.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// Any other operating system failure.
    #[error("upstream {addr} connect failed: {source}")]
    Io {
        /// The address dialled.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

impl ConnectError {
    /// A short, stable, machine-readable reason: `timeout`, `refused`, `unreachable`,
    /// or `io`. Suitable as a metric label because the set is closed.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            ConnectError::TimedOut { .. } => "timeout",
            ConnectError::Refused { .. } => "refused",
            ConnectError::Unreachable { .. } => "unreachable",
            ConnectError::Io { .. } => "io",
        }
    }

    /// The address that was dialled.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        match self {
            ConnectError::TimedOut { addr, .. }
            | ConnectError::Refused { addr }
            | ConnectError::Unreachable { addr, .. }
            | ConnectError::Io { addr, .. } => *addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use proptest::prelude::*;

    use super::{ConnectError, SingleUpstream, classify, io};

    #[test]
    fn reason_strings_are_stable() {
        let addr: SocketAddr = "127.0.0.1:1".parse().expect("valid literal");
        let timed_out = ConnectError::TimedOut { addr, millis: 5 };
        let refused = ConnectError::Refused { addr };
        let unreachable = ConnectError::Unreachable {
            addr,
            source: io::Error::from(io::ErrorKind::NetworkUnreachable),
        };
        let other = ConnectError::Io {
            addr,
            source: io::Error::other("boom"),
        };

        assert_eq!(timed_out.reason(), "timeout");
        assert_eq!(refused.reason(), "refused");
        assert_eq!(unreachable.reason(), "unreachable");
        assert_eq!(other.reason(), "io");
    }

    #[test]
    fn accessors_report_construction_values() {
        let addr: SocketAddr = "10.0.0.5:9000".parse().expect("valid literal");
        let configured = irontraffic_config::UpstreamAddr::try_from(addr.to_string())
            .expect("valid upstream literal");
        let timeout = Duration::from_millis(1234);

        let upstream = SingleUpstream::new(configured, timeout);

        assert_eq!(upstream.addr(), addr);
        assert_eq!(upstream.connect_timeout(), timeout);
    }

    #[test]
    fn classify_maps_known_error_kinds_to_named_variants() {
        let addr: SocketAddr = "127.0.0.1:1".parse().expect("valid literal");
        let budget_ms = 5_000;

        let refused = classify(
            addr,
            budget_ms,
            io::Error::from(io::ErrorKind::ConnectionRefused),
        );
        assert!(
            matches!(refused, ConnectError::Refused { addr: a } if a == addr),
            "ConnectionRefused must classify as Refused, got {refused:?}"
        );

        let network_unreachable = classify(
            addr,
            budget_ms,
            io::Error::from(io::ErrorKind::NetworkUnreachable),
        );
        assert!(
            matches!(network_unreachable, ConnectError::Unreachable { addr: a, .. } if a == addr),
            "NetworkUnreachable must classify as Unreachable, got {network_unreachable:?}"
        );

        let host_unreachable = classify(
            addr,
            budget_ms,
            io::Error::from(io::ErrorKind::HostUnreachable),
        );
        assert!(
            matches!(host_unreachable, ConnectError::Unreachable { addr: a, .. } if a == addr),
            "HostUnreachable must classify as Unreachable, got {host_unreachable:?}"
        );

        let timed_out = classify(addr, budget_ms, io::Error::from(io::ErrorKind::TimedOut));
        assert!(
            matches!(timed_out, ConnectError::TimedOut { addr: a, millis } if a == addr && millis == budget_ms),
            "a kernel TimedOut must classify as TimedOut with the configured budget, got {timed_out:?}"
        );

        let other = classify(addr, budget_ms, io::Error::from(io::ErrorKind::BrokenPipe));
        assert!(
            matches!(other, ConnectError::Io { addr: a, .. } if a == addr),
            "an unnamed kind must fall through to Io, got {other:?}"
        );
    }

    // A fixed list of 12 io::ErrorKind values: the three classify() names
    // explicitly (ConnectionRefused, NetworkUnreachable, HostUnreachable, plus
    // TimedOut), and eight more it must fall through to Io for, so the property
    // below exercises every arm of the match rather than only the happy ones.
    const CLASSIFY_KINDS: [io::ErrorKind; 12] = [
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::TimedOut,
        io::ErrorKind::NotFound,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::NotConnected,
        io::ErrorKind::AddrInUse,
        io::ErrorKind::AddrNotAvailable,
        io::ErrorKind::BrokenPipe,
    ];

    // The reason() classify() must produce for CLASSIFY_KINDS[index], so the
    // property below can check the exact variant, not only that addr() survives.
    fn expected_reason_for_classify_kind(index: usize) -> &'static str {
        match index {
            0 => "refused",
            1 | 2 => "unreachable",
            3 => "timeout",
            _ => "io",
        }
    }

    proptest! {
        #[test]
        fn prop_classify_is_total(
            kind_index in 0..CLASSIFY_KINDS.len(),
            raw_os_error in 1i32..=200,
            use_raw_os_error in any::<bool>(),
        ) {
            let addr: SocketAddr = "127.0.0.1:1".parse().expect("valid literal");
            let error = if use_raw_os_error {
                io::Error::from_raw_os_error(raw_os_error)
            } else {
                io::Error::from(CLASSIFY_KINDS[kind_index])
            };

            let result = classify(addr, 5_000, error);
            prop_assert_eq!(result.addr(), addr);
            if !use_raw_os_error {
                prop_assert_eq!(result.reason(), expected_reason_for_classify_kind(kind_index));
            }
        }
    }
}
