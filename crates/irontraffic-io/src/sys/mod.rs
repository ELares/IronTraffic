// SPDX-License-Identifier: MIT OR Apache-2.0

//! Platform facilities. Every raw socket option and every syscall wrapper in
//! the workspace lives in this module: a capability probe run once at
//! startup, the socket options a listener wants, and the one function in the
//! workspace that creates a listening socket.
//!
//! `socket2` is the only way anything here touches a raw option: this crate
//! denies `unsafe` like every other, and `socket2::Socket` is what lets
//! `SO_REUSEPORT` be set before `bind` (the one ordering that matters; see
//! [`bind_listener`]) without reaching for a raw `setsockopt`.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;

#[cfg(not(target_os = "linux"))]
mod fallback;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(target_os = "linux"))]
use fallback::read_somaxconn;
#[cfg(target_os = "linux")]
use linux::read_somaxconn;

/// What the running kernel supports. Probed once at startup, never re-probed.
#[allow(
    clippy::struct_excessive_bools,
    reason = "issue #8's Public API section specifies this exact five-field shape: each field is an \
              independent yes/no probe result read and logged by name (reuse_port, splice, \
              scm_rights, ...), never combined into a mode, so a state machine or an enum would need \
              one variant per combination while expressing nothing an enum encodes more clearly"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// `SO_REUSEPORT` can be set on a TCP socket.
    pub reuse_port: bool,
    /// `SO_REUSEADDR` can be set on a TCP socket.
    pub reuse_addr: bool,
    /// `IPV6_V6ONLY` can be set on an IPv6 socket.
    pub ipv6_only_settable: bool,
    /// The platform has `splice(2)`. Compile-time answer: a seccomp profile
    /// that blocks it can only be detected at first use, so the consumer
    /// (a later milestone) must still fall back to the buffered path on
    /// `EPERM`.
    pub splice: bool,
    /// The platform has `SCM_RIGHTS` file descriptor passing.
    pub scm_rights: bool,
    /// `net.core.somaxconn` on Linux, or `None` when it cannot be read.
    pub somaxconn: Option<u32>,
}

const _: () = assert!(std::mem::size_of::<Caps>() <= 16);

impl Caps {
    /// Probes the platform. Performs blocking file I/O and three socket
    /// creates; call once, before any runtime exists, never from a runtime
    /// thread.
    #[must_use]
    pub fn probe() -> Self {
        Self {
            reuse_addr: probe_sockopt(|s| s.set_reuse_address(true)),
            reuse_port: probe_reuse_port(),
            ipv6_only_settable: probe_v6_sockopt(|s| s.set_only_v6(true)),
            splice: cfg!(target_os = "linux"),
            scm_rights: cfg!(unix),
            somaxconn: read_somaxconn(),
        }
    }

    /// A one-line summary for the startup log. The format is fixed and
    /// pinned by a test, because an operator greps it:
    ///
    /// ```text
    /// reuse_port=true reuse_addr=true ipv6_only_settable=true splice=true scm_rights=true somaxconn=4096
    /// ```
    ///
    /// Six `key=value` pairs, in that order, separated by single spaces, no
    /// trailing space. Booleans render as `true` or `false`. `somaxconn`
    /// renders as the decimal number when it is `Some`, and as the literal
    /// `unknown` when it is `None`.
    #[must_use]
    pub fn summary(&self) -> String {
        let somaxconn = match self.somaxconn {
            Some(n) => n.to_string(),
            None => "unknown".to_owned(),
        };
        format!(
            "reuse_port={} reuse_addr={} ipv6_only_settable={} splice={} scm_rights={} somaxconn={somaxconn}",
            self.reuse_port, self.reuse_addr, self.ipv6_only_settable, self.splice, self.scm_rights,
        )
    }
}

/// Creates a throwaway IPv4 TCP socket, applies `f`, and reports whether it
/// succeeded. The socket is never bound, so this can neither fail because a
/// port is busy nor leave a listening socket behind.
fn probe_sockopt(f: impl FnOnce(&Socket) -> io::Result<()>) -> bool {
    let Ok(sock) = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) else {
        return false;
    };
    let ok = f(&sock).is_ok();
    drop(sock);
    ok
}

/// Identical to [`probe_sockopt`], on an IPv6 socket. A separate function
/// because `IPV6_V6ONLY` is not settable on an `AF_INET` socket, so probing
/// it on the IPv4 socket would report `false` on every host. On a host with
/// IPv6 disabled the socket creation fails and the probe honestly reports
/// `false`.
fn probe_v6_sockopt(f: impl FnOnce(&Socket) -> io::Result<()>) -> bool {
    let Ok(sock) = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) else {
        return false;
    };
    let ok = f(&sock).is_ok();
    drop(sock);
    ok
}

/// Whether `SO_REUSEPORT` can be set, probed for real on unix (Linux and
/// macOS both have it) and reported `false` on any other target without
/// attempting the call, because `socket2::Socket::set_reuse_port` itself
/// only exists on unix. This is one of the two `cfg` blocks that keep this
/// module compiling on every target; the other is in [`bind_listener`],
/// which applies the same option to a real socket instead of a throwaway
/// one.
#[cfg(unix)]
fn probe_reuse_port() -> bool {
    probe_sockopt(|s| s.set_reuse_port(true))
}

#[cfg(not(unix))]
fn probe_reuse_port() -> bool {
    false
}

/// What the caller wants on a listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockOpts {
    /// Request `SO_REUSEPORT` so one endpoint can have one socket per
    /// worker. Default `true`. See `docs/THREAT-MODEL.md`'s "Listening
    /// sockets and socket options" section before relying on this: a
    /// same-UID local process can join the group, and outside Linux that
    /// can silently redirect or black-hole the whole listener, not merely
    /// take a share of it.
    pub reuse_port: bool,
    /// Request `SO_REUSEADDR`.
    pub reuse_addr: bool,
    /// The `listen(2)` backlog. Default 4096. Linux clamps silently to
    /// `net.core.somaxconn`; [`BindOutcome::backlog_may_be_clamped`] reports
    /// that.
    pub backlog: u32,
    /// Set `IPV6_V6ONLY` on IPv6 sockets.
    pub ipv6_only: bool,
}

const _: () = assert!(std::mem::size_of::<SockOpts>() <= 16);

impl Default for SockOpts {
    fn default() -> Self {
        Self {
            reuse_port: true,
            reuse_addr: true,
            backlog: 4096,
            ipv6_only: false,
        }
    }
}

/// What `bind_listener` actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindOutcome {
    /// `SO_REUSEPORT` was requested and applied.
    pub reuse_port_applied: bool,
    /// The backlog passed to `listen(2)`.
    pub backlog_requested: u32,
    /// `net.core.somaxconn` is smaller than the requested backlog, so the
    /// kernel clamped it. Log a warning naming both numbers.
    pub backlog_may_be_clamped: bool,
}

/// The largest backlog [`resolve_backlog`] will pass through: `i32::MAX` as a
/// `u32`. Computed with [`i32::unsigned_abs`], never negative so this is
/// exact, rather than an `as` cast: the `unchecked-cast` invariant lint (and
/// this issue's own acceptance grep) fires on any narrowing `as
/// i32/u32/u16/u8/i16/i8` in this module.
const MAX_BACKLOG: u32 = i32::MAX.unsigned_abs();

/// Clamps a requested backlog into `1..=i32::MAX` and reports whether the
/// platform's `somaxconn` is known to be smaller than it, meaning the kernel
/// is expected to clamp it further on its own. The only place the backlog
/// clamp and the `somaxconn` comparison are written; [`bind_listener`] calls
/// this once and uses both results. `pub(crate)`, never `pub`: test 8 drives
/// the clamp decision directly without binding anything.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "issue #8's Design section specifies this exact by-reference signature \
              (`resolve_backlog(opts: &SockOpts, caps: &Caps)`), matching bind_listener's own \
              by-reference parameters of the same two types one level up; clippy exempts bind_listener \
              itself from this lint because it is part of the crate's public API, but resolve_backlog \
              is pub(crate) so the exemption does not reach it even though the same reasoning applies"
)]
pub(crate) fn resolve_backlog(opts: &SockOpts, caps: &Caps) -> (u32, bool) {
    let backlog = opts.backlog.clamp(1, MAX_BACKLOG);
    let may_be_clamped = matches!(caps.somaxconn, Some(m) if m < backlog);
    (backlog, may_be_clamped)
}

/// A step of listener creation failed.
#[derive(Debug, Error)]
pub enum BindError {
    /// Failed to create the socket.
    #[error("failed to create a socket: {0}")]
    Create(#[source] io::Error),
    /// Failed to set a socket option.
    #[error("failed to set a socket option: {0}")]
    Option(#[source] io::Error),
    /// Failed to bind the address. Names the address: "address already in
    /// use" without one is the least useful error message a proxy can emit
    /// at startup.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// The address that could not be bound.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// Failed to start listening.
    #[error("failed to listen: {0}")]
    Listen(#[source] io::Error),
}

/// Creates one listening socket, setting every option in the correct order.
///
/// `SO_REUSEPORT` and `SO_REUSEADDR` are set BEFORE `bind`, which is required
/// for them to take effect: `SO_REUSEPORT` set after `bind` is a silent
/// no-op that produces a single-queue listener with none of the sharding a
/// caller asked for. The returned listener is non-blocking.
///
/// # Errors
/// Returns [`BindError`] naming the failed operation, and for a bind failure
/// the address, because "address already in use" without an address is
/// useless.
pub fn bind_listener(
    addr: SocketAddr,
    opts: &SockOpts,
    caps: &Caps,
) -> Result<(std::net::TcpListener, BindOutcome), BindError> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(BindError::Create)?;

    if opts.reuse_addr && caps.reuse_addr {
        sock.set_reuse_address(true).map_err(BindError::Option)?;
    }

    let mut reuse_port_applied = false;
    if opts.reuse_port && caps.reuse_port {
        // `caps.reuse_port` is only ever `true` on unix (see
        // `probe_reuse_port` above), so the `#[cfg(not(unix))]` arm below
        // cannot be reached at runtime; it exists purely so this function
        // compiles on every target, which is the second of the two `cfg`
        // blocks the acceptance criteria ask a reader to check.
        #[cfg(unix)]
        {
            sock.set_reuse_port(true).map_err(BindError::Option)?;
            reuse_port_applied = true;
        }
        #[cfg(not(unix))]
        {
            reuse_port_applied = false;
        }
    }

    if addr.is_ipv6() {
        sock.set_only_v6(opts.ipv6_only)
            .map_err(BindError::Option)?;
    }

    sock.set_nonblocking(true).map_err(BindError::Option)?;
    sock.bind(&addr.into())
        .map_err(|source| BindError::Bind { addr, source })?;

    let (backlog, backlog_may_be_clamped) = resolve_backlog(opts, caps);
    let backlog_i32 = i32::try_from(backlog).unwrap_or(i32::MAX);
    sock.listen(backlog_i32).map_err(BindError::Listen)?;

    Ok((
        std::net::TcpListener::from(sock),
        BindOutcome {
            reuse_port_applied,
            backlog_requested: backlog,
            backlog_may_be_clamped,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{Caps, SockOpts, resolve_backlog};

    #[test]
    fn resolve_backlog_table() {
        // The fourth row's expected `may_be_clamped` differs from the value
        // issue #8's own Tests section literally states, which says
        // `(backlog: 0, somaxconn: Some(128))` -> `(1, true)`. Applying the
        // issue's own Design section algorithm verbatim
        // (`matches!(caps.somaxconn, Some(m) if m < backlog)`, compared
        // against the POST-clamp backlog, exactly as `resolve_backlog` below
        // implements it) gives `128 < 1 == false`, and
        // `BindOutcome::backlog_may_be_clamped`'s own doc comment ("somaxconn
        // is smaller than the requested backlog, so the kernel clamped it")
        // agrees: 128 is not smaller than 1, so there is no clamp to report.
        // This is a self-contradiction in the issue, filed as a defect; this
        // test asserts the value the specified algorithm and the specified
        // doc comment both actually produce.
        let base = Caps {
            reuse_port: false,
            reuse_addr: false,
            ipv6_only_settable: false,
            splice: false,
            scm_rights: false,
            somaxconn: Some(128),
        };
        let caps_low_somaxconn = base;
        let caps_high_somaxconn = Caps {
            somaxconn: Some(8192),
            ..base
        };
        let caps_unknown_somaxconn = Caps {
            somaxconn: None,
            ..base
        };

        let opts_default = SockOpts {
            backlog: 4096,
            ..SockOpts::default()
        };
        let opts_zero_backlog = SockOpts {
            backlog: 0,
            ..SockOpts::default()
        };

        assert_eq!(
            resolve_backlog(&opts_default, &caps_low_somaxconn),
            (4096, true)
        );
        assert_eq!(
            resolve_backlog(&opts_default, &caps_high_somaxconn),
            (4096, false)
        );
        assert_eq!(
            resolve_backlog(&opts_default, &caps_unknown_somaxconn),
            (4096, false)
        );
        assert_eq!(
            resolve_backlog(&opts_zero_backlog, &caps_low_somaxconn),
            (1, false)
        );
    }

    #[test]
    fn caps_summary_format_is_pinned() {
        // `Caps::summary`'s doc comment says the format "is fixed and pinned
        // by a test, because an operator greps it"; this is that test. Not
        // named in issue #8's `## Tests` list, but tests may be added freely.
        let caps = Caps {
            reuse_port: true,
            reuse_addr: true,
            ipv6_only_settable: true,
            splice: true,
            scm_rights: true,
            somaxconn: Some(4096),
        };
        assert_eq!(
            caps.summary(),
            "reuse_port=true reuse_addr=true ipv6_only_settable=true splice=true scm_rights=true somaxconn=4096"
        );

        let caps_unknown = Caps {
            somaxconn: None,
            ..caps
        };
        assert!(caps_unknown.summary().ends_with("somaxconn=unknown"));
    }
}
