// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests over real loopback binds.
//!
//! Every test here binds `127.0.0.1:0` and either holds or drops the
//! resulting listener explicitly; none of them carry traffic or spawn a
//! peer thread, so there is nothing to race the way `TcpTransport`'s
//! `nodelay_is_set_by_from_tokio` test once did.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use irontraffic_io::{BindError, Caps, SockOpts, bind_listener};

fn loopback_any_port() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[cfg(unix)]
#[test]
fn probe_reports_reuse_port_on_unix() {
    let caps = Caps::probe();
    assert!(
        caps.reuse_port,
        "SO_REUSEPORT must be reported available on Linux and macOS"
    );
}

#[test]
fn probe_leaves_no_listener() {
    let caps = Caps::probe();

    // The probe never binds a port, so a plain bind afterward must succeed.
    let opts = SockOpts::default();
    let (listener, _outcome) =
        bind_listener(loopback_any_port(), &opts, &caps).expect("probe must not hold any port");

    let caps_again = Caps::probe();
    assert_eq!(
        caps, caps_again,
        "Caps::probe() must be stable across repeated calls"
    );

    drop(listener);
}

#[test]
fn bind_returns_nonblocking_listener() {
    let caps = Caps::probe();
    let opts = SockOpts::default();
    let (listener, _outcome) = bind_listener(loopback_any_port(), &opts, &caps)
        .expect("binding an ephemeral loopback port must succeed");

    let err = listener
        .accept()
        .expect_err("a fresh non-blocking listener with no pending connection must not block");
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}

#[test]
fn bind_port_zero_resolves_a_port() {
    let caps = Caps::probe();
    let opts = SockOpts::default();
    let (listener, _outcome) = bind_listener(loopback_any_port(), &opts, &caps)
        .expect("binding an ephemeral loopback port must succeed");

    let resolved = listener
        .local_addr()
        .expect("a bound listener must report its local address");
    assert_ne!(resolved.port(), 0);
}

#[cfg(unix)]
#[test]
fn two_reuseport_sockets_share_one_port() {
    let caps = Caps::probe();
    let opts = SockOpts {
        reuse_port: true,
        ..SockOpts::default()
    };

    let (first, outcome1) = bind_listener(loopback_any_port(), &opts, &caps)
        .expect("the first SO_REUSEPORT bind must succeed");
    assert!(
        outcome1.reuse_port_applied,
        "SO_REUSEPORT must have been applied to the first socket"
    );
    let port = first
        .local_addr()
        .expect("a bound listener must report its local address")
        .port();

    let (second, outcome2) = bind_listener(loopback(port), &opts, &caps)
        .expect("a second SO_REUSEPORT socket must be able to join the group");
    assert!(
        outcome2.reuse_port_applied,
        "SO_REUSEPORT must have been applied to the second socket"
    );

    // Both sockets are held alive for the whole test; neither carries
    // traffic, so there is nothing for a peer thread to race.
    drop(first);
    drop(second);
}

#[test]
fn second_bind_without_reuseport_fails() {
    let caps = Caps::probe();
    let opts = SockOpts {
        reuse_port: false,
        ..SockOpts::default()
    };

    let (first, _outcome) =
        bind_listener(loopback_any_port(), &opts, &caps).expect("the first bind must succeed");
    // Keep `first` alive in this local binding for the whole test: dropping
    // it would free the port and make the second bind below succeed instead
    // of proving the failure this test exists to check.
    let port = first
        .local_addr()
        .expect("a bound listener must report its local address")
        .port();

    let err = bind_listener(loopback(port), &opts, &caps)
        .expect_err("a second bind to the same port without SO_REUSEPORT must fail");
    assert!(matches!(err, BindError::Bind { .. }));
    let message = err.to_string();
    assert!(
        message.contains(&port.to_string()),
        "error message {message:?} must name the port {port}"
    );

    drop(first);
}

#[test]
fn backlog_zero_is_clamped_to_one() {
    let caps = Caps::probe();
    let opts = SockOpts {
        backlog: 0,
        ..SockOpts::default()
    };

    let (listener, outcome) = bind_listener(loopback_any_port(), &opts, &caps)
        .expect("a zero backlog must be clamped, not rejected");
    assert_eq!(outcome.backlog_requested, 1);

    drop(listener);
}

#[test]
fn bind_error_names_the_address() {
    let caps = Caps::probe();
    let opts = SockOpts {
        reuse_port: false,
        ..SockOpts::default()
    };

    let (first, _outcome) =
        bind_listener(loopback_any_port(), &opts, &caps).expect("the first bind must succeed");
    let port = first
        .local_addr()
        .expect("a bound listener must report its local address")
        .port();

    let err = bind_listener(loopback(port), &opts, &caps)
        .expect_err("binding an address already in use must fail");
    let message = err.to_string();
    assert!(
        message.contains("127.0.0.1"),
        "error message {message:?} must name the address"
    );
    assert!(
        message.contains(&port.to_string()),
        "error message {message:?} must name the port {port}"
    );

    drop(first);
}
