// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests over real loopback binds.
//!
//! Every test uses `irontraffic_io::sys::Caps::probe()` for the real platform
//! capabilities, except `fallback_binds_one_socket`, which hand-builds a `Caps`
//! with `reuse_port` forced off. No test asserts on how connections distribute
//! across shards: the kernel's hash over a loopback 4-tuple is not something a
//! test may depend on.
//!
//! Every `ListenerName`/`BindAddr`/`Backlog` value below is built inline with
//! `.expect(...)` rather than through a shared helper function: clippy's
//! `expect_used` exemption for test code applies to functions carrying
//! `#[test]`/`#[tokio::test]` themselves, not to a plain helper a test merely
//! calls, so a shared constructor here would fail the crate's own
//! `expect_used = "deny"` lint.

use std::future::poll_fn;
use std::time::Duration;

use irontraffic_config::{Backlog, BindAddr, ListenerName};
use irontraffic_conn::{ListenError, ShardedListener};
use irontraffic_io::sys::Caps;
use irontraffic_io::{Acceptor, with_timeout};

#[test]
fn single_shard_binds_and_resolves() {
    let caps = Caps::probe();
    let name = ListenerName::try_from("single-shard").expect("valid listener name");
    let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
    let backlog = Backlog::try_from(4096u32).expect("valid backlog");

    let listener = ShardedListener::bind(&name, bind_addr, 1, true, false, backlog, &caps)
        .expect("a single shard must bind");

    assert_eq!(listener.shards(), 1);
    assert_ne!(listener.resolved_addr().port(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn all_shards_share_the_resolved_port() {
    let caps = Caps::probe();
    let name = ListenerName::try_from("shared-port").expect("valid listener name");
    let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
    let backlog = Backlog::try_from(4096u32).expect("valid backlog");

    let listener = ShardedListener::bind(&name, bind_addr, 4, true, false, backlog, &caps)
        .expect("four shards must bind");
    assert_eq!(listener.shards(), 4);
    let resolved = listener.resolved_addr();

    let (acceptors, _report, resolved_from_conversion) =
        listener.into_acceptors().expect("conversion must succeed");
    assert_eq!(resolved_from_conversion, resolved);
    assert_eq!(acceptors.len(), 4);
    // `ShardedListener` deliberately exposes no accessor for the individual
    // sockets, so the per-shard address must be observed through the
    // acceptors it hands back. This is the assertion that fails if a shard
    // rebinds a fresh ephemeral port instead of joining `resolved`.
    for acceptor in &acceptors {
        assert_eq!(acceptor.local_addr(), resolved);
    }
}

#[test]
fn report_reflects_reuseport_and_backlog() {
    let caps = Caps::probe();
    let name = ListenerName::try_from("report-check").expect("valid listener name");
    let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
    let backlog = Backlog::try_from(4096u32).expect("valid backlog");

    let listener = ShardedListener::bind(&name, bind_addr, 4, true, false, backlog, &caps)
        .expect("bind must succeed");

    let report = listener.report();
    assert_eq!(report.reuseport, caps.reuse_port);
    assert_eq!(report.shards_requested, 4);
    assert_eq!(report.backlog, 4096);
}

#[test]
fn fallback_binds_one_socket() {
    let probed = Caps::probe();
    let caps = Caps {
        reuse_port: false,
        ..probed
    };
    let name = ListenerName::try_from("fallback").expect("valid listener name");
    let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
    let backlog = Backlog::try_from(4096u32).expect("valid backlog");

    let listener = ShardedListener::bind(&name, bind_addr, 8, true, false, backlog, &caps)
        .expect("the fallback bind must still succeed");

    assert_eq!(listener.shards(), 1);
    let report = listener.report();
    assert_eq!(report.shards_bound, 1);
    assert!(!report.reuseport);
    assert_eq!(report.shards_requested, 8);
}

#[test]
fn bind_failure_names_the_shard_and_closes_sockets() {
    let caps = Caps::probe();
    // This blocker sets no `SO_REUSEPORT`, so no later `SO_REUSEPORT` socket
    // may join it: the kernel refuses any reuseport bind against a group
    // whose existing member did not opt in.
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the blocker");
    let port = blocker
        .local_addr()
        .expect("the blocker reports its local address")
        .port();
    let bind_addr =
        BindAddr::try_from(format!("127.0.0.1:{port}").as_str()).expect("valid bind address");
    let name = ListenerName::try_from("blocked").expect("valid listener name");
    let backlog = Backlog::try_from(4096u32).expect("valid backlog");

    let result = ShardedListener::bind(&name, bind_addr, 4, true, false, backlog, &caps);
    match result {
        Err(ListenError::Bind { shard, total, .. }) => {
            assert_eq!(shard, 0);
            assert_eq!(total, 4);
        }
        other => {
            panic!("expected Err(ListenError::Bind {{ shard: 0, total: 4, .. }}), got {other:?}")
        }
    }

    // Freeing the blocker must free the port: a leaked descriptor from the
    // failed attempt above would make this retry fail too.
    drop(blocker);

    let retry = ShardedListener::bind(&name, bind_addr, 4, true, false, backlog, &caps);
    assert!(
        retry.is_ok(),
        "the failed attempt must not have leaked the port: {retry:?}"
    );
}

#[tokio::test]
async fn into_acceptors_yields_one_per_shard() {
    let caps = Caps::probe();
    let name = ListenerName::try_from("three-shards").expect("valid listener name");
    let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
    let backlog = Backlog::try_from(4096u32).expect("valid backlog");

    let listener = ShardedListener::bind(&name, bind_addr, 3, true, false, backlog, &caps)
        .expect("three shards must bind");

    let (acceptors, _report, resolved) =
        listener.into_acceptors().expect("conversion must succeed");
    assert_eq!(acceptors.len(), 3);
    for acceptor in &acceptors {
        assert_eq!(acceptor.local_addr(), resolved);
    }
}

#[test]
fn into_acceptors_outside_a_runtime_errors() {
    // Run on a fresh OS thread, mirroring `irontraffic-io`'s own
    // `from_std_outside_runtime_is_err_not_panic`: the test harness reuses
    // threads across tests, so a plain `#[test]` body run on a thread that
    // previously hosted a `#[tokio::test]` could otherwise observe a leaked
    // ambient runtime and hide a regression.
    let result = std::thread::spawn(|| {
        let caps = Caps::probe();
        let name = ListenerName::try_from("no-runtime").expect("valid listener name");
        let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
        let backlog = Backlog::try_from(4096u32).expect("valid backlog");

        let listener = ShardedListener::bind(&name, bind_addr, 1, true, false, backlog, &caps)
            .expect("bind must succeed outside a runtime");
        listener.into_acceptors()
    })
    .join()
    .expect("the spawned thread must not panic");

    match result {
        Err(ListenError::Register { shard, .. }) => assert_eq!(shard, 0),
        other => panic!("expected Err(ListenError::Register {{ shard: 0, .. }}), got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn every_shard_can_accept() {
    const TOTAL_CONNECTIONS: usize = 32;

    let caps = Caps::probe();
    let name = ListenerName::try_from("two-shards").expect("valid listener name");
    let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
    let backlog = Backlog::try_from(4096u32).expect("valid backlog");

    let listener = ShardedListener::bind(&name, bind_addr, 2, true, false, backlog, &caps)
        .expect("two shards must bind");
    let resolved = listener.resolved_addr();
    let (mut acceptors, _report, _resolved) =
        listener.into_acceptors().expect("conversion must succeed");
    assert_eq!(acceptors.len(), 2);
    let second = acceptors.pop().expect("two acceptors");
    let first = acceptors.pop().expect("two acceptors");

    // Open every client connection up front and hold every one of them alive
    // for the whole test: nothing here needs to carry traffic, only to be
    // accepted, so there is nothing for a peer to race against a drop.
    let mut clients = Vec::with_capacity(TOTAL_CONNECTIONS);
    for _ in 0..TOTAL_CONNECTIONS {
        let stream = tokio::net::TcpStream::connect(resolved)
            .await
            .expect("a client must be able to connect");
        clients.push(stream);
    }

    let accept_both = async {
        let mut total = 0usize;
        let mut accepted = Vec::with_capacity(TOTAL_CONNECTIONS);
        while total < TOTAL_CONNECTIONS {
            tokio::select! {
                res = poll_fn(|cx| first.poll_accept(cx)) => {
                    let (transport, _peer) = res.expect("accept on the first shard must succeed");
                    accepted.push(transport);
                    total += 1;
                }
                res = poll_fn(|cx| second.poll_accept(cx)) => {
                    let (transport, _peer) = res.expect("accept on the second shard must succeed");
                    accepted.push(transport);
                    total += 1;
                }
            }
        }
        (total, accepted)
    };

    let (total, _accepted) = with_timeout(Duration::from_secs(5), accept_both)
        .await
        .expect("32 accepts must complete within the timeout guard");

    // No distribution assertion: the kernel hash over a loopback 4-tuple is
    // not something a test may depend on.
    assert_eq!(total, TOTAL_CONNECTIONS);

    drop(clients);
}

#[test]
fn dropping_without_conversion_frees_the_port() {
    let caps = Caps::probe();
    let name = ListenerName::try_from("drop-me").expect("valid listener name");
    let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
    let backlog = Backlog::try_from(4096u32).expect("valid backlog");

    let listener = ShardedListener::bind(&name, bind_addr, 4, true, false, backlog, &caps)
        .expect("four shards must bind");
    let port = listener.resolved_addr().port();
    drop(listener);

    let plain = std::net::TcpListener::bind(("127.0.0.1", port));
    assert!(
        plain.is_ok(),
        "dropping a ShardedListener without converting it must free the port: {plain:?}"
    );
}

#[test]
fn ipv6_loopback_binds() {
    // Probed explicitly rather than skipped with an ignore attribute, which
    // the invariant lints forbid anyway: an IPv6-less host must still
    // exercise `ShardedListener::bind` and see the expected error shape, not
    // silently report nothing.
    let probe = std::net::TcpListener::bind("[::1]:0");
    let caps = Caps::probe();
    let name = ListenerName::try_from("v6-loopback").expect("valid listener name");
    let bind_addr = BindAddr::try_from("[::1]:0").expect("valid bind address");
    let backlog = Backlog::try_from(4096u32).expect("valid backlog");

    if probe.is_err() {
        let result = ShardedListener::bind(&name, bind_addr, 2, true, false, backlog, &caps);
        assert!(
            matches!(result, Err(ListenError::Bind { .. })),
            "an IPv6-less host must fail with ListenError::Bind, got {result:?}"
        );
        return;
    }
    drop(probe);

    let listener = ShardedListener::bind(&name, bind_addr, 2, true, false, backlog, &caps)
        .expect("IPv6 loopback bind must succeed on a host that has IPv6");
    assert!(listener.resolved_addr().is_ipv6());
}

/// Not one of the 11 tests the issue names, added on top of them. Mutation
/// testing this crate at `-j 1` found that the fallback-warning condition in
/// `bind` (`reuseport_requested && !want_reuseport`) survived both a `&&` to
/// `||` mutation and a deletion of the `!`: nothing in the 11 named tests
/// observes `tracing` output, so a flipped or inverted condition still left
/// every one of them green. This module reuses the exact `Subscriber`
/// capture harness already reviewed and merged in
/// `irontraffic-runtime`'s `startup_log_tests` (`crates/irontraffic-runtime/src/plane.rs`)
/// to pin what the warning line actually depends on.
mod fallback_warning {
    use std::fmt::Debug;
    use std::sync::{Arc, Mutex};

    use irontraffic_config::{Backlog, BindAddr, ListenerName};
    use irontraffic_conn::ShardedListener;
    use irontraffic_io::sys::Caps;
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    /// One captured `tracing` event: its message and its fields, both as
    /// strings, so an assertion can name a field and a value literally.
    #[derive(Default, Debug, Clone)]
    struct Captured {
        message: String,
    }

    struct Collector(Arc<Mutex<Vec<Captured>>>);

    struct FieldVisitor<'a>(&'a mut Captured);

    impl Visit for FieldVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
            if field.name() == "message" {
                self.0.message = format!("{value:?}");
            }
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "message" {
                value.clone_into(&mut self.0.message);
            }
        }
    }

    impl Subscriber for Collector {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut captured = Captured::default();
            event.record(&mut FieldVisitor(&mut captured));
            if let Ok(mut events) = self.0.lock() {
                events.push(captured);
            }
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    /// Runs `f` under a fresh collecting subscriber and returns every event it
    /// recorded. Recovers from a poisoned lock instead of panicking, so this
    /// helper stays usable even though it is not itself a `#[test]` function
    /// (`clippy::expect_used`'s test exemption does not reach a plain function
    /// a test merely calls).
    fn capture(f: impl FnOnce()) -> Vec<Captured> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let collector = Collector(Arc::clone(&events));
        tracing::subscriber::with_default(collector, f);
        match events.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    const WARNING: &str = "SO_REUSEPORT is unavailable; bound a single socket and will run all accept tasks against it";

    #[test]
    fn requested_and_available_emits_no_fallback_warning() {
        let caps = Caps::probe();
        let name = ListenerName::try_from("warn-available").expect("valid listener name");
        let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
        let backlog = Backlog::try_from(4096u32).expect("valid backlog");

        let mut held = None;
        let events = capture(|| {
            held = ShardedListener::bind(&name, bind_addr, 2, true, false, backlog, &caps).ok();
        });
        assert!(held.is_some(), "the bind itself must still succeed");

        assert!(
            !events.iter().any(|e| e.message == WARNING),
            "no fallback warning is expected when SO_REUSEPORT was requested and available: {events:?}"
        );
    }

    #[test]
    fn not_requested_emits_no_fallback_warning_even_when_unavailable() {
        // `reuseport_requested: false` together with a `Caps` that also
        // reports `reuse_port: false` makes `want_reuseport` false too, which
        // is exactly the input that tells `&&` and `||` apart: with `&&` the
        // condition is `false && true == false` (no warning, correct, since
        // nobody asked for it); with `||` it would be
        // `false || true == true` (a spurious warning about a feature the
        // caller never requested).
        let probed = Caps::probe();
        let caps = Caps {
            reuse_port: false,
            ..probed
        };
        let name = ListenerName::try_from("warn-not-requested").expect("valid listener name");
        let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
        let backlog = Backlog::try_from(4096u32).expect("valid backlog");

        let mut held = None;
        let events = capture(|| {
            held = ShardedListener::bind(&name, bind_addr, 2, false, false, backlog, &caps).ok();
        });
        assert!(held.is_some(), "the bind itself must still succeed");

        assert!(
            !events.iter().any(|e| e.message == WARNING),
            "no fallback warning is expected when the caller never requested SO_REUSEPORT: {events:?}"
        );
    }

    #[test]
    fn requested_and_unavailable_emits_the_fallback_warning() {
        let probed = Caps::probe();
        let caps = Caps {
            reuse_port: false,
            ..probed
        };
        let name = ListenerName::try_from("warn-unavailable").expect("valid listener name");
        let bind_addr = BindAddr::try_from("127.0.0.1:0").expect("valid bind address");
        let backlog = Backlog::try_from(4096u32).expect("valid backlog");

        let mut held = None;
        let events = capture(|| {
            held = ShardedListener::bind(&name, bind_addr, 2, true, false, backlog, &caps).ok();
        });
        assert!(
            held.is_some(),
            "the fallback bind itself must still succeed"
        );

        assert_eq!(
            events.iter().filter(|e| e.message == WARNING).count(),
            1,
            "exactly one fallback warning is expected when SO_REUSEPORT was requested but \
             unavailable: {events:?}"
        );
    }
}
