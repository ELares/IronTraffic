// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests over a real loopback acceptor.
//!
//! Every peer socket a test opens is held alive for the whole test body and carries
//! no traffic beyond what the test actually needs to observe: `irontraffic-io`'s own
//! `nodelay_is_set_by_from_tokio` test documents a real flake caused by a spawned
//! peer thread racing its own drop against the assertion it existed to support, and
//! these tests are written to avoid that shape entirely rather than to survive it.
//!
//! `irontraffic_runtime::core::snapshot()` sums process-wide state shared by every
//! `#[tokio::test]` in this binary (they all run concurrently by default, and none
//! of them calls `irontraffic_runtime::install`, so they all lazily share one core
//! slot). `rejection_closes_the_socket_and_counts` and `accepted_counter_increments`
//! both read a delta off it, so every test in this file that runs an `accept_loop`
//! (which bumps `ConnectionsAccepted` or `ConnectionsRejected` on every iteration)
//! takes `COUNTER_TEST_LOCK` for its whole body, mirroring the convention
//! `irontraffic-runtime`'s own counter tests already establish.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use irontraffic_conn::{
    AcceptConfig, AcceptOutcome, BoxFut, ConnGuard, ConnHandler, ConnRegistry, accept_loop,
};
use irontraffic_io::{
    Acceptor, ShutdownController, ShutdownToken, Spawner, TcpAcceptor, TcpTransport, sleep,
    with_timeout,
};
use irontraffic_time::TestTimeSource;
use tokio::io::AsyncReadExt;

static COUNTER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Records every peer it is handed and drops the guard as soon as its future is
/// first polled, so a test using it sees an immediate accept-and-close cycle.
struct ImmediateHandler {
    peers: Mutex<Vec<SocketAddr>>,
    handled: AtomicUsize,
}

impl ImmediateHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            peers: Mutex::new(Vec::new()),
            handled: AtomicUsize::new(0),
        })
    }

    fn handled_count(&self) -> usize {
        self.handled.load(Ordering::Relaxed)
    }
}

impl ConnHandler<TcpTransport> for ImmediateHandler {
    fn handle(
        &self,
        _io: TcpTransport,
        peer: SocketAddr,
        guard: ConnGuard,
        _shutdown: ShutdownToken,
    ) -> BoxFut {
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(peer);
        self.handled.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            drop(guard);
        })
    }
}

/// Records every peer it is handed and holds each connection open until
/// [`HoldHandler::release`] is called. The wait loop mirrors the check-register-
/// recheck shape `irontraffic_io::ShutdownToken::drained` uses, so a release that
/// lands between a waiter's check and its registration is never lost.
struct HoldHandler {
    peers: Mutex<Vec<SocketAddr>>,
    released: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl HoldHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            peers: Mutex::new(Vec::new()),
            released: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        })
    }

    fn release(&self) {
        self.released.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
    }
}

impl ConnHandler<TcpTransport> for HoldHandler {
    fn handle(
        &self,
        _io: TcpTransport,
        peer: SocketAddr,
        guard: ConnGuard,
        _shutdown: ShutdownToken,
    ) -> BoxFut {
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(peer);
        let released = Arc::clone(&self.released);
        let notify = Arc::clone(&self.notify);
        Box::pin(async move {
            loop {
                if released.load(Ordering::Relaxed) {
                    break;
                }
                let notified = notify.notified();
                if released.load(Ordering::Relaxed) {
                    break;
                }
                notified.await;
            }
            drop(guard);
        })
    }
}

/// A handler whose future panics before doing anything else, so a test can prove the
/// `ConnGuard` moved into it still drops (and releases the connection balance) while
/// the spawned task unwinds.
struct PanicHandler;

impl ConnHandler<TcpTransport> for PanicHandler {
    #[allow(
        clippy::panic,
        reason = "test 8 (panicking_handler_releases_the_guard) exists specifically to prove \
                  that the ConnGuard moved into this future still drops during a panicking \
                  unwind; the panic here is the scenario under test, not a shortcut around \
                  error handling"
    )]
    fn handle(
        &self,
        _io: TcpTransport,
        _peer: SocketAddr,
        guard: ConnGuard,
        _shutdown: ShutdownToken,
    ) -> BoxFut {
        Box::pin(async move {
            let _guard = guard;
            panic!("intentional: proves the guard drops during a panicking unwind");
        })
    }
}

/// A stub acceptor that always errors with `PermissionDenied`, used to prove a
/// `Fatal` accept error ends only this one shard. Written the way `io-shutdown-token`
/// (#10) writes its own `ErrAcceptor`: `Io` is named but never constructed, because
/// the error arm returns before any `Io` value is needed.
struct PermissionDeniedAcceptor;

impl Acceptor for PermissionDeniedAcceptor {
    type Io = TcpTransport;

    fn poll_accept(&self, _cx: &mut Context<'_>) -> Poll<std::io::Result<(Self::Io, SocketAddr)>> {
        Poll::Ready(Err(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )))
    }

    fn local_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }
}

/// A stub acceptor that fails the first 5 polls with `EMFILE` and then delegates to a
/// real loopback acceptor. `#[cfg]`-gated to the two platforms whose real `EMFILE`
/// value this test hardcodes (24 on both), matching `classify`'s own gate: on any
/// other target `classify` treats it as a sentinel and the first failure would be
/// `Fatal`, not `BackOff`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct FlakyThenRealAcceptor {
    real: TcpAcceptor,
    polls: AtomicUsize,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Acceptor for FlakyThenRealAcceptor {
    type Io = TcpTransport;

    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<(Self::Io, SocketAddr)>> {
        let n = self.polls.fetch_add(1, Ordering::Relaxed);
        if n < 5 {
            // 24 is EMFILE on both Linux and macOS.
            return Poll::Ready(Err(std::io::Error::from_raw_os_error(24)));
        }
        self.real.poll_accept(cx)
    }

    fn local_addr(&self) -> SocketAddr {
        self.real.local_addr()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_loop_serves_connections_and_balances_back() {
    let _guard = COUNTER_TEST_LOCK.lock().await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = TcpAcceptor::from_std(listener).expect("register with reactor");

    let registry = ConnRegistry::new(64);
    let (_controller, token) = ShutdownController::new();
    let outer_spawner = Spawner::current().expect("a runtime drives this test");
    let inner_spawner = outer_spawner.clone();
    let handler = ImmediateHandler::new();
    let time: Arc<dyn irontraffic_time::TimeSource> = Arc::new(TestTimeSource::new());

    let _loop_handle = outer_spawner.spawn(accept_loop(
        acceptor,
        Arc::clone(&registry),
        token,
        inner_spawner,
        Arc::clone(&handler),
        time,
        AcceptConfig::default(),
    ));

    let mut clients = Vec::with_capacity(20);
    for _ in 0..20 {
        clients.push(
            tokio::net::TcpStream::connect(addr)
                .await
                .expect("client connects"),
        );
    }

    with_timeout(Duration::from_secs(5), async {
        while handler.handled_count() < 20 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("20 connections must be handled within the timeout");

    with_timeout(Duration::from_secs(5), async {
        while registry.stats().current != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the balance must return to 0 once every handler future completes");

    assert_eq!(registry.stats().current, 0);
    drop(clients);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_loop_stops_on_drain_and_leaves_live_connections_alone() {
    let _guard = COUNTER_TEST_LOCK.lock().await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = TcpAcceptor::from_std(listener).expect("register with reactor");

    let registry = ConnRegistry::new(8);
    let (controller, token) = ShutdownController::new();
    let outer_spawner = Spawner::current().expect("a runtime drives this test");
    let inner_spawner = outer_spawner.clone();
    let handler = HoldHandler::new();
    let time: Arc<dyn irontraffic_time::TimeSource> = Arc::new(TestTimeSource::new());

    let handle = outer_spawner.spawn(accept_loop(
        acceptor,
        Arc::clone(&registry),
        token,
        inner_spawner,
        Arc::clone(&handler),
        time,
        AcceptConfig::default(),
    ));

    let client_a = tokio::net::TcpStream::connect(addr)
        .await
        .expect("client a connects");
    let client_b = tokio::net::TcpStream::connect(addr)
        .await
        .expect("client b connects");

    with_timeout(Duration::from_secs(1), async {
        while registry.stats().current < 2 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("both connections must be admitted");

    controller.begin_drain();

    let outcome = with_timeout(Duration::from_secs(1), handle.join())
        .await
        .expect("accept_loop must return within 1 second of a drain")
        .expect("the accept_loop task must not panic or be aborted");
    assert_eq!(outcome, AcceptOutcome::Drained);
    assert_eq!(registry.stats().current, 2);

    handler.release();

    with_timeout(Duration::from_secs(1), async {
        while registry.stats().current != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the balance must return to 0 after release");

    drop(client_a);
    drop(client_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panicking_handler_releases_the_guard() {
    let _guard = COUNTER_TEST_LOCK.lock().await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = TcpAcceptor::from_std(listener).expect("register with reactor");

    let registry = ConnRegistry::new(8);
    let (_controller, token) = ShutdownController::new();
    let outer_spawner = Spawner::current().expect("a runtime drives this test");
    let inner_spawner = outer_spawner.clone();
    let handler = Arc::new(PanicHandler);
    let time: Arc<dyn irontraffic_time::TimeSource> = Arc::new(TestTimeSource::new());

    let _loop_handle = outer_spawner.spawn(accept_loop(
        acceptor,
        Arc::clone(&registry),
        token,
        inner_spawner,
        handler,
        time,
        AcceptConfig::default(),
    ));

    let client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("client connects");

    sleep(Duration::from_millis(200)).await;

    assert_eq!(registry.stats().current, 0);

    drop(client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejection_closes_the_socket_and_counts() {
    let _guard = COUNTER_TEST_LOCK.lock().await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = TcpAcceptor::from_std(listener).expect("register with reactor");

    let registry = ConnRegistry::new(1);
    let (_controller, token) = ShutdownController::new();
    let outer_spawner = Spawner::current().expect("a runtime drives this test");
    let inner_spawner = outer_spawner.clone();
    let handler = HoldHandler::new();
    let time: Arc<dyn irontraffic_time::TimeSource> = Arc::new(TestTimeSource::new());

    let before = irontraffic_runtime::core::snapshot();

    let _loop_handle = outer_spawner.spawn(accept_loop(
        acceptor,
        Arc::clone(&registry),
        token,
        inner_spawner,
        Arc::clone(&handler),
        time,
        AcceptConfig::default(),
    ));

    let first = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the first client connects");

    with_timeout(Duration::from_secs(1), async {
        while registry.stats().current < 1 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the first connection must be admitted");

    let mut second = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the second client connects");

    // The second connection is accepted at the kernel level, then rejected at
    // admission and dropped immediately, which the peer observes as EOF: no bytes
    // were ever queued on either side, so this is a clean FIN, not a reset.
    let mut buf = [0_u8; 1];
    let read = with_timeout(Duration::from_secs(1), second.read(&mut buf))
        .await
        .expect("the peer must observe the close within the timeout")
        .expect("the read itself must not error");
    assert_eq!(
        read, 0,
        "the rejected connection must be closed (EOF), not held open"
    );

    let after = irontraffic_runtime::core::snapshot();
    assert!(
        after[irontraffic_runtime::Counter::ConnectionsRejected as usize]
            > before[irontraffic_runtime::Counter::ConnectionsRejected as usize],
        "ConnectionsRejected must have increased by at least 1"
    );

    drop(first);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fatal_error_ends_only_this_loop() {
    let _guard = COUNTER_TEST_LOCK.lock().await;

    let registry = ConnRegistry::new(8);
    let (_controller, token) = ShutdownController::new();
    let outer_spawner = Spawner::current().expect("a runtime drives this test");
    let inner_spawner = outer_spawner.clone();
    let handler = ImmediateHandler::new();
    let time: Arc<dyn irontraffic_time::TimeSource> = Arc::new(TestTimeSource::new());

    let handle = outer_spawner.spawn(accept_loop(
        PermissionDeniedAcceptor,
        registry,
        token,
        inner_spawner,
        handler,
        time,
        AcceptConfig::default(),
    ));

    let outcome = with_timeout(Duration::from_secs(1), handle.join())
        .await
        .expect("accept_loop must return within 1 second")
        .expect("the accept_loop task must not panic or be aborted");

    assert_eq!(outcome, AcceptOutcome::Fatal);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backoff_error_does_not_spin() {
    let _guard = COUNTER_TEST_LOCK.lock().await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let real = TcpAcceptor::from_std(listener).expect("register with reactor");
    let acceptor = FlakyThenRealAcceptor {
        real,
        polls: AtomicUsize::new(0),
    };

    let registry = ConnRegistry::new(8);
    let (_controller, token) = ShutdownController::new();
    let outer_spawner = Spawner::current().expect("a runtime drives this test");
    let inner_spawner = outer_spawner.clone();
    let handler = ImmediateHandler::new();
    let time: Arc<dyn irontraffic_time::TimeSource> = Arc::new(TestTimeSource::new());

    // Queued before the loop even starts: once the loop moves past the five
    // injected EMFILE failures, the real acceptor already has a connection
    // waiting and accepts it on its very next poll, so the elapsed time measured
    // below is dominated by the backoff sleeps rather than by connection setup.
    let _client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("client connects");

    let start = std::time::Instant::now();
    let _loop_handle = outer_spawner.spawn(accept_loop(
        acceptor,
        registry,
        token,
        inner_spawner,
        Arc::clone(&handler),
        time,
        AcceptConfig::default(),
    ));

    with_timeout(Duration::from_secs(3), async {
        while handler.handled_count() < 1 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the real connection must be accepted within 3 seconds");
    let elapsed = start.elapsed();

    assert!(
        elapsed >= Duration::from_millis(155),
        "expected at least 155ms of doubling backoff (5+10+20+40+80), took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the backoff ceiling must have held the total under 3 seconds, took {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_counter_increments() {
    let _guard = COUNTER_TEST_LOCK.lock().await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = TcpAcceptor::from_std(listener).expect("register with reactor");

    let registry = ConnRegistry::new(64);
    let (_controller, token) = ShutdownController::new();
    let outer_spawner = Spawner::current().expect("a runtime drives this test");
    let inner_spawner = outer_spawner.clone();
    let handler = ImmediateHandler::new();
    let time: Arc<dyn irontraffic_time::TimeSource> = Arc::new(TestTimeSource::new());

    let before = irontraffic_runtime::core::snapshot();

    let _loop_handle = outer_spawner.spawn(accept_loop(
        acceptor,
        registry,
        token,
        inner_spawner,
        Arc::clone(&handler),
        time,
        AcceptConfig::default(),
    ));

    let mut clients = Vec::with_capacity(10);
    for _ in 0..10 {
        clients.push(
            tokio::net::TcpStream::connect(addr)
                .await
                .expect("client connects"),
        );
    }

    with_timeout(Duration::from_secs(5), async {
        while handler.handled_count() < 10 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("10 connections must be handled within the timeout");

    let after = irontraffic_runtime::core::snapshot();
    let delta = after[irontraffic_runtime::Counter::ConnectionsAccepted as usize]
        - before[irontraffic_runtime::Counter::ConnectionsAccepted as usize];
    assert!(delta >= 9, "expected at least 9 accepted, got {delta}");
    assert!(delta <= 10, "expected at most 10 accepted, got {delta}");

    drop(clients);
}
