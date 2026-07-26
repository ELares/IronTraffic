// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests over a real loopback socket.

use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use irontraffic_io::{
    Acceptor, Read as IoRead, ReadBuf, Spawner, TaskError, TaskHandle, TcpAcceptor, TimedOut,
    Transport, Write as IoWrite, sleep, with_timeout,
};
use std::pin::Pin;
use tokio::io::AsyncWriteExt;

/// Reads once into `dst`, returning the number of bytes filled (0 means end of file).
async fn read_once<T: Transport>(t: &mut T, dst: &mut [u8]) -> std::io::Result<usize> {
    std::future::poll_fn(|cx| {
        let mut rb = ReadBuf::new(dst);
        match IoRead::poll_read(Pin::new(&mut *t), cx, rb.unfilled()) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(rb.filled().len())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
        }
    })
    .await
}

/// Shuts the write half down.
async fn shutdown_write<T: Transport>(t: &mut T) -> std::io::Result<()> {
    std::future::poll_fn(|cx| IoWrite::poll_shutdown(Pin::new(&mut *t), cx)).await
}

#[tokio::test]
async fn accept_and_roundtrip_one_message() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TcpAcceptor::from_std(listener).unwrap();

    let client = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
    });

    let (mut transport, _peer) = std::future::poll_fn(|cx| acceptor.poll_accept(cx))
        .await
        .unwrap();

    let mut buf = [0u8; 16];
    let n = read_once(&mut transport, &mut buf).await.unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"ping");

    client.await.unwrap();
}

#[tokio::test]
async fn local_addr_reports_the_resolved_port() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acceptor = TcpAcceptor::from_std(listener).unwrap();
    assert_ne!(acceptor.local_addr().port(), 0);
}

#[tokio::test]
async fn peer_addr_survives_peer_close() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TcpAcceptor::from_std(listener).unwrap();

    let client = tokio::spawn(async move {
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Close the client side so the server sees a peer reset.
        drop(client);
    });

    let (transport, _peer) = std::future::poll_fn(|cx| acceptor.poll_accept(cx))
        .await
        .unwrap();
    let captured = transport.peer_addr().unwrap();
    client.await.unwrap();

    // The transport's peer_addr() is captured at construction and survives the
    // client closing the connection.
    assert_eq!(transport.peer_addr().unwrap(), captured);
}

#[tokio::test]
async fn poll_shutdown_is_idempotent() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TcpAcceptor::from_std(listener).unwrap();

    let client = tokio::spawn(async move {
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Keep the client open until the server finishes the test.
        client
    });

    let (mut transport, _peer) = std::future::poll_fn(|cx| acceptor.poll_accept(cx))
        .await
        .unwrap();
    assert!(shutdown_write(&mut transport).await.is_ok());
    assert!(shutdown_write(&mut transport).await.is_ok());
    let _client = client.await.unwrap();
}

#[tokio::test]
async fn write_vectored_is_advertised() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TcpAcceptor::from_std(listener).unwrap();

    let client = tokio::spawn(async move {
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Keep the client open until the server finishes the test.
        client
    });

    let (transport, _peer) = std::future::poll_fn(|cx| acceptor.poll_accept(cx))
        .await
        .unwrap();
    assert!(IoWrite::is_write_vectored(&transport));
    let _client = client.await.unwrap();
}

#[tokio::test]
async fn task_handle_drop_aborts() {
    let spawner = Spawner::current().unwrap();
    let counter = Arc::new(AtomicU32::new(0));
    let counter2 = Arc::clone(&counter);

    let handle: TaskHandle<()> = spawner.spawn(async move {
        sleep(Duration::from_millis(200)).await;
        counter2.fetch_add(1, Ordering::Relaxed);
    });
    drop(handle);

    sleep(Duration::from_millis(400)).await;
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn task_handle_detach_keeps_running() {
    let spawner = Spawner::current().unwrap();
    let counter = Arc::new(AtomicU32::new(0));
    let counter2 = Arc::clone(&counter);

    let handle: TaskHandle<()> = spawner.spawn(async move {
        sleep(Duration::from_millis(200)).await;
        counter2.fetch_add(1, Ordering::Relaxed);
    });
    handle.detach();

    sleep(Duration::from_millis(400)).await;
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn task_handle_join_maps_panic() {
    let spawner = Spawner::current().unwrap();
    let handle: TaskHandle<()> = spawner.spawn(async {
        panic!("deliberate test panic");
    });
    let result = handle.join().await;
    assert!(matches!(result, Err(TaskError::Panicked)));
}

#[tokio::test]
async fn task_handle_join_cancelled_still_aborts() {
    // `join()`'s future can be dropped before it resolves, for example raced
    // against a deadline, which is exactly the shape `conn-graceful-drain`
    // (#18) is named for: wait a bounded time per connection task, then move
    // on. That must abort the task, not silently detach it while it still
    // holds a `TcpTransport` and its file descriptor.
    let spawner = Spawner::current().unwrap();
    let counter = Arc::new(AtomicU32::new(0));
    let counter2 = Arc::clone(&counter);

    let handle: TaskHandle<()> = spawner.spawn(async move {
        sleep(Duration::from_millis(200)).await;
        counter2.fetch_add(1, Ordering::Relaxed);
    });

    // The task sleeps 200ms; give join() only 20ms, so with_timeout's internal
    // select drops the join() future well before the task finishes.
    let joined = with_timeout(Duration::from_millis(20), handle.join()).await;
    assert!(joined.is_err(), "join() should not have resolved in 20ms");

    // Wait past the task's original 200ms sleep. If join() detached the task
    // instead of aborting it, the counter reaches 1 here.
    sleep(Duration::from_millis(400)).await;
    assert_eq!(
        counter.load(Ordering::Relaxed),
        0,
        "a join() future dropped before it resolved must abort the task, not detach it"
    );
}

#[tokio::test]
async fn with_timeout_prefers_ready_future() {
    let result = with_timeout(Duration::ZERO, async { 7 }).await;
    assert_eq!(result, Ok(7));
}

#[tokio::test]
async fn with_timeout_reports_budget() {
    let result = with_timeout(Duration::from_millis(20), pending::<()>()).await;
    assert_eq!(result, Err(TimedOut { millis: 20 }));
}

#[tokio::test]
async fn connect_tcp_reaches_a_listener() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TcpAcceptor::from_std(listener).unwrap();

    let connecting = tokio::spawn(async move { irontraffic_io::net::connect_tcp(addr).await });

    let (_accepted, _peer) = std::future::poll_fn(|cx| acceptor.poll_accept(cx))
        .await
        .unwrap();

    let connected = connecting.await.unwrap().unwrap();
    assert_eq!(connected.peer_addr().unwrap(), addr);
}
