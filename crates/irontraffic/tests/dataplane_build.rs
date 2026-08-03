// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests that exercise the data-plane-only feature configuration and prove the
//! full and trimmed builds behave as specified.

mod support;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// The request every test that does not care about its exact bytes sends.
const HELLO_REQUEST: &[u8] = b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n";

/// The response `cfg_yaml`'s origin produces for [`HELLO_REQUEST`], byte for byte.
const HELLO_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

/// A minimal valid configuration: one listener, one upstream, and short timeouts.
fn cfg_yaml(upstream_port: u16) -> String {
    format!(
        "apiVersion: irontraffic.io/v1\n\
         listeners:\n\
         \x20\x20- name: web\n\
         \x20\x20\x20\x20bind: \"127.0.0.1:0\"\n\
         upstream:\n\
         \x20\x20address: \"127.0.0.1:{upstream_port}\"\n\
         timeouts:\n\
         \x20\x20connect_ms: 2000\n\
         \x20\x20idle_ms: 5000\n\
         \x20\x20half_close_ms: 5000\n\
         shutdown:\n\
         \x20\x20graceful_timeout_ms: 2000\n\
         \x20\x20drain_jitter_ms: 10\n"
    )
}

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_irontraffic"));
    cmd.env_remove("IRONTRAFFIC_LOG");
    cmd
}

static FIXTURE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn; see support::connect for the same reasoning"
)]
fn connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set a bounded read timeout");
    stream
}

#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn; see support::send_hello for the same reasoning"
)]
fn send_hello(stream: &mut TcpStream) {
    stream.write_all(HELLO_REQUEST).expect("write the request");
}

#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn; see support::read_all for the same reasoning"
)]
fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .expect("read the response to EOF");
    out
}

/// Writes `contents` to a fresh fixture file and returns the path and its directory.
#[allow(
    dead_code,
    reason = "used only in the data-plane-only test configuration"
)]
#[allow(
    clippy::expect_used,
    reason = "test-support helper, not itself a #[test] fn; see support::write_fixture for the same reasoning"
)]
fn write_fixture(contents: &str) -> (PathBuf, PathBuf) {
    let pid = std::process::id();
    let counter = FIXTURE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("irontraffic-dataplane-{pid}-{counter}"));
    std::fs::create_dir_all(&dir).expect("create fixture directory");
    let path = dir.join("cfg.yaml");
    std::fs::write(&path, contents).expect("write fixture file");
    (path, dir)
}

/// 1. `run_mode_matches_the_build`.
///
/// `free_local_port()`'s result in both arms below is always the config's UPSTREAM
/// address, never a port either arm binds itself, so neither is the "binds a real
/// listener on the returned port immediately" shape this crate's `free_local_port`
/// audit (see the commit that introduced `dead_local_port`) classified them as. What
/// actually makes each arm safe from issue #888's race differs:
/// - control-plane arm (below): a live `run`-mode proxy dials this dead upstream
///   exactly once, from `spawn_proxy_with_mode`'s own readiness probe, at the moment
///   its listener first answers (see `support::Origin::start`'s doc comment on why a
///   bare connect-then-close probe still reaches the upstream dial). That is the same
///   narrow, child-startup-scale window issue #888 itself scopes out as an accepted
///   residual (the `free_local_port` to child-bind race for the LISTEN port; see the
///   issue's "Proposed fix" section), not the whole-test-body exposure this PR's fix
///   closes elsewhere: no other connection ever reaches this proxy in the 500 ms it
///   runs before `shutdown()`.
/// - dataplane-only arm (below): the binary rejects `run` with exit code 2 before it
///   ever reaches the bind/dial logic, so this port is never touched by anything.
#[test]
fn run_mode_matches_the_build() {
    #[cfg(feature = "control-plane")]
    {
        let proxy = support::spawn_proxy_with_mode(&cfg_yaml(support::free_local_port()), "run");

        std::thread::sleep(Duration::from_millis(500));
        let status = proxy.shutdown();
        assert_eq!(status.code(), Some(0));
    }

    #[cfg(not(feature = "control-plane"))]
    {
        let (path, dir) = write_fixture(&cfg_yaml(support::free_local_port()));
        let output = bin()
            .arg("run")
            .arg("--config")
            .arg(&path)
            .output()
            .expect("run the binary");

        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--features dataplane"), "stderr: {stderr}");
        assert!(stderr.contains("proxy"), "stderr: {stderr}");
        assert!(output.stdout.is_empty(), "stdout must be empty");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// 2. `control_mode_matches_the_build`.
///
/// `free_local_port()`'s result in both arms below is, again, only ever the config's
/// upstream address, and control mode never binds a listener or dials an upstream at
/// all (see `control_mode_binds_nothing_and_exits_zero`'s doc comment in smoke.rs), so
/// this port is inert in the control-plane arm. The trimmed-build arm additionally
/// exits with an error before ever reaching that logic, the same as
/// `run_mode_matches_the_build`'s own trimmed-build arm above.
#[test]
fn control_mode_matches_the_build() {
    #[cfg(feature = "control-plane")]
    {
        let cfg = cfg_yaml(support::free_local_port());
        let (mut child, dir) = support::spawn_binary(&cfg, "control");
        let (status, _stderr) =
            support::wait_for_exit_capturing_stderr(&mut child, Duration::from_secs(5));

        assert_eq!(status.code(), Some(0));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(feature = "control-plane"))]
    {
        let cfg = cfg_yaml(support::free_local_port());
        let (mut child, dir) = support::spawn_binary(&cfg, "control");
        let (status, stderr) =
            support::wait_for_exit_capturing_stderr(&mut child, Duration::from_secs(5));

        assert_eq!(status.code(), Some(2));
        assert!(stderr.contains("control"), "stderr: {stderr}");
        assert!(stderr.contains("proxy"), "stderr: {stderr}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// 3. `proxy_and_validate_are_identical_in_both_builds`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_and_validate_are_identical_in_both_builds() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let example = manifest
        .parent()
        .expect("crate dir")
        .parent()
        .expect("workspace dir")
        .join("examples")
        .join("minimal.yaml");

    let validate = bin()
        .arg("validate")
        .arg("--config")
        .arg(&example)
        .output()
        .expect("run validate");
    assert_eq!(validate.status.code(), Some(0), "validate: {validate:?}");
    assert!(validate.stderr.is_empty(), "validate stderr: {validate:?}");

    let origin = support::Origin::start("hello").await;
    let proxy = support::spawn_proxy(&cfg_yaml(origin.addr.port()));

    let mut client = connect(proxy.addr);
    send_hello(&mut client);
    let response = read_all(&mut client);

    assert_eq!(response, HELLO_RESPONSE);
    assert_eq!(origin.hits(), 1);

    proxy.shutdown();
    origin.stop().await;
}

/// 4. `usage_text_matches_the_build`.
#[test]
fn usage_text_matches_the_build() {
    let output = bin().arg("--help").output().expect("run --help");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("--version"), "stdout: {stdout}");
    assert!(stdout.contains("--help"), "stdout: {stdout}");
    assert!(stdout.contains("validate"), "stdout: {stdout}");
    assert!(stdout.contains("proxy"), "stdout: {stdout}");

    // The words "run" and "control" must appear on their own usage lines in the
    // full build and must not appear on those lines in the trimmed build.
    #[cfg(feature = "control-plane")]
    {
        assert!(stdout.contains("irontraffic run      "), "stdout: {stdout}");
        assert!(stdout.contains("irontraffic control  "), "stdout: {stdout}");
    }
    #[cfg(not(feature = "control-plane"))]
    {
        assert!(
            !stdout.contains("irontraffic run      "),
            "stdout: {stdout}"
        );
        assert!(
            !stdout.contains("irontraffic control  "),
            "stdout: {stdout}"
        );
    }
}
