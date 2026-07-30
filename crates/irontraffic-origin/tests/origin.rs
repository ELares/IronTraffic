// SPDX-License-Identifier: MIT OR Apache-2.0
//! Behaviour and zero-allocation tests for `it-origin`, driving a real
//! listener on an ephemeral port, per issue #409's Tests section.
//!
//! Most tests start the server in-process, via `irontraffic_origin::serve::start`,
//! and drive it over a real loopback `TcpStream`: this crate's own test
//! binary is the client, `serve::start` is the server, and the two talk
//! actual TCP. Two tests (`accept_emfile_does_not_spin` and
//! `slowloris_head_is_closed_on_the_deadline`) instead spawn the compiled
//! `it-origin` binary as a real child process, because both need to observe
//! or bound *the origin's own* CPU time or file-descriptor limit distinctly
//! from the test harness's, which an in-process server cannot give them.
//!
//! This file is under `tests/`, which `scripts/invariant-lints.sh`'s
//! `rust_non_test_files()` excludes from the `determinism-seam` scan (see
//! `serve.rs`'s module doc comment): every wall-clock assertion below is a
//! deliberate, real measurement of the origin's own timing behaviour, which
//! is the thing several of these tests exist to prove.
//!
//! `origin_self_test` (test 16) installs a counting global allocator below,
//! which needs an `impl` of `GlobalAlloc` that is necessarily marked
//! `unsafe`; `[workspace.lints.rust]`'s `unsafe_code = "deny"` (not
//! `forbid`) is what makes allowing it locally, with a written reason,
//! legal. This crate-root inner attribute must precede every other item in
//! the file, which is why it is here rather than next to the allocator
//! itself.
#![allow(
    unsafe_code,
    reason = "a GlobalAlloc trait impl is necessarily marked unsafe, and is unavoidable for the counting global allocator origin_self_test needs; see that section's comment"
)] // it-allow: no-unsafe reason: a GlobalAlloc trait impl is necessarily marked unsafe and is unavoidable for a global allocator; workspace lints deny (not forbid) unsafe_code specifically so this inner allow is legal, and origin_self_test needs its own counting allocator to prove zero per-request heap allocation

use irontraffic_origin::config::{DelayDist, OriginConfig};
use irontraffic_origin::serve::{self, Origin};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// A config with every field at a sensible, explicit default, so each test
/// only names the fields it cares about.
fn base_config() -> OriginConfig {
    OriginConfig {
        listen: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
        body_bytes: 1024,
        status: 200,
        delay_us: 0,
        delay_dist: DelayDist::None,
        sequence: false,
        workers: 2,
        max_connections: 200_000,
        head_timeout_ms: 10_000,
        idle_timeout_ms: 60_000,
        stats_listen: None,
    }
}

/// Raises this process's own `RLIMIT_NOFILE` soft limit to its hard limit
/// (or a generous fallback), once. `cargo test` runs every test in this
/// file concurrently, on many threads, in one process, and some platforms'
/// default per-process descriptor limit for a freshly spawned process (256,
/// observed on this workspace's macOS development environment, regardless
/// of what an interactive shell's own `ulimit -n` reports) is comfortably
/// exhausted by that much concurrency, well before any individual test's
/// own descriptor use is unreasonable. Best-effort: a failure here is not
/// this test suite's to solve, and is left for whichever assertion below
/// then actually fails to say why.
fn ensure_high_fd_limit() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let limits = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        let target = limits.maximum.unwrap_or(65_536).min(65_536);
        if limits.current.unwrap_or(0) < target {
            let raised = rustix::process::Rlimit {
                current: Some(target),
                maximum: limits.maximum,
            };
            let _ = rustix::process::setrlimit(rustix::process::Resource::Nofile, raised); // it-allow: no-swallowed-error reason: best-effort; a platform that refuses this leaves the original limit in place and the tests fail with their own clear "too many open files" message instead
        }
    });
}

/// Starts an in-process origin. Returns the `serve::start` error rather than
/// panicking: `clippy::expect_used`'s test-code exemption applies to
/// functions carrying `#[test]` themselves, not to a plain helper a test
/// merely calls, so every call site unwraps with its own `.expect(...)`,
/// which IS inside a `#[test]` function and is where the exemption applies.
async fn start(config: OriginConfig) -> std::io::Result<Origin> {
    ensure_high_fd_limit();
    serve::start(config).await
}

/// See `start`'s doc comment for why this returns a `Result` instead of
/// panicking internally.
async fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    TcpStream::connect(addr).await
}

/// One parsed HTTP/1.1 response.
#[derive(Debug, Default, Clone)]
struct RawResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RawResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn header_count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .count()
    }
}

/// Reads one HTTP/1.1 response from `stream`. `carry` holds bytes already
/// read but not yet consumed (leftover from a previous pipelined read) on
/// the way in, and is left holding whatever belongs to the *next* response
/// on the way out. `None` on a clean EOF before a complete response arrives.
async fn read_response(stream: &mut TcpStream, carry: &mut Vec<u8>) -> Option<RawResponse> {
    loop {
        if let Some(pos) = memchr::memmem::find(carry, b"\r\n\r\n") {
            let head_end = pos.saturating_add(4);
            let head_bytes = carry.get(..head_end).unwrap_or(&[]);
            let head_text = String::from_utf8_lossy(head_bytes).into_owned();
            let mut lines = head_text.split("\r\n");
            let status_line = lines.next().unwrap_or_default();
            let status: u16 = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|word| word.parse().ok())
                .unwrap_or(0);

            let mut headers = Vec::new();
            let mut content_length: usize = 0;
            for line in lines {
                if line.is_empty() {
                    continue;
                }
                if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim().to_owned();
                    let value = value.trim().to_owned();
                    if key.eq_ignore_ascii_case("content-length") {
                        content_length = value.parse().unwrap_or(0);
                    }
                    headers.push((key, value));
                }
            }

            let total_needed = head_end.saturating_add(content_length);
            while carry.len() < total_needed {
                let mut chunk = [0u8; 8192];
                let n = stream.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                carry.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            }
            let body = carry.get(head_end..total_needed).unwrap_or(&[]).to_vec();
            carry.drain(..total_needed.min(carry.len()));
            return Some(RawResponse {
                status,
                headers,
                body,
            });
        }

        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        carry.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    }
}

/// Sends `request` and reads exactly one response on a fresh carry buffer.
/// `None` if the write fails or the connection closes before a complete
/// response arrives; see `start`'s doc comment for why this is a `None`
/// rather than a panic.
async fn roundtrip(stream: &mut TcpStream, request: &[u8]) -> Option<RawResponse> {
    stream.write_all(request).await.ok()?;
    let mut carry = Vec::new();
    read_response(stream, &mut carry).await
}

// ---------------------------------------------------------------------------
// 1. serves_exact_body_size
// ---------------------------------------------------------------------------
#[tokio::test]
async fn serves_exact_body_size() {
    for size in [0u32, 1, 1024, 8192, 65536, 1_048_576] {
        let mut config = base_config();
        config.body_bytes = size;
        let origin = start(config).await.expect("origin starts");
        let mut stream = connect(origin.listen_addrs[0])
            .await
            .expect("connects to the origin");
        let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
            .await
            .expect("a response arrives");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body.len(),
            size as usize,
            "body length for size {size}"
        );
        assert_eq!(
            response.header("content-length"),
            Some(size.to_string()).as_deref(),
            "Content-Length for size {size}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. content_length_always_present
// ---------------------------------------------------------------------------
#[tokio::test]
async fn content_length_always_present() {
    let origin = start(base_config()).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    for _ in 0..5 {
        let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
            .await
            .expect("a response arrives");
        assert_eq!(response.header_count("content-length"), 1);
    }
}

// ---------------------------------------------------------------------------
// 3. status_code_is_configurable
// ---------------------------------------------------------------------------
#[tokio::test]
async fn status_code_is_configurable() {
    let mut config = base_config();
    config.status = 503;
    let origin = start(config).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 503);
    assert_eq!(response.body.len(), 1024);
}

#[test]
fn status_100_199_204_are_usage_errors() {
    for status in ["100", "199", "204"] {
        let err = OriginConfig::parse(&[
            std::ffi::OsString::from("--status"),
            std::ffi::OsString::from(status),
        ])
        .expect_err(&format!("--status {status} must be a usage error"));
        assert!(matches!(
            err,
            irontraffic_origin::config::ArgError::OutOfRange {
                flag: "--status",
                ..
            }
        ));
    }
}

#[test]
fn status_304_body_bytes_combination() {
    let err = OriginConfig::parse(&[
        std::ffi::OsString::from("--status"),
        std::ffi::OsString::from("304"),
        std::ffi::OsString::from("--body-bytes"),
        std::ffi::OsString::from("1024"),
    ])
    .expect_err("304 with a nonzero body must be a usage error");
    assert!(matches!(
        err,
        irontraffic_origin::config::ArgError::Conflict(_)
    ));

    let config = OriginConfig::parse(&[
        std::ffi::OsString::from("--status"),
        std::ffi::OsString::from("304"),
        std::ffi::OsString::from("--body-bytes"),
        std::ffi::OsString::from("0"),
    ])
    .expect("304 with a zero-byte body is accepted");
    assert_eq!(config.status, 304);
}

#[tokio::test]
async fn status_304_emits_no_content_length() {
    let mut config = base_config();
    config.status = 304;
    config.body_bytes = 0;
    let origin = start(config).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 304);
    assert_eq!(response.header("content-length"), None);
}

// ---------------------------------------------------------------------------
// 4. head_scan_finds_terminator_incrementally
// ---------------------------------------------------------------------------
#[tokio::test]
async fn head_scan_finds_terminator_incrementally() {
    let origin = start(base_config()).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let request = b"GET / HTTP/1.1\r\n\r\n";
    for &byte in request {
        stream.write_all(&[byte]).await.expect("write succeeds");
    }
    let mut carry = Vec::new();
    let response = read_response(&mut stream, &mut carry)
        .await
        .expect("exactly one response arrives after the final byte");
    assert_eq!(response.status, 200);
    assert!(carry.is_empty(), "no extra response arrived");
}

// ---------------------------------------------------------------------------
// 5. head_too_large_returns_431
// ---------------------------------------------------------------------------
#[tokio::test]
async fn head_too_large_returns_431() {
    let origin = start(base_config()).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let mut request = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
    while request.len() < 16_385 {
        request.extend_from_slice(b"a");
    }
    stream.write_all(&request).await.expect("write succeeds");
    let mut carry = Vec::new();
    let response = read_response(&mut stream, &mut carry)
        .await
        .expect("a 431 response arrives");
    assert_eq!(response.status, 431);

    // The connection is closed after the 431: a further read reaches EOF.
    let mut probe = [0u8; 1];
    let n = stream.read(&mut probe).await.unwrap_or(0);
    assert_eq!(n, 0, "connection is closed after 431");
}

// ---------------------------------------------------------------------------
// 6. hundred_headers_8kib
// ---------------------------------------------------------------------------
#[tokio::test]
async fn hundred_headers_8kib() {
    let origin = start(base_config()).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let mut request = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
    for i in 0..100u32 {
        request.extend_from_slice(
            format!("X-Filler-{i:03}: {:0width$}\r\n", i, width = 65).as_bytes(),
        );
    }
    request.extend_from_slice(b"\r\n");
    assert!(
        (8_000..8_400).contains(&request.len()),
        "fixture must actually reach ~8 KiB, got {} bytes",
        request.len()
    );
    let response = roundtrip(&mut stream, &request)
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 200);
}

// ---------------------------------------------------------------------------
// 7. duplicate_delay_header_first_wins
// ---------------------------------------------------------------------------
#[tokio::test]
async fn duplicate_delay_header_first_wins() {
    let origin = start(base_config()).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let request = b"GET / HTTP/1.1\r\nX-Origin-Delay-Us: 0\r\nX-Origin-Delay-Us: 50000\r\n\r\n";
    let started = Instant::now();
    let response = roundtrip(&mut stream, request)
        .await
        .expect("a response arrives");
    let elapsed = started.elapsed();
    assert_eq!(response.status, 200);
    assert!(
        elapsed < Duration::from_millis(10),
        "first occurrence (0) should win, not the second (50000us); took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. conflicting_content_length_returns_400
// ---------------------------------------------------------------------------
#[tokio::test]
async fn conflicting_content_length_returns_400() {
    let origin = start(base_config()).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let request = b"GET / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
    let response = roundtrip(&mut stream, request)
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 400);
}

// ---------------------------------------------------------------------------
// 9. chunked_request_returns_411
// ---------------------------------------------------------------------------
#[tokio::test]
async fn chunked_request_returns_411() {
    let origin = start(base_config()).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let request = b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    let response = roundtrip(&mut stream, request)
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 411);
}

// ---------------------------------------------------------------------------
// 10. delay_header_is_honoured_and_capped
// ---------------------------------------------------------------------------
#[tokio::test]
async fn delay_header_is_honoured_and_capped() {
    let origin = start(base_config()).await.expect("origin starts");

    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let started = Instant::now();
    let response = roundtrip(
        &mut stream,
        b"GET / HTTP/1.1\r\nX-Origin-Delay-Us: 20000\r\n\r\n",
    )
    .await
    .expect("a response arrives");
    let elapsed = started.elapsed();
    assert_eq!(response.status, 200);
    assert!(
        elapsed >= Duration::from_millis(20),
        "a 20000us delay must measure at least 20ms; took {elapsed:?}"
    );

    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let started = Instant::now();
    let response = roundtrip(
        &mut stream,
        b"GET / HTTP/1.1\r\nX-Origin-Delay-Us: 999999999\r\n\r\n",
    )
    .await
    .expect("a response arrives");
    let elapsed = started.elapsed();
    assert_eq!(response.status, 200);
    assert!(
        elapsed <= Duration::from_secs(6),
        "an absurd delay header must be capped at 5,000,000us, proving the cap; took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// 11. delay_does_not_block_other_connections
// ---------------------------------------------------------------------------
#[tokio::test]
async fn delay_does_not_block_other_connections() {
    let origin = start(base_config()).await.expect("origin starts");
    let addr = origin.listen_addrs[0];

    // Measured from before the slow task is even spawned, not just around
    // the fast loop below: on the single-threaded runtime `#[tokio::test]`
    // defaults to, a blocking sleep anywhere in the slow connection's task
    // seizes the one OS thread for its whole duration in one go, whichever
    // point in this sequence the scheduler happens to poll it at. Starting
    // the clock only around the fast loop let exactly this bug (a
    // `std::thread::sleep` substituted for `sleep_until`, watched to fail
    // during this test's own development) land entirely inside the
    // intentional 50ms head-start sleep instead, where it went unmeasured;
    // this is the fix for that, not merely a style preference.
    let started = Instant::now();

    let slow = tokio::spawn(async move {
        let mut stream = connect(addr).await.expect("connects to the origin");
        roundtrip(
            &mut stream,
            b"GET / HTTP/1.1\r\nX-Origin-Delay-Us: 500000\r\n\r\n",
        )
        .await
        .expect("a response arrives")
    });

    // Give the slow request a head start so it is genuinely in flight
    // (mid-sleep) while the fast connection below runs.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut fast_stream = connect(addr).await.expect("connects to the origin");
    for _ in 0..100 {
        let response = roundtrip(&mut fast_stream, b"GET / HTTP/1.1\r\n\r\n")
            .await
            .expect("a response arrives");
        assert_eq!(response.status, 200);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(250),
        "the 50ms head start plus 100 fast requests must complete well under \
         the slow connection's 500ms delay while it sleeps; took {elapsed:?}"
    );

    let slow_response = slow.await.expect("slow task does not panic");
    assert_eq!(slow_response.status, 200);
}

// ---------------------------------------------------------------------------
// 12. pipelined_requests_are_answered_in_order
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pipelined_requests_are_answered_in_order() {
    let mut config = base_config();
    config.sequence = true;
    let origin = start(config).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");

    let mut batch = Vec::new();
    for _ in 0..4 {
        batch.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
    }
    stream.write_all(&batch).await.expect("write succeeds");

    let mut carry = Vec::new();
    let mut seqs = Vec::new();
    for _ in 0..4 {
        let response = read_response(&mut stream, &mut carry)
            .await
            .expect("four responses arrive");
        assert_eq!(response.status, 200);
        let seq: u64 = response
            .header("x-origin-seq")
            .expect("sequence header present")
            .parse()
            .expect("sequence header is numeric");
        seqs.push(seq);
    }
    assert_eq!(seqs, vec![0, 1, 2, 3], "responses arrive in order");

    // The connection stays open: one more request still gets an answer.
    let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 200);
}

// ---------------------------------------------------------------------------
// 13. sequence_numbers_are_monotone_and_unique
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sequence_numbers_are_monotone_and_unique() {
    const CONNECTIONS: usize = 8;
    const PER_CONNECTION: usize = 1_250; // 8 * 1250 = 10,000

    let mut config = base_config();
    config.sequence = true;
    let origin = start(config).await.expect("origin starts");
    let addr = origin.listen_addrs[0];

    let mut tasks = Vec::new();
    for _ in 0..CONNECTIONS {
        tasks.push(tokio::spawn(async move {
            let mut stream = connect(addr).await.expect("connects to the origin");
            let mut batch = Vec::new();
            for _ in 0..PER_CONNECTION {
                batch.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
            }
            stream.write_all(&batch).await.expect("write succeeds");

            let mut carry = Vec::new();
            let mut seqs = Vec::with_capacity(PER_CONNECTION);
            for _ in 0..PER_CONNECTION {
                let response = read_response(&mut stream, &mut carry)
                    .await
                    .expect("a response arrives");
                let seq: u64 = response
                    .header("x-origin-seq")
                    .expect("sequence header present")
                    .parse()
                    .expect("sequence header is numeric");
                seqs.push(seq);
            }
            seqs
        }));
    }

    let mut all_seqs: Vec<u64> = Vec::with_capacity(CONNECTIONS * PER_CONNECTION);
    for task in tasks {
        all_seqs.extend(task.await.expect("connection task does not panic"));
    }

    assert_eq!(all_seqs.len(), 10_000);
    let unique: HashSet<u64> = all_seqs.iter().copied().collect();
    assert_eq!(unique.len(), 10_000, "no sequence number repeats");
    let expected: HashSet<u64> = (0..10_000u64).collect();
    assert_eq!(
        unique, expected,
        "the collected set is exactly {{0, 1, ..., 9999}}"
    );
}

// ---------------------------------------------------------------------------
// 14. stats_endpoint_reconciles
// ---------------------------------------------------------------------------
#[tokio::test]
async fn stats_endpoint_reconciles() {
    let mut config = base_config();
    config.body_bytes = 256;
    config.stats_listen = Some(SocketAddr::from(([127, 0, 0, 1], 0)));

    // Computed independently of the running server, via the same response
    // module it uses internally, so the expected byte count below is a
    // value pinned against `response.rs`'s own construction, never against
    // an expression built out of the `bytes` counter this test is checking.
    let expected_head_len = irontraffic_origin::response::ResponseArena::new(&config).head_len();
    let expected_bytes_per_response = expected_head_len + 256;

    let origin = start(config).await.expect("origin starts");
    let main_addr = origin.listen_addrs[0];
    let stats_addr = origin.stats_addr.expect("stats listener is configured");

    let mut stream = connect(main_addr).await.expect("connects to the origin");
    for _ in 0..5_000 {
        let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
            .await
            .expect("a response arrives");
        assert_eq!(response.status, 200);
        assert_eq!(response.body.len(), 256);
    }

    let mut stats_stream = connect(stats_addr).await.expect("connects to the origin");
    let response = roundtrip(&mut stats_stream, b"GET /stats HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 200);
    let json = String::from_utf8(response.body).expect("stats body is UTF-8 JSON");

    let requests = json_number(&json, "requests").expect("requests key present");
    let bytes = json_number(&json, "bytes").expect("bytes key present");
    assert_eq!(requests, 5_000, "stats: {json}");
    assert_eq!(
        bytes,
        5_000 * u64::try_from(expected_bytes_per_response).unwrap_or(u64::MAX),
        "stats: {json}, expected head_len {expected_head_len} + body_bytes 256 per response"
    );
}

/// A minimal `"key":N` extractor for this fixture's own fixed-shape JSON.
/// Not a general JSON parser: `it-origin` emits exactly one shape, and
/// pulling in a JSON crate for a test that reads four integer fields would
/// be disproportionate.
/// `None` when `key` is not present; see `start`'s doc comment for why this
/// does not panic internally.
fn json_number(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = json.get(start..).unwrap_or("");
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..end).unwrap_or("0").parse().ok()
}

// ---------------------------------------------------------------------------
// 14b. stats_endpoint_does_not_inflate_its_own_counters
//
// `GET /stats` responses must not be counted in the SAME `requests`/`bytes`
// counters the endpoint exists to let a harness reconcile against the main
// listener's own traffic. Before this fix, the stats listener's own
// response fell through to the same `shared.counters.add_request(...)` call
// the main listener uses, so a harness that polls `/stats` more than once
// during a run would see `requests` inflated by exactly the number of prior
// polls, with zero main-listener traffic ever having occurred.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn stats_endpoint_does_not_inflate_its_own_counters() {
    let mut config = base_config();
    config.stats_listen = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
    let origin = start(config).await.expect("origin starts");
    let stats_addr = origin.stats_addr.expect("stats listener is configured");

    // Three successive stats queries, zero main-listener traffic at any
    // point: `requests` must read 0 every single time.
    for query in 0..3 {
        let mut stream = connect(stats_addr).await.expect("connects to the origin");
        let response = roundtrip(&mut stream, b"GET /stats HTTP/1.1\r\n\r\n")
            .await
            .expect("a response arrives");
        assert_eq!(response.status, 200);
        let json = String::from_utf8(response.body).expect("stats body is UTF-8 JSON");
        assert_eq!(
            json_number(&json, "requests").expect("requests key present"),
            0,
            "query {query}: stats: {json}"
        );
    }
}

// ---------------------------------------------------------------------------
// 22b. stats_404_connection_is_actually_closed
//
// The stats listener's 404 response advertises `Connection: close`
// (`RESPONSE_404`, the same preallocated constant the main listener's error
// paths use). Before this fix, the `Role::Stats` branch wrote that response
// and then fell through to loop again for another request on the SAME
// connection instead of closing it, so a client that honours the framing it
// was told and reads to EOF would stall for the full idle timeout instead
// of seeing the close it was promised.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn stats_404_connection_is_actually_closed() {
    let mut config = base_config();
    config.stats_listen = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
    let origin = start(config).await.expect("origin starts");
    let stats_addr = origin.stats_addr.expect("stats listener is configured");

    let mut stream = connect(stats_addr).await.expect("connects to the origin");
    let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 404);
    assert_eq!(response.header("connection"), Some("close"));

    let mut probe = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut probe))
        .await
        .expect("the connection closes within the safety window")
        .expect("a clean EOF, not a read error");
    assert_eq!(
        n, 0,
        "a 404 that advertises Connection: close must actually close the connection"
    );
}

// ---------------------------------------------------------------------------
// 17. max_connections_is_enforced_and_released
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_connections_is_enforced_and_released() {
    let mut config = base_config();
    config.max_connections = 32;
    config.stats_listen = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
    let origin = start(config).await.expect("origin starts");
    let main_addr = origin.listen_addrs[0];
    let stats_addr = origin.stats_addr.expect("stats listener is configured");

    let mut streams = Vec::new();
    for _ in 0..64 {
        streams.push(connect(main_addr).await.expect("connects to the origin"));
    }
    // Let the admission gate settle: every accept has been decided.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut still_open = 0usize;
    let mut closed = 0usize;
    for stream in &mut streams {
        let mut probe = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut probe)).await {
            Ok(Ok(0) | Err(_)) => closed += 1,
            Ok(Ok(_)) | Err(_) => still_open += 1,
        }
    }
    assert_eq!(still_open, 32, "exactly 32 connections stay open");
    assert_eq!(closed, 32, "the other 32 are closed immediately");

    // `accept` is still responsive: one more connection is accepted and
    // closed rather than left to time out. Checked here, while the 32 slots
    // are still occupied, is the only place this actually proves anything
    // about the bound; a stats query needs its own slot from the very same
    // shared gate (per the Design section), so it is deferred to after
    // every main connection below has been dropped and the gate has room.
    let mut probe_stream = connect(main_addr).await.expect("connects to the origin");
    let mut probe = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), probe_stream.read(&mut probe)).await;
    assert!(
        matches!(result, Ok(Ok(0))),
        "a 65th connection is accepted-then-closed rather than left hanging: {result:?}"
    );

    drop(streams);
    drop(probe_stream);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // rejects is monotonic and already carries every rejection recorded
    // above: 32 from the initial wave of 64, plus 1 from the 65th probe.
    let mut stats_stream = connect(stats_addr).await.expect("connects to the origin");
    let response = roundtrip(&mut stats_stream, b"GET /stats HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    let json = String::from_utf8(response.body).expect("stats body is UTF-8 JSON");
    assert_eq!(
        json_number(&json, "rejects").expect("rejects key present"),
        33,
        "stats: {json}"
    );
    // The stats connection shares the very same admission gate (per the
    // Design section): dropped before reopening 32 fresh main connections,
    // or it would itself occupy one of those 32 slots.
    drop(stats_stream);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut reopened = Vec::new();
    for _ in 0..32 {
        reopened.push(connect(main_addr).await.expect("connects to the origin"));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut reopened_open = 0usize;
    for stream in &mut reopened {
        let mut probe = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut probe)).await {
            Ok(Ok(_)) | Err(_) => reopened_open += 1,
            Ok(Err(_)) => {}
        }
    }
    assert_eq!(
        reopened_open, 32,
        "once every prior client disconnects, the live count returns to 0 and a fresh 32 fit"
    );
}

// ---------------------------------------------------------------------------
// 19. idle_keepalive_is_closed_on_the_deadline
// ---------------------------------------------------------------------------
#[tokio::test]
async fn idle_keepalive_is_closed_on_the_deadline() {
    let mut config = base_config();
    config.idle_timeout_ms = 500;
    let origin = start(config).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 200);

    let started = Instant::now();
    let mut probe = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut probe))
        .await
        .expect("the connection closes within the safety window")
        .expect("a clean EOF, not a read error");
    let elapsed = started.elapsed();
    assert_eq!(n, 0);
    assert!(
        elapsed >= Duration::from_millis(450) && elapsed <= Duration::from_millis(1500),
        "closed at {elapsed:?}, expected between 500 and 1500ms"
    );
}

// ---------------------------------------------------------------------------
// 19b. head_timeout_bounds_every_head_not_only_the_first
//
// `--head-timeout-ms` must bound EVERY request's head on a keepalive
// connection, not only the connection's first one. Before this fix, the
// second and every later request's head-reading loop reused a single
// deadline variable last set to `now + idle_timeout` after the previous
// response, so a slowloris that completes one trivial request and then
// trickles its next head got the (typically much longer) idle timeout to
// finish it, not the head timeout.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn head_timeout_bounds_every_head_not_only_the_first() {
    let mut config = base_config();
    config.head_timeout_ms = 400;
    config.idle_timeout_ms = 5_000;
    let origin = start(config).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");

    // Complete one full request first, so the connection is genuinely on
    // its SECOND request when the partial head below is sent.
    let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 200);

    // Now send a partial second head and stop.
    let started = Instant::now();
    stream
        .write_all(b"GET / HTTP/1.1\r\n")
        .await
        .expect("write succeeds");
    let mut probe = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut probe))
        .await
        .expect("the connection closes within the safety window")
        .expect("a clean EOF, not a read error");
    let elapsed = started.elapsed();
    assert_eq!(n, 0);
    assert!(
        elapsed >= Duration::from_millis(350) && elapsed <= Duration::from_millis(1500),
        "the connection's SECOND request must be bound by --head-timeout-ms \
         (400ms), not --idle-timeout-ms (5000ms); closed at {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// 20. byte_at_a_time_head_is_linear
// ---------------------------------------------------------------------------
// Two measured facts drove this test's shape (do not "simplify" either
// choice away without re-measuring):
//
// 1. `set_nodelay(true)` on the client stream, BY ITSELF, changed nothing:
//    the examined-byte count stayed at ~16,693 either way. The client's own
//    Nagle behaviour turned out not to be the bottleneck.
// 2. Switching this test from the single-threaded default `#[tokio::test]`
//    flavor to `multi_thread` is what actually mattered, because on the
//    default single-threaded runtime the client's writer loop and the
//    server's reader task are cooperatively scheduled on the SAME OS thread:
//    a loopback `write_all` of one byte very rarely blocks, so the writer
//    loop runs to completion, handing off all 16,384 bytes, before the
//    executor ever gets a chance to poll the server's read future -- which
//    then drains everything already sitting in the socket buffer in one or
//    two reads (measured: ~16,693 bytes examined, barely above one pass).
//    `multi_thread` lets the reader genuinely run on a second OS thread,
//    concurrently with the writer, so more of the 16,384 writes are
//    actually observed by a `read()` before the next one lands. Measured
//    over three runs after switching: 29,805 / 27,787 / 29,620 bytes
//    examined, roughly 1.7x this test's own former single-threaded number.
//    Real, verified movement toward the "delivered incrementally" regime
//    this test's own name promises, though (being a genuine OS thread race,
//    not a deterministic mechanism) still short of the four-H-minus-six
//    ceiling a client that could force one-byte reads deterministically
//    would reach. `set_nodelay(true)` is kept anyway: it costs nothing and
//    rules out the client's OWN transmission batching as a contributing
//    factor, even though it was not, on its own, the fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_at_a_time_head_is_linear() {
    // One well-formed header line, padded with a single long value, rather
    // than many repeated short lines truncated at an arbitrary byte offset:
    // truncating mid-line would leave a malformed fragment right before the
    // terminator and the origin would correctly (but unhelpfully, for this
    // fixture) answer 400 instead of the 200 this test needs to observe.
    const PREFIX: &[u8] = b"GET / HTTP/1.1\r\nX-Pad: ";
    const SUFFIX: &[u8] = b"\r\n\r\n";

    let origin = start(base_config()).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    stream.set_nodelay(true).expect("sets TCP_NODELAY");

    let padding_len = 16_384 - PREFIX.len() - SUFFIX.len();
    let mut request = Vec::with_capacity(16_384);
    request.extend_from_slice(PREFIX);
    request.extend(std::iter::repeat_n(b'a', padding_len));
    request.extend_from_slice(SUFFIX);
    assert_eq!(
        request.len(),
        16_384,
        "fixture must reach the full 16 KiB head"
    );

    let before = origin.scan_probe_bytes_examined();
    for &byte in &request {
        stream.write_all(&[byte]).await.expect("write succeeds");
    }
    let mut carry = Vec::new();
    let response = read_response(&mut stream, &mut carry)
        .await
        .expect("a response arrives after the final byte");
    assert_eq!(response.status, 200);
    let after = origin.scan_probe_bytes_examined();

    let examined = after - before;
    assert!(
        examined <= 4 * 16_384,
        "byte-at-a-time terminator search examined {examined} bytes, expected at most {}",
        4 * 16_384
    );
}

// ---------------------------------------------------------------------------
// 21. content_length_with_transfer_encoding_is_400
// ---------------------------------------------------------------------------
#[tokio::test]
async fn content_length_with_transfer_encoding_is_400() {
    let origin = start(base_config()).await.expect("origin starts");

    let cases: [&[u8]; 4] = [
        b"GET / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
        b"GET / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: identity\r\n\r\n",
        b"GET / HTTP/1.1\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\n\r\n",
    ];
    for request in cases {
        let mut stream = connect(origin.listen_addrs[0])
            .await
            .expect("connects to the origin");
        let response = roundtrip(&mut stream, request)
            .await
            .expect("a response arrives");
        assert_eq!(
            response.status,
            400,
            "request: {:?}",
            String::from_utf8_lossy(request)
        );
    }
}

// ---------------------------------------------------------------------------
// 21b. content_length_with_transfer_encoding_non_canonical_forms_is_400
//
// Pins, over a REAL socket against the running server (not just a direct
// `scan_head` call), that the smuggling refusal fires on the non-canonical
// spellings a lenient parser tends to miss: whitespace before the colon
// (both space and tab), mixed case, a duplicated `Transfer-Encoding` line,
// and an obs-fold continuation. Every case here answered 200 before the
// parsing fix (`Invariant 8` violated), because the header name comparison
// either carried the extra whitespace or the continuation line was parsed
// as an unrecognised header of its own.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn content_length_with_transfer_encoding_non_canonical_forms_is_400() {
    let origin = start(base_config()).await.expect("origin starts");

    let cases: [&[u8]; 5] = [
        // Space before the colon.
        b"GET / HTTP/1.1\r\nTransfer-Encoding : chunked\r\nContent-Length: 5\r\n\r\n",
        // Tab before the colon.
        b"GET / HTTP/1.1\r\nTransfer-Encoding\t: chunked\r\nContent-Length: 5\r\n\r\n",
        // Mixed case.
        b"GET / HTTP/1.1\r\ntRaNsFeR-EnCoDiNg: chunked\r\nContent-Length: 5\r\n\r\n",
        // Duplicated Transfer-Encoding lines.
        b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
        // Obs-fold continuation line.
        b"GET / HTTP/1.1\r\nContent-Length: 5\r\n Transfer-Encoding: chunked\r\n\r\n",
    ];
    for request in cases {
        let mut stream = connect(origin.listen_addrs[0])
            .await
            .expect("connects to the origin");
        let response = roundtrip(&mut stream, request)
            .await
            .expect("a response arrives");
        assert_eq!(
            response.status,
            400,
            "request: {:?}",
            String::from_utf8_lossy(request)
        );
    }
}

// ---------------------------------------------------------------------------
// 21c. bare_lf_line_terminator_is_rejected_over_the_wire
//
// The exact request-smuggling reproduction: bare LF (no CR) between the
// request line and each header used to collapse this parser's CRLF-only
// line splitting, hiding BOTH `Content-Length` and `Transfer-Encoding` and
// answering 200 with `content_length: 0` -- so the 5 declared body bytes
// the client actually sends would have been read back as the start of the
// next pipelined request on this same connection.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn bare_lf_line_terminator_is_rejected_over_the_wire() {
    let origin = start(base_config()).await.expect("origin starts");
    let mut stream = connect(origin.listen_addrs[0])
        .await
        .expect("connects to the origin");
    let request = b"POST / HTTP/1.1\nContent-Length: 5\nTransfer-Encoding: chunked\r\n\r\n";
    let response = roundtrip(&mut stream, request)
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 400);
}

// ---------------------------------------------------------------------------
// 22. stats_listener_answers_only_get_stats
// ---------------------------------------------------------------------------
#[tokio::test]
async fn stats_listener_answers_only_get_stats() {
    let mut config = base_config();
    config.stats_listen = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
    let origin = start(config).await.expect("origin starts");
    let stats_addr = origin.stats_addr.expect("stats listener is configured");

    let mut stream = connect(stats_addr).await.expect("connects to the origin");
    let response = roundtrip(&mut stream, b"GET /stats HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 200);
    assert!(
        response
            .header("content-type")
            .unwrap_or_default()
            .contains("json")
    );

    let mut stream = connect(stats_addr).await.expect("connects to the origin");
    let response = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    assert_eq!(response.status, 404);

    let mut stream = connect(stats_addr).await.expect("connects to the origin");
    let response = roundtrip(
        &mut stream,
        b"POST /stats HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    )
    .await
    .expect("a response arrives");
    assert_eq!(response.status, 404);

    // A 20 KiB head: closes per the same 431 rule as the main listener, and
    // must not panic (the surrounding `#[tokio::test]` would report a panic
    // as a test failure either way, which is the check).
    let mut stream = connect(stats_addr).await.expect("connects to the origin");
    let mut request = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
    while request.len() < 20_480 {
        request.extend_from_slice(b"a");
    }
    stream.write_all(&request).await.expect("write succeeds");
    let mut carry = Vec::new();
    let response = read_response(&mut stream, &mut carry).await;
    if let Some(response) = response {
        assert_eq!(response.status, 431);
    }
}

// ---------------------------------------------------------------------------
// 16. origin_self_test
// ---------------------------------------------------------------------------
//
// A counting global allocator, declared in this file and nowhere else. It
// needs an `impl` of `GlobalAlloc`, necessarily marked `unsafe`, which
// `[workspace.lints.rust]`'s `unsafe_code = "deny"` (not `forbid`) makes
// legal to allow locally with a written reason, per the crate-root
// `#![allow(unsafe_code, ...)]` at the top of this file (an inner attribute
// must precede every other item in its scope, so it cannot live down here
// next to the code it covers).
//
// The counter is THREAD-LOCAL, not a single process-wide atomic: `cargo
// test` runs every test in this file concurrently, on multiple threads, in
// one process, and a process-wide counter would attribute other tests'
// concurrent allocations to this one, making "exactly 0 after the first
// request" flaky by construction. This test instead runs its whole
// scenario (starting the origin, connecting, and driving 10,000 requests)
// on one dedicated OS thread with its own single-threaded Tokio runtime, so
// the thread-local counter it reads back is exactly this scenario's own
// allocation count, unaffected by whatever any other concurrently running
// test allocates on its own thread.

struct CountingAllocator;

thread_local! {
    static THREAD_ALLOCATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn thread_allocations() -> u64 {
    THREAD_ALLOCATIONS.with(std::cell::Cell::get)
}

// SAFETY: every method below delegates to `System`, the platform's default
// allocator, which is a correct `GlobalAlloc` implementation on its own;
// this wrapper only increments a thread-local counter around each call and
// changes no allocation behaviour.
//
// `#[rustfmt::skip]` on the impl and on each method: `rustfmt` relocates a
// trailing `//` comment on a long `{`-terminated `impl`/`fn` line onto the
// line after, which would separate the `it-allow: no-unsafe` marker from
// the `unsafe` token the invariant lint's grep must see on the same line.
// Skipping formatting for these three lines is what keeps the marker
// attached to the line it excuses, without shortening the reason to fit.
use std::alloc::{GlobalAlloc, Layout, System};

#[rustfmt::skip]
unsafe impl GlobalAlloc for CountingAllocator { // it-allow: no-unsafe reason: a GlobalAlloc impl is necessarily unsafe; this one delegates entirely to System, adding only a thread-local counter increment
    #[rustfmt::skip]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 { // it-allow: no-unsafe reason: the trait requires this signature to be unsafe; the body only increments a counter and delegates to System
        THREAD_ALLOCATIONS.with(|counter| counter.set(counter.get() + 1));
        unsafe { System.alloc(layout) } // it-allow: no-unsafe reason: delegates to the platform default allocator
    }

    #[rustfmt::skip]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { // it-allow: no-unsafe reason: the trait requires this signature to be unsafe; the body only delegates to System
        unsafe { System.dealloc(ptr, layout) } // it-allow: no-unsafe reason: delegates to the platform default allocator
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn origin_self_test() {
    let handle = std::thread::spawn(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime builds");
        runtime.block_on(async {
            let mut config = base_config();
            config.body_bytes = 777;
            config.workers = 1;
            // Computed independently, exactly like `stats_endpoint_reconciles`,
            // so the expected total below is pinned against `response.rs`'s
            // own construction rather than against the server's behavior
            // this test exists to check.
            let expected_head_len =
                irontraffic_origin::response::ResponseArena::new(&config).head_len();
            let expected_total = expected_head_len.saturating_add(777);

            ensure_high_fd_limit();
            let origin = serve::start(config).await.expect("origin starts");
            let mut stream = connect(origin.listen_addrs[0])
                .await
                .expect("connects to the origin");

            // The first request is allowed to allocate (the connection's own
            // 16 KiB read buffer, this test's own client-side parsing via
            // `roundtrip`, and any warm-up the runtime does): it establishes
            // the baseline this test measures growth from.
            let first = roundtrip(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
                .await
                .expect("a response arrives");
            assert_eq!(
                first.body.len(),
                777,
                "returned body size is exactly the configured size"
            );
            assert_eq!(
                expected_head_len.saturating_add(first.body.len()),
                expected_total
            );

            let allocations_after_first = thread_allocations();

            // From here on, every request is driven with a hand-rolled,
            // allocation-free client: `roundtrip`/`read_response` above
            // build `String`s and `Vec`s per call, which would measure this
            // test's OWN client code instead of the origin's. A static byte
            // literal for the request and one reused stack buffer for the
            // response is what actually isolates the origin's allocation
            // behavior.
            let mut scratch = [0u8; 4096];
            for _ in 0..9_999 {
                stream
                    .write_all(b"GET / HTTP/1.1\r\n\r\n")
                    .await
                    .expect("write succeeds");
                let mut received = 0usize;
                while received < expected_total {
                    let n = stream.read(&mut scratch).await.expect("read succeeds");
                    assert!(n > 0, "unexpected EOF mid-request");
                    received = received.saturating_add(n);
                }
                assert_eq!(
                    received, expected_total,
                    "no extra bytes beyond one response"
                );
            }

            let allocations_after_all = thread_allocations();
            (allocations_after_first, allocations_after_all)
        })
    });

    let (after_first, after_all) = handle.join().expect("the driving thread does not panic");
    assert_eq!(
        after_all, after_first,
        "zero heap allocations after the first request, across 10,000 requests"
    );
}

// ---------------------------------------------------------------------------
// Subprocess helpers, for the two tests that need to observe or bound the
// origin's own CPU time or file-descriptor limit distinctly from the test
// harness's own.
// ---------------------------------------------------------------------------

/// Binds an ephemeral port, reads it back, and immediately drops the
/// listener, freeing it for a child process to bind. A well-established
/// testing pattern; the TOCTOU window between drop and the child's own bind
/// is not eliminated, only made small.
///
/// Returns a `Result` rather than panicking, per `start`'s doc comment.
fn free_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Minimal POSIX single-quote shell escaping: wraps `value` in single quotes,
/// replacing any embedded single quote with `'\''` (close the quote, an
/// escaped literal quote, reopen the quote). Used only to build the
/// `/bin/sh -c` command line `spawn_with_rlimit` hands to a real shell; every
/// value passed through it here is a fixed test-controlled path or socket
/// address, never untrusted input, but quoting it properly is what makes the
/// command line correct regardless.
fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

/// Blocks the calling thread until `addr` accepts a TCP connection, up to a
/// generous bound, then returns.
///
/// Replaces a fixed `sleep(300ms)`-and-hope wait that both spawn paths used
/// to rely on. Watched to fail: under this file's own concurrency (`cargo
/// test` runs every test in this file, several of them multi-threaded, on
/// this one process's CPUs at once), a flat 300ms sleep occasionally elapsed
/// before the just-spawned child had actually bound its listener, and the
/// very next `connect` in the test then failed with `ConnectionRefused`;
/// reproduced directly with the fixed sleep still in place, 2 failures (both
/// subprocess tests together, in the same run) across 8 consecutive `cargo
/// test --locked -p irontraffic-origin --all-features` runs. Polling for a
/// real, successful connect is unaffected by how loaded the host happens to
/// be at the moment any one child was spawned, unlike a fixed guess.
fn wait_until_listening(addr: SocketAddr) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        if std::time::Instant::now() >= deadline {
            // Best-effort: give up and let the caller's own next connect
            // attempt surface the real error, exactly as the old fixed
            // sleep would have on a child that never came up at all.
            return;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
}

/// A real, separate `it-origin` process, killed on drop.
struct ChildOrigin {
    child: std::process::Child,
    addr: SocketAddr,
}

impl ChildOrigin {
    /// Spawns `it-origin --listen <a free port>` plus `extra_args`, waiting
    /// for it to bind before returning. Returns a `Result` rather than
    /// panicking, per `start`'s doc comment.
    fn spawn(extra_args: &[&str]) -> std::io::Result<Self> {
        let spawned = Self::spawn_child(extra_args)?;
        wait_until_listening(spawned.addr);
        Ok(spawned)
    }

    /// Spawns `it-origin` with its own `RLIMIT_NOFILE` soft limit lowered to
    /// `nofile_limit` before it execs, WITHOUT ever touching this test
    /// binary's own process-wide limit.
    ///
    /// An earlier version of this function lowered THIS PROCESS's own
    /// `RLIMIT_NOFILE`, spawned the child, then restored it. That is broken
    /// in both directions, because `cargo test` runs every test in this file
    /// concurrently, on many threads, in one process, and `RLIMIT_NOFILE` is
    /// process-wide state shared by every one of them:
    ///
    /// - Watched to fail: on a clean checkout, 5 consecutive runs of `cargo
    ///   test --locked -p irontraffic-origin --all-features` produced 1, 1,
    ///   10, 1, and 13 failures, every one of them an unrelated sibling test
    ///   whose own `TcpListener::bind` or socket allocation hit `EMFILE`
    ///   while this function's window held the limit at 64.
    /// - Even confined to that window, the lowered limit never actually
    ///   reached the child: `spawn_child` calls `ensure_high_fd_limit()` as
    ///   its first statement, and that function's `Once` -- if this is the
    ///   first call in the process -- raises the limit right back up before
    ///   `Command::spawn` forks, so the child always inherited a high limit
    ///   and this test's own EMFILE condition was never actually created.
    ///
    /// The fix lowers the limit only in the CHILD, never in this shared test
    /// binary: spawn `/bin/sh -c 'ulimit -n <n> && exec <bin> <args...>'`
    /// rather than the binary directly. The shell's own `ulimit` builtin
    /// calls `setrlimit` on the freshly forked shell process (never on this
    /// test binary's own process), and `exec` then replaces that process's
    /// image with `it-origin` while carrying the just-lowered limit forward
    /// -- unaffected by whatever this test binary's own limit is, or later
    /// becomes, regardless of run order or `ensure_high_fd_limit`. `/bin/sh`
    /// and its `ulimit` builtin are present on both platforms this crate is
    /// required to run on (Design section, point 2).
    fn spawn_with_rlimit(extra_args: &[&str], nofile_limit: u64) -> std::io::Result<Self> {
        ensure_high_fd_limit();
        let port = free_port()?;
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let bin = env!("CARGO_BIN_EXE_it-origin");

        let mut command_line = format!("ulimit -n {nofile_limit} && exec {}", shell_quote(bin));
        command_line.push_str(" --listen ");
        command_line.push_str(&shell_quote(&addr.to_string()));
        for arg in extra_args {
            command_line.push(' ');
            command_line.push_str(&shell_quote(arg));
        }

        let child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(&command_line)
            .spawn()?;
        wait_until_listening(addr);
        Ok(Self { child, addr })
    }

    fn spawn_child(extra_args: &[&str]) -> std::io::Result<Self> {
        ensure_high_fd_limit();
        let port = free_port()?;
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let bin = env!("CARGO_BIN_EXE_it-origin");
        let child = std::process::Command::new(bin)
            .arg("--listen")
            .arg(addr.to_string())
            .args(extra_args)
            .spawn()?;
        Ok(Self { child, addr })
    }

    /// The child's cumulative CPU time, read via `ps`, in milliseconds.
    ///
    /// Deliberately coarse rather than using `getrusage`: this crate depends
    /// on neither `libc` nor a Linux-only `/proc` reader (this workspace
    /// must build on macOS too, per the Design section), and `ps -o time=`
    /// is available on both. Some platforms report whole-second resolution
    /// only, which cannot distinguish 10ms of CPU from 400ms of CPU, but it
    /// reliably distinguishes "did not spin" (reports at or near 0) from
    /// "spun for the whole measurement window" (reports whole seconds),
    /// which is the property these tests exist to check. Documented as a
    /// known limitation rather than silently claimed to be precise.
    fn cpu_millis(&self) -> u64 {
        let pid = self.child.id().to_string();
        let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "time=", "-p", &pid])
            .output()
        else {
            return 0;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        parse_ps_cpu_time(text.trim())
    }
}

impl Drop for ChildOrigin {
    fn drop(&mut self) {
        let _ = self.child.kill(); // it-allow: no-swallowed-error reason: best-effort test cleanup; the process already having exited is not a test failure
        let _ = self.child.wait(); // it-allow: no-swallowed-error reason: reaps the child; a wait failure here cannot be acted on from Drop
    }
}

/// Parses a `ps -o time=` value (`[[HH:]MM:]SS[.ss]`) into milliseconds.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "converts a small, non-negative measured CPU time (at most a few seconds in these tests) from ps output; a test-only diagnostic conversion, never attacker-controlled"
)]
fn parse_ps_cpu_time(text: &str) -> u64 {
    let mut seconds: f64 = 0.0;
    for part in text.split(':') {
        let value: f64 = part.trim().parse().unwrap_or(0.0);
        seconds = seconds * 60.0 + value;
    }
    (seconds * 1000.0) as u64
}

// ---------------------------------------------------------------------------
// 15. accept_emfile_does_not_spin
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_emfile_does_not_spin() {
    let stats_addr = SocketAddr::from((
        [127, 0, 0, 1],
        free_port().expect("binds an ephemeral port"),
    ));
    let stats_arg = stats_addr.to_string();
    let origin = ChildOrigin::spawn_with_rlimit(&["--stats-listen", &stats_arg], 64)
        .expect("it-origin spawns");

    let mut streams = Vec::new();
    for _ in 0..200 {
        if let Ok(stream) = TcpStream::connect(origin.addr).await {
            streams.push(stream);
        }
    }
    assert!(
        streams.len() >= 100,
        "the test client itself (unaffected by the child's rlimit) must be able to open most of the 200 connections; opened {}",
        streams.len()
    );

    let cpu_before = origin.cpu_millis();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let cpu_after = origin.cpu_millis();
    let cpu_delta = cpu_after.saturating_sub(cpu_before);

    assert!(
        cpu_delta < 200,
        "origin CPU time over 2 seconds was {cpu_delta}ms, expected under 200ms (a spin bug costs whole seconds)"
    );

    // The 64-descriptor budget is shared by the main and stats listeners
    // (per the Design section), so with ~200 client connections still open
    // the stats listener itself has no descriptor to accept on. Drop the
    // main connections first, freeing the budget, before querying it: the
    // reject counter is monotonic and already recorded every EMFILE retry
    // above, so this ordering does not lose the thing being asserted.
    drop(streams);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut stats_stream = connect(stats_addr).await.expect("connects to the origin");
    let response = roundtrip(&mut stats_stream, b"GET /stats HTTP/1.1\r\n\r\n")
        .await
        .expect("a response arrives");
    let json = String::from_utf8(response.body).expect("stats body is UTF-8 JSON");
    assert!(
        json_number(&json, "rejects").expect("rejects key present") > 0,
        "the reject counter must rise while the descriptor limit is exhausted: {json}"
    );
}

// ---------------------------------------------------------------------------
// 18. slowloris_head_is_closed_on_the_deadline
// ---------------------------------------------------------------------------
#[tokio::test]
async fn slowloris_head_is_closed_on_the_deadline() {
    let origin = ChildOrigin::spawn(&["--head-timeout-ms", "500"]).expect("it-origin spawns");

    // Case A: opens a connection and sends nothing.
    {
        // Started before `connect`, not after: the origin's own head
        // deadline is set at `accept()` time, which races the client's
        // `connect()` call rather than following it, so starting the
        // client's clock afterward can measure a shorter interval than the
        // server actually waited.
        let started = Instant::now();
        let mut stream = TcpStream::connect(origin.addr).await.expect("connects");
        let cpu_before = origin.cpu_millis();
        let mut probe = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut probe))
            .await
            .expect("closes within the safety window")
            .expect("a clean EOF");
        let elapsed = started.elapsed();
        let cpu_after = origin.cpu_millis();
        assert_eq!(n, 0, "no bytes received");
        assert!(
            elapsed >= Duration::from_millis(450) && elapsed <= Duration::from_millis(1500),
            "closed at {elapsed:?}, expected between 500 and 1500ms"
        );
        assert!(
            cpu_after.saturating_sub(cpu_before) < 50,
            "origin CPU time over the wait was {}ms, expected under 50ms",
            cpu_after.saturating_sub(cpu_before)
        );
    }

    // Case B: declares a body and stops after one byte.
    {
        let started = Instant::now();
        let mut stream = TcpStream::connect(origin.addr).await.expect("connects");
        stream
            .write_all(b"GET / HTTP/1.1\r\nContent-Length: 16777216\r\n\r\nX")
            .await
            .expect("write succeeds");
        let mut probe = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut probe))
            .await
            .expect("closes within the safety window")
            .expect("a clean EOF");
        let elapsed = started.elapsed();
        assert_eq!(n, 0, "no bytes received");
        assert!(
            elapsed >= Duration::from_millis(450) && elapsed <= Duration::from_millis(1500),
            "closed at {elapsed:?}, expected between 500 and 1500ms"
        );
    }
}

// ---------------------------------------------------------------------------
// Property test: scan_head_is_total
// ---------------------------------------------------------------------------
proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(2048))]
    #[test]
    fn scan_head_is_total(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..20_480)) {
        match serve::scan_head(&bytes) {
            Ok(None) | Err(_) => {}
            Ok(Some(intent)) => {
                proptest::prop_assert!(intent.head_len <= bytes.len());
                proptest::prop_assert!(intent.content_length <= 16_777_216);
            }
        }
    }
}
