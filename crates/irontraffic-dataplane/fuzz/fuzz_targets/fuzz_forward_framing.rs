#![no_main]

//! Fuzz target for the forwarding loop's timing and framing behavior, driven
//! over the in-memory `DuplexTransport` double so the run is fast and
//! deterministic (a socket-driven target would be too slow to be useful).
//!
//! The input is interpreted as a script of `(direction, chunk_len, write_cap,
//! pending_every_n)` 4-byte tuples: each tuple appends `chunk_len * 16` (capped
//! at 1 MiB of total scripted content per direction) deterministic bytes to the
//! named direction's content, and sets that direction's write-acceptance
//! policy for the whole run (the last tuple naming a direction wins).
//! `write_cap` is clamped to at least 1: a cap of 0 always yields
//! `ForwardError::WriteZero`, which would fail the byte-identity assertion
//! below for a reason that has nothing to do with the loop.
//!
//! Contract: the forwarder never panics, never hangs (backstopped by a 10
//! second timeout, itself a finding if it ever fires), the
//! bytes delivered are always a byte-identical PREFIX of the bytes scripted for
//! that direction (a `pending_every_n` of 1 blocks a direction forever by
//! design, so full delivery is not guaranteed, only that nothing is corrupted
//! or reordered), and `irontraffic_io::buffer::stats().outstanding` never
//! exceeds 2 above the baseline captured before the run.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use irontraffic_dataplane::duplex::DuplexTransport;
use irontraffic_dataplane::{forward_bidirectional, EndReason, ForwardLimits};
use irontraffic_io::ShutdownController;
use libfuzzer_sys::fuzz_target;

/// One direction's accumulated scripted content and write policy.
struct Script {
    content: Vec<u8>,
    write_cap: usize,
    pending_every_n: usize,
}

impl Script {
    fn new() -> Self {
        Self {
            content: Vec::new(),
            write_cap: usize::MAX,
            pending_every_n: 0,
        }
    }
}

/// Bounds one direction's total scripted content so a huge fuzz input cannot
/// demand an unbounded amount of work from one execution.
const MAX_SCRIPT_BYTES: usize = 1024 * 1024;

fn build_scripts(data: &[u8]) -> (Script, Script) {
    let mut client = Script::new();
    let mut upstream = Script::new();
    for tuple in data.chunks_exact(4) {
        let (Some(&dir), Some(&len_b), Some(&cap_b), Some(&pend_b)) =
            (tuple.first(), tuple.get(1), tuple.get(2), tuple.get(3))
        else {
            break;
        };
        let script = if dir % 2 == 0 {
            &mut client
        } else {
            &mut upstream
        };
        if script.content.len() >= MAX_SCRIPT_BYTES {
            continue;
        }
        let want = usize::from(len_b) * 16;
        let room = MAX_SCRIPT_BYTES.saturating_sub(script.content.len());
        let len = want.min(room);
        let base = script.content.len();
        script.content.extend(
            (0..len).map(|i| dir.wrapping_add(u8::try_from((base + i) % 256).unwrap_or(0))),
        );
        // Never 0: a write cap of 0 always produces `WriteZero`, which would
        // make "delivered is a prefix of sent" true only vacuously (an empty
        // prefix) rather than exercising the loop.
        script.write_cap = usize::from(cap_b).max(1);
        script.pending_every_n = usize::from(pend_b);
    }
    (client, upstream)
}

/// Samples `irontraffic_io::buffer::stats().outstanding` on every yield, tracking
/// the maximum seen in `max_seen`. Runs until aborted.
async fn sample_outstanding(max_seen: Arc<AtomicU64>) {
    loop {
        let cur = irontraffic_io::buffer::stats().outstanding;
        max_seen.fetch_max(cur, Ordering::Relaxed);
        tokio::task::yield_now().await; // it-allow: transport-seam reason: fuzz harness in its own cargo-fuzz workspace, never linked into the server binary; yields on the fuzz crate's own runtime so this sampler and forward_bidirectional interleave
    }
}

fuzz_target!(|data: &[u8]| {
    let (client_script, upstream_script) = build_scripts(data);
    let client_sent = client_script.content.clone();
    let upstream_sent = upstream_script.content.clone();

    let mut client = DuplexTransport::new(client_script.content)
        .with_write_cap(client_script.write_cap)
        .with_pending_every_n(client_script.pending_every_n);
    let mut upstream = DuplexTransport::new(upstream_script.content)
        .with_write_cap(upstream_script.write_cap)
        .with_pending_every_n(upstream_script.pending_every_n);

    let Ok(rt) = tokio::runtime::Builder::new_current_thread() // it-allow: transport-seam reason: fuzz harness in its own cargo-fuzz workspace, never linked into the server binary; forward_bidirectional is async and needs a real runtime to drive its injected Timer, and the product's own Spawner/SystemTimer wiring lives inside the control plane, not exposed to a standalone driver
        .enable_time()
        .build()
    else {
        return;
    };

    let baseline = irontraffic_io::buffer::stats().outstanding;
    let max_outstanding = Arc::new(AtomicU64::new(baseline));

    rt.block_on(async {
        let sampler = tokio::spawn(sample_outstanding(Arc::clone(&max_outstanding))); // it-allow: transport-seam reason: fuzz harness in its own cargo-fuzz workspace, a background sampler task never linked into the server binary

        let (_controller, token) = ShutdownController::new();
        let timer = irontraffic_io::SystemTimer::new();
        let limits = ForwardLimits {
            idle: Duration::from_millis(200),
            half_close: Duration::from_millis(200),
            max_bytes_per_direction: None,
            max_lifetime: Some(Duration::from_secs(2)),
        };

        let fut = forward_bidirectional(&mut client, &mut upstream, &timer, &token, &limits);
        let outcome = tokio::time::timeout(Duration::from_secs(10), fut).await; // it-allow: transport-seam reason: fuzz harness in its own cargo-fuzz workspace; backstops a hang finding, never linked into the server binary
        sampler.abort();

        let Ok(result) = outcome else {
            panic!("forward_bidirectional hung past its 10 second bound"); // it-allow: no-panic reason: fuzz harness; a panic here is the finding libfuzzer-sys reports, never a request-path failure mode, since this file is never linked into the server binary.
        };

        match result {
            Ok((stats, reason)) => {
                let c2u = usize::try_from(stats.client_to_upstream).unwrap_or(usize::MAX);
                let u2c = usize::try_from(stats.upstream_to_client).unwrap_or(usize::MAX);
                // `stats` counts bytes written, so it must match exactly what the
                // destination actually recorded, and that must be a byte-identical
                // prefix of what the source ever had to send.
                assert_eq!(upstream.written().len(), c2u);
                assert_eq!(client.written().len(), u2c);
                assert_eq!(client_sent.get(..c2u), Some(upstream.written().as_slice()));
                assert_eq!(upstream_sent.get(..u2c), Some(client.written().as_slice()));
                if reason == EndReason::BothEof {
                    assert_eq!(c2u, client_sent.len());
                    assert_eq!(u2c, upstream_sent.len());
                }
            }
            Err(_) => {
                // A `WriteZero` or a real transport error is not this target's
                // concern (`DuplexTransport` never returns an `io::Error`, and
                // `write_cap` is clamped away from 0 above), but the forwarder
                // must still have moved bytes correctly up to that point.
                let c2u_prefix =
                    upstream.written().is_empty() || client_sent.starts_with(&upstream.written());
                let u2c_prefix =
                    client.written().is_empty() || upstream_sent.starts_with(&client.written());
                assert!(c2u_prefix);
                assert!(u2c_prefix);
            }
        }
    });

    let observed = max_outstanding.load(Ordering::Relaxed);
    assert!(
        observed <= baseline + 2,
        "outstanding rose to {observed}, baseline {baseline}"
    );
});
