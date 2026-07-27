#![no_main]
//! Fuzz target for `irontraffic_http::h1::chunked::ChunkedDecoder`.
//!
//! Input domain: arbitrary bytes. The first byte is consumed as a split-size
//! seed (`1 + b % 64`); the remainder is the wire bytes fed to two separate
//! decoder runs.
//!
//! Contract: no panic, no hang, bounded allocation. Runs the decoder twice
//! over the SAME remaining bytes: once handed as one whole buffer, once
//! split at the seeded size (revealing that many MORE bytes each round,
//! mimicking a real read loop that appends whatever arrived since the last
//! wakeup). Asserts the two runs agree on the error (if any), on the
//! concatenated `Data` bytes, and on `Done { consumed }` (reported as the
//! cumulative offset from the message's own start, which is what makes two
//! differently split runs comparable at all, since `ChunkedEvent::Done`'s
//! own `consumed` field is local to whichever call produced it). That
//! agreement is the resumption property `h1-chunked-and-trailers` (#36)
//! exists to guarantee, and it is the reason this target exists.

use bytes::BytesMut;
use irontraffic_http::RejectReason;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::chunked::{ChunkedDecoder, ChunkedEvent};
use irontraffic_http::limits::Limits;
use libfuzzer_sys::fuzz_target;

/// One run's outcome, comparable across two differently split runs of the
/// same underlying bytes.
#[derive(PartialEq, Eq, Debug)]
enum Outcome {
    /// The message completed; the value is the cumulative bytes-from-start
    /// offset of the first byte after it.
    Done(usize),
    /// The decoder refused the message.
    Err(RejectReason),
    /// Every available byte was consumed without either of the above: a
    /// legitimate, merely unfinished message.
    Unfinished,
}

/// Feeds `wire` to a fresh decoder, revealing at most `chunk` new bytes per
/// `decode` call, or the WHOLE remaining input in one call when `chunk` is
/// `None`. Bounded to `wire.len().saturating_add(2)` iterations, so a
/// decoder that stops making progress fails this target's own loop bound
/// instead of hanging it.
fn run(wire: &[u8], chunk: Option<usize>) -> (Vec<u8>, Outcome) {
    let mut decoder = ChunkedDecoder::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);
    let mut pos = 0usize;
    let mut revealed = 0usize;
    let mut data = Vec::new();
    let max_iters = wire.len().saturating_add(2);

    for _ in 0..=max_iters {
        if revealed < wire.len() {
            let step = chunk.unwrap_or(wire.len().saturating_sub(revealed).max(1));
            revealed = revealed.saturating_add(step).min(wire.len());
        }
        let buf = wire.get(pos..revealed).unwrap_or(&[]);
        let mut arena = BytesMut::new();
        match decoder.decode(buf, &mut arena) {
            Ok(ChunkedEvent::Data { offset, len }) => {
                let slice = buf.get(offset..offset.saturating_add(len)).unwrap_or(&[]);
                data.extend_from_slice(slice);
                pos = pos.saturating_add(decoder.consumed_this_call());
            }
            Ok(ChunkedEvent::NeedMore) => {
                let consumed = decoder.consumed_this_call();
                pos = pos.saturating_add(consumed);
                if consumed == 0 && revealed >= wire.len() {
                    return (data, Outcome::Unfinished);
                }
            }
            Ok(ChunkedEvent::Done { consumed }) => {
                return (data, Outcome::Done(pos.saturating_add(consumed)));
            }
            Err(reason) => return (data, Outcome::Err(reason)),
        }
    }
    (data, Outcome::Unfinished)
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let Some((&seed, wire)) = data.split_first() else {
        return;
    };
    let split = 1usize.saturating_add(usize::from(seed) % 64);

    let (whole_data, whole_outcome) = run(wire, None);
    let (split_data, split_outcome) = run(wire, Some(split));

    assert_eq!(
        whole_data, split_data,
        "split at {split} disagreed with the whole-buffer run on Data bytes for {wire:?}"
    );
    assert_eq!(
        whole_outcome, split_outcome,
        "split at {split} disagreed with the whole-buffer run on the final outcome for {wire:?}"
    );
});
