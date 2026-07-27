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
//! concatenated `Data` bytes, on `Done { consumed }` (reported as the
//! cumulative offset from the message's own start, which is what makes two
//! differently split runs comparable at all, since `ChunkedEvent::Done`'s
//! own `consumed` field is local to whichever call produced it), and on the
//! trailer section's own content. That agreement is the resumption property
//! `h1-chunked-and-trailers` (#36) exists to guarantee, and it is the reason
//! this target exists.
//!
//! The trailer comparison (issue #658) is not redundant with the other two:
//! `decode`'s documented precondition is that `arena` is the SAME growing
//! buffer across every call for one body, and a violation of it corrupts
//! only the trailer section, never `Data` bytes or `Done { consumed }`. A
//! fresh `BytesMut::new()` per call compiled and ran cleanly here for a
//! long time while silently destroying every trailer section this target
//! ever decoded.
//!
//! One exception to "agree on the outcome": the trailer re-scan budget
//! (`HeadScanBudget::MAX_BYTES` in `chunked.rs`'s `step_trailers`) is
//! deliberately charged per byte SEARCHED per `decode` call, not per byte
//! consumed, so a finer split of the identical wire bytes charges it more
//! and can trip `Err(FieldLineTooLong)` on one run where the other is merely
//! `Unfinished` or even reaches `Done` with real trailer content. That is
//! the intended path-dependent cost, not a resumption bug, and the
//! assertions below are narrowed accordingly: see the comment at the point
//! of the assertion for exactly what is and is not still checked.

use bytes::BytesMut;
use irontraffic_http::RejectReason;
use irontraffic_http::field::UnderscorePolicy;
use irontraffic_http::h1::chunked::{ChunkedDecoder, ChunkedEvent};
use irontraffic_http::limits::Limits;
use irontraffic_http::section::{FieldFlags, FieldSection};
use libfuzzer_sys::fuzz_target;

/// One trailer field as owned name bytes, value bytes and flags.
type TrailerField = (Vec<u8>, Vec<u8>, FieldFlags);

/// A whole trailer section snapshotted as owned bytes, so two `FieldSection`s
/// built into two different arenas (a whole-buffer run vs a split run) can
/// be compared for equality.
fn trailer_snapshot(section: Option<&FieldSection>) -> Vec<TrailerField> {
    section.map_or_else(Vec::new, |t| {
        t.iter()
            .map(|(name, value, flags)| (name.to_vec(), value.to_vec(), flags))
            .collect()
    })
}

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
fn run(wire: &[u8], chunk: Option<usize>) -> (Vec<u8>, Outcome, Vec<TrailerField>) {
    let mut decoder = ChunkedDecoder::new(&Limits::DEFAULT.clamped(), UnderscorePolicy::Reject);
    let mut pos = 0usize;
    let mut revealed = 0usize;
    let mut data = Vec::new();
    let max_iters = wire.len().saturating_add(2);
    // One arena for the whole drive, declared outside the loop: decode's
    // documented precondition (issue #658) is that arena is the SAME
    // growing buffer across every call for one body. A fresh arena per
    // call compiled and ran cleanly while silently corrupting every
    // trailer section this target ever decoded, which is exactly why this
    // fuzz target could not detect a trailer resumption bug before this
    // fix: neither Data bytes nor Done{consumed} depend on the arena.
    let mut arena = BytesMut::new();

    for _ in 0..=max_iters {
        if revealed < wire.len() {
            let step = chunk.unwrap_or(wire.len().saturating_sub(revealed).max(1));
            revealed = revealed.saturating_add(step).min(wire.len());
        }
        let buf = wire.get(pos..revealed).unwrap_or(&[]);
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
                    return (data, Outcome::Unfinished, Vec::new());
                }
            }
            Ok(ChunkedEvent::Done { consumed }) => {
                let trailers = trailer_snapshot(decoder.trailers());
                return (data, Outcome::Done(pos.saturating_add(consumed)), trailers);
            }
            Err(reason) => return (data, Outcome::Err(reason), Vec::new()),
        }
    }
    (data, Outcome::Unfinished, Vec::new())
}

// it-allow: no-unsafe reason: libfuzzer-sys macro expansion in a fuzz-only crate
fuzz_target!(|data: &[u8]| {
    let Some((&seed, wire)) = data.split_first() else {
        return;
    };
    let split = 1usize.saturating_add(usize::from(seed) % 64);

    let (whole_data, whole_outcome, whole_trailers) = run(wire, None);
    let (split_data, split_outcome, split_trailers) = run(wire, Some(split));

    assert_eq!(
        whole_data, split_data,
        "split at {split} disagreed with the whole-buffer run on Data bytes for {wire:?}"
    );

    // The resumption property is NOT exact split-invariance of the outcome in
    // one specific, deliberate case: the trailer re-scan budget
    // (`HeadScanBudget::MAX_BYTES`, charged in `chunked.rs`'s `step_trailers`)
    // and the per-line length cap it shares a `RejectReason` with are charged
    // against bytes SEARCHED per `decode` call, not bytes consumed, precisely
    // so that a peer drip-feeding one byte per call pays for re-searching the
    // same incomplete trailer line on every call (see the long comment at
    // `step_trailers` and the `trailer_rescan_is_bounded` unit test that pins
    // the resulting call count). Splitting the SAME wire bytes into more
    // calls therefore charges that budget more, by design: a fine enough
    // split can turn a whole-buffer `Unfinished`, or even a whole-buffer
    // `Done` with real trailer content, into a split-run
    // `Err(FieldLineTooLong)` that never got far enough to see any trailer
    // fields at all. That is the intended cost asymmetry, not a resumption
    // bug, so this assertion gives up exact outcome and trailer-content
    // equality in exactly that one case: when exactly one of the two runs
    // ended in `Err(FieldLineTooLong)` and the other did not.
    //
    // Everything else is kept exactly as before: Data bytes always (already
    // asserted above, unaffected because the budget only exists inside the
    // `Trailers` state, entirely after body data delivery), and outcome plus
    // trailer content whenever NEITHER run hit that budget, including when
    // BOTH did (their outcomes already agree, so the assertion below is not
    // skipped, only trivially satisfied). A genuine resumption bug, such as
    // issue #658's arena mismatch that silently corrupted trailer content
    // without ever touching Data bytes or the outcome, still fails this
    // assert exactly as before.
    let whole_hit_trailer_budget =
        matches!(whole_outcome, Outcome::Err(RejectReason::FieldLineTooLong));
    let split_hit_trailer_budget =
        matches!(split_outcome, Outcome::Err(RejectReason::FieldLineTooLong));
    if whole_hit_trailer_budget == split_hit_trailer_budget {
        assert_eq!(
            whole_outcome, split_outcome,
            "split at {split} disagreed with the whole-buffer run on the final outcome for {wire:?}"
        );
        assert_eq!(
            whole_trailers, split_trailers,
            "split at {split} disagreed with the whole-buffer run on the trailer section for {wire:?}"
        );
    } else {
        // Exactly one side was cut off by the path-dependent trailer budget.
        // Do not compare `whole_trailers` and `split_trailers` here: the
        // refused side's snapshot is trivially empty (see `run`, which
        // returns `Vec::new()` on every `Err`), so the comparison would
        // either pass vacuously (neither run ever reached a trailer field)
        // or fail on precisely the divergence this branch exists to permit
        // (the whole-buffer run reached `Done` with real trailer content
        // that the split run, cut off first, never saw).
    }
});
