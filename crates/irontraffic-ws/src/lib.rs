// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
#![deny(
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]
//! WebSocket frame codec for a RELAY.
//!
//! `irontraffic-ws` validates every frame header against RFC 6455 (reserved
//! bits, opcode, control-frame size and fragmentation, masking direction,
//! minimal length encoding, continuation ordering) and hands the payload
//! through without reassembling messages. We validate per frame and forward
//! per frame.
//!
//! We do NOT reassemble messages: the codec holds no message buffer, so an
//! attacker's many-fragment message costs us nothing but rate, which
//! [`TunnelBudget`] bounds.
//!
//! We do NOT validate `Text` frames as UTF-8 (RFC 6455 Section 5.6 puts that
//! obligation on endpoints, not intermediaries): validating would require
//! holding a fragmented message until it is complete, which is reassembly,
//! which is the thing this codec exists not to do.
//!
//! We do NOT unmask or remask payloads on the relay path. A frame arrives
//! from a client already masked and is forwarded to an upstream, which is
//! also a server, with its original mask key untouched. Unmasking and
//! remasking with a different key would produce a different byte stream for
//! the same message, and that is what makes the relay byte-opaque instead of
//! byte-transparent. The one exception, [`mask_in_place`], exists solely for
//! the RFC 8441 extended-CONNECT bridge and is never called from this crate.
//!
//! A proxy that forwards a malformed frame and then shovels bytes has
//! created a bidirectional channel in which the two endpoints disagree about
//! frame boundaries. That is the smuggling precondition wearing a different
//! protocol; see `docs/THREAT-MODEL.md`'s "WebSocket frame relay" section.
//!
//! This crate is sans-IO: no socket type, no filesystem, no clock, no
//! thread, no process. It is NOT `no_std`: `irontraffic-http`, which this
//! crate depends on, states plainly that it is not `no_std` either, because
//! the benefit is zero here and the cost is a `#[cfg(test)] extern crate
//! std;` dance in every module.

mod frame;
pub mod handshake;

pub use frame::{
    CloseCode, DEFAULT_MAX_FRAME_BYTES, Direction, FrameDecoder, FrameHeader, MAX_CONTROL_PAYLOAD,
    Opcode, TunnelBudget, WsError, mask_in_place,
};
pub use handshake::{
    HandshakeError, HandshakeSide, UpgradeRequest, UpgradeResponse, UpgradeTokens, accept_key,
};
