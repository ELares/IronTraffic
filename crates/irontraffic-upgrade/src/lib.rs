// SPDX-License-Identifier: MIT OR Apache-2.0

//! The zero-downtime binary upgrade wire format. Pure: no I/O, no clock, no entropy.

#![forbid(unsafe_code)]

pub mod frame;

pub use frame::{Ack, AckError, FrameError, HandoffEntry, HandoffFrame};

/// Frame magic.
pub const FRAME_MAGIC: [u8; 4] = *b"ITFD";
/// Frame version this build writes and accepts.
pub const FRAME_VERSION: u16 = 1;
/// Fixed header bytes before the entries.
pub const HEADER_BYTES: usize = 12;
/// Checksum bytes after the entries.
pub const CHECKSUM_BYTES: usize = 8;
/// Maximum transferred descriptors. Named, public, and reported in the error, unlike
/// Pingora's undocumented limit of 32.
///
/// 253 is not a round number chosen for taste: it is Linux's `SCM_MAX_FD`, the most
/// descriptors one `SCM_RIGHTS` control message can carry. `{{upgrade-scm-rights-handoff-and-bounded-drain}}`
/// sends every descriptor in exactly one `sendmsg`, so a larger cap here would encode a
/// frame that the kernel then refuses to send, turning a configuration limit into an
/// `EINVAL` at the worst moment of an upgrade. The cap is on total descriptors, which is
/// listeners times shards, so a 64-worker process is limited to three sharded listeners
/// plus one unsharded; the error names the count and the limit.
pub const MAX_FDS: usize = 253;
/// Maximum bytes of one canonical bind address.
pub const MAX_ADDR_BYTES: usize = 64;
/// Largest legal frame, for a receiver's read budget.
pub const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_FDS * (4 + MAX_ADDR_BYTES) + CHECKSUM_BYTES;
