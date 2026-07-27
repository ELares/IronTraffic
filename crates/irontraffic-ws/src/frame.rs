// SPDX-License-Identifier: MIT OR Apache-2.0
//! The frame codec: header decoding, fragmentation state, the close payload
//! check, masking, and the tunnel budget.
//!
//! Every byte this module reads came off the wire from an untrusted peer.
//! Every read goes through [`slice::first`] or [`slice::get`], or through a
//! fixed-size array destructure, never `[]`: `clippy::indexing_slicing` is
//! denied crate wide and a panic on the request path is an outage.

/// Largest control-frame payload, in bytes. RFC 6455 Section 5.5.
pub const MAX_CONTROL_PAYLOAD: u64 = 125;

/// Default largest forwarded frame payload, in bytes.
pub const DEFAULT_MAX_FRAME_BYTES: u64 = 16 * 1024 * 1024;

/// Which way a frame is travelling. Masking rules depend on it, so it is not
/// inferable and must be passed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client to server. Frames MUST be masked.
    ClientToServer,
    /// Server to client. Frames MUST NOT be masked.
    ServerToClient,
}

/// A WebSocket opcode. Reserved values are not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// 0x0. Continues a fragmented message.
    Continuation,
    /// 0x1. UTF-8 text. We do NOT validate the UTF-8: a relay forwards
    /// bytes, and validating would mean reassembling a fragmented message
    /// before its text could be checked.
    Text,
    /// 0x2. Binary.
    Binary,
    /// 0x8. Close.
    Close,
    /// 0x9. Ping.
    Ping,
    /// 0xA. Pong.
    Pong,
}

impl Opcode {
    /// The opcode for a wire nibble, or `None` for a reserved value (0x3 to
    /// 0x7, 0xB to 0xF).
    #[must_use]
    pub const fn from_wire(n: u8) -> Option<Self> {
        match n {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    /// The wire nibble.
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    /// True for `Close`, `Ping` and `Pong`.
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    /// The stable, `snake_case` metric label.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Continuation => "continuation",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Close => "close",
            Self::Ping => "ping",
            Self::Pong => "pong",
        }
    }
}

/// One validated frame header. The payload is NOT read here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// The opcode.
    pub opcode: Opcode,
    /// The FIN bit.
    pub fin: bool,
    /// The declared payload length. NEVER used to size an allocation.
    pub payload_len: u64,
    /// The masking key, present exactly when the direction is
    /// `ClientToServer`.
    pub mask: Option<[u8; 4]>,
    /// Header bytes consumed: 2 to 14.
    pub consumed: usize,
}

/// An RFC 6455 close code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    /// 1000.
    Normal,
    /// 1001.
    GoingAway,
    /// 1002. Every framing violation in this codec.
    ProtocolError,
    /// 1008. Budget exceeded.
    PolicyViolation,
    /// 1009. Frame above the configured ceiling.
    MessageTooBig,
    /// 1011.
    InternalError,
}

impl CloseCode {
    /// The wire value.
    #[must_use]
    pub const fn wire(self) -> u16 {
        match self {
            Self::Normal => 1000,
            Self::GoingAway => 1001,
            Self::ProtocolError => 1002,
            Self::PolicyViolation => 1008,
            Self::MessageTooBig => 1009,
            Self::InternalError => 1011,
        }
    }

    /// The stable, `snake_case` metric label.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::GoingAway => "going_away",
            Self::ProtocolError => "protocol_error",
            Self::PolicyViolation => "policy_violation",
            Self::MessageTooBig => "message_too_big",
            Self::InternalError => "internal_error",
        }
    }
}

/// A WebSocket framing violation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WsError {
    /// A reserved bit was set with no extension claiming it.
    #[error("reserved bits {rsv:#x} set with no negotiated extension")]
    ReservedBitSet {
        /// The three reserved bits.
        rsv: u8,
    },
    /// A reserved opcode.
    #[error("reserved opcode {opcode:#x}")]
    ReservedOpcode {
        /// The nibble.
        opcode: u8,
    },
    /// A client-to-server frame was not masked.
    #[error("client frame is not masked")]
    UnmaskedClientFrame,
    /// A server-to-client frame was masked.
    #[error("server frame is masked")]
    MaskedServerFrame,
    /// A length encoded in a longer form than necessary.
    #[error("payload length {declared} encoded in the {form}-bit form")]
    NonMinimalLength {
        /// The declared length.
        declared: u64,
        /// 16 or 64.
        form: u8,
    },
    /// A 64-bit length with the high bit set.
    #[error("payload length has the high bit set")]
    LengthHighBitSet,
    /// A control frame above 125 bytes.
    #[error("control frame payload is {len} bytes, above {MAX_CONTROL_PAYLOAD}")]
    ControlFrameTooLong {
        /// The declared length.
        len: u64,
    },
    /// A control frame without FIN.
    #[error("control frame is fragmented")]
    FragmentedControlFrame,
    /// A continuation with no open fragmented message.
    #[error("continuation frame with no open message")]
    UnexpectedContinuation,
    /// A data frame while a fragmented message is open.
    #[error("data frame interleaved into an open fragmented message")]
    InterleavedDataFrame,
    /// A frame above the configured ceiling.
    #[error("frame payload is {len} bytes, above the configured {max}")]
    FrameTooLong {
        /// The declared length.
        len: u64,
        /// The ceiling.
        max: u64,
    },
    /// A close frame carried a 1-byte payload, which is half a status code.
    #[error("close frame payload is {len} bytes; it must be 0 or at least 2")]
    CloseFramePayloadTooShort {
        /// The payload length.
        len: usize,
    },
    /// A close frame carried a status code that must not appear on the wire.
    #[error("close status code {code} must not appear on the wire")]
    InvalidCloseCode {
        /// The offending code.
        code: u16,
    },
    /// The tunnel budget went negative.
    #[error("tunnel budget exhausted")]
    BudgetExhausted,
}

impl WsError {
    /// The close code to send.
    #[must_use]
    pub const fn close_code(&self) -> CloseCode {
        match self {
            Self::ReservedBitSet { .. }
            | Self::ReservedOpcode { .. }
            | Self::UnmaskedClientFrame
            | Self::MaskedServerFrame
            | Self::NonMinimalLength { .. }
            | Self::LengthHighBitSet
            | Self::ControlFrameTooLong { .. }
            | Self::FragmentedControlFrame
            | Self::UnexpectedContinuation
            | Self::InterleavedDataFrame
            | Self::CloseFramePayloadTooShort { .. }
            | Self::InvalidCloseCode { .. } => CloseCode::ProtocolError,
            Self::FrameTooLong { .. } => CloseCode::MessageTooBig,
            Self::BudgetExhausted => CloseCode::PolicyViolation,
        }
    }

    /// The stable, `snake_case` metric label.
    #[must_use]
    pub const fn metric_label(&self) -> &'static str {
        match self {
            Self::ReservedBitSet { .. } => "reserved_bit_set",
            Self::ReservedOpcode { .. } => "reserved_opcode",
            Self::UnmaskedClientFrame => "unmasked_client_frame",
            Self::MaskedServerFrame => "masked_server_frame",
            Self::NonMinimalLength { .. } => "non_minimal_length",
            Self::LengthHighBitSet => "length_high_bit_set",
            Self::ControlFrameTooLong { .. } => "control_frame_too_long",
            Self::FragmentedControlFrame => "fragmented_control_frame",
            Self::UnexpectedContinuation => "unexpected_continuation",
            Self::InterleavedDataFrame => "interleaved_data_frame",
            Self::FrameTooLong { .. } => "frame_too_long",
            Self::CloseFramePayloadTooShort { .. } => "close_frame_payload_too_short",
            Self::InvalidCloseCode { .. } => "invalid_close_code",
            Self::BudgetExhausted => "budget_exhausted",
        }
    }
}

/// Reads a big-endian `u16` starting at `start`, or `None` if `buf` is not
/// yet long enough.
fn read_u16_be_at(buf: &[u8], start: usize) -> Option<u16> {
    let &b0 = buf.get(start)?;
    let i1 = start.checked_add(1)?;
    let &b1 = buf.get(i1)?;
    Some(u16::from_be_bytes([b0, b1]))
}

/// Reads a big-endian `u64` starting at `start`, or `None` if `buf` is not
/// yet long enough.
fn read_u64_be_at(buf: &[u8], start: usize) -> Option<u64> {
    let &b0 = buf.get(start)?;
    let i1 = start.checked_add(1)?;
    let &b1 = buf.get(i1)?;
    let i2 = start.checked_add(2)?;
    let &b2 = buf.get(i2)?;
    let i3 = start.checked_add(3)?;
    let &b3 = buf.get(i3)?;
    let i4 = start.checked_add(4)?;
    let &b4 = buf.get(i4)?;
    let i5 = start.checked_add(5)?;
    let &b5 = buf.get(i5)?;
    let i6 = start.checked_add(6)?;
    let &b6 = buf.get(i6)?;
    let i7 = start.checked_add(7)?;
    let &b7 = buf.get(i7)?;
    Some(u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]))
}

/// Reads a 4-byte mask key starting at `start`, or `None` if `buf` is not yet
/// long enough.
fn read_mask_key(buf: &[u8], start: usize) -> Option<[u8; 4]> {
    let &b0 = buf.get(start)?;
    let i1 = start.checked_add(1)?;
    let &b1 = buf.get(i1)?;
    let i2 = start.checked_add(2)?;
    let &b2 = buf.get(i2)?;
    let i3 = start.checked_add(3)?;
    let &b3 = buf.get(i3)?;
    Some([b0, b1, b2, b3])
}

/// The relay's per-direction frame state.
pub struct FrameDecoder {
    direction: Direction,
    /// True while a fragmented data message is open.
    fragment_open: bool,
    /// The opcode of the open fragmented message, for the trace.
    fragment_opcode: Option<Opcode>,
    /// Extension-claimed reserved bits. Zero in this milestone.
    reserved_allowed: u8,
    /// Largest payload we will forward in one frame.
    max_frame_bytes: u64,
}

impl FrameDecoder {
    /// A decoder for `direction` with no extensions negotiated and the
    /// default frame ceiling.
    #[must_use]
    pub const fn new(direction: Direction) -> Self {
        Self {
            direction,
            fragment_open: false,
            fragment_opcode: None,
            reserved_allowed: 0,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Sets the largest payload this direction will forward in one frame.
    #[must_use]
    pub const fn with_max_frame_bytes(mut self, max: u64) -> Self {
        self.max_frame_bytes = max;
        self
    }

    /// Declares which reserved bits a negotiated extension owns, as a 3-bit
    /// mask where bit 2 is RSV1. Zero in this milestone.
    #[must_use]
    pub const fn with_reserved_allowed(mut self, mask: u8) -> Self {
        self.reserved_allowed = mask;
        self
    }

    /// Decodes and validates the next frame header.
    ///
    /// Returns `Ok(None)` when `buf` does not yet hold a complete header.
    /// Does NOT advance the fragmentation state: call
    /// [`FrameDecoder::commit`] once the header is accepted.
    ///
    /// # Errors
    /// [`WsError`], each of which maps to exactly one [`CloseCode`].
    #[allow(
        clippy::too_many_lines,
        reason = "one cohesive header state machine (reserved bits, opcode, masking \
                  direction, minimal length encoding, control-frame shape, continuation \
                  ordering, the frame ceiling) that RFC 6455 defines as a single header; \
                  splitting it across functions would scatter the ordering the RFC and the \
                  issue's own numbered algorithm both depend on"
    )]
    pub fn decode_header(&self, buf: &[u8]) -> Result<Option<FrameHeader>, WsError> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let Some(&b0) = buf.first() else {
            return Ok(None);
        };
        let Some(&b1) = buf.get(1) else {
            return Ok(None);
        };

        let rsv = (b0 & 0x70) >> 4;
        if rsv & !self.reserved_allowed != 0 {
            return Err(WsError::ReservedBitSet { rsv });
        }

        let opcode =
            Opcode::from_wire(b0 & 0x0f).ok_or(WsError::ReservedOpcode { opcode: b0 & 0x0f })?;
        let fin = b0 & 0x80 != 0;
        let masked = b1 & 0x80 != 0;
        match (self.direction, masked) {
            (Direction::ClientToServer, false) => return Err(WsError::UnmaskedClientFrame),
            (Direction::ServerToClient, true) => return Err(WsError::MaskedServerFrame),
            (Direction::ClientToServer, true) | (Direction::ServerToClient, false) => {}
        }

        // Length, with the minimal encoding rule enforced (RFC 6455 Section 5.2).
        let (payload_len, len_bytes): (u64, usize) = match b1 & 0x7f {
            126 => {
                let Some(v16) = read_u16_be_at(buf, 2) else {
                    return Ok(None);
                };
                let v = u64::from(v16);
                if v < 126 {
                    return Err(WsError::NonMinimalLength {
                        declared: v,
                        form: 16,
                    });
                }
                (v, 4)
            }
            127 => {
                let Some(v) = read_u64_be_at(buf, 2) else {
                    return Ok(None);
                };
                if v < 65536 {
                    return Err(WsError::NonMinimalLength {
                        declared: v,
                        form: 64,
                    });
                }
                if v & (1u64 << 63) != 0 {
                    return Err(WsError::LengthHighBitSet);
                }
                (v, 10)
            }
            n => (u64::from(n), 2),
        };

        // Control frames: at most 125 bytes, never fragmented (RFC 6455 Section 5.5).
        if opcode.is_control() {
            if payload_len > MAX_CONTROL_PAYLOAD {
                return Err(WsError::ControlFrameTooLong { len: payload_len });
            }
            if !fin {
                return Err(WsError::FragmentedControlFrame);
            }
        }

        // Continuation ordering: the whole fragmentation state machine is these two arms.
        match (opcode, self.fragment_open) {
            (Opcode::Continuation, false) => return Err(WsError::UnexpectedContinuation),
            (Opcode::Text | Opcode::Binary, true) => return Err(WsError::InterleavedDataFrame),
            _ => {}
        }

        if payload_len > self.max_frame_bytes {
            return Err(WsError::FrameTooLong {
                len: payload_len,
                max: self.max_frame_bytes,
            });
        }

        let (mask, consumed) = if masked {
            let Some(key) = read_mask_key(buf, len_bytes) else {
                return Ok(None);
            };
            (Some(key), len_bytes.saturating_add(4))
        } else {
            (None, len_bytes)
        };

        Ok(Some(FrameHeader {
            opcode,
            fin,
            payload_len,
            mask,
            consumed,
        }))
    }

    /// Advances the fragmentation state for an accepted header.
    ///
    /// A non-final `Text` or `Binary` opens the fragment, a final
    /// `Continuation` closes it, and a control frame does not touch it: a
    /// control frame may be interleaved into a fragmented message and that
    /// is legal.
    pub fn commit(&mut self, header: &FrameHeader) {
        match header.opcode {
            Opcode::Continuation => {
                if header.fin {
                    self.fragment_open = false;
                    self.fragment_opcode = None;
                }
            }
            Opcode::Text | Opcode::Binary => {
                if header.fin {
                    self.fragment_open = false;
                    self.fragment_opcode = None;
                } else {
                    self.fragment_open = true;
                    self.fragment_opcode = Some(header.opcode);
                }
            }
            Opcode::Close | Opcode::Ping | Opcode::Pong => {}
        }
    }

    /// Validates a close frame's payload.
    ///
    /// Call once the control frame's payload (at most 125 bytes, never
    /// fragmented) is in hand. Reads the status code THROUGH the mask
    /// without modifying a byte: the forwarded payload is exactly the
    /// payload that arrived.
    ///
    /// # Errors
    /// [`WsError::CloseFramePayloadTooShort`] for a 1-byte payload and
    /// [`WsError::InvalidCloseCode`] for a code below 1000 or equal to 1005,
    /// 1006 or 1015. Codes in 3000 to 4999 are library and application
    /// ranges and are accepted.
    #[allow(
        clippy::unused_self,
        reason = "kept as a method on FrameDecoder, not a free function: the caller already \
                  holds the FrameDecoder for this direction when it has a control frame's \
                  payload in hand, and every per-frame validation step living on one type \
                  keeps the codec's public surface at one type instead of splitting it \
                  between a decoder and a set of orphan functions the caller has to import \
                  separately"
    )]
    pub fn validate_close_payload(
        &self,
        header: &FrameHeader,
        payload: &[u8],
    ) -> Result<(), WsError> {
        if payload.is_empty() {
            return Ok(());
        }
        let Some(&p0) = payload.first() else {
            return Err(WsError::CloseFramePayloadTooShort { len: payload.len() });
        };
        let Some(&p1) = payload.get(1) else {
            return Err(WsError::CloseFramePayloadTooShort { len: payload.len() });
        };

        // Read the code THROUGH the mask without modifying a byte. Masking is XOR, so
        // each of the first two plaintext bytes is that wire byte XORed with the
        // matching mask-key byte; reading them this way is not unmasking, since
        // nothing is written back to `payload` and the forwarded bytes stay exactly
        // the bytes that arrived.
        let code = match header.mask {
            None => u16::from_be_bytes([p0, p1]),
            Some(key) => {
                let [k0, k1, _k2, _k3] = key;
                u16::from_be_bytes([p0 ^ k0, p1 ^ k1])
            }
        };

        if code < 1000 || matches!(code, 1005 | 1006 | 1015) {
            return Err(WsError::InvalidCloseCode { code });
        }
        Ok(())
    }

    /// True while a fragmented data message is open.
    #[must_use]
    pub const fn fragment_open(&self) -> bool {
        self.fragment_open
    }

    /// The opcode of the currently open fragmented message, or `None` when
    /// none is open.
    ///
    /// `pub(crate)`, not `pub`: the Design section documents this field as
    /// existing "for the trace", but nothing in this issue's Public API
    /// exposes it yet, so this accessor stays crate-private rather than
    /// widening the public surface beyond what was specified. Its only
    /// caller today is this module's own unit tests below, which is a
    /// `#[cfg(test)]` block absent from an ordinary (non-test) build; without
    /// the allow, that ordinary build has no reader anywhere for either this
    /// method or the field it exposes and rustc's `dead_code` lint (which
    /// `-D warnings` turns into a hard error) fires on both. The field itself
    /// is still genuinely written on every `commit` call, so nothing here is
    /// unreachable, only unread outside tests in this milestone; its first
    /// production reader arrives with whichever of `ws-h1-upgrade-validation`
    /// (#203) or `ws-extended-connect-bridge` (#204) wants the trace.
    #[allow(
        dead_code,
        reason = "read only by this module's #[cfg(test)] unit tests until a later issue \
                  in this milestone adds a production reader; see the doc comment above"
    )]
    #[must_use]
    pub(crate) const fn fragment_opcode(&self) -> Option<Opcode> {
        self.fragment_opcode
    }
}

/// Applies a WebSocket mask to `payload` in place, starting at byte `offset`
/// of the frame's payload.
///
/// `offset` exists because a payload is relayed in pooled chunks, not whole:
/// masking chunk two with `offset: 0` shifts the key and corrupts the frame.
/// The caller keeps a running offset per frame and resets it when the next
/// frame header is committed.
///
/// The relay path NEVER calls this: frames are forwarded with their
/// original mask. Its only legitimate caller is the RFC 8441 bridge, and
/// only for a frame that arrived UNMASKED and is being sent to an HTTP/1
/// upstream that requires masking.
pub fn mask_in_place(payload: &mut [u8], key: [u8; 4], offset: usize) {
    let [k0, k1, k2, k3] = key;
    for (i, byte) in payload.iter_mut().enumerate() {
        let pos = offset.wrapping_add(i) % 4;
        let k = match pos {
            0 => k0,
            1 => k1,
            2 => k2,
            _ => k3,
        };
        *byte ^= k;
    }
}

/// Per-tunnel frame and byte budget.
///
/// Same lazily refilled token bucket shape `ConnBudget` uses for HTTP/2
/// frames, because a tunnel is otherwise an unmetered channel through a
/// gateway whose rate limits and quotas all operate per request.
pub struct TunnelBudget {
    frame_tokens: i64,
    frame_capacity: i64,
    frame_refill_per_sec: i64,
    byte_tokens: i64,
    byte_capacity: i64,
    byte_refill_per_sec: i64,
    last_refill_ms: u32,
}

impl TunnelBudget {
    /// The frame cost of a `Ping` or `Pong`: the cheapest frame for an
    /// attacker to generate and the one that forces a response, so it is
    /// priced above an ordinary data frame.
    const CONTROL_PING_PONG_FRAME_COST: i64 = 5;
    /// The frame cost of every other frame.
    const DEFAULT_FRAME_COST: i64 = 1;

    /// A budget with the shipped defaults: 1000 frames refilling at 200 per
    /// second and 16 MiB refilling at 4 MiB per second.
    #[must_use]
    pub const fn new(now_ms: u32) -> Self {
        Self::with_params(1000, 200, 16 * 1024 * 1024, 4 * 1024 * 1024, now_ms)
    }

    /// A budget with explicit parameters.
    #[must_use]
    pub const fn with_params(
        frame_capacity: i64,
        frame_refill_per_sec: i64,
        byte_capacity: i64,
        byte_refill_per_sec: i64,
        now_ms: u32,
    ) -> Self {
        Self {
            frame_tokens: frame_capacity,
            frame_capacity,
            frame_refill_per_sec,
            byte_tokens: byte_capacity,
            byte_capacity,
            byte_refill_per_sec,
            last_refill_ms: now_ms,
        }
    }

    /// Refills both buckets for the time elapsed since the last refill,
    /// clamped so the elapsed time (via `wrapping_sub`, so a clock that
    /// steps backwards still yields a defined value rather than
    /// underflowing) can never grant more than one full bucket.
    #[allow(
        clippy::integer_division,
        reason = "converting elapsed milliseconds into whole refill tokens; the truncated \
                  remainder is deliberate and simply carries less than one token forward to \
                  the next debit rather than accumulating fractional debt, and the divisor is \
                  the literal, nonzero constant 1000, so this can never divide by zero"
    )]
    fn refill(&mut self, now_ms: u32) {
        let elapsed_ms = i64::from(now_ms.wrapping_sub(self.last_refill_ms));

        let frame_refill = elapsed_ms.saturating_mul(self.frame_refill_per_sec) / 1000;
        self.frame_tokens = self
            .frame_tokens
            .saturating_add(frame_refill)
            .min(self.frame_capacity);

        let byte_refill = elapsed_ms.saturating_mul(self.byte_refill_per_sec) / 1000;
        self.byte_tokens = self
            .byte_tokens
            .saturating_add(byte_refill)
            .min(self.byte_capacity);

        self.last_refill_ms = now_ms;
    }

    /// Debits one frame. Call after the header validates and before the
    /// payload is forwarded.
    ///
    /// `now_ms` is a coarse counter the caller already has. This type never
    /// reads a clock.
    ///
    /// # Errors
    /// [`WsError::BudgetExhausted`], which the caller turns into a close
    /// with [`CloseCode::PolicyViolation`]. It MUST NOT silently drop the
    /// frame: a dropped frame produces a hung application and no signal.
    pub fn debit(&mut self, header: &FrameHeader, now_ms: u32) -> Result<(), WsError> {
        self.refill(now_ms);

        let frame_cost = match header.opcode {
            Opcode::Ping | Opcode::Pong => Self::CONTROL_PING_PONG_FRAME_COST,
            Opcode::Continuation | Opcode::Text | Opcode::Binary | Opcode::Close => {
                Self::DEFAULT_FRAME_COST
            }
        };
        // `decode_header` already refuses a 64-bit length whose high bit is set
        // (`LengthHighBitSet`), so every `payload_len` this type ever sees is at
        // most `i64::MAX`; `unwrap_or(i64::MAX)` is defensive rather than reachable.
        let byte_cost = i64::try_from(header.payload_len).unwrap_or(i64::MAX);

        self.frame_tokens = self.frame_tokens.saturating_sub(frame_cost);
        self.byte_tokens = self.byte_tokens.saturating_sub(byte_cost);

        if self.frame_tokens < 0 || self.byte_tokens < 0 {
            return Err(WsError::BudgetExhausted);
        }
        Ok(())
    }

    /// Frame tokens available. May be negative after an exhausting debit.
    #[must_use]
    pub const fn frame_tokens(&self) -> i64 {
        self.frame_tokens
    }

    /// Byte tokens available. May be negative after an exhausting debit.
    #[must_use]
    pub const fn byte_tokens(&self) -> i64 {
        self.byte_tokens
    }
}

#[cfg(test)]
mod tests {
    use super::{CloseCode, Direction, FrameDecoder, Opcode, TunnelBudget, WsError};

    #[test]
    fn opcode_wire_round_trips_every_defined_value() {
        for (nibble, opcode) in [
            (0x0, Opcode::Continuation),
            (0x1, Opcode::Text),
            (0x2, Opcode::Binary),
            (0x8, Opcode::Close),
            (0x9, Opcode::Ping),
            (0xA, Opcode::Pong),
        ] {
            assert_eq!(Opcode::from_wire(nibble), Some(opcode));
            assert_eq!(opcode.wire(), nibble);
        }
    }

    #[test]
    fn opcode_reserved_nibbles_are_none() {
        for nibble in [0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF] {
            assert_eq!(Opcode::from_wire(nibble), None, "nibble {nibble:#x}");
        }
    }

    #[test]
    fn opcode_is_control_matches_exactly_close_ping_pong() {
        for opcode in [Opcode::Close, Opcode::Ping, Opcode::Pong] {
            assert!(opcode.is_control(), "{opcode:?}");
        }
        for opcode in [Opcode::Continuation, Opcode::Text, Opcode::Binary] {
            assert!(!opcode.is_control(), "{opcode:?}");
        }
    }

    #[test]
    fn opcode_metric_labels_are_unique_and_snake_case() {
        let labels = [
            Opcode::Continuation.metric_label(),
            Opcode::Text.metric_label(),
            Opcode::Binary.metric_label(),
            Opcode::Close.metric_label(),
            Opcode::Ping.metric_label(),
            Opcode::Pong.metric_label(),
        ];
        let mut sorted = labels;
        sorted.sort_unstable();
        for pair in sorted.windows(2) {
            assert_ne!(pair[0], pair[1]);
        }
        for label in labels {
            assert!(label.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
    }

    #[test]
    fn close_code_wire_values_are_pinned() {
        assert_eq!(CloseCode::Normal.wire(), 1000);
        assert_eq!(CloseCode::GoingAway.wire(), 1001);
        assert_eq!(CloseCode::ProtocolError.wire(), 1002);
        assert_eq!(CloseCode::PolicyViolation.wire(), 1008);
        assert_eq!(CloseCode::MessageTooBig.wire(), 1009);
        assert_eq!(CloseCode::InternalError.wire(), 1011);
    }

    #[test]
    fn close_code_metric_labels_are_unique() {
        let labels = [
            CloseCode::Normal.metric_label(),
            CloseCode::GoingAway.metric_label(),
            CloseCode::ProtocolError.metric_label(),
            CloseCode::PolicyViolation.metric_label(),
            CloseCode::MessageTooBig.metric_label(),
            CloseCode::InternalError.metric_label(),
        ];
        let mut sorted = labels;
        sorted.sort_unstable();
        for pair in sorted.windows(2) {
            assert_ne!(pair[0], pair[1]);
        }
    }

    #[test]
    fn ws_error_close_code_mapping_is_pinned() {
        assert_eq!(
            WsError::ReservedBitSet { rsv: 1 }.close_code(),
            CloseCode::ProtocolError
        );
        assert_eq!(
            WsError::FrameTooLong { len: 1, max: 0 }.close_code(),
            CloseCode::MessageTooBig
        );
        assert_eq!(
            WsError::BudgetExhausted.close_code(),
            CloseCode::PolicyViolation
        );
    }

    #[test]
    fn ws_error_metric_labels_are_unique() {
        let errors = [
            WsError::ReservedBitSet { rsv: 0 },
            WsError::ReservedOpcode { opcode: 0 },
            WsError::UnmaskedClientFrame,
            WsError::MaskedServerFrame,
            WsError::NonMinimalLength {
                declared: 0,
                form: 16,
            },
            WsError::LengthHighBitSet,
            WsError::ControlFrameTooLong { len: 0 },
            WsError::FragmentedControlFrame,
            WsError::UnexpectedContinuation,
            WsError::InterleavedDataFrame,
            WsError::FrameTooLong { len: 0, max: 0 },
            WsError::CloseFramePayloadTooShort { len: 0 },
            WsError::InvalidCloseCode { code: 0 },
            WsError::BudgetExhausted,
        ];
        let mut labels: Vec<&str> = errors.iter().map(WsError::metric_label).collect();
        labels.sort_unstable();
        assert_eq!(labels.len(), 14);
        for pair in labels.windows(2) {
            assert_ne!(pair[0], pair[1], "duplicate metric label: {}", pair[0]);
        }
    }

    // `mask_in_place` is deliberately NOT unit-tested here: this crate's own
    // acceptance criterion greps `crates/irontraffic-ws/src` for the name and
    // requires it to show only the definition, never a call site, because the
    // relay path must never call it (see its doc comment above). Its tests
    // live in `tests/frames.rs` instead, a separate crate under `tests/`
    // rather than `src/`, where calling it to test it does not trip that grep.

    #[test]
    fn commit_opens_and_closes_the_fragment_and_tracks_its_opcode() {
        let mut decoder = FrameDecoder::new(Direction::ServerToClient);
        assert!(!decoder.fragment_open());
        assert_eq!(decoder.fragment_opcode(), None);

        // A non-final Binary opens the fragment.
        let open = decoder
            .decode_header(&[0x02, 0x00])
            .expect("valid header")
            .expect("complete header");
        decoder.commit(&open);
        assert!(decoder.fragment_open());
        assert_eq!(decoder.fragment_opcode(), Some(Opcode::Binary));

        // A control frame interleaved into the open fragment does not touch it.
        let ping = decoder
            .decode_header(&[0x89, 0x00])
            .expect("valid header")
            .expect("complete header");
        decoder.commit(&ping);
        assert!(decoder.fragment_open());
        assert_eq!(decoder.fragment_opcode(), Some(Opcode::Binary));

        // A final Continuation closes the fragment.
        let close = decoder
            .decode_header(&[0x80, 0x00])
            .expect("valid header")
            .expect("complete header");
        decoder.commit(&close);
        assert!(!decoder.fragment_open());
        assert_eq!(decoder.fragment_opcode(), None);
    }

    #[test]
    fn tunnel_budget_new_starts_at_full_capacity() {
        let budget = TunnelBudget::new(0);
        assert_eq!(budget.frame_tokens(), 1000);
        assert_eq!(budget.byte_tokens(), 16 * 1024 * 1024);
    }

    /// A two-byte unmasked `Ping` header: legal on `ServerToClient`, where
    /// masking is forbidden, and complete in exactly 2 bytes (no extended
    /// length, no mask key), which is all these budget tests need.
    fn server_to_client_ping_header() -> super::FrameHeader {
        FrameDecoder::new(Direction::ServerToClient)
            .decode_header(&[0x89, 0x00])
            .expect("a well-formed server-to-client ping header does not error")
            .expect("both header bytes are present, so decoding cannot be incomplete")
    }

    #[test]
    fn tunnel_budget_refill_never_exceeds_capacity_even_after_a_huge_gap() {
        let mut budget = TunnelBudget::with_params(10, 200, 10, 200, 0);
        let header = server_to_client_ping_header();
        // A debit at a far-future timestamp forces `refill` to see a huge elapsed
        // time; the result must still be clamped to `frame_capacity`/`byte_capacity`,
        // never exceed it.
        let _ = budget.debit(&header, u32::MAX);
        assert!(budget.frame_tokens() <= 10);
        assert!(budget.byte_tokens() <= 10);
    }

    #[test]
    fn tunnel_budget_debit_goes_negative_on_exhaustion_rather_than_clamping_at_zero() {
        let cost = TunnelBudget::CONTROL_PING_PONG_FRAME_COST;
        // Capacity covers exactly one ping's cost with room to spare, but not two:
        // the first debit must succeed and the second must exhaust the bucket.
        let mut budget = TunnelBudget::with_params(cost + 1, 0, 1_000_000, 0, 0);
        let header = server_to_client_ping_header();
        assert!(budget.debit(&header, 0).is_ok());
        assert_eq!(budget.debit(&header, 0), Err(WsError::BudgetExhausted));
        assert_eq!(budget.frame_tokens(), cost + 1 - cost - cost);
    }
}
