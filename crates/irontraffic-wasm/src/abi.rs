// SPDX-License-Identifier: MIT OR Apache-2.0

//! Names, return-value encoding, and the one guest-memory slice primitive for
//! ITX ABI v1.

use irontraffic_filter::action::{Action, DirectResponse, ResetCode, ShortCircuitReason};
use irontraffic_filter::phase::Phase;

/// The ABI version this host implements.
pub const ITX_ABI_VERSION: i32 = 1;

/// The mapping from a `Phase` to the guest export that serves it, written out in
/// full. This is the ONLY way to get an export name for a phase.
///
/// Seven entries, not ten: `RouteSelected`, `UpstreamRequestHeaders` and `Log`
/// have no guest export in ITX v1.
pub const PHASE_EXPORTS: [(Phase, &str); 7] = [
    (Phase::StreamStart, "itx_on_stream_start"),
    (Phase::RequestHeaders, "itx_on_request_headers"),
    (Phase::RequestBody, "itx_on_request_body"),
    (Phase::RequestTrailers, "itx_on_request_trailers"),
    (Phase::ResponseHeaders, "itx_on_response_headers"),
    (Phase::ResponseBody, "itx_on_response_body"),
    (Phase::ResponseTrailers, "itx_on_response_trailers"),
];

/// Every export name a v1 guest may define, in exactly this order. The array is
/// the admission-time checklist; it is not indexed by phase.
///
/// **There is no arithmetic relationship between a `Phase` index and an index into
/// this array, and code that invents one is wrong.** Only seven of the ten phases
/// have a guest export. A reader who writes `EXPORTS[2 + phase.index()]` gets the
/// right name for phases 0 to 3 and the WRONG name for every response phase
/// (`ResponseHeaders`, index 6, would resolve to `itx_on_response_trailers`),
/// which is a host that calls the guest's trailer hook and tells it that it is
/// looking at the response head. Use `PHASE_EXPORTS` above, which is the whole
/// mapping written out.
///
/// The two OPTIONAL body-arena exports added by `{{wasm-body-in-guest-memory}}`
/// are deliberately not members of this array; they live in their own
/// `ARENA_EXPORTS`, because `check_shape` derives the phase mask by position over
/// this one and growing it shifts every phase.
pub const EXPORTS: [&str; 10] = [
    "itx_abi_version",
    "itx_on_config",
    "itx_on_stream_start",
    "itx_on_request_headers",
    "itx_on_request_body",
    "itx_on_request_trailers",
    "itx_on_response_headers",
    "itx_on_response_body",
    "itx_on_response_trailers",
    "itx_on_stream_destroy",
];

/// Every import name the host defines, in the order of the import table.
pub const IMPORTS: [&str; 11] = [
    "itx_get_header",
    "itx_header_count",
    "itx_get_header_at",
    "itx_set_header",
    "itx_remove_header",
    "itx_apply_ops",
    "itx_get_attr",
    "itx_body_len",
    "itx_body_read",
    "itx_body_replace",
    "itx_log",
];

/// Import names that are reserved and deliberately not defined in v1.
pub const RESERVED_IMPORTS: [&str; 2] = ["itx_call_service", "itx_call_result"];

/// Bytes of one op record.
pub const OP_RECORD_BYTES: u32 = 20;

/// Largest name or value one op record may name. `65_536` bytes.
pub const MAX_OP_FIELD_BYTES: u32 = 65_536;

/// Return code for a host import that succeeded with no length to report.
pub const ITX_OK: i32 = 0;

/// Return code for an absent field or attribute.
pub const ITX_ABSENT: i32 = -1;

/// Return code for a field that appeared more than once, which the guest must not
/// resolve by picking one.
pub const ITX_DUPLICATE: i32 = -2;

/// Return code for an argument that failed validation.
pub const ITX_INVALID: i32 = -3;

/// Return code for an operation not permitted in the current phase.
pub const ITX_WRONG_PHASE: i32 = -4;

/// Return code for a budget that is exhausted: ops, scratch, or body hold.
pub const ITX_BUDGET: i32 = -5;

/// What a guest phase export returned, decoded from its `i32`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuestAction {
    /// Proceed to the next filter.
    Continue,
    /// The guest is waiting. The host pauses the chain.
    Pause,
    /// Send this response downstream.
    Respond {
        /// HTTP status code in `200..=599`.
        status: u16,
        /// Response-template index, or `u16::MAX` for no template.
        template: u16,
    },
    /// Reset the stream.
    Reset {
        /// Reset code in `0..=3`.
        code: u8,
    },
}

/// A wire-level or validation error in the ITX ABI.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AbiError {
    /// The guest returned a negative value, which is its way of reporting failure.
    GuestError {
        /// The exact value returned by the guest.
        code: i32,
    },
    /// The low four bits are not a defined action.
    UnknownAction {
        /// The raw return value.
        raw: i32,
    },
    /// A payload field is out of range: a status outside `200..=599`, a reset code
    /// above 3, or a non-zero payload on `Continue`.
    BadPayload {
        /// The raw return value.
        raw: i32,
    },
    /// A `(ptr, len)` pair that does not lie inside linear memory, including the
    /// case where `ptr + len` overflows.
    OutOfBounds {
        /// Guest pointer.
        ptr: u32,
        /// Guest length.
        len: u32,
        /// Length of the linear memory buffer.
        mem_len: usize,
    },
    /// An op-list length that is not a multiple of the record size.
    RaggedOpList {
        /// The length passed by the guest.
        len: u32,
    },
    /// More ops than the host's per-phase cap.
    TooManyOps {
        /// The number the guest claimed.
        count: u32,
        /// The host cap.
        max: u32,
    },
    /// A reserved field in an op record is non-zero.
    ReservedNonZero {
        /// Byte offset of the offending record.
        at: u32,
    },
    /// An op discriminant or target that is not defined.
    BadOpRecord {
        /// Byte offset of the offending record.
        at: u32,
    },
    /// An op-list pointer that is not 4-byte aligned.
    Misaligned {
        /// The guest pointer.
        ptr: u32,
    },
    /// A name or value length above `MAX_OP_FIELD_BYTES`.
    FieldTooLarge {
        /// Byte offset of the offending record.
        at: u32,
        /// The length that was too large.
        len: u32,
        /// The maximum allowed length.
        max: u32,
    },
}

impl GuestAction {
    /// Decodes a guest export's return value.
    ///
    /// # Errors
    /// `AbiError::GuestError`, `UnknownAction`, `BadPayload`.
    pub fn decode(raw: i32) -> Result<Self, AbiError> {
        if raw < 0 {
            return Err(AbiError::GuestError { code: raw });
        }

        let uraw = raw.cast_unsigned();
        let action = uraw & 0xF;

        match action {
            0 => {
                if uraw & !0xF != 0 {
                    Err(AbiError::BadPayload { raw })
                } else {
                    Ok(GuestAction::Continue)
                }
            }
            1 => {
                if uraw & !0xF != 0 {
                    Err(AbiError::BadPayload { raw })
                } else {
                    Ok(GuestAction::Pause)
                }
            }
            2 => {
                if uraw & !0x3FFF_FFFF != 0 {
                    return Err(AbiError::BadPayload { raw });
                }
                let status_field = ((uraw >> 4) & 0x3FF) as u16;
                if !(100..=499).contains(&status_field) {
                    return Err(AbiError::BadPayload { raw });
                }
                let template = ((uraw >> 14) & 0xFFFF) as u16;
                Ok(GuestAction::Respond {
                    status: status_field + 100,
                    template,
                })
            }
            3 => {
                if uraw & !0x3F != 0 {
                    return Err(AbiError::BadPayload { raw });
                }
                let code = ((uraw >> 4) & 0x3) as u8;
                Ok(GuestAction::Reset { code })
            }
            _ => Err(AbiError::UnknownAction { raw }),
        }
    }

    /// Encodes an action, for tests and for the guest SDK's reference
    /// implementation.
    ///
    /// # Errors
    /// `AbiError::BadPayload` when a field is out of range.
    pub fn encode(self) -> Result<i32, AbiError> {
        let raw = match self {
            GuestAction::Continue => 0,
            GuestAction::Pause => 1,
            GuestAction::Respond { status, template } => {
                let field = status.checked_sub(100).ok_or(AbiError::BadPayload {
                    raw: i32::from(status), // it-allow: no-std-io reason: this value is only used for diagnostics and never escapes to the guest.
                })?;
                if field > 499 {
                    return Err(AbiError::BadPayload {
                        raw: i32::from(status),
                    });
                }
                2 | ((i32::from(field)) << 4) | ((i32::from(template)) << 14)
            }
            GuestAction::Reset { code } => {
                if code > 3 {
                    return Err(AbiError::BadPayload {
                        raw: i32::from(code),
                    });
                }
                3 | ((i32::from(code)) << 4)
            }
        };
        Ok(raw)
    }

    /// The chain action this maps to, or `None` when the guest's payload does not
    /// name a legal one.
    ///
    /// Exactly:
    /// - `Continue` -> `Some(Action::Continue)`
    /// - `Pause` -> `Some(Action::Pause)`
    /// - `Respond { status, template }` ->
    ///   `DirectResponse::new(status, template, ShortCircuitReason::FilterGenerated)
    ///   .map(Action::Respond)`, so a status outside `200..=599` is `None`
    /// - `Reset { code }` -> `ResetCode::from_index(code).map(Action::Reset)`, so a
    ///   code above 3 is `None`
    ///
    /// `ShortCircuitReason::FilterGenerated` is correct for every guest-produced
    /// response: the guest is producing its output, not reporting a failure. A guest
    /// that failed returns a negative value, which never reaches this function.
    /// The caller (`{{wasm-filter-adapter-and-lifecycle}}`) treats `None` as a
    /// protocol violation: `FilterFailure::Protocol`, poison the instance, apply the
    /// failure mode.
    #[must_use]
    pub fn to_action(self) -> Option<Action> {
        match self {
            GuestAction::Continue => Some(Action::Continue),
            GuestAction::Pause => Some(Action::Pause),
            GuestAction::Respond { status, template } => {
                DirectResponse::new(status, template, ShortCircuitReason::FilterGenerated)
                    .map(Action::Respond)
            }
            GuestAction::Reset { code } => ResetCode::from_index(code).map(Action::Reset),
        }
    }
}

/// Turns a guest `(ptr, len)` pair into a slice of linear memory.
///
/// This is the ONLY function in this crate that indexes guest memory. Every other
/// function takes a slice this one returned. That rule is enforced by a CI grep.
///
/// # Errors
/// `AbiError::OutOfBounds`, including when `ptr + len` overflows `u32`.
pub fn guest_slice(mem: &[u8], ptr: u32, len: u32) -> Result<&[u8], AbiError> {
    let mem_len = mem.len();
    let end = u64::from(ptr)
        .checked_add(u64::from(len))
        .ok_or(AbiError::OutOfBounds { ptr, len, mem_len })?;
    if end > u64::try_from(mem_len).unwrap_or(u64::MAX) {
        return Err(AbiError::OutOfBounds { ptr, len, mem_len });
    }
    let start = usize::try_from(ptr).map_err(|_| AbiError::OutOfBounds { ptr, len, mem_len })?;
    let end = usize::try_from(end).map_err(|_| AbiError::OutOfBounds { ptr, len, mem_len })?;
    mem.get(start..end)
        .ok_or(AbiError::OutOfBounds { ptr, len, mem_len })
}

/// The mutable twin, for host functions that fill a guest-provided buffer.
///
/// # Errors
/// `AbiError::OutOfBounds`.
pub fn guest_slice_mut(mem: &mut [u8], ptr: u32, len: u32) -> Result<&mut [u8], AbiError> {
    let mem_len = mem.len();
    let end = u64::from(ptr)
        .checked_add(u64::from(len))
        .ok_or(AbiError::OutOfBounds { ptr, len, mem_len })?;
    if end > u64::try_from(mem_len).unwrap_or(u64::MAX) {
        return Err(AbiError::OutOfBounds { ptr, len, mem_len });
    }
    let start = usize::try_from(ptr).map_err(|_| AbiError::OutOfBounds { ptr, len, mem_len })?;
    let end = usize::try_from(end).map_err(|_| AbiError::OutOfBounds { ptr, len, mem_len })?;
    mem.get_mut(start..end)
        .ok_or(AbiError::OutOfBounds { ptr, len, mem_len })
}

#[cfg(test)]
mod tests {
    use super::*;
    use irontraffic_filter::action::ResetCode;

    #[test]
    fn decode_continue() {
        assert_eq!(GuestAction::decode(0), Ok(GuestAction::Continue));
    }

    #[test]
    fn decode_pause() {
        assert_eq!(GuestAction::decode(1), Ok(GuestAction::Pause));
    }

    #[test]
    fn continue_with_payload_is_bad() {
        for payload in [1 << 4, 1 << 14, 1 << 29] {
            let raw = payload;
            assert_eq!(
                GuestAction::decode(raw),
                Err(AbiError::BadPayload { raw }),
                "payload {payload}"
            );
        }
    }

    #[test]
    fn respond_status_bounds() {
        assert_eq!(
            GuestAction::decode(
                GuestAction::Respond {
                    status: 200,
                    template: 0
                }
                .encode()
                .unwrap()
            ),
            Ok(GuestAction::Respond {
                status: 200,
                template: 0
            })
        );
        assert_eq!(
            GuestAction::decode(
                GuestAction::Respond {
                    status: 599,
                    template: 0
                }
                .encode()
                .unwrap()
            ),
            Ok(GuestAction::Respond {
                status: 599,
                template: 0
            })
        );

        for status in [99, 100, 101, 199, 600] {
            assert_eq!(
                GuestAction::Respond {
                    status,
                    template: 0
                }
                .encode(),
                Err(AbiError::BadPayload {
                    raw: i32::from(status)
                }),
                "status {status}"
            );
        }

        // Field 99 is the 1xx status 199, rejected by the decode range check.
        assert_eq!(
            GuestAction::decode(2 | (99 << 4)),
            Err(AbiError::BadPayload { raw: 2 | (99 << 4) })
        );
        // Field 500 is the status 700, rejected by the decode range check.
        assert_eq!(
            GuestAction::decode(2 | (500 << 4)),
            Err(AbiError::BadPayload {
                raw: 2 | (500 << 4)
            })
        );
    }

    #[test]
    fn respond_template_max() {
        let action = GuestAction::Respond {
            status: 200,
            template: u16::MAX,
        };
        let raw = action.encode().unwrap();
        assert_eq!(GuestAction::decode(raw), Ok(action));
    }

    #[test]
    fn reset_code_bounds() {
        for code in 0..=3 {
            let action = GuestAction::Reset { code };
            let raw = action.encode().unwrap();
            assert_eq!(GuestAction::decode(raw), Ok(action));
        }

        assert_eq!(
            GuestAction::Reset { code: 4 }.encode(),
            Err(AbiError::BadPayload { raw: 4 })
        );

        // Raw with action=3 and bit 6 set, which is outside the reset-code field.
        assert_eq!(
            GuestAction::decode(3 | (4 << 4)),
            Err(AbiError::BadPayload { raw: 3 | (4 << 4) })
        );
    }

    #[test]
    fn bit_30_must_be_zero() {
        let raw = 2 | (100 << 4) | (1 << 30);
        assert!(raw > 0);
        assert_eq!(GuestAction::decode(raw), Err(AbiError::BadPayload { raw }));
    }

    #[test]
    fn negative_is_guest_error() {
        for code in [-1, -5, i32::MIN] {
            assert_eq!(
                GuestAction::decode(code),
                Err(AbiError::GuestError { code }),
                "code {code}"
            );
        }
    }

    #[test]
    fn unknown_action_nibble() {
        let raw = 7;
        assert_eq!(
            GuestAction::decode(raw),
            Err(AbiError::UnknownAction { raw })
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let actions = [
            GuestAction::Continue,
            GuestAction::Pause,
            GuestAction::Respond {
                status: 200,
                template: 0,
            },
            GuestAction::Respond {
                status: 599,
                template: u16::MAX,
            },
            GuestAction::Respond {
                status: 404,
                template: 7,
            },
            GuestAction::Reset { code: 0 },
            GuestAction::Reset { code: 3 },
        ];
        for action in actions {
            let raw = action.encode().unwrap();
            assert_eq!(GuestAction::decode(raw), Ok(action), "action {action:?}");
        }
    }

    #[test]
    fn to_action_mapping() {
        assert_eq!(GuestAction::Continue.to_action(), Some(Action::Continue));
        assert_eq!(GuestAction::Pause.to_action(), Some(Action::Pause));
        assert_eq!(
            GuestAction::Respond {
                status: 403,
                template: 7,
            }
            .to_action(),
            Some(Action::Respond(DirectResponse {
                status: 403,
                template: 7,
                reason: ShortCircuitReason::FilterGenerated,
            }))
        );
        assert_eq!(
            GuestAction::Reset { code: 3 }.to_action(),
            Some(Action::Reset(ResetCode::Overload))
        );
        assert_eq!(GuestAction::Reset { code: 9 }.to_action(), None);
    }

    #[test]
    fn guest_slice_zero_len_at_end() {
        let mem = [0u8, 1, 2, 3];
        let slice = guest_slice(&mem, 4, 0).expect("zero-length at end");
        assert!(slice.is_empty());
        assert_eq!(slice.as_ptr(), mem.as_ptr().wrapping_add(4));
    }

    #[test]
    fn guest_slice_one_past_end() {
        let mem = [0u8, 1, 2, 3];
        assert_eq!(
            guest_slice(&mem, 4, 1),
            Err(AbiError::OutOfBounds {
                ptr: 4,
                len: 1,
                mem_len: 4,
            })
        );
    }

    #[test]
    fn guest_slice_wrapping_pointer() {
        let mem = [0u8, 0, 0, 0];
        assert_eq!(
            guest_slice(&mem, 0xFFFF_FFF0, 0x20),
            Err(AbiError::OutOfBounds {
                ptr: 0xFFFF_FFF0,
                len: 0x20,
                mem_len: 4,
            })
        );
    }

    #[test]
    fn guest_slice_empty_memory() {
        let mem: [u8; 0] = [];
        let empty: &[u8] = &[];
        assert_eq!(guest_slice(&mem, 0, 0), Ok(empty));
        assert_eq!(
            guest_slice(&mem, 0, 1),
            Err(AbiError::OutOfBounds {
                ptr: 0,
                len: 1,
                mem_len: 0,
            })
        );
        assert_eq!(
            guest_slice(&mem, 1, 0),
            Err(AbiError::OutOfBounds {
                ptr: 1,
                len: 0,
                mem_len: 0,
            })
        );
    }

    #[test]
    fn guest_slice_mut_same_bounds() {
        let cases: [(u32, u32, usize, bool); 8] = [
            (0, 0, 0, true),
            (0, 0, 4, true),
            (0, 4, 4, true),
            (4, 0, 4, true),
            (4, 1, 4, false),
            (0xFFFF_FFF0, 0x20, 4, false),
            (3, 2, 4, false),
            (0, 5, 4, false),
        ];

        for (ptr, len, mem_len, ok) in cases {
            let mem_imm = vec![0u8; mem_len];
            let imm = guest_slice(&mem_imm, ptr, len);
            let mut mem_mut = vec![0u8; mem_len];
            let mut_res = guest_slice_mut(&mut mem_mut, ptr, len);
            assert_eq!(imm.is_ok(), ok, "ptr={ptr} len={len} mem_len={mem_len}");
            assert_eq!(mut_res.is_ok(), ok, "ptr={ptr} len={len} mem_len={mem_len}");
            if ok {
                assert_eq!(imm.unwrap().len(), len as usize);
                assert_eq!(mut_res.unwrap().len(), len as usize);
            }
        }
    }
}
