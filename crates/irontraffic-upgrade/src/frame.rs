// SPDX-License-Identifier: MIT OR Apache-2.0

//! The versioned, length-prefixed descriptor-handoff frame.

use crate::{CHECKSUM_BYTES, FRAME_MAGIC, FRAME_VERSION, HEADER_BYTES, MAX_ADDR_BYTES, MAX_FDS};

/// One transferred listening socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffEntry {
    /// The canonical bind address, from `irontraffic_config::BindAddr::canonical_key`.
    pub addr: String,
    /// Index into the accompanying descriptor array.
    pub fd_index: u16,
}

/// The handoff frame.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HandoffFrame {
    /// The transferred sockets, in the order the descriptors were sent.
    pub entries: Vec<HandoffEntry>,
}

impl HandoffFrame {
    /// A frame carrying `entries`.
    ///
    /// # Errors
    /// [`FrameError::TooManyDescriptors`] above [`MAX_FDS`],
    /// [`FrameError::BadAddressLength`] for an empty or oversized address,
    /// [`FrameError::FdIndexOutOfRange`] for an `fd_index` at or above `entries.len()`,
    /// [`FrameError::DuplicateFdIndex`] for two entries naming the same `fd_index`. The
    /// last two mirror [`HandoffFrame::decode`]'s own checks, so a frame this
    /// constructor accepts always decodes back to itself; see invariant 3 in the
    /// issue this crate implements.
    pub fn new(entries: Vec<HandoffEntry>) -> Result<Self, FrameError> {
        Self::validate(&entries)?;
        Ok(Self { entries })
    }

    /// Serialises the frame, allocating exactly the required bytes.
    ///
    /// # Errors
    /// The same errors [`HandoffFrame::new`] reports, re-checked so a mutated frame
    /// cannot produce an invalid encoding.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        Self::validate(&self.entries)?;

        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&FRAME_MAGIC);
        out.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(
            &u16::try_from(self.entries.len())
                .map_err(|_| FrameError::TooManyDescriptors {
                    count: self.entries.len(),
                    max: MAX_FDS,
                })?
                .to_le_bytes(),
        );
        out.extend_from_slice(&0u16.to_le_bytes());

        for entry in &self.entries {
            let addr_len =
                u16::try_from(entry.addr.len()).map_err(|_| FrameError::BadAddressLength {
                    entry: 0,
                    len: entry.addr.len(),
                    max: MAX_ADDR_BYTES,
                })?;
            out.extend_from_slice(&addr_len.to_le_bytes());
            out.extend_from_slice(&entry.fd_index.to_le_bytes());
            out.extend_from_slice(entry.addr.as_bytes());
        }

        let hash = blake3::hash(&out);
        out.extend(hash.as_bytes().iter().take(CHECKSUM_BYTES));

        Ok(out)
    }

    /// Parses a frame.
    ///
    /// Never panics, never allocates from an unvalidated length, and never reads past
    /// `bytes`.
    ///
    /// **The caller must verify that the number of descriptors it actually received
    /// equals `entries.len()` before using any `fd_index`.** This function validates that
    /// every index is below the declared count; it has no way to know how many
    /// descriptors arrived, and a frame declaring five with three received is an
    /// out-of-bounds index into a real array.
    ///
    /// # Errors
    /// See [`FrameError`]. Every variant names the offending value and the limit.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let min_len = HEADER_BYTES + CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(FrameError::Truncated {
                need: min_len,
                got: bytes.len(),
            });
        }

        let (count, rest) = Self::parse_header(bytes)?;
        let count_usize = usize::from(count);
        if count_usize > MAX_FDS {
            return Err(FrameError::TooManyDescriptors {
                count: count_usize,
                max: MAX_FDS,
            });
        }

        let (entries_end, rest) = Self::validate_entries(count_usize, rest)?;
        Self::verify_checksum(bytes, entries_end, rest)?;
        let entries = Self::build_entries(count_usize, bytes, entries_end)?;

        Ok(Self { entries })
    }

    fn parse_header(bytes: &[u8]) -> Result<(u16, &[u8]), FrameError> {
        let (header, rest) = bytes
            .split_at_checked(HEADER_BYTES)
            .ok_or(FrameError::BadMagic)?;

        let (magic, after_magic) = header
            .split_at_checked(FRAME_MAGIC.len())
            .ok_or(FrameError::BadMagic)?;
        if magic != FRAME_MAGIC.as_slice() {
            return Err(FrameError::BadMagic);
        }

        let (version, after_version) = split_u16_le(after_magic).ok_or(FrameError::BadMagic)?;
        if version != FRAME_VERSION {
            return Err(FrameError::UnsupportedVersion { found: version });
        }

        let (flags, after_flags) = split_u16_le(after_version).ok_or(FrameError::BadMagic)?;
        let (count, after_count) = split_u16_le(after_flags).ok_or(FrameError::BadMagic)?;
        let (reserved, _) = split_u16_le(after_count).ok_or(FrameError::BadMagic)?;

        if flags != 0 || reserved != 0 {
            return Err(FrameError::ReservedNotZero);
        }

        Ok((count, rest))
    }

    fn validate_entries(count: usize, mut rest: &[u8]) -> Result<(usize, &[u8]), FrameError> {
        let mut entries_end = HEADER_BYTES;
        let mut seen = [false; MAX_FDS];

        for entry in 0..count {
            if rest.len() < 4 {
                return Err(FrameError::Truncated {
                    need: 4,
                    got: rest.len(),
                });
            }

            let (fixed, _) = rest.split_at_checked(4).ok_or(FrameError::BadMagic)?;
            let (addr_len_bytes, fd_index_bytes) =
                fixed.split_at_checked(2).ok_or(FrameError::BadMagic)?;
            let addr_len = u16::from_le_bytes(
                addr_len_bytes
                    .try_into()
                    .map_err(|_| FrameError::BadMagic)?,
            );
            let fd_index = u16::from_le_bytes(
                fd_index_bytes
                    .try_into()
                    .map_err(|_| FrameError::BadMagic)?,
            );
            let addr_len_usize = usize::from(addr_len);

            if addr_len_usize == 0 || addr_len_usize > MAX_ADDR_BYTES {
                return Err(FrameError::BadAddressLength {
                    entry,
                    len: addr_len_usize,
                    max: MAX_ADDR_BYTES,
                });
            }

            // EQUIVALENT MUTANT, PROVED: mutation testing flagged `4 + addr_len_usize`
            // on the next line as survivable (`+` to `*`). It cannot be observed by any
            // input, well-formed or hostile: `addr_len_usize` was just checked above to
            // be at most MAX_ADDR_BYTES (64), so `4usize.checked_add(addr_len_usize)` is
            // `4usize.checked_add(<= 64)`, which is always `Some` on every platform this
            // crate builds for (`usize` is at least 16 bits). `checked_add` can only
            // return `None`, making this `.ok_or(...)` closure run at all, when the sum
            // would overflow `usize::MAX`, which is unreachable here by more than sixty
            // orders of magnitude. The expression inside is therefore dead code for
            // every reachable value of `addr_len_usize`, and no test can distinguish `+`
            // from `*` here without first making this branch reachable, which would be a
            // change to the bound above, not to this line.
            let need = 4usize
                .checked_add(addr_len_usize)
                .ok_or(FrameError::Truncated {
                    need: 4 + addr_len_usize,
                    got: rest.len(),
                })?;
            if rest.len() < need {
                return Err(FrameError::Truncated {
                    need,
                    got: rest.len(),
                });
            }

            let (entry_bytes, after_entry) =
                rest.split_at_checked(need).ok_or(FrameError::Truncated {
                    need,
                    got: rest.len(),
                })?;
            let (_, addr_bytes) = entry_bytes
                .split_at_checked(4)
                .ok_or(FrameError::Truncated {
                    need: 4,
                    got: entry_bytes.len(),
                })?;
            if core::str::from_utf8(addr_bytes).is_err() {
                return Err(FrameError::NotUtf8 { entry });
            }

            let fd_index_usize = usize::from(fd_index);
            if fd_index_usize >= count {
                return Err(FrameError::FdIndexOutOfRange {
                    entry,
                    index: fd_index,
                    count,
                });
            }
            let flag = seen
                .get_mut(fd_index_usize)
                .ok_or(FrameError::FdIndexOutOfRange {
                    entry,
                    index: fd_index,
                    count,
                })?;
            if *flag {
                return Err(FrameError::DuplicateFdIndex { index: fd_index });
            }
            *flag = true;

            rest = after_entry;
            entries_end = entries_end.checked_add(need).ok_or(FrameError::Truncated {
                need,
                got: rest.len(),
            })?;
        }

        Ok((entries_end, rest))
    }

    fn verify_checksum(bytes: &[u8], entries_end: usize, rest: &[u8]) -> Result<(), FrameError> {
        if rest.len() < CHECKSUM_BYTES {
            return Err(FrameError::Truncated {
                need: CHECKSUM_BYTES,
                got: rest.len(),
            });
        }

        let (content, _) = bytes
            .split_at_checked(entries_end)
            .ok_or(FrameError::Truncated {
                need: entries_end,
                got: bytes.len(),
            })?;
        let (received_checksum, tail) =
            rest.split_at_checked(CHECKSUM_BYTES)
                .ok_or(FrameError::Truncated {
                    need: CHECKSUM_BYTES,
                    got: rest.len(),
                })?;
        let hash = blake3::hash(content);
        let expected = hash.as_bytes();
        // `.take(CHECKSUM_BYTES)` on `expected` (32 bytes, a full blake3 hash) is
        // redundant with `.zip`, which already stops at `received_checksum`'s
        // length (exactly `CHECKSUM_BYTES`, from the `split_at_checked` above):
        // removing it changes nothing `zip` would ever iterate. It stays because
        // it makes "exactly CHECKSUM_BYTES bytes are compared" a property of this
        // line rather than a fact the reader has to derive from `zip`'s implicit
        // truncation and `received_checksum`'s length elsewhere in the function.
        if !received_checksum
            .iter()
            .zip(expected.iter().take(CHECKSUM_BYTES))
            .all(|(a, b)| a == b)
        {
            return Err(FrameError::BadChecksum);
        }

        if !tail.is_empty() {
            return Err(FrameError::TrailingBytes { extra: tail.len() });
        }

        Ok(())
    }

    // ALLOCATION BOUND, PROVED STATICALLY. `decode` calls this function only after
    // both `validate_entries` and `verify_checksum` have already succeeded, so by
    // the time it runs, every value it allocates from has already been checked
    // against bytes physically present in `bytes`, never merely against a
    // declared length:
    //   - `count` is at most `MAX_FDS` (checked in `decode` before
    //     `validate_entries` even starts), so `Vec::with_capacity(count)` below is
    //     bounded by the compile-time constant `MAX_FDS`, never by an
    //     attacker-chosen value.
    //   - each entry's `addr_len` was already checked by `validate_entries` to be
    //     at most `MAX_ADDR_BYTES` AND to have that many bytes actually present in
    //     `bytes` (`validate_entries` returns `Truncated` otherwise), so the
    //     `to_owned()` below allocates at most `MAX_ADDR_BYTES` bytes per entry
    //     and never reads, let alone allocates from, a length that outruns the
    //     input.
    // The total additional heap use this function can cause is therefore bounded
    // by `MAX_FDS * (size_of::<HandoffEntry>() + MAX_ADDR_BYTES)`, a fixed
    // constant, for every input, including one that DECLARES a far larger count
    // or address length than is present. This is the property tests 8 and 21 ask
    // for a counting allocator to measure; that measurement cannot be written in
    // this crate, because `[lints] workspace = true` denies `unsafe_code` on every
    // target including `tests/`, so `#[global_allocator]` will not compile here
    // (verified: it produces 5 `unsafe_code` errors). Per the corpus-wide rule for
    // exactly this conflict, the bound is proved here in place of measuring it.
    fn build_entries(
        count: usize,
        bytes: &[u8],
        entries_end: usize,
    ) -> Result<Vec<HandoffEntry>, FrameError> {
        let (entries_region, _) =
            bytes
                .split_at_checked(entries_end)
                .ok_or(FrameError::Truncated {
                    need: entries_end,
                    got: bytes.len(),
                })?;
        let (_, mut entries_src) = entries_region
            .split_at_checked(HEADER_BYTES)
            .ok_or(FrameError::BadMagic)?;
        let mut entries = Vec::with_capacity(count);

        for entry in 0..count {
            let (fixed, after_fixed) =
                entries_src
                    .split_at_checked(4)
                    .ok_or(FrameError::Truncated {
                        need: 4,
                        got: entries_src.len(),
                    })?;
            let (addr_len_bytes, fd_index_bytes) =
                fixed.split_at_checked(2).ok_or(FrameError::Truncated {
                    need: 2,
                    got: fixed.len(),
                })?;
            let addr_len = u16::from_le_bytes(addr_len_bytes.try_into().map_err(|_| {
                FrameError::Truncated {
                    need: 2,
                    got: addr_len_bytes.len(),
                }
            })?);
            let fd_index = u16::from_le_bytes(fd_index_bytes.try_into().map_err(|_| {
                FrameError::Truncated {
                    need: 2,
                    got: fd_index_bytes.len(),
                }
            })?);
            let (addr_bytes, next_entries_src) = after_fixed
                .split_at_checked(usize::from(addr_len))
                .ok_or(FrameError::Truncated {
                    need: usize::from(addr_len),
                    got: after_fixed.len(),
                })?;
            let addr = core::str::from_utf8(addr_bytes)
                .map_err(|_| FrameError::NotUtf8 { entry })?
                .to_owned();
            entries.push(HandoffEntry { addr, fd_index });
            entries_src = next_entries_src;
        }

        Ok(entries)
    }

    /// The exact encoded length, for a caller sizing a read.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_BYTES + CHECKSUM_BYTES + self.entries.iter().map(|e| 4 + e.addr.len()).sum::<usize>()
    }

    /// The **first** entry whose address matches `addr`, compared byte for byte against
    /// the canonical rendering.
    #[must_use]
    pub fn find(&self, addr: &str) -> Option<&HandoffEntry> {
        self.entries.iter().find(|e| e.addr == addr)
    }

    /// Every entry whose address matches `addr`, in frame order.
    pub fn find_all(&self, addr: &str) -> impl Iterator<Item = &HandoffEntry> {
        self.entries.iter().filter(move |e| e.addr == addr)
    }

    // Invariant 3 (decode(encode(x)) == x for every constructible x) requires that
    // `new` and `encode` reject exactly what `decode` would reject. `decode`'s
    // `validate_entries` checks that every `fd_index` is below `count` and that no
    // two entries share one (steps 11 and 12 of the issue's decode algorithm); this
    // function mirrors that check with the same `[bool; MAX_FDS]` fixed-size
    // tracker `validate_entries` uses, so a caller cannot build a `HandoffFrame`
    // whose own `encode` output is later refused by `decode`. The array is sized
    // by the constant `MAX_FDS`, never by `entries.len()`, and is only indexed
    // after the length check above has already bounded `entries.len()` to at most
    // `MAX_FDS`, so every index into it is in range.
    fn validate(entries: &[HandoffEntry]) -> Result<(), FrameError> {
        if entries.len() > MAX_FDS {
            return Err(FrameError::TooManyDescriptors {
                count: entries.len(),
                max: MAX_FDS,
            });
        }
        let mut seen = [false; MAX_FDS];
        for (entry, e) in entries.iter().enumerate() {
            if e.addr.is_empty() || e.addr.len() > MAX_ADDR_BYTES {
                return Err(FrameError::BadAddressLength {
                    entry,
                    len: e.addr.len(),
                    max: MAX_ADDR_BYTES,
                });
            }
            let fd_index_usize = usize::from(e.fd_index);
            if fd_index_usize >= entries.len() {
                return Err(FrameError::FdIndexOutOfRange {
                    entry,
                    index: e.fd_index,
                    count: entries.len(),
                });
            }
            let flag = seen
                .get_mut(fd_index_usize)
                .ok_or(FrameError::FdIndexOutOfRange {
                    entry,
                    index: e.fd_index,
                    count: entries.len(),
                })?;
            if *flag {
                return Err(FrameError::DuplicateFdIndex { index: e.fd_index });
            }
            *flag = true;
        }
        Ok(())
    }
}

fn split_u16_le(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let (chunk, rest) = bytes.split_at_checked(2)?;
    let b0 = *chunk.first()?;
    let b1 = *chunk.get(1)?;
    Some((u16::from_le_bytes([b0, b1]), rest))
}

/// The successor's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ack {
    /// Every descriptor was received and registered.
    Accepted,
    /// The handoff was refused; the predecessor keeps its sockets.
    Refused,
}

impl Ack {
    /// The single byte on the wire: `0x06` for accepted, `0x15` for refused.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Accepted => 0x06,
            Self::Refused => 0x15,
        }
    }

    /// Parses the byte.
    ///
    /// # Errors
    /// [`AckError::Unknown`] naming the byte.
    pub fn from_byte(b: u8) -> Result<Self, AckError> {
        match b {
            0x06 => Ok(Self::Accepted),
            0x15 => Ok(Self::Refused),
            other => Err(AckError::Unknown { byte: other }),
        }
    }
}

/// The acknowledgement could not be read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AckError {
    /// A byte that is neither `0x06` nor `0x15`.
    #[error("acknowledgement byte 0x{byte:02x} is not 0x06 (accepted) or 0x15 (refused)")]
    Unknown {
        /// The byte that was read.
        byte: u8,
    },
    /// The peer closed without answering, which is treated as a refusal.
    #[error("the successor closed the upgrade socket without acknowledging")]
    Closed,
}

/// A frame could not be encoded or decoded.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer bytes than the frame declares.
    #[error("handoff frame is truncated: need at least {need} bytes, got {got}")]
    Truncated {
        /// The minimum number of bytes needed for the field or frame.
        need: usize,
        /// The number of bytes actually present.
        got: usize,
    },
    /// The first four bytes are not the magic.
    #[error("handoff frame does not start with the expected magic")]
    BadMagic,
    /// A version this build does not understand.
    #[error(
        "handoff frame version {found} is not supported by this build (expected {FRAME_VERSION})"
    )]
    UnsupportedVersion {
        /// The version found in the frame.
        found: u16,
    },
    /// A reserved field is not zero.
    #[error("a reserved field in the handoff frame is not zero")]
    ReservedNotZero,
    /// More descriptors than the format allows.
    #[error("handoff frame declares {count} descriptors, above the limit of {max}")]
    TooManyDescriptors {
        /// The number of descriptors declared in the frame.
        count: usize,
        /// The maximum number of descriptors the format allows.
        max: usize,
    },
    /// An address length of zero or above the cap.
    #[error("handoff entry {entry} declares an address of {len} bytes, which must be 1 to {max}")]
    BadAddressLength {
        /// The zero-based entry index.
        entry: usize,
        /// The declared address length.
        len: usize,
        /// The maximum address length.
        max: usize,
    },
    /// An address that is not UTF-8.
    #[error("handoff entry {entry} has an address that is not valid UTF-8")]
    NotUtf8 {
        /// The zero-based entry index.
        entry: usize,
    },
    /// A descriptor index at or above the count.
    #[error(
        "handoff entry {entry} names descriptor index {index}, which is not below the count {count}"
    )]
    FdIndexOutOfRange {
        /// The zero-based entry index.
        entry: usize,
        /// The descriptor index found in the entry.
        index: u16,
        /// The number of entries in the frame.
        count: usize,
    },
    /// Two entries name the same descriptor.
    #[error("descriptor index {index} is named by more than one handoff entry")]
    DuplicateFdIndex {
        /// The descriptor index that appears more than once.
        index: u16,
    },
    /// The checksum does not match.
    #[error("handoff frame checksum does not match its contents")]
    BadChecksum,
    /// Trailing bytes after the checksum.
    #[error("handoff frame has {extra} trailing bytes after the checksum")]
    TrailingBytes {
        /// The number of bytes after the checksum.
        extra: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::{Ack, AckError};

    #[test]
    fn ack_round_trips() {
        assert_eq!(Ack::Accepted.to_byte(), 0x06);
        assert_eq!(Ack::from_byte(0x06).expect("accepted"), Ack::Accepted);
        assert_eq!(Ack::Refused.to_byte(), 0x15);
        assert_eq!(Ack::from_byte(0x15).expect("refused"), Ack::Refused);
        assert_eq!(Ack::from_byte(0x00), Err(AckError::Unknown { byte: 0 }));
        assert_eq!(
            AckError::Unknown { byte: 0 }.to_string(),
            "acknowledgement byte 0x00 is not 0x06 (accepted) or 0x15 (refused)"
        );
    }
}
