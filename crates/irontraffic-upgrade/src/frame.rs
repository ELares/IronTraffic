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
    /// [`FrameError::BadAddressLength`] for an empty or oversized address.
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

    fn validate(entries: &[HandoffEntry]) -> Result<(), FrameError> {
        if entries.len() > MAX_FDS {
            return Err(FrameError::TooManyDescriptors {
                count: entries.len(),
                max: MAX_FDS,
            });
        }
        for (entry, e) in entries.iter().enumerate() {
            if e.addr.is_empty() || e.addr.len() > MAX_ADDR_BYTES {
                return Err(FrameError::BadAddressLength {
                    entry,
                    len: e.addr.len(),
                    max: MAX_ADDR_BYTES,
                });
            }
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
