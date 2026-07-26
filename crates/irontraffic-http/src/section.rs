// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`FieldSection`], the flat, allocation-lean header container used by
//! every protocol path, and [`FieldSectionBuilder`], which builds one.
//!
//! **Correction 1 (Envoy CVE-2026-26308).** Envoy's RBAC filter combined
//! multiple values of the same header name into one comma-separated string
//! before matching, so a request carrying the same header twice bypassed
//! policy. Fixed in 1.37.1 / 1.36.5 / 1.35.8 / 1.34.13. The root cause is not
//! the filter; it is that a comma-combining accessor existed at all. Comma
//! joining is only correct for RFC 9110 Section 5.3 `#list` fields and is
//! never correct for policy matching. [`FieldSection`] therefore offers
//! [`FieldSection::get_all`], an iterator over every value for a name, for
//! the small number of callers that genuinely need the whole list, and
//! [`FieldSection::get_unique`], which every policy consumer (authorization,
//! RBAC, JWT, routing predicates, rate-limit keys) must use and which forces
//! them to handle the duplicate case explicitly. There is no third accessor,
//! and in particular no accessor that joins values together: that is
//! precisely the shape of the bug.
//!
//! **Correction 2 (Envoy header storage).** Envoy stores headers as a map of
//! reference-counted strings with per-header heap allocation. Storage here is
//! one contiguous byte arena plus a flat index of fixed-size slots
//! ([`FieldSlot`]). Looking up `authorization` among 20 slots is a handful of
//! already-resident cache lines and at most 20 one-byte comparisons; a hashed
//! lookup table pays a hash of the key plus a probe into a cold bucket array.
//! The flat array also makes the "no joining" API natural rather than awkward.
//!
//! **Why the arena is caller supplied.** A `Bytes` slice keeps its entire
//! backing allocation alive, so a 20-byte header value sliced out of a 32 KiB
//! read chunk pins 32 KiB; at 100,000 connections that is gigabytes instead
//! of megabytes (slice retention amplification). The fix is that field names
//! and values are compacted into one exactly sized buffer at the moment the
//! head completes, and the read chunk goes back to the per-worker pool. This
//! crate does not own a pool, so [`FieldSection`] is built into a caller
//! supplied [`bytes::BytesMut`] and performs no heap allocation for the arena
//! itself (the `SmallVec` index may spill to the heap past 32 fields, which
//! is bounded and documented).

use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;

use crate::error::RejectReason;
use crate::field::{self, UnderscorePolicy};
use crate::known::{self, KnownHeader};
use crate::limits::ClampedLimits;
use crate::scalar::WireVersion;

/// One field line's index entry. Offsets are relative to the start of the
/// `FieldSection` arena, not to any read buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FieldSlot {
    /// Offset of the first name byte in the arena.
    pub name_off: u32,
    /// Offset of the first value byte in the arena.
    pub value_off: u32,
    /// Name length in bytes. Never 0.
    pub name_len: u16,
    /// Value length in bytes. May be 0.
    pub value_len: u16,
    /// Classification of the name, or `Unknown`.
    pub known: KnownHeader,
    /// Per-field flags.
    pub flags: FieldFlags,
}

const _: () = assert!(core::mem::size_of::<FieldSlot>() == 16);
// Every `KnownHeader` variant must fit a bit in a `u64` mask; see
// `known_mask_bit` below, the one place that invariant is load bearing.
const _: () = assert!(known::KNOWN_HEADER_COUNT <= 63);

/// Per-field flags. One byte.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct FieldFlags(u8);

impl FieldFlags {
    /// The field was named by an inbound `Connection` header and is therefore hop-by-hop.
    pub const CONNECTION_NAMED: FieldFlags = FieldFlags(0b0000_0001);
    /// The field arrived in a trailer section rather than the header section.
    pub const FROM_TRAILER: FieldFlags = FieldFlags(0b0000_0010);
    /// The field was synthesized by IronTraffic rather than received.
    pub const SYNTHESIZED: FieldFlags = FieldFlags(0b0000_0100);
    /// The wire name contained `_`, which `UnderscorePolicy::MapToHyphen` rewrote to `-`.
    /// Two lines whose canonical names are equal but whose `UNDERSCORE_MAPPED` bits differ
    /// may not coexist in one section; see the underscore collision check on
    /// [`FieldSectionBuilder::push_normalized`].
    pub const UNDERSCORE_MAPPED: FieldFlags = FieldFlags(0b0000_1000);

    /// True when every bit in `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: FieldFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Sets every bit in `other`.
    pub fn insert(&mut self, other: FieldFlags) {
        self.0 |= other.0;
    }
}

/// A field appeared more than once where the caller required at most one.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DuplicateField {
    /// Length of the name that was duplicated, for diagnostics.
    pub name_len: u16,
}

/// A validated header section: end-to-end fields only, in arrival order.
///
/// Storage is one contiguous arena of name and value bytes plus a flat index.
/// There is deliberately no map, no interning table and no comma-joining
/// accessor.
#[derive(Clone, Debug)]
pub struct FieldSection {
    arena: Bytes,
    slots: SmallVec<[FieldSlot; 32]>,
    known_mask: u64,
}

/// The `known_mask` bit for `k`.
///
/// The cast is exact, not attacker controlled: `KnownHeader` is `#[repr(u8)]`
/// and `known::KNOWN_HEADER_COUNT` is asserted at compile time (above) to be
/// at most 63, so the discriminant always fits this shift. An attacker's
/// header name selects WHICH bounded variant `classify` returns; it can never
/// select a variant outside `0..KNOWN_HEADER_COUNT`.
const fn known_mask_bit(k: KnownHeader) -> u64 {
    1u64 << (k as u8) // it-allow: unchecked-cast reason: repr(u8) enum tag with <= 63 variants (compile-time asserted above), exact by construction, not attacker-controlled width
}

/// Reads the `len` bytes at `base + off` out of `arena`, or `None` if that
/// range is not entirely within `arena`. Shared by the builder (`base` is the
/// offset the current section started at within the live `BytesMut`) and by
/// `FieldSection` itself (`base` is always 0, because `finish` splits the
/// section's own bytes out of the builder's buffer so slot offsets become
/// absolute).
fn slot_bytes(arena: &[u8], base: usize, off: u32, len: u16) -> Option<&[u8]> {
    let start = base.checked_add(off as usize)?;
    let end = start.checked_add(len as usize)?;
    arena.get(start..end)
}

impl FieldSection {
    fn name_bytes(&self, slot: FieldSlot) -> Option<&[u8]> {
        slot_bytes(&self.arena, 0, slot.name_off, slot.name_len)
    }

    fn value_bytes(&self, slot: FieldSlot) -> Option<&[u8]> {
        slot_bytes(&self.arena, 0, slot.value_off, slot.value_len)
    }

    /// Number of field lines.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// True when there are no field lines.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Every value for `name`, in arrival order.
    ///
    /// Use this only for genuine RFC 9110 Section 5.3 `#list` fields. For any
    /// policy decision use [`FieldSection::get_unique`].
    ///
    /// When `name` classifies to a known header that is absent, this returns
    /// in O(1): one `AND` against `known_mask` proves there is nothing to
    /// find, so the underlying slots are never scanned at all.
    pub fn get_all<'s>(&'s self, name: &'s [u8]) -> impl Iterator<Item = &'s [u8]> + 's {
        let k = known::classify(name);
        let scan_len = if k == KnownHeader::Unknown {
            self.slots.len()
        } else if self.known_mask & known_mask_bit(k) == 0 {
            0
        } else {
            self.slots.len()
        };
        self.slots
            .iter()
            .take(scan_len)
            .filter(move |slot| {
                if k == KnownHeader::Unknown {
                    slot.name_len as usize == name.len() && self.name_bytes(**slot) == Some(name)
                } else {
                    slot.known == k
                }
            })
            .filter_map(move |slot| self.value_bytes(*slot))
    }

    /// Every value for a pre-classified known header, in arrival order.
    ///
    /// Absent this returns in O(1), exactly as [`FieldSection::get_all`].
    pub fn get_all_known(&self, k: KnownHeader) -> impl Iterator<Item = &[u8]> + '_ {
        let scan_len = if self.known_mask & known_mask_bit(k) == 0 {
            0
        } else {
            self.slots.len()
        };
        self.slots
            .iter()
            .take(scan_len)
            .filter(move |slot| slot.known == k)
            .filter_map(move |slot| self.value_bytes(*slot))
    }

    /// The single value for `name`.
    ///
    /// Returns `Ok(None)` when absent, `Ok(Some(v))` when present exactly
    /// once, and `Err(DuplicateField)` when present two or more times. Every
    /// authorization, routing, rate-limit and JWT consumer MUST use this and
    /// MUST handle `Err`.
    ///
    /// # Errors
    /// `DuplicateField` when the field appears more than once.
    pub fn get_unique<'s>(&'s self, name: &'s [u8]) -> Result<Option<&'s [u8]>, DuplicateField> {
        let mut it = self.get_all(name);
        match (it.next(), it.next()) {
            (None, _) => Ok(None),
            (Some(v), None) => Ok(Some(v)),
            (Some(_), Some(_)) => Err(DuplicateField {
                name_len: u16::try_from(name.len()).unwrap_or(u16::MAX),
            }),
        }
    }

    /// As [`FieldSection::get_unique`] for a pre-classified known header.
    ///
    /// # Errors
    /// `DuplicateField` when the field appears more than once.
    pub fn get_unique_known(&self, k: KnownHeader) -> Result<Option<&[u8]>, DuplicateField> {
        let mut it = self.get_all_known(k);
        match (it.next(), it.next()) {
            (None, _) => Ok(None),
            (Some(v), None) => Ok(Some(v)),
            (Some(_), Some(_)) => Err(DuplicateField {
                name_len: u16::try_from(k.as_bytes().len()).unwrap_or(u16::MAX),
            }),
        }
    }

    /// True when at least one field has this classification. One AND against a bitmask.
    #[must_use]
    pub fn contains_known(&self, k: KnownHeader) -> bool {
        self.known_mask & known_mask_bit(k) != 0
    }

    /// Number of field lines with this classification.
    #[must_use]
    pub fn count_known(&self, k: KnownHeader) -> usize {
        if self.known_mask & known_mask_bit(k) == 0 {
            return 0;
        }
        self.slots.iter().filter(|slot| slot.known == k).count()
    }

    /// Removes every field named `name` (canonical form) and returns how many were removed.
    pub fn remove_name(&mut self, name: &[u8]) -> u32 {
        self.retain(|n, _, _| n != name)
    }

    /// Removes every field with this classification and returns how many were removed.
    ///
    /// `remove_known(KnownHeader::Unknown)` removes nothing and returns 0: a
    /// generic "remove everything unclassified" is not this method's
    /// contract, and treating `Unknown` as an ordinary classification here
    /// would make it one by accident.
    pub fn remove_known(&mut self, k: KnownHeader) -> u32 {
        if k == KnownHeader::Unknown {
            return 0;
        }
        self.retain(|n, _, _| known::classify(n) != k)
    }

    /// Removes every field for which `keep` returns false and returns how many were
    /// removed. Index only: the arena is never compacted, so every surviving offset
    /// stays valid. `known_mask` is recomputed from the survivors.
    pub fn retain<F>(&mut self, mut keep: F) -> u32
    where
        F: FnMut(&[u8], &[u8], FieldFlags) -> bool,
    {
        // Cloning a `Bytes` is a refcount bump, not a copy. It is what lets the closure read
        // name and value bytes while `self.slots` is borrowed mutably; `self.slots.retain(|s|
        // keep(self.name_of(s), ...))` does not compile, because it borrows `self` twice.
        let arena = self.arena.clone();
        let before = self.slots.len();
        self.slots.retain(|s: &mut FieldSlot| {
            // `get(..)` rather than `arena[a..b]`: the crate denies `clippy::indexing_slicing`.
            // `checked_add` because the crate denies `clippy::arithmetic_side_effects`.
            // A slot whose bytes cannot be read is DROPPED, never kept. Both ranges are in
            // bounds because `push` wrote them, so this is unreachable today; it is written
            // this way because `retain` is the primitive under every strip pass, and the
            // failure direction has to be "the field we could not read does not survive".
            // Substituting an empty name here would hand a predicate like
            // `|n, _, _| !STRIP_SET.contains(n)` an empty slice, which answers true, which
            // forwards a field whose name we could not read; that is the exact shape of bug
            // this function must not reintroduce.
            let (Some(n), Some(v)) = (
                slot_bytes(&arena, 0, s.name_off, s.name_len),
                slot_bytes(&arena, 0, s.value_off, s.value_len),
            ) else {
                return false;
            };
            keep(n, v, s.flags)
        });
        self.known_mask = 0;
        for s in &self.slots {
            if s.known != KnownHeader::Unknown {
                self.known_mask |= known_mask_bit(s.known);
            }
        }
        u32::try_from(before.saturating_sub(self.slots.len())).unwrap_or(u32::MAX)
    }

    /// Iterates `(name, value, flags)` in arrival order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8], FieldFlags)> + '_ {
        self.slots.iter().filter_map(move |slot| {
            let n = self.name_bytes(*slot)?;
            let v = self.value_bytes(*slot)?;
            Some((n, v, slot.flags))
        })
    }

    /// The raw index, for the strip and serialize paths.
    #[must_use]
    pub fn slots(&self) -> &[FieldSlot] {
        &self.slots
    }

    /// The name bytes of the field at `index`, or `None` when out of range.
    #[must_use]
    pub fn name_at(&self, index: usize) -> Option<&[u8]> {
        let slot = self.slots.get(index)?;
        self.name_bytes(*slot)
    }

    /// The value bytes of the field at `index`, or `None` when out of range.
    #[must_use]
    pub fn value_at(&self, index: usize) -> Option<&[u8]> {
        let slot = self.slots.get(index)?;
        self.value_bytes(*slot)
    }

    /// Sets flags on the slot at `index`. No-op when `index` is out of range.
    pub fn set_flags(&mut self, index: usize, flags: FieldFlags) {
        if let Some(slot) = self.slots.get_mut(index) {
            slot.flags = flags;
        }
    }
}

/// Builds a [`FieldSection`] by writing directly into a caller-supplied
/// [`BytesMut`] arena.
///
/// The absence of a lifetime parameter is deliberate and load bearing. A
/// `FieldSectionBuilder<'a>` holding `&'a mut BytesMut` could not be stored
/// inside a longer-lived struct that is also handed the same buffer on each
/// call, which a trailer section spanning several decode calls needs. Taking
/// `arena` as a parameter on every call instead removes that problem and
/// removes a lifetime an implementer would otherwise have to reason about.
#[derive(Clone, Debug)]
pub struct FieldSectionBuilder {
    base: usize,
    slots: SmallVec<[FieldSlot; 32]>,
    known_mask: u64,
    limits: ClampedLimits,
    list_bytes: u64,
    /// Set once any push has mapped `_` to `-`. Keeps the underscore collision check off
    /// the path of every request that contains no underscore header.
    any_underscore_mapped: bool,
}

impl FieldSectionBuilder {
    /// Starts a section that will write its bytes into `arena` from its current end.
    ///
    /// `arena` is borrowed only for the duration of this call, to read its length. Every
    /// later call takes it again, so the builder can be stored in a struct that outlives
    /// any one borrow of the buffer.
    #[must_use]
    pub fn new(arena: &BytesMut, limits: &ClampedLimits) -> FieldSectionBuilder {
        FieldSectionBuilder {
            base: arena.len(),
            slots: SmallVec::new(),
            known_mask: 0,
            limits: *limits,
            list_bytes: 0,
            any_underscore_mapped: false,
        }
    }

    /// Steps 1 through 4 shared by every push entry point: the field-count
    /// cap, the u16-fit guard on both lengths, the per-line byte cap, and the
    /// running RFC 7541 Section 4.1 header-list-size charge. Runs before any
    /// byte is written and before `field::validate_name` / `validate_value`,
    /// so a field this rejects never touches the arena.
    fn admit(&mut self, name_len: usize, value_len: usize) -> Result<(), RejectReason> {
        let count = u32::try_from(self.slots.len()).unwrap_or(u32::MAX);
        if count >= self.limits.max_field_count {
            return Err(RejectReason::FieldCountExceeded);
        }
        // `FieldSlot::name_len` / `value_len` are 16 bits wide: a length that does not
        // fit would silently truncate under a bare narrowing cast, serving a short
        // prefix of an attacker's value as if it were the whole thing. Checked with
        // `try_from` before any cast is ever performed.
        if u16::try_from(name_len).is_err() || u16::try_from(value_len).is_err() {
            return Err(RejectReason::FieldLineTooLong);
        }
        if name_len.saturating_add(value_len) > self.limits.max_field_line_bytes as usize {
            return Err(RejectReason::FieldLineTooLong);
        }
        let name_u64 = u64::try_from(name_len).unwrap_or(u64::MAX);
        let value_u64 = u64::try_from(value_len).unwrap_or(u64::MAX);
        let next = self
            .list_bytes
            .saturating_add(name_u64)
            .saturating_add(value_u64)
            .saturating_add(32);
        if next > u64::from(self.limits.max_header_list_bytes) {
            return Err(RejectReason::HeaderListTooLarge);
        }
        self.list_bytes = next;
        Ok(())
    }

    /// True when pushing a name with underscore-mapping outcome `mapped`
    /// would collide with an already-pushed field whose canonical name is
    /// equal but whose `UNDERSCORE_MAPPED` provenance differs. See the module
    /// documentation on [`FieldFlags::UNDERSCORE_MAPPED`].
    fn underscore_collision(&self, arena: &[u8], canonical: &[u8], mapped: bool) -> bool {
        if mapped {
            self.slots.iter().any(|s| {
                !s.flags.contains(FieldFlags::UNDERSCORE_MAPPED)
                    && slot_bytes(arena, self.base, s.name_off, s.name_len) == Some(canonical)
            })
        } else if self.any_underscore_mapped {
            self.slots.iter().any(|s| {
                s.flags.contains(FieldFlags::UNDERSCORE_MAPPED)
                    && slot_bytes(arena, self.base, s.name_off, s.name_len) == Some(canonical)
            })
        } else {
            false
        }
    }

    /// Appends one field. `name` MUST already be canonical (lowercase, `-` separated) and
    /// `value` MUST already be OWS-trimmed.
    ///
    /// Both are then validated again here, under the strictest profile
    /// (`WireVersion::H2`), in release as well as in debug. A caller that "already
    /// validated" is a proof obligation with no backstop, and this is the single
    /// chokepoint through which every field, received or synthesized, reaches the wire.
    ///
    /// # Errors
    /// `FieldCountExceeded`, `FieldLineTooLong`, `HeaderListTooLarge`, and any error
    /// `field::validate_name` or `field::validate_value` can return:
    /// `FieldNameEmpty`, `FieldNameUppercase`, `FieldNameUnderscore`,
    /// `FieldNameInvalidByte`, `FieldValueInvalidByte`, `FieldValueLeadingWhitespace`,
    /// `FieldValueTrailingWhitespace`. Nothing is written on any error.
    pub fn push(
        &mut self,
        arena: &mut BytesMut,
        name: &[u8],
        value: &[u8],
    ) -> Result<(), RejectReason> {
        self.push_with_flags(arena, name, value, FieldFlags::default())
    }

    /// Appends one field from RAW wire bytes: lowercases the name and applies `policy`
    /// to `_` while writing it into the arena, then validates the written name and the
    /// value. This is the entry point for a parser that has not canonicalized yet, and
    /// it exists so no caller needs a scratch buffer sized to the longest legal name.
    ///
    /// `value` MUST already be OWS-trimmed, exactly as for `push`. Unlike `push`, this
    /// function validates it under the caller's `version`, and on HTTP/1 that profile does
    /// not reject a leading or trailing SP or HTAB, so the trimming is the caller's
    /// obligation and it is what keeps the whole-section invariant true.
    ///
    /// # Errors
    /// `FieldCountExceeded`, `FieldLineTooLong`, `HeaderListTooLarge`,
    /// `FieldNameUnderscore`, `FieldNameEmpty`, `FieldNameUppercase`,
    /// `FieldNameInvalidByte`, `FieldValueInvalidByte`, `FieldValueLeadingWhitespace`,
    /// `FieldValueTrailingWhitespace`. On every error the arena is truncated back to the
    /// length it had when this call started, so a failed push writes nothing.
    ///
    /// Under `UnderscorePolicy::MapToHyphen` it additionally returns `FieldNameUnderscore`
    /// when the canonical name collides with an already-pushed field whose wire name did
    /// not contain `_`, or vice versa. Two wire names that mean different things to a
    /// backend must not become one combinable `#list` here.
    pub fn push_normalized(
        &mut self,
        arena: &mut BytesMut,
        raw_name: &[u8],
        policy: UnderscorePolicy,
        value: &[u8],
        version: WireVersion,
    ) -> Result<(), RejectReason> {
        self.admit(raw_name.len(), value.len())?;

        let name_start = arena.len();
        let mut mapped_underscore = false;
        for &b in raw_name {
            let mut lowered = b.to_ascii_lowercase();
            if lowered == b'_' {
                match policy {
                    UnderscorePolicy::Reject => {
                        arena.truncate(name_start);
                        return Err(RejectReason::FieldNameUnderscore);
                    }
                    UnderscorePolicy::MapToHyphen => {
                        lowered = b'-';
                        mapped_underscore = true;
                    }
                }
            }
            arena.extend_from_slice(core::slice::from_ref(&lowered));
        }

        let name_end = name_start.saturating_add(raw_name.len());
        let Some(written_name) = arena.get(name_start..name_end) else {
            arena.truncate(name_start);
            return Err(RejectReason::FieldNameInvalidByte);
        };
        if let Err(e) = field::validate_name(written_name, version) {
            arena.truncate(name_start);
            return Err(e);
        }
        if let Err(e) = field::validate_value(value, version) {
            arena.truncate(name_start);
            return Err(e);
        }

        // Re-fetch rather than reuse `written_name`: that borrow of `arena`
        // must have already ended for the `arena.truncate` calls above to
        // have type-checked, so this looks the bytes up again instead of
        // trying to carry the earlier borrow across them.
        let Some(canonical) = arena.get(name_start..name_end) else {
            arena.truncate(name_start);
            return Err(RejectReason::FieldNameInvalidByte);
        };
        if self.underscore_collision(arena, canonical, mapped_underscore) {
            arena.truncate(name_start);
            return Err(RejectReason::FieldNameUnderscore);
        }

        let name_off = u32::try_from(name_start.saturating_sub(self.base)).unwrap_or(u32::MAX);
        let name_len = u16::try_from(raw_name.len()).unwrap_or(u16::MAX);
        let known = known::classify(canonical);

        let value_off = u32::try_from(arena.len().saturating_sub(self.base)).unwrap_or(u32::MAX);
        arena.extend_from_slice(value);
        let value_len = u16::try_from(value.len()).unwrap_or(u16::MAX);

        let mut flags = FieldFlags::default();
        if mapped_underscore {
            flags.insert(FieldFlags::UNDERSCORE_MAPPED);
            self.any_underscore_mapped = true;
        }

        self.slots.push(FieldSlot {
            name_off,
            value_off,
            name_len,
            value_len,
            known,
            flags,
        });
        if known != KnownHeader::Unknown {
            self.known_mask |= known_mask_bit(known);
        }
        Ok(())
    }

    /// Appends one field with explicit flags. Same contract as `push`.
    ///
    /// # Errors
    /// As `push`.
    pub fn push_with_flags(
        &mut self,
        arena: &mut BytesMut,
        name: &[u8],
        value: &[u8],
        flags: FieldFlags,
    ) -> Result<(), RejectReason> {
        self.admit(name.len(), value.len())?;
        field::validate_name(name, WireVersion::H2)?;
        field::validate_value(value, WireVersion::H2)?;

        // `admit` above already proved both lengths fit a `u16`; these never
        // hit the fallback in practice.
        let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
        let value_len = u16::try_from(value.len()).unwrap_or(u16::MAX);

        let name_off = u32::try_from(arena.len().saturating_sub(self.base)).unwrap_or(u32::MAX);
        arena.extend_from_slice(name);
        let value_off = u32::try_from(arena.len().saturating_sub(self.base)).unwrap_or(u32::MAX);
        arena.extend_from_slice(value);

        let known = known::classify(name);
        debug_assert_eq!(
            slot_bytes(arena, self.base, name_off, name_len).map(known::classify),
            Some(known),
            "FieldSlot.known must equal classify() of the bytes actually written at its offset"
        );

        self.slots.push(FieldSlot {
            name_off,
            value_off,
            name_len,
            value_len,
            known,
            flags,
        });
        if known != KnownHeader::Unknown {
            self.known_mask |= known_mask_bit(known);
        }
        Ok(())
    }

    /// Running uncompressed header-list size, in the RFC 7541 Section 4.1 sense
    /// (`name.len() + value.len() + 32` per field).
    #[must_use]
    pub fn list_bytes(&self) -> u64 {
        self.list_bytes
    }

    /// Number of fields pushed so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// True when no field has been pushed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Finishes the section, splitting the written region out of `arena`.
    #[must_use]
    pub fn finish(self, arena: &mut BytesMut) -> FieldSection {
        let arena = arena.split_off(self.base).freeze();
        FieldSection {
            arena,
            slots: self.slots,
            known_mask: self.known_mask,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    #[test]
    fn slot_is_16_bytes() {
        assert_eq!(core::mem::size_of::<FieldSlot>(), 16);
    }

    #[test]
    fn build_and_read_back() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder.push(&mut arena, b"host", b"a").unwrap();
        builder.push(&mut arena, b"accept", b"*/*").unwrap();
        builder.push(&mut arena, b"x-custom", b"v").unwrap();
        let section = builder.finish(&mut arena);

        assert_eq!(section.len(), 3);
        assert_eq!(section.get_unique(b"host"), Ok(Some(&b"a"[..])));
        assert_eq!(section.get_unique(b"x-custom"), Ok(Some(&b"v"[..])));
        assert!(section.contains_known(KnownHeader::Host));
        assert!(!section.contains_known(KnownHeader::Cookie));
    }

    #[test]
    fn get_unique_rejects_duplicates() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder.push(&mut arena, b"cookie", b"a").unwrap();
        builder.push(&mut arena, b"cookie", b"a").unwrap();
        let section = builder.finish(&mut arena);

        assert_eq!(
            section.get_unique(b"cookie"),
            Err(DuplicateField { name_len: 6 })
        );
        let all: Vec<&[u8]> = section.get_all(b"cookie").collect();
        assert_eq!(all, vec![&b"a"[..], &b"a"[..]]);
    }

    #[test]
    fn empty_value_is_not_absent() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder.push(&mut arena, b"x-e", b"").unwrap();
        let section = builder.finish(&mut arena);

        assert_eq!(section.get_unique(b"x-e"), Ok(Some(&b""[..])));
        assert_ne!(section.get_unique(b"x-e"), Ok(None));
    }

    #[test]
    fn limits_are_enforced_before_write() {
        // max_field_count: the boundary itself (the 2nd push, at the cap) succeeds;
        // one past it does not, and the arena is unchanged by the rejected push.
        let limits = Limits {
            max_field_count: 2,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder.push(&mut arena, b"a", b"1").unwrap();
        builder.push(&mut arena, b"b", b"2").unwrap();
        let before = arena.len();
        assert_eq!(
            builder.push(&mut arena, b"c", b"3"),
            Err(RejectReason::FieldCountExceeded)
        );
        assert_eq!(arena.len(), before);

        // max_field_line_bytes: exactly at the cap (name + value == 8) succeeds;
        // one byte more fails. Both sides of the boundary are asserted here, not
        // only the over side: a mutation of `>` to `>=` in `admit` would silently
        // reject the exact-boundary field and survive a suite that checked only
        // the excess case.
        let limits2 = Limits {
            max_field_line_bytes: 8,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut arena2 = BytesMut::new();
        let mut builder2 = FieldSectionBuilder::new(&arena2, &limits2);
        builder2.push(&mut arena2, b"ab", b"123456").unwrap();
        assert_eq!(builder2.len(), 1);
        let before2 = arena2.len();
        assert_eq!(
            builder2.push(&mut arena2, b"toolongname", b"v"),
            Err(RejectReason::FieldLineTooLong)
        );
        assert_eq!(arena2.len(), before2);

        // max_header_list_bytes: a field whose name + value + 32 lands EXACTLY on
        // the cap (1 + 7 + 32 == 40) succeeds; any further field, however small,
        // then exceeds it and is refused. Asserting the exact-boundary accept
        // catches a `>` to `>=` mutation in `admit`'s list-bytes check the same
        // way the field-line-bytes case above does.
        let limits3 = Limits {
            max_header_list_bytes: 40,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut arena3 = BytesMut::new();
        let mut builder3 = FieldSectionBuilder::new(&arena3, &limits3);
        builder3.push(&mut arena3, b"a", b"1234567").unwrap();
        assert_eq!(builder3.list_bytes(), 40);
        let before3 = arena3.len();
        assert_eq!(
            builder3.push(&mut arena3, b"b", b"2"),
            Err(RejectReason::HeaderListTooLarge)
        );
        assert_eq!(arena3.len(), before3);
    }

    #[test]
    fn list_bytes_counts_overhead() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder.push(&mut arena, b"a", b"b").unwrap();
        assert_eq!(builder.list_bytes(), 34);
    }

    #[test]
    fn spill_past_32_fields() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        for i in 0..40u32 {
            let name = format!("x-bench-{i:02}");
            builder.push(&mut arena, name.as_bytes(), b"v").unwrap();
        }
        let section = builder.finish(&mut arena);
        assert_eq!(section.len(), 40);
        assert_eq!(section.get_unique(b"x-bench-39"), Ok(Some(&b"v"[..])));
    }

    #[test]
    fn remove_name_is_index_only() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder.push(&mut arena, b"via", b"1.1 a").unwrap();
        builder.push(&mut arena, b"via", b"1.1 b").unwrap();
        builder.push(&mut arena, b"via", b"1.1 c").unwrap();
        builder.push(&mut arena, b"host", b"example").unwrap();
        let mut section = builder.finish(&mut arena);

        let arena_len_before = section.arena.len();
        let removed = section.remove_name(b"via");
        assert_eq!(removed, 3);
        assert_eq!(section.get_all(b"via").count(), 0);
        assert!(!section.contains_known(KnownHeader::Via));
        assert_eq!(section.get_unique(b"host"), Ok(Some(&b"example"[..])));
        assert_eq!(section.arena.len(), arena_len_before);
    }

    #[test]
    fn remove_known_unknown_removes_nothing() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder.push(&mut arena, b"x-a", b"1").unwrap();
        builder.push(&mut arena, b"x-b", b"2").unwrap();
        let mut section = builder.finish(&mut arena);

        assert_eq!(section.remove_known(KnownHeader::Unknown), 0);
        assert_eq!(section.len(), 2);
    }

    #[test]
    fn two_sections_share_one_arena() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();

        let mut builder_a = FieldSectionBuilder::new(&arena, &limits);
        builder_a.push(&mut arena, b"host", b"a").unwrap();
        let section_a = builder_a.finish(&mut arena);

        let mut builder_b = FieldSectionBuilder::new(&arena, &limits);
        builder_b.push(&mut arena, b"host", b"bb").unwrap();
        let section_b = builder_b.finish(&mut arena);

        assert_eq!(section_a.get_unique(b"host"), Ok(Some(&b"a"[..])));
        assert_eq!(section_b.get_unique(b"host"), Ok(Some(&b"bb"[..])));
    }

    proptest::proptest! {
        #[test]
        fn prop_get_unique_agrees_with_get_all(
            pairs in proptest::collection::vec(
                (
                    proptest::sample::select(&["x-a", "x-b", "x-c", "x-d"][..]),
                    proptest::sample::select(&["v1", "v2", "v3", "v4"][..]),
                ),
                2..=20,
            )
        ) {
            let limits = Limits::DEFAULT.clamped();
            let mut arena = BytesMut::new();
            let mut builder = FieldSectionBuilder::new(&arena, &limits);
            for (name, value) in &pairs {
                builder
                    .push(&mut arena, name.as_bytes(), value.as_bytes())
                    .expect("a 4x4 fixed alphabet of short names/values always fits DEFAULT limits");
            }
            let section = builder.finish(&mut arena);

            for name in ["x-a", "x-b", "x-c", "x-d"] {
                let count = section.get_all(name.as_bytes()).count();
                let unique = section.get_unique(name.as_bytes());
                match count {
                    0 => assert_eq!(unique, Ok(None)),
                    1 => {
                        let first = section.get_all(name.as_bytes()).next();
                        assert_eq!(unique, Ok(first));
                    }
                    _ => assert!(unique.is_err()),
                }
            }
        }
    }

    #[test]
    fn push_normalized_lowercases_into_the_arena() {
        let limits = Limits::DEFAULT.clamped();

        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder
            .push_normalized(
                &mut arena,
                b"X-Forwarded-For",
                UnderscorePolicy::Reject,
                b"1.2.3.4",
                WireVersion::Http11,
            )
            .unwrap();

        let long_upper: Vec<u8> = vec![b'A'; 200];
        let long_lower: Vec<u8> = vec![b'a'; 200];
        builder
            .push_normalized(
                &mut arena,
                &long_upper,
                UnderscorePolicy::Reject,
                b"v",
                WireVersion::Http11,
            )
            .unwrap();

        let before_len = arena.len();
        assert_eq!(
            builder.push_normalized(
                &mut arena,
                b"X_Forwarded_For",
                UnderscorePolicy::Reject,
                b"5.6.7.8",
                WireVersion::Http11,
            ),
            Err(RejectReason::FieldNameUnderscore)
        );
        assert_eq!(arena.len(), before_len);

        let section = builder.finish(&mut arena);
        assert_eq!(
            section.get_unique(b"x-forwarded-for"),
            Ok(Some(&b"1.2.3.4"[..]))
        );
        assert!(section.contains_known(KnownHeader::XForwardedFor));
        assert_eq!(section.name_at(1), Some(&long_lower[..]));

        // Repeated in isolation, under `MapToHyphen`, on a fresh builder so
        // this is testing only the mapping, not the collision rule (which
        // has its own test, `underscore_collision_is_refused_both_orders`).
        let mut arena2 = BytesMut::new();
        let mut builder2 = FieldSectionBuilder::new(&arena2, &limits);
        builder2
            .push_normalized(
                &mut arena2,
                b"X_Forwarded_For",
                UnderscorePolicy::MapToHyphen,
                b"5.6.7.8",
                WireVersion::Http11,
            )
            .unwrap();
        let section2 = builder2.finish(&mut arena2);
        assert_eq!(
            section2.get_unique(b"x-forwarded-for"),
            Ok(Some(&b"5.6.7.8"[..]))
        );
    }

    #[test]
    fn push_validates_in_release() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        let before = arena.len();

        assert_eq!(
            builder.push(&mut arena, b"x-a", b"v\r\nx: y"),
            Err(RejectReason::FieldValueInvalidByte)
        );
        assert_eq!(arena.len(), before);

        assert_eq!(
            builder.push(&mut arena, b"X-A", b"v"),
            Err(RejectReason::FieldNameUppercase)
        );
        assert_eq!(arena.len(), before);

        assert_eq!(
            builder.push(&mut arena, b"", b"v"),
            Err(RejectReason::FieldNameEmpty)
        );
        assert_eq!(arena.len(), before);

        assert_eq!(
            builder.push(&mut arena, b"x-a", b" v"),
            Err(RejectReason::FieldValueLeadingWhitespace)
        );
        assert_eq!(arena.len(), before);
    }

    #[test]
    fn push_rejects_lengths_that_do_not_fit_u16() {
        let limits = Limits {
            max_field_line_bytes: 65_535,
            max_header_list_bytes: 1_048_576,
            ..Limits::DEFAULT
        }
        .clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        let big_value = vec![b'v'; 70_000];
        assert_eq!(
            builder.push(&mut arena, b"x-big", &big_value),
            Err(RejectReason::FieldLineTooLong)
        );
        assert_eq!(builder.len(), 0);
    }

    #[test]
    fn underscore_collision_is_refused_both_orders() {
        let limits = Limits::DEFAULT.clamped();

        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder
            .push_normalized(
                &mut arena,
                b"X-Forwarded-For",
                UnderscorePolicy::MapToHyphen,
                b"10.9.9.9",
                WireVersion::Http11,
            )
            .unwrap();
        let after_first = arena.len();
        assert_eq!(
            builder.push_normalized(
                &mut arena,
                b"X_Forwarded_For",
                UnderscorePolicy::MapToHyphen,
                b"1.2.3.4",
                WireVersion::Http11,
            ),
            Err(RejectReason::FieldNameUnderscore)
        );
        assert_eq!(arena.len(), after_first);
        assert_eq!(builder.len(), 1);

        let mut arena2 = BytesMut::new();
        let mut builder2 = FieldSectionBuilder::new(&arena2, &limits);
        builder2
            .push_normalized(
                &mut arena2,
                b"X_Forwarded_For",
                UnderscorePolicy::MapToHyphen,
                b"1.2.3.4",
                WireVersion::Http11,
            )
            .unwrap();
        let after_first2 = arena2.len();
        assert_eq!(
            builder2.push_normalized(
                &mut arena2,
                b"X-Forwarded-For",
                UnderscorePolicy::MapToHyphen,
                b"10.9.9.9",
                WireVersion::Http11,
            ),
            Err(RejectReason::FieldNameUnderscore)
        );
        assert_eq!(arena2.len(), after_first2);
        assert_eq!(builder2.len(), 1);

        let mut arena3 = BytesMut::new();
        let mut builder3 = FieldSectionBuilder::new(&arena3, &limits);
        builder3
            .push_normalized(
                &mut arena3,
                b"X-Forwarded-For",
                UnderscorePolicy::MapToHyphen,
                b"1.1.1.1",
                WireVersion::Http11,
            )
            .unwrap();
        builder3
            .push_normalized(
                &mut arena3,
                b"X-Forwarded-For",
                UnderscorePolicy::MapToHyphen,
                b"2.2.2.2",
                WireVersion::Http11,
            )
            .unwrap();
        assert_eq!(builder3.len(), 2);
    }

    #[test]
    fn underscore_check_is_free_without_underscores() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        for i in 0..100u32 {
            let name = format!("x-field-{i:03}");
            builder
                .push_normalized(
                    &mut arena,
                    name.as_bytes(),
                    UnderscorePolicy::MapToHyphen,
                    b"v",
                    WireVersion::Http11,
                )
                .unwrap();
        }
        assert_eq!(builder.len(), 100);
    }

    #[test]
    fn retain_recomputes_the_mask() {
        let limits = Limits::DEFAULT.clamped();
        let mut arena = BytesMut::new();
        let mut builder = FieldSectionBuilder::new(&arena, &limits);
        builder.push(&mut arena, b"host", b"h").unwrap();
        builder.push(&mut arena, b"via", b"a").unwrap();
        builder.push(&mut arena, b"x-q", b"1").unwrap();
        builder.push(&mut arena, b"via", b"b").unwrap();
        let mut section = builder.finish(&mut arena);

        let arena_len_before = section.arena.len();
        let removed = section.retain(|name, _, _| !name.starts_with(b"vi"));
        assert_eq!(removed, 2);
        assert!(!section.contains_known(KnownHeader::Via));
        assert!(section.contains_known(KnownHeader::Host));
        assert_eq!(section.len(), 2);
        assert_eq!(section.arena.len(), arena_len_before);
    }
}
