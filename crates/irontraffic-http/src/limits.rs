// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hard limits applied to every inbound message.
//!
//! Every limit in [`Limits`] is the *only* thing standing between a network
//! peer and unbounded per-connection memory: `max_header_list_bytes` alone is
//! the entire HPACK and QPACK decompression-bomb defense. [`Limits`] is
//! populated by an operator-supplied configuration in a later milestone, and
//! a configuration that sets `max_header_list_bytes: 4294967295` would
//! silently convert that defense into nothing, with no error and no log
//! line, if nothing stopped it. [`Limits::CEILING`] makes the failure
//! impossible rather than detectable: the worst a misconfiguration can do is
//! spend 1 MiB of uncompressed header state and 1000 field slots per
//! in-flight message, a number this product can size a machine against.
//! That guarantee is enforced by the type system, not only documented here:
//! every parse function in this crate takes `&`[`ClampedLimits`], never
//! `&Limits`, and the only way to produce a [`ClampedLimits`] is
//! [`Limits::clamped`]. An unclamped `Limits` value simply does not type
//! check at a parse boundary.
//!
//! The rule for consumers, stated once here because every parser in this
//! milestone takes `&ClampedLimits`: the configuration layer calls
//! [`Limits::clamped`] exactly once when it builds the value; parse
//! functions do not re-clamp on the hot path, and cannot receive a value
//! that skipped clamping.
//!
//! No field of this struct may ever be given a sentinel meaning "unlimited"
//! (`0`, `u32::MAX`, `Option::None`). A sentinel is an off switch for a bound
//! that is reachable from the network, and [`Limits::CEILING`] cannot clamp
//! one.

/// Hard limits applied to every inbound message on every protocol version.
///
/// These are the values the configuration layer will populate in a later
/// milestone. `Limits::DEFAULT` is the shipped default and is what every
/// test in this crate uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of field lines in one header section. Default 100.
    pub max_field_count: u32,
    /// Maximum bytes of one field line (name plus value, excluding the colon
    /// and CRLF). Default 8192.
    pub max_field_line_bytes: u32,
    /// Maximum sum of `name.len() + value.len() + 32` over the whole header
    /// section, computed on UNCOMPRESSED bytes. Default 65536.
    pub max_header_list_bytes: u32,
    /// Maximum bytes of an HTTP/1 request line including the trailing CRLF.
    /// Default 8192.
    pub max_request_line_bytes: u32,
    /// Maximum bytes of a request target path component. Default 8192.
    pub max_path_bytes: u32,
    /// Maximum bytes of an authority (host plus optional port). Default 255.
    pub max_authority_bytes: u32,
    /// Maximum bytes of chunk extensions on one chunk. Default 256.
    pub max_chunk_ext_bytes: u32,
    /// Maximum forwarding-chain elements parsed before refusing. Default 32.
    pub max_forwarded_elements: u32,
    /// Maximum total bytes of forwarding-chain field values parsed. Default
    /// 4096.
    pub max_forwarded_bytes: u32,
    /// Maximum interim (1xx) responses relayed for one request. Default 5.
    pub max_interim_responses: u32,
    /// Maximum total bytes of interim responses relayed for one request.
    /// Default 16384.
    pub max_interim_bytes: u32,
    /// Maximum bytes of an extension method token. Default 16, and effective
    /// values are clamped to `MethodToken::CAP` (16) because the token is
    /// stored inline in a fixed 16-byte array. Setting this above 16 does
    /// not widen the token; it is clamped.
    pub max_method_bytes: u32,
    /// Maximum re-route cycles a rewrite chain may perform. Default 1, hard
    /// cap 3.
    pub max_rewrites: u8,
}

/// Clamps a `u32` field down to its ceiling. Never raises `value`.
const fn clamp_u32(value: u32, ceiling: u32) -> u32 {
    if value > ceiling { ceiling } else { value }
}

/// Clamps a `u8` field down to its ceiling. Never raises `value`.
const fn clamp_u8(value: u8, ceiling: u8) -> u8 {
    if value > ceiling { ceiling } else { value }
}

impl Limits {
    /// The shipped defaults.
    pub const DEFAULT: Limits = Limits {
        max_field_count: 100,
        max_field_line_bytes: 8192,
        max_header_list_bytes: 65_536,
        max_request_line_bytes: 8192,
        max_path_bytes: 8192,
        max_authority_bytes: 255,
        max_chunk_ext_bytes: 256,
        max_forwarded_elements: 32,
        max_forwarded_bytes: 4096,
        max_interim_responses: 5,
        max_interim_bytes: 16_384,
        max_method_bytes: 16,
        max_rewrites: 1,
    };

    /// The hard ceiling on `max_rewrites`, enforced by
    /// [`Limits::clamp_rewrites`].
    pub const MAX_REWRITES_CAP: u8 = 3;

    /// Returns `max_rewrites` clamped to [`Limits::MAX_REWRITES_CAP`].
    #[must_use]
    pub const fn clamp_rewrites(&self) -> u8 {
        clamp_u8(self.max_rewrites, Self::MAX_REWRITES_CAP)
    }

    /// The hard ceiling for every field, in the same field order as the
    /// struct. A configuration may lower a limit; it may never raise one
    /// past this.
    pub const CEILING: Limits = Limits {
        max_field_count: 1_000,
        max_field_line_bytes: 65_535,
        max_header_list_bytes: 1_048_576,
        max_request_line_bytes: 65_536,
        max_path_bytes: 65_536,
        max_authority_bytes: 1_024,
        max_chunk_ext_bytes: 4_096,
        max_forwarded_elements: 255,
        max_forwarded_bytes: 65_536,
        max_interim_responses: 100,
        max_interim_bytes: 1_048_576,
        max_method_bytes: 16,
        max_rewrites: 3,
    };

    /// Returns `self` with every field clamped to the matching field of
    /// [`Limits::CEILING`] (the smaller of the two, so a lower configured
    /// value is kept as configured), wrapped in a [`ClampedLimits`] so the
    /// result can only be handed to a parse function once it has actually
    /// been through this clamp. This is the ONLY way to construct a
    /// [`ClampedLimits`].
    #[must_use]
    pub const fn clamped(self) -> ClampedLimits {
        ClampedLimits(Limits {
            max_field_count: clamp_u32(self.max_field_count, Self::CEILING.max_field_count),
            max_field_line_bytes: clamp_u32(
                self.max_field_line_bytes,
                Self::CEILING.max_field_line_bytes,
            ),
            max_header_list_bytes: clamp_u32(
                self.max_header_list_bytes,
                Self::CEILING.max_header_list_bytes,
            ),
            max_request_line_bytes: clamp_u32(
                self.max_request_line_bytes,
                Self::CEILING.max_request_line_bytes,
            ),
            max_path_bytes: clamp_u32(self.max_path_bytes, Self::CEILING.max_path_bytes),
            max_authority_bytes: clamp_u32(
                self.max_authority_bytes,
                Self::CEILING.max_authority_bytes,
            ),
            max_chunk_ext_bytes: clamp_u32(
                self.max_chunk_ext_bytes,
                Self::CEILING.max_chunk_ext_bytes,
            ),
            max_forwarded_elements: clamp_u32(
                self.max_forwarded_elements,
                Self::CEILING.max_forwarded_elements,
            ),
            max_forwarded_bytes: clamp_u32(
                self.max_forwarded_bytes,
                Self::CEILING.max_forwarded_bytes,
            ),
            max_interim_responses: clamp_u32(
                self.max_interim_responses,
                Self::CEILING.max_interim_responses,
            ),
            max_interim_bytes: clamp_u32(self.max_interim_bytes, Self::CEILING.max_interim_bytes),
            max_method_bytes: clamp_u32(self.max_method_bytes, Self::CEILING.max_method_bytes),
            max_rewrites: clamp_u8(self.max_rewrites, Self::CEILING.max_rewrites),
        })
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits::DEFAULT
    }
}

// D7: nothing ties `MethodToken::CAP` (defined in `scalar.rs`) to
// `Limits::CEILING.max_method_bytes` other than both happening to read 16
// today; this line makes a future edit to either one a compile error instead
// of a silent divergence. Read as: the two rewrite ceilings agree.
const _: () = assert!(Limits::MAX_REWRITES_CAP == Limits::CEILING.max_rewrites);

/// A [`Limits`] value that has already been clamped to [`Limits::CEILING`]
/// via [`Limits::clamped`].
///
/// This exists because `Limits`'s 13 fields are, and must stay, public: the
/// configuration layer builds one with struct-update syntax and `serde`
/// derives on it. That means nothing stops `Limits { max_header_list_bytes:
/// u32::MAX, ..Limits::DEFAULT }` from compiling and reaching a parser,
/// which would silently turn off the entire HPACK/QPACK decompression-bomb
/// defense `CEILING` exists to guarantee against. Every parse function in
/// this crate therefore takes `&ClampedLimits`, not `&Limits`, and the only
/// way to build one is [`Limits::clamped`] (its tuple field is private to
/// this module). A `Limits` that never went through `clamped()` cannot be
/// named at a parse boundary; the compiler enforces what used to be only a
/// doc comment.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClampedLimits(Limits);

impl core::ops::Deref for ClampedLimits {
    type Target = Limits;

    fn deref(&self) -> &Limits {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_exact() {
        let d = Limits::DEFAULT;
        assert_eq!(d.max_field_count, 100);
        assert_eq!(d.max_field_line_bytes, 8192);
        assert_eq!(d.max_header_list_bytes, 65_536);
        assert_eq!(d.max_request_line_bytes, 8192);
        assert_eq!(d.max_path_bytes, 8192);
        assert_eq!(d.max_authority_bytes, 255);
        assert_eq!(d.max_chunk_ext_bytes, 256);
        assert_eq!(d.max_forwarded_elements, 32);
        assert_eq!(d.max_forwarded_bytes, 4096);
        assert_eq!(d.max_interim_responses, 5);
        assert_eq!(d.max_interim_bytes, 16_384);
        assert_eq!(d.max_method_bytes, 16);
        assert_eq!(d.max_rewrites, 1);

        let hostile_rewrites = Limits {
            max_rewrites: 200,
            ..Limits::DEFAULT
        };
        assert_eq!(hostile_rewrites.clamp_rewrites(), 3);
    }

    #[test]
    fn default_matches_default_via_default_trait() {
        // D9: `Default for Limits` had no test at all.
        assert_eq!(Limits::default(), Limits::DEFAULT);
    }

    #[test]
    fn ceiling_fields_are_pinned() {
        // D9: `CEILING` had no test. `clamped()` is implemented in terms of
        // `CEILING`, and the two prior tests only compare `clamped()`
        // against `CEILING`, so both sides could move together and stay
        // green even if `CEILING` were weakened to `u32::MAX` across the
        // board. Pin every one of the 13 fields against a literal instead.
        assert_eq!(Limits::CEILING.max_field_count, 1_000);
        assert_eq!(Limits::CEILING.max_field_line_bytes, 65_535);
        assert_eq!(Limits::CEILING.max_header_list_bytes, 1_048_576);
        assert_eq!(Limits::CEILING.max_request_line_bytes, 65_536);
        assert_eq!(Limits::CEILING.max_path_bytes, 65_536);
        assert_eq!(Limits::CEILING.max_authority_bytes, 1_024);
        assert_eq!(Limits::CEILING.max_chunk_ext_bytes, 4_096);
        assert_eq!(Limits::CEILING.max_forwarded_elements, 255);
        assert_eq!(Limits::CEILING.max_forwarded_bytes, 65_536);
        assert_eq!(Limits::CEILING.max_interim_responses, 100);
        assert_eq!(Limits::CEILING.max_interim_bytes, 1_048_576);
        assert_eq!(Limits::CEILING.max_method_bytes, 16);
        assert_eq!(Limits::CEILING.max_rewrites, 3);
    }

    #[test]
    fn default_is_already_within_ceiling() {
        // D9: companion to `ceiling_fields_are_pinned`. The shipped default
        // must already satisfy the ceiling, so clamping it is a no-op.
        assert_eq!(*Limits::DEFAULT.clamped(), Limits::DEFAULT);
    }

    #[test]
    fn ceiling_clamps_hostile_config() {
        let hostile = Limits {
            max_field_count: u32::MAX,
            max_field_line_bytes: u32::MAX,
            max_header_list_bytes: u32::MAX,
            max_request_line_bytes: u32::MAX,
            max_path_bytes: u32::MAX,
            max_authority_bytes: u32::MAX,
            max_chunk_ext_bytes: u32::MAX,
            max_forwarded_elements: u32::MAX,
            max_forwarded_bytes: u32::MAX,
            max_interim_responses: u32::MAX,
            max_interim_bytes: u32::MAX,
            max_method_bytes: u32::MAX,
            max_rewrites: u8::MAX,
        };
        let clamped = hostile.clamped();
        assert_eq!(*clamped, Limits::CEILING);
    }

    #[test]
    fn clamped_is_idempotent_and_never_raises() {
        proptest::proptest!(|(
            max_field_count: u32,
            max_field_line_bytes: u32,
            max_header_list_bytes: u32,
            max_request_line_bytes: u32,
            max_path_bytes: u32,
            max_authority_bytes: u32,
            max_chunk_ext_bytes: u32,
            max_forwarded_elements: u32,
            max_forwarded_bytes: u32,
            max_interim_responses: u32,
            max_interim_bytes: u32,
            max_method_bytes: u32,
            max_rewrites: u8,
        )| {
            let l = Limits {
                max_field_count,
                max_field_line_bytes,
                max_header_list_bytes,
                max_request_line_bytes,
                max_path_bytes,
                max_authority_bytes,
                max_chunk_ext_bytes,
                max_forwarded_elements,
                max_forwarded_bytes,
                max_interim_responses,
                max_interim_bytes,
                max_method_bytes,
                max_rewrites,
            };
            let once = l.clamped();
            let twice = (*once).clamped();

            assert!(once.max_field_count <= Limits::CEILING.max_field_count);
            assert!(once.max_field_line_bytes <= Limits::CEILING.max_field_line_bytes);
            assert!(once.max_header_list_bytes <= Limits::CEILING.max_header_list_bytes);
            assert!(once.max_request_line_bytes <= Limits::CEILING.max_request_line_bytes);
            assert!(once.max_path_bytes <= Limits::CEILING.max_path_bytes);
            assert!(once.max_authority_bytes <= Limits::CEILING.max_authority_bytes);
            assert!(once.max_chunk_ext_bytes <= Limits::CEILING.max_chunk_ext_bytes);
            assert!(once.max_forwarded_elements <= Limits::CEILING.max_forwarded_elements);
            assert!(once.max_forwarded_bytes <= Limits::CEILING.max_forwarded_bytes);
            assert!(once.max_interim_responses <= Limits::CEILING.max_interim_responses);
            assert!(once.max_interim_bytes <= Limits::CEILING.max_interim_bytes);
            assert!(once.max_method_bytes <= Limits::CEILING.max_method_bytes);
            assert!(once.max_rewrites <= Limits::CEILING.max_rewrites);

            assert!(once.max_field_count <= l.max_field_count);
            assert!(once.max_field_line_bytes <= l.max_field_line_bytes);
            assert!(once.max_header_list_bytes <= l.max_header_list_bytes);
            assert!(once.max_request_line_bytes <= l.max_request_line_bytes);
            assert!(once.max_path_bytes <= l.max_path_bytes);
            assert!(once.max_authority_bytes <= l.max_authority_bytes);
            assert!(once.max_chunk_ext_bytes <= l.max_chunk_ext_bytes);
            assert!(once.max_forwarded_elements <= l.max_forwarded_elements);
            assert!(once.max_forwarded_bytes <= l.max_forwarded_bytes);
            assert!(once.max_interim_responses <= l.max_interim_responses);
            assert!(once.max_interim_bytes <= l.max_interim_bytes);
            assert!(once.max_method_bytes <= l.max_method_bytes);
            assert!(once.max_rewrites <= l.max_rewrites);

            assert_eq!(once, twice);
        });
    }
}
