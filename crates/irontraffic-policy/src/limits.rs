// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admission limits for ITPL expressions.
//!
//! Every limit is checked at config-admission time, never at request time.
//! A configured policy may override the defaults, but every override is itself
//! bounded by a hard cap so a tenant cannot turn a limit into a memory knob.

/// Admission limits. Every one of these is checked at config time and none of them
/// is checked at request time, because by then the program is already bounded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PolicyLimits {
    /// Source bytes for one expression. Default 8192.
    pub max_source_bytes: u32,
    /// Tokens for one expression. Default 1024.
    pub max_tokens: u32,
    /// Decoded bytes of one string literal. Default 1024.
    pub max_string_bytes: u32,
    /// Nesting depth of the AST. Default 16.
    pub max_depth: u16,
    /// Bytecode instructions in one compiled program. Default 256.
    pub max_ops: u16,
    /// Distinct constants in one program. Default 128.
    pub max_consts: u16,
    /// Distinct attribute references in one program. Default 16.
    pub max_attr_slots: u16,
    /// Compiled regexes in one program. Default 8.
    pub max_regex: u16,
    /// Bytes of compiled regex program, passed to `RegexBuilder::size_limit`.
    /// Default 65_536.
    pub max_regex_size: u32,
    /// Elements in one list literal. Default 64.
    pub max_list_elems: u16,
}

/// Why a configured `PolicyLimits` override is not usable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LimitError {
    /// A field is 0. `field` is the field name as a `&'static str`.
    Zero {
        /// Name of the field that was zero.
        field: &'static str,
    },
    /// A field exceeds its hard cap.
    AboveCap {
        /// Name of the field that was too large.
        field: &'static str,
        /// The value that was requested.
        requested: u32,
        /// The hard cap for that field.
        cap: u32,
    },
}

impl PolicyLimits {
    /// The documented defaults, which are also what `docs/ITPL.md` publishes.
    #[must_use]
    pub const fn defaults() -> PolicyLimits {
        PolicyLimits {
            max_source_bytes: 8_192,
            max_tokens: 1_024,
            max_string_bytes: 1_024,
            max_depth: 16,
            max_ops: 256,
            max_consts: 128,
            max_attr_slots: 16,
            max_regex: 8,
            max_regex_size: 65_536,
            max_list_elems: 64,
        }
    }

    /// The hard cap for every field, as `(field name, cap)` pairs. Checked in this
    /// order, which is declaration order, so the reported field is deterministic:
    ///
    /// | field | default | hard cap |
    /// | --- | --- | --- |
    /// | `max_source_bytes` | 8_192 | 65_536 |
    /// | `max_tokens` | 1_024 | 8_192 |
    /// | `max_string_bytes` | 1_024 | 8_192 |
    /// | `max_depth` | 16 | 16 |
    /// | `max_ops` | 256 | 4_096 |
    /// | `max_consts` | 128 | 1_024 |
    /// | `max_attr_slots` | 16 | 16 |
    /// | `max_regex` | 8 | 64 |
    /// | `max_regex_size` | 65_536 | 1_048_576 |
    /// | `max_list_elems` | 64 | 1_024 |
    pub const CAPS: [(&'static str, u32); 10] = [
        ("max_source_bytes", 65_536),
        ("max_tokens", 8_192),
        ("max_string_bytes", 8_192),
        ("max_depth", 16),
        ("max_ops", 4_096),
        ("max_consts", 1_024),
        ("max_attr_slots", 16),
        ("max_regex", 64),
        ("max_regex_size", 1_048_576),
        ("max_list_elems", 1_024),
    ];

    /// Validates a configured override.
    ///
    /// # Errors
    /// `LimitError::Zero` when any field except `max_regex` is 0.
    /// `LimitError::AboveCap` when any field exceeds its entry in `CAPS`.
    ///
    /// The 16s are not arbitrary and must not be raised in isolation: the evaluator's
    /// operand stack is a fixed `[Value; 16]` and its slot cache is a fixed
    /// `[Option<Value>; 16]`, both sized so that evaluation cannot allocate. Raising
    /// either limit without resizing those arrays turns a configuration mistake into a
    /// runtime verification failure or an out-of-range slot write.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn validate(&self) -> Result<(), LimitError> {
        let caps = Self::CAPS;

        // Declaration order, matching CAPS.
        Self::check_u32(self.max_source_bytes, caps[0].0, caps[0].1)?;
        Self::check_u32(self.max_tokens, caps[1].0, caps[1].1)?;
        Self::check_u32(self.max_string_bytes, caps[2].0, caps[2].1)?;
        Self::check_u16(self.max_depth, caps[3].0, caps[3].1)?;
        Self::check_u16(self.max_ops, caps[4].0, caps[4].1)?;
        Self::check_u16(self.max_consts, caps[5].0, caps[5].1)?;
        Self::check_u16(self.max_attr_slots, caps[6].0, caps[6].1)?;
        Self::check_u16_regex(self.max_regex, caps[7].0, caps[7].1)?;
        Self::check_u32(self.max_regex_size, caps[8].0, caps[8].1)?;
        Self::check_u16(self.max_list_elems, caps[9].0, caps[9].1)?;

        Ok(())
    }

    fn check_u32(value: u32, field: &'static str, cap: u32) -> Result<(), LimitError> {
        if value == 0 {
            return Err(LimitError::Zero { field });
        }
        if value > cap {
            return Err(LimitError::AboveCap {
                field,
                requested: value,
                cap,
            });
        }
        Ok(())
    }

    fn check_u16(value: u16, field: &'static str, cap: u32) -> Result<(), LimitError> {
        // cap is guaranteed to fit in u16 for every u16 field, but this avoids a
        // narrowing cast and keeps the comparison in the wider type.
        let cap_u16 = match u16::try_from(cap) {
            Ok(c) => c,
            Err(_) => return Err(LimitError::AboveCap {
                field,
                requested: u32::from(value),
                cap,
            }),
        };
        if value == 0 {
            return Err(LimitError::Zero { field });
        }
        if value > cap_u16 {
            return Err(LimitError::AboveCap {
                field,
                requested: u32::from(value),
                cap,
            });
        }
        Ok(())
    }

    fn check_u16_regex(value: u16, field: &'static str, cap: u32) -> Result<(), LimitError> {
        let cap_u16 = match u16::try_from(cap) {
            Ok(c) => c,
            Err(_) => {
                return Err(LimitError::AboveCap {
                    field,
                    requested: u32::from(value),
                    cap,
                });
            }
        };
        // max_regex of 0 is legal and means "no regex operators allowed".
        if value > cap_u16 {
            return Err(LimitError::AboveCap {
                field,
                requested: u32::from(value),
                cap,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_validate_rejects_zero_and_caps() {
        let base = PolicyLimits::defaults();

        // Zero checks, except max_regex.
        let mut l = base;
        l.max_source_bytes = 0;
        assert_eq!(
            l.validate(),
            Err(LimitError::Zero {
                field: "max_source_bytes"
            })
        );

        let mut l = base;
        l.max_tokens = 0;
        assert_eq!(
            l.validate(),
            Err(LimitError::Zero {
                field: "max_tokens"
            })
        );

        let mut l = base;
        l.max_string_bytes = 0;
        assert_eq!(
            l.validate(),
            Err(LimitError::Zero {
                field: "max_string_bytes"
            })
        );

        let mut l = base;
        l.max_depth = 0;
        assert_eq!(
            l.validate(),
            Err(LimitError::Zero {
                field: "max_depth"
            })
        );

        let mut l = base;
        l.max_ops = 0;
        assert_eq!(
            l.validate(),
            Err(LimitError::Zero {
                field: "max_ops"
            })
        );

        let mut l = base;
        l.max_consts = 0;
        assert_eq!(
            l.validate(),
            Err(LimitError::Zero {
                field: "max_consts"
            })
        );

        let mut l = base;
        l.max_attr_slots = 0;
        assert_eq!(
            l.validate(),
            Err(LimitError::Zero {
                field: "max_attr_slots"
            })
        );

        let mut l = base;
        l.max_regex = 0;
        assert_eq!(l.validate(), Ok(()));

        let mut l = base;
        l.max_regex_size = 0;
        assert_eq!(
            l.validate(),
            Err(LimitError::Zero {
                field: "max_regex_size"
            })
        );

        let mut l = base;
        l.max_list_elems = 0;
        assert_eq!(
            l.validate(),
            Err(LimitError::Zero {
                field: "max_list_elems"
            })
        );

        // Above-cap checks.
        let mut l = base;
        l.max_depth = 17;
        assert_eq!(
            l.validate(),
            Err(LimitError::AboveCap {
                field: "max_depth",
                requested: 17,
                cap: 16,
            })
        );

        let mut l = base;
        l.max_ops = 4097;
        assert_eq!(
            l.validate(),
            Err(LimitError::AboveCap {
                field: "max_ops",
                requested: 4097,
                cap: 4096,
            })
        );

        let mut l = base;
        l.max_attr_slots = 17;
        assert_eq!(
            l.validate(),
            Err(LimitError::AboveCap {
                field: "max_attr_slots",
                requested: 17,
                cap: 16,
            })
        );

        // Boundary OK.
        let mut l = base;
        l.max_depth = 16;
        l.max_attr_slots = 16;
        assert_eq!(l.validate(), Ok(()));
    }

    #[test]
    fn every_limit_field_has_a_cap() {
        let base = PolicyLimits::defaults();
        let fields = [
            ("max_source_bytes", u32::from(base.max_source_bytes)),
            ("max_tokens", u32::from(base.max_tokens)),
            ("max_string_bytes", u32::from(base.max_string_bytes)),
            ("max_depth", u32::from(base.max_depth)),
            ("max_ops", u32::from(base.max_ops)),
            ("max_consts", u32::from(base.max_consts)),
            ("max_attr_slots", u32::from(base.max_attr_slots)),
            ("max_regex", u32::from(base.max_regex)),
            ("max_regex_size", base.max_regex_size),
            ("max_list_elems", u32::from(base.max_list_elems)),
        ];

        assert_eq!(PolicyLimits::CAPS.len(), fields.len());

        for (field, cap) in PolicyLimits::CAPS {
            let mut l = base;
            match field {
                "max_source_bytes" => l.max_source_bytes = cap,
                "max_tokens" => l.max_tokens = cap,
                "max_string_bytes" => l.max_string_bytes = cap,
                "max_depth" => l.max_depth = u16::try_from(cap).unwrap(),
                "max_ops" => l.max_ops = u16::try_from(cap).unwrap(),
                "max_consts" => l.max_consts = u16::try_from(cap).unwrap(),
                "max_attr_slots" => l.max_attr_slots = u16::try_from(cap).unwrap(),
                "max_regex" => l.max_regex = u16::try_from(cap).unwrap(),
                "max_regex_size" => l.max_regex_size = cap,
                "max_list_elems" => l.max_list_elems = u16::try_from(cap).unwrap(),
                _ => panic!("unknown field {field}"),
            }
            assert_eq!(l.validate(), Ok(()), "{field} at cap should validate");

            let requested = if field == "max_regex" {
                cap.checked_add(1).unwrap()
            } else if cap == u32::MAX {
                cap
            } else {
                cap.checked_add(1).unwrap()
            };

            if field == "max_regex" || cap != u32::MAX {
                let mut l2 = l;
                match field {
                    "max_source_bytes" => l2.max_source_bytes = requested,
                    "max_tokens" => l2.max_tokens = requested,
                    "max_string_bytes" => l2.max_string_bytes = requested,
                    "max_depth" => l2.max_depth = u16::try_from(requested).unwrap(),
                    "max_ops" => l2.max_ops = u16::try_from(requested).unwrap(),
                    "max_consts" => l2.max_consts = u16::try_from(requested).unwrap(),
                    "max_attr_slots" => {
                        l2.max_attr_slots = u16::try_from(requested).unwrap();
                    }
                    "max_regex" => l2.max_regex = u16::try_from(requested).unwrap(),
                    "max_regex_size" => l2.max_regex_size = requested,
                    "max_list_elems" => l2.max_list_elems = u16::try_from(requested).unwrap(),
                    _ => panic!("unknown field {field}"),
                }
                assert_eq!(
                    l2.validate(),
                    Err(LimitError::AboveCap {
                        field,
                        requested,
                        cap,
                    }),
                    "{field} over cap should fail"
                );
            }
        }
    }
}
