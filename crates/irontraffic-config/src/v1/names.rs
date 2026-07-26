// SPDX-License-Identifier: MIT OR Apache-2.0

//! The naming and identity vocabulary every dynamic configuration resource is
//! written in: `ResourceName`, `Namespace`, `ProviderName`, `Hostname`,
//! `Weight`, and the `[namespace/]name[@provider]` reference syntax as one
//! parsed [`ResourceRef`].
//!
//! Every constructor here is a `TryFrom` implementation, so a value that
//! exists has already been checked: there is no separate "validate this
//! later" step for any of these types, and [`ResourceRef::try_from`] is the
//! only reference parser in the workspace. No type in this module exposes its
//! inner field, and no constructor lowercases, trims, or otherwise repairs an
//! invalid identifier: it is rejected with a message naming the legal class.

/// Maximum bytes of a serialised [`ResourceRef`]: 63 + 1 + 253 + 1 + 32.
pub const MAX_REF_BYTES: usize = 350;

/// Maximum bytes of attacker-chosen input echoed back in a [`NameError`].
pub const MAX_ERROR_ECHO_BYTES: usize = 64;

/// Maximum bytes of a [`ResourceName`].
const RESOURCE_NAME_MAX_BYTES: usize = 253;
/// Maximum bytes of a [`Namespace`].
const NAMESPACE_MAX_BYTES: usize = 63;
/// Maximum bytes of a [`ProviderName`].
const PROVIDER_MAX_BYTES: usize = 32;
/// Maximum bytes of a [`Hostname`], per the Gateway API definition.
const HOSTNAME_MAX_BYTES: usize = 253;
/// Maximum labels in a [`Hostname`], matching
/// `irontraffic_router::limits::MAX_HOST_LABELS` so the two layers accept
/// exactly the same strings without a second parse.
const MAX_HOST_LABELS: usize = 16;

/// Bytes of the escaped-and-quoted `{found:?}` rendering past which the
/// surrounding fixed message text could no longer keep the whole rendered
/// error under 256 bytes even in the worst case. Every `NameError` variant's
/// own fixed text (the format string with `found` removed) is under 100
/// bytes, so this leaves comfortable headroom under the 256-byte ceiling
/// [`NameError`] promises.
///
/// This is a byte budget on the RENDERED (Debug-escaped) form, not on the raw
/// input, because a naive "keep the first `MAX_ERROR_ECHO_BYTES` raw bytes"
/// truncation does not actually bound the rendered length: a control byte
/// such as ESC (0x1B) has no short Rust escape and renders as `\u{1b}`, six
/// bytes for one input byte, so 64 raw bytes of such input would render as
/// roughly 384 bytes, well past 256, before the surrounding message text is
/// even added. [`truncate_echo`] therefore shrinks the raw prefix further
/// when its escaped form would still be too expensive, rather than trusting
/// the raw byte count alone.
const RENDERED_ECHO_BUDGET_BYTES: usize = 120;

/// A name, hostname, weight, reference or extension map failed its own validation.
///
/// Every `found` field holds at most [`MAX_ERROR_ECHO_BYTES`] bytes of the offending
/// input, cut at a character boundary with `"..."` appended when anything was cut, and
/// every format string renders it with `{:?}` so control bytes cannot forge a log line.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NameError {
    /// The resource name is empty, too long, or has an illegal byte.
    #[error(
        "resource name {found:?} is invalid: 1 to 253 bytes of [a-z0-9.-], not starting or ending with '-' or '.'"
    )]
    ResourceName {
        /// The value that was rejected, truncated.
        found: String,
    },
    /// The namespace is empty, too long, or has an illegal byte.
    #[error(
        "namespace {found:?} is invalid: 1 to 63 bytes of [a-z0-9-], not starting or ending with '-'"
    )]
    Namespace {
        /// The value that was rejected, truncated.
        found: String,
    },
    /// The provider name is empty, too long, or has an illegal byte.
    #[error("provider {found:?} is invalid: 1 to 32 bytes matching [a-z][a-z0-9-]*")]
    Provider {
        /// The value that was rejected, truncated.
        found: String,
    },
    /// The hostname is not a Gateway API hostname.
    #[error("hostname {found:?} is invalid: {why}")]
    Hostname {
        /// The value that was rejected, truncated.
        found: String,
        /// Which rule the value failed.
        why: &'static str,
    },
    /// The weight is above 1000000.
    #[error("weight {found:?} is out of range: expected 0 to 1000000")]
    Weight {
        /// The value that was rejected.
        found: u32,
    },
    /// The reference was empty.
    #[error("reference is empty: expected [namespace/]name[@provider]")]
    RefEmpty,
    /// The reference exceeded `MAX_REF_BYTES`.
    #[error("reference {found:?} exceeds {MAX_REF_BYTES} bytes")]
    RefTooLong {
        /// The value that was rejected, truncated.
        found: String,
    },
    /// The reference contained more than one `@`.
    #[error("reference {found:?} contains more than one '@'")]
    RefMultipleAt {
        /// The value that was rejected, truncated.
        found: String,
    },
    /// The reference contained more than one `/`.
    #[error("reference {found:?} contains more than one '/'")]
    RefMultipleSlash {
        /// The value that was rejected, truncated.
        found: String,
    },
    /// The provider part after `@` was empty.
    #[error("reference {found:?} has an empty provider after '@'")]
    RefProviderEmpty {
        /// The value that was rejected, truncated.
        found: String,
    },
    /// The namespace part before `/` was empty.
    #[error("reference {found:?} has an empty namespace before '/'")]
    RefNamespaceEmpty {
        /// The value that was rejected, truncated.
        found: String,
    },
    /// The name part was empty.
    #[error("reference {found:?} has an empty name")]
    RefNameEmpty {
        /// The value that was rejected, truncated.
        found: String,
    },
    /// The extension map had more than `MAX_EXTENSION_KEYS` entries.
    #[error(
        "x_extensions has {found:?} keys, at most {} allowed",
        crate::v1::MAX_EXTENSION_KEYS
    )]
    ExtensionsTooManyKeys {
        /// The number of keys the map had.
        found: usize,
    },
    /// An extension key was longer than `MAX_EXTENSION_KEY_BYTES`.
    #[error(
        "x_extensions key {found:?} exceeds {} bytes",
        crate::v1::MAX_EXTENSION_KEY_BYTES
    )]
    ExtensionsKeyTooLong {
        /// The key that was rejected, truncated.
        found: String,
    },
    /// The encoded extension map was larger than `MAX_EXTENSIONS_BYTES`.
    #[error(
        "x_extensions encodes to {found:?} bytes, at most {} allowed",
        crate::v1::MAX_EXTENSIONS_BYTES
    )]
    ExtensionsTooLarge {
        /// The encoded size in bytes.
        found: usize,
    },
    /// An extension value nested deeper than `MAX_EXTENSION_DEPTH`.
    #[error(
        "x_extensions value under key {found:?} nests deeper than {} levels",
        crate::v1::MAX_EXTENSION_DEPTH
    )]
    ExtensionsTooDeep {
        /// The key whose value was too deep, truncated.
        found: String,
    },
}

/// The largest byte index at most `cut` that lands on one of `s`'s UTF-8 character
/// boundaries. Requires `cut <= s.len()`. Never panics or underflows: byte `0` is
/// always a boundary for any `&str`, including an empty one, so the search always
/// terminates there even without an explicit `cut > 0` guard.
///
/// Mutation testing (`cargo mutants -j 1`) confirms `cut -= 1` is load bearing rather
/// than equivalent: mutating it to `cut += 1` or `cut /= 1` breaks the search's only
/// progress toward the boundary at `0`, so the mutant hangs instead of returning a
/// wrong answer. `cargo-mutants` reports that as TIMEOUT, not MISSED, which is the
/// correct classification: the mutant is genuinely detected, just via a hang under
/// its 20 second test timeout rather than a failed assertion.
fn floor_to_char_boundary(s: &str, mut cut: usize) -> usize {
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    cut
}

/// Truncates `s` for use in a [`NameError::found`](enum.NameError.html) field.
///
/// The result renders (via `{:?}`) to at most [`RENDERED_ECHO_BUDGET_BYTES`] bytes,
/// with `"..."` appended when anything was cut. Cutting always lands on a UTF-8
/// character boundary. See [`RENDERED_ECHO_BUDGET_BYTES`] for why this bounds the
/// escaped rendering rather than the raw byte count: a raw-byte-only bound does not
/// hold once the input is heavy with bytes that expand under `Debug` escaping.
pub(super) fn truncate_echo(s: &str) -> String {
    let mut cut = floor_to_char_boundary(s, s.len().min(MAX_ERROR_ECHO_BYTES));
    loop {
        let candidate = s.get(..cut).unwrap_or("");
        let rendered_len = format!("{candidate:?}").len();
        // No separate `cut == 0` escape is needed to guarantee this terminates: an
        // empty `candidate` always renders as `""`, two bytes, which is always within
        // budget, so the loop is guaranteed to accept by the time `cut` reaches 0.
        //
        // Mutation testing confirms `<=` here is load bearing: mutating it to `>`
        // makes the accept branch unreachable for any realistic input (rendered_len is
        // almost never greater than the budget), so the loop spins forever shrinking
        // `cut` to `0` and then testing the same always-false condition. Reported as
        // TIMEOUT rather than MISSED, for the same reason as `floor_to_char_boundary`.
        if rendered_len <= RENDERED_ECHO_BUDGET_BYTES {
            let mut out = candidate.to_owned();
            if cut < s.len() {
                out.push_str("...");
            }
            return out;
        }
        cut = floor_to_char_boundary(s, cut.saturating_sub(1));
    }
}

/// A resource name: 1 to 253 bytes matching `[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
#[schemars(
    with = "String",
    extend("pattern" = "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", "maxLength" = 253)
)]
pub struct ResourceName(smol_str::SmolStr);

impl ResourceName {
    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn parse_resource_name(s: &str) -> Result<ResourceName, NameError> {
    let bytes = s.as_bytes();
    let len_ok = !bytes.is_empty() && bytes.len() <= RESOURCE_NAME_MAX_BYTES;
    let charset_ok = bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    let edges_ok = match (bytes.first(), bytes.last()) {
        (Some(&first), Some(&last)) => {
            (first.is_ascii_lowercase() || first.is_ascii_digit())
                && (last.is_ascii_lowercase() || last.is_ascii_digit())
        }
        (None, _) | (_, None) => false,
    };
    if len_ok && charset_ok && edges_ok {
        Ok(ResourceName(smol_str::SmolStr::new(s)))
    } else {
        Err(NameError::ResourceName {
            found: truncate_echo(s),
        })
    }
}

impl TryFrom<String> for ResourceName {
    type Error = NameError;

    /// # Errors
    /// [`NameError::ResourceName`] when the value is empty, longer than 253 bytes, contains
    /// a byte outside `[a-z0-9.-]`, or starts or ends with `-` or `.`.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        parse_resource_name(&value)
    }
}

impl TryFrom<&str> for ResourceName {
    type Error = NameError;

    /// # Errors
    /// Same rejections as the `String` form.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_resource_name(value)
    }
}

impl From<ResourceName> for String {
    fn from(value: ResourceName) -> Self {
        value.0.as_str().to_owned()
    }
}

/// A namespace: 1 to 63 bytes matching `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`.
///
/// Absence of a namespace is the root namespace and is NOT the same as the namespace
/// literally named `default`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
#[schemars(
    with = "String",
    extend("pattern" = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", "maxLength" = 63)
)]
pub struct Namespace(smol_str::SmolStr);

impl Namespace {
    /// The namespace as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn parse_namespace(s: &str) -> Result<Namespace, NameError> {
    let bytes = s.as_bytes();
    let len_ok = !bytes.is_empty() && bytes.len() <= NAMESPACE_MAX_BYTES;
    let charset_ok = bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let edges_ok = match (bytes.first(), bytes.last()) {
        (Some(&first), Some(&last)) => {
            (first.is_ascii_lowercase() || first.is_ascii_digit())
                && (last.is_ascii_lowercase() || last.is_ascii_digit())
        }
        (None, _) | (_, None) => false,
    };
    if len_ok && charset_ok && edges_ok {
        Ok(Namespace(smol_str::SmolStr::new(s)))
    } else {
        Err(NameError::Namespace {
            found: truncate_echo(s),
        })
    }
}

impl TryFrom<String> for Namespace {
    type Error = NameError;

    /// # Errors
    /// [`NameError::Namespace`] when the value is empty, longer than 63 bytes, contains a
    /// byte outside `[a-z0-9-]`, or starts or ends with `-`.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        parse_namespace(&value)
    }
}

impl TryFrom<&str> for Namespace {
    type Error = NameError;

    /// # Errors
    /// Same rejections as the `String` form.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_namespace(value)
    }
}

impl From<Namespace> for String {
    fn from(value: Namespace) -> Self {
        value.0.as_str().to_owned()
    }
}

/// A provider name: 1 to 32 bytes matching `[a-z][a-z0-9-]{0,31}`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String", extend("pattern" = "^[a-z][a-z0-9-]*$", "maxLength" = 32))]
pub struct ProviderName(smol_str::SmolStr);

impl ProviderName {
    /// The provider name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The built-in `file` provider name.
    #[must_use]
    pub fn file() -> ProviderName {
        ProviderName(smol_str::SmolStr::new("file"))
    }

    /// The built-in `api` provider name.
    #[must_use]
    pub fn api() -> ProviderName {
        ProviderName(smol_str::SmolStr::new("api"))
    }
}

fn parse_provider_name(s: &str) -> Result<ProviderName, NameError> {
    let bytes = s.as_bytes();
    let len_ok = !bytes.is_empty() && bytes.len() <= PROVIDER_MAX_BYTES;
    let first_ok = bytes.first().is_some_and(u8::is_ascii_lowercase);
    let rest_ok = bytes.get(1..).is_some_and(|rest| {
        rest.iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if len_ok && first_ok && rest_ok {
        Ok(ProviderName(smol_str::SmolStr::new(s)))
    } else {
        Err(NameError::Provider {
            found: truncate_echo(s),
        })
    }
}

impl TryFrom<String> for ProviderName {
    type Error = NameError;

    /// # Errors
    /// [`NameError::Provider`] when the value is empty, longer than 32 bytes, does not
    /// start with a lowercase letter, or contains a byte outside `[a-z0-9-]` after the
    /// first.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        parse_provider_name(&value)
    }
}

impl TryFrom<&str> for ProviderName {
    type Error = NameError;

    /// # Errors
    /// Same rejections as the `String` form.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_provider_name(value)
    }
}

impl From<ProviderName> for String {
    fn from(value: ProviderName) -> Self {
        value.0.as_str().to_owned()
    }
}

/// Why a wildcard hostname's shape was rejected: the leading `*` was not followed by
/// `.` and at least two labels. Used both for a bare `*` (no dot follows at all) and
/// for `*.com` (a dot follows, but only one label remains), because both fail the
/// identical requirement.
const WILDCARD_SHAPE_WHY: &str = "a wildcard must be followed by '.' and at least two labels";
/// Why a label's own shape was rejected: illegal byte, empty, too long, or a leading
/// or trailing hyphen.
const LABEL_SHAPE_WHY: &str =
    "each label must be 1 to 63 bytes of [a-z0-9-], not starting or ending with '-'";
/// Why a hostname was rejected for having more than [`MAX_HOST_LABELS`] labels.
const TOO_MANY_LABELS_WHY: &str = "at most 16 labels are allowed";
/// Why a hostname whose last label is all digits was rejected.
const IP_LAST_LABEL_WHY: &str =
    "the last label must not be all digits; an IP address is not a valid hostname";
/// Why a hostname of the wrong total length was rejected.
const LENGTH_WHY: &str = "a hostname must be 1 to 253 bytes";

/// A Gateway API hostname, optionally prefixed with exactly one `*.` wildcard label.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String", extend("maxLength" = 253))]
pub struct Hostname(smol_str::SmolStr);

impl Hostname {
    /// The hostname as written, including any `*.` prefix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// True when the first label is `*`.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.0.as_str().starts_with("*.")
    }

    /// The text after `*.`, or the whole hostname when it is not a wildcard.
    #[must_use]
    pub fn suffix(&self) -> &str {
        let s = self.0.as_str();
        s.strip_prefix("*.").unwrap_or(s)
    }

    /// Bytes Gateway API counts for host precedence: the length excluding a `*.` prefix.
    #[must_use]
    pub fn specificity_len(&self) -> usize {
        self.suffix().len()
    }
}

/// Rejects a label that is empty, longer than 63 bytes, starts or ends with `-`, or
/// contains a byte outside `[a-z0-9-]`.
fn is_valid_label(label: &[u8]) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    if label.first() == Some(&b'-') || label.last() == Some(&b'-') {
        return false;
    }
    label
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn parse_hostname(s: &str) -> Result<Hostname, NameError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > HOSTNAME_MAX_BYTES {
        return Err(NameError::Hostname {
            found: truncate_echo(s),
            why: LENGTH_WHY,
        });
    }

    let (rest, wildcard) = if bytes.first() == Some(&b'*') {
        if bytes.get(1) == Some(&b'.') {
            (bytes.get(2..).unwrap_or(&[]), true)
        } else {
            return Err(NameError::Hostname {
                found: truncate_echo(s),
                why: WILDCARD_SHAPE_WHY,
            });
        }
    } else {
        (bytes, false)
    };

    if rest.is_empty() {
        return Err(NameError::Hostname {
            found: truncate_echo(s),
            why: WILDCARD_SHAPE_WHY,
        });
    }

    let min_labels = if wildcard { 2 } else { 1 };
    let mut label_count = 0usize;
    let mut last_label: &[u8] = &[];
    for label in rest.split(|&b| b == b'.') {
        label_count += 1;
        if label_count > MAX_HOST_LABELS {
            return Err(NameError::Hostname {
                found: truncate_echo(s),
                why: TOO_MANY_LABELS_WHY,
            });
        }
        if !is_valid_label(label) {
            return Err(NameError::Hostname {
                found: truncate_echo(s),
                why: LABEL_SHAPE_WHY,
            });
        }
        last_label = label;
    }
    if label_count < min_labels {
        return Err(NameError::Hostname {
            found: truncate_echo(s),
            why: WILDCARD_SHAPE_WHY,
        });
    }
    if last_label.iter().all(u8::is_ascii_digit) {
        return Err(NameError::Hostname {
            found: truncate_echo(s),
            why: IP_LAST_LABEL_WHY,
        });
    }

    Ok(Hostname(smol_str::SmolStr::new(s)))
}

impl TryFrom<String> for Hostname {
    type Error = NameError;

    /// # Errors
    /// [`NameError::Hostname`] when the value is not a lowercase RFC 1123 subdomain of
    /// at most 253 bytes, optionally prefixed with exactly one `*.` wildcard label that
    /// leaves at least two labels behind, whose last label is not all digits.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        parse_hostname(&value)
    }
}

impl TryFrom<&str> for Hostname {
    type Error = NameError;

    /// # Errors
    /// Same rejections as the `String` form.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_hostname(value)
    }
}

impl From<Hostname> for String {
    fn from(value: Hostname) -> Self {
        value.0.as_str().to_owned()
    }
}

/// A backend weight in `0..=1_000_000`. Zero is legal and means "receive no traffic
/// while remaining a valid reference".
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "u32", into = "u32")]
#[schemars(with = "u32", extend("maximum" = 1_000_000))]
pub struct Weight(u32);

impl Weight {
    /// The largest legal weight.
    pub const MAX: u32 = 1_000_000;

    /// The value.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for Weight {
    type Error = NameError;

    /// # Errors
    /// [`NameError::Weight`] when `value` is greater than 1,000,000.
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value <= Weight::MAX {
            Ok(Weight(value))
        } else {
            Err(NameError::Weight { found: value })
        }
    }
}

impl From<Weight> for u32 {
    fn from(value: Weight) -> Self {
        value.0
    }
}

/// A reference to another resource: `[namespace/]name[@provider]`.
///
/// An absent namespace means "the referring resource's own namespace", and an absent
/// provider means "the referring resource's own provider": copying a document under a
/// second provider leaves its internal references pointing at its own resources.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
    schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String", extend("maxLength" = 350))]
pub struct ResourceRef {
    namespace: Option<Namespace>,
    name: ResourceName,
    provider: Option<ProviderName>,
}

impl ResourceRef {
    /// Builds a reference from parts.
    #[must_use]
    pub fn new(
        namespace: Option<Namespace>,
        name: ResourceName,
        provider: Option<ProviderName>,
    ) -> ResourceRef {
        ResourceRef {
            namespace,
            name,
            provider,
        }
    }

    /// The explicit namespace, or `None` for "the referring resource's namespace".
    #[must_use]
    pub fn namespace(&self) -> Option<&Namespace> {
        self.namespace.as_ref()
    }

    /// The referenced name.
    #[must_use]
    pub fn name(&self) -> &ResourceName {
        &self.name
    }

    /// The explicit provider, or `None` for "the referring resource's provider".
    #[must_use]
    pub fn provider(&self) -> Option<&ProviderName> {
        self.provider.as_ref()
    }
}

/// Parses `s` as `[namespace/]name[@provider]`.
///
/// The provider is split off at the LAST `@`; the namespace is split off the remainder
/// at the FIRST `/`. A second `@` or a second `/` makes the input ambiguous rather than
/// choosing one of two readings of it, so both are refused outright.
fn parse_resource_ref(s: &str) -> Result<ResourceRef, NameError> {
    if s.is_empty() {
        return Err(NameError::RefEmpty);
    }
    if s.len() > MAX_REF_BYTES {
        return Err(NameError::RefTooLong {
            found: truncate_echo(s),
        });
    }

    if s.matches('@').count() > 1 {
        return Err(NameError::RefMultipleAt {
            found: truncate_echo(s),
        });
    }

    let (remainder, provider) = match s.rfind('@') {
        Some(idx) => {
            let after = s.get(idx.saturating_add(1)..).unwrap_or("");
            if after.is_empty() {
                return Err(NameError::RefProviderEmpty {
                    found: truncate_echo(s),
                });
            }
            let provider = ProviderName::try_from(after)?;
            let before = s.get(..idx).unwrap_or("");
            (before, Some(provider))
        }
        None => (s, None),
    };

    if remainder.matches('/').count() > 1 {
        return Err(NameError::RefMultipleSlash {
            found: truncate_echo(s),
        });
    }

    let (namespace, name_str) = if let Some(idx) = remainder.find('/') {
        let ns_str = remainder.get(..idx).unwrap_or("");
        let name_str = remainder.get(idx.saturating_add(1)..).unwrap_or("");
        if ns_str.is_empty() {
            return Err(NameError::RefNamespaceEmpty {
                found: truncate_echo(s),
            });
        }
        if name_str.is_empty() {
            return Err(NameError::RefNameEmpty {
                found: truncate_echo(s),
            });
        }
        (Some(Namespace::try_from(ns_str)?), name_str)
    } else {
        if remainder.is_empty() {
            return Err(NameError::RefNameEmpty {
                found: truncate_echo(s),
            });
        }
        (None, remainder)
    };

    let name = ResourceName::try_from(name_str)?;
    Ok(ResourceRef {
        namespace,
        name,
        provider,
    })
}

impl TryFrom<String> for ResourceRef {
    type Error = NameError;

    /// # Errors
    /// See the `NameError::Ref*` variants, or a propagated [`NameError::Namespace`],
    /// [`NameError::ResourceName`], or [`NameError::Provider`] from the corresponding
    /// part's own constructor.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        parse_resource_ref(&value)
    }
}

impl TryFrom<&str> for ResourceRef {
    type Error = NameError;

    /// # Errors
    /// Same rejections as the `String` form.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        parse_resource_ref(value)
    }
}

impl core::fmt::Display for ResourceRef {
    /// Renders `[namespace/]name[@provider]`, which parses back to an equal value.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(namespace) = &self.namespace {
            write!(f, "{}/", namespace.as_str())?;
        }
        f.write_str(self.name.as_str())?;
        if let Some(provider) = &self.provider {
            write!(f, "@{}", provider.as_str())?;
        }
        Ok(())
    }
}

impl From<ResourceRef> for String {
    fn from(value: ResourceRef) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;

    use super::{
        Hostname, LENGTH_WHY, MAX_ERROR_ECHO_BYTES, MAX_REF_BYTES, NameError, Namespace,
        ProviderName, ResourceName, ResourceRef, TOO_MANY_LABELS_WHY, Weight,
    };
    use crate::v1::{Extensions, Named};

    // Not one of the 28 tests the issue names, added on top of them. `MAX_REF_BYTES`
    // is used to COMPUTE the boundary values `ref_rejects_ambiguous_forms` checks (a
    // 350-byte reference is built AS `63 + 1 + 253 + 1 + 32`, and 351 as one byte
    // more), so both sides of that comparison move together and a change to the
    // constant would leave every named test green. `MAX_ERROR_ECHO_BYTES` has the
    // same gap for a different reason: it is only the STARTING point for
    // `truncate_echo`'s cut, and `RENDERED_ECHO_BUDGET_BYTES` is a second, stricter
    // cap that papers over a change to it for any input heavy enough to trigger the
    // escaping safety net. This pins both documented values directly.
    #[test]
    fn documented_constants_have_the_documented_values() {
        assert_eq!(MAX_REF_BYTES, 350);
        assert_eq!(MAX_ERROR_ECHO_BYTES, 64);
    }

    #[test]
    fn resource_name_boundaries() {
        assert!(ResourceName::try_from("").is_err());
        assert!(ResourceName::try_from("a").is_ok());
        let two_fifty_three = "a".repeat(253);
        assert!(ResourceName::try_from(two_fifty_three.as_str()).is_ok());
        let two_fifty_four = "a".repeat(254);
        assert!(ResourceName::try_from(two_fifty_four.as_str()).is_err());

        for case in [".a", "a.", "-a", "a-", "A", "a_b"] {
            match ResourceName::try_from(case) {
                Err(NameError::ResourceName { found }) => assert_eq!(found, case),
                other => panic!("expected NameError::ResourceName for {case:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn namespace_boundaries() {
        let sixty_three = "a".repeat(63);
        assert!(Namespace::try_from(sixty_three.as_str()).is_ok());
        let sixty_four = "a".repeat(64);
        assert!(Namespace::try_from(sixty_four.as_str()).is_err());
        assert!(matches!(
            Namespace::try_from("a.b"),
            Err(NameError::Namespace { .. })
        ));

        // Not required by edge case 4 alone, added because mutation testing found that
        // requiring only ONE of the first/last byte to be alphanumeric (an `&&` mutated
        // to `||` in `parse_namespace`'s `edges_ok`) survived every case above: "a.b"
        // fails on charset before edges are ever checked, and neither boundary case
        // has an illegal edge. "-a" and "a-" each have exactly one illegal edge, which
        // pins the requirement that BOTH ends must be alphanumeric.
        for case in ["-a", "a-", "A", "a_b", ""] {
            match Namespace::try_from(case) {
                Err(NameError::Namespace { found }) => assert_eq!(found, case),
                other => panic!("expected NameError::Namespace for {case:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn provider_name_rules() {
        for ok in ["file", "api", "k8s-gw"] {
            assert!(ProviderName::try_from(ok).is_ok(), "{ok} must be accepted");
        }
        let thirty_three = "a".repeat(33);
        for bad in ["1file", "FILE", "", thirty_three.as_str()] {
            assert!(
                ProviderName::try_from(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn provider_builtin_constructors() {
        assert_eq!(ProviderName::file().as_str(), "file");
        assert_eq!(ProviderName::api().as_str(), "api");
    }

    #[test]
    fn hostname_accepts_gateway_api_forms() {
        for ok in [
            "example.com",
            "a.b.example.com",
            "*.example.com",
            "1example.com",
        ] {
            let parsed = Hostname::try_from(ok).expect(ok);
            // Closes a gap mutation testing found: `as_str` was never asserted against
            // the actual accepted text anywhere, only against LENGTHS and derived
            // values (`suffix`, `specificity_len`), so a mutant returning a constant
            // string survived every named test.
            assert_eq!(parsed.as_str(), ok);
        }
        // 253 bytes built from labels of at most 63 bytes each, per the DNS
        // per-label cap: 4 labels of 63 bytes joined by 3 dots is 255 bytes,
        // one over target, so the last label is trimmed by two bytes.
        let mut long_host = String::new();
        for i in 0..3 {
            if i > 0 {
                long_host.push('.');
            }
            long_host.push_str(&"a".repeat(63));
        }
        long_host.push('.');
        long_host.push_str(&"a".repeat(61));
        assert_eq!(long_host.len(), 253);
        assert!(Hostname::try_from(long_host.as_str()).is_ok());
    }

    #[test]
    fn hostname_rejects_illegal_forms() {
        let two_fifty_four = "a".repeat(254);
        let seventeen_labels = vec!["a"; 17].join(".");
        let cases: [&str; 13] = [
            "*",
            "*.com",
            "*example.com",
            "a.*.example.com",
            "**.example.com",
            "EXAMPLE.com",
            "example.com.",
            ".example.com",
            "10.0.0.1",
            "*.10.0.0.1",
            "%2Aexample.com",
            two_fifty_four.as_str(),
            seventeen_labels.as_str(),
        ];
        for case in cases {
            match Hostname::try_from(case) {
                Err(NameError::Hostname { why, .. }) => assert!(!why.is_empty(), "{case}"),
                other => panic!("expected NameError::Hostname for {case:?}, got {other:?}"),
            }
        }
        // Pinned from both sides: a two-label wildcard suffix is fine even
        // though it looks like a public suffix, because the check counts
        // labels rather than consulting a public suffix list.
        assert!(Hostname::try_from("*.co.uk").is_ok());
    }

    // Not one of the 28 tests the issue names, added on top of them. `is_valid_label`
    // rejects a label starting OR ending with '-', two independent conditions joined
    // by `||`. None of the issue's own illegal-hostname cases has a hyphen at either
    // edge of any label, so a mutant that joined them with `&&` instead (rejecting
    // only a label illegal at BOTH ends at once) would survive every case above. This
    // pins each single-sided edge, and the internal-hyphen accepted case alongside it.
    #[test]
    fn hostname_rejects_single_sided_label_hyphens() {
        for case in ["-abc.com", "abc-.com", "abc.-def", "abc.def-"] {
            assert!(Hostname::try_from(case).is_err(), "{case} must be rejected");
        }
        assert!(Hostname::try_from("ab-c.com").is_ok());
    }

    // Not one of the 28 tests the issue names, added on top of them. Mutation testing
    // found that joining the empty check and the length check with `&&` instead of
    // `||` survived every case above: an empty hostname is caught later anyway (as an
    // empty `rest` after wildcard stripping), and every over-length case tested above
    // is ALSO shaped illegally some other way (a 254-byte single label is also over the
    // 63-byte per-label cap; 17 labels is also over the label-count cap), so neither
    // exercises the OVERALL length cap on its own. This builds a hostname that is legal
    // in every other respect and would be accepted if the length cap did not apply.
    #[test]
    fn hostname_length_boundary_is_pinned_independently_of_label_shape() {
        fn labeled_host(total_len: usize) -> String {
            // Labels of 63, 63, 63 and a final label sized to hit `total_len` exactly,
            // joined by three dots, so every label independently satisfies the 63-byte
            // and charset rules regardless of how long the whole hostname is.
            let last_label_len = total_len - (63 * 3 + 3);
            format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "a".repeat(63),
                "a".repeat(63),
                "a".repeat(last_label_len)
            )
        }
        let at_cap = labeled_host(253);
        assert_eq!(at_cap.len(), 253);
        assert!(Hostname::try_from(at_cap.as_str()).is_ok());

        let one_over = labeled_host(254);
        assert_eq!(one_over.len(), 254);
        assert!(matches!(
            Hostname::try_from(one_over.as_str()),
            Err(NameError::Hostname {
                why: LENGTH_WHY,
                ..
            })
        ));
    }

    // Not one of the 28 tests the issue names, added on top of them. Mutation testing
    // found that `label_count > MAX_HOST_LABELS` surviving as `==` or `>=` at 17 labels
    // alone (a linear count monotonically passes through 16 on its way to 17, so every
    // comparison agrees there). Pinned from both sides: exactly `MAX_HOST_LABELS` (16)
    // labels is accepted, one more is rejected.
    #[test]
    fn hostname_label_count_boundary_is_pinned_from_both_sides() {
        let sixteen_labels = vec!["a"; 16].join(".");
        assert!(Hostname::try_from(sixteen_labels.as_str()).is_ok());
        let seventeen_labels = vec!["a"; 17].join(".");
        assert!(matches!(
            Hostname::try_from(seventeen_labels.as_str()),
            Err(NameError::Hostname {
                why: TOO_MANY_LABELS_WHY,
                ..
            })
        ));
    }

    // Not one of the 28 tests the issue names, added on top of them. Closes gaps
    // mutation testing found: `From<Hostname> for String`, `From<Weight> for u32`, and
    // `From<ResourceRef> for String` (each of which only `#[serde(into = "...")]`
    // calls, never `Display` or an accessor) were each replaceable with
    // `Default::default()` and every named test still passed, because none of them
    // actually serialises one of these three types through serde and checks the
    // resulting text.
    #[test]
    fn hostname_weight_and_ref_serialise_through_serde_with_real_content() {
        let hostname = Hostname::try_from("example.com").expect("legal");
        assert_eq!(
            serde_json::to_string(&hostname).expect("serializes"),
            "\"example.com\""
        );

        let weight = Weight::try_from(42u32).expect("legal");
        assert_eq!(serde_json::to_string(&weight).expect("serializes"), "42");

        let reference = ResourceRef::try_from("ns/name@file").expect("legal");
        assert_eq!(
            serde_json::to_string(&reference).expect("serializes"),
            "\"ns/name@file\""
        );
    }

    #[test]
    fn hostname_accessors() {
        let wildcard = Hostname::try_from("*.example.com").expect("legal");
        assert!(wildcard.is_wildcard());
        assert_eq!(wildcard.suffix(), "example.com");
        assert_eq!(wildcard.specificity_len(), 11);

        let exact = Hostname::try_from("example.com").expect("legal");
        assert!(!exact.is_wildcard());
        assert_eq!(exact.suffix(), "example.com");
        assert_eq!(exact.specificity_len(), 11);
    }

    #[test]
    fn weight_boundaries() {
        assert_eq!(Weight::try_from(0u32).expect("0 is legal").get(), 0);
        assert_eq!(
            Weight::try_from(1_000_000u32).expect("legal").get(),
            1_000_000
        );
        assert!(Weight::try_from(1_000_001u32).is_err());
    }

    #[test]
    fn ref_parses_all_four_shapes() {
        let r = ResourceRef::try_from("name").expect("legal");
        assert_eq!(r.namespace(), None);
        assert_eq!(r.name().as_str(), "name");
        assert_eq!(r.provider(), None);

        let r = ResourceRef::try_from("ns/name").expect("legal");
        assert_eq!(r.namespace().map(Namespace::as_str), Some("ns"));
        assert_eq!(r.name().as_str(), "name");
        assert_eq!(r.provider(), None);

        let r = ResourceRef::try_from("name@file").expect("legal");
        assert_eq!(r.namespace(), None);
        assert_eq!(r.name().as_str(), "name");
        assert_eq!(r.provider().map(ProviderName::as_str), Some("file"));

        let r = ResourceRef::try_from("ns/name@file").expect("legal");
        assert_eq!(r.namespace().map(Namespace::as_str), Some("ns"));
        assert_eq!(r.name().as_str(), "name");
        assert_eq!(r.provider().map(ProviderName::as_str), Some("file"));
    }

    #[test]
    fn ref_at_splits_at_last_and_slash_at_first() {
        let r = ResourceRef::try_from("ns/name@file").expect("legal");
        assert_eq!(r.namespace().map(Namespace::as_str), Some("ns"));
        assert_eq!(r.name().as_str(), "name");
        assert_eq!(r.provider().map(ProviderName::as_str), Some("file"));
        assert!(!r.name().as_str().contains('/'));
        assert!(!r.name().as_str().contains('@'));
    }

    #[test]
    fn ref_rejects_ambiguous_forms() {
        let three_fifty_one = {
            let namespace = "a".repeat(63);
            let name = "b".repeat(253);
            let provider = "c".repeat(34);
            format!("{namespace}/{name}@{provider}")
        };
        assert!(three_fifty_one.len() > MAX_REF_BYTES);

        let cases: [(&str, &str); 7] = [
            ("a@b@c", "RefMultipleAt"),
            ("a/b/c", "RefMultipleSlash"),
            ("@file", "RefNameEmpty"),
            ("name@", "RefProviderEmpty"),
            ("/name", "RefNamespaceEmpty"),
            ("", "RefEmpty"),
            (three_fifty_one.as_str(), "RefTooLong"),
        ];
        for (input, expected) in cases {
            let err = ResourceRef::try_from(input).expect_err(input);
            let variant = match err {
                NameError::RefMultipleAt { .. } => "RefMultipleAt",
                NameError::RefMultipleSlash { .. } => "RefMultipleSlash",
                NameError::RefNameEmpty { .. } => "RefNameEmpty",
                NameError::RefProviderEmpty { .. } => "RefProviderEmpty",
                NameError::RefNamespaceEmpty { .. } => "RefNamespaceEmpty",
                NameError::RefEmpty => "RefEmpty",
                NameError::RefTooLong { .. } => "RefTooLong",
                other => panic!("unexpected error for {input:?}: {other:?}"),
            };
            assert_eq!(variant, expected, "input {input:?}");
        }

        // The cap is pinned from both sides: a maximal 350-byte reference
        // (63-byte namespace, 253-byte name, 32-byte provider) is accepted.
        let three_fifty = {
            let namespace = "a".repeat(63);
            let name = "b".repeat(253);
            let provider = "c".repeat(32);
            format!("{namespace}/{name}@{provider}")
        };
        assert_eq!(three_fifty.len(), MAX_REF_BYTES);
        assert!(ResourceRef::try_from(three_fifty.as_str()).is_ok());
    }

    #[test]
    fn ref_propagates_part_errors() {
        assert!(matches!(
            ResourceRef::try_from("name@FILE"),
            Err(NameError::Provider { .. })
        ));
    }

    #[test]
    fn ref_display_round_trips() {
        for shape in ["name", "ns/name", "name@file", "ns/name@file"] {
            let r = ResourceRef::try_from(shape).expect("legal");
            let rendered = r.to_string();
            let parsed = ResourceRef::try_from(rendered.as_str()).expect("round trips");
            assert_eq!(parsed, r);
        }
    }

    #[test]
    fn named_rejects_unknown_field() {
        let json = r#"{"name":"a","spec":{},"nmespace":"x"}"#;
        let err =
            serde_json::from_str::<Named<Extensions>>(json).expect_err("unknown field rejected");
        assert!(err.to_string().contains("nmespace"), "{err}");
    }

    #[test]
    fn named_namespace_is_optional_and_skipped_when_absent() {
        let named = Named {
            name: ResourceName::try_from("a").expect("legal"),
            namespace: None,
            spec: Extensions::default(),
        };
        let json = serde_json::to_string(&named).expect("serializes");
        assert!(!json.contains("namespace"), "{json}");
    }

    #[test]
    fn extensions_serialise_in_key_order() {
        let mut map = BTreeMap::new();
        map.insert("z".to_owned(), serde_json::Value::Bool(true));
        map.insert("a".to_owned(), serde_json::Value::Bool(false));
        let extensions = Extensions::try_from(map).expect("within every cap");
        let json = serde_json::to_string(&extensions).expect("serializes");
        let a_pos = json.find("\"a\"").expect("a present");
        let z_pos = json.find("\"z\"").expect("z present");
        assert!(a_pos < z_pos, "{json}");
    }

    #[test]
    fn named_rejects_duplicate_struct_field() {
        let json = r#"{"name":"a","name":"b","spec":{}}"#;
        let err =
            serde_json::from_str::<Named<Extensions>>(json).expect_err("duplicate field rejected");
        assert!(err.to_string().contains("duplicate field"), "{err}");
    }

    #[test]
    fn extensions_key_count_boundary() {
        let mut ok_map = BTreeMap::new();
        for i in 0..64 {
            ok_map.insert(format!("k{i:02}"), serde_json::Value::Bool(true));
        }
        assert!(Extensions::try_from(ok_map).is_ok());

        let mut too_many = BTreeMap::new();
        for i in 0..65 {
            too_many.insert(format!("k{i:02}"), serde_json::Value::Bool(true));
        }
        assert!(matches!(
            Extensions::try_from(too_many),
            Err(NameError::ExtensionsTooManyKeys { found: 65 })
        ));
    }

    #[test]
    fn extensions_key_length_boundary() {
        let mut ok_map = BTreeMap::new();
        ok_map.insert("k".repeat(128), serde_json::Value::Bool(true));
        assert!(Extensions::try_from(ok_map).is_ok());

        let mut too_long = BTreeMap::new();
        too_long.insert("k".repeat(129), serde_json::Value::Bool(true));
        assert!(matches!(
            Extensions::try_from(too_long),
            Err(NameError::ExtensionsKeyTooLong { .. })
        ));
    }

    #[test]
    fn extensions_encoded_size_cap() {
        let mut too_large = BTreeMap::new();
        too_large.insert("k".to_owned(), serde_json::Value::String("x".repeat(8192)));
        assert!(matches!(
            Extensions::try_from(too_large),
            Err(NameError::ExtensionsTooLarge { .. })
        ));

        // `{"k":"...4090 x's..."}` encodes to exactly 4096 bytes:
        // 7 bytes of fixed JSON punctuation (`{"k":""}`) plus the value.
        let mut exactly_at_cap = BTreeMap::new();
        let fixed_overhead = serde_json::to_vec(&{
            let mut m = BTreeMap::new();
            m.insert("k".to_owned(), serde_json::Value::String(String::new()));
            m
        })
        .expect("serializes")
        .len();
        let filler = 4096 - fixed_overhead;
        exactly_at_cap.insert(
            "k".to_owned(),
            serde_json::Value::String("x".repeat(filler)),
        );
        let encoded_len = serde_json::to_vec(&exactly_at_cap)
            .expect("serializes")
            .len();
        assert_eq!(encoded_len, 4096);
        assert!(Extensions::try_from(exactly_at_cap).is_ok());
    }

    #[allow(
        clippy::mem_forget,
        reason = "this fixture is a value nested 4096 levels deep, built solely to prove \
                  the depth check never recurses. serde_json::Value's ordinary Drop glue \
                  recurses once per nesting level, so letting this fixture drop normally \
                  would itself overflow this test's deliberately small 256 KiB stack: an \
                  artifact of the foreign type's own Drop, not of Extensions::try_from's \
                  depth check. Forgetting it is safe because this is a short-lived test \
                  process and the fixture is not retained across test runs."
    )]
    #[test]
    fn extensions_depth_cap_without_stack_overflow() {
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                // Alternates Array and Object wrapping at every level, rather than
                // nesting only arrays, so this one fixture exercises the depth walk's
                // and the teardown's Object arm just as thoroughly as its Array arm.
                let mut value = serde_json::Value::Null;
                for i in 0..4096 {
                    value = if i % 2 == 0 {
                        serde_json::Value::Array(vec![value])
                    } else {
                        let mut map = serde_json::Map::new();
                        map.insert("x".to_owned(), value);
                        serde_json::Value::Object(map)
                    };
                }
                let mut map = BTreeMap::new();
                map.insert("deep".to_owned(), value);
                let result = Extensions::try_from(map);
                assert!(
                    matches!(result, Err(NameError::ExtensionsTooDeep { .. })),
                    "{result:?}"
                );
                if let Ok(extensions) = result {
                    std::mem::forget(extensions);
                }
            })
            .expect("spawning the bounded-stack thread must succeed");
        handle
            .join()
            .expect("the bounded-stack thread must not panic");
    }

    // Not one of the 28 tests the issue names, added on top of them. Mutation testing
    // found that replacing `exceeds_depth`'s `depth > max_depth` with `==` or `>=`
    // survived: a purely linear chain increases depth by exactly one per level, so it
    // always passes through `max_depth` on its way to any deeper value, and every
    // comparison agrees at that point. This pins the boundary from both sides instead:
    // a value nested exactly `MAX_EXTENSION_DEPTH` levels deep is accepted, and one
    // level deeper is rejected.
    #[test]
    fn extensions_depth_boundary_is_pinned_from_both_sides() {
        fn nest(levels: usize) -> serde_json::Value {
            let mut value = serde_json::Value::Bool(true);
            for _ in 0..levels {
                value = serde_json::Value::Array(vec![value]);
            }
            value
        }

        let mut at_cap = BTreeMap::new();
        at_cap.insert("k".to_owned(), nest(8));
        assert!(Extensions::try_from(at_cap).is_ok());

        let mut one_over = BTreeMap::new();
        one_over.insert("k".to_owned(), nest(9));
        assert!(matches!(
            Extensions::try_from(one_over),
            Err(NameError::ExtensionsTooDeep { .. })
        ));
    }

    // Not one of the 28 tests the issue names, added on top of them. Closes gaps
    // mutation testing found: replacing `Extensions::len`'s body with a constant, or
    // `is_empty`'s with a fixed `true`/`false`, survived every named test, because none
    // of them calls either accessor directly.
    #[test]
    fn extensions_len_and_is_empty() {
        assert_eq!(Extensions::default().len(), 0);
        assert!(Extensions::default().is_empty());

        let mut map = BTreeMap::new();
        map.insert("a".to_owned(), serde_json::Value::Bool(true));
        map.insert("b".to_owned(), serde_json::Value::Bool(false));
        let extensions = Extensions::try_from(map).expect("within every cap");
        assert_eq!(extensions.len(), 2);
        assert!(!extensions.is_empty());
        assert_eq!(extensions.as_map().len(), 2);
    }

    #[test]
    fn error_echo_is_truncated() {
        let huge_name = "a".repeat(4 * 1024 * 1024);
        let err = ResourceName::try_from(huge_name.as_str()).expect_err("too long");
        assert!(err.to_string().len() < 256, "{}", err.to_string().len());

        let huge_ref = "a".repeat(4 * 1024 * 1024);
        let err = ResourceRef::try_from(huge_ref.as_str()).expect_err("too long");
        assert!(err.to_string().len() < 256, "{}", err.to_string().len());
    }

    #[test]
    fn error_echo_escapes_control_bytes() {
        let hostile = "a\r\nERROR: admin login succeeded\t\x1b[31m";
        let err = ResourceName::try_from(hostile).expect_err("illegal bytes");
        let rendered = err.to_string();
        assert!(!rendered.contains('\n'), "{rendered}");
        assert!(!rendered.contains('\r'), "{rendered}");
        assert!(!rendered.contains('\x1b'), "{rendered}");
    }

    // Not one of the 28 tests the issue names, added on top of them. Mutation testing
    // found that every named test's input is pure ASCII, so `floor_to_char_boundary`'s
    // backward search is never actually exercised: a boundary-seeking loop that instead
    // walked FORWARD, or that never moved at all, passed every one of them. This test
    // places a 3-byte character exactly where `MAX_ERROR_ECHO_BYTES` (64) would cut
    // through its middle, so the helper must step back to land on its start.
    #[test]
    fn floor_to_char_boundary_steps_back_from_a_non_boundary() {
        let mut s = "a".repeat(63);
        s.push('\u{4e2d}'); // 3 UTF-8 bytes, occupying offsets 63, 64 and 65.
        assert_eq!(s.len(), 66);
        assert!(!s.is_char_boundary(64));
        assert_eq!(super::floor_to_char_boundary(&s, 64), 63);
        // Already-boundary inputs are returned unchanged, which the search-forward or
        // never-moves mutants above would also get right by accident; asserted here so
        // a mutant that always returns 0 (or always returns the input as-is regardless
        // of validity) cannot hide behind this case alone.
        assert_eq!(super::floor_to_char_boundary(&s, 63), 63);
        assert_eq!(super::floor_to_char_boundary(&s, 0), 0);
    }

    // Not one of the 28 tests the issue names, added on top of them. Exercises the same
    // gap end to end through `truncate_echo`: the input is exactly `MAX_ERROR_ECHO_BYTES
    // + 2` bytes long with the multi-byte character straddling the cut point, so a
    // mutant that lands on byte 64 anyway (rather than backing off to 63) would call
    // `s.get(..64)`, which returns `None` on a non-boundary index and silently produces
    // an EMPTY truncated string instead of the 63-byte prefix. Pinning the exact
    // content, not just its length, is what catches that.
    #[test]
    fn truncate_echo_lands_on_a_char_boundary_and_marks_truncation() {
        let mut s = "a".repeat(63);
        s.push('\u{4e2d}');
        assert_eq!(s.len(), 66);
        let truncated = super::truncate_echo(&s);
        assert_eq!(truncated, format!("{}...", "a".repeat(63)));
    }

    /// An arbitrary Unicode string of up to `max_chars` characters, sampled uniformly
    /// over every `char`, including control characters, NUL, and newlines: a true
    /// "arbitrary String", not one narrowed to printable text.
    fn arb_string(max_chars: usize) -> impl Strategy<Value = String> {
        prop::collection::vec(any::<char>(), 0..max_chars).prop_map(|cs| cs.into_iter().collect())
    }

    /// A curated alphabet biased toward the bytes that actually stress
    /// `ResourceRef::try_from`'s parser: the two separators it splits on, a NUL and a
    /// newline (the adversarial cases the issue names by name), plus enough ordinary
    /// and illegal identifier characters that most draws still exercise every part
    /// constructor rather than only the top-level ambiguity checks.
    const REF_FUZZ_ALPHABET: [char; 15] = [
        'a', 'b', '0', '9', '.', '-', '@', '/', '\0', '\n', '\r', '\t', 'A', '*', '\u{e9}',
    ];

    fn arb_adversarial_ref_string() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(REF_FUZZ_ALPHABET.to_vec()), 0..400)
            .prop_map(|cs| cs.into_iter().collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn prop_name_round_trip(
            name in "[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?",
            namespace in "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
            provider in "[a-z][a-z0-9-]{0,31}",
        ) {
            let parsed = ResourceName::try_from(name.as_str())
                .expect("the regex only generates legal resource names");
            let json = serde_json::to_string(&parsed).expect("serializes");
            let restored: ResourceName = serde_json::from_str(&json).expect("deserializes");
            prop_assert_eq!(&restored, &parsed);
            let via_str = ResourceName::try_from(parsed.as_str().to_owned())
                .expect("its own rendered form always parses");
            prop_assert_eq!(via_str, parsed);

            let parsed = Namespace::try_from(namespace.as_str())
                .expect("the regex only generates legal namespaces");
            let json = serde_json::to_string(&parsed).expect("serializes");
            let restored: Namespace = serde_json::from_str(&json).expect("deserializes");
            prop_assert_eq!(&restored, &parsed);
            let via_str = Namespace::try_from(parsed.as_str().to_owned())
                .expect("its own rendered form always parses");
            prop_assert_eq!(via_str, parsed);

            let parsed = ProviderName::try_from(provider.as_str())
                .expect("the regex only generates legal provider names");
            let json = serde_json::to_string(&parsed).expect("serializes");
            let restored: ProviderName = serde_json::from_str(&json).expect("deserializes");
            prop_assert_eq!(&restored, &parsed);
            let via_str = ProviderName::try_from(parsed.as_str().to_owned())
                .expect("its own rendered form always parses");
            prop_assert_eq!(via_str, parsed);
        }

        #[test]
        fn prop_ref_round_trip(
            namespace in proptest::option::of("[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?"),
            name in "[a-z0-9]([a-z0-9.-]{0,10}[a-z0-9])?",
            provider in proptest::option::of("[a-z][a-z0-9-]{0,10}"),
        ) {
            let namespace = namespace.map(|s| Namespace::try_from(s.as_str()).expect("legal"));
            let name = ResourceName::try_from(name.as_str()).expect("legal");
            let provider = provider.map(|s| ProviderName::try_from(s.as_str()).expect("legal"));
            let r = ResourceRef::new(namespace, name, provider);
            let rendered = r.to_string();
            let restored = ResourceRef::try_from(rendered.as_str()).expect("round trips");
            prop_assert_eq!(restored, r);
        }

        #[test]
        fn prop_hostname_never_panics(s in arb_string(300)) {
            let result = Hostname::try_from(s.as_str());
            if let Ok(hostname) = result {
                prop_assert!(hostname.as_str().len() <= 253);
                prop_assert!(!hostname.as_str().contains(char::is_uppercase));
            }
        }

        #[test]
        fn prop_ref_never_panics(s in arb_adversarial_ref_string()) {
            let result = ResourceRef::try_from(s.as_str());
            if let Err(err) = result {
                prop_assert!(err.to_string().len() < 256);
            }
            // `try_from` never panics: proptest itself fails this test on a panic. The
            // "never slices at a non-character boundary" half is structural, not just
            // observed: every split point comes from `find`/`rfind` on `'@'` or `'/'`,
            // both single ASCII bytes whose byte offset is always a char boundary, and
            // every substring is taken with `str::get`, which returns `None` instead
            // of panicking for a bad range rather than slicing unchecked.
        }

        #[test]
        fn prop_error_echo_bounded(
            s in arb_string(300),
            weight in any::<u32>(),
        ) {
            let mut rendered_errors: Vec<String> = Vec::new();
            if let Err(e) = ResourceName::try_from(s.as_str()) { rendered_errors.push(e.to_string()); }
            if let Err(e) = Namespace::try_from(s.as_str()) { rendered_errors.push(e.to_string()); }
            if let Err(e) = ProviderName::try_from(s.as_str()) { rendered_errors.push(e.to_string()); }
            if let Err(e) = Hostname::try_from(s.as_str()) { rendered_errors.push(e.to_string()); }
            if let Err(e) = Weight::try_from(weight) { rendered_errors.push(e.to_string()); }
            if let Err(e) = ResourceRef::try_from(s.as_str()) { rendered_errors.push(e.to_string()); }
            for rendered in rendered_errors {
                prop_assert!(rendered.len() < 256, "{rendered}");
                prop_assert!(!rendered.bytes().any(|b| b < 0x20 || b == 0x7f), "{rendered}");
            }
        }
    }
}
