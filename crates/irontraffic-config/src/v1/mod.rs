// SPDX-License-Identifier: MIT OR Apache-2.0

//! Layer 1, version `irontraffic.io/v1`: the dynamic configuration document.
//!
//! Names are namespaced by provider. A reference is `[namespace/]name[@provider]`,
//! and an absent namespace or provider means "the referring resource's own".
//!
//! This module carries only the identifier vocabulary and the machinery that
//! attaches identity to a body: [`names`] (`ResourceName`, `Namespace`,
//! `ProviderName`, `Hostname`, `Weight`, `ResourceRef`), [`Named`], and
//! [`Extensions`], the single documented extension point. No resource body and
//! no document envelope live here; they depend on these types and land in a
//! later milestone.

pub mod names;

pub use names::{
    Hostname, MAX_ERROR_ECHO_BYTES, MAX_REF_BYTES, NameError, Namespace, ProviderName,
    ResourceName, ResourceRef, Weight,
};

/// The only `apiVersion` a dynamic configuration document may carry.
///
/// Deliberately the same literal as [`crate::API_VERSION`]: one product version, two
/// document shapes. The constant is re-declared here rather than aliased so that a
/// future `v2` module can carry its own value without touching this one.
pub const DYNAMIC_API_VERSION: &str = "irontraffic.io/v1";

/// Maximum entries in one [`Extensions`] map.
pub const MAX_EXTENSION_KEYS: usize = 64;
/// Maximum bytes of one [`Extensions`] key.
pub const MAX_EXTENSION_KEY_BYTES: usize = 128;
/// Maximum bytes of the canonical JSON encoding of one [`Extensions`] map.
pub const MAX_EXTENSIONS_BYTES: usize = 4096;
/// Maximum object/array nesting depth inside one [`Extensions`] value.
pub const MAX_EXTENSION_DEPTH: usize = 8;

/// Identity plus body. Every dynamic resource in a source document is one of these.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Named<T> {
    /// Resource name, unique per (kind, namespace) within one provider.
    pub name: ResourceName,
    /// Namespace, or absent for the root namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<Namespace>,
    /// The kind-specific body.
    pub spec: T,
}

/// The one open extension point, key-sorted so output bytes are deterministic,
/// and bounded on entry count, key length, encoded size, and nesting depth.
///
/// Nothing in the compiler reads it; it exists so an out-of-tree tool can round-trip
/// its own annotations through our documents. It is a newtype, not a bare type alias,
/// because a bare alias has no place to enforce a bound, and every dynamic resource
/// embeds one: an unbounded map multiplied by a bounded resource count is still an
/// unbounded amount of memory, retained for the life of the bundle.
#[derive(
    Debug, Clone, PartialEq, Default, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(
    try_from = "std::collections::BTreeMap<String, serde_json::Value>",
    into = "std::collections::BTreeMap<String, serde_json::Value>"
)]
pub struct Extensions(std::collections::BTreeMap<String, serde_json::Value>);

impl Extensions {
    /// Read-only view of the entries.
    #[must_use]
    pub fn as_map(&self) -> &std::collections::BTreeMap<String, serde_json::Value> {
        &self.0
    }

    /// Entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One child-value iterator, over either an array's elements or an object's values.
/// Lets [`exceeds_depth`] walk both container kinds through one loop.
enum ChildIter<'a> {
    Array(std::slice::Iter<'a, serde_json::Value>),
    Object(serde_json::map::Values<'a>),
}

impl<'a> Iterator for ChildIter<'a> {
    type Item = &'a serde_json::Value;

    // Mutation testing (`cargo mutants -j 1`) confirms this delegation is load
    // bearing rather than equivalent: a mutant that always returns `Some(..)` (never
    // exhausting the iterator) makes `exceeds_depth`'s and `dismantle`'s backtracking
    // loops spin forever popping and re-visiting the same never-ending sibling
    // iterator. `cargo-mutants` reports that mutant as TIMEOUT, not MISSED, which is
    // the correct classification: it is genuinely detected, just via a hang under
    // its 20 second test timeout rather than a failed assertion.
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ChildIter::Array(it) => it.next(),
            ChildIter::Object(it) => it.next(),
        }
    }
}

/// An iterator over `value`'s direct children, or `None` when `value` is a scalar
/// (nothing to descend into).
fn children_of(value: &serde_json::Value) -> Option<ChildIter<'_>> {
    match value {
        serde_json::Value::Array(items) => Some(ChildIter::Array(items.iter())),
        serde_json::Value::Object(map) => Some(ChildIter::Object(map.values())),
        _ => None,
    }
}

/// True when some value nested inside `value` sits deeper than `max_depth` levels of
/// array/object nesting. The root itself is depth 0.
///
/// Uses an explicit stack of "the sibling iterator at one open ancestor level", never
/// recursion: a recursive walk over attacker-controlled nesting can exhaust the stack
/// before it can report the value as too deep, which turns a rejected document into a
/// process abort instead of a typed error. The stack holds at most one frame per
/// currently open ancestor, so its size is bounded by the walk's own depth, not by how
/// many siblings live at any one level, and the walk stops as soon as depth exceeds
/// `max_depth` rather than visiting the rest of a possibly enormous value.
fn exceeds_depth(value: &serde_json::Value, max_depth: usize) -> bool {
    let mut stack: Vec<ChildIter<'_>> = Vec::new();
    let mut node = value;
    let mut depth = 0usize;
    loop {
        if depth > max_depth {
            return true;
        }
        if let Some(mut children) = children_of(node)
            && let Some(child) = children.next()
        {
            stack.push(children);
            node = child;
            depth = depth.saturating_add(1);
            continue;
        }
        // `node` is a leaf, or a container with no children left to visit. Backtrack
        // to the nearest ancestor that still has an unvisited sibling; every pop
        // reduces `depth` by exactly one, since each stack frame corresponds to
        // exactly one level of ancestry.
        loop {
            match stack.last_mut() {
                None => return false,
                Some(children) => {
                    depth = depth.saturating_sub(1);
                    match children.next() {
                        Some(sibling) => {
                            node = sibling;
                            break;
                        }
                        None => {
                            stack.pop();
                        }
                    }
                }
            }
        }
    }
}

/// Iteratively discards every value in `map` so a maliciously deep JSON value cannot
/// overflow the stack through `serde_json::Value`'s ordinary recursive `Drop` glue,
/// which recurses once per nesting level.
///
/// This runs before a map rejected as too deep is allowed to fall out of scope on any
/// normal path: letting the ordinary `Drop` path run instead is exactly the "process
/// abort" [`exceeds_depth`]'s own recursion-free walk exists to prevent, not just the
/// depth walk itself. Once every remaining value has been proven no deeper than
/// `MAX_EXTENSION_DEPTH` (a handful of levels), the ordinary `Drop` path is trivially
/// safe again, which is why only the too-deep rejection path calls this.
fn dismantle(map: std::collections::BTreeMap<String, serde_json::Value>) {
    let mut stack: Vec<serde_json::Value> = Vec::new();
    stack.extend(map.into_values());
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::Array(items) => stack.extend(items),
            serde_json::Value::Object(map) => stack.extend(map.into_values()),
            _ => {}
        }
    }
}

impl TryFrom<std::collections::BTreeMap<String, serde_json::Value>> for Extensions {
    type Error = NameError;

    /// # Errors
    /// [`NameError::ExtensionsTooManyKeys`] above [`MAX_EXTENSION_KEYS`] entries,
    /// [`NameError::ExtensionsKeyTooLong`] above [`MAX_EXTENSION_KEY_BYTES`] key bytes,
    /// [`NameError::ExtensionsTooLarge`] above [`MAX_EXTENSIONS_BYTES`] encoded bytes,
    /// [`NameError::ExtensionsTooDeep`] above [`MAX_EXTENSION_DEPTH`] nesting levels.
    /// The depth walk uses an explicit worklist and never recurses.
    fn try_from(
        value: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, Self::Error> {
        // Depth first, and before any other check: once this loop completes without
        // finding a violation, every value in `map` is provably no deeper than
        // MAX_EXTENSION_DEPTH, so `map` can be dropped normally (here, by a later
        // rejection branch, or eventually by `Extensions`'s own Drop) without risking
        // the stack overflow a much deeper adversarial value's ordinary Drop glue
        // would cause. See `dismantle`'s own docs for why that risk is real and not
        // merely theoretical.
        let mut too_deep_key: Option<String> = None;
        for (key, val) in &value {
            if exceeds_depth(val, MAX_EXTENSION_DEPTH) {
                too_deep_key = Some(key.clone());
                break;
            }
        }
        if let Some(found) = too_deep_key {
            dismantle(value);
            return Err(NameError::ExtensionsTooDeep {
                found: names::truncate_echo(&found),
            });
        }

        if value.len() > MAX_EXTENSION_KEYS {
            return Err(NameError::ExtensionsTooManyKeys { found: value.len() });
        }

        for key in value.keys() {
            if key.len() > MAX_EXTENSION_KEY_BYTES {
                return Err(NameError::ExtensionsKeyTooLong {
                    found: names::truncate_echo(key),
                });
            }
        }

        let encoded_len = serde_json::to_vec(&value).map_or_else(
            |_serialisation_error| MAX_EXTENSIONS_BYTES.saturating_add(1),
            |bytes| bytes.len(),
        );
        if encoded_len > MAX_EXTENSIONS_BYTES {
            return Err(NameError::ExtensionsTooLarge { found: encoded_len });
        }

        Ok(Extensions(value))
    }
}

impl From<Extensions> for std::collections::BTreeMap<String, serde_json::Value> {
    fn from(value: Extensions) -> Self {
        value.0
    }
}
