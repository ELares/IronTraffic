// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading a bootstrap document off disk and applying the override ladder.
//!
//! The precedence ladder is `CLI flags > environment (IRONTRAFFIC_*) > bootstrap file >
//! built-in defaults`. The layered-configuration crate this workspace's dependency
//! spine originally named is deliberately not used here: its only YAML provider
//! depends on the same abandoned pre-fork crate `serde_norway` replaces (published as
//! `0.9.34+deprecated`), and the M1 override surface is four keys, small enough that
//! an explicit [`Overrides`] struct applied after deserialization is both simpler and
//! more testable, because the environment is injected through the [`EnvSource`] trait
//! rather than read from the process.
//!
//! **Byte-level limits, and why a byte cap alone is not one.** The document is capped
//! at [`MAX_DOC_BYTES`] before parsing. That bounds the input and does not bound the
//! parse, because YAML aliases expand: a document of a few hundred bytes that defines
//! an anchor, aliases it many times inside a second anchor, and repeats that nesting a
//! few levels deep expands to gigabytes during deserialization (the billion-laughs
//! shape). So a second, cheap, lexical bound runs before the YAML parser ever sees the
//! text: at most [`MAX_YAML_ALIASES`] alias tokens (`*`), counted as raw byte
//! occurrences. It is deliberately a byte count rather than a parse of YAML's alias
//! grammar: a guard that has to understand YAML in order to protect the YAML parser is
//! a second parser with the same class of bug. The residual limitation is that this is
//! a token count rather than a measured expansion factor: 64 aliases each expanding a
//! large anchor are still accepted, bounded only by the 1 MiB input cap. The full
//! document budget (a 32 MiB cap, an explicit recursion depth cap, and a measured
//! expansion factor) belongs to the dynamic configuration path in a later milestone.
//! JSON needs no such guard: `serde_json` enforces its own recursion limit (128 by
//! default) and reports a parse error beyond it.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::{BindAddr, BootstrapDoc, ModeSpec, UpstreamAddr};

/// The largest bootstrap document accepted, in bytes.
pub const MAX_DOC_BYTES: u64 = 1_048_576;

/// The largest number of YAML alias tokens (`*`) accepted in one document.
///
/// A byte cap bounds the input; it does not bound YAML alias expansion, which is
/// how a few hundred bytes become gigabytes during deserialization. Counted as raw
/// byte occurrences before the parser runs, because a guard that has to parse YAML
/// to protect the YAML parser has the same class of bug it is guarding against. The
/// bootstrap schema contains names, addresses, integers, and booleans, none of which
/// can legitimately contain `*`, so 64 leaves room for comments and none for a bomb.
pub const MAX_YAML_ALIASES: usize = 64;

const ENV_WORKERS: &str = "IRONTRAFFIC_WORKERS";
const ENV_RUNTIME_MODE: &str = "IRONTRAFFIC_RUNTIME_MODE";
const ENV_BIND: &str = "IRONTRAFFIC_BIND";
const ENV_UPSTREAM: &str = "IRONTRAFFIC_UPSTREAM";

/// Which parser to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `serde_json`.
    Json,
    /// `serde_norway`.
    Yaml,
}

/// Where environment overrides come from, injected so tests do not mutate the process
/// environment.
pub trait EnvSource {
    /// The value of `key`, if set and non-empty.
    fn get(&self, key: &str) -> Option<String>;
}

/// Reads the real process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().and_then(non_empty)
    }
}

/// Treats an empty string as absent. Shared by both [`EnvSource`] implementations
/// so the "an empty value is treated as unset" rule is defined in exactly one
/// place: [`ProcessEnv`] cannot be driven with an empty value in a test without
/// mutating the real process environment (`std::env::set_var` is `unsafe` and
/// this workspace denies `unsafe` everywhere), so the rule lives here, where
/// [`MapEnv`]'s tests exercise it directly.
fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// A fixed map, for tests.
#[derive(Debug, Clone, Default)]
pub struct MapEnv(std::collections::BTreeMap<String, String>);

impl MapEnv {
    /// Builds from key and value pairs.
    #[must_use]
    pub fn new(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        )
    }
}

impl EnvSource for MapEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned().and_then(non_empty)
    }
}

/// Command-line overrides, applied last and therefore winning.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    /// Overrides `runtime.workers`.
    pub workers: Option<usize>,
    /// Overrides the FIRST listener's `bind`. Ignored when there are no listeners.
    pub bind: Option<BindAddr>,
    /// Overrides `upstream.address`.
    pub upstream: Option<UpstreamAddr>,
    /// Overrides `runtime.mode`.
    pub mode: Option<ModeSpec>,
}

/// A loaded document plus where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    /// The document after the precedence ladder was applied.
    pub doc: BootstrapDoc,
    /// The file it was read from.
    pub path: PathBuf,
    /// Which parser was used.
    pub format: Format,
}

impl Loaded {
    /// The resolved document as pretty-printed JSON, for `validate --print`.
    ///
    /// Total: a `BootstrapDoc` is a plain tree of strings, integers, and booleans, so
    /// serialization cannot fail; an impossible failure renders as a one-line JSON
    /// object carrying the error text rather than panicking.
    #[must_use]
    pub fn render_json(&self) -> String {
        serde_json::to_string_pretty(&self.doc)
            .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"))
    }
}

/// A document could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file could not be opened or read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file is larger than [`MAX_DOC_BYTES`].
    #[error("{path} is {bytes} bytes, above the {limit} byte limit")]
    TooLarge {
        /// The file that was too large.
        path: PathBuf,
        /// The size observed, in bytes.
        bytes: u64,
        /// The limit that was exceeded, always [`MAX_DOC_BYTES`].
        limit: u64,
    },
    /// The file is not valid UTF-8.
    #[error("{path} is not valid UTF-8 (first bad byte at offset {valid_up_to})")]
    NotUtf8 {
        /// The file that was not UTF-8.
        path: PathBuf,
        /// The byte offset of the first invalid byte.
        valid_up_to: usize,
    },
    /// The extension is neither json, yaml, nor yml.
    #[error("cannot tell the format of {path}: expected a .json, .yaml, or .yml extension")]
    UnknownFormat {
        /// The file with the unrecognised extension.
        path: PathBuf,
    },
    /// The YAML document contains more alias tokens than [`MAX_YAML_ALIASES`].
    #[error(
        "{path} contains {found} YAML alias tokens, above the limit of {limit}; \
         aliases expand during parsing and a small document can expand without bound"
    )]
    AliasBudget {
        /// The file that exceeded the budget.
        path: PathBuf,
        /// How many alias tokens were found.
        found: usize,
        /// The limit that was exceeded, always [`MAX_YAML_ALIASES`].
        limit: usize,
    },
    /// The parser rejected the document.
    #[error("{path}:{line}:{column}: {message}")]
    Parse {
        /// The file that failed to parse.
        path: PathBuf,
        /// The 1-based line at which parsing failed.
        line: usize,
        /// The 1-based column at which parsing failed.
        column: usize,
        /// The parser's own message.
        message: String,
    },
    /// An environment override could not be parsed.
    #[error("environment variable {key}={value:?} is invalid: {reason}")]
    BadEnv {
        /// The environment variable name.
        key: &'static str,
        /// The value that failed to parse.
        value: String,
        /// Why it failed.
        reason: String,
    },
}

/// Reads at most [`MAX_DOC_BYTES`] plus one byte from `reader`.
///
/// A private helper, factored out of [`load`] so the "plus one" is a single, directly
/// unit-testable piece of arithmetic against an in-memory reader rather than only
/// reachable through the filesystem. It is the second, load-bearing enforcement of
/// [`MAX_DOC_BYTES`] (the first is the metadata check in [`load`]), catching a file
/// that grows between that check and this read.
fn read_bounded(reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    reader.take(MAX_DOC_BYTES + 1).read_to_end(&mut raw)?;
    Ok(raw)
}

/// Reads, parses, and applies overrides in the order
/// `CLI > environment > file > defaults`.
///
/// Reads at most [`MAX_DOC_BYTES`] plus one byte. Performs blocking file I/O: call at
/// startup, never from a runtime thread.
///
/// A YAML document is additionally rejected if it contains more than
/// [`MAX_YAML_ALIASES`] alias tokens, counted on the raw bytes before the parser runs,
/// because a byte cap bounds the input size and not YAML alias expansion. The residual
/// limitation is that this is a token count rather than a measured expansion factor;
/// the full document budget (a 32 MiB cap, an explicit recursion depth cap, and a
/// measured expansion factor) belongs to the dynamic configuration path in a later
/// milestone. JSON needs no such guard: `serde_json` enforces its own recursion limit.
///
/// # Errors
/// [`LoadError`], always naming the path, naming line and column for a parse failure,
/// and naming the count and the limit for an alias-budget failure.
pub fn load(path: &Path, env: &dyn EnvSource, cli: &Overrides) -> Result<Loaded, LoadError> {
    let metadata_result = std::fs::metadata(path); // it-allow: no-blocking-in-async reason: called once at startup before any runtime exists, per this function's own doc comment
    let metadata = metadata_result.map_err(|source| LoadError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > MAX_DOC_BYTES {
        return Err(LoadError::TooLarge {
            path: path.to_path_buf(),
            bytes: metadata.len(),
            limit: MAX_DOC_BYTES,
        });
    }

    let file = std::fs::File::open(path) // it-allow: no-blocking-in-async reason: called once at startup before any runtime exists, per this function's own doc comment
        .map_err(|source| LoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    // The metadata check above can race a file that grows after it runs; this bounded
    // read is the second, load-bearing enforcement of the same cap.
    let raw = read_bounded(file).map_err(|source| LoadError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let read_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
    if read_len > MAX_DOC_BYTES {
        return Err(LoadError::TooLarge {
            path: path.to_path_buf(),
            bytes: read_len,
            limit: MAX_DOC_BYTES,
        });
    }

    let text = String::from_utf8(raw).map_err(|error| LoadError::NotUtf8 {
        path: path.to_path_buf(),
        valid_up_to: error.utf8_error().valid_up_to(),
    })?;

    let format = match path.extension().and_then(OsStr::to_str) {
        Some(ext) if ext.eq_ignore_ascii_case("json") => Format::Json,
        Some(ext) if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") => {
            Format::Yaml
        }
        _ => {
            return Err(LoadError::UnknownFormat {
                path: path.to_path_buf(),
            });
        }
    };

    if format == Format::Yaml {
        // Counted BEFORE the parser runs, on raw bytes, because the point is to never
        // hand an expanding document to the expander. See the module documentation.
        let aliases = text.bytes().filter(|byte| *byte == b'*').count();
        if aliases > MAX_YAML_ALIASES {
            return Err(LoadError::AliasBudget {
                path: path.to_path_buf(),
                found: aliases,
                limit: MAX_YAML_ALIASES,
            });
        }
    }

    let mut doc: BootstrapDoc = match format {
        Format::Json => serde_json::from_str(&text).map_err(|error| LoadError::Parse {
            path: path.to_path_buf(),
            line: error.line(),
            column: error.column(),
            message: error.to_string(),
        })?,
        Format::Yaml => serde_norway::from_str(&text).map_err(|error| LoadError::Parse {
            path: path.to_path_buf(),
            line: error.location().map_or(0, |location| location.line()),
            column: error.location().map_or(0, |location| location.column()),
            message: error.to_string(),
        })?,
    };

    let env_overrides = read_env_overrides(env)?;
    apply_overrides(&mut doc, &env_overrides);
    apply_overrides(&mut doc, cli);

    Ok(Loaded {
        doc,
        path: path.to_path_buf(),
        format,
    })
}

/// Reads the four documented `IRONTRAFFIC_*` keys, each becoming a [`LoadError::BadEnv`]
/// on a parse failure.
fn read_env_overrides(env: &dyn EnvSource) -> Result<Overrides, LoadError> {
    let mut overrides = Overrides::default();

    if let Some(value) = env.get(ENV_WORKERS) {
        let workers = value.parse::<usize>().map_err(|error| LoadError::BadEnv {
            key: ENV_WORKERS,
            value: value.clone(),
            reason: error.to_string(),
        })?;
        overrides.workers = Some(workers);
    }

    if let Some(value) = env.get(ENV_RUNTIME_MODE) {
        let mode = match value.as_str() {
            "balanced" => ModeSpec::Balanced,
            "shard" => ModeSpec::Shard,
            _ => {
                return Err(LoadError::BadEnv {
                    key: ENV_RUNTIME_MODE,
                    value: value.clone(),
                    reason: "expected \"balanced\" or \"shard\"".to_owned(),
                });
            }
        };
        overrides.mode = Some(mode);
    }

    if let Some(value) = env.get(ENV_BIND) {
        let bind = BindAddr::try_from(value.as_str()).map_err(|error| LoadError::BadEnv {
            key: ENV_BIND,
            value: value.clone(),
            reason: error.to_string(),
        })?;
        overrides.bind = Some(bind);
    }

    if let Some(value) = env.get(ENV_UPSTREAM) {
        let upstream =
            UpstreamAddr::try_from(value.as_str()).map_err(|error| LoadError::BadEnv {
                key: ENV_UPSTREAM,
                value: value.clone(),
                reason: error.to_string(),
            })?;
        overrides.upstream = Some(upstream);
    }

    Ok(overrides)
}

/// Applies `overrides` onto `doc`. A `None` field leaves the current value unchanged.
///
/// Overriding the first listener's `bind` when there are no listeners applies to
/// nothing and records nothing: [`crate::validate::validate`] then reports its
/// `no_listeners` error, which is the right message for an operator to see.
fn apply_overrides(doc: &mut BootstrapDoc, overrides: &Overrides) {
    if let Some(workers) = overrides.workers {
        doc.runtime.workers = Some(workers);
    }
    if let Some(mode) = overrides.mode {
        doc.runtime.mode = mode;
    }
    if let Some(bind) = overrides.bind
        && let Some(first) = doc.listeners.first_mut()
    {
        first.bind = bind;
    }
    if let Some(upstream) = overrides.upstream {
        doc.upstream.address = upstream;
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        EnvSource, LoadError, MAX_DOC_BYTES, MAX_YAML_ALIASES, MapEnv, Overrides, ProcessEnv, load,
        read_bounded,
    };

    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct FixtureGuard(PathBuf);

    impl Drop for FixtureGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0); // it-allow: no-swallowed-error reason: best-effort test fixture cleanup; a leftover temp directory does not affect any assertion.
        }
    }

    fn write_fixture(name: &str, filename: &str, bytes: &[u8]) -> (PathBuf, FixtureGuard) {
        let pid = std::process::id();
        let counter = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("irontraffic-config-{name}-{pid}-{counter}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(filename);
        std::fs::write(&path, bytes).unwrap();
        (path, FixtureGuard(dir))
    }

    const MINIMAL_JSON: &str = r#"{"apiVersion":"irontraffic.io/v1",
        "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
        "upstream":{"address":"127.0.0.1:9000"}}"#;

    #[test]
    fn load_json_and_yaml_produce_equal_documents() {
        let yaml = "apiVersion: irontraffic.io/v1\n\
                    listeners:\n\
                    \x20\x20- name: web\n\
                    \x20\x20\x20\x20bind: \"127.0.0.1:0\"\n\
                    upstream:\n\
                    \x20\x20address: \"127.0.0.1:9000\"\n";
        let (json_path, _guard1) = write_fixture("json-yaml", "doc.json", MINIMAL_JSON.as_bytes());
        let (yaml_path, _guard2) = write_fixture("json-yaml", "doc.yaml", yaml.as_bytes());
        let env = MapEnv::default();
        let cli = Overrides::default();
        let from_json = load(&json_path, &env, &cli).expect("json loads");
        let from_yaml = load(&yaml_path, &env, &cli).expect("yaml loads");
        assert_eq!(from_json.doc, from_yaml.doc);
    }

    #[test]
    fn load_rejects_unknown_extension() {
        let (path, _guard) = write_fixture("unknown-ext", "doc.toml", b"anything");
        let env = MapEnv::default();
        let cli = Overrides::default();
        let err = load(&path, &env, &cli).expect_err("toml is not a supported format");
        assert!(matches!(err, LoadError::UnknownFormat { .. }));
    }

    #[test]
    fn load_rejects_oversized_file() {
        let limit = usize::try_from(MAX_DOC_BYTES).unwrap();
        let bytes = vec![b'a'; limit + 1];
        let (path, _guard) = write_fixture("oversized", "doc.json", &bytes);
        let env = MapEnv::default();
        let cli = Overrides::default();
        let err = load(&path, &env, &cli).expect_err("oversized file is rejected");
        match err {
            LoadError::TooLarge { limit, .. } => assert_eq!(limit, MAX_DOC_BYTES),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_non_utf8() {
        let (path, _guard) = write_fixture("non-utf8", "doc.json", &[0xff, 0xfe]);
        let env = MapEnv::default();
        let cli = Overrides::default();
        let err = load(&path, &env, &cli).expect_err("non utf8 is rejected");
        match err {
            LoadError::NotUtf8 { valid_up_to, .. } => assert_eq!(valid_up_to, 0),
            other => panic!("expected NotUtf8, got {other:?}"),
        }
    }

    #[test]
    fn load_parse_error_carries_line_and_column() {
        let (path, _guard) = write_fixture("parse-error", "doc.json", b"{\"apiVersion\":");
        let env = MapEnv::default();
        let cli = Overrides::default();
        let err = load(&path, &env, &cli).expect_err("truncated json fails to parse");
        match err {
            LoadError::Parse { line, message, .. } => {
                assert!(line >= 1);
                assert!(!message.is_empty());
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn env_overrides_file() {
        let json = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "runtime":{"workers":4}}"#;
        let (path, _guard) = write_fixture("env-override", "doc.json", json.as_bytes());
        let env = MapEnv::new(&[("IRONTRAFFIC_WORKERS", "8")]);
        let cli = Overrides::default();
        let loaded = load(&path, &env, &cli).expect("loads");
        assert_eq!(loaded.doc.runtime.workers, Some(8));
    }

    #[test]
    fn cli_overrides_env_and_file() {
        let json = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "runtime":{"workers":4}}"#;
        let (path, _guard) = write_fixture("cli-override", "doc.json", json.as_bytes());
        let env = MapEnv::new(&[("IRONTRAFFIC_WORKERS", "8")]);
        let cli = Overrides {
            workers: Some(2),
            ..Overrides::default()
        };
        let loaded = load(&path, &env, &cli).expect("loads");
        assert_eq!(loaded.doc.runtime.workers, Some(2));
    }

    #[test]
    fn bad_env_value_is_an_error() {
        let (path, _guard) = write_fixture("bad-env", "doc.json", MINIMAL_JSON.as_bytes());
        let env = MapEnv::new(&[("IRONTRAFFIC_WORKERS", "abc")]);
        let cli = Overrides::default();
        let err = load(&path, &env, &cli).expect_err("bad env value is rejected");
        match err {
            LoadError::BadEnv { key, .. } => assert_eq!(key, "IRONTRAFFIC_WORKERS"),
            other => panic!("expected BadEnv, got {other:?}"),
        }
    }

    #[test]
    fn empty_env_value_is_treated_as_unset() {
        let json = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "runtime":{"workers":4}}"#;
        let (path, _guard) = write_fixture("empty-env", "doc.json", json.as_bytes());
        let env = MapEnv::new(&[("IRONTRAFFIC_WORKERS", "")]);
        let cli = Overrides::default();
        let loaded = load(&path, &env, &cli).expect("loads");
        assert_eq!(loaded.doc.runtime.workers, Some(4));
    }

    #[test]
    fn bind_override_with_no_listeners_is_ignored() {
        let json = r#"{"apiVersion":"irontraffic.io/v1","listeners":[],
            "upstream":{"address":"127.0.0.1:9000"}}"#;
        let (path, _guard) = write_fixture("bind-no-listeners", "doc.json", json.as_bytes());
        let env = MapEnv::new(&[("IRONTRAFFIC_BIND", "0.0.0.0:80")]);
        let cli = Overrides::default();
        let loaded =
            load(&path, &env, &cli).expect("loads even though the override applies to nothing");
        assert!(loaded.doc.listeners.is_empty());
        let diagnostics = crate::validate::validate(&loaded.doc);
        assert!(diagnostics.iter().any(|d| d.code == "no_listeners"));
    }

    #[test]
    fn yaml_alias_bomb_is_rejected_before_parsing() {
        let mut yaml =
            String::from("a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n");
        let mut previous = "a".to_owned();
        for letter in ["b", "c", "d", "e", "f", "g", "h"] {
            let alias = format!("*{previous}");
            let items = vec![alias; 10].join(",");
            writeln!(yaml, "{letter}: &{letter} [{items}]").unwrap();
            previous = letter.to_owned();
        }
        writeln!(yaml, "i: *{previous}").unwrap();

        let (path, _guard) = write_fixture("alias-bomb", "bomb.yaml", yaml.as_bytes());
        let env = MapEnv::default();
        let cli = Overrides::default();

        let start = std::time::Instant::now();
        let err = load(&path, &env, &cli).expect_err("an alias bomb is rejected before parsing");
        let elapsed = start.elapsed();

        match err {
            LoadError::AliasBudget { found, limit, .. } => {
                assert!(found > MAX_YAML_ALIASES);
                assert_eq!(limit, MAX_YAML_ALIASES);
            }
            other => panic!("expected AliasBudget, got {other:?}"),
        }
        // A test that only asserted the error variant would still pass if the guard
        // ran AFTER the parser tried (and failed slowly) to expand the bomb; the
        // timing bound is what proves the guard ran first.
        assert!(elapsed < std::time::Duration::from_millis(100));
    }

    #[test]
    fn yaml_under_the_alias_budget_still_loads() {
        let yaml = "apiVersion: irontraffic.io/v1\n\
                    listeners:\n\
                    \x20\x20- name: web1\n\
                    \x20\x20\x20\x20bind: &addr \"127.0.0.1:0\"\n\
                    \x20\x20- name: web2\n\
                    \x20\x20\x20\x20bind: *addr\n\
                    \x20\x20- name: web3\n\
                    \x20\x20\x20\x20bind: *addr\n\
                    \x20\x20- name: web4\n\
                    \x20\x20\x20\x20bind: *addr\n\
                    upstream:\n\
                    \x20\x20address: \"127.0.0.1:9000\"\n";
        let (path, _guard) = write_fixture("alias-ok", "doc.yaml", yaml.as_bytes());
        let env = MapEnv::default();
        let cli = Overrides::default();
        let loaded = load(&path, &env, &cli).expect("a document under the alias budget loads");
        assert_eq!(loaded.doc.listeners.len(), 4);
    }

    #[test]
    fn json_alias_budget_does_not_apply() {
        let stars = "*".repeat(500);
        let json = format!(
            r#"{{"apiVersion":"{stars}","listeners":[{{"name":"web","bind":"127.0.0.1:0"}}],"upstream":{{"address":"127.0.0.1:9000"}}}}"#
        );
        let (path, _guard) = write_fixture("json-stars", "doc.json", json.as_bytes());
        let env = MapEnv::default();
        let cli = Overrides::default();
        let loaded =
            load(&path, &env, &cli).expect("the yaml-only alias budget does not apply to json");
        assert_eq!(loaded.doc.api_version, stars);
    }

    // Not one of the 13 named loader tests, added on top of them: proves the
    // `EnvSource` trait's own documented contract (empty value treated as unset) on
    // both implementations, not only through a full `load` call.
    #[test]
    fn env_source_implementations_treat_empty_as_unset() {
        assert_eq!(MapEnv::new(&[("K", "")]).get("K"), None);
        assert_eq!(MapEnv::new(&[("K", "v")]).get("K"), Some("v".to_owned()));
        assert_eq!(MapEnv::default().get("MISSING"), None);
    }

    // Not one of the 13 named loader tests. Mutation testing found that the "plus
    // one" in `read_bounded`'s cap was untestable through `load` alone: the file-size
    // race it exists to catch cannot be reproduced deterministically through the
    // filesystem, so both a "limit - 1" and a "limit" (no plus-one at all) mutant
    // survived every filesystem-backed test. This drives the helper directly against
    // an in-memory reader instead.
    #[test]
    fn read_bounded_reads_up_to_the_cap_plus_one() {
        let limit = usize::try_from(MAX_DOC_BYTES).unwrap();

        let exact = vec![b'a'; limit];
        let raw = read_bounded(std::io::Cursor::new(exact)).expect("reads");
        assert_eq!(raw.len(), limit);

        let one_over = vec![b'a'; limit + 1];
        let raw = read_bounded(std::io::Cursor::new(one_over)).expect("reads");
        assert_eq!(raw.len(), limit + 1);

        let two_over = vec![b'a'; limit + 2];
        let raw = read_bounded(std::io::Cursor::new(two_over)).expect("reads");
        // Capped at exactly limit + 1: distinguishes "+ 1" from "+ 0" (a "*" mutant,
        // which would report `limit` here) and from a fixed excess of 2 or more.
        assert_eq!(raw.len(), limit + 1);
    }

    // Not one of the 13 named loader tests. Mutation testing found that
    // `ProcessEnv::get` was never exercised anywhere in this crate's own suite
    // (every `load` test injects `MapEnv` instead), so a version that always
    // returned `None` or a fixed string regardless of the real environment passed
    // every named test. This cannot set an empty value to test the "empty means
    // unset" rule without mutating the real process environment
    // (`std::env::set_var` is `unsafe`, denied everywhere in this workspace); that
    // rule is tested directly against `MapEnv` instead, and `ProcessEnv::get`
    // delegates to the exact same private `non_empty` function, so a mutation to
    // the rule itself is caught there regardless of which `EnvSource` calls it.
    #[test]
    fn process_env_reads_the_real_environment() {
        // PATH is set to a non-empty value in every process that can run this
        // test at all, including under a minimal CI sandbox, so it stands in for
        // an environment variable this test cannot set itself.
        let expected =
            std::env::var("PATH").expect("PATH is set in any process that can run a test binary");
        assert!(!expected.is_empty());
        assert_eq!(ProcessEnv.get("PATH"), Some(expected));
        assert_eq!(
            ProcessEnv.get("IRONTRAFFIC_CONFIG_DEFINITELY_UNSET_TEST_KEY_9f3a"),
            None
        );
    }

    // Not one of the 13 named loader tests. Mutation testing found that
    // `Loaded::render_json` was only ever exercised through the `irontraffic`
    // crate's own integration test (a structural "looks like JSON" check, in a
    // separate test binary this crate's own suite does not run), so within this
    // crate a version that always returned an empty string or a fixed placeholder
    // passed every test.
    #[test]
    fn render_json_reflects_actual_document_content() {
        let (path, _guard) = write_fixture("render-json", "doc.json", MINIMAL_JSON.as_bytes());
        let env = MapEnv::default();
        let cli = Overrides::default();
        let loaded = load(&path, &env, &cli).expect("loads");
        let rendered = loaded.render_json();
        assert!(rendered.contains("127.0.0.1:9000"), "{rendered}");
        assert!(rendered.contains("\"web\""), "{rendered}");
    }

    // Not one of the 13 named loader tests. Mutation testing found that neither
    // enforcement of MAX_DOC_BYTES (the metadata check, or the bounded-read check)
    // was ever exercised exactly AT the limit, so a "> mutated to >=" survived on
    // both: every existing test used a value strictly above the limit, which
    // behaves identically under `>` and `>=`.
    #[test]
    fn load_accepts_a_file_exactly_at_the_byte_cap() {
        let limit = usize::try_from(MAX_DOC_BYTES).unwrap();
        let prefix = r#"{"apiVersion":""#;
        let suffix = r#"","listeners":[{"name":"web","bind":"127.0.0.1:0"}],"upstream":{"address":"127.0.0.1:9000"}}"#;
        let padding_len = limit - prefix.len() - suffix.len();
        let mut json = String::with_capacity(limit);
        json.push_str(prefix);
        for _ in 0..padding_len {
            json.push('a');
        }
        json.push_str(suffix);
        assert_eq!(json.len(), limit);
        let (path, _guard) = write_fixture("exact-cap", "doc.json", json.as_bytes());
        let env = MapEnv::default();
        let cli = Overrides::default();
        let loaded = load(&path, &env, &cli).expect("a file exactly at the byte cap is accepted");
        assert_eq!(loaded.doc.api_version.len(), padding_len);
    }

    // Not one of the 13 named loader tests. Mutation testing found that the alias
    // budget's own boundary (exactly MAX_YAML_ALIASES) was never exercised: the
    // bomb test is far above it and the "still loads" test is far below it, so a
    // "> mutated to >=" survived.
    #[test]
    fn yaml_alias_budget_boundary_is_inclusive() {
        let yaml = format!(
            "# {}\napiVersion: irontraffic.io/v1\nlisteners:\n  - name: web\n    bind: \"127.0.0.1:0\"\nupstream:\n  address: \"127.0.0.1:9000\"\n",
            "*".repeat(MAX_YAML_ALIASES)
        );
        let (path, _guard) = write_fixture("alias-boundary", "doc.yaml", yaml.as_bytes());
        let env = MapEnv::default();
        let cli = Overrides::default();
        let loaded = load(&path, &env, &cli)
            .expect("exactly MAX_YAML_ALIASES asterisks is at, not above, the budget");
        assert_eq!(loaded.doc.listeners.len(), 1);
    }

    // Not one of the 13 named loader tests. Mutation testing found that neither
    // the IRONTRAFFIC_RUNTIME_MODE nor the IRONTRAFFIC_UPSTREAM override path was
    // exercised anywhere (the named tests only cover WORKERS and BIND), so
    // deleting either match arm in `read_env_overrides` passed every named test.
    #[test]
    fn env_overrides_runtime_mode_and_upstream() {
        let (path, _guard) =
            write_fixture("env-mode-upstream", "doc.json", MINIMAL_JSON.as_bytes());
        let cli = Overrides::default();

        let shard_env = MapEnv::new(&[
            ("IRONTRAFFIC_RUNTIME_MODE", "shard"),
            ("IRONTRAFFIC_UPSTREAM", "10.0.0.9:9999"),
        ]);
        let loaded = load(&path, &shard_env, &cli).expect("loads");
        assert_eq!(loaded.doc.runtime.mode, crate::newtypes::ModeSpec::Shard);
        assert_eq!(
            loaded.doc.upstream.address,
            crate::newtypes::UpstreamAddr::try_from("10.0.0.9:9999").expect("legal")
        );

        let balanced_env = MapEnv::new(&[("IRONTRAFFIC_RUNTIME_MODE", "balanced")]);
        let loaded_balanced = load(&path, &balanced_env, &cli).expect("loads");
        assert_eq!(
            loaded_balanced.doc.runtime.mode,
            crate::newtypes::ModeSpec::Balanced
        );
    }
}
