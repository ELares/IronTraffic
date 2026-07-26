// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bootstrap document: M1's process identity configuration.
//!
//! What to listen on, where to forward, how many workers, which deadlines.
//! Every struct here rejects any field it does not recognise: a misspelled
//! security-relevant key is a typed error at deserialization, never a silent
//! no-op. Checking the document's *meaning* (duplicate listener names, an
//! empty listener list, `max_connections == 0`) is the loader issue's
//! validator, not this file; this file only checks *shape*.

use crate::newtypes::{Backlog, BindAddr, ListenerName, Millis, ModeSpec, UpstreamAddr};

/// The bootstrap document. Process identity: what to listen on, where to
/// forward, how many workers, which deadlines.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapDoc {
    /// Must equal [`crate::API_VERSION`]. A mismatch deserializes successfully
    /// here; rejecting the wrong value is the loader's validator, so the error
    /// it raises can name both the found and the supported version.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// At least one listener. Duplicate names and duplicate addresses are
    /// rejected by the validator, not here.
    pub listeners: Vec<ListenerSection>,
    /// The single upstream every connection is forwarded to in this version.
    pub upstream: UpstreamSection,
    /// Runtime shape. Defaults to `balanced` with a cgroup-derived worker count.
    #[serde(default)]
    pub runtime: RuntimeSection,
    /// Deadlines. All defaults are stated in the `DEFAULT_*` constants, except
    /// `timeouts.max_lifetime_ms`, whose default is `None` (unlimited).
    #[serde(default)]
    pub timeouts: TimeoutSection,
    /// Resource caps. `limits.max_connections` bounds live connections and,
    /// through them, peak read-buffer memory and file descriptors.
    #[serde(default)]
    pub limits: LimitSection,
    /// Drain behaviour.
    #[serde(default)]
    pub shutdown: ShutdownSection,
}

/// One listener: where to bind, and how.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerSection {
    /// Unique among the listeners in this document. Duplicate detection is
    /// the validator's job in a later issue.
    pub name: ListenerName,
    /// The address to bind, for example `0.0.0.0:8080` or `[::]:8080`.
    pub bind: BindAddr,
    /// `listen(2)` backlog. Defaults to [`DEFAULT_BACKLOG`].
    #[serde(default = "default_backlog")]
    pub backlog: Backlog,
    /// `SO_REUSEPORT`, one socket per worker. Defaults to `true`.
    #[serde(default = "default_true")]
    pub reuseport: bool,
    /// `IPV6_V6ONLY` on a wildcard `[::]` bind. Defaults to `false`.
    #[serde(default)]
    pub ipv6_only: bool,
}

/// The single upstream every connection is forwarded to in this version.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSection {
    /// The upstream socket address.
    pub address: UpstreamAddr,
}

/// Runtime shape: how the data plane and the control plane are built.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSection {
    /// Data-plane structure. Defaults to [`ModeSpec::Balanced`].
    #[serde(default)]
    pub mode: ModeSpec,
    /// Explicit data-plane worker count. `None` derives it from the cgroup
    /// quota. Clamped to `1..=1024` by the runtime.
    #[serde(default)]
    pub workers: Option<usize>,
    /// Data-plane blocking pool cap. `None` means `min(4, workers)`. Clamped
    /// to `1..=512` by the runtime.
    #[serde(default)]
    pub max_blocking_threads: Option<usize>,
    /// Control-plane worker count. Defaults to [`DEFAULT_CONTROL_WORKERS`].
    /// A value above 1024 is clamped down to 1024 by the runtime. Zero is
    /// not clamped up: the runtime returns
    /// `irontraffic_runtime::RuntimeError::ZeroControlWorkers` instead,
    /// because a control plane with no workers cannot reload configuration,
    /// so the operator is told rather than surprised.
    #[serde(default = "default_control_workers")]
    pub control_workers: usize,
}

impl Default for RuntimeSection {
    fn default() -> Self {
        Self {
            mode: ModeSpec::default(),
            workers: None,
            max_blocking_threads: None,
            control_workers: default_control_workers(),
        }
    }
}

/// Deadlines for a proxied connection.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutSection {
    /// Deadline to establish the upstream connection. Defaults to
    /// [`DEFAULT_CONNECT_MS`].
    #[serde(default = "default_connect_ms")]
    pub connect_ms: Millis,
    /// Deadline for a connection that goes silent (no bytes in either
    /// direction). Defaults to [`DEFAULT_IDLE_MS`].
    #[serde(default = "default_idle_ms")]
    pub idle_ms: Millis,
    /// Deadline after one direction has closed. Defaults to
    /// [`DEFAULT_HALF_CLOSE_MS`].
    #[serde(default = "default_half_close_ms")]
    pub half_close_ms: Millis,
    /// An absolute ceiling on how long one proxied connection may live,
    /// regardless of progress. `idle_ms` does not bound a connection that
    /// keeps making a byte of progress: a client that sends one byte every 59
    /// seconds resets the idle deadline forever and holds its connection
    /// slot, its file descriptors, and its task indefinitely, which at the
    /// default connection cap costs an attacker roughly 170 bytes per second
    /// in total to occupy every slot. This field is the lever that bounds
    /// time instead of silence. Defaults to `None` (unlimited): M1 forwards
    /// arbitrary TCP, so WebSocket and gRPC streams that legitimately run for
    /// hours are the normal case, and any finite default would silently
    /// sever them. The residual risk of leaving it unset is recorded in
    /// `docs/THREAT-MODEL.md`.
    #[serde(default)]
    pub max_lifetime_ms: Option<Millis>,
}

impl Default for TimeoutSection {
    fn default() -> Self {
        Self {
            connect_ms: default_connect_ms(),
            idle_ms: default_idle_ms(),
            half_close_ms: default_half_close_ms(),
            max_lifetime_ms: None,
        }
    }
}

/// Resource caps.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitSection {
    /// Live connection cap. Also bounds peak read-buffer memory
    /// (`2 * max_connections * 32 KiB`) and file descriptors
    /// (`2 * max_connections` plus the listeners). Not a newtype: a future
    /// version may want `0` to mean "derive from `RLIMIT_NOFILE`", so that
    /// meaning is reserved rather than forbidden by construction. `0`
    /// deserializes here and is rejected by the validator in a later issue.
    /// Defaults to [`DEFAULT_MAX_CONNECTIONS`].
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

impl Default for LimitSection {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
        }
    }
}

/// Drain behaviour.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownSection {
    /// Budget for a graceful drain before the process exits regardless.
    /// Defaults to [`DEFAULT_GRACEFUL_MS`].
    #[serde(default = "default_graceful_ms")]
    pub graceful_timeout_ms: Millis,
    /// Window over which drain wakeups are spread. Defaults to
    /// [`DEFAULT_DRAIN_JITTER_MS`].
    #[serde(default = "default_drain_jitter_ms")]
    pub drain_jitter_ms: Millis,
}

impl Default for ShutdownSection {
    fn default() -> Self {
        Self {
            graceful_timeout_ms: default_graceful_ms(),
            drain_jitter_ms: default_drain_jitter_ms(),
        }
    }
}

/// Default backlog: 4096, chosen so the kernel honours it without tuning
/// `net.core.somaxconn`.
pub const DEFAULT_BACKLOG: u32 = 4096;
/// Default control-plane worker count.
pub const DEFAULT_CONTROL_WORKERS: usize = 2;
/// Default upstream connect deadline, in milliseconds.
pub const DEFAULT_CONNECT_MS: u32 = 5_000;
/// Default idle deadline for a connection with no bytes in either direction,
/// in milliseconds.
pub const DEFAULT_IDLE_MS: u32 = 60_000;
/// Default deadline after one direction has closed, in milliseconds.
pub const DEFAULT_HALF_CLOSE_MS: u32 = 60_000;
/// Default connection cap.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 10_000;
/// Default graceful shutdown budget, in milliseconds.
pub const DEFAULT_GRACEFUL_MS: u32 = 300_000;
/// Default window over which drain wakeups are spread, in milliseconds.
pub const DEFAULT_DRAIN_JITTER_MS: u32 = 5_000;

fn default_backlog() -> Backlog {
    Backlog::try_from(DEFAULT_BACKLOG).unwrap_or(Backlog::MIN)
}

fn default_true() -> bool {
    true
}

fn default_control_workers() -> usize {
    DEFAULT_CONTROL_WORKERS
}

fn default_connect_ms() -> Millis {
    Millis::try_from(DEFAULT_CONNECT_MS).unwrap_or(Millis::MIN)
}

fn default_idle_ms() -> Millis {
    Millis::try_from(DEFAULT_IDLE_MS).unwrap_or(Millis::MIN)
}

fn default_half_close_ms() -> Millis {
    Millis::try_from(DEFAULT_HALF_CLOSE_MS).unwrap_or(Millis::MIN)
}

fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

fn default_graceful_ms() -> Millis {
    Millis::try_from(DEFAULT_GRACEFUL_MS).unwrap_or(Millis::MIN)
}

fn default_drain_jitter_ms() -> Millis {
    Millis::try_from(DEFAULT_DRAIN_JITTER_MS).unwrap_or(Millis::MIN)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{
        BootstrapDoc, DEFAULT_BACKLOG, DEFAULT_CONNECT_MS, DEFAULT_CONTROL_WORKERS,
        DEFAULT_DRAIN_JITTER_MS, DEFAULT_GRACEFUL_MS, DEFAULT_HALF_CLOSE_MS, DEFAULT_IDLE_MS,
        DEFAULT_MAX_CONNECTIONS, LimitSection, ListenerSection, RuntimeSection, ShutdownSection,
        TimeoutSection, UpstreamSection,
    };
    use crate::newtypes::{Backlog, BindAddr, ListenerName, Millis, ModeSpec, UpstreamAddr};

    const MINIMAL: &str = r#"{"apiVersion":"irontraffic.io/v1",
        "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
        "upstream":{"address":"127.0.0.1:9000"}}"#;

    #[test]
    fn minimal_document_parses_with_all_defaults() {
        let doc: BootstrapDoc = serde_json::from_str(MINIMAL).expect("minimal document parses");
        assert_eq!(doc.listeners[0].backlog.get(), DEFAULT_BACKLOG);
        assert!(doc.listeners[0].reuseport);
        assert!(!doc.listeners[0].ipv6_only);
        assert_eq!(doc.runtime.mode, ModeSpec::Balanced);
        assert_eq!(doc.runtime.control_workers, DEFAULT_CONTROL_WORKERS);
        assert_eq!(doc.timeouts.idle_ms.get(), DEFAULT_IDLE_MS);
        assert_eq!(doc.limits.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(doc.shutdown.graceful_timeout_ms.get(), DEFAULT_GRACEFUL_MS);
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let json = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "listenerz":[]}"#;
        let err = serde_json::from_str::<BootstrapDoc>(json).expect_err("unknown field rejected");
        assert!(err.to_string().contains("listenerz"));
    }

    #[test]
    fn unknown_nested_field_is_rejected() {
        let json = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0","backlogg":1}],
            "upstream":{"address":"127.0.0.1:9000"}}"#;
        let err = serde_json::from_str::<BootstrapDoc>(json).expect_err("unknown field rejected");
        assert!(err.to_string().contains("backlogg"));
    }

    #[test]
    fn empty_listeners_deserializes() {
        let json = r#"{"apiVersion":"irontraffic.io/v1","listeners":[],
            "upstream":{"address":"127.0.0.1:9000"}}"#;
        let doc: BootstrapDoc =
            serde_json::from_str(json).expect("empty listeners is a valid shape");
        assert!(doc.listeners.is_empty());
    }

    #[test]
    fn full_document_round_trips() {
        let doc = BootstrapDoc {
            api_version: crate::API_VERSION.to_owned(),
            listeners: vec![ListenerSection {
                name: ListenerName::try_from("edge").expect("legal name"),
                bind: BindAddr::try_from("[::]:9443").expect("legal bind"),
                backlog: Backlog::try_from(128u32).expect("in range"),
                reuseport: false,
                ipv6_only: true,
            }],
            upstream: UpstreamSection {
                address: UpstreamAddr::try_from("10.0.0.5:9000").expect("legal upstream"),
            },
            runtime: RuntimeSection {
                mode: ModeSpec::Shard,
                workers: Some(4),
                max_blocking_threads: Some(8),
                control_workers: 3,
            },
            timeouts: TimeoutSection {
                connect_ms: Millis::try_from(1_234u32).expect("in range"),
                idle_ms: Millis::try_from(2_345u32).expect("in range"),
                half_close_ms: Millis::try_from(3_456u32).expect("in range"),
                max_lifetime_ms: Some(Millis::try_from(4_567u32).expect("in range")),
            },
            limits: LimitSection {
                max_connections: 42,
            },
            shutdown: ShutdownSection {
                graceful_timeout_ms: Millis::try_from(5_678u32).expect("in range"),
                drain_jitter_ms: Millis::try_from(6_789u32).expect("in range"),
            },
        };
        let json = serde_json::to_string(&doc).expect("serializes");
        let restored: BootstrapDoc = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(restored, doc);
    }

    #[test]
    fn missing_api_version_is_rejected() {
        let json = r#"{"listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"}}"#;
        let err = serde_json::from_str::<BootstrapDoc>(json).expect_err("missing apiVersion");
        assert!(err.to_string().contains("apiVersion"));
    }

    #[test]
    fn wrong_api_version_still_deserializes() {
        let json = r#"{"apiVersion":"irontraffic.io/v2",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"}}"#;
        let doc: BootstrapDoc = serde_json::from_str(json).expect("shape is still valid");
        assert_eq!(doc.api_version, "irontraffic.io/v2");
    }

    #[test]
    fn section_defaults_match_the_constants() {
        assert_eq!(
            RuntimeSection::default().control_workers,
            DEFAULT_CONTROL_WORKERS
        );
        assert_eq!(
            TimeoutSection::default().connect_ms.get(),
            DEFAULT_CONNECT_MS
        );
        assert_eq!(TimeoutSection::default().idle_ms.get(), DEFAULT_IDLE_MS);
        assert_eq!(
            TimeoutSection::default().half_close_ms.get(),
            DEFAULT_HALF_CLOSE_MS
        );
        assert!(TimeoutSection::default().max_lifetime_ms.is_none());
        assert_eq!(
            LimitSection::default().max_connections,
            DEFAULT_MAX_CONNECTIONS
        );
        assert_eq!(
            ShutdownSection::default().graceful_timeout_ms.get(),
            DEFAULT_GRACEFUL_MS
        );
        assert_eq!(
            ShutdownSection::default().drain_jitter_ms.get(),
            DEFAULT_DRAIN_JITTER_MS
        );
    }

    // Not one of the 23 tests the issue names, added on top of them. Every
    // `default_*` function in this file is defined IN TERMS OF its matching
    // `DEFAULT_*` constant (`default_backlog` literally calls
    // `Backlog::try_from(DEFAULT_BACKLOG)`), so a test that only compares a
    // `default_*` function's output against the same `DEFAULT_*` constant, as
    // `section_defaults_match_the_constants` above necessarily does, cannot
    // catch the constant itself silently drifting to the wrong real-world
    // value: both sides of that comparison move together. Mutation testing
    // confirmed this: changing `DEFAULT_BACKLOG` from 4096 to any other legal
    // value left every one of the 23 named tests passing. This test pins the
    // literal values instead, so a `DEFAULT_*` typo has an independent check.
    #[test]
    fn default_constants_have_the_documented_values() {
        assert_eq!(DEFAULT_BACKLOG, 4096);
        assert_eq!(DEFAULT_CONTROL_WORKERS, 2);
        assert_eq!(DEFAULT_CONNECT_MS, 5_000);
        assert_eq!(DEFAULT_IDLE_MS, 60_000);
        assert_eq!(DEFAULT_HALF_CLOSE_MS, 60_000);
        assert_eq!(DEFAULT_MAX_CONNECTIONS, 10_000);
        assert_eq!(DEFAULT_GRACEFUL_MS, 300_000);
        assert_eq!(DEFAULT_DRAIN_JITTER_MS, 5_000);
    }

    // KNOWN GAP, FILED AS A DEFECT (not fixed here; this crate's own acceptance
    // criteria forbid the fix). Issue #14 names this test
    // `duplicate_keys_are_rejected_in_both_formats` and its body says: "deserialize
    // a document whose top level contains apiVersion twice... once as JSON and
    // once as YAML". But the same issue's acceptance criteria say
    // "[dev-dependencies] contains exactly serde_json and proptest", and its "Do
    // NOT" list separately forbids adding serde_norway (the workspace's YAML
    // crate) to this manifest. There is no way to deserialize YAML text without a
    // YAML crate, so the test's YAML half and the issue's own dependency
    // constraints cannot both be satisfied. Per CODER-PROMPT's instruction to
    // follow the stronger, doubly-stated constraint (an explicit "Do NOT" plus an
    // explicit dependency-count acceptance criterion) over a single test
    // description, this test covers the JSON half only, for both the top-level
    // and the nested duplicate-key cases the issue describes. Filed as issue
    // #501.
    #[test]
    fn duplicate_keys_are_rejected_in_both_formats() {
        let top_level = r#"{"apiVersion":"irontraffic.io/v1","apiVersion":"irontraffic.io/v2",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"}}"#;
        let err = serde_json::from_str::<BootstrapDoc>(top_level)
            .expect_err("a duplicated apiVersion key must be rejected");
        assert!(err.to_string().contains("apiVersion"));
        // `contains("apiVersion")` alone is also satisfied by serde's
        // "unknown field" or "missing field" messages, neither of which
        // proves the duplicate-key property this test exists to pin: a
        // security-relevant key written twice must never resolve silently
        // to one of them (the configuration equivalent of a
        // request-smuggling ambiguity). `duplicate field` is the one
        // substring only the duplicate-key path produces.
        assert!(err.to_string().contains("duplicate field"));

        let nested = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0","bind":"127.0.0.1:1"}],
            "upstream":{"address":"127.0.0.1:9000"}}"#;
        let err_nested = serde_json::from_str::<BootstrapDoc>(nested)
            .expect_err("a duplicated bind key must be rejected");
        assert!(err_nested.to_string().contains("bind"));
        // Same strengthening as above: `contains("bind")` is also satisfied
        // by an unrelated "unknown field `bindx`"-shaped message.
        assert!(err_nested.to_string().contains("duplicate field"));
    }

    #[test]
    fn max_lifetime_defaults_to_none_and_round_trips() {
        let doc: BootstrapDoc = serde_json::from_str(MINIMAL).expect("minimal document parses");
        assert_eq!(doc.timeouts.max_lifetime_ms, None);

        let with_value = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "timeouts":{"max_lifetime_ms":900000}}"#;
        let doc_with_value: BootstrapDoc =
            serde_json::from_str(with_value).expect("a set max_lifetime_ms parses");
        assert_eq!(
            doc_with_value.timeouts.max_lifetime_ms.map(Millis::get),
            Some(900_000)
        );

        let zero = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "timeouts":{"max_lifetime_ms":0}}"#;
        let err = serde_json::from_str::<BootstrapDoc>(zero)
            .expect_err("zero max_lifetime_ms is rejected");
        assert!(err.to_string().contains("duration 0 ms is out of range"));
    }

    // Edge case 15: `max_connections` is a plain `u32`, not a newtype,
    // because a future version may want 0 to mean "derive from
    // `RLIMIT_NOFILE`". This crate must deserialize 0 rather than reject it;
    // the validator in `config-load-and-validate` (#15) is the layer that
    // rejects it. Not one of the 23 named tests; added because nothing else
    // exercises this deliberate non-validation, and it is exactly the kind
    // of statement a later implementer "fixes" by adding a second clamp
    // here.
    #[test]
    fn max_connections_zero_deserializes_here_and_is_left_to_the_validator() {
        let json = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "limits":{"max_connections":0}}"#;
        let doc: BootstrapDoc =
            serde_json::from_str(json).expect("zero max_connections deserializes at this layer");
        assert_eq!(doc.limits.max_connections, 0);
    }

    // Edge case 19: `runtime.workers: Some(0)` deserializes unchanged. The
    // runtime clamps it to 1 and the validator warns; this crate does
    // neither, which is the point, stated so nobody adds a second clamp
    // here. Not one of the 23 named tests, for the same reason as the test
    // above.
    #[test]
    fn runtime_workers_zero_deserializes_without_a_second_clamp() {
        let json = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "runtime":{"workers":0}}"#;
        let doc: BootstrapDoc =
            serde_json::from_str(json).expect("zero workers deserializes at this layer");
        assert_eq!(doc.runtime.workers, Some(0));
    }

    // Closes DU3..DU7: proves deny_unknown_fields is on EVERY struct, not
    // just that the attribute appears seven times in the file.
    #[test]
    fn unknown_field_is_rejected_in_every_section() {
        let cases: [(&str, &str); 5] = [
            (r#","listenerz":[]"#, "listenerz"),
            (r#","runtime":{"workerz":4}"#, "workerz"),
            (r#","timeouts":{"max_liftime_ms":900000}"#, "max_liftime_ms"),
            (r#","limits":{"max_conections":5000}"#, "max_conections"),
            (
                r#","shutdown":{"graceful_timeout_mss":1000}"#,
                "graceful_timeout_mss",
            ),
        ];
        for (extra, needle) in cases {
            let json = format!(
                r#"{{"apiVersion":"irontraffic.io/v1",
                   "listeners":[{{"name":"web","bind":"127.0.0.1:0"}}],
                   "upstream":{{"address":"127.0.0.1:9000"}}{extra}}}"#
            );
            let err = serde_json::from_str::<BootstrapDoc>(&json)
                .expect_err(&format!("unknown field {needle} must be rejected"));
            assert!(
                err.to_string().contains(needle),
                "expected {needle} in {err}"
            );
        }
        // UpstreamSection and ListenerSection, which need the typo inside their
        // own object rather than beside it.
        let upstream = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000","addres":"127.0.0.1:1"}}"#;
        let err = serde_json::from_str::<BootstrapDoc>(upstream).expect_err("unknown upstream key");
        assert!(err.to_string().contains("addres"), "{err}");
        let listener = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0","backlogg":1}],
            "upstream":{"address":"127.0.0.1:9000"}}"#;
        let err = serde_json::from_str::<BootstrapDoc>(listener).expect_err("unknown listener key");
        assert!(err.to_string().contains("backlogg"), "{err}");
    }

    // Closes SD4..SD11 and SD17..SD19: every named test either omits the four
    // optional sections entirely (which routes through the hand-written Default
    // impls) or supplies every field, so the per-field `#[serde(default = ...)]`
    // attributes are never both exercised and asserted. This parses each section
    // PRESENT BUT INCOMPLETE and pins every filled-in value.
    #[test]
    fn partial_sections_fill_missing_fields_from_the_constants() {
        // Every section PRESENT but EMPTY, which is the only shape that routes
        // through the per-field `#[serde(default = "...")]` attributes rather
        // than through the hand-written `Default` impls.
        let json = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "runtime":{},"timeouts":{},"limits":{},"shutdown":{}}"#;
        let doc: BootstrapDoc = serde_json::from_str(json).expect("empty sections parse");
        assert_eq!(doc.runtime.mode, ModeSpec::Balanced);
        assert_eq!(doc.runtime.workers, None);
        assert_eq!(doc.runtime.max_blocking_threads, None);
        assert_eq!(doc.runtime.control_workers, DEFAULT_CONTROL_WORKERS);
        assert_eq!(doc.timeouts.connect_ms.get(), DEFAULT_CONNECT_MS);
        assert_eq!(doc.timeouts.idle_ms.get(), DEFAULT_IDLE_MS);
        assert_eq!(doc.timeouts.half_close_ms.get(), DEFAULT_HALF_CLOSE_MS);
        assert_eq!(doc.timeouts.max_lifetime_ms, None);
        assert_eq!(doc.limits.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(doc.shutdown.graceful_timeout_ms.get(), DEFAULT_GRACEFUL_MS);
        assert_eq!(doc.shutdown.drain_jitter_ms.get(), DEFAULT_DRAIN_JITTER_MS);
        assert_eq!(doc.listeners[0].backlog.get(), DEFAULT_BACKLOG);
        assert!(doc.listeners[0].reuseport);
        assert!(!doc.listeners[0].ipv6_only);

        // One field set per section: the explicit value wins and the rest still
        // come from the constants.
        let partial = r#"{"apiVersion":"irontraffic.io/v1",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"},
            "runtime":{"workers":4},"timeouts":{"idle_ms":1000},
            "shutdown":{"drain_jitter_ms":7}}"#;
        let d2: BootstrapDoc = serde_json::from_str(partial).expect("partial sections parse");
        assert_eq!(d2.runtime.workers, Some(4));
        assert_eq!(d2.runtime.control_workers, DEFAULT_CONTROL_WORKERS);
        assert_eq!(d2.timeouts.idle_ms.get(), 1000);
        assert_eq!(d2.timeouts.connect_ms.get(), DEFAULT_CONNECT_MS);
        assert_eq!(d2.timeouts.half_close_ms.get(), DEFAULT_HALF_CLOSE_MS);
        assert_eq!(d2.shutdown.drain_jitter_ms.get(), 7);
        assert_eq!(d2.shutdown.graceful_timeout_ms.get(), DEFAULT_GRACEFUL_MS);
    }

    // Closes DI1 and DI2: nothing asserted that the default runtime leaves the
    // worker counts underived, so a Default impl that pinned workers to Some(1)
    // would ship a one-thread data plane with a green suite.
    #[test]
    fn default_runtime_leaves_worker_counts_underived() {
        assert_eq!(RuntimeSection::default().workers, None);
        assert_eq!(RuntimeSection::default().max_blocking_threads, None);
        let doc: BootstrapDoc = serde_json::from_str(MINIMAL).expect("minimal parses");
        assert_eq!(doc.runtime.workers, None);
        assert_eq!(doc.runtime.max_blocking_threads, None);
    }

    // Strengthens test 22: `contains("bind")` is also satisfied by
    // "unknown field `bindx`", so the existing assertion does not distinguish a
    // duplicate-key rejection from any other error naming the field.
    #[test]
    fn duplicate_key_error_names_the_duplication() {
        let top = r#"{"apiVersion":"irontraffic.io/v1","apiVersion":"irontraffic.io/v2",
            "listeners":[{"name":"web","bind":"127.0.0.1:0"}],
            "upstream":{"address":"127.0.0.1:9000"}}"#;
        let err = serde_json::from_str::<BootstrapDoc>(top).expect_err("rejected");
        assert!(err.to_string().contains("duplicate field"), "{err}");
        assert!(err.to_string().contains("apiVersion"), "{err}");
    }

    fn arb_listener_name() -> impl Strategy<Value = ListenerName> {
        "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?".prop_map(|s| {
            ListenerName::try_from(s.as_str()).expect("regex only generates legal names")
        })
    }

    fn arb_ip() -> impl Strategy<Value = std::net::IpAddr> {
        prop_oneof![
            any::<[u8; 4]>().prop_map(|b| std::net::IpAddr::V4(std::net::Ipv4Addr::from(b))),
            any::<[u16; 8]>().prop_map(|b| std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))),
        ]
    }

    fn arb_bind_addr() -> impl Strategy<Value = BindAddr> {
        (arb_ip(), any::<u16>()).prop_map(|(ip, port)| {
            let addr = std::net::SocketAddr::new(ip, port);
            BindAddr::try_from(addr.to_string().as_str())
                .expect("SocketAddr's Display always round trips through BindAddr::try_from")
        })
    }

    fn arb_upstream_addr() -> impl Strategy<Value = UpstreamAddr> {
        (arb_ip(), any::<u16>()).prop_map(|(ip, port)| {
            let addr = std::net::SocketAddr::new(ip, port);
            UpstreamAddr::try_from(addr.to_string().as_str())
                .expect("SocketAddr's Display always round trips through UpstreamAddr::try_from")
        })
    }

    fn arb_listener_section() -> impl Strategy<Value = ListenerSection> {
        (
            arb_listener_name(),
            arb_bind_addr(),
            1u32..=65_535,
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(
                |(name, bind, backlog_val, reuseport, ipv6_only)| ListenerSection {
                    name,
                    bind,
                    backlog: Backlog::try_from(backlog_val).expect("in range by construction"),
                    reuseport,
                    ipv6_only,
                },
            )
    }

    fn arb_bootstrap_doc() -> impl Strategy<Value = BootstrapDoc> {
        let listeners_and_upstream = (
            prop::collection::vec(arb_listener_section(), 1..=8),
            arb_upstream_addr(),
            prop_oneof![Just(ModeSpec::Balanced), Just(ModeSpec::Shard)],
            proptest::option::of(1usize..=64),
        );
        let runtime_rest = (
            proptest::option::of(1usize..=32),
            1usize..=16,
            1u32..=86_400_000,
            1u32..=86_400_000,
        );
        let timeouts_rest = (
            1u32..=86_400_000,
            proptest::option::of(1u32..=86_400_000),
            1u32..=1_000_000,
            1u32..=86_400_000,
            1u32..=86_400_000,
        );
        (listeners_and_upstream, runtime_rest, timeouts_rest).prop_map(
            |(
                (listeners, upstream_addr, mode, workers),
                (max_blocking_threads, control_workers, connect_ms, idle_ms),
                (half_close_ms, max_lifetime_ms, max_connections, graceful_ms, drain_jitter_ms),
            )| {
                BootstrapDoc {
                    api_version: crate::API_VERSION.to_owned(),
                    listeners,
                    upstream: UpstreamSection {
                        address: upstream_addr,
                    },
                    runtime: RuntimeSection {
                        mode,
                        workers,
                        max_blocking_threads,
                        control_workers,
                    },
                    timeouts: TimeoutSection {
                        connect_ms: Millis::try_from(connect_ms).expect("in range by construction"),
                        idle_ms: Millis::try_from(idle_ms).expect("in range by construction"),
                        half_close_ms: Millis::try_from(half_close_ms)
                            .expect("in range by construction"),
                        max_lifetime_ms: max_lifetime_ms
                            .map(|m| Millis::try_from(m).expect("in range by construction")),
                    },
                    limits: LimitSection { max_connections },
                    shutdown: ShutdownSection {
                        graceful_timeout_ms: Millis::try_from(graceful_ms)
                            .expect("in range by construction"),
                        drain_jitter_ms: Millis::try_from(drain_jitter_ms)
                            .expect("in range by construction"),
                    },
                }
            },
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn prop_document_round_trip(doc in arb_bootstrap_doc()) {
            let json = serde_json::to_string(&doc).expect("serializes");
            let restored: BootstrapDoc = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(restored, doc);
        }
    }
}
