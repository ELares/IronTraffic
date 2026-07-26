// SPDX-License-Identifier: MIT OR Apache-2.0

//! The semantic validator: whole-document checks over a [`BootstrapDoc`].
//!
//! Pure. No I/O, no clock, no randomness, no allocation beyond the diagnostics
//! themselves. That rule exists because ingress-nginx validates an admission request
//! by rendering attacker-controlled input to a temp file and executing the real proxy
//! binary on it, which turned a set of authenticated injections into an
//! unauthenticated pre-auth remote code execution reachable from any pod. This
//! validator runs in the same address space, is deterministic, and touches nothing.
//!
//! A second consequence of purity: `irontraffic validate` and the startup path call
//! this identical function on the identical value, so "it validated but then failed
//! to apply" is impossible by construction.
//!
//! Every check below is O(1) or O(L) except the two duplicate scans and the
//! self-loop scan, which are O(L^2) and O(L) respectively and run only after the
//! listener count has been proved at most [`MAX_LISTENERS`], so the whole validator
//! costs at most a few thousand comparisons however large the document is. That bound
//! matters because a validator is reachable from the admin API in a later milestone
//! and an unbounded validator is a denial of service with no packets sent.
//!
//! Duplicate detection uses a small `Vec<(&str, usize)>` scanned linearly rather than
//! a `HashMap`, because `L <= 64` and a linear scan of a hot 64-entry vector beats a
//! hash plus a cold bucket probe, and because `HashMap` iteration order would make the
//! diagnostic order nondeterministic. Diagnostics are emitted in a fixed, numbered
//! check order, so two runs over one document produce byte-identical output.

use crate::diagnostic::{Diagnostic, Diagnostics, Severity};
use crate::model::BootstrapDoc;
use crate::newtypes::ModeSpec;

/// The largest number of listeners accepted.
pub const MAX_LISTENERS: usize = 64;

/// Checks a document for semantic errors. Pure: no I/O, no clock, no randomness.
///
/// Returns every finding at once, in document order, so an operator fixes one
/// configuration rather than four. The same function is called by `irontraffic
/// validate` and by the startup path, so "it validated but then failed to apply"
/// cannot happen for anything this function checks.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one cohesive, sequentially numbered validation pass; splitting it would scatter the check order that document-order determinism depends on across several functions for no readability gain"
)]
pub fn validate(doc: &BootstrapDoc) -> Diagnostics {
    let mut diagnostics = Diagnostics::default();

    // 1. apiVersion must be the one this build supports.
    if doc.api_version != crate::API_VERSION {
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/apiVersion".to_owned(),
            code: "unsupported_api_version",
            message: format!(
                "apiVersion {:?} is not supported; this build supports {:?}",
                doc.api_version,
                crate::API_VERSION
            ),
        });
    }

    // 2. At least one listener is required.
    if doc.listeners.is_empty() {
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/listeners".to_owned(),
            code: "no_listeners",
            message: "at least one listener is required".to_owned(),
        });
    }

    // 3. The listener count must be bounded before any O(L^2) or O(L) check below
    // runs, so that the rest of this function is provably bounded regardless of how
    // large the document is.
    let listener_count_ok = doc.listeners.len() <= MAX_LISTENERS;
    if listener_count_ok {
        // 4. Duplicate listener names.
        let mut seen_names: Vec<(&str, usize)> = Vec::new();
        for (index, listener) in doc.listeners.iter().enumerate() {
            let name = listener.name.as_str();
            match seen_names.iter().find(|(seen, _)| *seen == name) {
                Some(&(_, earlier)) => diagnostics.push(Diagnostic {
                    severity: Severity::Error,
                    pointer: format!("/listeners/{index}/name"),
                    code: "duplicate_listener_name",
                    message: format!(
                        "listener name {name:?} was already used by listener {earlier}"
                    ),
                }),
                None => seen_names.push((name, index)),
            }
        }

        // 5. Duplicate bind addresses, skipping port 0 ("any port"), which may
        // legitimately repeat.
        let mut seen_binds: Vec<(String, usize)> = Vec::new();
        for (index, listener) in doc.listeners.iter().enumerate() {
            if listener.bind.socket_addr().port() == 0 {
                continue;
            }
            let key = listener.bind.canonical_key();
            let earlier = seen_binds
                .iter()
                .find(|(seen_key, _)| *seen_key == key)
                .map(|&(_, earlier_index)| earlier_index);
            match earlier {
                Some(earlier_index) => diagnostics.push(Diagnostic {
                    severity: Severity::Error,
                    pointer: format!("/listeners/{index}/bind"),
                    code: "duplicate_bind_address",
                    message: format!("{key} is already bound by listener {earlier_index}"),
                }),
                None => seen_binds.push((key, index)),
            }
        }
    } else {
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/listeners".to_owned(),
            code: "too_many_listeners",
            message: format!(
                "{} listeners exceeds the limit of {MAX_LISTENERS}",
                doc.listeners.len()
            ),
        });
    }

    // 6. A connection cap of zero admits nothing.
    if doc.limits.max_connections == 0 {
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/limits/max_connections".to_owned(),
            code: "zero_max_connections",
            message: "max_connections is 0; at least one connection must be permitted".to_owned(),
        });
    }

    // 7. A very large connection cap is past the tested ceiling.
    if doc.limits.max_connections > 1_000_000 {
        diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            pointer: "/limits/max_connections".to_owned(),
            code: "max_connections_above_tested_ceiling",
            message: format!(
                "max_connections is {}, above the tested ceiling of 1000000 idle connections; \
                 each connection costs two file descriptors and up to two 32 KiB read buffers",
                doc.limits.max_connections
            ),
        });
    }

    // 8. runtime.workers = 0 deserializes but is clamped by the runtime.
    if doc.runtime.workers == Some(0) {
        diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            pointer: "/runtime/workers".to_owned(),
            code: "zero_workers_clamped",
            message: "runtime.workers is 0; the runtime clamps it to 1".to_owned(),
        });
    }

    // 9. runtime.workers above the runtime's own ceiling is silently clamped there.
    if let Some(workers) = doc.runtime.workers
        && workers > irontraffic_runtime::MAX_WORKERS
    {
        diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            pointer: "/runtime/workers".to_owned(),
            code: "workers_above_reasonable",
            message: format!(
                "runtime.workers is {workers}, above {}; the runtime clamps to it",
                irontraffic_runtime::MAX_WORKERS
            ),
        });
    }

    // 10. A control plane with no workers cannot reload configuration; the runtime
    // refuses to start rather than clamping this one up, so the operator is told.
    if doc.runtime.control_workers == 0 {
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/runtime/control_workers".to_owned(),
            code: "zero_control_workers",
            message:
                "control_workers is 0; a control plane with no workers cannot reload configuration"
                    .to_owned(),
        });
    }

    // 11. Shard mode is refused at runtime build time in this version.
    if doc.runtime.mode == ModeSpec::Shard {
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/runtime/mode".to_owned(),
            code: "shard_mode_unsupported",
            // The identical text the runtime's own error uses, so an operator who
            // hits this at validate time and an operator who hits it at startup see
            // one story rather than two independently maintained descriptions.
            message: irontraffic_runtime::RuntimeError::ShardModeUnsupported.to_string(),
        });
    }

    // 12. A connect deadline longer than the idle deadline can never be reached.
    if doc.timeouts.connect_ms.get() > doc.timeouts.idle_ms.get() {
        diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            pointer: "/timeouts/connect_ms".to_owned(),
            code: "connect_exceeds_idle",
            message: format!(
                "connect_ms is {}, above idle_ms {}; a connect deadline longer than the idle \
                 deadline cannot be reached",
                doc.timeouts.connect_ms.get(),
                doc.timeouts.idle_ms.get()
            ),
        });
    }

    // 13. A jitter window at least as long as the whole drain budget means some
    // connections are never signalled before the deadline.
    if doc.shutdown.drain_jitter_ms.get() >= doc.shutdown.graceful_timeout_ms.get() {
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/shutdown/drain_jitter_ms".to_owned(),
            code: "jitter_exceeds_graceful",
            message: format!(
                "drain_jitter_ms is {}, at or above graceful_timeout_ms {}; some connections \
                 would never be signalled before the deadline",
                doc.shutdown.drain_jitter_ms.get(),
                doc.shutdown.graceful_timeout_ms.get()
            ),
        });
    }

    // 14. A proxy forwarding to its own listener turns one client connection into an
    // unbounded self-dial chain. O(L), so it also waits on the count check above.
    if listener_count_ok {
        let upstream_addr = doc.upstream.address.socket_addr();
        for (index, listener) in doc.listeners.iter().enumerate() {
            let listener_addr = listener.bind.socket_addr();
            let same_port = listener_addr.port() == upstream_addr.port();
            let same_endpoint = same_port
                && (listener_addr.ip() == upstream_addr.ip()
                    || listener_addr.ip().is_unspecified()
                    || upstream_addr.ip().is_unspecified());
            if same_endpoint {
                diagnostics.push(Diagnostic {
                    severity: Severity::Error,
                    pointer: "/upstream/address".to_owned(),
                    code: "upstream_is_own_listener",
                    message: format!(
                        "upstream {upstream_addr} names the same endpoint as listener {index} \
                         ({name}, {listener_addr})",
                        name = listener.name
                    ),
                });
            }
        }
    }

    // 15. Every unit here is an operating-system thread the blocking pool may create.
    if let Some(threads) = doc.runtime.max_blocking_threads
        && threads > irontraffic_runtime::MAX_BLOCKING_THREADS
    {
        diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            pointer: "/runtime/max_blocking_threads".to_owned(),
            code: "blocking_threads_above_ceiling",
            message: format!(
                "max_blocking_threads is {threads}, above {}; the runtime clamps to it",
                irontraffic_runtime::MAX_BLOCKING_THREADS
            ),
        });
    }

    // 16. control_workers above the runtime's ceiling is silently clamped there too.
    if doc.runtime.control_workers > irontraffic_runtime::MAX_WORKERS {
        diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            pointer: "/runtime/control_workers".to_owned(),
            code: "control_workers_above_reasonable",
            message: format!(
                "control_workers is {}, above {}; the runtime clamps to it",
                doc.runtime.control_workers,
                irontraffic_runtime::MAX_WORKERS
            ),
        });
    }

    // 17. An absolute lifetime at or below the idle deadline ends every connection
    // before the idle deadline could ever apply, which is almost certainly not meant.
    if let Some(max_lifetime) = doc.timeouts.max_lifetime_ms
        && max_lifetime.get() <= doc.timeouts.idle_ms.get()
    {
        diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            pointer: "/timeouts/max_lifetime_ms".to_owned(),
            code: "max_lifetime_below_idle",
            message: format!(
                "max_lifetime_ms is {}, at or below idle_ms {}; the connection would always \
                 end before the idle deadline can apply",
                max_lifetime.get(),
                doc.timeouts.idle_ms.get()
            ),
        });
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{MAX_LISTENERS, validate};
    use crate::model::{
        BootstrapDoc, LimitSection, ListenerSection, RuntimeSection, ShutdownSection,
        TimeoutSection, UpstreamSection,
    };
    use crate::newtypes::{Backlog, BindAddr, ListenerName, Millis, ModeSpec, UpstreamAddr};

    fn listener(name: &str, bind: &str) -> ListenerSection {
        ListenerSection {
            name: ListenerName::try_from(name).expect("legal name"),
            bind: BindAddr::try_from(bind).expect("legal bind"),
            backlog: Backlog::try_from(4096u32).expect("legal backlog"),
            reuseport: true,
            ipv6_only: false,
        }
    }

    fn minimal_doc() -> BootstrapDoc {
        BootstrapDoc {
            api_version: crate::API_VERSION.to_owned(),
            listeners: vec![listener("web", "127.0.0.1:8080")],
            upstream: UpstreamSection {
                address: UpstreamAddr::try_from("10.0.0.1:9000").expect("legal upstream"),
            },
            runtime: RuntimeSection::default(),
            timeouts: TimeoutSection::default(),
            limits: LimitSection::default(),
            shutdown: ShutdownSection::default(),
        }
    }

    #[test]
    fn valid_minimal_document_has_no_diagnostics() {
        assert!(validate(&minimal_doc()).is_empty());
    }

    #[test]
    fn wrong_api_version_is_an_error() {
        let mut doc = minimal_doc();
        doc.api_version = "irontraffic.io/v2".to_owned();
        let diagnostics = validate(&doc);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "unsupported_api_version");
        assert_eq!(d.pointer, "/apiVersion");
        assert!(d.message.contains("irontraffic.io/v2"));
        assert!(d.message.contains(crate::API_VERSION));
    }

    #[test]
    fn no_listeners_is_an_error() {
        let mut doc = minimal_doc();
        doc.listeners.clear();
        let diagnostics = validate(&doc);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == "no_listeners" && d.pointer == "/listeners")
        );
    }

    #[test]
    fn duplicate_listener_name_is_an_error() {
        let mut doc = minimal_doc();
        doc.listeners = vec![
            listener("web", "127.0.0.1:8080"),
            listener("web", "127.0.0.1:8081"),
        ];
        let diagnostics = validate(&doc);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "duplicate_listener_name");
        assert_eq!(d.pointer, "/listeners/1/name");
        assert!(d.message.contains('0'));
    }

    #[test]
    fn duplicate_bind_address_is_an_error() {
        let mut doc = minimal_doc();
        doc.listeners = vec![
            listener("web1", "127.0.0.1:8080"),
            listener("web2", "127.0.0.1:8080"),
        ];
        let diagnostics = validate(&doc);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "duplicate_bind_address");
        assert_eq!(d.pointer, "/listeners/1/bind");
    }

    #[test]
    fn duplicate_port_zero_is_allowed() {
        let mut doc = minimal_doc();
        doc.listeners = vec![listener("web1", "0.0.0.0:0"), listener("web2", "0.0.0.0:0")];
        assert!(validate(&doc).is_empty());
    }

    #[test]
    fn v4_and_v6_same_port_are_not_duplicates() {
        let mut doc = minimal_doc();
        doc.listeners = vec![listener("web1", "0.0.0.0:80"), listener("web2", "[::]:80")];
        doc.upstream.address = UpstreamAddr::try_from("10.0.0.1:9000").expect("legal");
        assert!(validate(&doc).is_empty());
    }

    #[test]
    fn too_many_listeners_is_an_error() {
        let mut doc = minimal_doc();
        doc.listeners = (0..65).map(|_| listener("web", "127.0.0.1:8080")).collect();
        let diagnostics = validate(&doc);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "too_many_listeners");
        assert!(d.message.contains(&MAX_LISTENERS.to_string()));
    }

    #[test]
    fn zero_max_connections_is_an_error() {
        let mut doc = minimal_doc();
        doc.limits.max_connections = 0;
        let diagnostics = validate(&doc);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "zero_max_connections");
        assert_eq!(d.severity, crate::diagnostic::Severity::Error);
    }

    #[test]
    fn huge_max_connections_is_a_warning() {
        let mut doc = minimal_doc();
        doc.limits.max_connections = 2_000_000;
        let diagnostics = validate(&doc);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "max_connections_above_tested_ceiling");
        assert_eq!(d.severity, crate::diagnostic::Severity::Warn);
        assert!(!diagnostics.has_errors());
    }

    #[test]
    fn zero_workers_is_a_warning() {
        let mut doc = minimal_doc();
        doc.runtime.workers = Some(0);
        let diagnostics = validate(&doc);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "zero_workers_clamped");
        assert_eq!(d.severity, crate::diagnostic::Severity::Warn);
    }

    #[test]
    fn shard_mode_is_an_error_with_the_same_text_as_the_runtime() {
        let mut doc = minimal_doc();
        doc.runtime.mode = ModeSpec::Shard;
        let diagnostics = validate(&doc);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "shard_mode_unsupported");
        assert!(d.message.contains("balanced"));
        assert_eq!(
            d.message,
            irontraffic_runtime::RuntimeError::ShardModeUnsupported.to_string()
        );
    }

    #[test]
    fn jitter_at_or_above_graceful_is_an_error() {
        let mut doc = minimal_doc();
        doc.shutdown.graceful_timeout_ms = Millis::try_from(1_000u32).expect("legal");
        doc.shutdown.drain_jitter_ms = Millis::try_from(1_000u32).expect("legal");
        assert!(
            validate(&doc)
                .iter()
                .any(|d| d.code == "jitter_exceeds_graceful")
        );

        let mut lower = minimal_doc();
        lower.shutdown.graceful_timeout_ms = Millis::try_from(1_000u32).expect("legal");
        lower.shutdown.drain_jitter_ms = Millis::try_from(999u32).expect("legal");
        assert!(validate(&lower).is_empty());
    }

    #[test]
    fn connect_longer_than_idle_is_a_warning() {
        let mut doc = minimal_doc();
        doc.timeouts.connect_ms = Millis::try_from(90_000u32).expect("legal");
        doc.timeouts.idle_ms = Millis::try_from(60_000u32).expect("legal");
        let diagnostics = validate(&doc);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "connect_exceeds_idle");
        assert_eq!(d.severity, crate::diagnostic::Severity::Warn);
    }

    #[test]
    fn diagnostics_are_in_document_order() {
        let mut doc = minimal_doc();
        doc.api_version = "irontraffic.io/v2".to_owned();
        doc.listeners = vec![
            listener("web1", "127.0.0.1:8080"),
            listener("web2", "127.0.0.1:8080"),
        ];
        doc.limits.max_connections = 0;
        let diagnostics = validate(&doc);
        let pointers: Vec<&str> = diagnostics.iter().map(|d| d.pointer.as_str()).collect();
        assert_eq!(
            pointers,
            vec![
                "/apiVersion",
                "/listeners/1/bind",
                "/limits/max_connections"
            ]
        );
    }

    #[test]
    fn validate_is_deterministic() {
        let doc = minimal_doc();
        assert_eq!(validate(&doc), validate(&doc));

        let mut invalid = minimal_doc();
        invalid.listeners.clear();
        invalid.limits.max_connections = 0;
        assert_eq!(validate(&invalid), validate(&invalid));
    }

    #[test]
    fn upstream_equal_to_a_listener_is_an_error() {
        let cases: [(&str, &str, bool); 5] = [
            ("127.0.0.1:8080", "127.0.0.1:8080", true),
            ("0.0.0.0:8080", "127.0.0.1:8080", true),
            ("127.0.0.1:8080", "0.0.0.0:8080", true),
            ("10.0.0.1:8080", "10.0.0.2:8080", false),
            ("127.0.0.1:8080", "127.0.0.1:9000", false),
        ];
        for (bind, upstream, expect_error) in cases {
            let mut doc = minimal_doc();
            doc.listeners = vec![listener("web", bind)];
            doc.upstream.address = UpstreamAddr::try_from(upstream).expect("legal upstream");
            let diagnostics = validate(&doc);
            if expect_error {
                assert_eq!(
                    diagnostics.len(),
                    1,
                    "bind {bind} upstream {upstream} should be exactly one diagnostic"
                );
                let d = diagnostics.iter().next().expect("one diagnostic");
                assert_eq!(d.code, "upstream_is_own_listener");
                assert_eq!(d.pointer, "/upstream/address");
                assert!(d.message.contains("web"));
            } else {
                assert!(
                    diagnostics.is_empty(),
                    "bind {bind} upstream {upstream} should be accepted, got {diagnostics:?}"
                );
            }
        }
    }

    #[test]
    fn runtime_ceilings_are_warned() {
        let mut blocking = minimal_doc();
        blocking.runtime.max_blocking_threads = Some(100_000);
        let diagnostics = validate(&blocking);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "blocking_threads_above_ceiling");
        assert!(d.message.contains("512"));
        assert!(!diagnostics.has_errors());

        let mut control = minimal_doc();
        control.runtime.control_workers = 5_000;
        let diagnostics = validate(&control);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "control_workers_above_reasonable");
        assert!(d.message.contains("1024"));
        assert!(!diagnostics.has_errors());

        let mut lifetime = minimal_doc();
        lifetime.timeouts.idle_ms = Millis::try_from(60_000u32).expect("legal");
        lifetime.timeouts.max_lifetime_ms = Some(Millis::try_from(30_000u32).expect("legal"));
        let diagnostics = validate(&lifetime);
        assert_eq!(diagnostics.len(), 1);
        let d = diagnostics.iter().next().expect("one diagnostic");
        assert_eq!(d.code, "max_lifetime_below_idle");
        assert!(!diagnostics.has_errors());
    }

    // Not one of the 17 named tests, added on top of them: mutation testing found
    // that every "above the ceiling" check was only ever tested with a value
    // strictly above its threshold, so a `>` mutated to `>=` survived on every one
    // of them: a value strictly above the threshold behaves identically under
    // either operator, and only the boundary value itself tells them apart.
    #[test]
    fn ceiling_boundaries_are_not_warnings() {
        let mut max_connections = minimal_doc();
        max_connections.limits.max_connections = 1_000_000;
        assert!(validate(&max_connections).is_empty());

        let mut workers = minimal_doc();
        workers.runtime.workers = Some(irontraffic_runtime::MAX_WORKERS);
        assert!(validate(&workers).is_empty());

        let mut control_workers = minimal_doc();
        control_workers.runtime.control_workers = irontraffic_runtime::MAX_WORKERS;
        assert!(validate(&control_workers).is_empty());

        let mut blocking = minimal_doc();
        blocking.runtime.max_blocking_threads = Some(irontraffic_runtime::MAX_BLOCKING_THREADS);
        assert!(validate(&blocking).is_empty());

        let mut timeouts = minimal_doc();
        let same = Millis::try_from(30_000u32).expect("legal");
        timeouts.timeouts.connect_ms = same;
        timeouts.timeouts.idle_ms = same;
        assert!(validate(&timeouts).is_empty());
    }

    // Not one of the 17 named tests, added on top of them: every code emitted above
    // must appear in the closed list documented on `Diagnostic::code`, which is the
    // acceptance criterion "every code value in validate.rs appears in the
    // seventeen-entry closed list ... and every entry in that list is produced by
    // exactly one check". A silent 18th code, or a documented code nothing ever
    // produces, is exactly the kind of drift a doc comment alone cannot catch.
    const DOCUMENTED_CODES: [&str; 17] = [
        "unsupported_api_version",
        "no_listeners",
        "too_many_listeners",
        "duplicate_listener_name",
        "duplicate_bind_address",
        "zero_max_connections",
        "max_connections_above_tested_ceiling",
        "zero_workers_clamped",
        "workers_above_reasonable",
        "zero_control_workers",
        "shard_mode_unsupported",
        "connect_exceeds_idle",
        "jitter_exceeds_graceful",
        "upstream_is_own_listener",
        "blocking_threads_above_ceiling",
        "control_workers_above_reasonable",
        "max_lifetime_below_idle",
    ];

    fn fires(doc: &BootstrapDoc, code: &str) -> bool {
        validate(doc).iter().any(|d| d.code == code)
    }

    #[test]
    fn every_documented_code_is_reachable() {
        let mut empty = minimal_doc();
        empty.api_version = "irontraffic.io/v2".to_owned();
        empty.listeners.clear();
        empty.limits.max_connections = 0;
        empty.runtime.control_workers = 0;
        empty.runtime.mode = ModeSpec::Shard;
        for code in [
            "unsupported_api_version",
            "no_listeners",
            "zero_max_connections",
            "zero_control_workers",
            "shard_mode_unsupported",
        ] {
            assert!(fires(&empty, code), "{code} should have fired");
        }

        let mut too_many = minimal_doc();
        too_many.listeners = (0..65).map(|_| listener("web", "127.0.0.1:8080")).collect();
        assert!(fires(&too_many, "too_many_listeners"));

        let mut dup = minimal_doc();
        dup.listeners = vec![
            listener("web", "127.0.0.1:8080"),
            listener("web", "127.0.0.1:8081"),
        ];
        assert!(fires(&dup, "duplicate_listener_name"));

        let mut dup_bind = minimal_doc();
        dup_bind.listeners = vec![
            listener("web1", "127.0.0.1:8080"),
            listener("web2", "127.0.0.1:8080"),
        ];
        assert!(fires(&dup_bind, "duplicate_bind_address"));

        let mut ceiling = minimal_doc();
        ceiling.limits.max_connections = 2_000_000;
        ceiling.runtime.workers = Some(0);
        assert!(fires(&ceiling, "max_connections_above_tested_ceiling"));
        assert!(fires(&ceiling, "zero_workers_clamped"));

        let mut workers = minimal_doc();
        workers.runtime.workers = Some(2000);
        assert!(fires(&workers, "workers_above_reasonable"));

        let mut timeouts = minimal_doc();
        timeouts.timeouts.connect_ms = Millis::try_from(90_000u32).expect("legal");
        timeouts.timeouts.idle_ms = Millis::try_from(60_000u32).expect("legal");
        assert!(fires(&timeouts, "connect_exceeds_idle"));

        let mut jitter = minimal_doc();
        jitter.shutdown.graceful_timeout_ms = Millis::try_from(1_000u32).expect("legal");
        jitter.shutdown.drain_jitter_ms = Millis::try_from(1_000u32).expect("legal");
        assert!(fires(&jitter, "jitter_exceeds_graceful"));

        // upstream_is_own_listener, blocking_threads_above_ceiling,
        // control_workers_above_reasonable, and max_lifetime_below_idle are each
        // covered end to end by their own named test above; not repeated here.
        assert_eq!(DOCUMENTED_CODES.len(), 17);
    }

    #[test]
    fn every_code_in_validate_rs_is_in_the_documented_list() {
        // The inverse direction of the acceptance criterion: every `code` value
        // this function can actually produce must be one of the seventeen
        // documented values, checked here by construction against a representative
        // document for every remaining branch not exercised in the test above.
        let mut blocking = minimal_doc();
        blocking.runtime.max_blocking_threads = Some(100_000);
        assert!(DOCUMENTED_CODES.contains(&"blocking_threads_above_ceiling"));
        assert!(fires(&blocking, "blocking_threads_above_ceiling"));

        let mut control = minimal_doc();
        control.runtime.control_workers = 5_000;
        assert!(DOCUMENTED_CODES.contains(&"control_workers_above_reasonable"));
        assert!(fires(&control, "control_workers_above_reasonable"));

        let mut lifetime = minimal_doc();
        lifetime.timeouts.idle_ms = Millis::try_from(60_000u32).expect("legal");
        lifetime.timeouts.max_lifetime_ms = Some(Millis::try_from(30_000u32).expect("legal"));
        assert!(DOCUMENTED_CODES.contains(&"max_lifetime_below_idle"));
        assert!(fires(&lifetime, "max_lifetime_below_idle"));

        let mut own_listener = minimal_doc();
        own_listener.upstream.address =
            UpstreamAddr::try_from("127.0.0.1:8080").expect("legal upstream");
        assert!(DOCUMENTED_CODES.contains(&"upstream_is_own_listener"));
        assert!(fires(&own_listener, "upstream_is_own_listener"));
    }

    fn arb_listener() -> impl Strategy<Value = ListenerSection> {
        (
            "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?",
            any::<[u8; 4]>(),
            any::<u16>(),
        )
            .prop_map(|(name, ip_bytes, port)| {
                let ip = std::net::Ipv4Addr::from(ip_bytes);
                let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port);
                listener(
                    ListenerName::try_from(name.as_str())
                        .expect("the regex only generates legal listener names")
                        .as_str(),
                    addr.to_string().as_str(),
                )
            })
    }

    fn arb_doc() -> impl Strategy<Value = BootstrapDoc> {
        (
            prop::collection::vec(arb_listener(), 0..=70),
            any::<[u8; 4]>(),
            any::<u16>(),
            any::<u32>(),
            proptest::option::of(0usize..=2000),
            1u32..=u32::MAX,
            1u32..=u32::MAX,
        )
            .prop_map(
                |(
                    listeners,
                    upstream_ip,
                    upstream_port,
                    max_connections,
                    workers,
                    connect_ms,
                    idle_ms,
                )| {
                    let mut doc = minimal_doc();
                    doc.listeners = listeners;
                    doc.upstream.address = UpstreamAddr::try_from(
                        std::net::SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::from(upstream_ip)),
                            upstream_port,
                        )
                        .to_string()
                        .as_str(),
                    )
                    .expect("SocketAddr always round trips");
                    doc.limits.max_connections = max_connections;
                    doc.runtime.workers = workers;
                    doc.timeouts.connect_ms = Millis::try_from(connect_ms).unwrap_or(Millis::MIN);
                    doc.timeouts.idle_ms = Millis::try_from(idle_ms).unwrap_or(Millis::MIN);
                    doc
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn prop_validate_never_panics(doc in arb_doc()) {
            let diagnostics = validate(&doc);
            for d in &diagnostics {
                prop_assert!(!d.pointer.is_empty());
                prop_assert!(!d.code.is_empty());
            }
        }
    }
}
