// SPDX-License-Identifier: MIT OR Apache-2.0

//! Located findings about a configuration document.
//!
//! A diagnostic without a location is an unusable diagnostic: an operator staring at
//! a thousand-line document needs to be pointed at the offending field, not told that
//! something, somewhere, is wrong. Every [`Diagnostic`] here carries a JSON Pointer
//! and a stable machine-readable `code`, so an operator can grep for the code and a
//! future admin API can key on it without parsing English.

/// How severe a diagnostic is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The configuration is usable but something is probably wrong.
    Warn,
    /// The configuration is not usable.
    Error,
}

/// One located finding about a configuration document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// How severe.
    pub severity: Severity,
    /// JSON Pointer into the document, for example `/listeners/2/bind`. Never empty.
    pub pointer: String,
    /// Stable machine-readable code from a closed set. Safe to grep and to key on.
    ///
    /// The set is exactly these seventeen values and nothing else, one per numbered
    /// check in `crate::validate`'s design, in check order:
    /// `unsupported_api_version`, `no_listeners`, `too_many_listeners`,
    /// `duplicate_listener_name`, `duplicate_bind_address`, `zero_max_connections`,
    /// `max_connections_above_tested_ceiling`, `zero_workers_clamped`,
    /// `workers_above_reasonable`, `zero_control_workers`, `shard_mode_unsupported`,
    /// `connect_exceeds_idle`, `jitter_exceeds_graceful`, `upstream_is_own_listener`,
    /// `blocking_threads_above_ceiling`, `control_workers_above_reasonable`,
    /// `max_lifetime_below_idle`. Adding a code means editing this list in the same
    /// change, which is the review checkpoint.
    pub code: &'static str,
    /// Human-readable explanation naming the offending values.
    pub message: String,
}

/// An ordered collection of diagnostics, in document order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics(Vec<Diagnostic>);

impl Diagnostics {
    /// Appends a diagnostic.
    pub fn push(&mut self, d: Diagnostic) {
        self.0.push(d);
    }

    /// True when at least one diagnostic has [`Severity::Error`].
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.0.iter().any(|d| d.severity == Severity::Error)
    }

    /// Iterates in document order.
    pub fn iter(&self) -> std::slice::Iter<'_, Diagnostic> {
        self.0.iter()
    }

    /// Number of diagnostics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// One line per diagnostic, in document order, each line terminated by `\n`:
    ///
    /// ```text
    /// <SEVERITY> <pointer> <code>: <message>
    /// ```
    ///
    /// `<SEVERITY>` is the literal `ERROR` or the literal `WARN`, uppercase, with no
    /// padding. Fields are separated by single spaces except that a colon and a space
    /// follow the code. An empty `Diagnostics` renders as the empty string, not as a
    /// lone newline. A full example line:
    ///
    /// ```text
    /// ERROR /listeners/1/bind duplicate_bind_address: 127.0.0.1:8080 is already bound by listener 0
    /// ```
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for d in &self.0 {
            let severity = match d.severity {
                Severity::Error => "ERROR",
                Severity::Warn => "WARN",
            };
            out.push_str(severity);
            out.push(' ');
            out.push_str(&d.pointer);
            out.push(' ');
            out.push_str(d.code);
            out.push_str(": ");
            out.push_str(&d.message);
            out.push('\n');
        }
        out
    }
}

impl<'a> IntoIterator for &'a Diagnostics {
    type Item = &'a Diagnostic;
    type IntoIter = std::slice::Iter<'a, Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::{Diagnostic, Diagnostics, Severity};

    #[test]
    fn empty_diagnostics_render_as_the_empty_string() {
        assert_eq!(Diagnostics::default().render(), "");
        assert!(Diagnostics::default().is_empty());
        assert_eq!(Diagnostics::default().len(), 0);
        assert!(!Diagnostics::default().has_errors());
    }

    // Pins the exact byte-for-byte render format the Public API section quotes.
    // A test that only checked `.contains(...)` fragments would still pass if a
    // separator drifted (a missing space, an extra colon), and the acceptance
    // criteria explicitly require byte-for-byte agreement with the documented
    // example line.
    #[test]
    fn render_matches_the_documented_format_exactly() {
        let mut diagnostics = Diagnostics::default();
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/listeners/1/bind".to_owned(),
            code: "duplicate_bind_address",
            message: "127.0.0.1:8080 is already bound by listener 0".to_owned(),
        });
        assert_eq!(
            diagnostics.render(),
            "ERROR /listeners/1/bind duplicate_bind_address: 127.0.0.1:8080 is already bound by listener 0\n"
        );
    }

    #[test]
    fn render_orders_multiple_diagnostics_and_uses_warn_for_warnings() {
        let mut diagnostics = Diagnostics::default();
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/apiVersion".to_owned(),
            code: "unsupported_api_version",
            message: "first".to_owned(),
        });
        diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            pointer: "/limits/max_connections".to_owned(),
            code: "max_connections_above_tested_ceiling",
            message: "second".to_owned(),
        });
        assert_eq!(
            diagnostics.render(),
            "ERROR /apiVersion unsupported_api_version: first\n\
             WARN /limits/max_connections max_connections_above_tested_ceiling: second\n"
        );
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.has_errors());
        // Mutation testing found that `is_empty` always returning `true` passed
        // every other test here, since none of them checked it on a non-empty
        // `Diagnostics`.
        assert!(!diagnostics.is_empty());
        let pointers: Vec<&str> = diagnostics.iter().map(|d| d.pointer.as_str()).collect();
        assert_eq!(pointers, vec!["/apiVersion", "/limits/max_connections"]);
    }

    #[test]
    fn severity_orders_warn_below_error() {
        assert!(Severity::Warn < Severity::Error);
    }

    // Not a named test, added on top of them: mutation testing found that
    // `IntoIterator for &Diagnostics` returning `Default::default()` (an iterator
    // over an empty slice) instead of the real one passed every other test, since
    // `.iter()` (not `for .. in &diagnostics`) is what every other assertion uses.
    #[test]
    fn into_iter_visits_every_diagnostic() {
        let mut diagnostics = Diagnostics::default();
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            pointer: "/a".to_owned(),
            code: "code_a",
            message: "m".to_owned(),
        });
        diagnostics.push(Diagnostic {
            severity: Severity::Warn,
            pointer: "/b".to_owned(),
            code: "code_b",
            message: "m".to_owned(),
        });
        let mut visited = Vec::new();
        for d in &diagnostics {
            visited.push(d.pointer.as_str());
        }
        assert_eq!(visited, vec!["/a", "/b"]);
    }
}
