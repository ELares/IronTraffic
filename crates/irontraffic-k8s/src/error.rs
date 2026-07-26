// SPDX-License-Identifier: MIT OR Apache-2.0
//! Errors returned by the Kubernetes configuration source.

use std::cmp;

/// Everything this crate can fail with that is not a per-object diagnostic.
#[derive(Debug, thiserror::Error)]
pub enum K8sError {
    /// A Kubernetes client call failed.
    #[error("kubernetes api call failed: {0}")]
    Api(#[from] kube::Error),
    /// An object arrived that we could not project into a view.
    ///
    /// `namespace`, `name` and `why` all carry bytes we did not choose. They are
    /// passed through `sanitize_for_log` at construction, never at display time, so
    /// there is no path that formats the raw value.
    #[error("could not decode {kind} {namespace}/{name}: {why}")]
    Decode {
        /// The kind string of the object that failed to decode.
        kind: &'static str,
        /// Sanitized namespace of the object.
        namespace: String,
        /// Sanitized name of the object.
        name: String,
        /// Sanitized reason the object could not be decoded.
        why: String,
    },
    /// A required CRD is not installed.
    #[error("custom resource definition {0} is not installed")]
    CrdMissing(&'static str),
    /// The controller was asked to run without a usable kubeconfig or in-cluster
    /// service account.
    #[error("no kubernetes credentials: {0}")]
    NoCredentials(String),
}

impl K8sError {
    /// Builds a `Decode` error with sanitized strings.
    #[must_use]
    pub fn decode(kind: &'static str, namespace: &str, name: &str, why: &str) -> Self {
        Self::Decode {
            kind,
            namespace: sanitize_for_log(namespace),
            name: sanitize_for_log(name),
            why: sanitize_for_log(why),
        }
    }
}

/// Makes a string safe to put in a log line, an Event message, or a condition
/// message.
///
/// Every string this crate renders that came from an object we did not write goes
/// through this: object names, namespaces, annotation keys and values, hostnames,
/// serde error text, and API server error bodies. Without it, a namespace owner who
/// names an object with an embedded newline plus a plausible-looking log prefix can
/// forge log records in the operator's aggregator, and one who embeds an ANSI escape
/// can rewrite what `kubectl logs` and `itctl` show on a terminal.
///
/// Rules, applied in order:
/// 1. Replace every byte below 0x20, plus 0x7f, with `.` (this covers CR, LF, TAB,
///    and the ESC that starts every ANSI control sequence).
/// 2. Truncate to at most 200 bytes on a UTF-8 character boundary, appending the
///    three ASCII bytes `...` when anything was removed.
///
/// Never allocates more than 203 bytes of output regardless of input length.
#[must_use]
pub fn sanitize_for_log(s: &str) -> String {
    let mut out = String::with_capacity(cmp::min(s.len(), 203));
    let mut bytes = 0;
    for c in s.chars().map(|c| {
        let cp = u32::from(c);
        if cp < 0x20 || cp == 0x7f { '.' } else { c }
    }) {
        let len = c.len_utf8();
        if bytes + len > 200 {
            out.push_str("...");
            return out;
        }
        out.push(c);
        bytes += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_empty_is_empty() {
        assert_eq!(sanitize_for_log(""), "");
    }

    #[test]
    fn sanitize_leaves_clean_strings() {
        assert_eq!(sanitize_for_log("team-a/api"), "team-a/api");
    }
}
