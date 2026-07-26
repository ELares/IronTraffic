// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hard limits on attacker-controlled input, and the two match-time budgets
//! derived from them.
//!
//! Every limit here is a hard ceiling chosen so that the worst case of a
//! match is within a constant factor of the average.

/// Maximum bytes of a normalized request path the router will match. Longer paths
/// are refused upstream of the router with 414 by the HTTP layer; the router
/// independently refuses to match them, because a budget you only check in one
/// place is not a budget.
pub const MAX_PATH_BYTES: usize = 8192;
/// Maximum `/`-delimited segments in a path.
pub const MAX_SEGMENTS: usize = 128;
/// Maximum bytes of a normalized authority (host, port already stripped).
pub const MAX_AUTHORITY_BYTES: usize = 255;
/// Size of the stack buffer authority normalization writes into.
pub const AUTHORITY_BUF_BYTES: usize = 256;
/// Maximum labels in a CONFIGURED hostname or hostname pattern. Request
/// authorities are deliberately NOT capped by this: a 20-label request authority
/// is bounded by `MAX_AUTHORITY_BYTES` and must still be able to match a wildcard
/// pattern or the listener catch-all, so capping it would 404 legitimate traffic.
pub const MAX_HOST_LABELS: usize = 16;
/// Maximum groups in one host fallthrough chain.
///
/// For an authority of `L` labels a chain holds at most one exact pattern, at most
/// `L - 2` wildcard patterns (a wildcard suffix has at least two labels, so the
/// matching suffixes run from `L - 1` labels down to 2), and one catch-all, which is
/// `L` entries. That bounds the chain at 16 for `L <= 16`. For a DEEPER authority the
/// bound comes from the pattern cap instead: a configured pattern has at most
/// `MAX_HOST_LABELS` labels, so at `L > 16` no exact pattern can match at all, the
/// matching wildcard suffixes run from 16 labels down to 2 (15 of them), and with the
/// catch-all that is again 16. So 16 is exact and tight in both regimes.
pub const MAX_CHAIN_LEN: usize = 16;
/// Maximum query parameters indexed for one request.
pub const MAX_QUERY_PARAMS: usize = 64;
/// Maximum bytes of query string parsed for one request.
pub const MAX_QUERY_BYTES: usize = 4096;
/// Maximum header matches on one route match, per Gateway API.
pub const MAX_HEADER_MATCHES: usize = 16;
/// Maximum query parameter matches on one route match, per Gateway API.
pub const MAX_QUERY_MATCHES: usize = 16;
/// Maximum bytes of a header or query parameter NAME in a configured match.
///
/// Names are tenant-supplied in a Gateway API cluster, they are copied into the
/// interned name set, and every request header of the same length is compared
/// against them. Without a cap a single route could put a megabyte-long name into
/// the interning structure and make every request pay for it. 256 is far above any
/// real field name.
pub const MAX_NAME_BYTES: usize = 256;
/// Maximum bytes of a header or query parameter VALUE literal in a configured match.
///
/// The literal is copied into the group blob and `memcmp`-ed on every candidate
/// evaluation that reaches it. 4096 bounds both the blob contribution and the
/// per-comparison cost.
pub const MAX_VALUE_BYTES: usize = 4096;
/// Maximum bytes of `RouteOrderKey::namespace`. Matches the Kubernetes namespace
/// limit (RFC 1123 label).
pub const MAX_ORDER_NAMESPACE_BYTES: usize = 63;
/// Maximum bytes of `RouteOrderKey::name`. Matches the Kubernetes object-name limit
/// (RFC 1123 subdomain).
///
/// Both order-key caps exist because the ordinal sort compares these two strings
/// byte by byte, `O(n log n)` times, over tenant-supplied text. Uncapped, one tenant
/// submitting 100,000 routes whose names share a one-megabyte prefix turns a
/// few-millisecond sort into minutes of control-plane CPU.
pub const MAX_ORDER_NAME_BYTES: usize = 253;
/// Candidate count above which the builder synthesizes a secondary discriminator.
pub const DISCRIMINATOR_THRESHOLD: u16 = 32;
/// Maximum nesting depth of synthesized discriminators.
pub const MAX_DISCRIMINATOR_DEPTH: u8 = 3;

/// Maximum candidate and predicate evaluations in one `match_request` call, summed
/// over every group in the fallthrough chain and every node on every `up` walk.
///
/// This is a SECOND, independent budget, and it exists because candidate work is
/// bounded by the route table (`M` candidates on the visited nodes, `q` predicates
/// each), not by the request. Charging candidate work against `visit_budget` instead
/// would make the number of candidates a node may hold depend on the request's path
/// length: at `4 * 1 + 64 = 68` a request to `/` could not finish scanning even 34
/// single-predicate candidates, so a table with 100 header-differentiated rules on
/// `/` would 404 the most common request there is. Keeping the two budgets separate
/// bounds both dimensions honestly: the request-driven one grows with the path, and
/// the config-driven one is a flat ceiling an attacker cannot inflate.
///
/// 4096 evaluations is a few microseconds, the same order as the 32,832-unit ceiling
/// `visit_budget` reaches at `MAX_PATH_BYTES`. Exhausting it returns `None` with
/// `MatchStatus::BudgetExhausted` (defined by `match-scratch-per-worker` (#58)),
/// exactly as a visit exhaustion does.
///
/// `match-request-core` (#60) initializes a second local counter to this value at the
/// top of `match_request` and threads it through the candidate scan and
/// `predicate-bytecode-eval` (#59)'s `eval_preds`. It is NOT derived from the path
/// length: a flat ceiling is what an attacker cannot inflate.
pub const MAX_CAND_EVALS: u32 = 4096;

/// The node-visit budget for a path of `path_len` bytes: `4 * path_len + 64`.
///
/// Charged for every node visit: each path-descent iteration, each node on the `up`
/// walk, and each synthesized-discriminator level walked. The check is inside the
/// loop. On exhaustion the match returns `None`. This is what bounds the
/// request-driven part of the match to linear in path length regardless of how
/// pathological the route table is: a single request cannot spend more than
/// `4 * path_len + 64` node visits across every group in its fallthrough chain.
///
/// Candidate and predicate evaluation is charged against `MAX_CAND_EVALS` instead,
/// for the reason recorded there.
#[must_use]
#[allow(clippy::cast_possible_truncation, reason = "path_len is capped above")]
pub const fn visit_budget(path_len: usize) -> u32 {
    // 4 * 8192 + 64 fits in u32 with enormous headroom. The cast is lossless for
    // every value the caller can pass, because the caller has already refused a
    // path longer than MAX_PATH_BYTES; min first so that a caller who has not cannot
    // wrap a 2^32-byte length down to a tiny budget.
    let len = if path_len > MAX_PATH_BYTES {
        MAX_PATH_BYTES
    } else {
        path_len
    };
    (len as u32).saturating_mul(4).saturating_add(64) // it-allow: unchecked-cast reason: len is clamped to MAX_PATH_BYTES above, so this cannot truncate
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHORITY_BUF_BYTES, MAX_AUTHORITY_BYTES, MAX_CAND_EVALS, MAX_NAME_BYTES,
        MAX_ORDER_NAME_BYTES, MAX_ORDER_NAMESPACE_BYTES, MAX_PATH_BYTES, MAX_QUERY_BYTES,
        MAX_VALUE_BYTES, visit_budget,
    };

    #[test]
    fn visit_budget_values() {
        assert_eq!(visit_budget(0), 64);
        assert_eq!(visit_budget(1), 68);
        assert_eq!(visit_budget(60), 304);
        assert_eq!(visit_budget(MAX_PATH_BYTES), 32_832);
        assert_eq!(visit_budget(8193), 32_832);
        assert_eq!(visit_budget(usize::MAX), 32_832);
        assert_eq!(MAX_CAND_EVALS, 4096);
    }

    #[allow(clippy::assertions_on_constants, reason = "tests documented constants")]
    #[test]
    fn authority_buffer_fits() {
        assert!(AUTHORITY_BUF_BYTES > MAX_AUTHORITY_BYTES);
        assert_eq!(MAX_NAME_BYTES, 256);
        assert_eq!(MAX_VALUE_BYTES, 4096);
        assert_eq!(MAX_ORDER_NAMESPACE_BYTES, 63);
        assert_eq!(MAX_ORDER_NAME_BYTES, 253);
        assert_eq!(MAX_QUERY_BYTES, 4096);
    }
}
