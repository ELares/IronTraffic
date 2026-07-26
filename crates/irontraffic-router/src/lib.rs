#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

//! The compiled, immutable IronTraffic route table.

pub mod ids;
pub mod limits;
pub mod normalize;
pub mod precedence;
pub mod request;
pub mod spec;
pub mod table;
#[cfg(test)]
pub mod testutil;
pub mod trace;

pub use ids::{
    ActionId, CertId, GroupId, ListenerId, MethodMask, NameId, NodeId, RouteId, SENTINEL,
};
pub use normalize::{
    AuthorityError, HOST_KEY_BUF_BYTES, HostKind, host_key, normalize_authority,
    normalize_host_pattern,
};
pub use precedence::{MatchOrdinalKey, OrdinalError, PathKind, Precedence, assign_ordinals};
pub use request::RequestView;
pub use spec::{
    AdmissionError, AdmissionErrorKind, HeaderMatch, HostPattern, HttpRouteSpec, PathMatch,
    QueryParamMatch, RouteMatchSpec, RouteOrderKey, RouteRuleSpec,
};
#[cfg(any(test, feature = "test-util"))]
pub use table::TableParts;
pub use table::{
    Cand, Group, HostNode, MatchOutcome, PathNode, Pred, PredOp, RouteTable, ValidateError,
};
pub use trace::{ExplainStep, NoTrace, RecordTrace, RejectReason, RouteTrace};
