#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

//! The compiled, immutable IronTraffic route table.

pub mod ids;
pub mod limits;
pub mod request;
pub mod spec;
#[cfg(test)]
pub mod testutil;

pub use ids::{
    ActionId, CertId, GroupId, ListenerId, MethodMask, NameId, NodeId, RouteId, SENTINEL,
};
pub use request::RequestView;
pub use spec::{
    AdmissionError, AdmissionErrorKind, HeaderMatch, HostPattern, HttpRouteSpec, PathMatch,
    QueryParamMatch, RouteMatchSpec, RouteOrderKey, RouteRuleSpec,
};
