// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTPRoute reconciler.
//!
//! This is a thin re-export module. The implementation now lives in
//! [`crate::gateway::reconcile::route`] and its `http_parse` submodule.

pub use crate::gateway::reconcile::route::http_parse::parse_httproute_state;
pub use crate::gateway::reconcile::route::{
    reconcile_httproute, reconcile_httproutes, reconcile_httproutes_with_context, reconcile_single,
    run_httproute_controller, HTTPRouteContext, HTTPRouteParentStatus, ReconciledHTTPRoute,
};

/// Parse hostnames from an HTTPRoute spec.
pub fn parse_route_hostnames(
    route: &crate::gateway::api::HTTPRoute,
) -> Vec<crate::gateway::model::HostnameMatch> {
    crate::gateway::reconcile::route::http_parse::parse_route_hostnames(route)
}

/// Parse parentRefs from an HTTPRoute spec.
pub fn parse_parent_refs(
    route: &crate::gateway::api::HTTPRoute,
) -> Vec<crate::gateway::reconcile::parent::ParsedParentRef> {
    crate::gateway::reconcile::route::http_parse::parse_parent_refs(route)
}

pub mod controller {
    pub use crate::gateway::reconcile::route::{reconcile_httproute, run_httproute_controller};
}

pub mod model {
    pub use crate::gateway::reconcile::route::{
        HTTPRouteContext, HTTPRouteParentStatus, ReconciledHTTPRoute,
    };
}

pub mod parse {
    pub use crate::gateway::reconcile::route::http_parse::parse_httproute_state;
}

pub mod reconcile {
    pub use crate::gateway::reconcile::route::{
        reconcile_httproutes, reconcile_httproutes_with_context, reconcile_single,
    };
}
