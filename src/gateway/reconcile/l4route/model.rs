// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::gateway::model::{AllowedRoutes, HostnameMatch, ParentRef, RouteState, WeightedBackend};
use crate::gateway::reconcile::backend::BackendRefLike;
use crate::gateway::reconcile::context::ReconcilerContext;
use crate::gateway::reconcile::parent::ParsedParentRef;
use crate::gateway::status::StatusCondition;
use crate::impl_backend_ref_like;
use gateway_api::experimental::tcproutes::TcpRouteRulesBackendRefs;
use gateway_api::experimental::udproutes::UdpRouteRulesBackendRefs;
use gateway_api::tlsroutes::TlsRouteRulesBackendRefs;
use std::collections::HashMap;
use std::sync::Arc;

/// Result of reconciling a single L4 route.
#[derive(Clone, Debug)]
pub struct ReconciledL4Route {
    /// Generic route identity produced by the reconcile.
    pub route_state: RouteState,
    /// SNI hostnames for TLSRoute; empty for TCP/UDP.
    pub hostnames: Vec<HostnameMatch>,
    /// Resolved weighted backends.
    pub backends: Vec<WeightedBackend>,
    /// True when the route is accepted and all backend references resolve.
    pub programmed: bool,
    /// Per-parentRef status entries.
    pub parent_statuses: Vec<L4ParentStatus>,
}

/// Status conditions for a single parentRef entry on an L4 route.
#[derive(Clone, Debug)]
pub struct L4ParentStatus {
    pub parent_ref: ParentRef,
    pub conditions: Vec<StatusCondition>,
}

impl crate::gateway::status::builder::ParentStatusLike for L4ParentStatus {
    fn parent_ref(&self) -> &ParentRef {
        &self.parent_ref
    }
    fn conditions(&self) -> &[StatusCondition] {
        &self.conditions
    }
}

#[derive(Clone, Debug)]
pub struct ParsedBackendRef {
    pub group: Option<String>,
    pub kind: Option<String>,
    pub namespace: Option<String>,
    pub name: String,
    pub port: Option<i32>,
    pub weight: Option<i32>,
}

#[derive(Clone, Debug)]
pub struct ParsedL4Route {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub generation: i64,
    pub hostnames: Vec<HostnameMatch>,
    pub parent_refs: Vec<ParsedParentRef>,
    pub backends: Vec<ParsedBackendRef>,
}

impl_backend_ref_like!(TcpRouteRulesBackendRefs, port, weight);
impl_backend_ref_like!(UdpRouteRulesBackendRefs, port, weight);
impl_backend_ref_like!(TlsRouteRulesBackendRefs, port, weight);

impl BackendRefLike for ParsedBackendRef {
    fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }
    fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }
    fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn port(&self) -> Option<i32> {
        self.port
    }
    fn weight(&self) -> Option<i32> {
        self.weight
    }
}

pub(crate) fn into_parsed_backend<T: BackendRefLike>(value: &T) -> ParsedBackendRef {
    ParsedBackendRef {
        group: value.group().map(|s| s.to_string()),
        kind: value.kind().map(|s| s.to_string()),
        namespace: value.namespace().map(|s| s.to_string()),
        name: value.name().to_string(),
        port: value.port(),
        weight: value.weight(),
    }
}

/// Context shared by the L4 route controllers.
pub type L4RouteContext = ReconcilerContext;

/// Trait implemented by each L4 route CRD so the controller skeleton can be
/// written once and reused for TCP, UDP, and TLS routes.
pub trait L4RouteKind:
    kube::Resource<Scope = k8s_openapi::NamespaceResourceScope, DynamicType = ()>
    + kube::core::object::HasStatus
    + serde::de::DeserializeOwned
    + Clone
    + std::fmt::Debug
    + Send
    + Sync
    + 'static
{
    fn kind_str() -> &'static str;
    /// API version used when patching this route's status.
    fn status_api_version() -> &'static str;
    fn protocols() -> &'static [&'static str];
    fn parse(route: &Self) -> ParsedL4Route;

    fn reconcile_routes(
        routes: &[Self],
        gateways: &[crate::gateway::model::GatewayState],
        namespace_labels: &HashMap<String, HashMap<String, String>>,
        listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    ) -> Vec<ReconciledL4Route> {
        let parsed: Vec<_> = routes.iter().map(|r| Self::parse(r)).collect();
        crate::gateway::reconcile::l4route::reconcile::reconcile_l4_routes(
            &parsed,
            Self::kind_str(),
            Self::protocols(),
            gateways,
            namespace_labels,
            listener_allowed,
        )
    }
}
