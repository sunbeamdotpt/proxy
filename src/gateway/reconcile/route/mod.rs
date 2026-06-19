// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic reconciliation logic shared by HTTPRoute and GRPCRoute.
//!
//! This module provides route-kind-agnostic helpers for resolving parentRefs,
//! building status conditions, and running the Kubernetes controller loop.
//! Route-specific behavior is injected through the [`RouteResource`] trait.

use crate::gateway::api::{GRPCRoute, HTTPRoute};
use crate::gateway::model::{
    AllowedRoutes, GatewayState, HostnameMatch, ListenerSetState, ParentRef, RouteState,
};
use crate::gateway::reconcile::backend::{
    BackendResolution, BackendResolutionStatus, RouteLike, build_backend_resolution_conditions,
    resolve_backend_refs,
};
use crate::gateway::reconcile::context::{ReconcilerContext, run_controller};
use crate::gateway::reconcile::parent::{ParsedParentRef, resolve_listener_parent};
use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::gateway::status::builder::ParentStatusLike;
use crate::gateway::status::{ConditionStatus, StatusCondition, conditions};
use kube::Client;
use kube::api::Api;
use kube::runtime::controller::Action;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Status conditions for a single parentRef entry.
#[derive(Clone, Debug)]
pub struct RouteParentStatus {
    pub parent_ref: ParentRef,
    pub conditions: Vec<StatusCondition>,
}

impl ParentStatusLike for RouteParentStatus {
    fn parent_ref(&self) -> &ParentRef {
        &self.parent_ref
    }
    fn conditions(&self) -> &[StatusCondition] {
        &self.conditions
    }
}

/// Result of reconciling a single route CRD.
#[derive(Clone, Debug)]
pub struct ReconciledRoute {
    pub route_state: RouteState,
    pub parent_statuses: Vec<RouteParentStatus>,
    /// True only when the route is accepted and all backend references resolve.
    pub programmed: bool,
}

/// Context shared across route reconcile invocations.
pub type RouteContext = ReconcilerContext;

/// Trait for route CRDs that can be reconciled by the generic machinery in
/// this module.
pub trait RouteResource: kube::Resource + RouteLike + Send + Sync + Clone + 'static {
    /// Route kind string used in status messages and `RouteState`.
    fn kind_str() -> &'static str;
    /// Kind string used when patching `.status` via Server-Side Apply.
    fn status_kind_str() -> &'static str;
    /// Parse the route's hostnames into model `HostnameMatch` values.
    fn parse_hostnames(&self) -> Vec<HostnameMatch>;
    /// Parse the route's `spec.parentRefs` into route-independent values.
    fn parse_parent_refs(&self) -> Vec<ParsedParentRef>;
    /// Build a `RouteState` for this route with the given resolved parentRefs.
    fn route_state(&self, parent_refs: Vec<ParentRef>) -> RouteState;
    /// Route metadata `name`, defaulting to the empty string.
    fn metadata_name(&self) -> &str;
    /// Route metadata `namespace`, defaulting to "default".
    fn metadata_namespace(&self) -> &str;
    /// Route metadata `generation`, defaulting to `0`.
    fn generation(&self) -> i64;
}

/// Reconcile a slice of route CRDs against the current Gateway set.
///
/// This is the test-friendly entry point that uses default listener
/// permissions (same-namespace, route kind allowed) and no namespace labels.
pub fn reconcile_routes_default<R: RouteResource>(
    routes: &[R],
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> Vec<ReconciledRoute> {
    let namespace_labels = HashMap::<String, HashMap<String, String>>::new();
    let listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    let listener_sets = Vec::<ListenerSetState>::new();
    let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    reconcile_routes(
        routes,
        gateways,
        &listener_sets,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        grant_index,
    )
}

/// Reconcile route CRDs with full listener permission context.
pub fn reconcile_routes<R: RouteResource>(
    routes: &[R],
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    grant_index: &GrantIndex,
) -> Vec<ReconciledRoute> {
    routes
        .iter()
        .map(|route| {
            let route_ns = route.metadata_namespace();
            let backend_resolution = resolve_backend_refs(route, route_ns, grant_index);
            reconcile_single_route(
                route,
                gateways,
                listener_sets,
                namespace_labels,
                listener_allowed,
                listener_set_allowed,
                grant_index,
                backend_resolution,
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn reconcile_single_route<R: RouteResource>(
    route: &R,
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    _grant_index: &GrantIndex,
    backend_resolution: BackendResolution,
) -> ReconciledRoute {
    let route_ns = route.metadata_namespace();
    let generation = route.generation();
    let route_hostnames = route.parse_hostnames();
    let route_kind = R::kind_str();

    let parsed_refs = route.parse_parent_refs();
    let mut parent_refs = Vec::with_capacity(parsed_refs.len());
    let mut parent_statuses = Vec::with_capacity(parsed_refs.len());

    for parsed in &parsed_refs {
        let (resolved, mut conditions) = resolve_route_parent(
            parsed,
            route_ns,
            generation,
            &route_hostnames,
            gateways,
            listener_sets,
            namespace_labels,
            listener_allowed,
            listener_set_allowed,
            route_kind,
        );
        let status_parent_ref = resolved.clone().unwrap_or_else(|| ParentRef {
            group: Arc::from(parsed.group.clone()),
            kind: Arc::from(parsed.kind.clone()),
            namespace: Some(Arc::from(parsed.namespace.as_deref().unwrap_or(route_ns))),
            name: Arc::from(parsed.name.clone()),
            section_name: parsed.section_name.clone().map(Arc::from),
            port: parsed.port.map(|p| p as u16),
        });
        let accepted = resolved.is_some();
        if let Some(pr) = resolved {
            parent_refs.push(pr);
        }

        // Merge backend ref resolution into the parent status.
        conditions.extend(build_backend_resolution_conditions(
            &backend_resolution,
            accepted,
            generation,
        ));

        parent_statuses.push(RouteParentStatus {
            parent_ref: status_parent_ref,
            conditions,
        });
    }

    let route_state = route.route_state(parent_refs);
    let programmed = !route_state.parent_refs.is_empty()
        && matches!(backend_resolution.overall, BackendResolutionStatus::Ok);

    ReconciledRoute {
        route_state,
        parent_statuses,
        programmed,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_route_parent(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[HostnameMatch],
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    route_kind: &str,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    if parsed.group != "gateway.networking.k8s.io" {
        return unsupported_parent(parsed, observed_generation, route_kind);
    }

    match parsed.kind.as_str() {
        "Gateway" => resolve_gateway_parent(
            parsed,
            route_ns,
            observed_generation,
            route_hostnames,
            gateways,
            namespace_labels,
            listener_allowed,
            route_kind,
        ),
        "ListenerSet" => resolve_listenerset_parent(
            parsed,
            route_ns,
            observed_generation,
            route_hostnames,
            listener_sets,
            namespace_labels,
            listener_set_allowed,
            route_kind,
        ),
        _ => unsupported_parent(parsed, observed_generation, route_kind),
    }
}

fn unsupported_parent(
    parsed: &ParsedParentRef,
    observed_generation: i64,
    route_kind: &str,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let conditions = vec![conditions::accepted_condition(
        ConditionStatus::False,
        "UnsupportedValue",
        &format!(
            "parentRef group {} kind {} is not supported for {}",
            parsed.group, parsed.kind, route_kind
        ),
        observed_generation,
    )];
    (None, conditions)
}

#[allow(clippy::too_many_arguments)]
fn resolve_gateway_parent(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[HostnameMatch],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    route_kind: &str,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let target_ns = parsed.namespace.as_deref().unwrap_or(route_ns);

    let gateway = gateways
        .iter()
        .find(|g| g.namespace.as_ref() == target_ns && g.name.as_ref() == parsed.name);

    let Some(gateway) = gateway else {
        return (
            None,
            vec![conditions::accepted_condition(
                ConditionStatus::False,
                "NoMatchingParent",
                &format!("Gateway {}/{} not found", target_ns, parsed.name),
                observed_generation,
            )],
        );
    };

    let no_conflicts = std::collections::BTreeMap::<Arc<str>, Arc<str>>::new();
    resolve_listener_parent(
        parsed,
        route_ns,
        observed_generation,
        route_hostnames,
        &gateway.listeners,
        namespace_labels,
        listener_allowed,
        target_ns,
        &parsed.name,
        "Gateway",
        &no_conflicts,
        route_kind,
        Some(&["HTTP", "HTTPS"]),
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_listenerset_parent(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[HostnameMatch],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    route_kind: &str,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let target_ns = parsed.namespace.as_deref().unwrap_or(route_ns);

    let ls = listener_sets
        .iter()
        .find(|s| s.namespace.as_ref() == target_ns && s.name.as_ref() == parsed.name);

    let Some(ls) = ls else {
        return (
            None,
            vec![conditions::accepted_condition(
                ConditionStatus::False,
                "NoMatchingParent",
                &format!("ListenerSet {}/{} not found", target_ns, parsed.name),
                observed_generation,
            )],
        );
    };

    resolve_listener_parent(
        parsed,
        route_ns,
        observed_generation,
        route_hostnames,
        &ls.listeners,
        namespace_labels,
        listener_set_allowed,
        target_ns,
        &parsed.name,
        "ListenerSet",
        &ls.conflicts,
        route_kind,
        Some(&["HTTP", "HTTPS"]),
    )
}

/// Reconcile a single route CRD: resolve parentRefs, compute status,
/// and patch `.status.parents[]` when leader.
pub async fn reconcile_route_controller<R>(
    route: Arc<R>,
    ctx: Arc<RouteContext>,
) -> Result<Action, kube::Error>
where
    R: RouteResource
        + kube::Resource<DynamicType = (), Scope = kube::core::NamespaceResourceScope>
        + kube::core::object::HasStatus
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    <R as kube::core::object::HasStatus>::Status: serde::Serialize,
    <R as RouteLike>::Rule: Sync,
    <<R as RouteLike>::Rule as crate::gateway::reconcile::backend::RuleLike>::BackendRef: Sync,
{
    let ns = route.metadata_namespace().to_string();
    let name = route.metadata_name().to_string();

    // Fetch all Gateways, Namespaces, and ReferenceGrants for parentRef resolution.
    // In T1 we do a fresh list per reconcile; a shared cache can be added later.
    let gateways: Api<crate::gateway::api::Gateway> = Api::all(ctx.client.clone());
    let grants: Api<crate::gateway::api::ReferenceGrant> = Api::all(ctx.client.clone());
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(ctx.client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways for {} reconcile", R::kind_str());
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let grant_list = match grants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to list ReferenceGrants for {} reconcile",
                R::kind_str()
            );
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let namespace_list = match namespaces.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Namespaces for {} reconcile", R::kind_str());
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };

    let gateway_states: Vec<GatewayState> = gateway_list
        .iter()
        .map(crate::gateway::reconcile::gateway::build_gateway_state)
        .collect();

    let grant_states =
        crate::gateway::reconcile::refgrant::reconcile_reference_grants(&grant_list.items);
    let grant_index = GrantIndex::new(grant_states);

    let namespace_labels: HashMap<String, HashMap<String, String>> = namespace_list
        .iter()
        .map(|ns| {
            let name = ns.metadata.name.clone().unwrap_or_default();
            let labels: HashMap<String, String> = ns
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            (name, labels)
        })
        .collect();

    // Only fetch ListenerSets when this route actually parents to one.
    let parsed_refs = route.parse_parent_refs();
    let needs_listener_sets = parsed_refs
        .iter()
        .any(|p| p.group == "gateway.networking.k8s.io" && p.kind == "ListenerSet");

    let (listener_set_list_items, mut listener_set_states) = if needs_listener_sets {
        let listener_sets: Api<crate::gateway::api::ListenerSet> = Api::all(ctx.client.clone());
        let listener_set_list = match listener_sets.list(&Default::default()).await {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to list ListenerSets for {} reconcile",
                    R::kind_str()
                );
                return Ok(Action::requeue(Duration::from_secs(5)));
            }
        };
        let mut states = Vec::new();
        for ls in &listener_set_list.items {
            states.push(
                crate::gateway::reconcile::listenerset::build_listener_set_state(
                    ls,
                    &gateway_list.items,
                    &namespace_labels,
                    &ctx.client,
                    &grant_index,
                )
                .await,
            );
        }
        (listener_set_list.items, states)
    } else {
        (Vec::new(), Vec::new())
    };
    if !listener_set_states.is_empty() {
        crate::gateway::reconcile::listenerset::resolve_listener_set_conflicts(
            &mut listener_set_states,
            &gateway_states,
        );
    }
    let listener_allowed =
        crate::gateway::reconcile::gateway::build_listener_allowed_map(&gateway_list.items);
    let listener_set_allowed =
        crate::gateway::reconcile::listenerset::build_listener_set_allowed_map(
            &listener_set_list_items,
            &listener_set_states,
        );

    let route_ns = route.metadata_namespace();
    let backend_resolution = crate::gateway::reconcile::backend::resolve_backend_refs_async(
        &ctx.client,
        route.as_ref(),
        route_ns,
        &grant_index,
    )
    .await;
    let reconciled = reconcile_single_route(
        route.as_ref(),
        &gateway_states,
        &listener_set_states,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        &grant_index,
        backend_resolution,
    );

    if ctx.is_leader.load(Ordering::Relaxed) {
        let parents =
            crate::gateway::status::builder::build_status_parents(&reconciled.parent_statuses);
        let new_status = serde_json::json!({ "parents": parents });

        let api: Api<R> = Api::namespaced(ctx.client.clone(), &ns);
        if let Err(e) = crate::gateway::status::patch::patch_status_if_changed(
            &api,
            &route,
            new_status,
            "gateway.networking.k8s.io/v1",
            R::status_kind_str(),
            "sunbeam-proxy",
        )
        .await
        {
            tracing::warn!(error = %e, name, namespace = ns, "{} status patch failed", R::kind_str());
        }
    }

    crate::gateway::reconcile::trigger::trigger();
    Ok(Action::requeue(Duration::from_secs(30)))
}

pub(crate) fn error_policy_route<R: RouteResource>(
    _route: Arc<R>,
    _error: &kube::Error,
    _ctx: Arc<RouteContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

/// Start the generic route controller.
pub fn run_route_controller<R>(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()>
where
    R: RouteResource
        + kube::Resource<DynamicType = (), Scope = kube::core::NamespaceResourceScope>
        + kube::core::object::HasStatus
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
    <R as kube::core::object::HasStatus>::Status: serde::Serialize,
    <R as RouteLike>::Rule: Sync,
    <<R as RouteLike>::Rule as crate::gateway::reconcile::backend::RuleLike>::BackendRef: Sync,
{
    run_controller::<R, _, _, _>(
        client,
        is_leader,
        reconcile_route_controller::<R>,
        error_policy_route::<R>,
        R::kind_str(),
    )
}

pub mod grpc_parse;
pub mod http_parse;

pub use grpc_parse::parse_grpcroute_state;
pub use http_parse::parse_httproute_state;

/// Result of reconciling a single HTTPRoute.
pub type ReconciledHTTPRoute = ReconciledRoute;

/// Status conditions for a single HTTPRoute parentRef entry.
pub type HTTPRouteParentStatus = RouteParentStatus;

/// Context shared across HTTPRoute reconcile invocations.
pub type HTTPRouteContext = RouteContext;

/// Reconcile a slice of HTTPRoute CRDs against the current Gateway set.
pub fn reconcile_httproutes(
    routes: &[HTTPRoute],
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> Vec<ReconciledHTTPRoute> {
    reconcile_routes_default(routes, gateways, grant_index)
}

/// Reconcile HTTPRoutes with full listener permission context.
pub fn reconcile_httproutes_with_context(
    routes: &[HTTPRoute],
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    grant_index: &GrantIndex,
) -> Vec<ReconciledHTTPRoute> {
    reconcile_routes(
        routes,
        gateways,
        listener_sets,
        namespace_labels,
        listener_allowed,
        listener_set_allowed,
        grant_index,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn reconcile_single(
    route: &HTTPRoute,
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    grant_index: &GrantIndex,
    backend_resolution: BackendResolution,
) -> ReconciledHTTPRoute {
    reconcile_single_route(
        route,
        gateways,
        listener_sets,
        namespace_labels,
        listener_allowed,
        listener_set_allowed,
        grant_index,
        backend_resolution,
    )
}

/// Reconcile a single HTTPRoute: resolve parentRefs, compute status,
/// and patch `.status.parents[]` when leader.
pub async fn reconcile_httproute(
    route: Arc<HTTPRoute>,
    ctx: Arc<RouteContext>,
) -> Result<Action, kube::Error> {
    reconcile_route_controller::<HTTPRoute>(route, ctx).await
}

/// Start the HTTPRoute controller.
pub fn run_httproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    run_route_controller::<HTTPRoute>(client, is_leader)
}

/// Result of reconciling a single GRPCRoute.
pub type ReconciledGRPCRoute = ReconciledRoute;

/// Status conditions for a single GRPCRoute parentRef entry.
pub type GRPCRouteParentStatus = RouteParentStatus;

/// Context shared across GRPCRoute reconcile invocations.
pub type GRPCRouteContext = RouteContext;

/// Reconcile a slice of GRPCRoute CRDs against the current Gateway set.
pub fn reconcile_grpcroutes(
    routes: &[GRPCRoute],
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> Vec<ReconciledGRPCRoute> {
    reconcile_routes_default(routes, gateways, grant_index)
}

/// Reconcile GRPCRoutes with full listener permission context.
pub fn reconcile_grpcroutes_with_context(
    routes: &[GRPCRoute],
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    grant_index: &GrantIndex,
) -> Vec<ReconciledGRPCRoute> {
    reconcile_routes(
        routes,
        gateways,
        listener_sets,
        namespace_labels,
        listener_allowed,
        listener_set_allowed,
        grant_index,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn reconcile_single_grpcroute(
    route: &GRPCRoute,
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    grant_index: &GrantIndex,
    backend_resolution: BackendResolution,
) -> ReconciledGRPCRoute {
    reconcile_single_route(
        route,
        gateways,
        listener_sets,
        namespace_labels,
        listener_allowed,
        listener_set_allowed,
        grant_index,
        backend_resolution,
    )
}

/// Reconcile a single GRPCRoute: resolve parentRefs, compute status,
/// and patch `.status.parents[]` when leader.
pub async fn reconcile_grpcroute(
    route: Arc<GRPCRoute>,
    ctx: Arc<RouteContext>,
) -> Result<Action, kube::Error> {
    reconcile_route_controller::<GRPCRoute>(route, ctx).await
}

/// Start the GRPCRoute controller.
pub fn run_grpcroute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    run_route_controller::<GRPCRoute>(client, is_leader)
}

pub fn error_policy_httproute(
    route: Arc<HTTPRoute>,
    error: &kube::Error,
    ctx: Arc<RouteContext>,
) -> Action {
    error_policy_route::<HTTPRoute>(route, error, ctx)
}

pub fn error_policy_grpcroute(
    route: Arc<GRPCRoute>,
    error: &kube::Error,
    ctx: Arc<RouteContext>,
) -> Action {
    error_policy_route::<GRPCRoute>(route, error, ctx)
}
