// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::gateway::api::{Gateway, ReferenceGrant, TCPRoute, TLSRoute, UDPRoute};
use crate::gateway::model::{AllowedRoutes, GatewayState, RouteState};
use crate::gateway::reconcile::context::run_controller;
use crate::gateway::reconcile::l4route::model::{
    L4ParentStatus, L4RouteContext, L4RouteKind, ReconciledL4Route,
};
use crate::gateway::reconcile::l4route::reconcile::resolve_l4_backends_async;
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use crate::gateway::status::patch::patch_status_if_changed;
use crate::gateway::status::{conditions, ConditionStatus};
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::Client;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub(crate) async fn build_reconcile_context(
    client: &kube::Client,
) -> Option<(
    Vec<GatewayState>,
    GrantIndex,
    HashMap<String, HashMap<String, String>>,
    HashMap<(String, String, String), AllowedRoutes>,
)> {
    let gateways: Api<Gateway> = Api::all(client.clone());
    let grants: Api<ReferenceGrant> = Api::all(client.clone());
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways for L4 reconcile");
            return None;
        }
    };
    let grant_list = match grants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ReferenceGrants for L4 reconcile");
            return None;
        }
    };
    let namespace_list = match namespaces.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Namespaces for L4 reconcile");
            return None;
        }
    };

    let gateway_states: Vec<GatewayState> = gateway_list
        .iter()
        .map(crate::gateway::reconcile::gateway::build_gateway_state)
        .collect();
    let grant_states = reconcile_reference_grants(&grant_list.items);
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
    let listener_allowed =
        crate::gateway::reconcile::gateway::build_listener_allowed_map(&gateway_list.items);

    Some((
        gateway_states,
        grant_index,
        namespace_labels,
        listener_allowed,
    ))
}

pub async fn patch_l4_status<R>(
    route: &R,
    ctx: &L4RouteContext,
    parent_statuses: &[L4ParentStatus],
    api_version: &str,
    kind: &str,
) where
    R: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope, DynamicType = ()>
        + kube::core::object::HasStatus
        + serde::de::DeserializeOwned,
    <R as kube::core::object::HasStatus>::Status: serde::Serialize,
{
    let meta = route.meta();
    let ns = meta.namespace.clone().unwrap_or_default();
    let new_status = serde_json::json!({ "parents": crate::gateway::status::builder::build_status_parents(parent_statuses) });
    let api: Api<R> = Api::namespaced(ctx.client.clone(), &ns);
    if let Err(e) =
        patch_status_if_changed(&api, route, new_status, api_version, kind, "sunbeam-proxy").await
    {
        let name = meta.name.clone().unwrap_or_default();
        tracing::warn!(error = %e, name, namespace = ns, "{} status patch failed", kind);
    }
}

async fn reconcile_l4_route<K: L4RouteKind>(
    route: Arc<K>,
    ctx: Arc<L4RouteContext>,
) -> Result<Action, kube::Error>
where
    <K as kube::core::object::HasStatus>::Status: serde::Serialize,
{
    let meta = route.meta();
    let ns = meta.namespace.clone().unwrap_or_default();
    let name = meta.name.clone().unwrap_or_default();
    let observed_generation = meta.generation.unwrap_or(0);

    let Some((gateway_states, grant_index, namespace_labels, listener_allowed)) =
        build_reconcile_context(&ctx.client).await
    else {
        return Ok(Action::requeue(Duration::from_secs(5)));
    };

    let mut reconciled = K::reconcile_routes(
        std::slice::from_ref(&*route),
        &gateway_states,
        &namespace_labels,
        &listener_allowed,
    )
    .into_iter()
    .next()
    .unwrap_or_else(|| ReconciledL4Route {
        route_state: RouteState {
            namespace: Arc::from(ns.as_str()),
            name: Arc::from(name.as_str()),
            kind: Arc::from(K::kind_str()),
            generation: observed_generation,
            parent_refs: vec![],
        },
        hostnames: vec![],
        backends: vec![],
        programmed: false,
        parent_statuses: vec![],
    });

    let parsed = K::parse(&route);
    let (backends, resolved_refs_condition) = resolve_l4_backends_async(
        &ctx.client,
        &parsed.backends,
        &ns,
        K::kind_str(),
        &grant_index,
        observed_generation,
    )
    .await;
    reconciled.backends = backends;
    let resolved_refs = resolved_refs_condition.unwrap_or_else(|| {
        conditions::resolved_refs_condition(
            ConditionStatus::True,
            "ResolvedRefs",
            "All backend references resolved",
            observed_generation,
        )
    });
    for parent_status in &mut reconciled.parent_statuses {
        parent_status.conditions.push(resolved_refs.clone());
    }
    reconciled.programmed = reconciled.programmed && resolved_refs.status == ConditionStatus::True;

    if ctx.is_leader.load(Ordering::Relaxed) {
        patch_l4_status(
            &*route,
            &ctx,
            &reconciled.parent_statuses,
            K::status_api_version(),
            K::kind_str(),
        )
        .await;
    }

    crate::gateway::reconcile::trigger::trigger();
    Ok(Action::requeue(Duration::from_secs(30)))
}

pub fn error_policy_l4<K: L4RouteKind>(
    _route: Arc<K>,
    _error: &kube::Error,
    _ctx: Arc<L4RouteContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

fn run_l4_controller<K: L4RouteKind>(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()>
where
    <K as kube::core::object::HasStatus>::Status: serde::Serialize,
{
    run_controller::<K, _, _, _>(
        client,
        is_leader,
        reconcile_l4_route::<K>,
        error_policy_l4::<K>,
        K::kind_str(),
    )
}

async fn maybe_run_l4_controller<K: L4RouteKind>(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>>
where
    <K as kube::core::object::HasStatus>::Status: serde::Serialize,
{
    if l4_crd_available::<K>(&client, K::kind_str()).await {
        Some(run_l4_controller::<K>(client, is_leader))
    } else {
        None
    }
}

/// Reconcile a single TCPRoute: resolve parentRefs, compute status, and patch
/// `.status.parents[]` when leader.
pub async fn reconcile_tcproute(
    route: Arc<TCPRoute>,
    ctx: Arc<L4RouteContext>,
) -> Result<Action, kube::Error> {
    reconcile_l4_route::<TCPRoute>(route, ctx).await
}

/// Reconcile a single UDPRoute: resolve parentRefs, compute status, and patch
/// `.status.parents[]` when leader.
pub async fn reconcile_udproute(
    route: Arc<UDPRoute>,
    ctx: Arc<L4RouteContext>,
) -> Result<Action, kube::Error> {
    reconcile_l4_route::<UDPRoute>(route, ctx).await
}

/// Reconcile a single TLSRoute: resolve parentRefs, compute status, and patch
/// `.status.parents[]` when leader.
pub async fn reconcile_tlsroute(
    route: Arc<TLSRoute>,
    ctx: Arc<L4RouteContext>,
) -> Result<Action, kube::Error> {
    reconcile_l4_route::<TLSRoute>(route, ctx).await
}

/// Check whether an L4 route CRD is installed by attempting a list.
///
/// Returns `false` when the API returns 404 (CRD missing) or any other
/// error, logging once at debug/warn level instead of letting the
/// controller enter a tight error backoff loop.
pub async fn l4_crd_available<R>(client: &Client, kind: &str) -> bool
where
    R: kube::Resource<DynamicType = ()> + serde::de::DeserializeOwned + Clone + std::fmt::Debug,
{
    let api: Api<R> = Api::all(client.clone());
    match api.list(&Default::default()).await {
        Ok(_) => true,
        Err(kube::Error::Api(s)) if s.code == 404 => {
            tracing::debug!(kind, "L4 route CRD is not installed; skipping controller");
            false
        }
        Err(e) => {
            tracing::warn!(error = %e, kind, "failed to list L4 route CRD; skipping controller");
            false
        }
    }
}

/// Start the TCPRoute controller only when the CRD is installed.
pub async fn maybe_run_tcproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    maybe_run_l4_controller::<TCPRoute>(client, is_leader).await
}

/// Start the TCPRoute controller.
pub fn run_tcproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    run_l4_controller::<TCPRoute>(client, is_leader)
}

/// Start the UDPRoute controller only when the CRD is installed.
pub async fn maybe_run_udproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    maybe_run_l4_controller::<UDPRoute>(client, is_leader).await
}

/// Start the UDPRoute controller.
pub fn run_udproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    run_l4_controller::<UDPRoute>(client, is_leader)
}

/// Start the TLSRoute controller only when the CRD is installed.
pub async fn maybe_run_tlsroute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    maybe_run_l4_controller::<TLSRoute>(client, is_leader).await
}

/// Start the TLSRoute controller.
pub fn run_tlsroute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    run_l4_controller::<TLSRoute>(client, is_leader)
}
