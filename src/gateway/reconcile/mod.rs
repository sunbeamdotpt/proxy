// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reconciler submodule.
//!
//! Watches Gateway API CRDs in the configured namespace, validates
//! cross-references (RefGrant, parentRefs, backendRefs), and produces
//! a `GatewayView` that is handed off to `translate`.

pub mod backend;
pub mod backendtlspolicy;
pub mod endpoints;
pub mod gateway;
pub mod gatewayclass;
pub mod grpcroute;
pub mod httproute;
pub mod l4route;
pub mod leader;
pub mod listenerset;
pub mod refgrant;
pub mod trigger;

pub use leader::run_reconcile_loop;

use crate::gateway::api::{
    BackendTLSPolicy, GRPCRoute, Gateway, HTTPRoute, ListenerSet, ReferenceGrant, TCPRoute,
    TLSRoute, UDPRoute,
};
use crate::gateway::model::{GatewayView, ListenerSetState, RouteState};
use crate::gateway::reconcile::backend::{
    resolve_backend_refs_async, resolve_backend_refs_async as resolve_grpc_backend_refs_async,
    BackendResolutionStatus,
};
use crate::gateway::reconcile::gateway::build_gateway_state;
use crate::gateway::reconcile::grpcroute::{
    parse_grpcroute_state, reconcile_grpcroutes_with_context,
};
use crate::gateway::reconcile::httproute::{
    parse_httproute_state, reconcile_httproutes_with_context,
};
use crate::gateway::reconcile::l4route::{
    parse_tcproute, parse_tcproute_state, parse_tlsroute, parse_tlsroute_state, parse_udproute,
    parse_udproute_state, reconcile_tcproutes, reconcile_tlsroutes, reconcile_udproutes,
    resolve_l4_backends_async,
};
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use kube::api::Api;
use std::collections::HashMap;
use std::sync::Arc;

/// List an optional L4 route CRD, returning an empty list when the CRD is not
/// installed. Other list failures (e.g. API server 429 during CRD storage
/// initialization) are propagated as `None` so the reconcile tick can retry on
/// the next interval instead of programming an empty route table.
async fn list_l4_routes<T>(api: &Api<T>, kind: &str) -> Option<Vec<T>>
where
    T: kube::Resource<DynamicType = ()> + serde::de::DeserializeOwned + std::fmt::Debug + Clone,
{
    match api.list(&Default::default()).await {
        Ok(list) => Some(list.items),
        Err(e) => {
            let is_missing = matches!(&e, kube::Error::Api(s) if s.code == 404);
            if is_missing {
                tracing::debug!(kind, "L4 route CRD is not installed; treating as empty");
                Some(vec![])
            } else {
                tracing::warn!(error = %e, kind, "failed to list L4 routes; skipping tick");
                None
            }
        }
    }
}

/// Single reconcile tick: fetch all Gateway API objects and emit a view.
pub async fn reconcile_tick(client: &kube::Client) -> Option<GatewayView> {
    reconcile_tick_with_leader(client, false).await
}

/// Single reconcile tick with optional leader status writeback.
pub async fn reconcile_tick_with_leader(
    client: &kube::Client,
    is_leader: bool,
) -> Option<GatewayView> {
    let gateways: Api<Gateway> = Api::all(client.clone());
    let httproutes: Api<HTTPRoute> = Api::all(client.clone());
    let grpcroutes: Api<GRPCRoute> = Api::all(client.clone());
    let grants: Api<ReferenceGrant> = Api::all(client.clone());
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways");
            return None;
        }
    };

    let listenersets: Api<ListenerSet> = Api::all(client.clone());
    let listenerset_list = match listenersets.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            let is_missing = matches!(&e, kube::Error::Api(s) if s.code == 404);
            if is_missing {
                tracing::debug!("ListenerSet CRD is not installed; treating as empty");
                kube::core::object::ObjectList {
                    types: kube::core::TypeMeta::default(),
                    metadata: kube::core::ListMeta::default(),
                    items: vec![],
                }
            } else {
                tracing::warn!(error = %e, "failed to list ListenerSets; skipping tick");
                return None;
            }
        }
    };

    let httproute_list = match httproutes.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list HTTPRoutes");
            return None;
        }
    };

    let grpcroute_list = match grpcroutes.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            let is_missing = matches!(&e, kube::Error::Api(s) if s.code == 404);
            if is_missing {
                tracing::debug!("GRPCRoute CRD is not installed; treating as empty");
                kube::core::object::ObjectList {
                    types: kube::core::TypeMeta::default(),
                    metadata: kube::core::ListMeta::default(),
                    items: vec![],
                }
            } else {
                tracing::warn!(error = %e, "failed to list GRPCRoutes; skipping tick");
                return None;
            }
        }
    };

    let grant_list = match grants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ReferenceGrants");
            return None;
        }
    };

    let namespace_list = match namespaces.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Namespaces");
            return None;
        }
    };

    let backendtlspolicies: Api<BackendTLSPolicy> = Api::all(client.clone());
    let _backendtlspolicy_list = match backendtlspolicies.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            let is_missing = matches!(&e, kube::Error::Api(s) if s.code == 404);
            if is_missing {
                tracing::debug!("BackendTLSPolicy CRD is not installed; treating as empty");
                kube::core::object::ObjectList {
                    types: kube::core::TypeMeta::default(),
                    metadata: kube::core::ListMeta::default(),
                    items: vec![],
                }
            } else {
                tracing::warn!(error = %e, "failed to list BackendTLSPolicies; skipping tick");
                return None;
            }
        }
    };

    let mut gateway_states: Vec<_> = gateway_list.iter().map(build_gateway_state).collect();
    let grant_states = reconcile_reference_grants(&grant_list.items);
    let grant_index = GrantIndex::new(grant_states.clone());
    crate::gateway::reconcile::gateway::load_gateway_frontend_validations(
        client,
        &gateway_list.items,
        &mut gateway_states,
        &grant_index,
    )
    .await;

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

    let mut listener_set_states: Vec<ListenerSetState> = Vec::new();
    for ls in &listenerset_list.items {
        listener_set_states.push(
            crate::gateway::reconcile::listenerset::build_listener_set_state(
                ls,
                &gateway_list.items,
                &namespace_labels,
                client,
                &grant_index,
            )
            .await,
        );
    }
    crate::gateway::reconcile::listenerset::resolve_listener_set_conflicts(
        &mut listener_set_states,
        &gateway_states,
    );
    let listener_set_allowed =
        crate::gateway::reconcile::listenerset::build_listener_set_allowed_map(
            &listenerset_list.items,
            &listener_set_states,
        );

    let reconciled_routes = reconcile_httproutes_with_context(
        &httproute_list.items,
        &gateway_states,
        &listener_set_states,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        &grant_index,
    );

    let mut http_routes = Vec::new();
    for (raw, reconciled) in httproute_list.items.iter().zip(reconciled_routes.iter()) {
        let mut state = parse_httproute_state(raw);
        state.parent_refs = reconciled.route_state.parent_refs.clone();
        let route_ns = raw.metadata.namespace.as_deref().unwrap_or("default");
        let backend_resolution =
            resolve_backend_refs_async(client, raw, route_ns, &grant_index).await;
        state.programmed = !state.parent_refs.is_empty()
            && matches!(backend_resolution.overall, BackendResolutionStatus::Ok);
        for (rule, res) in state.rules.iter_mut().zip(&backend_resolution.rules) {
            rule.programmed = rule.programmed && res.ok;
        }
        http_routes.push(state);
    }

    let reconciled_grpc_routes = reconcile_grpcroutes_with_context(
        &grpcroute_list.items,
        &gateway_states,
        &listener_set_states,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        &grant_index,
    );

    let mut grpc_routes = Vec::new();
    for (raw, reconciled) in grpcroute_list
        .items
        .iter()
        .zip(reconciled_grpc_routes.iter())
    {
        let mut state = parse_grpcroute_state(raw);
        state.parent_refs = reconciled.route_state.parent_refs.clone();
        let route_ns = raw.metadata.namespace.as_deref().unwrap_or("default");
        let backend_resolution =
            resolve_grpc_backend_refs_async(client, raw, route_ns, &grant_index).await;
        state.programmed = !state.parent_refs.is_empty()
            && matches!(
                backend_resolution.overall,
                crate::gateway::reconcile::BackendResolutionStatus::Ok
            );
        for (rule, res) in state.rules.iter_mut().zip(&backend_resolution.rules) {
            rule.programmed = rule.programmed && res.ok;
        }
        grpc_routes.push(state);
    }

    // Compute BackendTLSPolicy status before endpoint expansion replaces service
    // FQDN backend addresses with concrete pod IPs.
    let backend_tls_policies =
        crate::gateway::reconcile::backendtlspolicy::reconcile_backend_tls_policies(
            client,
            &http_routes,
            &grpc_routes,
            &grant_index,
            is_leader,
        )
        .await;

    crate::gateway::reconcile::endpoints::resolve_service_endpoints(
        client,
        &mut http_routes,
        &backend_tls_policies,
    )
    .await;
    crate::gateway::reconcile::endpoints::resolve_service_endpoints(
        client,
        &mut grpc_routes,
        &backend_tls_policies,
    )
    .await;

    let routes: Vec<RouteState> = reconciled_routes
        .into_iter()
        .map(|r| r.route_state)
        .collect();

    // ------------------------------------------------------------------
    // L4 routes
    // ------------------------------------------------------------------
    let tcproutes: Api<TCPRoute> = Api::all(client.clone());
    let udproutes: Api<UDPRoute> = Api::all(client.clone());
    let tlsroutes: Api<TLSRoute> = Api::all(client.clone());

    let tcp_route_items = match list_l4_routes(&tcproutes, "TCPRoute").await {
        Some(items) => items,
        None => return None,
    };
    let udp_route_items = match list_l4_routes(&udproutes, "UDPRoute").await {
        Some(items) => items,
        None => return None,
    };
    let tls_route_items = match list_l4_routes(&tlsroutes, "TLSRoute").await {
        Some(items) => items,
        None => return None,
    };

    let tcp_reconciled = reconcile_tcproutes(
        &tcp_route_items,
        &gateway_states,
        &namespace_labels,
        &listener_allowed,
    );
    let udp_reconciled = reconcile_udproutes(
        &udp_route_items,
        &gateway_states,
        &namespace_labels,
        &listener_allowed,
    );
    let tls_reconciled = reconcile_tlsroutes(
        &tls_route_items,
        &gateway_states,
        &namespace_labels,
        &listener_allowed,
    );

    let mut tcp_routes = Vec::new();
    for (raw, reconciled) in tcp_route_items.iter().zip(tcp_reconciled.iter()) {
        let mut state = parse_tcproute_state(raw);
        state.parent_refs = reconciled.route_state.parent_refs.clone();
        let route_ns = raw.metadata.namespace.as_deref().unwrap_or("default");
        let observed_generation = raw.metadata.generation.unwrap_or(0);
        let parsed = parse_tcproute(raw);
        let (backends, resolved_refs) = resolve_l4_backends_async(
            client,
            &parsed.backends,
            route_ns,
            "TCPRoute",
            &grant_index,
            observed_generation,
        )
        .await;
        state.backends = backends;
        state.programmed = reconciled.programmed && resolved_refs.is_none();
        tcp_routes.push(state);
    }

    let mut udp_routes = Vec::new();
    for (raw, reconciled) in udp_route_items.iter().zip(udp_reconciled.iter()) {
        let mut state = parse_udproute_state(raw);
        state.parent_refs = reconciled.route_state.parent_refs.clone();
        let route_ns = raw.metadata.namespace.as_deref().unwrap_or("default");
        let observed_generation = raw.metadata.generation.unwrap_or(0);
        let parsed = parse_udproute(raw);
        let (backends, resolved_refs) = resolve_l4_backends_async(
            client,
            &parsed.backends,
            route_ns,
            "UDPRoute",
            &grant_index,
            observed_generation,
        )
        .await;
        state.backends = backends;
        state.programmed = reconciled.programmed && resolved_refs.is_none();
        udp_routes.push(state);
    }

    let mut tls_routes = Vec::new();
    for (raw, reconciled) in tls_route_items.iter().zip(tls_reconciled.iter()) {
        let mut state = parse_tlsroute_state(raw);
        state.parent_refs = reconciled.route_state.parent_refs.clone();
        let route_ns = raw.metadata.namespace.as_deref().unwrap_or("default");
        let observed_generation = raw.metadata.generation.unwrap_or(0);
        let parsed = parse_tlsroute(raw);
        let (backends, resolved_refs) = resolve_l4_backends_async(
            client,
            &parsed.backends,
            route_ns,
            "TLSRoute",
            &grant_index,
            observed_generation,
        )
        .await;
        state.backends = backends;
        state.programmed = reconciled.programmed && resolved_refs.is_none();
        tls_routes.push(state);
    }

    let reference_grants = grant_states;

    crate::gateway::reconcile::listenerset::patch_listener_set_statuses(
        client,
        &listenerset_list.items,
        &listener_set_states,
        &httproute_list.items,
        &namespace_labels,
        is_leader,
    )
    .await;

    if is_leader {
        for gw in &gateway_list.items {
            let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
            let gw_name = gw.metadata.name.as_deref().unwrap_or("");
            let current = gw
                .status
                .as_ref()
                .and_then(|s| s.attached_listener_sets)
                .unwrap_or(0) as i64;
            let desired = crate::gateway::reconcile::listenerset::count_attached_listener_sets(
                gw_ns,
                gw_name,
                &listener_set_states,
            );
            if current != desired {
                let patch = serde_json::json!({
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "Gateway",
                    "metadata": { "name": gw_name, "namespace": gw_ns },
                    "status": { "attachedListenerSets": desired }
                });
                let api: Api<Gateway> = Api::namespaced(client.clone(), gw_ns);
                if let Err(e) = api
                    .patch_status(
                        gw_name,
                        &kube::api::PatchParams::apply("sunbeam-proxy"),
                        &kube::api::Patch::Apply(&patch),
                    )
                    .await
                {
                    tracing::warn!(error = %e, %gw_ns, %gw_name, "failed to patch Gateway attachedListenerSets");
                } else {
                    tracing::debug!(%gw_ns, %gw_name, desired, "patched Gateway attachedListenerSets");
                }
            }
        }
    }

    let namespace_labels_arc: crate::gateway::model::NamespaceLabels = namespace_labels
        .into_iter()
        .map(|(ns, labels)| {
            (
                Arc::from(ns),
                labels
                    .into_iter()
                    .map(|(k, v)| (Arc::from(k), Arc::from(v)))
                    .collect(),
            )
        })
        .collect();
    let listener_allowed_arc: crate::gateway::model::ListenerAllowedMap = listener_allowed
        .into_iter()
        .map(|((ns, name, ln), allowed)| ((Arc::from(ns), Arc::from(name), Arc::from(ln)), allowed))
        .collect();
    let listener_set_allowed_arc: crate::gateway::model::ListenerAllowedMap = listener_set_allowed
        .into_iter()
        .map(|((ns, name, ln), allowed)| ((Arc::from(ns), Arc::from(name), Arc::from(ln)), allowed))
        .collect();

    Some(GatewayView {
        gateways: gateway_states,
        listener_sets: listener_set_states,
        routes,
        http_routes,
        grpc_routes,
        tcp_routes,
        udp_routes,
        tls_routes,
        reference_grants,
        backend_tls_policies,
        namespace_labels: namespace_labels_arc,
        listener_allowed: listener_allowed_arc,
        listener_set_allowed: listener_set_allowed_arc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_response(kind: &str, items: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": kind,
            "metadata": { "resourceVersion": "1" },
            "items": items
        })
    }

    fn mock_client(
        responses: std::collections::HashMap<String, serde_json::Value>,
    ) -> kube::Client {
        let responses = std::sync::Arc::new(std::sync::Mutex::new(responses));
        kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let responses = responses.clone();
                async move {
                    let map = responses.lock().unwrap();
                    let body = if path.contains("/gateways") {
                        map.get("gateways")
                            .cloned()
                            .unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/httproutes") {
                        map.get("httproutes")
                            .cloned()
                            .unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/referencegrants") {
                        map.get("referencegrants")
                            .cloned()
                            .unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/namespaces") {
                        map.get("namespaces")
                            .cloned()
                            .unwrap_or(serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []}))
                    } else if path.contains("/grpcroutes") {
                        map.get("grpcroutes")
                            .cloned()
                            .unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/listenersets") {
                        map.get("listenersets")
                            .cloned()
                            .unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/tcproutes") {
                        map.get("tcproutes")
                            .cloned()
                            .unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/udproutes") {
                        map.get("udproutes")
                            .cloned()
                            .unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/tlsroutes") {
                        map.get("tlsroutes")
                            .cloned()
                            .unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/services") {
                        serde_json::json!({"apiVersion": "v1", "kind": "ServiceList", "items": []})
                    } else if path.contains("/endpointslices") {
                        serde_json::json!({"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList", "items": []})
                    } else {
                        serde_json::json!({"items": []})
                    };
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        )
    }

    #[tokio::test]
    async fn reconcile_tick_builds_view() {
        let gateway = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw-1", "namespace": "default", "generation": 1 },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{ "name": "http", "protocol": "HTTP", "port": 80 }]
            }
        });
        let httproute = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": {
                "parentRefs": [{ "name": "gw-1", "sectionName": "http" }],
                "hostnames": ["example.com"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        });
        let grant = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ReferenceGrant",
            "metadata": { "name": "grant-1", "namespace": "default", "generation": 1 },
            "spec": {
                "from": [{ "group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "default" }],
                "to": [{ "group": "gateway.networking.k8s.io", "kind": "Gateway" }]
            }
        });

        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "gateways".to_string(),
            list_response("GatewayList", vec![gateway]),
        );
        responses.insert(
            "httproutes".to_string(),
            list_response("HTTPRouteList", vec![httproute]),
        );
        responses.insert(
            "referencegrants".to_string(),
            list_response("ReferenceGrantList", vec![grant]),
        );

        let client = mock_client(responses);
        let view = reconcile_tick(&client)
            .await
            .expect("reconcile_tick returns a view");

        assert_eq!(view.gateways.len(), 1);
        assert_eq!(view.gateways[0].name.as_ref(), "gw-1");
        assert_eq!(view.http_routes.len(), 1);
        assert_eq!(view.http_routes[0].name.as_ref(), "route-1");
        assert_eq!(view.http_routes[0].parent_refs.len(), 1);
        assert_eq!(view.reference_grants.len(), 1);
        assert_eq!(view.reference_grants[0].name.as_ref(), "grant-1");
    }

    #[tokio::test]
    async fn reconcile_tick_returns_none_on_gateway_list_error() {
        let client = kube::Client::new(
            tower::service_fn(|req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                async move {
                    if path.contains("/gateways") {
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(500)
                                .body(kube::client::Body::empty())
                                .unwrap(),
                        )
                    } else {
                        let body = serde_json::json!({"items": []});
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(kube::client::Body::from(body.to_string().into_bytes()))
                                .unwrap(),
                        )
                    }
                }
            }),
            "default",
        );
        assert!(reconcile_tick(&client).await.is_none());
    }

    #[tokio::test]
    async fn reconcile_tick_empty_lists_produce_empty_view() {
        let mut responses = std::collections::HashMap::new();
        responses.insert("gateways".to_string(), list_response("GatewayList", vec![]));
        responses.insert(
            "httproutes".to_string(),
            list_response("HTTPRouteList", vec![]),
        );
        responses.insert(
            "referencegrants".to_string(),
            list_response("ReferenceGrantList", vec![]),
        );

        let client = mock_client(responses);
        let view = reconcile_tick(&client)
            .await
            .expect("reconcile_tick returns a view");
        assert!(view.gateways.is_empty());
        assert!(view.http_routes.is_empty());
        assert!(view.reference_grants.is_empty());
        assert!(view.routes.is_empty());
    }

    #[tokio::test]
    async fn reconcile_tick_returns_none_on_httproute_list_error() {
        let client = kube::Client::new(
            tower::service_fn(|req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                async move {
                    if path.contains("/httproutes") {
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(500)
                                .body(kube::client::Body::empty())
                                .unwrap(),
                        )
                    } else {
                        let body = serde_json::json!({"items": []});
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(kube::client::Body::from(body.to_string().into_bytes()))
                                .unwrap(),
                        )
                    }
                }
            }),
            "default",
        );
        assert!(reconcile_tick(&client).await.is_none());
    }

    #[tokio::test]
    async fn reconcile_tick_returns_none_on_referencegrant_list_error() {
        let client = kube::Client::new(
            tower::service_fn(|req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                async move {
                    if path.contains("/referencegrants") {
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(500)
                                .body(kube::client::Body::empty())
                                .unwrap(),
                        )
                    } else {
                        let body = serde_json::json!({"items": []});
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(kube::client::Body::from(body.to_string().into_bytes()))
                                .unwrap(),
                        )
                    }
                }
            }),
            "default",
        );
        assert!(reconcile_tick(&client).await.is_none());
    }

    #[tokio::test]
    async fn reconcile_tick_returns_none_on_namespace_list_error() {
        let client = kube::Client::new(
            tower::service_fn(|req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                async move {
                    if path.contains("/namespaces") {
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(500)
                                .body(kube::client::Body::empty())
                                .unwrap(),
                        )
                    } else {
                        let body = serde_json::json!({"items": []});
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(kube::client::Body::from(body.to_string().into_bytes()))
                                .unwrap(),
                        )
                    }
                }
            }),
            "default",
        );
        assert!(reconcile_tick(&client).await.is_none());
    }

    #[tokio::test]
    async fn reconcile_tick_returns_none_on_l4_route_list_errors() {
        let gateway = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw-1", "namespace": "default", "generation": 1 },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{ "name": "http", "protocol": "HTTP", "port": 80 }]
            }
        });

        let mut responses_map = std::collections::HashMap::new();
        responses_map.insert(
            "gateways".to_string(),
            list_response("GatewayList", vec![gateway]),
        );
        responses_map.insert(
            "httproutes".to_string(),
            list_response("HTTPRouteList", vec![]),
        );
        responses_map.insert(
            "referencegrants".to_string(),
            list_response("ReferenceGrantList", vec![]),
        );
        let responses = std::sync::Arc::new(std::sync::Mutex::new(responses_map));

        let client = kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let responses = responses.clone();
                async move {
                    let map = responses.lock().unwrap();
                    if path.contains("/tcproutes")
                        || path.contains("/udproutes")
                        || path.contains("/tlsroutes")
                    {
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(500)
                                .body(kube::client::Body::empty())
                                .unwrap(),
                        )
                    } else {
                        let body = if path.contains("/gateways") {
                            map.get("gateways")
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!({"items": []}))
                        } else if path.contains("/httproutes") {
                            map.get("httproutes")
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!({"items": []}))
                        } else if path.contains("/referencegrants") {
                            map.get("referencegrants")
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!({"items": []}))
                        } else if path.contains("/namespaces") {
                            serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []})
                        } else if path.contains("/services") {
                            serde_json::json!({"apiVersion": "v1", "kind": "ServiceList", "items": []})
                        } else if path.contains("/endpointslices") {
                            serde_json::json!({"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList", "items": []})
                        } else {
                            serde_json::json!({"items": []})
                        };
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(kube::client::Body::from(body.to_string().into_bytes()))
                                .unwrap(),
                        )
                    }
                }
            }),
            "default",
        );
        assert!(reconcile_tick(&client).await.is_none());
    }

    #[tokio::test]
    async fn reconcile_tick_with_leader_includes_listener_sets_and_grpc_routes() {
        let gateway = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw-1", "namespace": "default", "generation": 1 },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{ "name": "http", "protocol": "HTTP", "port": 80 }],
                "allowedListeners": { "namespaces": { "from": "All" } }
            }
        });
        let listenerset = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": "ls-1", "namespace": "default", "generation": 1, "creationTimestamp": "2026-01-01T00:00:00Z" },
            "spec": {
                "parentRef": { "name": "gw-1" },
                "listeners": [{ "name": "extra", "protocol": "HTTP", "port": 8080 }]
            }
        });
        let grpcroute = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "grpc-1", "namespace": "default", "generation": 1 },
            "spec": {
                "parentRefs": [{ "name": "gw-1" }],
                "hostnames": ["grpc.example.com"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 50051 }] }]
            }
        });

        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "gateways".to_string(),
            list_response("GatewayList", vec![gateway]),
        );
        responses.insert(
            "httproutes".to_string(),
            list_response("HTTPRouteList", vec![]),
        );
        responses.insert(
            "grpcroutes".to_string(),
            list_response("GRPCRouteList", vec![grpcroute]),
        );
        responses.insert(
            "referencegrants".to_string(),
            list_response("ReferenceGrantList", vec![]),
        );
        responses.insert(
            "listenersets".to_string(),
            list_response("ListenerSetList", vec![listenerset]),
        );
        responses.insert(
            "namespaces".to_string(),
            serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []}),
        );

        let client = mock_client(responses);
        let view = reconcile_tick_with_leader(&client, false).await;
        assert!(view.is_some());
        let view = view.unwrap();
        assert_eq!(view.gateways.len(), 1);
        assert_eq!(view.listener_sets.len(), 1);
        assert_eq!(view.grpc_routes.len(), 1);
    }

    #[tokio::test]
    async fn reconcile_tick_leader_patches_attached_listener_sets() {
        let gateway = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw-1", "namespace": "default", "generation": 1 },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [{ "name": "http", "protocol": "HTTP", "port": 80 }],
                "allowedListeners": { "namespaces": { "from": "All" } }
            },
            "status": { "attachedListenerSets": 0 }
        });
        let listenerset = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": "ls-1", "namespace": "default", "generation": 1, "creationTimestamp": "2026-01-01T00:00:00Z" },
            "spec": {
                "parentRef": { "name": "gw-1" },
                "listeners": [{ "name": "extra", "protocol": "HTTP", "port": 8080 }]
            }
        });
        let namespace = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "default", "labels": { "team": "gateway" } }
        });

        let mut responses = std::collections::HashMap::new();
        responses.insert(
            "gateways".to_string(),
            list_response("GatewayList", vec![gateway]),
        );
        responses.insert(
            "httproutes".to_string(),
            list_response("HTTPRouteList", vec![]),
        );
        responses.insert(
            "grpcroutes".to_string(),
            list_response("GRPCRouteList", vec![]),
        );
        responses.insert(
            "referencegrants".to_string(),
            list_response("ReferenceGrantList", vec![]),
        );
        responses.insert(
            "listenersets".to_string(),
            list_response("ListenerSetList", vec![listenerset]),
        );
        responses.insert(
            "namespaces".to_string(),
            serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": [namespace]}),
        );
        let tcproute = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "TCPRoute",
            "metadata": { "name": "tcp-1", "namespace": "default", "generation": 1 },
            "spec": {
                "parentRefs": [{ "name": "gw-1" }],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 8080 }] }]
            }
        });
        let udproute = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "UDPRoute",
            "metadata": { "name": "udp-1", "namespace": "default", "generation": 1 },
            "spec": {
                "parentRefs": [{ "name": "gw-1" }],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 9090 }] }]
            }
        });
        let tlsroute = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "TLSRoute",
            "metadata": { "name": "tls-1", "namespace": "default", "generation": 1 },
            "spec": {
                "hostnames": ["*.example.com"],
                "parentRefs": [{ "name": "gw-1" }],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 8443 }] }]
            }
        });
        responses.insert(
            "tcproutes".to_string(),
            list_response("TCPRouteList", vec![tcproute]),
        );
        responses.insert(
            "udproutes".to_string(),
            list_response("UDPRouteList", vec![udproute]),
        );
        responses.insert(
            "tlsroutes".to_string(),
            list_response("TLSRouteList", vec![tlsroute]),
        );

        let client = mock_client(responses);
        let view = reconcile_tick_with_leader(&client, true).await;
        assert!(view.is_some());
        let view = view.unwrap();
        assert_eq!(
            view.namespace_labels.get("default").unwrap().get("team"),
            Some(&Arc::from("gateway"))
        );
    }

    #[tokio::test]
    async fn list_l4_routes_treats_missing_crd_as_empty() {
        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(404)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let api: kube::Api<TCPRoute> = kube::Api::all(client);
        let result = list_l4_routes(&api, "TCPRoute").await;
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_l4_routes_propagates_other_errors() {
        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(500)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let api: kube::Api<TCPRoute> = kube::Api::all(client);
        let result = list_l4_routes(&api, "TCPRoute").await;
        assert!(result.is_none());
    }
}
