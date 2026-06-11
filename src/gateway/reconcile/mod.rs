// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Reconciler submodule.
//!
//! Watches Gateway API CRDs in the configured namespace, validates
//! cross-references (RefGrant, parentRefs, backendRefs), and produces
//! a `GatewayView` that is handed off to `translate`.

pub mod gateway;
pub mod gatewayclass;
pub mod httproute;
pub mod leader;
pub mod refgrant;

pub use leader::run_reconcile_loop;

use serde_json::Value;

/// Recursively strip `lastTransitionTime` from a JSON value so that two
/// status objects can be compared without regard to their timestamps.
pub fn strip_last_transition_time(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut new = serde_json::Map::new();
            for (k, v) in map {
                if k == "lastTransitionTime" {
                    continue;
                }
                new.insert(k.clone(), strip_last_transition_time(v));
            }
            Value::Object(new)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(strip_last_transition_time).collect()),
        other => other.clone(),
    }
}

use crate::gateway::api::{Gateway, HTTPRoute, ReferenceGrant};
use crate::gateway::model::{GatewayView, RouteState};
use crate::gateway::reconcile::gateway::build_gateway_state;
use crate::gateway::reconcile::httproute::{reconcile_httproutes, parse_httproute_state};
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use kube::api::Api;

/// Single reconcile tick: fetch all Gateway API objects and emit a view.
pub async fn reconcile_tick(client: &kube::Client) -> Option<GatewayView> {
    let gateways: Api<Gateway> = Api::all(client.clone());
    let httproutes: Api<HTTPRoute> = Api::all(client.clone());
    let grants: Api<ReferenceGrant> = Api::all(client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways");
            return None;
        }
    };

    let httproute_list = match httproutes.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list HTTPRoutes");
            return None;
        }
    };

    let grant_list = match grants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ReferenceGrants");
            return None;
        }
    };

    let gateway_states: Vec<_> = gateway_list.iter().map(build_gateway_state).collect();
    let grant_states = reconcile_reference_grants(&grant_list.items);
    let grant_index = GrantIndex::new(grant_states.clone());

    let reconciled_routes = reconcile_httproutes(&httproute_list.items, &gateway_states, &grant_index);

    let mut http_routes = Vec::new();
    for (raw, reconciled) in httproute_list.items.iter().zip(reconciled_routes.iter()) {
        let mut state = parse_httproute_state(raw);
        state.parent_refs = reconciled.route_state.parent_refs.clone();
        http_routes.push(state);
    }

    let routes: Vec<RouteState> = reconciled_routes
        .into_iter()
        .map(|r| r.route_state)
        .collect();

    let reference_grants = grant_states;

    Some(GatewayView {
        gateways: gateway_states,
        routes,
        http_routes,
        reference_grants,
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

    fn mock_client(responses: std::collections::HashMap<String, serde_json::Value>) -> kube::Client {
        let responses = std::sync::Arc::new(std::sync::Mutex::new(responses));
        kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let responses = responses.clone();
                async move {
                    let map = responses.lock().unwrap();
                    let body = if path.contains("/gateways") {
                        map.get("gateways").cloned().unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/httproutes") {
                        map.get("httproutes").cloned().unwrap_or(serde_json::json!({"items": []}))
                    } else if path.contains("/referencegrants") {
                        map.get("referencegrants").cloned().unwrap_or(serde_json::json!({"items": []}))
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
        responses.insert("gateways".to_string(), list_response("GatewayList", vec![gateway]));
        responses.insert("httproutes".to_string(), list_response("HTTPRouteList", vec![httproute]));
        responses.insert("referencegrants".to_string(), list_response("ReferenceGrantList", vec![grant]));

        let client = mock_client(responses);
        let view = reconcile_tick(&client).await.expect("reconcile_tick returns a view");

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
        responses.insert("httproutes".to_string(), list_response("HTTPRouteList", vec![]));
        responses.insert("referencegrants".to_string(), list_response("ReferenceGrantList", vec![]));

        let client = mock_client(responses);
        let view = reconcile_tick(&client).await.expect("reconcile_tick returns a view");
        assert!(view.gateways.is_empty());
        assert!(view.http_routes.is_empty());
        assert!(view.reference_grants.is_empty());
        assert!(view.routes.is_empty());
    }
}
