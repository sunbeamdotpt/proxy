// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GRPCRoute reconciler tests.

use gateway_api::grpcroutes::GrpcRouteRulesBackendRefs;
use kube::runtime::controller::Action;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use sunbeam_proxy::gateway::api::GRPCRoute;
use sunbeam_proxy::gateway::api::grpcroute::GRPCRouteStatus;
use sunbeam_proxy::gateway::model::{GatewayState, ListenerState};
use sunbeam_proxy::gateway::reconcile::backend::{
    BackendResolutionStatus, resolve_backend_refs, resolve_backend_refs_async,
};
use sunbeam_proxy::gateway::reconcile::context::ReconcilerContext;
use sunbeam_proxy::gateway::reconcile::refgrant::GrantIndex;
use sunbeam_proxy::gateway::reconcile::route::grpc_parse::{
    parse_grpcroute_state, parse_parent_refs, parse_route_hostnames,
};
use sunbeam_proxy::gateway::reconcile::route::{
    error_policy_grpcroute, reconcile_grpcroute, reconcile_grpcroutes, run_grpcroute_controller,
};
use sunbeam_proxy::gateway::status::{ConditionStatus, ConditionType};

fn gw_with_listener(ns: &str, name: &str, listener: &str) -> GatewayState {
    GatewayState {
        namespace: Arc::from(ns),
        name: Arc::from(name),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from(listener),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    }
}

fn sample_route(parent_refs: Vec<Value>) -> GRPCRoute {
    let json = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": {
            "name": "route-1",
            "namespace": "default",
            "generation": 1
        },
        "spec": {
            "parentRefs": parent_refs
        }
    });
    serde_json::from_value(json).expect("valid GRPCRoute")
}

#[test]
fn accepted_when_parent_matches_same_namespace() {
    let route = sample_route(vec![serde_json::json!({
        "name": "gw-1",
        "sectionName": "http"
    })]);
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_grpcroutes(&[route], &gateways, &grant_index);
    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.route_state.parent_refs.len(), 1);

    let accepted = result.parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::True);
    assert_eq!(accepted.reason, "Accepted");
}

#[test]
fn denied_when_gateway_not_found() {
    let route = sample_route(vec![serde_json::json!({"name": "missing-gw"})]);
    let gateways: Vec<GatewayState> = vec![];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_grpcroutes(&[route], &gateways, &grant_index);
    let status = &results[0].parent_statuses[0];
    let accepted = status
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NoMatchingParent");
}

#[test]
fn parse_method_match_to_exact_path() {
    let yaml = r#"
        apiVersion: gateway.networking.k8s.io/v1
        kind: GRPCRoute
        metadata:
          name: grpc
          namespace: default
          generation: 1
        spec:
          parentRefs:
            - name: gw
          hostnames:
            - example.com
          rules:
            - matches:
                - method:
                    service: foo.bar
                    method: Baz
                    type: Exact
              backendRefs:
                - name: svc
                  port: 50051
    "#;
    let route: GRPCRoute = serde_yaml::from_str(yaml).unwrap();
    let state = parse_grpcroute_state(&route);
    assert_eq!(state.hostnames.len(), 1);
    assert_eq!(state.rules.len(), 1);
    let m = state.rules[0].matches[0].method.as_ref().unwrap();
    assert_eq!(m.service.as_ref(), "foo.bar");
    assert_eq!(m.method.as_deref(), Some("Baz"));
    assert!(matches!(
        m.match_type,
        sunbeam_proxy::gateway::model::MethodMatchType::Exact
    ));
    assert_eq!(m.exact_path().as_deref(), Some("/foo.bar/Baz"));
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn route_from_value(value: serde_json::Value) -> GRPCRoute {
    serde_json::from_value(value).expect("valid GRPCRoute")
}

fn route_with_backends(parent_refs: Vec<Value>, backends: Vec<Value>) -> GRPCRoute {
    route_from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": parent_refs, "rules": [{ "backendRefs": backends }] }
    }))
}

fn route_with_rules(rules: Vec<Value>) -> GRPCRoute {
    route_from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "rules": rules }
    }))
}

fn gateway_json(name: &str, ns: &str, listeners: Vec<Value>) -> Value {
    serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": name, "namespace": ns, "generation": 1 },
        "spec": { "gatewayClassName": "sunbeam", "listeners": listeners }
    })
}

fn listener_set_json(name: &str, ns: &str, parent: Value, listeners: Vec<Value>) -> Value {
    serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": { "name": name, "namespace": ns, "generation": 1 },
        "spec": { "parentRef": parent, "listeners": listeners }
    })
}

fn mock_client<F>(responder: F) -> kube::Client
where
    F: Fn(&str, &str) -> (u16, Value) + Clone + Send + Sync + 'static,
{
    kube::Client::new(
        tower::service_fn(move |req: http::Request<kube::client::Body>| {
            let path = req.uri().path().to_string();
            let method = req.method().to_string();
            let responder = responder.clone();
            async move {
                let (status, body) = responder(&path, &method);
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(body.to_string().into_bytes()))
                        .unwrap(),
                )
            }
        }),
        "default",
    )
}

// ---------------------------------------------------------------------------
// Backend reference resolution
// ---------------------------------------------------------------------------

#[test]
fn check_backend_permitted_rejects_unsupported_group() {
    let backend = GrpcRouteRulesBackendRefs {
        group: Some("example.com".to_string()),
        kind: None,
        namespace: None,
        name: "svc".to_string(),
        port: None,
        weight: None,
        filters: None,
    };
    let err = sunbeam_proxy::gateway::reconcile::backend::check_backend_permitted(
        &backend,
        "default",
        "GRPCRoute",
        &GrantIndex::new(vec![]),
    )
    .unwrap_err();
    assert!(matches!(err, BackendResolutionStatus::Unsupported(_)));
}

#[test]
fn resolve_backend_refs_no_rules() {
    let route = route_from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "r", "namespace": "default", "generation": 1 },
        "spec": {}
    }));
    let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
    assert!(matches!(res.overall, BackendResolutionStatus::Ok));
    assert!(res.rules.is_empty());
}

#[test]
fn resolve_backend_refs_rule_without_backends_ok() {
    let route = route_with_rules(vec![serde_json::json!({})]);
    let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
    assert!(matches!(res.overall, BackendResolutionStatus::Ok));
    assert_eq!(res.rules.len(), 1);
    assert!(res.rules[0].ok);
}

#[test]
fn resolve_backend_refs_rejects_unsupported_kind() {
    let route = route_with_backends(
        vec![],
        vec![serde_json::json!({
            "group": "example.com",
            "kind": "Foo",
            "name": "svc"
        })],
    );
    let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
    assert!(matches!(
        res.overall,
        BackendResolutionStatus::Unsupported(_)
    ));
    assert!(!res.rules[0].ok);
}

#[test]
fn resolve_backend_refs_rejects_cross_namespace_without_grant() {
    let route = route_with_backends(
        vec![],
        vec![serde_json::json!({
            "name": "svc",
            "namespace": "other"
        })],
    );
    let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
    assert!(matches!(
        res.overall,
        BackendResolutionStatus::RefNotPermitted(_)
    ));
    assert!(!res.rules[0].ok);
}

#[test]
fn resolve_backend_refs_allows_same_namespace_service() {
    let route = route_with_backends(vec![], vec![serde_json::json!({ "name": "svc" })]);
    let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
    assert!(matches!(res.overall, BackendResolutionStatus::Ok));
    assert!(res.rules[0].ok);
}

#[tokio::test]
async fn resolve_backend_refs_async_finds_service() {
    let route = route_with_backends(
        vec![serde_json::json!({"name": "gw-1"})],
        vec![serde_json::json!({"name": "svc-1", "port": 50051})],
    );
    let client = mock_client(|path, _method| {
        if path.contains("/services/svc-1") {
            (
                200,
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": { "name": "svc-1", "namespace": "default" }
                }),
            )
        } else {
            (
                200,
                serde_json::json!({"apiVersion": "v1", "kind": "List", "items": []}),
            )
        }
    });
    let res =
        resolve_backend_refs_async(&client, &route, "default", &GrantIndex::new(vec![])).await;
    assert!(matches!(res.overall, BackendResolutionStatus::Ok));
}

#[tokio::test]
async fn resolve_backend_refs_async_missing_service() {
    let route = route_with_backends(
        vec![serde_json::json!({"name": "gw-1"})],
        vec![serde_json::json!({"name": "missing-svc", "port": 50051})],
    );
    let client = mock_client(|_path, _method| (404, serde_json::json!({})));
    let res =
        resolve_backend_refs_async(&client, &route, "default", &GrantIndex::new(vec![])).await;
    assert!(
        matches!(res.overall, BackendResolutionStatus::BackendNotFound(ref m) if m.contains("missing-svc")),
        "unexpected result: {res:?}"
    );
}

// ---------------------------------------------------------------------------
// Reconcile status branches
// ---------------------------------------------------------------------------

#[test]
fn reconciled_programmed_false_when_backend_ref_not_permitted() {
    let route = route_with_backends(
        vec![serde_json::json!({"name": "gw-1"})],
        vec![serde_json::json!({"name": "svc", "namespace": "other"})],
    );
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let res = &reconcile_grpcroutes(&[route], &gateways, &GrantIndex::new(vec![]))[0];
    assert!(!res.programmed);
    let cond = res.parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
        .unwrap();
    assert_eq!(cond.status, ConditionStatus::False);
    assert_eq!(cond.reason, "RefNotPermitted");
}

#[test]
fn reconciled_programmed_false_when_backend_unsupported() {
    let route = route_with_backends(
        vec![serde_json::json!({"name": "gw-1"})],
        vec![serde_json::json!({"group": "example.com", "kind": "Foo", "name": "svc"})],
    );
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let res = &reconcile_grpcroutes(&[route], &gateways, &GrantIndex::new(vec![]))[0];
    assert!(!res.programmed);
    let cond = res.parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
        .unwrap();
    assert_eq!(cond.status, ConditionStatus::False);
    assert_eq!(cond.reason, "InvalidKind");
}

#[test]
fn reconciled_with_unsupported_parent_group() {
    let route = route_from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "r", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [{ "group": "example.com", "kind": "Gateway", "name": "gw" }] }
    }));
    let gateways = vec![gw_with_listener("default", "gw", "http")];
    let res = &reconcile_grpcroutes(&[route], &gateways, &GrantIndex::new(vec![]))[0];
    let cond = res.parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(cond.status, ConditionStatus::False);
    assert_eq!(cond.reason, "UnsupportedValue");
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_route_hostnames_exact_and_wildcard() {
    let route = route_from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": { "hostnames": ["example.com", "*.example.com"] }
    }));
    let hostnames = parse_route_hostnames(&route);
    assert!(
        matches!(&hostnames[0], sunbeam_proxy::gateway::model::HostnameMatch::Exact(h) if h.as_ref() == "example.com")
    );
    assert!(
        matches!(&hostnames[1], sunbeam_proxy::gateway::model::HostnameMatch::Wildcard(h) if h.as_ref() == "example.com")
    );
}

#[test]
fn parse_grpcroute_state_empty_rules() {
    let route = route_from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "r", "namespace": "default", "generation": 2 },
        "spec": {}
    }));
    let state = parse_grpcroute_state(&route);
    assert_eq!(state.namespace.as_ref(), "default");
    assert_eq!(state.name.as_ref(), "r");
    assert_eq!(state.generation, 2);
    assert!(state.hostnames.is_empty());
    assert!(state.rules.is_empty());
    assert!(state.parent_refs.is_empty());
}

#[test]
fn parse_grpcroute_state_method_variations() {
    let route = route_with_rules(vec![
        serde_json::json!({ "matches": [{ "method": { "service": "foo.bar" } }] }),
        serde_json::json!({ "matches": [{ "method": { "method": "Baz" } }] }),
        serde_json::json!({ "matches": [{ "method": { "service": "foo.bar", "type": "RegularExpression" } }] }),
        serde_json::json!({ "matches": [{ "method": {} }] }),
    ]);
    let state = parse_grpcroute_state(&route);
    assert_eq!(state.rules.len(), 4);

    let m0 = state.rules[0].matches[0].method.as_ref().unwrap();
    assert_eq!(m0.service.as_ref(), "foo.bar");
    assert!(m0.method.is_none());
    assert!(matches!(
        m0.match_type,
        sunbeam_proxy::gateway::model::MethodMatchType::Exact
    ));

    let m1 = state.rules[1].matches[0].method.as_ref().unwrap();
    assert_eq!(m1.service.as_ref(), "");
    assert_eq!(m1.method.as_deref(), Some("Baz"));

    let m2 = state.rules[2].matches[0].method.as_ref().unwrap();
    assert!(matches!(
        m2.match_type,
        sunbeam_proxy::gateway::model::MethodMatchType::Regular
    ));

    assert!(state.rules[3].matches[0].method.is_none());
}

#[test]
fn parse_grpcroute_state_header_matches() {
    let route = route_with_rules(vec![serde_json::json!({
        "matches": [{
            "headers": [
                { "name": "X-V", "value": "1" },
                { "name": "X-R", "type": "RegularExpression", "value": ".*" }
            ]
        }]
    })]);
    let state = parse_grpcroute_state(&route);
    let headers = &state.rules[0].matches[0].headers;
    assert_eq!(headers[0].name.as_ref(), "X-V");
    assert_eq!(
        headers[0].value,
        sunbeam_proxy::gateway::model::HeaderMatchValue::Exact(Arc::from("1"))
    );
    assert_eq!(headers[1].name.as_ref(), "X-R");
    assert_eq!(
        headers[1].value,
        sunbeam_proxy::gateway::model::HeaderMatchValue::Regex(Arc::from(".*"))
    );
}

#[test]
fn parse_grpcroute_state_filters() {
    let route = route_with_rules(vec![serde_json::json!({
        "filters": [
            { "type": "RequestHeaderModifier", "requestHeaderModifier": {
                "set": [{ "name": "X-S", "value": "v" }],
                "add": [{ "name": "X-A", "value": "v" }],
                "remove": ["X-R"]
            }},
            { "type": "ResponseHeaderModifier", "responseHeaderModifier": {
                "set": [{ "name": "Y-S", "value": "v" }]
            }},
            { "type": "RequestHeaderModifier" },
            { "type": "ExtensionRef" }
        ]
    })]);
    let state = parse_grpcroute_state(&route);
    let filters = &state.rules[0].filters;
    assert_eq!(filters.len(), 4);
    assert!(matches!(
        filters[0],
        sunbeam_proxy::gateway::model::RouteFilter::RequestHeaderSet { .. }
    ));
    assert!(matches!(
        filters[1],
        sunbeam_proxy::gateway::model::RouteFilter::RequestHeaderAdd { .. }
    ));
    assert!(matches!(
        filters[2],
        sunbeam_proxy::gateway::model::RouteFilter::RequestHeaderRemove { .. }
    ));
    assert!(matches!(
        filters[3],
        sunbeam_proxy::gateway::model::RouteFilter::ResponseHeaderSet { .. }
    ));
}

#[test]
fn parse_grpcroute_state_backend_filters() {
    let route = route_with_rules(vec![serde_json::json!({
        "backendRefs": [{
            "name": "svc",
            "filters": [
                { "type": "RequestHeaderModifier", "requestHeaderModifier": {
                    "add": [{ "name": "B-A", "value": "v" }]
                }},
                { "type": "ResponseHeaderModifier", "responseHeaderModifier": {
                    "remove": ["B-R"]
                }},
                { "type": "ResponseHeaderModifier" }
            ]
        }]
    })]);
    let state = parse_grpcroute_state(&route);
    let backend = &state.rules[0].backends[0];
    assert_eq!(backend.filters.len(), 2);
    assert!(matches!(
        backend.filters[0],
        sunbeam_proxy::gateway::model::RouteFilter::RequestHeaderAdd { .. }
    ));
    assert!(matches!(
        backend.filters[1],
        sunbeam_proxy::gateway::model::RouteFilter::ResponseHeaderRemove { .. }
    ));
}

#[test]
fn parse_grpcroute_state_backend_ref_defaults() {
    let route = route_with_rules(vec![serde_json::json!({
        "backendRefs": [{ "name": "svc" }]
    })]);
    let state = parse_grpcroute_state(&route);
    let b = &state.rules[0].backends[0];
    assert_eq!(b.backend.as_ref(), "svc.default.svc.cluster.local.:80");
    assert_eq!(b.weight, 1);
}

#[test]
fn parse_grpcroute_state_backend_ref_explicit() {
    let route = route_with_rules(vec![serde_json::json!({
        "backendRefs": [{ "name": "svc", "namespace": "ns", "port": 50051, "weight": 5 }]
    })]);
    let state = parse_grpcroute_state(&route);
    let b = &state.rules[0].backends[0];
    assert_eq!(b.backend.as_ref(), "svc.ns.svc.cluster.local.:50051");
    assert_eq!(b.weight, 5);
}

#[test]
fn parse_parent_refs_defaults() {
    let route = route_from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": { "parentRefs": [{ "name": "gw" }] }
    }));
    let refs = parse_parent_refs(&route);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].group, "gateway.networking.k8s.io");
    assert_eq!(refs[0].kind, "Gateway");
    assert_eq!(refs[0].namespace, None);
    assert_eq!(refs[0].name, "gw");
}

#[test]
fn parse_parent_refs_explicit() {
    let route = route_from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": { "parentRefs": [{
            "group": "foo",
            "kind": "Bar",
            "name": "x",
            "namespace": "ns",
            "sectionName": "sec",
            "port": 8080
        }] }
    }));
    let refs = parse_parent_refs(&route);
    assert_eq!(refs[0].group, "foo");
    assert_eq!(refs[0].kind, "Bar");
    assert_eq!(refs[0].namespace, Some("ns".to_string()));
    assert_eq!(refs[0].section_name, Some("sec".to_string()));
    assert_eq!(refs[0].port, Some(8080));
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reconcile_grpcroute_non_leader_returns_requeue() {
    let route: GRPCRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [] }
    }))
    .unwrap();

    let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": []});
    let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
    let namespace_list =
        serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});

    let client = mock_client(move |path, _method| {
        if path.contains("/namespaces") {
            (200, namespace_list.clone())
        } else if path.contains("/referencegrants") {
            (200, grant_list.clone())
        } else {
            (200, gateway_list.clone())
        }
    });

    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_grpcroute_leader_patches_status() {
    let route: GRPCRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": {
            "parentRefs": [{ "name": "gw-1" }],
            "rules": [{ "backendRefs": [{ "name": "svc-1", "port": 50051 }] }]
        }
    }))
    .unwrap();

    let gw = gateway_json(
        "gw-1",
        "default",
        vec![serde_json::json!({
            "name": "http",
            "protocol": "HTTP",
            "port": 80
        })],
    );
    let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": [gw]});
    let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
    let namespace_list =
        serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});

    let patched = Arc::new(AtomicUsize::new(0));
    let patched_clone = patched.clone();
    let client = mock_client(move |path, method| {
        if method == "PATCH" && path.contains("/status") {
            patched_clone.fetch_add(1, Ordering::SeqCst);
            (
                200,
                serde_json::json!({
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "GRPCRoute",
                    "metadata": { "name": "route-1", "namespace": "default" },
                    "status": { "parents": [] }
                }),
            )
        } else if path.contains("/services/svc-1") {
            (
                200,
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": { "name": "svc-1", "namespace": "default" }
                }),
            )
        } else if path.contains("/namespaces") {
            (200, namespace_list.clone())
        } else if path.contains("/referencegrants") {
            (200, grant_list.clone())
        } else {
            (200, gateway_list.clone())
        }
    });

    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(true)),
    });
    let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    assert!(patched.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn reconcile_grpcroute_leader_skips_unchanged_status() {
    let mut route: GRPCRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [] }
    }))
    .unwrap();
    route.status = Some(GRPCRouteStatus { parents: vec![] });

    let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": []});
    let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
    let namespace_list =
        serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});

    let patched = Arc::new(AtomicUsize::new(0));
    let patched_clone = patched.clone();
    let client = mock_client(move |path, method| {
        if method == "PATCH" && path.contains("/status") {
            patched_clone.fetch_add(1, Ordering::SeqCst);
            (200, serde_json::json!({}))
        } else if path.contains("/namespaces") {
            (200, namespace_list.clone())
        } else if path.contains("/referencegrants") {
            (200, grant_list.clone())
        } else {
            (200, gateway_list.clone())
        }
    });

    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(true)),
    });
    let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    assert_eq!(patched.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reconcile_grpcroute_patch_failure_still_requeues() {
    let route: GRPCRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": {
            "parentRefs": [{ "name": "gw-1" }],
            "rules": [{ "backendRefs": [{ "name": "svc-1" }] }]
        }
    }))
    .unwrap();

    let gw = gateway_json(
        "gw-1",
        "default",
        vec![serde_json::json!({
            "name": "http",
            "protocol": "HTTP",
            "port": 80
        })],
    );
    let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": [gw]});
    let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
    let namespace_list =
        serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});

    let client = mock_client(move |path, method| {
        let (status, body) = if method == "PATCH" && path.contains("/status") {
            (403, serde_json::json!({}))
        } else if path.contains("/services/svc-1") {
            (
                200,
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": { "name": "svc-1", "namespace": "default" }
                }),
            )
        } else if path.contains("/namespaces") {
            (200, namespace_list.clone())
        } else if path.contains("/referencegrants") {
            (200, grant_list.clone())
        } else {
            (200, gateway_list.clone())
        };
        (status, body)
    });

    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(true)),
    });
    let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_grpcroute_gateway_list_error_requeues() {
    let route: GRPCRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [] }
    }))
    .unwrap();

    let client = mock_client(|_path, _method| (500, serde_json::json!({"message": "fail"})));
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn reconcile_grpcroute_grant_list_error_requeues() {
    let route: GRPCRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [] }
    }))
    .unwrap();

    let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": []});
    let client = mock_client(move |path, _method| {
        if path.contains("/gateways") {
            (200, gateway_list.clone())
        } else {
            (500, serde_json::json!({"message": "fail"}))
        }
    });
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn reconcile_grpcroute_namespace_list_error_requeues() {
    let route: GRPCRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [] }
    }))
    .unwrap();

    let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": []});
    let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
    let client = mock_client(move |path, _method| {
        if path.contains("/gateways") {
            (200, gateway_list.clone())
        } else if path.contains("/referencegrants") {
            (200, grant_list.clone())
        } else {
            (500, serde_json::json!({"message": "fail"}))
        }
    });
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn reconcile_grpcroute_listenerset_list_error_requeues() {
    let route: GRPCRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [{ "group": "gateway.networking.k8s.io", "kind": "ListenerSet", "name": "ls-1" }] }
    }))
    .unwrap();

    let gw = gateway_json(
        "gw-1",
        "default",
        vec![serde_json::json!({
            "name": "http",
            "protocol": "HTTP",
            "port": 80,
            "allowedListeners": { "namespaces": { "from": "All" } }
        })],
    );
    let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": [gw]});
    let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
    let namespace_list =
        serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});
    let client = mock_client(move |path, _method| {
        if path.contains("/namespaces") {
            (200, namespace_list.clone())
        } else if path.contains("/referencegrants") {
            (200, grant_list.clone())
        } else if path.contains("/gateways") {
            (200, gateway_list.clone())
        } else {
            (500, serde_json::json!({"message": "fail"}))
        }
    });
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn reconcile_grpcroute_with_listener_set_parent() {
    let route: GRPCRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [{
            "group": "gateway.networking.k8s.io",
            "kind": "ListenerSet",
            "name": "ls-1",
            "sectionName": "http"
        }] }
    }))
    .unwrap();

    let gw = gateway_json(
        "gw-1",
        "default",
        vec![serde_json::json!({
            "name": "http",
            "protocol": "HTTP",
            "port": 80,
            "allowedListeners": { "namespaces": { "from": "All" } }
        })],
    );
    let ls = listener_set_json(
        "ls-1",
        "default",
        serde_json::json!({ "name": "gw-1" }),
        vec![serde_json::json!({ "name": "http", "protocol": "HTTP", "port": 80 })],
    );
    let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": [gw]});
    let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
    let namespace_list =
        serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});
    let listenerset_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ListenerSetList", "items": [ls]});

    let client = mock_client(move |path, _method| {
        if path.contains("/namespaces") {
            (200, namespace_list.clone())
        } else if path.contains("/referencegrants") {
            (200, grant_list.clone())
        } else if path.contains("/listenersets") {
            (200, listenerset_list.clone())
        } else {
            (200, gateway_list.clone())
        }
    });
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn error_policy_grpcroute_requeues_after_5s() {
    let route = Arc::new(sample_route(vec![]));
    let ctx = Arc::new(ReconcilerContext {
        client: kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "default",
        ),
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let err = kube::Error::Service(std::io::Error::other("test").into());
    let action = error_policy_grpcroute(route, &err, ctx);
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn run_grpcroute_controller_returns_handle() {
    let client = kube::Client::new(
        tower::service_fn(|_req| async {
            Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
        }),
        "default",
    );
    let handle = run_grpcroute_controller(client, Arc::new(AtomicBool::new(false)));
    handle.abort();
}
